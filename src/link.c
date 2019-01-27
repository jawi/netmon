#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

#include "addr_common.h"
#include "event.h"
#include "link.h"
#include "mqtt.h"
#include "logging.h"
#include "util.h"
#include "mnl_extra.h"

typedef struct link_info {
    int index;
    char *name;
    uint8_t ll_addr[MAC_LEN];
    uint16_t *vlan_id;
    struct link_info *next;
} link_info_t;

struct link_handle {
    link_info_t *links;
};

link_handle_t *init_link(void) {
    link_handle_t *handle = malloc(sizeof(link_handle_t));

    handle->links = NULL;

    return handle;
}

void destroy_link(link_handle_t *handle) {
    link_info_t *ptr = handle->links;

    while (ptr != NULL) {
        link_info_t *old = ptr;
        ptr = ptr->next;
        free(old->name);
        free(old->vlan_id);
        free(old);
    }

    handle->links = NULL;
    free(handle);
}

static char *format_payload(const link_info_t *link) {
    char *payload = malloc((size_t) MAX_PAYLOAD_SIZE);

    int len = snprintf(payload, MAX_PAYLOAD_SIZE - 1,
                       "time=%lu,idx=%d,name=%s,mac=%s",
                       time(NULL), link->index, link->name, format_mac(link->ll_addr));

    if (link->vlan_id && len < MAX_PAYLOAD_SIZE) {
        snprintf(payload + len, (size_t) (MAX_PAYLOAD_SIZE - len - 1),
                 ",vlan=%d", *(link->vlan_id));
    }

    return payload;
}

static uint16_t *int16dup(uint16_t *src) {
    if (!src) {
        return NULL;
    }
    uint16_t *dst = malloc(sizeof(uint16_t));
    *dst = *src;
    return dst;
}

static event_t *add_link(link_handle_t *handle, int index, const char *name,
                         uint8_t ll_addr[MAC_LEN], uint16_t *vlan_id) {
    link_info_t *ptr = NULL;

    // Look whether we already have it in our list...
    for (ptr = handle->links; ptr; ptr = ptr->next) {
        if (ptr->index != index) {
            continue;
        }
        if (memcmp(ptr->name, name, strlen(ptr->name)) != 0) {
            continue;
        }
        if (memcmp(ptr->ll_addr, ll_addr, MAC_LEN) != 0) {
            continue;
        }

        // Found it...
        log_debug("updating existing link (%s @ %d)", name, index);

        return create_event(LINK_UPDATE, format_payload(ptr));
    }

    assert(ptr == NULL);

    ptr = malloc(sizeof(link_info_t));
    ptr->index = index;
    ptr->name = strdup(name);
    ptr->vlan_id = int16dup(vlan_id);
    memcpy(ptr->ll_addr, ll_addr, MAC_LEN);
    ptr->next = handle->links;

    handle->links = ptr;

    log_debug("added new link (%s @ %d)", name, index);

    return create_event(LINK_ADD, format_payload(ptr));
}

static event_t *del_link(link_handle_t *handle, int index, const char *name,
                         uint8_t ll_addr[MAC_LEN]) {
    link_info_t *ptr = NULL, *prev = NULL;

    // Look whether we already have it in our list...
    for (ptr = handle->links; ptr; prev = ptr, ptr = ptr->next) {
        if (ptr->index != index) {
            continue;
        }
        if (memcmp(ptr->name, name, strlen(ptr->name)) != 0) {
            continue;
        }
        if (memcmp(ptr->ll_addr, ll_addr, MAC_LEN) != 0) {
            continue;
        }
        // Found it...
        break;
    }

    if (ptr == NULL) {
        log_debug("not deleting unknown link (%s @ %d)", name, index);
        return NULL;
    }

    if (prev != NULL) {
        // Remove intermediary item...
        prev->next = ptr->next;
    } else {
        // Remove first item...
        handle->links = ptr->next;
    }

    log_debug("deleted link (%s @ %d)", name, index);

    event_t *event = create_event(LINK_DELETE, format_payload(ptr));

    free(ptr->name);
    free(ptr->vlan_id);
    free(ptr);

    return event;
}

static int vlan_data_attr_cb(const struct nlattr *attr, void *data) {
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    // skip unsupported attribute in user-space
    if (mnl_attr_type_valid(attr, IFLA_VLAN_MAX) < 0) {
        return MNL_CB_OK;
    }

    switch (type) {
    case IFLA_VLAN_ID:
        VERIFY_attr(MNL_TYPE_U16);
        break;
    case IFLA_VLAN_PROTOCOL:
        VERIFY_attr(MNL_TYPE_U16);
        break;
    }
    tb[type] = attr;
    return MNL_CB_OK;
}

static int linkinfo_data_attr_cb(const struct nlattr *attr, void *data) {
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    // skip unsupported attribute in user-space
    if (mnl_attr_type_valid(attr, IFLA_INFO_MAX) < 0) {
        return MNL_CB_OK;
    }

    switch (type) {
    case IFLA_INFO_KIND:
        VERIFY_attr(MNL_TYPE_STRING);
        break;
    case IFLA_INFO_DATA:
        VERIFY_attr(MNL_TYPE_BINARY);
        break;
    }

    tb[type] = attr;
    return MNL_CB_OK;
}

static int link_data_attr_cb(const struct nlattr *attr, void *data) {
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    // skip unsupported attribute in user-space
    if (mnl_attr_type_valid(attr, IFLA_MAX) < 0) {
        return MNL_CB_OK;
    }

    switch (type) {
    case IFLA_ADDRESS:
        VERIFY_attr(MNL_TYPE_BINARY);
        break;
    case IFLA_MTU:
        VERIFY_attr(MNL_TYPE_U32);
        break;
    case IFLA_IFNAME:
        VERIFY_attr(MNL_TYPE_STRING);
        break;
    case IFLA_LINKINFO:
        VERIFY_attr(MNL_TYPE_BINARY);
        break;
    }

    tb[type] = attr;
    return MNL_CB_OK;
}

event_t *update_link(link_handle_t *handle, const struct nlmsghdr *nlh, int *result) {
    struct nlattr *tb[IFLA_MAX + 1] = { 0 };
    struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);

    *result = MNL_CB_OK;

    if (ifm->ifi_flags & IFF_LOOPBACK) {
        // Skip loopback interfaces...
        return NULL;
    }

    const char *name = NULL;
    uint8_t ll_addr[MAC_LEN] = { 0 };
    uint16_t *vlan_id = NULL;

    mnl_attr_parse(nlh, sizeof(*ifm), link_data_attr_cb, tb);
    if (tb[IFLA_IFNAME]) {
        name = mnl_attr_get_str(tb[IFLA_IFNAME]);
    }
    if (tb[IFLA_ADDRESS]) {
        uint8_t *hwaddr = mnl_attr_get_payload(tb[IFLA_ADDRESS]);

        if (!memcpy(&ll_addr, hwaddr, MAC_LEN)) {
            perror("memcpy");
            *result = MNL_CB_ERROR;
            return NULL;
        }
    }

    if (tb[IFLA_LINKINFO]) {
        struct nlattr *li_tb[IFLA_INFO_MAX + 1] = { 0 };

        mnl_attr_parse_nested(tb[IFLA_LINKINFO], linkinfo_data_attr_cb, li_tb);

        void *kind = mnl_attr_get_payload(li_tb[IFLA_INFO_KIND]);

        if (li_tb[IFLA_INFO_DATA] && memcmp(kind, "vlan", 4) == 0) {
            struct nlattr *vlan_tb[IFLA_VLAN_MAX + 1] = { 0 };

            mnl_attr_parse_nested(li_tb[IFLA_INFO_DATA], vlan_data_attr_cb, vlan_tb);

            if (vlan_tb[IFLA_VLAN_ID]) {
                uint16_t id = mnl_attr_get_u16(vlan_tb[IFLA_VLAN_ID]);
                vlan_id = &id;
            }
        }
    }

    const uint16_t type = nlh->nlmsg_type;
    if (type == RTM_NEWLINK) {
        return add_link(handle, ifm->ifi_index, name, ll_addr, vlan_id);
    } else if (type == RTM_DELLINK) {
        return del_link(handle, ifm->ifi_index, name, ll_addr);
    } else {
        log_warning("unsupported link_type = %02d!\n", type);
    }

    return NULL;
}
