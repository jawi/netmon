/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

#include "addr_common.h"
#include "link.h"
#include "logging.h"
#include "mnl_extra.h"
#include "util.h"

typedef struct link_info link_info_t;

struct link_info {
    link_t link;
    link_info_t *next;
};

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
        free(old->link.name);
        free(old->link.vlan_id);
        free(old);
    }

    handle->links = NULL;
    free(handle);
}

static uint16_t *int16dup(const uint16_t *src) {
    if (!src) {
        return NULL;
    }
    uint16_t *dst = malloc(sizeof(uint16_t));
    *dst = *src;
    return dst;
}

static void add_link(link_handle_t *handle, int index, const char *name,
                     uint8_t ll_addr[MAC_LEN], const uint16_t *vlan_id) {
    link_info_t *ptr = NULL;

    // Look whether we already have it in our list...
    for (ptr = handle->links; ptr; ptr = ptr->next) {
        const link_t ptr_link = ptr->link;
        if (ptr_link.index != index) {
            continue;
        }
        if (memcmp(ptr_link.name, name, strlen(ptr_link.name)) != 0) {
            continue;
        }
        if (memcmp(ptr_link.ll_addr, ll_addr, MAC_LEN) != 0) {
            continue;
        }

        // Found it...
        log_debug("found known link (%s @ %d)", name, index);

        return;
    }

    assert(ptr == NULL);

    ptr = malloc(sizeof(link_info_t));
    ptr->link.index = index;
    ptr->link.name = strdup(name);
    ptr->link.vlan_id = int16dup(vlan_id);
    memcpy(ptr->link.ll_addr, ll_addr, MAC_LEN);
    ptr->next = handle->links;

    handle->links = ptr;

    log_debug("added new link (%s @ %d)", name, index);
}

static void del_link(link_handle_t *handle, int index, const char *name,
                     uint8_t ll_addr[MAC_LEN]) {
    link_info_t *ptr = NULL, *prev = NULL;

    // Look whether we already have it in our list...
    for (ptr = handle->links; ptr; prev = ptr, ptr = ptr->next) {
        const link_t ptr_link = ptr->link;
        if (ptr_link.index != index) {
            continue;
        }
        if (memcmp(ptr_link.name, name, strlen(ptr_link.name)) != 0) {
            continue;
        }
        if (memcmp(ptr_link.ll_addr, ll_addr, MAC_LEN) != 0) {
            continue;
        }
        // Found it...
        break;
    }

    if (ptr == NULL) {
        log_debug("ignoring unknown link (%s @ %d)", name, index);
        return;
    }

    if (prev != NULL) {
        // Remove intermediary item...
        prev->next = ptr->next;
    } else {
        // Remove first item...
        handle->links = ptr->next;
    }

    log_debug("deleted link (%s @ %d)", name, index);

    free(ptr->link.name);
    free(ptr->link.vlan_id);
    free(ptr);
}

void free_link(link_t *link) {
    if (link) {
        free(link->name);
        free(link->vlan_id);
        memset(link->ll_addr, 0, sizeof(link->ll_addr));
        free(link);
    }
}

link_t *get_link(link_handle_t *handle, int32_t index) {
    link_info_t *ptr = handle->links;

    while (ptr != NULL) {
        const link_t ptr_link = ptr->link;
        if (ptr_link.index != index) {
            ptr = ptr->next;
            continue;
        }

        // Found it, return a copy of the link data...
        link_t *result = malloc(sizeof(link_t));
        result->name = strdup(ptr_link.name);
        result->vlan_id = int16dup(ptr_link.vlan_id);
        memcpy(result->ll_addr, ptr_link.ll_addr, sizeof(ptr_link.ll_addr));
        return result;
    }

    return NULL;
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

void update_link(link_handle_t *handle, const struct nlmsghdr *nlh, int *result) {
    struct nlattr *tb[IFLA_MAX + 1] = { 0 };
    struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);

    *result = MNL_CB_OK;

    if (ifm->ifi_flags & IFF_LOOPBACK) {
        // Skip loopback interfaces...
        return;
    }

    const char *name = NULL;
    uint8_t ll_addr[MAC_LEN] = { 0 };
    const uint16_t *vlan_id = NULL;

    mnl_attr_parse(nlh, sizeof(*ifm), link_data_attr_cb, tb);
    if (tb[IFLA_IFNAME]) {
        name = mnl_attr_get_str(tb[IFLA_IFNAME]);
    }
    if (tb[IFLA_ADDRESS]) {
        uint8_t *hwaddr = mnl_attr_get_payload(tb[IFLA_ADDRESS]);

        if (!memcpy(&ll_addr, hwaddr, MAC_LEN)) {
            perror("memcpy");
            *result = MNL_CB_ERROR;
            return;
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
                vlan_id = (uint16_t *)mnl_attr_get_payload(vlan_tb[IFLA_VLAN_ID]);
            }
        }
    }

    const uint16_t type = nlh->nlmsg_type;
    if (type == RTM_NEWLINK) {
        add_link(handle, ifm->ifi_index, name, ll_addr, vlan_id);
    } else if (type == RTM_DELLINK) {
        del_link(handle, ifm->ifi_index, name, ll_addr);
    } else {
        log_warning("unsupported link_type = %02d!\n", type);
    }
}
