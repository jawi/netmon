#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

#include "addr_common.h"
#include "addr.h"
#include "event.h"
#include "logging.h"
#include "mqtt.h"
#include "mnl_extra.h"
#include "util.h"

typedef struct addr_info {
    uint32_t index;
    struct addr addr;
    struct addr_info *next;
} addr_info_t;

struct addr_handle {
    addr_info_t *addresses;
};

addr_handle_t *init_addr(void) {
    addr_handle_t *handle = malloc(sizeof(addr_handle_t));

    handle->addresses = NULL;

    return handle;
}

void destroy_addr(addr_handle_t *handle) {
    addr_info_t *ptr = handle->addresses;

    while (ptr != NULL) {
        addr_info_t *old = ptr;
        ptr = ptr->next;
        free(old);
    }

    handle->addresses = NULL;
    free(handle);
}

static inline event_t *create_addr_event(event_type_t event_type, addr_info_t *ptr) {
    return create_event(event_type, "time=%lu,idx=%d,addr=%s",
                        time(NULL), ptr->index, ptr->addr.addr);
}

static event_t *add_addr(addr_handle_t *handle, uint32_t index,
                         uint8_t family, char addr[INET6_ADDRSTRLEN]) {
    addr_info_t *ptr = NULL;

    // Look whether we already have it in our list...
    for (ptr = handle->addresses; ptr; ptr = ptr->next) {
        if (ptr->index != index) {
            continue;
        }
        const struct addr ptr_addr = ptr->addr;
        if (ptr_addr.family != family) {
            continue;
        }
        if (strncmp(ptr_addr.addr, addr, strlen(ptr_addr.addr)) != 0) {
            continue;
        }

        // Found it...
        log_debug("updating existing address (%s @ %d)", addr, index);

        return create_addr_event(ADDRESS_UPDATE, ptr);
    }

    assert(ptr == NULL);

    ptr = malloc(sizeof(addr_info_t));
    ptr->index = index;
    ptr->addr.family = family;
    memcpy(ptr->addr.addr, addr, INET6_ADDRSTRLEN);
    ptr->next = handle->addresses;

    handle->addresses = ptr;

    log_debug("added new address (%s @ %d)", addr, index);

    return create_addr_event(ADDRESS_ADD, ptr);
}

static event_t *del_addr(addr_handle_t *handle, uint32_t index,
                         uint8_t family, char addr[INET6_ADDRSTRLEN]) {
    addr_info_t *ptr = NULL, *prev = NULL;

    // Look whether we already have it in our list...
    for (ptr = handle->addresses; ptr; prev = ptr, ptr = ptr->next) {
        if (ptr->index != index) {
            continue;
        }
        const struct addr ptr_addr = ptr->addr;
        if (ptr_addr.family != family) {
            continue;
        }
        if (strncmp(ptr_addr.addr, addr, strlen(ptr_addr.addr)) != 0) {
            continue;
        }
        // Found it...
        break;
    }

    if (ptr == NULL) {
        log_debug("not deleting unknown address (%s @ %d)", addr, index);
        return NULL;
    }

    if (prev != NULL) {
        // Remove intermediary item...
        prev->next = ptr->next;
    } else {
        // Remove first item...
        handle->addresses = ptr->next;
    }

    log_debug("deleted address (%s @ %d)", addr, index);

    event_t *event = create_addr_event(ADDRESS_DELETE, ptr);

    free(ptr);

    return event;
}

static int addr_data_attr_cb(const struct nlattr *attr, void *data) {
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    // skip unsupported attribute in user-space
    if (mnl_attr_type_valid(attr, IFA_MAX) < 0) {
        return MNL_CB_OK;
    }

    if (type == IFA_ADDRESS) {
        VERIFY_attr(MNL_TYPE_BINARY);
    }

    tb[type] = attr;
    return MNL_CB_OK;
}

event_t *update_addr(addr_handle_t *handle, const struct nlmsghdr *nlh, int *result) {
    struct nlattr *tb[IFA_MAX + 1] = { 0 };
    struct ifaddrmsg *ifa = mnl_nlmsg_get_payload(nlh);

    *result = MNL_CB_OK;

    if (ifa->ifa_scope != 0) {
        // Only global scope addresses...
        return NULL;
    }

    mnl_attr_parse(nlh, sizeof(*ifa), addr_data_attr_cb, tb);
    if (tb[IFA_ADDRESS]) {
        void *attr_data = mnl_attr_get_payload(tb[IFA_ADDRESS]);

        char addr[INET6_ADDRSTRLEN];

        if (!inet_ntop(ifa->ifa_family, attr_data, addr, sizeof(addr))) {
            perror("inet_ntop");
            *result = MNL_CB_ERROR;
            return NULL;
        }

        const uint16_t type = nlh->nlmsg_type;
        if (type == RTM_NEWADDR) {
            return add_addr(handle, ifa->ifa_index, ifa->ifa_family, addr);
        } else if (type == RTM_DELADDR) {
            return del_addr(handle, ifa->ifa_index, ifa->ifa_family, addr);
        } else {
            log_warning("unsupported addr_type = %02d!", type);
        }
    }

    return NULL;
}
