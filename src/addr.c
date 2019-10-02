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
#include "addr.h"
#include "logging.h"
#include "mnl_extra.h"
#include "util.h"

typedef struct addr_info addr_info_t;

struct addr_info {
    addr_t addr;
    addr_info_t *next;
};

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

static void add_addr(addr_handle_t *handle, int32_t index,
                     uint8_t family, char addr[INET6_ADDRSTRLEN]) {
    addr_info_t *ptr = NULL;

    // Look whether we already have it in our list...
    for (ptr = handle->addresses; ptr; ptr = ptr->next) {
        const addr_t ptr_addr = ptr->addr;
        if (ptr_addr.index != index) {
            continue;
        }
        if (ptr_addr.family != family) {
            continue;
        }
        if (strncmp(ptr_addr.addr, addr, strlen(ptr_addr.addr)) != 0) {
            continue;
        }

        // Found it...
        log_debug("found known address (%s @ %d)", addr, index);

        return;
    }

    assert(ptr == NULL);

    ptr = malloc(sizeof(addr_info_t));
    ptr->addr.index = index;
    ptr->addr.family = family;
    memcpy(ptr->addr.addr, addr, INET6_ADDRSTRLEN);
    ptr->next = handle->addresses;

    handle->addresses = ptr;

    log_debug("added new address (%s @ %d)", addr, index);
}

static void del_addr(addr_handle_t *handle, int32_t index,
                     uint8_t family, char addr[INET6_ADDRSTRLEN]) {
    addr_info_t *ptr = NULL, *prev = NULL;

    // Look whether we already have it in our list...
    for (ptr = handle->addresses; ptr; prev = ptr, ptr = ptr->next) {
        const struct addr ptr_addr = ptr->addr;
        if (ptr_addr.index != index) {
            continue;
        }
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
        log_debug("ignoring unknown address (%s @ %d)", addr, index);
        return;
    }

    if (prev != NULL) {
        // Remove intermediary item...
        prev->next = ptr->next;
    } else {
        // Remove first item...
        handle->addresses = ptr->next;
    }

    log_debug("removed address (%s @ %d)", addr, index);

    free(ptr);
}

void free_addr(addr_t *addr) {
    if (addr) {
        memset(addr->addr, 0, sizeof(addr->addr));

        free(addr);
    }
}

addr_t *get_addr(addr_handle_t *handle, int32_t index) {
    addr_info_t *ptr = handle->addresses;

    while (ptr != NULL) {
        const addr_t ptr_addr = ptr->addr;
        if (ptr_addr.index != index) {
            ptr = ptr->next;
            continue;
        }

        // Found it, return a copy of the address data...
        addr_t *result = malloc(sizeof(addr_t));
        memcpy(result->addr, ptr_addr.addr, sizeof(ptr_addr.addr));
        result->family = ptr_addr.family;
        result->index = ptr_addr.index;
        return result;
    }

    return NULL;
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

void update_addr(addr_handle_t *handle, const struct nlmsghdr *nlh, int *result) {
    struct nlattr *tb[IFA_MAX + 1] = { 0 };
    struct ifaddrmsg *ifa = mnl_nlmsg_get_payload(nlh);

    if (ifa->ifa_scope != 0) {
        // Only global scope addresses...
        return;
    }

    mnl_attr_parse(nlh, sizeof(*ifa), addr_data_attr_cb, tb);
    if (tb[IFA_ADDRESS]) {
        void *attr_data = mnl_attr_get_payload(tb[IFA_ADDRESS]);

        char addr[INET6_ADDRSTRLEN];

        if (!inet_ntop(ifa->ifa_family, attr_data, addr, sizeof(addr))) {
            perror("inet_ntop");
            *result = MNL_CB_ERROR;
            return;
        }

        const uint16_t type = nlh->nlmsg_type;
        if (type == RTM_NEWADDR) {
            add_addr(handle, (int32_t) ifa->ifa_index, ifa->ifa_family, addr);
        } else if (type == RTM_DELADDR) {
            del_addr(handle, (int32_t) ifa->ifa_index, ifa->ifa_family, addr);
        } else {
            log_warning("unsupported addr_type = %02d!", type);
        }
    }
}

void dump_addr(addr_handle_t *handle) {
    addr_info_t *ptr = NULL;
	uint32_t idx = 0;

    for (ptr = handle->addresses; ptr; ptr = ptr->next, idx++) {
		log_info("[addr:%d] link_idx:%d, family:%d, addr:%s", idx,
			ptr->addr.index, ptr->addr.family, ptr->addr.addr);
    }
}
