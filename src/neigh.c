/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libmnl/libmnl.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "addr_common.h"
#include "neigh.h"
#include "mnl_extra.h"
#include "logging.h"
#include "util.h"

typedef struct neighbour_info neighbour_info_t;

struct neighbour_info {
    neigh_t neigh;
    neighbour_info_t *next;
};

struct neigh_handle {
    neighbour_info_t *neighbours;
};

neigh_handle_t *init_neigh(void) {
    neigh_handle_t *handle = malloc(sizeof(neigh_handle_t));

    handle->neighbours = NULL;

    return handle;
}

void destroy_neigh(neigh_handle_t *handle) {
    neighbour_info_t *ptr = handle->neighbours;

    while (ptr != NULL) {
        neighbour_info_t *old = ptr;
        ptr = ptr->next;
        free(old);
    }

    handle->neighbours = NULL;
    free(handle);
}

static neigh_t *copy_neigh(const neigh_t *src) {
    neigh_t *result = malloc(sizeof(neigh_t));
    memcpy(result->ll_addr, src->ll_addr, sizeof(src->ll_addr));
    result->index = src->index;
    result->dst_addr = src->dst_addr;
    result->state = src->state;
    return result;
}

static neigh_t *add_neigh(neigh_handle_t *handle, int32_t index, uint8_t family,
                          char dst_ip[INET6_ADDRSTRLEN], uint8_t ll_addr[MAC_LEN],
                          uint16_t state) {
    neighbour_info_t *ptr = NULL;

    // Look whether we already have it in our list...
    for (ptr = handle->neighbours; ptr; ptr = ptr->next) {
        neigh_t ptr_neigh = ptr->neigh;
        if (ptr_neigh.index != index) {
            continue;
        }

        const addr_t dst_addr = ptr_neigh.dst_addr;
        if (dst_addr.family != family) {
            continue;
        }
        if (strncmp(dst_addr.addr, dst_ip, strlen(dst_addr.addr)) != 0) {
            continue;
        }
        if (memcmp(ptr->neigh.ll_addr, ll_addr, MAC_LEN) != 0) {
            continue;
        }

        // Found it...
        uint16_t old_state = ptr_neigh.state;
        ptr_neigh.state = state;

        log_debug("updating existing neighbour (%s <=> %s), state = %d vs %d)",
                  dst_ip, format_mac(ll_addr), old_state, state);

        return copy_neigh(&ptr->neigh);
    }

    assert(ptr == NULL);

    ptr = malloc(sizeof(neighbour_info_t));
    ptr->neigh.index = index;
    ptr->neigh.state = state;
    ptr->neigh.dst_addr.family = family;
    memcpy(ptr->neigh.dst_addr.addr, dst_ip, INET6_ADDRSTRLEN);
    memcpy(ptr->neigh.ll_addr, ll_addr, MAC_LEN);
    ptr->next = handle->neighbours;

    handle->neighbours = ptr;

    log_debug("added new neighbour (%s <=> %s), state = %d",
              dst_ip, format_mac(ll_addr), state);

    return copy_neigh(&ptr->neigh);
}

static neigh_t *del_neigh(neigh_handle_t *handle, int index, uint8_t family,
                          char dst_ip[INET6_ADDRSTRLEN]) {
    neighbour_info_t *ptr = NULL, *prev = NULL;

    // Look whether we already have it in our list...
    for (ptr = handle->neighbours; ptr; prev = ptr, ptr = ptr->next) {
        const neigh_t ptr_neigh = ptr->neigh;
        if (ptr_neigh.index != index) {
            continue;
        }
        const addr_t dst_addr = ptr->neigh.dst_addr;
        if (dst_addr.family != family) {
            continue;
        }
        if (strncmp(dst_addr.addr, dst_ip, strlen(dst_addr.addr)) != 0) {
            continue;
        }
        // Found it...
        break;
    }

    if (ptr == NULL) {
        log_debug("ignoring unknown neighbour (%s)", dst_ip);
        return NULL;
    }

    if (prev != NULL) {
        // Remove intermediary item...
        prev->next = ptr->next;
    } else {
        // Remove first item...
        handle->neighbours = ptr->next;
    }

    log_debug("deleted neighbour (%s <=> %s)", dst_ip, format_mac(ptr->neigh.ll_addr));

    neigh_t *result = copy_neigh(&ptr->neigh);

    free(ptr);

    return result;
}

static int neigh_data_attr_cb(const struct nlattr *attr, void *data) {
    const struct nlattr **tb = data;

    // skip unsupported attributes
    if (mnl_attr_type_valid(attr, NDA_MAX) < 0) {
        return MNL_CB_OK;
    }

    int type = mnl_attr_get_type(attr);
    if (type == NDA_DST || type == NDA_LLADDR) {
        VERIFY_attr(MNL_TYPE_BINARY);
    }

    tb[type] = attr;

    return MNL_CB_OK;
}

neigh_t *update_neigh(neigh_handle_t *handle, const struct nlmsghdr *nlh, int *result) {
    struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);

    if (ndm->ndm_state == NUD_NOARP || ndm->ndm_state == NUD_PERMANENT) {
        // Not interested...
        return NULL;
    }

    char dst_ip[INET6_ADDRSTRLEN] = { 0 };
    uint8_t ll_addr[MAC_LEN] = { 0 };

    struct nlattr *tb[NDA_MAX + 1] = { 0 };
    mnl_attr_parse(nlh, sizeof(*ndm), neigh_data_attr_cb, tb);

    if (tb[NDA_DST]) {
        void *addr = mnl_attr_get_payload(tb[NDA_DST]);

        if (!inet_ntop(ndm->ndm_family, addr, dst_ip, INET6_ADDRSTRLEN)) {
            log_error("failed to convert IP address to string: %s", strerror(errno));
            *result = MNL_CB_ERROR;
            return NULL;
        }
    }

    if (tb[NDA_LLADDR]) {
        void *addr = mnl_attr_get_payload(tb[NDA_LLADDR]);

        memcpy(&ll_addr, addr, MAC_LEN);
    }

    const uint16_t type = nlh->nlmsg_type;
    if (type == RTM_NEWNEIGH && tb[NDA_DST]) {
        if (ndm->ndm_state == NUD_FAILED) {
            return del_neigh(handle, (int32_t) ndm->ndm_ifindex, ndm->ndm_family, dst_ip);
        } else if (tb[NDA_LLADDR]) {
            return add_neigh(handle, (int32_t) ndm->ndm_ifindex, ndm->ndm_family, dst_ip, ll_addr, ndm->ndm_state);
        } else {
            log_debug("neigh_data_cb[type = %02x], dst_ip = %s, mac = %s, state = %02x\n",
                      nlh->nlmsg_type, dst_ip, format_mac(ll_addr), ndm->ndm_state);
        }
    } else if (type == RTM_DELNEIGH && tb[NDA_DST]) {
        return del_neigh(handle, (int32_t) ndm->ndm_ifindex, ndm->ndm_family, dst_ip);
    } else {
        log_debug("neigh_data_cb[type = %02x], dst_ip = %s, mac = %s, state = %02x\n",
                  nlh->nlmsg_type, dst_ip, format_mac(ll_addr), ndm->ndm_state);
    }

    return NULL;
}

void dump_neigh(neigh_handle_t *handle) {
    neighbour_info_t *ptr = NULL;
	uint32_t idx = 0;

    for (ptr = handle->neighbours; ptr; ptr = ptr->next, idx++) {
		log_info("[neigh:%d] link_idx:%d, state:%d, mac:%s, addr:%s", idx,
			ptr->neigh.index, ptr->neigh.state, format_mac(ptr->neigh.ll_addr), ptr->neigh.dst_addr.addr);
	}
}
