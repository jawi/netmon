#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libmnl/libmnl.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "addr_common.h"
#include "event.h"
#include "neigh.h"
#include "mqtt.h"
#include "mnl_extra.h"
#include "logging.h"
#include "util.h"

typedef struct neighbour_info {
    int index;
    uint16_t state;
    uint8_t ll_addr[MAC_LEN];
    struct addr dst_addr;
    struct neighbour_info *next;
} neighbour_info_t;

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

static char *format_state(const uint16_t state) {
    switch (state) {
    case NUD_INCOMPLETE:
        return "incomplete";
    case NUD_REACHABLE:
        return "reachable";
    case NUD_STALE:
        return "stale";
    case NUD_DELAY:
        return "delayed";
    case NUD_PROBE:
        return "probing";
    case NUD_FAILED:
        return "failed";
    default:
        return "unknown";
    }
}

static inline event_t *create_neigh_event(event_type_t event_type, neighbour_info_t *ptr) {
    return create_event(event_type, "time=%lu,idx=%d,addr=%s,mac=%s,state=%s",
                        time(NULL), ptr->index, ptr->dst_addr.addr, format_mac(ptr->ll_addr),
                        format_state(ptr->state));
}

static event_t *add_neigh(neigh_handle_t *handle, int index, uint8_t family,
                          char dst_ip[INET6_ADDRSTRLEN], uint8_t ll_addr[MAC_LEN],
                          uint16_t state) {
    neighbour_info_t *ptr = NULL;

    // Look whether we already have it in our list...
    for (ptr = handle->neighbours; ptr; ptr = ptr->next) {
        if (ptr->index != index) {
            continue;
        }
        const struct addr dst_addr = ptr->dst_addr;
        if (dst_addr.family != family) {
            continue;
        }
        if (strncmp(dst_addr.addr, dst_ip, strlen(dst_addr.addr)) != 0) {
            continue;
        }
        if (memcmp(ptr->ll_addr, ll_addr, MAC_LEN) != 0) {
            continue;
        }

        // Found it...
        uint16_t old_state = ptr->state;
        ptr->state = state;

        log_debug("updating existing neighbour (%s <=> %s), state = %d vs %d)",
                  dst_ip, format_mac(ll_addr), old_state, state);

        return create_neigh_event(NEIGHBOUR_UPDATE, ptr);
    }

    assert(ptr == NULL);

    ptr = malloc(sizeof(neighbour_info_t));
    ptr->index = index;
    ptr->state = state;
    ptr->dst_addr.family = family;
    memcpy(ptr->dst_addr.addr, dst_ip, INET6_ADDRSTRLEN);
    memcpy(ptr->ll_addr, ll_addr, MAC_LEN);
    ptr->next = handle->neighbours;

    handle->neighbours = ptr;

    log_debug("added new neighbour (%s <=> %s), state = %d",
              dst_ip, format_mac(ll_addr), state);

    return create_neigh_event(NEIGHBOUR_ADD, ptr);
}

static event_t *del_neigh(neigh_handle_t *handle, int index, uint8_t family,
                          char dst_ip[INET6_ADDRSTRLEN]) {
    neighbour_info_t *ptr = NULL, *prev = NULL;

    // Look whether we already have it in our list...
    for (ptr = handle->neighbours; ptr; prev = ptr, ptr = ptr->next) {
        if (ptr->index != index) {
            continue;
        }
        const struct addr dst_addr = ptr->dst_addr;
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
        log_debug("not deleting unknown neighbour (%s)", dst_ip);
        return NULL;
    }

    if (prev != NULL) {
        // Remove intermediary item...
        prev->next = ptr->next;
    } else {
        // Remove first item...
        handle->neighbours = ptr->next;
    }

    log_debug("deleted neighbour (%s <=> %s)", dst_ip, format_mac(ptr->ll_addr));

    event_t *event = create_neigh_event(NEIGHBOUR_DELETE, ptr);

    free(ptr);

    return event;
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

event_t *update_neigh(neigh_handle_t *handle, const struct nlmsghdr *nlh, int *result) {
    struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);

    *result = MNL_CB_OK;

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
            return del_neigh(handle, ndm->ndm_ifindex, ndm->ndm_family, dst_ip);
        } else if (tb[NDA_LLADDR]) {
            return add_neigh(handle, ndm->ndm_ifindex, ndm->ndm_family, dst_ip, ll_addr, ndm->ndm_state);
        } else {
            log_debug("neigh_data_cb[type = %02x], dst_ip = %s, mac = %s, state = %02x\n",
                      nlh->nlmsg_type, dst_ip, format_mac(ll_addr), ndm->ndm_state);
        }
    } else if (type == RTM_DELNEIGH && tb[NDA_DST]) {
        return del_neigh(handle, ndm->ndm_ifindex, ndm->ndm_family, dst_ip);
    } else {
        log_debug("neigh_data_cb[type = %02x], dst_ip = %s, mac = %s, state = %02x\n",
                  nlh->nlmsg_type, dst_ip, format_mac(ll_addr), ndm->ndm_state);
    }

    return NULL;
}
