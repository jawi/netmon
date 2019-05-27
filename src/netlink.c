/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

#include "addr.h"
#include "config.h"
#include "link.h"
#include "logging.h"
#include "neigh.h"
#include "netlink.h"

struct netlink_handle {
    addr_handle_t *addr;
    link_handle_t *link;
    neigh_handle_t *neigh;

    netlink_event_callback_t callback;
    struct mnl_socket *sock;
    uint32_t seqNo;
};

netlink_handle_t *init_netlink(netlink_event_callback_t callback) {
    netlink_handle_t *handle = malloc(sizeof(netlink_handle_t));
    if (!handle) {
        log_error("failed to create netlink handle: out of memory!");
        return NULL;
    }

    handle->seqNo = 0;
    handle->callback = callback;
    handle->addr = init_addr();
    handle->link = init_link();
    handle->neigh = init_neigh();

    return handle;
}

void destroy_netlink(netlink_handle_t *handle) {
    if (handle) {
        destroy_addr(handle->addr);
        destroy_link(handle->link);
        destroy_neigh(handle->neigh);

        free(handle);
    }
}

static int netlink_data_cb(const struct nlmsghdr *nlh, void *data) {
    const netlink_handle_t *handle = (netlink_handle_t *)data;
    const uint16_t type = nlh->nlmsg_type;

    int ret = MNL_CB_OK;
    if (type == RTM_NEWLINK || type == RTM_DELLINK) {
        update_link(handle->link, nlh, &ret);
    } else if (type == RTM_NEWADDR || type == RTM_DELADDR) {
        update_addr(handle->addr, nlh, &ret);
    } else if (type == RTM_NEWNEIGH || type == RTM_DELNEIGH) {
        neigh_t *neigh = update_neigh(handle->neigh, nlh, &ret);
        if (neigh) {
            addr_t *addr = get_addr(handle->addr, neigh->index);
            link_t *link = get_link(handle->link, neigh->index);

            event_t *event = create_event(NEIGHBOUR_UPDATE, addr, link, neigh);

            if (event) {
                (handle->callback)(event);
            }

            free_addr(addr);
            free_link(link);
        }
        free(neigh);
    } else {
        log_warning("Unhandled netlink message with type: %02d", type);
    }

    return ret;
}

static int netlink_recv_data(netlink_handle_t *handle, uint32_t expectedSeqNo) {
    char buf[MNL_SOCKET_BUFFER_SIZE];
    int ret = 0;

    do {
        ssize_t rec = mnl_socket_recvfrom(handle->sock, buf, sizeof(buf));
        if (rec < 0) {
            return -1;
        }

        ret = mnl_cb_run(buf, (size_t) rec, expectedSeqNo, 0, netlink_data_cb, handle);
    } while (ret > 0);

    return 0;
}

static int netlink_send_data(netlink_handle_t *handle, const uint16_t msg_type) {
    char buf[MNL_SOCKET_BUFFER_SIZE];

    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_type = msg_type;
    nlh->nlmsg_seq = ++(handle->seqNo);

    struct rtgenmsg *rt = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
    rt->rtgen_family = AF_UNSPEC;

    ssize_t sent = mnl_socket_sendto(handle->sock, nlh, nlh->nlmsg_len);
    if (sent != nlh->nlmsg_len) {
        log_warning("message not sent completely! Only %d of %d bytes were sent.", sent, nlh->nlmsg_len);
        return -1;
    }

    return 0;
}

int connect_netlink(netlink_handle_t *handle) {
    handle->sock = mnl_socket_open(NETLINK_ROUTE);
    if (!handle->sock) {
        log_error("failed to open netlink socket: %m");
        return -1;
    }

    if (mnl_socket_bind(handle->sock,
                        RTMGRP_NEIGH | RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR,
                        MNL_SOCKET_AUTOPID) < 0) {
        log_error("failed to bind netlink socket: %m");
        return -1;
    }

    netlink_send_data(handle, RTM_GETADDR);
    netlink_recv_data(handle, handle->seqNo);

    netlink_send_data(handle, RTM_GETLINK);
    netlink_recv_data(handle, handle->seqNo);

    netlink_send_data(handle, RTM_GETNEIGH);
    netlink_recv_data(handle, handle->seqNo);

    return 0;
}

int disconnect_netlink(netlink_handle_t *handle) {
    int status = mnl_socket_close(handle->sock);
    if (status) {
        log_warning("failed to disconnect from netlink socket!");
        return -1;
    }

    handle->sock = NULL;

    log_debug("netlink connection teardown complete");

    return 0;
}

int netlink_loop(netlink_handle_t *handle) {
    int status = netlink_recv_data(handle, 0);
    if (status) {
        log_warning("failed to receive data!");
        return -1;
    }

    return 0;
}
