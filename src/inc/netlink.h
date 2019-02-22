/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#ifndef NETLINK_H_
#define NETLINK_H_

#include "event.h"

typedef struct netlink_handle netlink_handle_t;

typedef void (*netlink_event_callback_t)(event_t *event);

netlink_handle_t *init_netlink(netlink_event_callback_t callback);

void destroy_netlink(netlink_handle_t *handle);

int connect_netlink(netlink_handle_t *handle);
int disconnect_netlink(netlink_handle_t *handle);

int netlink_loop(netlink_handle_t *handle);

#endif /* NETLINK_H_ */
