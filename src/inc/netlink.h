/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#ifndef NETLINK_H_
#define NETLINK_H_

#include "event.h"
#include "addr.h"
#include "link.h"
#include "neigh.h"

/**
 * Defines the handle that is to be used to talk to the Netlink routines.
 */
typedef struct netlink_handle netlink_handle_t;

/**
 * Callback method in case of events.
 */
typedef void (*netlink_event_callback_t)(event_t *event);

/**
 * Allocates and initializes the Netlink routines. Note that no connection to Netlink is opened, see @see #connect_netlink!
 */
netlink_handle_t *init_netlink(netlink_event_callback_t callback);

/**
 * Destroys a previously created netlink handle.
 *
 * @param handle the netlink handle.
 */
void destroy_netlink(netlink_handle_t *handle);

/**
 * Connects to the Netlink API.
 *
 * @param handle the netlink handle.
 */
int connect_netlink(netlink_handle_t *handle);

/**
 * Disconnects from the Netlink API.
 *
 * @param handle the netlink handle.
 */
int disconnect_netlink(netlink_handle_t *handle);

/**
 * Returns the file descriptor for Netlink.
 *
 * @param handle the netlink handle.
 * @returns a Netlink file descriptor, or -1 in case of an error.
 */
int netlink_fd(const netlink_handle_t *handle);

/**
 * Performs a read cycle for Netlink.
 *
 * @param handle the netlink handle.
 */
int netlink_read_data(const netlink_handle_t *handle);

/**
 * Dumps the private information of the Netlink routines.
 */
void netlink_dump_data(const netlink_handle_t *handle);

#endif /* NETLINK_H_ */
