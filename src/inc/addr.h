/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#ifndef ADDR_H_
#define ADDR_H_

#include "addr_common.h"
#include "event.h"

typedef struct addr_handle addr_handle_t;

addr_handle_t *init_addr(void);

void destroy_addr(addr_handle_t *handle);

event_t *update_addr(addr_handle_t *handle, const struct nlmsghdr *nlh, int *result);

#endif /* ADDR_H_ */
