/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#ifndef ADDR_H_
#define ADDR_H_

#include "addr_common.h"

typedef struct addr_handle addr_handle_t;

addr_handle_t *init_addr(void);

void destroy_addr(addr_handle_t *handle);

void update_addr(addr_handle_t *handle, const struct nlmsghdr *nlh, int *result);

addr_t *get_addr(addr_handle_t *handle, int32_t index);

void free_addr(addr_t *addr);

void dump_addr(addr_handle_t *handle);

#endif /* ADDR_H_ */
