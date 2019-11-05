/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#ifndef LINK_H_
#define LINK_H_

#include <libmnl/libmnl.h>

typedef struct link_handle link_handle_t;

link_handle_t *init_link(void);

void destroy_link(link_handle_t *handle);

void update_link(link_handle_t *handle, const struct nlmsghdr *nlh, int *result);

link_t *get_link(link_handle_t *handle, int32_t index);

void free_link(link_t *link);

void dump_link(link_handle_t *handle);

#endif /* LINK_H_ */
