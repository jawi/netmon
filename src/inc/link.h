/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#ifndef LINK_H_
#define LINK_H_

#include "event.h"

typedef struct link_handle link_handle_t;

link_handle_t *init_link(void);

void destroy_link(link_handle_t *handle);

event_t *update_link(link_handle_t *handle, const struct nlmsghdr *nlh, int *result);

#endif /* LINK_H_ */
