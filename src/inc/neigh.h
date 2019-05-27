/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#ifndef NEIGH_H_
#define NEIGH_H_

typedef struct neigh_handle neigh_handle_t;

neigh_handle_t *init_neigh(void);

void destroy_neigh(neigh_handle_t *handle);

neigh_t *update_neigh(neigh_handle_t *handle, const struct nlmsghdr *nlh, int *result);

#endif /* NEIGH_H_ */
