/*
 * neigh.h
 *
 *  Created on: Jan 18, 2019
 *      Author: jawi
 */

#ifndef NEIGH_H_
#define NEIGH_H_

#include "event.h"

typedef struct neigh_handle neigh_handle_t;

neigh_handle_t *init_neigh(void);

void destroy_neigh(neigh_handle_t *handle);

event_t *update_neigh(neigh_handle_t *handle, const struct nlmsghdr *nlh, int *result);

#endif /* NEIGH_H_ */
