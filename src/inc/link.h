/*
 * link.h
 *
 *  Created on: Jan 18, 2019
 *      Author: jawi
 */

#ifndef LINK_H_
#define LINK_H_

#include "event.h"

typedef struct link_handle link_handle_t;

link_handle_t *init_link(void);

void destroy_link(link_handle_t *handle);

event_t *update_link(link_handle_t *handle, const struct nlmsghdr *nlh, int *result);

#endif /* LINK_H_ */
