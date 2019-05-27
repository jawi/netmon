/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#ifndef EVENT_H_
#define EVENT_H_

#include <stddef.h>

#include "addr_common.h"

typedef enum event_type {
    NEIGHBOUR_UPDATE,
    event_type_count,
} event_type_t;

typedef struct event {
    event_type_t event_type;
    char *data;
} event_t;

const char *event_topic_name(event_type_t event_type);

event_t *create_event(event_type_t event_type, const addr_t *src_addr, const link_t *src_link, const neigh_t *neigh);

void free_event(event_t *event);

#endif /* EVENT_H_ */