/*
 * event.h
 *
 *  Created on: Jan 19, 2019
 *      Author: jawi
 */

#ifndef EVENT_H_
#define EVENT_H_

#include <stddef.h>

typedef enum event_type {
    LINK_ADD,
    LINK_UPDATE,
    LINK_DELETE,
    ADDRESS_ADD,
    ADDRESS_UPDATE,
    ADDRESS_DELETE,
    NEIGHBOUR_ADD,
    NEIGHBOUR_UPDATE,
    NEIGHBOUR_DELETE,
    event_type_count,
} event_type_t;

typedef struct event {
    event_type_t event_type;
    char *data;
} event_t;

const char *event_topic_name(event_type_t event_type);

event_t *create_event(event_type_t event_type, char *data);

void free_event(event_t *event);

#endif /* EVENT_H_ */