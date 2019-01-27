#include <stdlib.h>

#include "event.h"
#include "netmon.h"

#define LINK "link/"
#define ADDR "address/"
#define NEIGH "neighbour/"

#define ADD "add"
#define UPD "update"
#define DEL "delete"

const char *event_topic_names[event_type_count] = {
    TOPIC_PREFIX LINK ADD,
    TOPIC_PREFIX LINK UPD,
    TOPIC_PREFIX LINK DEL,
    TOPIC_PREFIX ADDR ADD,
    TOPIC_PREFIX ADDR UPD,
    TOPIC_PREFIX ADDR DEL,
    TOPIC_PREFIX NEIGH ADD,
    TOPIC_PREFIX NEIGH UPD,
    TOPIC_PREFIX NEIGH DEL,
};

const char *event_topic_name(event_type_t event_type) {
    return event_topic_names[event_type];
}

event_t *create_event(event_type_t event_type, char *data) {
    event_t *result = malloc(sizeof(event_t));
    result->event_type = event_type;
    result->data = data;
    return result;
}

void free_event(event_t *event) {
    free(event->data);
    free(event);
}
