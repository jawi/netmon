#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "event.h"
#include "logging.h"
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

#define INITIAL_BUFFER_SIZE 256

event_t *create_event(event_type_t event_type, const char *fmt, ...) {
    va_list ap;
    char *payload = NULL;
    size_t bufsize = INITIAL_BUFFER_SIZE;

    do {
        payload = malloc(bufsize*sizeof(char));
        if (payload == NULL) {
            log_error("failed to allocate memory for event payload buffer!");
            return NULL;
        }

        va_start(ap, fmt);

        size_t written = (size_t) vsnprintf(payload, bufsize, fmt, ap);

        va_end(ap);

        if (written < 0) {
            // generic failure...
            log_error("vnsprintf failed for event payload: %m");
            free(payload);
            return NULL;
        } else if (written >= bufsize) {
            // buffer was not large enough...
            log_debug("did not allocate enough room for event payload: need %d extra bytes...",
                      (written - bufsize));

            bufsize = written + 1;

            free(payload);
            payload = NULL;
        }
    } while (payload == NULL);

    event_t *result = malloc(sizeof(event_t));
    if (result == NULL) {
        log_error("failed to allocate memory for event!");
        return NULL;
    }

    result->event_type = event_type;
    result->data = payload;

    return result;
}

void free_event(event_t *event) {
    free(event->data);
    free(event);
}
