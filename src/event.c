/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>

#include "addr_common.h"
#include "event.h"
#include "logging.h"
#include "netmon.h"
#include "util.h"

const char *event_topic_names[event_type_count] = {
    "netmon.neigh"
};

const char *event_topic_name(event_type_t event_type) {
    return event_topic_names[event_type];
}

#define INITIAL_BUFFER_SIZE 256

#define BUFFER_ADD(...)                                                        \
  do {                                                                         \
    int status;                                                                \
    status = snprintf(buffer + offset, buffer_size - offset, __VA_ARGS__);     \
    if (status < 1) {                                                          \
      free(buffer);                                                            \
      return NULL;                                                             \
    } else if (((size_t)status) >= (buffer_size - offset)) {                   \
      free(buffer);                                                            \
      return NULL;                                                             \
    } else                                                                     \
      offset += ((size_t)status);                                              \
  } while (0)

event_t *create_event(event_type_t event_type, const addr_t *src_addr, const link_t *src_link, const neigh_t *neigh) {
    size_t offset = 0;
    size_t buffer_size = INITIAL_BUFFER_SIZE;
    char *buffer = malloc(buffer_size * sizeof(char));

    BUFFER_ADD("{\"last_seen\":%lu,\"addr\":\"%s\",\"mac\":\"%s\"",
               time(NULL), neigh->dst_addr.addr, format_mac(neigh->ll_addr));

    if (src_addr || src_link) {
        BUFFER_ADD(",\"src\":{");
        if (src_link) {
            BUFFER_ADD("\"iface\":\"%s\",\"mac\":\"%s\"",
                       src_link->name, format_mac(src_link->ll_addr));
            if (src_link->vlan_id) {
                BUFFER_ADD(",\"vlan\":%d", *src_link->vlan_id);
            }
        }
        if (src_addr) {
            BUFFER_ADD(",\"ip\":\"%s\"", src_addr->addr);
        }
        BUFFER_ADD("}");
    }

    BUFFER_ADD("}");

    event_t *result = malloc(sizeof(event_t));
    if (result == NULL) {
        log_error("failed to allocate memory for event!");
        return NULL;
    }

    result->event_type = event_type;
    result->data = buffer;

    return result;
}

void free_event(event_t *event) {
    free(event->data);
    free(event);
}
