/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#ifndef _NATS_H_ // NATS_H_ is also used by nats.h itself!
#define _NATS_H_

#include <stddef.h>

#include "config.h"
#include "event.h"

#define MAX_TOPIC_NAME_LENGTH 256

typedef struct nats_handle nats_handle_t;

nats_handle_t *init_nats(void);

void destroy_nats(nats_handle_t *handle);

int connect_nats(nats_handle_t *handle, const config_t *cfg);

int disconnect_nats(nats_handle_t *handle);

void publish_nats(nats_handle_t *handle, const event_t *event);

#endif /* _NATS_H_ */
