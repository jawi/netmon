/*
 * mqtt.h
 *
 *  Created on: Jan 18, 2019
 *      Author: jawi
 */

#ifndef MQTT_H_
#define MQTT_H_

#include <stddef.h>

#include "config.h"
#include "event.h"

#define MAX_TOPIC_NAME_LENGTH 256

typedef struct mqtt_handle mqtt_handle_t;

mqtt_handle_t *init_mqtt(void);

void destroy_mqtt(mqtt_handle_t *handle);

int connect_mqtt(mqtt_handle_t *handle, const config_t *cfg);

int disconnect_mqtt(mqtt_handle_t *handle);

void publish_mqtt(mqtt_handle_t *handle, const event_t *event);


#endif /* MQTT_H_ */
