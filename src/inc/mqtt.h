/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#ifndef MQTT_H_
#define MQTT_H_

#include <stddef.h>

#include "config.h"
#include "event.h"

#define MAX_TOPIC_NAME_LENGTH 256

/**
 * Defines the handle that is to be used to talk to the MQTT routines.
 */
typedef struct mqtt_handle mqtt_handle_t;

/**
 * Allocates and initializes a new MQTT handle, but does not connect to MQTT yet, @see #connect_mqtt.
 *
 * @returns a new #mqtt_handle_t instance, or NULL in case no memory was available.
 */
mqtt_handle_t *init_mqtt(void);

/**
 * Destroys and frees all previously allocated resources.
 *
 * @param handle the MQTT handle.
 */
void destroy_mqtt(mqtt_handle_t *handle);

/**
 * Connects to MQTT using a given configuration.
 *
 * @param handle the MQTT handle;
 * @param config the configuration options.
 * @return 0 upon success, or a non-zero value in case of errors.
 */
int connect_mqtt(mqtt_handle_t *handle, const config_t *config);

/**
 * Disconnects from a MQTT server.
 *
 * @param handle the MQTT handle.
 * @return 0 upon success, or a non-zero value in case of errors.
 */
int disconnect_mqtt(mqtt_handle_t *handle);

/**
 * Returns the file descriptor for MQTT.
 *
 * @param handle the MQTT handle.
 * @returns a MQTT file descriptor, or -1 in case of an error.
 */
int mqtt_fd(const mqtt_handle_t *handle);

/**
 * Performs a read cycle for Netlink.
 *
 * @param handle the MQTT handle.
 * @return 0 upon success, or a non-zero value in case of errors.
 */
int mqtt_read_data(mqtt_handle_t *handle);

/**
 * Performs a read cycle for Netlink.
 *
 * @param handle the MQTT handle.
 * @return 0 upon success, or a non-zero value in case of errors.
 */
int mqtt_write_data(mqtt_handle_t *handle);

/**
 * Returns whether or not MQTT wants to write data.
 *
 * @param handle the MQTT handle.
 * @return true if MQTT has data to write, false otherwise.
 */
bool mqtt_wants_to_write(const mqtt_handle_t *handle);

/**
 * Performs miscellaneous administrative tasks for MQTT.
 *
 * @param handle the MQTT handle.
 * @return 0 upon success, or a non-zero value in case of errors.
 */
int mqtt_update_administration(mqtt_handle_t *handle);

/**
 * Publishes a new event to MQTT.
 *
 * @param handle the MQTT handle;
 * @param event the event to publish.
 * @return 0 upon success, or a non-zero value in case of errors.
 */
int publish_mqtt(mqtt_handle_t *handle, const event_t *event);


#endif /* MQTT_H_ */
