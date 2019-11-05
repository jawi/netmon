/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <mosquitto.h>

#include "event.h"
#include "mqtt.h"
#include "logging.h"

#define MAX_RECONNECT_DELAY_VALUE 32

#define MOSQ_ERROR(s) \
	((s) == MOSQ_ERR_ERRNO) ? strerror(errno) : mosquitto_strerror((s))

typedef enum conn_state {
    INITIALIZED,
    NOT_CONNECTED,
    CONNECTED,
    RECONNECTING,
    DISCONNECTED,
} conn_state_t;

struct mqtt_handle {
    struct mosquitto *mosq;
    conn_state_t conn_state;
    char *host;
    int port;
    bool retain;
    int qos;

    time_t next_reconnect_attempt;
    int next_delay_value;
};

mqtt_handle_t *init_mqtt(void) {
    mosquitto_lib_init();

    mqtt_handle_t *handle = malloc(sizeof(mqtt_handle_t));
    if (!handle) {
        log_error("failed to create MQTT handle: out of memory!");
        return NULL;
    }

    handle->mosq = NULL;
    handle->conn_state = INITIALIZED;
    handle->retain = true;
    handle->qos = 0;
    handle->next_reconnect_attempt = -1L;
    handle->next_delay_value = 1;

    return handle;
}

static inline void internal_destroy_mqtt(mqtt_handle_t *handle) {
    if (handle) {
        mosquitto_destroy(handle->mosq);
        handle->mosq = NULL;
    }
}

void destroy_mqtt(mqtt_handle_t *handle) {
    if (handle) {
        internal_destroy_mqtt(handle);

        free(handle);
    }

    mosquitto_lib_cleanup();
}

static int internal_connect_mqtt(const mqtt_handle_t *handle) {
    int status = mosquitto_connect(handle->mosq, handle->host, handle->port, 60 /* keepalive */);
    if (status != MOSQ_ERR_SUCCESS) {
        log_warning("failed to connect to MQTT broker: %s", MOSQ_ERROR(status));
        return -1;
    }

    return 0;
}

static int internal_disconnect_mqtt(const mqtt_handle_t *handle) {
    int status = mosquitto_disconnect(handle->mosq);
    if (status != MOSQ_ERR_SUCCESS && status != MOSQ_ERR_NO_CONN) {
        log_warning("failed to disconnect from MQTT broker: %s", MOSQ_ERROR(status));
        return -1;
    }

    return 0;
}

static int internal_reconnect_mqtt(mqtt_handle_t *handle) {
    if (handle->conn_state == CONNECTED || handle->conn_state == DISCONNECTED) {
        return 0;
    }

    time_t now = time(NULL);
    if (handle->conn_state == RECONNECTING && handle->next_reconnect_attempt >= now) {
        return 1;
    }

    handle->conn_state = RECONNECTING;

    int status = mosquitto_reconnect(handle->mosq);
    if (status != MOSQ_ERR_SUCCESS) {
        log_debug("failed to reconnect to MQTT broker: %s", MOSQ_ERROR(status));

        handle->next_reconnect_attempt = now + handle->next_delay_value;

        if (handle->next_delay_value < MAX_RECONNECT_DELAY_VALUE) {
            handle->next_delay_value <<= 1;
        }

        return -1;
    }

    handle->conn_state = CONNECTED;
    handle->next_reconnect_attempt = -1L;
    handle->next_delay_value = 1;

    return 0;
}

static void my_connect_cb(struct mosquitto *mosq, void *user_data, int result) {
    (void)mosq;
    mqtt_handle_t *handle = (mqtt_handle_t *)user_data;

    if (!result) {
        log_info("successfully connected to MQTT broker");
        handle->conn_state = CONNECTED;
    } else if (handle->conn_state != DISCONNECTED) {
        log_warning("unable to connect to MQTT broker. Reason: %s", MOSQ_ERROR(result));
        handle->conn_state = NOT_CONNECTED;
    }
}

static void my_disconnect_cb(struct mosquitto *mosq, void *user_data, int result) {
    (void)mosq;
    mqtt_handle_t *handle = (mqtt_handle_t *)user_data;

    if (handle->conn_state != DISCONNECTED) {
        log_info("disconnected from MQTT broker. Reason: %s", MOSQ_ERROR(result));
        handle->conn_state = NOT_CONNECTED;
    }
}

static void my_log_callback(struct mosquitto *mosq, void *user_data, int level, const char *msg) {
    (void)mosq;
    (void)user_data;
    (void)level;
    log_debug(msg);
}

int connect_mqtt(mqtt_handle_t *handle, const config_t *cfg) {
    int status;

    if (!handle->mosq) {
        log_debug("creating new mosquitto instance");

        handle->mosq = mosquitto_new(cfg->client_id, true /* clean session */, handle);
    }
    if (!handle->mosq) {
        log_error("failed to create new mosquitto instance");
        return -1;
    }

    if (cfg->use_tls) {
        log_debug("setting up TLS parameters on mosquitto instance");

        status = mosquitto_tls_insecure_set(handle->mosq, false);
        if (status != MOSQ_ERR_SUCCESS) {
            log_error("failed to disable insecure TLS: %s", MOSQ_ERROR(status));
            internal_destroy_mqtt(handle);
            return -1;
        }

        status = mosquitto_tls_opts_set(handle->mosq,
                                        cfg->verify_peer, cfg->tls_version, cfg->ciphers);
        if (status != MOSQ_ERR_SUCCESS) {
            log_error("failed to set TLS options: %s", MOSQ_ERROR(status));
            internal_destroy_mqtt(handle);
            return -1;
        }

        status = mosquitto_tls_set(handle->mosq,
                                   cfg->cacertfile, cfg->cacertpath, cfg->certfile, cfg->keyfile, NULL);
        if (status != MOSQ_ERR_SUCCESS) {
            log_error("failed to set TLS settings: %s", MOSQ_ERROR(status));
            internal_destroy_mqtt(handle);
            return -1;
        }
    }

    if (cfg->use_auth) {
        log_debug("setting up authentication on mosquitto instance");

        status = mosquitto_username_pw_set(handle->mosq, cfg->username, cfg->password);
        if (status != MOSQ_ERR_SUCCESS) {
            log_error("failed to set authentication credentials: %s", MOSQ_ERROR(status));
            internal_destroy_mqtt(handle);
            return -1;
        }
    }

    log_debug("connecting to MQTT broker");

    mosquitto_connect_callback_set(handle->mosq, my_connect_cb);
    mosquitto_disconnect_callback_set(handle->mosq, my_disconnect_cb);
    mosquitto_log_callback_set(handle->mosq, my_log_callback);

    handle->host = cfg->host;
    handle->port = cfg->port;
    handle->qos = cfg->qos;
    handle->retain = cfg->retain;

    status = internal_connect_mqtt(handle);
    if (status == MOSQ_ERR_SUCCESS) {
        log_debug("connection setup to MQTT broker complete");
    } else {
        log_error("connection to MQTT broker pending. Reason: %s", MOSQ_ERROR(status));
    }

    return 0;
}

int disconnect_mqtt(mqtt_handle_t *handle) {
    if (handle == NULL || handle->mosq == NULL) {
        // Nothing to do...
        return 0;
    }

    handle->conn_state = DISCONNECTED;

    int status = internal_disconnect_mqtt(handle);

    log_debug("MQTT broker connection teardown complete");

    return status;
}

static bool mqtt_needs_to_reconnect(int status) {
    return status == MOSQ_ERR_NO_CONN ||
           status == MOSQ_ERR_CONN_REFUSED ||
           status == MOSQ_ERR_CONN_LOST ||
           status == MOSQ_ERR_TLS ||
           status == MOSQ_ERR_AUTH ||
           status == MOSQ_ERR_UNKNOWN;
}

int mqtt_fd(const mqtt_handle_t *handle) {
    if (handle->mosq == NULL) {
        return -1;
    }
    return mosquitto_socket(handle->mosq);
}

int mqtt_read_data(mqtt_handle_t *handle) {
    int status = mosquitto_loop_read(handle->mosq, 1 /* max_packets */);
    if (status != MOSQ_ERR_SUCCESS) {
        if (mqtt_needs_to_reconnect(status)) {
            return internal_reconnect_mqtt(handle);
        }

        log_warning("Failed to read MQTT messages. Reason: %s", MOSQ_ERROR(status));
        return -1;
    }

    return 0;
}

int mqtt_update_administration(mqtt_handle_t *handle) {
    int status = mosquitto_loop_misc(handle->mosq);
    if (status != MOSQ_ERR_SUCCESS) {
        if (mqtt_needs_to_reconnect(status)) {
            return internal_reconnect_mqtt(handle);
        }

        log_warning("Failed to do misc MQTT administration. Reason: %s", MOSQ_ERROR(status));
        return -1;
    }

    return 0;
}

int mqtt_write_data(mqtt_handle_t *handle) {
    int status = mosquitto_loop_write(handle->mosq, 1 /* max_packets */);
    if (status != MOSQ_ERR_SUCCESS) {
        if (mqtt_needs_to_reconnect(status)) {
            return internal_reconnect_mqtt(handle);
        }

        log_warning("Failed to write MQTT messages. Reason: %s", MOSQ_ERROR(status));
        return -1;
    }

    return 0;
}

bool mqtt_wants_to_write(const mqtt_handle_t *handle) {
    return mosquitto_want_write(handle->mosq);
}

int publish_mqtt(mqtt_handle_t *handle, const event_t *event) {
    const char *topic = event_topic_name(event->event_type);

    int status = mosquitto_publish(handle->mosq, NULL /* message id */,
                                   topic,
                                   (int) strlen(event->data), event->data,
                                   handle->qos, handle->retain);

    if (status != MOSQ_ERR_SUCCESS) {
        if (mqtt_needs_to_reconnect(status)) {
            return internal_reconnect_mqtt(handle);
        }

        log_warning("Failed to publish data to MQTT broker. Reason: %s", MOSQ_ERROR(status));
        return -1;
    }

    log_debug("Successfully send event on %s :: %s", topic, (char *)event->data);

    return 0;
}
