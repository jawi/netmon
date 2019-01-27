/*
 * mqtt.c
 *
 *  Created on: Jan 18, 2019
 *      Author: jawi
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

#define MOSQ_ERROR(s) \
	((s) == MOSQ_ERR_ERRNO) ? strerror(errno) : mosquitto_strerror((s))

typedef enum conn_state {
    INITIALIZED,
    NOT_CONNECTED,
    CONNECTED,
    DISCONNECTED,
} conn_state_t;

struct mqtt_handle {
    struct mosquitto *mosq;
    conn_state_t conn_state;
    char *host;
    int port;
    bool retain;
    int qos;
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

    return handle;
}

void destroy_mqtt(mqtt_handle_t *handle) {
    if (handle) {
        mosquitto_destroy(handle->mosq);

        handle->mosq = NULL;

        free(handle);
    }

    mosquitto_lib_cleanup();
}

static int internal_connect_mqtt(mqtt_handle_t *handle) {
    int status = mosquitto_connect(handle->mosq, handle->host, handle->port, 60 /* keepalive */);
    if (status != MOSQ_ERR_SUCCESS) {
        log_warning("failed to connect to MQTT broker: %s", MOSQ_ERROR(status));
        return -1;
    }

    // do not wait until our connect callback is called to set our state
    // there: it will cause reconnection problems!
    handle->conn_state = CONNECTED;

    return 0;
}

static int internal_disconnect_mqtt(mqtt_handle_t *handle) {
    int status = mosquitto_disconnect(handle->mosq);
    if (status != MOSQ_ERR_SUCCESS && status != MOSQ_ERR_NO_CONN) {
        log_warning("failed to disconnect from MQTT broker: %s", MOSQ_ERROR(status));
        return -1;
    }

    handle->conn_state = NOT_CONNECTED;

    return 0;
}

static int internal_reconnect_mqtt(mqtt_handle_t *handle) {
    if (handle->conn_state == CONNECTED || handle->conn_state == DISCONNECTED) {
        return 0;
    }

    log_debug("reconnecting to MQTT broker");

    int status = mosquitto_reconnect(handle->mosq);
    if (status != MOSQ_ERR_SUCCESS) {
        log_warning("failed to reconnect to MQTT broker: %s", MOSQ_ERROR(status));

        internal_disconnect_mqtt(handle);
        internal_connect_mqtt(handle);
    }

    handle->conn_state = CONNECTED;

    return 0;
}

static void my_connect_cb(struct mosquitto *mosq, void *user_data, int result) {
    mqtt_handle_t *handle = (mqtt_handle_t *)user_data;

    if (!result) {
        log_info("successfully connected to MQTT broker");
        handle->conn_state = CONNECTED;
    } else if (handle->conn_state != DISCONNECTED) {
        log_warning("failed to connect to MQTT broker");

        handle->conn_state = NOT_CONNECTED;
        internal_reconnect_mqtt(handle);
    }
}

static void my_disconnect_cb(struct mosquitto *mosq, void *user_data, int result) {
    mqtt_handle_t *handle = (mqtt_handle_t *)user_data;

    if (handle->conn_state != DISCONNECTED) {
        log_info("disconnected from MQTT broker");

        handle->conn_state = NOT_CONNECTED;
        internal_reconnect_mqtt(handle);
    }
}

int connect_mqtt(mqtt_handle_t *handle, const config_t *cfg) {
    int status;

    log_debug("creating new mosquitto instance");

    handle->mosq = mosquitto_new(cfg->client_id, true /* clean session */, handle);
    if (!handle->mosq) {
        log_error("failed to create new mosquitto instance");
        return -1;
    }

    if (cfg->use_tls) {
        log_debug("setting up TLS parameters on mosquitto instance");

        status = mosquitto_tls_insecure_set(handle->mosq, false);
        if (status != MOSQ_ERR_SUCCESS) {
            log_error("failed to disable insecure TLS: %s", MOSQ_ERROR(status));
            return -1;
        }

        status = mosquitto_tls_opts_set(handle->mosq,
                                        cfg->verify_peer, cfg->tls_version, cfg->ciphers);
        if (status != MOSQ_ERR_SUCCESS) {
            log_error("failed to set TLS options: %s", MOSQ_ERROR(status));
            return -1;
        }

        status = mosquitto_tls_set(handle->mosq,
                                   cfg->cacertfile, cfg->cacertpath, cfg->certfile, cfg->keyfile, NULL);
        if (status != MOSQ_ERR_SUCCESS) {
            log_error("failed to set TLS settings: %s", MOSQ_ERROR(status));
            return -1;
        }
    }

    if (cfg->use_auth) {
        log_debug("setting up authentication on mosquitto instance");

        status = mosquitto_username_pw_set(handle->mosq, cfg->username, cfg->password);
        if (status != MOSQ_ERR_SUCCESS) {
            log_error("failed to set authentication credentials: %s", MOSQ_ERROR(status));
            return -1;
        }
    }

    log_debug("connecting to MQTT broker");

    mosquitto_connect_callback_set(handle->mosq, my_connect_cb);
    mosquitto_disconnect_callback_set(handle->mosq, my_disconnect_cb);

    handle->host = cfg->host;
    handle->port = cfg->port;
    handle->qos = cfg->qos;
    handle->retain = cfg->retain;

    if (internal_connect_mqtt(handle)) {
        log_error("failed to connect to MQTT broker: %s", MOSQ_ERROR(status));
        return -1;
    }

    log_debug("starting MQTT message loop");

    status = mosquitto_loop_start(handle->mosq);
    if (status != MOSQ_ERR_SUCCESS) {
        log_error("failed to start MQTT message loop: %s", MOSQ_ERROR(status));
        return -1;
    }

    log_debug("connection setup to MQTT broker complete");

    return 0;
}

int disconnect_mqtt(mqtt_handle_t *handle) {
    handle->conn_state = DISCONNECTED;

    int status = mosquitto_loop_stop(handle->mosq, true /* force */);
    if (status != MOSQ_ERR_SUCCESS) {
        log_warning("failed to stop MQTT message loop: %s", MOSQ_ERROR(status));
        return -1;
    }

    status = internal_disconnect_mqtt(handle);

    log_debug("MQTT broker connection teardown complete");

    return status;
}

void publish_mqtt(mqtt_handle_t *handle, const event_t *event) {
    const char *topic = event_topic_name(event->event_type);

    log_debug("sending event on %s :: %s", topic, (char *)event->data);

    int status = mosquitto_publish(handle->mosq, NULL /* message id */,
                                   topic,
                                   (int) strlen(event->data), event->data,
                                   handle->qos, handle->retain);

    if (status != MOSQ_ERR_SUCCESS) {
        log_warning("failed to publish data to MQTT broker: %s", MOSQ_ERROR(status));

        internal_reconnect_mqtt(handle);
    }
}
