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

#include <nats/nats.h>

#include "config.h"
#include "event.h"
#include "nats.h"
#include "logging.h"

struct nats_handle {
    natsConnection  *conn;
    natsOptions *opts;
};

nats_handle_t *init_nats(void) {
    log_debug("creating new NATS instance");

    nats_handle_t *handle = malloc(sizeof(struct nats_handle));
    handle->conn = NULL;
    handle->opts = NULL;
    return handle;
}

void destroy_nats(nats_handle_t *handle) {
    if (handle) {
        natsConnection_Destroy(handle->conn);
        natsOptions_Destroy(handle->opts);
        nats_Close();

        free(handle);
    }
}

#define CHECK_STATUS(s, msg) \
    if (s != NATS_OK) { \
         log_warning(msg ": %s", natsStatus_GetText(s)); \
         natsOptions_Destroy(opts); \
         nats_Close(); \
         return -1; \
    }

#define SET_OPTION(cmd, opts, vals...) \
    do { \
      natsStatus s = natsOptions_ ## cmd (opts, ##vals); \
      CHECK_STATUS(s, "Failed to set NATS option " # cmd) \
    } while (0);

int connect_nats(nats_handle_t *handle, const config_t *cfg) {
    char url[512];
    natsOptions *opts;

    log_debug("creating new NATS options");

    if (natsOptions_Create(&opts) != NATS_OK) {
        log_error("Unable to create NATS options: not enough memory!");
        return -1;
    }

    // Set the individual options...
    if (cfg->use_tls) {
        snprintf(url, sizeof(url), "nats://%s:%d", cfg->host, cfg->port);

        SET_OPTION(SetSecure, opts, true);
        SET_OPTION(SkipServerVerification, opts, !cfg->verify_peer);
        if (cfg->certfile || cfg->keyfile) {
            SET_OPTION(LoadCertificatesChain, opts, cfg->certfile, cfg->keyfile);
        }
        if (cfg->cacertfile) {
            SET_OPTION(LoadCATrustedCertificates, opts, cfg->cacertfile);
        }
        // TODO remove cfg->cacertpath!

        SET_OPTION(SetCiphers, opts, cfg->ciphers);
    } else {
        snprintf(url, sizeof(url), "nats://%s:%d", cfg->host, cfg->port);
    }

    if (cfg->use_auth) {
        SET_OPTION(SetUserInfo, opts, cfg->username, cfg->password);
    }

    SET_OPTION(SetAllowReconnect, opts, true);
    SET_OPTION(SetMaxReconnect, opts, 10);
    SET_OPTION(SetName, opts, cfg->client_id);
    SET_OPTION(SetTimeout, opts, 2000);
    SET_OPTION(SetPedantic, opts, true);

    SET_OPTION(SetURL, opts, url);

    log_debug("connecting to NATS server");

    natsStatus status = natsConnection_Connect(&handle->conn, opts);
    CHECK_STATUS(status, "Failed to connect to NATS server")

    handle->opts = opts;

    log_debug("connected to NATS server");

    return 0;
}

int disconnect_nats(nats_handle_t *handle) {
    // Nop
    return 0;
}

void publish_nats(nats_handle_t *handle, const event_t *event) {
    const char *topic = event_topic_name(event->event_type);

    log_debug("sending event on %s :: %s", topic, (char *)event->data);

    natsConnection_Publish(handle->conn, topic, event->data, (int) strlen(event->data));
}

// EOF