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

#include <pwd.h>
#include <grp.h>

#include <sys/types.h>

#include <yaml.h>

#include "config.h"
#include "logging.h"

typedef enum config_block {
    ROOT = 0,
    DAEMON,
    NATS,
    NATS_AUTH,
    NATS_TLS,
} config_block_t;

static inline char *safe_strdup(const char *val) {
    if (!val) {
        return NULL;
    }
    if (strlen(val) == 0) {
        return NULL;
    }
    return strdup(val);
}

static inline int32_t safe_atoi(const char *val) {
    if (!val) {
        return -1;
    }
    if (strlen(val) == 0) {
        return -1;
    }
    return (int32_t) atoi(val);
}

static inline bool safe_atob(const char *val) {
    if (!val) {
        return false;
    }
    if (strlen(val) == 0) {
        return false;
    }
    return strncasecmp(val, "true", 4) == 0 || strncasecmp(val, "yes", 3) == 0;
}

static int init_priv_user(config_t *cfg) {
    struct passwd *pwd = getpwnam("nobody");
    if (pwd) {
        cfg->priv_user = pwd->pw_uid;
        cfg->priv_group = pwd->pw_gid;
    } else {
        log_error("unable to get user nobody: %p");
        return -1;
    }
    return 0;
}

static int init_config(config_t *cfg) {
    cfg->client_id = NULL;
    cfg->host = NULL;
    cfg->port = 0;

    cfg->use_auth = false;
    cfg->use_tls = false;

    cfg->username = NULL;
    cfg->password = NULL;

    cfg->cacertfile = NULL;
    cfg->certfile = NULL;
    cfg->keyfile = NULL;
    cfg->tls_version = NULL;
    cfg->ciphers = NULL;
    cfg->verify_peer = true;

    if (init_priv_user(cfg)) {
        return -1;
    }

    return 0;
}

config_t *read_config(const char *file) {
    config_t *cfg = NULL;
    yaml_parser_t parser;
    yaml_event_t event;

    config_block_t cblock = ROOT;
    bool key_expected = false;

    int done = 0;
    bool error = false;
    char key[64] = {};

#define IN_CONTEXT(b) (cblock == (b))
#define KEY_IN_CONTEXT(n, b) ((strcmp(key, (n)) == 0) && IN_CONTEXT(b))
#define VALUE_IN_CONTEXT(n, b) ((strcmp(val, (n)) == 0) && IN_CONTEXT(b))
#define PARSE_ERROR(...) \
    do { \
        log_error(__VA_ARGS__); \
        if (event.type != 0) { \
            log_error("  at line %d, column %d", event.start_mark.line+1, event.start_mark.column+1); \
        } \
        error = true; \
        goto cleanup; \
    } while (0);

    FILE *fh = fopen(file, "r");
    if (fh == NULL) {
        PARSE_ERROR("failed to open configuration file: %s", file);
    }

    if (!yaml_parser_initialize(&parser)) {
        PARSE_ERROR("failed to initialize parser!");
    }

    yaml_parser_set_input_file(&parser, fh);
    yaml_parser_set_encoding(&parser, YAML_UTF8_ENCODING);

    do {
        if (!yaml_parser_parse(&parser, &event)) {
            PARSE_ERROR("failed to parse configuration file: %s", parser.problem);
        }

        switch (event.type) {
        case YAML_STREAM_START_EVENT: {
            cfg = malloc(sizeof(config_t));
            if (cfg == NULL) {
                PARSE_ERROR("failed to allocate memory for configuration");
            }
            // set the defaults...
            if (init_config(cfg)) {
                error = true;
                goto cleanup;
            }

            break;
        }
        case YAML_STREAM_END_EVENT:
            done = 1;
            break;

        case YAML_DOCUMENT_START_EVENT:
        case YAML_DOCUMENT_END_EVENT:
            // nop
            break;

        case YAML_MAPPING_START_EVENT:
            key_expected = true;
            break;

        case YAML_MAPPING_END_EVENT:
            if (IN_CONTEXT(NATS_AUTH) || IN_CONTEXT(NATS_TLS)) {
                cblock = NATS;
            } else {
                cblock = ROOT;
            }
            break;

        case YAML_SCALAR_EVENT: {
            size_t len = event.data.scalar.length;
            const char *val = (char *)event.data.scalar.value;

            if (VALUE_IN_CONTEXT("daemon", ROOT)) {
                cblock = DAEMON;
            } else if (VALUE_IN_CONTEXT("nats", ROOT)) {
                cblock = NATS;
            } else if (VALUE_IN_CONTEXT("auth", NATS)) {
                cblock = NATS_AUTH;
            } else if (VALUE_IN_CONTEXT("tls", NATS)) {
                cblock = NATS_TLS;
            } else if (key_expected) {
                strncpy(key, val, len);
                key[len] = 0;
                key_expected = false;
            } else {
                if (KEY_IN_CONTEXT("user", DAEMON)) {
                    struct passwd *pwd = getpwnam(val);
                    if (pwd) {
                        cfg->priv_user = pwd->pw_uid;
                        cfg->priv_group = pwd->pw_gid;
                    } else {
                        PARSE_ERROR("invalid configuration file: unknown user '%s'", val);
                    }
                } else if (KEY_IN_CONTEXT("group", DAEMON)) {
                    struct group *grp = getgrnam(val);
                    if (grp) {
                        cfg->priv_group = grp->gr_gid;
                    } else {
                        PARSE_ERROR("invalid configuriation file: unknown group '%s'", val);
                    }
                } else if (KEY_IN_CONTEXT("client_id", NATS)) {
                    cfg->client_id = safe_strdup(val);
                } else if (KEY_IN_CONTEXT("host", NATS)) {
                    cfg->host = safe_strdup(val);
                } else if (KEY_IN_CONTEXT("port", NATS)) {
                    int32_t n = safe_atoi(val);
                    if (n < 1 || n > 65535) {
                        PARSE_ERROR("invalid server port: %s. Use a port between 1 and 65535!", val);
                    }
                    cfg->port = (uint16_t) n;
                } else if (KEY_IN_CONTEXT("username", NATS_AUTH)) {
                    cfg->username = safe_strdup(val);
                    cfg->use_auth = true;
                } else if (KEY_IN_CONTEXT("password", NATS_AUTH)) {
                    cfg->password = safe_strdup(val);
                    cfg->use_auth = true;
                } else if (KEY_IN_CONTEXT("ca_cert_file", NATS_TLS)) {
                    cfg->cacertfile = safe_strdup(val);
                    cfg->use_tls = true;
                } else if (KEY_IN_CONTEXT("cert_file", NATS_TLS)) {
                    cfg->certfile = safe_strdup(val);
                    cfg->use_tls = true;
                } else if (KEY_IN_CONTEXT("key_file", NATS_TLS)) {
                    cfg->keyfile = safe_strdup(val);
                    cfg->use_tls = true;
                } else if (KEY_IN_CONTEXT("verify_peer", NATS_TLS)) {
                    cfg->verify_peer = safe_atob(val);
                    cfg->use_tls = true;
                } else if (KEY_IN_CONTEXT("tls_version", NATS_TLS)) {
                    cfg->tls_version = safe_strdup(val);
                    cfg->use_tls = true;
                } else if (KEY_IN_CONTEXT("ciphers", NATS_TLS)) {
                    cfg->ciphers = safe_strdup(val);
                    cfg->use_tls = true;
                } else {
                    PARSE_ERROR("unexpected key/value %s => %s", key, val);
                }

                key_expected = true;
            }

            break;
        }

        default:
            PARSE_ERROR("invalid configuration file: unexpected construct");
        }

        yaml_event_delete(&event);
    } while (!done);

    if (!cfg->client_id) {
        cfg->client_id = strdup("netmon");
    }
    if (!cfg->host) {
        cfg->host = strdup("localhost");
    }
    if (!cfg->port) {
        cfg->port = 4222;
    }

    // Do some additional validations...
    if (cfg->use_auth) {
        if (!cfg->username ^ !cfg->password) {
            PARSE_ERROR("need both username and password for proper authentication!");
        }
    }

    if (cfg->use_tls) {
        if (!cfg->tls_version) {
            cfg->tls_version = strdup("tlsv1.2");
        }

        if (!cfg->cacertfile) {
            PARSE_ERROR("need ca_cert_file to be set!");
        }
        if (!cfg->certfile ^ !cfg->keyfile) {
            PARSE_ERROR("need both cert_file and key_file for proper TLS operation!");
        }

        if (!cfg->verify_peer) {
            log_warning("insecure TLS operation used: verify_peer = false! Potential MITM vulnerability!");
        }
    }

cleanup:
    if (error) {
        free_config(cfg);
        cfg = NULL;
    }

    yaml_event_delete(&event);
    yaml_parser_delete(&parser);

    if (fh) {
        fclose(fh);
    }

    return cfg;
}

void free_config(config_t *config) {
    if (!config) {
        return;
    }

    free(config->client_id);
    free(config->host);

    free(config->username);
    free(config->password);

    free(config->cacertfile);
    free(config->certfile);
    free(config->keyfile);
    free(config->tls_version);
    free(config->ciphers);

    free(config);
}
