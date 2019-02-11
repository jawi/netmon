/*
 * config.c
 *
 *  Created on: Jan 18, 2019
 *      Author: jawi
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

typedef enum parser_state {
    UNKNOWN_STATE = 0,
    KEY,
    VALUE,
} parser_state_t;

typedef enum config_block {
    ROOT = 0,
    DAEMON,
    SERVER,
    AUTH,
    TLS,
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
    cfg->qos = 1;
    cfg->retain = false;

    cfg->use_auth = false;
    cfg->use_tls = false;

    cfg->username = NULL;
    cfg->password = NULL;

    cfg->cacertpath = NULL;
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
    yaml_token_t token;

    parser_state_t pstate = UNKNOWN_STATE;
    config_block_t cblock = ROOT;

    int done = 0;
    bool error = false;
    char key[64] = {};

#define KEY_EQUALS(n) (strncmp(key, (n), sizeof(n)) == 0)
#define IN_BLOCK(b) (cblock == (b))
#define PARSE_ERROR(...) \
    do { \
        log_error(__VA_ARGS__); \
        error = true; \
        goto cleanup; \
    } while (0);

    if (!yaml_parser_initialize(&parser)) {
        PARSE_ERROR("failed to initialize parser!");
    }

    FILE *fh = fopen(file, "r");
    if (fh == NULL) {
        PARSE_ERROR("failed to open configuration file: %s", file);
    }

    yaml_parser_set_input_file(&parser, fh);
    yaml_parser_set_encoding(&parser, YAML_UTF8_ENCODING);

    do {
        if (!yaml_parser_scan(&parser, &token)) {
            PARSE_ERROR("failed to parse configuration file: %d", parser.error);
        }

        switch (token.type) {
        case YAML_STREAM_START_TOKEN: {
            cfg = malloc(sizeof(config_t));
            if (cfg == NULL) {
                PARSE_ERROR("failed to allocate memory!");
            }
            // set the defaults...
            if (init_config(cfg)) {
                error = true;
                goto cleanup;
            }

            break;
        }
        case YAML_STREAM_END_TOKEN:
            done = 1;
            break;

        case YAML_KEY_TOKEN:
            pstate = KEY;
            break;

        case YAML_VALUE_TOKEN:
            pstate = VALUE;
            break;

        case YAML_BLOCK_END_TOKEN:
            cblock = ROOT;
            break;

        case YAML_BLOCK_MAPPING_START_TOKEN:
            if (KEY_EQUALS("")) {
                cblock = ROOT;
            } else if (KEY_EQUALS("daemon")) {
                cblock = DAEMON;
            } else if (KEY_EQUALS("server")) {
                cblock = SERVER;
            } else if (KEY_EQUALS("auth")) {
                cblock = AUTH;
            } else if (KEY_EQUALS("tls")) {
                cblock = TLS;
            } else {
                PARSE_ERROR("unknown/unhandled configuration block: %s", key);
            }
            break;
        case YAML_SCALAR_TOKEN: {
            size_t len = token.data.scalar.length;
            const char *val = (const char *)token.data.scalar.value;

            if (pstate == KEY) {
                strncpy(key, val, len);
                key[len] = 0;
            } else if (pstate == VALUE) {
                if (IN_BLOCK(DAEMON) && KEY_EQUALS("user")) {
                    struct passwd *pwd = getpwnam(val);
                    if (pwd) {
                        cfg->priv_user = pwd->pw_uid;
                        cfg->priv_group = pwd->pw_gid;
                    } else {
                        PARSE_ERROR("invalid configuration file: unknown user '%s'", val);
                    }
                } else if (IN_BLOCK(DAEMON) && KEY_EQUALS("group")) {
                    struct group *grp = getgrnam(val);
                    if (grp) {
                        cfg->priv_group = grp->gr_gid;
                    } else {
                        PARSE_ERROR("invalid configuriation file: unknown group '%s'", val);
                    }
                } else if (IN_BLOCK(SERVER) && KEY_EQUALS("client_id")) {
                    cfg->client_id = safe_strdup(val);
                } else if (IN_BLOCK(SERVER) && KEY_EQUALS("host")) {
                    cfg->host = safe_strdup(val);
                } else if (IN_BLOCK(SERVER) && KEY_EQUALS("port")) {
                    int32_t n = safe_atoi(val);
                    if (n < 1 || n > 65535) {
                        PARSE_ERROR("invalid server port: %s. Use a port between 1 and 65535!", val);
                    }
                    cfg->port = (uint16_t) n;
                } else if (IN_BLOCK(SERVER) && KEY_EQUALS("qos")) {
                    int32_t n = safe_atoi(val);
                    if (n < 0 || n > 2) {
                        PARSE_ERROR("invalid QoS value: %s. Use 0, 1 or 2 as value!", val);
                    }
                    cfg->qos = (uint8_t) n;
                } else if (IN_BLOCK(SERVER) && KEY_EQUALS("retain")) {
                    cfg->retain = safe_atob(val);
                } else if (IN_BLOCK(AUTH) && KEY_EQUALS("username")) {
                    cfg->username = safe_strdup(val);
                    cfg->use_auth = true;
                } else if (IN_BLOCK(AUTH) && KEY_EQUALS("password")) {
                    cfg->password = safe_strdup(val);
                    cfg->use_auth = true;
                } else if (IN_BLOCK(TLS) && KEY_EQUALS("ca_cert_path")) {
                    cfg->cacertpath = safe_strdup(val);
                    cfg->use_tls = true;
                } else if (IN_BLOCK(TLS) && KEY_EQUALS("ca_cert_file")) {
                    cfg->cacertfile = safe_strdup(val);
                    cfg->use_tls = true;
                } else if (IN_BLOCK(TLS) && KEY_EQUALS("cert_file")) {
                    cfg->certfile = safe_strdup(val);
                    cfg->use_tls = true;
                } else if (IN_BLOCK(TLS) && KEY_EQUALS("key_file")) {
                    cfg->keyfile = safe_strdup(val);
                    cfg->use_tls = true;
                } else if (IN_BLOCK(TLS) && KEY_EQUALS("tls_version")) {
                    cfg->tls_version = safe_strdup(val);
                    cfg->use_tls = true;
                } else if (IN_BLOCK(TLS) && KEY_EQUALS("ciphers")) {
                    cfg->ciphers = safe_strdup(val);
                    cfg->use_tls = true;
                } else if (IN_BLOCK(TLS) && KEY_EQUALS("verify_peer")) {
                    cfg->verify_peer = safe_atob(val);
                    cfg->use_tls = true;
                } else {
                    PARSE_ERROR("invalid configuration key/value in block %d: %s => %s", cblock, key, val);
                }
            }

            break;
        }

        default:
            PARSE_ERROR("invalid configuration file: unexpected token (id = %d)", token.type);
        }

        yaml_token_delete(&token);
    } while (!done);

    if (!cfg->client_id) {
        cfg->client_id = strdup("netmon");
    }
    if (!cfg->host) {
        cfg->host = strdup("localhost");
    }
    if (!cfg->port) {
        cfg->port = (cfg->use_tls) ? 8883 : 1883;
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

        if (!cfg->cacertpath && !cfg->cacertfile) {
            PARSE_ERROR("need either ca_cert_path or ca_cert_file to be set!");
        }
        if (!cfg->certfile ^ !cfg->keyfile) {
            PARSE_ERROR("need both cert_file and key_file for proper TLS operation!");
        }

        if (!cfg->verify_peer) {
            log_warning("insecure TLS operation used: verify_peer = false! Potential MITM vulnerability!");
        }
        if (cfg->port == 1883) {
            log_warning("connecting to non-TLS port of MQTT while TLS settings were configured!");
        }
    }

cleanup:
    if (error) {
        free_config(cfg);
        cfg = NULL;
    }

    yaml_token_delete(&token);
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
    free(config->cacertpath);
    free(config->certfile);
    free(config->keyfile);
    free(config->tls_version);
    free(config->ciphers);

    free(config);
}
