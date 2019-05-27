/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#ifndef CONFIG_H_
#define CONFIG_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

typedef struct config {
    uid_t priv_user;
    gid_t priv_group;

    char *client_id;
    char *host;
    uint16_t port;
    uint8_t qos;
    bool retain;

    bool use_tls;
    bool use_auth;

    char *username;
    char *password;

    char *cacertpath;
    char *cacertfile;
    char *certfile;
    char *keyfile;
    char *tls_version;
    char *ciphers;
    bool verify_peer;
} config_t;

config_t *read_config(const char *file);
void free_config(config_t *config);

#endif /* CONFIG_H_ */
