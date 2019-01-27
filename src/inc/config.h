/*
 * config.h
 *
 *  Created on: Jan 18, 2019
 *      Author: jawi
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#include <stdint.h>
#include <stdbool.h>

typedef struct config {
    char *client_id;

    uid_t priv_user;
    gid_t priv_group;

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

int read_config(const char *file, config_t *config);
void free_config(config_t *config);

#endif /* CONFIG_H_ */
