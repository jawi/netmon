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

#include <confuse.h>

#include "config.h"
#include "logging.h"

static inline char *safe_strdup(const char *val) {
    if (!val) {
        return NULL;
    }
    if (strlen(val) == 0) {
        return NULL;
    }
    return strdup(val);
}

int read_config(const char *file, config_t *config) {
    cfg_opt_t opts[] = {
        CFG_STR("client_id", "netmon", CFGF_NONE),

        CFG_STR("host", "localhost", CFGF_NONE),
        CFG_INT("port", 1883, CFGF_NONE),

        CFG_INT("qos", 1, CFGF_NONE),
        CFG_BOOL("retain", cfg_false, CFGF_NONE),

        CFG_STR("priv_user", "nobody", CFGF_NONE),
        CFG_STR("priv_group", "nogroup", CFGF_NONE),

        CFG_STR("username", NULL, CFGF_NODEFAULT),
        CFG_STR("password", NULL, CFGF_NODEFAULT),

        CFG_STR("ca_cert_path", NULL, CFGF_NODEFAULT),
        CFG_STR("ca_cert_file", NULL, CFGF_NODEFAULT),
        CFG_STR("cert_file", NULL, CFGF_NODEFAULT),
        CFG_STR("key_file", NULL, CFGF_NODEFAULT),
        CFG_STR("tls_version", "tlsv1.2", CFGF_NONE),
        CFG_STR("ciphers", NULL, CFGF_NODEFAULT),
        CFG_BOOL("verify_peer", cfg_true, CFGF_NONE),

        CFG_END()
    };

    cfg_t *cfg = cfg_init(opts, CFGF_NONE);

    int status = cfg_parse(cfg, file);
    if (status == CFG_FILE_ERROR) {
        log_error("failed to open configuration file: %s", file);
        return -1;
    } else if (status == CFG_PARSE_ERROR) {
        log_error("failed to parse configuration file: %s", file);
        return -1;
    }

    // Copy options back to our configuration...
    char *val;

    val = cfg_getstr(cfg, "client_id");
    config->client_id = safe_strdup(val);

    val = cfg_getstr(cfg, "host");
    config->host = safe_strdup(val);

    config->port = (uint16_t) cfg_getint(cfg, "port");
    config->qos = (uint8_t) cfg_getint(cfg, "qos");
    config->retain = cfg_getbool(cfg, "retain");

    val = cfg_getstr(cfg, "priv_user");

    struct passwd *pwd = getpwnam(val);
    if (pwd) {
        config->priv_user = pwd->pw_uid;
    } else {
        log_error("unknown user: %s", val);
        return -1;
    }

    val = cfg_getstr(cfg, "priv_group");
    if (!val) {
        config->priv_group = pwd->pw_gid;
    } else {
        struct group *grp = getgrnam(val);
        if (grp) {
            config->priv_group = grp->gr_gid;
        } else {
            log_error("unknown group: %s", val);
            return -1;
        }
    }

    val = cfg_getstr(cfg, "username");
    config->username = safe_strdup(val);

    val = cfg_getstr(cfg, "password");
    config->password = safe_strdup(val);

    // for convenience
    config->use_auth = config->username || config->password;

    val = cfg_getstr(cfg, "ca_cert_path");
    config->cacertpath = safe_strdup(val);

    val = cfg_getstr(cfg, "ca_cert_file");
    config->cacertfile = safe_strdup(val);

    val = cfg_getstr(cfg, "cert_file");
    config->certfile = safe_strdup(val);

    val = cfg_getstr(cfg, "key_file");
    config->keyfile = safe_strdup(val);

    val = cfg_getstr(cfg, "tls_version");
    config->tls_version = safe_strdup(val);

    val = cfg_getstr(cfg, "ciphers");
    config->ciphers = safe_strdup(val);

    config->verify_peer = cfg_getbool(cfg, "verify_peer");

    // for convenience
    config->use_tls = config->cacertfile || config->cacertpath || config->keyfile || config->certfile;

    // Do some additional validations...
    if (config->use_auth) {
        if (!config->certfile ^ !config->keyfile) {
            log_error("need both username and password for proper authentication!");
            return -1;
        }
    }

    if (config->use_tls) {
        if (!config->cacertpath && !config->cacertfile) {
            log_error("need either ca_cert_path or ca_cert_file to be set!");
            return -1;
        }
        if (!config->certfile ^ !config->keyfile) {
            log_error("need both cert_file and key_file for proper TLS operation!");
            return -1;
        }
    }

    if (config->qos < 1 || config->qos > 2) {
        log_error("invalid QoS value: either 1, 2 or 3 is allowed!");
        return -1;
    }

    if (!config->verify_peer) {
        log_warning("insecure TLS operation used: verify_peer = false! Potential MITM vulnerability!");
    }

    cfg_free(cfg);

    return 0;
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
