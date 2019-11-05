/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#ifndef UTIL_H_
#define UTIL_H_

#include <stddef.h>

#include "addr_common.h"

#define ERR_UNKNOWN 1
#define ERR_PIPE 10
#define ERR_FORK 11
#define ERR_PIPE_READ 12
#define ERR_SETSID 20
#define ERR_DAEMONIZE 21
#define ERR_DEV_NULL 22
#define ERR_PID_FILE 23
#define ERR_CONFIG 24
#define ERR_CHDIR 25
#define ERR_DROP_PRIVS 26

char *format_mac(const uint8_t lladdr[MAC_LEN]);

uint64_t convert_to_oui(const uint8_t lladdr[MAC_LEN]);

int drop_privileges(uid_t uid, gid_t gid);

int write_pidfile(const char *pidfile, uid_t uid, gid_t gid);

int daemonize(const char *pid_file, uid_t uid, gid_t gid);

#endif /* UTIL_H_ */
