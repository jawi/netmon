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

char *format_mac(const uint8_t lladdr[MAC_LEN]);

int drop_privileges(uid_t uid, gid_t gid);
int write_pidfile(const char *pidfile, uid_t uid, gid_t gid);

#endif /* UTIL_H_ */
