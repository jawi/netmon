/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "addr_common.h"
#include "logging.h"
#include "util.h"

// 6*2 digits + 5*colon + '\0' = 18
#define MAC_STR_LEN 18

char *format_mac(const uint8_t lladdr[MAC_LEN]) {
    static char buf[MAC_STR_LEN];
    // no need to check return value here, we're using a static buffer
    snprintf(buf, MAC_STR_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             lladdr[0], lladdr[1], lladdr[2],
             lladdr[3], lladdr[4], lladdr[5]);
    return buf;
}

int drop_privileges(uid_t uid, gid_t gid) {
    if (getuid() != 0) {
        // not running as root...
        return 0;
    }

    if (setgid(gid) != 0) {
        log_error("unable to drop group privileges: %m");
        return -1;
    }

    if (setuid(uid) != 0) {
        log_error("unable to drop user privileges: %m");
        return -1;
    }

    return 0;
}

int write_pidfile(const char *pid_file, uid_t uid, gid_t gid) {
    const bool is_root = (getuid() == 0);

    if (unlink(pid_file)) {
        if (errno != ENOENT) {
            if (is_root) {
                log_error("unable to remove pidfile: %m");
            }
        }
    }

    int fd;

    if ((fd = open(pid_file, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, S_IWUSR|S_IRUSR|S_IRGRP|S_IROTH)) < 0) {
        if (is_root) {
            log_error("unable to create pidfile: %m");
            return -1;
        } else {
            // no sense in continuing here, write will fail any way...
            return 0;
        }
    }

    // ensure the pid file has the correct permissions...
    if (is_root && uid != 0) {
        if (fchown(fd, uid, gid)) {
            log_error("unable to change ownership of pidfile: %m");
        }
    }

    dprintf(fd, "%d\n", getpid());

    close(fd);

    return 0;
}