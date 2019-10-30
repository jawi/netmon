/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */

#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

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

uint64_t convert_to_oui(const uint8_t lladdr[MAC_LEN]) {
    return ((uint64_t)lladdr[0] << 40)
           | ((uint64_t)lladdr[1] << 32)
           | ((uint64_t)lladdr[2] << 24)
           | ((uint64_t)lladdr[3] << 16)
           | ((uint64_t)lladdr[4] << 8)
           | ((uint64_t)lladdr[5]);
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

#define SAFE_SIGNAL(rc) \
    int _rc = rc; \
    if (write(err_pipe[1], &_rc, 1) != 1) { \
        log_warning("failed to write single byte to pipe!"); \
    } \
    close(err_pipe[1]);

#define SIGNAL_SUCCESS() \
	do { \
        SAFE_SIGNAL(0) \
	} while (0)

#define SIGNAL_FAILURE(rc) \
	do { \
        SAFE_SIGNAL(rc) \
		exit(rc); \
	} while (0)

int daemonize(const char *pid_file, uid_t uid, gid_t gid) {
    // create a anonymous pipe to communicate between daemon and our parent...
    int err_pipe[2] = { 0 };
    if (pipe(err_pipe) < 0) {
        perror("pipe");
        return ERR_PIPE;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return ERR_FORK;
    } else if (pid > 0) {
        // parent, wait until daemon is finished initializing...
        close(err_pipe[1]);

        int rc = 0;
        if (read(err_pipe[0], &rc, 1) < 0) {
            rc = ERR_PIPE_READ;
        }
        exit(rc);
    } else { /* pid == 0 */
        // first child continues here...
        // NOTE: we can/should communicate our state to our parent in order for it to terminate!

        // we only write to this pipe...
        close(err_pipe[0]);

        // create a new session...
        pid = setsid();
        if (pid < 0) {
            SIGNAL_FAILURE(ERR_SETSID);
        }

        // fork again to ensure the daemon cannot take back the controlling tty...
        pid = fork();
        if (pid < 0) {
            SIGNAL_FAILURE(ERR_DAEMONIZE);
        } else if (pid > 0) {
            // terminate first child...
            exit(0);
        } else { /* pid == 0 */
            // actual daemon starts here...
            int fd;

            if ((fd = open("/dev/null", O_RDWR)) < 0) {
                log_error("unable to open /dev/null: %s", strerror(errno));
                SIGNAL_FAILURE(ERR_DEV_NULL);
            } else {
                dup2(fd, STDIN_FILENO);
                dup2(fd, STDOUT_FILENO);
                dup2(fd, STDERR_FILENO);
                close(fd);
            }

            umask(0);

            if (chdir("/") != 0) {
                log_error("unable to change directory: %m");
                SIGNAL_FAILURE(ERR_CHDIR);
            }

            if (write_pidfile(pid_file, uid, gid)) {
                SIGNAL_FAILURE(ERR_PID_FILE);
            }

            if (drop_privileges(uid, gid)) {
                SIGNAL_FAILURE(ERR_DROP_PRIVS);
            }

            // Finish startup...
            if (err_pipe[1] != -1) {
                SIGNAL_SUCCESS();
            }
        } /* daemon pid == 0 */
    } /* first child pid == 0 */

    return 0;
}
