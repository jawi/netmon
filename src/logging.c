/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <syslog.h>
#include <time.h>

#include "logging.h"

typedef struct log_config {
    bool debug;
    bool foreground;
} log_config_t;

static log_config_t log_cfg;

void init_logging(bool debug, bool foreground) {
    log_cfg.debug = debug;
    log_cfg.foreground = foreground;

    int options = LOG_CONS | LOG_PID | LOG_ODELAY;
    if (log_cfg.foreground) {
        options |= LOG_PERROR;
    }

    openlog("netmon", options, LOG_DAEMON);
}

void destroy_logging() {
    closelog();
}

static void do_log(const int level, const char *msg, va_list ap) {
    vsyslog(level, msg, ap);
}

void log_debug(const char *msg, ...) {
    if (log_cfg.debug) {
        va_list ap;
        va_start(ap, msg);
        do_log(LOG_DEBUG, msg, ap);
        va_end(ap);
    }
}

void log_info(const char *msg, ...) {
    va_list ap;
    va_start(ap, msg);
    do_log(LOG_INFO, msg, ap);
    va_end(ap);
}

void log_warning(const char *msg, ...) {
    va_list ap;
    va_start(ap, msg);
    do_log(LOG_WARNING, msg, ap);
    va_end(ap);
}

void log_error(const char *msg, ...) {
    va_list ap;
    va_start(ap, msg);
    do_log(LOG_ERR, msg, ap);
    va_end(ap);
}

