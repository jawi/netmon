/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#ifndef LOGGING_H_
#define LOGGING_H_

#include <stdbool.h>

void init_logging(bool debug, bool foreground);
void destroy_logging(void);

void log_debug(const char *msg, ...);

void log_info(const char *msg, ...);

void log_warning(const char *msg, ...);

void log_error(const char *msg, ...);

#endif /* LOGGING_H_ */
