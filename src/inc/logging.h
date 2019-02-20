/*
 * logging.h
 *
 *  Created on: Jan 22, 2019
 *      Author: jawi
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
