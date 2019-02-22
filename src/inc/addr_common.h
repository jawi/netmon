/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#ifndef ADDR_COMMON_H_
#define ADDR_COMMON_H_

#include <arpa/inet.h>

#define MAC_LEN 6

struct addr {
    uint8_t family;
    char addr[INET6_ADDRSTRLEN];
};

#endif /* ADDR_COMMON_H_ */
