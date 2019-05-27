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

typedef struct addr {
    int32_t index;
    uint8_t family;
    char addr[INET6_ADDRSTRLEN];
} addr_t;

typedef struct link {
    int32_t index;
    char *name;
    uint8_t ll_addr[MAC_LEN];
    uint16_t *vlan_id;
} link_t;

typedef struct neigh {
    int32_t index;
    uint16_t state;
    uint8_t ll_addr[MAC_LEN];
    addr_t dst_addr;
} neigh_t;

#endif /* ADDR_COMMON_H_ */
