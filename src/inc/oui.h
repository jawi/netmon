/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */
#ifndef OUI_H_
#define OUI_H_

#include <stddef.h>

#define MAX_NAME_LEN  64

typedef struct oui_info oui_info_t;

typedef struct oui_list oui_list_t;

typedef struct oui_info {
    uint64_t oui;
    uint64_t mask;
    char manuf[MAX_NAME_LEN];
    struct oui_info *next;
} oui_info_t;

extern oui_list_t *oui_list;

/**
 * Parses the OUI entries from the given file.
 *
 * @param oui_file the source file to read the entries from.
 * @return the list with OUI entries, or NULL in case the parsing failed.
 */
oui_list_t *parse_oui_list(char *src_file);

/**
 * Releases all allocated memory for the given OUI list.
 *
 * @param list the OUI list to free.
 * @return always NULL.
 */
oui_list_t *free_oui_list(oui_list_t *list);

/**
 * Finds the OUI vendor information for a given OUI-value.
 *
 * @param list the OUI list to search in;
 * @param oui the OUI-value to search for.
 * @return the vendor that owns the given OUI, or NULL in case no vendor
 *         information could be found.
 */
const char *find_oui_vendor(oui_list_t *list, uint64_t oui);

/**
 * Finds a OUI entry in a given list of OUI entries, searching for most
 * specific MAC addresses first, then for vendor-specific blocks and lastly in
 * the general manufacturers table.
 *
 * @param list the OUI list to search in, cannot be NULL;
 * @param oui the OUI-value to search for.
 * @return the OUI information, or NULL in case no entry exists that matches
 *         the given OUI-value.
 */
oui_info_t *find_oui(oui_list_t *list, uint64_t oui);

#endif /* OUI_H_ */
