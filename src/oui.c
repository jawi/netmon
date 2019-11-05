/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */

#define _GNU_SOURCE

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

#include "logging.h"
#include "oui.h"
#include "util.h"

#define OUI_MASK      0xffffffffffffull

struct oui_list {
    oui_info_t *manufacturers; // mask == 0
    oui_info_t *addr; // mask > 0 && mask < 48
    oui_info_t *macs; // mask == 48
};

static uint8_t digit(char ch) {
    if (ch >= '0' && ch <= '9') {
        return (uint8_t) (ch - '0');
    }
    assert(0);
}

static bool iseol(char ch) {
    return (ch == '#' || ch == '\r' || ch == '\n');
}

static uint8_t xdigit(char ch) {
    if (ch >= '0' && ch <= '9') {
        return (uint8_t) (ch - '0');
    }
    if (ch >= 'A' && ch <= 'F') {
        return (uint8_t) (10 + (ch - 'A'));
    }
    if (ch >= 'a' && ch <= 'f') {
        return (uint8_t) (10 + (ch - 'a'));
    }
    assert(0);
}

static inline size_t min(size_t a, size_t b) {
    return (a < b) ? a : b;
}

/**
 * Parses the entries from the given file.
 *
 * @param oui_file the source file to read the entries from.
 * @return the OUI entries list.
 */
oui_list_t *parse_oui_list(char *oui_file) {
    FILE *fh = fopen(oui_file, "r");
    if (fh == NULL) {
        log_warning("Unable to read file: %s: %m", oui_file);
        return NULL;
    }

    char line[1024];
    uint32_t line_no = 0;

    oui_info_t *manufs = NULL, *manufs_ptr = NULL;
    oui_info_t *addr = NULL, *addr_ptr = NULL;
    oui_info_t *macs = NULL, *macs_ptr = NULL;

    log_debug("Parsing OUI list '%s'...", oui_file);

#define DO_WHILE(pred) while (s < sizeof(line) && line[s] != '\0' && pred(line[s])) { s++; }
#define SKIP_WS DO_WHILE(isspace)
#define APPEND_TO_LIST(l, e) \
    if (l == NULL) { \
        l = e; \
        l ## _ptr = e; \
    } else { \
        l ## _ptr->next = e; \
        l ## _ptr = l ## _ptr->next; \
    }

    while (fgets(line, sizeof(line)-1, fh) != NULL) {
        line_no++;
        size_t s = 0;

        SKIP_WS;

        if (line[s] == '#' || line[s] == '\0') {
            // skip comments and empty lines...
            continue;
        }

        uint64_t oui = 0, mask = 24;
        bool manuf_entry = true;
        int oui_len = 0;

        while (!isspace(line[s])) {
            char ch = line[s++];
            if (ch == '/') {
                // mask specifier, switch to parsing decimals...
                manuf_entry = false;
                mask = 0;
            }
            if (ch == ':' || ch == '-' || ch == '.' || (manuf_entry && !isxdigit(ch)) || (!manuf_entry && !isdigit(ch))) {
                continue;
            }
            if (manuf_entry) {
                oui = (oui << 4) | xdigit(ch);
                oui_len++;
            } else {
                mask = (mask * 10) + digit(ch);
            }
        }

        if (oui_len < 6 || oui_len > 12) {
            // invalid OUI...
            log_warning("Found invalid OUI data on line %d: %s\n", line_no, line);
            continue;
        }
        if (mask <= 0 || mask > 48) {
            // invalid mask value...
            log_warning("Found invalid OUI mask on line %d: %s\n", line_no, line);
            continue;
        }

        if (oui_len == 12 && manuf_entry && (mask == 24)) {
            log_debug("Got a complete MAC address at line %d", line);
            // We've got a full MAC address, presume it is a well-known MAC...
            manuf_entry = false;
            mask = 48;
        }

        SKIP_WS;

        // short vendor name...
        size_t sv_start = s;
        DO_WHILE(!isspace);
        size_t sv_len = min(MAX_NAME_LEN, (s - sv_start));

        SKIP_WS;

        // long vendor name...
        size_t lv_start = s;
        DO_WHILE(!iseol);
        // trim trailing whitespaces...
        while (s > lv_start && isspace(line[s])) {
            s--;
        }
        size_t lv_len = min(MAX_NAME_LEN, (s - lv_start + 1));

        // valid oui; extend it to a complete 48-bit address
        oui_info_t *entry = malloc(sizeof(oui_info_t));

        entry->oui = (oui << (8 * ((12 - oui_len) / 2)));
        entry->mask = (-1ull << (48 - mask)) & OUI_MASK;
        entry->next = NULL;

        if (lv_len > 1) {
            strncpy(entry->manuf, line + lv_start, lv_len);
            entry->manuf[lv_len] = '\0';
        } else if (sv_len > 0) {
            strncpy(entry->manuf, line + sv_start, sv_len);
            entry->manuf[sv_len] = '\0';
        } else {
            // no short or long vendor???
            log_debug("No vendor information on line %d: %s", line_no, line);
            entry->manuf[0] = 0;
        }

        // determine where to add this entry...
        if (manuf_entry) {
            APPEND_TO_LIST(manufs, entry);
        } else if (mask > 24 && mask < 48) {
            APPEND_TO_LIST(addr, entry);
        } else {
            APPEND_TO_LIST(macs, entry);
        }
    }

    log_debug("OUI list parsing complete: processed %d lines...", line_no);

    oui_list_t *result = malloc(sizeof(oui_list_t));
    result->manufacturers = manufs;
    result->addr = addr;
    result->macs = macs;

    fclose(fh);

    return result;
}

static oui_info_t *free_entries(oui_info_t *entries) {
    oui_info_t *ptr = entries;
    while (ptr) {
        oui_info_t *entry = ptr;
        ptr = ptr->next;

        free(entry);
    }
    return NULL;
}

oui_list_t *free_oui_list(oui_list_t *list) {
    if (list) {
        free_entries(list->manufacturers);
        free_entries(list->addr);
        free_entries(list->macs);
        free(list);
    }
    return NULL;
}

/**
 * Finds the middle element for a given linked list as denotes by the given start and end elements.
 *
 * @param start the start element, can be NULL in which case no middle element is found;
 * @param end the last element, can be NULL for the end-of-list.
 * @return the middle element, or NULL in case no middle element could be found.
 */
static oui_info_t *find_middle(oui_info_t *start, oui_info_t *end) {
    if (!start) {
        return NULL;
    }

    oui_info_t *slow = start;
    oui_info_t *fast = start->next;

    while (fast != end) {
        fast = fast->next;
        if (fast != end) {
            slow = slow->next;
            fast = fast->next;
        }
    }

    return slow;
}

/**
 * Compares the given OUI-value against a given entry, using the exact mask of the given entry.
 *
 * @param entry the OUI information to compare against;
 * @param oui the OUI-value to compare.
 * @return -1, 0 or 1 if the given OUI-value is more, equal or less than the given OUI information.
 */
static int compare_oui(oui_info_t *entry, uint64_t oui) {
    uint64_t masked_oui = oui & entry->mask;
    if (entry->oui > masked_oui) {
        return 1;
    } else if (entry->oui < masked_oui) {
        return -1;
    }
    return 0;
}

/**
 * Searches for a OUI that matches a given OUI value.
 *
 * @param entries the OUI entries to seach in;
 * @param oui the OUI-value to search for.
 * @return the found OUI information, or NULL in case no such entry exists.
 */
static oui_info_t *find_oui_info(oui_info_t *entries, uint64_t oui) {
    oui_info_t *start = entries;
    oui_info_t *middle = NULL;
    oui_info_t *end = NULL;

    do {
        middle = find_middle(start, end);
        if (!middle) {
            // not found...
            return NULL;
        }

        int r = compare_oui(middle, oui);
        if (r == 0) {
            // match...
            return middle;
        } else if (r < 0) {
            start = middle->next;
        } else {
            end = middle;
        }
    }
    while (!end || end != start);

    // not found...
    return NULL;
}

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
oui_info_t *find_oui(oui_list_t *list, uint64_t oui) {
    oui_info_t *info;
    if (!list) {
        return NULL;
    }

    info = find_oui_info(list->macs, oui);
    if (info) {
        return info;
    }

    info = find_oui_info(list->addr, oui);
    if (info) {
        return info;
    }

    info = find_oui_info(list->manufacturers, oui);
    if (info) {
        return info;
    }
    return NULL;
}

/**
 * Finds the OUI vendor information for a given OUI-value.
 * 
 * @param list the OUI list to search in;
 * @param oui the OUI-value to search for.
 * @return the vendor that owns the given OUI, or NULL in case no vendor information could be found.
 */
const char *find_oui_vendor(oui_list_t *list, uint64_t oui) {
    oui_info_t *info = find_oui(list, oui);
    if (info) {
        return info->manuf;
    }

    return NULL;
}
