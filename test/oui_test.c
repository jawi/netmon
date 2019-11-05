/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

#include "oui.h"

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

oui_list_t *oui_list = { 0 };

static int init_suite(void) {
    oui_list = parse_oui_list("netmon_oui.list");

    return 0;
}

static int clean_suite(void) {
    free_oui_list(oui_list);

    return 0;
}

static void find_no_entry(uint64_t input_oui) {
    oui_info_t *entry = find_oui(oui_list, input_oui);
    CU_ASSERT_PTR_NULL(entry);
}

static void find_oui_entry(uint64_t input_oui, uint64_t expected_oui, const char *expected_vendor) {
    oui_info_t *entry = find_oui(oui_list, input_oui);
    CU_ASSERT_PTR_NOT_NULL_FATAL(entry);
    CU_ASSERT_EQUAL(entry->oui, expected_oui);
    CU_ASSERT_STRING_EQUAL(entry->manuf, expected_vendor);
}

static void test_oui_non_matches(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(oui_list);

    struct tst_vec {
        uint64_t input;
    } tst_vecs[] = {
        { 0x0050c3000000 }, // Not allocated
        { 0x8439bee12345 }, // Not allocated
        { 0x843b00000000 }, // Not allocated
    };

    int tst_vec_cnt = sizeof(tst_vecs) / sizeof(struct tst_vec);
    for (int i = 0; i < tst_vec_cnt; i++) {
        find_no_entry(tst_vecs[i].input);
    }
}

static void test_oui_matches(void) {
    CU_ASSERT_PTR_NOT_NULL_FATAL(oui_list);

    struct tst_vec {
        uint64_t input;
        uint64_t expected_oui;
        const char *expected_vendor;
    } tst_vecs[] = {
        { 0x000000123456, 0x000000000000, "Officially Xerox, but 0:0:0:0:0:0 is more common" },
        { 0x000000000000, 0x000000000000, "Officially Xerox, but 0:0:0:0:0:0 is more common" },
        { 0x000001123456, 0x000001000000, "Xerox Corporation" },
        { 0xfcffaa112233, 0xfcffaa000000, "IEEE Registration Authority" },
        { 0xfcfc48123456, 0xfcfc48000000, "Apple, Inc." },
        { 0x001bc5000234, 0x001bc5000000, "Converging Systems Inc." },
        { 0x001bc5001234, 0x001bc5001000, "OpenRB.com, Direct SIA" },
        { 0x001bc50c9234, 0x001bc50c9000, "UAB Kitron" },
        { 0x001bc50ca234, 0x001bc5000000, "IEEE Registration Authority" },
        { 0x001bc60ca234, 0x001bc6000000, "Strato Rechenzentrum AG" },
        { 0x843838123456, 0x843838000000, "Samsung Electro-Mechanics(Thailand)" },
        { 0x8439be012345, 0x8439be000000, "Hino Engineering, Inc" },
        { 0x0050c2000123, 0x0050c2000000, "T.L.S. Corp." },
        { 0x0050c2003234, 0x0050c2003000, "Microsoft" },
        { 0x0050c200a456, 0x0050c200a000, "Tharsys" },
        { 0x0050c2ffffff, 0x0050c2fff000, "MSR-Solutions GmbH" },
    };

    int tst_vec_cnt = sizeof(tst_vecs) / sizeof(struct tst_vec);
    for (int i = 0; i < tst_vec_cnt; i++) {
        find_oui_entry(tst_vecs[i].input, tst_vecs[i].expected_oui, tst_vecs[i].expected_vendor);
    }
}

CU_pSuite create_oui_test_suite(void) {
    CU_pSuite suite = CU_add_suite("oui test suite", init_suite, clean_suite);
    if (!suite) {
        return NULL;
    }

    if (!CU_add_test(suite, "oui matches", test_oui_matches) ||
            !CU_add_test(suite, "oui misses", test_oui_non_matches)) {
        return NULL;
    }

    return suite;
}
