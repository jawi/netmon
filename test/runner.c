/*
 * netmon - simple Linux network monitor
 *
 * Copyright: (C) 2019 jawi
 *   License: Apache License 2.0
 */

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>

// oui_test.c
extern CU_pSuite create_oui_test_suite(void);

int main(void) {
    // initialize the CUnit test registry
    if (CU_initialize_registry()) {
        return CU_get_error();
    }

    // add a suite to the registry
    CU_pSuite suite = create_oui_test_suite();
    if (!suite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_basic_show_failures(CU_get_failure_list());

    CU_cleanup_registry();

    return CU_get_error();
}
