/*
 * Copyright (c) 2017-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <time.h>

#include "test.h"

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
__attribute__((weak)) enum fork_status desired_fork_mode = CK_NOFORK;

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
static void teardown(void)
{
}

static Suite* create_suite(void)
{
    Suite *s;
    /* to test only one function, pass function name to below parameter */
    char *test_name = getenv("SINGLE_TEST_LOG");
    s = suite_create(test_suite_name);
    for (test_case_t *t = test_cases; NULL != t->name; t++) {
        if (test_name) {
            if (strcmp(test_name, t->name) != 0) {
                continue;
            }
        }
        TCase *tc = tcase_create(t->name);
        if (0 != t->timeout) {
            tcase_set_timeout(tc, t->timeout);
        }
#ifdef CHECK_HAS_TTEST
        _tcase_add_test(tc, *t->test, 0, 0, 0, 1);
#else
        _tcase_add_test(tc, t->function, t->name, 0, 0, 0, 1);
#endif
        tcase_add_checked_fixture(tc, NULL, teardown);
        suite_add_tcase(s, tc);
    }
    return s;
}

/*#######################################################################
#                       MAIN                                            #
########################################################################*/
int main(void)
{
    int number_failed;
    SRunner *sr;
    Suite *s;
    char fname[128];

    s = create_suite();
    sr = srunner_create(s);

    snprintf(fname, sizeof(fname), "%s-testresults.xml", test_suite_name);
    srunner_set_xml(sr, fname);
    srunner_set_fork_status(sr, desired_fork_mode);
    srunner_run_all(sr, CK_ENV);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
