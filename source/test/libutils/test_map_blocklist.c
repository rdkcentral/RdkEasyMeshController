/*
 * Copyright (c) 2022-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include "map_blocklist.h"
#include "test.h"

/*#######################################################################
#                   GLOBALS                                             #
########################################################################*/
static mac_addr g_mac1 = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
static mac_addr g_mac2 = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
static mac_addr g_mac3 = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25};

static int g_update_cb_called;
static int g_iter_cb_called;

/*#######################################################################
#                   HELP FUNCTIONS                                      #
########################################################################*/
static void dummy_printf(const char *fmt, ...)
{
}

static void update_cb(void)
{
    g_update_cb_called++;
}

static void iter_cb(mac_addr mac, map_block_reason_t reason, size_t idx, void *data)
{
    fail_unless(idx >= 0 && idx <= 2);
    fail_unless(data == (void*)0x123);

    if (idx == 0) {
        fail_unless(!maccmp(mac, g_mac1));
        fail_unless(reason == THIRD_PARTY_CONTROLLER);
        g_iter_cb_called |= 0x01;
    }

    if (idx == 1) {
        fail_unless(!maccmp(mac, g_mac2));
        fail_unless(reason == THIRD_PARTY_AGENT);
        g_iter_cb_called |= 0x02;
    }
}

/*#######################################################################
#                   TEST_BLOCKLIST                                      #
########################################################################*/
START_TEST(test_blocklist)
{
    map_blocked_dev_info_t *dev;

    fail_unless(!map_blocklist_init());

    map_blocklist_register_update_cb(update_cb);

    /* Add */
    fail_unless(!!(dev = map_blocklist_add_dev(g_mac1, THIRD_PARTY_CONTROLLER)));
    fail_unless(map_blocklist_get_nr_dev() == 1);
    fail_unless(g_update_cb_called == 1);

    fail_unless(!!(dev = map_blocklist_add_dev(g_mac2, THIRD_PARTY_AGENT)));
    fail_unless(map_blocklist_get_nr_dev() == 2);
    fail_unless(g_update_cb_called == 2);

    /* Dump */
    map_blocklist_dump(dummy_printf);

    /* Get */
    fail_unless(!!(dev = map_blocklist_get_dev(g_mac1)));
    fail_unless(!!(dev = map_blocklist_get_dev(g_mac2)));
    fail_unless(!(dev = map_blocklist_get_dev(g_mac3)));

    /* Iter */
    map_bloclist_iter_dev(iter_cb, (void*)0x123);
    fail_unless(g_iter_cb_called == 0x03);

    /* Del */
    fail_unless(!!(dev = map_blocklist_get_dev(g_mac1)));
    fail_unless(!map_blocklist_remove_dev(dev));
    fail_unless(g_update_cb_called == 3);
    fail_unless(map_blocklist_get_nr_dev() == 1);
    fail_unless(!(dev = map_blocklist_get_dev(g_mac1)));

    map_blocklist_fini();
}
END_TEST

const char *test_suite_name = "blocklist";
test_case_t test_cases[] = {
    TEST("blocklist", test_blocklist  ),
    TEST_CASES_END
};
