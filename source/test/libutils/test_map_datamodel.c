/*
 * Copyright (c) 2019-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include "test.h"
#include "map_data_model.h"
#include "map_data_model_dumper.h"

/*#######################################################################
#                   HELP FUNCTIONS                                      #
########################################################################*/
static void dummy_printf(const char *fmt, ...)
{
}

/*#######################################################################
#                   TEST_DATAMODEL                                      #
########################################################################*/
START_TEST(test_datamodel)
{
    mac_addr ale_mac1 = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    mac_addr ale_mac2 = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
    mac_addr radio_id = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03};
    mac_addr bssid1   = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04};
    mac_addr bssid2   = {0x00, 0x00, 0x00, 0x00, 0x00, 0x05};
    mac_addr sta_mac1 = {0x00, 0x00, 0x00, 0x00, 0x00, 0x06};
    mac_addr sta_mac2 = {0x00, 0x00, 0x00, 0x00, 0x00, 0x07};
    mac_addr sta_mac3 = {0x00, 0x00, 0x00, 0x00, 0x00, 0x08};

    map_ale_info_t   *ale1, *ale2;
    map_radio_info_t *radio1, *radio2;
    map_bss_info_t   *bss1, *bss2;
    map_sta_info_t   *sta, *sta1, *sta2, *sta3;

    int               count;

    fail_unless(!map_dm_init());

    fail_unless(!!(ale1   = map_dm_create_ale(ale_mac1)));
    fail_unless(!!(ale2   = map_dm_create_ale(ale_mac2)));
    fail_unless(!!(radio1 = map_dm_create_radio(ale1, radio_id)));
    fail_unless(!!(radio2 = map_dm_create_radio(ale2, radio_id))); /* Same Id -> not unique */
    fail_unless(!!(bss1   = map_dm_create_bss(radio1, bssid1)));
    fail_unless(!!(bss2   = map_dm_create_bss(radio1, bssid2)));
    fail_unless(!!(sta1   = map_dm_create_sta(bss1, sta_mac1)));
    fail_unless(!!(sta2   = map_dm_create_sta(bss1, sta_mac2)));
    fail_unless(!!(sta3   = map_dm_create_sta(bss2, sta_mac3)));

    /* Get back */
    fail_unless(ale1->radios_nr == 1);
    fail_unless(ale2->radios_nr == 1);
    fail_unless(radio1->bsss_nr == 2);
    fail_unless(radio2->bsss_nr == 0);
    fail_unless(bss1->stas_nr   == 2);
    fail_unless(bss2->stas_nr   == 1);

    fail_unless(ale1   == map_dm_get_ale(ale_mac1));
    fail_unless(ale2   == map_dm_get_ale(ale_mac2));
    fail_unless(radio1 == map_dm_get_radio(ale1, radio_id));
    fail_unless(!strcmp(radio1->radio_id_base64, "AAAAAAAD"));
    fail_unless(radio2 == map_dm_get_radio(ale2, radio_id));
    fail_unless(bss1   == map_dm_get_bss(radio1, bssid1));
    fail_unless(bss1   == map_dm_get_bss_from_ale(ale1, bssid1));
    fail_unless(bss1   == map_dm_get_bss_gbl(bssid1));
    fail_unless(bss2   == map_dm_get_bss(radio1, bssid2));
    fail_unless(bss2   == map_dm_get_bss_from_ale(ale1, bssid2));
    fail_unless(bss2   == map_dm_get_bss_gbl(bssid2));
    fail_unless(sta1   == map_dm_get_sta(bss1, sta_mac1));
    fail_unless(sta1   == map_dm_get_sta_from_ale(ale1, sta_mac1));
    fail_unless(sta1   == map_dm_get_sta_gbl(sta_mac1));
    fail_unless(sta2   == map_dm_get_sta(bss1, sta_mac2));
    fail_unless(sta2   == map_dm_get_sta_from_ale(ale1, sta_mac2));
    fail_unless(sta2   == map_dm_get_sta_gbl(sta_mac2));
    fail_unless(sta3   == map_dm_get_sta(bss2, sta_mac3));
    fail_unless(sta3   == map_dm_get_sta_from_ale(ale1, sta_mac3));
    fail_unless(sta3   == map_dm_get_sta_gbl(sta_mac3));

    fail_unless(NULL   == map_dm_get_bss(radio2, bssid1));
    fail_unless(NULL   == map_dm_get_bss_from_ale(ale2, bssid1));
    fail_unless(NULL   == map_dm_get_sta(bss2, sta_mac1));
    fail_unless(NULL   == map_dm_get_sta_from_ale(ale2, sta_mac1));

    count = 0;
    map_dm_foreach_sta(bss1, sta) {
        fail_unless(!maccmp(sta->mac, sta_mac1) || !maccmp(sta->mac, sta_mac2));
        count++;
    }
    fail_unless(count == 2);

    /* Move sta */
    map_dm_update_sta_bss(bss1, sta3);
    fail_unless(bss1->stas_nr   == 3);
    fail_unless(bss2->stas_nr   == 0);

    count = 0;
    map_dm_foreach_sta(bss1, sta) {
        fail_unless(!maccmp(sta->mac, sta_mac1) || !maccmp(sta->mac, sta_mac2) || !maccmp(sta->mac, sta_mac3));
        count++;
    }
    fail_unless(count == 3);


    /* For code coverage... */
    map_dm_dump_agent_info_tree(dummy_printf);

    map_dm_remove_sta(sta1);
    map_dm_remove_sta(sta2);
    map_dm_remove_sta(sta3);
    map_dm_remove_bss(bss1);
    map_dm_remove_bss(bss2);
    map_dm_remove_radio(radio1);
    map_dm_remove_radio(radio2);
    map_dm_remove_ale(ale1);
    map_dm_remove_ale(ale2);

    map_dm_fini();
}
END_TEST

/*#######################################################################
#                   TEST_INACTIVE_STA                                      #
########################################################################*/
START_TEST(test_inactive_sta)
{
#define NUM_MACS (MAX_INACTIVE_STA + 10)
    mac_addr  ale_mac  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    mac_addr  radio_id = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03};
    mac_addr  bssid    = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04};
    mac_addr  macs[NUM_MACS];
    uint8_t  *p        = (uint8_t *)macs;

    map_ale_info_t   *ale;
    map_radio_info_t *radio;
    map_bss_info_t   *bss;
    map_sta_info_t   *sta;
    map_sta_info_t   *stas[NUM_MACS] = { 0 };
    int i;

    fail_unless(NUM_MACS > MAX_INACTIVE_STA);

    fail_unless(!map_dm_init());
    fail_unless(!!(ale   = map_dm_create_ale(ale_mac)));
    fail_unless(!!(radio = map_dm_create_radio(ale, radio_id)));
    fail_unless(!!(bss   = map_dm_create_bss(radio, bssid)));

    /* Create random sta */
    for (i = 0; i<sizeof(macs); i++) {
        p[i] = (i * 257) % 251;
    }

    /* No mac is in inactive list */
    for (i = 0; i < NUM_MACS; i++) {
        fail_unless(!map_dm_is_inactive_sta(macs[i]));
    }

    /* Add 20, remove 10 */
    for (i = 0; i < 20; i++) {
        fail_unless(!!(stas[i] = map_dm_create_sta(bss, macs[i])));
        if (i < 10) {
            map_dm_remove_sta(stas[i]);
            stas[i] = NULL;
        }
    }

    for (i = 0; i < NUM_MACS; i++) {
        fail_unless(map_dm_is_inactive_sta(macs[i]) == (i < 10) ? true : false);
    }

    /* Remove other 10 */
    for (i = 10; i < 20; i++) {
        map_dm_remove_sta(stas[i]);
        stas[i] = NULL;
    }

    for (i = 0; i < NUM_MACS; i++) {
        fail_unless(map_dm_is_inactive_sta(macs[i]) == (i < 20) ? true : false);
    }

    /* Again add 20 */
    for (i = 0; i < 20; i++) {
        fail_unless(!!(stas[i] = map_dm_create_sta(bss, macs[i])));
    }

    for (i = 0; i < NUM_MACS; i++) {
        fail_unless(map_dm_is_inactive_sta(macs[i]) == false);
    }

    /* Add and remove all.  The first will be removed from inactive list when it is full */
    for (i = 0; i < NUM_MACS; i++) {
        fail_unless(!!(sta = map_dm_create_sta(bss, macs[i])));
        map_dm_remove_sta(sta);
        fail_unless(map_dm_is_inactive_sta(macs[i]) == true);
    }

    /* First 10 are removed from list... */
    for (i = 0; i < NUM_MACS; i++) {
        fail_unless(map_dm_is_inactive_sta(macs[i]) == (i >= (NUM_MACS - MAX_INACTIVE_STA)) ? true : false);
    }

    map_dm_fini();
}
END_TEST

/*#######################################################################
#                   TEST_MARK_STA                                       #
########################################################################*/
START_TEST(test_mark_sta)
{
    mac_addr  ale_mac   = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    mac_addr  radio_id1 = {0x01, 0x00, 0x00, 0x00, 0x00, 0x01};
    mac_addr  radio_id2 = {0x01, 0x00, 0x00, 0x00, 0x00, 0x02};
    mac_addr  bssid1    = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    mac_addr  bssid2    = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    mac_addr  bssid3    = {0x02, 0x00, 0x00, 0x00, 0x00, 0x03};
    mac_addr  bssid4    = {0x02, 0x00, 0x00, 0x00, 0x00, 0x04};
    mac_addr  mac1      = {0x03, 0x00, 0x00, 0x00, 0x00, 0x01};
    mac_addr  mac2      = {0x03, 0x00, 0x00, 0x00, 0x00, 0x02};
    mac_addr  mac3      = {0x03, 0x00, 0x00, 0x00, 0x00, 0x03};
    mac_addr  mac4      = {0x03, 0x00, 0x00, 0x00, 0x00, 0x04};
    mac_addr  mac5      = {0x03, 0x00, 0x00, 0x00, 0x00, 0x05};

    map_ale_info_t   *ale;
    map_radio_info_t *radio1, *radio2;
    map_bss_info_t   *bss1, *bss2, *bss3, *bss4;
    map_sta_info_t   *sta1, *sta2, *sta3, *sta4, *sta5;

    fail_unless(!map_dm_init());
    fail_unless(!!(ale   = map_dm_create_ale(ale_mac)));
    fail_unless(!!(radio1 = map_dm_create_radio(ale, radio_id1)));
    fail_unless(!!(radio2 = map_dm_create_radio(ale, radio_id2)));
    fail_unless(!!(bss1 = map_dm_create_bss(radio1, bssid1)));
    fail_unless(!!(bss2 = map_dm_create_bss(radio1, bssid2)));
    fail_unless(!!(bss3 = map_dm_create_bss(radio2, bssid3)));
    fail_unless(!!(bss4 = map_dm_create_bss(radio2, bssid4)));
    fail_unless(!!(sta1 = map_dm_create_sta(bss1, mac1)));
    fail_unless(!!(sta2 = map_dm_create_sta(bss2, mac2)));
    fail_unless(!!(sta3 = map_dm_create_sta(bss3, mac3)));
    fail_unless(!!(sta4 = map_dm_create_sta(bss4, mac4)));
    fail_unless(!!(sta5 = map_dm_create_sta(bss4, mac5)));

    /* Mark all stas */
    map_dm_mark_stas(ale);
    fail_unless(map_dm_is_marked_sta(sta1) && map_dm_is_marked_sta(sta2) &&
                map_dm_is_marked_sta(sta3) && map_dm_is_marked_sta(sta4) &&
                map_dm_is_marked_sta(sta5));

    /* Unmark sta1 and sta2 */
    map_dm_unmark_sta(sta1);
    map_dm_unmark_sta(sta2);

    /* sta3 and sta4 associated a long time ago, sta5 just */
    sta3->assoc_ts = map_dm_get_sta_assoc_ts(5000);
    sta4->assoc_ts = map_dm_get_sta_assoc_ts(5000);
    sta5->assoc_ts = map_dm_get_sta_assoc_ts(5);

    /* Remove unmarked - sta3 and sta4 got removed */
    map_dm_remove_marked_stas(ale, 1000);

    fail_unless(!!map_dm_get_sta_gbl(mac1));
    fail_unless(!!map_dm_get_sta_gbl(mac2));
    fail_unless(!map_dm_get_sta_gbl(mac3));
    fail_unless(!map_dm_get_sta_gbl(mac4));
    fail_unless(!!map_dm_get_sta_gbl(mac5));

    map_dm_fini();
}
END_TEST

/*#######################################################################
#                   TEST_CLEANUP                                        #
########################################################################*/
START_TEST(test_cleanup)
{
    mac_addr ale_mac  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    mac_addr radio_id = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
    mac_addr bssid    = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03};
    mac_addr sta_mac  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04};

    map_ale_info_t   *ale;
    map_radio_info_t *radio;
    map_bss_info_t   *bss;
    map_sta_info_t   *sta;

    fail_unless(!map_dm_init());

    fail_unless(!!(ale   = map_dm_create_ale(ale_mac)));
    fail_unless(!!(radio = map_dm_create_radio(ale, radio_id)));
    fail_unless(!!(bss   = map_dm_create_bss(radio, bssid)));
    fail_unless(!!(sta   = map_dm_create_sta(bss, sta_mac)));

    ale_mac[4]++;
    radio_id[4]++;
    bssid[4]++;
    fail_unless(!!(ale   = map_dm_create_ale(ale_mac)));
    fail_unless(!!(radio = map_dm_create_radio(ale, radio_id)));
    fail_unless(!!(bss   = map_dm_create_bss(radio, bssid)));
    fail_unless(!!(sta   = map_dm_create_sta(bss, sta_mac)));

    /* map_datamodel_fini must remove all objects */
    map_dm_fini();
}
END_TEST

const char *test_suite_name = "map_datamodel";
test_case_t test_cases[] = {
    TEST("datamodel",    test_datamodel  ),
    TEST("inactive_sta", test_inactive_sta  ),
    TEST("mark_sta",     test_mark_sta  ),
    TEST("cleanup",      test_cleanup  ),
    TEST_CASES_END
};
