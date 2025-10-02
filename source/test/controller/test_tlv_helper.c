/*
 * Copyright (c) 2021-2024 AirTies Wireless Networks
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

#include "map_ctrl_tlv_helper.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static mac_addr g_radio_id = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
static void test_init(void)
{
    fail_unless(!map_info_init());
}

static void test_fini(void)
{
    map_info_fini();
}

/*#######################################################################
#                       TEST_FILL_CHANNEL_SCAN_REQUEST_TLV              #
########################################################################*/
START_TEST(test_fill_channel_scan_request_tlv)
{
    map_channel_scan_request_tlv_t tlv           = {0};
    map_radio_info_t               radio         = {0};
    map_op_class_t                 op_classes[5] = {0};
    map_channel_set_t              channels;
    int                            i;

    test_init();

    /* Set radio data */
    maccpy(radio.radio_id, g_radio_id);

    /* Set channels 36, 40, 44, 48, 52, 56, 60, 100, 104 */
    for (i = 36; i <= 60; i++) {
       map_cs_set(&radio.ctl_channels, i);
    }
    map_cs_set(&radio.ctl_channels, 100);
    map_cs_set(&radio.ctl_channels, 104);

    /* Scan caps */
    op_classes[0].op_class = 115; /* 36, 40, 44, 48 */
    map_cs_set(&op_classes[0].channels, 36);
    map_cs_set(&op_classes[0].channels, 40);
    map_cs_set(&op_classes[0].channels, 44);
    map_cs_set(&op_classes[0].channels, 48);
    op_classes[1].op_class = 118; /* 52, 56, 60, 64 */
    op_classes[2].op_class = 121; /* 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144 */
    map_cs_set(&op_classes[2].channels, 100);
    map_cs_set(&op_classes[2].channels, 104);
    map_cs_set(&op_classes[2].channels, 108);
    map_cs_set(&op_classes[2].channels, 112);
    op_classes[3].op_class = 124; /* 149, 153, 157, 161 */
    op_classes[4].op_class = 128; /* 80MHz */

    radio.scan_caps.op_class_list.op_classes_nr = ARRAY_SIZE(op_classes);
    radio.scan_caps.op_class_list.op_classes = op_classes;

    free_1905_TLV_structure2((uint8_t *)&tlv);


    /* No fresh scan */
    map_fill_channel_scan_request_tlv(&tlv, &radio, false, NULL);

    fail_unless(tlv.tlv_type == TLV_TYPE_CHANNEL_SCAN_REQUEST);
    fail_unless(tlv.fresh_scan_performed    == 0);
    fail_unless(tlv.radios_nr               == 1);
    fail_unless(tlv.radios[0].op_classes_nr == 0);
    fail_unless(!maccmp(tlv.radios[0].radio_id, g_radio_id));

    free_1905_TLV_structure2((uint8_t *)&tlv);


    /* Fresh scan all channels */
    map_fill_channel_scan_request_tlv(&tlv, &radio, true, NULL);

    fail_unless(tlv.tlv_type == TLV_TYPE_CHANNEL_SCAN_REQUEST);
    fail_unless(tlv.fresh_scan_performed    == 1);
    fail_unless(tlv.radios_nr               == 1);
    fail_unless(tlv.radios[0].op_classes_nr == 4);
    fail_unless(!maccmp(tlv.radios[0].radio_id, g_radio_id));
    fail_unless(               tlv.radios[0].op_classes[0].op_class  == 115);
    fail_unless(map_cs_nr(    &tlv.radios[0].op_classes[0].channels) == 4);
    fail_unless(map_cs_is_set(&tlv.radios[0].op_classes[0].channels, 36));
    fail_unless(map_cs_is_set(&tlv.radios[0].op_classes[0].channels, 40));
    fail_unless(map_cs_is_set(&tlv.radios[0].op_classes[0].channels, 44));
    fail_unless(map_cs_is_set(&tlv.radios[0].op_classes[0].channels, 48));
    fail_unless(               tlv.radios[0].op_classes[1].op_class  == 118);
    fail_unless(map_cs_nr(    &tlv.radios[0].op_classes[1].channels) == 0);
    fail_unless(               tlv.radios[0].op_classes[2].op_class  == 121);
    fail_unless(map_cs_nr(    &tlv.radios[0].op_classes[2].channels) == 4);
    fail_unless(map_cs_is_set(&tlv.radios[0].op_classes[2].channels, 100));
    fail_unless(map_cs_is_set(&tlv.radios[0].op_classes[2].channels, 104));
    fail_unless(map_cs_is_set(&tlv.radios[0].op_classes[2].channels, 108));
    fail_unless(map_cs_is_set(&tlv.radios[0].op_classes[2].channels, 112));
    fail_unless(               tlv.radios[0].op_classes[3].op_class == 124);

    free_1905_TLV_structure2((uint8_t *)&tlv);


    /* Fresh scan with channels */
    map_cs_unset_all(&channels);
    map_cs_set(&channels, 36);
    map_cs_set(&channels, 40);
    map_cs_set(&channels, 52);
    map_cs_set(&channels, 56);
    map_cs_set(&channels, 100);
    map_cs_set(&channels, 104);

    map_fill_channel_scan_request_tlv(&tlv, &radio, true, &channels);

    fail_unless(tlv.tlv_type == TLV_TYPE_CHANNEL_SCAN_REQUEST);
    fail_unless(tlv.fresh_scan_performed    == 1);
    fail_unless(tlv.radios_nr               == 1);
    fail_unless(tlv.radios[0].op_classes_nr == 3);
    fail_unless(!maccmp(tlv.radios[0].radio_id, g_radio_id));
    fail_unless(               tlv.radios[0].op_classes[0].op_class  == 115);
    fail_unless(map_cs_nr(    &tlv.radios[0].op_classes[0].channels) == 2);
    fail_unless(map_cs_is_set(&tlv.radios[0].op_classes[0].channels, 36));
    fail_unless(map_cs_is_set(&tlv.radios[0].op_classes[0].channels, 40));
    fail_unless(               tlv.radios[0].op_classes[1].op_class  == 118);
    fail_unless(map_cs_nr(    &tlv.radios[0].op_classes[1].channels) == 2);
    fail_unless(map_cs_is_set(&tlv.radios[0].op_classes[1].channels, 52));
    fail_unless(map_cs_is_set(&tlv.radios[0].op_classes[1].channels, 56));
    fail_unless(               tlv.radios[0].op_classes[2].op_class  == 121);
    fail_unless(map_cs_nr(    &tlv.radios[0].op_classes[2].channels) == 2);
    fail_unless(map_cs_is_set(&tlv.radios[0].op_classes[2].channels, 100));
    fail_unless(map_cs_is_set(&tlv.radios[0].op_classes[2].channels, 104));

    free_1905_TLV_structure2((uint8_t *)&tlv);

    test_fini();
}
END_TEST


const char *test_suite_name = "tlv_helper";
test_case_t test_cases[] = {
    TEST("fill_channel_scan_request_tlv", test_fill_channel_scan_request_tlv  ),
    TEST_CASES_END
};
