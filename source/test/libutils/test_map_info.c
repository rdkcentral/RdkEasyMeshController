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
#include "map_info.h"


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
#                   TEST_OP_CLASS                                       #
########################################################################*/
START_TEST(test_op_class)
{
    map_channel_set_t ch_set;
    uint8_t           center_op_classes[]     = {128, 129, 132, 133, 134, 137};
    uint8_t           not_center_op_classes[] = { 81,  82,  83, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127};
    bool              is_center_chan;
    int i;

    test_init();

    fail_unless(map_get_op_class(6, 20, IEEE80211_FREQUENCY_BAND_2_4_GHZ) == 81);
    fail_unless(map_get_op_class(6, 40, IEEE80211_FREQUENCY_BAND_2_4_GHZ) == 83);
    fail_unless(map_get_op_class(11, 40, IEEE80211_FREQUENCY_BAND_2_4_GHZ) == 84);

    fail_unless(map_get_op_class_20MHz(6, IEEE80211_FREQUENCY_BAND_2_4_GHZ)  == 81);
    fail_unless(map_get_op_class_20MHz(11, IEEE80211_FREQUENCY_BAND_2_4_GHZ) == 81);

    fail_unless(map_get_op_class(100, 20, IEEE80211_FREQUENCY_BAND_5_GHZ)  == 121);
    fail_unless(map_get_op_class(100, 40, IEEE80211_FREQUENCY_BAND_5_GHZ)  == 122);
    fail_unless(map_get_op_class(100, 80, IEEE80211_FREQUENCY_BAND_5_GHZ)  == 128);
    fail_unless(map_get_op_class(100, 160, IEEE80211_FREQUENCY_BAND_5_GHZ) == 129);

    fail_unless(map_get_op_class(165, 20, IEEE80211_FREQUENCY_BAND_5_GHZ)  == 125);

    fail_unless(map_get_op_class(101, 20, IEEE80211_FREQUENCY_BAND_5_GHZ) == 0);

    fail_unless(map_get_op_class(101, 20,  IEEE80211_FREQUENCY_BAND_6_GHZ)  == 131);
    fail_unless(map_get_op_class(165, 20,  IEEE80211_FREQUENCY_BAND_6_GHZ)  == 131);
    fail_unless(map_get_op_class(165, 40,  IEEE80211_FREQUENCY_BAND_6_GHZ)  == 132);
    fail_unless(map_get_op_class(165, 80,  IEEE80211_FREQUENCY_BAND_6_GHZ)  == 133);
    fail_unless(map_get_op_class(165, 320, IEEE80211_FREQUENCY_BAND_6_GHZ)  == 137);

    fail_unless(map_is_channel_in_op_class(81, 13));
    fail_unless(map_is_channel_in_op_class(128, 106));
    fail_unless(!map_is_channel_in_op_class(128, 100));
    fail_unless(!map_is_channel_in_op_class(134, 95));
    fail_unless(!map_is_channel_in_op_class(134, 97));
    fail_unless(map_is_channel_in_op_class(134, 111));
    fail_unless(map_is_channel_in_op_class(137, 95));
    fail_unless(!map_is_channel_in_op_class(137, 97));

    fail_unless(map_get_channel_set_from_op_class(81, &ch_set) == 0);
    fail_unless(map_cs_nr(&ch_set) == 13);
    map_cs_foreach(&ch_set, i) {
        fail_unless(i >= 1 && i <= 13);
    }

    fail_unless(map_get_channel_set_from_op_class(134, &ch_set) == 0);
    fail_unless(map_cs_nr(&ch_set) == 56);
    map_cs_foreach(&ch_set, i) {
        fail_unless(i >= 1 && i <= 221 && (i % 4) == 1);
    }

    fail_unless(map_get_center_channel_set_from_op_class(134, &ch_set) == 0);
    fail_unless(map_cs_nr(&ch_set) == 7);
    map_cs_foreach(&ch_set, i) {
        fail_unless(i >= 15 && i <= 207 && (i % 32) == 15);
    }

    for (i = 0; i < ARRAY_SIZE(center_op_classes); i++) {
        fail_unless(map_get_is_center_channel_from_op_class(center_op_classes[i], &is_center_chan) == 0);
        fail_unless(is_center_chan);
    }

    for (i = 0; i < ARRAY_SIZE(not_center_op_classes); i++) {
        fail_unless(map_get_is_center_channel_from_op_class(not_center_op_classes[i], &is_center_chan) == 0);
        fail_unless(!is_center_chan);
    }

    test_fini();
}
END_TEST

/*#######################################################################
#                   TEST_CHANNELS                                       #
########################################################################*/
START_TEST(test_channels)
{
    map_channel_set_t ch_set = {0};
    uint8_t c;
    int i;

    test_init();

    fail_unless(map_is_ctl_channel(6, IEEE80211_FREQUENCY_BAND_2_4_GHZ));
    fail_unless(map_is_ctl_channel(14, IEEE80211_FREQUENCY_BAND_2_4_GHZ));
    fail_unless(map_is_ctl_channel(36, IEEE80211_FREQUENCY_BAND_5_GHZ));
    fail_unless(map_is_ctl_channel(177, IEEE80211_FREQUENCY_BAND_5_GHZ));
    fail_unless(map_is_ctl_channel(5, IEEE80211_FREQUENCY_BAND_6_GHZ));
    fail_unless(map_is_ctl_channel(221, IEEE80211_FREQUENCY_BAND_6_GHZ));

    fail_unless(!map_is_ctl_channel(38, IEEE80211_FREQUENCY_BAND_5_GHZ));
    fail_unless(!map_is_ctl_channel(42, IEEE80211_FREQUENCY_BAND_5_GHZ));
    fail_unless(!map_is_ctl_channel(50, IEEE80211_FREQUENCY_BAND_5_GHZ));

    fail_unless(map_is_2G_ctl_channel(6));
    fail_unless(!map_is_5G_ctl_channel(6));
    fail_unless(!map_is_6G_ctl_channel(6));

    fail_unless(!map_is_2G_ctl_channel(36));
    fail_unless(map_is_5G_ctl_channel(36));
    fail_unless(!map_is_6G_ctl_channel(36));

    fail_unless(!map_is_2G_ctl_channel(221));
    fail_unless(!map_is_5G_ctl_channel(221));
    fail_unless(map_is_6G_ctl_channel(221));


    map_get_2G_ctl_channel_set(&ch_set);
    for (i = 0; i < 255; i++) {
        bool exp = (i >= 1 && i <= 14);
        fail_unless(exp == map_cs_is_set(&ch_set, i));
    }

    map_cs_foreach(&ch_set, c) {
        fail_unless(map_is_2G_ctl_channel(c));
    }


    map_get_5G_ctl_channel_set(&ch_set);
    for (i = 0; i < 255; i++) {
        bool exp = (((i >= 36 && i <= 64) || (i >= 100 && i <= 144)) && (i % 4 == 0)) ||
                   ((i >= 149 && i <= 177) && (i % 4 == 1));
        fail_unless(exp == map_cs_is_set(&ch_set, i));
    }

    map_cs_foreach(&ch_set, c) {
        fail_unless(map_is_5G_ctl_channel(c));
        if (c < 100) {
            fail_unless(map_is_5G_low_ctl_channel(c));
        } else {
            fail_unless(map_is_5G_high_ctl_channel(c));
        }
    }


    map_get_5G_low_ctl_channel_set(&ch_set);
    for (i = 0; i < 255; i++) {
        bool exp = ((i >= 36 && i <= 64) && (i % 4 == 0));
        fail_unless(exp == map_cs_is_set(&ch_set, i));
    }

    map_cs_foreach(&ch_set, c) {
        fail_unless(map_is_5G_ctl_channel(c));
        fail_unless(map_is_5G_low_ctl_channel(c));
    }


    map_get_5G_high_ctl_channel_set(&ch_set);
    for (i = 0; i < 255; i++) {
        bool exp = ((i >= 100 && i <= 144) && (i % 4 == 0)) || ((i >= 149 && i <= 177) && (i % 4 == 1));
        fail_unless(exp == map_cs_is_set(&ch_set, i));
    }

    map_cs_foreach(&ch_set, c) {
        fail_unless(map_is_5G_ctl_channel(c));
        fail_unless(map_is_5G_high_ctl_channel(c));
    }


    map_get_5G_weatherband_channel_set(&ch_set);
    for (i = 0; i < 255; i++) {
        bool exp = (i == 120 || i == 124 || i == 128);
        fail_unless(exp == map_cs_is_set(&ch_set, i));
    }


    map_get_6G_ctl_channel_set(&ch_set);
    for (i = 0; i < 255; i++) {
        bool exp = (i == 1) || (i == 2) || ((i >= 5 && i <= 233) && (i % 4 == 1));
        fail_unless(exp == map_cs_is_set(&ch_set, i));
    }

    map_cs_foreach(&ch_set, c) {
        fail_unless(map_is_6G_ctl_channel(c));
    }


    map_get_6G_psc_channel_set(&ch_set);
    fail_unless(map_cs_nr(&ch_set) == 15);
    for (i = 0; i < 255; i++) {
        bool exp = (i >= 5) && (i <= 229) && (((i - 5) % 16) == 0);
        fail_unless(exp == map_cs_is_set(&ch_set, i));
    }


    /* Get center channels - returns error when op class does not use center channels */
    fail_unless( map_get_center_channel(81,  1,   &c));             /* no center */
    fail_unless( map_get_center_channel(126, 149, &c));             /* no center */
    fail_unless( map_get_center_channel(128, 101, &c));             /* center - invalid channel */
    fail_unless( map_get_center_channel(137, 76,  &c));             /* center - invalid channel */
    fail_unless(!map_get_center_channel(128, 100, &c) && c == 106); /* center */
    fail_unless(!map_get_center_channel(129, 40,  &c) && c == 50);  /* center */
    fail_unless(!map_get_center_channel(132, 9,   &c) && c == 11);  /* center */
    fail_unless(!map_get_center_channel(133, 9,   &c) && c == 7);   /* center */
    fail_unless(!map_get_center_channel(134, 9,   &c) && c == 15);  /* center */
    fail_unless(!map_get_center_channel(132, 77,  &c) && c == 75);  /* center */
    fail_unless(!map_get_center_channel(133, 77,  &c) && c == 71);  /* center */
    fail_unless(!map_get_center_channel(134, 77,  &c) && c == 79);  /* center */
    fail_unless(!map_get_center_channel(137, 77,  &c) && c == 95);  /* center */

    test_fini();
}
END_TEST

/*#######################################################################
#                   TEST_BW                                             #
########################################################################*/
START_TEST(test_bw)
{
    uint16_t bw;

    test_init();

    fail_unless(!map_get_bw_from_op_class(81,  &bw) && bw == 20);
    fail_unless(!map_get_bw_from_op_class(126, &bw) && bw == 40);
    fail_unless(!map_get_bw_from_op_class(128, &bw) && bw == 80);
    fail_unless(!map_get_bw_from_op_class(128, &bw) && bw == 80);
    fail_unless(!map_get_bw_from_op_class(129, &bw) && bw == 160);
    fail_unless(!map_get_bw_from_op_class(131, &bw) && bw == 20);
    fail_unless(!map_get_bw_from_op_class(132, &bw) && bw == 40);
    fail_unless(!map_get_bw_from_op_class(133, &bw) && bw == 80);
    fail_unless(!map_get_bw_from_op_class(134, &bw) && bw == 160);
    fail_unless(!map_get_bw_from_op_class(137, &bw) && bw == 320);

    test_fini();
}
END_TEST

/*#######################################################################
#                   TEST_SUBBAND_RANGE                                  #
########################################################################*/
START_TEST(test_subband_range)
{
    uint8_t from, to;

    test_init();

    fail_unless(0 == map_get_subband_channel_range(81,  1,   &from, &to) && from == 1 && to == 1);
    fail_unless(0 == map_get_subband_channel_range(115, 36,  &from, &to) && from == 36 && to == 36);
    fail_unless(0 == map_get_subband_channel_range(126, 149, &from, &to) && from == 149 && to == 153);
    fail_unless(0 == map_get_subband_channel_range(131, 17,  &from, &to) && from == 17 && to == 17);
    fail_unless(0 == map_get_subband_channel_range(128, 40,  &from, &to) && from == 36  && to  == 48);
    fail_unless(0 == map_get_subband_channel_range(128, 149, &from, &to) && from == 149 && to == 161);
    fail_unless(0 == map_get_subband_channel_range(129, 52,  &from, &to) && from == 36  && to  == 64);
    fail_unless(0 == map_get_subband_channel_range(129, 100, &from, &to) && from == 100 && to == 128);
    fail_unless(0 == map_get_subband_channel_range(129, 153, &from, &to) && from == 149 && to == 177);
    fail_unless(0 == map_get_subband_channel_range(132, 17,  &from, &to) && from == 17  && to == 21);
    fail_unless(0 == map_get_subband_channel_range(133, 17,  &from, &to) && from == 17  && to == 29);
    fail_unless(0 == map_get_subband_channel_range(134, 17,  &from, &to) && from == 1   && to == 29);
    fail_unless(0 == map_get_subband_channel_range(137, 17,  &from, &to) && from == 1   && to == 61);

    test_fini();
}
END_TEST

/*#######################################################################
#                   TEST_INVALID_OP_CLASS                               #
########################################################################*/
START_TEST(test_invalid_op_class)
{
    map_channel_set_t ch_set;
    uint16_t          dummy_16;
    uint8_t           dummy_8;
    bool              dummy_b;

    test_init();
    map_cs_unset_all(&ch_set);

    /* In order of appearance in map_info.h */
    fail_unless(map_get_frequency_type(40, &ch_set, &dummy_8, &dummy_16));
    fail_unless(!map_is_5g_low_op_class(111));
    fail_unless(!map_is_5g_high_op_class(111));
    fail_unless(!map_is_channel_in_op_class(250, 100));
    fail_unless(map_get_center_channel(40, 100, &dummy_8));
    fail_unless(map_get_ext_channel_type(250) == MAP_EXT_CHANNEL_NONE);
    fail_unless(map_get_subband_channel_range(40, 100, &dummy_8, &dummy_8));
    fail_unless(map_get_bw_from_op_class(111, &dummy_16));
    fail_unless(map_get_band_from_op_class(250, &dummy_8));
    fail_unless(map_get_is_center_channel_from_op_class(40, &dummy_b));
    fail_unless(map_get_channel_set_from_op_class(111, &ch_set));
    fail_unless(map_get_center_channel_set_from_op_class(250, &ch_set));

    test_fini();
}
END_TEST

/*#######################################################################
#                   TEST_6G_320MHz                                      #
########################################################################*/
START_TEST(test_6G_320MHz)
{
    uint8_t c;
    uint8_t center_channel;
    uint8_t from, to;
    int ret;

    fail_unless(map_is_6G_320MHz_op_class(137));
    fail_unless(!map_is_6G_320MHz_op_class(134));

    /* map_get_center_channel_6G_320MHz */
    for (c = 0; c < 255; c++) {
        ret = map_get_center_channel_6G_320MHz(137, false, c, &center_channel);
        if (c % 4 != 1 || c < 1 || c > 189) {
            fail_unless(ret);
        } else {
            fail_unless(!ret);
            fail_unless(center_channel == ((c / 64) * 64) + 31);
        }

        ret = map_get_center_channel_6G_320MHz(137, true, c, &center_channel);
        if (c % 4 != 1 || c < 33 || c > 221) {
            fail_unless(ret);
        } else {
            fail_unless(!ret);
            fail_unless(center_channel == (((c - 32) / 64) * 64) + 63);
        }

    }

    /* map_get_subband_channel_range_6G_320MHz */
    for (c = 0; c < 255; c++) {
        ret = map_get_subband_channel_range_6G_320MHz(137, false, c, &from, &to);
        if (c % 4 != 1 || c < 1 || c > 189) {
            fail_unless(ret);
        } else {
            fail_unless(!ret);
            center_channel = ((c / 64) * 64) + 31;
            fail_unless(from == center_channel - 30 && to == center_channel + 30);
        }

        ret = map_get_subband_channel_range_6G_320MHz(137, true, c, &from, &to);
        if (c % 4 != 1 || c < 33 || c > 221) {
            fail_unless(ret);
        } else {
            fail_unless(!ret);
            center_channel =  (((c - 32) / 64) * 64) + 63;
            fail_unless(from == center_channel - 30 && to == center_channel + 30);
        }
    }
}
END_TEST

const char *test_suite_name = "map_info";
test_case_t test_cases[] = {
    TEST("op_class",         test_op_class  ),
    TEST("channels",         test_channels  ),
    TEST("bw",               test_bw        ),
    TEST("subband_range",    test_subband_range  ),
    TEST("invalid_op_class", test_invalid_op_class ),
    TEST("6G_320MHz",        test_6G_320MHz ),
    TEST_CASES_END
};
