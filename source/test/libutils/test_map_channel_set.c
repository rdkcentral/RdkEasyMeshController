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
#include "map_channel_set.h"

/*#######################################################################
#                   TEST_CHANNEL_SET                                    #
########################################################################*/
START_TEST(test_channel_set)
{
    map_channel_set_t ch_set;
    map_channel_set_t ch_set2;
    map_channel_bw_set_t ch_bw_set;

    int count = 0;
    int i;
    char buf[128];

    /* map_cs_unset_all */
    map_cs_unset_all(&ch_set);

    fail_unless(map_cs_nr(&ch_set) == 0);
    for (i = 0; i < 255; i++) {
        fail_unless(false == map_cs_is_set(&ch_set, i));
    }

    /* map_cs_set */
    map_cs_set(&ch_set, 1);
    map_cs_set(&ch_set, 36);
    map_cs_set(&ch_set, 100);
    fail_unless(map_cs_nr(&ch_set) == 3);
    for (i = 0; i < 255; i++) {
        bool exp = (i == 1 || i == 36 || i == 100);
        fail_unless(exp == map_cs_is_set(&ch_set, i));
    }

    /* map_cs_foreach */
    map_cs_foreach(&ch_set, i) {
        fail_unless(i == 1 || i == 36 || i == 100);
        count++;
    }
    fail_unless(count == 3);

    /* map_cs_unset */
    map_cs_unset(&ch_set, 36);
    for (i = 0; i < 255; i++) {
        bool exp = (i == 1 || i == 100);
        fail_unless(exp == map_cs_is_set(&ch_set, i));
    }

    map_cs_unset(&ch_set, 1);
    for (i = 0; i < 255; i++) {
        bool exp = (i == 100);
        fail_unless(exp == map_cs_is_set(&ch_set, i));
    }

    map_cs_unset(&ch_set, 100);
    fail_unless(map_cs_nr(&ch_set) == 0);
    for (i = 0; i < 255; i++) {
        fail_unless(false == map_cs_is_set(&ch_set, i));
    }

    /* map_cs_set_all */
    map_cs_set_all(&ch_set);
    fail_unless(map_cs_nr(&ch_set) == MAP_MAX_CHANNEL - 1);
    fail_unless(!map_cs_is_set(&ch_set, 0));
    for (i = 1; i < MAP_MAX_CHANNEL; i++) {
        fail_unless(map_cs_is_set(&ch_set, i));
    }

    for (i = MAP_MAX_CHANNEL; i < 255; i++) {
        fail_unless(!map_cs_is_set(&ch_set, i));
    }

    /* map_cs_or */
    map_cs_unset_all(&ch_set);
    map_cs_unset_all(&ch_set2);
    map_cs_set(&ch_set,  1);
    map_cs_set(&ch_set,  6);
    map_cs_set(&ch_set,  100);
    map_cs_set(&ch_set2, 1);
    map_cs_set(&ch_set2, 6);
    map_cs_set(&ch_set2, 104);

    map_cs_or(&ch_set, &ch_set2);

    fail_unless(map_cs_nr(&ch_set) == 4);
    fail_unless(map_cs_is_set(&ch_set, 1));
    fail_unless(map_cs_is_set(&ch_set, 6));
    fail_unless(map_cs_is_set(&ch_set, 100));
    fail_unless(map_cs_is_set(&ch_set, 104));

    /* map_cs_and */
    map_cs_unset_all(&ch_set);
    map_cs_unset_all(&ch_set2);
    map_cs_set(&ch_set, 1);
    map_cs_set(&ch_set, 6);
    map_cs_set(&ch_set, 100);
    map_cs_set(&ch_set2, 1);
    map_cs_set(&ch_set2, 6);
    map_cs_set(&ch_set2, 104);

    map_cs_and(&ch_set, &ch_set2);

    fail_unless(map_cs_nr(&ch_set) == 2);
    fail_unless(map_cs_is_set(&ch_set, 1));
    fail_unless(map_cs_is_set(&ch_set, 6));

    /* map_cs_and_not */
    map_cs_unset_all(&ch_set);
    map_cs_unset_all(&ch_set2);
    map_cs_set(&ch_set, 1);
    map_cs_set(&ch_set, 6);
    map_cs_set(&ch_set, 100);
    map_cs_set(&ch_set2, 1);
    map_cs_set(&ch_set2, 6);
    map_cs_set(&ch_set2, 104);

    map_cs_and_not(&ch_set, &ch_set2);

    fail_unless(map_cs_nr(&ch_set) == 1);
    fail_unless(map_cs_is_set(&ch_set, 100));

    /* map_cs_copy & map_cs_compare */
    map_cs_unset_all(&ch_set);
    map_cs_set(&ch_set, 1);
    map_cs_set(&ch_set, 6);
    map_cs_set(&ch_set, 100);
    map_cs_copy(&ch_set2, &ch_set);
    fail_unless(!map_cs_compare(&ch_set, &ch_set2));
    map_cs_set(&ch_set, 104);
    fail_unless(map_cs_compare(&ch_set, &ch_set2));

    /* map_cs_to_string */
    map_cs_unset_all(&ch_set);
    map_cs_set(&ch_set, 1);
    map_cs_set(&ch_set, 36);
    map_cs_set(&ch_set, 100);
    fail_unless(!strcmp(map_cs_to_string(&ch_set, ' ', buf, sizeof(buf)), "1 36 100"));

    /* map_cs_from_string */
    fail_unless(!map_cs_from_string("1 4 7", ' ', &ch_set));
    fail_unless(map_cs_nr(&ch_set) == 3);
    fail_unless(map_cs_is_set(&ch_set, 1) && map_cs_is_set(&ch_set, 4) && map_cs_is_set(&ch_set, 7));
    fail_unless(!map_cs_from_string("10,11,12", ',', &ch_set));
    fail_unless(map_cs_nr(&ch_set) == 3);
    fail_unless(map_cs_is_set(&ch_set, 10) && map_cs_is_set(&ch_set, 11) && map_cs_is_set(&ch_set, 12));

    /* map_cs_bw_unset_all */
    map_cs_bw_unset_all(&ch_bw_set);

    fail_unless(map_cs_nr(&ch_bw_set.channel_set_20) == 0);
    fail_unless(map_cs_nr(&ch_bw_set.channel_set_40) == 0);
    fail_unless(map_cs_nr(&ch_bw_set.channel_set_80) == 0);
    fail_unless(map_cs_nr(&ch_bw_set.channel_set_160) == 0);
    fail_unless(map_cs_nr(&ch_bw_set.channel_set_320) == 0);

    for (i = 0; i < 255; i++) {
        fail_unless(false == map_cs_is_set(&ch_bw_set.channel_set_20, i));
        fail_unless(false == map_cs_is_set(&ch_bw_set.channel_set_40, i));
        fail_unless(false == map_cs_is_set(&ch_bw_set.channel_set_80, i));
        fail_unless(false == map_cs_is_set(&ch_bw_set.channel_set_160, i));
        fail_unless(false == map_cs_is_set(&ch_bw_set.channel_set_320, i));
    }

    /* map_cs_bw_set */
    map_cs_bw_set(&ch_bw_set, 20, 1);
    map_cs_bw_set(&ch_bw_set, 40, 1);
    map_cs_bw_set(&ch_bw_set, 80, 1);
    map_cs_bw_set(&ch_bw_set, 160, 1);
    map_cs_bw_set(&ch_bw_set, 320, 1);

    map_cs_bw_set(&ch_bw_set, 20, 36);
    map_cs_bw_set(&ch_bw_set, 40, 36);
    map_cs_bw_set(&ch_bw_set, 80, 36);
    map_cs_bw_set(&ch_bw_set, 160, 36);
    map_cs_bw_set(&ch_bw_set, 320, 36);

    map_cs_bw_set(&ch_bw_set, 20, 100);
    map_cs_bw_set(&ch_bw_set, 40, 100);
    map_cs_bw_set(&ch_bw_set, 80, 100);
    map_cs_bw_set(&ch_bw_set, 160, 100);
    map_cs_bw_set(&ch_bw_set, 320, 100);

    fail_unless(map_cs_nr(&ch_bw_set.channel_set_20) == 3);
    fail_unless(map_cs_nr(&ch_bw_set.channel_set_40) == 3);
    fail_unless(map_cs_nr(&ch_bw_set.channel_set_80) == 3);
    fail_unless(map_cs_nr(&ch_bw_set.channel_set_160) == 3);
    fail_unless(map_cs_nr(&ch_bw_set.channel_set_320) == 3);

    for (i = 0; i < 255; i++) {
        bool exp = (i == 1 || i == 36 || i == 100);

        fail_unless(exp == map_cs_is_set(&ch_bw_set.channel_set_20, i));
        fail_unless(exp == map_cs_is_set(&ch_bw_set.channel_set_40, i));
        fail_unless(exp == map_cs_is_set(&ch_bw_set.channel_set_80, i));
        fail_unless(exp == map_cs_is_set(&ch_bw_set.channel_set_160, i));
        fail_unless(exp == map_cs_is_set(&ch_bw_set.channel_set_320, i));
    }

    /* map_cs_bw_to_string */
    map_cs_bw_unset_all(&ch_bw_set);
    map_cs_bw_set(&ch_bw_set, 20, 1);
    map_cs_bw_set(&ch_bw_set, 40, 4);
    map_cs_bw_set(&ch_bw_set, 80, 100);
    map_cs_bw_set(&ch_bw_set, 160, 157);
    map_cs_bw_set(&ch_bw_set, 320, 95);
    fail_unless(!strcmp(map_cs_bw_to_string(&ch_bw_set, ',', buf, sizeof(buf)), "1/20,4/40,100/80,157/160,95/320"));
}
END_TEST

const char *test_suite_name = "channel_set";
test_case_t test_cases[] = {
    TEST("channel_set",   test_channel_set  ),
    TEST_CASES_END
};
