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
#include <unistd.h>

#include "test.h"

#include "map_ctrl_chan_sel.h"
#include "map_ctrl_utils.h"
#include "map_config.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static mac_addr g_al_mac    = {0x02, 0x01, 0x02, 0x03, 0x04, 0x05};
static mac_addr g_al2_mac   = {0x02, 0x01, 0x02, 0x03, 0x04, 0x06};
static mac_addr g_radio_id  = {0x12, 0x11, 0x12, 0x13, 0x14, 0x15};
static mac_addr g_radio2_id = {0x12, 0x11, 0x12, 0x13, 0x14, 0x16};
static mac_addr g_radio3_id = {0x12, 0x11, 0x12, 0x13, 0x14, 0x17};

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/

static void set_cs(map_channel_set_t *set, int c_nr, int *c)
{
    int i;

    map_cs_unset_all(set);

    for (i = 0; i < c_nr; i++) {
        map_cs_set(set, c[i]);
    }
}

static int check_cs(map_channel_set_t *set, int c_nr, int *c)
{
    int i;

    if (map_cs_nr(set) != c_nr) {
        log_test_e("check_cs: map_cs_nr: %d vs %d\n", map_cs_nr(set), c_nr);
        return -1;
    }

    for (i = 0; i < c_nr; i++) {
        if (!map_cs_is_set(set, c[i])) {
            log_test_e("check_cs: map_cs_is_set: %d not set", c[i]);
            return -1;
        }
    }

    return 0;
}

static void test_init()
{
    map_controller_cfg_t *cfg = get_controller_cfg();
    map_chan_sel_cfg_t   *cs_cfg = &cfg->chan_sel;

    /* Allow all channels */
    map_cs_set_all(&cs_cfg->allowed_channel_set_2g);
    map_cs_set_all(&cs_cfg->allowed_channel_set_5g);
    map_cs_set_all(&cs_cfg->allowed_channel_set_6g);

    /* Set some default preferences */
    set_cs(&cs_cfg->default_pref_channel_set_2g, 11, (int[]){1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11});
    set_cs(&cs_cfg->default_pref_channel_set_5g,  7, (int[]){36, 40, 44, 52, 56, 60, 100});
    set_cs(&cs_cfg->default_pref_channel_set_6g,  6, (int[]){5, 21, 37, 53, 69, 85}); /* PSC only */
    cs_cfg->allowed_channel_6g_psc = true;

    cs_cfg->align_multiap = false;
    cs_cfg->bandlock_5g = MAP_BANDLOCK_5G_DISABLED;

    /* Add a backhaul profile (multiap_align only works on backhaul radios) */
    cfg->num_profiles = 1;
    fail_unless(!!(cfg->profiles = calloc(cfg->num_profiles, sizeof(map_profile_cfg_t))));
    strcpy(cfg->profiles[0].bss_ssid, "ssid0");
    cfg->profiles[0].enabled        = true;
    cfg->profiles[0].bss_freq_bands = MAP_M2_BSS_RADIO2G | MAP_M2_BSS_RADIO5GL | MAP_M2_BSS_RADIO5GU | MAP_M2_BSS_RADIO6G;
    cfg->profiles[0].bss_state      = MAP_BACKHAUL_BSS;
    cfg->profiles[0].gateway        = true;
    cfg->profiles[0].extender       = true;
    cfg->profiles[0].vlan_id        = -1;

    fail_unless(!map_info_init());
    fail_unless(!map_dm_init());
    fail_unless(!map_ctrl_chan_sel_init());
}

static void test_fini(void)
{
    map_controller_cfg_t *cfg = get_controller_cfg();

    free(cfg->profiles);

    map_ctrl_chan_sel_fini();
    map_dm_fini();
    map_info_fini();
}

static void print_cb(const char *fmt, ...)
{
    char buf[1024];
    va_list args;
    int len;

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    /* Remove newline because log_test_i also adds one */
    len = strlen(buf);
    if ((len > 0) && (buf[len - 1] == '\n')) {
        buf[len - 1] = 0;
    }

    log_test_i("%s", buf);
}

static void print_op_class_list(const char *name, map_op_class_list_t *list)
{
    int  i;
    char buf[MAP_CS_BUF_LEN];

    log_test_i("op_class_list[%s]", name);

    for (i = 0; i < list->op_classes_nr; i++) {
        map_op_class_t *op_class = &list->op_classes[i];

        log_test_i("    op_class[%d] pref[%d] reason[%d] channels[%s]",
                   op_class->op_class, op_class->pref, op_class->reason,
                   map_cs_to_string(&op_class->channels, ',', buf, sizeof(buf)));
    }
}

/*#######################################################################
#                       TEST_CHAN_SEL                                   #
########################################################################*/
START_TEST(test_chan_sel)
{
    map_ale_info_t      *ale;
    map_radio_info_t    *radio;
    map_channel_set_t    channels;
    map_op_class_list_t *agent_cap_list;
    map_op_class_list_t *agent_pref_list;
    map_op_class_list_t *ctrl_pref_list;
    map_op_class_list_t *merged_pref_list;
    bool                 acs_enable = true;
    int                  channel = 0;
    int                  bandwidth = 0;

    /* INIT */
    log_test_i("INIT TEST_CHAN_SEL");
    test_init();

    fail_unless(!!(ale = map_dm_create_ale(g_al_mac)));
    fail_unless(!!(radio = map_dm_create_radio(ale, g_radio_id)));
    radio->chan_sel.acs_enable = radio->chan_sel.cloud_mgmt_enable = true;

    agent_cap_list = &radio->cap_op_class_list;
    agent_pref_list = &radio->pref_op_class_list;
    ctrl_pref_list = &radio->ctrl_pref_op_class_list;
    merged_pref_list = &radio->merged_pref_op_class_list;

    radio->supported_freq = IEEE80211_FREQUENCY_BAND_5_GHZ;
    /* Add radio operating classes (20MHz: 115, 118, 40MHz: 116, 117, 119, 120, 80MHz: 128) */
    agent_cap_list->op_classes_nr = 7;
    agent_cap_list->op_classes = calloc(7, sizeof(map_op_class_t));
    agent_cap_list->op_classes[0].op_class = 115;
    agent_cap_list->op_classes[1].op_class = 118;
    agent_cap_list->op_classes[2].op_class = 116;
    agent_cap_list->op_classes[3].op_class = 117;
    agent_cap_list->op_classes[4].op_class = 119;
    agent_cap_list->op_classes[5].op_class = 120;
    agent_cap_list->op_classes[6].op_class = 128;
    print_op_class_list("agent_cap", agent_cap_list);

    set_cs(&radio->ctl_channels, 8, (int[]){36, 40, 44, 48, 52, 56, 60, 64});

    /* Add agent preference
       - bad prio for channels 36/20 and 40/20
       - low prio for channels 60/20, 64/20, 56/40 and 64/40
    */
    agent_pref_list->op_classes_nr = 3;
    agent_pref_list->op_classes = calloc(3, sizeof(map_op_class_t));
    agent_pref_list->op_classes[0].op_class = 115;
    agent_pref_list->op_classes[0].pref = 1;
    agent_pref_list->op_classes[0].reason = 6;
    map_cs_set(&agent_pref_list->op_classes[0].channels, 36);
    map_cs_set(&agent_pref_list->op_classes[0].channels, 40);
    agent_pref_list->op_classes[1].op_class = 118;
    agent_pref_list->op_classes[1].pref = 3;
    map_cs_set(&agent_pref_list->op_classes[1].channels, 60);
    map_cs_set(&agent_pref_list->op_classes[1].channels, 64);
    agent_pref_list->op_classes[2].op_class = 120;
    agent_pref_list->op_classes[2].pref = 4;
    print_op_class_list("agent_pref", agent_pref_list);


    /* 1. MAP_CTRL_CHAN_SEL_UPDATE */
    log_test_i("1. MAP_CTRL_CHAN_SEL_UPDATE");
    fail_unless(!map_ctrl_chan_sel_update(radio));

    print_op_class_list("ctrl_pref", ctrl_pref_list);
    print_op_class_list("merged_pref", merged_pref_list);

    /* Check prefered channel list.
       - 36/40 are not allowed because of agent
       - 48 not allowed because of controller config
    */
    fail_unless(!check_cs(&radio->chan_sel.pref_channels, 4, (int[]){44, 52, 56, 60}));
    fail_unless(!check_cs(&radio->chan_sel.def_pref_channels, 4, (int[]){44, 52, 56, 60}));
    fail_unless(!check_cs(&radio->bad_channels, 2, (int[]){36, 40}));

    /* Check controller preference: channels 36, 40, 48 and 64 not allowed */
    fail_unless(ctrl_pref_list->op_classes_nr == 6);
    fail_unless(ctrl_pref_list->op_classes[0].op_class == 115);
    fail_unless(ctrl_pref_list->op_classes[0].pref == 0);
    fail_unless(map_cs_nr(&ctrl_pref_list->op_classes[0].channels) == 3); /* 36, 40, 48 */
    fail_unless(map_cs_is_set(&ctrl_pref_list->op_classes[0].channels, 36));
    fail_unless(map_cs_is_set(&ctrl_pref_list->op_classes[0].channels, 40));
    fail_unless(map_cs_is_set(&ctrl_pref_list->op_classes[0].channels, 48));

    fail_unless(ctrl_pref_list->op_classes[1].op_class == 118);
    fail_unless(ctrl_pref_list->op_classes[1].pref == 0);
    fail_unless(map_cs_nr(&ctrl_pref_list->op_classes[1].channels) == 1); /* 64 */
    fail_unless(map_cs_is_set(&ctrl_pref_list->op_classes[1].channels, 64));

    fail_unless(ctrl_pref_list->op_classes[2].op_class == 116);
    fail_unless(ctrl_pref_list->op_classes[2].pref == 0);
    fail_unless(map_cs_nr(&ctrl_pref_list->op_classes[2].channels) == 1); /* 36 */
    fail_unless(map_cs_is_set(&ctrl_pref_list->op_classes[2].channels, 36));

    fail_unless(ctrl_pref_list->op_classes[3].op_class == 117);
    fail_unless(ctrl_pref_list->op_classes[3].pref == 0);
    fail_unless(map_cs_nr(&ctrl_pref_list->op_classes[3].channels) == 2); /* 40, 48 */
    fail_unless(map_cs_is_set(&ctrl_pref_list->op_classes[3].channels, 40));
    fail_unless(map_cs_is_set(&ctrl_pref_list->op_classes[3].channels, 48));

    fail_unless(ctrl_pref_list->op_classes[4].op_class == 120);
    fail_unless(ctrl_pref_list->op_classes[4].pref == 0);
    fail_unless(map_cs_nr(&ctrl_pref_list->op_classes[4].channels) == 1); /* 64 */
    fail_unless(map_cs_is_set(&ctrl_pref_list->op_classes[4].channels, 64));

    fail_unless(ctrl_pref_list->op_classes[5].op_class == 128);
    fail_unless(ctrl_pref_list->op_classes[5].pref == 0);
    fail_unless(map_cs_nr(&ctrl_pref_list->op_classes[5].channels) == 5); /* 106, 122, ... because map_is_channel_in_cap_op_class returns true for all */
    fail_unless(!map_cs_is_set(&ctrl_pref_list->op_classes[5].channels, 42));
    fail_unless(!map_cs_is_set(&ctrl_pref_list->op_classes[5].channels, 58));
    fail_unless(map_cs_is_set(&ctrl_pref_list->op_classes[5].channels, 106));

    /* Check merged preference: channels 36, 40, 48 and 64 not allowed, channel 60/20 and 56/40 have low prio */
    /* NOTE: order is different as above because the list is optimized and sorted... */
    fail_unless(merged_pref_list->op_classes_nr == 8);
    fail_unless(merged_pref_list->op_classes[0].op_class == 115);
    fail_unless(merged_pref_list->op_classes[0].pref == 0);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[0].channels) == 3); /* 36, 40, 48 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[0].channels, 36));
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[0].channels, 40));
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[0].channels, 48));

    fail_unless(merged_pref_list->op_classes[1].op_class == 116);
    fail_unless(merged_pref_list->op_classes[1].pref == 0);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[1].channels) == 1); /* 36 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[1].channels, 36));

    fail_unless(merged_pref_list->op_classes[2].op_class == 117);
    fail_unless(merged_pref_list->op_classes[2].pref == 0);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[2].channels) == 0); /* 40, 48 */

    fail_unless(merged_pref_list->op_classes[3].op_class == 118);
    fail_unless(merged_pref_list->op_classes[3].pref == 0);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[3].channels) == 1); /* 64 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[3].channels, 64));

    fail_unless(merged_pref_list->op_classes[4].op_class == 118);
    fail_unless(merged_pref_list->op_classes[4].pref == 3);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[4].channels) == 1); /* 60 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[4].channels, 60));

    fail_unless(merged_pref_list->op_classes[5].op_class == 120);
    fail_unless(merged_pref_list->op_classes[5].pref == 0);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[5].channels) == 1); /* 64 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[5].channels, 64));

    fail_unless(merged_pref_list->op_classes[6].op_class == 120);
    fail_unless(merged_pref_list->op_classes[6].pref == 4);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[6].channels) == 1); /* 60 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[6].channels, 56));

    fail_unless(merged_pref_list->op_classes[7].op_class == 128);
    fail_unless(merged_pref_list->op_classes[7].pref == 0);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[7].channels) == 5); /* 106, 122, ... because map_is_channel_in_cap_op_class returns true for all */
    fail_unless(!map_cs_is_set(&merged_pref_list->op_classes[7].channels, 42));
    fail_unless(!map_cs_is_set(&merged_pref_list->op_classes[7].channels, 58));
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[7].channels, 106));


    /* UNSET AGENT PREFERENCE FOR EVERYTHING BELOW */
    agent_pref_list->op_classes_nr = 0;


    /* 2. CHANGE ACS CHANNEL LIST */
    log_test_i("2. CHANGE ACS CHANNEL LIST");
    acs_enable = true;
    set_cs(&channels, 4, (int[]){36, 40, 44, 48});
    fail_unless(!map_ctrl_chan_sel_set(radio, NULL, &acs_enable, &channels, NULL, NULL));
    fail_unless(!check_cs(&radio->chan_sel.pref_channels, 4, (int[]){36,40, 44, 48}));
    fail_unless(!check_cs(&radio->chan_sel.def_pref_channels, 6, (int[]){36, 40, 44, 52, 56, 60}));

    /* Check controller preference: only 36, 40, 44, 48 is allowed */
    fail_unless(ctrl_pref_list->op_classes_nr == 4);
    fail_unless(ctrl_pref_list->op_classes[0].op_class == 118);
    fail_unless(map_cs_nr(&ctrl_pref_list->op_classes[0].channels) == 4);

    fail_unless(ctrl_pref_list->op_classes[1].op_class == 119);
    fail_unless(map_cs_nr(&ctrl_pref_list->op_classes[1].channels) == 2);

    fail_unless(ctrl_pref_list->op_classes[2].op_class == 120);
    fail_unless(map_cs_nr(&ctrl_pref_list->op_classes[2].channels) == 2);

    fail_unless(ctrl_pref_list->op_classes[3].op_class == 128);
    fail_unless(map_cs_nr(&ctrl_pref_list->op_classes[3].channels) == 6);


    /* 3. DISABLE CHANNEL MGMT */
    log_test_i("4. DISABLE CLOUD CHANNEL MGMT");
    fail_unless(!map_ctrl_chan_sel_set_cloud_mgmt_enable(radio, false));
    fail_unless(!check_cs(&radio->chan_sel.pref_channels, 6, (int[]){36, 40, 44, 52, 56, 60}));
    fail_unless(!check_cs(&radio->chan_sel.def_pref_channels, 6, (int[]){36, 40, 44, 52, 56, 60}));

    /* Enable again... */
    fail_unless(!map_ctrl_chan_sel_set_cloud_mgmt_enable(radio, true));
    fail_unless(!check_cs(&radio->chan_sel.pref_channels, 4, (int[]){36,40, 44, 48}));
    fail_unless(!check_cs(&radio->chan_sel.def_pref_channels, 6, (int[]){36, 40, 44, 52, 56, 60}));


    /* 4. FIXED CHANNEL */
    log_test_i("4. FIXED CHANNEL");
    acs_enable = false;
    channel = 40;
    bandwidth = 40;
    fail_unless(!map_ctrl_chan_sel_set(radio, NULL, &acs_enable, NULL, &channel, &bandwidth));
    fail_unless(!check_cs(&radio->chan_sel.pref_channels, 4, (int[]){36, 40, 44, 48}));
    fail_unless(!check_cs(&radio->chan_sel.def_pref_channels, 6, (int[]){36, 40, 44, 52, 56, 60}));

    fail_unless(radio->chan_sel.acs_enable == false);
    fail_unless(radio->chan_sel.channel == 40);
    fail_unless(radio->chan_sel.bandwidth == 40);

    /* Check controller preference: only 40 is allowed in all 20/40 */
    fail_unless(ctrl_pref_list->op_classes_nr == 7);
    fail_unless(ctrl_pref_list->op_classes[0].op_class == 115);
    fail_unless(map_cs_nr(&ctrl_pref_list->op_classes[0].channels) == 3);
    fail_unless(map_cs_is_set(&ctrl_pref_list->op_classes[0].channels, 36));
    fail_unless(map_cs_is_set(&ctrl_pref_list->op_classes[0].channels, 44));
    fail_unless(map_cs_is_set(&ctrl_pref_list->op_classes[0].channels, 48));

    fail_unless(ctrl_pref_list->op_classes[1].op_class == 118);
    fail_unless(map_cs_nr(&ctrl_pref_list->op_classes[1].channels) == 4);

    fail_unless(ctrl_pref_list->op_classes[2].op_class == 116);
    fail_unless(map_cs_nr(&ctrl_pref_list->op_classes[2].channels) == 2);

    fail_unless(ctrl_pref_list->op_classes[3].op_class == 117);
    fail_unless(map_cs_nr(&ctrl_pref_list->op_classes[3].channels) == 1);
    fail_unless(map_cs_is_set(&ctrl_pref_list->op_classes[3].channels, 48));

    fail_unless(ctrl_pref_list->op_classes[4].op_class == 119);
    fail_unless(map_cs_nr(&ctrl_pref_list->op_classes[4].channels) == 2);

    fail_unless(ctrl_pref_list->op_classes[5].op_class == 120);
    fail_unless(map_cs_nr(&ctrl_pref_list->op_classes[5].channels) == 2);

    fail_unless(ctrl_pref_list->op_classes[6].op_class == 128);
    fail_unless(map_cs_nr(&ctrl_pref_list->op_classes[6].channels) == 0);


    /* 5. BACK TO AUTO */
    log_test_i("5. BACK TO AUTO");
    fail_unless(!map_ctrl_chan_sel_set_channel(radio, 0));
    fail_unless(radio->chan_sel.acs_enable == true);
    fail_unless(radio->chan_sel.channel == 0);


    /* 6. INVALID FIXED CHANNEL */
    log_test_i("6. INVALID FIXED CHANNEL");
    fail_unless(!map_ctrl_chan_sel_set_channel(radio, 40));
    fail_unless(radio->chan_sel.acs_enable == false);
    fail_unless(radio->chan_sel.channel == 40);

    fail_unless(!map_ctrl_chan_sel_set_channel(radio, 41));
    fail_unless(!map_ctrl_chan_sel_set_bandwidth(radio, 20));
    fail_unless(radio->chan_sel.acs_enable == true);
    fail_unless(radio->chan_sel.channel == 0);
    fail_unless(radio->chan_sel.bandwidth == 20);


    /* 7. VALID FIXED CHANNEL BECOMES INVALID */
    log_test_i("7. VALID FIXED CHANNEL BECOMES INVALID");
    fail_unless(!map_ctrl_chan_sel_set_channel(radio, 40));
    fail_unless(radio->chan_sel.acs_enable == false);
    fail_unless(radio->chan_sel.channel == 40);

    map_cs_unset(&radio->ctl_channels, 40);

    fail_unless(!map_ctrl_chan_sel_update(radio));
    fail_unless(radio->chan_sel.acs_enable == true);
    fail_unless(radio->chan_sel.channel == 0);


    /* 8. FOR CODE COVERAGE */
    log_test_i("8. MAP_CTRL_CHAN_SEL_DUMP");
    map_ctrl_chan_sel_dump(print_cb, NULL, false);
    map_ctrl_chan_sel_dump(print_cb, NULL, true);


    /* FINI */
    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_CHAN_SEL_WEATHERBAND                       #
########################################################################*/
/* EU weatherband channels get a lower preference when they are not cleared */
START_TEST(test_chan_sel_weatherband)
{
    map_chan_sel_cfg_t       *cfg = &get_controller_cfg()->chan_sel;
    map_ale_info_t           *ale;
    map_radio_info_t         *radio;
    map_op_class_list_t      *agent_cap_list;
    map_op_class_list_t      *agent_pref_list;
    map_op_class_list_t      *ctrl_pref_list;
    map_op_class_list_t      *merged_pref_list;
    map_cac_available_pair_t *pairs;

    /* INIT */
    log_test_i("INIT TEST_CHAN_SEL_WEATHERBAND");
    test_init();

    /* Allow all channels except 100 and 144*/
    map_cs_set_all(&cfg->default_pref_channel_set_5g);
    map_cs_unset(&cfg->default_pref_channel_set_5g, 140);
    map_cs_unset(&cfg->default_pref_channel_set_5g, 144);

    fail_unless(!!(ale = map_dm_create_ale(g_al_mac)));
    fail_unless(!!(radio = map_dm_create_radio(ale, g_radio_id)));
    radio->chan_sel.acs_enable = radio->chan_sel.cloud_mgmt_enable = true;

    agent_cap_list = &radio->cap_op_class_list;
    agent_pref_list = &radio->pref_op_class_list;
    ctrl_pref_list = &radio->ctrl_pref_op_class_list;
    merged_pref_list = &radio->merged_pref_op_class_list;

    radio->supported_freq = IEEE80211_FREQUENCY_BAND_5_GHZ;
    /* Add radio operating classes (20MHz: 121, 40MHz: 122, 123, 80MHz: 128, 160MHz: 129) */
    agent_cap_list->op_classes_nr = 5;
    agent_cap_list->op_classes = calloc(7, sizeof(map_op_class_t));
    agent_cap_list->op_classes[0].op_class = 121;
    agent_cap_list->op_classes[1].op_class = 122;
    agent_cap_list->op_classes[2].op_class = 123;
    agent_cap_list->op_classes[3].op_class = 128;
    set_cs(&agent_cap_list->op_classes[3].channels, 4, (int[]){42, 58, 155, 171});
    agent_cap_list->op_classes[4].op_class = 129;
    set_cs(&agent_cap_list->op_classes[4].channels, 2, (int[]){50, 163});
    print_op_class_list("agent_cap", agent_cap_list);

    map_update_radio_channels(radio);

    /* Set lower agent preference for op_class 129 */
    agent_pref_list->op_classes_nr = 1;
    agent_pref_list->op_classes = calloc(1, sizeof(map_op_class_t));
    agent_pref_list->op_classes[0].op_class = 129;
    agent_pref_list->op_classes[0].pref = 5;
    agent_pref_list->op_classes[0].reason = 0;
    print_op_class_list("agent_pref", agent_pref_list);


    /* 1. MAP_CTRL_CHAN_SEL_UPDATE WITHOUT EU WEATHERBAND */
    log_test_i("1. MAP_CTRL_CHAN_SEL_UPDATE WITHOUT EU WEATHERBAND");
    radio->cac_caps.has_eu_weatherband = false;
    fail_unless(!map_ctrl_chan_sel_update(radio));

    print_op_class_list("ctrl_pref", ctrl_pref_list);
    print_op_class_list("merged_pref", merged_pref_list);

    /* Preferred channels: 100, 104, 108, 112, 116, 120, 124, 128, 132, 136 */
    fail_unless(!check_cs(&radio->chan_sel.def_pref_channels, 10, (int[]){100, 104, 108, 112, 116, 120, 124, 128, 132, 136}));

    /* Check merged preference */
    fail_unless(merged_pref_list->op_classes_nr == 4);

    fail_unless(merged_pref_list->op_classes[0].op_class == 121);
    fail_unless(merged_pref_list->op_classes[0].pref == 0);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[0].channels) == 2); /* 140, 144 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[0].channels, 140));
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[0].channels, 144));

    fail_unless(merged_pref_list->op_classes[1].op_class == 122);
    fail_unless(merged_pref_list->op_classes[1].pref == 0);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[1].channels) == 1); /* 140 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[1].channels, 140));

    fail_unless(merged_pref_list->op_classes[2].op_class == 123);
    fail_unless(merged_pref_list->op_classes[2].pref == 0);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[2].channels) == 1); /* 144 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[2].channels, 144));

    fail_unless(merged_pref_list->op_classes[3].op_class == 129);
    fail_unless(merged_pref_list->op_classes[3].pref == 5);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[3].channels) == 0);


    /* 2. MAP_CTRL_CHAN_SEL_UPDATE WITH EU WEATHERBAND */
    log_test_i("2. MAP_CTRL_CHAN_SEL_UPDATE WITH EU WEATHERBAND");
    radio->cac_caps.has_eu_weatherband = true;
    fail_unless(!map_ctrl_chan_sel_update(radio));

    print_op_class_list("ctrl_pref", ctrl_pref_list);
    print_op_class_list("merged_pref", merged_pref_list);

    /* Preferred channels: 100, 104, 108, 112, 116, 132, 136 */
    fail_unless(!check_cs(&radio->chan_sel.def_pref_channels, 10, (int[]){100, 104, 108, 112, 116, 120, 124, 128, 132, 136}));

    /* Check merged preference */
    fail_unless(merged_pref_list->op_classes_nr == 8);

    fail_unless(merged_pref_list->op_classes[0].op_class == 121);
    fail_unless(merged_pref_list->op_classes[0].pref == 0);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[0].channels) == 2); /* 140, 144 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[0].channels, 140));
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[0].channels, 144));
    fail_unless(merged_pref_list->op_classes[1].op_class == 121);
    fail_unless(merged_pref_list->op_classes[1].pref == 14);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[1].channels) == 3); /* 120, 124, 128 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[1].channels, 120));
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[1].channels, 124));
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[1].channels, 128));

    fail_unless(merged_pref_list->op_classes[2].op_class == 122);
    fail_unless(merged_pref_list->op_classes[2].pref == 0);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[2].channels) == 1); /* 140 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[2].channels, 140));
    fail_unless(merged_pref_list->op_classes[3].op_class == 122);
    fail_unless(merged_pref_list->op_classes[3].pref == 14);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[3].channels) == 2); /* 116, 124 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[3].channels, 116));
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[3].channels, 124));

    fail_unless(merged_pref_list->op_classes[4].op_class == 123);
    fail_unless(merged_pref_list->op_classes[4].pref == 0);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[4].channels) == 1); /* 144 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[4].channels, 144));
    fail_unless(merged_pref_list->op_classes[5].op_class == 123);
    fail_unless(merged_pref_list->op_classes[5].pref == 14);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[5].channels) == 2); /* 120, 128 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[5].channels, 120));
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[5].channels, 128));

    fail_unless(merged_pref_list->op_classes[6].op_class == 128);
    fail_unless(merged_pref_list->op_classes[6].pref == 14);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[6].channels) == 1); /* 122 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[6].channels, 122));

    fail_unless(merged_pref_list->op_classes[7].op_class == 129);
    fail_unless(merged_pref_list->op_classes[7].pref == 5);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[7].channels) == 0);


    /* 3. MAP_CTRL_CHAN_SEL_UPDATE WITH EU WEATHERBAND AND 120, 124 ALLOWED */
    log_test_i("3. MAP_CTRL_CHAN_SEL_UPDATE WITH EU WEATHERBAND AND 120, 124 ALLOWED");
    radio->cac_caps.has_eu_weatherband = true;
    pairs = calloc(20, sizeof(*pairs));
    ale->cac_status_report.available_pairs = pairs;
    ale->cac_status_report.available_pairs_nr = 4;

    pairs[0].op_class = 121;    pairs[0].channel  = 120;
    pairs[1].op_class = 121;    pairs[1].channel  = 124;
    pairs[2].op_class = 122;    pairs[2].channel  = 116;
    pairs[3].op_class = 123;    pairs[3].channel  = 120;

    fail_unless(!map_ctrl_chan_sel_update(radio));

    print_op_class_list("ctrl_pref", ctrl_pref_list);
    print_op_class_list("merged_pref", merged_pref_list);

    /* Preferred channels: 100, 104, 108, 112, 116, 132, 136 */
    fail_unless(!check_cs(&radio->chan_sel.def_pref_channels, 10, (int[]){100, 104, 108, 112, 116, 120, 124, 128, 132, 136}));

    /* Check merged preference */
    fail_unless(merged_pref_list->op_classes_nr == 8);

    fail_unless(merged_pref_list->op_classes[0].op_class == 121);
    fail_unless(merged_pref_list->op_classes[0].pref == 0);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[0].channels) == 2); /* 140, 144 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[0].channels, 140));
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[0].channels, 144));
    fail_unless(merged_pref_list->op_classes[1].op_class == 121);
    fail_unless(merged_pref_list->op_classes[1].pref == 14);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[1].channels) == 1); /* 128 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[1].channels, 128));

    fail_unless(merged_pref_list->op_classes[2].op_class == 122);
    fail_unless(merged_pref_list->op_classes[2].pref == 0);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[2].channels) == 1); /* 140 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[2].channels, 140));
    fail_unless(merged_pref_list->op_classes[3].op_class == 122);
    fail_unless(merged_pref_list->op_classes[3].pref == 14);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[3].channels) == 1); /* 124 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[3].channels, 124));

    fail_unless(merged_pref_list->op_classes[4].op_class == 123);
    fail_unless(merged_pref_list->op_classes[4].pref == 0);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[4].channels) == 1); /* 144 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[4].channels, 144));
    fail_unless(merged_pref_list->op_classes[5].op_class == 123);
    fail_unless(merged_pref_list->op_classes[5].pref == 14);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[5].channels) == 1); /* 128 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[5].channels, 128));

    fail_unless(merged_pref_list->op_classes[6].op_class == 128);
    fail_unless(merged_pref_list->op_classes[6].pref == 14);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[6].channels) == 1); /* 122 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[6].channels, 122));

    fail_unless(merged_pref_list->op_classes[7].op_class == 129);
    fail_unless(merged_pref_list->op_classes[7].pref == 5);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[7].channels) == 0);


    /* 4. MAP_CTRL_CHAN_SEL_UPDATE WITH EU WEATHERBAND AND 120, 124, 128 ALLOWED */
    log_test_i("4. MAP_CTRL_CHAN_SEL_UPDATE WITH EU WEATHERBAND AND 120, 124, 128 ALLOWED");
    radio->cac_caps.has_eu_weatherband = true;
    ale->cac_status_report.available_pairs_nr = 9;

    pairs[0].op_class = 121;    pairs[0].channel  = 120;
    pairs[1].op_class = 121;    pairs[1].channel  = 124;
    pairs[2].op_class = 121;    pairs[2].channel  = 128;
    pairs[3].op_class = 122;    pairs[3].channel  = 116;
    pairs[4].op_class = 122;    pairs[4].channel  = 124;
    pairs[5].op_class = 123;    pairs[5].channel  = 120;
    pairs[6].op_class = 123;    pairs[6].channel  = 128;
    pairs[7].op_class = 128;    pairs[7].channel  = 122;
    pairs[8].op_class = 129;    pairs[8].channel  = 114;

    fail_unless(!map_ctrl_chan_sel_update(radio));

    print_op_class_list("ctrl_pref", ctrl_pref_list);
    print_op_class_list("merged_pref", merged_pref_list);

    /* Preferred channels: 100, 104, 108, 112, 116, 132, 136 */
    fail_unless(!check_cs(&radio->chan_sel.def_pref_channels, 10, (int[]){100, 104, 108, 112, 116, 120, 124, 128, 132, 136}));

    /* Check merged preference (= same as in step 1) */
    fail_unless(merged_pref_list->op_classes_nr == 4);

    fail_unless(merged_pref_list->op_classes[0].op_class == 121);
    fail_unless(merged_pref_list->op_classes[0].pref == 0);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[0].channels) == 2); /* 140, 144 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[0].channels, 140));
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[0].channels, 144));

    fail_unless(merged_pref_list->op_classes[1].op_class == 122);
    fail_unless(merged_pref_list->op_classes[1].pref == 0);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[1].channels) == 1); /* 140 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[1].channels, 140));

    fail_unless(merged_pref_list->op_classes[2].op_class == 123);
    fail_unless(merged_pref_list->op_classes[2].pref == 0);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[2].channels) == 1); /* 144 */
    fail_unless(map_cs_is_set(&merged_pref_list->op_classes[2].channels, 144));

    fail_unless(merged_pref_list->op_classes[3].op_class == 129);
    fail_unless(merged_pref_list->op_classes[3].pref == 5);
    fail_unless(map_cs_nr(&merged_pref_list->op_classes[3].channels) == 0);


    /* FINI */
    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_MULTIAP_ALIGN                              #
########################################################################*/
/* Note the test below is only using op class 131. */
static int check_op_class_131(map_op_class_list_t *list, int excl_nr, int *excl)
{
    return (list->op_classes_nr                                    == 1      ) &&
           (list->op_classes[0].op_class                           == 131    ) &&
           (list->op_classes[0].pref                               == 0      ) &&
           (map_cs_nr(&list->op_classes[0].channels)               == excl_nr) &&
           (check_cs(&list->op_classes[0].channels, excl_nr, excl) == 0      ) ? 0 : -1;
}

START_TEST(test_multiap_align)
{
    map_chan_sel_cfg_t  *cfg = &get_controller_cfg()->chan_sel;
    map_ale_info_t      *ale;
    map_ale_info_t      *ale2;
    map_radio_info_t    *radio;
    map_radio_info_t    *radio2;
    map_op_class_list_t *agent_cap_list;
    map_op_class_list_t *agent_cap_list2;
    map_op_class_list_t *agent_pref_list2;
    map_op_class_list_t *ctrl_pref_list;
    map_op_class_list_t *ctrl_pref_list2;
    map_channel_set_t    ctl_channels;

    /* INIT */
    log_test_i("INIT TEST_MULTIAP_ALIGN");
    test_init(DATA_DIR"/does_not_exist");

    fail_unless(!!(ale = map_dm_create_ale(g_al_mac)));
    fail_unless(!!(ale2 = map_dm_create_ale(g_al2_mac)));
    fail_unless(!!(radio = map_dm_create_radio(ale, g_radio_id)));
    radio->chan_sel.acs_enable = radio->chan_sel.cloud_mgmt_enable = true;
    fail_unless(!!(radio2 = map_dm_create_radio(ale2, g_radio2_id)));
    radio2->chan_sel.acs_enable = radio2->chan_sel.cloud_mgmt_enable = true;

    set_radio_state_channel_pref_report_received(&radio->state);
    set_radio_state_channel_pref_report_received(&radio2->state);

    agent_cap_list    = &radio->cap_op_class_list;
    agent_cap_list2   = &radio2->cap_op_class_list;
    agent_pref_list2  = &radio2->pref_op_class_list;
    ctrl_pref_list    = &radio->ctrl_pref_op_class_list;
    ctrl_pref_list2   = &radio2->ctrl_pref_op_class_list;

    radio->supported_freq = IEEE80211_FREQUENCY_BAND_6_GHZ;
    radio2->supported_freq = IEEE80211_FREQUENCY_BAND_6_GHZ;

    /* Add radio operating classes (20MHz: 131 - supported channels 1, 5, 9, 13, 17, 21, 37, 53, 69, 85, 101, 117) */
    agent_cap_list->op_classes_nr = 1;
    agent_cap_list->op_classes = calloc(1, sizeof(map_op_class_t));
    agent_cap_list->op_classes[0].op_class = 131;
    set_cs(&ctl_channels, 12, (int[]){1, 5, 9, 13, 17, 21, 37, 53, 69, 85, 101, 117});
    map_get_channel_set_from_op_class(131, &agent_cap_list->op_classes[0].channels);
    map_cs_and_not(&agent_cap_list->op_classes[0].channels, &ctl_channels);
    map_update_radio_channels(radio);
    print_op_class_list("radio agent_cap", agent_cap_list);


    /* 1. MAP_CTRL_CHAN_SEL_UPDATE */
    log_test_i("1. MAP_CTRL_CHAN_SEL_UPDATE");
    fail_unless(!map_ctrl_chan_sel_update(radio));

    print_op_class_list("radio ctrl_pref", ctrl_pref_list);

    /* Check preferences: 5, 21, 37, 53, 69, 85 are allowed */
    fail_unless(!check_cs(&radio->chan_sel.pref_channels, 6, (int[]){5, 21, 37, 53, 69, 85}));
    fail_unless(!check_cs(&radio->chan_sel.def_pref_channels, 6, (int[]){5, 21, 37, 53, 69, 85}));
    fail_unless(!check_op_class_131(ctrl_pref_list, 6, (int[]){1, 9, 13, 17, 101, 117}));

    /* 2. MAP_CTRL_CHAN_SEL_UPDATE RADIO_2 */
    log_test_i("2. MAP_CTRL_CHAN_SEL_UPDATE RADIO_2");

    /* Configure radio2 same as radio except that it does not support channels 5 and 21 */
    /* Add radio operating classes (20MHz: 131 - supported channels 1, 9, 13, 17, 37, 53, 69, 85, 101, 117) */
    agent_cap_list2->op_classes_nr = 1;
    agent_cap_list2->op_classes = calloc(1, sizeof(map_op_class_t));
    agent_cap_list2->op_classes[0].op_class = 131;
    set_cs(&ctl_channels, 10, (int[]){1, 9, 13, 17, 37, 53, 69, 85, 101, 117});
    map_get_channel_set_from_op_class(131, &agent_cap_list2->op_classes[0].channels);
    map_cs_and_not(&agent_cap_list2->op_classes[0].channels, &ctl_channels);
    map_update_radio_channels(radio2);
    print_op_class_list("radio_2 agent_cap", agent_cap_list2);

    fail_unless(!map_ctrl_chan_sel_update(radio2));

    print_op_class_list("radio ctrl_pref",  ctrl_pref_list);
    print_op_class_list("radio_2 ctrl_pref",  ctrl_pref_list2);

    /* Check preferences for RADIO: 5, 21, 37, 53, 69, 85 are allowed (same as above) */
    fail_unless(!check_cs(&radio->chan_sel.pref_channels, 6, (int[]){5, 21, 37, 53, 69, 85}));
    fail_unless(!check_cs(&radio->chan_sel.def_pref_channels, 6, (int[]){5, 21, 37, 53, 69, 85}));
    fail_unless(!check_op_class_131(ctrl_pref_list, 6, (int[]){1, 9, 13, 17, 101, 117}));

    /* Check preferences for RADIO_2: 37, 53, 69, 85 are allowed */
    fail_unless(!check_cs(&radio2->chan_sel.pref_channels, 4, (int[]){37, 53, 69, 85}));
    fail_unless(!check_cs(&radio2->chan_sel.def_pref_channels, 4, (int[]){37, 53, 69, 85}));
    fail_unless(!check_op_class_131(ctrl_pref_list2, 6, (int[]){1, 9, 13, 17, 101, 117}));


    /* 3. ENABLE ALIGN_MULTIAP AND DO MAP_CTRL_CHAN_SEL_UPDATE RADIO_2 AGAIN */
    log_test_i("3. ENABLE ALIGN_MULTIAP AND DO MAP_CTRL_CHAN_SEL_UPDATE RADIO_2 AGAIN");
    cfg->align_multiap = true;
    cfg->align_multiap_backoff_time = 60;
    fail_unless(!map_ctrl_chan_sel_update(radio2));

    print_op_class_list("radio ctrl_pref",  ctrl_pref_list);
    print_op_class_list("radio_2 ctrl_pref",  ctrl_pref_list2);

    /* Check preferences for RADIO: 37, 53, 69, 85 are allowed */
    fail_unless(!check_cs(&radio->chan_sel.pref_channels, 4, (int[]){37, 53, 69, 85}));
    fail_unless(!check_cs(&radio->chan_sel.def_pref_channels, 4, (int[]){37, 53, 69, 85}));
    fail_unless(!check_op_class_131(ctrl_pref_list, 8, (int[]){1, 5, 9, 13, 17, 21, 101, 117}));

    /* Check preferences for RADIO_2: 37, 53, 69, 85 are allowed */
    fail_unless(!check_cs(&radio2->chan_sel.pref_channels, 4, (int[]){37, 53, 69, 85}));
    fail_unless(!check_cs(&radio2->chan_sel.def_pref_channels, 4, (int[]){37, 53, 69, 85}));
    /* Note: 5 and 21 are not excluded because they are not in the capabilities... */
    fail_unless(!check_op_class_131(ctrl_pref_list2, 6, (int[]){1, 9, 13, 17, 101, 117}));


    /* 4. ADD BAD CHANNELS AND DO MAP_CTRL_CHAN_SEL_UPDATE RADIO_2 AGAIN */
    log_test_i("4. ADD BAD CHANNELS AND DO MAP_CTRL_CHAN_SEL_UPDATE RADIO_2 AGAIN");

    /* Mark channels 69 and 85 as bad */
    agent_pref_list2->op_classes_nr = 1;
    agent_pref_list2->op_classes = calloc(1, sizeof(map_op_class_t));
    agent_pref_list2->op_classes[0].op_class = 131;
    agent_pref_list2->op_classes[0].pref = 1;
    agent_pref_list2->op_classes[0].reason = 1;
    set_cs(&agent_pref_list2->op_classes[0].channels, 2, (int[]){69, 85});
    print_op_class_list("radio_2 agent_pref", agent_pref_list2);

    fail_unless(!map_ctrl_chan_sel_update(radio2));

    print_op_class_list("radio ctrl_pref",  ctrl_pref_list);
    print_op_class_list("radio_2 ctrl_pref",  ctrl_pref_list2);

    /* Check preferences for RADIO: 37, 53 are allowed */
    fail_unless(!check_cs(&radio->chan_sel.pref_channels, 2, (int[]){37, 53}));
    fail_unless(!check_cs(&radio->chan_sel.def_pref_channels, 2, (int[]){37, 53}));
    fail_unless(!check_op_class_131(ctrl_pref_list, 10, (int[]){1, 5, 9, 13, 17, 21, 69, 85, 101, 117}));

    /* Check preferences for RADIO_2: 37, 53 are allowed */
    fail_unless(!check_cs(&radio2->chan_sel.pref_channels, 2, (int[]){37, 53}));
    fail_unless(!check_cs(&radio2->chan_sel.def_pref_channels, 2, (int[]){37, 53}));
    /* Note: 5 and 21 are not excluded because they are not in the capabilities... */
    fail_unless(!check_op_class_131(ctrl_pref_list2, 8, (int[]){1, 9, 13, 17, 69, 85, 101, 117}));


    /* 5. ADD CTL AND REMOVE BAD CHANNEL AND DO MAP_CTRL_CHAN_SEL_UPDATE RADIO_2 AGAIN */
    log_test_i("5. ADD CTL AND REMOVE BAD CHANNEL AND DO MAP_CTRL_CHAN_SEL_UPDATE RADIO_2 AGAIN");

    /* Radio2: add channel 5 to cap channels and remove 85 from bad channels */
    map_cs_unset(&agent_cap_list2->op_classes[0].channels, 5);
    map_update_radio_channels(radio2);
    map_cs_unset(&agent_pref_list2->op_classes[0].channels, 85);

    fail_unless(!map_ctrl_chan_sel_update(radio2));

    print_op_class_list("radio ctrl_pref",  ctrl_pref_list);
    print_op_class_list("radio_2 ctrl_pref",  ctrl_pref_list2);

    /* Check preferences for RADIO: 5, 37, 53, 85 are allowed */
    fail_unless(!check_cs(&radio->chan_sel.pref_channels, 4, (int[]){5, 37, 53, 85}));
    fail_unless(!check_cs(&radio->chan_sel.def_pref_channels, 4, (int[]){5, 37, 53, 85}));
    fail_unless(!check_op_class_131(ctrl_pref_list, 8, (int[]){1, 9, 13, 17, 21, 69, 101, 117}));

    /* Check preferences for RADIO_2: 37, 53 are allowed */
    fail_unless(!check_cs(&radio2->chan_sel.pref_channels, 4, (int[]){5, 37, 53, 85}));
    fail_unless(!check_cs(&radio2->chan_sel.def_pref_channels, 4, (int[]){5, 37, 53, 85}));
    /* Note: 21 is not excluded because it not in the capabilities... */
    fail_unless(!check_op_class_131(ctrl_pref_list2, 7, (int[]){1, 9, 13, 17, 69, 101, 117}));


    /* 6. REMOVE RADIO_2 */
    log_test_i("6. REMOVE RADIO_2");
    map_dm_remove_radio(radio2);

    print_op_class_list("radio ctrl_pref",  ctrl_pref_list);

    /* Check preferences for RADIO: 5, 21, 37, 53, 69, 85 are allowed */
    fail_unless(!check_cs(&radio->chan_sel.pref_channels, 6, (int[]){5, 21, 37, 53, 69, 85}));
    fail_unless(!check_cs(&radio->chan_sel.def_pref_channels, 6, (int[]){5, 21, 37, 53, 69, 85}));
    fail_unless(!check_op_class_131(ctrl_pref_list, 6, (int[]){1, 9, 13, 17, 101, 117}));


    /* FINI */
    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_DUAL_5G_BANDLOCK                           #
########################################################################*/
START_TEST(test_dual_5g_bandlock)
{
    map_chan_sel_cfg_t  *cfg = &get_controller_cfg()->chan_sel;
    map_ale_info_t      *ale1;
    map_ale_info_t      *ale2;
    map_radio_info_t    *radio1_1;  /* ale, low_high */
    map_radio_info_t    *radio2_1;  /* ale2, low */
    map_radio_info_t    *radio2_2;  /* ale3, high */
    map_op_class_list_t *agent_cap_list;
    map_op_class_list_t *agent_pref_list;

    /* INIT */
    log_test_i("INIT TEST_DUAL_5G_BANDLOCK");
    test_init();

    /* Set defaults.  Allow all channels except 100 */
    map_cs_set_all(&cfg->default_pref_channel_set_5g);
    map_cs_unset(&cfg->default_pref_channel_set_5g, 100);

    fail_unless(!!(ale1 = map_dm_create_ale(g_al_mac)));
    fail_unless(!!(ale2 = map_dm_create_ale(g_al2_mac)));
    fail_unless(!!(radio1_1 = map_dm_create_radio(ale1, g_radio_id)));
    radio1_1->chan_sel.acs_enable = radio1_1->chan_sel.cloud_mgmt_enable = true;
    fail_unless(!!(radio2_1 = map_dm_create_radio(ale2, g_radio2_id)));
    radio2_1->chan_sel.acs_enable = radio2_1->chan_sel.cloud_mgmt_enable = true;
    fail_unless(!!(radio2_2 = map_dm_create_radio(ale2, g_radio3_id)));
    radio2_2->chan_sel.acs_enable = radio2_2->chan_sel.cloud_mgmt_enable = true;

    radio1_1->supported_freq = IEEE80211_FREQUENCY_BAND_5_GHZ;
    radio1_1->band_type_5G   = MAP_M2_BSS_RADIO5GL | MAP_M2_BSS_RADIO5GU;
    radio2_1->supported_freq = IEEE80211_FREQUENCY_BAND_5_GHZ;
    radio2_1->band_type_5G   = MAP_M2_BSS_RADIO5GL;
    radio2_2->supported_freq = IEEE80211_FREQUENCY_BAND_5_GHZ;
    radio2_2->band_type_5G   = MAP_M2_BSS_RADIO5GU;

    set_radio_state_channel_pref_report_received(&radio1_1->state);
    set_radio_state_channel_pref_report_received(&radio2_1->state);
    set_radio_state_channel_pref_report_received(&radio2_2->state);

    /* Radio1_1: 36->44 and 100->144, bad_channels 36 and 144 */
    agent_cap_list = &radio1_1->cap_op_class_list;
    agent_cap_list->op_classes_nr = 2;
    agent_cap_list->op_classes = calloc(2, sizeof(map_op_class_t));
    agent_cap_list->op_classes[0].op_class = 115;
    set_cs(&agent_cap_list->op_classes[0].channels, 1, (int[]){48});
    agent_cap_list->op_classes[1].op_class = 121;
    print_op_class_list("radio1_1 agent_cap", agent_cap_list);

    agent_pref_list = &radio1_1->pref_op_class_list;
    agent_pref_list->op_classes_nr = 2;
    agent_pref_list->op_classes = calloc(2, sizeof(map_op_class_t));
    agent_pref_list->op_classes[0].op_class = 115;
    agent_pref_list->op_classes[0].pref = 1;
    agent_pref_list->op_classes[0].reason = 6;
    set_cs(&agent_pref_list->op_classes[0].channels, 1, (int[]){36});
    agent_pref_list->op_classes[1].op_class = 121;
    agent_pref_list->op_classes[1].pref = 1;
    agent_pref_list->op_classes[1].reason = 6;
    set_cs(&agent_pref_list->op_classes[1].channels, 1, (int[]){144});
    print_op_class_list("radio1_1 agent_pref", agent_cap_list);

    /* Radio2_1: 36->48, bad channel 40 */
    agent_cap_list = &radio2_1->cap_op_class_list;
    agent_cap_list->op_classes_nr = 1;
    agent_cap_list->op_classes = calloc(1, sizeof(map_op_class_t));
    agent_cap_list->op_classes[0].op_class = 115;
    print_op_class_list("radio2_1 agent_cap", agent_cap_list);

    agent_pref_list = &radio2_1->pref_op_class_list;
    agent_pref_list->op_classes_nr = 1;
    agent_pref_list->op_classes = calloc(1, sizeof(map_op_class_t));
    agent_pref_list->op_classes[0].op_class = 115;
    agent_pref_list->op_classes[0].pref = 1;
    agent_pref_list->op_classes[0].reason = 6;
    set_cs(&agent_pref_list->op_classes[0].channels, 1, (int[]){40});
    print_op_class_list("radio2_1 agent_pref", agent_cap_list);

    /* Radio2_2: 100->144 but no weatherband, bad_channel 140 */
    agent_cap_list = &radio2_2->cap_op_class_list;
    agent_cap_list->op_classes_nr = 1;
    agent_cap_list->op_classes = calloc(1, sizeof(map_op_class_t));
    agent_cap_list->op_classes[0].op_class = 121;
    set_cs(&agent_cap_list->op_classes[0].channels, 3, (int[]){120, 124, 128});
    print_op_class_list("radio2_2 agent_cap", agent_cap_list);

    agent_pref_list = &radio2_2->pref_op_class_list;
    agent_pref_list->op_classes_nr = 1;
    agent_pref_list->op_classes = calloc(1, sizeof(map_op_class_t));
    agent_pref_list->op_classes[0].op_class = 121;
    agent_pref_list->op_classes[0].pref = 1;
    agent_pref_list->op_classes[0].reason = 6;
    set_cs(&agent_pref_list->op_classes[0].channels, 1, (int[]){140});
    print_op_class_list("radio2_2 agent_pref", agent_cap_list);

    /* Create ctl channels */
    map_update_radio_channels(radio1_1);
    map_update_radio_channels(radio2_1);
    map_update_radio_channels(radio2_2);

    fail_unless(!check_cs(&radio1_1->ctl_channels, 15, (int[]){36, 40, 44, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144}));
    fail_unless(!check_cs(&radio2_1->ctl_channels,  4, (int[]){36, 40, 44, 48}));
    fail_unless(!check_cs(&radio2_2->ctl_channels,  9, (int[]){100, 104, 108, 112, 116, 132, 136, 140, 144}));


    /* 1. CHANNEL SELECTION (ALIGN_MULTIAP=FALSE) */
    log_test_i("1. CHANNEL SELECTION (ALIGN_MULTIAP=FALSE)");

    fail_unless(!map_ctrl_chan_sel_update(radio1_1));
    fail_unless(!map_ctrl_chan_sel_update(radio2_1));
    fail_unless(!map_ctrl_chan_sel_update(radio2_2));

    fail_unless(!check_cs(&radio1_1->chan_sel.pref_channels, 12, (int[]){40, 44, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140}));
    fail_unless(!check_cs(&radio2_1->chan_sel.pref_channels,  3, (int[]){36, 44, 48}));
    fail_unless(!check_cs(&radio2_2->chan_sel.pref_channels,  7, (int[]){104, 108, 112, 116, 132, 136, 144}));


    /* 2. CHANNEL SELECTION (ALIGN_MULTIAP=TRUE) */
    log_test_i("2. CHANNEL SELECTION (ALIGN_MULTIAP=TRUE)");
    cfg->align_multiap = true;

    /* Note: because align multiap is enabled "in the middle", the first
       update was not tracked and we are currently not multiap_aliging the
       preference of the radio that is being updated.

       -> call 2 times
    */
    fail_unless(!map_ctrl_chan_sel_update(radio1_1));
    fail_unless(!map_ctrl_chan_sel_update(radio2_1));
    fail_unless(!map_ctrl_chan_sel_update(radio2_2));

    fail_unless(!map_ctrl_chan_sel_update(radio1_1));
    fail_unless(!map_ctrl_chan_sel_update(radio2_1));
    fail_unless(!map_ctrl_chan_sel_update(radio2_2));

    fail_unless(!check_cs(&radio1_1->chan_sel.pref_channels, 7, (int[]){44, 104, 108, 112, 116, 132, 136}));
    fail_unless(!check_cs(&radio2_1->chan_sel.pref_channels, 1, (int[]){44}));
    fail_unless(!check_cs(&radio2_2->chan_sel.pref_channels, 6, (int[]){104, 108, 112, 116, 132, 136}));


    /* 3. ENABLE BANDLOCK */
    log_test_i("3. ENABLE BANDLOCK");

    cfg->bandlock_5g = MAP_BANDLOCK_5G_HIGH;
    map_update_radio_channels(radio1_1);
    map_update_radio_channels(radio2_1);
    map_update_radio_channels(radio2_2);

    fail_unless(!check_cs(&radio1_1->ctl_channels, 12, (int[]){100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144}));
    fail_unless(!check_cs(&radio2_1->ctl_channels,  4, (int[]){36, 40, 44, 48}));
    fail_unless(!check_cs(&radio2_2->ctl_channels,  9, (int[]){100, 104, 108, 112, 116, 132, 136, 140, 144}));

    /* Run channel selection again.
       - radio1_1 is bandlocked
       - radio2_1 can use channel 48 again
    */
    fail_unless(!map_ctrl_chan_sel_update(radio1_1));
    fail_unless(!map_ctrl_chan_sel_update(radio2_1));
    fail_unless(!map_ctrl_chan_sel_update(radio2_2));

    fail_unless(!check_cs(&radio1_1->chan_sel.pref_channels, 6, (int[]){104, 108, 112, 116, 132, 136}));
    fail_unless(!check_cs(&radio2_1->chan_sel.pref_channels, 3, (int[]){36, 44, 48}));
    fail_unless(!check_cs(&radio2_2->chan_sel.pref_channels, 6, (int[]){104, 108, 112, 116, 132, 136}));

    /* FINI */
    test_fini();
}
END_TEST


/*#######################################################################
#                       TEST_REMOVED_STRICT_ALLOWED_CHANNELS            #
########################################################################*/
START_TEST(test_removed_strict_allowed_channels)
{
    map_chan_sel_cfg_t  *cfg = &get_controller_cfg()->chan_sel;
    map_ale_info_t      *ale;
    map_radio_info_t    *radio_5g;
    map_radio_info_t    *radio_2g;
    map_radio_info_t    *radio_6g;
    map_op_class_list_t *pref_list_5g;
    map_op_class_list_t *pref_list_2g;
    map_op_class_list_t *pref_list_6g;
    //char                 buf[MAP_CS_BUF_LEN];

    log_test_i("INIT TEST_REMOVED_STRICT_ALLOWED_CHANNELS");
    test_init();

    /* Change 5G and 6G default preferred channels */
    set_cs(&cfg->default_pref_channel_set_5g, 12, (int[]){36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112});
    set_cs(&cfg->default_pref_channel_set_6g,  4, (int[]){5, 21, 37, 53}); /* PSC only */

    fail_unless(!!(ale = map_dm_create_ale(g_al_mac)));
    fail_unless(!!(radio_5g = map_dm_create_radio(ale, g_radio_id)));
    radio_5g->chan_sel.acs_enable = radio_5g->chan_sel.cloud_mgmt_enable = true;
    fail_unless(!!(radio_2g = map_dm_create_radio(ale, g_radio2_id)));
    radio_2g->chan_sel.acs_enable = radio_2g->chan_sel.cloud_mgmt_enable = true;
    fail_unless(!!(radio_6g = map_dm_create_radio(ale, g_radio3_id)));
    radio_6g->chan_sel.acs_enable = radio_6g->chan_sel.cloud_mgmt_enable = true;

    pref_list_5g = &radio_5g->ctrl_pref_op_class_list;
    pref_list_2g = &radio_2g->ctrl_pref_op_class_list;
    pref_list_6g = &radio_6g->ctrl_pref_op_class_list;

    radio_5g->supported_freq = IEEE80211_FREQUENCY_BAND_5_GHZ;
    radio_2g->supported_freq = IEEE80211_FREQUENCY_BAND_2_4_GHZ;
    radio_6g->supported_freq = IEEE80211_FREQUENCY_BAND_6_GHZ;

    /* add radio operating classes 20MHz: 115, 118, 40MHz: 116, 117, 119, 120, 121, 122, 123 80MHz: 128 */
    radio_5g->cap_op_class_list.op_classes_nr = 10;
    radio_5g->cap_op_class_list.op_classes = calloc(10, sizeof(map_op_class_t));
    radio_5g->cap_op_class_list.op_classes[0].op_class = 115;
    radio_5g->cap_op_class_list.op_classes[1].op_class = 118;
    radio_5g->cap_op_class_list.op_classes[2].op_class = 116;
    radio_5g->cap_op_class_list.op_classes[3].op_class = 117;
    radio_5g->cap_op_class_list.op_classes[4].op_class = 119;
    radio_5g->cap_op_class_list.op_classes[5].op_class = 120;
    radio_5g->cap_op_class_list.op_classes[6].op_class = 121;
    radio_5g->cap_op_class_list.op_classes[7].op_class = 122;
    radio_5g->cap_op_class_list.op_classes[8].op_class = 123;
    radio_5g->cap_op_class_list.op_classes[9].op_class = 128;

    /* add radio operating classes 20MHz: 81, 40MHz: 83, 84 */
    radio_2g->cap_op_class_list.op_classes_nr = 3;
    radio_2g->cap_op_class_list.op_classes = calloc(3, sizeof(map_op_class_t));
    radio_2g->cap_op_class_list.op_classes[0].op_class = 81;
    radio_2g->cap_op_class_list.op_classes[1].op_class = 83;
    radio_2g->cap_op_class_list.op_classes[2].op_class = 84;

    /* add radio operating classes 20MHz: 131, 40MHz: 132, 80MHz: 133, 160MHz: 134 */
    radio_6g->cap_op_class_list.op_classes_nr = 4;
    radio_6g->cap_op_class_list.op_classes = calloc(4, sizeof(map_op_class_t));
    radio_6g->cap_op_class_list.op_classes[0].op_class = 131;
    radio_6g->cap_op_class_list.op_classes[1].op_class = 132;
    radio_6g->cap_op_class_list.op_classes[2].op_class = 133;
    radio_6g->cap_op_class_list.op_classes[3].op_class = 134;

    // 5GHz radio
    set_cs(&radio_5g->ctl_channels, 9, (int[]){36, 40, 44, 48, 52, 60, 64, 104, 108});

    // 2.4GHz radio
    set_cs(&radio_2g->ctl_channels, 6, (int[]){1, 2, 3, 4, 5, 6});

    // 6GHz radio
    set_cs(&radio_6g->ctl_channels, 2, (int[]){5, 21});  /* PSC only */

    /* map_ctrl_chan_sel_update */
    fail_unless(!map_ctrl_chan_sel_update(radio_5g));
    fail_unless(!map_ctrl_chan_sel_update(radio_2g));
    fail_unless(!map_ctrl_chan_sel_update(radio_6g));

    /* CHECK 5GHz RADIO */
    fail_unless(!check_cs(&radio_5g->chan_sel.pref_channels, 9, (int[]){36, 40, 44, 48, 52, 60, 64, 104, 108}));
    fail_unless(!check_cs(&radio_5g->chan_sel.def_pref_channels, 9, (int[]){36, 40, 44, 48, 52, 60, 64, 104, 108}));

    fail_unless(pref_list_5g->op_classes_nr == 7);
    /*
    for(int i = 0; i < pref_list_5g->op_classes_nr; i++) {
        log_test_i("i=%d class=%d #chan=%d %s\n", pref_list_5g->op_classes_nr, pref_list_5g->op_classes[i].op_class, map_cs_nr(&pref_list_5g->op_classes[i].channels),
                   map_cs_to_string(&pref_list_5g->op_classes[i].channels, ',', buf, sizeof(buf)));
    }
    */

    /* 20MHz */
    fail_unless(pref_list_5g->op_classes[0].op_class == 118);
    fail_unless(pref_list_5g->op_classes[0].pref == 0);
    fail_unless(map_cs_nr(&pref_list_5g->op_classes[0].channels) == 1); /* 56 */
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[0].channels, 56));

    /* 40MHz lower */
    fail_unless(pref_list_5g->op_classes[1].op_class == 119);
    fail_unless(pref_list_5g->op_classes[1].pref == 0);
    fail_unless(map_cs_nr(&pref_list_5g->op_classes[1].channels) == 1); /* 52 */
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[1].channels, 52));

    /* 40MHz upper */
    fail_unless(pref_list_5g->op_classes[2].op_class == 120);
    fail_unless(pref_list_5g->op_classes[2].pref == 0);
    fail_unless(map_cs_nr(&pref_list_5g->op_classes[2].channels) == 1); /* 56 */
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[2].channels, 56));

    /* 20MHz */
    fail_unless(pref_list_5g->op_classes[3].op_class == 121);
    fail_unless(pref_list_5g->op_classes[3].pref == 0);
    fail_unless(map_cs_nr(&pref_list_5g->op_classes[3].channels) == 10); /* 100, 112, 116, 120, 124, 128, 132, 136, 140, 144 */
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[3].channels, 100));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[3].channels, 112));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[3].channels, 116));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[3].channels, 120));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[3].channels, 124));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[3].channels, 128));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[3].channels, 136));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[3].channels, 140));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[3].channels, 144));

    /* 40MHz lower */
    fail_unless(pref_list_5g->op_classes[4].op_class == 122);
    fail_unless(pref_list_5g->op_classes[4].pref == 0);
    fail_unless(map_cs_nr(&pref_list_5g->op_classes[4].channels) == 6); /* 100, 108, 116, 124, 132, 140 */
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[4].channels, 100));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[4].channels, 108));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[4].channels, 116));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[4].channels, 124));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[4].channels, 132));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[4].channels, 140));

    /* 40MHz upper */
    fail_unless(pref_list_5g->op_classes[5].op_class == 123);
    fail_unless(pref_list_5g->op_classes[5].pref == 0);
    fail_unless(map_cs_nr(&pref_list_5g->op_classes[5].channels) == 6); /* 104, 112, 120, 128, 136, 144 */
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[5].channels, 104));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[5].channels, 112));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[5].channels, 120));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[5].channels, 128));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[5].channels, 136));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[5].channels, 144));

    /* 80MHz */
    fail_unless(pref_list_5g->op_classes[6].op_class == 128);
    fail_unless(pref_list_5g->op_classes[6].pref == 0);
    fail_unless(map_cs_nr(&pref_list_5g->op_classes[6].channels) == 6); /* 58, 106, 122, 138, 155, 171 */
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[6].channels, 58));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[6].channels, 106));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[6].channels, 122));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[6].channels, 138));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[6].channels, 155));
    fail_unless(map_cs_is_set(&pref_list_5g->op_classes[6].channels, 171));

    /* CHECK 2.4GHz RADIO */
    fail_unless(!check_cs(&radio_2g->chan_sel.pref_channels, 6, (int[]){1, 2, 3, 4, 5, 6}));
    fail_unless(!check_cs(&radio_2g->chan_sel.def_pref_channels, 6, (int[]){1, 2, 3, 4, 5, 6}));

    fail_unless(pref_list_2g->op_classes_nr == 3);
    /*
    for(int i = 0; i < pref_list_2g->op_classes_nr; i++) {
        log_test_i("i=%d class=%d #chan=%d %s\n", pref_list_2g->op_classes_nr, pref_list_2g->op_classes[i].op_class, map_cs_nr(&pref_list_2g->op_classes[i].channels),
                   map_cs_to_string(&pref_list_2g->op_classes[i].channels, ',', buf, sizeof(buf)));
    }*/

    /* 20MHz */
    fail_unless(pref_list_2g->op_classes[0].op_class == 81);
    fail_unless(pref_list_2g->op_classes[0].pref == 0);
    fail_unless(map_cs_nr(&pref_list_2g->op_classes[0].channels) == 7); /* 7, 8, 9, 10, 11, 12, 13 */
    fail_unless(map_cs_is_set(&pref_list_2g->op_classes[0].channels, 7));
    fail_unless(map_cs_is_set(&pref_list_2g->op_classes[0].channels, 8));
    fail_unless(map_cs_is_set(&pref_list_2g->op_classes[0].channels, 9));
    fail_unless(map_cs_is_set(&pref_list_2g->op_classes[0].channels, 10));
    fail_unless(map_cs_is_set(&pref_list_2g->op_classes[0].channels, 11));
    fail_unless(map_cs_is_set(&pref_list_2g->op_classes[0].channels, 12));
    fail_unless(map_cs_is_set(&pref_list_2g->op_classes[0].channels, 13));

    /* 40MHz lower */
    fail_unless(pref_list_2g->op_classes[1].op_class == 83);
    fail_unless(pref_list_2g->op_classes[1].pref == 0);
    fail_unless(map_cs_nr(&pref_list_2g->op_classes[1].channels) == 7); /* 3, 4, 5, 6, 7, 8, 9 */
    fail_unless(map_cs_is_set(&pref_list_2g->op_classes[1].channels, 3));
    fail_unless(map_cs_is_set(&pref_list_2g->op_classes[1].channels, 4));
    fail_unless(map_cs_is_set(&pref_list_2g->op_classes[1].channels, 5));
    fail_unless(map_cs_is_set(&pref_list_2g->op_classes[1].channels, 6));
    fail_unless(map_cs_is_set(&pref_list_2g->op_classes[1].channels, 7));
    fail_unless(map_cs_is_set(&pref_list_2g->op_classes[1].channels, 8));
    fail_unless(map_cs_is_set(&pref_list_2g->op_classes[1].channels, 9));

    /* 40MHz upper */
    fail_unless(pref_list_2g->op_classes[2].op_class == 84);
    fail_unless(pref_list_2g->op_classes[2].pref == 0);
    fail_unless(map_cs_nr(&pref_list_2g->op_classes[2].channels) == 7); /* 7, 8, 9, 10, 11, 12, 13 */
    fail_unless(map_cs_is_set(&pref_list_2g->op_classes[2].channels, 7));
    fail_unless(map_cs_is_set(&pref_list_2g->op_classes[2].channels, 8));
    fail_unless(map_cs_is_set(&pref_list_2g->op_classes[2].channels, 9));
    fail_unless(map_cs_is_set(&pref_list_2g->op_classes[2].channels, 10));
    fail_unless(map_cs_is_set(&pref_list_2g->op_classes[2].channels, 11));
    fail_unless(map_cs_is_set(&pref_list_2g->op_classes[2].channels, 12));
    fail_unless(map_cs_is_set(&pref_list_2g->op_classes[2].channels, 13));

    /* CHECK 6GHz RADIO (with PSC set) */
    fail_unless(!check_cs(&radio_6g->chan_sel.pref_channels, 2, (int[]){5, 21}));
    fail_unless(!check_cs(&radio_6g->chan_sel.def_pref_channels, 2, (int[]){5, 21}));

    fail_unless(pref_list_6g->op_classes_nr == 4);

    /* 20MHz */
    fail_unless(pref_list_6g->op_classes[0].op_class == 131);
    fail_unless(pref_list_6g->op_classes[0].pref == 0);
    fail_unless(map_cs_nr(&pref_list_6g->op_classes[0].channels) == 59 - 2); /* all except 5 and 21 (1, 9, 13, 17, 25, ..., 233) */
    fail_unless(!map_cs_is_set(&pref_list_6g->op_classes[0].channels, 5));
    fail_unless(!map_cs_is_set(&pref_list_6g->op_classes[0].channels, 21));
    fail_unless(map_cs_is_set(&pref_list_6g->op_classes[0].channels, 1));
    fail_unless(map_cs_is_set(&pref_list_6g->op_classes[0].channels, 9));
    fail_unless(map_cs_is_set(&pref_list_6g->op_classes[0].channels, 13));
    fail_unless(map_cs_is_set(&pref_list_6g->op_classes[0].channels, 17));

    /* 40 MHz */
    fail_unless(pref_list_6g->op_classes[1].op_class == 132);
    fail_unless(pref_list_6g->op_classes[1].pref == 0);
    fail_unless(map_cs_nr(&pref_list_6g->op_classes[1].channels) == 29 - 2); /* all except 3 and 19 (11, 27, 35, 43, 51, ..., 227) */
    fail_unless(!map_cs_is_set(&pref_list_6g->op_classes[1].channels, 3));
    fail_unless(!map_cs_is_set(&pref_list_6g->op_classes[1].channels, 19));
    fail_unless(map_cs_is_set(&pref_list_6g->op_classes[1].channels, 11));
    fail_unless(map_cs_is_set(&pref_list_6g->op_classes[1].channels, 27));
    fail_unless(map_cs_is_set(&pref_list_6g->op_classes[1].channels, 35));
    fail_unless(map_cs_is_set(&pref_list_6g->op_classes[1].channels, 227));

    /* 80 MHz */
    fail_unless(pref_list_6g->op_classes[2].op_class == 133);
    fail_unless(pref_list_6g->op_classes[2].pref == 0);
    fail_unless(map_cs_nr(&pref_list_6g->op_classes[2].channels) == 14 - 2); /* all except 7 and 23 (39, 55, 71, 87, ..., 215) */
    fail_unless(!map_cs_is_set(&pref_list_6g->op_classes[2].channels, 7));
    fail_unless(!map_cs_is_set(&pref_list_6g->op_classes[2].channels, 32));
    fail_unless(map_cs_is_set(&pref_list_6g->op_classes[2].channels, 39));
    fail_unless(map_cs_is_set(&pref_list_6g->op_classes[2].channels, 55));
    fail_unless(map_cs_is_set(&pref_list_6g->op_classes[2].channels, 71));
    fail_unless(map_cs_is_set(&pref_list_6g->op_classes[2].channels, 215));

    /* 160 MHz */
    fail_unless(pref_list_6g->op_classes[3].op_class == 134);
    fail_unless(pref_list_6g->op_classes[3].pref == 0);
    fail_unless(map_cs_nr(&pref_list_6g->op_classes[3].channels) == 7 - 1); /* all except 15 (47, 79, 111, 143, ..., 207) */
    fail_unless(!map_cs_is_set(&pref_list_6g->op_classes[3].channels, 15));
    fail_unless(map_cs_is_set(&pref_list_6g->op_classes[3].channels, 47));
    fail_unless(map_cs_is_set(&pref_list_6g->op_classes[3].channels, 79));
    fail_unless(map_cs_is_set(&pref_list_6g->op_classes[3].channels, 111));
    fail_unless(map_cs_is_set(&pref_list_6g->op_classes[3].channels, 207));

    /* CHECK 6GHz RADIO (without PSC set) -> 40/80/160 are no longer allowed */
    cfg->allowed_channel_6g_psc = false;
    fail_unless(!map_ctrl_chan_sel_update(radio_6g));

    /* 20MHz */
    fail_unless(pref_list_6g->op_classes[0].op_class == 131);
    fail_unless(pref_list_6g->op_classes[0].pref == 0);
    fail_unless(map_cs_nr(&pref_list_6g->op_classes[0].channels) == 59 - 2); /* all except 5 and 21 (1, 9, 13, 17, 25, ..., 233) */
    fail_unless(!map_cs_is_set(&pref_list_6g->op_classes[0].channels, 5));
    fail_unless(!map_cs_is_set(&pref_list_6g->op_classes[0].channels, 21));
    fail_unless(map_cs_is_set(&pref_list_6g->op_classes[0].channels, 1));
    fail_unless(map_cs_is_set(&pref_list_6g->op_classes[0].channels, 9));
    fail_unless(map_cs_is_set(&pref_list_6g->op_classes[0].channels, 13));
    fail_unless(map_cs_is_set(&pref_list_6g->op_classes[0].channels, 17));

    /* 40MHz */
    fail_unless(pref_list_6g->op_classes[1].op_class == 132);
    fail_unless(pref_list_6g->op_classes[1].pref == 0);
    fail_unless(map_cs_nr(&pref_list_6g->op_classes[1].channels) == 29); /* all (3, 11, 19, ..., 227) */

    /* 80MHz */
    fail_unless(pref_list_6g->op_classes[2].op_class == 133);
    fail_unless(pref_list_6g->op_classes[2].pref == 0);
    fail_unless(map_cs_nr(&pref_list_6g->op_classes[2].channels) == 14); /* all (7, 23, 39, ..., 227) */

    /* 160MHz */
    fail_unless(pref_list_6g->op_classes[3].op_class == 134);
    fail_unless(pref_list_6g->op_classes[3].pref == 0);
    fail_unless(map_cs_nr(&pref_list_6g->op_classes[3].channels) == 7); /* all (15, 47, 79, ..., 207) */

    test_fini();
}
END_TEST

const char *test_suite_name = "chan_sel";
test_case_t test_cases[] = {
    TEST("chan_sel",                         test_chan_sel  ),
    TEST("chan_sel_weatherband",             test_chan_sel_weatherband  ),
    TEST("multiap_align",                    test_multiap_align  ),
    TEST("dual_5g_bandlock",                 test_dual_5g_bandlock  ),
    TEST("removed_strict_allowed_channels",  test_removed_strict_allowed_channels  ),
    TEST_CASES_END
};
