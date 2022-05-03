/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <libubox/uloop.h>

#define LOG_TAG "config"

#include "map_ctrl_config.h"
#include "map_ctrl_utils.h"
#include "map_ctrl_defines.h"
#include "map_ctrl_cmdu_tx.h"
#include "map_ctrl_post_onboarding_handler.h"
#include "map_config.h"
#include "map_retry_handler.h"
#include "map_topology_tree.h"
#include "map_dm_airdata.h"

#include "i1905.h"

/*#######################################################################
#                       PRIVATE FUNCTIONS
########################################################################*/
static void retrigger_channel_selection(map_ale_info_t *ale, map_radio_info_t *radio)
{
    /* 1. Cancel possible ongoing channel selection */
    map_agent_cancel_channel_selection(ale);

    /* 2. Trigger DM update.  This will update allowed channel list in both msg_lib and
          airdata Device.WiFi.MultiAP and it will update the controller channel
          preference.
    */
    map_dm_radio_set_capabilities(radio);

    /* 3. Invalidate any previous channel selection. This will trigger a new selection after
          next topology response.
    */
    set_radio_state_channel_preference_query_not_sent(&radio->state);
    set_radio_state_channel_pref_report_not_received(&radio->state);
    set_radio_state_oper_chan_report_not_received(&radio->state);
    map_recompute_radio_state_and_update_ale_state(ale);
}

static void configure_radio_channel_bandwidth(int ale_idx, int radio_idx, int channel, int bw)
{
    map_ale_info_t   *ale;
    map_radio_info_t *radio;

    if ((ale   = map_dm_airdata_get_ale(ale_idx)) &&
        (radio = map_dm_airdata_get_radio(ale, radio_idx))) {
        /* Sync with airdata */
        if (channel >= 0) {
            radio->configured_channel = channel;
        }
        if (bw >= 0) {
            radio->configured_bw = bw;
        }
    }
}

/*#######################################################################
#                       PUBLIC FUNCTIONS
########################################################################*/
static void enable_dormant_cb(bool enable)
{
    /* Called in dormant mode -> exit when enabled */
    if (enable) {
        log_ctrl_i("exit dormant state");
        uloop_end();
    }
}

static void enable_running_cb(bool enable)
{
    /* Called in running mode -> exit when not enabled */
    if (!enable) {
        log_ctrl_i("exit running state");
        uloop_end();
    }
}

static void update_cb(void)
{
    log_ctrl_i("config update");

    if (map_cfg_reload()) {
        log_ctrl_e("map_cfg_reload failed");
    }
}

static void profile_update_cb(void)
{
    bool changed;

    log_ctrl_i("profile update");

    do {
        log_ctrl_i("reload profiles");
        if (map_profile_load(&changed)) {
            log_ctrl_e("map_profile_load failed");
            break;
        }

        if (!changed) {
            log_ctrl_i("profiles did not change");
            break;
        }
        log_ctrl_i("profiles changed -> send autoconfig renew");

        /* Irrespective of the frequency band, Agent has to send M1 for all the radios
           as per section 7.1 in the Multiap specification.
        */

        if (map_send_autoconfig_renew(IEEE80211_FREQUENCY_BAND_2_4_GHZ, MID_NA)) {
            log_ctrl_e("map_send_autoconfig_renew failed");
            break;
        }

        /* This will also cause resending of policy config request which is required to update
           traffic separation policy
        */
        map_reset_all_agent_nodes_onboarding_status();
    } while(0);
}

static void allowed_channel_list_update_cb(bool is_5g)
{
    map_ale_info_t   *ale;
    map_radio_info_t *radio;
    bool              is_2g = !is_5g;

    log_ctrl_i("Allowed channel list changed is_5g[%d]", is_5g);

    /* Reload all... */
    if (map_cfg_reload()) {
        log_ctrl_e("map_cfg_reload failed");
    }

    /* Retrigger channel selection for all radios */
    map_dm_foreach_agent_ale(ale) {
        map_dm_foreach_radio(ale, radio) {
            if ((is_5g && radio->supported_freq != IEEE80211_FREQUENCY_BAND_5_GHZ) ||
                (is_2g && radio->supported_freq != IEEE80211_FREQUENCY_BAND_2_4_GHZ)) {
                continue;
            }

            retrigger_channel_selection(ale, radio);
        }
    }
}

static void bandlock_5g_update_cb(bandlock_5g_t type)
{
    map_ale_info_t   *ale;
    map_radio_info_t *radio;

    log_ctrl_i("Bandlock 5G update type[%d]", type);

    /* Store new type */
    get_controller_cfg()->bandlock_5g = type;

    /* Retrigger channel selection for all 5G radio in the network that support
       both low and high band
    */
    map_dm_foreach_agent_ale(ale) {
        map_dm_foreach_radio(ale, radio) {
            if (!map_is_5g_low_high(radio)) {
                continue;
            }

            retrigger_channel_selection(ale, radio);
        }
    }
}

static void radio_channel_cb(int ale_idx, int radio_idx, int channel)
{
    log_ctrl_i("Radio channel update ale_idx[%d] radio_idx[%d] channel[%d]", ale_idx, radio_idx, channel);

    configure_radio_channel_bandwidth(ale_idx, radio_idx, channel, -1);
}

static void radio_bandwidth_cb(int ale_idx, int radio_idx, int bw)
{
    log_ctrl_i("Radio bandwidth update ale_idx[%d] radio_idx[%d] bw[%d]", ale_idx, radio_idx, bw);

    configure_radio_channel_bandwidth(ale_idx, radio_idx, -1, bw);
}

/*#######################################################################
#                       CALLBACK STRUCTS                                #
########################################################################*/
/* In dormant mode, only intall enable callback */
static map_cfg_cbs_t g_dormant_cfg_cbs = {
    .enable_cb = enable_dormant_cb
};

static map_cfg_cbs_t g_monitor_cfg_cbs = {
    .enable_cb                  = enable_running_cb,
    .master_state_cb            = NULL,
    .update_cb                  = update_cb,
};

static map_cfg_cbs_t g_running_cfg_cbs = {
    .enable_cb                      = enable_running_cb,
    .master_state_cb                = NULL,
    .update_cb                      = update_cb,
    .profile_update_cb              = profile_update_cb,
    .backhaul_profile_update_cb     = NULL,
    .allowed_channel_list_update_cb = allowed_channel_list_update_cb,
    .bandlock_5g_update_cb          = bandlock_5g_update_cb,
    .radio_channel_cb               = radio_channel_cb,
    .radio_bandwidth_cb             = radio_bandwidth_cb,
};

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
void map_cfg_set_dormant_cbs(void)
{
    map_cfg_set_cbs(&g_dormant_cfg_cbs);
}

void map_cfg_set_monitor_cbs(void)
{
    map_cfg_set_cbs(&g_monitor_cfg_cbs);
}

void map_cfg_set_running_cbs(void)
{
    map_cfg_set_cbs(&g_running_cfg_cbs);
}
