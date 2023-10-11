/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#define LOG_TAG "post_onboarding"

#include "map_ctrl_post_onboarding_handler.h"
#include "map_ctrl_onboarding_handler.h"
#include "map_ctrl_defines.h"
#include "map_ctrl_cmdu_tx.h"
#include "map_ctrl_tlv_helper.h"
#include "map_ctrl_utils.h"
#include "map_info.h"
#include "map_timer_handler.h"

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
static bool is_policy_config_required(void)
{
    /* In case of WFA certification, policy config is triggered by CAPI command */
    return WFA_CERT() ? false : true;
}

static bool is_initial_channel_scan_required(void)
{
    /* In case of WFA certification, channel scan is triggered by CAPI command */
    return WFA_CERT() ? false : true;
}

static int chan_sel_query_compl_cb(int status, void *args, UNUSED void *opaque_cmdu)
{
    map_ale_info_t *ale = args;

    /* Channel preferencey query completed -> perform channel selection on all radios */
    if (status == MAP_RETRY_STATUS_SUCCESS && map_is_channel_selection_enabled()) {
        map_agent_handle_channel_selection(ale, /* all radios */NULL, MAP_CHAN_SEL_REQUEST);
    }

    return 0;
}

static uint8_t onboarding_status_check_timer_cb(UNUSED char* timer_id, void *ale_object)
{
    map_ale_info_t *ale = ale_object;

    if (!ale || WFA_CERT()) {
        return 0;
    }

    /* Send autoconfig renew if not all M1 where received */
    if (ale->radios_nr > 0 && !map_is_all_radio_M1_received(ale)) {
        log_ctrl_i("sending config renew to ALE[%s]", ale->al_mac_str);
        if (map_send_autoconfig_renew_ucast(ale, IEEE80211_FREQUENCY_BAND_2_4_GHZ, MID_NA)) {
            log_ctrl_e("map_send_autoconfig_renew failed");
        }
    }

    /* Send extra topology query when not yet completely onboarded */
    if (ale->ale_onboard_status == ALE_NODE_ONBOARDING) {
        map_send_topology_query(ale, MID_NA);
    }

    return 0; /* Keep running */
}

/*#######################################################################
#                       CALLBACKS                                       #
########################################################################*/
int map_build_and_send_policy_config(void *args, uint16_t *mid)
{
    map_ale_info_t                         *ale = args;
    map_radio_info_t                       *radio;
    map_cfg_t                              *cfg = map_cfg_get();
    map_policy_config_tlvs_t                tlvs = {0};
    map_metric_reporting_policy_tlv_t       metric_policy_tlv;
    map_steering_policy_tlv_t               steering_policy_tlv;
    map_channel_scan_reporting_policy_tlv_t channel_scan_report_policy_tlv;
    map_unsuccessful_assoc_policy_tlv_t     unsuccess_assoc_policy_tlv;
    map_default_8021q_settings_tlv_t        default_8021q_settings_tlv;
    map_traffic_separation_policy_tlv_t     traffic_separation_policy_tlv;
    int                                     idx;

    if (ale == NULL) {
        return -1;
    }

    if (!is_policy_config_required()) {
        return 0;
    }

    /* See TRS "WLAN-Controller_M4" for the used values below */

    /* Update Metric reporting policy TLV */
    metric_policy_tlv.radios_nr                 = ale->radios_nr;
    metric_policy_tlv.metric_reporting_interval = 1;
    tlvs.metric_policy_tlv = &metric_policy_tlv;

    /* Update steering policy TLV */
    steering_policy_tlv.radios_nr                  = ale->radios_nr;
    steering_policy_tlv.local_steering_dis_macs_nr = 0;
    steering_policy_tlv.btm_steering_dis_macs_nr   = 0;
    steering_policy_tlv.local_steering_dis_macs    = NULL;
    steering_policy_tlv.btm_steering_dis_macs      = NULL;

    idx = 0;
    map_dm_foreach_radio(ale, radio) {
        maccpy(metric_policy_tlv.radios[idx].radio_id, radio->radio_id);
        metric_policy_tlv.radios[idx].reporting_rssi_threshold                = 0;
        metric_policy_tlv.radios[idx].reporting_rssi_margin_override          = 0;
        metric_policy_tlv.radios[idx].channel_utilization_reporting_threshold = 0;
        metric_policy_tlv.radios[idx].associated_sta_policy                   = MAP_METRIC_POLICY_TRAFFIC_STATS |
                                                                                MAP_METRIC_POLICY_LINK_METRICS  |
                                                                                MAP_METRIC_POLICY_WIFI_6_STATS;

        maccpy(steering_policy_tlv.radios[idx].radio_id, radio->radio_id);
        steering_policy_tlv.radios[idx].channel_utilization_threshold = 0x00;
        steering_policy_tlv.radios[idx].rssi_steering_threshold       = 0x00;
        steering_policy_tlv.radios[idx].steering_policy               = 0x00;
        set_radio_state_policy_config_ack_not_received(&radio->state);

        idx++;
    }

    tlvs.steering_policy_tlv = &steering_policy_tlv;

    /* For profile 2 and higher */
    /* Add Channel scan reporting policy TLV: report independent channel scans */
    channel_scan_report_policy_tlv.report_independent_ch_scans = 0;  /* TODO: wbd_slave crashes when reporting independant scan results */
    tlvs.channel_scan_report_policy_tlv = &channel_scan_report_policy_tlv;

    /* Add Unsuccessfull association policy TLV: report maximum 60 per minute */
    unsuccess_assoc_policy_tlv.report_flag        = 1;
    unsuccess_assoc_policy_tlv.max_reporting_rate = 60;
    tlvs.unsuccess_assoc_policy_tlv = &unsuccess_assoc_policy_tlv;

    /* Add default 8021Q settings tlv and traffic separation tlv if primary network is tagged */
    if (ale->agent_capability.profile_2_ap_cap_valid) {
        if (TS_ENABLED()) {
            map_fill_default_8021q_settings_tlv(cfg, &default_8021q_settings_tlv);
            tlvs.default_8021q_settings_tlv = &default_8021q_settings_tlv;

            map_fill_traffic_separation_policy_tlv(get_controller_cfg(), cfg->primary_vlan_id,
                                                   ale->agent_capability.max_vid_count,
                                                   &traffic_separation_policy_tlv);
        } else {
            /* If TS is disabled add an empty ts tlv so agent can remove any existing vlan */
            map_fill_empty_traffic_separation_policy_tlv(&traffic_separation_policy_tlv);
        }
        tlvs.traffic_separation_policy_tlv = &traffic_separation_policy_tlv;
    }

    /* Policy config is sent for all radios of respective ale, so reset state
       radio state respective bit for all radios and change ale state to onboarding
    */
    map_dm_ale_set_onboard_status(ale, ALE_NODE_ONBOARDING);

    return map_send_policy_config_request(ale, &tlvs, mid);
}

int map_handle_policy_config_sent(int status, void *args, UNUSED void *compl_user_data)
{
    map_ale_info_t   *ale = args;
    map_radio_info_t *radio;

    if (status == MAP_RETRY_STATUS_SUCCESS) {
        map_dm_foreach_radio(ale, radio) {
            set_radio_state_policy_config_ack_received(&radio->state);
        }
        map_recompute_radio_state_and_update_ale_state(ale);
    }
    return 0;
}

int map_build_and_send_initial_channel_scan_req(void *args, UNUSED uint16_t *mid)
{
    map_radio_info_t               *radio = args;
    map_channel_scan_request_tlv_t  channel_scan_req_tlv = {0};

    if (!is_initial_channel_scan_required()) {
        return 0;
    }

    if (is_radio_initial_scan_results_received(radio->state) || !radio->scan_caps.valid) {
        return 0;
    }

    /* NOTE: When boot_only is false, EMR2 does not say that the agent needs to do a boot scan.  BRCM agent doesn't do this.
       Attempt to get boot/cached results once, afterwards perform fresh scan.
    */
    bool fresh_scan = !radio->scan_caps.boot_only && radio->last_scan_info.last_scan_status_failed;

    map_fill_channel_scan_request_tlv(&channel_scan_req_tlv, radio, fresh_scan, /* all channels */ NULL);

    if (map_send_channel_scan_request(radio->ale, &channel_scan_req_tlv, MID_NA)) {
        log_ctrl_e("map_send_channel_scan_request failed");
        return -1;
    }

    radio->last_scan_info.last_scan_req_time = acu_get_timestamp_sec();

    return 0;
}

int map_handle_initial_channel_scan_request_sent(int status, void *args, UNUSED void *compl_user_data)
{
    map_radio_info_t *radio = args;

    if (status == MAP_RETRY_STATUS_TIMEOUT) {
        if (!is_radio_initial_scan_results_received(radio->state)) {
            /* Assume received not to prevent operation. This is not crucial */
            log_ctrl_i("Initial Scan Results are not received after retries. Assume received, explicitly");
            set_radio_state_initial_scan_results_received(&radio->state);
        }
    }

    return 0;
}


/*#######################################################################
#                       ONBOARDING STATUS CHECK TIMER                   #
########################################################################*/
int map_start_onboarding_status_check_timer(map_ale_info_t *ale)
{
    timer_id_t timer_id;
    int        ret = 0;

    map_dm_get_ale_timer_id(timer_id, ale, ONBOARDING_STATUS_TIMER_ID);

    /* Restart when already created */
    if (map_is_timer_registered(timer_id)) {
        if ((ret = map_timer_restart_callback(timer_id))) {
            log_ctrl_e("%s: failed to restarting onboarding status check timer", __FUNCTION__);
        }
    } else {
        if ((ret = map_timer_register_callback(ONBOARDING_STATUS_CHECK_TIME, timer_id, ale, onboarding_status_check_timer_cb))) {
            log_ctrl_e("%s: failed to register onboarding status check timer", __FUNCTION__);
        }
    }

    return ret;
}

/*#######################################################################
#                       CHANNEL SELECTION                               #
########################################################################*/
int map_agent_handle_channel_selection(map_ale_info_t *ale, map_radio_info_t *radio, int action)
{
    timer_id_t retry_id;
    int8_t     status = 0;

    do {
        /* Radio can be NULL (= request for all radios) */
        if (ale == NULL) {
            log_ctrl_e("ale is NULL");
            ERROR_EXIT(status)
        }

        if (action == MAP_CHAN_SEL_QUERY) {
            /* Retry Channel preference query untill we get a report from agent. */
            map_dm_get_ale_timer_id(retry_id, ale, CHAN_PREF_QUERY_RETRY_ID);
            if (!map_is_timer_registered(retry_id)) {
                if (map_register_retry(retry_id, 10, 10, ale, chan_sel_query_compl_cb, map_send_channel_preference_query)) {
                    log_ctrl_e("failed Registering retry timer[%s]", retry_id);
                    ERROR_EXIT(status)
                }
            }
        } else if (action == MAP_CHAN_SEL_REQUEST) {
            /* Retry Channel selection request untill we get a response.
               This memory will be freed by cleanup_retry_args during retry completion handler
            */

            if (radio) {
                map_dm_get_radio_timer_id(retry_id, radio, CHAN_SELECT_REQ_RETRY_ID);
            } else {
                map_dm_get_ale_timer_id(retry_id, ale, CHAN_SELECT_REQ_RETRY_ID);
            }

            /* Check if already active */
            if (!map_is_timer_registered(retry_id)) {
                map_chan_select_pref_type_t *pref_type = calloc(1, sizeof(map_chan_select_pref_type_t));

                if (!pref_type) {
                    log_ctrl_e("failed to allocate memory");
                    ERROR_EXIT(status)
                }

                pref_type->ale   = ale;
                pref_type->radio = radio;
                pref_type->pref  = MAP_CHAN_SEL_PREF_MERGED;

                ale->first_chan_sel_req_done = 1;
                ale->last_chan_sel_req_time  = acu_get_timestamp_sec();

                if (map_register_retry(retry_id, 10, 10, pref_type, map_cleanup_retry_args, map_send_channel_selection_request)) {
                    log_ctrl_e("failed Registering retry timer[%s]", retry_id);
                    free(pref_type);
                    ERROR_EXIT(status)
                }
            }
        }
    } while (0);

    return status;
}

int map_agent_cancel_channel_selection(map_ale_info_t *ale)
{
    map_radio_info_t *radio;
    timer_id_t        retry_id;

    /* Stop per ALE query and select timer */
    map_dm_get_ale_timer_id(retry_id, ale, CHAN_PREF_QUERY_RETRY_ID);
    if (map_is_timer_registered(retry_id)) {
        map_unregister_retry(retry_id);
    }

    map_dm_get_ale_timer_id(retry_id, ale, CHAN_SELECT_REQ_RETRY_ID);
    if (map_is_timer_registered(retry_id)) {
        map_unregister_retry(retry_id);
    }

    /* Stop per RADIO select timer */
    map_dm_foreach_radio(ale, radio) {
        map_dm_get_radio_timer_id(retry_id, radio, CHAN_SELECT_REQ_RETRY_ID);
        if (map_is_timer_registered(retry_id)) {
            map_unregister_retry(retry_id);
        }
    }

    return 0;
}
