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
#define LOG_TAG "tlv_parser"

#include "map_ctrl_tlv_parser.h"
#include "map_ctrl_onboarding_handler.h"
#include "map_ctrl_post_onboarding_handler.h"
#include "map_ctrl_metrics_handler.h"
#include "map_ctrl_topology_tree.h"
#include "map_ctrl_cmdu_tx.h"
#include "map_ctrl_utils.h"
#include "map_ctrl_defines.h"
#include "map_ctrl_chan_sel.h"

#include "map_info.h"
#include "map_topology_tree.h"
#include "1905_platform.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define min(a,b) ((a) < (b) ? (a) : (b))

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/

static void remove_missing_radios(map_ale_info_t* ale, map_ap_operational_bss_tlv_t *tlv)
{
    map_radio_info_t *radio, *next;
    uint8_t           i;

    /* Remove those Radios that are not present in the AP Operational BSS tlv */
    map_dm_foreach_radio_safe(ale, radio, next) {
        /* Check if the radio is present in the TLV */
        for (i = 0; i < tlv->radios_nr; i++) {
            if (!maccmp(radio->radio_id, tlv->radios[i].radio_id)) {
                break;
            }
        }

        /* Remove radio if not found */
        if (i == tlv->radios_nr) {
            map_dm_remove_radio(radio);
            map_recompute_radio_state_and_update_ale_state(ale);
        }
    }
}

static void remove_missing_bsss(map_radio_info_t *radio, map_ap_operational_bss_tlv_radio_t *tlv_radio)
{
    map_bss_info_t *bss, *next;
    uint8_t         i;

    /* Remove those BSS that are not present in the AP Operational BSS tlv */
    map_dm_foreach_bss_safe(radio, bss, next) {
        /* Check if the BSS is present in the TLV */
        for (i = 0; i < tlv_radio->bsss_nr; i++) {
            if (!maccmp(bss->bssid, tlv_radio->bsss[i].bssid)) {
                break;
            }
        }

        /* Remove BSS if not found */
        if (i == tlv_radio->bsss_nr) {
            map_dm_remove_bss(bss);
        }
    }
}

/* TODO: use logic from map_get_airdata_profile_idx ? */
static bool get_bss_type(map_bss_info_t *bss, int *type)
{
    map_controller_cfg_t *cfg = get_controller_cfg();
    size_t                i;
    bool                  configured = false;

    for (i = 0; i < cfg->num_profiles; i++) {
        map_profile_cfg_t *profile  = &cfg->profiles[i];
        int                ssid_len = strlen(profile->bss_ssid);

        if (ssid_len == bss->ssid_len && !memcmp(profile->bss_ssid, bss->ssid, ssid_len)) {
            if ((profile->bss_state & MAP_FRONTHAUL_BSS) && (profile->bss_state & MAP_BACKHAUL_BSS)) {
                *type = MAP_FRONTHAUL_BSS | MAP_BACKHAUL_BSS;
                configured = true;
                break;
            } else if(profile->bss_state & MAP_FRONTHAUL_BSS) {
                *type = MAP_FRONTHAUL_BSS;
                configured = true;
                break;
            } else if(profile->bss_state & MAP_BACKHAUL_BSS){
                *type = MAP_BACKHAUL_BSS;
                configured = true;
                break;
            }
        }
    }

    return configured;
}

static int update_radio_bsss(map_radio_info_t *radio, map_ap_operational_bss_tlv_radio_t *tlv_radio)
{
    bool matching_bss_found = false;
    int  bss_type;
    uint8_t i;

    /* Validate and update the number of BSS on this radio */
    if (tlv_radio->bsss_nr > MAX_BSS_PER_RADIO) {
        /* TODO: this is too drastic... */
        log_ctrl_e("%s: too many bss[%d]", __FUNCTION__, tlv_radio->bsss_nr);
        return -1;
    }

    /* Remove missing BSS and its data from the list */
    remove_missing_bsss(radio, tlv_radio);

    /* Update the BSS info */
    for (i = 0 ; i < tlv_radio->bsss_nr; i++) {
        map_ap_operational_bss_tlv_bss_t *tlv_bss = &tlv_radio->bsss[i];
        map_bss_info_t                   *bss     = map_dm_get_bss(radio, tlv_bss->bssid);

        if (NULL == bss){
            bss = map_dm_create_bss(radio, tlv_bss->bssid);
            if (NULL == bss) {
                log_ctrl_e("%s: failed creating BSS node", __FUNCTION__);
                continue;
            }
        }

        /* get bss configured and type */
        bss_type = 0;
        matching_bss_found |= get_bss_type(bss, &bss_type);

        map_dm_bss_set_ssid(bss, tlv_bss->ssid_len, tlv_bss->ssid, bss_type);
    }

    /* Set the radio state to CONFIGURED on below case to handle controller re-boot after onboarding.
       => If at least one BSS is matching the configuration
       => If teardown sent to radio and no bss reported(as expected)
    */

    if (!is_radio_configured(radio->state)) {
        if((matching_bss_found) ||
           (tlv_radio->bsss_nr == 0 && is_radio_teardown_sent(radio->state))) {
            set_radio_state_configured(&radio->state);
            map_recompute_radio_state_and_update_ale_state(radio->ale);
        }
    }

    return 0;
}

static void update_radio_channel_from_iface(map_ale_info_t *ale, map_local_iface_t *iface)
{
    map_bss_info_t   *bss     = map_dm_get_bss_from_ale(ale, iface->mac_address);
    map_radio_info_t *radio;
    int               channel = iface->ieee80211_ap_channel_center_freq_1;
    uint8_t           current_op_class, supported_freq, center_channel;
    uint16_t          current_bw = 0, bw = 0;
    bool              is_center_channel = false;

    if (!bss || !(radio = bss->radio)) {
        return;
    }

    supported_freq   = radio->supported_freq;
    current_op_class = radio->current_op_class;

    /* Frequency band must be known */
    if (supported_freq == IEEE80211_FREQUENCY_BAND_UNKNOWN) {
        return;
    }

    /* Validate BW (80P80 not supported) */
    switch (iface->ieee80211_ap_channel_band) {
        case IEEE80211_AP_CHANNEL_BAND_20MHZ:  bw =  20; break;
        case IEEE80211_AP_CHANNEL_BAND_40MHZ:  bw =  40; break;
        case IEEE80211_AP_CHANNEL_BAND_80MHZ:  bw =  80; break;
        case IEEE80211_AP_CHANNEL_BAND_160MHZ: bw = 160; break;
        case IEEE80211_AP_CHANNEL_BAND_320MHZ: bw = 320; break;
        default:                                         return;
    }

    /* According to 1905.1 spec, ap_channel_center_freq_1 is the center channel but some
       agents (e.g BRCM) use the beacon channel

       -> Detect what is used.

          For 5G, 40/80/160 MHz, a channel number cannot be a valid beacon and center channel
          at the same time.  For 2G 40MHz that is possible... so we can't know.
          Also return if channel + bw combination does not have a valid op class

    */
    if (!map_is_ctl_channel(channel, supported_freq) || (map_is_2G_ctl_channel(channel) && bw == 40) || map_get_op_class(channel, bw, supported_freq) == 0) {
        return;
    }

    /* Get current bw and is_center_channel */
    if (current_op_class) {
        if (map_get_bw_from_op_class(current_op_class, &current_bw) ||
            map_get_is_center_channel_from_op_class(current_op_class, &is_center_channel)) {
            current_op_class = 0; /* Must be invalid */
            current_bw = 0;
        }
    }

    /* Update if something changed */
    if (radio->current_op_channel != channel || current_bw != bw) {
        /* Keep current op class if that is still ok.  This is to avoid toggling value when updated from operating
           channel report TLV.
        */
        if (current_op_class > 0) {
            if (current_bw != bw) {
                current_op_class = 0;
            } else {
                if (is_center_channel) {
                    if (map_get_center_channel(current_op_class, channel, &center_channel) ||
                        !map_is_channel_in_op_class(current_op_class, center_channel)) {
                        current_op_class = 0;
                    }
                } else {
                    if (!map_is_channel_in_op_class(current_op_class, channel)) {
                        current_op_class = 0;
                    }
                }
            }
        }

        /* Set op_class and channel in dm (keep current tx_pwr) */
        map_dm_radio_set_channel(radio,
                                 current_op_class > 0 ? current_op_class : map_get_op_class(channel, bw, supported_freq),
                                 channel, 0, bw, radio->current_tx_pwr);

        log_ctrl_i("updated channel/bw for radio[%s] op_class[%d] channel[%d] bw[%d] from %s",
                   mac_string(radio->radio_id), radio->current_op_class, radio->current_op_channel, bw,
                   i1905_tlv_type_to_string(TLV_TYPE_DEVICE_INFORMATION));
    }
}

static void update_i1905_interfaces(map_ale_info_t *ale)
{
    char    **interfaces;
    uint8_t   interfaces_nr, i, j;
    mac_addr  mac;

    if (!(interfaces = i1905_get_list_of_interfaces(&interfaces_nr))) {
        return;
    }

    for (i = 0; i < interfaces_nr; i++) {
        if (i1905_get_interface_mac(interfaces[i], mac) == 0) {
            /* Find MAC in local interfaces */
            for (j = 0; j < ale->local_iface_count; j++) {
                map_local_iface_t *iface = &ale->local_iface_list[j];

                if (!maccmp(iface->mac_address, mac)) {
                    /* Update info in i1905 layer */
                    i1905_set_interface_type(interfaces[i], iface->media_type);

                    if (INTERFACE_TYPE_GROUP_GET(iface->media_type) == INTERFACE_TYPE_GROUP_WLAN && iface->ieee80211_valid) {
                        i1905_set_interface_80211_media_specific_info(interfaces[i], iface->ieee80211_network_membership,
                                                                      iface->ieee80211_role, iface->ieee80211_ap_channel_band,
                                                                      iface->ieee80211_ap_channel_center_freq_1,
                                                                      iface->ieee80211_ap_channel_center_freq_2);
                    }
                }
            }
        }
    }

    i1905_free_list_of_interfaces(interfaces, interfaces_nr);
}

static int update_radio_op_classes(map_radio_info_t *radio, map_ap_radio_basic_cap_tlv_t *tlv)
{
    bool fill_disallowed = false;
    int i;

    if (radio->cap_op_class_list.op_classes) {
        free(radio->cap_op_class_list.op_classes);
    }

    if (!(radio->cap_op_class_list.op_classes = calloc(tlv->op_classes_nr, sizeof(map_op_class_t)))) {
        radio->cap_op_class_list.op_classes_nr = 0;
        return -1;
    }

    if (radio->disallowed_op_class_list.op_classes_nr == 0) {
        if (!(radio->disallowed_op_class_list.op_classes = calloc(tlv->op_classes_nr, sizeof(map_op_class_t)))) {
            radio->disallowed_op_class_list.op_classes_nr = 0;
            return -1;
        }

        radio->disallowed_op_class_list.op_classes_nr = tlv->op_classes_nr;
        fill_disallowed = true;
    }

    radio->cap_op_class_list.op_classes_nr = tlv->op_classes_nr;

    for (i = 0; i<tlv->op_classes_nr; i++) {
        map_op_class_t *op_class = &radio->cap_op_class_list.op_classes[i];

        op_class->op_class = tlv->op_classes[i].op_class;
        op_class->eirp     = tlv->op_classes[i].eirp;
        map_cs_copy(&op_class->channels, &tlv->op_classes[i].channels);

        if (fill_disallowed) {
            op_class = &radio->disallowed_op_class_list.op_classes[i];
            op_class->op_class = tlv->op_classes[i].op_class;
        }
    }

    /* Update allowed channels based on config and cap_op_class_list */
    map_update_radio_channels(radio);

    /* Update channel preference */
    map_ctrl_chan_sel_update(radio);

    return 0;
}

static map_sta_info_t *handle_sta_connect(map_bss_info_t *bss, mac_addr mac, uint16_t assoc_time)
{
    map_sta_info_t *sta;

    /* Currently a sta can only be linked to one BSS -> move if it already existed */
    if (!(sta = map_dm_get_sta_from_ale(bss->radio->ale, mac))) {
        if (!(sta = map_dm_create_sta(bss, mac))) {
            log_ctrl_e("failed creating sta[%s]", mac_string(mac));
            return NULL;
        }

        sta->assoc_ts = map_dm_get_sta_assoc_ts(assoc_time);

        /* If there is a BTM steering request for this station and
           there was no BTM response yet finalize the steering
        */
        map_dm_sta_steering_finalize(sta);

        map_dm_create_assoc(sta);
    } else {
        /* Check if current and old BSS is the same */
        if (sta->bss != bss) {
            log_ctrl_i("sta[%s] moved from bss[%s] to bss[%s]", sta->mac_str, sta->bss->bssid_str, bss->bssid_str);

            sta->assoc_ts = map_dm_get_sta_assoc_ts(assoc_time);
            map_dm_update_sta_bss(bss, sta);
        }
    }

    return sta;
}

static int compare_expired_scan_result(void* obj_old, void* obj_new)
{
    map_scan_result_t *scan_result_old = obj_old;
    map_scan_result_t *scan_result_new = obj_new;

    if (scan_result_old->channel == scan_result_new->channel &&
        scan_result_old->scan_cnt < scan_result_new->scan_cnt) {
        return 1;
    }
    return 0;
}

/*#######################################################################
#                       1905.1 TLV HANDLERS                             #
########################################################################*/
/* 1905.1 6.4.5 */
int map_parse_device_information_tlv(map_ale_info_t *ale, i1905_device_information_tlv_t *tlv)
{
    size_t i;

    /* Re-allocate if number of interfaces changed */
    if (tlv->local_interfaces_nr != ale->local_iface_count) {
        SFREE(ale->local_iface_list);
    }

    ale->local_iface_count = 0;

    if (tlv->local_interfaces_nr == 0) {
        return 0;
    }

    if (!ale->local_iface_list && !(ale->local_iface_list = calloc(tlv->local_interfaces_nr, sizeof(*ale->local_iface_list)))) {
        log_ctrl_e("%s: calloc failed", __FUNCTION__);
        return -1;
    }

    for (i = 0; i < tlv->local_interfaces_nr; i++) {
        i1905_local_interface_entry_t *tlv_iface = &tlv->local_interfaces[i];
        map_local_iface_t             *iface     = &ale->local_iface_list[i];

        memset(iface, 0, sizeof(map_local_iface_t));
        maccpy(iface->mac_address, tlv_iface->mac_address);
        iface->media_type = tlv_iface->media_type;

        /* Store some info from the media specific data */
        if (INTERFACE_TYPE_GROUP_WLAN == INTERFACE_TYPE_GROUP_GET(iface->media_type)) {
            if (tlv_iface->media_specific_data_size == sizeof(i1905_ieee80211_specific_information_t)) {
                iface->ieee80211_valid = true;

                maccpy(iface->ieee80211_network_membership, tlv_iface->media_specific_data.ieee80211.network_membership);

                iface->ieee80211_role                     = tlv_iface->media_specific_data.ieee80211.role;
                iface->ieee80211_ap_channel_band          = tlv_iface->media_specific_data.ieee80211.ap_channel_band;
                iface->ieee80211_ap_channel_center_freq_1 = tlv_iface->media_specific_data.ieee80211.ap_channel_center_frequency_index_1;
                iface->ieee80211_ap_channel_center_freq_2 = tlv_iface->media_specific_data.ieee80211.ap_channel_center_frequency_index_2;

                /* Try to update channel for AP interfaces */
                /* TODO: for BH_STA STA interface could be used as well */
                if (iface->ieee80211_role == IEEE80211_SPECIFIC_INFO_ROLE_AP) {
                    update_radio_channel_from_iface(ale, iface);
                }
            } else {
                /* Allowed if media type was INTERFACE_TYPE_IEEE_802_11AX or INTERFACE_TYPE_IEEE_802_11BE */
                if (!(iface->media_type == INTERFACE_TYPE_IEEE_802_11AX || iface->media_type == INTERFACE_TYPE_IEEE_802_11BE)) {
                    log_ctrl_e("dev info for ale[%s] has wlan interface with unexpected media_specific_data_size[%d]",
                               ale->al_mac_str, tlv_iface->media_specific_data_size);
                }
            }
        }
    }

    ale->local_iface_count = tlv->local_interfaces_nr;

    if (ale->is_local && ale->is_local_colocated) {
        /* Update our interfaces with data from colocated local agent */
        update_i1905_interfaces(ale);
    }

    return 0;
}

/* 1905.1 6.4.8 */
int map_parse_non_1905_neighbor_device_list_tlv(map_ale_info_t *ale, i1905_non_1905_neighbor_device_list_tlv_t **tlvs, size_t tlvs_nr)
{
    size_t i, j;

    /* Free old list */
    map_dm_free_non_1905_neighbor_list(ale);

    if (!(ale->non_1905_neighbor_list = calloc(tlvs_nr, sizeof(*ale->non_1905_neighbor_list)))) {
        log_ctrl_e("%s: calloc failed", __FUNCTION__);
        return -1;
    }

    ale->non_1905_neighbor_count = tlvs_nr;

    for (i = 0; i < tlvs_nr; i++) {
        i1905_non_1905_neighbor_device_list_tlv_t *tlv   = tlvs[i];
        map_non_1905_neighbor_t                   *n     = &ale->non_1905_neighbor_list[i];
        map_local_iface_t                         *iface = map_find_local_iface(ale, tlv->local_mac_address);

        maccpy(n->local_iface_mac, tlv->local_mac_address);
        n->media_type = iface ? iface->media_type : INTERFACE_TYPE_UNKNOWN;

        if (tlv->non_1905_neighbors_nr == 0) {
            continue;
        }

        if (!(n->macs = malloc(tlv->non_1905_neighbors_nr * sizeof(*n->macs)))) {
            log_ctrl_e("%s: malloc failed", __FUNCTION__);
            return -1;
        }

        n->macs_nr = tlv->non_1905_neighbors_nr;

        for (j = 0; j < n->macs_nr; j++) {
            maccpy(n->macs[j], tlv->non_1905_neighbors[j].mac_address);
        }

        /* Sort list */
        acu_sort_mac_array(n->macs, n->macs_nr);
    }

    return 0;
}

/* 1905.1 6.4.9 */
int map_parse_neighbor_device_list_tlv(map_ale_info_t *ale, i1905_neighbor_device_list_tlv_t **tlvs, size_t tlvs_nr)
{
    /* Do not process neighbors from local agent when that is connected via loopback as in that case
       we will see them directly via the other interfaces.

       Local agent is not connected via loopback in case when controller runs on PC or in a container.
    */
    if (tlvs_nr > 0 && !(map_is_local_agent(ale) && map_is_loopback_iface(ale->iface_name))) {
        map_build_topology_tree(ale, tlvs, tlvs_nr);
    }

    return 0;
}

/*#######################################################################
#                       MAP R1 TLV HANDLERS                             #
########################################################################*/

/* MAP_R1 17.2.1 */
int map_parse_ap_supported_service_tlv(UNUSED map_ale_info_t *ale, map_supported_service_tlv_t* tlv,
                                                bool *is_controller, bool *is_agent, bool *is_em_plus)
{
    uint8_t i;

    if (is_controller) {
        *is_controller = false;
    }
    if (is_agent) {
        *is_agent = false;
    }
    if (is_em_plus) {
        *is_em_plus = false;
    }

    if (tlv == NULL) {
        return -1;
    }

    for (i = 0; i < tlv->services_nr; i++) {
        if (tlv->services[i] == MAP_SERVICE_CONTROLLER) {
            if (is_controller) {
                *is_controller = true;
            }
        }
        if (tlv->services[i] == MAP_SERVICE_AGENT) {
            if (is_agent) {
                *is_agent = true;
            }
        }
        if (tlv->services[i] == MAP_SERVICE_EMEX_CONTROLLER || tlv->services[i] == MAP_SERVICE_EMEX_AGENT) {
            if (is_em_plus) {
                *is_em_plus = true;
            }
        }
    }

    return 0;

}

/* MAP_R1 17.2.4 */
int map_parse_ap_operational_bss_tlv(map_ale_info_t *ale, map_ap_operational_bss_tlv_t* tlv)
{
    bool              do_ap_cap_query     = false;
    bool              do_policy_config    = false;
    bool              do_bhsta_cap_query  = false;
    map_radio_info_t *radio;
    map_radio_info_t *policy_config_radio = NULL;
    timer_id_t        timer_id;
    size_t            i;

    /* Mark as easymesh device */
    ale->easymesh = true;

    /* Remove missing radio and its data from the radio list */
    remove_missing_radios(ale, tlv);

    for (i = 0; i < tlv->radios_nr; i++) {
        map_ap_operational_bss_tlv_radio_t *tlv_radio = &tlv->radios[i];

        if (!(radio = map_dm_get_radio(ale, tlv_radio->radio_id))) {
            if (!(radio = map_handle_new_radio_onboarding(ale, tlv_radio->radio_id, false))) {
                log_ctrl_e("%s: radio[%s] onboarding failed", __FUNCTION__, mac_string(tlv_radio->radio_id));
                continue;
            }
            do_ap_cap_query = true;
        }

        /* Check if any actions need to be performened */
        if (is_radio_M1_received(radio->state) && !is_radio_policy_config_ack_received(radio->state)) {
            do_policy_config = true;
            policy_config_radio = radio;
        }

        if (!is_radio_ap_cap_report_received(radio->state)) {
            do_ap_cap_query = true;
        }

        /* Update BSSs */
        if (update_radio_bsss(radio, tlv_radio)) {
            log_ctrl_e("failed to update bsss of radio[%s]", mac_string(radio->radio_id));
        }
    }

    if (!is_ale_bhsta_cap_report_received(ale->state) && ale->map_profile >= MAP_PROFILE_2) {
        do_bhsta_cap_query = true;
    }

    /* Perform any required actions */
    if (do_policy_config) {
        map_dm_get_radio_timer_id(timer_id, policy_config_radio, POLICY_CONFIG_RETRY_ID);
        if (!map_is_timer_registered(timer_id)) {
            if (map_register_retry(timer_id, 10, 10, ale, map_handle_policy_config_sent, map_build_and_send_policy_config)) {
                log_ctrl_e("%s: failed Registering retry timer[%s]", __FUNCTION__, timer_id);
            }
        }
    }

    /* Send AP Capability query in retry timer until we get a response */
    if (do_ap_cap_query) {
        map_dm_get_ale_timer_id(timer_id, ale, AP_CAPS_QUERY_RETRY_ID);
        if (!map_is_timer_registered(timer_id)) {
            if (map_register_retry(timer_id, 10, 10, ale, NULL, map_send_ap_capability_query)) {
                log_ctrl_e("%s: failed Registering retry timer[%s]", __FUNCTION__, timer_id);
            }
        }
    }

    /* Send Backhaul Sta Capability query */
    if (do_bhsta_cap_query) {
        map_dm_get_ale_timer_id(timer_id, ale, BHSTA_CAP_QUERY_RETRY_ID);
        if (!map_is_timer_registered(timer_id)) {
            if (map_register_retry(timer_id, 10, 10, ale, NULL, map_send_backhaul_sta_capability_query)) {
                log_ctrl_e("%s: failed Registering retry timer[%s]", __FUNCTION__, timer_id);
            }
        }
    }

    /* Channel selection:
       - only when all M1 are received as several agents report an error otherwise and request needs to be retried
       - if preference query not recevied for at least one radio -> do query + selection on all radio
       - otherwise do selection on all radios for which we did not get an oper channel report.
         NOTE: As the oper channel report can come with a delay, don't do this too fast
    */
    if (map_is_channel_selection_enabled() && ale->radios_nr > 0 && map_is_all_radio_M1_received(ale)) {
        uint64_t last_chan_sel_req  = acu_timestamp_delta_sec(ale->last_chan_sel_req_time); /* Should be per radio */
        bool     do_chan_pref_query = false;

        map_dm_foreach_radio(ale, radio) {
            if (!is_radio_channel_preference_query_sent(radio->state) || !is_radio_state_channel_pref_report_received(radio->state)) {
                /* Set query_sent state for all radios */
                set_radio_state_channel_preference_query_sent(&radio->state);
                do_chan_pref_query = true;

                /* No break... */
            }
        }

        if (do_chan_pref_query) {
            map_agent_handle_channel_selection(ale, NULL, MAP_CHAN_SEL_QUERY);
        } else if (ale->first_chan_sel_req_done && last_chan_sel_req > MAP_CHAN_SEL_BACKOFF_TIME) {
            map_dm_foreach_radio(ale, radio) {
                if (!is_radio_operating_chan_report_received(radio->state)) {
                    log_ctrl_w("current oper class/channel for radio[%s] not known - do new channel selection request", radio->radio_id_str);
                    map_agent_handle_channel_selection(ale, radio, MAP_CHAN_SEL_REQUEST);
                }
            }
        }
    }

    return 0;
}

/* MAP_R1 17.2.5 */
int map_parse_assoc_clients_tlv(map_ale_info_t *ale, map_assoc_clients_tlv_t* tlv)
{
    size_t i, j;

    /* For MLO:
       - tlv->bssid can be a regular BSSID or an AP MLD MAC
       - tlv->sta_mac can be a regular MAC or an STA MLD MAC

       At this point, MLD stations should already have been added in the DM so we need
       to ignore those.
    */

    for (i = 0; i < tlv->bsss_nr; i++) {
        map_assoc_clients_tlv_bss_t *tlv_bss = &tlv->bsss[i];
        map_bss_info_t              *bss;

        if (!(bss = map_dm_get_bss_from_ale(ale, tlv_bss->bssid))) {
            /* Only print error when this is no ap_mld either */
            if (map_dm_ale_has_mld(ale)) {
                if (map_dm_get_ap_mld(ale, tlv_bss->bssid)) {
                    continue;
                }
            }

            log_ctrl_e("%s: unknown bss[%s]", __FUNCTION__, mac_string(tlv_bss->bssid));
            continue;
        }

        for (j = 0; j < tlv_bss->stas_nr; j++) {
            map_assoc_clients_tlv_sta_t *tlv_sta = &tlv_bss->stas[j];
            map_sta_info_t              *sta;

            if (map_dm_ale_has_mld(ale)) {
                if (map_dm_get_sta_mld_from_ale(ale, tlv_sta->mac)) {
                    continue;
                }
            }

            if ((sta = handle_sta_connect(bss, tlv_sta->mac, tlv_sta->assoc_time))) {
                /* Unmark so sta is not removed */
                map_dm_unmark_sta(sta);
            }
        }
    }

    return 0;
}

/* MAP_R1 17.2.6 */
int map_parse_ap_cap_tlv(map_ale_info_t *ale, map_ap_cap_tlv_t* tlv)
{
    ale->agent_capability.ib_unassociated_sta_link_metrics_supported  = tlv->operating_unsupported_link_metrics;
    ale->agent_capability.oob_unassociated_sta_link_metrics_supported = tlv->non_operating_unsupported_link_metrics;
    ale->agent_capability.rssi_agent_steering_supported               = tlv->agent_initiated_steering;

    return 0;
}

/* MAP_R1 17.2.7 */
int map_parse_ap_radio_basic_cap_tlv(map_ale_info_t *ale, map_ap_radio_basic_cap_tlv_t* tlv)
{
    map_radio_info_t *radio;
    uint8_t           radio_freq_type = NUM_FREQ_BANDS;
    uint16_t          band_type_5G   = 0;
    int               i;

    /* Mark as easymesh device */
    ale->easymesh = true;

    if (!(radio = map_dm_get_radio(ale, tlv->radio_id))) {
        log_ctrl_e("%s: radio[%s] not found", __FUNCTION__, mac_string(tlv->radio_id));
        return -1;
    }

    /* Get the frequency type from the operating class list */
    for (i = 0; i < tlv->op_classes_nr; i++) {
        map_get_frequency_type(tlv->op_classes[i].op_class,
                               &tlv->op_classes[i].channels,
                               &radio_freq_type, &band_type_5G);
    }

    if (radio_freq_type == NUM_FREQ_BANDS) {
        log_ctrl_e("%s: failed to get frequency band for radio[%s]", __FUNCTION__, tlv->radio_id);
        return -1;
    }

    if (tlv->max_bss == 0) {
        log_ctrl_e("%s: max_bss is zero for radio[%s]", __FUNCTION__, tlv->radio_id);
        return -1;
    }

    radio->supported_freq = radio_freq_type;
    radio->band_type_5G   = band_type_5G;
    radio->max_bss        = tlv->max_bss;

    return update_radio_op_classes(radio, tlv);
}

/* MAP_R1 17.2.8 */
int map_parse_ap_ht_caps_tlv(map_ale_info_t *ale, map_ap_ht_cap_tlv_t *tlv)
{
    map_radio_info_t *radio = map_dm_get_radio(ale, tlv->radio_id);

    if (!radio) {
        log_ctrl_e("%s: radio[%s] not found", __FUNCTION__, mac_string(tlv->radio_id));
        return -1;
    }

    if (!radio->ht_caps && !(radio->ht_caps = calloc(1, sizeof(*radio->ht_caps)))) {
        log_ctrl_e("%s: calloc failed", __FUNCTION__);
        return -1;
    }

    radio->ht_caps->max_supported_tx_streams = tlv->max_supported_tx_streams + 1;
    radio->ht_caps->max_supported_rx_streams = tlv->max_supported_rx_streams + 1;
    radio->ht_caps->gi_support_20mhz         = tlv->gi_support_20mhz;
    radio->ht_caps->gi_support_40mhz         = tlv->gi_support_40mhz;
    radio->ht_caps->ht_support_40mhz         = tlv->ht_support_40mhz;

    return 0;
}

/* MAP_R1 17.2.9 */
int map_parse_ap_vht_caps_tlv(map_ale_info_t *ale, map_ap_vht_cap_tlv_t* tlv)
{
    map_radio_info_t *radio = map_dm_get_radio(ale, tlv->radio_id);

    if (!radio) {
        log_ctrl_e("%s: radio[%s] not found", __FUNCTION__, mac_string(tlv->radio_id));
        return -1;
    }

    if (!radio->vht_caps && !(radio->vht_caps = calloc(1, sizeof(*radio->vht_caps)))) {
        log_ctrl_e("%s: calloc failed", __FUNCTION__);
        return -1;
    }

    radio->vht_caps->supported_tx_mcs         = tlv->supported_tx_mcs;
    radio->vht_caps->supported_rx_mcs         = tlv->supported_rx_mcs;
    radio->vht_caps->max_supported_tx_streams = tlv->max_supported_tx_streams + 1;
    radio->vht_caps->max_supported_rx_streams = tlv->max_supported_rx_streams + 1;
    radio->vht_caps->gi_support_80mhz         = tlv->gi_support_80mhz;
    radio->vht_caps->gi_support_160mhz        = tlv->gi_support_160mhz;
    radio->vht_caps->support_80_80_mhz        = tlv->support_80_80_mhz;
    radio->vht_caps->support_160mhz           = tlv->support_160mhz;
    radio->vht_caps->su_beamformer_capable    = tlv->su_beamformer_capable;
    radio->vht_caps->mu_beamformer_capable    = tlv->mu_beamformer_capable;

    return 0;
}

/* MAP_R1 17.2.10 */
int map_parse_ap_he_caps_tlv(map_ale_info_t *ale, map_ap_he_cap_tlv_t *tlv)
{
    map_radio_info_t *radio = map_dm_get_radio(ale, tlv->radio_id);

    if (!radio) {
        log_ctrl_e("%s: radio[%s] not found", __FUNCTION__, mac_string(tlv->radio_id));
        return -1;
    }

    if (tlv->supported_mcs_length > MAX_MCS * sizeof(uint16_t)){
        log_ctrl_e("invalid supported MCS length[%d] for radio[%s]", tlv->supported_mcs_length, mac_string(tlv->radio_id));
        return -1;
    }

    if (!radio->he_caps && !(radio->he_caps = calloc(1, sizeof(*radio->he_caps)))) {
        log_ctrl_e("%s: calloc failed", __FUNCTION__);
        return -1;
    }

    memcpy(radio->he_caps->supported_tx_rx_mcs, tlv->supported_tx_rx_mcs, tlv->supported_mcs_length);
    radio->he_caps->supported_mcs_length     = tlv->supported_mcs_length;
    radio->he_caps->max_supported_tx_streams = tlv->max_supported_tx_streams + 1;
    radio->he_caps->max_supported_rx_streams = tlv->max_supported_rx_streams + 1;
    radio->he_caps->support_80_80_mhz        = tlv->support_80_80_mhz;
    radio->he_caps->support_160mhz           = tlv->support_160mhz;
    radio->he_caps->su_beamformer_capable    = tlv->su_beamformer_capable;
    radio->he_caps->mu_beamformer_capable    = tlv->mu_beamformer_capable;
    radio->he_caps->ul_mimo_capable          = tlv->ul_mimo_capable;
    radio->he_caps->ul_mimo_ofdma_capable    = tlv->ul_mimo_ofdma_capable;
    radio->he_caps->dl_mimo_ofdma_capable    = tlv->dl_mimo_ofdma_capable;
    radio->he_caps->ul_ofdma_capable         = tlv->ul_ofdma_capable;
    radio->he_caps->dl_ofdma_capable         = tlv->dl_ofdma_capable;

    return 0;
}

/* MAP_R1 17.2.12 */
int map_parse_ap_metrics_tlv(map_ale_info_t *ale, map_ap_metrics_tlv_t* tlv)
{
    map_bss_info_t *bss = map_dm_get_bss_from_ale(ale, tlv->bssid);
    uint8_t         ac_index;

    if (!bss) {
        log_ctrl_d("%s: bss[%s] not found", __FUNCTION__, mac_string(tlv->bssid));
        return -1;
    }

    bss->metrics.valid               = true;
    bss->metrics.channel_utilization = tlv->channel_util;
    bss->metrics.stas_nr             = tlv->stas_nr;
    bss->metrics.esp_present         = tlv->esp_present;

    for (ac_index = 0; ac_index < MAX_ACCESS_CATEGORY; ac_index++) {
        if (bss->metrics.esp_present & (1 << (7 - ac_index))) {
            memcpy(bss->metrics.esp[ac_index].byte_stream, tlv->esp[ac_index].byte_stream, 3);
        }
    }
    return 0;
}

/* MAP_R2 17.2.13 */
int map_parse_channel_preference_tlv(map_ale_info_t *ale, map_channel_preference_tlv_t *tlv)
{
    map_radio_info_t *radio = map_dm_get_radio(ale, tlv->radio_id);
    int               i;

    if (!radio) {
        log_ctrl_e("%s: radio[%s] not found", __FUNCTION__, mac_string(tlv->radio_id));
        return -1;
    }

    /* Remove old list */
    SFREE(radio->pref_op_class_list.op_classes);
    radio->pref_op_class_list.op_classes_nr = 0;

    if (tlv->op_classes_nr == 0) {
        return 0;
    }

    if (!(radio->pref_op_class_list.op_classes = calloc(tlv->op_classes_nr, sizeof(*radio->pref_op_class_list.op_classes)))) {
        log_ctrl_e("%s: calloc failed", __FUNCTION__);
        return -1;
    }

    for (i = 0; i < tlv->op_classes_nr; i++) {
        map_channel_preference_tlv_op_class_t *tlv_op_class = &tlv->op_classes[i];
        map_op_class_t                        *op_class     = &radio->pref_op_class_list.op_classes[i];

        op_class->op_class = tlv_op_class->op_class;
        op_class->pref     = tlv_op_class->pref;
        op_class->reason   = tlv_op_class->reason;
        map_cs_copy(&op_class->channels, &tlv_op_class->channels);
    }

    radio->pref_op_class_list.op_classes_nr = tlv->op_classes_nr;

    return 0;
}

/* MAP_R2 17.2.14 */
int map_parse_radio_operation_restriction_tlv(map_ale_info_t *ale, map_radio_operation_restriction_tlv_t *tlv)
{
    map_radio_info_t *radio = map_dm_get_radio(ale, tlv->radio_id);
    uint8_t           i, j;

    if (!radio) {
        log_ctrl_e("%s: radio[%s] not found", __FUNCTION__, mac_string(tlv->radio_id));
        return -1;
    }

    /* Remove old list */
    map_dm_free_op_restriction_list(radio);

    if (tlv->op_classes_nr == 0) {
        return 0;
    }

    if (!(radio->op_restriction_list.op_classes = calloc(tlv->op_classes_nr, sizeof(*radio->op_restriction_list.op_classes)))) {
        log_ctrl_e("%s: calloc failed", __FUNCTION__);
        return -1;
    }

    radio->op_restriction_list.op_classes_nr = tlv->op_classes_nr;

    for (i = 0; i < tlv->op_classes_nr; i++) {
        map_radio_operation_restriction_tlv_op_class_t *tlv_op_class = &tlv->op_classes[i];
        map_op_restriction_t                           *op_class     = &radio->op_restriction_list.op_classes[i];

        op_class->op_class = tlv_op_class->op_class;
        op_class->channels_nr = 0;

        if (tlv_op_class->channels_nr > 0) {
            if (!(op_class->channels = calloc(tlv_op_class->channels_nr, sizeof(*op_class->channels)))) {
                map_dm_free_op_restriction_list(radio);
                return -1;
            }

            op_class->channels_nr = tlv_op_class->channels_nr;

            for (j = 0; j < op_class->channels_nr; j++) {
                op_class->channels[j].channel          = tlv_op_class->channels[j].channel;
                op_class->channels[j].freq_restriction = tlv_op_class->channels[j].freq_restriction;
            }
        }
    }

    return 0;
}

/* MAP_R1 17.2.20 */
int map_parse_client_assoc_event_tlv(map_ale_info_t *ale, map_client_assoc_event_tlv_t *tlv)
{
    /* tlv->bssid can be both ap_mld and bss */
    map_ap_mld_info_t  *ap_mld = map_dm_ale_has_mld(ale) ? map_dm_get_ap_mld(ale, tlv->bssid) : NULL;
    map_bss_info_t     *bss    = map_dm_get_bss_from_ale(ale, tlv->bssid);
    map_sta_mld_info_t *sta_mld;
    map_sta_info_t     *sta;

    if (!ap_mld && !bss) {
        log_ctrl_e("%s: unknown bss[%s]", __FUNCTION__, mac_string(tlv->bssid));
        return -1;
    }

    /* Handle connect/disconnect seperatly */
    if (tlv->association_event == MAP_CLIENT_ASSOC_EVENT_CONNECTED) {
        /* For MLO:
           - tlv->bssid can be a regular BSSID or an AP MLD MAC
           - tlv->sta_mac can be a regular MAC or an STA MLD MAC

           Because the BSSID and the AP MLD MAC can be the same at this point we cannot
           know if this is a regular or MLD station

           -> wait for topology response to resolve
        */

        if (ap_mld) {
            /* Regular or MLD STA -> need more information */
            map_send_topology_query(ale, MID_NA);
            /* map_dm_sta_steering_finalize(sta); TODO:??? */
            /* map_dm_create_assoc(sta); TODO:??? */
        } else if (bss) {
            handle_sta_connect(bss, tlv->sta_mac, 0);
        }
    } else {
        if (ap_mld && (sta_mld = map_dm_get_sta_mld(ap_mld, tlv->sta_mac))) {
            map_dm_remove_sta_mld(sta_mld);
        } else if (bss && (sta = map_dm_get_sta(bss, tlv->sta_mac))) {
            map_dm_create_disassoc(sta);
            map_dm_remove_sta(sta);
        }
    }

    return 0;
}

/* MAP_R1 17.2.24 */
int map_parse_assoc_sta_link_metrics_tlv(map_ale_info_t *ale, map_assoc_sta_link_metrics_tlv_t* tlv)
{
    map_sta_info_t         *sta = map_dm_get_sta_from_ale(ale, tlv->sta_mac);
    map_sta_link_metrics_t *link_metrics;
    int                     i;

    if (sta == NULL || sta->bss == NULL) {
        log_ctrl_e("%s: sta[%s] not found or bss NULL", __FUNCTION__, mac_string(tlv->sta_mac));
        return -1;
    }

    for (i = 0; i < tlv->bsss_nr; i++) {
        map_assoc_sta_link_metrics_tlv_bss_t *tlv_bss = &tlv->bsss[i];

        if (!maccmp( sta->bss->bssid, tlv_bss->bssid)) {
            if ((link_metrics = calloc(1, sizeof(map_sta_link_metrics_t)))) {
                /* Update the metrics data */
                link_metrics->age             = tlv_bss->report_time_interval;
                link_metrics->dl_mac_datarate = tlv_bss->downlink_data_rate;
                link_metrics->ul_mac_datarate = tlv_bss->uplink_data_rate;
                link_metrics->rssi            = RCPI_TO_RSSI(tlv_bss->uplink_rcpi);
                map_update_assoc_sta_link_metrics(sta, link_metrics);
            }
        } else {
            /* TODO What should be done here? */
            mac_addr_str mac_str, bssid_str, tlv_bssid_str;

            log_ctrl_e("%s: STA[%s] associated to BSS[%s] received metrics for other BSS[%s]",
                       __FUNCTION__, mac_to_string(sta->mac, mac_str), mac_to_string(sta->bss->bssid, bssid_str),
                       mac_to_string(tlv_bss->bssid, tlv_bssid_str));
        }
    }

    return 0;
}

/* MAP_R1 17.2.35 */
int map_parse_assoc_sta_traffic_stats_tlv(map_ale_info_t *ale, map_assoc_sta_traffic_stats_tlv_t* tlv)
{
    map_sta_mld_info_t      *sta_mld;
    map_sta_info_t          *sta;
    map_sta_traffic_stats_t *traffic_stats;
    uint8_t                  byte_counter_unit = ale->map_profile >= MAP_PROFILE_2 ?
                                                 ale->agent_capability.byte_counter_unit : MAP_BYTE_COUNTER_UNIT_BYTES;
    uint64_t                 tx_bytes          = map_convert_mapunits_to_bytes(tlv->tx_bytes, byte_counter_unit);
    uint64_t                 rx_bytes          = map_convert_mapunits_to_bytes(tlv->rx_bytes, byte_counter_unit);

    /* tlv->sta_mac can be a STA_MLD or a STA */
    if (map_dm_ale_has_mld(ale) && (sta_mld = map_dm_get_sta_mld_from_ale(ale, tlv->sta_mac))) {
        traffic_stats = &sta_mld->traffic_stats;
    } else if ((sta = map_dm_get_sta_from_ale(ale, tlv->sta_mac))) {
        traffic_stats = &sta->traffic_stats;
    } else {
        log_ctrl_e("%s: sta[%s] not found", __FUNCTION__, mac_string(tlv->sta_mac));
        return -1;
    }

    traffic_stats->tx_bytes         = tx_bytes;
    traffic_stats->rx_bytes         = rx_bytes;
    traffic_stats->tx_packets       = tlv->tx_packets;
    traffic_stats->rx_packets       = tlv->rx_packets;
    traffic_stats->tx_packet_errors = tlv->tx_packet_errors;
    traffic_stats->rx_packet_errors = tlv->rx_packet_errors;
    traffic_stats->retransmissions  = tlv->retransmissions;

    return 0;
}

/*#######################################################################
#                       MAP R2 TLV HANDLERS                             #
########################################################################*/
/* MAP_R2 17.2.36 */
int map_parse_channel_scan_cap_tlv(map_ale_info_t *ale, map_channel_scan_cap_tlv_t* tlv)
{
    size_t i, j;

    log_ctrl_d( "SCAN CAPABILITIES:");
    log_ctrl_d("*****************************");

    for (i = 0; i < tlv->radios_nr; i++) {
        map_channel_scan_cap_tlv_radio_t *tlv_radio = &tlv->radios[i];
        map_radio_info_t                 *radio     = map_dm_get_radio(ale, tlv_radio->radio_id);

        if (!radio) {
            log_ctrl_e("%s: radio[%s] not found", __FUNCTION__, mac_string(tlv_radio->radio_id));
            return -1;
        }

        radio->scan_caps.valid                       = true;
        radio->scan_caps.boot_only                   = tlv->radios[i].boot_only;
        radio->scan_caps.scan_impact                 = tlv->radios[i].scan_impact;
        radio->scan_caps.min_scan_interval           = tlv->radios[i].min_scan_interval;
        radio->scan_caps.op_class_list.op_classes_nr = tlv->radios[i].op_classes_nr;

        free(radio->scan_caps.op_class_list.op_classes);

        if (!(radio->scan_caps.op_class_list.op_classes = calloc(radio->scan_caps.op_class_list.op_classes_nr, sizeof(map_op_class_t)))) {
            log_ctrl_e("%s: calloc failed", __FUNCTION__);
            return -1;
        }

        for (j = 0; j < radio->scan_caps.op_class_list.op_classes_nr; j++) {
            map_op_class_t *op_class = &radio->scan_caps.op_class_list.op_classes[j];

            op_class->op_class = tlv->radios[i].op_classes[j].op_class;
            map_cs_copy(&op_class->channels, &tlv->radios[i].op_classes[j].channels);
        }

        log_ctrl_d("Radio[%s]",              mac_string(radio->radio_id));
        log_ctrl_d("  boot_only:%d",         radio->scan_caps.boot_only);
        log_ctrl_d("  scan_impact:%d",       radio->scan_caps.scan_impact);
        log_ctrl_d("  min_scan_interval:%d", radio->scan_caps.min_scan_interval);
        log_ctrl_d("  op_class_count:%d",    radio->scan_caps.op_class_list.op_classes_nr);

        for (j = 0; j < radio->scan_caps.op_class_list.op_classes_nr; j++) {
            map_op_class_t *op_class = &radio->scan_caps.op_class_list.op_classes[j];
            char buf[MAP_CS_BUF_LEN];

            log_ctrl_t("  op_class:%d",        op_class->op_class);
            log_ctrl_t("    channel_count:%d", map_cs_nr(&op_class->channels));
            log_ctrl_t("    channel_list:%s",  map_cs_nr(&op_class->channels) > 0 ? map_cs_to_string(&op_class->channels, ' ', buf, sizeof(buf)) : "all");
        }
        log_ctrl_d("*****************************");
    }

    return 0;
}

/* MAP_R2 17.2.40 */
int map_parse_channel_scan_result_tlv(map_ale_info_t *ale, map_channel_scan_result_tlv_t* tlv, int last_scan_cnt)
{
    map_radio_info_t   *radio;
    map_scan_result_t   cmp_scan_result = {.channel = tlv->channel, .scan_cnt = last_scan_cnt};
    map_scan_result_t  *expired_scan_result;
    int                 i;

    if (!(radio = map_dm_get_radio(ale, tlv->radio_id))) {
        log_ctrl_e("%s: radio[%s] not found", __FUNCTION__, mac_string(tlv->radio_id));
        return -1;
    }

    /* Remove old scan results */
    do {
        expired_scan_result = find_remove_object(radio->scanned_bssid_list, &cmp_scan_result, compare_expired_scan_result);
        free(expired_scan_result);
    } while(expired_scan_result);

    log_ctrl_d("<---- Channel Scan Result TLV");
    log_ctrl_d("Radio: %s",       mac_string(tlv->radio_id));
    log_ctrl_d("opclass: %u",     tlv->op_class);
    log_ctrl_d("channel: %u",     tlv->channel);
    log_ctrl_d("scan status: %s", map_scan_status_to_string(tlv->scan_status));

    if (tlv->scan_status != MAP_SCAN_STATUS_SUCCESS) {
        return 0; /* No parsing error */
    }

    log_ctrl_d("timestamp length: %u",           tlv->timestamp_len);
    log_ctrl_d("timestamp: %s",                  tlv->timestamp);
    log_ctrl_d("utilization: %u",                tlv->utilization);
    log_ctrl_d("noise: %u",                      tlv->noise);
    log_ctrl_d("aggregate_scan_duration: %u ms", tlv->aggregate_scan_duration);
    log_ctrl_d("scan_type: %s",                  map_scan_type_to_string(tlv->scan_type));
    log_ctrl_d("no. of neighbors: %u",           tlv->neighbors_nr);

    for (i = 0; i < tlv->neighbors_nr; i++) {
        map_channel_scan_neighbor_t *nb = &tlv->neighbors[i];
        map_scan_result_t           *scan_result;

        log_ctrl_t("Neighbor [%d]:",              i);
        log_ctrl_t("\tbssid: %s",                 mac_string(nb->bssid));
        log_ctrl_t("\tssid len: %u",              nb->ssid_len);
        log_ctrl_t("\tssid: %s",                  nb->ssid);
        log_ctrl_t("\trssi: %d dBm",              RCPI_TO_RSSI(nb->rcpi));
        log_ctrl_t("\tch_bw_len: %u",             nb->ch_bw_len);
        log_ctrl_t("\tch_bw: %s MHz",             nb->ch_bw);
        log_ctrl_t("\tbss_load_elem_present: %u", nb->bss_load_elem_present);
        if (nb->bss_load_elem_present == 1) {
            log_ctrl_t("\tchannel_utilization: %u", nb->channel_utilization);
            log_ctrl_t("\tsta_count: %u",           nb->stas_nr);
        }

        if (!(scan_result = calloc(1, sizeof(*scan_result)))) {
            log_ctrl_e("%s: calloc failed", __FUNCTION__);
            return -1;
        }

        scan_result->scan_cnt = last_scan_cnt;
        scan_result->opclass  = tlv->op_class;
        scan_result->channel  = tlv->channel;
        scan_result->ts_len   = tlv->timestamp_len;
        memcpy(scan_result->channel_scan_ts, tlv->timestamp, tlv->timestamp_len);

        maccpy(scan_result->neighbor_info.bssid, nb->bssid);
        scan_result->neighbor_info.ssid_len  = min(nb->ssid_len, (MAX_SSID_LEN - 1));
        memcpy(scan_result->neighbor_info.ssid, nb->ssid, scan_result->neighbor_info.ssid_len);
        scan_result->neighbor_info.rcpi      = nb->rcpi;
        scan_result->neighbor_info.ch_bw_len = nb->ch_bw_len;
        memcpy(scan_result->neighbor_info.ch_bw, nb->ch_bw, nb->ch_bw_len);
        scan_result->neighbor_info.bss_load_elem_present = nb->bss_load_elem_present;
        scan_result->neighbor_info.channel_utilization   = nb->channel_utilization;
        scan_result->neighbor_info.stas_nr               = nb->stas_nr;

        /* add new scan info to the list */
        if (push_object(radio->scanned_bssid_list, scan_result)) {
            log_ctrl_e("%s: failed to push scan info obj to the list", __FUNCTION__);
            free(scan_result);
            return -1;
        }
    }

    return 0;
}

/* MAP_R2 17.2.41 */
int map_parse_timestamp_tlv(UNUSED map_ale_info_t *ale, map_timestamp_tlv_t* tlv)
{
    log_ctrl_t("Timestamp: %s", tlv->timestamp);
    return 0;
}

/* MAP_R2 17.2.44 */
int map_parse_cac_completion_report_tlv(map_ale_info_t* ale, map_cac_completion_report_tlv_t* tlv)
{
    int i, j;

    if (tlv->radios_nr == 0) {
        /* agent sends empty CAC completion report when CAC req is sent */
        /* do not remove valid CAC completion report for invalid one */
        return -1;
    }

    log_ctrl_d("<---- CAC Completion Report TLV");
    log_ctrl_d("radios_nr: %u", tlv->radios_nr);

    for (i = 0; i < tlv->radios_nr; i++) {
        map_cac_completion_report_tlv_radio_t *tlv_radio = &tlv->radios[i];
        map_radio_info_t                      *radio     = map_dm_get_radio(ale, tlv_radio->radio_id);
        map_cac_detected_pair_t               *cac_pair  = NULL;

        if (!radio) {
            log_ctrl_e("%s: radio[%s] not found", __FUNCTION__, mac_string(tlv_radio->radio_id));
            continue;
        }

        radio->cac_completion_info.op_class          = tlv_radio->op_class;
        radio->cac_completion_info.channel           = tlv_radio->channel;
        radio->cac_completion_info.status            = tlv_radio->status;

        log_ctrl_d("radio: %s",                 mac_string(tlv_radio->radio_id));
        log_ctrl_d("opclass: %u",               tlv_radio->op_class);
        log_ctrl_d("channel: %u",               tlv_radio->channel);
        log_ctrl_d("cac_completion_status: %u", tlv_radio->status);
        log_ctrl_d("detected_pairs_nr: %u",     tlv_radio->detected_pairs_nr);

        /* reset ongoing cac flag */
        radio->ongoing_cac_request = 0;

        if (0 == tlv_radio->detected_pairs_nr) {
            /* remove current CAC completion list and break */
            radio->cac_completion_info.detected_pairs_nr = 0;
            SFREE(radio->cac_completion_info.detected_pairs);
            continue;
        }

        /* find out number of cac detected pairs, allocate space if needed */
        if (radio->cac_completion_info.detected_pairs_nr != tlv_radio->detected_pairs_nr) {
            if (!(cac_pair = calloc(tlv_radio->detected_pairs_nr, sizeof(*cac_pair)))) {
                log_ctrl_e("%s: calloc failed", __FUNCTION__);
                return -1;
            }

            SFREE(radio->cac_completion_info.detected_pairs);
            radio->cac_completion_info.detected_pairs    = cac_pair;
            radio->cac_completion_info.detected_pairs_nr = tlv_radio->detected_pairs_nr;
        } else {
            cac_pair = radio->cac_completion_info.detected_pairs;
        }

        for (j = 0; j < tlv_radio->detected_pairs_nr; j++) {
            cac_pair[j].opclass_detected = tlv_radio->detected_pairs[j].op_class;
            cac_pair[j].channel_detected = tlv_radio->detected_pairs[j].channel;

            log_ctrl_d("opclass_detected: %u", tlv_radio->detected_pairs[j].op_class);
            log_ctrl_d("channel_detected: %u", tlv_radio->detected_pairs[j].channel);
        }
    }

    return 0;
}

/* MAP_R2 17.2.45 */
int map_parse_cac_status_report_tlv(map_ale_info_t *ale, map_cac_status_report_tlv_t* tlv)
{
    map_cac_available_pair_t     *available_pairs     = NULL;
    map_cac_non_occupancy_pair_t *non_occupancy_pairs = NULL;
    map_cac_ongoing_pair_t       *ongoing_cac_pairs   = NULL;
    int                           i;

    log_ctrl_d("<-------- CAC Status Report TLV");

    log_ctrl_d("Number of Available Channels: %u", tlv->available_pairs_nr);
    if (tlv->available_pairs_nr > 0) {
        if (ale->cac_status_report.available_pairs_nr != tlv->available_pairs_nr) {
            if (!(available_pairs = calloc(tlv->available_pairs_nr, sizeof(*available_pairs)))) {
                goto fail;
            }

            SFREE(ale->cac_status_report.available_pairs);
            ale->cac_status_report.available_pairs    = available_pairs;
            ale->cac_status_report.available_pairs_nr = tlv->available_pairs_nr;
        } else {
            available_pairs = ale->cac_status_report.available_pairs;
        }

        for (i = 0; i < tlv->available_pairs_nr; i++) {
            available_pairs[i].op_class                     = tlv->available_pairs[i].op_class;
            available_pairs[i].channel                      = tlv->available_pairs[i].channel;
            available_pairs[i].minutes_since_cac_completion = tlv->available_pairs[i].minutes_since_cac_completion;

            log_ctrl_t("     Opclass: %u", tlv->available_pairs[i].op_class);
            log_ctrl_t("     Channel: %u", tlv->available_pairs[i].channel);
            log_ctrl_t("     Passed Time after CAC completion: %u min", tlv->available_pairs[i].minutes_since_cac_completion);
        }
    } else {
        /* corrupted/zero number of available channels */
        SFREE(ale->cac_status_report.available_pairs);
        ale->cac_status_report.available_pairs_nr = 0;
    }

    log_ctrl_d("Number of Non-Occupancy Pairs: %u", tlv->non_occupancy_pairs_nr);
    if (tlv->non_occupancy_pairs_nr) {
        if (ale->cac_status_report.non_occupancy_pairs_nr != tlv->non_occupancy_pairs_nr) {
            if (!(non_occupancy_pairs = calloc(tlv->non_occupancy_pairs_nr, sizeof(*non_occupancy_pairs)))) {
                goto fail;
            }

            SFREE(ale->cac_status_report.non_occupancy_pairs);
            ale->cac_status_report.non_occupancy_pairs    = non_occupancy_pairs;
            ale->cac_status_report.non_occupancy_pairs_nr = tlv->non_occupancy_pairs_nr;
        } else {
            non_occupancy_pairs = ale->cac_status_report.non_occupancy_pairs;
        }

        for (i = 0; i < tlv->non_occupancy_pairs_nr; i++) {
            non_occupancy_pairs[i].op_class                                 = tlv->non_occupancy_pairs[i].op_class;
            non_occupancy_pairs[i].channel                                  = tlv->non_occupancy_pairs[i].channel;
            non_occupancy_pairs[i].seconds_remaining_non_occupancy_duration = tlv->non_occupancy_pairs[i].seconds_remaining_non_occupancy_duration;

            log_ctrl_t("     Opclass: %u", tlv->non_occupancy_pairs[i].op_class);
            log_ctrl_t("     Channel: %u", tlv->non_occupancy_pairs[i].channel);
            log_ctrl_t("     Remainin Non-Occupancy Duration: %u seconds", tlv->non_occupancy_pairs[i].seconds_remaining_non_occupancy_duration);
        }
    } else {
        /* corrupted/zero number of non-occupancy channels */
        SFREE(ale->cac_status_report.non_occupancy_pairs);
        ale->cac_status_report.non_occupancy_pairs_nr = 0;
    }

    log_ctrl_d("Number of Ongoing CAC Pairs: %u", tlv->ongoing_cac_pairs_nr);
    if (tlv->ongoing_cac_pairs_nr) {
        if (ale->cac_status_report.ongoing_cac_pairs_nr != tlv->ongoing_cac_pairs_nr) {
            if (!(ongoing_cac_pairs = calloc(tlv->ongoing_cac_pairs_nr, sizeof(*ongoing_cac_pairs)))) {
                goto fail;
            }

            SFREE(ale->cac_status_report.ongoing_cac_pairs);
            ale->cac_status_report.ongoing_cac_pairs    = ongoing_cac_pairs;
            ale->cac_status_report.ongoing_cac_pairs_nr = tlv->ongoing_cac_pairs_nr;
        } else {
            ongoing_cac_pairs = ale->cac_status_report.ongoing_cac_pairs;
        }

        for (i = 0; i < tlv->ongoing_cac_pairs_nr; i++) {
            ongoing_cac_pairs[i].op_class                         = tlv->ongoing_cac_pairs[i].op_class;
            ongoing_cac_pairs[i].channel                          = tlv->ongoing_cac_pairs[i].channel;
            ongoing_cac_pairs[i].seconds_remaining_cac_completion = tlv->ongoing_cac_pairs[i].seconds_remaining_cac_completion;

            log_ctrl_t("     Opclass: %u", tlv->ongoing_cac_pairs[i].op_class);
            log_ctrl_t("     Channel: %u", tlv->ongoing_cac_pairs[i].channel);
            log_ctrl_t("     Remaining CAC completion Duration: %u seconds", tlv->ongoing_cac_pairs[i].seconds_remaining_cac_completion);
        }
    } else {
        /* corrupted/zero number of non-occupancy channels */
        SFREE(ale->cac_status_report.ongoing_cac_pairs);
        ale->cac_status_report.ongoing_cac_pairs_nr = 0;
    }

    ale->cac_status_report.valid = true;

    map_dm_ale_set_cac_status(ale);

    return 0;

fail:
    /* remove corrupted results */
    SFREE(ale->cac_status_report.available_pairs);
    SFREE(ale->cac_status_report.non_occupancy_pairs);
    SFREE(ale->cac_status_report.ongoing_cac_pairs);

    ale->cac_status_report.available_pairs_nr     = 0;
    ale->cac_status_report.non_occupancy_pairs_nr = 0;
    ale->cac_status_report.ongoing_cac_pairs_nr   = 0;

    log_ctrl_e("Storing CAC Status Report Information in DM failed");

    return -1;
}

/* MAP_R2 17.2.46 */
int map_parse_cac_cap_tlv(map_ale_info_t *ale, map_cac_cap_tlv_t* tlv)
{
    map_radio_info_t *radio;
    size_t i, j, k;

    log_ctrl_d("CAC CAPABILITIES:");
    log_ctrl_d("*****************************");

    /* Reset EU weatherband flag */
    map_dm_foreach_radio(ale, radio) {
        radio->cac_caps.has_eu_weatherband = false;
    }

    for (i = 0; i < tlv->radios_nr; i++) {
        map_cac_cap_tlv_radio_t *tlv_radio = &tlv->radios[i];
        map_cac_method_t        *new_cac_methods;

        if (!(radio = map_dm_get_radio(ale, tlv_radio->radio_id))) {
            log_ctrl_e("%s: radio[%s] not found", __FUNCTION__, mac_string(tlv_radio->radio_id));
            continue;
        }

        if (!(new_cac_methods = calloc(tlv_radio->cac_methods_nr, sizeof(*new_cac_methods)))) {
            log_ctrl_e("%s: calloc failed", __FUNCTION__);
            return -1;
        }

        for (j = 0; j < tlv_radio->cac_methods_nr; j++) {
            map_cac_cap_tlv_method_t *tlv_cac_method = &tlv_radio->cac_methods[j];
            map_cac_method_t         *cac_method     = &new_cac_methods[j];
            map_op_class_list_t      *op_class_list  = &cac_method->op_class_list;

            cac_method->cac_method       = tlv_cac_method->cac_method;
            cac_method->cac_duration     = tlv_cac_method->cac_duration;
            op_class_list->op_classes_nr = tlv_cac_method->op_classes_nr;

            op_class_list->op_classes = calloc(op_class_list->op_classes_nr, sizeof(map_op_class_t));
            if (!op_class_list->op_classes) {
                log_ctrl_e("%s: calloc failed", __FUNCTION__);
                map_dm_free_cac_methods(new_cac_methods, tlv_radio->cac_methods_nr);
                return -1;
            }

            for (k = 0; k < op_class_list->op_classes_nr; k++) {
                map_op_class_t *op_class = &op_class_list->op_classes[k];

                op_class->op_class = tlv_cac_method->op_classes[k].op_class;
                map_cs_copy(&op_class->channels, &tlv_cac_method->op_classes[k].channels);
            }

            /* Check if radio has EU weatherband.
               Using country code is difficult -> check for continuous cac method with large duration
            */
            if (cac_method->cac_method == MAP_CAC_METHOD_CONTINUOUS && cac_method->cac_duration >= 600) {
                for (k = 0; !radio->cac_caps.has_eu_weatherband && k < op_class_list->op_classes_nr; k++) {
                    map_op_class_t *op_class = &op_class_list->op_classes[k];
                    int             c;

                    if (!map_is_5G_weatherband_op_class(op_class->op_class)) {
                        continue;
                    }

                    map_cs_foreach(&op_class->channels, c) {
                        if (map_is_5G_weatherband_channel(op_class->op_class, c)) {
                            radio->cac_caps.has_eu_weatherband = true;
                            break;
                        }
                    }
                }
            }
        }

        map_dm_free_cac_methods(radio->cac_caps.cac_method, radio->cac_caps.cac_method_count);

        radio->cac_caps.cac_method_count = tlv_radio->cac_methods_nr;
        radio->cac_caps.cac_method       = new_cac_methods;

        log_ctrl_d("Radio[%s]",            mac_string(radio->radio_id));
        log_ctrl_d(" cac_method_count:%d", radio->cac_caps.cac_method_count);

        for (j = 0; j < radio->cac_caps.cac_method_count; j++) {
            map_cac_method_t *method = &radio->cac_caps.cac_method[j];

            log_ctrl_d("  cac_method:%d",     method->cac_method);
            log_ctrl_d("  cac_duration:%d",   method->cac_duration);
            log_ctrl_d("  op_class_count:%d", method->op_class_list.op_classes_nr);

            for (k = 0; k < method->op_class_list.op_classes_nr; k++) {
                map_op_class_t *op_class = &method->op_class_list.op_classes[k];
                char buf[MAP_CS_BUF_LEN];

                log_ctrl_t("  op_class:%d",        op_class->op_class);
                log_ctrl_t("    channel_count:%d", map_cs_nr(&op_class->channels));
                log_ctrl_t("    channel_list:%s",  map_cs_to_string(&op_class->channels, ' ', buf, sizeof(buf)));
            }
        }
        log_ctrl_d("*****************************");

    }

    /* Note ale's country code (using last radio - assumes that all radio have the same code) */
    ale->country_code = tlv->country_code;

    return 0;
}

/* MAP_R2 17.2.47 */
int map_parse_multiap_profile_tlv(map_ale_info_t *ale, map_multiap_profile_tlv_t* tlv)
{
    /* If multiap profile tlv exists and set to 1, we assume that relevant agent supports release 4 or higher */
    ale->map_profile = (tlv->map_profile == 1) ? MAP_PROFILE_4P : tlv->map_profile;

    return 0;
}

/* MAP_R2 17.2.48 */
int map_parse_ap_cap_profile_2_tlv(map_ale_info_t *ale, map_profile2_ap_cap_tlv_t* tlv)
{
    ale->agent_capability.profile_2_ap_cap_valid = true;
    ale->agent_capability.byte_counter_unit      = tlv->byte_counter_unit;
    ale->agent_capability.max_vid_count          = tlv->max_vid_count;

    return 0;
}

/* MAP_R2 17.2.53 */
int map_parse_assoc_status_notification_tlv(map_ale_info_t *ale, map_assoc_status_notification_tlv_t* tlv)
{
    size_t i;

    for (i = 0; i < tlv->bsss_nr; i++) {
        map_assoc_status_notification_tlv_bss_t *tlv_bss = &tlv->bsss[i];
        map_bss_info_t                          *bss = map_dm_get_bss_from_ale(ale, tlv_bss->bssid);

        if (!bss) {
            log_ctrl_e("%s: bss[%s] not found", __FUNCTION__, mac_string(tlv_bss->bssid));
            return -1;
        }

        bss->assoc_allowance_status = tlv_bss->assoc_allowance_status;
        log_ctrl_i("BSS[%s] association allowance status changed to %sALLOWED", mac_string(bss->bssid), bss->assoc_allowance_status ? "" : "NOT_");
    }

    return 0;
}

/* MAP_R2 17.2.59 */
int map_parse_metric_collection_interval_tlv(map_ale_info_t *ale, map_metric_collection_interval_tlv_t* tlv)
{
    ale->agent_capability.metric_collection_interval = tlv->metric_collection_interval;

    return 0;
}

/* MAP_R2 17.2.60 */
int map_parse_radio_metrics_tlv(map_ale_info_t *ale, map_radio_metrics_tlv_t* tlv)
{
    map_radio_info_t *radio = map_dm_get_radio(ale, tlv->radio_id);

    if (!radio) {
        log_ctrl_e("%s: radio[%s] not found", __FUNCTION__, mac_string(tlv->radio_id));
        return -1;
    }

    radio->radio_metrics.valid         = true;
    radio->radio_metrics.noise         = tlv->noise;
    radio->radio_metrics.transmit      = tlv->transmit;
    radio->radio_metrics.receive_self  = tlv->receive_self;
    radio->radio_metrics.receive_other = tlv->receive_other;

    /* For debug purposes
    log_ctrl_d("\nRadioMetrics::RadioID: [%s]",     mac_string(tlv->radio_id));
    log_ctrl_d("RadioMetrics::Noise: [%d]",         radio->radio_metrics.noise);
    log_ctrl_d("RadioMetrics::Transmit: [%d]",      radio->radio_metrics.transmit);
    log_ctrl_d("RadioMetrics::Receive_Self: [%d]",  radio->radio_metrics.receive_self);
    log_ctrl_d("RadioMetrics::Receive_Other: [%d]", radio->radio_metrics.receive_other);
    */

    return 0;
}

/* MAP_R2 17.2.61 */
int map_parse_ap_ext_metrics_response_tlv(map_ale_info_t *ale, map_ap_ext_metrics_tlv_t* tlv)
{
    map_bss_info_t *bss               = map_dm_get_bss_from_ale(ale, tlv->bssid);
    uint8_t         byte_counter_unit = ale->map_profile >= MAP_PROFILE_2 ?
                                        ale->agent_capability.byte_counter_unit : MAP_BYTE_COUNTER_UNIT_BYTES;
    if (!bss) {
        log_ctrl_d("%s: bss[%s] not found", __FUNCTION__, mac_string(tlv->bssid));
        return -1;
    }

    bss->extended_metrics.valid          = true;
    bss->extended_metrics.tx_ucast_bytes = map_convert_mapunits_to_bytes(tlv->tx_ucast_bytes, byte_counter_unit);
    bss->extended_metrics.rx_ucast_bytes = map_convert_mapunits_to_bytes(tlv->rx_ucast_bytes, byte_counter_unit);
    bss->extended_metrics.tx_mcast_bytes = map_convert_mapunits_to_bytes(tlv->tx_mcast_bytes, byte_counter_unit);
    bss->extended_metrics.rx_mcast_bytes = map_convert_mapunits_to_bytes(tlv->rx_mcast_bytes, byte_counter_unit);
    bss->extended_metrics.tx_bcast_bytes = map_convert_mapunits_to_bytes(tlv->tx_bcast_bytes, byte_counter_unit);
    bss->extended_metrics.rx_bcast_bytes = map_convert_mapunits_to_bytes(tlv->rx_bcast_bytes, byte_counter_unit);

    return 0;
}

/* MAP_R2 17.2.62 */
int map_parse_assoc_sta_ext_link_metrics_tlv(map_ale_info_t *ale, map_assoc_sta_ext_link_metrics_tlv_t* tlv)
{
    map_sta_ext_bss_metrics_t *ext_metrics = NULL;
    map_sta_info_t            *sta = map_dm_get_sta_from_ale(ale, tlv->sta_mac);
    int                        i;

    if (!sta) {
        log_ctrl_e("%s: sta[%s] not found", __FUNCTION__, mac_string(tlv->sta_mac));
        return -1;
    }

    if (tlv->bsss_nr == 0) {
        sta->last_sta_ext_metrics.no_of_bss_metrics = 0;
        SFREE(sta->last_sta_ext_metrics.ext_bss_metrics_list);
        return 0;
    }

    if (sta->last_sta_ext_metrics.no_of_bss_metrics != tlv->bsss_nr) {
        if (!(ext_metrics = calloc(tlv->bsss_nr, sizeof(*ext_metrics)))) {
            return -1;
        }

        SFREE(sta->last_sta_ext_metrics.ext_bss_metrics_list);
        sta->last_sta_ext_metrics.ext_bss_metrics_list = ext_metrics;
    } else {
        ext_metrics = sta->last_sta_ext_metrics.ext_bss_metrics_list;
    }

    for (i = 0; i < tlv->bsss_nr; i++) {
        maccpy(ext_metrics[i].bssid, tlv->bsss[i].bssid);
        ext_metrics[i].last_data_dl_rate = tlv->bsss[i].last_data_dl_rate;
        ext_metrics[i].last_data_ul_rate = tlv->bsss[i].last_data_ul_rate;
        ext_metrics[i].utilization_rx    = tlv->bsss[i].utilization_rx;
        ext_metrics[i].utilization_tx    = tlv->bsss[i].utilization_tx;
    }

    sta->last_sta_ext_metrics.no_of_bss_metrics = tlv->bsss_nr;

    return 0;
}

/* MAP_R2 17.2.65 */
int map_parse_backhaul_sta_radio_capability_tlv(map_ale_info_t *ale, map_backhaul_sta_radio_cap_tlv_t **tlvs, size_t tlvs_nr)
{
    size_t i;

    /* Remove old backhaul sta interfaces */
    SFREE(ale->backhaul_sta_iface_list);

    ale->backhaul_sta_iface_count = 0;

    if (tlvs_nr == 0) {
        return 0;
    }

    if (!ale->backhaul_sta_iface_list && !(ale->backhaul_sta_iface_list = calloc(tlvs_nr, sizeof(*ale->backhaul_sta_iface_list)))) {
        log_ctrl_e("%s: calloc failed", __FUNCTION__);
        return -1;
    }

    ale->backhaul_sta_iface_count = tlvs_nr;

    for (i = 0; i < tlvs_nr; i++) {
        map_backhaul_sta_radio_cap_tlv_t *tlv          = tlvs[i];
        map_backhaul_sta_iface_t         *bhsta_iface  = &ale->backhaul_sta_iface_list[i];
        map_radio_info_t                 *bhsta_radio;

        maccpy(bhsta_iface->radio_id, tlv->radio_id);
        if (tlv->bsta_mac_present) {
            maccpy(bhsta_iface->mac_address, tlv->bsta_mac);
            /* Check if it is connected(active) */
            bhsta_iface->active = !!map_dm_get_sta_gbl(bhsta_iface->mac_address);

            if ((bhsta_radio = map_dm_get_radio(ale, bhsta_iface->radio_id))) {
                map_dm_radio_set_channel_configurable(bhsta_radio, !bhsta_iface->active);
            }
        }
    }

    return 0;
}

/*#######################################################################
#                       MAP R3 TLV HANDLERS                             #
########################################################################*/
/* MAP_R3 17.2.72 */
int map_parse_ap_wifi6_cap_tlv(map_ale_info_t *ale, map_ap_wifi6_cap_tlv_t *tlv)
{
    map_radio_info_t *radio = map_dm_get_radio(ale, tlv->radio_id);
    int               i;

    if (!radio) {
        log_ctrl_e("%s: radio[%s] not found", __FUNCTION__, mac_string(tlv->radio_id));
        return -1;
    }

    if (tlv->roles_nr == 0 || tlv->roles_nr > MAP_AP_ROLE_MAX) {
        log_ctrl_e("%s: invalid role count[%d] for radio[%s]", __FUNCTION__,
                   tlv->roles_nr, mac_string(tlv->radio_id));
        return -1;
    }

    if (!radio->wifi6_caps && !(radio->wifi6_caps = calloc(1, sizeof(*radio->wifi6_caps)))) {
        log_ctrl_e("%s: calloc failed", __FUNCTION__);
        return -1;
    }

    for (i = 0; i < tlv->roles_nr; i++) {
        if (tlv->cap_data[i].mcs_nss_nr > MAX_MCS_NSS * 2) {
            log_ctrl_e("%s: invalid MCS NSS length[%d] for radio[%s]", __FUNCTION__,
                       tlv->cap_data[i].mcs_nss_nr, mac_string(tlv->radio_id));
            return -1;
        }
        radio->wifi6_caps->cap_data[i] = tlv->cap_data[i];
    }

    return 0;
}

/* MAP_R3 17.2.73 */
int map_parse_assoc_wifi6_sta_status_tlv(map_ale_info_t *ale, map_assoc_wifi6_sta_status_tlv_t *tlv)
{
    map_sta_mld_info_t       *sta_mld;
    map_sta_info_t           *sta = map_dm_get_sta_from_ale(ale, tlv->sta_mac);
    map_wifi6_sta_tid_info_t *tid_info;
    uint8_t i;

    /* tlv->sta_mac can be a STA_MLD or a STA */
    if (map_dm_ale_has_mld(ale) && (sta_mld = map_dm_get_sta_mld_from_ale(ale, tlv->sta_mac))) {
        tid_info = &sta_mld->wifi6_sta_tid_info;
    } else if ((sta = map_dm_get_sta_from_ale(ale, tlv->sta_mac))) {
        tid_info = &sta->wifi6_sta_tid_info;
    } else {
        log_ctrl_e("%s: sta[%s] not found", __FUNCTION__, mac_string(tlv->sta_mac));
        return -1;
    }

    tid_info->TID_nr = tlv->TID_nr;

    for (i = 0; i < tid_info->TID_nr; i++) {
        tid_info->TID[i] = tlv->TID[i];
        tid_info->queue_size[i] = tlv->queue_size[i];
    }

    return 0;
}

/* MAP_R3 17.2.75 */
int map_parse_bss_configuration_report_tlv(map_ale_info_t *ale, map_bss_configuration_report_tlv_t *tlv)
{
    int i, j;

    if (tlv->radios_nr > MAX_RADIO_PER_AGENT) {
        log_ctrl_e("invalid radio number[%d] for ale[%s]", tlv->radios_nr, ale->al_mac_str);
        return -1;
    }

    for (i = 0; i < tlv->radios_nr; i++) {
        map_bss_configuration_radio_t *tlv_radio = &tlv->radios[i];
        if (tlv_radio->bss_nr > MAX_BSS_PER_RADIO) {
            log_ctrl_e("invalid bss number[%d] for radio[%s]", tlv_radio->bss_nr, mac_string(tlv_radio->ruid));
            return -1;
        }

        map_radio_info_t *radio = map_dm_get_radio(ale, tlv_radio->ruid);
        if (!radio) {
            log_ctrl_w("radio[%s] not found", mac_string(tlv_radio->ruid));
            continue;
        }

        for (j = 0; j < tlv_radio->bss_nr; j++) {
            map_bss_configuration_bss_t *tlv_bss = &tlv_radio->bss[j];

            map_bss_info_t *bss = map_dm_get_bss(radio, tlv_bss->bssid);
            if (!bss) {
                log_ctrl_w("bss [%s] not found", mac_string(tlv_bss->bssid));
                continue;
            }

            bss->flags.backhaul_bss = tlv_bss->backhaul_bss;
            bss->flags.fronthaul_bss = tlv_bss->fronthaul_bss;
            bss->flags.r1_disallowed_status = tlv_bss->r1_disallowed_status;
            bss->flags.r2_disallowed_status = tlv_bss->r2_disallowed_status;
            bss->flags.multiple_bssid = tlv_bss->multiple_bssid;
            bss->flags.transmitted_bssid = tlv_bss->transmitted_bssid;
        }
    }

    return 0;
}

/* MAP_R3 17.2.79 */
int map_parse_1905_encap_dpp_tlv(map_ale_info_t *ale, map_1905_encap_dpp_tlv_t *tlv)
{
    int ret = -1;

    if (tlv->enrollee_mac_present) {
        maccpy(ale->dpp_info.encap_msg.enrollee, tlv->sta_mac);
    }
    ale->dpp_info.encap_msg.frame_indicator = tlv->dpp_frame_indicator;
    ale->dpp_info.encap_msg.frame_type = tlv->frame_type;
    if (tlv->frame_len && tlv->frame) {
        free(ale->dpp_info.encap_msg.frame);
        ale->dpp_info.encap_msg.frame_len = tlv->frame_len;
        ale->dpp_info.encap_msg.frame = calloc(tlv->frame_len, sizeof(uint8_t));
        if (ale->dpp_info.encap_msg.frame == NULL) {
            return ret;
        }
        memcpy(ale->dpp_info.encap_msg.frame, tlv->frame, tlv->frame_len);
        ret = 0;
    }

    return ret;
}

/* MAP_R3 17.2.80 */
int map_parse_1905_encap_eapol_tlv(map_ale_info_t *ale, map_1905_encap_eapol_tlv_t *tlv)
{
    int ret = -1;

    if (tlv->frame_len && tlv->frame) {
        free(ale->dpp_info.encap_eapol.frame);
        ale->dpp_info.encap_eapol.frame_len = tlv->frame_len;
        ale->dpp_info.encap_eapol.frame = calloc(tlv->frame_len, sizeof(uint8_t));
        if (ale->dpp_info.encap_eapol.frame == NULL) {
            return ret;
        }
        memcpy(ale->dpp_info.encap_eapol.frame, tlv->frame, tlv->frame_len);
        ret = 0;
    }

    return ret;
}

/* MAP_R3 17.2.83 */
int map_parse_dpp_chirp_value_tlv(map_ale_info_t *ale, map_dpp_chirp_value_tlv_t *tlv)
{
    int ret = -1;

    if (tlv->enrollee_mac_present) {
        maccpy(ale->dpp_info.chirp.enrollee, tlv->sta_mac);
    }

    ale->dpp_info.chirp.hash_validity = tlv->hash_validity;
    if (tlv->hash_len && tlv->hash) {
        free(ale->dpp_info.chirp.hash);
        ale->dpp_info.chirp.hash_len = tlv->hash_len;
        ale->dpp_info.chirp.hash = calloc(tlv->hash_len, sizeof(uint8_t));
        if (ale->dpp_info.chirp.hash == NULL) {
            return ret;
        }
        memcpy(ale->dpp_info.chirp.hash, tlv->hash, tlv->hash_len);
        ret = 0;
    }

    return ret;
}

/* MAP_R3 17.2.84 */
int map_parse_bss_configuration_request_tlv(map_ale_info_t *ale, map_bss_configuration_request_tlv_t *tlv)
{
    int ret = -1;

    if (tlv->obj_len && tlv->obj) {
        free(ale->dpp_info.bss_config_req.obj);
        ale->dpp_info.bss_config_req.obj_len = tlv->obj_len;
        ale->dpp_info.bss_config_req.obj = calloc(tlv->obj_len, sizeof(uint8_t));
        if (ale->dpp_info.bss_config_req.obj == NULL) {
            return ret;
        }
        memcpy(ale->dpp_info.bss_config_req.obj, tlv->obj, tlv->obj_len);
        ret = 0;
    }

    return ret;
}

/* MAP_R3 17.2.86 */
int map_parse_dpp_message_tlv(map_ale_info_t *ale, map_dpp_message_tlv_t *tlv)
{
    int ret = -1;

    if (tlv->frame_len && tlv->frame) {
        free(ale->dpp_info.message.frame);
        ale->dpp_info.message.frame_len = tlv->frame_len;
        ale->dpp_info.message.frame = calloc(tlv->frame_len, sizeof(uint8_t));
        if (ale->dpp_info.message.frame == NULL) {
            return ret;
        }
        memcpy(ale->dpp_info.message.frame, tlv->frame, tlv->frame_len);
        ret = 0;
    }

    return ret;
}

/* MAP_R3 17.2.76 */
int map_parse_device_inventory_tlv(map_ale_info_t *ale, map_device_inventory_tlv_t *tlv)
{
    int i;

    memcpy(ale->inventory.serial, tlv->serial, tlv->serial_len);
    ale->inventory.serial[tlv->serial_len] = 0;
    memcpy(ale->inventory.version, tlv->version, tlv->version_len);
    ale->inventory.version[tlv->version_len] = 0;
    memcpy(ale->inventory.environment, tlv->environment, tlv->environment_len);
    ale->inventory.environment[tlv->environment_len] = 0;

    for (i = 0; i < tlv->radios_nr; i++) {
        map_radio_info_t *radio = map_dm_get_radio(ale, tlv->radios[i].ruid);
        if (!radio) {
            continue;
        }
        memcpy(radio->vendor, tlv->radios[i].vendor, tlv->radios[i].vendor_len);
        radio->vendor[tlv->radios[i].vendor_len] = 0;
    }
    ale->inventory_exists = true;

    return 0;
}

/*#######################################################################
#                       MAP R6 TLV HANDLERS                             #
########################################################################*/
/* MAP_R6 17.2.95 */
int map_parse_wifi7_agent_capability_tlv(map_ale_info_t *ale, map_wifi7_agent_cap_tlv_t *tlv, bool *ret_changed)
{
    int i, j;
    bool changed = false;

    log_ctrl_t("WI-FI 7 CAPABILITIES:");
    log_ctrl_t("*****************************");
    ale->agent_capability.max_mlds = tlv->max_mlds;
    ale->agent_capability.ap_max_links = tlv->ap_max_links;
    ale->agent_capability.bsta_max_links = tlv->bsta_max_links;
    ale->agent_capability.tid_to_link_map_cap = tlv->tid_to_link_map_cap;

    log_ctrl_t("ALE[%s]", ale->al_mac_str);
    log_ctrl_t(" max_mlds: %d, ap_max_links: %d, bsta_max_links: %d, tid_to_link_map: %d", ale->agent_capability.max_mlds,
                ale->agent_capability.ap_max_links, ale->agent_capability.bsta_max_links, ale->agent_capability.tid_to_link_map_cap);

    for (i = 0; i < tlv->radios_nr; i++) {
        map_radio_info_t        *radio          = map_dm_get_radio(ale, tlv->radios[i].ruid);
        map_radio_wifi7_caps_t  *tlv_wifi7_caps = &tlv->radios[i].cap;
        map_radio_wifi7_caps_t  *wifi7_caps;

        if (!radio) {
            log_ctrl_e("%s: radio[%s] not found", __FUNCTION__, mac_string(tlv->radios[i].ruid));
            continue;
        }

        log_ctrl_t(" Radio[%s]", mac_string(radio->radio_id));

        /* TODO: Remove it when EHT operations TLV implemented by agent.
        * Until that time this is the most deterministic eht capability indicator.
        */
        if (!radio->eht_caps && !(radio->eht_caps = calloc(1, sizeof(*radio->eht_caps)))) {
            log_ctrl_e("%s: calloc failed", __FUNCTION__);
            return -1;
        }

        /* Check if wifi7 capabilities are changed */
        if (radio->wifi7_caps) {
            if (memcmp(&radio->wifi7_caps->ap_mld_modes, &tlv_wifi7_caps->ap_mld_modes, sizeof(map_mld_modes_t)) ||
                memcmp(&radio->wifi7_caps->bsta_mld_modes, &tlv_wifi7_caps->bsta_mld_modes, sizeof(map_mld_modes_t)) ||
                radio->wifi7_caps->ap_str_records_nr != tlv_wifi7_caps->ap_str_records_nr ||
                radio->wifi7_caps->ap_nstr_records_nr != tlv_wifi7_caps->ap_nstr_records_nr ||
                radio->wifi7_caps->ap_emlsr_records_nr != tlv_wifi7_caps->ap_emlsr_records_nr ||
                radio->wifi7_caps->ap_emlmr_records_nr != tlv_wifi7_caps->ap_emlmr_records_nr) {
                changed = true;
            }

            map_free_wifi7_caps(radio);

        } else if (is_radio_M2_sent(radio->state)) {
            changed = true;
        }

        if (!radio->wifi7_caps && !(radio->wifi7_caps = calloc(1, sizeof(*radio->wifi7_caps)))) {
            log_ctrl_e("%s: calloc failed", __FUNCTION__);
            return -1;
        }

        wifi7_caps = radio->wifi7_caps;
        wifi7_caps->ap_mld_modes   = tlv_wifi7_caps->ap_mld_modes;
        wifi7_caps->bsta_mld_modes = tlv_wifi7_caps->bsta_mld_modes;

        log_ctrl_t("  ap_str_support: %s, ap_nstr_support: %s, ap_emlsr_support: %s, ap_emlmr_support: %s",
                    wifi7_caps->ap_mld_modes.str ? "true" : "false", wifi7_caps->ap_mld_modes.nstr ? "true" : "false",
                    wifi7_caps->ap_mld_modes.emlsr ? "true" : "false", wifi7_caps->ap_mld_modes.emlmr ? "true" : "false");
        log_ctrl_t("  bsta_str_support: %s, bsta_nstr_support: %s, bsta_emlsr_support: %s, bsta_emlmr_support: %s",
                    wifi7_caps->bsta_mld_modes.str ? "true" : "false", wifi7_caps->bsta_mld_modes.nstr ? "true" : "false",
                    wifi7_caps->bsta_mld_modes.emlsr ? "true" : "false", wifi7_caps->bsta_mld_modes.emlmr ? "true" : "false");

        wifi7_caps->ap_str_records_nr = tlv_wifi7_caps->ap_str_records_nr;
        log_ctrl_t("  ap_str_records_nr:     %d",  wifi7_caps->ap_str_records_nr);
        if (wifi7_caps->ap_str_records_nr > 0) {
            wifi7_caps->ap_str_records = calloc(wifi7_caps->ap_str_records_nr, sizeof(*wifi7_caps->ap_str_records));
            for (j=0; j < wifi7_caps->ap_str_records_nr; j++) {
                maccpy(wifi7_caps->ap_str_records[j].ruid, tlv_wifi7_caps->ap_str_records[j].ruid);
                wifi7_caps->ap_str_records[j].freq_separation = tlv_wifi7_caps->ap_str_records[j].freq_separation;
                log_ctrl_t("   ap_str_record[%d] ruid[%s] freq_separation[%d] ",
                            j, mac_string(wifi7_caps->ap_str_records[j].ruid), wifi7_caps->ap_str_records[j].freq_separation);
            }
        }

        wifi7_caps->ap_nstr_records_nr = tlv_wifi7_caps->ap_nstr_records_nr;
        log_ctrl_t("  ap_nstr_records_nr:    %d",  wifi7_caps->ap_nstr_records_nr);
        if (wifi7_caps->ap_nstr_records_nr > 0) {
            wifi7_caps->ap_nstr_records = calloc(wifi7_caps->ap_nstr_records_nr, sizeof(*wifi7_caps->ap_nstr_records));
            for (j=0; j < wifi7_caps->ap_nstr_records_nr; j++) {
                maccpy(wifi7_caps->ap_nstr_records[j].ruid, tlv_wifi7_caps->ap_nstr_records[j].ruid);
                wifi7_caps->ap_nstr_records[j].freq_separation = tlv_wifi7_caps->ap_nstr_records[j].freq_separation;
                log_ctrl_t("   ap_nstr_record[%d] ruid[%s] freq_separation[%d] ",
                            j, mac_string(wifi7_caps->ap_nstr_records[j].ruid), wifi7_caps->ap_nstr_records[j].freq_separation);
            }
        }

        wifi7_caps->ap_emlsr_records_nr = tlv_wifi7_caps->ap_emlsr_records_nr;
        log_ctrl_t("  ap_emlsr_records_nr:   %d",  wifi7_caps->ap_emlsr_records_nr);
        if (wifi7_caps->ap_emlsr_records_nr > 0) {
            wifi7_caps->ap_emlsr_records = calloc(wifi7_caps->ap_emlsr_records_nr, sizeof(*wifi7_caps->ap_emlsr_records));
            for (j=0; j < wifi7_caps->ap_emlsr_records_nr; j++) {
                maccpy(wifi7_caps->ap_emlsr_records[j].ruid, tlv_wifi7_caps->ap_emlsr_records[j].ruid);
                wifi7_caps->ap_emlsr_records[j].freq_separation = tlv_wifi7_caps->ap_emlsr_records[j].freq_separation;
                log_ctrl_t("   ap_emlsr_record[%d] ruid[%s] freq_separation[%d] ",
                            j, mac_string(wifi7_caps->ap_emlsr_records[j].ruid), wifi7_caps->ap_emlsr_records[j].freq_separation);
            }
        }

        wifi7_caps->ap_emlmr_records_nr = tlv_wifi7_caps->ap_emlmr_records_nr;
        log_ctrl_t("  ap_emlmr_records_nr:   %d",  wifi7_caps->ap_emlmr_records_nr);
        if (wifi7_caps->ap_emlmr_records_nr > 0) {
            wifi7_caps->ap_emlmr_records = calloc(wifi7_caps->ap_emlmr_records_nr, sizeof(*wifi7_caps->ap_emlmr_records));
            for (j=0; j < wifi7_caps->ap_emlmr_records_nr; j++) {
                maccpy(wifi7_caps->ap_emlmr_records[j].ruid, tlv_wifi7_caps->ap_emlmr_records[j].ruid);
                wifi7_caps->ap_emlmr_records[j].freq_separation = tlv_wifi7_caps->ap_emlmr_records[j].freq_separation;
                log_ctrl_t("   ap_emlmr_record[%d] ruid[%s] freq_separation[%d] ",
                            j, mac_string(wifi7_caps->ap_emlmr_records[j].ruid), wifi7_caps->ap_emlmr_records[j].freq_separation);
            }
        }

        wifi7_caps->bsta_str_records_nr = tlv_wifi7_caps->bsta_str_records_nr;
        log_ctrl_t("  bsta_str_records_nr:   %d",  wifi7_caps->bsta_str_records_nr);
        if (wifi7_caps->bsta_str_records_nr > 0) {
            wifi7_caps->bsta_str_records = calloc(wifi7_caps->bsta_str_records_nr, sizeof(*wifi7_caps->bsta_str_records));
            for (j=0; j < wifi7_caps->bsta_str_records_nr; j++) {
                maccpy(wifi7_caps->bsta_str_records[j].ruid, tlv_wifi7_caps->bsta_str_records[j].ruid);
                wifi7_caps->bsta_str_records[j].freq_separation = tlv_wifi7_caps->bsta_str_records[j].freq_separation;
                log_ctrl_t("   bsta_str_record[%d] ruid[%s] freq_separation[%d] ",
                            j, mac_string(wifi7_caps->bsta_str_records[j].ruid), wifi7_caps->bsta_str_records[j].freq_separation);
            }
        }

        wifi7_caps->bsta_nstr_records_nr = tlv_wifi7_caps->bsta_nstr_records_nr;
        log_ctrl_t("  bsta_nstr_records_nr:  %d",  wifi7_caps->bsta_nstr_records_nr);
        if (wifi7_caps->bsta_nstr_records_nr > 0) {
            wifi7_caps->bsta_nstr_records = calloc(wifi7_caps->bsta_nstr_records_nr, sizeof(*wifi7_caps->bsta_nstr_records));
            for (j=0; j < wifi7_caps->bsta_nstr_records_nr; j++) {
                maccpy(wifi7_caps->bsta_nstr_records[j].ruid, tlv_wifi7_caps->bsta_nstr_records[j].ruid);
                wifi7_caps->bsta_nstr_records[j].freq_separation = tlv_wifi7_caps->bsta_nstr_records[j].freq_separation;
                log_ctrl_t("   bsta_nstr_record[%d] ruid[%s] freq_separation[%d] ",
                            j, mac_string(wifi7_caps->bsta_nstr_records[j].ruid), wifi7_caps->bsta_nstr_records[j].freq_separation);
            }
        }

        wifi7_caps->bsta_emlsr_records_nr = tlv_wifi7_caps->bsta_emlsr_records_nr;
        log_ctrl_t("  bsta_emlsr_records_nr: %d",  wifi7_caps->bsta_emlsr_records_nr);
        if (wifi7_caps->bsta_emlsr_records_nr > 0) {
            wifi7_caps->bsta_emlsr_records = calloc(wifi7_caps->bsta_emlsr_records_nr, sizeof(*wifi7_caps->bsta_emlsr_records));
            for (j=0; j < wifi7_caps->bsta_emlsr_records_nr; j++) {
                maccpy(wifi7_caps->bsta_emlsr_records[j].ruid, tlv_wifi7_caps->bsta_emlsr_records[j].ruid);
                wifi7_caps->bsta_emlsr_records[j].freq_separation = tlv_wifi7_caps->bsta_emlsr_records[j].freq_separation;
                log_ctrl_t("   bsta_emlsr_record[%d] ruid[%s] freq_separation[%d] ",
                            j, mac_string(wifi7_caps->bsta_emlsr_records[j].ruid), wifi7_caps->bsta_emlsr_records[j].freq_separation);
            }
        }

        wifi7_caps->bsta_emlmr_records_nr = tlv_wifi7_caps->bsta_emlmr_records_nr;
        log_ctrl_t("  bsta_emlmr_records_nr: %d",  wifi7_caps->bsta_emlmr_records_nr);
        if (wifi7_caps->bsta_emlmr_records_nr > 0) {
            wifi7_caps->bsta_emlmr_records = calloc(wifi7_caps->bsta_emlmr_records_nr, sizeof(*wifi7_caps->bsta_emlmr_records));
            for (j=0; j < wifi7_caps->bsta_emlmr_records_nr; j++) {
                maccpy(wifi7_caps->bsta_emlmr_records[j].ruid, tlv_wifi7_caps->bsta_emlmr_records[j].ruid);
                wifi7_caps->bsta_emlmr_records[j].freq_separation = tlv_wifi7_caps->bsta_emlmr_records[j].freq_separation;
                log_ctrl_t("   bsta_emlmr_record[%d] ruid[%s] freq_separation[%d] ",
                            j, mac_string(wifi7_caps->bsta_emlmr_records[j].ruid), wifi7_caps->bsta_emlmr_records[j].freq_separation);
            }
        }
    }
    log_ctrl_t("*****************************");

    if (ret_changed) {
        *ret_changed = changed;
    }

    return 0;
}

/* MAP_R6 17.2.96 */
int map_parse_agent_ap_mld_conf_tlv(map_ale_info_t *ale, map_agent_ap_mld_conf_tlv_t *tlv)
{
    map_ap_mld_info_t                  *mld, *next;
    map_agent_ap_mld_conf_tlv_ap_mld_t *tlv_mld;
    mac_addr_str                        mac_str;
    int                                 i, j;

    /* First remove no longer present ap_mld */
    map_dm_foreach_ap_mld_safe(ale, mld, next) {
        bool found = false;

        for (i = 0; i < tlv->ap_mld_nr; i++) {
            tlv_mld = &tlv->ap_mlds[i];

            if (tlv_mld->ap_mld_mac_valid && !maccmp(mld->mac, tlv_mld->ap_mld_mac)) {
                found = true;
                break;
            }
        }

        if (!found) {
            log_ctrl_i("Removing AP MLD[%s] from ALE[%s]", mld->mac_str, ale->al_mac_str);
            map_dm_remove_ap_mld(mld);
        }
    }

    for (i = 0; i < tlv->ap_mld_nr; i++) {
        tlv_mld = &tlv->ap_mlds[i];

        if (!tlv_mld->ap_mld_mac_valid) {
            log_ctrl_e("AP MLD from ale[%s] has ap_mld_mac_valid set to false -> ignore", ale->al_mac_str);
            continue;
        }

        if (!(mld = map_dm_get_ap_mld(ale, tlv_mld->ap_mld_mac))) {
            mac_to_string(tlv_mld->ap_mld_mac, mac_str);

            log_ctrl_i("Creating AP MLD[%s] on ALE[%s]", mac_str, ale->al_mac_str);
            if (!(mld = map_dm_create_ap_mld(ale, tlv_mld->ap_mld_mac))) {
                log_ctrl_i("Could not create AP MLD[%s] on ALE[%s]", mac_str, ale->al_mac_str);
                continue;
            }
        }

        /* Get affiliated BSS */
        /* TODO: detect if BSS is part more than one MLD?? */
        map_aff_ap_cfg_t aff_aps[MAX_MLD_AFF_APSTA];
        size_t           aff_ap_nr = 0;

        for (j = 0; j < tlv_mld->aff_ap_nr && aff_ap_nr < MAX_MLD_AFF_APSTA; j++) {
            map_agent_ap_mld_conf_tlv_aff_ap_t *tlv_aff_ap = &tlv_mld->aff_aps[j];
            map_radio_info_t *radio;
            map_bss_info_t *bss;

            if (!(radio = map_dm_get_radio(ale, tlv_aff_ap->radio_id))) {
                mac_to_string(tlv_aff_ap->radio_id, mac_str);
                log_ctrl_e("Could not find affiliated AP radio[%s] on ALE[%s]", mac_str, ale->al_mac_str);
                continue;
            }

            if (!(bss = map_dm_get_bss(radio, tlv_aff_ap->aff_ap_mac))) {
                 mac_to_string(tlv_aff_ap->aff_ap_mac, mac_str);
                 log_ctrl_e("Could not find affiliated AP[%s] on radio[%s] on ALE[%s]", mac_str, radio->radio_id_str, ale->al_mac_str);
                 continue;
            }
            aff_aps[aff_ap_nr].bss     = bss;
            aff_aps[aff_ap_nr].link_id = tlv_aff_ap->link_id_valid ? tlv_aff_ap->link_id : 255;
            aff_ap_nr++;
        }

        /* Update parameters */
        map_dm_ap_mld_set(mld, tlv_mld->ssid_len, tlv_mld->ssid,
                          tlv_mld->str, tlv_mld->nstr, tlv_mld->emlsr, tlv_mld->emlmr,
                          aff_aps, aff_ap_nr);
    }

    return 0;
}

/* MAP_R6 17.2.97 */
int map_parse_bsta_mld_conf_tlv(map_ale_info_t *ale, map_bsta_mld_conf_tlv_t *tlv)
{
    int i;

    if (!tlv->bsta_mld_mac_valid) {
        map_dm_bsta_mld_set(&ale->bsta_mld, false, NULL, NULL, false, false, false, false, NULL, 0);
    } else {
        mac_addr aff_sta_macs[MAX_MLD_AFF_APSTA];
        size_t   aff_sta_mac_nr = 0;

        for (i = 0; i < tlv->aff_bsta_nr && aff_sta_mac_nr < MAX_MLD_AFF_APSTA; i++) {
            map_bsta_mld_conf_tlv_aff_bsta_t *tlv_aff_bsta = &tlv->aff_bstas[i];

            if (tlv_aff_bsta->aff_bsta_mac_valid) {
                maccpy(aff_sta_macs[aff_sta_mac_nr], tlv_aff_bsta->aff_bsta_mac);
                aff_sta_mac_nr++;
            }
        }

        /* Sort array in case order would change... */
        acu_sort_mac_array(aff_sta_macs, aff_sta_mac_nr);

        map_dm_bsta_mld_set(&ale->bsta_mld, true, tlv->bsta_mld_mac, tlv->ap_mld_mac,
                            tlv->str, tlv->nstr, tlv->emlsr, tlv->emlmr,
                            aff_sta_macs, aff_sta_mac_nr);
    }

    return 0;
}

/* MAP_R6 17.2.97 */
int map_parse_assoc_sta_mld_conf_tlv(map_ale_info_t *ale, map_assoc_sta_mld_conf_tlv_t *tlv)
{
    map_ap_mld_info_t  *ap_mld;
    map_sta_mld_info_t *sta_mld;
    map_bss_info_t     *bss;
    map_sta_info_t     *sta;
    mac_addr_str        sta_mld_mac_str;
    mac_addr_str        ap_mld_mac_str;
    size_t              i;

    mac_to_string(tlv->sta_mld_mac, sta_mld_mac_str);
    mac_to_string(tlv->ap_mld_mac, ap_mld_mac_str);

    /* Is the AP_MLD known? */
    if (!(ap_mld = map_dm_get_ap_mld(ale, tlv->ap_mld_mac))) {
        log_ctrl_e("ALE[%s]: could not find AP_MLD[%s]", ale->al_mac_str, ap_mld_mac_str);
        return -1;
    }

    /* Is this STA connected (to this or another ap_mld) */
    if ((sta_mld = map_dm_get_sta_mld_from_ale(ale, tlv->sta_mld_mac))) {
        if (sta_mld->ap_mld != ap_mld) {
            /* This would mean a roam from e.g home to guest and is not that likely
               -> Just remove and re-create
            */
            log_ctrl_i("ALE[%s]: removing STA_MLD[%s] part of the wrong AP_MLD[%s <-> %s]",
                       ale->al_mac_str, sta_mld_mac_str, ap_mld_mac_str, sta_mld->ap_mld ? sta_mld->ap_mld->mac_str : "-");
            map_dm_remove_sta_mld(sta_mld);
            sta_mld = NULL;
        }
    }

    /* Create if needed */
    if (!sta_mld) {
        log_ctrl_i("ALE[%s]: creating STA_MLD[%s] on AP_MLD[%s]", ale->al_mac_str, sta_mld_mac_str, ap_mld_mac_str);
        if (!(sta_mld = map_dm_create_sta_mld(ap_mld, tlv->sta_mld_mac))) {
            log_ctrl_e("ALE[%s]: could not create STA_MLD[%s] on AP_MLD[%s]", ale->al_mac_str, sta_mld_mac_str, ap_mld_mac_str);
            return -1;
        }
    }

    /* Update */
    sta_mld->enabled_mld_modes.str   = tlv->str;
    sta_mld->enabled_mld_modes.nstr  = tlv->nstr;
    sta_mld->enabled_mld_modes.emlsr = tlv->emlsr;
    sta_mld->enabled_mld_modes.emlmr = tlv->emlmr;

    /* Create/update affiliated stas
       NOTE: No longer "referenced" STA will be deleted automatically as they remain "marked"
    */
    for (i = 0; i < tlv->aff_sta_nr; i++) {
        map_assoc_sta_mld_conf_tlv_aff_sta_t *tlv_aff_sta = &tlv->aff_stas[i];
        mac_addr_str                          aff_sta_mac_str;
        mac_addr_str                          bssid_str;

        mac_to_string(tlv_aff_sta->aff_sta_mac, aff_sta_mac_str);
        mac_to_string(tlv_aff_sta->bssid, bssid_str);

        if (!(bss = map_dm_get_bss_from_ale(ale, tlv_aff_sta->bssid))) {
            mac_to_string(tlv_aff_sta->bssid, bssid_str);
            log_ctrl_e("ALE[%s]: could not find BSSID[%s] to add AFF_STA[%s]", ale->al_mac_str, bssid_str, aff_sta_mac_str);
            continue;
        }

        /* Can we assume that affiliated sta never roam?
           For now - just delete mismatching STAs
        */
        if ((sta = map_dm_get_sta_from_ale(ale, tlv_aff_sta->aff_sta_mac))) {
            if (sta->sta_mld != sta_mld) {
                log_ctrl_i("ALE[%s]: removing AFF_STA[%s] part of the wrong STA_MLD[%s <-> %s]",
                           ale->al_mac_str, aff_sta_mac_str, sta_mld_mac_str, sta->sta_mld ? sta->sta_mld->mac_str : "-");
                map_dm_remove_sta(sta);
                sta = NULL;
            } else if (sta->bss != bss) {
                log_ctrl_i("ALE[%s]: removing AFF_STA[%s] part of the wrong BSS[%s <-> %s]",
                           ale->al_mac_str, aff_sta_mac_str, bssid_str, sta->bss->bssid_str);
                map_dm_remove_sta(sta);
                sta = NULL;
            }
        }

        if (!sta) {
            log_ctrl_i("ALE[%s]: creating AFF_STA[%s] on STA_MLD[%s] and BSSID[%s]", ale->al_mac_str, aff_sta_mac_str, sta_mld_mac_str, bssid_str);
            if (!(sta = map_dm_create_aff_sta(bss, sta_mld, tlv_aff_sta->aff_sta_mac))) {
                log_ctrl_e("could not create AFF_STA[%s] on BSSID[%s] ALE[%s]", aff_sta_mac_str, bssid_str, ale->al_mac_str);
                continue;
            }
        }

        map_dm_unmark_sta(sta);
    }

    map_dm_unmark_sta_mld(sta_mld);

    return 0;
}

/* MAP_R6 17.2.100 */
int map_parse_aff_sta_metrics_tlv(map_ale_info_t *ale, map_aff_sta_metrics_tlv_t *tlv)
{
    map_sta_info_t *sta;
    uint8_t         byte_counter_unit = ale->map_profile >= MAP_PROFILE_2 ?
                                        ale->agent_capability.byte_counter_unit : MAP_BYTE_COUNTER_UNIT_BYTES;
    uint64_t        tx_bytes          = map_convert_mapunits_to_bytes(tlv->tx_bytes, byte_counter_unit);
    uint64_t        rx_bytes          = map_convert_mapunits_to_bytes(tlv->rx_bytes, byte_counter_unit);

    if (!(sta = map_dm_get_sta_from_ale(ale, tlv->sta_mac))) {
        log_ctrl_e("%s: sta[%s] not found", __FUNCTION__, mac_string(tlv->sta_mac));
        return -1;
    }

    sta->traffic_stats.tx_bytes         = tx_bytes;
    sta->traffic_stats.rx_bytes         = rx_bytes;
    sta->traffic_stats.tx_packets       = tlv->tx_packets;
    sta->traffic_stats.rx_packets       = tlv->rx_packets;
    sta->traffic_stats.tx_packet_errors = tlv->tx_packet_errors;
    sta->traffic_stats.rx_packet_errors = 0; /* Not available */
    sta->traffic_stats.retransmissions  = 0; /* Not available */

    return 0;
}

/* MAP_R6 17.2.103 */
int map_parse_eht_operations_tlv(map_ale_info_t *ale, map_eht_operations_tlv_t *tlv)
{
    int i, j;

    if (tlv->radios_nr == 0 || tlv->radios_nr > MAX_RADIO_PER_AGENT) {
        return -1;
    }

    for (i = 0; i < tlv->radios_nr; i++) {
        map_radio_info_t *radio = map_dm_get_radio(ale, tlv->radios[i].ruid);
        if (!radio) {
            log_ctrl_e("%s: radio[%s] not found", __FUNCTION__, mac_string(tlv->radios[i].ruid));
            continue;
        }

        if (!radio->eht_caps && !(radio->eht_caps = calloc(1, sizeof(*radio->eht_caps)))) {
            log_ctrl_e("%s: calloc failed", __FUNCTION__);
            return -1;
        }

        if (tlv->radios[i].bsss_nr == 0 || tlv->radios[i].bsss_nr > MAX_BSS_PER_AGENT) {
            return -1;
        }

        for (j = 0; j < tlv->radios[i].bsss_nr; j++) {
            map_bss_info_t *bss = map_dm_get_bss(radio, tlv->radios[i].bsss[j].bssid);
            if (!bss) {
                log_ctrl_e("%s: bss[%s] not found", __FUNCTION__, mac_string(tlv->radios[i].bsss[j].bssid));
                continue;
            }
            bss->eht_ops = tlv->radios[i].bsss[j].eht_ops;
        }
    }

    return 0;
}
