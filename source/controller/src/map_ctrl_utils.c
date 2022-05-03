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
#define LOG_TAG "utils"

#include "map_ctrl_utils.h"
#include "map_ctrl_cmdu_tx.h"
#include "map_ctrl_topology_tree.h"

#include "map_info.h"
#include "map_80211.h"
#include "map_airdata.h"
#include "arraylist.h"
#include "map_topology_tree.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define min(a,b) ((a) < (b) ? (a) : (b))

/*#######################################################################
#                       PRIVATE FUNCTIONS                               #
########################################################################*/
/* Find op_class that matches op_class_nr/channel
   Note: channel is center channel for 80/160MHz
*/
static map_op_class_t *find_op_class(map_op_class_list_t *list, uint8_t op_class_nr, uint8_t channel, bool in_channel_list)
{
    uint8_t i;

    for (i = 0; i < list->op_classes_nr; i++) {
        map_op_class_t *op_class = &list->op_classes[i];

        /* Channel matches when channel list is empty or it is in the channel list */
        if (op_class->op_class == op_class_nr &&
            is_matching_channel_in_opclass(op_class->op_class, channel) &&
            (op_class->channel_count == 0 ||
             ((in_channel_list && map_is_channel_in_op_class_list(op_class, channel)) ||
              (!in_channel_list && !map_is_channel_in_op_class_list(op_class, channel))))) {
            return op_class;
        }
    }

    return NULL; /* Not found */
}

/* Get preference of op_class_nr/channel */
static uint8_t get_channel_pref(map_op_class_list_t *list, uint8_t op_class_nr, uint8_t channel)
{
    /* Empty channel list or channel must be in channel list */
    map_op_class_t *op_class = find_op_class(list, op_class_nr, channel, true);

    return op_class ? op_class->pref : PREF_SCORE_15;
}

/* Check if op_class_nr/channel is supported in op_class */
static bool is_channel_operable(map_op_class_list_t *cap_list, uint8_t op_class_nr, uint8_t channel)
{
    /* Empty channel list or channel must be NOT in channel list */
    return find_op_class(cap_list, op_class_nr, channel, false);
}

/* Add op_class with pref and channel to list (if not present yet)
   Note: list is guaranteed to be big enough
*/
static void check_add_op_class_channel(map_op_class_list_t *merged_list, map_op_class_list_t *cap_list,
                                       map_op_class_list_t *other_list, map_op_class_t *op_class, uint8_t channel)
{
    map_op_class_t *find_op_class;
    uint8_t         pref, other_pref;
    uint8_t         i;

    /* Do not add static non operable channels */
    if (!is_channel_operable(cap_list, op_class->op_class, channel)) {
        return;
    }

    /* Get pref in other list, and use minimum */
    other_pref = get_channel_pref(other_list, op_class->op_class, channel);
    pref = min(op_class->pref, other_pref);

    /* Do not add max pref */
    if (pref == PREF_SCORE_15) {
        return;
    }

    /* Find op_class/pref... */
    for (i = 0; i < merged_list->op_classes_nr; i++) {
        find_op_class = &merged_list->op_classes[i];

        if (find_op_class->op_class == op_class->op_class && find_op_class->pref == pref) {
            break;
        }
    }

    /* ...op_class/pref not found */
    if (i == merged_list->op_classes_nr) {
        find_op_class = &merged_list->op_classes[merged_list->op_classes_nr++];
        find_op_class->op_class = op_class->op_class;
        find_op_class->pref     = pref;
        find_op_class->reason   = 0; /* TODO... */
    }

    /* Add channel */
    if (!map_is_channel_in_op_class_list(find_op_class, channel) && find_op_class->channel_count < MAX_CHANNEL_PER_OP_CLASS) {
        find_op_class->channel_list[find_op_class->channel_count++] = channel;
    }
}

/* Add all op_classes/channels from add_list to merged_list, using lowest pref from add_list or other_list */
static void merge_pref_op_class_list_add(map_op_class_list_t *merged_list, map_op_class_list_t *cap_list,
                                         map_op_class_list_t *add_list, map_op_class_list_t *other_list)
{
    wifi_channel_set ch_set;
    uint8_t          channel, bw, i, j;

    for (i = 0; i < add_list->op_classes_nr; i++) {
        map_op_class_t *op_class = &add_list->op_classes[i];

        /* Add all channels when channel_count is 0 */
        if (op_class->channel_count == 0) {
            if (0 != get_bw_from_operating_class(op_class->op_class, &bw)) {
                continue;
            }
            if (0 != get_channel_set_for_rclass(op_class->op_class, &ch_set)) {
                continue;
            }

            for (j = 0; j < ch_set.length; j++) {
                /* Use center channel for 80/160 MHz */
                channel = (bw == 20 || bw == 40) ? ch_set.ch[j] : get_mid_freq(ch_set.ch[j], op_class->op_class, bw);

                check_add_op_class_channel(merged_list, cap_list, other_list, op_class, channel);
            }

        } else {
            for (j = 0; j < op_class->channel_count; j++) {
                channel = op_class->channel_list[j];

                check_add_op_class_channel(merged_list, cap_list, other_list, op_class, channel);
            }
        }
    }
}

static int comp_op_class(const void *obj1, const void *obj2)
{
    const map_op_class_t *a = obj1;
    const map_op_class_t *b = obj2;

    /* op_class: low->high, pref: low->high */
    return (a->op_class == b->op_class) ? a->pref - b->pref : a->op_class - b->op_class;
}

static int comp_channel(const void *obj1, const void *obj2)
{
    const uint8_t *a = obj1;
    const uint8_t *b = obj2;

    return *a - *b;
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
map_controller_cfg_t* get_controller_cfg()
{
    return &map_cfg_get()->controller_cfg;
}

void map_update_ale_receiving_iface(map_ale_info_t *ale, char* if_name)
{
    map_strlcpy(ale->iface_name, if_name, sizeof(ale->iface_name));

    /* For local agent, check if located next to controller */
    if (ale->is_local) {
        ale->is_local_colocated = map_is_loopback_iface(ale->iface_name);
    }
}

int parse_update_client_capability(map_sta_info_t *sta, uint16_t assoc_frame_len, uint8_t* assoc_frame)
{
    if (sta == NULL || assoc_frame_len == 0 || assoc_frame == NULL) {
        return -1;
    }

    /* Free the existing memory, and Alloc new memory for assoc_frame.
     * This will make sure, we will maintain one memory for assoc frame
     * irrespective of the function called multiple times for the same sta.
     */
    free(sta->assoc_frame);
    sta->assoc_frame_len = 0;

    /*
     *
     * Freeing of sta->assoc_frame is also taken care in remove_sta();
     * being called when sta disconnects from EBSS.
     *
     * If ever we don't need "sta->assoc_frame", we can free(sta->assoc_frame)
     * the memory and update the sta->assoc_frame_len = 0;
     */

    if (NULL == (sta->assoc_frame = malloc(assoc_frame_len))) {
        log_ctrl_e("failed to allocate assoc frame");
        return -1;
    }


    sta->assoc_frame_len = assoc_frame_len;
    memcpy(sta->assoc_frame, assoc_frame, assoc_frame_len);

    /* Fill in sta capabilities */
    map_80211_parse_assoc_body(&sta->sta_caps, sta->assoc_frame, sta->assoc_frame_len,
                               sta->bss->radio->supported_freq == IEEE80211_FREQUENCY_BAND_5_GHZ,
                               (uint8_t*)sta->bss->ssid, sta->bss->ssid_len);
    return 0;
}

/** Function to recalculate the ale onboarding state based on current radio
    state(with MAP_ONBOARD_DEP_BITMASK in radio state) and updates the ALE
    onboarding state of respective ale in ale data model as well
*/
void map_recompute_radio_state_and_update_ale_state(map_ale_info_t *ale)
{
    map_radio_info_t     *radio;
    map_onboard_status_t  onboard_status = ALE_NODE_ONBOARDING;

    if (ale == NULL) {
        log_ctrl_e("invalid ale node onboarding state computation");
        return;
    }

    map_dm_foreach_radio(ale, radio) {
        if ((radio->state & MAP_ONBOARD_DEP_BITMASK) == MAP_ONBOARD_DEP_BITMASK) {
            onboard_status = ALE_NODE_ONBOARDED;
            break;
        }
    }

    map_dm_ale_set_onboard_status(ale, onboard_status);
}

/* Function resets single ale node status to onboarding state(reset state) */
void map_reset_agent_node_onboarding_status(map_ale_info_t *ale)
{
    map_radio_info_t *radio;
    uint64_t    last_chan_sel_req = 0;

    /* REIMPLEMENT the channel selection request retrigger restriction logic to reset its state as per
        map_refresh_radio_data */
    if (ale->first_chan_sel_req_done) {
        last_chan_sel_req=get_clock_diff_secs(get_current_time(), ale->last_chan_sel_req_time);
    }

    map_dm_foreach_radio(ale, radio) {
        set_radio_state_policy_config_ack_not_received(&radio->state);
        set_radio_state_ap_cap_report_not_received(&radio->state);
        if (ale->first_chan_sel_req_done && last_chan_sel_req > 90) {
            set_radio_state_oper_chan_report_not_received(&radio->state);
            set_radio_state_channel_pref_report_not_received(&radio->state);
        }
        set_radio_state_unconfigured(&radio->state);
    }
    map_dm_ale_set_onboard_status(ale, ALE_NODE_ONBOARDING);
}

/* Function resets all ale node status to onboarding state(reset state)
   This can be due to any system level change in MAP implementation like renew etc.,
*/
void map_reset_all_agent_nodes_onboarding_status(void)
{
    map_ale_info_t   *ale;

    map_dm_foreach_agent_ale(ale) {
        map_reset_agent_node_onboarding_status(ale);
    }
}

uint64_t map_convert_mapunits_to_bytes(uint32_t val, uint8_t unit)
{
    uint64_t conv = val;

    if (unit == MAP_BYTE_COUNTER_UNIT_KIBI_BYTES) {
        conv = conv << 10;
    }

    if (unit == MAP_BYTE_COUNTER_UNIT_MEBI_BYTES) {
        conv = conv << 20;
    }

    return conv;
}

const char *map_scan_status_to_string(uint8_t scan_status)
{
    switch (scan_status) {
        case MAP_SCAN_STATUS_SUCCESS:               return "SUCCESS";
        case MAP_SCAN_STATUS_OPCLASS_NOT_SUPPORTED: return "NOT SUPPORTED";
        case MAP_SCAN_STATUS_TOO_SOON:              return "TOO SOON";
        case MAP_SCAN_STATUS_BUSY:                  return "BUSY";
        case MAP_SCAN_STATUS_NOT_COMPLETED:         return "NOT COMPLETED";
        case MAP_SCAN_STATUS_ABORTED:               return "ABORTED";
        case MAP_SCAN_STATUS_FRESH_NOT_SUPPORTED:   return "FRESH SCAN NOT SUPPORTED";
        default:                                    return "INVALID";
    }
}

const char* map_scan_type_to_string(uint8_t scan_type)
{
    switch (scan_type) {
        case MAP_SCAN_TYPE_PASSIVE: return "PASSIVE";
        case MAP_SCAN_TYPE_ACTIVE:  return "ACTIVE";
        default:                    return "INVALID";
    }
}

bool map_is_channel_in_op_class_list(map_op_class_t *op_class, int channel)
{
    int i;

    for (i = 0; i < op_class->channel_count; i++) {
        if (channel == op_class->channel_list[i]) {
            return true;
        }
    }
    return false;
}

map_radio_info_t *map_find_radio_by_supported_channel(map_ale_info_t *ale, int channel)
{
    map_radio_info_t *radio;
    int               i;

    map_dm_foreach_radio(ale, radio) {
        for (i = 0; i < radio->cap_op_class_list.op_classes_nr; i++) {
            map_op_class_t *op_class = &radio->cap_op_class_list.op_classes[i];

            /* Channel in this op class and not in the non operable list */
            if (is_matching_channel_in_opclass(op_class->op_class, channel) &&
                !map_is_channel_in_op_class_list(op_class, channel)) {
                return radio;
            }
        }
    }

    return NULL;
}

uint16_t map_get_freq_bands(map_radio_info_t *radio)
{
    if (radio->supported_freq == IEEE80211_FREQUENCY_BAND_2_4_GHZ) {
        return MAP_M2_BSS_RADIO2G;
    } else if(radio->supported_freq == IEEE80211_FREQUENCY_BAND_5_GHZ) {
        return radio->band_type_5G & (MAP_M2_BSS_RADIO5GL | MAP_M2_BSS_RADIO5GU);
    } else {
        return 0;
    }
}

bool map_is_5g_low_high(map_radio_info_t *radio)
{
    return (radio->supported_freq == IEEE80211_FREQUENCY_BAND_5_GHZ) &&
           (radio->band_type_5G & MAP_M2_BSS_RADIO5GL) &&
           (radio->band_type_5G & MAP_M2_BSS_RADIO5GU);
}

/* Guess which profile was used to configure this bss - using same logic as in
   map_get_m2_config
*/
map_profile_cfg_t *map_get_profile_from_bss(map_bss_info_t *bss)
{
    map_controller_cfg_t *cfg = get_controller_cfg();
    map_ale_info_t       *ale;
    map_radio_info_t     *radio;
    uint16_t              freq_bands;
    bool                  is_gateway;
    size_t                i;

    if (!bss || !(radio = bss->radio) || !(ale = radio->ale)) {
        return NULL;
    }

    freq_bands = map_get_freq_bands(radio);
    is_gateway = map_is_local_agent(ale);

    for (i = 0; i < cfg->num_profiles; i++) {
        map_profile_cfg_t *profile = &cfg->profiles[i];
        int                ssid_len = strlen(profile->bss_ssid);

        if (WFA_CERT() && memcmp(profile->al_mac, ale->al_mac, MAC_ADDR_LEN)) {
            continue;
        }

        if (ssid_len != bss->ssid_len || memcmp(profile->bss_ssid, bss->ssid, ssid_len)) {
            continue;
        }

        if ((is_gateway  && !profile->gateway) ||
            (!is_gateway && !profile->extender)) {
            continue;
        }

        if (!(profile->bss_freq_bands & freq_bands)) {
            continue;
        }

        /* FOUND */
        return profile;
    }

    return NULL;
}

uint8_t *map_get_wsc_attr(uint8_t *message, uint16_t message_size, uint16_t attr_type, uint16_t *attr_len)
{
    uint8_t *p = message;

    while (p - message < message_size) {
        uint16_t t;

        _E2B(&p, &t);
        _E2B(&p, attr_len);

        if (t == attr_type) {
            return p;
        }
        p += *attr_len;
    }

    return NULL;
}

int map_merge_pref_op_class_list(map_op_class_list_t *merged_list, map_op_class_list_t *cap_list,
                                 map_op_class_list_t *list1, map_op_class_list_t *list2)
{
    merged_list->op_classes_nr = 0;

    /* Result cannot have more op_classes than the sum of list1 and list2 */
    merged_list->op_classes = calloc(list1->op_classes_nr + list2->op_classes_nr, sizeof(map_op_class_t));
    if (!merged_list->op_classes) {
        return -1;
    }

    /* Add list 1 */
    merge_pref_op_class_list_add(merged_list, cap_list, list1, list2);

    /* Add list 2 */
    merge_pref_op_class_list_add(merged_list, cap_list, list2, list1);

    /* Clear channel lists when they contain all channels of an op class */
    map_optimize_pref_op_class_list(merged_list, cap_list);

    /* Sort op_classes and channels */
    map_sort_op_class_list(merged_list);

    return 0;
}

void map_optimize_pref_op_class_list(map_op_class_list_t *list, map_op_class_list_t *cap_list)
{
    wifi_channel_set ch_set;
    uint8_t          channel, bw, i, j;

    for (i = 0; i < list->op_classes_nr; i++) {
        map_op_class_t *op_class = &list->op_classes[i];
        bool            all      = true;

        if (0 != get_bw_from_operating_class(op_class->op_class, &bw)) {
            continue;
        }
        if (0 != get_channel_set_for_rclass(op_class->op_class, &ch_set)) {
            continue;
        }

        for (j = 0; j < ch_set.length; j++) {
            /* Use center channel for 80/160 MHz */
            channel = (bw == 20 || bw == 40) ? ch_set.ch[j] : get_mid_freq(ch_set.ch[j], op_class->op_class, bw);

            /* Skip static non operable channels */
            if (!is_channel_operable(cap_list, op_class->op_class, channel)) {
                continue;
             }

            if (!map_is_channel_in_op_class_list(op_class, channel)) {
                all = false;
            }
        }

        if (all) {
            op_class->channel_count = 0;
            memset(op_class->channel_list, 0, sizeof(op_class->channel_list));
        }
    }
}

void map_sort_op_class_list(map_op_class_list_t *list)
{
    int i;

    qsort(list->op_classes, list->op_classes_nr, sizeof(map_op_class_t), comp_op_class);

    for (i = 0; i < list->op_classes_nr; i++) {
        map_op_class_t *op_class = &list->op_classes[i];

        qsort(op_class->channel_list, op_class->channel_count, sizeof(uint8_t), comp_channel);
    }
}

bool map_is_cac_request_valid(map_radio_info_t *radio, uint8_t cac_method, uint8_t op_class, uint8_t channel)
{
    int8_t method_idx   = -1;
    int8_t op_class_idx = -1;
    int    i;

    /* Search method */
    for (i = 0; i < radio->cac_caps.cac_method_count; i++) {
        if (radio->cac_caps.cac_method[i].cac_method == cac_method) {
            method_idx = i;
            break;
        }
    }

    if (method_idx == -1) {
        log_ctrl_i("CAC request method[%u] is not valid for radio[%s]", cac_method, radio->radio_id_str);
        return false;
    }

    /* Search op_class */
    for (i = 0; i < radio->cac_caps.cac_method[method_idx].op_class_list.op_classes_nr; i++) {
        if (radio->cac_caps.cac_method[method_idx].op_class_list.op_classes[i].op_class == op_class) {
            op_class_idx = i;
            break;
        }
    }

    if (op_class_idx == -1) {
        log_ctrl_i("CAC request op_class[%u] is not valid for radio[%s]", op_class, radio->radio_id_str);
        return false;
    }

    /* Search channel */
    for (i = 0; i < radio->cac_caps.cac_method[method_idx].op_class_list.op_classes[op_class_idx].channel_count; i++) {
        if (radio->cac_caps.cac_method[method_idx].op_class_list.op_classes[op_class_idx].channel_list[i] == channel) {
            return true;
        }
    }

    log_ctrl_i("CAC request channel[%u] is not valid for radio[%s]", channel, radio->radio_id_str);

    return false;
}

map_local_iface_t *map_find_local_iface(map_ale_info_t *ale, mac_addr mac)
{
    size_t i;

    for (i = 0; i < ale->local_iface_count; i++) {
        map_local_iface_t *iface = &ale->local_iface_list[i];

        if (!maccmp(iface->mac_address, mac)) {
            return iface;
        }
    }

    return NULL;
}
