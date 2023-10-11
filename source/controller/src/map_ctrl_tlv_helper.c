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
#define LOG_TAG "tlv_helper"

#include "map_ctrl_tlv_helper.h"
#include "map_ctrl_defines.h"
#include "map_ctrl_utils.h"
#include "map_data_model.h"
#include "map_topology_tree.h"
#include "map_info.h"
#include "arraylist.h"
#include "1905_platform.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define min(a,b) ((a) < (b) ? (a) : (b))

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
int map_get_bridging_cap_tlv(i1905_device_bridging_cap_tlv_t *bridging_cap_tlv)
{
    i1905_bridge_t *br        = NULL;
    uint8_t         nr_bridge = 0;
    int             status    = 0;
    int             i, j;

    do {
        if (!bridging_cap_tlv) {
            log_ctrl_e("bridging_cap_tlv is NULL");
            break;
        }

        br = i1905_get_list_of_bridges(&nr_bridge);

        bridging_cap_tlv->tlv_type = TLV_TYPE_DEVICE_BRIDGING_CAPABILITY;
        bridging_cap_tlv->bridging_tuples_nr = nr_bridge;

        if (!br || 0 == nr_bridge) {
            bridging_cap_tlv->bridging_tuples = NULL;
            break;
        }

        bridging_cap_tlv->bridging_tuples = calloc(nr_bridge, sizeof(i1905_bridging_tuple_entry_t));

        for (i = 0; i < nr_bridge; i++) {
            i1905_bridging_tuple_entry_t *bridging_tuple = &bridging_cap_tlv->bridging_tuples[i];

            bridging_tuple->bridging_tuple_macs_nr = br[i].bridged_interfaces_nr;

            if (0 == br[i].bridged_interfaces_nr) {
                bridging_tuple->bridging_tuple_macs = NULL;
                continue;
            }

            bridging_tuple->bridging_tuple_macs = calloc(br[i].bridged_interfaces_nr, sizeof(i1905_bridging_tuple_mac_entry_t));

            for (j = 0; j < br[i].bridged_interfaces_nr; j++) {
                if (strcmp(br[i].bridged_interfaces[j], "")) {
                    i1905_interface_info_t *info = i1905_get_interface_info(br[i].bridged_interfaces[j]);
                    if (info) {
                        maccpy(bridging_tuple->bridging_tuple_macs[j].mac_address, info->mac_address);
                        i1905_free_interface_info(info);
                    }
                }
            }
        }
    } while (0);

    i1905_free_list_of_bridges(br, nr_bridge);

    return status;
}

void map_free_bridging_cap_tlv(i1905_device_bridging_cap_tlv_t *bridging_cap_tlv)
{
    int  i;

    if (bridging_cap_tlv) {
        if (bridging_cap_tlv->bridging_tuples_nr > 0) {
            for (i = 0; i < bridging_cap_tlv->bridging_tuples_nr; i++) {
                free(bridging_cap_tlv->bridging_tuples[i].bridging_tuple_macs);
            }
            free(bridging_cap_tlv->bridging_tuples);
        }
    }
}

static size_t count_neighbors(map_ale_info_t *ale)
{
    map_ale_info_t *neighbor_ale;
    size_t          count = 0;

    foreach_neighbors_of(ale, neighbor_ale) {
        count++;
    }

    return count;
}

int map_get_1905_neighbor_tlvs(i1905_neighbor_device_list_tlv_t **ret_tlvs, size_t *ret_tlvs_nr)
{
    i1905_neighbor_device_list_tlv_t *tlvs;
    map_ale_info_t                   *neighbor_ale;
    map_ale_info_t                   *root_ale;
    bool                              break_loop = false;
    size_t                            tlvs_nr    = 0;
    size_t                            total_nb_nr;
    size_t                            i;

    if (!ret_tlvs || !ret_tlvs_nr) {
        log_ctrl_e("ret_tlvs or ret_tlvs_nr is NULL");
        return -1;
    }

    if (!(root_ale = get_root_ale_node())) {
        return -1;
    }

    total_nb_nr = count_neighbors(root_ale);

    /* Allocate worst case number of TLVs (all behind a different interface) */
    if (!(tlvs = calloc(total_nb_nr, sizeof(i1905_neighbor_device_list_tlv_t)))) {
        return -1;
    }

    foreach_neighbors_of(root_ale, neighbor_ale) {
        i1905_neighbor_device_list_tlv_t *neigh = NULL;

        /* NOTE: it is not allowed to break out of this loop -> on error just iterate until the end... */
        if (break_loop || !neighbor_ale) {
            continue;
        }

        /* Check if interface is already added */
        for (i = 0; i < tlvs_nr; i++) {
            if (0 == maccmp(tlvs[i].local_mac_address, neighbor_ale->upstream_remote_iface_mac)) {
                neigh = &tlvs[i];
                break;
            }
        }

        if (!neigh) {
            neigh = &tlvs[tlvs_nr];
            neigh->tlv_type = TLV_TYPE_NEIGHBOR_DEVICE_LIST;
            maccpy(neigh->local_mac_address, neighbor_ale->upstream_remote_iface_mac);
            neigh->neighbors_nr = 0;
            /* Allocate worst case number of neighbors (all behind this interface) */
            if (!(neigh->neighbors = calloc(total_nb_nr, sizeof(i1905_neighbor_entry_t)))) {
                break_loop = true;
                continue;
            }
            tlvs_nr++;
        }
        maccpy(neigh->neighbors[neigh->neighbors_nr].mac_address, neighbor_ale->al_mac);
        neigh->neighbors[neigh->neighbors_nr].bridge_flag = 0;
        neigh->neighbors_nr++;
    }

    if (break_loop) {
        map_free_1905_neighbor_tlv(tlvs, tlvs_nr);
        tlvs = NULL;
        tlvs_nr = 0;
    }

    *ret_tlvs = tlvs;
    *ret_tlvs_nr = tlvs_nr;

    return break_loop ? -1 : 0;
}

void map_free_1905_neighbor_tlv(i1905_neighbor_device_list_tlv_t *tlvs, size_t tlvs_nr)
{
    size_t i;

    for (i = 0; i < tlvs_nr; i++) {
        free(tlvs[i].neighbors);
    }
    free(tlvs);
}

map_error_code_tlv_t *map_get_error_code_tlv(mac_addr sta_mac, uint8_t reason_code)
{
    map_error_code_tlv_t *tlv;

    /* Input Parameters Validation */
    if (reason_code < MAP_ERROR_CODE_STA_ASSOCIATED || reason_code > MAP_ERROR_CODE_BH_STEERSTEERING_REJECTED_BY_TARGET) {
        log_ctrl_e("invalid error_code_tlv reason[%d]", reason_code);
        return NULL;
    }

    if (!(tlv = calloc(1, sizeof(map_error_code_tlv_t)))) {
        log_ctrl_e("could not allocate error_code_tlv");
        return NULL;
    }

    tlv->tlv_type    = TLV_TYPE_ERROR_CODE;
    tlv->reason_code = reason_code;
    maccpy(tlv->sta_mac, sta_mac);

    return tlv;
}

map_ap_metrics_tlv_t *map_get_ap_metrics_tlv(map_bss_info_t *bss)
{
    map_ap_metrics_tlv_t *tlv;
    uint8_t               i;

    if (!(tlv = calloc(1, sizeof(*tlv)))) {
        return NULL;
    }

    tlv->tlv_type = TLV_TYPE_AP_METRICS;
    maccpy(tlv->bssid, bss->bssid);
    tlv->channel_util = bss->metrics.channel_utilization;
    tlv->stas_nr      = bss->stas_nr;
    tlv->esp_present  = bss->metrics.esp_present | MAP_ESP_INCLUDE_AC_BE_MASK; /* AC_BE shall always be included according to standard */

    if (tlv->esp_present) {
        for (i = 0; i<MAX_ACCESS_CATEGORY; i++) {
            if (bss->metrics.esp_present & (1<<(7-i))) {
                memcpy(&tlv->esp[i], &bss->metrics.esp[i], sizeof(bss->metrics.esp[i]));
            }
        }
    }

    return tlv;
}

i1905_receiver_link_metric_tlv_t *map_get_receiver_link_metric_tlv(mac_addr local_al_mac, map_neighbor_link_metric_t *neighbor_lm)
{
    i1905_receiver_link_metric_tlv_t *tlv;

    if (!(tlv = calloc(1, sizeof(*tlv)))) {
        return NULL;
    }

   tlv->tlv_type = TLV_TYPE_RECEIVER_LINK_METRIC;
   maccpy(tlv->local_al_address,    local_al_mac);
   maccpy(tlv->neighbor_al_address, neighbor_lm->al_mac);
   tlv->receiver_link_metrics_nr = 1;

   if (!(tlv->receiver_link_metrics = calloc(1, sizeof(*tlv->receiver_link_metrics)))) {
       free(tlv);
       return NULL;
   }

   tlv->receiver_link_metrics->intf_type  = neighbor_lm->intf_type;
   maccpy(tlv->receiver_link_metrics->neighbor_interface_address, neighbor_lm->neighbor_iface_mac);
   maccpy(tlv->receiver_link_metrics->local_interface_address,    neighbor_lm->local_iface_mac);

   tlv->receiver_link_metrics->packet_errors    = neighbor_lm->rx_metric.packet_errors;
   tlv->receiver_link_metrics->packets_received = neighbor_lm->rx_metric.packets_received;
   tlv->receiver_link_metrics->rssi             = neighbor_lm->rx_metric.rssi;

   return tlv;
}

i1905_transmitter_link_metric_tlv_t *map_get_transmitter_link_metric_tlv(mac_addr local_al_mac, map_neighbor_link_metric_t *neighbor_lm)
{
    i1905_transmitter_link_metric_tlv_t *tlv;

    if (!(tlv = calloc(1, sizeof(*tlv)))) {
        return NULL;
    }

    tlv->tlv_type = TLV_TYPE_TRANSMITTER_LINK_METRIC;
    maccpy(tlv->local_al_address,    local_al_mac);
    maccpy(tlv->neighbor_al_address, neighbor_lm->al_mac);
    tlv->transmitter_link_metrics_nr = 1;

    if (!(tlv->transmitter_link_metrics = calloc(1, sizeof(*tlv->transmitter_link_metrics)))) {
        free(tlv);
        return NULL;
    }

    maccpy(tlv->transmitter_link_metrics->neighbor_interface_address, neighbor_lm->neighbor_iface_mac);
    maccpy(tlv->transmitter_link_metrics->local_interface_address,    neighbor_lm->local_iface_mac);

    tlv->transmitter_link_metrics->intf_type = neighbor_lm->intf_type;
    tlv->transmitter_link_metrics->packet_errors           = neighbor_lm->tx_metric.packet_errors;
    tlv->transmitter_link_metrics->transmitted_packets     = neighbor_lm->tx_metric.transmitted_packets;
    tlv->transmitter_link_metrics->mac_throughput_capacity = neighbor_lm->tx_metric.mac_throughput_capacity;
    tlv->transmitter_link_metrics->link_availability       = neighbor_lm->tx_metric.link_availability;
    tlv->transmitter_link_metrics->phy_rate                = neighbor_lm->tx_metric.phy_rate;

   return tlv;
}

/* pref_type:
    - MAP_CHAN_SEL_PREF_CONTROLLER: use controller preference "ctrl_pref_op_class_list"
    - MAP_CHAN_SEL_PREF_AGENT:      use agent preference "pref_op_class_list"
    - MAP_CHAN_SEL_PERF_MERGED:     use merged preference "merged_pref_op_class_list"
*/
void map_fill_channel_preference_tlv(map_channel_preference_tlv_t *tlv, map_radio_info_t *radio, uint8_t pref_type)
{
    map_op_class_list_t *op_class_list = &radio->merged_pref_op_class_list; /* default and MAP_CHAN_SEL_PREF_MERGED */
    uint8_t              i;

    if (pref_type == MAP_CHAN_SEL_PREF_CONTROLLER) {
        op_class_list = &radio->ctrl_pref_op_class_list;
    } else if (pref_type == MAP_CHAN_SEL_PREF_AGENT) {
        op_class_list = &radio->pref_op_class_list;
    }

    tlv->tlv_type = TLV_TYPE_CHANNEL_PREFERENCE;
    maccpy(tlv->radio_id, radio->radio_id);

    for (i = 0; i < op_class_list->op_classes_nr && i < MAX_OP_CLASS; i++) {
        map_op_class_t                        *op_class     = &op_class_list->op_classes[i];
        map_channel_preference_tlv_op_class_t *tlv_op_class = &tlv->op_classes[i];

        tlv_op_class->op_class = op_class->op_class;
        tlv_op_class->pref     = op_class->pref;
        tlv_op_class->reason   = op_class->reason;
        map_cs_copy(&tlv_op_class->channels, &op_class->channels);
    }

    tlv->op_classes_nr = i;
}

void map_fill_transmit_power_tlv(map_transmit_power_limit_tlv_t *tlv, map_radio_info_t *radio)
{
    tlv->tlv_type = TLV_TYPE_TRANSMIT_POWER_LIMIT;
    maccpy(tlv->radio_id, radio->radio_id);
    tlv->transmit_power_eirp = radio->tx_pwr_limit;
}

void map_fill_channel_scan_request_tlv(map_channel_scan_request_tlv_t *tlv, map_radio_info_t *radio,
                                       bool fresh_scan, map_channel_set_t *channels)
{
    map_channel_scan_request_tlv_radio_t *rsri = &tlv->radios[0];
    int i;

    memset(tlv, 0, sizeof(map_channel_scan_request_tlv_t));
    tlv->tlv_type             = TLV_TYPE_CHANNEL_SCAN_REQUEST;
    tlv->fresh_scan_performed = fresh_scan ? 1 : 0;
    tlv->radios_nr            = 1;

    maccpy(rsri->radio_id, radio->radio_id);
    rsri->op_classes_nr = 0;

    if (!fresh_scan) {
        return;
    }

    /* Add all 20MHz op classes from scan cap tlv */
    for (i = 0; i < radio->scan_caps.op_class_list.op_classes_nr && rsri->op_classes_nr < MAX_OP_CLASS; i++) {
        map_op_class_t     *op_class     = &radio->scan_caps.op_class_list.op_classes[i];
        map_tlv_op_class_t *tlv_op_class = &rsri->op_classes[rsri->op_classes_nr];
        uint16_t            bw;

        if (0 != map_get_bw_from_op_class(op_class->op_class, &bw) || 20 != bw) {
            continue;
        }

        /* Start with what we received from channel scan capabilities */
        tlv_op_class->op_class = op_class->op_class;
        map_cs_copy(&tlv_op_class->channels, &op_class->channels);

        if (channels) {
            /* If 0 channels then add all supported channels in op_class */
            if (map_cs_nr(&tlv_op_class->channels) == 0) {
                if (0 != map_get_channel_set_from_op_class(op_class->op_class, &tlv_op_class->channels)) {
                    continue;
                }
                map_cs_and(&tlv_op_class->channels, &radio->ctl_channels);
            }

            /* Only keep requested channels */
            map_cs_and(&tlv_op_class->channels, channels);

            /* Skip op_class if no channels set */
            if (map_cs_nr(&tlv_op_class->channels) == 0) {
                continue;
            }
        }

        rsri->op_classes_nr++;
    }
}

void map_fill_default_8021q_settings_tlv(map_cfg_t *cfg, map_default_8021q_settings_tlv_t *tlv)
{
    memset(tlv, 0, sizeof(map_default_8021q_settings_tlv_t));

    tlv->tlv_type        = TLV_TYPE_DEFAULT_8021Q_SETTINGS;
    tlv->primary_vlan_id = cfg->primary_vlan_id;
    tlv->default_pcp     = cfg->default_pcp;
}

void map_fill_traffic_separation_policy_tlv(map_controller_cfg_t *cfg, uint16_t prim_vid, unsigned int max_vid_count,
                                            map_traffic_separation_policy_tlv_t *tlv)
{
    unsigned int i, j, vid_count;
    uint16_t     vid, vids[cfg->num_profiles + 1];  /* +1: primary vid */

    memset(tlv, 0, sizeof(map_traffic_separation_policy_tlv_t));
    tlv->tlv_type = TLV_TYPE_TRAFFIC_SEPARATION_POLICY;

    /* Cannot add vlan if max_vid_count is 0 */
    if (max_vid_count == 0) {
        return;
    }

    /* Primary vlan_id also counts as a distinct vlan */
    vids[0] = prim_vid;
    vid_count = 1;

    /* Loop over all profiles and add vlans */
    for (i = 0; i < cfg->num_profiles && tlv->ssids_nr < MAX_TRAFFIC_SEP_SSID; i++) {
        map_profile_cfg_t *profile = &cfg->profiles[i];

        /* Don't add disabled ones */
        if (!profile->enabled) {
            continue;
        }

        /* Never add dedicated BH... */
        if (!(profile->bss_state & MAP_FRONTHAUL_BSS)) {
            continue;
        }

        /* ...and for FH, use primary vid if unconfigured */
        vid = profile->vlan_id < 0 ? prim_vid : (uint16_t)profile->vlan_id;

        /* Check if this a new vid and if yes check if there are not too many */
        for (j = 0; j < vid_count; j++) {
            if (vid == vids[j]) {
                break;
            }
        }
        if (j == vid_count) {
            if (j < max_vid_count) {
                vids[j] = vid;
                vid_count++;
            } else {
                /* Too many vid... */
                continue;
            }
        }

        /* Check if ssid is already present */
        for (j = 0; j < tlv->ssids_nr; j++) {
            if (tlv->ssids[j].ssid_len == strlen(profile->bss_ssid) &&
                !memcmp(tlv->ssids[j].ssid, profile->bss_ssid, tlv->ssids[j].ssid_len)) {
                break;
            }
        }

        /* Add if needed */
        if (j == tlv->ssids_nr) {
            tlv->ssids[j].ssid_len = strlen(profile->bss_ssid);
            tlv->ssids[j].ssid_len = min(tlv->ssids[j].ssid_len, sizeof(tlv->ssids[j].ssid) - 1);
            memcpy(tlv->ssids[j].ssid, profile->bss_ssid, tlv->ssids[j].ssid_len);
            tlv->ssids[j].vlan_id  = vid;

            tlv->ssids_nr++;
        }
    }
}

void map_fill_empty_traffic_separation_policy_tlv(map_traffic_separation_policy_tlv_t *tlv)
{
    memset(tlv, 0, sizeof(map_traffic_separation_policy_tlv_t));
    tlv->tlv_type = TLV_TYPE_TRAFFIC_SEPARATION_POLICY;
}
