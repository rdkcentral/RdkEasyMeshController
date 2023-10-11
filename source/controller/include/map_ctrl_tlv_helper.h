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

#ifndef MAP_CTRL_TLV_HELPER_H_
#define MAP_CTRL_TLV_HELPER_H_
#include "i1905.h"

int  map_get_bridging_cap_tlv(i1905_device_bridging_cap_tlv_t *bridging_cap_tlv);
void map_free_bridging_cap_tlv(i1905_device_bridging_cap_tlv_t *bridging_cap_tlv);

int  map_get_1905_neighbor_tlvs(i1905_neighbor_device_list_tlv_t **tlvs, size_t *tlvs_nr);
void map_free_1905_neighbor_tlv(i1905_neighbor_device_list_tlv_t *tlvs, size_t tlvs_nr);

map_error_code_tlv_t *map_get_error_code_tlv(mac_addr sta_mac, uint8_t reason_code);

map_ap_metrics_tlv_t *map_get_ap_metrics_tlv(map_bss_info_t *bss);

i1905_receiver_link_metric_tlv_t *map_get_receiver_link_metric_tlv(mac_addr local_al_mac, map_neighbor_link_metric_t *neighbor_lm);

i1905_transmitter_link_metric_tlv_t *map_get_transmitter_link_metric_tlv(mac_addr local_al_mac, map_neighbor_link_metric_t *neighbor_lm);

void map_fill_channel_preference_tlv(map_channel_preference_tlv_t *tlv, map_radio_info_t *radio, uint8_t pref_type);

void map_fill_transmit_power_tlv(map_transmit_power_limit_tlv_t *tlv, map_radio_info_t *radio);

/* Fill scan request tlv with all 20MHz operating class received in scan capability tlv.
   Optionally set channels != NULL to add only those.
*/
void map_fill_channel_scan_request_tlv(map_channel_scan_request_tlv_t *tlv, map_radio_info_t *radio,
                                       bool fresh_scan, map_channel_set_t *channels);

void map_fill_default_8021q_settings_tlv(map_cfg_t *cfg, map_default_8021q_settings_tlv_t *tlv);

void map_fill_traffic_separation_policy_tlv(map_controller_cfg_t *cfg, uint16_t prim_vid, unsigned int max_vid_count,
                                            map_traffic_separation_policy_tlv_t *tlv);

void map_fill_empty_traffic_separation_policy_tlv(map_traffic_separation_policy_tlv_t *tlv);

#endif /*  MAP_CTRL_TLV_HELPER_H_ */
