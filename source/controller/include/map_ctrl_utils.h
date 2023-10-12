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

#ifndef MAP_CTRL_UTILS_H_
#define MAP_CTRL_UTILS_H_

#include "map_utils.h"
#include "map_data_model.h"
#include "map_config.h"

#define IS_ANY_SUBBAND_CHANNEL_SET(channel_set, channel, opclass) (!map_is_no_subband_channel_set(channel_set, channel, opclass))

/** @brief Get controller configuration
 *
 *  @return pointer to config structure
 */
map_controller_cfg_t* get_controller_cfg();

/** @brief Parse client assoc frame
 *
 *  @param sta:             station for which assoc frame needs to be parsed
 *  @param assoc_frame_len: length of assoc frame
 *  @param assoc_frame:     assoc frame
 *  @return                 0 success
 */
int parse_update_client_capability(map_sta_info_t *sta, uint16_t assoc_frame_len, uint8_t* assoc_frame);

/** @brief This function will update the source mac used for CMDU received from the ALE
 *
 *  @param ale:     pointer to ALE node to be updated
 *  @param src_mac: pointer to a mac address
 *  @return None
 */
static inline void map_update_ale_source_mac(map_ale_info_t *ale, uint8_t* src_mac)
{
    maccpy(ale->src_mac, src_mac);
}

/** @brief This function will update the receiving interface of the ALE
 *
 *  @param ale:     pointer to ALE node to be updated
 *  @param if_name: pointer to a string of interface name
 *  @return None
 */
void map_update_ale_receiving_iface(map_ale_info_t *ale, char* if_name);

/** @Brief This function will calculate the onboard state of ale from the
 *  onboard status bits defined in radio state
 *
 *  @param ale:  pointer to ALE node to be updated
 */
void map_recompute_radio_state_and_update_ale_state(map_ale_info_t *ale);

/** @Brief This function will reset the onboard state of a single ale node
 *  available in the controller data model to onboarding state
 */
void map_reset_agent_node_onboarding_status(map_ale_info_t *ale);

/** @Brief This function will reset the onboard state of all ale nodes
 *  available in the controller data model to onboarding state
 */
void map_reset_all_agent_nodes_onboarding_status(void);

/**
 *  @brief This function converts incoming stats' resolution that is in terms of
 *  byte_counter_unit in Profile-2 AP capability TLV to the byte resolution.
 */
uint64_t map_convert_mapunits_to_bytes(uint32_t val, uint8_t unit);

/**
 *  @brief  This function converts scan status flag value of channel scan result
 *  TLV to the meaningful string format.
 */
const char *map_scan_status_to_string(uint8_t scan_status);

/**
 *  @brief  This function converts scan type flag value of channel scan result
 *  TLV to the meaningful string format.
 */
const char* map_scan_type_to_string(uint8_t scan_type);

/**
 *  @brief  Find first radio that supports provided channel.
 *
 *  Checks if channel is supported in op class list received in
 *  AP Basic Capability TLV.
 */
map_radio_info_t *map_find_radio_by_supported_channel(map_ale_info_t *ale, int channel);

/**
 *  @brief  Get supported frequency bands of radio
 */
uint16_t map_get_freq_bands(map_radio_info_t *radio);

/**
 *  @brief  Return true when radio is 5G and supports low and high band
 */
bool map_is_5g_low_high(map_radio_info_t *radio);

/**
 *  @brief  Guess profile used to configure bss.
 */
map_profile_cfg_t *map_get_profile_from_bss(map_bss_info_t *bss);

/**
 *  @brief  Check if this radio has a profile with a wanted bss state (MAP_xxx_BSS)
 */
bool map_radio_has_profile_with_bss_state(map_radio_info_t *radio, uint8_t bss_state);

/**
 *  @brief  Get attribute from WSC message/
 */
uint8_t *map_get_wsc_attr(uint8_t *message, uint16_t message_size, uint16_t attr_type, uint16_t *attr_len);

/**
 * @brief Check if channel is in op class and not its non operable list
 */
bool map_is_channel_in_cap_op_class(map_op_class_t *cap_op_class, uint8_t channel);

/**
 * @brief Get channel preference in op_class list
 */
uint8_t map_get_channel_pref(map_op_class_list_t *list, uint8_t op_class, uint8_t channel);

/**
 *  @brief  Update radio supported channel set based on config and cap_op_class_list.
 */
void map_update_radio_channels(map_radio_info_t *radio);

/**
 *  @brief  Merge 2 op_class lists into 1 (taking lowest preference for each op_class/channel).
 */
int map_merge_pref_op_class_list(map_op_class_list_t *merged_list, map_op_class_list_t *cap_list,
                                 map_op_class_list_t *list1, map_op_class_list_t *list2);

/**
 *  @brief  Optimize op_class list by removing channel lists that contain all channels of an op_class.
 */
void map_optimize_pref_op_class_list(map_op_class_list_t *list, map_op_class_list_t *cap_list);

/**
 *  @brief  Check if none of the subband channels from chan/op_class are present in channels list
 */
bool map_is_no_subband_channel_set(map_channel_set_t *channels, uint8_t chan, uint8_t op_class);

/**
 *  @brief  Check if all of the subband channels from chan/op_class are present in channels list
 */
bool map_is_all_subband_channel_set(map_channel_set_t *channels, uint8_t chan, uint8_t op_class);

/**
 *  @brief  Sort op_classes and channels in op_class list.
 */
void map_sort_op_class_list(map_op_class_list_t *list);

/**
 *  @brief  Check if cac request for radio is valid
 */
bool map_is_cac_request_valid(map_radio_info_t *radio, uint8_t cac_method, uint8_t op_class, uint8_t channel);

/**
 *  @brief  Find local iface of ale based on mac
 */
map_local_iface_t *map_find_local_iface(map_ale_info_t *ale, mac_addr mac);

/**
 *  @brief  Find backhaul sta iface of ale based on mac
 */
map_backhaul_sta_iface_t *map_find_bhsta_iface_from_ale(map_ale_info_t *ale, mac_addr sta_mac);

/**
 *  @brief  Find backhaul sta iface globally based on mac
 */
map_backhaul_sta_iface_t *map_find_bhsta_iface_gbl(mac_addr sta_mac, map_ale_info_t **ret_ale);

/**
 *  @brief  Delete ht/vht/he/wifi6 capability tlv
 */
void map_free_ht_vht_he_wifi6_caps(map_radio_info_t *radio);

/**
 *  @brief  Update global radio caps from ht/vht/he capability tlv
 */
void map_update_radio_caps(map_radio_info_t *radio);

#endif /* MAP_CTRL_UTILS_H_ */
