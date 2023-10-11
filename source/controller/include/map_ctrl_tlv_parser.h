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

#ifndef MAP_CTRL_TLV_PARSER_H_
#define MAP_CTRL_TLV_PARSER_H_

#include "map_data_model.h"
#include "i1905.h"

/*#######################################################################
#                       1905.1 TLV HANDLERS                             #
########################################################################*/
/* 1905.1 6.4.5 */
int map_parse_device_information_tlv(map_ale_info_t *ale, i1905_device_information_tlv_t *tlv);

/* 1905.1 6.4.8 */
int map_parse_non_1905_neighbor_device_list_tlv(map_ale_info_t *ale, i1905_non_1905_neighbor_device_list_tlv_t **tlvs, size_t tlvs_nr);

/* 1905.1 6.4.9 */
int map_parse_neighbor_device_list_tlv(map_ale_info_t *ale, i1905_neighbor_device_list_tlv_t **tlvs, size_t tlvs_nr);

/*#######################################################################
#                       MAP R1 TLV HANDLERS                             #
########################################################################*/
/* MAP_R1 17.2.1 */
int map_parse_ap_supported_service_tlv(map_ale_info_t *ale, map_supported_service_tlv_t* tlv, bool *is_controller, bool *is_agent, bool *is_em_plus);

/* MAP_R1 17.2.4 */
int map_parse_ap_operational_bss_tlv(map_ale_info_t *ale, map_ap_operational_bss_tlv_t* tlv);

/* MAP_R1 17.2.5 */
int map_parse_assoc_clients_tlv(map_ale_info_t *ale, map_assoc_clients_tlv_t* tlv);

/* MAP_R1 17.2.6 */
int map_parse_ap_cap_tlv(map_ale_info_t *ale, map_ap_cap_tlv_t* tlv);

/* MAP_R1 17.2.7 */
int map_parse_ap_radio_basic_cap_tlv(map_ale_info_t *ale, map_ap_radio_basic_cap_tlv_t* tlv);

/* MAP_R1 17.2.8 */
int map_parse_ap_ht_caps_tlv(map_ale_info_t *ale, map_ap_ht_cap_tlv_t *tlv);

/* MAP_R1 17.2.9 */
int map_parse_ap_vht_caps_tlv(map_ale_info_t *ale, map_ap_vht_cap_tlv_t *tlv);

/* MAP_R1 17.2.10 */
int map_parse_ap_he_caps_tlv(map_ale_info_t *ale, map_ap_he_cap_tlv_t *tlv);

/* MAP_R1 17.2.12 */
int map_parse_ap_metrics_tlv(map_ale_info_t *ale, map_ap_metrics_tlv_t* tlv);

/* MAP_R2 17.2.13 */
int map_parse_channel_preference_tlv(map_ale_info_t *ale, map_channel_preference_tlv_t *tlv);

/* MAP_R2 17.2.14 */
int map_parse_radio_operation_restriction_tlv(map_ale_info_t *ale, map_radio_operation_restriction_tlv_t *tlv);

/* MAP_R1 17.2.20 */
int map_parse_client_assoc_event_tlv(map_ale_info_t *ale, map_client_assoc_event_tlv_t *tlv);

/* MAP_R1 17.2.24 */
int map_parse_assoc_sta_link_metrics_tlv(map_ale_info_t *ale, map_assoc_sta_link_metrics_tlv_t* tlv);

/* MAP_R1 17.2.35 */
int map_parse_assoc_sta_traffic_stats_tlv(map_ale_info_t *ale, map_assoc_sta_traffic_stats_tlv_t* tlv);

/*#######################################################################
#                       MAP R2 TLV HANDLERS                             #
########################################################################*/
/* MAP_R2 17.2.36 */
int map_parse_channel_scan_cap_tlv(map_ale_info_t *ale, map_channel_scan_cap_tlv_t* tlv);

/* MAP_R2 17.2.40 */
int map_parse_channel_scan_result_tlv(map_ale_info_t *ale, map_channel_scan_result_tlv_t* tlv, int last_scan_cnt);

/* MAP_R2 17.2.41 */
int map_parse_timestamp_tlv(map_ale_info_t *ale, map_timestamp_tlv_t* tlv);

/* MAP_R2 17.2.44 */
int map_parse_cac_completion_report_tlv(map_ale_info_t* ale, map_cac_completion_report_tlv_t* tlv);

/* MAP_R2 17.2.45 */
int map_parse_cac_status_report_tlv(map_ale_info_t *ale, map_cac_status_report_tlv_t* tlv);

/* MAP_R2 17.2.46 */
int map_parse_cac_cap_tlv(map_ale_info_t *ale, map_cac_cap_tlv_t* tlv);

/* MAP_R2 17.2.47 */
int map_parse_multiap_profile_tlv(map_ale_info_t *ale, map_multiap_profile_tlv_t* tlv);

/* MAP_R2 17.2.48 */
int map_parse_ap_cap_profile_2_tlv(map_ale_info_t *ale, map_profile2_ap_cap_tlv_t* tlv);

/* MAP_R2 17.2.53 */
int map_parse_assoc_status_notification_tlv(map_ale_info_t *ale, map_assoc_status_notification_tlv_t* tlv);

/* MAP_R2 17.2.59 */
int map_parse_metric_collection_interval_tlv(map_ale_info_t *ale, map_metric_collection_interval_tlv_t* tlv);

/* MAP_R2 17.2.60 */
int map_parse_radio_metrics_tlv(map_ale_info_t *ale, map_radio_metrics_tlv_t* tlv);

/* MAP_R2 17.2.61 */
int map_parse_ap_ext_metrics_response_tlv(map_ale_info_t *ale, map_ap_ext_metrics_tlv_t* tlv);

/* MAP_R2 17.2.62 */
int map_parse_assoc_sta_ext_link_metrics_tlv(map_ale_info_t *ale, map_assoc_sta_ext_link_metrics_tlv_t* tlv);

/* MAP_R2 17.2.65 */
int map_parse_backhaul_sta_radio_capability_tlv(map_ale_info_t *ale, map_backhaul_sta_radio_cap_tlv_t **tlvs, size_t tlvs_nr);

/*#######################################################################
#                       MAP R3 TLV HANDLERS                             #
########################################################################*/
/* MAP_R3 17.2.72 */
int map_parse_ap_wifi6_cap_tlv(map_ale_info_t *ale, map_ap_wifi6_cap_tlv_t *tlv);

/* MAP_R3 17.2.73 */
int map_parse_assoc_wifi6_sta_status_tlv(map_ale_info_t *ale, map_assoc_wifi6_sta_status_tlv_t *tlv);

/* MAP_R3 17.2.76 */
int map_parse_device_inventory_tlv(map_ale_info_t *ale, map_device_inventory_tlv_t *tlv);

/* MAP_R3 17.2.79 */
int map_parse_1905_encap_dpp_tlv(map_ale_info_t *ale, map_1905_encap_dpp_tlv_t *tlv);

/* MAP_R3 17.2.80 */
int map_parse_1905_encap_eapol_tlv(map_ale_info_t *ale, map_1905_encap_eapol_tlv_t *tlv);

/* MAP_R3 17.2.83 */
int map_parse_dpp_chirp_value_tlv(map_ale_info_t *ale, map_dpp_chirp_value_tlv_t *tlv);

/* MAP_R3 17.2.86 */
int map_parse_dpp_message_tlv(map_ale_info_t *ale, map_dpp_message_tlv_t *tlv);

#endif /* MAP_CTRL_TLV_PARSER_H_ */
