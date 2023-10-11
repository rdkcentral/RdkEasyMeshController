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

#ifndef MAP_CTRL_CMDU_VALIDATOR_H_
#define MAP_CTRL_CMDU_VALIDATOR_H_

#include "map_data_model.h"
#include "i1905.h"

/*#######################################################################
#                       1905.1 CMDU VALIDATORS                          #
########################################################################*/
/* 1905.1 6.3.1 (type 0x0000) */
int map_validate_topology_discovery(i1905_cmdu_t *cmdu);

/* 1905.1 6.3.2 (type 0x0001) */
int map_validate_topology_query(i1905_cmdu_t *cmdu);

/* 1905.1 6.3.3 (type 0x0002) */
int map_validate_topology_response(i1905_cmdu_t *cmdu);

/* 1905.1 6.3.4 (type 0x0003) */
int map_validate_topology_notification(i1905_cmdu_t *cmdu);

/* 1905.1 6.3.5 (type 0x0005) */
int map_validate_link_metrics_query(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* 1905.1 6.3.6 (type 0x0006) */
int map_validate_link_metrics_response(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* 1905.1 6.3.7 (type 0x0007) */
int map_validate_ap_autoconfig_search(i1905_cmdu_t *cmdu);

/* 1905.1 6.3.9 (type 0x0009) */
int map_validate_ap_autoconfig_wsc(i1905_cmdu_t *cmdu);

/* 1905.1 6.3.13 (type 0x0004) */
int map_validate_vendor_specific(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/*#######################################################################
#                       MAP R1 CMDU VALIDATORS                          #
########################################################################*/
/* MAP_R1 17.1 (type 0x8000) */
int map_validate_ack(UNUSED i1905_cmdu_t *cmdu);

/* MAP_R1 17.1.6 (type 0x8002) */
int map_validate_ap_capability_report(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* MAP_R1 17.1.10 (type 0x8005) */
int map_validate_channel_preference_report(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* MAP_R1 17.1.12 (type 0x8007) */
int map_validate_channel_selection_response(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* MAP_R1 17.1.13 (type 0x8008) */
int map_validate_operating_channel_report(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* MAP_R1 17.1.15 (type 0x800A) */
int map_validate_client_capability_report(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* MAP_R1 17.1.17 (type 0x800C) */
int map_validate_ap_metrics_response(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* MAP_R1 17.1.19 (type 0x800E) */
int map_validate_assoc_sta_link_metrics_response(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* MAP_R1 17.1.21 (type 0x8010) */
int map_validate_unassoc_sta_link_metrics_response(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* MAP_R1 17.1.23 (type 0x8012) */
int map_validate_beacon_metrics_response(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* MAP_R1 17.1.26 (type 0x8015) */
int map_validate_client_steering_btm_report(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* MAP_R1 17.1.28 (type 0x8017) */
int map_validate_steering_completed(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* MAP_R1 17.1.30 (type 0x801A) */
int map_validate_backhaul_steering_response(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* MAP_R1 17.1.31 (type 0x8018) */
int map_validate_higher_layer_data(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/*#######################################################################
#                       MAP R2 CMDU VALIDATORS                          #
########################################################################*/
/* MAP_R2 17.1.34 (type 0x801C) */
int map_validate_channel_scan_report(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* MAP_R2 17.1.39 (type 0x8025) */
int map_validate_assoc_status_notification(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* MAP_R2 17.1.40 (type 0x8026) */
int map_validate_tunneled_msg(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* MAP_R2 17.1.41 (type 0x8022) */
int map_validate_client_disassoc_stats(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* MAP_R2 17.1.43 (type 0x8028) */
int map_validate_backhaul_sta_capability_report(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* MAP_R2 17.1.44 (type 0x8033) */
int map_validate_failed_connection(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/*#######################################################################
#                       MAP R3 CMDU VALIDATORS                          #
########################################################################*/
/* MAP_R3 17.1.48 (type 0x8029) */
int map_validate_proxied_encap_dpp(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* MAP_R3 17.1.49 (type 0x8030) */
int map_validate_1905_encap_eapol(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* MAP_R3 17.1.52 (type 0x802f) */
int map_validate_chirp_notification(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

/* MAP_R3 17.1.56 (type 0x802a) */
int map_validate_direct_encap_dpp(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu);
#endif /* MAP_CTRL_CMDU_VALIDATOR_H_ */
