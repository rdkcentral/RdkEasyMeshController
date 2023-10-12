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

#ifndef MAP_CTRL_CMDU_TX_H_
#define MAP_CTRL_CMDU_TX_H_

#include "map_data_model.h"
#include "map_retry_handler.h"

#include "i1905.h"

/* NOTES
x function prototypes:
  - preferred (mid is in/out):
    map_send_xxx(map_ale_info_t *ale, ..., uint16_t *mid);

  - some functions are directly used as retry callback:
    map_send_xxx(void *args, uint16_t *mid);

  - some special cases cannot use ale and have recv_cmdu or dest mac

x mid
  There are three options:
  - NULL: mid is auto-incremented (use MID_NA macro)
  - !NULL && initialized to 0: mid is auto-incremented, value returned
  - !NULL && initialized to !0: specified value is used

x tlvs
  - tlv->tlv_type does not have to be filled in by the caller
*/

#define MID_NA NULL

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
typedef struct {
    map_ale_info_t *ale;
    mac_addr_oui    oui;
    uint64_t        user_mid;
    uint16_t        len;
    uint8_t        *data;
} map_vendor_specific_t;

typedef struct {
    uint16_t  len;
    uint8_t  *data;
} map_vendor_tlv_tuple_t;

typedef struct {
    map_ale_info_t         *ale;
    mac_addr_oui            oui;
    uint64_t                user_mid;
    uint8_t                 tlvs_cnt;
    map_vendor_tlv_tuple_t *tlvs;
} map_vendor_specific_mult_tlv_t;

typedef struct {
    /* more TLVs can be added to this struct */
    map_metric_reporting_policy_tlv_t       *metric_policy_tlv;
    map_steering_policy_tlv_t               *steering_policy_tlv;
    map_unsuccessful_assoc_policy_tlv_t     *unsuccess_assoc_policy_tlv;
    map_channel_scan_reporting_policy_tlv_t *channel_scan_report_policy_tlv;
    int                                      bh_bss_config_tlvs_nr;
    map_backhaul_bss_configuration_tlv_t    *bh_bss_config_tlvs;
    map_default_8021q_settings_tlv_t        *default_8021q_settings_tlv;
    map_traffic_separation_policy_tlv_t     *traffic_separation_policy_tlv;
} map_policy_config_tlvs_t;

typedef struct {
    map_ale_info_t   *ale;
    map_radio_info_t *radio; /* When NULL request is for all radio */
    uint8_t           pref;  /* MAP_CHAN_SEL_PREF_XXX */
} map_chan_select_pref_type_t;

typedef struct {
    mac_addr sta_mac;
    mac_addr target_bssid;
    uint8_t  op_class;
    uint8_t  channel;
    uint8_t  reason;
} map_steer_sta_bssid_t;

typedef struct {
    mac_addr              bssid;
    uint16_t              disassociation_timer;
    uint16_t              opportunity_wnd;
    uint8_t               flags; /* MAP_STEERING_REQUEST_FLAG_xxx */
    uint8_t               sta_bssid_nr;
    map_steer_sta_bssid_t sta_bssid[1]; /* Must be last */
} map_steer_t;

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
int map_send_cmdu(mac_addr dest_mac, i1905_cmdu_t *cmdu, uint16_t *mid);

/*#######################################################################
#                       LLDP                                            #
########################################################################*/
int map_send_lldp_bridge_discovery(i1905_interface_info_t *interface);

/*#######################################################################
#                       1905.1 CMDU                                     #
########################################################################*/
/* 1905.1 6.3.1 (type 0x0000) */
int map_send_topology_discovery(i1905_interface_info_t *interface, uint16_t *mid);

/* 1905.1 6.3.2 (type 0x0001) - args is of type map_ale_info_t */
int map_send_topology_query(void *args, uint16_t *mid);
int map_send_topology_query_with_al_mac(mac_addr al_mac_addr, char *iface, uint16_t *mid);

/* 1905.1 6.3.3 (type 0x0002) */
int map_send_topology_response(mac_addr src_mac, i1905_cmdu_t *recv_cmdu);

/* 1905.1 6.3.5 (type 0x0005) */
int map_send_link_metric_query(map_ale_info_t *ale, i1905_link_metric_query_tlv_t *tlv, uint16_t *mid);

/* 1905.1 6.3.6 (type 0x0006) - MID must be the same as what was used in the request */
int map_send_link_metric_response(map_ale_info_t *ale, uint16_t mid, i1905_transmitter_link_metric_tlv_t *tx_tlvs, int tx_tlvs_nr,
                                  i1905_receiver_link_metric_tlv_t *rx_tlvs, int rx_tlvs_nr);

/* 1905.1 6.3.6 (type 0x0006) - MID must be the same as what was used in the request */
int map_send_link_metric_response_error(map_ale_info_t *ale, uint16_t mid, uint8_t error_code);

/* 1905.1 6.3.8 (type 0x0008) */
int map_send_autoconfig_response(i1905_cmdu_t *recv_cmdu, bool ale_is_agent);

/* 1905.1 6.3.9 (type 0x0009) */
int map_send_autoconfig_wsc_m2(map_ale_info_t *ale, map_radio_info_t *radio, i1905_cmdu_t *recv_cmdu, uint16_t *mid);

/* 1905.1 6.3.10 (type 0x000A) */
int map_send_autoconfig_renew(uint8_t freq_band, uint16_t *mid);

/* 1905.1 6.3.10 (type 0x000A) */
int map_send_autoconfig_renew_ucast(map_ale_info_t *ale, uint8_t freq_band, uint16_t *mid);

/* 1905.1 6.3.13 (type 0x0004) - args is of type map_vendor_specific_t */
int map_send_vendor_specific(void *args, uint16_t *mid);

/* 1905.1 6.3.13 (type 0x0004) - args is of type map_vendor_specific_mult_tlv_t */
int map_send_vendor_specific_mult_tlvs(void *args, uint16_t *mid);

/*#######################################################################
#                       MAP R1 CMDU                                     #
########################################################################*/
/* MAP_R1 17.1 (type 0x8000) */
int map_send_ack(map_ale_info_t *ale, i1905_cmdu_t *recv_cmdu);

/* MAP_R1 17.1 (type 0x8000) */
int map_send_ack_sta_error(map_ale_info_t *ale, i1905_cmdu_t *recv_cmdu, mac_addr *sta_macs, int sta_mac_nr, uint8_t error_code);

/* MAP_R2 17.1.6 (type 0x8001) - args is of type map_ale_info_t */
int map_send_ap_capability_query(void *args, uint16_t *mid);

/* MAP_R1 17.8 (type 0x8003) */
int map_send_policy_config_request(map_ale_info_t *ale, map_policy_config_tlvs_t *tlvs, uint16_t *mid);

/* MAP_R2 17.1.9 (type 0x8004) - args is of type map_ale_info_t */
int map_send_channel_preference_query(void *args, uint16_t *mid);

/* MAP_R2 17.1.11 (type 0x8006) - args is of type map_chan_select_pref_type_t */
int map_send_channel_selection_request(void *args, uint16_t *mid);

/* MAP_R2 17.1.14 (type 0x8009) - args is of type map_sta_info_t */
int map_send_client_capability_query(void *args, uint16_t *mid);

/* MAP_R2 17.1.16 (type 0x800B) */
int map_send_ap_metrics_query(map_ale_info_t *ale, mac_addr *bssids, uint8_t bssid_nr, uint16_t *mid);

/* MAP_R2 17.1.18 (type 0x800D) - args is of type map_sta_info_t */
int map_send_assoc_sta_link_metrics_query(void *args, uint16_t *mid);

/* MAP_R2 17.1.20 (type 0x800F) */
int map_send_unassoc_sta_link_metrics_query(map_ale_info_t *ale, map_unassoc_sta_link_metrics_query_tlv_t *tlv, uint16_t *mid);

/* MAP_R2 17.1.20 (type 0x8012) */
int map_send_beacon_metrics_query(map_ale_info_t *ale, map_beacon_metrics_query_tlv_t *tlv, uint16_t *mid);

/* MAP_R2 17.1.24 (type 0x8013) */
int map_send_combined_infrastructure_metrics(map_ale_info_t *ale, uint16_t *mid);

/* MAP_R2 17.1.25 (type 0x8014) */
int map_send_client_steering_request(map_ale_info_t *ale, map_steer_t *steer, uint16_t *mid);

/* MAP_R2 17.1.27 (type 0x8016) */
int map_send_client_acl_request(map_ale_info_t *ale, map_client_assoc_control_request_tlv_t *tlv, uint16_t *mid);

/* MAP_R2 17.1.29 (type 0x8019) */
int map_send_backhaul_steering_request(map_ale_info_t *ale, map_backhaul_steering_request_tlv_t *tlv, uint16_t *mid);

/* MAP_R1 17.1.31 (type 0x8018) */
int map_send_higher_layer_data_msg(map_ale_info_t *ale, uint8_t protocol, const uint8_t *payload, uint16_t payload_len, uint16_t *mid);

/*#######################################################################
#                       MAP R2 CMDU                                     #
########################################################################*/
/* MAP_R2 17.1.33 (type 0x801B) */
int map_send_channel_scan_request(map_ale_info_t *ale, map_channel_scan_request_tlv_t *tlv, uint16_t *mid);

/* MAP_R2 17.1.35 (type 0x8020) */
int map_send_cac_request(map_ale_info_t *ale, map_cac_request_tlv_t *tlv, uint16_t *mid);

/* MAP_R2 17.1.36 (type 0x8021) */
int map_send_cac_termination(map_ale_info_t *ale, map_cac_termination_tlv_t *tlv, uint16_t *mid);

/* MAP_R2 17.1.42 (type 0x8027) - args is of type map_ale_info_t */
int map_send_backhaul_sta_capability_query(void *args, uint16_t *mid);

/*#######################################################################
#                       MAP R3 CMDU                                     #
########################################################################*/
/* MAP_R3 17.1.48 (type 0x8029) */
int map_send_proxied_encap_dpp(map_ale_info_t *ale, map_1905_encap_dpp_tlv_t *encap_tlv, map_dpp_chirp_value_tlv_t *chirp_tlv, uint16_t *mid);

/* MAP_R3 17.1.49 (type 0x8030) */
int map_send_1905_encap_eapol(map_ale_info_t *ale, map_1905_encap_eapol_tlv_t *encap_eapol_tlv, uint16_t *mid);

/* MAP_R3 17.1.51 (type 0x801D) */
int map_send_dpp_cce_indication(map_ale_info_t *ale, uint8_t advertise, uint16_t *mid);

/* MAP_R3 17.1.52 (type 0x802F) */
int map_send_dpp_chirp_notification(map_dpp_chirp_value_tlv_t *chirp_value_tlv_list, int num_chirp_tlv, uint16_t *mid);

/* MAP_R3 17.1.56 (type 0x802A) */
int map_send_direct_encap_dpp(map_ale_info_t *ale, map_dpp_message_tlv_t *dpp_message_tlv, uint16_t *mid);

/*#######################################################################
#                       RAW                                             #
########################################################################*/
int map_send_raw(char *ifname, mac_addr dmac, mac_addr smac, uint16_t eth_type, uint8_t *data, uint16_t data_len);

#endif /* MAP_CTRL_CMDU_TX_H_ */
