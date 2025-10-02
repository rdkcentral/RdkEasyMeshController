/*
 * Copyright (c) 2021-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef STUB_MAP_CTRL_CMDU_TX_H_
#define STUB_MAP_CTRL_CMDU_TX_H_

#include "map_ctrl_cmdu_tx.h"

/* Register stub_cmdu_tx_send callback functions
   Example:
        typedef void (*stub_cmdu_tx_send_topology_query_cb_t)(void *args, uint16_t *mid);
        void stub_cmdu_tx_register_send_topology_query_cb(stub_cmdu_tx_topology_query_cb_t cb);
*/


#define STUB_CMDU_TX_CB(name, args) \
    typedef int (*stub_cmdu_tx_send_##name##_cb_t)args; \
    void stub_cmdu_tx_register_send_##name##_cb(stub_cmdu_tx_send_##name##_cb_t cb);

/* 1905.1 */
STUB_CMDU_TX_CB(topology_query,                  (void *args, uint16_t *mid))
STUB_CMDU_TX_CB(link_metric_query,               (map_ale_info_t *ale, i1905_link_metric_query_tlv_t *tlv, uint16_t *mid))
STUB_CMDU_TX_CB(autoconfig_renew,                (uint8_t freq_band, uint16_t *mid, bool reset_onboarding))
STUB_CMDU_TX_CB(autoconfig_renew_ucast,          (map_ale_info_t *ale, uint8_t freq_band, uint16_t *mid, bool reset_onboarding))

/* MAP R1 */
STUB_CMDU_TX_CB(ap_capability_query,             (void *args, uint16_t *mid))
STUB_CMDU_TX_CB(policy_config_request,           (map_ale_info_t *ale, map_policy_config_tlvs_t *tlvs, uint16_t *mid))
STUB_CMDU_TX_CB(channel_preference_query,        (void *args, uint16_t *mid))
STUB_CMDU_TX_CB(client_capability_query,         (void *args, uint16_t *mid))
STUB_CMDU_TX_CB(mld_client_capability_query,     (void *args, uint16_t *mid))
STUB_CMDU_TX_CB(assoc_sta_link_metrics_query,    (void *args, uint16_t *mid))
STUB_CMDU_TX_CB(unassoc_sta_link_metrics_query,  (map_ale_info_t *ale, map_unassoc_sta_link_metrics_query_tlv_t *tlv, uint16_t *mid))
STUB_CMDU_TX_CB(beacon_metrics_query,            (map_ale_info_t *ale, map_beacon_metrics_query_tlv_t *tlv, uint16_t *mid))
STUB_CMDU_TX_CB(combined_infrastructure_metrics, (map_ale_info_t *ale, uint16_t *mid))
STUB_CMDU_TX_CB(client_steering_request,         (map_ale_info_t *ale, map_steer_t *steer, uint16_t *mid))
STUB_CMDU_TX_CB(client_acl_request,              (map_ale_info_t *ale, map_client_assoc_control_request_tlv_t *tlv, uint16_t *mid))
STUB_CMDU_TX_CB(backhaul_steering_request,       (map_ale_info_t *ale, map_backhaul_steering_request_tlv_t *tlv, uint16_t *mid))
STUB_CMDU_TX_CB(higher_layer_data_msg,           (map_ale_info_t *ale, uint8_t protocol, const uint8_t *payload, uint16_t payload_len, uint16_t *mid))

/* MAP R2 */
STUB_CMDU_TX_CB(channel_scan_request,            (map_ale_info_t *ale, map_channel_scan_request_tlv_t *tlv, uint16_t *mid))
STUB_CMDU_TX_CB(cac_request,                     (map_ale_info_t *ale, map_cac_request_tlv_t *tlv, uint16_t *mid))
STUB_CMDU_TX_CB(cac_termination,                 (map_ale_info_t *ale, map_cac_termination_tlv_t *tlv, uint16_t *mid))
STUB_CMDU_TX_CB(backhaul_sta_capability_query,   (map_ale_info_t *ale, uint16_t *mid))

/* MAP R3 */
STUB_CMDU_TX_CB(dpp_cce_indication,              (map_ale_info_t *ale, uint8_t advertise, uint16_t *mid))
STUB_CMDU_TX_CB(proxied_encap_dpp,               (map_ale_info_t *ale, map_1905_encap_dpp_tlv_t *encap_tlv, map_dpp_chirp_value_tlv_t *chirp_tlv, uint16_t *mid))

/* RAW */
STUB_CMDU_TX_CB(raw,                             (char *ifname, mac_addr dmac, mac_addr smac, uint16_t eth_type, uint8_t *data, uint16_t data_len))

#endif /* STUB_MAP_CTRL_CMDU_TX_H_ */
