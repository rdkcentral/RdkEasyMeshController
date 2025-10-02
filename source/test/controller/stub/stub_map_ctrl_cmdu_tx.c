/*
 * Copyright (c) 2021-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#include "stub_map_ctrl_cmdu_tx.h"

/* Macros for stub callbacks */
#define STUB_CB(name) \
    static stub_cmdu_tx_send_##name##_cb_t g_send_##name##_cb; \
    void stub_cmdu_tx_register_send_##name##_cb(stub_cmdu_tx_send_##name##_cb_t cb) {g_send_##name##_cb = cb;}

#define CALL_CB(name, ...) \
    g_send_##name##_cb ? g_send_##name##_cb(__VA_ARGS__) : 0

/* LLDP */
int map_send_lldp_bridge_discovery(i1905_interface_info_t *interface)
{
    return 0;
}

/* 1905.1 */
STUB_CB(topology_query)
STUB_CB(link_metric_query)
STUB_CB(autoconfig_renew)
STUB_CB(autoconfig_renew_ucast)

int map_send_topology_discovery(i1905_interface_info_t *interface, uint16_t *mid)
{
    return 0;
}

int map_send_topology_query_with_al_mac(mac_addr al_mac_addr, char *iface, uint16_t *mid)
{
    return 0;
}

int map_send_topology_query(void *args, uint16_t *mid)
{
    return CALL_CB(topology_query, args, mid);
}

int map_send_topology_response(mac_addr src_mac, i1905_cmdu_t *recv_cmdu)
{
    return 0;
}

int map_send_link_metric_query(map_ale_info_t *ale, i1905_link_metric_query_tlv_t *tlv, uint16_t *mid)
{
    return CALL_CB(link_metric_query, ale, tlv, mid);
}

int map_send_link_metric_response(map_ale_info_t *ale, uint16_t mid, i1905_transmitter_link_metric_tlv_t *tx_tlvs, int tx_tlvs_nr,
                                  i1905_receiver_link_metric_tlv_t *rx_tlvs, int rx_tlvs_nr)
{
    return 0;
}

int map_send_link_metric_response_error(map_ale_info_t *ale, uint16_t mid, uint8_t error_code)
{
    return 0;
}

int map_send_autoconfig_search(void)
{
    return 0;
}

int map_send_autoconfig_response(i1905_cmdu_t *recv_cmdu, bool ale_is_agent)
{
    return 0;
}

int map_send_autoconfig_wsc_m2(map_ale_info_t *ale, map_radio_info_t *radio, i1905_cmdu_t *recv_cmdu, uint16_t *mid)
{
    return 0;
}


int map_send_autoconfig_renew(uint8_t freq_band, uint16_t *mid, bool reset_onboarding)
{
    return CALL_CB(autoconfig_renew, freq_band, mid, reset_onboarding);
}

int map_send_autoconfig_renew_ucast(map_ale_info_t *ale, uint8_t freq_band, uint16_t *mid, bool reset_onboarding)
{
    return CALL_CB(autoconfig_renew_ucast, ale, freq_band, mid, reset_onboarding);
}

int map_send_vendor_specific(void *args, uint16_t *mid)
{
    return 0;
}

int map_send_vendor_specific_mult_tlvs(void *args, uint16_t *mid)
{
    return 0;
}

/* MAP R1 */
STUB_CB(ap_capability_query)
STUB_CB(policy_config_request)
STUB_CB(channel_preference_query)
STUB_CB(client_capability_query)
STUB_CB(mld_client_capability_query)
STUB_CB(assoc_sta_link_metrics_query)
STUB_CB(unassoc_sta_link_metrics_query)
STUB_CB(beacon_metrics_query)
STUB_CB(combined_infrastructure_metrics)
STUB_CB(client_steering_request)
STUB_CB(client_acl_request)
STUB_CB(backhaul_steering_request)
STUB_CB(higher_layer_data_msg)

int map_send_ack(map_ale_info_t *ale, i1905_cmdu_t *recv_cmdu)
{
    return 0;
}

int map_send_ack_sta_error(map_ale_info_t *ale, i1905_cmdu_t *recv_cmdu, mac_addr *sta_macs, int sta_mac_nr, uint8_t error_code)
{
    return 0;
}

int map_send_ap_capability_query(void *args, uint16_t *mid)
{
    return CALL_CB(ap_capability_query, args, mid);
}

int map_send_policy_config_request(map_ale_info_t *ale, map_policy_config_tlvs_t *tlvs, uint16_t *mid)
{
    return CALL_CB(policy_config_request, ale, tlvs, mid);
}

int map_send_channel_preference_query(void *args, uint16_t *mid)
{
    return CALL_CB(channel_preference_query, args, mid);
}

int map_send_channel_selection_request(void *args, uint16_t *mid)
{
    return 0;
}

int map_send_client_capability_query(void *args, uint16_t *mid)
{
    return CALL_CB(client_capability_query, args, mid);
}

int map_send_mld_client_capability_query(void *args, uint16_t *mid)
{
    return CALL_CB(mld_client_capability_query, args, mid);
}

int map_send_ap_metrics_query(map_ale_info_t *ale, mac_addr *bssids, uint8_t bssid_nr, uint16_t *mid)
{
    return 0;
}

int map_send_assoc_sta_link_metrics_query(void *args, uint16_t *mid)
{
    return CALL_CB(assoc_sta_link_metrics_query, args, mid);
}

int map_send_unassoc_sta_link_metrics_query(map_ale_info_t *ale, map_unassoc_sta_link_metrics_query_tlv_t *tlv, uint16_t *mid)
{
    return CALL_CB(unassoc_sta_link_metrics_query, ale, tlv, mid);
}

int map_send_beacon_metrics_query(map_ale_info_t *ale, map_beacon_metrics_query_tlv_t *tlv, uint16_t *mid)
{
    return CALL_CB(beacon_metrics_query, ale, tlv, mid);
}

int map_send_combined_infrastructure_metrics(map_ale_info_t *ale, uint16_t *mid)
{
    return CALL_CB(combined_infrastructure_metrics, ale, mid);
}

int map_send_client_steering_request(map_ale_info_t *ale, map_steer_t *steer, uint16_t *mid)
{
    return CALL_CB(client_steering_request, ale, steer, mid);
}

int map_send_client_acl_request(map_ale_info_t *ale, map_client_assoc_control_request_tlv_t *tlv, uint16_t *mid)
{
    return CALL_CB(client_acl_request, ale, tlv, mid);
}

int map_send_backhaul_steering_request(map_ale_info_t *ale, map_backhaul_steering_request_tlv_t *tlv, uint16_t *mid)
{
    return CALL_CB(backhaul_steering_request, ale, tlv, mid);
}

int map_send_higher_layer_data_msg(map_ale_info_t *ale, uint8_t protocol, const uint8_t *payload, uint16_t payload_len, uint16_t *mid)
{
    return CALL_CB(higher_layer_data_msg, ale, protocol, payload, payload_len, mid);
}

/* MAP R2 */
STUB_CB(channel_scan_request)
STUB_CB(cac_request)
STUB_CB(cac_termination)
STUB_CB(backhaul_sta_capability_query)

int map_send_agent_list_message(map_ale_info_t *ale, uint16_t *mid)  {
    return 0;
}

int map_send_channel_scan_request(map_ale_info_t *ale, map_channel_scan_request_tlv_t *tlv, uint16_t *mid)
{
    return CALL_CB(channel_scan_request, ale, tlv, mid);
}

int map_send_cac_request(map_ale_info_t *ale, map_cac_request_tlv_t *tlv, uint16_t *mid)
{
    return CALL_CB(cac_request, ale, tlv, mid);
}

int map_send_cac_termination(map_ale_info_t *ale, map_cac_termination_tlv_t *tlv, uint16_t *mid)
{
    return CALL_CB(cac_termination, ale, tlv, mid);
}

int map_send_backhaul_sta_capability_query(void *args, uint16_t *mid)
{
    return CALL_CB(backhaul_sta_capability_query, args, mid);
}

/* MAP R3 */
STUB_CB(dpp_cce_indication)
STUB_CB(proxied_encap_dpp)

int map_send_dpp_cce_indication(map_ale_info_t *ale, uint8_t advertise, uint16_t *mid)
{
    return CALL_CB(dpp_cce_indication, ale, advertise, mid);
}

int map_send_proxied_encap_dpp(map_ale_info_t *ale, map_1905_encap_dpp_tlv_t *encap_tlv, map_dpp_chirp_value_tlv_t *chirp_tlv, uint16_t *mid)
{
    return CALL_CB(proxied_encap_dpp, ale, encap_tlv, chirp_tlv, mid);
}

/* RAW */
STUB_CB(raw)

int map_send_raw(char *ifname, mac_addr dmac, mac_addr smac, uint16_t eth_type, uint8_t *data, uint16_t data_len)
{
    return CALL_CB(raw, ifname, dmac, smac, eth_type, data, data_len);
}
