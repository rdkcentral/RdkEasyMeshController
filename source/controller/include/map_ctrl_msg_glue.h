/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef MAP_CTRL_MSG_GLUE_H_
#define MAP_CTRL_MSG_GLUE_H_

#include <stddef.h>
#include "map_data_model.h"
#include "map_info.h"
#include "i1905.h"

void msg_glue_update_ale(map_ale_info_t *ale);
void msg_glue_remove_ale(map_ale_info_t *ale);

void msg_glue_update_interface(map_ale_info_t *ale, map_local_iface_t *interface);
void msg_glue_remove_interface(map_ale_info_t *ale, map_local_iface_t* interface);

void msg_glue_update_link(map_ale_info_t* ale, map_neighbor_link_t* link);
void msg_glue_remove_link(map_ale_info_t* ale, map_neighbor_link_t* link);

void msg_glue_update_radio(map_radio_info_t* radio);
void msg_glue_remove_radio(map_radio_info_t* radio);

void msg_glue_update_bss(map_bss_info_t* bss);
void msg_glue_remove_bss(map_bss_info_t* bss);

void msg_glue_handle_ap_metrics_response(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

void msg_glue_handle_steering_btm_report(map_ale_info_t *ale, map_steering_btm_report_tlv_t *tlv);

void msg_glue_handle_unassoc_sta_link_metrics_response(map_ale_info_t *ale, map_unassoc_sta_link_metrics_response_tlv_t *tlv);

void msg_glue_handle_beacon_metrics_response(map_ale_info_t *ale, map_beacon_metrics_response_tlv_t *tlv);

void msg_glue_handle_association_event(map_ale_info_t *ale, map_client_assoc_event_tlv_t *tlv);

void msg_glue_handle_connection_failed(map_ale_info_t *ale, mac_addr sta_mac, mac_addr bssid, uint16_t status, uint16_t reason);

void msg_glue_handle_disassoc_reason(map_ale_info_t * ale, mac_addr sta_mac, uint16_t reason);

void msg_glue_update_radio_scan_results(map_radio_info_t *radio, bool forced);

void msg_glue_handle_radar_detected(map_radio_info_t *radio, wifi_channel_set *channel_set);

void msg_glue_handle_vendor_specific(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

void msg_glue_configure_channel(map_radio_info_t *radio, int channel, int bandwidth);

void msg_glue_get_configured_channel(map_radio_info_t *radio);

void msg_glue_update_def_pref_channel_list(void);

void msg_glue_send_relay(map_ale_info_t *ale, int type, mac_addr stamac, uint8_t *data, size_t data_len);

void msg_glue_update_info(void);

void msg_glue_debug_cmd(const char *cmd, char *args);

int  msg_glue_init(void);
void msg_glue_fini(void);

#endif /* MAP_CTRL_MSG_GLUE_H_ */
