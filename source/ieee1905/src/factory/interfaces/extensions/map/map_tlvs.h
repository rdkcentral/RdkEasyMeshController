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

/*
 *  Broadband Forum IEEE 1905.1/1a stack
 *
 *  Copyright (c) 2017, Broadband Forum
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  Subject to the terms and conditions of this license, each copyright
 *  holder and contributor hereby grants to those receiving rights under
 *  this license a perpetual, worldwide, non-exclusive, no-charge,
 *  royalty-free, irrevocable (except for failure to satisfy the
 *  conditions of this license) patent license to make, have made, use,
 *  offer to sell, sell, import, and otherwise transfer this software,
 *  where such license applies only to those patent claims, already
 *  acquired or hereafter acquired, licensable by such copyright holder or
 *  contributor that are necessarily infringed by:
 *
 *  (a) their Contribution(s) (the licensed copyrights of copyright holders
 *      and non-copyrightable additions of contributors, in source or binary
 *      form) alone; or
 *
 *  (b) combination of their Contribution(s) with the work of authorship to
 *      which such Contribution(s) was added by such copyright holder or
 *      contributor, if, at the time the Contribution is added, such addition
 *      causes such combination to be necessarily infringed. The patent
 *      license shall not apply to any other combinations which include the
 *      Contribution.
 *
 *  Except as expressly stated above, no rights or licenses from any
 *  copyright holder or contributor is granted under this license, whether
 *  expressly, by implication, estoppel or otherwise.
 *
 *  DISCLAIMER
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 *  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 *  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 *  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 *  DAMAGE.
 */

#ifndef MAP_TLVS_H_
#define MAP_TLVS_H_

#include "platform.h"
#include "map_common_defines.h"
#include "map_data_model.h"
#include "map_emex_tlvs.h"

/*#######################################################################
# MAP R1 TLV types                                                      #
########################################################################*/
#define TLV_TYPE_SUPPORTED_SERVICE                        0x80
#define TLV_TYPE_SEARCHED_SERVICE                         0x81
#define TLV_TYPE_AP_RADIO_IDENTIFIER                      0x82
#define TLV_TYPE_AP_OPERATIONAL_BSS                       0x83
#define TLV_TYPE_ASSOCIATED_CLIENTS                       0x84
#define TLV_TYPE_AP_RADIO_BASIC_CAPABILITIES              0x85
#define TLV_TYPE_AP_HT_CAPABILITIES                       0x86
#define TLV_TYPE_AP_VHT_CAPABILITIES                      0x87
#define TLV_TYPE_AP_HE_CAPABILITIES                       0x88
#define TLV_TYPE_STEERING_POLICY                          0x89
#define TLV_TYPE_METRIC_REPORTING_POLICY                  0x8A
#define TLV_TYPE_CHANNEL_PREFERENCE                       0x8B
#define TLV_TYPE_RADIO_OPERATION_RESTRICTION              0x8C
#define TLV_TYPE_TRANSMIT_POWER_LIMIT                     0x8D
#define TLV_TYPE_CHANNEL_SELECTION_RESPONSE               0x8E
#define TLV_TYPE_OPERATING_CHANNEL_REPORT                 0x8F
#define TLV_TYPE_CLIENT_INFO                              0x90
#define TLV_TYPE_CLIENT_CAPABILITY_REPORT                 0x91
#define TLV_TYPE_CLIENT_ASSOCIATION_EVENT                 0x92
#define TLV_TYPE_AP_METRIC_QUERY                          0x93
#define TLV_TYPE_AP_METRICS                               0x94
#define TLV_TYPE_STA_MAC_ADDRESS                          0x95
#define TLV_TYPE_ASSOCIATED_STA_LINK_METRICS              0x96
#define TLV_TYPE_UNASSOCIATED_STA_LINK_METRICS_QUERY      0x97
#define TLV_TYPE_UNASSOCIATED_STA_LINK_METRICS_RESPONSE   0x98
#define TLV_TYPE_BEACON_METRICS_QUERY                     0x99
#define TLV_TYPE_BEACON_METRICS_RESPONSE                  0x9A
#define TLV_TYPE_STEERING_REQUEST                         0x9B
#define TLV_TYPE_STEERING_BTM_REPORT                      0x9C
#define TLV_TYPE_CLIENT_ASSOCIATION_CONTROL_REQUEST       0x9D
#define TLV_TYPE_BACKHAUL_STEERING_REQUEST                0x9E
#define TLV_TYPE_BACKHAUL_STEERING_RESPONSE               0x9F
#define TLV_TYPE_HIGHER_LAYER_DATA                        0xA0
#define TLV_TYPE_AP_CAPABILITY                            0xA1
#define TLV_TYPE_ASSOCIATED_STA_TRAFFIC_STATS             0xA2
#define TLV_TYPE_ERROR_CODE                               0xA3

/*#######################################################################
# MAP R2 TLV types                                                      #
########################################################################*/
#define TLV_TYPE_CHANNEL_SCAN_REPORTING_POLICY            0xA4
#define TLV_TYPE_CHANNEL_SCAN_CAPABILITIES                0xA5
#define TLV_TYPE_CHANNEL_SCAN_REQUEST                     0xA6
#define TLV_TYPE_CHANNEL_SCAN_RESULT                      0xA7
#define TLV_TYPE_TIMESTAMP                                0xA8
#define TLV_TYPE_CAC_REQUEST                              0xAD
#define TLV_TYPE_CAC_TERMINATION                          0xAE
#define TLV_TYPE_CAC_COMPLETION_REPORT                    0xAF
#define TLV_TYPE_CAC_STATUS_REPORT                        0xB1
#define TLV_TYPE_CAC_CAPABILITIES                         0xB2
#define TLV_TYPE_MULTIAP_PROFILE                          0xB3
#define TLV_TYPE_PROFILE2_AP_CAPABILITY                   0xB4
#define TLV_TYPE_DEFAULT_8021Q_SETTINGS                   0xB5
#define TLV_TYPE_TRAFFIC_SEPARATION_POLICY                0xB6
#define TLV_TYPE_PROFILE2_ERROR_CODE                      0xBC
#define TLV_TYPE_AP_RADIO_ADVANCED_CAPABILITIES           0xBE
#define TLV_TYPE_ASSOCIATION_STATUS_NOTIFICATION          0xBF
#define TLV_TYPE_SOURCE_INFO                              0xC0
#define TLV_TYPE_TUNNELED_MESSAGE_TYPE                    0xC1
#define TLV_TYPE_TUNNELED                                 0xC2
#define TLV_TYPE_PROFILE2_STEERING_REQUEST                0xC3
#define TLV_TYPE_UNSUCCESSFUL_ASSOCIATION_POLICY          0xC4
#define TLV_TYPE_METRIC_COLLECTION_INTERVAL               0xC5
#define TLV_TYPE_RADIO_METRICS                            0xC6
#define TLV_TYPE_AP_EXTENDED_METRICS                      0xC7
#define TLV_TYPE_ASSOCIATED_STA_EXTENDED_LINK_METRICS     0xC8
#define TLV_TYPE_STATUS_CODE                              0xC9
#define TLV_TYPE_REASON_CODE                              0xCA
#define TLV_TYPE_BACKHAUL_STA_RADIO_CAPABILITIES          0xCB
#define TLV_TYPE_BACKHAUL_BSS_CONFIGURATION               0xD0

/*#######################################################################
# MAP R3 TLV types                                                      #
########################################################################*/
#define TLV_TYPE_AP_WIFI6_CAPABILITIES                    0xAA
#define TLV_TYPE_ASSOCIATED_WIFI6_STA_STATUS_REPORT       0xB0
#define TLV_TYPE_ENCRYPTED_PAYLOAD                        0xAC
#define TLV_TYPE_BSSID                                    0xB8
#define TLV_TYPE_DPP_CCE_INDICATION                       0xD2
#define TLV_TYPE_1905_ENCAP_DPP                           0xCD
#define TLV_TYPE_1905_ENCAP_EAPOL                         0xCE
#define TLV_TYPE_DPP_MESSAGE                              0xD1
#define TLV_TYPE_DPP_CHIRP_VALUE                          0xD3
#define TLV_TYPE_DEVICE_INVENTORY                         0xD4

/*#######################################################################
# Types used in other TLV                                               #
########################################################################*/
typedef struct  {
    uint8_t           op_class;
    map_channel_set_t channels;
} map_tlv_op_class_t;

/*#######################################################################
# Supported service TLV associated structures ("Section 17.2.1")        #
########################################################################*/
#define MAP_SERVICE_CONTROLLER          0x00
#define MAP_SERVICE_AGENT               0x01
#define MAP_SERVICE_EMEX_CONTROLLER     0xA0
#define MAP_SERVICE_EMEX_AGENT          0xA1
#define MAX_SERVICE            8

typedef struct mapSupportedServiceTLV {
    uint8_t  tlv_type;
    uint8_t  services_nr;
    uint8_t  services[MAX_SERVICE];
} map_supported_service_tlv_t;

/*#######################################################################
# Searched service TLV associated structures ("Section 17.2.2")         #
########################################################################*/
typedef struct mapSearchedServiceTLV {
    uint8_t tlv_type;
    uint8_t services_nr;
    uint8_t services[MAX_SERVICE];
} map_searched_service_tlv_t;

/*#######################################################################
# AP radio identifier TLV associated structures ("Section 17.2.3")      #
########################################################################*/
typedef struct mapApRadioIdTLV {
    uint8_t  tlv_type;
    mac_addr radio_id;
} map_ap_radio_identifier_tlv_t;

/*#######################################################################
# AP operational BSS TLV associated structures ("Section 17.2.4")       #
########################################################################*/
typedef struct {
    mac_addr bssid;
    uint8_t  ssid_len;
    uint8_t  ssid[MAX_SSID_LEN];
} map_ap_operational_bss_tlv_bss_t;

typedef struct {
    mac_addr                         radio_id;
    uint8_t                          bsss_nr;
    map_ap_operational_bss_tlv_bss_t bsss[MAX_BSS_PER_RADIO];
} map_ap_operational_bss_tlv_radio_t;

typedef struct mapApOperationalBssTLV {
    uint8_t                            tlv_type;
    uint8_t                            radios_nr;
    map_ap_operational_bss_tlv_radio_t radios[MAX_RADIO_PER_AGENT];
} map_ap_operational_bss_tlv_t;

/*#######################################################################
# Associated clients TLV associated structures ("Section 17.2.5")       #
########################################################################*/
typedef struct {
    mac_addr mac;
    uint16_t assoc_time;
} map_assoc_clients_tlv_sta_t;

typedef struct {
    mac_addr                     bssid;
    uint16_t                     stas_nr;
    map_assoc_clients_tlv_sta_t *stas;
} map_assoc_clients_tlv_bss_t;

typedef struct mapAssociatedClientsTLV {
    uint8_t                     tlv_type;
    uint8_t                     bsss_nr;
    map_assoc_clients_tlv_bss_t bsss[MAX_BSS_PER_RADIO];
} map_assoc_clients_tlv_t;

/*#######################################################################
# AP capability TLV associated structures ("Section 17.2.6")            #
########################################################################*/
typedef struct mapAPCapabilityTLV {
    uint8_t tlv_type;
    uint8_t operating_unsupported_link_metrics:     1;
    uint8_t non_operating_unsupported_link_metrics: 1;
    uint8_t agent_initiated_steering:               1;
    uint8_t reserved:                               5;
} map_ap_cap_tlv_t;

/*##########################################################################
# AP radio basic capabilities TLV associated structures ("Section 17.2.7") #
###########################################################################*/
typedef struct {
    uint8_t           op_class;
    uint8_t           eirp;
    map_channel_set_t channels;
} map_ap_radio_basic_cap_tlv_op_class_t;

typedef struct mapApRadioBasicCapabilitiesTLV {
    uint8_t                               tlv_type;
    mac_addr                              radio_id;
    uint8_t                               max_bss;
    uint8_t                               op_classes_nr;
    map_ap_radio_basic_cap_tlv_op_class_t op_classes[MAX_OP_CLASS];
} map_ap_radio_basic_cap_tlv_t;

/*#######################################################################
# AP HT capabilities TLV associated structures ("Section 17.2.8")       #
########################################################################*/
typedef struct mapAPHTCapabilityTLV {
    uint8_t  tlv_type;
    mac_addr radio_id;
    uint8_t  max_supported_tx_streams: 2;
    uint8_t  max_supported_rx_streams: 2;
    uint8_t  gi_support_20mhz:         1;
    uint8_t  gi_support_40mhz:         1;
    uint8_t  ht_support_40mhz:         1;
    uint8_t  reserved:                 1;
} map_ap_ht_cap_tlv_t;

/*#######################################################################
# AP VHT capabilities TLV associated structures ("Section 17.2.9")      #
########################################################################*/
typedef struct mapAPVHTCapabilityTLV {
    uint8_t  tlv_type;
    mac_addr radio_id;
    uint16_t supported_tx_mcs;
    uint16_t supported_rx_mcs;
    uint8_t  max_supported_tx_streams: 3;
    uint8_t  max_supported_rx_streams: 3;
    uint8_t  gi_support_80mhz:         1;
    uint8_t  gi_support_160mhz:        1;
    uint8_t  support_80_80_mhz:        1;
    uint8_t  support_160mhz:           1;
    uint8_t  su_beamformer_capable:    1;
    uint8_t  mu_beamformer_capable:    1;
    uint8_t  reserved:                 4;
} map_ap_vht_cap_tlv_t;

/*#######################################################################
# AP HE capabilities TLV associated structures ("Section 17.2.10")      #
########################################################################*/
#define MAX_MCS 6

typedef struct mapAPHECapabilityTLV {
    uint8_t  tlv_type;
    mac_addr radio_id;
    uint8_t  supported_mcs_length;
    uint16_t supported_tx_rx_mcs[MAX_MCS];
    uint8_t  max_supported_tx_streams: 3;
    uint8_t  max_supported_rx_streams: 3;
    uint8_t  support_80_80_mhz:        1;
    uint8_t  support_160mhz:           1;
    uint8_t  su_beamformer_capable:    1;
    uint8_t  mu_beamformer_capable:    1;
    uint8_t  ul_mimo_capable:          1;
    uint8_t  ul_mimo_ofdma_capable:    1;
    uint8_t  dl_mimo_ofdma_capable:    1;
    uint8_t  ul_ofdma_capable:         1;
    uint8_t  dl_ofdma_capable:         1;
    uint8_t  reserved:                 1;
} map_ap_he_cap_tlv_t;

/*#######################################################################
# Steering policy TLV associated structures ("Section 17.2.11")         #
########################################################################*/
typedef struct {
    mac_addr radio_id;
    uint8_t  steering_policy;
    uint8_t  channel_utilization_threshold;
    uint8_t  rssi_steering_threshold;
} map_steering_policy_tlv_radio_t;

typedef struct mapSteeringPolicyTLV {
    uint8_t                          tlv_type;
    uint8_t                          local_steering_dis_macs_nr;
    mac_addr                        *local_steering_dis_macs;
    uint8_t                          btm_steering_dis_macs_nr;
    mac_addr                        *btm_steering_dis_macs;
    uint8_t                          radios_nr;
    map_steering_policy_tlv_radio_t  radios[MAX_RADIO_PER_AGENT];
} map_steering_policy_tlv_t;

/*#######################################################################
# Metric reporting policy TLV associated structures ("Section 17.2.12") #
########################################################################*/
#define MAP_METRIC_POLICY_TRAFFIC_STATS 0x80
#define MAP_METRIC_POLICY_LINK_METRICS  0x40
#define MAP_METRIC_POLICY_WIFI_6_STATS  0x20

typedef struct {
    mac_addr radio_id;
    uint8_t  reporting_rssi_threshold;
    uint8_t  reporting_rssi_margin_override;
    uint8_t  channel_utilization_reporting_threshold;
    uint8_t  associated_sta_policy;
} map_metric_reporting_policy_tlv_radio_t;

typedef struct mapMetricPolicyTLV {
    uint8_t                                 tlv_type;
    uint8_t                                 metric_reporting_interval;
    uint8_t                                 radios_nr;
    map_metric_reporting_policy_tlv_radio_t radios[MAX_RADIO_PER_AGENT];
} map_metric_reporting_policy_tlv_t;

/*#######################################################################
# Channel preference TLV associated structures ("Section 17.2.13")      #
########################################################################*/
#define MAP_PREF_SCORE_0                           0
#define MAP_PREF_SCORE_14                          14
#define MAP_PREF_SCORE_15                          15

#define MAP_PREF_REASON_UNSPECFIED                  0
#define MAP_PREF_REASON_NON80211_INTF               1
#define MAP_PREF_REASON_80211_INTRA_OBSS_INTF_MGMT  2
#define MAP_PREF_REASON_80211_EXT_OBSS_INTF_MGMT    3
#define MAP_PREF_REASON_REDUCED_COVERAGE            4
#define MAP_PREF_REASON_REDUCED_TPUT                5
#define MAP_PREF_REASON_INDEVICE_INTF               6
#define MAP_PREF_REASON_RADAR                       7
#define MAP_PREF_REASON_BACKHAUL                    8
#define MAP_PREF_REASON_DFS_CAC_COMPLETE            9
#define MAP_PREF_REASON_DFS_PASSIVE                10
#define MAP_PREF_REASON_CHAN_CLEAR_IND             11

typedef struct {
    uint8_t           op_class;
    map_channel_set_t channels;
    uint8_t           pref:   4;
    uint8_t           reason: 4;
} map_channel_preference_tlv_op_class_t;

typedef struct mapChannelPreferenceTLV {
    uint8_t                               tlv_type;
    mac_addr                              radio_id;
    uint8_t                               op_classes_nr;
    map_channel_preference_tlv_op_class_t op_classes[MAX_OP_CLASS];
} map_channel_preference_tlv_t;

/*###########################################################################
# Radio operation restriction TLV associated structures ("Section 17.2.14") #
############################################################################*/
typedef struct {
    uint8_t channel;
    uint8_t freq_restriction;
} map_radio_operation_restriction_tlv_channel_t;

typedef struct  {
    uint8_t                                       op_class;
    uint8_t                                       channels_nr;
    map_radio_operation_restriction_tlv_channel_t channels[MAX_CHANNEL_PER_OP_CLASS];
} map_radio_operation_restriction_tlv_op_class_t;

typedef struct mapRadioOperationRestrictionTLV {
    uint8_t                                        tlv_type;
    mac_addr                                       radio_id;
    uint8_t                                        op_classes_nr;
    map_radio_operation_restriction_tlv_op_class_t op_classes[MAX_OP_CLASS];
} map_radio_operation_restriction_tlv_t;

/*#######################################################################
# Transmit power limit TLV associated structures ("Section 17.2.15")    #
########################################################################*/
typedef struct mapTransmitPowerLimitTLV {
    uint8_t  tlv_type;
    mac_addr radio_id;
    uint8_t  transmit_power_eirp;
} map_transmit_power_limit_tlv_t;

/*##########################################################################
# Channel selection response TLV associated structures ("Section 17.2.16") #
############################################################################*/
#define MAP_CHAN_SEL_RESPONSE_ACCEPTED               0x00
#define MAP_CHAN_SEL_RESPONSE_DECLINED_CURRENT_PREF  0x01
#define MAP_CHAN_SEL_RESPONSE_DECLINED_REPORTED_PREF 0x02
#define MAP_CHAN_SEL_RESPONSE_DECLINED_BH_STA        0x03

typedef struct mapChannelSelectionResponseTLV {
    uint8_t  tlv_type;
    mac_addr radio_id;
    uint8_t  channel_selection_response;
} map_channel_selection_response_tlv_t;

/*########################################################################
# Operating channel report TLV associated structures ("Section 17.2.17") #
#########################################################################*/
typedef struct {
    uint8_t op_class;
    uint8_t channel;
} map_operating_channel_report_tlv_op_class_t;

typedef struct mapOperatingChannelReportTLV {
    uint8_t                                     tlv_type;
    mac_addr                                    radio_id;
    uint8_t                                     op_classes_nr;
    map_operating_channel_report_tlv_op_class_t op_classes[MAX_OP_CLASS];
    uint8_t                                     transmit_power_eirp;
} map_operating_channel_report_tlv_t;

/*#######################################################################
# Client info TLV associated structures ("Section 17.2.18")             #
########################################################################*/
typedef struct mapClientInfoTLV {
    uint8_t  tlv_type;
    mac_addr bssid;
    mac_addr sta_mac;
} map_client_info_tlv_t;

/*########################################################################
# Client capability report TLV associated structures ("Section 17.2.19") #
#########################################################################*/
#define MAP_CLIENT_CAP_SUCCESS 0x00
#define MAP_CLIENT_CAP_FAILURE 0x01

typedef struct mapClientCapabilityReportTLV {
    uint8_t   tlv_type;
    uint8_t   result_code;
    uint16_t  assoc_frame_body_len;
    uint8_t  *assoc_frame_body;
} map_client_cap_report_tlv_t;

/*########################################################################
# Client association event TLV associated structures ("Section 17.2.20") #
#########################################################################*/
#define MAP_CLIENT_ASSOC_EVENT_DISCONNECTED 0x00
#define MAP_CLIENT_ASSOC_EVENT_CONNECTED    0x01

typedef struct mapClientAssociationEventTLV {
    uint8_t  tlv_type;
    mac_addr sta_mac;
    mac_addr bssid;
    uint8_t  association_event: 1;
} map_client_assoc_event_tlv_t;

/*#######################################################################
# AP metric query TLV associated structures ("Section 17.2.21")         #
########################################################################*/
typedef struct mapApMetricsQueryTLV {
    uint8_t  tlv_type;
    uint8_t  bssids_nr;
    mac_addr bssids[MAX_BSS_PER_AGENT];
} map_ap_metric_query_tlv_t;

/*#######################################################################
# AP metrics TLV associated structures ("Section 17.2.22")              #
########################################################################*/
typedef union {
    struct {
       uint8_t esp_subelement;              /* This holds access_category->0-1bits, data_format->3-4bits, ba_window_size->5-7 */
       uint8_t estimated_air_time_fraction;
       uint8_t ppdu_target_duration;
    } s;
    uint8_t byte_stream[3];
} map_ap_metrics_tlv_esp_t;                 /* esp = estimated service parameters */

typedef struct mapApMetricsResponseTLV {
    uint8_t                  tlv_type;
    mac_addr                 bssid;
    uint8_t                  channel_util;
    uint16_t                 stas_nr;
    uint8_t                  esp_present;
    map_ap_metrics_tlv_esp_t esp[MAX_ACCESS_CATEGORY];
} map_ap_metrics_tlv_t;

/*#######################################################################
# STA MAC address TLV associated structures ("Section 17.2.23")         #
########################################################################*/
typedef struct mapStaMacAddressTLV {
    uint8_t  tlv_type;
    mac_addr sta_mac;
} map_sta_mac_address_tlv_t;

/*###########################################################################
# Associated STA link metrics TLV associated structures ("Section 17.2.24") #
############################################################################*/
typedef struct {
    mac_addr bssid;
    uint32_t report_time_interval;
    uint32_t downlink_data_rate;
    uint32_t uplink_data_rate;
    uint8_t  uplink_rssi;
} map_assoc_sta_link_metrics_tlv_bss_t;

typedef struct mapAssociatedStaLinkMetricsTLV {
    uint8_t                              tlv_type;
    mac_addr                             sta_mac;
    uint8_t                              bsss_nr;
    map_assoc_sta_link_metrics_tlv_bss_t bsss[0]; /* Could be MAX_BSS_PER_AGENT which is too big */
} map_assoc_sta_link_metrics_tlv_t;

/*###################################################################################
# Unassociated STA link metrics query TLV associated structures ("Section 17.2.25") #
####################################################################################*/
typedef struct {
     uint8_t   channel;
     uint8_t   sta_macs_nr;
     mac_addr *sta_macs;
} map_unassoc_sta_link_metrics_query_tlv_channel_t;

typedef struct mapUnassocStaMetricsQueryTLV {
    uint8_t                                          tlv_type;
    uint8_t                                          op_class;
    uint8_t                                          channels_nr;
    map_unassoc_sta_link_metrics_query_tlv_channel_t channels[MAX_CHANNEL_PER_OP_CLASS];
} map_unassoc_sta_link_metrics_query_tlv_t;

/*######################################################################################
# Unassociated STA link metrics response TLV associated structures ("Section 17.2.26") #
#######################################################################################*/
typedef struct {
    mac_addr mac;
    uint8_t  channel;
    uint32_t time_delta;
    uint8_t  rcpi_uplink;
} map_unassoc_sta_link_metrics_response_tlv_sta_t;

typedef struct mapUnassocStaMetricsResponseTLV {
    uint8_t                                         tlv_type;
    uint8_t                                         op_class;
    uint8_t                                         stas_nr;
    map_unassoc_sta_link_metrics_response_tlv_sta_t stas[0]; /* Could be MAX_STATION_PER_AGENT which is too big */
} map_unassoc_sta_link_metrics_response_tlv_t;

/*#######################################################################
# Beacon metrics query TLV associated structures ("Section 17.2.27")    #
########################################################################*/
#define MAP_BEACON_REPORT_DETAIL_NONE      0
#define MAP_BEACON_REPORT_DETAIL_REQUESTED 1
#define MAP_BEACON_REPORT_DETAIL_ALL       2

typedef struct mapBeaconMetricsQueryTLV {
    uint8_t            tlv_type;
    mac_addr           sta_mac;
    uint8_t            op_class;
    uint8_t            channel;
    mac_addr           bssid;
    uint8_t            reporting_detail;
    uint8_t            ssid_len;
    uint8_t            ssid[MAX_SSID_LEN];
    uint8_t            element_ids_nr;
    uint8_t            element_ids[255];
    uint8_t            ap_channel_reports_nr;
    map_tlv_op_class_t ap_channel_reports[MAX_OP_CLASS];
} map_beacon_metrics_query_tlv_t;

/*#######################################################################
# Beacon metrics response TLV associated structures ("Section 17.2.28") #
########################################################################*/
#define MAP_BEACON_REPORT_STATUS_CODE_SUCCESS     0x00
#define MAP_BEACON_REPORT_STATUS_CODE_NO_REPORT   0x40
#define MAP_BEACON_REPORT_STATUS_CODE_NO_SUPPORT  0x80
#define MAP_BEACON_REPORT_STATUS_CODE_UNSPECIFIED 0xc0

#define MAP_MEASUREMENT_REPORT_ELEMENTID          39

#define MAP_BEACON_REPORT_ELEMENT_SIZE            sizeof(map_beacon_metrics_response_tlv_element_t) - sizeof(uint8_t *)

/* Note: this struct must be packed as data from 1905 packet is copied directly into it. */
typedef struct {
    uint8_t   element_id;
    uint8_t   length;
    uint8_t   measurement_token;
    uint8_t   measurement_report_mode;
    uint8_t   measurement_type;
    uint8_t   op_class;
    uint8_t   channel;
    uint8_t   measurement_time[8];
    uint16_t  measurement_duration;
    uint8_t   reported_frame_information;
    uint8_t   rcpi;
    uint8_t   rsni;
    mac_addr  bssid;
    uint8_t   antenna_id;
    uint32_t  parent_tsf;
    uint8_t  *subelements;
} STRUCT_PACKED map_beacon_metrics_response_tlv_element_t;

typedef struct mapBeaconMetricsResponseTLV {
    uint8_t                                   tlv_type;
    mac_addr                                  sta_mac;
    uint8_t                                   status_code;   /* MAP spec mentions "reserved" but this seems to be a status code */
    uint8_t                                   elements_nr;
    map_beacon_metrics_response_tlv_element_t elements[0];
} map_beacon_metrics_response_tlv_t;

/*#######################################################################
# Steering request TLV associated structures ("Section 17.2.29")        #
########################################################################*/
#define MAP_STEERING_REQUEST_FLAG_MANDATE               0x80
#define MAP_STEERING_REQUEST_FLAG_BTM_DISASSOC_IMMINENT 0x40
#define MAP_STEERING_REQUEST_FLAG_BTM_ABRIDGED          0x20

typedef struct steering_request_target_bss_s {
    mac_addr bssid;
    uint8_t  op_class;
    uint8_t  channel;
    uint8_t  reason;          /* Profile 2 */
} map_steering_request_tlv_target_bss_t;

/* Structure is used also for profile 2 steering request */
typedef struct mapSteeringRequestTLV {
    uint8_t                               tlv_type;
    mac_addr                              bssid;
    uint8_t                               flag;
    uint16_t                              opportunity_wnd;
    uint16_t                              disassociation_timer;
    uint8_t                               sta_macs_nr;
    mac_addr                              sta_macs[MAX_STATION_PER_BSS];
    uint8_t                               target_bsss_nr;
    map_steering_request_tlv_target_bss_t target_bsss[MAX_STATION_PER_BSS];
} map_steering_request_tlv_t;

/*#######################################################################
# Steering BTM report TLV associated structures ("Section 17.2.30")     #
########################################################################*/
typedef struct mapSteeringBTMReportTLV {
    uint8_t  tlv_type;
    mac_addr bssid;
    mac_addr sta_mac;
    uint8_t  btm_status_code;
    uint8_t  target_bssid_present;
    mac_addr target_bssid;         /* This field is valid only if target_bssid_present = 1 */
} map_steering_btm_report_tlv_t;

/*##################################################################################
# Client association control request TLV associated structures ("Section 17.2.31") #
###################################################################################*/
#define MAP_CLIENT_ASSOC_CONTROL_BLOCK   0x00
#define MAP_CLIENT_ASSOC_CONTROL_UNBLOCK 0x01

typedef struct mapClientAsociationControlRequestTLV {
    uint8_t  tlv_type;
    mac_addr bssid;
    uint8_t  association_control;
    uint16_t validity_period;
    uint8_t  sta_macs_nr;
    mac_addr sta_macs[MAX_STATION_PER_BSS];
} map_client_assoc_control_request_tlv_t;

/*################################################################################
# Backhaul steering request report TLV associated structures ("Section 17.2.32") #
#################################################################################*/
typedef struct mapBackhaulSteeringRequestTLV {
    uint8_t  tlv_type;
    mac_addr bsta_mac;
    mac_addr target_bssid;
    uint8_t  target_op_class;
    uint8_t  target_channel;
} map_backhaul_steering_request_tlv_t;

/*#################################################################################
# Backhaul steering response report TLV associated structures ("Section 17.2.33") #
##################################################################################*/
#define MAP_BACKHAUL_STEER_RESULT_SUCCESS 0x00
#define MAP_BACKHAUL_STEER_RESULT_FAILURE 0x01

typedef struct mapBackhaulSteeringResponseTLV {
    uint8_t  tlv_type;
    mac_addr bsta_mac;
    mac_addr target_bssid;
    uint8_t  result;
} map_backhaul_steering_response_tlv_t;

/*#######################################################################
# Higher layer data TLV associated structures ("Section 17.2.34")       #
########################################################################*/
typedef struct mapHigherLayerDataTLV {
    uint8_t   tlv_type;
    uint8_t   protocol;
    uint16_t  payload_len;
    uint8_t  *payload;
} map_higher_layer_data_tlv_t;

/*############################################################################
# Associated STA traffic stats TLV associated structures ("Section 17.2.35") #
#############################################################################*/
typedef struct mapAssocStaTrafficStatsTLV {
    uint8_t  tlv_type;
    mac_addr sta_mac;
    uint32_t txbytes;
    uint32_t rxbytes;
    uint32_t txpkts;
    uint32_t rxpkts;
    uint32_t txpkterrors;
    uint32_t rxpkterrors;
    uint32_t retransmission_cnt;
} map_assoc_sta_traffic_stats_tlv_t;

/*#######################################################################
# Error code TLV associated structures ("Section 17.2.36")              #
########################################################################*/
#define MAP_ERROR_CODE_STA_ASSOCIATED                      0x01
#define MAP_ERROR_CODE_STA_UNASSOCIATED                    0x02
#define MAP_ERROR_CODE_CLIENT_CAP_UNSPECIFIED_FAILURE      0x03
#define MAP_ERROR_CODE_BH_STEER_NON_OPERABLE_CHANNEL       0x04
#define MAP_ERROR_CODE_BH_STEER_BSS_SIGNAL_WEAK            0x05
#define MAP_ERROR_CODE_BH_STEERSTEERING_REJECTED_BY_TARGET 0x06

typedef struct mapErrorCodeTLV {
    uint8_t  tlv_type;
    uint8_t  reason_code;
    mac_addr sta_mac;
} map_error_code_tlv_t;

/*#############################################################################
# Channel scan reporting policy TLV associated structures ("Section 17.2.37") #
##############################################################################*/
typedef struct mapChannelScanReportPolicyTLV {
    uint8_t  tlv_type;
    uint16_t tlv_length;
    uint8_t  report_independent_ch_scans: 1; /* 1: report independent ch scans, 0: do not report unless explicitly requested in ch scan request */
} map_channel_scan_reporting_policy_tlv_t;

/*#########################################################################
# Channel scan capabilities TLV associated structures ("Section 17.2.38") #
##########################################################################*/
#define MAP_SCAN_IMPACT_NONE              0x00 /* Independent radio is available for scanning */
#define MAP_SCAN_IMPACT_REDUCED_NSS       0x01 /* Reduced number of spatial streaming */
#define MAP_SCAN_IMPACT_TIME_SLICING      0x02 /* Time slicing impairment */
#define MAP_SCAN_IMPACT_RADIO_UNAVAILABLE 0x03 /* Radio unavailable for >=2 seconds */

typedef struct {
    mac_addr           radio_id;
    uint8_t            boot_only:   1;
    uint8_t            scan_impact: 2;
    uint32_t           min_scan_interval;
    uint8_t            op_classes_nr;
    map_tlv_op_class_t op_classes[MAX_OP_CLASS];
} map_channel_scan_cap_tlv_radio_t;

typedef struct mapChannelScanCapabilitiesTLV {
    uint8_t                          tlv_type;
    uint8_t                          radios_nr;
    map_channel_scan_cap_tlv_radio_t radios[MAX_RADIO_PER_AGENT];
} map_channel_scan_cap_tlv_t;

/*#######################################################################
# Channel scan request TLV associated structures ("Section 17.2.39")    #
########################################################################*/
typedef struct {
    mac_addr           radio_id;
    uint8_t            op_classes_nr;
    map_tlv_op_class_t op_classes[MAX_OP_CLASS];
} map_channel_scan_request_tlv_radio_t;

typedef struct mapChannelScanRequestTLV {
    uint8_t                              tlv_type;
    uint8_t                              fresh_scan_performed: 1;   /* 1: fresh scan, 0: old scan results are requested */
    uint8_t                              radios_nr;
    map_channel_scan_request_tlv_radio_t radios[MAX_RADIO_PER_AGENT];
} map_channel_scan_request_tlv_t;

/*#######################################################################
# Channel scan result TLV associated structures ("Section 17.2.40")     #
########################################################################*/
#define MAP_SCAN_STATUS_SUCCESS               0x00
#define MAP_SCAN_STATUS_OPCLASS_NOT_SUPPORTED 0x01
#define MAP_SCAN_STATUS_TOO_SOON              0x02
#define MAP_SCAN_STATUS_BUSY                  0x03
#define MAP_SCAN_STATUS_NOT_COMPLETED         0x04
#define MAP_SCAN_STATUS_ABORTED               0x05
#define MAP_SCAN_STATUS_FRESH_NOT_SUPPORTED   0x06

#define MAP_SCAN_TYPE_PASSIVE                 0x00
#define MAP_SCAN_TYPE_ACTIVE                  0x01

typedef struct mapChannelScanResultTLV {
    uint8_t                      tlv_type;
    mac_addr                     radio_id;
    uint8_t                      op_class;
    uint8_t                      channel;
    uint8_t                      scan_status;
    uint8_t                      timestamp_len;
    uint8_t                      timestamp[MAX_1905_TIMESTAMP_LEN];
    uint8_t                      utilization;     /* look section 9.4.2.28 of IEEE Std 802.11-2016. */
    uint8_t                      noise;           /* look section 11.11.9.4 of IEEE Std 802.11-2016. */
    uint16_t                     neighbors_nr;
    map_channel_scan_neighbor_t *neighbors;       /* Type efined in map_data_model.h */
    uint32_t                     aggregate_scan_duration;
    uint8_t                      scan_type;
} map_channel_scan_result_tlv_t;

/*#######################################################################
# Timestamp TLV associated structures ("Section 17.2.41")               #
########################################################################*/
typedef struct mapTimestampTLV {
    uint8_t tlv_type;
    uint8_t timestamp_len;
    uint8_t timestamp[MAX_1905_TIMESTAMP_LEN];
} map_timestamp_tlv_t;

/*#######################################################################
# CAC request TLV associated structures ("Section 17.2.42")             #
########################################################################*/
#define MAP_CAC_ACTION_REMAIN_AND_CONT_TO_MON 0x00 /* Remain on channel and continue to monitor for radar */
#define MAP_CAC_ACTION_RETURN_PREV_OP_CONF    0x01 /* Return the radio that was performing the CAC to its most recent operational configuration. */

typedef struct {
    mac_addr radio_id;
    uint8_t  op_class;
    uint8_t  channel;
    uint8_t  cac_method:            3;
    uint8_t  cac_completion_action: 2;
    uint8_t  reserved:              3;
} map_cac_request_tlv_radio_t;

typedef struct mapCACRequestTLV {
    uint8_t                     tlv_type;
    uint8_t                     radios_nr;
    map_cac_request_tlv_radio_t radios[MAX_RADIO_PER_AGENT];
} map_cac_request_tlv_t;

/*#######################################################################
# CAC termination TLV associated structures ("Section 17.2.43")         #
########################################################################*/
typedef struct {
    mac_addr radio_id;
    uint8_t  op_class;
    uint8_t  channel;
} map_cac_termination_tlv_radio_t;

typedef struct mapCACTerminationTLV {
    uint8_t                         tlv_type;
    uint8_t                         radios_nr;
    map_cac_termination_tlv_radio_t radios[MAX_RADIO_PER_AGENT];
} map_cac_termination_tlv_t;

/*#######################################################################
# CAC completion report TLV associated structures ("Section 17.2.44")   #
########################################################################*/
typedef struct {
    uint8_t op_class;
    uint8_t channel;
} map_cac_completion_report_tlv_pair_t;

typedef struct {
    mac_addr                              radio_id;
    uint8_t                               op_class;
    uint8_t                               channel;
    uint8_t                               status;
    uint8_t                               detected_pairs_nr;
    map_cac_completion_report_tlv_pair_t *detected_pairs;
} map_cac_completion_report_tlv_radio_t;

typedef struct mapCACCompletionReportTLV {
    uint8_t                               tlv_type;
    uint8_t                               radios_nr;
    map_cac_completion_report_tlv_radio_t radios[MAX_RADIO_PER_AGENT];
} map_cac_completion_report_tlv_t;

/*#######################################################################
# CAC statiu report TLV associated structures ("Section 17.2.45")       #
########################################################################*/
typedef struct mapCACStatusReportTLV {
    uint8_t                       tlv_type;
    uint8_t                       available_pairs_nr;
    map_cac_available_pair_t     *available_pairs;        /* Type defined in map_data_model.h */
    uint8_t                       non_occupancy_pairs_nr;
    map_cac_non_occupancy_pair_t *non_occupancy_pairs;    /* Type defined in map_data_model.h */
    uint8_t                       ongoing_cac_pairs_nr;
    map_cac_ongoing_pair_t       *ongoing_cac_pairs;      /* Type defined in map_data_model.h */
} map_cac_status_report_tlv_t;

/*#######################################################################
# CAC capabilities TLV associated structures ("Section 17.2.46")        #
########################################################################*/
#define MAP_CAC_METHOD_CONTINUOUS            0x00 /* Continuous CAC */
#define MAP_CAC_METHOD_CONT_WDEDICATED_RADIO 0x01 /* Continuous with dedicated Radio */
#define MAP_CAC_METHOD_MIMO_DIM_REDUCED      0x02 /* MIMO dimension reduced */
#define MAP_CAC_METHOD_TIME_SLICED           0x03 /* Time sliced CAC */
#define MAX_CAC_METHODS                      4

typedef struct {
    uint8_t            cac_method;
    uint32_t           cac_duration;
    uint8_t            op_classes_nr;
    map_tlv_op_class_t op_classes[MAX_OP_CLASS];
} map_cac_cap_tlv_method_t;

typedef struct  {
    mac_addr                 radio_id;
    uint8_t                  cac_methods_nr;
    map_cac_cap_tlv_method_t cac_methods[MAX_CAC_METHODS];
} map_cac_cap_tlv_radio_t;

typedef struct mapCacCapabilitiesTLV {
    uint8_t                 tlv_type;
    uint16_t                country_code;
    uint8_t                 radios_nr;
    map_cac_cap_tlv_radio_t radios[MAX_RADIO_PER_AGENT];
} map_cac_cap_tlv_t;

/*#######################################################################
# Multi-AP profile TLV associated structures ("Section 17.2.47")        #
########################################################################*/
typedef struct mapProfileTLV {
    uint8_t tlv_type;
    uint8_t map_profile;
} map_multiap_profile_tlv_t;

/*#######################################################################
# Profile 2 AP capability TLV associated structures ("Section 17.2.48") #
########################################################################*/
#define MAP_BYTE_COUNTER_UNIT_BYTES      0x00
#define MAP_BYTE_COUNTER_UNIT_KIBI_BYTES 0x01
#define MAP_BYTE_COUNTER_UNIT_MEBI_BYTES 0x02

typedef struct mapProfile2APCapabilityTLV {
    uint8_t tlv_type;
    uint8_t byte_counter_unit;
    uint8_t max_vid_count;
} map_profile2_ap_cap_tlv_t;

/*#######################################################################
# Default 8021Q settings TLV associated structures ("Section 17.2.49")  #
########################################################################*/
typedef struct mapDefault8021QSettingsTLV {
    uint8_t  tlv_type;
    uint16_t primary_vlan_id;
    uint8_t  default_pcp: 3;
} map_default_8021q_settings_tlv_t;

/*#########################################################################
# Traffic separation policy TLV associated structures ("Section 17.2.50") #
###########################################################################*/
typedef struct {
    uint8_t  ssid_len;
    uint8_t  ssid[MAX_SSID_LEN];
    uint16_t vlan_id;
} map_traffic_separation_policy_tlv_ssid_t;

typedef struct mapTrafficSeparationPolicyTLV {
    uint8_t                                  tlv_type;
    uint8_t                                  ssids_nr;
    map_traffic_separation_policy_tlv_ssid_t ssids[MAX_TRAFFIC_SEP_SSID];
} map_traffic_separation_policy_tlv_t;

/*#######################################################################
# Profile 2 error code TLV associated structures ("Section 17.2.51")    #
########################################################################*/
#define MAP_ERROR_CODE2_DEFAULT_PCP_VLAN_ID_NOT_PROVIDED                0x03
#define MAP_ERROR_CODE2_TOO_MANY_VLAN_ID                                0x05
#define MAP_ERROR_CODE2_TS_COMBINED_FH_PROFILE1_BH_UNSUPPORTED          0x07
#define MAP_ERROR_CODE2_TS_COMBINED_PROFILE1_BH_PROFILE2_BH_UNSUPPORTED 0x08

typedef struct mapProfile2ErrorCodeTLV {
    uint8_t  tlv_type;
    uint8_t  reason_code;
    mac_addr sta_mac;
} map_profile2_error_code_tlv_t;

/*##############################################################################
# AP radio advanced capabilities TLV associated structures ("Section 17.2.52") #
###############################################################################*/
typedef struct mapAPRadioAdvancedCapabilitiesTLV {
    uint8_t  tlv_type;
    mac_addr radio_id;
    uint8_t  combined_fh_profile2_bh:          1;
    uint8_t  combined_profile1_bh_profile2_bh: 1;
} map_ap_radio_advanced_cap_tlv_t;

/*###############################################################################
# Association status notification TLV associated structures ("Section 17.2.53") #
################################################################################*/
#define MAP_ASSOC_STATUS_DISALLOWED 0x00
#define MAP_ASSOC_STATUS_ALLOWED    0x01

typedef struct  {
    mac_addr bssid;
    uint8_t  assoc_allowance_status;
} map_assoc_status_notification_tlv_bss_t;

typedef struct mapAssocStatusNotificationTLV {
    uint8_t                                 tlv_type;
    uint8_t                                 bsss_nr;
    map_assoc_status_notification_tlv_bss_t bsss[MAX_BSS_PER_AGENT];
} map_assoc_status_notification_tlv_t;

/*#######################################################################
# Source info TLV associated structures ("Section 17.2.54")             #
########################################################################*/
typedef struct mapSourceInfoTLV {
    uint8_t  tlv_type;
    mac_addr src_mac;
} map_source_info_tlv_t;

/*#######################################################################
# Tunneled message type TLV associated structures ("Section 17.2.55")   #
########################################################################*/
typedef struct mapTunneledMessageTypeTLV {
    uint8_t tlv_type;
    uint8_t message_type;
} map_tunneled_message_type_tlv_t;

/*#######################################################################
# Tunneled TLV associated structures ("Section 17.2.56")                #
########################################################################*/
typedef struct mapTunneledTLV {
    uint8_t   tlv_type;
    uint16_t  frame_body_len;
    uint8_t  *frame_body;
} map_tunneled_tlv_t;

/*##########################################################################
# Profile 2 steering request TLV associated structures ("Section 17.2.57") #
###########################################################################*/
typedef map_steering_request_tlv_t map_profile2_steering_request_tlv_t;

/*###############################################################################
# Unsuccessful association policy TLV associated structures ("Section 17.2.58") #
################################################################################*/
#define MAP_UNSUCCESSFUL_ASSOC_NO_REPORT 0x00
#define MAP_UNSUCCESSFUL_ASSOC_REPORT    0x01

typedef struct mapUnsuccessAssocPolicyTLV {
    uint8_t  tlv_type;
    uint8_t  report_flag;
    uint32_t max_reporting_rate;
} map_unsuccessful_assoc_policy_tlv_t;

/*##########################################################################
# Metric collection interval TLV associated structures ("Section 17.2.59") #
###########################################################################*/
typedef struct mapMetricCollectionIntervalTLV {
    uint8_t  tlv_type;
    uint32_t metric_collection_interval;
} map_metric_collection_interval_tlv_t;

/*#######################################################################
# Radio metrics TLV associated structures ("Section 17.2.60")           #
########################################################################*/
typedef struct mapRadioMetricsTLV {
    uint8_t  tlv_type;
    mac_addr radio_id;
    uint8_t  noise;
    uint8_t  transmit;
    uint8_t  receive_self;
    uint8_t  receive_other;
} map_radio_metrics_tlv_t;

/*#######################################################################
# AP extended metrics TLV associated structures ("Section 17.2.61")     #
########################################################################*/
typedef struct mapAPExtendedMetricsTLV {
    uint8_t  tlv_type;
    mac_addr bssid;
    uint32_t ucast_bytes_tx;
    uint32_t ucast_bytes_rx;
    uint32_t mcast_bytes_tx;
    uint32_t mcast_bytes_rx;
    uint32_t bcast_bytes_tx;
    uint32_t bcast_bytes_rx;
} map_ap_ext_metrics_tlv_t;

/*####################################################################################
# Associated STA extended link metrics TLV associated structures ("Section 17.2.62") #
#####################################################################################*/
typedef struct {
    mac_addr bssid;
    uint32_t last_data_dl_rate;  /* from AP to STA in Kbps */
    uint32_t last_data_ul_rate;  /* from STA to AP in Kbps */
    uint32_t utilization_rx;     /* the time that the radio's spent on channel to rx data from STA in ms */
    uint32_t utilization_tx;     /* the time that the radio's spent on channel to tx data from STA in ms */
} map_assoc_sta_ext_link_metrics_tlv_bss_t;

typedef struct mapAssocStaExtLinkMetricsTLV {
    uint8_t                                  tlv_type;
    mac_addr                                 sta_mac;
    uint8_t                                  bsss_nr;
    map_assoc_sta_ext_link_metrics_tlv_bss_t bsss[MAX_BSS_PER_AGENT];
} map_assoc_sta_ext_link_metrics_tlv_t;

/*#######################################################################
# Status code TLV associated structures ("Section 17.2.63")             #
########################################################################*/
typedef struct mapStatusCodeTLV {
    uint8_t  tlv_type;
    uint16_t status_code;
} map_status_code_tlv_t;

/*#######################################################################
# Reason code TLV associated structures ("Section 17.2.64")             #
########################################################################*/
typedef struct mapReasonCodeTLV {
    uint8_t  tlv_type;
    uint16_t reason_code;
} map_reason_code_tlv_t;

/*###############################################################################
# Backhaul STA radio capabilities TLV associated structures ("Section 17.2.65") #
################################################################################*/
typedef struct mapBackhaulSTARadioCapabilitiesTLV {
    uint8_t  tlv_type;
    mac_addr radio_id;
    uint8_t  bsta_mac_present: 1;
    mac_addr bsta_mac;
} map_backhaul_sta_radio_cap_tlv_t;

/*#######################################################################
# Backhaul BSS configuration associated structures ("Section 17.2.66")  #
########################################################################*/
typedef struct mapBhBssConfigTLV {
    uint8_t  tlv_type;
    mac_addr bssid;
    uint8_t  p1_bsta_disallowed: 1;   /* 1: profile-1 bh sta association disallowed, 0: allowed */
    uint8_t  p2_bsta_disallowed: 1;   /* 1: profile-2 bh sta association disallowed, 0: allowed */
    uint8_t  reserved:           6;
} map_backhaul_bss_configuration_tlv_t;

/*#######################################################################
# Encrypted Payload TLV associated structures      ("Section 17.2.69")  #
########################################################################*/
typedef struct mapEncryptedPayloadTLV {
    uint8_t  tlv_type;
    uint8_t  encr_tx_counter[ENCRYPTION_TX_COUNTER_LEN];
    mac_addr src_al_mac;
    mac_addr dst_al_mac;
    uint16_t siv_len;
    uint8_t *siv_output;
} map_encrypted_payload_tlv_t;

/*#######################################################################
# AP Wi-Fi 6 Capabilities associated structures ("Section 17.2.72")     #
########################################################################*/
typedef struct mapAPWiFi6CapTLV {
    uint8_t  tlv_type;
    mac_addr radio_id;
    uint8_t  roles_nr;
    map_radio_wifi6_cap_data_t cap_data[MAP_AP_ROLE_MAX];
} map_ap_wifi6_cap_tlv_t;


/*################################################################################
# Associated Wi-Fi 6 STA Status Report associated structures ("Section 17.2.73") #
#################################################################################*/

typedef struct mapAssocWiFi6STAStatusTLV {
    uint8_t tlv_type;
    mac_addr sta_mac;
    uint8_t TID_nr;
    uint8_t TID[MAX_NUM_TID];
    uint8_t queue_size[MAX_NUM_TID];
} map_assoc_wifi6_sta_status_tlv_t;

/*#######################################################################
# BSSID TLV associated structures ("Section 17.2.74")                   #
########################################################################*/
typedef struct mapBSSIDTLV {
    uint8_t  tlv_type;
    mac_addr bssid;
} map_bssid_tlv_t;

/*#######################################################################
# 1905 Encap DPP TLV ("Section 17.2.79")                            #
########################################################################*/
typedef struct map1905EncapDPPTLV {
    uint8_t   tlv_type;
    uint8_t   enrollee_mac_present:   1;
    uint8_t   reserved1:              1;
    uint8_t   dpp_frame_indicator:    1;
    uint8_t   reserved2:              5;
    mac_addr  sta_mac;
    uint8_t   frame_type;
    uint16_t  frame_len;
    uint8_t  *frame;
} map_1905_encap_dpp_tlv_t;

/*#######################################################################
# DPP Message TLV ("Section 17.2.80")                                   #
########################################################################*/
typedef struct map1905EncapEapolTLV {
    uint8_t   tlv_type;
    uint16_t  frame_len;
    uint8_t  *frame;
} map_1905_encap_eapol_tlv_t;

/*#######################################################################
# DPP CCE Indication TLV ("Section 17.2.82")                            #
########################################################################*/
typedef struct mapDPPCCEIndicationTLV {
    uint8_t  tlv_type;
    uint8_t advertise;
} map_dpp_cce_indication_tlv_t;

/*#######################################################################
# DPP Chirp Value TLV ("Section 17.2.83")                               #
########################################################################*/
typedef struct mapDPPChirpValueTLV {
    uint8_t   tlv_type;
    uint8_t   enrollee_mac_present:   1;
    uint8_t   hash_validity:          1;
    uint8_t   reserved:               6;
    mac_addr  sta_mac;
    uint8_t   hash_len;
    uint8_t  *hash;
} map_dpp_chirp_value_tlv_t;

/*#######################################################################
# DPP Message TLV ("Section 17.2.86")                                   #
########################################################################*/
typedef struct mapDPPMessageTLV {
    uint8_t   tlv_type;
    uint16_t  frame_len;
    uint8_t  *frame;
} map_dpp_message_tlv_t;

/*#######################################################################
# Device Inventory TLV ("Section 17.2.76")                              #
########################################################################*/
typedef struct {
    mac_addr  ruid;
    uint8_t   vendor_len;
    uint8_t   vendor[MAP_INVENTORY_ITEM_LEN];
} map_radio_vendor_t;
typedef struct mapDeviceInventoryTLV {
    uint8_t   tlv_type;
    uint8_t   serial_len;
    uint8_t   serial[MAP_INVENTORY_ITEM_LEN];
    uint8_t   version_len;
    uint8_t   version[MAP_INVENTORY_ITEM_LEN];
    uint8_t   environment_len;
    uint8_t   environment[MAP_INVENTORY_ITEM_LEN];
    uint8_t   radios_nr;
    map_radio_vendor_t radios[MAX_RADIO_PER_AGENT];
} map_device_inventory_tlv_t;

/*#######################################################################
# PUBLIC FUNCTIONS                                                      #
########################################################################*/
/* Common handlers for profile 1 and 2 steering request */
uint8_t* map_parse_p1_p2_steering_request_tlv(uint8_t *packet_stream, uint16_t len, bool profile2);
uint8_t* map_forge_p1_p2_steering_request_tlv(void *memory_structure, uint16_t *len, bool profile2);
void map_free_p1_p2_steering_request_tlv(void *memory_structure, bool profile2);

/* Register TLVS */
void map_r1_register_tlvs(void);
void map_r2_register_tlvs(void);
void map_r3_register_tlvs(void);

#endif /* MAP_TLVS_H_ */
