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

#ifndef MAP_DATA_MODEL_H_
#define MAP_DATA_MODEL_H_

#include "arraylist.h"
#include "kwaytree.h"
#include "map_common_defines.h"
#include "map_channel_set.h"
#include "map_timer_handler.h"
#include "map_utils.h"

/* Forward declarations */
struct map_ale_info_s;
struct map_radio_info_s;
struct map_bss_info_s;
struct map_sta_info_s;

/*#######################################################################
#                       STA INFO TYPES                                  #
########################################################################*/
typedef struct map_client_traffic_stats_s {
    uint64_t txbytes;
    uint64_t rxbytes;
    uint32_t txpkts;
    uint32_t rxpkts;
    uint32_t txpkterrors;
    uint32_t rxpkterrors;
    uint32_t retransmission_cnt;
} map_sta_traffic_stats_t;

typedef struct map_client_link_metrics_s {
    uint32_t age;
    uint32_t dl_mac_datarate;
    uint32_t ul_mac_datarate;
    uint8_t  rssi;
} map_sta_link_metrics_t;

typedef struct map_client_metrics_s {
    struct timespec         last_sta_metric_time; /* This is different from age, age is (curr_time - last_sta_metric_time) */
    map_sta_link_metrics_t  link;
    map_sta_traffic_stats_t traffic;
} map_sta_metrics_t;

typedef struct map_sta_capability_s {
    bool     valid;
    uint8_t  max_tx_spatial_streams;
    uint8_t  max_rx_spatial_streams;
    uint8_t  max_bandwidth;
    uint8_t  supported_standard;
    uint8_t  he_support:         1;
    uint8_t  vht_support:        1;
    uint8_t  ht_support:         1;
    uint8_t  erp_support:        1;  /* ofdm rates, false for 11B */
    uint8_t  sgi_support:        1;
    uint8_t  dot11k_support:     1;
    uint8_t  dot11k_brp_support: 1;
    uint8_t  dot11k_bra_support: 1;
    uint8_t  dot11v_btm_support: 1;
    uint8_t  backhaul_sta:       1;
    uint8_t  mbo_support:        1;
    uint32_t max_phy_rate;           /* in kbps */
} map_sta_capability_t;

typedef struct map_tunneled_msg_s {
    uint16_t  assoc_req_body_len;
    uint8_t  *assoc_req_body;
    uint16_t  reassoc_req_body_len;
    uint8_t  *reassoc_req_body;
    uint16_t  btm_query_body_len;
    uint8_t  *btm_query_body;
    uint16_t  wnm_req_body_len;
    uint8_t  *wnm_req_body;
    uint16_t  anqp_req_body_len;
    uint8_t  *anqp_req_body;
} map_tunneled_msg_t;

typedef struct map_sta_ext_link_metrics_s {
    uint8_t                       no_of_bss_metrics;
    struct map_sta_ext_metrics_s *ext_bss_metrics_list; /* Type defined in map_tlvs.h */
} map_sta_ext_link_metrics_t;

/*#######################################################################
#                       STA INFO                                        #
########################################################################*/
typedef struct map_sta_info_s {
    mac_addr                    mac;
    mac_addr_str                mac_str;

    list_head_t                 list;
    list_head_t                 hlist;

    bool                        marked;

    char                        if_name[MAX_IFACE_NAME_LEN]; /* BSTA interface name */
    map_sta_capability_t        sta_caps;
    uint64_t                    assoc_ts; /* Association timestamp in seconds (acu_get_timestamp_sec() + MAP_ASSOC_TS_DELTA) */
    array_list_t               *metrics;
    void                       *beacon_metrics;
    map_sta_traffic_stats_t    *traffic_stats;
    struct map_bss_info_s      *bss;
    uint16_t                    assoc_frame_len;
    uint8_t                    *assoc_frame;
    map_tunneled_msg_t         *tunneled_msg;
    uint16_t                    last_disassoc_reason_code;
    map_sta_ext_link_metrics_t  last_sta_ext_metrics;
} map_sta_info_t;

/*#######################################################################
#                       BSS INFO TYPES                                  #
########################################################################*/
typedef union map_esp_info_s {  /* esp = estimated service parameters */
    struct {
        uint8_t esp_subelement; /* This holds access_category->0-1bits, data_format->3-4bits, ba_window_size->5-7 */
        uint8_t estimated_air_time_fraction;
        uint8_t ppdu_target_duration;
    } s;
    uint8_t byte_stream[3];
} map_esp_info_t;

typedef struct map_ap_metric_s {
    bool           valid;
    uint32_t       channel_utilization;
    uint8_t        stas_nr;     /* as per the metrics parameter */
    uint8_t        esp_present; /* BIT7->AC_BE, BIT6->AC_BK, BIT5->VO, BIT4->VI */
    map_esp_info_t esp[MAX_ACCESS_CATEGORY];
} map_ap_metric_t;

typedef struct map_ap_extended_metrics_s {
    bool     valid;
    uint64_t ucast_bytes_tx;
    uint64_t ucast_bytes_rx;
    uint64_t mcast_bytes_tx;
    uint64_t mcast_bytes_rx;
    uint64_t bcast_bytes_tx;
    uint64_t bcast_bytes_rx;
} map_ap_extended_metrics_t;

/*#######################################################################
#                       BSS INFO                                        #
########################################################################*/
typedef struct map_bss_info_s {
    mac_addr                   bssid;
    mac_addr_str               bssid_str;

    list_head_t                list;
    list_head_t                sta_list;
    list_head_t                sta_hlist[MAP_MAX_MAC_HASH];
    uint16_t                   stas_nr;

    int                        airdata_idx;
    bool                       airdata_removed;
    uint8_t                    ssid_len;
    char                       ssid[MAX_SSID_LEN];
    uint16_t                   state;  /* active/configured/wps_enabled */
    uint8_t                    type;   /* Fronthaul or backhaul */
    uint8_t                    assoc_allowance_status;
    array_list_t              *neigh_link_metric_list;
    map_ap_metric_t            metrics;
    map_ap_extended_metrics_t  extended_metrics;
    struct map_radio_info_s   *radio;
} map_bss_info_t;

/*#######################################################################
#                       RADIO INFO TYPES                                #
########################################################################*/
/* Operating class structure used for storing:
  - Radio basic capabilities op class list
  - Agent channel preference
  - Controller channel preference
  - Scan capability op class list
  - CAC method op clas list
  - Wi-Fi 6 capabilities

   Fields op_class, channel_count, channel_list are used for all
   Fields eirp, pref, reason for some
*/
typedef struct map_op_class_s {
    uint8_t           op_class;
    uint8_t           eirp;      /* Radio basic capabilities */
    uint8_t           pref;      /* Agent and controller channel preference */
    uint8_t           reason;    /* Agent and controller channel preference */
    map_channel_set_t channels;
} map_op_class_t;

typedef struct map_op_class_list_s {
    uint8_t         op_classes_nr;
    map_op_class_t *op_classes;
} map_op_class_list_t;

typedef struct map_channel_restriction_s {
    uint8_t channel;
    uint8_t freq_restriction;
} map_channel_restriction_t;

typedef struct map_op_restriction_s {
    uint8_t                   op_class;
    uint8_t                   channel_count;
    map_channel_restriction_t channel_list[MAX_CHANNEL_PER_OP_CLASS];
} map_op_restriction_t;

typedef struct map_op_restriction_list_s {
    uint8_t               op_classes_nr;
    map_op_restriction_t *op_classes;
} map_op_restriction_list_t;

typedef struct map_radio_capablity_s {
    uint8_t  max_bss_supported;
    uint8_t  max_tx_spatial_streams;
    uint8_t  max_rx_spatial_streams;
    uint8_t  type;
    uint8_t  max_bandwidth;
    uint8_t  sgi_support;
    uint8_t  su_beamformer_capable;
    uint8_t  mu_beamformer_capable;
    uint8_t  dl_ofdma;
    uint8_t  ul_ofdma;
    uint8_t  supported_standard;
    uint8_t  transmit_power_limit;
    uint16_t unassoc_measurement_support; /* bit 0 -> ib_unassoc, bit 1 -> oob_unassoc */
} map_radio_capability_t;

typedef struct map_radio_ht_capability_s {
    uint8_t max_supported_tx_streams: 4;
    uint8_t max_supported_rx_streams: 4;
    uint8_t gi_support_20mhz:         1;
    uint8_t gi_support_40mhz:         1;
    uint8_t ht_support_40mhz:         1;
    uint8_t reserved:                 5;
} map_radio_ht_capability_t;

typedef struct map_radio_vht_capability_s {
    uint16_t supported_tx_mcs;
    uint16_t supported_rx_mcs;
    uint8_t  max_supported_tx_streams: 4;
    uint8_t  max_supported_rx_streams: 4;
    uint8_t  gi_support_80mhz:         1;
    uint8_t  gi_support_160mhz:        1;
    uint8_t  support_80_80_mhz:        1;
    uint8_t  support_160mhz:           1;
    uint8_t  su_beamformer_capable:    1;
    uint8_t  mu_beamformer_capable:    1;
    uint8_t  reserved:2;
} map_radio_vht_capability_t;

typedef struct map_radio_he_capability_s {
    uint8_t  supported_mcs_length;
    uint16_t supported_tx_rx_mcs[6];
    uint8_t  max_supported_tx_streams: 4;
    uint8_t  max_supported_rx_streams: 4;
    uint8_t  support_80_80_mhz:        1;
    uint8_t  support_160mhz:           1;
    uint8_t  su_beamformer_capable:    1;
    uint8_t  mu_beamformer_capable:    1;
    uint8_t  ul_mimo_capable:          1;
    uint8_t  ul_mimo_ofdma_capable:    1;
    uint8_t  dl_mimo_ofdma_capable:    1;
    uint8_t  ul_ofdma_capable:         1;
    uint8_t  dl_ofdma_capable:         1;
    uint8_t  reserved:                 7;
} map_radio_he_capability_t;

typedef struct map_agent_capablity_s {
    /* AP Capability TLV */
    uint8_t  ib_unassociated_sta_link_metrics_supported;
    uint8_t  oob_unassociated_sta_link_metrics_supported;
    uint8_t  rssi_agent_steering_supported;

    /* Profile 2 AP Capability TLV */
    bool     profile_2_ap_cap_valid;
    uint8_t  byte_counter_unit;
    uint16_t max_vid_count;

    /* Metric collection interval TLV */
    uint32_t metric_collection_interval;
} map_agent_capability_t;

typedef struct map_radio_metrics_s {
    bool    valid;
    uint8_t noise;
    uint8_t transmit;
    uint8_t receive_self;
    uint8_t receive_other;
} map_radio_metrics_t;

typedef struct map_radio_scan_capability_s {
    bool                valid;
    uint8_t             boot_only;
    uint8_t             scan_impact;
    uint32_t            min_scan_interval;
    map_op_class_list_t op_class_list;
} map_radio_scan_capability_t;

typedef struct map_cac_method_s {
    uint8_t             cac_method;
    uint32_t            cac_duration;
    map_op_class_list_t op_class_list;
} map_cac_method_t;

typedef struct map_radio_cac_capability_s {
    uint8_t           cac_method_count;
    map_cac_method_t *cac_method;
} map_radio_cac_capability_t;

typedef struct neighbor_info {
    mac_addr bssid;
    uint8_t  ssid_len;
    uint8_t  ssid[MAX_SSID_LEN];
    uint8_t  rcpi;
    uint8_t  ch_bw_len;
    uint8_t  ch_bw[MAX_CH_BW_STR_LEN];   /* String "20" or "40" or "80" or "80+80" or "160" */
    uint8_t  bss_load_elem_present;      /* 1: field present 0: not */
    uint8_t  channel_utilization;
    uint16_t stas_nr;
} map_channel_scan_neighbor_t;

typedef struct map_scan_result_s {
    int                         scan_cnt;
    uint8_t                     opclass;
    uint8_t                     channel;
    uint8_t                     ts_len;
    uint8_t                     channel_scan_ts[MAX_1905_TIMESTAMP_LEN];
    map_channel_scan_neighbor_t neighbor_info;
} map_scan_result_t;

typedef struct map_scan_info_s {
    struct timespec last_scan_req_time;
    int             last_scan_cnt;
    uint8_t         ts_len;
    uint8_t         last_scan_ts[MAX_1905_TIMESTAMP_LEN]; /* Current time when scan results' came */
    bool            last_scan_status_failed;
} map_scan_info_t;

typedef struct cac_detected_pair {
    uint8_t opclass_detected;
    uint8_t channel_detected;
} map_cac_detected_pair_t;

typedef struct cac_completion_info_s {
    uint8_t                  op_class;
    uint8_t                  channel;
    uint8_t                  status;
    uint8_t                  detected_pairs_nr;
    map_cac_detected_pair_t *detected_pairs;
} map_cac_completion_info_t;

#define MAX_MCS_NSS 6
#define MAP_AP_ROLE_AP  0
#define MAP_AP_ROLE_STA 1
#define MAP_AP_ROLE_MAX 2
typedef struct map_radio_wifi6_cap_data_s {
    uint8_t  agent_role:         2;
    uint8_t  he160:              1;
    uint8_t  he8080:             1;
    uint8_t  mcs_nss_nr:         4;
    uint16_t mcs_nss[MAX_MCS_NSS];
    uint8_t  su_beamformer:      1;
    uint8_t  su_beamformee:      1;
    uint8_t  mu_beamformer:      1;
    uint8_t  beamformee_sts_l80: 1;
    uint8_t  beamformee_sts_g80: 1;
    uint8_t  ul_mu_mimo:         1;
    uint8_t  ul_ofdma:           1;
    uint8_t  dl_ofdma:           1;
    uint8_t  max_dl_mu_mimo_tx:  4;
    uint8_t  max_ul_mu_mimo_rx:  4;
    uint8_t  max_dl_ofdma_tx;
    uint8_t  max_ul_ofdma_rx;
    uint8_t  rts:                1;
    uint8_t  mu_rts:             1;
    uint8_t  multi_bssid:        1;
    uint8_t  mu_edca:            1;
    uint8_t  twt_requester:      1;
    uint8_t  twt_responder:      1;
    uint8_t  reserved:           2;
} map_radio_wifi6_cap_data_t;

typedef struct map_radio_wifi6_capabilities_s {
    uint8_t roles_nr;
    map_radio_wifi6_cap_data_t cap_data[MAP_AP_ROLE_MAX];
} map_radio_wifi6_caps_t;

typedef struct {
    bool              acs_enable;        /* ACS enabled or not */
    map_channel_set_t acs_channels;      /* List of channels ACS may use */
    uint8_t           channel;           /* Fixed channel to be used when acs_enable = false */
    uint8_t           bandwidth;         /* Maximum bandwidth to be used */

    map_channel_set_t def_pref_channels;
    map_channel_set_t pref_channels;
} map_radio_chan_sel_t;

/*#######################################################################
#                       RADIO INFO                                      #
########################################################################*/
typedef struct map_radio_info_s {
    mac_addr                     radio_id;
    mac_addr_str                 radio_id_str;

    list_head_t                  list;
    list_head_t                  bss_list;
    uint8_t                      bsss_nr;

    int                          airdata_idx;
    bool                         airdata_removed;
    uint8_t                      supported_freq;
    uint16_t                     band_type_5G;
    uint8_t                      max_bss;
    uint8_t                      current_op_class;
    uint8_t                      current_op_channel;
    uint8_t                      current_bw;
    uint8_t                      current_tx_pwr;          /* From operating channel report */
    uint8_t                      tx_pwr_limit;            /* Used in channel selection request when not 0 */
    uint16_t                     state;
    struct map_ale_info_s       *ale;
    map_radio_capability_t       radio_caps;
    map_radio_metrics_t          radio_metrics;
    map_radio_ht_capability_t   *ht_caps;
    map_radio_vht_capability_t  *vht_caps;
    map_radio_he_capability_t   *he_caps;
    map_radio_scan_capability_t  scan_caps;
    map_radio_cac_capability_t   cac_caps;
    map_radio_wifi6_caps_t      *wifi6_caps;
    char                         vendor[MAP_INVENTORY_ITEM_LEN + 1];

    map_op_class_list_t          cap_op_class_list;       /* Radio basic capabilities TLV */
    map_op_class_list_t          pref_op_class_list;      /* Agent preference from channel preference report */
    map_op_class_list_t          ctrl_pref_op_class_list; /* Controller preference to be setn in channel selection request */
    map_op_restriction_list_t    op_restriction_list;     /* Radio operating restriction */

    map_channel_set_t            ctl_channels;            /* Set of all possible 20MHz channels */
    map_channel_bw_set_t         channels_with_bandwidth;  /* Set of all possible channels with bandwidth information*/

    void                        *unassoc_metrics;
    map_scan_info_t              last_scan_info;
    array_list_t                *scanned_bssid_list;
    map_cac_completion_info_t    cac_completion_info;
    uint8_t                      ongoing_cac_request;     /* 1: cac request is made and still not finished, 0: there is no cac request */
    map_radio_chan_sel_t         chan_sel;
} map_radio_info_t;

/*#######################################################################
#                       ALE INFO TYPES                                  #
########################################################################*/
typedef enum {
    MAP_PROFILE_1 = 1, /* Multiap Profile-1 */
    MAP_PROFILE_2 = 2  /* Multiap Profile-2 */
} map_profile_t;

typedef struct map_tx_metric_params_s {
    uint16_t phy_rate;
    uint32_t packet_errors;
    uint32_t transmitted_packets;
    uint16_t mac_throughput_capacity;
    uint16_t link_availability;
} map_tx_metric_params_t;

typedef struct map_rx_metric_params_s {
    uint32_t packets_received;
    uint32_t packet_errors;
    int8_t   rssi;
} map_rx_metric_params_t;

typedef struct map_neighbor_link_s {
    mac_addr neighbor_al_mac;
    mac_addr local_iface_mac;
    mac_addr neighbor_iface_mac;
} map_neighbor_link_t;

typedef struct map_neighbor_link_metric_s {
    mac_addr               al_mac;
    mac_addr               neighbor_iface_mac;
    mac_addr               local_iface_mac;
    uint16_t               intf_type;
    map_tx_metric_params_t tx_metric;
    map_rx_metric_params_t rx_metric;
} map_neighbor_link_metric_t;

typedef struct map_local_iface_s {
    mac_addr mac_address;
    uint16_t media_type;
    bool     ieee80211_valid;               /* When true, all ieee80211_xxx fields below are valid */
    uint8_t  ieee80211_role;
    mac_addr ieee80211_network_membership;  /* BSSID for sta interfaces */
    uint8_t  ieee80211_ap_channel_band;
    uint8_t  ieee80211_ap_channel_center_freq_1;
    uint8_t  ieee80211_ap_channel_center_freq_2;
} map_local_iface_t;

typedef struct map_non_1905_neighbor_s {
    mac_addr  local_iface_mac;
    uint16_t  media_type;
    size_t    macs_nr;
    mac_addr *macs;
} map_non_1905_neighbor_t;

typedef struct map_backhaul_sta_iface_s {
    mac_addr  mac_address;
    mac_addr  radio_id;
    bool      active;
} map_backhaul_sta_iface_t;

typedef struct map_device_info_s {
    char     manufacturer_name[MAX_MANUFACTURER_NAME_LEN];
    char     model_name[MAX_MODEL_NAME_LEN];
    char     model_number[MAX_MODEL_NUMBER_LEN];
    char     serial_number[MAX_SERIAL_NUM_LEN];
    uint32_t os_version;
    char     os_version_str[sizeof("123.123.123.123")];  /* os_version as string with format a.b.c.d */
} map_device_info_t;

typedef struct  {
    uint8_t  op_class;
    uint8_t  channel;
    uint16_t minutes_since_cac_completion;
} map_cac_available_pair_t;

typedef struct {
    uint8_t  op_class;
    uint8_t  channel;
    uint16_t seconds_remaining_non_occupancy_duration;
} map_cac_non_occupancy_pair_t;

typedef struct {
    uint8_t  op_class;
    uint8_t  channel;
    uint32_t seconds_remaining_cac_completion;
} map_cac_ongoing_pair_t;

typedef struct map_cac_status_report_s {
    bool                          valid;
    uint8_t                       available_pairs_nr;
    map_cac_available_pair_t     *available_pairs;
    uint8_t                       non_occupancy_pairs_nr;
    map_cac_non_occupancy_pair_t *non_occupancy_pairs;
    uint8_t                       ongoing_cac_pairs_nr;
    map_cac_ongoing_pair_t       *ongoing_cac_pairs;
} map_cac_status_report_t;

typedef struct map_device_inventory_s {
    char serial[MAP_INVENTORY_ITEM_LEN + 1];
    char version[MAP_INVENTORY_ITEM_LEN + 1];
    char environment[MAP_INVENTORY_ITEM_LEN + 1];
} map_device_inventory_t;

/*#######################################################################
#                 ALE INFO TYPES: AIRTIES EM+ EXTENSIONS                #
########################################################################*/
#define EMEX_DEVICE_INFO_CLIENT_ID_MAX  255
#define EMEX_DEVICE_INFO_CLIENT_SEC_MAX 255

#define EMEX_PRODUCT_CLASS_GATEWAY      0x80
#define EMEX_PRODUCT_CLASS_EXTENDER     0x40
#define EMEX_PRODUCT_CLASS_STB          0x20

#define EMEX_DEVICE_ROLE_CONTROLLER     0x80

typedef struct map_agent_extensions_device_info_s {
    bool     received;
    uint32_t boot_id;
    uint8_t  client_id_len;
    uint8_t  client_id[EMEX_DEVICE_INFO_CLIENT_ID_MAX];
    uint8_t  client_secret_len;
    uint8_t  client_secret[EMEX_DEVICE_INFO_CLIENT_SEC_MAX];
    uint8_t  product_class;
    uint8_t  device_role;
} map_agent_extensions_device_info_t;

typedef struct map_agent_extensions_supported_feature_s {
    uint16_t id;
    uint16_t version;
} map_agent_extensions_supported_feature_t;

typedef struct map_agent_extensions_feature_profile_s {
    uint32_t agent_version;
    uint16_t feature_count;
    map_agent_extensions_supported_feature_t *feature_list;
} map_agent_extensions_feature_profile_t;

typedef struct map_agent_extensions_radio_info_s {
	mac_addr id;
	uint8_t  temp;
} STRUCT_PACKED map_agent_extensions_radio_info_t;

typedef struct map_agent_extensions_radios_s {
    uint8_t count;
    map_agent_extensions_radio_info_t *info;
} map_agent_extensions_radios_t;

typedef struct map_agent_extensions_device_metrics_s {
    uint32_t uptime;
    uint8_t  cpu_load;
    uint8_t  cpu_temp;
    uint32_t mem_total;
    uint32_t mem_free;
    uint32_t mem_cached;
    uint32_t cpu_load_sum;
    uint32_t samples;
} map_agent_extensions_device_metrics_t;

typedef struct map_agent_extensions_s {
    bool                                   enabled;
    map_agent_extensions_device_info_t     device_info;
    map_agent_extensions_feature_profile_t feature_profile;
    map_agent_extensions_device_metrics_t  device_metrics;
    map_agent_extensions_radios_t          radios;
} map_agent_extensions_t;

typedef struct map_emex_common_feature_list_s {
    uint16_t feature_count;
    map_agent_extensions_supported_feature_t *feature_list;
} map_agent_extensions_common_feature_list_t;

/*#######################################################################
#                         ALE INFO TYPES: DPP                           #
########################################################################*/
typedef struct map_dpp_encap_msg_s {
    mac_addr enrollee;
    uint8_t  frame_indicator;
    uint8_t  frame_type;
    uint16_t frame_len;
    uint8_t *frame;
} map_dpp_encap_msg_t;

typedef struct map_dpp_chirp_s {
    mac_addr enrollee;
    uint8_t  hash_validity;
    uint8_t  hash_len;
    uint8_t *hash;
} map_dpp_chirp_t;

typedef struct map_dpp_message_s {
    uint16_t frame_len;
    uint8_t *frame;
} map_dpp_message_t;

typedef struct map_dpp_info_s {
    bool cce_advertised;
    map_dpp_chirp_t chirp;
    map_dpp_encap_msg_t encap_msg;
    map_dpp_message_t message;
} map_dpp_info_t;

/*#######################################################################
#                       ALE INFO                                        #
########################################################################*/
typedef enum  {
    ALE_NODE_ONBOARDING                 = 0x01,
    ALE_NODE_ONBOARDED                  = 0x02,
    ALE_NODE_ONBOARD_INCOMPLETE         = 0x04, /* No logic defined now for this state, timer has \
                                                   to be implemented for defining this state */
    ALE_NODE_CONTROLLER_NOT_REACHABLE   = 0x08,
} map_onboard_status_t;

typedef struct map_ale_info_s {
    mac_addr                    al_mac;
    mac_addr_str                al_mac_str;

    bool                        is_local;                       /* True for local agent */
    bool                        is_local_colocated;             /* True for local_agent and running next to controller (same host) */

    list_head_t                 list;
    list_head_t                 radio_list;
    uint8_t                     radios_nr;

    mac_addr                    src_mac;                        /* Source mac used by ALE (mostly same as al_mac) */
    bool                        removing;
    int                         airdata_idx;
    bool                        easymesh;                       /* This is an easymesh 1905 device. Set as follows:
                                                                   - AP Operational BSS TLV present in topology response
                                                                   - AP Radio Capabilities TLV present in autoconfig M1 message
                                                                */
    uint16_t                    state;
    uint8_t                     ale_bcu_status;
    map_onboard_status_t        ale_onboard_status;             /* onboarding status: holds flags to define different onboarding  state */
    struct timespec             ale_onboarding_time;            /* The time that ALE onboarded */
    struct timespec             keep_alive_time;
    uint8_t                     first_chan_sel_req_done;
    struct timespec             last_chan_sel_req_time;
    uint8_t                     local_iface_count;
    map_local_iface_t          *local_iface_list;
    uint8_t                     non_1905_neighbor_count;
    map_non_1905_neighbor_t    *non_1905_neighbor_list;
    uint8_t                     backhaul_sta_iface_count;
    map_backhaul_sta_iface_t   *backhaul_sta_iface_list;
    map_device_info_t           device_info;
    char                        iface_name[MAX_IFACE_NAME_LEN]; /* Receiving interface in controller */
    mac_addr                    upstream_al_mac;                /* AL mac of upstream device. For ease of use as this can also be retreived via the k_tree */
    mac_addr                    upstream_remote_iface_mac;      /* Parent interface mac */
    mac_addr                    upstream_local_iface_mac;       /* bSTA mac */
    uint16_t                    upstream_iface_type;            /* Interface type per table 6-12 of 1905.1 specification */
    uint16_t                    country_code;
    map_agent_capability_t      agent_capability;
    map_profile_t               map_profile;
    array_list_t*               eth_neigh_link_metric_list;
    uint8_t                     neighbor_link_count;
    map_neighbor_link_t        *neighbor_link_list;
    map_neighbor_link_metric_t  upstream_link_metrics;
    void                       *unassoc_metrics;
    k_tree_node                *self_tree_node;
    map_cac_status_report_t     cac_status_report;
    map_agent_extensions_t      agent_extensions;
    map_dpp_info_t              dpp_info;
    map_device_inventory_t      inventory;
    bool                        inventory_exists;
} map_ale_info_t;

/*#######################################################################
#                       FUNCTIONS                                       #
########################################################################*/
/** Initialize data model. */
int map_dm_init(void);

/** De-initializes data model. */
void map_dm_fini(void);

/** Get datamodel. */
list_head_t *map_dm_get(void);

/** Create new agent if not exist. */
map_ale_info_t *map_dm_create_ale(mac_addr al_mac);

/** Get agent node. */
map_ale_info_t *map_dm_get_ale(mac_addr al_mac);

/** Get agent node using source mac address. */
map_ale_info_t *map_dm_get_ale_from_src_mac(mac_addr src_mac);

/** Remove agent node. */
int map_dm_remove_ale(map_ale_info_t *ale);

/** Create new radio node if not exist. */
map_radio_info_t* map_dm_create_radio(map_ale_info_t *ale, mac_addr radio_id);

/** Get radio from ale */
map_radio_info_t* map_dm_get_radio(map_ale_info_t* ale, mac_addr radio_id);

/** Remove radio. */
int map_dm_remove_radio(map_radio_info_t *radio);

/** Create BSS if not exist. */
map_bss_info_t* map_dm_create_bss(map_radio_info_t *radio, mac_addr bssid);

/** Get BSS from radio. */
map_bss_info_t* map_dm_get_bss(map_radio_info_t *radio, mac_addr bssid);

/** Get BSS from ale */
map_bss_info_t* map_dm_get_bss_from_ale(map_ale_info_t *ale, mac_addr bssid);

/** Get BSS global */
map_bss_info_t* map_dm_get_bss_gbl(mac_addr bssid);

/** Remove BSS. */
int map_dm_remove_bss(map_bss_info_t *bss);

/** Create new STA if not exist. */
map_sta_info_t *map_dm_create_sta(map_bss_info_t *bss, mac_addr mac);

/** Get STA from bss */
map_sta_info_t* map_dm_get_sta(map_bss_info_t *bss, mac_addr mac);

/** Get STA from  ale */
map_sta_info_t* map_dm_get_sta_from_ale(map_ale_info_t *ale, mac_addr mac);

/** Get sta global */
map_sta_info_t *map_dm_get_sta_gbl(mac_addr mac);

/** Remove sta. */
int map_dm_remove_sta(map_sta_info_t *sta);

/** Link sta to other bss
 *
 *  DEPRECATED. Should keep sta per BSS and not move between
 */
int map_dm_update_sta_bss(map_bss_info_t *bss, map_sta_info_t *sta);

/*#######################################################################
#                       VARIOUS                                         #
########################################################################*/
/** Remove cac methods info if exist. */
void map_dm_free_cac_methods(map_cac_method_t *cac_method, uint8_t count);

void map_dm_free_non_1905_neighbor_list(map_ale_info_t *ale);

void map_dm_get_ale_timer_id(timer_id_t id, map_ale_info_t *ale, const char *type);

void map_dm_get_ale_int_timer_id(timer_id_t id, map_ale_info_t *ale, const char *type, uint64_t val);

void map_dm_get_radio_timer_id(timer_id_t id, map_radio_info_t *radio, const char *type);

void map_dm_get_sta_timer_id(timer_id_t id, map_sta_info_t *sta, const char *type);

bool map_dm_is_inactive_sta(mac_addr mac);

#define map_dm_is_bh_sta(sta) (sta->sta_caps.backhaul_sta)
#define map_dm_is_mbo_sta(sta) (sta->sta_caps.mbo_support)

#define map_dm_get_sta_assoc_ts(assoc_time)          (acu_get_timestamp_sec() + MAP_ASSOC_TS_DELTA - assoc_time)
#define map_dm_get_sta_assoc_ts_delta(assoc_ts)      (acu_get_timestamp_sec() + MAP_ASSOC_TS_DELTA - assoc_ts)
#define map_dm_get_sta_assoc_ts_delta2(ts, assoc_ts) (ts                      + MAP_ASSOC_TS_DELTA - assoc_ts)


#define map_dm_mark_sta(sta)      do { sta->marked = true; } while(0)
#define map_dm_unmark_sta(sta)    do { sta->marked = false; } while(0)
#define map_dm_is_marked_sta(sta) (sta->marked)

/* Mark all sta of an ale */
void map_dm_mark_stas(map_ale_info_t *ale);

/* Remove sta that are marked and where associated longer than "min_assoc_time */
void map_dm_remove_marked_stas(map_ale_info_t *ale, unsigned int min_assoc_time);

/*#######################################################################
#                       ITERATORS                                       #
########################################################################*/
extern map_ale_info_t* get_root_ale_node();

/* ALEs */
#define map_dm_foreach_ale(ale)                     list_for_each_entry(ale, map_dm_get(), list)
#define map_dm_foreach_ale_safe(ale, next)          list_for_each_entry_safe(ale, next, map_dm_get(), list)

/* Agent ALEs (so skip controller) */
#define map_dm_foreach_agent_ale(ale)               list_for_each_entry(ale, map_dm_get(), list) if (ale != get_root_ale_node())
#define map_dm_foreach_agent_ale_safe(ale, next)    list_for_each_entry_safe(ale, next, map_dm_get(), list) if (ale != get_root_ale_node())

/* Radios */
#define map_dm_foreach_radio(ale, radio)            list_for_each_entry(radio, &ale->radio_list, list)
#define map_dm_foreach_radio_safe(ale, radio, next) list_for_each_entry_safe(radio, next, &ale->radio_list, list)

/* Bsss */
#define map_dm_foreach_bss(radio, bss)              list_for_each_entry(bss, &radio->bss_list, list)
#define map_dm_foreach_bss_safe(radio, bss, next)   list_for_each_entry_safe(bss, next, &radio->bss_list, list)

/* Stas */
#define map_dm_foreach_sta(bss, sta)                list_for_each_entry(sta, &bss->sta_list, list)
#define map_dm_foreach_sta_safe(bss, sta, next)     list_for_each_entry_safe(sta, next, &bss->sta_list, list)

/*#######################################################################
#                       DM UPDATE CALLBACKS AND FUNCTIONS               #
########################################################################*/
/* THIS IS WORK IN PROGRESS
   The goal is that all datamodel updates that need to trigger something
   are done via functions in stead of directly modifying the data

   There are currently 2 use cases:
   - msg_lib:  Target should be that no longer needs to be cached in side
               to detect changes
   - dm_airdata: Avoid unescessary data set actions
*/

typedef struct {
    list_head_t list;
    bool        registered;

    void (*ale_create_cb)(map_ale_info_t *ale);
    void (*ale_update_cb)(map_ale_info_t *ale);
    void (*ale_remove_cb)(map_ale_info_t *ale);

    void (*radio_create_cb)(map_radio_info_t *radio);
    void (*radio_update_cb)(map_radio_info_t *radio);
    void (*radio_remove_cb)(map_radio_info_t *radio);

    void (*bss_create_cb)(map_bss_info_t *bss);
    void (*bss_update_cb)(map_bss_info_t *bss);
    void (*bss_remove_cb)(map_bss_info_t *bss);
} map_dm_cbs_t;

/* Register dm callback functions (note: cbs must be static structure) */
void map_dm_register_cbs(map_dm_cbs_t *cbs);

/* Unregister dm callback functions */
void map_dm_unregister_cbs(map_dm_cbs_t *cbs);

/* Update device info */
void map_dm_ale_set_device_info(map_ale_info_t *ale, map_device_info_t *device_info);

/* Update onboard status */
void map_dm_ale_set_onboard_status(map_ale_info_t *ale, map_onboard_status_t status);

/* Update upstream ale and interface */
void map_dm_ale_set_upstream_info(map_ale_info_t *ale, mac_addr us_al_mac, mac_addr us_local_mac,
                                  mac_addr us_remote_mac, bool set_if_type, int if_type);

/* Update capabilities */
void map_dm_radio_set_capabilities(map_radio_info_t *radio);

/* Update channel related parameters */
void map_dm_radio_set_channel(map_radio_info_t *radio, uint8_t op_class, uint8_t channel, uint8_t bw, uint8_t tx_pwr);

/* Update channel selection data */
void map_dm_radio_set_chan_sel(map_radio_info_t *radio, bool acs_enable, map_channel_set_t *acs_channels, uint8_t channel, uint8_t bw);

/* Update ssid and bss type */
void map_dm_bss_set_ssid(map_bss_info_t *bss, size_t ssid_len, uint8_t *ssid, int bss_type);

#endif /* MAP_DATA_MODEL_H_ */
