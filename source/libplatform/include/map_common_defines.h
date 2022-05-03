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

#ifndef MAP_COMMON_DEFINES_H_
#define MAP_COMMON_DEFINES_H_

#include <stdint.h>

/****************** DEFAULT VALUES ******************/
#define MAP_DEFAULT_FREQ_2_4_GHZ                    1
#define MAP_DEFAULT_FREQ_5_GHZ                      1
#define MAP_DEFAULT_FREQ_60_GHZ                     0
#define MAP_DEFAULT_TOPOLOGY_DISCOVERY_INTERVAL     60
#define MAP_DEFAULT_LLDP_BRIDGE_DISCOVERY_INTERVAL  3
#define MAP_DEFAULT_UCI_MGMT_IPC_REPORT_INTERVAL    5
#define MAP_DEFAULT_CHANNEL_SELECTION_ENABLED       1
#define MAP_DEFAULT_MULTIAP_PROFILE                 2
/****************************************************/


/* Add all the macros in here */
#define MAP_MAX_MAC_HASH            17 /* Number of buckets for sta hash table (must be prime) */

#define MAX_IFACE_NAME_LEN          17 /* Length = 16 + 1 for Null character at the end */
#define MAX_INTERFACE_COUNT         32
#define MAX_RADIO_NAME_LEN          32
#define MAC_ADDR_LEN                6
#define MAX_MAC_STRING_LEN          18 /* sizeof("00:00:00:00:00:00") */
#define MAX_TIMER_ID_STRING_LENGTH  80 /* including NULL char */

#define MAX_NUM_PROFILES            16

#define MAX_BSS_PER_RADIO           16
#define MAX_RADIO_PER_AGENT         4
#define MAX_BSS_PER_AGENT           MAX_RADIO_PER_AGENT * MAX_BSS_PER_RADIO
#define MAX_STATION_PER_BSS         128
#define MAX_STATION_PER_AGENT       (MAX_RADIO_PER_AGENT * MAX_STATION_PER_BSS) /* Should be per bss but that is ridicoulous */

#define MAX_INACTIVE_STA            128

#define MAX_OP_CLASS                48
#define MAX_CHANNEL_PER_OP_CLASS    24

#define MAX_TRAFFIC_SEP_SSID        8
#define MAX_ACCESS_CATEGORY         4
#define MAX_WIFI_SSID_LEN           33 /* Length = 32 + 1 for Null character at the end */
#define MAX_SSID_LEN                33 /* Length = 32 + 1 for adding NULL character at the end */
#define MAX_WIFI_PASSWORD_LEN       65 /* Length = 64 + 1 for Null character at the end */
#define MAX_AUTH_TYPE_LEN           25
#define MAX_MANUFACTURER_NAME_LEN   65 /* Length = 64 (WPS spec) + 1 for adding NULL character at the end */
#define MAX_MODEL_NAME_LEN          33 /* Length = 32 (WPS spec) + 1 for adding NULL character at the end */
#define MAX_MODEL_NUMBER_LEN        33 /* Length = 32 (WPS spec) + 1 for adding NULL character at the end */
#define MAX_SERIAL_NUM_LEN          65 /* Length = 64 (WPS spec) + 1 for adding NULL character at the end */
#define MAX_1905_TIMESTAMP_LEN      30 /* YYYY-MM-DDTHH:MM:SS.FFF+HH:MM + null */
#define MAX_CH_BW_STR_LEN           6  /* "80+80" + null */
#define MAX_SCAN_STATUS_STR_LEN     25 /* "FRESH SCAN NOT SUPPORTED" + null */
#define MAX_SCAN_TYPE_STR_LEN       9  /* "PASSIVE" + null */
#define MAX_PROFILE_LABEL_LEN       65 /* Length = 64 + 1 for Null character at the end */
#define NUM_FREQ_BANDS              3  /* 2.4G, 5G, 6G */

/* Flags for MultiAp extension subelement  */
#define MAP_TEAR_DOWN               0x10 /* Bit 4 */
#define MAP_FRONTHAUL_BSS           0x20 /* Bit 5 */
#define MAP_BACKHAUL_BSS            0x40 /* Bit 6 */
#define MAP_BACKHAUL_STA            0x80 /* Bit 7 */

#define HASH_KEY_LEN                22  /* sizeof("ALE:00:00:00:00:00:00") */
#define MAC_ADDR_START_OFFSET       4

#define MAX_CHANNEL_SET             54

#define MAX_TIME_LEN                50

#define PREF_SCORE_0                0
#define PREF_SCORE_15               15

#define PREF_REASON_UNSPECFIED                 0
#define PREF_REASON_RADAR_DETECT               7
#define PREF_REASON_EXT_NETWORK_INTERFERENCE   3

#define TLV_TYPE_FIELD   1
#define TLV_LENGTH_FIELD 2

#define STD_80211_B      0
#define STD_80211_G      1
#define STD_80211_A      2
#define STD_80211_N      3
#define STD_80211_AC     4
#define STD_80211_AN     5
#define STD_80211_ANAC   6
#define STD_80211_NAX    7
#define STD_80211_ANACAX 8
#define STD_80211_ANAX   9
#define STD_80211_ACAX   10

#define WIFI_AC_BE       0  /* Best effort Access class */
#define WIFI_AC_BK       1  /* Background Access class */
#define WIFI_AC_VD       2  /* Video Access class */
#define WIFI_AC_VO       3  /* Voice Access class */

#define MAP_ASSOC_STA_LINK_METRICS_INCLUSION_POLICY (1<<6)
#define MAP_ASSOC_STA_TRAFFIC_STA_INCLUSION_POLICY  (1<<7)

/* Use below keys prepended with ALE MAC address of the agent */
#define ONBOARDING_STATUS_TIMER_ID          "ONBOARDING-STATUS-TIMER"
#define HLDATA_SSID_PROFILE_SYNC_TIMER_ID   "HLDATA-SSID-PROFILE-SYNC-TIMER"
#define MCAST_CONFIG_RENEW_TIMER_ID         "MCAST-CONFIG-RENEW-TIMER"

#define AP_CAPS_QUERY_RETRY_ID      "AP-CAPS-QUERY"
#define CHAN_PREF_QUERY_RETRY_ID    "AP-CHAN-PREF-QUERY"
#define CHAN_SELEC_REQ_RETRY_ID     "AP-CHAN-SELC_REQ"
#define TOPOLOGY_QUERY_RETRY_ID     "TOPOLOGY-QUERY"
#define BEACON_METRICS_RETRY_ID     "BEACON-METRICS-RESP"
#define AUTOCONFIG_RESP_RETRY_ID    "AUTOCONFIG-RESP"
#define UCAST_CONFIG_RENEW_RETRY_ID "UCAST-CONFIG-RENEW"
#define VENDOR_SPEFICIC_RETRY_ID    "VENDOR-SPECIFIC"
#define HIGHER_LAYER_DATA_RETRY_ID  "HIGHER-LAYER-DATA"
#define ASSOC_CONTROL_RETRY_ID      "ASSOC-CONTROL"

/* Use below keys prepended with RADIO MAC address */
#define POLICY_CONFIG_RETRY_ID      "POLICY-CONFIG"
#define INITIAL_SCAN_REQ_RETRY_ID   "INITIAL-SCAN-REQ"

/* Use below keys prepended with STA MAC address */
#define CLIENT_CAPS_QUERY_RETRY_ID  "CLIENT-CAPS-QUERY"
#define CLIENT_ASSOC_FRAME_RETRY_ID "CLIENT-ASSOC-FRAME"

#define MAP_RETRY_STATUS_SUCCESS     0
#define MAP_RETRY_STATUS_TIMEOUT   (-1)
#define MAP_RETRY_STATUS_CANCELLED (-2)

#define MAP_INVENTORY_ITEM_LEN 64

enum {
    TUNNELED_MSG_PAYLOAD_ASSOC_REQ       = 0x00,
    TUNNELED_MSG_PAYLOAD_REASSOC_REQ     = 0x01,
    TUNNELED_MSG_PAYLOAD_BTM_QUERY       = 0x02,
    TUNNELED_MSG_PAYLOAD_WNM_REQ         = 0x03,
    TUNNELED_MSG_PAYLOAD_ANQP_REQ        = 0x04,
};

#define MAX_TOTAL_CHANNELS 39 //25 ch for 5GHZ and 14 ch for 2.4Ghz

#define MAP_ASSOC_TS_DELTA            65536 /* Max assoc time in Associated Clients TLV */

/* TODO: also defines in 1905_tlvs.h */
#ifndef IEEE80211_FREQUENCY_BAND_2_4_GHZ
  #define IEEE80211_FREQUENCY_BAND_2_4_GHZ 0x00
  #define IEEE80211_FREQUENCY_BAND_5_GHZ   0x01
  #define IEEE80211_FREQUENCY_BAND_60_GHZ  0x02
#endif

enum map_m2_bss_freq_band {
    MAP_M2_BSS_RADIO2G  = 0x10,
    MAP_M2_BSS_RADIO5GU = 0x20,
    MAP_M2_BSS_RADIO5GL = 0x40,
};

#endif /* MAP_COMMON_DEFINES_H_ */
