/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef MAP_EMEX_TLVS_H_
#define MAP_EMEX_TLVS_H_

/* AirTies EM+ Extension Vendor OUI */
#define AIRTIES_VENDOR_OUI_1 0x88
#define AIRTIES_VENDOR_OUI_2 0x41
#define AIRTIES_VENDOR_OUI_3 0xfc

/* AirTies EM+ Extension TLV IDs */
enum emex_tlv_type {
    EMEX_TLV_UNUSED                             = 0x0000,
    EMEX_TLV_DEVICE_METRICS                     = 0x0004,
    EMEX_TLV_ETH_STATS                          = 0x000A,
    EMEX_TLV_ETH_INTERFACES                     = 0x000F,
    EMEX_TLV_ETH_STATS_V2                       = 0x0010,
    EMEX_TLV_TYPE_ETH_NON_1905_NEIGHBOR_DEVICES = 0x0011,
    EMEX_TLV_TYPE_ETH_1905_NEIGHBOR_DEVICES     = 0x0012,
};

/* Ethernet interfaces TLV */
#define EMEX_ETH_LINK_TYPE_UNDEFINED 0
#define EMEX_ETH_LINK_TYPE_10MBPS    1
#define EMEX_ETH_LINK_TYPE_100MBPS   2
#define EMEX_ETH_LINK_TYPE_1000MBPS  3
#define EMEX_ETH_LINK_TYPE_2500MBPS  4
#define EMEX_ETH_LINK_TYPE_5000MBPS  5
#define EMEX_ETH_LINK_TYPE_10000MBPS 6

/* Ethernet stats TLV supported stats flags */
#define EMEX_ETH_STATS_HAS_TX_BCAST_BYTES   0x8000
#define EMEX_ETH_STATS_HAS_RX_BCAST_BYTES   0x4000
#define EMEX_ETH_STATS_HAS_TX_BCAST_PACKETS 0x2000
#define EMEX_ETH_STATS_HAS_RX_BCAST_PACKETS 0x1000
#define EMEX_ETH_STATS_HAS_TX_MCAST_BYTES   0x0800
#define EMEX_ETH_STATS_HAS_RX_MCAST_BYTES   0x0400
#define EMEX_ETH_STATS_HAS_TX_MCAST_PACKETS 0x0200
#define EMEX_ETH_STATS_HAS_RX_MCAST_PACKETS 0x0100

#endif /* MAP_EMEX_TLVS_H_ */
