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

/* FRV: This header file belongs in 1905 stack, should be moved back */

#ifndef PLATFORM_1905_H
#define PLATFORM_1905_H

#include <stdio.h>
#include <stdint.h>

#include "map_common_defines.h"

typedef void (*i1905_interface_cb_t)(const char *ifname, bool added);

/*******************************************************************************
*  The 1905 standard originally only recognized a limited set of interface
*  types (IEEE802.11, IEEE802.3, IEEE1901, MOCA, ...) and for each of these
*  types some parameters were defined (for example, the "bssid" and other
*  things for IEEE802.11 interfaces, the "networ).
*
*  Later, the standard was expanded to accept arbitrary parameters from all
*  types of interfaces. This is done by using the next structure.
*******************************************************************************/
struct genericInterfaceType {
    uint8_t oui[3];         /* Three bytes containing either the
                            *  "Organizationally Unique Identifier"
                            *  ("http://standards.ieee.org/develop/regauth/oui")
                            *  or the "Company ID"
                            *  ("http://standards.ieee.org/develop/regauth/cid")
                            *  responsible for this particular interface type.
                            */

    char *generic_phy_description_xml_url;
                            /* NULL terminated string pointing to the URL of
                            *  the "Generic Phy XML Description Document" that
                            *  describes the properties of this interface type.
                            *  This document must conform to the "Generic Phy
                            *  XML schema"
                            *  ("http://standards.ieee.org/downloads/1905/GenericPhyInfoV1.xsd")
                            */

    uint8_t variant_index;  /* The "Generic Phy XML Description Document" might
                            *  might contain more than one "class" of
                            *  interfaces for each OUI. This variable is used
                            *  to identify which class/variant is the one that
                            *  applies to this particular interface type.
                            */

    char *variant_name;     /* NULL terminated string containing the "friendly
                            *  name" this variant receives in the "Generic Phy
                            *  XML Description Document".
                            *  Must not be longer than 32 bytes (including the
                            *  final NULL character).
                            *    NOTE: The OUI and variant_index are
                            *    enough to identify a variant inside a
                            *    "Generic Phy XML Description Document",
                            *    however we required this field too for
                            *    convinience.
                            */

    union _mediaSpecific {
        struct _ituGhn {
            /* This is the structure to fill when:
            *
            *   - 'generic_phy_description_xml_url' is set to
            *     "http://handle.itu.int/11.1002/3000/1706"
            *
            *   - 'oui' is set to 00:19:A7
            *
            *   - ...and the 'variant_index' is set to either 1, 2, 3 or 4
            */

            uint8_t dni[2]; /* Domain name identifier (see clause
                            *  8.6.8.2.1 of "ITU-T G.9961")
                            */
        } ituGhn;

        struct _unsupported {
            /* This is the structure to fill in all other cases. If you don't
            *  want to provide media specific data, just set 'bytes_nr' to '0',
            *  otherwise use this array to send arbitrary data to upper layers
            */
            uint16_t  bytes_nr;
            uint8_t  *bytes;

        } unsupported;

    } media_specific;

};

/*******************************************************************************
** Interfaces info
*******************************************************************************/
typedef struct interfaceInfo {
    char  *name;

    int interface_index;

    uint8_t mac_address[6];


    char manufacturer_name[64];
    char model_name       [64];
    char model_number     [64];
    char serial_number    [64];
    char device_name      [64];
    char uuid             [64];

    #define INTERFACE_TYPE_IEEE_802_3U_FAST_ETHERNET       (0x0000)
    #define INTERFACE_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET   (0x0001)
    #define INTERFACE_TYPE_IEEE_802_11B_2_4_GHZ            (0x0100)
    #define INTERFACE_TYPE_IEEE_802_11G_2_4_GHZ            (0x0101)
    #define INTERFACE_TYPE_IEEE_802_11A_5_GHZ              (0x0102)
    #define INTERFACE_TYPE_IEEE_802_11N_2_4_GHZ            (0x0103)
    #define INTERFACE_TYPE_IEEE_802_11N_5_GHZ              (0x0104)
    #define INTERFACE_TYPE_IEEE_802_11AC_5_GHZ             (0x0105)
    #define INTERFACE_TYPE_IEEE_802_11AD_60_GHZ            (0x0106)
    #define INTERFACE_TYPE_IEEE_802_11AF                   (0x0107)
    #define INTERFACE_TYPE_IEEE_802_11AX                   (0x0108) /* MAP R2 extension. One value all bands */
    #define INTERFACE_TYPE_IEEE_1901_WAVELET               (0x0200)
    #define INTERFACE_TYPE_IEEE_1901_FFT                   (0x0201)
    #define INTERFACE_TYPE_MOCA_V1_1                       (0x0300)
    #define INTERFACE_TYPE_UNKNOWN                         (0xFFFF)
    uint16_t interface_type;    /* Indicates the MAC/PHY type of the underlying
                                *  network technology.
                                *  Valid values: any "INTERFACE_TYPE_*" value.
                                *  If your interface is of a type not listed here,
                                *  set it to "INTERFACE_TYPE_UNKNOWN" and then
                                *  use the "interface_type_data.other" field to
                                *  further identify it.
                                */

    union _interfaceTypeData {
        /* Only to be filled when interface_type = INTERFACE_TYPE_IEEE_802_11* */
        struct _ieee80211Data {
            uint8_t  bssid[6];  /* This is the BSSID (MAC address of the
                                *  registrar AP on a wifi network).
                                *  On unconfigured nodes (ie. STAs which
                                *  have not yet joined a network or non-
                                *  registrar APs which have not yet cloned
                                *  the credentiales from the registrar) this
                                *  parameter must be set to all zeros.
                                */

            char   ssid[50];    /* This is the "friendly" name of the wifi
                                *  network created by the registrar AP
                                *  identified by 'bssid'
                                */

            #define IEEE80211_ROLE_AP                   (0x0)
            #define IEEE80211_ROLE_NON_AP_NON_PCP_STA   (0x4)
            #define IEEE80211_ROLE_WIFI_P2P_CLIENT      (0x8)
            #define IEEE80211_ROLE_WIFI_P2P_GROUP_OWNER (0x9)
            #define IEEE80211_ROLE_AD_PCP               (0xa)
            uint8_t  role;            /* One of the values from above */

            #define IEEE80211_AP_CHANNEL_BAND_20MHZ     (0x0)
            #define IEEE80211_AP_CHANNEL_BAND_40MHZ     (0x1)
            #define IEEE80211_AP_CHANNEL_BAND_80MHZ     (0x2)
            #define IEEE80211_AP_CHANNEL_BAND_160MHZ    (0x3)
            #define IEEE80211_AP_CHANNEL_BAND_80P80MHZ  (0x4)
            #define IEEE80211_AP_CHANNEL_BAND_320MHZ    (0x5) /* TODO: check agent behaviors */
            uint8_t ap_channel_band;  /* Hex value of dot11CurrentChannelBandwidth
                                      *  (see "IEEE P802.11ac/D3.0" for description)
                                      */

            uint8_t ap_channel_center_frequency_index_1;
                                      /* Hex value of
                                      *  dot11CurrentChannelCenterFrequencyIndex1
                                      *  (see "IEEE P802.11ac/D3.0" for description)
                                      */

            uint8_t ap_channel_center_frequency_index_2;
                                      /* Hex value of
                                      *  dot11CurrentChannelCenterFrequencyIndex2
                                      *  (see "IEEE P802.11ac/D3.0" for description)
                                      */

            #define IEEE80211_AUTH_MODE_OPEN    (0x0001)
            #define IEEE80211_AUTH_MODE_WPAPSK  (0x0002)
            #define IEEE80211_AUTH_MODE_SHARED  (0x0004) /* deprecated */
            #define IEEE80211_AUTH_MODE_WPA     (0x0008)
            #define IEEE80211_AUTH_MODE_WPA2    (0x0010)
            #define IEEE80211_AUTH_MODE_WPA2PSK (0x0020)
            #define IEEE80211_AUTH_MODE_SAE     (0x0040)


            uint16_t authentication_mode;
                                     /* For APs: list of supported modes that
                                     *  clients can use (OR'ed list of flags)
                                     *  For STAs: current mode being used with
                                     *  its AP (a single flag)
                                     */

            #define IEEE80211_ENCRYPTION_MODE_NONE (0x0001)
            #define IEEE80211_ENCRYPTION_MODE_TKIP (0x0004)
            #define IEEE80211_ENCRYPTION_MODE_AES  (0x0008)
            uint16_t encryption_mode;
                                     /* For APs: list of supported modes that
                                     *  clients can use (OR'ed list of flags)
                                     *  For STAs: current mode being used with
                                     *  its AP (a single flag)
                                     */

            char  network_key[64];   /* Key that grants access to the AP network */

        } ieee80211;

        /* Only to be filled when interface_type = INTERFACE_TYPE_IEEE_1901* */
        struct _ieee1901Data {
            char network_identifier[7];  /* Network membership */
        } ieee1901;

        /* Only to be filled when interface_type = INTERFACE_TYPE_UNKNOWN */
        struct genericInterfaceType other;

    } interface_type_data; /* Depending on the value of "interface_type", one
                           *  (and only one!) of the structures of this union
                           *  must be filled
                           */

    uint8_t is_secured;    /* Contains "1" if the interface is secure, "0"
                           *  otherwise.
                           *
                           *  Note that "secure" in this context means that the
                           *  interface can be trusted to send private (in a
                           *  "local network" way) messages.
                           *
                           *  For example:
                           *
                           *    1. A "wifi" interface can only be considered
                           *       "secure" if encryption is on (WPA, WPA2,
                           *       etc...)
                           *
                           *    2. A G.hn/1901 interface can only be considered
                           *       "secure" if some one else's untrusted device
                           *       can not "sniff" your traffic.  This typically
                           *       means either encryption or some other
                           *       technology dependent "trick" (ex: "network
                           *       id") is enabled.
                           *
                           *    3. An ethernet interface can probably be always
                           *       be considered "secure" (but this is let for
                           *       the implementer to decide)
                           *
                           *  One interface becomes "secured" when it contains
                           *  at least one link which is "secured".
                           *  For example, a wifi AP interface is considered
                           *  "secured" if there is at least one STA connected
                           *  to it by means of an encrypted channel.
                           */

    uint8_t push_button_on_going;
                           /* Some types of interfaces support a technology-
                           *  specific "push button" configuration mechanism
                           *  (ex: "802.11", "G.hn"). Others don't (ex: "eth").
                           *
                           *  This value is set to any of these possible values:
                           *
                           *    - "0" if the interface type supports this "push
                           *      button" configuration mechanism but, right
                           *      now, this process is not running.
                           *
                           *    - "1" if the interface type supports this "push
                           *      button" configuration mechanism and, right
                           *      now, we are in the middle of such process.
                           *
                           *    - "2" if the interface does not support the
                           *     "push button" configuration mechanism.
                           */

    uint8_t push_button_new_mac_address[6];
                           /* 6  bytes long MAC address of the device that has
                           *  just joined the network as a result of a "push
                           *  button configuration" process (ie., just after
                           *  "push_button_on_going" changes from "1" to "0")
                           *  This field is set to all zeros when either:
                           *
                           *    A) WE are the device joining the network
                           *
                           *    B) No new device entered the network
                           *
                           *    C) The underlying technology does not offer this
                           *      information
                           */

    #define INTERFACE_POWER_STATE_ON     (0x00)
    #define INTERFACE_POWER_STATE_SAVE   (0x01)
    #define INTERFACE_POWER_STATE_OFF    (0x02)
    uint8_t power_state;   /* Contains one of the INTERFACE_POWER_STATE_* values from above */

    #define INTERFACE_PORT_STATE_DISABLED    (0x00)
    #define INTERFACE_PORT_STATE_LISTENING   (0x01)
    #define INTERFACE_PORT_STATE_LEARNING    (0x02)
    #define INTERFACE_PORT_STATE_FORWARDING  (0x03)
    #define INTERFACE_PORT_STATE_BLOCKING    (0x04)
    uint8_t port_state;

    #define INTERFACE_NEIGHBORS_UNKNOWN (0xFF)
    uint8_t  neighbor_mac_addresses_nr;
                             /* Number of other MAC addresses (pertaining -or
                             *  not- to 1905 devices) this interface has
                             *  received packets from in the past (not
                             *  necessarily from the time the interface was
                             *  brought up, but a reasonable amount of time)
                             *  A special value of "INTERFACE_NEIGHBORS_UNKNOWN"
                             *  is used to indicate that this interface has no
                             *  way of obtaining this information (note that
                             *  this is different from "0" which means "I know I
                             *  have zero neighbors")
                             */

    uint8_t  (*neighbor_mac_addresses)[6];
                             /* List containing those MAC addreses just
                             *  described in the comment above.
                             */

    uint8_t  ipv4_nr;        /* Number of IPv4 this device responds to */
    struct _ipv4 {
        #define IPV4_UNKNOWN (0)
        #define IPV4_DHCP    (1)
        #define IPV4_STATIC  (2)
        #define IPV4_AUTOIP  (3)
        uint8_t type;           /* One of the values from above */

        uint8_t address[4];     /* IPv4 address */

        uint8_t dhcp_server[4]; /* If the ip was obtained by DHCP, this
                                *  variable holds the IPv4 of the server
                                *  (if known). Set to all zeros otherwise
                                */
    } *ipv4;                    /* Array of 'ipv4_nr' elements. Each
                                *  element represents one of the IPv4 of
                                *  this device.
                                */

    uint8_t  ipv6_nr;           /* Number of IPv6 this device responds to */
    struct _ipv6 {
        #define IPV6_UNKNOWN (0)
        #define IPV6_DHCP    (1)
        #define IPV6_STATIC  (2)
        #define IPV6_SLAAC   (3)
        uint8_t type;          /* One of the values from above */

        uint8_t address[16];   /* IPv6 address */

        uint8_t origin[16];    /* If type == IPV6_TYPE_DHCP, this field
                               *  contains the IPv6 address of the DHCPv6 server.
                               *  If type == IPV6_TYPE_SLAAC, this field contains
                               *  the IPv6 address of the router that provided
                               *  the SLAAC address.
                               *  In any other case this field is set to all
                               *  zeros.
                               */

    } *ipv6;                   /* Array of 'ipv6_nr' elements. Each
                               *  element represents one of the IPv6 of
                               *  this device.
                               */

    uint8_t  vendor_specific_elements_nr;
                           /* Number of items in the "vendor_specific_elements" array */

    struct _vendorSpecificInfoElement  {
        uint8_t    oui[3]; /* 24 bits globally unique IEEE-RA assigned
                           *  number to the vendor
                           */

        uint16_t   vendor_data_len;  /* Number of bytes in "vendor_data" */
        uint8_t   *vendor_data;      /* Vendor specific data */
    } *vendor_specific_elements;
} i1905_interface_info_t;

#define INTERFACE_TYPE_GROUP_ETHERNET    (0x00)
#define INTERFACE_TYPE_GROUP_WLAN        (0x01)
#define INTERFACE_TYPE_GROUP_WAVELET_FFT (0x02)
#define INTERFACE_TYPE_GROUP_MOCA        (0x03)
#define INTERFACE_TYPE_GROUP_GET(m)      ((m & 0xFF00) >> 8)

/*******************************************************************************
** Bridges info
*******************************************************************************/
#define MAX_IFACES_IN_BRIDGE   20
#define MAX_BRIDGES_PER_DEV    32

typedef struct bridge {
    char      name[MAX_IFACE_NAME_LEN];

    uint8_t   bridged_interfaces_nr;
    char      bridged_interfaces[MAX_IFACES_IN_BRIDGE][MAX_IFACE_NAME_LEN];
                            /* Names of the interfaces (such as "eth0") that
                            *  belong to this bridge
                            */

    uint8_t   forwarding_rules_nr;
    struct   _forwardingRules {
        /* TODO */
    } forwarding_rules;
} i1905_bridge_t;


static inline char *convert_interface_type_to_string(uint16_t iface_type)
{
    switch (iface_type) {
        case INTERFACE_TYPE_IEEE_802_3U_FAST_ETHERNET:
        case INTERFACE_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET:
            return "ETHERNET";
        case INTERFACE_TYPE_IEEE_802_11B_2_4_GHZ:
        case INTERFACE_TYPE_IEEE_802_11G_2_4_GHZ:
        case INTERFACE_TYPE_IEEE_802_11N_2_4_GHZ:
            return "2_4_GHZ_WIRELESS";
        case INTERFACE_TYPE_IEEE_802_11N_5_GHZ:
        case INTERFACE_TYPE_IEEE_802_11A_5_GHZ:
        case INTERFACE_TYPE_IEEE_802_11AC_5_GHZ:
            return "5_GHZ_WIRELESS";
        case INTERFACE_TYPE_IEEE_802_11AD_60_GHZ:
            return "60_GHZ_WIRELESS";
        case INTERFACE_TYPE_IEEE_802_11AX:
            return "WIRELESS";
        case INTERFACE_TYPE_IEEE_1901_WAVELET:
        case INTERFACE_TYPE_IEEE_1901_FFT:
        case INTERFACE_TYPE_MOCA_V1_1:
        case INTERFACE_TYPE_UNKNOWN:
            return "UNKNOWN";
        default:
            return "UNKNOWN";
    }
}

#endif //PLATFORM_1905_H
