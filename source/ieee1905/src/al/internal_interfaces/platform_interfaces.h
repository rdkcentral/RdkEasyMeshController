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

#ifndef PLATFORM_INTERFACES_H_
#define PLATFORM_INTERFACES_H_

#include "media_specific_blobs.h"  /* struct genericInterfaceType */

/* Return a list of strings (each one representing an "interface name", such
*  as "eth0", "eth1", etc...).
*
*  The length of the list is returned in the 'nr' output argument.
*
*  If something goes wrong, return NULL and set the contents of 'nr' to '0'
*
*  Each element of the list represents an interface on the localhost that will
*  participate in the 1905 network.
*
*  The 'name' field is a platform-specific NULL terminated string that will
*  later be used in other functions to refer to this particular interface.
*
*  The returned list must not be modified by the caller.
*
*  When the returned list is no longer needed, it can be freed by calling
*  "PLATFORM_FREE_LIST_OF_1905_INTERFACES()"
*
*  [PLATFORM PORTING NOTE]
*    Typically you want to return as many entries as physical interfaces there
*    are in the platform. However, if for some reason you want to make one or
*    more interfaces "invisible" to 1905 (maybe because they are "debug"
*    interfaces, such as a "management" ethernet port) you can return a reduced
*    list of interfaces.
*/
char **PLATFORM_GET_LIST_OF_1905_INTERFACES(uint8_t *nr);

/* Used to free the pointer returned by a previous call to
*  "PLATFORM_GET_LIST_OF_1905_INTERFACES()"
*
*  'nr' is the same one returned by "PLATFORM_GET_LIST_OF_1905_INTERFACES()"
*/
void PLATFORM_FREE_LIST_OF_1905_INTERFACES(char **x, uint8_t nr);

/* Return a "struct interfaceInfo" structure containing all kinds of information
*  associated to the provided 'interface_name'
*
*  If something goes wrong, return NULL.
*
*  'interface_name' is one of the names previously returned in a call to
*  "PLATFORM_GET_LIST_OF_1905_INTERFACES()"
*
*  The documentation of the "struct interfaceInfo" structure explain what each
*  field of this structure should contain.
*
*  Once the caller is done with the returned structure, hw must call
*  "PLATFORM_FREE_1905_STRUCTURE()" to dispose it
*/
i1905_interface_info_t *PLATFORM_GET_1905_INTERFACE_INFO(char *interface_name);

/* Free the memory used by a "struct interfaceInfo" structure previously
*  obtained by calling "PLATFORM_GET_1905_INTERFACE_INFO()"
*/
void PLATFORM_FREE_1905_INTERFACE_INFO(i1905_interface_info_t *i);

/*#######################################################################
# Link metrics                                                          #
########################################################################*/

typedef struct linkMetrics {
    uint8_t   local_interface_address[6];  /* A MAC address belonging to one of
                                           *  the local interfaces.
                                           *  Let's call this MAC "A"
                                           */

    uint8_t   neighbor_interface_address[6];  /* A MAC address belonging to a
                                              *  neighbor interface that is
                                              *  directly reachable from "A".
                                              *  Let's call this MAC "B".
                                              */

    uint64_t  measures_window;  /* Time in seconds representing how far back in
                                *  time statistics have been being recorded for
                                *  this interface.
                                *  For example, if this value is set to "5" and
                                *  'tx_packet_ok' is set to "7", it means that
                                *  in the last 5 seconds 7 packets have been
                                *  transmitted OK between "A" and "B".
                                *
                                *  [PLATFORM PORTING NOTE]
                                *    This is typically the amount of time
                                *    ellapsed since the interface was brought
                                *    up.
                                */

    uint32_t  tx_packet_ok;  /* Estimated number of transmitted packets from
                              *  "A" to "B" in the last 'measures_window'
                              *  seconds.
                              */

    uint32_t  tx_packet_errors;  /* Estimated number of packets with errors
                                 *  transmitted from "A" to "B" in the last
                                 * 'measures_window' seconds.
                                 */

    uint16_t  tx_max_xput;  /* Extimated maximum MAC throughput from "A" to
                            *  "B" in Mbits/s.
                            */

    uint16_t  tx_phy_rate;  /* Extimated PHY rate from "A" to "B" in Mbits/s. */

    uint16_t  tx_link_availability;  /* Estimated average percentage of time that the
                                     * link is available to transmit data from "A"
                                     *  to "B" in the last 'measures_window' seconds.
                                     */

    uint32_t  rx_packet_ok;  /* Estimated number of transmitted packets from
                             *  "B" to "A" in the last 'measures_window'
                             *  seconds.
                             */

    uint32_t  rx_packet_errors;  /* Estimated number of packets with errors
                                 *  transmitted from "B" to "A" i nthe last
                                 *  'measures_window' seconds.
                                 */

    uint8_t   rx_rssi;  /* Estimated RSSI when receiving data from "B" to
                        *  "A" in dB.
                        */
} i1905_link_metrics_t;

/* Return a "struct linkMetrics" structure containing all kinds of information
*  associated to the link that exists between the provided local interface and
*  neighbor's interface whose MAC address is 'neighbor_interface_address'.
*
*  If something goes wrong, return NULL.
*
*  'local_interface_name' is one of the names previously returned in a call to
*  "PLATFORM_GET_LIST_OF_1905_INTERFACES()"
*
*  'neighbor_interface_address' is the MAC address at the other end of the link.
*  (This MAC address belong to a neighbor's interface)
*
*  The documentation of the "struct linkMetrics" structure explain what each
*  field of this structure should contain.
*
*  Once the caller is done with the returned structure, hw must call
*  "PLATFORM_FREE_LINK_METRICS()" to dispose it
*
*  [PLATFORM PORTING NOTE]
*    You will notice how each 'struct linkMetrics' is associated to a LINK and
*    not to an interface.
*    In some cases, the platform might not be able to keep PER LINK stats.
*    For example, in Linux is easy to check how many packets were received by
*    "eth0" *in total*, but it is not trivial to find out how many packets were
*    received by "eth0" *from each neighbor*.
*    In these cases there are two solutions:
*      1. Add new platform code to make this PER LINK reporting possible (for
*         example, in Linux you would have to create iptables rules among other
*         things)
*      2. Just report the overwall PER INTERFACE stats (thus ignoring the
*         'neighbor_interface_address' parameter).
*         This is better than reporting nothing at all.
*/
i1905_link_metrics_t *PLATFORM_GET_LINK_METRICS(char *local_interface_name, uint8_t *neighbor_interface_address);

/* Free the memory used by a "struct linkMetrics" structure previously
*  obtained by calling "PLATFORM_GET_LINK_METRICS()"
*/
void PLATFORM_FREE_LINK_METRICS(i1905_link_metrics_t *l);

/* Return a list of "bridge" structures. Each of them represents a set of
*  local interfaces that have been "bridged" together.
*
*  The length of the list is returned in the 'nr' output argument.
*
*  When the returned list is no longer needed, it can be freed by calling
*  "PLATFORM_FREE_LIST_OF_BRIDGES()"
*/
i1905_bridge_t *PLATFORM_GET_LIST_OF_BRIDGES(uint8_t *nr);

/* Used to free the pointer returned by a previous call to
*  "PLATFORM_GET_LIST_OF_BRIDGES()"
*
*  'nr' is the same one returned by "PLATFORM_GET_LIST_OF_BRIDGES()"
*/
void PLATFORM_FREE_LIST_OF_BRIDGES(i1905_bridge_t *x, uint8_t nr);


/*#######################################################################
# RAW packet generation                                                 #
########################################################################*/

/* Send a RAW ethernet frame on interface 'name_interface' with:
*
*    - The "destination MAC address" field set to 'dst_mac'
*    - The "source MAC address" field set to 'src_mac'
*    - The "ethernet type" field set to 'eth_type'
*    - The payload os the ethernet frame set to the first 'payload_len' bytes
*      pointed by 'payload'
*
*  If there is a problem and the packet cannot be sent, this function returns
*  "0", otherwise it returns "1"
*/
uint8_t PLATFORM_SEND_RAW_PACKET(char *interface_name, mac_addr dst_mac, mac_addr src_mac, uint16_t eth_type, uint8_t *payload, uint16_t payload_len);


/*#######################################################################
# Power control                                                         #
########################################################################*/

/* Change the power mode of the provided interface.
*
*  'power_mode' can take any of the "INTERFACE_POWER_STATE_*" values
*
*  The returned value can take any of the following values:
*    INTERFACE_POWER_RESULT_EXPECTED
*      The power mode has been applied as expected (ie. the new "power mode" is
*      the specified in the call)
*    INTERFACE_POWER_RESULT_NO_CHANGE
*      There was no need to apply anything, because the interface *already* was
*      in the requested mode
*    INTERFACE_POWER_RESULT_ALTERNATIVE
*      The interface power mode has changed as a result for this call, however
*      the new state is *not* the given one.  Example: You said
*      "INTERFACE_POWER_STATE_OFF", but the interface, due to maybe platform
*      limitations, ends up in "INTERFACE_POWER_STATE_SAVE"
*    INTERFACE_POWER_RESULT_KO
*      There was some problem trying to apply the given power mode
*/
#define INTERFACE_POWER_RESULT_EXPECTED     (0x00)
#define INTERFACE_POWER_RESULT_NO_CHANGE    (0x01)
#define INTERFACE_POWER_RESULT_ALTERNATIVE  (0x02)
#define INTERFACE_POWER_RESULT_KO           (0x03)
uint8_t PLATFORM_SET_INTERFACE_POWER_MODE(char *interface_name, uint8_t power_mode);

/*#######################################################################
# Security configuration                                                #
########################################################################*/

/* Configure an 80211 AP interface.
*
*  'interface_name' is one of the names previously returned in a call to
*  "PLATFORM_GET_LIST_OF_1905_INTERFACES()".
*  It must be an 802.11 interface with the role of "AP".
*
*  'ssid' is a NULL terminated string containing the "friendly" name of the
*  network that the AP is going to create.
*
*  'bssid' is a 6 bytes long ID containing the MAC address of the "main" AP
*  (typically the registrar) on "extended" networks (where several APs share the
*  same security settings to make it easier for devices to "roam" between them).
*
*  'auth_mode' is the "authentication mode" the AP is going to use. It must take
*  one of the values from "IEEE80211_AUTH_MODE_*"
*
*  'encryption_mode' is "encryption mode" the AP is going to use. It must take
*  one of the values from "IEEE80211_ENCRYPTION_MODE_*"
*
*  'network_key' is a NULL terminated string representing the "network key" the
*  AP is going to use.
*/
uint8_t PLATFORM_CONFIGURE_80211_AP(char *interface_name, uint8_t *ssid, uint8_t *bssid,
                                    uint16_t auth_mode, uint16_t encryption_mode, uint8_t *network_key,
                                    uint8_t map_ext);

/*#######################################################################
# Unit test support                                                     #
########################################################################*/
#ifdef UNIT_TEST
typedef void (*i1905_unit_test_send_cb_t)(char *if_name, uint8_t *payload, uint16_t payload_len);
typedef void (*i1905_unit_test_configure_ap_cb_t)(char *if_name, uint8_t *ssid, uint8_t *bssid,
                                                  uint16_t auth_mode, uint16_t encryption_mode, uint8_t *network_key,
                                                  uint8_t map_ext);

void PLATFORM_REGISTER_UNIT_TEST_SEND_CB(i1905_unit_test_send_cb_t cb);
void PLATFORM_REGISTER_UNIT_TEST_CONFIGURE_AP_CB(i1905_unit_test_configure_ap_cb_t cb);
#endif /* UNIT_TEST */

#endif /* PLATFORM_INTERFACES_H_ */
