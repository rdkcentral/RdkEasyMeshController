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

#ifndef AL_SEND_H_
#define AL_SEND_H_

#include "1905_cmdus.h"
#include "1905_tlvs.h"
#include "i1905.h"

/*#######################################################################
# Function to forward "raw" 1905 messages                               #
########################################################################*/

/* This function sends a "1905 packet" (the one represented by the provided
*  'cmdu' structure) on the provided interface.
*
*  This function is called directly by multicast forwarding function
*  _check_forwarding with a flag to specify the source mac should not be changed.
*
*  'interface_name' is one of the values returned by
*  "PLATFORM_GET_LIST_OF_1905_INTERFACES()" and must refer to the interface we
*  want to use to send the packet.
*
*  'mid' is the "Message identifier" value we want this packet to contain. Its
*  value must be calculated according to what is said on "Section 7.8"
*
*  'dst_mac_address' is the destination MAC address that will be contained in
*  the ETH header.
*
*  get_src_mac_frm_stream decides whether the packet to be sent should have Current
*  Al_mac_addr as src mac address or if it is a relayed multicast packet, then
*  the MAC address from the received stream will be extracted and used. Which is
*  just forwarding the relayed multicast packet.
*
*  Return '0' if there was a problem, '1' otherwise.
*/
uint8_t forward1905RawPacket(char *interface_name, uint16_t mid, uint8_t *dest_mac, i1905_cmdu_t *cmdu, int get_src_mac_frm_stream);


/*#######################################################################
# Function to send "raw" 1905 messages                                  #
########################################################################*/

/* This function sends a "1905 packet" (the one represented by the provided
*  'cmdu' structure) on the provided interface.
*
*  This function send all 1905 raw packet to forward1905RawPacket as it is
*  with a flag to specify that the SRC MAC address has to be generated from
*  local AL MAC address
*
*  'interface_name' is one of the values returned by
*  "PLATFORM_GET_LIST_OF_1905_INTERFACES()" and must refer to the interface we
*  want to use to send the packet.
*
*  'mid' is the "Message identifier" value we want this packet to contain. Its
*  value must be calculated according to what is said on "Section 7.8"
*
*  'dst_mac_address' is the destination MAC address that will be contained in
*  the ETH header.
*
*  Return '0' if there was a problem, '1' otherwise.
*/
uint8_t send1905RawPacket(char *interface_name, uint16_t mid, uint8_t *dest_mac, i1905_cmdu_t *cmdu);


/*#######################################################################
# Functions to send LLDP messages                                       #
########################################################################*/

/* This function sends a "LLDP bridge discovery packet" on the provided
*  interface.
*
*  'interface_name' is one of the values returned by
*  "PLATFORM_GET_LIST_OF_1905_INTERFACES()" and must refer to the interface we
*  want to use to send the packet.
*
*
*  The format of this packet is detailed in "Section 6.1"
*
*  Return "0" if a problem was found. "1" otherwise.
*/
uint8_t sendLLDPBridgeDiscoveryPacket(char *interface_name, uint8_t* src_mac, i1905_lldp_payload_t *payload);


/*#######################################################################
# Functions to get specific TLV                                         #
########################################################################*/
/* Given a pointer to a preallocated TLV structure, fill it
*  with all the pertaining information retrieved from the local device.
*/
int obtainTLVFrom1905(char *ifname, i1905_param_t param, void *data);

#endif /* AL_SEND_H */
