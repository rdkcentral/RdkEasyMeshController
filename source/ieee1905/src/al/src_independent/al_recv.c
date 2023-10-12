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

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include "platform.h"

#include "al_recv.h"
#include "al_datamodel.h"
#include "al_utils.h"
#include "al_send.h"
#include "al_wsc.h"

#include "1905_tlvs.h"
#include "1905_cmdus.h"
#include "1905_l2.h"
#include "lldp_tlvs.h"
#include "lldp_payload.h"

#include "platform_interfaces.h"

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
uint8_t processLlpdPayload(i1905_lldp_payload_t *payload, uint8_t *receiving_interface_addr)
{
    uint8_t  *p;
    uint16_t  i = 0;

    uint8_t  dummy_mac_address[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    uint8_t  al_mac_address[6];
    uint8_t  mac_address[6];

    memcpy(al_mac_address, dummy_mac_address, 6);
    memcpy(mac_address,    dummy_mac_address, 6);

    if (NULL == payload) {
        return 0;
    }

    log_i1905_t("<-- LLDP BRIDGE DISCOVERY (%s)", DMmacToInterfaceName(receiving_interface_addr));

    /* We need to update the data model structure, which keeps track
    *  of local interfaces, neighbors, and neighbors' interfaces, and
    *  what type of discovery messages ("topology discovery" and/or
    *  "bridge discovery") have been received on each link.
    *
    *  First, extract the AL MAC and MAC addresses of the interface
    *  which transmitted this bridge discovery message
    */

    while (NULL != (p = payload->list_of_TLVs[i])) {
        switch (*p) {
            case TLV_TYPE_CHASSIS_ID: {
                struct chassisIdTLV *t = (struct chassisIdTLV *)p;

                if (CHASSIS_ID_TLV_SUBTYPE_MAC_ADDRESS == t->chassis_id_subtype) {
                    memcpy(al_mac_address, t->chassis_id, 6);
                }
                break;
            }
            case TLV_TYPE_MAC_ADDRESS: {
                struct portIdTLV *t = (struct portIdTLV *)p;

                if (PORT_ID_TLV_SUBTYPE_MAC_ADDRESS == t->port_id_subtype) {
                    memcpy(mac_address, t->port_id, 6);
                }
                break;
            }
            case TLV_TYPE_TIME_TO_LIVE:
            break;
            default:
                log_i1905_d("Ignoring TLV type %d", *p);
            break;
        }
        i++;
    }

    /* Make sure that both the AL MAC and MAC addresses were contained in the payload */
    if (0 == memcmp(al_mac_address, dummy_mac_address, 6) ||
        0 == memcmp(mac_address,    dummy_mac_address, 6))
    {
        log_i1905_t("More TLVs were expected inside this LLDP message");
        return 0;
    }

    log_i1905_t("AL MAC address = %02x:%02x:%02x:%02x:%02x:%02x", al_mac_address[0], al_mac_address[1], al_mac_address[2], al_mac_address[3], al_mac_address[4], al_mac_address[5]);
    log_i1905_t("MAC    address = %02x:%02x:%02x:%02x:%02x:%02x", mac_address[0],    mac_address[1],    mac_address[2],    mac_address[3],    mac_address[4],    mac_address[5]);

    // Finally, update the data model
    //
    if (0 == DMupdateDiscoveryTimeStamps(receiving_interface_addr, al_mac_address, mac_address, TIMESTAMP_BRIDGE_DISCOVERY, NULL)) {
        log_i1905_w("Problems updating data model with topology response TLVs");
        return 0;
    }

    return 1;
}
