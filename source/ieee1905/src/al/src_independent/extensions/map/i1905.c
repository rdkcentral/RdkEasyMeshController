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

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#define LOG_TAG "api"

#include "i1905.h"

#include "al_send.h"
#include "al_recv.h"
#include "al.h"
#include "al_utils.h"
#include "al_wsc.h"
#include "al_datamodel.h"
#include "platform_interfaces.h"
#include "platform.h"
#include "platform_os.h"
#include "al_datamodel.h"

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
int i1905_init(uint8_t *al_mac, i1905_interface_cb_t interface_cb, i1905_cmdu_cb_t cmdu_cb)
{
    return start1905AL(al_mac, 0, NULL, interface_cb, cmdu_cb);
}

void i1905_fini(void)
{
    return stop1905AL();
}

char **i1905_get_list_of_interfaces(uint8_t *nr)
{
    return PLATFORM_GET_LIST_OF_1905_INTERFACES(nr);
}

void i1905_free_list_of_interfaces(char **interfaces, uint8_t nr)
{
    PLATFORM_FREE_LIST_OF_1905_INTERFACES(interfaces, nr);
}

i1905_interface_info_t *i1905_get_interface_info(char *ifname)
{
    return PLATFORM_GET_1905_INTERFACE_INFO(ifname);
}

void i1905_free_interface_info(i1905_interface_info_t *info)
{
    PLATFORM_FREE_1905_INTERFACE_INFO(info);
}

i1905_bridge_t *i1905_get_list_of_bridges(uint8_t *nr)
{
    return PLATFORM_GET_LIST_OF_BRIDGES(nr);
}

void i1905_free_list_of_bridges(i1905_bridge_t *br, uint8_t nr)
{
    PLATFORM_FREE_LIST_OF_BRIDGES(br, nr);
}

void i1905_dump_interfaces(map_printf_cb_t print_cb)
{
    PLATFORM_OS_DUMP_INTERFACES(print_cb);
}

void i1905_get_mcast_mac(mac_addr mac)
{
    maccpy(mac, g_mcast_mac_1905);
}

int i1905_get(char *ifname, i1905_param_t param, void *data, UNUSED size_t *data_len)
{
    if (obtainTLVFrom1905(ifname, param, data)) {
        log_i1905_e("tlv get from 1905 failed");
        return -1;
    }
    return 0;
}

int i1905_set(UNUSED char *ifname, i1905_param_t param, void *data, UNUSED size_t data_len)
{
    int ret = 0;
    switch(param) {
        case I1905_SET_WSCM2_TLV: {
            i1905_wsc_data_t *wsc_data     = data;
            uint8_t          *wsc_m2_frame = wsc_data->m2.wsc_frame;
            uint16_t          wsc_m2_size  = wsc_data->m2.wsc_frame_size;
            uint8_t          *wsc_m1_frame = wsc_data->m1.wsc_frame;
            uint16_t          wsc_m1_size  = wsc_data->m1.wsc_frame_size;
            uint8_t           wsc_type     = wscGetType(wsc_m2_frame, wsc_m2_size);

            if (WSC_TYPE_M2 == wsc_type) {
                /* Process it and apply the configuration to the corresponding interface */
                if (wscProcessM2(wsc_data->wsc_key, wsc_m1_frame, wsc_m1_size,
                    wsc_m2_frame, wsc_m2_size) == 0) {
                    ret = -1;
                    break;
                }
            }
            break;
        }
        default:
        break;
    }

    return ret;
}

int i1905_send(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid)
{
    log_i1905_t("send packet on %s", cmdu->interface_name);

    if (mid && *mid) {
       cmdu->message_id = *mid;
    } else {
       cmdu->message_id = getNextMid();
       if (mid != NULL) {
           *mid = cmdu->message_id;
       }
    }

    if (strcmp(cmdu->interface_name, "all") == 0) {
        uint8_t   ifcount = 0, i;
        char    **if_list = PLATFORM_GET_LIST_OF_1905_INTERFACES(&ifcount);

        if (!if_list) {
            log_i1905_e("Could not get list of 1905 interfaces");
            return -1;
        }

        for (i = 0; i < ifcount; i++) {
            if (!PLATFORM_OS_IS_INTERFACE_UP(if_list[i])) {
                continue;
            }
            if (0 == send1905RawPacket(if_list[i], cmdu->message_id, dmac, cmdu)) {
                log_i1905_e("send1905RawPacket() on interface %s failed", if_list[i]);
            }
        }
        PLATFORM_FREE_LIST_OF_1905_INTERFACES(if_list, ifcount);
    } else if (PLATFORM_OS_IS_INTERFACE_UP(cmdu->interface_name)) {
        if (0 == send1905RawPacket(cmdu->interface_name, cmdu->message_id, dmac, cmdu)) {
            log_i1905_e("send1905RawPacket() on interface %s failed", cmdu->interface_name);
            return -1;
        }
    }

    return 0;
}

int i1905_send_raw(char *ifname, mac_addr dmac, mac_addr smac, uint16_t eth_type, uint8_t *data, uint16_t data_len)
{
    log_i1905_t("interface Name in Send (raw): '%s'", ifname);

    if (strcmp(ifname, "all") == 0) {
        uint8_t   ifcount = 0, i;
        char    **if_list = PLATFORM_GET_LIST_OF_1905_INTERFACES(&ifcount);

        if (!if_list) {
            log_i1905_e("Could not get list of 1905 interfaces");
            return -1;
        }

        for (i = 0; i < ifcount; i++) {
            if (!PLATFORM_OS_IS_INTERFACE_UP(if_list[i])) {
                continue;
            }
            if (0 == PLATFORM_SEND_RAW_PACKET(if_list[i], dmac, smac, eth_type, data, data_len)) {
                log_i1905_e("failed to send raw message to interface '%s'", if_list[i]);
            }
        }
        PLATFORM_FREE_LIST_OF_1905_INTERFACES(if_list, ifcount);
    } else if (PLATFORM_OS_IS_INTERFACE_UP(ifname)) {
        if (0 == PLATFORM_SEND_RAW_PACKET(ifname, dmac, smac, eth_type, data, data_len)) {
            log_i1905_e("failed to send raw message to interface '%s'", ifname);
            return -1;
        }
    }

    log_i1905_t("managed to send raw message via '%s'", ifname);

    return 0;
}

int i1905_send_lldp(char *ifname, mac_addr smac, i1905_lldp_payload_t *payload)
{
    if (PLATFORM_OS_IS_INTERFACE_UP(ifname)) {
        sendLLDPBridgeDiscoveryPacket(ifname, smac, payload);
    }

    return 0;
}

void i1905_cmdu_free(i1905_cmdu_t *cmdu)
{
    free_1905_CMDU_structure(cmdu);
}

const char *i1905_cmdu_type_to_string(uint16_t cmdu_type)
{
    return convert_1905_CMDU_type_to_string(cmdu_type);
}

const char *i1905_tlv_type_to_string(uint8_t tlv_type)
{
    return convert_1905_TLV_type_to_string(tlv_type);
}

void i1905_get_gateway_mac_address(mac_addr mac)
{
    maccpy(mac, PLATFORM_OS_GET_GATEWAY_MAC());
}
