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
#include "utils.h"

#include "al_send.h"
#include "al_datamodel.h"
#include "al_utils.h"
#include "al_wsc.h"

#include "1905_tlvs.h"
#include "1905_cmdus.h"
#include "1905_l2.h"
#include "lldp_tlvs.h"
#include "lldp_payload.h"
#include "1905_platform.h"

#include "platform_os.h"
#include "platform_interfaces.h"

/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
static void _obtainLocalDeviceInfoTLV(i1905_device_information_tlv_t *device_info)
{
    uint8_t   al_mac_address[6];

    char    **interfaces_names;
    uint8_t   interfaces_names_nr;
    uint8_t   i;

    memcpy(al_mac_address, DMalMacGet(), 6);

    device_info->tlv_type            = TLV_TYPE_DEVICE_INFORMATION;
    device_info->al_mac_address[0]   = al_mac_address[0];
    device_info->al_mac_address[1]   = al_mac_address[1];
    device_info->al_mac_address[2]   = al_mac_address[2];
    device_info->al_mac_address[3]   = al_mac_address[3];
    device_info->al_mac_address[4]   = al_mac_address[4];
    device_info->al_mac_address[5]   = al_mac_address[5];
    device_info->local_interfaces_nr = 0;
    device_info->local_interfaces    = NULL;

    interfaces_names = PLATFORM_GET_LIST_OF_1905_INTERFACES(&interfaces_names_nr);

    /* Add all interfaces that are *not* in "POWER OFF" mode */
    for (i=0; i<interfaces_names_nr; i++) {
        struct interfaceInfo *x;

        if (NULL == (x = PLATFORM_GET_1905_INTERFACE_INFO(interfaces_names[i]))) {
            /* Error retrieving information for this interface. Ignor it. */
            continue;
        }

        if (INTERFACE_POWER_STATE_OFF == x->power_state) {
            /* Ignore interfaces that are in "POWER OFF" mode (they will
            * be included in the "power off" TLV, later, on this same CMDU)
            */
            PLATFORM_FREE_1905_INTERFACE_INFO(x);
            continue;
        }

        if (0 == device_info->local_interfaces_nr) {
            device_info->local_interfaces = malloc(sizeof(struct _localInterfaceEntries));
        } else {
            device_info->local_interfaces = realloc(device_info->local_interfaces, sizeof(struct _localInterfaceEntries) *(device_info->local_interfaces_nr + 1));
        }

        device_info->local_interfaces[device_info->local_interfaces_nr].mac_address[0] = x->mac_address[0];
        device_info->local_interfaces[device_info->local_interfaces_nr].mac_address[1] = x->mac_address[1];
        device_info->local_interfaces[device_info->local_interfaces_nr].mac_address[2] = x->mac_address[2];
        device_info->local_interfaces[device_info->local_interfaces_nr].mac_address[3] = x->mac_address[3];
        device_info->local_interfaces[device_info->local_interfaces_nr].mac_address[4] = x->mac_address[4];
        device_info->local_interfaces[device_info->local_interfaces_nr].mac_address[5] = x->mac_address[5];
        device_info->local_interfaces[device_info->local_interfaces_nr].media_type     = x->interface_type;
        switch (x->interface_type) {
            case INTERFACE_TYPE_IEEE_802_11B_2_4_GHZ:
            case INTERFACE_TYPE_IEEE_802_11G_2_4_GHZ:
            case INTERFACE_TYPE_IEEE_802_11A_5_GHZ:
            case INTERFACE_TYPE_IEEE_802_11N_2_4_GHZ:
            case INTERFACE_TYPE_IEEE_802_11N_5_GHZ:
            case INTERFACE_TYPE_IEEE_802_11AC_5_GHZ:
            case INTERFACE_TYPE_IEEE_802_11AD_60_GHZ:
            case INTERFACE_TYPE_IEEE_802_11AF:
            case INTERFACE_TYPE_IEEE_802_11AX: {
                device_info->local_interfaces[device_info->local_interfaces_nr].media_specific_data_size                                          = 10;
                device_info->local_interfaces[device_info->local_interfaces_nr].media_specific_data.ieee80211.network_membership[0]               = x->interface_type_data.ieee80211.bssid[0];
                device_info->local_interfaces[device_info->local_interfaces_nr].media_specific_data.ieee80211.network_membership[1]               = x->interface_type_data.ieee80211.bssid[1];
                device_info->local_interfaces[device_info->local_interfaces_nr].media_specific_data.ieee80211.network_membership[2]               = x->interface_type_data.ieee80211.bssid[2];
                device_info->local_interfaces[device_info->local_interfaces_nr].media_specific_data.ieee80211.network_membership[3]               = x->interface_type_data.ieee80211.bssid[3];
                device_info->local_interfaces[device_info->local_interfaces_nr].media_specific_data.ieee80211.network_membership[4]               = x->interface_type_data.ieee80211.bssid[4];
                device_info->local_interfaces[device_info->local_interfaces_nr].media_specific_data.ieee80211.network_membership[5]               = x->interface_type_data.ieee80211.bssid[5];
                device_info->local_interfaces[device_info->local_interfaces_nr].media_specific_data.ieee80211.role                                = x->interface_type_data.ieee80211.role;
                device_info->local_interfaces[device_info->local_interfaces_nr].media_specific_data.ieee80211.ap_channel_band                     = x->interface_type_data.ieee80211.ap_channel_band;
                device_info->local_interfaces[device_info->local_interfaces_nr].media_specific_data.ieee80211.ap_channel_center_frequency_index_1 = x->interface_type_data.ieee80211.ap_channel_center_frequency_index_1;
                device_info->local_interfaces[device_info->local_interfaces_nr].media_specific_data.ieee80211.ap_channel_center_frequency_index_2 = x->interface_type_data.ieee80211.ap_channel_center_frequency_index_2;
                break;
            }
            case INTERFACE_TYPE_IEEE_1901_FFT: {
                device_info->local_interfaces[device_info->local_interfaces_nr].media_specific_data_size                           = 7;
                device_info->local_interfaces[device_info->local_interfaces_nr].media_specific_data.ieee1901.network_identifier[0] = x->interface_type_data.ieee1901.network_identifier[0];
                device_info->local_interfaces[device_info->local_interfaces_nr].media_specific_data.ieee1901.network_identifier[1] = x->interface_type_data.ieee1901.network_identifier[1];
                device_info->local_interfaces[device_info->local_interfaces_nr].media_specific_data.ieee1901.network_identifier[2] = x->interface_type_data.ieee1901.network_identifier[2];
                device_info->local_interfaces[device_info->local_interfaces_nr].media_specific_data.ieee1901.network_identifier[3] = x->interface_type_data.ieee1901.network_identifier[3];
                device_info->local_interfaces[device_info->local_interfaces_nr].media_specific_data.ieee1901.network_identifier[4] = x->interface_type_data.ieee1901.network_identifier[4];
                device_info->local_interfaces[device_info->local_interfaces_nr].media_specific_data.ieee1901.network_identifier[5] = x->interface_type_data.ieee1901.network_identifier[5];
                device_info->local_interfaces[device_info->local_interfaces_nr].media_specific_data.ieee1901.network_identifier[6] = x->interface_type_data.ieee1901.network_identifier[6];
                break;
            }
            default: {
                device_info->local_interfaces[device_info->local_interfaces_nr].media_specific_data_size  = 0;
                device_info->local_interfaces[device_info->local_interfaces_nr].media_specific_data.dummy = 0;
                break;
            }
        }
        device_info->local_interfaces_nr++;

        PLATFORM_FREE_1905_INTERFACE_INFO(x);
    }

    PLATFORM_FREE_LIST_OF_1905_INTERFACES(interfaces_names, interfaces_names_nr);
}

/* Given a pointer to a preallocated "alMacAddressTypeTLV" structure, fill it
*  with all the pertaining information retrieved from the local device.
*/
static void _obtainLocalAlMacAddressTLV(i1905_al_mac_address_tlv_t *al_mac_addr)
{
    uint8_t al_mac_address[6];

    memcpy(al_mac_address, DMalMacGet(), 6);

    al_mac_addr->tlv_type          = TLV_TYPE_AL_MAC_ADDRESS;
    al_mac_addr->al_mac_address[0] = al_mac_address[0];
    al_mac_addr->al_mac_address[1] = al_mac_address[1];
    al_mac_addr->al_mac_address[2] = al_mac_address[2];
    al_mac_addr->al_mac_address[3] = al_mac_address[3];
    al_mac_addr->al_mac_address[4] = al_mac_address[4];
    al_mac_addr->al_mac_address[5] = al_mac_address[5];
}

/* Given a pointer to a preallocated "searchedRoleTLV" structure, fill it
*  with all the pertaining information retrieved from the local device.
*/
static void _obtainSearchedRoleTLV(i1905_searched_role_tlv_t *searched_role_tlv)
{
    searched_role_tlv->tlv_type = TLV_TYPE_SEARCHED_ROLE;
    searched_role_tlv->role     = IEEE80211_ROLE_AP;
}

/* Given a pointer to a preallocated "supportedRoleTLV" structure, fill it
*  with all the pertaining information retrieved from the local device.
*/
static void _obtainSupportedRoleTLV(i1905_supported_role_tlv_t *supported_role_tlv)
{
    supported_role_tlv->tlv_type = TLV_TYPE_SUPPORTED_ROLE;
    supported_role_tlv->role     = IEEE80211_ROLE_AP;
}

static void _obtainSupportedFrequencyBandTLV(i1905_supported_freq_band_tlv_t *supported_freq_band_tlv, uint8_t freq_band)
{
    supported_freq_band_tlv->tlv_type  = TLV_TYPE_SUPPORTED_FREQ_BAND;
    supported_freq_band_tlv->freq_band = freq_band;
}

/* Given a pointer to a preallocated "autoconfigFreqBandTLV" structure, fill it
*  with all the pertaining information retrieved from the local device.
*/
static void _obtainAutoconfigFreqBandTLV(i1905_autoconfig_freq_band_tlv_t *ac_freq_band_tlv, uint8_t freq_band, char *interface)
{
    ac_freq_band_tlv->tlv_type = TLV_TYPE_AUTOCONFIG_FREQ_BAND;

    if (freq_band == 0) {
        uint8_t   i;
        char    **ifs_names;
        uint8_t   ifs_nr;
        uint8_t   unconfigured_ap_exists = 0;
        uint8_t   unconfigured_ap_band   = 0;

        ifs_names = PLATFORM_GET_LIST_OF_1905_INTERFACES(&ifs_nr);

        for (i=0; i<ifs_nr; i++) {
            if (0 == memcmp(ifs_names[i], interface, strlen(interface))) {
                struct interfaceInfo *x;

                x = PLATFORM_GET_1905_INTERFACE_INFO(ifs_names[i]);

                if (NULL == x) {
                    log_i1905_e("Could not retrieve info of interface %s", ifs_names[i]);
                    continue;
                }

                if ((INTERFACE_TYPE_IEEE_802_11B_2_4_GHZ == x->interface_type ||
                    INTERFACE_TYPE_IEEE_802_11G_2_4_GHZ == x->interface_type ||
                    INTERFACE_TYPE_IEEE_802_11A_5_GHZ   == x->interface_type ||
                    INTERFACE_TYPE_IEEE_802_11N_2_4_GHZ == x->interface_type ||
                    INTERFACE_TYPE_IEEE_802_11N_5_GHZ   == x->interface_type ||
                    INTERFACE_TYPE_IEEE_802_11AC_5_GHZ  == x->interface_type ||
                    INTERFACE_TYPE_IEEE_802_11AX        == x->interface_type ||
                    INTERFACE_TYPE_IEEE_802_11AD_60_GHZ == x->interface_type) &&
                    IEEE80211_ROLE_AP == x->interface_type_data.ieee80211.role)
                {
                    unconfigured_ap_exists = 1;

                    if (INTERFACE_TYPE_IEEE_802_11B_2_4_GHZ == x->interface_type ||
                        INTERFACE_TYPE_IEEE_802_11G_2_4_GHZ == x->interface_type ||
                        INTERFACE_TYPE_IEEE_802_11N_2_4_GHZ == x->interface_type)
                    {
                        unconfigured_ap_band = IEEE80211_FREQUENCY_BAND_2_4_GHZ;
                    } else if (INTERFACE_TYPE_IEEE_802_11A_5_GHZ  == x->interface_type ||
                               INTERFACE_TYPE_IEEE_802_11N_5_GHZ  == x->interface_type ||
                               INTERFACE_TYPE_IEEE_802_11AC_5_GHZ == x->interface_type)
                    {
                        unconfigured_ap_band = IEEE80211_FREQUENCY_BAND_5_GHZ;
                    }
#ifdef MULTIAP
                    /* MAP R2 defined media type 11AX (wifi6) is not band specific.
                       Frequency band is irrelevant for MAP anyhow.
                    */
                    else if (INTERFACE_TYPE_IEEE_802_11AX == x->interface_type) {
                        unconfigured_ap_band = IEEE80211_FREQUENCY_BAND_5_GHZ;
                    }
#endif
                    else if (INTERFACE_TYPE_IEEE_802_11AD_60_GHZ == x->interface_type) {
                        unconfigured_ap_band = IEEE80211_FREQUENCY_BAND_60_GHZ;
                    } else {
                        log_i1905_w("Unknown interface type %d", x->interface_type);
                        unconfigured_ap_exists = 0;

                        PLATFORM_FREE_1905_INTERFACE_INFO(x);
                        continue;
                    }

                    PLATFORM_FREE_1905_INTERFACE_INFO(x);
                    break;
                }
                PLATFORM_FREE_1905_INTERFACE_INFO(x);
            }
        }
        PLATFORM_FREE_LIST_OF_1905_INTERFACES(ifs_names, ifs_nr);

        if (1 == unconfigured_ap_exists) {
            ac_freq_band_tlv->freq_band = unconfigured_ap_band;
        }
    } else {
        ac_freq_band_tlv->freq_band = freq_band;
    }
}

/*#######################################################################
#                       GLOBAL FUNCTIONS                                #
########################################################################*/
uint8_t forward1905RawPacket(char *interface_name, uint16_t mid, uint8_t *dest_mac, i1905_cmdu_t *cmdu, int get_src_mac_frm_stream)
{
    uint8_t  **streams;
    uint16_t  *streams_lens;
    uint8_t   *src_mac;
    uint8_t    total_streams, x;

    log_i1905_d("Contents of CMDU to send:0x%x",cmdu->message_type);

    streams = forge_1905_CMDU_from_structure(cmdu, &streams_lens);
    if (NULL == streams) {
        /* Could not forge the packet. Error? */
        log_i1905_e("forge_1905_CMDU_from_structure() failed!");
        return 0;
    }

    total_streams = 0;
    while(streams[total_streams]) {
        total_streams++;
    }

    if (0 == total_streams)  {
        /* Could not forge the packet. Error? */
        log_i1905_w("forge_1905_CMDU_from_structure() returned 0 streams!");

        free_1905_CMDU_packets(streams);
        free(streams_lens);
        return 0;
    }

    x = 0;
    while(streams[x]) {
        log_i1905_d("Sending 1905 message on interface %s, MID %d, fragment %d/%d", interface_name, mid, x+1, total_streams);
	if (get_src_mac_frm_stream) {
            src_mac = cmdu->cmdu_stream.src_mac_addr;
        } else {
            src_mac = DMalMacGet();
        }

        if (0 == PLATFORM_SEND_RAW_PACKET(interface_name,
                                          dest_mac,
                                          src_mac,
                                          ETHERTYPE_1905,
                                          streams[x],
                                          streams_lens[x]))
        {
            log_i1905_e("Packet could not be sent!");
        }

        x++;
    }

    free_1905_CMDU_packets(streams);
    free(streams_lens);

    return 1;
}

uint8_t send1905RawPacket(char *interface_name, uint16_t mid, uint8_t *dest_mac, i1905_cmdu_t *cmdu)
{
    return forward1905RawPacket(interface_name, mid, dest_mac, cmdu, GET_NATIVE_AL_SRC_MAC);
}

uint8_t sendLLDPBridgeDiscoveryPacket(char *interface_name, uint8_t* src_mac, i1905_lldp_payload_t *payload)
{
    uint8_t  *stream;
    uint16_t  stream_len;
    uint8_t   mcast_address[] = MCAST_LLDP;

    stream = forge_lldp_PAYLOAD_from_structure(payload, &stream_len);

    if (!stream) {
        log_i1905_e("%s: Packet could not be sent!", __func__);
        return 0;
    }

    log_i1905_d("Sending LLDP bridge discovery message on interface %s", interface_name);
    if (0 == PLATFORM_SEND_RAW_PACKET(interface_name, mcast_address, src_mac,
                                      ETHERTYPE_LLDP, stream, stream_len)) {
        log_i1905_e("%s: Packet could not be sent!", __func__);
    }
    free_lldp_PAYLOAD_packet(stream);

    return 1;
}

int obtainTLVFrom1905(char *ifname, i1905_param_t param, void *data)
{
    if (NULL == data) {
       return -1;
    }

    switch(param) {
        case I1905_GET_ALMAC_TLV: {
            _obtainLocalAlMacAddressTLV(data);
            break;
        }
        case I1905_GET_SEARCHEDROLE_TLV: {
            _obtainSearchedRoleTLV(data);
            break;
        }
        case I1905_GET_FREQUENCYBAND_TLV: {
            _obtainAutoconfigFreqBandTLV(data, 0, ifname);
            break;
        }
        case I1905_GET_SUPPORTEDROLE_TLV: {
            _obtainSupportedRoleTLV(data);
            break;
        }
        case I1905_GET_SUPPORTEDFREQBAND_TLV: {
            i1905_supported_freq_band_data_t *supp_freq_band = data;
            _obtainSupportedFrequencyBandTLV(supp_freq_band->supported_freq_band_tlv, supp_freq_band->freq_band);
            break;
        }
        case I1905_GET_DEVICEINFO_TLV: {
            _obtainLocalDeviceInfoTLV(data);
            break;
        }
        case I1905_GET_WSCM1_TLV: {
            i1905_wsc_data_t *wsc_data = data;
            uint8_t          *m1;
            uint16_t          m1_size;

            if (NULL == ifname) {
                return -1;
            }

            if (wscBuildM1(ifname, &m1, &m1_size, (void**)&wsc_data->wsc_key) == 0) {
                return -1;
            }

            /* Fill the WSC TLV */
            wsc_data->m1.tlv_type       = TLV_TYPE_WSC;
            wsc_data->m1.wsc_frame      = m1;
            wsc_data->m1.wsc_frame_size = m1_size;
            break;
        }
        case I1905_GET_WSCM2_TLV: {
            i1905_wsc_data_t *wsc_data = data;
            uint8_t          *m2;
            uint16_t          m2_size;

            if (!wsc_data || !wsc_data->m1.wsc_frame || !wsc_data->m2_config) {
                return -1;
            }

            if (wscBuildM2(wsc_data->m1.wsc_frame, wsc_data->m1.wsc_frame_size, &m2, &m2_size, wsc_data->m2_config, ifname) == 0) {
                return -1;
            }

            /* Fill the WSC TLV */
            wsc_data->m2.tlv_type       = TLV_TYPE_WSC;
            wsc_data->m2.wsc_frame      = m2;
            wsc_data->m2.wsc_frame_size = m2_size;
            break;
        }
        default: {
            return -1;
        }
    }
    return 0;
}
