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
#include "platform_crypto.h"
#include "platform_interfaces.h"

/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
static int _obtainLocalDeviceInfoTLV(i1905_device_information_tlv_t *device_info)
{
    char    **interface_names;
    uint8_t   interface_names_nr;
    uint8_t   i;

    device_info->tlv_type            = TLV_TYPE_DEVICE_INFORMATION;
    maccpy(device_info->al_mac_address, DMalMacGet());
    device_info->local_interfaces_nr = 0;
    device_info->local_interfaces    = NULL;

    interface_names = PLATFORM_GET_LIST_OF_1905_INTERFACES(&interface_names_nr);
    if (!interface_names) {
        log_i1905_e("Could not get list of 1905 interfaces");
        return -1;
    }

    if (interface_names_nr == 0) {
        PLATFORM_FREE_LIST_OF_1905_INTERFACES(interface_names, interface_names_nr);
        return 0;
    }

    /* Allocate enough memory for all interfaces... */
    device_info->local_interfaces = calloc(interface_names_nr, sizeof(i1905_local_interface_entry_t));
    if (!device_info->local_interfaces) {
        PLATFORM_FREE_LIST_OF_1905_INTERFACES(interface_names, interface_names_nr);
        return -1;
    }

    /* Add all interfaces that are *not* in "POWER OFF" mode */
    for (i=0; i<interface_names_nr; i++) {
        i1905_local_interface_entry_t *interface = &device_info->local_interfaces[device_info->local_interfaces_nr];
        i1905_interface_info_t *x;

        if (NULL == (x = PLATFORM_GET_1905_INTERFACE_INFO(interface_names[i]))) {
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

        maccpy(interface->mac_address, x->mac_address);
        interface->media_type = x->interface_type;
        switch (x->interface_type) {
            case INTERFACE_TYPE_IEEE_802_11B_2_4_GHZ:
            case INTERFACE_TYPE_IEEE_802_11G_2_4_GHZ:
            case INTERFACE_TYPE_IEEE_802_11A_5_GHZ:
            case INTERFACE_TYPE_IEEE_802_11N_2_4_GHZ:
            case INTERFACE_TYPE_IEEE_802_11N_5_GHZ:
            case INTERFACE_TYPE_IEEE_802_11AC_5_GHZ:
            case INTERFACE_TYPE_IEEE_802_11AD_60_GHZ:
            case INTERFACE_TYPE_IEEE_802_11AF: {
                interface->media_specific_data_size                                          = 10;
                maccpy(interface->media_specific_data.ieee80211.network_membership, x->interface_type_data.ieee80211.bssid);
                interface->media_specific_data.ieee80211.role                                = x->interface_type_data.ieee80211.role;
                interface->media_specific_data.ieee80211.ap_channel_band                     = x->interface_type_data.ieee80211.ap_channel_band;
                interface->media_specific_data.ieee80211.ap_channel_center_frequency_index_1 = x->interface_type_data.ieee80211.ap_channel_center_frequency_index_1;
                interface->media_specific_data.ieee80211.ap_channel_center_frequency_index_2 = x->interface_type_data.ieee80211.ap_channel_center_frequency_index_2;
                break;
            }
            case INTERFACE_TYPE_IEEE_1901_FFT: {
                interface->media_specific_data_size = 7;
                memcpy(interface->media_specific_data.ieee1901.network_identifier, x->interface_type_data.ieee1901.network_identifier, 7);
                break;
            }
            case INTERFACE_TYPE_IEEE_802_11AX: /* Do not add media specific info for 11AX */
            case INTERFACE_TYPE_IEEE_802_11BE: /* Do not add media specific info for 11BE */
            default: {
                interface->media_specific_data_size  = 0;
                interface->media_specific_data.dummy = 0;
                break;
            }
        }
        device_info->local_interfaces_nr++;

        PLATFORM_FREE_1905_INTERFACE_INFO(x);
    }

    PLATFORM_FREE_LIST_OF_1905_INTERFACES(interface_names, interface_names_nr);

    return 0;
}

/* Given a pointer to a preallocated "alMacAddressTypeTLV" structure, fill it
*  with all the pertaining information retrieved from the local device.
*/
static void _obtainLocalAlMacAddressTLV(i1905_al_mac_address_tlv_t *al_mac_addr)
{
    al_mac_addr->tlv_type = TLV_TYPE_AL_MAC_ADDRESS;
    maccpy(al_mac_addr->al_mac_address, DMalMacGet());
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
static int _obtainAutoconfigFreqBandTLV(i1905_autoconfig_freq_band_tlv_t *ac_freq_band_tlv, uint8_t freq_band, char *interface)
{
    ac_freq_band_tlv->tlv_type = TLV_TYPE_AUTOCONFIG_FREQ_BAND;

    if (freq_band == 0) {
        uint8_t   i;
        char    **ifs_names;
        uint8_t   ifs_nr;
        uint8_t   unconfigured_ap_exists = 0;
        uint8_t   unconfigured_ap_band   = 0;

        ifs_names = PLATFORM_GET_LIST_OF_1905_INTERFACES(&ifs_nr);
        if (!ifs_names) {
            log_i1905_e("Could not get list of 1905 interfaces");
            return -1;
        }

        for (i=0; i<ifs_nr; i++) {
            if (0 == memcmp(ifs_names[i], interface, strlen(interface))) {
                i1905_interface_info_t *x;

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
                    INTERFACE_TYPE_IEEE_802_11BE        == x->interface_type ||
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
                    else if (INTERFACE_TYPE_IEEE_802_11AX == x->interface_type || INTERFACE_TYPE_IEEE_802_11BE == x->interface_type) {
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

    return 0;
}

static bool pre_filter_encryption(uint16_t message_type) {
    if (message_type == CMDU_TYPE_MAP_DIRECT_ENCAP_DPP ||
        message_type == CMDU_TYPE_MAP_1905_ENCAP_EAPOL ||
        message_type == CMDU_TYPE_MAP_ACK) {
            return false;
    }

    return true;
}

static int calculate_mic(uint8_t *stream, uint16_t stream_len,
                         uint8_t *key, size_t key_len,
                         map_mic_tlv_t *mic_tlv, i1905_cmdu_t *cmdu)
{
    #define CMDU_OCTETS_LEN     6
    #define MIC_TLV_OCTETS_LEN 13

    uint8_t  mic_value[SHA256_MAC_LEN]    = {0};
    uint8_t *params[3]                    = {0};
    uint32_t params_lens[3]               = {0};
    uint8_t  cmdu_octets[CMDU_OCTETS_LEN] = {0};
    uint8_t *p = cmdu_octets;
    uint8_t  reserved = 0;

    _I1B(&cmdu->message_version, &p);
    _I1B(&reserved, &p);
    _I2B(&cmdu->message_type, &p);
    _I2B(&cmdu->message_id, &p);

    uint8_t mic_tlv_octets[MIC_TLV_OCTETS_LEN] = {0};

    /* skip tlv_type while copying */
    memcpy(mic_tlv_octets, (&mic_tlv->tlv_type) + 1, MIC_TLV_OCTETS_LEN);

    params[0] = cmdu_octets;
    params[1] = mic_tlv_octets;
    params[2] = stream;
    params_lens[0] = CMDU_OCTETS_LEN;
    params_lens[1] = MIC_TLV_OCTETS_LEN;
    params_lens[2] = stream_len;

    /* calculate MIC (using HMAC-SHA256) */
    if (PLATFORM_HMAC_SHA256(key, key_len, 3, params, params_lens, mic_value) == 0) {
        log_i1905_e("HMAC-SHA256 failed during MIC calculation!");
        return -1;
    }

    mic_tlv->mic_len = SHA256_MAC_LEN;
    memcpy(mic_tlv->mic, mic_value, SHA256_MAC_LEN);

    return 0;
}

static map_encrypted_payload_tlv_t *encrypt1905RawPacket(uint8_t *stream, uint16_t stream_len,
                                                         uint8_t *src_mac, uint8_t *dest_mac,
                                                         i1905_cmdu_t *cmdu, uint8_t *encr_tx_counter,
                                                         uint8_t *key, size_t key_len)
{
#define CMDU_OCTETS_LEN    6

    uint8_t *encrypted_payload     = NULL;
    uint16_t encrypted_payload_len = 0;
    uint8_t *params[4]             = {0};
    size_t   params_lens[4]        = {0};

    /* exclude End Of Message TLV from the stream */
    stream_len -= TLV_HDR_SIZE;

    encrypted_payload_len = stream_len + AES_BLOCK_SIZE;
    encrypted_payload = calloc(1, encrypted_payload_len);
    if (!encrypted_payload) {
        log_i1905_e("failed to allocate buffer for encrypted payload");
        return NULL;
    }

    /* MAP R4 13.3.2 Encryption Requirements
     * K = 1905 TK (256 bit) corresponding to the receiver
     * P = all of the TLVs in the message concatenated (except the End of Message TLV)
     * AD1 = The first six octets of the 1905 CMDU.
     * AD2 = The Encryption Transmission Counter value at the sender from the field in Encrypted Payload TLV.
     * AD3 = Source 1905 AL MAC Address from the field in Encrypted Payload TLV.
     * AD4 = Destination 1905 AL MAC Address from the field in Encrypted Payload TLV.
     */
    uint8_t cmdu_octets[CMDU_OCTETS_LEN]           = {0};
    uint8_t *p = cmdu_octets;
    uint8_t reserved = 0;

    _I1B(&cmdu->message_version, &p);
    _I1B(&reserved, &p);
    _I2B(&cmdu->message_type, &p);
    _I2B(&cmdu->message_id, &p);

    params[0] = cmdu_octets;
    params[1] = encr_tx_counter;
    params[2] = src_mac;
    params[3] = dest_mac;
    params_lens[0] = CMDU_OCTETS_LEN;
    params_lens[1] = ENCRYPTION_TX_COUNTER_LEN;
    params_lens[2] = ETHER_ADDR_LEN;
    params_lens[3] = ETHER_ADDR_LEN;

    if (PLATFORM_AES_SIV_ENCRYPT(key, key_len, stream, stream_len, 4, params, params_lens, encrypted_payload) == 0) {
        log_i1905_e("AES-SIV encryption failed during 1905 encryption!");
        free(encrypted_payload);
        return NULL;
    }

    map_encrypted_payload_tlv_t *tlv = calloc(1, sizeof(map_encrypted_payload_tlv_t));
    if (!tlv) {
        log_i1905_e("failed to allocate buffer for Encrypted Payload TLV");
        free(encrypted_payload);
        return NULL;
    }

    tlv->tlv_type = TLV_TYPE_ENCRYPTED_PAYLOAD;
    memcpy(tlv->encr_tx_counter, encr_tx_counter, ENCRYPTION_TX_COUNTER_LEN);
    maccpy(tlv->src_al_mac, src_mac);
    maccpy(tlv->dst_al_mac, dest_mac);
    tlv->siv_len = encrypted_payload_len;
    tlv->siv_output = encrypted_payload;

    return tlv;
}

/*#######################################################################
#                       GLOBAL FUNCTIONS                                #
########################################################################*/
static int insert_mic_tlv(i1905_cmdu_t *cmdu, map_mic_tlv_t *mic_tlv, uint8_t *tlv_buf, uint16_t tlv_buf_len,
                          uint8_t *src_mac, map_1905_sec_key_info_t *key_info)
{
    mic_tlv->tlv_type = TLV_TYPE_MIC;
    mic_tlv->gtk_key_id = 1;  /* according to BCM implementation */
    mic_tlv->mic_version = 0; /* according to EM-R4 spec 17.2.68 */
    memcpy(mic_tlv->integrity_tx_counter, key_info->integrity_tx_counter, INTEGRITY_TX_COUNTER_LEN);
    maccpy(mic_tlv->src_al_mac, src_mac);
    mic_tlv->mic = calloc(1, SHA256_MAC_LEN);
    if (!mic_tlv->mic) {
        log_i1905_e("failed to allocate buffer for MIC");
        return -1;
    }

    /* calculate MIC value for MIC TLV using HMAC-SHA256 */
    if (calculate_mic(tlv_buf, tlv_buf_len, key_info->gtk, key_info->gtk_len, mic_tlv, cmdu) != 0) {
        log_i1905_e("failed to calculate MIC");
        free(mic_tlv->mic);
        return -1;
    }

    /* find number of TLVs in list_of_TLVs */
    int num_tlvs = i1905_count_tlvs_in_cmdu(cmdu);
    if (num_tlvs <= 0) {
        log_i1905_e("failed to count TLVs");
        free(mic_tlv->mic);
        return -1;
    }

    /* reallocate list_of_TLVs to insert MIC TLV */
    uint8_t **new_list_of_TLVs = realloc(cmdu->list_of_TLVs, sizeof(uint8_t *) * (num_tlvs + 1));
    if (!new_list_of_TLVs) {
        log_i1905_e("failed to reallocate list of TLVs");
        free(mic_tlv->mic);
        return -1;
    }

    /* insert MIC TLV right before EOM TLV */
    cmdu->list_of_TLVs = new_list_of_TLVs;
    cmdu->list_of_TLVs[num_tlvs - 1] = (uint8_t *)mic_tlv;
    cmdu->list_of_TLVs[num_tlvs]     = NULL;

    return 0;
}

uint8_t forward1905RawPacket(char *interface_name, uint16_t mid, uint8_t *dest_mac, i1905_cmdu_t *cmdu, int get_src_mac_frm_stream)
{
    uint8_t  **streams;
    uint16_t  *streams_lens;
    uint8_t   *src_mac;
    uint8_t    total_streams, x;
    map_1905_sec_key_info_t key_info;

    log_i1905_d("Contents of CMDU to send:0x%x", cmdu->message_type);

    streams = forge_1905_CMDU_from_structure(cmdu, &streams_lens);
    if (NULL == streams) {
        /* Could not forge the packet. Error? */
        log_i1905_e("forge_1905_CMDU_from_structure() failed!");
        return 0;
    }

    src_mac = get_src_mac_frm_stream ? cmdu->cmdu_stream.src_mac_addr : DMalMacGet();

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

    do
    {
        bool is_multicast = is_multicast_ether_addr(dest_mac);

        /* do not encrypt specific 1905 cmdus */
        if (!pre_filter_encryption(cmdu->message_type)) {
            log_i1905_d("this cmdu type should not be encrypted, skipping encryption... type: %08X", cmdu->message_type);
            break;
        }

        /** encrypt frames iff;
         * key information exists for that ale
         * the frame is not fragmented (for phase-1 as per our talk with Koen)
         */
        memset(&key_info, 0, sizeof(key_info));
        
        if (PLATFORM_OS_GET_KEY_INFO(dest_mac, &key_info)) {
            break;
        }
        
        uint8_t *tlv_buf = streams[0] + CMDU_HDR_SIZE; /* skip cmdu header */
        uint16_t tlv_buf_len = streams_lens[0] - CMDU_HDR_SIZE; /* skip cmdu header */
        i1905_cmdu_t new_cmdu = {0};

        /* messages transmitted with CMDU unicast transmission procedures are protected by TLV encryption */
        if (!is_multicast && key_info.ptk_len > 0 && 1 == total_streams) {
            map_encrypted_payload_tlv_t *encrypted_payload_tlv = NULL;

            encrypted_payload_tlv = encrypt1905RawPacket(tlv_buf, tlv_buf_len, src_mac, dest_mac, cmdu, key_info.encr_tx_counter,
                                                         key_info.ptk, key_info.ptk_len);
            if (NULL == encrypted_payload_tlv) {
                log_i1905_e("failed to encrypt 1905 raw packet");
                free_1905_CMDU_packets(streams);
                free(streams_lens);
                return 0;
            }

            /* clean up previous streams */
            free_1905_CMDU_packets(streams);
            free(streams_lens);
            streams_lens = NULL;

            uint8_t *tlvs[2]      = {0};

            tlvs[0] = (uint8_t *)encrypted_payload_tlv;
            new_cmdu.message_version = cmdu->message_version;
            new_cmdu.message_type = cmdu->message_type;
            new_cmdu.message_id = cmdu->message_id;
            new_cmdu.relay_indicator = cmdu->relay_indicator;
            new_cmdu.list_of_TLVs = tlvs;
            map_strlcpy(new_cmdu.interface_name, cmdu->interface_name, sizeof(new_cmdu.interface_name));

            /* forge new stream from the cmdu */
            streams = forge_1905_CMDU_from_structure(&new_cmdu, &streams_lens);
            if (NULL == streams) {
                /* Could not forge the packet. Error? */
                log_i1905_w("forge_1905_CMDU_from_structure() returned 0 streams!");
                free_1905_CMDU_packets(streams);
                free(streams_lens);
                free(encrypted_payload_tlv->siv_output);
                free(encrypted_payload_tlv);
                return 0;
            }
            total_streams = 1;
            free(encrypted_payload_tlv->siv_output);
            free(encrypted_payload_tlv);
            increment_counter_48(key_info.encr_tx_counter);
        }
        /** Messages transmitted with:
         *   - CMDU neighbor multicast transmission procedures or
         *   - CMDU relayed multicast transmission procedures
         * have the transmission of TLVs protected by a message integrity code (MIC) */
        else if (is_multicast && key_info.gtk_len > 0 && 1 == total_streams) {
            map_mic_tlv_t mic_tlv = {0};

            /* calculate MIC value and insert MIC TLV in to the cmdu->list_of_TLVs before forging new streams */
            if (insert_mic_tlv(cmdu, &mic_tlv, tlv_buf, tlv_buf_len, src_mac, &key_info)) {
                log_i1905_e("failed to insert MIC TLV");
                free_1905_CMDU_packets(streams);
                free(streams_lens);
                return 0;
            }

            /* clean up previous streams */
            free_1905_CMDU_packets(streams);
            free(streams_lens);
            streams_lens = NULL;

            /* forge new stream from the cmdu */
            streams = forge_1905_CMDU_from_structure(&new_cmdu, &streams_lens);
            if (NULL == streams) {
                /* Could not forge the packet. Error? */
                log_i1905_w("forge_1905_CMDU_from_structure() returned 0 streams!");
                free_1905_CMDU_packets(streams);
                free(streams_lens);
                free(mic_tlv.mic);
                return 0;
            }
            total_streams = 1;
            free(mic_tlv.mic);
            increment_counter_48(key_info.integrity_tx_counter);
        }
    } while (0);

    x = 0;
    while (streams[x]) {
        log_i1905_t("Sending 1905 message on interface %s, MID %d, fragment %d/%d", interface_name, mid, x + 1, total_streams);

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

    log_i1905_t("Sending LLDP bridge discovery message on interface %s", interface_name);
    if (0 == PLATFORM_SEND_RAW_PACKET(interface_name, mcast_address, src_mac,
                                      ETHERTYPE_LLDP, stream, stream_len)) {
        log_i1905_e("%s: Packet could not be sent!", __func__);
    }
    free_lldp_PAYLOAD_packet(stream);

    return 1;
}

int obtainTLVFrom1905(char *ifname, i1905_param_t param, void *data)
{
    int ret = 0;

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
            ret = _obtainAutoconfigFreqBandTLV(data, 0, ifname);
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
            ret = _obtainLocalDeviceInfoTLV(data);
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

            if (!wsc_data || !wsc_data->m1.wsc_frame || !wsc_data->m2_cfg) {
                return -1;
            }

            if (wscBuildM2(wsc_data->m1.wsc_frame, wsc_data->m1.wsc_frame_size, &m2, &m2_size,
                           wsc_data->m2_cfg->profile, wsc_data->m2_cfg->map_ext, ifname) == 0) {
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
    return ret;
}
