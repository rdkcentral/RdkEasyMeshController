/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE ************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]
** All Rights Reserved
** The source code form of this Open Source Project components
** is subject to the terms of the BSD-2-Clause-Patent.
** You can redistribute it and/or modify it under the terms of
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent)
** See COPYING file/LICENSE file for more details.
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
#define TLV_STRUCT_NAME_PREFIX TLV_STRUCT_NAME_PREFIX_MAP

#include "1905_tlvs.h"
#include "packet_tools.h"
#include "map_tlvs.h"

/*#######################################################################
#                       TLV HANDLERS                                    #
########################################################################*/
/*#######################################################################
# 1905 Layer Security Capability TLV ("Section 17.2.67")                #
########################################################################*/
TLV_FREE_FUNCTION(1905_security_cap) {}

static uint8_t* parse_1905_security_cap_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_1905_security_cap_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_EXP_LEN(3);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_1905_LAYER_SECURITY_CAPABILITY;

    _E1B(&p, &ret->onboarding_protocol);
    _E1B(&p, &ret->mic_algorithm);
    _E1B(&p, &ret->encryption_algorithm);

    PARSE_CHECK_INTEGRITY(1905_security_cap)
    PARSE_RETURN
}

static uint8_t* forge_1905_security_cap_tlv(void *memory_structure, uint16_t *len)
{
    map_1905_security_cap_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 3;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,              &p);
    _I2B(&tlv_length,               &p);

    _I1B(&m->onboarding_protocol,   &p);
    _I1B(&m->mic_algorithm,         &p);
    _I1B(&m->encryption_algorithm,  &p);

    FORGE_RETURN
}

/*#######################################################################
# MIC TLV ("Section 17.2.68")                                           #
########################################################################*/
TLV_FREE_FUNCTION(mic)
{
    SFREE(m->mic);
}

static uint8_t *parse_mic_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_mic_tlv_t *ret;
    uint8_t *p = packet_stream;
    uint8_t byte;

    PARSE_CHECK_MIN_LEN(1 + INTEGRITY_TX_COUNTER_LEN + ETHER_ADDR_LEN + 2 + 32); /* 32 is SHA256 MAC Length */

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_MIC;

    /**
     * bits 7-6: 1905 GTK Key Id
     * bits 5-4: MIC Version
     * bits 3-0: Reserved
     */
    _E1B(&p, &byte);
    ret->gtk_key_id  = (byte & (BIT_MASK_7 | BIT_MASK_6)) >> BIT_SHIFT_6;
    ret->mic_version = (byte & (BIT_MASK_5 | BIT_MASK_4)) >> BIT_SHIFT_4;
    ret->reserved    =  byte & (BIT_MASK_3 | BIT_MASK_2 | BIT_MASK_1 | BIT_MASK_0);

    _EnB(&p, ret->integrity_tx_counter, INTEGRITY_TX_COUNTER_LEN);
    _EnB(&p, ret->src_al_mac, ETHER_ADDR_LEN);
    _E2B(&p, &ret->mic_len);

    if (ret->mic_len > 0) {
        ret->mic = calloc(1, (ret->mic_len * sizeof(uint8_t)));
        if (NULL == ret->mic) {
            free(ret);
            return NULL;
        }
        _EnB(&p, ret->mic, ret->mic_len);
    }

    PARSE_CHECK_INTEGRITY(mic)
    PARSE_RETURN
}

static uint8_t *forge_mic_tlv(void *memory_structure, uint16_t *len)
{
    map_mic_tlv_t *m = (map_mic_tlv_t *)memory_structure;
    uint8_t *ret, *p, byte;

    uint16_t tlv_length = 1 + INTEGRITY_TX_COUNTER_LEN + ETHER_ADDR_LEN + 2 + m->mic_len;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,        &p);
    _I2B(&tlv_length,         &p);

    byte = ((m->gtk_key_id << BIT_SHIFT_6)  |
            (m->mic_version << BIT_SHIFT_4) |
             m->reserved);
    _I1B(&byte, &p);

    _InB(m->integrity_tx_counter, &p, INTEGRITY_TX_COUNTER_LEN);
    _InB(m->src_al_mac,           &p, ETHER_ADDR_LEN);
    _I2B(&m->mic_len,             &p);
    _InB(m->mic,                  &p, m->mic_len);

    FORGE_RETURN
}

/*#######################################################################
# Encrypted Payload TLV ("Section 17.2.69")                             #
########################################################################*/
TLV_FREE_FUNCTION(encrypted_payload) {
    SFREE(m->siv_output);
}

static uint8_t *parse_encrypted_payload_tlv(uint8_t *packet_stream, uint16_t len)
{
#define AES_BLOCK_SIZE 16
    map_encrypted_payload_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_MIN_LEN(ENCRYPTION_TX_COUNTER_LEN + ETHER_ADDR_LEN + ETHER_ADDR_LEN + 2 + AES_BLOCK_SIZE);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_ENCRYPTED_PAYLOAD;
    _EnB(&p, ret->encr_tx_counter, ENCRYPTION_TX_COUNTER_LEN);
    _EnB(&p, ret->src_al_mac, ETHER_ADDR_LEN);
    _EnB(&p, ret->dst_al_mac, ETHER_ADDR_LEN);
    _E2B(&p, &ret->siv_len);

    if (ret->siv_len > 0) {
        ret->siv_output = calloc(1, (ret->siv_len * sizeof(uint8_t)));
        if (NULL == ret->siv_output) {
            free(ret);
            return NULL;
        }
        _EnB(&p, ret->siv_output, ret->siv_len);
    }

    PARSE_CHECK_INTEGRITY(encrypted_payload)
    PARSE_RETURN
}

static uint8_t *forge_encrypted_payload_tlv(void *memory_structure, uint16_t *len)
{
    map_encrypted_payload_tlv_t *m = (map_encrypted_payload_tlv_t *)memory_structure;
    uint8_t  *ret, *p;
    /*  17.2.69 Encrypted Payload TLV len (Page 145 of MAP-R4 Spec):
     *  type (1 byte) +
     *  length field (2 bytes) +
     *  encryption transmission counter (6 bytes) +
     *  source al mac address (6 bytes -> ETHER_ADDR_LEN) +
     *  destination 1905 al mac address (6 bytes -> ETHER_ADDR_LEN) +
     *  aes-siv length (2 bytes) +
     *  aes-siv (n bytes) */
    uint16_t  tlv_length = ENCRYPTION_TX_COUNTER_LEN + ETHER_ADDR_LEN + ETHER_ADDR_LEN + 2 + m->siv_len;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,        &p);
    _I2B(&tlv_length,         &p);
    _InB(&m->encr_tx_counter, &p, ENCRYPTION_TX_COUNTER_LEN);
    _InB(&m->src_al_mac,      &p, ETHER_ADDR_LEN);
    _InB(&m->dst_al_mac,      &p, ETHER_ADDR_LEN);
    _I2B(&m->siv_len,         &p);
    _InB(m->siv_output,       &p, m->siv_len);

    FORGE_RETURN
}

/*#######################################################################
# AP Wi-Fi 6 Capabilities TLV ("Section 17.2.72")                       #
########################################################################*/
TLV_FREE_FUNCTION(ap_wifi6_cap) {}

static uint8_t* parse_ap_wifi6_cap_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_ap_wifi6_cap_tlv_t *ret;
    uint8_t *p = packet_stream, byte, i, j;

    /* Min TLV len: radio id + roles_nr len. */
    PARSE_CHECK_MIN_LEN(ETHER_ADDR_LEN + 1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_AP_WIFI6_CAPABILITIES;

    _EnB(&p, ret->radio_id, ETHER_ADDR_LEN);
    _E1B(&p, &ret->roles_nr);

    for (i = 0; i < ret->roles_nr; i++) {
        _E1B(&p, &byte);
        ret->cap_data[i].agent_role  = (byte & (BIT_MASK_7 | BIT_MASK_6)) >> BIT_SHIFT_6;
        ret->cap_data[i].he160       = (byte & BIT_MASK_5) ? SET_BIT : RESET_BIT;
        ret->cap_data[i].he8080      = (byte & BIT_MASK_4) ? SET_BIT : RESET_BIT;
        ret->cap_data[i].mcs_nss_nr  =  byte & (BIT_MASK_3 | BIT_MASK_2 | BIT_MASK_1 | BIT_MASK_0);
        PARSE_LIMIT(ret->cap_data[i].mcs_nss_nr, 2 * MAX_MCS_NSS);

        for (j = 0; j < ret->cap_data[i].mcs_nss_nr / 2; j++) {
            _E2B(&p, &ret->cap_data[i].mcs_nss[j]);
        }

        _E1B(&p, &byte);
        ret->cap_data[i].su_beamformer      = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;
        ret->cap_data[i].su_beamformee      = (byte & BIT_MASK_6) ? SET_BIT : RESET_BIT;
        ret->cap_data[i].mu_beamformer      = (byte & BIT_MASK_5) ? SET_BIT : RESET_BIT;
        ret->cap_data[i].beamformee_sts_l80 = (byte & BIT_MASK_4) ? SET_BIT : RESET_BIT;
        ret->cap_data[i].beamformee_sts_g80 = (byte & BIT_MASK_3) ? SET_BIT : RESET_BIT;
        ret->cap_data[i].ul_mu_mimo         = (byte & BIT_MASK_2) ? SET_BIT : RESET_BIT;
        ret->cap_data[i].ul_ofdma           = (byte & BIT_MASK_1) ? SET_BIT : RESET_BIT;
        ret->cap_data[i].dl_ofdma           = (byte & BIT_MASK_0) ? SET_BIT : RESET_BIT;

        _E1B(&p, &byte);
        ret->cap_data[i].max_dl_mu_mimo_tx = (byte & (BIT_MASK_7 | BIT_MASK_6 | BIT_MASK_5 | BIT_MASK_4)) >> BIT_SHIFT_4;
        ret->cap_data[i].max_ul_mu_mimo_rx =  byte & (BIT_MASK_3 | BIT_MASK_2 | BIT_MASK_1 | BIT_MASK_0);

        _E1B(&p, &ret->cap_data[i].max_dl_ofdma_tx);
        _E1B(&p, &ret->cap_data[i].max_ul_ofdma_rx);

        _E1B(&p, &byte);
        ret->cap_data[i].rts           = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;
        ret->cap_data[i].mu_rts        = (byte & BIT_MASK_6) ? SET_BIT : RESET_BIT;
        ret->cap_data[i].multi_bssid   = (byte & BIT_MASK_5) ? SET_BIT : RESET_BIT;
        ret->cap_data[i].mu_edca       = (byte & BIT_MASK_4) ? SET_BIT : RESET_BIT;
        ret->cap_data[i].twt_requester = (byte & BIT_MASK_3) ? SET_BIT : RESET_BIT;
        ret->cap_data[i].twt_responder = (byte & BIT_MASK_2) ? SET_BIT : RESET_BIT;
        ret->cap_data[i].reserved      = byte & (BIT_MASK_1 | BIT_MASK_0);
    }

    PARSE_CHECK_INTEGRITY(ap_wifi6_cap)
    PARSE_RETURN
}

static uint8_t* forge_ap_wifi6_cap_tlv(void *memory_structure, uint16_t *len)
{
    map_ap_wifi6_cap_tlv_t *m = memory_structure;
    uint8_t  *ret, *p, byte, i, j;
    /* TLV len: radio id + roles_nr len. */
    uint16_t tlv_length = ETHER_ADDR_LEN + 1;

    for (i = 0; i < m->roles_nr; i++) {
        /* ap cap byte + mcs_nss len + cap bytes 1..5 */
        tlv_length += 1 + m->cap_data[i].mcs_nss_nr + 5;
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _InB(m->radio_id,  &p, ETHER_ADDR_LEN);
    _I1B(&m->roles_nr, &p);

    for (i = 0; i < m->roles_nr; i++) {
        byte = ((m->cap_data[i].agent_role << BIT_SHIFT_6) |
                (m->cap_data[i].he160      << BIT_SHIFT_5) |
                (m->cap_data[i].he8080     << BIT_SHIFT_4) |
                 m->cap_data[i].mcs_nss_nr);
        _I1B(&byte, &p);

        for (j = 0; j < m->cap_data[i].mcs_nss_nr / 2; j++) {
            _I2B(&m->cap_data[i].mcs_nss[j], &p);
        }

        byte = ((m->cap_data[i].su_beamformer      << BIT_SHIFT_7) |
                (m->cap_data[i].su_beamformee      << BIT_SHIFT_6) |
                (m->cap_data[i].mu_beamformer      << BIT_SHIFT_5) |
                (m->cap_data[i].beamformee_sts_l80 << BIT_SHIFT_4) |
                (m->cap_data[i].beamformee_sts_g80 << BIT_SHIFT_3) |
                (m->cap_data[i].ul_mu_mimo         << BIT_SHIFT_2) |
                (m->cap_data[i].ul_ofdma           << BIT_SHIFT_1) |
                 m->cap_data[i].dl_ofdma);
        _I1B(&byte, &p);

        byte = ((m->cap_data[i].max_dl_mu_mimo_tx << BIT_SHIFT_4) |
                 m->cap_data[i].max_ul_mu_mimo_rx);
        _I1B(&byte, &p);

        _I1B(&m->cap_data[i].max_dl_ofdma_tx, &p);
        _I1B(&m->cap_data[i].max_ul_ofdma_rx, &p);

        byte = ((m->cap_data[i].rts           << BIT_SHIFT_7) |
                (m->cap_data[i].mu_rts        << BIT_SHIFT_6) |
                (m->cap_data[i].multi_bssid   << BIT_SHIFT_5) |
                (m->cap_data[i].mu_edca       << BIT_SHIFT_4) |
                (m->cap_data[i].twt_requester << BIT_SHIFT_3) |
                (m->cap_data[i].twt_responder << BIT_SHIFT_2) |
                 m->cap_data[i].reserved);
        _I1B(&byte, &p);
    }

    FORGE_RETURN
}

/*#######################################################################
# Associated Wi-Fi 6 STA Status Report TLV ("Section 17.2.73")           #
########################################################################*/
TLV_FREE_FUNCTION(assoc_wifi6_sta_status) {}

static uint8_t* parse_assoc_wifi6_sta_status_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_assoc_wifi6_sta_status_tlv_t *ret;
    uint8_t *p = packet_stream, i;

/* Min TLV len: sta mac addr + number of TID */
    PARSE_CHECK_MIN_LEN(ETHER_ADDR_LEN + 1);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_ASSOCIATED_WIFI6_STA_STATUS_REPORT;

    _EnB(&p, ret->sta_mac, ETHER_ADDR_LEN);
    _E1B(&p, &ret->TID_nr);

    PARSE_LIMIT(ret->TID_nr, MAX_NUM_TID)

    for (i = 0; i < ret->TID_nr; i++) {
        _E1B(&p, &ret->TID[i]);
        _E1B(&p, &ret->queue_size[i]);
    }

    PARSE_CHECK_INTEGRITY(assoc_wifi6_sta_status)
    PARSE_RETURN
}

static uint8_t* forge_assoc_wifi6_sta_status_tlv(void *memory_structure, uint16_t *len)
{
    map_assoc_wifi6_sta_status_tlv_t *m = memory_structure;
    /* TLV len: sta_mac(6) + TID_nr(1) + (TID(1) + QueueSize(1))*TID_nr. */
    uint16_t  tlv_length = 6 + 1 + 2*m->TID_nr;
    uint8_t  *ret, *p, i;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _InB(&m->sta_mac,  &p, 6);
    _I1B(&m->TID_nr,  &p);

    for (i=0; i < m->TID_nr; i++) {
        _I1B(&m->TID[i],  &p);
        _I1B(&m->queue_size[i],  &p);
    }

    FORGE_RETURN
}

/*#######################################################################
# BSSID TLV ("Section 17.2.74")                                         #
########################################################################*/
TLV_FREE_FUNCTION(bssid) {}

static uint8_t* parse_bssid_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_bssid_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_EXP_LEN(6);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_BSSID;

    _EnB(&p, ret->bssid, 6);

    PARSE_CHECK_INTEGRITY(bssid)
    PARSE_RETURN
}

static uint8_t* forge_bssid_tlv(void *memory_structure, uint16_t *len)
{
    map_bssid_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 6;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _InB(&m->bssid,    &p, 6);

    FORGE_RETURN
}

/*#######################################################################
# BSS Configuration Report TLV ("Section 17.2.75")                      #
########################################################################*/
TLV_FREE_FUNCTION(bss_configuration_report) {}

static uint8_t *parse_bss_configuration_report_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_bss_configuration_report_tlv_t *ret;
    uint8_t *p = packet_stream;
    uint8_t byte;
    int i, j;

    PARSE_CHECK_MIN_LEN(1);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_BSS_CONFIGURATION_REPORT;

    _E1B(&p, &ret->radios_nr);
    PARSE_LIMIT(ret->radios_nr, MAX_RADIO_PER_AGENT);
    for (i = 0; i < ret->radios_nr; i++) {
        _EnB(&p, ret->radios[i].ruid, ETHER_ADDR_LEN);
        _E1B(&p, &ret->radios[i].bss_nr);

        PARSE_LIMIT(ret->radios[i].bss_nr, MAX_BSS_PER_RADIO);
        for (j = 0; j < ret->radios[i].bss_nr; j++) {
            _EnB(&p, ret->radios[i].bss[j].bssid, ETHER_ADDR_LEN);
            _E1B(&p, &byte);
            ret->radios[i].bss[j].backhaul_bss         = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;
            ret->radios[i].bss[j].fronthaul_bss        = (byte & BIT_MASK_6) ? SET_BIT : RESET_BIT;
            ret->radios[i].bss[j].r1_disallowed_status = (byte & BIT_MASK_5) ? SET_BIT : RESET_BIT;
            ret->radios[i].bss[j].r2_disallowed_status = (byte & BIT_MASK_4) ? SET_BIT : RESET_BIT;
            ret->radios[i].bss[j].multiple_bssid       = (byte & BIT_MASK_3) ? SET_BIT : RESET_BIT;
            ret->radios[i].bss[j].transmitted_bssid    = (byte & BIT_MASK_2) ? SET_BIT : RESET_BIT;
            ret->radios[i].bss[j].reserved1            =  byte & (BIT_MASK_1 | BIT_MASK_0);
            _E1B(&p, &ret->radios[i].bss[j].reserved2);
            _E1B(&p, &ret->radios[i].bss[j].ssid_len);
            PARSE_LIMIT(ret->radios[i].bss[j].ssid_len, MAX_SSID_LEN);
            _EnB(&p, ret->radios[i].bss[j].ssid, ret->radios[i].bss[j].ssid_len);
        }
    }

    PARSE_CHECK_INTEGRITY(bss_configuration_report)
    PARSE_RETURN
}

static uint8_t *forge_bss_configuration_report_tlv(void *memory_structure, uint16_t *len)
{
    uint16_t tlv_length = 1;
    uint8_t *ret, *p;
    map_bss_configuration_report_tlv_t *m = memory_structure;
    int i, j;

    if (m->radios_nr > 0 ) {
        for (i = 0; i < m->radios_nr; i++) {
            tlv_length += ETHER_ADDR_LEN;
            if (m->radios[i].bss_nr > 0) {
                tlv_length += 1;
                for (j = 0; j < m->radios[i].bss_nr; j++) {
                    tlv_length += ETHER_ADDR_LEN + 1 + 1 + 1 + m->radios[i].bss[j].ssid_len;
                }
            }
        }
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _I1B(&m->radios_nr, &p);
    for (i = 0; i < m->radios_nr; i++) {
        _InB(m->radios[i].ruid, &p, ETHER_ADDR_LEN);
        _I1B(&m->radios[i].bss_nr, &p);
        for (j = 0; j < m->radios[i].bss_nr; j++) {
            _InB(m->radios[i].bss[j].bssid, &p, ETHER_ADDR_LEN);

            uint8_t byte = ((m->radios[i].bss[j].backhaul_bss << BIT_SHIFT_7) |
                            (m->radios[i].bss[j].fronthaul_bss << BIT_SHIFT_6) |
                            (m->radios[i].bss[j].r1_disallowed_status << BIT_SHIFT_5) |
                            (m->radios[i].bss[j].r2_disallowed_status << BIT_SHIFT_4) |
                            (m->radios[i].bss[j].multiple_bssid << BIT_SHIFT_3) |
                            (m->radios[i].bss[j].transmitted_bssid << BIT_SHIFT_2) |
                             m->radios[i].bss[j].reserved1);
            _I1B(&byte, &p);
            _I1B(&m->radios[i].bss[j].reserved2, &p);
            _I1B(&m->radios[i].bss[j].ssid_len, &p);
            _InB(m->radios[i].bss[j].ssid, &p, m->radios[i].bss[j].ssid_len);
        }
    }

    FORGE_RETURN
}

/*#######################################################################
# Agent List TLV ("Section 17.2.77")                                    #
########################################################################*/
TLV_FREE_FUNCTION(agent_list) {}

static uint8_t *parse_agent_list_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_agent_list_tlv_t *ret;
    uint8_t *p = packet_stream;
    int i;

    PARSE_CHECK_MIN_LEN(1);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_AGENT_LIST;

    _E1B(&p, &ret->agent_nr);
    for (i = 0; i < ret->agent_nr; i++) {
        _EnB(&p, ret->entries[i].al_mac, ETHER_ADDR_LEN);
        _E1B(&p, &ret->entries[i].map_profile);
        _E1B(&p, &ret->entries[i].security);
    }

    PARSE_CHECK_INTEGRITY(agent_list)
    PARSE_RETURN
}

static uint8_t *forge_agent_list_tlv(void *memory_structure, uint16_t *len)
{
    uint16_t tlv_length = 1;
    uint8_t *ret, *p;
    map_agent_list_tlv_t *m = memory_structure;
    int i;

    if (m->agent_nr > 0 ) {
        tlv_length += m->agent_nr * (ETHER_ADDR_LEN + 1 + 1);
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _I1B(&m->agent_nr, &p);
    for (i = 0; i < m->agent_nr; i++) {
        _InB(m->entries[i].al_mac, &p, ETHER_ADDR_LEN);
        _I1B(&m->entries[i].map_profile, &p);
        _I1B(&m->entries[i].security, &p);
    }

    FORGE_RETURN
}

/*#######################################################################
# 1905 Encap DPP TLV ("Section 17.2.79")                                #
########################################################################*/
TLV_FREE_FUNCTION(1905_encap_dpp)
{
    SFREE(m->frame);
}

static uint8_t* parse_1905_encap_dpp_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_1905_encap_dpp_tlv_t *ret;
    uint8_t *p = packet_stream, byte;

    /* Min TLV len: bitfield (1) + frame_type (1) + frame_len (2) */
    PARSE_CHECK_MIN_LEN(4)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_1905_ENCAP_DPP;

    _E1B(&p, &byte);
    ret->enrollee_mac_present = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;
    ret->reserved1 = (byte & BIT_MASK_6) ? SET_BIT : RESET_BIT;
    ret->dpp_frame_indicator = (byte & BIT_MASK_5) ? SET_BIT : RESET_BIT;
    ret->reserved2 = byte & (BIT_MASK_4 | BIT_MASK_3 | BIT_MASK_2 | BIT_MASK_1 | BIT_MASK_0);

    if (ret->enrollee_mac_present) {
        /* MAP R3 17.2.79 : This field is present if the Enrollee MAC Address present bit is set to one */
        _EnB(&p, ret->sta_mac, ETHER_ADDR_LEN);
    }
    _E1B(&p, &ret->frame_type);
    _E2B(&p, &ret->frame_len);

    if (ret->frame_len > 0) {
        ret->frame = calloc(ret->frame_len, sizeof(uint8_t));
        if (NULL == ret->frame) {
            free(ret);
            return NULL;
        }
        _EnB(&p, ret->frame, ret->frame_len);
    }

    PARSE_CHECK_INTEGRITY(1905_encap_dpp)
    PARSE_RETURN
}

static uint8_t* forge_1905_encap_dpp_tlv(void *memory_structure, uint16_t *len)
{
    map_1905_encap_dpp_tlv_t *m = memory_structure;
    uint8_t  *ret, *p, byte;
    /* TLV len: bitfield (1) + type (1) + length field (2) + frame length (n) */
    uint16_t tlv_length = 1 + 2 + 1 + m->frame_len;
    if (m->enrollee_mac_present) {
        /* Include STA MAC length if Enrollee MAC is present. */
        tlv_length += ETHER_ADDR_LEN;
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);

    byte = ((m->enrollee_mac_present << BIT_SHIFT_7) |
            (m->reserved1            << BIT_SHIFT_6) |
            (m->dpp_frame_indicator  << BIT_SHIFT_5) |
             m->reserved2);
    _I1B(&byte, &p);

    if (m->enrollee_mac_present) {
        /* MAP R3 17.2.79 : This field is present if the Enrollee MAC Address present bit is set to one */
        _InB(m->sta_mac, &p, ETHER_ADDR_LEN);
    }
    _I1B(&m->frame_type, &p);
    _I2B(&m->frame_len, &p);
    _InB(m->frame, &p, m->frame_len);

    FORGE_RETURN
}

/*#######################################################################
# DPP CCE Indication TLV ("Section 17.2.82")                            #
########################################################################*/
TLV_FREE_FUNCTION(dpp_cce_indication) {}

static uint8_t* parse_dpp_cce_indication_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_dpp_cce_indication_tlv_t *ret;
    uint8_t *p = packet_stream;

    /* Min TLV len: 1 byte of Advertise flag */
    PARSE_CHECK_MIN_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_DPP_CCE_INDICATION;
    _E1B(&p, &ret->advertise);

    PARSE_CHECK_INTEGRITY(dpp_cce_indication)
    PARSE_RETURN
}

static uint8_t* forge_dpp_cce_indication_tlv(void *memory_structure, uint16_t *len)
{
    map_dpp_cce_indication_tlv_t *m = memory_structure;
    uint8_t  *ret, *p;
    /* TLV len: 1 byte of Advertise flag */
    uint16_t tlv_length = 1;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _I1B(&m->advertise, &p);

    FORGE_RETURN
}

/*#######################################################################
# DPP Chirp Value TLV ("Section 17.2.83")                               #
########################################################################*/
TLV_FREE_FUNCTION(dpp_chirp_value)
{
    SFREE(m->hash);
}

static uint8_t* parse_dpp_chirp_value_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_dpp_chirp_value_tlv_t *ret;
    uint8_t *p = packet_stream, byte;

    /* TLV len: bitfield (1) + length field (1) + hash length (n) */
    PARSE_CHECK_MIN_LEN(2)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_DPP_CHIRP_VALUE;

    _E1B(&p, &byte);
    ret->enrollee_mac_present = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;
    ret->hash_validity = (byte & BIT_MASK_6) ? SET_BIT : RESET_BIT;
    ret->reserved = byte & (BIT_MASK_5 | BIT_MASK_4 | BIT_MASK_3 | BIT_MASK_2 | BIT_MASK_1 | BIT_MASK_0);

    if (ret->enrollee_mac_present) {
        /* MAP R3 17.2.79 : This field is present if the Enrollee MAC Address present bit is set to one */
        _EnB(&p, ret->sta_mac, ETHER_ADDR_LEN);
    }
    _E1B(&p, &ret->hash_len);

    if (ret->hash_len > 0) {
        ret->hash = calloc(ret->hash_len, sizeof(uint8_t));
        if (NULL == ret->hash) {
            free(ret);
            return NULL;
        }
        _EnB(&p, ret->hash, ret->hash_len);
    }

    PARSE_CHECK_INTEGRITY(dpp_chirp_value)
    PARSE_RETURN
}

static uint8_t* forge_dpp_chirp_value_tlv(void *memory_structure, uint16_t *len)
{
    map_dpp_chirp_value_tlv_t *m = memory_structure;
    uint8_t  *ret, *p, byte;
    /* TLV len: bitfield (1) + length field (1) + hash length (n) */
    uint16_t tlv_length = 1 + 1 + m->hash_len;
    if (m->enrollee_mac_present) {
        /* Include STA MAC length if Enrollee MAC is present. */
        tlv_length += ETHER_ADDR_LEN;
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);

    byte = ((m->enrollee_mac_present << BIT_SHIFT_7) |
            (m->hash_validity        << BIT_SHIFT_6) |
             m->reserved);
    _I1B(&byte, &p);

    if (m->enrollee_mac_present) {
        /* MAP R3 17.2.83 : This field is present if the Enrollee MAC Address present bit is set to one */
        _InB(m->sta_mac, &p, ETHER_ADDR_LEN);
    }
    _I1B(&m->hash_len, &p);
    _InB(m->hash, &p, m->hash_len);

    FORGE_RETURN
}

/*#######################################################################
# 1905 Encap EAPOL TLV ("Section 17.2.80")                              #
########################################################################*/
TLV_FREE_FUNCTION(1905_encap_eapol) {}

static uint8_t* parse_1905_encap_eapol_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_1905_encap_eapol_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_MIN_LEN(1)

    /* Allocate struct and frame_body */
    ret = calloc(1, sizeof(*ret) + len);
    if (NULL == ret) {
        return NULL;
    }

    ret->tlv_type  = TLV_TYPE_1905_ENCAP_EAPOL;
    ret->frame_len = len;
    ret->frame     = (uint8_t *)(ret + 1);
    _EnB(&p, ret->frame, ret->frame_len);

    PARSE_CHECK_INTEGRITY(1905_encap_eapol)
    PARSE_RETURN
}

static uint8_t* forge_1905_encap_eapol_tlv(void *memory_structure, uint16_t *len)
{
    map_1905_encap_eapol_tlv_t *m = memory_structure;
    uint16_t tlv_length = m->frame_len;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _InB(m->frame, &p, m->frame_len);

    FORGE_RETURN
}

/*#######################################################################
# BSS Configuration Request TLV ("Section 17.2.84")                     #
########################################################################*/
TLV_FREE_FUNCTION(bss_configuration_request) {}

static uint8_t* parse_bss_configuration_request_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_bss_configuration_request_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_MIN_LEN(1)

    /* Allocate struct and frame_body */
    ret = calloc(1, sizeof(*ret) + len);
    if (NULL == ret) {
        return NULL;
    }

    ret->tlv_type  = TLV_TYPE_BSS_CONFIGURATION_REQUEST;
    ret->obj_len = len;
    ret->obj     = (uint8_t *)(ret + 1);
    _EnB(&p, ret->obj, ret->obj_len);

    PARSE_CHECK_INTEGRITY(bss_configuration_request)
    PARSE_RETURN
}

static uint8_t* forge_bss_configuration_request_tlv(void *memory_structure, uint16_t *len)
{
    map_bss_configuration_request_tlv_t *m = memory_structure;
    uint16_t tlv_length = m->obj_len;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _InB(m->obj, &p, m->obj_len);

    FORGE_RETURN
}

/*#######################################################################
# DPP Message TLV ("Section 17.2.86")                                   #
########################################################################*/
TLV_FREE_FUNCTION(dpp_message) {}

static uint8_t* parse_dpp_message_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_dpp_message_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_MIN_LEN(1)

    /* Allocate struct and frame_body */
    ret = calloc(1, sizeof(*ret) + len);
    if (NULL == ret) {
        return NULL;
    }

    ret->tlv_type  = TLV_TYPE_DPP_MESSAGE;
    ret->frame_len = len;
    ret->frame     = (uint8_t *)(ret + 1);
    _EnB(&p, ret->frame, ret->frame_len);

    PARSE_CHECK_INTEGRITY(dpp_message)
    PARSE_RETURN
}

static uint8_t* forge_dpp_message_tlv(void *memory_structure, uint16_t *len)
{
    map_dpp_message_tlv_t *m = memory_structure;
    uint16_t tlv_length = m->frame_len;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _InB(m->frame, &p, m->frame_len);

    FORGE_RETURN
}

/*#######################################################################
# Device Inventory TLV ("Section 17.2.76")                              #
########################################################################*/
TLV_FREE_FUNCTION(device_inventory) {}

static uint8_t* parse_device_inventory_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_device_inventory_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    /* TLV len: lsn (1) + lsv (1) + lee (1) */
    PARSE_CHECK_MIN_LEN(3)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_DEVICE_INVENTORY;

    _E1B(&p, &ret->serial_len);
    if (ret->serial_len > MAP_INVENTORY_ITEM_LEN) {
        free(ret);
        return NULL;
    } else if (ret->serial_len > 0) {
        _EnB(&p, ret->serial, ret->serial_len);
    }

    _E1B(&p, &ret->version_len);
    if (ret->version_len > MAP_INVENTORY_ITEM_LEN) {
        free(ret);
        return NULL;
    } else if (ret->version_len) {
        _EnB(&p, ret->version, ret->version_len);
    }

    _E1B(&p, &ret->environment_len);
    if (ret->environment_len > MAP_INVENTORY_ITEM_LEN) {
        free(ret);
        return NULL;
    } else if (ret->environment_len) {
        _EnB(&p, ret->environment, ret->environment_len);
    }

    _E1B(&p, &ret->radios_nr);
    PARSE_LIMIT(ret->radios_nr, MAX_RADIO_PER_AGENT);
    for (i = 0; i < ret->radios_nr; i++) {
        _EnB(&p, ret->radios[i].ruid, ETHER_ADDR_LEN);
        _E1B(&p, &ret->radios[i].vendor_len);
        if (ret->radios[i].vendor_len > MAP_INVENTORY_ITEM_LEN) {
            free(ret);
            return NULL;
        } else if (ret->radios[i].vendor_len > 0) {
            _EnB(&p, ret->radios[i].vendor, ret->radios[i].vendor_len);
        }
    }

    PARSE_CHECK_INTEGRITY(device_inventory)
    PARSE_RETURN
}

static uint8_t* forge_device_inventory_tlv(void *memory_structure, uint16_t *len)
{
    map_device_inventory_tlv_t *m = memory_structure;
    uint8_t  *ret, *p, i;
    uint16_t tlv_length = 1 + m->serial_len + 1 + m->version_len + 1 + m->environment_len;

    if (m->radios_nr > 0) {
        /* Increase lenght as radio count is valid. */
        tlv_length += 1;
        for (i = 0; i < m->radios_nr; i++) {
            /* Add ruid len and vendor len per radio. */
            tlv_length += ETHER_ADDR_LEN + 1 + m->radios[i].vendor_len;
        }
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);

    _I1B(&m->serial_len, &p);
    if (m->serial_len > MAP_INVENTORY_ITEM_LEN) {
        free(ret);
        return NULL;
    }else if (m->serial_len) {
        _InB(m->serial, &p, m->serial_len);
    }

    _I1B(&m->version_len, &p);
    if (m->version_len > MAP_INVENTORY_ITEM_LEN) {
        free(ret);
        return NULL;
    } else if (m->version_len) {
        _InB(m->version, &p, m->version_len);
    }

    _I1B(&m->environment_len, &p);
    if (m->environment_len > MAP_INVENTORY_ITEM_LEN) {
        free(ret);
        return NULL;
    } else if (m->environment_len) {
        _InB(m->environment, &p, m->environment_len);
    }

    _I1B(&m->radios_nr, &p);
    for (i = 0; i < m->radios_nr; i++) {
        _InB(m->radios[i].ruid, &p, ETHER_ADDR_LEN);
        _I1B(&m->radios[i].vendor_len, &p);
        if (m->radios[i].vendor_len > MAP_INVENTORY_ITEM_LEN) {
            free(ret);
            return NULL;
        } else if (m->radios[i].vendor_len > 0) {
            _InB(m->radios[i].vendor, &p, m->radios[i].vendor_len);
        }
    }

    FORGE_RETURN
}

/*#######################################################################
# AKM Suite Capabilities TLV ("Section 17.2.78")                        #
########################################################################*/
TLV_FREE_FUNCTION(akm_suite_cap) {
    SFREE(m->bh_akm_suites);
    SFREE(m->fh_akm_suites);
}

static uint8_t* parse_akm_suite_cap_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_akm_suite_cap_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    /* Min TLV len: bh_akm_suites_nr (1) + fh_akm_suites_nr (1) */
    PARSE_CHECK_MIN_LEN(2)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_AKM_SUITE_CAPABILITIES;

    _E1B(&p, &ret->bh_akm_suites_nr);
    if (ret->bh_akm_suites_nr > 0) {
        ret->bh_akm_suites = calloc(ret->bh_akm_suites_nr, sizeof(*ret->bh_akm_suites));
        if (ret->bh_akm_suites == NULL) {
            PARSE_FREE_RET_RETURN(akm_suite_cap)
        }

        for (i = 0; i < ret->bh_akm_suites_nr; i++) {
            _E1B(&p, &ret->bh_akm_suites[i].oui[0]);
            _E1B(&p, &ret->bh_akm_suites[i].oui[1]);
            _E1B(&p, &ret->bh_akm_suites[i].oui[2]);
            _E1B(&p, &ret->bh_akm_suites[i].akm_suite_type);
        }
    }

    _E1B(&p, &ret->fh_akm_suites_nr);
    if (ret->fh_akm_suites_nr > 0) {
        ret->fh_akm_suites = calloc(ret->fh_akm_suites_nr, sizeof(*ret->fh_akm_suites));
        if (ret->fh_akm_suites == NULL) {
            PARSE_FREE_RET_RETURN(akm_suite_cap)
        }

        for (i = 0; i < ret->fh_akm_suites_nr; i++) {
            _E1B(&p, &ret->fh_akm_suites[i].oui[0]);
            _E1B(&p, &ret->fh_akm_suites[i].oui[1]);
            _E1B(&p, &ret->fh_akm_suites[i].oui[2]);
            _E1B(&p, &ret->fh_akm_suites[i].akm_suite_type);
        }
    }

    PARSE_CHECK_INTEGRITY(akm_suite_cap)
    PARSE_RETURN
}

static uint8_t* forge_akm_suite_cap_tlv(void *memory_structure, uint16_t *len)
{
    map_akm_suite_cap_tlv_t *m = memory_structure;
    uint8_t  *ret, *p, i;

    /* Calculate TLV length */
    uint16_t tlv_length = 2; /* bh_akm_suites_nr + fh_akm_suites_nr */
    tlv_length += m->bh_akm_suites_nr * sizeof(map_akm_suite_t);
    tlv_length += m->fh_akm_suites_nr * sizeof(map_akm_suite_t);

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,              &p);
    _I2B(&tlv_length,               &p);

    _I1B(&m->bh_akm_suites_nr,      &p);
    for (i = 0; i < m->bh_akm_suites_nr; i++) {
        _I1B(&m->bh_akm_suites[i].oui[0],           &p);
        _I1B(&m->bh_akm_suites[i].oui[1],           &p);
        _I1B(&m->bh_akm_suites[i].oui[2],           &p);
        _I1B(&m->bh_akm_suites[i].akm_suite_type,   &p);
    }

    _I1B(&m->fh_akm_suites_nr,      &p);
    for (i = 0; i < m->fh_akm_suites_nr; i++) {
        _I1B(&m->fh_akm_suites[i].oui[0],           &p);
        _I1B(&m->fh_akm_suites[i].oui[1],           &p);
        _I1B(&m->fh_akm_suites[i].oui[2],           &p);
        _I1B(&m->fh_akm_suites[i].akm_suite_type,   &p);
    }

    FORGE_RETURN
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
void map_r3_register_tlvs(void)
{
    I1905_REGISTER_TLV(TLV_TYPE_1905_LAYER_SECURITY_CAPABILITY,     1905_security_cap        );
    I1905_REGISTER_TLV(TLV_TYPE_MIC,                                mic                      );
    I1905_REGISTER_TLV(TLV_TYPE_ENCRYPTED_PAYLOAD,                  encrypted_payload        );
    I1905_REGISTER_TLV(TLV_TYPE_AP_WIFI6_CAPABILITIES,              ap_wifi6_cap             );
    I1905_REGISTER_TLV(TLV_TYPE_ASSOCIATED_WIFI6_STA_STATUS_REPORT, assoc_wifi6_sta_status   );
    I1905_REGISTER_TLV(TLV_TYPE_BSSID,                              bssid                    );
    I1905_REGISTER_TLV(TLV_TYPE_1905_ENCAP_DPP,                     1905_encap_dpp           );
    I1905_REGISTER_TLV(TLV_TYPE_1905_ENCAP_EAPOL,                   1905_encap_eapol         );
    I1905_REGISTER_TLV(TLV_TYPE_DPP_MESSAGE,                        dpp_message              );
    I1905_REGISTER_TLV(TLV_TYPE_DPP_CCE_INDICATION,                 dpp_cce_indication       );
    I1905_REGISTER_TLV(TLV_TYPE_DPP_CHIRP_VALUE,                    dpp_chirp_value          );
    I1905_REGISTER_TLV(TLV_TYPE_DEVICE_INVENTORY,                   device_inventory         );
    I1905_REGISTER_TLV(TLV_TYPE_BSS_CONFIGURATION_REQUEST,          bss_configuration_request);
    I1905_REGISTER_TLV(TLV_TYPE_BSS_CONFIGURATION_REPORT,           bss_configuration_report );
    I1905_REGISTER_TLV(TLV_TYPE_AGENT_LIST,                         agent_list               );
    I1905_REGISTER_TLV(TLV_TYPE_AKM_SUITE_CAPABILITIES,             akm_suite_cap            );
}
