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
# Supported service TLV ("Section 17.2.1")                              #
########################################################################*/
TLV_FREE_FUNCTION(supported_service) {}

static uint8_t* parse_supported_service_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_supported_service_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_MIN_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_SUPPORTED_SERVICE;

    _E1B(&p, &ret->services_nr);
    PARSE_LIMIT(ret->services_nr, MAX_SERVICE)
    _EnB(&p, ret->services, ret->services_nr);

    PARSE_CHECK_INTEGRITY(supported_service)
    PARSE_RETURN
}

static uint8_t* forge_supported_service_tlv(void *memory_structure, uint16_t *len)
{
    map_supported_service_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 1 + m->services_nr;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,    &p);
    _I2B(&tlv_length,     &p);
    _I1B(&m->services_nr, &p);
    _InB(m->services,     &p, m->services_nr);

    FORGE_RETURN
}

/*#######################################################################
# Searched service TLV ("Section 17.2.2")                               #
########################################################################*/
TLV_FREE_FUNCTION(searched_service) {}

static uint8_t* parse_searched_service_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_searched_service_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_MIN_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_SEARCHED_SERVICE;

    _E1B(&p, &ret->services_nr);
    PARSE_LIMIT(ret->services_nr, MAX_SERVICE)
    _EnB(&p, ret->services, ret->services_nr);

    PARSE_CHECK_INTEGRITY(searched_service)
    PARSE_RETURN
}

static uint8_t* forge_searched_service_tlv(void *memory_structure, uint16_t *len)
{
    map_searched_service_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 1 + m->services_nr;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,    &p);
    _I2B(&tlv_length,     &p);
    _I1B(&m->services_nr, &p);
    _InB(m->services,     &p, m->services_nr);

    FORGE_RETURN
}

/*#######################################################################
# AP radio identifier TLV ("Section 17.2.3")                            #
########################################################################*/
TLV_FREE_FUNCTION(ap_radio_identifier) {}

static uint8_t* parse_ap_radio_identifier_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_ap_radio_identifier_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_EXP_LEN(6)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_AP_RADIO_IDENTIFIER;

    _EnB(&p, ret->radio_id, 6);

    PARSE_CHECK_INTEGRITY(ap_radio_identifier)
    PARSE_RETURN
}

static uint8_t* forge_ap_radio_identifier_tlv(void *memory_structure, uint16_t *len)
{
    map_ap_radio_identifier_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 6;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _InB(m->radio_id,  &p, 6);

    FORGE_RETURN
}

/*#######################################################################
# AP operational BSS TLV ("Section 17.2.4")                             #
########################################################################*/
TLV_FREE_FUNCTION(ap_operational_bss) {}

static uint8_t* parse_ap_operational_bss_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_ap_operational_bss_tlv_t *ret;
    uint8_t *p = packet_stream, i, j;

    PARSE_CHECK_MIN_LEN(1);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_AP_OPERATIONAL_BSS;

    _E1B(&p, &ret->radios_nr);
    PARSE_LIMIT(ret->radios_nr, MAX_RADIO_PER_AGENT)

    for (i = 0; i < ret->radios_nr; i++) {
        _EnB(&p, ret->radios[i].radio_id, 6);
        _E1B(&p, &ret->radios[i].bsss_nr);
        PARSE_LIMIT(ret->radios[i].bsss_nr, MAX_BSS_PER_RADIO)

        for (j = 0; j < ret->radios[i].bsss_nr; j++) {
            _EnB(&p, ret->radios[i].bsss[j].bssid, 6);
            _E1B(&p, &ret->radios[i].bsss[j].ssid_len);
            PARSE_LIMIT_N_DROP(ap_operational_bss, ret->radios[i].bsss[j].ssid_len, (MAX_SSID_LEN - 1))

            _EnB(&p, ret->radios[i].bsss[j].ssid, ret->radios[i].bsss[j].ssid_len);
        }
    }

    PARSE_CHECK_INTEGRITY(ap_operational_bss)
    PARSE_RETURN
}

static uint8_t* forge_ap_operational_bss_tlv(void *memory_structure, uint16_t *len)
{
    map_ap_operational_bss_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i, j;

    tlv_length = 1;  /* no_of_radio */
    for (i = 0; i < m->radios_nr; i++) {
        tlv_length += 6 + 1; /* radio_id + bsss_nr */
        for (j = 0; j < m->radios[i].bsss_nr; j++) {
            tlv_length += 6 + 1 + m->radios[i].bsss[j].ssid_len; /* bssid + ssid_len + ssid */
        }
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,  &p);
    _I2B(&tlv_length,   &p);
    _I1B(&m->radios_nr, &p);

    for (i=0; i< m->radios_nr; i++) {
        _InB(m->radios[i].radio_id,  &p, 6);
        _I1B(&m->radios[i].bsss_nr,  &p);

        for (j = 0; j < m->radios[i].bsss_nr; j++) {
            _InB(m->radios[i].bsss[j].bssid,     &p, 6);
            _I1B(&m->radios[i].bsss[j].ssid_len, &p);
            _InB(m->radios[i].bsss[j].ssid,      &p, m->radios[i].bsss[j].ssid_len);
        }
    }

    FORGE_RETURN
}

/*#######################################################################
# Associated clients TLV ("Section 17.2.5")                             #
########################################################################*/
TLV_FREE_FUNCTION(assoc_clients)
{
    uint8_t i;

    for (i = 0; i < m->bsss_nr; i++) {
        SFREE(m->bsss[i].stas);
    }
}

static uint8_t* parse_assoc_clients_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_assoc_clients_tlv_t *ret;
    uint8_t *p = packet_stream, i, j;

    PARSE_CHECK_MIN_LEN(1);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_ASSOCIATED_CLIENTS;

    _E1B(&p, &ret->bsss_nr);
    PARSE_LIMIT(ret->bsss_nr, MAX_BSS_PER_RADIO)

    for (i = 0; i < ret->bsss_nr; i++) {
       _EnB(&p, ret->bsss[i].bssid, 6);
       _E2B(&p, &ret->bsss[i].stas_nr);
        PARSE_LIMIT(ret->bsss[i].stas_nr, MAX_STATION_PER_BSS)

        if ((ret->bsss[i].stas = calloc(ret->bsss[i].stas_nr, sizeof(*ret->bsss[i].stas)))) {
           for(j = 0; j < ret->bsss[i].stas_nr; j++) {
               _EnB(&p, ret->bsss[i].stas[j].mac, 6);
               _E2B(&p, &ret->bsss[i].stas[j].assoc_time);
           }
       } else {
           ret->bsss[i].stas_nr = 0;
       }
    }

    PARSE_CHECK_INTEGRITY(assoc_clients)
    PARSE_RETURN
}

static uint8_t* forge_assoc_clients_tlv(void *memory_structure, uint16_t *len)
{
    map_assoc_clients_tlv_t *m = memory_structure;
    uint16_t  i, j, tlv_length;
    uint8_t  *ret, *p;

    tlv_length = 1; /* bsss_nr */
    for (i = 0; i < m->bsss_nr; i++) {
        tlv_length += 6 + 2;                        /* bssid + no_of_sta */
        tlv_length += m->bsss[i].stas_nr * (6 + 2); /* sta_mac + assoc_time */
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _I1B(&m->bsss_nr,  &p);

    for (i = 0; i < m->bsss_nr; i++) {
       _InB(m->bsss[i].bssid,    &p, 6);
       _I2B(&m->bsss[i].stas_nr, &p);

       for(j = 0; j < m->bsss[i].stas_nr; j++) {
           _InB(m->bsss[i].stas[j].mac,         &p, 6);
           _I2B(&m->bsss[i].stas[j].assoc_time, &p);
       }
    }

    FORGE_RETURN
}

/*#######################################################################
# AP capability TLV ("Section 17.2.6")                                  #
########################################################################*/
TLV_FREE_FUNCTION(ap_cap) {}

static uint8_t* parse_ap_cap_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_ap_cap_tlv_t *ret;
    uint8_t *p = packet_stream, byte;

    PARSE_CHECK_EXP_LEN(1);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_AP_CAPABILITY;

    _E1B(&p,&byte);
    ret->operating_unsupported_link_metrics     = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;
    ret->non_operating_unsupported_link_metrics = (byte & BIT_MASK_6) ? SET_BIT : RESET_BIT;
    ret->agent_initiated_steering               = (byte & BIT_MASK_5) ? SET_BIT : RESET_BIT;
    ret->reserved                               = byte & (BIT_MASK_4 | BIT_MASK_3 | BIT_MASK_2 | BIT_MASK_1 | BIT_MASK_0);

    PARSE_CHECK_INTEGRITY(ap_cap)
    PARSE_RETURN
}

static uint8_t* forge_ap_cap_tlv(void *memory_structure, uint16_t *len)
{
    map_ap_cap_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 1;
    uint8_t  *ret, *p, byte;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,&p);
    _I2B(&tlv_length, &p);

    byte = ((m->operating_unsupported_link_metrics     << BIT_SHIFT_7) |
            (m->non_operating_unsupported_link_metrics << BIT_SHIFT_6) |
            (m->agent_initiated_steering               << BIT_SHIFT_5) | m->reserved);
    _I1B(&byte, &p);

    FORGE_RETURN
}

/*#######################################################################
# AP radio basic capabilities TLV ("Section 17.2.7")                    #
########################################################################*/
TLV_FREE_FUNCTION(ap_radio_basic_cap) {}

static uint8_t* parse_ap_radio_basic_cap_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_ap_radio_basic_cap_tlv_t *ret;
    uint8_t i, j, channels_nr, channel;
    uint8_t *p = packet_stream;

    PARSE_CHECK_MIN_LEN(6 + 1); /* radio_id + max_bss */

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_AP_RADIO_BASIC_CAPABILITIES;

    _EnB(&p, ret->radio_id, 6);
    _E1B(&p, &ret->max_bss);
    _E1B(&p, &ret->op_classes_nr);
    PARSE_LIMIT(ret->op_classes_nr, MAX_OP_CLASS);

    for (i = 0; i < ret->op_classes_nr; i++) {
        _E1B(&p, &ret->op_classes[i].op_class);
        _E1B(&p, &ret->op_classes[i].eirp);
        _E1B(&p, &channels_nr);
        PARSE_LIMIT(channels_nr, MAX_CHANNEL_PER_OP_CLASS);

        for (j = 0; j < channels_nr; j++) {
            _E1B(&p, &channel);
            map_cs_set(&ret->op_classes[i].channels, channel);
        }
    }

    PARSE_CHECK_INTEGRITY(ap_radio_basic_cap)
    PARSE_RETURN
}

static uint8_t* forge_ap_radio_basic_cap_tlv(void *memory_structure, uint16_t *len)
{
    map_ap_radio_basic_cap_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i, channels_nr, channel;

    tlv_length = 6 + 1 + 1; /* radio_id + max_bss + op_classes_nr */
    for (i = 0; i < m->op_classes_nr; i++) {
        tlv_length += 1 + 1 + 1 + map_cs_nr(&m->op_classes[i].channels); /* op_class + eirp + channels_nr + channels */
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,      &p);
    _I2B(&tlv_length,       &p);
    _InB(m->radio_id,       &p, 6);
    _I1B(&m->max_bss,       &p);
    _I1B(&m->op_classes_nr, &p);

    for (i=0; i <m->op_classes_nr; i++) {
        channels_nr = map_cs_nr(&m->op_classes[i].channels);

        _I1B(&m->op_classes[i].op_class, &p);
        _I1B(&m->op_classes[i].eirp,     &p);
        _I1B(&channels_nr,               &p);
        map_cs_foreach(&m->op_classes[i].channels, channel) {
            _I1B(&channel, &p);
        }
    }

    FORGE_RETURN
}

/*#######################################################################
# AP HT capabilities TLV ("Section 17.2.8")                             #
########################################################################*/
TLV_FREE_FUNCTION(ap_ht_cap) {}

static uint8_t* parse_ap_ht_cap_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_ap_ht_cap_tlv_t *ret;
    uint8_t *p = packet_stream, byte;

    PARSE_CHECK_EXP_LEN(7);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_AP_HT_CAPABILITIES;

    _EnB(&p, ret->radio_id, ETHER_ADDR_LEN);
    _E1B(&p, &byte);

    ret->max_supported_tx_streams = (byte & (BIT_MASK_7 | BIT_MASK_6)) >> BIT_SHIFT_6;
    ret->max_supported_rx_streams = (byte & (BIT_MASK_5 | BIT_MASK_4)) >> BIT_SHIFT_4;
    ret->gi_support_20mhz         = (byte & BIT_MASK_3) ? SET_BIT : RESET_BIT;
    ret->gi_support_40mhz         = (byte & BIT_MASK_2) ? SET_BIT : RESET_BIT;
    ret->ht_support_40mhz         = (byte & BIT_MASK_1) ? SET_BIT : RESET_BIT;
    ret->reserved                 = (byte & BIT_MASK_0) ? SET_BIT : RESET_BIT;

    PARSE_CHECK_INTEGRITY(ap_ht_cap)
    PARSE_RETURN
}

static uint8_t* forge_ap_ht_cap_tlv(void *memory_structure, uint16_t *len)
{
    map_ap_ht_cap_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 7;
    uint8_t  *ret, *p, byte;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type ,&p);
    _I2B(&tlv_length,  &p);
    _InB(&m->radio_id, &p,ETHER_ADDR_LEN);

    byte = ((m->max_supported_tx_streams << BIT_SHIFT_6) |
            (m->max_supported_rx_streams << BIT_SHIFT_4) |
            (m->gi_support_20mhz << BIT_SHIFT_3) |
            (m->gi_support_40mhz << BIT_SHIFT_2) |
            (m->ht_support_40mhz << BIT_SHIFT_1) |
            m->reserved);

    _I1B(&byte,&p);

    FORGE_RETURN
}

/*#######################################################################
# AP VHT capabilities TLV ("Section 17.2.9")                            #
########################################################################*/
TLV_FREE_FUNCTION(ap_vht_cap) {}

static uint8_t* parse_ap_vht_cap_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_ap_vht_cap_tlv_t *ret;
    uint8_t *p = packet_stream, byte;

    PARSE_CHECK_EXP_LEN(12);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_AP_VHT_CAPABILITIES;

    _EnB(&p, ret->radio_id, ETHER_ADDR_LEN);
    _E2B(&p, &ret->supported_tx_mcs);
    _E2B(&p, &ret->supported_rx_mcs);

    _E1B(&p, &byte);
    ret->max_supported_tx_streams = (byte & (BIT_MASK_7 | BIT_MASK_6 | BIT_MASK_5)) >> BIT_SHIFT_5;
    ret->max_supported_rx_streams = (byte & (BIT_MASK_4 | BIT_MASK_3 | BIT_MASK_2)) >> BIT_SHIFT_2;
    ret->gi_support_80mhz         = (byte & BIT_MASK_1) ? SET_BIT : RESET_BIT;
    ret->gi_support_160mhz        = (byte & BIT_MASK_0) ? SET_BIT : RESET_BIT;

     _E1B(&p, &byte);
    ret->support_80_80_mhz        = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;
    ret->support_160mhz           = (byte & BIT_MASK_6) ? SET_BIT : RESET_BIT;
    ret->su_beamformer_capable    = (byte & BIT_MASK_5) ? SET_BIT : RESET_BIT;
    ret->mu_beamformer_capable    = (byte & BIT_MASK_4) ? SET_BIT : RESET_BIT;
    ret->reserved                 = byte & (BIT_MASK_3 | BIT_MASK_2 | BIT_MASK_1 | BIT_MASK_0);

    PARSE_CHECK_INTEGRITY(ap_vht_cap)
    PARSE_RETURN
}

static uint8_t* forge_ap_vht_cap_tlv(void *memory_structure, uint16_t *len)
{
    map_ap_vht_cap_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 12;
    uint8_t  *ret, *p, byte;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,         &p);
    _I2B(&tlv_length,          &p);
    _InB(&m->radio_id,         &p, 6);
    _I2B(&m->supported_tx_mcs, &p);
    _I2B(&m->supported_rx_mcs, &p);

    byte = ((m->max_supported_tx_streams << BIT_SHIFT_5) |
            (m->max_supported_rx_streams << BIT_SHIFT_2) |
            (m->gi_support_80mhz << BIT_SHIFT_1) |
            m->gi_support_160mhz);
    _I1B(&byte,&p);

    byte = ((m->support_80_80_mhz << BIT_SHIFT_7) |
            (m->support_160mhz << BIT_SHIFT_6) |
            (m->su_beamformer_capable << BIT_SHIFT_5) |
            (m->mu_beamformer_capable << BIT_SHIFT_4) |
            m->reserved);
    _I1B(&byte,&p);

    FORGE_RETURN
}

/*#######################################################################
# AP HE capabilities TLV ("Section 17.2.10")                            #
########################################################################*/
TLV_FREE_FUNCTION(ap_he_cap) {}

static uint8_t* parse_ap_he_cap_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_ap_he_cap_tlv_t *ret;
    uint8_t *p = packet_stream, i, byte;

    PARSE_CHECK_MIN_LEN(9) /* All fields except supported mcs */

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_AP_HE_CAPABILITIES;

    _EnB(&p,  ret->radio_id, ETHER_ADDR_LEN);
    _E1B(&p, &ret->supported_mcs_length);
    PARSE_LIMIT(ret->supported_mcs_length, 2 * MAX_MCS);

    for (i = 0; i < ret->supported_mcs_length / 2; i++) {
        _E2B(&p, &ret->supported_tx_rx_mcs[i]);
    }

    _E1B(&p, &byte);
    ret->max_supported_tx_streams = (byte & (BIT_MASK_7 | BIT_MASK_6 | BIT_MASK_5)) >> BIT_SHIFT_5;
    ret->max_supported_rx_streams = (byte & (BIT_MASK_4 | BIT_MASK_3 | BIT_MASK_2)) >> BIT_SHIFT_2;
    ret->support_80_80_mhz        = (byte & BIT_MASK_1) ? SET_BIT : RESET_BIT;
    ret->support_160mhz           = (byte & BIT_MASK_0) ? SET_BIT : RESET_BIT;

    _E1B(&p, &byte);
    ret->su_beamformer_capable = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;
    ret->mu_beamformer_capable = (byte & BIT_MASK_6) ? SET_BIT : RESET_BIT;
    ret->ul_mimo_capable       = (byte & BIT_MASK_5) ? SET_BIT : RESET_BIT;
    ret->ul_mimo_ofdma_capable = (byte & BIT_MASK_4) ? SET_BIT : RESET_BIT;
    ret->dl_mimo_ofdma_capable = (byte & BIT_MASK_3) ? SET_BIT : RESET_BIT;
    ret->ul_ofdma_capable      = (byte & BIT_MASK_2) ? SET_BIT : RESET_BIT;
    ret->dl_ofdma_capable      = (byte & BIT_MASK_1) ? SET_BIT : RESET_BIT;
    ret->reserved              = (byte & BIT_MASK_0) ? SET_BIT : RESET_BIT;

    PARSE_CHECK_INTEGRITY(ap_he_cap)
    PARSE_RETURN
}

static uint8_t* forge_ap_he_cap_tlv(void *memory_structure, uint16_t *len)
{
    map_ap_he_cap_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 9 + m->supported_mcs_length;
    uint8_t  *ret, *p, i, byte;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,             &p);
    _I2B(&tlv_length,              &p);
    _InB(&m->radio_id,             &p, 6);
    _I1B(&m->supported_mcs_length, &p);

    for (i = 0; i < m->supported_mcs_length / 2; i++) {
        _I2B(&m->supported_tx_rx_mcs[i], &p);
    }

    byte = ((m->max_supported_tx_streams << BIT_SHIFT_5) |
            (m->max_supported_rx_streams << BIT_SHIFT_2) |
            (m->support_80_80_mhz << BIT_SHIFT_1) |
            m->support_160mhz);
    _I1B(&byte,&p);

    byte = ((m->su_beamformer_capable << BIT_SHIFT_7) |
            (m->mu_beamformer_capable << BIT_SHIFT_6) |
            (m->ul_mimo_capable << BIT_SHIFT_5) |
            (m->ul_mimo_ofdma_capable << BIT_SHIFT_4) |
            (m->dl_mimo_ofdma_capable << BIT_SHIFT_3) |
            (m->ul_ofdma_capable << BIT_SHIFT_2) |
            (m->dl_ofdma_capable << BIT_SHIFT_1) |
            m->reserved);
    _I1B(&byte,&p);

    FORGE_RETURN
}

/*#######################################################################
# Steering policy TLV ("Section 17.2.11")                               #
########################################################################*/
TLV_FREE_FUNCTION(steering_policy)
{
    SFREE(m->local_steering_dis_macs);
    SFREE(m->btm_steering_dis_macs);
}

static uint8_t* parse_steering_policy_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_steering_policy_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    PARSE_CHECK_MIN_LEN(3)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_STEERING_POLICY;

    _E1B(&p, &ret->local_steering_dis_macs_nr);
    if (ret->local_steering_dis_macs_nr > 0) {
        ret->local_steering_dis_macs = calloc(ret->local_steering_dis_macs_nr, sizeof(*ret->local_steering_dis_macs));
        if (NULL == ret->local_steering_dis_macs) {
            PARSE_FREE_RET_RETURN(steering_policy)
        }
        for (i = 0; i < ret->local_steering_dis_macs_nr; i++) {
            _EnB(&p, ret->local_steering_dis_macs[i], 6);
        }
    }

    _E1B(&p, &ret->btm_steering_dis_macs_nr);
    if (ret->btm_steering_dis_macs_nr > 0) {
        ret->btm_steering_dis_macs = calloc(ret->btm_steering_dis_macs_nr, sizeof(*ret->btm_steering_dis_macs));
        if (NULL == ret->btm_steering_dis_macs) {
            PARSE_FREE_RET_RETURN(steering_policy)
        }
        for (i = 0; i < ret->btm_steering_dis_macs_nr; i++) {
            _EnB(&p, ret->btm_steering_dis_macs[i], 6);
        }
    }

    _E1B(&p, &ret->radios_nr);
    PARSE_LIMIT(ret->radios_nr, MAX_RADIO_PER_AGENT);
    for (i = 0; i < ret->radios_nr; i++) {
        _EnB(&p, &ret->radios[i].radio_id, 6);
        _E1B(&p, &ret->radios[i].steering_policy);
        _E1B(&p, &ret->radios[i].channel_utilization_threshold);
        _E1B(&p, &ret->radios[i].rssi_steering_threshold);
    }

    PARSE_CHECK_INTEGRITY(steering_policy)
    PARSE_RETURN
}

static uint8_t* forge_steering_policy_tlv(void *memory_structure, uint16_t *len)
{
    map_steering_policy_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i;

    /* Calculate TLV length */
    tlv_length = 1 + 1 + 1; /* steering_dis_nr + btm_dis_nr + radios_nr */
    tlv_length += m->local_steering_dis_macs_nr * 6;
    tlv_length += m->btm_steering_dis_macs_nr * 6;
    tlv_length += m->radios_nr * (6 + 1 + 1 + 1); /* radio_id + policy + channel_th + steering_th */

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,                   &p);
    _I2B(&tlv_length,                    &p);
    _I1B(&m->local_steering_dis_macs_nr, &p);

    for (i = 0; i < m->local_steering_dis_macs_nr; i++) {
        _InB(m->local_steering_dis_macs[i], &p, 6);
    }

    _I1B(&m->btm_steering_dis_macs_nr, &p);
    for (i = 0; i < m->btm_steering_dis_macs_nr; i++) {
        _InB(m->btm_steering_dis_macs[i], &p, 6);
    }

    _I1B(&m->radios_nr, &p);
    for (i = 0; i < m->radios_nr; i++) {
        _InB(m->radios[i].radio_id,                       &p, 6);
        _I1B(&m->radios[i].steering_policy,               &p);
        _I1B(&m->radios[i].channel_utilization_threshold, &p);
        _I1B(&m->radios[i].rssi_steering_threshold,       &p);
    }

    FORGE_RETURN
}

/*#######################################################################
# Metric reporting policy TLV ("Section 17.2.12")                       #
########################################################################*/
TLV_FREE_FUNCTION(metric_reporting_policy) {}

static uint8_t* parse_metric_reporting_policy_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_metric_reporting_policy_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    PARSE_CHECK_MIN_LEN(2)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_METRIC_REPORTING_POLICY;

    _E1B(&p, &ret->metric_reporting_interval);
    _E1B(&p, &ret->radios_nr);
    PARSE_LIMIT(ret->radios_nr, MAX_RADIO_PER_AGENT);

    for (i = 0; i < ret->radios_nr; i++) {
        _EnB(&p, &ret->radios[i].radio_id, 6);
        _E1B(&p, &ret->radios[i].reporting_rssi_threshold);
        _E1B(&p, &ret->radios[i].reporting_rssi_margin_override);
        _E1B(&p, &ret->radios[i].channel_utilization_reporting_threshold);
        _E1B(&p, &ret->radios[i].associated_sta_policy);
    }

    PARSE_CHECK_INTEGRITY(metric_reporting_policy)
    PARSE_RETURN
}

static uint8_t* forge_metric_reporting_policy_tlv(void *memory_structure, uint16_t *len)
{
    map_metric_reporting_policy_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 2 + m->radios_nr * (6 + 1 + 1 + 1 + 1);
    uint8_t  *ret, *p, i;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,                  &p);
    _I2B(&tlv_length,                   &p);
    _I1B(&m->metric_reporting_interval, &p);
    _I1B(&m->radios_nr,                 &p);

    for (i = 0;  i <m->radios_nr; i++) {
        _InB(m->radios[i].radio_id,                                 &p, 6);
        _I1B(&m->radios[i].reporting_rssi_threshold,                &p);
        _I1B(&m->radios[i].reporting_rssi_margin_override,          &p);
        _I1B(&m->radios[i].channel_utilization_reporting_threshold, &p);
        _I1B(&m->radios[i].associated_sta_policy,                   &p);
    }

    FORGE_RETURN
}

/*#######################################################################
# Channel preference TLV ("Section 17.2.13")                            #
########################################################################*/
TLV_FREE_FUNCTION(channel_preference) {}

static uint8_t* parse_channel_preference_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_channel_preference_tlv_t *ret;
    uint8_t i, j, byte, channels_nr, channel;
    uint8_t *p = packet_stream;

    PARSE_CHECK_MIN_LEN(7)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_CHANNEL_PREFERENCE;

    _EnB(&p, ret->radio_id, 6);
    _E1B(&p, &ret->op_classes_nr);
    PARSE_LIMIT(ret->op_classes_nr, MAX_OP_CLASS);

    for (i = 0; i < ret->op_classes_nr; i++) {
        _E1B(&p, &ret->op_classes[i].op_class);
        _E1B(&p, &channels_nr);
        PARSE_LIMIT(channels_nr, MAX_CHANNEL_PER_OP_CLASS);

        for (j = 0; j < channels_nr; j++) {
            _E1B(&p, &channel);
            map_cs_set(&ret->op_classes[i].channels, channel);
        }

        _E1B(&p, &byte);
        ret->op_classes[i].pref   = (byte & (BIT_MASK_7 | BIT_MASK_6 | BIT_MASK_5 | BIT_MASK_4)) >> BIT_SHIFT_4;
        ret->op_classes[i].reason = (byte & (BIT_MASK_3 | BIT_MASK_2 | BIT_MASK_1 | BIT_MASK_0));
    }

    PARSE_CHECK_INTEGRITY(channel_preference)
    PARSE_RETURN
}

static uint8_t* forge_channel_preference_tlv(void *memory_structure, uint16_t *len)
{
    map_channel_preference_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i, byte, channels_nr, channel;

    /* Calculate TLV length */
    tlv_length = 6 + 1; /* radio_id + op_classes_nr */
    for (i = 0; i < m->op_classes_nr; i++) {
        tlv_length += 1 + 1 + map_cs_nr(&m->op_classes[i].channels) + 1; /* op_class, channels_nr, channels, pref_reason */
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,      &p);
    _I2B(&tlv_length,       &p);
    _InB(m->radio_id,       &p, 6);
    _I1B(&m->op_classes_nr, &p);

    for (i = 0; i < m->op_classes_nr; i++) {
        channels_nr = map_cs_nr(&m->op_classes[i].channels);

        _I1B(&m->op_classes[i].op_class, &p);
        _I1B(&channels_nr,               &p);
        map_cs_foreach(&m->op_classes[i].channels, channel) {
            _I1B(&channel, &p);
        }

        byte = (m->op_classes[i].pref << BIT_SHIFT_4) | m->op_classes[i].reason;
        _I1B(&byte, &p);
    }

    FORGE_RETURN
}

/*#######################################################################
# Radio operation restriction TLV ("Section 17.2.14")                   #
########################################################################*/
TLV_FREE_FUNCTION(radio_operation_restriction) {}

static uint8_t* parse_radio_operation_restriction_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_radio_operation_restriction_tlv_t *ret;
    uint8_t *p = packet_stream, i, j;

    PARSE_CHECK_MIN_LEN(7)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_RADIO_OPERATION_RESTRICTION;

    _EnB(&p, ret->radio_id, 6);
    _E1B(&p, &ret->op_classes_nr);
    PARSE_LIMIT(ret->op_classes_nr, MAX_OP_CLASS);

    for (i = 0; i < ret->op_classes_nr; i++) {
        _E1B(&p, &ret->op_classes[i].op_class);
        _E1B(&p, &ret->op_classes[i].channels_nr);
        PARSE_LIMIT(ret->op_classes[i].channels_nr, MAX_CHANNEL_PER_OP_CLASS);

        for(j = 0; j < ret->op_classes[i].channels_nr; j++) {
            _E1B(&p,&ret->op_classes[i].channels[j].channel);
            _E1B(&p,&ret->op_classes[i].channels[j].freq_restriction);
        }
    }

    PARSE_CHECK_INTEGRITY(radio_operation_restriction)
    PARSE_RETURN
}

static uint8_t* forge_radio_operation_restriction_tlv(void *memory_structure, uint16_t *len)
{
    map_radio_operation_restriction_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i, j;

    /* Calculate TLV length */
    tlv_length = 6 + 1; /* radio_id + opclasses_nr */
    for (i = 0; i < m->op_classes_nr; i++) {
        tlv_length += 1 + 1 + m->op_classes[i].channels_nr * (1 + 1); /* op_class + channels_nr + channels * (channel + freq_restrict) */
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,      &p);
    _I2B(&tlv_length,       &p);
    _InB(m->radio_id,       &p, 6);
    _I1B(&m->op_classes_nr, &p);

    for (i = 0; i < m->op_classes_nr; i++) {
        _I1B(&m->op_classes[i].op_class,    &p);
        _I1B(&m->op_classes[i].channels_nr, &p);

        for (j = 0; j < m->op_classes[i].channels_nr; j++) {
            _I1B(&m->op_classes[i].channels[j].channel,          &p);
            _I1B(&m->op_classes[i].channels[j].freq_restriction, &p);
        }
    }

    FORGE_RETURN
}

/*#######################################################################
# Transmit power limit TLV ("Section 17.2.15")                          #
########################################################################*/
TLV_FREE_FUNCTION(transmit_power_limit) {}

static uint8_t* parse_transmit_power_limit_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_transmit_power_limit_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_EXP_LEN(7)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_TRANSMIT_POWER_LIMIT;

    _EnB(&p, ret->radio_id, 6);
    _E1B(&p, &ret->transmit_power_eirp);

    PARSE_CHECK_INTEGRITY(transmit_power_limit)
    PARSE_RETURN
}

static uint8_t* forge_transmit_power_limit_tlv(void *memory_structure, uint16_t *len)
{
    map_transmit_power_limit_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 7;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,            &p);
    _I2B(&tlv_length,             &p);
    _InB(m->radio_id,             &p, 6);
    _I1B(&m->transmit_power_eirp, &p);

    FORGE_RETURN
}

/*#######################################################################
# Channel selection response TLV ("Section 17.2.16")                    #
########################################################################*/
TLV_FREE_FUNCTION(channel_selection_response) {}

static uint8_t* parse_channel_selection_response_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_channel_selection_response_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_EXP_LEN(7)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_CHANNEL_SELECTION_RESPONSE;

    _EnB(&p, ret->radio_id, 6);
    _E1B(&p, &ret->channel_selection_response);

    PARSE_CHECK_INTEGRITY(channel_selection_response)
    PARSE_RETURN
}

static uint8_t* forge_channel_selection_response_tlv(void *memory_structure, uint16_t *len)
{
    map_channel_selection_response_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 7;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,                   &p);
    _I2B(&tlv_length,                    &p);
    _InB(m->radio_id,                    &p, 6);
    _I1B(&m->channel_selection_response, &p);

    FORGE_RETURN
}

/*#######################################################################
# Operating channel report TLV ("Section 17.2.17")                      #
########################################################################*/
TLV_FREE_FUNCTION(operating_channel_report) {}

static uint8_t* parse_operating_channel_report_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_operating_channel_report_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    PARSE_CHECK_MIN_LEN(7)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_OPERATING_CHANNEL_REPORT;
    _EnB(&p, ret->radio_id, 6);
    _E1B(&p, &ret->op_classes_nr);
    PARSE_LIMIT(ret->op_classes_nr, MAX_OP_CLASS);

    for (i = 0; i < ret->op_classes_nr; i++) {
        _E1B(&p, &ret->op_classes[i].op_class);
        _E1B(&p, &ret->op_classes[i].channel);
    }

    _E1B(&p, &ret->transmit_power_eirp);

    PARSE_CHECK_INTEGRITY(operating_channel_report)
    PARSE_RETURN
}

static uint8_t* forge_operating_channel_report_tlv(void *memory_structure, uint16_t *len)
{
    map_operating_channel_report_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 6 + 1 + m->op_classes_nr * (1 + 1) + 1; /* radio_id + op_classes_nr + op_classes_nr * (op_class + channel) + eirp */
    uint8_t  *ret, *p, i;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,      &p);
    _I2B(&tlv_length,       &p);
    _InB(m->radio_id,       &p, 6);
    _I1B(&m->op_classes_nr, &p);

    for (i=0; i< m->op_classes_nr; i++) {
        _I1B( &m->op_classes[i].op_class, &p);
        _I1B( &m->op_classes[i].channel, &p);
    }

    _I1B(&m->transmit_power_eirp, &p);

    FORGE_RETURN
}

/*#######################################################################
# Client info TLV ("Section 17.2.18")                                   #
########################################################################*/
TLV_FREE_FUNCTION(client_info) {}

static uint8_t* parse_client_info_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_client_info_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_MIN_LEN(12)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_CLIENT_INFO;

    _EnB(&p, ret->bssid,   6);
    _EnB(&p, ret->sta_mac, 6);

    PARSE_CHECK_INTEGRITY(client_info)
    PARSE_RETURN
}

static uint8_t* forge_client_info_tlv(void *memory_structure, uint16_t *len)
{
    map_client_info_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 12;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _InB(&m->bssid,    &p, 6);
    _InB(&m->sta_mac,  &p, 6);

    FORGE_RETURN
}

/*#######################################################################
# Client capability report TLV ("Section 17.2.19")                      #
########################################################################*/
TLV_FREE_FUNCTION(client_cap_report) {}

static uint8_t* parse_client_cap_report_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_client_cap_report_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_MIN_LEN(1)

    /* Allocate ret and frame_body at once */
    ret = calloc(1, sizeof(*ret) + len - 1);
    if (NULL == ret) {
        return NULL;
    }

    ret->tlv_type = TLV_TYPE_CLIENT_CAPABILITY_REPORT;
    _E1B(&p, &ret->result_code);

    if (ret->result_code == MAP_CLIENT_CAP_SUCCESS && len > 1) {
        ret->assoc_frame_body_len = len - 1;
        ret->assoc_frame_body     = (uint8_t *)(ret + 1);
        _EnB(&p, ret->assoc_frame_body, ret->assoc_frame_body_len);
    }

    PARSE_CHECK_INTEGRITY(client_cap_report)
    PARSE_RETURN
}

static uint8_t* forge_client_cap_report_tlv(void *memory_structure, uint16_t *len)
{
    map_client_cap_report_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 1 + m->assoc_frame_body_len;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,    &p);
    _I2B(&tlv_length,     &p);
    _I1B(&m->result_code, &p);
    _InB(m->assoc_frame_body,  &p, m->assoc_frame_body_len);

    FORGE_RETURN
}

/*#######################################################################
# Client association event TLV ("Section 17.2.20")                      #
########################################################################*/
TLV_FREE_FUNCTION(client_assoc_event) {}

static uint8_t* parse_client_assoc_event_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_client_assoc_event_tlv_t *ret;
    uint8_t *p = packet_stream, byte;

    PARSE_CHECK_EXP_LEN(13)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_CLIENT_ASSOCIATION_EVENT;

    _EnB(&p, ret->sta_mac, 6);
    _EnB(&p, ret->bssid, 6);
    _E1B(&p, &byte);
    ret->association_event = (byte & BIT_MASK_7) >> BIT_SHIFT_7;

    PARSE_CHECK_INTEGRITY(client_assoc_event)
    PARSE_RETURN
}

static uint8_t* forge_client_assoc_event_tlv(void *memory_structure, uint16_t *len)
{
    map_client_assoc_event_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 13;
    uint8_t  *ret, *p, byte;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _InB(m->sta_mac,   &p, 6);
    _InB(m->bssid,     &p, 6);

    byte = (m->association_event << BIT_SHIFT_7);
    _I1B(&byte, &p);

    FORGE_RETURN
}

/*#######################################################################
# AP metric query TLV ("Section 17.2.21")                               #
########################################################################*/
TLV_FREE_FUNCTION(ap_metric_query) {}

static uint8_t* parse_ap_metric_query_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_ap_metric_query_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    PARSE_CHECK_MIN_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_AP_METRIC_QUERY;

    _E1B(&p, &ret->bssids_nr);
    PARSE_LIMIT(ret->bssids_nr, MAX_BSS_PER_AGENT);

    for(i = 0; i < ret->bssids_nr; i++) {
        _EnB(&p, ret->bssids[i], 6);
    }

    PARSE_CHECK_INTEGRITY(ap_metric_query)
    PARSE_RETURN
}

static uint8_t* forge_ap_metric_query_tlv(void *memory_structure, uint16_t *len)
{
    map_ap_metric_query_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 1 + m->bssids_nr * 6;
    uint8_t  *ret, *p, i;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,  &p);
    _I2B(&tlv_length,   &p);
    _I1B(&m->bssids_nr, &p);
    for(i = 0; i < m->bssids_nr; i++) {
        _InB(&m->bssids[i], &p, 6);
    }

    FORGE_RETURN
}

/*#######################################################################
# AP metrics TLV ("Section 17.2.22")                                    #
########################################################################*/
TLV_FREE_FUNCTION(ap_metrics) {}

static uint8_t* parse_ap_metrics_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_ap_metrics_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    PARSE_CHECK_MIN_LEN(13)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_AP_METRICS;

    _EnB(&p, ret->bssid, 6);
    _E1B(&p, &ret->channel_util);
    _E2B(&p, &ret->stas_nr);
    _E1B(&p, &ret->esp_present);

    for(i = 0; i<MAX_ACCESS_CATEGORY; i++) {
        if(ret->esp_present & (1 << (7 - i))) {
            _EnB(&p, ret->esp[i].byte_stream, 3);
        }
    }

    PARSE_CHECK_INTEGRITY(ap_metrics)
    PARSE_RETURN
}

static uint8_t* forge_ap_metrics_tlv(void *memory_structure, uint16_t *len)
{
    map_ap_metrics_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i;

    /* Calculate TLV length */
    tlv_length = 6 + 1 + 2 + 1; /* bssid + chan_util + stas_nr + esp_present */
    for(i = 0; i<MAX_ACCESS_CATEGORY; i++) {
        if (m->esp_present & (1 << (7 - i))) {
            tlv_length += 3;
        }
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,     &p);
    _I2B(&tlv_length,      &p);
    _InB(m->bssid,         &p, 6);
    _I1B(&m->channel_util, &p);
    _I2B(&m->stas_nr,      &p);
    _I1B(&m->esp_present,  &p);

    for (i = 0; i < MAX_ACCESS_CATEGORY; i++) {
        if(m->esp_present & (1<<(7-i))) {
             _InB(m->esp[i].byte_stream, &p, 3);
        }
    }

    FORGE_RETURN
}

/*#######################################################################
# STA MAC address TLV ("Section 17.2.23")                               #
########################################################################*/
TLV_FREE_FUNCTION(sta_mac_address) {}

static uint8_t* parse_sta_mac_address_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_sta_mac_address_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_EXP_LEN(6);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_STA_MAC_ADDRESS;

    _EnB(&p, ret->sta_mac, 6);

    PARSE_CHECK_INTEGRITY(sta_mac_address)
    PARSE_RETURN
}

static uint8_t* forge_sta_mac_address_tlv(void *memory_structure, uint16_t *len)
{
    map_sta_mac_address_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 6;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _InB(&m->sta_mac,  &p, 6);

    FORGE_RETURN
}

/*#######################################################################
# Associated STA link metrics TLV ("Section 17.2.24")                   #
########################################################################*/
TLV_FREE_FUNCTION(assoc_sta_link_metrics) {}

static uint8_t* parse_assoc_sta_link_metrics_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_assoc_sta_link_metrics_tlv_t *ret;
    mac_addr mac;
    uint8_t  *p = packet_stream, bsss_nr, i;

    PARSE_CHECK_MIN_LEN(7)

    /* Get bss count to allocate struct and metrics in one time */
    _EnB(&p, &mac, 6);
    _E1B(&p, &bsss_nr);
    PARSE_LIMIT(bsss_nr, MAX_BSS_PER_AGENT);

    ret = calloc(1, sizeof(*ret) + bsss_nr * sizeof(*ret->bsss));
    if (NULL == ret) {
        return 0;
    }

    ret->tlv_type = TLV_TYPE_ASSOCIATED_STA_LINK_METRICS;
    maccpy(ret->sta_mac, mac);
    ret->bsss_nr = bsss_nr;

    for (i = 0; i < ret->bsss_nr; i++) {
        _EnB(&p, &ret->bsss[i].bssid, 6);
        _E4B(&p, &ret->bsss[i].report_time_interval);
        _E4B(&p, &ret->bsss[i].downlink_data_rate);
        _E4B(&p, &ret->bsss[i].uplink_data_rate);
        _E1B(&p, &ret->bsss[i].uplink_rssi);
    }

    PARSE_CHECK_INTEGRITY(assoc_sta_link_metrics)
    PARSE_RETURN
}

static uint8_t* forge_assoc_sta_link_metrics_tlv(void *memory_structure, uint16_t *len)
{
    map_assoc_sta_link_metrics_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 6 + 1 + m->bsss_nr * (6 + 4 + 4 + 4 + 1); /* mac + bsss_nr + bsss_nr * (bssid + interval + dl_rate + ul_rate + ul_rssi */
    uint8_t  *ret, *p, i;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _InB(&m->sta_mac,  &p, 6);
    _I1B(&m->bsss_nr,  &p);

    for (i = 0; i < m->bsss_nr; i++) {
        _InB(&m->bsss[i].bssid,                &p, 6);
        _I4B(&m->bsss[i].report_time_interval, &p);
        _I4B(&m->bsss[i].downlink_data_rate,   &p);
        _I4B(&m->bsss[i].uplink_data_rate,     &p);
        _I1B(&m->bsss[i].uplink_rssi,          &p);
    }

    FORGE_RETURN
}

/*#######################################################################
# Unassociated STA link metrics query TLV ("Section 17.2.25")           #
########################################################################*/
TLV_FREE_FUNCTION(unassoc_sta_link_metrics_query)
{
    uint8_t i;

    for(i = 0; i < m->channels_nr; i++){
        SFREE(m->channels[i].sta_macs);
    }
}

static uint8_t* parse_unassoc_sta_link_metrics_query_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_unassoc_sta_link_metrics_query_tlv_t *ret;
    uint8_t *p = packet_stream, i, j;

    PARSE_CHECK_MIN_LEN(2)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_UNASSOCIATED_STA_LINK_METRICS_QUERY;

    _E1B(&p, &ret->op_class);
    _E1B(&p, &ret->channels_nr);
    PARSE_LIMIT(ret->channels_nr, MAX_CHANNEL_PER_OP_CLASS);

    for(i = 0; i < ret->channels_nr; i++){
        _E1B(&p, &ret->channels[i].channel);
        _E1B(&p, &ret->channels[i].sta_macs_nr);
        ret->channels[i].sta_macs = calloc(ret->channels[i].sta_macs_nr, sizeof(*ret->channels[i].sta_macs));
        if (ret->channels[i].sta_macs) {
            for(j = 0; j < ret->channels[i].sta_macs_nr; j++) {
                _EnB(&p, ret->channels[i].sta_macs[j], 6);
            }
        }
    }

    PARSE_CHECK_INTEGRITY(unassoc_sta_link_metrics_query)
    PARSE_RETURN
}

static uint8_t* forge_unassoc_sta_link_metrics_query_tlv(void *memory_structure, uint16_t *len)
{
    map_unassoc_sta_link_metrics_query_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i, j;

    /* Calculate TLV length */
    tlv_length = 1 + 1; /* op_class + channels_nr */
    for (i = 0; i < m->channels_nr; i++) {
        tlv_length += 1 + 1 + m->channels[i].sta_macs_nr * 6; /* channel + macs_nr + sta_macs */
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,    &p);
    _I2B(&tlv_length,     &p);
    _I1B(&m->op_class,    &p);
    _I1B(&m->channels_nr, &p);

    for(i = 0; i < m->channels_nr; i++){
        _I1B(&m->channels[i].channel, &p);
        _I1B(&m->channels[i].sta_macs_nr, &p);

        for(j = 0; j < m->channels[i].sta_macs_nr; j++) {
            _InB(m->channels[i].sta_macs[j], &p, 6);
        }
    }

    FORGE_RETURN
}

/*#######################################################################
# Unassociated STA link metrics response TLV ("Section 17.2.26")        #
########################################################################*/
TLV_FREE_FUNCTION(unassoc_sta_link_metrics_response) {}

static uint8_t* parse_unassoc_sta_link_metrics_response_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_unassoc_sta_link_metrics_response_tlv_t *ret;
    uint8_t *p = packet_stream, op_class, stas_nr, i;

    PARSE_CHECK_MIN_LEN(2)

    _E1B(&p, &op_class);
    _E1B(&p, &stas_nr);

    /* Allocate tlv struct + metrics */
    ret = calloc(1, sizeof(*ret) + stas_nr * sizeof(*ret->stas));
    if (NULL == ret) {
        return NULL;
    }

    ret->tlv_type = TLV_TYPE_UNASSOCIATED_STA_LINK_METRICS_RESPONSE;
    ret->op_class = op_class;
    ret->stas_nr  = stas_nr;

    for (i = 0; i < ret->stas_nr; i++){
        _EnB(&p, ret->stas[i].mac, 6);
        _E1B(&p, &ret->stas[i].channel);
        _E4B(&p, &ret->stas[i].time_delta);
        _E1B(&p, &ret->stas[i].rcpi_uplink);
    }

    PARSE_CHECK_INTEGRITY(unassoc_sta_link_metrics_response)
    PARSE_RETURN
}

static uint8_t* forge_unassoc_sta_link_metrics_response_tlv(void *memory_structure, uint16_t *len)
{
    map_unassoc_sta_link_metrics_response_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 1 + 1 + m->stas_nr * (6 + 1 + 4 + 1); /* op_class + stas_nr + stas_nr * (mac + channel + time_delta + rcpi) */
    uint8_t  *ret, *p, i;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _I1B(&m->op_class, &p);
    _I1B(&m->stas_nr,  &p);

    for(i = 0; i <m->stas_nr; i++){
        _InB(m->stas[i].mac,          &p, 6);
        _I1B(&m->stas[i].channel,     &p);
        _I4B(&m->stas[i].time_delta,  &p);
        _I1B(&m->stas[i].rcpi_uplink, &p);
    }

    FORGE_RETURN
}

/*#######################################################################
# Beacon metrics query TLV ("Section 17.2.27")                          #
########################################################################*/
TLV_FREE_FUNCTION(beacon_metrics_query) {}

static uint8_t* parse_beacon_metrics_query_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_beacon_metrics_query_tlv_t *ret;
    uint8_t i, j, op_class_channels_nr, channel;
    uint8_t *p = packet_stream;

    PARSE_CHECK_MIN_LEN(18)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_BEACON_METRICS_QUERY;

    _EnB(&p, ret->sta_mac, 6);
    _E1B(&p, &ret->op_class);
    _E1B(&p, &ret->channel);
    _EnB(&p, ret->bssid, 6);
    _E1B(&p, &ret->reporting_detail);
    _E1B(&p, &ret->ssid_len);
    PARSE_LIMIT_N_DROP(beacon_metrics_query, ret->ssid_len, (MAX_SSID_LEN - 1))

    _EnB(&p, ret->ssid, ret->ssid_len);
    _E1B(&p, &ret->ap_channel_reports_nr);
    PARSE_LIMIT(ret->ap_channel_reports_nr, MAX_OP_CLASS);

    for(i = 0; i < ret->ap_channel_reports_nr; i++) {
        _E1B(&p, &op_class_channels_nr);
        if (op_class_channels_nr == 0) {
            free(ret);
            return NULL;
        }
        _E1B(&p, &ret->ap_channel_reports[i].op_class);
        /* Copy channel list - length includes the operating_class byte */
        for (j = 0; j < op_class_channels_nr - 1; j++) {
            _E1B(&p, &channel);
            map_cs_set(&ret->ap_channel_reports[i].channels, channel);
        }
    }

    _E1B(&p, &ret->element_ids_nr);
    _EnB(&p, ret->element_ids, ret->element_ids_nr);

    PARSE_CHECK_INTEGRITY(beacon_metrics_query)
    PARSE_RETURN
}

static uint8_t* forge_beacon_metrics_query_tlv(void *memory_structure, uint16_t *len)
{
    map_beacon_metrics_query_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i, op_class_channels_nr, channel;

    /* Calculate tlv length */
    tlv_length = 6 + 1 + 1 + 6 + 1 + 1 + m->ssid_len + 1; /* sta_mac + op_class + channel + bssid + rep_det + ssid_len + ssid + chan_rep_nr */
    for (i = 0; i < m->ap_channel_reports_nr; i++) {
        tlv_length += 1 + 1 + map_cs_nr(&m->ap_channel_reports[i].channels); /* len + op_class + channels */
    }
    tlv_length += 1 + m->element_ids_nr; /* element_id_nr + element_id */

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,              &p);
    _I2B(&tlv_length,               &p);
    _InB(m->sta_mac,                &p, 6);
    _I1B(&m->op_class,              &p);
    _I1B(&m->channel,               &p);
    _InB(m->bssid,                  &p, 6);
    _I1B(&m->reporting_detail,      &p);
    _I1B(&m->ssid_len,              &p);
    _InB(m->ssid,                   &p, m->ssid_len);
    _I1B(&m->ap_channel_reports_nr, &p);

    for(i = 0; i < m->ap_channel_reports_nr; i++) {
         op_class_channels_nr = map_cs_nr(&m->ap_channel_reports[i].channels) + 1; /* inculdes op_class byte */

        _I1B(&op_class_channels_nr,              &p);
        _I1B(&m->ap_channel_reports[i].op_class, &p);
        map_cs_foreach(&m->ap_channel_reports[i].channels, channel) {
            _I1B(&channel, &p);
        }
    }

    _I1B(&m->element_ids_nr, &p);
    _InB(m->element_ids,     &p, m->element_ids_nr);

    FORGE_RETURN
}

/*#######################################################################
# Beacon metrics response TLV ("Section 17.2.28")                       #
########################################################################*/
TLV_FREE_FUNCTION(beacon_metrics_response)
{
    uint8_t i;

    for (i = 0; i < m->elements_nr; i++){
        SFREE(m->elements[i].subelements);
    }
}

static uint8_t* parse_beacon_metrics_response_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_beacon_metrics_response_tlv_t *ret;
    mac_addr mac;
    uint8_t  status_code, elements_nr, i;
    uint8_t *p = packet_stream;

    PARSE_CHECK_MIN_LEN(8)

    _EnB(&p, mac, 6);
    _E1B(&p, &status_code);
    _E1B(&p, &elements_nr);

    /* Allocate tlv struct + elements */
    ret = calloc(1, sizeof(*ret) + elements_nr * sizeof(*ret->elements));
    if (NULL == ret) {
        return NULL;
    }

    ret->tlv_type = TLV_TYPE_BEACON_METRICS_RESPONSE;
    maccpy(ret->sta_mac, mac);
    ret->status_code = status_code;

    /* Add valid elements */
    ret->elements_nr = 0;
    for (i = 0; i < elements_nr; i++) {
        uint8_t elem_id  = p[0];
        uint8_t elem_len = p[1];

        if (elem_id == MAP_MEASUREMENT_REPORT_ELEMENTID) {
            size_t copy_len = elem_len + 2;

            if (copy_len > MAP_BEACON_REPORT_ELEMENT_SIZE) {
                /* Report contains subelements */
                size_t subelem_len;

                copy_len = MAP_BEACON_REPORT_ELEMENT_SIZE;
                subelem_len = elem_len + 2 - copy_len;

                ret->elements[i].subelements = calloc(1, subelem_len);
                if (ret->elements[i].subelements == NULL) {
                    free(ret);
                    return NULL;
                }

                memcpy(ret->elements[i].subelements, p + copy_len, subelem_len);
            }
            memcpy(&ret->elements[i], p, copy_len);

            /* Skip complete IE in received data */
            p += elem_len + 2;

            ret->elements_nr++;
        }
    }

    PARSE_CHECK_INTEGRITY(beacon_metrics_response)
    PARSE_RETURN
}

static uint8_t* forge_beacon_metrics_response_tlv(void *memory_structure, uint16_t *len)
{
    map_beacon_metrics_response_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 6 + 1 + 1 + m->elements_nr * MAP_BEACON_REPORT_ELEMENT_SIZE; /* mac + status_code + elements_nr + elements */
    uint8_t  *ret, *p, i;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,    &p);
    _I2B(&tlv_length,     &p);
    _InB(m->sta_mac,      &p, 6);
    _I1B(&m->status_code, &p);
    _I1B(&m->elements_nr, &p);

    for (i = 0; i < m->elements_nr; i++) {
        _InB(&m->elements[i], &p, MAP_BEACON_REPORT_ELEMENT_SIZE);
    }

    FORGE_RETURN
}

/*#######################################################################
# Steering request TLV ("Section 17.2.29")                              #
########################################################################*/
void map_free_p1_p2_steering_request_tlv(UNUSED void *memory_structure, UNUSED bool profile2)
{
}

TLV_FREE_FUNCTION(steering_request)
{
    map_free_p1_p2_steering_request_tlv(m, false);
}

/* Functions used for both profile 1 and 2 steering request */
uint8_t* map_parse_p1_p2_steering_request_tlv(uint8_t *packet_stream, uint16_t len, bool profile2)
{
    map_steering_request_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    PARSE_CHECK_MIN_LEN(11)

    PARSE_CALLOC_RET

    ret->tlv_type = profile2 ? TLV_TYPE_PROFILE2_STEERING_REQUEST : TLV_TYPE_STEERING_REQUEST;

    _EnB(&p, &ret->bssid, 6);
    _E1B(&p, &ret->flag);
    _E2B(&p, &ret->opportunity_wnd);
    _E2B(&p, &ret->disassociation_timer);
    _E1B(&p, &ret->sta_macs_nr);
    PARSE_LIMIT(ret->sta_macs_nr, MAX_STATION_PER_BSS);

    for(i = 0; i < ret->sta_macs_nr;i++) {
        _EnB(&p, &ret->sta_macs[i], 6);
    }

    _E1B(&p, &ret->target_bsss_nr);
    PARSE_LIMIT(ret->target_bsss_nr, MAX_STATION_PER_BSS);

    for (i = 0; i < ret->target_bsss_nr; i++) {
        _EnB(&p, &ret->target_bsss[i].bssid, 6);
        _E1B(&p, &ret->target_bsss[i].op_class);
        _E1B(&p, &ret->target_bsss[i].channel);
        if (profile2) {
            _E1B(&p, &ret->target_bsss[i].reason);
        }
    }

    PARSE_CHECK_INTEGRITY(steering_request)
    PARSE_RETURN
}

uint8_t* map_forge_p1_p2_steering_request_tlv(void *memory_structure, uint16_t *len, bool profile2)
{
    map_steering_request_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i;

    /* Calculate TLV length */
    tlv_length  = 6 + 1 + 2 + 2;                    /* bssid + flags + opp_wnd + dis_tmr */
    tlv_length += 1 + m->sta_macs_nr * 6;           /* sta_nr + sta_macs */
    tlv_length += 1 + m->target_bsss_nr * (6 + 1 + 1 + (profile2 ? 1 : 0)); /* bsss_nr + bsss_nr * (bssid + op_class + channel + reason if profile2) */

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,             &p);
    _I2B(&tlv_length,              &p);
    _InB(&m->bssid,                &p, 6);
    _I1B(&m->flag,                 &p);
    _I2B(&m->opportunity_wnd,      &p);
    _I2B(&m->disassociation_timer, &p);

    _I1B(&m->sta_macs_nr,          &p);
    for (i = 0; i < m->sta_macs_nr; i++) {
        _InB(&m->sta_macs[i], &p, 6);
    }

    _I1B(&m->target_bsss_nr, &p);
    for (i = 0; i < m->target_bsss_nr; i++) {
        _InB(&m->target_bsss[i].bssid,    &p, 6);
        _I1B(&m->target_bsss[i].op_class, &p);
        _I1B(&m->target_bsss[i].channel,  &p);
        if (profile2) {
            _I1B(&m->target_bsss[i].reason, &p);
        }
    }

    FORGE_RETURN
}

static uint8_t* parse_steering_request_tlv(uint8_t *packet_stream, uint16_t len)
{
    return map_parse_p1_p2_steering_request_tlv(packet_stream, len, false);
}

static uint8_t* forge_steering_request_tlv(void *memory_structure, uint16_t *len)
{
    return map_forge_p1_p2_steering_request_tlv(memory_structure, len, false);
}

/*#######################################################################
# Steering BTM report TLV ("Section 17.2.30")                           #
########################################################################*/
TLV_FREE_FUNCTION(steering_btm_report) {}

static uint8_t* parse_steering_btm_report_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_steering_btm_report_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_MIN_LEN(13)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_STEERING_BTM_REPORT;

    _EnB(&p, ret->bssid, 6);
    _EnB(&p, ret->sta_mac, 6);
    _E1B(&p, &ret->btm_status_code);

    if (len == 19) {
        ret->target_bssid_present = 1;
        _EnB(&p, ret->target_bssid, 6);
    }

    PARSE_CHECK_INTEGRITY(steering_btm_report)
    PARSE_RETURN
}

static uint8_t* forge_steering_btm_report_tlv(void *memory_structure, uint16_t *len)
{
    map_steering_btm_report_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 6 + 6 + 1 + (m->target_bssid_present ? 6 : 0);
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,        &p);
    _I2B(&tlv_length,         &p);
    _InB(m->bssid,            &p, 6);
    _InB(m->sta_mac,          &p, 6);
    _I1B(&m->btm_status_code, &p);

    if (m->target_bssid_present) {
        _InB(m->target_bssid, &p, 6);
    }

    FORGE_RETURN
}

/*#######################################################################
# Client association control request TLV ("Section 17.2.31")            #
########################################################################*/
TLV_FREE_FUNCTION(client_assoc_control_request) {}

static uint8_t* parse_client_assoc_control_request_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_client_assoc_control_request_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    PARSE_CHECK_MIN_LEN(10)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_CLIENT_ASSOCIATION_CONTROL_REQUEST;

    _EnB(&p, ret->bssid, 6);
    _E1B(&p, &ret->association_control);
    _E2B(&p, &ret->validity_period);
    _E1B(&p, &ret->sta_macs_nr);
    PARSE_LIMIT(ret->sta_macs_nr, MAX_STATION_PER_BSS);

    for (i = 0; i < ret->sta_macs_nr; i++) {
        _EnB(&p, ret->sta_macs[i], 6);
    }

    PARSE_CHECK_INTEGRITY(client_assoc_control_request)
    PARSE_RETURN
}

static uint8_t* forge_client_assoc_control_request_tlv(void *memory_structure, uint16_t *len)
{
    map_client_assoc_control_request_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 6 + 1 + 2 + 1 + m->sta_macs_nr * 6; /* bssid + assoc_control + val_period + stas_nr + sta_macs */
    uint8_t  *ret, *p, i;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,             &p);
    _InB(&m->bssid,               &p, 6);
    _I1B(&m->association_control, &p);
    _I2B(&m->validity_period,     &p);
    _I1B(&m->sta_macs_nr,         &p);

    for (i = 0; i < m->sta_macs_nr; i++) {
       _InB(m->sta_macs[i], &p, 6);
    }

    FORGE_RETURN
}

/*#######################################################################
# Backhaul steering request report TLV ("Section 17.2.32")              #
########################################################################*/
TLV_FREE_FUNCTION(backhaul_steering_request) {}

static uint8_t* parse_backhaul_steering_request_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_backhaul_steering_request_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_EXP_LEN(14)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_BACKHAUL_STEERING_REQUEST;

    _EnB(&p, ret->bsta_mac, 6);
    _EnB(&p, ret->target_bssid, 6);
    _E1B(&p, &ret->target_op_class);
    _E1B(&p, &ret->target_channel);

    PARSE_CHECK_INTEGRITY(backhaul_steering_request)
    PARSE_RETURN
}

static uint8_t* forge_backhaul_steering_request_tlv(void *memory_structure, uint16_t *len)
{
    map_backhaul_steering_request_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 6 + 6 + 1 + 1; /* bsta_mac + target_bssid + op_class + target_channel */
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,        &p);
    _I2B(&tlv_length,         &p);
    _InB(m->bsta_mac,         &p, 6);
    _InB(m->target_bssid,     &p, 6);
    _I1B(&m->target_op_class, &p);
    _I1B(&m->target_channel,  &p);

    FORGE_RETURN
}

/*#######################################################################
# Backhaul steering response report TLV ("Section 17.2.33")             #
########################################################################*/
TLV_FREE_FUNCTION(backhaul_steering_response) {}

static uint8_t* parse_backhaul_steering_response_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_backhaul_steering_response_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_EXP_LEN(13)

    PARSE_CALLOC_RET

    ret->tlv_type   = TLV_TYPE_BACKHAUL_STEERING_RESPONSE;

    _EnB(&p, ret->bsta_mac, 6);
    _EnB(&p, ret->target_bssid, 6);
    _E1B(&p, &ret->result);

    PARSE_CHECK_INTEGRITY(backhaul_steering_response)
    PARSE_RETURN
}

static uint8_t* forge_backhaul_steering_response_tlv(void *memory_structure, uint16_t *len)
{
    map_backhaul_steering_response_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 6 + 6 + 1; /* bsta_mac + target_bssid + result */
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,    &p);
    _I2B(&tlv_length,     &p);
    _InB(m->bsta_mac,     &p, 6);
    _InB(m->target_bssid, &p, 6);
    _I1B(&m->result,      &p);

    FORGE_RETURN
}

/*#######################################################################
# Higher layer data TLV ("Section 17.2.34")                             #
########################################################################*/
TLV_FREE_FUNCTION(higher_layer_data) {}

static uint8_t* parse_higher_layer_data_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_higher_layer_data_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_MIN_LEN(1);

    /* Allocate tlv struct and data */
    ret = calloc(1, sizeof(*ret) + (len - 1));
    if (NULL == ret) {
        return NULL;
    }

    ret->tlv_type = TLV_TYPE_HIGHER_LAYER_DATA;

    _E1B(&p, &ret->protocol);

    /* 1 octet protocol field */
    if (len > 1) {
        ret->payload_len = len - 1 ;
        ret->payload = (uint8_t*)(ret + 1);
        _EnB(&p, ret->payload, ret->payload_len);
    }


    PARSE_CHECK_INTEGRITY(higher_layer_data)
    PARSE_RETURN
}

static uint8_t* forge_higher_layer_data_tlv(void *memory_structure, uint16_t *len)
{
    map_higher_layer_data_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 1 + m->payload_len;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _I1B(&m->protocol, &p);
    _InB(m->payload,   &p, m->payload_len);

    FORGE_RETURN
}

/*#######################################################################
# Associated STA traffic stats TLV ("Section 17.2.35")                  #
########################################################################*/
TLV_FREE_FUNCTION(assoc_sta_traffic_stats) {}

static uint8_t* parse_assoc_sta_traffic_stats_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_assoc_sta_traffic_stats_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_EXP_LEN(34)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_ASSOCIATED_STA_TRAFFIC_STATS;

    _EnB(&p, ret->sta_mac, 6);
    _E4B(&p, &ret->txbytes);
    _E4B(&p, &ret->rxbytes);
    _E4B(&p, &ret->txpkts);
    _E4B(&p, &ret->rxpkts);
    _E4B(&p, &ret->txpkterrors);
    _E4B(&p, &ret->rxpkterrors);
    _E4B(&p, &ret->retransmission_cnt);

    PARSE_CHECK_INTEGRITY(assoc_sta_traffic_stats)
    PARSE_RETURN
}

static uint8_t* forge_assoc_sta_traffic_stats_tlv(void *memory_structure, uint16_t *len)
{
    map_assoc_sta_traffic_stats_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 6 + 7 * 4;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,           &p);
    _I2B(&tlv_length,            &p);
    _InB(m->sta_mac,             &p, 6);
    _I4B(&m->txbytes,            &p);
    _I4B(&m->rxbytes,            &p);
    _I4B(&m->txpkts,             &p);
    _I4B(&m->rxpkts,             &p);
    _I4B(&m->txpkterrors,        &p);
    _I4B(&m->rxpkterrors,        &p);
    _I4B(&m->retransmission_cnt, &p);

    FORGE_RETURN
}

/*#######################################################################
# Error code TLV ("Section 17.2.36")                                    #
########################################################################*/
TLV_FREE_FUNCTION(error_code) {}

static uint8_t* parse_error_code_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_error_code_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_EXP_LEN(7)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_ERROR_CODE;

    _E1B(&p, &ret->reason_code);
    _EnB(&p, ret->sta_mac, 6);

    PARSE_CHECK_INTEGRITY(error_code)
    PARSE_RETURN
}

static uint8_t* forge_error_code_tlv(void *memory_structure, uint16_t *len)
{
    map_error_code_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 7;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,    &p);
    _I2B(&tlv_length,     &p);
    _I1B(&m->reason_code, &p);
    _InB(m->sta_mac,      &p, 6);

    FORGE_RETURN
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
void map_r1_register_tlvs(void)
{
    I1905_REGISTER_TLV(TLV_TYPE_SUPPORTED_SERVICE,                      supported_service                );
    I1905_REGISTER_TLV(TLV_TYPE_SEARCHED_SERVICE,                       searched_service                 );
    I1905_REGISTER_TLV(TLV_TYPE_AP_RADIO_IDENTIFIER,                    ap_radio_identifier              );
    I1905_REGISTER_TLV(TLV_TYPE_AP_OPERATIONAL_BSS,                     ap_operational_bss               );
    I1905_REGISTER_TLV(TLV_TYPE_ASSOCIATED_CLIENTS,                     assoc_clients                    );
    I1905_REGISTER_TLV(TLV_TYPE_AP_CAPABILITY,                          ap_cap                           );
    I1905_REGISTER_TLV(TLV_TYPE_AP_RADIO_BASIC_CAPABILITIES,            ap_radio_basic_cap               );
    I1905_REGISTER_TLV(TLV_TYPE_AP_HT_CAPABILITIES,                     ap_ht_cap                        );
    I1905_REGISTER_TLV(TLV_TYPE_AP_VHT_CAPABILITIES,                    ap_vht_cap                       );
    I1905_REGISTER_TLV(TLV_TYPE_AP_HE_CAPABILITIES,                     ap_he_cap                        );
    I1905_REGISTER_TLV(TLV_TYPE_STEERING_POLICY,                        steering_policy                  );
    I1905_REGISTER_TLV(TLV_TYPE_METRIC_REPORTING_POLICY,                metric_reporting_policy          );
    I1905_REGISTER_TLV(TLV_TYPE_CHANNEL_PREFERENCE,                     channel_preference               );
    I1905_REGISTER_TLV(TLV_TYPE_RADIO_OPERATION_RESTRICTION,            radio_operation_restriction      );
    I1905_REGISTER_TLV(TLV_TYPE_TRANSMIT_POWER_LIMIT,                   transmit_power_limit             );
    I1905_REGISTER_TLV(TLV_TYPE_CHANNEL_SELECTION_RESPONSE,             channel_selection_response       );
    I1905_REGISTER_TLV(TLV_TYPE_OPERATING_CHANNEL_REPORT,               operating_channel_report         );
    I1905_REGISTER_TLV(TLV_TYPE_CLIENT_INFO,                            client_info                      );
    I1905_REGISTER_TLV(TLV_TYPE_CLIENT_CAPABILITY_REPORT,               client_cap_report                );
    I1905_REGISTER_TLV(TLV_TYPE_CLIENT_ASSOCIATION_EVENT,               client_assoc_event               );
    I1905_REGISTER_TLV(TLV_TYPE_AP_METRIC_QUERY,                        ap_metric_query                  );
    I1905_REGISTER_TLV(TLV_TYPE_AP_METRICS,                             ap_metrics                       );
    I1905_REGISTER_TLV(TLV_TYPE_STA_MAC_ADDRESS,                        sta_mac_address                  );
    I1905_REGISTER_TLV(TLV_TYPE_ASSOCIATED_STA_LINK_METRICS,            assoc_sta_link_metrics           );
    I1905_REGISTER_TLV(TLV_TYPE_UNASSOCIATED_STA_LINK_METRICS_QUERY,    unassoc_sta_link_metrics_query   );
    I1905_REGISTER_TLV(TLV_TYPE_UNASSOCIATED_STA_LINK_METRICS_RESPONSE, unassoc_sta_link_metrics_response);
    I1905_REGISTER_TLV(TLV_TYPE_BEACON_METRICS_QUERY,                   beacon_metrics_query             );
    I1905_REGISTER_TLV(TLV_TYPE_BEACON_METRICS_RESPONSE,                beacon_metrics_response          );
    I1905_REGISTER_TLV(TLV_TYPE_STEERING_REQUEST,                       steering_request                 );
    I1905_REGISTER_TLV(TLV_TYPE_STEERING_BTM_REPORT,                    steering_btm_report              );
    I1905_REGISTER_TLV(TLV_TYPE_CLIENT_ASSOCIATION_CONTROL_REQUEST,     client_assoc_control_request     );
    I1905_REGISTER_TLV(TLV_TYPE_BACKHAUL_STEERING_REQUEST,              backhaul_steering_request        );
    I1905_REGISTER_TLV(TLV_TYPE_BACKHAUL_STEERING_RESPONSE,             backhaul_steering_response       );
    I1905_REGISTER_TLV(TLV_TYPE_HIGHER_LAYER_DATA,                      higher_layer_data                );
    I1905_REGISTER_TLV(TLV_TYPE_ASSOCIATED_STA_TRAFFIC_STATS,           assoc_sta_traffic_stats          );
    I1905_REGISTER_TLV(TLV_TYPE_ERROR_CODE,                             error_code                       );
}
