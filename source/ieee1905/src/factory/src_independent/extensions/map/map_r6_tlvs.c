/*
 * Copyright (c) 2019-2023 AirTies Wireless Networks
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
# Wi-Fi 7 Agent Capabilities TLV ("Section 17.2.95")                    #
########################################################################*/
TLV_FREE_FUNCTION(wifi7_agent_cap)
{
    uint8_t i;

    for (i = 0; i < m->radios_nr; i++) {
        SFREE(m->radios[i].cap.ap_str_records);
        SFREE(m->radios[i].cap.ap_nstr_records);
        SFREE(m->radios[i].cap.ap_emlsr_records);
        SFREE(m->radios[i].cap.ap_emlmr_records);
        SFREE(m->radios[i].cap.bsta_str_records);
        SFREE(m->radios[i].cap.bsta_nstr_records);
        SFREE(m->radios[i].cap.bsta_emlsr_records);
        SFREE(m->radios[i].cap.bsta_emlmr_records);
    }
}

static uint8_t* parse_wifi7_agent_cap_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_wifi7_agent_cap_tlv_t *ret;
    uint8_t *p = packet_stream, byte, i, j;

    /* Min TLV len: MaxMLD + Maxlinks + TIDtoLinkMap + Reserved(13) + radio_nr */
    PARSE_CHECK_MIN_LEN(17);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_WIFI7_AGENT_CAPABILITIES;

    _E1B(&p, &ret->max_mlds);
    _E1B(&p, &byte);
    ret->ap_max_links   =  (byte & (BIT_MASK_7 | BIT_MASK_6 | BIT_MASK_5 | BIT_MASK_4)) >> BIT_SHIFT_4;
    ret->bsta_max_links =  byte & (BIT_MASK_3 | BIT_MASK_2 | BIT_MASK_1 | BIT_MASK_0);
    _E1B(&p, &byte);
    ret->tid_to_link_map_cap = (byte & (BIT_MASK_7 | BIT_MASK_6)) >> BIT_SHIFT_6;
    _EnB(&p, ret->reserved2, 13);

    _E1B(&p, &ret->radios_nr);
    PARSE_LIMIT(ret->radios_nr, MAX_RADIO_PER_AGENT);
    for (i = 0; i < ret->radios_nr; i++) {
        _EnB(&p, ret->radios[i].ruid, ETHER_ADDR_LEN);
        _EnB(&p, ret->radios[i].reserved, 24);

        _E1B(&p, &byte);
        ret->radios[i].cap.ap_mld_modes.str     = (byte & BIT_MASK_7);
        ret->radios[i].cap.ap_mld_modes.nstr    = (byte & BIT_MASK_6);
        ret->radios[i].cap.ap_mld_modes.emlsr   = (byte & BIT_MASK_5);
        ret->radios[i].cap.ap_mld_modes.emlmr   = (byte & BIT_MASK_4);

        _E1B(&p, &byte);
        ret->radios[i].cap.bsta_mld_modes.str   = (byte & BIT_MASK_7);
        ret->radios[i].cap.bsta_mld_modes.nstr  = (byte & BIT_MASK_6);
        ret->radios[i].cap.bsta_mld_modes.emlsr = (byte & BIT_MASK_5);
        ret->radios[i].cap.bsta_mld_modes.emlmr = (byte & BIT_MASK_4);

        _E1B(&p, &ret->radios[i].cap.ap_str_records_nr);
        if (ret->radios[i].cap.ap_str_records_nr > 0) {
            ret->radios[i].cap.ap_str_records = calloc(ret->radios[i].cap.ap_str_records_nr, sizeof(*ret->radios[i].cap.ap_str_records));
            if (ret->radios[i].cap.ap_str_records == NULL) {
                PARSE_FREE_RET_RETURN(wifi7_agent_cap)
            }

            for (j = 0; j < ret->radios[i].cap.ap_str_records_nr; j++) {
                _EnB(&p, ret->radios[i].cap.ap_str_records[j].ruid, ETHER_ADDR_LEN);
                _E1B(&p, &byte);
                ret->radios[i].cap.ap_str_records[j].freq_separation = (byte & (BIT_MASK_7 | BIT_MASK_6 | BIT_MASK_5 | BIT_MASK_4 | BIT_MASK_3)) >> BIT_SHIFT_3;
            }
        }

        _E1B(&p, &ret->radios[i].cap.ap_nstr_records_nr);
        if (ret->radios[i].cap.ap_nstr_records_nr > 0) {
            ret->radios[i].cap.ap_nstr_records = calloc(ret->radios[i].cap.ap_nstr_records_nr, sizeof(*ret->radios[i].cap.ap_nstr_records));
            if (ret->radios[i].cap.ap_nstr_records == NULL) {
                PARSE_FREE_RET_RETURN(wifi7_agent_cap)
            }

            for (j = 0; j < ret->radios[i].cap.ap_nstr_records_nr; j++) {
                _EnB(&p, ret->radios[i].cap.ap_nstr_records[j].ruid, ETHER_ADDR_LEN);
                _E1B(&p, &byte);
                ret->radios[i].cap.ap_nstr_records[j].freq_separation = (byte & (BIT_MASK_7 | BIT_MASK_6 | BIT_MASK_5 | BIT_MASK_4 | BIT_MASK_3)) >> BIT_SHIFT_3;
            }
        }

        _E1B(&p, &ret->radios[i].cap.ap_emlsr_records_nr);
        if (ret->radios[i].cap.ap_emlsr_records_nr > 0) {
            ret->radios[i].cap.ap_emlsr_records = calloc(ret->radios[i].cap.ap_emlsr_records_nr, sizeof(*ret->radios[i].cap.ap_emlsr_records));
            if (ret->radios[i].cap.ap_emlsr_records == NULL) {
                PARSE_FREE_RET_RETURN(wifi7_agent_cap)
            }

            for (j = 0; j < ret->radios[i].cap.ap_emlsr_records_nr; j++) {
                _EnB(&p, ret->radios[i].cap.ap_emlsr_records[j].ruid, ETHER_ADDR_LEN);
                _E1B(&p, &byte);
                ret->radios[i].cap.ap_emlsr_records[j].freq_separation = (byte & (BIT_MASK_7 | BIT_MASK_6 | BIT_MASK_5 | BIT_MASK_4 | BIT_MASK_3)) >> BIT_SHIFT_3;
            }
        }

        _E1B(&p, &ret->radios[i].cap.ap_emlmr_records_nr);
        if (ret->radios[i].cap.ap_emlmr_records_nr > 0) {
            ret->radios[i].cap.ap_emlmr_records = calloc(ret->radios[i].cap.ap_emlmr_records_nr, sizeof(*ret->radios[i].cap.ap_emlmr_records));
            if (ret->radios[i].cap.ap_emlmr_records == NULL) {
                PARSE_FREE_RET_RETURN(wifi7_agent_cap)
            }

            for (j = 0; j < ret->radios[i].cap.ap_emlmr_records_nr; j++) {
                _EnB(&p, ret->radios[i].cap.ap_emlmr_records[j].ruid, ETHER_ADDR_LEN);
                _E1B(&p, &byte);
                ret->radios[i].cap.ap_emlmr_records[j].freq_separation = (byte & (BIT_MASK_7 | BIT_MASK_6 | BIT_MASK_5 | BIT_MASK_4 | BIT_MASK_3)) >> BIT_SHIFT_3;
            }
        }

        _E1B(&p, &ret->radios[i].cap.bsta_str_records_nr);
        if (ret->radios[i].cap.bsta_str_records_nr > 0) {
            ret->radios[i].cap.bsta_str_records = calloc(ret->radios[i].cap.bsta_str_records_nr, sizeof(*ret->radios[i].cap.ap_str_records));
            if (ret->radios[i].cap.bsta_str_records == NULL) {
                PARSE_FREE_RET_RETURN(wifi7_agent_cap)
            }

            for (j = 0; j < ret->radios[i].cap.bsta_str_records_nr; j++) {
                _EnB(&p, ret->radios[i].cap.bsta_str_records[j].ruid, ETHER_ADDR_LEN);
                _E1B(&p, &byte);
                ret->radios[i].cap.bsta_str_records[j].freq_separation = (byte & (BIT_MASK_7 | BIT_MASK_6 | BIT_MASK_5 | BIT_MASK_4 | BIT_MASK_3)) >> BIT_SHIFT_3;
            }
        }

        _E1B(&p, &ret->radios[i].cap.bsta_nstr_records_nr);
        if (ret->radios[i].cap.bsta_nstr_records_nr > 0) {
            ret->radios[i].cap.bsta_nstr_records = calloc(ret->radios[i].cap.bsta_nstr_records_nr, sizeof(*ret->radios[i].cap.bsta_nstr_records));
            if (ret->radios[i].cap.bsta_nstr_records == NULL) {
                PARSE_FREE_RET_RETURN(wifi7_agent_cap)
            }

            for (j = 0; j < ret->radios[i].cap.bsta_nstr_records_nr; j++) {
                _EnB(&p, ret->radios[i].cap.bsta_nstr_records[j].ruid, ETHER_ADDR_LEN);
                _E1B(&p, &byte);
                ret->radios[i].cap.bsta_nstr_records[j].freq_separation = (byte & (BIT_MASK_7 | BIT_MASK_6 | BIT_MASK_5 | BIT_MASK_4 | BIT_MASK_3)) >> BIT_SHIFT_3;
            }
        }

        _E1B(&p, &ret->radios[i].cap.bsta_emlsr_records_nr);
        if (ret->radios[i].cap.bsta_emlsr_records_nr > 0) {
            ret->radios[i].cap.bsta_emlsr_records = calloc(ret->radios[i].cap.bsta_emlsr_records_nr, sizeof(*ret->radios[i].cap.bsta_emlsr_records));
            if (ret->radios[i].cap.bsta_emlsr_records == NULL) {
                PARSE_FREE_RET_RETURN(wifi7_agent_cap)
            }

            for (j = 0; j < ret->radios[i].cap.bsta_emlsr_records_nr; j++) {
                _EnB(&p, ret->radios[i].cap.bsta_emlsr_records[j].ruid, ETHER_ADDR_LEN);
                _E1B(&p, &byte);
                ret->radios[i].cap.bsta_emlsr_records[j].freq_separation = (byte & (BIT_MASK_7 | BIT_MASK_6 | BIT_MASK_5 | BIT_MASK_4 | BIT_MASK_3)) >> BIT_SHIFT_3;
            }
        }

        _E1B(&p, &ret->radios[i].cap.bsta_emlmr_records_nr);
        if (ret->radios[i].cap.bsta_emlmr_records_nr > 0) {
            ret->radios[i].cap.bsta_emlmr_records = calloc(ret->radios[i].cap.bsta_emlmr_records_nr, sizeof(*ret->radios[i].cap.bsta_emlmr_records));
            if (ret->radios[i].cap.bsta_emlmr_records == NULL) {
                PARSE_FREE_RET_RETURN(wifi7_agent_cap)
            }

            for (j = 0; j < ret->radios[i].cap.bsta_emlmr_records_nr; j++) {
                _EnB(&p, ret->radios[i].cap.bsta_emlmr_records[j].ruid, ETHER_ADDR_LEN);
                _E1B(&p, &byte);
                ret->radios[i].cap.bsta_emlmr_records[j].freq_separation = (byte & (BIT_MASK_7 | BIT_MASK_6 | BIT_MASK_5 | BIT_MASK_4 | BIT_MASK_3)) >> BIT_SHIFT_3;
            }
        }

    }

    PARSE_CHECK_INTEGRITY(wifi7_agent_cap)
    PARSE_RETURN
}

static uint8_t* forge_wifi7_agent_cap_tlv(void *memory_structure, uint16_t *len)
{
    map_wifi7_agent_cap_tlv_t *m = memory_structure;
    uint8_t  *ret, *p, i, j, byte;

    /* Calculate TLV length */
    uint16_t tlv_length = 17; /* MaxMLD + Maxlinks + TIDtoLinkMap + Reserved(13) + radio_nr */
    for (i = 0; i < m->radios_nr; i++) {
        tlv_length += 6 + 24 + 1 + 1; /* ruid, reserved, ap_cap, bsta_cap */
        tlv_length += 1 + (m->radios[i].cap.ap_str_records_nr     * 7); /* ruid, freq_sep */
        tlv_length += 1 + (m->radios[i].cap.ap_nstr_records_nr    * 7);
        tlv_length += 1 + (m->radios[i].cap.ap_emlsr_records_nr   * 7);
        tlv_length += 1 + (m->radios[i].cap.ap_emlmr_records_nr   * 7);
        tlv_length += 1 + (m->radios[i].cap.bsta_str_records_nr   * 7);
        tlv_length += 1 + (m->radios[i].cap.bsta_nstr_records_nr  * 7);
        tlv_length += 1 + (m->radios[i].cap.bsta_emlsr_records_nr * 7);
        tlv_length += 1 + (m->radios[i].cap.bsta_emlmr_records_nr * 7);
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,   &p);
    _I2B(&tlv_length,    &p);
    _I1B(&m->max_mlds,   &p);

    byte = (m->ap_max_links << BIT_SHIFT_4) | m->bsta_max_links;
    _I1B(&byte, &p);
    byte = m->tid_to_link_map_cap << BIT_SHIFT_6;
    _I1B(&byte, &p);
    _InB(&m->reserved2, &p, 13);

    _I1B(&m->radios_nr, &p);
    for (i = 0; i < m->radios_nr; i++) {
        _InB(m->radios[i].ruid,     &p, ETHER_ADDR_LEN);
        _InB(m->radios[i].reserved, &p, 24);
        byte = (m->radios[i].cap.ap_mld_modes.str     << BIT_SHIFT_7) |
               (m->radios[i].cap.ap_mld_modes.nstr    << BIT_SHIFT_6) |
               (m->radios[i].cap.ap_mld_modes.emlsr   << BIT_SHIFT_5) |
               (m->radios[i].cap.ap_mld_modes.emlmr   << BIT_SHIFT_4);
        _I1B(&byte, &p);
        byte = (m->radios[i].cap.bsta_mld_modes.str   << BIT_SHIFT_7) |
               (m->radios[i].cap.bsta_mld_modes.nstr  << BIT_SHIFT_6) |
               (m->radios[i].cap.bsta_mld_modes.emlsr << BIT_SHIFT_5) |
               (m->radios[i].cap.bsta_mld_modes.emlmr << BIT_SHIFT_4);
        _I1B(&byte, &p);

        _I1B(&m->radios[i].cap.ap_str_records_nr, &p);
        for (j = 0; j < m->radios[i].cap.ap_str_records_nr; j++) {
            _InB(m->radios[i].cap.ap_str_records[j].ruid, &p, ETHER_ADDR_LEN);
            byte = m->radios[i].cap.ap_str_records[j].freq_separation << BIT_SHIFT_3;
            _I1B(&byte, &p);
        }

        _I1B(&m->radios[i].cap.ap_nstr_records_nr, &p);
        for (j = 0; j < m->radios[i].cap.ap_nstr_records_nr; j++) {
            _InB(m->radios[i].cap.ap_nstr_records[j].ruid, &p, ETHER_ADDR_LEN);
            byte = m->radios[i].cap.ap_nstr_records[j].freq_separation << BIT_SHIFT_3;
            _I1B(&byte, &p);
        }

        _I1B(&m->radios[i].cap.ap_emlsr_records_nr, &p);
        for (j = 0; j < m->radios[i].cap.ap_emlsr_records_nr; j++) {
            _InB(m->radios[i].cap.ap_emlsr_records[j].ruid, &p, ETHER_ADDR_LEN);
            byte = m->radios[i].cap.ap_emlsr_records[j].freq_separation << BIT_SHIFT_3;
            _I1B(&byte, &p);
        }

        _I1B(&m->radios[i].cap.ap_emlmr_records_nr, &p);
        for (j = 0; j < m->radios[i].cap.ap_emlmr_records_nr; j++) {
            _InB(m->radios[i].cap.ap_emlmr_records[j].ruid, &p, ETHER_ADDR_LEN);
            byte = m->radios[i].cap.ap_emlmr_records[j].freq_separation << BIT_SHIFT_3;
            _I1B(&byte, &p);
        }

        _I1B(&m->radios[i].cap.bsta_str_records_nr, &p);
        for (j = 0; j < m->radios[i].cap.bsta_str_records_nr; j++) {
            _InB(m->radios[i].cap.bsta_str_records[j].ruid, &p, ETHER_ADDR_LEN);
            byte = m->radios[i].cap.bsta_str_records[j].freq_separation << BIT_SHIFT_3;
            _I1B(&byte, &p);
        }

        _I1B(&m->radios[i].cap.bsta_nstr_records_nr, &p);
        for (j = 0; j < m->radios[i].cap.bsta_nstr_records_nr; j++) {
            _InB(m->radios[i].cap.bsta_nstr_records[j].ruid, &p, ETHER_ADDR_LEN);
            byte = m->radios[i].cap.bsta_nstr_records[j].freq_separation << BIT_SHIFT_3;
            _I1B(&byte, &p);
        }

        _I1B(&m->radios[i].cap.bsta_emlsr_records_nr, &p);
        for (j = 0; j < m->radios[i].cap.bsta_emlsr_records_nr; j++) {
            _InB(m->radios[i].cap.bsta_emlsr_records[j].ruid, &p, ETHER_ADDR_LEN);
            byte = m->radios[i].cap.bsta_emlsr_records[j].freq_separation << BIT_SHIFT_3;
            _I1B(&byte, &p);
        }

        _I1B(&m->radios[i].cap.bsta_emlmr_records_nr, &p);
        for (j = 0; j < m->radios[i].cap.bsta_emlmr_records_nr; j++) {
            _InB(m->radios[i].cap.bsta_emlmr_records[j].ruid, &p, ETHER_ADDR_LEN);
            byte = m->radios[i].cap.bsta_emlmr_records[j].freq_separation << BIT_SHIFT_3;
            _I1B(&byte, &p);
        }
    }

    FORGE_RETURN
}

/*#######################################################################
# Agent AP MLD Configuration TLV ("Section 17.2.96")                    #
########################################################################*/
TLV_FREE_FUNCTION(agent_ap_mld_conf) {}

static uint8_t* parse_agent_ap_mld_conf_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_agent_ap_mld_conf_tlv_t *ret;
    uint8_t *p = packet_stream, byte, i, j;

    /* Min TLV len: Num_APMLD */
    PARSE_CHECK_MIN_LEN(1);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_AGENT_AP_MLD_CONFIGURATION;

    _E1B(&p, &ret->ap_mld_nr);
    PARSE_LIMIT(ret->ap_mld_nr, MAX_BSS_PER_RADIO);

    for (i = 0; i < ret->ap_mld_nr; i++) {
        _E1B(&p, &byte);
        ret->ap_mlds[i].ap_mld_mac_valid = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;

        _E1B(&p, &ret->ap_mlds[i].ssid_len);
        PARSE_LIMIT_N_DROP(agent_ap_mld_conf, ret->ap_mlds[i].ssid_len, (MAX_SSID_LEN - 1));
        _EnB(&p, ret->ap_mlds[i].ssid, ret->ap_mlds[i].ssid_len);

        _EnB(&p, ret->ap_mlds[i].ap_mld_mac, ETHER_ADDR_LEN);

        _E1B(&p, &byte);
        ret->ap_mlds[i].str   = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;
        ret->ap_mlds[i].nstr  = (byte & BIT_MASK_6) ? SET_BIT : RESET_BIT;
        ret->ap_mlds[i].emlsr = (byte & BIT_MASK_5) ? SET_BIT : RESET_BIT;
        ret->ap_mlds[i].emlmr = (byte & BIT_MASK_4) ? SET_BIT : RESET_BIT;

        /* Skip 20 reserved bytes */
        p += 20;

        _E1B(&p, &ret->ap_mlds[i].aff_ap_nr);
        PARSE_LIMIT(ret->ap_mlds[i].aff_ap_nr, MAX_MLD_AFF_APSTA);

        for (j = 0; j < ret->ap_mlds[i].aff_ap_nr; j++) {
            _E1B(&p, &byte);
            ret->ap_mlds[i].aff_aps[j].aff_ap_mac_valid = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;
            ret->ap_mlds[i].aff_aps[j].link_id_valid    = (byte & BIT_MASK_6) ? SET_BIT : RESET_BIT;

            _EnB(&p, ret->ap_mlds[i].aff_aps[j].radio_id, ETHER_ADDR_LEN);
            _EnB(&p, ret->ap_mlds[i].aff_aps[j].aff_ap_mac, ETHER_ADDR_LEN);

            _E1B(&p, &ret->ap_mlds[i].aff_aps[j].link_id);

            /* Skip 18 reserved bytes */
            p += 18;
        }
    }

    PARSE_CHECK_INTEGRITY(agent_ap_mld_conf)
    PARSE_RETURN
}

static uint8_t* forge_agent_ap_mld_conf_tlv(void *memory_structure, uint16_t *len)
{
    map_agent_ap_mld_conf_tlv_t *m = memory_structure;
    uint8_t  *ret, *p, i, j, byte;

    /* Calculate TLV length */
    uint16_t tlv_length = 1; /* ap_mld_nr */
    for (i = 0; i < m->ap_mld_nr; i++) {
        tlv_length += 1 + 1 + m->ap_mlds[i].ssid_len + 6 + 1 + 20 + 1; /* flags, ssid_len, ssid, ap_mld_mac, flags2, reserved, aff_ap_nr */
        for (j = 0; j < m->ap_mlds[i].aff_ap_nr; j++) {
            tlv_length += 1 + 6 + 6 + 1 + 18; /* flags, radio_id, aff_ap_mac, link_id, reserved */
        }
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,  &p);
    _I2B(&tlv_length,   &p);
    _I1B(&m->ap_mld_nr, &p);

    for (i = 0; i < m->ap_mld_nr; i++) {
        byte = m->ap_mlds[i].ap_mld_mac_valid << BIT_SHIFT_7;
        _I1B(&byte, &p);

        _I1B(&m->ap_mlds[i].ssid_len, &p);
        _InB(m->ap_mlds[i].ssid, &p, m->ap_mlds[i].ssid_len);

        _InB(m->ap_mlds[i].ap_mld_mac, &p, ETHER_ADDR_LEN);

        byte = (m->ap_mlds[i].str   << BIT_SHIFT_7) |
               (m->ap_mlds[i].nstr  << BIT_SHIFT_6) |
               (m->ap_mlds[i].emlsr << BIT_SHIFT_5) |
               (m->ap_mlds[i].emlmr << BIT_SHIFT_4);
        _I1B(&byte, &p);

        FORGE_RESERVE(p, 20);

        _I1B(&m->ap_mlds[i].aff_ap_nr, &p);

        for (j = 0; j < m->ap_mlds[i].aff_ap_nr; j++) {
            byte = (m->ap_mlds[i].aff_aps[j].aff_ap_mac_valid << BIT_SHIFT_7) |
                   (m->ap_mlds[i].aff_aps[j].link_id_valid    << BIT_SHIFT_6);
            _I1B(&byte, &p);

            _InB(m->ap_mlds[i].aff_aps[j].radio_id, &p, ETHER_ADDR_LEN);
            _InB(m->ap_mlds[i].aff_aps[j].aff_ap_mac, &p, ETHER_ADDR_LEN);

            _I1B(&m->ap_mlds[i].aff_aps[j].link_id, &p);

            FORGE_RESERVE(p, 18);
        }
    }

    FORGE_RETURN
}

/*#######################################################################
# Backhaul STA MLD Configuration TLV ("Section 17.2.97")                #
########################################################################*/
TLV_FREE_FUNCTION(bsta_mld_conf) {}

static uint8_t* parse_bsta_mld_conf_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_bsta_mld_conf_tlv_t *ret;
    uint8_t *p = packet_stream, byte, i;

    /* Min TLV len: flags, bsta_mld_mac, ap_mld_mac, flags2, reserved, aff_bsta_nr */
    PARSE_CHECK_MIN_LEN(1 + 6 + 6 + 1 + 17 + 1);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_BACKHAUL_STA_MLD_CONFIGURATION;

    _E1B(&p, &byte);
    ret->bsta_mld_mac_valid = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;
    ret->ap_mld_mac_valid   = (byte & BIT_MASK_6) ? SET_BIT : RESET_BIT;

    _EnB(&p, ret->bsta_mld_mac, ETHER_ADDR_LEN);
    _EnB(&p, ret->ap_mld_mac,   ETHER_ADDR_LEN);

    _E1B(&p, &byte);
    ret->str   = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;
    ret->nstr  = (byte & BIT_MASK_6) ? SET_BIT : RESET_BIT;
    ret->emlsr = (byte & BIT_MASK_5) ? SET_BIT : RESET_BIT;
    ret->emlmr = (byte & BIT_MASK_4) ? SET_BIT : RESET_BIT;

    /* Skip 17 reserved bytes */
    p += 17;

    _E1B(&p, &ret->aff_bsta_nr);
    PARSE_LIMIT(ret->aff_bsta_nr, MAX_MLD_AFF_APSTA);

    for (i = 0; i < ret->aff_bsta_nr; i++) {
         _E1B(&p, &byte);
         ret->aff_bstas[i].aff_bsta_mac_valid = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;

        _EnB(&p, ret->aff_bstas[i].radio_id,     ETHER_ADDR_LEN);
        _EnB(&p, ret->aff_bstas[i].aff_bsta_mac, ETHER_ADDR_LEN);

        /* Skip 19 reserved bytes */
        p += 19;
    }

    PARSE_CHECK_INTEGRITY(bsta_mld_conf)
    PARSE_RETURN
}

static uint8_t* forge_bsta_mld_conf_tlv(void *memory_structure, uint16_t *len)
{
    map_bsta_mld_conf_tlv_t *m = memory_structure;
    uint8_t  *ret, *p, i, byte;

    /* Calculate TLV length */
    uint16_t tlv_length = 6 + 6 + 1 + 18 + 1; /* flags, bsta_mld_mac, ap_mld_mac, flags2, reserved, aff_bsta_nr */
    for (i = 0; i < m->aff_bsta_nr; i++) {
        tlv_length += 1 + 6 + 6 + 19; /* flags, radio_id, aff_bsta_mac, reserved */
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);

    byte = (m->bsta_mld_mac_valid << BIT_SHIFT_7) |
           (m->ap_mld_mac_valid   << BIT_SHIFT_6);
    _I1B(&byte, &p);

    _InB(m->bsta_mld_mac, &p, ETHER_ADDR_LEN);
    _InB(m->ap_mld_mac,   &p, ETHER_ADDR_LEN);

    byte = (m->str   << BIT_SHIFT_7) |
           (m->nstr  << BIT_SHIFT_6) |
           (m->emlsr << BIT_SHIFT_5) |
           (m->emlmr << BIT_SHIFT_4);
    _I1B(&byte, &p);

    FORGE_RESERVE(p, 17);

    _I1B(&m->aff_bsta_nr, &p);

    for (i = 0; i < m->aff_bsta_nr; i++) {
        byte = m->aff_bstas[i].aff_bsta_mac_valid << BIT_SHIFT_7;
        _I1B(&byte, &p);

        _InB(m->aff_bstas[i].radio_id,     &p, ETHER_ADDR_LEN);
        _InB(m->aff_bstas[i].aff_bsta_mac, &p, ETHER_ADDR_LEN);

        FORGE_RESERVE(p, 19);
    }

    FORGE_RETURN
}

/*#######################################################################
# Associated STA MLD Configuration TLV ("Section 17.2.98")              #
########################################################################*/
TLV_FREE_FUNCTION(assoc_sta_mld_conf) {}

static uint8_t* parse_assoc_sta_mld_conf_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_assoc_sta_mld_conf_tlv_t *ret;
    uint8_t *p = packet_stream, byte, i;

    /* Min TLV len: sta_mld_mac, ap_mld_mac, flags, reserved, aff_sta_nr */
    PARSE_CHECK_MIN_LEN(6 + 6 + 1 + 18 + 1);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_ASSOCIATED_STA_MLD_CONFIGURATION;

    _EnB(&p, ret->sta_mld_mac, ETHER_ADDR_LEN);
    _EnB(&p, ret->ap_mld_mac,  ETHER_ADDR_LEN);

    _E1B(&p, &byte);
    ret->str   = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;
    ret->nstr  = (byte & BIT_MASK_6) ? SET_BIT : RESET_BIT;
    ret->emlsr = (byte & BIT_MASK_5) ? SET_BIT : RESET_BIT;
    ret->emlmr = (byte & BIT_MASK_4) ? SET_BIT : RESET_BIT;

    /* Skip 18 reserved bytes */
    p += 18;

    _E1B(&p, &ret->aff_sta_nr);
    PARSE_LIMIT(ret->aff_sta_nr, MAX_MLD_AFF_APSTA);

    for (i = 0; i < ret->aff_sta_nr; i++) {
        _EnB(&p, ret->aff_stas[i].bssid,       ETHER_ADDR_LEN);
        _EnB(&p, ret->aff_stas[i].aff_sta_mac, ETHER_ADDR_LEN);

        /* Skip 19 reserved bytes */
        p += 19;
    }

    PARSE_CHECK_INTEGRITY(assoc_sta_mld_conf)
    PARSE_RETURN
}

static uint8_t* forge_assoc_sta_mld_conf_tlv(void *memory_structure, uint16_t *len)
{
    map_assoc_sta_mld_conf_tlv_t *m = memory_structure;
    uint8_t  *ret, *p, i, byte;

    /* Calculate TLV length */
    uint16_t tlv_length = 6 + 6 + 1 + 18 + 1; /* sta_mld_mac, ap_mld_mac, flags, reserved, aff_sta_nr */
    for (i = 0; i < m->aff_sta_nr; i++) {
        tlv_length += 6 + 6 + 19; /* bssid, aff_sta_mac, reserved */
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);

    _InB(m->sta_mld_mac, &p, ETHER_ADDR_LEN);
    _InB(m->ap_mld_mac, &p, ETHER_ADDR_LEN);

    byte = (m->str   << BIT_SHIFT_7) |
           (m->nstr  << BIT_SHIFT_6) |
           (m->emlsr << BIT_SHIFT_5) |
           (m->emlmr << BIT_SHIFT_4);
    _I1B(&byte, &p);

    FORGE_RESERVE(p, 18);

    _I1B(&m->aff_sta_nr, &p);

    for (i = 0; i < m->aff_sta_nr; i++) {
        _InB(m->aff_stas[i].bssid, &p, ETHER_ADDR_LEN);
        _InB(m->aff_stas[i].aff_sta_mac, &p, ETHER_ADDR_LEN);

        FORGE_RESERVE(p, 19);
    }

    FORGE_RETURN
}

/*#######################################################################
# Affiliated STA Metrics TLV ("Section 17.2.100")                       #
########################################################################*/
TLV_FREE_FUNCTION(aff_sta_metrics) {}

static uint8_t* parse_aff_sta_metrics_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_aff_sta_metrics_tlv_t *ret;
    uint8_t *p = packet_stream;

    /* Min TLV len: sta_mac and 5 4-byte fields */
    PARSE_CHECK_MIN_LEN(6 + 5 * 4);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_AFFILIATED_STA_METRICS;

    _EnB(&p, ret->sta_mac, ETHER_ADDR_LEN);
    _E4B(&p, &ret->tx_bytes);
    _E4B(&p, &ret->rx_bytes);
    _E4B(&p, &ret->tx_packets);
    _E4B(&p, &ret->rx_packets);
    _E4B(&p, &ret->tx_packet_errors);

    /* According to R6 standard, now 998 reserved bytes follow. We are not checking that
       as it looks like a standard oversight
    */
    ret->reserved_len = len - (p - packet_stream);
    p += ret->reserved_len;

    PARSE_CHECK_INTEGRITY(aff_sta_metrics)
    PARSE_RETURN
}

static uint8_t* forge_aff_sta_metrics_tlv(void *memory_structure, uint16_t *len)
{
    map_aff_sta_metrics_tlv_t *m = memory_structure;
    uint8_t  *ret, *p;

    /* Calculate TLV length */
    uint16_t tlv_length = 6 + 5 * 4 + m->reserved_len; /* sta_mac, 5 4-byte fields, reserved */

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,         &p);
    _I2B(&tlv_length,          &p);
    _InB(m->sta_mac,           &p, ETHER_ADDR_LEN);
    _I4B(&m->tx_bytes,         &p);
    _I4B(&m->rx_bytes,         &p);
    _I4B(&m->tx_packets,       &p);
    _I4B(&m->rx_packets,       &p);
    _I4B(&m->tx_packet_errors, &p);

    FORGE_RESERVE(p, m->reserved_len);

    FORGE_RETURN
}

/*#######################################################################
# Affiliated AP Metrics TLV ("Section 17.2.101")                        #
########################################################################*/
TLV_FREE_FUNCTION(aff_ap_metrics) {}

static uint8_t* parse_aff_ap_metrics_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_aff_ap_metrics_tlv_t *ret;
    uint8_t *p = packet_stream;

    /* Min TLV len: bssid and 9 4-byte fields */
    PARSE_CHECK_MIN_LEN(6 + 9 * 4);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_AFFILIATED_AP_METRICS;

    _EnB(&p, ret->bssid, ETHER_ADDR_LEN);
    _E4B(&p, &ret->tx_packets);
    _E4B(&p, &ret->rx_packets);
    _E4B(&p, &ret->tx_packet_errors);
    _E4B(&p, &ret->tx_ucast_bytes);
    _E4B(&p, &ret->rx_ucast_bytes);
    _E4B(&p, &ret->tx_mcast_bytes);
    _E4B(&p, &ret->rx_mcast_bytes);
    _E4B(&p, &ret->tx_bcast_bytes);
    _E4B(&p, &ret->rx_bcast_bytes);

    /* According to R6 standard, now 988 reserved bytes follow. We are not checking that
       as it looks like a standard oversight
    */
    ret->reserved_len = len - (p - packet_stream);
    p += ret->reserved_len;

    PARSE_CHECK_INTEGRITY(aff_ap_metrics)
    PARSE_RETURN
}

static uint8_t* forge_aff_ap_metrics_tlv(void *memory_structure, uint16_t *len)
{
    map_aff_ap_metrics_tlv_t *m = memory_structure;
    uint8_t  *ret, *p;

    /* Calculate TLV length */
    uint16_t tlv_length = 6 + 9 * 4 + m->reserved_len; /* bssid, 9 4-byte fields, reserved */

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,         &p);
    _I2B(&tlv_length,          &p);
    _InB(m->bssid,             &p, ETHER_ADDR_LEN);
    _I4B(&m->tx_packets,       &p);
    _I4B(&m->rx_packets,       &p);
    _I4B(&m->tx_packet_errors, &p);
    _I4B(&m->tx_ucast_bytes,   &p);
    _I4B(&m->rx_ucast_bytes,   &p);
    _I4B(&m->tx_mcast_bytes,   &p);
    _I4B(&m->rx_mcast_bytes,   &p);
    _I4B(&m->tx_bcast_bytes,   &p);
    _I4B(&m->rx_bcast_bytes,   &p);

    FORGE_RESERVE(p, m->reserved_len);

    FORGE_RETURN
}

/*#######################################################################
# EHT Operations TLV ("Section 17.2.103")                               #
########################################################################*/
TLV_FREE_FUNCTION(eht_operations) {}

static uint8_t* parse_eht_operations_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_eht_operations_tlv_t *ret;
    uint8_t *p = packet_stream, byte, i, j;

    /* Min TLV len: Reserved(32) + radio_nr */
    PARSE_CHECK_MIN_LEN(33);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_EHT_OPERATIONS;

    _EnB(&p, &ret->reserved, 32);

    _E1B(&p, &ret->radios_nr);
    PARSE_LIMIT(ret->radios_nr, MAX_RADIO_PER_AGENT);
    for (i = 0; i < ret->radios_nr; i++) {
        _EnB(&p, ret->radios[i].ruid, ETHER_ADDR_LEN);

        _E1B(&p, &ret->radios[i].bsss_nr);
        for (j = 0; j < ret->radios[i].bsss_nr; j++) {
            _EnB(&p, ret->radios[i].bsss[j].bssid, ETHER_ADDR_LEN);

            _E1B(&p, &byte);
            ret->radios[i].bsss[j].eht_ops.eht_op_info_valid               = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;
            ret->radios[i].bsss[j].eht_ops.disabled_subchan_valid          = (byte & BIT_MASK_6) ? SET_BIT : RESET_BIT;
            ret->radios[i].bsss[j].eht_ops.eht_default_pe_duration         = (byte & BIT_MASK_5) ? SET_BIT : RESET_BIT;
            ret->radios[i].bsss[j].eht_ops.group_addr_bu_indication_limit  = (byte & BIT_MASK_4) ? SET_BIT : RESET_BIT;
            ret->radios[i].bsss[j].eht_ops.group_addr_bu_indication_exp    = (byte & (BIT_MASK_3 | BIT_MASK_2)) >> BIT_SHIFT_2;

            _EnB(&p, &ret->radios[i].bsss[j].eht_ops.basic_eht_mcs_nss, 4);
            _E1B(&p, &ret->radios[i].bsss[j].eht_ops.control);
            _E1B(&p, &ret->radios[i].bsss[j].eht_ops.ccfs0);
            _E1B(&p, &ret->radios[i].bsss[j].eht_ops.ccfs1);
            _E2B(&p, &ret->radios[i].bsss[j].eht_ops.disabled_subchan_bitmap);
            _EnB(&p, &ret->radios[i].bsss[j].reserved, 16);
        }
        _EnB(&p, &ret->radios[i].reserved, 25);
    }

    PARSE_CHECK_INTEGRITY(eht_operations)
    PARSE_RETURN
}

static uint8_t* forge_eht_operations_tlv(void *memory_structure, uint16_t *len)
{
    map_eht_operations_tlv_t *m = memory_structure;
    uint8_t  *ret, *p, i, j, byte;

    /* Calculate TLV length */
    uint16_t tlv_length = 33; /*  Reserved(32) + radios_nr */
    for (i = 0; i < m->radios_nr; i++) {
        tlv_length += 6 + 1 + 25; /* ruid, bsss_br, reserved */
        for (j = 0; j < m->radios[i].bsss_nr; j++) {
            tlv_length += 6 + 1 + 4 + 1 + 1 + 1 + 2 + 16; /* bssid, eht_op, mcs_nss , control, ccfs0, ccfs1, subchan_bitmap, reserved */
        }
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,   &p);
    _I2B(&tlv_length,    &p);
    _InB(&m->reserved,   &p, 32);

    _I1B(&m->radios_nr,  &p);
    for (i = 0; i < m->radios_nr; i++) {
        _InB(&m->radios[i].ruid,     &p, ETHER_ADDR_LEN);

        _I1B(&m->radios[i].bsss_nr,  &p);
        for (j = 0; j < m->radios[i].bsss_nr; j++) {
            _InB(&m->radios[i].bsss[j].bssid,     &p, ETHER_ADDR_LEN);

            byte = (m->radios[i].bsss[j].eht_ops.eht_op_info_valid                << BIT_SHIFT_7) |
                   (m->radios[i].bsss[j].eht_ops.disabled_subchan_valid           << BIT_SHIFT_6) |
                   (m->radios[i].bsss[j].eht_ops.eht_default_pe_duration          << BIT_SHIFT_5) |
                   (m->radios[i].bsss[j].eht_ops.group_addr_bu_indication_limit   << BIT_SHIFT_4) |
                   (m->radios[i].bsss[j].eht_ops.group_addr_bu_indication_exp     << BIT_SHIFT_2);
            _I1B(&byte, &p);

            _I4B(&m->radios[i].bsss[j].eht_ops.basic_eht_mcs_nss,       &p);
            _I1B(&m->radios[i].bsss[j].eht_ops.control,                 &p);
            _I1B(&m->radios[i].bsss[j].eht_ops.ccfs0,                   &p);
            _I1B(&m->radios[i].bsss[j].eht_ops.ccfs1,                   &p);
            _I2B(&m->radios[i].bsss[j].eht_ops.disabled_subchan_bitmap, &p);

            _InB(&m->radios[i].bsss[j].reserved, &p, 16);
        }

    }

    FORGE_RETURN
}

/*#################################################################################
#      AVAILABLE SPECTRUM INQUIRY REQUEST TLV ("Section 17.2.104")                #
##################################################################################*/
TLV_FREE_FUNCTION(available_spec_inq_req) {}

static uint8_t* parse_available_spec_inq_req_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_available_spec_inq_req_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_MIN_LEN(1)

    /* Allocate struct and request frame */
    ret = calloc(1, sizeof(*ret) + len);
    if (NULL == ret) {
        return NULL;
    }

    ret->tlv_type  = TLV_TYPE_AVAILABLE_SPECTRUM_INQUIRY_REQUEST;
    ret->req_len = len;
    ret->req     = (uint8_t *)(ret + 1);
    _EnB(&p, ret->req, ret->req_len);

    PARSE_CHECK_INTEGRITY(available_spec_inq_req)
    PARSE_RETURN
}

static uint8_t* forge_available_spec_inq_req_tlv(void *memory_structure, uint16_t *len)
{
    map_available_spec_inq_req_tlv_t *m = memory_structure;
    uint16_t tlv_length = m->req_len;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _InB(m->req, &p, m->req_len);

    FORGE_RETURN
}

/*#################################################################################
#      AVAILABLE SPECTRUM INQUIRY RESPONSE TLV ("Section 17.2.105")               #
##################################################################################*/
TLV_FREE_FUNCTION(available_spec_inq_resp) {}

static uint8_t* parse_available_spec_inq_resp_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_available_spec_inq_resp_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_MIN_LEN(1)

    /* Allocate struct and response frame */
    ret = calloc(1, sizeof(*ret) + len);
    if (NULL == ret) {
        return NULL;
    }

    ret->tlv_type  = TLV_TYPE_AVAILABLE_SPECTRUM_INQUIRY_RESPONSE;
    ret->resp_len = len;
    ret->resp     = (uint8_t *)(ret + 1);
    _EnB(&p, ret->resp, ret->resp_len);

    PARSE_CHECK_INTEGRITY(available_spec_inq_resp)
    PARSE_RETURN
}

static uint8_t* forge_available_spec_inq_resp_tlv(void *memory_structure, uint16_t *len)
{
    map_available_spec_inq_resp_tlv_t *m = memory_structure;
    uint16_t tlv_length = m->resp_len;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _InB(m->resp, &p, m->resp_len);

    FORGE_RETURN
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
void map_r6_register_tlvs(void)
{
    I1905_REGISTER_TLV(TLV_TYPE_WIFI7_AGENT_CAPABILITIES,                           wifi7_agent_cap             );
    I1905_REGISTER_TLV(TLV_TYPE_AGENT_AP_MLD_CONFIGURATION,                         agent_ap_mld_conf           );
    I1905_REGISTER_TLV(TLV_TYPE_BACKHAUL_STA_MLD_CONFIGURATION,                     bsta_mld_conf               );
    I1905_REGISTER_TLV(TLV_TYPE_ASSOCIATED_STA_MLD_CONFIGURATION,                   assoc_sta_mld_conf          );
    I1905_REGISTER_TLV(TLV_TYPE_AFFILIATED_STA_METRICS,                             aff_sta_metrics             );
    I1905_REGISTER_TLV(TLV_TYPE_AFFILIATED_AP_METRICS,                              aff_ap_metrics              );
    I1905_REGISTER_TLV(TLV_TYPE_EHT_OPERATIONS,                                     eht_operations              );
    I1905_REGISTER_TLV(TLV_TYPE_AVAILABLE_SPECTRUM_INQUIRY_REQUEST,                 available_spec_inq_req      );
    I1905_REGISTER_TLV(TLV_TYPE_AVAILABLE_SPECTRUM_INQUIRY_RESPONSE,                available_spec_inq_resp     );
}
