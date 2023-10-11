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
# Channel scan reporting policy TLV ("Section 17.2.37")                 #
########################################################################*/
TLV_FREE_FUNCTION(channel_scan_reporting_policy) {}

static uint8_t* parse_channel_scan_reporting_policy_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_channel_scan_reporting_policy_tlv_t *ret;
    uint8_t *p = packet_stream, byte;

    PARSE_CHECK_EXP_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_CHANNEL_SCAN_REPORTING_POLICY;

    _E1B(&p, &byte);
    ret->report_independent_ch_scans = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;

    PARSE_CHECK_INTEGRITY(channel_scan_reporting_policy)
    PARSE_RETURN
}

static uint8_t* forge_channel_scan_reporting_policy_tlv(void *memory_structure, uint16_t *len)
{
    map_channel_scan_reporting_policy_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 1;
    uint8_t  *ret, *p, byte;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);

    byte = (m->report_independent_ch_scans << BIT_SHIFT_7);
    _I1B(&byte, &p);

    FORGE_RETURN
}

/*#######################################################################
# Channel scan capabilities TLV ("Section 17.2.38")                     #
########################################################################*/
TLV_FREE_FUNCTION(channel_scan_cap) {}

static uint8_t* parse_channel_scan_cap_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_channel_scan_cap_tlv_t *ret;
    uint8_t i, j, k, byte, channels_nr, channel;
    uint8_t *p = packet_stream;

    PARSE_CHECK_MIN_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_CHANNEL_SCAN_CAPABILITIES;

    _E1B(&p, &ret->radios_nr);
    PARSE_LIMIT(ret->radios_nr, MAX_RADIO_PER_AGENT);

    for (i=0; i < ret->radios_nr; i++) {
        _EnB(&p, &ret->radios[i].radio_id, 6);
        _E1B(&p, &byte);
        ret->radios[i].boot_only   = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;
        ret->radios[i].scan_impact = (byte & (BIT_MASK_6 | BIT_MASK_5)) >> BIT_SHIFT_5;

        _E4B(&p, &ret->radios[i].min_scan_interval);
        _E1B(&p, &ret->radios[i].op_classes_nr);
        PARSE_LIMIT(ret->radios[i].op_classes_nr, MAX_OP_CLASS);

        for (j = 0; j < ret->radios[i].op_classes_nr; j++) {
            _E1B(&p, &ret->radios[i].op_classes[j].op_class);
            _E1B(&p, &channels_nr);
            PARSE_LIMIT(channels_nr, MAX_CHANNEL_PER_OP_CLASS);
            for (k = 0; k < channels_nr; k++) {
                _E1B(&p, &channel);
                map_cs_set(&ret->radios[i].op_classes[j].channels, channel);
            }
        }
    }

    PARSE_CHECK_INTEGRITY(channel_scan_cap)
    PARSE_RETURN
}

static uint8_t* forge_channel_scan_cap_tlv(void *memory_structure, uint16_t *len)
{
    map_channel_scan_cap_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i, j, byte, channels_nr, channel;

    /* Calculate TLV length */
    tlv_length = 1; /* radios_nr */
    for (i = 0; i < m->radios_nr; i++) {
        tlv_length += 6 + 1 + 4 + 1; /* radio_id, scan_cap_flag, min_scan_interval, op_classes_nr */
        for (j = 0; j < m->radios[i].op_classes_nr; j++) {
            tlv_length += 1 + 1 + map_cs_nr(&m->radios[i].op_classes[j].channels); /* op_class + channels_nr + channels */
        }
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,     &p);
    _I2B(&tlv_length,      &p);
    _I1B(&m->radios_nr, &p);

    for (i = 0; i < m->radios_nr; i++) {
        _InB(m->radios[i].radio_id, &p, 6);

        byte = (m->radios[i].boot_only   << BIT_SHIFT_7) |
               (m->radios[i].scan_impact << BIT_SHIFT_5);
        _I1B(&byte,                           &p);
        _I4B(&m->radios[i].min_scan_interval, &p);
        _I1B(&m->radios[i].op_classes_nr,     &p);

        for (j = 0; j < m->radios[i].op_classes_nr; j++) {
            channels_nr = map_cs_nr(&m->radios[i].op_classes[j].channels);

            _I1B(&m->radios[i].op_classes[j].op_class, &p);
            _I1B(&channels_nr,                         &p);
            map_cs_foreach(&m->radios[i].op_classes[j].channels, channel) {
                _I1B(&channel, &p);
            }
        }
    }

    FORGE_RETURN
}

/*#######################################################################
# Channel scan request TLV ("Section 17.2.39")                          #
########################################################################*/
TLV_FREE_FUNCTION(channel_scan_request) {}

static uint8_t* parse_channel_scan_request_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_channel_scan_request_tlv_t *ret;
    uint8_t i, j, k, byte, channels_nr, channel;
    uint8_t *p = packet_stream;

    PARSE_CHECK_MIN_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_CHANNEL_SCAN_REQUEST;

    _E1B(&p, &byte);
    ret->fresh_scan_performed = (byte & BIT_MASK_7) ? 1 : 0;
    _E1B(&p, &ret->radios_nr);
    PARSE_LIMIT(ret->radios_nr, MAX_RADIO_PER_AGENT)

    for (i = 0; i < ret->radios_nr; i++) {
        _EnB(&p, ret->radios[i].radio_id, 6);
        _E1B(&p, &ret->radios[i].op_classes_nr);
        PARSE_LIMIT(ret->radios[i].op_classes_nr, MAX_OP_CLASS);

        for (j = 0; j < ret->radios[i].op_classes_nr; j++) {
            _E1B(&p, &ret->radios[i].op_classes[j].op_class);
            _E1B(&p, &channels_nr);
            PARSE_LIMIT(channels_nr, MAX_CHANNEL_PER_OP_CLASS);
            for (k = 0; k < channels_nr; k++) {
                _E1B(&p, &channel);
                map_cs_set(&ret->radios[i].op_classes[j].channels, channel);
            }
        }
    }

    PARSE_CHECK_INTEGRITY(channel_scan_request)
    PARSE_RETURN
}

static uint8_t* forge_channel_scan_request_tlv(void *memory_structure, uint16_t *len)
{
    map_channel_scan_request_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i, j, byte, channels_nr, channel;

    /* Calculate TLV length */
    tlv_length = 2; /* flags + radios_nr */
    for (i = 0; i < m->radios_nr; i++) {
        tlv_length += 6 + 1; /* radio_id + op_classes_nr */
        for (j = 0; j < m->radios[i].op_classes_nr; j++) {
            tlv_length += 1 + 1 + map_cs_nr(&m->radios[i].op_classes[j].channels); /* op_class+ channels_nr + channels */
        }
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);

    byte = (m->fresh_scan_performed & BIT_MASK_0) << BIT_SHIFT_7;
    _I1B(&byte,         &p);
    _I1B(&m->radios_nr, &p);

    for (i = 0; i < m->radios_nr; i++) {
        _InB(&m->radios[i].radio_id,       &p, 6);
        _I1B(&m->radios[i].op_classes_nr, &p);
        for (j = 0; j < m->radios[i].op_classes_nr; j++) {
            channels_nr = map_cs_nr(&m->radios[i].op_classes[j].channels);

            _I1B(&m->radios[i].op_classes[j].op_class, &p);
            _I1B(&channels_nr,                         &p);
            map_cs_foreach(&m->radios[i].op_classes[j].channels, channel) {
                _I1B(&channel, &p);
            }
        }
    }

    FORGE_RETURN
}

/*#######################################################################
# Channel scan result TLV ("Section 17.2.40")                           #
########################################################################*/
TLV_FREE_FUNCTION(channel_scan_result)
{
    SFREE(m->neighbors);
}

static uint8_t* parse_channel_scan_result_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_channel_scan_result_tlv_t *ret;
    uint16_t i;
    uint8_t  *p = packet_stream, byte;

    PARSE_CHECK_MIN_LEN(9)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_CHANNEL_SCAN_RESULT;

    _EnB(&p, &ret->radio_id, 6);
    _E1B(&p, &ret->op_class);
    _E1B(&p, &ret->channel);
    _E1B(&p, &ret->scan_status);
    if (ret->scan_status != 0x00) {
        PARSE_RETURN
    }

    _E1B(&p, &ret->timestamp_len);
    PARSE_LIMIT_N_DROP(channel_scan_result, ret->timestamp_len, MAX_1905_TIMESTAMP_LEN)

    _EnB(&p, &ret->timestamp, ret->timestamp_len);
    _E1B(&p, &ret->utilization);
    _E1B(&p, &ret->noise);
    _E2B(&p, &ret->neighbors_nr);
    if (ret->neighbors_nr != 0) {
        /* Add neighbors */
        ret->neighbors = calloc(ret->neighbors_nr, sizeof(*ret->neighbors));
        if (ret->neighbors == NULL) {
            free(ret);
            return NULL;
        }

        for (i = 0; i < ret->neighbors_nr; i++) {
            _EnB(&p, ret->neighbors[i].bssid, 6);
            _E1B(&p, &ret->neighbors[i].ssid_len);
            PARSE_LIMIT_N_DROP(channel_scan_result, ret->neighbors[i].ssid_len, (MAX_SSID_LEN - 1))

            _EnB(&p, ret->neighbors[i].ssid, ret->neighbors[i].ssid_len);
            _E1B(&p, &ret->neighbors[i].rcpi);
            _E1B(&p, &ret->neighbors[i].ch_bw_len);
            PARSE_LIMIT_N_DROP(channel_scan_result, ret->neighbors[i].ch_bw_len, MAX_CH_BW_STR_LEN)

            _EnB(&p, ret->neighbors[i].ch_bw, ret->neighbors[i].ch_bw_len);
            _E1B(&p, &byte);
            ret->neighbors[i].bss_load_elem_present = (byte & BIT_MASK_7) >> BIT_SHIFT_7;
            if (ret->neighbors[i].bss_load_elem_present) {
                _E1B(&p, &ret->neighbors[i].channel_utilization);
                _E2B(&p, &ret->neighbors[i].stas_nr);
            }
        }
    }

    _E4B(&p, &ret->aggregate_scan_duration);
    _E1B(&p, &byte);
    ret->scan_type = (byte & BIT_MASK_7) >> BIT_SHIFT_7;

    PARSE_CHECK_INTEGRITY(channel_scan_result)
    PARSE_RETURN
}

static uint8_t* forge_channel_scan_result_tlv(void *memory_structure, uint16_t *len)
{
    map_channel_scan_result_tlv_t *m = memory_structure;
    uint16_t  i, tlv_length;
    uint8_t  *ret, *p, byte;

    /* Calculate TLV length */
    tlv_length = 6 + 1 + 1 + 1; /* radio_id + op_class + channel + status */
    if (m->scan_status == 0) {
        tlv_length += 1 + m->timestamp_len; /* timestamp_len + timestamp */
        tlv_length += 1 + 1 + 2;            /* utilization + noise + neighbors */
        for (i = 0; i < m->neighbors_nr; i++) {
            tlv_length += 6 + 1 + m->neighbors[i].ssid_len + 1 + 1 + m->neighbors[i].ch_bw_len ; /* bssid + ssid_len + ssid + rcpi + ch_bw_len + ch_bw */
            tlv_length += 1 + (m->neighbors[i].bss_load_elem_present ? 3 : 0);                   /* bss_load_flag + channel_util + stas_nr */
        }
    }
    tlv_length += 4 + 1; /* scan_duration + scan_type */

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,    &p);
    _I2B(&tlv_length,     &p);
    _InB(m->radio_id,     &p, 6);
    _I1B(&m->op_class,    &p);
    _I1B(&m->channel,     &p);
    _I1B(&m->scan_status, &p);
    if (m->scan_status != 0x00) {
        FORGE_RETURN
    }

    _I1B(&m->timestamp_len, &p);
    _InB(m->timestamp,      &p, m->timestamp_len);
    _I1B(&m->utilization,   &p);
    _I1B(&m->noise,         &p);
    _I2B(&m->neighbors_nr,  &p);

    for (i = 0; i < m->neighbors_nr; i++) {
        _InB(m->neighbors[i].bssid,      &p, 6);
        _I1B(&m->neighbors[i].ssid_len,  &p);
        _InB(m->neighbors[i].ssid,       &p, m->neighbors[i].ssid_len);
        _I1B(&m->neighbors[i].rcpi,      &p);
        _I1B(&m->neighbors[i].ch_bw_len, &p);
        _InB(m->neighbors[i].ch_bw,      &p, m->neighbors[i].ch_bw_len);

        byte = (m->neighbors[i].bss_load_elem_present << BIT_SHIFT_7);
        _I1B(&byte, &p);
        if (m->neighbors[i].bss_load_elem_present) {
            _I1B(&m->neighbors[i].channel_utilization, &p);
            _I2B(&m->neighbors[i].stas_nr,             &p);
        }
    }

    _I4B(&m->aggregate_scan_duration, &p);
     byte = (m->scan_type << BIT_SHIFT_7);
    _I1B(&byte, &p);

    FORGE_RETURN
}

/*#######################################################################
# Timestamp TLV ("Section 17.2.41")                                     #
########################################################################*/
TLV_FREE_FUNCTION(timestamp) {}

static uint8_t* parse_timestamp_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_timestamp_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_MIN_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_TIMESTAMP;

    _E1B(&p, &ret->timestamp_len);
    PARSE_LIMIT(ret->timestamp_len, MAX_1905_TIMESTAMP_LEN);
    _EnB(&p, &ret->timestamp, ret->timestamp_len);

    PARSE_CHECK_INTEGRITY(timestamp)
    PARSE_RETURN
}

static uint8_t* forge_timestamp_tlv(void *memory_structure, uint16_t *len)
{
    map_timestamp_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 1 + m->timestamp_len;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,      &p);
    _I2B(&tlv_length,       &p);
    _I1B(&m->timestamp_len, &p);
    _InB(m->timestamp,      &p, m->timestamp_len);

    FORGE_RETURN
}

/*#######################################################################
# CAC request TLV ("Section 17.2.42")                                   #
########################################################################*/
TLV_FREE_FUNCTION(cac_request) {}

static uint8_t* parse_cac_request_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_cac_request_tlv_t *ret;
    uint8_t *p = packet_stream, i, byte;

    PARSE_CHECK_MIN_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_CAC_REQUEST;

    _E1B(&p, &ret->radios_nr);
    PARSE_LIMIT(ret->radios_nr, MAX_RADIO_PER_AGENT);

    for (i = 0; i < ret->radios_nr; i++) {
        _EnB(&p, ret->radios[i].radio_id, 6);
        _E1B(&p, &ret->radios[i].op_class);
        _E1B(&p, &ret->radios[i].channel);
        _E1B(&p, &byte);
        ret->radios[i].cac_method = (byte & (BIT_MASK_7 | BIT_MASK_6 | BIT_MASK_5)) >> BIT_SHIFT_5;
        ret->radios[i].cac_completion_action = (byte & (BIT_MASK_4 | BIT_MASK_3)) >> BIT_SHIFT_3;
    }

    PARSE_CHECK_INTEGRITY(cac_request)
    PARSE_RETURN
}

static uint8_t* forge_cac_request_tlv(void *memory_structure, uint16_t *len)
{
    map_cac_request_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 1 + m->radios_nr * (6 + 1 + 1 + 1); /* radios_nr + radios_nr * (radio_id + op_class + channel + flags) */
    uint8_t  *ret, *p, i, byte;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,  &p);
    _I2B(&tlv_length,   &p);
    _I1B(&m->radios_nr, &p);

    for (i = 0; i < m->radios_nr; i++) {
        _InB(&m->radios[i].radio_id, &p, 6);
        _I1B(&m->radios[i].op_class, &p);
        _I1B(&m->radios[i].channel,  &p);

        byte = (m->radios[i].cac_method << BIT_SHIFT_5) |
               (m->radios[i].cac_completion_action << BIT_SHIFT_3);
        _I1B(&byte, &p);
    }

    FORGE_RETURN
}

/*#######################################################################
# CAC termination TLV ("Section 17.2.43")                               #
########################################################################*/
TLV_FREE_FUNCTION(cac_termination) {}

static uint8_t* parse_cac_termination_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_cac_termination_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    PARSE_CHECK_MIN_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_CAC_TERMINATION;

    _E1B(&p, &ret->radios_nr);
    PARSE_LIMIT(ret->radios_nr, MAX_RADIO_PER_AGENT);

    for (i = 0; i < ret->radios_nr; i++) {
        _EnB(&p, ret->radios[i].radio_id, 6);
        _E1B(&p, &ret->radios[i].op_class);
        _E1B(&p, &ret->radios[i].channel);
    }

    PARSE_CHECK_INTEGRITY(cac_termination)
    PARSE_RETURN
}

static uint8_t* forge_cac_termination_tlv(void *memory_structure, uint16_t *len)
{
    map_cac_termination_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 1 + m->radios_nr * (6 + 1 + 1); /* radios_nr + radios_nr * (radio_id + op_class + channel) */
    uint8_t  *ret, *p, i;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,  &p);
    _I2B(&tlv_length,   &p);
    _I1B(&m->radios_nr, &p);

    for (i = 0; i < m->radios_nr; i++) {
        _InB(&m->radios[i].radio_id, &p, 6);
        _I1B(&m->radios[i].op_class, &p);
        _I1B(&m->radios[i].channel,  &p);
    }

    FORGE_RETURN
}

/*#######################################################################
# CAC completion report TLV ("Section 17.2.44")                         #
########################################################################*/
TLV_FREE_FUNCTION(cac_completion_report)
{
    uint8_t i;

    for (i = 0; i < m->radios_nr; i++) {
        SFREE(m->radios[i].detected_pairs);
    }
}

static uint8_t* parse_cac_completion_report_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_cac_completion_report_tlv_t *ret;
    uint8_t *p = packet_stream, i, j;

    PARSE_CHECK_MIN_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_CAC_COMPLETION_REPORT;

    _E1B(&p, &ret->radios_nr);
    PARSE_LIMIT(ret->radios_nr, MAX_RADIO_PER_AGENT);

    for (i = 0; i < ret->radios_nr; i++) {
        _EnB(&p, ret->radios[i].radio_id, 6);
        _E1B(&p, &ret->radios[i].op_class);
        _E1B(&p, &ret->radios[i].channel);
        _E1B(&p, &ret->radios[i].status);
        _E1B(&p, &ret->radios[i].detected_pairs_nr);

        if (ret->radios[i].detected_pairs_nr > 0) {
            ret->radios[i].detected_pairs = calloc(ret->radios[i].detected_pairs_nr, sizeof(*ret->radios[i].detected_pairs));
            if (ret->radios[i].detected_pairs == NULL) {
                PARSE_FREE_RET_RETURN(cac_completion_report)
            }

            for (j = 0; j < ret->radios[i].detected_pairs_nr; j++) {
                _E1B(&p, &ret->radios[i].detected_pairs[j].op_class);
                _E1B(&p, &ret->radios[i].detected_pairs[j].channel);
            }
        }
    }

    PARSE_CHECK_INTEGRITY(cac_completion_report)
    PARSE_RETURN
}

static uint8_t* forge_cac_completion_report_tlv(void *memory_structure, uint16_t *len)
{
    map_cac_completion_report_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i, j;

    /* Calculate TLV length */
    tlv_length = 1; /* radios_nr */
    for (i = 0; i < m->radios_nr; i++) {
        tlv_length += 6 + 1 + 1 + 1 + 1; /* radio_id + op_class + channel + cac_status + pairs_nr */
        tlv_length += m->radios[i].detected_pairs_nr * (1 + 1); /* pairs_nr * (op_class + channel) */
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,  &p);
    _I2B(&tlv_length,   &p);
    _I1B(&m->radios_nr, &p);

    for (i = 0; i < m->radios_nr; i++) {
        _InB(&m->radios[i].radio_id,          &p, 6);
        _I1B(&m->radios[i].op_class,          &p);
        _I1B(&m->radios[i].channel,           &p);
        _I1B(&m->radios[i].status,            &p);
        _I1B(&m->radios[i].detected_pairs_nr, &p);

        for (j = 0; j < m->radios[i].detected_pairs_nr; j++) {
            _I1B(&m->radios[i].detected_pairs[j].op_class, &p);
            _I1B(&m->radios[i].detected_pairs[j].channel, &p);
        }
    }

    FORGE_RETURN
}

/*#######################################################################
# CAC status report TLV ("Section 17.2.45")                             #
########################################################################*/
TLV_FREE_FUNCTION(cac_status_report)
{
    SFREE(m->available_pairs);
    SFREE(m->non_occupancy_pairs);
    SFREE(m->ongoing_cac_pairs);
}

static uint8_t* parse_cac_status_report_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_cac_status_report_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    PARSE_CHECK_MIN_LEN(3)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_CAC_STATUS_REPORT;

    _E1B(&p, &ret->available_pairs_nr);
    if (ret->available_pairs_nr > 0) {
        ret->available_pairs = calloc(ret->available_pairs_nr, sizeof(*ret->available_pairs));
        if (ret->available_pairs == NULL) {
            PARSE_FREE_RET_RETURN(cac_status_report)
        }

        for (i = 0; i < ret->available_pairs_nr; i++) {
            _E1B(&p, &ret->available_pairs[i].op_class);
            _E1B(&p, &ret->available_pairs[i].channel);
            _E2B(&p, &ret->available_pairs[i].minutes_since_cac_completion);
        }
    }

    _E1B(&p, &ret->non_occupancy_pairs_nr);
    if (ret->non_occupancy_pairs_nr > 0) {
        ret->non_occupancy_pairs = calloc(ret->non_occupancy_pairs_nr, sizeof(*ret->non_occupancy_pairs));
        if (ret->non_occupancy_pairs == NULL) {
            PARSE_FREE_RET_RETURN(cac_status_report)
        }

        for (i = 0; i < ret->non_occupancy_pairs_nr; i++) {
            _E1B(&p, &ret->non_occupancy_pairs[i].op_class);
            _E1B(&p, &ret->non_occupancy_pairs[i].channel);
            _E2B(&p, &ret->non_occupancy_pairs[i].seconds_remaining_non_occupancy_duration);
        }
    }

    _E1B(&p, &ret->ongoing_cac_pairs_nr);
    if (ret->ongoing_cac_pairs_nr > 0) {
        ret->ongoing_cac_pairs = calloc(ret->ongoing_cac_pairs_nr, sizeof(*ret->ongoing_cac_pairs));
        if (ret->ongoing_cac_pairs == NULL) {
            PARSE_FREE_RET_RETURN(cac_status_report)
        }

        for (i = 0; i < ret->ongoing_cac_pairs_nr; i++) {
            _E1B(&p, &ret->ongoing_cac_pairs[i].op_class);
            _E1B(&p, &ret->ongoing_cac_pairs[i].channel);
            _E3B(&p, &ret->ongoing_cac_pairs[i].seconds_remaining_cac_completion);
        }
    }

    PARSE_CHECK_INTEGRITY(cac_status_report)
    PARSE_RETURN
}

static uint8_t* forge_cac_status_report_tlv(void *memory_structure, uint16_t *len)
{
    map_cac_status_report_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 3 + m->available_pairs_nr * 4 + m->non_occupancy_pairs_nr * 4 + m->ongoing_cac_pairs_nr * 5;
    uint8_t  *ret, *p, i;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);

    _I1B(&m->available_pairs_nr, &p);
    for (i = 0; i < m->available_pairs_nr; i++) {
        _I1B(&m->available_pairs[i].op_class,                     &p);
        _I1B(&m->available_pairs[i].channel,                      &p);
        _I2B(&m->available_pairs[i].minutes_since_cac_completion, &p);
    }

    _I1B(&m->non_occupancy_pairs_nr, &p);
    for (i = 0; i < m->non_occupancy_pairs_nr; i++) {
        _I1B(&m->non_occupancy_pairs[i].op_class,                                 &p);
        _I1B(&m->non_occupancy_pairs[i].channel,                                  &p);
        _I2B(&m->non_occupancy_pairs[i].seconds_remaining_non_occupancy_duration, &p);
    }

    _I1B(&m->ongoing_cac_pairs_nr, &p);
    for (i = 0; i < m->ongoing_cac_pairs_nr; i++) {
        _I1B(&m->ongoing_cac_pairs[i].op_class,                         &p);
        _I1B(&m->ongoing_cac_pairs[i].channel,                          &p);
        _I3B(&m->ongoing_cac_pairs[i].seconds_remaining_cac_completion, &p);
    }

    FORGE_RETURN
}

/*#######################################################################
# CAC capabilities TLV ("Section 17.2.46")                              #
########################################################################*/
TLV_FREE_FUNCTION(cac_cap) {}

static uint8_t* parse_cac_cap_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_cac_cap_tlv_t *ret;
    uint8_t i, j, k, l, channels_nr, channel;
    uint8_t *p = packet_stream;

    PARSE_CHECK_MIN_LEN(3)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_CAC_CAPABILITIES;

    _E2B(&p, &ret->country_code);
    _E1B(&p, &ret->radios_nr);
    PARSE_LIMIT(ret->radios_nr, MAX_RADIO_PER_AGENT)

    for (i = 0; i < ret->radios_nr; i++) {
        _EnB(&p, &ret->radios[i].radio_id, 6);
        _E1B(&p, &ret->radios[i].cac_methods_nr);

        for (j = 0; j < ret->radios[i].cac_methods_nr; j++) {
            _E1B(&p, &ret->radios[i].cac_methods[j].cac_method);
            _E3B(&p, &ret->radios[i].cac_methods[j].cac_duration);
            _E1B(&p, &ret->radios[i].cac_methods[j].op_classes_nr);
            PARSE_LIMIT(ret->radios[i].cac_methods[j].op_classes_nr, MAX_OP_CLASS);

            for (k = 0; k < ret->radios[i].cac_methods[j].op_classes_nr; k++) {
                _E1B(&p, &ret->radios[i].cac_methods[j].op_classes[k].op_class);
                _E1B(&p, &channels_nr);
                PARSE_LIMIT(channels_nr, MAX_CHANNEL_PER_OP_CLASS);
                for (l = 0; l < channels_nr; l++) {
                    _E1B(&p, &channel);
                    map_cs_set(&ret->radios[i].cac_methods[j].op_classes[k].channels, channel);
                }
            }
        }
    }

    PARSE_CHECK_INTEGRITY(cac_cap)
    PARSE_RETURN
}

static uint8_t* forge_cac_cap_tlv(void *memory_structure, uint16_t *len)
{
    map_cac_cap_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i, j, k, channels_nr, channel;

    /* Calculate TLV length */
    tlv_length = 2 + 1; /* country + radio_nr */
    for (i = 0; i < m->radios_nr; i++) {
        tlv_length += 6 + 1; /* radio_id + cac_methods_nr */
        for (j = 0; j < m->radios[i].cac_methods_nr; j++) {
            tlv_length += 1 + 3 + 1; /* cac_method + cac_duration + op_classes_nr */
            for (k = 0; k < m->radios[i].cac_methods[j].op_classes_nr; k++) {
                tlv_length += 1 + 1 + map_cs_nr(&m->radios[i].cac_methods[j].op_classes[k].channels); /* op_class + channels_nr + channels */
            }
        }
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,     &p);
    _I2B(&tlv_length,      &p);
    _I2B(&m->country_code, &p);
    _I1B(&m->radios_nr,    &p);

    for (i = 0; i < m->radios_nr; i++) {
        _InB(m->radios[i].radio_id,        &p, 6);
        _I1B(&m->radios[i].cac_methods_nr, &p);

        for (j = 0; j < m->radios[i].cac_methods_nr; j++) {
            _I1B(&m->radios[i].cac_methods[j].cac_method,    &p);
            _I3B(&m->radios[i].cac_methods[j].cac_duration,  &p);
            _I1B(&m->radios[i].cac_methods[j].op_classes_nr, &p);

            for (k = 0; k < m->radios[i].cac_methods[j].op_classes_nr; k++) {
                channels_nr = map_cs_nr(&m->radios[i].cac_methods[j].op_classes[k].channels);

                _I1B(&m->radios[i].cac_methods[j].op_classes[k].op_class, &p);
                _I1B(&channels_nr,                                        &p);
                map_cs_foreach(&m->radios[i].cac_methods[j].op_classes[k].channels, channel) {
                    _I1B(&channel, &p);
                }
            }
        }
    }

    FORGE_RETURN
}

/*#######################################################################
# Multi-AP profile TLV ("Section 17.2.47")                              #
########################################################################*/
TLV_FREE_FUNCTION(multiap_profile) {}

static uint8_t* parse_multiap_profile_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_multiap_profile_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_EXP_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_MULTIAP_PROFILE;

    _E1B(&p, &ret->map_profile);

    PARSE_CHECK_INTEGRITY(multiap_profile)
    PARSE_RETURN
}

static uint8_t* forge_multiap_profile_tlv(void *memory_structure, uint16_t *len)
{
    map_multiap_profile_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 1;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,    &p);
    _I2B(&tlv_length,     &p);
    _I1B(&m->map_profile, &p);

    FORGE_RETURN
}

/*#######################################################################
# Profile 2 AP capability TLV ("Section 17.2.48")                       #
########################################################################*/
TLV_FREE_FUNCTION(profile2_ap_cap) {}

static uint8_t* parse_profile2_ap_cap_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_profile2_ap_cap_tlv_t *ret;
    uint16_t reserved;
    uint8_t  *p = packet_stream, byte;

    PARSE_CHECK_EXP_LEN(4)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_PROFILE2_AP_CAPABILITY;

    _E2B(&p, &reserved);
    _E1B(&p, &byte);
    ret->byte_counter_unit  = (byte & (BIT_MASK_7 | BIT_MASK_6)) >> BIT_SHIFT_6;
    _E1B(&p, &ret->max_vid_count);

    PARSE_CHECK_INTEGRITY(profile2_ap_cap)
    PARSE_RETURN
}

static uint8_t* forge_profile2_ap_cap_tlv(void *memory_structure, uint16_t *len)
{
    map_profile2_ap_cap_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 4;
    uint16_t  reserved = 0;
    uint8_t  *ret, *p, byte;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,            &p);
    _I2B(&tlv_length,             &p);
    _I2B(&reserved,               &p);

    byte = (m->byte_counter_unit << BIT_SHIFT_6);
    _I1B(&byte,             &p);
    _I1B(&m->max_vid_count, &p);

    FORGE_RETURN
}

/*#######################################################################
# Default 8021Q settings TLV ("Section 17.2.49")                        #
########################################################################*/
TLV_FREE_FUNCTION(default_8021q_settings) {}

static uint8_t* parse_default_8021q_settings_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_default_8021q_settings_tlv_t *ret;
    uint8_t *p = packet_stream, byte;

    PARSE_CHECK_EXP_LEN(3)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_DEFAULT_8021Q_SETTINGS;

    _E2B(&p, &ret->primary_vlan_id);
    _E1B(&p, &byte);
    ret->default_pcp = (byte & (BIT_MASK_7 | BIT_MASK_6 | BIT_MASK_5)) >> BIT_SHIFT_5;

    PARSE_CHECK_INTEGRITY(default_8021q_settings)
    PARSE_RETURN
}

static uint8_t* forge_default_8021q_settings_tlv(void *memory_structure, uint16_t *len)
{
    map_default_8021q_settings_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 3;
    uint8_t  *ret, *p, byte;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,        &p);
    _I2B(&tlv_length,         &p);
    _I2B(&m->primary_vlan_id, &p);

     byte = (m->default_pcp << BIT_SHIFT_5);
    _I1B(&byte, &p);

    FORGE_RETURN
}

/*#######################################################################
# Traffic separation policy TLV ("Section 17.2.50")                     #
########################################################################*/
TLV_FREE_FUNCTION(traffic_separation_policy) {}

static uint8_t* parse_traffic_separation_policy_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_traffic_separation_policy_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    PARSE_CHECK_MIN_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_TRAFFIC_SEPARATION_POLICY;

    _E1B(&p, &ret->ssids_nr);
    PARSE_LIMIT(ret->ssids_nr, MAX_TRAFFIC_SEP_SSID);

    for (i = 0; i < ret->ssids_nr; i++) {
        _E1B(&p, &ret->ssids[i].ssid_len);
        PARSE_LIMIT_N_DROP(traffic_separation_policy, ret->ssids[i].ssid_len, (MAX_SSID_LEN - 1))

        _EnB(&p, ret->ssids[i].ssid, ret->ssids[i].ssid_len);
        _E2B(&p, &ret->ssids[i].vlan_id);
    }

    PARSE_CHECK_INTEGRITY(traffic_separation_policy)
    PARSE_RETURN
}

static uint8_t* forge_traffic_separation_policy_tlv(void *memory_structure, uint16_t *len)
{
    map_traffic_separation_policy_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i;

    /* Calculate TLV length */
    tlv_length = 1; /* ssid_nr */
    for (i = 0; i < m->ssids_nr; i++) {
        tlv_length += 1 + m->ssids[i].ssid_len + 2; /* ssid_len + ssid + vlan_id */
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _I1B(&m->ssids_nr, &p);

    for (i = 0; i < m->ssids_nr; i++) {
        _I1B(&m->ssids[i].ssid_len, &p);
        _InB(&m->ssids[i].ssid, &p, m->ssids[i].ssid_len);
        _I2B(&m->ssids[i].vlan_id, &p);
    }

    FORGE_RETURN
}

/*#######################################################################
# Profile 2 error code TLV ("Section 17.2.51")                          #
########################################################################*/
TLV_FREE_FUNCTION(profile2_error_code) {}

static uint8_t* parse_profile2_error_code_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_profile2_error_code_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_MIN_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_PROFILE2_ERROR_CODE;

    _E1B(&p, &ret->reason_code);

    if (ret->reason_code == MAP_ERROR_CODE2_TS_COMBINED_FH_PROFILE1_BH_UNSUPPORTED ||
        ret->reason_code == MAP_ERROR_CODE2_TS_COMBINED_PROFILE1_BH_PROFILE2_BH_UNSUPPORTED) {
        if (len != 7) {
            free(ret);
            return NULL;
        }
        _EnB(&p, ret->sta_mac, 6);
    }

    PARSE_CHECK_INTEGRITY(profile2_error_code)
    PARSE_RETURN
}

static uint8_t* forge_profile2_error_code_tlv(void *memory_structure, uint16_t *len)
{
    map_profile2_error_code_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 1; /* or 7 */
    uint8_t  *ret, *p;

    if (m->reason_code == MAP_ERROR_CODE2_TS_COMBINED_FH_PROFILE1_BH_UNSUPPORTED ||
        m->reason_code == MAP_ERROR_CODE2_TS_COMBINED_PROFILE1_BH_PROFILE2_BH_UNSUPPORTED) {
        tlv_length += 6;
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,    &p);
    _I2B(&tlv_length,     &p);
    _I1B(&m->reason_code, &p);

    if (tlv_length == 7) {
        _InB(m->sta_mac, &p, 6);
    }

    FORGE_RETURN
}

/*#######################################################################
# AP radio advanced capabilities TLV ("Section 17.2.52")                #
########################################################################*/
TLV_FREE_FUNCTION(ap_radio_advanced_cap) {}

static uint8_t* parse_ap_radio_advanced_cap_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_ap_radio_advanced_cap_tlv_t *ret;
    uint8_t *p = packet_stream, byte;

    PARSE_CHECK_EXP_LEN(7)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_AP_RADIO_ADVANCED_CAPABILITIES;

    _EnB(&p, ret->radio_id, 6);
    _E1B(&p, &byte);

    ret->combined_fh_profile2_bh          = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;
    ret->combined_profile1_bh_profile2_bh = (byte & BIT_MASK_6) ? SET_BIT : RESET_BIT;

    PARSE_CHECK_INTEGRITY(ap_radio_advanced_cap)
    PARSE_RETURN
}

static uint8_t* forge_ap_radio_advanced_cap_tlv(void *memory_structure, uint16_t *len)
{
    map_ap_radio_advanced_cap_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 7;
    uint8_t  *ret, *p, byte;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,  &p);
    _I2B(&tlv_length,   &p);
    _InB(m->radio_id, &p, 6);

    byte = (m->combined_fh_profile2_bh          << BIT_SHIFT_7) |
           (m->combined_profile1_bh_profile2_bh << BIT_SHIFT_6);
    _I1B(&byte, &p);

    FORGE_RETURN
}

/*#######################################################################
# Association status notification TLV ("Section 17.2.53")               #
########################################################################*/
TLV_FREE_FUNCTION(assoc_status_notification) {}

static uint8_t* parse_assoc_status_notification_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_assoc_status_notification_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    PARSE_CHECK_MIN_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_ASSOCIATION_STATUS_NOTIFICATION;

    _E1B(&p, &ret->bsss_nr);
    PARSE_LIMIT(ret->bsss_nr, MAX_BSS_PER_AGENT)

    for (i = 0; i < ret->bsss_nr; i++) {
        _EnB(&p, &ret->bsss[i].bssid, 6);
        _E1B(&p, &ret->bsss[i].assoc_allowance_status);
    }

    PARSE_CHECK_INTEGRITY(assoc_status_notification)
    PARSE_RETURN
}

static uint8_t* forge_assoc_status_notification_tlv(void *memory_structure, uint16_t *len)
{
    map_assoc_status_notification_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 1 + m->bsss_nr * 7;
    uint8_t  *ret, *p, i;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _I1B(&m->bsss_nr,  &p);

    for (i = 0; i < m->bsss_nr; i++) {
        _InB(m->bsss[i].bssid,                   &p, 6);
        _I1B(&m->bsss[i].assoc_allowance_status, &p);
    }

    FORGE_RETURN
}

/*#######################################################################
# Source info TLV ("Section 17.2.54")                                   #
########################################################################*/
TLV_FREE_FUNCTION(source_info) {}

static uint8_t* parse_source_info_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_source_info_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_EXP_LEN(6)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_SOURCE_INFO;

    _EnB(&p, ret->src_mac, 6);

    PARSE_CHECK_INTEGRITY(source_info)
    PARSE_RETURN
}

static uint8_t* forge_source_info_tlv(void *memory_structure, uint16_t *len)
{
    map_source_info_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 6;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _InB(m->src_mac,   &p, 6);

    FORGE_RETURN
}

/*#######################################################################
# Tunneled message type TLV ("Section 17.2.55")                         #
########################################################################*/
TLV_FREE_FUNCTION(tunneled_message_type) {}

static uint8_t* parse_tunneled_message_type_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_tunneled_message_type_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_EXP_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_TUNNELED_MESSAGE_TYPE;

    _E1B(&p, &ret->message_type);

    PARSE_CHECK_INTEGRITY(tunneled_message_type)
    PARSE_RETURN
}

static uint8_t* forge_tunneled_message_type_tlv(void *memory_structure, uint16_t *len)
{
    map_tunneled_message_type_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 1;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,     &p);
    _I2B(&tlv_length,      &p);
    _I1B(&m->message_type, &p);

    FORGE_RETURN
}

/*#######################################################################
# Tunneled TLV ("Section 17.2.56")                                      #
########################################################################*/
TLV_FREE_FUNCTION(tunneled) {}

static uint8_t* parse_tunneled_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_tunneled_tlv_t *ret;
    uint8_t *p = packet_stream;

    /* Allocate struct and frame_body */
    ret = calloc(1, sizeof(*ret) + len);
    if (NULL == ret) {
        return NULL;
    }

    ret->tlv_type = TLV_TYPE_TUNNELED;

    if (len > 0) {
        ret->frame_body_len = len;
        ret->frame_body     = (uint8_t *)(ret + 1);
        _EnB(&p, ret->frame_body, len);
    }

    PARSE_CHECK_INTEGRITY(tunneled)
    PARSE_RETURN
}

static uint8_t* forge_tunneled_tlv(void *memory_structure, uint16_t *len)
{
    map_tunneled_tlv_t *m = memory_structure;
    uint16_t  tlv_length = m->frame_body_len;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,  &p);
    _I2B(&tlv_length,   &p);
    _InB(m->frame_body, &p, m->frame_body_len);

    FORGE_RETURN
}

/*#######################################################################
# Profile 2 steering request TLV ("Section 17.2.57")                    #
########################################################################*/
TLV_FREE_FUNCTION(profile2_steering_request)
{
    map_free_p1_p2_steering_request_tlv(m, true);
}

static uint8_t* parse_profile2_steering_request_tlv(uint8_t *packet_stream, uint16_t len)
{
    return map_parse_p1_p2_steering_request_tlv(packet_stream, len, true);
}

static uint8_t* forge_profile2_steering_request_tlv(void *memory_structure, uint16_t *len)
{
    return map_forge_p1_p2_steering_request_tlv(memory_structure, len, true);
}

/*#######################################################################
# Unsuccessful association policy TLV ("Section 17.2.58")               #
########################################################################*/
TLV_FREE_FUNCTION(unsuccessful_assoc_policy) {}

static uint8_t* parse_unsuccessful_assoc_policy_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_unsuccessful_assoc_policy_tlv_t *ret;
    uint8_t *p = packet_stream, byte;

    PARSE_CHECK_EXP_LEN(5)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_UNSUCCESSFUL_ASSOCIATION_POLICY;

    _E1B(&p, &byte);
    ret->report_flag = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;

    _E4B(&p, &ret->max_reporting_rate);

    PARSE_CHECK_INTEGRITY(unsuccessful_assoc_policy)
    PARSE_RETURN
}

static uint8_t* forge_unsuccessful_assoc_policy_tlv(void *memory_structure, uint16_t *len)
{
    map_unsuccessful_assoc_policy_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 5;
    uint8_t  *ret, *p, byte;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);

    byte = (m->report_flag << BIT_SHIFT_7);
    _I1B(&byte, &p);
    _I4B(&m->max_reporting_rate, &p);

    FORGE_RETURN
}

/*#######################################################################
# Metric collection interval TLV ("Section 17.2.59")                    #
########################################################################*/
TLV_FREE_FUNCTION(metric_collection_interval) {}

static uint8_t* parse_metric_collection_interval_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_metric_collection_interval_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_EXP_LEN(4);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_METRIC_COLLECTION_INTERVAL;

    _E4B(&p, &ret->metric_collection_interval);

    PARSE_CHECK_INTEGRITY(metric_collection_interval)
    PARSE_RETURN
}

static uint8_t* forge_metric_collection_interval_tlv(void *memory_structure, uint16_t *len)
{
    map_metric_collection_interval_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 4;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,                   &p);
    _I2B(&tlv_length,                    &p);
    _I4B(&m->metric_collection_interval, &p);

    FORGE_RETURN
}

/*#######################################################################
# Radio metrics TLV ("Section 17.2.60")                                 #
########################################################################*/
TLV_FREE_FUNCTION(radio_metrics) {}

static uint8_t* parse_radio_metrics_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_radio_metrics_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_EXP_LEN(10);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_RADIO_METRICS;

    _EnB(&p, ret->radio_id, 6);
    _E1B(&p, &ret->noise);
    _E1B(&p, &ret->transmit);
    _E1B(&p, &ret->receive_self);
    _E1B(&p, &ret->receive_other);

    PARSE_CHECK_INTEGRITY(radio_metrics)
    PARSE_RETURN
}

static uint8_t* forge_radio_metrics_tlv(void *memory_structure, uint16_t *len)
{
    map_radio_metrics_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 10;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,      &p);
    _I2B(&tlv_length,       &p);
    _InB(&m->radio_id,      &p, 6);
    _I1B(&m->noise,         &p);
    _I1B(&m->transmit,      &p);
    _I1B(&m->receive_self,  &p);
    _I1B(&m->receive_other, &p);

    FORGE_RETURN
}

/*#######################################################################
# AP extended metrics TLV ("Section 17.2.61")                           #
########################################################################*/
TLV_FREE_FUNCTION(ap_ext_metrics) {}

static uint8_t* parse_ap_ext_metrics_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_ap_ext_metrics_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_EXP_LEN(30);

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_AP_EXTENDED_METRICS;

    _EnB(&p, &ret->bssid, 6);
    _E4B(&p, &ret->ucast_bytes_tx);
    _E4B(&p, &ret->ucast_bytes_rx);
    _E4B(&p, &ret->mcast_bytes_tx);
    _E4B(&p, &ret->mcast_bytes_rx);
    _E4B(&p, &ret->bcast_bytes_tx);
    _E4B(&p, &ret->bcast_bytes_rx);

    PARSE_CHECK_INTEGRITY(ap_ext_metrics)
    PARSE_RETURN
}

static uint8_t* forge_ap_ext_metrics_tlv(void *memory_structure, uint16_t *len)
{
    map_ap_ext_metrics_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 30;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,       &p);
    _I2B(&tlv_length,        &p);
    _InB(&m->bssid,          &p, 6);
    _I4B(&m->ucast_bytes_tx, &p);
    _I4B(&m->ucast_bytes_rx, &p);
    _I4B(&m->mcast_bytes_tx, &p);
    _I4B(&m->mcast_bytes_rx, &p);
    _I4B(&m->bcast_bytes_tx, &p);
    _I4B(&m->bcast_bytes_rx, &p);

    FORGE_RETURN
}

/*#######################################################################
# Associated STA extended link metrics TLV ("Section 17.2.62")          #
########################################################################*/
TLV_FREE_FUNCTION(assoc_sta_ext_link_metrics) {}

static uint8_t* parse_assoc_sta_ext_link_metrics_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_assoc_sta_ext_link_metrics_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    PARSE_CHECK_MIN_LEN(7)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_ASSOCIATED_STA_EXTENDED_LINK_METRICS;

    _EnB(&p, &ret->sta_mac, 6);
    _E1B(&p, &ret->bsss_nr);
    PARSE_LIMIT(ret->bsss_nr, MAX_BSS_PER_AGENT);

    for (i = 0; i < ret->bsss_nr; i++) {
        _EnB(&p, &ret->bsss[i].bssid, 6);
        _E4B(&p, &ret->bsss[i].last_data_dl_rate);
        _E4B(&p, &ret->bsss[i].last_data_ul_rate);
        _E4B(&p, &ret->bsss[i].utilization_rx);
        _E4B(&p, &ret->bsss[i].utilization_tx);
    }

    PARSE_CHECK_INTEGRITY(assoc_sta_ext_link_metrics)
    PARSE_RETURN
}

static uint8_t* forge_assoc_sta_ext_link_metrics_tlv(void *memory_structure, uint16_t *len)
{
    map_assoc_sta_ext_link_metrics_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 7 + m->bsss_nr * 22;
    uint8_t  *ret, *p, i;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _InB(&m->sta_mac,  &p, 6);
    _I1B(&m->bsss_nr,  &p);

    for (i = 0; i < m->bsss_nr; i++) {
        _InB(&m->bsss[i].bssid,             &p, 6);
        _I4B(&m->bsss[i].last_data_dl_rate, &p);
        _I4B(&m->bsss[i].last_data_ul_rate, &p);
        _I4B(&m->bsss[i].utilization_rx,    &p);
        _I4B(&m->bsss[i].utilization_tx,    &p);
    }

    FORGE_RETURN
}

/*#######################################################################
# Status code TLV ("Section 17.2.63")                                   #
########################################################################*/
TLV_FREE_FUNCTION(status_code) {}

static uint8_t* parse_status_code_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_status_code_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_EXP_LEN(2);

    PARSE_CALLOC_RET;

    ret->tlv_type = TLV_TYPE_STATUS_CODE;

    _E2B(&p, &ret->status_code);

    PARSE_CHECK_INTEGRITY(status_code)
    PARSE_RETURN
}

static uint8_t* forge_status_code_tlv(void *memory_structure, uint16_t *len)
{
    map_status_code_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 2;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,    &p);
    _I2B(&tlv_length,     &p);
    _I2B(&m->status_code, &p);

    FORGE_RETURN
}

/*#######################################################################
# Reason code TLV ("Section 17.2.64")                                   #
########################################################################*/
TLV_FREE_FUNCTION(reason_code) {}

static uint8_t* parse_reason_code_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_reason_code_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CHECK_EXP_LEN(2);

    PARSE_CALLOC_RET;

    ret->tlv_type = TLV_TYPE_REASON_CODE;

    _E2B(&p, &ret->reason_code);

    PARSE_CHECK_INTEGRITY(reason_code)
    PARSE_RETURN
}

static uint8_t* forge_reason_code_tlv(void *memory_structure, uint16_t *len)
{
    map_reason_code_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 2;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,    &p);
    _I2B(&tlv_length,     &p);
    _I2B(&m->reason_code, &p);

    FORGE_RETURN
}

/*#######################################################################
# Backhaul STA radio capabilities TLV ("Section 17.2.65")               #
########################################################################*/
TLV_FREE_FUNCTION(backhaul_sta_radio_cap) {}

static uint8_t* parse_backhaul_sta_radio_cap_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_backhaul_sta_radio_cap_tlv_t *ret;
    uint8_t *p = packet_stream, byte;

    PARSE_CHECK_MIN_LEN(7)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_BACKHAUL_STA_RADIO_CAPABILITIES;

    _EnB(&p, ret->radio_id, 6);
    _E1B(&p, &byte);
    ret->bsta_mac_present = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;

    if (ret->bsta_mac_present) {
        _EnB(&p, ret->bsta_mac, 6);
    }

    PARSE_CHECK_INTEGRITY(backhaul_sta_radio_cap)
    PARSE_RETURN
}

static uint8_t* forge_backhaul_sta_radio_cap_tlv(void *memory_structure, uint16_t *len)
{
    map_backhaul_sta_radio_cap_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 7 + (m->bsta_mac_present ? 6 : 0); /* radio + flags + optional mac */
    uint8_t  *ret, *p, byte;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _InB(m->radio_id,  &p, 6);

    byte = m->bsta_mac_present << BIT_SHIFT_7;
    _I1B(&byte, &p);

    if (m->bsta_mac_present) {
        _InB(m->bsta_mac, &p, 6);
    }

    FORGE_RETURN
}

/*#######################################################################
# Backhaul BSS configuration ("Section 17.2.66")                        #
########################################################################*/
TLV_FREE_FUNCTION(backhaul_bss_configuration) {}

static uint8_t* parse_backhaul_bss_configuration_tlv(uint8_t *packet_stream, uint16_t len)
{
    map_backhaul_bss_configuration_tlv_t *ret;
    uint8_t *p = packet_stream, byte;

    PARSE_CHECK_EXP_LEN(7)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_BACKHAUL_BSS_CONFIGURATION;

    _EnB(&p, ret->bssid, 6);
    _E1B(&p, &byte);
    ret->p1_bsta_disallowed = (byte & BIT_MASK_7) ? SET_BIT : RESET_BIT;
    ret->p2_bsta_disallowed = (byte & BIT_MASK_6) ? SET_BIT : RESET_BIT;

    PARSE_CHECK_INTEGRITY(backhaul_bss_configuration)
    PARSE_RETURN
}

static uint8_t* forge_backhaul_bss_configuration_tlv(void *memory_structure, uint16_t *len)
{
    map_backhaul_bss_configuration_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 7;
    uint8_t  *ret, *p, byte;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _InB(&m->bssid,    &p, 6);

    byte = (m->p1_bsta_disallowed << BIT_SHIFT_7) |
           (m->p2_bsta_disallowed << BIT_SHIFT_6);
    _I1B(&byte, &p);

    FORGE_RETURN
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
void map_r2_register_tlvs(void)
{
    I1905_REGISTER_TLV(TLV_TYPE_CHANNEL_SCAN_REPORTING_POLICY,        channel_scan_reporting_policy);
    I1905_REGISTER_TLV(TLV_TYPE_CHANNEL_SCAN_CAPABILITIES,            channel_scan_cap             );
    I1905_REGISTER_TLV(TLV_TYPE_CHANNEL_SCAN_REQUEST,                 channel_scan_request         );
    I1905_REGISTER_TLV(TLV_TYPE_CHANNEL_SCAN_RESULT,                  channel_scan_result          );
    I1905_REGISTER_TLV(TLV_TYPE_TIMESTAMP,                            timestamp                    );
    I1905_REGISTER_TLV(TLV_TYPE_CAC_REQUEST,                          cac_request                  );
    I1905_REGISTER_TLV(TLV_TYPE_CAC_TERMINATION,                      cac_termination              );
    I1905_REGISTER_TLV(TLV_TYPE_CAC_COMPLETION_REPORT,                cac_completion_report        );
    I1905_REGISTER_TLV(TLV_TYPE_CAC_STATUS_REPORT,                    cac_status_report            );
    I1905_REGISTER_TLV(TLV_TYPE_CAC_CAPABILITIES,                     cac_cap                      );
    I1905_REGISTER_TLV(TLV_TYPE_MULTIAP_PROFILE,                      multiap_profile              );
    I1905_REGISTER_TLV(TLV_TYPE_PROFILE2_AP_CAPABILITY,               profile2_ap_cap              );
    I1905_REGISTER_TLV(TLV_TYPE_DEFAULT_8021Q_SETTINGS,               default_8021q_settings       );
    I1905_REGISTER_TLV(TLV_TYPE_TRAFFIC_SEPARATION_POLICY,            traffic_separation_policy    );
    I1905_REGISTER_TLV(TLV_TYPE_PROFILE2_ERROR_CODE,                  profile2_error_code          );
    I1905_REGISTER_TLV(TLV_TYPE_AP_RADIO_ADVANCED_CAPABILITIES,       ap_radio_advanced_cap        );
    I1905_REGISTER_TLV(TLV_TYPE_ASSOCIATION_STATUS_NOTIFICATION,      assoc_status_notification    );
    I1905_REGISTER_TLV(TLV_TYPE_SOURCE_INFO,                          source_info                  );
    I1905_REGISTER_TLV(TLV_TYPE_TUNNELED_MESSAGE_TYPE,                tunneled_message_type        );
    I1905_REGISTER_TLV(TLV_TYPE_TUNNELED,                             tunneled                     );
    I1905_REGISTER_TLV(TLV_TYPE_PROFILE2_STEERING_REQUEST,            profile2_steering_request    );
    I1905_REGISTER_TLV(TLV_TYPE_UNSUCCESSFUL_ASSOCIATION_POLICY,      unsuccessful_assoc_policy    );
    I1905_REGISTER_TLV(TLV_TYPE_METRIC_COLLECTION_INTERVAL,           metric_collection_interval   );
    I1905_REGISTER_TLV(TLV_TYPE_RADIO_METRICS,                        radio_metrics                );
    I1905_REGISTER_TLV(TLV_TYPE_AP_EXTENDED_METRICS,                  ap_ext_metrics               );
    I1905_REGISTER_TLV(TLV_TYPE_ASSOCIATED_STA_EXTENDED_LINK_METRICS, assoc_sta_ext_link_metrics   );
    I1905_REGISTER_TLV(TLV_TYPE_STATUS_CODE,                          status_code                  );
    I1905_REGISTER_TLV(TLV_TYPE_REASON_CODE,                          reason_code                  );
    I1905_REGISTER_TLV(TLV_TYPE_BACKHAUL_STA_RADIO_CAPABILITIES,      backhaul_sta_radio_cap       );
    I1905_REGISTER_TLV(TLV_TYPE_BACKHAUL_BSS_CONFIGURATION,           backhaul_bss_configuration   );
}
