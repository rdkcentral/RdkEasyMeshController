/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

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

#include "lldp_tlvs.h"
#include "packet_tools.h"

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
uint8_t *parse_lldp_TLV_from_packet(uint8_t *packet_stream)
{
    if (NULL == packet_stream) {
        return NULL;
    }

    uint8_t  *p = packet_stream;
    uint8_t   byte1, byte2;
    uint8_t   type;
    uint16_t  len;

    _E1B(&p, &byte1);
    _E1B(&p, &byte2);

    /* All LLDP TLVs start with the same two bytes:
    *
    *    |byte #1 |byte #2 |
    *    |--------|--------|
    *    |TTTTTTTL|LLLLLLLL|
    *    |--------|--------|
    *     <-----><-------->
    *     7 bits   9 bits
    *     (type)   (length)
    */

    type = byte1 >> 1;
    len  = ((byte1 & 0x1) << 8) + byte2;

    switch (type) {
        case TLV_TYPE_END_OF_LLDPPDU: {
            /* This parsing is done according to the information detailed in
            *  "IEEE Std 802.1AB-2009 Section 8.5.1"
            */

            lldp_end_of_lldp_ppdu_tlv_t *ret;

            /* According to the standard, the length *must* be 0 */
            if (0 != len) {
                /* Malformed packet */
                return NULL;
            }

            ret = malloc(sizeof(lldp_end_of_lldp_ppdu_tlv_t));
            if (!ret) {
                return NULL;
            }

            ret->tlv_type = TLV_TYPE_END_OF_LLDPPDU;

            return (uint8_t *)ret;
        }
        case TLV_TYPE_CHASSIS_ID: {
            /* This parsing is done according to the information detailed in
            *  "IEEE Std 802.1AB-2009 Section 8.5.2"
            */

            lldp_chassis_id_tlv_t *ret;

            /* In the 1905 context we are only interested in processing those
            *  TLVs whose length is "6+1" (ie. it contains a 6 bytes MAC address
            *  in the "chassis_id" field) (see "IEEE Std 1905.1-2013 Section
            *  6.1")
            */
            if (6+1 != len) {
                /* Not interested */
                return NULL;
            }

            ret = malloc(sizeof(lldp_chassis_id_tlv_t));
            if (!ret) {
                return NULL;
            }

            ret->tlv_type = TLV_TYPE_CHASSIS_ID;

            _E1B(&p, &ret->chassis_id_subtype);

            /* In the 1905 context we are only interested in processing those
            *  TLVs whose chassis subtype is "4" (see "IEEE Std 1905.1-2013
            *  Section 6.1")
            */
            if (CHASSIS_ID_TLV_SUBTYPE_MAC_ADDRESS != ret->chassis_id_subtype) {
                /* Not interested */
                free(ret);
                return NULL;
            }

            _EnB(&p, ret->chassis_id, 6);

            return (uint8_t *)ret;
        }
        case TLV_TYPE_PORT_ID: {
            /* This parsing is done according to the information detailed in
            *  "IEEE Std 802.1AB-2009 Section 8.5.3"
            */

            lldp_port_id_tlv_t *ret;

            /* In the 1905 context we are only interested in processing those
            *  TLVs whose length is "6+1" (ie. it contains a 6 bytes MAC address
            *  in the "port_id" field) (see "IEEE Std 1905.1-2013 Section
            *  6.1")
            */
            if (6+1 != len) {
                /* Not interested */
                return NULL;
            }

            ret = malloc(sizeof(lldp_port_id_tlv_t));
            if (!ret) {
                return NULL;
            }

            ret->tlv_type = TLV_TYPE_PORT_ID;

            _E1B(&p, &ret->port_id_subtype);

            /* In the 1905 context we are only interested in processing those
            *  TLVs whose chassis subtype is "3" (see "IEEE Std 1905.1-2013
            *  Section 6.1")
            */
            if (PORT_ID_TLV_SUBTYPE_MAC_ADDRESS != ret->port_id_subtype) {
                /* Not interested */
                free(ret);
                return NULL;
            }

            _EnB(&p, ret->port_id, 6);

            return (uint8_t *)ret;
        }
        case TLV_TYPE_TIME_TO_LIVE: {
            /* This parsing is done according to the information detailed in
            *  "IEEE Std 802.1AB-2009 Section 8.5.4"
            */

            lldp_time_to_live_tlv_t *ret;

            /* According to the standard, the length *must* be 2 */
            if (2 != len) {
                /* Not interested */
                return NULL;
            }

            ret = malloc(sizeof(lldp_time_to_live_tlv_t));
            if (!ret) {
                return NULL;
            }

            ret->tlv_type = TLV_TYPE_TIME_TO_LIVE;

            _E2B(&p, &ret->ttl);

            return (uint8_t *)ret;
        }
        default: {
            /* Ignore */
            return NULL;
        }
    }

    /* This code cannot be reached */
    return NULL;
}

uint8_t *forge_lldp_TLV_from_structure(uint8_t *memory_structure, uint16_t *len)
{
    if (NULL == memory_structure) {
        return NULL;
    }

    /* The first byte of any of the valid structures is always the "tlv_type"
    *  field.
    */
    switch (*memory_structure) {
        case TLV_TYPE_END_OF_LLDPPDU: {
            /* This forging is done according to the information detailed in
            *  "IEEE Std 802.1AB-2009 Section 8.5.1"
            */

            uint8_t *ret, *p;
            lldp_end_of_lldp_ppdu_tlv_t *m;
            uint8_t byte1, byte2;

            uint16_t tlv_length;

            m = (lldp_end_of_lldp_ppdu_tlv_t *)memory_structure;

            tlv_length = 0;
            *len = 1 + 1 + tlv_length;

            ret = malloc(1 + 1 + tlv_length);
            if (!ret) {
                return NULL;
            }
            p = ret;


            byte1 = (m->tlv_type << 1) | ((tlv_length & 0x80) >> 7);
            byte2 = tlv_length & 0x7f;

            _I1B(&byte1,  &p);
            _I1B(&byte2,  &p);

            return ret;
        }
        case TLV_TYPE_CHASSIS_ID: {
            /* This forging is done according to the information detailed in
            *  "IEEE Std 802.1AB-2009 Section 8.5.2"
            */

            uint8_t *ret, *p;
            lldp_chassis_id_tlv_t *m;
            uint8_t byte1, byte2;

            uint16_t tlv_length;

            m = (lldp_chassis_id_tlv_t *)memory_structure;

            if (CHASSIS_ID_TLV_SUBTYPE_MAC_ADDRESS != m->chassis_id_subtype) {
                /* 1905 *only* forges chassis of type "MAC address" */
                return NULL;
            }

            tlv_length = 1+6;  /* subtype (1 byte) + AL MAC address (6 bytes) */
            *len = 1 + 1 + tlv_length;

            ret = malloc(1 + 1 + tlv_length);
            if (!ret) {
                return NULL;
            }
            p = ret;

            byte1 = (m->tlv_type << 1) | ((tlv_length & 0x80) >> 7);
            byte2 = tlv_length & 0x7f;

            _I1B(&byte1,                 &p);
            _I1B(&byte2,                 &p);
            _I1B(&m->chassis_id_subtype, &p);
            _InB( m->chassis_id,         &p, 6);

            return ret;
        }
        case TLV_TYPE_PORT_ID: {
            /* This forging is done according to the information detailed in
            *  "IEEE Std 802.1AB-2009 Section 8.5.3"
            */

            uint8_t *ret, *p;
            lldp_port_id_tlv_t *m;
            uint8_t byte1, byte2;

            uint16_t tlv_length;

            m = (lldp_port_id_tlv_t *)memory_structure;

            if (PORT_ID_TLV_SUBTYPE_MAC_ADDRESS != m->port_id_subtype) {
                /* 1905 *only* forges ports of type "MAC address" */
                return NULL;
            }

            tlv_length = 1+6;  // subtype (1 byte) + AL MAC address (6 bytes)
            *len = 1 + 1 + tlv_length;

            ret = malloc(1 + 1 + tlv_length);
            if (!ret) {
                return NULL;
            }
            p = ret;

            byte1 = (m->tlv_type << 1) | ((tlv_length & 0x80) >> 7);
            byte2 = tlv_length & 0x7f;

            _I1B(&byte1,              &p);
            _I1B(&byte2,              &p);
            _I1B(&m->port_id_subtype, &p);
            _InB( m->port_id,         &p, 6);

            return ret;
        }
        case TLV_TYPE_TIME_TO_LIVE: {
            /* This forging is done according to the information detailed in
            *  "IEEE Std 802.1AB-2009 Section 8.5.4"
            */

            uint8_t *ret, *p;
            lldp_time_to_live_tlv_t *m;
            uint8_t byte1, byte2;

            uint16_t tlv_length;

            m = (lldp_time_to_live_tlv_t *)memory_structure;

            if (TIME_TO_LIVE_TLV_1905_DEFAULT_VALUE != m->ttl) {
                /* 1905 *only* forges TTLs with this default value */
                return NULL;
            }

            tlv_length = 2;
            *len = 1 + 1 + tlv_length;

            ret = malloc(1 + 1 + tlv_length);
            if (!ret) {
                return NULL;
            }
            p = ret;

            byte1 = (m->tlv_type << 1) | ((tlv_length & 0x80) >> 7);
            byte2 = tlv_length & 0x7f;

            _I1B(&byte1,  &p);
            _I1B(&byte2,  &p);
            _I2B(&m->ttl, &p);

            return ret;
        }
        default: {
            /* Ignore */
            return NULL;
        }
    }

    /* This code cannot be reached */
    return NULL;
}


void free_lldp_TLV_structure(uint8_t *memory_structure)
{
    if (NULL == memory_structure) {
        return;
    }

    /* The first byte of any of the valid structures is always the "tlv_type"
    *  field.
    */
    switch (*memory_structure) {
        case TLV_TYPE_END_OF_LLDPPDU:
        case TLV_TYPE_CHASSIS_ID:
        case TLV_TYPE_PORT_ID:
        case TLV_TYPE_TIME_TO_LIVE:
            free(memory_structure);
        break;
        default:
        break;
    }
}


uint8_t compare_lldp_TLV_structures(uint8_t *memory_structure_1, uint8_t *memory_structure_2)
{
    if (NULL == memory_structure_1 || NULL == memory_structure_2) {
        return 1;
    }

    /* The first byte of any of the valid structures is always the "tlv_type"
    *  field.
    */
    if (*memory_structure_1 != *memory_structure_2) {
        return 1;
    }
    switch (*memory_structure_1) {
        case TLV_TYPE_END_OF_LLDPPDU: {
            /* Nothing to compare (this TLV is always empty) */
            return 0;
        }
        case TLV_TYPE_CHASSIS_ID: {
            struct chassisIdTLV *p1, *p2;

            p1 = (struct chassisIdTLV *)memory_structure_1;
            p2 = (struct chassisIdTLV *)memory_structure_2;

            if (p1->chassis_id_subtype != p2->chassis_id_subtype ||
                (memcmp(p1->chassis_id,p2->chassis_id, 6) != 0)) {
                return 1;
            } else {
                return 0;
            }
        }
        case TLV_TYPE_PORT_ID: {
            struct portIdTLV *p1, *p2;

            p1 = (struct portIdTLV *)memory_structure_1;
            p2 = (struct portIdTLV *)memory_structure_2;

            if (p1->port_id_subtype != p2->port_id_subtype ||
                 (memcmp(p1->port_id, p2->port_id, 6) !=0)) {
                return 1;
            } else {
                return 0;
            }
        }
        case TLV_TYPE_TIME_TO_LIVE: {
            struct timeToLiveTypeTLV *p1, *p2;

            p1 = (struct timeToLiveTypeTLV *)memory_structure_1;
            p2 = (struct timeToLiveTypeTLV *)memory_structure_2;

            if (p1->ttl != p2->ttl) {
                return 1;
            } else {
                return 0;
            }
        }
        default: {
            /* Unknown structure type */
            return 1;
        }
    }

    /* This code cannot be reached */
    return 1;
}

void visit_lldp_TLV_structure(uint8_t *memory_structure, void (*callback)(void (*write_function)(const char *fmt, ...),
                              const char *prefix, size_t size, const char *name, const char *fmt, void *p),
                              void (*write_function)(const char *fmt, ...), const char *prefix)
{
    if (NULL == memory_structure) {
        return;
    }

    /* The first byte of any of the valid structures is always the "tlv_type"
    *  field.
    */
    switch (*memory_structure) {
        case TLV_TYPE_END_OF_LLDPPDU:
            /* There is nothing to visit. This TLV is always empty */
        break;
        case TLV_TYPE_CHASSIS_ID: {
            struct chassisIdTLV *p = (struct chassisIdTLV *)memory_structure;

            callback(write_function, prefix, sizeof(p->chassis_id_subtype), "chassis_id_subtype", "%d",     &p->chassis_id_subtype);
            callback(write_function, prefix, 6,                             "chassis_id",         "0x%02x",  p->chassis_id);
            break;
        }
        case TLV_TYPE_PORT_ID: {
            struct portIdTLV *p = (struct portIdTLV *)memory_structure;

            callback(write_function, prefix, sizeof(p->port_id_subtype), "port_id_subtype", "%d",     &p->port_id_subtype);
            callback(write_function, prefix, 6,                          "port_id",         "0x%02x",  p->port_id);
            break;
        }
        case TLV_TYPE_TIME_TO_LIVE: {
            struct timeToLiveTypeTLV *p= (struct timeToLiveTypeTLV *)memory_structure;

            callback(write_function, prefix, sizeof(p->ttl), "ttl", "%d", &p->ttl);
            break;
        }
        default:
            // Ignore */
        break;
    }
}

char *convert_lldp_TLV_type_to_string(uint8_t tlv_type)
{
    switch (tlv_type) {
        case TLV_TYPE_END_OF_LLDPPDU:
            return "TLV_TYPE_END_OF_LLDPPDU";
        case TLV_TYPE_CHASSIS_ID:
            return "TLV_TYPE_CHASSIS_ID";
        case TLV_TYPE_PORT_ID:
            return "TLV_TYPE_PORT_ID";
        case TLV_TYPE_TIME_TO_LIVE:
            return "TLV_TYPE_TIME_TO_LIVE";
        default:
            return "Unknown";
    }
}
