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
#define TLV_STRUCT_NAME_PREFIX TLV_STRUCT_NAME_PREFIX_I1905
#define LOG_TAG "tlv"

#include "platform.h"

#include "1905_tlvs.h"
#include "packet_tools.h"
#include "map_tlvs.h"

#include "map_config.h"

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
typedef struct {
    char                 *name;
    i1905_tlv_parse_cb_t  parse_cb;
    i1905_tlv_forge_cb_t  forge_cb;
    i1905_tlv_free_cb_t   free_cb;
} tlv_table_entry_t;

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static tlv_table_entry_t g_tlv_table[UINT8_MAX + 1];

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
void i1905_register_tlv(uint8_t type, char *name, i1905_tlv_parse_cb_t parse_cb,
                        i1905_tlv_forge_cb_t forge_cb, i1905_tlv_free_cb_t free_cb)
{
    g_tlv_table[type].name     = name;
    g_tlv_table[type].parse_cb = parse_cb;
    g_tlv_table[type].forge_cb = forge_cb;
    g_tlv_table[type].free_cb  = free_cb;
}

/*#######################################################################
#                       TLV HANDLERS                                    #
########################################################################*/
/*#######################################################################
# End of message TLV ("Section 6.4.1")                                  #
########################################################################*/
TLV_FREE_FUNCTION(end_of_message) {}

static uint8_t* parse_end_of_message_tlv(UNUSED uint8_t *packet_stream, uint16_t len)
{
    i1905_end_of_message_tlv_t *ret;

    /* According to the standard, the length *must* be 0 */
    PARSE_CHECK_EXP_LEN(0)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_END_OF_MESSAGE;

    PARSE_RETURN
}

static uint8_t* forge_end_of_message_tlv(void *memory_structure, uint16_t *len)
{
    i1905_end_of_message_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 0;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);

    FORGE_RETURN
}

/*#######################################################################
# Vendor specific TLV ("Section 6.4.2")                                 #
########################################################################*/
TLV_FREE_FUNCTION(vendor_specific)
{
    SFREE(m->m);
}

static uint8_t* parse_vendor_specific_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_vendor_specific_tlv_t *ret;
    uint8_t *p = packet_stream;

    /* According to the standard, the length *must* be at least "3" */
    PARSE_CHECK_MIN_LEN(3)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_VENDOR_SPECIFIC;
    _E1B(&p, &ret->vendorOUI[0]);
    _E1B(&p, &ret->vendorOUI[1]);
    _E1B(&p, &ret->vendorOUI[2]);

    ret->m_nr = len - 3;

    if (ret->m_nr) {
        ret->m = malloc(ret->m_nr);
        if (!ret->m) {
            free(ret);
            return NULL;
        }
        _EnB(&p, ret->m, ret->m_nr);
    }

    PARSE_CHECK_INTEGRITY(vendor_specific)
    PARSE_RETURN
}

static uint8_t* forge_vendor_specific_tlv(void *memory_structure, uint16_t *len)
{
    i1905_vendor_specific_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 3 + m->m_nr;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,     &p);
    _I2B(&tlv_length,      &p);
    _I1B(&m->vendorOUI[0], &p);
    _I1B(&m->vendorOUI[1], &p);
    _I1B(&m->vendorOUI[2], &p);
    _InB( m->m,            &p,  m->m_nr);

    FORGE_RETURN
}

/*#######################################################################
# AL MAC address TLV ("Section 6.4.3")                                  #
########################################################################*/
TLV_FREE_FUNCTION(al_mac_address) {}

static uint8_t* parse_al_mac_address_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_al_mac_address_tlv_t *ret;
    uint8_t *p = packet_stream;

    /* According to the standard, the length *must* be 6 */
    PARSE_CHECK_EXP_LEN(6)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_AL_MAC_ADDRESS;
    _EnB(&p, ret->al_mac_address, 6);

    PARSE_CHECK_INTEGRITY(al_mac_address)
    PARSE_RETURN
}

static uint8_t* forge_al_mac_address_tlv(void *memory_structure, uint16_t *len)
{
    i1905_al_mac_address_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 6;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,      &p);
    _I2B(&tlv_length,       &p);
    _InB(m->al_mac_address, &p, 6);

    FORGE_RETURN
}

/*#######################################################################
# MAC address TLV ("Section 6.4.4")                                     #
########################################################################*/
TLV_FREE_FUNCTION(mac_address) {}

static uint8_t* parse_mac_address_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_mac_address_tlv_t *ret;
    uint8_t *p = packet_stream;

    /* According to the standard, the length *must* be 6 */
    PARSE_CHECK_EXP_LEN(6)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_MAC_ADDRESS;
    _EnB(&p, ret->mac_address, 6);

    PARSE_CHECK_INTEGRITY(mac_address)
    PARSE_RETURN
}

static uint8_t* forge_mac_address_tlv(void *memory_structure, uint16_t *len)
{
    i1905_mac_address_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 6;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,      &p);
    _I2B(&tlv_length,       &p);
    _InB(m->mac_address, &p, 6);

    FORGE_RETURN
}

/*#######################################################################
# Device information TLV ("Section 6.4.5")                              #
########################################################################*/
TLV_FREE_FUNCTION(device_information)
{
    SFREE(m->local_interfaces);
}

static uint8_t* parse_device_information_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_device_information_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_DEVICE_INFORMATION;
    _EnB(&p, ret->al_mac_address, 6);
    _E1B(&p, &ret->local_interfaces_nr);

    ret->local_interfaces = calloc(ret->local_interfaces_nr, sizeof(*ret->local_interfaces));
    if (!ret->local_interfaces) {
        free(ret);
        return NULL;
    }

    for (i = 0; i < ret->local_interfaces_nr; i++) {
        _EnB(&p, ret->local_interfaces[i].mac_address, 6);
        _E2B(&p, &ret->local_interfaces[i].media_type);
        _E1B(&p, &ret->local_interfaces[i].media_specific_data_size);

        if ((MEDIA_TYPE_IEEE_802_11B_2_4_GHZ == ret->local_interfaces[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11G_2_4_GHZ == ret->local_interfaces[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11A_5_GHZ   == ret->local_interfaces[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11N_2_4_GHZ == ret->local_interfaces[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11N_5_GHZ   == ret->local_interfaces[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11AC_5_GHZ  == ret->local_interfaces[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11AD_60_GHZ == ret->local_interfaces[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11AF        == ret->local_interfaces[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11AX        == ret->local_interfaces[i].media_type))
        {
            uint8_t aux;
            /* For 11AX, EM R2 standard says size should be 0 but some agents do provide data -> accept both */
            bool    ok =  (10 == ret->local_interfaces[i].media_specific_data_size) ||
                         (( 0 == ret->local_interfaces[i].media_specific_data_size) && (MEDIA_TYPE_IEEE_802_11AX == ret->local_interfaces[i].media_type));

            if (!ok) {
                /* Malformed packet */
                PARSE_FREE_RET_RETURN(device_information)
            }

            if (10 == ret->local_interfaces[i].media_specific_data_size) {
                _EnB(&p, ret->local_interfaces[i].media_specific_data.ieee80211.network_membership, 6);
                _E1B(&p, &aux);
                ret->local_interfaces[i].media_specific_data.ieee80211.role = aux >> 4;
                _E1B(&p, &ret->local_interfaces[i].media_specific_data.ieee80211.ap_channel_band);
                _E1B(&p, &ret->local_interfaces[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_1);
                _E1B(&p, &ret->local_interfaces[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_2);
            }
        } else if ((MEDIA_TYPE_IEEE_1901_WAVELET == ret->local_interfaces[i].media_type) ||
                   (MEDIA_TYPE_IEEE_1901_FFT     == ret->local_interfaces[i].media_type))
        {
            if (7 != ret->local_interfaces[i].media_specific_data_size) {
                /* Malformed packet */
                PARSE_FREE_RET_RETURN(device_information)
            }
            _EnB(&p, ret->local_interfaces[i].media_specific_data.ieee1901.network_identifier, 7);
        } else {
            if (0 != ret->local_interfaces[i].media_specific_data_size) {
                /* Some WFA testbed devices send media_type in a wrong byte order. It is a workaround to be able handle them. */
                if (WFA_CERT_R1_COMPATIBLE() && 10 == ret->local_interfaces[i].media_specific_data_size) {
                     uint8_t aux;
                    _EnB(&p, ret->local_interfaces[i].media_specific_data.ieee80211.network_membership, 6);
                    _E1B(&p, &aux);
                    ret->local_interfaces[i].media_specific_data.ieee80211.role = aux >> 4;
                    _E1B(&p, &ret->local_interfaces[i].media_specific_data.ieee80211.ap_channel_band);
                    _E1B(&p, &ret->local_interfaces[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_1);
                    _E1B(&p, &ret->local_interfaces[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_2);
                } else {
                    /* Malformed packet */
                    PARSE_FREE_RET_RETURN(device_information)
                }
            }
        }
    }

    PARSE_CHECK_INTEGRITY(device_information)
    PARSE_RETURN
}

static uint8_t* forge_device_information_tlv(void *memory_structure, uint16_t *len)
{
    i1905_device_information_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i;

    tlv_length = 7;  /* AL MAC (6 bytes) + number of ifaces (1 bytes) */
    for (i=0; i<m->local_interfaces_nr; i++) {
        tlv_length += 6 + 2 + 1;  /* MAC (6 bytes) + media type (2 bytes) + number of octets (1 byte) */
        tlv_length += m->local_interfaces[i].media_specific_data_size;
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,            &p);
    _I2B(&tlv_length,             &p);
    _InB(m->al_mac_address,       &p, 6);
    _I1B(&m->local_interfaces_nr, &p);

    for (i = 0; i < m->local_interfaces_nr; i++) {
        _InB(m->local_interfaces[i].mac_address,               &p, 6);
        _I2B(&m->local_interfaces[i].media_type,               &p);
        _I1B(&m->local_interfaces[i].media_specific_data_size, &p);

        if ((MEDIA_TYPE_IEEE_802_11B_2_4_GHZ == m->local_interfaces[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11G_2_4_GHZ == m->local_interfaces[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11A_5_GHZ   == m->local_interfaces[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11N_2_4_GHZ == m->local_interfaces[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11N_5_GHZ   == m->local_interfaces[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11AC_5_GHZ  == m->local_interfaces[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11AD_60_GHZ == m->local_interfaces[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11AF        == m->local_interfaces[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11AX        ==  m->local_interfaces[i].media_type))
        {
            uint8_t aux;

            if (10 != m->local_interfaces[i].media_specific_data_size) {
                free(ret);
                return NULL;
            }

            _InB(m->local_interfaces[i].media_specific_data.ieee80211.network_membership,                   &p, 6);
            aux = m->local_interfaces[i].media_specific_data.ieee80211.role << 4;
            _I1B(&aux,                                                                                      &p);
            _I1B(&m->local_interfaces[i].media_specific_data.ieee80211.ap_channel_band,                     &p);
            _I1B(&m->local_interfaces[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_1, &p);
            _I1B(&m->local_interfaces[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_2, &p);

        } else if ((MEDIA_TYPE_IEEE_1901_WAVELET == m->local_interfaces[i].media_type) ||
                   (MEDIA_TYPE_IEEE_1901_FFT     == m->local_interfaces[i].media_type))
        {
            if (7 != m->local_interfaces[i].media_specific_data_size) {
                free(ret);
                return NULL;
            }
            _InB(m->local_interfaces[i].media_specific_data.ieee1901.network_identifier, &p, 7);
        } else {
            if (0 != m->local_interfaces[i].media_specific_data_size) {
                free(ret);
                return NULL;
            }
        }
    }

    FORGE_RETURN
}

/*########################################################################
# Device bridging capability TLV ("Section 6.4.6")                       #
#########################################################################*/
TLV_FREE_FUNCTION(device_bridging_cap)
{
    uint8_t i;

    for (i=0; i < m->bridging_tuples_nr; i++) {
        SFREE(m->bridging_tuples[i].bridging_tuple_macs);
    }
    SFREE(m->bridging_tuples);
}

static uint8_t* parse_device_bridging_cap_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_device_bridging_cap_tlv_t *ret;
    uint8_t *p = packet_stream, i, j;

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_DEVICE_BRIDGING_CAPABILITY;

    if (0 == len) {
#ifdef FIX_BROKEN_TLVS
        /* Malformed packet. Even if there are NO bridging tuples, the
        *  length should be "1" (which is the length of the next field,
        *  that would containing a "zero", indicating the number of
        *  bridging tuples).
        *  *However*, because at least one other implementation sets
        *  the 'length' to zero to indicate "no bridging tuples", we
        *  will also accept this type of "malformed" packet.
        */
        ret->bridging_tuples_nr = 0;
        PARSE_RETURN
#else
        free(ret);
        return NULL;
#endif
    }

    _E1B(&p, &ret->bridging_tuples_nr);

    if (ret->bridging_tuples_nr > 0) {
        ret->bridging_tuples = calloc(ret->bridging_tuples_nr, sizeof(*ret->bridging_tuples));
        if (!ret->bridging_tuples) {
            free(ret);
            return NULL;
        }

        for (i = 0; i < ret->bridging_tuples_nr; i++) {
            _E1B(&p, &ret->bridging_tuples[i].bridging_tuple_macs_nr);

            if (ret->bridging_tuples[i].bridging_tuple_macs_nr > 0) {
                ret->bridging_tuples[i].bridging_tuple_macs = calloc(ret->bridging_tuples[i].bridging_tuple_macs_nr, sizeof(*ret->bridging_tuples[i].bridging_tuple_macs));
                if (!ret->bridging_tuples[i].bridging_tuple_macs) {
                    PARSE_FREE_RET_RETURN(device_bridging_cap)
                }

                for (j=0; j < ret->bridging_tuples[i].bridging_tuple_macs_nr; j++) {
                    _EnB(&p, ret->bridging_tuples[i].bridging_tuple_macs[j].mac_address, 6);
                }
            }
        }
    }

    PARSE_CHECK_INTEGRITY(device_bridging_cap)
    PARSE_RETURN
}

static uint8_t* forge_device_bridging_cap_tlv(void *memory_structure, uint16_t *len)
{
    i1905_device_bridging_cap_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i, j;

    tlv_length = 1;  /* number of bridging tuples (1 bytes) */
    for (i = 0; i < m->bridging_tuples_nr; i++) {
        tlv_length += 1;  /* number of MAC addresses (1 bytes) */
        tlv_length += 6 * m->bridging_tuples[i].bridging_tuple_macs_nr;
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,           &p);
    _I2B(&tlv_length,            &p);
    _I1B(&m->bridging_tuples_nr, &p);

     for (i = 0; i < m->bridging_tuples_nr; i++) {
         _I1B(&m->bridging_tuples[i].bridging_tuple_macs_nr, &p);

         for (j=0; j<m->bridging_tuples[i].bridging_tuple_macs_nr; j++) {
            _InB(m->bridging_tuples[i].bridging_tuple_macs[j].mac_address,  &p, 6);
        }
    }

    FORGE_RETURN
}

/*######################################################################
# Non-1905 neighbor device list TLV ("Section 6.4.8")                  #
#######################################################################*/
TLV_FREE_FUNCTION(non_1905_neighbor_device_list)
{
    SFREE(m->non_1905_neighbors);
}

static uint8_t* parse_non_1905_neighbor_device_list_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_non_1905_neighbor_device_list_tlv_t *ret;;
    uint8_t *p = packet_stream, i;

    /* According to the standard, the length *must* be "6 + 6*n" */
    if (0 != ((len - 6) % 6))
    {
        /* Malformed packet */
        return NULL;
    }

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST;
    _EnB(&p, ret->local_mac_address, 6);

    ret->non_1905_neighbors_nr = (len - 6) / 6;
    ret->non_1905_neighbors = calloc(ret->non_1905_neighbors_nr, sizeof(*ret->non_1905_neighbors));
    if (!ret->non_1905_neighbors) {
        free(ret);
        return NULL;
    }

    for (i = 0; i < ret->non_1905_neighbors_nr; i++) {
        _EnB(&p,  ret->non_1905_neighbors[i].mac_address, 6);
    }

    PARSE_CHECK_INTEGRITY(non_1905_neighbor_device_list)
    PARSE_RETURN
}

static uint8_t* forge_non_1905_neighbor_device_list_tlv(void *memory_structure, uint16_t *len)
{
    i1905_non_1905_neighbor_device_list_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 6 + 6 * m->non_1905_neighbors_nr;
    uint8_t  *ret, *p, i;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,         &p);
    _I2B(&tlv_length,          &p);
    _InB(m->local_mac_address, &p, 6);

    for (i=0; i < m->non_1905_neighbors_nr; i++) {
        _InB(m->non_1905_neighbors[i].mac_address, &p, 6);
    }

    FORGE_RETURN
}

/*#######################################################################
# Neighbor device TLV ("Section 6.4.9")                                 #
########################################################################*/
TLV_FREE_FUNCTION(neighbor_device_list)
{
    SFREE(m->neighbors);
}

static uint8_t* parse_neighbor_device_list_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_neighbor_device_list_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    /* According to the standard, the length *must* be "6 + 7*n" "6+1" */
    if (0 != ((len - 6) % 7)) {
        /* Malformed packet */
        return NULL;
    }

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_NEIGHBOR_DEVICE_LIST;
    _EnB(&p,ret->local_mac_address, 6);

    ret->neighbors_nr = (len-6) / 7;

    ret->neighbors = calloc(ret->neighbors_nr, sizeof(*ret->neighbors));
    if (!ret->neighbors) {
        free(ret);
        return NULL;
    }

    for (i = 0; i < ret->neighbors_nr; i++) {
        uint8_t aux;

        _EnB(&p, ret->neighbors[i].mac_address, 6);
        _E1B(&p, &aux);

        ret->neighbors[i].bridge_flag = (aux & 0x80) ? 1 : 0;
    }

    PARSE_CHECK_INTEGRITY(neighbor_device_list)
    PARSE_RETURN
}

static uint8_t* forge_neighbor_device_list_tlv(void *memory_structure, uint16_t *len)
{
    i1905_neighbor_device_list_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 6 + 7 * m->neighbors_nr;
    uint8_t  *ret, *p, i;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,         &p);
    _I2B(&tlv_length,          &p);
    _InB(m->local_mac_address, &p, 6);

    for (i = 0; i < m->neighbors_nr; i++) {
        uint8_t aux;

        _InB(m->neighbors[i].mac_address, &p, 6);

        if (1 == m->neighbors[i].bridge_flag) {
            aux = 1 << 7;
            _I1B(&aux, &p);
        } else {
            aux = 0;
            _I1B(&aux, &p);
        }
    }

    FORGE_RETURN
}

/*#######################################################################
# Link metric query TLV ("Section 6.4.10")                              #
########################################################################*/
TLV_FREE_FUNCTION(link_metric_query) {}

static uint8_t* parse_link_metric_query_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_link_metric_query_tlv_t *ret;
    uint8_t destination, link_metrics_type;
    uint8_t *p = packet_stream;

    /* According to the standard, the length *must* be atleast 2 */
    PARSE_CHECK_MIN_LEN(2)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_LINK_METRIC_QUERY;
    _E1B(&p, &destination);

    if (8 == len) {
        _EnB(&p, ret->specific_neighbor, 6);
    }

    if (destination == 0) {
        uint8_t dummy_address[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

        ret->destination = LINK_METRIC_QUERY_TLV_ALL_NEIGHBORS;
        maccpy(ret->specific_neighbor, dummy_address);
    } else if (destination == 1) {
        ret->destination = LINK_METRIC_QUERY_TLV_SPECIFIC_NEIGHBOR;
    } else {
        /* Reserved (invalid) value received */
        free(ret);
        return NULL;
    }
    _E1B(&p, &link_metrics_type);

    if (link_metrics_type == 0) {
        ret->link_metrics_type = LINK_METRIC_QUERY_TLV_TX_LINK_METRICS_ONLY;
    } else if (link_metrics_type == 1) {
        ret->link_metrics_type = LINK_METRIC_QUERY_TLV_RX_LINK_METRICS_ONLY;
    } else if (link_metrics_type == 2) {
        ret->link_metrics_type = LINK_METRIC_QUERY_TLV_BOTH_TX_AND_RX_LINK_METRICS;
    } else {
        /* Reserved (invalid) value received */
        free(ret);
        return NULL;
    }

    PARSE_CHECK_INTEGRITY(link_metric_query)
    PARSE_RETURN
}

static uint8_t* forge_link_metric_query_tlv(void *memory_structure, uint16_t *len)
{
    i1905_link_metric_query_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 8;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,    &p);
    _I2B(&tlv_length,     &p);
    _I1B(&m->destination, &p);

    if (LINK_METRIC_QUERY_TLV_SPECIFIC_NEIGHBOR == m->destination) {
        _InB(m->specific_neighbor,  &p, 6);
    } else {
        uint8_t empty_address[] = {m->link_metrics_type, 0x00, 0x00, 0x00, 0x00, 0x00};
        _InB(empty_address, &p, 6);

        /* Ugh? Why is the first value set to "m->link_metrics_type"
        *  instead of "0x00"? What kind of black magic is this?
        *
        *  Well... it turns out there is a reason for this. Take a
        *  chair and let me explain.
        *
        *  The original 1905 standard document (and also its later "1a"
        *  update) describe the "metric query TLV" fields like this:
        *
        *    - Field #1: 1 octet set to "8" (tlv_type)
        *    - Field #2: 1 octet set to "8" (tlv_length)
        *    - Field #3: 1 octet set to "0" or "1" (destination)
        *    - Field #4: 6 octets set to the MAC address of a neighbour
        *                when field #3 is set "1"
        *    - Field #5: 1 octet set to "0", "1", "2" or "3" (link_
        *                _metrics_type)
        *
        *  The problem is that we don't know what to put inside field
        *  #4 when Field #3 is set to "0" ("all neighbors") instead of
        *  "1" ("specific neighbor").
        *
        *  A "reasonable" solution would be to set all bytes from field
        *  #4 to "0x00". *However*, one could also think that the
        *  correct thing to do is to not include the field at all (ie.
        *  skip from field #3 to field #5).
        *
        *  Now... this is actually insane. Typically protocols have a
        *  fixed number of fields (whenever possible) to make it easier
        *  for parsers (in fact, this would be the only exception to
        *  this rule in the whole 1905 standard). Then... why would
        *  someone think that not including field #4 is a good idea?
        *
        *  Well... because this is what the "description" of field #3
        *  reads on the standard:
        *
        *    "If the value is 0, then the EUI-48 field is not present;
        *     if the value is 1, then the EUI-48 field shall be present"
        *
        *  ...and "not present" seems to imply not to include it
        *  (although one could argue that it could also mean "set all
        *  bytes to zero).
        *
        *  I really think the standard means "set to zero" instead of
        *  "not including it" (even if the wording seems to imply
        *  otherwise). Why? For two reasons:
        *
        *    1. The standard says field #2 must *always* be "8" (and if
        *       field #4 could not be included, this value should be
        *       allowed to also take the value of 6)
        *
        *    2. There is no other place in the whole standard where a
        *       field can be present or not.
        *
        *  Despite what I have just said, *some implementations* seem
        *  to have taken the other route, and expect field #4 *not* to
        *  be present (even if field #2 is set to "8"!!).
        *
        *  When we send one "all neighbors" topology query to one of
        *  these implementations they will interpret the first byte of
        *  field #4 as the contents of field #5.
        *
        *  And that's why when querying for all neighbors, because the
        *  contents of field #4 don't really matter, we are going to
        *  set its first byte to the same value as field #5.
        *  This way all implementations, no matter how they decided to
        *  interpret the standard, will work :)
        */
    }

    _I1B(&m->link_metrics_type, &p);

    FORGE_RETURN
}

/*#######################################################################
# Transmitter link metric TLV ("Section 6.4.11")                        #
########################################################################*/
TLV_FREE_FUNCTION(transmitter_link_metric)
{
    SFREE(m->transmitter_link_metrics);
}

static uint8_t* parse_transmitter_link_metric_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_transmitter_link_metric_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    /* According to the standard, the length *must* be "12+29*n" where
    *  "n" is "1" or greater
    */
    PARSE_CHECK_MIN_LEN(12 + 29 * 1);

    if (0 != (len - 12) % 29) {
        /* Malformed packet */
        return NULL;
    }

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_TRANSMITTER_LINK_METRIC;
    _EnB(&p, ret->local_al_address,    6);
    _EnB(&p, ret->neighbor_al_address, 6);

    ret->transmitter_link_metrics_nr = (len - 12) / 29;

    ret->transmitter_link_metrics = calloc(ret->transmitter_link_metrics_nr, sizeof(*ret->transmitter_link_metrics));
    if (!ret->transmitter_link_metrics) {
        free(ret);
        return NULL;
    }

    for (i=0; i < ret->transmitter_link_metrics_nr; i++) {
        _EnB(&p, ret->transmitter_link_metrics[i].local_interface_address,    6);
        _EnB(&p, ret->transmitter_link_metrics[i].neighbor_interface_address, 6);

        _E2B(&p, &ret->transmitter_link_metrics[i].intf_type);
        _E1B(&p, &ret->transmitter_link_metrics[i].bridge_flag);
        _E4B(&p, &ret->transmitter_link_metrics[i].packet_errors);
        _E4B(&p, &ret->transmitter_link_metrics[i].transmitted_packets);
        _E2B(&p, &ret->transmitter_link_metrics[i].mac_throughput_capacity);
        _E2B(&p, &ret->transmitter_link_metrics[i].link_availability);
        _E2B(&p, &ret->transmitter_link_metrics[i].phy_rate);
    }

    PARSE_CHECK_INTEGRITY(transmitter_link_metric)
    PARSE_RETURN
}

static uint8_t* forge_transmitter_link_metric_tlv(void *memory_structure, uint16_t *len)
{
    i1905_transmitter_link_metric_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 12 + 29 * m->transmitter_link_metrics_nr;
    uint8_t  *ret, *p, i;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,           &p);
    _I2B(&tlv_length,            &p);
    _InB(m->local_al_address,    &p, 6);
    _InB(m->neighbor_al_address, &p, 6);

    for (i = 0; i < m->transmitter_link_metrics_nr; i++) {
        _InB( m->transmitter_link_metrics[i].local_interface_address,    &p, 6);
        _InB( m->transmitter_link_metrics[i].neighbor_interface_address, &p, 6);
        _I2B(&m->transmitter_link_metrics[i].intf_type,                  &p);
        _I1B(&m->transmitter_link_metrics[i].bridge_flag,                &p);
        _I4B(&m->transmitter_link_metrics[i].packet_errors,              &p);
        _I4B(&m->transmitter_link_metrics[i].transmitted_packets,        &p);
        _I2B(&m->transmitter_link_metrics[i].mac_throughput_capacity,    &p);
        _I2B(&m->transmitter_link_metrics[i].link_availability,          &p);
        _I2B(&m->transmitter_link_metrics[i].phy_rate,                   &p);
    }

    FORGE_RETURN
}

/*#######################################################################
# Receiver link metric TLV ("Section 6.4.12")                           #
########################################################################*/
TLV_FREE_FUNCTION(receiver_link_metric)
{
    SFREE(m->receiver_link_metrics);
}

static uint8_t* parse_receiver_link_metric_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_receiver_link_metric_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    /* According to the standard, the length *must* be "12+23*n" where
    *  "n" is "1" or greater
    */
    PARSE_CHECK_MIN_LEN(12 + 23 * 1)

    if (0 != (len - 12) % 23) {
        /* Malformed packet */
        return NULL;
    }

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_RECEIVER_LINK_METRIC;
    _EnB(&p, ret->local_al_address,    6);
    _EnB(&p, ret->neighbor_al_address, 6);

    ret->receiver_link_metrics_nr = (len - 12) / 23;

    ret->receiver_link_metrics = calloc(ret->receiver_link_metrics_nr, sizeof(*ret->receiver_link_metrics));
    if (!ret->receiver_link_metrics) {
        free(ret);
        return NULL;
    }

    for (i=0; i < ret->receiver_link_metrics_nr; i++) {
        _EnB(&p,  ret->receiver_link_metrics[i].local_interface_address,    6);
        _EnB(&p,  ret->receiver_link_metrics[i].neighbor_interface_address, 6);

        _E2B(&p, &ret->receiver_link_metrics[i].intf_type);
        _E4B(&p, &ret->receiver_link_metrics[i].packet_errors);
        _E4B(&p, &ret->receiver_link_metrics[i].packets_received);
        _E1B(&p, &ret->receiver_link_metrics[i].rssi);
    }

    PARSE_CHECK_INTEGRITY(receiver_link_metric)
    PARSE_RETURN
}

static uint8_t* forge_receiver_link_metric_tlv(void *memory_structure, uint16_t *len)
{
    i1905_receiver_link_metric_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 12 + 23*m->receiver_link_metrics_nr;
    uint8_t  *ret, *p, i;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,           &p);
    _I2B(&tlv_length,            &p);
    _InB(m->local_al_address,    &p, 6);
    _InB(m->neighbor_al_address, &p, 6);

    for (i=0; i<m->receiver_link_metrics_nr; i++) {
        _InB( m->receiver_link_metrics[i].local_interface_address,    &p, 6);
        _InB( m->receiver_link_metrics[i].neighbor_interface_address, &p, 6);
        _I2B(&m->receiver_link_metrics[i].intf_type,                  &p);
        _I4B(&m->receiver_link_metrics[i].packet_errors,              &p);
        _I4B(&m->receiver_link_metrics[i].packets_received,           &p);
        _I1B(&m->receiver_link_metrics[i].rssi,                       &p);
    }

    FORGE_RETURN
}

/*#######################################################################
# Link metric result code TLV ("Section 6.4.13")                        #
########################################################################*/
TLV_FREE_FUNCTION(link_metric_result_code) {}

static uint8_t* parse_link_metric_result_code_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_link_metric_result_code_tlv_t *ret;
    uint8_t *p = packet_stream;

    /* According to the standard, the length *must* be 1 */
    PARSE_CHECK_EXP_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_LINK_METRIC_RESULT_CODE;
    _E1B(&p, &ret->result_code);

    PARSE_CHECK_INTEGRITY(link_metric_result_code)
    PARSE_RETURN
}

static uint8_t* forge_link_metric_result_code_tlv(void *memory_structure, uint16_t *len)
{
    i1905_link_metric_result_code_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 1;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);

    if (m->result_code != LINK_METRIC_RESULT_CODE_TLV_INVALID_NEIGHBOR) {
        /* Malformed structure */
        free(ret);
        return NULL;
    }

    _I1B(&m->result_code,  &p);

    FORGE_RETURN
}

/*#######################################################################
# Searched role TLV ("Section 6.4.14")                                  #
########################################################################*/
TLV_FREE_FUNCTION(searched_role) {}

static uint8_t* parse_searched_role_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_searched_role_tlv_t *ret;
    uint8_t *p = packet_stream;

    /* According to the standard, the length *must* be 1 */
    PARSE_CHECK_EXP_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_SEARCHED_ROLE;
    _E1B(&p, &ret->role);

    PARSE_CHECK_INTEGRITY(searched_role)
    PARSE_RETURN
}

static uint8_t* forge_searched_role_tlv(void *memory_structure, uint16_t *len)
{
    i1905_searched_role_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 1;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,     &p);
    _I2B(&tlv_length,      &p);

    if (m->role != IEEE80211_ROLE_REGISTRAR) {
        /* Malformed structure */
        free(ret);
        return NULL;
    }

    _I1B(&m->role,  &p);

    FORGE_RETURN
}

/*#######################################################################
# Autoconfig frequency band TLV ("Section 6.4.15")                      #
########################################################################*/
TLV_FREE_FUNCTION(autoconfig_freq_band) {}

static uint8_t* parse_autoconfig_freq_band_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_autoconfig_freq_band_tlv_t *ret;
    uint8_t *p = packet_stream;

    /* According to the standard, the length *must* be 1 */
    PARSE_CHECK_EXP_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_AUTOCONFIG_FREQ_BAND;
    _E1B(&p, &ret->freq_band);

    PARSE_CHECK_INTEGRITY(autoconfig_freq_band)
    PARSE_RETURN
}

static uint8_t* forge_autoconfig_freq_band_tlv(void *memory_structure, uint16_t *len)
{
    i1905_autoconfig_freq_band_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 1;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);

    if ((m->freq_band != IEEE80211_FREQUENCY_BAND_2_4_GHZ) &&
        (m->freq_band != IEEE80211_FREQUENCY_BAND_5_GHZ)   &&
        (m->freq_band != IEEE80211_FREQUENCY_BAND_60_GHZ)) {
        /* Malformed structure */
        free(ret);
        return NULL;
    }

    _I1B(&m->freq_band,  &p);

    FORGE_RETURN
}

/*#######################################################################
# Supported role TLV ("Section 6.4.16")                                 #
########################################################################*/
TLV_FREE_FUNCTION(supported_role) {}

static uint8_t* parse_supported_role_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_supported_role_tlv_t *ret;
    uint8_t *p = packet_stream;

    /* According to the standard, the length *must* be 1 */
    PARSE_CHECK_EXP_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_SUPPORTED_ROLE;
    _E1B(&p, &ret->role);

    PARSE_CHECK_INTEGRITY(supported_role)
    PARSE_RETURN
}

static uint8_t* forge_supported_role_tlv(void *memory_structure, uint16_t *len)
{
    i1905_supported_role_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 1;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);

    if (m->role != IEEE80211_ROLE_REGISTRAR) {
        /* Malformed structure */
        free(ret);
        return NULL;
    }

    _I1B(&m->role,  &p);

    FORGE_RETURN
}

/*#######################################################################
# Supported frequency band TLV ("Section 6.4.17")                       #
########################################################################*/
TLV_FREE_FUNCTION(supported_freq_band) {}

static uint8_t* parse_supported_freq_band_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_supported_freq_band_tlv_t *ret;
    uint8_t *p = packet_stream;

    /* According to the standard, the length *must* be 1 */
    PARSE_CHECK_EXP_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_SUPPORTED_FREQ_BAND;
    _E1B(&p, &ret->freq_band);

    PARSE_CHECK_INTEGRITY(supported_freq_band)
    PARSE_RETURN
}

static uint8_t* forge_supported_freq_band_tlv(void *memory_structure, uint16_t *len)
{
    i1905_supported_freq_band_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 1;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);

    if ((m->freq_band != IEEE80211_FREQUENCY_BAND_2_4_GHZ) &&
        (m->freq_band != IEEE80211_FREQUENCY_BAND_5_GHZ)   &&
        /* (m->freq_band != IEEE80211_FREQUENCY_BAND_6_GHZ)   &&  TODO: add when it is defined in the standard */
        (m->freq_band != IEEE80211_FREQUENCY_BAND_60_GHZ)) {
        /* Malformed structure */
        free(ret);
        return NULL;
    }

    _I1B(&m->freq_band,  &p);

    FORGE_RETURN
}

/*#######################################################################
# WSC TLV ("Section 6.4.18")                                            #
########################################################################*/
TLV_FREE_FUNCTION(wsc)
{
    SFREE(m->wsc_frame);
}

static uint8_t* parse_wsc_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_wsc_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CALLOC_RET

    ret->tlv_type       = TLV_TYPE_WSC;
    ret->wsc_frame_size = len;

    if (len > 0) {
        ret->wsc_frame = malloc(len);
        if (!ret->wsc_frame) {
            free(ret);
            return NULL;
        }
        _EnB(&p, ret->wsc_frame, len);
    }

    PARSE_CHECK_INTEGRITY(wsc)
    PARSE_RETURN
}

static uint8_t* forge_wsc_tlv(void *memory_structure, uint16_t *len)
{
    i1905_wsc_tlv_t *m = memory_structure;
    uint16_t  tlv_length = m->wsc_frame_size;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _InB(m->wsc_frame, &p, m->wsc_frame_size);

    FORGE_RETURN
}

/*#######################################################################
# Push button event notification TLV ("Section 6.4.19")                 #
########################################################################*/
TLV_FREE_FUNCTION(push_button_event_notification)
{
    SFREE(m->media_types);
}

static uint8_t* parse_push_button_event_notification_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_push_button_event_notification_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION;

    if (0 == len) {
#ifdef FIX_BROKEN_TLVS
        /* Malformed packet. Even if there are NO bridging tuples, the
        *  Malformed packet. Even if there are NO media types, the
        *  length should be "1" (which is the length of the next field,
        *  that would containing a "zero", indicating the number of
        *  media types).
        *  *However*, because at least one other implementation sets
        *  the 'length' to zero to indicate "no media types", we will
        *  also accept this type of "malformed" packet.
        */
        ret->media_types_nr = 0;
        PARSE_RETURN
#else
        free(ret);
        return NULL;
#endif
    }

    _E1B(&p, &ret->media_types_nr);

    if (ret->media_types_nr > 0) {
        ret->media_types = calloc(ret->media_types_nr, sizeof(*ret->media_types));
        if (!ret->media_types) {
            free(ret);
            return NULL;
        }

        for (i=0; i < ret->media_types_nr; i++) {
            _E2B(&p, &ret->media_types[i].media_type);
            _E1B(&p, &ret->media_types[i].media_specific_data_size);

            if ((MEDIA_TYPE_IEEE_802_11B_2_4_GHZ == ret->media_types[i].media_type) ||
                (MEDIA_TYPE_IEEE_802_11G_2_4_GHZ == ret->media_types[i].media_type) ||
                (MEDIA_TYPE_IEEE_802_11A_5_GHZ   == ret->media_types[i].media_type) ||
                (MEDIA_TYPE_IEEE_802_11N_2_4_GHZ == ret->media_types[i].media_type) ||
                (MEDIA_TYPE_IEEE_802_11N_5_GHZ   == ret->media_types[i].media_type) ||
                (MEDIA_TYPE_IEEE_802_11AC_5_GHZ  == ret->media_types[i].media_type) ||
                (MEDIA_TYPE_IEEE_802_11AD_60_GHZ == ret->media_types[i].media_type) ||
                (MEDIA_TYPE_IEEE_802_11AF        == ret->media_types[i].media_type) ||
                (MEDIA_TYPE_IEEE_802_11AX        == ret->media_types[i].media_type))
            {
            uint8_t aux;

                if (10 != ret->media_types[i].media_specific_data_size) {
                    /* Malformed packet */
                    PARSE_FREE_RET_RETURN(push_button_event_notification)
                }

                _EnB(&p, ret->media_types[i].media_specific_data.ieee80211.network_membership, 6);
                _E1B(&p, &aux);
                ret->media_types[i].media_specific_data.ieee80211.role = aux >> 4;
                _E1B(&p, &ret->media_types[i].media_specific_data.ieee80211.ap_channel_band);
                _E1B(&p, &ret->media_types[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_1);
                _E1B(&p, &ret->media_types[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_2);

            } else if ((MEDIA_TYPE_IEEE_1901_WAVELET == ret->media_types[i].media_type) ||
                    (MEDIA_TYPE_IEEE_1901_FFT     == ret->media_types[i].media_type))
            {
                if (7 != ret->media_types[i].media_specific_data_size) {
                    /* Malformed packet */
                    PARSE_FREE_RET_RETURN(push_button_event_notification)
                }
                _EnB(&p, ret->media_types[i].media_specific_data.ieee1901.network_identifier, 7);
            } else {
                if (0 != ret->media_types[i].media_specific_data_size) {
                    PARSE_FREE_RET_RETURN(push_button_event_notification)
                }
            }
        }
    }

    PARSE_CHECK_INTEGRITY(push_button_event_notification)
    PARSE_RETURN
}

static uint8_t* forge_push_button_event_notification_tlv(void *memory_structure, uint16_t *len)
{
    i1905_push_button_event_notification_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i;

    tlv_length = 1;  /* number of media types (1 byte) */
    for (i = 0; i < m->media_types_nr; i++) {
        tlv_length += 2 + 1;  /*  media type (2 bytes) + number of octets (1 byte) */

        tlv_length += m->media_types[i].media_specific_data_size;
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,       &p);
    _I2B(&tlv_length,        &p);
    _I1B(&m->media_types_nr, &p);

    for (i=0; i<m->media_types_nr; i++) {
        _I2B(&m->media_types[i].media_type,               &p);
        _I1B(&m->media_types[i].media_specific_data_size, &p);

        if ((MEDIA_TYPE_IEEE_802_11B_2_4_GHZ == m->media_types[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11G_2_4_GHZ == m->media_types[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11A_5_GHZ   == m->media_types[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11N_2_4_GHZ == m->media_types[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11N_5_GHZ   == m->media_types[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11AC_5_GHZ  == m->media_types[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11AD_60_GHZ == m->media_types[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11AF        == m->media_types[i].media_type) ||
            (MEDIA_TYPE_IEEE_802_11AX        ==  m->media_types[i].media_type))
        {
            uint8_t aux;

            if (10 != m->media_types[i].media_specific_data_size) {
                /* Malformed structure */
                free(ret);
                return NULL;
            }

            _InB(m->media_types[i].media_specific_data.ieee80211.network_membership,                   &p, 6);
            aux = m->media_types[i].media_specific_data.ieee80211.role << 4;
            _I1B(&aux,                                                                                 &p);
            _I1B(&m->media_types[i].media_specific_data.ieee80211.ap_channel_band,                     &p);
            _I1B(&m->media_types[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_1, &p);
            _I1B(&m->media_types[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_2, &p);

        } else if ((MEDIA_TYPE_IEEE_1901_WAVELET == m->media_types[i].media_type) ||
                  (MEDIA_TYPE_IEEE_1901_FFT     == m->media_types[i].media_type))
        {
            if (7 != m->media_types[i].media_specific_data_size) {
                /* Malformed structure */
                free(ret);
                return NULL;
            }
            _InB(m->media_types[i].media_specific_data.ieee1901.network_identifier, &p, 7);
        } else {
            if (0 != m->media_types[i].media_specific_data_size) {
                /* Malformed structure */
                free(ret);
                return NULL;
            }
        }
    }

    FORGE_RETURN
}

/*#######################################################################
# Push button join notification TLV ("Section 6.4.20")                  #
########################################################################*/
TLV_FREE_FUNCTION(push_button_join_notification) {}

static uint8_t* parse_push_button_join_notification_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_push_button_join_notification_tlv_t *ret;
    uint8_t *p = packet_stream;

    /* According to the standard, the length *must* be 20 */
    PARSE_CHECK_EXP_LEN(20)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION;
    _EnB(&p, ret->al_mac_address, 6);
    _E2B(&p, &ret->message_identifier);
    _EnB(&p, ret->mac_address, 6);
    _EnB(&p, ret->new_mac_address, 6);

    PARSE_CHECK_INTEGRITY(push_button_join_notification)
    PARSE_RETURN
}

static uint8_t* forge_push_button_join_notification_tlv(void *memory_structure, uint16_t *len)
{
    i1905_push_button_join_notification_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 20;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,           &p);
    _I2B(&tlv_length,            &p);
    _InB(m->al_mac_address,      &p, 6);
    _I2B(&m->message_identifier, &p);
    _InB(m->mac_address,         &p, 6);
    _InB(m->new_mac_address,     &p, 6);

    FORGE_RETURN
}

/*#######################################################################
# Generic PHY device information TLV ("Section 6.4.21")                 #
########################################################################*/
TLV_FREE_FUNCTION(generic_phy_device_information)
{
    uint8_t i;

    for (i=0; i < m->local_interfaces_nr; i++) {
        SFREE(m->local_interfaces[i].generic_phy_description_xml_url);
        SFREE(m->local_interfaces[i].generic_phy_common_data.media_specific_bytes);
    }
    SFREE(m->local_interfaces);
}

static uint8_t* parse_generic_phy_device_information_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_generic_phy_device_information_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_GENERIC_PHY_DEVICE_INFORMATION;

    _EnB(&p,  ret->al_mac_address, 6);
    _E1B(&p, &ret->local_interfaces_nr);

    if (ret->local_interfaces_nr > 0) {
        ret->local_interfaces = calloc(ret->local_interfaces_nr, sizeof(*ret->local_interfaces));
        if (!ret->local_interfaces) {
            free(ret);
            return NULL;
        }

        for (i = 0; i < ret->local_interfaces_nr; i++) {
            _EnB(&p, ret->local_interfaces[i].local_interface_address,                 6);
            _EnB(&p, ret->local_interfaces[i].generic_phy_common_data.oui,             3);
            _E1B(&p, &ret->local_interfaces[i].generic_phy_common_data.variant_index);
            _EnB(&p, ret->local_interfaces[i].variant_name,                           32);
            _E1B(&p, &ret->local_interfaces[i].generic_phy_description_xml_url_len);
            _E1B(&p, &ret->local_interfaces[i].generic_phy_common_data.media_specific_bytes_nr);

            if (ret->local_interfaces[i].generic_phy_description_xml_url_len > 0) {
                ret->local_interfaces[i].generic_phy_description_xml_url = malloc(ret->local_interfaces[i].generic_phy_description_xml_url_len);
                if (!ret->local_interfaces[i].generic_phy_description_xml_url) {
                    PARSE_FREE_RET_RETURN(generic_phy_device_information)
                }
                _EnB(&p, ret->local_interfaces[i].generic_phy_description_xml_url, ret->local_interfaces[i].generic_phy_description_xml_url_len);
            }

            if (ret->local_interfaces[i].generic_phy_common_data.media_specific_bytes_nr > 0) {
                ret->local_interfaces[i].generic_phy_common_data.media_specific_bytes = malloc(ret->local_interfaces[i].generic_phy_common_data.media_specific_bytes_nr);
                if (!ret->local_interfaces[i].generic_phy_common_data.media_specific_bytes) {
                    PARSE_FREE_RET_RETURN(generic_phy_device_information)
                }
                _EnB(&p, ret->local_interfaces[i].generic_phy_common_data.media_specific_bytes, ret->local_interfaces[i].generic_phy_common_data.media_specific_bytes_nr);
            }
        }
    }

    PARSE_CHECK_INTEGRITY(generic_phy_device_information)
    PARSE_RETURN
}

static uint8_t* forge_generic_phy_device_information_tlv(void *memory_structure, uint16_t *len)
{
    i1905_generic_phy_device_information_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i;

    tlv_length  = 6;  /* AL MAC address (6 bytes) */
    tlv_length += 1;  /* number of local interfaces (1 bytes) */
    for (i = 0;  i <m->local_interfaces_nr; i++) {
        tlv_length += 6;  /* local interface MAC address (6 bytes) */
        tlv_length += 3;  /* OUI (3 bytes) */
        tlv_length += 1;  /* variant_index (1 byte) */
        tlv_length += 32; /* variant_name (32 bytes) */
        tlv_length += 1;  /* URL len (1 byte) */
        tlv_length += 1;  /* media specific bytes number (1 bytes) */
        tlv_length += m->local_interfaces[i].generic_phy_description_xml_url_len; /* URL bytes */
        tlv_length += m->local_interfaces[i].generic_phy_common_data.media_specific_bytes_nr; /* media specific bytes */
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,            &p);
    _I2B(&tlv_length,             &p);
    _InB(m->al_mac_address ,      &p,  6);
    _I1B(&m->local_interfaces_nr, &p);

    for (i = 0; i < m->local_interfaces_nr; i++) {
        _InB(m->local_interfaces[i].local_interface_address,                          &p, 6);
        _InB(m->local_interfaces[i].generic_phy_common_data.oui,                      &p, 3);
        _I1B(&m->local_interfaces[i].generic_phy_common_data.variant_index,           &p);
        _InB(m->local_interfaces[i].variant_name,                                     &p, 32);
        _I1B(&m->local_interfaces[i].generic_phy_description_xml_url_len,             &p);
        _I1B(&m->local_interfaces[i].generic_phy_common_data.media_specific_bytes_nr, &p);
        if (m->local_interfaces[i].generic_phy_description_xml_url_len > 0) {
            _InB( m->local_interfaces[i].generic_phy_description_xml_url, &p, m->local_interfaces[i].generic_phy_description_xml_url_len);
        }
        if (m->local_interfaces[i].generic_phy_common_data.media_specific_bytes_nr > 0) {
            _InB( m->local_interfaces[i].generic_phy_common_data.media_specific_bytes, &p, m->local_interfaces[i].generic_phy_common_data.media_specific_bytes_nr);
        }
    }

    FORGE_RETURN
}

/*#######################################################################
# Device identification type TLV ("Section 6.4.22")                     #
########################################################################*/
TLV_FREE_FUNCTION(device_identification) {}

static uint8_t* parse_device_identification_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_device_identification_tlv_t *ret;
    uint8_t *p = packet_stream;

    /* According to the standard, the length *must* be 192 */
    PARSE_CHECK_EXP_LEN(192)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_DEVICE_IDENTIFICATION;

    _EnB(&p, ret->friendly_name,      64);
    _EnB(&p, ret->manufacturer_name,  64);
    _EnB(&p, ret->manufacturer_model, 64);

    PARSE_CHECK_INTEGRITY(device_identification)
    PARSE_RETURN
}

static uint8_t* forge_device_identification_tlv(void *memory_structure, uint16_t *len)
{
    i1905_device_identification_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 192;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,          &p);
    _I2B(&tlv_length,           &p);
    _InB(m->friendly_name,      &p, 64);
    _InB(m->manufacturer_name,  &p, 64);
    _InB(m->manufacturer_model, &p, 64);

    FORGE_RETURN
}

/*#######################################################################
# Control URL type TLV ("Section 6.4.23")                               #
########################################################################*/
TLV_FREE_FUNCTION(control_url)
{
    SFREE(m->url);
}

static uint8_t* parse_control_url_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_control_url_tlv_t *ret;
    uint8_t *p = packet_stream;

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_CONTROL_URL;

    if (len > 0) {
        ret->url = malloc(len);
        if (!ret->url) {
            free(ret);
            return NULL;
        }
        _EnB(&p, ret->url, len);
    }

    PARSE_CHECK_INTEGRITY(control_url)
    PARSE_RETURN
}

static uint8_t* forge_control_url_tlv(void *memory_structure, uint16_t *len)
{
    i1905_control_url_tlv_t *m = memory_structure;
    uint16_t  tlv_length = strlen(m->url)+1;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type, &p);
    _I2B(&tlv_length,  &p);
    _InB(m->url,      &p, tlv_length);

    FORGE_RETURN
}

/*#######################################################################
# IPv4 type TLV ("Section 6.4.24")                                      #
########################################################################*/
TLV_FREE_FUNCTION(ipv4)
{
    uint8_t i;

    for (i=0; i < m->ipv4_interfaces_nr; i++) {
        SFREE(m->ipv4_interfaces[i].ipv4);
    }
    SFREE(m->ipv4_interfaces);
}

static uint8_t* parse_ipv4_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_ipv4_tlv_t *ret;
    uint8_t *p = packet_stream, i, j;

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_IPV4;

    if (0 == len) {
#ifdef FIX_BROKEN_TLVS
        /* Malformed packet. Even if there are NO bridging tuples, the
        *  Malformed packet. Even if there are NO entris, the length
        *  should be "1" (which is the length of the next field, that
        *  would containing a "zero", indicating the number of
        *  entries).
        *  *However*, because at least one other implementation sets
        *  the 'length' to zero to indicate "no entries", we will also
        *  accept this type of "malformed" packet.
        */
        ret->ipv4_interfaces_nr = 0;
        PARSE_RETURN
#else
        free(ret);
        return NULL;
#endif
    }

    _E1B(&p, &ret->ipv4_interfaces_nr);

    if (ret->ipv4_interfaces_nr > 0) {
        ret->ipv4_interfaces = calloc(ret->ipv4_interfaces_nr, sizeof(*ret->ipv4_interfaces));
        if (!ret->ipv4_interfaces) {
            free(ret);
            return NULL;
        }

        for (i=0; i < ret->ipv4_interfaces_nr; i++) {
            _EnB(&p,  ret->ipv4_interfaces[i].mac_address, 6);
            _E1B(&p, &ret->ipv4_interfaces[i].ipv4_nr);

            if (ret->ipv4_interfaces[i].ipv4_nr > 0) {
                ret->ipv4_interfaces[i].ipv4 = calloc(ret->ipv4_interfaces[i].ipv4_nr, sizeof(*ret->ipv4_interfaces[i].ipv4));
                if (!ret->ipv4_interfaces[i].ipv4) {
                    PARSE_FREE_RET_RETURN(ipv4);
                }

                for (j=0; j < ret->ipv4_interfaces[i].ipv4_nr; j++) {
                    _E1B(&p, &ret->ipv4_interfaces[i].ipv4[j].type);
                    _EnB(&p,  ret->ipv4_interfaces[i].ipv4[j].ipv4_address,     4);
                    _EnB(&p,  ret->ipv4_interfaces[i].ipv4[j].ipv4_dhcp_server, 4);
                }
            }
        }
    }

    PARSE_CHECK_INTEGRITY(ipv4)
    PARSE_RETURN
}

static uint8_t* forge_ipv4_tlv(void *memory_structure, uint16_t *len)
{
    i1905_ipv4_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i, j;

    tlv_length = 1;  // number of entries (1 bytes)
    for (i = 0; i < m->ipv4_interfaces_nr; i++) {
        tlv_length += 6;  /* interface MAC address (6 bytes) */
        tlv_length += 1;  /* number of IPv4s (1 bytes) */
        tlv_length += (1 + 4 + 4) * m->ipv4_interfaces[i].ipv4_nr;
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,           &p);
    _I2B(&tlv_length,            &p);
    _I1B(&m->ipv4_interfaces_nr, &p);

    for (i = 0; i < m->ipv4_interfaces_nr; i++) {
        _InB(m->ipv4_interfaces[i].mac_address, &p, 6);
        _I1B(&m->ipv4_interfaces[i].ipv4_nr,    &p);

        for (j = 0; j < m->ipv4_interfaces[i].ipv4_nr; j++) {
            _I1B(&m->ipv4_interfaces[i].ipv4[j].type,            &p);
            _InB(m->ipv4_interfaces[i].ipv4[j].ipv4_address,     &p, 4);
            _InB(m->ipv4_interfaces[i].ipv4[j].ipv4_dhcp_server, &p, 4);
        }
    }

    FORGE_RETURN
}

/*#######################################################################
# IPv6 type TLV ("Section 6.4.25")                                      #
########################################################################*/
TLV_FREE_FUNCTION(ipv6)
{
    uint8_t i;

    for (i=0; i < m->ipv6_interfaces_nr; i++) {
        SFREE(m->ipv6_interfaces[i].ipv6);
    }
    SFREE(m->ipv6_interfaces);
}

static uint8_t* parse_ipv6_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_ipv6_tlv_t *ret;
    uint8_t *p = packet_stream, i, j;

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_IPV6;

    if (0 == len) {
#ifdef FIX_BROKEN_TLVS
        /* Malformed packet. Even if there are NO bridging tuples, the
        *  Malformed packet. Even if there are NO entris, the length
        *  should be "1" (which is the length of the next field, that
        *  would containing a "zero", indicating the number of
        *  entries).
        *  *However*, because at least one other implementation sets
        *  the 'length' to zero to indicate "no entries", we will also
        *  accept this type of "malformed" packet.
        */
        ret->ipv6_interfaces_nr = 0;
        PARSE_RETURN
#else
        free(ret);
        return NULL;
#endif
    }

    _E1B(&p, &ret->ipv6_interfaces_nr);

    if (ret->ipv6_interfaces_nr > 0) {
        ret->ipv6_interfaces = calloc(ret->ipv6_interfaces_nr, sizeof(*ret->ipv6_interfaces));
        if (!ret->ipv6_interfaces) {
            free(ret);
            return NULL;
        }

        for (i=0; i < ret->ipv6_interfaces_nr; i++) {
            _EnB(&p, ret->ipv6_interfaces[i].mac_address,              6);
            _EnB(&p, ret->ipv6_interfaces[i].ipv6_link_local_address, 16);
            _E1B(&p, &ret->ipv6_interfaces[i].ipv6_nr);

            if (ret->ipv6_interfaces[i].ipv6_nr > 0) {
                ret->ipv6_interfaces[i].ipv6 = calloc(ret->ipv6_interfaces[i].ipv6_nr, sizeof(*ret->ipv6_interfaces[i].ipv6));
                if (!ret->ipv6_interfaces[i].ipv6) {
                    PARSE_FREE_RET_RETURN(ipv6);
                }

                for (j=0; j < ret->ipv6_interfaces[i].ipv6_nr; j++) {
                    _E1B(&p, &ret->ipv6_interfaces[i].ipv6[j].type);
                    _EnB(&p, ret->ipv6_interfaces[i].ipv6[j].ipv6_address,        16);
                    _EnB(&p, ret->ipv6_interfaces[i].ipv6[j].ipv6_address_origin, 16);
                }
            }
        }
    }

    PARSE_CHECK_INTEGRITY(ipv6)
    PARSE_RETURN
}

static uint8_t* forge_ipv6_tlv(void *memory_structure, uint16_t *len)
{
    i1905_ipv6_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i, j;

    tlv_length = 1;  /* number of entries (1 bytes) */
    for (i = 0; i < m->ipv6_interfaces_nr; i++) {
        tlv_length += 6;  /* interface MAC address (6 bytes) */
        tlv_length += 16; /* interface ipv6 local link address (16 bytes) */
        tlv_length += 1;  /* number of ipv6s (1 bytes) */
        tlv_length += (1 + 16 + 16) * m->ipv6_interfaces[i].ipv6_nr;
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,           &p);
    _I2B(&tlv_length,            &p);
    _I1B(&m->ipv6_interfaces_nr, &p);

    for (i = 0; i < m->ipv6_interfaces_nr; i++) {
        _InB(m->ipv6_interfaces[i].mac_address,             &p,  6);
        _InB(m->ipv6_interfaces[i].ipv6_link_local_address, &p, 16);
        _I1B(&m->ipv6_interfaces[i].ipv6_nr,                &p);

        for (j = 0; j < m->ipv6_interfaces[i].ipv6_nr; j++) {
            _I1B(&m->ipv6_interfaces[i].ipv6[j].type,               &p);
            _InB(m->ipv6_interfaces[i].ipv6[j].ipv6_address,        &p, 16);
            _InB(m->ipv6_interfaces[i].ipv6[j].ipv6_address_origin, &p, 16);
        }
    }

    FORGE_RETURN
}

/*#######################################################################
# Push button generic PHY event notification TLV ("Section 6.4.26")     #
########################################################################*/
TLV_FREE_FUNCTION(generic_phy_event_notification)
{
    uint8_t i;

    for (i = 0; i < m->local_interfaces_nr; i++) {
        SFREE(m->local_interfaces[i].media_specific_bytes);
    }

    SFREE(m->local_interfaces);
}

static uint8_t* parse_generic_phy_event_notification_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_generic_phy_event_notification_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_GENERIC_PHY_EVENT_NOTIFICATION;

    if (0 == len) {
#ifdef FIX_BROKEN_TLVS
        /* Malformed packet. Even if there are NO bridging tuples, the
        *  Malformed packet. Even if there are NO interfaces, the length
        *  should be "1" (which is the length of the next field, that
        *  would containing a "zero", indicating the number of
        *  interfaces).
        *  *However*, because at least one other implementation sets
        *  the 'length' to zero to indicate "no interfaces", we will
        *  also accept this type of "malformed" packet.
        */
        ret->local_interfaces_nr = 0;
        PARSE_RETURN
#else
        free(ret);
        return NULL;
#endif
    }

    _E1B(&p, &ret->local_interfaces_nr);

    if (ret->local_interfaces_nr > 0) {
        ret->local_interfaces = calloc(ret->local_interfaces_nr, sizeof(*ret->local_interfaces));
        if (!ret->local_interfaces) {
            free(ret);
            return NULL;
        }

        for (i=0; i < ret->local_interfaces_nr; i++) {
            _EnB(&p, ret->local_interfaces[i].oui, 3);
            _E1B(&p, &ret->local_interfaces[i].variant_index);
            _E1B(&p, &ret->local_interfaces[i].media_specific_bytes_nr);

            if (ret->local_interfaces[i].media_specific_bytes_nr > 0) {
                ret->local_interfaces[i].media_specific_bytes = malloc(ret->local_interfaces[i].media_specific_bytes_nr);
                _EnB(&p, ret->local_interfaces[i].media_specific_bytes, ret->local_interfaces[i].media_specific_bytes_nr);
            }
        }
    }

    PARSE_CHECK_INTEGRITY(generic_phy_event_notification)
    PARSE_RETURN
}

static uint8_t* forge_generic_phy_event_notification_tlv(void *memory_structure, uint16_t *len)
{
    i1905_generic_phy_event_notification_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i;

    tlv_length = 1;  /* number of local interfaces (1 bytes) */
    for (i = 0; i < m->local_interfaces_nr; i++) {
        tlv_length += 3;  /* OUI (3 bytes) */
        tlv_length += 1;  /* variant_index (1 byte) */
        tlv_length += 1;  /* media specific bytes number (1 bytes) */
        tlv_length += m->local_interfaces[i].media_specific_bytes_nr; /* media specific bytes */
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,                &p);
    _I2B(&tlv_length,                 &p);
    _I1B(&m->local_interfaces_nr, &p);

    for (i = 0; i < m->local_interfaces_nr; i++) {
        _InB(m->local_interfaces[i].oui,                      &p, 3);
        _I1B(&m->local_interfaces[i].variant_index,           &p);
        _I1B(&m->local_interfaces[i].media_specific_bytes_nr, &p);
        if (m->local_interfaces[i].media_specific_bytes_nr > 0) {
            _InB( m->local_interfaces[i].media_specific_bytes, &p, m->local_interfaces[i].media_specific_bytes_nr);
        }
    }

    FORGE_RETURN
}

/*#######################################################################
# Profile version TLV ("Section 6.4.27")                                #
########################################################################*/
TLV_FREE_FUNCTION(profile_version) {}

static uint8_t* parse_profile_version_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_profile_version_tlv_t *ret;
    uint8_t *p = packet_stream;

    /* According to the standard, the length *must* be 1 */
    PARSE_CHECK_EXP_LEN(1)

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_1905_PROFILE_VERSION;
    _E1B(&p, &ret->profile);

    PARSE_CHECK_INTEGRITY(profile_version)
    PARSE_RETURN
}

static uint8_t* forge_profile_version_tlv(void *memory_structure, uint16_t *len)
{
    i1905_profile_version_tlv_t *m = memory_structure;
    uint16_t  tlv_length = 1;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,     &p);
    _I2B(&tlv_length,      &p);

    if (m->profile != PROFILE_1905_1 &&
        m->profile != PROFILE_1905_1A) {
        /* Malformed structure */
        free(ret);
        return NULL;
    }

    _I1B(&m->profile,  &p);

    FORGE_RETURN
}

/*#######################################################################
# Power off interface TLV ("Section 6.4.28")                            #
########################################################################*/
TLV_FREE_FUNCTION(power_off_interface)
{
    uint8_t i;

    for (i = 0; i < m->power_off_interfaces_nr; i++) {
        SFREE(m->power_off_interfaces[i].generic_phy_common_data.media_specific_bytes);
    }
    SFREE(m->power_off_interfaces);
}

static uint8_t* parse_power_off_interface_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_power_off_interface_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_POWER_OFF_INTERFACE;

    if (0 == len) {
#ifdef FIX_BROKEN_TLVS
        /* Malformed packet. Even if there are NO interfaces, the length
        *  should be "1" (which is the length of the next field, that
        *  would contain a "zero", indicating the number of interfaces)
        *  *However*, because at least one other implementation sets
        *  the 'length' to zero to indicate "no interfaces", we will
        *  also accept this type of "malformed" packet.
        */
        ret->power_off_interfaces_nr = 0;
        PARSE_RETURN
#else
        free(ret);
        return NULL;
#endif
    }

    _E1B(&p, &ret->power_off_interfaces_nr);

    if (ret->power_off_interfaces_nr > 0) {
        ret->power_off_interfaces = calloc(ret->power_off_interfaces_nr, sizeof(*ret->power_off_interfaces));
        if (!ret->power_off_interfaces) {
            free(ret);
            return NULL;
        }

        for (i = 0; i < ret->power_off_interfaces_nr; i++) {
            _EnB(&p, ret->power_off_interfaces[i].interface_address, 6);
            _E2B(&p, &ret->power_off_interfaces[i].media_type);
            _EnB(&p, ret->power_off_interfaces[i].generic_phy_common_data.oui, 3);
            _E1B(&p, &ret->power_off_interfaces[i].generic_phy_common_data.variant_index);
            _E1B(&p, &ret->power_off_interfaces[i].generic_phy_common_data.media_specific_bytes_nr);

            if (ret->power_off_interfaces[i].generic_phy_common_data.media_specific_bytes_nr > 0) {
                ret->power_off_interfaces[i].generic_phy_common_data.media_specific_bytes = malloc(ret->power_off_interfaces[i].generic_phy_common_data.media_specific_bytes_nr);
                _EnB(&p, ret->power_off_interfaces[i].generic_phy_common_data.media_specific_bytes, ret->power_off_interfaces[i].generic_phy_common_data.media_specific_bytes_nr);
            }
        }
    }

    PARSE_CHECK_INTEGRITY(power_off_interface)
    PARSE_RETURN
}

static uint8_t* forge_power_off_interface_tlv(void *memory_structure, uint16_t *len)
{
    i1905_power_off_interface_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i;

    tlv_length = 1;  /* number of power off interfaces (1 bytes) */
    for (i = 0; i < m->power_off_interfaces_nr; i++) {
        tlv_length += 6;  /* interface MAC address (6 bytes) */
        tlv_length += 2;  /* media type (2 bytes) */
        tlv_length += 3;  /* OUI (2 bytes) */
        tlv_length += 1;  /* variant_index (1 byte) */
        tlv_length += 1;  /* media specific bytes number (1 bytes) */
        tlv_length += m->power_off_interfaces[i].generic_phy_common_data.media_specific_bytes_nr; /* media specific bytes */
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,                &p);
    _I2B(&tlv_length,                 &p);
    _I1B(&m->power_off_interfaces_nr, &p);

    for (i=0; i<m->power_off_interfaces_nr; i++) {
        _InB(m->power_off_interfaces[i].interface_address,                                &p, 6);
        _I2B(&m->power_off_interfaces[i].media_type,                                      &p);
        _InB(m->power_off_interfaces[i].generic_phy_common_data.oui,                      &p, 3);
        _I1B(&m->power_off_interfaces[i].generic_phy_common_data.variant_index,           &p);
        _I1B(&m->power_off_interfaces[i].generic_phy_common_data.media_specific_bytes_nr, &p);
        if (m->power_off_interfaces[i].generic_phy_common_data.media_specific_bytes_nr > 0) {
            _InB( m->power_off_interfaces[i].generic_phy_common_data.media_specific_bytes, &p, m->power_off_interfaces[i].generic_phy_common_data.media_specific_bytes_nr);
        }
    }

    FORGE_RETURN
}

/*#######################################################################
# Interface power change information TLV ("Section 6.4.29")             #
########################################################################*/
TLV_FREE_FUNCTION(interface_power_change_information)
{
    SFREE(m->power_change_interfaces);
}

static uint8_t* parse_interface_power_change_information_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_interface_power_change_information_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_INTERFACE_POWER_CHANGE_INFORMATION;

    if (0 == len) {
#ifdef FIX_BROKEN_TLVS
        /* Malformed packet. Even if there are NO bridging tuples, the
        *  Malformed packet. Even if there are NO interfaces, the length
        *  should be "1" (which is the length of the next field, that
        *  would containing a "zero", indicating the number of
        *  interfaces).
        *  *However*, because at least one other implementation sets
        *  the 'length' to zero to indicate "no interfaces", we will
        *  also accept this type of "malformed" packet.
        */
        ret->power_change_interfaces_nr = 0;
        PARSE_RETURN
#else
        free(ret);
        return NULL;
#endif
    }

    _E1B(&p, &ret->power_change_interfaces_nr);

    if (ret->power_change_interfaces_nr > 0) {
        ret->power_change_interfaces = calloc(ret->power_change_interfaces_nr, sizeof(*ret->power_change_interfaces));
        if (!ret->power_change_interfaces) {
            free(ret);
            return NULL;
        }

        for (i=0; i < ret->power_change_interfaces_nr; i++) {
            _EnB(&p,  ret->power_change_interfaces[i].interface_address, 6);
            _E1B(&p, &ret->power_change_interfaces[i].requested_power_state);
        }
    }

    PARSE_CHECK_INTEGRITY(interface_power_change_information)
    PARSE_RETURN
}

static uint8_t* forge_interface_power_change_information_tlv(void *memory_structure, uint16_t *len)
{
    i1905_interface_power_change_information_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i;

    tlv_length  = 1;  /* number of interfaces (1 bytes) */
    tlv_length += (6 + 1) * m->power_change_interfaces_nr;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,                   &p);
    _I2B(&tlv_length,                    &p);
    _I1B(&m->power_change_interfaces_nr, &p);

    for (i = 0; i < m->power_change_interfaces_nr; i++) {
        _InB(m->power_change_interfaces[i].interface_address,      &p, 6);
        _I1B(&m->power_change_interfaces[i].requested_power_state, &p);
    }

    FORGE_RETURN
}

/*#######################################################################
# Interface power change status TLV ("Section 6.4.30")                  #
########################################################################*/
TLV_FREE_FUNCTION(interface_power_change_status)
{
    SFREE(m->power_change_interfaces);
}

static uint8_t* parse_interface_power_change_status_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_interface_power_change_status_tlv_t *ret;
    uint8_t *p = packet_stream, i;

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_INTERFACE_POWER_CHANGE_STATUS;

    if (0 == len) {
#ifdef FIX_BROKEN_TLVS
        /* Malformed packet. Even if there are NO bridging tuples, the
        *  Malformed packet. Even if there are NO interfaces, the length
        *  should be "1" (which is the length of the next field, that
        *  would containing a "zero", indicating the number of
        *  interfaces).
        *  *However*, because at least one other implementation sets
        *  the 'length' to zero to indicate "no interfaces", we will
        *  also accept this type of "malformed" packet.
        */
        ret->power_change_interfaces_nr = 0;
        PARSE_RETURN
#else
        free(ret);
        return NULL;
#endif
    }

    _E1B(&p, &ret->power_change_interfaces_nr);

    if (ret->power_change_interfaces_nr > 0) {
        ret->power_change_interfaces = calloc(ret->power_change_interfaces_nr, sizeof(*ret->power_change_interfaces));
        if (!ret->power_change_interfaces) {
            free(ret);
            return NULL;
        }

        for (i = 0; i < ret->power_change_interfaces_nr; i++) {
            _EnB(&p, ret->power_change_interfaces[i].interface_address, 6);
            _E1B(&p, &ret->power_change_interfaces[i].result);
        }
    }

    PARSE_CHECK_INTEGRITY(interface_power_change_status)
    PARSE_RETURN
}

static uint8_t* forge_interface_power_change_status_tlv(void *memory_structure, uint16_t *len)
{
    i1905_interface_power_change_status_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i;

    tlv_length  = 1;  /* number of interfaces (1 bytes) */
    tlv_length += (6+1) * m->power_change_interfaces_nr;

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,                   &p);
    _I2B(&tlv_length,                    &p);
    _I1B(&m->power_change_interfaces_nr, &p);

    for (i = 0; i<m->power_change_interfaces_nr; i++) {
        _InB( m->power_change_interfaces[i].interface_address, &p, 6);
        _I1B(&m->power_change_interfaces[i].result,            &p);
    }

    FORGE_RETURN
}

/*#######################################################################
# L2 neighbor device TLV ("Section 6.4.31")                             #
########################################################################*/
TLV_FREE_FUNCTION(l2_neighbor_device)
{
    uint8_t i, j;

    for (i = 0; i < m->local_interfaces_nr; i++) {
        for (j = 0; j < m->local_interfaces[i].l2_neighbors_nr; j++) {
             SFREE(m->local_interfaces[i].l2_neighbors[j].behind_mac_addresses);
        }
        SFREE(m->local_interfaces[i].l2_neighbors);
    }
    SFREE(m->local_interfaces);
}

static uint8_t* parse_l2_neighbor_device_tlv(uint8_t *packet_stream, uint16_t len)
{
    i1905_l2_neighbor_device_tlv_t *ret;
    uint8_t *p = packet_stream, i, j, k;

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_L2_NEIGHBOR_DEVICE;

    if (0 == len) {
#ifdef FIX_BROKEN_TLVS
        /* Malformed packet. Even if there are NO bridging tuples, the
        *  Malformed packet. Even if there are NO interfaces, the length
        *  should be "1" (which is the length of the next field, that
        *  would containing a "zero", indicating the number of
        *  interfaces).
        *  *However*, because at least one other implementation sets
        *  the 'length' to zero to indicate "no interfaces", we will
        *  also accept this type of "malformed" packet.
        */
        ret->local_interfaces_nr = 0;
        PARSE_RETURN
#else
        free(ret);
        return NULL;
#endif
    }

    _E1B(&p, &ret->local_interfaces_nr);

    if (ret->local_interfaces_nr > 0) {
        ret->local_interfaces = calloc(ret->local_interfaces_nr, sizeof(*ret->local_interfaces));
        if (!ret->local_interfaces) {
            free(ret);
            return NULL;
        }

        for (i=0; i < ret->local_interfaces_nr; i++) {
            _EnB(&p, ret->local_interfaces[i].local_mac_address, 6);
            _E2B(&p, &ret->local_interfaces[i].l2_neighbors_nr);

            if (ret->local_interfaces[i].l2_neighbors_nr > 0) {
                ret->local_interfaces[i].l2_neighbors = calloc(ret->local_interfaces[i].l2_neighbors_nr, sizeof(*ret->local_interfaces[i].l2_neighbors));
                if (!ret->local_interfaces[i].l2_neighbors) {
                    /* Set l2_neighbors_nr to 0 so tlv is ok for free function */
                    ret->local_interfaces[i].l2_neighbors_nr = 0;
                    PARSE_FREE_RET_RETURN(l2_neighbor_device)
                }

                for (j=0; j < ret->local_interfaces[i].l2_neighbors_nr; j++) {
                    _EnB(&p,  ret->local_interfaces[i].l2_neighbors[j].l2_neighbor_mac_address, 6);
                    _E2B(&p, &ret->local_interfaces[i].l2_neighbors[j].behind_mac_addresses_nr);

                    if (ret->local_interfaces[i].l2_neighbors[j].behind_mac_addresses_nr > 0)
                    {
                        ret->local_interfaces[i].l2_neighbors[j].behind_mac_addresses = malloc(sizeof(mac_addr) * ret->local_interfaces[i].l2_neighbors[j].behind_mac_addresses_nr);
                        if (!ret->local_interfaces[i].l2_neighbors[j].behind_mac_addresses) {
                            PARSE_FREE_RET_RETURN(l2_neighbor_device)
                        }

                        for (k = 0; k < ret->local_interfaces[i].l2_neighbors[j].behind_mac_addresses_nr; k++) {
                            _EnB(&p,  ret->local_interfaces[i].l2_neighbors[j].behind_mac_addresses[k], 6);
                        }
                    }
                }
            }
        }
    }

    PARSE_CHECK_INTEGRITY(l2_neighbor_device)
    PARSE_RETURN
}

static uint8_t* forge_l2_neighbor_device_tlv(void *memory_structure, uint16_t *len)
{
    i1905_l2_neighbor_device_tlv_t *m = memory_structure;
    uint16_t  tlv_length;
    uint8_t  *ret, *p, i, j, k;

    tlv_length = 1;  /* number of entries (1 bytes) */
    for (i = 0; i < m->local_interfaces_nr; i++) {
        tlv_length += 6;  /* interface MAC address (6 bytes) */
        tlv_length += 2;  /* number of neighbors (2 bytes) */

        for (j = 0; j < m->local_interfaces[i].l2_neighbors_nr; j++) {
            tlv_length += 6;  /* neighbor MAC address (6 bytes) */
            tlv_length += 2;  /* number of "behind" MACs (1 bytes) */
            tlv_length += 6 * m->local_interfaces[i].l2_neighbors[j].behind_mac_addresses_nr;
        }
    }

    FORGE_MALLOC_RET

    _I1B(&m->tlv_type,            &p);
    _I2B(&tlv_length,             &p);
    _I1B(&m->local_interfaces_nr, &p);

    for (i=0; i<m->local_interfaces_nr; i++) {
        _InB(m->local_interfaces[i].local_mac_address, &p, 6);
        _I2B(&m->local_interfaces[i].l2_neighbors_nr,  &p);

        for (j = 0; j < m->local_interfaces[i].l2_neighbors_nr; j++) {
            _InB(m->local_interfaces[i].l2_neighbors[j].l2_neighbor_mac_address,  &p, 6);
            _I2B(&m->local_interfaces[i].l2_neighbors[j].behind_mac_addresses_nr, &p);

            for (k = 0; k < m->local_interfaces[i].l2_neighbors[j].behind_mac_addresses_nr; k++) {
                _InB(m->local_interfaces[i].l2_neighbors[j].behind_mac_addresses[k], &p, 6);
            }
        }
    }

    FORGE_RETURN
}

/*#######################################################################
# Unknown TLV                                                           #
########################################################################*/
TLV_FREE_FUNCTION(unknown)
{
    SFREE(m->v);
}

static uint8_t* parse_unknown_tlv(uint8_t *p, uint16_t len)
{
    i1905_unknown_tlv_t *ret;

    PARSE_CALLOC_RET

    ret->tlv_type = TLV_TYPE_UNKNOWN;
    ret->real_tlv_type = p[-TLV_HDR_SIZE]; /* Go back... */
    ret->v_nr = len;

    if (ret->v_nr > 0) {
         ret->v = malloc(ret->v_nr);
         if (NULL == ret->v) {
             free(ret);
             return NULL;
         }
         _EnB(&p, ret->v, ret->v_nr);
     }

    PARSE_RETURN
}

static uint8_t* forge_unknown_tlv(void *memory_structure, uint16_t *len)
{
    i1905_unknown_tlv_t *m = memory_structure;
    uint16_t  tlv_length = m->v_nr;
    uint8_t  *ret, *p;

    FORGE_MALLOC_RET

    _I1B(&m->real_tlv_type, &p);
    _I2B(&tlv_length,       &p);
    if (m->v_nr > 0) {
        _InB(m->v,          &p, m->v_nr);
    }

    FORGE_RETURN
}

/*#######################################################################
# Register TLVs                                                         #
########################################################################*/
static void register_tlvs()
{
    static bool tlvs_registered = false;
    size_t i;

    if (tlvs_registered) {
        return;
    }

    /* Initialize table with unknown tlv handler */
    for (i = 0; i < ARRAY_SIZE(g_tlv_table); i++) {
        tlv_table_entry_t *e = &g_tlv_table[i];
        e->name     = "TLV_TYPE_UNKNOWN";
        e->parse_cb = parse_unknown_tlv;
        e->forge_cb = forge_unknown_tlv;
        e->free_cb  = TLV_VOID_FREE_FUNCTION_NAME(unknown);
    }

    I1905_REGISTER_TLV(TLV_TYPE_END_OF_MESSAGE,                     end_of_message                    );
    I1905_REGISTER_TLV(TLV_TYPE_VENDOR_SPECIFIC,                    vendor_specific                   );
    I1905_REGISTER_TLV(TLV_TYPE_AL_MAC_ADDRESS,                     al_mac_address                    );
    I1905_REGISTER_TLV(TLV_TYPE_MAC_ADDRESS,                        mac_address                       );
    I1905_REGISTER_TLV(TLV_TYPE_DEVICE_INFORMATION,                 device_information                );
    I1905_REGISTER_TLV(TLV_TYPE_DEVICE_BRIDGING_CAPABILITY,         device_bridging_cap               );
    I1905_REGISTER_TLV(TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST,      non_1905_neighbor_device_list     );
    I1905_REGISTER_TLV(TLV_TYPE_NEIGHBOR_DEVICE_LIST,               neighbor_device_list              );
    I1905_REGISTER_TLV(TLV_TYPE_LINK_METRIC_QUERY,                  link_metric_query                 );
    I1905_REGISTER_TLV(TLV_TYPE_TRANSMITTER_LINK_METRIC,            transmitter_link_metric           );
    I1905_REGISTER_TLV(TLV_TYPE_RECEIVER_LINK_METRIC,               receiver_link_metric              );
    I1905_REGISTER_TLV(TLV_TYPE_LINK_METRIC_RESULT_CODE,            link_metric_result_code           );
    I1905_REGISTER_TLV(TLV_TYPE_SEARCHED_ROLE,                      searched_role                     );
    I1905_REGISTER_TLV(TLV_TYPE_AUTOCONFIG_FREQ_BAND,               autoconfig_freq_band              );
    I1905_REGISTER_TLV(TLV_TYPE_SUPPORTED_ROLE,                     supported_role                    );
    I1905_REGISTER_TLV(TLV_TYPE_SUPPORTED_FREQ_BAND,                supported_freq_band               );
    I1905_REGISTER_TLV(TLV_TYPE_WSC,                                wsc                               );
    I1905_REGISTER_TLV(TLV_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION,     push_button_event_notification    );
    I1905_REGISTER_TLV(TLV_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION,      push_button_join_notification     );
    I1905_REGISTER_TLV(TLV_TYPE_GENERIC_PHY_DEVICE_INFORMATION,     generic_phy_device_information    );
    I1905_REGISTER_TLV(TLV_TYPE_DEVICE_IDENTIFICATION,              device_identification             );
    I1905_REGISTER_TLV(TLV_TYPE_CONTROL_URL,                        control_url                       );
    I1905_REGISTER_TLV(TLV_TYPE_IPV4,                               ipv4                              );
    I1905_REGISTER_TLV(TLV_TYPE_IPV6,                               ipv6                              );
    I1905_REGISTER_TLV(TLV_TYPE_GENERIC_PHY_EVENT_NOTIFICATION,     generic_phy_event_notification    );
    I1905_REGISTER_TLV(TLV_TYPE_1905_PROFILE_VERSION,               profile_version                   );
    I1905_REGISTER_TLV(TLV_TYPE_POWER_OFF_INTERFACE,                power_off_interface               );
    I1905_REGISTER_TLV(TLV_TYPE_INTERFACE_POWER_CHANGE_INFORMATION, interface_power_change_information);
    I1905_REGISTER_TLV(TLV_TYPE_INTERFACE_POWER_CHANGE_STATUS,      interface_power_change_status     );
    I1905_REGISTER_TLV(TLV_TYPE_L2_NEIGHBOR_DEVICE,                 l2_neighbor_device                );

    map_r1_register_tlvs();
    map_r2_register_tlvs();
    map_r3_register_tlvs();

    tlvs_registered = true;
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
uint8_t *parse_1905_TLV_from_packet(uint8_t *packet_stream, uint16_t bytes_left)
{
    uint8_t  tlv_type, *ret;
    uint8_t *p = packet_stream;
    uint16_t len;

    register_tlvs();

    if (NULL == packet_stream) {
        return NULL;
    }

    /* Need at least 3 bytes */
    if (bytes_left < TLV_HDR_SIZE) {
        log_i1905_e("malformed packet TLV too short header");
        return NULL;
    }

    /* The first byte of the stream is the "Type" field from the TLV structure. */
    _E1B(&p, &tlv_type);
    _E2B(&p, &len);

    bytes_left -= TLV_HDR_SIZE;
    if (len > bytes_left) {
        log_i1905_e("malformed packet TLV truncated: size[%d] bytes_left[%d]", len, bytes_left);
        return NULL;
    }

    /* FRV: For EMR3 this check needs to be removed */
    if (len > MAX_TLV_PAYLOAD_SIZE) {
        log_i1905_e("malformed packet TLV size is too big size = %d\n", len);
        return NULL;
    }

    if (NULL == (ret = g_tlv_table[tlv_type].parse_cb(p, len))) {
        log_i1905_e("failed parsing %s", convert_1905_TLV_type_to_string(tlv_type));
    }

    return ret;
}


uint8_t *forge_1905_TLV_from_structure(uint8_t *memory_structure, uint16_t *len)
{
    uint8_t tlv_type, *ret;

    register_tlvs();

    if (NULL == memory_structure) {
        return NULL;
    }
    tlv_type = *memory_structure;

#ifndef UNIT_TEST
    /* Do not insert multiap_profile tlv during WFA R1 certification. */
    if (WFA_CERT_R1_COMPATIBLE() && tlv_type == TLV_TYPE_MULTIAP_PROFILE) {
        return NULL;
    }
#endif /* UNIT_TEST */

    if (NULL == (ret = g_tlv_table[tlv_type].forge_cb(memory_structure, len))) {
        log_i1905_e("failed forging %s", convert_1905_TLV_type_to_string(tlv_type));
    }

    return ret;
}

void free_1905_TLV_structure(uint8_t *memory_structure)
{
    register_tlvs();

    if (NULL == memory_structure) {
        return;
    }

    g_tlv_table[*memory_structure].free_cb(memory_structure);
    free(memory_structure);
}


uint8_t compare_1905_TLV_structures(uint8_t *memory_structure_1, uint8_t *memory_structure_2)
{
    uint8_t i, j, k;

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
        case TLV_TYPE_END_OF_MESSAGE: {
            /* Nothing to compare (this TLV is always empty) */
            return 0;
        }
        case TLV_TYPE_VENDOR_SPECIFIC: {
            i1905_vendor_specific_tlv_t *p1 = (i1905_vendor_specific_tlv_t *)memory_structure_1;
            i1905_vendor_specific_tlv_t *p2 = (i1905_vendor_specific_tlv_t *)memory_structure_2;

            if (p1->vendorOUI[0] != p2->vendorOUI[0]      ||
                p1->vendorOUI[1] != p2->vendorOUI[1]      ||
                p1->vendorOUI[2] != p2->vendorOUI[2]      ||
                p1->m_nr         != p2->m_nr              ||
                (memcmp(p1->m, p2->m, p1->m_nr) !=0)) {
                return 1;
            } else {
                return 0;
            }
        }
        case TLV_TYPE_AL_MAC_ADDRESS: {
            i1905_al_mac_address_tlv_t *p1 = (i1905_al_mac_address_tlv_t *)memory_structure_1;
            i1905_al_mac_address_tlv_t *p2 = (i1905_al_mac_address_tlv_t *)memory_structure_2;

            if ((maccmp(p1->al_mac_address, p2->al_mac_address) !=0)) {
                return 1;
            } else {
                return 0;
            }
        }
        case TLV_TYPE_MAC_ADDRESS: {
            i1905_mac_address_tlv_t *p1 = (i1905_mac_address_tlv_t *)memory_structure_1;
            i1905_mac_address_tlv_t *p2 = (i1905_mac_address_tlv_t *)memory_structure_2;

            if ((maccmp(p1->mac_address, p2->mac_address) !=0)) {
                return 1;
            } else {
                return 0;
            }
        }
        case TLV_TYPE_DEVICE_INFORMATION: {
            i1905_device_information_tlv_t *p1 = (i1905_device_information_tlv_t *)memory_structure_1;
            i1905_device_information_tlv_t *p2 = (i1905_device_information_tlv_t *)memory_structure_2;

            if (maccmp(p1->al_mac_address, p2->al_mac_address) !=0  ||
                p1->local_interfaces_nr != p2->local_interfaces_nr) {
                return 1;
            }

            if (p1->local_interfaces_nr > 0 && (NULL == p1->local_interfaces || NULL == p2->local_interfaces)) {
                /* Malformed structure */
                return 1;
            }

            for (i = 0; i < p1->local_interfaces_nr; i++) {
                if (maccmp(p1->local_interfaces[i].mac_address, p2->local_interfaces[i].mac_address) !=0   ||
                    p1->local_interfaces[i].media_type               != p2->local_interfaces[i].media_type ||
                    p1->local_interfaces[i].media_specific_data_size != p2->local_interfaces[i].media_specific_data_size) {
                    return 1;
                }

                if ((MEDIA_TYPE_IEEE_802_11B_2_4_GHZ == p1->local_interfaces[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11G_2_4_GHZ == p1->local_interfaces[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11A_5_GHZ   == p1->local_interfaces[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11N_2_4_GHZ == p1->local_interfaces[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11N_5_GHZ   == p1->local_interfaces[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11AC_5_GHZ  == p1->local_interfaces[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11AD_60_GHZ == p1->local_interfaces[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11AF        == p1->local_interfaces[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11AX        ==  p1->local_interfaces[i].media_type)) {
                    if (maccmp(p1->local_interfaces[i].media_specific_data.ieee80211.network_membership, p2->local_interfaces[i].media_specific_data.ieee80211.network_membership) !=0      ||
                        p1->local_interfaces[i].media_specific_data.ieee80211.role                                !=  p2->local_interfaces[i].media_specific_data.ieee80211.role            ||
                        p1->local_interfaces[i].media_specific_data.ieee80211.ap_channel_band                     !=  p2->local_interfaces[i].media_specific_data.ieee80211.ap_channel_band ||
                        p1->local_interfaces[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_1 !=  p2->local_interfaces[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_1) {
                        return 1;
                    }

                }
                else if ((MEDIA_TYPE_IEEE_1901_WAVELET == p1->local_interfaces[i].media_type) ||
                         (MEDIA_TYPE_IEEE_1901_FFT     == p1->local_interfaces[i].media_type)) {
                    if (maccmp(p1->local_interfaces[i].media_specific_data.ieee1901.network_identifier,  p2->local_interfaces[i].media_specific_data.ieee1901.network_identifier) !=0) {
                        return 1;
                    }
                }
            }

            return 0;
        }
        case TLV_TYPE_DEVICE_BRIDGING_CAPABILITY: {
            i1905_device_bridging_cap_tlv_t *p1 = (i1905_device_bridging_cap_tlv_t *)memory_structure_1;
            i1905_device_bridging_cap_tlv_t *p2 = (i1905_device_bridging_cap_tlv_t *)memory_structure_2;

            if ( p1->bridging_tuples_nr != p2->bridging_tuples_nr) {
                return 1;
            }

            if (p1->bridging_tuples_nr > 0 && (NULL == p1->bridging_tuples || NULL == p2->bridging_tuples)) {
                /* Malformed structure */
                return 1;
            }

            for (i = 0; i < p1->bridging_tuples_nr; i++) {
                if (p1->bridging_tuples[i].bridging_tuple_macs_nr  !=  p2->bridging_tuples[i].bridging_tuple_macs_nr) {
                    return 1;
                }

                for (j = 0; j < p1->bridging_tuples[i].bridging_tuple_macs_nr; j++) {
                    if (maccmp(p1->bridging_tuples[i].bridging_tuple_macs[j].mac_address,  p2->bridging_tuples[i].bridging_tuple_macs[j].mac_address) !=0) {
                        return 1;
                    }
                }
            }

            return 0;
        }
        case TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST: {
            i1905_non_1905_neighbor_device_list_tlv_t *p1 = (i1905_non_1905_neighbor_device_list_tlv_t *)memory_structure_1;
            i1905_non_1905_neighbor_device_list_tlv_t *p2 = (i1905_non_1905_neighbor_device_list_tlv_t *)memory_structure_2;

            if (maccmp(p1->local_mac_address, p2->local_mac_address) !=0  ||
                p1->non_1905_neighbors_nr != p2->non_1905_neighbors_nr) {
                return 1;
            }

            if (p1->non_1905_neighbors_nr > 0 && (NULL == p1->non_1905_neighbors || NULL == p2->non_1905_neighbors)) {
                /* Malformed structure */
                return 1;
            }

            for (i = 0; i < p1->non_1905_neighbors_nr; i++) {
                if (maccmp(p1->non_1905_neighbors[i].mac_address,     p2->non_1905_neighbors[i].mac_address) !=0) {
                    return 1;
                }
            }

            return 0;
        }
        case TLV_TYPE_NEIGHBOR_DEVICE_LIST: {
            i1905_neighbor_device_list_tlv_t *p1 = (i1905_neighbor_device_list_tlv_t *)memory_structure_1;
            i1905_neighbor_device_list_tlv_t *p2 = (i1905_neighbor_device_list_tlv_t *)memory_structure_2;

            if (maccmp(p1->local_mac_address, p2->local_mac_address) !=0  ||
                p1->neighbors_nr != p2->neighbors_nr) {
                return 1;
            }

            if (p1->neighbors_nr > 0 && (NULL == p1->neighbors || NULL == p2->neighbors)) {
                //* Malformed structure */
                return 1;
            }

            for (i = 0; i < p1->neighbors_nr; i++) {
                if (maccmp(p1->neighbors[i].mac_address, p2->neighbors[i].mac_address) !=0  ||
                    p1->neighbors[i].bridge_flag != p2->neighbors[i].bridge_flag) {
                    return 1;
                }
            }

            return 0;
        }
        case TLV_TYPE_LINK_METRIC_QUERY: {
            i1905_link_metric_query_tlv_t *p1 = (i1905_link_metric_query_tlv_t *)memory_structure_1;
            i1905_link_metric_query_tlv_t *p2 = (i1905_link_metric_query_tlv_t *)memory_structure_2;

            if (p1->destination != p2->destination                        ||
                maccmp(p1->specific_neighbor, p2->specific_neighbor) !=0  ||
                p1->link_metrics_type != p2->link_metrics_type) {
                return 1;
            } else {
                return 0;
            }
        }
        case TLV_TYPE_TRANSMITTER_LINK_METRIC: {
            i1905_transmitter_link_metric_tlv_t *p1 = (i1905_transmitter_link_metric_tlv_t *)memory_structure_1;
            i1905_transmitter_link_metric_tlv_t *p2 = (i1905_transmitter_link_metric_tlv_t *)memory_structure_2;

            if (maccmp(p1->local_al_address, p2->local_al_address) !=0       ||
                maccmp(p1->neighbor_al_address, p2->neighbor_al_address) !=0 ||
                p1->transmitter_link_metrics_nr != p2->transmitter_link_metrics_nr) {
                return 1;
            }

            if (p1->transmitter_link_metrics_nr > 0 && (NULL == p1->transmitter_link_metrics || NULL == p2->transmitter_link_metrics)) {
                /* Malformed structure */
                return 1;
            }

            for (i = 0; i<p1->transmitter_link_metrics_nr; i++) {
                if (maccmp(p1->transmitter_link_metrics[i].local_interface_address, p2->transmitter_link_metrics[i].local_interface_address) !=0       ||
                    maccmp(p1->transmitter_link_metrics[i].neighbor_interface_address, p2->transmitter_link_metrics[i].neighbor_interface_address) !=0 ||
                    p1->transmitter_link_metrics[i].intf_type               != p2->transmitter_link_metrics[i].intf_type                               ||
                    p1->transmitter_link_metrics[i].bridge_flag             != p2->transmitter_link_metrics[i].bridge_flag                             ||
                    p1->transmitter_link_metrics[i].packet_errors           != p2->transmitter_link_metrics[i].packet_errors                           ||
                    p1->transmitter_link_metrics[i].transmitted_packets     != p2->transmitter_link_metrics[i].transmitted_packets                     ||
                    p1->transmitter_link_metrics[i].mac_throughput_capacity != p2->transmitter_link_metrics[i].mac_throughput_capacity                 ||
                    p1->transmitter_link_metrics[i].link_availability       != p2->transmitter_link_metrics[i].link_availability                       ||
                    p1->transmitter_link_metrics[i].phy_rate                != p2->transmitter_link_metrics[i].phy_rate) {
                    return 1;
                }
            }

            return 0;
        }
        case TLV_TYPE_RECEIVER_LINK_METRIC: {
            i1905_receiver_link_metric_tlv_t *p1 = (i1905_receiver_link_metric_tlv_t *)memory_structure_1;
            i1905_receiver_link_metric_tlv_t *p2 = (i1905_receiver_link_metric_tlv_t *)memory_structure_2;

            if (maccmp(p1->local_al_address, p2->local_al_address) !=0       ||
                maccmp(p1->neighbor_al_address,p2->neighbor_al_address) !=0  ||
                p1->receiver_link_metrics_nr != p2->receiver_link_metrics_nr) {
                return 1;
            }

            if (p1->receiver_link_metrics_nr > 0 && (NULL == p1->receiver_link_metrics || NULL == p2->receiver_link_metrics)) {
                /* Malformed structure */
                return 1;
            }

            for (i = 0; i < p1->receiver_link_metrics_nr; i++) {
                if (maccmp(p1->receiver_link_metrics[i].local_interface_address,    p2->receiver_link_metrics[i].local_interface_address) !=0    ||
                    maccmp(p1->receiver_link_metrics[i].neighbor_interface_address, p2->receiver_link_metrics[i].neighbor_interface_address) !=0 ||
                    p1->receiver_link_metrics[i].intf_type        != p2->receiver_link_metrics[i].intf_type                                      ||
                    p1->receiver_link_metrics[i].packet_errors    != p2->receiver_link_metrics[i].packet_errors                                  ||
                    p1->receiver_link_metrics[i].packets_received != p2->receiver_link_metrics[i].packets_received                               ||
                    p1->receiver_link_metrics[i].rssi             != p2->receiver_link_metrics[i].rssi) {
                    return 1;
                }
            }

            return 0;
        }
        case TLV_TYPE_LINK_METRIC_RESULT_CODE: {
            i1905_link_metric_result_code_tlv_t *p1 = (i1905_link_metric_result_code_tlv_t *)memory_structure_1;
            i1905_link_metric_result_code_tlv_t *p2 = (i1905_link_metric_result_code_tlv_t *)memory_structure_2;

            return (p1->result_code != p2->result_code) ? 1 : 0;
        }
        case TLV_TYPE_SEARCHED_ROLE: {
            i1905_searched_role_tlv_t *p1 = (i1905_searched_role_tlv_t *)memory_structure_1;
            i1905_searched_role_tlv_t *p2 = (i1905_searched_role_tlv_t *)memory_structure_2;

            return (p1->role != p2->role) ? 1 : 0;
        }
        case TLV_TYPE_AUTOCONFIG_FREQ_BAND: {
            i1905_autoconfig_freq_band_tlv_t *p1 = (i1905_autoconfig_freq_band_tlv_t *)memory_structure_1;
            i1905_autoconfig_freq_band_tlv_t *p2 = (i1905_autoconfig_freq_band_tlv_t *)memory_structure_2;

            return (p1->freq_band != p2->freq_band) ? 1 : 0;
        }
        case TLV_TYPE_SUPPORTED_ROLE: {
            i1905_supported_role_tlv_t *p1 = (i1905_supported_role_tlv_t *)memory_structure_1;
            i1905_supported_role_tlv_t *p2 = (i1905_supported_role_tlv_t *)memory_structure_2;

            return (p1->role != p2->role) ? 1 : 0;
        }
        case TLV_TYPE_SUPPORTED_FREQ_BAND: {
            i1905_supported_freq_band_tlv_t *p1 = (i1905_supported_freq_band_tlv_t *)memory_structure_1;
            i1905_supported_freq_band_tlv_t *p2 = (i1905_supported_freq_band_tlv_t *)memory_structure_2;

            return (p1->freq_band != p2->freq_band) ? 1 : 0;
        }
        case TLV_TYPE_WSC: {
            i1905_wsc_tlv_t *p1 = (i1905_wsc_tlv_t *)memory_structure_1;
            i1905_wsc_tlv_t *p2 = (i1905_wsc_tlv_t *)memory_structure_2;

            if (p1->wsc_frame_size != p2->wsc_frame_size                      ||
                memcmp(p1->wsc_frame, p2->wsc_frame, p1->wsc_frame_size) !=0) {
                return 1;
            }

            return 0;
        }
        case TLV_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION: {
            i1905_push_button_event_notification_tlv_t *p1 = (i1905_push_button_event_notification_tlv_t *)memory_structure_1;
            i1905_push_button_event_notification_tlv_t *p2 = (i1905_push_button_event_notification_tlv_t *)memory_structure_2;

            if (p1->media_types_nr !=  p2->media_types_nr) {
                return 1;
            }

            if (p1->media_types_nr > 0 && (NULL == p1->media_types || NULL == p2->media_types)) {
                /* Malformed structure */
                return 1;
            }

            for (i = 0; i < p1->media_types_nr; i++) {
                if (p1->media_types[i].media_type               !=  p2->media_types[i].media_type               ||
                    p1->media_types[i].media_specific_data_size !=  p2->media_types[i].media_specific_data_size) {
                    return 1;
                }

                if ((MEDIA_TYPE_IEEE_802_11B_2_4_GHZ == p1->media_types[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11G_2_4_GHZ == p1->media_types[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11A_5_GHZ   == p1->media_types[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11N_2_4_GHZ == p1->media_types[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11N_5_GHZ   == p1->media_types[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11AC_5_GHZ  == p1->media_types[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11AD_60_GHZ == p1->media_types[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11AF        == p1->media_types[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11AX        ==  p1->media_types[i].media_type)) {
                    if (maccmp(p1->media_types[i].media_specific_data.ieee80211.network_membership, p2->media_types[i].media_specific_data.ieee80211.network_membership) !=0                          ||
                        p1->media_types[i].media_specific_data.ieee80211.role                                != p2->media_types[i].media_specific_data.ieee80211.role                                 ||
                        p1->media_types[i].media_specific_data.ieee80211.ap_channel_band                     != p2->media_types[i].media_specific_data.ieee80211.ap_channel_band                      ||
                        p1->media_types[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_1 != p2->media_types[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_1) {
                        return 1;
                    }
                } else if ((MEDIA_TYPE_IEEE_1901_WAVELET == p1->media_types[i].media_type) ||
                           (MEDIA_TYPE_IEEE_1901_FFT     == p1->media_types[i].media_type)) {
                    if (maccmp(p1->media_types[i].media_specific_data.ieee1901.network_identifier,  p2->media_types[i].media_specific_data.ieee1901.network_identifier) !=0) {
                        return 1;
                    }
                }
            }

            return 0;
        }
        case TLV_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION: {
            i1905_push_button_join_notification_tlv_t *p1 = (i1905_push_button_join_notification_tlv_t *)memory_structure_1;
            i1905_push_button_join_notification_tlv_t *p2 = (i1905_push_button_join_notification_tlv_t *)memory_structure_2;

            if (maccmp(p1->al_mac_address,  p2->al_mac_address) !=0 ||
                p1->message_identifier !=   p2->message_identifier  ||
                maccmp(p1->mac_address,     p2->mac_address) !=0    ||
                maccmp(p1->new_mac_address, p2->new_mac_address) !=0) {
                return 1;
            } else {
                return 0;
            }
        }
        case TLV_TYPE_DEVICE_IDENTIFICATION: {
            i1905_device_identification_tlv_t*p1 = (i1905_device_identification_tlv_t*)memory_structure_1;
            i1905_device_identification_tlv_t*p2 = (i1905_device_identification_tlv_t*)memory_structure_2;

            if (memcmp(p1->friendly_name,      p2->friendly_name,      64) !=0  ||
                memcmp(p1->manufacturer_name,  p2->manufacturer_name,  64) !=0  ||
                memcmp(p1->manufacturer_model, p2->manufacturer_model, 64) !=0) {
                return 1;
            } else {
                return 0;
            }
        }
        case TLV_TYPE_CONTROL_URL: {
            i1905_control_url_tlv_t *p1 = (i1905_control_url_tlv_t *)memory_structure_1;
            i1905_control_url_tlv_t *p2 = (i1905_control_url_tlv_t *)memory_structure_2;

            if (memcmp(p1->url, p2->url, strlen(p1->url)+1) !=0) {
                return 1;
            } else {
                return 0;
            }
        }
        case TLV_TYPE_IPV4: {
            i1905_ipv4_tlv_t *p1 = (i1905_ipv4_tlv_t *)memory_structure_1;
            i1905_ipv4_tlv_t *p2 = (i1905_ipv4_tlv_t *)memory_structure_2;

            if (p1->ipv4_interfaces_nr != p2->ipv4_interfaces_nr) {
                return 1;
            }

            if (p1->ipv4_interfaces_nr > 0 && (NULL == p1->ipv4_interfaces || NULL == p2->ipv4_interfaces)) {
                /* Malformed structure */
                return 1;
            }

            for (i=0; i<p1->ipv4_interfaces_nr; i++) {
                if (maccmp(p1->ipv4_interfaces[i].mac_address, p2->ipv4_interfaces[i].mac_address) !=0   ||
                    p1->ipv4_interfaces[i].ipv4_nr !=  p2->ipv4_interfaces[i].ipv4_nr) {
                    return 1;
                }

                for (j = 0; j < p1->ipv4_interfaces[i].ipv4_nr; j++) {
                    if (p1->ipv4_interfaces[i].ipv4[j].type != p2->ipv4_interfaces[i].ipv4[j].type                                      ||
                        memcmp(p1->ipv4_interfaces[i].ipv4[j].ipv4_address,     p2->ipv4_interfaces[i].ipv4[j].ipv4_address,     4) !=0 ||
                        memcmp(p1->ipv4_interfaces[i].ipv4[j].ipv4_dhcp_server, p2->ipv4_interfaces[i].ipv4[j].ipv4_dhcp_server, 4) !=0) {
                        return 1;
                    }
                }
            }

            return 0;
        }
        case TLV_TYPE_IPV6: {
            i1905_ipv6_tlv_t *p1 = (i1905_ipv6_tlv_t *)memory_structure_1;
            i1905_ipv6_tlv_t *p2 = (i1905_ipv6_tlv_t *)memory_structure_2;

            if (p1->ipv6_interfaces_nr != p2->ipv6_interfaces_nr) {
                return 1;
            }

            if (p1->ipv6_interfaces_nr > 0 && (NULL == p1->ipv6_interfaces || NULL == p2->ipv6_interfaces)) {
                /* Malformed structure */
                return 1;
            }

            for (i = 0; i < p1->ipv6_interfaces_nr; i++) {
                if (maccmp(p1->ipv6_interfaces[i].mac_address, p2->ipv6_interfaces[i].mac_address) !=0   ||
                    p1->ipv6_interfaces[i].ipv6_nr != p2->ipv6_interfaces[i].ipv6_nr) {
                    return 1;
                }

                for (j = 0; j < p1->ipv6_interfaces[i].ipv6_nr; j++) {
                    if (p1->ipv6_interfaces[i].ipv6[j].type !=  p2->ipv6_interfaces[i].ipv6[j].type                                            ||
                        memcmp(p1->ipv6_interfaces[i].ipv6[j].ipv6_address,        p2->ipv6_interfaces[i].ipv6[j].ipv6_address,        16) !=0 ||
                        memcmp(p1->ipv6_interfaces[i].ipv6[j].ipv6_address_origin, p2->ipv6_interfaces[i].ipv6[j].ipv6_address_origin, 16) !=0) {
                        return 1;
                    }
                }
            }

            return 0;
        }
        case TLV_TYPE_GENERIC_PHY_DEVICE_INFORMATION: {
            i1905_generic_phy_device_information_tlv_t *p1 = (i1905_generic_phy_device_information_tlv_t *)memory_structure_1;
            i1905_generic_phy_device_information_tlv_t *p2 = (i1905_generic_phy_device_information_tlv_t *)memory_structure_2;

            if (maccmp(p1->al_mac_address, p2->al_mac_address) !=0 ||
                p1->local_interfaces_nr != p2->local_interfaces_nr) {
                return 1;
            }

            if (p1->local_interfaces_nr > 0 && (NULL == p1->local_interfaces || NULL == p2->local_interfaces)) {
                /* Malformed structure */
                return 1;
            }

            for (i = 0; i < p1->local_interfaces_nr; i++) {
                if (maccmp(p1->local_interfaces[i].local_interface_address, p2->local_interfaces[i].local_interface_address) !=0                                      ||
                    memcmp(p1->local_interfaces[i].generic_phy_common_data.oui, p2->local_interfaces[i].generic_phy_common_data.oui, 3) !=0                           ||
                    p1->local_interfaces[i].generic_phy_common_data.variant_index != p2->local_interfaces[i].generic_phy_common_data.variant_index                    ||
                    memcmp(p1->local_interfaces[i].variant_name, p2->local_interfaces[i].variant_name, 32) !=0                                                        ||
                    p1->local_interfaces[i].generic_phy_description_xml_url_len != p2->local_interfaces[i].generic_phy_description_xml_url_len                        ||
                    p1->local_interfaces[i].generic_phy_common_data.media_specific_bytes_nr!= p2->local_interfaces[i].generic_phy_common_data.media_specific_bytes_nr ||
                    memcmp(p1->local_interfaces[i].generic_phy_description_xml_url, p2->local_interfaces[i].generic_phy_description_xml_url, p1->local_interfaces[i].generic_phy_description_xml_url_len) !=0 ||
                    memcmp(p1->local_interfaces[i].generic_phy_common_data.media_specific_bytes, p2->local_interfaces[i].generic_phy_common_data.media_specific_bytes, p1->local_interfaces[i].generic_phy_common_data.media_specific_bytes_nr) !=0) {
                    return 1;
                }
            }

            return 0;
        }
        case TLV_TYPE_GENERIC_PHY_EVENT_NOTIFICATION: {
            i1905_generic_phy_event_notification_tlv_t *p1 = (i1905_generic_phy_event_notification_tlv_t *)memory_structure_1;
            i1905_generic_phy_event_notification_tlv_t *p2 = (i1905_generic_phy_event_notification_tlv_t *)memory_structure_2;

            if (p1->local_interfaces_nr != p2->local_interfaces_nr) {
                return 1;
            }

            if (p1->local_interfaces_nr > 0 && (NULL == p1->local_interfaces || NULL == p2->local_interfaces)) {
                /* Malformed structure */
                return 1;
            }

            for (i = 0; i < p1->local_interfaces_nr; i++) {
                if (memcmp(p1->local_interfaces[i].oui, p2->local_interfaces[i].oui, 3) !=0                            ||
                    p1->local_interfaces[i].variant_index != p2->local_interfaces[i].variant_index                     ||
                    p1->local_interfaces[i].media_specific_bytes_nr != p2->local_interfaces[i].media_specific_bytes_nr ||
                    memcmp(p1->local_interfaces[i].media_specific_bytes, p2->local_interfaces[i].media_specific_bytes, p1->local_interfaces[i].media_specific_bytes_nr) !=0) {
                    return 1;
                }
            }

            return 0;
        }
        case TLV_TYPE_1905_PROFILE_VERSION: {
            i1905_profile_version_tlv_t *p1 = (i1905_profile_version_tlv_t *)memory_structure_1;
            i1905_profile_version_tlv_t *p2 = (i1905_profile_version_tlv_t *)memory_structure_2;

            return (p1->profile != p2->profile) ? 1 : 0;
        }
        case TLV_TYPE_POWER_OFF_INTERFACE: {
            i1905_power_off_interface_tlv_t *p1 = (i1905_power_off_interface_tlv_t *)memory_structure_1;
            i1905_power_off_interface_tlv_t *p2 = (i1905_power_off_interface_tlv_t *)memory_structure_2;

            if (p1->power_off_interfaces_nr != p2->power_off_interfaces_nr) {
                return 1;
            }

            if (p1->power_off_interfaces_nr > 0 && (NULL == p1->power_off_interfaces || NULL == p2->power_off_interfaces)) {
                /* Malformed structure */
                return 1;
            }

            for (i = 0; i < p1->power_off_interfaces_nr; i++) {
                if (maccmp(p1->power_off_interfaces[i].interface_address, p2->power_off_interfaces[i].interface_address) !=0                                                   ||
                    p1->power_off_interfaces[i].media_type != p2->power_off_interfaces[i].media_type                                                                           ||
                    memcmp(p1->power_off_interfaces[i].generic_phy_common_data.oui, p2->power_off_interfaces[i].generic_phy_common_data.oui,                  3) !=0           ||
                    p1->power_off_interfaces[i].generic_phy_common_data.variant_index != p2->power_off_interfaces[i].generic_phy_common_data.variant_index                     ||
                    p1->power_off_interfaces[i].generic_phy_common_data.media_specific_bytes_nr != p2->power_off_interfaces[i].generic_phy_common_data.media_specific_bytes_nr ||
                    memcmp(p1->power_off_interfaces[i].generic_phy_common_data.media_specific_bytes, p2->power_off_interfaces[i].generic_phy_common_data.media_specific_bytes, p1->power_off_interfaces[i].generic_phy_common_data.media_specific_bytes_nr) !=0) {
                    return 1;
                }
            }

            return 0;
        }
        case TLV_TYPE_INTERFACE_POWER_CHANGE_INFORMATION: {
            i1905_interface_power_change_information_tlv_t *p1 = (i1905_interface_power_change_information_tlv_t *)memory_structure_1;
            i1905_interface_power_change_information_tlv_t *p2 = (i1905_interface_power_change_information_tlv_t *)memory_structure_2;

            if (p1->power_change_interfaces_nr != p2->power_change_interfaces_nr) {
                return 1;
            }

            if (p1->power_change_interfaces_nr > 0 && (NULL == p1->power_change_interfaces || NULL == p2->power_change_interfaces)) {
                /* Malformed structure */
                return 1;
            }

            for (i = 0; i < p1->power_change_interfaces_nr; i++) {
                if (maccmp(p1->power_change_interfaces[i].interface_address, p2->power_change_interfaces[i].interface_address) !=0  ||
                    p1->power_change_interfaces[i].requested_power_state != p2->power_change_interfaces[i].requested_power_state) {
                    return 1;
                }
            }

            return 0;
        }
        case TLV_TYPE_INTERFACE_POWER_CHANGE_STATUS: {
            i1905_interface_power_change_status_tlv_t *p1 = (i1905_interface_power_change_status_tlv_t *)memory_structure_1;
            i1905_interface_power_change_status_tlv_t *p2 = (i1905_interface_power_change_status_tlv_t *)memory_structure_2;

            if (p1->power_change_interfaces_nr != p2->power_change_interfaces_nr) {
                return 1;
            }

            if (p1->power_change_interfaces_nr > 0 && (NULL == p1->power_change_interfaces || NULL == p2->power_change_interfaces)) {
                /* Malformed structure */
                return 1;
            }

            for (i = 0; i < p1->power_change_interfaces_nr; i++) {
                if (maccmp(p1->power_change_interfaces[i].interface_address, p2->power_change_interfaces[i].interface_address) !=0 ||
                    p1->power_change_interfaces[i].result != p2->power_change_interfaces[i].result) {
                    return 1;
                }
            }

            return 0;
        }
        case TLV_TYPE_L2_NEIGHBOR_DEVICE: {
            i1905_l2_neighbor_device_tlv_t *p1 = (i1905_l2_neighbor_device_tlv_t *)memory_structure_1;
            i1905_l2_neighbor_device_tlv_t *p2 = (i1905_l2_neighbor_device_tlv_t *)memory_structure_2;

            if (p1->local_interfaces_nr != p2->local_interfaces_nr) {
                return 1;
            }

            if (p1->local_interfaces_nr > 0 && (NULL == p1->local_interfaces || NULL == p2->local_interfaces)) {
                /* Malformed structure */
                return 1;
            }

            for (i=0; i<p1->local_interfaces_nr; i++) {
                if (maccmp(p1->local_interfaces[i].local_mac_address, p2->local_interfaces[i].local_mac_address) !=0 ||
                    p1->local_interfaces[i].l2_neighbors_nr != p2->local_interfaces[i].l2_neighbors_nr) {
                    return 1;
                }

                if (p1->local_interfaces[i].l2_neighbors_nr > 0 && (NULL == p1->local_interfaces[i].l2_neighbors || NULL == p2->local_interfaces[i].l2_neighbors)) {
                    /* Malformed structure */
                    return 1;
                }

                for (j=0; j<p1->local_interfaces[i].l2_neighbors_nr; j++) {
                    if (maccmp(p1->local_interfaces[i].l2_neighbors[j].l2_neighbor_mac_address, p2->local_interfaces[i].l2_neighbors[j].l2_neighbor_mac_address) !=0 ||
                        p1->local_interfaces[i].l2_neighbors[j].behind_mac_addresses_nr != p2->local_interfaces[i].l2_neighbors[j].behind_mac_addresses_nr) {
                        return 1;
                    }

                    if (p1->local_interfaces[i].l2_neighbors[j].behind_mac_addresses_nr > 0 && (NULL == p1->local_interfaces[i].l2_neighbors[j].behind_mac_addresses || NULL == p2->local_interfaces[i].l2_neighbors[j].behind_mac_addresses)) {
                        /* Malformed structure */
                        return 1;
                    }

                    for (k = 0; k < p1->local_interfaces[i].l2_neighbors[j].behind_mac_addresses_nr; k++) {
                        if (maccmp(p1->local_interfaces[i].l2_neighbors[j].behind_mac_addresses[k], p2->local_interfaces[i].l2_neighbors[j].behind_mac_addresses[k]) !=0) {
                            return 1;
                        }
                    }
                }
            }

            return 0;
        }
        default: {
            /* Unknown structure type */
            return 1;
        }
    }

    /* This code cannot be reached */
    return 1;
}

void visit_1905_TLV_structure(uint8_t *memory_structure, void (*callback)(void (*write_function)(const char *fmt, ...),
                              const char *prefix, size_t size, const char *name, const char *fmt, void *p),
                              void (*write_function)(const char *fmt, ...), const char *prefix)
{
    /* Buffer size to store a prefix string that will be used to show each
    *  element of a structure on screen
    */
    #define MAX_PREFIX  100
    char    new_prefix[MAX_PREFIX];
    uint8_t i, j, k;

    if (NULL == memory_structure) {
        return;
    }

    /* The first byte of any of the valid structures is always the "tlv_type"
    *  field.
    */
    switch (*memory_structure)
    {
        case TLV_TYPE_END_OF_MESSAGE: {
            /* There is nothing to visit. This TLV is always empty */
            return;
        }
        case TLV_TYPE_VENDOR_SPECIFIC: {
            i1905_vendor_specific_tlv_t *p = (i1905_vendor_specific_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->vendorOUI), "vendorOUI",  "0x%02x",   p->vendorOUI);
            callback(write_function, prefix, sizeof(p->m_nr),      "m_nr",       "%d",      &p->m_nr);
            callback(write_function, prefix, p->m_nr,              "m",          "0x%02x",   p->m);

            return;
        }
        case TLV_TYPE_AL_MAC_ADDRESS: {
            i1905_al_mac_address_tlv_t *p = (i1905_al_mac_address_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->al_mac_address), "al_mac_address",  "0x%02x",  p->al_mac_address);

            return;
        }
        case TLV_TYPE_MAC_ADDRESS: {
            i1905_mac_address_tlv_t *p = (i1905_mac_address_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->mac_address), "mac_address",  "0x%02x",  p->mac_address);

            return;
        }
        case TLV_TYPE_DEVICE_INFORMATION: {
            i1905_device_information_tlv_t *p = (i1905_device_information_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->al_mac_address),      "al_mac_address",       "0x%02x",   p->al_mac_address);
            callback(write_function, prefix, sizeof(p->local_interfaces_nr), "local_interfaces_nr",  "%d",       &p->local_interfaces_nr);
            for (i=0; i < p->local_interfaces_nr; i++) {
                snprintf(new_prefix, MAX_PREFIX, "%slocal_interfaces[%d]->", prefix, i);

                callback(write_function, new_prefix, sizeof(p->local_interfaces[i].mac_address),              "mac_address",              "0x%02x",   p->local_interfaces[i].mac_address);
                callback(write_function, new_prefix, sizeof(p->local_interfaces[i].media_type),               "media_type",               "0x%04x",  &p->local_interfaces[i].media_type);
                callback(write_function, new_prefix, sizeof(p->local_interfaces[i].media_specific_data_size), "media_specific_data_size", "%d",      &p->local_interfaces[i].media_specific_data_size);

                if ((MEDIA_TYPE_IEEE_802_11B_2_4_GHZ == p->local_interfaces[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11G_2_4_GHZ == p->local_interfaces[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11A_5_GHZ   == p->local_interfaces[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11N_2_4_GHZ == p->local_interfaces[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11N_5_GHZ   == p->local_interfaces[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11AC_5_GHZ  == p->local_interfaces[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11AD_60_GHZ == p->local_interfaces[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11AF        == p->local_interfaces[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11AX        == p->local_interfaces[i].media_type)) {
                    callback(write_function, new_prefix, sizeof(p->local_interfaces[i].media_specific_data.ieee80211.network_membership),                  "network_membership",                   "0x%02x",   p->local_interfaces[i].media_specific_data.ieee80211.network_membership);
                    callback(write_function, new_prefix, sizeof(p->local_interfaces[i].media_specific_data.ieee80211.role),                                "role",                                 "%d",      &p->local_interfaces[i].media_specific_data.ieee80211.role);
                    callback(write_function, new_prefix, sizeof(p->local_interfaces[i].media_specific_data.ieee80211.ap_channel_band),                     "ap_channel_band",                      "%d",      &p->local_interfaces[i].media_specific_data.ieee80211.ap_channel_band);
                    callback(write_function, new_prefix, sizeof(p->local_interfaces[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_1), "ap_channel_center_frequency_index_1",  "%d",      &p->local_interfaces[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_1);
                    callback(write_function, new_prefix, sizeof(p->local_interfaces[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_2), "ap_channel_center_frequency_index_2",  "%d",      &p->local_interfaces[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_2);
                } else if ((MEDIA_TYPE_IEEE_1901_WAVELET == p->local_interfaces[i].media_type) ||
                           (MEDIA_TYPE_IEEE_1901_FFT     == p->local_interfaces[i].media_type)) {
                    callback(write_function, new_prefix, sizeof(p->local_interfaces[i].media_specific_data.ieee1901.network_identifier), "network_identifier", "0x%02x", p->local_interfaces[i].media_specific_data.ieee1901.network_identifier);
                }
            }

            return;
        }
        case TLV_TYPE_DEVICE_BRIDGING_CAPABILITY: {
            i1905_device_bridging_cap_tlv_t *p = (i1905_device_bridging_cap_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->bridging_tuples_nr), "bridging_tuples_nr", "%d",  &p->bridging_tuples_nr);
            for (i = 0; i < p->bridging_tuples_nr; i++) {
                snprintf(new_prefix, MAX_PREFIX, "%sbridging_tuples[%d]->", prefix, i);

                callback(write_function, new_prefix, sizeof(p->bridging_tuples[i].bridging_tuple_macs_nr), "bridging_tuple_macs_nr", "%d",  &p->bridging_tuples[i].bridging_tuple_macs_nr);

                for (j = 0; j < p->bridging_tuples[i].bridging_tuple_macs_nr; j++) {
                    snprintf(new_prefix, MAX_PREFIX, "%sbridging_tuples[%d]->bridging_tuple_macs[%d]->", prefix, i, j);

                    callback(write_function, new_prefix, sizeof(p->bridging_tuples[i].bridging_tuple_macs[j].mac_address), "mac_address", "0x%02x",  p->bridging_tuples[i].bridging_tuple_macs[j].mac_address);
                }
            }

            return;
        }
        case TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST: {
            i1905_non_1905_neighbor_device_list_tlv_t *p = (i1905_non_1905_neighbor_device_list_tlv_t *)memory_structure;

            if (p->non_1905_neighbors_nr > 0 && NULL == p->non_1905_neighbors) {
                /* Malformed structure */
                return;
            }

            callback(write_function, prefix, sizeof(p->local_mac_address),     "local_mac_address",     "0x%02x",   p->local_mac_address);
            callback(write_function, prefix, sizeof(p->non_1905_neighbors_nr), "non_1905_neighbors_nr", "%d",      &p->non_1905_neighbors_nr);
            for (i = 0; i < p->non_1905_neighbors_nr; i++) {
                snprintf(new_prefix, MAX_PREFIX, "%snon_1905_neighbors[%d]->", prefix, i);

                callback(write_function, new_prefix, sizeof(p->non_1905_neighbors[i].mac_address), "mac_address", "0x%02x", p->non_1905_neighbors[i].mac_address);
            }

            return;
        }
        case TLV_TYPE_NEIGHBOR_DEVICE_LIST: {
            i1905_neighbor_device_list_tlv_t *p = (i1905_neighbor_device_list_tlv_t *)memory_structure;

            if (p->neighbors_nr > 0 && NULL == p->neighbors) {
                /* Malformed structure */
                return;
            }

            callback(write_function, prefix, sizeof(p->local_mac_address), "local_mac_address",  "0x%02x",   p->local_mac_address);
            callback(write_function, prefix, sizeof(p->neighbors_nr),      "neighbors_nr",       "%d",      &p->neighbors_nr);
            for (i = 0; i < p->neighbors_nr; i++) {
                snprintf(new_prefix, MAX_PREFIX, "%sneighbors[%d]->", prefix, i);

                callback(write_function, new_prefix, sizeof(p->neighbors[i].mac_address), "mac_address", "0x%02x",  p->neighbors[i].mac_address);
                callback(write_function, new_prefix, sizeof(p->neighbors[i].bridge_flag), "bridge_flag", "%d",     &p->neighbors[i].bridge_flag);
            }

            return;
        }
        case TLV_TYPE_LINK_METRIC_QUERY: {
            i1905_link_metric_query_tlv_t *p = (i1905_link_metric_query_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->destination),       "destination",        "%d",      &p->destination);
            callback(write_function, prefix, sizeof(p->specific_neighbor), "specific_neighbor",  "0x%02x",   p->specific_neighbor);
            callback(write_function, prefix, sizeof(p->link_metrics_type), "link_metrics_type",  "%d",      &p->link_metrics_type);

            return;
        }
        case TLV_TYPE_TRANSMITTER_LINK_METRIC: {
            i1905_transmitter_link_metric_tlv_t *p = (i1905_transmitter_link_metric_tlv_t *)memory_structure;

            if (NULL == p->transmitter_link_metrics) {
                /* Malformed structure */
                return;
            }

            callback(write_function, prefix, sizeof(p->local_al_address),            "local_al_address",            "0x%02x",   p->local_al_address);
            callback(write_function, prefix, sizeof(p->neighbor_al_address),         "neighbor_al_address",         "0x%02x",   p->neighbor_al_address);
            callback(write_function, prefix, sizeof(p->transmitter_link_metrics_nr), "transmitter_link_metrics_nr", "%d",      &p->transmitter_link_metrics_nr);
            for (i = 0; i < p->transmitter_link_metrics_nr; i++) {
                snprintf(new_prefix, MAX_PREFIX, "%stransmitter_link_metrics[%d]->", prefix, i);

                callback(write_function, new_prefix, sizeof(p->transmitter_link_metrics[i].local_interface_address),    "local_interface_address",    "0x%02x",   p->transmitter_link_metrics[i].local_interface_address);
                callback(write_function, new_prefix, sizeof(p->transmitter_link_metrics[i].neighbor_interface_address), "neighbor_interface_address", "0x%02x",   p->transmitter_link_metrics[i].neighbor_interface_address);
                callback(write_function, new_prefix, sizeof(p->transmitter_link_metrics[i].intf_type),                  "intf_type",                  "0x%04x",  &p->transmitter_link_metrics[i].intf_type);
                callback(write_function, new_prefix, sizeof(p->transmitter_link_metrics[i].bridge_flag),                "bridge_flag",                "%d",      &p->transmitter_link_metrics[i].bridge_flag);
                callback(write_function, new_prefix, sizeof(p->transmitter_link_metrics[i].packet_errors),              "packet_errors",              "%d",      &p->transmitter_link_metrics[i].packet_errors);
                callback(write_function, new_prefix, sizeof(p->transmitter_link_metrics[i].transmitted_packets),        "transmitted_packets",        "%d",      &p->transmitter_link_metrics[i].transmitted_packets);
                callback(write_function, new_prefix, sizeof(p->transmitter_link_metrics[i].mac_throughput_capacity),    "mac_throughput_capacity",    "%d",      &p->transmitter_link_metrics[i].mac_throughput_capacity);
                callback(write_function, new_prefix, sizeof(p->transmitter_link_metrics[i].link_availability),          "link_availability",          "%d",      &p->transmitter_link_metrics[i].link_availability);
                callback(write_function, new_prefix, sizeof(p->transmitter_link_metrics[i].phy_rate),                   "phy_rate",                   "%d",      &p->transmitter_link_metrics[i].phy_rate);
            }

            return;
        }
        case TLV_TYPE_RECEIVER_LINK_METRIC: {
            i1905_receiver_link_metric_tlv_t *p = (i1905_receiver_link_metric_tlv_t *)memory_structure;

            if (NULL == p->receiver_link_metrics) {
                /* Malformed structure */
                return;
            }

            callback(write_function, prefix, sizeof(p->local_al_address),         "local_al_address",         "0x%02x",   p->local_al_address);
            callback(write_function, prefix, sizeof(p->neighbor_al_address),      "neighbor_al_address",      "0x%02x",   p->neighbor_al_address);
            callback(write_function, prefix, sizeof(p->receiver_link_metrics_nr), "receiver_link_metrics_nr", "%d",      &p->receiver_link_metrics_nr);
            for (i = 0; i < p->receiver_link_metrics_nr; i++) {
                snprintf(new_prefix, MAX_PREFIX, "%sreceiver_link_metrics[%d]->", prefix, i);

                callback(write_function, new_prefix, sizeof(p->receiver_link_metrics[i].local_interface_address),    "local_interface_address",    "0x%02x",   p->receiver_link_metrics[i].local_interface_address);
                callback(write_function, new_prefix, sizeof(p->receiver_link_metrics[i].neighbor_interface_address), "neighbor_interface_address", "0x%02x",   p->receiver_link_metrics[i].neighbor_interface_address);
                callback(write_function, new_prefix, sizeof(p->receiver_link_metrics[i].intf_type),                  "intf_type",                  "0x%04x",  &p->receiver_link_metrics[i].intf_type);
                callback(write_function, new_prefix, sizeof(p->receiver_link_metrics[i].packet_errors),              "packet_errors",              "%d",      &p->receiver_link_metrics[i].packet_errors);
                callback(write_function, new_prefix, sizeof(p->receiver_link_metrics[i].packets_received),           "packets_received",           "%d",      &p->receiver_link_metrics[i].packets_received);
                callback(write_function, new_prefix, sizeof(p->receiver_link_metrics[i].rssi),                       "rssi",                       "%d",      &p->receiver_link_metrics[i].rssi);
            }

            return;
        }
        case TLV_TYPE_LINK_METRIC_RESULT_CODE: {
            i1905_link_metric_result_code_tlv_t *p = (i1905_link_metric_result_code_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->result_code), "result_code",  "%d",  &p->result_code);

            return;
        }
        case TLV_TYPE_SEARCHED_ROLE: {
            i1905_searched_role_tlv_t *p = (i1905_searched_role_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->role), "role",  "%d",  &p->role);

            return;
        }
        case TLV_TYPE_AUTOCONFIG_FREQ_BAND: {
            i1905_autoconfig_freq_band_tlv_t *p = (i1905_autoconfig_freq_band_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->freq_band), "freq_band",  "%d",  &p->freq_band);

            return;
        }
        case TLV_TYPE_SUPPORTED_ROLE: {
            i1905_supported_role_tlv_t *p = (i1905_supported_role_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->role), "role",  "%d",  &p->role);

            return;
        }
        case TLV_TYPE_SUPPORTED_FREQ_BAND: {
            i1905_supported_freq_band_tlv_t *p = (i1905_supported_freq_band_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->freq_band), "freq_band",  "%d",  &p->freq_band);

            return;
        }
        case TLV_TYPE_WSC: {
            i1905_wsc_tlv_t *p = (i1905_wsc_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->wsc_frame_size), "wsc_frame_size",  "%d",      &p->wsc_frame_size);
            callback(write_function, prefix, p->wsc_frame_size,         "wsc_frame",       "0x%02x",   p->wsc_frame);

            return;
        }
        case TLV_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION: {
            i1905_push_button_event_notification_tlv_t *p = (i1905_push_button_event_notification_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->media_types_nr), "media_types_nr",  "0x%02x",  &p->media_types_nr);
            for (i = 0; i < p->media_types_nr; i++) {
                snprintf(new_prefix, MAX_PREFIX, "%smedia_types[%d]->", prefix, i);

                callback(write_function, new_prefix, sizeof(p->media_types[i].media_type),               "media_type",               "0x%04x",  &p->media_types[i].media_type);
                callback(write_function, new_prefix, sizeof(p->media_types[i].media_specific_data_size), "media_specific_data_size", "%d",      &p->media_types[i].media_specific_data_size);

                if ((MEDIA_TYPE_IEEE_802_11B_2_4_GHZ == p->media_types[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11G_2_4_GHZ == p->media_types[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11A_5_GHZ   == p->media_types[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11N_2_4_GHZ == p->media_types[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11N_5_GHZ   == p->media_types[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11AC_5_GHZ  == p->media_types[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11AD_60_GHZ == p->media_types[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11AF        == p->media_types[i].media_type) ||
                    (MEDIA_TYPE_IEEE_802_11AX        == p->media_types[i].media_type)) {
                    callback(write_function, new_prefix, sizeof(p->media_types[i].media_specific_data.ieee80211.network_membership),                  "network_membership",                   "0x%02x",   p->media_types[i].media_specific_data.ieee80211.network_membership);
                    callback(write_function, new_prefix, sizeof(p->media_types[i].media_specific_data.ieee80211.role),                                "role",                                 "%d",      &p->media_types[i].media_specific_data.ieee80211.role);
                    callback(write_function, new_prefix, sizeof(p->media_types[i].media_specific_data.ieee80211.ap_channel_band),                     "ap_channel_band",                      "%d",      &p->media_types[i].media_specific_data.ieee80211.ap_channel_band);
                    callback(write_function, new_prefix, sizeof(p->media_types[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_1), "ap_channel_center_frequency_index_1",  "%d",      &p->media_types[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_1);
                    callback(write_function, new_prefix, sizeof(p->media_types[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_2), "ap_channel_center_frequency_index_2",  "%d",      &p->media_types[i].media_specific_data.ieee80211.ap_channel_center_frequency_index_2);
                } else if ((MEDIA_TYPE_IEEE_1901_WAVELET == p->media_types[i].media_type) ||
                           (MEDIA_TYPE_IEEE_1901_FFT     == p->media_types[i].media_type)) {
                    callback(write_function, new_prefix, sizeof(p->media_types[i].media_specific_data.ieee1901.network_identifier), "network_identifier", "0x%02x", p->media_types[i].media_specific_data.ieee1901.network_identifier);
                }
            }

            return;
        }
        case TLV_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION: {
            i1905_push_button_join_notification_tlv_t *p = (i1905_push_button_join_notification_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->al_mac_address),     "al_mac_address",      "0x%02x",   p->al_mac_address);
            callback(write_function, prefix, sizeof(p->message_identifier), "message_identifier",  "%d",      &p->message_identifier);
            callback(write_function, prefix, sizeof(p->mac_address),        "mac_address",         "0x%02x",   p->mac_address);
            callback(write_function, prefix, sizeof(p->new_mac_address),    "new_mac_address",     "0x%02x",   p->new_mac_address);

            return;
        }
        case TLV_TYPE_GENERIC_PHY_DEVICE_INFORMATION: {
            i1905_generic_phy_device_information_tlv_t *p = (i1905_generic_phy_device_information_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->al_mac_address),      "al_mac_address",      "0x%02x",  &p->al_mac_address);
            callback(write_function, prefix, sizeof(p->local_interfaces_nr), "local_interfaces_nr", "%d",      &p->local_interfaces_nr);
            for (i = 0; i < p->local_interfaces_nr; i++) {
                snprintf(new_prefix, MAX_PREFIX, "%slocal_interfaces[%d]->", prefix, i);

                callback(write_function, new_prefix, sizeof(p->local_interfaces[i].local_interface_address),                         "local_interface_address",             "0x%02x",   p->local_interfaces[i].local_interface_address);
                callback(write_function, new_prefix, sizeof(p->local_interfaces[i].generic_phy_common_data.oui),                     "oui",                                 "0x%02x",   p->local_interfaces[i].generic_phy_common_data.oui);
                callback(write_function, new_prefix, sizeof(p->local_interfaces[i].generic_phy_common_data.variant_index),           "variant_index",                       "%d",      &p->local_interfaces[i].generic_phy_common_data.variant_index);
                callback(write_function, new_prefix, sizeof(p->local_interfaces[i].variant_name),                                    "variant_name",                        "%s",       p->local_interfaces[i].variant_name);
                callback(write_function, new_prefix, sizeof(p->local_interfaces[i].generic_phy_description_xml_url_len),             "generic_phy_description_xml_url_len", "%d",      &p->local_interfaces[i].generic_phy_description_xml_url_len);
                callback(write_function, new_prefix, sizeof(p->local_interfaces[i].generic_phy_common_data.media_specific_bytes_nr), "media_specific_bytes_nr",             "%d",      &p->local_interfaces[i].generic_phy_common_data.media_specific_bytes_nr);
                callback(write_function, new_prefix, p->local_interfaces[i].generic_phy_description_xml_url_len,                     "generic_phy_description_xml_url",     "%s",       p->local_interfaces[i].generic_phy_description_xml_url);
                callback(write_function, new_prefix, p->local_interfaces[i].generic_phy_common_data.media_specific_bytes_nr,         "media_specific_bytes",                "0x%02x",   p->local_interfaces[i].generic_phy_common_data.media_specific_bytes);
            }

            return;
        }
        case TLV_TYPE_DEVICE_IDENTIFICATION: {
            i1905_device_identification_tlv_t*p = (i1905_device_identification_tlv_t*)memory_structure;

            callback(write_function, prefix, sizeof(p->friendly_name),      "friendly_name",       "%s",   p->friendly_name);
            callback(write_function, prefix, sizeof(p->manufacturer_name),  "manufacturer_name",   "%s",   p->manufacturer_name);
            callback(write_function, prefix, sizeof(p->manufacturer_model), "manufacturer_model",  "%s",   p->manufacturer_model);
            return;
        }
        case TLV_TYPE_CONTROL_URL: {
            i1905_control_url_tlv_t *p = (i1905_control_url_tlv_t *)memory_structure;

            callback(write_function, prefix, strlen(p->url)+1, "url", "%s", p->url);

            return;
        }
        case TLV_TYPE_IPV4: {
            i1905_ipv4_tlv_t *p = (i1905_ipv4_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->ipv4_interfaces_nr), "ipv4_interfaces_nr", "%d",  &p->ipv4_interfaces_nr);
            for (i = 0; i < p->ipv4_interfaces_nr; i++) {
                snprintf(new_prefix, MAX_PREFIX, "%sipv4_interfaces[%d]->", prefix, i);

                callback(write_function, new_prefix, sizeof(p->ipv4_interfaces[i].mac_address), "mac_address", "0x%02x",   p->ipv4_interfaces[i].mac_address);
                callback(write_function, new_prefix, sizeof(p->ipv4_interfaces[i].ipv4_nr),     "ipv4_nr",     "%d",      &p->ipv4_interfaces[i].ipv4_nr);

                for (j = 0; j < p->ipv4_interfaces[i].ipv4_nr; j++) {
                    snprintf(new_prefix, MAX_PREFIX, "%sipv4_interfaces[%d]->ipv4[%d]->", prefix, i, j);

                    callback(write_function, new_prefix, sizeof(p->ipv4_interfaces[i].ipv4[j].type),             "type",             "%d",     &p->ipv4_interfaces[i].ipv4[j].type);
                    callback(write_function, new_prefix, sizeof(p->ipv4_interfaces[i].ipv4[j].ipv4_address),     "ipv4_address",     "%ipv4",   p->ipv4_interfaces[i].ipv4[j].ipv4_address);
                    callback(write_function, new_prefix, sizeof(p->ipv4_interfaces[i].ipv4[j].ipv4_dhcp_server), "ipv4_dhcp_server", "%ipv4",   p->ipv4_interfaces[i].ipv4[j].ipv4_dhcp_server);
                }
            }

            return;
        }
        case TLV_TYPE_IPV6: {
            i1905_ipv6_tlv_t *p = (i1905_ipv6_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->ipv6_interfaces_nr), "ipv6_interfaces_nr", "%d",  &p->ipv6_interfaces_nr);
            for (i=0; i < p->ipv6_interfaces_nr; i++) {
                snprintf(new_prefix, MAX_PREFIX, "%sipv6_interfaces[%d]->", prefix, i);

                callback(write_function, new_prefix, sizeof(p->ipv6_interfaces[i].mac_address), "mac_address", "0x%02x",   p->ipv6_interfaces[i].mac_address);
                callback(write_function, new_prefix, sizeof(p->ipv6_interfaces[i].ipv6_nr),     "ipv6_nr",     "%d",      &p->ipv6_interfaces[i].ipv6_nr);

                for (j = 0; j < p->ipv6_interfaces[i].ipv6_nr; j++) {
                    snprintf(new_prefix, MAX_PREFIX, "%sipv6_interfaces[%d]->ipv6[%d]->", prefix, i, j);

                    callback(write_function, new_prefix, sizeof(p->ipv6_interfaces[i].ipv6[j].type),                "type",                "%d",      &p->ipv6_interfaces[i].ipv6[j].type);
                    callback(write_function, new_prefix, sizeof(p->ipv6_interfaces[i].ipv6[j].ipv6_address),        "ipv6_address",        "0x%02x",   p->ipv6_interfaces[i].ipv6[j].ipv6_address);
                    callback(write_function, new_prefix, sizeof(p->ipv6_interfaces[i].ipv6[j].ipv6_address_origin), "ipv6_address_origin", "0x%02x",   p->ipv6_interfaces[i].ipv6[j].ipv6_address_origin);
                }
            }

            return;
        }
        case TLV_TYPE_GENERIC_PHY_EVENT_NOTIFICATION: {
            i1905_generic_phy_event_notification_tlv_t *p = (i1905_generic_phy_event_notification_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->local_interfaces_nr), "local_interfaces_nr", "%d",  &p->local_interfaces_nr);
            for (i = 0; i < p->local_interfaces_nr; i++) {
                snprintf(new_prefix, MAX_PREFIX, "%slocal_interfaces[%d]->", prefix, i);

                callback(write_function, new_prefix, sizeof(p->local_interfaces[i].oui),                     "oui",                     "0x%02x",   p->local_interfaces[i].oui);
                callback(write_function, new_prefix, sizeof(p->local_interfaces[i].variant_index),           "variant_index",           "%d",      &p->local_interfaces[i].variant_index);
                callback(write_function, new_prefix, sizeof(p->local_interfaces[i].media_specific_bytes_nr), "media_specific_bytes_nr", "%d",      &p->local_interfaces[i].media_specific_bytes_nr);
                callback(write_function, new_prefix, p->local_interfaces[i].media_specific_bytes_nr,         "media_specific_bytes",    "0x%02x",   p->local_interfaces[i].media_specific_bytes);
            }

            return;
        }
        case TLV_TYPE_1905_PROFILE_VERSION: {
            i1905_profile_version_tlv_t *p = (i1905_profile_version_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->profile), "profile",  "%d",  &p->profile);

            return;
        }
        case TLV_TYPE_POWER_OFF_INTERFACE: {
            i1905_power_off_interface_tlv_t *p = (i1905_power_off_interface_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->power_off_interfaces_nr), "power_off_interfaces_nr", "%d",  &p->power_off_interfaces_nr);
            for (i = 0; i < p->power_off_interfaces_nr; i++) {
                snprintf(new_prefix, MAX_PREFIX, "%spower_off_interfaces[%d]->", prefix, i);

                callback(write_function, new_prefix, sizeof(p->power_off_interfaces[i].interface_address),                               "interface_address",       "0x%02x",   p->power_off_interfaces[i].interface_address);
                callback(write_function, new_prefix, sizeof(p->power_off_interfaces[i].media_type),                                      "media_type",              "0x%04x",  &p->power_off_interfaces[i].media_type);
                callback(write_function, new_prefix, sizeof(p->power_off_interfaces[i].generic_phy_common_data.oui),                     "oui",                     "0x%02x",   p->power_off_interfaces[i].generic_phy_common_data.oui);
                callback(write_function, new_prefix, sizeof(p->power_off_interfaces[i].generic_phy_common_data.variant_index),           "variant_index",           "%d",      &p->power_off_interfaces[i].generic_phy_common_data.variant_index);
                callback(write_function, new_prefix, sizeof(p->power_off_interfaces[i].generic_phy_common_data.media_specific_bytes_nr), "media_specific_bytes_nr", "%d",      &p->power_off_interfaces[i].generic_phy_common_data.media_specific_bytes_nr);
                callback(write_function, new_prefix, p->power_off_interfaces[i].generic_phy_common_data.media_specific_bytes_nr,         "media_specific_bytes",    "0x%02x",   p->power_off_interfaces[i].generic_phy_common_data.media_specific_bytes);
            }

            return;
        }
        case TLV_TYPE_INTERFACE_POWER_CHANGE_INFORMATION: {
            i1905_interface_power_change_information_tlv_t *p = (i1905_interface_power_change_information_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->power_change_interfaces_nr), "power_change_interfaces_nr", "%d",  &p->power_change_interfaces_nr);
            for (i=0; i < p->power_change_interfaces_nr; i++) {
                snprintf(new_prefix, MAX_PREFIX, "%spower_change_interfaces[%d]->", prefix, i);

                callback(write_function, new_prefix, sizeof(p->power_change_interfaces[i].interface_address),     "interface_address",       "0x%02x",   p->power_change_interfaces[i].interface_address);
                callback(write_function, new_prefix, sizeof(p->power_change_interfaces[i].requested_power_state), "requested_power_state",   "0x%02x",  &p->power_change_interfaces[i].requested_power_state);
            }

            return;
        }
        case TLV_TYPE_INTERFACE_POWER_CHANGE_STATUS: {
            i1905_interface_power_change_status_tlv_t *p = (i1905_interface_power_change_status_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->power_change_interfaces_nr), "power_change_interfaces_nr", "%d",  &p->power_change_interfaces_nr);
            for (i = 0; i < p->power_change_interfaces_nr; i++) {
                snprintf(new_prefix, MAX_PREFIX, "%spower_change_interfaces[%d]->", prefix, i);

                callback(write_function, new_prefix, sizeof(p->power_change_interfaces[i].interface_address), "interface_address",  "0x%02x",  p->power_change_interfaces[i].interface_address);
                callback(write_function, new_prefix, sizeof(p->power_change_interfaces[i].result),            "result",             "%d",     &p->power_change_interfaces[i].result);
            }

            return;
        }
        case TLV_TYPE_L2_NEIGHBOR_DEVICE: {
            i1905_l2_neighbor_device_tlv_t *p = (i1905_l2_neighbor_device_tlv_t *)memory_structure;

            callback(write_function, prefix, sizeof(p->local_interfaces_nr), "local_interfaces_nr", "%d",  &p->local_interfaces_nr);
            for (i = 0; i < p->local_interfaces_nr; i++) {
                snprintf(new_prefix, MAX_PREFIX, "%slocal_interfaces[%d]->", prefix, i);

                callback(write_function, new_prefix, sizeof(p->local_interfaces[i].local_mac_address), "local_mac_address", "0x%02x",   p->local_interfaces[i].local_mac_address);
                callback(write_function, new_prefix, sizeof(p->local_interfaces[i].l2_neighbors_nr),   "l2_neighbors_nr",   "%d",      &p->local_interfaces[i].l2_neighbors_nr);

                for (j = 0; j < p->local_interfaces[i].l2_neighbors_nr; j++) {
                    snprintf(new_prefix, MAX_PREFIX, "%slocal_interfaces[%d]->l2_neighbors[%d]->", prefix, i, j);

                    callback(write_function, new_prefix, sizeof(p->local_interfaces[i].l2_neighbors[j].l2_neighbor_mac_address), "l2_neighbor_mac_address", "0x%02x",   p->local_interfaces[i].l2_neighbors[j].l2_neighbor_mac_address);
                    callback(write_function, new_prefix, sizeof(p->local_interfaces[i].l2_neighbors[j].behind_mac_addresses_nr), "behind_mac_addresses_nr", "%d",      &p->local_interfaces[i].l2_neighbors[j].behind_mac_addresses_nr);

                    for (k=0; k < p->local_interfaces[i].l2_neighbors[j].behind_mac_addresses_nr; k++) {
                        snprintf(new_prefix, MAX_PREFIX, "%slocal_interfaces[%d]->l2_neighbors[%d]->behind_mac_addresses[%d]", prefix, i, j, k);

                        callback(write_function, new_prefix, 6, "behind_mac_addresses", "0x%02x", p->local_interfaces[i].l2_neighbors[j].behind_mac_addresses[k]);
                    }
                }
            }

            return;
        }
        default: {
            /* Ignore */
            return;
        }
    }

    /* This code cannot be reached */
}

char *convert_1905_TLV_type_to_string(uint8_t tlv_type)
{
    register_tlvs();

    return g_tlv_table[tlv_type].name;
}

int check_and_log_1905_TLV_malformed(int parsed, int len, uint8_t tlv_type)
{
    int ret = 0;

    if (parsed != len) {
        log_i1905_e("Parsed TLV length mismatch: parsed[%d] expected[%d] for %s", parsed, len, convert_1905_TLV_type_to_string(tlv_type));

        if (parsed > len) {
            /* Critical -> drop tlv */
            ret = -1;
        }
    }

    return ret;
}
