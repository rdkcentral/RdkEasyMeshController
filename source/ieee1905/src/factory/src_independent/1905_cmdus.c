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
#define LOG_TAG "cmdu"

#include "platform.h"

#include "1905_cmdus.h"
#include "1905_tlvs.h"
#include "map_tlvs.h"
#include "packet_tools.h"

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
/*   WARNING:
*      If the CMDU message type changes (ie. the definition of  CMD_TYPE_*)
*      the following tables will have to be adapted (as the array index depends
*      on that).
*      Fortunately this should never happen.
*/

/* These tables marks, for each CMDU type of message, which TLVs are:
*
*    1. Require to be present zero or more times
*
*    2. required to be present exactly once
*
*  The values in these tables were obtained from "IEEE Std 1905.1-2013, Section
*  6.3"
*
*
*  TODO:
*      Right now this mechanism only considers either "zero or more" or "exactly
*      one" possibilities... however, in the "1a" update of the standard, there
*      are new types of TLVs that can appear "zero or one" and "one or more"
*      times.
*      For now I'm treating:
*        A) ...the "zero or one" type as "zero or more" (this
*           happens with the "push button generic phy event notification TLV",
*           the "control URL TLV" and the "IPv4/v6 TLVs") and...
*        B) ...the "one or more" type as "exactly one" (the "interface power
*           change information type TLV" and the "interface power change status
*           TLV").
*      Case (B) is not really a problem (in fact, I think "one or more" is an
*      error in the standard for these TLVs... as it should be "exactly one"...
*      maybe this will be corrected in a future update).
*      However, because of case (A), we could end up considering valid CMDUs
*      with, for example, more than one "IPv4 TLVs" (which is clearly an error).
*
*
*/
static uint32_t _zeroormore_tlvs_for_cmdu[] = {
    /* CMDU_TYPE_TOPOLOGY_DISCOVERY             */  0x00000000,
    /* CMDU_TYPE_TOPOLOGY_NOTIFICATION          */  0x00000000,
    /* CMDU_TYPE_TOPOLOGY_QUERY                 */  0x00000000,
    /* CMDU_TYPE_TOPOLOGY_RESPONSE              */  1 << TLV_TYPE_DEVICE_BRIDGING_CAPABILITY   | 1 << TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST | 1<< TLV_TYPE_NEIGHBOR_DEVICE_LIST | 1 << TLV_TYPE_POWER_OFF_INTERFACE | 1 << TLV_TYPE_L2_NEIGHBOR_DEVICE,
    /* CMDU_TYPE_VENDOR_SPECIFIC                */  0xffffffff,
    /* CMDU_TYPE_LINK_METRIC_QUERY              */  0x00000000,
    /* CMDU_TYPE_LINK_METRIC_RESPONSE           */  1 << TLV_TYPE_TRANSMITTER_LINK_METRIC | 1 << TLV_TYPE_RECEIVER_LINK_METRIC | 1 << TLV_TYPE_LINK_METRIC_RESULT_CODE,
    /* CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH    */  0x00000000,
    /* CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE  */  0x00000000,
    /* CMDU_TYPE_AP_AUTOCONFIGURATION_WSC       */  0x00000000,
    /* CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW     */  0x00000000,
    /* CMDU_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION */  1 << TLV_TYPE_GENERIC_PHY_EVENT_NOTIFICATION,
    /* CMDU_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION  */  0x00000000,
    /* CMDU_TYPE_HIGHER_LAYER_QUERY             */  0x00000000,
    /* CMDU_TYPE_HIGHER_LAYER_RESPONSE          */  1 << TLV_TYPE_CONTROL_URL | 1 << TLV_TYPE_IPV4 | 1 << TLV_TYPE_IPV6,
    /* CMDU_TYPE_INTERFACE_POWER_CHANGE_REQUEST */  0x00000000,
    /* CMDU_TYPE_INTERFACE_POWER_CHANGE_RESPONSE*/  0x00000000,
    /* CMDU_TYPE_GENERIC_PHY_QUERY              */  0x00000000,
    /* CMDU_TYPE_GENERIC_PHY_RESPONSE           */  0x00000000,
};

static uint32_t _exactlyone_tlvs_for_cmdu[] = {
    /* CMDU_TYPE_TOPOLOGY_DISCOVERY             */  1 << TLV_TYPE_AL_MAC_ADDRESS     | 1 << TLV_TYPE_MAC_ADDRESS,
    /* CMDU_TYPE_TOPOLOGY_NOTIFICATION          */  1 << TLV_TYPE_AL_MAC_ADDRESS,
    /* CMDU_TYPE_TOPOLOGY_QUERY                 */  0x00000000,
    /* CMDU_TYPE_TOPOLOGY_RESPONSE              */  1 << TLV_TYPE_DEVICE_INFORMATION,
    /* CMDU_TYPE_VENDOR_SPECIFIC                */  0x00000000,
    /* CMDU_TYPE_LINK_METRIC_QUERY              */  1 << TLV_TYPE_LINK_METRIC_QUERY,
    /* CMDU_TYPE_LINK_METRIC_RESPONSE           */  0x00000000,
    /* CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH    */  1 << TLV_TYPE_AL_MAC_ADDRESS     | 1 << TLV_TYPE_SEARCHED_ROLE                  | 1 << TLV_TYPE_AUTOCONFIG_FREQ_BAND,
    /* CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE  */  1 << TLV_TYPE_SUPPORTED_ROLE     | 1 << TLV_TYPE_SUPPORTED_FREQ_BAND,
    /* CMDU_TYPE_AP_AUTOCONFIGURATION_WSC       */  1 << TLV_TYPE_WSC,
    /* CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW     */  1 << TLV_TYPE_AL_MAC_ADDRESS     | 1 << TLV_TYPE_SUPPORTED_ROLE                 | 1 << TLV_TYPE_SUPPORTED_FREQ_BAND,
    /* CMDU_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION */  1 << TLV_TYPE_AL_MAC_ADDRESS     | 1 << TLV_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION,
    /* CMDU_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION  */  1 << TLV_TYPE_AL_MAC_ADDRESS     | 1 << TLV_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION,
    /* CMDU_TYPE_HIGHER_LAYER_QUERY             */  0x00000000,
    /* CMDU_TYPE_HIGHER_LAYER_RESPONSE          */  1 << TLV_TYPE_AL_MAC_ADDRESS     | 1 << TLV_TYPE_1905_PROFILE_VERSION           | 1 << TLV_TYPE_DEVICE_IDENTIFICATION,
    /* CMDU_TYPE_INTERFACE_POWER_CHANGE_REQUEST */  1 << TLV_TYPE_INTERFACE_POWER_CHANGE_INFORMATION,
    /* CMDU_TYPE_INTERFACE_POWER_CHANGE_RESPONSE*/  1 << TLV_TYPE_INTERFACE_POWER_CHANGE_STATUS,
    /* CMDU_TYPE_GENERIC_PHY_QUERY              */  0x00000000,
    /* CMDU_TYPE_GENERIC_PHY_RESPONSE           */  1 << TLV_TYPE_GENERIC_PHY_DEVICE_INFORMATION,
};

/* The following table tells us the value of the 'relay_indicator' flag for
*  each type of CMDU message.
*
*  The values were obtained from "IEEE Std 1905.1-2013, Table 6-4"
*
*  Note that '0xff' is a special value that means: "this CMDU message type can
*  have the flag set to either '0' or '1' and its actual value for this
*  particular message must be specified in some other way"
*/
static uint8_t _relayed_CMDU[] = {
    /* CMDU_TYPE_TOPOLOGY_DISCOVERY             */  0,
    /* CMDU_TYPE_TOPOLOGY_NOTIFICATION          */  0xff,
    /* CMDU_TYPE_TOPOLOGY_QUERY                 */  0,
    /* CMDU_TYPE_TOPOLOGY_QUERY                 */  0,
    /* CMDU_TYPE_VENDOR_SPECIFIC                */  0xff,
    /* CMDU_TYPE_LINK_METRIC_QUERY              */  0,
    /* CMDU_TYPE_LINK_METRIC_RESPONSE           */  0,
    /* CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH    */  1,
    /* CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE  */  0,
    /* CMDU_TYPE_AP_AUTOCONFIGURATION_WSC       */  0,
    /* CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW     */  1,
    /* CMDU_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION */  1,
    /* CMDU_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION  */  1,
    /* CMDU_TYPE_HIGHER_LAYER_QUERY             */  0,
    /* CMDU_TYPE_HIGHER_LAYER_RESPONSE          */  0,
    /* CMDU_TYPE_INTERFACE_POWER_CHANGE_REQUEST */  0,
    /* CMDU_TYPE_INTERFACE_POWER_CHANGE_RESPONSE*/  0,
    /* CMDU_TYPE_GENERIC_PHY_QUERY              */  0,
    /* CMDU_TYPE_GENERIC_PHY_RESPONSE           */  0,
};


/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
/* Each CMDU must follow some rules regarding which TLVs they can contain
*  depending on their type.
*
*  This is extracted from "IEEE Std 1905.1-2013, Section 6.2":
*
*    1. When generating a CMDU:
*       a) It shall include all of the TLVs that are listed for the message
*       b) It shall not include any other TLV that is not listed for the message
*       c) It may additionally include zero or more vendor specific TLVs
*
*    2. When receiving a CMDU:
*       a) It may process or ignore any vendor specific TLVs
*       b) It shall ignore all TLVs that are not specified for the message
*       c) It shall ignore the entire message if the message does not include
*          all of the TLVs that are listed for this message
*
*  This function receives a pointer to a CMDU structure, 'p' and a 'rules_type'
*  value:
*
*    * If 'rules_type' == CHECK_CMDU_TX_RULES, the function will check the
*      structure against the "generating a CMDU" rules (ie. rules 1.a, 1.b and
*      1.c).
*      If any of them is broken this function returns "0" (and 'p' is *not*
*      freed, as this is the caller's responsability)
*
*    * If 'rules_type' == CHECK_CMDU_RX_RULES, the function will check the
*      structure against the "receiving a CMDU" rules (ie. rules 2.a, 2.b and
*      2.c)
*      Regarding rule 2.a, we have chosen to preserve vendor specific TLVs in
*      the structure.
*      Rule 2.b is special in that non-vendor specific TLVs that are not
*      specified for the message type are removed (ie. the 'p' structure is
*      modified!)
*      Rule 2.c is special in that if it is broken, 'p' is freed
*
*   Note a small asymmetry: with 'rules_type' == CHECK_CMDU_TX_RULES,
*   unexpected options cause the function to fail while with 'rules_type' ==
*   CHECK_CMDU_RX_RULES they are simply removed (and freed) from the structure.
*   If you think about it, this is the correct behaviour: in transmission,
*   do not let invalid packets to be generated, while in reception, if invalid
*   packets are receive, ignore the unexpected pieces but process the rest.
*
*   In both cases, this function returns:
*     '0' --> If 'p' did not respect the rules and could not be "fixed"
*     '1' --> If 'p' was modified (ie. it is now valid). This can only happen
*             when 'rules_type' == CHECK_CMDU_RX_RULES
*     '2' --> If 'p' was not modifed (ie. it was valid from the beginning)
*/
#define CHECK_CMDU_TX_RULES (1)
#define CHECK_CMDU_RX_RULES (2)
static uint8_t check_cmdu_rules(i1905_cmdu_t *p, uint8_t rules_type)
{
    uint16_t  i = 0;
    uint8_t   structure_has_been_modified;
    uint8_t   counter[TLV_TYPE_LAST];
    uint8_t   tlvs_to_remove[TLV_TYPE_LAST];

    if ((NULL == p) || (NULL == p->list_of_TLVs)) {
        /* Invalid arguments */
        log_i1905_e("invalid CMDU structure");
        return 0;
    }
    /* Added this hack as the below check rules are applicable for only 1905 TLV types
    Multi AP TLV type check to be handled */
    while (NULL != p->list_of_TLVs[i]) {
        if (*(p->list_of_TLVs[i]) > TLV_TYPE_LAST) {
            /* Invalid arguments */
	    log_i1905_t("no 1905 TLV type");
	    return 2;
	}
	i++;
    }
    /* First of all, count how many times each type of TLV message appears in
    *  the structure. We will use this information later
    */
    for (i = 0; i < TLV_TYPE_LAST; i++) {
        counter[i]        = 0;
        tlvs_to_remove[i] = 0;
    }

    i = 0;
    while (NULL != p->list_of_TLVs[i]) {
        if (*(p->list_of_TLVs[i]) <= TLV_TYPE_LAST) {
             counter[*(p->list_of_TLVs[i])]++;
        }
        i++;
    }

    /* Rules 1.a and 2.c check the same thing : make sure the structure
    *  contains, *at least*, the required TLVs
    *
    *  If not, return '0'
    *
    *  The required TLVs are those contained in the "_exactlyone_tlvs_for_cmdu"
    *  table.
    */
    for (i = 0; i < TLV_TYPE_LAST; i++) {
        if ((p->message_type <=  CMDU_TYPE_1905_LAST_MESSAGE) &&
            (1 != counter[i])                                 &&
            (_exactlyone_tlvs_for_cmdu[p->message_type] & (1 << i))) {
            log_i1905_w("TLV %s should appear once on this CMDU, but it appears %d times", convert_1905_TLV_type_to_string(i), counter[i]);
            return 0;
        }
    }

    /* Rules 1.b and 2.b also both check for the same thing (unexpected TLVs),
    *  but they act in different ways:
    *
    *    * In case 'rules_type' == CHECK_CMDU_TX_RULES, return '0'
    *    * In case 'rules_type' == CHECK_CMDU_RX_RULES, remove the unexpected
    *      TLVs (and later, when all other checks have been performed, return
    *      '1' to indicate that the structure has been modified)
    *
    *  Unexpected TLVs are those that do not appear in neither the
    *  "_exactlyone_tlvs_for_cmdu" nor the "_zeroormore_tlvs_for_cmdu" tables
    */
    for (i = 0; i < TLV_TYPE_LAST; i++) {
        if ((p->message_type <=  CMDU_TYPE_1905_LAST_MESSAGE) &&
            (0 != counter[i])                                        &&
            (i != TLV_TYPE_VENDOR_SPECIFIC)                          &&
            !(_zeroormore_tlvs_for_cmdu[p->message_type] & (1 << i)) &&
            !(_exactlyone_tlvs_for_cmdu[p->message_type] & (1 << i)))
        {
            if (CHECK_CMDU_TX_RULES == rules_type) {
                log_i1905_w("TLV %s should not appear on this CMDU, but it appears %d times", convert_1905_TLV_type_to_string(i), counter[i]);
                return 0;
            } else {
                tlvs_to_remove[i] = 1;
            }
        }
    }
    i = 0;
    structure_has_been_modified = 0;
    while (NULL != p->list_of_TLVs[i]) {
        /* Here we will just traverse the list of TLVs and remove the ones
        *  that shouldn't be there.
        *  When this happens, mark the structure as 'modified' so that we can
        *  later return the appropriate return code.
        *
        *    NOTE:
        *      When removing TLVs they are first freed and the list of
        *      pointers ('list_of_TLVs') is simply overwritten.
        *      The original piece of memory that holds all pointers is not
        *      redimensioned, though, as it would make things unnecessary more
        *      complex.
        *      In other words:
        *
        *        Before removal:
        *          list_of_TLVs --> [p1, p2, p3, NULL]
        *
        *        After removing p2:
        *          list_of_TLVs --> [p1, p3, NULL, NULL]
        *
        *        ...and not:
        *          list_of_TLVs --> [p1, p3, NULL]
        */
        if (1 == tlvs_to_remove[*(p->list_of_TLVs[i])]) {
            uint16_t j = i + 1;

            free_1905_TLV_structure(p->list_of_TLVs[i]);

            structure_has_been_modified = 1;
            while (p->list_of_TLVs[j]) {
                p->list_of_TLVs[j-1] = p->list_of_TLVs[j];
                j++;
            }
            p->list_of_TLVs[j-1] = p->list_of_TLVs[j];
        } else {
           i++;
        }
    }

    /* Regarding rules 1.c and 2.a, we don't really have to do anything special,
    *  thus we can return now
    */
    if (1 == structure_has_been_modified) {
        return 1;
    } else {
        return 2;
    }
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
i1905_cmdu_t *parse_1905_CMDU_from_packets(uint8_t **packet_streams, uint16_t *packet_lenghts)
{
    i1905_cmdu_t *ret;

    uint8_t       fragments_nr;
    uint8_t       current_fragment;
    uint16_t      tlvs_nr;
    uint8_t       error;

    if (NULL == packet_streams) {
        /* Invalid arguments */
        log_i1905_e("NULL packet_streams");
        return NULL;
    }

    /* Find out how many streams/fragments we have received */
    fragments_nr = 0;
    while (*(packet_streams+fragments_nr)) {
        fragments_nr++;
    }
    if (0 == fragments_nr) {
        /* No streams supplied! */
        log_i1905_e("No fragments supplied");
        return NULL;
    }

    /* Allocate the return structure.
    *  Initially it will contain an empty list of TLVs that we will later
    *  re-allocate and fill.
    */
    ret = malloc(sizeof(i1905_cmdu_t) * 1);
    if (!ret) {
        return NULL;
    }
    ret->list_of_TLVs = malloc(sizeof(uint8_t *) * 1);
    if (!ret->list_of_TLVs) {
        free(ret);
        return NULL;
    }
    ret->list_of_TLVs[0] = NULL;
    tlvs_nr = 0;

    /* Next, parse each fragment */
    error = 0;
    for (current_fragment = 0; current_fragment<fragments_nr; current_fragment++) {
        uint8_t  *p;
        uint16_t  bytes_left;
        uint8_t   i;

        uint8_t   message_version;
        uint8_t   reserved_field;
        uint16_t  message_type;
        uint16_t  message_id;
        uint8_t   fragment_id;
        uint8_t   indicators;

        uint8_t   relay_indicator;
        uint8_t   last_fragment_indicator;

        uint8_t  *parsed;

        bytes_left = 0;
        /* We want to traverse fragments in order, thus lets search for the
        *  fragment whose 'fragment_id' matches 'current_fragment' (which will
        *  monotonically increase starting at '0')
        */
        for (i = 0; i < fragments_nr; i++) {
            p = *(packet_streams+i);
            bytes_left = *(packet_lenghts+i);

            /* The 'fragment_id' field is the 7th byte (offset 6) */
            if (current_fragment == *(p+6)) {
                break;
            }
        }
        if (i == fragments_nr) {
            /* One of the fragments is missing! */
            error = 1;
            break;
        }

        if (bytes_left < 8) {
            /* Packet too short to have cmdu header */
            error = 8;
            break;
        }
        bytes_left -= 8;

        /* At this point 'p' points to the stream whose 'fragment_id' is 'current_fragment' */

        /* Let's parse the header fields */
        _E1B(&p, &message_version);
        _E1B(&p, &reserved_field);
        _E2B(&p, &message_type);
        _E2B(&p, &message_id);
        _E1B(&p, &fragment_id);
        _E1B(&p, &indicators);

        last_fragment_indicator = (indicators & 0x80) >> 7; /* MSB and 2nd MSB of the 'indicators' field */
        relay_indicator         = (indicators & 0x40) >> 6;

        if (0 == current_fragment) {
            /* This is the first fragment, thus fill the 'common' values.
            *  We will later (in later fragments) check that their values always
            *  remain the same
            */
            ret->message_version = message_version;
            ret->message_type    = message_type;
            ret->message_id      = message_id;
            ret->relay_indicator = relay_indicator;
        } else {
            /* Check for consistency in all 'common' values */
            if ((ret->message_version != message_version) ||
                (ret->message_type    != message_type)    ||
                (ret->message_id      != message_id)      ||
                (ret->relay_indicator != relay_indicator))
            {
                /* Fragments with different common fields were detected! */
                error = 2;
                break;
            }
        }

        /* Regarding the 'relay_indicator', depending on the message type, it
        *  can only have a valid specific value
        */
        if ((message_type <= CMDU_TYPE_GENERIC_PHY_RESPONSE) && (0xff == _relayed_CMDU[message_type])) {
            /* Special, case. All values are allowed */
        } else if (message_type <= CMDU_TYPE_GENERIC_PHY_RESPONSE) {
            /* Check if the value for this type of message is valid */
            if (_relayed_CMDU[message_type] != relay_indicator) {
                /* Malformed packet */
                error = 3;
                break;
            }
        }

        /* Regarding the 'last_fragment_indicator' flag, the following condition
        *  must be met: the last fragement (and only it!) must have it set to
        *  '1'
        */
        if ((1 == last_fragment_indicator) && (current_fragment < fragments_nr-1)) {
            /* 'last_fragment_indicator' appeared *before* the last fragment */
            error = 4;
            break;
        }
        if ((0 == last_fragment_indicator) && (current_fragment == fragments_nr-1)) {
            /* 'last_fragment_indicator' did not appear in the last fragment */
            error = 5;
            break;
        }

        /* We can now parse the TLVs. 'p' is pointing to the first one at this moment */
        while (1) {
            parsed = parse_1905_TLV_from_packet(p, bytes_left);
            if (NULL == parsed) {
                /* Error while parsing a TLV
                *  Dump TLV for visual inspection
                */

                /* FRV: TODO: THIS CODE DOES NOT CHECK IF TLV GOES BEYOND CMDU */

                char      aux1[200];
                char      aux2[10];

                uint8_t  *p2 = p;
                uint16_t  len;

                uint8_t   first_time;
                uint8_t   j;
                uint8_t   aux;

                _E1B(&p2, &aux);
                _E2B(&p2, &len);

                log_i1905_w("Parsing error. Dumping bytes: %d ", error);

                /* Limit dump length */
                if (len > 200) {
                    len = 200;
                }

                aux1[0]    = 0x0;
                aux2[0]    = 0x0;
                first_time = 1;
                for (j = 0; j < len + 3; j++) {
                    snprintf(aux2, 6, "0x%02x ", p[j]);
                    strncat(aux1, aux2, 200 - strlen(aux1)-1);

                    if (0 != j && 0 == (j + 1) % 8) {
                        if (1 == first_time) {
                            log_i1905_t("[PLATFORM]   - Payload        = %s", aux1);
                            first_time = 0;
                        } else {
                            log_i1905_t("[PLATFORM]                      %s", aux1);
                        }
                        aux1[0] = 0x0;
                    }
                }

                error = 6;
                break;
            }

            /* FRV: End_of_message_TLV should only be present at the end of the last fragment,
            *       some ale send it in every packet.
            *
            *       Parsing error when
            *         "no end_of_message_TLV" and "bytes_left == 0" and "last_fragment bit set"
            *       Advance to next fragment if:
            *         "end_of_message_TLV present" or "bytes_left == 0"
            */
            if (TLV_TYPE_END_OF_MESSAGE == *parsed) {
                /* No more TLVs */
                free_1905_TLV_structure(parsed);
                break;
            }

            /* Advance 'p' to the next TLV */
            uint8_t  tlv_type;
            uint16_t tlv_len;

            _E1B(&p, &tlv_type);
            _E2B(&p, &tlv_len);

            p += tlv_len;
            bytes_left -= (3 + tlv_len);

            /* Add this new TLV to the list (the list needs to be re-allocated
            *  with more space first)
            */
            tlvs_nr++;
            uint8_t **new_list_of_TLVs = realloc(ret->list_of_TLVs, sizeof(uint8_t *) * (tlvs_nr + 1));
            if (!new_list_of_TLVs) {
                error = 10;
                break;
            }
            ret->list_of_TLVs = new_list_of_TLVs;
            ret->list_of_TLVs[tlvs_nr - 1] = parsed;
            ret->list_of_TLVs[tlvs_nr]     = NULL;

            if (0 == bytes_left) {
                /* Advance to next packet, except last fragment should have had an end_of_message_TLV */
                if (1 == last_fragment_indicator) {
                    error = 9;
                }
                break;
            }
        }
        if (0 != error) {
            break;
        }
    }

    if (0 == error) {
        /* Ok then... we now have our output structure properly filled.
        *  However, there is one last battery of checks we must perform:
        *
        *    - CMDU_TYPE_VENDOR_SPECIFIC: The first TLV *must* be of type
        *      TLV_TYPE_VENDOR_SPECIFIC
        *
        *    - All the other message types: Some TLVs (different for each of
        *      them) can only appear once, others can appear zero or more times
        *      and others must be ignored.
        *      The 'check_cmdu_rules()' takes care of this for us.
        */
        log_i1905_t("CMDU type: %s", convert_1905_CMDU_type_to_string(ret->message_type));

        if (CMDU_TYPE_VENDOR_SPECIFIC == ret->message_type) {
            if (NULL == ret->list_of_TLVs || NULL == ret->list_of_TLVs[0] || TLV_TYPE_VENDOR_SPECIFIC != *(ret->list_of_TLVs[0])) {
                error = 7;
            }
        } else {
            switch (check_cmdu_rules(ret, CHECK_CMDU_RX_RULES)) {
                case 0:
                    /* The structure was missing some required TLVs. This is
                    *  a malformed packet which must be ignored.
                    */
                    log_i1905_w("Structure is missing some required TLVs");
                    log_i1905_w("List of present TLVs:");

                    if (NULL != ret->list_of_TLVs) {
                        uint16_t i = 0;

                        while (ret->list_of_TLVs[i]) {
                            log_i1905_w("  - %s", convert_1905_TLV_type_to_string(*(ret->list_of_TLVs[i])));
                            i++;
                        }
                        log_i1905_w("  - <END>");
                    } else {
                        log_i1905_w("  - <NONE>");
                    }

                    free_1905_CMDU_structure(ret);
                    return NULL;
                case 1:
                    /* The structure contained unxecpected TLVs. They have been
                    *  removed for us.
                    */
                break;
                case 2:
                    /* The structure was perfect and 'check_cmdu_rules()' did
                    *  not need to modify anything.
                    */
                break;
                default:
                    /* This point should never be reached */
                    error = 8;
                break;
            }
        }
    }

    /* Finally! If we get this far without errors we are already done, otherwise
    *  free everything and return NULL
    */
    if (0 != error) {
        log_i1905_e("Parsing error %d", error);
        free_1905_CMDU_structure(ret);
        return NULL;
    }

    return ret;
}

uint8_t **forge_1905_CMDU_from_structure(i1905_cmdu_t *memory_structure, uint16_t **lens)
{
    uint8_t **ret;

    uint16_t  tlv_start;
    uint16_t  tlv_stop;

    uint8_t   fragments_nr;

    uint32_t  max_tlvs_block_size;
    uint32_t  max_last_tlvs_block_size;

    uint8_t   error = 0;

    if (NULL == memory_structure || NULL == lens) {
        /* Invalid arguments */
        return NULL;
    }
    if (NULL == memory_structure->list_of_TLVs) {
        /* Invalid arguments */
        return NULL;
    }

    /* Before anything else, let's check that the CMDU 'rules' are satisfied: */
    if (0 == check_cmdu_rules(memory_structure, CHECK_CMDU_TX_RULES)) {
        /* Invalid arguments */
        return NULL;
    }

    /* Allocate the return streams.
    *  Initially we will just have an empty list (ie. it contains a single
    *  element marking the end-of-list: a NULL pointer)
    */
    ret = malloc(sizeof(uint8_t *) * 1);
    if (ret == NULL) {
        return NULL;
    }
    ret[0] = NULL;

    *lens = malloc(sizeof(uint16_t) * 1);
    if (*lens == NULL) {
        free(ret);
        return NULL;
    }
    (*lens)[0] = 0;

    fragments_nr = 0;

    /* Let's create as many streams as needed so that all of them fit in
    *  MAX_NETWORK_SEGMENT_SIZE bytes.
    *
    *  More specifically, each of the fragments that we are going to generate
    *  will have a size equal to the sum of:
    *
    *    ETHERNET HEADER
    *    - 6 bytes (destination MAC address)
    *    - 6 bytes (origin MAC address)
    *    - 2 bytes (ETH type)
    *    - 4 bytes (.1Q TAG)
    *    CMDU HEADER
    *    - 1 byte  (CMDU message version)
    *    - 1 byte  (CMDU reserved field)
    *    - 2 bytes (CMDU message type)
    *    - 2 bytes (CMDU message id)
    *    - 1 byte  (CMDU fragment id)
    *    - 1 byte  (CMDU flags/indicators)
    *    TLVS
    *    - X bytes (size of all TLVs contained in the fragment)
    *    - 3 bytes (TLV_TYPE_END_OF_MESSAGE TLV) - only in last fragment
    *
    *  In other words, X (the size of all the TLVs that are going to be inside
    *  this fragmen) can not be greater than MAX_NETWORK_SEGMENT_SIZE - 6 - 6 -
    *  - 4- 2 - 1 - 1 - 2 - 2 - 1 - 1 = MAX_NETWORK_SEGMENT_SIZE - 26 bytes.
    *
    *  And another 3 bytes need to be reserved in for the last fragment
    *
    *  Note: MAX_NETWORK_SEGMENT_SIZE must be 1518, so max total CMDU size is
    *        1500 bytes
    */
#if MAX_NETWORK_SEGMENT_SIZE != 1518
    #error Invalid MAX_NETWORK_SEGMENT_SIZE
#endif

    max_tlvs_block_size      = MAX_NETWORK_SEGMENT_SIZE - ETH_8021Q_HDR_SIZE - CMDU_HDR_SIZE;
    max_last_tlvs_block_size = max_tlvs_block_size - 3;
    tlv_start                = 0;
    tlv_stop                 = 0;
    do {
        uint8_t  *s;
        uint16_t  i;

        uint16_t  current_X_size = 0;
        uint8_t   no_space = 0;

        uint8_t   reserved_field;
        uint8_t   fragment_id;
        uint8_t   indicators;

        uint16_t  tlv_stream_size = 0;

        while (memory_structure->list_of_TLVs[tlv_stop]) {
            uint8_t  *p;
            uint8_t  *tlv_stream;
            /* Max block size is different for last fragment (no next TLV) */
            uint32_t break_size = memory_structure->list_of_TLVs[tlv_stop + 1] ?
                                  max_tlvs_block_size : max_last_tlvs_block_size;

            p = memory_structure->list_of_TLVs[tlv_stop];

            tlv_stream = forge_1905_TLV_from_structure(p, &tlv_stream_size);
            free(tlv_stream);

            if (current_X_size + tlv_stream_size <= break_size) {
                tlv_stop++;
            } else {
                /* There is no space for more TLVs */
                no_space = 1;
                break;
            }

            current_X_size += tlv_stream_size;
        }
        if (tlv_start == tlv_stop) {
            if (1 == no_space) {
                /* One *single* TLV does not fit in a fragment!
                *  This is an error... there is no way to split one single TLV into
                *  several fragments according to the standard.
                */
                log_i1905_e("single TLV does not fit (length %d)", tlv_stream_size);
                error = 1;
                break;
            } else {
                /* If we end up here, it means tlv_start = tlv_stop = 0 --> this
                *  CMDU contains no TLVs (which is something that can happen...
                *  for example, in the "topology query" CMDU).
                *  Just keep executing...
                */
            }
        }

        /* Now that we know how many TLVs are going to be embedded inside this
        *  fragment (from 'tlv_start' up to -and not including- 'tlv_stop'),
        *  let's build it
        */
        fragments_nr++;

        /* Allocate memory for next fragment, realloc ret and lens arrays */
        uint8_t **new_ret = realloc(ret, sizeof(uint8_t *) * (fragments_nr + 1));
        if (!new_ret) {
            error = 2;
            break;
        }
        ret = new_ret;
        ret[fragments_nr-1] = malloc(MAX_NETWORK_SEGMENT_SIZE);
        ret[fragments_nr]   = NULL;
        if (!ret[fragments_nr-1]) {
            error = 3;
            break;
        }

        uint16_t *new_lens = realloc(*lens, sizeof(uint16_t) * (fragments_nr + 1));
        if (!new_lens) {
            error = 4;
            break;
        }
        *lens = new_lens;
        (*lens)[fragments_nr-1] = 0; /* To be updated a few lines later */
        (*lens)[fragments_nr]   = 0;

        s = ret[fragments_nr-1];

        reserved_field = 0;
        fragment_id    = fragments_nr-1;
        indicators     = 0;

        /* Set 'last_fragment_indicator' flag (bit #7) */
        if (NULL == memory_structure->list_of_TLVs[tlv_stop]) {
            indicators |= 1 << 7;
        }

        /* Set 'relay_indicator' flag (bit #6) */
        /* Again this hack as relayed CMDU is only handled for 1905 TLV
           Avoid array out of bounds for the MultiAP TLV types
        */
        if (memory_structure->message_type < CMDU_TYPE_1905_LAST_MESSAGE) {
            if (0xff == _relayed_CMDU[memory_structure->message_type]) {
                /* Special, case. Respect what the caller told us */
                indicators |= memory_structure->relay_indicator << 6;
            } else {
                /* Use the fixed value for this type of message according to the standard */
                indicators |= _relayed_CMDU[memory_structure->message_type] << 6;
            }
        }

        _I1B(&memory_structure->message_version, &s);
        _I1B(&reserved_field,                    &s);
        _I2B(&memory_structure->message_type,    &s);
        _I2B(&memory_structure->message_id,      &s);
        _I1B(&fragment_id,                       &s);
        _I1B(&indicators,                        &s);

        for (i = tlv_start; i < tlv_stop; i++) {
            uint8_t  *tlv_stream      = NULL;
            uint16_t  tlv_stream_size = 0;

            tlv_stream = forge_1905_TLV_from_structure(memory_structure->list_of_TLVs[i], &tlv_stream_size);

            if(tlv_stream == NULL) {
                log_i1905_e("forged NULL tlv stream out of memory structure");
            } else {
                memcpy(s, tlv_stream, tlv_stream_size);
            }
            SFREE(tlv_stream);

            s += tlv_stream_size;
        }

        /* Don't forget to add the last three octects representing the
        *  TLV_TYPE_END_OF_MESSAGE message for the last fragment
        */
        if (NULL == memory_structure->list_of_TLVs[tlv_stop]) {
            *s = 0x0; s++;
            *s = 0x0; s++;
            *s = 0x0; s++;
        }

        /* Update the length return value */
        (*lens)[fragments_nr-1] = s - ret[fragments_nr-1];

        /* And advance the TLV pointer so that, if more fragments are needed,
        *  the next one starts where we have stopped.
        */
        tlv_start = tlv_stop;

    } while (memory_structure->list_of_TLVs[tlv_start]);

    /* Finally! If we get this far without errors we are already done, otherwise
    *  free everything and return NULL
    */
    if (0 != error) {
        free_1905_CMDU_packets(ret);
        free(*lens);
        return NULL;
    }

    return ret;
}

uint8_t parse_1905_CMDU_header_from_packet(uint8_t *stream, uint16_t *mid, uint8_t *fragment_id, uint8_t *last_fragment_indicator)
{
    uint8_t  message_version;
    uint8_t  reserved_field;
    uint16_t message_type;
    uint8_t  indicators;

    if ((NULL == stream) || (NULL == mid) || (NULL == fragment_id) || (NULL == last_fragment_indicator)) {
        /* Invalid params */
        return 0;
    }

    /* Let's parse the header fields */
    _E1B(&stream, &message_version);
    _E1B(&stream, &reserved_field);
    _E2B(&stream, &message_type);
    _E2B(&stream, mid);
    _E1B(&stream, fragment_id);
    _E1B(&stream, &indicators);

    *last_fragment_indicator = (indicators & 0x80) >> 7; /* MSB and 2nd MSB */

    return 1;
}

void free_1905_CMDU_structure(i1905_cmdu_t *memory_structure)
{
    if ((NULL != memory_structure) && (NULL != memory_structure->list_of_TLVs)) {
        uint16_t i = 0;

        while (memory_structure->list_of_TLVs[i]) {
            free_1905_TLV_structure(memory_structure->list_of_TLVs[i]);
            i++;
        }
        free(memory_structure->list_of_TLVs);
    }

    free(memory_structure);
}

void free_1905_CMDU_packets(uint8_t **packet_streams)
{
    uint8_t i = 0;

    if (NULL == packet_streams) {
        return;
    }

    while (packet_streams[i]) {
        free(packet_streams[i]);
        i++;
    }
    free(packet_streams);
}

uint8_t compare_1905_CMDU_structures(i1905_cmdu_t *memory_structure_1, i1905_cmdu_t *memory_structure_2)
{
    uint16_t i = 0;

    if (NULL == memory_structure_1 || NULL == memory_structure_2) {
        return 1;
    }
    if (NULL == memory_structure_1->list_of_TLVs || NULL == memory_structure_2->list_of_TLVs) {
        return 1;
    }

    if ((memory_structure_1->message_version         != memory_structure_2->message_version)         ||
        (memory_structure_1->message_type            != memory_structure_2->message_type)            ||
        (memory_structure_1->message_id              != memory_structure_2->message_id)              ||
        (memory_structure_1->relay_indicator         != memory_structure_2->relay_indicator)) {
        return 1;
    }

    while (1) {
        if (NULL == memory_structure_1->list_of_TLVs[i] && NULL == memory_structure_2->list_of_TLVs[i]) {
            /* No more TLVs to compare! Return '0' (structures are equal) */
            return 0;
        }

        if (0 != compare_1905_TLV_structures(memory_structure_1->list_of_TLVs[i], memory_structure_2->list_of_TLVs[i])) {
            /* TLVs are not the same */
            return 1;
        }

        i++;
    }

    /* This point should never be reached */
    return 1;
}

void visit_1905_CMDU_structure(i1905_cmdu_t *memory_structure, void (*callback)(void (*write_function)(const char *fmt, ...),
                               const char *prefix, size_t size, const char *name, const char *fmt, void *p),
                               void (*write_function)(const char *fmt, ...), const char *prefix)
{
    /* Buffer size to store a prefix string that will be used to show each
    *  element of a structure on screen
    */
    #define MAX_PREFIX  100

    uint16_t i = 0;

    if (NULL == memory_structure) {
        return;
    }

    callback(write_function, prefix, sizeof(memory_structure->message_version), "message_version", "%d",  &memory_structure->message_version);
    callback(write_function, prefix, sizeof(memory_structure->message_type),    "message_type",    "%d",  &memory_structure->message_type);
    callback(write_function, prefix, sizeof(memory_structure->message_id),      "message_id",      "%d",  &memory_structure->message_id);
    callback(write_function, prefix, sizeof(memory_structure->relay_indicator), "relay_indicator", "%d",  &memory_structure->relay_indicator);

    if (NULL == memory_structure->list_of_TLVs) {
        return;
    }

    while (NULL != memory_structure->list_of_TLVs[i]) {
        /* In order to make it easier for the callback() function to present
        *  useful information, append the type of the TLV to the prefix
        */
        char new_prefix[MAX_PREFIX];
        snprintf(new_prefix, MAX_PREFIX, "%s(%s)->", prefix, convert_1905_TLV_type_to_string(*(memory_structure->list_of_TLVs[i])));

        visit_1905_TLV_structure(memory_structure->list_of_TLVs[i], callback, write_function, new_prefix);
        i++;
    }
}

char *convert_1905_CMDU_type_to_string(uint16_t cmdu_type)
{
#define CMDU_STR(type) case type: return #type;

    switch(cmdu_type) {
        /* 1905 */
        CMDU_STR(CMDU_TYPE_TOPOLOGY_DISCOVERY)
        CMDU_STR(CMDU_TYPE_TOPOLOGY_NOTIFICATION)
        CMDU_STR(CMDU_TYPE_TOPOLOGY_QUERY)
        CMDU_STR(CMDU_TYPE_TOPOLOGY_RESPONSE)
        CMDU_STR(CMDU_TYPE_VENDOR_SPECIFIC)
        CMDU_STR(CMDU_TYPE_LINK_METRIC_QUERY)
        CMDU_STR(CMDU_TYPE_LINK_METRIC_RESPONSE)
        CMDU_STR(CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH)
        CMDU_STR(CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE)
        CMDU_STR(CMDU_TYPE_AP_AUTOCONFIGURATION_WSC)
        CMDU_STR(CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW)
        CMDU_STR(CMDU_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION)
        CMDU_STR(CMDU_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION)
        CMDU_STR(CMDU_TYPE_HIGHER_LAYER_QUERY)
        CMDU_STR(CMDU_TYPE_HIGHER_LAYER_RESPONSE)
        CMDU_STR(CMDU_TYPE_INTERFACE_POWER_CHANGE_REQUEST)
        CMDU_STR(CMDU_TYPE_INTERFACE_POWER_CHANGE_RESPONSE)
        CMDU_STR(CMDU_TYPE_GENERIC_PHY_QUERY)
        CMDU_STR(CMDU_TYPE_GENERIC_PHY_RESPONSE)

        /* MAP R1 */
        CMDU_STR(CMDU_TYPE_MAP_ACK)
        CMDU_STR(CMDU_TYPE_MAP_AP_CAPABILITY_QUERY)
        CMDU_STR(CMDU_TYPE_MAP_AP_CAPABILITY_REPORT)
        CMDU_STR(CMDU_TYPE_MAP_MULTI_AP_POLICY_CONFIG_REQUEST)
        CMDU_STR(CMDU_TYPE_MAP_CHANNEL_PREFERENCE_QUERY)
        CMDU_STR(CMDU_TYPE_MAP_CHANNEL_PREFERENCE_REPORT)
        CMDU_STR(CMDU_TYPE_MAP_CHANNEL_SELECTION_REQUEST)
        CMDU_STR(CMDU_TYPE_MAP_CHANNEL_SELECTION_RESPONSE)
        CMDU_STR(CMDU_TYPE_MAP_OPERATING_CHANNEL_REPORT)
        CMDU_STR(CMDU_TYPE_MAP_CLIENT_CAPABILITY_QUERY)
        CMDU_STR(CMDU_TYPE_MAP_CLIENT_CAPABILITY_REPORT)
        CMDU_STR(CMDU_TYPE_MAP_AP_METRICS_QUERY)
        CMDU_STR(CMDU_TYPE_MAP_AP_METRICS_RESPONSE)
        CMDU_STR(CMDU_TYPE_MAP_ASSOCIATED_STA_LINK_METRICS_QUERY)
        CMDU_STR(CMDU_TYPE_MAP_ASSOCIATED_STA_LINK_METRICS_RESPONSE)
        CMDU_STR(CMDU_TYPE_MAP_UNASSOCIATED_STA_LINK_METRICS_QUERY)
        CMDU_STR(CMDU_TYPE_MAP_UNASSOCIATED_STA_LINK_METRICS_RESPONSE)
        CMDU_STR(CMDU_TYPE_MAP_BEACON_METRICS_QUERY)
        CMDU_STR(CMDU_TYPE_MAP_BEACON_METRICS_RESPONSE)
        CMDU_STR(CMDU_TYPE_MAP_COMBINED_INFRASTRUCTURE_METRICS)
        CMDU_STR(CMDU_TYPE_MAP_CLIENT_STEERING_REQUEST)
        CMDU_STR(CMDU_TYPE_MAP_CLIENT_STEERING_BTM_REPORT)
        CMDU_STR(CMDU_TYPE_MAP_CLIENT_ASSOCIATION_CONTROL_REQUEST)
        CMDU_STR(CMDU_TYPE_MAP_STEERING_COMPLETED)
        CMDU_STR(CMDU_TYPE_MAP_HIGHER_LAYER_DATA)
        CMDU_STR(CMDU_TYPE_MAP_BACKHAUL_STEERING_REQUEST)
        CMDU_STR(CMDU_TYPE_MAP_BACKHAUL_STEERING_RESPONSE)

        /* MAP R2 */
        CMDU_STR(CMDU_TYPE_MAP_CHANNEL_SCAN_REQUEST)
        CMDU_STR(CMDU_TYPE_MAP_CHANNEL_SCAN_REPORT)
        CMDU_STR(CMDU_TYPE_MAP_CAC_REQUEST)
        CMDU_STR(CMDU_TYPE_MAP_CAC_TERMINATION)
        CMDU_STR(CMDU_TYPE_MAP_CLIENT_DISASSOCIATION_STATS)
        CMDU_STR(CMDU_TYPE_MAP_ERROR_RESPONSE)
        CMDU_STR(CMDU_TYPE_MAP_ASSOCIATION_STATUS_NOTIFICATION)
        CMDU_STR(CMDU_TYPE_MAP_TUNNELED)
        CMDU_STR(CMDU_TYPE_MAP_BACKHAUL_STA_CAPABILITY_QUERY)
        CMDU_STR(CMDU_TYPE_MAP_BACKHAUL_STA_CAPABILITY_REPORT)
        CMDU_STR(CMDU_TYPE_MAP_FAILED_CONNECTION)

        /* MAP R3 */
        CMDU_STR(CMDU_TYPE_MAP_DPP_CCE_INDICATION)
        CMDU_STR(CMDU_TYPE_MAP_PROXIED_ENCAP_DPP)
        CMDU_STR(CMDU_TYPE_MAP_DIRECT_ENCAP_DPP)
        CMDU_STR(CMDU_TYPE_MAP_CHIRP_NOTIFICATION)
        CMDU_STR(CMDU_TYPE_MAP_1905_ENCAP_EAPOL)

        default: return "CMDU_TYPE_UNKNOWN";
    }
}
