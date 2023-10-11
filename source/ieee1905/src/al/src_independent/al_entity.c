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

// In the comments below, every time a reference is made (ex: "See Section 6.4"
// or "See Table 6-11") we are talking about the contents of the following
// document:
//
//   "IEEE Std 1905.1-2013"

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <net/ethernet.h>
#include <arpa/inet.h>

#define LOG_TAG "al"

#include "platform.h"
#include "utils.h"
#include "packet_tools.h"

#include "1905_tlvs.h"
#include "1905_cmdus.h"
#include "1905_l2.h"

#include "lldp_tlvs.h"
#include "lldp_payload.h"

#include "al.h"
#include "al_datamodel.h"
#include "al_send.h"
#include "al_recv.h"
#include "al_utils.h"

#include "platform_interfaces.h"
#include "platform_os.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define MAX_MIDS_IN_FLIGHT          8

#define MAX_FRAGMENTS_PER_MID      26

#define MAX_DUPLICATES_LOG_ENTRIES 16

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
/* This is a structure used to store the fragments belonging to up to
*  'MAX_MIDS_IN_FLIGHT' CMDU messages.
*  Initially all entries are marked as "empty" by setting the 'in_use' field
*  to "0"
*/
typedef struct mids_in_flight_s {
    uint8_t  in_use; /* Is this entry free? */

    uint16_t mid;    /* 'mid' associated to this CMDU */

    mac_addr src_addr;
    mac_addr dst_addr;
                     /* These two (together with the 'mid' field) will be used
                     *  to identify fragments belonging to one same CMDU.
                     */

    uint8_t fragments[MAX_FRAGMENTS_PER_MID];
                     /* Each entry represents a fragment number.
                     *    - "1" means that fragment has been received
                     *    - "0" means no fragment with that number has been
                     *  received.
                     */

    uint8_t last_fragment;
                     /* Number of the fragment carrying the
                     *  'last_fragment_indicator' flag.
                     *  This is always a number between 0 and
                     *  MAX_FRAGMENTS_PER_MID-1.
                     *  Iniitally it is set to "MAX_FRAGMENTS_PER_MID",
                     *  meaning that no fragment with the
                     *  'last_fragment_indicator' flag has been received yet.
                     */

    uint8_t *streams[MAX_FRAGMENTS_PER_MID + 1];
                    /* Each of the bit streams associated to each fragment
                     *
                     *  The size is "MAX_FRAGMENTS_PER_MID+1" instead of
                     *  "MAX_FRAGMENTS_PER_MID" to store a final NULL entry
                     *  (this makes it easier to later call
                     *  "parse_1905_CMDU_header_from_packet()"
                     */

    uint16_t lengths[MAX_FRAGMENTS_PER_MID + 1];
                     /* Length of each fragment.
                     *  Counted from after the ethernet header
                     */

    uint32_t age;    /* Used to keep track of which is the oldest CMDU for
                     *  which a fragment was received (so that we can free
                     *  it when the CMDUs buffer is full)
                     */
} mids_in_flight_t;

typedef struct {
    mids_in_flight_t mids_in_flight[MAX_MIDS_IN_FLIGHT];
    uint32_t         current_age;
} reassemble_t;

typedef struct {
    mac_addr mac_addresses[MAX_DUPLICATES_LOG_ENTRIES];
    uint16_t message_ids  [MAX_DUPLICATES_LOG_ENTRIES];
    uint16_t message_type [MAX_DUPLICATES_LOG_ENTRIES];

    uint8_t  start;
    uint8_t  total;
} check_duplicates_t;

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static al1905_cmdu_cb_t   g_cmdu_cb;

static reassemble_t       g_reassemble;

static check_duplicates_t g_check_dup;

/*#######################################################################
#                       PRIVATE FUNCTIONS                               #
########################################################################*/
/* CMDUs can be received in multiple fragments/packets when they are too big to
*  fit in a single "network transmission unit" (which is never bigger than
*  MAX_NETWORK_SEGMENT_SIZE).
*
*  Fragments that belong to one same CMDU contain the same 'mid' and different
*  'fragment id' values. In addition, the last fragment is the only one to
*  contain the 'last fragment indicator' field set.
*
*    NOTE: This is all also explained in "Sections 7.1.1 and 7.1.2"
*
*  This function will "buffer" fragments until either all pieces arrive or a
*  timer expires (in which case all previous fragments are discarded/ignored)
*
*    NOTE: Instead of a timer, we will use a buffer that holds up to
*          MAX_MIDS_IN_FLIGHT CMDUs.
*          If we are still waiting for MAX_MIDS_IN_FLIGHT CMDUs to be completed
*          (ie. we haven't received all their fragments yet), and a new fragment
*          for a new CMDU arrives, we will discard all fragments from the
*          oldest one.
*
*  Every time this function is called, two things can happen:
*
*    1. The just received fragment was the last one needed to complete a CMDU.
*       In this case, the CMDU structure result of all those fragments being
*       parsed is returned.
*
*    2. The just received fragment is not yet the last one needed to complete a
*       CMDU. In this case the fragment is internally buffered (ie. the caller
*       does not need to keep the passed buffer around in memory) and this
*       function returns NULL.
*
*  This function received two arguments:
*
*    - 'packet_buffer' is a pointer to the received stream containing a
*      fragment (or a whole) CMDU
*
*    - 'len' is the length of this 'packet_buffer' in bytes
*/

/* FRV: Notes about fragmentation
1) The original 1905 stack only keeps the payload (called stream) and does not
   use the length in the parser.  Also it did expect an end of message TLV in
   every fragment.

   EM R2 specifically states that there should only be an end of message TLV in
   the last fragment.

   To handle this:
     - the length is stored also and checked by the parser.
     - end of message cmdu in stream that does not have the last fragment bit set
       is ignored

2)  FUTURE: In EMR1/2, fragmentation is on a TLV boundary.  In EMR3, this restriction
    is removed.

    Currently, all packets are stored in the streams array. To handle EM3 case,
    the fragments must first be concatenated and then handled to the parser
    as one big packet.

    In this case unwanted end of message TLV's must be removed.
*/

static i1905_cmdu_t *reassemble_fragmented_cmdu(uint8_t *packet_buffer, uint16_t len)
{
    struct ether_header *eh       = (struct ether_header*) packet_buffer;
    uint8_t             *dst_addr = eh->ether_dhost;
    uint8_t             *src_addr = eh->ether_shost;

    uint16_t             mid;
    uint8_t              fragment_id;
    uint8_t              last_fragment_indicator;

    uint8_t              i, j;
    uint8_t             *p = &packet_buffer[sizeof(struct ether_header)]; /* After ethernet header */

    len -= sizeof(struct ether_header);
    log_i1905_t("Parse Stream Length From Reassembly:%d", len);

    if (0 == parse_1905_CMDU_header_from_packet(p, &mid, &fragment_id, &last_fragment_indicator)) {
        log_i1905_e("Could not retrieve CMDU header from bit stream");
        return NULL;
    }
    log_i1905_t("mid = 0x%x, fragment_id = %d, last_fragment_indicator = %d", mid, fragment_id, last_fragment_indicator);

    /* Find the set of streams associated to this 'mid' and add the just
    *  received stream to its set of streams
    */
    for (i = 0; i<MAX_MIDS_IN_FLIGHT; i++) {
        if (1   == g_reassemble.mids_in_flight[i].in_use                      &&
            mid == g_reassemble.mids_in_flight[i].mid                         &&
            0   == maccmp(dst_addr, g_reassemble.mids_in_flight[i].dst_addr)  &&
            0   == maccmp(src_addr, g_reassemble.mids_in_flight[i].src_addr)) {
            /* Fragments for this 'mid' have previously been received. Add this new one to the set.
            *  ...but first check for errors
            */
            if (fragment_id > MAX_FRAGMENTS_PER_MID - 1) {
                log_i1905_w("Too many fragments (%d) for one same CMDU (max supported is %d)", fragment_id, MAX_FRAGMENTS_PER_MID);
                log_i1905_w("  mid      = %d", mid);
                log_i1905_w("  src_addr = %s", acu_mac_string(src_addr));
                log_i1905_w("  dst_addr = %s", acu_mac_string(dst_addr));
                return NULL;
            }

            if (1 == g_reassemble.mids_in_flight[i].fragments[fragment_id]) {
                log_i1905_w("Ignoring duplicated fragment #%d",fragment_id);
                log_i1905_w("  mid      = %d", mid);
                log_i1905_w("  src_addr = %s", acu_mac_string(src_addr));
                log_i1905_w("  dst_addr = %s", acu_mac_string(dst_addr));
                return NULL;
            }

            if (1 == last_fragment_indicator && MAX_FRAGMENTS_PER_MID != g_reassemble.mids_in_flight[i].last_fragment) {
                log_i1905_w("This fragment (#%d) and a previously received one (#%d) both contain the 'last_fragment_indicator' flag set. Ignoring...", fragment_id, g_reassemble.mids_in_flight[i].last_fragment);
                log_i1905_w("  mid      = %d", mid);
                log_i1905_w("  src_addr = %s", acu_mac_string(src_addr));
                log_i1905_w("  dst_addr = %s", acu_mac_string(dst_addr));
                return NULL;
            }

            /* ...and now actually save the stream for later */
            g_reassemble.mids_in_flight[i].fragments[fragment_id] = 1;

            if (1 == last_fragment_indicator) {
                g_reassemble.mids_in_flight[i].last_fragment = fragment_id;
            }

            g_reassemble.mids_in_flight[i].streams[fragment_id] = (uint8_t *)malloc((sizeof(uint8_t) * len));
            memcpy(g_reassemble.mids_in_flight[i].streams[fragment_id], p, len);
            g_reassemble.mids_in_flight[i].lengths[fragment_id] = len;

            g_reassemble.mids_in_flight[i].age = g_reassemble.current_age++;

            break;
        }
    }

    /* If we get inside the next "if()", that means no previous entry matches
    *  this 'mid' + 'src_addr' + 'dst_addr' tuple.
    *  What we have to do then is to search for an empty slot and add this as
    *  the first stream associated to this new tuple.
    */
    if (MAX_MIDS_IN_FLIGHT == i) {
        for (i = 0; i < MAX_MIDS_IN_FLIGHT; i++) {
            if (0 == g_reassemble.mids_in_flight[i].in_use) {
                break;
            }
        }

        if (MAX_MIDS_IN_FLIGHT == i) {
            /* All slots are in use!!
            *
            *  We need to discard the oldest one (ie. the one with the lowest
            *  'age')
            */
            uint32_t lowest_age;

            lowest_age = g_reassemble.mids_in_flight[0].age;
            j          = 0;

            for (i = 1; i < MAX_MIDS_IN_FLIGHT; i++) {
                if (g_reassemble.mids_in_flight[i].age < lowest_age) {
                    lowest_age = g_reassemble.mids_in_flight[i].age;
                    j          = i;
                }
            }

            log_i1905_w("Discarding old CMDU fragments to make room for the just received one. CMDU being discarded:");
            log_i1905_w("  mid      = %d", g_reassemble.mids_in_flight[j].mid);
            log_i1905_w("  mids_in_flight[j].src_addr = %s", acu_mac_string(g_reassemble.mids_in_flight[j].src_addr));
            log_i1905_w("  mids_in_flight[j].dst_addr = %s", acu_mac_string(g_reassemble.mids_in_flight[j].dst_addr));

            for (i=0; i<MAX_FRAGMENTS_PER_MID; i++) {
                if (1 == g_reassemble.mids_in_flight[j].fragments[i] && NULL != g_reassemble.mids_in_flight[j].streams[i]) {
                    free(g_reassemble.mids_in_flight[j].streams[i]);
                }
            }

            g_reassemble.mids_in_flight[j].in_use = 0;

            i = j;
        }

        /* Now that we have our empty slot, initialize it and fill it with the
        *  just received stream:
        */
        g_reassemble.mids_in_flight[i].in_use = 1;
        g_reassemble.mids_in_flight[i].mid    = mid;

        maccpy(g_reassemble.mids_in_flight[i].src_addr, src_addr);
        maccpy(g_reassemble.mids_in_flight[i].dst_addr, dst_addr);

        for (j = 0; j < MAX_FRAGMENTS_PER_MID; j++) {
            g_reassemble.mids_in_flight[i].fragments[j] = 0;
            g_reassemble.mids_in_flight[i].streams[j]   = NULL;
        }
        g_reassemble.mids_in_flight[i].streams[MAX_FRAGMENTS_PER_MID] = NULL;

        g_reassemble.mids_in_flight[i].fragments[fragment_id]  = 1;
        g_reassemble.mids_in_flight[i].streams[fragment_id]    = (uint8_t *)malloc((sizeof(uint8_t) * len));
        memcpy(g_reassemble.mids_in_flight[i].streams[fragment_id], p, len);
        g_reassemble.mids_in_flight[i].lengths[fragment_id] = len;

        if (1 == last_fragment_indicator) {
            g_reassemble.mids_in_flight[i].last_fragment = fragment_id;
        } else {
            g_reassemble.mids_in_flight[i].last_fragment = MAX_FRAGMENTS_PER_MID;
            /* NOTE: This means "no 'last_fragment_indicator' flag has been received yet. */
        }

        g_reassemble.mids_in_flight[i].age = g_reassemble.current_age++;
    }

    /* At this point we have an entry in the 'g_reassemble.mids_in_flight' array (entry 'i')
    *  where a new stream/fragment has been added.
    *
    *  We now have to check if we have received all fragments for this 'mid'
    *  and, if so, process them and obtain a CMDU structure that will be
    *  returned to the caller of the function.
    *
    *  Otherwise, return NULL.
    */
    if (MAX_FRAGMENTS_PER_MID != g_reassemble.mids_in_flight[i].last_fragment) {
        i1905_cmdu_t *c;

        for (j = 0; j <= g_reassemble.mids_in_flight[i].last_fragment; j++) {
            if (0 == g_reassemble.mids_in_flight[i].fragments[j]) {
                log_i1905_t("We still have to wait for more fragments to complete the CMDU message");
                return NULL;
            }
        }

        c = parse_1905_CMDU_from_packets(g_reassemble.mids_in_flight[i].streams, g_reassemble.mids_in_flight[i].lengths);

        if (NULL == c) {
            log_i1905_e("parse_1905_CMDU_header_from_packet() failed");
        } else {
            log_i1905_t("All fragments belonging to this CMDU have already been received and the CMDU structure is ready");
            maccpy(c->cmdu_stream.src_mac_addr, src_addr);
        }

        for (j = 0; j <= g_reassemble.mids_in_flight[i].last_fragment; j++) {
            free(g_reassemble.mids_in_flight[i].streams[j]);
        }
        g_reassemble.mids_in_flight[i].in_use = 0;

        return c;
    }

    log_i1905_t("The last fragment has not yet been received");
    return NULL;
}

/* Returns '1' if the packet has already been processed in the past and thus,
*  should be discarded (to avoid network storms). '0' otherwise.
*
*  According to what is explained in "Sections 7.5, 7.6 and 7.7" if a
*  defragmented packet whose "AL MAC address TLV" and "message id" match one
*  that has already been received in the past, then it should be discarded.
*
*  I *personally* think the standard is "slightly" wrong here because *not* all
*  CMDUs contain an "AL MAC address TLV".
*  We could use the ethernet source address instead, however this would only
*  work for those messages that are *not* relayed (one same duplicated relayed
*  message can arrive at our local node with two different ethernet source
*  addresses).
*  Fortunately for us, all relayed CMDUs *do* contain an "AL MAC address TLV",
*  thus this is what we are going to do:
*
*    1. If the CMDU is a relayed one, check against the "AL MAC" contained in
*       the "AL MAC address TLV"
*
*    2. If the CMDU is *not* a relayed one, check against the ethernet source
*       address
*
*  This function keeps track of the latest MAX_DUPLICATES_LOG_ENTRIES tuples
*  of ("mac_address", "message_id") and:
*
*    1. If the provided tuple matches an already existing one, this function
*       returns '1'
*
*    2. Otherwise, the entry is added (discarding, if needed, the oldest entry)
*       and this function returns '0'
*/
static uint8_t check_duplicates(uint8_t *src_mac_address, i1905_cmdu_t *c)
{
    mac_addr mac_address;
    uint8_t  i;

    if (CMDU_TYPE_TOPOLOGY_RESPONSE               == c->message_type ||
        CMDU_TYPE_LINK_METRIC_RESPONSE            == c->message_type ||
        CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE   == c->message_type ||
        CMDU_TYPE_HIGHER_LAYER_RESPONSE           == c->message_type ||
        CMDU_TYPE_INTERFACE_POWER_CHANGE_RESPONSE == c->message_type ||
        CMDU_TYPE_GENERIC_PHY_RESPONSE            == c->message_type ||
        CMDU_TYPE_AP_AUTOCONFIGURATION_WSC        == c->message_type ) {
        /* This is a "hack" until a better way to handle MIDs is found.
        *
        *  Let me explain.
        *
        *  According to the standard, each AL entity generates its monotonically
        *  increasing MIDs every time a new packet is sent.
        *  The only exception to this rule is when generating a "response". In
        *  these cases the same MID contained in the original query must be
        *  used.
        *
        *  Imagine we have two ALs that are started in different moments:
        *
        *         AL 1               AL 2
        *         ====               ====
        *    t=0  --- MID=1 -->
        *    t=1  --- MID=2 -->
        *    t=2  --- MID=3 -->      <-- MID=1 --
        *    t=3  --- MID=4 -->      <-- MID=2 --
        *    t=4  --- MID=5 -->      <-- MID=3 --
        *
        *  In "t=2", "AL 2" learns that, in the future, messages from "AL 1" with
        *  a "MID=3" should be discarded.
        *
        *  Now, imagine in "t=4" the message "AL 2" sends (with "MID=3") is a
        *  query that triggers a response from "AL 1" (which *must* have the
        *  same MID, ie., "MID=3").
        *
        *  HOWEVER, because of what "AL 2" learnt in "t=2", this response will
        *  be discarded!
        *
        *  In oder words... until the standard clarifies how MIDs should be
        *  generated to avoid this problem, we will just accept (and process)
        *  all response messages... even if they are duplicates.
        */
#ifndef MULTIAP
        return 0; /* TODO Make use of Message types also to reduce probable problem space */
#endif
    }

    /* For relayed CMDUs, use the AL MAC, otherwise use the ethernet src MAC. */
    maccpy(mac_address, src_mac_address);
    if (1 == c->relay_indicator) {
        uint16_t i;
        uint8_t *p;

        i = 0;
        while (NULL != (p = c->list_of_TLVs[i])) {
            if (TLV_TYPE_AL_MAC_ADDRESS == *p) {
                struct alMacAddressTypeTLV *t = (struct alMacAddressTypeTLV *)p;

                maccpy(mac_address, t->al_mac_address);
                break;
            }
            i++;
        }
    }

    /* Agent and controller may run in the same device but with different al mac,
    *  hence discard CMDUs whose AL MAC is our own (that means someone
    *  is retrasnmitting us back a message we originally created)
    */
    if (0 == maccmp(mac_address, DMalMacGet())) {
        log_i1905_d("Packet with src MAC as AL MAC is detected -> drop");
        return 1;
    }

    /* Find if the ("mac_address", "message_id") tuple is already present in the
    *  database
    */
    for (i=0; i<g_check_dup.total; i++) {
        uint8_t index;

        index = (g_check_dup.start + i) % MAX_DUPLICATES_LOG_ENTRIES;

        if (0 == maccmp(g_check_dup.mac_addresses[index],    mac_address) &&
            g_check_dup.message_ids[index] == c->message_id &&
            g_check_dup.message_type[index]  == c->message_type ) {
            /* The entry already exists! */
            if (c->message_type == CMDU_TYPE_AP_AUTOCONFIGURATION_WSC ) {
                return 0; /* by pass WSC messages */
            }
            return 1;
        }
    }

    /* This is a new entry, insert it into the cache and return "0" */
    if (g_check_dup.total < MAX_DUPLICATES_LOG_ENTRIES) {
        /* There is space for new entries */
        uint8_t index;

        index = (g_check_dup.start + g_check_dup.total) % MAX_DUPLICATES_LOG_ENTRIES;

        maccpy(g_check_dup.mac_addresses[index], mac_address);
        g_check_dup.message_ids[index]  = c->message_id;
        g_check_dup.message_type[index] = c->message_type;

        g_check_dup.total++;
    } else {
        /* We need to replace the oldest entry */
        maccpy(g_check_dup.mac_addresses[g_check_dup.start], mac_address);
        g_check_dup.message_ids[g_check_dup.start]  = c->message_id;
        g_check_dup.message_type[g_check_dup.start] = c->message_type;

        g_check_dup.start++;

        g_check_dup.start = g_check_dup.start % MAX_DUPLICATES_LOG_ENTRIES;
    }

    return 0;
}

/* According to "Section 7.6", if a received packet has the "relayed multicast"
*  bit set, after processing, we must forward it on all authenticated 1905
*  interfaces (except on the one where it was received).
*
*  This function checks if the provided 'c' structure has that "relayed
*  multicast" flag set and, if so, retransmits it on all local interfaces
*  (except for the one whose interface name matches 'receiving_interface_name') to
*  'destination iface name' and the same "message id" (MID) as the one contained
*  in the originally received 'c' structure.
*/
static void check_forwarding(char *receiving_interface_name, uint8_t *destination_mac_addr, i1905_cmdu_t *c)
{
    uint8_t i;

    if (c->relay_indicator) {
        char **ifs_names;
        uint8_t  ifs_nr;

        if (map_is_loopback_iface(receiving_interface_name)) {
            log_i1905_t("Do not relay packet from lo interface");
            return;
        }

        log_i1905_t("Relay multicast flag set. Forwarding...");

        ifs_names = PLATFORM_GET_LIST_OF_1905_INTERFACES(&ifs_nr);
        if (!ifs_names) {
            log_i1905_e("Could not get list of 1905 interfaces");
            return;
        }

        for (i = 0; i < ifs_nr; i++) {
            uint8_t authenticated;
            uint8_t power_state;

            i1905_interface_info_t *x;

            x = PLATFORM_GET_1905_INTERFACE_INFO(ifs_names[i]);

            if (NULL == x) {
                log_i1905_w("Could not retrieve info of interface %s", ifs_names[i]);
                authenticated = 0;
                power_state   = INTERFACE_POWER_STATE_OFF;
            }
            else {
                authenticated = x->is_secured;
                power_state   = x->power_state;
            }

            if ((0 == authenticated                                                                     ) ||
                ((power_state != INTERFACE_POWER_STATE_ON) && (power_state!= INTERFACE_POWER_STATE_SAVE)) ||
		(0 == strcmp(ifs_names[i], receiving_interface_name)                                    ) ||
                /* Forward packets only to interfaces other than lo */
                (map_is_loopback_iface(ifs_names[i]))) {
                /* Do not forward the message on this interface */
                log_i1905_t("Do not forward the message on this interface: %s",ifs_names[i]);
                if (NULL != x) {
                    PLATFORM_FREE_1905_INTERFACE_INFO(x);
                }
                continue;
            }

            if (NULL != x) {
                PLATFORM_FREE_1905_INTERFACE_INFO(x);
            }

            /* Retransmit message */
            log_i1905_t("--> %s (forwarding from %s to %s)", convert_1905_CMDU_type_to_string(c->message_type),
                        receiving_interface_name, ifs_names[i]);

            if (0 == forward1905RawPacket(ifs_names[i], c->message_id, destination_mac_addr, c, GET_SRC_MAC_FRM_STREAM)) {
                log_i1905_w("Could not retransmit 1905 message on interface %s", ifs_names[i]);
            }
        }
        PLATFORM_FREE_LIST_OF_1905_INTERFACES(ifs_names, ifs_nr);
    }
}

static void packet_cb(char *if_name, uint8_t *packet, uint16_t packet_len)
{
    struct ether_header    *eh = (struct ether_header*) packet;
    uint8_t                *dst_addr = eh->ether_dhost;
    uint8_t                *src_addr = eh->ether_shost;
    i1905_interface_info_t *x;
    uint16_t                ether_type;
    uint8_t                *ifmac;

    if (packet_len < sizeof(struct ethhdr)) {
        log_i1905_w("Received too short packet from %s, len %d", if_name, packet_len);
        return;
    }

    ether_type = htons(eh->ether_type);
    ifmac = DMinterfaceNameToMac(if_name);

    if (NULL == ifmac) {
        log_i1905_e("A packet was received on interface %s, which does not match any local interface", if_name);
        return;
    }

    x = PLATFORM_GET_1905_INTERFACE_INFO(if_name);
    if (NULL == x) {
        log_i1905_e("Could not retrieve info of interface %s", if_name);
        return;
    }

    if (0 == x->is_secured) {
        log_i1905_w("This interface (%s) is not secured. No packets should be received. Ignoring...", if_name);
        PLATFORM_FREE_1905_INTERFACE_INFO(x);
        return;
    }
    PLATFORM_FREE_1905_INTERFACE_INFO(x);

    log_i1905_t("New queue message arrived: packet captured on interface %s", if_name);
    log_i1905_t("    Dst address: %s", acu_mac_string(dst_addr));
    log_i1905_t("    Src address: %s", acu_mac_string(src_addr));
    log_i1905_t("    Ether type : 0x%04x", ether_type);

    /* packets captured from lo interface may not be destined to my AL MAC */
    if (maccmp(dst_addr, DMalMacGet()) && maccmp(dst_addr, g_mcast_mac_1905) && maccmp(dst_addr, g_mcast_mac_lldp)) {
        log_i1905_d("Packet not destined to my AL MAC");
        return;
    }

    switch(ether_type) {
        case ETHERTYPE_LLDP: {
            i1905_lldp_payload_t *payload;

            log_i1905_t("LLDP message received.");

            payload = parse_lldp_PAYLOAD_from_packet(/* remove eth header */ &packet[sizeof(struct ethhdr)]);

            if (NULL == payload) {
                log_i1905_w("Invalid bridge discovery message. Ignoring...");
            } else {
                if (PLATFORM_OS_LOG_LEVEL_TRACE()) {
                    log_i1905_t("LLDP message contents:");
                    visit_lldp_PAYLOAD_structure(payload, print_callback, PLATFORM_PRINTF, "");
                }

                processLlpdPayload(payload, ifmac);

                free_lldp_PAYLOAD_structure(payload);
            }
            break;
        }
        case ETHERTYPE_1905: {
            i1905_cmdu_t *c;
            log_i1905_t("CMDU message received. Reassembling...");

            c = reassemble_fragmented_cmdu(packet, packet_len);

            if (NULL == c) {
                /* This was just a fragment part of a big CMDU.
                *  The data has been internally cached, waiting for
                *  the rest of pieces.
                */
                break;
            }
            strncpy(c->interface_name, if_name, sizeof(c->interface_name) - 1);
            if (1 == check_duplicates(src_addr, c)) {
                log_i1905_d("Receiving on %s a CMDU which is a duplicate of a previous one (mid = 0x%x). Discarding...", if_name, c->message_id);
                free_1905_CMDU_structure(c);
                break;
            }
            /* It might be necessary to retransmit this
            *  message on the rest of interfaces (depending
            *  on the "relayed multicast" flag
            */
            check_forwarding(if_name, dst_addr, c);

            /* Send to upper layer */
            if (!g_cmdu_cb || false == g_cmdu_cb(c)) {
                free_1905_CMDU_structure(c);
            }
            break;
        }
        default: {
            log_i1905_w("Unknown ethertype 0x%04x!! Ignoring...", ether_type);
            break;
        }
    }
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
uint8_t start1905AL(mac_addr al_mac_address, uint8_t map_whole_network_flag,
                    UNUSED char *registrar_interface, i1905_interface_cb_t interface_cb,
                    al1905_cmdu_cb_t cmdu_cb)
{
    /* Initialize platform-specific code */
    if (0 == PLATFORM_INIT()) {
        log_i1905_e("Failed to initialize platform");
        return AL_ERROR_OS;
    }

    if (NULL == al_mac_address) {
        log_i1905_e("NULL AL MAC address not allowed");
        return AL_ERROR_INVALID_ARGUMENTS;
    }

    DMinit();
    DMalMacSet(al_mac_address);
    DMmapWholeNetworkSet(map_whole_network_flag);
    log_i1905_d("Starting AL entity (AL MAC = %s). Map whole network = %d...",
                acu_mac_string(al_mac_address),
                map_whole_network_flag);

    g_cmdu_cb = cmdu_cb;

    /* Must be after DMinit as call below adds interfaces */
    if (0 == PLATFORM_OS_INIT(interface_cb, packet_cb)) {
        log_i1905_e("Failed to initialize platform os");
        return AL_ERROR_OS;
    }

    return 0;
}

void stop1905AL(void)
{
    size_t i, j;

    g_cmdu_cb = NULL;

    /* Reset cmdu reassemble state (and free all fragments) */
    for (i = 0; i < MAX_MIDS_IN_FLIGHT; i++) {
        if (g_reassemble.mids_in_flight[i].in_use) {
            for (j = 0; j <= g_reassemble.mids_in_flight[i].last_fragment; j++) {
                free(g_reassemble.mids_in_flight[i].streams[j]);
            }
        }
    }
    memset(&g_reassemble, 0, sizeof(g_reassemble));

    /* Reset duplicate cmdu detection */
    memset(&g_check_dup, 0, sizeof(g_check_dup));

    DMfini();

    PLATFORM_OS_FINI();
}
