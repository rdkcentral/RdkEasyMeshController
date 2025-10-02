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

/* This file contains functions to parse 80211 frames.  It is based on
   code from hostapd (e.g ieee802_11_parse_elems)
*/
/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h> /* htons */

#define LOG_TAG "80211"

#include "map_80211.h"
#include "map_utils.h"
#include "map_data_model.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define min(a, b) (((a) < (b)) ? (a) : (b))

#ifndef BIT
#define BIT(x) (1 << (x))
#endif

/* Runtime check - compiler will optimize this... */
#define IS_BIG_ENDIAN() (htonl(1) == 1)

#define IEEE80211_IE_HDR_LEN            2

/* Fixed part of body size */
#define BODY_ASSOC_REQ_FIXED_SIZE       4
#define BODY_REASSOC_REQ_FIXED_SIZE    10

/* Fixed part of frame size */
#define IEEE80211_HDRLEN               24
#define FRAME_ASSOC_REQ_FIXED_SIZE     (BODY_ASSOC_REQ_FIXED_SIZE   + IEEE80211_HDRLEN)
#define FRAME_REASSOC_REQ_FIXED_SIZE   (BODY_REASSOC_REQ_FIXED_SIZE + IEEE80211_HDRLEN)

/* Assoc/reassoc frame types */
#define IEEE80211_FC_TYPE_MGMT         0
#define IEEE80211_FC_STYPE_ASSOC_REQ   0
#define IEEE80211_FC_STYPE_REASSOC_REQ 2
#define IEEE80211_FC_GET_TYPE(fc)      (((fc) & 0x000c) >> 2)
#define IEEE80211_FC_GET_STYPE(fc)     (((fc) & 0x00f0) >> 4)


/* Information element Id's */
#define IEEE80211_EID_SSID                          0
#define IEEE80211_EID_SUPP_RATES                    1
#define IEEE80211_EID_HT_CAP                       45
#define IEEE80211_EID_SUPP_EXT_RATES               50
#define IEEE80211_EID_RRM_ENABLED_CAP              70
#define IEEE80211_EID_EXT_CAP                     127
#define IEEE80211_EID_VHT_CAP                     191
#define IEEE80211_EID_VENDOR_SPECIFIC             221
#define IEEE80211_EID_FRAGMENT                    242
#define IEEE80211_EXTID_CAP                       255

#define IEEE80211_EXTID_HE_CAP                     35
#define IEEE80211_EXTID_MULTI_LINK                107
#define IEEE80211_EXTID_EHT_CAP                   108

#define IEEE80211_MULTI_LINK_SEID_PER_STA_PROFILE   0
#define IEEE80211_MULTI_LINK_SEID_FRAGMENT        254


/* Minimum length of IEs */
#define IEEE80211_EID_HT_CAP_LEN                          sizeof(ieee80211_ht_cap)
#define IEEE80211_EID_RRM_ENABLED_CAP_LEN                 5
#define IEEE80211_EID_EXT_CAP_MIN_LEN                     3
#define IEEE80211_EID_VHT_CAP_LEN                         sizeof(ieee80211_vht_cap)
#define IEEE80211_EID_VENDOR_SPECIFIC_MIN_LEN             3
#define IEEE80211_EXTID_MIN_LEN                           1

#define IEEE80211_EXTID_HE_CAP_MIN_LEN                    sizeof(ieee80211_he_cap)
#define IEEE80211_EXTID_MULTI_LINK_CTRL_LEN               2
#define IEEE80211_EXTID_MULTI_LINK_MIN_LEN                (IEEE80211_EXTID_MULTI_LINK_CTRL_LEN + 1) /* Control + info.len */
#define IEEE80211_EXTID_EHT_CAP_MIN_LEN                   sizeof(ieee80211_eht_cap)

#define IEEE80211_MULTI_LINK_SEID_PER_STA_PROFILE_MIN_LEN (IEEE80211_EXTID_MULTI_LINK_CTRL_LEN + 1) /* Control + info.len */


/* Bit fields for various IEs */
/* Fixed capabiltiy bits */
#define IEEE80211_CAP_RRM                                     BIT(12)

/* RRM Enabled Capabilities IE */
/* Byte 1 */
#define IEEE80211_RRM_CAPS_BEACON_REQUEST_PASSIVE             BIT(4)
#define IEEE80211_RRM_CAPS_BEACON_REQUEST_ACTIVE              BIT(5)

/* Ext cap */
/* Byte 3 */
#define IEEE80211_EXT_CAPS_BTM                                BIT(3)

/* HT Cap */
#define IEEE80211_HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET          BIT(1)
#define IEEE80211_HT_CAP_INFO_SHORT_GI20MHZ                   BIT(5)
#define IEEE80211_HT_CAP_INFO_SHORT_GI40MHZ                   BIT(6)

/* VHT Cap */
#define IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ              BIT(2)
#define IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ     BIT(3)
#define IEEE80211_VHT_CAP_SHORT_GI_80                         BIT(5)
#define IEEE80211_VHT_CAP_SHORT_GI_160                        BIT(6)
#define IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE               BIT(11)
#define IEEE80211_VHT_CAP_MU_BEAMFORMER_CAPABLE               BIT(19)

/* HE Cap */
#define IEEE80211_HE_CAP_PHY_CAP_40MHZ_24G                    BIT(1)
#define IEEE80211_HE_CAP_PHY_CAP_40MHZ_80MGHZ_5G_6G           BIT(2)
#define IEEE80211_HE_CAP_PHY_CAP_160MHZ_5G_6G                 BIT(3)
#define IEEE80211_HE_CAP_PHY_CAP_8080MHZ_5G_6G                BIT(4)

#define IEEE80211_HE_CAP_PHY_CAP_FULL_BANDWIDTH_UL_MU_MIMO    BIT(6) /* PHY_CAP B22 - Byte 2 Bit 6 */
#define IEEE80211_HE_CAP_PHY_CAP_PARTIAL_BANDWIDTH_UL_MU_MIMO BIT(7) /* PHY_CAP B23 - Byte 2 Bit 7 */
#define IEEE80211_HE_CAP_PHY_CAP_SU_BEAMFORMER                BIT(7) /* PHY_CAP B31 - Byte 3 Bit 7 */
#define IEEE80211_HE_CAP_PHY_CAP_MU_BEAMFORMER                BIT(1) /* PHY_CAP B33 - Byte 4 Bit 1 */
#define IEEE80211_HE_CAP_PHY_CAP_PARTIAL_BANDWIDTH_DL_MU_MIMO BIT(6) /* PHY_CAP B54 - Byte 6 Bit 6 */

/* MULTI LINK IE */
#define IEEE80211_MULTI_LINK_CTRL_TYPE_MASK                   (BIT(2) | BIT(1) | BIT(0))
#define IEEE80211_MULTI_LINK_CTRL_TYPE_BASIC                  0
#define IEEE80211_MULTI_LINK_CTRL_LINK_ID_PRESENT             BIT(4)
#define IEEE80211_MULTI_LINK_CTRL_BSS_PARAM_CH_COUNT_PRESENT  BIT(5)
#define IEEE80211_MULTI_LINK_CTRL_MSD_INFO_PRESENT            BIT(6)
#define IEEE80211_MULTI_LINK_CTRL_EML_CAP_PRESENT             BIT(7)
#define IEEE80211_MULTI_LINK_CTRL_MLD_CAP_PRESENT             BIT(8)

#define IEEE80211_MULTI_LINK_EML_CAP_EMLSR                    BIT(1)
#define IEEE80211_MULTI_LINK_EML_CAP_EMLMR                    BIT(7)

#define IEEE80211_MULTI_LINK_MLD_CAP_MAX_SYM_LINKS_MASK       (BIT(3) | BIT(2) | BIT(1) | BIT(0))

#define IEEE80211_MULTI_LINK_STA_PROFILE_CTRL_COMPLETE        BIT(4)
#define IEEE80211_MULTI_LINK_STA_PROFILE_CTRL_MAC_PRESENT     BIT(5)
#define IEEE80211_MULTI_LINK_STA_PROFILE_CTRL_NSTR_LP_PRESENT BIT(9)

/* WFA Vendor specific IEs */
#define WFA_OUI_BYTE_0                   0x50
#define WFA_OUI_BYTE_1                   0x6F
#define WFA_OUI_BYTE_2                   0x9A
#define WFA_VENDOR_IE_MIN_LEN            4

/* MAP IE */
#define WFA_EID_MAP                      27
#define WFA_SUB_EID_MAP_EXTENSION        6
#define WFA_SUB_EID_MAP_EXTENSION_LEN    1
#define MAP_EXTENSION_BACKHAUL_STA_FLAG  0x80

/* MBO IE */
#define WFA_EID_MBO                      22

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
typedef struct ieee802_11_elems {
    uint8_t *ssid;
    uint8_t *rates;
    uint8_t *ext_rates;
    uint8_t *ht_cap;
    uint8_t *rrm_enabled_cap;
    uint8_t *ext_cap;
    uint8_t *vht_cap;
    uint8_t *he_cap;
    uint8_t *eht_cap;
    uint8_t *map;
    uint8_t *mbo;
    uint8_t *multi_link;
    uint8_t *multi_link_defrag;
    uint8_t *multi_link_sta_profile;

    uint8_t  ssid_len;
    uint8_t  rates_len;
    uint8_t  ext_rates_len;
    uint8_t  ht_cap_len;
    uint8_t  rrm_enabled_cap_len;
    uint8_t  ext_cap_len;
    uint8_t  vht_cap_len;
    uint8_t  he_cap_len;
    uint8_t  eht_cap_len;
    uint8_t  map_len;
    uint8_t  mbo_len;
    uint8_t  multi_link_len;
    uint16_t multi_link_left; /* length of assoc ies after end of multi link event (could contain fragments) */
    uint16_t multi_link_defrag_len;
    uint16_t multi_link_sta_profile_len;
} ieee802_11_elems;

typedef struct {
    uint16_t ht_cap_info;
    uint8_t  a_mpdu_params;
    uint8_t  supported_mcs_set[16];
    uint16_t ht_extended_cap;
    uint32_t tx_bf_capability_info;
    uint8_t  asel_cap;
} STRUCT_PACKED ieee80211_ht_cap;

typedef struct {
    uint32_t vht_cap_info;
    struct {
        uint16_t rx_map;
        uint16_t rx_highest;
        uint16_t tx_map;
        uint16_t tx_highest;
    } vht_supported_mcs_set;
} STRUCT_PACKED ieee80211_vht_cap;

typedef struct {
    uint8_t mac_cap_info[6];
    uint8_t phy_cap_info[11];
    /* Followed by 1,2 or 3 sets of 4 bytes containing supported MCS and NSS set
       for 80, 160 and 80+80Mhz
       For now, we will use only the first -> 4 bytes below

       NOTE: if you change this, also adapt IEEE80211_EXTID_HE_CAP_MIN_LEN above
    */
    uint16_t rx_mcs_map_80;
    uint16_t tx_mcs_map_80;
    //uint16_t rx_mcs_map_160;
    //uint16_t tx_mcs_map_160;
    //uint16_t rx_mcs_map_8080;
    //uint16_t tx_mcs_map_8080;
} STRUCT_PACKED ieee80211_he_cap;

typedef struct {
    uint8_t mac_cap_info[2];
    uint8_t phy_cap_info[9];

    /* TODO: mcs map */
} STRUCT_PACKED ieee80211_eht_cap;

typedef struct {
    uint16_t ctrl;
    struct {
        uint8_t  len;
        mac_addr mld_mac;
    } info;

    /* Sub elements follow after skipping common len after "ctrl" */
} STRUCT_PACKED ieee80211_multi_link;

typedef struct {
    uint16_t ctrl;
    struct {
        uint8_t len;
        mac_addr aff_mac;
    } info;

    /* Capabilities and tags follow */
} STRUCT_PACKED ieee80211_multi_link_sta_profile;

/*#######################################################################
#                       ENDIAN CONVERSION                               #
########################################################################*/
/* Could be done by just including endian.h but that is not portable
   (see mess in hostapd common.h)
*/
static inline uint16_t map_swap_16(uint16_t v)
{
    return ((v & 0xff) << 8) | (v >> 8);
}

static inline uint32_t map_swap_32(uint32_t v)
{
    return ((v & 0xff) << 24) | ((v & 0xff00) << 8) |
           ((v & 0xff0000) >> 8) | (v >> 24);
}

static inline uint16_t map_le_to_host16(uint16_t v)
{
    return IS_BIG_ENDIAN() ? map_swap_16(v) : v;
}

static inline uint32_t map_le_to_host32(uint32_t v)
{
    return IS_BIG_ENDIAN() ? map_swap_32(v) : v;
}

/*#######################################################################
#                       IE PARSING                                      #
########################################################################*/
static void free_elems(ieee802_11_elems *elems)
{
    SFREE(elems->multi_link_defrag);
}

static int parse_ies(ieee802_11_elems *elems, uint8_t *ies, int len)
{
    uint8_t *pos  = ies;
    int      left = len;
    int      ok = 1;

    memset(elems, 0, sizeof(ieee802_11_elems));

    while (left >= 2) {
        uint8_t id   = *pos++;
        uint8_t elen = *pos++;
        left -= 2;

        if (elen > left) {
            // FRV: do not complain, attempt to use so far found IE's
            // log_lib_e("parse_ies: frame failed (id=%d elen=%d left=%d)", id, elen, left);
            // ok = 0;
            break;
        }

        switch(id) {
            case IEEE80211_EID_SSID:
                if (NULL == elems->ssid) {
                    elems->ssid = pos;
                    elems->ssid_len = elen;
                }
            break;
            case IEEE80211_EID_SUPP_RATES:
                if (NULL == elems->rates) {
                    elems->rates = pos;
                    elems->rates_len = elen;
                }
            break;
            case IEEE80211_EID_SUPP_EXT_RATES:
                if (NULL == elems->ext_rates) {
                    elems->ext_rates = pos;
                    elems->ext_rates_len = elen;
                }
            break;
            case IEEE80211_EID_HT_CAP:
                if (NULL == elems->ht_cap && elen == IEEE80211_EID_HT_CAP_LEN) {
                    elems->ht_cap = pos;
                    elems->ht_cap_len = elen;
                }
            break;
            case IEEE80211_EID_RRM_ENABLED_CAP:
                if (NULL == elems->rrm_enabled_cap && elen == IEEE80211_EID_RRM_ENABLED_CAP_LEN) {
                    elems->rrm_enabled_cap = pos;
                    elems->rrm_enabled_cap_len = elen;
                }
            break;
            case IEEE80211_EID_EXT_CAP:
                if (NULL == elems->ext_cap && elen >= IEEE80211_EID_EXT_CAP_MIN_LEN) {
                    elems->ext_cap = pos;
                    elems->ext_cap_len = elen;
                }
            break;
            case IEEE80211_EID_VHT_CAP:
                if (NULL == elems->vht_cap && elen == IEEE80211_EID_VHT_CAP_LEN) {
                    elems->vht_cap = pos;
                    elems->vht_cap_len = elen;
                }
            break;
            case IEEE80211_EXTID_CAP:
                if (elen >= IEEE80211_EXTID_MIN_LEN) {
                    uint8_t ext_id      = pos[0];
                    uint8_t ext_id_elen = elen - 1;
                    switch (ext_id) {
                        case IEEE80211_EXTID_HE_CAP:
                            if (NULL == elems->he_cap && ext_id_elen >= IEEE80211_EXTID_HE_CAP_MIN_LEN) {
                                elems->he_cap = &pos[1];
                                elems->he_cap_len = ext_id_elen;
                            }
                        break;
                        case IEEE80211_EXTID_EHT_CAP:
                            if (NULL == elems->eht_cap && ext_id_elen >= IEEE80211_EXTID_EHT_CAP_MIN_LEN) {
                                elems->eht_cap = &pos[1];
                                elems->eht_cap_len = ext_id_elen;
                            }
                        break;
                        case IEEE80211_EXTID_MULTI_LINK:
                            if (NULL == elems->multi_link && ext_id_elen >= IEEE80211_EXTID_MULTI_LINK_MIN_LEN) {
                                elems->multi_link = &pos[1];
                                elems->multi_link_len = ext_id_elen;
                                elems->multi_link_left = left - elen;
                            }
                        default:
                        break;
                    }
                }
            break;
            case IEEE80211_EID_VENDOR_SPECIFIC:
                /* Check on WFA OUI */
                if (elen >= IEEE80211_EID_VENDOR_SPECIFIC_MIN_LEN &&
                    pos[0] == WFA_OUI_BYTE_0 &&
                    pos[1] == WFA_OUI_BYTE_1 &&
                    pos[2] == WFA_OUI_BYTE_2) {
                    if (NULL == elems->map && elen >= WFA_VENDOR_IE_MIN_LEN) {
                        if (pos[3] == WFA_EID_MAP) {
                            elems->map = pos;
                            elems->map_len = elen;
                        } else if (pos[3] == WFA_EID_MBO) {
                            elems->mbo = pos;
                            elems->mbo_len = elen;
                        }
                    }
                }
            default:
            break;
        }

        left -= elen;
        pos  += elen;
    }

    if (left) {
        // FRV: do not complain, attempt to use so found IE's
        // log_lib_e("parse assoc frame failed (left=%d)", left);
        // ok = 0;  Attempt to use correct IE
    }

    return ok;
}

/* Defrag IE.  Note: left = length of ies after this ie */
static uint8_t *defrag_ie(uint8_t *ie, uint8_t len, uint16_t left, bool is_ext, uint16_t *defrag_len)
{
    uint8_t  max_len = is_ext ? 254 : 255;
    uint8_t *pos = ie;
    uint8_t *defrag_ie;
    uint8_t *defrag_pos;
    uint8_t  elen;

    /*  Check if IE is fragmented and can be de-fragmented */
    if (len < max_len || left < 2 || ie[len] != IEEE80211_EID_FRAGMENT) {
        return NULL;
    }

    /* Allocate length of IE + remainder of IES (defragmented IE can never be bigger) */
    if (!(defrag_ie = defrag_pos = malloc(len + left))) {
        return NULL;
    }

    /* Copy first fragment */
    memcpy(defrag_pos, pos, len);
    pos        += len;
    defrag_pos += len;

    /* Copy next fragments */
    do {
        elen = pos[1];

        pos += 2;
        left -= 2;

        if (elen > left) {
            break;
        }

        memcpy(defrag_pos, pos, elen);
        pos        += elen;
        defrag_pos += elen;
        left       -= elen;

        /* Continue if this fragment has max size and another is following */
    } while (left >= 2 && elen == 255 && pos[0] == IEEE80211_EID_FRAGMENT);

    *defrag_len = defrag_pos - defrag_ie;

    return defrag_ie;
}

static void parse_multi_link_ie(ieee802_11_elems *elems, mac_addr aff_sta_mac)
{
    /* This function parses the multi link ie and searches in the sub elements for the aff_sta_mac

       If that is found, some IE are replaced.

       NOTE:
       - the multi_link IE can be fragmented and the station profile inside the multi_link IE can be fragmented again
       - to test fragmented IE, dummy vendor TLV can be added in function wlc_mlo_filter_ie_for_assocreq (wlc_mlo.c)
    */

    int                   ok = 1;
    uint8_t              *pos;
    uint16_t              left;
    uint8_t               info_len;
    ieee80211_multi_link *ml;

    /* Defragment */
    elems->multi_link_defrag = defrag_ie(elems->multi_link, elems->multi_link_len, elems->multi_link_left, true, &elems->multi_link_defrag_len);

    pos  = elems->multi_link_defrag ? elems->multi_link_defrag     : elems->multi_link;
    left = elems->multi_link_defrag ? elems->multi_link_defrag_len : elems->multi_link_len;

    /* Find Start of first sub element */
    ml       = (ieee80211_multi_link *)pos;
    info_len = IEEE80211_EXTID_MULTI_LINK_CTRL_LEN + ml->info.len;

    if (left < info_len) {
        return;
    }

    /* Only parse the basic type */
    if ((map_le_to_host16(ml->ctrl) & IEEE80211_MULTI_LINK_CTRL_TYPE_MASK) != IEEE80211_MULTI_LINK_CTRL_TYPE_BASIC) {
        return;
    }

    pos += info_len;
    left -= info_len;

    while (left >= 2) {
        ieee80211_multi_link_sta_profile *sta_profile;
        ieee802_11_elems                  sp_elems;
        uint8_t                           sub_id   = *pos++;
        uint16_t                          sub_elen = *pos++;

        left -= 2;
        if (sub_elen > left) {
            break;
        }

        /* Only parse Sta profile sub element */
        if (sub_id != IEEE80211_MULTI_LINK_SEID_PER_STA_PROFILE) {
            goto next;
        }

        if (sub_elen < IEEE80211_MULTI_LINK_SEID_PER_STA_PROFILE_MIN_LEN) {
            goto next;
        }

        sta_profile = (ieee80211_multi_link_sta_profile *)pos;
        info_len    = IEEE80211_EXTID_MULTI_LINK_CTRL_LEN + sta_profile->info.len;

        if (sub_elen < info_len) {
            /* Invalid */
            break;
        }

        /* MAC must be present */
        if (!(map_le_to_host16(sta_profile->ctrl) & IEEE80211_MULTI_LINK_STA_PROFILE_CTRL_MAC_PRESENT)) {
            break;
        }

        /* Check if it is for affiliated MAC we are looking for */
        if (maccmp(sta_profile->info.aff_mac, aff_sta_mac)) {
            goto next;
        }

        /* Check if sta profile is fragmented
           Defragmentation is "in place", destroying original multi link IE

           Which is ok because we break out of the parsing anyhow
        */
        if (elems->multi_link_defrag) {
            uint8_t *frag_pos  = pos;  /* pos still points at the start of the defragmented IE */
            uint8_t  frag_len  = sub_elen;
            uint8_t  frag_left = left;

            while (frag_len == 255 && left >= (frag_len + 2) && frag_pos[frag_len] == IEEE80211_MULTI_LINK_SEID_FRAGMENT) {
               /* Skip fragment */
               frag_pos  += frag_len;
               frag_left -= frag_len;

               frag_len   = frag_pos[1];
               frag_left -= 2;

               /* Move remainder 2 bytes back */
               memmove(frag_pos, frag_pos + 2, frag_left);
               frag_left -= frag_len;

               sub_elen += frag_len;
            }
        }

        /* Store pointer */
        elems->multi_link_sta_profile = (uint8_t *)sta_profile;
        elems->multi_link_sta_profile_len = sub_elen;

        /* Parse elements again (skip 2 byte fixed capabilities) */
        info_len += 2;
        if (sub_elen < info_len) {
            /* Invalid */
            break;
        }

        if ((ok = parse_ies(&sp_elems, pos + info_len, sub_elen - info_len))) {
            /* Replace ies */
            /* TODO: 80211 spec contains special inheritance rules -> to be checked when we have more MLO clients */
            #define REPLACE_IE(ie) if (sp_elems.ie) {elems->ie = sp_elems.ie; elems->ie##_len = sp_elems.ie##_len;}
            REPLACE_IE(rates)
            REPLACE_IE(ext_rates)
            REPLACE_IE(ht_cap)
            REPLACE_IE(vht_cap)
            REPLACE_IE(he_cap)
            REPLACE_IE(eht_cap)
        }
        break;

next:
        left -= sub_elen;
        pos  += sub_elen;
    }
}

static int parse_ies_check_ssid(ieee802_11_elems *elems, uint8_t *ies, int len, uint8_t *match_ssid, int match_ssid_len)
{
    int ok = parse_ies(elems, ies, len);

    if (ok) {
        if (NULL == elems->ssid || elems->ssid_len != match_ssid_len || memcmp(elems->ssid, match_ssid, match_ssid_len)) {
            ok = 0;
        }
    }

    return ok;
}

static int parse_ies_check_ssid_offset(ieee802_11_elems *elems, uint8_t *body, int body_len, int offset, uint8_t *match_ssid, int match_ssid_len)
{
    return (body_len > offset) &&
           parse_ies_check_ssid(elems, body + offset, body_len - offset, match_ssid, match_ssid_len);
}

static int vht_he_mcs_map_to_ss(uint16_t map)
{
    int i;

    /* Search for first group of 2 bits not equal to 0x3 */
    for (i = 7; i > 0; i--) {
        uint16_t mask = 0x3 << (i << 1);
        if ((map & mask) != mask) {
            break;
        }
    }

    return i + 1;
}

static int ht_mcs_set_to_ss(uint8_t *mcs_set)
{
    int i;

    for (i = 3; i > 0; i--) {
        if (mcs_set[i]) {
            break;
        }
    }

    return i + 1;
}

static bool has_ofdm(uint8_t *rates, int len)
{
    int i;

    for (i=0; i<len; i++) {
        /* Rates are in steps of 500kB, first bit is basic rate flag */
        if ((rates[i] & 0x7f) > 22) {
            return true;
        }
    }

    return false;
}

/*#######################################################################
#                       MAX PHY RATE                                    #
########################################################################*/
/* based on fhc_802_11_caps.c from air-steer-ng */

/* 11AX has 3 SGI options - use 0.8 us */
                                                       /*    1 SS,    2 SS,    3 SS,    4 SS */
/* TODO: get real 11BE table... */
static uint32_t pr_11be     [/* bw */ 5][/* ss */ 4] = {{  143400,  286800,  430100,  573500}, /*  20MHz - MCS 11 */
                                                        {  286800,  573500,  860300, 1147100}, /*  40MHz - MCS 11 */
                                                        {  600500, 1201000, 1801500, 2402000}, /*  80MHz - MCS 11 */
                                                        { 1201000, 2402000, 3602900, 4803900}, /* 160MHz - MCS 11 */
                                                        { 2402000, 4804000, 7205800, 9607800}, /* 320MHz - MCS 11 */
                                                       };

static uint32_t pr_11ax     [/* bw */ 4][/* ss */ 4] = {{  143400,  286800,  430100,  573500}, /*  20MHz - MCS 11 */
                                                        {  286800,  573500,  860300, 1147100}, /*  40MHz - MCS 11 */
                                                        {  600500, 1201000, 1801500, 2402000}, /*  80MHz - MCS 11 */
                                                        { 1201000, 2402000, 3602900, 4803900}, /* 160MHz - MCS 11 */
                                                       };


static uint32_t pr_11ac     [/* bw */ 4][/* ss */ 4] = {{   78000,  156000,  260000,  312000}, /*  20MHz - MCS 8 or 9 */
                                                        {  180000,  360000,  540000,  720000}, /*  40MHz - MCS 9 */
                                                        {  390000,  780000, 1170000, 1560000}, /*  80MHz - MCS 9 */
                                                        {  780000, 1560000, 2106000, 3120000}  /* 160MHz - MCS 8 or 9 */
                                                       };

static uint32_t pr_11ac_sgi [/* bw */ 4][/* ss */ 4] = {{   86700,  173300,  288900,  346700}, /*  20MHz - MCS 8 or 9 */
                                                        {  200000,  400000,  600000,  800000}, /*  40MHz - MCS 9 */
                                                        {  433300,  866700, 1300000, 1733300}, /*  80MHz - MCS 9 */
                                                        {  866700, 1733300, 2340000, 3466700}  /* 160MHz - MCS 8 or 9 */
                                                       };


static uint32_t pr_11n      [/* bw */ 2][/* ss */ 4] = {{   65000,  130000,  195000,  260000}, /*  20MHz - MCS 7, 15, 23, 31 */
                                                        {  135000,  270000,  405000,  540000}  /*  40MHz - MCS 7, 15, 23, 31 */
                                                       };

static uint32_t pr_11n_sgi  [/* bw */ 2][/* ss */ 4] = {{   72200,  144000,  216700,  288900}, /*  20MHz - MCS 7, 15, 23, 31 */
                                                        {  150000,  300000,  450000,  600000}  /*  40MHz - MCS 7, 15, 23, 31 */
                                                       };


uint32_t map_get_max_phy_rate(map_sta_capability_t *caps)
{
    /* Limit to 4 SS */
    int ss = min(4, caps->max_tx_spatial_streams) - 1;
    int b  = caps->max_bandwidth;
    int bw = b >= 320 ? 4 : b >= 160 ? 3 : b >= 80 ? 2 : b >= 40 ? 1 : 0;

    switch(caps->supported_standard) {
        case STD_80211_BE:
            bw = min(bw, 4);
            return pr_11be[bw][ss];
        break;
        case STD_80211_ANACAX:
        case STD_80211_ACAX:
        case STD_80211_ANAX:
        case STD_80211_NAX:
        case STD_80211_AX:
            bw = min(bw, 3);
            return pr_11ax[bw][ss];
        break;
        case STD_80211_ANAC:
        case STD_80211_AC:
            bw = min(bw, 3);
            return caps->sgi_support ? pr_11ac_sgi[bw][ss] : pr_11ac[bw][ss];
        break;
        case STD_80211_AN:
        case STD_80211_N:
            bw = min(bw, 1);
            return caps->sgi_support ? pr_11n_sgi[bw][ss] : pr_11n[bw][ss];
        break;
        case STD_80211_A:
        case STD_80211_G:
            return 54000;
        break;
        case STD_80211_B:
            return 11000;
        break;
        default:
            return 11000;
        break;
    }

    return 0;
}

/*#######################################################################
#                       PARSE ASSOC BODY                                #
########################################################################*/
int map_80211_parse_assoc_body(map_sta_capability_t *caps, uint8_t *body, int body_len, int supported_freq,
                               uint8_t *match_ssid, int match_ssid_len, mac_addr aff_sta_mac)
{
    ieee802_11_elems  elems     = {0};
    uint16_t          fixed_cap = 0;

    memset(caps, 0, sizeof(map_sta_capability_t));

    /* There are 5 options:
       - contains the complete body and is an assoc
       - contains the complete body and is a reassoc
       - contains the IE only (BRCM)
       - contains the complete frame and is an assoc  (NG-182051 - Arcadyan interop)
       - contains the complete frame and is a reassoc (NG-182051 - Arcadyan interop)
    */

    do {
        /* Body */
        if (parse_ies_check_ssid_offset(&elems, body, body_len, BODY_ASSOC_REQ_FIXED_SIZE, match_ssid, match_ssid_len)) {
            log_lib_d("assoc request body");
            fixed_cap = map_le_to_host16(*(uint16_t*)body);
            break;
        }
        if (parse_ies_check_ssid_offset(&elems, body, body_len, BODY_REASSOC_REQ_FIXED_SIZE, match_ssid, match_ssid_len)) {
            log_lib_d("reassoc request body");
            fixed_cap = map_le_to_host16(*(uint16_t*)body);
            break;
        }

        /* IE only */
        if (parse_ies_check_ssid_offset(&elems, body, body_len, 0, match_ssid, match_ssid_len)) {
            log_lib_d("body contains IE only");
            break;
        }

        /* Frame */
        if (body_len >= IEEE80211_HDRLEN) {
            uint16_t frame_control = map_le_to_host16(*(uint16_t*)body);
            int      type          = IEEE80211_FC_GET_TYPE(frame_control);
            int      sub_type      = IEEE80211_FC_GET_STYPE(frame_control);
            if (type == IEEE80211_FC_TYPE_MGMT && sub_type == IEEE80211_FC_STYPE_ASSOC_REQ &&
                parse_ies_check_ssid_offset(&elems, body, body_len, FRAME_ASSOC_REQ_FIXED_SIZE, match_ssid, match_ssid_len)) {
                log_lib_d("assoc request frame");
                fixed_cap = map_le_to_host16(*(uint16_t*)(body + IEEE80211_HDRLEN));
                break;
            }
            if (type == IEEE80211_FC_TYPE_MGMT && sub_type == IEEE80211_FC_STYPE_REASSOC_REQ &&
                parse_ies_check_ssid_offset(&elems, body, body_len, FRAME_REASSOC_REQ_FIXED_SIZE, match_ssid, match_ssid_len)) {
                log_lib_d("reassoc request frame");
                fixed_cap = map_le_to_host16(*(uint16_t*)(body + IEEE80211_HDRLEN));
                break;
            }
        }

        log_lib_e("could not parse body");

        return -1;
    } while(0);

    /* For affiliated STA: parse nested multi link IE */
    if (aff_sta_mac) {
        if (elems.multi_link) {
            parse_multi_link_ie(&elems, aff_sta_mac);
        } else {
            log_lib_w("parsing ies for affiliated STA but multi_link IE was not found");
        }
    }


    /* Fill in capability */

    /* Caps from he/vht/he ie */
    ieee80211_eht_cap *eht_cap      = (ieee80211_eht_cap *)elems.eht_cap;
    ieee80211_he_cap  *he_cap       = (ieee80211_he_cap  *)elems.he_cap;
    ieee80211_vht_cap *vht_cap      = (ieee80211_vht_cap *)elems.vht_cap;
    ieee80211_ht_cap  *ht_cap       = (ieee80211_ht_cap  *)elems.ht_cap;
    bool               is_erp       = (elems.rates     && has_ofdm(elems.rates, elems.rates_len)) ||
                                      (elems.ext_rates && has_ofdm(elems.ext_rates, elems.ext_rates_len));  /* ERP = Extended Rate Phy - 11B -> 11G */
    uint32_t           vht_cap_info = vht_cap ? map_le_to_host32(vht_cap->vht_cap_info) : 0;
    uint16_t           ht_cap_info  = ht_cap  ? map_le_to_host16(ht_cap->ht_cap_info)   : 0;


    /* Defaults (can be changed later) */
    caps->max_tx_spatial_streams = 1;
    caps->max_rx_spatial_streams = 1;
    caps->max_bandwidth          = 20;

    /* Standard */
    if (supported_freq == IEEE80211_FREQUENCY_BAND_6_GHZ) {
        caps->supported_standard = eht_cap ? STD_80211_BE : STD_80211_AX;
    } else if (supported_freq == IEEE80211_FREQUENCY_BAND_5_GHZ) {
        caps->supported_standard = (he_cap && vht_cap && ht_cap) ? STD_80211_ANACAX :
                                   (he_cap && vht_cap) ? STD_80211_ACAX :
                                   (he_cap && ht_cap) ? STD_80211_ANAX :
                                   (vht_cap) ? STD_80211_AC :
                                   (ht_cap) ? STD_80211_N : STD_80211_A;
    } else { /* 2.4ghz */
        caps->supported_standard = he_cap ? STD_80211_NAX :
                                   ht_cap ? STD_80211_N :
                                   is_erp ? STD_80211_G : STD_80211_B;
    }

    caps->eht_support = eht_cap ? 1 : 0;
    caps->he_support  = he_cap  ? 1 : 0;
    caps->vht_support = vht_cap ? 1 : 0;
    caps->ht_support  = ht_cap  ? 1 : 0;
    caps->erp_support = is_erp  ? 1 : 0;

    /* HE, VHT (5G only) and HT CAP - see dapi_fill_bssinfo_from_ie in hostapd */
    if (he_cap) {
        if (supported_freq != IEEE80211_FREQUENCY_BAND_2_4_GHZ) {
            caps->max_bandwidth = (he_cap->phy_cap_info[0] & (IEEE80211_HE_CAP_PHY_CAP_160MHZ_5G_6G | IEEE80211_HE_CAP_PHY_CAP_8080MHZ_5G_6G)) ? 160 :
                                  (he_cap->phy_cap_info[0] & IEEE80211_HE_CAP_PHY_CAP_40MHZ_80MGHZ_5G_6G) ? 80 : 20;   /* 80 vs 40 not possible??? */
        } else {
            caps->max_bandwidth = (he_cap->phy_cap_info[0] & IEEE80211_HE_CAP_PHY_CAP_40MHZ_24G) ? 40 : 20;
        }
        caps->max_tx_spatial_streams = vht_he_mcs_map_to_ss(map_le_to_host16(he_cap->tx_mcs_map_80));
        caps->max_rx_spatial_streams = vht_he_mcs_map_to_ss(map_le_to_host16(he_cap->rx_mcs_map_80));
    } else if (supported_freq != IEEE80211_FREQUENCY_BAND_2_4_GHZ && vht_cap) {
        caps->max_bandwidth          = vht_cap_info & (IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ | IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ) ? 160 : 80;
        caps->max_tx_spatial_streams = vht_he_mcs_map_to_ss(map_le_to_host16(vht_cap->vht_supported_mcs_set.tx_map));
        caps->max_rx_spatial_streams = vht_he_mcs_map_to_ss(map_le_to_host16(vht_cap->vht_supported_mcs_set.rx_map));
    } else if (ht_cap) {
        caps->max_bandwidth          = ht_cap_info & IEEE80211_HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET ? 40 : 20;
        caps->max_tx_spatial_streams = ht_mcs_set_to_ss(ht_cap->supported_mcs_set);  /* ?? - actually gives rx set */
        caps->max_rx_spatial_streams = ht_mcs_set_to_ss(ht_cap->supported_mcs_set);
    }

    /* TODO: parse eht_cap - for now just overrule the bandwith */
    if (supported_freq == IEEE80211_FREQUENCY_BAND_6_GHZ && eht_cap) {
        caps->max_bandwidth = 320;
    }

    /* SGI from HE, VHT and HT */
    if (he_cap) {
        /* 11ax sgi field must be marked as False */
        caps->sgi_support = false;
    } else if (supported_freq != IEEE80211_FREQUENCY_BAND_2_4_GHZ && vht_cap) {
        caps->sgi_support = vht_cap_info & (IEEE80211_VHT_CAP_SHORT_GI_80 | IEEE80211_VHT_CAP_SHORT_GI_160) ? 1 : 0;
    } else if (ht_cap) {
        caps->sgi_support = ht_cap_info & (IEEE80211_HT_CAP_INFO_SHORT_GI20MHZ | IEEE80211_HT_CAP_INFO_SHORT_GI40MHZ) ? 1 : 0;
    }

    if (ht_cap) {
        caps->ht_caps.max_supported_rx_streams = ht_mcs_set_to_ss(ht_cap->supported_mcs_set);
        caps->ht_caps.max_supported_tx_streams = ht_mcs_set_to_ss(ht_cap->supported_mcs_set); /* ?? - actually gives rx set */
        caps->ht_caps.gi_support_20mhz = ht_cap_info & IEEE80211_HT_CAP_INFO_SHORT_GI20MHZ ? 1 : 0;
        caps->ht_caps.gi_support_40mhz = ht_cap_info & IEEE80211_HT_CAP_INFO_SHORT_GI40MHZ ? 1 : 0;
        caps->ht_caps.ht_support_40mhz = ht_cap_info & IEEE80211_HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET;
    }
    if (supported_freq != IEEE80211_FREQUENCY_BAND_2_4_GHZ && vht_cap) {
        caps->vht_caps.supported_tx_mcs = vht_cap->vht_supported_mcs_set.tx_map; /* put as LE */
        caps->vht_caps.supported_rx_mcs = vht_cap->vht_supported_mcs_set.rx_map; /* put as LE */
        caps->vht_caps.max_supported_tx_streams = vht_he_mcs_map_to_ss(map_le_to_host16(vht_cap->vht_supported_mcs_set.tx_map));
        caps->vht_caps.max_supported_rx_streams = vht_he_mcs_map_to_ss(map_le_to_host16(vht_cap->vht_supported_mcs_set.rx_map));
        caps->vht_caps.gi_support_80mhz = (vht_cap_info & IEEE80211_VHT_CAP_SHORT_GI_80) ? 1 : 0;
        caps->vht_caps.gi_support_160mhz = (vht_cap_info & IEEE80211_VHT_CAP_SHORT_GI_160) ? 1 : 0;
        caps->vht_caps.support_80_80_mhz = (vht_cap_info & IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ) ? 1 : 0;
        caps->vht_caps.support_160mhz = (vht_cap_info & IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ) ? 1 : 0;
        caps->vht_caps.su_beamformer_capable = (vht_cap_info & IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE) ? 1 : 0;
        caps->vht_caps.mu_beamformer_capable = (vht_cap_info & IEEE80211_VHT_CAP_MU_BEAMFORMER_CAPABLE) ? 1 : 0;
    }
    if (he_cap) {
        /* mcs maps size is fixed length for now as ieee80211_he_cap struct currently only has the first two rx/tx mcs fields */
        caps->he_caps.supported_mcs_length = 4;
        caps->he_caps.supported_tx_rx_mcs[0] = he_cap->rx_mcs_map_80; /* put as LE */
        caps->he_caps.supported_tx_rx_mcs[1] = he_cap->tx_mcs_map_80; /* put as LE */
        caps->he_caps.max_supported_tx_streams = vht_he_mcs_map_to_ss(map_le_to_host16(he_cap->tx_mcs_map_80));
        caps->he_caps.max_supported_rx_streams = vht_he_mcs_map_to_ss(map_le_to_host16(he_cap->rx_mcs_map_80));
        if (supported_freq != IEEE80211_FREQUENCY_BAND_2_4_GHZ) {
            caps->he_caps.support_80_80_mhz = (he_cap->phy_cap_info[0] & IEEE80211_HE_CAP_PHY_CAP_8080MHZ_5G_6G) ? 1 : 0;
            caps->he_caps.support_160mhz = (he_cap->phy_cap_info[0] & IEEE80211_HE_CAP_PHY_CAP_160MHZ_5G_6G) ? 1 : 0;
        } else {
            caps->he_caps.support_80_80_mhz = 0;
            caps->he_caps.support_160mhz = 0;
        }
        caps->he_caps.su_beamformer_capable = (IEEE80211_HE_CAP_PHY_CAP_SU_BEAMFORMER & he_cap->phy_cap_info[3]) ? 1 : 0;
        caps->he_caps.mu_beamformer_capable = (IEEE80211_HE_CAP_PHY_CAP_MU_BEAMFORMER & he_cap->phy_cap_info[4]) ? 1 : 0;
        caps->he_caps.ul_mimo_capable = (IEEE80211_HE_CAP_PHY_CAP_FULL_BANDWIDTH_UL_MU_MIMO & he_cap->phy_cap_info[2]) ? 1 : 0;
        caps->he_caps.ul_mimo_ofdma_capable = (IEEE80211_HE_CAP_PHY_CAP_PARTIAL_BANDWIDTH_UL_MU_MIMO & he_cap->phy_cap_info[2]) ? 1 : 0;
        caps->he_caps.dl_mimo_ofdma_capable = (IEEE80211_HE_CAP_PHY_CAP_PARTIAL_BANDWIDTH_DL_MU_MIMO & he_cap->phy_cap_info[6]) ? 1 : 0;
        /* UL/DL OFDMA is mandatory in 11ax, however it may not be implemented in pre-final 11ax implementations */
        caps->he_caps.ul_ofdma_capable = 1;
        caps->he_caps.dl_ofdma_capable = 1;
    }

    /* 11K */
    /* Support when either mentioned in fixed cap or the RRM IE is present */
    caps->dot11k_support = fixed_cap & IEEE80211_CAP_RRM ? 1 : 0;
    if (elems.rrm_enabled_cap) {
        caps->dot11k_support = 1;
        caps->dot11k_brp_support = elems.rrm_enabled_cap[0] & IEEE80211_RRM_CAPS_BEACON_REQUEST_PASSIVE ? 1 : 0;
        caps->dot11k_bra_support = elems.rrm_enabled_cap[0] & IEEE80211_RRM_CAPS_BEACON_REQUEST_ACTIVE  ? 1 : 0;
    }

    /* 11V */
    if (elems.ext_cap) {
        caps->dot11v_btm_support = elems.ext_cap[2] & IEEE80211_EXT_CAPS_BTM ? 1 : 0;
    }

    /* MAP */
    if (elems.map) {
        /* Check for MAP extension sub element */
        if (elems.map_len >= WFA_VENDOR_IE_MIN_LEN + IEEE80211_IE_HDR_LEN + WFA_SUB_EID_MAP_EXTENSION_LEN) {
            if (elems.map[4]==WFA_SUB_EID_MAP_EXTENSION && elems.map[5]==WFA_SUB_EID_MAP_EXTENSION_LEN) {
                caps->backhaul_sta = elems.map[6] & MAP_EXTENSION_BACKHAUL_STA_FLAG ? 1 : 0;
            }
        }
    }

    /* MBO */
    if (elems.mbo) {
        caps->mbo_support = 1;
    }

    /* Max phy rate */
    caps->max_phy_rate = map_get_max_phy_rate(caps);

    /* MLD Modes */
    if (elems.multi_link) {
        /* - EMLSR and  EMLR: EML_CAP field from the MLD common info.
           - STR and NSTR: MLD_CAP field from the MLD common info + sta profile control field
        */

        /* Common */
        ieee80211_multi_link *ml      = (ieee80211_multi_link *)elems.multi_link;
        uint16_t              ctrl    = map_le_to_host16(ml->ctrl);
        uint8_t              *pos     = elems.multi_link + sizeof(ieee80211_multi_link); /* = After MLD MAC */
        uint8_t              *end     = elems.multi_link + IEEE80211_EXTID_MULTI_LINK_CTRL_LEN + ml->info.len;
        uint16_t              eml_cap = 0;
        uint16_t              mld_cap = 0;

        /* Length check */
        if (end > (elems.multi_link + elems.multi_link_len)) {
            goto skip_mld_modes;
        }

        /* Expect basic type */
        if ((ctrl & IEEE80211_MULTI_LINK_CTRL_TYPE_MASK) != IEEE80211_MULTI_LINK_CTRL_TYPE_BASIC) {
            goto skip_mld_modes;
        }

        /* Bits set in the ctrl field determine the locaction of eml and mld cap */
        if (ctrl & IEEE80211_MULTI_LINK_CTRL_LINK_ID_PRESENT) {
            pos++; /* 1 byte - should not be present according to hostapd */
        }
        if (ctrl & IEEE80211_MULTI_LINK_CTRL_BSS_PARAM_CH_COUNT_PRESENT) {
            pos++; /* 1 byte - should not be present according to hostapd */
        }
        if (ctrl & IEEE80211_MULTI_LINK_CTRL_MSD_INFO_PRESENT) {
            pos += 2; /* 2 bytes - should not be present according to hostapd */
        }
        if (ctrl & IEEE80211_MULTI_LINK_CTRL_EML_CAP_PRESENT) {
            eml_cap = (pos[1] << 8) + pos[0]; /* Little endian... */
            pos += 2;
        }
        if (ctrl & IEEE80211_MULTI_LINK_CTRL_MLD_CAP_PRESENT) {
            mld_cap = (pos[1] << 8) + pos[0]; /* Little endian... */
            pos += 2;
        }
        /* Check that we are still in the control field */
        if (pos > end) {
            goto skip_mld_modes;
        }

        /* Fill in supported mld modes */
        caps->mld_modes.emlsr = eml_cap & IEEE80211_MULTI_LINK_EML_CAP_EMLSR;
        caps->mld_modes.emlmr = eml_cap & IEEE80211_MULTI_LINK_EML_CAP_EMLMR;
        caps->mld_modes.str   = mld_cap & IEEE80211_MULTI_LINK_MLD_CAP_MAX_SYM_LINKS_MASK;

        /* For STR/NSTR: also check sta profile control */
        if (caps->mld_modes.str && elems.multi_link_sta_profile) {
            ieee80211_multi_link_sta_profile *sp = (ieee80211_multi_link_sta_profile *)elems.multi_link_sta_profile;
            uint16_t sta_ctrl                    = map_le_to_host16(sp->ctrl);

            caps->mld_modes.nstr = sta_ctrl & IEEE80211_MULTI_LINK_STA_PROFILE_CTRL_NSTR_LP_PRESENT;
            caps->mld_modes.str = !caps->mld_modes.nstr;
        }

skip_mld_modes:
        ;
    }

    caps->valid = true;

    free_elems(&elems);

    return 0;
}
