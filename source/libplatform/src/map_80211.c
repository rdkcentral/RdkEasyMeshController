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
#define IEEE80211_EID_SSID              0
#define IEEE80211_EID_SUPP_RATES        1
#define IEEE80211_EID_HT_CAP           45
#define IEEE80211_EID_SUPP_EXT_RATES   50
#define IEEE80211_EID_RRM_ENABLED_CAP  70
#define IEEE80211_EID_EXT_CAP         127
#define IEEE80211_EID_VHT_CAP         191
#define IEEE80211_EID_VENDOR_SPECIFIC 221
#define IEEE80211_EXTID_CAP           255

#define IEEE80211_EXTID_HE_CAP         35

#define IEEE80211_EID_HT_CAP_LEN              sizeof(ieee80211_ht_cap)
#define IEEE80211_EID_RRM_ENABLED_CAP_LEN     5
#define IEEE80211_EID_EXT_CAP_MIN_LEN         3
#define IEEE80211_EID_VHT_CAP_LEN             sizeof(ieee80211_vht_cap)
#define IEEE80211_EID_VENDOR_SPECIFIC_MIN_LEN 3
#define IEEE80211_EXTID_MIN_LEN               1

#define IEEE80211_EXTID_HE_CAP_MIN_LEN        sizeof(ieee80211_he_cap)
/* Fixed capabiltiy bits */
#define IEEE80211_CAP_RRM BIT(12)

/* RRM Enabled Capabilities IE */
/* Byte 1 */
#define IEEE80211_RRM_CAPS_BEACON_REQUEST_PASSIVE BIT(4)
#define IEEE80211_RRM_CAPS_BEACON_REQUEST_ACTIVE  BIT(5)

/* Ext cap */
/* Byte 3 */
#define IEEE80211_EXT_CAPS_BTM BIT(3)

/* HT Cap */
#define IEEE80211_HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET      BIT(1)
#define IEEE80211_HT_CAP_INFO_SHORT_GI20MHZ               BIT(5)
#define IEEE80211_HT_CAP_INFO_SHORT_GI40MHZ               BIT(6)

/* VHT Cap */
#define IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ          BIT(2)
#define IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ BIT(3)
#define IEEE80211_VHT_CAP_SHORT_GI_80                     BIT(5)
#define IEEE80211_VHT_CAP_SHORT_GI_160                    BIT(6)
#define IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE           BIT(11)
#define IEEE80211_VHT_CAP_MU_BEAMFORMER_CAPABLE           BIT(19)

/* HE Cap */
#define IEEE80211_HE_CAP_PHY_CAP_40MHZ_24G                BIT(1)
#define IEEE80211_HE_CAP_PHY_CAP_40MHZ_80MGHZ_5G_6G       BIT(2)
#define IEEE80211_HE_CAP_PHY_CAP_160MHZ_5G_6G             BIT(3)
#define IEEE80211_HE_CAP_PHY_CAP_8080MHZ_5G_6G            BIT(4)

#define IEEE80211_HE_CAP_PHY_CAP_FULL_BANDWIDTH_UL_MU_MIMO    BIT(6) /* PHY_CAP B22 - Byte 2 Bit 6 */
#define IEEE80211_HE_CAP_PHY_CAP_PARTIAL_BANDWIDTH_UL_MU_MIMO BIT(7) /* PHY_CAP B23 - Byte 2 Bit 7 */
#define IEEE80211_HE_CAP_PHY_CAP_SU_BEAMFORMER                BIT(7) /* PHY_CAP B31 - Byte 3 Bit 7 */
#define IEEE80211_HE_CAP_PHY_CAP_MU_BEAMFORMER                BIT(1) /* PHY_CAP B33 - Byte 4 Bit 1 */
#define IEEE80211_HE_CAP_PHY_CAP_PARTIAL_BANDWIDTH_DL_MU_MIMO BIT(6) /* PHY_CAP B54 - Byte 6 Bit 6 */

/* MAP IE */
#define WFA_OUI_BYTE_0                   0x50
#define WFA_OUI_BYTE_1                   0x6F
#define WFA_OUI_BYTE_2                   0x9A
#define WFA_VENDOR_IE_MIN_LEN            4
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
    uint8_t *he_cap;
    uint8_t *rrm_enabled_cap;
    uint8_t *ext_cap;
    uint8_t *vht_cap;
    uint8_t *map;
    uint8_t *mbo;

    uint8_t ssid_len;
    uint8_t rates_len;
    uint8_t ext_rates_len;
    uint8_t ht_cap_len;
    uint8_t rrm_enabled_cap_len;
    uint8_t ext_cap_len;
    uint8_t vht_cap_len;
    uint8_t he_cap_len;
    uint8_t map_len;
    uint8_t mbo_len;
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
    int bw = b >= 160 ? 3 : b >= 80 ? 2 : b >= 40 ? 1 : 0;

    switch(caps->supported_standard) {
        case STD_80211_ANACAX:
        case STD_80211_ACAX:
        case STD_80211_ANAX:
        case STD_80211_NAX:
        case STD_80211_AX:
            return pr_11ax[bw][ss];
        break;
        case STD_80211_ANAC:
        case STD_80211_AC:
            return caps->sgi_support ? pr_11ac_sgi[bw][ss] : pr_11ac[bw][ss];
        break;
        case STD_80211_AN:
        case STD_80211_N:
            bw = min(1, bw);
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
int map_80211_parse_assoc_body(map_sta_capability_t *caps, uint8_t *body, int body_len, int supported_freq, uint8_t *match_ssid, int match_ssid_len)
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

    /* Fill in capability */

    /* Caps from he/vht/he ie */
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
        caps->supported_standard = STD_80211_AX;
    } else if (he_cap) {
        if (supported_freq != IEEE80211_FREQUENCY_BAND_2_4_GHZ) {
            caps->supported_standard = (vht_cap && ht_cap)? STD_80211_ANACAX:
                                       (vht_cap)? STD_80211_ACAX:STD_80211_ANAX;
        } else {
           caps->supported_standard = STD_80211_NAX;
        }
    } else if (supported_freq != IEEE80211_FREQUENCY_BAND_2_4_GHZ && vht_cap) {
        caps->supported_standard = STD_80211_AC;
    } else if (ht_cap) {
        caps->supported_standard = STD_80211_N;
    } else if (supported_freq == IEEE80211_FREQUENCY_BAND_2_4_GHZ) {
        caps->supported_standard = is_erp ? STD_80211_G : STD_80211_B;
    } else {
        caps->supported_standard = STD_80211_A;
    }

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

    caps->valid = true;

    return 0;
}
