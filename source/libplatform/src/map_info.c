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

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "map_info.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define OP_CLASS_TABLE_LEN ARRAY_SIZE(g_wifi_op_class_table)

#define MAX_CHANNEL_SET 60

#define CHAN_2G_BEGIN      1
#define CHAN_2G_END        14
#define CHAN_5G_BEGIN      36
#define CHAN_5G_END        177
#define CHAN_5G_LOW_BEGIN  CHAN_5G_BEGIN
#define CHAN_5G_LOW_END    64
#define CHAN_5G_HIGH_BEGIN 100
#define CHAN_5G_HIGH_END   CHAN_5G_END
#define CHAN_6G_BEGIN      1
#define CHAN_6G_END        233
#define CHAN_PSC_BEGIN     5
#define CHAN_PSC_END       229
#define CHAN_PSC_DELTA     16

#define OP_CLASS_2G_BEGIN            81
#define OP_CLASS_2G_END              84
#define OP_CLASS_5G_BEGIN            115
#define OP_CLASS_5G_END              130
#define OP_CLASS_5G_LOW_BEGIN        OP_CLASS_5G_BEGIN
#define OP_CLASS_5G_LOW_END          120
#define OP_CLASS_5G_HIGH_BEGIN       121
#define OP_CLASS_5G_HIGH_END         OP_CLASS_5G_END
#define OP_CLASS_6G_BEGIN            131
#define OP_CLASS_6G_END              137
#define OP_CLASS_20MHZ_5G_LOW_BEGIN  115
#define OP_CLASS_20MHZ_5G_LOW_END    120
#define OP_CLASS_20MHZ_5G_HIGH_BEGIN 121
#define OP_CLASS_20MHZ_5G_HIGH_END   127

#define OP_CLASS_MIN                 OP_CLASS_2G_BEGIN
#define OP_CLASS_MAX                 OP_CLASS_6G_END

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
typedef struct {
    uint8_t ch[MAX_CHANNEL_SET];
    uint8_t length;
} wifi_channel_set_t;

typedef struct _wifi_op_class_table {
    uint8_t            op_class;
    wifi_channel_set_t set;
    uint8_t            ch_freq;
    uint16_t           bw;
    bool               center_channel;
    uint8_t            ext_channel;
    map_channel_set_t  map_ch_set;
} wifi_op_class_t;

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
/* NOTE: All channels in this table are control channels. */
static wifi_op_class_t g_wifi_op_class_table[] = {
    { 81, {{   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13},                13}, IEEE80211_FREQUENCY_BAND_2_4_GHZ,    20, false, MAP_EXT_CHANNEL_NONE,  {0}},
    { 82, {{  14},                                                                             1}, IEEE80211_FREQUENCY_BAND_2_4_GHZ,    20, false, MAP_EXT_CHANNEL_NONE,  {0}},
    { 83, {{   1,   2,   3,   4,   5,   6,   7,   8,   9},                                     9}, IEEE80211_FREQUENCY_BAND_2_4_GHZ,    40, false, MAP_EXT_CHANNEL_ABOVE, {0}},
    { 84, {{   5,   6,   7,   8,   9,  10,  11,  12,  13},                                     9}, IEEE80211_FREQUENCY_BAND_2_4_GHZ,    40, false, MAP_EXT_CHANNEL_BELOW, {0}},
    {115, {{  36, 40, 44, 48},                                                                 4}, IEEE80211_FREQUENCY_BAND_5_GHZ,      20, false, MAP_EXT_CHANNEL_NONE,  {0}},
    {116, {{  36, 44},                                                                         2}, IEEE80211_FREQUENCY_BAND_5_GHZ,      40, false, MAP_EXT_CHANNEL_ABOVE, {0}},
    {117, {{  40, 48},                                                                         2}, IEEE80211_FREQUENCY_BAND_5_GHZ,      40, false, MAP_EXT_CHANNEL_BELOW, {0}},
    {118, {{  52,  56,  60,  64},                                                              4}, IEEE80211_FREQUENCY_BAND_5_GHZ,      20, false, MAP_EXT_CHANNEL_NONE,  {0}},
    {119, {{  52,  60},                                                                        2}, IEEE80211_FREQUENCY_BAND_5_GHZ,      40, false, MAP_EXT_CHANNEL_ABOVE, {0}},
    {120, {{  56,  64},                                                                        2}, IEEE80211_FREQUENCY_BAND_5_GHZ,      40, false, MAP_EXT_CHANNEL_BELOW, {0}},
    {121, {{ 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144},                     12}, IEEE80211_FREQUENCY_BAND_5_GHZ,      20, false, MAP_EXT_CHANNEL_NONE,  {0}},
    {122, {{ 100, 108, 116, 124, 132, 140},                                                    6}, IEEE80211_FREQUENCY_BAND_5_GHZ,      40, false, MAP_EXT_CHANNEL_ABOVE, {0}},
    {123, {{ 104, 112, 120, 128, 136, 144},                                                    6}, IEEE80211_FREQUENCY_BAND_5_GHZ,      40, false, MAP_EXT_CHANNEL_BELOW, {0}},
    {124, {{ 149, 153, 157, 161},                                                              4}, IEEE80211_FREQUENCY_BAND_5_GHZ,      20, false, MAP_EXT_CHANNEL_NONE,  {0}},
    {125, {{ 149, 153, 157, 161, 165, 169, 173, 177},                                          8}, IEEE80211_FREQUENCY_BAND_5_GHZ,      20, false, MAP_EXT_CHANNEL_NONE,  {0}},
    {126, {{ 149, 157, 165, 173},                                                              4}, IEEE80211_FREQUENCY_BAND_5_GHZ,      40, false, MAP_EXT_CHANNEL_ABOVE, {0}},
    {127, {{ 153, 161, 169, 177},                                                              4}, IEEE80211_FREQUENCY_BAND_5_GHZ,      40, false, MAP_EXT_CHANNEL_BELOW, {0}},
    {128, {{  36,  40,  44,  48,  52,  56,  60,  64, 100, 104, 108, 112, 116, 120, 124, 128,
              132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173, 177},                    28}, IEEE80211_FREQUENCY_BAND_5_GHZ,      80,  true, MAP_EXT_CHANNEL_NONE,  {0}},
    {129, {{  36,  40,  44,  48,  52,  56,  60,  64, 100, 104, 108, 112, 116, 120, 124, 128,
             149, 153, 157, 161, 165, 169, 173, 177},                                         24}, IEEE80211_FREQUENCY_BAND_5_GHZ,     160,  true, MAP_EXT_CHANNEL_NONE,  {0}},
    {130, {{  36,  40,  44,  48,  52,  56,  60,  64, 100, 104, 108, 112, 116, 120, 124, 128,
             132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173, 177},                     28}, IEEE80211_FREQUENCY_BAND_5_GHZ, 80+80+1,  true, MAP_EXT_CHANNEL_NONE,  {0}},
    {131, {{   1,   5,   9,  13,  17,  21,  25,  29,  33,  37,  41,  45,  49,  53,  57,  61,
              65,  69,  73,  77,  81,  85,  89,  93,  97, 101, 105, 109, 113, 117, 121, 125,
             129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185, 189,
             193, 197, 201, 205, 209, 213, 217, 221, 225, 229, 233},                          59}, IEEE80211_FREQUENCY_BAND_6_GHZ,      20, false, MAP_EXT_CHANNEL_NONE,  {0}},
    {132, {{   1,   5,   9,  13,  17,  21,  25,  29,  33,  37,  41,  45,  49,  53,  57,  61,
              65,  69,  73,  77,  81,  85,  89,  93,  97, 101, 105, 109, 113, 117, 121, 125,
             129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185, 189,
             193, 197, 201, 205, 209, 213, 217, 221, 225, 229},                               58}, IEEE80211_FREQUENCY_BAND_6_GHZ,      40,  true, MAP_EXT_CHANNEL_NONE,  {0}},
    {133, {{   1,   5,   9,  13,  17,  21,  25,  29,  33,  37,  41,  45,  49,  53,  57,  61,
              65,  69,  73,  77,  81,  85,  89,  93,  97, 101, 105, 109, 113, 117, 121, 125,
             129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185, 189,
             193, 197, 201, 205, 209, 213, 217, 221},                                         56}, IEEE80211_FREQUENCY_BAND_6_GHZ,      80,  true, MAP_EXT_CHANNEL_NONE,  {0}},
    {134, {{   1,   5,   9,  13,  17,  21,  25,  29,  33,  37,  41,  45,  49,  53,  57,  61,
              65,  69,  73,  77,  81,  85,  89,  93,  97, 101, 105, 109, 113, 117, 121, 125,
             129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185, 189,
             193, 197, 201, 205, 209, 213, 217, 221},                                         56}, IEEE80211_FREQUENCY_BAND_6_GHZ,     160,  true, MAP_EXT_CHANNEL_NONE,  {0}},
    {135, {{   1,   5,   9,  13,  17,  21,  25,  29,  33,  37,  41,  45,  49,  53,  57,  61,
              65,  69,  73,  77,  81,  85,  89,  93,  97, 101, 105, 109, 113, 117, 121, 125,
             129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185, 189,
             193, 197, 201, 205, 209, 213, 217, 221},                                         56}, IEEE80211_FREQUENCY_BAND_6_GHZ, 80+80+1,  true, MAP_EXT_CHANNEL_NONE,  {0}},
    {136, {{ 2},                                                                               1}, IEEE80211_FREQUENCY_BAND_6_GHZ,      20, false, MAP_EXT_CHANNEL_NONE,  {0}},
    {137, {{   1,   5,   9,  13,  17,  21,  25,  29,  33,  37,  41,  45,  49,  53,  57,  61,
              65,  69,  73,  77,  81,  85,  89,  93,  97, 101, 105, 109, 113, 117, 121, 125,
             129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185, 189,
             193, 197, 201, 205, 209, 213, 217, 221},                                         56}, IEEE80211_FREQUENCY_BAND_6_GHZ,     320,  true, MAP_EXT_CHANNEL_NONE,  {0}},

/* Not relevant operating classes:
    {85, {{ 1,2,3,4,5,6,7,8,9,10,11,12,13}, 13}, 7, 6},
    {86, {{ 1,2,3,4,5,6,7,8,9,10,11,12,13}, 13}, 7, 12},
    {87, {{ 1,2,3,4,5,6,7,8,9,10,11,12,13}, 13}, 7, 24},
    {94, {{ 133,137}, 2}, 4, 20},
    {95, {{ 132,134,136,138}, 4}, 4, 10},
    {96, {{ 131,132,133,134,135,136,137,138}, 8}, 4, 5},
    {101, {{ 21,25}, 2}, 5, 20},
    {102, {{ 11,13,15,17,19}, 5}, 5, 40},
    {103, {{ 1,2,3,4,5,6,7,8,9,10}, 10,}, 5, 5},
    {104, {{ 184,192}, 2}, 6, 40},
    {105, {{ 188,196}, 2}, 6, 40},
    {106, {{ 191,195}, 2}, 6, 20},
    {107, {{ 189,191,193,195,197}, 5}, 6, 10},
    {108, {{ 188,189,190,191,192,193,194,195,196,197}, 10}, 6, 5},
    {109, {{ 184,188,192,196}, 4}, 6, 20},
    {110, {{ 183,184,185,186,187,188,189}, 7}, 6, 10},
    {111, {{ 182,183,184,185,186,187,188,189}, 8}, 6, 5},
    {112, {{ 8, 12, 16}, 3}, 2, 20},
    {113, {{ 7,8,9,10,11}, 5}, 2, 5},
    {114, {{ 6,7,8,9,10,11}, 6}, 2, 5},
    {180, {{ 1,2,3,4,5,6}, 6}, 3, 2160}
*/
};

static wifi_op_class_t   *g_wifi_op_class_ptrs[OP_CLASS_MAX - OP_CLASS_MIN + 1];
static map_channel_set_t  g_2G_ctl_channel_set;
static map_channel_set_t  g_5G_ctl_channel_set;
static map_channel_set_t  g_5G_low_ctl_channel_set;
static map_channel_set_t  g_5G_high_ctl_channel_set;
static map_channel_set_t  g_5G_weatherband_channel_set;
static map_channel_set_t  g_6G_ctl_channel_set;
static map_channel_set_t  g_6G_psc_channel_set;

/*#######################################################################
#                       INIT                                            #
########################################################################*/
static void get_ctl_channel_set(map_channel_set_t *ch_set, uint8_t from_op_class, uint8_t to_op_class)
{
    size_t i;

    map_cs_unset_all(ch_set);

    for (i = 0; i < OP_CLASS_TABLE_LEN; i++) {
        wifi_op_class_t *t = &g_wifi_op_class_table[i];

        if ((t->op_class >= from_op_class) && (t->op_class <= to_op_class) && (t->bw == 20)) {
            map_cs_or(ch_set, &t->map_ch_set);
        }
    }
}

/* Prepare some frequently used data */
int map_info_init(void)
{
    size_t i, j;

    /* Op_class pointers */
    for (i = 0; i < OP_CLASS_TABLE_LEN; i++) {
        wifi_op_class_t *t = &g_wifi_op_class_table[i];

        g_wifi_op_class_ptrs[t->op_class - OP_CLASS_MIN] = t;
    }

    /* Op_class channel sets */
    for (i = 0; i < OP_CLASS_TABLE_LEN; i++) {
        wifi_op_class_t *t = &g_wifi_op_class_table[i];

        map_cs_unset_all(&t->map_ch_set);

        for (j = 0; j < t->set.length; j++) {
            map_cs_set(&t->map_ch_set, t->set.ch[j]);
        }
    }

    /* CTL channel sets */
    get_ctl_channel_set(&g_2G_ctl_channel_set,      OP_CLASS_2G_BEGIN,      OP_CLASS_2G_END);
    get_ctl_channel_set(&g_5G_ctl_channel_set,      OP_CLASS_5G_BEGIN,      OP_CLASS_5G_END);
    get_ctl_channel_set(&g_5G_low_ctl_channel_set,  OP_CLASS_5G_LOW_BEGIN,  OP_CLASS_5G_LOW_END);
    get_ctl_channel_set(&g_5G_high_ctl_channel_set, OP_CLASS_5G_HIGH_BEGIN, OP_CLASS_5G_HIGH_END);
    get_ctl_channel_set(&g_6G_ctl_channel_set,      OP_CLASS_6G_BEGIN,      OP_CLASS_6G_END);

    /* Weatherband channel set */
    map_cs_unset_all(&g_5G_weatherband_channel_set);
    map_cs_set(&g_5G_weatherband_channel_set, 120);
    map_cs_set(&g_5G_weatherband_channel_set, 124);
    map_cs_set(&g_5G_weatherband_channel_set, 128);

    /* PSC channel set */
    map_cs_unset_all(&g_6G_psc_channel_set);

    for (i = CHAN_PSC_BEGIN; i <= CHAN_PSC_END; i += CHAN_PSC_DELTA) {
        map_cs_set(&g_6G_psc_channel_set, i);
    }

    return 0;
}

void map_info_fini(void)
{
}

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
static wifi_op_class_t* get_op_class_ptr(uint8_t op_class)
{
    if (op_class < OP_CLASS_MIN || op_class > OP_CLASS_MAX) {
        return NULL;
    }

    return g_wifi_op_class_ptrs[op_class - OP_CLASS_MIN];
}

static int get_channel_index(wifi_op_class_t *op_class, uint8_t channel)
{
    int i;
    for (i = 0; i < op_class->set.length; i++) {
        if (op_class->set.ch[i] == channel)
            return i;
    }
    return -1;
}

static uint8_t get_primary_channel_for_midfreq(uint8_t channel, uint16_t bw)
{
    if (bw == 40) {
        return channel - 2;
    } else if (bw == 80) {
        return channel - 6;
    } else if (bw == 160) {
        return channel- 14;
    } else if (bw == 320) {
        return channel - 30;
    } else {
        return channel;
    }
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
int8_t map_get_frequency_type(uint8_t op_class, map_channel_set_t *channels,
                              uint8_t *freq_type, uint16_t *band_type_5G)
{
    wifi_op_class_t *p_op_class = get_op_class_ptr(op_class);

    if (!p_op_class || !freq_type || !band_type_5G) {
        return -1;
    }

    if (p_op_class->ch_freq == IEEE80211_FREQUENCY_BAND_2_4_GHZ) {
        *freq_type = IEEE80211_FREQUENCY_BAND_2_4_GHZ;
    } else if (p_op_class->ch_freq == IEEE80211_FREQUENCY_BAND_5_GHZ) {
        *freq_type = IEEE80211_FREQUENCY_BAND_5_GHZ;

        if (op_class >= OP_CLASS_20MHZ_5G_LOW_BEGIN && op_class <= OP_CLASS_20MHZ_5G_LOW_END) {
            *band_type_5G |= MAP_M2_BSS_RADIO5GL;
        } else if (op_class >= OP_CLASS_20MHZ_5G_HIGH_BEGIN && op_class <= OP_CLASS_20MHZ_5G_HIGH_END) {
            *band_type_5G |= MAP_M2_BSS_RADIO5GU;
        } else if (op_class >= 128  && op_class <= 130) {
            uint8_t upper_band = 0;
            uint8_t lower_band = 0;
            uint8_t channel;

            map_cs_foreach(channels, channel) {
                if (channel < 100) {
                    lower_band++;
                } else {
                    upper_band++;
                }
            }

            if (op_class != 129) {
                if (lower_band < 2) {
                    *band_type_5G |= MAP_M2_BSS_RADIO5GL;
                }
                if (upper_band < 4) {
                    *band_type_5G |= MAP_M2_BSS_RADIO5GU;
                }
            } else {
                if (lower_band == 0) {
                    *band_type_5G |= MAP_M2_BSS_RADIO5GL;
                } else {
                    *band_type_5G |= MAP_M2_BSS_RADIO5GU;
                }
            }
        }
    } else if (p_op_class->ch_freq == IEEE80211_FREQUENCY_BAND_6_GHZ){
        *freq_type = IEEE80211_FREQUENCY_BAND_6_GHZ;
    } else {
        return -1;
    }

    return 0;
}

uint8_t map_get_op_class(uint8_t channel, uint16_t bw, uint8_t ch_freq)
{
    size_t i;

    /* Return first operating class that matches bw and includes channel  */
    for (i = 0; i < OP_CLASS_TABLE_LEN; i++) {
        wifi_op_class_t *t = &g_wifi_op_class_table[i];

        if (((ch_freq == IEEE80211_FREQUENCY_BAND_UNKNOWN) || (t->ch_freq == ch_freq)) &&
            (t->bw == bw) && (map_cs_is_set(&t->map_ch_set, channel))) {
            return t->op_class;
        }
    }

    return 0;
}

uint8_t map_get_op_class_20MHz(uint8_t channel, uint8_t ch_freq)
{
    return map_get_op_class(channel, 20, ch_freq);
}

bool map_is_5g_low_op_class(uint8_t op_class)
{
    return op_class >= OP_CLASS_20MHZ_5G_LOW_BEGIN && op_class <= OP_CLASS_20MHZ_5G_LOW_END;
}

bool map_is_5g_high_op_class(uint8_t op_class)
{
    return op_class >= OP_CLASS_20MHZ_5G_HIGH_BEGIN && op_class <= OP_CLASS_20MHZ_5G_HIGH_END;
}

int map_get_center_channel(uint8_t op_class, uint8_t ctl_channel, uint8_t *center_channel)
{
    wifi_op_class_t *p_op_class = get_op_class_ptr(op_class);
    int channel_index, set_no, position;
    uint16_t bw;
    uint8_t primary_channel;

    /* Only for center channel operating classes */
    if (!p_op_class || !p_op_class->center_channel ||
        (channel_index = get_channel_index(p_op_class, ctl_channel)) < 0) {
        return -1;
    }

    bw = p_op_class->bw;

    if (bw == 40) {
        set_no           = channel_index / 2;
        position         = set_no * 2;
        primary_channel  = p_op_class->set.ch[position];
        *center_channel  = primary_channel + 2;
    } else if (bw == 80) {
        set_no           = channel_index / 4;
        position         = set_no * 4;
        primary_channel  = p_op_class->set.ch[position];
        *center_channel  = primary_channel + 6;
    } else if (bw == 160) {
        set_no           = channel_index / 8;
        position         = set_no * 8;
        primary_channel  = p_op_class->set.ch[position];
        *center_channel  = primary_channel + 14;
    } else if (bw == 320) {
        set_no           = channel_index / 16;
        position         = set_no * 16;
        primary_channel  = p_op_class->set.ch[position];
        *center_channel  = primary_channel + 30;
    } else {
        /* Should not get here... */
        return -1;
    }

    return 0;
}

int map_get_first_ctl_channel(uint8_t op_class, uint8_t center_channel, uint8_t *ctl_channel)
{
    wifi_op_class_t *p_op_class = get_op_class_ptr(op_class);

    /* Only for center channel operating classes */
    if (!map_is_channel_in_op_class(op_class, center_channel) ||
        !p_op_class || !p_op_class->center_channel) {
        return -1;
    }

    *ctl_channel = get_primary_channel_for_midfreq(center_channel, p_op_class->bw);

    return 0;
}

int map_get_ext_channel_type(uint8_t op_class)
{
    wifi_op_class_t *p_op_class = get_op_class_ptr(op_class);

    return p_op_class ? p_op_class->ext_channel : MAP_EXT_CHANNEL_NONE;
}

/*
 * get all subband channels of a given channel/op_class combo
 * for 20MHz: single channel
 * for 40MHz: primary channel + secondary channel
 * for 80MHz + 160MHz: all 20MHz channels a 80/160MHz channel exists of
 */
int map_get_subband_channel_range(uint8_t op_class, uint8_t channel, uint8_t *from, uint8_t *to)
{
    wifi_op_class_t *p_op_class = get_op_class_ptr(op_class);
    uint16_t bw;
    uint8_t  sub_channels, set_no, position;

    if (!p_op_class) {
        return -1;
    }

    bw = p_op_class->bw;

    if (p_op_class->center_channel) {
        int channel_index = get_channel_index(p_op_class, channel);

        if (channel_index <  0) {
            return -1;
        }

        /* op_classes with 'Channel center frequency index' set (bw=80MHz/160MHz/320MHz or 11ax op_class )*/
        sub_channels = bw / 20;

        set_no   = channel_index / sub_channels;
        position = set_no * sub_channels;
        *from    = p_op_class->set.ch[position];
        *to      = p_op_class->set.ch[position + sub_channels - 1];
    } else if (bw == 20) {
        *from    = channel;
        *to      = channel;
    } else if (bw == 40) {
        int channel_type      =  map_get_ext_channel_type(op_class);
        int secondary_channel = (channel_type == MAP_EXT_CHANNEL_BELOW) ? channel - 4 : channel + 4;

        if (channel_type == MAP_EXT_CHANNEL_NONE) {
            return -1;
        }

        *from    = (channel_type == MAP_EXT_CHANNEL_BELOW) ? secondary_channel : channel;
        *to      = (channel_type == MAP_EXT_CHANNEL_BELOW) ? channel : secondary_channel;
    } else {
        /* should not be possible */
        return -1;
    }

    return 0;
}

bool map_is_channel_in_op_class(uint8_t op_class, uint8_t channel)
{
    wifi_op_class_t *p_op_class = get_op_class_ptr(op_class);

    if (!p_op_class) {
        return false;
    }

    if (p_op_class->center_channel) {
        channel = get_primary_channel_for_midfreq(channel, p_op_class->bw);
    }

    return map_cs_is_set(&p_op_class->map_ch_set, channel);
}

int map_get_bw_from_op_class(uint8_t op_class, uint16_t *bw)
{
    wifi_op_class_t *p_op_class = get_op_class_ptr(op_class);

    if (p_op_class) {
        *bw = p_op_class->bw;
    }

    return p_op_class ? 0 : -EINVAL;
}

int map_get_band_from_op_class(uint8_t op_class, uint8_t *band)
{
    wifi_op_class_t *p_op_class = get_op_class_ptr(op_class);

    if (p_op_class) {
        *band = p_op_class->ch_freq;
    }

    return p_op_class ? 0 : -EINVAL;
}

int map_get_is_center_channel_from_op_class(uint8_t op_class, bool *is_center_channel)
{
    wifi_op_class_t *p_op_class = get_op_class_ptr(op_class);

    if (p_op_class) {
        *is_center_channel = p_op_class->center_channel;
    }

    return p_op_class ? 0 : -EINVAL;
}

int map_get_channel_set_from_op_class(uint8_t op_class, map_channel_set_t *ch_set)
{
    wifi_op_class_t *p_op_class = get_op_class_ptr(op_class);

    if (p_op_class) {
        map_cs_copy(ch_set, &p_op_class->map_ch_set);
    } else {
        map_cs_unset_all(ch_set);
    }

    return p_op_class ? 0 : -EINVAL;
}

int map_get_center_channel_set_from_op_class(uint8_t op_class, map_channel_set_t *ch_set)
{
    map_channel_set_t ch_set2;
    bool              is_center_channel;
    uint8_t           ctl_channel, center_channel;

    map_cs_unset_all(ch_set);

    /* Only for center channel op classes */
    if (map_get_is_center_channel_from_op_class(op_class, &is_center_channel) ||
        !is_center_channel ||
        map_get_channel_set_from_op_class(op_class, &ch_set2)) {
        return -EINVAL;
    }

    map_cs_foreach(&ch_set2, ctl_channel) {
        if (!map_get_center_channel(op_class, ctl_channel, &center_channel)) {
            map_cs_set(ch_set, center_channel);
        }
    }

    return 0;
}

bool map_is_2G_ctl_channel(uint8_t channel)
{
    return map_cs_is_set(&g_2G_ctl_channel_set, channel);
}

bool map_is_5G_ctl_channel(uint8_t channel)
{
    return map_cs_is_set(&g_5G_ctl_channel_set, channel);
}

bool map_is_5G_low_ctl_channel(uint8_t channel)
{
    return map_cs_is_set(&g_5G_low_ctl_channel_set, channel);
}

bool map_is_5G_high_ctl_channel(uint8_t channel)
{
    return map_cs_is_set(&g_5G_high_ctl_channel_set, channel);
}


int map_get_5G_weatherband_op_class_nr(void)
{
    /* 121, 122, 123, 128, 129 */

    return 5;
}

bool map_is_5G_weatherband_op_class(uint8_t op_class)
{
    uint8_t o = op_class;

    return o == 121 || o == 122 || o == 123 || o == 128 || o == 129;
}

bool map_is_5G_weatherband_channel(uint8_t op_class, uint8_t ctl_or_center_channel)
{
    uint8_t c = ctl_or_center_channel;

    /* For operating class 128 and 129: check both control and center channels */
    switch (op_class) {
        case 121: return c == 120 || c == 124 || c == 128;             /* 20 MHz */
        case 122: return c == 116 || c == 124;                         /* 40 MHz */
        case 123: return c == 120 || c == 128;                         /* 40 MHz */
        case 128: return c == 120 || c == 124 || c == 128 || c == 122; /* 80 MHz (center channel 122) */
        case 129: return c == 120 || c == 124 || c == 128 || c == 114; /* 160 MHz (center channel 114) */
        default:  return false;
    }
}

bool map_is_6G_ctl_channel(uint8_t channel)
{
    return map_cs_is_set(&g_6G_ctl_channel_set, channel);
}

bool map_is_ctl_channel(uint8_t channel, uint8_t band)
{
    if (band == BAND_2G) {
        return map_is_2G_ctl_channel(channel);
    } else if (band == BAND_5G) {
        return map_is_5G_ctl_channel(channel);
    } else if (band == BAND_6G) {
        return map_is_6G_ctl_channel(channel);
    } else {
        return false;
    }
}

void map_get_2G_ctl_channel_set(map_channel_set_t *ch_set)
{
    map_cs_copy(ch_set, &g_2G_ctl_channel_set);
}

void map_get_5G_ctl_channel_set(map_channel_set_t *ch_set)
{
    map_cs_copy(ch_set, &g_5G_ctl_channel_set);
}

void map_get_5G_low_ctl_channel_set(map_channel_set_t *ch_set)
{
    map_cs_copy(ch_set, &g_5G_low_ctl_channel_set);
}

void map_get_5G_high_ctl_channel_set(map_channel_set_t *ch_set)
{
    map_cs_copy(ch_set, &g_5G_high_ctl_channel_set);
}

void map_get_5G_weatherband_channel_set(map_channel_set_t *ch_set)
{
    map_cs_copy(ch_set, &g_5G_weatherband_channel_set);
}

void map_get_6G_ctl_channel_set(map_channel_set_t *ch_set)
{
    map_cs_copy(ch_set, &g_6G_ctl_channel_set);
}

void map_get_6G_psc_channel_set(map_channel_set_t *ch_set)
{
    map_cs_copy(ch_set, &g_6G_psc_channel_set);
}

void map_get_ctl_channel_set(map_channel_set_t *ch_set, uint8_t band)
{
    if (band == BAND_2G) {
        map_get_2G_ctl_channel_set(ch_set);
    } else if (band == BAND_5G) {
        map_get_5G_ctl_channel_set(ch_set);
    } else if (band == BAND_6G) {
        map_get_6G_ctl_channel_set(ch_set);
    } else {
        map_cs_unset_all(ch_set);
    }
}

char *map_get_freq_band_str(uint8_t freq_band)
{
    if (freq_band == IEEE80211_FREQUENCY_BAND_2_4_GHZ) {
        return "2.4GHz";
    } else if (freq_band == IEEE80211_FREQUENCY_BAND_5_GHZ) {
        return "5GHz";
    } else if (freq_band == IEEE80211_FREQUENCY_BAND_6_GHZ) {
        return "6GHz";
    } else {
        return "UNKNOWN";
    }
}
