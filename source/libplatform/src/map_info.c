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
#define CLASS_TABLE_LEN ARRAY_SIZE(g_wifi_class_tbl)

#define MAX_CHANNEL_SET 60

#define CHAN_2G_BEGIN 1
#define CHAN_2G_END   14

#define CHAN_5G_BEGIN 36
#define CHAN_5G_END   177

#define CHAN_6G_BEGIN 1
#define CHAN_6G_END   233

#define PSC_BEGIN     5
#define PSC_END       229
#define PSC_DELTA     16

#define OP_CLASS_2G_BEGIN            81
#define OP_CLASS_2G_END              84
#define OP_CLASS_5G_LOW_BEGIN        115
#define OP_CLASS_5G_LOW_END          120
#define OP_CLASS_5G_HIGH_BEGIN       121
#define OP_CLASS_5G_HIGH_END         130
#define OP_CLASS_6G_BEGIN            131
#define OP_CLASS_6G_END              136
#define OP_CLASS_20MHZ_5G_LOW_BEGIN  115
#define OP_CLASS_20MHZ_5G_LOW_END    120
#define OP_CLASS_20MHZ_5G_HIGH_BEGIN 121
#define OP_CLASS_20MHZ_5G_HIGH_END   127

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
    uint8_t            bw;
    bool               center_channel;
    uint8_t            ext_channel;
} wifi_op_class_table_t;

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
/* NOTE: All channels in this table are control channels. */
static wifi_op_class_table_t g_wifi_class_tbl[] = {
    { 81, {{   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13},                13}, IEEE80211_FREQUENCY_BAND_2_4_GHZ,    20, false, MAP_EXT_CHANNEL_NONE},
    { 82, {{  14},                                                                             1}, IEEE80211_FREQUENCY_BAND_2_4_GHZ,    20, false, MAP_EXT_CHANNEL_NONE },
    { 83, {{   1,   2,   3,   4,   5,   6,   7,   8,   9},                                     9}, IEEE80211_FREQUENCY_BAND_2_4_GHZ,    40, false, MAP_EXT_CHANNEL_ABOVE},
    { 84, {{   5,   6,   7,   8,   9,  10,  11,  12,  13},                                     9}, IEEE80211_FREQUENCY_BAND_2_4_GHZ,    40, false, MAP_EXT_CHANNEL_BELOW},
    {115, {{  36, 40, 44, 48},                                                                 4}, IEEE80211_FREQUENCY_BAND_5_GHZ,      20, false, MAP_EXT_CHANNEL_NONE},
    {116, {{  36, 44},                                                                         2}, IEEE80211_FREQUENCY_BAND_5_GHZ,      40, false, MAP_EXT_CHANNEL_ABOVE},
    {117, {{  40, 48},                                                                         2}, IEEE80211_FREQUENCY_BAND_5_GHZ,      40, false, MAP_EXT_CHANNEL_BELOW},
    {118, {{  52,  56,  60,  64},                                                              4}, IEEE80211_FREQUENCY_BAND_5_GHZ,      20, false, MAP_EXT_CHANNEL_NONE},
    {119, {{  52,  60},                                                                        2}, IEEE80211_FREQUENCY_BAND_5_GHZ,      40, false, MAP_EXT_CHANNEL_ABOVE},
    {120, {{  56,  64},                                                                        2}, IEEE80211_FREQUENCY_BAND_5_GHZ,      40, false, MAP_EXT_CHANNEL_BELOW},
    {121, {{ 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144},                     12}, IEEE80211_FREQUENCY_BAND_5_GHZ,      20, false, MAP_EXT_CHANNEL_NONE},
    {122, {{ 100, 108, 116, 124, 132, 140},                                                    6}, IEEE80211_FREQUENCY_BAND_5_GHZ,      40, false, MAP_EXT_CHANNEL_ABOVE},
    {123, {{ 104, 112, 120, 128, 136, 144},                                                    6}, IEEE80211_FREQUENCY_BAND_5_GHZ,      40, false, MAP_EXT_CHANNEL_BELOW},
    {124, {{ 149, 153, 157, 161},                                                              4}, IEEE80211_FREQUENCY_BAND_5_GHZ,      20, false, MAP_EXT_CHANNEL_NONE},
    {125, {{ 149, 153, 157, 161, 165, 169, 173, 177},                                          8}, IEEE80211_FREQUENCY_BAND_5_GHZ,      20, false, MAP_EXT_CHANNEL_NONE},
    {126, {{ 149, 157, 165, 173},                                                              4}, IEEE80211_FREQUENCY_BAND_5_GHZ,      40, false, MAP_EXT_CHANNEL_ABOVE},
    {127, {{ 153, 161, 169, 177},                                                              4}, IEEE80211_FREQUENCY_BAND_5_GHZ,      40, false, MAP_EXT_CHANNEL_BELOW},
    {128, {{  36,  40,  44,  48,  52,  56,  60,  64, 100, 104, 108, 112, 116, 120, 124, 128,
              132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173, 177},                    28}, IEEE80211_FREQUENCY_BAND_5_GHZ,      80,  true, MAP_EXT_CHANNEL_NONE},
    {129, {{  36,  40,  44,  48,  52,  56,  60,  64, 100, 104, 108, 112, 116, 120, 124, 128,
             149, 153, 157, 161, 165, 169, 173, 177},                                         24}, IEEE80211_FREQUENCY_BAND_5_GHZ,     160,  true, MAP_EXT_CHANNEL_NONE},
    {130, {{  36,  40,  44,  48,  52,  56,  60,  64, 100, 104, 108, 112, 116, 120, 124, 128,
             132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173, 177},                     28}, IEEE80211_FREQUENCY_BAND_5_GHZ, 80+80+1,  true, MAP_EXT_CHANNEL_NONE},
    {131, {{   1,   5,   9,  13,  17,  21,  25,  29,  33,  37,  41,  45,  49,  53,  57,  61,
              65,  69,  73,  77,  81,  85,  89,  93,  97, 101, 105, 109, 113, 117, 121, 125,
             129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185, 189,
             193, 197, 201, 205, 209, 213, 217, 221, 225, 229, 233},                          59}, IEEE80211_FREQUENCY_BAND_6_GHZ,      20, false, MAP_EXT_CHANNEL_NONE},
    {132, {{   1,   5,   9,  13,  17,  21,  25,  29,  33,  37,  41,  45,  49,  53,  57,  61,
              65,  69,  73,  77,  81,  85,  89,  93,  97, 101, 105, 109, 113, 117, 121, 125,
             129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185, 189,
             193, 197, 201, 205, 209, 213, 217, 221, 225, 229},                               58}, IEEE80211_FREQUENCY_BAND_6_GHZ,      40,  true, MAP_EXT_CHANNEL_NONE},
    {133, {{   1,   5,   9,  13,  17,  21,  25,  29,  33,  37,  41,  45,  49,  53,  57,  61,
              65,  69,  73,  77,  81,  85,  89,  93,  97, 101, 105, 109, 113, 117, 121, 125,
             129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185, 189,
             193, 197, 201, 205, 209, 213, 217, 221},                                         56}, IEEE80211_FREQUENCY_BAND_6_GHZ,      80,  true, MAP_EXT_CHANNEL_NONE},
    {134, {{   1,   5,   9,  13,  17,  21,  25,  29,  33,  37,  41,  45,  49,  53,  57,  61,
              65,  69,  73,  77,  81,  85,  89,  93,  97, 101, 105, 109, 113, 117, 121, 125,
             129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185, 189,
             193, 197, 201, 205, 209, 213, 217, 221},                                         56}, IEEE80211_FREQUENCY_BAND_6_GHZ,     160,  true, MAP_EXT_CHANNEL_NONE},
    {135, {{   1,   5,   9,  13,  17,  21,  25,  29,  33,  37,  41,  45,  49,  53,  57,  61,
              65,  69,  73,  77,  81,  85,  89,  93,  97, 101, 105, 109, 113, 117, 121, 125,
             129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185, 189,
             193, 197, 201, 205, 209, 213, 217, 221},                                         56}, IEEE80211_FREQUENCY_BAND_6_GHZ, 80+80+1,  true, MAP_EXT_CHANNEL_NONE},
    {136, {{ 2},                                                                               1}, IEEE80211_FREQUENCY_BAND_6_GHZ,      20, false, MAP_EXT_CHANNEL_NONE},

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

/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
static int get_index(uint8_t op_class)
{
    unsigned int i;
    for( i = 0; i < CLASS_TABLE_LEN; i++) {
        if (g_wifi_class_tbl[i].op_class == op_class)
            return i;
    }
    return -1;
}

static int get_channel_index(uint8_t channel,int op_class_index)
{
    int i;
    for (i = 0; i < g_wifi_class_tbl[op_class_index].set.length; i++) {
        if (g_wifi_class_tbl[op_class_index].set.ch[i] == channel)
            return i;
    }
    return -1;
}

static void get_primary_channel_for_midfreq(uint8_t *channel, uint8_t bw)
{
    if (bw == 40) {
        *channel = (*channel) - 2;
    } else if (bw == 80) {
        *channel = (*channel) - 6;
    } else if (bw == 160) {
        *channel = (*channel) - 14;
    }
}

static void get_ctl_channel_set(map_channel_set_t *ch_set, uint8_t freq_type)
{
    int i, from = 0, to = 255;

    if (freq_type == IEEE80211_FREQUENCY_BAND_2_4_GHZ) {
        from = CHAN_2G_BEGIN; to = CHAN_2G_END;
    } else if (freq_type == IEEE80211_FREQUENCY_BAND_5_GHZ) {
        from = CHAN_5G_BEGIN; to = CHAN_5G_END;
    } else if (freq_type == IEEE80211_FREQUENCY_BAND_6_GHZ) {
        from = CHAN_6G_BEGIN; to = CHAN_6G_END;
    }

    map_cs_unset_all(ch_set);

    for (i = from; i <= to; i++) {
        if (map_is_ctl_channel(i, freq_type)) {
            map_cs_set(ch_set, i);
        }
    }
}

static void get_psc_channel_set(map_channel_set_t *ch_set)
{
    int i;

    map_cs_unset_all(ch_set);

    for (i = PSC_BEGIN; i <= PSC_END; i += PSC_DELTA) {
        map_cs_set(ch_set, i);
    }
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
int8_t map_get_frequency_type(uint8_t op_class, map_channel_set_t *channels,
                              uint8_t *freq_type, uint16_t *band_type_5G)
{
    if (NULL == freq_type || NULL == band_type_5G) {
        return -1;
    }

    int index = get_index(op_class);
    if (index != -1) {

        if (g_wifi_class_tbl[index].ch_freq == IEEE80211_FREQUENCY_BAND_2_4_GHZ) {
            *freq_type = IEEE80211_FREQUENCY_BAND_2_4_GHZ;
        } else if (g_wifi_class_tbl[index].ch_freq == IEEE80211_FREQUENCY_BAND_5_GHZ) {
            *freq_type = IEEE80211_FREQUENCY_BAND_5_GHZ;

            if (op_class >= OP_CLASS_20MHZ_5G_LOW_BEGIN && op_class <= OP_CLASS_20MHZ_5G_LOW_END) {
                *band_type_5G |= MAP_M2_BSS_RADIO5GL;
            } else if (op_class >= OP_CLASS_20MHZ_5G_HIGH_BEGIN && op_class <= OP_CLASS_20MHZ_5G_HIGH_END) {
                *band_type_5G |= MAP_M2_BSS_RADIO5GU;
            } else if (op_class >= 128  && op_class <=130) {
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
        } else if(g_wifi_class_tbl[index].ch_freq == IEEE80211_FREQUENCY_BAND_6_GHZ){
            *freq_type = IEEE80211_FREQUENCY_BAND_6_GHZ;
        } else {
            return -1;
        }
    } else {
        return -1;
    }

    return 0;
}

uint8_t map_get_op_class(uint8_t channel, uint8_t bw, uint8_t ch_freq)
{
    size_t i;

    /* Return first operating class that matches bw and includes channel  */
    for (i = 0; i < CLASS_TABLE_LEN; i++) {
        if (((ch_freq == IEEE80211_FREQUENCY_BAND_UNKNOWN) || (g_wifi_class_tbl[i].ch_freq == ch_freq)) &&
                    (g_wifi_class_tbl[i].bw == bw) && (get_channel_index(channel, i) >= 0)) {
            return g_wifi_class_tbl[i].op_class;
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

uint8_t map_get_center_channel(uint8_t op_class, uint8_t channel)
{
    int opclass_index = get_index(op_class);
    int channel_index = get_channel_index(channel, opclass_index);
    int bw, set_no, position;
    uint8_t primary_channel, center_channel = channel;

    /* Only derive center channel if this op_class uses center channels */
    if (opclass_index >= 0 && g_wifi_class_tbl[opclass_index].center_channel && channel_index >= 0) {
        bw = g_wifi_class_tbl[opclass_index].bw;

        if (bw == 40) {
            set_no          = channel_index / 2;
            position        = set_no * 2;
            primary_channel = g_wifi_class_tbl[opclass_index].set.ch[position];
            center_channel  = primary_channel + 2;
        } else if (bw == 80) {
            set_no          = channel_index / 4;
            position        = set_no * 4;
            primary_channel = g_wifi_class_tbl[opclass_index].set.ch[position];
            center_channel  = primary_channel + 6;
        } else if (bw == 160) {
            set_no          = channel_index / 8;
            position        = set_no * 8;
            primary_channel = g_wifi_class_tbl[opclass_index].set.ch[position];
            center_channel  = primary_channel + 14;
        }
    }
    return center_channel; /* Should return error when input was invalid? */
}

int map_get_ext_channel_type(uint8_t op_class)
{
    int idx = get_index(op_class);

    return idx >= 0 ? g_wifi_class_tbl[idx].ext_channel : MAP_EXT_CHANNEL_NONE;
}

/*
 * get all subband channels of a given channel/op_class combo
 * for 20MHz: single channel
 * for 40MHz: primary channel + secondary channel
 * for 80MHz + 160MHz: all 20MHz channels a 80/160MHz channel exists of
 */
int map_get_subband_channel_range(uint8_t channel, uint8_t op_class, uint8_t *from, uint8_t *to)
{
    int     opclass_index = get_index(op_class);
    uint8_t bw, sub_channels, set_no, position;

    if (opclass_index < 0) {
        return -1;
    }

    bw = g_wifi_class_tbl[opclass_index].bw;

    if(g_wifi_class_tbl[opclass_index].center_channel) {
        int channel_index = get_channel_index(channel, opclass_index);

        if(channel_index <  0) {
            return -1;
        }

        /* op_classes with 'Channel center frequency index' set (bw=80MHz/160MHz or 11ax op_class )*/
        sub_channels = bw / 20;

        set_no   = channel_index / sub_channels;
        position = set_no * sub_channels;
        *from    = g_wifi_class_tbl[opclass_index].set.ch[position];
        *to      = g_wifi_class_tbl[opclass_index].set.ch[position + sub_channels - 1];
    } else if (bw == 20) {
        *from    = channel;
        *to      = channel;
    } else if(bw == 40) {
        int channel_type      =  map_get_ext_channel_type(op_class);
        int secondary_channel = (channel_type == MAP_EXT_CHANNEL_BELOW) ? channel - 4 : channel + 4;

        if(channel_type == MAP_EXT_CHANNEL_NONE)
            return -1;

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
    int i = 0, opclass_index = 0;
    uint8_t bw = 0;
    opclass_index = get_index(op_class);
    if (opclass_index < 0) {
        return false;
    }
    map_get_bw_from_op_class(op_class, &bw);
    if (g_wifi_class_tbl[opclass_index].center_channel) {
        get_primary_channel_for_midfreq(&channel, bw);
    }

    for (i = 0; i < g_wifi_class_tbl[opclass_index].set.length; i++) {
        if (g_wifi_class_tbl[opclass_index].set.ch[i] == channel) {
            return true;
        }
    }
    return false;
}

int map_get_bw_from_op_class(uint8_t op_class, uint8_t *bw)
{
    size_t i;

    for (i = 0; i < CLASS_TABLE_LEN; i++) {
        if (g_wifi_class_tbl[i].op_class == op_class) {
             *bw = g_wifi_class_tbl[i].bw;
             return 0;
        }
    }
    return -EINVAL;
}

int map_get_band_from_op_class(uint8_t op_class, uint8_t *band)
{
    size_t i;

    for (i = 0; i < CLASS_TABLE_LEN; i++) {
        if (g_wifi_class_tbl[i].op_class == op_class) {
             *band = g_wifi_class_tbl[i].ch_freq;
             return 0;
        }
    }
    return -EINVAL;
}

int map_get_is_center_channel_from_op_class(uint8_t op_class, bool *is_center_channel)
{
    size_t i;

    for (i = 0; i < CLASS_TABLE_LEN; i++) {
        if (g_wifi_class_tbl[i].op_class == op_class) {
             *is_center_channel = g_wifi_class_tbl[i].center_channel;
             return 0;
        }
    }
    return -EINVAL;
}

int map_get_channel_set_from_op_class(uint8_t op_class, map_channel_set_t *ch_set)
{
    size_t i, j;

    map_cs_unset_all(ch_set);

    for (i = 0; i < CLASS_TABLE_LEN; i++) {
        if (g_wifi_class_tbl[i].op_class == op_class) {
            for (j = 0; j < g_wifi_class_tbl[i].set.length; j++) {
                map_cs_set(ch_set, g_wifi_class_tbl[i].set.ch[j]);
            }
            return 0;
        }
    }
    return -EINVAL;
}

bool map_is_ctl_channel(uint8_t channel, uint8_t ch_freq)
{
    /* Ok if we find a 20MHz op class for it */
    return map_get_op_class_20MHz(channel, ch_freq) > 0;
}

bool map_is_2G_ctl_channel(uint8_t channel)
{
    return map_is_ctl_channel(channel, IEEE80211_FREQUENCY_BAND_2_4_GHZ);
}

bool map_is_5G_ctl_channel(uint8_t channel)
{
    return map_is_ctl_channel(channel, IEEE80211_FREQUENCY_BAND_5_GHZ);
}

bool map_is_6G_ctl_channel(uint8_t channel)
{
    return map_is_ctl_channel(channel, IEEE80211_FREQUENCY_BAND_6_GHZ);
}

void map_get_2G_ctl_channel_set(map_channel_set_t *ch_set)
{
    get_ctl_channel_set(ch_set, IEEE80211_FREQUENCY_BAND_2_4_GHZ);
}

void map_get_5G_ctl_channel_set(map_channel_set_t *ch_set)
{
    get_ctl_channel_set(ch_set, IEEE80211_FREQUENCY_BAND_5_GHZ);
}

void map_get_6G_ctl_channel_set(map_channel_set_t *ch_set)
{
    get_ctl_channel_set(ch_set, IEEE80211_FREQUENCY_BAND_6_GHZ);
}

void map_get_6G_psc_channel_set(map_channel_set_t *ch_set)
{
    get_psc_channel_set(ch_set);
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
