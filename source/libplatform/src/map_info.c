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
#                       DEFIENS                                         #
########################################################################*/
#define CLASS_TABLE_LEN ARRAY_SIZE(g_wifi_class_tbl)

#define CHAN_2G_BEGIN 1
#define CHAN_2G_END   14

#define CHAN_5G_BEGIN 36
#define CHAN_5G_END   177

#define OP_CLASS_20MHZ_5G_LOW_BEGIN  115
#define OP_CLASS_20MHZ_5G_LOW_END    120
#define OP_CLASS_20MHZ_5G_HIGH_BEGIN 121
#define OP_CLASS_20MHZ_5G_HIGH_END   127

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static wifi_op_class_table g_wifi_class_tbl[] = {
    {81, { { 1,2,3,4,5,6,7,8,9,10,11,12,13}, 13}, MAP_CH_FREQ_2G, 20, MAP_EXT_CHANNEL_NONE},
    {82, { { 14}, 1}, MAP_CH_FREQ_2G, 20, MAP_EXT_CHANNEL_NONE },
    {83, { { 1,2,3,4,5,6,7,8,9}, 9}, MAP_CH_FREQ_2G, 40, MAP_EXT_CHANNEL_ABOVE},
    {84, { { 5,6,7,8,9,10,11,12,13}, 9}, MAP_CH_FREQ_2G, 40, MAP_EXT_CHANNEL_BELOW},
//    {85, { { 1,2,3,4,5,6,7,8,9,10,11,12,13}, 13}, 7, 6},
//    {86, { { 1,2,3,4,5,6,7,8,9,10,11,12,13}, 13}, 7, 12},
//    {87, { { 1,2,3,4,5,6,7,8,9,10,11,12,13}, 13}, 7, 24},
//    {94, { { 133,137}, 2}, 4, 20},
//    {95, { { 132,134,136,138}, 4}, 4, 10},
//    {96, { { 131,132,133,134,135,136,137,138}, 8}, 4, 5},
//    {101, { { 21,25}, 2}, 5, 20},
//    {102, { { 11,13,15,17,19}, 5}, 5, 40},
//    {103, { { 1,2,3,4,5,6,7,8,9,10}, 10,}, 5, 5},
//    {104, { { 184,192}, 2}, 6, 40},
//    {105, { { 188,196}, 2}, 6, 40},
//    {106, { { 191,195}, 2}, 6, 20},
//    {107, { { 189,191,193,195,197}, 5}, 6, 10},
//    {108, { { 188,189,190,191,192,193,194,195,196,197}, 10}, 6, 5},
//    {109, { { 184,188,192,196}, 4}, 6, 20},
//    {110, { { 183,184,185,186,187,188,189}, 7}, 6, 10},
//    {111, { { 182,183,184,185,186,187,188,189}, 8}, 6, 5},
//    {112, { { 8, 12, 16}, 3}, 2, 20},
//    {113, { { 7,8,9,10,11}, 5}, 2, 5},
//    {114, { { 6,7,8,9,10,11}, 6}, 2, 5},
    {115, { { 36,40,44,48}, 4}, MAP_CH_FREQ_5G, 20, MAP_EXT_CHANNEL_NONE},
    {116, { { 36, 44}, 2}, MAP_CH_FREQ_5G, 40, MAP_EXT_CHANNEL_ABOVE},
    {117, { { 40, 48}, 2}, MAP_CH_FREQ_5G, 40, MAP_EXT_CHANNEL_BELOW},
    {118, { { 52, 56, 60, 64}, 4}, MAP_CH_FREQ_5G, 20, MAP_EXT_CHANNEL_NONE},
    {119, { { 52, 60}, 2}, MAP_CH_FREQ_5G, 40, MAP_EXT_CHANNEL_ABOVE},
    {120, { { 56, 64}, 2}, MAP_CH_FREQ_5G, 40, MAP_EXT_CHANNEL_BELOW},
    {121, { { 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144}, 12}, MAP_CH_FREQ_5G, 20, MAP_EXT_CHANNEL_NONE},
    {122, { { 100, 108, 116, 124, 132, 140}, 6}, MAP_CH_FREQ_5G, 40, MAP_EXT_CHANNEL_ABOVE},
    {123, { { 104, 112, 120, 128, 136, 144}, 6}, MAP_CH_FREQ_5G, 40, MAP_EXT_CHANNEL_BELOW},
    {124, { { 149, 153, 157, 161}, 4}, MAP_CH_FREQ_5G, 20, MAP_EXT_CHANNEL_NONE},
    {125, { { 149, 153, 157, 161, 165, 169, 173, 177}, 8}, MAP_CH_FREQ_5G, 20, MAP_EXT_CHANNEL_NONE},
    {126, { { 149, 157, 165, 173}, 4}, MAP_CH_FREQ_5G, 40, MAP_EXT_CHANNEL_ABOVE},
    {127, { { 153, 161, 169, 177}, 4}, MAP_CH_FREQ_5G, 40, MAP_EXT_CHANNEL_BELOW},
    {128, { { 36,40,44,48, 52,56,60,64, 100,104,108,112, 116,120,124,128, 132,136,140,144, 149,153,157,161, 165,169,173,177}, 28}, MAP_CH_FREQ_5G, 80, MAP_EXT_CHANNEL_NONE},
    {129, { { 36,40,44,48, 52,56,60,64, 100,104,108,112, 116,120,124,128, 149,153,157,161, 165,169,173,177}, 24}, MAP_CH_FREQ_5G, 160, MAP_EXT_CHANNEL_NONE},
    {130, { { 36,40,44,48, 52,56,60,64, 100,104,108,112, 116,120,124,128, 132,136,140,144, 149,153,157,161, 165,169,173,177}, 28}, MAP_CH_FREQ_5G, 80+80+1, MAP_EXT_CHANNEL_NONE},
//    {180, { { 1,2,3,4,5,6}, 6}, 3, 2160}i
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
    if (bw == 80) {
        *channel = (*channel)-6;
    } else if (bw == 160) {
        *channel = (*channel)-14;
    }
}

static void get_ctl_channel_set(wifi_channel_set *ch_set, int from, int to)
{
    int i;

    ch_set->length = 0;

    for (i = from; (i <= to) && (ch_set->length < MAX_CHANNEL_SET); i++) {
        if (map_is_ctl_channel(i)) {
            ch_set->ch[ch_set->length++] = i;
        }
    }
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
bool map_is_channel_set(wifi_channel_set *ch_set, uint8_t ch)
{
    size_t i;

    for (i = 0; i < ch_set->length; i++) {
        if (ch_set->ch[i] == ch) {
            return true;
        }
    }
    return false;
}

void map_set_channel(wifi_channel_set *ch_set, uint8_t ch)
{
    if (!map_is_channel_set(ch_set, ch) && (ch_set->length < MAX_CHANNEL_SET)) {
        ch_set->ch[ch_set->length++] = ch;
    }
}

void map_unset_channel(wifi_channel_set *ch_set, uint8_t ch)
{
    size_t i;

    for (i = 0; i < ch_set->length; i++) {
        if (ch_set->ch[i] == ch) {
            memmove(&ch_set->ch[i], &ch_set->ch[i+1], (ch_set->length - i - 1) * sizeof(ch_set->ch[i]));
            ch_set->length--;
            break;
        }
    }
}

int8_t get_frequency_type(uint8_t op_class, uint8_t num_channels,
                          uint8_t *channels, uint8_t *freq_type, uint16_t *band_type_5G)
{
    if (NULL == freq_type || NULL == band_type_5G) {
        return -1;
    }

    int index = get_index(op_class);
    if (index != -1) {

        if (g_wifi_class_tbl[index].ch_freq == MAP_CH_FREQ_2G) {
            *freq_type = IEEE80211_FREQUENCY_BAND_2_4_GHZ;
        } else if (g_wifi_class_tbl[index].ch_freq == MAP_CH_FREQ_5G) {
            *freq_type = IEEE80211_FREQUENCY_BAND_5_GHZ;

            if (op_class >= OP_CLASS_20MHZ_5G_LOW_BEGIN && op_class <= OP_CLASS_20MHZ_5G_LOW_END) {
                *band_type_5G |= MAP_M2_BSS_RADIO5GL;
            } else if (op_class >= OP_CLASS_20MHZ_5G_HIGH_BEGIN && op_class <= OP_CLASS_20MHZ_5G_HIGH_END) {
                *band_type_5G |= MAP_M2_BSS_RADIO5GU;
            } else if (op_class >= 128  && op_class <=130) {
                uint8_t upper_band = 0;
                uint8_t lower_band = 0;
                int i;
                for (i = 0; i < num_channels; i++) {
                    if (channels[i] < 100) {
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
        }
        /* Add other frequency band here once supported*/
        /*
        else if(g_wifi_class_tbl[index].ch_freq == 3){
		*freq_type = IEEE80211_FREQUENCY_BAND_60_GHZ;
        }
        */
        else {
            return -1;
        }
    } else {
        return -1;
    }

    return 0;
}

int is_matching_bw(wifi_op_class_table* entry, uint8_t bw, wifi_channel_set* set)
{

    /* if the set length is 1, then it is for the current operating channel report and hence the BW must match
    Else it is general and for all supported operating class and hence BW must be less or equal to the max BW*/
    if (((set->length == 1) && (entry->bw == bw)) ||
        ((set->length != 1) && (entry->bw <= bw))) {
        return 1;
    }

    return 0;
}

int is_matching_channel(wifi_op_class_table* entry, wifi_channel_set* set)
{
    int i, j;
    for (i = 0; i < set->length; i++) {
        for (j = 0; j < entry->set.length; j++) {
            if (set->ch[i] == entry->set.ch[j]) {
                return 1;
            }
        }
    }
    return 0;
}

void get_operating_class_set(wifi_channel_set * set, uint8_t bw, wifi_op_class_array * op_class)
{
    unsigned int i;
    uint8_t freq = 0;

    if (set->ch[0] <= 14) {
        freq = IEEE80211_FREQUENCY_BAND_2_4_GHZ+1;
    } else {
        freq = IEEE80211_FREQUENCY_BAND_5_GHZ+1;
    }

    for (i = 0; i < CLASS_TABLE_LEN; i++) {
        if ((g_wifi_class_tbl[i].ch_freq == freq) &&  (is_matching_bw(&(g_wifi_class_tbl[i]), bw, set)) &&
            (is_matching_channel(&(g_wifi_class_tbl[i]), set))) {
            op_class->array[op_class->length] = g_wifi_class_tbl[i].op_class;
            op_class->length++;
        }
    }
}

uint8_t get_operating_class(uint8_t channel, uint8_t bw)
{
    size_t i;

    /* Return first operating class that matches bw and includes channel  */
    for (i = 0; i < CLASS_TABLE_LEN; i++) {
        if ((g_wifi_class_tbl[i].bw == bw) && (get_channel_index(channel, i) >= 0)) {
            return g_wifi_class_tbl[i].op_class;
        }
    }

    return 0;
}

uint8_t get_operating_class_20MHz(uint8_t channel)
{
    return get_operating_class(channel, 20);
}

bool map_is_5g_low_op_class(uint8_t op_class)
{
    return op_class >= OP_CLASS_20MHZ_5G_LOW_BEGIN && op_class <= OP_CLASS_20MHZ_5G_LOW_END;
}

bool map_is_5g_high_op_class(uint8_t op_class)
{
    return op_class >= OP_CLASS_20MHZ_5G_HIGH_BEGIN && op_class <= OP_CLASS_20MHZ_5G_HIGH_END;
}

uint8_t get_mid_freq(uint8_t channel, uint8_t opclass, uint8_t bw)
{
    if ((bw != 80) && (bw != 160)) {
        return channel;
    }

    int opclass_index = get_index(opclass);
    int channel_index = get_channel_index(channel, opclass_index);

    if (channel_index != -1 && opclass_index != -1) {
        if (bw == 80) {
            int set_no = channel_index/4;
            int position = set_no * 4;
            uint8_t primary_channel = g_wifi_class_tbl[opclass_index].set.ch[position];
            return (primary_channel+6);
        } else if (bw == 160) {
            int set_no = channel_index/8;
            int position = set_no * 8;
            uint8_t primary_channel = g_wifi_class_tbl[opclass_index].set.ch[position];
            return (primary_channel+14);
        }
    }
    return 0;
}

int map_get_ext_channel_type(uint8_t opclass)
{
    int idx = get_index(opclass);

    return idx >= 0 ? g_wifi_class_tbl[idx].ext_channel : MAP_EXT_CHANNEL_NONE;
}

int map_get_subband_channel_range(uint8_t channel, uint8_t opclass, uint8_t *from, uint8_t *to)
{
    int     opclass_index = get_index(opclass);
    int     channel_index = get_channel_index(channel, opclass_index);
    uint8_t bw, sub_channels, set_no, position;

    if (channel_index < 0 || opclass_index < -1) {
        return -1;
    }
    bw = g_wifi_class_tbl[opclass_index].bw;
    if (bw != 80 && bw != 160) {
        return -1;
    }
    sub_channels = bw / 20;

    set_no   = channel_index / sub_channels;
    position = set_no * sub_channels;
    *from    = g_wifi_class_tbl[opclass_index].set.ch[position];
    *to      = g_wifi_class_tbl[opclass_index].set.ch[position + sub_channels - 1];

    return 0;
}

void get_operable_channels(uint8_t op_class, wifi_channel_set *oper_ch_set, wifi_channel_set *set)
{
    int tbl_index = get_index(op_class);

    if (tbl_index != -1) {
        int i = 0, j = 0;
        uint8_t bw = 0, mid_freq = 0, new_freq = 0;
        get_bw_from_operating_class(op_class, &bw);
        for (i = 0; i < g_wifi_class_tbl[tbl_index].set.length;  i++) {
            for (j = 0; j < set->length; j++) {
                if (set->ch[j] == g_wifi_class_tbl[tbl_index].set.ch[i]) {
                    if (mid_freq == (new_freq = get_mid_freq(g_wifi_class_tbl[tbl_index].set.ch[i], op_class, bw))) {
                        continue;
                    }

                    oper_ch_set->ch[oper_ch_set->length] = mid_freq = new_freq;
                    oper_ch_set->length++;
                }
            }
        }
    }
}

void get_non_operating_ch(uint8_t op_class, wifi_channel_set *non_op_ch, wifi_channel_set *set)
{
    int tbl_index = get_index(op_class);

    if (tbl_index != -1) {
        int i = 0, j = 0;
        uint8_t bw = 0, mid_freq = 0, new_freq = 0;
        get_bw_from_operating_class(op_class, &bw);
        for (i = 0; i < g_wifi_class_tbl[tbl_index].set.length;  i++) {
            int bfound = 0;
            for (j = 0; j < set->length; j++) {
                if(set->ch[j] == g_wifi_class_tbl[tbl_index].set.ch[i]) {
                    bfound = 1;
                    break;
                }
            }
            if (bfound == 0) {
                if (mid_freq == (new_freq = get_mid_freq(g_wifi_class_tbl[tbl_index].set.ch[i], op_class, bw))) {
                    continue;
                }

                non_op_ch->ch[non_op_ch->length] = mid_freq = new_freq;
                non_op_ch->length++;
            }
        }
    }
}

int is_matching_channel_in_opclass(uint8_t op_class, uint8_t channel)
{
    int i = 0, opclass_index = 0;
    uint8_t bw = 0;
    opclass_index = get_index(op_class);
    if (opclass_index < 0) {
        return 0;
    }
    get_bw_from_operating_class(op_class, &bw);
    if ((bw == 80) || (bw == 160)) {
        get_primary_channel_for_midfreq(&channel, bw);
    }

    for (i = 0; i < g_wifi_class_tbl[opclass_index].set.length; i++) {
        if (g_wifi_class_tbl[opclass_index].set.ch[i] == channel) {
            return 1;
        }
    }
    return 0;
}

int get_bw_from_operating_class(uint8_t op_class, uint8_t *bw)
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

int get_channel_set_for_rclass(uint8_t rclass, wifi_channel_set *ch_set)
{
    size_t i;

    for (i = 0; i < CLASS_TABLE_LEN; i++) {
        if (g_wifi_class_tbl[i].op_class == rclass) {
            memcpy(ch_set->ch, g_wifi_class_tbl[i].set.ch, g_wifi_class_tbl[i].set.length);
            ch_set->length = g_wifi_class_tbl[i].set.length;
            return 0;
        }
    }
    return -EINVAL;
}

bool map_is_ctl_channel(uint8_t channel)
{
    /* Ok if we find a 20MHz op class for it */
    return get_operating_class_20MHz(channel) > 0;
}

bool map_is_2G_ctl_channel(uint8_t channel)
{
    return map_is_ctl_channel(channel) && channel >= CHAN_2G_BEGIN && channel <= CHAN_2G_END;
}

bool map_is_5G_ctl_channel(uint8_t channel)
{
    return map_is_ctl_channel(channel) && channel >= CHAN_5G_BEGIN && channel <= CHAN_5G_END;
}

void map_get_2G_ctl_channel_set(wifi_channel_set *ch_set)
{
    get_ctl_channel_set(ch_set, CHAN_2G_BEGIN, CHAN_2G_END);
}

void map_get_5G_ctl_channel_set(wifi_channel_set *ch_set)
{
    get_ctl_channel_set(ch_set, CHAN_5G_BEGIN, CHAN_5G_END);
}
