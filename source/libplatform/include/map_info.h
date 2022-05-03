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

#ifndef MAP_INFO_H_
#define MAP_INFO_H_

#include "map_data_model.h"


typedef struct _wifi_channel_set {
    uint8_t ch[MAX_CHANNEL_SET];
    uint8_t length;
} wifi_channel_set;

#define MAP_CH_FREQ_2G 0x01
#define MAP_CH_FREQ_5G 0x02

#define MAP_EXT_CHANNEL_NONE  0x00
#define MAP_EXT_CHANNEL_ABOVE 0x01
#define MAP_EXT_CHANNEL_BELOW 0x02

typedef struct _wifi_op_class_table {
    uint8_t op_class;
    wifi_channel_set set;
    uint8_t ch_freq;
    uint8_t bw;
    uint8_t ext_channel;
} wifi_op_class_table;

typedef struct _wifi_op_class_array {
    uint8_t array[MAX_OP_CLASS];
    uint8_t length;
} wifi_op_class_array;


#define MAP_RADIO_IB_UNASSOC_MEASUREMENT_SUPPORTED  0x01
#define MAP_RADIO_OOB_UNASSOC_MEASUREMENT_SUPPORTED 0x02

#define MAP_ONBOARD_DEP_BITMASK (MAP_RADIO_M1_RECEIVED | MAP_RADIO_CONFIGURED | MAP_RADIO_OPER_CHAN_REPORT_RECEIVED | MAP_RADIO_POLICY_CONFIG_ACK_RECEIVED | MAP_RADIO_AP_CAPABILITY_REPORT_RECEIVED)

typedef enum _map_radio_states {
    MAP_RADIO_ON                              = 0x0001,
    MAP_RADIO_FREQUENCY_SUPPORTED             = 0x0002,
    MAP_RADIO_CONFIGURED                      = 0x0004,
    MAP_RADIO_M1_SENT                         = 0x0008,
    MAP_RADIO_M1_RECEIVED                     = 0x0010,
    MAP_RADIO_M2_SENT                         = 0x0020,
    MAP_RADIO_UNASSOC_MEASUREMENT_SUPPORTED   = 0x0040,
    MAP_RADIO_OPER_CHAN_REPORT_RECEIVED       = 0x0080,
    MAP_RADIO_POLICY_CONFIG_ACK_RECEIVED      = 0x0100,
    MAP_RADIO_CHANNEL_PREF_REPORT_RECEIVED    = 0x0200,
    MAP_RADIO_AP_CAPABILITY_REPORT_RECEIVED   = 0x0400,
    MAP_RADIO_INITIAL_SCAN_RESULTS_RECEIVED   = 0x0800,
    MAP_RADIO_CHANNEL_PREFERENCE_QUERY_SENT   = 0x1000,
} map_radio_states_t;


static inline void set_state_bit(uint16_t *state, uint16_t bit)
{
    *state = (*state) | bit;
}

static inline void reset_state_bit(uint16_t *state, uint16_t bit)
{
    *state = (*state) & (~bit);
}

static inline int is_state_bit_set(uint16_t state, uint16_t bit)
{
    if (bit == (state & bit)) {
        return 1;
    }
    return 0;
}

#define MUTUALLY_EXCLUSIVE_RADIO_STATES (MAP_RADIO_CONFIGURED | MAP_RADIO_M1_SENT | \
                                         MAP_RADIO_M1_RECEIVED | MAP_RADIO_M2_SENT)

#define set_radio_state_on(radio_state) (set_state_bit(radio_state,MAP_RADIO_ON))

#define set_radio_state_configured(radio_state) {\
                                                  set_state_bit(radio_state,MAP_RADIO_CONFIGURED);\
                                                }
#define set_radio_state_M1_sent(radio_state) { \
                                                reset_state_bit(radio_state, MUTUALLY_EXCLUSIVE_RADIO_STATES);\
                                                set_state_bit(radio_state,MAP_RADIO_M1_SENT); \
                                             }

#define set_radio_state_M1_receive(radio_state) { \
                                                   reset_state_bit(radio_state, MUTUALLY_EXCLUSIVE_RADIO_STATES);\
                                                   set_state_bit(radio_state,MAP_RADIO_M1_RECEIVED); \
                                                }

#define set_radio_state_M2_sent(radio_state) { \
                                                set_state_bit(radio_state,MAP_RADIO_M2_SENT); \
                                             }

#define set_radio_state_policy_config_ack_received(radio_state) \
                                 (set_state_bit(radio_state, MAP_RADIO_POLICY_CONFIG_ACK_RECEIVED))
#define set_radio_state_oper_chan_report_received(radio_state) \
                                 (set_state_bit(radio_state, MAP_RADIO_OPER_CHAN_REPORT_RECEIVED))
#define set_radio_state_channel_pref_report_received(radio_state) \
                                 (set_state_bit(radio_state, MAP_RADIO_CHANNEL_PREF_REPORT_RECEIVED))
#define set_radio_state_ap_cap_report_received(radio_state) \
                                 (set_state_bit(radio_state, MAP_RADIO_AP_CAPABILITY_REPORT_RECEIVED))
#define set_radio_state_initial_scan_results_received(radio_state) \
                                 (set_state_bit(radio_state, MAP_RADIO_INITIAL_SCAN_RESULTS_RECEIVED))
#define set_radio_state_channel_preference_query_sent(radio_state) \
                                 (set_state_bit(radio_state, MAP_RADIO_CHANNEL_PREFERENCE_QUERY_SENT))

/*Reset radio state bit*/
#define set_radio_state_off(radio_state) (reset_state_bit(radio_state,MAP_RADIO_ON))
#define set_radio_state_freq_unsupported(radio_state) (reset_state_bit(radio_state,MAP_RADIO_FREQUENCY_SUPPORTED))
#define set_radio_state_unconfigured(radio_state) {\
                                                    reset_state_bit(radio_state,MAP_RADIO_CONFIGURED);\
                                                    reset_state_bit(radio_state,MAP_RADIO_M1_SENT);\
                                                  }

#define set_ib_unassoc_measurement_supported(radio_state) (set_state_bit(radio_state,MAP_RADIO_IB_UNASSOC_MEASUREMENT_SUPPORTED))
#define set_oob_unassoc_measurement_supported(radio_state) (set_state_bit(radio_state,MAP_RADIO_OOB_UNASSOC_MEASUREMENT_SUPPORTED))

#define set_radio_state_policy_config_ack_not_received(radio_state) \
                                 (reset_state_bit(radio_state, MAP_RADIO_POLICY_CONFIG_ACK_RECEIVED))
#define set_radio_state_oper_chan_report_not_received(radio_state) \
                                 (reset_state_bit(radio_state, MAP_RADIO_OPER_CHAN_REPORT_RECEIVED))
#define set_radio_state_channel_pref_report_not_received(radio_state) \
                                 (reset_state_bit(radio_state, MAP_RADIO_CHANNEL_PREF_REPORT_RECEIVED))
#define set_radio_state_ap_cap_report_not_received(radio_state) \
                                 (reset_state_bit(radio_state, MAP_RADIO_AP_CAPABILITY_REPORT_RECEIVED))
#define set_radio_state_channel_preference_query_not_sent(radio_state) \
                                 (reset_state_bit(radio_state, MAP_RADIO_CHANNEL_PREFERENCE_QUERY_SENT))


/*Get if radio state is set or not*/
#define is_radio_on(radio_state) (is_state_bit_set(radio_state,MAP_RADIO_ON))
#define is_radio_freq_supported(radio_state) (is_state_bit_set(radio_state,MAP_RADIO_FREQUENCY_SUPPORTED))
#define is_radio_configured(radio_state) (is_state_bit_set(radio_state,MAP_RADIO_CONFIGURED))
#define is_radio_M1_sent(radio_state) (is_state_bit_set(radio_state,MAP_RADIO_M1_SENT))
#define is_radio_M1_received(radio_state) (is_state_bit_set(radio_state,MAP_RADIO_M1_RECEIVED))
#define is_radio_M2_sent(radio_state) (is_state_bit_set(radio_state,MAP_RADIO_M2_SENT))
#define is_unassoc_measurement_inprogress(radio_state) (is_state_bit_set(radio_state,MAP_RADIO_UNASSOC_MEASUREMENT_IN_PROGRESS))

#define is_unassoc_measurement_supported(radio_state) (is_ib_unassoc_measurement_supported(radio_state) || is_oob_unassoc_measurement_supported(radio_state))
#define is_ib_unassoc_measurement_supported(radio_state) (is_state_bit_set(radio_state,MAP_RADIO_IB_UNASSOC_MEASUREMENT_SUPPORTED))
#define is_oob_unassoc_measurement_supported(radio_state) (is_state_bit_set(radio_state,MAP_RADIO_OOB_UNASSOC_MEASUREMENT_SUPPORTED))
#define is_radio_policy_config_ack_received(radio_state) \
                                 (is_state_bit_set(radio_state, MAP_RADIO_POLICY_CONFIG_ACK_RECEIVED))
#define is_radio_operating_chan_report_received(radio_state) \
                                 (is_state_bit_set(radio_state, MAP_RADIO_OPER_CHAN_REPORT_RECEIVED))
#define is_radio_state_channel_pref_report_received(radio_state) \
                                 (is_state_bit_set(radio_state, MAP_RADIO_CHANNEL_PREF_REPORT_RECEIVED))
#define is_radio_ap_cap_report_received(radio_state) \
                                 (is_state_bit_set(radio_state, MAP_RADIO_AP_CAPABILITY_REPORT_RECEIVED))
#define is_radio_initial_scan_results_received(radio_state) \
                                 (is_state_bit_set(radio_state, MAP_RADIO_INITIAL_SCAN_RESULTS_RECEIVED))
#define is_radio_channel_preference_query_sent(radio_state) \
                                 (is_state_bit_set(radio_state, MAP_RADIO_CHANNEL_PREFERENCE_QUERY_SENT))

/* Channel set */
bool map_is_channel_set(wifi_channel_set *ch_set, uint8_t ch);

void map_set_channel(wifi_channel_set *ch_set, uint8_t ch);

void map_unset_channel(wifi_channel_set *ch_set, uint8_t ch);


/* Get the frequency type from operating class. */
int8_t get_frequency_type(uint8_t op_class, uint8_t num_channels,
                          uint8_t *channels, uint8_t *freq_type, uint16_t *band_type_5G);

void get_operating_class_set(wifi_channel_set * set, uint8_t bw, wifi_op_class_array * op_class);

/* Get first found op class for control channel and bw */
uint8_t get_operating_class(uint8_t channel, uint8_t bw);

/* Get first found 20MHz op class for control channel */
uint8_t get_operating_class_20MHz(uint8_t channel);

bool map_is_5g_low_op_class(uint8_t op_class);

bool map_is_5g_high_op_class(uint8_t op_class);

void get_non_operating_ch(uint8_t op_class, wifi_channel_set * non_op_ch, wifi_channel_set * set );

void get_operable_channels(uint8_t op_class, wifi_channel_set * oper_ch, wifi_channel_set * set );

int is_matching_channel_in_opclass(uint8_t op_class, uint8_t channel);

uint8_t get_mid_freq(uint8_t channel, uint8_t opclass, uint8_t bw);

int map_get_ext_channel_type(uint8_t opclass);

/* Get 20MHz subband range (only works for 80 and 160MHz) */
int map_get_subband_channel_range(uint8_t channel, uint8_t opclass, uint8_t *from, uint8_t *to);

int get_bw_from_operating_class(uint8_t op_class, uint8_t *bw);

int get_channel_set_for_rclass(uint8_t rclass, wifi_channel_set *ch_set);


/* Control channel utility functions */
bool map_is_ctl_channel(uint8_t channel);

bool map_is_2G_ctl_channel(uint8_t channel);

bool map_is_5G_ctl_channel(uint8_t channel);

void map_get_2G_ctl_channel_set(wifi_channel_set *ch_set);

void map_get_5G_ctl_channel_set(wifi_channel_set *ch_set);

#endif /* MAP_INFO_H_ */
