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

#include "map_channel_set.h"
#include "map_data_model.h"

#define MAP_EXT_CHANNEL_NONE  0x00
#define MAP_EXT_CHANNEL_ABOVE 0x01
#define MAP_EXT_CHANNEL_BELOW 0x02

#define MAP_RADIO_IB_UNASSOC_MEASUREMENT_SUPPORTED  0x01
#define MAP_RADIO_OOB_UNASSOC_MEASUREMENT_SUPPORTED 0x02

#define MAP_ONBOARD_DEP_BITMASK (MAP_RADIO_M1_RECEIVED | MAP_RADIO_CONFIGURED | MAP_RADIO_OPER_CHAN_REPORT_RECEIVED | MAP_RADIO_POLICY_CONFIG_ACK_RECEIVED | MAP_RADIO_AP_CAPABILITY_REPORT_RECEIVED)

typedef enum _map_bss_states {
    MAP_BSS_ACTIVE                            = 0x0001,
} map_bss_states_t;

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

typedef enum _map_ale_states {
    MAP_ALE_INITIALIZED                       = 0x0001,
    MAP_ALE_AP_CAPABILITY_REPORT_RECEIVED     = 0x0002,
    MAP_ALE_BHSTA_CAPABILITY_REPORT_RECEIVED  = 0x0004,
} map_ale_states_t;

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

/* BSS state macros */
#define set_bss_state_active(bss_state) (set_state_bit(bss_state,MAP_BSS_ACTIVE))
#define is_bss_active(bss_state) (is_state_bit_set(bss_state,MAP_BSS_ACTIVE))

/* Radio state macros */
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
                                                    reset_state_bit(radio_state,MAP_RADIO_M1_RECEIVED);\
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

/* ALE state macros */
#define is_ale_ap_cap_report_received(ale_state) \
                                 (is_state_bit_set(ale_state, MAP_ALE_AP_CAPABILITY_REPORT_RECEIVED))
#define set_ale_state_ap_cap_report_received(ale_state) \
                                 (set_state_bit(ale_state, MAP_ALE_AP_CAPABILITY_REPORT_RECEIVED))
#define set_ale_state_ap_cap_report_not_received(ale_state) \
                                 (reset_state_bit(ale_state, MAP_ALE_AP_CAPABILITY_REPORT_RECEIVED))

#define is_ale_bhsta_cap_report_received(ale_state) \
                                 (is_state_bit_set(ale_state, MAP_ALE_BHSTA_CAPABILITY_REPORT_RECEIVED))
#define set_ale_state_bhsta_cap_report_received(ale_state) \
                                 (set_state_bit(ale_state, MAP_ALE_BHSTA_CAPABILITY_REPORT_RECEIVED))
#define set_ale_state_bhsta_cap_report_not_received(ale_state) \
                                 (reset_state_bit(ale_state, MAP_ALE_BHSTA_CAPABILITY_REPORT_RECEIVED))

/* Init */
int map_info_init(void);

/* Fini */
void map_info_fini(void);

/* Get the frequency type from operating class. */
int8_t map_get_frequency_type(uint8_t op_class, map_channel_set_t *channels,
                              uint8_t *freq_type, uint16_t *band_type_5G);

/* Get first found op class for control channel, bw and channel_frequency */
uint8_t map_get_op_class(uint8_t channel, uint16_t bw, uint8_t ch_freq);

/* Get first found 20MHz op class for control channel */
uint8_t map_get_op_class_20MHz(uint8_t channel, uint8_t ch_freq);

/* Check if operating class is 5G low band */
bool map_is_5g_low_op_class(uint8_t op_class);

/* Check if operating class is 5G high band */
bool map_is_5g_high_op_class(uint8_t op_class);

/* Check if channel is in operating class */
bool map_is_channel_in_op_class(uint8_t op_class, uint8_t channel);

/* Get center channel from ctl_channel for operating classes that use center channels */
int map_get_center_channel(uint8_t op_class, uint8_t ctl_channel, uint8_t *center_channel);

/* Get first ctl channel from center_channel for op_class that uses center channels */
int map_get_first_ctl_channel(uint8_t op_class, uint8_t center_channel, uint8_t *ctl_channel);

/* Get extension channel type */
int map_get_ext_channel_type(uint8_t op_class);

/* Get 20MHz subband range (only works for 80 and 160MHz) */
int map_get_subband_channel_range(uint8_t op_class, uint8_t channel, uint8_t *from, uint8_t *to);

/* Get bandwidth from operating class */
int map_get_bw_from_op_class(uint8_t op_class, uint16_t *bw);

/* Get band from operating class */
int map_get_band_from_op_class(uint8_t op_class, uint8_t *band);

/* Get is_center_channel from operating class (80/160 MHz and 40MHz in 6G band) */
int map_get_is_center_channel_from_op_class(uint8_t op_class, bool *is_center_channel);

/* Get control channel set from operating class */
int map_get_channel_set_from_op_class(uint8_t op_class, map_channel_set_t *ch_set);

/* Get center channel set from operating class (only for center channel operating classes) */
int map_get_center_channel_set_from_op_class(uint8_t op_class, map_channel_set_t *ch_set);

/* Control channel utility functions */
bool map_is_ctl_channel(uint8_t channel, uint8_t ch_freq);

/* Check if channel is a 2G control channel */
bool map_is_2G_ctl_channel(uint8_t channel);

/* Check if channel is a 5G control channel */
bool map_is_5G_ctl_channel(uint8_t channel);

/* Check if channel is a 5G "low" control channel */
bool map_is_5G_low_ctl_channel(uint8_t channel);

/* Check if channel is a 5G "high" control channel */
bool map_is_5G_high_ctl_channel(uint8_t channel);

/* Get number of operating classes that contain weatherband channels */
int map_get_5G_weatherband_op_class_nr(void);

/* Check if op_class contains weatherband channels */
bool map_is_5G_weatherband_op_class(uint8_t op_class);

/* Check if channel is a 5G weatherband control or center channel */
bool map_is_5G_weatherband_channel(uint8_t op_class, uint8_t ctl_or_center_channel);

/* Check if channel is a 6G control channel */
bool map_is_6G_ctl_channel(uint8_t channel);

/* Get channel set containing all 2G control channels */
void map_get_2G_ctl_channel_set(map_channel_set_t *ch_set);

/* Get channel set containing all 5G control channels */
void map_get_5G_ctl_channel_set(map_channel_set_t *ch_set);

/* Get channel set containing all 5G "low" control channels */
void map_get_5G_low_ctl_channel_set(map_channel_set_t *ch_set);

/* Get channel set containing all 5G "high" control channels */
void map_get_5G_high_ctl_channel_set(map_channel_set_t *ch_set);

/* Get channel set containing all 5G weatherband channels */
void map_get_5G_weatherband_channel_set(map_channel_set_t *ch_set);

/* Get channel set containing all 6G control channels */
void map_get_6G_ctl_channel_set(map_channel_set_t *ch_set);

/* Get channel set containing all 6G PSC channels */
void map_get_6G_psc_channel_set(map_channel_set_t *ch_set);

/* Get channel set containing all control channels for a band */
void map_get_ctl_channel_set(map_channel_set_t *ch_set, uint8_t band);

/* Get frequency band as string */
char *map_get_freq_band_str(uint8_t freq_band);

#endif /* MAP_INFO_H_ */
