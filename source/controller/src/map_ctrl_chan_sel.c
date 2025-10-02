/*
 * Copyright (c) 2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#include <json-c/json.h>

#define LOG_TAG "chan_sel"

#include "map_ctrl_chan_sel.h"
#include "map_ctrl_utils.h"
#include "map_ctrl_post_onboarding_handler.h"
#include "map_ctrl_defines.h"

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
typedef struct {
    map_channel_set_t ctl_channels;       /* latest common set of allowed control channels */
    map_channel_set_t align_ctl_channels; /* to be used common set of allowed control channels */
    map_channel_set_t bad_channels;       /* latest common set of bad channels */
    map_channel_set_t align_bad_channels; /* to be used common set of bad channels */
} chan_sel_multiap_band_t;

typedef struct {
    chan_sel_multiap_band_t band_2g;
    chan_sel_multiap_band_t band_5g;
    chan_sel_multiap_band_t band_6g;
    chan_sel_multiap_band_t band_unknown;
} chan_sel_multiap_t;

/*#######################################################################
#                       PROTOTYPES                                      #
########################################################################*/
static void multiap_radio_remove_cb(map_radio_info_t *radio);

static int set_def_pref_channels(map_radio_info_t *radio);
static int set_pref_channels(map_radio_info_t *radio);

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static chan_sel_multiap_t g_chan_sel_multiap;

static map_dm_cbs_t g_dm_cbs = {
    .radio_remove_cb = multiap_radio_remove_cb
};

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
static char *int_to_str(char *s, int len, int *val)
{
    if (val) {
       snprintf(s, len, "%d", *val);
    } else {
        map_strlcpy(s, "-", len);
    }

    return s;
}

static char *band_to_str(char *s, int len, map_radio_info_t *radio)
{
    char *b = map_get_freq_band_str(radio->supported_freq);

    if (radio->supported_freq == BAND_5G) {
        uint16_t bands = map_get_freq_bands(radio);
        char *sb = (bands == MAP_M2_BSS_RADIO5GL) ? "low" :
                   (bands == MAP_M2_BSS_RADIO5GU) ? "high" :
                   (bands == (MAP_M2_BSS_RADIO5GL | MAP_M2_BSS_RADIO5GU)) ? "low_high" : "unknown";

        snprintf(s, len, "%s %s", b, sb);
    } else {
        map_strlcpy(s, b, len);
    }

    return s;
}

static char *bool_to_str(char *s, int len, bool *val)
{
    map_strlcpy(s, val ? (*val ? "true" : "false") : "-", len);

    return s;
}

static void print_op_class_list(map_printf_cb_t print_cb, map_op_class_list_t *list, char *indent)
{
    int  i;
    char buf[MAP_CS_BUF_LEN];

    for (i = 0; i < list->op_classes_nr; i++) {
        map_op_class_t *op_class = &list->op_classes[i];

        print_cb("%sop_class[%d] pref[%d] reason[%d] channels[%s]\n",
                 indent, op_class->op_class, op_class->pref, op_class->reason,
                 map_cs_to_string(&op_class->channels, ',', buf, sizeof(buf)));
    }
}

static void set_added_removed_channels(map_channel_set_t *added_channels, map_channel_set_t *removed_channels,
                                       map_channel_set_t *prev_channels, map_channel_set_t *channels)
{
    if (added_channels) {
        map_cs_copy(added_channels, channels);
        map_cs_and_not(added_channels, prev_channels);
    }

    if (removed_channels) {
        map_cs_copy(removed_channels, prev_channels);
        map_cs_and_not(removed_channels, channels);
    }
}

static bool is_backhaul_radio(map_radio_info_t *radio)
{
    return map_radio_has_profile_with_bss_state(radio, MAP_BACKHAUL_BSS);
}

/*#######################################################################
#                       MULTIAP CHANNEL SELECTION                       #
########################################################################*/
static void get_multiap_timer_id(timer_id_t timer_id, uint8_t band)
{
    snprintf(timer_id, sizeof(timer_id_t), "%s_%s", CHAN_SEL_MULTIAP_ALIGN_TIMER_ID, map_get_freq_band_str(band));
}

static chan_sel_multiap_band_t *get_multiap_band(uint8_t band)
{
    switch (band) {
        case BAND_2G: return &g_chan_sel_multiap.band_2g;
        case BAND_5G: return &g_chan_sel_multiap.band_5g;
        case BAND_6G: return &g_chan_sel_multiap.band_6g;
        default:      return &g_chan_sel_multiap.band_unknown;
        break;
    }
}

static void print_multiap_band(map_printf_cb_t print_cb, uint8_t band, char *indent)
{
    chan_sel_multiap_band_t *b = get_multiap_band(band);
    char                     buf[MAP_CS_BUF_LEN];
    timer_id_t               timer_id;
    uint32_t                 align_backoff = 0;

    get_multiap_timer_id(timer_id, band);
    if (map_is_timer_registered(timer_id)) {
        map_timer_remaining(timer_id, &align_backoff);
    }

    print_cb("%sctl_channels      : [%s]\n",       indent, map_cs_to_string(&b->ctl_channels,       ',', buf, sizeof(buf)));
    print_cb("%salign_ctl_channels: [%s]\n",       indent, map_cs_to_string(&b->align_ctl_channels, ',', buf, sizeof(buf)));
    print_cb("%slpr_channels      : [%s]\n",       indent, map_cs_to_string(&b->bad_channels,       ',', buf, sizeof(buf)));
    print_cb("%salign_lpr_channels: [%s]\n",       indent, map_cs_to_string(&b->align_bad_channels, ',', buf, sizeof(buf)));
    print_cb("%salign_backoff     : %"PRIu32"s\n", indent, align_backoff);
}

/* Remove globally unsupported and bad channels from channel set.

   Keep original if resulting channel set would be empty
*/
static int multiap_align_channels(map_channel_set_t *channels, uint8_t band)
{
    chan_sel_multiap_band_t *multiap_band       = get_multiap_band(band);
    map_channel_set_t       *align_ctl_channels = &multiap_band->align_ctl_channels;
    map_channel_set_t       *align_bad_channels = &multiap_band->align_bad_channels;
    map_channel_set_t        channels_copy;

    /* Remove not supported channels */
    map_cs_copy(&channels_copy, channels);

    map_cs_and(&channels_copy, align_ctl_channels);

    if (map_cs_nr(&channels_copy) > 0) {
        map_cs_copy(channels, &channels_copy);
    }

    /* Remove bad channels */
    if (map_cs_nr(align_bad_channels) > 0) {
         map_cs_and_not(&channels_copy, align_bad_channels);

        if (map_cs_nr(&channels_copy) > 0) {
            map_cs_copy(channels, &channels_copy);
        }
    }

    return 0;
}

/* Test if multiap alignment would result in a different preference for
   other radios than the one that is being updated
   If yes, do device update and trigger channel selection
*/
static int multiap_test_align(map_radio_info_t *updated_radio, uint8_t band)
{
    map_ale_info_t   *ale;
    map_radio_info_t *radio;

    map_dm_foreach_agent_ale(ale) {
        map_dm_foreach_radio(ale, radio) {
            map_radio_chan_sel_t *chan_sel = &radio->chan_sel;
            map_channel_set_t     def_pref_channels_copy;
            map_channel_set_t     pref_channels_copy;

            /* Skip if:
               - radio is the one that is being updated
               - radio is other band
               - radio did not yet receive a preference report
               - radio is no backhaul radio
               - radio has fixed channel
            */
            if ((updated_radio && radio == updated_radio)                  ||
                radio->supported_freq != band                              ||
                !is_radio_state_channel_pref_report_received(radio->state) ||
                !is_backhaul_radio(radio)                                  ||
                !chan_sel->acs_enable) {
                continue;
            }

            /* Test if (default) preference would change. This will modify radio object
               but that is ok as on any change map_ctrl_chan_sel_update is called to
               do complete update.
            */
            map_cs_copy(&def_pref_channels_copy, &chan_sel->def_pref_channels);
            map_cs_copy(&pref_channels_copy, &chan_sel->pref_channels);

            set_def_pref_channels(radio);
            set_pref_channels(radio);

            /* Depending on what changed, do update and channel selection */
            if (map_cs_compare(&pref_channels_copy, &chan_sel->pref_channels)) {
                /* Update and send channel selection request */
                log_ctrl_i("[multiap_align] preferred channels changed for ale[%s] radio[%s] band[%s] -> update and select",
                           ale->al_mac_str, radio->radio_id_str, map_get_freq_band_str(band));

                map_ctrl_chan_sel_update(radio);
                map_agent_cancel_channel_selection(radio->ale);
                map_agent_handle_channel_selection(radio->ale, radio, MAP_CHAN_SEL_REQUEST);
            } else if (map_cs_compare(&def_pref_channels_copy, &chan_sel->def_pref_channels)) {
                /* Update only */
                log_ctrl_i("[multiap_align] default preferred channels changed for ale[%s] radio[%s] band[%s] -> update",
                           ale->al_mac_str, radio->radio_id_str, map_get_freq_band_str(band));

                map_ctrl_chan_sel_update(radio);
            }
        }
    }

    return 0;
}

static uint8_t multiap_timer_cb(UNUSED char *timer_id, void *arg)
{
    uint8_t                  band = (uintptr_t)arg;
    chan_sel_multiap_band_t *b = get_multiap_band(band);
    map_channel_set_t        added_ctl_channels;
    map_channel_set_t        removed_bad_channels;
    char                     cs_buf1[MAP_CS_BUF_LEN];
    char                     cs_buf2[MAP_CS_BUF_LEN];

    /* Sync align channel sets for this band */
    set_added_removed_channels(&added_ctl_channels, NULL,                  &b->align_ctl_channels, &b->ctl_channels);
    set_added_removed_channels(NULL,                &removed_bad_channels, &b->align_bad_channels, &b->bad_channels);

    log_ctrl_i("[multiap align] timer expired for band[%s] remove channel restriction ctl_channels[%s] bad_channels[%s]",
               map_get_freq_band_str(band),
               map_cs_to_string(&added_ctl_channels,   ',', cs_buf1, sizeof(cs_buf1)),
               map_cs_to_string(&removed_bad_channels, ',', cs_buf2, sizeof(cs_buf2)));

    map_cs_copy(&b->align_ctl_channels, &b->ctl_channels);
    map_cs_copy(&b->align_bad_channels, &b->bad_channels);

    /* Check if any radio needs to be updated and needs channel selection  */
    if ((map_cs_nr(&added_ctl_channels) > 0) || (map_cs_nr(&removed_bad_channels) > 0)) {
        multiap_test_align(NULL, band);
    }

    return 1; /* remove timer */
}

/* Modify channel sets for 5G radio that:
   - only support the low or high channels
   - is bandlocked

   ctl_channels: set all channels in the not supported band so they do
                 not affect the global ctl_channels

   bad_channels: unset all channels in the not supported band so they do
                 not affect the global bad_channels
*/
static void check_5g_low_high_bandlocked(map_radio_info_t *radio, map_channel_set_t *ctl_channels,
                                         map_channel_set_t *bad_channels)
{
    map_channel_set_t other_subband_ctl_channels;
    uint16_t          bands        = map_get_freq_bands(radio);
    bool              band_5g_low  = false;
    bool              band_5g_high = false;

    if (bands == MAP_M2_BSS_RADIO5GL) {
        band_5g_low = true;
    } else if (bands == MAP_M2_BSS_RADIO5GU) {
        band_5g_high = true;
    } else if (bands == (MAP_M2_BSS_RADIO5GL | MAP_M2_BSS_RADIO5GU)) {
        bandlock_5g_t bandlock_5g = get_controller_cfg()->chan_sel.bandlock_5g;

        if (bandlock_5g == MAP_BANDLOCK_5G_LOW) {
            band_5g_low = true;
        } else if (bandlock_5g == MAP_BANDLOCK_5G_HIGH) {
            band_5g_high = true;
        }
    }

    if (band_5g_low || band_5g_high) {
        /* Get ctl channel set of the not supported subband */
        if (band_5g_low) {
            map_get_5G_high_ctl_channel_set(&other_subband_ctl_channels);
        } else {
            map_get_5G_low_ctl_channel_set(&other_subband_ctl_channels);
        }

        /* ctl_channels: set all channels in the not supported subband */
        map_cs_or(ctl_channels, &other_subband_ctl_channels);

        /* bad_channels: unset all channels in the not supported subband */
        map_cs_and_not(bad_channels, &other_subband_ctl_channels);
    }
}

/* Perform multiap channel selection */
static int multiap_update(map_radio_info_t *updated_radio, bool remove)
{
    map_chan_sel_cfg_t      *cfg                = &get_controller_cfg()->chan_sel;
    map_ale_info_t          *ale;
    map_radio_info_t        *radio;
    uint8_t                  band               = updated_radio->supported_freq;
    chan_sel_multiap_band_t *multiap_band       = get_multiap_band(band);
    map_channel_set_t       *prev_ctl_channels  = &multiap_band->ctl_channels;
    map_channel_set_t       *prev_bad_channels  = &multiap_band->bad_channels;
    map_channel_set_t       *align_ctl_channels = &multiap_band->align_ctl_channels;
    map_channel_set_t       *align_bad_channels = &multiap_band->align_bad_channels;
    map_channel_set_t        ctl_channels;
    map_channel_set_t        bad_channels;
    map_channel_set_t        added_ctl_channels;
    map_channel_set_t        removed_ctl_channels;
    map_channel_set_t        added_bad_channels;
    map_channel_set_t        removed_bad_channels;
    timer_id_t               timer_id;
    char                     cs_buf1[MAP_CS_BUF_LEN];
    char                     cs_buf2[MAP_CS_BUF_LEN];

    /* Derive common set of allowed ctl and bad channels.
       - ctl_channels: start from all and "AND" with each radio
                       use cap_ctl_channels which are not affected by configuration
       - bad_channels: start from empty and "OR" with each radio
    */
    map_get_ctl_channel_set(&ctl_channels, band);
    map_cs_unset_all(&bad_channels);

    map_dm_foreach_agent_ale(ale) {
        map_dm_foreach_radio(ale, radio) {
            map_channel_set_t cap_ctl_channels_copy;
            map_channel_set_t bad_channels_copy;

            /* Skip when:
               - radio is being removed
               - radio is other band
            */
            if ((remove && radio == updated_radio) ||
                radio->supported_freq != band) {
                continue;
            }

            map_cs_copy(&cap_ctl_channels_copy, &radio->cap_ctl_channels);
            map_cs_copy(&bad_channels_copy, &radio->bad_channels);

            /* For dual 5G band and single 5G band with bandlock
               only the allowed subband must be considered
            */
            if (band == BAND_5G) {
                check_5g_low_high_bandlocked(radio, &cap_ctl_channels_copy, &bad_channels_copy);
            }

            map_cs_and(&ctl_channels, &cap_ctl_channels_copy);
            map_cs_or(&bad_channels, &bad_channels_copy);
        }
    }

    /* Check if ctl or bad channels changed. */
    if (!map_cs_compare(prev_ctl_channels, &ctl_channels) && !map_cs_compare(prev_bad_channels, &bad_channels)) {
        /* Nothing to do... */
        return 0;
    }

    /* Check if channels are added and/or removed */
    set_added_removed_channels(&added_ctl_channels, &removed_ctl_channels, prev_ctl_channels, &ctl_channels);
    set_added_removed_channels(&added_bad_channels, &removed_bad_channels, prev_bad_channels, &bad_channels);

    /* Update last channel sets */
    map_cs_copy(prev_ctl_channels, &ctl_channels);
    map_cs_copy(prev_bad_channels, &bad_channels);

    /* Two types of actions are possible:
       - When there is a new restriction (removed ctl channels or added bad channels),
         align_channels is updated and channel selection of all radios in this band
         is checked.
       - When a restriction is removed (added ctl channels or removed bad channels),
         a long timer is started.  When that expires, align_channels is updated and
         channel selection of all radios in this band is checked.

         This is done to avoid toggling channel preferences.
    */
    if ((map_cs_nr(&removed_ctl_channels) > 0) || (map_cs_nr(&added_bad_channels) > 0)) {
        log_ctrl_i("[multiap_align] add channel restriction ale[%s] radio[%s] band[%s] ctl_channels[%s] bad_channels[%s]",
                   updated_radio->ale->al_mac_str, updated_radio->radio_id_str,
                   map_get_freq_band_str(band),
                   map_cs_to_string(&removed_ctl_channels, ',', cs_buf1, sizeof(cs_buf1)),
                   map_cs_to_string(&added_bad_channels,   ',', cs_buf2, sizeof(cs_buf2)));

        map_cs_and_not(align_ctl_channels, &removed_ctl_channels);
        map_cs_or(align_bad_channels, &added_bad_channels);

        multiap_test_align(updated_radio, band);
    }

    if ((map_cs_nr(&added_ctl_channels) > 0) || (map_cs_nr(&removed_bad_channels) > 0)) {
        log_ctrl_i("[multiap_align] remove channel restriction ale[%s] radio[%s] band[%s] ctl_channels[%s] bad_channels[%s]",
                   updated_radio->ale->al_mac_str, updated_radio->radio_id_str,
                   map_get_freq_band_str(band),
                   map_cs_to_string(&added_ctl_channels,   ',', cs_buf1, sizeof(cs_buf1)),
                   map_cs_to_string(&removed_bad_channels, ',', cs_buf2, sizeof(cs_buf2)));
    }

    /* Start or restart timer when aligned set if not the same as latest set
       NOTE: Currently there is only one timer per band.  It is (re)started when
             a restriction is removed and restarted when a restriction is added.
             The result is that the state must be "stable" for the complete
             timer period before restricted channels are allowed again
    */
    get_multiap_timer_id(timer_id, band);
    if (map_cs_compare(align_ctl_channels, &ctl_channels) || map_cs_compare(align_bad_channels, &bad_channels)) {
        /* Timer needs to run: start or restart */
        if (map_is_timer_registered(timer_id)) {
            log_ctrl_i("[multiap_align] restarting timer for band[%s]", map_get_freq_band_str(band));

            if (map_timer_restart_callback(timer_id)) {
                log_ctrl_e("failed restarting timer[%s]", timer_id);
            }
        } else {
            uint32_t backoff_time = cfg->align_multiap_backoff_time;

            log_ctrl_i("[multiap_align] starting timer for band[%s] backoff[%"PRIu32"]",
                       map_get_freq_band_str(band), backoff_time);

            if (map_timer_register_callback(backoff_time, timer_id, (void*)(uintptr_t)band, multiap_timer_cb)) {
                log_ctrl_e("failed registering timer[%s]", timer_id);
            }
        }
    } else {
        /* Timer does not need to run */
        if (map_is_timer_registered(timer_id)) {
            log_ctrl_i("[multiap_align] stopping timer for band[%s]", map_get_freq_band_str(band));

            map_timer_unregister_callback(timer_id);
        }
    }

    return 0;
}

static void multiap_radio_remove_cb(map_radio_info_t *radio)
{
    multiap_update(radio, true);
}

/*#######################################################################
#                       DEVICE CHANNEL SELECTION                        #
########################################################################*/
static bool is_bad_preference(map_op_class_t *op_class)
{
    /* Agent can indicate allowed but bad channels in the following way:
       - Preference: 1
       - Reason: 1, 5 or 6
    */

    if (op_class->pref == 1) {
        if (op_class->reason == MAP_PREF_REASON_NON80211_INTF ||
            op_class->reason == MAP_PREF_REASON_REDUCED_TPUT  ||
            op_class->reason == MAP_PREF_REASON_INDEVICE_INTF) {
                return true;
        }
    }

    return false;
}

/* Set bad control channel list.

   These are all control channels the agent has marked with a bad preference.
*/
static int set_bad_channels(map_radio_info_t *radio)
{
    map_op_class_list_t *list = &radio->pref_op_class_list;
    int                  i;

    map_cs_unset_all(&radio->bad_channels);

    for (i = 0; i < list->op_classes_nr; i++) {
        map_op_class_t *op_class = &list->op_classes[i];
        uint16_t        bw;

        /* Only look at 20MHz operating classes */
        if (map_get_bw_from_op_class(op_class->op_class, &bw) || bw != 20) {
            continue;
        }

        if (is_bad_preference(op_class)) {
            map_cs_or(&radio->bad_channels, &op_class->channels);
        }
    }

    return 0;
}

/* Set default preferred control channel list (aka default acs list).

   - Start from global config.
   - Remove all control channels that are not supported (in ap capability report).
   - Remove all bad channels
   - If enabled, remove channels that cannot be used because of multiap alignment
*/
static int set_def_pref_channels(map_radio_info_t *radio)
{
    map_chan_sel_cfg_t *cfg      = &get_controller_cfg()->chan_sel;
    map_channel_set_t  *channels = &radio->chan_sel.def_pref_channels;
    map_channel_set_t   channels_copy;

    switch(radio->supported_freq) {
        case BAND_2G:
            map_cs_copy(channels, &cfg->default_pref_channel_set_2g);
        break;
        case BAND_5G:
            map_cs_copy(channels, &cfg->default_pref_channel_set_5g);
        break;
        case BAND_6G:
            map_cs_copy(channels, &cfg->default_pref_channel_set_6g);
        break;
        default:
            map_cs_unset_all(channels);
        break;
    }

    /* Remove not supported channels */
    map_cs_and(channels, &radio->ctl_channels);

    /* Remove bad channels (if not all bad) */
    if (map_cs_nr(&radio->bad_channels) > 0) {
        map_cs_copy(&channels_copy, channels);

        map_cs_and_not(&channels_copy, &radio->bad_channels);

        if (map_cs_nr(&channels_copy) > 0) {
            map_cs_copy(channels, &channels_copy);
        }
    }

    /* Do multiap alignment */
    if (cfg->align_multiap && is_backhaul_radio(radio)) {
        multiap_align_channels(channels, radio->supported_freq);
    }

    return 0;
}

/* Set control channel channel list (aka acs list).

   - Start from what has been configured (by cloud) when cloud_mgmt_enable is true
   - Remove all control channels that are not supported (in ap capability report).
   - Remove all bad channels
   - If enabled, remove channels that cannot be used because of multiap alignment

NOTES:
   - When the resulting list is empty, fall back to the default.
   - It is allowed that this list contains channels that are not in the default
     preferred control channe list.
*/
static int set_pref_channels(map_radio_info_t *radio)
{
    map_chan_sel_cfg_t   *cfg      = &get_controller_cfg()->chan_sel;
    map_radio_chan_sel_t *chan_sel = &radio->chan_sel;
    map_channel_set_t    *channels = &radio->chan_sel.pref_channels;

    /* When cloud mgmt is enabled, start from channels set by cloud */
    if (chan_sel->cloud_mgmt_enable) {
        map_cs_copy(channels, &chan_sel->acs_channels);
    } else {
        map_cs_copy(channels, &chan_sel->def_pref_channels);
    }

    /* Remove not supported channels */
    map_cs_and(channels, &radio->ctl_channels);

    /* Remove bad channels */
    map_cs_and_not(channels, &radio->bad_channels);

    /* Do multiap alignment */
    if ((map_cs_nr(channels) > 0) && cfg->align_multiap && is_backhaul_radio(radio)) {
        multiap_align_channels(channels, radio->supported_freq);
    }

    /* If empty -> revert to default preferred channel list */
    if (map_cs_nr(channels) == 0) {
        map_cs_copy(channels, &chan_sel->def_pref_channels);

        /* If still empty (config error??) -> revert to allowed channel list */
        if (map_cs_nr(channels) == 0) {
            map_cs_copy(channels, &radio->ctl_channels);
        }
    }

    return 0;
}

/* Check if channel is available in the cac status report */
static bool is_channel_available(map_radio_info_t *radio, uint8_t op_class, uint8_t channel)
{
    map_ale_info_t           *ale      = radio->ale;
    map_cac_available_pair_t *pairs    = ale->cac_status_report.available_pairs;
    uint8_t                   pairs_nr = ale->cac_status_report.available_pairs_nr;
    uint8_t                   i;

    for (i = 0; i < pairs_nr; i++) {
        map_cac_available_pair_t *pair = &pairs[i];

        if (pair->op_class == op_class && pair->channel == channel) {
            return true;
        }
    }

    return false;
}

/* Lower preference for not cleared EU weatherband channels.
   This is to avoid triggering the agent to perform 10 minute
   Continuous CAC
*/
static int set_eu_weatherband_preference(map_radio_info_t *radio)
{
    int pref_idx = radio->ctrl_pref_op_class_list.op_classes_nr;
    int i;

    for (i = 0; i < radio->cap_op_class_list.op_classes_nr; i++) {
        map_op_class_t    *cap_op_class  = &radio->cap_op_class_list.op_classes[i];
        map_op_class_t    *pref_op_class = &radio->ctrl_pref_op_class_list.op_classes[pref_idx];
        uint8_t            op_class      = cap_op_class->op_class;
        bool               is_center_chan;
        map_channel_set_t  ch_set;
        int                chan;
        uint8_t            op_class_chan;
        bool               op_class_added = false;

        if (!map_is_5G_weatherband_op_class(op_class)) {
            continue;
        }

        if (map_get_is_center_channel_from_op_class(op_class, &is_center_chan)) {
            continue;
        }

        if (map_get_channel_set_from_op_class(op_class, &ch_set)) {
            continue;
        }

        map_cs_foreach(&ch_set, chan) {
            if (!map_is_channel_in_cap_op_class(cap_op_class, chan)) {
                continue;
            }

            /* Skip if not weatherband */
            if (!map_is_5G_weatherband_channel(op_class, chan)) {
                continue;
            }

            /* Use center channel for center channel op_classes */
            if (is_center_chan) {
                if (map_get_center_channel(op_class, chan, &op_class_chan)) {
                    continue;
                }
            } else {
                op_class_chan = chan;
            }

            /* Skip if channel is available (cleared) in cac status report */
            if (is_channel_available(radio, op_class, op_class_chan)) {
                continue;
            }

            /* Skip if channel already added with lower prio */
            if (map_get_channel_pref(&radio->ctrl_pref_op_class_list, op_class, op_class_chan) < MAP_PREF_SCORE_15) {
               continue;
            }

            /* Add op_class */
            if (!op_class_added) {
                memset(pref_op_class, 0, sizeof(map_op_class_t));
                pref_op_class->op_class = op_class;
                pref_op_class->pref     = MAP_PREF_SCORE_14;
                pref_op_class->reason   = MAP_PREF_REASON_DFS_PASSIVE;

                op_class_added = true;
            }

            /* Add channel */
            map_cs_set(&pref_op_class->channels, op_class_chan);
        }

        if (op_class_added) {
            pref_idx++;
        }
    }

    radio->ctrl_pref_op_class_list.op_classes_nr = pref_idx;

    return 0;
}

/* Set controller preferred operating class list.

   - Go over all supported operating classes and channels from the ap capability report
   - Set 0 prerference for op_class/channel that are not allowed because:
     - control channel not in "channels" list
     - bandwidth above configred value

NOTES:
   - For center channel operating classes: keep channels allowed as long as there is at least
     one of the 20MHz subband channels is allowed.
   - Optimization: when all channels in an operating class have preference 0,
     the channel count is set to 0 (= applies to whole operating class).
*/
static int set_controller_pref_op_class_list(map_radio_info_t *radio, map_channel_set_t *channels)
{
    map_chan_sel_cfg_t *cfg               = &get_controller_cfg()->chan_sel;
    bool                is_6g_psc         = (radio->supported_freq == BAND_6G) && cfg->allowed_channel_6g_psc;
    uint16_t            allowed_bandwidth = map_get_allowed_bandwidth(radio->supported_freq);
    uint16_t            bandwidth         = radio->chan_sel.bandwidth;
    int                 pref_idx          = 0;
    int                 extra_alloc_nr    = radio->cac_caps.has_eu_weatherband ? map_get_5G_weatherband_op_class_nr() : 0;
    int                 i;

    /* Max number of operation classes is radio->cap_op_class_count + extra_alloc_nr ( + 1 to avoid malloc(0) )*/
    int alloc_nr             = radio->cap_op_class_list.op_classes_nr + extra_alloc_nr;
    map_op_class_t *new_list = realloc(radio->ctrl_pref_op_class_list.op_classes, alloc_nr * sizeof(map_op_class_t) + 1);
    if (NULL == new_list) {
        SFREE(radio->ctrl_pref_op_class_list.op_classes);
        radio->ctrl_pref_op_class_list.op_classes_nr = 0;
        goto fail;
    }
    radio->ctrl_pref_op_class_list.op_classes = new_list;

    /* Implementation version 1:
       - Base on list of oper classes from AP Basic capability TLV
       - Make all channels not in channels not operable
    */

    for (i = 0; i < radio->cap_op_class_list.op_classes_nr; i++) {
        map_op_class_t    *cap_op_class   = &radio->cap_op_class_list.op_classes[i];
        map_op_class_t    *pref_op_class  = &radio->ctrl_pref_op_class_list.op_classes[pref_idx];
        uint8_t            op_class       = cap_op_class->op_class;
        bool               op_class_added = false;
        map_channel_set_t  ch_set;
        bool               is_center_chan;
        uint8_t            chan;
        uint8_t            center_chan;
        uint16_t           bw;

        if (map_get_bw_from_op_class(op_class, &bw)) {
            continue;
        }
        if (map_get_is_center_channel_from_op_class(op_class, &is_center_chan)) {
            continue;
        }
        if (map_get_channel_set_from_op_class(op_class, &ch_set)) {
            continue;
        }

#define ADD_OP_CLASS                                          \
        if (!op_class_added) {                                \
            memset(pref_op_class, 0, sizeof(map_op_class_t)); \
            pref_op_class->op_class = op_class;               \
            pref_op_class->pref     = 0; /* Unoperable  */    \
            pref_op_class->reason   = 0; /* Unspecified */    \
            op_class_added          = true;                   \
            pref_idx++;                                       \
        }

#define ADD_CHANNEL(channel) \
        ADD_OP_CLASS              \
        map_cs_set(&pref_op_class->channels, channel);

        /* Unconditionally reject 80 + 80 operating classes */
        if (map_is_80p80_op_class(op_class)) {
            /* Add op_class with 0 channels */
            ADD_OP_CLASS
            continue;
        }

        /* Add opclass with empty channel list if bw is too high */
        if ((allowed_bandwidth > 0 && bw > allowed_bandwidth) ||
            (bandwidth > 0 && bw > bandwidth)) {
            /* Add op_class with 0 channels */
            ADD_OP_CLASS
            continue;
        }

        /* Loop over all channels in op_class */
        map_cs_foreach(&ch_set, chan) {
            if (!map_is_6G_320MHz_op_class(op_class)) {
                /* Checks also if channel is in non operable list */
                if (!map_is_channel_in_cap_op_class(cap_op_class, chan)) {
                    continue;
                }

                if (!is_center_chan) {
                    if (!map_cs_is_set(channels, chan)) {
                        /* block because primary channel is not set */
                        ADD_CHANNEL(chan);
                    } else if (bw > 20 && !is_6g_psc && !map_is_all_subband_channel_set(&radio->ctl_channels, op_class, chan)) {
                        /* block because secondary is not set (40MHz only) */
                        ADD_CHANNEL(chan);
                    }
                } else {
                    /* For 40 (6G), 80, 160 and 320MHz, the center channel needs to be added */
                    if (!map_get_center_channel(op_class, chan, &center_chan)) {
                        if (map_is_no_subband_channel_set(channels, op_class, chan)) {
                            /* block because none of the subband channels are preferred */
                            ADD_CHANNEL(center_chan);
                        } else if (!is_6g_psc && !map_is_all_subband_channel_set(&radio->ctl_channels, op_class, chan)) {
                            /* block because one of the subband channels is allowed */
                            ADD_CHANNEL(center_chan);
                        }
                    }
                }
            } else {
                /* 6G 320MHz is special because it has 2 overlapping sets of channels -> check both */
                foreach_bool(upper) {
                    if (map_is_channel_in_cap_op_class_6G_320MHz(cap_op_class, upper, chan)) {
                        if (!map_get_center_channel_6G_320MHz(op_class, upper, chan, &center_chan)) {
                            if (map_is_no_subband_channel_set_6G_320MHz(channels, op_class, upper, chan)) {
                                /* block because none of the subband channels are preferred */
                                ADD_CHANNEL(center_chan);
                            } else if (!is_6g_psc && !map_is_all_subband_channel_set_6G_320MHz(&radio->ctl_channels, op_class, upper, chan)) {
                                /* block because one of the subband channels is not allowed */
                                ADD_CHANNEL(center_chan);
                            }
                        }
                    }
                }
            }
        }
#undef ADD_OP_CLASS
#undef ADD_CHANNEL
    }
    radio->ctrl_pref_op_class_list.op_classes_nr = pref_idx;

    /* For 5G with ACS enabled, reduce prio of un-cleared EU weatherband channels */
    if (radio->cac_caps.has_eu_weatherband && radio->chan_sel.acs_enable) {
        set_eu_weatherband_preference(radio);
    }

    return 0;

fail:
    return -1;
}

/* Set agent and controller merged operating class list.

   This function combines both preference lists and keeps
   the lowest preference for each operating class and channel
   combination.
*/
static int set_merged_pref_op_class_list(map_radio_info_t *radio)
{
    SFREE(radio->merged_pref_op_class_list.op_classes);
    radio->merged_pref_op_class_list.op_classes_nr = 0;

    return map_merge_pref_op_class_list(&radio->merged_pref_op_class_list, &radio->cap_op_class_list,
                                        &radio->ctrl_pref_op_class_list, &radio->pref_op_class_list,
                                        &radio->disallowed_op_class_list);
}

/* Update all preferred control channel and operating class lists. */
static int update_pref_channel_op_class_list(map_ale_info_t *ale, map_radio_info_t *radio)
{
    map_radio_chan_sel_t *chan_sel = &radio->chan_sel;
    map_channel_set_t     channels;

    if (set_bad_channels(radio)) {
        log_ctrl_e("failed setting bad channel list for ale[%s] radio[%s]",
                   ale->al_mac_str, radio->radio_id_str);
        goto fail;
    }

    if (set_def_pref_channels(radio)) {
        log_ctrl_e("failed setting default preferred channel list for ale[%s] radio[%s]",
                   ale->al_mac_str, radio->radio_id_str);
        goto fail;
    }

    if (set_pref_channels(radio)) {
        log_ctrl_e("failed setting preferred channel list for ale[%s] radio[%s]",
                   ale->al_mac_str, radio->radio_id_str);
        goto fail;
    }

    /* For controller: check if fixed or not */
    if (!chan_sel->acs_enable && chan_sel->channel > 0 && map_cs_is_set(&radio->ctl_channels, chan_sel->channel)) {
        map_cs_unset_all(&channels);
        map_cs_set(&channels, chan_sel->channel);
    } else {
        map_cs_copy(&channels, &chan_sel->pref_channels);
    }

    if (set_controller_pref_op_class_list(radio, &channels)) {
        log_ctrl_e("failed setting controller preferred operating class list for ale[%s] radio[%s]",
                   ale->al_mac_str, radio->radio_id_str);
        goto fail;
    }

    if (set_merged_pref_op_class_list(radio)) {
        log_ctrl_e("failed merging preferred operating class list for ale[%s] radio[%s]",
                   ale->al_mac_str, radio->radio_id_str);
        goto fail;
    }

    return 0;

fail:
    return -1;
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
int map_ctrl_chan_sel_set(map_radio_info_t *radio, bool *cloud_mgmt_enable, bool *acs_enable,
                          map_channel_set_t *acs_channels, int *channel, int *bandwidth)
{
    map_ale_info_t       *ale            = radio->ale;
    map_radio_chan_sel_t *chan_sel       = &radio->chan_sel;
    bool                  new_acs_enable = acs_enable ? *acs_enable : chan_sel->acs_enable;
    int                   new_channel    = channel ? *channel : chan_sel->channel;
    char                  cs_str[MAP_CS_BUF_LEN];
    char                  cloud_mgmt_enable_str[16];
    char                  acs_enable_str[16];
    char                  channel_str[16];
    char                  bandwidth_str[16];

    log_ctrl_i("set ale[%s] radio[%s]: cloud_mgmt_enable[%s] acs_enable[%s] acs_channels[%s] channel[%s] bandwidth[%s]",
               radio->ale->al_mac_str, radio->radio_id_str,
               bool_to_str(cloud_mgmt_enable_str, sizeof(cloud_mgmt_enable_str), cloud_mgmt_enable),
               bool_to_str(acs_enable_str, sizeof(acs_enable_str), acs_enable),
               acs_channels ? map_cs_to_string(acs_channels, ',', cs_str, sizeof(cs_str)) : "-",
               int_to_str(channel_str, sizeof(channel_str), channel),
               int_to_str(bandwidth_str, sizeof(bandwidth_str), bandwidth));

    if ((radio->supported_freq == IEEE80211_FREQUENCY_BAND_UNKNOWN) || (map_cs_nr(&radio->ctl_channels) == 0)) {
        log_ctrl_e("cannot set chan_sel for radio[%s] band/ctl_channels not known", radio->radio_id_str);
        goto fail;
    }

    /* Sync acs_enable and channel - acs_enable has precedence */
    if (acs_enable) {
       if (new_acs_enable) {
           new_channel = 0;
        }
    } else if (channel) {
        new_acs_enable = new_channel == 0;
    }

    /* Validate fixed channel */
    if (!new_acs_enable && new_channel > 0) {
        if (!map_cs_is_set(&radio->ctl_channels, new_channel)) {
            new_acs_enable = true;
            new_channel = 0;
        }
    }

    map_dm_radio_set_chan_sel(radio,
                              cloud_mgmt_enable ? *cloud_mgmt_enable : chan_sel->cloud_mgmt_enable,
                              new_acs_enable,
                              acs_channels      ? acs_channels       : &chan_sel->acs_channels,
                              new_channel,
                              bandwidth         ? *bandwidth         : chan_sel->bandwidth);

    /* Update preferred channels */
    if (update_pref_channel_op_class_list(ale, radio)) {
        log_ctrl_e("failed updating preferred channel and operating class list for ale[%s] radio[%s]",
                   ale->al_mac_str, radio->radio_id_str);
        goto fail;
    }

    /* Do channel selection */
    map_agent_cancel_channel_selection(radio->ale);
    map_agent_handle_channel_selection(radio->ale, radio, MAP_CHAN_SEL_REQUEST);

    return 0;

fail:
    return -1;
}

int map_ctrl_chan_sel_set_channel(map_radio_info_t *radio, int channel)
{
    return map_ctrl_chan_sel_set(radio, NULL, NULL, NULL, &channel, NULL);
}

int map_ctrl_chan_sel_set_bandwidth(map_radio_info_t *radio, int bandwidth)
{
    return map_ctrl_chan_sel_set(radio, NULL, NULL, NULL, NULL, &bandwidth);
}

int map_ctrl_chan_sel_set_cloud_mgmt_enable(map_radio_info_t *radio, bool enable)
{
    return map_ctrl_chan_sel_set(radio, &enable, NULL, NULL, NULL, NULL);
}

int map_ctrl_chan_sel_update(map_radio_info_t *radio)
{
    map_chan_sel_cfg_t   *cfg      = &get_controller_cfg()->chan_sel;
    map_ale_info_t       *ale      = radio->ale;
    map_radio_chan_sel_t *chan_sel = &radio->chan_sel;

    if ((radio->supported_freq == IEEE80211_FREQUENCY_BAND_UNKNOWN) || (map_cs_nr(&radio->ctl_channels) == 0)) {
        log_ctrl_e("cannot update chan_sel for ale[%s] radio[%s] band/ctl_channels not known",
                   ale->al_mac_str, radio->radio_id_str);
        goto fail;
    }

    /* Check if fixed channel still possible, switch to auto if not */
    if (!chan_sel->acs_enable && chan_sel->channel > 0) {
        if (!map_cs_is_set(&radio->ctl_channels, chan_sel->channel)) {
            map_dm_radio_set_chan_sel(radio, chan_sel->cloud_mgmt_enable, true, &chan_sel->acs_channels, 0, chan_sel->bandwidth);
        }
    }

    if (update_pref_channel_op_class_list(ale, radio)) {
        log_ctrl_e("failed updating preferred channel and operating class list for ale[%s] radio[%s]",
                   ale->al_mac_str, radio->radio_id_str);
        goto fail;
    }

    /* multiap_update */
    if (cfg->align_multiap) {
        if (multiap_update(radio, false)) {
            log_ctrl_e("failed updating multiap channel selection");
            goto fail;
        }
    }

    return 0;

fail:
    return -1;
}

void map_ctrl_chan_sel_dump(map_printf_cb_t print_cb, map_ale_info_t *req_ale, bool extended)
{
    map_chan_sel_cfg_t *cfg       = &get_controller_cfg()->chan_sel;
    map_ale_info_t     *ale;
    map_radio_info_t   *radio;
    bool                first_ale = true;
    char                buf[MAP_CS_BUF_LEN];

    if (req_ale == NULL) {
        print_cb("GLOBAL\n");
        print_cb("    config:\n");
        print_cb("      align_multiap        : %s\n",         bool_to_str(buf, sizeof(buf), &cfg->align_multiap));
        print_cb("      align_multiap_backoff: %"PRIu32"s\n", cfg->align_multiap_backoff_time);
        print_cb("\n");
        print_cb("  BAND[2G]\n");
        print_multiap_band(print_cb, BAND_2G, "    ");
        print_cb("\n");
        print_cb("  BAND[5G]\n");
        print_multiap_band(print_cb, BAND_5G, "    ");
        print_cb("\n");
        print_cb("  BAND[6G]\n");
        print_multiap_band(print_cb, BAND_6G, "    ");
        print_cb("\n\n");
    }

    map_dm_foreach_agent_ale(ale) {
        bool first_radio = true;

        if (req_ale && ale != req_ale) {
            continue;
        }

        if (!first_ale) {
           print_cb("\n\n");
        }
        first_ale = false;

        print_cb("ALE[%s]\n", ale->al_mac_str);

        map_dm_foreach_radio(ale, radio) {
            map_radio_chan_sel_t *chan_sel    = &radio->chan_sel;
            bool                  is_backhaul = is_backhaul_radio(radio);

            if (!first_radio) {
                print_cb("\n");
            }
            first_radio = false;

            print_cb("  RADIO[%s][%s]\n", radio->radio_id_str, band_to_str(buf, sizeof(buf), radio));
            print_cb("    config:\n");
            print_cb("      cloud_mgmt_enable: %s\n",   bool_to_str(buf, sizeof(buf), &chan_sel->cloud_mgmt_enable));
            print_cb("      acs_enable       : %s\n",   bool_to_str(buf, sizeof(buf), &chan_sel->acs_enable));
            print_cb("      acs_channels     : [%s]\n", map_cs_to_string(&chan_sel->acs_channels, ',', buf, sizeof(buf)));
            print_cb("      channel          : %d\n",   chan_sel->channel);
            print_cb("      bandwidth        : %d\n",   chan_sel->bandwidth);
            print_cb("      backhaul         : %s\n",   bool_to_str(buf, sizeof(buf), &is_backhaul));
            print_cb("    state:\n");
            print_cb("      channel          : %d\n",   radio->current_op_channel);
            print_cb("      bandwidth        : %d\n",   radio->current_bw);
            print_cb("      op_class         : %d\n",   radio->current_op_class);
            print_cb("      curr_op_classes:\n");
            print_op_class_list(print_cb, &radio->curr_op_class_list, "        ");
            print_cb("      cap_ctl_channels : [%s]\n", map_cs_to_string(&radio->cap_ctl_channels, ',', buf, sizeof(buf)));
            print_cb("      ctl_channels     : [%s]\n", map_cs_to_string(&radio->ctl_channels, ',', buf, sizeof(buf)));
            print_cb("      pref_channels    : [%s]\n", map_cs_to_string(&chan_sel->pref_channels, ',', buf, sizeof(buf)));
            print_cb("      def_pref_channels: [%s]\n", map_cs_to_string(&chan_sel->def_pref_channels, ',', buf, sizeof(buf)));
            print_cb("      low_pref_channels: [%s]\n", map_cs_to_string(&radio->bad_channels, ',', buf, sizeof(buf)));
            print_cb("      eu_weatherband   : [%s]\n", bool_to_str(buf, sizeof(buf), &radio->cac_caps.has_eu_weatherband));
            if (extended) {
                print_cb("      agent_cap:\n");
                print_op_class_list(print_cb, &radio->cap_op_class_list, "        ");
                print_cb("      agent_pref:\n");
                print_op_class_list(print_cb, &radio->pref_op_class_list, "        ");
                print_cb("      ctrl_pref:\n");
                print_op_class_list(print_cb, &radio->ctrl_pref_op_class_list, "        ");
                print_cb("      disallowed:\n");
                print_op_class_list(print_cb, &radio->disallowed_op_class_list, "        ");
                print_cb("      merged_pref:\n");
                print_op_class_list(print_cb, &radio->merged_pref_op_class_list, "        ");
            }
        }
    }
}

int map_ctrl_chan_sel_init(void)
{
    static const uint8_t bands[] = {BAND_2G, BAND_5G, BAND_6G, BAND_UNKNOWN};
    uint8_t i;

    map_dm_register_cbs(&g_dm_cbs);

    /* Initialise multiap align channel sets (no restriction) */
    for (i = 0; i < ARRAY_SIZE(bands); i++) {
        uint8_t band = bands[i];
        chan_sel_multiap_band_t *b = get_multiap_band(band);

        if (band != BAND_UNKNOWN) {
            map_get_ctl_channel_set(&b->ctl_channels, band);
        } else {
            map_cs_set_all(&b->ctl_channels);
        }
        map_cs_unset_all(&b->bad_channels);

        map_cs_copy(&b->align_ctl_channels, &b->ctl_channels);
        map_cs_copy(&b->align_bad_channels, &b->bad_channels);
    }

    return 0;
}

void map_ctrl_chan_sel_fini(void)
{
    map_timer_unregister_callback_prefix(CHAN_SEL_MULTIAP_ALIGN_TIMER_ID);

    map_dm_unregister_cbs(&g_dm_cbs);
}
