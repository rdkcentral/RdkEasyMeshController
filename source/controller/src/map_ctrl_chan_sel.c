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
#                       GLOBALS                                         #
########################################################################*/
static chan_sel_multiap_t g_chan_sel_multiap;

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

static bool is_backhaul_radio(map_radio_info_t *radio)
{
    return map_radio_has_profile_with_bss_state(radio, MAP_BACKHAUL_BSS);
}

/*#######################################################################
#                       MULTIAP CHANNEL SELECTION                       #
########################################################################*/
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

    print_cb("%sctl_channels      : [%s]\n",       indent, map_cs_to_string(&b->ctl_channels,       ',', buf, sizeof(buf)));
    print_cb("%salign_ctl_channels: [%s]\n",       indent, map_cs_to_string(&b->align_ctl_channels, ',', buf, sizeof(buf)));
    print_cb("%slpr_channels      : [%s]\n",       indent, map_cs_to_string(&b->bad_channels,       ',', buf, sizeof(buf)));
    print_cb("%salign_lpr_channels: [%s]\n",       indent, map_cs_to_string(&b->align_bad_channels, ',', buf, sizeof(buf)));
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

    return 0;
}

/* Set control channel channel list (aka acs list).

   - Start from what has been configured (by cloud).
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
    map_radio_chan_sel_t *chan_sel = &radio->chan_sel;
    map_channel_set_t    *channels = &radio->chan_sel.pref_channels;

    map_cs_copy(channels, &chan_sel->acs_channels);

    /* Remove not supported channels */
    map_cs_and(channels, &radio->ctl_channels);

    /* Remove bad channels */
    map_cs_and_not(channels, &radio->bad_channels);

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
    map_chan_sel_cfg_t *cfg = &get_controller_cfg()->chan_sel;
    bool                is_6g_psc = (radio->supported_freq == BAND_6G) && cfg->allowed_channel_6g_psc;
    uint16_t            bandwidth = radio->chan_sel.bandwidth;
    uint16_t            global_bandwidth = 0;
    int                 i;
    int                 pref_idx = 0;
    int                 extra_alloc_nr = radio->cac_caps.has_eu_weatherband ? map_get_5G_weatherband_op_class_nr() : 0;

    /* Max number of operation classes is radio->cap_op_class_count + extra_alloc_nr ( + 1 to avoid malloc(0) )*/
    int alloc_nr             = radio->cap_op_class_list.op_classes_nr + extra_alloc_nr;
    map_op_class_t *new_list = realloc(radio->ctrl_pref_op_class_list.op_classes, alloc_nr * sizeof(map_op_class_t) + 1);
    if (NULL == new_list) {
        SFREE(radio->ctrl_pref_op_class_list.op_classes);
        radio->ctrl_pref_op_class_list.op_classes_nr = 0;
        goto fail;
    }
    radio->ctrl_pref_op_class_list.op_classes = new_list;

    /* Get global max bandwidth */
    switch(radio->supported_freq) {
        case BAND_2G: global_bandwidth = cfg->allowed_bandwidth_2g; break;
        case BAND_5G: global_bandwidth = cfg->allowed_bandwidth_5g; break;
        case BAND_6G: global_bandwidth = cfg->allowed_bandwidth_6g; break;
        default:      global_bandwidth = 0; break; /* Should not happen */
    }

    /* Implementation version 1:
       - Base on list of oper classes from AP Basic capability TLV
       - Make all channels not in channels not operable
    */

    for (i = 0; i < radio->cap_op_class_list.op_classes_nr; i++) {
        map_op_class_t    *cap_op_class  = &radio->cap_op_class_list.op_classes[i];
        map_op_class_t    *pref_op_class = &radio->ctrl_pref_op_class_list.op_classes[pref_idx];
        map_channel_set_t  ch_set;
        bool               add_op_class  = false;
        bool               add_all_chan  = false;
        bool               is_center_chan;
        uint8_t            op_class      = cap_op_class->op_class;
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

        /* Add opclass with empty channel list if bw is too high */
        if ((global_bandwidth > 0 && bw > global_bandwidth) ||
            (bandwidth > 0 && bw > bandwidth)) {
            add_op_class = true;
            add_all_chan = true;
        }

        map_cs_foreach(&ch_set, chan) {
            if (!map_is_channel_in_cap_op_class(cap_op_class, chan)) {
                continue;
            }

            if (bw != 20) {
                /* check if ALL subband channels are allowed (according to radio allowed list)
                   exception: when 6G psc channels have been configured subbands are allowed
                */
                if (!is_6g_psc && !map_is_all_subband_channel_set(&radio->ctl_channels, chan, op_class)) {
                    add_op_class = true;
                    break;
                }
            }

            /* For 20 and 40MHz (2G and 5G), check "this" channel is allowed,
               For 40MHz (6G), 80, 160 and 320MHz, check if any subband channel is allowed.
            */
            if (!is_center_chan) {
                if (!map_cs_is_set(channels, chan)) {
                    add_op_class = true;
                    break;
                }
            } else {
                if (map_is_no_subband_channel_set(channels, chan, op_class)) {
                    add_op_class = true;
                    break;
                }
            }
        }

        if (!add_op_class) {
            continue;
        }

        memset(pref_op_class, 0, sizeof(map_op_class_t));
        pref_op_class->op_class = op_class;
        pref_op_class->pref     = 0; /* Unoperable  */
        pref_op_class->reason   = 0; /* Unspecified */

        /* Loop again and add channels... */
        map_cs_foreach(&ch_set, chan) {
            /* Checks also if channel is in non operable list */
            if (!map_is_channel_in_cap_op_class(cap_op_class, chan)) {
                continue;
            }

            if (add_all_chan) {
                /* channel count remains zero */
                continue;
            }

            /* Add channel */
            if (!is_center_chan) {
                if (!map_cs_is_set(channels, chan)) {
                   /* block because primary channel is not set */
                    map_cs_set(&pref_op_class->channels, chan);
                } else if (bw != 20 && !is_6g_psc && !map_is_all_subband_channel_set(&radio->ctl_channels, chan, op_class)) {
                   /* block because secondary is not set (40MHz only) */
                    map_cs_set(&pref_op_class->channels, chan);
                }
            } else {
                /* For 40 (6G), 80, 160 and 320MHz, the center channel needs to be added (and only once).
                   Code below assumes the channels in the set are sorted.
                */
                if (!map_get_center_channel(op_class, chan, &center_chan)) {
                    if (map_is_no_subband_channel_set(channels, chan, op_class)) {
                        /* block because none of the subband channels are set */
                        map_cs_set(&pref_op_class->channels, center_chan);
                    } else if (!is_6g_psc && !map_is_all_subband_channel_set(&radio->ctl_channels, chan, op_class)) {
                        /* block because one of the subband channels are not set */
                        map_cs_set(&pref_op_class->channels, center_chan);
                    }
                }
            }
        }
        pref_idx++;
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
                                        &radio->ctrl_pref_op_class_list, &radio->pref_op_class_list);
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
int map_ctrl_chan_sel_set(map_radio_info_t *radio, bool *acs_enable, map_channel_set_t *acs_channels,
                          int *channel, int *bandwidth)
{
    map_ale_info_t       *ale            = radio->ale;
    map_radio_chan_sel_t *chan_sel       = &radio->chan_sel;
    bool                  new_acs_enable = acs_enable ? *acs_enable : chan_sel->acs_enable;
    int                   new_channel    = channel ? *channel : chan_sel->channel;
    char                  cs_str[MAP_CS_BUF_LEN];
    char                  acs_enable_str[16];
    char                  channel_str[16];
    char                  bandwidth_str[16];

    log_ctrl_i("set ale[%s] radio[%s]: acs_enable[%s] acs_channels[%s] channel[%s] bandwidth[%s]",
               radio->ale->al_mac_str, radio->radio_id_str,
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
                              new_acs_enable,
                              acs_channels ? acs_channels : &chan_sel->acs_channels,
                              new_channel,
                              bandwidth    ? *bandwidth   : chan_sel->bandwidth);

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
    return map_ctrl_chan_sel_set(radio, NULL, NULL, &channel, NULL);
}

int map_ctrl_chan_sel_set_bandwidth(map_radio_info_t *radio, int bandwidth)
{
    return map_ctrl_chan_sel_set(radio, NULL, NULL, NULL, &bandwidth);
}

int map_ctrl_chan_sel_update(map_radio_info_t *radio)
{
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
            map_dm_radio_set_chan_sel(radio, true, &chan_sel->acs_channels, 0, chan_sel->bandwidth);
        }
    }

    if (update_pref_channel_op_class_list(ale, radio)) {
        log_ctrl_e("failed updating preferred channel and operating class list for ale[%s] radio[%s]",
                   ale->al_mac_str, radio->radio_id_str);
        goto fail;
    }

    return 0;

fail:
    return -1;
}

void map_ctrl_chan_sel_dump(map_printf_cb_t print_cb, map_ale_info_t *req_ale, bool extended)
{
    map_ale_info_t     *ale;
    map_radio_info_t   *radio;
    bool                first_ale = true;
    char                buf[MAP_CS_BUF_LEN];

    if (req_ale == NULL) {
        print_cb("GLOBAL\n");
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
            print_cb("      acs_enable  : %s\n",   bool_to_str(buf, sizeof(buf), &chan_sel->acs_enable));
            print_cb("      acs_channels: [%s]\n", map_cs_to_string(&chan_sel->acs_channels, ',', buf, sizeof(buf)));
            print_cb("      channel     : %d\n",   chan_sel->channel);
            print_cb("      bandwidth   : %d\n",   chan_sel->bandwidth);
            print_cb("      backhaul    : %s\n",   bool_to_str(buf, sizeof(buf), &is_backhaul));
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
}
