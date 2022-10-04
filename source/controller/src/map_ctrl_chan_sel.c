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

        print_cb("%sop_class: %d channels[%s]\n", indent, op_class->op_class,
                                                  map_cs_to_string(&op_class->channels, ',', buf, sizeof(buf)));
    }
}

static void set_def_pref_channels(map_radio_info_t *radio)
{
    map_controller_cfg_t *cfg = get_controller_cfg();
    map_channel_set_t    *channels = &radio->chan_sel.def_pref_channels;

    switch(radio->supported_freq) {
        case IEEE80211_FREQUENCY_BAND_2_4_GHZ:
            map_cs_copy(channels, &cfg->default_pref_channel_set_2g);
        break;
        case IEEE80211_FREQUENCY_BAND_5_GHZ:
            map_cs_copy(channels, &cfg->default_pref_channel_set_5g);
        break;
        case IEEE80211_FREQUENCY_BAND_6_GHZ:
            map_cs_copy(channels, &cfg->default_pref_channel_set_6g);
        break;
        default:
            map_cs_unset_all(channels);
        break;
    }

    map_cs_and(channels, &radio->ctl_channels);
}

static void set_acs_pref_channels(map_radio_info_t *radio)
{
    map_radio_chan_sel_t *chan_sel = &radio->chan_sel;
    map_channel_set_t    *channels = &radio->chan_sel.pref_channels;

    map_cs_copy(channels, &chan_sel->acs_channels);

    /* Sanitize channel list */
    /* Only keep allowed channels */
    map_cs_and(channels, &radio->ctl_channels);

    /* If empty -> revert to default preferred channel list */
    if (map_cs_nr(channels) == 0) {
        map_cs_copy(channels, &chan_sel->def_pref_channels);

        /* If still empty (config error??) -> revert to allowed channel list */
        if (map_cs_nr(channels) == 0) {
            map_cs_copy(channels, &radio->ctl_channels);
        }
    }
}

static void set_controller_pref_channels(map_radio_info_t *radio, map_channel_set_t *channels)
{
    map_controller_cfg_t *cfg = get_controller_cfg();
    bool                  is_6g_psc = (radio->supported_freq == IEEE80211_FREQUENCY_BAND_6_GHZ) && cfg->allowed_channel_6g_psc;
    int                   bandwidth = radio->chan_sel.bandwidth;
    int                   global_bandwidth = 0;
    int                   i;
    int                   pref_idx = 0;

    /* Max number of operation classes is radio->cap_op_class_count ( + 1 to avoid malloc(0) )*/
    map_op_class_t *new_list = realloc(radio->ctrl_pref_op_class_list.op_classes, radio->cap_op_class_list.op_classes_nr * sizeof(map_op_class_t) + 1);
    if (NULL == new_list) {
        SFREE(radio->ctrl_pref_op_class_list.op_classes);
        radio->ctrl_pref_op_class_list.op_classes_nr = 0;
        return;
    }
    radio->ctrl_pref_op_class_list.op_classes = new_list;

    /* Get global max bandwidth */
    switch(radio->supported_freq) {
        case IEEE80211_FREQUENCY_BAND_2_4_GHZ: global_bandwidth = cfg->allowed_bandwidth_2g; break;
        case IEEE80211_FREQUENCY_BAND_5_GHZ:   global_bandwidth = cfg->allowed_bandwidth_5g; break;
        case IEEE80211_FREQUENCY_BAND_6_GHZ:   global_bandwidth = cfg->allowed_bandwidth_6g; break;
        default:                               global_bandwidth = 0; break; /* Should not happen */
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
        uint8_t            bw, chan;

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
               For 40MHz (6G), 80 and 160MHz, check if any subband channel is allowed.
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
                /* For 40 (6G), 80 and 160MHz, the center channel needs to be added (and only once).
                   Code below assumes the channels in the set are sorted.
                */
                if (map_is_no_subband_channel_set(channels, chan, op_class)) {
                    /* block because none of the subband channels are set */
                    map_cs_set(&pref_op_class->channels, map_get_center_channel(op_class, chan));
                } else if (!is_6g_psc && !map_is_all_subband_channel_set(&radio->ctl_channels, chan, op_class)) {
                    /* block because one of the subband channels are not set */
                    map_cs_set(&pref_op_class->channels, map_get_center_channel(op_class, chan));
                }
            }
        }
        pref_idx++;
    }
    radio->ctrl_pref_op_class_list.op_classes_nr = pref_idx;
}

static void update_pref_channels(map_radio_info_t *radio)
{
    map_radio_chan_sel_t *chan_sel = &radio->chan_sel;
    map_channel_set_t     channels;

    set_def_pref_channels(radio);
    set_acs_pref_channels(radio);

    /* For controller: check if fixed or not */
    if (!chan_sel->acs_enable && chan_sel->channel > 0 && map_cs_is_set(&radio->ctl_channels, chan_sel->channel)) {
        map_cs_unset_all(&channels);
        map_cs_set(&channels, chan_sel->channel);
    } else {
        map_cs_copy(&channels, &chan_sel->pref_channels);
    }

    set_controller_pref_channels(radio, &channels);
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
int map_ctrl_chan_sel_set(map_radio_info_t *radio, bool *acs_enable, map_channel_set_t *acs_channels,
                          int *channel, int *bandwidth)
{
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
        return -1;
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

    /* Do channel selection */
    update_pref_channels(radio);
    map_agent_cancel_channel_selection(radio->ale);
    map_agent_handle_channel_selection(radio->ale, radio, MAP_CHAN_SEL_REQUEST);

    return 0;
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
    map_radio_chan_sel_t *chan_sel = &radio->chan_sel;

    if ((radio->supported_freq == IEEE80211_FREQUENCY_BAND_UNKNOWN) || (map_cs_nr(&radio->ctl_channels) == 0)) {
        log_ctrl_e("cannot update chan_sel for radio[%s] band/ctl_channels not known", radio->radio_id_str);
        return -1;
    }

    /* Check if fixed channel still possible, switch to auto if not */
    if (!chan_sel->acs_enable && chan_sel->channel > 0) {
        if (!map_cs_is_set(&radio->ctl_channels, chan_sel->channel)) {
            map_dm_radio_set_chan_sel(radio, true, &chan_sel->acs_channels, 0, chan_sel->bandwidth);
        }
    }

    update_pref_channels(radio);

    return 0;
}

void map_ctrl_chan_sel_dump(map_printf_cb_t print_cb, bool extended)
{
    map_ale_info_t   *ale;
    map_radio_info_t *radio;
    char              buf[MAP_CS_BUF_LEN];

    map_dm_foreach_agent_ale(ale) {
        print_cb("ALE[%s]\n", ale->al_mac_str);
        map_dm_foreach_radio(ale, radio) {
            map_radio_chan_sel_t *chan_sel  = &radio->chan_sel;

            print_cb("  RADIO[%s]\n", radio->radio_id_str);
            print_cb("    config:\n");
            print_cb("      acs_enable  : %s\n",   bool_to_str(buf, sizeof(buf), &chan_sel->acs_enable));
            print_cb("      acs_channels: [%s]\n", map_cs_to_string(&chan_sel->acs_channels, ',', buf, sizeof(buf)));
            print_cb("      channel     : %d\n",   chan_sel->channel);
            print_cb("      bandwidth   : %d\n",   chan_sel->bandwidth);
            print_cb("    state:\n");
            print_cb("      channel          : %d\n",   radio->current_op_channel);
            print_cb("      bandwidth        : %d\n",   radio->current_bw);
            print_cb("      op_class         : %d\n",   radio->current_op_class);
            print_cb("      control_channels : [%s]\n", map_cs_to_string(&radio->ctl_channels, ',', buf, sizeof(buf)));
            print_cb("      pref_channels    : [%s]\n", map_cs_to_string(&chan_sel->pref_channels, ',', buf, sizeof(buf)));
            print_cb("      def_pref_channels: [%s]\n", map_cs_to_string(&chan_sel->def_pref_channels, ',', buf, sizeof(buf)));
            if (extended) {
                print_cb("      agent_cap:\n");
                print_op_class_list(print_cb, &radio->cap_op_class_list, "        ");
                print_cb("      ctrl_pref:\n");
                print_op_class_list(print_cb, &radio->ctrl_pref_op_class_list, "        ");
            }
        }
        print_cb("\n");
    }
}

int map_ctrl_chan_sel_init(void)
{
    return 0;
}

void map_ctrl_chan_sel_fini(void)
{
}
