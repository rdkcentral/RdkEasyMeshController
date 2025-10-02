/*
 * Copyright (c) 2024-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/* Perform actions when a sta or mld sta connects
   - request or update client capabilities
   - check backhaul sta connection to
     - start/stop channel selection when backhaul disconnects/connects
     - mark channel configurable when backhaul disconnects
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#define LOG_TAG "sta"

#include "map_ctrl_sta.h"
#include "map_data_model.h"
#include "map_ctrl_utils.h"
#include "map_ctrl_post_onboarding_handler.h"
#include "map_ctrl_cmdu_tx.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
/* Delay before sending channel selection request when backhaul station disconnects.
   A delay is used because in the agent might start onboarding again which
   already includes channel selection -> avoid multiple channel selections.

   In case the agent does not do that controller will send a channel selection
   after this delay.
*/
#define BHSTA_DISCONNECT_CHAN_SEL_DELAY 15

/*#######################################################################
#                       HELP FUNCTION                                   #
########################################################################*/
static void set_bhsta_iface_active(map_ale_info_t *bhsta_ale, map_backhaul_sta_iface_t *bhsta_iface, bool active)
{
    map_radio_info_t *bhsta_radio;

    bhsta_iface->active = active;

    log_ctrl_i("ALE[%s]: setting bSTA[%s] %sactive", bhsta_ale->al_mac_str,
               mac_string(bhsta_iface->mac_address), active ? "" : "in");

    if ((bhsta_radio = map_dm_get_radio(bhsta_ale, bhsta_iface->radio_id))) {
        if (active) {
            map_agent_cancel_delayed_channel_selection(bhsta_radio);
        } else {
            map_agent_start_delayed_channel_selection(bhsta_radio, BHSTA_DISCONNECT_CHAN_SEL_DELAY);
        }

        map_dm_radio_set_channel_configurable(bhsta_radio, !active);
    }
}

static void check_backhaul_connected(map_sta_info_t *sta)
{
    map_ale_info_t           *bhsta_ale;
    map_backhaul_sta_iface_t *bhsta_iface;
    map_bss_info_t           *bss = sta->bss;

    if (!(bhsta_iface = map_find_bhsta_iface_gbl(sta->mac, &bhsta_ale))) {
        return;
    }

    log_ctrl_i("ALE[%s]: bSTA[%s] band[%s] connected to BSS[%s]", bhsta_ale->al_mac_str, sta->mac_str,
               map_get_freq_band_str(bss->radio->supported_freq), bss->bssid_str);

    set_bhsta_iface_active(bhsta_ale, bhsta_iface, true);
}

static void check_backhaul_disconnected(map_sta_info_t *sta)
{
    map_ale_info_t           *bhsta_ale;
    map_backhaul_sta_iface_t *bhsta_iface;
    map_ale_info_t           *ale;
    map_radio_info_t         *radio;
    map_bss_info_t           *bss = sta->bss;

    if (!(bhsta_iface = map_find_bhsta_iface_gbl(sta->mac, &bhsta_ale))) {
        return;
    }

    log_ctrl_i("ALE[%s]: bSTA[%s] band[%s] disconnected from BSS[%s]", bhsta_ale->al_mac_str, sta->mac_str,
                map_get_freq_band_str(bss->radio->supported_freq), bss->bssid_str);

    /* Check if this sta is connected anywhere else - cannot use map_dm_get_sta_gbl */
    map_dm_foreach_ale(ale) {
        map_dm_foreach_radio(ale, radio) {
            map_dm_foreach_bss(radio, bss) {
                if (bss != sta->bss && map_dm_get_sta(bss, sta->mac)) {
                    /* Sta is connected somewhere else -> stop */
                    return;
                }
            }
        }
    }

    set_bhsta_iface_active(bhsta_ale, bhsta_iface, false);
}

/*#######################################################################
#                       CALLBACKS                                       #
########################################################################*/
void create_sta_cb(map_sta_info_t *sta)
{
    map_bss_info_t *bss = sta->bss;

    log_ctrl_i("ALE[%s]: %sSTA[%s] connected to BSS[%s]", bss->radio->ale->al_mac_str, sta->sta_mld ? "AFF_" : "", sta->mac_str, bss->bssid_str);

    /* 1. Update client capabilities:
       - regular STA: send query
       - affiliated STA: update sta_mld
    */

    if (!sta->sta_mld) {
        timer_id_t retry_id;

        map_dm_get_sta_timer_id(retry_id, sta, CLIENT_CAPS_QUERY_RETRY_ID);
        if (!map_is_timer_registered(retry_id)) {
            if (map_register_retry(retry_id, 15, 20, sta, NULL, map_send_client_capability_query)) {
               log_ctrl_e("failed registering retry timer[%s]", retry_id);
            }
        }
    } else {
        parse_update_mld_aff_client_capability(sta->sta_mld, false);
    }

    /* 2. Check backhaul sta connection */
    check_backhaul_connected(sta);
}

void remove_sta_cb(map_sta_info_t *sta)
{
    map_bss_info_t *bss = sta->bss;

    log_ctrl_i("ALE[%s]: %sSTA[%s] disconnected from BSS[%s]", bss->radio->ale->al_mac_str, sta->sta_mld ? "AFF_" : "", sta->mac_str, bss->bssid_str);

    /* Check backhaul sta connection */
    check_backhaul_disconnected(sta);
}

void create_sta_mld_cb(map_sta_mld_info_t *sta_mld)
{
    map_ap_mld_info_t *ap_mld = sta_mld->ap_mld;

    log_ctrl_i("ALE[%s]: STA_MLD[%s] connected to AP_MLD[%s]", ap_mld->ale->al_mac_str, sta_mld->mac_str, ap_mld->mac_str);

    /* Update client capabilities */
    timer_id_t retry_id;

    map_dm_get_sta_mld_timer_id(retry_id, sta_mld, CLIENT_CAPS_QUERY_RETRY_ID);
    if (!map_is_timer_registered(retry_id)) {
        if (map_register_retry(retry_id, 15, 20, sta_mld, NULL, map_send_mld_client_capability_query)) {
            log_ctrl_e("failed registering retry timer[%s]", retry_id);
        }
    }
}

void remove_sta_mld_cb(map_sta_mld_info_t *sta_mld)
{
    map_ap_mld_info_t *ap_mld = sta_mld->ap_mld;

    log_ctrl_i("ALE[%s]: STA_MLD[%s] disconnected from AP_MLD[%s]", ap_mld->ale->al_mac_str, sta_mld->mac_str, ap_mld->mac_str);
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
static map_dm_cbs_t g_dm_cbs = {
    .sta_create_cb     = create_sta_cb,
    .sta_remove_cb     = remove_sta_cb,

    .sta_mld_create_cb = create_sta_mld_cb,
    .sta_mld_remove_cb = remove_sta_mld_cb,
};

int map_ctrl_sta_init(void)
{
    map_dm_register_cbs(&g_dm_cbs);

    return 0;
}

void map_ctrl_sta_fini()
{
    map_dm_unregister_cbs(&g_dm_cbs);
}
