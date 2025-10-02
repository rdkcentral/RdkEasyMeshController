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
#include <stdlib.h>
#include <string.h>

#include <libubox/utils.h>

#define LOG_TAG "dm"

#include "map_data_model.h"
#include "map_dm_eth_device_list.h"
#include "map_dm_rbus.h"
#include "map_info.h"
#include "map_config.h"
#include "map_data_model_dumper.h"
#include "map_topology_tree.h"
#include "map_timer_handler.h"
#include "map_retry_handler.h"
#include "1905_platform.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define min(a,b) ((a) < (b) ? (a) : (b))

#define mac_hash(mac) acu_mac_hash(mac, MAP_MAX_MAC_HASH)

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
typedef struct {
    list_head_t list;
    uint8_t hash[SHA256_MAC_LEN];
} map_dm_dpp_enrollee_hash_t;

typedef struct {
    list_head_t list;
    list_head_t hlist;
    mac_addr    mac;
} inactive_sta_t;

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static LIST_HEAD(g_ale_list);
static map_event_lists_t g_event_lists;

static LIST_HEAD(g_dm_cbs_list);
static LIST_HEAD(g_dm_unassociated_station_list);
static LIST_HEAD(g_dpp_hash_list);

/* Inactive sta list */
static LIST_HEAD(g_inactive_sta_list);
static list_head_t g_inactive_sta_hlist[MAP_MAX_MAC_HASH];
static size_t g_inactive_sta_count;

static map_dm_nbapi_t g_map_nbapi_cbs;

/*#######################################################################
#                       DM UPDATE CALLBACKS                             #
########################################################################*/
/* Do not call those callback for the controller ALE.
   Assuming that "controllers" will not get radio/bss
   TODO: - reconsider legacy 1905 devices
*/
static bool is_controller(map_ale_info_t *ale)
{
    return !maccmp(ale->al_mac, map_cfg_get()->controller_cfg.al_mac);
}

static void call_ale_create_cbs(map_ale_info_t *ale)
{
    map_dm_cbs_t *cbs;

    if (!is_controller(ale)) {
        list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->ale_create_cb) cbs->ale_create_cb(ale);
    }
}

static void call_ale_update_cbs(map_ale_info_t *ale)
{
    map_dm_cbs_t *cbs;

    if (!ale->removing && !is_controller(ale)) {
        list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->ale_update_cb) cbs->ale_update_cb(ale);
    }
}

static void call_ale_eth_device_list_update_cbs(map_ale_info_t *ale)
{
    map_dm_cbs_t *cbs;

    if (!ale->removing && !is_controller(ale)) {
        list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->ale_eth_device_list_update_cb) cbs->ale_eth_device_list_update_cb(ale);
    }
}

static void call_ale_remove_cbs(map_ale_info_t *ale)
{
    map_dm_cbs_t *cbs;

    if (!is_controller(ale)) {
        list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->ale_remove_cb) cbs->ale_remove_cb(ale);
    }
}

static void call_radio_create_cbs(map_radio_info_t *radio)
{
    map_dm_cbs_t *cbs;

    list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->radio_create_cb) cbs->radio_create_cb(radio);
}

static void call_radio_update_cbs(map_radio_info_t *radio)
{
    map_dm_cbs_t *cbs;

    list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->radio_update_cb) cbs->radio_update_cb(radio);
}

static void call_radio_remove_cbs(map_radio_info_t *radio)
{
    map_dm_cbs_t *cbs;

    list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->radio_remove_cb) cbs->radio_remove_cb(radio);
}

static void call_bss_create_cbs(map_bss_info_t *bss)
{
    map_dm_cbs_t *cbs;

    list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->bss_create_cb) cbs->bss_create_cb(bss);
}

static void call_bss_update_cbs(map_bss_info_t *bss)
{
    map_dm_cbs_t *cbs;

    list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->bss_update_cb) cbs->bss_update_cb(bss);
}

static void call_bss_remove_cbs(map_bss_info_t *bss)
{
    map_dm_cbs_t *cbs;

    list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->bss_remove_cb) cbs->bss_remove_cb(bss);
}

static void call_ap_mld_create_cbs(map_ap_mld_info_t *ap_mld)
{
    map_dm_cbs_t *cbs;

    list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->ap_mld_create_cb) cbs->ap_mld_create_cb(ap_mld);
}

static void call_ap_mld_update_cbs(map_ap_mld_info_t *ap_mld)
{
    map_dm_cbs_t *cbs;

    list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->ap_mld_update_cb) cbs->ap_mld_update_cb(ap_mld);
}

static void call_ap_mld_remove_cbs(map_ap_mld_info_t *ap_mld)
{
    map_dm_cbs_t *cbs;

    list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->ap_mld_remove_cb) cbs->ap_mld_remove_cb(ap_mld);
}

static void call_bsta_mld_update_cbs(map_bsta_mld_info_t *bsta_mld)
{
    map_dm_cbs_t *cbs;

    list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->bsta_mld_update_cb) cbs->bsta_mld_update_cb(bsta_mld);
}

static void call_sta_create_cbs(map_sta_info_t *sta)
{
    map_dm_cbs_t *cbs;

    list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->sta_create_cb) cbs->sta_create_cb(sta);
}

static void call_sta_update_cbs(map_sta_info_t *sta)
{
    map_dm_cbs_t *cbs;

    list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->sta_update_cb) cbs->sta_update_cb(sta);
}

static void call_sta_remove_cbs(map_sta_info_t *sta)
{
    map_dm_cbs_t *cbs;

    list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->sta_remove_cb) cbs->sta_remove_cb(sta);
}

static void call_sta_mld_create_cbs(map_sta_mld_info_t *sta_mld)
{
    map_dm_cbs_t *cbs;

    list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->sta_mld_create_cb) cbs->sta_mld_create_cb(sta_mld);
}

static void call_sta_mld_remove_cbs(map_sta_mld_info_t *sta_mld)
{
    map_dm_cbs_t *cbs;

    list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->sta_mld_remove_cb) cbs->sta_mld_remove_cb(sta_mld);
}

static void call_assoc_create_cbs(map_assoc_data_t *assoc)
{
    map_dm_cbs_t *cbs;

    list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->assoc_create_cb) cbs->assoc_create_cb(assoc);
}

static void call_assoc_remove_cbs(map_assoc_data_t *assoc)
{
    map_dm_cbs_t *cbs;

    list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->assoc_remove_cb) cbs->assoc_remove_cb(assoc);
}

static void call_disassoc_create_cbs(map_disassoc_data_t *disassoc)
{
    map_dm_cbs_t *cbs;

    list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->disassoc_create_cb) cbs->disassoc_create_cb(disassoc);
}

static void call_disassoc_remove_cbs(map_disassoc_data_t *disassoc)
{
    map_dm_cbs_t *cbs;

    list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->disassoc_remove_cb) cbs->disassoc_remove_cb(disassoc);
}

static void call_failconn_create_cbs(map_failconn_data_t *failconn)
{
    map_dm_cbs_t *cbs;

    list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->failconn_create_cb) cbs->failconn_create_cb(failconn);
}

static void call_failconn_remove_cbs(map_failconn_data_t *failconn)
{
    map_dm_cbs_t *cbs;

    list_for_each_entry(cbs, &g_dm_cbs_list, list) if (cbs->failconn_remove_cb) cbs->failconn_remove_cb(failconn);
}

/*#######################################################################
#                       DPP ENROLLEE HASH LIST                          #
########################################################################*/
static void map_dm_dpp_hash_list_fini(void) {
    map_dm_clear_dpp_hash_list();
}

void map_dm_clear_dpp_hash_list(void) {
    map_dm_dpp_enrollee_hash_t *entry, *tmp;

    list_for_each_entry_safe(entry, tmp, &g_dpp_hash_list, list) {
        list_del(&entry->list);
        free(entry);
    }
}

int map_dm_add_dpp_hash(const uint8_t *hash) {
    if (map_dm_get_dpp_hash(hash)) {
        /* already exists */
        return 0;
    }

    map_dm_dpp_enrollee_hash_t *new_entry = calloc(1, sizeof(map_dm_dpp_enrollee_hash_t));
    if (!new_entry) {
        return -1;
    }

    memcpy(new_entry->hash, hash, sizeof(new_entry->hash));
    list_add_tail(&new_entry->list, &g_dpp_hash_list);
    return 0;
}

bool map_dm_get_dpp_hash(const uint8_t *hash) {
    map_dm_dpp_enrollee_hash_t *entry;

    list_for_each_entry(entry, &g_dpp_hash_list, list) {
        if (memcmp(entry->hash, hash, sizeof(entry->hash)) == 0) {
            return true;
        }
    }

    return false;
}

/*#######################################################################
#                       INACTIVE STA LIST                               #
########################################################################*/
static void unassociated_station_list_add(map_sta_info_t *sta)
{
    if (sta) {
        log_lib_d("Add sta %s in unassoc list", sta->mac_str);
        list_add_tail(&sta->list, &g_dm_unassociated_station_list);
    }
}

static void unassociated_station_list_remove(map_sta_info_t *sta)
{
    if (sta) {
        log_lib_d("Remove sta %s from unassoc list", sta->mac_str);
        list_del_init(&sta->list);
    }
}

static map_sta_info_t *unassociated_station_list_pop(mac_addr sta_mac)
{
    map_sta_info_t *sta = NULL;
    mac_addr_str    mac_str;

    mac_to_string(sta_mac, mac_str);

    log_lib_d("Search sta %s in unassoc list", mac_str);
    list_for_each_entry(sta, &g_dm_unassociated_station_list, list) {
        if (!maccmp(sta->mac, sta_mac)) {
            log_lib_d("Found sta %s in unassoc list", sta->mac_str);
            unassociated_station_list_remove(sta);
            return sta;
        }
    }

    log_lib_w("Can't find sta %s in unassoc list", mac_str);

    return NULL;
}

/* Keep list of known sta mac that are no longer connected.  Currently
   only used to derive ethernet clients.  Can be extended later.
*/

static void inactive_sta_free(inactive_sta_t *sta)
{
    g_inactive_sta_count--;
    list_del(&sta->list);
    list_del(&sta->hlist);
    free(sta);
}

static inactive_sta_t *inactive_sta_find(mac_addr mac)
{
    inactive_sta_t *sta;
    int             h = mac_hash(mac);

    list_for_each_entry(sta, &g_inactive_sta_hlist[h], hlist) {
        if (!maccmp(sta->mac, mac)) {
            return sta;
        }
    }

    return NULL;
}

static int inactive_sta_add(mac_addr mac)
{
    inactive_sta_t *sta = inactive_sta_find(mac);
    int             h;

    if (inactive_sta_find(mac)) {
        return 0;
    }

    if (g_inactive_sta_count == MAX_INACTIVE_STA) {
        inactive_sta_free(list_first_entry(&g_inactive_sta_list, inactive_sta_t, list));
    }

    if (!(sta = calloc(1, sizeof(inactive_sta_t)))) {
        return -1;
    }

    maccpy(sta->mac, mac);

    h = mac_hash(mac);
    list_add_tail(&sta->list, &g_inactive_sta_list);
    list_add_tail(&sta->hlist, &g_inactive_sta_hlist[h]);
    g_inactive_sta_count++;

    return 0;
}

static void inactive_sta_remove(mac_addr mac)
{
    inactive_sta_t *sta = inactive_sta_find(mac);

    if (sta) {
        inactive_sta_free(sta);
    }
}

static void inactive_sta_list_init(void)
{
    int i;

    for (i = 0; i < MAP_MAX_MAC_HASH; i++) {
        INIT_LIST_HEAD(&g_inactive_sta_hlist[i]);
    }
}

static void inactive_sta_fini(void)
{
    inactive_sta_t *sta, *next;

    list_for_each_entry_safe(sta, next, &g_inactive_sta_list, list) {
        inactive_sta_free(sta);
    }
}

bool map_dm_is_inactive_sta(mac_addr mac)
{
    return inactive_sta_find(mac);
}

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
/* Cleanup of ALE, Radio, STA*/
static inline void cleanup_ale_timers(map_ale_info_t *ale)
{
    timer_id_t timer_id;

    map_dm_get_ale_timer_id(timer_id, ale, "");
    map_unregister_retry_prefix(timer_id);
    map_timer_unregister_callback_prefix(timer_id);
}

static inline void cleanup_radio_timers(map_radio_info_t *radio)
{
    timer_id_t timer_id;

    map_dm_get_radio_timer_id(timer_id, radio, "");
    map_unregister_retry_prefix(timer_id);
    map_timer_unregister_callback_prefix(timer_id);
}

static inline void cleanup_sta_timers(map_sta_info_t *sta)
{
    timer_id_t timer_id;

    map_dm_get_sta_timer_id(timer_id, sta, "");
    map_unregister_retry_prefix(timer_id);
    map_timer_unregister_callback_prefix(timer_id);
}

static inline void cleanup_sta_mld_timers(map_sta_mld_info_t *sta_mld)
{
    timer_id_t timer_id;

    map_dm_get_sta_mld_timer_id(timer_id, sta_mld, "");
    map_unregister_retry_prefix(timer_id);
    map_timer_unregister_callback_prefix(timer_id);
}

static void set_counter_48(uint8_t *array, uint64_t value) {
    int i;
    for (i = 5; i >= 0; i--) {
        array[i] = (uint8_t)(value & 0xFF);  // Extract the least significant byte
        value >>= 8;                         // Shift the value right by 8 bits
    }
}

/*#######################################################################
#                       ALE                                             #
########################################################################*/
map_ale_info_t *map_dm_create_ale(mac_addr al_mac)
{
    map_ale_info_t *ale;

    if ((ale = map_dm_get_ale(al_mac))) {
        return ale;
    }

    if (!(ale = calloc(1, sizeof(map_ale_info_t)))) {
        log_lib_e("failed to allocating memory");
        return NULL;
    }

    /* Update the AL mac */
    maccpy(ale->al_mac, al_mac);
    mac_to_string(ale->al_mac, ale->al_mac_str);

    if (!maccmp(al_mac, map_cfg_get()->controller_cfg.local_agent_al_mac)) {
        ale->is_local = true;
    }

    map_strlcpy(ale->iface_name, "null", sizeof(ale->iface_name));
    ale->upstream_iface_type = INTERFACE_TYPE_UNKNOWN;
    ale->ale_onboard_status = ALE_NODE_ONBOARDING;

    /* Create the neighbor link metrics */
    if (!(ale->eth_neigh_link_metric_list = new_array_list())) {
        log_lib_e("failed to create neighbor link metric list");
        free(ale);
        return NULL;
    }

    /* Create new topology tree node for the al entity */
    if (create_topology_tree_node(ale, AL_ENTITY) < 0) {
        log_lib_e("failed to create topology tree node");
        delete_array_list(ale->eth_neigh_link_metric_list);
        free(ale);
        return NULL;
    }

    /* Init key info counters */
    set_counter_48(ale->key_info.encr_rx_counter, 0);
    set_counter_48(ale->key_info.encr_tx_counter, 1);
    set_counter_48(ale->key_info.integrity_rx_counter, 0);
    set_counter_48(ale->key_info.integrity_tx_counter, 1);

    /* Set back pointer for bsta_mld */
    ale->bsta_mld.ale = ale;

    /* Init lists */
    INIT_LIST_HEAD(&ale->list);
    INIT_LIST_HEAD(&ale->radio_list);
    INIT_LIST_HEAD(&ale->ap_mld_list);

    /* Add to linked list */
    list_add_tail(&ale->list, &g_ale_list);

    /* Call create callbacks */
    call_ale_create_cbs(ale);

    log_lib_d("-----------------------------------------------------");
    if (maccmp(al_mac, map_cfg_get()->controller_cfg.al_mac)) {
        log_lib_d("| %s MAP Agent %s", ale->is_local ? "Local" : "New", ale->al_mac_str);
    } else {
        log_lib_d("| MAP Controller %s", ale->al_mac_str);
    }
    log_lib_d("-----------------------------------------------------");

    return ale;
}

void map_dm_remove_ale_key_info(map_ale_info_t *ale)
{
    if (!ale)
        return;

    memset(ale->key_info.ptk, 0, sizeof(ale->key_info.ptk));
    ale->key_info.ptk_len = 0;
    memset(ale->key_info.gtk, 0, sizeof(ale->key_info.gtk));
    ale->key_info.gtk_len = 0;
    set_counter_48(ale->key_info.encr_rx_counter, 0);
    set_counter_48(ale->key_info.encr_tx_counter, 1);
    set_counter_48(ale->key_info.integrity_rx_counter, 0);
    set_counter_48(ale->key_info.integrity_tx_counter, 1);
}

int map_dm_get_ale_key_info(mac_addr al_mac, map_1905_sec_key_info_t *key_info)
{
    map_ale_info_t *ale;

    map_dm_foreach_ale(ale) {
        if (!maccmp(ale->al_mac, al_mac)) {
            memcpy(key_info, &ale->key_info, sizeof(*key_info));
            return 0;
        }
    }

    return -1;
}

map_ale_info_t* map_dm_get_ale(mac_addr al_mac)
{
    map_ale_info_t *ale;

    map_dm_foreach_ale(ale) {
        if (!maccmp(ale->al_mac, al_mac)) {
            return ale;
        }
    }

    return NULL;
}

map_ale_info_t *map_dm_get_ale_from_src_mac(mac_addr src_mac)
{
    map_ale_info_t *ale;
    uint8_t         i;

    /* First try to find as ale_mac */
    if ((ale = map_dm_get_ale(src_mac))) {
        return ale;
    }

    /* Then try to find as source mac */
    map_dm_foreach_ale(ale) {
        if (!maccmp(ale->src_mac, src_mac)) {
            return ale;
        }
    }

    /* Then try to find in local interface list */
    map_dm_foreach_ale(ale) {
        for (i = 0; i < ale->local_iface_count; i++) {
            map_local_iface_t *iface = &ale->local_iface_list[i];

            if (!maccmp(iface->mac_address, src_mac)) {
                return ale;
            }
        }
    }

    return NULL;
}

int map_dm_remove_ale(map_ale_info_t *ale)
{
    map_ap_mld_info_t *ap_mld, *next_ap_mld;
    map_radio_info_t *radio, *next_radio;
    int i;

    ale->removing = true;

    /* Call remove callbacks before removing radios to avoid that they need
       to be remove one by one.  This is ok for current use cases.
    */
    call_ale_remove_cbs(ale);

    /* cleanup the ap mld */
    map_dm_foreach_ap_mld_safe(ale, ap_mld, next_ap_mld) {
        if (map_dm_remove_ap_mld(ap_mld)) {
            log_lib_e("failed Removing ap_mld");
        }
    }

    /* cleanup the radios */
    map_dm_foreach_radio_safe(ale, radio, next_radio) {
        if (map_dm_remove_radio(radio)) {
            log_lib_e("failed Removing radio");
            /* procceed cleaning other resources Event if cleanup of one radio failed. */
        }
    }

    /* Cleanup all the timers */
    cleanup_ale_timers(ale);

    /* Remove steering disallowed macs lists */
    free(ale->btm_steering_disallow_macs);
    free(ale->local_steering_disallow_macs);

    /* Remove local interface list */
    free(ale->local_iface_list);

    /* Free non 1905 neighbors */
    map_dm_free_non_1905_neighbor_list(ale);

    /* Remove bachaul sta interface list */
    free(ale->backhaul_sta_iface_list);

    /* cleanup neighbor link metric references */
    if (ale->eth_neigh_link_metric_list != NULL) {
        while (list_get_size(ale->eth_neigh_link_metric_list) > 0) {
            map_neighbor_link_metric_t *neigh_obj = remove_last_object(ale->eth_neigh_link_metric_list);
            free(neigh_obj);
        }
        delete_array_list(ale->eth_neigh_link_metric_list);
    }
    free(ale->neighbor_link_list);

    free(ale->unassoc_metrics);

    /* Clean CAC Status report */
    free(ale->cac_status_report.available_pairs);
    free(ale->cac_status_report.non_occupancy_pairs);
    free(ale->cac_status_report.ongoing_cac_pairs);

    /* Clean agent extension specific allocations. */
    free(ale->emex.feature_profile.feature_list);
    free(ale->emex.radios.info);
    map_dm_free_emex_eth_iface_list(ale);

    /* Clean DPP specific allocations */
    free(ale->dpp_info.chirp.hash);
    free(ale->dpp_info.encap_msg.frame);
    free(ale->dpp_info.message.frame);
    free(ale->dpp_info.encap_eapol.frame);

    /* Clean 1905 security specific allocations */
    map_dm_remove_ale_key_info(ale);

    /* Free list of ethernet device macs */
    free(ale->eth_device_list.macs);
    for (i = 0; i < ETH_DEVICE_HISTORY_LEN; i++) {
        free(ale->eth_device_list.h_macs[i]);
    }

    /* Remove from topology */
    remove_topology_tree_node(ale);

    /* Unlink */
    list_del(&ale->list);

    log_lib_d("ALE[%s] removed", ale->al_mac_str);

    free(ale);

    return 0;
}

/*#######################################################################
#                       RADIO                                           #
########################################################################*/
map_radio_info_t *map_dm_create_radio(map_ale_info_t *ale, mac_addr radio_id)
{
    map_radio_info_t        *radio;

    if ((radio = map_dm_get_radio(ale, radio_id))) {
        return radio;
    }

    if (!(radio = calloc(1, sizeof(map_radio_info_t)))) {
        log_lib_e("failed to allocating memory");
        return NULL;
    }

    /* Update radio_id */
    maccpy(radio->radio_id, radio_id);
    mac_to_string(radio->radio_id, radio->radio_id_str);
    b64_encode(radio->radio_id, sizeof(radio->radio_id), radio->radio_id_base64, sizeof(radio->radio_id_base64));
    //TODO: acu_base64_encode_to_buf(radio->radio_id, sizeof(mac_addr), radio->radio_id_base64, sizeof(radio->radio_id_base64));

    /* Set state */
    set_radio_state_on(&radio->state);

    /* Update the default to a invalid value */
    radio->supported_freq = 0xFF;

    /* Create the scan results list */
    if (!(radio->scanned_bssid_list = new_array_list())) {
        log_lib_e("failed to create scan results list");
        free(radio);
        return NULL;
    }
    if (!(radio->unassoc_sta_list = new_array_list())) {
        log_lib_e("failed to create unassoc sta list");
        delete_array_list(radio->scanned_bssid_list);
        free(radio);
        return NULL;
    }
    radio->unassoc_sta_list_idx = 0;

    /* Default channel selection data */
    //radio->chan_sel.acs_enable = true;

    /* All radios have channel configuration capability until backhaul sta connection happens */
    radio->channel_configurable = true;

    /* Init lists */
    INIT_LIST_HEAD(&radio->list);
    INIT_LIST_HEAD(&radio->bss_list);

    /* Add to linked list */
    radio->ale = ale;
    ale->radios_nr++;
    list_add_tail(&radio->list, &ale->radio_list);

    /* Call create callbacks */
    call_radio_create_cbs(radio);

    log_lib_d("-----------------------------------------------------");
    log_lib_d("| New Radio %s ", radio->radio_id_str);
    log_lib_d("-----------------------------------------------------");

    return radio;
}

map_radio_info_t *map_dm_get_radio(map_ale_info_t *ale, mac_addr radio_id)
{
    map_radio_info_t *radio;

    map_dm_foreach_radio(ale, radio) {
        if (!maccmp(radio->radio_id, radio_id)) {
            return radio;
        }
    }

    return NULL;
}

int map_dm_remove_radio(map_radio_info_t *radio)
{
    map_bss_info_t *bss, *next;

    /* Call remove callbacks before removing bss to avoid that they need
       to be remove one by one.  This is ok for current use cases.
    */
    call_radio_remove_cbs(radio);

    /* Cleanup BSS nodes under the radio */
    map_dm_foreach_bss_safe(radio, bss, next) {
        if (map_dm_remove_bss(bss)) {
            log_lib_e("failed to remove bss");
            /* Procceed cleaning other resources Event if cleanup of one BSS failed */
        }
    }

    /* Cleanup all the retry timers associated with this radio */
    cleanup_radio_timers(radio);

    /* Cleanup scan results list */
    if (radio->scanned_bssid_list) {
        while (list_get_size(radio->scanned_bssid_list) > 0) {
            map_scan_result_t *scan_info_obj = remove_last_object(radio->scanned_bssid_list);
            free(scan_info_obj);
        }
        delete_array_list(radio->scanned_bssid_list);
    }

    if (radio->unassoc_sta_list) {
        while (list_get_size(radio->unassoc_sta_list) > 0) {
            void *unassoc_sta = remove_last_object(radio->unassoc_sta_list);
            free(unassoc_sta);
        }
        delete_array_list(radio->unassoc_sta_list);
    }

    free(radio->ht_caps);
    free(radio->vht_caps);
    free(radio->he_caps);
    free(radio->eht_caps);

    free(radio->cap_op_class_list.op_classes);
    free(radio->pref_op_class_list.op_classes);
    free(radio->ctrl_pref_op_class_list.op_classes);
    free(radio->disallowed_op_class_list.op_classes);
    free(radio->merged_pref_op_class_list.op_classes);
    free(radio->curr_op_class_list.op_classes);
    free(radio->scan_caps.op_class_list.op_classes);

    map_dm_free_op_restriction_list(radio);
    map_dm_free_cac_methods(radio->cac_caps.cac_method, radio->cac_caps.cac_method_count);

    free(radio->cac_completion_info.detected_pairs);
    free(radio->wifi6_caps);
    if (radio->wifi7_caps) {
        SFREE(radio->wifi7_caps->ap_str_records);
        SFREE(radio->wifi7_caps->ap_nstr_records);
        SFREE(radio->wifi7_caps->ap_emlsr_records);
        SFREE(radio->wifi7_caps->ap_emlmr_records);
        SFREE(radio->wifi7_caps->bsta_str_records);
        SFREE(radio->wifi7_caps->bsta_nstr_records);
        SFREE(radio->wifi7_caps->bsta_emlsr_records);
        SFREE(radio->wifi7_caps->bsta_emlmr_records);
        SFREE(radio->wifi7_caps);
    }

    /* Unlink */
    radio->ale->radios_nr--;
    list_del(&radio->list);

    log_lib_d("Radio[%s] removed", radio->radio_id_str);

    free(radio);

    return 0;
}

/*#######################################################################
#                       BSS                                             #
########################################################################*/
map_bss_info_t *map_dm_create_bss(map_radio_info_t *radio, mac_addr bssid)
{
    map_bss_info_t *bss;
    int             i;

    if ((bss = map_dm_get_bss(radio, bssid))) {
        return bss;
    }

    if (!(bss = calloc(1, sizeof(map_bss_info_t)))) {
        log_lib_e("failed to allocating memory");
        return NULL;
    }

    /* Update bssid */
    maccpy(bss->bssid, bssid);
    mac_to_string(bss->bssid, bss->bssid_str);

    /* Set state and timestamp */
    set_bss_state_active(&bss->state);
    bss->change_ts = acu_get_timestamp_sec();

    /* Create the neighbor link metrics */
    if (!(bss->neigh_link_metric_list = new_array_list())) {
        log_lib_e("failed to create neighbor link metric list");
        free(bss);
        return NULL;
    }

    /* Init lists */
    INIT_LIST_HEAD(&bss->list);
    INIT_LIST_HEAD(&bss->sta_list);
    for (i = 0; i < MAP_MAX_MAC_HASH; i++) {
        INIT_LIST_HEAD(&bss->sta_hlist[i]);
    }
    INIT_LIST_HEAD(&bss->aff_ap_list);

    /* Add to linked list */
    bss->radio = radio;
    radio->bsss_nr++;
    list_add_tail(&bss->list, &radio->bss_list);

    /* Call create callbacks */
    call_bss_create_cbs(bss);

    log_lib_d("-----------------------------------------------------");
    log_lib_d("| New BSS %s ", bss->bssid_str);
    log_lib_d("-----------------------------------------------------");

    return bss;
}

map_bss_info_t* map_dm_get_bss(map_radio_info_t *radio, mac_addr bssid)
{
    map_bss_info_t *bss;

    map_dm_foreach_bss(radio, bss) {
        if (!maccmp(bss->bssid, bssid)) {
            return bss;
        }
    }

    return NULL;
}

map_bss_info_t* map_dm_get_bss_from_ale(map_ale_info_t *ale, mac_addr bssid)
{
    map_radio_info_t *radio;
    map_bss_info_t   *bss;

    map_dm_foreach_radio(ale, radio) {
        if ((bss = map_dm_get_bss(radio, bssid))) {
            return bss;
        }
    }

    return NULL;
}

map_bss_info_t* map_dm_get_bss_gbl(mac_addr bssid)
{
    map_ale_info_t *ale;
    map_bss_info_t *bss;

    map_dm_foreach_agent_ale(ale) {
        if ((bss = map_dm_get_bss_from_ale(ale, bssid))) {
            return bss;
        }
    }

    return NULL;
}

int map_dm_remove_bss(map_bss_info_t *bss)
{
    map_sta_info_t *sta, *next;

    /* Remove stas */
    map_dm_foreach_sta_safe(bss, sta, next) {
        map_dm_remove_sta(sta);
    }

    /* Cleanup neighbor link metric references */
    if (bss->neigh_link_metric_list != NULL) {
        while (list_get_size(bss->neigh_link_metric_list) > 0) {
            map_neighbor_link_metric_t *neigh_obj = remove_last_object(bss->neigh_link_metric_list);
            free(neigh_obj);
        }
        delete_array_list(bss->neigh_link_metric_list);
    }

    /* Call remove callbacks */
    call_bss_remove_cbs(bss);

    /* Unlink */
    bss->radio->bsss_nr--;
    list_del(&bss->list);
    if (bss->ap_mld) {
        list_del(&bss->aff_ap_list);
        call_ap_mld_update_cbs(bss->ap_mld);
    }

    log_lib_d("Bss[%s] removed", bss->bssid_str);

    free(bss);

    return 0;
}

/*#######################################################################
#                       STA                                             #
########################################################################*/
int map_dm_sta_init_payload(map_sta_info_t *sta, void *payload)
{
    if (!sta) {
        return -1;
    }

    if (!payload) {
        return -1;
    }

    sta->dm_payload = payload;

    return 0;
}

static map_sta_info_t *create_sta(map_bss_info_t *bss, map_sta_mld_info_t *sta_mld, mac_addr mac)
{
    map_sta_info_t *sta = NULL;

    if ((sta = map_dm_get_sta(bss, mac))) {
        return sta;
    }

    if ((sta = unassociated_station_list_pop(mac))) {
        goto reinit;
    }

    if (!(sta = calloc(1, sizeof(map_sta_info_t)))) {
        log_lib_e("failed to allocating memory");
        return NULL;
    }

    /* Update mac address */
    maccpy(sta->mac, mac);
    mac_to_string(sta->mac, sta->mac_str);

reinit:
    /* Steering History will be recreated */
    sta->steering_history_size_delta = 0;

    /* Create sta metrics array */
    if (!(sta->metrics = new_array_list())) {
        log_lib_e("failed to create sta metrics list");
        free(sta);
        return NULL;
    }

    /* Create sta beacon metrics array */
    if (!(sta->beacon_metrics = new_array_list())) {
        log_lib_e("failed to create sta beacon metrics list");
        delete_array_list(sta->metrics);
        free(sta);
        return NULL;
    }

    /* Create sta steering history array */
    if (!sta->steering_history && !(sta->steering_history = new_array_list())) {
        log_lib_e("failed to create sta steering history list");
        delete_array_list(sta->metrics);
        delete_array_list(sta->beacon_metrics);
        free(sta);
        return NULL;
    }

    /* Init lists */
    INIT_LIST_HEAD(&sta->list);
    INIT_LIST_HEAD(&sta->hlist);

    /* Link with bss */
    sta->bss = bss;
    bss->stas_nr++;
    list_add_tail(&sta->list, &bss->sta_list);
    list_add_tail(&sta->hlist, &bss->sta_hlist[mac_hash(sta->mac)]);

    /* Link to sta_mld when this is affiliated sta */
    if (sta_mld) {
        sta_mld->aff_sta_nr++;
        sta->sta_mld = sta_mld;
        list_add_tail(&sta->aff_sta_list, &sta_mld->aff_sta_list);
    }

    /* Remove from inactive sta list */
    inactive_sta_remove(mac);

    /* Call create callbacks */
    call_sta_create_cbs(sta);

    log_lib_d("-----------------------------------------------------");
    log_lib_d("| New %sSTA %s", sta_mld ? "Affiliated " : "", sta->mac_str);
    log_lib_d("-----------------------------------------------------");

    return sta;
}

map_sta_info_t *map_dm_create_sta(map_bss_info_t *bss, mac_addr mac)
{
    return create_sta(bss, NULL, mac);
}

map_sta_info_t *map_dm_create_aff_sta(map_bss_info_t *bss, map_sta_mld_info_t *sta_mld, mac_addr mac)
{
    return create_sta(bss, sta_mld, mac);
}

int map_dm_update_sta_bss(map_bss_info_t *bss, map_sta_info_t *sta)
{
    int  h      = mac_hash(sta->mac);
    bool roamed = sta->bss;

    if (sta->bss == bss) {
        return 0;
    }

    /* Remove from old bss (can only be NULL when called from create_bss above) */
    if (sta->bss) {
        if (roamed) {
            /* Call remove callbacks (for old bss) */
            call_sta_remove_cbs(sta);
        }

        /* Cleanup retry timers associated with STA */
        cleanup_sta_timers(sta);

        sta->bss->stas_nr--;
        list_del(&sta->list);
        list_del(&sta->hlist);
    }

    /* Add to new bss */
    sta->bss = bss;
    bss->stas_nr++;
    list_add_tail(&sta->list,  &bss->sta_list);
    list_add_tail(&sta->hlist, &bss->sta_hlist[h]);

    if (roamed) {
        /* Call create callbacks (for new bss) */
        call_sta_create_cbs(sta);
    }

    return 0;
}

static map_sta_info_t *get_sta_h(map_bss_info_t *bss, mac_addr mac, int h)
{
    map_sta_info_t *sta;

    list_for_each_entry(sta, &bss->sta_hlist[h], hlist) {
        if (!maccmp(sta->mac, mac)) {
            return sta;
        }
    }

    return NULL;
}

static map_sta_info_t *get_sta_from_ale_h(map_ale_info_t *ale, mac_addr mac, int h)
{
    map_radio_info_t *radio;
    map_bss_info_t   *bss;
    map_sta_info_t   *sta;

    map_dm_foreach_radio(ale, radio) {
        map_dm_foreach_bss(radio, bss) {
            if ((sta = get_sta_h(bss, mac, h))) {
                return sta;
            }
        }
    }

    return NULL;
}

map_sta_info_t *map_dm_get_sta(map_bss_info_t *bss, mac_addr mac)
{
    return get_sta_h(bss, mac, mac_hash(mac));
}

map_sta_info_t* map_dm_get_sta_from_ale(map_ale_info_t *ale, mac_addr mac)
{
    return get_sta_from_ale_h(ale, mac, mac_hash(mac));
}

map_sta_info_t *map_dm_get_sta_gbl(mac_addr mac)
{
    map_ale_info_t *ale;
    map_sta_info_t *sta;
    int             h = mac_hash(mac);

    map_dm_foreach_agent_ale(ale) {
        if ((sta = get_sta_from_ale_h(ale, mac, h))) {
            return sta;
        }
    }

    return NULL;
}

int map_dm_remove_sta(map_sta_info_t *sta)
{
    /* Call remove callbacks */
    call_sta_remove_cbs(sta);

    sta->dm_removed = 0;
    sta->dm_idx = 0;

    /* Cleanup retry timers associated with STA */
    cleanup_sta_timers(sta);

    /* Removes the metrics reference from sta */
    if (sta->metrics != NULL) {
        while (list_get_size(sta->metrics) > 0) {
            free(remove_last_object(sta->metrics));
        }
        delete_array_list(sta->metrics);
        sta->metrics = NULL;
    }

    /* Removes the beacon metrics reference from sta */
    if (sta->beacon_metrics != NULL) {
        while (list_get_size(sta->beacon_metrics) > 0) {
            free(remove_last_object(sta->beacon_metrics));
        }
        delete_array_list(sta->beacon_metrics);
        sta->beacon_metrics = NULL;
    }

    /* Cleanup STA assoc frame */
    SFREE(sta->assoc_frame);

    /* Cleanup STA tunneled messages */
    if (sta->tunneled_msg) {
        SFREE(sta->tunneled_msg->assoc_req_body);
        SFREE(sta->tunneled_msg->reassoc_req_body);
        SFREE(sta->tunneled_msg->btm_query_body);
        SFREE(sta->tunneled_msg->wnm_req_body);
        SFREE(sta->tunneled_msg->anqp_req_body);
        SFREE(sta->tunneled_msg);
    }

    /* STA extended metrics */
    sta->last_sta_ext_metrics.no_of_bss_metrics = 0;
    SFREE(sta->last_sta_ext_metrics.ext_bss_metrics_list);

    sta->last_disassoc_reason_code = 0;

    /* Unlink from bss */
    sta->bss->stas_nr--;
    list_del_init(&sta->list);
    list_del_init(&sta->hlist);
    if (sta->sta_mld) {
        sta->sta_mld->aff_sta_nr--;
        list_del(&sta->aff_sta_list);
    }
    sta->bss = NULL;

    unassociated_station_list_add(sta);

    /* Add to inactive sta list */
    inactive_sta_add(sta->mac);

    return 0;
}

/*#######################################################################
#                       AP MLD                                          #
########################################################################*/
map_ap_mld_info_t* map_dm_create_ap_mld(map_ale_info_t *ale, mac_addr mld_mac)
{
    map_ap_mld_info_t *ap_mld;
    int                i;

    if ((ap_mld = map_dm_get_ap_mld(ale, mld_mac))) {
        return ap_mld;
    }

    if (!(ap_mld = calloc(1, sizeof(map_ap_mld_info_t)))) {
        log_lib_e("failed to allocating memory");
        return NULL;
    }

    /* Update mac address */
    maccpy(ap_mld->mac, mld_mac);
    mac_to_string(ap_mld->mac, ap_mld->mac_str);

    /* Init lists */
    INIT_LIST_HEAD(&ap_mld->list);
    INIT_LIST_HEAD(&ap_mld->aff_ap_list);
    INIT_LIST_HEAD(&ap_mld->sta_mld_list);
    for (i = 0; i < MAP_MAX_MAC_HASH; i++) {
        INIT_LIST_HEAD(&ap_mld->sta_mld_hlist[i]);
    }

    /* Add to linked list */
    ap_mld->ale = ale;
    ale->ap_mld_nr++;
    list_add_tail(&ap_mld->list, &ale->ap_mld_list);

    /* Call create callbacks */
    call_ap_mld_create_cbs(ap_mld);

    log_lib_d("-----------------------------------------------------");
    log_lib_d("| New AP_MLD %s", ap_mld->mac_str);
    log_lib_d("-----------------------------------------------------");

    return ap_mld;
}

map_ap_mld_info_t* map_dm_get_ap_mld(map_ale_info_t *ale, mac_addr mld_mac)
{
    map_ap_mld_info_t *ap_mld;

    map_dm_foreach_ap_mld(ale, ap_mld) {
        if (!maccmp(ap_mld->mac, mld_mac)) {
            return ap_mld;
        }
    }

    return NULL;
}

int map_dm_remove_ap_mld(map_ap_mld_info_t *ap_mld)
{
    map_bss_info_t *bss, *next_bss;
    map_sta_mld_info_t *sta_mld, *next_sta_mld;

    /* Call remove callbacks */
    call_ap_mld_remove_cbs(ap_mld);

    /* Remove affiliated aps */
    map_dm_foreach_aff_ap_safe(ap_mld, bss, next_bss) {
         map_dm_bss_set_ap_mld(bss, NULL);
    }

    /* Remove sta_mld */
    map_dm_foreach_sta_mld_safe(ap_mld, sta_mld, next_sta_mld) {
        map_dm_remove_sta_mld(sta_mld);
    }

    /* Unlink */
    ap_mld->ale->ap_mld_nr--;
    list_del(&ap_mld->list);

    log_lib_d("AP_MLD[%s] removed", ap_mld->mac_str);

    free(ap_mld);

    return 0;
}

/*#######################################################################
#                       STA_MLD                                         #
########################################################################*/
map_sta_mld_info_t *map_dm_create_sta_mld(map_ap_mld_info_t *ap_mld, mac_addr mac)
{
    map_sta_mld_info_t *sta_mld;

    if ((sta_mld = map_dm_get_sta_mld(ap_mld, mac))) {
        return sta_mld;
    }

    if (!(sta_mld = calloc(1, sizeof(map_sta_mld_info_t)))) {
        log_lib_e("failed to allocating memory");
        return NULL;
    }

    /* Update mac address */
    maccpy(sta_mld->mac, mac);
    mac_to_string(sta_mld->mac, sta_mld->mac_str);

    sta_mld->assoc_ts = acu_get_timestamp_sec();

    /* Init lists */
    INIT_LIST_HEAD(&sta_mld->list);
    INIT_LIST_HEAD(&sta_mld->hlist);
    INIT_LIST_HEAD(&sta_mld->aff_sta_list);

    /* Link with ap_mld */
    sta_mld->ap_mld = ap_mld;
    ap_mld->sta_mld_nr++;
    list_add_tail(&sta_mld->list,  &ap_mld->sta_mld_list);
    list_add_tail(&sta_mld->hlist, &ap_mld->sta_mld_hlist[mac_hash(sta_mld->mac)]);

    /* Remove from inactive sta list */
    inactive_sta_remove(mac);

    /* Call create callbacks */
    call_sta_mld_create_cbs(sta_mld);

    log_lib_d("-----------------------------------------------------");
    log_lib_d("| New STA MLD %s", sta_mld->mac_str);
    log_lib_d("-----------------------------------------------------");

    return sta_mld;
}

static map_sta_mld_info_t *get_sta_mld_h(map_ap_mld_info_t *ap_mld, mac_addr mac, int h)
{
    map_sta_mld_info_t *sta_mld;

    list_for_each_entry(sta_mld, &ap_mld->sta_mld_hlist[h], hlist) {
        if (!maccmp(sta_mld->mac, mac)) {
            return sta_mld;
        }
    }

    return NULL;
}

static map_sta_mld_info_t *get_sta_mld_from_ale_h(map_ale_info_t *ale, mac_addr mac, int h)
{
    map_ap_mld_info_t  *ap_mld;
    map_sta_mld_info_t *sta_mld;

    map_dm_foreach_ap_mld(ale, ap_mld) {
        if ((sta_mld = get_sta_mld_h(ap_mld, mac, h))) {
            return sta_mld;
        }
    }

    return NULL;
}

map_sta_mld_info_t *map_dm_get_sta_mld(map_ap_mld_info_t *ap_mld, mac_addr mac)
{
    return get_sta_mld_h(ap_mld, mac, mac_hash(mac));
}

map_sta_mld_info_t* map_dm_get_sta_mld_from_ale(map_ale_info_t *ale, mac_addr mac)
{
    return get_sta_mld_from_ale_h(ale, mac, mac_hash(mac));
}

map_sta_mld_info_t *map_dm_get_sta_mld_gbl(mac_addr mac)
{
    map_ale_info_t     *ale;
    map_sta_mld_info_t *sta_mld;
    int                 h = mac_hash(mac);

    map_dm_foreach_agent_ale(ale) {
        if ((sta_mld = get_sta_mld_from_ale_h(ale, mac, h))) {
            return sta_mld;
        }
    }

    return NULL;
}

map_sta_info_t *map_dm_get_aff_sta(map_sta_mld_info_t *sta_mld, mac_addr mac)
{
    map_sta_info_t *sta;

    map_dm_foreach_aff_sta(sta_mld, sta) {
        if (!maccmp(sta->mac, mac)) {
            return sta;
        }
    }

    return NULL;
}

int map_dm_remove_sta_mld(map_sta_mld_info_t *sta_mld)
{
    map_sta_info_t *sta, *next;

    /* Remove affiliated sta */
    map_dm_foreach_aff_sta_safe(sta_mld, sta, next) {
        map_dm_remove_sta(sta);
    }

    /* Call remove callbacks */
    call_sta_mld_remove_cbs(sta_mld);

    /* Cleanup retry timers associated with STA */
    cleanup_sta_mld_timers(sta_mld);

    /* Cleanup STA assoc frame */
    free(sta_mld->assoc_frame);

    /* Unlink */
    sta_mld->ap_mld->sta_mld_nr--;
    list_del(&sta_mld->list);
    list_del(&sta_mld->hlist);

    /* Add to inactive sta list */
    inactive_sta_add(sta_mld->mac);

    log_lib_d("STA_MLD[%s] removed", sta_mld->mac_str);

    free(sta_mld);
    return 0;
}

/*#######################################################################
#                       CONNECTION EVENTS                               #
########################################################################*/
map_assoc_data_t *map_dm_create_assoc(map_sta_info_t *sta)
{
    map_assoc_data_t *assoc;
    uint16_t status_code = 0;

    assoc = calloc(1, sizeof(map_assoc_data_t));
    if (!(assoc = calloc(1, sizeof(map_assoc_data_t)))) {
        log_lib_e("Failed to allocate memory");
        return NULL;
    }

    acu_maccpy(assoc->mac, sta->mac);
    acu_maccpy(assoc->bssid, sta->bss->bssid);
    assoc->status_code = status_code;
    assoc->timestamp = acu_get_epoch_nsec();

    INIT_LIST_HEAD(&assoc->list);

    /* Add to linked list */
    g_event_lists.assoc_cnt++;
    list_add_tail(&assoc->list, &g_event_lists.assoc_list);

    /* Call create callbacks */
    call_assoc_create_cbs(assoc);

    return assoc;
}

int map_dm_remove_assoc(map_assoc_data_t *assoc)
{
    /* Call remove callbacks */
    call_assoc_remove_cbs(assoc);

    /* Unlink */
    g_event_lists.assoc_cnt--;
    list_del(&assoc->list);

    free(assoc);

    return 0;
}

map_disassoc_data_t *map_dm_create_disassoc(map_sta_info_t *sta)
{
    map_disassoc_data_t *disassoc;

    disassoc = calloc(1, sizeof(map_disassoc_data_t));
    if (!(disassoc = calloc(1, sizeof(map_disassoc_data_t)))) {
        log_lib_e("Failed to allocate memory");
        return NULL;
    }

    acu_maccpy(disassoc->mac, sta->mac);
    acu_maccpy(disassoc->bssid, sta->bss->bssid);
    disassoc->reason_code = sta->last_disassoc_reason_code;
    disassoc->timestamp = acu_get_epoch_nsec();

    INIT_LIST_HEAD(&disassoc->list);

    /* Add to linked list */
    g_event_lists.disassoc_cnt++;
    list_add_tail(&disassoc->list, &g_event_lists.disassoc_list);

    /* Call create callbacks */
    call_disassoc_create_cbs(disassoc);

    return disassoc;
}

int map_dm_remove_disassoc(map_disassoc_data_t *disassoc)
{
    /* Call remove callbacks */
    call_disassoc_remove_cbs(disassoc);

    /* Unlink */
    g_event_lists.disassoc_cnt--;
    list_del(&disassoc->list);

    free(disassoc);

    return 0;
}

map_failconn_data_t *map_dm_create_failconn(mac_addr sta_mac, mac_addr bssid, uint16_t status_code, uint16_t reason_code)
{
    map_failconn_data_t *failconn;

    failconn = calloc(1, sizeof(map_failconn_data_t));
    if (!(failconn = calloc(1, sizeof(map_failconn_data_t)))) {
        log_lib_e("Failed to allocate memory");
        return NULL;
    }

    acu_maccpy(failconn->mac, sta_mac);
    if (bssid != NULL) {
        acu_maccpy(failconn->bssid, bssid);
    }
    failconn->status_code = status_code;
    failconn->reason_code = reason_code;
    failconn->timestamp = acu_get_epoch_nsec();

    INIT_LIST_HEAD(&failconn->list);

    /* Add to linked list */
    g_event_lists.failconn_cnt++;
    list_add_tail(&failconn->list, &g_event_lists.failconn_list);

    /* Call create callbacks */
    call_failconn_create_cbs(failconn);

    return failconn;
}

int map_dm_remove_failconn(map_failconn_data_t *failconn)
{
    /* Call remove callbacks */
    call_failconn_remove_cbs(failconn);

    /* Unlink */
    g_event_lists.failconn_cnt--;
    list_del(&failconn->list);

    free(failconn);

    return 0;
}

/*#######################################################################
#                       DM UPDATE FUNCTIONS                             #
########################################################################*/
void map_dm_ale_set_device_info(map_ale_info_t *ale, map_device_info_t *new_d)
{
    map_device_info_t *old_d = &ale->device_info;
    bool update = false;

    if (old_d->os_version != new_d->os_version                     ||
        strcmp(old_d->os_version_str,    new_d->os_version_str)    ||
        strcmp(old_d->manufacturer_name, new_d->manufacturer_name) ||
        strcmp(old_d->model_name,        new_d->model_name)        ||
        strcmp(old_d->model_number,      new_d->model_number)      ||
        strcmp(old_d->serial_number,     new_d->serial_number)) {
        *old_d = *new_d;
        update = true;
    }

    if (update) {
        call_ale_update_cbs(ale);
    }
}

void map_dm_ale_set_onboard_status(map_ale_info_t *ale, map_onboard_status_t status)
{
    bool update = false;

    if (ale->ale_onboard_status != status) {
        ale->ale_onboard_status = status;
        if (ale->ale_onboard_status == ALE_NODE_ONBOARDED) {
            ale->ale_onboarding_time = acu_get_timestamp_sec();
            if(!ale->ale_onboarded_first_time) {
                ale->ale_onboarded_first_time = true;
            }
        }
        update = true;
    }

    if (update) {
        call_ale_update_cbs(ale);
    }
}

void map_dm_ale_set_upstream_info(map_ale_info_t *ale, mac_addr us_al_mac, mac_addr us_local_mac,
                                  mac_addr us_remote_mac, bool set_if_type, int if_type)
{
    bool update = false;

    if (us_al_mac && maccmp(ale->upstream_al_mac, us_al_mac)) {
        maccpy(ale->upstream_al_mac, us_al_mac);
        update = true;
    }

    if (us_local_mac && maccmp(ale->upstream_local_iface_mac, us_local_mac)) {
        maccpy(ale->upstream_local_iface_mac, us_local_mac);
        /* No update needed yet (MAC toggles) */
        // update = true;
    }

    if (us_remote_mac && maccmp(ale->upstream_remote_iface_mac, us_remote_mac)) {
        maccpy(ale->upstream_remote_iface_mac, us_remote_mac);
        /* No update needed yet (MAC toggles) */
        // update = true;
    }

    if (set_if_type && ale->upstream_iface_type != if_type) {
        ale->upstream_iface_type = if_type;
        update = true;
    }

    if (update) {
        if (0 && !maccmp(get_root_ale_node()->al_mac, us_al_mac) && !ale->is_local) {
            map_ale_info_t *local;
            bool local_found = false;

            log_lib_e("ale %s has controller as us_al_mac", ale->al_mac_str);
            map_dm_foreach_agent_ale(local) {
                if (local->is_local) {
                    local_found = true;
                    break;
                }
            }

            if (!local_found) {
                log_lib_e("no local agent, set ale %s as local", ale->al_mac_str);
                ale->is_local = true;
            }
        }

        call_ale_update_cbs(ale);
    }
}

void map_dm_ale_set_cac_status(map_ale_info_t *ale)
{
    call_ale_update_cbs(ale);
}

void map_dm_ale_eth_update(map_ale_info_t *ale)
{
    call_ale_update_cbs(ale);
}

void map_dm_ale_update_unassoc_sta_link_metrics(map_ale_info_t *ale)
{
    ale->update_unassoc_sta_link_metrics = 1;
    call_ale_update_cbs(ale);
}

void map_dm_radio_set_capabilities(map_radio_info_t *radio)
{
    call_radio_update_cbs(radio);
}

void map_dm_radio_set_channel_configurable(map_radio_info_t *radio, bool channel_configurable)
{
    bool update = false;

    if (radio->channel_configurable != channel_configurable) {
        radio->channel_configurable = channel_configurable;
        update = true;
    }

    if (update) {
        call_radio_update_cbs(radio);
    }
}

void map_dm_radio_set_channel(map_radio_info_t *radio, uint8_t op_class, uint8_t channel, uint8_t highest_bw_channel, uint16_t bw, uint8_t tx_pwr)
{
    bool update = false;

    if (radio->current_op_class != op_class) {
        radio->current_op_class = op_class;
        update = true;
    }

    if (radio->current_op_channel != channel) {
        radio->current_op_channel = channel;
        update = true;
    }

    if (radio->current_bw != bw) {
        radio->current_bw = bw;
        update = true;
    }

    if (highest_bw_channel && radio->highest_bw_channel != highest_bw_channel) {
        /* highest_bw_channel=0 when called from topo response */
        radio->highest_bw_channel = highest_bw_channel;
        update = true;
    }

    if (radio->current_tx_pwr != tx_pwr) {
        radio->current_tx_pwr = tx_pwr;
        update = true;
    }

    if (update) {
        call_radio_update_cbs(radio);
    }
}

void map_dm_radio_set_chan_sel(map_radio_info_t *radio, bool cloud_mgmt_enable, bool acs_enable,
                               map_channel_set_t *acs_channels, uint8_t channel, uint16_t bw)
{
    map_radio_chan_sel_t *chan_sel = &radio->chan_sel;
    bool                  update   = false;

    if (chan_sel->cloud_mgmt_enable != cloud_mgmt_enable) {
        chan_sel->cloud_mgmt_enable = cloud_mgmt_enable;
        update = true;
    }

    if (chan_sel->acs_enable != acs_enable) {
        chan_sel->acs_enable = acs_enable;
        update = true;
    }

    if (map_cs_compare(&chan_sel->acs_channels, acs_channels)) {
        map_cs_copy(&chan_sel->acs_channels, acs_channels);
        update = true;
    }

    if (chan_sel->channel != channel) {
        chan_sel->channel = channel;
        update = true;
    }

    if (chan_sel->bandwidth != bw) {
        chan_sel->bandwidth = bw;
        update = true;
    }

    if (update) {
        call_radio_update_cbs(radio);
    }
}

void map_dm_radio_scan_result(map_radio_info_t *radio)
{
    radio->update_scan_results = 1;
    call_radio_update_cbs(radio);
}

void map_dm_bss_set_ssid(map_bss_info_t *bss, size_t ssid_len, uint8_t *ssid, int bss_type)
{
    bool update = false;

    ssid_len = min(ssid_len, MAX_SSID_LEN - 1);

    if (bss->ssid_len != ssid_len || memcmp(bss->ssid, ssid, ssid_len)) {
        bss->ssid_len = ssid_len;
        memcpy(bss->ssid, ssid, ssid_len);
        bss->ssid[bss->ssid_len] = 0;
        update = true;
    }

    if (bss->type != bss_type) {
        bss->type = bss_type;
        update = true;
    }

    if (update) {
        call_bss_update_cbs(bss);
    }
}

void map_dm_sta_beacon_metrics_completed(map_sta_info_t *sta)
{
    call_sta_update_cbs(sta);
}

void map_dm_sta_steering_finalize(map_sta_info_t *sta)
{
    map_sta_steering_history_t *steering_history = NULL;

    steering_history = last_object(sta->steering_history);
    if (!steering_history) {
        log_lib_d("There is no steering history entry");
        return;
    }

    if (steering_history->completed) {
        return;
    }

    if ( steering_history->steering_approach == MAP_STEERING_APPROACH_BTM_REQUEST ) {
        if ( acu_timestamp_delta_msec(steering_history->start_time) < 1000 ) {
            /* Assume station has steered without response */
            steering_history->btm_response = IEEE80211_BTM_STATUS_ACCEPT;
            sta->steering_stats.btm_successes++;
            maccpy(steering_history->ap_dest, sta->bss->bssid);

            steering_history->completion_time = acu_get_epoch_nsec();
        } else {
            steering_history->btm_response = IEEE80211_BTM_STATUS_UNKNOWN;
            sta->steering_stats.btm_failures++;
        }
    }

    steering_history->completed = true;
    sta->bss->radio->ale->last_sta_steered = NULL;

    call_sta_update_cbs(sta);
}

void map_dm_sta_steering_btm_report(map_sta_info_t *sta, uint8_t status_code, mac_addr target_bssid)
{
    map_sta_steering_history_t *steering_history = NULL;

    steering_history = last_object(sta->steering_history);
    if (!steering_history) {
        log_lib_e("Can't get last steering history entry");
        return;
    }

    steering_history->btm_response = status_code;

    if (status_code == 0) {
        sta->steering_stats.btm_successes++;
    } else {
        sta->steering_stats.btm_failures++;
    }

    if (target_bssid) {
        maccpy(steering_history->ap_dest, target_bssid);
    }

    steering_history->completion_time = acu_get_epoch_nsec();
    steering_history->completed = true;

    sta->bss->radio->ale->last_sta_steered = NULL;

    /* Lastly call callback */
    call_sta_update_cbs(sta);
}

void map_dm_sta_steering_completed(map_ale_info_t *ale)
{
    map_sta_info_t *sta = ale->last_sta_steered;
    map_sta_steering_history_t *steering_history = NULL;

    if (!sta) {
        log_lib_e("Can't get last steered station");
        return;
    }

    steering_history = last_object(sta->steering_history);
    if (!steering_history) {
        log_lib_e("Can't get last steering history entry");
        return;
    }
    steering_history->btm_response = IEEE80211_BTM_STATUS_UNKNOWN;
}

void map_dm_bss_set_ap_mld(map_bss_info_t *bss, map_ap_mld_info_t *ap_mld)
{
    if (bss->ap_mld == ap_mld) {
        return;
    }

    if (bss->ap_mld) {
        /* Remove from other ap_mld */
        bss->ap_mld->aff_ap_nr--;
        list_del(&bss->aff_ap_list);

        call_ap_mld_update_cbs(bss->ap_mld);
    }
    bss->prev_ap_mld = bss->ap_mld;

    /* Add to new ap_mld */
    if (ap_mld) {
        ap_mld->aff_ap_nr++;
        list_add_tail(&bss->aff_ap_list, &ap_mld->aff_ap_list);
    }
    bss->ap_mld = ap_mld;

    call_bss_update_cbs(bss);
    bss->prev_ap_mld = NULL;
}

void map_dm_ap_mld_set(map_ap_mld_info_t *ap_mld, size_t ssid_len, uint8_t *ssid,
                       bool str, bool nstr, bool emlsr, bool emlmr,
                       map_aff_ap_cfg_t *aff_aps, size_t aff_ap_nr)
{
    map_bss_info_t *old_aff_ap, *new_aff_ap, *next;
    bool update = false;
    size_t i;

    ssid_len = min(ssid_len, MAX_SSID_LEN - 1);

    if (ap_mld->ssid_len != ssid_len || memcmp(ap_mld->ssid, ssid, ssid_len)) {
        ap_mld->ssid_len = ssid_len;
        memcpy(ap_mld->ssid, ssid, ssid_len);
        ap_mld->ssid[ap_mld->ssid_len] = 0;
        update = true;
    }

    if (ap_mld->enabled_mld_modes.str != str) {
        ap_mld->enabled_mld_modes.str = str;
        update = true;
    }

    if (ap_mld->enabled_mld_modes.nstr != nstr) {
        ap_mld->enabled_mld_modes.nstr = nstr;
        update = true;
    }

    if (ap_mld->enabled_mld_modes.emlsr != emlsr) {
        ap_mld->enabled_mld_modes.emlsr = emlsr;
        update = true;
    }

    if (ap_mld->enabled_mld_modes.emlmr != emlmr) {
        ap_mld->enabled_mld_modes.emlmr = emlmr;
        update = true;
    }

    /* Check affiliated aps */
    /* Remove? */
    map_dm_foreach_aff_ap_safe(ap_mld, old_aff_ap, next) {
        bool found = false;

        for (i = 0; i < aff_ap_nr; i++) {
            new_aff_ap = aff_aps[i].bss;
            if (new_aff_ap == old_aff_ap) {
                found = true;
                break;
            }
        }

        if (!found) {
            map_dm_bss_set_ap_mld(old_aff_ap, NULL);
            update = true;
        }
    }

    /* Add ? */
    for (i = 0; i < aff_ap_nr; i++) {
        bool found = false;
        new_aff_ap = aff_aps[i].bss;

        map_dm_foreach_aff_ap(ap_mld, old_aff_ap) {
            if (new_aff_ap == old_aff_ap) {
                found = true;
                break;
            }
        }

        if (!found) {
            map_dm_bss_set_ap_mld(new_aff_ap, ap_mld);
            update = true;
        }

        /* Check link_id */
        if (new_aff_ap->link_id != aff_aps[i].link_id) {
            new_aff_ap->link_id = aff_aps[i].link_id;
            update = true;
        }
    }

    if (update) {
        call_ap_mld_update_cbs(ap_mld);
    }
}

void map_dm_bsta_mld_set(map_bsta_mld_info_t *bsta_mld, bool valid,
                         mac_addr bsta_mld_mac, mac_addr ap_mld_mac,
                         bool str, bool nstr, bool emlsr, bool emlmr,
                         mac_addr *aff_bsta_macs, size_t aff_bsta_mac_nr)
{
    bool update = false;

    if (bsta_mld->valid != valid) {
        bsta_mld->valid = valid;
        update = true;

        if (!valid) {
            /* Clear fields */
            maccpy(bsta_mld->mac,        g_zero_mac);
            maccpy(bsta_mld->ap_mld_mac, g_zero_mac);

            bsta_mld->aff_bsta_mac_nr = 0;

            bsta_mld->enabled_mld_modes.str   = false;
            bsta_mld->enabled_mld_modes.nstr  = false;
            bsta_mld->enabled_mld_modes.emlsr = false;
            bsta_mld->enabled_mld_modes.emlmr = false;

            /* Skip all the rest */
            goto check_update;
        }
    }

    if (bsta_mld_mac && maccmp(bsta_mld->mac, bsta_mld_mac)) {
        maccpy(bsta_mld->mac, bsta_mld_mac);
        mac_to_string(bsta_mld->mac, bsta_mld->mac_str);
        update = true;
    }

    if (ap_mld_mac && maccmp(bsta_mld->ap_mld_mac, ap_mld_mac)) {
        maccpy(bsta_mld->ap_mld_mac, ap_mld_mac);
        update = true;
    }

    if (bsta_mld->enabled_mld_modes.str != str) {
        bsta_mld->enabled_mld_modes.str = str;
        update = true;
    }

    if (bsta_mld->enabled_mld_modes.nstr != nstr) {
        bsta_mld->enabled_mld_modes.nstr = nstr;
        update = true;
    }

    if (bsta_mld->enabled_mld_modes.emlsr != emlsr) {
        bsta_mld->enabled_mld_modes.emlsr = emlsr;
        update = true;
    }

    if (bsta_mld->enabled_mld_modes.emlmr != emlmr) {
        bsta_mld->enabled_mld_modes.emlmr = emlmr;
        update = true;
    }

    if (aff_bsta_macs) {
        if (aff_bsta_mac_nr > MAX_MLD_AFF_APSTA) {
            aff_bsta_mac_nr = MAX_MLD_AFF_APSTA;
        }

        size_t len = aff_bsta_mac_nr * sizeof(mac_addr);

        if (bsta_mld->aff_bsta_mac_nr != aff_bsta_mac_nr ||
            memcmp(bsta_mld->aff_bsta_macs, aff_bsta_macs, len)) {

            bsta_mld->aff_bsta_mac_nr = aff_bsta_mac_nr;
            memcpy(bsta_mld->aff_bsta_macs, aff_bsta_macs, len);
            update = true;
        }
    }

check_update:
    if (update) {
        call_bsta_mld_update_cbs(bsta_mld);
    }
}

/*#######################################################################
#                       VARIOUS                                         #
########################################################################*/
void map_dm_free_op_restriction_list(map_radio_info_t *radio)
{
    uint8_t i;

    for (i = 0; i < radio->op_restriction_list.op_classes_nr; i++) {
        SFREE(radio->op_restriction_list.op_classes[i].channels);
    }

    SFREE(radio->op_restriction_list.op_classes);
    radio->op_restriction_list.op_classes_nr = 0;
}

void map_dm_free_cac_methods(map_cac_method_t *cac_method, uint8_t count)
{
    uint8_t i;

    if (cac_method) {
        for (i = 0; i < count; i++) {
            free(cac_method[i].op_class_list.op_classes);
        }
        free(cac_method);
    }
}

void map_dm_free_non_1905_neighbor_list(map_ale_info_t *ale)
{
    uint8_t i;

    for (i = 0; i < ale->non_1905_neighbor_count; i++) {
        free(ale->non_1905_neighbor_list[i].macs);
    }

    SFREE(ale->non_1905_neighbor_list);
    ale->non_1905_neighbor_count = 0;
}

void map_dm_free_emex_eth_iface_list(map_ale_info_t *ale)
{
    map_emex_eth_iface_list_t *list = &ale->emex.eth_iface_list;
    size_t i;

    for (i = 0; i < list->iface_nr; i++) {
        free(list->ifaces[i].non_i1905_neighbor_macs);
        free(list->ifaces[i].filtered_non_i1905_neighbor_macs);
        free(list->ifaces[i].i1905_neighbor_macs);
    }

    SFREE(list->ifaces);
    list->iface_nr = 0;
}

void map_dm_get_ale_timer_id(timer_id_t id, map_ale_info_t *ale, const char *type)
{
    snprintf(id, sizeof(timer_id_t), "ALE-%s-%s", ale->al_mac_str, type);
}

void map_dm_get_ale_int_timer_id(timer_id_t id, map_ale_info_t *ale, const char *type, uint64_t val)
{
    snprintf(id, sizeof(timer_id_t), "ALE-%s-%s-%"PRIu64, ale->al_mac_str, type, val);
}

void map_dm_get_radio_timer_id(timer_id_t id, map_radio_info_t *radio, const char *type)
{
    snprintf(id, sizeof(timer_id_t), "RAD-%s_%s-%s", radio->ale->al_mac_str, radio->radio_id_str, type);
}

void map_dm_get_sta_timer_id(timer_id_t id, map_sta_info_t *sta, const char *type)
{
    snprintf(id, sizeof(timer_id_t), "STA-%s_%s-%s", sta->bss->bssid_str, sta->mac_str, type);
}

void map_dm_get_sta_mld_timer_id(timer_id_t id, map_sta_mld_info_t *sta_mld, const char *type)
{
    snprintf(id, sizeof(timer_id_t), "MSTA-%s_%s-%s", sta_mld->ap_mld->mac_str, sta_mld->mac_str, type);
}

void map_dm_mark_stas(map_ale_info_t *ale)
{
    map_radio_info_t *radio;
    map_bss_info_t   *bss;
    map_sta_info_t   *sta;

    map_dm_foreach_radio(ale, radio) {
        map_dm_foreach_bss(radio, bss) {
            map_dm_foreach_sta(bss, sta) {
                map_dm_mark_sta(sta);
            }
        }
    }
}

void map_dm_remove_marked_stas(map_ale_info_t *ale, unsigned int min_assoc_time)
{
    map_radio_info_t *radio;
    map_bss_info_t   *bss;
    map_sta_info_t   *sta, *next;
    uint64_t          ts_sec = acu_get_timestamp_sec();

    map_dm_foreach_radio(ale, radio) {
        map_dm_foreach_bss(radio, bss) {
            map_dm_foreach_sta_safe(bss, sta, next) {
                if (map_dm_is_marked_sta(sta)) {
                    uint64_t assoc_time = map_dm_get_sta_assoc_ts_delta2(ts_sec, sta->assoc_ts);
                    if (assoc_time > min_assoc_time) {
                        map_dm_remove_sta(sta);
                    }
                }
            }
        }
    }
}

void map_dm_mark_sta_mlds(map_ale_info_t *ale)
{
    map_ap_mld_info_t  *ap_mld;
    map_sta_mld_info_t *sta_mld;

    map_dm_foreach_ap_mld(ale, ap_mld) {
        map_dm_foreach_sta_mld(ap_mld, sta_mld) {
            map_dm_mark_sta_mld(sta_mld);
        }
    }
}

void map_dm_remove_marked_sta_mlds(map_ale_info_t *ale)
{
    map_ap_mld_info_t  *ap_mld;
    map_sta_mld_info_t *sta_mld, *next_sta_mld;

    map_dm_foreach_ap_mld(ale, ap_mld) {
        map_dm_foreach_sta_mld_safe(ap_mld, sta_mld, next_sta_mld) {
            if (map_dm_is_marked_sta_mld(sta_mld)) {
                map_dm_remove_sta_mld(sta_mld);
            }
        }
    }
}

/*#######################################################################
#                       INIT                                            #
########################################################################*/
int map_dm_init(void)
{
    /* Re-init list heads to avoid problems with not properly terminated unit tests */
    INIT_LIST_HEAD(&g_ale_list);
    INIT_LIST_HEAD(&g_event_lists.assoc_list);
    INIT_LIST_HEAD(&g_event_lists.disassoc_list);
    INIT_LIST_HEAD(&g_event_lists.failconn_list);

    INIT_LIST_HEAD(&g_dm_cbs_list);
    INIT_LIST_HEAD(&g_dm_unassociated_station_list);
    INIT_LIST_HEAD(&g_dpp_hash_list);

    map_dm_rbus_init();
    map_dm_eth_device_list_init(call_ale_eth_device_list_update_cbs);
    inactive_sta_list_init();

    return 0;
}

list_head_t *map_dm_get(void)
{
    return &g_ale_list;
}

map_event_lists_t *map_dm_get_events(void)
{
    return &g_event_lists;
}

void map_dm_fini(void)
{
    map_ale_info_t *ale, *next;
    map_assoc_data_t *assoc, *nexta;
    map_disassoc_data_t *disassoc, *nextd;
    map_failconn_data_t *failconn, *nextf;

    /* Call first so that dm objects are not removed one by one */
    map_dm_rbus_fini();
    map_dm_eth_device_list_fini();

    /* Remove all events */
    map_dm_foreach_assoc_safe(assoc, nexta) {
        map_dm_remove_assoc(assoc);
    }
    map_dm_foreach_disassoc_safe(disassoc, nextd) {
        map_dm_remove_disassoc(disassoc);
    }
    map_dm_foreach_failconn_safe(failconn, nextf) {
        map_dm_remove_failconn(failconn);
    }

    /* Remove all ale */
    map_dm_foreach_ale_safe(ale, next) {
        map_dm_remove_ale(ale);
    }

    map_dm_dpp_hash_list_fini();
    inactive_sta_fini();
}

/* Register dm callback functions (note: cbs must be static structure) */
void map_dm_register_cbs(map_dm_cbs_t *cbs)
{
    INIT_LIST_HEAD(&cbs->list);

    list_add_tail(&cbs->list, &g_dm_cbs_list);

    cbs->registered = true;
}

/* Unregister dm callback functions */
void map_dm_unregister_cbs(map_dm_cbs_t *cbs)
{
    if (cbs->registered) {
        list_del(&cbs->list);
        cbs->registered = false;
    }
}

void map_dm_set_nbapi_cbs(map_dm_nbapi_t *nbapi)
{
    g_map_nbapi_cbs = *nbapi;
}

map_dm_nbapi_t *map_dm_get_nbapi()
{
    return &g_map_nbapi_cbs;
}
