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

#define LOG_TAG "dm"

#include "map_data_model.h"
#include "map_dm_airdata.h"
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
    list_head_t hlist;
    mac_addr    mac;
} inactive_sta_t;

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static LIST_HEAD(g_ale_list);
static LIST_HEAD(g_dm_cbs_list);

/* Inactive sta list */
static LIST_HEAD(g_inactive_sta_list);
static list_head_t g_inactive_sta_hlist[MAP_MAX_MAC_HASH];
static size_t g_inactive_sta_count;

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

/*#######################################################################
#                       INACTIVE STA LIST                               #
########################################################################*/
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

    strcpy(ale->iface_name, "null");
    ale->upstream_iface_type = INTERFACE_TYPE_UNKNOWN;
    ale->ale_onboard_status = ALE_NODE_ONBOARDING;

    /* Create the neighbor link metrics */
    if (!(ale->eth_neigh_link_metric_list = new_array_list())) {
        log_lib_e("failed to create neighbor link metric list");
        return NULL;
    }

    /* Create new topology tree node for the al entity */
    if (create_topology_tree_node(ale, AL_ENTITY) < 0) {
        log_lib_e("failed to create topology tree node");
        delete_array_list(ale->eth_neigh_link_metric_list);
        free(ale);
        return NULL;
    }

    /* Init lists */
    INIT_LIST_HEAD(&ale->list);
    INIT_LIST_HEAD(&ale->radio_list);

    /* Add to linked list */
    list_add_tail(&ale->list, &g_ale_list);

    /* Call create callbacks */
    call_ale_create_cbs(ale);

    log_lib_d("-----------------------------------------------------");
    log_lib_d("| New MAP Agent %s ", ale->al_mac_str);
    log_lib_d("-----------------------------------------------------");

    return ale;
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

    return NULL;
}

int map_dm_remove_ale(map_ale_info_t *ale)
{
    map_radio_info_t *radio, *next;

    ale->removing = true;

    /* Cleanup all the timers */
    cleanup_ale_timers(ale);

    /* Remove local interface list */
    free(ale->local_iface_list);

    /* Free non 1905 neighbors */
    map_dm_free_non_1905_neighbor_list(ale);

    /* Call remove callbacks before removing radios to avoid that they need
       to be remove one by one.  This is ok for current use cases.
    */
    call_ale_remove_cbs(ale);

    /* cleanup the radios */
    map_dm_foreach_radio_safe(ale, radio, next) {
        if (map_dm_remove_radio(radio)) {
            log_lib_e("failed Removing radio");
            /* procceed cleaning other resources Event if cleanup of one radio failed. */
        }
    }

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
    free(ale->agent_extensions.feature_profile.feature_list);
    free(ale->agent_extensions.radios.info);

    /* Clean DPP specific allocations */
    free(ale->dpp_info.chirp.hash);
    free(ale->dpp_info.encap_msg.frame);

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
    map_radio_info_t *radio;

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

    /* Update the default to a invalid value */
    radio->supported_freq = 0xFF;

    /* Create the scan results list */
    if (!(radio->scanned_bssid_list = new_array_list())) {
        log_lib_e("failed to create scan results list");
        free(radio);
        return NULL;
    }

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

    /* Cleanup all the retry timers associated with this radio */
    cleanup_radio_timers(radio);

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

    /* Cleanup scan results list */
    if (radio->scanned_bssid_list) {
        while (list_get_size(radio->scanned_bssid_list) > 0) {
            map_scan_result_t *scan_info_obj = remove_last_object(radio->scanned_bssid_list);
            free(scan_info_obj);
        }
        delete_array_list(radio->scanned_bssid_list);
    }

    free(radio->ht_caps);
    free(radio->vht_caps);
    free(radio->he_caps);

    free(radio->cap_op_class_list.op_classes);
    free(radio->pref_op_class_list.op_classes);
    free(radio->ctrl_pref_op_class_list.op_classes);
    free(radio->op_restriction_list.op_classes);
    free(radio->scan_caps.op_class_list.op_classes);

    map_dm_free_cac_methods(radio->cac_caps.cac_method, radio->cac_caps.cac_method_count);

    free(radio->cac_completion_info.detected_pairs);
    free(radio->wifi6_caps);

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

    log_lib_d("Bss[%s] removed", bss->bssid_str);

    free(bss);

    return 0;
}

/*#######################################################################
#                       STA                                             #
########################################################################*/
map_sta_info_t *map_dm_create_sta(map_bss_info_t *bss, mac_addr mac)
{
    map_sta_info_t *sta;

    if ((sta = map_dm_get_sta(bss, mac))) {
        return sta;
    }

    if (!(sta = calloc(1, sizeof(map_sta_info_t)))) {
        log_lib_e("failed to allocating memory");
        return NULL;
    }

    /* Update mac address */
    maccpy(sta->mac, mac);
    mac_to_string(sta->mac, sta->mac_str);

    /* Create sta metrics array */
    if (!(sta->metrics = new_array_list())) {
        log_lib_e("failed to create sta metrics list");
        free(sta);
        return NULL;
    }

    /* Init lists */
    INIT_LIST_HEAD(&sta->list);
    INIT_LIST_HEAD(&sta->hlist);

    /* Link with bss */
    map_dm_update_sta_bss(bss, sta);

    /* Remove from inactive sta list */
    inactive_sta_remove(mac);

    log_lib_d("-----------------------------------------------------\n");
    log_lib_d("| New STA %s ", sta->mac_str);
    log_lib_d("-----------------------------------------------------\n");

    return sta;
}

int map_dm_update_sta_bss(map_bss_info_t *bss, map_sta_info_t *sta)
{
    int h = mac_hash(sta->mac);

    /* Remove from old bss (can only be NULL when called from create_bss above) */
    if (sta->bss) {
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
    /* Cleanup retry timers associated with STA */
    cleanup_sta_timers(sta);

    /* Removes the metrics reference from sta */
    if (sta->metrics != NULL) {
        while (list_get_size(sta->metrics) > 0) {
            free(remove_last_object(sta->metrics));
        }
        delete_array_list(sta->metrics);
    }

    /* Cleanup Beacon metrics */
    free(sta->beacon_metrics);

    /* Cleanup STA traffic stats */
    free(sta->traffic_stats);

    /* Cleanup STA assoc frame */
    free(sta->assoc_frame);

    /* Cleanup STA tunneled messages */
    if (sta->tunneled_msg) {
        free(sta->tunneled_msg->assoc_req_body);
        free(sta->tunneled_msg->reassoc_req_body);
        free(sta->tunneled_msg->btm_query_body);
        free(sta->tunneled_msg->wnm_req_body);
        free(sta->tunneled_msg->anqp_req_body);
        free(sta->tunneled_msg);
    }

    /* STA extended metrics */
    free(sta->last_sta_ext_metrics.ext_bss_metrics_list);

    /* Unlink */
    sta->bss->stas_nr--;
    list_del(&sta->list);
    list_del(&sta->hlist);

    /* Add to inactive sta list */
    inactive_sta_add(sta->mac);

    free(sta);
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
            ale->ale_onboarding_time = get_current_time();
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
        call_ale_update_cbs(ale);
    }
}

void map_dm_radio_set_capabilities(map_radio_info_t *radio)
{
    call_radio_update_cbs(radio);
}

void map_dm_radio_set_channel(map_radio_info_t *radio, uint8_t op_class, uint8_t channel, uint8_t bw, uint8_t tx_pwr)
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
    }

    if (radio->current_tx_pwr != tx_pwr) {
        radio->current_tx_pwr = tx_pwr;
    }

    if (update) {
        call_radio_update_cbs(radio);
    }
}

void map_dm_radio_set_configured_channel(map_radio_info_t *radio, uint8_t channel, uint8_t bw)
{
    bool update = false;

    if (radio->configured_channel != channel) {
        radio->configured_channel = channel;
        update = true;
    }

    if (radio->configured_bw != bw) {
        radio->configured_bw = bw;
        update = true;
    }

    if (update) {
        call_radio_update_cbs(radio);
    }
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

/*#######################################################################
#                       VARIOUS                                         #
########################################################################*/
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

/*#######################################################################
#                       INIT                                            #
########################################################################*/
int map_dm_init(void)
{
    map_dm_airdata_init();
    inactive_sta_list_init();
    return 0;
}

list_head_t *map_dm_get(void)
{
    return &g_ale_list;
}

void map_dm_fini(void)
{
    map_ale_info_t *ale, *next;

    /* Call first so that airdata objects are not removed one by one */
    map_dm_airdata_fini();

    /* Remove all ale */
    map_dm_foreach_ale_safe(ale, next) {
        map_dm_remove_ale(ale);
    }

    inactive_sta_fini();
}

/* Register dm callback functions (note: cbs must be static structure) */
void map_dm_register_cbs(map_dm_cbs_t *cbs)
{
    INIT_LIST_HEAD(&cbs->list);

    list_add(&cbs->list, &g_dm_cbs_list);

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

