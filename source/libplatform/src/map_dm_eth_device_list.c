/*
 * Copyright (c) 20022-2023 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/* NOTE:
   - Update is done 5 seconds after periodic topology query.  This means that
     it is expected that the topology responses have arrived during that time.

   - MACS are added to the ALE when they are present 4 times in
     a row (history depth + 1).  So after 4 minutes.

   - When an ale is created or updated, free the history as it might
     no longer be valid.

   - When an ale is removed, also free the history and on top wait for
     5 minutes.  This is to make sure that devices that where connected
     to the removed ALE do not appear behind an upstream ALE.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "dm_eth_device_list"
#include "map_dm_eth_device_list.h"
#include "map_data_model.h"
#include "map_topology_tree.h"
#include "map_timer_handler.h"
#include "map_utils.h"
#include "1905_platform.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define UPDATE_TIMEOUT          5
#define ALE_REMOVE_BACKOFF_TIME 300

#define foreach_non_1905_eth_iface(ale, idx, n) \
    for (idx = 0; n = &ale->non_1905_neighbor_list[i], idx < ale->non_1905_neighbor_count; idx++) \
        if (INTERFACE_TYPE_GROUP_GET(n->media_type) == INTERFACE_TYPE_GROUP_ETHERNET)

/*#######################################################################
#                       PROTOTYPES                                      #
########################################################################*/
static void ale_create_update_cb(map_ale_info_t *ale);

static void ale_remove_cb(map_ale_info_t *ale);

/*#######################################################################
#                       GLOBAL                                          #
########################################################################*/
static map_dm_eth_device_list_update_cb_t g_update_cb;
static uint64_t g_update_backoff_ts;

static map_dm_cbs_t g_dm_cbs = {
    .ale_create_cb = ale_create_update_cb,
    .ale_update_cb = ale_create_update_cb,
    .ale_remove_cb = ale_remove_cb,
};

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
/* Check if mac is an ALE or local interface */
static bool is_ale_or_iface_mac(mac_addr mac)
{
    map_ale_info_t *ale;
    size_t          i;

    map_dm_foreach_agent_ale(ale) {
        if (!maccmp(mac, ale->al_mac)) {
            return true;
        }

        for (i = 0; i < ale->local_iface_count; i++) {
            map_local_iface_t *iface = &ale->local_iface_list[i];

            if (!maccmp(mac, iface->mac_address)) {
                return true;
            }
        }
    }

    return false;
}

/* Check if mac is reported also by a downstream ALE */
static bool is_downstream_non_1905_eth_neighbor(map_ale_info_t *ale, mac_addr mac)
{
    map_ale_info_t          *parent_ale = ale->is_local_colocated ? get_root_ale_node() : ale;
    map_ale_info_t          *child;
    map_non_1905_neighbor_t *n;
    size_t                   i;
    bool                     ret = false;

    /* NOTE: If local agent is co-located with controller, we need to go over childs of controller */
    /* NOTE: Can't break or return from within foreach_child_in */
    foreach_child_in(parent_ale, child) {
        if (ret || child == ale) {
            continue;
        }

        foreach_non_1905_eth_iface(child, i, n) {
            if (acu_mac_in_sorted_array(mac, n->macs, n->macs_nr)) {
                ret = true;
                break;
            }
        }

        if (!ret && is_downstream_non_1905_eth_neighbor(child, mac)) {
            ret = true;
        }
    }

    return ret;
}

/* Check if interface is used as a backhaul in downstream or upstream direction */
static bool is_downstream_or_upstream_backhaul_iface(map_ale_info_t *ale, mac_addr mac)
{
    map_ale_info_t *parent_ale = ale->is_local_colocated ? get_root_ale_node() : ale;
    map_ale_info_t *child;
    bool            ret = false;

    /* Upstream */
    if (!ale->is_local && !maccmp(mac, ale->upstream_local_iface_mac)) {
        return true;
    }

    /* Downstream */
    /* NOTE: If local agent is co-located with controller, we need to iterate over childs of controller */
    /* NOTE: Can't break or return from within foreach_child_in */
    foreach_child_in(parent_ale, child) {
        if (ret || child == ale) {
            continue;
        }

        if (!maccmp(mac, child->upstream_remote_iface_mac)) {
            ret = true;
        }
    }

    return ret;
}

/* Check if MAC is found behind a non backhaul ethernet interface */
static bool is_behind_non_backhaul_eth_iface(map_ale_info_t *this_ale, mac_addr mac)
{
    map_ale_info_t          *ale;
    map_non_1905_neighbor_t *n;
    size_t                   i;

    map_dm_foreach_agent_ale(ale) {
        if (ale == this_ale) {
            continue;
        }

        foreach_non_1905_eth_iface(ale, i, n) {
            if (is_downstream_or_upstream_backhaul_iface(ale, n->local_iface_mac)) {
                continue;
            }

            if (acu_mac_in_sorted_array(mac, n->macs, n->macs_nr)) {
                return true;
            }
        }
    }

    return false;
}

static int derive_macs(map_ale_info_t *ale, mac_addr **ret_macs, size_t *ret_macs_nr)
{
    map_non_1905_neighbor_t *n;
    mac_addr                *macs;
    size_t                   i, j, macs_nr = 0;

    /* Count total nr of devices to allocate memory */
    foreach_non_1905_eth_iface(ale, i, n) {
        macs_nr += n->macs_nr;
    }

    if (macs_nr == 0) {
        *ret_macs = NULL;
        *ret_macs_nr = 0;
        return 0;
    }

    if (!(macs = malloc(macs_nr * sizeof(mac_addr)))) {
        return -1;
    }

    macs_nr = 0;
    foreach_non_1905_eth_iface(ale, i, n) {
        bool is_bh = is_downstream_or_upstream_backhaul_iface(ale, n->local_iface_mac);

        for (j = 0; j < n->macs_nr; j++) {
            uint8_t *mac = n->macs[j];

            /* Skip when MAC is an ALE or local iface MAC */
            if (is_ale_or_iface_mac(mac)) {
                continue;
            }

            /* Skip when MAC is a wifi client */
            if (map_dm_get_sta_gbl(mac) || map_dm_is_inactive_sta(mac)) {
                continue;
            }

            /* If interface is a backhaul (downstream or upstream) then skip when device is seen
               - behind a non backhaul interface
               - further downstream (see agent integration spec)
            */
            if (is_bh) {
                if (is_behind_non_backhaul_eth_iface(ale, mac)) {
                    continue;
                }

                if (is_downstream_non_1905_eth_neighbor(ale, mac)) {
                    continue;
                }
            }

            maccpy(macs[macs_nr], mac);
            macs_nr++;
        }
    }

    /* Sort list so order does not matter when comparing lists */
    acu_sort_mac_array(macs, macs_nr);

    *ret_macs    = macs;
    *ret_macs_nr = macs_nr;

    return 0;
}

/* Changed can go only to true, new_macs_equal to false */
static void update_ale(map_ale_info_t *ale)
{
    map_eth_device_list_t *list = &ale->eth_device_list;
    mac_addr              *new_macs;
    size_t                 new_macs_nr;
    mac_addr              *stable_macs;
    size_t                 stable_macs_nr = 0;
    size_t                 i, j;

    if (derive_macs(ale, &new_macs, &new_macs_nr)) {
        return;
    }

    /* Check if all history is set - don't update if not yet the case */
    for (i = 0; i < ETH_DEVICE_HISTORY_LEN; i++) {
        if (!list->h_set[i]) {
            goto update_history;
        }
    }

    /* Allocate memory to derive "stable" mac list */
    if (!(stable_macs = calloc(new_macs_nr, sizeof(mac_addr)))) {
        free(new_macs);
        return;
    }

    /* Go over history and add all macs where present all the time */
    for (i = 0; i < new_macs_nr; i++) {
        bool in_all = true;
        for (j = 0; j < ETH_DEVICE_HISTORY_LEN; j++) {
            if (!acu_mac_in_sorted_array(new_macs[i], list->h_macs[j], list->h_macs_nr[j])) {
                in_all = false;
                break;
            }
        }
        if (in_all) {
            maccpy(stable_macs[stable_macs_nr], new_macs[i]);
            stable_macs_nr++;
        }
    }

    /* Update if something changed */
    if (!acu_mac_array_equal(list->macs, list->macs_nr, stable_macs, stable_macs_nr)) {
        log_lib_d("updating eth devices for ale[%s] macs_nr[%zu -> %zu]", ale->al_mac_str, list->macs_nr, stable_macs_nr);

        free(list->macs);
        list->macs    = stable_macs;
        list->macs_nr = stable_macs_nr;

        if (g_update_cb) {
            g_update_cb(ale);
        }
    } else {
        free(stable_macs);
    }

update_history:
    /* Shift history */
    free(list->h_macs[ETH_DEVICE_HISTORY_LEN - 1]);
    for (i = ETH_DEVICE_HISTORY_LEN - 1; i >= 1; i--) {
        list->h_set[i]     = list->h_set[i - 1];
        list->h_macs[i]    = list->h_macs[i - 1];
        list->h_macs_nr[i] = list->h_macs_nr[i - 1];
    }
    list->h_set[0]     = true;
    list->h_macs[0]    = new_macs;
    list->h_macs_nr[0] = new_macs_nr;
}

static void emex_filter_non_i1905_neighbor_macs(map_ale_info_t *ale)
{
    map_emex_eth_iface_list_t *iface_list = &ale->emex.eth_iface_list;
    map_eth_device_list_t     *ale_eth_dev_list = &ale->eth_device_list;
    size_t i, j;

    for (i = 0; i < iface_list->iface_nr; i++) {
        map_emex_eth_iface_t *iface = &iface_list->ifaces[i];
        mac_addr             *new_list;

        iface->filtered_non_i1905_neighbor_macs_nr = 0;

        /* Check for empty list */
        if (iface->non_i1905_neighbor_macs_nr == 0) {
            SFREE(iface->filtered_non_i1905_neighbor_macs);
            continue;
        }

        /* Allocate room as big as unfiltered list */
        new_list = realloc(iface->filtered_non_i1905_neighbor_macs,
                           iface->non_i1905_neighbor_macs_nr * sizeof(mac_addr));
        if (!new_list) {
            SFREE(iface->filtered_non_i1905_neighbor_macs);
            continue;
        }
        iface->filtered_non_i1905_neighbor_macs = new_list;

        /* Add mac to filtered list when also in ale_eth_dev_list */
        for (j = 0; j < iface->non_i1905_neighbor_macs_nr; j++) {
            if (acu_mac_in_sorted_array(iface->non_i1905_neighbor_macs[j],
                                        ale_eth_dev_list->macs, ale_eth_dev_list->macs_nr)) {

                maccpy(iface->filtered_non_i1905_neighbor_macs[iface->filtered_non_i1905_neighbor_macs_nr++],
                       iface->non_i1905_neighbor_macs[j]);
            }
        }

        /* Sort list */
        acu_sort_mac_array(iface->filtered_non_i1905_neighbor_macs, iface->filtered_non_i1905_neighbor_macs_nr);
    }
}

static uint8_t update_timer_cb(UNUSED char* timer_id, UNUSED void *arg)
{
    map_ale_info_t *ale;
    uint64_t        ts = acu_get_timestamp_usec();

    map_dm_foreach_agent_ale(ale) {
        update_ale(ale);

        /* For emex: derive a filtered ethernet device list per ethernet port */
        emex_filter_non_i1905_neighbor_macs(ale);
    }

    log_lib_d("updated eth devices in %"PRIu64" usec", acu_timestamp_delta_usec(ts));

    return 1; /* Remove timer */
}

static void stop_timer(void)
{
    if (map_is_timer_registered(ETH_DEVICE_TIMER_ID)) {
        map_timer_unregister_callback(ETH_DEVICE_TIMER_ID);
    }
}

static void free_history(void)
{
    map_ale_info_t *ale;
    size_t          i;

    map_dm_foreach_agent_ale(ale) {
        for (i = 0; i < ETH_DEVICE_HISTORY_LEN; i++) {
            map_eth_device_list_t *list = &ale->eth_device_list;

            SFREE(list->h_macs[i]);
            list->h_macs_nr[i] = 0;
        }
    }
}

static void ale_create_update_cb(UNUSED map_ale_info_t *ale)
{
    /* New or updated ale -> history might now be invalid */
    free_history();
    stop_timer();
}

static void ale_remove_cb(UNUSED map_ale_info_t *ale)
{
    /* Do not update for some time as the other agents might still
       report macs that where connected to the removed ALE
    */
    free_history();
    stop_timer();
    g_update_backoff_ts = acu_get_timestamp_sec() + ALE_REMOVE_BACKOFF_TIME;
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
int map_dm_eth_device_list_schedule_update(void)
{
    /* Called after every periodic topology query.  Set some delay so
       we have received topology responses.
    */

    /* Do not schedule timer when in backoff */
    if (g_update_backoff_ts > acu_get_timestamp_sec()) {
        return 0;
    }

    stop_timer();
    if (map_timer_register_callback(UPDATE_TIMEOUT, ETH_DEVICE_TIMER_ID, NULL, update_timer_cb)) {
        log_lib_e("failed starting timer[%s]", ETH_DEVICE_TIMER_ID);
        return -1;
    }

    return 0;
}

int map_dm_eth_device_list_init(map_dm_eth_device_list_update_cb_t update_cb)
{
    g_update_backoff_ts = acu_get_timestamp_sec();
    g_update_cb = update_cb;

    map_dm_register_cbs(&g_dm_cbs);

    return 0;
}

void map_dm_eth_device_list_fini(void)
{
    map_dm_unregister_cbs(&g_dm_cbs);

    stop_timer();
}
