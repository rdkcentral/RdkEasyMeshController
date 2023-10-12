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
#define LOG_TAG "topology_tree"

#include "map_ctrl_topology_tree.h"
#include "map_ctrl_onboarding_handler.h"
#include "map_ctrl_defines.h"
#include "map_ctrl_cmdu_tx.h"
#include "map_ctrl_utils.h"
#include "map_topology_tree.h"
#include "map_staging_list.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define TOPOLOGY_CONFLICT_QUERY_DELAY 2 /* seconds */

/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
static void send_topology_query_for_children(map_ale_info_t *ale)
{
    map_ale_info_t *child_ale;

    /* Send topology query to all child nodes */
    forall_child_in(ale, child_ale) {
        log_ctrl_i("send topology query to ALE[%s] ", child_ale->al_mac_str);
        map_register_topology_query_retry(child_ale);
    }
}

static int detect_dead_agent_timer_cb(int status, void *ale_object, UNUSED void *cmdu)
{
    map_ale_info_t *ale = ale_object;
    uint64_t        no_update_since = 0;

    if (!ale) {
        goto done;
    }

    /* Timer removed at cleanup... -> do not remove ale again */
    if (status == MAP_RETRY_STATUS_CANCELLED) {
        goto done;
    }

    no_update_since = acu_timestamp_delta_sec(ale->keep_alive_time);
    if (ale->keep_alive_time == 0 || map_get_dead_agent_detection_interval() < no_update_since) {
        map_cleanup_agent(ale);
    }

done:
    /* Must return 0 to keep timer running */
    return 0;
}

static uint8_t delayed_topology_query_timer_cb(UNUSED char *timer_id, void *arg)
{
    map_ale_info_t *ale = arg;

    if (ale) {
        map_register_topology_query_retry(ale);
    }

    return 1; /* stop timer */
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
int map_ctrl_topology_tree_init(void)
{
    if (init_topology_tree(get_controller_cfg()->al_mac) < 0) {
        log_ctrl_e("failed to create controller topology tree");
        return -1;
    }

    return 0;
}

void map_add_as_child_of_controller(map_ale_info_t *ale)
{
    if (ale) {
        topology_tree_insert(get_root_ale_node(), ale);
    }
}

void map_build_topology_tree(map_ale_info_t *ale, i1905_neighbor_device_list_tlv_t **tlvs, uint8_t tlv_nr)
{
    map_ale_info_t *parent_of_ale;
    map_ale_info_t *neighbor_ale;
    bool            parent_of_ale_found                       = false;
    map_ale_info_t *conflict_ale_list[MAX_ALE_NEIGHBOR_COUNT] = {NULL};
    uint8_t         conflict_list_count                       = 0;
    int             new_neighbor_count                        = 0;
    uint8_t         i, j;

    /* If the current ALE is orphaned lets not process the neighbors */
    if (!ale || !(parent_of_ale = get_parent_ale_node(ale))) {
        return;
    }

    /* Iterate through all the neighbor device TLV */
    for (i = 0; i < tlv_nr; i++) {
        i1905_neighbor_device_list_tlv_t *current_tlv = tlvs[i];

        if (current_tlv == NULL) {
            continue;
        }

        for (j = 0; j < current_tlv->neighbors_nr;  j++) {
            i1905_neighbor_entry_t *neighbor               = &current_tlv->neighbors[j];
            map_ale_info_t         *parent_of_neighbor_ale = NULL;

            if (!(neighbor_ale = map_dm_get_ale(neighbor->mac_address))) {
                /* This new neighbor category is not clear yet? EM or good non-EM or bad non-EM */
                map_send_topology_query_with_al_mac(neighbor->mac_address, ale->iface_name, MID_NA);
                if (map_stglist_get_1905_dev(neighbor->mac_address)) {
                    continue; /* ALE is in the staging list */
                }
                if (!map_stglist_create_1905_dev(neighbor->mac_address, g_zero_mac, false)) {
                    log_ctrl_e("%s: Failed to create 1905 dev info", __FUNCTION__);
                }
                continue;
            }

            parent_of_neighbor_ale = get_parent_ale_node(neighbor_ale);

            /* Avoid handling local agent and controller as a neighbor
             *
             * Note: There are two possible cases need to be discriminated here:
             * If the Controller and local agent work in same device via loopback iface,
             * we shouldn't handle local agent because both of them discover same agents as neighbor.
             * But if controller and local agent work on different devices, we should consider local agent as well.
             */
            if (map_is_local_agent(neighbor_ale) && map_is_loopback_iface(neighbor_ale->iface_name)) {
                continue;
            }

            /* Skip this existing parent from neighbor list */
            if (neighbor_ale == parent_of_ale) {
                parent_of_ale_found = true;
                continue;
            }


            /* 1   Check if ALE is a child of neighbor */
            /* 1.1 If the controller is reported as the neighbor then make the current ALE as the child of controller. */
            if (map_is_controller(neighbor_ale)) {
                log_ctrl_i("[build_topology] ale[%s] neighbor[%s]: set ale parent to controller",
                           ale->al_mac_str, neighbor_ale->al_mac_str);

                topology_tree_insert(neighbor_ale, ale);

                /* Update information about upstream link */
                map_dm_ale_set_upstream_info(ale,
                                             /* upstream al mac     */ neighbor_ale->al_mac,
                                             /* local upstream mac  */ current_tlv->local_mac_address,
                                             /* remove upstream mac */ NULL,
                                             false, 0);

                parent_of_ale_found = true;
                continue;
            }

            /* 1.2 Check if neighbor is closer to root than current ALE parent */
            if (parent_of_neighbor_ale) {
                int parent_height = map_get_height_of(parent_of_ale);
                int neighbor_height = map_get_height_of(neighbor_ale);

                if ((parent_height > 0) && (neighbor_height > 0) && (neighbor_height < parent_height)) {
                    log_ctrl_i("[build_topology] ale[%s] neighbor[%s]: change ale parent from [%s] to neighbor",
                               ale->al_mac_str, neighbor_ale->al_mac_str, parent_of_ale->al_mac_str);

                    topology_tree_insert(neighbor_ale, ale);

                    /* Update information about upstream link */
                    map_dm_ale_set_upstream_info(ale,
                                                 /* upstream al mac     */ neighbor_ale->al_mac,
                                                 /* local upstream mac  */ current_tlv->local_mac_address,
                                                 /* remove upstream mac */ NULL,
                                                 false, 0);

                    parent_of_ale_found = true;
                    continue;
                }
            }


            /* 2   Check if ALE is a child of neighbor */
            /* 2.1 Add as child of ALE when neighbor has no parent */
            if (parent_of_neighbor_ale == NULL) {
                log_ctrl_i("[build_topology] ale[%s] neighbor[%s]: set neighbor as child of ale",
                           ale->al_mac_str, neighbor_ale->al_mac_str);

                topology_tree_insert(ale, neighbor_ale);
                new_neighbor_count++;

                /* Update information about upstream link. */
                map_dm_ale_set_upstream_info(neighbor_ale,
                                             /* upstream al mac     */ ale->al_mac,
                                             /* local upstream mac  */ NULL,
                                             /* remote upstream mac */ current_tlv->local_mac_address,
                                             false, 0);

                /* Update the receiving interface name. */
                map_strlcpy(neighbor_ale->iface_name, ale->iface_name, MAX_IFACE_NAME_LEN);
                continue;
            }

            /* 2.2 When neighbor is already child of parent, remove and add again (to the front) for easy deletion
                   of the no longer existing neighbors which will be at the end of the child list
            */
            if (parent_of_neighbor_ale == ale) {
                make_ale_orphaned(neighbor_ale);
                topology_tree_insert(ale, neighbor_ale);
                new_neighbor_count++;
                continue;
            }

            /* 2.3 If it is a child of controller then do nothing
                   NOTE: this could also be caught by check 2.4 below but keeping
                         check as controller's direct neighbors are very lickely to
                         be correct as we got a topology discovery from them
            */
            if (map_is_controller(parent_of_neighbor_ale)) {
                continue;
            }

            /* 2.4 If ALE and neighbor have the same parent then do nothing

                   This can happen in a topology with switch where ALE and neighbor report
                   the common parent and each other as neighbor.

                       PARENT
                         |
                       SWITCH
                       |    |
                       A    B
            */
            if (parent_of_neighbor_ale == parent_of_ale) {
                continue;
            }

            /* 2.5 There is a conflict. Send new topology query so neighbors are analyzed again */
            if (conflict_list_count < MAX_ALE_NEIGHBOR_COUNT) {
                conflict_ale_list[conflict_list_count++] = neighbor_ale;
            }
        }
    }

    /* If the old parent is not found in the new neighbor list disassemble the subtree */
    if (!parent_of_ale_found) {
        disassemble_tree(ale);
    }

    /* Send topology query to the conflict nodes */
    for (i = 0; i < conflict_list_count; i++) {
        /* Update the receiving interface name */
        map_update_ale_receiving_iface(conflict_ale_list[i], ale->iface_name);

        /* Send delayed topology query (to avoid query/response flood) */
        map_register_delayed_topology_query_retry(conflict_ale_list[i], TOPOLOGY_CONFLICT_QUERY_DELAY);
    }

    /* Handle neighbor deletion
       Old neighbors are bubbled towards the end of the list -> remove all nodes at the end.
    */
    foreach_child_in(ale, neighbor_ale) {
        if (new_neighbor_count == 0) {
            map_register_topology_query_retry(neighbor_ale);
            make_ale_orphaned(neighbor_ale);
        } else if (map_is_topology_update_required(neighbor_ale)) {
            map_register_topology_query_retry(neighbor_ale);
        }
        if (new_neighbor_count) {
            new_neighbor_count--;
        }
    }
}

void map_register_topology_query_retry(map_ale_info_t *ale)
{
    uint16_t   interval = map_get_topology_query_retry_interval_sec();
    timer_id_t retry_id;

    if (interval > 0) {
        map_dm_get_ale_timer_id(retry_id, ale, TOPOLOGY_QUERY_RETRY_ID);
        if (!map_is_timer_registered(retry_id)) {
            if (map_register_retry(retry_id, interval, MAX_TOPOLOGY_QUERY_RETRY, ale, detect_dead_agent_timer_cb, map_send_topology_query)) {
                log_ctrl_e("failed to register retry timer[%s]", retry_id);
            }
        }
    }
}

void map_register_delayed_topology_query_retry(map_ale_info_t *ale, uint32_t delay_sec)
{
    timer_id_t timer_id;

    map_dm_get_ale_timer_id(timer_id, ale, DELAYED_TOPOLOGY_QUERY_TIMER_ID);
    if (!map_is_timer_registered(timer_id)) {
        if (map_timer_register_callback(delay_sec, timer_id, (void *)ale, delayed_topology_query_timer_cb)) {
            log_ctrl_e("failed to register timer[%s]", timer_id);
        }
    }
}

int8_t map_cleanup_agent(map_ale_info_t *ale) {

    map_ale_info_t *child_ale;

    log_ctrl_n("-------------------------------------------");
    log_ctrl_n(" Deleting ALE : %s from DM", ale->al_mac_str);
    log_ctrl_n("-------------------------------------------");

    /* Trigger topology query for all child nodes before removing the ALE */
    send_topology_query_for_children(ale);

    foreach_child_in(ale, child_ale) {
        /* Clear information about upstream link */
        map_dm_ale_set_upstream_info(child_ale, g_zero_mac, g_zero_mac, g_zero_mac,
                                     true, INTERFACE_TYPE_UNKNOWN);
    }

    map_dm_remove_ale(ale);

    return 0;
}

void map_extend_ale_deletion(map_ale_info_t *ale)
{
    timer_id_t retry_id;

    map_dm_get_ale_timer_id(retry_id, ale, TOPOLOGY_QUERY_RETRY_ID);
    map_restart_retry_timer(retry_id);
}

uint8_t map_is_topology_update_required(map_ale_info_t *ale)
{
    if (ale) {
        uint64_t no_update_since = acu_timestamp_delta_sec(ale->keep_alive_time);
        if (ale->keep_alive_time == 0 || ALE_KEEP_ALIVE_THRESHOLD_IN_SEC < no_update_since) {
            return 1;
        }
    }
    return 0;
}

map_ale_info_t* map_get_local_agent_ale(void)
{
    return map_dm_get_ale(get_controller_cfg()->local_agent_al_mac);
}

bool map_is_local_agent(map_ale_info_t *ale)
{
    return ale->is_local;
}

bool map_is_controller(map_ale_info_t *ale)
{
    return ale == get_root_ale_node();
}
