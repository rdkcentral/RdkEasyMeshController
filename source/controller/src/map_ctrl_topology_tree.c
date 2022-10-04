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

    if (!ale) {
        goto done;
    }

    /* Timer removed at cleanup... -> do not remove ale again */
    if (status == MAP_RETRY_STATUS_CANCELLED) {
        goto done;
    }

    uint64_t no_update_since = get_clock_diff_secs(get_current_time(), ale->keep_alive_time);
    if (map_get_dead_agent_detection_interval() < no_update_since) {
        map_cleanup_agent(ale);
    }

done:
    /* Must return 0 to keep timer running */
    return 0;
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
    map_ale_info_t *neighbor_ale;
    bool            parent_of_ale_found                       = false;
    map_ale_info_t *conflict_ale_list[MAX_ALE_NEIGHBOR_COUNT] = {NULL};
    uint8_t         conflict_list_count                       = 0;
    int             new_neighbor_count                        = 0;
    uint8_t         i, j;

    /* If the current ALE is orphaned lets not process the neighbors */
    if (!ale || !get_parent_ale_node(ale)) {
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
                map_1905_dev_info_t        *dev;

                /* This new neighbor category is not clear yet? EM or good non-EM or bad non-EM */
                map_send_topology_query_with_al_mac(neighbor->mac_address, ale->iface_name, MID_NA);
                if (NULL != (dev = map_stglist_get_1905_dev(neighbor->mac_address))) {
                    continue; /* ALE is in the staging list */
                }
                if (!(dev = map_stglist_create_1905_dev(neighbor->mac_address, g_zero_mac, false))) {
                    log_ctrl_e("%s: Failed to create 1905 dev info", __FUNCTION__);
                }
                continue;
            }

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
            if (neighbor_ale == get_parent_ale_node(ale)) {
                parent_of_ale_found = get_parent_ale_node(ale);
                continue;
            }

            /* If the controller is reported as the neighbor then make the current ALE as the child of controller. */
            if (map_is_controller(neighbor_ale)) {
                if (!is_parent_of(neighbor_ale,ale)) {
                    topology_tree_insert(neighbor_ale, ale);

                    /* Update information about upstream link */
                    map_dm_ale_set_upstream_info(ale,
                                                 /* upstream al mac     */ neighbor_ale->al_mac,
                                                 /* local upstream mac  */ current_tlv->local_mac_address,
                                                 /* remove upstream mac */ NULL,
                                                 false, 0);
                }
                parent_of_ale_found = get_parent_ale_node(ale);
                continue;
            }

            parent_of_neighbor_ale = get_parent_ale_node(neighbor_ale);
            if (parent_of_neighbor_ale == NULL) {
                /* Add this neighbor as child of current ALE. */
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
            } else if (parent_of_neighbor_ale == ale) {
                /* Alread a child node. Remove from the list and add it to the front for easy deletion. */
                make_ale_orphaned(neighbor_ale);
                topology_tree_insert(ale, neighbor_ale);
                new_neighbor_count++;
            } else if (map_is_controller(parent_of_neighbor_ale)){
                /* It is already a child of the controller. Do nothing. */
            } else {
                /* This conflict can only be resolved after iterating all the TLVs. */
                if (conflict_list_count < MAX_ALE_NEIGHBOR_COUNT) {
                    conflict_ale_list[conflict_list_count++] = neighbor_ale;
                }
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

        /* Send topology query */
        map_register_topology_query_retry(conflict_ale_list[i]);
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

int8_t map_cleanup_agent(map_ale_info_t *ale) {

    map_ale_info_t *child_ale;

    log_ctrl_i("-------------------------------------------");
    log_ctrl_i(" Deleting ALE : %s from DM", ale->al_mac_str);
    log_ctrl_i("-------------------------------------------");

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
        uint64_t no_update_since = get_clock_diff_secs( get_current_time(), ale->keep_alive_time);
        if (ALE_KEEP_ALIVE_THRESHOLD_IN_SEC < no_update_since) {
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
