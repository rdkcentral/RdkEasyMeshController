/*
 * Copyright (c) 2021-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#include "map_ctrl_topology_tree.h"

void map_build_topology_tree(map_ale_info_t *ale, i1905_neighbor_device_list_tlv_t **tlvs, uint8_t tlv_nr)
{
}

void map_add_as_child_of_controller(map_ale_info_t *ale)
{
}

uint8_t map_is_topology_update_required(map_ale_info_t *ale)
{
    return 0;
}

void map_register_topology_query_retry(map_ale_info_t *ale)
{
}

void map_extend_ale_deletion(map_ale_info_t *ale)
{
}

bool map_is_local_agent(map_ale_info_t *ale)
{
    return false;
}

bool map_is_controller(map_ale_info_t *ale)
{
    return false;
}

map_ale_info_t* map_get_local_agent_ale()
{
    return NULL;
}

int8_t map_cleanup_agent(map_ale_info_t *ale)
{
    return 0;
}
