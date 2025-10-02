/********** COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) 2020-2020  -  AirTies Wireless Networks                **
** - All Rights Reserved                                                **
** AirTies hereby informs you that certain portions                     **
** of this software module and/or Work are owned by AirTies             **
** and/or its software providers.                                       **
** Distribution copying and modification of all such work are reserved  **
** to AirTies and/or its affiliates, and are not permitted without      **
** express written authorization from AirTies.                          **
** AirTies is registered trademark and trade name of AirTies,           **
** and shall not be used in any manner without express written          **
** authorization from AirTies                                           **
*************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "map_topology_tree.h"

int8_t create_topology_tree_node(map_ale_info_t *ale_node, tree_node_type_t type)
{
    return 0;
}

void remove_topology_tree_node(map_ale_info_t *ale_node)
{
}

map_ale_info_t* get_root_ale_node()
{
    return NULL;
}

int8_t is_parent_of(map_ale_info_t *parent, map_ale_info_t *child)
{
    return 0;
}

void dump_topology_tree(map_printf_cb_t print_cb)
{
}

map_ale_info_t* get_parent_ale_node(map_ale_info_t* child_ale)
{
    return NULL;
}

map_ale_info_t* fetch_and_free_child_iter(list_iterator_t* iter)
{
    return NULL;
}