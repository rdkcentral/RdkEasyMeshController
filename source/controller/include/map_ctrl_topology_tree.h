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

#ifndef MAP_CTRL_TOPOLOGY_TREE_H_
#define MAP_CTRL_TOPOLOGY_TREE_H_

#include "map_data_model.h"
#include "1905_tlvs.h"

/** @brief Intialize controller's topology tree.
*
*   This will be used to intialize the internally maintained
*   topology tree data structures
*
*   @return The status code 0-success, -ve for failure
*/
int map_ctrl_topology_tree_init(void);

/** @brief This function will update topology
*   tree to add controller's child.
*
*   This will be used to add the immediate neighbors of controller
*   as the child of controller in topology tree data structures.
*
*   @return None
*/
void map_add_as_child_of_controller(map_ale_info_t *ale);

/** @brief This function will update tree from the neighbor list
*   tree to add
*
*   This will be used to create a topology tree from 1905 neighbor list TLV
*
*   @return None
*/
void map_build_topology_tree(map_ale_info_t *ale, i1905_neighbor_device_list_tlv_t **tlvs, uint8_t tlv_nr);

/** @brief This function create a retry timer to send topology query
 *
 *  This function registers to a retry timer to send topology query
 *  until we get a topology response
 *
 *  @param ale pointer to ALE node
 *  @return The 0- Expired , 1 - Query required
 */
void map_register_topology_query_retry(map_ale_info_t *ale);

/** @brief This function create a retry timer to send topology query after a delay
 *
 *  This function registers to a retry timer to send topology query after a delay
 *  until we get a topology response
 *
 *  @param ale        pointer to ALE node
 *  @param delay_sec  delay in seconds
 *  @return The 0- Expired , 1 - Query required
 */
void map_register_delayed_topology_query_retry(map_ale_info_t *ale, uint32_t delay_sec);

/** @brief This function will remove the dead ALE from controller DM
 *
 *  This API will cleanup all the resources assocciated with the ALE.
 *
 *  @param ale pointer to ALE node
 *  @return The 0 - Success, -1 - fail
 */
int8_t map_cleanup_agent(map_ale_info_t *ale);

/** @brief This function will extend the ALE deletion
 *
 *  This API restart the retry handler which extends the ALE deletion
 *
 *  @param ale pointer to ALE node to check for local agent
 *  @param cmdu that lead to completion of retry
 *  @return The 0- Expired , 1 - Query required
 */
void map_extend_ale_deletion(map_ale_info_t *ale);

/** @brief This function returns if we need to update the topology or not
 *
 *  This functions checks the last received topology response time stamp
 *  and take decision to register for topology query retry or not to
 *  control topology query flooding.
 *
 *  @param ale pointer to ALE node to check for local agent
 *  @return The 0- Expired , 1 - Query required
 */
uint8_t map_is_topology_update_required(map_ale_info_t *ale);

/** @brief This function will get the local agent dm from hash
 *
 *  @param ale pointer to ALE node of local agent
 */
map_ale_info_t* map_get_local_agent_ale(void);

/** @brief This function will return true the ALE node passed is local agent
 *
 *  @param ale pointer to ALE node to check for local agent
 *  @return true for local agent, false other agents
 */
bool map_is_local_agent(map_ale_info_t *ale);

/** @brief This function will return true the ALE node passed is controller
 *
 *  @param ale pointer to ALE node to check for controller
 *  @return ture for controller, false for other ALEs
 */
bool map_is_controller(map_ale_info_t *ale);

#endif /* MAP_CTRL_TOPOLOGY_TREE_H_ */
