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

#ifndef MAP_CTRL_ONBOARDING_HANDLER_H_
#define MAP_CTRL_ONBOARDING_HANDLER_H_

#include "map_data_model.h"

/** @brief Intialize onboarding agent.
 *
 *  This will be used to intialize the internally maintained
 *  onboarding data structures
 *
 *  @return The status code 0-success, -ve for failure
 */
int map_onboarding_handler_init();

/** @brief Deintialize onboarding handler
 */
void map_onboarding_handler_fini(void);

/** @brief This API prepares the controller for new agent onboarding
 *
 *  This API will
 *      Create a new ALE data structure if not created already.
 *      Intiate a topology query
 *
 *  @param
 *      al_mac          - AL MAC address of the agent
 *      recv_iface      - Receiving interface Name
 *      easymesh_plus   - easymesh_plus agent indication
 *  @return The reference to map_ale_info_t on success otherwise NULL.
 */
map_ale_info_t* map_handle_new_agent_onboarding(uint8_t *al_mac, char* recv_iface, bool easymesh_plus);

/** @brief This API prepares the controller for new radio onboarding
 *
 *  This API will
 *      Create new Radio info node in data model if not created already.
 *      Intiates Policy configuration request message
 *
 *  @param
 *      al_mac              - AL MAC address of the agent
 *      recv_ifname         - Receiving interface Name
 *      do_policy_config    - policy config request decision
 *  @return The reference to map_ale_info_t on success otherwise NULL.
 */
map_radio_info_t* map_handle_new_radio_onboarding(map_ale_info_t *ale, uint8_t *radio_id, bool do_policy_config);

/** @brief Check if agent is onboarded
 *
 *  Returns true when agent is no longer in the onboarding list
 *
 *  @return True when agent is onboarded, false when onboarding is still ongoing
 */
bool map_is_agent_onboarded(map_ale_info_t *ale);

/** @brief Check if we received an M1 for all radsios
 *
 *  @return True when all M1 have been received
 */
bool map_is_all_radio_M1_received(map_ale_info_t* ale);

/** @brief Get the agent onborading
 *
 *  @param
 *      ale - Pointer to map_ale_info_t structure
 *
 *  @return The true if successfully onboarded otherwise false
 */
bool map_is_all_radio_configured(map_ale_info_t* ale);

/** @brief Checks if channel selection is enabled/disabled in UCI
 *
 *  @param 	None
 *  @return None
 */
bool map_is_channel_selection_enabled();

/** @brief Get dead agent detection interval from UCI
 *
 *  @param      None
 *  @return dead_agent_detection_interval from uci
 */
uint16_t map_get_dead_agent_detection_interval();

/** @brief Get topology query retry interval in sec
 *
 *  @param      None
 *  @return topology_query_retry_interval_sec
 */
uint16_t map_get_topology_query_retry_interval_sec();

/** @brief (Re)-start sending topology discovery on an interface
 *
 *  @param
 *      ifname    - interface name
 *  @return     None
 */
void map_restart_topology_discovery(const char *ifname);

/** @brief Stop sending topology discovery on an interface
 *
 *  @param
 *      ifname    - interface name
 *  @return     None
 */
void map_stop_topology_discovery(const char *ifname);

#endif /* MAP_CTRL_ONBOARDING_HANDLER_H_ */
