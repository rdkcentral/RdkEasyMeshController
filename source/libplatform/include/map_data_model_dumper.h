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

#ifndef MAP_DATA_MODEL_DUMPER_H_
#define MAP_DATA_MODEL_DUMPER_H_

#include "map_data_model.h"

/** @brief This will dump the agent info tree on the terminal
 *
 * It prints all the agents data in the below hierarchy
 *
 *  Agent Info
 *          |_ Radio info
 *                      |_ BSS info
 *  @param None
 *  @return Node
 */
void map_dm_dump_agent_info_tree(map_printf_cb_t print_cb);

/** @brief Dump tunneled messages
 *
 */
void map_dm_dump_tunneled_messages(map_printf_cb_t print_cb, uint8_t *sta_mac, uint8_t type);

#endif /* MAP_DATA_MODEL_DUMPER_H_ */
