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

#ifndef MAP_CTRL_POST_ONBOARDING_HANDLER_H_
#define MAP_CTRL_POST_ONBOARDING_HANDLER_H_

#include "map_data_model.h"
#include "map_retry_handler.h"

/* Channel selection handling declarations */
#define MAP_CHAN_SEL_QUERY   1
#define MAP_CHAN_SEL_REQUEST 2

/* Callbacks */
int map_build_and_send_policy_config(void *args /* type map_ale_info_t */, uint16_t *mid);

int map_handle_policy_config_sent(int status, void *args, void *compl_user_data);

int map_build_and_send_initial_channel_scan_req(void *args /* type map_radio_info_t */, uint16_t *mid);

int map_handle_initial_channel_scan_request_sent(int status, void *args, void *compl_user_data);

/* Onboarding status check timer */
int map_start_onboarding_status_check_timer(map_ale_info_t *ale);

/* Channel selection */
int map_agent_handle_channel_selection(map_ale_info_t *ale, map_radio_info_t *radio, int action);

int map_agent_cancel_channel_selection(map_ale_info_t *ale);

#endif /* MAP_CTRL_POST_ONBOARDING_HANDLER_H_ */
