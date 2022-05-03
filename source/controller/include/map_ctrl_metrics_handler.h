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

#ifndef MAP_CTRL_METRICS_HANDLER_H_
#define MAP_CTRL_METRICS_HANDLER_H_

#include "map_data_model.h"

void    map_update_assoc_sta_link_metrics(map_sta_info_t* sta, map_sta_link_metrics_t* link_metrics);
uint8_t map_periodic_link_metric_query_timer_cb(char* timer_id, void *arg);

#endif /* MAP_CTRL_METRICS_HANDLER_H_ */
