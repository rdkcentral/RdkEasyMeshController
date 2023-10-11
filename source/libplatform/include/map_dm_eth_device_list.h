/*
 * Copyright (c) 20022-2023 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef MAP_DM_ETH_DEVICE_LIST_H_
#define MAP_DM_ETH_DEVICE_LIST_H_

#include "map_data_model.h"

typedef void (*map_dm_eth_device_list_update_cb_t)(map_ale_info_t *ale);

int map_dm_eth_device_list_schedule_update(void);

int map_dm_eth_device_list_init(map_dm_eth_device_list_update_cb_t update_cb);

void map_dm_eth_device_list_fini(void);

#endif /* MAP_DM_ETH_DEVICE_LIST_H_ */
