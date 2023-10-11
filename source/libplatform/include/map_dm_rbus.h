/*
 * Copyright (c) 2021-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef MAP_DM_RBUS_H_
#define MAP_DM_RBUS_H_

#include "map_data_model.h"

map_ale_info_t *map_dm_rbus_get_ale(int ale_idx);

map_radio_info_t *map_dm_rbus_get_radio(map_ale_info_t *ale, int radio_idx);

int map_dm_rbus_init(void);

void map_dm_rbus_fini(void);

#endif /* MAP_DM_RBUS_H_ */
