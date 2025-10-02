/*
 * Copyright (c) 2021-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#include "map_ctrl_utils.h"

map_controller_cfg_t* get_controller_cfg()
{
    return &map_cfg_get()->controller_cfg;
}

bool map_is_channel_in_cap_op_class(map_op_class_t *cap_op_class, uint8_t channel)
{
    return true;
}
