/*
 * Copyright (c) 2022-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#include "map_ctrl_chan_sel.h"

int map_ctrl_chan_sel_set(map_radio_info_t *radio, bool *cloud_mgmt_enable, bool *acs_enable,
                          map_channel_set_t *acs_channels, int *channel, int *bandwidth)
{
    return 0;
}

int map_ctrl_chan_sel_update(map_radio_info_t *radio)
{
    return 0;
}

void map_ctrl_chan_sel_dump(map_printf_cb_t print_cb, map_ale_info_t *ale, bool extended)
{
    print_cb("dump chan_sel %s %s\n", ale ? "ALE" : NULL, extended ? "EXT" : NULL);
}
