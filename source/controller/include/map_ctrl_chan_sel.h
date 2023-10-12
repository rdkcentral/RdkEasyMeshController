/*
 * Copyright (c) 2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef MAP_CTRL_CHAN_SEL_H_
#define MAP_CTRL_CHAN_SEL_H_

#include "map_data_model.h"
#include "i1905.h"

/* Update controller preference and send channel selection request */
int map_ctrl_chan_sel_set(map_radio_info_t *radio, bool *acs_enable, map_channel_set_t *acs_channels,
                          int *channel, int *bandwidth);

int map_ctrl_chan_sel_set_channel(map_radio_info_t *radio, int channel);

int map_ctrl_chan_sel_set_bandwidth(map_radio_info_t *radio, int bandwidth);

/* Update controller preference but do not send channel selection request
   To be used when ctl_channels are updated.
*/
int map_ctrl_chan_sel_update(map_radio_info_t *radio);

void map_ctrl_chan_sel_dump(map_printf_cb_t print_cb, map_ale_info_t *ale, bool extended);

int map_ctrl_chan_sel_init(void);

void map_ctrl_chan_sel_fini(void);

#endif /* MAP_CTRL_CHAN_SEL_H_ */
