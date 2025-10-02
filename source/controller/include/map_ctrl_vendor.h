/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef MAP_CTRL_VENDOR_H
#define MAP_CTRL_VENDOR_H

#include "map_info.h"
#include "map_config.h"
#include "map_ctrl_cmdu_tx.h"

int map_ctrl_vendor_send_message(map_ale_info_t *ale, map_vendor_tlv_tuple_t tlvs[],
                                 uint8_t tlvs_cnt, uint16_t *mid);
int map_ctrl_vendor_send_reboot_request(map_ale_info_t *ale, uint8_t action_type, uint8_t reset_type);
void map_ctrl_vendor_fini(void);
int map_ctrl_vendor_init(void);

#endif /* MAP_CTRL_VENDOR_H */
