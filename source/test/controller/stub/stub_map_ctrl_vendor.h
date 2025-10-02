/*
 * Copyright (c) 2021-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef STUB_MAP_CTRL_VENDOR_H_
#define STUB_MAP_CTRL_VENDOR_H_

#include "map_ctrl_vendor.h"

typedef int (*stub_vendor_send_message_cb_t)(map_ale_info_t *ale, map_vendor_tlv_tuple_t tlvs[],
                                             uint8_t tlvs_cnt, uint16_t *mid);

void stub_vendor_register_send_message_cb(stub_vendor_send_message_cb_t cb);

#endif /* STUB_MAP_CTRL_VENDOR_H_ */
