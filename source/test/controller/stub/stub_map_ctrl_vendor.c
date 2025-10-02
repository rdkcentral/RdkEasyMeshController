/*
 * Copyright (c) 2021-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#include "stub_map_ctrl_vendor.h"

static stub_vendor_send_message_cb_t g_send_message_cb;

int map_ctrl_vendor_send_message(map_ale_info_t *ale, map_vendor_tlv_tuple_t tlvs[],
                                 uint8_t tlvs_cnt, uint16_t *mid)
{
    return g_send_message_cb ? g_send_message_cb(ale, tlvs, tlvs_cnt, mid) : 0;
}

void stub_vendor_register_send_message_cb(stub_vendor_send_message_cb_t cb)
{
    g_send_message_cb = cb;
}
