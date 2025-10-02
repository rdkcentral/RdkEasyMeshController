/*
 * Copyright (c) 2021-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#include "map_ctrl_emex_tlv_handler.h"
#include "map_emex_tlvs.h"

bool map_emex_is_valid_tlv(i1905_vendor_specific_tlv_t *vendor_tlv)
{
    return false;
}

int8_t map_emex_parse_tlv(map_ale_info_t *ale, i1905_vendor_specific_tlv_t *vendor_tlv)
{
    return 0;
}

bool map_emex_agent_is_feature_supported(map_ale_info_t *ale, uint16_t id)
{
    return true;
}

int map_emex_handle_cmdu_pre(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    return 0;
}

int map_emex_handle_cmdu_post(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    return 0;
}

int8_t map_emex_init(void)
{
    return 0;
}

void map_emex_fini(void)
{
}
