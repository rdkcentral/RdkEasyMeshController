/*
 * Copyright (c) 2021-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#include "map_ctrl_tlv_helper.h"

int map_get_bridging_cap_tlv(i1905_device_bridging_cap_tlv_t *tlv)
{
    memset(tlv, 0, sizeof(*tlv));
    return 0;
}

void map_free_bridging_cap_tlv(i1905_device_bridging_cap_tlv_t *tlv)
{
}

int map_get_1905_neighbor_tlvs(i1905_neighbor_device_list_tlv_t **tlvs, size_t *tlvs_nr)
{
    *tlvs = NULL;
    *tlvs_nr = 0;
    return 0;
}

void map_free_1905_neighbor_tlv(i1905_neighbor_device_list_tlv_t *tlvs, size_t tlvs_nr)
{
}

int map_fill_channel_scan_request_tlv(map_channel_scan_request_tlv_t *tlv, map_radio_info_t *radio,
                                      bool fresh_scan, map_channel_set_t *channels)
{
    memset(tlv, 0, sizeof(*tlv));
    return 0;
}

void map_fill_default_8021q_settings_tlv(map_cfg_t *cfg, map_default_8021q_settings_tlv_t *tlv)
{
    memset(tlv, 0, sizeof(*tlv));
}

void map_fill_traffic_separation_policy_tlv(map_controller_cfg_t *cfg, uint16_t prim_vid, unsigned int max_vid_count,
                                            map_traffic_separation_policy_tlv_t *tlv)
{
    memset(tlv, 0, sizeof(*tlv));
}

void map_fill_empty_traffic_separation_policy_tlv(map_traffic_separation_policy_tlv_t *tlv)
{
    memset(tlv, 0, sizeof(*tlv));
}
