/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef MAP_CTRL_EMEX_TLV_HANDLER_H_
#define MAP_CTRL_EMEX_TLV_HANDLER_H_

#include "map_data_model.h"
#include "i1905.h"

/* Feature IDs reported in Feature Profile */
enum emex_feature_ids {
    MAP_EMEX_FEATURE_UNUSED         = 0x0000,
    MAP_EMEX_FEATURE_DEVICE_METRICS,                /* 0x0001 */
    MAP_EMEX_FEATURE_IEEE1905_1_14,                 /* 0x0002 */
    MAP_EMEX_FEATURE_DEVICE_INFO,                   /* 0x0003 */
    MAP_EMEX_FEATURE_ETH_STATS,                     /* 0x0004 */
    MAP_EMEX_FEATURE_REBOOT_RESET   = 0x0006,       /* 0x0006 */
};

enum emex_reboot_request_action_ids {
    MAP_EMEX_REBOOT_ACTION_REBOOT   = 0x00,
    MAP_EMEX_REBOOT_ACTION_RESET    = 0x01,
};

enum emex_reboot_request_reset_types {
    MAP_EMEX_RESET_SOFT_RESET       = 0x00,
    MAP_EMEX_RESET_FACTORY_RESET    = 0x01,
};

map_emex_common_feature_list_t *controller_get_emex_common_feature_list(void);

bool map_emex_agent_is_feature_supported(map_ale_info_t *ale, uint16_t id);
bool map_emex_common_is_feature_supported(uint16_t id);
bool map_emex_is_valid_tlv(i1905_vendor_specific_tlv_t* vendor_tlv);
int8_t map_emex_parse_tlv(map_ale_info_t* ale, i1905_vendor_specific_tlv_t* vendor_tlv);

int map_emex_handle_cmdu_pre(map_ale_info_t *ale, i1905_cmdu_t *cmdu);
int map_emex_handle_cmdu_post(map_ale_info_t *ale, i1905_cmdu_t *cmdu);

int8_t map_emex_init(void);
void   map_emex_fini(void);

#endif /* MAP_CTRL_EMEX_TLV_HANDLER_H_ */
