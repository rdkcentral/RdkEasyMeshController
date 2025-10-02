/********** COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) 2022-2022  -  AirTies Wireless Networks                **
** - All Rights Reserved                                                **
** AirTies hereby informs you that certain portions                     **
** of this software module and/or Work are owned by AirTies             **
** and/or its software providers.                                       **
** Distribution copying and modification of all such work are reserved  **
** to AirTies and/or its affiliates, and are not permitted without      **
** express written authorization from AirTies.                          **
** AirTies is registered trademark and trade name of AirTies,           **
** and shall not be used in any manner without express written          **
** authorization from AirTies                                           **
*************************************************************************/

#include "map_dm_eth_device_list.h"

#include "test.h"

int map_dm_eth_device_list_schedule_update(void)
{
    map_ale_info_t *ale;
    mac_addr        macs[2] = {{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}};

    /* Add some dummy macs */
    map_dm_foreach_agent_ale(ale) {
        if (!ale->eth_device_list.macs) {
            fail_unless(!!(ale->eth_device_list.macs = malloc(2 * sizeof(mac_addr))));
            memcpy(ale->eth_device_list.macs, macs, sizeof(macs));
            ale->eth_device_list.macs_nr = 2;
        }
    }

    return 0;
}

int map_dm_eth_device_list_init(map_dm_eth_device_list_update_cb_t update_cb)
{
    return 0;
}

void map_dm_eth_device_list_fini(void)
{
}
