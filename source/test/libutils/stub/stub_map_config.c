/********** COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) 2020-2020  -  AirTies Wireless Networks                **
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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "map_config.h"

static map_cfg_t g_cfg;

map_cfg_t *map_cfg_get(void)
{
    return &g_cfg;
}

map_controller_cfg_t *map_controller_cfg_get(void)
{
    return &g_cfg.controller_cfg;
}

int map_cfg_set_master_state(bool master)
{
    map_cfg_get()->is_master = master;

    return 0;
}

void map_profile_clone(map_profile_cfg_t *dst, map_profile_cfg_t *src)
{
    *dst = *src;
}
