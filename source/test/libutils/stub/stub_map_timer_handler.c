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

#include "map_timer_handler.h"

bool map_is_timer_registered(const char *timer_id)
{
    return 0;
}

int map_timer_register_callback(uint32_t    frequency_sec,
                                const char *timer_id,
                                void       *args,
                                timer_cb_t  cb)
{
    /* Call immediatly */
    if (cb) {
        cb((char*)timer_id, args);
    }

    return 0;
}

int map_timer_unregister_callback(const char *timer_id)
{
    return 0;
}

int map_timer_unregister_callback_prefix(const char *timer_id_prefix)
{
    return 0;
}

int map_timer_restart_callback(const char* timer_id)
{
    return 0;
}

int map_timer_change_callback(const char *timer_id, uint32_t frequency_sec, void *args)
{
    return 0;
}

int map_timer_remaining(const char *timer_id, uint32_t *remaining_sec)
{
    *remaining_sec = 0;

    return 0;
}
