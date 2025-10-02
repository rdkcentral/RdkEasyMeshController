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

#include "map_retry_handler.h"

int map_register_retry(const char*     retry_id,
                       uint8_t         retry_intervel,
                       uint8_t         max_retry_count,
                       void           *args,
                       map_compl_cb_t  compl_cb,
                       map_retry_cb_t  retry_cb)
{
    uint16_t mid;

    /* Call once... */
    if (retry_cb) {
        retry_cb(args, &mid);
    }

    /* ...and completed */
    if (compl_cb != NULL) {
       compl_cb(MAP_RETRY_STATUS_SUCCESS, args, NULL);
    }
    return 0;
}

int map_update_retry_handler(uint16_t mid, void *compl_user_data)
{
    return 0;
}

int map_cleanup_retry_args(int status, void *args, void *compl_user_data)
{
    free(args);
    return 0;
}

int map_unregister_retry(const char* retry_id)
{
    return 0;
}

int map_unregister_retry_prefix(const char* retry_id_prefix)
{
    return 0;
}
