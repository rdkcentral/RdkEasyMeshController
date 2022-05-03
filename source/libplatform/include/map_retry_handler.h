/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

#ifndef MAP_RETRY_HANDLER_H_
#define MAP_RETRY_HANDLER_H_

#include <stdio.h>
#include <stdint.h>

#include "map_timer_handler.h"
#include "map_common_defines.h"

typedef int (*map_compl_cb_t)(int status, void *args, void *compl_user_data);
typedef int (*map_retry_cb_t)(void *args, uint16_t *mid);

typedef struct retry_handler_s
{
    char            timer_id[MAX_TIMER_ID_STRING_LENGTH];
    uint16_t        retry_id;
    uint8_t         retry_intervel;
    uint8_t         max_retry_count;
    uint8_t         retry_count;
    map_compl_cb_t  compl_cb;
    map_retry_cb_t  retry_cb;
    void           *args;
} map_retry_handler_t;

/** @brief Initializes the Retry timer module
 *
 *  @param : None
 *  @return -1 or error, 0 on success
 */
int map_retry_handler_init(void);

/** @brief De-initialize the Retry timer module
 *
*/
void map_retry_handler_fini(void);

/** @brief Register new retry timer callback
 *
 *
 *
 *  @param :
 *    retry_id        : Unique retry ID
 *    message_id      : Message ID of the 1905 message sent during retry
 *    retry_intervel  : Peroidicity of the retry
 *    max_retry_count : Maximum allowed retry count
 *                      0   - Infinite retry
 *                      >0  - max retry count
 *    args            : This will be passed as an argument to retry_cb
 *    compl_cb        : retry completion callback.
 *                      Handle args cleanup during completion cb.
 *    retry_cb        : Retry callback to be registered
 *
 *  @return -1 or error, 0 on success
 */
int map_register_retry( const char*     retry_id,
                        uint8_t         retry_intervel,
                        uint8_t         max_retry_count,
                        void           *args,
                        map_compl_cb_t  compl_cb,
                        map_retry_cb_t  retry_cb);

/** @brief Remove existig retry timer
 *
 *
 *
 *  @param :
 *    retry_id        : Unique retry ID
 *  @return -1 or error, 0 on success
 */
int map_unregister_retry(const char* retry_id);

/** @brief Remove existig retry timers which name stars with retry_id_prefix
 *
 *
 *
 *  @param :
 *    retry_id        : Unique retry ID
 *  @return -1 or error, 0 on success
 */
int map_unregister_retry_prefix(const char* retry_id_prefix);

/** @brief Retry completion check API
 *
 *  @param :
 *    mid           : Message id of CMDU received
 *    compl_user_data: Userdata provided with completed callback
 *
 *  @return -1 - Error case
 *           0 - Success Case
 */
int map_update_retry_handler(uint16_t mid, void *compl_user_data);

/** @brief Restart the retry timer
 *
 *  @param :
 *    mid           : Message id of CMDU received
 *    compl_user_data: Userdata provided with completed callback
 *
 *  @return -1 - Error case
 *           0 - Success Case
 */
int map_restart_retry_timer(const char* retry_id);

/** @brief Default completion callback
 *
 *  @param :
 *    status           : Status after retry ends
 *    args             : Args provided when registering retry
 *    compl_user_data  : User data provided with completed callback
 *
 *  @return -1 - Error case
 *           0 - Success Case
 */
int map_cleanup_retry_args(int status, void *args, void *compl_user_data);

#endif /* MAP_RETRY_HANDLER_H_ */
