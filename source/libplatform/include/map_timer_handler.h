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

#ifndef MAP_TIMER_HANDLER_H_
#define MAP_TIMER_HANDLER_H_

#include <stdio.h>
#include <stdbool.h>

#include "map_common_defines.h"

typedef char timer_id_t[MAX_TIMER_ID_STRING_LENGTH];

typedef uint8_t (*timer_cb_t)(char* timer_id, void *arg);

/** @brief Initializes the MAP timer module
 *
 *
 *  @return -1 or error, 0 on success
 */
int map_timer_handler_init(void);

/** @brief Register timer callback
 *
 *  This will register a new timer call back
 *
 *  @param
 *    frequency_ms    - Frequency of the callback
 *    timer_id        - pointer to char will be filled unique timer id for later usage.
 *    args            - Callback args
 *    cb              - Function call back to be called upon timer expiry
 *
 *  @return -1 or error, 0 on success
 */
int map_timer_register_callback(uint32_t    frequency_sec,
                                const char *timer_id,
                                void       *args,
                                timer_cb_t  cb);


/** @brief Check if the timer id is registered.
 *
 *  This API will identify if the timer ID is registed already or not.
 *
 *  @param
 *    timer_id        - pointer to char will be unique timer that we are searching for.
 *
 *
 *  @return 1 if exists or 0 if not
 */
bool map_is_timer_registered(const char *timer_id);

/** @brief Un-register timer callback
 *
 *  This will remove the already registered callback
 *
 *  @param
 *    timer_id        - unique timer ID used during map_timer_register_callback
 *
 *  @return Pointer to args passed during map_timer_register_callback
 */
int map_timer_unregister_callback(const char *timer_id);

/** @brief Un-register timer callback staring with timer_id_prefix
 *
 *  This will remove the already registered callback
 *
 *  @param
 *    timer_id        - unique timer ID used during map_timer_register_callback
 *
 *  @return Pointer to args passed during map_timer_register_callback
 */
int map_timer_unregister_callback_prefix(const char *timer_id_prefix);

/** @brief Cleanup all the timer resources
 *
 *  This API should only be called upon exiting the controller/Agent
 */
void map_timer_handler_fini();

/** @brief Restart timer.
 *
 *  This API will restart the timer.
 *
 *  @param
 *    timer_id        - pointer to char will be unique timer that we are searching for.
 *
 *
 *  @return 0 on success, < 0 on failure
 */
int map_timer_restart_callback(const char* timer_id);

/** @brief Change timer.
 *
 *  This API will change the timer frequency and args
 *
 *  @param
 *    timer_id        - pointer to char will be unique timer that we are searching for.
 *    frequency_sec   - new frequency
 *    args            - new args
 *
 *
 *  @return 0 on success, < 0 on failure
 */
int map_timer_change_callback(const char *timer_id, uint32_t frequency_sec, void *args);

/** @brief Get time before timer will expire
 *
 *
 *  @param
 *    timer_id        - pointer to char will be unique timer that we are searching for.
 *    remaining_sec   - time in seconds before timer will expire
 *
 *  @return 0 on success, < 0 on failure
 */
int map_timer_remaining(const char *timer_id, uint32_t *remaining_sec);

#endif /* MAP_TIMER_HANDLER_H_ */
