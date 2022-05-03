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

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>

#define LOG_TAG "retry"

#include "map_retry_handler.h"
#include "map_common_defines.h"
#include "map_utils.h"
#include "arraylist.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define CASTO_RETRY(p)  ((map_retry_handler_t*)p)
#define CASTO_MID(p)    ((uint16_t*)p)

#define CONTINUE_RETRY_TIMER    0
#define UNREGISTER_RETRY_TIMER  1

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static array_list_t* retry_list = NULL;

/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
static int compare_mid(void* retry_object, void* mid_to_find)
{
    if (*CASTO_MID(mid_to_find) == CASTO_RETRY(retry_object)->retry_id) {
        return 1;
    }
    return 0;
}

static int compare_retry_id(void* retry_object, void* retry_id_to_find)
{
    if (strcmp(retry_id_to_find, CASTO_RETRY(retry_object)->timer_id) == 0) {
        return 1;
    }
    return 0;
}

static int compare_retry_id_prefix(void* retry_object, void* retry_id_to_find)
{
    if (strncmp(retry_id_to_find, CASTO_RETRY(retry_object)->timer_id, strlen(retry_id_to_find)) == 0) {
        return 1;
    }
    return 0;
}

static void cleanup_retry_obj(map_retry_handler_t *retry_obj, int status, void *compl_user_data)
{
    if (retry_obj->compl_cb != NULL) {
       retry_obj->compl_cb(status, retry_obj->args, compl_user_data);
    }
    free(retry_obj);
}

static uint8_t max_retry_check_and_cleanup(map_retry_handler_t *retry_obj)
{
    /* Update the retry count */
    retry_obj->retry_count++;

    /* Check for max retry count */
    if (retry_obj->max_retry_count != 0 &&
        retry_obj->retry_count == retry_obj->max_retry_count) {
        /* Max retry count achived stop retry timer or callback completed its purpose
           Completion CB should cleanup all the resource passed by user
        */
        remove_object(retry_list, retry_obj);
        cleanup_retry_obj(retry_obj, MAP_RETRY_STATUS_TIMEOUT, NULL);
        return UNREGISTER_RETRY_TIMER;
    }
    return CONTINUE_RETRY_TIMER;
}

static void call_retry_cb(map_retry_handler_t *retry_obj)
{
    uint16_t mid = 0;

    /* Reset the MID */
    retry_obj->retry_id = 0;

    if (-1 == retry_obj->retry_cb(retry_obj->args, &mid)) {
        log_lib_e("retry callback failed for retry_id[%s]", retry_obj->timer_id);
    }
    /* Catch the mid sent in retry cb */
    retry_obj->retry_id = mid;
}

static uint8_t map_retry_timer_cb(char* timer_id, void* retry_obj)
{
    /* Validate the input parameters */
    if (timer_id == NULL || retry_obj == NULL || CASTO_RETRY(retry_obj)->retry_cb == NULL) {
        log_lib_e("calling retry cb failed");
        return UNREGISTER_RETRY_TIMER; /* Unregister during error case */
    }

    /* Call the Retry callback */
    call_retry_cb(retry_obj);

    /* Max retry check */
    return max_retry_check_and_cleanup(CASTO_RETRY(retry_obj));
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
int map_retry_handler_init(void)
{
    retry_list = new_array_list();
    if (retry_list == NULL) {
        log_lib_e("failed to create new array list for retry module");
        return -1;
    }
    return 0;
}

void map_retry_handler_fini(void)
{
    delete_array_list(retry_list);
}

int map_register_retry(const char*     retry_id,
                       uint8_t         retry_intervel,
                       uint8_t         max_retry_count,
                       void           *args,
                       map_compl_cb_t  compl_cb,
                       map_retry_cb_t  retry_cb)
{
    int8_t status = 0;
    map_retry_handler_t *retry_obj = NULL;
    do {
        /* Input args check */
        if (retry_id == NULL || retry_cb == NULL || retry_intervel == 0) {
            log_lib_e("invalid input args");
            ERROR_EXIT(status)
        }
        size_t str_len = strlen(retry_id);
        if (str_len >= MAX_TIMER_ID_STRING_LENGTH) {
            ERROR_EXIT(status)
        }

        if (map_is_timer_registered(retry_id)) {
            log_lib_d("retry_id[%s] already running", retry_id);
            ERROR_EXIT(status)
        }

        retry_obj = calloc(1, sizeof(map_retry_handler_t));
        if (retry_obj == NULL) {
            log_lib_e("alloc retry object failed");
            ERROR_EXIT(status)
        }

        strncpy(retry_obj->timer_id, retry_id, MAX_TIMER_ID_STRING_LENGTH);
        retry_obj->timer_id[MAX_TIMER_ID_STRING_LENGTH-1] = '\0';
        retry_obj->retry_intervel = retry_intervel;
        retry_obj->max_retry_count = max_retry_count;
        retry_obj->compl_cb = compl_cb;
        retry_obj->retry_cb = retry_cb;
        retry_obj->args = args;

        /* Update the retry mid array list */
        if (-1 == push_object(retry_list, retry_obj)) {
            log_lib_e("failed to insert retry_id[%s] in retry list", retry_id);
            ERROR_EXIT(status)
        }

        /* Register this retry with the periodic timer handler */
        if (-1 == map_timer_register_callback(retry_intervel, retry_id, retry_obj, map_retry_timer_cb)) {
            log_lib_e("failed to register timer for retry_id[%s]", retry_id);
            pop_object(retry_list); /* Remove the mid Mapping */
            ERROR_EXIT(status)
        }

        /* Call the first retry callback immediatly */
        call_retry_cb(retry_obj);

    } while (0);

    /* Cleanup upon failure */
    if(-1 == status) {
        free(retry_obj);
    }
    return status;
}

int map_update_retry_handler(uint16_t mid, void *compl_user_data)
{
    map_retry_handler_t *retry_obj = find_remove_object(retry_list, &mid, compare_mid);

    /* We are not interested in this CMDU. Nothing to do. */
    if (retry_obj == NULL) {
        return 0;
    }

    int8_t ret = map_timer_unregister_callback(retry_obj->timer_id);
    if (ret == -1) {
        log_lib_e("retry handler cleanup failed for retry_id[%s]", retry_obj->timer_id);
    }

    log_lib_d("retry timer completed for retry_id[%s]", retry_obj->timer_id);

    cleanup_retry_obj(retry_obj, MAP_RETRY_STATUS_SUCCESS, compl_user_data);

    return 0;
}

int map_restart_retry_timer(const char* retry_id)
{
    int8_t status = -1;
    if (retry_id && (MAX_TIMER_ID_STRING_LENGTH > strlen(retry_id))) {
        map_retry_handler_t *retry_obj = find_object(retry_list, (void *)retry_id, compare_retry_id);
        if (retry_obj) {
            retry_obj->retry_count = 0;
            return 0;
        }
    }
    return status;
}

int map_cleanup_retry_args(UNUSED int status, void *args, UNUSED void *compl_user_data)
{
    free(args);
    return 0;
}

int map_unregister_retry(const char* retry_id)
{
    int8_t status = 0;
    do {
        map_retry_handler_t *retry_obj = find_remove_object(retry_list, (void *)retry_id, compare_retry_id);

        if (retry_obj == NULL) {
            ERROR_EXIT(status)
        }

        int8_t ret = map_timer_unregister_callback(retry_id);
        if (ret == -1) {
            log_lib_e("retry_id[%s] cleanup failed", retry_obj->timer_id);
            ERROR_EXIT(status)
        }

        log_lib_d("retry_id[%s] removed\n", retry_obj->timer_id);
        cleanup_retry_obj(retry_obj, MAP_RETRY_STATUS_CANCELLED, NULL);
    } while(0);
    return status;
}

int map_unregister_retry_prefix(const char* retry_id_prefix)
{
    do {
        map_retry_handler_t *retry_obj = find_object(retry_list, (void*)retry_id_prefix, compare_retry_id_prefix);
        if (!retry_obj) {
            break;
        }

        map_unregister_retry(retry_obj->timer_id);
    } while (true);

    return 0;
}
