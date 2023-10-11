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
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "timer"

#include "map_timer_handler.h"
#include "map_utils.h"
#include "arraylist.h"

/*#######################################################################
#                       TYPEDEF                                         #
########################################################################*/
typedef struct timer_cb_data_s {
    timer_id_t           timer_id;
    acu_evloop_timer_t  *evloop_timer;
    timer_cb_t           cb;
    void                *args;
} timer_cb_data_t;

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static array_list_t *g_registered_callbacks;

/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
static void free_timer_data(timer_cb_data_t *timer_data)
{
    if (timer_data->evloop_timer) {
        acu_evloop_timer_delete(timer_data->evloop_timer);
    }
    free(timer_data);
}

static void timer_callback(void *userdata)
{
    timer_cb_data_t *timer_data = userdata;

    if (timer_data->cb(timer_data->timer_id, timer_data->args)) {
        /* Timer might have removed itself from callback */
        if (remove_object(g_registered_callbacks, timer_data)) {
            log_lib_d("removed unregistered timer [%s] from list", timer_data->timer_id);
            free_timer_data(timer_data);
        }
    }
}

static int compare_timer_node(void* timer_data, void* timer_id)
{
    if (timer_data && timer_id) {
        if (strcmp(((timer_cb_data_t*)timer_data)->timer_id, (char*)timer_id) == 0) {
            return 1;
        }
    }
    return 0;
}

static int compare_timer_node_prefix(void* timer_data, void* timer_id)
{
    if (timer_data && timer_id) {
        if (strncmp(((timer_cb_data_t*)timer_data)->timer_id, timer_id, strlen(timer_id)) == 0) {
            return 1;
        }
    }
    return 0;
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
int map_timer_handler_init(void)
{
    if (!(g_registered_callbacks = new_array_list())) {
        log_lib_e("failed to create new array list for timer callback.\n");
        return -1;
    }

    return 0;
}

int map_timer_register_callback(uint32_t    frequency_sec,
                                const char *timer_id,
                                void       *args,
                                timer_cb_t  cb)
{
    int status = 0;
    timer_cb_data_t *timer_data = NULL;

    do {
        if (cb == NULL || timer_id == NULL) {
            ERROR_EXIT(status)
        }

        size_t str_len = strlen(timer_id);
        if (str_len >= MAX_TIMER_ID_STRING_LENGTH) {
            ERROR_EXIT(status)
        }

        /* If there is already a timer registered with the same ID return error */
        if (map_is_timer_registered(timer_id)) {
            ERROR_EXIT(status)
        }

        timer_data = calloc(1,sizeof(timer_cb_data_t));
        if (timer_data == NULL) {
            ERROR_EXIT(status)
        }

        map_strlcpy(timer_data->timer_id, timer_id, sizeof(timer_data->timer_id));
        timer_data->cb   = cb;
        timer_data->args = args;

        timer_data->evloop_timer = acu_evloop_timer_add(SEC_TO_MSEC(frequency_sec), SEC_TO_MSEC(frequency_sec), timer_callback, timer_data);
        if (timer_data->evloop_timer == NULL) {
            log_lib_e("failed to add timer");
            free_timer_data(timer_data);
            ERROR_EXIT(status)
        }

        if (push_object(g_registered_callbacks, (void*)timer_data) == -1) {
            log_lib_e("failed to register timer callback");
            free_timer_data(timer_data);
            ERROR_EXIT(status)
        }

    } while (0);

    return status;
}

bool map_is_timer_registered(const char *timer_id)
{
    return find_object(g_registered_callbacks, (void*)timer_id, compare_timer_node) != NULL;
}

int map_timer_unregister_callback(const char* timer_id)
{
    int status = 0;
    timer_cb_data_t *timer_data = NULL;

    do {
        if (timer_id == NULL) {
            ERROR_EXIT(status)
        }

        size_t str_len = strlen(timer_id);
        if (str_len >= MAX_TIMER_ID_STRING_LENGTH) {
            ERROR_EXIT(status)
        }

        if (!(timer_data = find_object(g_registered_callbacks, (void*)timer_id, compare_timer_node))) {
            log_lib_e("timer [%s] isn't registered yet", timer_id);
            ERROR_EXIT(status);
        }

        remove_object(g_registered_callbacks, timer_data);
        free_timer_data(timer_data);
    } while (0);

    return status;
}

int map_timer_unregister_callback_prefix(const char *timer_id_prefix)
{
    do {
        timer_cb_data_t *timer_data = find_object(g_registered_callbacks, (void*)timer_id_prefix, compare_timer_node_prefix);
        if (!timer_data) {
            break;
        }

        map_timer_unregister_callback(timer_data->timer_id);
    } while (true);

    return 0;
}

int map_timer_restart_callback(const char* timer_id)
{
    int status = 0;
    timer_cb_data_t *timer_data;

    do {
        if (timer_id == NULL) {
            ERROR_EXIT(status)
        }

        if (!(timer_data = find_object(g_registered_callbacks, (void*)timer_id, compare_timer_node))) {
            log_lib_e("timer [%s] isn't registered yet", timer_id);
            ERROR_EXIT(status)
        } else {
            acu_evloop_timer_restart(timer_data->evloop_timer);
        }
    } while (0);

    return status;
}

int map_timer_change_callback(const char *timer_id, uint32_t frequency_sec, void *args)
{
    int status = 0;
    timer_cb_data_t *timer_data;

    do {
        if (timer_id == NULL) {
            ERROR_EXIT(status)
        }

        if (!(timer_data = find_object(g_registered_callbacks, (void*)timer_id, compare_timer_node))) {
            log_lib_e("timer [%s] isn't registered yet", timer_id);
            ERROR_EXIT(status)
        } else {
            acu_evloop_timer_change_period(timer_data->evloop_timer, SEC_TO_MSEC(frequency_sec));
            timer_data->args = args;
        }
    } while (0);

    return status;
}

int map_timer_remaining(const char *timer_id, uint32_t *remaining_sec)
{
    int status = 0;
    timer_cb_data_t *timer_data;
    uint32_t remaining_msec;

    do {
        if (timer_id == NULL || remaining_sec == NULL) {
            ERROR_EXIT(status)
        }

        *remaining_sec = 0;

        if (!(timer_data = find_object(g_registered_callbacks, (void*)timer_id, compare_timer_node))) {
            log_lib_e("timer [%s] isn't registered yet", timer_id);
            ERROR_EXIT(status)
        } else if (acu_evloop_timer_remaining(timer_data->evloop_timer, &remaining_msec)) {
            log_lib_e("failed to get timer remaining");
            ERROR_EXIT(status)
        } else {
            *remaining_sec = MSEC_TO_SEC(remaining_msec);
        }
    } while (0);

    return status;
}

void map_timer_handler_fini()
{
    timer_cb_data_t *timer_data;

    while ((timer_data = pop_object(g_registered_callbacks))) {
        free_timer_data(timer_data);
    }

    delete_array_list(g_registered_callbacks);
}
