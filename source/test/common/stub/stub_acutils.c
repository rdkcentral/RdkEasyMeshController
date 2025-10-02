/*
 * Copyright (c) 2021-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#include "acu_utils.h"

/* Overrule some functions of libacutils.so */
acu_evloop_fd_t *acu_evloop_fd_add(int fd, acu_evloop_fd_cb_t cb, void *userdata)
{
    return (acu_evloop_fd_t *)0xdeadbeef;
}

void acu_evloop_fd_delete(acu_evloop_fd_t *evloop_fd)
{
}
