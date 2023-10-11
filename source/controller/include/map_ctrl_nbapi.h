/*
 * Copyright (c) 2023 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef MAP_CTRL_NBAPI_H_
#define MAP_CTRL_NBAPI_H_

#include "map_data_model.h"

typedef enum {
    NB_OK = 0,    /**< success */
    NB_EFAIL,     /**< failure */
    NB_ENOMEM,    /**< out of memory */
    NB_EINVAL,    /**< invalid arguments */
    NB_ENOENT,    /**< does not exist */
} nb_retcode_t;

int map_ctrl_nbapi_init(void);

void map_ctrl_nbapi_fini(void);

#endif /* MAP_CTRL_NBAPI_H_ */
