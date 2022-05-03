/*
 * Copyright (c) 2020-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef MAP_CTRL_COMPRESS_H
#define MAP_CTRL_COMPRESS_H

#include <stdint.h>

struct compress_params {
    uint8_t *data_in;
    size_t data_in_len;
    uint8_t *data_out;
    size_t data_out_len;
};

int map_ctrl_compress(struct compress_params *params);
int map_ctrl_decompress(struct compress_params *params);

#endif /* MAP_CTRL_COMPRESS_H */
