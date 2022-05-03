/*
 * Copyright (c) 2020-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "compress"

#include "map_ctrl_compress.h"
#include "map_compress.h"
#include "map_utils.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
static const struct map_compression_ops *const g_compression_ops[] = {
        &g_map_zlib_ops,
};

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/

/*#######################################################################
#                       PROTOTYPES                                      #
########################################################################*/

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/

/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
static inline int _compress_init(struct map_compression_ctx **ctx, const int type)
{
    return g_compression_ops[type]->init(ctx);
}

static inline int _compress(struct map_compression_ctx *ctx, const int type)
{
    return g_compression_ops[type]->compress(ctx);
}

static inline void _compress_exit(struct map_compression_ctx *ctx, const int type)
{
    g_compression_ops[type]->exit(ctx);
}

static inline int _decompress_init(struct map_compression_ctx **ctx, const int type)
{
    return g_compression_ops[type]->init(ctx);
}

static inline int _decompress(struct map_compression_ctx *ctx, const int type)
{
    return g_compression_ops[type]->decompress(ctx);
}

static inline void _decompress_exit(struct map_compression_ctx *ctx, const int type)
{
    g_compression_ops[type]->exit(ctx);
}

int map_ctrl_decompress(struct compress_params *params)
{
    struct map_compression_ctx *ctx = NULL;
    const unsigned compress_type = COMPRESSION_TYPE;
    int rc;

    rc = _decompress_init(&ctx, compress_type);
    if (rc != 0) {
        log_ctrl_e("Failed to initialize decompression context (err %d)", -rc);
        return rc;
    }
    ctx->in_size = params->data_in_len;
    ctx->inp = (void *)params->data_in;
    ctx->out_size = params->data_out_len;
    ctx->outp = (void *)params->data_out;
    rc = _decompress(ctx, compress_type);
    if (rc == -ERR_COMP_NOSPC) {
        log_ctrl_e("Avail space (%d bytes) is not enough", (int)params->data_out_len);
        goto fail;
    } else if (rc != 0) {
        log_ctrl_e("Failed to decompress data (err %d)", -rc);
        goto fail;
    }
    log_ctrl_d("compressed to decompressed: (%u bytes) -> (%u bytes)",
            ctx->in_size, ctx->out_size);
    params->data_out_len = ctx->out_size;
fail:
    _decompress_exit(ctx, compress_type);
    return rc;
}

int map_ctrl_compress(struct compress_params *params)
{
    struct map_compression_ctx *ctx = NULL;
    const unsigned compress_type = COMPRESSION_TYPE;
    int rc;

    rc = _compress_init(&ctx, compress_type);
    if (rc != 0) {
        log_ctrl_e("Failed to initialize compression context (err %d)", -rc);
        return rc;
    }
    ctx->level = COMPRESSION_LEVEL;
    ctx->in_size = params->data_in_len;
    ctx->inp = (void *)params->data_in;
    ctx->out_size = params->data_out_len;
    ctx->outp = (void *)params->data_out;
    rc = _compress(ctx, compress_type);
    if (rc == -ERR_COMP_NOSPC) {
        log_ctrl_e("Avail space (%d bytes) is not enough", (int)params->data_out_len);
        goto fail;
    } else if (rc != 0) {
        log_ctrl_e("Failed to compress data (err %d)", -rc);
        goto fail;
    }
    log_ctrl_d("uncompressed to compressed: (%u bytes) -> (%u bytes)",
            ctx->in_size, ctx->out_size);
    params->data_out_len = ctx->out_size;
fail:
    _compress_exit(ctx, compress_type);
    return rc;
}
