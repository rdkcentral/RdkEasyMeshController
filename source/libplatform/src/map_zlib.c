/*
 * Copyright (c) 2021-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zlib.h>

#include "map_utils.h"
#include "map_compress.h"

static void zlib_exit(struct map_compression_ctx *ctx)
{
	free(ctx->stream);
	free(ctx);
}

static int zlib_init(struct map_compression_ctx **ctx_ptr)
{
	struct map_compression_ctx *ctx;
	z_stream *stream;

	ctx = calloc(1, sizeof(struct map_compression_ctx));
	if (!ctx) {
		return -ERR_COMP_NOMEM;
	}
	stream = calloc(1, sizeof(z_stream));
	if (!stream) {
		free(ctx);
		return -ERR_COMP_NOMEM;
	}
	stream->zalloc = Z_NULL;
	stream->zfree = Z_NULL;
	stream->opaque = Z_NULL;
	ctx->stream = stream;
	*ctx_ptr = ctx;

	return 0;
}

static int zlib_decompress(struct map_compression_ctx *ctx)
{
	z_stream *stream = ctx->stream;
	int ret;

	/* Allocate inflate state. */
	ret = inflateInit(stream);
	if (ret != Z_OK) {
		log_lib_e("Failed to initialize decompression module.");
		return (ret == Z_MEM_ERROR) ? -ERR_COMP_NOMEM : -ERR_COMP_INVAL;
	}
	stream->avail_in = ctx->in_size;
	stream->next_in = ctx->inp;
	stream->avail_out = ctx->out_size;
	stream->next_out = ctx->outp;;
	log_lib_d("Compressed stream: avail_in %u, total_in %lu, "
			"avail_out %u, total_out %lu.",
			stream->avail_in, stream->total_in,
			stream->avail_out, stream->total_out);
	do { /* Decompression of the block. */
		ret = inflate(stream, Z_FINISH);
		if (ret == Z_NEED_DICT || ret < 0) {
			log_lib_e("Decompression failed (zlib err %d).", ret);
			ret = (ret == Z_BUF_ERROR) ?
					-ERR_COMP_NOSPC : -ERR_COMP_IO;
			goto fail;
		} else if (ret == Z_OK && stream->avail_out == 0) {
			ret = -ERR_COMP_NOSPC;
			goto fail;
		}
	} while (ret != Z_STREAM_END);
	/* Ensure that all the input is consumed. */
	/* assert(!stream->avail_in); */
	log_lib_d("Decompressed stream: avail_in %u, total_in %lu, "
			"avail_out %u, total_out %lu.",
			stream->avail_in, stream->total_in,
			stream->avail_out, stream->total_out);
	ctx->in_size = stream->total_in;
	ctx->out_size = stream->total_out;
	ret = 0;

fail:
	if (ret == -ERR_COMP_NOSPC) {
		log_lib_e("May no space left in the output buffer?");
	}
	/* Deallocate inflate state. */
	(void)inflateEnd(stream);

	return ret;
}

static int zlib_compress(struct map_compression_ctx *ctx)
{
	z_stream *stream = ctx->stream;
	int ret;

	/* Allocate deflate state. */
	ret = deflateInit(stream, ctx->level);
	if (ret != Z_OK) {
		log_lib_e("Failed to initialize compression module.");
		return (ret == Z_MEM_ERROR) ? -ERR_COMP_NOMEM : -ERR_COMP_INVAL;
	}
	stream->avail_in = ctx->in_size;
	stream->next_in = ctx->inp;
	stream->avail_out = ctx->out_size;
	stream->next_out = ctx->outp;;
	log_lib_d("Uncompressed stream: avail_in %u, total_in %lu, "
			"avail_out %u, total_out %lu.",
			stream->avail_in, stream->total_in,
			stream->avail_out, stream->total_out);
	do { /* Compression of the block. */
		ret = deflate(stream, Z_FINISH);
		if (ret < 0) {
			log_lib_e("Compression failed (zlib err %d).", ret);
			ret = (ret == Z_BUF_ERROR) ?
					-ERR_COMP_NOSPC : -ERR_COMP_IO;
			goto fail;
		} else if (ret == Z_OK && stream->avail_out == 0) {
			ret = -ERR_COMP_NOSPC;
			goto fail;
		}
	} while (ret == Z_OK &&
			stream->avail_in != 0 && stream->avail_out != 0);
	/* Ensure that all the input is consumed. */
	/* assert(!stream->avail_in); */
	log_lib_d("Compressed stream: avail_in %u, total_in %lu, "
			"avail_out %u, total_out %lu.",
			stream->avail_in, stream->total_in,
			stream->avail_out, stream->total_out);
	ctx->in_size = stream->total_in;
	ctx->out_size = stream->total_out;
	ret = 0;

fail:
	if (ret == -ERR_COMP_NOSPC) {
		log_lib_e("May no space left in the output buffer?");
	}
	/* Deallocate deflate state. */
	(void)deflateEnd(stream);

	return ret;
}

const struct map_compression_ops g_map_zlib_ops = {
	.name		= "zlib:deflate",
	.init		= zlib_init,
	.exit		= zlib_exit,
	.compress	= zlib_compress,
	.decompress	= zlib_decompress,
};
