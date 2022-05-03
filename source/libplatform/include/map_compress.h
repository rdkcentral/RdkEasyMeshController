/*
 * Copyright (c) 2021-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef __MAP_COMPRESS_H__
#define __MAP_COMPRESS_H__

#define COMPRESSION_TYPE_ZLIB   0
#define COMPRESSION_TYPE        COMPRESSION_TYPE_ZLIB

#define ERR_COMP_INVAL  1
#define ERR_COMP_NOMEM  2
#define ERR_COMP_NOSPC  3
#define ERR_COMP_IO     4

/*
 * Compression level:
 *	0 -> no compression
 *	1 -> best speed
 *	2 ... 8
 *	9 -> best compression
 */
#define COMPRESSION_LEVEL    9

struct map_compression_ctx {
	void *stream;
	unsigned level;
	void *inp;	/* Input data to (de)compression operation. */
	void *outp;	/* Destination buffer for (de)compression operation. */
	uint32_t in_size;	/* IN: Size of the input buffer @inp.
			 * OUT: How many bytes of the original @in_size have
			 * been processed. */
	uint32_t out_size;	/* IN: Size of the output buffer @outp.
			 * OUT: How many bytes are returned in the output
			 * buffer @outp. */
};

struct map_compression_ops {
	char *name;
	int (*init)(struct map_compression_ctx **ctx);
	void (*exit)(struct map_compression_ctx *ctx);
	int (*compress)(struct map_compression_ctx *ctx);
	int (*decompress)(struct map_compression_ctx *ctx);
};

extern const struct map_compression_ops g_map_zlib_ops;

#endif /* __MAP_COMPRESS_H__ */
