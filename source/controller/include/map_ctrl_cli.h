/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef MAP_CTRL_CLI_H_
#define MAP_CTRL_CLI_H_

#include <stdarg.h>

int map_cli_init(void);

void map_cli_fini(void);

void map_cli_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

void map_cli_vprintf(const char *fmt, va_list args);

#endif /* MAP_CTRL_CLI_H_ */
