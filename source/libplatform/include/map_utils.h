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

#ifndef MAP_UTILS_H_
#define MAP_UTILS_H_

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <time.h>

#include <libubox/list.h>

#include "acu_utils.h"

#include "map_common_defines.h"


/* Useful defines and typedefs */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define host_to_le16(n) ((uint16_t) (n))
#define htonll(n) ((((uint64_t)htonl(n)) << 32) + htonl((n) >> 32))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define host_to_le16(n) (bswap_16(n))
#define htonll(n) ((uint64_t) (n))
#else
#error Neither little nor big endian
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#endif

#define STRUCT_PACKED __attribute__ ((packed))


/* BIT MASKs */
#define BIT_MASK_7 0x80
#define BIT_MASK_6 0x40
#define BIT_MASK_5 0x20
#define BIT_MASK_4 0x10
#define BIT_MASK_3 0x08
#define BIT_MASK_2 0x04
#define BIT_MASK_1 0x02
#define BIT_MASK_0 0x01

/* BIT SHIFTs */
#define BIT_SHIFT_7   7
#define BIT_SHIFT_6   6
#define BIT_SHIFT_5   5
#define BIT_SHIFT_4   4
#define BIT_SHIFT_3   3
#define BIT_SHIFT_2   2
#define BIT_SHIFT_1   1

/* SET/RESET a bit */
#define RESET_BIT 0x00
#define SET_BIT   0x01

/* Value conversion */
#define BYTE_TO_PERCENTAGE(x)         ((((int)x) * 100) >> 8)
#define UINT8_2S_COMPLEMENT_TO_INT(x) ((x) <= 127 ? ((int)x) : ((int)x - 256))

static inline int RCPI_TO_RSSI(uint8_t x)
{
    /* [0 : 220] => [-110 : 0] */
    return x > 220 ? 0 : ((x >> 1) - 110);
}

static inline uint8_t RSSI_TO_RCPI(int x)
{
    /* [-110 : 0] => [0 : 220] */
    return x < -110 ? 0 : x > 0 ? 220 : ((x + 110) << 1);
}

/* Use it only in do while loop */
#define ERROR_EXIT(status) {status = -1; break;}

typedef struct list_head list_head_t;


/* Zero and wildcard mac address */
extern mac_addr g_zero_mac;
extern mac_addr g_wildcard_mac;


/* Mac addresses */
#define maccpy(d, s) memcpy(d, s, sizeof(mac_addr))
#define maccmp(a, b) memcmp(a, b, sizeof(mac_addr))

#define ouicpy(d, s) memcpy(d, s, sizeof(mac_addr_oui))
#define ouicmp(a, b) memcmp(a, b, sizeof(mac_addr_oui))

static inline int mac_from_string(const char *mac_str, mac_addr mac)
{
    return ACU_OK == acu_mac_from_string(mac_str, mac) ? 0 : -1;
}

#define mac_string(mac) acu_mac_string(mac)

static inline const char* mac_to_string(mac_addr mac, char *mac_str)
{
    acu_mac_to_string(mac, mac_str);
    return mac_str;
}

/* Obsolete */
#define MAC_AS_STR(mac, mac_str) mac_to_string(mac, mac_str)

/* Obsolete */
static inline void get_mac_as_str(uint8_t* mac, char* mac_str, UNUSED int length)
{
    acu_mac_to_string(mac, mac_str);
}


/* Logging */
#ifdef LOG_TAG
  #define _LOG_TAG "[" LOG_TAG "]"
#else
  #define _LOG_TAG ""
#endif

#ifndef LOG_TRACE
#define LOG_TRACE LOG_DEBUG + 1
#endif

typedef enum {
    MAP_LIBRARY,
    MAP_IEEE1905,
    MAP_CONTROLLER,
    MAP_SSP,
    MAP_TEST
} map_log_source_t;

typedef void (*map_printf_cb_t)(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

void map_log(int module, int level, const char *format, ...) __attribute__((format(printf, 3, 4)));

void map_vlog(int module, int level, const char *format, va_list args);

void map_vlog_ext(int module, int level, bool check_level, const char *format, va_list args);

#define log_i1905_e(...) map_log(MAP_IEEE1905,   LOG_ERR,     "[i1905]" _LOG_TAG " " __VA_ARGS__);
#define log_i1905_w(...) map_log(MAP_IEEE1905,   LOG_WARNING, "[i1905]" _LOG_TAG " " __VA_ARGS__);
#define log_i1905_n(...) map_log(MAP_IEEE1905,   LOG_NOTICE,  "[i1905]" _LOG_TAG " " __VA_ARGS__);
#define log_i1905_i(...) map_log(MAP_IEEE1905,   LOG_INFO,    "[i1905]" _LOG_TAG " " __VA_ARGS__);
#define log_i1905_d(...) map_log(MAP_IEEE1905,   LOG_DEBUG,   "[i1905]" _LOG_TAG " " __VA_ARGS__);
#define log_i1905_t(...) map_log(MAP_IEEE1905,   LOG_TRACE,   "[i1905]" _LOG_TAG " " __VA_ARGS__);
#define log_lib_e(...)   map_log(MAP_LIBRARY,    LOG_ERR,     "[lib]"   _LOG_TAG " " __VA_ARGS__);
#define log_lib_w(...)   map_log(MAP_LIBRARY,    LOG_WARNING, "[lib]"   _LOG_TAG " " __VA_ARGS__);
#define log_lib_n(...)   map_log(MAP_LIBRARY,    LOG_NOTICE,  "[lib]"   _LOG_TAG " " __VA_ARGS__);
#define log_lib_i(...)   map_log(MAP_LIBRARY,    LOG_INFO,    "[lib]"   _LOG_TAG " " __VA_ARGS__);
#define log_lib_d(...)   map_log(MAP_LIBRARY,    LOG_DEBUG,   "[lib]"   _LOG_TAG " " __VA_ARGS__);
#define log_lib_t(...)   map_log(MAP_LIBRARY,    LOG_TRACE,   "[lib]"   _LOG_TAG " " __VA_ARGS__);
#define log_ctrl_e(...)  map_log(MAP_CONTROLLER, LOG_ERR,     "[ctrl]"  _LOG_TAG " " __VA_ARGS__);
#define log_ctrl_w(...)  map_log(MAP_CONTROLLER, LOG_WARNING, "[ctrl]"  _LOG_TAG " " __VA_ARGS__);
#define log_ctrl_n(...)  map_log(MAP_CONTROLLER, LOG_NOTICE,  "[ctrl]"  _LOG_TAG " " __VA_ARGS__);
#define log_ctrl_i(...)  map_log(MAP_CONTROLLER, LOG_INFO,    "[ctrl]"  _LOG_TAG " " __VA_ARGS__);
#define log_ctrl_d(...)  map_log(MAP_CONTROLLER, LOG_DEBUG,   "[ctrl]"  _LOG_TAG " " __VA_ARGS__);
#define log_ctrl_t(...)  map_log(MAP_CONTROLLER, LOG_TRACE,   "[ctrl]"  _LOG_TAG " " __VA_ARGS__);
#define log_ssp_e(...)   map_log(MAP_SSP,        LOG_ERR,     "[ssp]"   _LOG_TAG " " __VA_ARGS__);
#define log_ssp_w(...)   map_log(MAP_SSP,        LOG_WARNING, "[ssp]"   _LOG_TAG " " __VA_ARGS__);
#define log_ssp_n(...)   map_log(MAP_SSP,        LOG_NOTICE,  "[ssp]"   _LOG_TAG " " __VA_ARGS__);
#define log_ssp_i(...)   map_log(MAP_SSP,        LOG_INFO,    "[ssp]"   _LOG_TAG " " __VA_ARGS__);
#define log_ssp_d(...)   map_log(MAP_SSP,        LOG_DEBUG,   "[ssp]"   _LOG_TAG " " __VA_ARGS__);
#define log_ssp_t(...)   map_log(MAP_SSP,        LOG_TRACE,   "[ssp]"   _LOG_TAG " " __VA_ARGS__);
#define log_test_e(...)  map_log(MAP_TEST,       LOG_ERR,     "[test]"  _LOG_TAG " " __VA_ARGS__);
#define log_test_w(...)  map_log(MAP_TEST,       LOG_WARNING, "[test]"  _LOG_TAG " " __VA_ARGS__);
#define log_test_n(...)  map_log(MAP_TEST,       LOG_NOTICE,  "[test]"  _LOG_TAG " " __VA_ARGS__);
#define log_test_i(...)  map_log(MAP_TEST,       LOG_INFO,    "[test]"  _LOG_TAG " " __VA_ARGS__);
#define log_test_d(...)  map_log(MAP_TEST,       LOG_DEBUG,   "[test]"  _LOG_TAG " " __VA_ARGS__);
#define log_test_t(...)  map_log(MAP_TEST,       LOG_TRACE,   "[test]"  _LOG_TAG " " __VA_ARGS__);


/* Ebtables */
int map_set_ebtables_rules(mac_addr al_mac);


/* Various */
bool map_is_loopback_iface(const char *ifname);

bool map_is_ethernet_iface(const char *ifname);

#define map_strlcpy(dst, src, max_len) acu_strlcpy(dst, src, max_len)

uint8_t map_count_bits_16(uint16_t n);

#endif /* MAP_UTILS_H_ */
