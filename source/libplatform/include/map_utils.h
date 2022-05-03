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

#include "map_common_defines.h"

#include "ssp_global.h"

#ifndef UNUSED
#define UNUSED __attribute__((__unused__))
#endif

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

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define STRUCT_PACKED __attribute__ ((packed))

#define SFREE(_ptr)         \
    do {                    \
        if (_ptr != NULL) { \
            free(_ptr);     \
            _ptr = NULL;    \
        }                   \
    } while (0)


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

#define BRED    "\033[1;31m"
#define BGREEN  "\033[1;32m"
#define BYELLOW "\033[1;33m"
#define BBLUE   "\033[1;34m"
#define NORM    "\033[0m"

#ifdef FALSE
#undef FALSE
#endif
#ifdef TRUE
#undef TRUE
#endif
#define FALSE 0
#define TRUE 1

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


#define HAVE_MAC_ADDR
/* Structure representing a MAC address */
typedef unsigned char mac_addr[6];
/* Structure representing an OUI */
typedef uint8_t mac_addr_oui[3];

#define HAVE_MAC_ADDR_STR
/* representation of a MAC address as a string */
typedef char mac_addr_str[18];
/* representation of a MAC address OUI as a string */
typedef char mac_addr_oui_str[9];

/* Zero and wildcard mac address */
extern mac_addr g_zero_mac;
extern mac_addr g_wildcard_mac;

int acu_mac_from_string(const char *macstr, mac_addr mac);
int acu_mac_to_string(const mac_addr mac, mac_addr_str macstr);
char *acu_mac_string(const mac_addr mac);
int acu_mac_hash(const mac_addr mac, int buckets);


/* FD and timers */
typedef struct map_fd_s map_fd_t;
typedef struct map_timer_s map_timer_t;

typedef void (*map_fd_cb_t)(int fd, void *userdata);
typedef void (*map_timer_cb_t)(void *userdata);

map_fd_t *map_fd_add(int fd, map_fd_cb_t cb, void *userdata);
void      map_fd_delete(map_fd_t *map_fd);

map_timer_t *map_timer_add(uint32_t expire_ms, uint32_t period_ms, map_timer_cb_t cb, void *userdata);
void         map_timer_delete(map_timer_t *map_timer);
int          map_timer_restart(map_timer_t *map_timer);
int          map_timer_change_period(map_timer_t *map_timer, uint32_t period_ms);


/* Mac addresses */
#define maccpy(d, s) memcpy(d, s, sizeof(mac_addr))
#define maccmp(a, b) memcmp(a, b, sizeof(mac_addr))

#define ouicpy(d, s) memcpy(d, s, sizeof(mac_addr_oui))
#define ouicmp(a, b) memcmp(a, b, sizeof(mac_addr_oui))

static inline int mac_from_string(const char *mac_str, mac_addr mac)
{
    return acu_mac_from_string(mac_str, mac);
}

#define mac_string(mac) acu_mac_string(mac)

static inline const char* mac_to_string(mac_addr mac, char *mac_str)
{
    acu_mac_to_string(mac, mac_str);
    return mac_str;
}

/* Obsolete */
static inline void get_mac_as_str(uint8_t* mac, char* mac_str, UNUSED int length)
{
    acu_mac_to_string(mac, mac_str);
}


/* Time */
#ifdef CLOCK_BOOTTIME
#define TIMESTAMP_CLOCK_TYPE CLOCK_BOOTTIME
#else
#define TIMESTAMP_CLOCK_TYPE CLOCK_MONOTONIC
#endif

#define SEC_TO_MSEC(x)		((x) * (1000))
#define SEC_TO_USEC(x)		((SEC_TO_MSEC(x)) * (1000))
#define SEC_TO_NSEC(x)		((SEC_TO_USEC(x)) * (1000))
#define MSEC_TO_USEC(x)		((x) * (1000))
#define MSEC_TO_NSEC(x)		((MSEC_TO_USEC(x)) * (1000))
#define MSEC_TO_SEC(x) 		((x) / (1000))
#define USEC_TO_NSEC(x)		((x) * (1000))
#define USEC_TO_MSEC(x)		((x) / (1000))
#define USEC_TO_SEC(x)		((USEC_TO_MSEC(x)) / (1000))
#define NSEC_TO_USEC(x)		((x) / (1000))
#define NSEC_TO_MSEC(x)		((NSEC_TO_USEC(x)) / (1000))
#define NSEC_TO_SEC(x)		((NSEC_TO_MSEC(x)) / (1000))

struct timespec get_current_time();

uint64_t get_clock_diff_secs(struct timespec new_time, struct timespec old_time);
uint64_t acu_get_timestamp_sec(void);
uint64_t acu_get_timestamp_msec(void);


/* Logging */
#ifdef LOG_TAG
  #define _LOG_TAG "[" LOG_TAG "]"
#else
  #define _LOG_TAG ""
#endif

typedef enum {
    MAP_LIBRARY,
    MAP_IEEE1905,
    MAP_AGENT,
    MAP_CONTROLLER,
    MAP_VENDOR_IPC,
    MAP_CONTROLLER_BHS,
    MAP_TEST
} map_log_source_t;

typedef void (*map_printf_cb_t)(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

void map_log(int module, int level, const char *format, ...) __attribute__((format(printf, 3, 4)));

void map_vlog(int module, int level, const char *format, va_list args);

void map_vlog_ext(int module, int level, bool check_level, const char *format, va_list args);

#define log_i1905_e(...) map_log(MAP_IEEE1905,   LOG_ERR,     "[i1905]" _LOG_TAG " " __VA_ARGS__);
#define log_i1905_w(...) map_log(MAP_IEEE1905,   LOG_WARNING, "[i1905]" _LOG_TAG " " __VA_ARGS__);
#define log_i1905_i(...) map_log(MAP_IEEE1905,   LOG_INFO,    "[i1905]" _LOG_TAG " " __VA_ARGS__);
#define log_i1905_d(...) map_log(MAP_IEEE1905,   LOG_DEBUG,   "[i1905]" _LOG_TAG " " __VA_ARGS__);
#define log_lib_e(...)   map_log(MAP_LIBRARY,    LOG_ERR,     "[lib]"   _LOG_TAG " " __VA_ARGS__);
#define log_lib_w(...)   map_log(MAP_LIBRARY,    LOG_WARNING, "[lib]"   _LOG_TAG " " __VA_ARGS__);
#define log_lib_i(...)   map_log(MAP_LIBRARY,    LOG_INFO,    "[lib]"   _LOG_TAG " " __VA_ARGS__);
#define log_lib_d(...)   map_log(MAP_LIBRARY,    LOG_DEBUG,   "[lib]"   _LOG_TAG " " __VA_ARGS__);
#define log_ctrl_e(...)  map_log(MAP_CONTROLLER, LOG_ERR,     "[ctrl]"  _LOG_TAG " " __VA_ARGS__);
#define log_ctrl_w(...)  map_log(MAP_CONTROLLER, LOG_WARNING, "[ctrl]"  _LOG_TAG " " __VA_ARGS__);
#define log_ctrl_i(...)  map_log(MAP_CONTROLLER, LOG_INFO,    "[ctrl]"  _LOG_TAG " " __VA_ARGS__);
#define log_ctrl_d(...)  map_log(MAP_CONTROLLER, LOG_DEBUG,   "[ctrl]"  _LOG_TAG " " __VA_ARGS__);
#define log_test_e(...)  map_log(MAP_TEST,       LOG_ERR,     "[test]"  _LOG_TAG " " __VA_ARGS__);
#define log_test_w(...)  map_log(MAP_TEST,       LOG_WARNING, "[test]"  _LOG_TAG " " __VA_ARGS__);
#define log_test_i(...)  map_log(MAP_TEST,       LOG_INFO,    "[test]"  _LOG_TAG " " __VA_ARGS__);
#define log_test_d(...)  map_log(MAP_TEST,       LOG_DEBUG,   "[test]"  _LOG_TAG " " __VA_ARGS__);


/* for compat - to be removed */
#define platform_log(module, level, ...) map_log(module, level, __VA_ARGS__);

/* Ebtables */
int map_set_ebtables_rules(mac_addr al_mac);


/* Various */
bool map_is_loopback_iface(const char *ifname);

size_t map_strlcpy(char *dst, const char *src, size_t max_len);

int acu_hex_string_to_buf(const char *const hex, uint8_t *const buf, size_t length);

#endif /* MAP_UTILS_H_ */
