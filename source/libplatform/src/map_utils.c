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
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>

#include <libubox/uloop.h>

#include "map_utils.h"
#include "map_config.h"

#include "ssp_global.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define PRINT_BUF_SIZE 1024

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
struct map_fd_s {
    struct uloop_fd  u_fd;
    map_fd_cb_t      cb;
    void            *userdata;
};

struct map_timer_s {
    struct uloop_timeout  u_timeout;
    uint32_t              period_ms;
    map_timer_cb_t        cb;
    void                 *userdata;
    bool                  in_cb;
    bool                  deleted;
};

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
mac_addr g_zero_mac     = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
mac_addr g_wildcard_mac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/*#######################################################################
#                       FD AND TIMERS                                   #
########################################################################*/
static void map_uloop_fd_handler(struct uloop_fd *u_fd, UNUSED unsigned int events)
{
    map_fd_t *map_fd = (map_fd_t *) u_fd;

    map_fd->cb(map_fd->u_fd.fd, map_fd->userdata);
}

static void map_uloop_timeout_handler(struct uloop_timeout *u_timeout)
{
    map_timer_t *map_timer = (map_timer_t*) u_timeout;

    map_timer->in_cb = true;
    map_timer->cb(map_timer->userdata);
    map_timer->in_cb = false;

    if (map_timer->deleted || 0 == map_timer->period_ms) {
        free(map_timer);
    } else {
        uloop_timeout_set(&map_timer->u_timeout, map_timer->period_ms);
    }
}

map_fd_t *map_fd_add(int fd, map_fd_cb_t cb, void *userdata)
{
    map_fd_t *map_fd;

    map_fd = calloc(1, sizeof(map_fd_t));
    if (NULL == map_fd) {
        return NULL;
    }

    map_fd->u_fd.fd  = fd;
    map_fd->u_fd.cb  = map_uloop_fd_handler;
    map_fd->cb       = cb;
    map_fd->userdata = userdata;
    if (uloop_fd_add(&map_fd->u_fd, ULOOP_READ) < 0) {
        free(map_fd);
        map_fd = NULL;
    }

    return map_fd;
}

void map_fd_delete(map_fd_t *map_fd)
{
    if (NULL == map_fd) {
        return;
    }

    uloop_fd_delete(&map_fd->u_fd);
    free(map_fd);
}

map_timer_t *map_timer_add(uint32_t expire_ms, uint32_t period_ms, map_timer_cb_t cb, void *userdata)
{
    map_timer_t *map_timer;

    map_timer = calloc(1, sizeof(map_timer_t));
    if (NULL == map_timer) {
        return NULL;
    }

    map_timer->u_timeout.cb = map_uloop_timeout_handler;
    map_timer->period_ms    = period_ms;
    map_timer->cb           = cb;
    map_timer->userdata     = userdata;
    if (uloop_timeout_set(&map_timer->u_timeout, expire_ms) < 0) {
        free(map_timer);
        map_timer = NULL;
    }

    return map_timer;
}

void map_timer_delete(map_timer_t *map_timer)
{
    if (NULL == map_timer) {
        return;
    }

    /* Cannot free map_timer when delete is called from timer callback */
    if (map_timer->in_cb) {
        map_timer->deleted = true;
        return;
    }
    uloop_timeout_cancel(&map_timer->u_timeout);
    free(map_timer);
}

int map_timer_restart(map_timer_t *map_timer)
{
    if (NULL == map_timer) {
        return -1;
    }
    /* Only for periodic timer */
    if (0 == map_timer->period_ms) {
        return -1;
    }

    uloop_timeout_set(&map_timer->u_timeout, map_timer->period_ms);

    return 0;
}

int map_timer_change_period(map_timer_t *map_timer, uint32_t period_ms)
{
    int new_timeout = period_ms;
    int remaining;

    if (NULL == map_timer) {
        return -1;
    }
    /* Only for periodic timer */
    if (0 == map_timer->period_ms || 0 == period_ms) {
        return -1;
    }

    /* Subtract running time and limit between 0 and period_ms */
    if ((remaining = uloop_timeout_remaining(&map_timer->u_timeout)) >= 0) {
        new_timeout -= ((int)map_timer->period_ms - remaining);
        if (new_timeout < 0) {
            new_timeout = 0;
        } else if (new_timeout > (int)period_ms) {
            new_timeout = period_ms;
        }
    }
    map_timer->period_ms = period_ms;
    uloop_timeout_set(&map_timer->u_timeout, new_timeout);

    return 0;
}

/*#######################################################################
#                       TIME                                            #
########################################################################*/
struct timespec get_current_time()
{
    struct timespec boottime = {0};
    clockid_t clocktype = CLOCK_MONOTONIC;
#ifdef CLOCK_BOOTTIME
    clocktype = CLOCK_BOOTTIME;
#endif
    clock_gettime(clocktype, &boottime);

    return boottime;
}

uint64_t get_clock_diff_secs(struct timespec new_time, struct timespec old_time)
{
    uint64_t old_ms  = 0;
    uint64_t new_ms  = 0;
    uint64_t diff = 0;

    old_ms = (old_time.tv_sec * 1000) + (old_time.tv_nsec / 1000000);
    new_ms = (new_time.tv_sec * 1000) + (new_time.tv_nsec / 1000000);

    diff = ((new_ms - old_ms + 500)/1000);   /* 500 added To round off
                                                Eg: 4999 milliseconds will be 4.999 seconds
                                                So adding 500 will behave as a round() func.
                                                We are not using math.round() here because
                                                it mandates to include -lm library */

    return diff;
}

static uint64_t get_time_sec(clockid_t clockid)
{
    struct timespec ts;

    if (0 != clock_gettime(clockid, &ts)) {
        return 0;
    }
    return ts.tv_sec;
}

static uint64_t get_time_msec(clockid_t clockid)
{
    struct timespec ts;

    if (0 != clock_gettime(clockid, &ts)) {
        return 0;
    }
    return SEC_TO_MSEC((uint64_t)ts.tv_sec) + NSEC_TO_MSEC((uint64_t)ts.tv_nsec);
}

uint64_t acu_get_timestamp_sec(void)
{
    return get_time_sec(TIMESTAMP_CLOCK_TYPE);
}

uint64_t acu_get_timestamp_msec(void)
{
    return get_time_msec(TIMESTAMP_CLOCK_TYPE);
}

/*#######################################################################
#                       LOGGING                                         #
########################################################################*/
static int get_module_loglevel(map_cfg_t *cfg, int module)
{
    switch(module) {
        case MAP_LIBRARY:        return cfg->library_log_level;
        case MAP_IEEE1905:       return cfg->ieee1905_log_level;
        case MAP_AGENT:          return cfg->agent_log_level;
        case MAP_CONTROLLER:     return cfg->controller_log_level;
        case MAP_VENDOR_IPC:     return cfg->vendor_ipc_log_level;
        case MAP_CONTROLLER_BHS: return cfg->controller_bhs_log_level;
        default:                 return LOG_INFO;
    }
}

void map_vlog_ext(int module, int level, bool check_level, const char *format, va_list args)
{
    map_cfg_t *cfg = map_cfg_get();

    if (check_level && level > get_module_loglevel(cfg, module)) {
        return;
    }

    if (log_stderr == cfg->log_output) {
        switch (level) {
            case LOG_ERR:
                CcspTraceError((format, args));
                break;
            case LOG_WARNING:
                CcspTraceWarning((format, args));
                break;
            case LOG_INFO:
                CcspTraceInfo((format, args));
                break;
            case LOG_DEBUG:
                CcspTraceDebug((format, args));
                break;
            default:
                break;
        }
    } else {
        vsyslog(level, format, args);
    }
}

void map_vlog(int module, int level, const char *format, va_list args)
{
    map_vlog_ext(module, level, true, format, args);
}

void map_log(int module, int level, const char *format,...)
{
    va_list args;
    va_start(args, format);
    map_vlog(module, level, format, args);
    va_end(args);
}

/*#######################################################################
#                       EBTABLES                                        #
########################################################################*/
static void ebtables_delete_insert(const char *mac_str)
{
    char cmd[256];

    snprintf(cmd, sizeof(cmd), "ebtables -t broute -D BROUTING -p 0x893a -d %s -j DROP", mac_str);
    if (0 != system(cmd)) {
        log_lib_e("failed to delete ebtables rule for %s", mac_str);
    }

    snprintf(cmd, sizeof(cmd), "ebtables -t broute -I BROUTING 1 -p 0x893a -d %s -j DROP", mac_str);
    if (0 != system(cmd)) {
        log_lib_e("failed to insert ebtables rule for %s", mac_str);
    }
}

int map_set_ebtables_rules(mac_addr al_mac)
{
    mac_addr_str mac_str;

    acu_mac_to_string(al_mac, mac_str);
    ebtables_delete_insert("01:80:c2:00:00:13");
    ebtables_delete_insert(mac_str);

    return 0;
}

/*#######################################################################
#                       VARIOUS                                         #
########################################################################*/
bool map_is_loopback_iface(const char *ifname)
{
    int sockfd;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr.ifr_name));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);

    if ((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
        return false;
    }

    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1) {
        close(sockfd);
        return false;
    }

    close(sockfd);
    return (ifr.ifr_flags & IFF_LOOPBACK);
}

size_t map_strlcpy(char *dst, const char *src, size_t max_len)
{
    size_t src_len = strlen(src);

    if (src_len + 1 < max_len) {
        memcpy(dst, src, src_len + 1);
    } else if (max_len != 0) {
        memcpy(dst, src, max_len - 1);
        dst[max_len-1] = '\0';
    }

    return src_len;
}

static int hex_to_num(const char ch)
{
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    } else if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    } else if (ch >= '0' && ch <= '9') {
        return ch - '0';
    } else {
        return -1;
    }
}

static int hex_to_byte(const char *hexadecimal)
{
    int num1, num2, val;

    num1 = hex_to_num(*hexadecimal);
    ++hexadecimal;
    num2 = hex_to_num(*hexadecimal);
    ++hexadecimal;

    if (num1 < 0 || num2 < 0) {
        return -1;
    }

    val = num2 | (num1 << 4);
    return val;
}

int acu_hex_string_to_buf(const char *const hex, uint8_t *const buf, size_t length)
{
    int num = 0;
    unsigned int i = 0;
    uint8_t *end_pos = buf;
    const char *start_pos = hex;

    if (!hex || !buf) {
        return -1;
    }

    while ((i < length) && (*start_pos != 0) && (*(start_pos + 1) != 0)) {
        num = hex_to_byte(start_pos);
        if (-1 == num) {
            return -1;
        }
        start_pos = start_pos + 2;
        *end_pos = num;
        ++end_pos;
        ++i;
    }

    if ((*start_pos == 0)) {
        return 0;
    }

    return -1;
}


/*#######################################################################
#                            MAC ADDRESSES                              #
########################################################################*/
int acu_mac_from_string(const char *macstr, mac_addr mac)
{
    if ((NULL != macstr) && (NULL != mac)) {
        if (sscanf(macstr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
            return 0;
        }
    }
    return -1;
}

int acu_mac_to_string(const mac_addr mac, mac_addr_str macstr)
{
    if ((NULL != macstr) && (NULL != mac)) {
        snprintf(macstr, sizeof(mac_addr_str), "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return 0;
    }
    return -1;
}

char *acu_mac_string(const mac_addr mac)
{
    static char macstr[18];

    acu_mac_to_string(mac, macstr);
    return macstr;
}

int acu_mac_hash(const mac_addr mac, int buckets)
{
    unsigned long h = 0, high;
    int i;

    for (i = 0; i < 6; i++) {
        h = (h << 4) + mac[i];
        if ((high = h & 0xF0000000) != 0) {
            h ^= high >> 24;
        }
        h &= ~high;
    }
    return h % buckets;
}
