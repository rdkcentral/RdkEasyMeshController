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
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#include <libubox/uloop.h>

#include "ssp_global.h"

#include "map_utils.h"
#include "map_config.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
mac_addr g_zero_mac     = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
mac_addr g_wildcard_mac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

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

bool map_is_ethernet_iface(const char *ifname)
{
    int sockfd;
    struct ifreq ifr;
    struct ethtool_cmd ecmd;

    memset(&ecmd, 0, sizeof(ecmd));
    memset(&ifr, 0, sizeof(ifr));

    if ((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
        return false;
    }

    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_data = (void *)&ecmd;
    ecmd.cmd = ETHTOOL_GSET;

    if (ioctl(sockfd, SIOCETHTOOL, &ifr) == -1) {
        close(sockfd);
        return false;
    }

    close(sockfd);
    return true;
}
