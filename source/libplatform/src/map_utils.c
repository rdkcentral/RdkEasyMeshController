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

#include "ccsp_trace.h"

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
#                       LOGGING                                         #
########################################################################*/
static int get_module_loglevel(map_cfg_t *cfg, int module)
{
    switch(module) {
        case MAP_LIBRARY:        return cfg->library_log_level;
        case MAP_IEEE1905:       return cfg->ieee1905_log_level;
        case MAP_CONTROLLER:     return cfg->controller_log_level;
        case MAP_SSP:            return cfg->ssp_log_level;
        default:                 return LOG_INFO;
    }
}

static void map_vlog_file(int level, const char *format, va_list args)
{
    char buffer[1024];

    vsnprintf(buffer, sizeof(buffer), format, args);
    switch (level) {
        case LOG_ERR:
            CcspTraceError(("%s\n", buffer));
            break;
        case LOG_WARNING:
            CcspTraceWarning(("%s\n", buffer));
            break;
        case LOG_NOTICE:
            CcspTraceNotice(("%s\n", buffer));
            break;
        case LOG_INFO:
            CcspTraceInfo(("%s\n", buffer));
            break;
        case LOG_DEBUG:
        case LOG_TRACE:
            CcspTraceDebug(("%s\n", buffer));
            break;
        default:
            break;
    }
}

void map_vlog_ext(int module, int level, bool check_level, const char *format, va_list args)
{
    va_list args2;
    map_cfg_t *cfg = map_cfg_get();

    if (check_level && level > get_module_loglevel(cfg, module)) {
        return;
    }

    /* args will be consumed for stderr, we need to copy */
    va_copy(args2, args);
    map_vlog_file(level, format, args2);
    va_end(args2);

    if (log_file_only == cfg->log_output) {
        return;
    }

    if (log_stderr == cfg->log_output) {
        vfprintf(stderr, format, args);
        fprintf(stderr, "\n");
    } else {
        vsyslog(level, format, args);
    }
}

void map_vlog(int module, int level, const char *format, va_list args)
{
    map_vlog_ext(module, level, true, format, args);
}

void map_log(int module, int level, const char *format, ...)
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

uint8_t map_count_bits_16(uint16_t n)
{
        uint8_t c = 0;

        for (; n; ++c) {
                n &= n - 1;
        }

        return c;
}
