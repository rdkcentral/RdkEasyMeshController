/********** COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) 2020-2020  -  AirTies Wireless Networks                **
** - All Rights Reserved                                                **
** AirTies hereby informs you that certain portions                     **
** of this software module and/or Work are owned by AirTies             **
** and/or its software providers.                                       **
** Distribution copying and modification of all such work are reserved  **
** to AirTies and/or its affiliates, and are not permitted without      **
** express written authorization from AirTies.                          **
** AirTies is registered trademark and trade name of AirTies,           **
** and shall not be used in any manner without express written          **
** authorization from AirTies                                           **
*************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "map_utils.h"

mac_addr g_zero_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
mac_addr g_wildcard_mac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void map_vlog(int module, int level, const char *format, va_list args)
{
    int   log_level = 0;
    char *p = getenv("UNITTEST_LOG_LEVEL");

    if (p) {
        char *strs[]   = {"emerge",  "alert",  "crit",   "error", "warn",      "notice",   "info",   "debug",    "trace"};
        int   levels[] = {LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG, LOG_TRACE};
        int   i;

        for (i = 0; i < ARRAY_SIZE(strs); i++) {
            if (strcasestr(p, strs[i])) {
                log_level = levels[i];
                break;
            }
        }
    }

    if (level <= log_level) {
        vfprintf(stderr, format, args);
        fprintf(stderr, "\n");
    }
}

struct timespec get_current_time()
{
    struct timespec boottime = {0};

    return boottime;
}

uint64_t get_clock_diff_secs(struct timespec new_time, struct timespec old_time)
{
    return 0;
}

void map_log(int module, int level, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    map_vlog(module, level, format, args);
    va_end(args);
}

bool map_is_loopback_iface(const char *ifname)
{
    return !strcmp(ifname, "lo");
}

bool map_is_auth_mode_enterprise_supported(uint16_t auth_modes)
{
    /* All enterprise security modes will advertise auth mode as WPA2-enterprise
     * since there (is/will be) no enterprise security mode for WPA3 defined in WSC standard.
     * We will discriminate enterprise modes using airties attributes.
    */
    return (auth_modes & 0x0010/* IEEE80211_AUTH_MODE_WPA2 */);
}

uint8_t map_count_bits_16(uint16_t n)
{
        uint8_t c = 0;

        for (; n; ++c) {
                n &= n - 1;
        }

        return c;
}
