/*
 * Copyright (c) 2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "blocklist"

#include "map_utils.h"
#include "map_blocklist.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define MAP_BLOCKLIST_MAX_AGE     (30 * 60) /* 30 Minutes */
#define MAP_BLOCKLIST_AGE_TIMEOUT ( 1 * 60) /* 1 Minute */

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
typedef struct map_blocked_dev_info_s {
    mac_addr            src_mac;
    mac_addr_str        src_mac_str;
    map_block_reason_t  reason;
    uint64_t            last_seen_ts; /* in seconds */
    list_head_t         list;
} map_blocked_dev_info_t;

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static size_t g_block_nr;
static LIST_HEAD(g_block_list);
static map_blocklist_update_cb_t g_update_cb;

/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
static const char* map_blocklist_get_block_reason_str(map_block_reason_t reason)
{
    switch (reason) {
        case THIRD_PARTY_CONTROLLER:    return "3rd Party Controller";
        case THIRD_PARTY_AGENT:         return "3rd Party Agent";
        default:                        return "Unknown";
    }
}

static int map_blocklist_flush(uint32_t age)
{
    map_blocked_dev_info_t *dev, *next;

    /* Remove all blocked devs */
    list_for_each_entry_safe(dev, next, &g_block_list, list) {
        if (age == 0 || acu_timestamp_delta_sec(dev->last_seen_ts) > age) {
            map_blocklist_remove_dev(dev);
        }
    }

    return 0;
}

static uint8_t map_blocklist_age_timer_cb(UNUSED char* timer_id, UNUSED void *arg)
{
    map_blocklist_flush(MAP_BLOCKLIST_MAX_AGE);

    return 0;
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
void map_blocklist_dump(map_printf_cb_t print_cb)
{
    map_blocked_dev_info_t *dev;

    list_for_each_entry(dev, &g_block_list, list) {
        print_cb("device[%s] reason[%s] age[%"PRIu64"]\n",
                 dev->src_mac_str, map_blocklist_get_block_reason_str(dev->reason),
                 acu_timestamp_delta_sec(dev->last_seen_ts));
    }
}

map_blocked_dev_info_t *map_blocklist_add_dev(mac_addr src_mac, map_block_reason_t reason)
{
    map_blocked_dev_info_t *dev;

    if (!(dev = calloc(1, sizeof(map_blocked_dev_info_t)))) {
        log_lib_e("Failed to alloc memory");
        return NULL;
    }

    /* Update src mac */
    maccpy(dev->src_mac, src_mac);
    mac_to_string(dev->src_mac, dev->src_mac_str);

    /* Update the reason */
    dev->reason = reason;

    /* Set last seen timestamp to now */
    dev->last_seen_ts = acu_get_timestamp_sec();

    INIT_LIST_HEAD(&dev->list);

    /* Add to linked list */
    list_add_tail(&dev->list, &g_block_list);
    g_block_nr++;

    log_lib_w("-----------------------------------------------------");
    log_lib_w("| Device[%s] blocked. Reason:[%s] ", dev->src_mac_str, map_blocklist_get_block_reason_str(dev->reason));
    log_lib_w("-----------------------------------------------------");

    /* Call update callback when registered */
    if (g_update_cb) {
        g_update_cb();
    }

    return dev;
}

int map_blocklist_update_dev(map_blocked_dev_info_t *dev)
{
    dev->last_seen_ts = acu_get_timestamp_sec();

    return 0;
}

int map_blocklist_remove_dev(map_blocked_dev_info_t *dev)
{
    /* Unlink */
    list_del(&dev->list);
    g_block_nr--;

    log_lib_w("dev[%s] removed", dev->src_mac_str);

    free(dev);

    /* Call update callback when registered */
    if (g_update_cb) {
        g_update_cb();
    }

    return 0;
}

map_blocked_dev_info_t *map_blocklist_get_dev(mac_addr src_mac)
{
    map_blocked_dev_info_t *dev;

    list_for_each_entry(dev, &g_block_list, list) {
        if (!maccmp(dev->src_mac, src_mac)) {
            return dev;
        }
    }

    return NULL;
}

size_t map_blocklist_get_nr_dev(void)
{
    return g_block_nr;
}

void map_bloclist_iter_dev(map_blocklist_iter_cb_t cb, void *data)
{
    map_blocked_dev_info_t *dev;
    int                     idx = 0;

    list_for_each_entry(dev, &g_block_list, list) {
        cb(dev->src_mac, dev->reason, idx++, data);
    }
}

void map_blocklist_register_update_cb(map_blocklist_update_cb_t cb)
{
    g_update_cb = cb;
}

void map_blocklist_fini(void)
{
    if (map_is_timer_registered(BLOCKLIST_AGE_TIMER_ID)) {
        map_timer_unregister_callback(BLOCKLIST_AGE_TIMER_ID);
    }

    map_blocklist_flush(0);
}

int map_blocklist_init(void)
{
    if (map_timer_register_callback(MAP_BLOCKLIST_AGE_TIMEOUT, BLOCKLIST_AGE_TIMER_ID, NULL, map_blocklist_age_timer_cb)) {
        log_lib_e("Failed to register BLOCKLIST_REFRESH_TIMER.");
        return -1;
    }

    return 0;
}
