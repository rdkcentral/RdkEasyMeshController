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
typedef struct map_blocked_dev_info_s {
    mac_addr            src_mac;
    mac_addr_str        src_mac_str;
    map_block_reason_t  reason;
    list_head_t         list;
} map_blocked_dev_info_t;

#define MAP_BLOCKLIST_REFRESH_TIMEOUT   60 * 30 /* 30 Minutes */
/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static LIST_HEAD(g_block_list);

/*#######################################################################
#                       HELPER FUNCTIONS                                #
########################################################################*/
const char* map_blocklist_get_block_reason_str(map_block_reason_t reason)
{
    switch (reason) {
        case REASON_0:                  return "Reason 0";
        default:                        return "Unknown";
    }
}

/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
static int map_blocklist_flush()
{
    map_blocked_dev_info_t *dev, *next;

    log_lib_w("Flushing block list:");

    /* Remove all blocked devs */
    list_for_each_entry_safe(dev, next, &g_block_list, list) {
        map_blocklist_remove_dev(dev);
    }

    return 0;
}

static uint8_t map_blocklist_refresh_timer_cb(UNUSED char* timer_id, UNUSED void *arg)
{
    map_blocklist_flush();

    return 1; /* Remove Timer */
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
void map_blocklist_dump(void)
{
    map_blocked_dev_info_t *dev;

    list_for_each_entry(dev, &g_block_list, list) {
        log_lib_w("blocked_device_list -> device:[%s] reason:[%s]", dev->src_mac_str, map_blocklist_get_block_reason_str(dev->reason));
    }
}

map_blocked_dev_info_t *map_blocklist_add_dev(mac_addr src_mac, map_block_reason_t reason)
{
    map_blocked_dev_info_t *dev;

    /* Add a timer to refresh blocklist by flushing */
    if (!map_is_timer_registered(BLOCKLIST_REFRESH_TIMER_ID)) {
        if(map_timer_register_callback(MAP_BLOCKLIST_REFRESH_TIMEOUT, BLOCKLIST_REFRESH_TIMER_ID, NULL, map_blocklist_refresh_timer_cb)) {
            log_lib_e("Failed to register BLOCKLIST_REFRESH_TIMER.");
            return NULL;
        }
    }

    if (!(dev = calloc(1, sizeof(map_blocked_dev_info_t)))) {
        log_lib_e("Failed to alloc memory");
        return NULL;
    }

    /* Update src mac */
    maccpy(dev->src_mac, src_mac);
    mac_to_string(dev->src_mac, dev->src_mac_str);

    /* Update the reason */
    dev->reason = reason;

    INIT_LIST_HEAD(&dev->list);

    /* Add to linked list */
    list_add_tail(&dev->list, &g_block_list);

    log_lib_w("-----------------------------------------------------");
    log_lib_w("| Device[%s] blocked. Reason:[%s] ", dev->src_mac_str, map_blocklist_get_block_reason_str(dev->reason));
    log_lib_w("-----------------------------------------------------");

    return dev;
}

int map_blocklist_remove_dev(map_blocked_dev_info_t *dev)
{
    /* Unlink */
    list_del(&dev->list);

    log_lib_w("dev[%s] removed", dev->src_mac_str);

    free(dev);

    return 0;
}

map_blocked_dev_info_t *map_blocklist_get_blocked_dev(mac_addr src_mac)
{
    map_blocked_dev_info_t *dev;

    list_for_each_entry(dev, &g_block_list, list) {
        if (!maccmp(dev->src_mac, src_mac)) {
            return dev;
        }
    }

    return NULL;
}


void map_blocklist_fini(void)
{

    if (map_is_timer_registered(BLOCKLIST_REFRESH_TIMER_ID)) {
        map_timer_unregister_callback(BLOCKLIST_REFRESH_TIMER_ID);
    }

    map_blocklist_flush();
}

int map_blocklist_init(void)
{
    return 0;
}
