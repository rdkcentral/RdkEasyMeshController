/*
 * Copyright (c) 2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef MAP_BLOCKLIST_LIST_H_
#define MAP_BLOCKLIST_LIST_H_

#include "arraylist.h"
#include "kwaytree.h"
#include "map_common_defines.h"
#include "map_timer_handler.h"
#include "map_utils.h"

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
typedef enum {
    THIRD_PARTY_CONTROLLER = 0,
    THIRD_PARTY_AGENT,
} map_block_reason_t;

typedef struct map_blocked_dev_info_s map_blocked_dev_info_t;

typedef void (*map_blocklist_update_cb_t)(void);

typedef void (*map_blocklist_iter_cb_t)(mac_addr src_mac, map_block_reason_t reason, size_t idx, void *data);

/*#######################################################################
#                       FUNCTIONS                                       #
########################################################################*/
/** Initialize block list. */
int map_blocklist_init(void);

/** De-initializes block list. */
void map_blocklist_fini(void);

/* Set update callback (only one callback supported at the moment) */
void map_blocklist_register_update_cb(map_blocklist_update_cb_t cb);

/** Dump block list list. */
void map_blocklist_dump(map_printf_cb_t print_cb);

/* Add device to blocklist */
map_blocked_dev_info_t *map_blocklist_add_dev(mac_addr src_mac, map_block_reason_t reason);

/* Get device from blocllist */
map_blocked_dev_info_t *map_blocklist_get_dev(mac_addr src_mac);

/* Update timestamp of device in blocklist */
int map_blocklist_update_dev(map_blocked_dev_info_t *dev);

/* Remove device from blocklist */
int map_blocklist_remove_dev(map_blocked_dev_info_t *dev);

/* Get number of devices in blocklist */
size_t map_blocklist_get_nr_dev(void);

/* Iterate over devices in blocklist */
void map_bloclist_iter_dev(map_blocklist_iter_cb_t cb, void *data);

#endif /* MAP_BLOCKLIST_H_ */
