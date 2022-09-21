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
    REASON_0 = 0,
} map_block_reason_t;

typedef struct map_blocked_dev_info_s map_blocked_dev_info_t;

/*#######################################################################
#                       FUNCTIONS                                       #
########################################################################*/
/** Initialize block list. */
int map_blocklist_init(void);

/** De-initializes block list. */
void map_blocklist_fini(void);

/** Dump block list list. */
void map_blocklist_dump(void);

map_blocked_dev_info_t *map_blocklist_add_dev(mac_addr src_mac, map_block_reason_t reason);

map_blocked_dev_info_t *map_blocklist_get_blocked_dev(mac_addr src_mac);

int map_blocklist_remove_dev(map_blocked_dev_info_t *dev);

#endif /* MAP_BLOCKLIST_H_ */
