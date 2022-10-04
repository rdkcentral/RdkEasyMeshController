/*
 * Copyright (c) 2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef MAP_STAGING_LIST_H_
#define MAP_STAGING_LIST_H_

#include "arraylist.h"
#include "kwaytree.h"
#include "map_common_defines.h"
#include "map_timer_handler.h"
#include "map_utils.h"

typedef struct map_1905_dev_info_s map_1905_dev_info_t;

/*#######################################################################
#                       FUNCTIONS                                       #
########################################################################*/
/** De-initializes staging list. */
void map_stglist_fini(void);

/** Initialize staging list. */
int map_stglist_init(void);

/** Create new 1905 dev. */
map_1905_dev_info_t *map_stglist_create_1905_dev(mac_addr al_mac, mac_addr src_mac, bool topo_discovery);

/** Remove 1905 node. */
int map_stglist_remove_1905_dev(map_1905_dev_info_t *dev);

/** Get 1905 dev. */
map_1905_dev_info_t *map_stglist_get_1905_dev(mac_addr al_mac);
map_1905_dev_info_t *map_stglist_get_1905_dev_from_src_mac(mac_addr src_mac);

/** Get 1905 dev AL mac. */
uint8_t *map_stglist_get_1905_dev_al_mac(map_1905_dev_info_t *dev);

/** Is 1905 dev received topology discovery. */
bool map_stglist_is_1905_dev_rcvd_topo_discovery(map_1905_dev_info_t *dev);

/** Dump 1905 dev staging list. */
void map_stglist_dump(void);

/** Sets MAC address type TLV MAC. */
void map_stglist_set_1905_dev_mac_tlv_mac(map_1905_dev_info_t *dev, uint8_t *mac);

/** Gets MAC address type TLV MAC. */
uint8_t *map_stglist_get_1905_dev_mac_tlv_mac(map_1905_dev_info_t *dev);

#endif /* MAP_STAGING_LIST_H_ */
