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

#include "map_utils.h"

#define LOG_TAG "staging_list"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
typedef struct map_1905_dev_info_s {
    mac_addr     al_mac;
    mac_addr_str al_mac_str;
    mac_addr     src_mac;
    mac_addr     mac_tlv_mac;
    list_head_t  list;
    bool         topo_discovery;
} map_1905_dev_info_t;

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static LIST_HEAD(g_staging_list);

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
void map_stglist_dump(void)
{
    map_1905_dev_info_t *dev;

    list_for_each_entry(dev, &g_staging_list, list) {
        log_lib_i("staging_list -> 1905 dev mac is %s", dev->al_mac_str);
    }
}

map_1905_dev_info_t *map_stglist_create_1905_dev(mac_addr al_mac, mac_addr src_mac, bool topo_discovery)
{
    map_1905_dev_info_t *dev;

    if (!(dev = calloc(1, sizeof(map_1905_dev_info_t)))) {
        log_lib_e("Failed to alloc memory");
        return NULL;
    }

    /* Update the AL and SRC mac */
    maccpy(dev->al_mac, al_mac);
    mac_to_string(dev->al_mac, dev->al_mac_str);
    maccpy(dev->src_mac, src_mac);

    INIT_LIST_HEAD(&dev->list);

    /* Add to linked list */
    list_add_tail(&dev->list, &g_staging_list);

    dev->topo_discovery = topo_discovery;

    log_lib_d("-----------------------------------------------------");
    log_lib_d("| New 1905 dev %s ", dev->al_mac_str);
    log_lib_d("-----------------------------------------------------");

    return dev;
}

int map_stglist_remove_1905_dev(map_1905_dev_info_t *dev)
{
    /* Unlink */
    list_del(&dev->list);

    log_lib_d("dev[%s] removed", dev->al_mac_str);

    free(dev);

    return 0;
}

map_1905_dev_info_t *map_stglist_get_1905_dev_from_src_mac(mac_addr src_mac)
{
    map_1905_dev_info_t *dev;

    list_for_each_entry(dev, &g_staging_list, list) {
        if (!maccmp(dev->src_mac, src_mac)) {
            return dev;
        }
    }

    return NULL;
}

map_1905_dev_info_t *map_stglist_get_1905_dev(mac_addr al_mac)
{
    map_1905_dev_info_t *dev;

    list_for_each_entry(dev, &g_staging_list, list) {
        if (!maccmp(dev->al_mac, al_mac)) {
            return dev;
        }
    }

    return NULL;
}

uint8_t *map_stglist_get_1905_dev_al_mac(map_1905_dev_info_t *dev)
{
    return (uint8_t *)dev->al_mac;
}

bool map_stglist_is_1905_dev_rcvd_topo_discovery(map_1905_dev_info_t *dev)
{
    return dev->topo_discovery;
}

void map_stglist_set_1905_dev_mac_tlv_mac(map_1905_dev_info_t *dev, uint8_t *mac)
{
    maccpy(dev->mac_tlv_mac, mac);
}

uint8_t *map_stglist_get_1905_dev_mac_tlv_mac(map_1905_dev_info_t *dev)
{
    return dev->mac_tlv_mac;
}

void map_stglist_fini(void)
{
    map_1905_dev_info_t *dev, *next;

    /* Remove all 1905 devs */
    list_for_each_entry_safe(dev, next, &g_staging_list, list) {
        map_stglist_remove_1905_dev(dev);
    }
}

int map_stglist_init(void)
{
    return 0;
}
