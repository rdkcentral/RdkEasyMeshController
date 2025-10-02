/*
 * Copyright (c) 2019-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include "test.h"
#include "map_data_model.h"
#include "map_dm_eth_device_list.h"
#include "map_topology_tree.h"
#include "1905_platform.h"

/*#######################################################################
#                   GLOBALS                                             #
########################################################################*/
static mac_addr g_root_ale_mac    = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
static mac_addr g_ale_mac         = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static mac_addr g_ale2_mac        = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
static mac_addr g_radio_id        = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03};
static mac_addr g_bssid           = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04};
static mac_addr g_sta_mac         = {0x00, 0x00, 0x00, 0x00, 0x00, 0x05};

static mac_addr g_eth_mac         = {0x01, 0x00, 0x00, 0x00, 0x00, 0x02};
static mac_addr g_eth2_mac        = {0x01, 0x00, 0x00, 0x00, 0x00, 0x03};
static mac_addr g_eth_dev_macs[3] = {{0x81, 0x00, 0x00, 0x00, 0x00, 0x01}, {0x81, 0x00, 0x00, 0x00, 0x00, 0x02}, {0x79, 0x00, 0x00, 0x00, 0x00, 0x03}};

/*#######################################################################
#                   HELP FUNCTIONS                                      #
########################################################################*/
static void test_init(void)
{
    fail_unless(!map_dm_init());
    fail_unless(init_topology_tree(g_root_ale_mac) == 1);
}

static void test_fini(void)
{
    map_dm_fini();
}

/*#######################################################################
#                   TEST_ETH_DEVICE_LIST                                #
########################################################################*/
/* Create topology:
    controller
        - ale (eth backhaul g_eth_mac)
            - ale2 (eth backhaul g_eth2_mac)
*/
START_TEST(test_eth_device_list)
{
    map_ale_info_t       *ale, *ale2;
    map_radio_info_t     *radio;
    map_bss_info_t       *bss;
    map_sta_info_t       *sta;
    map_emex_eth_iface_t *eth_iface;
    int                   i;

    test_init();

    /* ALE 1 */
    fail_unless(!!(ale   = map_dm_create_ale(g_ale_mac)));
    fail_unless(!!(radio = map_dm_create_radio(ale, g_radio_id)));
    fail_unless(!!(bss   = map_dm_create_bss(radio, g_bssid)));
    fail_unless(!!(sta   = map_dm_create_sta(bss, g_sta_mac)));

    fail_unless(topology_tree_insert(get_root_ale_node(), ale) == 1);

    /* Add local interfaces */
    ale->local_iface_count = 2;
    fail_unless(!!(ale->local_iface_list = calloc(2, sizeof(map_local_iface_t))));

    maccpy(ale->local_iface_list[0].mac_address, g_eth_mac);
    ale->local_iface_list[0].media_type = INTERFACE_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET;

    maccpy(ale->local_iface_list[1].mac_address, g_bssid);
    ale->local_iface_list[1].media_type = INTERFACE_TYPE_IEEE_802_11AX;

    /* Add non 1905 mac */
    ale->non_1905_neighbor_count = 2;
    fail_unless(!!(ale->non_1905_neighbor_list = calloc(2, sizeof(map_non_1905_neighbor_t))));

    maccpy(ale->non_1905_neighbor_list[0].local_iface_mac, g_eth_mac);
    ale->non_1905_neighbor_list[0].media_type = INTERFACE_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET;
    ale->non_1905_neighbor_list[0].macs_nr = 2;
    ale->non_1905_neighbor_list[0].macs = calloc(2, sizeof(mac_addr));
    maccpy(ale->non_1905_neighbor_list[0].macs[0], g_eth_dev_macs[0]);
    maccpy(ale->non_1905_neighbor_list[0].macs[1], g_eth_dev_macs[1]);
    acu_sort_mac_array(ale->non_1905_neighbor_list[0].macs, ale->non_1905_neighbor_list[0].macs_nr);

    maccpy(ale->non_1905_neighbor_list[1].local_iface_mac, g_bssid);
    ale->non_1905_neighbor_list[1].media_type = INTERFACE_TYPE_IEEE_802_11AX;
    ale->non_1905_neighbor_list[1].macs_nr = 1;
    ale->non_1905_neighbor_list[1].macs = calloc(1, sizeof(mac_addr));
    maccpy(ale->non_1905_neighbor_list[1].macs[0], g_sta_mac);

    /* Add emex ethernet interface */
    ale->emex.eth_iface_list.iface_nr = 1;
    ale->emex.eth_iface_list.ifaces = calloc(1, sizeof(map_emex_eth_iface_t));
    eth_iface = &ale->emex.eth_iface_list.ifaces[0];
    eth_iface->non_i1905_neighbor_macs_nr = 2;
    eth_iface->non_i1905_neighbor_macs = calloc(2, sizeof(mac_addr));
    maccpy(eth_iface->non_i1905_neighbor_macs[0], g_eth_dev_macs[0]);
    maccpy(eth_iface->non_i1905_neighbor_macs[1], g_eth_dev_macs[1]);


    /* ALE2 */
    fail_unless(!!(ale2 = map_dm_create_ale(g_ale2_mac)));

    fail_unless(topology_tree_insert(ale, ale2) == 1);

    maccpy(ale2->upstream_local_iface_mac, g_eth2_mac);
    maccpy(ale2->upstream_remote_iface_mac, g_eth_mac);

    ale2->local_iface_count = 1;
    fail_unless(!!(ale2->local_iface_list = calloc(1, sizeof(map_local_iface_t))));

    maccpy(ale2->local_iface_list[0].mac_address, g_eth2_mac);
    ale2->local_iface_list[0].media_type = INTERFACE_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET;

    /* Add non 1905 mac */
    ale2->non_1905_neighbor_count = 1;
    fail_unless(!!(ale2->non_1905_neighbor_list = calloc(2, sizeof(map_non_1905_neighbor_t))));

    maccpy(ale2->non_1905_neighbor_list[0].local_iface_mac, g_eth2_mac);
    ale2->non_1905_neighbor_list[0].media_type = INTERFACE_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET;
    ale2->non_1905_neighbor_list[0].macs_nr = 3;
    ale2->non_1905_neighbor_list[0].macs = calloc(3, sizeof(mac_addr));
    maccpy(ale2->non_1905_neighbor_list[0].macs[0], g_eth_dev_macs[1]);
    maccpy(ale2->non_1905_neighbor_list[0].macs[1], g_sta_mac);  /* Needs to be ignored */
    maccpy(ale2->non_1905_neighbor_list[0].macs[2], g_eth2_mac); /* Needs to be ignored */
    acu_sort_mac_array(ale2->non_1905_neighbor_list[0].macs, ale2->non_1905_neighbor_list[0].macs_nr);


    /* Update device list several times.  Nothing happens the first "HISTORY_LEN" times. */
    for (i = 0; i < ETH_DEVICE_HISTORY_LEN; i++) {
        map_dm_eth_device_list_schedule_update();
        fail_unless(ale->eth_device_list.macs_nr == 0);
        fail_unless(ale2->eth_device_list.macs_nr == 0);
    }

    /* Update device list again. */
    map_dm_eth_device_list_schedule_update();

    /* Verify result */
    /* Check ALE:
       - ethernet device with mac g_eth_dev_macs[0]
       - emex filtered iface list is equal to device list
    */
    fail_unless(ale->eth_device_list.macs_nr == 1);
    fail_unless(!maccmp(ale->eth_device_list.macs[0], g_eth_dev_macs[0]));
    fail_unless(eth_iface->filtered_non_i1905_neighbor_macs_nr = 1);
    fail_unless(!maccmp(eth_iface->filtered_non_i1905_neighbor_macs[0], g_eth_dev_macs[0]));

    /* Check ALE2
        - ethernet device with mac g_eth_dev_macs[1]
    */
    fail_unless(ale2->eth_device_list.macs_nr == 1);
    fail_unless(!maccmp(ale2->eth_device_list.macs[0], g_eth_dev_macs[1]));


    /* Add another mac to ALE2 */
    maccpy(ale2->non_1905_neighbor_list[0].macs[0], g_eth_dev_macs[1]);
    maccpy(ale2->non_1905_neighbor_list[0].macs[1], g_sta_mac);
    maccpy(ale2->non_1905_neighbor_list[0].macs[2], g_eth_dev_macs[2]);
    acu_sort_mac_array(ale2->non_1905_neighbor_list[0].macs, ale2->non_1905_neighbor_list[0].macs_nr);

    /* Update device list several times.  Nothing happens the first "HISTORY_LEN" times. */
    for (i = 0; i < ETH_DEVICE_HISTORY_LEN; i++) {
        map_dm_eth_device_list_schedule_update();
        fail_unless(ale->eth_device_list.macs_nr == 1);
        fail_unless(ale2->eth_device_list.macs_nr == 1);
    }

    /* Update second time */
    map_dm_eth_device_list_schedule_update();

    /* Verify result */
    /* Check ALE:
       - ethernet device with mac g_eth_dev_macs[0]
    */
    fail_unless(ale->eth_device_list.macs_nr == 1);
    fail_unless(!maccmp(ale->eth_device_list.macs[0], g_eth_dev_macs[0]));
    fail_unless(eth_iface->filtered_non_i1905_neighbor_macs_nr = 1);
    fail_unless(!maccmp(eth_iface->filtered_non_i1905_neighbor_macs[0], g_eth_dev_macs[0]));

    /* Check ALE2
        - ethernet device with mac g_eth_dev_macs[1] and g_eth_dev_macs[2]
        !! macs are sorted
    */
    fail_unless(ale2->eth_device_list.macs_nr == 2);
    fail_unless(!maccmp(ale2->eth_device_list.macs[0], g_eth_dev_macs[2]));
    fail_unless(!maccmp(ale2->eth_device_list.macs[1], g_eth_dev_macs[1]));

    test_fini();
}
END_TEST

const char *test_suite_name = "map_dm_eth_device_list";
test_case_t test_cases[] = {
    TEST("eth_device_list", test_eth_device_list  ),
    TEST_CASES_END
};
