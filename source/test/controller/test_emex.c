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

#include "map_ctrl_emex_tlv_handler.h"

#include "1905_cmdus.h"
#include "1905_tlvs.h"
#include "map_tlvs.h"
#include "map_data_model.h"
#include "map_config.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define VARS                              \
    map_ale_info_t        *ale    = NULL; \
    UNUSED packet_t       *packet = NULL; \
    UNUSED i1905_cmdu_t   *cmdu   = NULL;

#define INIT                                           \
    fail_unless(!map_dm_init());                       \
    fail_unless(!map_emex_init());                     \
    fail_unless(!!(ale = map_dm_create_ale(g_al_mac)));

#define READ_PARSE(file)                      \
    fail_unless(!!(packet = pcap_read_first_packet(DATA_DIR "/" file))); \
    fail_unless(!!(cmdu = parse_cmdu(packet)));                          \
    process_emex_tlv(ale, cmdu);                                         \
    free_1905_CMDU_structure(cmdu);                                      \
    free(packet);

#define CLEANUP             \
    map_dm_remove_ale(ale); \
    map_emex_fini();        \
    map_dm_fini();

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static mac_addr g_al_mac    = {0x02, 0x01, 0x02, 0x03, 0x04, 0x05};

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
static i1905_cmdu_t *parse_cmdu(packet_t *p)
{
    uint8_t *streams[2] = {p->data + sizeof(eth_hdr_t), NULL};
    uint16_t lengths[2]  = {p->len, 0};

    fail_unless(p->len >= sizeof(eth_hdr_t));

    return parse_1905_CMDU_from_packets(streams, lengths);
}

static void process_emex_tlv(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    uint8_t *tlv;
    size_t   idx;
    size_t   count = 0;

    i1905_foreach_tlv_type_in_cmdu(TLV_TYPE_VENDOR_SPECIFIC, tlv, cmdu, idx) {
        i1905_vendor_specific_tlv_t *t = (i1905_vendor_specific_tlv_t *)tlv;

        count++;
        fail_unless(map_emex_is_valid_tlv(t));
        fail_unless(map_emex_parse_tlv(ale, t) == 1);
    }
    fail_unless(count == 1);
}

/*#######################################################################
#                       TEST_0002_FEATURE_PROFILE_TLV                   #
########################################################################*/
START_TEST(test_0002_feature_profile_tlv)
{
    VARS
    INIT
    READ_PARSE("emex_tlv_0002_feature_profile.pcap");

    /* Check datamodel */
    fail_unless(ale->emex.enabled                                 == true);
    fail_unless(ale->emex.feature_profile.agent_version           == 0x01020304);
    fail_unless(ale->emex.feature_profile.feature_count           == 2);
    fail_unless(ale->emex.feature_profile.feature_list[0].id      == 3);
    fail_unless(ale->emex.feature_profile.feature_list[0].version == 1);
    fail_unless(ale->emex.feature_profile.feature_list[1].id      == 9);
    fail_unless(ale->emex.feature_profile.feature_list[1].version == 1);

    /* With one agent, common feature list should be equal */
    map_emex_common_feature_list_t *f = controller_get_emex_common_feature_list();
    fail_unless(f->feature_count           == 2);
    fail_unless(f->feature_list[0].id      == 3);
    fail_unless(f->feature_list[0].version == 1);
    fail_unless(f->feature_list[1].id      == 9);
    fail_unless(f->feature_list[1].version == 1);

    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_0003_DEVICE_INFO_TLV                       #
########################################################################*/
START_TEST(test_0003_device_info_tlv)
{
    VARS
    INIT
    READ_PARSE("emex_tlv_0003_device_info.pcap");

    /* Check datamodel */
    fail_unless(!memcmp(ale->emex.device_info.client_id, (char*)"test", 4));
    fail_unless(!memcmp(ale->emex.device_info.client_secret, (char*)"topsecret", 9));
    fail_unless(ale->emex.device_info.boot_id == 0x6FEF8CCF);
    fail_unless(ale->emex.device_info.product_class & EMEX_PRODUCT_CLASS_EXTENDER);
    fail_unless(ale->emex.device_info.device_role & EMEX_DEVICE_ROLE_CONTROLLER);

    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_0004_DEVICE_METRICS_TLV                    #
########################################################################*/
START_TEST(test_0004_device_metrics_tlv)
{
    VARS
    INIT
    READ_PARSE("emex_tlv_0004_device_metrics.pcap");

    /* Check datamodel */
    fail_unless(ale->emex.device_metrics.uptime     == 60132);
    fail_unless(ale->emex.device_metrics.cpu_load   == 0);
    fail_unless(ale->emex.device_metrics.cpu_temp   == 53);
    fail_unless(ale->emex.device_metrics.mem_total  == 148500);
    fail_unless(ale->emex.device_metrics.mem_free   == 40304);
    fail_unless(ale->emex.device_metrics.mem_cached == 64612);
    fail_unless(ale->emex.radios.count              == 2);
    fail_unless(!memcmp(ale->emex.radios.info[0].id, (mac_addr){0xf4, 0x17, 0xb8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(ale->emex.radios.info[0].temp       == 45);
    fail_unless(!memcmp(ale->emex.radios.info[1].id, (mac_addr){0xf4, 0x17, 0xb8, 0x86, 0x57, 0x6A}, sizeof(mac_addr)));
    fail_unless(ale->emex.radios.info[1].temp       == 50);

    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_000F_ETH_INTERFACES_TLV                    #
########################################################################*/
START_TEST(test_000F_eth_interfaces_tlv)
{
    VARS
    INIT
    READ_PARSE("emex_tlv_000F_eth_interfaces.pcap");

    map_emex_eth_iface_list_t *list = &ale->emex.eth_iface_list;
    mac_addr mac = {0xa0, 0x2d, 0x13, 0x3b, 0xf1, 0x8f};

    /* Check datamodel */
    fail_unless(list->iface_nr == 3);
    fail_unless(list->ifaces[0].port_id == 0);
    fail_unless(!maccmp(list->ifaces[0].mac, mac));
    fail_unless(!strcmp(list->ifaces[0].name, "eth0"));
    fail_unless(list->ifaces[0].admin_state == 1);
    fail_unless(list->ifaces[0].oper_state == 1);
    fail_unless(list->ifaces[0].full_duplex == 1);
    fail_unless(list->ifaces[0].supported_link_speed == 1000);
    fail_unless(list->ifaces[0].link_speed == 1000);

    fail_unless(list->ifaces[1].port_id == 1);
    fail_unless(!maccmp(list->ifaces[1].mac, mac));
    fail_unless(!strcmp(list->ifaces[1].name, "eth1"));
    fail_unless(list->ifaces[1].admin_state == 1);
    fail_unless(list->ifaces[1].oper_state == 1);
    fail_unless(list->ifaces[1].full_duplex == 0);
    fail_unless(list->ifaces[1].supported_link_speed == 1000);
    fail_unless(list->ifaces[1].link_speed == 10);

    fail_unless(list->ifaces[2].port_id == 2);
    fail_unless(!maccmp(list->ifaces[2].mac, mac));
    fail_unless(!strcmp(list->ifaces[2].name, "eth2"));
    fail_unless(list->ifaces[2].admin_state == 1);
    fail_unless(list->ifaces[2].oper_state == 0);
    fail_unless(list->ifaces[2].full_duplex == 0);
    fail_unless(list->ifaces[2].supported_link_speed == 2500);
    fail_unless(list->ifaces[2].link_speed == 0);

    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_0010_ETH_STATS_V2_TLV                      #
########################################################################*/
START_TEST(test_0010_eth_stats_v2_tlv)
{
    VARS
    INIT

    /* Read first before adding interfaces to make sure nothing goes wrong... */
    READ_PARSE("emex_tlv_0010_eth_stats_v2.pcap");
    READ_PARSE("emex_tlv_000F_eth_interfaces.pcap");
    READ_PARSE("emex_tlv_0010_eth_stats_v2.pcap");

    map_emex_eth_iface_list_t *list = &ale->emex.eth_iface_list;
    fail_unless(list->iface_nr == 3);
    fail_unless(list->supported_stats_mask == 0x3F01);

    /* Interface 1 and 2 have stats, interface 0 has no stats */
    map_emex_eth_stats_t zero_stats = { 0 };
    fail_unless(!memcmp(&list->ifaces[0].stats, &zero_stats, sizeof(map_emex_eth_stats_t)));

    fail_unless(list->ifaces[1].stats.tx_bytes         == 47313920);
    fail_unless(list->ifaces[1].stats.rx_bytes         == 302023680);
    fail_unless(list->ifaces[1].stats.tx_packets       == 149479);
    fail_unless(list->ifaces[1].stats.rx_packets       == 376394);
    fail_unless(list->ifaces[1].stats.tx_errors        == 1);
    fail_unless(list->ifaces[1].stats.rx_errors        == 2);
    fail_unless(list->ifaces[1].stats.tx_bcast_bytes   == 0);
    fail_unless(list->ifaces[1].stats.rx_bcast_bytes   == 0);
    fail_unless(list->ifaces[1].stats.tx_bcast_packets == 150);
    fail_unless(list->ifaces[1].stats.rx_bcast_packets == 14046);
    fail_unless(list->ifaces[1].stats.tx_mcast_bytes   == 3072);
    fail_unless(list->ifaces[1].stats.rx_mcast_bytes   == 4096);
    fail_unless(list->ifaces[1].stats.tx_mcast_packets == 17716);
    fail_unless(list->ifaces[1].stats.rx_mcast_packets == 93497);
    fail_unless(list->ifaces[1].stats.tx_ucast_bytes   == 0);
    fail_unless(list->ifaces[1].stats.rx_ucast_bytes   == 0);
    fail_unless(list->ifaces[1].stats.tx_ucast_packets == 149479 - 150 - 17716);
    fail_unless(list->ifaces[1].stats.rx_ucast_packets == 376394 - 14046 - 93497);

    fail_unless(list->ifaces[2].stats.tx_bytes         == 20496382301481984ULL);
    fail_unless(list->ifaces[2].stats.tx_packets       == 38780996750012ULL);

    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_0011_ETH_NON1905_NB_DEVS_TLV               #
########################################################################*/
START_TEST(test_0011_eth_non1905_nb_devs_tlv)
{
    VARS
    INIT

    /* Read first before adding interfaces to make sure nothing goes wrong... */
    READ_PARSE("emex_tlv_0011_eth_non1905_nb_devs.pcap");
    READ_PARSE("emex_tlv_000F_eth_interfaces.pcap");
    READ_PARSE("emex_tlv_0011_eth_non1905_nb_devs.pcap");

    map_emex_eth_iface_list_t *list = &ale->emex.eth_iface_list;
    fail_unless(list->iface_nr == 3);
    fail_unless(list->ifaces[0].non_i1905_neighbor_macs_nr == 2);
    fail_unless(!memcmp(list->ifaces[0].non_i1905_neighbor_macs[0], (uint8_t []) {0xB0, 0x7B, 0x25, 0x79, 0xD4, 0x85}, 6));
    fail_unless(!memcmp(list->ifaces[0].non_i1905_neighbor_macs[1], (uint8_t []) {0xD0, 0x67, 0xE5, 0x30, 0xFE, 0xCA}, 6));
    fail_unless(list->ifaces[1].non_i1905_neighbor_macs_nr == 1);
    fail_unless(!memcmp(list->ifaces[1].non_i1905_neighbor_macs[0], (uint8_t []) {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, 6));
    fail_unless(list->ifaces[2].non_i1905_neighbor_macs_nr == 0);

    /* Test if macs are removed when receiving topology response without TLV */
    i1905_cmdu_t cmdu2 = {.message_type = CMDU_TYPE_TOPOLOGY_RESPONSE};
    map_emex_handle_cmdu_pre(ale, &cmdu2);
    map_emex_handle_cmdu_post(ale, &cmdu2);

    fail_unless(list->ifaces[0].non_i1905_neighbor_macs_nr == 0);
    fail_unless(list->ifaces[1].non_i1905_neighbor_macs_nr == 0);
    fail_unless(list->ifaces[2].non_i1905_neighbor_macs_nr == 0);

    /* Reload to test cleanup */
    READ_PARSE("emex_tlv_0011_eth_non1905_nb_devs.pcap");
    fail_unless(list->ifaces[0].non_i1905_neighbor_macs_nr == 2);

    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_0012_ETH_1905_NB_DEVS_TLV                  #
########################################################################*/
START_TEST(test_0012_eth_1905_nb_devs_tlv)
{
    VARS
    INIT

    /* Read first before adding interfaces to make sure nothing goes wrong... */
    READ_PARSE("emex_tlv_0012_eth_1905_nb_devs.pcap");
    READ_PARSE("emex_tlv_000F_eth_interfaces.pcap");
    READ_PARSE("emex_tlv_0012_eth_1905_nb_devs.pcap");

    map_emex_eth_iface_list_t *list = &ale->emex.eth_iface_list;
    fail_unless(list->iface_nr == 3);
    fail_unless(list->ifaces[0].i1905_neighbor_macs_nr == 0);
    fail_unless(list->ifaces[1].i1905_neighbor_macs_nr == 1);
    fail_unless(!memcmp(list->ifaces[1].i1905_neighbor_macs[0], (uint8_t []) {0xA2, 0xB5, 0x3C, 0x3F, 0xC7, 0x71}, 6));
    fail_unless(list->ifaces[2].i1905_neighbor_macs_nr == 2);
    fail_unless(!memcmp(list->ifaces[2].i1905_neighbor_macs[0], (uint8_t []) {0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF}, 6));
    fail_unless(!memcmp(list->ifaces[2].i1905_neighbor_macs[1], (uint8_t []) {0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF}, 6));

    /* Test if macs are removed when receiving topology response without TLV */
    i1905_cmdu_t cmdu2 = {.message_type = CMDU_TYPE_TOPOLOGY_RESPONSE};
    map_emex_handle_cmdu_pre(ale, &cmdu2);
    map_emex_handle_cmdu_post(ale, &cmdu2);

    fail_unless(list->ifaces[0].i1905_neighbor_macs_nr == 0);
    fail_unless(list->ifaces[1].i1905_neighbor_macs_nr == 0);
    fail_unless(list->ifaces[2].i1905_neighbor_macs_nr == 0);

    /* Reload to test cleanup */
    READ_PARSE("emex_tlv_0012_eth_1905_nb_devs.pcap");
    fail_unless(list->ifaces[2].i1905_neighbor_macs_nr == 2);

    CLEANUP
}
END_TEST

const char *test_suite_name = "emex";
test_case_t test_cases[] = {
    TEST("0002_feature_profile_tlv",           test_0002_feature_profile_tlv  ),
    TEST("0003_device_info_tlv",               test_0003_device_info_tlv  ),
    TEST("0004_device_metrics_tlv",            test_0004_device_metrics_tlv  ),
    TEST("000F_eth_interfaces_tlv",            test_000F_eth_interfaces_tlv  ),
    TEST("0010_eth_stats_v2_tlv",              test_0010_eth_stats_v2_tlv  ),
    TEST("0011_eth_non1905_nb_devs_tlv",       test_0011_eth_non1905_nb_devs_tlv  ),
    TEST("0012_eth_1905_nb_devs_tlv",          test_0012_eth_1905_nb_devs_tlv  ),
    TEST_CASES_END
};
