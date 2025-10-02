/*
 * Copyright (c) 2020-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <linux/limits.h>


#include "test.h"

#include "map_ctrl_cmdu_rx.h"

#include "1905_cmdus.h"
#include "1905_tlvs.h"
#include "map_tlvs.h"
#include "map_data_model.h"
#include "map_data_model_dumper.h"
#include "map_topology_tree.h"
#include "map_staging_list.h"
#include "map_blocklist.h"
#include "map_ctrl_onboarding_handler.h"
#include "map_ctrl_cmdu_handler.h"
#include "map_ctrl_utils.h"
#include "map_ctrl_sta.h"
#include "map_ctrl_emex_tlv_handler.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define MAX_FRAGMENTS   26

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static mac_addr g_ctrl_al_mac =  {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};

/* All frames are captured from the same device
 * Frames that captured later are manipulated to have same mac address as much as possible
*/
static char     *g_src_if_name          = "eth0";
static mac_addr  g_al_mac               = {0xF6, 0x17, 0xB8, 0x86, 0x57, 0x68};
static mac_addr  g_src_mac              = {0xF4, 0x17, 0xB8, 0x86, 0x57, 0x68};
static mac_addr  g_eth_mac              = {0xF4, 0x17, 0xB8, 0x86, 0x57, 0x68};

static mac_addr  g_radio_id_2G          = {0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6B};
static mac_addr  g_radio_id_5G          = {0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6A};
static mac_addr  g_radio_id_6G          = {0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6C};

static mac_addr  g_bssid_2G_fh          = {0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6B};
static mac_addr  g_bssid_5G_fh          = {0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6A};
static mac_addr  g_bssid_5G_bh          = {0x6A, 0x17, 0xB8, 0x86, 0x57, 0x6B};
static mac_addr  g_bssid_6G_fh          = {0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6C};
static mac_addr  g_bssid_6G_bh          = {0x6A, 0x17, 0xB8, 0x86, 0x57, 0x6D};

static mac_addr  g_slave_al_mac         = {0xCE, 0xAA, 0xCC, 0xAA, 0x00, 0x00};
//static mac_addr  g_slave_src_mac        = {0xCE, 0xAA, 0xCC, 0xAA, 0x00, 0x00};
static mac_addr  g_slave_eth_mac        = {0xCC, 0xAA, 0xCC, 0xAA, 0x00, 0x00};

static mac_addr  g_slave_radio_id_2G    = {0xCC, 0xAA, 0xCC, 0xAA, 0x00, 0x03};
static mac_addr  g_slave_radio_id_5G    = {0xCC, 0xAA, 0xCC, 0xAA, 0x00, 0x04};
static mac_addr  g_slave_radio_id_6G    = {0x16, 0xAA, 0xCC, 0xAA, 0x00, 0x05};

static mac_addr  g_slave_bssid_2G_fh    = {0xCC, 0xAA, 0xCC, 0xAA, 0x00, 0x03};
static mac_addr  g_slave_bssid_5G_fh    = {0x82, 0xAA, 0xCC, 0xAA, 0x00, 0x05};
static mac_addr  g_slave_bssid_5G_bh    = {0x82, 0xAA, 0xCC, 0xAA, 0x00, 0x06};
static mac_addr  g_slave_bssid_6G_fh    = {0x16, 0xAA, 0xCC, 0xAA, 0x00, 0x06};
static mac_addr  g_slave_bssid_6G_bh    = {0x16, 0xAA, 0xCC, 0xAA, 0x00, 0x07};

static mac_addr  g_5g_bh_sta_mac        = {0xCC, 0xAA, 0xCC, 0xAA, 0x00, 0x04};
static mac_addr  g_6g_bh_sta_mac        = {0x16, 0xAA, 0xCC, 0xAA, 0x00, 0x05};

static mac_addr  g_bh_sta_mac           = {0xF4, 0x17, 0xB8, 0xAE, 0x86, 0xF1};
static mac_addr  g_S10_mac              = {0xA8, 0xDB, 0x03, 0x05, 0x92, 0x1C};

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
static void dummy_printf(const char *fmt, ...)
{
}


static void test_init(void)
{
    map_cfg_get()->is_master = true;

    fail_unless(!map_info_init());
    fail_unless(!map_dm_init());
    fail_unless(init_topology_tree(g_ctrl_al_mac));
    fail_unless(!map_stglist_init());
    fail_unless(!map_blocklist_init());
    fail_unless(!map_emex_init());
    fail_unless(!map_ctrl_sta_init());
}

static void test_fini(void)
{
    /* For code coverage... */
    map_dm_dump_agent_info_tree(dummy_printf);

    map_ctrl_sta_fini();
    map_emex_fini();
    map_blocklist_fini();
    map_stglist_fini();
    map_dm_fini();
    map_info_fini();
}

static i1905_cmdu_t *parse_cmdu(packet_t **p, size_t packets_nr)
{
    uint8_t *streams[MAX_FRAGMENTS + 1];
    uint16_t lengths[MAX_FRAGMENTS + 1];
    uint16_t length;
    i1905_cmdu_t *c;
    size_t i;

    for (i = 0; i <= packets_nr ; i++) {
        streams[i] = NULL;
        lengths[i] = 0;
    }

    fail_unless(packets_nr < MAX_FRAGMENTS);

    for (i = 0; i < packets_nr; i++) {
        length = p[i]->len - sizeof(eth_hdr_t); /* Remove eth header */
        streams[i] = (uint8_t *)malloc((sizeof(uint8_t) * length));
        memcpy(streams[i], p[i]->data + sizeof(eth_hdr_t), length);
        lengths[i] = length;
    }

    c = parse_1905_CMDU_from_packets(streams, lengths);

    for (i = 0; i < packets_nr; i++) {
        free(streams[i]);
    }

    return c;
}

/* TODO:
   - pcap with more than one CMDU
*/
static void read_parse(const char *file, mac_addr src_mac)
{
    packet_t    **packets;
    size_t        packets_nr;
    i1905_cmdu_t *cmdu;
    char          file_path[PATH_MAX];

    snprintf(file_path, sizeof(file_path), DATA_DIR"/%s", file);

    fail_unless(!!(packets = pcap_read_all_packets(file_path, &packets_nr)));
    fail_unless(!!(cmdu = parse_cmdu(packets, packets_nr)));

    strcpy(cmdu->interface_name, g_src_if_name);
    maccpy(cmdu->cmdu_stream.src_mac_addr, src_mac);

    fail_unless(!!map_cmdu_rx_cb(cmdu));

    /* Test has stubbed i1905_cmdu_cleanup */
    free_1905_CMDU_structure(cmdu);
    free_packets(packets, packets_nr);
}
/*#######################################################################
#                       TEST_TOPOLOGY_DISCOVERY                         #
########################################################################*/
START_TEST(test_topology_discovery)
{
    map_1905_dev_info_t *dev;
    map_ale_info_t      *ale;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);

    fail_unless(!!(dev = map_stglist_get_1905_dev(g_al_mac)));
    fail_unless(!!(dev = map_stglist_get_1905_dev_from_src_mac(g_al_mac)));
    fail_unless(!!(ale = map_handle_new_agent_onboarding(g_al_mac, g_src_if_name, true)));
    fail_unless(!map_handle_topology_discovery_ale(ale, g_src_if_name, g_al_mac, map_stglist_get_1905_dev_mac_tlv_mac(dev)));
    fail_unless(!map_stglist_remove_1905_dev(dev));

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));
    fail_unless(!maccmp(ale->src_mac, g_al_mac));
    fail_unless(!maccmp(ale->upstream_local_iface_mac, g_src_mac));
    fail_unless(!strcmp(ale->iface_name, g_src_if_name));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_TOPOLOGY_QUERY                             #
########################################################################*/
START_TEST(test_topology_query)
{
    test_init();

    read_parse("cmdu_topology_query.pcap", g_al_mac);

    /* Cannot validate anything yet */

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_TOPOLOGY_RESPONSE                          #
########################################################################*/
START_TEST(test_topology_response)
{
    map_ale_info_t   *ale;
    map_radio_info_t *radio;
    map_bss_info_t   *bss;
    map_sta_info_t   *sta;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));
    fail_unless(!maccmp(ale->src_mac, g_al_mac));
    fail_unless(!maccmp(ale->upstream_local_iface_mac, g_src_mac));
    fail_unless(!strcmp(ale->iface_name, g_src_if_name));
    fail_unless(ale->easymesh == true);
    fail_unless(ale->map_profile == MAP_PROFILE_2);

    fail_unless(ale->radios_nr == 2);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
    fail_unless(radio->bsss_nr            == 1);

    fail_unless(!!(bss = map_dm_get_bss(radio, g_bssid_2G_fh)) && bss->radio == radio);
    fail_unless(bss->radio == radio);

    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_5G)));
    fail_unless(radio->bsss_nr            == 2);

    fail_unless((bss = map_dm_get_bss(radio, g_bssid_5G_fh)) && bss->radio == radio);
    fail_unless((sta = map_dm_get_sta(bss, g_S10_mac)) && sta->bss == bss);

    fail_unless((bss = map_dm_get_bss(radio, g_bssid_5G_bh)) && bss->radio == radio);
    fail_unless((sta = map_dm_get_sta(bss, g_bh_sta_mac)) && sta->bss == bss);

    /* Local interface and non 1905 neighbors */
    fail_unless(ale->local_iface_count == 4);
    fail_unless(!maccmp(ale->local_iface_list[0].mac_address, g_bssid_5G_fh));
    fail_unless(ale->local_iface_list[0].media_type == INTERFACE_TYPE_IEEE_802_11AC_5_GHZ);
    fail_unless(!maccmp(ale->local_iface_list[3].mac_address, g_eth_mac));
    fail_unless(ale->local_iface_list[3].media_type == INTERFACE_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET);

    fail_unless(ale->non_1905_neighbor_count == 2);
    fail_unless(!maccmp(ale->non_1905_neighbor_list[0].local_iface_mac, g_bssid_5G_fh));
    fail_unless(ale->non_1905_neighbor_list[0].media_type == INTERFACE_TYPE_IEEE_802_11AC_5_GHZ);
    fail_unless(ale->non_1905_neighbor_list[0].macs_nr == 2);
    fail_unless(!memcmp(ale->non_1905_neighbor_list[0].macs[0], (mac_addr){0x4E, 0x8F, 0x3B, 0x88, 0xF5, 0x57}, sizeof(mac_addr)));
    fail_unless(!maccmp(ale->non_1905_neighbor_list[0].macs[1], g_S10_mac));

    fail_unless(!maccmp(ale->non_1905_neighbor_list[1].local_iface_mac, g_eth_mac));
    fail_unless(ale->non_1905_neighbor_list[1].media_type == INTERFACE_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET);
    fail_unless(ale->non_1905_neighbor_list[1].macs_nr == 2);
    /* List is sorted */
    fail_unless(!memcmp(ale->non_1905_neighbor_list[1].macs[0], (mac_addr){0xC8, 0xF7, 0x50, 0x4C, 0x29, 0x95}, sizeof(mac_addr)));
    fail_unless(!memcmp(ale->non_1905_neighbor_list[1].macs[1], (mac_addr){0xD0, 0x67, 0xE5, 0x30, 0xFE, 0xCA}, sizeof(mac_addr)));

    /* Channel learning from "device information tlv" requires band to be known
       -> read ap cap report and again topology response
    */
    read_parse("cmdu_ap_capability_report.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);

    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
    fail_unless(radio->current_op_class   == 81);
    fail_unless(radio->current_op_channel == 6);
    fail_unless(radio->current_bw         == 20);

    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_5G)));
    fail_unless(radio->bsss_nr            == 2);
    fail_unless(radio->current_op_class   == 128);
    fail_unless(radio->current_op_channel == 157);
    fail_unless(radio->current_bw         == 80);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_LEGACY_TOPOLOGY_RESPONSE                   #
########################################################################*/
START_TEST(test_legacy_topology_response)
{
    map_ale_info_t   *ale;

    test_init();

    read_parse("cmdu_legacy_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_legacy_topology_response.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));
    fail_unless(!maccmp(ale->src_mac, g_al_mac));
    fail_unless(!maccmp(ale->upstream_local_iface_mac, g_src_mac));
    fail_unless(!strcmp(ale->iface_name, g_src_if_name));
    fail_unless(ale->easymesh == false);

    fail_unless(ale->radios_nr == 0);

    test_fini();
}
END_TEST

/*#######################################################################
#                    TEST_TRIBAND_TOPOLOGY_RESPONSE                     #
########################################################################*/
START_TEST(test_triband_topology_response)
{
    map_ale_info_t   *ale;
    map_radio_info_t *radio;
    map_bss_info_t   *bss;
    map_sta_info_t   *sta;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_triband_topology_response.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));
    fail_unless(!maccmp(ale->src_mac, g_al_mac));
    fail_unless(!maccmp(ale->upstream_local_iface_mac, g_src_mac));
    fail_unless(!strcmp(ale->iface_name, g_src_if_name));
    fail_unless(ale->easymesh == true);
    fail_unless(ale->map_profile == MAP_PROFILE_2);

    fail_unless(ale->radios_nr == 3);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
    fail_unless(radio->bsss_nr            == 1);

    fail_unless(!!(bss = map_dm_get_bss(radio, g_bssid_2G_fh)) && bss->radio == radio);
    fail_unless(bss->radio == radio);

    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_5G)));
    fail_unless(radio->bsss_nr            == 1);

    fail_unless((bss = map_dm_get_bss(radio, g_bssid_5G_fh)) && bss->radio == radio);
    fail_unless((sta = map_dm_get_sta(bss, g_S10_mac)) && sta->bss == bss);

    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_6G)));
    fail_unless(radio->bsss_nr            == 2);

    fail_unless(!!(bss = map_dm_get_bss(radio, g_bssid_6G_fh)) && bss->radio == radio);
    fail_unless(bss->radio == radio);

    fail_unless(!!(bss = map_dm_get_bss(radio, g_bssid_6G_bh)) && bss->radio == radio);
    fail_unless(bss->radio == radio);

    /* Local interface and non 1905 neighbors */
    fail_unless(ale->local_iface_count == 5);
    fail_unless(!maccmp(ale->local_iface_list[0].mac_address, g_bssid_2G_fh));
    fail_unless(ale->local_iface_list[0].media_type == INTERFACE_TYPE_IEEE_802_11AX);
    fail_unless(!maccmp(ale->local_iface_list[1].mac_address, g_eth_mac));
    fail_unless(ale->local_iface_list[1].media_type == INTERFACE_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET);
    fail_unless(!maccmp(ale->local_iface_list[3].mac_address, g_bssid_6G_fh));
    fail_unless(ale->local_iface_list[3].media_type == INTERFACE_TYPE_IEEE_802_11AX);

    fail_unless(ale->non_1905_neighbor_count == 2);

    fail_unless(!maccmp(ale->non_1905_neighbor_list[0].local_iface_mac, g_eth_mac));
    fail_unless(ale->non_1905_neighbor_list[0].media_type == INTERFACE_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET);
    fail_unless(ale->non_1905_neighbor_list[0].macs_nr == 1);
    fail_unless(!memcmp(ale->non_1905_neighbor_list[0].macs[0], (mac_addr){0x4E, 0x8F, 0x3B, 0x88, 0xF5, 0x57}, sizeof(mac_addr)));

    fail_unless(!maccmp(ale->non_1905_neighbor_list[1].local_iface_mac, g_bssid_5G_fh));
    fail_unless(ale->non_1905_neighbor_list[1].media_type == INTERFACE_TYPE_IEEE_802_11AX);
    fail_unless(ale->non_1905_neighbor_list[1].macs_nr == 1);
    fail_unless(!maccmp(ale->non_1905_neighbor_list[1].macs[0], g_S10_mac));

    /* Channel learning from "device information tlv" requires band to be known
       -> read ap cap report and again topology response
    */
    read_parse("cmdu_triband_ap_capability_report.pcap", g_al_mac);
    read_parse("cmdu_triband_topology_response.pcap", g_al_mac);

    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
    fail_unless(radio->current_op_class   == 81);
    fail_unless(radio->current_op_channel == 12);
    fail_unless(radio->current_bw         == 20);

    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_5G)));
    fail_unless(radio->current_op_class   == 129);
    fail_unless(radio->current_op_channel == 100);
    fail_unless(radio->current_bw         == 160);

    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_6G)));
    fail_unless(radio->current_op_class   == 134);
    fail_unless(radio->current_op_channel == 165);
    fail_unless(radio->current_bw         == 160);

    test_fini();
}
END_TEST

/*#######################################################################
#             TEST_MULTIPLE_BACKHAUL_TOPOLOGY_RESPONSE                  #
########################################################################*/
START_TEST(test_multiple_backhaul_topology_response)
{
    map_ale_info_t   *ale;
    map_ale_info_t   *slave_ale;
    map_radio_info_t *radio;
    map_bss_info_t   *bss;
    map_sta_info_t   *sta;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_multiple_backhaul_topology_response_master.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));
    fail_unless(!maccmp(ale->src_mac, g_al_mac));
    fail_unless(!maccmp(ale->upstream_local_iface_mac, g_src_mac));

    fail_unless(ale->radios_nr == 3);

    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
    fail_unless(radio->bsss_nr            == 1);

    fail_unless(!!(bss = map_dm_get_bss(radio, g_bssid_2G_fh)) && bss->radio == radio);
    fail_unless(bss->radio == radio);

    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_5G)));
    fail_unless(radio->bsss_nr            == 2);

    fail_unless((bss = map_dm_get_bss(radio, g_bssid_5G_fh)) && bss->radio == radio);
    fail_unless(bss->radio == radio);

    fail_unless((bss = map_dm_get_bss(radio, g_bssid_5G_bh)) && bss->radio == radio);
    fail_unless(bss->radio == radio);

    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_6G)));
    fail_unless(radio->bsss_nr            == 2);

    fail_unless(!!(bss = map_dm_get_bss(radio, g_bssid_6G_fh)) && bss->radio == radio);
    fail_unless(bss->radio == radio);

    fail_unless(!!(bss = map_dm_get_bss(radio, g_bssid_6G_bh)) && bss->radio == radio);
    fail_unless(bss->radio == radio);
    fail_unless((sta = map_dm_get_sta(bss, g_6g_bh_sta_mac)) && sta->bss == bss);

    /* Local interfaces */
    fail_unless(ale->local_iface_count == 6);

    fail_unless(ale->local_iface_list[1].media_type == INTERFACE_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET);
    fail_unless(!maccmp(ale->local_iface_list[3].mac_address, g_bssid_6G_bh));
    fail_unless(ale->local_iface_list[3].media_type == INTERFACE_TYPE_IEEE_802_11AX);
    fail_unless(ale->local_iface_list[3].ieee80211_role == IEEE80211_SPECIFIC_INFO_ROLE_AP);

    fail_unless(!maccmp(ale->local_iface_list[5].mac_address, g_bssid_5G_bh));
    fail_unless(ale->local_iface_list[5].media_type == INTERFACE_TYPE_IEEE_802_11AX);
    fail_unless(ale->local_iface_list[5].ieee80211_role == IEEE80211_SPECIFIC_INFO_ROLE_AP);

    /* Onboard slave node */
    read_parse("cmdu_topology_discovery_slave.pcap", g_slave_al_mac);
    read_parse("cmdu_multiple_backhaul_topology_response_slave.pcap", g_slave_al_mac);

    fail_unless(!!(slave_ale = map_dm_get_ale(g_slave_al_mac)));
    fail_unless(!maccmp(slave_ale->src_mac, g_slave_al_mac));
    fail_unless(!maccmp(slave_ale->upstream_local_iface_mac, g_6g_bh_sta_mac));

    fail_unless(slave_ale->radios_nr == 3);

    fail_unless(!!(radio = map_dm_get_radio(slave_ale, g_slave_radio_id_2G)));
    fail_unless(radio->bsss_nr            == 1);

    fail_unless(!!(bss = map_dm_get_bss(radio, g_slave_bssid_2G_fh)) && bss->radio == radio);
    fail_unless(bss->radio == radio);

    fail_unless(!!(radio = map_dm_get_radio(slave_ale, g_slave_radio_id_5G)));
    fail_unless(radio->bsss_nr            == 2);

    fail_unless((bss = map_dm_get_bss(radio, g_slave_bssid_5G_fh)) && bss->radio == radio);
    fail_unless(bss->radio == radio);

    fail_unless((bss = map_dm_get_bss(radio, g_slave_bssid_5G_bh)) && bss->radio == radio);
    fail_unless(bss->radio == radio);

    fail_unless(!!(radio = map_dm_get_radio(slave_ale, g_slave_radio_id_6G)));
    fail_unless(radio->bsss_nr            == 2);

    fail_unless(!!(bss = map_dm_get_bss(radio, g_slave_bssid_6G_fh)) && bss->radio == radio);
    fail_unless(bss->radio == radio);

    fail_unless(!!(bss = map_dm_get_bss(radio, g_slave_bssid_6G_bh)) && bss->radio == radio);
    fail_unless(bss->radio == radio);

    /* Local interfaces */
    fail_unless(slave_ale->local_iface_count == 8);
    fail_unless(!maccmp(slave_ale->local_iface_list[1].mac_address, g_slave_eth_mac));
    fail_unless(slave_ale->local_iface_list[1].media_type == INTERFACE_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET);

    fail_unless(!maccmp(slave_ale->local_iface_list[2].mac_address, g_6g_bh_sta_mac));
    fail_unless(!maccmp(slave_ale->local_iface_list[2].ieee80211_network_membership, g_bssid_6G_bh));
    fail_unless(slave_ale->local_iface_list[2].media_type == INTERFACE_TYPE_IEEE_802_11AX);
    fail_unless(slave_ale->local_iface_list[2].ieee80211_role == IEEE80211_SPECIFIC_INFO_ROLE_NON_AP_NON_PCP_STA);

    fail_unless(!maccmp(slave_ale->local_iface_list[5].mac_address, g_5g_bh_sta_mac));
    fail_unless(!maccmp(slave_ale->local_iface_list[5].ieee80211_network_membership, g_zero_mac));
    fail_unless(slave_ale->local_iface_list[5].media_type == INTERFACE_TYPE_IEEE_802_11AX);
    fail_unless(slave_ale->local_iface_list[5].ieee80211_role == IEEE80211_SPECIFIC_INFO_ROLE_NON_AP_NON_PCP_STA);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_MLO_TOPOLOGY_RESPONSE                      #
########################################################################*/
START_TEST(test_mlo_topology_response)
{
    map_ale_info_t     *ale;
    map_ap_mld_info_t  *ap_mld;
    map_sta_mld_info_t *sta_mld;
    map_radio_info_t   *radio;
    map_bss_info_t     *bss;
    map_sta_info_t     *sta;
    int                 count = 0;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_mlo_topology_response.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));
    fail_unless(!maccmp(ale->src_mac, g_al_mac));

    /* Check AP MLD */
    fail_unless(ale->ap_mld_nr == 2);
    fail_unless(!!(ap_mld = map_dm_get_ap_mld(ale, (mac_addr){0x00, 0x90, 0x4C, 0x4C, 0x84, 0x7A})));
    fail_unless(ap_mld->ssid_len == 11);
    fail_unless(!memcmp(ap_mld->ssid, (char*)"frv_test_fh", 11));

    map_dm_foreach_aff_ap(ap_mld, bss) {
        if (count == 0) {
            fail_unless(bss->ap_mld == ap_mld);
            fail_unless(!memcmp(bss->bssid, (mac_addr){0x00, 0x90, 0x4C, 0x4C, 0x94, 0x1F}, sizeof(mac_addr)));
            fail_unless(bss->link_id == 1);
        }
        count++;
    }
    fail_unless(count == 3);

    /* Check STA MLD */
    fail_unless(ap_mld->sta_mld_nr == 1);
    fail_unless(!!(sta_mld = map_dm_get_sta_mld(ap_mld, (mac_addr){0xE4, 0x60, 0x17, 0x5E, 0x34, 0x4F})));
    fail_unless(sta_mld == map_dm_get_sta_mld_from_ale(ale, (mac_addr){0xE4, 0x60, 0x17, 0x5E, 0x34, 0x4F}));

    count = 0;
    map_dm_foreach_aff_sta(sta_mld, sta) {
        if (count == 0) {
            fail_unless(sta->sta_mld == sta_mld);
            fail_unless(!memcmp(sta->mac, (mac_addr){0xFA, 0x43, 0xD1, 0x0F, 0x33, 0xD6}, sizeof(mac_addr)));
            fail_unless(!memcmp(sta->bss->bssid, (mac_addr){0x00, 0x90, 0x4C, 0x4D, 0x41, 0xF5}, sizeof(mac_addr)));
            fail_unless(sta == map_dm_get_sta_from_ale(ale, (mac_addr){0xFA, 0x43, 0xD1, 0x0F, 0x33, 0xD6}));
        }
        count++;
    }
    fail_unless(count == 2);

    /* Check normal STA (there should be 4 in total) */
    fail_unless(!!map_dm_get_sta_from_ale(ale, (mac_addr){0x70, 0xD8, 0x23, 0xD2, 0xE3, 0x62}));
    count = 0;
    map_dm_foreach_radio(ale, radio) {
        map_dm_foreach_bss(radio, bss) {
            map_dm_foreach_sta(bss, sta) {
                count++;
            }
        }
    }
    fail_unless(count == 4);

    /* Remove all MLD */
    read_parse("cmdu_topology_response.pcap", g_al_mac);
    fail_unless(ale->ap_mld_nr == 0);

    /* Add again to test cleanup */
    read_parse("cmdu_mlo_topology_response.pcap", g_al_mac);
    fail_unless(ale->ap_mld_nr == 2);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_TOPOLOGY_NOTIFICATION                      #
########################################################################*/
START_TEST(test_topology_notification)
{
    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);

    /* Sta is connected at this moment */
    fail_unless(!!map_dm_get_sta_gbl(g_S10_mac));

    read_parse("cmdu_topology_notification_disassoc.pcap", g_al_mac);
    fail_unless(!map_dm_get_sta_gbl(g_S10_mac));

    read_parse("cmdu_topology_notification_assoc.pcap", g_al_mac);
    fail_unless(!!map_dm_get_sta_gbl(g_S10_mac));

    test_fini();
}
END_TEST

/*#######################################################################
#              TEST_TOPOLOGY_NOTIFICATION_BACKHAUL_SWITCH               #
########################################################################*/
START_TEST(topology_notification_backhaul_switch)
{
    map_ale_info_t              *master_ale;
    map_ale_info_t              *slave_ale;
    map_radio_info_t            *master_radio_5g, *master_radio_6g, *slave_radio_5g, *slave_radio_6g;
    map_backhaul_sta_iface_t    *bhsta_iface_5g, *bhsta_iface_6g;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_multiple_backhaul_topology_response_master.pcap", g_al_mac);
    read_parse("cmdu_topology_discovery_slave.pcap", g_slave_al_mac);
    read_parse("cmdu_multiple_backhaul_topology_response_slave.pcap", g_slave_al_mac);
    read_parse("cmdu_backhaul_sta_capability_report_slave.pcap", g_slave_al_mac);

    fail_unless(!!(master_ale = map_dm_get_ale(g_al_mac)));
    fail_unless(!!(slave_ale = map_dm_get_ale(g_slave_al_mac)));

    fail_unless(!!(master_radio_5g = map_dm_get_radio(master_ale, g_radio_id_5G)));
    fail_unless(!!(master_radio_6g = map_dm_get_radio(master_ale, g_radio_id_6G)));

    fail_unless(!!(slave_radio_5g = map_dm_get_radio(slave_ale, g_slave_radio_id_5G)));
    fail_unless(!!(slave_radio_6g = map_dm_get_radio(slave_ale, g_slave_radio_id_6G)));

    fail_unless(!!(bhsta_iface_5g = map_find_bhsta_iface_from_ale(slave_ale, g_5g_bh_sta_mac)));
    fail_unless(!!(bhsta_iface_6g = map_find_bhsta_iface_from_ale(slave_ale, g_6g_bh_sta_mac)));

    /* 6G Backhaul connection */
    fail_unless(master_radio_5g->channel_configurable == true);
    fail_unless(master_radio_5g->channel_configurable == true);
    fail_unless(slave_radio_5g->channel_configurable == true);
    fail_unless(slave_radio_6g->channel_configurable == false);

    read_parse("cmdu_topology_notification_bhsta_disassoc_6G.pcap", g_al_mac);
    read_parse("cmdu_topology_notification_bhsta_assoc_5G.pcap", g_al_mac);

    /* 5G Backhaul connection */
    fail_unless(master_radio_5g->channel_configurable == true);
    fail_unless(master_radio_5g->channel_configurable == true);
    fail_unless(slave_radio_5g->channel_configurable == false);
    fail_unless(slave_radio_6g->channel_configurable == true);

    read_parse("cmdu_topology_notification_bhsta_disassoc_5G.pcap", g_al_mac);

    /* Ethernet Backhaul connection */
    fail_unless(master_radio_5g->channel_configurable == true);
    fail_unless(master_radio_5g->channel_configurable == true);
    fail_unless(slave_radio_5g->channel_configurable == true);
    fail_unless(slave_radio_6g->channel_configurable == true);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_LINK_METRIC_QUERY                          #
########################################################################*/
START_TEST(test_link_metric_query)
{
    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);
    read_parse("cmdu_link_metric_query.pcap", g_al_mac);

    /* Nothing to test */

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_LINK_METRIC_RESPONSE                       #
########################################################################*/
START_TEST(test_link_metric_response)
{
    map_ale_info_t *ale;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);

    /* Add other ale, otherwise "links" will not be stored */
    fail_unless(!!map_dm_create_ale((mac_addr){0xF6, 0x17, 0xB8, 0xAE, 0x86, 0xEF}));
    fail_unless(!!map_dm_create_ale((mac_addr){0xF6, 0x17, 0xB8, 0xBD, 0xBA, 0xBC}));

    read_parse("cmdu_link_metric_response.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));
#if 0
    fail_unless(ale->neighbor_link_count == 2);
    fail_unless(!memcmp(ale->neighbor_link_list[0].neighbor_al_mac,    (mac_addr){0xF6, 0x17, 0xB8, 0xAE, 0x86, 0xEF}, sizeof(mac_addr)));
    fail_unless(!memcmp(ale->neighbor_link_list[0].local_iface_mac,    (mac_addr){0x6A, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(!memcmp(ale->neighbor_link_list[0].neighbor_iface_mac, (mac_addr){0xF4, 0x17, 0xB8, 0xAE, 0x86, 0xF1}, sizeof(mac_addr)));
    fail_unless(!memcmp(ale->neighbor_link_list[1].neighbor_al_mac,    (mac_addr){0xF6, 0x17, 0xB8, 0xBD, 0xBA, 0xBC}, sizeof(mac_addr)));
#else
    fail_unless(ale->neighbor_link_count == 0);
#endif

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_AUTOCONFIG_SEARCH_1                        #
########################################################################*/
/* Autoconfig search after topology response */
START_TEST(test_autoconfig_search_1)
{
    map_ale_info_t *ale;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);
    read_parse("cmdu_ap_autoconfiguration_search.pcap", g_al_mac);

    /* Nothing extra happened */
    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));
    fail_unless(ale->easymesh == true);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_AUTOCONFIG_SEARCH_2                        #
########################################################################*/
/* Autoconfig search as first onboarding message -> ale created */
START_TEST(test_autoconfig_search_2)
{
    map_ale_info_t *ale;

    test_init();

    read_parse("cmdu_ap_autoconfiguration_search.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));
    fail_unless(ale->map_profile == MAP_PROFILE_2);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_LEGACY_AUTOCONFIG_SEARCH_1                 #
########################################################################*/
/* Autoconfig search after topology response */
START_TEST(test_legacy_autoconfig_search_1)
{
    map_ale_info_t *ale;

    test_init();

    read_parse("cmdu_legacy_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_legacy_topology_response.pcap", g_al_mac);
    read_parse("cmdu_legacy_ap_autoconfiguration_search.pcap", g_al_mac);

    /* Nothing extra happened */
    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));
    fail_unless(ale->easymesh == false);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_LEGACY_AUTOCONFIG_SEARCH_2                 #
########################################################################*/
/* Autoconfig search as first onboarding message -> ale not created */
START_TEST(test_legacy_autoconfig_search_2)
{
    test_init();

    read_parse("cmdu_legacy_ap_autoconfiguration_search.pcap", g_al_mac);

    /* No ale created but added to staging list */
    fail_unless(!map_dm_get_ale(g_al_mac));
    fail_unless(!!map_stglist_get_1905_dev(g_al_mac));
    fail_unless(!!map_stglist_get_1905_dev_from_src_mac(g_al_mac));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_AUTOCONFIG_WSC_1                           #
########################################################################*/
/* Autoconfig WSC after topology response */
START_TEST(test_autoconfig_wsc_1)
{
    map_ale_info_t   *ale;
    map_radio_info_t *radio;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));

    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
    fail_unless(radio->max_bss == 0);
    fail_unless(radio->cap_op_class_list.op_classes_nr == 0);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_5G)));
    fail_unless(radio->max_bss == 0);
    fail_unless(radio->cap_op_class_list.op_classes_nr == 0);

    read_parse("cmdu_ap_autoconfiguration_wsc_2G.pcap", g_al_mac);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
    fail_unless(radio->max_bss == 15);
    fail_unless(radio->cap_op_class_list.op_classes_nr == 3);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_5G)));
    fail_unless(radio->max_bss == 0);
    fail_unless(radio->cap_op_class_list.op_classes_nr == 0);

    read_parse("cmdu_ap_autoconfiguration_wsc_5G.pcap", g_al_mac);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
    fail_unless(radio->max_bss == 15);
    fail_unless(radio->cap_op_class_list.op_classes_nr == 3);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_5G)));
    fail_unless(radio->max_bss == 15);
    fail_unless(radio->cap_op_class_list.op_classes_nr == 15);

    /* Profile 2 AP cap */
    fail_unless(ale->agent_capability.profile_2_ap_cap_valid == true);
    fail_unless(ale->agent_capability.max_vid_count          == 2);
    fail_unless(ale->agent_capability.byte_counter_unit      == MAP_BYTE_COUNTER_UNIT_KIBI_BYTES);

    /* M1 attributes */
    fail_unless(!strcmp(ale->device_info.manufacturer_name, "AirTies Wireless Networks"));
    fail_unless(!strcmp(ale->device_info.model_name,        "Air4960"));
    fail_unless(!strcmp(ale->device_info.model_number,      "4960"));
    fail_unless(!strcmp(ale->device_info.serial_number,     "AW2631942000028"));
    fail_unless(ale->device_info.os_version == 0xFFFEFDFC);
    fail_unless(!strcmp(ale->device_info.os_version_str,    "127.254.253.252"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_AUTOCONFIG_WSC_2                           #
########################################################################*/
/* Autoconfig WSC as first onboarding message -> ale and radio created from M1 */
START_TEST(test_autoconfig_wsc_2)
{
    map_ale_info_t   *ale;
    map_radio_info_t *radio;

    test_init();

    read_parse("cmdu_ap_autoconfiguration_wsc_2G.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
    fail_unless(!map_dm_get_radio(ale, g_radio_id_5G));
    fail_unless(!map_dm_get_radio(ale, g_radio_id_6G));

    read_parse("cmdu_ap_autoconfiguration_wsc_5G.pcap", g_al_mac);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_5G)));
    fail_unless(!map_dm_get_radio(ale, g_radio_id_6G));

    read_parse("cmdu_ap_autoconfiguration_wsc_6G.pcap", g_al_mac);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_6G)));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_AUTOCONFIG_WSC_TRIBAND                     #
########################################################################*/
/* Autoconfig WSC after topology response */
START_TEST(test_autoconfig_wsc_triband)
{
    map_ale_info_t   *ale;
    map_radio_info_t *radio;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_triband_topology_response.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));

    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
    fail_unless(radio->max_bss == 0);
    fail_unless(radio->cap_op_class_list.op_classes_nr == 0);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_5G)));
    fail_unless(radio->max_bss == 0);
    fail_unless(radio->cap_op_class_list.op_classes_nr == 0);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_6G)));
    fail_unless(radio->max_bss == 0);
    fail_unless(radio->cap_op_class_list.op_classes_nr == 0);

    read_parse("cmdu_ap_autoconfiguration_wsc_2G.pcap", g_al_mac);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
    fail_unless(radio->max_bss == 15);
    fail_unless(radio->cap_op_class_list.op_classes_nr == 3);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_5G)));
    fail_unless(radio->max_bss == 0);
    fail_unless(radio->cap_op_class_list.op_classes_nr == 0);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_6G)));
    fail_unless(radio->max_bss == 0);
    fail_unless(radio->cap_op_class_list.op_classes_nr == 0);

    read_parse("cmdu_ap_autoconfiguration_wsc_5G.pcap", g_al_mac);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
    fail_unless(radio->max_bss == 15);
    fail_unless(radio->cap_op_class_list.op_classes_nr == 3);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_5G)));
    fail_unless(radio->max_bss == 15);
    fail_unless(radio->cap_op_class_list.op_classes_nr == 15);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_6G)));
    fail_unless(radio->max_bss == 0);
    fail_unless(radio->cap_op_class_list.op_classes_nr == 0);

    read_parse("cmdu_ap_autoconfiguration_wsc_6G.pcap", g_al_mac);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
    fail_unless(radio->max_bss == 15);
    fail_unless(radio->cap_op_class_list.op_classes_nr == 3);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_5G)));
    fail_unless(radio->max_bss == 15);
    fail_unless(radio->cap_op_class_list.op_classes_nr == 15);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_6G)));
    fail_unless(radio->max_bss == 15);
    fail_unless(radio->cap_op_class_list.op_classes_nr == 5);

    /* Profile 2 AP cap */
    fail_unless(ale->agent_capability.profile_2_ap_cap_valid == true);
    fail_unless(ale->agent_capability.max_vid_count          == 2);
    fail_unless(ale->agent_capability.byte_counter_unit      == MAP_BYTE_COUNTER_UNIT_KIBI_BYTES);

    /* M1 attributes */
    fail_unless(!strcmp(ale->device_info.manufacturer_name, "AirTies Wireless Networks"));
    fail_unless(!strcmp(ale->device_info.model_name,        "Air4980"));
    fail_unless(!strcmp(ale->device_info.model_number,      "4980"));
    fail_unless(!strcmp(ale->device_info.serial_number,     "ATT498000COFFEE"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_AUTOCONFIG_WSC_TOO_MANY_RADIO              #
########################################################################*/
/* WCS-6239: Adding too many radios resulted in a stack corruption in map_build_and_send_policy_config
             Why appearantly extra radio MAC appear is not known
 */
START_TEST(test_autoconfig_wsc_too_many_radio)
{
    map_ale_info_t   *ale;
    map_radio_info_t *radio;

    test_init();
    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_triband_topology_response.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));

    /* Modify radio_id's and read WSC captures that will add more radio and call map_build_and_send_policy_config */
    for (int i = 1; i < 32; i++) {
        fail_unless(ale->radios_nr == 3 * i);
        fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
        radio->radio_id[0] = 0x00;
        radio->radio_id[1] = i;
        acu_mac_to_string(radio->radio_id, radio->radio_id_str);
        fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_5G)));
        radio->radio_id[0] = 0x01;
        radio->radio_id[1] = i;
        acu_mac_to_string(radio->radio_id, radio->radio_id_str);
        fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_6G)));
        radio->radio_id[0] = 0x02;
        radio->radio_id[1] = i;
        acu_mac_to_string(radio->radio_id, radio->radio_id_str);

        read_parse("cmdu_ap_autoconfiguration_wsc_2G.pcap", g_al_mac);
        read_parse("cmdu_ap_autoconfiguration_wsc_5G.pcap", g_al_mac);
        read_parse("cmdu_ap_autoconfiguration_wsc_6G.pcap", g_al_mac);
    }

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_AP_CAP_REPORT                              #
########################################################################*/
START_TEST(test_ap_cap_report)
{
    map_ale_info_t   *ale;
    map_radio_info_t *radio;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);
    read_parse("cmdu_ap_capability_report.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_5G)));

    /* AP cap tlv */
    fail_unless(ale->agent_capability.ib_unassociated_sta_link_metrics_supported);
    fail_unless(!ale->agent_capability.oob_unassociated_sta_link_metrics_supported);

    /* AP radio basic cap tlv */
    fail_unless(radio->max_bss == 15);
    fail_unless(radio->cap_op_class_list.op_classes_nr == 15);
    fail_unless(radio->cap_op_class_list.op_classes[14].op_class             == 129);
    fail_unless(radio->cap_op_class_list.op_classes[14].eirp                 == 23);
    fail_unless(map_cs_nr(&radio->cap_op_class_list.op_classes[14].channels) == 2);
    fail_unless(map_cs_is_set(&radio->cap_op_class_list.op_classes[14].channels, 114));
    fail_unless(map_cs_is_set(&radio->cap_op_class_list.op_classes[14].channels, 163));

    /* AP HT cap tlv */
    fail_unless(!!radio->ht_caps);
    fail_unless(radio->ht_caps->max_supported_tx_streams == 4);

    /* AP VHT cap tlv */
    fail_unless(!!radio->vht_caps);
    fail_unless(radio->vht_caps->max_supported_tx_streams == 4);

    /* AP HE cap tlv */
    fail_unless(!!radio->he_caps);
    fail_unless(radio->he_caps->max_supported_tx_streams == 4);
    fail_unless(radio->he_caps->support_160mhz == 1);

    /* Combined caps */
    fail_unless(radio->radio_caps.supported_standard == STD_80211_ANACAX);
    fail_unless(radio->radio_caps.max_tx_spatial_streams == 4);
    fail_unless(radio->radio_caps.max_bandwidth == 160);

    /* Profile 2 AP cap */
    fail_unless(ale->agent_capability.profile_2_ap_cap_valid == true);
    fail_unless(ale->agent_capability.max_vid_count          == 2);
    fail_unless(ale->agent_capability.byte_counter_unit      == MAP_BYTE_COUNTER_UNIT_KIBI_BYTES);

    /* scan cap */
    fail_unless(radio->scan_caps.valid                            == true);
    fail_unless(radio->scan_caps.boot_only                        == 0);
    fail_unless(radio->scan_caps.scan_impact                      == MAP_SCAN_IMPACT_TIME_SLICING);
    fail_unless(radio->scan_caps.min_scan_interval                == 900);
    fail_unless(radio->scan_caps.op_class_list.op_classes_nr                      == 5);
    fail_unless(radio->scan_caps.op_class_list.op_classes[4].op_class             == 125);
    fail_unless(map_cs_nr(&radio->scan_caps.op_class_list.op_classes[4].channels) == 5);
    fail_unless(map_cs_is_set(&radio->scan_caps.op_class_list.op_classes[4].channels, 149));
    fail_unless(map_cs_is_set(&radio->scan_caps.op_class_list.op_classes[4].channels, 165));

    /* metric collection interval tlv */
    fail_unless(ale->agent_capability.metric_collection_interval == 2108000); /* weird value... */

    /* cac capabilities */
    fail_unless(ale->country_code                            == 0x5553);
    fail_unless(radio->cac_caps.cac_method_count             == 2);
    fail_unless(radio->cac_caps.cac_method[0].cac_method     == MAP_CAC_METHOD_CONTINUOUS);
    fail_unless(radio->cac_caps.cac_method[0].cac_duration   == 60);
    fail_unless(radio->cac_caps.cac_method[0].op_class_list.op_classes_nr                      == 8);
    fail_unless(radio->cac_caps.cac_method[0].op_class_list.op_classes[7].op_class             == 129);
    fail_unless(map_cs_nr(&radio->cac_caps.cac_method[0].op_class_list.op_classes[7].channels) == 1);
    fail_unless(map_cs_is_set(&radio->cac_caps.cac_method[0].op_class_list.op_classes[7].channels, 50));
    fail_unless(radio->cac_caps.cac_method[1].cac_method     == MAP_CAC_METHOD_MIMO_DIM_REDUCED);

    test_fini();
}
END_TEST


/*#######################################################################
#                       TEST_AP_CAP_REPORT_CHANGE                       #
########################################################################*/
static void check_cap_change(map_radio_info_t *radio, bool ht, bool vht, bool he, int std, int ss, int bw)
{
    fail_unless((ht  && radio->ht_caps)  || !radio->ht_caps);
    fail_unless((vht && radio->vht_caps) || !radio->vht_caps);
    fail_unless((he  && radio->he_caps)  || !radio->he_caps);
    fail_unless(radio->radio_caps.supported_standard     == std);
    fail_unless(radio->radio_caps.max_tx_spatial_streams == ss);
    fail_unless(radio->radio_caps.max_bandwidth          == bw);
}

START_TEST(test_ap_cap_report_change)
{
    map_ale_info_t   *ale;
    map_radio_info_t *radio;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);
    read_parse("cmdu_ap_capability_report.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_5G)));

    /* HT/VHT/HE on 2.4G */
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
    check_cap_change(radio, true, true, true, STD_80211_NAX, 2, 40);

    /* HT/VHT/HE on 5G */
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_5G)));
    check_cap_change(radio, true, true, true, STD_80211_ANACAX, 4, 160);


    /* Read pcap with some cap removed. */
    read_parse("cmdu_ap_capability_report_no_he.pcap", g_al_mac);

    /* HT on 2.4G */
    /* Note: nmode was 0, brcm still adds HT cap TLV with 11G cap?? */
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
    check_cap_change(radio, true, false, false, STD_80211_N, 1, 20);

    /* HT/VHT on 5G */
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_5G)));
    check_cap_change(radio, true, true, false, STD_80211_AC, 4, 160);


    /* Read with some cap added again. */
    read_parse("cmdu_ap_capability_report.pcap", g_al_mac);

    /* HT/VHT/HE on 2.4G */
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
    check_cap_change(radio, true, true, true, STD_80211_NAX, 2, 40);

    /* HT/VHT/HE on 5G */
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_5G)));
    check_cap_change(radio, true, true, true, STD_80211_ANACAX, 4, 160);

    test_fini();
}
END_TEST

/*#######################################################################
#                   TEST_TRIBAND_AP_CAP_REPORT                          #
########################################################################*/
START_TEST(test_triband_ap_cap_report)
{
    map_ale_info_t   *ale;
    map_radio_info_t *radio;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_triband_topology_response.pcap", g_al_mac);
    read_parse("cmdu_triband_ap_capability_report.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_6G)));

    /* AP cap tlv */
    fail_unless(ale->agent_capability.ib_unassociated_sta_link_metrics_supported);
    fail_unless(ale->agent_capability.oob_unassociated_sta_link_metrics_supported);

    /* AP radio basic cap tlv */
    fail_unless(radio->max_bss == 15);
    fail_unless(radio->cap_op_class_list.op_classes_nr == 5);
    fail_unless(radio->cap_op_class_list.op_classes[4].op_class             == 136);
    fail_unless(radio->cap_op_class_list.op_classes[4].eirp                 == 23);
    fail_unless(map_cs_nr(&radio->cap_op_class_list.op_classes[4].channels) == 0);

    /* AP HT cap tlv */
    fail_unless(!!radio->ht_caps);
    fail_unless(radio->ht_caps->max_supported_tx_streams == 4);

    /* AP VHT cap tlv */
    fail_unless(!!radio->vht_caps);
    fail_unless(radio->vht_caps->max_supported_tx_streams == 4);

    /* AP HE cap tlv */
    fail_unless(!!radio->he_caps);
    fail_unless(radio->he_caps->max_supported_tx_streams == 4);
    fail_unless(radio->he_caps->support_160mhz == 1);

    /* Combined caps */
    fail_unless(radio->radio_caps.supported_standard == STD_80211_AX);
    fail_unless(radio->radio_caps.max_tx_spatial_streams == 4);
    fail_unless(radio->radio_caps.max_bandwidth == 160);

    /* Profile 2 AP cap */
    fail_unless(ale->agent_capability.profile_2_ap_cap_valid == true);
    fail_unless(ale->agent_capability.max_vid_count          == 2);
    fail_unless(ale->agent_capability.byte_counter_unit      == MAP_BYTE_COUNTER_UNIT_KIBI_BYTES);

    /* scan cap */
    fail_unless(radio->scan_caps.valid                                            == true);
    fail_unless(radio->scan_caps.boot_only                                        == 0);
    fail_unless(radio->scan_caps.scan_impact                                      == MAP_SCAN_IMPACT_TIME_SLICING);
    fail_unless(radio->scan_caps.min_scan_interval                                == 900);
    fail_unless(radio->scan_caps.op_class_list.op_classes_nr                      == 2);
    fail_unless(radio->scan_caps.op_class_list.op_classes[1].op_class             == 136);
    fail_unless(map_cs_nr(&radio->scan_caps.op_class_list.op_classes[1].channels) == 0);

    /* metric collection interval tlv */
    fail_unless(ale->agent_capability.metric_collection_interval == 12000);

    test_fini();
}
END_TEST

/*#######################################################################
#                   TEST_EARLY_AP_CAP_REPORT                          #
########################################################################*/
START_TEST(test_early_ap_cap_report)
{
    map_ale_info_t   *ale;
    map_radio_info_t *radio;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_mlo_topology_response.pcap", g_al_mac);
    read_parse("cmdu_early_ap_capability_report.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_6G)));

    /* Other TLVs are handled same in regular ap capability report */

    /* wifi7 agent capabilities tlv */
    fail_unless(ale->agent_capability.max_mlds              == 16);
    fail_unless(ale->agent_capability.ap_max_links          == 2);
    fail_unless(ale->agent_capability.bsta_max_links        == 2);
    fail_unless(ale->agent_capability.tid_to_link_map_cap   == 1);

    fail_unless(!!radio->eht_caps);
    fail_unless(!!radio->wifi7_caps);

    fail_unless(radio->wifi7_caps->ap_mld_modes.str         == true);
    fail_unless(radio->wifi7_caps->ap_mld_modes.nstr        == false);
    fail_unless(radio->wifi7_caps->ap_mld_modes.emlsr       == false);
    fail_unless(radio->wifi7_caps->ap_mld_modes.emlmr       == false);
    fail_unless(radio->wifi7_caps->bsta_mld_modes.str       == true);
    fail_unless(radio->wifi7_caps->bsta_mld_modes.nstr      == false);
    fail_unless(radio->wifi7_caps->bsta_mld_modes.emlsr     == false);
    fail_unless(radio->wifi7_caps->bsta_mld_modes.emlmr     == false);

    fail_unless(radio->wifi7_caps->ap_str_records_nr        == 2);
    fail_unless(!maccmp(radio->wifi7_caps->ap_str_records[0].ruid, g_radio_id_5G));
    fail_unless(!maccmp(radio->wifi7_caps->ap_str_records[1].ruid, g_radio_id_2G));
    fail_unless(radio->wifi7_caps->ap_str_records[0].freq_separation == 0);
    fail_unless(radio->wifi7_caps->ap_str_records[1].freq_separation == 0);
    fail_unless(radio->wifi7_caps->ap_nstr_records_nr       == 0);
    fail_unless(radio->wifi7_caps->ap_emlsr_records_nr      == 0);
    fail_unless(radio->wifi7_caps->ap_emlmr_records_nr      == 0);

    fail_unless(radio->wifi7_caps->bsta_str_records_nr      == 0);
    fail_unless(radio->wifi7_caps->bsta_nstr_records_nr     == 0);
    fail_unless(radio->wifi7_caps->bsta_emlsr_records_nr    == 0);
    fail_unless(radio->wifi7_caps->bsta_emlmr_records_nr    == 0);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_CHANNEL_PREFERENCE_REPORT                  #
########################################################################*/
/* NOTE: emulated radar to generate this cmdu */
START_TEST(test_channel_preference_report)
{
    map_ale_info_t   *ale;
    map_radio_info_t *radio;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));
    fail_unless(ale->cac_status_report.available_pairs_nr     == 0);
    fail_unless(ale->cac_status_report.non_occupancy_pairs_nr == 0);
    fail_unless(ale->cac_status_report.ongoing_cac_pairs_nr   == 0);

    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_5G)));
    fail_unless(radio->pref_op_class_list.op_classes_nr == 0);
    fail_unless(radio->cac_completion_info.detected_pairs_nr == 0);

    read_parse("cmdu_channel_preference_report.pcap", g_al_mac);

    /* channel preference report */
    fail_unless(radio->pref_op_class_list.op_classes_nr == 29);
    fail_unless(!!radio->pref_op_class_list.op_classes);
    fail_unless(radio->pref_op_class_list.op_classes[28].op_class             == 129);
    fail_unless(radio->pref_op_class_list.op_classes[28].pref                 == 0xE);
    fail_unless(radio->pref_op_class_list.op_classes[28].reason               == 0xA);
    fail_unless(map_cs_nr(&radio->pref_op_class_list.op_classes[28].channels) == 1);
    fail_unless(map_cs_is_set(&radio->pref_op_class_list.op_classes[28].channels, 50));


    /* radio operation restriction */
    fail_unless(radio->op_restriction_list.op_classes_nr == 2);
    fail_unless(radio->op_restriction_list.op_classes[0].op_class                     == 128);
    fail_unless(radio->op_restriction_list.op_classes[0].channels_nr                  == 2);
    fail_unless(radio->op_restriction_list.op_classes[0].channels[0].channel          == 44);
    fail_unless(radio->op_restriction_list.op_classes[0].channels[0].freq_restriction == 0x01);
    fail_unless(radio->op_restriction_list.op_classes[0].channels[1].channel          == 112);
    fail_unless(radio->op_restriction_list.op_classes[0].channels[1].freq_restriction == 0x02);
    fail_unless(radio->op_restriction_list.op_classes[1].op_class                     == 129);
    fail_unless(radio->op_restriction_list.op_classes[1].channels_nr                  == 1);
    fail_unless(radio->op_restriction_list.op_classes[1].channels[0].channel          == 100);
    fail_unless(radio->op_restriction_list.op_classes[1].channels[0].freq_restriction == 0x03);


    /* cac status report */
    fail_unless(ale->cac_status_report.available_pairs_nr              == 48);
    fail_unless(ale->cac_status_report.available_pairs[47].op_class    == 84);
    fail_unless(ale->cac_status_report.available_pairs[47].channel     == 11);

    fail_unless(ale->cac_status_report.non_occupancy_pairs_nr          == 9);
    fail_unless(ale->cac_status_report.non_occupancy_pairs[8].op_class == 128);
    fail_unless(ale->cac_status_report.non_occupancy_pairs[8].channel  == 106);

    fail_unless(ale->cac_status_report.ongoing_cac_pairs_nr            == 2);
    fail_unless(ale->cac_status_report.ongoing_cac_pairs[0].op_class   == 118);
    fail_unless(ale->cac_status_report.ongoing_cac_pairs[0].channel    == 52);
    fail_unless(ale->cac_status_report.ongoing_cac_pairs[0].seconds_remaining_cac_completion == 500);
    fail_unless(ale->cac_status_report.ongoing_cac_pairs[1].op_class   == 118);
    fail_unless(ale->cac_status_report.ongoing_cac_pairs[1].channel    == 56);
    fail_unless(ale->cac_status_report.ongoing_cac_pairs[1].seconds_remaining_cac_completion == 400);


    /* cac completion report */
    fail_unless(radio->cac_completion_info.op_class == 128);
    fail_unless(radio->cac_completion_info.channel  == 100);
    fail_unless(radio->cac_completion_info.status   == 0x01);

    fail_unless(radio->cac_completion_info.detected_pairs_nr                  == 4);
    fail_unless(radio->cac_completion_info.detected_pairs[3].opclass_detected == 121);
    fail_unless(radio->cac_completion_info.detected_pairs[3].channel_detected == 112);


    /* 2G radio has nothing... */
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
    fail_unless(radio->pref_op_class_list.op_classes_nr      == 0);
    fail_unless(radio->op_restriction_list.op_classes_nr     == 0);
    fail_unless(radio->cac_completion_info.detected_pairs_nr == 0);


    /* Read again (triggers radar detection code) */
    read_parse("cmdu_channel_preference_report.pcap", g_al_mac);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_CHANNEL_SELECTION_RESPONSE                 #
########################################################################*/
START_TEST(test_channel_selection_response)
{
    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);
    read_parse("cmdu_channel_selection_response.pcap", g_al_mac);

    /* Can't validate anything yet */

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_OPERATING_CHANNEL_REPORT                   #
########################################################################*/
START_TEST(test_operating_channel_report)
{
    map_ale_info_t   *ale;
    map_radio_info_t *radio;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));

    /* Reset op_class/channel learned from topology response */
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_5G)));
    radio->current_op_class   = 0;
    radio->current_op_channel = 0;

    read_parse("cmdu_operating_channel_report.pcap", g_al_mac);

    fail_unless(radio->current_op_class   == 128);
    fail_unless(radio->current_op_channel == 157);
    fail_unless(radio->current_bw         == 80);
    fail_unless(radio->current_tx_pwr     == 23);

    test_fini();
}
END_TEST

/*#######################################################################
#                      TEST_6G_OPERATING_CHANNEL_REPORT                 #
########################################################################*/
START_TEST(test_6g_operating_channel_report)
{
    map_ale_info_t   *ale;
    map_radio_info_t *radio;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_triband_topology_response.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));

    /* Reset op_class/channel learned from topology response */
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_6G)));
    radio->current_op_class   = 0;
    radio->current_op_channel = 0;

    read_parse("cmdu_6G_operating_channel_report.pcap", g_al_mac);

    fail_unless(radio->current_op_class   == 134);
    fail_unless(radio->current_op_channel == 165);
    fail_unless(radio->current_bw         == 160);
    fail_unless(radio->current_tx_pwr     == 21);

    test_fini();
}
END_TEST

/*#######################################################################
#                      TEST_6G_320MHZ_OPERATING_CHANNEL_REPORT          #
########################################################################*/
START_TEST(test_6g_320mhz_operating_channel_report)
{
    map_ale_info_t   *ale;
    map_radio_info_t *radio;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_triband_topology_response.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));

    /* Reset op_class/channel learned from topology response */
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_6G)));
    radio->current_op_class   = 0;
    radio->current_op_channel = 0;

    read_parse("cmdu_6G_320MHz_operating_channel_report.pcap", g_al_mac);

    fail_unless(radio->current_op_class   == 137);
    fail_unless(radio->current_op_channel == 165);
    fail_unless(radio->current_bw         == 320);
    fail_unless(radio->current_tx_pwr     == 21);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_CLIENT_CAP_REPORT                          #
########################################################################*/
START_TEST(test_client_cap_report)
{
    map_sta_info_t *sta;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);
    read_parse("cmdu_ap_capability_report.pcap", g_al_mac);

    fail_unless(!!(sta = map_dm_get_sta_gbl(g_S10_mac)));
    fail_unless(!sta->assoc_frame && sta->assoc_frame_len == 0);

    read_parse("cmdu_client_capability_report.pcap", g_al_mac);
    fail_unless(sta->assoc_frame && sta->assoc_frame_len > 0);

    /* STA is 5GHz */
    fail_unless(sta->bss->radio->supported_freq == IEEE80211_FREQUENCY_BAND_5_GHZ);

    map_sta_capability_t *c = &sta->sta_caps;
    fail_unless(c->he_support && c->vht_support && c->ht_support && c->erp_support);
    fail_unless(c->supported_standard == STD_80211_ANACAX);
    fail_unless(c->max_tx_spatial_streams == 2);
    fail_unless(c->dot11k_bra_support && c->dot11v_btm_support && c->mbo_support);
    fail_unless(!c->backhaul_sta);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_MLO_CLIENT_CAP_REPORT                      #
########################################################################*/
/* These are 3 tests:
   - not fragmented multi link IE
   - fragemented multi link IE
   - fragmented multi link IE and fragmented per station profile sub element
*/

static void test_mlo_client_cap_report_common(const char *client_cap_report_pcap)
{
    map_ale_info_t *ale;
    map_radio_info_t *radio, *radio_2G = NULL, *radio_5G = NULL, *radio_6G = NULL;
    map_bss_info_t *bss_2G, *bss_5G, *bss_6G;
    map_ap_mld_info_t *ap_mld;
    map_sta_mld_info_t *sta_mld;
    map_sta_info_t *sta_2G, *sta_5G, *sta_6G;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_mlo_topology_response.pcap", g_al_mac);
    read_parse("cmdu_mlo_ap_capability_report.pcap", g_al_mac);

    fail_unless(!!(ale    = map_dm_get_ale(g_al_mac)));
    fail_unless(!!(ap_mld = map_dm_get_ap_mld(ale, (mac_addr){0x00, 0x90, 0x4C, 0x4C, 0x84, 0x7A})));
    map_dm_foreach_radio(ale, radio) {
        if (radio->supported_freq == IEEE80211_FREQUENCY_BAND_6_GHZ) {
            radio_6G = radio;
        } else if (radio->supported_freq == IEEE80211_FREQUENCY_BAND_5_GHZ) {
            radio_5G = radio;
        } else if (radio->supported_freq == IEEE80211_FREQUENCY_BAND_2_4_GHZ) {
            radio_2G = radio;
        }
    }

    fail_unless(radio_6G && radio_5G && radio_2G);
    fail_unless(!!(bss_6G = list_first_entry(&radio_6G->bss_list, map_bss_info_t, list)));
    fail_unless(!!(bss_5G = list_first_entry(&radio_5G->bss_list, map_bss_info_t, list)));
    fail_unless(!!(bss_2G = list_first_entry(&radio_2G->bss_list, map_bss_info_t, list)));

    /* Add sta and mld sta present in cmdu_client_capability_report.pcap */
    fail_unless(!!(sta_mld = map_dm_create_sta_mld(ap_mld, (mac_addr){0x00, 0x90 , 0x4c, 0x4c, 0x84, 0x7a})));
    fail_unless(!!(sta_6G  = map_dm_create_aff_sta(bss_6G, sta_mld, (mac_addr){0x00, 0x90 , 0x4c, 0x4c, 0x84, 0x7a}))); /* 6G */
    fail_unless(!!(sta_5G  = map_dm_create_aff_sta(bss_5G, sta_mld, (mac_addr){0x00, 0x90 , 0x4c, 0x4c, 0x94, 0x1f}))); /* 5G */
    fail_unless(!!(sta_2G  = map_dm_create_aff_sta(bss_2G, sta_mld, (mac_addr){0x00, 0x90 , 0x4c, 0x4d, 0x41, 0xf5}))); /* 2G */

    read_parse(client_cap_report_pcap, g_al_mac);
    fail_unless(sta_6G->assoc_frame && sta_6G->assoc_frame_len > 0);
    fail_unless(sta_5G->assoc_frame && sta_5G->assoc_frame_len > 0);
    fail_unless(sta_2G->assoc_frame && sta_2G->assoc_frame_len > 0);

    fail_unless(sta_6G->sta_caps.eht_support && sta_6G->sta_caps.he_support && !sta_6G->sta_caps.vht_support);
    fail_unless(sta_5G->sta_caps.eht_support && sta_5G->sta_caps.he_support &&  sta_5G->sta_caps.vht_support);
    fail_unless(sta_2G->sta_caps.eht_support && sta_2G->sta_caps.he_support && !sta_2G->sta_caps.vht_support);

    fail_unless(sta_6G->sta_caps.max_tx_spatial_streams == 4);
    fail_unless(sta_5G->sta_caps.max_tx_spatial_streams == 3);
    fail_unless(sta_2G->sta_caps.max_tx_spatial_streams == 2);

    fail_unless(sta_mld->supported_mld_modes.str);
    fail_unless(!sta_mld->supported_mld_modes.nstr);
    fail_unless(!sta_mld->supported_mld_modes.emlsr);
    fail_unless(!sta_mld->supported_mld_modes.emlmr);

    test_fini();
}

START_TEST(test_mlo_client_cap_report)
{
    test_mlo_client_cap_report_common("cmdu_mlo_client_capability_report.pcap");
}
END_TEST

START_TEST(test_mlo_client_cap_report_frag_ml_ie)
{
    test_mlo_client_cap_report_common("cmdu_mlo_client_capability_report_frag_ml_ie.pcap");
}
END_TEST

START_TEST(test_mlo_client_cap_report_frag_ml_ie_frag_sp)
{
    test_mlo_client_cap_report_common("cmdu_mlo_client_capability_report_frag_ml_ie_frag_sp.pcap");
}
END_TEST

/*#######################################################################
#                       TEST_AP_METRICS_RESPONSE                        #
########################################################################*/
START_TEST(test_ap_metrics_response)
{
    map_ale_info_t         *ale;
    map_radio_info_t       *radio;
    map_bss_info_t         *bss;
    map_sta_info_t         *sta;
    map_sta_link_metrics_t *lm;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);
    read_parse("cmdu_ap_metrics_response.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
    fail_unless(radio->radio_metrics.valid);

    fail_unless(!!(bss = map_dm_get_bss(radio, g_bssid_2G_fh)));
    fail_unless(bss->metrics.valid);
    fail_unless(bss->extended_metrics.valid);

    fail_unless(!!(sta = map_dm_get_sta_gbl(g_S10_mac)));
    fail_unless(!!(lm = first_object(sta->metrics)));
    fail_unless(lm->dl_mac_datarate == 1134);
    fail_unless(lm->rssi == -48);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_6G_AP_METRICS_RESPONSE                     #
########################################################################*/
START_TEST(test_6g_ap_metrics_response)
{
    map_ale_info_t         *ale;
    map_radio_info_t       *radio;
    map_bss_info_t         *bss;
    map_sta_info_t         *sta;
    map_sta_link_metrics_t *lm;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_triband_topology_response.pcap", g_al_mac);
    read_parse("cmdu_6G_ap_metrics_response.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_6G)));
    fail_unless(radio->radio_metrics.valid);

    fail_unless(!!(bss = map_dm_get_bss(radio, g_bssid_6G_fh)));
    fail_unless(bss->metrics.valid);
    fail_unless(bss->extended_metrics.valid);

    fail_unless(!!(sta = map_dm_get_sta_gbl(g_S10_mac)));
    fail_unless(!!(lm = first_object(sta->metrics)));
    fail_unless(lm->dl_mac_datarate == 1134);
    fail_unless(lm->rssi == -48);
    fail_unless(sta->wifi6_sta_tid_info.TID_nr        == 3);
    fail_unless(sta->wifi6_sta_tid_info.TID[0]        == 0);
    fail_unless(sta->wifi6_sta_tid_info.queue_size[0] == 65);
    fail_unless(sta->wifi6_sta_tid_info.TID[2]        == 6);
    fail_unless(sta->wifi6_sta_tid_info.queue_size[2] == 19);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_ASSOC_STA_LINK_METRICS_RESPONSE            #
########################################################################*/
START_TEST(test_assoc_sta_link_metrics_response)
{
    map_sta_info_t         *sta;
    map_sta_link_metrics_t *lm;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);
    read_parse("cmdu_assoc_sta_link_metrics_response.pcap", g_al_mac);

    fail_unless(!!(sta = map_dm_get_sta_gbl(g_S10_mac)));
    fail_unless(!!(lm = first_object(sta->metrics)));
    fail_unless(lm->dl_mac_datarate == 65);
    fail_unless(lm->rssi == -51);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_UNASSOC_STA_LINK_METRICS_RESPONSE          #
########################################################################*/
START_TEST(test_unassoc_sta_link_metrics_response)
{
    map_ale_info_t *ale;
    map_unassoc_sta_link_metrics_response_tlv_t *tlv;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);
    read_parse("cmdu_unassoc_sta_link_metrics_response.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));
    fail_unless(!!(tlv = ale->unassoc_metrics));
    fail_unless(tlv->op_class == 121);
    fail_unless(tlv->stas_nr  == 1);
    fail_unless(!maccmp(tlv->stas[0].mac, g_S10_mac));
    fail_unless(tlv->stas[0].channel     == 112);
    fail_unless(tlv->stas[0].rcpi_uplink == 128);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_BEACON_METRICS_RESPONSE                    #
########################################################################*/
START_TEST(test_beacon_metrics_response)
{
    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);
    read_parse("cmdu_beacon_metrics_response.pcap", g_al_mac);

    /* Cannot validate anything yet */

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_CLIENT_STEERING_BTM_REPORT                 #
########################################################################*/
START_TEST(test_client_steering_btm_report)
{
    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);
    read_parse("cmdu_client_steering_btm_report.pcap", g_al_mac);

    /* Cannot validate anything yet */

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_CHANNEL_SCAN_REPORT                        #
########################################################################*/
START_TEST(test_channel_scan_report)
{
    map_ale_info_t    *ale;
    map_radio_info_t  *radio;
    map_scan_result_t *sr;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));

    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
    fail_unless(radio->last_scan_info.last_scan_cnt == 0);

    read_parse("cmdu_channel_scan_report.pcap", g_al_mac);

    fail_unless(radio->last_scan_info.last_scan_cnt == 1);
    fail_unless(list_get_size(radio->scanned_bssid_list) == 6);

    /* Check last bss (they are added in front of the list) */
    fail_unless(!!(sr = first_object(radio->scanned_bssid_list)));
    fail_unless(!memcmp(sr->neighbor_info.bssid, (mac_addr){0xF4, 0x17, 0xB8, 0xBD, 0xBA, 0xBF}, sizeof(mac_addr)));
    fail_unless(sr->neighbor_info.ssid_len == 11);
    fail_unless(!memcmp(sr->neighbor_info.ssid, (char*)"frv_test_fh", 11));
    fail_unless(sr->neighbor_info.rcpi == 198);
    fail_unless(sr->neighbor_info.ch_bw_len == 2);
    fail_unless(!memcmp(sr->neighbor_info.ch_bw, (char*)"20", 2));
    fail_unless(sr->neighbor_info.bss_load_elem_present);
    fail_unless(sr->neighbor_info.channel_utilization == 53);
    fail_unless(sr->neighbor_info.stas_nr == 0);

    test_fini();
}
END_TEST

/*#######################################################################
#                        TEST_PROXIED_ENCAP_DPP                         #
########################################################################*/
START_TEST(test_proxied_encap_dpp)
{
    map_ale_info_t   *ale;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));

    read_parse("cmdu_proxied_encap_dpp.pcap", g_al_mac);

    mac_addr enrollee_test = {0xF4, 0x17, 0xB8, 0x86, 0x59, 0x47};
    uint8_t  frame_test[6] = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6};
    uint8_t  hash_test[6]  = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    fail_unless(ale->dpp_info.encap_msg.frame_len > 0);
    fail_unless(ale->dpp_info.encap_msg.frame_type == 255);
    fail_unless(ale->dpp_info.encap_msg.frame_indicator == 1);
    fail_unless(!memcmp(ale->dpp_info.encap_msg.enrollee, enrollee_test, sizeof(mac_addr)));
    fail_unless(!memcmp(ale->dpp_info.encap_msg.frame, frame_test, ale->dpp_info.encap_msg.frame_len));

    fail_unless(ale->dpp_info.chirp.hash_validity == 0);
    fail_unless(!memcmp(ale->dpp_info.chirp.enrollee, enrollee_test, sizeof(mac_addr)));
    fail_unless(!memcmp(ale->dpp_info.chirp.hash, hash_test, ale->dpp_info.chirp.hash_len));

    test_fini();
}
END_TEST

/*#######################################################################
#                        TEST_CHIRP_NOTIFICATION                        #
########################################################################*/
START_TEST(test_chirp_notification)
{
    map_ale_info_t   *ale;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));

    read_parse("cmdu_chirp_notification.pcap", g_al_mac);

    fail_unless(ale->dpp_info.chirp.hash_validity == 0);
    mac_addr enrollee_test = {0xF4, 0x17, 0xB8, 0x86, 0x59, 0x47};
    fail_unless(!memcmp(ale->dpp_info.chirp.enrollee, enrollee_test, sizeof(mac_addr)));
    uint8_t hash_test[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    fail_unless(!memcmp(ale->dpp_info.chirp.hash, hash_test, ale->dpp_info.chirp.hash_len));

    test_fini();
}
END_TEST

/*#######################################################################
#                        TEST_1905_ENCAP_EAPOL                          #
########################################################################*/
START_TEST(test_1905_encap_eapol)
{
    map_ale_info_t *ale;
    uint8_t msg[] = {0x00, 0x01, 0x00, 0x0A, 0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));

    read_parse("cmdu_1905_encap_eapol.pcap", g_al_mac);

    fail_unless(ale->dpp_info.encap_eapol.frame_len == sizeof(msg));
    fail_unless(!memcmp(ale->dpp_info.encap_eapol.frame, msg, sizeof(msg)));

    test_fini();
}
END_TEST

/*#######################################################################
#                        TEST_DIRECT_ENCAP_DPP                          #
########################################################################*/
START_TEST(test_direct_encap_dpp)
{
    map_ale_info_t *ale;
    uint8_t msg[] = {0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));

    read_parse("cmdu_direct_encap_dpp.pcap", g_al_mac);

    fail_unless(ale->dpp_info.message.frame_len == sizeof(msg));
    fail_unless(!memcmp(ale->dpp_info.message.frame, msg, sizeof(msg)));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_CLIENT_DISASSOC_STATS                      #
########################################################################*/
START_TEST(test_client_disassoc_stats)
{
    map_sta_info_t *sta;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);
    read_parse("cmdu_client_disassociation_stats.pcap", g_al_mac);

    fail_unless(!!(sta = map_dm_get_sta_gbl(g_S10_mac)));
    fail_unless(sta->last_disassoc_reason_code == 0x08);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_ASSOC_STATUS_NOTIFICATION                  #
########################################################################*/
START_TEST(test_assoc_status_notification)
{
    map_bss_info_t *bss_2G;
    map_bss_info_t *bss_5G;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);

    fail_unless(!!(bss_2G = map_dm_get_bss_gbl(g_bssid_2G_fh)));
    fail_unless(!!(bss_5G = map_dm_get_bss_gbl(g_bssid_5G_fh)));

    bss_2G->assoc_allowance_status = MAP_ASSOC_STATUS_ALLOWED;
    bss_5G->assoc_allowance_status = MAP_ASSOC_STATUS_ALLOWED;

    /* Read assoc status notification, will disallow assoc on 2G bss */
    read_parse("cmdu_assoc_status_notification.pcap", g_al_mac);

    fail_unless(bss_2G->assoc_allowance_status == MAP_ASSOC_STATUS_DISALLOWED);
    fail_unless(bss_5G->assoc_allowance_status == MAP_ASSOC_STATUS_ALLOWED);

    test_fini();
}
END_TEST

/*#######################################################################
#                  TEST_BACKHAUL_STA_CAPABILITY_REPORT                  #
########################################################################*/
START_TEST(test_backhaul_sta_capability_report)
{
    map_ale_info_t              *ale;
    map_ale_info_t              *slave_ale;
    map_backhaul_sta_iface_t    *bhsta_iface;

    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_multiple_backhaul_topology_response_master.pcap", g_al_mac);
    read_parse("cmdu_topology_discovery_slave.pcap", g_slave_al_mac);
    read_parse("cmdu_multiple_backhaul_topology_response_slave.pcap", g_slave_al_mac);
    read_parse("cmdu_backhaul_sta_capability_report_slave.pcap", g_slave_al_mac);

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));
    fail_unless(!!(slave_ale = map_dm_get_ale(g_slave_al_mac)));

    fail_unless(!!(bhsta_iface = map_find_bhsta_iface_from_ale(slave_ale, g_5g_bh_sta_mac)));
    fail_unless(bhsta_iface->active == false);
    fail_unless(!maccmp(bhsta_iface->mac_address, g_5g_bh_sta_mac));
    fail_unless(!maccmp(bhsta_iface->radio_id, g_slave_radio_id_5G));

    fail_unless(!!(bhsta_iface = map_find_bhsta_iface_from_ale(slave_ale, g_6g_bh_sta_mac)));
    fail_unless(bhsta_iface->active == true);
    fail_unless(!maccmp(bhsta_iface->mac_address, g_6g_bh_sta_mac));
    fail_unless(!maccmp(bhsta_iface->radio_id, g_slave_radio_id_6G));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_BACKHAUL_STEERING_RESPONSE                 #
########################################################################*/
START_TEST(test_backhaul_steering_response)
{
    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);
    read_parse("cmdu_backhaul_steering_response.pcap", g_al_mac);

    /* Cannot validate anything yet */

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_BACKHAUL_STEERING_RESPONSE_ERROR           #
########################################################################*/
START_TEST(test_backhaul_steering_response_error)
{
    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);
    read_parse("cmdu_backhaul_steering_response_error.pcap", g_al_mac);

    /* Cannot validate anything yet */

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_FAILED_CONNECTION                          #
########################################################################*/
START_TEST(test_failed_connection)
{
    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);
    read_parse("cmdu_failed_connection.pcap", g_al_mac);

    /* Cannot validate anything yet */

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_ACK                                        #
########################################################################*/
START_TEST(test_ack)
{
    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);
    read_parse("cmdu_ack.pcap", g_al_mac);

    /* Cannot validate anything yet */

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_STEERING_COMPLETED                         #
########################################################################*/
START_TEST(test_steering_completed)
{
    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);
    read_parse("cmdu_steering_completed.pcap", g_al_mac);

    /* Cannot validate anything yet */

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_HIGHER_LAYER_DATA                          #
########################################################################*/
START_TEST(test_higher_layer_data)
{
    test_init();

    read_parse("cmdu_topology_discovery.pcap", g_al_mac);
    read_parse("cmdu_topology_response.pcap", g_al_mac);
    read_parse("cmdu_higher_layer_data.pcap", g_al_mac);

    /* Cannot validate anything yet */

    test_fini();
}
END_TEST

/*#######################################################################
#                   TEST_AVAILABLE_SPECTRUM_INQUIRY                     #
########################################################################*/
START_TEST(test_available_spectrum_inquiry)
{
    test_init();

    read_parse("cmdu_available_spectrum_inquiry.pcap", g_al_mac);

    /* Cannot validate anything yet */

    test_fini();
}
END_TEST

const char *test_suite_name = "cmdu_rx";
test_case_t test_cases[] = {
    TEST("topology_discovery",                       test_topology_discovery  ),
    TEST("topology_query",                           test_topology_query  ),
    TEST("topology_response",                        test_topology_response  ),
    TEST("legacy_topology_response",                 test_legacy_topology_response  ),
    TEST("triband_topology_response",                test_triband_topology_response  ),
    TEST("multi_backhaul_topology_response",         test_multiple_backhaul_topology_response  ),
    TEST("mlo_topology_response",                    test_mlo_topology_response  ),
    TEST("topology_notification",                    test_topology_notification  ),
    TEST("topology_notification_backhaul_switch",    topology_notification_backhaul_switch ),
    TEST("link_metric_query",                        test_link_metric_query  ),
    TEST("link_metric_response",                     test_link_metric_response  ),
    TEST("autoconfig_search_1",                      test_autoconfig_search_1  ),
    TEST("autoconfig_search_2",                      test_autoconfig_search_2  ),
    TEST("legacy_autoconfig_search_1",               test_legacy_autoconfig_search_1  ),
    TEST("legacy_autoconfig_search_2",               test_legacy_autoconfig_search_2  ),
    TEST("autoconfig_wsc_1",                         test_autoconfig_wsc_1  ),
    TEST("autoconfig_wsc_2",                         test_autoconfig_wsc_2  ),
    TEST("autoconfig_wsc_triband",                   test_autoconfig_wsc_triband  ),
    TEST("autoconfig_wsc_too_many_radio",            test_autoconfig_wsc_too_many_radio  ),
    TEST("ap_cap_report",                            test_ap_cap_report  ),
    TEST("ap_cap_report_change",                     test_ap_cap_report_change  ),
    TEST("triband_ap_cap_report",                    test_triband_ap_cap_report  ),
    TEST("early_ap_cap_report",                      test_early_ap_cap_report  ),
    TEST("channel_preference_report",                test_channel_preference_report  ),
    TEST("channel_selection_response",               test_channel_selection_response  ),
    TEST("operating_channel_report",                 test_operating_channel_report  ),
    TEST("6g_operating_channel_report",              test_6g_operating_channel_report  ),
    TEST("6g_320mhz_operating_channel_report",       test_6g_320mhz_operating_channel_report  ),
    TEST("client_cap_report",                        test_client_cap_report  ),
    TEST("mlo_client_cap_report",                    test_mlo_client_cap_report  ),
    TEST("mlo_client_cap_report_frag_ml_ie",         test_mlo_client_cap_report_frag_ml_ie ),
    TEST("mlo_client_cap_report_frag_ml_ie_frag_sp", test_mlo_client_cap_report_frag_ml_ie_frag_sp  ),
    TEST("ap_metrics_response",                      test_ap_metrics_response  ),
    TEST("6g_ap_metrics_response",                   test_6g_ap_metrics_response  ),
    TEST("assoc_sta_link_metrics_response",          test_assoc_sta_link_metrics_response  ),
    TEST("unassoc_sta_link_metrics_response",        test_unassoc_sta_link_metrics_response  ),
    TEST("beacon_metrics_response",                  test_beacon_metrics_response  ),
    TEST("client_steering_btm_report",               test_client_steering_btm_report  ),
    TEST("channel_scan_report",                      test_channel_scan_report  ),
    TEST("chirp_notification",                       test_chirp_notification  ),
    TEST("proxied_encap_dpp",                        test_proxied_encap_dpp  ),
    TEST("1905_encap_eapol",                         test_1905_encap_eapol  ),
    TEST("direct_encap_dpp",                         test_direct_encap_dpp  ),
    TEST("client_disassoc_stats",                    test_client_disassoc_stats  ),
    TEST("assoc_status_notification",                test_assoc_status_notification  ),
    TEST("backhaul_sta_capability_report",           test_backhaul_sta_capability_report  ),
    TEST("backhaul_steering_response",               test_backhaul_steering_response  ),
    TEST("backhaul_steering_response_error",         test_backhaul_steering_response_error  ),
    TEST("failed_connection",                        test_failed_connection  ),
    TEST("ack",                                      test_ack  ),
    TEST("steering_completed",                       test_steering_completed  ),
    TEST("higher_layer_data",                        test_higher_layer_data  ),
    TEST("available_spectrum_inquiry",               test_available_spectrum_inquiry  ),
    TEST_CASES_END
};
