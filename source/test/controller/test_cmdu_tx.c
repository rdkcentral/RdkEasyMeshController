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
#include "map_ctrl_cmdu_tx.h"
#include "map_ctrl_defines.h"

#include "map_data_model.h"
#include "map_topology_tree.h"

#include "../ieee1905/stub/stub_i1905.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
typedef struct {
    bool    mld_enabled;
    bool    bsta_cap_report_received;
} mld_test_t;

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static mac_addr      g_ctrl_al_mac =  {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};

static mac_addr      g_mcast_mac   = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x13};

/* All frames are captured from the same device */
static char         *g_src_ifname  = "eth0";
static mac_addr      g_al_mac      = {0xF6, 0x17, 0xB8, 0x86, 0x57, 0x68};
static mac_addr      g_radio_id_2G = {0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6B};
static mac_addr      g_radio_id_5G = {0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6A};
static mac_addr      g_radio_id_6G = {0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6C};
static mac_addr      g_bssid_2G_fh = {0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6B};
static mac_addr      g_bssid_5G_fh = {0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6A};
static mac_addr      g_S10_mac     = {0xA8, 0xDB, 0x03, 0x05, 0x92, 0x1C};

static mac_addr_oui  g_oui         = {0xAA, 0xBB, 0xCC};
static bool          g_mlo_test    = false;

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
static i1905_cmdu_t *parse_cmdu(packet_t *p)
{
    uint8_t *streams[2] = {p->data + sizeof(eth_hdr_t), NULL};
    uint16_t lengths[2] = {p->len, 0};

    fail_unless(p->len >= sizeof(eth_hdr_t));

    return parse_1905_CMDU_from_packets(streams, lengths);
}

static void free_cmdu(i1905_cmdu_t *cmdu)
{
    free_1905_CMDU_structure(cmdu);
}

static i1905_cmdu_t *read_parse(const char *file)
{
    packet_t     *packet;
    i1905_cmdu_t *cmdu;
    char          file_path[PATH_MAX];

    snprintf(file_path, sizeof(file_path), DATA_DIR"/%s", file);

    fail_unless(!!(packet = pcap_read_first_packet(file_path)));
    fail_unless(!!(cmdu = parse_cmdu(packet)));

    strcpy(cmdu->interface_name, g_src_ifname);
    maccpy(cmdu->cmdu_stream.src_mac_addr, g_al_mac);

    free(packet);

    return cmdu;
}

static void read_parse_rx(const char *file)
{
    i1905_cmdu_t *cmdu;

    fail_unless(!!(cmdu = read_parse(file)));
    fail_unless(!!map_cmdu_rx_cb(cmdu));

    free_cmdu(cmdu);
}

static void test_init(stub_i1905_cmdu_send_cb_t send_cb, void *send_args, map_ale_info_t **ret_ale)
{
    map_controller_cfg_t *cfg = &map_cfg_get()->controller_cfg;
    map_ale_info_t       *ale;

    stub_i1905_register_lldp_send_cb(NULL, NULL);
    stub_i1905_register_cmdu_send_cb(NULL, NULL);
    stub_i1905_register_raw_send_cb(NULL, NULL);

    maccpy(cfg->al_mac, g_ctrl_al_mac);
    map_cfg_get()->is_master = true;

    fail_unless(!map_info_init());
    fail_unless(!map_dm_init());
    fail_unless(init_topology_tree(g_ctrl_al_mac));

    /* Put some data in DM */
    read_parse_rx("cmdu_topology_discovery.pcap");
    if (g_mlo_test) {
        read_parse_rx("cmdu_mlo_topology_response.pcap");
        read_parse_rx("cmdu_early_ap_capability_report.pcap");
    } else {
        read_parse_rx("cmdu_topology_response.pcap");
        read_parse_rx("cmdu_ap_capability_report.pcap");
    }
    read_parse_rx("cmdu_channel_preference_report.pcap");

    /* Add other ale, otherwise "links" will not be stored */
    fail_unless(!!map_dm_create_ale((mac_addr){0xF6, 0x17, 0xB8, 0xAE, 0x86, 0xEF}));
    fail_unless(!!map_dm_create_ale((mac_addr){0xF6, 0x17, 0xB8, 0xBD, 0xBA, 0xBC}));
    read_parse_rx("cmdu_link_metric_response.pcap");

    fail_unless(!!(ale = map_dm_get_ale(g_al_mac)));
    if (ret_ale) {
        *ret_ale = ale;
    }

    stub_i1905_register_cmdu_send_cb(send_cb, send_args);
    stub_i1905_reset_send_nr();
}

static void test_fini(void)
{
    map_controller_cfg_t *cfg = &map_cfg_get()->controller_cfg;

    stub_i1905_register_cmdu_send_cb(NULL, NULL);

    map_dm_fini();
    map_info_fini();

    free(cfg->profiles);
    memset(cfg, 0, sizeof(map_controller_cfg_t));
}

static int count_tlvs_type(i1905_cmdu_t *cmdu, uint8_t tlv_type)
{
    uint8_t *tlv;
    int      idx, count = 0;

    i1905_foreach_tlv_type_in_cmdu(tlv_type, tlv, cmdu, idx) count++;

    return count;
}

static void check_cmdu(mac_addr dmac, mac_addr exp_dmac, i1905_cmdu_t *cmdu, uint16_t message_type,
                       uint8_t relay_indicator, const char *interface_name, int tlvs_nr)
{
    fail_unless(!maccmp(dmac, exp_dmac));
    fail_unless(cmdu->message_type    == message_type);
    fail_unless(cmdu->relay_indicator == relay_indicator);
    fail_unless(!strcmp(cmdu->interface_name, interface_name));
    fail_unless(i1905_count_tlvs_in_cmdu(cmdu) == tlvs_nr);

    /* Check EOM TLV. This should trigger valgrind error if array is not big enough */
    fail_unless(cmdu->list_of_TLVs[tlvs_nr] == NULL);
}


/*#######################################################################
#                       TEST_BRIDGE_DISCOVERY                           #
########################################################################*/
static void bridge_discovery_send_cb(char *ifname, mac_addr smac, i1905_lldp_payload_t *payload, void *args)
{
    lldp_chassis_id_tlv_t   *chassis_id_tlv   = NULL;
    lldp_port_id_tlv_t      *port_id_tlv      = NULL;
    lldp_time_to_live_tlv_t *time_to_live_tlv = NULL;
    uint8_t                 *tlv;
    int                      idx              = 0;

    while((tlv = payload->list_of_TLVs[idx])) {
        switch(*tlv) {
            case TLV_TYPE_CHASSIS_ID:
                chassis_id_tlv = (lldp_chassis_id_tlv_t *)tlv;
            break;
            case TLV_TYPE_PORT_ID:
                port_id_tlv = (lldp_port_id_tlv_t *)tlv;
            break;
            case TLV_TYPE_TIME_TO_LIVE:
                time_to_live_tlv = (lldp_time_to_live_tlv_t *)tlv;
            break;
            default:
                fail_unless(false, "unexpected LLDP TLV");
            break;
        }
        idx++;
    }

    fail_unless(idx == 3 && chassis_id_tlv && port_id_tlv && time_to_live_tlv);

    fail_unless(chassis_id_tlv->chassis_id_subtype == CHASSIS_ID_TLV_SUBTYPE_MAC_ADDRESS);
    fail_unless(!maccmp(chassis_id_tlv->chassis_id, g_ctrl_al_mac));

    fail_unless(port_id_tlv->port_id_subtype == PORT_ID_TLV_SUBTYPE_MAC_ADDRESS);
    fail_unless(!memcmp(port_id_tlv->port_id, (mac_addr){0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, sizeof(mac_addr)));

    fail_unless(time_to_live_tlv->ttl == TIME_TO_LIVE_TLV_1905_DEFAULT_VALUE);
}

START_TEST(test_bridge_discovery)
{
    i1905_interface_info_t interface = {.name = "eth1", .mac_address = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};

    g_mlo_test = false;
    test_init(NULL, NULL, NULL);

    stub_i1905_register_lldp_send_cb(bridge_discovery_send_cb, NULL);

    fail_unless(!map_send_lldp_bridge_discovery(&interface));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_TOPOLOGY_DISCOVERY                         #
########################################################################*/
static void topology_discovery_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    check_cmdu(dmac, g_mcast_mac, cmdu, CMDU_TYPE_TOPOLOGY_DISCOVERY, RELAY_INDICATOR_OFF, "eth1", 2);

    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_AL_MAC_ADDRESS, cmdu));
    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_MAC_ADDRESS, cmdu));
}

START_TEST(test_topology_discovery)
{
    i1905_interface_info_t interface = {.name = "eth1", .mac_address = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};

    g_mlo_test = false;
    test_init(topology_discovery_send_cb, NULL, NULL);

    fail_unless(!map_send_topology_discovery(&interface, MID_NA));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_TOPOLOGY_QUERY                             #
########################################################################*/
static void topology_query_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_TOPOLOGY_QUERY, RELAY_INDICATOR_OFF, g_src_ifname, 1);

    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_MULTIAP_PROFILE, cmdu));
}

START_TEST(test_topology_query)
{
    map_ale_info_t *ale;

    g_mlo_test = false;
    test_init(topology_query_send_cb, NULL, &ale);

    fail_unless(!map_send_topology_query(ale, MID_NA));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_TOPOLOGY_RESPONSE                          #
########################################################################*/
static void topology_response_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_TOPOLOGY_RESPONSE, RELAY_INDICATOR_OFF, g_src_ifname, 4);

    /* With current test data, there is not bridging tlv and no neighbor tlv */

    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_DEVICE_INFORMATION, cmdu));
    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_SUPPORTED_SERVICE,  cmdu));
    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_AP_OPERATIONAL_BSS, cmdu));
    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_MULTIAP_PROFILE,    cmdu));
}

START_TEST(test_topology_response)
{
    i1905_cmdu_t *cmdu;

    g_mlo_test = false;
    test_init(NULL, NULL, NULL);

    /* Read topology query */
    fail_unless(!!(cmdu = read_parse("cmdu_topology_query.pcap")));

    stub_i1905_register_cmdu_send_cb(topology_response_send_cb, NULL);

    fail_unless(!map_send_topology_response(g_al_mac, cmdu));
    fail_unless(stub_i1905_get_send_nr() == 1);

    free_cmdu(cmdu);
    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_LINK_METRIC_QUERY                          #
########################################################################*/
static void link_metric_query_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_LINK_METRIC_QUERY, RELAY_INDICATOR_OFF, g_src_ifname, 1);

    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_LINK_METRIC_QUERY, cmdu));
}

START_TEST(test_link_metric_query)
{
    map_ale_info_t                *ale;
    i1905_link_metric_query_tlv_t  tlv = {0};

    g_mlo_test = false;
    test_init(link_metric_query_send_cb, NULL, &ale);

    fail_unless(!map_send_link_metric_query(ale, &tlv, MID_NA));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_LINK_METRIC_RESPONSE                       #
########################################################################*/
static void link_metric_response_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_LINK_METRIC_RESPONSE, RELAY_INDICATOR_OFF, g_src_ifname, 4);
    fail_unless(cmdu->message_id == 123);

    fail_unless(count_tlvs_type(cmdu, TLV_TYPE_TRANSMITTER_LINK_METRIC) == 2);
    fail_unless(count_tlvs_type(cmdu, TLV_TYPE_RECEIVER_LINK_METRIC)    == 2);
}

START_TEST(test_link_metric_response)
{
    map_ale_info_t                      *ale;
    i1905_transmitter_link_metric_tlv_t  tx_tlvs[2];
    i1905_receiver_link_metric_tlv_t     rx_tlvs[2];
    int                                  i;

    g_mlo_test = false;
    test_init(link_metric_response_send_cb, NULL, &ale);

    for (i = 0; i < 2; i++) {
        tx_tlvs[i].tlv_type = TLV_TYPE_TRANSMITTER_LINK_METRIC;
        rx_tlvs[i].tlv_type = TLV_TYPE_RECEIVER_LINK_METRIC;
    }

    fail_unless(!map_send_link_metric_response(ale, 123, tx_tlvs, 2, rx_tlvs, 2));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_LINK_METRIC_RESPONSE_ERROR                 #
########################################################################*/
static void link_metric_response_error_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    i1905_link_metric_result_code_tlv_t *tlv;

    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_LINK_METRIC_RESPONSE, RELAY_INDICATOR_OFF, g_src_ifname, 1);
    fail_unless(cmdu->message_id == 123);

    fail_unless(!!(tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_LINK_METRIC_RESULT_CODE, cmdu)));
    fail_unless(tlv->result_code == 111);
}

START_TEST(test_link_metric_response_error)
{
    map_ale_info_t *ale;

    g_mlo_test = false;
    test_init(link_metric_response_error_send_cb, NULL, &ale);

    fail_unless(!map_send_link_metric_response_error(ale, 123, 111));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                        TEST_AUTOCONFIG_SEARCH                         #
########################################################################*/
static void autoconfig_search_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    map_supported_service_tlv_t *tlv;

    check_cmdu(dmac, g_mcast_mac, cmdu, CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH, RELAY_INDICATOR_ON, "all", 6);

    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_AL_MAC_ADDRESS,          cmdu));
    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_SEARCHED_ROLE,           cmdu));
    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_AUTOCONFIG_FREQ_BAND,    cmdu));
    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_SEARCHED_SERVICE,        cmdu));
    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_MULTIAP_PROFILE,         cmdu));

    fail_unless(!!(tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_SUPPORTED_SERVICE, cmdu)));
    fail_unless(tlv->services_nr == 1);

}

START_TEST(test_autoconfig_search)
{
    g_mlo_test = false;
    test_init(autoconfig_search_send_cb, NULL, NULL);

    fail_unless(!map_send_autoconfig_search());
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_AUTOCONFIG_RESPONSE                        #
########################################################################*/
static void autoconfig_response_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    map_supported_service_tlv_t     *ss_tlv;
    map_controller_capability_tlv_t *controller_cap_tlv;
    map_1905_security_cap_tlv_t     *i1905_security_cap_tlv;

    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE, RELAY_INDICATOR_OFF, g_src_ifname, 6);

    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_SUPPORTED_ROLE,      cmdu));
    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_SUPPORTED_FREQ_BAND, cmdu));
    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_MULTIAP_PROFILE,     cmdu));

    fail_unless(!!(ss_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_SUPPORTED_SERVICE, cmdu)));
    fail_unless(ss_tlv->services_nr == 1);

    fail_unless(!!(controller_cap_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_CONTROLLER_CAPABILITY, cmdu)));
    fail_unless(controller_cap_tlv->capability == (MAP_CONTROLLER_CAP_KIBMIB_COUNTER /*| MAP_CONTROLLER_CAP_EARLY_AP_CAP */));

    fail_unless(!!(i1905_security_cap_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_1905_LAYER_SECURITY_CAPABILITY, cmdu)));
    fail_unless(i1905_security_cap_tlv->onboarding_protocol     == MAP_1905_ONBOARDING_PROTOCOL_DPP);
    fail_unless(i1905_security_cap_tlv->mic_algorithm           == MAP_1905_MIC_ALGO_HMAC_SHA256);
    fail_unless(i1905_security_cap_tlv->encryption_algorithm    == MAP_1905_ENCRPYT_ALGO_AES_SIV);
}

START_TEST(test_autoconfig_response)
{
    i1905_cmdu_t *cmdu;

    g_mlo_test = false;
    test_init(NULL, NULL, NULL);

    /* Read topology query */
    fail_unless(!!(cmdu = read_parse("cmdu_ap_autoconfiguration_search.pcap")));

    stub_i1905_register_cmdu_send_cb(autoconfig_response_send_cb, NULL);

    fail_unless(!map_send_autoconfig_response(cmdu, true));
    fail_unless(stub_i1905_get_send_nr() == 1);

    free_cmdu(cmdu);
    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_AUTOCONFIG_WSC_M2                          #
########################################################################*/
static void autoconfig_wsc_m2_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    map_ap_radio_identifier_tlv_t       *radio_id_tlv;
    map_traffic_separation_policy_tlv_t *ts_tlv;
    map_default_8021q_settings_tlv_t    *def_8021q_tlv;
    bool                                 ts = *(bool *)args;

    /* Expected TLVS:
       - 1 AP Radio Identifier TLV
       - 2 WSC TLV
       - 1 TS Policy TLV
       - When TS enabled, 1 default 8021Q settings tlv
    */

    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_AP_AUTOCONFIGURATION_WSC, RELAY_INDICATOR_OFF, g_src_ifname, ts ? 5 : 4);

    fail_unless(!!(radio_id_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_AP_RADIO_IDENTIFIER,       cmdu)));
    fail_unless(!maccmp(radio_id_tlv->radio_id, g_radio_id_2G));

    if (!ts) {
        /* Only empty ts policy TLV */
        fail_unless(!!(ts_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_TRAFFIC_SEPARATION_POLICY, cmdu)));
        fail_unless(ts_tlv->ssids_nr == 0);
    } else {
        /* TS and default 8021Q settings TLV */
        fail_unless(!!(ts_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_TRAFFIC_SEPARATION_POLICY, cmdu)));
        fail_unless(ts_tlv->ssids_nr == 3);

        fail_unless(ts_tlv->ssids[0].ssid_len == 5);
        fail_unless(!memcmp(ts_tlv->ssids[0].ssid, "ssid0", 5));
        fail_unless(ts_tlv->ssids[0].vlan_id == 10);

        fail_unless(ts_tlv->ssids[1].ssid_len == 5);
        fail_unless(!memcmp(ts_tlv->ssids[1].ssid, "ssid1", 5));
        fail_unless(ts_tlv->ssids[1].vlan_id == 20);

        fail_unless(ts_tlv->ssids[2].ssid_len == 5);
        fail_unless(!memcmp(ts_tlv->ssids[2].ssid, "ssid2", 5));
        fail_unless(ts_tlv->ssids[2].vlan_id == 20);

        fail_unless(!!(def_8021q_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_DEFAULT_8021Q_SETTINGS, cmdu)));
        fail_unless(def_8021q_tlv->primary_vlan_id == 10);
        fail_unless(def_8021q_tlv->default_pcp == 3);
    }

    fail_unless(count_tlvs_type(cmdu, TLV_TYPE_WSC) == 2);
}

START_TEST(test_autoconfig_wsc_m2)
{
    map_controller_cfg_t *cfg = &map_cfg_get()->controller_cfg;
    map_ale_info_t       *ale;
    map_radio_info_t     *radio;
    i1905_cmdu_t         *cmdu;
    bool                  ts = false;

    g_mlo_test = false;
    test_init(NULL, NULL, &ale);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));

    /* Read topology query */
    fail_unless(!!(cmdu = read_parse("cmdu_ap_autoconfiguration_wsc_2G.pcap")));

    stub_i1905_register_cmdu_send_cb(autoconfig_wsc_m2_send_cb, &ts);

    /* Configure some profiles */
    cfg->num_profiles = 3;
    fail_unless(!!(cfg->profiles = calloc(cfg->num_profiles, sizeof(map_profile_cfg_t))));
    strcpy(cfg->profiles[0].bss_ssid, "ssid0");
    cfg->profiles[0].enabled        = true;
    cfg->profiles[0].bss_freq_bands = MAP_M2_BSS_RADIO2G;
    cfg->profiles[0].bss_state      = MAP_FRONTHAUL_BSS;
    cfg->profiles[0].gateway        = true;
    cfg->profiles[0].extender       = true;
    cfg->profiles[0].vlan_id        = -1;

    strcpy(cfg->profiles[1].bss_ssid, "ssid1");
    cfg->profiles[1].enabled        = true;
    cfg->profiles[1].bss_freq_bands = MAP_M2_BSS_RADIO2G | MAP_M2_BSS_RADIO5GU;
    cfg->profiles[1].bss_state      = MAP_FRONTHAUL_BSS;
    cfg->profiles[1].gateway        = true;
    cfg->profiles[1].extender       = true;
    cfg->profiles[1].vlan_id        = 20;

    strcpy(cfg->profiles[2].bss_ssid, "ssid2");
    cfg->profiles[2].enabled        = true;
    cfg->profiles[2].bss_freq_bands = MAP_M2_BSS_RADIO5GU; /* will not be used except in ts tlv */
    cfg->profiles[2].bss_state      = MAP_FRONTHAUL_BSS;
    cfg->profiles[2].gateway        = true;
    cfg->profiles[2].extender       = true;
    cfg->profiles[2].vlan_id        = 20;

    /* No traffic separation */
    ts = false; map_cfg_get()->primary_vlan_id = -1;
    fail_unless(!map_send_autoconfig_wsc_m2(ale, radio, cmdu, MID_NA));

    /* With traffic separation */
    ts = true; map_cfg_get()->primary_vlan_id = 10; map_cfg_get()->default_pcp = 3;
    fail_unless(!map_send_autoconfig_wsc_m2(ale, radio, cmdu, MID_NA));

    fail_unless(stub_i1905_get_send_nr() == 2);

    free_cmdu(cmdu);
    test_fini();
}
END_TEST

/*#######################################################################
#                     TEST_AUTOCONFIG_WSC_M2_MLD                         #
########################################################################*/
static void autoconfig_wsc_m2_mld_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    map_ap_radio_identifier_tlv_t   *radio_id_tlv;
    map_agent_ap_mld_conf_tlv_t     *ap_mld_conf_tlv;
    map_bsta_mld_conf_tlv_t         *bsta_mld_conf_tlv;
    mld_test_t                      *mld = (mld_test_t *)args;
    int                              tlvs_expected;

    tlvs_expected = 6 + (mld->mld_enabled ? 1 : 0) + (mld->bsta_cap_report_received ? 1 : 0);
    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_AP_AUTOCONFIGURATION_WSC, RELAY_INDICATOR_OFF, g_src_ifname, tlvs_expected);

    fail_unless(!!(radio_id_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_AP_RADIO_IDENTIFIER, cmdu)));
    fail_unless(!maccmp(radio_id_tlv->radio_id, g_radio_id_6G));

    if (!mld->mld_enabled) {
        fail_unless(!(ap_mld_conf_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_AGENT_AP_MLD_CONFIGURATION, cmdu)));
        fail_unless(!(bsta_mld_conf_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_BACKHAUL_STA_MLD_CONFIGURATION, cmdu)));
    } else {
        fail_unless(!!(ap_mld_conf_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_AGENT_AP_MLD_CONFIGURATION, cmdu)));

        fail_unless(ap_mld_conf_tlv->ap_mld_nr == 2);

        fail_unless(ap_mld_conf_tlv->ap_mlds[0].ssid_len    == 5);
        fail_unless(!memcmp(ap_mld_conf_tlv->ap_mlds[0].ssid, "ssid0", 5));
        fail_unless(ap_mld_conf_tlv->ap_mlds[0].str         == 1);
        fail_unless(ap_mld_conf_tlv->ap_mlds[0].nstr        == 0);
        fail_unless(ap_mld_conf_tlv->ap_mlds[0].emlsr       == 0);
        fail_unless(ap_mld_conf_tlv->ap_mlds[0].emlmr       == 0);

        fail_unless(ap_mld_conf_tlv->ap_mlds[0].aff_ap_nr   == 3);
        fail_unless(!maccmp(ap_mld_conf_tlv->ap_mlds[0].aff_aps[0].radio_id, g_radio_id_2G));
        fail_unless(!maccmp(ap_mld_conf_tlv->ap_mlds[0].aff_aps[1].radio_id, g_radio_id_6G));
        fail_unless(!maccmp(ap_mld_conf_tlv->ap_mlds[0].aff_aps[2].radio_id, g_radio_id_5G));

        fail_unless(ap_mld_conf_tlv->ap_mlds[1].ssid_len    == 5);
        fail_unless(!memcmp(ap_mld_conf_tlv->ap_mlds[1].ssid, "ssid1", 5));

        fail_unless(ap_mld_conf_tlv->ap_mlds[1].aff_ap_nr   == 2);
        fail_unless(!maccmp(ap_mld_conf_tlv->ap_mlds[1].aff_aps[0].radio_id, g_radio_id_6G));
        fail_unless(!maccmp(ap_mld_conf_tlv->ap_mlds[1].aff_aps[1].radio_id, g_radio_id_5G));

        if (mld->bsta_cap_report_received) {
            fail_unless(!!(bsta_mld_conf_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_BACKHAUL_STA_MLD_CONFIGURATION, cmdu)));

            fail_unless(bsta_mld_conf_tlv->str                  == 1);
            fail_unless(bsta_mld_conf_tlv->nstr                 == 0);
            fail_unless(bsta_mld_conf_tlv->emlsr                == 0);
            fail_unless(bsta_mld_conf_tlv->emlmr                == 0);

            fail_unless(bsta_mld_conf_tlv->aff_bsta_nr          == 2);
            fail_unless(!maccmp(bsta_mld_conf_tlv->aff_bstas[0].radio_id, g_radio_id_6G));
            fail_unless(!maccmp(bsta_mld_conf_tlv->aff_bstas[1].radio_id, g_radio_id_5G));
        } else {
            fail_unless(!(bsta_mld_conf_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_BACKHAUL_STA_MLD_CONFIGURATION, cmdu)));
        }
    }

    fail_unless(count_tlvs_type(cmdu, TLV_TYPE_WSC) == 3);
}

START_TEST(test_autoconfig_wsc_m2_mld)
{
    map_controller_cfg_t *cfg = &map_cfg_get()->controller_cfg;
    map_ale_info_t       *ale;
    map_radio_info_t     *radio;
    i1905_cmdu_t         *cmdu;
    mld_test_t            mld = {0};

    g_mlo_test = true;
    test_init(NULL, NULL, &ale);
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_6G)));

    /* Read WSC M1 */
    fail_unless(!!(cmdu = read_parse("cmdu_ap_autoconfiguration_wsc_6G.pcap")));

    stub_i1905_register_cmdu_send_cb(autoconfig_wsc_m2_mld_send_cb, &mld);

    /* Configure some profiles */
    cfg->num_profiles = 3;
    fail_unless(!!(cfg->profiles = calloc(cfg->num_profiles, sizeof(map_profile_cfg_t))));
    strcpy(cfg->profiles[0].bss_ssid, "ssid0");
    cfg->profiles[0].profile_idx    = 0;
    cfg->profiles[0].enabled        = true;
    cfg->profiles[0].bss_freq_bands = MAP_M2_BSS_RADIO2G | MAP_M2_BSS_RADIO5GU | MAP_M2_BSS_RADIO5GL | MAP_M2_BSS_RADIO6G;
    cfg->profiles[0].bss_state      = MAP_FRONTHAUL_BSS;
    cfg->profiles[0].gateway        = true;
    cfg->profiles[0].extender       = true;
    cfg->profiles[0].vlan_id        = -1;
    cfg->profiles[0].mld_id         = 0;

    strcpy(cfg->profiles[1].bss_ssid, "ssid1");
    cfg->profiles[1].profile_idx    = 1;
    cfg->profiles[1].enabled        = true;
    cfg->profiles[1].bss_freq_bands = MAP_M2_BSS_RADIO5GU | MAP_M2_BSS_RADIO5GL | MAP_M2_BSS_RADIO6G;
    cfg->profiles[1].bss_state      = MAP_BACKHAUL_BSS;
    cfg->profiles[1].gateway        = true;
    cfg->profiles[1].extender       = true;
    cfg->profiles[1].vlan_id        = -1;
    cfg->profiles[1].mld_id         = 1;

    strcpy(cfg->profiles[2].bss_ssid, "ssid2");
    cfg->profiles[2].profile_idx    = 2;
    cfg->profiles[2].enabled        = true;
    cfg->profiles[2].bss_freq_bands = MAP_M2_BSS_RADIO6G;
    cfg->profiles[2].bss_state      = MAP_FRONTHAUL_BSS;
    cfg->profiles[2].gateway        = true;
    cfg->profiles[2].extender       = true;
    cfg->profiles[2].vlan_id        = -1;
    cfg->profiles[2].mld_id         = -1;

    /* No MLD */
    mld.mld_enabled = false;
    mld.bsta_cap_report_received = false;
    cfg->mld_enabled = false;
    fail_unless(!map_send_autoconfig_wsc_m2(ale, radio, cmdu, MID_NA));

    /* MLD Enabled, No bsta */
    mld.mld_enabled = true;
    mld.bsta_cap_report_received = false;
    cfg->mld_enabled = true;
    fail_unless(!map_send_autoconfig_wsc_m2(ale, radio, cmdu, MID_NA));

    /* MLD Enabled, bsta exists(slave ap) */
    mld.mld_enabled = true;
    mld.bsta_cap_report_received = true;
    cfg->mld_enabled = true;
    read_parse_rx("cmdu_backhaul_sta_capability_report.pcap");
    fail_unless(!map_send_autoconfig_wsc_m2(ale, radio, cmdu, MID_NA));

    fail_unless(stub_i1905_get_send_nr() == 3);

    g_mlo_test = false;

    free_cmdu(cmdu);
    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_AUTOCONFIG_RENEW                           #
########################################################################*/
static void autoconfig_renew_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    check_cmdu(dmac, g_mcast_mac, cmdu, CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW, RELAY_INDICATOR_ON, "all", 3);

    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_AL_MAC_ADDRESS,      cmdu));
    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_SUPPORTED_ROLE,      cmdu));
    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_SUPPORTED_FREQ_BAND, cmdu));
}

START_TEST(test_autoconfig_renew)
{
    g_mlo_test = false;
    test_init(autoconfig_renew_send_cb, NULL, NULL);

    fail_unless(!map_send_autoconfig_renew(IEEE80211_FREQUENCY_BAND_2_4_GHZ, MID_NA, true));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_AUTOCONFIG_RENEW_UCAST                     #
########################################################################*/
static void autoconfig_renew_ucast_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW, RELAY_INDICATOR_OFF, g_src_ifname, 3);

    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_AL_MAC_ADDRESS,      cmdu));
    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_SUPPORTED_ROLE,      cmdu));
    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_SUPPORTED_FREQ_BAND, cmdu));
}

START_TEST(test_autoconfig_renew_ucast)
{
    map_ale_info_t *ale;

    g_mlo_test = false;
    test_init(autoconfig_renew_ucast_send_cb, NULL, &ale);

    fail_unless(!map_send_autoconfig_renew_ucast(ale, IEEE80211_FREQUENCY_BAND_2_4_GHZ, MID_NA, true));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_VENDOR_SPECIFIC                            #
########################################################################*/
static void vendor_specific_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    i1905_vendor_specific_tlv_t *tlv;

    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_VENDOR_SPECIFIC, RELAY_INDICATOR_OFF, g_src_ifname, 1);

    fail_unless(!!(tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_VENDOR_SPECIFIC, cmdu)));
    fail_unless(!memcmp(tlv->vendorOUI, g_oui, sizeof(tlv->vendorOUI)));
    fail_unless(tlv->m_nr == 4);
    fail_unless(!memcmp(tlv->m, "test", 4));
}

START_TEST(test_vendor_specific)
{
    map_ale_info_t        *ale;
    map_vendor_specific_t  vs = {0};

    g_mlo_test = false;
    test_init(vendor_specific_send_cb, NULL, &ale);

    vs.ale = ale;
    memcpy(vs.oui, g_oui, sizeof(vs.oui));
    vs.len = 4;
    vs.data = (uint8_t *)"test";

    fail_unless(!map_send_vendor_specific(&vs, MID_NA));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_VENDOR_SPECIFIC_MULT_TLVS                  #
########################################################################*/
static void vendor_specific_mult_tlvs_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    i1905_vendor_specific_tlv_t *tlv;

    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_VENDOR_SPECIFIC, RELAY_INDICATOR_OFF, g_src_ifname, 2);

    tlv = (i1905_vendor_specific_tlv_t *)cmdu->list_of_TLVs[0];
    fail_unless(!memcmp(tlv->vendorOUI, g_oui, sizeof(tlv->vendorOUI)));
    fail_unless(tlv->m_nr == 5);
    fail_unless(!memcmp(tlv->m, "test1", 5));

    tlv = (i1905_vendor_specific_tlv_t *)cmdu->list_of_TLVs[1];
    fail_unless(!memcmp(tlv->vendorOUI, g_oui, sizeof(tlv->vendorOUI)));
    fail_unless(tlv->m_nr == 6);
    fail_unless(!memcmp(tlv->m, "test22", 6));
}

START_TEST(test_vendor_specific_mult_tlvs)
{
    map_ale_info_t                 *ale;
    map_vendor_specific_mult_tlv_t  vs      = {0};
    map_vendor_tlv_tuple_t          tlvs[2] = {0};

    g_mlo_test = false;
    test_init(vendor_specific_mult_tlvs_send_cb, NULL, &ale);

    vs.ale = ale;
    memcpy(vs.oui, g_oui, sizeof(vs.oui));
    vs.tlvs = tlvs;
    vs.tlvs_cnt = 2;
    tlvs[0].len = 5;
    tlvs[0].data = (uint8_t *)"test1";
    tlvs[1].len = 6;
    tlvs[1].data = (uint8_t *)"test22";

    fail_unless(!map_send_vendor_specific_mult_tlvs(&vs, MID_NA));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_ACK                                        #
########################################################################*/
static void ack_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_ACK, RELAY_INDICATOR_OFF, g_src_ifname, 0);
}

START_TEST(test_ack)
{
    map_ale_info_t *ale;
    i1905_cmdu_t   *cmdu;

    g_mlo_test = false;
    test_init(NULL, NULL, &ale);

    /* Read some cmdu */
    fail_unless(!!(cmdu = read_parse("cmdu_channel_scan_report.pcap")));

    stub_i1905_register_cmdu_send_cb(ack_send_cb, NULL);

    fail_unless(!map_send_ack(ale, cmdu));

    free_cmdu(cmdu);
    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_ACK_STA_ERROR                              #
########################################################################*/
static void ack_sta_error_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    map_error_code_tlv_t *tlv;

    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_ACK, RELAY_INDICATOR_OFF, g_src_ifname, 2);

    fail_unless(count_tlvs_type(cmdu, TLV_TYPE_ERROR_CODE) == 2);

    tlv = (map_error_code_tlv_t *)cmdu->list_of_TLVs[0];
    fail_unless(!maccmp(tlv->sta_mac, g_bssid_2G_fh));
    fail_unless(tlv->reason_code == MAP_ERROR_CODE_STA_ASSOCIATED);

    tlv = (map_error_code_tlv_t *)cmdu->list_of_TLVs[1];
    fail_unless(!maccmp(tlv->sta_mac, g_bssid_5G_fh));
    fail_unless(tlv->reason_code == MAP_ERROR_CODE_STA_ASSOCIATED);
}

START_TEST(test_ack_sta_error)
{
    map_ale_info_t *ale;
    i1905_cmdu_t   *cmdu;
    mac_addr        stas[2];

    g_mlo_test = false;
    test_init(NULL, NULL, &ale);

    /* Read some cmdu */
    fail_unless(!!(cmdu = read_parse("cmdu_channel_scan_report.pcap")));

    stub_i1905_register_cmdu_send_cb(ack_sta_error_send_cb, NULL);

    maccpy(stas[0], g_bssid_2G_fh);
    maccpy(stas[1], g_bssid_5G_fh);

    fail_unless(!map_send_ack_sta_error(ale, cmdu, stas, 2, MAP_ERROR_CODE_STA_ASSOCIATED));

    free_cmdu(cmdu);
    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_AP_CAPABILITY_QUERY                        #
########################################################################*/
static void ap_capability_query_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_AP_CAPABILITY_QUERY, RELAY_INDICATOR_OFF, g_src_ifname, 0);
}

START_TEST(test_ap_capability_query)
{
    map_ale_info_t *ale;

    g_mlo_test = false;
    test_init(ap_capability_query_send_cb, NULL, &ale);

    fail_unless(!map_send_ap_capability_query(ale, MID_NA));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_POLICY_CONFIG_REQUEST                      #
########################################################################*/
static void policy_config_request_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_MULTI_AP_POLICY_CONFIG_REQUEST, RELAY_INDICATOR_OFF, g_src_ifname, 8);

    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_METRIC_REPORTING_POLICY,         cmdu));
    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_STEERING_POLICY,                 cmdu));
    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_UNSUCCESSFUL_ASSOCIATION_POLICY, cmdu));
    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_CHANNEL_SCAN_REPORTING_POLICY,   cmdu));
    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_DEFAULT_8021Q_SETTINGS,          cmdu));
    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_TRAFFIC_SEPARATION_POLICY,       cmdu));
    fail_unless(count_tlvs_type(cmdu, TLV_TYPE_BACKHAUL_BSS_CONFIGURATION) == 2);
}

START_TEST(test_policy_config_request)
{
    map_ale_info_t                          *ale;
    map_metric_reporting_policy_tlv_t        metric_policy_tlv              = {0};
    map_steering_policy_tlv_t                steering_policy_tlv            = {0};
    map_unsuccessful_assoc_policy_tlv_t      unsuccess_assoc_policy_tlv     = {0};
    map_channel_scan_reporting_policy_tlv_t  channel_scan_report_policy_tlv = {0};
    map_default_8021q_settings_tlv_t         default_8021q_settings_tlv     = {0};
    map_traffic_separation_policy_tlv_t      traffic_separation_policy_tlv  = {0};
    map_backhaul_bss_configuration_tlv_t     bh_bss_config_tlvs[2]          = {0};

    map_policy_config_tlvs_t                 tlvs  = { .metric_policy_tlv              = &metric_policy_tlv,
                                                       .steering_policy_tlv            = &steering_policy_tlv,
                                                       .unsuccess_assoc_policy_tlv     = &unsuccess_assoc_policy_tlv,
                                                       .channel_scan_report_policy_tlv = &channel_scan_report_policy_tlv,
                                                       .default_8021q_settings_tlv     = &default_8021q_settings_tlv,
                                                       .traffic_separation_policy_tlv  = &traffic_separation_policy_tlv,
                                                       .bh_bss_config_tlvs_nr          = 2,
                                                       .bh_bss_config_tlvs             = bh_bss_config_tlvs
                                                     };

    g_mlo_test = false;
    test_init(policy_config_request_send_cb, NULL, &ale);

    fail_unless(!map_send_policy_config_request(ale, &tlvs, MID_NA));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_CHANNEL_PREFERENCE_QUERY                   #
########################################################################*/
static void channel_preference_query_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_CHANNEL_PREFERENCE_QUERY, RELAY_INDICATOR_OFF, g_src_ifname, 0);
}

START_TEST(test_channel_preference_query)
{
    map_ale_info_t *ale;

    g_mlo_test = false;
    test_init(channel_preference_query_send_cb, NULL, &ale);

    fail_unless(!map_send_channel_preference_query(ale, MID_NA));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_CHANNEL_SELECTION_REQUEST                  #
########################################################################*/
static void channel_selection_request_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    map_channel_preference_tlv_t   *c_tlv;
    map_transmit_power_limit_tlv_t *p_tlv;
    bool                           *all_radios = args;
    int                             c_tlv_nr   = *all_radios ? 2 : 1;
    int                             idx;
    bool                            twoG_ok = false, fiveG_ok = false;

    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_CHANNEL_SELECTION_REQUEST, RELAY_INDICATOR_OFF, g_src_ifname, c_tlv_nr + 1);

    fail_unless(count_tlvs_type(cmdu, TLV_TYPE_CHANNEL_PREFERENCE) == c_tlv_nr);
    i1905_foreach_tlv_type_in_cmdu(TLV_TYPE_CHANNEL_PREFERENCE, c_tlv, cmdu, idx) {
        if (!maccmp(c_tlv->radio_id, g_radio_id_2G)) {
            twoG_ok = true;
        } else if (!maccmp(c_tlv->radio_id, g_radio_id_5G)) {
            fiveG_ok = true;
        }
    }
    fail_unless(twoG_ok && (c_tlv_nr == 1 || fiveG_ok));

    fail_unless(!!(p_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_TRANSMIT_POWER_LIMIT, cmdu)));
    fail_unless(!maccmp(p_tlv->radio_id, g_radio_id_2G));
    fail_unless(p_tlv->transmit_power_eirp == 20);
}

START_TEST(test_channel_selection_request)
{
    map_ale_info_t              *ale;
    map_radio_info_t            *radio;
    map_chan_select_pref_type_t  pref = {0};
    bool                         all_radios = true;

    g_mlo_test = false;
    test_init(channel_selection_request_send_cb, &all_radios, &ale);

    /* Set transmit power limit for one radio */
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
    radio->tx_pwr_limit = 20;

    /* Set tx power limit for one radio */
    fail_unless(!!(radio = map_dm_get_radio(ale, g_radio_id_2G)));
    radio->tx_pwr_limit = 20;

    /* Request for all radios */
    pref.ale   = ale;
    pref.radio = NULL;
    pref.pref  = MAP_CHAN_SEL_PREF_AGENT;
    fail_unless(!map_send_channel_selection_request(&pref, MID_NA));

    /* Request for one radio */
    all_radios = false;
    pref.ale   = ale;
    pref.radio = radio;
    pref.pref  = MAP_CHAN_SEL_PREF_MERGED;
    fail_unless(!map_send_channel_selection_request(&pref, MID_NA));

    fail_unless(stub_i1905_get_send_nr() == 2);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_CLIENT_CAPABILITY_QUERY                    #
########################################################################*/
static void client_capability_query_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    map_client_info_tlv_t *tlv;
    map_sta_info_t        *sta = *(map_sta_info_t **)args;

    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_CLIENT_CAPABILITY_QUERY, RELAY_INDICATOR_OFF, g_src_ifname, 1);

    fail_unless(!!(tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_CLIENT_INFO, cmdu)));
    fail_unless(!maccmp(tlv->bssid, sta->bss->bssid));
    fail_unless(!maccmp(tlv->sta_mac, sta->mac));
}

START_TEST(test_client_capability_query)
{
    map_ale_info_t *ale;
    map_sta_info_t *sta;

    g_mlo_test = false;
    test_init(client_capability_query_send_cb, &sta, &ale);

    fail_unless(!!(sta = map_dm_get_sta_from_ale(ale, g_S10_mac)));

    fail_unless(!map_send_client_capability_query(sta, MID_NA));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_AP_METRICS_QUERY                           #
########################################################################*/
static void ap_metrics_query_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    map_ap_metric_query_tlv_t *tlv;

    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_AP_METRICS_QUERY, RELAY_INDICATOR_OFF, g_src_ifname, 1);

    fail_unless(!!(tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_AP_METRIC_QUERY, cmdu)));
    fail_unless(tlv->bssids_nr == 2);
    fail_unless(!maccmp(tlv->bssids[0], g_bssid_2G_fh));
    fail_unless(!maccmp(tlv->bssids[1], g_bssid_5G_fh));
}

START_TEST(test_ap_metrics_query)
{
    map_ale_info_t *ale;
    mac_addr        bssids[2];

    g_mlo_test = false;
    test_init(ap_metrics_query_send_cb, NULL, &ale);

    maccpy(bssids[0], g_bssid_2G_fh);
    maccpy(bssids[1], g_bssid_5G_fh);

    fail_unless(!map_send_ap_metrics_query(ale, bssids, 2, MID_NA));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_ASSOC_STA_LINK_METRICS                     #
########################################################################*/
static void assoc_sta_link_metrics_query_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    map_sta_mac_address_tlv_t *tlv;

    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_ASSOCIATED_STA_LINK_METRICS_QUERY, RELAY_INDICATOR_OFF, g_src_ifname, 1);

    fail_unless(!!(tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_STA_MAC_ADDRESS, cmdu)));
    fail_unless(!maccmp(tlv->sta_mac, g_S10_mac));
}

START_TEST(test_assoc_sta_link_metrics_query)
{
    map_ale_info_t *ale;
    map_sta_info_t *sta;

    g_mlo_test = false;
    test_init(assoc_sta_link_metrics_query_send_cb, NULL, &ale);

    fail_unless(!!(sta = map_dm_get_sta_from_ale(ale, g_S10_mac)));

    fail_unless(!map_send_assoc_sta_link_metrics_query(sta, MID_NA));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_UNASSOC_STA_LINK_METRICS_QUERY             #
########################################################################*/
static void unassoc_sta_link_metrics_query_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_UNASSOCIATED_STA_LINK_METRICS_QUERY, RELAY_INDICATOR_OFF, g_src_ifname, 1);

    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_UNASSOCIATED_STA_LINK_METRICS_QUERY, cmdu));
}

START_TEST(test_unassoc_sta_link_metrics_query)
{
    map_ale_info_t                           *ale;
    map_unassoc_sta_link_metrics_query_tlv_t  tlv = {0};

    g_mlo_test = false;
    test_init(unassoc_sta_link_metrics_query_send_cb, NULL, &ale);

    fail_unless(!map_send_unassoc_sta_link_metrics_query(ale, &tlv, MID_NA));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_COMBINED_INFRASTRUCTURE_METRICS            #
########################################################################*/
static void combined_infrastructure_metrics_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_COMBINED_INFRASTRUCTURE_METRICS, RELAY_INDICATOR_OFF, g_src_ifname, 7);

    /* With current data:
       2 TLV_TYPE_RECEIVER_LINK_METRIC, 2 TLV_TYPE_TRANSMITTER_LINK_METRIC and 3 TLV_TYPE_AP_METRICS
    */
    fail_unless(count_tlvs_type(cmdu, TLV_TYPE_TRANSMITTER_LINK_METRIC) == 2);
    fail_unless(count_tlvs_type(cmdu, TLV_TYPE_RECEIVER_LINK_METRIC)    == 2);
    fail_unless(count_tlvs_type(cmdu, TLV_TYPE_AP_METRICS)              == 3);
}

START_TEST(test_combined_infrastructure_metrics)
{
    map_ale_info_t *ale;

    g_mlo_test = false;
    test_init(combined_infrastructure_metrics_send_cb, NULL, &ale);

    /* TODO: add more data */

    fail_unless(!map_send_combined_infrastructure_metrics(ale, MID_NA));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_CLIENT_STEERING_REQUEST                    #
########################################################################*/
static void client_steering_request_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    bool *mbo = args;

    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_CLIENT_STEERING_REQUEST, RELAY_INDICATOR_OFF, g_src_ifname, 1);

    if (*mbo) {
        map_profile2_steering_request_tlv_t *tlv;

        fail_unless(!!(tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_PROFILE2_STEERING_REQUEST, cmdu)));

        fail_unless(!maccmp(tlv->bssid, g_bssid_2G_fh));
        fail_unless(tlv->flag = MAP_STEERING_REQUEST_FLAG_MANDATE | MAP_STEERING_REQUEST_FLAG_BTM_DISASSOC_IMMINENT);
        fail_unless(tlv->disassociation_timer == 1234);
        fail_unless(tlv->opportunity_wnd == 5678);
        fail_unless(tlv->sta_macs_nr == 1);
        fail_unless(tlv->target_bsss_nr == 1);
        fail_unless(!maccmp(tlv->sta_macs[0], g_S10_mac));
        fail_unless(!maccmp(tlv->target_bsss[0].bssid, g_bssid_5G_fh));
        fail_unless(tlv->target_bsss[0].op_class == 121);
        fail_unless(tlv->target_bsss[0].channel == 100);
        fail_unless(tlv->target_bsss[0].reason == 3);
    } else {
        map_steering_request_tlv_t *tlv;

        fail_unless(!!(tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_STEERING_REQUEST, cmdu)));

        fail_unless(!maccmp(tlv->bssid, g_bssid_2G_fh));
        fail_unless(tlv->flag = MAP_STEERING_REQUEST_FLAG_MANDATE | MAP_STEERING_REQUEST_FLAG_BTM_DISASSOC_IMMINENT);
        fail_unless(tlv->disassociation_timer == 1234);
        fail_unless(tlv->opportunity_wnd == 5678);
        fail_unless(tlv->sta_macs_nr == 1);
        fail_unless(tlv->target_bsss_nr == 1);
        fail_unless(!maccmp(tlv->sta_macs[0], g_S10_mac));
        fail_unless(!maccmp(tlv->target_bsss[0].bssid, g_bssid_5G_fh));
        fail_unless(tlv->target_bsss[0].op_class == 121);
        fail_unless(tlv->target_bsss[0].channel == 100);
    }
}

START_TEST(test_client_steering_request)
{
    map_ale_info_t *ale;
    map_sta_info_t *sta;
    map_steer_t     steer = {0};
    bool            mbo = false;

    g_mlo_test = false;
    test_init(client_steering_request_send_cb, &mbo, &ale);

    fail_unless(!!(sta = map_dm_get_sta_from_ale(ale, g_S10_mac)));

    /* Fill steering request */
    maccpy(steer.bssid, g_bssid_2G_fh);
    steer.disassociation_timer = 1234;
    steer.opportunity_wnd      = 5678;
    steer.flags                = MAP_STEERING_REQUEST_FLAG_MANDATE | MAP_STEERING_REQUEST_FLAG_BTM_DISASSOC_IMMINENT;
    steer.sta_bssid_nr         = 1;
    maccpy(steer.sta_bssid[0].sta_mac, sta->mac);
    maccpy(steer.sta_bssid[0].target_bssid, g_bssid_5G_fh);
    steer.sta_bssid[0].op_class = 121;
    steer.sta_bssid[0].channel  = 100;
    steer.sta_bssid[0].reason   = 3;

    /* No mbo -> P1 TLV */
    mbo = false; sta->sta_caps.mbo_support = false;
    fail_unless(!map_send_client_steering_request(ale, &steer, MID_NA));

    /* Mbo -> P2 TLV */
    mbo = true; sta->sta_caps.mbo_support = true;
    fail_unless(!map_send_client_steering_request(ale, &steer, MID_NA));
    fail_unless(stub_i1905_get_send_nr() == 2);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_CLIENT_ACL_REQUEST                         #
########################################################################*/
static void client_acl_request_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_CLIENT_ASSOCIATION_CONTROL_REQUEST, RELAY_INDICATOR_OFF, g_src_ifname, 1);

    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_CLIENT_ASSOCIATION_CONTROL_REQUEST, cmdu));
}

START_TEST(test_client_acl_request)
{
    map_ale_info_t                         *ale;
    map_client_assoc_control_request_tlv_t  tlv = {0};

    g_mlo_test = false;
    test_init(client_acl_request_send_cb, NULL, &ale);

    fail_unless(!map_send_client_acl_request(ale, &tlv, MID_NA));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_BEACON_METRICS_QUERY                       #
########################################################################*/
static void beacon_metrics_query_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_BEACON_METRICS_QUERY, RELAY_INDICATOR_OFF, g_src_ifname, 1);

    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_BEACON_METRICS_QUERY, cmdu));
}

START_TEST(test_beacon_metrics_query)
{
    map_ale_info_t                 *ale;
    map_beacon_metrics_query_tlv_t  tlv = {0};

    g_mlo_test = false;
    test_init(beacon_metrics_query_send_cb, NULL, &ale);

    fail_unless(!map_send_beacon_metrics_query(ale, &tlv, MID_NA));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_BACKHAUL_STEERING_REQUEST                  #
########################################################################*/
static void backhaul_steering_request_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_BACKHAUL_STEERING_REQUEST, RELAY_INDICATOR_OFF, g_src_ifname, 1);

    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_BACKHAUL_STEERING_REQUEST, cmdu));
}

START_TEST(test_backhaul_steering_request)
{
    map_ale_info_t                      *ale;
    map_backhaul_steering_request_tlv_t  tlv = {0};

    g_mlo_test = false;
    test_init(backhaul_steering_request_send_cb, NULL, &ale);

    fail_unless(!map_send_backhaul_steering_request(ale, &tlv, MID_NA));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_HIGHER_LAYER_DATA_MSG                      #
########################################################################*/
static void higher_layer_data_msg_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    map_higher_layer_data_tlv_t *tlv;

    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_HIGHER_LAYER_DATA, RELAY_INDICATOR_OFF, g_src_ifname, 1);

    fail_unless(!!(tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_HIGHER_LAYER_DATA, cmdu)));
    fail_unless(tlv->protocol == 123);
    fail_unless(!memcmp(tlv->payload, "test", 4));
    fail_unless(tlv->payload_len == 4);
}

START_TEST(test_higher_layer_data_msg)
{
    map_ale_info_t *ale;

    g_mlo_test = false;
    test_init(higher_layer_data_msg_send_cb, NULL, &ale);

    fail_unless(!map_send_higher_layer_data_msg(ale, 123, (uint8_t*)"test", 4, MID_NA));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_CHANNEL_SCAN_REQUEST                       #
########################################################################*/
static void channel_scan_request_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_CHANNEL_SCAN_REQUEST, RELAY_INDICATOR_OFF, g_src_ifname, 1);

    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_CHANNEL_SCAN_REQUEST, cmdu));
}

START_TEST(test_channel_scan_request)
{
    map_ale_info_t                 *ale;
    map_channel_scan_request_tlv_t  tlv = {0};

    g_mlo_test = false;
    test_init(channel_scan_request_send_cb, NULL, &ale);

    fail_unless(!map_send_channel_scan_request(ale, &tlv, MID_NA));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_CAC_REQUEST                                #
########################################################################*/
static void cac_request_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_CAC_REQUEST, RELAY_INDICATOR_OFF, g_src_ifname, 1);

    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_CAC_REQUEST, cmdu));
}

START_TEST(test_cac_request)
{
    map_ale_info_t        *ale;
    map_cac_request_tlv_t  tlv = {0};

    g_mlo_test = false;
    test_init(cac_request_send_cb, NULL, &ale);

    /* Fill in something valid as this is checked */
    tlv.radios_nr = 1;
    maccpy(tlv.radios[0].radio_id, g_radio_id_5G);
    tlv.radios[0].cac_method = MAP_CAC_METHOD_MIMO_DIM_REDUCED;
    tlv.radios[0].op_class   = 121;
    tlv.radios[0].channel    = 200; /* Invalid */
    fail_unless(map_send_cac_request(ale, &tlv, MID_NA));
    fail_unless(stub_i1905_get_send_nr() == 0);

    tlv.radios[0].channel    = 100; /* Valid */
    fail_unless(!map_send_cac_request(ale, &tlv, MID_NA));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_CAC_TERMINATION                            #
########################################################################*/
static void cac_termination_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_CAC_TERMINATION, RELAY_INDICATOR_OFF, g_src_ifname, 1);

    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_CAC_TERMINATION, cmdu));
}

START_TEST(test_cac_termination)
{
    map_ale_info_t            *ale;
    map_cac_termination_tlv_t  tlv = {0};

    g_mlo_test = false;
    test_init(cac_termination_send_cb, NULL, &ale);

    fail_unless(!map_send_cac_termination(ale, &tlv, MID_NA));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_PROXIED_ENCAP_DPP                          #
########################################################################*/
static void proxied_encap_dpp_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    bool *chirp = args;

    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_PROXIED_ENCAP_DPP, RELAY_INDICATOR_OFF, g_src_ifname, *chirp ? 2 : 1);

    fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_1905_ENCAP_DPP, cmdu));
    if (*chirp) {
        fail_unless(!!i1905_get_tlv_from_cmdu(TLV_TYPE_DPP_CHIRP_VALUE, cmdu));
    }
}

START_TEST(test_proxied_encap_dpp)
{
    map_ale_info_t            *ale;
    map_1905_encap_dpp_tlv_t   encap_tlv = {0};
    map_dpp_chirp_value_tlv_t  chirp_tlv = {0};
    bool                       chirp = false;

    g_mlo_test = false;
    test_init(proxied_encap_dpp_send_cb, &chirp, &ale);

    fail_unless(!map_send_proxied_encap_dpp(ale, &encap_tlv, NULL, MID_NA));
    chirp = true;
    fail_unless(!map_send_proxied_encap_dpp(ale, &encap_tlv, &chirp_tlv, MID_NA));
    fail_unless(stub_i1905_get_send_nr() == 2);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_DPP_CCE_INDICATION                         #
########################################################################*/
static void dpp_cce_indication_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    map_dpp_cce_indication_tlv_t *tlv;
    uint8_t                      *advertise = args;

    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_DPP_CCE_INDICATION, RELAY_INDICATOR_OFF, g_src_ifname, 1);

    fail_unless(!!(tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_DPP_CCE_INDICATION, cmdu)));
    fail_unless(tlv->advertise == *advertise);
}

START_TEST(test_dpp_cce_indication)
{
    map_ale_info_t *ale;
    uint8_t         advertise = 1;

    g_mlo_test = false;
    test_init(dpp_cce_indication_send_cb, &advertise, &ale);
    fail_unless(!map_send_dpp_cce_indication(ale, advertise, MID_NA));
    advertise = 0;
    fail_unless(!map_send_dpp_cce_indication(ale, advertise, MID_NA));
    fail_unless(stub_i1905_get_send_nr() == 2);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_BACKHAUL_STA_CAPABILITY_QUERY              #
########################################################################*/
static void backhaul_sta_capability_query_send_cb(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid, void *args)
{
    check_cmdu(dmac, g_al_mac, cmdu, CMDU_TYPE_MAP_BACKHAUL_STA_CAPABILITY_QUERY, RELAY_INDICATOR_OFF, g_src_ifname, 0);
}

START_TEST(test_backhaul_sta_capability_query)
{
    map_ale_info_t *ale;

    g_mlo_test = false;
    test_init(backhaul_sta_capability_query_send_cb, NULL, &ale);

    fail_unless(!map_send_backhaul_sta_capability_query(ale, MID_NA));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_RAW                                        #
########################################################################*/
static void raw_cb(char *ifname, mac_addr dmac, mac_addr smac, uint16_t eth_type, uint8_t *data, uint16_t data_len, void *args)
{
    fail_unless(!strcmp(ifname, "eth0"));
    fail_unless(!maccmp(dmac, g_bssid_2G_fh));
    fail_unless(!maccmp(smac, g_bssid_5G_fh));
    fail_unless(eth_type = 0x1234);
    fail_unless(data_len == 4);
    fail_unless(!memcmp(data, (uint8_t[]){0x00,0x01,0x02,0x03}, 4));
}

START_TEST(test_raw)
{
    g_mlo_test = false;
    test_init(NULL, NULL, NULL);

    stub_i1905_register_raw_send_cb(raw_cb, NULL);

    fail_unless(!map_send_raw("eth0", g_bssid_2G_fh, g_bssid_5G_fh, 0x1234, (uint8_t[]){0x00,0x01,0x02,0x03}, 4));
    fail_unless(stub_i1905_get_send_nr() == 1);

    test_fini();
}
END_TEST


const char *test_suite_name = "cmdu_tx";
test_case_t test_cases[] = {
    /* lldp */
    TEST("bridge_discovery",                test_bridge_discovery  ),
    /* 1905.1 */
    TEST("topology_discovery",              test_topology_discovery  ),
    TEST("topology_query",                  test_topology_query  ),
    TEST("topology_response",               test_topology_response  ),
    TEST("link_metric_query",               test_link_metric_query  ),
    TEST("link_metric_response",            test_link_metric_response  ),
    TEST("link_metric_response_error",      test_link_metric_response_error  ),
    TEST("autoconfig_search",               test_autoconfig_search  ),
    TEST("autoconfig_response",             test_autoconfig_response  ),
    TEST("autoconfig_wsc_m2",               test_autoconfig_wsc_m2  ),
    TEST("autoconfig_wsc_m2_mld",           test_autoconfig_wsc_m2_mld  ),
    TEST("autoconfig_renew",                test_autoconfig_renew  ),
    TEST("autoconfig_renew_ucast",          test_autoconfig_renew_ucast  ),
    TEST("vendor_specific",                 test_vendor_specific  ),
    TEST("vendor_specific_mult_tlvs",       test_vendor_specific_mult_tlvs  ),
    /* MAP R1 */
    TEST("ack",                             test_ack  ),
    TEST("ack_sta_error",                   test_ack_sta_error  ),
    TEST("ap_capability_query",             test_ap_capability_query  ),
    TEST("test_policy_config_request",      test_policy_config_request  ),
    TEST("channel_preference_query",        test_channel_preference_query  ),
    TEST("channel_selection_request",       test_channel_selection_request  ),
    TEST("client_capability_query",         test_client_capability_query  ),
    TEST("ap_metrics_query",                test_ap_metrics_query  ),
    TEST("assoc_sta_link_metrics_query",    test_assoc_sta_link_metrics_query  ),
    TEST("unassoc_sta_link_metrics_query",  test_unassoc_sta_link_metrics_query  ),
    TEST("combined_infrastructure_metrics", test_combined_infrastructure_metrics  ),
    TEST("client_steering_request",         test_client_steering_request  ),
    TEST("client_acl_request",              test_client_acl_request  ),
    TEST("beacon_metrics_query",            test_beacon_metrics_query  ),
    TEST("backhaul_steering_request",       test_backhaul_steering_request  ),
    TEST("higher_layer_data_msg",           test_higher_layer_data_msg  ),
    /* MAP R2 */
    TEST("channel_scan_request",            test_channel_scan_request  ),
    TEST("cac_request",                     test_cac_request  ),
    TEST("cac_termination",                 test_cac_termination  ),
    TEST("backhaul_sta_capability_query",   test_backhaul_sta_capability_query  ),
    /* MAP R3 */
    TEST("proxied_encap_dpp",               test_proxied_encap_dpp  ),
    TEST("dpp_cce_indication",              test_dpp_cce_indication  ),
    /* RAW */
    TEST("raw",                             test_raw  ),
    { NULL},
};
