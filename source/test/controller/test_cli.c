/*
 * Copyright (c) 2021-2024 AirTies Wireless Networks
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

#include "test.h"

#include "map_ctrl_cli.h"
#include "map_ctrl_emex_tlv_handler.h"
#include "map_data_model.h"
#include "map_config.h"
#include "map_tlvs.h"

#include "stub/stub_map_ctrl_cmdu_tx.h"
#include "../libutils/stub/stub_map_cli.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define AL_MAC_STR     "F6:17:B8:86:57:61"
#define AL_MAC_QSTR    "\"F6:17:B8:86:57:61\""

#define RADIO_ID_STR   "F4:17:B8:86:57:61"
#define RADIO_ID_QSTR  "\"F4:17:B8:86:57:61\""

#define RADIO2_ID_STR  "F4:17:B8:86:57:62"
#define RADIO2_ID_QSTR "\"F4:17:B8:86:57:62\""

#define BSSID_STR      "F2:17:B8:86:57:61"
#define BSSID_QSTR     "\"F2:17:B8:86:57:61\""

#define BSSID2_STR     "F2:17:B8:86:57:62"
#define BSSID2_QSTR    "\"F2:17:B8:86:57:62\""

#define STA_MAC_STR    "A8:DB:03:05:92:C1"
#define STA_MAC_QSTR   "\"A8:DB:03:05:92:C1\""

#define STA2_MAC_STR   "A8:DB:03:05:92:C2"
#define STA2_MAC_QSTR  "\"A8:DB:03:05:92:C2\""

#define STA3_MAC_STR   "A8:DB:03:05:92:C3"
#define STA3_MAC_QSTR  "\"A8:DB:03:05:92:C3\""

#define PBUF_CONTAINS(s) !!strcasestr(g_print_buf, s)

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static mac_addr          g_al_mac    = {0xF6, 0x17, 0xB8, 0x86, 0x57, 0x61};
static mac_addr          g_radio_id  = {0xF4, 0x17, 0xB8, 0x86, 0x57, 0x61};
static mac_addr          g_radio2_id = {0xF4, 0x17, 0xB8, 0x86, 0x57, 0x62};
static mac_addr          g_bssid     = {0xF2, 0x17, 0xB8, 0x86, 0x57, 0x61};
static mac_addr          g_bssid2    = {0xF2, 0x17, 0xB8, 0x86, 0x57, 0x62};
static mac_addr          g_sta_mac   = {0xA8, 0xDB, 0x03, 0x05, 0x92, 0xC1};
static mac_addr          g_sta2_mac  = {0xA8, 0xDB, 0x03, 0x05, 0x92, 0xC2};
static mac_addr          g_sta3_mac  = {0xA8, 0xDB, 0x03, 0x05, 0x92, 0xC3};

static map_ale_info_t   *g_ale;
static map_radio_info_t *g_radio;
static map_radio_info_t *g_radio2;
static map_bss_info_t   *g_bss;
static map_bss_info_t   *g_bss2;
static map_sta_info_t   *g_sta;
static map_sta_info_t   *g_sta2;
static map_sta_info_t   *g_sta3;

static bool              g_cb_called;
static char             *g_print_buf;

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
static void print_buf_init(void)
{
    free(g_print_buf);
    fail_unless(!!(g_print_buf = strdup("")));
}

static void test_init(void)
{
    map_cfg_get()->is_master = true;

    fail_unless(!map_info_init());
    fail_unless(!map_dm_init());
    fail_unless(!map_cli_init());

    /* Add some data */
    fail_unless(!!(g_ale    = map_dm_create_ale  (g_al_mac)));
    fail_unless(!!(g_radio  = map_dm_create_radio(g_ale,   g_radio_id)));
    fail_unless(!!(g_radio2 = map_dm_create_radio(g_ale,   g_radio2_id)));
    fail_unless(!!(g_bss    = map_dm_create_bss  (g_radio, g_bssid)));
    fail_unless(!!(g_bss2   = map_dm_create_bss  (g_radio2, g_bssid2)));
    fail_unless(!!(g_sta    = map_dm_create_sta  (g_bss,   g_sta_mac)));
    fail_unless(!!(g_sta2   = map_dm_create_sta  (g_bss,   g_sta_mac)));
    fail_unless(!!(g_sta3   = map_dm_create_sta  (g_bss2,  g_sta_mac)));

    print_buf_init();
    stub_map_cli_set_print_buf(&g_print_buf);

    g_cb_called = false;
}

static void test_fini(void)
{
    stub_map_cli_set_print_buf(NULL);
    stub_cmdu_tx_register_send_topology_query_cb(NULL);
    stub_cmdu_tx_register_send_link_metric_query_cb(NULL);
    stub_cmdu_tx_register_send_autoconfig_renew_cb(NULL);
    stub_cmdu_tx_register_send_autoconfig_renew_ucast_cb(NULL);
    stub_cmdu_tx_register_send_ap_capability_query_cb(NULL);
    stub_cmdu_tx_register_send_channel_preference_query_cb(NULL);
    stub_cmdu_tx_register_send_client_capability_query_cb(NULL);
    stub_cmdu_tx_register_send_assoc_sta_link_metrics_query_cb(NULL);
    stub_cmdu_tx_register_send_unassoc_sta_link_metrics_query_cb(NULL);
    stub_cmdu_tx_register_send_beacon_metrics_query_cb(NULL);
    stub_cmdu_tx_register_send_combined_infrastructure_metrics_cb(NULL);
    stub_cmdu_tx_register_send_client_steering_request_cb(NULL);
    stub_cmdu_tx_register_send_client_acl_request_cb(NULL);
    stub_cmdu_tx_register_send_backhaul_sta_capability_query_cb(NULL);
    stub_cmdu_tx_register_send_backhaul_steering_request_cb(NULL);
    stub_cmdu_tx_register_send_policy_config_request_cb(NULL);
    stub_cmdu_tx_register_send_channel_scan_request_cb(NULL);
    stub_cmdu_tx_register_send_cac_request_cb(NULL);
    stub_cmdu_tx_register_send_cac_termination_cb(NULL);
    stub_cmdu_tx_register_send_dpp_cce_indication_cb(NULL);
    stub_cmdu_tx_register_send_proxied_encap_dpp_cb(NULL);
    stub_cmdu_tx_register_send_raw_cb(NULL);

    SFREE(g_print_buf);

    map_cli_fini();
    map_dm_fini();
    map_info_fini();
}

static int map_cli_exec(char *cmd, char *payload)
{
    print_buf_init();

    return stub_map_cli_exec(cmd, payload);
}

static void test_cmd_help(char *cmd)
{
    fail_unless(!map_cli_exec(cmd, "{\"args\":\"help\"}"));

    fail_unless(PBUF_CONTAINS("Help"));
    fail_unless(PBUF_CONTAINS("Example"));
    fail_unless(PBUF_CONTAINS(cmd));
}

/*#######################################################################
#                       TEST_HELP                                       #
########################################################################*/
START_TEST(test_help)
{
    test_init();

    fail_unless(!map_cli_exec("help", NULL));
    fail_unless(PBUF_CONTAINS("dumpCtrlInfo"));
    fail_unless(PBUF_CONTAINS("sendTopologyQuery"));
    fail_unless(PBUF_CONTAINS("sendWFACAPI"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_INVALID                                    #
########################################################################*/
START_TEST(test_invalid)
{
    test_init();

    fail_unless(map_cli_exec("invalid", NULL));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_VERSION                                    #
########################################################################*/
START_TEST(test_version)
{
    test_init();

    map_cfg_get()->version = "test";

    fail_unless(!map_cli_exec("version", NULL));
    fail_unless(PBUF_CONTAINS("test"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_CASE_INSENSITIVE                           #
########################################################################*/
START_TEST(test_case_insensitive)
{
    test_init();

    map_cfg_get()->version = "test";

    fail_unless(!map_cli_exec("VeRsIoN", NULL));
    fail_unless(PBUF_CONTAINS("test"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_DUMP_CTRL_INFO                             #
########################################################################*/
START_TEST(test_dump_ctrl_info)
{
    test_init();

    fail_unless(!map_cli_exec("dumpCtrlInfo", NULL));
    fail_unless(PBUF_CONTAINS(AL_MAC_STR));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_DUMP_INTERFACES                            #
########################################################################*/
START_TEST(test_dump_interfaces)
{
    test_init();

    fail_unless(!map_cli_exec("dumpInterfaces", NULL));
    fail_unless(PBUF_CONTAINS("eth0"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_DUMP_BLOCKLIST                             #
########################################################################*/
START_TEST(test_dump_blocklist)
{
    test_init();

    fail_unless(!map_cli_exec("dumpBlockList", NULL));
    fail_unless(PBUF_CONTAINS("dump blocklist"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_DUMP_OP_CLASSES                            #
########################################################################*/
START_TEST(test_dump_op_classes)
{
    test_init();

    fail_unless(!map_cli_exec("dumpOpClasses", NULL));
    fail_unless(PBUF_CONTAINS("     81   2.4GHz    20MHz       no       13  1,2,3,4,5,6,7,8,9,10,11,12,13"));
    fail_unless(PBUF_CONTAINS("    137     6GHz   320MHz      yes        6  31,63,95,127,159,191"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_DUMP_CHAN_SEL                              #
########################################################################*/
START_TEST(test_dump_chan_sel)
{
    test_init();

    print_buf_init();
    fail_unless(!map_cli_exec("dumpChanSel", NULL));
    fail_unless(PBUF_CONTAINS("dump chan_sel") && !PBUF_CONTAINS("ALE") && !PBUF_CONTAINS("EXT"));

    print_buf_init();
    fail_unless(!map_cli_exec("dumpChanSel", "{\"extended\":true}"));
    fail_unless(PBUF_CONTAINS("dump chan_sel") && !PBUF_CONTAINS("ALE") && PBUF_CONTAINS("EXT"));

    print_buf_init();
    fail_unless(!map_cli_exec("dumpChanSel", "{\"almac\":"AL_MAC_QSTR"}"));
    fail_unless(PBUF_CONTAINS("dump chan_sel") && PBUF_CONTAINS("ALE") && !PBUF_CONTAINS("EXT"));

    print_buf_init();
    fail_unless(!map_cli_exec("dumpChanSel", "{\"almac\":"AL_MAC_QSTR",\"extended\":true}"));
    fail_unless(PBUF_CONTAINS("dump chan_sel") && PBUF_CONTAINS("ALE") && PBUF_CONTAINS("EXT"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_DUMP_TUNNELED_MESSAGE                      #
########################################################################*/
START_TEST(test_dump_tunneled_message)
{
    map_tunneled_msg_t *tm;
    int i;

    test_init();

    /* Add some tunneled message */
    fail_unless(!!(tm = calloc(1, sizeof(*tm))));
    fail_unless(!!(tm->assoc_req_body = malloc(8)));
    tm->assoc_req_body_len = 8;
    for (i = 0; i < 8; i++) {
        tm->assoc_req_body[i] = i;
    }

    g_sta->tunneled_msg = tm;
    fail_unless(!map_cli_exec("dumpTunneledMessage", "{\"mac\":"STA_MAC_QSTR",\"msgtype\":\"assoc\"}"));
    fail_unless(PBUF_CONTAINS("ASSOC_REQ BODY"));
    fail_unless(PBUF_CONTAINS("0001020304050607"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_DUMP_AP_METRICS                            #
########################################################################*/
START_TEST(test_dump_ap_metrics)
{
    test_init();

    g_bss->metrics.channel_utilization = 10;
    g_bss->metrics.esp_present = 0xf0;
    g_bss->extended_metrics.tx_ucast_bytes = 100;

    fail_unless(!map_cli_exec("dumpAPMetrics", "{\"bssid\":"BSSID_QSTR"}"));
    fail_unless(PBUF_CONTAINS("Channel util  : 10"));
    fail_unless(PBUF_CONTAINS("AC-BE"));
    fail_unless(PBUF_CONTAINS("-unicast bytes tx   : 100"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_DUMP_RADIO_METRICS                         #
########################################################################*/
START_TEST(test_dump_radio_metrics)
{
    test_init();

    g_radio->radio_metrics.transmit      = 10;
    g_radio->radio_metrics.receive_self  = 15;
    g_radio->radio_metrics.receive_other = 20;

    fail_unless(!map_cli_exec("dumpRadioMetrics", "{\"almac\":"AL_MAC_QSTR",\"radio_id\":"RADIO_ID_QSTR"}"));
    fail_unless(PBUF_CONTAINS("Transmit: 3.92 %"));
    fail_unless(PBUF_CONTAINS("Receive Self: 5.88 %"));
    fail_unless(PBUF_CONTAINS("Receive Other: 7.84 %"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_DUMP_STA_METRICS                           #
########################################################################*/
START_TEST(test_dump_sta_metrics)
{
    map_sta_link_metrics_t     *lm;
    map_sta_ext_link_metrics_t *elm;

    test_init();

    test_cmd_help("dumpStaMetrics");

    /* Link metrics */
    lm = calloc(1, sizeof(*lm));
    lm->dl_mac_datarate = 1000;
    lm->rssi            = -50;
    push_object(g_sta->metrics, lm);

    fail_unless(!map_cli_exec("dumpStaMetrics", "{\"stamac\":"STA_MAC_QSTR",\"type\":\"metrics\"}"));
    fail_unless(PBUF_CONTAINS(BSSID_STR));
    fail_unless(PBUF_CONTAINS("dl_mac_datarate: 1000 Mbps"));
    fail_unless(PBUF_CONTAINS("rssi: -50 dBm"));

    /* Extended link metrics */
    elm = &g_sta->last_sta_ext_metrics;
    elm->no_of_bss_metrics = 1;
    fail_unless(!!(elm->ext_bss_metrics_list = calloc(1, sizeof(*elm->ext_bss_metrics_list))));
    maccpy(elm->ext_bss_metrics_list[0].bssid, g_bssid);
    elm->ext_bss_metrics_list[0].last_data_dl_rate = 6000;
    elm->ext_bss_metrics_list[0].utilization_tx = 40;

    fail_unless(!map_cli_exec("dumpStaMetrics", "{\"stamac\":"STA_MAC_QSTR",\"type\":\"extended_metrics\"}"));
    fail_unless(PBUF_CONTAINS(BSSID_STR));
    fail_unless(PBUF_CONTAINS("last_data_dl_rate: 6000 Kbps"));
    fail_unless(PBUF_CONTAINS("utilization_tx: 40 ms"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_GET_CHANNEL_SCAN_RESULTS                   #
########################################################################*/
START_TEST(test_get_channel_scan_results)
{
    map_scan_result_t *sr;

    test_init();

    test_cmd_help("getChannelScanResults");

    fail_unless(!!(sr = calloc(1, sizeof(*sr))));
    sr->opclass = 115;
    sr->channel = 36;
    strcpy((char*)sr->neighbor_info.ssid, "test_ssid");
    sr->neighbor_info.rcpi = 40;
    sr->neighbor_info.bss_load_elem_present = 1;
    sr->neighbor_info.stas_nr = 4;
    push_object(g_radio->scanned_bssid_list, sr);

    fail_unless(!map_cli_exec("getChannelScanResults", "{\"almac\":"AL_MAC_QSTR",\"radio_id\":"RADIO_ID_QSTR",\"type\":\"lastRequest\"}"));

    fail_unless(PBUF_CONTAINS("Opclass: 115"));
    fail_unless(PBUF_CONTAINS("Channel: 36"));
    fail_unless(PBUF_CONTAINS("SSID: test_ssid"));
    fail_unless(PBUF_CONTAINS("RSSI: -90 dBm"));
    fail_unless(PBUF_CONTAINS("STA Count: 4"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SET_CHANNEL                                #
########################################################################*/
START_TEST(test_set_channel)
{
    test_init();

    test_cmd_help("setChannel");

    fail_unless(!map_cli_exec("setChannel", "{\"almac\":"AL_MAC_QSTR",\"radio_id\":"RADIO_ID_QSTR",\"channel\":100}"));
    fail_unless(PBUF_CONTAINS("OK"));

    g_cb_called = false;
    fail_unless(!map_cli_exec("setChannel", "{\"almac\":"AL_MAC_QSTR",\"radio_id\":"RADIO_ID_QSTR",\"channel\":100, \"bandwidth\":20}"));
    fail_unless(PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_TOPOLOGY_QUERY                        #
########################################################################*/
static int send_topology_query_cb(void *args, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(args == g_ale);

    return 0;
}

START_TEST(test_send_topology_query)
{
    test_init();

    stub_cmdu_tx_register_send_topology_query_cb(send_topology_query_cb);
    fail_unless(!map_cli_exec("sendTopologyQuery", "{\"almac\":"AL_MAC_QSTR"}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_LINK_METRIC_QUERY                     #
########################################################################*/
static int send_link_metric_query_1_cb(map_ale_info_t *ale, i1905_link_metric_query_tlv_t *tlv, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(ale == g_ale);
    fail_unless(tlv->destination == LINK_METRIC_QUERY_TLV_ALL_NEIGHBORS);
    fail_unless(tlv->link_metrics_type == LINK_METRIC_QUERY_TLV_BOTH_TX_AND_RX_LINK_METRICS);

    return 0;
}

static int send_link_metric_query_2_cb(map_ale_info_t *ale, i1905_link_metric_query_tlv_t *tlv, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(ale == g_ale);
    fail_unless(tlv->destination == LINK_METRIC_QUERY_TLV_SPECIFIC_NEIGHBOR);
    fail_unless(tlv->link_metrics_type == LINK_METRIC_QUERY_TLV_RX_LINK_METRICS_ONLY);

    return 0;
}

START_TEST(test_send_link_metric_query)
{
    test_init();

    test_cmd_help("sendLinkMetricQuery");

    stub_cmdu_tx_register_send_link_metric_query_cb(send_link_metric_query_1_cb);
    fail_unless(!map_cli_exec("sendLinkMetricQuery", "{\"almac\":"AL_MAC_QSTR"}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    g_cb_called = false;
    stub_cmdu_tx_register_send_link_metric_query_cb(send_link_metric_query_2_cb);
    fail_unless(!map_cli_exec("sendLinkMetricQuery", "{\"almac\":"AL_MAC_QSTR",\"neighbor\":\"00:01:02:03:04:05\",\"type\":\"rx\"}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_AUTOCONFIG_RENEW                      #
########################################################################*/
static int send_autoconfig_renew_cb(uint8_t freq_band, uint16_t *mid, bool reset_onboarding)
{
    g_cb_called = true;

    return 0;
}

static int send_autoconfig_renew_ucast_cb(map_ale_info_t *ale, uint8_t freq_band, uint16_t *mid, bool reset_onboarding)
{
    g_cb_called = true;
    fail_unless(ale == g_ale);

    return 0;
}

START_TEST(test_send_autoconfig_renew)
{
    test_init();

    test_cmd_help("sendAutoconfigRenew");

    stub_cmdu_tx_register_send_autoconfig_renew_cb(send_autoconfig_renew_cb);
    fail_unless(!map_cli_exec("sendAutoconfigRenew", "{}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    stub_cmdu_tx_register_send_autoconfig_renew_cb(NULL);
    stub_cmdu_tx_register_send_autoconfig_renew_ucast_cb(send_autoconfig_renew_ucast_cb);
    fail_unless(!map_cli_exec("sendAutoConfigRenew", "{\"almac\":"AL_MAC_QSTR"}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_AP_CAPABILITY_QUERY                   #
########################################################################*/
static int send_ap_capability_query_cb(void *args, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(args == g_ale);

    return 0;
}

START_TEST(test_send_ap_capability_query)
{
    test_init();

    stub_cmdu_tx_register_send_ap_capability_query_cb(send_ap_capability_query_cb);
    fail_unless(!map_cli_exec("sendAPCapabilityQuery", "{\"almac\":"AL_MAC_QSTR"}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_CHANNEL_PREFERENCE_QUERY              #
########################################################################*/
static int send_channel_preference_query_cb(void *args, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(args == g_ale);

    return 0;
}

START_TEST(test_send_channel_preference_query)
{
    test_init();

    stub_cmdu_tx_register_send_channel_preference_query_cb(send_channel_preference_query_cb);
    fail_unless(!map_cli_exec("sendChannelPreferenceQuery", "{\"almac\":"AL_MAC_QSTR"}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_CLIENT_CAPABILITY_QUERY               #
########################################################################*/
static int send_client_capability_query_cb(void *args, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(args == g_sta);

    return 0;
}

START_TEST(test_send_client_capability_query)
{
    test_init();

    stub_cmdu_tx_register_send_client_capability_query_cb(send_client_capability_query_cb);
    fail_unless(!map_cli_exec("sendClientCapabilityQuery", "{\"almac\":"AL_MAC_QSTR",\"stamac\":"STA_MAC_QSTR"}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_ASSOC_STA_LINK_METRICS_QUERY          #
########################################################################*/
static int send_assoc_sta_link_metrics_query_cb(void *args, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(args == g_sta);

    return 0;
}

START_TEST(test_send_assoc_sta_link_metrics_query)
{
    test_init();

    stub_cmdu_tx_register_send_assoc_sta_link_metrics_query_cb(send_assoc_sta_link_metrics_query_cb);
    fail_unless(!map_cli_exec("sendAssocStaLinkMetricsQuery", "{\"almac\":"AL_MAC_QSTR",\"stamac\":"STA_MAC_QSTR"}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_UNASSOC_STA_LINK_METRICS_QUERY        #
########################################################################*/
static int send_unassoc_sta_link_metrics_query_cb(map_ale_info_t *ale, map_unassoc_sta_link_metrics_query_tlv_t *tlv, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(ale == g_ale);
    fail_unless(tlv->op_class == 115);
    fail_unless(tlv->channels_nr == 2);
    fail_unless(tlv->channels[0].channel == 36);
    fail_unless(tlv->channels[0].sta_macs_nr == 2);
    fail_unless(!maccmp(tlv->channels[0].sta_macs[0], g_sta_mac));
    fail_unless(!maccmp(tlv->channels[0].sta_macs[1], g_sta2_mac));
    fail_unless(tlv->channels[1].channel == 40);
    fail_unless(tlv->channels[1].sta_macs_nr == 1);
    fail_unless(!maccmp(tlv->channels[1].sta_macs[0], g_sta3_mac));

    return 0;
}

START_TEST(test_send_unassoc_sta_link_metrics_query)
{
    test_init();

    test_cmd_help("sendUnassocStaLinkMetricsQuery");

    stub_cmdu_tx_register_send_unassoc_sta_link_metrics_query_cb(send_unassoc_sta_link_metrics_query_cb);
    fail_unless(!map_cli_exec("sendUnassocStaLinkMetricsQuery", "{\"almac\":"AL_MAC_QSTR",\"opclass\":115,\"channels\":[{\"channel\":36,\"stamacs\":["STA_MAC_QSTR","STA2_MAC_QSTR"]},{\"channel\":40,\"stamacs\":["STA3_MAC_QSTR"]}]}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_BEACON_METRICS_QUERY                  #
########################################################################*/
static int send_beacon_metrics_query_1_cb(map_ale_info_t *ale, map_beacon_metrics_query_tlv_t *tlv, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(ale == g_ale);
    fail_unless(tlv->op_class == 115);
    fail_unless(tlv->channel == 36);
    fail_unless(!maccmp(tlv->bssid, g_bssid));
    fail_unless(tlv->reporting_detail == MAP_BEACON_REPORT_DETAIL_NONE);
    fail_unless(tlv->ssid_len == strlen("test_ssid"));
    fail_unless(!memcmp(tlv->ssid, (uint8_t*)"test_ssid", tlv->ssid_len));
    fail_unless(tlv->ap_channel_reports_nr == 0);

    return 0;
}

static int send_beacon_metrics_query_2_cb(map_ale_info_t *ale, map_beacon_metrics_query_tlv_t *tlv, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(ale == g_ale);
    fail_unless(tlv->op_class == 0);
    fail_unless(tlv->channel == 255);
    fail_unless(!maccmp(tlv->bssid, g_bssid));
    fail_unless(tlv->reporting_detail == MAP_BEACON_REPORT_DETAIL_ALL);
    fail_unless(tlv->ssid_len == 0);
    fail_unless(tlv->ap_channel_reports_nr == 2);
    fail_unless(tlv->ap_channel_reports[0].op_class == 115);
    fail_unless(map_cs_nr(&tlv->ap_channel_reports[0].channels) == 3);
    fail_unless(map_cs_is_set(&tlv->ap_channel_reports[0].channels, 36));
    fail_unless(map_cs_is_set(&tlv->ap_channel_reports[0].channels, 40));
    fail_unless(map_cs_is_set(&tlv->ap_channel_reports[0].channels, 44));
    fail_unless(tlv->ap_channel_reports[1].op_class == 118);
    fail_unless(map_cs_nr(&tlv->ap_channel_reports[1].channels) == 2);
    fail_unless(map_cs_is_set(&tlv->ap_channel_reports[1].channels, 52));
    fail_unless(map_cs_is_set(&tlv->ap_channel_reports[1].channels, 64));

    return 0;
}

START_TEST(test_send_beacon_metrics_query)
{
    test_init();

    test_cmd_help("sendBeaconMetricsQuery");

    stub_cmdu_tx_register_send_beacon_metrics_query_cb(send_beacon_metrics_query_1_cb);
    fail_unless(!map_cli_exec("sendBeaconMetricsQuery", "{\"almac\":"AL_MAC_QSTR",\"stamac\":"STA_MAC_QSTR",\"opclass\":115,\"channel\":36,\"bssid\":"BSSID_QSTR",\"reporting_detail\":\"none\",\"ssid\":\"test_ssid\",\"ap_channel_reports\":[]}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    g_cb_called = false;
    stub_cmdu_tx_register_send_beacon_metrics_query_cb(send_beacon_metrics_query_2_cb);
    fail_unless(!map_cli_exec("sendBeaconMetricsQuery", "{\"almac\":"AL_MAC_QSTR",\"stamac\":"STA_MAC_QSTR",\"opclass\":0,\"channel\":255,\"bssid\":"BSSID_QSTR",\"reporting_detail\":\"all\",\"ssid\":\"\",\"ap_channel_reports\":[{\"opclass\":115,\"channels\":[36,40,44]},{\"opclass\":118,\"channels\":[52,64]}]}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_COMBINED_INFRASTRUCTURE_METRICS       #
########################################################################*/
static int send_combined_infrastructure_metrics_cb(map_ale_info_t *ale, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(ale == g_ale);

    return 0;
}

START_TEST(test_send_combined_infrastructure_metrics)
{
    test_init();

    stub_cmdu_tx_register_send_combined_infrastructure_metrics_cb(send_combined_infrastructure_metrics_cb);
    fail_unless(!map_cli_exec("sendCombinedInfrastructureMetrics", "{\"almac\":"AL_MAC_QSTR"}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_CLIENT_STEERING_REQUEST               #
########################################################################*/
static int send_client_steering_request_cb(map_ale_info_t *ale, map_steer_t *steer, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(ale == g_ale);
    fail_unless(steer->flags == (MAP_STEERING_REQUEST_FLAG_MANDATE | MAP_STEERING_REQUEST_FLAG_BTM_DISASSOC_IMMINENT | MAP_STEERING_REQUEST_FLAG_BTM_ABRIDGED));
    fail_unless(!maccmp(steer->bssid, g_bssid));
    fail_unless(steer->opportunity_wnd == 100);
    fail_unless(steer->disassociation_timer == 6000);
    fail_unless(steer->sta_bssid_nr == 1);
    fail_unless(!maccmp(steer->sta_bssid[0].sta_mac, g_sta_mac));
    fail_unless(!maccmp(steer->sta_bssid[0].target_bssid, g_bssid2));
    fail_unless(steer->sta_bssid[0].op_class == 115);
    fail_unless(steer->sta_bssid[0].channel == 36);
    fail_unless(steer->sta_bssid[0].reason == 2);

    return 0;
}

START_TEST(test_send_client_steering_request)
{
    test_init();

    test_cmd_help("sendClientSteeringRequest");

    stub_cmdu_tx_register_send_client_steering_request_cb(send_client_steering_request_cb);
    fail_unless(!map_cli_exec("sendClientSteeringRequest", "{\"almac\":"AL_MAC_QSTR",\"bssid\":"BSSID_QSTR",\"mode\":\"mandate\",\"disassoc_imminent\":true, \"abridged\":true,\"opp_window\":100,\"disassoc_timer\":6000,\"targets\":[{\"stamac\":"STA_MAC_QSTR",\"bssid\":"BSSID2_QSTR",\"opclass\":115,\"channel\":36,\"reason\":2}]}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_CLIENT_ASSOC_CONTROL_REQUEST          #
########################################################################*/
static int send_client_acl_request_cb(map_ale_info_t *ale, map_client_assoc_control_request_tlv_t *tlv, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(ale == g_ale);
    fail_unless(!maccmp(tlv->bssid, g_bssid));
    fail_unless(tlv->association_control == MAP_CLIENT_ASSOC_CONTROL_BLOCK);
    fail_unless(tlv->validity_period == 30);
    fail_unless(tlv->sta_macs_nr == 2);
    fail_unless(!maccmp(tlv->sta_macs[0], g_sta_mac));
    fail_unless(!maccmp(tlv->sta_macs[1], g_sta2_mac));

    return 0;
}

START_TEST(test_send_client_assoc_control_request)
{
    test_init();

    test_cmd_help("sendClientAssocControlRequest");

    stub_cmdu_tx_register_send_client_acl_request_cb(send_client_acl_request_cb);
    fail_unless(!map_cli_exec("sendClientAssocControlRequest", "{\"almac\":"AL_MAC_QSTR",\"bssid\":"BSSID_QSTR",\"block\":true,\"period\":30,\"stamacs\":["STA_MAC_QSTR","STA2_MAC_QSTR"]}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_BACKHAUL_STA_CAPABILITY_QUERY         #
########################################################################*/
static int send_backhaul_sta_capability_query_cb(map_ale_info_t *ale, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(ale == g_ale);

    return 0;
}

START_TEST(test_send_backhaul_sta_capability_query)
{
    test_init();

    stub_cmdu_tx_register_send_backhaul_sta_capability_query_cb(send_backhaul_sta_capability_query_cb);
    fail_unless(!map_cli_exec("sendBackhaulStaCapabilityQuery", "{\"almac\":"AL_MAC_QSTR"}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_BACKHAUL_STEERING_REQUEST             #
########################################################################*/
static int send_backhaul_steering_request_cb(map_ale_info_t *ale, map_backhaul_steering_request_tlv_t *tlv, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(ale == g_ale);
    fail_unless(!maccmp(tlv->bsta_mac, g_sta_mac));
    fail_unless(!maccmp(tlv->target_bssid, g_bssid));
    fail_unless(tlv->target_op_class == 115);
    fail_unless(tlv->target_channel == 36);

    return 0;
}

START_TEST(test_send_backhaul_steering_request)
{
    test_init();

    test_cmd_help("sendBackhaulSteeringRequest");

    stub_cmdu_tx_register_send_backhaul_steering_request_cb(send_backhaul_steering_request_cb);
    fail_unless(!map_cli_exec("sendBackhaulSteeringRequest", "{\"almac\":"AL_MAC_QSTR",\"stamac\":"STA_MAC_QSTR",\"bssid\":"BSSID_QSTR",\"opclass\":115,\"channel\":36}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_UNSUCCESS_ASSOC_POLICY_CONF           #
########################################################################*/
static int send_assoc_unsuccess_policy_config_request_cb(map_ale_info_t *ale, map_policy_config_tlvs_t *tlvs, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(ale == g_ale);
    fail_unless(!!tlvs->unsuccess_assoc_policy_tlv);
    fail_unless(tlvs->unsuccess_assoc_policy_tlv->report_flag == MAP_UNSUCCESSFUL_ASSOC_REPORT);
    fail_unless(tlvs->unsuccess_assoc_policy_tlv->max_reporting_rate == 10);

    return 0;
}

START_TEST(test_send_unsuccess_assoc_policy_conf)
{
    test_init();

    test_cmd_help("sendUnsuccessAssocPolicyConf");

    stub_cmdu_tx_register_send_policy_config_request_cb(send_assoc_unsuccess_policy_config_request_cb);
    fail_unless(!map_cli_exec("sendUnsuccessAssocPolicyConf", "{\"almac\":"AL_MAC_QSTR",\"report\":true,\"max_reporting_rate\":10}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_BH_BSS_POLICY_CONF                    #
########################################################################*/
static int send_bh_bss_policy_config_request_cb(map_ale_info_t *ale, map_policy_config_tlvs_t *tlvs, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(ale == g_ale);
    fail_unless(tlvs->bh_bss_config_tlvs_nr == 2);
    fail_unless(!maccmp(tlvs->bh_bss_config_tlvs[0].bssid, g_bssid));
    fail_unless(tlvs->bh_bss_config_tlvs[0].p1_bsta_disallowed == 1);
    fail_unless(tlvs->bh_bss_config_tlvs[0].p2_bsta_disallowed == 0);
    fail_unless(!maccmp(tlvs->bh_bss_config_tlvs[1].bssid, g_bssid2));
    fail_unless(tlvs->bh_bss_config_tlvs[1].p1_bsta_disallowed == 0);
    fail_unless(tlvs->bh_bss_config_tlvs[1].p2_bsta_disallowed == 1);

    return 0;
}

START_TEST(test_send_bh_bss_policy_conf)
{
    test_init();

    test_cmd_help("sendBhBssPolicyConf");

    stub_cmdu_tx_register_send_policy_config_request_cb(send_bh_bss_policy_config_request_cb);
    fail_unless(!map_cli_exec("sendBhBssPolicyConf", "{\"no_of_bssid\":2,\"bssid_list\":[{\"bssid\":"BSSID_QSTR",\"p1_bsta_disallowed\":true,\"p2_bsta_disallowed\":false},{\"bssid\":"BSSID2_QSTR",\"p1_bsta_disallowed\":false,\"p2_bsta_disallowed\":true}]}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_CHANNEL_SCAN_REQUEST                  #
########################################################################*/
static int send_channel_scan_request_1_cb(map_ale_info_t *ale, map_channel_scan_request_tlv_t *tlv, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(ale == g_ale);
    fail_unless(tlv->fresh_scan_performed == 0);
    fail_unless(tlv->radios_nr == 1);
    fail_unless(!maccmp(tlv->radios[0].radio_id, g_radio_id));
    fail_unless(tlv->radios[0].op_classes_nr == 0);

    return 0;
}

static int send_channel_scan_request_2_cb(map_ale_info_t *ale, map_channel_scan_request_tlv_t *tlv, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(ale == g_ale);
    fail_unless(tlv->fresh_scan_performed == 1);
    fail_unless(tlv->radios_nr == 2);
    fail_unless(!maccmp(tlv->radios[0].radio_id, g_radio_id));
    fail_unless(tlv->radios[0].op_classes_nr == 2);
    fail_unless(tlv->radios[0].op_classes[0].op_class == 115);
    fail_unless(map_cs_nr(&tlv->radios[0].op_classes[0].channels) == 2);
    fail_unless(map_cs_is_set(&tlv->radios[0].op_classes[0].channels, 36));
    fail_unless(map_cs_is_set(&tlv->radios[0].op_classes[0].channels, 40));
    fail_unless(tlv->radios[0].op_classes[1].op_class == 118);
    fail_unless(map_cs_nr(&tlv->radios[0].op_classes[1].channels) == 0);
    fail_unless(!maccmp(tlv->radios[1].radio_id, g_radio2_id));
    fail_unless(tlv->radios[1].op_classes_nr == 1);
    fail_unless(tlv->radios[1].op_classes[0].op_class == 81);
    fail_unless(map_cs_nr(&tlv->radios[1].op_classes[0].channels) == 2);
    fail_unless(map_cs_is_set(&tlv->radios[1].op_classes[0].channels, 1));
    fail_unless(map_cs_is_set(&tlv->radios[1].op_classes[0].channels, 11));

    return 0;
}

START_TEST(test_send_channel_scan_request)
{
    test_init();

    test_cmd_help("sendChannelScanRequest");

    stub_cmdu_tx_register_send_channel_scan_request_cb(send_channel_scan_request_1_cb);
    fail_unless(!map_cli_exec("sendChannelScanRequest", "{\"almac\":"AL_MAC_QSTR",\"fresh_scan\":false,\"no_of_radios\":1,\"radio_list\":[{\"radio_id\":"RADIO_ID_QSTR",\"no_of_opclass\":0,\"opclass_list\":[]}]}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    g_cb_called = false;
    stub_cmdu_tx_register_send_channel_scan_request_cb(send_channel_scan_request_2_cb);
    fail_unless(!map_cli_exec("sendChannelScanRequest", "{\"almac\":"AL_MAC_QSTR",\"fresh_scan\":true,\"no_of_radios\":2,\"radio_list\":[{\"radio_id\":"RADIO_ID_QSTR",\"no_of_opclass\":2,\"opclass_list\":[{\"opclass\":115,\"no_of_channels\":2,\"channel_list\":[36,40]},{\"opclass\":118,\"no_of_channels\":0,\"channel_list\":[]}]},{\"radio_id\":"RADIO2_ID_QSTR",\"no_of_opclass\":1,\"opclass_list\":[{\"opclass\":81,\"no_of_channels\":2,\"channel_list\":[1,11]}]}]}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_CAC_REQUEST                           #
########################################################################*/
static int send_cac_request_cb(map_ale_info_t *ale, map_cac_request_tlv_t *tlv, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(ale == g_ale);
    fail_unless(tlv->radios_nr == 2);
    fail_unless(!maccmp(tlv->radios[0].radio_id, g_radio_id));
    fail_unless(tlv->radios[0].op_class == 122);
    fail_unless(tlv->radios[0].channel == 132);
    fail_unless(tlv->radios[0].cac_method == MAP_CAC_METHOD_TIME_SLICED);
    fail_unless(tlv->radios[0].cac_completion_action == MAP_CAC_ACTION_RETURN_PREV_OP_CONF);
    fail_unless(!maccmp(tlv->radios[1].radio_id, g_radio2_id));
    fail_unless(tlv->radios[1].op_class == 115);
    fail_unless(tlv->radios[1].channel == 100);
    fail_unless(tlv->radios[1].cac_method == MAP_CAC_METHOD_MIMO_DIM_REDUCED);
    fail_unless(tlv->radios[1].cac_completion_action == MAP_CAC_ACTION_REMAIN_AND_CONT_TO_MON);

    return 0;
}

START_TEST(test_send_cac_request)
{
    test_init();

    test_cmd_help("sendCACRequest");

    stub_cmdu_tx_register_send_cac_request_cb(send_cac_request_cb);
    fail_unless(!map_cli_exec("sendCACRequest", "{\"almac\":"AL_MAC_QSTR",\"no_of_reqs\":2,\"cac_req_list\":[{\"radio_id\":"RADIO_ID_QSTR",\"opclass\":122,\"channel\":132,\"cac_method\":\"time_sliced\",\"cac_completion_act\":\"return_prev_conf\"},{\"radio_id\":"RADIO2_ID_QSTR",\"opclass\":115,\"channel\":100,\"cac_method\":\"mimo_dim_reduced\",\"cac_completion_act\":\"remain_continue_mon\"}]}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_CAC_TERMINATION                       #
########################################################################*/
static int send_cac_termination_cb(map_ale_info_t *ale, map_cac_termination_tlv_t *tlv, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(ale == g_ale);
    fail_unless(tlv->radios_nr == 1);
    fail_unless(!maccmp(tlv->radios[0].radio_id, g_radio_id));
    fail_unless(tlv->radios[0].op_class == 122);
    fail_unless(tlv->radios[0].channel == 132);

    return 0;
}

START_TEST(test_send_cac_termination)
{
    test_init();

    test_cmd_help("sendCACTermination");

    stub_cmdu_tx_register_send_cac_termination_cb(send_cac_termination_cb);
    fail_unless(!map_cli_exec("sendCACTermination", "{\"almac\":"AL_MAC_QSTR",\"no_of_radios\":1,\"cac_radio_list\":[{\"radio_id\":"RADIO_ID_QSTR",\"opclass\":122,\"channel\":132}]}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_CH_SCAN_REPORT_POLICY_CONF            #
########################################################################*/
static int send_ch_scan_report_policy_config_request_cb(map_ale_info_t *ale, map_policy_config_tlvs_t *tlvs, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(ale == g_ale);
    fail_unless(!!tlvs->channel_scan_report_policy_tlv);
    fail_unless(tlvs->channel_scan_report_policy_tlv->report_independent_ch_scans == 1);

    return 0;
}

START_TEST(test_send_ch_scan_report_policy_conf)
{
    test_init();

    test_cmd_help("sendChScanReportPolicyConf");

    stub_cmdu_tx_register_send_policy_config_request_cb(send_ch_scan_report_policy_config_request_cb);
    fail_unless(!map_cli_exec("sendChScanReportPolicyConf", "{\"almac\":"AL_MAC_QSTR",\"report_indep_scans\":true}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_DPP_CCE_INDICATION                    #
########################################################################*/
static int send_dpp_cce_indication_cb(map_ale_info_t *ale, uint8_t advertise, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(ale == g_ale);
    fail_unless(advertise);

    return 0;
}

START_TEST(test_send_dpp_cce_indication)
{
    test_init();

    test_cmd_help("sendDPPCCEIndication");

    stub_cmdu_tx_register_send_dpp_cce_indication_cb(send_dpp_cce_indication_cb);
    fail_unless(!map_cli_exec("sendDPPCCEIndication", "{\"almac\":"AL_MAC_QSTR",\"advertise\":true}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_PROXIED_ENCAP_DPP                     #
########################################################################*/
static int send_proxied_encap_dpp_1_cb(map_ale_info_t *ale, map_1905_encap_dpp_tlv_t *encap_tlv, map_dpp_chirp_value_tlv_t *chirp_tlv, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(ale == g_ale);
    fail_unless(!!encap_tlv);
    fail_unless(!chirp_tlv);
    fail_unless(encap_tlv->enrollee_mac_present == 1);
    fail_unless(!maccmp(encap_tlv->sta_mac, g_sta_mac));
    fail_unless(encap_tlv->dpp_frame_indicator == 1);
    fail_unless(encap_tlv->frame_type == 10);
    fail_unless(encap_tlv->frame_len == 4);
    fail_unless(!memcmp(encap_tlv->frame, (uint8_t[]){0xAA, 0xBB, 0xCC, 0xDD}, 4));

    return 0;
}

static int send_proxied_encap_dpp_2_cb(map_ale_info_t *ale, map_1905_encap_dpp_tlv_t *encap_tlv, map_dpp_chirp_value_tlv_t *chirp_tlv, uint16_t *mid)
{
    g_cb_called = true;
    fail_unless(ale == g_ale);
    fail_unless(!!encap_tlv);
    fail_unless(!!chirp_tlv);
    fail_unless(encap_tlv->enrollee_mac_present == 0);
    fail_unless(encap_tlv->dpp_frame_indicator == 1);
    fail_unless(encap_tlv->frame_type == 10);
    fail_unless(encap_tlv->frame_len == 4);
    fail_unless(!memcmp(encap_tlv->frame, (uint8_t[]){0xAA, 0xBB, 0xCC, 0xDD}, 4));
    fail_unless(!maccmp(chirp_tlv->sta_mac, g_sta_mac));
    fail_unless(chirp_tlv->hash_validity == 1);
    fail_unless(chirp_tlv->hash_len == 4);
    fail_unless(!memcmp(chirp_tlv->hash, (uint8_t[]){0x01, 0x02, 0x03, 0x04}, 4));

    return 0;
}

START_TEST(test_send_proxied_encap_dpp)
{
    test_init();

    test_cmd_help("sendProxiedEncapDPP");

    stub_cmdu_tx_register_send_proxied_encap_dpp_cb(send_proxied_encap_dpp_1_cb);
    fail_unless(!map_cli_exec("sendProxiedEncapDPP", "{\"almac\":"AL_MAC_QSTR",\"encap\":{\"stamac\":"STA_MAC_QSTR",\"frame_indicator\":1,\"frame_type\":10,\"frame\":\"AABBCCDD\"}}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    g_cb_called = false;
    stub_cmdu_tx_register_send_proxied_encap_dpp_cb(send_proxied_encap_dpp_2_cb);
    fail_unless(!map_cli_exec("sendProxiedEncapDPP", "{\"almac\":"AL_MAC_QSTR",\"encap\":{\"frame_indicator\":1,\"frame_type\":10,\"frame\":\"AABBCCDD\"},\"chirp\":{\"stamac\":"STA_MAC_QSTR",\"hash_validity\":1,\"hash\":\"01020304\"}}"));
    fail_unless(g_cb_called && PBUF_CONTAINS("OK"));

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_RAW_MESSAGE                           #
########################################################################*/
static int send_raw_1_cb(char *ifname, mac_addr dmac, mac_addr smac, uint16_t eth_type, uint8_t *data, uint16_t data_len)
{
    int i;

    g_cb_called = true;
    fail_unless(!memcmp(dmac, (mac_addr){0xA1,0xA2,0xA3,0xA4,0xA5,0xA6}, sizeof(mac_addr)));
    fail_unless(!memcmp(smac, (mac_addr){0xB1,0xB2,0xB3,0xB4,0xB5,0xB6}, sizeof(mac_addr)));
    fail_unless(eth_type == 0x893A);
    fail_unless(data_len == 46); /* Padding: 64 - 14(HDR) - 4(CRC) */
    fail_unless(!memcmp(data, (uint8_t[]){0x00,0x01,0x02,0x03}, 4));

    for (i = 4; i < data_len; i++) {
        fail_unless(data[i] == 0);
    }

    return 0;
}

static int send_raw_2_cb(char *ifname, mac_addr dmac, mac_addr smac, uint16_t eth_type, uint8_t *data, uint16_t data_len)
{
    int i;

    g_cb_called = true;
    fail_unless(!memcmp(dmac, (mac_addr){0xA1,0xA2,0xA3,0xA4,0xA5,0xA6}, sizeof(mac_addr)));
    fail_unless(!memcmp(smac, (mac_addr){0xB1,0xB2,0xB3,0xB4,0xB5,0xB6}, sizeof(mac_addr)));
    fail_unless(eth_type == 0x893A);
    fail_unless(data_len == 256);

    for (i = 0; i < data_len; i++) {
        fail_unless(data[i] == (i % 256));
    }

    return 0;
}


static void fill_raw_buf(char *buf, int count)
{
    int i, pos = sprintf(buf, "eth0|A1 A2 A3 A4 A5 A6   B1 B2 B3 B4 B5 B6    89 3A ");

    for (i = 0; i < count; i++) {
        pos += sprintf(&buf[pos], "%02X ", (i % 256));
    }
}

START_TEST(test_send_raw_message)
{
    char *buf;

    test_init();

    fail_unless(!!(buf=malloc(8192)));

    /* Shorter than 64 bytes */
    stub_cmdu_tx_register_send_raw_cb(send_raw_1_cb);
    fill_raw_buf(buf, 4);
    fail_unless(!map_cli_exec("sendRawMessage", buf));
    fail_unless(g_cb_called);

    /* Longer than 64 bytes */
    g_cb_called = false;
    stub_cmdu_tx_register_send_raw_cb(send_raw_2_cb);
    fill_raw_buf(buf, 256);
    fail_unless(!map_cli_exec("sendRawMessage", buf));
    fail_unless(g_cb_called);

    /* Too long */
    g_cb_called = false;
    fill_raw_buf(buf, 1515);
    fail_unless(!map_cli_exec("sendRawMessage", buf));
    fail_unless(!g_cb_called);

    free(buf);
    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_WFA_CAPI                              #
########################################################################*/
START_TEST(test_send_wfa_capi)
{
    test_init();

    test_cmd_help("sendWFACAPI");

    fail_unless(!map_cli_exec("sendWFACAPI", "{\"args\":\"dev_get_parameter,program,map,parameter,ALid\"}"));

    test_fini();
}
END_TEST


const char *test_suite_name = "cli";
test_case_t test_cases[] = {
    TEST("help",                                 test_help  ),
    TEST("invalid",                              test_invalid  ),
    TEST("version",                              test_version  ),
    TEST("case_insensitive",                     test_case_insensitive  ),
    TEST("dump_ctrl_info",                       test_dump_ctrl_info  ),
    TEST("dump_interfaces",                      test_dump_interfaces  ),
    TEST("dump_blocklist",                       test_dump_blocklist  ),
    TEST("dump_op_classes",                      test_dump_op_classes  ),
    TEST("dump_chan_sel",                        test_dump_chan_sel  ),
    TEST("dump_tunneled_message",                test_dump_tunneled_message  ),
    TEST("dump_ap_metrics",                      test_dump_ap_metrics  ),
    TEST("dump_radio_metrics",                   test_dump_radio_metrics  ),
    TEST("dump_sta_metrics",                     test_dump_sta_metrics  ),
    TEST("get_channel_scan_results",             test_get_channel_scan_results  ),
    TEST("set_channel",                          test_set_channel  ),
    TEST("send_topology_query",                  test_send_topology_query  ),
    TEST("send_link_metric_query",               test_send_link_metric_query  ),
    TEST("send_autoconfig_renew",                test_send_autoconfig_renew  ),
    TEST("send_ap_capability_query",             test_send_ap_capability_query  ),
    TEST("send_channel_preference_query",        test_send_channel_preference_query  ),
    TEST("send_client_capability_query",         test_send_client_capability_query  ),
    TEST("send_assoc_sta_link_metrics_query",    test_send_assoc_sta_link_metrics_query  ),
    TEST("send_unassoc_sta_link_metrics_query",  test_send_unassoc_sta_link_metrics_query  ),
    TEST("send_beacon_metrics_query",            test_send_beacon_metrics_query  ),
    TEST("send_combined_infrastructure_metrics", test_send_combined_infrastructure_metrics  ),
    TEST("send_client_steering_request",         test_send_client_steering_request  ),
    TEST("send_client_assoc_control_request",    test_send_client_assoc_control_request  ),
    TEST("send_backhaul_sta_capability_query",   test_send_backhaul_sta_capability_query  ),
    TEST("send_backhaul_steering_request",       test_send_backhaul_steering_request  ),
    TEST("send_unsuccess_assoc_policy_conf",     test_send_unsuccess_assoc_policy_conf  ),
    TEST("send_bh_bss_policy_conf",              test_send_bh_bss_policy_conf  ),
    TEST("send_channel_scan_request",            test_send_channel_scan_request  ),
    TEST("send_cac_request",                     test_send_cac_request  ),
    TEST("send_cac_termination",                 test_send_cac_termination  ),
    TEST("send_ch_scan_report_policy_conf",      test_send_ch_scan_report_policy_conf ),
    TEST("send_dpp_cce_indication",              test_send_dpp_cce_indication ),
    TEST("send_proxied_encap_dpp",               test_send_proxied_encap_dpp ),
    TEST("send_raw_message",                     test_send_raw_message ),
    TEST("send_wfa_capi",                        test_send_wfa_capi ),
    TEST_CASES_END
};
