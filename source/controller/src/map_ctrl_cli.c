/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <json-c/json.h>

#define LOG_TAG "cli"

#include "map_ctrl_cli.h"
#include "map_ctrl_utils.h"
#include "map_ctrl_cmdu_tx.h"
#include "map_ctrl_wfa_capi.h"
#include "map_ctrl_chan_sel.h"

#include "map_cli.h"
#include "map_cli_subscription.h"
#include "map_data_model_dumper.h"
#include "map_blocklist.h"
#include "map_utils.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define JSON_PARSE                                              \
    memset(&json, 0, sizeof(json));                             \
    json.object = json_tokener_parse(payload ? payload : "{}"); \
    if (!json.object ||                                         \
        !json_object_is_type(json.object, json_type_object)) {  \
        goto out;                                               \
    }

#define CHECK_PRINT_HELP(help_str)                 \
    if (check_print_help(json.object, help_str)) { \
        args_ok = true;                            \
        goto out;                                  \
    }

#define JSON_PUT_CHECK_ARGS_OK                       \
    if (json.object != NULL) {                       \
        json_object_put(json.object);                \
    }                                                \
    if (!args_ok) {                                  \
        map_cli_printf("Error parsing arguments\n"); \
    }

#define PAYLOAD_HELP "--payload '{\"args\":\"help\"}'"

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
typedef struct map_subscription_s {
    const char *event;
    cli_function_t handler;
    uint32_t flags;
} map_subscription_t;

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static cli_t           *g_cli;
static acu_evloop_fd_t *g_cli_fd;

/*#######################################################################
#                       COMMAND HELP                                    #
########################################################################*/
/* Global help */
static const char *g_help =
    "Multiap controller CLI help:\n"

/* DUMP/GET */
    "map_cli --command help\n"
    "map_cli --command version\n"
    "map_cli --command dumpCtrlInfo\n"
    "map_cli --command dumpInterfaces\n"
    "map_cli --command dumpBlockList\n"
    "map_cli --command dumpOpClasses\n"
    "map_cli --command dumpChanSel "PAYLOAD_HELP"\n"
    "map_cli --command dumpTunneledMessage --payload '{\"mac\": \"AA:BB:CC:DD:EE:FF\",\"msgtype\":\"assoc|reassoc|btm|wnm|anqp\"}'\n"
    "map_cli --command dumpAPMetrics --payload '{\"bssid\":\"AA:BB:CC:DD:EE:FF\"}'\n"
    "map_cli --command dumpRadioMetrics --payload '{\"almac\":\"AA:BB:CC:DD:EE:FF\", \"radio_id\":\"AA:BB:CC:DD:EE:FF\"}'\n"
    "map_cli --command dumpStaMetrics "PAYLOAD_HELP"\n"
    "map_cli --command getChannelScanResults "PAYLOAD_HELP"\n"

/* SET */
    "map_cli --command setChannel "PAYLOAD_HELP"\n"

/* SEND */
    "map_cli --command sendTopologyQuery --payload '{\"almac\":\"AA:BB:CC:DD:EE:FF\"}'\n"
    "map_cli --command sendLinkMetricQuery "PAYLOAD_HELP"\n"
    "map_cli --command sendAutoconfigRenew "PAYLOAD_HELP"\n"
    "map_cli --command sendAPCapabilityQuery --payload '{\"almac\":\"AA:BB:CC:DD:EE:FF\"}'\n"
    "map_cli --command sendChannelPreferenceQuery --payload '{\"almac\":\"AA:BB:CC:DD:EE:FF\"}'\n"
    "map_cli --command sendClientCapabilityQuery --payload '{\"almac\":\"AA:BB:CC:DD:EE:FF\", \"stamac\":\"AA:BB:CC:DD:EE:FF\"}'\n"
    "map_cli --command sendAssocStaLinkMetricsQuery --payload '{\"almac\":\"AA:BB:CC:DD:EE:FF\", \"stamac\":\"AA:BB:CC:DD:EE:FF\"}'\n"
    "map_cli --command sendUnassocStaLinkMetricsQuery "PAYLOAD_HELP"\n"
    "map_cli --command sendBeaconMetricsQuery "PAYLOAD_HELP"\n"
    "map_cli --command sendCombinedInfrastructureMetrics --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\"}'\n"
    "map_cli --command sendClientSteeringRequest "PAYLOAD_HELP"\n"
    "map_cli --command sendClientAssocControlRequest "PAYLOAD_HELP"\n"
    "map_cli --command sendBackhaulStaCapabilityQuery --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\"}'\n"
    "map_cli --command sendBackhaulSteeringRequest "PAYLOAD_HELP"\n"
    "map_cli --command sendUnsuccessAssocPolicyConf "PAYLOAD_HELP"\n"
    "map_cli --command sendBhBssPolicyConf "PAYLOAD_HELP"\n"
    "map_cli --command sendChannelScanRequest "PAYLOAD_HELP"\n"
    "map_cli --command sendCACRequest "PAYLOAD_HELP"\n"
    "map_cli --command sendCACTermination "PAYLOAD_HELP"\n"
    "map_cli --command sendChScanReportPolicyConf "PAYLOAD_HELP"\n"
    "map_cli --command sendDPPCCEIndication "PAYLOAD_HELP"\n"
    "map_cli --command sendProxiedEncapDPP "PAYLOAD_HELP"\n"
    "map_cli --command sendRawMessage --payload '$ifname|MSB raw message bytes in hex separated by ws (network byte order) LSB'\n"

/* VARIOUS */
    "map_cli --command sendWFACAPI "PAYLOAD_HELP"\n";

/* Command specific help */
static const char *g_help_dump_chan_sel =
    "~Dump Channel selection Help~\n"
    "-Payload format-\n"
    "   {\n"
    "       \"almac\": \"AA:BB:CC:DD:EE:FF\", (optional)\n"
    "       \"extended\": true|false (optional)\n"
    "   }\n\n"
    "-Example-\n"
    "map_cli --command dumpChanSel\n"
    "map_cli --command dumpChanSel --payload '{\"extended\": true}'\n"
    "map_cli --command dumpChanSel --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\"}'\n"
    "map_cli --command dumpChanSel --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\", \"extended\": true}'\n";

static const char *g_help_dump_sta_metrics =
    "~Dump STA Metrics Help~\n"
    "This function dumps STA metrics with two options as \"metrics\" which the information comes from the Associated STA Link Metrics TLV and \"extended_metrics\" which the information comes from Associated STA Extended Link Metrics TLV. \"metrics\" option shows info for the BSS that sta is currently associated. \"extended_metrics\" opt shows current and old BSSs info.\n\n"
    "-Payload format-\n"
    "   {\n"
    "       \"stamac\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"type\": \"metrics\"|\"extended_metrics\"\n"
    "   }\n\n"
    "-Example-\n"
    "map_cli --command dumpStaMetrics --payload '{\"stamac\": \"AA:BB:CC:DD:EE:FF\", \"type\": \"metrics\"}'\n";

static const char *g_help_get_scan_results =
    "~Get Scan Results Help~\n"
    "This function dumps scan results with two options as \"all\" which dumps all scan results in the data-model (results from last and previous scan requests) \"lastRequest\" which dumps only the response of last scan request.\n\n"
    "-Payload format-\n"
    "   {\n"
    "       \"almac\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"radio_id\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"type\": \"all\"|\"lastRequest\"\n"
    "   }\n\n"
    "-Example-\n"
    "map_cli --command getChannelScanResults --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\", \"radio_id\": \"AA:BB:CC:DD:EE:FF\", \"type\": \"all|lastRequest\"}'\n";

static const char *g_help_set_channel =
    "~Set Channel Help~\n"
    "-Payload format-\n"
    "   {\n"
    "       \"almac\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"radio_id\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"channel\": channel|0 (auto)\n"
    "       \"bandwidth\": bw|0(auto) (optional)\n"
    "   }\n\n"
    "-Example-\n"
    "map_cli --command setChannel --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\", \"radio_id\": \"AA:BB:CC:DD:EE:FF\", \"channel\": 11}'\n";

static const char *g_help_send_link_metric_query =
    "~Link Metric Query Help~\n"
    "This function sends a link metric query.  Neighbor is optional (all neighbors if omitted). Type is optional (both if omitted)\n\n"
    "-Payload format-\n"
    "   {\n"
    "       \"almac\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"neighbor\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"type\": \"rx|tx|both\",\n"
    "   }\n\n"
    "-Example-\n"
    "map_cli --command sendLinkMetricQuery --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\"}'\n"
    "map_cli --command sendLinkMetricQuery --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\", \"neighbor\":\"AA:BB:CC:DD:EE:FF\"}'\n"
    "map_cli --command sendLinkMetricQuery --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\", \"type\":\"rx\"}'\n"
    "map_cli --command sendLinkMetricQuery --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\", \"neighbor\":\"AA:BB:CC:DD:EE:FF\", \"type\":\"rx\"}'\n";

static const char *g_help_send_autoconfig_renew =
    "~Autoconfig Renew Help~\n"
    "This function sends an autoconfig renew.  Almac is optional (multicast when omitted).\n\n"
    "-Payload format-\n"
    "   {\n"
    "       \"almac\": \"AA:BB:CC:DD:EE:FF\" (OPTIONAL),\n"
    "   }\n\n"
    "-Example-\n"
    "map_cli --command sendAutoconfigRenew --payload '{}'\n"
    "map_cli --command sendAutoconfigRenew --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\"}'\n";

static const char *g_help_send_unassoc_sta_link_metrics_query =
    "~Unassoc Sta Link Metrics Query Help~\n"
    "-Payload format-\n"
    "   {\n"
    "       \"almac\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"opclass\": 115,\n"
    "       \"channels\":"
    "       [\n"
    "           {\n"
    "               \"channel\": 36,\n"
    "               \"stamacs\": [\"AA:BB:CC:DD:EE:FF\"]\n"
    "           }\n"
    "       ]\n"
    "   }\n\n"
    "-Example-\n"
    "map_cli --command sendUnassocStaLinkMetricsQuery --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\", \"opclass\": 115, \"channels\":[{\"channel\": 36, \"stamacs\": [\"AA:BB:CC:DD:EE:FF\"]}]}'";

static const char *g_help_send_beacon_metrics_query =
    "~Beacon Metrics Query Help~\n"
    "-Payload format-\n"
    "   {\n"
    "       \"almac\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"stamac\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"opclass\": 115,\n"
    "       \"channel\": 36,\n"
    "       \"bssid\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"reporting_detail\": \"none|all|requested\",\n"
    "       \"ssid\": \"ssid\",\n"
    "       \"ap_channel_reports\":\n"
    "       [\n"
    "           {\n"
    "               \"opclass\": 115,\n"
    "               \"channels\": [36]\n"
    "           }\n"
    "       ]\n"
    "   }\n\n"
    "-Example-\n"
    "map_cli --command sendBeaconMetricsQuery --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\", \"stamac\": \"AA:BB:CC:DD:EE:FF\", \"opclass\": 115, \"channel\": 36, \"bssid\": \"FF:FF:FF:FF:FF:FF\", \"reporting_detail\": \"none\", \"ssid\": \"test\", \"ap_channel_reports\": []}'\n"
    "map_cli --command sendBeaconMetricsQuery --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\", \"stamac\": \"AA:BB:CC:DD:EE:FF\", \"opclass\": 115, \"channel\": 255, \"bssid\": \"FF:FF:FF:FF:FF:FF\", \"reporting_detail\": \"none\", \"ssid\": \"test\", \"ap_channel_reports\": [{\"opclass\": 115, \"channels\": [36]}]}'\n";

static const char *g_help_send_client_steering_request =
    "~Client Steering Request Help~\n"
    "-Payload format-\n"
    "   {\n"
    "       \"almac\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"bssid\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"mode\": \"opportunity|mandate\",\n"
    "       \"disassoc_imminent\": true|false,\n"
    "       \"abridged\": true|false,\n"
    "       \"opp_window\": 2000,\n"
    "       \"disassoc_timer\": 6000,\n"
    "       \"targets\":\n"
    "       [\n"
    "           {\n"
    "               \"stamac\": \"AA:BB:CC:DD:EE:FF\",\n"
    "               \"bssid\": \"AA:BB:CC:DD:EE:FF\",\n"
    "               \"opclass\": 115,\n"
    "               \"channel\": 36,\n"
    "               \"reason\": 0\n"
    "           }\n"
    "       ]\n"
    "   }\n\n"
    "-Example-\n"
    "map_cli --command sendClientSteeringRequest --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\", \"bssid\": \"AA:BB:CC:DD:EE:FF\", \"mode\": \"mandate\", \"disassoc_imminent\": true, \"abridged\": true, \"opp_window\": 0, \"disassoc_timer\": 6000, \"targets\": [{\"stamac\": \"AA:BB:CC:DD:EE:FF\", \"bssid\": \"AA:BB:CC:DD:EE:FF\", \"opclass\": 115, \"channel\": 36, \"reason\": 0}]}'\n";

static const char *g_help_send_client_assoc_control_request =
    "~Client Assoc Control Request Help~\n"
    "-Payload format-\n"
    "   {\n"
    "       \"almac\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"bssid\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"block\": true|false,\n"
    "       \"period\": integer (only required when block = true)\n"
    "       \"stamacs\": [\"AA:BB:CC:DD:EE:FF\"]\n"
    "   }\n\n"
    "-Example-\n"
    "map_cli --command sendClientAssocControlRequest --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\", \"bssid\": \"AA:BB:CC:DD:EE:FF\", \"stamacs\": [\"AA:BB:CC:DD:EE:FF\"], \"block\":true, \"period\": 30}'\n";

static const char *g_help_send_backhaul_steering_request =
    "~Backhaul Steering Request Help~\n"
    "Steer [stamac] to [bssid] operating on [opclass][channel]"
    "-Payload format-\n"
    "   {\n"
    "       \"almac\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"stamac\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"bssid\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"opclass\": 115\n"
    "       \"channel\": 36\n"
    "   }\n\n"
    "-Example-\n"
    "map_cli --command sendBackhaulSteeringRequest --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\", \"stamac\": \"AA:BB:CC:DD:EE:FF\", \"bssid\": \"AA:BB:CC:DD:EE:FF\", \"opclass\": 115, \"channel\": 36}'";

static const char *g_help_send_unsuccess_assoc_policy_config =
    "~Unsuccessful Assoc Policy Config Help~\n"
    "This function sends policy config request message to given BSS. Prepared message only contains \"Unsuccessful Association Policy TLV\" with given options.\n\n"
    "-Payload format-\n"
    "   {\n"
    "       \"almac\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"report\": true|false\n"
    "       \"max_reporting_rate\": 10\n"
    "   }\n\n"
    "-Example-\n"
    "map_cli --command sendUnsuccessAssocPolicyConf --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\", \"report\": true, \"max_reporting_rate\": 10}'\n";

static const char *g_help_send_bh_bss_policy_config =
    "~Backhaul BSS Policy Config Help~\n"
    "This function sends policy config request message to given BSS. Prepared message can contain one or multiple \"Backhaul BSS Configuration TLV\"s with given options.\n\n"
    "-Payload format-\n"
    "    {\n"
    "       \"no_of_bssid\": 2,\n"
    "       \"bssid_list\":\n"
    "       [\n"
    "           {\n"
    "               \"bssid\": \"AA:BB:CC:DD:EE:FF\",\n"
    "               \"p1_bsta_disallowed\": true|false,\n"
    "               \"p2_bsta_disallowed\": true|false,\n"
    "           },\n"
    "           {\n"
    "               \"bssid\": \"11:22:33:44:55:66\",\n"
    "               \"p1_bsta_disallowed\": true|false,\n"
    "               \"p2_bsta_disallowed\": true|false,\n"
    "           }\n"
    "       ]\n"
    "    }\n\n"
    "-Example-\n"
    "map_cli --command sendBhBssPolicyConf --payload '{ \"no_of_bssid\": 2, \"bssid_list\": [ { \"bssid\": \"AA:BB:CC:DD:EE:FF\", \"p1_bsta_disallowed\": false, \"p2_bsta_disallowed\": false, }, { \"bssid\": \"11:22:33:44:55:66\", \"p1_bsta_disallowed\": false, \"p2_bsta_disallowed\": false, }, ] }'\n";

static const char *g_help_send_channel_scan_request =
    "~Channel Scan Request Help~\n"
    "-Payload format-\n"
    "{\n"
    "   \"almac\":\"AA:BB:CC:DD:EE:FF\",\n"
    "   \"fresh_scan\":true,\n"
    "   \"no_of_radios\":2,\n"
    "   \"radio_list\":\n"
    "   [\n"
    "        {\n"
    "            \"radio_id\":\"AA:BB:CC:DD:EE:FF\",\n"
    "            \"no_of_opclass\":1,\n"
    "            \"opclass_list\":\n"
    "            [\n"
    "                {\n"
    "                    \"opclass\":118,\n"
    "                    \"no_of_channels\":1,\n"
    "                    \"channel_list\":\n"
    "                    [\n"
    "                        64,\n"
    "                    ]\n"
    "                }\n"
    "            ]\n"
    "        },\n"
    "        {\n"
    "            \"radio_id\":\"11:22:33:44:55:66\",\n"
    "            \"no_of_opclass\":1,\n"
    "            \"opclass_list\":\n"
    "            [\n"
    "                {\n"
    "                    \"opclass\":81,\n"
    "                    \"no_of_channels\":4,\n"
    "                    \"channel_list\":\n"
    "                    [\n"
    "                        7,8,9,10,\n"
    "                    ]\n"
    "                }\n"
    "            ]\n"
    "        },\n"
    "    ]\n"
    "}\n\n"
    "-Request Examples-\n"
    "Get Last Scan From Agent (no_of_opclass shall be zero):\n"
    "map_cli --command sendChannelScanRequest --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\", \"fresh_scan\":false, \"no_of_radios\":1, \"radio_list\":[ { \"radio_id\":\"AA:BB:CC:DD:EE:FF\", \"no_of_opclass\":0, \"opclass_list\":[ ] } ] }'\n\n"
    "Fresh Scan on Specific Channels:\n"
    "map_cli --command sendChannelScanRequest --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\", \"fresh_scan\":true, \"no_of_radios\":1, \"radio_list\":[ { \"radio_id\":\"AA:BB:CC:DD:EE:FF\", \"no_of_opclass\":1, \"opclass_list\":[ { \"opclass\":118, \"no_of_channels\":1, \"channel_list\":[ 64, ] } ] }, ] }'\n\n"
    "Fresh Scan All Channels on Specific Operation Classes:\n"
    "map_cli --command sendChannelScanRequest --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\", \"fresh_scan\":true, \"no_of_radios\":1, \"radio_list\":[ { \"radio_id\":\"AA:BB:CC:DD:EE:FF\", \"no_of_opclass\":1, \"opclass_list\":[ { \"opclass\":118, \"no_of_channels\":0, \"channel_list\":[ ] } ] }, ] }'\n";

static const char *g_help_send_cac_request =
    "~CAC Request Help~\n"
    "-Payload format-\n"
    "{\n"
    "   \"almac\":\"AA:BB:CC:DD:EE:FF\",\n"
    "   \"no_of_reqs\":2,\n"
    "   \"cac_req_list\":\n"
    "       [\n"
    "           {\n"
    "               \"radio_id\":\"AA:BB:CC:DD:EE:FF\",\n"
    "               \"opclass\":118,\n"
    "               \"channel\":64,\n"
    "               \"cac_method\":\"cont\"|\"cont_wdedicated_radio\"|\"mimo_dim_reduced\"|\"time_sliced\",\n"
    "               \"cac_completion_act\":\"remain_continue_mon\"|\"return_prev_conf\"\n"
    "           },\n"
    "           {\n"
    "               \"radio_id\":\"11:22:33:44:55:66\",\n"
    "               \"opclass\":81,\n"
    "               \"channel\":10,\n"
    "               \"cac_method\":\"cont\"|\"cont_wdedicated_radio\"|\"mimo_dim_reduced\"|\"time_sliced\",\n"
    "               \"cac_completion_act\":\"remain_continue_mon\"|\"return_prev_conf\"\n"
    "           },\n"
    "       ]\n"
    "   }\n\n"
    "-Example-\n"
    "map_cli --command sendCACRequest --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\", \"no_of_reqs\":1, \"cac_req_list\": [ { \"radio_id\":\"AA:BB:CC:DD:EE:FF\", \"opclass\":122, \"channel\":132, \"cac_method\":\"time_sliced\", \"cac_completion_act\":\"return_prev_conf\" } ] }'";

static const char *g_help_send_cac_termination =
    "~CAC Termination Help~\n"
    "-Payload format-\n"
    "{\n"
    "   \"almac\":\"AA:BB:CC:DD:EE:FF\",\n"
    "   \"no_of_radios\":2,\n"
    "   \"cac_radio_list\":\n"
    "       [\n"
    "           {\n"
    "               \"radio_id\":\"AA:BB:CC:DD:EE:FF\",\n"
    "               \"opclass\":118,\n"
    "               \"channel\":64\n"
    "           },\n"
    "           {\n"
    "               \"radio_id\":\"11:22:33:44:55:66\",\n"
    "               \"opclass\":122,\n"
    "               \"channel\":140\n"
    "           },\n"
    "       ]\n"
    "   }\n\n"
    "-Example-\n"
    "map_cli --command sendCACTermination --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\", \"no_of_radios\":1, \"cac_radio_list\": [ { \"radio_id\":\"AA:BB:CC:DD:EE:FF\", \"opclass\":122, \"channel\":132 } ] }'";

static const char *g_help_send_ch_scan_reporting_policy_config =
    "~Channel Scan Reporting Policy Config Help~\n"
    "This function sends policy config request message to given ALE. Prepared message only contains \"Channel Scan Reporting Policy TLV\" with given options.\n\n"
    "-Payload format-\n"
    "   {\n"
    "       \"almac\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"report_indep_scans\": true|false\n"
    "   }\n\n"
    "-Example-\n"
    "map_cli --command sendChScanReportPolicyConf --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\", \"report_indep_scans\": true}'\n";

static const char *g_help_send_dpp_cce_indication =
    "~DPP CCE Indication Help~\n"
    "This function sends DPP CCE Indication message to given ALE. Prepared message only contains \"DPP CCE Indication TLV\" with given options.\n\n"
    "-Payload format-\n"
    "   {\n"
    "       \"almac\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"advertise\": true|false\n"
    "   }\n\n"
    "-Example-\n"
    "map_cli --command sendDPPCCEIndication --payload '{\"almac\": \"AA:BB:CC:DD:EE:FF\", \"advertise\": true}'\n";

static const char *g_help_send_proxied_encap_dpp =
    "~1905 Encap DPP Help~\n"
    "This function sends 1905 Encap DPP message to given ALE. Prepared message will contain one \"1905 Encap DPP TLV\" and zero or one \"DPP Chirp Value TLV\"  with given options.\n\n"
    "-Payload format-\n"
    "   {\n"
    "       \"almac\": \"AA:BB:CC:DD:EE:FF\",\n"
    "       \"encap\":\n"
    "           {\n"
    "               \"frame_indicator\": 0 (Action Frame) | 1 (GAS),\n"
    "               \"stamac\": \"AA:BB:CC:DD:EE:FF\",\n"
    "               \"frame_type\": 0-255,\n"
    "               \"frame\": Frame body to be sent.,\n"
    "           }\n"
    "       \"chirp\":\n"
    "           {\n"
    "               \"hash_calidity\": 0 (Establish) | 1 (Purge),\n"
    "               \"stamac\": \"AA:BB:CC:DD:EE:FF\",\n"
    "               \"hash\": Hash data.,\n"
    "           }\n"
    "   }\n\n"
    "-Example-\n"
    "map_cli --command sendProxiedEncapDPP --payload '{\"almac\":\"AA:BB:CC:DD:EE:FF\",\"encap\":{\"stamac\":\"AA:BB:CC:DD:EE:FF\",\"frame_indicator\":0,\"frame_type\":10,\"frame\":\"AABBCCDDEEFF\"},\"chirp\":{\"stamac\":\"AA:BB:CC:DD:EE:FF\",\"hash_validity\":1,\"hash\":\"AABBCCDDEEFF\"}}'\n";

static const char *g_help_send_wfa_capi =
    "~Send WFA CAPI Help~\n"
    "This command is used for WFA certification to send Control API commands as specified in the Wi-Fi Testsuite Control API Specification.\n"
    "It only works when controller is started in WFA certification mode (-w option).\n\n"
    "-Payload format-\n"
    "   {\n"
    "       \"args\":\"CAPI_COMMAND\"\n"
    "   }\n\n"
    "-Example-\n"
    "map_cli --command sendWFACAPI --payload '{\"args\":\"dev_get_parameter,program,map,parameter,ALid\"}'";

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
static void map_cli_fd_cb(UNUSED int fd, void *userdata)
{
    cli_run(userdata);
}

static int json_get_mac(struct json_object *json, const char *field, mac_addr mac)
{
    struct json_object *json_mac = NULL;

    return json_object_object_get_ex(json, field, &json_mac) &&
           json_object_is_type(json_mac, json_type_string)   &&
           !mac_from_string(json_object_get_string(json_mac), mac) ? 0 : -1;
}

static map_ale_info_t *json_get_ale(struct json_object *json, const char *field)
{
    mac_addr al_mac;

    return json_get_mac(json, field, al_mac) ? NULL : map_dm_get_ale(al_mac);
}

/* Looks for "args" field with value "help" */
static bool check_print_help(struct json_object *json, const char *help_str)
{
    struct json_object *json_args = NULL;
    const char *str;

    if (json_object_object_get_ex(json, "args", &json_args) &&
        json_object_is_type(json_args, json_type_string)    &&
        (str = json_object_get_string(json_args)) &&
        !strcmp(str, "help"))
    {
        map_cli_printf("%s", help_str);
        return true;
    }
    return false;
}

static const char *yes_no(bool b)
{
    return b ? "yes" : "no";
}

/*#######################################################################
#                       CLI HANDLERS: DUMP                              #
########################################################################*/
static void cli_help(UNUSED const char *event, UNUSED const char *payload, UNUSED void *context)
{
    map_cli_printf("%s", g_help);
}

static void cli_version(UNUSED const char *event, UNUSED const char *payload, UNUSED void *context)
{
    map_cli_printf("%s\n", map_cfg_get()->version);
}

static void cli_dump_info(UNUSED const char *event, UNUSED const char *payload, UNUSED void *context)
{
    mac_addr_str    gw_mac_str;
    mac_addr        gw_mac = {0};

    map_dm_dump_agent_info_tree(map_cli_printf);

    i1905_get_gateway_mac_address(gw_mac);
    map_cli_printf("|---- GATEWAY MAC : [%s] -------|\n", mac_to_string(gw_mac, gw_mac_str));

}

static void cli_dump_interfaces(UNUSED const char *event, UNUSED const char *payload, UNUSED void *context)
{
    i1905_dump_interfaces(map_cli_printf);
}

static void cli_dump_blocklist(UNUSED const char *event, UNUSED const char *payload, UNUSED void *context)
{
    map_blocklist_dump(map_cli_printf);
}

static void cli_dump_op_classes(UNUSED const char *event, UNUSED const char *payload, UNUSED void *context)
{
    int               i, count;
    uint8_t           op_class, band, channel;
    uint16_t          bw;
    bool              is_center_channel;
    map_channel_set_t channel_set, channel_set2;
    char              buf[MAP_CS_BUF_LEN];

    map_cli_printf("OPCLASS     BAND    BANDW   CENTER  CHAN_NR  CHANNELS\n");

    /* Go over all possible op classes */
    for (op_class = 0; op_class < 255; op_class++) {
        if (map_get_band_from_op_class(op_class, &band) ||
            map_get_bw_from_op_class(op_class, &bw) || bw == 161 ||
            map_get_is_center_channel_from_op_class(op_class, &is_center_channel) ||
            (!is_center_channel && map_get_channel_set_from_op_class(op_class, &channel_set)) ||
            (is_center_channel && map_get_center_channel_set_from_op_class(op_class, &channel_set))) {
            continue; /* not a valid one... */
        }

        map_cli_printf("%7d %8s %5dMHz %8s %8d",
                       op_class, map_get_freq_band_str(band), bw,
                       yes_no(is_center_channel), map_cs_nr(&channel_set));

        /* Print channels in groups of 16 */
        for (i = 0; i < map_cs_nr(&channel_set); i += 16) {
            /* Copy and keep channel indexes [i, i + 15] */
            map_cs_copy(&channel_set2, &channel_set);

            count = 0;
            map_cs_foreach_safe(&channel_set2, channel) {
                if ((count < i) || (count > i + 15)) {
                    map_cs_unset(&channel_set2, channel);
                }
                count++;
            }

            map_cli_printf("%*s%s\n", (i > 0) ? 45 : 2, "", map_cs_to_string(&channel_set2, ',', buf, sizeof(buf)));
        }
    }
}

static void cli_dump_chan_sel(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "almac": "AA:BB:CC:DD:EE:FF",
     *      "extended": false|true
     *   }
     */

    map_ale_info_t *ale = NULL;
    bool            extended = false;
    bool            args_ok = false;

    struct {
        struct json_object *object;
        struct json_object *extended;
    } json;

    JSON_PARSE

    CHECK_PRINT_HELP(g_help_dump_chan_sel)

    /* almac is optional */
    if (json_object_object_get_ex(json.object, "almac", NULL)) {
        if (!(ale = json_get_ale(json.object, "almac"))) {
            map_cli_printf("ALE not found\n");
            goto out;
        }
    }

    /* extended is optional  */
    if (json_object_object_get_ex(json.object, "extended", &json.extended)) {
        if (!json_object_is_type(json.extended, json_type_boolean)) {
           goto out;
        }
        extended = json_object_get_boolean(json.extended);
    }

    args_ok = true;
    map_ctrl_chan_sel_dump(map_cli_printf, ale, extended);

out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_dump_tunneled_msg(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    mac_addr    mac;
    const char* type_str;
    int         type;
    bool        args_ok = false;

    struct {
        struct json_object *object;
        struct json_object *msgtype;
    } json;

    JSON_PARSE

    if (json_get_mac(json.object, "mac", mac)) {
        goto out;
    }

    if (!json_object_object_get_ex(json.object, "msgtype", &json.msgtype) ||
        !json_object_is_type(json.msgtype, json_type_string) ||
        !(type_str = json_object_get_string(json.msgtype))) {
        goto out;
    }

    if (!strcmp(type_str, "reassoc")) {
        type = TUNNELED_MSG_PAYLOAD_REASSOC_REQ;
    } else if (!strcmp(type_str, "assoc")) {
        type = TUNNELED_MSG_PAYLOAD_ASSOC_REQ;
    } else if (!strcmp(type_str, "btm")) {
        type = TUNNELED_MSG_PAYLOAD_BTM_QUERY;
    } else if (!strcmp(type_str, "wnm")) {
        type = TUNNELED_MSG_PAYLOAD_WNM_REQ;
    } else if (!strcmp(type_str, "anqp")) {
        type = TUNNELED_MSG_PAYLOAD_ANQP_REQ;
    } else {
        goto out;
    }
    args_ok = true;

    map_dm_dump_tunneled_messages(map_cli_printf, mac, type);

out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_dump_ap_metrics(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "bssid": "AA:BB:CC:DD:EE:FF"
     *   }
     */

    mac_addr        bssid    = {0};
    map_bss_info_t *bss      = NULL;
    uint8_t         ac_index = 0;
    bool            args_ok  = false;

    struct {
        struct json_object *object;
    } json;

    JSON_PARSE

    if (json_get_mac(json.object, "bssid", bssid)) {
        goto out;
    }

    if (NULL == (bss = map_dm_get_bss_gbl(bssid))) {
        map_cli_printf("cannot get bss for given bssid\n");
        goto out;
    }
    args_ok = true;

    /* Dump AP metrics */
    map_cli_printf("    -BSSID: %s\n", acu_mac_string(bssid));
    map_cli_printf("    -Channel util  : %d\n", bss->metrics.channel_utilization);
    map_cli_printf("    -Station count : %d\n", bss->metrics.stas_nr);
    map_cli_printf("    -ESP presence  : 0x%02x\n", bss->metrics.esp_present);
    map_cli_printf("    -ESP\n");
    map_cli_printf("      |-----------------------------------------------\n");
    for(ac_index = 0; ac_index < MAX_ACCESS_CATEGORY; ac_index++) {
        if (bss->metrics.esp_present & (1<<(7 - ac_index))) {
            if (ac_index == WIFI_AC_BE) {
                map_cli_printf("      | AC-BE:\n");
            } else if(ac_index == WIFI_AC_BK) {
                map_cli_printf("      | AC-BK:\n");
            } else if(ac_index == WIFI_AC_VO) {
                map_cli_printf("      | AC-VO:\n");
            } else if(ac_index == WIFI_AC_VD) {
                map_cli_printf("      | AC-VI:\n");
            }

            map_cli_printf("      |  -ESP Sub Element      : 0x%02x\n", bss->metrics.esp[ac_index].s.esp_subelement);
            map_cli_printf("      |  -Air Time Fraction    : 0x%02x\n", bss->metrics.esp[ac_index].s.estimated_air_time_fraction);
            map_cli_printf("      |  -PPDU Target Duration : 0x%02x\n", bss->metrics.esp[ac_index].s.ppdu_target_duration);
        }
    }
    map_cli_printf("       -----------------------------------------------\n");
    map_cli_printf("    -unicast bytes tx   : %"PRIu64"\n", bss->extended_metrics.ucast_bytes_tx);
    map_cli_printf("    -unicast bytes rx   : %"PRIu64"\n", bss->extended_metrics.ucast_bytes_rx);
    map_cli_printf("    -multicast bytes tx : %"PRIu64"\n", bss->extended_metrics.mcast_bytes_tx);
    map_cli_printf("    -multicast bytes rx : %"PRIu64"\n", bss->extended_metrics.mcast_bytes_rx);
    map_cli_printf("    -broadcast bytes tx : %"PRIu64"\n", bss->extended_metrics.bcast_bytes_tx);
    map_cli_printf("    -broadcast bytes rx : %"PRIu64"\n", bss->extended_metrics.bcast_bytes_rx);

out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_dump_radio_metrics(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "almac":"AA:BB:CC:DD:EE:FF",
     *      "radio_id": "AA:BB:CC:DD:EE:FF",
     *   }
     */

    map_ale_info_t   *ale;
    map_radio_info_t *radio;
    mac_addr          radio_id = {0};
    bool              args_ok  = false;

    struct {
        struct json_object *object;
        struct json_object *radio_id;
        struct json_object *type;
    } json;

    JSON_PARSE

    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    if (json_get_mac(json.object, "radio_id", radio_id)) {
        goto out;
    }

    if (NULL == (radio = map_dm_get_radio(ale, radio_id))) {
        map_cli_printf("Radio is not found!");
        goto out;
    }
    args_ok = true;

    map_cli_printf("--Radio Metrics--\n\n");
    map_cli_printf("Radio: %s\n\n", acu_mac_string(radio_id));
    map_cli_printf("    Noise: %d dBm\n", RCPI_TO_RSSI(radio->radio_metrics.noise));
    map_cli_printf("    Transmit: %.2f %%\n", (float)radio->radio_metrics.transmit / 255 * 100);
    map_cli_printf("    Receive Self: %.2f %%\n", (float)radio->radio_metrics.receive_self / 255 * 100);
    map_cli_printf("    Receive Other: %.2f %%\n", (float)radio->radio_metrics.receive_other / 255 * 100);

out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_dump_sta_metrics(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "stamac": "AA:BB:CC:DD:EE:FF",
     *      "type": "metrics|extended_metrics",
     *   }
     */

    map_sta_info_t *sta = NULL;
    mac_addr        mac = {0};
    const char     *type = NULL;
    int             i = 0;
    bool            args_ok = false;

    struct {
        struct json_object *object;
        struct json_object *type;
    } json;

    JSON_PARSE

    CHECK_PRINT_HELP(g_help_dump_sta_metrics)

    if (json_get_mac(json.object, "stamac", mac)) {
        goto out;
    }

    if (NULL == (sta = map_dm_get_sta_gbl(mac))) {
        map_cli_printf("STA not found!\n");
        goto out;
    }

    if (!json_object_object_get_ex(json.object, "type", &json.type) ||
        !json_object_is_type(json.type, json_type_string)) {
        goto out;
    }

    if (NULL == (type = json_object_get_string(json.type))) {
        goto out;
    }
    args_ok = true;

    if (!strcmp(type, "metrics")) {
        map_sta_link_metrics_t *link_metrics = first_object(sta->metrics);
        map_cli_printf("--Associated STA Link Metrics--\n\n");
        map_cli_printf("STA: %s\n\n", acu_mac_string(mac));
        map_cli_printf("BSS[0]\n\n");
        map_cli_printf("    bssid: %s\n", acu_mac_string(sta->bss->bssid));
        if (link_metrics) {
            map_cli_printf("    dl_mac_datarate: %u Mbps\n", link_metrics->dl_mac_datarate);
            map_cli_printf("    ul_mac_datarate: %u Mbps\n", link_metrics->ul_mac_datarate);
            map_cli_printf("    rssi: %d dBm\n", RCPI_TO_RSSI(link_metrics->rssi));
        }
    } else if (!strcmp(type, "extended_metrics")) {
        map_cli_printf("--Associated STA Extended Link Metrics--\n\n");
        map_cli_printf("STA: %s\n\n", acu_mac_string(mac));
        for (i = 0; i < sta->last_sta_ext_metrics.no_of_bss_metrics; i++) {
            map_cli_printf("BSS[%d]\n\n", i);
            map_cli_printf("    bssid: %s\n", acu_mac_string(sta->last_sta_ext_metrics.ext_bss_metrics_list[i].bssid));
            map_cli_printf("    last_data_dl_rate: %u Kbps\n", sta->last_sta_ext_metrics.ext_bss_metrics_list[i].last_data_dl_rate);
            map_cli_printf("    last_data_ul_rate: %u Kbps\n", sta->last_sta_ext_metrics.ext_bss_metrics_list[i].last_data_ul_rate);
            map_cli_printf("    utilization_rx: %u ms\n", sta->last_sta_ext_metrics.ext_bss_metrics_list[i].utilization_rx);
            map_cli_printf("    utilization_tx: %u ms\n", sta->last_sta_ext_metrics.ext_bss_metrics_list[i].utilization_tx);
        }
    } else {
        map_cli_printf("wrong metrics type\n");
    }

out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_get_scan_results(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "almac": "AA:BB:CC:DD:EE:FF",
     *      "radio_id": "AA:BB:CC:DD:EE:FF",
     *      "type": "all|lastRequest"
     *   }
     */

    map_ale_info_t   *ale;
    map_radio_info_t *radio;
    mac_addr          radio_id = {0};
    int               neighbor_count = 0;
    const char       *type = NULL;
    list_iterator_t  *it = NULL;
    bool              get_all_results = false; /* false: dump last scan results, true: dump all scan results */
    bool              args_ok = false;

    struct {
        struct json_object *object;
        struct json_object *type;
    } json;

    JSON_PARSE

    CHECK_PRINT_HELP(g_help_get_scan_results)

    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    if (json_get_mac(json.object, "radio_id", radio_id)) {
        goto out;
    }

    if (NULL == (radio = map_dm_get_radio(ale, radio_id))) {
        map_cli_printf("Radio not found\n");
        goto out;
    }

    if (!json_object_object_get_ex(json.object, "type", &json.type) ||
        !json_object_is_type(json.type, json_type_string)) {
        goto out;
    }

    if (NULL == (type = json_object_get_string(json.type))) {
        goto out;
    }

    if (!strcmp(type, "all")) {
        get_all_results = true;
    } else if (!strcmp(type, "lastRequest")) {
        get_all_results = false;
    } else {
        map_cli_printf("Invalid get scan results type!\n");
        goto out;
    }
    args_ok = true;

    if (0 == list_get_size(radio->scanned_bssid_list)) {
        map_cli_printf("There is no scan results for this radio\n");
        goto out;
    }

    if (NULL == (it = new_list_iterator(radio->scanned_bssid_list))) {
        map_cli_printf("Scan result list cannot be found for this radio!\n");
        goto out;
    }

    /* DUMP Scan Results */
    map_cli_printf("%s", get_all_results ? "~ALL Scan Results~\n\n" : "~Last Scan Results~\n\n");
    if (!get_all_results) {
        map_cli_printf("Timestamp: %s\n", radio->last_scan_info.last_scan_ts);
        map_cli_printf("Scan count: %d\n", radio->last_scan_info.last_scan_cnt);
    }
    map_cli_printf("Radio: %s\n\n", acu_mac_string(radio_id));

    while (it->iter != NULL) {
        map_scan_result_t* scan_info_obj = (map_scan_result_t*) get_next_list_object(it);
        if (scan_info_obj &&
            ((get_all_results) ||   /* dump all scan results */
            (!get_all_results && scan_info_obj->scan_cnt == radio->last_scan_info.last_scan_cnt))) { /* dump just latest results */
            map_cli_printf("----------------------------\n");
            map_cli_printf("Neighbor [%d]:\n\n", neighbor_count);
            map_cli_printf("    Opclass: %u\n", scan_info_obj->opclass);
            map_cli_printf("    Channel: %u\n", scan_info_obj->channel);
            map_cli_printf("    Channel Scan Timestamp: %s\n", scan_info_obj->channel_scan_ts);
            map_cli_printf("    BSSID: %s\n", acu_mac_string(scan_info_obj->neighbor_info.bssid));
            map_cli_printf("    SSID: %s\n", scan_info_obj->neighbor_info.ssid);
            map_cli_printf("    RSSI: %d dBm\n", (int8_t)RCPI_TO_RSSI(scan_info_obj->neighbor_info.rcpi));
            map_cli_printf("    Channel BW: %s MHz\n", scan_info_obj->neighbor_info.ch_bw);
            map_cli_printf("    BSS Load Element Present: %u\n", scan_info_obj->neighbor_info.bss_load_elem_present);
            if (scan_info_obj->neighbor_info.bss_load_elem_present == 1) {
                map_cli_printf("    Channel Utilization: %u %%\n", scan_info_obj->neighbor_info.channel_utilization * 100 / 255);
                map_cli_printf("    STA Count: %u\n", scan_info_obj->neighbor_info.stas_nr);
            }
            neighbor_count++;
        }
    }
    free_list_iterator(it);

    if (!neighbor_count) {
        map_cli_printf("There are no neighbors for this scan.\n\n");
    }

out:
    JSON_PUT_CHECK_ARGS_OK
}

/*#######################################################################
#                       CLI HANDLERS: SET                               #
########################################################################*/
static void cli_set_channel(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "almac": "AA:BB:CC:DD:EE:FF",
     *      "radio_id": "AA:BB:CC:DD:EE:FF",
     *      "channel": 36,
     *      "bandwidth": 20 (optional)
     *   }
     */

    map_ale_info_t   *ale;
    map_radio_info_t *radio;
    mac_addr          radio_id;
    int               channel = -1, bw = -1; /* -1: do not update */
    bool              args_ok = false;

    struct {
        struct json_object *object;
        struct json_object *channel;
        struct json_object *bandwidth;
    } json;

    JSON_PARSE

    CHECK_PRINT_HELP(g_help_set_channel);

    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found");
        goto out;
    }

    if (json_get_mac(json.object, "radio_id", radio_id)) {
        goto out;
    }

    if (NULL == (radio = map_dm_get_radio(ale, radio_id))) {
        map_cli_printf("Radio not found!");
        goto out;
    }

    /* channel */
    if (!json_object_object_get_ex(json.object, "channel", &json.channel) ||
        !json_object_is_type(json.channel, json_type_int)) {
        goto out;
    }
    channel = json_object_get_int(json.channel);

    /* Optional bw */
    if (json_object_object_get_ex(json.object, "bandwidth", &json.bandwidth)) {
        if (!json_object_is_type(json.bandwidth, json_type_int)) {
            goto out;
        }
        bw = json_object_get_int(json.bandwidth);
    }
    args_ok = true;

    map_ctrl_chan_sel_set(radio, NULL, NULL, channel >= 0 ? &channel : NULL, bw >= 0 ? &bw : NULL);

    map_cli_printf("OK\n");

out:
    JSON_PUT_CHECK_ARGS_OK
}

/*#######################################################################
#                       CLI HANDLERS: SEND MESSAGES                     #
########################################################################*/
static void cli_send_topology_query(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "almac": "AA:BB:CC:DD:EE:FF",
     *   }
     */

    map_ale_info_t *ale     = NULL;
    bool            args_ok = false;

    struct {
        struct json_object *object;
    } json;

    JSON_PARSE

    /* Get ale */
    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    args_ok = true;
    if (map_send_topology_query(ale, MID_NA)) {
        goto out;
    }

    map_cli_printf("OK\n");

out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_send_link_metric_query(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "almac": "AA:BB:CC:DD:EE:FF",
     *      "neighbor": "AA:BB:CC:DD:EE:FF", (OPTIONAL)
     *      "type": "rx|tx|both" (OPTIONAL)
     *   }
     */

    map_ale_info_t                *ale     = NULL;
    i1905_link_metric_query_tlv_t  tlv     = {0};
    const char                    *type;
    bool                           args_ok = false;

    struct {
        struct json_object *object;
        struct json_object *type;
    } json;

    JSON_PARSE

    CHECK_PRINT_HELP(g_help_send_link_metric_query)

    /* Get ale */
    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    /* Defaults: */
    tlv.destination       = LINK_METRIC_QUERY_TLV_ALL_NEIGHBORS;
    tlv.link_metrics_type = LINK_METRIC_QUERY_TLV_BOTH_TX_AND_RX_LINK_METRICS;

    /* Get neighbor (optional) */
    if (!json_get_mac(json.object, "neighbor", tlv.specific_neighbor)) {
        tlv.destination = LINK_METRIC_QUERY_TLV_SPECIFIC_NEIGHBOR;
    }

    /* Get type (optional) */
    if (json_object_object_get_ex(json.object, "type", &json.type)) {
        if (!json_object_is_type(json.type, json_type_string)) {
            goto out;
        }

        if (!(type = json_object_get_string(json.type))) {
            goto out;
        }

        if (!strcmp(type, "rx")) {
            tlv.link_metrics_type = LINK_METRIC_QUERY_TLV_RX_LINK_METRICS_ONLY;
        } else if (!strcmp(type, "tx")) {
            tlv.link_metrics_type = LINK_METRIC_QUERY_TLV_TX_LINK_METRICS_ONLY;
        } else if (!strcmp(type, "both")) {
            tlv.link_metrics_type = LINK_METRIC_QUERY_TLV_BOTH_TX_AND_RX_LINK_METRICS;
        } else {
            goto out;
        }
    }

    args_ok = true;
    if (map_send_link_metric_query(ale, &tlv, MID_NA)) {
        goto out;
    }

    map_cli_printf("OK\n");

out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_send_autoconfig_renew(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "almac": "AA:BB:CC:DD:EE:FF", (OPTIONAL)
     *   }
     */

    mac_addr        al_mac  = {0};
    map_ale_info_t *ale     = NULL;
    bool            args_ok = false;

    struct {
        struct json_object *object;
    } json;

    JSON_PARSE

    CHECK_PRINT_HELP(g_help_send_autoconfig_renew)

    /* almac is optional */
    if (!json_get_mac(json.object, "almac", al_mac)) {
        if (NULL == (ale = map_dm_get_ale(al_mac))) {
            map_cli_printf("ALE not found\n");
            goto out;
        }
    }

    args_ok = true;
    if (ale) {
        if (map_send_autoconfig_renew_ucast(ale, IEEE80211_FREQUENCY_BAND_2_4_GHZ, MID_NA)) {
            map_cli_printf("map_send_autoconfig_renew_ucast() failed\n");
            goto out;
        }
    } else {
        if (map_send_autoconfig_renew(IEEE80211_FREQUENCY_BAND_2_4_GHZ, MID_NA)) {
            map_cli_printf("map_send_autoconfig_renew() failed\n");
            goto out;
        }
    }

    map_cli_printf("OK\n");

out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_send_ap_capability_query(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "almac": "AA:BB:CC:DD:EE:FF",
     *   }
     */

    map_ale_info_t *ale     = NULL;
    bool            args_ok = false;

    struct {
        struct json_object *object;
    } json;

    JSON_PARSE

    /* Get ale */
    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    args_ok = true;
    if (map_send_ap_capability_query(ale, MID_NA)) {
        goto out;
    }

    map_cli_printf("OK\n");

out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_send_channel_preference_query(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "almac": "AA:BB:CC:DD:EE:FF",
     *   }
     */

    map_ale_info_t *ale     = NULL;
    bool            args_ok = false;

    struct {
        struct json_object *object;
    } json;

    JSON_PARSE

    /* Get ale */
    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    args_ok = true;
    if (map_send_channel_preference_query(ale, MID_NA)) {
        goto out;
    }

    map_cli_printf("OK\n");

out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_send_client_capability_query(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "almac": "AA:BB:CC:DD:EE:FF",
     *      "stamac": "AA:BB:CC:DD:EE:FF",
     *   }
     */

    map_ale_info_t *ale     = NULL;
    map_sta_info_t *sta     = NULL;
    mac_addr        sta_mac;
    bool            args_ok = false;

    struct {
        struct json_object *object;
    } json;

    JSON_PARSE

    /* Get ale */
    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    /* Get sta */
    if (json_get_mac(json.object, "stamac", sta_mac) ||
        !(sta = map_dm_get_sta_from_ale(ale, sta_mac))) {
        map_cli_printf("STA not found\n");
        goto out;
    }


    args_ok = true;
    if (map_send_client_capability_query(sta, MID_NA)) {
        goto out;
    }

    map_cli_printf("OK\n");

out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_send_assoc_sta_link_metrics_query(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "almac": "AA:BB:CC:DD:EE:FF",
     *      "stamac": "AA:BB:CC:DD:EE:FF",
     *   }
     */

    map_ale_info_t *ale     = NULL;
    map_sta_info_t *sta     = NULL;
    mac_addr        sta_mac;
    bool            args_ok = false;

    struct {
        struct json_object *object;
    } json;

    JSON_PARSE

    /* Get ale */
    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    /* Get sta */
    if (json_get_mac(json.object, "stamac", sta_mac) ||
        !(sta = map_dm_get_sta_from_ale(ale, sta_mac))) {
        map_cli_printf("STA not found\n");
        goto out;
    }


    args_ok = true;
    if (map_send_assoc_sta_link_metrics_query(sta, MID_NA)) {
        goto out;
    }

    map_cli_printf("OK\n");

out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_send_unassoc_sta_link_metrics_query(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "almac": "AA:BB:CC:DD:EE:FF",
     *      "opclass": 115,
     *      "channels":
     *      [
     *          {
     *              "channel": 36,
                    "stamacs": [\"AA:BB:CC:DD:EE:FF\"]
     *          }
     *      ]
     *   }
     */

    map_ale_info_t                           *ale          = NULL;
    map_unassoc_sta_link_metrics_query_tlv_t  tlv          = { 0 };
    mac_addr                                  sta_macs[64]; /* array over all channels */
    size_t                                    sta_macs_idx = 0;
    unsigned int                              i, j;
    bool                                      args_ok      = false;

    struct {
        struct json_object *object;
        struct json_object *opclass;
        struct {
            struct json_object *object;
            struct json_object *channel;
            struct json_object *stamacs;
        } channels;
    } json;

    JSON_PARSE

    CHECK_PRINT_HELP(g_help_send_unassoc_sta_link_metrics_query)

    /* Get ale */
    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    /* Get opclass */
    if (!json_object_object_get_ex(json.object, "opclass", &json.opclass) ||
        !json_object_is_type(json.opclass, json_type_int)) {
        goto out;
    }
    tlv.op_class = json_object_get_int(json.opclass);

    /* Channels */
    if (!json_object_object_get_ex(json.object, "channels", &json.channels.object) ||
        !json_object_is_type(json.channels.object, json_type_array)) {
        goto out;
    }

    for (i = 0; i < json_object_array_length(json.channels.object) && i < MAX_CHANNEL_PER_OP_CLASS; i++) {
        struct json_object *obj = json_object_array_get_idx(json.channels.object, i);

        if (!obj || !json_object_is_type(obj, json_type_object)) {
            goto out;
        }

        /* Channel */
        if (!json_object_object_get_ex(obj, "channel", &json.channels.channel) ||
            !json_object_is_type(json.channels.channel, json_type_int)) {
            goto out;
        }
        tlv.channels[i].channel = json_object_get_int(json.channels.channel);

        /* STA macs */
        if (!json_object_object_get_ex(obj, "stamacs", &json.channels.stamacs) ||
            !json_object_is_type(json.channels.stamacs, json_type_array)) {
            goto out;
        }

        tlv.channels[i].sta_macs = &sta_macs[sta_macs_idx];
        for (j = 0; j < json_object_array_length(json.channels.stamacs) && sta_macs_idx < ARRAY_SIZE(sta_macs); j++) {
            struct json_object *obj2 = json_object_array_get_idx(json.channels.stamacs, j);

            if (!obj2 || !json_object_is_type(obj2, json_type_string)) {
                goto out;
            }

            if (mac_from_string(json_object_get_string(obj2), sta_macs[sta_macs_idx])) {
                goto out;
            }
            sta_macs_idx++;
        }
        tlv.channels[i].sta_macs_nr = j;
    }
    tlv.channels_nr = i;

    args_ok = true;

    if (0 != map_send_unassoc_sta_link_metrics_query(ale, &tlv, MID_NA)) {
        map_cli_printf("failed to send request to ale[%s]\n", ale->al_mac_str);
        goto out;
    }

    map_cli_printf("OK\n");

out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_send_beacon_metrics_query(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "almac": "AA:BB:CC:DD:EE:FF",
     *      "stamac": "AA:BB:CC:DD:EE:FF",
     *      "opclass": 115,
     *      "channel": 36,
     *      "bssid,": ,"AA:BB:CC:DD:EE:FF",
     *      "reporting_detail": "none|all|requested",
     *      "ssid": "ssid",
     *      "ap_channel_reports":
     *      [
     *          {
     *              "opclass": 115,
     *              "channels": [\"AA:BB:CC:DD:EE:FF\"]
     *          }
     *      ]
     *   }
     */

    map_ale_info_t                 *ale          = NULL;
    map_beacon_metrics_query_tlv_t  tlv = { 0 };
    const char                     *rep_det, *ssid;
    unsigned int                    i, j;
    bool                            args_ok      = false;

    struct {
        struct json_object *object;
        struct json_object *opclass;
        struct json_object *channel;
        struct json_object *rep_det;
        struct json_object *ssid;
        struct {
            struct json_object *object;
            struct json_object *opclass;
            struct json_object *channels;
        } ap_channel_reports;
    } json;

    JSON_PARSE

    CHECK_PRINT_HELP(g_help_send_beacon_metrics_query)

    /* Get ale */
    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    /* Get stamac */
    if (json_get_mac(json.object, "stamac", tlv.sta_mac)) {
        goto out;
    }

    /* Get opclass */
    if (!json_object_object_get_ex(json.object, "opclass", &json.opclass) ||
        !json_object_is_type(json.opclass, json_type_int)) {
        goto out;
    }
    tlv.op_class = json_object_get_int(json.opclass);

    /* Get channel */
    if (!json_object_object_get_ex(json.object, "channel", &json.channel) ||
        !json_object_is_type(json.channel, json_type_int)) {
        goto out;
    }
    tlv.channel = json_object_get_int(json.channel);

    /* Get bssid */
    if (json_get_mac(json.object, "bssid", tlv.bssid)) {
        goto out;
    }

    /* Get reporting_detail */
    if (!json_object_object_get_ex(json.object, "reporting_detail", &json.rep_det) ||
        !json_object_is_type(json.rep_det, json_type_string) ||
        !(rep_det = json_object_get_string(json.rep_det))) {
        goto out;
    }

    if (!strcmp(rep_det, "none")) {
        tlv.reporting_detail = MAP_BEACON_REPORT_DETAIL_NONE;
    } else if (!strcmp(rep_det, "requested")) {
        tlv.reporting_detail = MAP_BEACON_REPORT_DETAIL_REQUESTED;
    } else if (!strcmp(rep_det, "all")) {
        tlv.reporting_detail = MAP_BEACON_REPORT_DETAIL_ALL;
    } else {
        goto out;
    }

    /* Get ssid */
    if (!json_object_object_get_ex(json.object, "ssid", &json.ssid) ||
        !json_object_is_type(json.ssid, json_type_string) ||
        !(ssid = json_object_get_string(json.ssid)) ||
        strlen(ssid) > MAX_SSID_LEN - 1) {
        goto out;
    }
    tlv.ssid_len = strlen(ssid);
    memcpy(tlv.ssid, ssid, tlv.ssid_len);

    /* Get ap_channel_reports */
    if (!json_object_object_get_ex(json.object, "ap_channel_reports", &json.ap_channel_reports.object) ||
        !json_object_is_type(json.ap_channel_reports.object, json_type_array)) {
        goto out;
    }

    for (i = 0; i < json_object_array_length(json.ap_channel_reports.object) && i < MAX_OP_CLASS; i++) {
        struct json_object *obj = json_object_array_get_idx(json.ap_channel_reports.object, i);

        if (!obj || !json_object_is_type(obj, json_type_object)) {
            goto out;
        }

        /* opclass */
        if (!json_object_object_get_ex(obj, "opclass", &json.ap_channel_reports.opclass) ||
            !json_object_is_type(json.ap_channel_reports.opclass, json_type_int)) {
            goto out;
        }
        tlv.ap_channel_reports[i].op_class = json_object_get_int(json.ap_channel_reports.opclass);

        /* channels */
        if (!json_object_object_get_ex(obj, "channels", &json.ap_channel_reports.channels) ||
            !json_object_is_type(json.ap_channel_reports.channels, json_type_array)) {
            goto out;
        }

        for (j = 0; j < json_object_array_length(json.ap_channel_reports.channels); j++) {
            struct json_object *obj2 = json_object_array_get_idx(json.ap_channel_reports.channels, j);

            if (!obj2 || !json_object_is_type(obj2, json_type_int)) {
                goto out;
            }
            map_cs_set(&tlv.ap_channel_reports[i].channels, json_object_get_int(obj2));
        }
    }
    tlv.ap_channel_reports_nr = i;

    args_ok = true;

    if (0 != map_send_beacon_metrics_query(ale, &tlv, MID_NA)) {
        map_cli_printf("failed to send request to ale[%s]\n", ale->al_mac_str);
        goto out;
    }

    map_cli_printf("OK\n");

out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_send_combined_infrastructure_metrics(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    map_ale_info_t *ale;
    bool            args_ok = false;

    struct {
        struct json_object *object;
    } json;

    JSON_PARSE

    /* Get ale */
    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    args_ok = true;
    if (map_send_combined_infrastructure_metrics(ale, MID_NA)) {
        goto out;
    }

    map_cli_printf("OK\n");

out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_send_client_steering_request(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     * {
     *     "almac": "AA:BB:CC:DD:EE:FF",
     *     "bssid": "AA:BB:CC:DD:EE:FF",
     *     "mode": "opportunity|mandate",
     *     "disassoc_imminent": true|false,
     *     "abridged": true|false,
     *     "opp_window": 2000,
     *     "disassoc_timer": 6000,
     *     "targets":
     *     [
     *         {
     *             "stamac": "AA:BB:CC:DD:EE:FF",
     *             "bssid": "AA:BB:CC:DD:EE:FF",
     *             "opclass": 115,
     *             "channel": 36,
     *             "reason": 0
     *         }
     *     ]
     * }
     */

    map_ale_info_t *ale     = NULL;
#define MAX_STEER_TARGET 16
    uint8_t         steer_buf[sizeof(map_steer_t) + MAX_STEER_TARGET * sizeof(map_steer_sta_bssid_t)] = {0};
    map_steer_t    *steer   = (map_steer_t *)steer_buf;
    const char*     mode;
    bool            args_ok = false;
    unsigned int    i;

    struct {
        struct json_object *object;
        struct json_object *mode;
        struct json_object *disassoc_imminent;
        struct json_object *abridged;
        struct json_object *opp_window;
        struct json_object *disassoc_timer;
        struct {
            struct json_object *object;
            struct json_object *opclass;
            struct json_object *channel;
            struct json_object *reason;
        } targets;
    } json;

    JSON_PARSE

    CHECK_PRINT_HELP(g_help_send_client_steering_request)

    /* Get ale */
    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    /* Get bssid */
    if (json_get_mac(json.object, "bssid", steer->bssid)) {
        goto out;
    }

    /* Get mode */
    if (!json_object_object_get_ex(json.object, "mode", &json.mode) ||
        !json_object_is_type(json.mode, json_type_string) ||
        !(mode = json_object_get_string(json.mode))) {
        goto out;
    }
    if (!strcmp(mode, "opportunity")) {
        /* Default */
    } else if (!strcmp(mode, "mandate")) {
        steer->flags |= MAP_STEERING_REQUEST_FLAG_MANDATE;
    } else {
        goto out;
    }

    /* Get disassoc_imminent* */
    if (!json_object_object_get_ex(json.object, "disassoc_imminent", &json.disassoc_imminent) ||
        !json_object_is_type(json.disassoc_imminent, json_type_boolean)) {
        goto out;
    }
    if (json_object_get_boolean(json.disassoc_imminent)) {
        steer->flags |= MAP_STEERING_REQUEST_FLAG_BTM_DISASSOC_IMMINENT;
    }

    /* Get abridged */
    if (!json_object_object_get_ex(json.object, "abridged", &json.abridged) ||
        !json_object_is_type(json.abridged, json_type_boolean)) {
        goto out;
    }
    if (json_object_get_boolean(json.abridged)) {
        steer->flags |= MAP_STEERING_REQUEST_FLAG_BTM_ABRIDGED;
    }

    /* Get opp_window */
    if (!json_object_object_get_ex(json.object, "opp_window", &json.opp_window) ||
        !json_object_is_type(json.opp_window, json_type_int)) {
        goto out;
    }
    steer->opportunity_wnd = json_object_get_int(json.opp_window);

    /* Get disassoc timer */
    if (!json_object_object_get_ex(json.object, "disassoc_timer", &json.disassoc_timer) ||
        !json_object_is_type(json.disassoc_timer, json_type_int)) {
        goto out;
    }
    steer->disassociation_timer = json_object_get_int(json.disassoc_timer);

    /* Get targets */
    if (!json_object_object_get_ex(json.object, "targets", &json.targets.object) ||
        !json_object_is_type(json.targets.object, json_type_array)) {
        goto out;
    }

    for (i = 0; i < json_object_array_length(json.targets.object) && i < MAX_STEER_TARGET; i++) {
        struct json_object *obj = json_object_array_get_idx(json.targets.object, i);

        if (!obj || !json_object_is_type(obj, json_type_object)) {
            goto out;
        }

        /* stamac */
        if (json_get_mac(obj, "stamac", steer->sta_bssid[i].sta_mac)) {
            goto out;
        }

        /* bssid */
        if (json_get_mac(obj, "bssid", steer->sta_bssid[i].target_bssid)) {
            goto out;
        }

        /* opclass */
        if (!json_object_object_get_ex(obj, "opclass", &json.targets.opclass) ||
            !json_object_is_type(json.targets.opclass, json_type_int)) {
            goto out;
        }
        steer->sta_bssid[i].op_class = json_object_get_int(json.targets.opclass);

        /* channel */
        if (!json_object_object_get_ex(obj, "channel", &json.targets.channel) ||
            !json_object_is_type(json.targets.channel, json_type_int)) {
            goto out;
        }
        steer->sta_bssid[i].channel = json_object_get_int(json.targets.channel);

        /* reason */
        if (!json_object_object_get_ex(obj, "reason", &json.targets.reason) ||
            !json_object_is_type(json.targets.reason, json_type_int)) {
            goto out;
        }
        steer->sta_bssid[i].reason = json_object_get_int(json.targets.reason);
    }
    steer->sta_bssid_nr = i;

    args_ok = true;

    if (0 != map_send_client_steering_request(ale, steer, MID_NA)) {
        map_cli_printf("failed to send request to ale[%s]\n", ale->al_mac_str);
        goto out;
    }

    map_cli_printf("OK\n");

out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_send_client_assoc_control_request(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "almac": "AA:BB:CC:DD:EE:FF",
     *      "bssid": "AA:BB:CC:DD:EE:FF",
     *      "block": true|false,
     *      "period": integer (only required when block = true)
     *      "stamacs": ["AA:BB:CC:DD:EE:FF"],
     *   }
     */

    map_ale_info_t                         *ale     = NULL;
    map_client_assoc_control_request_tlv_t  tlv = {0};
    bool                                    block;
    bool                                    args_ok = false;
    unsigned int                            i;

    struct {
        struct json_object *object;
        struct json_object *block;
        struct json_object *period;
        struct json_object *stamacs;
    } json;

    JSON_PARSE

    CHECK_PRINT_HELP(g_help_send_client_assoc_control_request)

    /* Get ale */
    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    /* Get bssid */
    if (json_get_mac(json.object, "bssid", tlv.bssid) ||
        !map_dm_get_bss_from_ale(ale, tlv.bssid)) {
        map_cli_printf("BSS not found\n");
        goto out;
    }

    /* block */
    if (!json_object_object_get_ex(json.object, "block", &json.block) ||
        !json_object_is_type(json.block, json_type_boolean)) {
        goto out;
    }
    block = json_object_get_boolean(json.block);
    tlv.association_control = block ? MAP_CLIENT_ASSOC_CONTROL_BLOCK : MAP_CLIENT_ASSOC_CONTROL_UNBLOCK;

    /* period */
    if (block) {
        if (!json_object_object_get_ex(json.object, "period", &json.period) ||
            !json_object_is_type(json.period, json_type_int)) {
            goto out;
        }
        tlv.validity_period = json_object_get_int(json.period);
    }

    /* Sta mac adresses */
    if (!json_object_object_get_ex(json.object, "stamacs", &json.stamacs) ||
        !json_object_is_type(json.stamacs, json_type_array)) {
        goto out;
    }

    for (i = 0; i < json_object_array_length(json.stamacs) && i < MAX_STATION_PER_BSS; i++) {
        struct json_object *obj = json_object_array_get_idx(json.stamacs, i);

        if (!obj || !json_object_is_type(obj, json_type_string)) {
            goto out;
        }

        if (mac_from_string(json_object_get_string(obj), tlv.sta_macs[i])) {
            goto out;
        }
    }
    tlv.sta_macs_nr = i;

    args_ok = true;

    if (0 != map_send_client_acl_request(ale, &tlv, MID_NA)) {
        map_cli_printf("failed to send request to ale[%s]\n", ale->al_mac_str);
        goto out;
    }

    map_cli_printf("OK\n");

out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_send_backhaul_sta_capability_query(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "almac": "AA:BB:CC:DD:EE:FF",
     *   }
     */

    map_ale_info_t *ale     = NULL;
    bool            args_ok = false;

    struct {
        struct json_object *object;
    } json;

    JSON_PARSE

    /* Get ale */
    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    args_ok = true;
    if (map_send_backhaul_sta_capability_query(ale, MID_NA)) {
        goto out;
    }

    map_cli_printf("OK\n");

out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_send_backhaul_steering_request(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "almac": "AA:BB:CC:DD:EE:FF",
     *      "stamac": "AA:BB:CC:DD:EE:FF",
     *      "bssid": "AA:BB:CC:DD:EE:FF",
     *      "opclass": 115,
     *      "channel": 36
     *   }
     */

    map_ale_info_t                      *ale     = NULL;
    map_backhaul_steering_request_tlv_t  tlv = {0};
    bool                                 args_ok = false;

    struct {
        struct json_object *object;
        struct json_object *opclass;
        struct json_object *channel;
    } json;

    JSON_PARSE

    CHECK_PRINT_HELP(g_help_send_backhaul_steering_request)

    /* Get ale */
    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    /* Get stamac */
    if (json_get_mac(json.object, "stamac", tlv.bsta_mac)) {
        goto out;
    }

    /* Get bssid */
    if (json_get_mac(json.object, "bssid", tlv.target_bssid)) {

        goto out;
    }

    /* Get opclass */
    if (!json_object_object_get_ex(json.object, "opclass", &json.opclass) ||
        !json_object_is_type(json.opclass, json_type_int)) {
        goto out;
    }
    tlv.target_op_class = json_object_get_int(json.opclass);

    /* Get channel */
    if (!json_object_object_get_ex(json.object, "channel", &json.channel) ||
        !json_object_is_type(json.channel, json_type_int)) {
        goto out;
    }
    tlv.target_channel = json_object_get_int(json.channel);

    args_ok = true;

    if (0 != map_send_backhaul_steering_request(ale, &tlv, MID_NA)) {
        map_cli_printf("failed to send request to ale[%s]\n", ale->al_mac_str);
        goto out;
    }

    map_cli_printf("OK\n");

out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_send_unsuccess_assoc_policy_config(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "almac": "AA:BB:CC:DD:EE:FF",
     *      "report": true|false,
     *      "max_reporting_rate": 10
     *   }
     */

    map_policy_config_tlvs_t             tlvs                       = {0};
    map_unsuccessful_assoc_policy_tlv_t  unsuccess_assoc_policy_tlv = {0};
    map_ale_info_t                      *ale;
    int8_t                               report = 0;
    int32_t                              max_reporting_rate = 0;
    bool                                 args_ok = false;

    struct {
        struct json_object *object;
        struct json_object *report;
        struct json_object *max_reporting_rate;
    } json;

    JSON_PARSE

    CHECK_PRINT_HELP(g_help_send_unsuccess_assoc_policy_config);

    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    if (!json_object_object_get_ex(json.object, "report", &json.report) ||
        !json_object_is_type(json.report, json_type_boolean)) {
        goto out;
    }
    report = json_object_get_boolean(json.report);

    if (!json_object_object_get_ex(json.object, "max_reporting_rate", &json.max_reporting_rate) ||
        !json_object_is_type(json.max_reporting_rate, json_type_int)) {
        goto out;
    }

    max_reporting_rate = json_object_get_int(json.max_reporting_rate);
    if (errno == EINVAL || max_reporting_rate <= 0) {
        goto out;
    }
    args_ok = true;

    unsuccess_assoc_policy_tlv.report_flag = report ? MAP_UNSUCCESSFUL_ASSOC_REPORT : MAP_UNSUCCESSFUL_ASSOC_NO_REPORT;
    unsuccess_assoc_policy_tlv.max_reporting_rate = max_reporting_rate;

    tlvs.unsuccess_assoc_policy_tlv = &unsuccess_assoc_policy_tlv;
    if (0 != map_send_policy_config_request(ale, &tlvs, MID_NA)) {
        map_cli_printf("failed to send policy config to ale[%s]\n", ale->al_mac_str);
        goto out;
    }

    map_cli_printf("OK\n");

out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_send_bh_bss_policy_config(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "no_of_bssid": 2,
     *      "bssid_list":
     *      [
     *          {
     *              "bssid": "AA:BB:CC:DD:EE:FF",
     *              "p1_bsta_disallowed": true|false,
     *              "p2_bsta_disallowed": true|false,
     *          },
     *          {
     *              "bssid": "11:22:33:44:55:66",
     *              "p1_bsta_disallowed": true|false,
     *              "p2_bsta_disallowed": true|false,
     *          },
     *      ]
     *   }
     */

    map_policy_config_tlvs_t  tlvs = {0};
    map_ale_info_t           *last_ale = NULL;
    map_bss_info_t           *bss;
    int                       i, l, bssid_count;
    bool                      args_ok = false;

    struct {
        struct json_object *object;
        struct json_object *no_of_bssid;
        struct {
            struct json_object *object;
            struct json_object *p1_bsta_disallowed;
            struct json_object *p2_bsta_disallowed;
        } bssid_list;
    } json;

    JSON_PARSE

    CHECK_PRINT_HELP(g_help_send_bh_bss_policy_config)

    /* get number of bssid */
    if (!json_object_object_get_ex(json.object, "no_of_bssid", &json.no_of_bssid) ||
       !json_object_is_type(json.no_of_bssid, json_type_int)) {
        goto out;
    }

    bssid_count = json_object_get_int(json.no_of_bssid);
    if (errno == EINVAL || bssid_count <= 0) {
        goto out;
    }

    /* get bssid list and its properties */
    if (!json_object_object_get_ex(json.object, "bssid_list", &json.bssid_list.object) ||
        !json_object_is_type(json.bssid_list.object, json_type_array)) {
        goto out;
    }

    l = json_object_array_length(json.bssid_list.object);
    if (l != bssid_count) {
        map_cli_printf("no_of_bssid and bssid_list length do not match.\n");
        goto out;
    }

    tlvs.bh_bss_config_tlvs_nr = bssid_count;
    if (!(tlvs.bh_bss_config_tlvs = calloc(1, bssid_count * sizeof(map_backhaul_bss_configuration_tlv_t)))) {
        goto out;
    }
    for (i = 0; i < l; i++) {
        struct json_object *bssid_obj = json_object_array_get_idx(json.bssid_list.object, i);
        if (NULL == bssid_obj) {
            goto out;
        }

        if (json_get_mac(bssid_obj, "bssid", tlvs.bh_bss_config_tlvs[i].bssid)) {
            goto out;
        }

        if (!json_object_object_get_ex(bssid_obj, "p1_bsta_disallowed", &json.bssid_list.p1_bsta_disallowed) ||
            !json_object_is_type(json.bssid_list.p1_bsta_disallowed, json_type_boolean)) {
            goto out;
        }
        tlvs.bh_bss_config_tlvs[i].p1_bsta_disallowed = json_object_get_boolean(json.bssid_list.p1_bsta_disallowed) ? 1 : 0;

        if (!json_object_object_get_ex(bssid_obj, "p2_bsta_disallowed", &json.bssid_list.p2_bsta_disallowed) ||
            !json_object_is_type(json.bssid_list.p2_bsta_disallowed, json_type_boolean)) {
            goto out;
        }
        tlvs.bh_bss_config_tlvs[i].p2_bsta_disallowed = json_object_get_boolean(json.bssid_list.p2_bsta_disallowed) ? 1 : 0;

        bss = map_dm_get_bss_gbl(tlvs.bh_bss_config_tlvs[i].bssid);
        if (NULL == bss || NULL == bss->radio->ale) {
            map_cli_printf("cannot found config for given bss: %s\n", acu_mac_string(tlvs.bh_bss_config_tlvs[i].bssid));
            goto out;
        }

        if (last_ale != NULL && last_ale != bss->radio->ale) {
            map_cli_printf("BSSIDs should belong to same ALE!\n");
            goto out;
        }
        last_ale = bss->radio->ale;
    }
    args_ok = true;

    if (0 != map_send_policy_config_request(last_ale, &tlvs, MID_NA)) {
        map_cli_printf("failed to send policy config to ale[%s]\n", last_ale->al_mac_str);
        goto out;
    }

    map_cli_printf("OK\n");

out:
    free(tlvs.bh_bss_config_tlvs);
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_send_channel_scan_request(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
    * {
    *    "almac":"AA:BB:CC:DD:EE:FF",
    *    "fresh_scan":true,
    *    "no_of_radios":2,
    *    "radio_list":
    *    [
    *         {
    *             "radio_id":"AA:BB:CC:DD:EE:FF",
    *             "no_of_opclass":1,
    *             "opclass_list":
    *             [
    *                 {
    *                     "opclass":118,
    *                     "no_of_channels":1,
    *                     "channel_list":
    *                     [
    *                         64,
    *                     ]
    *                 }
    *             ]
    *         },
    *         {
    *             "radio_id":"11:22:33:44:55:66",
    *             "no_of_opclass":1,
    *             "opclass_list":
    *             [
    *                 {
    *                     "opclass":81,
    *                     "no_of_channels":4,
    *                     "channel_list":
    *                     [
    *                         7,8,9,10,
    *                     ]
    *                 }
    *             ]
    *         },
    *     ]
    * }
    */

    map_channel_scan_request_tlv_t  channel_scan_req_tlv = {0};
    map_ale_info_t                 *ale;
    int                             l, i, j, channel_nr, channel_len, k, channel;
    bool                            args_ok = false;

    struct {
        struct json_object *object;
        struct json_object *fresh_scan;
        struct json_object *no_of_radios;
        struct {
            struct json_object *object;
            struct json_object *no_of_opclass;
            struct {
                struct json_object *object;
                struct json_object *opclass;
                struct json_object *no_of_channels;
                struct json_object *channel_list;
            } opclass_list;
        } radio_list;
    } json;

    JSON_PARSE

    CHECK_PRINT_HELP(g_help_send_channel_scan_request)

    /* Get ale */
    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    /* get fresh scan bit */
    if (!json_object_object_get_ex(json.object, "fresh_scan", &json.fresh_scan) ||
        !json_object_is_type(json.fresh_scan, json_type_boolean)) {
        goto out;
    }
    channel_scan_req_tlv.fresh_scan_performed = json_object_get_boolean(json.fresh_scan) ? 1 : 0;

    /* get number of radios */
    if (!json_object_object_get_ex(json.object, "no_of_radios", &json.no_of_radios) ||
        !json_object_is_type(json.no_of_radios, json_type_int)) {
        goto out;
    }

    channel_scan_req_tlv.radios_nr = json_object_get_int(json.no_of_radios);
    if (errno == EINVAL || channel_scan_req_tlv.radios_nr <= 0) {
        goto out;
    }

    /* get radio list and its properties */
    if (!json_object_object_get_ex(json.object, "radio_list", &json.radio_list.object) ||
        !json_object_is_type(json.radio_list.object, json_type_array)) {
        goto out;
    }

    l = json_object_array_length(json.radio_list.object);
    if (l != channel_scan_req_tlv.radios_nr) {
        map_cli_printf("no_of_radios and radio_list length do not match.\n");
        goto out;
    }
    for (i = 0; i < l; i++) {
        struct json_object *radio_obj = json_object_array_get_idx(json.radio_list.object, i);
        if (NULL == radio_obj) {
            goto out;
        }

        /* get radio id of each radio */
        if (json_get_mac(radio_obj, "radio_id", channel_scan_req_tlv.radios[i].radio_id)) {
            goto out;
        }

        /* get number of opclass */
        if (!json_object_object_get_ex(radio_obj, "no_of_opclass", &json.radio_list.no_of_opclass) ||
            !json_object_is_type(json.radio_list.no_of_opclass, json_type_int)) {
            goto out;
        }

        channel_scan_req_tlv.radios[i].op_classes_nr = json_object_get_int(json.radio_list.no_of_opclass);
        if (errno == EINVAL || (int8_t)channel_scan_req_tlv.radios[i].op_classes_nr < 0) {
            goto out;
        }

        /* get opclass list and its properties */
        if (!json_object_object_get_ex(radio_obj, "opclass_list", &json.radio_list.opclass_list.object) ||
            !json_object_is_type(json.radio_list.opclass_list.object, json_type_array)) {
            goto out;
        }

        int opcl_len = json_object_array_length(json.radio_list.opclass_list.object);
        if (opcl_len != channel_scan_req_tlv.radios[i].op_classes_nr) {
            map_cli_printf("no_of_opclass and opclass_list length do not match.\n");
            goto out;
        }

        for (j = 0; j < opcl_len; j++) {
            struct json_object *opclass_obj = json_object_array_get_idx(json.radio_list.opclass_list.object, j);
            if (NULL == opclass_obj) {
                goto out;
            }

            /* get opclass */
            if (!json_object_object_get_ex(opclass_obj, "opclass", &json.radio_list.opclass_list.opclass) ||
                !json_object_is_type(json.radio_list.opclass_list.opclass, json_type_int)) {
                goto out;
            }

            channel_scan_req_tlv.radios[i].op_classes[j].op_class = json_object_get_int(json.radio_list.opclass_list.opclass);
            if (errno == EINVAL || channel_scan_req_tlv.radios[i].op_classes[j].op_class <= 0) {
                goto out;
            }

            /* get number of channels for current opclass */
            if (!json_object_object_get_ex(opclass_obj, "no_of_channels", &json.radio_list.opclass_list.no_of_channels) ||
                !json_object_is_type(json.radio_list.opclass_list.no_of_channels, json_type_int)) {
                goto out;
            }

            channel_nr = json_object_get_int(json.radio_list.opclass_list.no_of_channels);
            if (errno == EINVAL || channel_nr < 0) {
                goto out;
            }

            /* get channel list */
            if (!json_object_object_get_ex(opclass_obj, "channel_list", &json.radio_list.opclass_list.channel_list) ||
                !json_object_is_type(json.radio_list.opclass_list.channel_list, json_type_array)) {
                goto out;
            }

            channel_len = json_object_array_length(json.radio_list.opclass_list.channel_list);
            if (channel_len != channel_nr) {
                map_cli_printf("no_of_channels and channel_list length do not match.\n");
                goto out;
            }

            for (k = 0; k < channel_len; k++) {
                struct json_object *channel_obj = json_object_array_get_idx(json.radio_list.opclass_list.channel_list, k);
                if (NULL == channel_obj) {
                    goto out;
                }

                channel = json_object_get_int(channel_obj);
                if (errno == EINVAL || channel <= 0) {
                    goto out;
                }
                map_cs_set(&channel_scan_req_tlv.radios[i].op_classes[j].channels, channel);
            }
        }
    }
    args_ok = true;

    if (map_send_channel_scan_request(ale, &channel_scan_req_tlv, MID_NA)) {
        map_cli_printf("failed to send channel scan request.\n");
        goto out;
    }

    map_cli_printf("OK\n");
out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_send_cac_request(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
    * {
    *    "almac":"AA:BB:CC:DD:EE:FF",
    *    "no_of_reqs":2,
    *    "cac_req_list":
    *    [
    *         {
    *             "radio_id":"AA:BB:CC:DD:EE:FF",
    *             "opclass":118,
    *             "channel":64,
    *             "cac_method":"cont|cont_wdedicated_radio|mimo_dim_reduced|time_sliced",
    *             "cac_completion_act":"remain_continue_mon|return_prev_conf"
    *         },
    *         {
    *             "radio_id":"11:22:33:44:55:66",
    *             "opclass":81,
    *             "channel":10,
    *             "cac_method":"cont|cont_wdedicated_radio|mimo_dim_reduced|time_sliced",
    *             "cac_completion_act":"remain_continue_mon|return_prev_conf"
    *         },
    *     ]
    * }
    */

    map_cac_request_tlv_t  cac_request_tlv = {0};
    map_ale_info_t        *ale;
    int                    l, i, ret;
    const char            *cac_method;
    const char            *cac_completion_action;
    bool                   args_ok = false;

    struct {
        struct json_object *object;
        struct json_object *no_of_reqs;
        struct {
            struct json_object *object;
            struct json_object *opclass;
            struct json_object *channel;
            struct json_object *cac_method;
            struct json_object *cac_completion_action;
        } cac_req_list;
    } json;

    JSON_PARSE

    CHECK_PRINT_HELP(g_help_send_cac_request)

    /* Get ale */
    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    /* get number of radios */
    if (!json_object_object_get_ex(json.object, "no_of_reqs", &json.no_of_reqs) ||
        !json_object_is_type(json.no_of_reqs, json_type_int)) {
        goto out;
    }

    cac_request_tlv.radios_nr = json_object_get_int(json.no_of_reqs);
    if (errno == EINVAL || cac_request_tlv.radios_nr <= 0) {
        goto out;
    }

    /* get radio list and its properties */
    if (!json_object_object_get_ex(json.object, "cac_req_list", &json.cac_req_list.object) ||
        !json_object_is_type(json.cac_req_list.object, json_type_array)) {
        goto out;
    }

    l = json_object_array_length(json.cac_req_list.object);
    if (l != cac_request_tlv.radios_nr) {
        map_cli_printf("no_of_reqs and cac_req_list length do not match.\n");
        goto out;
    }
    for (i = 0; i < l; i++) {
        struct json_object *cac_obj = json_object_array_get_idx(json.cac_req_list.object, i);
        if (NULL == cac_obj) {
            goto out;
        }

        /* get radio id of each radio */
        if (json_get_mac(cac_obj, "radio_id", cac_request_tlv.radios[i].radio_id)) {
            goto out;
        }

        /* get opclass */
        if (!json_object_object_get_ex(cac_obj, "opclass", &json.cac_req_list.opclass) ||
            !json_object_is_type(json.cac_req_list.opclass, json_type_int)) {
            goto out;
        }

        cac_request_tlv.radios[i].op_class = json_object_get_int(json.cac_req_list.opclass);
        if (errno == EINVAL || cac_request_tlv.radios[i].op_class <= 0) {
            goto out;
        }

        /* get channel */
        if (!json_object_object_get_ex(cac_obj, "channel", &json.cac_req_list.channel) ||
            !json_object_is_type(json.cac_req_list.channel, json_type_int)) {
            goto out;
        }

        cac_request_tlv.radios[i].channel = json_object_get_int(json.cac_req_list.channel);
        if (errno == EINVAL || cac_request_tlv.radios[i].channel <= 0) {
            goto out;
        }

        /* get CAC method */
        if (!json_object_object_get_ex(cac_obj, "cac_method", &json.cac_req_list.cac_method) ||
            !json_object_is_type(json.cac_req_list.cac_method, json_type_string)) {
            goto out;
        }

        if (NULL == (cac_method = json_object_get_string(json.cac_req_list.cac_method))) {
            goto out;
        }

        if (!strcmp(cac_method, "cont_wdedicated_radio")) {
            cac_request_tlv.radios[i].cac_method = MAP_CAC_METHOD_CONT_WDEDICATED_RADIO;
        } else if (!strcmp(cac_method, "cont")) {
            cac_request_tlv.radios[i].cac_method = MAP_CAC_METHOD_CONTINUOUS;
        } else if (!strcmp(cac_method, "mimo_dim_reduced")) {
            cac_request_tlv.radios[i].cac_method = MAP_CAC_METHOD_MIMO_DIM_REDUCED;
        } else if (!strcmp(cac_method, "time_sliced")) {
            cac_request_tlv.radios[i].cac_method = MAP_CAC_METHOD_TIME_SLICED;
        } else {
            map_cli_printf("invalid cac method\n");
            goto out;
        }

        /* get CAC completion action */
        if (!json_object_object_get_ex(cac_obj, "cac_completion_act", &json.cac_req_list.cac_completion_action) ||
            !json_object_is_type(json.cac_req_list.cac_completion_action, json_type_string)) {
            goto out;
        }

        if (NULL == (cac_completion_action = json_object_get_string(json.cac_req_list.cac_completion_action))) {
            goto out;
        }

        if (!strcmp(cac_completion_action, "remain_continue_mon")) {
            cac_request_tlv.radios[i].cac_completion_action = MAP_CAC_ACTION_REMAIN_AND_CONT_TO_MON;
        } else if (!strcmp(cac_completion_action, "return_prev_conf")) {
            cac_request_tlv.radios[i].cac_completion_action = MAP_CAC_ACTION_RETURN_PREV_OP_CONF;
        } else {
            map_cli_printf("invalid cac completion action\n");
            goto out;
        }
    }
    args_ok = true;

    ret = map_send_cac_request(ale, &cac_request_tlv, MID_NA);
    if (0 != ret) {
        if (-2 == ret) {
            /* give detailed explanation for cli users */
            map_cli_printf("There is ongoing CAC request for this agent.\n");
            goto out;
        }

        map_cli_printf("failed to send CAC request.\n");
        goto out;
    }

    map_cli_printf("OK\n");
out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_send_cac_termination(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
    * {
    *    "almac":"AA:BB:CC:DD:EE:FF",
    *    "no_of_radios":2,
    *    "cac_radio_list":
    *    [
    *         {
    *             "radio_id":"AA:BB:CC:DD:EE:FF",
    *             "opclass":118,
    *             "channel":64,
    *         },
    *         {
    *             "radio_id":"11:22:33:44:55:66",
    *             "opclass":122,
    *             "channel":140,
    *         },
    *     ]
    * }
    */

    map_cac_termination_tlv_t  cac_termination_tlv = {0};
    map_ale_info_t            *ale;
    int                        l, i;
    bool                       args_ok = false;

    struct {
        struct json_object *object;
        struct json_object *no_of_radios;
        struct {
            struct json_object *object;
            struct json_object *opclass;
            struct json_object *channel;
        } cac_radio_list;
    } json;

    JSON_PARSE

    CHECK_PRINT_HELP(g_help_send_cac_termination)

    /* Get ale */
    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    /* get number of radios */
    if (!json_object_object_get_ex(json.object, "no_of_radios", &json.no_of_radios) ||
        !json_object_is_type(json.no_of_radios, json_type_int)) {
        goto out;
    }

    cac_termination_tlv.radios_nr = json_object_get_int(json.no_of_radios);
    if (errno == EINVAL || cac_termination_tlv.radios_nr <= 0) {
        goto out;
    }

    /* get radio list and its properties */
    if (!json_object_object_get_ex(json.object, "cac_radio_list", &json.cac_radio_list.object) ||
        !json_object_is_type(json.cac_radio_list.object, json_type_array)) {
        goto out;
    }

    l = json_object_array_length(json.cac_radio_list.object);
    if (l != cac_termination_tlv.radios_nr) {
        map_cli_printf("no_of_radios and cac_radio_list length do not match.\n");
        goto out;
    }
    for (i = 0; i < l; i++) {
        struct json_object *cac_obj = json_object_array_get_idx(json.cac_radio_list.object, i);
        if (NULL == cac_obj) {
            goto out;
        }

        /* get radio id of each radio */
        if (json_get_mac(cac_obj, "radio_id", cac_termination_tlv.radios[i].radio_id)) {
            goto out;
        }

        /* get opclass */
        if (!json_object_object_get_ex(cac_obj, "opclass", &json.cac_radio_list.opclass) ||
            !json_object_is_type(json.cac_radio_list.opclass, json_type_int)) {
            goto out;
        }

        cac_termination_tlv.radios[i].op_class = json_object_get_int(json.cac_radio_list.opclass);
        if (errno == EINVAL || cac_termination_tlv.radios[i].op_class <= 0) {
            goto out;
        }

        /* get channel */
        if (!json_object_object_get_ex(cac_obj, "channel", &json.cac_radio_list.channel) ||
            !json_object_is_type(json.cac_radio_list.channel, json_type_int)) {
            goto out;
        }

        cac_termination_tlv.radios[i].channel = json_object_get_int(json.cac_radio_list.channel);
        if (errno == EINVAL || cac_termination_tlv.radios[i].channel <= 0) {
            goto out;
        }
    }
    args_ok = true;

    if (map_send_cac_termination(ale, &cac_termination_tlv, MID_NA)) {
        map_cli_printf("failed to send CAC termination message.\n");
        goto out;
    }

    map_cli_printf("OK\n");
out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_send_ch_scan_reporting_policy_config(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "almac": "AA:BB:CC:DD:EE:FF",
     *      "report_indep_scans": true|false,
     *   }
     */

    map_policy_config_tlvs_t                 tlvs                           = {0};
    map_channel_scan_reporting_policy_tlv_t  channel_scan_report_policy_tlv = {0};
    map_ale_info_t                          *ale;
    bool                                     args_ok = false;

    struct {
        struct json_object *object;
        struct json_object *report;
    } json;

    JSON_PARSE

    CHECK_PRINT_HELP(g_help_send_ch_scan_reporting_policy_config)

    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    if (!json_object_object_get_ex(json.object, "report_indep_scans", &json.report) ||
       !json_object_is_type(json.report, json_type_boolean)) {
        goto out;
    }
    args_ok = true;

    channel_scan_report_policy_tlv.report_independent_ch_scans = json_object_get_boolean(json.report) ? 1 : 0;

    tlvs.channel_scan_report_policy_tlv = &channel_scan_report_policy_tlv;
    if (map_send_policy_config_request(ale, &tlvs, MID_NA)) {
        map_cli_printf("failed to send policy config to ale[%s]\n", ale->al_mac_str);
        goto out;
    }

    map_cli_printf("OK\n");

out:
    JSON_PUT_CHECK_ARGS_OK
}

static void cli_send_dpp_cce_indication(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "almac": "AA:BB:CC:DD:EE:FF",
     *      "advertise": true|false,
     *   }
     */

    map_ale_info_t *ale;
    bool            args_ok = false;

    struct {
        struct json_object *object;
        struct json_object *advertise;
    } json;

    JSON_PARSE

    CHECK_PRINT_HELP(g_help_send_dpp_cce_indication)

    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    if (!json_object_object_get_ex(json.object, "advertise", &json.advertise) ||
        !json_object_is_type(json.advertise, json_type_boolean)) {
        goto out;
    }
    args_ok = true;

    if (map_send_dpp_cce_indication(ale, json_object_get_boolean(json.advertise), MID_NA)) {
        map_cli_printf("failed to send DPP CCE Indication to ale[%s]\n", ale->al_mac_str);
        goto out;
    }

    map_cli_printf("OK\n");

out:
    JSON_PUT_CHECK_ARGS_OK
}


static void cli_send_proxied_encap_dpp(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "almac": "AA:BB:CC:DD:EE:FF",
     *      "encap":
     *      {
     *          "stamac": "AA:BB:CC:DD:EE:FF", (Optional)
     *          "frame_indicator": 0
     *          "frame_type": 10
     *          "frame": "AABBCCDDEEFF"
     *      }
     *      "chirp":
     *      {
     *          "stamac": "AA:BB:CC:DD:EE:FF", (Optional)
     *          "hash_validity": 1
     *          "hash": "AABBCCDDEEFF"
     *      }
     *   }
     */

    map_ale_info_t            *ale;
    map_1905_encap_dpp_tlv_t   encap_tlv = {0};
    map_dpp_chirp_value_tlv_t  chirp_tlv = {0};
    bool                       add_chirp_tlv = false;
    bool                       args_ok = false;
    const char *frame_body = NULL, *hash_body = NULL;

    struct {
        struct json_object *object;
        struct {
            struct json_object *object;
            struct json_object *frame_indicator;
            struct json_object *frame_type;
            struct json_object *frame;
        } encap;
        struct {
            struct json_object *object;
            struct json_object *hash_validity;
            struct json_object *hash;
        } chirp;
    } json;

    memset(&encap_tlv, 0, sizeof(encap_tlv));
    memset(&chirp_tlv, 0, sizeof(chirp_tlv));

    JSON_PARSE

    CHECK_PRINT_HELP(g_help_send_proxied_encap_dpp)

    if (!(ale = json_get_ale(json.object, "almac"))) {
        map_cli_printf("ALE not found\n");
        goto out;
    }

    json.encap.object = json_object_object_get(json.object, "encap");
    if (json.encap.object == NULL || !json_object_is_type(json.encap.object, json_type_object)) {
        map_cli_printf("can not get encap dpp object\n");
        goto out;
    }

    /* If Enrollee MAC Address was set on CLI cmd, set the related field. */
    encap_tlv.enrollee_mac_present = 1;
    if (json_get_mac(json.encap.object, "stamac", encap_tlv.sta_mac)) {
        encap_tlv.enrollee_mac_present = 0;
    }

    if (!json_object_object_get_ex(json.encap.object, "frame_indicator", &json.encap.frame_indicator) ||
        !json_object_is_type(json.encap.frame_indicator, json_type_int)) {
        goto out;
    }
    encap_tlv.dpp_frame_indicator = json_object_get_int(json.encap.frame_indicator);

    if (!json_object_object_get_ex(json.encap.object, "frame_type", &json.encap.frame_type) ||
        !json_object_is_type(json.encap.frame_type, json_type_int)) {
        goto out;
    }
    encap_tlv.frame_type = json_object_get_int(json.encap.frame_type);

    if (!json_object_object_get_ex(json.encap.object, "frame", &json.encap.frame) ||
        !json_object_is_type(json.encap.frame, json_type_string)) {
        goto out;
    }
    frame_body = json_object_get_string(json.encap.frame);
    if (NULL == frame_body) {
        goto out;
    }
    /* Allocate strlen / 2 for byte array demonstration. */
    encap_tlv.frame = calloc(strlen(frame_body) / 2, sizeof(uint8_t));
    /* Convert string to byte array for transmission. */
    if (acu_hex_string_to_buf(frame_body, encap_tlv.frame, strlen(frame_body) / 2) != ACU_OK) {
        goto out;
    }

    encap_tlv.frame_len = strlen(frame_body) / 2;

    json.chirp.object = json_object_object_get(json.object, "chirp");
    if (json.chirp.object == NULL || !json_object_is_type(json.chirp.object, json_type_object)) {
        map_cli_printf("no chirp field in JSON.\n");
        args_ok = true;
    } else {
        /* If Enrollee MAC Address was set on CLI cmd, set the related field. */
        chirp_tlv.enrollee_mac_present = 1;
        if (json_get_mac(json.chirp.object, "stamac", chirp_tlv.sta_mac)) {
            chirp_tlv.enrollee_mac_present = 0;
        }

        if (!json_object_object_get_ex(json.chirp.object, "hash_validity", &json.chirp.hash_validity) ||
            !json_object_is_type(json.chirp.hash_validity, json_type_int)) {
            goto out;
        }
        chirp_tlv.hash_validity = json_object_get_int(json.chirp.hash_validity);

        if (!json_object_object_get_ex(json.chirp.object, "hash", &json.chirp.hash) ||
            !json_object_is_type(json.chirp.hash, json_type_string)) {
            goto out;
        }
        hash_body = json_object_get_string(json.chirp.hash);
        if (NULL == hash_body) {
            goto out;
        }
        /* Allocate strlen / 2 for byte array demonstration. */
        chirp_tlv.hash = calloc(strlen(hash_body) / 2, sizeof(uint8_t));
        /* Convert string to byte array for transmission. */
        if (acu_hex_string_to_buf(hash_body, chirp_tlv.hash, strlen(hash_body) / 2) != ACU_OK) {
            goto out;
        }
        chirp_tlv.hash_len = strlen(hash_body) / 2;

        add_chirp_tlv = true;
        args_ok = true;
    }

    if (map_send_proxied_encap_dpp(ale, &encap_tlv, add_chirp_tlv ? &chirp_tlv : NULL, MID_NA)) {
        map_cli_printf("failed to send 1905 Encap DPP message to ale[%s]\n", ale->al_mac_str);
        goto out;
    }

    map_cli_printf("OK\n");

out:
    free(encap_tlv.frame);
    free(chirp_tlv.hash);
    JSON_PUT_CHECK_ARGS_OK
}

static inline void dump_hex(unsigned char *buf, int len, const char *indent)
{
    int i;

    map_cli_printf("%s", indent);
    for (i = 0; i < len; i++) {
        if (i > 0 && (i % 16) == 0) {
            map_cli_printf("\n%s", indent);
        }
        map_cli_printf("%02x ", buf[i]);
    }
    map_cli_printf("\n");
}

static inline int skip_ws(const char *str)
{
    int idx = 0;

    while (isblank(str[idx]) == 1) {
        idx++;
    }
    return idx;
}

static int parse_payload(const char *str, char **ifname, unsigned char **data, int *datalen)
{
#define ETHERNET_MIN_PKT_LEN    60
#define ETHERNET_MAX_PKT_LEN  1514
    unsigned char buf[ETHERNET_MAX_PKT_LEN];
    const char *errstr;
    const char *nptr;
    char *endptr;
    unsigned long hex_byte;
    int idx = 0, fidx, clen;

    errstr = "ifname format is wrong.";
    idx = skip_ws(str);
    if (str[idx] == '\0' || str[idx] == '|')
        goto fail;
    fidx = idx;
    do {
        if (!islower(str[idx]) && !isdigit(str[idx]) && str[idx] != '.')
            goto fail;
        idx++;
    } while (str[idx] != '|' && str[idx] != '\0');
    if (str[idx] == '\0') {
        goto fail;
    }
    errstr = "Failed to alloc mem for ifname.\n";
    *ifname = strndup(&str[fidx], idx - fidx);
    if (!*ifname) {
        goto fail;
    }
    errstr = "data format is wrong.";
    idx++;
    nptr = str + idx;
    idx += skip_ws(nptr);
    if (str[idx] == '\0') {
        goto fail_ifname_free;
    }
    nptr = str + idx;
    fidx = 0;
    do {
        int off = 0;

        off = skip_ws(nptr);
        nptr += off;
        if (*nptr == '\0')
            break;
        idx += off;
        hex_byte = strtoul(nptr, &endptr, 16);
        if (*endptr != '\0' && !isblank(*endptr))
            goto fail_ifname_free;
        clen = endptr - nptr;
        if (clen > 2)
            goto fail_ifname_free;
        if (fidx >= ETHERNET_MAX_PKT_LEN) {
            errstr = "data too long.";
            goto fail_ifname_free;
        }
        buf[fidx++] = (unsigned char)hex_byte;
        nptr += clen;
        idx += clen;
    } while (str[idx] != '\0');
    if (fidx < ETHERNET_MIN_PKT_LEN) {
        memset(&buf[fidx], 0, ETHERNET_MIN_PKT_LEN - fidx);
        fidx = ETHERNET_MIN_PKT_LEN;
    }
    *datalen = fidx;
    *data = malloc(*datalen);
    if (!*data) {
        errstr = "Failed to alloc mem for data.";
        goto fail_ifname_free;
    }
    memcpy(*data, buf, *datalen);
    return 0;
fail_ifname_free:
    free(*ifname);
    *ifname = NULL;
fail:
    map_cli_printf("[%s-%d] %s\n", __func__, __LINE__, errstr);
    return -1;
}

static void cli_send_raw_message(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    unsigned char *data, *dmac, *smac;
    char *ifname;
    int rc, data_len;
    unsigned short eth_type;

    /*
     * payload: "$ifname|MSB raw message bytes in hex separated by ws (network byte order) LSB"
     */
    rc = parse_payload(payload, &ifname, &data, &data_len);
    if (rc != 0) {
        map_cli_printf("[%s-%d] payload format is invalid.\n", __func__, __LINE__);
        return;
    }
    map_cli_printf("[%s-%d] payload format is valid.\n", __func__, __LINE__);
    map_cli_printf("[%s-%d] data is:\n", __func__, __LINE__);
    dump_hex(data, data_len, "\t");
    dmac = data;
    smac = &data[6];
    eth_type = ntohs(*(unsigned short *)(&data[12]));
    rc = map_send_raw(ifname, dmac, smac, eth_type, data + 14, data_len - 14);
    if (rc == 0) {
        map_cli_printf("[%s-%d] Managed to send raw message\n", __func__, __LINE__);
    } else {
        map_cli_printf("[%s-%d] Failed to send raw message\n", __func__, __LINE__);
    }
    SFREE(data);
    SFREE(ifname);
}

/*#######################################################################
#                       CLI HANDLERS: VARIOUS                           #
########################################################################*/

static void cli_send_wfa_capi(UNUSED const char *event, const char *payload, UNUSED void *context)
{
    /*
     * payload:
     *   {
     *      "args": "..."
     *   }
     */

    char *args      = NULL;
    const char *str = NULL;
    bool  args_ok   = false;
    int   ret;

    struct {
        struct json_object *object;
        struct json_object *args;
    } json;

    JSON_PARSE

    CHECK_PRINT_HELP(g_help_send_wfa_capi)

    ret = json_object_object_get_ex(json.object, "args", &json.args);
    if (0 == ret || !json_object_is_type(json.args, json_type_string)) {
        goto out;
    }

    /* Must dup as command handling uses strtok which modifies the string */
    if (!(str = json_object_get_string(json.args)) || !(args = strdup(str))) {
        goto out;
    }

    map_ctrl_wfa_capi(args, map_cli_printf);

    args_ok = true;

out:
    free(args);
    JSON_PUT_CHECK_ARGS_OK
}

/*#######################################################################
#                       CLI SUBSCRIPTIONS                               #
########################################################################*/
static map_subscription_t g_cli_subscriptions[] = {
    /* DUMP /GET */
    { "help",                                   cli_help,                                   (SUBS_FLAG_MODE_FULL | SUBS_FLAG_MODE_REDUCED) },
    { "version",                                cli_version,                                (SUBS_FLAG_MODE_FULL | SUBS_FLAG_MODE_REDUCED) },
    { "dumpCtrlInfo",                           cli_dump_info,                              (SUBS_FLAG_MODE_FULL | SUBS_FLAG_MODE_REDUCED) },
    { "dumpInterfaces",                         cli_dump_interfaces,                        (SUBS_FLAG_MODE_FULL | SUBS_FLAG_MODE_REDUCED) },
    { "dumpBlockList",                          cli_dump_blocklist,                         (SUBS_FLAG_MODE_FULL | SUBS_FLAG_MODE_REDUCED) },
    { "dumpOpClasses",                          cli_dump_op_classes,                        (SUBS_FLAG_MODE_FULL | SUBS_FLAG_MODE_REDUCED) },
    { "dumpChanSel",                            cli_dump_chan_sel,                          (SUBS_FLAG_MODE_FULL) },
    { "dumpTunneledMessage",                    cli_dump_tunneled_msg,                      (SUBS_FLAG_MODE_FULL) },
    { "dumpAPMetrics",                          cli_dump_ap_metrics,                        (SUBS_FLAG_MODE_FULL) },
    { "dumpRadioMetrics",                       cli_dump_radio_metrics,                     (SUBS_FLAG_MODE_FULL) },
    { "dumpStaMetrics",                         cli_dump_sta_metrics,                       (SUBS_FLAG_MODE_FULL) },
    { "getChannelScanResults",                  cli_get_scan_results,                       (SUBS_FLAG_MODE_FULL) },

    /* SET */
    { "setChannel",                             cli_set_channel,                            (SUBS_FLAG_MODE_FULL) },

    /* SEND */
    { "sendTopologyQuery",                      cli_send_topology_query,                    (SUBS_FLAG_MODE_FULL) },
    { "sendLinkMetricQuery",                    cli_send_link_metric_query,                 (SUBS_FLAG_MODE_FULL) },
    { "sendAutoconfigRenew",                    cli_send_autoconfig_renew,                  (SUBS_FLAG_MODE_FULL) },
    { "sendAPCapabilityQuery",                  cli_send_ap_capability_query,               (SUBS_FLAG_MODE_FULL) },
    { "sendChannelPreferenceQuery",             cli_send_channel_preference_query,          (SUBS_FLAG_MODE_FULL) },
    { "sendClientCapabilityQuery",              cli_send_client_capability_query,           (SUBS_FLAG_MODE_FULL) },
    { "sendAssocStaLinkMetricsQuery",           cli_send_assoc_sta_link_metrics_query,      (SUBS_FLAG_MODE_FULL) },
    { "sendUnassocStaLinkMetricsQuery",         cli_send_unassoc_sta_link_metrics_query,    (SUBS_FLAG_MODE_FULL) },
    { "sendBeaconMetricsQuery",                 cli_send_beacon_metrics_query,              (SUBS_FLAG_MODE_FULL) },
    { "sendCombinedInfrastructureMetrics",      cli_send_combined_infrastructure_metrics,   (SUBS_FLAG_MODE_FULL) },
    { "sendClientSteeringRequest",              cli_send_client_steering_request,           (SUBS_FLAG_MODE_FULL) },
    { "sendClientAssocControlRequest",          cli_send_client_assoc_control_request,      (SUBS_FLAG_MODE_FULL) },
    { "sendBackhaulStaCapabilityQuery",         cli_send_backhaul_sta_capability_query,     (SUBS_FLAG_MODE_FULL) },
    { "sendBackhaulSteeringRequest",            cli_send_backhaul_steering_request,         (SUBS_FLAG_MODE_FULL) },
    { "sendUnsuccessAssocPolicyConf",           cli_send_unsuccess_assoc_policy_config,     (SUBS_FLAG_MODE_FULL) },
    { "sendBhBssPolicyConf",                    cli_send_bh_bss_policy_config,              (SUBS_FLAG_MODE_FULL) },
    { "sendChannelScanRequest",                 cli_send_channel_scan_request,              (SUBS_FLAG_MODE_FULL) },
    { "sendCACRequest",                         cli_send_cac_request,                       (SUBS_FLAG_MODE_FULL) },
    { "sendCACTermination",                     cli_send_cac_termination,                   (SUBS_FLAG_MODE_FULL) },
    { "sendChScanReportPolicyConf",             cli_send_ch_scan_reporting_policy_config,   (SUBS_FLAG_MODE_FULL) },
    { "sendDPPCCEIndication",                   cli_send_dpp_cce_indication,                (SUBS_FLAG_MODE_FULL) },
    { "sendProxiedEncapDPP",                    cli_send_proxied_encap_dpp,                 (SUBS_FLAG_MODE_FULL) },
    { "sendRawMessage",                         cli_send_raw_message,                       (SUBS_FLAG_MODE_FULL | SUBS_FLAG_MODE_REDUCED) },

    /* VARIOUS */
    { "sendWFACapi",                            cli_send_wfa_capi,                          (SUBS_FLAG_MODE_FULL) },
};

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
void map_cli_vprintf(const char *fmt, va_list args)
{
    cli_vprintf(g_cli, fmt, args);
}

void map_cli_printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    map_cli_vprintf(fmt, args);
    va_end(args);
}

int map_cli_init(void)
{
    cli_options_t cli_options;
    size_t        i;

    /* Create cli and subscriptions */
    memset(&cli_options, 0, sizeof(cli_options_t));
    map_strlcpy(cli_options.sock_path, CLI_SOCK_PATH, sizeof(cli_options.sock_path));

    if (NULL == (g_cli = cli_create(&cli_options))) {
        log_ctrl_e("can not create cli");
            goto fail;
    }

    for (i = 0; i < ARRAY_SIZE(g_cli_subscriptions); i++) {
        map_subscription_t *s = &g_cli_subscriptions[i];
        if (0 != cli_subscribe(g_cli, s->event, s->handler, s->flags, NULL)) {
            log_ctrl_e("can not subscribe cli event: %s", s->event);
            goto fail;
        }
    }

    if (NULL == (g_cli_fd = acu_evloop_fd_add(cli_fd(g_cli), map_cli_fd_cb, g_cli))) {
        log_ctrl_e("failed register cli socket");
        goto fail;
    }

    return 0;
fail:
    return -1;
}

void map_cli_fini(void)
{
    if (g_cli_fd != NULL) {
        acu_evloop_fd_delete(g_cli_fd);
    }
    if (g_cli != NULL) {
        cli_destroy(g_cli);
    }
}
