/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#define LOG_TAG "onboarding"

#include "map_ctrl_onboarding_handler.h"
#include "map_ctrl_post_onboarding_handler.h"
#include "map_ctrl_topology_tree.h"
#include "map_ctrl_metrics_handler.h"
#include "map_ctrl_cmdu_tx.h"
#include "map_topology_tree.h"
#include "map_timer_handler.h"
#include "map_retry_handler.h"
#include "map_ctrl_utils.h"
#include "map_ctrl_defines.h"
#include "map_info.h"
#include "map_dm_eth_device_list.h"
#include "arraylist.h"
#include "1905_platform.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define START_TOPOLOGY_DISCOVERY_INTERVAL        1 /* second */
#define TOPOLOGY_DISCOVERY_INTERVAL_SCALE_FACTOR 4

#define min(a,b) ((a) < (b) ? (a) : (b))

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
static int send_topology_discovery(const char *ifname)
{
    i1905_interface_info_t *info = i1905_get_interface_info((char *)ifname);
    int                     ret  = -1;

    if (info) {
        ret = map_send_topology_discovery(info, MID_NA);
        i1905_free_interface_info(info);
    }

    return ret;
}

static uint8_t map_topology_discovery_timer_cb(char* timer_id, void *arg)
{
    uintptr_t  cfg_interval = get_controller_cfg()->topology_discovery_interval;
    uintptr_t  cur_interval = (int)(uintptr_t)arg;
    char      *ifname       = &timer_id[sizeof(TOPOLOGY_DISCOVERY_TIMER_ID)];

    send_topology_discovery(ifname);

    /* Set next timeout */
    if (cur_interval < cfg_interval) {
        cur_interval *= TOPOLOGY_DISCOVERY_INTERVAL_SCALE_FACTOR;
        cur_interval = min(cur_interval, cfg_interval);
        map_timer_change_callback(timer_id, cur_interval, (void*)cur_interval);
    }

    return 0;
}

static uint8_t map_lldp_discovery_timer_cb(UNUSED char* timer_id, UNUSED void *arg)
{
    char      **interfaces;
    uint8_t     nr_interfaces, i;

    interfaces = i1905_get_list_of_interfaces(&nr_interfaces);

    if (interfaces) {
        for (i = 0; i < nr_interfaces; i++) {
            i1905_interface_info_t *info = i1905_get_interface_info(interfaces[i]);

           if (info) {
                map_send_lldp_bridge_discovery(info);
                i1905_free_interface_info(info);
            }
        }

        i1905_free_list_of_interfaces(interfaces, nr_interfaces);
    }

    return 0;
}

/* Send topology query to all known ALE */
static uint8_t map_periodic_topology_query_timer_cb(UNUSED char* timer_id, UNUSED void *arg)
{
    map_ale_info_t *ale;

    map_dm_foreach_agent_ale(ale) {
        if (map_is_topology_update_required(ale)) {
            map_register_topology_query_retry(ale);
        }
    }

    /* Schedule derivation of ethernet client locations */
    map_dm_eth_device_list_schedule_update();

    return 0;
}

/* Send ap capability query to all known ALE */
static uint8_t map_periodic_ap_capability_query_timer_cb(UNUSED char* timer_id, UNUSED void *arg)
{
    map_ale_info_t *ale;

    map_dm_foreach_agent_ale(ale) {
        map_send_ap_capability_query(ale, MID_NA);
    }

    return 0;
}

/* Send config renew */
static uint8_t map_config_renew_timer_cb(UNUSED char* timer_id, UNUSED void *arg)
{
    if (map_send_autoconfig_renew(IEEE80211_FREQUENCY_BAND_2_4_GHZ, MID_NA)){
        log_ctrl_e("map_send_autoconfig_renew failed");
        return 0; /* Restart timer */
    }

    map_reset_all_agent_nodes_onboarding_status();

    return 1; /* Remove timer */
}

static uint8_t get_configured_radio_nr(map_ale_info_t* ale)
{
    map_radio_info_t *radio;
    int8_t            configured_radio_nr = 0;

    map_dm_foreach_radio(ale, radio) {
        configured_radio_nr += is_radio_configured(radio->state) ? 1 : 0;
    }

    return configured_radio_nr;
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
int map_onboarding_handler_init()
{
    int16_t link_interval        = get_controller_cfg()->link_metrics_query_interval;
    int16_t topquery_interval    = get_controller_cfg()->topology_query_interval;
    int16_t apcapquery_interval  = get_controller_cfg()->ap_capability_query_interval;
    int16_t lldp_br_dis_interval = get_controller_cfg()->lldp_interval;
    int     status = 0;

    do {
        /* Registering a timer for lldp bridge discovery message */
        if (lldp_br_dis_interval > 0) {
            if (lldp_br_dis_interval > 60) {
                lldp_br_dis_interval = 3; /* Default to basic requirement of LLDP interval */
            }
            if (map_timer_register_callback(lldp_br_dis_interval, LLDP_BRIDGE_DISCOVERY_TIMER_ID, NULL, map_lldp_discovery_timer_cb)) {
                log_ctrl_e("failed to register LLDP-DISCOVERY-TIMER");
                ERROR_EXIT(status)
            }
        }

        /* Registering a timer for topology query */
        if (topquery_interval > 0) {
            if (topquery_interval > 60) {
                topquery_interval = 60;
            }
            if (map_timer_register_callback(topquery_interval, TOPOLOGY_QUERY_TIMER_ID, NULL, map_periodic_topology_query_timer_cb)) {
                log_ctrl_e("failed to register TOPOLOGY_QUERY_TIMER");
                ERROR_EXIT(status)
            }
        }

        /* Registering a timer for link metric query */
        if (link_interval > 0) {
            if (link_interval > 60) {
                link_interval = 60;
            }
            if (map_timer_register_callback(link_interval, LINK_METRIC_QUERY_TIMER_ID, NULL, map_periodic_link_metric_query_timer_cb)) {
                log_ctrl_e("failed to register LINK_METRIC_QUERY_TIMER");
                ERROR_EXIT(status)
            }
        }

        /* Registering a timer for ap capability query */
        if (apcapquery_interval > 0) {
            if (map_timer_register_callback(apcapquery_interval, AP_CAPABILITY_QUERY_TIMER_ID, NULL, map_periodic_ap_capability_query_timer_cb)) {
                log_ctrl_e("failed to register AP_CAPABILITY_QUERY_TIMER_ID");
                ERROR_EXIT(status)
            }
        }

        /* Send initial config renew.
           Don't do this during wfa cert to avoid sending unexpected config renew that might confuse the testbed.
        */
        if (!WFA_CERT()) {
            if (map_timer_register_callback(INITIAL_CONFIG_RENEW_TIME, CONFIG_RENEW_TIMER_ID, NULL, map_config_renew_timer_cb)) {
                log_ctrl_e("failed to register CONFIG_RENEW_TIMER");
                ERROR_EXIT(status)
            }
        }
    } while (0);

    return status;
}

void map_onboarding_handler_fini(void)
{
    map_timer_unregister_callback_prefix(TOPOLOGY_DISCOVERY_TIMER_ID);

    if (map_is_timer_registered(LLDP_BRIDGE_DISCOVERY_TIMER_ID)) {
        map_timer_unregister_callback(LLDP_BRIDGE_DISCOVERY_TIMER_ID);
    }

    if (map_is_timer_registered(TOPOLOGY_QUERY_TIMER_ID)) {
        map_timer_unregister_callback(TOPOLOGY_QUERY_TIMER_ID);
    }

    if (map_is_timer_registered(LINK_METRIC_QUERY_TIMER_ID)) {
        map_timer_unregister_callback(LINK_METRIC_QUERY_TIMER_ID);
    }

    if (map_is_timer_registered(AP_CAPABILITY_QUERY_TIMER_ID)) {
        map_timer_unregister_callback(AP_CAPABILITY_QUERY_TIMER_ID);
    }

    if (map_is_timer_registered(CONFIG_RENEW_TIMER_ID)) {
        map_timer_unregister_callback(CONFIG_RENEW_TIMER_ID);
    }
}

/* For Controller certification we need not require channel mgmt at post onboarding operation.
   This API will be used a control flag to enable or disable channel selection.
*/
bool map_is_channel_selection_enabled()
{
    /* In case of WFA certification, channel selection is triggered by CAPI command */
    return !WFA_CERT() && get_controller_cfg()->channel_selection_enabled;
}

uint16_t map_get_dead_agent_detection_interval()
{
    unsigned int interval = 0;

    interval = get_controller_cfg()->dead_agent_detection_interval;

    if (interval < MIN_DEAD_AGENT_DETECT_TIME_IN_SEC) {
        interval = MIN_DEAD_AGENT_DETECT_TIME_IN_SEC;
    } else if (interval > MAX_DEAD_AGENT_DETECT_TIME_IN_SEC) {
        interval = MAX_DEAD_AGENT_DETECT_TIME_IN_SEC;
    }

    return interval;
}

uint16_t map_get_topology_query_retry_interval_sec()
{
    return map_get_dead_agent_detection_interval() / MAX_TOPOLOGY_QUERY_RETRY;
}

map_ale_info_t* map_handle_new_agent_onboarding(uint8_t *al_mac, char *recv_iface, bool easymesh_plus)
{
    map_ale_info_t* ale;

    if (!al_mac || !recv_iface) {
        return NULL;
    }

    /* This will update the topology tree */
    if (!(ale = map_dm_get_ale(al_mac))) {
        if ((ale = map_dm_create_ale(al_mac))) {
            /* Update the receiving interface name */
            map_update_ale_receiving_iface(ale, recv_iface);

            /* Send topology query as soon as we create */
            map_send_topology_query(ale, MID_NA);

            /* Start onboarding status check timer */
            map_start_onboarding_status_check_timer(ale);

            /* Set default profile to 1 */
            ale->map_profile = MAP_PROFILE_1;

            ale->easymesh_plus = easymesh_plus;
        } else {
            log_ctrl_e("failed creating ALE node");
        }
    }

    return ale;
}

map_radio_info_t* map_handle_new_radio_onboarding(map_ale_info_t *ale, uint8_t *radio_id, bool do_policy_config)
{
    map_radio_info_t *radio;
    timer_id_t        retry_id;

    if (!ale || !radio_id) {
        return NULL;
    }

    if (!(radio = map_dm_create_radio(ale, radio_id))) {
        return NULL;
    }

    if (do_policy_config) {
        /* Send policy config request */
        map_dm_get_radio_timer_id(retry_id, radio, POLICY_CONFIG_RETRY_ID);
        if (!map_is_timer_registered(retry_id)) {
            if (map_register_retry(retry_id, 10, 10,
                                        ale, map_handle_policy_config_sent, map_build_and_send_policy_config)) {
                log_ctrl_e("Failed registering retry timer[%s] ", retry_id);
            }
        }
    }

    /* Send initial channel scan request when needed */
    if (!is_radio_initial_scan_results_received(radio->state)) {
        map_dm_get_radio_timer_id(retry_id, radio, INITIAL_SCAN_REQ_RETRY_ID);
        /* Because at least BRCM agent restarts one or more times due to initial
           onboarding we must try long enough to get successfull initial scan.
           -> Start retry 6 times with 30 second timeout.
        */
        if (!map_is_timer_registered(retry_id)) {
            if (map_register_retry(retry_id, INITIAL_SCAN_RETRY_PERIOD, MAX_INITIAL_SCAN_RETRY,
                                radio, map_handle_initial_channel_scan_request_sent, map_build_and_send_initial_channel_scan_req)) {
                log_ctrl_e("Failed Registering retry timer : %s ", retry_id);
            }
        }
    }

    return radio;
}

bool map_is_agent_onboarded(map_ale_info_t *ale)
{
    if (!ale) {
        return 0;
    }

    return (ale->ale_onboard_status == ALE_NODE_ONBOARDED);
}

bool map_is_all_radio_M1_received(map_ale_info_t* ale)
{
    map_radio_info_t *radio;
    bool              all_M1_received = true;

    if (!ale) {
        return false;
    }

    map_dm_foreach_radio(ale, radio) {
        /* Mark the agent as M1 received if all radios are in M1 received state */
        if (!is_radio_M1_received(radio->state)) {
            all_M1_received = false;
            break;
        }
    }
    return all_M1_received;
}

bool map_is_all_radio_configured(map_ale_info_t* ale)
{
    if (ale) {
        uint8_t configured_radio_nr = get_configured_radio_nr(ale);
        if (configured_radio_nr && (configured_radio_nr == ale->radios_nr)) {
            return true;
        }
    }
    return false;
}

void map_restart_topology_discovery(const char *ifname)
{
    int        topo_dis_interval = get_controller_cfg()->topology_discovery_interval;
    int        start_interval    = START_TOPOLOGY_DISCOVERY_INTERVAL;
    timer_id_t timer_id;

    /* Send first topology discovery immediatly */
    send_topology_discovery(ifname);

    if (topo_dis_interval == 0) {
        return;
    }

    /* Add interface name in timer id */
    snprintf(timer_id, sizeof(timer_id), "%s_%s", TOPOLOGY_DISCOVERY_TIMER_ID, ifname);

    if (map_is_timer_registered(timer_id)) {
        /* Go back to initial timeout. Do not restart to avoid that this is done several times in a row */
        map_timer_change_callback(timer_id, start_interval, (void*)(uintptr_t)start_interval);
    } else {
        if (map_timer_register_callback(start_interval, timer_id, (void*)(uintptr_t)start_interval, map_topology_discovery_timer_cb)) {
            log_ctrl_e("failed starting timer[%s]", timer_id);
        }
    }
}

void map_stop_topology_discovery(const char *ifname)
{
    timer_id_t timer_id;

    snprintf(timer_id, sizeof(timer_id), "%s_%s", TOPOLOGY_DISCOVERY_TIMER_ID, ifname);

    if (map_is_timer_registered(timer_id)) {
        map_timer_unregister_callback(timer_id);
    }
}
