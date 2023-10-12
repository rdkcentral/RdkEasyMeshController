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
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>

#define LOG_TAG "main"

#include "map_ctrl_cmdu_rx.h"
#include "map_ctrl_utils.h"
#include "map_ctrl_onboarding_handler.h"
#include "map_ctrl_config.h"
#include "map_ctrl_cli.h"
#include "map_ctrl_topology_tree.h"
#include "map_ctrl_chan_sel.h"
#include "map_ctrl_nbapi.h"

#include "map_timer_handler.h"
#include "map_retry_handler.h"
#include "map_staging_list.h"
#include "map_blocklist.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
/* TODO: Autogenerate with build_version.h */
#ifndef MAP_GIT_BRANCH
#define MAP_GIT_BRANCH  "HEAD"
#endif
#ifndef MAP_GIT_HASH
#define MAP_GIT_HASH    "300abe0f3933f28fe89f90db41269cd80774a7d0"
#endif
#define BUILD_VERSION   MAP_GIT_BRANCH"-"MAP_GIT_HASH

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static bool g_signal_stop = false;

/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
static void interface_cb(const char *ifname, bool added)
{
    log_ctrl_n("interface[%s] %s", ifname, added ? "added" : "removed");

    if (added) {
        map_restart_topology_discovery(ifname);
    } else {
        map_stop_topology_discovery(ifname);
    }
}

/*#######################################################################
#                       MAIN                                            #
########################################################################*/
int map_ctrl_main(bool ebtables, bool wfa_cert)
{
    bool enabled;

    openlog("Multiap_Controller", 0, LOG_DAEMON);

    do {
        if (acu_evloop_init()) {
            log_ctrl_e("acu_evloop_init failed");
            goto fini;
        }

        /* Init map info */
        if (map_info_init()) {
            log_ctrl_e("map_info_init failed");
            break;
        }

        /* Init config */
        if (map_cfg_init()) {
            log_ctrl_e("map_cfg_init failed");
            break;
        }

dormant_loop:
        map_cfg_set_dormant_cbs();
        if (map_cfg_is_enabled(&enabled)) {
            log_ctrl_e("map_cfg_is_enabled failed");
            break;
        }
        if (!enabled) {
            /* Uloop run exits when config enabled callback is called */
            acu_evloop_run();
            if (g_signal_stop) {
                break; /* exit gracefully */
            }
            goto dormant_loop;
        }

        /* Load config */
        if (map_cfg_load(BUILD_VERSION, wfa_cert)) {
            log_ctrl_e("map_cfg_load failed");
            break;
        }

        /* Ebtables rules
           - For licensing products, ebtables rules for controller mac must be set by integrator.
           - For 4960, the easiest is to still do it from here
        */
        if (ebtables) {
            if (map_set_ebtables_rules(get_controller_cfg()->al_mac)) {
                log_ctrl_e("map_set_ebtables_rules failed");
                break;
            }
        }

        /* Timer handler */
        if (map_timer_handler_init() != 0) {
            log_ctrl_e("map_timer_handler_init failed");
            break;
        }

        /* Retry handler */
        if (map_retry_handler_init()) {
            log_ctrl_e("map_retry_handler_init failed");
            break;
        }

        /* 1905 stack */
        if (i1905_init(get_controller_cfg()->al_mac, interface_cb, map_cmdu_rx_cb)) {
            log_ctrl_e("init_map_controller_callback failed");
            break;
        }

        /* CLI */
        if (map_cli_init()) {
            log_ctrl_e("map_cli_init failed");
            break;
        }

        map_cfg_set_running_cbs();

        /* Load profiles.
           NOTE: Do not load profiles when doing WFA certification as
                 in this case profiles are configured by CAPI command
        */
        if (!wfa_cert) {
            if (map_profile_load(NULL, true)) {
                log_ctrl_e("map_profile_load failed");
                break;
            }
        }

        /* Datamodel */
        if (map_dm_init()) {
            log_ctrl_e("map_dm_init failed");
            break;
        }

        /* Topology tree */
        if (map_ctrl_topology_tree_init()) {
            log_ctrl_e("map_ctrl_topology_tree_init failed");
            break;
        }

        /* Onboarding */
        if (map_onboarding_handler_init()) {
            log_ctrl_e("map_onboarding_handler_init failed");
            break;
        }

        /* Channel selection */
        if (map_ctrl_chan_sel_init()) {
            log_ctrl_e("map_ctrl_chan_sel_init failed");
            break;
        }

        /* Northbound API */
        if (map_ctrl_nbapi_init()) {
            log_ctrl_e("map_ctrl_nbapi_init failed");
            break;
        }

        map_stglist_init();

        map_blocklist_init();

        log_ctrl_e("map_controller started");

        acu_evloop_run();
    } while (0);


    /* Deinit in reverse order */
    map_blocklist_fini();

    map_stglist_fini();

    map_ctrl_nbapi_fini();

    map_ctrl_chan_sel_fini();

    map_onboarding_handler_fini();

    map_dm_fini();

    map_cli_fini();

    i1905_fini();

    map_retry_handler_fini();

    map_timer_handler_fini();

    map_cfg_fini();

    map_info_fini();

fini:
    acu_evloop_fini();

    log_ctrl_e("map_controller stopped");

    return 0;
}

void map_controller_stop(void)
{
    g_signal_stop = true;
    acu_evloop_end();
}
