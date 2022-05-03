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

#include <libubox/uloop.h>

#define LOG_TAG "main"

#include "map_ctrl_cmdu_rx.h"
#include "map_ctrl_utils.h"
#include "map_ctrl_onboarding_handler.h"
#include "map_ctrl_config.h"
#include "map_ctrl_cli.h"
#include "map_ctrl_topology_tree.h"

#include "map_timer_handler.h"
#include "map_retry_handler.h"
#include "map_airdata.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
/* TODO: Autogenerate with build_version.h */
#ifndef MAP_GIT_BRANCH
#define MAP_GIT_BRANCH  "HEAD"
#endif
#ifndef MAP_GIT_HASH
#define MAP_GIT_HASH    "b736affc7b65c1a8d5671a76f5896a356558538a"
#endif
#define BUILD_VERSION   MAP_GIT_BRANCH"-"MAP_GIT_HASH

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static bool g_ebtables;
static bool g_wfa_cert;
static bool g_signal_stop = false;

/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
static void signal_stop_handler(UNUSED int signum)
{
    if (signum != SIGINT) {
        ssp_stack_backtrace();
    }
    g_signal_stop = true;
    uloop_end();
}

static void signal_ignore_handler(UNUSED int signum)
{
}

static void print_usage()
{
    printf("------MultiAP Controller Daemon-------\n");
    printf(" -e   set ebtables rules\n");
    printf(" -w   wfa certification\n");
}

static void parse_options(int argc, char *argv[])
{
    int opt = 0;

    while(-1 != (opt = getopt( argc, argv, "ew" ))) {
        switch( opt ) {
            case 'e':
                g_ebtables = true;
            break;
            case 'w':
                g_wfa_cert = true;
            break;
            case 'h':
            case '?':
            default:
                print_usage();
                exit(EXIT_FAILURE);
                break;
        }
    }
}

static void interface_cb(const char *ifname, bool added)
{
    log_ctrl_i("interface[%s] %s", ifname, added ? "added" : "removed");

    if (added) {
        /* Send some fast topology discovery to make sure we
           are discovered quickly
        */
        map_restart_topology_discovery();
    }
}

/* TODO: create a proper header file */
int ssp_fini(void);
int ssp_main(int argc, char *argv[]);
void ssp_stack_backtrace(void);

/*#######################################################################
#                       MAIN                                            #
########################################################################*/
int main(int argc, char *argv[])
{
    struct sigaction sig_stop_action;
    struct sigaction sig_no_reaction;
    bool             enabled;

    openlog("Multiap_Controller", 0, LOG_DAEMON);

    parse_options(argc,argv);
    ssp_main(argc, argv);

    do {
        /* Signal handlers */
        sig_stop_action.sa_handler = signal_stop_handler;
        sigemptyset(&sig_stop_action.sa_mask);
        sig_stop_action.sa_flags = 0;
        sigaction(SIGTERM, &sig_stop_action, NULL);
        sigaction(SIGINT, &sig_stop_action, NULL);
        sigaction(SIGSEGV, &sig_stop_action, NULL);
        sigaction(SIGBUS, &sig_stop_action, NULL);
        sigaction(SIGKILL, &sig_stop_action, NULL);
        sigaction(SIGFPE, &sig_stop_action, NULL);
        sigaction(SIGILL, &sig_stop_action, NULL);
        sigaction(SIGQUIT, &sig_stop_action, NULL);
        sigaction(SIGHUP, &sig_stop_action, NULL);

        sig_no_reaction.sa_handler = signal_ignore_handler;
        sigemptyset(&sig_no_reaction.sa_mask);
        sig_no_reaction.sa_flags = 0;
        //sigaction(SIGHUP,  &sig_no_reaction, NULL);
        sigaction(SIGPIPE, &sig_no_reaction, NULL);
        sigaction(SIGALRM, &sig_no_reaction, NULL);
        sigaction(SIGUSR1, &sig_no_reaction, NULL);
        sigaction(SIGUSR2, &sig_no_reaction, NULL);

        uloop_init();

        /* Init airdata */
        if (map_airdata_init("libairdata.so")) {
            log_ctrl_e("map_airdata_init failed");
            break;
        }

        /* Init config */
        if (map_cfg_init()) {
            log_ctrl_e("map_cfg_init failed");
            break;
        }

        /* Check dormant mode
           NOTE: only read MultiAPControllerEnabled as all the rest might
                 not yet be configured
        */
dormant_loop:
        map_cfg_set_dormant_cbs();
        if (map_cfg_is_enabled(&enabled)) {
            log_ctrl_e("map_cfg_is_enabled failed");
            break;
        }
        if (!enabled) {
            /* Uloop run exits when config enabled callback is called */
            uloop_run();
            if (g_signal_stop) {
                break; /* exit gracefully */
            }
            goto dormant_loop;
        }

        /* Load config */
        if (map_cfg_load(BUILD_VERSION, g_wfa_cert)) {
            log_ctrl_e("map_cfg_load failed");
            break;
        }

        /* Ebtables rules
           - For licensing products, ebtables rules for controller mac must be set by integrator.
           - For 4960, the easiest is to still do it from here
        */
        if (g_ebtables) {
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

        map_cfg_set_running_cbs();

        /* Load profiles.
           NOTE: Do not load profiles when doing WFA certification as
                 in this case profiles are configured by CAPI command
        */
        if (!g_wfa_cert) {
            if (map_profile_load(NULL)) {
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

        /* CLI */
        if (map_cli_init()) {
            log_ctrl_e("map_cli_init failed");
            break;
        }

        log_ctrl_e("map_controller started");

        uloop_run();
    } while (0);

    map_cli_fini();

    map_onboarding_handler_fini();

    map_dm_fini();

    i1905_fini();

    map_retry_handler_fini();

    map_timer_handler_fini();

    map_cfg_fini();

    map_airdata_fini();

    uloop_done();

    ssp_fini();

    log_ctrl_e("map_controller stopped");

    return 0;
}
