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

#ifndef MAP_CTRL_DEFINES_H_
#define MAP_CTRL_DEFINES_H_

/* Timer ID's */
#define TOPOLOGY_QUERY_TIMER_ID            "TOPOLOGY-QUERY-TIMER"
#define DELAYED_TOPOLOGY_QUERY_TIMER_ID    "DELAYED-TOPOLOGY-QUERY-TIMER"
#define LINK_METRIC_QUERY_TIMER_ID         "LINK-METRIC-TIMER"
#define TOPOLOGY_DISCOVERY_TIMER_ID        "TOPOLOGY-DISOVERY-TIMER"
#define LLDP_BRIDGE_DISCOVERY_TIMER_ID     "LLDP-BRIDGE-DISCOVERY-TIMER"
#define AP_CAPABILITY_QUERY_TIMER_ID       "AP-CAPABILITY-QUERY-TIMER"
#define CONFIG_RENEW_TIMER_ID              "CONFIG_RENEW_TIMER"
#define TOPOLOGY_STABLE_CHECK_TIMER_ID     "TOPOLOGY_STABLE_CHECK_TIMER"
#define AUTO_CONFIG_SEARCH_TIMER_ID        "AUTO-CONFIG_SEARCH-TIMER"

#define MAX_TOPOLOGY_QUERY_RETRY            5
#define ALE_KEEP_ALIVE_THRESHOLD_IN_SEC     30

#define MAP_CHAN_SEL_PREF_AGENT             0x00
#define MAP_CHAN_SEL_PREF_CONTROLLER        0x01
#define MAP_CHAN_SEL_PREF_MERGED            0x02

#define MAP_CHAN_SEL_BACKOFF_TIME           30

#define MAX_NEIGHBOR_COUNT                  256
#define MAX_ALE_NEIGHBOR_COUNT              32

#define MAX_DEAD_AGENT_DETECT_TIME_IN_SEC   240
#define MIN_DEAD_AGENT_DETECT_TIME_IN_SEC   15

#define INITIAL_CONFIG_RENEW_TIME           10
#define ONBOARDING_STATUS_CHECK_TIME        30

#define SCAN_REQUEST_TIMEOUT                30
#define MAX_INITIAL_SCAN_RETRY              6
#define INITIAL_SCAN_RETRY_PERIOD           SCAN_REQUEST_TIMEOUT /* 3 minutes in total */

#endif /* MAP_CTRL_DEFINES_H_ */
