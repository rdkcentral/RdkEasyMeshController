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
#define LOG_TAG "metrics"

#include "map_ctrl_metrics_handler.h"
#include "map_ctrl_cmdu_tx.h"
#include "map_topology_tree.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define MAX_STA_METRICS_COUNT 16

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
void map_update_assoc_sta_link_metrics(map_sta_info_t* sta, map_sta_link_metrics_t* link_metrics)
{
    if (sta == NULL || link_metrics == NULL) {
        return;
    }

    if (list_get_size(sta->metrics) >= MAX_STA_METRICS_COUNT) {
        map_sta_link_metrics_t* node = remove_last_object(sta->metrics);
        free(node);
    }

    if (-1 == push_object(sta->metrics, (void*)link_metrics)) {
        log_ctrl_e("Failed updating the station metrics");
        return;
    }
}

/* Send link metric query to all known ALE */
uint8_t map_periodic_link_metric_query_timer_cb(UNUSED char* timer_id, UNUSED void *arg)
{
    map_ale_info_t *ale;

    map_dm_foreach_agent_ale(ale) {
        i1905_link_metric_query_tlv_t tlv = { .tlv_type          = TLV_TYPE_LINK_METRIC_QUERY,
                                              .destination       = LINK_METRIC_QUERY_TLV_ALL_NEIGHBORS,
                                              .link_metrics_type = LINK_METRIC_QUERY_TLV_BOTH_TX_AND_RX_LINK_METRICS
                                            };
        map_send_link_metric_query(ale, &tlv, MID_NA);
    }
    return 0;
}
