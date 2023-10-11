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
#define LOG_TAG "cmdu_rx"

#include "map_ctrl_cmdu_validator.h"
#include "map_ctrl_cmdu_handler.h"

#include "map_retry_handler.h"

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
/* There are two types of CMDU callbacks:
   - without ALE: use for CMDU that can be received at a moment the ALE might not be known yet
   - with ALE:    use for CMDU that can only be processed when ALE is known
*/

typedef struct {
    uint16_t   cmdu_type;
    int      (*validate_cb)     (i1905_cmdu_t *cmdu);
    int      (*validate_ale_cb) (map_ale_info_t *ale, i1905_cmdu_t *cmdu);
    int      (*handle_cb)       (i1905_cmdu_t *cmdu);
    int      (*handle_ale_cb)   (map_ale_info_t *ale, i1905_cmdu_t *cmdu);
} cmdu_cbs_t;

/*#######################################################################
#                       CMDU CALLBACK TABLE                             #
########################################################################*/
static cmdu_cbs_t g_cmdu_cbs[]={
    /* 1905.1 */
    {
        .cmdu_type       = CMDU_TYPE_TOPOLOGY_DISCOVERY,                         /* 1905.1 6.3.1 (type 0x0000) */
        .validate_cb     = map_validate_topology_discovery,
        .handle_cb       = map_handle_topology_discovery,
    },
    {
        .cmdu_type       = CMDU_TYPE_TOPOLOGY_QUERY,                             /* 1905.1 6.3.2 (type 0x0001) */
        .validate_cb     = map_validate_topology_query,
        .handle_cb       = map_handle_topology_query,
    },
    {
        .cmdu_type       = CMDU_TYPE_TOPOLOGY_RESPONSE,                          /* 1905.1 6.3.3 (type 0x0002) */
        .validate_cb     = map_validate_topology_response,
        .handle_cb       = map_handle_topology_response,
    },
    {
        .cmdu_type       = CMDU_TYPE_TOPOLOGY_NOTIFICATION,                      /* 1905.1 6.3.4 (type 0x0003) */
        .validate_cb     = map_validate_topology_notification,
        .handle_cb       = map_handle_topology_notification,
    },
    {
        .cmdu_type       = CMDU_TYPE_LINK_METRIC_QUERY,                          /* 1905.1 6.3.5 (type 0x0005) */
        .validate_ale_cb = map_validate_link_metrics_query,
        .handle_ale_cb   = map_handle_link_metrics_query,
    },
    {
        .cmdu_type       = CMDU_TYPE_LINK_METRIC_RESPONSE,                       /* 1905.1 6.3.6 (type 0x0006) */
        .validate_ale_cb = map_validate_link_metrics_response,
        .handle_ale_cb   = map_handle_link_metrics_response,
    },
    {
        .cmdu_type       = CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH,                /* 1905.1 6.3.7 (type 0x0007) */
        .validate_cb     = map_validate_ap_autoconfig_search,
        .handle_cb       = map_handle_ap_autoconfig_search,
    },
    {
        .cmdu_type       = CMDU_TYPE_AP_AUTOCONFIGURATION_WSC,                   /* 1905.1 6.3.9 (type 0x0009) */
        .validate_cb     = map_validate_ap_autoconfig_wsc,
        .handle_cb       = map_handle_ap_autoconfig_wsc,
    },
    {
        .cmdu_type       = CMDU_TYPE_VENDOR_SPECIFIC,                            /* 1905.1 6.3.13 (type 0x0004) */
        .validate_ale_cb = map_validate_vendor_specific,
        .handle_ale_cb   = map_handle_vendor_specific,
    },


    /* MAP R1 */
    {
        .cmdu_type       = CMDU_TYPE_MAP_ACK,                                    /* MAP_R1 17.1 (type 0x8000) */
        .validate_cb     = map_validate_ack,
        .handle_cb       = map_handle_ack,
    },
    {
        .cmdu_type       = CMDU_TYPE_MAP_AP_CAPABILITY_REPORT,                   /* MAP_R1 17.1.6 (type 0x8002) */
        .validate_ale_cb = map_validate_ap_capability_report,
        .handle_ale_cb   = map_handle_ap_capability_report,
    },
    {
        .cmdu_type       = CMDU_TYPE_MAP_CHANNEL_PREFERENCE_REPORT,              /* MAP_R1 17.1.10 (type 0x8005) */
        .validate_ale_cb = map_validate_channel_preference_report,
        .handle_ale_cb   = map_handle_channel_preference_report,
    },
    {
        .cmdu_type       = CMDU_TYPE_MAP_CHANNEL_SELECTION_RESPONSE,             /* MAP_R1 17.1.12 (type 0x8007) */
        .validate_ale_cb = map_validate_channel_selection_response,
        .handle_ale_cb   = map_handle_channel_selection_response,
    },
    {
        .cmdu_type       = CMDU_TYPE_MAP_OPERATING_CHANNEL_REPORT,               /* MAP_R1 17.1.13 (type 0x8008) */
        .validate_ale_cb = map_validate_operating_channel_report,
        .handle_ale_cb   = map_handle_operating_channel_report,
    },
    {
        .cmdu_type       = CMDU_TYPE_MAP_CLIENT_CAPABILITY_REPORT,               /* MAP_R1 17.1.15 (type 0x800A) */
        .validate_ale_cb = map_validate_client_capability_report,
        .handle_ale_cb   = map_handle_client_capability_report,
    },
    {
        .cmdu_type       = CMDU_TYPE_MAP_AP_METRICS_RESPONSE,                    /* MAP_R1 17.1.17 (type 0x800C) */
        .validate_ale_cb = map_validate_ap_metrics_response,
        .handle_ale_cb   = map_handle_ap_metrics_response,
    },
    {
        .cmdu_type       = CMDU_TYPE_MAP_ASSOCIATED_STA_LINK_METRICS_RESPONSE,   /* MAP_R1 17.1.19 (type 0x800E) */
        .validate_ale_cb = map_validate_assoc_sta_link_metrics_response,
        .handle_ale_cb   = map_handle_assoc_sta_link_metrics_response,
    },
    {
        .cmdu_type       = CMDU_TYPE_MAP_UNASSOCIATED_STA_LINK_METRICS_RESPONSE, /* MAP_R1 17.1.21 (type 0x8010) */
        .validate_ale_cb = map_validate_unassoc_sta_link_metrics_response,
        .handle_ale_cb   = map_handle_unassoc_sta_link_metrics_response,
    },
    {
        .cmdu_type       = CMDU_TYPE_MAP_BEACON_METRICS_RESPONSE,                /* MAP_R1 17.1.23 (type 0x8012) */
        .validate_ale_cb = map_validate_beacon_metrics_response,
        .handle_ale_cb   = map_handle_beacon_metrics_response,
    },
    {
        .cmdu_type       = CMDU_TYPE_MAP_CLIENT_STEERING_BTM_REPORT,             /* MAP_R1 17.1.26 (type 0x8015) */
        .validate_ale_cb = map_validate_client_steering_btm_report,
        .handle_ale_cb   = map_handle_client_steering_btm_report,
    },
    {
        .cmdu_type       = CMDU_TYPE_MAP_STEERING_COMPLETED,                     /* MAP_R1 17.1.28 (type 0x8017) */
        .validate_ale_cb = map_validate_steering_completed,
        .handle_ale_cb   = map_handle_steering_completed,
    },
    {
        .cmdu_type       = CMDU_TYPE_MAP_BACKHAUL_STEERING_RESPONSE,             /* MAP_R1 17.1.30 (type 0x801A) */
        .validate_ale_cb = map_validate_backhaul_steering_response,
        .handle_ale_cb   = map_handle_backhaul_steering_response,
    },
    {
        .cmdu_type       = CMDU_TYPE_MAP_HIGHER_LAYER_DATA,                      /* MAP_R1 17.1.31 (type 0x8018) */
        .validate_ale_cb = map_validate_higher_layer_data,
        .handle_ale_cb   = map_handle_higher_layer_data,
    },


    /* MAP R2 */
    {
        .cmdu_type       = CMDU_TYPE_MAP_CHANNEL_SCAN_REPORT,                    /* MAP_R2 17.1.34 (type 0x801C) */
        .validate_ale_cb = map_validate_channel_scan_report,
        .handle_ale_cb   = map_handle_channel_scan_report,
    },
    {
        .cmdu_type       = CMDU_TYPE_MAP_ASSOCIATION_STATUS_NOTIFICATION,        /* MAP_R2 17.1.39 (type 0x8025) */
        .validate_ale_cb = map_validate_assoc_status_notification,
        .handle_ale_cb   = map_handle_assoc_status_notification,
    },
    {
        .cmdu_type       = CMDU_TYPE_MAP_TUNNELED,                               /* MAP_R2 17.1.40 (type 0x8026) */
        .validate_ale_cb = map_validate_tunneled_msg,
        .handle_ale_cb   = map_handle_tunneled_msg,
    },
    {
        .cmdu_type       = CMDU_TYPE_MAP_CLIENT_DISASSOCIATION_STATS,            /* MAP_R2 17.1.41 (type 0x8022) */
        .validate_ale_cb = map_validate_client_disassoc_stats,
        .handle_ale_cb   = map_handle_client_disassoc_stats,
    },
    {
        .cmdu_type       = CMDU_TYPE_MAP_BACKHAUL_STA_CAPABILITY_REPORT,         /* MAP_R2 17.1.43 (type 0x8028) */
        .validate_ale_cb = map_validate_backhaul_sta_capability_report,
        .handle_ale_cb   = map_handle_backhaul_sta_capability_report,
    },
    {
        .cmdu_type       = CMDU_TYPE_MAP_FAILED_CONNECTION,                      /* MAP_R2 17.1.44 (type 0x8033) */
        .validate_ale_cb = map_validate_failed_connection,
        .handle_ale_cb   = map_handle_failed_connection,
    },

    /* MAP R3 */
    {
        .cmdu_type       = CMDU_TYPE_MAP_PROXIED_ENCAP_DPP,                     /* MAP_R3 17.1.48 (type 0x8029) */
        .validate_ale_cb = map_validate_proxied_encap_dpp,
        .handle_ale_cb   = map_handle_proxied_encap_dpp,
    },
    {
        .cmdu_type       = CMDU_TYPE_MAP_1905_ENCAP_EAPOL,                      /* MAP_R3 17.1.49 (type 0x8030) */
        .validate_ale_cb = map_validate_1905_encap_eapol,
        .handle_ale_cb   = map_handle_1905_encap_eapol,
    },
    {
        .cmdu_type       = CMDU_TYPE_MAP_DIRECT_ENCAP_DPP,                      /* MAP_R3 17.1.56 (type 0x802a) */
        .validate_ale_cb = map_validate_direct_encap_dpp,
        .handle_ale_cb   = map_handle_direct_encap_dpp,
    },
    {
        .cmdu_type       = CMDU_TYPE_MAP_CHIRP_NOTIFICATION,                    /* MAP_R3 17.1.52 (type 0x802f) */
        .validate_ale_cb = map_validate_chirp_notification,
        .handle_ale_cb   = map_handle_chirp_notification,
    },
};

/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
static cmdu_cbs_t *get_cmdu_cbs(uint16_t cmdu_type)
{
    size_t i;
    size_t arr_size;
    cmdu_cbs_t *cmdu_cbs;

    cmdu_cbs = (cmdu_cbs_t *)&g_cmdu_cbs;
    arr_size = ARRAY_SIZE(g_cmdu_cbs);

    for (i = 0; i < arr_size; i++ ) {
        if (cmdu_cbs[i].cmdu_type == cmdu_type) {
            return &cmdu_cbs[i];
        }
    }

    return NULL;
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
bool map_cmdu_rx_cb(i1905_cmdu_t *cmdu)
{
    cmdu_cbs_t     *cbs         = get_cmdu_cbs(cmdu->message_type);
    const char     *cmdu_name   = i1905_cmdu_type_to_string(cmdu->message_type);
    uint8_t        *src_mac     = cmdu->cmdu_stream.src_mac_addr;
    map_ale_info_t *ale         = NULL;
    mac_addr_str    src_mac_str = { 0 };

    if (!cbs) {
        log_ctrl_i("cmdu[%s] not handled", cmdu_name);
        return false;
    }

    mac_to_string(src_mac, src_mac_str);
    log_ctrl_d("received cmdu[%s] interface[%s] src[%s]",
               cmdu_name, cmdu->interface_name, src_mac_str);

    if (!cmdu->list_of_TLVs) {
        log_ctrl_e("cmdu[%s] malformed", cmdu_name);
        goto cleanup;
    }

    /* Get ale if needed */
    if (cbs->validate_ale_cb && !(ale = map_dm_get_ale_from_src_mac(src_mac))) {
        log_ctrl_i("cmdu[%s] src[%s]: ale not found - ignoring", cmdu_name, src_mac_str);
        goto cleanup;
    }

    /* Validate cmdu */
    if ((cbs->validate_ale_cb && cbs->validate_ale_cb(ale, cmdu)) ||
        (cbs->validate_cb && cbs->validate_cb(cmdu))) {
        log_ctrl_e("cmdu[%s] src[%s]: validation failed", cmdu_name, src_mac_str);
        goto cleanup;
    }

    /* Get ale again if needed */
    if (cbs->handle_ale_cb && !ale && !(ale = map_dm_get_ale_from_src_mac(src_mac))) {
        log_ctrl_i("cmdu[%s] src[%s]: ale not found - ignoring", cmdu_name, src_mac_str);
        goto cleanup;
    }

    /* Handle cmdu */
    if ((cbs->handle_ale_cb && cbs->handle_ale_cb(ale, cmdu)) ||
        (cbs->handle_cb && cbs->handle_cb(cmdu))) {
        log_ctrl_e("cmdu[%s] src[%s]: handler failed", cmdu_name, src_mac_str);
        goto cleanup;
    }

    map_update_retry_handler(cmdu->message_id, cmdu);

cleanup:
    i1905_cmdu_free(cmdu);
    return true;
}
