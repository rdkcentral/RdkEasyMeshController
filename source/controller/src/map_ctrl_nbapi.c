/*
 * Copyright (c) 2023 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define LOG_TAG "nbapi"

#include "map_ctrl_cmdu_tx.h"
#include "map_ctrl_tlv_helper.h"
#include "map_ctrl_nbapi.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
typedef struct client_assoc_control_s {
    map_ale_info_t                         *ale;
    bool                                    request_sent;
    map_client_assoc_control_request_tlv_t  tlv;
} client_assoc_control_t;

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/

/*#######################################################################
#                       API FUNCTIONS                                   #
########################################################################*/

static void nb_channel_scan(map_ale_info_t *ale, map_nb_ch_scan_param_t *payload)
{
    map_channel_scan_request_tlv_t  tlv = {0};
    unsigned int i;

    if (!ale || !payload) {
        return;
    }

    tlv.fresh_scan_performed    = true;
    tlv.radios_nr               = 1;
    maccpy(&tlv.radios[0].radio_id, &payload->radio_id);
    tlv.radios[0].op_classes_nr = payload->op_classes_nr;
    for (i = 0; i < payload->op_classes_nr; i++) {
        tlv.radios[0].op_classes[i].op_class = payload->op_classes[i].op_class;
        tlv.radios[0].op_classes[i].channels = payload->op_classes[i].channels;
    }

    if (map_send_channel_scan_request(ale, &tlv, MID_NA)) {
        log_ctrl_e("send channel scan request failed");
    }
}

static void nb_beacon_metrics_query(map_ale_info_t *ale, map_nb_bmquery_param_t *payload)
{
    map_beacon_metrics_query_tlv_t  tlv = {0};
    unsigned int i;

    if (!ale || !payload) {
        return;
    }

    maccpy(&tlv.sta_mac, &payload->sta_mac);
    tlv.op_class              = payload->op_class;
    tlv.channel               = payload->channel;
    maccpy(&tlv.bssid, &payload->bssid);
    tlv.reporting_detail      = payload->reporting_detail;
    tlv.ssid_len              = strlen(payload->ssid);
    memcpy(tlv.ssid, payload->ssid, tlv.ssid_len);
    tlv.ap_channel_reports_nr = payload->ap_chan_reports_nr;
    for (i = 0; i < payload->ap_chan_reports_nr; i++) {
        tlv.ap_channel_reports[i].op_class = payload->ap_chan_reports[i].op_class;
        tlv.ap_channel_reports[i].channels = payload->ap_chan_reports[i].channels;
    }
    tlv.element_ids_nr        = payload->element_ids_nr;
    memcpy(tlv.element_ids, payload->element_ids, tlv.element_ids_nr);

    if (map_send_beacon_metrics_query(ale, &tlv, MID_NA)) {
        log_ctrl_e("send beacon metrics query failed");
    }
}

static nb_retcode_t send_steering_request(map_ale_info_t *ale, mac_addr bssid, mac_addr sta_mac,
                                                  mac_addr t_bssid, uint8_t t_channel, uint8_t t_op_class,
                                                  bool mandate,
                                                  bool abridged,
                                                  bool disassoc_imminent,
                                                  int disassoc_timer,
                                                  uint8_t reason)
{
    nb_retcode_t ret = NB_EFAIL;
    map_steer_t  steer;

    memset(&steer, 0, sizeof(map_steer_t));
    maccpy(steer.bssid, bssid);

    steer.sta_bssid_nr = 1;
    maccpy(steer.sta_bssid[0].sta_mac, sta_mac);
    maccpy(steer.sta_bssid[0].target_bssid, t_bssid);
    steer.sta_bssid[0].channel  = t_channel;
    steer.sta_bssid[0].op_class = t_op_class;
    steer.sta_bssid[0].reason   = reason;

    steer.flags |= mandate           ? MAP_STEERING_REQUEST_FLAG_MANDATE               : 0;
    steer.flags |= abridged          ? MAP_STEERING_REQUEST_FLAG_BTM_ABRIDGED          : 0;
    steer.flags |= disassoc_imminent ? MAP_STEERING_REQUEST_FLAG_BTM_DISASSOC_IMMINENT : 0;
    steer.disassociation_timer = disassoc_timer;

    ret = map_send_client_steering_request(ale, &steer, MID_NA) ?
            NB_EFAIL : NB_OK;

    return ret;
}

static nb_retcode_t set_btm_steering_disallowed_list(map_ale_info_t *ale, int num_sta_mac, mac_addr *sta_mac_list)
{
    nb_retcode_t               ret = NB_EFAIL;
    map_policy_config_tlvs_t   tlvs = {0};
    map_steering_policy_tlv_t  steering_policy_tlv;
    int                        i;
    mac_addr                  *btm_steering_macs = NULL;

    do {

        if (num_sta_mac > 0) {
            btm_steering_macs = malloc(num_sta_mac * sizeof(mac_addr));
            if (NULL == btm_steering_macs) {
                break;
            }
            for (i=0; i<num_sta_mac; i++) {
                maccpy(&btm_steering_macs[i], sta_mac_list[i]);
            }
        }

        memset(&steering_policy_tlv, 0, sizeof(map_steering_policy_tlv_t));
        steering_policy_tlv.btm_steering_dis_macs_nr = num_sta_mac;
        steering_policy_tlv.local_steering_dis_macs  = NULL;
        steering_policy_tlv.btm_steering_dis_macs    = btm_steering_macs;

        tlvs.steering_policy_tlv = &steering_policy_tlv;
        ret = map_send_policy_config_request(ale, &tlvs, MID_NA) ?
              NB_EFAIL : NB_OK;
    } while(0);

    free(btm_steering_macs);

    return ret;
}

static void nb_client_steer(map_ale_info_t *ale, map_nb_client_steer_params_t *payload)
{
    if (NB_OK != send_steering_request(ale, payload->bssid, payload->target.sta_mac,
                          payload->target.bssid, payload->target.channel, payload->target.op_class,
                          payload->flags & NB_STEERING_REQUEST_FLAG_MANDATE,
                          payload->flags & NB_STEERING_REQUEST_FLAG_BTM_ABRIDGED,
                          payload->flags & NB_STEERING_REQUEST_FLAG_BTM_DISASSOC_IMMINENT,
                          payload->disassociation_timer, payload->target.reason)) {
        log_ctrl_e("send_steering_request failed");
    }
}

static void nb_mapsta_disassociate(map_ale_info_t *ale, map_nb_sta_disassociate_params_t *payload)
{
    nb_retcode_t ret = NB_EFAIL;
    bool         rem_btm_dis = false;
    mac_addr_str mac_str;

    if (!payload)
        return;

    do {
        mac_to_string(payload->sta_mac, mac_str);
        if (NB_OK != (ret = set_btm_steering_disallowed_list(ale, 1, &payload->sta_mac))) {
            log_ctrl_e("set_btm_steering_disallowed_list failed");
            break;
        }
        rem_btm_dis = true;

        if (NB_OK != (ret = send_steering_request(ale, payload->bssid, payload->sta_mac, g_wildcard_mac, 0, 0,
                                                true, false, false, 0, 0))) {
            log_ctrl_e("send_steering_request failed");
            break;
        }
    } while(0);

    /* Also in case of error, attempt to remove from steering disallowed list */
    if (rem_btm_dis) {
        ;//msg_lib_remove_from_btm_steering_disallowed_list(ap_mac, sta_mac);
    }

}

static int
nb_unassoc_sta_link_metrics_query(map_ale_info_t *ale,
                                  map_nb_unassoc_sta_link_metrics_query_params_t *payload)
{
    unsigned int i;
    map_unassoc_sta_link_metrics_query_tlv_t tlv = { 0 };

    tlv.op_class = payload->op_class;
    tlv.channels_nr = payload->chan_list_len;
    for (i = 0; i < payload->chan_list_len; i++) {
        tlv.channels[i].channel = payload->chan_list[i].channel;
        tlv.channels[i].sta_macs = payload->chan_list[i].mac_list;
        tlv.channels[i].sta_macs_nr = payload->chan_list[i].mac_list_len;
    }
    return map_send_unassoc_sta_link_metrics_query(ale, &tlv, MID_NA);
}

static int nb_unassoc_sta_link_metrics_response(map_ale_info_t *ale,
                                                map_nb_unassoc_sta_link_metrics_response_t *metrics)
{
    unsigned int i;
    map_unassoc_sta_link_metrics_response_tlv_t *dm_tlv = ale->unassoc_metrics;
    metrics->sta_metrics_list = NULL;

    if (!dm_tlv) {
        return -1;
    }
    metrics->sta_metrics_list = calloc(dm_tlv->stas_nr, sizeof(*metrics->sta_metrics_list));
    if (!metrics->sta_metrics_list) {
        return -1;
    }
    metrics->sta_metrics_list_len = dm_tlv->stas_nr;
    metrics->op_class = dm_tlv->op_class;
    for (i = 0; i < dm_tlv->stas_nr; i++) {
        metrics->sta_metrics_list[i].channel = dm_tlv->stas[i].channel;
        metrics->sta_metrics_list[i].time_delta = dm_tlv->stas[i].time_delta;
        metrics->sta_metrics_list[i].rcpi_uplink = dm_tlv->stas[i].rcpi_uplink;
        maccpy(metrics->sta_metrics_list[i].mac, dm_tlv->stas[i].mac);
    }

    return 0;
}

static int send_association_control_request_compl_cb(int status, void *args, void *opaque_cmdu)
{
    struct CMDU            *cmdu = opaque_cmdu;
    client_assoc_control_t *assoc_control = args;
    uint16_t                i;
    uint8_t                *p;

    if (status == MAP_RETRY_STATUS_SUCCESS &&
        cmdu->message_type == CMDU_TYPE_MAP_ACK) {

        for (i = 0; NULL != (p = cmdu->list_of_TLVs[i]); i++ ) {
            if (*p == TLV_TYPE_ERROR_CODE) {
                map_error_code_tlv_t *error_code = (map_error_code_tlv_t *)p;
                if (error_code->reason_code == MAP_ERROR_CODE_STA_ASSOCIATED) {
                    log_ctrl_e("MAP_ERROR_CODE_STA_ASSOCIATED response returned!");
                    /* ToDo ? */
                }
            }
        }
    }

    free(assoc_control);

    return 0;
}

static int send_association_control_request_retry_cb(void *args, uint16_t *mid)
{
    client_assoc_control_t *assoc_control = args;

    /* Only send one request */
    if (false == assoc_control->request_sent) {
        map_send_client_acl_request(assoc_control->ale, &assoc_control->tlv, mid);
        assoc_control->request_sent = true;
    }

    return 0;
}

static void nb_assoc_control(map_ale_info_t *ale, map_nb_assoc_control_params_t *payload)
{
    static uint64_t                         req_nr; /* static counter to create unique timer ids */
    nb_retcode_t                            ret = NB_EFAIL;
    client_assoc_control_t                 *assoc_control = NULL;
    map_client_assoc_control_request_tlv_t *tlv;
    int                                     i;
    timer_id_t                              retry_id;

    do {
        if (!payload) {
            break;
        }

        if ( !ale ) {
            break;
        }

        if (payload->num_sta_mac < 1) {
            break;
        }
        payload->num_sta_mac = MIN(payload->num_sta_mac, MAX_STATION_PER_BSS);

        if (!(assoc_control = calloc(1, sizeof(client_assoc_control_t)))) {
            ret = NB_ENOMEM;
            break;
        }

        assoc_control->ale = ale;

        tlv = &assoc_control->tlv;
        maccpy(tlv->bssid, payload->bssid);
        tlv->association_control = payload->block ? MAP_CLIENT_ASSOC_CONTROL_BLOCK : MAP_CLIENT_ASSOC_CONTROL_UNBLOCK;
        tlv->validity_period     = payload->period;
        tlv->sta_macs_nr         = payload->num_sta_mac;

        for (i = 0; i < payload->num_sta_mac; i++) {
            maccpy(&tlv->sta_macs[i], payload->sta_mac_list[i]);
        }

        /* For block with async error reporting, use retry framework to see content of ack frame */
        if (payload->block) {
            /* Create unique retry id */
            map_dm_get_ale_int_timer_id(retry_id, ale, ASSOC_CONTROL_RETRY_ID, req_nr++);
            if (map_register_retry(retry_id, 2 /* interval */, 1 /* num retries */, assoc_control,
                send_association_control_request_compl_cb, send_association_control_request_retry_cb)) {
                break;
            }

            assoc_control = NULL;
            ret = NB_OK;
        } else {
            ret = map_send_client_acl_request(ale, tlv, MID_NA) ? NB_EINVAL : NB_OK;
        }
    } while(0);

    free(assoc_control);

    log_ctrl_d("ret: %d", ret);
}

static map_dm_nbapi_t g_nbapi_cbs = {
    .channel_scan                      = nb_channel_scan,
    .beacon_metrics_query              = nb_beacon_metrics_query,
    .client_steer                      = nb_client_steer,
    .mapsta_disassociate               = nb_mapsta_disassociate,
    .unassoc_sta_link_metrics_query    = nb_unassoc_sta_link_metrics_query,
    .unassoc_sta_link_metrics_response = nb_unassoc_sta_link_metrics_response,
    .assoc_control                     = nb_assoc_control
};

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
int map_ctrl_nbapi_init(void)
{
    map_dm_set_nbapi_cbs(&g_nbapi_cbs);

    return 0;
}

void map_ctrl_nbapi_fini(void)
{
}

