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
#include "map_ctrl_post_onboarding_handler.h"
#include "map_ctrl_tlv_helper.h"
#include "map_ctrl_utils.h"
#include "map_ctrl_emex_tlv_handler.h"
#include "map_ctrl_vendor.h"
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

static int nb_steer_wifi_backhaul(map_ale_info_t *ale, map_nb_steer_wifi_bh_param_t *payload)
{
    map_backhaul_steering_request_tlv_t tlv = {0};

    if (!ale || !payload) {
        return NB_EINVAL;
    }

    maccpy(&tlv.bsta_mac, &payload->bsta_mac);
    maccpy(&tlv.target_bssid, &payload->target_bssid);
    tlv.target_op_class = payload->op_class;
    tlv.target_channel  = payload->channel;

    if (map_send_backhaul_steering_request(ale, &tlv, MID_NA)) {
        log_ctrl_e("send steer wifi backhaul request failed");
        return NB_EFAIL;
    }

    return NB_OK;
}

static int nb_set_steering_policy(map_ale_info_t *ale)
{
    map_steering_policy_tlv_t steering_policy_tlv = {0};
    map_policy_config_tlvs_t  tlvs = {0};

    if (!ale) {
        return NB_EINVAL;
    }

    steering_policy_tlv.btm_steering_dis_macs      = ale->btm_steering_disallow_macs;
    steering_policy_tlv.btm_steering_dis_macs_nr   = ale->btm_steering_disallow_macs_nr;
    steering_policy_tlv.local_steering_dis_macs    = ale->local_steering_disallow_macs;
    steering_policy_tlv.local_steering_dis_macs_nr = ale->local_steering_disallow_macs_nr;

    tlvs.steering_policy_tlv = &steering_policy_tlv;

    if (map_send_policy_config_request(ale, &tlvs, MID_NA)) {
        log_ctrl_e("send policy config request failed");
        return NB_EFAIL;
    }

    return NB_OK;
}

static int nb_reset_reboot(map_ale_info_t *ale, map_nb_reset_reboot_param_t *payload)
{
    uint8_t action_type;
    uint8_t reset_type;

    if (!ale || !payload) {
        return NB_EINVAL;
    }

    action_type = payload->is_reset ? MAP_EMEX_REBOOT_ACTION_RESET : MAP_EMEX_REBOOT_ACTION_REBOOT;
    reset_type = payload->factory_reset ? MAP_EMEX_RESET_FACTORY_RESET : MAP_EMEX_RESET_SOFT_RESET;

    if (map_ctrl_vendor_send_reboot_request(ale, action_type, reset_type)) {
        log_ctrl_e("send reboot/reset request failed");
        return NB_EFAIL;
    }

    return NB_OK;
}

static int nb_channel_scan(map_ale_info_t *ale, map_nb_ch_scan_param_t *payload)
{
    map_channel_scan_request_tlv_t tlv = {.tlv_type = TLV_TYPE_CHANNEL_SCAN_REQUEST};
    unsigned int i;
    int ret = NB_OK;

    if (!ale || !payload) {
        ret = NB_EINVAL;
        goto fail;
    }

    tlv.fresh_scan_performed    = true;
    tlv.radios_nr               = 1;
    maccpy(&tlv.radios[0].radio_id, &payload->radio_id);
    tlv.radios[0].op_classes_nr = payload->op_classes_nr;
#if 0
    tlv.radios[0].op_classes    = payload->op_classes;
#else
    tlv.radios[0].op_classes    = calloc(tlv.radios[0].op_classes_nr, sizeof(*tlv.radios[0].op_classes));
    for (i = 0; i < payload->op_classes_nr; i++) {
        tlv.radios[0].op_classes[i].op_class = payload->op_classes[i].op_class;
        tlv.radios[0].op_classes[i].channels = payload->op_classes[i].channels;
    }
#endif

    if (map_send_channel_scan_request(ale, &tlv, MID_NA)) {
        log_ctrl_e("send channel scan request failed");
        ret = NB_EFAIL;
    }

fail:
    free_1905_TLV_structure2((uint8_t *)&tlv);

    return ret;
}

static int nb_channel_selection(map_ale_info_t *ale, map_nb_ch_selection_param_t *payload)
{
    map_radio_info_t *radio;
    int rc;

    if (!ale || !payload) {
        return NB_EINVAL;
    }

    radio = map_dm_get_radio(ale, payload->radio_id);
    if (!radio) {
        log_ctrl_e("get radio failed");
        return NB_EINVAL;
    }

    /* Update preferred channels */
    SFREE(radio->merged_pref_op_class_list.op_classes);
    radio->merged_pref_op_class_list.op_classes_nr = 0;
    rc = map_merge_pref_op_class_list(&radio->merged_pref_op_class_list,
        &radio->cap_op_class_list, &radio->ctrl_pref_op_class_list,
        &radio->pref_op_class_list, &radio->disallowed_op_class_list);

    if (rc) {
        log_ctrl_e("update preferred channel and operating class list failed");
        return NB_EFAIL;
    }

    /* Do channel selection */
    map_agent_cancel_channel_selection(ale);
    map_agent_handle_channel_selection(ale, radio, MAP_CHAN_SEL_REQUEST);

    return NB_OK;
}

static int nb_beacon_metrics_query(map_ale_info_t *ale, map_nb_bmquery_param_t *payload)
{
    map_beacon_metrics_query_tlv_t tlv = {0};
    unsigned int i;

    if (!ale || !payload) {
        return NB_EINVAL;
    }

    maccpy(&tlv.sta_mac, &payload->sta_mac);
    tlv.op_class              = payload->op_class;
    tlv.channel               = payload->channel;
    maccpy(&tlv.bssid, &payload->bssid);
    tlv.reporting_detail      = payload->reporting_detail;
    tlv.ssid_len              = strlen(payload->ssid);
    memcpy(tlv.ssid, payload->ssid, tlv.ssid_len);
    tlv.ap_channel_reports_nr = payload->ap_chan_reports_nr;
#if 0
    tlv.ap_channel_reports    = payload->ap_chan_reports;
#else
    tlv.ap_channel_reports    = calloc(tlv.ap_channel_reports_nr, sizeof(*tlv.ap_channel_reports));
    for (i = 0; i < payload->ap_chan_reports_nr; i++) {
        tlv.ap_channel_reports[i].op_class = payload->ap_chan_reports[i].op_class;
        tlv.ap_channel_reports[i].channels = payload->ap_chan_reports[i].channels;
    }
#endif
    tlv.element_ids_nr        = payload->element_ids_nr;
    memcpy(tlv.element_ids, payload->element_ids, tlv.element_ids_nr);

    if (map_send_beacon_metrics_query(ale, &tlv, MID_NA)) {
        log_ctrl_e("send beacon metrics query failed");
        return NB_EFAIL;
    }

    return NB_OK;
}

static int nb_client_steer(map_ale_info_t *ale, map_nb_client_steer_params_t *payload)
{
    map_steer_t steer = {0};

    if (!ale || !payload) {
        return NB_EINVAL;
    }

    maccpy(steer.bssid, payload->bssid);
    steer.sta_bssid_nr          = 1;
    maccpy(steer.sta_bssid[0].sta_mac, payload->target.sta_mac);
    maccpy(steer.sta_bssid[0].target_bssid, payload->target.bssid);
    steer.sta_bssid[0].channel  = payload->target.channel;
    steer.sta_bssid[0].op_class = payload->target.op_class;
    steer.sta_bssid[0].reason   = payload->target.reason;
    steer.flags |= payload->flags & NB_STEERING_REQUEST_FLAG_MANDATE ?
                   MAP_STEERING_REQUEST_FLAG_MANDATE : 0;
    steer.flags |= payload->flags & NB_STEERING_REQUEST_FLAG_BTM_ABRIDGED ?
                   MAP_STEERING_REQUEST_FLAG_BTM_ABRIDGED : 0;
    steer.flags |= payload->flags & NB_STEERING_REQUEST_FLAG_BTM_DISASSOC_IMMINENT ?
                   MAP_STEERING_REQUEST_FLAG_BTM_DISASSOC_IMMINENT : 0;
    steer.disassociation_timer  = payload->disassociation_timer;

    if (map_send_client_steering_request(ale, &steer, MID_NA)) {
        log_ctrl_e("send_steering_request failed");
        return NB_EFAIL;
    }

    return NB_OK;
}

static int nb_mapsta_disassociate(map_ale_info_t *ale, map_nb_sta_disassociate_params_t *payload)
{
    bool remove = false;
    map_nb_client_steer_params_t steer = {0};
    int rc = NB_OK;

    if (!ale || !payload) {
        return NB_EINVAL;
    }

    if (!acu_mac_in_array(payload->sta_mac, ale->btm_steering_disallow_macs,
        ale->btm_steering_disallow_macs_nr)) {
        if (ale->btm_steering_disallow_macs_nr == UINT8_MAX) {
            log_ctrl_e("btm steering disallow list maxed out");
            return NB_EFAIL;
        }
        if (acu_mac_add_to_array(payload->sta_mac, &ale->btm_steering_disallow_macs,
            &ale->btm_steering_disallow_macs_nr)) {
            log_ctrl_e("mac add to array failed");
            return NB_ENOMEM;
        }
        remove = true;
        if ((rc = nb_set_steering_policy(ale)) != NB_OK) {
            log_ctrl_e("set steering policy failed");
            goto fail;
        }
    }

    maccpy(steer.bssid, payload->bssid);
    maccpy(steer.target.sta_mac, payload->sta_mac);
    maccpy(steer.target.bssid, g_wildcard_mac);
    steer.target.reason         = payload->reason_code;
    steer.flags                 = NB_STEERING_REQUEST_FLAG_MANDATE;
    steer.disassociation_timer  = payload->disassociation_timer;
    if ((rc = nb_client_steer(ale, &steer)) != NB_OK) {
        log_ctrl_e("client steer failed");
        goto fail;
    }

    if (remove) {
        if (acu_mac_del_from_array(payload->sta_mac, &ale->btm_steering_disallow_macs,
            &ale->btm_steering_disallow_macs_nr)) {
            log_ctrl_e("mac delete from array failed");
            return NB_ENOMEM;
        }
        if (nb_set_steering_policy(ale)) {
            log_ctrl_e("set steering policy failed");
            return NB_EFAIL;
        }
    }

    return NB_OK;

fail:
    if (remove) {
        acu_mac_del_from_array(payload->sta_mac, &ale->btm_steering_disallow_macs,
            &ale->btm_steering_disallow_macs_nr);
    }

    return rc;
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
    .steer_wifi_backhaul               = nb_steer_wifi_backhaul,
    .set_steering_policy               = nb_set_steering_policy,
    .reset_reboot                      = nb_reset_reboot,
    .channel_scan                      = nb_channel_scan,
    .channel_selection                 = nb_channel_selection,
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

