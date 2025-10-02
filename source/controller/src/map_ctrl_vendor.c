/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>

#define LOG_TAG "vendor"

#include "map_ctrl_defines.h"
#include "map_ctrl_utils.h"
#include "map_ctrl_vendor.h"
#include "map_ctrl_emex_tlv_handler.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
typedef struct vendor_reboot_request_s {
    map_ale_info_t      *ale;
    uint8_t             action_type;
    uint8_t             reset_type;
} vendor_reboot_request_t;

/*#######################################################################
#                       PROTOTYPES                                      #
########################################################################*/

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/

/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
static int vendor_send_compl_cb(UNUSED int status, UNUSED void *args, UNUSED void *opaque_cmdu)
{
    return 0;
}

static int vendor_send_reboot_request_retry_cb(void *args, uint16_t *mid)
{
    vendor_reboot_request_t *reboot_req = (vendor_reboot_request_t *)args;

    int ret = -1;
    map_vendor_tlv_tuple_t tlvs[2];
    uint16_t tlv_type, msg_type;
    uint8_t buf_msg_type_tlv[4] = {0};
    uint8_t *buf_reboot_request_tlv = NULL, *p;
    uint8_t reboot_request_tlv_len = 0;

    /* AirTies Message Type TLV */
    tlv_type = EMEX_TLV_MESSAGE_TYPE;
    p = buf_msg_type_tlv;
    _I2B(&tlv_type, &p);
    msg_type = EMEX_MESSAGE_REBOOT_REQUEST;
    _I2B(&msg_type, &p);

    /* AirTies Reboot Request TLV */
    tlv_type = EMEX_TLV_REBOOT_REQUEST;

    if (reboot_req->action_type == MAP_EMEX_REBOOT_ACTION_REBOOT) {
        reboot_request_tlv_len = 3; /* 2 (tlv type) + 1 (action) */
    } else if (reboot_req->action_type == MAP_EMEX_REBOOT_ACTION_RESET) {
        reboot_request_tlv_len = 4; /* 2 (tlv type) + 1 (action) + 1 (reset type) */
    } else {
        log_ctrl_e("[%s-%d] Failed to parse action type", __func__, __LINE__);
        goto out;
    }

    buf_reboot_request_tlv = calloc(1, reboot_request_tlv_len);
    if (!buf_reboot_request_tlv) {
        log_ctrl_e("[%s-%d] Failed to allocate memory", __func__, __LINE__);
        goto out;
    }

    p = buf_reboot_request_tlv;
    _I2B(&tlv_type, &p);
    _I1B(&reboot_req->action_type, &p);

    if (reboot_req->action_type == MAP_EMEX_REBOOT_ACTION_RESET) {
        _I1B(&reboot_req->reset_type, &p);
    }

    tlvs[0].len = 4; /* 2 (tlv type) + 2 (msg type) */
    tlvs[0].data = buf_msg_type_tlv;
    tlvs[1].len = reboot_request_tlv_len;
    tlvs[1].data = buf_reboot_request_tlv;

    if (map_ctrl_vendor_send_message(reboot_req->ale, tlvs, 2, mid)) {
        goto out;
    }

    ret = 0;

out:
    SFREE(buf_reboot_request_tlv);

    return ret;

}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
int map_ctrl_vendor_send_reboot_request(map_ale_info_t *ale, uint8_t action_type, uint8_t reset_type)
{
    vendor_reboot_request_t *reboot_req;
    timer_id_t               retry_id;

    if (WFA_CERT()) {
        return 0;
    }

    if (!map_emex_agent_is_feature_supported(ale, MAP_EMEX_FEATURE_REBOOT_RESET)) {
        log_ctrl_i("Reboot request message is not supported by the agent [%s]", ale->al_mac_str);
        return 0;
    }

    map_dm_get_ale_timer_id(retry_id, ale, VENDOR_REBOOT_REQ_RETRY_ID);

    if (map_is_timer_registered(retry_id)) {
        log_ctrl_i("Reboot request for agent [%s] already ongoing", ale->al_mac_str);
        return 0;
    }

    if (!(reboot_req = calloc(1, sizeof(vendor_reboot_request_t)))) {
        log_ctrl_e("[%s-%d] Failed to allocate memory", __func__, __LINE__);
        return -1;
    }

    reboot_req->ale = ale;
    reboot_req->action_type = action_type;
    reboot_req->reset_type = reset_type;

    if (map_register_retry(retry_id, 5/*interval*/, 6/*retry*/, reboot_req, vendor_send_compl_cb, vendor_send_reboot_request_retry_cb)) {
        log_ctrl_e("failed Registering retry timer[%s]", retry_id);
        SFREE(reboot_req);
        return -1;
    }

    return 0;
}

int map_ctrl_vendor_send_message(map_ale_info_t *ale, map_vendor_tlv_tuple_t tlvs[],
                                 uint8_t tlvs_cnt, uint16_t *mid)
{
    map_vendor_specific_mult_tlv_t vs;

    /* Send the message */
    vs.ale = ale;
    vs.oui[0] = AIRTIES_VENDOR_OUI_1;
    vs.oui[1] = AIRTIES_VENDOR_OUI_2;
    vs.oui[2] = AIRTIES_VENDOR_OUI_3;
    vs.tlvs_cnt = tlvs_cnt;
    vs.tlvs = tlvs;
    return map_send_vendor_specific_mult_tlvs(&vs, mid);
}

void map_ctrl_vendor_fini(void)
{
}

int map_ctrl_vendor_init(void)
{
    return 0;
}
