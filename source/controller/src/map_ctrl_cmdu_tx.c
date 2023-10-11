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
#define LOG_TAG "cmdu_tx"

#include "map_ctrl_cmdu_tx.h"
#include "map_ctrl_tlv_helper.h"
#include "map_ctrl_defines.h"
#include "map_ctrl_utils.h"
#include "map_ctrl_topology_tree.h"
#include "map_data_model.h"
#include "map_topology_tree.h"
#include "map_retry_handler.h"
#include "map_info.h"
#include "arraylist.h"
#include "i1905.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define min(a,b) ((a) < (b) ? (a) : (b))

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
/* "Empty" profile used for teardown */
static const map_profile_cfg_t g_teardown_profile;

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
static int get_m2_profiles(map_ale_info_t *ale, map_radio_info_t *radio,
                           i1905_wsc_m2_cfg_t *m2_profiles, uint8_t max_m2_profiles, uint8_t *ret_m2_profiles_nr,
                           map_traffic_separation_policy_tlv_t *tsp_tlv)
{
    map_controller_cfg_t *cfg            = get_controller_cfg();
    uint16_t              freq_bands     = map_get_freq_bands(radio);
    bool                  is_gateway     = map_is_local_agent(ale); /* Note: at this moment, the controller is expected to run on a gateway */
    bool                  is_extender    = !is_gateway;
    int                   prim_vid       = map_cfg_get()->primary_vlan_id;
    uint8_t               m2_profiles_nr = 0;
    unsigned int          i, j;

    log_ctrl_n("[get_m2_profiles] configure ale[%s] gw[%d] ext[%d] radio[%s] max_bss[%d] max_vid[%d] band[%s%s%s%s]",
               ale->al_mac_str, is_gateway ? 1 : 0, is_extender ? 1 : 0,
               radio->radio_id_str, radio->max_bss, ale->agent_capability.max_vid_count,
               freq_bands & MAP_M2_BSS_RADIO2G  ? "2G "  : "",
               freq_bands & MAP_M2_BSS_RADIO5GL ? "5GL " : "",
               freq_bands & MAP_M2_BSS_RADIO5GU ? "5GH " : "",
               freq_bands & MAP_M2_BSS_RADIO6G  ? "6G"  : "");

    for (i = 0; (i < cfg->num_profiles) && (m2_profiles_nr < radio->max_bss) && (m2_profiles_nr < max_m2_profiles); i++) {
        i1905_wsc_m2_cfg_t *m2_cfg =  &m2_profiles[m2_profiles_nr];
        map_profile_cfg_t  *profile = &cfg->profiles[i];
        uint8_t             bss_state;

        /* Skip disabled profile */
        if (!profile->enabled) {
            continue;
        }

        /* In case of wfa certification, profiles are configured per ALE */
        if (WFA_CERT() && memcmp(profile->al_mac, ale->al_mac, MAC_ADDR_LEN)) {
            continue;
        }

        /* Skip if traffic separation is enabled and secondary vlan is configured when:
           - TS is not supported (e.g profile 1 agent)
           - Too many secondary vlan
        */
        if (TS_ENABLED() && profile->vlan_id >= 0 && profile->vlan_id != prim_vid) {
            if (NULL == tsp_tlv) {
                /* TS not supported */
                continue;
            }
            for (j = 0; j < tsp_tlv->ssids_nr; j++) {
                if (tsp_tlv->ssids[j].ssid_len == strlen(profile->bss_ssid) &&
                    !memcmp(tsp_tlv->ssids[j].ssid, profile->bss_ssid, tsp_tlv->ssids[j].ssid_len)) {
                    break;
                }
            }
            if (j == tsp_tlv->ssids_nr) {
                /* Cannot configure ssid because too many secondary VLAN */
                continue;
            }
        }

        /* Skip if for device type does not match */
        if ((is_gateway  && !profile->gateway) ||
            (is_extender && !profile->extender)) {
            continue;
        }

        /* Filter by frequency band */
        if (0 == (profile->bss_freq_bands & freq_bands)) {
            continue;
        }

        /* NOTE: Credentials are applied in the order they are configured. In the future we could have
                 additional filtering/sorting rules (e.g only add guest if max_bss is high enough)
        */

        bss_state = profile->bss_state & (MAP_FRONTHAUL_BSS | MAP_BACKHAUL_BSS);
        if (!bss_state) {
            continue;
        }

        m2_cfg->profile  = profile;
        m2_cfg->map_ext  = 0;
        m2_cfg->map_ext |= (bss_state & MAP_FRONTHAUL_BSS) ? WSC_WFA_MAP_ATTR_FLAG_FRONTHAUL_BSS : 0;
        m2_cfg->map_ext |= (bss_state & MAP_BACKHAUL_BSS)  ? WSC_WFA_MAP_ATTR_FLAG_BACKHAUL_BSS  : 0;

        log_ctrl_n("[get_m2_profiles] use profile idx[%d] and map_ext[0x%02x] for bss[%d]",
                    profile->profile_idx, m2_cfg->map_ext, m2_profiles_nr);

        m2_profiles_nr++;
    }

    /* We do not have a profile for reported radio frequency band. Send the
       configuration to tear down the radio
    */
    if (m2_profiles_nr == 0) {
        /* Setting the SSID to NULL will build a WSC TLV with TEAR-DOWN bit set. */
        log_ctrl_n("[get_m2_profiles] teardown radio (no bss configured)");
        goto teardown;
    }

    *ret_m2_profiles_nr = m2_profiles_nr;

    return 0;

teardown:
    m2_profiles[0].profile = &g_teardown_profile;
    m2_profiles[0].map_ext = WSC_WFA_MAP_ATTR_FLAG_TEARDOWN;
    *ret_m2_profiles_nr = 1;

    return 0;
}

static int get_wsc_m2_tlv(char *iface_name, i1905_wsc_data_t *wsc_params, i1905_wsc_tlv_t *wsc_m2_tlv)
{
    size_t length;

    if (i1905_get(iface_name, I1905_GET_WSCM2_TLV, wsc_params, &length)) {
        log_ctrl_e("I1905_GET_WSCM2_TLV failed");
        return -1;
    }

    wsc_m2_tlv->tlv_type       = wsc_params->m2.tlv_type;
    wsc_m2_tlv->wsc_frame_size = wsc_params->m2.wsc_frame_size;
    wsc_m2_tlv->wsc_frame      = wsc_params->m2.wsc_frame;

    return 0;
}

static int fill_upstream_iface_link_metrics(map_ale_info_t *ale, uint8_t **tlvs) {

    map_ale_info_t             *root_ale = get_root_ale_node();
    map_neighbor_link_metric_t *neigh_lm = &ale->upstream_link_metrics;

    /* Do not link to controller*/
    if (map_is_local_agent(ale) && !maccmp(neigh_lm->al_mac, root_ale->al_mac)) {
        return 0;
    }
    if (!maccmp(neigh_lm->al_mac, g_zero_mac)) {
        return 0;
    }

    if (!(tlvs[0] = (uint8_t*)map_get_receiver_link_metric_tlv(ale->al_mac, neigh_lm))) {
        return -1;
    }

    if (!(tlvs[1] = (uint8_t*)map_get_transmitter_link_metric_tlv(ale->al_mac, neigh_lm))) {
        return -1;
    }

    return 2;
}

static int fill_iface_link_metrics(map_ale_info_t *ale, uint8_t **tlvs, array_list_t *list)
{
    map_ale_info_t             *root_ale = get_root_ale_node();
    map_neighbor_link_metric_t *neigh_lm;
    list_iterator_t             iterator = {0};
    int                         tlvs_nr  =  0;

    bind_list_iterator(&iterator, list);

    while ((neigh_lm = get_next_list_object(&iterator))) {
        /* Ignore link to controller */
        if (!maccmp(neigh_lm->al_mac, root_ale->al_mac)) {
            continue;
        }

        if (!(tlvs[tlvs_nr] = (uint8_t*)map_get_receiver_link_metric_tlv(ale->al_mac, neigh_lm))) {
            return -1;
        }
        tlvs_nr++;

        if (!(tlvs[tlvs_nr] = (uint8_t*)map_get_transmitter_link_metric_tlv(ale->al_mac, neigh_lm))) {
            return -1;
        }
        tlvs_nr++;
    }

    return tlvs_nr;
}

/* Send "normal" cmdu (no relay, dest = al_mac) with zero TLV */
static int send_cmdu_zero_tlv(map_ale_info_t *ale, uint16_t cmdu_type, uint16_t *mid)
{
    i1905_cmdu_t  cmdu    = {0};
    uint8_t      *tlvs[1] = {0};

    cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type    = cmdu_type;
    cmdu.message_id      = 0;
    cmdu.relay_indicator = RELAY_INDICATOR_OFF;
    cmdu.list_of_TLVs    = tlvs;
    map_strlcpy(cmdu.interface_name, ale->iface_name, sizeof(cmdu.interface_name));

    return map_send_cmdu(ale->al_mac, &cmdu, mid);
}

/* Send "normal" cmdu (no relay, dest = al_mac) with single TLV */
static int send_cmdu_one_tlv(map_ale_info_t *ale, uint16_t cmdu_type, uint8_t tlv_type, void *v_tlv, uint16_t *mid)
{
    i1905_cmdu_t  cmdu    = {0};
    uint8_t      *tlvs[2] = {0};
    uint8_t      *tlv     = v_tlv;

    tlv[0]  = tlv_type;
    tlvs[0] = tlv;

    cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type    = cmdu_type;
    cmdu.message_id      = 0;
    cmdu.relay_indicator = RELAY_INDICATOR_OFF;
    cmdu.list_of_TLVs    = tlvs;
    map_strlcpy(cmdu.interface_name, ale->iface_name, sizeof(cmdu.interface_name));

    return map_send_cmdu(ale->al_mac, &cmdu, mid);
}

/*#######################################################################
#                       PUBLIC HELP FUNCTIONS                           #
########################################################################*/
int map_send_cmdu(mac_addr dest_mac, i1905_cmdu_t *cmdu, uint16_t *mid)
{
    const char   *cmdu_name = i1905_cmdu_type_to_string(cmdu->message_type);
    mac_addr_str  mac_str;
    int           ret;

    mac_to_string(dest_mac, mac_str);

    if (!(ret = i1905_send(cmdu, dest_mac, mid))) {
        log_ctrl_d("sent cmdu[%s] interface[%s] dst[%s]", cmdu_name, cmdu->interface_name, mac_str);
    } else {
        log_ctrl_e("failed sending cmdu[%s] interface[%s] dst[%s]", cmdu_name, cmdu->interface_name, mac_str);
    }

    return ret;
}

/*#######################################################################
#                       LLDP                                            #
########################################################################*/
int map_send_lldp_bridge_discovery(i1905_interface_info_t *interface)
{
    lldp_chassis_id_tlv_t   chassis_id_tlv   = {0};
    lldp_port_id_tlv_t      port_id_tlv      = {0};
    lldp_time_to_live_tlv_t time_to_live_tlv = {0};
    i1905_lldp_payload_t    payload;

    if (!interface) {
        return -1;
    }

    memset(&payload, 0, sizeof(payload));

    chassis_id_tlv.tlv_type           = TLV_TYPE_CHASSIS_ID;
    chassis_id_tlv.chassis_id_subtype = CHASSIS_ID_TLV_SUBTYPE_MAC_ADDRESS;
    maccpy(chassis_id_tlv.chassis_id, get_controller_cfg()->al_mac);

    port_id_tlv.tlv_type        = TLV_TYPE_PORT_ID;
    port_id_tlv.port_id_subtype = PORT_ID_TLV_SUBTYPE_MAC_ADDRESS;
    maccpy(port_id_tlv.port_id, interface->mac_address);

    time_to_live_tlv.tlv_type = TLV_TYPE_TIME_TO_LIVE;
    time_to_live_tlv.ttl      = TIME_TO_LIVE_TLV_1905_DEFAULT_VALUE;

    payload.list_of_TLVs[0] = (uint8_t *)&chassis_id_tlv;
    payload.list_of_TLVs[1] = (uint8_t *)&port_id_tlv;
    payload.list_of_TLVs[2] = (uint8_t *)&time_to_live_tlv;

    return i1905_send_lldp(interface->name, interface->mac_address, &payload);
}

/*#######################################################################
#                       1905.1 CMDU                                     #
########################################################################*/
/* 1905.1 6.3.1 (type 0x0000) */
int map_send_topology_discovery(i1905_interface_info_t *interface, uint16_t *mid)
{
    i1905_cmdu_t                cmdu            = {0};
    uint8_t                    *tlvs[3]         = {0};
    i1905_al_mac_address_tlv_t  al_mac_addr_tlv = {0};
    i1905_mac_address_tlv_t     mac_addr_tlv    = {0};
    mac_addr                    mcast_mac;

    i1905_get_mcast_mac(mcast_mac);

    /* AL MAC TLV */
    al_mac_addr_tlv.tlv_type = TLV_TYPE_AL_MAC_ADDRESS;
    maccpy(al_mac_addr_tlv.al_mac_address, get_controller_cfg()->al_mac);
    tlvs[0] = (uint8_t *)&al_mac_addr_tlv;

    /* MAC TLV */
    mac_addr_tlv.tlv_type = TLV_TYPE_MAC_ADDRESS;
    maccpy(mac_addr_tlv.mac_address, interface->mac_address);
    tlvs[1] = (uint8_t *)&mac_addr_tlv;

    /* Create CMDU */
    cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type    = CMDU_TYPE_TOPOLOGY_DISCOVERY;
    cmdu.message_id      = 0;
    cmdu.relay_indicator = RELAY_INDICATOR_OFF;
    cmdu.list_of_TLVs    = tlvs;
    map_strlcpy(cmdu.interface_name, interface->name, sizeof(cmdu.interface_name));

    return map_send_cmdu(mcast_mac, &cmdu, mid);
}

/* 1905.1 6.3.2 (type 0x0001) */
int map_send_topology_query_with_al_mac(mac_addr al_mac_addr, char *iface, uint16_t *mid)
{
    i1905_cmdu_t               cmdu            = {0};
    uint8_t                   *tlvs[2]         = {0};
    map_multiap_profile_tlv_t  map_profile_tlv = {0};

    /* MAP Profile TLV */
    map_profile_tlv.tlv_type        = TLV_TYPE_MULTIAP_PROFILE;
    map_profile_tlv.map_profile     = get_controller_cfg()->map_profile;
    tlvs[0] = (uint8_t *)&map_profile_tlv;

    /* Create CMDU */
    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_TOPOLOGY_QUERY;
    cmdu.message_id       =  0;
    cmdu.relay_indicator  =  RELAY_INDICATOR_OFF;
    cmdu.list_of_TLVs     =  tlvs;
    map_strlcpy(cmdu.interface_name, iface, sizeof(cmdu.interface_name));

    return map_send_cmdu(al_mac_addr, &cmdu, mid);
}

/* 1905.1 6.3.2 (type 0x0001) */
int map_send_topology_query(void *args, uint16_t *mid)
{
    map_ale_info_t            *ale             = args;
    i1905_cmdu_t               cmdu            = {0};
    uint8_t                   *tlvs[2]         = {0};
    map_multiap_profile_tlv_t  map_profile_tlv = {0};

    if (!ale) {
        return -1;
    }

    /* MAP Profile TLV */
    map_profile_tlv.tlv_type        = TLV_TYPE_MULTIAP_PROFILE;
    map_profile_tlv.map_profile     = get_controller_cfg()->map_profile;
    tlvs[0] = (uint8_t *)&map_profile_tlv;

    /* Create CMDU */
    cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     =  CMDU_TYPE_TOPOLOGY_QUERY;
    cmdu.message_id       =  0;
    cmdu.relay_indicator  =  RELAY_INDICATOR_OFF;
    cmdu.list_of_TLVs     =  tlvs;
    map_strlcpy(cmdu.interface_name, ale->iface_name, sizeof(cmdu.interface_name));

    return map_send_cmdu(ale->al_mac, &cmdu, mid);
}

/* 1905.1 6.3.3 (type 0x0002) */
int map_send_topology_response(mac_addr src_mac, i1905_cmdu_t *recv_cmdu)
{
#define BASIC_TLVS_FOR_TOPOLOGY_RESP 5 /* DEVICE INFO + SUPPORTED SERVICE + AP OPERATIONAL + MAP PROFILE + NULL tlv */
    i1905_cmdu_t                      cmdu                   = {0};
    i1905_device_information_tlv_t    device_info_tlv        = {0};
    i1905_device_bridging_cap_tlv_t   bridge_info_tlv        = {0};
    i1905_neighbor_device_list_tlv_t *neighbor_dev_tlvs      = NULL;
    map_supported_service_tlv_t       supported_service_tlv  = {0};
    map_ap_operational_bss_tlv_t      ap_operational_bss_tlv = {0};
    map_multiap_profile_tlv_t         map_profile_tlv        = {0};
    size_t                            neighbor_dev_tlvs_nr   = 0;
    int                               status                 = -1;
    uint16_t                          tlvs_nr                = 0;
    uint16_t                          tlv_count              = 0;
    size_t                            i                      = 0;

    do {
        if (src_mac == NULL || recv_cmdu == NULL) {
            break;
        }

        /* Device information TLV */
        if (i1905_get(NULL, I1905_GET_DEVICEINFO_TLV, &device_info_tlv, NULL)) {
            log_ctrl_e("I1905_GET_DEVICEINFO_TLV failed");
            break;
        }

        /* Get 1905 bridge capability tlv */
        if (map_get_bridging_cap_tlv(&bridge_info_tlv)) {
            log_ctrl_e("get_bridge_capability_tlv failed");
            break;
        }

        /* Neighbor TLVs */
        if (map_get_1905_neighbor_tlvs(&neighbor_dev_tlvs, &neighbor_dev_tlvs_nr)) {
            log_ctrl_e("get_neighbor_tlvs failed");
            break;
        }

        /* Supported service TLV */
        supported_service_tlv.tlv_type    = TLV_TYPE_SUPPORTED_SERVICE;
        supported_service_tlv.services_nr = 2;
        supported_service_tlv.services[0] = MAP_SERVICE_CONTROLLER;
        supported_service_tlv.services[1] = MAP_SERVICE_EMEX_CONTROLLER;

        /* AP Operational BSS TLV */
        ap_operational_bss_tlv.tlv_type  = TLV_TYPE_AP_OPERATIONAL_BSS;
        ap_operational_bss_tlv.radios_nr = 0;

        /* MAP Profile TLV */
        map_profile_tlv.tlv_type    = TLV_TYPE_MULTIAP_PROFILE;
        map_profile_tlv.map_profile = get_controller_cfg()->map_profile;

        /* Intilise list of tlvs */
        tlvs_nr = BASIC_TLVS_FOR_TOPOLOGY_RESP + neighbor_dev_tlvs_nr;

        if (bridge_info_tlv.bridging_tuples_nr > 0) {
            tlvs_nr++; /*Increment for bridge tlv */
        }

        /* Create CMDU */
        cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
        cmdu.message_type    = CMDU_TYPE_TOPOLOGY_RESPONSE;
        cmdu.message_id      = recv_cmdu->message_id;
        cmdu.relay_indicator = 0;
        map_strlcpy(cmdu.interface_name, recv_cmdu->interface_name, sizeof(cmdu.interface_name));

        if (!(cmdu.list_of_TLVs = calloc(1, tlvs_nr * sizeof(uint8_t *)))) {
            log_ctrl_e("[%s] calloc failed\n", __FUNCTION__);
            break;
        }

        cmdu.list_of_TLVs[tlv_count++] = (uint8_t *)&device_info_tlv;           /* Device info tlv*/

        if (bridge_info_tlv.bridging_tuples_nr > 0) {
            cmdu.list_of_TLVs[tlv_count++] = (uint8_t *)&bridge_info_tlv;       /* Bridge Info tlv */
        }

        for (i = 0; i < neighbor_dev_tlvs_nr; i++) {
            cmdu.list_of_TLVs[tlv_count++] = (uint8_t *)&neighbor_dev_tlvs[i];  /* 1905 Neighbor tlvs */
        }

        cmdu.list_of_TLVs[tlv_count++] = (uint8_t *)&supported_service_tlv;     /* Supported Service tlv */
        cmdu.list_of_TLVs[tlv_count++] = (uint8_t *)&ap_operational_bss_tlv;    /* AP Operational BSS tlv */
        cmdu.list_of_TLVs[tlv_count++] = (uint8_t *)&map_profile_tlv;
        cmdu.list_of_TLVs[tlv_count++] = NULL;

        if (tlv_count != tlvs_nr) {
            log_ctrl_e("[%s] TLV count mismatch", __FUNCTION__);
            break;
        }

        if (map_send_cmdu(src_mac, &cmdu, &cmdu.message_id)) {
            break;
        }

        status = 0;
    } while(0);

    /* Free Device Info tlv */
    free(device_info_tlv.local_interfaces);

    /* Free Bridge info tlv */
    map_free_bridging_cap_tlv(&bridge_info_tlv);

    /* Free 1905 neighbor tlvs */
    map_free_1905_neighbor_tlv(neighbor_dev_tlvs, neighbor_dev_tlvs_nr);

    free(cmdu.list_of_TLVs);

    return status;
}

/* 1905.1 6.3.5 (type 0x0005) */
int map_send_link_metric_query(map_ale_info_t *ale, i1905_link_metric_query_tlv_t *tlv, uint16_t *mid)
{
    return send_cmdu_one_tlv(ale, CMDU_TYPE_LINK_METRIC_QUERY, TLV_TYPE_LINK_METRIC_QUERY, tlv, mid);
}

/* 1905.1 6.3.6 (type 0x0006) */
int map_send_link_metric_response(map_ale_info_t *ale, uint16_t mid, i1905_transmitter_link_metric_tlv_t *tx_tlvs, int tx_tlvs_nr,
                                  i1905_receiver_link_metric_tlv_t *rx_tlvs, int rx_tlvs_nr)
{
    i1905_cmdu_t   cmdu = {0};
    uint8_t      **tlvs = NULL;
    int            ret;
    int            i;

    if (!(tlvs = calloc(tx_tlvs_nr + rx_tlvs_nr + 1, sizeof(uint8_t *)))) {
        return -1;
    }

    for (i = 0; i < tx_tlvs_nr; i++) {
        tlvs[i] = (uint8_t *)&tx_tlvs[i];
    }

    for (i = 0; i < rx_tlvs_nr; i++) {
        tlvs[tx_tlvs_nr + i] = (uint8_t *)&rx_tlvs[i];
    }


    /* Create CMDU */
    cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type    = CMDU_TYPE_LINK_METRIC_RESPONSE;
    cmdu.message_id      = mid;
    cmdu.relay_indicator = RELAY_INDICATOR_OFF;
    cmdu.list_of_TLVs    = tlvs;
    map_strlcpy(cmdu.interface_name, ale->iface_name, sizeof(cmdu.interface_name));

    ret = map_send_cmdu(ale->al_mac, &cmdu, &mid);

    free(tlvs);

    return ret;
}

/* 1905.1 6.3.6 (type 0x0006) */
int map_send_link_metric_response_error(map_ale_info_t *ale, uint16_t mid, uint8_t error_code)
{
    i1905_cmdu_t                         cmdu    = {0};
    uint8_t                             *tlvs[2] = {0};
    i1905_link_metric_result_code_tlv_t  tlv     = {0};

    tlv.tlv_type    = TLV_TYPE_LINK_METRIC_RESULT_CODE;
    tlv.result_code = error_code;
    tlvs[0] = (uint8_t *)&tlv;

    cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type    = CMDU_TYPE_LINK_METRIC_RESPONSE;
    cmdu.message_id      = mid;
    cmdu.relay_indicator = RELAY_INDICATOR_OFF;
    cmdu.list_of_TLVs    = tlvs;
    map_strlcpy(cmdu.interface_name, ale->iface_name, sizeof(cmdu.interface_name));

    return map_send_cmdu(ale->al_mac, &cmdu, &mid);
}

/* 1905.1 6.3.8 (type 0x0008) */
int map_send_autoconfig_response(i1905_cmdu_t *recv_cmdu, bool ale_is_agent)
{
    i1905_al_mac_address_tlv_t       *al_mac_tlv;
    i1905_autoconfig_freq_band_tlv_t *autoconfig_freq_band_tlv;
    i1905_cmdu_t                      cmdu                     = {0};
    uint8_t                          *tlvs[5]                  = {0}; /* supp_role, supp_freq_band, supp_service, map_profile,  NULL */
    i1905_supported_role_tlv_t        supported_role_tlv       = {0};
    i1905_supported_freq_band_data_t  supp_freq_band_data      = {0};
    i1905_supported_freq_band_tlv_t   supported_freq_band_tlv  = {0};
    map_supported_service_tlv_t       supported_service_tlv    = {0};
    map_multiap_profile_tlv_t         map_profile_tlv          = {0};
    int8_t                            status                   = 0;

    do {
        if (!recv_cmdu) {
            ERROR_EXIT(status)
        }

        /* Get the AL MAC TLV to identify the agent node */
        if (!(al_mac_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_AL_MAC_ADDRESS, recv_cmdu))) {
            log_ctrl_e("[%s] unable to get TLV_TYPE_AL_MAC_ADDRESS", __FUNCTION__);
            ERROR_EXIT(status)
        }

        if (ale_is_agent) {
            /* Check if agent exists */
            if (!map_dm_get_ale(al_mac_tlv->al_mac_address)) {
                log_ctrl_e("[%s] agent[%s] node failed", __FUNCTION__, mac_string(al_mac_tlv->al_mac_address));
                ERROR_EXIT(status)
            }
        }

        /* Get autoconfig freq band TLV from received cmdu */
        if (!(autoconfig_freq_band_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_AUTOCONFIG_FREQ_BAND, recv_cmdu))) {
            log_ctrl_e("[%s] unable to get TLV_TYPE_AUTOCONFIG_FREQ_BAND", __FUNCTION__);
            ERROR_EXIT(status)
        }

        /* Supported Role TLV */
        if (i1905_get(NULL, I1905_GET_SUPPORTEDROLE_TLV, &supported_role_tlv, NULL)) {
            log_ctrl_e("I1905_GET_SUPPORTEDROLE_TLV failed");
            ERROR_EXIT(status)
        }

        /* Supported Frequency Band TLV */
        supp_freq_band_data.supported_freq_band_tlv = &supported_freq_band_tlv;
        supp_freq_band_data.freq_band               = autoconfig_freq_band_tlv->freq_band;

        if (i1905_get(NULL, I1905_GET_SUPPORTEDFREQBAND_TLV, &supp_freq_band_data, NULL)) {
            log_ctrl_e("I1905_GET_SUPPORTEDFREQBAND_TLV failed");
            ERROR_EXIT(status)
        }

        /* Supported service TLV */
        supported_service_tlv.tlv_type    = TLV_TYPE_SUPPORTED_SERVICE;
        supported_service_tlv.services_nr = 1;
        supported_service_tlv.services[0] = MAP_SERVICE_CONTROLLER;

        /* Map profile TLV */
        map_profile_tlv.tlv_type    = TLV_TYPE_MULTIAP_PROFILE;
        map_profile_tlv.map_profile = get_controller_cfg()->map_profile;

        /* Create CMDU */
        cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
        cmdu.message_type    = CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE;
        cmdu.message_id      = recv_cmdu->message_id;
        cmdu.relay_indicator = RELAY_INDICATOR_OFF;
        cmdu.list_of_TLVs    = tlvs;
        map_strlcpy(cmdu.interface_name, recv_cmdu->interface_name, sizeof(cmdu.interface_name));

        tlvs[0] = (uint8_t *)&supported_role_tlv;
        tlvs[1] = (uint8_t *)&supported_freq_band_tlv;
        tlvs[2] = (uint8_t *)&supported_service_tlv;
        tlvs[3] = (uint8_t *)&map_profile_tlv;

        /* The spec implies (certification test plan) the messages to be sent to the AL MAC address of the 1905 device
           intead the source mac address, CMDUs that has ALMAC tlv can be handled this way
        */
        if (map_send_cmdu(al_mac_tlv->al_mac_address, &cmdu, &cmdu.message_id)) {
            ERROR_EXIT(status)
        }
    } while (0);

    return status;
}

/* 1905.1 6.3.9 (type 0x0009) */
int map_send_autoconfig_wsc_m2(map_ale_info_t *ale, map_radio_info_t *radio, i1905_cmdu_t *recv_cmdu, uint16_t *mid)
{
    i1905_cmdu_t                         cmdu                          = {0};
    i1905_wsc_tlv_t                     *wsc_m1_tlv;
    i1905_wsc_tlv_t                      wsc_m2_tlv[MAX_BSS_PER_RADIO] = {{0}};
    map_ap_radio_identifier_tlv_t        radio_id_tlv                  = {0};
    map_default_8021q_settings_tlv_t     default_8021q_settings_tlv    = {0};
    map_traffic_separation_policy_tlv_t  traffic_separation_policy_tlv = {0};
    map_cfg_t                           *cfg                           = map_cfg_get();
    bool                                 add_ts_tlv                    = ale->agent_capability.profile_2_ap_cap_valid;
    bool                                 add_def_8021q_tlv             = TS_ENABLED() && add_ts_tlv;
    int8_t                               status                        = 0;
    uint8_t                              tlvs_nr                       = 0;
    uint8_t                              wsc_tlv_count                 = 0;
    uint8_t                              current_tlv                   = 0;
    uint8_t                              i;
    i1905_wsc_m2_cfg_t                   m2_profiles[MAX_BSS_PER_RADIO];
    i1905_wsc_data_t                     wsc_params;

    memset(m2_profiles, 0, sizeof(m2_profiles));

    do {
        /* Create cmdu */
        cmdu.message_version  =  CMDU_MESSAGE_VERSION_1905_1_2013;
        cmdu.message_type     =  CMDU_TYPE_AP_AUTOCONFIGURATION_WSC;
        cmdu.message_id       =  recv_cmdu->message_id;
        cmdu.relay_indicator  =  RELAY_INDICATOR_OFF;
        map_strlcpy(cmdu.interface_name, recv_cmdu->interface_name, sizeof(cmdu.interface_name));

        /* Traffic separationtlvs */
        if (add_def_8021q_tlv) {
            map_fill_default_8021q_settings_tlv(cfg, &default_8021q_settings_tlv);
        }
        if (add_ts_tlv) {
            if (TS_ENABLED()) {
                map_fill_traffic_separation_policy_tlv(get_controller_cfg(), cfg->primary_vlan_id,
                                                       ale->agent_capability.max_vid_count,
                                                       &traffic_separation_policy_tlv);
            } else {
                /* If TS is disabled add an empty ts tlv so agent can remove any existing vlan */
                map_fill_empty_traffic_separation_policy_tlv(&traffic_separation_policy_tlv);
            }
        }

        /* Get to be configured profiles */
        if (get_m2_profiles(ale, radio, m2_profiles, MAX_BSS_PER_RADIO, &wsc_tlv_count,
                            add_ts_tlv ? &traffic_separation_policy_tlv : NULL)) {
            ERROR_EXIT(status)
        }

        /* Get total number of TLVs required and allocate memory accordingly */
        tlvs_nr = wsc_tlv_count + /* radio_id */ 1 + /* eom */ 1 +
                  (add_ts_tlv ? 1 : 0) + (add_def_8021q_tlv ? 1 : 0);

        if (!(cmdu.list_of_TLVs = calloc(tlvs_nr, sizeof(uint8_t *)))) {
            log_ctrl_e("calloc failed");
            ERROR_EXIT(status)
        }

        /* Get M1 from receive CMDU */
        if (!(wsc_m1_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_WSC, recv_cmdu))) {
            log_ctrl_e("unable to get TLV_TYPE_WSC");
            ERROR_EXIT(status)
        }
        /* Radio Identifier TLV */
        radio_id_tlv.tlv_type = TLV_TYPE_AP_RADIO_IDENTIFIER;
        maccpy(radio_id_tlv.radio_id, radio->radio_id);
        cmdu.list_of_TLVs[current_tlv++] = (uint8_t *)&radio_id_tlv;

        /* Default 8021q settings TLV and traffic separation policy TLV */
        if (add_def_8021q_tlv) {
            cmdu.list_of_TLVs[current_tlv++] = (uint8_t *)&default_8021q_settings_tlv;
        }
        if (add_ts_tlv) {
            cmdu.list_of_TLVs[current_tlv++] = (uint8_t *)&traffic_separation_policy_tlv;
        }

        /* WSC M2 TLVs */
        wsc_params.m1.tlv_type       = wsc_m1_tlv->tlv_type;
        wsc_params.m1.wsc_frame_size = wsc_m1_tlv->wsc_frame_size;
        wsc_params.m1.wsc_frame      = wsc_m1_tlv->wsc_frame;

        for (i = 0; i < wsc_tlv_count; i++) {
            wsc_params.m2_cfg = &m2_profiles[i];
            if (get_wsc_m2_tlv(recv_cmdu->interface_name, &wsc_params, &wsc_m2_tlv[i])) {
                ERROR_EXIT(status)
            }

            cmdu.list_of_TLVs[current_tlv++] = (uint8_t *)&wsc_m2_tlv[i];
        }

        if (0 != status) {
            break;
        }

        if (map_send_cmdu(ale->al_mac, &cmdu, mid)) {
            ERROR_EXIT(status)
        }

        set_radio_state_M2_sent(&radio->state);

    } while (0);

    /* Free WSC TLV */
    for (i = 0; i < wsc_tlv_count; i++) {
        free(wsc_m2_tlv[i].wsc_frame);
    }

    free(cmdu.list_of_TLVs);

    return status;
}

/* 1905.1 6.3.10 (type 0x000A) */
static int send_autoconfig_renew(const char *ifname, mac_addr dest_mac, uint8_t freq_band, uint8_t relay_indicator, uint16_t *mid)
{
    i1905_cmdu_t                      cmdu                    = {0};
    uint8_t                          *tlvs[4]                 = {0}; /* AL MAC, Supp Role, Supp freq band, NULL */
    i1905_al_mac_address_tlv_t        al_mac_tlv              = {0};
    i1905_supported_role_tlv_t        supported_role_tlv      = {0};
    i1905_supported_freq_band_data_t  supp_freq_band_data     = {0};
    i1905_supported_freq_band_tlv_t   supported_freq_band_tlv = {0};

    /* AL MAC TLV */
    if (i1905_get(NULL, I1905_GET_ALMAC_TLV, &al_mac_tlv, NULL)) {
        log_ctrl_e("I1905_GET_ALMAC_TLV failed");
        return -1;
    }

    /* Supported Role TLV */
    if (i1905_get(NULL, I1905_GET_SUPPORTEDROLE_TLV, &supported_role_tlv, NULL)) {
        log_ctrl_e("I1905_GET_SUPPORTEDROLE_TLV failed");
        return -1;
    }

    /* Supported Frequency Band TLV */
    supp_freq_band_data.supported_freq_band_tlv = &supported_freq_band_tlv;
    supp_freq_band_data.freq_band               = freq_band;

    if (i1905_get(NULL, I1905_GET_SUPPORTEDFREQBAND_TLV, &supp_freq_band_data, NULL)) {
        log_ctrl_e("I1905_GET_SUPPORTEDFREQBAND_TLV failed");
        return -1;
    }

    /* Create CMDU */
    cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type    = CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW;
    cmdu.message_id      = 0;
    cmdu.relay_indicator = relay_indicator;
    cmdu.list_of_TLVs    = tlvs;
    map_strlcpy(cmdu.interface_name, ifname, sizeof(cmdu.interface_name));

    tlvs[0] = (uint8_t *)&al_mac_tlv;
    tlvs[1] = (uint8_t *)&supported_role_tlv;
    tlvs[2] = (uint8_t *)&supported_freq_band_tlv;

    return map_send_cmdu(dest_mac, &cmdu, mid);
}

/* 1905.1 6.3.10 (type 0x000A) */
int map_send_autoconfig_renew(uint8_t freq_band, uint16_t *mid)
{
    mac_addr dest_mac;

    i1905_get_mcast_mac(dest_mac);

    return send_autoconfig_renew("all", dest_mac, freq_band, RELAY_INDICATOR_ON, mid);
}

/* 1905.1 6.3.10 (type 0x000A) */
int map_send_autoconfig_renew_ucast(map_ale_info_t *ale, uint8_t freq_band, uint16_t *mid)
{
    return send_autoconfig_renew(ale->iface_name, ale->al_mac, freq_band, RELAY_INDICATOR_OFF, mid);
}

/* 1905.1 6.3.13 (type 0x0004) */
int map_send_vendor_specific(void *args, uint16_t *mid)
{
    map_vendor_specific_t       *vs  = args;
    i1905_vendor_specific_tlv_t  tlv = {0};
    map_ale_info_t              *ale;

    if (!vs || !(ale = vs->ale)) {
        return -1;
    }

    /* Vendor specific TLVs */
    tlv.m_nr = vs->len;
    tlv.m    = vs->data;
    memcpy(tlv.vendorOUI, vs->oui, sizeof(tlv.vendorOUI));

    return send_cmdu_one_tlv(ale, CMDU_TYPE_VENDOR_SPECIFIC, TLV_TYPE_VENDOR_SPECIFIC, &tlv, mid);
}

/* 1905.1 6.3.13 (type 0x0004) */
int map_send_vendor_specific_mult_tlvs(void *args, uint16_t *mid)
{
    map_vendor_specific_mult_tlv_t *vs          = args;
    i1905_cmdu_t                    cmdu        = {0};
    i1905_vendor_specific_tlv_t    *vendor_tlvs = NULL;
    int                             status      = -1;
    map_ale_info_t                 *ale;
    int                             i;

    if (!vs || !(ale = vs->ale)) {
        return -1;
    }

    if (!(cmdu.list_of_TLVs = calloc(vs->tlvs_cnt + 1, sizeof(uint8_t *)))) {
        log_ctrl_e("[%s] calloc failed", __FUNCTION__);
        goto cleanup;
    }
    if (!(vendor_tlvs = calloc(vs->tlvs_cnt, sizeof(i1905_vendor_specific_tlv_t)))) {
        log_ctrl_e("[%s] calloc failed", __FUNCTION__);
        goto cleanup;
    }

    /* Vendor specific TLVs */
    for (i = 0; i < vs->tlvs_cnt; i++) {
        vendor_tlvs[i].tlv_type = TLV_TYPE_VENDOR_SPECIFIC;
        vendor_tlvs[i].m_nr     = vs->tlvs[i].len;
        vendor_tlvs[i].m        = vs->tlvs[i].data;
        memcpy(vendor_tlvs[i].vendorOUI, vs->oui, sizeof(vendor_tlvs[i].vendorOUI));
        cmdu.list_of_TLVs[i] = (uint8_t *)&vendor_tlvs[i];
    }

    /* Create CMDU */
    cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type    = CMDU_TYPE_VENDOR_SPECIFIC;
    cmdu.message_id      = 0;
    cmdu.relay_indicator = RELAY_INDICATOR_OFF;
    map_strlcpy(cmdu.interface_name, ale->iface_name, sizeof(cmdu.interface_name));

    if (map_send_cmdu(ale->al_mac, &cmdu, mid)) {
        goto cleanup;
    }

    status = 0;

cleanup:
    free(vendor_tlvs);
    free(cmdu.list_of_TLVs);

    return status;
}

/*#######################################################################
#                       MAP R1 CMDU                                     #
########################################################################*/
/* MAP_R1 17.1 (type 0x8000) */
int map_send_ack(map_ale_info_t *ale, i1905_cmdu_t *recv_cmdu)
{
    i1905_cmdu_t  cmdu   = {0};
    uint8_t     *tlvs[1] = {0};

    /* Create CMDU */
    cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type    = CMDU_TYPE_MAP_ACK;
    cmdu.message_id      = recv_cmdu->message_id;
    cmdu.relay_indicator = RELAY_INDICATOR_OFF;
    cmdu.list_of_TLVs    = tlvs;
    map_strlcpy(cmdu.interface_name, recv_cmdu->interface_name, sizeof(cmdu.interface_name));

    return map_send_cmdu(ale->al_mac, &cmdu, &cmdu.message_id);
}

/* MAP_R1 17.1 (type 0x8000) */
int map_send_ack_sta_error(map_ale_info_t *ale, i1905_cmdu_t *recv_cmdu, mac_addr *sta_macs, int sta_mac_nr, uint8_t error_code)
{
    i1905_cmdu_t   cmdu = {0};
    uint8_t      **tlvs;
    int            i    = 0;
    int            ret  = -1;

    if (!(tlvs = calloc(sta_mac_nr + 1, sizeof(uint8_t *)))) {
        log_ctrl_e("[%s] tlvs calloc failed", __FUNCTION__);
        goto cleanup;
    }

    for (i = 0; i < sta_mac_nr; i++) {
        if (!(tlvs[i] = (uint8_t *)map_get_error_code_tlv(sta_macs[i], error_code))) {
            log_ctrl_e("[%s] failed getting error code TLV", __FUNCTION__);
            goto cleanup;
        }
    }

    /* Create CMDU */
    cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type    = CMDU_TYPE_MAP_ACK;
    cmdu.message_id      = recv_cmdu->message_id;
    cmdu.relay_indicator = RELAY_INDICATOR_OFF;
    cmdu.list_of_TLVs    = tlvs;
    map_strlcpy(cmdu.interface_name, recv_cmdu->interface_name, sizeof(cmdu.interface_name));

    if (map_send_cmdu(ale->al_mac, &cmdu, &cmdu.message_id)) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (tlvs) {
        for (i = 0; i < sta_mac_nr; i++) {
            free_1905_TLV_structure(tlvs[i]);
        }
        free(tlvs);
    }

    return ret;
}

/* MAP_R2 17.1.6 (type 0x8001) */
int map_send_ap_capability_query(void *args, uint16_t *mid)
{
    map_ale_info_t *ale = args;

    return send_cmdu_zero_tlv(ale, CMDU_TYPE_MAP_AP_CAPABILITY_QUERY, mid);
}

/* MAP_R1 17.8 (type 0x8003) */
int map_send_policy_config_request(map_ale_info_t *ale, map_policy_config_tlvs_t *tlvs, uint16_t *mid)
{
    i1905_cmdu_t   cmdu      = {0};
    uint8_t      **c_tlvs    = NULL;
    uint8_t        tlvs_nr   = 0;
    int            ret       = -1;
    uint8_t        tlv_index = 0;
    int            i;

    /* Count and fix TLVs */
    if (tlvs->metric_policy_tlv) {
        tlvs->metric_policy_tlv->tlv_type = TLV_TYPE_METRIC_REPORTING_POLICY;
        tlvs_nr++;
    }

    if (tlvs->steering_policy_tlv) {
        tlvs->steering_policy_tlv->tlv_type = TLV_TYPE_STEERING_POLICY;
        tlvs_nr++;
    }

    if (tlvs->unsuccess_assoc_policy_tlv) {
        tlvs->unsuccess_assoc_policy_tlv->tlv_type = TLV_TYPE_UNSUCCESSFUL_ASSOCIATION_POLICY;
        tlvs_nr++;
    }

    if (tlvs->channel_scan_report_policy_tlv) {
        tlvs->channel_scan_report_policy_tlv->tlv_type = TLV_TYPE_CHANNEL_SCAN_REPORTING_POLICY;
        tlvs_nr++;
    }

    if (tlvs->bh_bss_config_tlvs) {
        for (i = 0; i < tlvs->bh_bss_config_tlvs_nr; i++) {
            tlvs->bh_bss_config_tlvs[i].tlv_type = TLV_TYPE_BACKHAUL_BSS_CONFIGURATION;
            tlvs_nr++;
        }
    }

    if (tlvs->default_8021q_settings_tlv) {
        tlvs->default_8021q_settings_tlv->tlv_type = TLV_TYPE_DEFAULT_8021Q_SETTINGS;
        tlvs_nr++;
    }

    if (tlvs->traffic_separation_policy_tlv) {
        tlvs->traffic_separation_policy_tlv->tlv_type = TLV_TYPE_TRAFFIC_SEPARATION_POLICY;
        tlvs_nr++;
    }

    /* Allocate and Assign TLVs array */
    if (!(c_tlvs = calloc(tlvs_nr + 1, sizeof(uint8_t *)))) {
        goto cleanup;
    }

    if (tlvs->steering_policy_tlv) {
        c_tlvs[tlv_index++] = (uint8_t*)tlvs->steering_policy_tlv;
    }

    if (tlvs->metric_policy_tlv) {
        c_tlvs[tlv_index++] = (uint8_t*)tlvs->metric_policy_tlv;
    }

    if (tlvs->unsuccess_assoc_policy_tlv) {
        c_tlvs[tlv_index++] = (uint8_t*)tlvs->unsuccess_assoc_policy_tlv;
    }

    if (tlvs->channel_scan_report_policy_tlv) {
        c_tlvs[tlv_index++] = (uint8_t*)tlvs->channel_scan_report_policy_tlv;
    }

    if (tlvs->bh_bss_config_tlvs) {
        for (i = 0; i < tlvs->bh_bss_config_tlvs_nr; i++) {
            c_tlvs[tlv_index++] = (uint8_t*)&tlvs->bh_bss_config_tlvs[i];
        }
    }

    if (tlvs->default_8021q_settings_tlv) {
        c_tlvs[tlv_index++] = (uint8_t*)tlvs->default_8021q_settings_tlv;
    }

    if (tlvs->traffic_separation_policy_tlv) {
        c_tlvs[tlv_index++] = (uint8_t*)tlvs->traffic_separation_policy_tlv;
    }

    /* Create CMDU */
    cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type    = CMDU_TYPE_MAP_MULTI_AP_POLICY_CONFIG_REQUEST;
    cmdu.message_id      = 0;
    cmdu.relay_indicator = RELAY_INDICATOR_OFF;
    cmdu.list_of_TLVs    = c_tlvs;
    map_strlcpy(cmdu.interface_name, ale->iface_name, sizeof(cmdu.interface_name));

    if (map_send_cmdu(ale->al_mac, &cmdu, mid)) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    free(c_tlvs);

    return ret;
}

/* MAP_R2 17.1.9 (type 0x8004) */
int map_send_channel_preference_query(void *args, uint16_t *mid)
{
    map_ale_info_t *ale = args;

    return send_cmdu_zero_tlv(ale, CMDU_TYPE_MAP_CHANNEL_PREFERENCE_QUERY, mid);
}

/* MAP_R2 17.1.11 (type 0x8006) */
int map_send_channel_selection_request(void *args, uint16_t *mid)
{
#define  MAX_TLVS_CHANNEL_SEL_REQ  (MAX_RADIO_PER_AGENT * 2) + 1
    map_chan_select_pref_type_t    *pref_type                      = args;
    i1905_cmdu_t                    cmdu                           = {0};
    uint8_t                        *tlvs[MAX_TLVS_CHANNEL_SEL_REQ] = {0};
    map_channel_preference_tlv_t    chan_pref_tlvs[MAX_RADIO_PER_AGENT];
    map_transmit_power_limit_tlv_t  transmit_pwr_tlvs[MAX_RADIO_PER_AGENT];
    uint8_t                         tlvs_nr = 0;
    uint8_t                         idx = 0;
    map_ale_info_t                 *ale;
    map_radio_info_t               *radio;

    memset(chan_pref_tlvs, 0, sizeof(chan_pref_tlvs));
    memset(transmit_pwr_tlvs, 0, sizeof(transmit_pwr_tlvs));

    if (!pref_type || !(ale = pref_type->ale)) {
        return -1;
    }

    /* Request can be for one or all radio */
    map_dm_foreach_radio(ale, radio) {
        if (pref_type->radio && pref_type->radio != radio) {
            continue;
        }

        /* Channel preference TLV */
        map_fill_channel_preference_tlv(&chan_pref_tlvs[idx], radio, pref_type->pref);
        tlvs[tlvs_nr++] = (uint8_t *)&chan_pref_tlvs[idx];

        /* Optional transmit power TLV */
        if (radio->tx_pwr_limit != 0) {
            map_fill_transmit_power_tlv(&transmit_pwr_tlvs[idx], radio);
            tlvs[tlvs_nr++] = (uint8_t *)&transmit_pwr_tlvs[idx];
        }
        idx++;
    }

    /* Create CMDU */
    cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type    = CMDU_TYPE_MAP_CHANNEL_SELECTION_REQUEST;
    cmdu.message_id      = 0;
    cmdu.relay_indicator = RELAY_INDICATOR_OFF;
    cmdu.list_of_TLVs    = tlvs;
    map_strlcpy(cmdu.interface_name, ale->iface_name, sizeof(cmdu.interface_name));

    return map_send_cmdu(ale->al_mac, &cmdu, mid);
}

/* MAP_R2 17.1.14 (type 0x8009) */
int map_send_client_capability_query(void *args, uint16_t *mid)
{
    map_sta_info_t        *sta = args;
    map_bss_info_t        *bss;
    map_radio_info_t      *radio;
    map_ale_info_t        *ale;
    map_client_info_tlv_t  tlv = {0};

    if (!sta || !(bss = sta->bss) || !(radio = bss->radio) || !(ale = radio->ale)) {
        return -1;
    }

    /* Client info tlv */
    maccpy(tlv.bssid, bss->bssid);
    maccpy(tlv.sta_mac, sta->mac);

    return send_cmdu_one_tlv(ale, CMDU_TYPE_MAP_CLIENT_CAPABILITY_QUERY, TLV_TYPE_CLIENT_INFO, &tlv, mid);
}

/* MAP_R2 17.1.16 (type 0x800B) */
int map_send_ap_metrics_query(map_ale_info_t *ale, mac_addr *bssids, uint8_t bssid_nr, uint16_t *mid)
{
    map_ap_metric_query_tlv_t tlv = {0};
    uint8_t                   i;

    /* AP metric query TLV */
    tlv.bssids_nr = bssid_nr;

    for (i = 0; i < bssid_nr; i++) {
        maccpy(tlv.bssids[i], bssids[i]);
    }

    return send_cmdu_one_tlv(ale, CMDU_TYPE_MAP_AP_METRICS_QUERY, TLV_TYPE_AP_METRIC_QUERY, &tlv, mid);
}

/* MAP_R2 17.1.18 (type 0x800D) */
int map_send_assoc_sta_link_metrics_query(void *args, uint16_t *mid)
{
    map_sta_info_t            *sta  = args;
    map_bss_info_t            *bss;
    map_radio_info_t          *radio;
    map_ale_info_t            *ale;
    map_sta_mac_address_tlv_t  tlv  = {0};

    if (!sta || !(bss = sta->bss) || !(radio = bss->radio) || !(ale = radio->ale)) {
        return -1;
    }

    /* STA MAC tlv */
    maccpy(tlv.sta_mac, sta->mac);

    return send_cmdu_one_tlv(ale, CMDU_TYPE_MAP_ASSOCIATED_STA_LINK_METRICS_QUERY, TLV_TYPE_STA_MAC_ADDRESS, &tlv, mid);
}

/* MAP_R2 17.1.20 (type 0x800F) */
int map_send_unassoc_sta_link_metrics_query(map_ale_info_t *ale, map_unassoc_sta_link_metrics_query_tlv_t *tlv, uint16_t *mid)
{
    return send_cmdu_one_tlv(ale, CMDU_TYPE_MAP_UNASSOCIATED_STA_LINK_METRICS_QUERY, TLV_TYPE_UNASSOCIATED_STA_LINK_METRICS_QUERY, tlv, mid);
}

/* MAP_R2 17.1.24 (type 0x8013) */
int map_send_combined_infrastructure_metrics(map_ale_info_t *ale, uint16_t *mid)
{
#define MAX_TLVS_IN_COMBINED_INFRA 512
    i1905_cmdu_t           cmdu = {0};
    map_ale_info_t        *foreach_ale;
    map_radio_info_t      *foreach_radio;
    map_bss_info_t        *foreach_bss;
    map_ap_metrics_tlv_t  *ap_metrics_tlv;
    uint8_t              **tlvs;
    int                    tlvs_nr = 0;
    int                    ret     = -1;
    int                    i, cnt;

    if (!(tlvs = calloc(MAX_TLVS_IN_COMBINED_INFRA, sizeof(uint8_t *)))) {
        return -1;
    }

    map_dm_foreach_agent_ale(foreach_ale) {
        log_ctrl_d("[%s] iterate_through ale[%s]",__FUNCTION__, foreach_ale->al_mac_str);

        if ((cnt = fill_upstream_iface_link_metrics(foreach_ale, &tlvs[tlvs_nr])) < 0) {
            goto cleanup;
        }
        tlvs_nr += cnt;

        /* Ethernet links */
        if ((cnt = fill_iface_link_metrics(foreach_ale, &tlvs[tlvs_nr], foreach_ale->eth_neigh_link_metric_list)) < 0) {
            goto cleanup;
        }
        tlvs_nr += cnt;

        /* Get bss list and form apmetrics tlv for each bss of the ale */
        map_dm_foreach_radio(foreach_ale, foreach_radio) {
            map_dm_foreach_bss(foreach_radio, foreach_bss) {

                /* Wireless links */
                if ((cnt = fill_iface_link_metrics(foreach_ale, &tlvs[tlvs_nr], foreach_bss->neigh_link_metric_list)) < 0) {
                    goto cleanup;
                }
                tlvs_nr += cnt;

                if ((ap_metrics_tlv = map_get_ap_metrics_tlv(foreach_bss))) {
                    tlvs[tlvs_nr++] = (uint8_t *)ap_metrics_tlv;
                }
            }
        }
    }

    /* Create CMDU */
    cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type    = CMDU_TYPE_MAP_COMBINED_INFRASTRUCTURE_METRICS;
    cmdu.message_id      = 0;
    cmdu.relay_indicator = RELAY_INDICATOR_OFF;
    cmdu.list_of_TLVs    = tlvs;
    map_strlcpy(cmdu.interface_name, ale->iface_name, sizeof(cmdu.interface_name));

    if (map_send_cmdu(ale->al_mac, &cmdu, mid)) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    for (i = 0; i < MAX_TLVS_IN_COMBINED_INFRA; i++) {
        free_1905_TLV_structure(tlvs[i]);
    }

    free(tlvs);

    return ret;
}

/* MAP_R2 17.1.25 (type 0x8014) */
int map_send_client_steering_request(map_ale_info_t *ale, map_steer_t *steer, uint16_t *mid)
{
    i1905_cmdu_t                         cmdu             = {0};
    uint8_t                             *tlvs[3]          = {0};  /* There can be zero or one P1 TLV and zero or one P2 TLV */
    map_steering_request_tlv_t           steer_req_tlv    = {0};
    map_profile2_steering_request_tlv_t  steer_req_p2_tlv = {0};
    int                                  tlv_idx          = 0;
    int                                  i;

    /* Profile 1 steer request TLV */
    steer_req_tlv.tlv_type = TLV_TYPE_STEERING_REQUEST;
    maccpy(steer_req_tlv.bssid, steer->bssid);
    steer_req_tlv.flag                 = steer->flags;
    steer_req_tlv.opportunity_wnd      = steer->opportunity_wnd;
    steer_req_tlv.disassociation_timer = steer->disassociation_timer;

    /* Profile 2 steer request TLV */
    steer_req_p2_tlv.tlv_type = TLV_TYPE_PROFILE2_STEERING_REQUEST;
    maccpy(steer_req_p2_tlv.bssid, steer->bssid);
    steer_req_p2_tlv.flag                 = steer->flags;
    steer_req_p2_tlv.opportunity_wnd      = steer->opportunity_wnd;
    steer_req_p2_tlv.disassociation_timer = steer->disassociation_timer;

    /* Add sta to either profile 1 or profile 2 TLV */
    for (i = 0; i < steer->sta_bssid_nr; i++) {
        map_sta_info_t *sta = map_dm_get_sta_from_ale(ale, steer->sta_bssid[i].sta_mac);

        /* Profile 1 or non MBO -> profile 1 TLV */
	if (ale->map_profile == MAP_PROFILE_1 || !(sta && map_dm_is_mbo_sta(sta))) {
            maccpy(steer_req_tlv.sta_macs   [steer_req_tlv.sta_macs_nr],          steer->sta_bssid[i].sta_mac);
            maccpy(steer_req_tlv.target_bsss[steer_req_tlv.target_bsss_nr].bssid, steer->sta_bssid[i].target_bssid);

            steer_req_tlv.target_bsss[steer_req_tlv.target_bsss_nr].op_class = steer->sta_bssid[i].op_class;
            steer_req_tlv.target_bsss[steer_req_tlv.target_bsss_nr].channel  = steer->sta_bssid[i].channel;

            steer_req_tlv.sta_macs_nr++;
            steer_req_tlv.target_bsss_nr++;
        } else {
            maccpy(steer_req_p2_tlv.sta_macs   [steer_req_p2_tlv.sta_macs_nr],          steer->sta_bssid[i].sta_mac);
            maccpy(steer_req_p2_tlv.target_bsss[steer_req_p2_tlv.target_bsss_nr].bssid, steer->sta_bssid[i].target_bssid);

            steer_req_p2_tlv.target_bsss[steer_req_p2_tlv.target_bsss_nr].op_class = steer->sta_bssid[i].op_class;
            steer_req_p2_tlv.target_bsss[steer_req_p2_tlv.target_bsss_nr].channel  = steer->sta_bssid[i].channel;
            steer_req_p2_tlv.target_bsss[steer_req_p2_tlv.target_bsss_nr].reason   = steer->sta_bssid[i].reason;

            steer_req_p2_tlv.sta_macs_nr++;
            steer_req_p2_tlv.target_bsss_nr++;
        }
    }

    if (steer_req_tlv.sta_macs_nr > 0) {
        tlvs[tlv_idx++] = (uint8_t *)&steer_req_tlv;
    }

    if (steer_req_p2_tlv.sta_macs_nr > 0) {
        tlvs[tlv_idx++] = (uint8_t *)&steer_req_p2_tlv;
    }

    /* Create CMDU */
    cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type    = CMDU_TYPE_MAP_CLIENT_STEERING_REQUEST;
    cmdu.message_id      = 0;
    cmdu.relay_indicator = RELAY_INDICATOR_OFF;
    cmdu.list_of_TLVs    = tlvs;
    map_strlcpy(cmdu.interface_name, ale->iface_name, sizeof(cmdu.interface_name));

    return map_send_cmdu(ale->al_mac, &cmdu, mid);
}

/* MAP_R2 17.1.27 (type 0x8016) */
int map_send_client_acl_request(map_ale_info_t *ale, map_client_assoc_control_request_tlv_t *tlv, uint16_t *mid)
{
    return send_cmdu_one_tlv(ale, CMDU_TYPE_MAP_CLIENT_ASSOCIATION_CONTROL_REQUEST, TLV_TYPE_CLIENT_ASSOCIATION_CONTROL_REQUEST, tlv, mid);
}

/* MAP_R2 17.1.20 (type 0x8012) */
int map_send_beacon_metrics_query(map_ale_info_t *ale, map_beacon_metrics_query_tlv_t *tlv, uint16_t *mid)
{
    return send_cmdu_one_tlv(ale, CMDU_TYPE_MAP_BEACON_METRICS_QUERY, TLV_TYPE_BEACON_METRICS_QUERY, tlv, mid);
}

/* MAP_R2 17.1.29 (type 0x8019) */
int map_send_backhaul_steering_request(map_ale_info_t *ale, map_backhaul_steering_request_tlv_t *tlv, uint16_t *mid)
{
    return send_cmdu_one_tlv(ale, CMDU_TYPE_MAP_BACKHAUL_STEERING_REQUEST, TLV_TYPE_BACKHAUL_STEERING_REQUEST, tlv, mid);
}

/* MAP_R1 17.1.31 (type 0x8018) */
int map_send_higher_layer_data_msg(map_ale_info_t *ale, uint8_t protocol, const uint8_t *payload, uint16_t payload_len, uint16_t *mid)
{
    map_higher_layer_data_tlv_t tlv = {0};

    /* HLD TLV */
    tlv.protocol    = protocol;
    tlv.payload     = (uint8_t *)payload;
    tlv.payload_len = payload ? payload_len : 0;

    return send_cmdu_one_tlv(ale, CMDU_TYPE_MAP_HIGHER_LAYER_DATA, TLV_TYPE_HIGHER_LAYER_DATA, &tlv, mid);
}

/*#######################################################################
#                       MAP R2 CMDU                                     #
########################################################################*/
/* MAP_R2 17.1.33 (type 0x801B) */
int map_send_channel_scan_request(map_ale_info_t *ale, map_channel_scan_request_tlv_t *tlv, uint16_t *mid)
{
    return send_cmdu_one_tlv(ale, CMDU_TYPE_MAP_CHANNEL_SCAN_REQUEST, TLV_TYPE_CHANNEL_SCAN_REQUEST, tlv, mid);
}

/* MAP_R2 17.1.35 (type 0x8020) */
int map_send_cac_request(map_ale_info_t *ale, map_cac_request_tlv_t *tlv, uint16_t *mid)
{
    map_radio_info_t *radio;
    int               i;

    /* Controller should not send cac request outside of agent's cac caps */
    for (i = 0; i < tlv->radios_nr; i++) {
        if (!(radio = map_dm_get_radio(ale, tlv->radios[i].radio_id))) {
            log_ctrl_e("[%s] radio not found", __FUNCTION__);
            continue;
        }

        if (radio->ongoing_cac_request) {
            log_ctrl_e("cac request ongoing for radio[%s]", radio->radio_id_str);
            return -2;
        }

        if (!map_is_cac_request_valid(radio, tlv->radios[i].cac_method,
            tlv->radios[i].op_class, tlv->radios[i].channel)) {
            log_ctrl_e("requested CAC method is not supported by radio[%s]", radio->radio_id_str);
            return -1;
        }
    }

    if (send_cmdu_one_tlv(ale, CMDU_TYPE_MAP_CAC_REQUEST, TLV_TYPE_CAC_REQUEST, tlv, mid)) {
        return -1;
    }

    for (i = 0; i < tlv->radios_nr; i++) {
        radio = map_dm_get_radio(ale, tlv->radios[i].radio_id);

        /* Already known all radios are available */
        radio->ongoing_cac_request = 1;
    }

    return 0;
}

/* MAP_R2 17.1.36 (type 0x8021) */
int map_send_cac_termination(map_ale_info_t *ale, map_cac_termination_tlv_t *tlv, uint16_t *mid)
{
    return send_cmdu_one_tlv(ale, CMDU_TYPE_MAP_CAC_TERMINATION, TLV_TYPE_CAC_TERMINATION, tlv, mid);
}

/* MAP_R2 17.1.42 (type 0x8027) */
int map_send_backhaul_sta_capability_query(void *args, uint16_t *mid)
{
    map_ale_info_t *ale = args;

    return send_cmdu_zero_tlv(ale, CMDU_TYPE_MAP_BACKHAUL_STA_CAPABILITY_QUERY, mid);
}

/*#######################################################################
#                       MAP R3 CMDU                                     #
########################################################################*/
/* MAP_R3 17.1.48 (type 0x8029) */
int map_send_proxied_encap_dpp(map_ale_info_t *ale, map_1905_encap_dpp_tlv_t *encap_tlv, map_dpp_chirp_value_tlv_t *chirp_tlv, uint16_t *mid)
{
    i1905_cmdu_t  cmdu = {0};
    uint8_t      *tlvs[3] = {0};

    if (!encap_tlv) {
        log_ctrl_e("invalid encap_dpp_tlv");
        return -1;
    }

    encap_tlv->tlv_type = TLV_TYPE_1905_ENCAP_DPP;
    tlvs[0] = (uint8_t *)encap_tlv;

    if (chirp_tlv) {
        chirp_tlv->tlv_type = TLV_TYPE_DPP_CHIRP_VALUE;
        tlvs[1] = (uint8_t *)chirp_tlv;
    }

    cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type    = CMDU_TYPE_MAP_PROXIED_ENCAP_DPP;
    cmdu.message_id      = 0;
    cmdu.relay_indicator = RELAY_INDICATOR_OFF;
    cmdu.list_of_TLVs    = tlvs;
    map_strlcpy(cmdu.interface_name, ale->iface_name, sizeof(cmdu.interface_name));

    return map_send_cmdu(ale->al_mac, &cmdu, mid);
}

/* MAP_R3 17.1.49 (type 0x8030) */
int map_send_1905_encap_eapol(map_ale_info_t *ale, map_1905_encap_eapol_tlv_t *encap_eapol_tlv, uint16_t *mid)
{
    return send_cmdu_one_tlv(ale, CMDU_TYPE_MAP_1905_ENCAP_EAPOL, TLV_TYPE_1905_ENCAP_EAPOL, encap_eapol_tlv, mid);
}

/* MAP_R3 17.1.51 (type 0x801D) */
int map_send_dpp_cce_indication(map_ale_info_t *ale, uint8_t advertise, uint16_t *mid)
{
    map_dpp_cce_indication_tlv_t tlv = {0};

    tlv.advertise = advertise;

    return send_cmdu_one_tlv(ale, CMDU_TYPE_MAP_DPP_CCE_INDICATION, TLV_TYPE_DPP_CCE_INDICATION, &tlv, mid);
}

/* MAP_R3 17.1.52 (type 0x802F) */
int map_send_dpp_chirp_notification(map_dpp_chirp_value_tlv_t *chirp_value_tlv_list, int num_chirp_tlv, uint16_t *mid)
{
    int i, ret;
    i1905_cmdu_t  cmdu = {0};
    mac_addr mcast_mac;
    uint8_t **tlvs = NULL;

    if (!(tlvs = calloc(num_chirp_tlv + 1, sizeof(uint8_t *)))) {
        return -1;
    }

    i1905_get_mcast_mac(mcast_mac);

    for (i = 0; i < num_chirp_tlv; i++) {
        chirp_value_tlv_list[i].tlv_type = TLV_TYPE_DPP_CHIRP_VALUE;
        tlvs[i] = (uint8_t *)&chirp_value_tlv_list[i];
    }

    cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type    = CMDU_TYPE_MAP_CHIRP_NOTIFICATION;
    cmdu.message_id      = 0;
    cmdu.relay_indicator = RELAY_INDICATOR_ON;
    cmdu.list_of_TLVs    = tlvs;
    map_strlcpy(cmdu.interface_name, "all", sizeof(cmdu.interface_name));

    ret = map_send_cmdu(mcast_mac, &cmdu, mid);

    free(tlvs);
    return ret;
}

/* MAP_R3 17.1.56 (type 0x802A) */
int map_send_direct_encap_dpp(map_ale_info_t *ale, map_dpp_message_tlv_t *dpp_message_tlv, uint16_t *mid)
{
    return send_cmdu_one_tlv(ale, CMDU_TYPE_MAP_DIRECT_ENCAP_DPP, TLV_TYPE_DPP_MESSAGE, dpp_message_tlv, mid);
}

/*#######################################################################
#                       RAW                                             #
########################################################################*/
int map_send_raw(char *ifname, mac_addr dmac, mac_addr smac, uint16_t eth_type, uint8_t *data, uint16_t data_len)
{
    return i1905_send_raw(ifname, dmac, smac, eth_type, data, data_len);
}
