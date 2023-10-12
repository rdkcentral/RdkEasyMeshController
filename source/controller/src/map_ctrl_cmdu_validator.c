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
#define LOG_TAG "cmdu_validator"

#include "map_ctrl_cmdu_validator.h"
#include "map_ctrl_utils.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define CHECK_ZERO_OR_ONE_TLV(tlv, nr)                 \
    if (nr > 1)  {                                     \
        log_missing_or_too_many_tlv(false, cmdu, tlv); \
        return -1;                                     \
    }

#define CHECK_ONE_TLV(tlv, nr)                           \
    if (nr != 1) {                                       \
        log_missing_or_too_many_tlv(nr == 0, cmdu, tlv); \
        return -1;                                       \
    }

#define CHECK_ONE_OR_MORE_TLV(tlv, nr)                \
    if (nr == 0) {                                    \
        log_missing_or_too_many_tlv(true, cmdu, tlv); \
        return -1;                                    \
    }

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
/* There are two types of cmdu callbacks:
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
#                       HELP FUNCTIONS                                  #
########################################################################*/
static void log_unexpected_tlv(i1905_cmdu_t *cmdu, uint8_t tlv)
{
    /* Ignore all vendor specific tlvs */
    if (tlv != TLV_TYPE_VENDOR_SPECIFIC) {
        log_ctrl_w("unexpected tlv[%s] in cmdu[%s]", i1905_tlv_type_to_string(tlv),
                                                     i1905_cmdu_type_to_string(cmdu->message_type));
    }
}

static void log_missing_or_too_many_tlv(bool missing, i1905_cmdu_t *cmdu, uint8_t tlv)
{
    log_ctrl_e("%s tlv[%s] in cmdu[%s]", missing ? "missing" : "too many",
                                         i1905_tlv_type_to_string(tlv),
                                         i1905_cmdu_type_to_string(cmdu->message_type));
}

static int expect_one_tlv_type_common(i1905_cmdu_t *cmdu, uint8_t tlv_type, bool one_or_more)
{
    uint8_t *tlv;
    size_t   idx;
    int      tlv_nr = 0;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        if (*tlv == tlv_type) {
            tlv_nr++;
        } else {
            log_unexpected_tlv(cmdu, *tlv);
        }
    }

    if (one_or_more) {
        CHECK_ONE_OR_MORE_TLV(tlv_type, tlv_nr);
    } else {
        CHECK_ONE_TLV(tlv_type, tlv_nr);
    }

    return 0;
}

/* Function to be used for CMDU that should only have one TLV type */
static int expect_one_tlv_type(i1905_cmdu_t *cmdu, uint8_t tlv_type)
{
    return expect_one_tlv_type_common(cmdu, tlv_type, false);
}

static int expect_one_or_more_tlv_type(i1905_cmdu_t *cmdu, uint8_t tlv_type)
{
    return expect_one_tlv_type_common(cmdu, tlv_type, true);
}

/*#######################################################################
#                       1905 CMDU VALIDATION                            #
########################################################################*/
/* 1905.1 6.3.7 (type 0x0007) */
int map_validate_ap_autoconfig_search(i1905_cmdu_t *cmdu)
{
    uint8_t *tlv;
    size_t   idx;
    int      al_mac_tlv_nr           = 0;
    int      searched_role_tlv_nr    = 0;
    int      freq_band_tlv_nr        = 0;
    int      supp_service_tlv_nr     = 0;
    int      searched_service_tlv_nr = 0;
    int      multiap_profile_tlv_nr  = 0;
    int      i;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_AL_MAC_ADDRESS:
                al_mac_tlv_nr++;
            break;
            case TLV_TYPE_SEARCHED_ROLE: {
                i1905_searched_role_tlv_t *sr_tlv = (i1905_searched_role_tlv_t *)tlv;
                searched_role_tlv_nr++;

                /* Searched role must be registrar */
                if (sr_tlv->role != IEEE80211_ROLE_REGISTRAR) {
                    log_ctrl_e("invalid searched role[%d] tlv[%s] cmdu[%s]",
                               sr_tlv->role, i1905_tlv_type_to_string(*tlv), i1905_cmdu_type_to_string(cmdu->message_type));
                    return -1;
                }
                break;
            }
            case TLV_TYPE_AUTOCONFIG_FREQ_BAND:
                freq_band_tlv_nr++;
            break;
            case TLV_TYPE_SUPPORTED_SERVICE: {
                supp_service_tlv_nr++;
                break;
            }
            case TLV_TYPE_SEARCHED_SERVICE: {
                map_searched_service_tlv_t* ss_tlcv = (map_searched_service_tlv_t*)tlv;
                searched_service_tlv_nr++;

                /* One service must be controller */
                for (i = 0; i < ss_tlcv->services_nr; i++) {
                    if (ss_tlcv->services[i] == MAP_SERVICE_CONTROLLER) {
                        break;
                    }
                }

                if (i == ss_tlcv->services_nr) {
                    log_ctrl_e("no controller in searched services tlv[%s] cmdu[%s]",
                               i1905_tlv_type_to_string(*tlv), i1905_cmdu_type_to_string(cmdu->message_type));
                }
                break;
            }
            case TLV_TYPE_MULTIAP_PROFILE:
                multiap_profile_tlv_nr++;
            break;
            default:
                log_unexpected_tlv(cmdu, *tlv);
            break;
        }
    }

    CHECK_ONE_TLV        (TLV_TYPE_AL_MAC_ADDRESS,       al_mac_tlv_nr          );
    CHECK_ONE_TLV        (TLV_TYPE_SEARCHED_ROLE,        searched_role_tlv_nr   );
    CHECK_ONE_TLV        (TLV_TYPE_AUTOCONFIG_FREQ_BAND, freq_band_tlv_nr       );
    CHECK_ZERO_OR_ONE_TLV(TLV_TYPE_SUPPORTED_SERVICE,    supp_service_tlv_nr    );
    CHECK_ZERO_OR_ONE_TLV(TLV_TYPE_SEARCHED_SERVICE,     searched_service_tlv_nr);
    CHECK_ZERO_OR_ONE_TLV(TLV_TYPE_MULTIAP_PROFILE,      multiap_profile_tlv_nr );

    return 0;
}

/* 1905.1 6.3.9 (type 0x0009) */
int map_validate_ap_autoconfig_wsc(i1905_cmdu_t *cmdu)
{
    uint8_t        *tlv;
    size_t          idx;
    int             wsc_tlv_nr              = 0;
    int             ap_basic_cap_tlv_nr     = 0;
    int             profile2_ap_cap_tlv_nr  = 0;
    int             ap_radio_adv_cap_tlv_nr = 0;
    uint8_t        *al_mac;
    map_ale_info_t *ale;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_WSC: {
                i1905_wsc_tlv_t *wsc_tlv = (i1905_wsc_tlv_t *)tlv;
                uint16_t         mac_len;

                wsc_tlv_nr++;
                al_mac = map_get_wsc_attr(wsc_tlv->wsc_frame, wsc_tlv->wsc_frame_size, WSC_ATTR_MAC_ADDR, &mac_len);
                if (!al_mac || mac_len != sizeof(mac_addr)) {
                    log_ctrl_e("al_mac not found in wsc attributes");
                    return -1;
                }
                break;
            }
            case TLV_TYPE_AP_RADIO_BASIC_CAPABILITIES:
                ap_basic_cap_tlv_nr++;
            break;
            case TLV_TYPE_PROFILE2_AP_CAPABILITY:         /* Profile 2 */
                profile2_ap_cap_tlv_nr++;
            break;
            case TLV_TYPE_AP_RADIO_ADVANCED_CAPABILITIES: /* Profile 2 */
                ap_radio_adv_cap_tlv_nr++;
            break;
            default:
                log_unexpected_tlv(cmdu, *tlv);
            break;
        }
    }

    /* Profile 1 requirements */
    CHECK_ONE_TLV(TLV_TYPE_WSC,                         wsc_tlv_nr);
    CHECK_ONE_TLV(TLV_TYPE_AP_RADIO_BASIC_CAPABILITIES, ap_basic_cap_tlv_nr);

    /* Profile 2 requirements */
    /* Note that we do not always know the profile yet at this point.
       E.g: When controller starts, it sends config renew. Agent directly sends
            WSC M1, so we did not yet receive the profile TLV...

       To avoid different onboarding sequences, we should make sure to have received at least
       one topology response before handling M1 and create ale and radios from there.
    */
    if (al_mac && (ale = map_dm_get_ale(al_mac))) {
        if (ale->map_profile >= MAP_PROFILE_2) {
            CHECK_ONE_TLV(TLV_TYPE_PROFILE2_AP_CAPABILITY,         profile2_ap_cap_tlv_nr);
            CHECK_ONE_TLV(TLV_TYPE_AP_RADIO_ADVANCED_CAPABILITIES, ap_radio_adv_cap_tlv_nr);
        }
    }

    return 0;
}

/* 1905.1 6.3.1 (type 0x0000) */
int map_validate_topology_discovery(i1905_cmdu_t *cmdu)
{
    uint8_t *tlv;
    size_t   idx;
    int      al_mac_tlv_nr = 0;
    int      mac_tlv_nr    = 0;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_AL_MAC_ADDRESS:
                al_mac_tlv_nr++;
            break;
            case TLV_TYPE_MAC_ADDRESS:
                mac_tlv_nr++;
            break;
            default:
                log_unexpected_tlv(cmdu, *tlv);
            break;
        }
    }

    CHECK_ONE_TLV(TLV_TYPE_AL_MAC_ADDRESS, al_mac_tlv_nr);
    CHECK_ONE_TLV(TLV_TYPE_MAC_ADDRESS,    mac_tlv_nr);

    return 0;
}

/* 1905.1 6.3.2 (type 0x0001) */
int map_validate_topology_query(i1905_cmdu_t *cmdu)
{
    uint8_t *tlv;
    size_t   idx;

    /* Nothing is expected */
    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_MULTIAP_PROFILE:
                /* Optional */
            break;
            default:
                log_unexpected_tlv(cmdu, *tlv);
            break;
        }
    }

    return 0;
}

/* 1905.1 6.3.3 (type 0x0002) */
int map_validate_topology_response(i1905_cmdu_t *cmdu)
{
    uint8_t        *src_mac              = cmdu->cmdu_stream.src_mac_addr;
    uint8_t        *tlv                  = NULL;
    map_ale_info_t *ale                  = NULL;
    size_t          idx;
    int             dev_info_tlv_nr      = 0;
    int             supp_service_tlv_nr  = 0;
    int             ap_op_bss_nr         = 0;
    int             assoc_clients_tlv_nr = 0;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_DEVICE_INFORMATION: {
                i1905_device_information_tlv_t *dev_info_tlv = (i1905_device_information_tlv_t *)tlv;
                dev_info_tlv_nr++;

                if (NULL != (ale = map_dm_get_ale_from_src_mac(src_mac))) {
                    if (maccmp(ale->al_mac, dev_info_tlv->al_mac_address)) {
                        mac_addr_str mac_str1;
                        mac_addr_str mac_str2;

                        log_ctrl_w("al mac mismatch in %s (%s <-> %s)", i1905_tlv_type_to_string(*tlv),
                               mac_to_string(ale->al_mac, mac_str1), mac_to_string(dev_info_tlv->al_mac_address, mac_str2));
                    }
                }
                break;
            }
            case TLV_TYPE_DEVICE_BRIDGING_CAPABILITY:
                /* Optional */
            break;
            case TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST:
                /* Optional */
            break;
            case TLV_TYPE_NEIGHBOR_DEVICE_LIST:
                /* Optional */
            break;
            case TLV_TYPE_SUPPORTED_SERVICE:
                supp_service_tlv_nr++;
            break;
            case TLV_TYPE_AP_OPERATIONAL_BSS:
                /* This is mandatory for easymesh, but treat optional here so we don't reject
                   topology response from a legacy 1905 device
                */
                ap_op_bss_nr++;
            break;
            case TLV_TYPE_ASSOCIATED_CLIENTS:
                assoc_clients_tlv_nr++;
            break;
            case TLV_TYPE_MULTIAP_PROFILE:
                /* Optional */
            break;
            default:
                log_unexpected_tlv(cmdu, *tlv);
            break;
        }
    }

    CHECK_ONE_TLV        (TLV_TYPE_DEVICE_INFORMATION, dev_info_tlv_nr     );
    CHECK_ZERO_OR_ONE_TLV(TLV_TYPE_SUPPORTED_SERVICE,  supp_service_tlv_nr );
    CHECK_ZERO_OR_ONE_TLV(TLV_TYPE_AP_OPERATIONAL_BSS, ap_op_bss_nr        );
    CHECK_ZERO_OR_ONE_TLV(TLV_TYPE_ASSOCIATED_CLIENTS, assoc_clients_tlv_nr);

    return 0;
}

/* 1905.1 6.3.4 (type 0x0003) */
int map_validate_topology_notification(i1905_cmdu_t *cmdu)
{
    uint8_t *tlv;
    size_t   idx;
    int      al_mac_tlv_nr = 0;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_AL_MAC_ADDRESS:
                al_mac_tlv_nr++;
            break;
            case TLV_TYPE_CLIENT_ASSOCIATION_EVENT:
                /* Optional */
            break;
            default:
                log_unexpected_tlv(cmdu, *tlv);
            break;
        }
    }

    CHECK_ONE_TLV(TLV_TYPE_AL_MAC_ADDRESS, al_mac_tlv_nr);

    return 0;
}

/* 1905.1 6.3.5 (type 0x0005) */
int map_validate_link_metrics_query(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    i1905_link_metric_query_tlv_t *lmq_tlv = NULL;
    uint8_t                       *tlv;
    size_t                         idx;
    int                            lmq_tlv_nr = 0;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_LINK_METRIC_QUERY:
                lmq_tlv_nr++;
                lmq_tlv = (i1905_link_metric_query_tlv_t *)tlv;
            break;
            default:
                log_unexpected_tlv(cmdu, *tlv);
            break;
        }
    }

    CHECK_ONE_TLV(TLV_TYPE_LINK_METRIC_QUERY, lmq_tlv_nr);

    /* Check query */
    if (lmq_tlv->destination != LINK_METRIC_QUERY_TLV_ALL_NEIGHBORS &&
        lmq_tlv->destination != LINK_METRIC_QUERY_TLV_SPECIFIC_NEIGHBOR) {

        log_ctrl_e("invalid link metrics query destination type");
        return -1;
    }

    if (lmq_tlv->destination == LINK_METRIC_QUERY_TLV_SPECIFIC_NEIGHBOR &&
        !maccmp(lmq_tlv->specific_neighbor, g_zero_mac)) {

        log_ctrl_e("invalid link metrics query destination mac");
        return -1;

    }

    if (lmq_tlv->link_metrics_type != LINK_METRIC_QUERY_TLV_TX_LINK_METRICS_ONLY &&
        lmq_tlv->link_metrics_type != LINK_METRIC_QUERY_TLV_RX_LINK_METRICS_ONLY &&
        lmq_tlv->link_metrics_type != LINK_METRIC_QUERY_TLV_BOTH_TX_AND_RX_LINK_METRICS) {

        log_ctrl_e("invalid link metrics query type");
        return -1;
    }

    return 0;
}

/* 1905.1 6.3.6 (type 0x0006) */
int map_validate_link_metrics_response(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    uint8_t *tlv;
    size_t   idx;
    int      metrics_tlv_nr = 0;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_TRANSMITTER_LINK_METRIC:
                metrics_tlv_nr++;
            break;
            case TLV_TYPE_RECEIVER_LINK_METRIC:
                metrics_tlv_nr++;
            break;
            case TLV_TYPE_LINK_METRIC_RESULT_CODE:
                metrics_tlv_nr++;
            break;
            default:
                log_unexpected_tlv(cmdu, *tlv);
            break;
        }
    }

    /* One of the 3 must be present */
    if (metrics_tlv_nr == 0) {
        log_ctrl_e("missing tlv in cmdu[%s]", i1905_cmdu_type_to_string(cmdu->message_type));
        return -1;
    }

    return 0;
}

/* 1905.1 6.3.13 (type 0x0004) */
int map_validate_vendor_specific(UNUSED map_ale_info_t * ale, i1905_cmdu_t *cmdu)
{
    return expect_one_or_more_tlv_type(cmdu, TLV_TYPE_VENDOR_SPECIFIC);
}

/*#######################################################################
#                       MAP R1 CMDU VALIDATION                          #
########################################################################*/
/* MAP_R1 17.1 (type 0x8000) */
int map_validate_ack(i1905_cmdu_t *cmdu)
{
    uint8_t *tlv;
    size_t   idx;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_ERROR_CODE:
                /* Optional */
            break;
            default:
                log_unexpected_tlv(cmdu, *tlv);
            break;
        }
    }

    return 0;
}

/* MAP_R1 17.1.6 (type 0x8002) */
int map_validate_ap_capability_report(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    uint8_t *tlv;
    size_t   idx;
    int      ap_cap_tlv_nr             = 0;
    int      ap_radio_basic_cap_tlv_nr = 0;
    int      channel_scan_cap_tlv_nr   = 0;
    int      cac_cap_tlv_nr            = 0;
    int      profile2_ap_cap_tlv_nr    = 0;
    int      metric_coll_int_tlv_nr    = 0;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_AP_CAPABILITY:
                ap_cap_tlv_nr++;
            break;
            case TLV_TYPE_AP_RADIO_BASIC_CAPABILITIES:
                ap_radio_basic_cap_tlv_nr++;
            break;
            case TLV_TYPE_AP_HT_CAPABILITIES:
                /* Optional */
            break;
            case TLV_TYPE_AP_VHT_CAPABILITIES:
                /* Optional */
            break;
            case TLV_TYPE_AP_HE_CAPABILITIES:
                /* Optional */
            break;
            case TLV_TYPE_CHANNEL_SCAN_CAPABILITIES:  /* Profile 2 */
                channel_scan_cap_tlv_nr++;
            break;
            case TLV_TYPE_CAC_CAPABILITIES:           /* Profile 2 */
                cac_cap_tlv_nr++;
            break;
            case TLV_TYPE_PROFILE2_AP_CAPABILITY:     /* Profile 2 */
                profile2_ap_cap_tlv_nr++;
            break;
            case TLV_TYPE_METRIC_COLLECTION_INTERVAL: /* Profile 2 */
                metric_coll_int_tlv_nr++;
            break;
            case TLV_TYPE_AP_WIFI6_CAPABILITIES:      /* Profile 3 */
                /* Optional */
            break;
            case TLV_TYPE_DEVICE_INVENTORY:            /* Profile 3 */
                /* Optional */
            break;
            default:
                log_unexpected_tlv(cmdu, *tlv);
            break;
        }
    }

    /* Profile 1 requirements */
    CHECK_ONE_TLV        (TLV_TYPE_AP_CAPABILITY,               ap_cap_tlv_nr            );
    CHECK_ONE_OR_MORE_TLV(TLV_TYPE_AP_RADIO_BASIC_CAPABILITIES, ap_radio_basic_cap_tlv_nr);

    /* Profile 2 requirements */
    if (ale->map_profile >= MAP_PROFILE_2) {
        CHECK_ONE_TLV(TLV_TYPE_CHANNEL_SCAN_CAPABILITIES,  channel_scan_cap_tlv_nr);
        CHECK_ONE_TLV(TLV_TYPE_CAC_CAPABILITIES,           cac_cap_tlv_nr         );
        CHECK_ONE_TLV(TLV_TYPE_PROFILE2_AP_CAPABILITY,     profile2_ap_cap_tlv_nr );
        CHECK_ONE_TLV(TLV_TYPE_METRIC_COLLECTION_INTERVAL, metric_coll_int_tlv_nr );
    }

    return 0;
}

/* MAP_R1 17.1.10 (type 0x8005) */
int map_validate_channel_preference_report(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    uint8_t *tlv;
    size_t   idx;
    int      cac_status_report_tlv_nr = 0;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_CHANNEL_PREFERENCE:
                /* Optional */
            break;
            case TLV_TYPE_RADIO_OPERATION_RESTRICTION:
                /* Optional */
            break;
            case TLV_TYPE_CAC_COMPLETION_REPORT:
                /* Optional */
            break;
            case TLV_TYPE_CAC_STATUS_REPORT:
                cac_status_report_tlv_nr++;
            break;
            default:
                log_unexpected_tlv(cmdu, *tlv);
            break;
        }
    }

    /* Profile 2 requirements */
    if (ale->map_profile >= MAP_PROFILE_2) {
        CHECK_ONE_TLV(TLV_TYPE_CAC_STATUS_REPORT, cac_status_report_tlv_nr);
    }

    return 0;
}

/* MAP_R1 17.1.12 (type 0x8007) */
int map_validate_channel_selection_response(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    return expect_one_or_more_tlv_type(cmdu, TLV_TYPE_CHANNEL_SELECTION_RESPONSE);
}

/* MAP_R1 17.1.13 (type 0x8008) */
int map_validate_operating_channel_report(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    return expect_one_or_more_tlv_type(cmdu, TLV_TYPE_OPERATING_CHANNEL_REPORT);
}

/* MAP_R1 17.1.15 (type 0x800A) */
int map_validate_client_capability_report(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    uint8_t *tlv;
    size_t   idx;
    int      client_info_tlv_nr       = 0;
    int      client_cap_report_tlv_nr = 0;
    int      error_code_tlv_nr        = 0;
    map_client_cap_report_tlv_t *cap_report_tlv = NULL;


    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_CLIENT_INFO:
                client_info_tlv_nr++;
            break;
            case TLV_TYPE_CLIENT_CAPABILITY_REPORT:
                client_cap_report_tlv_nr++;
                cap_report_tlv = (map_client_cap_report_tlv_t *)tlv;
            break;
            case TLV_TYPE_ERROR_CODE:
                error_code_tlv_nr++;
            break;
            default:
                log_unexpected_tlv(cmdu, *tlv);
            break;
        }
    }

    CHECK_ONE_TLV(TLV_TYPE_CLIENT_INFO,              client_info_tlv_nr);
    CHECK_ONE_TLV(TLV_TYPE_CLIENT_CAPABILITY_REPORT, client_cap_report_tlv_nr);

    /* In case of failure, error code TLV is also mandatory */
    if (cap_report_tlv && cap_report_tlv->result_code == MAP_CLIENT_CAP_FAILURE) {
        CHECK_ONE_TLV(TLV_TYPE_ERROR_CODE, error_code_tlv_nr);
    }

    return 0;
}

/* MAP_R1 17.1.17 (type 0x800C) */
int map_validate_ap_metrics_response(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    uint8_t *tlv;
    size_t   idx;
    //int      ap_metrics_tlv_nr     = 0;
    //int      ap_ext_metrics_tlv_nr = 0;


    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_AP_METRICS:
                //ap_metrics_tlv_nr++;
            break;
            case TLV_TYPE_ASSOCIATED_STA_TRAFFIC_STATS:
                /* Optional */
            break;
            case TLV_TYPE_ASSOCIATED_STA_LINK_METRICS:
                /* Optional */
            break;
            case TLV_TYPE_AP_EXTENDED_METRICS:                  /* Profile 2 */
                //ap_ext_metrics_tlv_nr++;
            break;
            case TLV_TYPE_RADIO_METRICS:                        /* Profile 2 */
                /* Optional */
            break;
            case TLV_TYPE_ASSOCIATED_STA_EXTENDED_LINK_METRICS: /* Profile 2 */
                /* Optional */
            break;
            case TLV_TYPE_ASSOCIATED_WIFI6_STA_STATUS_REPORT: /* Profile 3 */
                /* Optional */
            break;
            default:
                log_unexpected_tlv(cmdu, *tlv);
            break;
        }
    }

    /* Profile 1 requirements */
    /* TODO: make validation smarter */
    /*       EM standard is not correct.
             If there are no bss, there are no AP (extended) metrics TLVs
    */
#if 0
    CHECK_ONE_OR_MORE_TLV(TLV_TYPE_AP_METRICS, ap_metrics_tlv_nr);

    /* Profile 2 requirements */
    if (ale->map_profile >= MAP_PROFILE_2) {
        CHECK_ONE_OR_MORE_TLV(TLV_TYPE_AP_EXTENDED_METRICS, ap_ext_metrics_tlv_nr);
    }
#endif

    return 0;
}

/* MAP_R1 17.1.19 (type 0x800E) */
int map_validate_assoc_sta_link_metrics_response(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    uint8_t *tlv;
    size_t   idx;
    int      lm_tlv_nr     = 0;
    int      ext_lm_tlv_nr = 0;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_ASSOCIATED_STA_LINK_METRICS:
                lm_tlv_nr++;
            break;
            case TLV_TYPE_ERROR_CODE:
                /* Optional */
            break;
            case TLV_TYPE_ASSOCIATED_STA_EXTENDED_LINK_METRICS:
                ext_lm_tlv_nr++;
            break;
            default:
                log_unexpected_tlv(cmdu, *tlv);
            break;
        }
    }

    /* Profile 1 requirements */
    CHECK_ONE_OR_MORE_TLV(TLV_TYPE_ASSOCIATED_STA_LINK_METRICS, lm_tlv_nr);

    /* Profile 2 requirements */
    if (ale->map_profile >= MAP_PROFILE_2) {
        CHECK_ONE_OR_MORE_TLV(TLV_TYPE_ASSOCIATED_STA_EXTENDED_LINK_METRICS, ext_lm_tlv_nr);
    }

    return 0;
}

/* MAP_R1 17.1.21 (type 0x8010) */
int map_validate_unassoc_sta_link_metrics_response(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    return expect_one_tlv_type(cmdu, TLV_TYPE_UNASSOCIATED_STA_LINK_METRICS_RESPONSE);
}

/* MAP_R1 17.1.23 (type 0x8012) */
int map_validate_beacon_metrics_response(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    return expect_one_tlv_type(cmdu, TLV_TYPE_BEACON_METRICS_RESPONSE);
}

/* MAP_R1 17.1.26 (type 0x8015) */
int map_validate_client_steering_btm_report(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    return expect_one_tlv_type(cmdu, TLV_TYPE_STEERING_BTM_REPORT);
}

/* MAP_R1 17.1.28 (type 0x8017) */
int map_validate_steering_completed(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    uint8_t *tlv;
    size_t   idx;

    /* Nothing is expected */
    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        log_unexpected_tlv(cmdu, *tlv);
    }

    return 0;
}

/* MAP_R1 17.1.30 (type 0x801A) */
int map_validate_backhaul_steering_response(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    uint8_t *tlv;
    size_t   idx;
    int      bh_steer_resp_tlv_nr = 0;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_BACKHAUL_STEERING_RESPONSE:
                bh_steer_resp_tlv_nr++;
            break;
            case TLV_TYPE_ERROR_CODE:
                /* Optional */
            break;
            default:
                log_unexpected_tlv(cmdu, *tlv);
            break;
        }
    }

    CHECK_ONE_TLV(TLV_TYPE_BACKHAUL_STEERING_RESPONSE, bh_steer_resp_tlv_nr);

    return 0;
}

/* MAP_R1 17.1.31 (type 0x8018) */
int map_validate_higher_layer_data(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    return expect_one_tlv_type(cmdu, TLV_TYPE_HIGHER_LAYER_DATA);
}

/*#######################################################################
#                       MAP R2 CMDU VALIDATION                          #
########################################################################*/
/* MAP_R2 17.1.34 (type 0x801C) */
int map_validate_channel_scan_report(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    uint8_t *tlv;
    size_t   idx;
    int      timestamp_tlv_nr           = 0;
    int      channel_scan_result_tlv_nr = 0;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_TIMESTAMP:
                timestamp_tlv_nr++;
            break;
            case TLV_TYPE_CHANNEL_SCAN_RESULT:
                channel_scan_result_tlv_nr++;
            break;
            default:
                log_unexpected_tlv(cmdu, *tlv);
            break;
        }
    }

    CHECK_ONE_TLV        (TLV_TYPE_TIMESTAMP,           timestamp_tlv_nr          );
    CHECK_ONE_OR_MORE_TLV(TLV_TYPE_CHANNEL_SCAN_RESULT, channel_scan_result_tlv_nr);

    return 0;
}

/* MAP_R2 17.1.39 (type 0x8025) */
int map_validate_assoc_status_notification(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    return expect_one_tlv_type(cmdu, TLV_TYPE_ASSOCIATION_STATUS_NOTIFICATION);
}

/* MAP_R2 17.1.40 (type 0x8026) */
int map_validate_tunneled_msg(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    uint8_t *tlv;
    size_t   idx;
    int      source_info_tlv_nr       = 0;
    int      tunneled_msg_type_tlv_nr = 0;
    int      tunneled_tlv_nr          = 0;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_SOURCE_INFO:
                source_info_tlv_nr++;
            break;
            case TLV_TYPE_TUNNELED_MESSAGE_TYPE:
                tunneled_msg_type_tlv_nr++;
            break;
            case TLV_TYPE_TUNNELED:
                tunneled_tlv_nr++;
            break;
            default:
                log_unexpected_tlv(cmdu, *tlv);
            break;
        }
    }

    CHECK_ONE_TLV        (TLV_TYPE_SOURCE_INFO,           source_info_tlv_nr      );
    CHECK_ONE_TLV        (TLV_TYPE_TUNNELED_MESSAGE_TYPE, tunneled_msg_type_tlv_nr);
    CHECK_ONE_OR_MORE_TLV(TLV_TYPE_TUNNELED,              tunneled_tlv_nr         );

    return 0;
}

/* MAP_R2 17.1.41 (type 0x8022) */
int map_validate_client_disassoc_stats(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    uint8_t *tlv;
    size_t   idx;
    int      sta_mac_addr_tlv_nr            = 0;
    int      reason_code_tlv_nr             = 0;
    int      assoc_sta_traffic_stats_tlv_nr = 0;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_STA_MAC_ADDRESS:
                sta_mac_addr_tlv_nr++;
            break;
            case TLV_TYPE_REASON_CODE:
                reason_code_tlv_nr++;
            break;
            case TLV_TYPE_ASSOCIATED_STA_TRAFFIC_STATS:
                assoc_sta_traffic_stats_tlv_nr++;
            break;
            default:
                log_unexpected_tlv(cmdu, *tlv);
            break;
        }
    }

    CHECK_ONE_TLV(TLV_TYPE_STA_MAC_ADDRESS,              sta_mac_addr_tlv_nr           );
    CHECK_ONE_TLV(TLV_TYPE_REASON_CODE,                  reason_code_tlv_nr            );
    CHECK_ONE_TLV(TLV_TYPE_ASSOCIATED_STA_TRAFFIC_STATS, assoc_sta_traffic_stats_tlv_nr);

    return 0;
}

/* MAP_R2 17.1.43 (type 0x8028) */
int map_validate_backhaul_sta_capability_report(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    uint8_t *tlv;
    size_t   idx;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_BACKHAUL_STA_RADIO_CAPABILITIES:
                /* Optional */
            break;
            default:
                log_unexpected_tlv(cmdu, *tlv);
            break;
        }
    }

    return 0;
}

/* MAP_R2 17.1.44 (type 0x8033) */
int map_validate_failed_connection(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    uint8_t *tlv;
    size_t   idx;
    int      sta_mac_addr_tlv_nr = 0;
    int      status_code_tlv_nr  = 0;
    int      bssid_tlv_nr        = 0;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_BSSID:
                bssid_tlv_nr++;
            break;
            case TLV_TYPE_STA_MAC_ADDRESS:
                sta_mac_addr_tlv_nr++;
            break;
            case TLV_TYPE_STATUS_CODE:
                status_code_tlv_nr++;
            break;
            case TLV_TYPE_REASON_CODE:
                /* Optional */
            break;
            default:
                log_unexpected_tlv(cmdu, *tlv);
            break;
        }
    }

    CHECK_ZERO_OR_ONE_TLV(TLV_TYPE_BSSID,   bssid_tlv_nr );
    CHECK_ONE_TLV(TLV_TYPE_STA_MAC_ADDRESS, sta_mac_addr_tlv_nr);
    CHECK_ONE_TLV(TLV_TYPE_STATUS_CODE,     status_code_tlv_nr );

    return 0;
}

/*#######################################################################
#                       MAP R3 CMDU VALIDATION                          #
########################################################################*/
/* MAP_R3 17.1.48 (type 0x8029) */
int map_validate_proxied_encap_dpp(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    uint8_t *tlv;
    size_t   idx;
    int      encap_dpp_tlv_nr = 0;
    int      chirp_value_tlv_nr  = 0;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_1905_ENCAP_DPP:
                encap_dpp_tlv_nr++;
            break;
            case TLV_TYPE_DPP_CHIRP_VALUE:
                chirp_value_tlv_nr++;
            break;
            default:
                log_unexpected_tlv(cmdu, *tlv);
            break;
        }
    }
    CHECK_ONE_TLV(TLV_TYPE_1905_ENCAP_DPP,          encap_dpp_tlv_nr);
    CHECK_ZERO_OR_ONE_TLV(TLV_TYPE_DPP_CHIRP_VALUE, chirp_value_tlv_nr );

    return 0;
}

/* MAP_R3 17.1.49 (type 0x8030) */
int map_validate_1905_encap_eapol(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    return expect_one_tlv_type(cmdu, TLV_TYPE_1905_ENCAP_EAPOL);
}

/* MAP_R3 17.1.52 (type 0x802f) */
int map_validate_chirp_notification(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    return expect_one_tlv_type(cmdu, TLV_TYPE_DPP_CHIRP_VALUE);
}

/* MAP_R3 17.1.56 (type 0x802a) */
int map_validate_direct_encap_dpp(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    return expect_one_tlv_type(cmdu, TLV_TYPE_DPP_MESSAGE);
}
