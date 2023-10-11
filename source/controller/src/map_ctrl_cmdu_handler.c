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
#define LOG_TAG "cmdu_handler"

#include "map_ctrl_cmdu_handler.h"
#include "map_ctrl_tlv_parser.h"
#include "map_ctrl_emex_tlv_handler.h"
#include "map_ctrl_cmdu_tx.h"
#include "map_ctrl_onboarding_handler.h"
#include "map_ctrl_post_onboarding_handler.h"
#include "map_ctrl_topology_tree.h"
#include "map_ctrl_utils.h"
#include "map_ctrl_defines.h"
#include "map_ctrl_chan_sel.h"

#include "map_info.h"
#include "map_retry_handler.h"
#include "map_topology_tree.h"
#include "map_staging_list.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define min(a,b) ((a) < (b) ? (a) : (b))

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
static void get_str_attribute(uint16_t attr_type, char *dest, uint16_t dest_len, uint8_t *m1, uint16_t m1_size)
{
    uint16_t  len;
    uint8_t  *p;

    if ((p = map_get_wsc_attr(m1, m1_size, attr_type, &len))) {
        len = min(len, dest_len - 1);
        memcpy(dest, p, len);
        dest[len] = 0;
    } else {
        dest[0] = 0;
    }
}

static void os_version_to_str(map_device_info_t *d)
{
    /* clear msb which is reserved and always 1 */
    uint8_t *p = (uint8_t*)&d->os_version;

    snprintf(d->os_version_str, sizeof(d->os_version_str), "%d.%d.%d.%d",
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
             p[0] & 0x7f, p[1], p[2], p[3]);
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
             p[3] & 0x7f, p[2], p[1], p[0]);
#else
#error Not big and not little endian
#endif
}

static void get_m1_attributes(map_ale_info_t *ale, uint8_t *m1, uint16_t m1_size)
{
    map_device_info_t  d;
    uint16_t           len;
    uint8_t           *p;

    memset(&d, 0, sizeof(map_device_info_t));

    if ((p = map_get_wsc_attr(m1, m1_size, WSC_ATTR_OS_VERSION, &len)) && len == 4) {
        _E4B(&p, &d.os_version);
        os_version_to_str(&d);
    }

    get_str_attribute(WSC_ATTR_MANUFACTURER,  d.manufacturer_name, sizeof(d.manufacturer_name), m1, m1_size);
    get_str_attribute(WSC_ATTR_MODEL_NAME,    d.model_name,        sizeof(d.model_name),        m1, m1_size);
    get_str_attribute(WSC_ATTR_MODEL_NUMBER,  d.model_number,      sizeof(d.model_number),      m1, m1_size);
    get_str_attribute(WSC_ATTR_SERIAL_NUMBER, d.serial_number,     sizeof(d.serial_number),     m1, m1_size);

    map_dm_ale_set_device_info(ale, &d);
}

static void refresh_radio_data(map_ale_info_t *ale, map_radio_info_t *radio)
{
    timer_id_t retry_id;

    set_radio_state_unconfigured(&radio->state);

    /* Send policy config (stop timer if it was running) */
    map_dm_get_radio_timer_id(retry_id, radio, POLICY_CONFIG_RETRY_ID);
    if (map_is_timer_registered(retry_id)) {
        map_unregister_retry(retry_id);
    }
    if (map_register_retry(retry_id, 10, 10, ale,
                           map_handle_policy_config_sent, map_build_and_send_policy_config)) {
        log_ctrl_e("%s: failed registring policy config retry[%s]", __FUNCTION__, retry_id);
    }

    /* Renew operating channel & channel preference info */
    map_agent_cancel_channel_selection(ale);
    set_radio_state_channel_preference_query_not_sent(&radio->state);
    set_radio_state_channel_pref_report_not_received(&radio->state);
    set_radio_state_oper_chan_report_not_received(&radio->state);

    /* Recomputation of radio state will be required if policy config retry timer registration fails */
    map_recompute_radio_state_and_update_ale_state(ale);

    /* Renew AP Capabilities */
    set_radio_state_ap_cap_report_not_received(&radio->state);

    /* Renew bhsta capabilities */
    set_ale_state_bhsta_cap_report_not_received(&ale->state);
}

/*#######################################################################
#                       LINK METRICS HANDLING                           #
########################################################################*/
/* TODO: this is way too much code to track links */
static int compare_neighbor_link_metrics_node(void* link_metrics_node, void* al_mac)
{
    if (link_metrics_node && al_mac) {
        if (0 == maccmp(((map_neighbor_link_metric_t*)link_metrics_node)->al_mac, al_mac)) {
            return 1;
        }
    }
    return 0;
}

static void map_update_tx_params(i1905_transmitter_link_metric_tlv_t *tlv, map_neighbor_link_metric_t *neighbor_link_metrics)
{
    maccpy(neighbor_link_metrics->al_mac,             tlv->neighbor_al_address);
    maccpy(neighbor_link_metrics->neighbor_iface_mac, tlv->transmitter_link_metrics->neighbor_interface_address);
    maccpy(neighbor_link_metrics->local_iface_mac,    tlv->transmitter_link_metrics->local_interface_address);

    neighbor_link_metrics->intf_type = tlv->transmitter_link_metrics->intf_type;
    neighbor_link_metrics->tx_metric.packet_errors           = tlv->transmitter_link_metrics->packet_errors;
    neighbor_link_metrics->tx_metric.transmitted_packets     = tlv->transmitter_link_metrics->transmitted_packets;
    neighbor_link_metrics->tx_metric.mac_throughput_capacity = tlv->transmitter_link_metrics->mac_throughput_capacity;
    neighbor_link_metrics->tx_metric.link_availability       = tlv->transmitter_link_metrics->link_availability;
    neighbor_link_metrics->tx_metric.phy_rate                = tlv->transmitter_link_metrics->phy_rate;
}

static void map_update_rx_params(i1905_receiver_link_metric_tlv_t *tlv, map_neighbor_link_metric_t *neighbor_link_metrics)
{
    maccpy(neighbor_link_metrics->al_mac,             tlv->neighbor_al_address);
    maccpy(neighbor_link_metrics->neighbor_iface_mac, tlv->receiver_link_metrics->neighbor_interface_address);
    maccpy(neighbor_link_metrics->local_iface_mac,    tlv->receiver_link_metrics->local_interface_address);

    neighbor_link_metrics->intf_type = tlv->receiver_link_metrics->intf_type;
    neighbor_link_metrics->rx_metric.packet_errors    = tlv->receiver_link_metrics->packet_errors;
    neighbor_link_metrics->rx_metric.packets_received = tlv->receiver_link_metrics->packets_received;
    neighbor_link_metrics->rx_metric.rssi             = tlv->receiver_link_metrics->rssi;
}

static map_neighbor_link_metric_t* map_get_neighbor_metrics(array_list_t *link_metrics_list, uint8_t *al_mac)
{
    /* Check if it already exists */
    map_neighbor_link_metric_t *link_metrics = find_object(link_metrics_list, al_mac, compare_neighbor_link_metrics_node);

    /* Create a new object if it doesn't exists */
    if (NULL == link_metrics) {
        link_metrics = calloc(1, sizeof(map_neighbor_link_metric_t));

        if (link_metrics && (-1 == push_object(link_metrics_list, link_metrics))) {
            free(link_metrics);
            link_metrics = NULL;
        }
    }
    return link_metrics;
}

static void map_cache_updated_link_metrics(array_list_t *link_metrics_list, map_neighbor_link_metric_t *link_metrics)
{
    if (NULL == find_object(link_metrics_list, link_metrics->al_mac, compare_neighbor_link_metrics_node)) {
        if (push_object(link_metrics_list, link_metrics) == -1) {
            log_ctrl_e("%s failed to add to the new neighbor link metrics list", __FUNCTION__);
        }
    }
}

static void map_parse_tx_link_metrics_tlv(i1905_transmitter_link_metric_tlv_t *tx_tlv, array_list_t *link_metrics_cache_list, map_ale_info_t **ale)
{
    map_ale_info_t             *current_ale;
    map_ale_info_t             *neighbor_ale;
    map_bss_info_t             *bss;
    map_neighbor_link_metric_t *link_metrics;

    do {
        /* Validate the TLV struct params */
        if (tx_tlv->transmitter_link_metrics_nr == 0 || tx_tlv->transmitter_link_metrics == NULL) {
            break;
        }

        /* Get the current/neighbor ALE for which link metrics reported */
        current_ale  = map_dm_get_ale(tx_tlv->local_al_address);
        neighbor_ale = map_dm_get_ale(tx_tlv->neighbor_al_address);
        if (current_ale == NULL || neighbor_ale == NULL) {
            break;
        }

        /* If the reported neighbor is parent update it as a upstream link metrics */
        if (is_parent_of(neighbor_ale, current_ale)) {
            /* Update information about upstream link */
            map_dm_ale_set_upstream_info(current_ale,
                                         /* upstream al mac     */ neighbor_ale->al_mac,
                                         /* local upstream mac  */ tx_tlv->transmitter_link_metrics->local_interface_address,
                                         /* remote upstream mac */ tx_tlv->transmitter_link_metrics->neighbor_interface_address,
                                         true, tx_tlv->transmitter_link_metrics->intf_type);

            map_update_tx_params(tx_tlv, &current_ale->upstream_link_metrics);

            *ale = current_ale;
            break;
        } else {
            if ((bss = map_dm_get_bss_gbl(tx_tlv->transmitter_link_metrics->local_interface_address))) {
                /* Neighbor connected via backhaul wifi interface. Update the link metrics under the BSS metrics list */
                if (bss->radio == NULL || bss->radio->ale == NULL || bss->radio->ale != current_ale) {
                    log_ctrl_e("%s: orphan BSS node or BSS is not associated with given ALE", __FUNCTION__);
                    break;
                }

                if (!(bss->type & MAP_BACKHAUL_BSS)) {
                    log_ctrl_e("%s: link metrics reported for non backhaul BSS", __FUNCTION__);
                    break;
                }

                if (!(link_metrics = map_get_neighbor_metrics(bss->neigh_link_metric_list, tx_tlv->neighbor_al_address))) {
                    break;
                }
            } else {
                // Neighbor connected via ethernet interface. Update the link metrics under the ethernet metrics list
                if (!(link_metrics = map_get_neighbor_metrics(current_ale->eth_neigh_link_metric_list, tx_tlv->neighbor_al_address))) {
                    break;
                }
            }

            // Update the TX metrics into the metrics object
            map_update_tx_params(tx_tlv, link_metrics);

            // Store the newly created link metrics
            map_cache_updated_link_metrics(link_metrics_cache_list, link_metrics);

            *ale = current_ale;
        }
    } while (0);
}

static void map_parse_rx_link_metrics_tlv(i1905_receiver_link_metric_tlv_t *rx_tlv, array_list_t *link_metrics_cache_list, map_ale_info_t **ale)
{
    map_ale_info_t             *current_ale;
    map_ale_info_t             *neighbor_ale;
    map_bss_info_t             *bss;
    map_neighbor_link_metric_t *link_metrics;

    do {
        /* Validate the TLV struct params */
        if (rx_tlv->receiver_link_metrics_nr == 0 || rx_tlv->receiver_link_metrics == NULL) {
            break;
        }

        /* Get the current/neighbor ALE for which link metrics reported */
        current_ale  = map_dm_get_ale(rx_tlv->local_al_address);
        neighbor_ale = map_dm_get_ale(rx_tlv->neighbor_al_address);
        if (current_ale == NULL || neighbor_ale == NULL) {
            break;
        }

        /* If the reported neighbor is parent update it as a upstream link metrics */
        if (is_parent_of(neighbor_ale, current_ale)) {
            /* Update information about upstream link */
            map_dm_ale_set_upstream_info(current_ale,
                                         /* upstream al mac     */ neighbor_ale->al_mac,
                                         /* local upstream mac   */ rx_tlv->receiver_link_metrics->local_interface_address,
                                         /* remote upstream mac  */ rx_tlv->receiver_link_metrics->neighbor_interface_address,
                                         true, rx_tlv->receiver_link_metrics->intf_type);

            map_update_rx_params(rx_tlv, &current_ale->upstream_link_metrics);

            *ale = current_ale;
            break;
        } else {
            if ((bss = map_dm_get_bss_gbl(rx_tlv->receiver_link_metrics->local_interface_address))) {
                /* Neighbor connected via backhaul wifi interface. Update the link metrics under the BSS metrics list */
                if (bss->radio == NULL || bss->radio->ale == NULL || bss->radio->ale != current_ale) {
                    break;
                }

                if (!(link_metrics = map_get_neighbor_metrics(bss->neigh_link_metric_list, rx_tlv->neighbor_al_address))) {
                    break;
                }
            } else {
                /* Neighbor connected via ethernet interface. Update the link metrics under the ethernet metrics list */
                if (!(link_metrics = map_get_neighbor_metrics(current_ale->eth_neigh_link_metric_list, rx_tlv->neighbor_al_address))) {
                    break;
                }
            }

            /* Update the RX metrics into the metrics object */
            map_update_rx_params(rx_tlv, link_metrics);

            /* Store the newly created link metrics */
            map_cache_updated_link_metrics(link_metrics_cache_list, link_metrics);

            *ale = current_ale;
        }
    } while (0);
}

static size_t map_get_all_iface_link_metrics_list(map_ale_info_t *ale, array_list_t **link_metrics_list)
{
    map_radio_info_t *radio;
    map_bss_info_t   *bss;
    size_t            count = 0;

    map_dm_foreach_radio(ale, radio) {
        map_dm_foreach_bss(radio, bss) {
            if ((bss->type & MAP_BACKHAUL_BSS) && bss->neigh_link_metric_list &&
                list_get_size(bss->neigh_link_metric_list) && (count <= MAX_BSS_PER_AGENT)) {
                link_metrics_list[count++] = bss->neigh_link_metric_list;
            }
        }
    }

    if (ale->eth_neigh_link_metric_list && list_get_size(ale->eth_neigh_link_metric_list) && (count <= MAX_BSS_PER_AGENT)) {
        link_metrics_list[count++] = ale->eth_neigh_link_metric_list;
    }

    return count;
}

static void map_remove_old_link_metrics(map_ale_info_t *ale, array_list_t *new_link_metrics_list)
{
    /* array of array_list_t * with size as (MAX_BSS_PER_AGENT) + 1 (Arraylist for ethernet devices) */
    array_list_t               *link_metrics_list[MAX_BSS_PER_AGENT + 1] = {0};
    map_neighbor_link_metric_t *existing_link_metrics;
    list_iterator_t             iter = {0};
    size_t                      list_count, i;

    list_count = map_get_all_iface_link_metrics_list(ale, link_metrics_list);

    for (i = 0; i < list_count; i++) {

        bind_list_iterator(&iter, link_metrics_list[i]);

        while(NULL != (existing_link_metrics = get_next_list_object(&iter))) {
            if (NULL == find_object(new_link_metrics_list , existing_link_metrics->al_mac, compare_neighbor_link_metrics_node)) {
                /* Remove the old object, since it does not exist in new_link_metrics_list */
                free(find_remove_object(link_metrics_list[i], existing_link_metrics->al_mac, compare_neighbor_link_metrics_node));
            } else {
                /* Removing the found object from new list will speedup upcoming search */
                find_remove_object(new_link_metrics_list, existing_link_metrics->al_mac, compare_neighbor_link_metrics_node);
            }
        }
    }

    if (0 != list_get_size(new_link_metrics_list)) {
        log_ctrl_e("%s: something went wrong", __FUNCTION__);
    }
}

/*#######################################################################
#                       1905 CMDU HANDLERS                              #
########################################################################*/
static int handle_1905_dev(i1905_cmdu_t *cmdu, bool topo_discovery)
{
    i1905_al_mac_address_tlv_t *al_mac_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_AL_MAC_ADDRESS, cmdu);
    map_1905_dev_info_t        *dev;

    if (!al_mac_tlv) {
        /* Already checked in map_ctrl_cmdu_validator.c */
        return -1;
    }

    /* Send topology query as soon as we see a 1905 device */
    map_send_topology_query_with_al_mac(al_mac_tlv->al_mac_address, cmdu->interface_name, MID_NA);

    if (NULL != (dev = map_stglist_get_1905_dev(al_mac_tlv->al_mac_address))) {
        return 0; /* ALE is in the staging list */
    }

    if (!(dev = map_stglist_create_1905_dev(al_mac_tlv->al_mac_address, cmdu->cmdu_stream.src_mac_addr, topo_discovery))) {
        log_ctrl_e("%s: Failed to create 1905 dev info", __FUNCTION__);
    }

    if (topo_discovery) {
	i1905_mac_address_tlv_t *mac_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_MAC_ADDRESS, cmdu);
	map_stglist_set_1905_dev_mac_tlv_mac(dev, mac_tlv->mac_address);
    }

    return 0;
}

static int map_handle_topology_response_ale(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    i1905_device_information_tlv_t   *dev_info_tlv      = i1905_get_tlv_from_cmdu(TLV_TYPE_DEVICE_INFORMATION, cmdu); /* Mandatory */
    map_ap_operational_bss_tlv_t     *op_bss_tlv        = i1905_get_tlv_from_cmdu(TLV_TYPE_AP_OPERATIONAL_BSS, cmdu); /* Optional  */
    map_assoc_clients_tlv_t          *assoc_clients_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_ASSOCIATED_CLIENTS, cmdu); /* Optional  */
    map_multiap_profile_tlv_t        *profile_tlv       = i1905_get_tlv_from_cmdu(TLV_TYPE_MULTIAP_PROFILE,    cmdu); /* Optional  */
    i1905_neighbor_device_list_tlv_t            *neighbor_dev_tlv;
    i1905_non_1905_neighbor_device_list_tlv_t   *non_1905_neighbor_dev_tlv;
    i1905_neighbor_device_list_tlv_t            *neighbor_dev_tlvs[MAX_ALE_NEIGHBOR_COUNT] = {NULL};
    i1905_non_1905_neighbor_device_list_tlv_t   *non_1905_neighbor_dev_tlvs[MAX_ALE_NEIGHBOR_COUNT] = {NULL};
    i1905_vendor_specific_tlv_t                 *vendor_tlv;
    size_t                                       neighbor_dev_tlvs_nr = 0, non_1905_neighbor_dev_tlvs_nr = 0, tlv_idx;
    bool                                         update_dm = false;

    if (!dev_info_tlv) {
        return -1; /* Not possble - checked during validate */
    }

    /* Get all i1905 neighbor tlvs */
    i1905_foreach_tlv_type_in_cmdu(TLV_TYPE_NEIGHBOR_DEVICE_LIST, neighbor_dev_tlv, cmdu, tlv_idx) {
        if (neighbor_dev_tlvs_nr < MAX_ALE_NEIGHBOR_COUNT) {
            neighbor_dev_tlvs[neighbor_dev_tlvs_nr++] = neighbor_dev_tlv;
        }
    }

    /* Get all non_i1905 neighbor tlvs */
    i1905_foreach_tlv_type_in_cmdu(TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST, non_1905_neighbor_dev_tlv, cmdu, tlv_idx) {
        if (non_1905_neighbor_dev_tlvs_nr < MAX_ALE_NEIGHBOR_COUNT) {
            non_1905_neighbor_dev_tlvs[non_1905_neighbor_dev_tlvs_nr++] = non_1905_neighbor_dev_tlv;
        }
    }

    /* Parse map_profile of ale first as it is used in the onboarding flow */
    if (profile_tlv) {
        map_parse_multiap_profile_tlv(ale, profile_tlv);
    }

    /* Update the source mac of this frame */
    map_update_ale_source_mac(ale, cmdu->cmdu_stream.src_mac_addr);

    /* Update the receiving interface name. */
    map_update_ale_receiving_iface(ale, cmdu->interface_name);

    /* Parse and update the neighbor list */
    map_parse_neighbor_device_list_tlv(ale, neighbor_dev_tlvs, neighbor_dev_tlvs_nr);

    /* Parse and update the radio and BSS info. */
    if (op_bss_tlv) {
        map_parse_ap_operational_bss_tlv(ale, op_bss_tlv);
    }

    /* Parse device info (includes local interface list).
       Must currently be done after parsing operational bss tlv
       as that contains information required to find radio of
       sta interfaces in map_ctrl_msg_glue.c
    */
    map_parse_device_information_tlv(ale, dev_info_tlv);

    /* Store non 1905 neighbors.  Must be done after parsing device information tlv */
    map_parse_non_1905_neighbor_device_list_tlv(ale, non_1905_neighbor_dev_tlvs, non_1905_neighbor_dev_tlvs_nr);

    /* Parse and update the connected clients
       - Assoc_clients_tlv is only mandatory when at least one client is connected
       - Before parsing, mark all stas.
       - After parsing, remove all sta that are still marked. Only remove sta that
         where connected for some time to avoid race between topology response
         and topology notification.
    */
    map_dm_mark_stas(ale);
    if (assoc_clients_tlv) {
        map_parse_assoc_clients_tlv(ale, assoc_clients_tlv);
    }
    map_dm_remove_marked_stas(ale, 30 /* seconds */);

    /* Handle emex tlvs */
    map_emex_handle_cmdu_pre(ale, cmdu);
    i1905_foreach_tlv_type_in_cmdu(TLV_TYPE_VENDOR_SPECIFIC, vendor_tlv, cmdu, tlv_idx) {
        if (map_emex_is_valid_tlv(vendor_tlv)) {
            map_emex_parse_tlv(ale, vendor_tlv);
            update_dm = true;
        }
    }
    map_emex_handle_cmdu_post(ale, cmdu);
    if (update_dm) {
        map_dm_ale_eth_update(ale);
    }

    /* Store the last received topology response message */
    ale->keep_alive_time = acu_get_timestamp_sec();

    return 0;
}

int map_handle_topology_discovery_ale(map_ale_info_t *ale, char *iface_name, uint8_t *src_mac_addr, uint8_t *mac_tlv_mac)
{
    /* Update the topology tree */
    if (0 == is_parent_of(get_root_ale_node(), ale)) {
        map_add_as_child_of_controller(ale);
    }

    /* Update the source mac of this frame */
    map_update_ale_source_mac(ale, src_mac_addr);

    /* Update the receiving interface name. */
    map_update_ale_receiving_iface(ale, iface_name);

    i1905_interface_info_t *info = i1905_get_interface_info(iface_name);

    /* Update information about upstream link */
    map_dm_ale_set_upstream_info(ale,
                                 /* upstream al mac     */ get_root_ale_node()->al_mac,
                                 /* local upstream mac  */ mac_tlv_mac,
                                 /* remote upstream mac */ info ? info->mac_address : NULL,
                                 false, 0);

    if (info) {
        i1905_free_interface_info(info);
    }

    return 0;
}

/* 1905.1 6.3.1 (type 0x0000) */
int map_handle_topology_discovery(i1905_cmdu_t *cmdu)
{
    i1905_al_mac_address_tlv_t *al_mac_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_AL_MAC_ADDRESS, cmdu); /* Mandatory */
    i1905_mac_address_tlv_t    *mac_tlv    = i1905_get_tlv_from_cmdu(TLV_TYPE_MAC_ADDRESS,    cmdu); /* Mandatory */
    map_ale_info_t             *ale;

    if (!al_mac_tlv || !mac_tlv) {
        return -1; /* Not possble - checked during validate */
    }

    /* Check if this is a new ale */
    if (!(ale = map_dm_get_ale(al_mac_tlv->al_mac_address))) {
        return handle_1905_dev(cmdu, true);
    }

    return map_handle_topology_discovery_ale(ale, cmdu->interface_name, cmdu->cmdu_stream.src_mac_addr, mac_tlv->mac_address);
}

/* 1905.1 6.3.2 (type 0x0001) */
int map_handle_topology_query(i1905_cmdu_t *cmdu)
{
    uint8_t        *src_mac = cmdu->cmdu_stream.src_mac_addr;
    map_ale_info_t *ale     = map_dm_get_ale_from_src_mac(src_mac);

    /* Answer to topology query also when device is not in DM.

       1905 standard requires to use AL_MAC as source MAC but
       in that case fallback to incoming source MAC
       (which might or might not be the same)
    */

    return map_send_topology_response(ale ? ale->al_mac : src_mac, cmdu);
}

/* 1905.1 6.3.3 (type 0x0002) */
int map_handle_topology_response(i1905_cmdu_t *cmdu)
{
    i1905_device_information_tlv_t *dev_info_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_DEVICE_INFORMATION, cmdu); /* Mandatory */
    map_supported_service_tlv_t    *ss_tlv       = i1905_get_tlv_from_cmdu(TLV_TYPE_SUPPORTED_SERVICE,  cmdu); /* Optional  */
    uint8_t                        *src_mac      = cmdu->cmdu_stream.src_mac_addr;
    map_ale_info_t                 *ale          = NULL;
    map_1905_dev_info_t            *dev          = NULL;
    mac_addr_str                    mac_str;
    bool                            ale_is_controller = false, ale_is_agent = false, ale_is_em_plus = false;

    if (!dev_info_tlv) {
        return -1; /* Not possible - checked during validate */
    }

    map_parse_ap_supported_service_tlv(NULL, ss_tlv, &ale_is_controller, &ale_is_agent, &ale_is_em_plus);

    if (NULL != (ale = map_dm_get_ale(dev_info_tlv->al_mac_address))) {
        return map_handle_topology_response_ale(ale, cmdu);
    }

    if (NULL != (dev = map_stglist_get_1905_dev(dev_info_tlv->al_mac_address))) {
        if (!(ale = map_handle_new_agent_onboarding(map_stglist_get_1905_dev_al_mac(dev), cmdu->interface_name, ale_is_em_plus))) {
            log_ctrl_e("%s: new agent onboarding failed", __FUNCTION__);
            return -1;
        }

        /* Update the source mac of this frame */
        map_update_ale_source_mac(ale, src_mac);

        if (map_stglist_is_1905_dev_rcvd_topo_discovery(dev)) {
            map_handle_topology_discovery_ale(ale, cmdu->interface_name, src_mac,
                                              map_stglist_get_1905_dev_mac_tlv_mac(dev));
        }

        map_stglist_remove_1905_dev(dev);

        return map_handle_topology_response_ale(ale, cmdu);
    }
    log_ctrl_w("%s: Failed to find (non-)EM device [%s]", __FUNCTION__, mac_to_string(src_mac, mac_str));
    return 0;
}

/* 1905.1 6.3.4 (type 0x0003) */
int map_handle_topology_notification(i1905_cmdu_t *cmdu)
{
    i1905_al_mac_address_tlv_t   *al_mac_tlv       = i1905_get_tlv_from_cmdu(TLV_TYPE_AL_MAC_ADDRESS,           cmdu); /* Mandatory */
    map_client_assoc_event_tlv_t *client_assoc_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_CLIENT_ASSOCIATION_EVENT, cmdu); /* Optional  */
    map_ale_info_t               *ale;

    if (!al_mac_tlv) {
        return -1; /* Not possble - checked during validate */
    }

    /* Check if this is a new ale */
    if (!(ale = map_dm_get_ale(al_mac_tlv->al_mac_address))) {
        return handle_1905_dev(cmdu, false);
    }

    /* Update the receiving interface name */
    map_update_ale_receiving_iface(ale, cmdu->interface_name);

    if (client_assoc_tlv) {
        map_parse_client_assoc_event_tlv(ale, client_assoc_tlv);
    } else {
        /* This is an empty topology notification, send Topology query to check what has changed */
        map_send_topology_query(ale, MID_NA);
    }

    return 0;
}

/* 1905.1 6.3.5 (type 0x0005) */
int map_handle_link_metrics_query(UNUSED map_ale_info_t *ale, UNUSED i1905_cmdu_t *cmdu)
{
    /* Controller currently does not answer to link metrics query.
       If we have to we can:
       - use the generic linux platform implementation in i1905 stack (not portable)
       - add a platform API which we do not want
       - replay what we received from the local agent
    */
    return 0;
}

/* 1905.1 6.3.6 (type 0x0006) */
int map_handle_link_metrics_response(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    array_list_t *link_metrics_list;
    void         *tlv;
    size_t        idx;


    if (!(link_metrics_list = new_array_list())) {
        log_ctrl_e("%s: failed to create array list", __FUNCTION__);
        return -1;
    }

    i1905_foreach_tlv_type_in_cmdu(TLV_TYPE_TRANSMITTER_LINK_METRIC, tlv, cmdu, idx) {
        map_parse_tx_link_metrics_tlv(tlv, link_metrics_list, &ale);
    }

    i1905_foreach_tlv_type_in_cmdu(TLV_TYPE_RECEIVER_LINK_METRIC, tlv, cmdu, idx) {
        map_parse_rx_link_metrics_tlv(tlv, link_metrics_list, &ale);
    }

    /* Remove the old metrics */
    map_remove_old_link_metrics(ale, link_metrics_list);

    while(list_get_size(link_metrics_list) > 0) {
        remove_last_object(link_metrics_list);
    }
    delete_array_list(link_metrics_list);

    return 0;
}

/* 1905.1 6.3.7 (type 0x0007) */
int map_handle_ap_autoconfig_search(i1905_cmdu_t *cmdu)
{
    i1905_al_mac_address_tlv_t  *al_mac_tlv  = i1905_get_tlv_from_cmdu(TLV_TYPE_AL_MAC_ADDRESS,  cmdu); /* Mandatory */
    map_multiap_profile_tlv_t   *profile_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_MULTIAP_PROFILE, cmdu); /* Optional  */
    map_supported_service_tlv_t *ss_tlv      = i1905_get_tlv_from_cmdu(TLV_TYPE_SUPPORTED_SERVICE, cmdu); /* Optional  */
    map_1905_dev_info_t         *dev;
    map_ale_info_t              *ale;
    mac_addr                     mac_tlv_mac;
    bool                         ale_is_controller = false, ale_is_agent = false, ale_is_em_plus = false;
    bool                         topo_discovery_is_rcvd = false;

    if (!al_mac_tlv) {
        return -1; /* Not possble - checked during validate */
    }

    map_parse_ap_supported_service_tlv(NULL, ss_tlv, &ale_is_controller, &ale_is_agent, &ale_is_em_plus);

    if (!ss_tlv) {
        /* non-EM 1905 device */
        if (map_dm_get_ale(al_mac_tlv->al_mac_address)) {
            return 0; /* Do nothing. It is a well behaving legacy 1905 dev */
        }
        return handle_1905_dev(cmdu, false);
    } else if (NULL != (dev = map_stglist_get_1905_dev(al_mac_tlv->al_mac_address))) {
        /* EM device is not added as ALE yet */
        topo_discovery_is_rcvd = map_stglist_is_1905_dev_rcvd_topo_discovery(dev);
        maccpy(mac_tlv_mac, map_stglist_get_1905_dev_mac_tlv_mac(dev));
        map_stglist_remove_1905_dev(dev);
    }


    if (!ale_is_agent) {
        goto response;
    }

    /* Check if this is a new ale */
    if (!(ale = map_dm_get_ale(al_mac_tlv->al_mac_address))) {
        if (!(ale = map_handle_new_agent_onboarding(al_mac_tlv->al_mac_address, cmdu->interface_name, ale_is_em_plus))) {
            log_ctrl_e("%s: new agent onboarding failed", __FUNCTION__);
            return -1;
        }
        if (topo_discovery_is_rcvd) {
            map_handle_topology_discovery_ale(ale, cmdu->interface_name, cmdu->cmdu_stream.src_mac_addr, mac_tlv_mac);
        }
    }

    if (profile_tlv) {
        map_parse_multiap_profile_tlv(ale, profile_tlv);
    }

    /* If agent, restart topology discovery to speed up discovery
       of controller by the agent (which might have been restarted).
    */
    map_restart_topology_discovery(cmdu->interface_name);

response:
    return map_send_autoconfig_response(cmdu, ale_is_agent);
}

/* 1905.1 6.3.9 (type 0x0009) */
int map_handle_ap_autoconfig_wsc(i1905_cmdu_t *cmdu)
{
    i1905_wsc_tlv_t              *wsc_tlv             = i1905_get_tlv_from_cmdu(TLV_TYPE_WSC,                         cmdu); /* Mandatory */
    map_ap_radio_basic_cap_tlv_t *ap_basic_cap_tlv    = i1905_get_tlv_from_cmdu(TLV_TYPE_AP_RADIO_BASIC_CAPABILITIES, cmdu); /* Mandatory */
    map_profile2_ap_cap_tlv_t    *profile2_ap_cap_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_PROFILE2_AP_CAPABILITY,      cmdu); /* Optional  */
    /* TODO: map_ap_radio_advanced_cap_tlv_t *adv_cap_tlv_t =  i1905_get_tlv_from_cmdu(TLV_TYPE_AP_RADIO_ADVANCED_CAPABILITIES, cmdu);*/ /* Optional */
    uint16_t                      mac_len;
    uint8_t                      *al_mac;
    map_ale_info_t               *ale;
    map_radio_info_t             *radio;

    if (!wsc_tlv || !ap_basic_cap_tlv) {
        return -1; /* Not possble - checked during validate */
    }

    if (!(al_mac = map_get_wsc_attr(wsc_tlv->wsc_frame, wsc_tlv->wsc_frame_size, WSC_ATTR_MAC_ADDR, &mac_len))) {
        return -1; /* Not possble - checked during validate */
    }

    /* Onboard agent if it is not known yet */
    if (!(ale = map_dm_get_ale(al_mac))) {
        if (!(ale = map_handle_new_agent_onboarding(al_mac, cmdu->interface_name, true))) {
            log_ctrl_e("%s: agent onboarding failed", __FUNCTION__);
            return -1;
        }
    }

    /* Get some attributes from wsc TLV */
    get_m1_attributes(ale, wsc_tlv->wsc_frame, wsc_tlv->wsc_frame_size);

    /* Parse profile 2 ap capabilties before onboarding new radio
       (impacts content of policy config reuqest and wsc response)
    */
    if (profile2_ap_cap_tlv) {
        map_parse_ap_cap_profile_2_tlv(ale, profile2_ap_cap_tlv);
    }

    /* Onboard radio if it is not known yet */
    if (!(radio = map_dm_get_radio(ale, ap_basic_cap_tlv->radio_id))) {
        if (!(radio = map_handle_new_radio_onboarding(ale, ap_basic_cap_tlv->radio_id, true))) {
            log_ctrl_e("%s: radio[%s] onboarding failed", __FUNCTION__, mac_string(ap_basic_cap_tlv->radio_id));
            return -1;
        }
    } else {
        /* Radio already known -> clear all the old data.  This will result in new
           policy config and queries.
           (queries happen from topology response).
           This is done as an M1 request might mean that the agent restarted.
        */
        refresh_radio_data(ale, radio);

        /* Extend the agent deletion by restarting topology query retry timer.
           This is done because for some agents (e.g BRCM) the reconfiguration
           takes very long and we don't want that the ALE gets deleted during
           that process
        */
        map_extend_ale_deletion(ale);
    }

    /* Parse ap basic capabilities */
    if (map_parse_ap_radio_basic_cap_tlv(ale, ap_basic_cap_tlv)) {
        log_ctrl_e("%s: radio parse_ap_basic_caps_tlv failed", __FUNCTION__);
        return -1;
    }

    set_radio_state_M1_receive(&radio->state);
    map_recompute_radio_state_and_update_ale_state(ale);

    /* Update caps and generate dm updates for this radio. */
    map_update_radio_caps(radio);
    map_dm_radio_set_capabilities(radio);

    if (map_send_autoconfig_wsc_m2(ale, radio, cmdu, MID_NA)) {
        log_ctrl_e("unable to send WSC M2 message");
        return -1;
    }

    /* Restart onboarding status check timer */
    map_start_onboarding_status_check_timer(ale);

    /* Send topology query to speed up onboarding process */
    map_send_topology_query(ale, MID_NA);

    return 0;
}

/* 1905.1 6.3.13 (type 0x0004) */
int map_handle_vendor_specific(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    /* Send 1905 Ack  */
    if (map_send_ack(ale, cmdu)) {
        log_ctrl_e("%s: map_send_ack failed", __FUNCTION__);
        return -1;
    }

    return 0;
}

/*#######################################################################
#                       MAP R1 CMDU HANDLERS                            #
########################################################################*/
/* MAP_R1 17.1 (type 0x8000) */
int map_handle_ack(UNUSED i1905_cmdu_t *cmdu)
{
    return 0;
}

/* MAP_R1 17.1.6 (type 0x8002) */
int map_handle_ap_capability_report(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    map_radio_info_t *radio;
    uint8_t          *tlv;
    size_t            idx;

    /* Remove existing ht/vht/he/wifi6 capabilities... */
    map_dm_foreach_radio(ale, radio) {
        map_free_ht_vht_he_wifi6_caps(radio);
    }

    /* ...and then first update them to avoid doing other stuff with those unknown */
    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_AP_HT_CAPABILITIES:
                map_parse_ap_ht_caps_tlv(ale, (map_ap_ht_cap_tlv_t *)tlv);
            break;
            case TLV_TYPE_AP_VHT_CAPABILITIES:
                map_parse_ap_vht_caps_tlv(ale, (map_ap_vht_cap_tlv_t *)tlv);
            break;
            case TLV_TYPE_AP_HE_CAPABILITIES:
                map_parse_ap_he_caps_tlv(ale, (map_ap_he_cap_tlv_t *)tlv);
            break;
            case TLV_TYPE_AP_WIFI6_CAPABILITIES:
                map_parse_ap_wifi6_cap_tlv(ale, (map_ap_wifi6_cap_tlv_t *)tlv);
            break;
            default:
            break;
        }
    }

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_AP_CAPABILITY:
                map_parse_ap_cap_tlv(ale, (map_ap_cap_tlv_t *)tlv);
                if (!is_ale_ap_cap_report_received(ale->state)) {
                    set_ale_state_ap_cap_report_received(&ale->state);
                }
            break;
            case TLV_TYPE_AP_RADIO_BASIC_CAPABILITIES: {
                map_ap_radio_basic_cap_tlv_t *cap_tlv = (map_ap_radio_basic_cap_tlv_t *)tlv;
                map_radio_info_t *radio               = map_dm_get_radio(ale, cap_tlv->radio_id);

                if (radio != NULL) {
                    map_parse_ap_radio_basic_cap_tlv(ale, cap_tlv);
                    if (!is_radio_ap_cap_report_received(radio->state)) {
                        set_radio_state_ap_cap_report_received(&radio->state);
                        map_recompute_radio_state_and_update_ale_state(radio->ale);
                    }
                }
                break;
            }
            case TLV_TYPE_CHANNEL_SCAN_CAPABILITIES:
                map_parse_channel_scan_cap_tlv(ale, (map_channel_scan_cap_tlv_t *)tlv);
            break;
            case TLV_TYPE_CAC_CAPABILITIES:
                map_parse_cac_cap_tlv(ale, (map_cac_cap_tlv_t *)tlv);
            break;
            case TLV_TYPE_PROFILE2_AP_CAPABILITY:
                map_parse_ap_cap_profile_2_tlv(ale, (map_profile2_ap_cap_tlv_t *)tlv);
            break;
            case TLV_TYPE_METRIC_COLLECTION_INTERVAL:
                map_parse_metric_collection_interval_tlv(ale, (map_metric_collection_interval_tlv_t *)tlv);
            break;
            case TLV_TYPE_DEVICE_INVENTORY:
                map_parse_device_inventory_tlv(ale, (map_device_inventory_tlv_t *)tlv);
            break;
            default:
            break;
        }
    }

    /* Update caps and generate dm updates for all radios. */
    map_dm_foreach_radio(ale, radio) {
        map_update_radio_caps(radio);
        /* TODO: check diffs but ok as this does not happen often */
        map_dm_radio_set_capabilities(radio);
    }

    return 0;
}

/* MAP_R1 17.1.10 (type 0x8005) */
int map_handle_channel_preference_report(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    map_radio_info_t *radio;
    uint8_t          *tlv;
    size_t            idx;

    /* Send 1905 Ack  */
    if (map_send_ack(ale, cmdu)) {
        log_ctrl_e("%s: map_send_ack failed", __FUNCTION__);
        return -1;
    }

    /* Remove existing preference for all radios */
    map_dm_foreach_radio(ale, radio) {
        SFREE(radio->pref_op_class_list.op_classes);
        SFREE(radio->op_restriction_list.op_classes);
        radio->pref_op_class_list.op_classes_nr  = 0;
        radio->op_restriction_list.op_classes_nr = 0;
    }

    /* Mark channel preference report as received for all radios
       (tlv can be omitted when it would contain 0 op_classes)
    */
    map_dm_foreach_radio(ale, radio) {
        set_radio_state_channel_pref_report_received(&radio->state);
    }

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_CHANNEL_PREFERENCE: {
                map_channel_preference_tlv_t *pref_tlv = (map_channel_preference_tlv_t *)tlv;

                if (map_parse_channel_preference_tlv(ale, pref_tlv) != 0) {
                    /* Parsing failed -> reset received state */
                    if ((radio = map_dm_get_radio(ale, pref_tlv->radio_id))) {
                        set_radio_state_channel_pref_report_not_received(&radio->state);
                    }
                }
                break;
            }
            case TLV_TYPE_RADIO_OPERATION_RESTRICTION:
                 map_parse_radio_operation_restriction_tlv(ale, (map_radio_operation_restriction_tlv_t *)tlv);
            break;
            case TLV_TYPE_CAC_COMPLETION_REPORT:
                map_parse_cac_completion_report_tlv(ale, (map_cac_completion_report_tlv_t *)tlv);
            break;
            case TLV_TYPE_CAC_STATUS_REPORT: {
                map_cac_status_report_tlv_t *cac_status_tlv = (map_cac_status_report_tlv_t *)tlv;
                map_parse_cac_status_report_tlv(ale, cac_status_tlv);
                break;
            }
            default:
            break;
        }
    }

    /* Update channel preference for all radios */
    map_dm_foreach_radio(ale, radio) {
        map_ctrl_chan_sel_update(radio);
    }

    return 0;
}

/* MAP_R1 17.1.12 (type 0x8007) */
int map_handle_channel_selection_response(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    map_channel_selection_response_tlv_t *tlv;
    size_t                                idx;

    i1905_foreach_tlv_type_in_cmdu(TLV_TYPE_CHANNEL_SELECTION_RESPONSE, tlv, cmdu, idx) {
       if (tlv->channel_selection_response == MAP_CHAN_SEL_RESPONSE_ACCEPTED) {
           log_ctrl_n("channel selection for radio[%s] completed", mac_string(tlv->radio_id));
       } else {
           log_ctrl_e("channel selection for radio[%s] failed. Reason[%d]",
                      mac_string(tlv->radio_id), tlv->channel_selection_response);

           /* TODO: If reason == 3 (rejected by BH STA) the requests keep failing.
                    Should add exp backoff or a maximum number of retries
           */
       }
    }

    return 0;
}

/* MAP_R1 17.1.13 (type 0x8008) */
int map_handle_operating_channel_report(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    map_operating_channel_report_tlv_t *tlv;
    map_radio_info_t                   *radio;
    size_t                              tlv_idx;

    /* Send 1905 Ack */
    if (map_send_ack(ale, cmdu)) {
        log_ctrl_e("%s: map_send_ack failed", __FUNCTION__);
        return -1;
    }

    i1905_foreach_tlv_type_in_cmdu(TLV_TYPE_OPERATING_CHANNEL_REPORT, tlv, cmdu, tlv_idx) {
        if (tlv->op_classes_nr > 0 && NULL != (radio = map_dm_get_radio(ale, tlv->radio_id))) {
            uint8_t idx = 0, min_bw_idx = 0, max_bw_idx = 0;
            uint16_t bw, min_bw = 320, max_bw = 20;

            SFREE(radio->curr_op_class_list.op_classes);
            if (!(radio->curr_op_class_list.op_classes = calloc(tlv->op_classes_nr, sizeof(map_op_class_t)))) {
                log_ctrl_e("%s: memory allocation failed", __FUNCTION__);
                radio->curr_op_class_list.op_classes_nr = 0;
                return -1;
            }
            radio->curr_op_class_list.op_classes_nr = tlv->op_classes_nr;

            for (idx = 0; idx < tlv->op_classes_nr; idx++) {
                map_op_class_t *op_class = &radio->curr_op_class_list.op_classes[idx];

                /* One channel per operating class, transmit power is common */
                op_class->op_class = tlv->op_classes[idx].op_class;
                op_class->eirp     = tlv->transmit_power_eirp;
                map_cs_set(&op_class->channels, tlv->op_classes[idx].channel);

                if (!map_get_bw_from_op_class(tlv->op_classes[idx].op_class, &bw)) {
                    if (bw < min_bw) {
                        min_bw = bw;
                        min_bw_idx = idx;
                    }
                    if (bw > max_bw) {
                        max_bw = bw;
                        max_bw_idx = idx;
                    }
                }
            }

            /* Update channel related parameters and current operating classes in DM
               - use op_class with the maximum bw to be able to get operating bw correctly
               - use op_class with the minimum bw to get control channel
            */
            map_dm_radio_set_channel(radio, tlv->op_classes[max_bw_idx].op_class,
                                     tlv->op_classes[min_bw_idx].channel,
                                     max_bw, tlv->transmit_power_eirp);

            log_ctrl_n("updated channel/bw for radio[%s] op_class[%d] channel[%d] bw[%d] from %s",
                       mac_string(radio->radio_id), radio->current_op_class, radio->current_op_channel, max_bw,
                       i1905_tlv_type_to_string(tlv->tlv_type));

            if (is_radio_operating_chan_report_received(radio->state) == 0 ) {
                set_radio_state_oper_chan_report_received(&radio->state);
                map_recompute_radio_state_and_update_ale_state(radio->ale);
            }
        }
    }

    return 0;
}

/* MAP_R1 17.1.15 (type 0x800A) */
int map_handle_client_capability_report(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    map_client_info_tlv_t       *client_info_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_CLIENT_INFO,              cmdu); /* Mandatory */
    map_client_cap_report_tlv_t *cap_report_tlv  = i1905_get_tlv_from_cmdu(TLV_TYPE_CLIENT_CAPABILITY_REPORT, cmdu); /* Mandatory */
    map_sta_info_t              *sta;

    if (!client_info_tlv || !cap_report_tlv) {
        return -1; /* Not possble - checked during validate */
    }

    if (!(sta = map_dm_get_sta_from_ale(ale, client_info_tlv->sta_mac))) {
        log_ctrl_e("handle[%s]: sta[%s] not found", i1905_cmdu_type_to_string(cmdu->message_type), mac_string(client_info_tlv->sta_mac));
        return 0;
    }

    if (cap_report_tlv->result_code == MAP_CLIENT_CAP_FAILURE) {
        log_ctrl_e("handle[%s]: sta[%s] result code failure", i1905_cmdu_type_to_string(cmdu->message_type), mac_string(client_info_tlv->sta_mac));
        return 0;
    }

    return parse_update_client_capability(sta, cap_report_tlv->assoc_frame_body_len, cap_report_tlv->assoc_frame_body);
}

/* MAP_R1 17.1.17 (type 0x800C) */
int map_handle_ap_metrics_response(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    map_radio_info_t *radio;
    map_bss_info_t   *bss;
    uint8_t          *tlv;
    size_t            idx;

    /* Invalidate some data */
    map_dm_foreach_radio(ale, radio) {
        radio->radio_metrics.valid = false;

        map_dm_foreach_bss(radio, bss) {
            bss->metrics.valid = false;
            bss->extended_metrics.valid = false;
        }
    }

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        switch (*tlv) {
            case TLV_TYPE_AP_METRICS:
                map_parse_ap_metrics_tlv(ale, (map_ap_metrics_tlv_t *)tlv);
            break;
            case TLV_TYPE_ASSOCIATED_STA_TRAFFIC_STATS:
                map_parse_assoc_sta_traffic_stats_tlv(ale, (map_assoc_sta_traffic_stats_tlv_t *)tlv);
            break;
            case TLV_TYPE_ASSOCIATED_STA_LINK_METRICS:
                map_parse_assoc_sta_link_metrics_tlv(ale, (map_assoc_sta_link_metrics_tlv_t *)tlv);
            break;
            case TLV_TYPE_RADIO_METRICS:
                map_parse_radio_metrics_tlv(ale, (map_radio_metrics_tlv_t*)tlv);
            break;
            case TLV_TYPE_AP_EXTENDED_METRICS:
                map_parse_ap_ext_metrics_response_tlv(ale, (map_ap_ext_metrics_tlv_t *)tlv);
            break;
            case TLV_TYPE_ASSOCIATED_STA_EXTENDED_LINK_METRICS:
                map_parse_assoc_sta_ext_link_metrics_tlv(ale, (map_assoc_sta_ext_link_metrics_tlv_t *)tlv);
            break;
            case TLV_TYPE_VENDOR_SPECIFIC: {
                i1905_vendor_specific_tlv_t *vs_tlv = (i1905_vendor_specific_tlv_t *)tlv;
                if (map_emex_is_valid_tlv(vs_tlv)) {
                    map_emex_parse_tlv(ale, vs_tlv);
                }
                break;
            }
            case TLV_TYPE_ASSOCIATED_WIFI6_STA_STATUS_REPORT:
                map_parse_assoc_wifi6_sta_status_tlv(ale, (map_assoc_wifi6_sta_status_tlv_t *)tlv);
                break;
            default:
            break;
        }
    }

    return 0;
}

/* MAP_R1 17.1.19 (type 0x800E) */
int map_handle_assoc_sta_link_metrics_response(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    map_error_code_tlv_t *error_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_ERROR_CODE, cmdu); /* Optional */
    void                 *tlv;
    size_t                idx;

    /* Check error code */
    if (error_tlv) {
        log_ctrl_e("error reason[%d] received in cmdu[%s] for sta[%s]", error_tlv->reason_code,
                   i1905_cmdu_type_to_string(cmdu->message_type), mac_string(error_tlv->sta_mac));
        return 0;
    }

    i1905_foreach_tlv_type_in_cmdu(TLV_TYPE_ASSOCIATED_STA_LINK_METRICS, tlv, cmdu, idx) {
        map_parse_assoc_sta_link_metrics_tlv(ale, tlv);
    }

    i1905_foreach_tlv_type_in_cmdu(TLV_TYPE_ASSOCIATED_STA_EXTENDED_LINK_METRICS, tlv, cmdu, idx) {
        map_parse_assoc_sta_ext_link_metrics_tlv(ale, tlv);
    }

    return 0;
}

/* MAP_R1 17.1.21 (type 0x8010) */
int map_handle_unassoc_sta_link_metrics_response(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    map_unassoc_sta_link_metrics_response_tlv_t *tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_UNASSOCIATED_STA_LINK_METRICS_RESPONSE, cmdu); /* Mandatory */
    map_unassoc_sta_link_metrics_response_tlv_t *dm_tlv;
    int i;

    if (!tlv) {
        return -1; /* Not possble - checked during validate */
    }

    /* Send 1905 ACK */
    if (map_send_ack(ale, cmdu)) {
        log_ctrl_e("%s: map_send_ack failed", __FUNCTION__);
        return -1;
    }

    /* update the unassoc metrics in data model */
    free(ale->unassoc_metrics);

    dm_tlv = malloc(sizeof(map_unassoc_sta_link_metrics_response_tlv_t) + (sizeof(map_unassoc_sta_link_metrics_response_tlv_sta_t) * tlv->stas_nr));
    if (dm_tlv == NULL) {
        log_ctrl_e("%s: unable to create unassoc metrics list", __FUNCTION__);
        return -1;
    }

    dm_tlv->op_class = tlv->op_class;
    dm_tlv->stas_nr  = tlv->stas_nr;

    for(i = 0; i < tlv->stas_nr; i++){
        maccpy(dm_tlv->stas[i].mac, tlv->stas[i].mac);
        dm_tlv->stas[i].channel     = tlv->stas[i].channel;
        dm_tlv->stas[i].time_delta  = tlv->stas[i].time_delta;
        dm_tlv->stas[i].rcpi_uplink = tlv->stas[i].rcpi_uplink;
    }

    ale->unassoc_metrics = dm_tlv;

    log_ctrl_d("Received Unassoc STA metrics Response");
    log_ctrl_d("=====================================");
    log_ctrl_d("-->op_class %d", tlv->op_class);
    log_ctrl_d("-->sta_cnt  %d", tlv->stas_nr);

    for (i = 0; i < tlv->stas_nr; i++){
        log_ctrl_d("------> sta_mac %s",        mac_string(tlv->stas[i].mac));
        log_ctrl_d("------> channel number %d", tlv->stas[i].channel);
        log_ctrl_d("------> time_delta     %d", tlv->stas[i].time_delta);
        log_ctrl_d("------> uplink rcpi    %d", tlv->stas[i].rcpi_uplink);
    }

    map_dm_ale_update_unassoc_sta_link_metrics(ale);

    return 0;
}

/* MAP_R1 17.1.23 (type 0x8012) */
int map_handle_beacon_metrics_response(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    map_beacon_metrics_response_tlv_t *tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_BEACON_METRICS_RESPONSE, cmdu); /* Mandatory */
    map_sta_info_t                    *sta;
    uint8_t                            i;

    if (!tlv) {
        return -1; /* Not possble - checked during validate */
    }

    /* Send 1905 ACK */
    if (map_send_ack(ale, cmdu)) {
        log_ctrl_e("%s: map_send_ack failed", __FUNCTION__);
        return -1;
    }

    if (!(sta = map_dm_get_sta_from_ale(ale, tlv->sta_mac))) {
        log_ctrl_e("%s: sta[%s] not found", __FUNCTION__, mac_string(tlv->sta_mac));
        return -1;
    }

    /* update the beacon metrics in data model */
    if (sta->beacon_metrics != NULL) {
        while (list_get_size(sta->beacon_metrics) > 0) {
            free(remove_last_object(sta->beacon_metrics));
        }
    }

    for (i = 0; i < tlv->elements_nr; i++) {
        map_beacon_metrics_response_tlv_element_t *element;
        map_sta_beacon_metrics_t                  *beacon_metrics;
        size_t                                     elem_len, subelem_len;

        /* Combine element with subelements into beacon metrics */
        element = &tlv->elements[i];
        beacon_metrics = calloc(1, element->length + 2);
        if (beacon_metrics == NULL) {
            /* Already created ones will be freed later */
            log_ctrl_e("%s: unable to create beacon metrics object", __FUNCTION__);
            return -1;
        }

        elem_len = MAP_BEACON_REPORT_ELEMENT_SIZE;
        subelem_len = element->length + 2 - elem_len;

        memcpy(beacon_metrics, element, elem_len);
        if (subelem_len) {
            uint8_t *bm = (uint8_t *)beacon_metrics + elem_len;
            memcpy(bm, element->subelements, subelem_len);
        }

        insert_last_object(sta->beacon_metrics, beacon_metrics);
    }

    sta->bmquery_status = tlv->status_code;
    map_dm_sta_beacon_metrics_completed(sta);

    return 0;
}

/* MAP_R1 17.1.26 (type 0x8015) */
int map_handle_client_steering_btm_report(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    map_steering_btm_report_tlv_t *tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_STEERING_BTM_REPORT, cmdu); /* Mandatory */
    map_sta_info_t                *sta = NULL;

    if (!tlv) {
        return -1; /* Not possible - checked during validate */
    }

    /* Send 1905 ACK */
    if (map_send_ack(ale, cmdu)) {
        log_ctrl_e("%s: map_send_ack failed", __FUNCTION__);
        return -1;
    }

    if (!(sta = map_dm_get_sta_from_ale(ale, tlv->sta_mac))) {
        log_ctrl_e("%s: sta[%s] not found", __FUNCTION__, mac_string(tlv->sta_mac));
        return -1;
    }

    map_dm_sta_steering_btm_report(sta, tlv->btm_status_code, (tlv->target_bssid_present ? tlv->target_bssid : NULL));

    return 0;
}

/* MAP_R1 17.1.28 (type 0x8017) */
int map_handle_steering_completed(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    /* Send 1905 ACK */
    if (map_send_ack(ale, cmdu)) {
        log_ctrl_e("%s: map_send_ack failed", __FUNCTION__);
        return -1;
    }

    map_dm_sta_steering_completed(ale);

    return 0;
}

/* MAP_R1 17.1.30 (type 0x801A) */
int map_handle_backhaul_steering_response(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    /* Send 1905 Ack  */
    if (map_send_ack(ale, cmdu)) {
        log_ctrl_e("%s: map_send_ack failed", __FUNCTION__);
        return -1;
    }

    return 0;
}

/* MAP_R1 17.1.31 (type 0x8018) */
int map_handle_higher_layer_data(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    map_higher_layer_data_tlv_t *tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_HIGHER_LAYER_DATA, cmdu); /* Mandatory */

    if (!tlv) {
        return -1; /* Not possible - checked during validate */
    }

    /* Send 1905 Ack  */
    if (map_send_ack(ale, cmdu)) {
        log_ctrl_e("%s: map_send_ack failed", __FUNCTION__);
        return -1;
    }

    log_ctrl_i("received higher layer data from ale[%s] protocol[%d] payload_len[%d]",
               mac_string(ale->al_mac), tlv->protocol, tlv->payload_len);

    return 0;
}

/*#######################################################################
#                       MAP R2 CMDU HANDLERS                            #
########################################################################*/
/* MAP_R2 17.1.34 (type 0x801C) */
int map_handle_channel_scan_report(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    map_timestamp_tlv_t *ts_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_TIMESTAMP, cmdu); /* Mandatory */
    map_radio_info_t    *radio;

    if (!ts_tlv) {
        return -1; /* Not possble - checked during validate */
    }

    map_parse_timestamp_tlv(ale, ts_tlv);

    /* Process results for each radio */
    map_dm_foreach_radio(ale, radio) {
        map_scan_info_t               *scan_info  = &radio->last_scan_info;
        bool                           first      = true;
        bool                           need_retry = false;
        map_channel_scan_result_tlv_t *scan_results_tlv;
        size_t                         idx;

        i1905_foreach_tlv_type_in_cmdu(TLV_TYPE_CHANNEL_SCAN_RESULT, scan_results_tlv, cmdu, idx) {
            if (radio != map_dm_get_radio(ale, scan_results_tlv->radio_id)) {
                continue;
            }

            if (first) {
                /* increment scan counter once for each CMDU */
                scan_info->last_scan_cnt++;
                scan_info->ts_len = ts_tlv->timestamp_len;
                memcpy(scan_info->last_scan_ts, ts_tlv->timestamp, scan_info->ts_len);
                first = false;
            }

            map_parse_channel_scan_result_tlv(ale, scan_results_tlv, scan_info->last_scan_cnt);

            /* Mark failed scan status (retry needed) */
            switch(scan_results_tlv->scan_status) {
                case MAP_SCAN_STATUS_TOO_SOON:
                case MAP_SCAN_STATUS_BUSY:
                case MAP_SCAN_STATUS_NOT_COMPLETED:
                case MAP_SCAN_STATUS_ABORTED:
                    need_retry = true;
                break;
                default:
                    /* Other values will fail again on retry. */
                break;
            }
        }

        if (!first) {
            scan_info->last_scan_status_failed = need_retry;
            if (!is_radio_initial_scan_results_received(radio->state) && !need_retry) {
                set_radio_state_initial_scan_results_received(&radio->state);
            }

            map_dm_radio_scan_result(radio);
        }
    }

    /* Send 1905 Ack  */
    if (map_send_ack(ale, cmdu)) {
        log_ctrl_e("%s: map_send_ack failed", __FUNCTION__);
        return -1;
    }

    return 0;
}

/* MAP_R2 17.1.39 (type 0x8025) */
int map_handle_assoc_status_notification(UNUSED map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    map_assoc_status_notification_tlv_t *tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_ASSOCIATION_STATUS_NOTIFICATION, cmdu); /* Mandatory */

    if (!tlv) {
        return -1; /* Not possble - checked during validate */
    }

    map_parse_assoc_status_notification_tlv(ale, tlv);

    return 0;
}

/* MAP_R2 17.1.40 (type 0x8026) */
static int update_tunneled_message(map_ale_info_t *ale, map_tunneled_tlv_t *tunneled_tlv, mac_addr src_mac, uint8_t msg_type)
{
    map_sta_info_t      *sta      = map_dm_get_sta_from_ale(ale, src_mac);
    map_tunneled_msg_t  *tm       = NULL;
    uint8_t            **body     = NULL;
    uint16_t            *body_len = NULL;

    if (!sta) {
        log_ctrl_i("%s: ale[%s] type[%d]: sta[%s] not found", __FUNCTION__, ale->al_mac_str, msg_type, mac_string(src_mac));
        goto fail;
    }

    if (!sta->tunneled_msg && !(sta->tunneled_msg = calloc(1, sizeof(map_tunneled_msg_t)))) {
        log_ctrl_e("%s: could not allocated tunneled msg", __FUNCTION__);
        goto fail;
    }
    tm = sta->tunneled_msg;

    switch (msg_type) {
        case TUNNELED_MSG_PAYLOAD_ASSOC_REQ:
            body     = &tm->assoc_req_body;
            body_len = &tm->assoc_req_body_len;
        break;
        case TUNNELED_MSG_PAYLOAD_REASSOC_REQ:
            body     = &tm->reassoc_req_body;
            body_len = &tm->reassoc_req_body_len;
        break;
        case TUNNELED_MSG_PAYLOAD_BTM_QUERY:
            body     = &tm->btm_query_body;
            body_len = &tm->btm_query_body_len;
        break;
        case TUNNELED_MSG_PAYLOAD_WNM_REQ:
            body     = &tm->wnm_req_body;
            body_len = &tm->wnm_req_body_len;
        break;
        case TUNNELED_MSG_PAYLOAD_ANQP_REQ:
            body     = &tm->anqp_req_body;
            body_len = &tm->anqp_req_body_len;
        break;
        default:
            log_ctrl_e("%s: unexpected tunneled message type[%d]", __FUNCTION__, msg_type);
            goto fail;
        break;
    }

    /* Replace body */
    free(*body);
    if (!(*body = malloc(tunneled_tlv->frame_body_len))) {
        log_ctrl_e("%s: could not allocated tunneled msg body", __FUNCTION__);
        *body_len = 0;
        goto fail;
    }
    memcpy(*body, tunneled_tlv->frame_body, tunneled_tlv->frame_body_len);
    *body_len = tunneled_tlv->frame_body_len;
    return 0;
fail:
    return -1;
}

int map_handle_tunneled_msg(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    map_source_info_tlv_t           *source_info_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_SOURCE_INFO,           cmdu); /* Mandatory */
    map_tunneled_message_type_tlv_t *msg_type_tlv    = i1905_get_tlv_from_cmdu(TLV_TYPE_TUNNELED_MESSAGE_TYPE, cmdu); /* Mandatory */
    map_tunneled_tlv_t              *tunneled_tlv;
    size_t                           idx;

    if (!source_info_tlv || !msg_type_tlv) {
        return -1; /* Not possble - checked during validate */
    }

    /* Send 1905 ACK */
    if (map_send_ack(ale, cmdu)) {
        log_ctrl_e("%s: map_send_ack failed", __FUNCTION__);
        return -1;
    }

    /* There can be one or more tunneled tlv */
    i1905_foreach_tlv_type_in_cmdu(TLV_TYPE_TUNNELED, tunneled_tlv, cmdu, idx) {
        update_tunneled_message(ale, tunneled_tlv, source_info_tlv->src_mac, msg_type_tlv->message_type);
    }

    return 0;
}

/* MAP_R2 17.1.41 (type 0x8022) */
int map_handle_client_disassoc_stats(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    map_assoc_sta_traffic_stats_tlv_t *stats_tlv  = i1905_get_tlv_from_cmdu(TLV_TYPE_ASSOCIATED_STA_TRAFFIC_STATS, cmdu); /* Mandatory */
    map_reason_code_tlv_t             *reason_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_REASON_CODE,                  cmdu); /* Mandatory */
    map_sta_info_t                    *sta;

    if (!stats_tlv || !reason_tlv) {
        return -1; /* Not possble - checked during validate */
    }

    if(!(sta = map_dm_get_sta_from_ale(ale, stats_tlv->sta_mac))) {
        log_ctrl_e("%s: sta[%s] not found", __FUNCTION__, mac_string(stats_tlv->sta_mac));
        return -1;
    }

    /* update reason code of disassociated STA in data model */
    sta->last_disassoc_reason_code = reason_tlv->reason_code;

    log_ctrl_n("--------------------------");
    log_ctrl_n("client is disassociated");
    log_ctrl_n("reason code: 0x%02x", reason_tlv->reason_code);
    log_ctrl_n("sta mac:     %s",     mac_string(sta->mac));
    log_ctrl_n("ale mac:     %s",     mac_string(ale->al_mac));
    log_ctrl_i("radio id:    %s",     mac_string(sta->bss->radio->radio_id));
    log_ctrl_i("bssid:       %s",     mac_string(sta->bss->bssid));
    log_ctrl_n("--------------------------");

    return 0;
}

/* MAP_R2 17.1.43 (type 0x8028) */
int map_handle_backhaul_sta_capability_report(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    map_backhaul_sta_radio_cap_tlv_t *bhsta_radio_cap_tlv = NULL;
    map_backhaul_sta_radio_cap_tlv_t *bhsta_radio_cap_tlvs[MAX_RADIO_PER_AGENT] = {NULL};
    uint8_t                           bhsta_radio_cap_tlvs_nr = 0, tlv_idx = 0;

    /* Get all bhsta radio capability tlvs */
    i1905_foreach_tlv_type_in_cmdu(TLV_TYPE_BACKHAUL_STA_RADIO_CAPABILITIES, bhsta_radio_cap_tlv, cmdu, tlv_idx) {
        if (bhsta_radio_cap_tlvs_nr < MAX_RADIO_PER_AGENT) {
            bhsta_radio_cap_tlvs[bhsta_radio_cap_tlvs_nr++] = bhsta_radio_cap_tlv;
        }
    }

    if (!map_parse_backhaul_sta_radio_capability_tlv(ale, bhsta_radio_cap_tlvs, bhsta_radio_cap_tlvs_nr)) {
        set_ale_state_bhsta_cap_report_received(&ale->state);
    }

    return 0;
}

/* MAP_R2 17.1.44 (type 0x8033) */
int map_handle_failed_connection(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    (void) ale;
    map_bssid_tlv_t           *bssid_tlv   = i1905_get_tlv_from_cmdu(TLV_TYPE_BSSID,           cmdu); /* Included in EM R3, keep optional. */
    map_sta_mac_address_tlv_t *sta_mac_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_STA_MAC_ADDRESS, cmdu); /* Mandatory */
    map_status_code_tlv_t     *status_tlv  = i1905_get_tlv_from_cmdu(TLV_TYPE_STATUS_CODE,     cmdu); /* Mandatory */
    map_reason_code_tlv_t     *reason_tlv  = i1905_get_tlv_from_cmdu(TLV_TYPE_REASON_CODE,     cmdu); /* Optional  */

    if (!sta_mac_tlv || !status_tlv) {
        return -1; /* Not possible - checked during validate */
    }

    log_ctrl_d("--------------------------");
    log_ctrl_d("client has failed connection attempt.");
    log_ctrl_d("status code:    0x%02x", status_tlv->status_code);
    if (reason_tlv) {
        log_ctrl_d("reason code: 0x%02x", reason_tlv->reason_code);
    }
    log_ctrl_d("sta mac:    %s", mac_string(sta_mac_tlv->sta_mac));
    if (bssid_tlv) {
        log_ctrl_d("bssid:      %s", mac_string(bssid_tlv->bssid));
    }
    log_ctrl_d("--------------------------");

    map_dm_create_failconn(sta_mac_tlv->sta_mac, bssid_tlv ? bssid_tlv->bssid : NULL,
        status_tlv->status_code, reason_tlv ? reason_tlv->reason_code : 0);

    return 0;
}

/*#######################################################################
#                       MAP R3 CMDU HANDLERS                            #
########################################################################*/
/* MAP_R3 17.1.48 (type 0x8029) */
int map_handle_proxied_encap_dpp(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    map_1905_encap_dpp_tlv_t  *encap_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_1905_ENCAP_DPP,  cmdu); /* Mandatory */
    map_dpp_chirp_value_tlv_t *chirp_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_DPP_CHIRP_VALUE, cmdu); /* Optional  */

    if (!encap_tlv) {
        log_ctrl_e("Cannot get a valid 1905 Encap DPP TLV!");
        return -1;
    }

    if (chirp_tlv) {
        map_parse_dpp_chirp_value_tlv(ale, chirp_tlv);
    }

    return map_parse_1905_encap_dpp_tlv(ale, encap_tlv);
}

/* MAP_R3 17.1.49 (type 0x8030) */
int map_handle_1905_encap_eapol(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    map_1905_encap_eapol_tlv_t  *eapol_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_1905_ENCAP_EAPOL,  cmdu); /* Mandatory */

    if (!eapol_tlv) {
        log_ctrl_e("Cannot get a valid 1905 Encap EAPOL TLV!");
        return -1;
    }

    return map_parse_1905_encap_eapol_tlv(ale, eapol_tlv);
}

/* MAP_R3 17.1.52 (type 0x802f) */
int map_handle_chirp_notification(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    map_dpp_chirp_value_tlv_t *chirp_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_DPP_CHIRP_VALUE, cmdu); /* Mandatory */

    if (!chirp_tlv) {
        log_ctrl_e("Cannot get a valid DPP Chirp Value TLV!");
        return -1;
    }

    return map_parse_dpp_chirp_value_tlv(ale, chirp_tlv);
}

/* MAP_R3 17.1.56 (type 0x802a) */
int map_handle_direct_encap_dpp(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    map_dpp_message_tlv_t  *dpp_message_tlv = i1905_get_tlv_from_cmdu(TLV_TYPE_DPP_MESSAGE,  cmdu); /* Mandatory */

    if (!dpp_message_tlv) {
        log_ctrl_e("Cannot get a valid DPP Message TLV!");
        return -1;
    }

    return map_parse_dpp_message_tlv(ale, dpp_message_tlv);
}
