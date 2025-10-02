/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <arpa/inet.h>

#define LOG_TAG "emex"

#include "map_ctrl_emex_tlv_handler.h"
#include "map_tlvs.h"
#include "map_ctrl_utils.h"
#include "map_ctrl_topology_tree.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define MAX_EMEX_FEATURE_COUNT  16
#define VITAL_EVENT_PERIOD      30

#define max(a, b) ((a) > (b) ? (a) : (b))

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static map_emex_common_feature_list_t g_common_feature_list;

/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
map_emex_common_feature_list_t *controller_get_emex_common_feature_list(void)
{
    return &g_common_feature_list;
}

static int8_t map_emex_calculate_common_feature_list(void)
{
    map_ale_info_t *ale_info;
    uint16_t common_feature_count = 0;
    uint16_t i, j;

    /* Temporary array to manipulate */
    map_emex_supported_feature_t common_feature_list[MAX_EMEX_FEATURE_COUNT] = {{0}};

    /* Clear previous common feature list */
    controller_get_emex_common_feature_list()->feature_count = 0;
    SFREE(controller_get_emex_common_feature_list()->feature_list);

    map_dm_foreach_agent_ale(ale_info) {
        /* Do not calculate third party agents */
#ifndef UNIT_TEST
        if (!ale_info->easymesh_plus) {
            continue;
        }
#endif
        if (ale_info->emex.feature_profile.feature_count > 0) {

            /* If common feature list is not calculated before, pick first ale's list as common feature list. */
            if (common_feature_count == 0) {
                for (i = 0; i < ale_info->emex.feature_profile.feature_count; i++) {
                    common_feature_list[i].id = ale_info->emex.feature_profile.feature_list[i].id;
                    common_feature_list[i].version = ale_info->emex.feature_profile.feature_list[i].version;
                }
                common_feature_count = ale_info->emex.feature_profile.feature_count;
                continue;
            }

            /* Check common features that is not exist in incoming ALE's feature list. Remove from common list if it is not exist. */
            for (i = 0; i < common_feature_count; i++) {
                bool found = false;

                /* Search for feature existency */
                for (j = 0; j < ale_info->emex.feature_profile.feature_count; j++) {
                        if (common_feature_list[i].id == ale_info->emex.feature_profile.feature_list[j].id) {
                            if (common_feature_list[i].version > ale_info->emex.feature_profile.feature_list[j].version) {
                                /* ALE has an older version of this feature. Use older version for feature list. */
                                common_feature_list[i].version = ale_info->emex.feature_profile.feature_list[j].version;
                            }
                            found = true;
                            break;
                        }
                }

                /* Remove if it is not exist in upcoming ale */
                if (found == false) {
                    /* Shift all elements and reduce feature list size */
                    for (j=i; j<common_feature_count; j++) {
                        common_feature_list[j].id = common_feature_list[j+1].id;
                        common_feature_list[j].version = common_feature_list[j+1].version;
                    }
                    common_feature_list[common_feature_count - 1].id = 0;
                    common_feature_list[common_feature_count - 1].version = 0;
                    common_feature_count--;
                    i--;
                }
            }
        }
    }

    controller_get_emex_common_feature_list()->feature_count = common_feature_count;
    controller_get_emex_common_feature_list()->feature_list = calloc(1,
                                common_feature_count * sizeof(map_emex_supported_feature_t));
    if (controller_get_emex_common_feature_list()->feature_list == NULL) {
        log_ctrl_e("Cannot allocate memory!");
        return 0;
    }

    for (i = 0; i < common_feature_count; i++) {
        controller_get_emex_common_feature_list()->feature_list[i].id = common_feature_list[i].id;
        controller_get_emex_common_feature_list()->feature_list[i].version = common_feature_list[i].version;
    }

    return 1;
}

static int8_t parse_emex_feature_profile(struct vendorSpecificTLV* vendor_tlv, map_ale_info_t *ale, bool *changed)
{
    int i;
    int8_t ret = 0;

    do {
        /* TLV len: emex_tlv_id(2) + agent_version(4) + feature_count(2) */
        unsigned short min_tlv_len = 2 + 4 + 2;
        if (vendor_tlv->m_nr < min_tlv_len) {
            log_ctrl_e("Minimal TLV size check failed!");
            break;
        }
        if (ale == NULL) {
            log_ctrl_e("ale is not exist");
            break;
        }

        /* Iterate 2-byte AirTies EM+ TLV ID to get payload data. */
        uint8_t *data = vendor_tlv->m + sizeof(uint16_t);
        uint8_t *buf = data;
        map_emex_feature_profile_t *fp = &ale->emex.feature_profile;
        uint16_t feature_count;

        _E4B(&buf, &fp->agent_version);
        _E2B(&buf, &feature_count);

        /* Compare incoming variable payload size and calculated one. */
        if (vendor_tlv->m_nr != min_tlv_len +
            feature_count * sizeof(map_emex_supported_feature_t)) {
            log_ctrl_e("Size mismatch on payload!");
            break;
        }

        /* Feature indication will show that we have extensions on board. */
        ale->emex.enabled = true;

        /* Allocate feature list if feature count has changed. */
        if (feature_count != fp->feature_count) {
            *changed = true;
            SFREE(fp->feature_list);
            fp->feature_count = feature_count;
            /* Check incoming feature size and break if 0. */
            if (feature_count == 0) {
                log_ctrl_w("No incoming feature list.");
                /* EM+ spec notation: k >= 0 */
                ret = 1;
                break;
            }
            fp->feature_list = calloc(feature_count,
                sizeof(map_emex_supported_feature_t));
            if (fp->feature_list == NULL) {
                log_ctrl_e("Cannot allocate memory!");
                break;
            }
        }

        /* Store incoming agent feature id and version. */
        for (i = 0; i < feature_count; i++) {
            _E2B(&buf, &fp->feature_list[i].id);
            _E2B(&buf, &fp->feature_list[i].version);
        }

        ret = 1;
    } while (0);

    return ret;
}

static int8_t parse_emex_device_info(struct vendorSpecificTLV* vendor_tlv, map_ale_info_t *ale)
{
    int8_t ret = 0;

    do {
        /* TLV len: emex_tlv_id(2) + boot_id(4) + clientid_len(1) + clientsec_len(1) + product(1) + role(1) */
        unsigned short min_tlv_len = 2 + 4 + 1 + 1 + 1 + 1;
        if (vendor_tlv->m_nr < min_tlv_len) {
            log_ctrl_e("Minimal TLV size check failed!");
            break;
        }
        if (ale == NULL) {
            log_ctrl_e("ale is not exist");
            break;
        }

        /* Iterate 2-byte AirTies EM+ TLV ID to get payload data. */
        uint8_t *data = vendor_tlv->m + sizeof(uint16_t);
        uint8_t *buf = data;
        map_emex_device_info_t *di = &ale->emex.device_info;

        _E4B(&buf, &di->boot_id);
        _E1B(&buf, &di->client_id_len);

        /* Check buffer over flow before fetching client id:
         * Diff between iterated (buf) and base address of the data + client id len
         */
        if (vendor_tlv->m_nr <= (buf - data) + di->client_id_len) {
            log_ctrl_e("Possible buffer overflow before getting client ID!");
            break;
        }
        _EnB(&buf, di->client_id, di->client_id_len);
        _E1B(&buf, &di->client_secret_len);

        /* Check exact buffer size after gathering all variable length elements */
        if (vendor_tlv->m_nr != min_tlv_len + di->client_id_len + di->client_secret_len) {
            log_ctrl_e("Size mismatch on payload!");
            break;
        }
        _EnB(&buf, di->client_secret, di->client_secret_len);
        _E1B(&buf, &di->product_class);
        _E1B(&buf, &di->device_role);
        di->received = true;

        ret = 1;
    } while (0);

    return ret;
}

static int8_t parse_emex_device_metrics(struct vendorSpecificTLV* vendor_tlv, map_ale_info_t *ale)
{
    int i;
    int8_t ret = 0;

    do {
        /* TLV len: emex_tlv_id(2) + uptime(4) + cpu_load(1) + cpu_temp(1) + mem_total(4) +
         * mem_free(4) + mem_cached(4) + radio_count(1)
         */
        unsigned short min_tlv_len = 2 + 4 + 1 + 1 + 4 + 4 + 4 + 1;
        if (vendor_tlv->m_nr < min_tlv_len) {
            log_ctrl_e("Minimal TLV size check failed!");
            break;
        }
        if (ale == NULL) {
            log_ctrl_e("ale is not exist");
            break;
        }

        /* Iterate 2-byte AirTies EM+ TLV ID to get payload data. */
        uint8_t *data = vendor_tlv->m + sizeof(uint16_t);
        uint8_t *buf = data;
        map_emex_device_metrics_t *dm = &ale->emex.device_metrics;
        map_emex_radios_t *radios = &ale->emex.radios;
        uint8_t radio_count;

        _E4B(&buf, &dm->uptime);
        _E1B(&buf, &dm->cpu_load);
        _E1B(&buf, &dm->cpu_temp);
        _E4B(&buf, &dm->mem_total);
        _E4B(&buf, &dm->mem_free);
        _E4B(&buf, &dm->mem_cached);
        _E1B(&buf, &radio_count);

        /* Compare incoming variable payload size and calculated one. */
        if (vendor_tlv->m_nr != min_tlv_len +
            radio_count * sizeof(map_emex_radio_info_t)) {
            log_ctrl_e("Size mismatch on payload!");
            break;
        }

        /* Allocate radio info array if radio count has changed. */
        if (radio_count != radios->count) {
            SFREE(radios->info);
            radios->count = radio_count;
            /* Check incoming radio size and break if 0. */
            if (radio_count == 0) {
                /* EM+ spec notation: k >= 1 */
                log_ctrl_e("No incoming radio list.");
                break;
            }
            radios->info = calloc(radio_count,
                sizeof(map_emex_radio_info_t));
            if (radios->info == NULL) {
                log_ctrl_e("Cannot allocate memory!");
                break;
            }
        }

        /* Store incoming radio info : mac + temperature. */
        for (i = 0; i < radio_count; i++) {
            _EnB(&buf, radios->info[i].id, 6);
            _E1B(&buf, &radios->info[i].temp);
        }

        ret = 1;
    } while (0);

    return ret;
}

static uint16_t eth_link_type_to_speed(uint8_t link_type)
{
    switch(link_type) {
        case EMEX_ETH_LINK_TYPE_10MBPS:    return 10;
        case EMEX_ETH_LINK_TYPE_100MBPS:   return 100;
        case EMEX_ETH_LINK_TYPE_1000MBPS:  return 1000;
        case EMEX_ETH_LINK_TYPE_2500MBPS:  return 2500;
        case EMEX_ETH_LINK_TYPE_5000MBPS:  return 5000;
        case EMEX_ETH_LINK_TYPE_10000MBPS: return 10000;
        default:                           return 0;
    }
}

static int parse_emex_eth_interfaces(i1905_vendor_specific_tlv_t *vendor_tlv, map_ale_info_t *ale)
{
    map_emex_eth_iface_list_t *list = &ale->emex.eth_iface_list;
    int err = -EINVAL;
    uint16_t tlv_id;
    uint8_t iface_nr, name_len, flags, link_type;
    uint8_t *p = vendor_tlv->m;
    uint8_t *end = p + vendor_tlv->m_nr;
    size_t i;

    if ((end - p) < (/* tlv_id */ 2 + /* iface_nr */ 1)) {
        goto out;
    }

    _E2B(&p, &tlv_id);
    _E1B(&p, &iface_nr);

    if (iface_nr != list->iface_nr) {
        /* TODO: this will reset stats and devices also - assumption is that iface_nr will not change... */
        map_emex_eth_iface_t *new_ifaces = calloc(iface_nr, sizeof(*new_ifaces));
        if (!new_ifaces) {
            err = -ENOMEM;
            goto out;
        }
        map_dm_free_emex_eth_iface_list(ale);
        free(list->ifaces);
        list->ifaces = new_ifaces;
        list->iface_nr = iface_nr;
    }

    /* TODO: The code below assumes that the order of interfaces in the TLV remains the same.
             If not, the stats and devices should also be moved
    */
    for (i = 0; i < iface_nr; i++) {
        map_emex_eth_iface_t *iface = &list->ifaces[i];

        if ((end - p) < (/* port_id */ 1 + /* mac */ 6 + /* name_len */ 1)) {
            goto out;
        }
        _E1B(&p, &iface->port_id);
        _EnB(&p, iface->mac, sizeof(mac_addr));

        _E1B(&p, &name_len);
        if ((end - p) < (name_len + /* flags */ 1 + /* link_type */ 1)) {
            goto out;
        }
        _EnB(&p, iface->name, name_len);
        iface->name[name_len] = 0;

        _E1B(&p, &flags);
        iface->admin_state = (flags & 0x80) ? 1 : 0;
        iface->oper_state  = (flags & 0x40) ? 1 : 0;
        iface->full_duplex = (flags & 0x20) ? 1 : 0;

        _E1B(&p, &link_type);
        iface->supported_link_type  = (link_type >> 4) & 0x0f;
        iface->link_type            = link_type & 0x0f;
        iface->supported_link_speed = eth_link_type_to_speed(iface->supported_link_type);
        iface->link_speed           = eth_link_type_to_speed(iface->link_type);
    }

    err = 0;

out:
    if (err) {
        if (err == -EINVAL) {
            log_ctrl_e("received invalid eth interfaces TLV from ale[%s]", ale->al_mac_str);
        }
        map_dm_free_emex_eth_iface_list(ale);
    }

    /* These functions need to return 1 on success */
    return err == 0 ? 1 : 0;
}

static inline uint64_t ucast_stat(uint64_t tot, uint64_t bmc)
{
    return (tot > bmc) ? (tot - bmc) : 0;
}

static int parse_emex_eth_stats_v2(i1905_vendor_specific_tlv_t *vendor_tlv, map_ale_info_t *ale)
{
    map_emex_eth_iface_list_t *list = &ale->emex.eth_iface_list;
    int err = -EINVAL;
    uint16_t tlv_id, smask;
    uint8_t iface_nr, stats_nr, port_id;
    uint8_t *p = vendor_tlv->m;
    uint8_t *end = p + vendor_tlv->m_nr;
    size_t i, j;

    if ((end - p) < (/* tlv_id */ 2 + /* supp_stats_mask */ 2 + /* iface_nr */ 1)) {
        goto out;
    }

    _E2B(&p, &tlv_id);
    _E2B(&p, &list->supported_stats_mask);
    _E1B(&p, &iface_nr);

    smask = list->supported_stats_mask;
    stats_nr = /* required */ 6 + /* optional */ map_count_bits_16(smask);

    for (i = 0; i < iface_nr; i++) {
        map_emex_eth_stats_t *s = NULL;

        if ((end - p) < (/* port_id */ 1 + /* N 48 bit stats */ stats_nr * 6)) {
            goto out;
        }

        _E1B(&p, &port_id);

        /* Find port_id */
        for (j = 0; j < list->iface_nr; j++) {
            if (list->ifaces[j].port_id == port_id) {
                s = &list->ifaces[j].stats;
                break;
            }
        }

        if (s) {
            uint8_t *q = p;

            memset(s, 0, sizeof(*s));
            _E6B(&q, &s->tx_bytes); s->tx_bytes <<= 10;
            _E6B(&q, &s->rx_bytes); s->rx_bytes <<= 10;
            _E6B(&q, &s->tx_packets);
            _E6B(&q, &s->rx_packets);
            _E6B(&q, &s->tx_errors);
            _E6B(&q, &s->rx_errors);

            if (smask & EMEX_ETH_STATS_HAS_TX_BCAST_BYTES) {
                _E6B(&q, &s->tx_bcast_bytes); s->tx_bcast_bytes <<= 10;
            }
            if (smask & EMEX_ETH_STATS_HAS_RX_BCAST_BYTES) {
                _E6B(&q, &s->rx_bcast_bytes); s->rx_bcast_bytes <<= 10;
            }
            if (smask & EMEX_ETH_STATS_HAS_TX_BCAST_PACKETS) {
                _E6B(&q, &s->tx_bcast_packets);
            }
            if (smask & EMEX_ETH_STATS_HAS_RX_BCAST_PACKETS) {
                _E6B(&q, &s->rx_bcast_packets);
            }

            if (smask & EMEX_ETH_STATS_HAS_TX_MCAST_BYTES) {
                _E6B(&q, &s->tx_mcast_bytes); s->tx_mcast_bytes <<= 10;
            }
            if (smask & EMEX_ETH_STATS_HAS_RX_MCAST_BYTES) {
                _E6B(&q, &s->rx_mcast_bytes); s->rx_mcast_bytes <<= 10;
            }
            if (smask & EMEX_ETH_STATS_HAS_TX_MCAST_PACKETS) {
                _E6B(&q, &s->tx_mcast_packets);
            }
            if (smask & EMEX_ETH_STATS_HAS_RX_MCAST_PACKETS) {
                _E6B(&q, &s->rx_mcast_packets);
            }

            /* Calculate unicast stats */
            if ((smask & EMEX_ETH_STATS_HAS_TX_BCAST_BYTES) && (smask & EMEX_ETH_STATS_HAS_TX_MCAST_BYTES)) {
                s->tx_ucast_bytes = ucast_stat(s->tx_bytes, s->tx_bcast_bytes + s->tx_mcast_bytes);
            }
            if ((smask & EMEX_ETH_STATS_HAS_RX_BCAST_BYTES) && (smask & EMEX_ETH_STATS_HAS_RX_MCAST_BYTES)) {
                s->rx_ucast_bytes = ucast_stat(s->rx_bytes, s->rx_bcast_bytes + s->rx_mcast_bytes);
            }
            if ((smask & EMEX_ETH_STATS_HAS_TX_BCAST_PACKETS) && (smask & EMEX_ETH_STATS_HAS_TX_MCAST_PACKETS)) {
                s->tx_ucast_packets = ucast_stat(s->tx_packets, s->tx_bcast_packets + s->tx_mcast_packets);
            }
            if ((smask & EMEX_ETH_STATS_HAS_RX_BCAST_PACKETS) && (smask & EMEX_ETH_STATS_HAS_RX_MCAST_PACKETS)) {
                s->rx_ucast_packets = ucast_stat(s->rx_packets, s->rx_bcast_packets + s->rx_mcast_packets);
            }
        }

        /* Skip all stats (also those added later) */
        p += stats_nr * 6;
    }

    err = 0;

out:
    if (err == -EINVAL) {
        log_ctrl_e("received invalid eth stats TLV from ale[%s]", ale->al_mac_str);
    }

    /* These functions need to return 1 on success */
    return err == 0 ? 1 : 0;
}

static int parse_emex_eth_neighbor_devices(i1905_vendor_specific_tlv_t *vendor_tlv, map_ale_info_t *ale, bool is_i1905)
{
    map_emex_eth_iface_list_t *list = &ale->emex.eth_iface_list;
    int err = -EINVAL;
    uint16_t tlv_id;
    uint8_t iface_nr, port_id, macs_nr;
    uint8_t *p = vendor_tlv->m;
    uint8_t *end = p + vendor_tlv->m_nr;
    size_t i, j;

    if ((end - p) < (/* tlv_id */ 2 + /* iface_nr */ 1)) {
        goto out;
    }

    _E2B(&p, &tlv_id);
    _E1B(&p, &iface_nr);

    for (i = 0; i < iface_nr; i++) {
        map_emex_eth_iface_t *iface = NULL;

        if ((end - p) < (/* port_id */ 1 + /* macs_nr */ 1)) {
            goto out;
        }

        _E1B(&p, &port_id);
        _E1B(&p, &macs_nr);

        if ((end - p) < (int)(macs_nr * sizeof(mac_addr))) {
            goto out;
        }

        /* Find port_id */
        for (j = 0; j < list->iface_nr; j++) {
            if (list->ifaces[j].port_id == port_id) {
                iface = &list->ifaces[j];
                break;
            }
        }

        if (iface) {
            mac_addr **p_macs    = is_i1905 ? &iface->i1905_neighbor_macs : &iface->non_i1905_neighbor_macs;
            size_t    *p_macs_nr = is_i1905 ? &iface->i1905_neighbor_macs_nr : &iface->non_i1905_neighbor_macs_nr;
            bool      *updated   = is_i1905 ? &iface->i1905_neighbor_macs_updated: &iface->non_i1905_neighbor_macs_updated;
            mac_addr  *new_macs  = realloc(*p_macs, macs_nr * sizeof(mac_addr));

            if (!new_macs) {
                SFREE(*p_macs);
                *p_macs_nr = 0;
                err = -ENOMEM;
                goto out;
            }

            *p_macs = new_macs;
            *p_macs_nr = macs_nr;
            *updated = true;
            memcpy(*p_macs, p, macs_nr * sizeof(mac_addr));
        }

        /* Skip macs */
        p += macs_nr * sizeof(mac_addr);
    }

    err = 0;

out:
    if (err) {
        if (err == -EINVAL) {
            log_ctrl_e("received invalid eth %s1905 neighbor devices TLV from ale[%s]", is_i1905 ? "" : "non-", ale->al_mac_str);
        }
    }

    /* These functions need to return 1 on success */
    return err == 0 ? 1 : 0;
}

static int parse_emex_eth_non_1905_neighbor_devices(i1905_vendor_specific_tlv_t *vendor_tlv, map_ale_info_t *ale)
{
    return parse_emex_eth_neighbor_devices(vendor_tlv, ale, false);
}

static int parse_emex_eth_1905_neighbor_devices(i1905_vendor_specific_tlv_t *vendor_tlv, map_ale_info_t *ale)
{
    return parse_emex_eth_neighbor_devices(vendor_tlv, ale, true);
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
bool map_emex_is_valid_tlv(i1905_vendor_specific_tlv_t* vendor_tlv)
{
    if (vendor_tlv == NULL) {
        return false;
    }

    /* We must be looking for AirTies OUI in Vendor Specific TLV for our extensions.
       Also check that tlv length is at least 2 (emex_tlv_id)
    */
    return (vendor_tlv->vendorOUI[0] == AIRTIES_VENDOR_OUI_1 &&
            vendor_tlv->vendorOUI[1] == AIRTIES_VENDOR_OUI_2 &&
            vendor_tlv->vendorOUI[2] == AIRTIES_VENDOR_OUI_3 &&
            vendor_tlv->m && vendor_tlv->m_nr >= 2);
}

int8_t map_emex_parse_tlv(map_ale_info_t *ale, i1905_vendor_specific_tlv_t* vendor_tlv)
{
    int8_t ret = 0;
    bool feature_changed = false;

    if (!ale) {
        return ret;
    }

    /* Check if incoming TLV has AirTies vendor OUI. */
    if (!map_emex_is_valid_tlv(vendor_tlv)) {
        log_ctrl_d("Cannot validate AirTies OUI");
        return ret;
    }

    /* Convert incoming 2-byte AirTies TLV id into short integer for ease of comparison. */
    uint16_t emex_tlv_id = (vendor_tlv->m[0] << 8) | vendor_tlv->m[1];
    log_ctrl_t("Received AirTies EM+ TLV (%d)", emex_tlv_id);
    switch (emex_tlv_id)
    {
        case EMEX_TLV_MESSAGE_TYPE:
        {
            /* Currently not handled */
            break;
        }
        case EMEX_TLV_FEATURE_PROFILE:
        {
            ret = parse_emex_feature_profile(vendor_tlv, ale, &feature_changed);

            if (feature_changed) {
                map_emex_calculate_common_feature_list();
            }
            break;
        }
        case EMEX_TLV_DEVICE_INFO:
        {
            ret = parse_emex_device_info(vendor_tlv, ale);
            break;
        }
        case EMEX_TLV_DEVICE_METRICS:
        {
            ret = parse_emex_device_metrics(vendor_tlv, ale);
            break;
        }
        case EMEX_TLV_ETH_INTERFACES:
        {
            ret = parse_emex_eth_interfaces(vendor_tlv, ale);
            break;
        }
        case EMEX_TLV_ETH_STATS_V2:
        {
            ret = parse_emex_eth_stats_v2(vendor_tlv, ale);
            break;
        }
        case EMEX_TLV_TYPE_ETH_NON_1905_NEIGHBOR_DEVICES:
        {
            ret = parse_emex_eth_non_1905_neighbor_devices(vendor_tlv, ale);
            break;
        }
        case EMEX_TLV_TYPE_ETH_1905_NEIGHBOR_DEVICES:
        {
            ret = parse_emex_eth_1905_neighbor_devices(vendor_tlv, ale);
            break;
        }
        default:
        {
            log_ctrl_w("Unexpected AirTies EM+ TLV type (%d)", emex_tlv_id);
            break;
        }
    }

    return ret;
}

bool map_emex_agent_is_feature_supported(map_ale_info_t *ale, uint16_t id)
{
    map_emex_supported_feature_t *f_list;
    int i, f_count;

    f_list = ale->emex.feature_profile.feature_list;
    f_count = ale->emex.feature_profile.feature_count;
    for (i = 0; i < f_count; i++) {
        if (id == f_list[i].id)
        return true;
    }
    return false;
}

bool map_emex_common_is_feature_supported(uint16_t id)
{
    map_emex_common_feature_list_t *cf_list;
    int i, f_count;

    cf_list = controller_get_emex_common_feature_list();
    f_count = cf_list->feature_count;
    for (i = 0; i < f_count; i++) {
        if (id == cf_list->feature_list[i].id)
        return true;
    }
    return false;
}

int map_emex_handle_cmdu_pre(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    if (cmdu->message_type == CMDU_TYPE_TOPOLOGY_RESPONSE) {
        /* Mark all ethernet neighbors */
        map_emex_eth_iface_list_t *list = &ale->emex.eth_iface_list;
        size_t i;

        for (i = 0; i < list->iface_nr; i++) {
            map_emex_eth_iface_t *iface = &list->ifaces[i];

            iface->non_i1905_neighbor_macs_updated = false;
            iface->i1905_neighbor_macs_updated = false;
        }
    }

    return 0;
}

int map_emex_handle_cmdu_post(map_ale_info_t *ale, i1905_cmdu_t *cmdu)
{
    if (cmdu->message_type == CMDU_TYPE_TOPOLOGY_RESPONSE) {
        /* Remove ethernet neigbors that where not updated */
        map_emex_eth_iface_list_t *list = &ale->emex.eth_iface_list;
        size_t i;

        for (i = 0; i < list->iface_nr; i++) {
            map_emex_eth_iface_t *iface = &list->ifaces[i];

            if (!iface->non_i1905_neighbor_macs_updated) {
                SFREE(iface->non_i1905_neighbor_macs);
                iface->non_i1905_neighbor_macs_nr = 0;
            }

            if (!iface->i1905_neighbor_macs_updated) {
                SFREE(iface->i1905_neighbor_macs);
                iface->i1905_neighbor_macs_nr = 0;
            }
        }
    }

    return 0;
}

int8_t map_emex_init(void)
{
    return 0;
}

void map_emex_fini(void)
{
    SFREE(controller_get_emex_common_feature_list()->feature_list);
    controller_get_emex_common_feature_list()->feature_count = 0;
}
