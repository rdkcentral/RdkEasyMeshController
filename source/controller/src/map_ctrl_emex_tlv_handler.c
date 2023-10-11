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
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
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

        ale->emex.enabled = true;

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

    ale->emex.enabled = true;

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

    ale->emex.enabled = true;

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

    ale->emex.enabled = true;

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
    log_ctrl_d("Received AirTies EM+ TLV (%d)", emex_tlv_id);
    switch (emex_tlv_id)
    {
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

int8_t map_emex_get_emex_tlv(UNUSED map_ale_info_t *ale, uint16_t emex_tlv_type,
                             i1905_vendor_specific_tlv_t *vendor_specific_tlv)
{
    uint8_t *payload = NULL;
    uint16_t payload_len = 0;
    int8_t   ret = -1;

    switch (emex_tlv_type)
    {
        default:
            log_ctrl_e("Unsupported AirTies EM+ TLV type (%d)", emex_tlv_type);
            break;
    }

    if (!ret) {
        vendor_specific_tlv->tlv_type = TLV_TYPE_VENDOR_SPECIFIC;
        vendor_specific_tlv->vendorOUI[0] = AIRTIES_VENDOR_OUI_1;
        vendor_specific_tlv->vendorOUI[1] = AIRTIES_VENDOR_OUI_2;
        vendor_specific_tlv->vendorOUI[2] = AIRTIES_VENDOR_OUI_3;
        vendor_specific_tlv->m_nr = payload_len;
        vendor_specific_tlv->m = (uint8_t *)payload;
    }

    return ret;
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
}
