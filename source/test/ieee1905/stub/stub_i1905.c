/*
 * Copyright (c) 2021-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#include "stub_i1905.h"

static stub_i1905_lldp_send_cb_t  g_lldp_send_cb;
static void                      *g_lldp_send_args;
static stub_i1905_cmdu_send_cb_t  g_cmdu_send_cb;
static void                      *g_cmdu_send_args;
static stub_i1905_raw_send_cb_t   g_raw_send_cb;
static void                      *g_raw_send_args;
static int                        g_send_nr;

void stub_i1905_register_lldp_send_cb(stub_i1905_lldp_send_cb_t cb, void *args)
{
    g_lldp_send_cb   = cb;
    g_lldp_send_args = args;
}

void stub_i1905_register_cmdu_send_cb(stub_i1905_cmdu_send_cb_t cb, void *args)
{
    g_cmdu_send_cb   = cb;
    g_cmdu_send_args = args;
}

void stub_i1905_register_raw_send_cb(stub_i1905_raw_send_cb_t cb, void *args)
{
    g_raw_send_cb   = cb;
    g_raw_send_args = args;
}

void stub_i1905_reset_send_nr(void)
{
    g_send_nr = 0;
}

int stub_i1905_get_send_nr(void)
{
    return g_send_nr;
}

char **i1905_get_list_of_interfaces(uint8_t *nr)
{
    static char *interfaces[] = {"eth0", "lo"};

    *nr = 2;
    return interfaces;
}

void i1905_free_list_of_interfaces(char **interfaces, uint8_t nr)
{
}

i1905_interface_info_t *i1905_get_interface_info(char *ifname)
{
    static i1905_interface_info_t info;

    return &info;
}

void i1905_free_interface_info(i1905_interface_info_t *info)
{
}

int i1905_get_interface_mac(char *if_name, mac_addr mac)
{
    memset(mac, 0, sizeof(mac_addr));
    return 0;
}

void i1905_set_interface_type(char *if_name, uint16_t type)
{
}

void i1905_set_interface_80211_media_specific_info(char *if_name, mac_addr network_membership,
                                                   uint8_t role, uint8_t ap_channel_band,
                                                   uint8_t ap_channel_center_freq_1,
                                                   uint8_t ap_channel_center_freq_2)
{
}

void i1905_get_mcast_mac(mac_addr mac)
{
    memcpy(mac, (mac_addr){0x01, 0x80, 0xC2, 0x00, 0x00, 0x13}, sizeof(mac_addr));
}

void i1905_cmdu_free(i1905_cmdu_t *cmdu)
{
}

int i1905_send(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid)
{
    if (g_cmdu_send_cb) {
        g_cmdu_send_cb(cmdu, dmac, mid, g_cmdu_send_args);
    }
    g_send_nr++;

    return 0;
}

int i1905_send_lldp(char *ifname, mac_addr smac, i1905_lldp_payload_t *payload)
{
    if (g_lldp_send_cb) {
        g_lldp_send_cb(ifname, smac, payload, g_lldp_send_args);
    }
    g_send_nr++;

    return 0;
}

int i1905_send_raw(char *ifname, mac_addr dmac, mac_addr smac, uint16_t eth_type, uint8_t *data, uint16_t data_len)
{
    if (g_raw_send_cb) {
        g_raw_send_cb(ifname, dmac, smac, eth_type, data, data_len, g_raw_send_args);
    }
    g_send_nr++;

    return 0;
}

const char *i1905_cmdu_type_to_string(uint16_t cmdu_type)
{
    return "CMDU_UNKNOWN";
}

const char *i1905_tlv_type_to_string(uint8_t tlv_type)
{
    return "TLV_UNKNOWN";
}

void i1905_get_gateway_mac_address(mac_addr mac)
{
    memcpy(mac, (mac_addr){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, sizeof(mac_addr));
}

void i1905_set_leader_selected(bool leader_selected)
{
}

int i1905_get(char *ifname, i1905_param_t param, void *data, size_t *data_len)
{
    /* Minimal implementation */
    switch(param) {
        case I1905_GET_SEARCHEDROLE_TLV: {
            i1905_searched_role_tlv_t *tlv = data;
            memset(tlv, 0, sizeof(*tlv));
            tlv->tlv_type = TLV_TYPE_SEARCHED_ROLE;
        }
        break;
        case I1905_GET_ALMAC_TLV: {
            i1905_al_mac_address_tlv_t *tlv = data;
            memset(tlv, 0, sizeof(*tlv));
            tlv->tlv_type = TLV_TYPE_AL_MAC_ADDRESS;
        }
        break;
        case I1905_GET_SUPPORTEDROLE_TLV: {
            i1905_supported_role_tlv_t *tlv = data;
            memset(tlv, 0, sizeof(*tlv));
            tlv->tlv_type = TLV_TYPE_SUPPORTED_ROLE;
        }
        break;
        case I1905_GET_SUPPORTEDFREQBAND_TLV: {
            i1905_supported_freq_band_data_t *d = data;
            i1905_supported_freq_band_tlv_t  *tlv = d->supported_freq_band_tlv;
            memset(tlv, 0, sizeof(*tlv));
            tlv->tlv_type = TLV_TYPE_SUPPORTED_FREQ_BAND;
        }
        break;
        case I1905_GET_DEVICEINFO_TLV: {
            i1905_device_information_tlv_t *tlv = data;
            memset(tlv, 0, sizeof(*tlv));
            tlv->tlv_type = TLV_TYPE_DEVICE_INFORMATION;
        }
        break;
        case I1905_GET_WSCM2_TLV: {
            i1905_wsc_data_t *wsc_params = data;
            wsc_params->m2.tlv_type       = TLV_TYPE_WSC;
            wsc_params->m2.wsc_frame_size = 0;
            wsc_params->m2.wsc_frame      = NULL;
        }
        default:
        break;
    }

    return 0;
}

i1905_bridge_t *i1905_get_list_of_bridges(uint8_t *nr)
{
    *nr = 0;

    return NULL;
}

void i1905_free_list_of_bridges(i1905_bridge_t *br, uint8_t nr)
{
}

void i1905_dump_interfaces(map_printf_cb_t print_cb)
{
    print_cb("eth0\n");
}
