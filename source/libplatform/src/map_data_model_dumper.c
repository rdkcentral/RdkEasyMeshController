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
#include "map_data_model_dumper.h"
#include "map_data_model.h"
#include "map_info.h"
#include "1905_platform.h"
#include "map_topology_tree.h"

/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
static void print_sta_bss_mapping(map_printf_cb_t print_cb)
{
    map_ale_info_t   *ale;
    map_radio_info_t *radio;
    map_bss_info_t   *bss;
    map_sta_info_t   *sta;
    bool              printed_one = false;

    print_cb(" ======================================================================\n");
    print_cb(" ||    Station MAC      ||       BSS ID        ||         ALE        ||\n");
    print_cb(" ======================================================================\n");

    map_dm_foreach_agent_ale(ale) {
        map_dm_foreach_radio(ale, radio) {
            map_dm_foreach_bss(radio, bss) {
                map_dm_foreach_sta(bss, sta) {
                    print_cb(" ||  %s  ||  %s  ||  %s  ||\n", sta->mac_str, bss->bssid_str, ale->al_mac_str);
                    printed_one = true;
                }
            }
        }
    }

    if (!printed_one) {
        print_cb(" ||                     ||                     ||                    ||\n");
    }
    print_cb(" ======================================================================\n");
}

static void print_sta_link_metrics(map_sta_info_t *sta, size_t print_last_n, map_printf_cb_t print_cb)
{
    list_iterator_t *it;
    size_t           index;

    if (!sta->metrics) {
        return;
    }

    if (!(it = new_list_iterator(sta->metrics))) {
        return;
    }

    print_cb("     |    - LINK METRICS  :\n");

    for (index = 0; it->iter != NULL && index < print_last_n; ) {
        map_sta_link_metrics_t *link_metrics = get_next_list_object(it);
        if (link_metrics) {
            print_cb("     |      -[%zu]\n", index);
            print_cb("     |        - Age           : %d\n",   link_metrics->age);
            print_cb("     |        - DL Data rate  : %d\n",   link_metrics->dl_mac_datarate);
            print_cb("     |        - UL Data rate  : %d\n",   link_metrics->ul_mac_datarate);
            print_cb("     |        - RSSI          : %d\n\n", link_metrics->rssi);
            index++;
        }
    }
    free_list_iterator(it);
}

static void print_sta_metrics( map_sta_info_t *sta, map_printf_cb_t print_cb)
{
    print_cb("     |    - TRAFFIC STATS :\n");
    print_cb("     |      - Tx bytes      : %"PRIu64"\n", sta->traffic_stats.tx_bytes);
    print_cb("     |      - Rx bytes      : %"PRIu64"\n", sta->traffic_stats.rx_bytes);
    print_cb("     |      - Tx pkts       : %d\n",        sta->traffic_stats.tx_packets);
    print_cb("     |      - Rx pkts       : %d\n",        sta->traffic_stats.rx_packets);
    print_cb("     |      - Tx pkt errors : %d\n",        sta->traffic_stats.tx_packet_errors);
    print_cb("     |      - Rx pkt errors : %d\n",        sta->traffic_stats.rx_packet_errors);
    print_cb("     |      - ReTx count    : %d\n",        sta->traffic_stats.retransmissions);

    print_sta_link_metrics(sta, 1, print_cb);
}

static void print_sta_info(map_bss_info_t *bss, map_printf_cb_t print_cb)
{
    map_sta_info_t *sta;
    int             idx = 0;

    print_cb("   -STA LIST\n");
    print_cb("     |\n");
    print_cb("     |-----------------------------------------------\n");

    map_dm_foreach_sta(bss, sta) {
        print_cb("     | STA[%d]\n", idx++);
        print_cb("     |    - STA MAC       : %s\n",        sta->mac_str);
        print_cb("     |    - Assoc to      : %s\n",        sta->bss->bssid_str);
        print_cb("     |    - Assoc since   : %"PRIu64"\n", map_dm_get_sta_assoc_ts_delta(sta->assoc_ts));
        print_sta_metrics(sta, print_cb);
    }

    print_cb("     |\n");
    print_cb("     -----------------------------------------------\n");
}

static void print_ap_metrics(map_bss_info_t *bss, map_printf_cb_t print_cb)
{
    uint8_t ac_index;

    print_cb("    -Channel util  : %d\n", bss->metrics.channel_utilization);
    print_cb("    -Station count : %d\n", bss->metrics.stas_nr);
    print_cb("    -ESP presence  : 0x%02x\n", bss->metrics.esp_present);
    print_cb("    -ESP\n");
    print_cb("      |-----------------------------------------------\n");

    for(ac_index = 0; ac_index < MAX_ACCESS_CATEGORY; ac_index++) {
        if (bss->metrics.esp_present & (1<<(7 - ac_index))) {
            if (ac_index == WIFI_AC_BE) {
                print_cb("      | AC-BE:\n");
            } else if(ac_index == WIFI_AC_BK) {
                print_cb("      | AC-BK:\n");
            } else if(ac_index == WIFI_AC_VO) {
                print_cb("      | AC-VO:\n");
            } else if(ac_index == WIFI_AC_VD) {
                print_cb("      | AC-VI:\n");
            }

            print_cb("      |  -ESP Sub Element      : 0x%02x\n", bss->metrics.esp[ac_index].s.esp_subelement);
            print_cb("      |  -Air Time Fraction    : 0x%02x\n", bss->metrics.esp[ac_index].s.estimated_air_time_fraction);
            print_cb("      |  -PPDU Target Duration : 0x%02x\n", bss->metrics.esp[ac_index].s.ppdu_target_duration);
        }
    }
    print_cb("       -----------------------------------------------\n");
    print_cb("    -unicast bytes tx   : %"PRIu64"\n", bss->extended_metrics.tx_ucast_bytes);
    print_cb("    -unicast bytes rx   : %"PRIu64"\n", bss->extended_metrics.rx_ucast_bytes);
    print_cb("    -multicast bytes tx : %"PRIu64"\n", bss->extended_metrics.tx_mcast_bytes);
    print_cb("    -multicast bytes rx : %"PRIu64"\n", bss->extended_metrics.rx_mcast_bytes);
    print_cb("    -broadcast bytes tx : %"PRIu64"\n", bss->extended_metrics.tx_bcast_bytes);
    print_cb("    -broadcast bytes rx : %"PRIu64"\n", bss->extended_metrics.rx_bcast_bytes);
}

static void print_bss_in_radio(map_radio_info_t *radio, map_printf_cb_t print_cb)
{
    map_bss_info_t *bss;
    int             idx = 0;

    print_cb(" Num of BSS  : %d\n", radio->bsss_nr);

    map_dm_foreach_bss(radio, bss) {
        print_cb("   BSS[%d]\n", idx++);
        print_cb("   |\n");

        print_cb("    -BSSID         : %s\n", bss->bssid_str);
        print_cb("    -SSID          : %s\n", bss->ssid);
        if ((bss->type & MAP_BACKHAUL_BSS) && (bss->type & MAP_FRONTHAUL_BSS)) {
            print_cb("    -BSS TYPE      : FRONTHAUL (and/or) BACKHAUL\n");
        } else if (bss->type & MAP_FRONTHAUL_BSS) {
            print_cb("    -BSS TYPE      : FRONTHAUL\n");
        } else if (bss->type & MAP_BACKHAUL_BSS) {
            print_cb("    -BSS TYPE      : BACKHAUL\n");
        } else {
            print_cb("    -BSS TYPE      : UNCONFIGURED\n");
        }
        print_ap_metrics(bss, print_cb);
        print_sta_info(bss, print_cb);
    }
}

static void print_op_class_channel_list(map_op_class_t *op_class, map_printf_cb_t print_cb)
{
    map_channel_set_t  ch_set;
    bool               is_center_channel;
    char               buf[MAP_CS_BUF_LEN];

    if (map_get_is_center_channel_from_op_class(op_class->op_class, &is_center_channel)) {
        return;
    }

    if ((is_center_channel && map_get_center_channel_set_from_op_class(op_class->op_class, &ch_set)) ||
        (!is_center_channel && map_get_channel_set_from_op_class(op_class->op_class, &ch_set))) {
        return;
    }

    /* Unset non operable channels */
    map_cs_and_not(&ch_set, &op_class->channels);

    print_cb("     -Channels : %s\n", map_cs_to_string(&ch_set, ',', buf, sizeof(buf)));
}

static void print_curr_op_class_list(map_radio_info_t *radio, map_printf_cb_t print_cb)
{
    uint8_t i;

    print_cb("  Current op class list:\n");
    print_cb("  |\n");

    for (i = 0; i < radio->curr_op_class_list.op_classes_nr ; ++i) {
        map_op_class_t *op_class = &radio->curr_op_class_list.op_classes[i];

        print_cb("  -[%d]\n", i);
        print_cb("     |\n");
        print_cb("     -OP Class : %d\n", op_class->op_class);
        print_cb("     -EIRP     : %d\n", op_class->eirp);
        print_op_class_channel_list(op_class, print_cb);
    }
}

static void print_cap_op_class_list(map_radio_info_t *radio, map_printf_cb_t print_cb)
{
    uint8_t i;

    print_cb("  Capable op class list:\n");
    print_cb("  |\n");

    for (i = 0; i < radio->cap_op_class_list.op_classes_nr ; ++i) {
        map_op_class_t *op_class = &radio->cap_op_class_list.op_classes[i];

        print_cb("  -[%d]\n", i);
        print_cb("     |\n");
        print_cb("     -OP Class : %d\n", op_class->op_class);
        print_cb("     -EIRP     : %d\n", op_class->eirp);
        print_op_class_channel_list(op_class, print_cb);
    }
}

static void print_pref_op_class_list(map_radio_info_t *radio, map_printf_cb_t print_cb, bool agent_pref)
{
    map_op_class_t *list  = agent_pref ? radio->pref_op_class_list.op_classes    : radio->ctrl_pref_op_class_list.op_classes;
    int             count = agent_pref ? radio->pref_op_class_list.op_classes_nr : radio->ctrl_pref_op_class_list.op_classes_nr;
    uint8_t         i;

    print_cb("  %s channel pref op class list:\n", agent_pref ? "Agent" : "Controller");
    print_cb("  |\n");

    for (i = 0; i < count ; ++i) {
        print_cb("  -[%d]\n", i);
        print_cb("     |\n");
        print_cb("     -OP Class : %d\n", list[i].op_class);
        print_cb("     -Pref     : %d\n", list[i].pref);
        print_cb("     -Reason   : %d\n", list[i].reason);
        print_op_class_channel_list(&list[i], print_cb);
    }
}

static void print_op_restriction_in_radio(map_radio_info_t *radio, map_printf_cb_t print_cb)
{
    char buf[MAP_CS_BUF_LEN];
    uint8_t i, j;

    print_cb("  Operation restriction:\n");
    print_cb("  |\n");

    for (i = 0; i < radio->op_restriction_list.op_classes_nr; ++i) {
        map_op_restriction_t *op_class = &radio->op_restriction_list.op_classes[i];
        int                   pos = 0;

        print_cb("  -[%d]\n", i);
        print_cb("     |\n");
        print_cb("     -OP Class : %d\n", op_class->op_class);

        buf[0] = 0;
        for (j = 0; j < op_class->channels_nr && pos < MAP_CS_BUF_LEN; j++) {
            pos += snprintf(buf + pos, MAP_CS_BUF_LEN - pos, "%d, ", op_class->channels[j].channel);
        }
        print_cb("     -Channels : %s\n", buf);
    }
}

static void map_print_ht_caps(map_radio_ht_capability_t* ht_caps, map_printf_cb_t print_cb)
{
    print_cb("   -HT Caps\n");
    print_cb("    |\n");
    print_cb("     -max_supported_tx_streams : %d\n", ht_caps->max_supported_tx_streams);
    print_cb("     -max_supported_rx_streams : %d\n", ht_caps->max_supported_rx_streams);
    print_cb("     -gi_support_20mhz         : %d\n", ht_caps->gi_support_20mhz);
    print_cb("     -gi_support_40mhz         : %d\n", ht_caps->gi_support_40mhz);
    print_cb("     -ht_support_40mhz         : %d\n", ht_caps->ht_support_40mhz);
}

static void map_print_vht_caps(map_radio_vht_capability_t* vht_caps, map_printf_cb_t print_cb)
{
    print_cb("   -VHT Caps\n");
    print_cb("    |\n");
    print_cb("     -supported_tx_mcs          : %d\n", vht_caps->supported_tx_mcs);
    print_cb("     -supported_rx_mcs          : %d\n", vht_caps->supported_rx_mcs);
    print_cb("     -max_supported_tx_streams  : %d\n", vht_caps->max_supported_tx_streams);
    print_cb("     -max_supported_rx_streams  : %d\n", vht_caps->max_supported_rx_streams);
    print_cb("     -gi_support_80mhz          : %d\n", vht_caps->gi_support_80mhz);
    print_cb("     -gi_support_160mhz         : %d\n", vht_caps->gi_support_160mhz);
    print_cb("     -support_80_80_mhz         : %d\n", vht_caps->support_80_80_mhz);
    print_cb("     -support_160mhz            : %d\n", vht_caps->support_160mhz);
    print_cb("     -su_beamformer_capable     : %d\n", vht_caps->su_beamformer_capable);
    print_cb("     -mu_beamformer_capable     : %d\n", vht_caps->mu_beamformer_capable);
}

static void map_print_he_caps(map_radio_he_capability_t* he_caps, map_printf_cb_t print_cb)
{
    print_cb("   -HE Caps\n");
    print_cb("    |\n");
    print_cb("     -supported_mcs_length      : %d\n", he_caps->supported_mcs_length);
    //TODO: Print supported mcs from 802.11ax spec
    print_cb("     -max_supported_tx_streams  : %d\n", he_caps->max_supported_tx_streams);
    print_cb("     -max_supported_rx_streams  : %d\n", he_caps->max_supported_rx_streams);
    print_cb("     -support_80_80_mhz         : %d\n", he_caps->support_80_80_mhz);
    print_cb("     -support_160mhz            : %d\n", he_caps->support_160mhz);
    print_cb("     -su_beamformer_capable     : %d\n", he_caps->su_beamformer_capable);
    print_cb("     -mu_beamformer_capable     : %d\n", he_caps->mu_beamformer_capable);
    print_cb("     -ul_mimo_capable           : %d\n", he_caps->ul_mimo_capable);
    print_cb("     -ul_mimo_ofdma_capable     : %d\n", he_caps->ul_mimo_ofdma_capable);
    print_cb("     -dl_mimo_ofdma_capable     : %d\n", he_caps->dl_mimo_ofdma_capable);
    print_cb("     -ul_ofdma_capable          : %d\n", he_caps->ul_ofdma_capable);
    print_cb("     -dl_ofdma_capable          : %d\n", he_caps->dl_ofdma_capable);

}

static void map_print_radio_caps(map_radio_info_t* radio, map_printf_cb_t print_cb)
{
    print_cb("  Radio Caps  :\n");
    print_cb("  |\n");
    print_cb("   -Radio ID                   : %s\n", radio->radio_id_str);
    print_cb("   -IB UnAssocStaLinkMetricSupp: %d\n", radio->ale->agent_capability.ib_unassociated_sta_link_metrics_supported);
    print_cb("   -OB UnAssocStaLinkMetricSupp: %d\n", radio->ale->agent_capability.oob_unassociated_sta_link_metrics_supported);
    print_cb("   -Agent Initiated Steering   : %d\n", radio->ale->agent_capability.rssi_agent_steering_supported);

    if (radio->ht_caps) {
        map_print_ht_caps(radio->ht_caps, print_cb);
    }

    if (radio->vht_caps) {
        map_print_vht_caps(radio->vht_caps, print_cb);
    }

    if (radio->he_caps) {
        map_print_he_caps(radio->he_caps, print_cb);
    }
}

static void print_radios_in_agent(map_ale_info_t *ale, map_printf_cb_t print_cb)
{
    map_radio_info_t *radio;
    int               idx = 0;

    map_dm_foreach_radio(ale, radio) {
        print_cb("Radio[%d]\n", idx++);
        print_cb("  |\n");
        print_cb("  Radio MAC      : %s\n", radio->radio_id_str);

        print_cb("  Radio Type     : %s\n", map_get_freq_band_str(radio->supported_freq));

        print_cb("  Radio State    : %sCONFIGURED[0x%04x]\n", is_radio_configured(radio->state) ? "" : "UN", radio->state);

        print_cb("  Radio OP Class : %d\n",radio->current_op_class);
        print_cb("  Radio OP Chan  : %d\n",radio->current_op_channel);
        print_cb("  Radio BW       : %d\n",radio->current_bw);
        print_cb("  Radio Tx Pwr   : %d\n",radio->current_tx_pwr);
        print_cb("  Radio Auth Modes      : 0x%04x\n",radio->auth_modes_flag);

        print_curr_op_class_list(radio, print_cb);
        print_cap_op_class_list(radio, print_cb);
        print_pref_op_class_list(radio, print_cb, true);
        print_pref_op_class_list(radio, print_cb, false);
        print_op_restriction_in_radio(radio, print_cb);

        map_print_radio_caps(radio, print_cb);

        /* print the BSS */
        print_bss_in_radio(radio, print_cb);
        print_cb("----------------------------------------------\n");
    }
}

static void print_local_interfaces(map_ale_info_t *ale, map_printf_cb_t print_cb)
{
    size_t i, j, k;

    for (i = 0; i <ale->local_iface_count; i++) {
        map_local_iface_t *iface = &ale->local_iface_list[i];

        print_cb("Interface[%zu]\n", i);
        print_cb("  MAC          : %s\n", mac_string(iface->mac_address));
        print_cb("  Type         : %s[%d]\n", convert_interface_type_to_string(iface->media_type), iface->media_type);

        /* Add any non 1905 mac behind it */
        for (j = 0; j < ale->non_1905_neighbor_count; j++) {
            map_non_1905_neighbor_t *n = &ale->non_1905_neighbor_list[j];

            if (!maccmp(iface->mac_address, n->local_iface_mac)) {
                print_cb("  Non_1905_nbr : %zu\n", n->macs_nr);
                for (k = 0; k < n->macs_nr; k++) {
                    print_cb("    %s\n", mac_string(n->macs[k]));
                }
            }
        }
    }
    print_cb("----------------------------------------------\n");

}

static void print_backhaul_sta_interfaces(map_ale_info_t *ale, map_printf_cb_t print_cb)
{
    uint8_t i;

    if (ale->backhaul_sta_iface_count == 0) {
        return;
    }

    for (i = 0; i < ale->backhaul_sta_iface_count; i++) {
        map_backhaul_sta_iface_t *bhsta_iface = &ale->backhaul_sta_iface_list[i];
        map_radio_info_t         *radio = map_dm_get_radio(ale, bhsta_iface->radio_id);
        uint8_t                   band = radio ? radio->supported_freq : IEEE80211_FREQUENCY_BAND_UNKNOWN;

        print_cb("BHSTA Interface[%u]\n", i);
        print_cb("  STA MAC      : %s\n", mac_string(bhsta_iface->mac_address));
        print_cb("  Radio MAC    : %s\n", mac_string(bhsta_iface->radio_id));
        print_cb("  Radio Band   : %s\n", map_get_freq_band_str(band));
        print_cb("  Active       : %s\n", bhsta_iface->active ? "true" : "false");
    }
    print_cb("----------------------------------------------\n");
}

static void print_eth_devices(map_ale_info_t *ale, map_printf_cb_t print_cb)
{
    size_t i;

    print_cb("Ethernet devices:\n");

    for (i = 0; i < ale->eth_device_list.macs_nr; i++) {
        print_cb("  %s\n", mac_string(ale->eth_device_list.macs[i]));
    }
    print_cb("----------------------------------------------\n");
}

static void print_emex_eth_interfaces(map_ale_info_t *ale, map_printf_cb_t print_cb)
{
    map_emex_eth_iface_list_t *list = &ale->emex.eth_iface_list;
    size_t i, j;

    print_cb("Emex ethernet interfaces:\n");

    for (i = 0; i < list->iface_nr; i++) {
        map_emex_eth_iface_t *iface = &list->ifaces[i];

        print_cb("interface[%d][%s]\n", iface->port_id, iface->name);
        print_cb("  MAC          : %s\n", mac_string(iface->mac));
        print_cb("  Admin state  : %d\n", iface->admin_state);
        print_cb("  Oper state   : %d\n", iface->oper_state);
        print_cb("  Full duplex  : %d\n", iface->full_duplex);
        print_cb("  Supp speed   : %d\n", iface->supported_link_speed);
        print_cb("  Speed        : %d\n", iface->link_speed);
        print_cb("  Non_1905_nbr : %zu\n", iface->non_i1905_neighbor_macs_nr);
        for (j = 0; j < iface->non_i1905_neighbor_macs_nr; j++) {
            print_cb("    %s\n", mac_string(iface->non_i1905_neighbor_macs[j]));
        }
        print_cb("  1905_nbr     : %zu\n", iface->i1905_neighbor_macs_nr);
        for (j = 0; j < iface->i1905_neighbor_macs_nr; j++) {
            print_cb("    %s\n", mac_string(iface->i1905_neighbor_macs[j]));
        }
    }
    print_cb("----------------------------------------------\n");
}

static char *mld_modes_to_buf(char *buf, size_t buf_len, map_mld_modes_t *m)
{
    int pos = snprintf(buf, buf_len, "%s%s%s%s",
                       m->str   ? "STR "   : "",
                       m->nstr  ? "NSTR "  : "",
                       m->emlsr ? "EMLSR " : "",
                       m->emlmr ? "EMLMR " : "");

    if (pos > 0) {
        buf[pos] = 0;
    }

    return buf;
}

static void print_mld(map_ale_info_t *ale, map_printf_cb_t print_cb, const char *indent, bool print_sep)
{
    map_ap_mld_info_t      *ap_mld;
    map_bsta_mld_info_t    *bsta_mld = &ale->bsta_mld;
    map_sta_mld_info_t     *sta_mld;
    map_sta_info_t         *sta;
    map_radio_info_t       *radio;
    map_radio_wifi7_caps_t *wifi7_caps;
    map_bss_info_t         *bss;
    size_t                  count1 = 0;
    map_mld_modes_t         supp_ap_mld_modes = {0};
    map_mld_modes_t         supp_bsta_mld_modes = {0};
    char                    mld_modes_buf[64];

    /* Or all ap and bsta radio mld modes (normally they are all the same) */
    map_dm_foreach_radio(ale, radio) {
        if ((wifi7_caps = radio->wifi7_caps)) {
            supp_ap_mld_modes.str     |= wifi7_caps->ap_mld_modes.str;
            supp_ap_mld_modes.nstr    |= wifi7_caps->ap_mld_modes.nstr;
            supp_ap_mld_modes.emlsr   |= wifi7_caps->ap_mld_modes.emlsr;
            supp_ap_mld_modes.emlmr   |= wifi7_caps->ap_mld_modes.emlmr;

            supp_bsta_mld_modes.str   |= wifi7_caps->bsta_mld_modes.str;
            supp_bsta_mld_modes.nstr  |= wifi7_caps->bsta_mld_modes.nstr;
            supp_bsta_mld_modes.emlsr |= wifi7_caps->bsta_mld_modes.emlsr;
            supp_bsta_mld_modes.emlmr |= wifi7_caps->bsta_mld_modes.emlmr;
        }
    }

    if (ale->ap_mld_nr > 0) {
        print_cb("%sAP MLDs:\n", indent);

        map_dm_foreach_ap_mld(ale, ap_mld) {
            size_t count2 = 0;

            print_cb("%s  MLD[%zu][%s]\n", indent, count1++, ap_mld->mac_str);
            print_cb("%s    SSID      : %s\n", indent, ap_mld->ssid);
            print_cb("%s    Supp modes: %s\n", indent, mld_modes_to_buf(mld_modes_buf, sizeof(mld_modes_buf), &supp_ap_mld_modes));
            print_cb("%s    Enab modes: %s\n", indent, mld_modes_to_buf(mld_modes_buf, sizeof(mld_modes_buf), &ap_mld->enabled_mld_modes));
            print_cb("%s    Aff APs   :\n", indent);
            map_dm_foreach_aff_ap(ap_mld, bss) {
                print_cb("%s      AP[%zu][%s]\n", indent, count2++, bss->bssid_str);
                print_cb("%s        LinkID: %d\n", indent, bss->link_id);
                print_cb("%s        Band  : %s\n", indent, map_get_freq_band_str(bss->radio->supported_freq));
            }

            if (ap_mld->sta_mld_nr > 0) {
                size_t count3 = 0;

                map_dm_foreach_sta_mld(ap_mld, sta_mld) {
                    size_t count4 = 0;

                    print_cb("%s    STA MLDs:\n", indent);
                    print_cb("%s      STA[%zu][%s]\n", indent, count3++, sta_mld->mac_str);
                    print_cb("%s      Supp modes: %s\n", indent, mld_modes_to_buf(mld_modes_buf, sizeof(mld_modes_buf), &sta_mld->supported_mld_modes));
                    print_cb("%s      Enab modes: %s\n", indent, mld_modes_to_buf(mld_modes_buf, sizeof(mld_modes_buf), &sta_mld->enabled_mld_modes));
                    print_cb("%s      Aff STAs  :\n", indent);
                    map_dm_foreach_aff_sta(sta_mld, sta) {
                        print_cb("%s        STA[%zu][%s]\n", indent, count4++, sta->mac_str);
                        print_cb("%s          Band  : %s\n", indent, map_get_freq_band_str(sta->bss->radio->supported_freq));
                    }
                }
            }

            print_cb("\n");
        }
    }

    if (bsta_mld->valid) {
        size_t i;

        print_cb("%sbSTA MLD[%s]:\n", indent, bsta_mld->mac_str);
        print_cb("%s  AP MLD MAC: %s\n", indent, mac_string(bsta_mld->ap_mld_mac));
        print_cb("%s  Supp modes: %s\n", indent, mld_modes_to_buf(mld_modes_buf, sizeof(mld_modes_buf), &supp_bsta_mld_modes));
        print_cb("%s  Enab modes: %s\n", indent, mld_modes_to_buf(mld_modes_buf, sizeof(mld_modes_buf), &bsta_mld->enabled_mld_modes));
        print_cb("%s  Aff bSTAs :\n", indent);
        for (i = 0; i < bsta_mld->aff_bsta_mac_nr; i++) {
            print_cb("%s    bSTA[%zu][%s]\n", indent, i, mac_string(bsta_mld->aff_bsta_macs[i]));
        }
    }

    if (print_sep) {
        print_cb("----------------------------------------------\n");
    }
}

static void print_agent_info(map_ale_info_t *ale, map_printf_cb_t print_cb)
{
    print_cb("***********************************************\n");

    print_cb(" Al ENTITY MAC          : %s\n",          ale->al_mac_str);
    print_cb(" ALE LOCAL              : %s %s\n",       ale->is_local ? "yes" : "no", ale->is_local ? (ale->is_local_colocated ? "(colocated)" : "(not colocated)") : "");
    print_cb(" ALE EASYMESH PLUS      : %s\n",          ale->easymesh_plus ? "yes" : "no");
    print_cb(" ALE SOURCE MAC         : %s\n",          mac_string(ale->src_mac));
    print_cb(" ALE UPSTREAM LOCAL MAC : %s\n",          mac_string(ale->upstream_local_iface_mac));
    print_cb(" ALE UPSTREAM INTERFACE Type : %s[%d]\n", convert_interface_type_to_string(ale->upstream_iface_type), ale->upstream_iface_type);
    print_cb(" ALE UPSTREAM REMOTE MAC: %s\n",          mac_string(ale->upstream_remote_iface_mac));

    if (ale->ale_onboard_status == ALE_NODE_ONBOARDING) {
        print_cb(" ALE STATUS             : ONBOARDING\n");
    } else if(ale->ale_onboard_status == ALE_NODE_ONBOARDED){
        print_cb(" ALE STATUS             : ONBOARDED\n");
    }

    print_cb(" RECEIVING INTERFACE    : %s\n",            ale->iface_name);
    print_cb(" KEEP ALIVE TIME        : %"PRIu64" sec\n", ale->keep_alive_time);
    print_cb(" MANUFACTURER NAME      : %s\n",            ale->device_info.manufacturer_name);
    print_cb(" NUM OF RADIOS          : %d\n",            ale->radios_nr);
    print_cb("***********************************************\n");
    /* Print all the radio info */
    print_radios_in_agent(ale, print_cb);

    print_local_interfaces(ale, print_cb);

    print_backhaul_sta_interfaces(ale, print_cb);

    print_eth_devices(ale, print_cb);

    print_emex_eth_interfaces(ale, print_cb);

    print_mld(ale, print_cb, "", true);
}

static const char *convert_tunneled_type_to_string(uint8_t type)
{
    switch (type){
        case TUNNELED_MSG_PAYLOAD_ASSOC_REQ:
            return "ASSOC_REQ";
        case TUNNELED_MSG_PAYLOAD_REASSOC_REQ:
            return "REASSOC_REQ";
        case TUNNELED_MSG_PAYLOAD_BTM_QUERY:
            return "BTM_QUERY";
        case TUNNELED_MSG_PAYLOAD_WNM_REQ:
            return "WNM_REQ";
        case TUNNELED_MSG_PAYLOAD_ANQP_REQ:
            return "ANQP_REQ";
        default:
            return "UNKNOWN";
    }
}

static void map_print_tunneled_message(map_printf_cb_t print_cb, uint8_t *msg_body, uint16_t msg_len, uint8_t type)
{
    uint16_t i;

    if (msg_len > 0) {
        print_cb("%s BODY:\n", convert_tunneled_type_to_string(type));
        for (i = 0; i < msg_len; i++) {
            print_cb("%02x",msg_body[i]);
            if (((i + 1) % 16) == 0) {
                print_cb("\n");
            }
        }
    } else {
        print_cb("no stored %s body\n", convert_tunneled_type_to_string(type));
    }
    print_cb("\n");
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
void map_dm_dump_agent_info_tree(map_printf_cb_t print_cb)
{
    map_ale_info_t *ale;

    map_dm_foreach_agent_ale(ale) {
        print_agent_info(ale, print_cb);
        print_cb("\n\n\n");
    }

    print_cb("\n\n\n");

    /* Print the STA and BSS mapping */
    print_sta_bss_mapping(print_cb);

    print_cb("\n\n\n");

    /* Dump the Agent's topology tree */
    dump_topology_tree(print_cb);
}

void map_dm_dump_tunneled_messages(map_printf_cb_t print_cb, uint8_t *sta_mac, uint8_t type)
{
    map_sta_info_t     *sta;
    map_tunneled_msg_t *tmsg;

    if (NULL == (sta = map_dm_get_sta_gbl(sta_mac))) {
        print_cb("sta[%s] does not exist\n", mac_string(sta_mac));
        return;
    }

    if (NULL == (tmsg = sta->tunneled_msg)) {
        print_cb("sta[%s] has no tunneled messages\n", sta->mac_str);
        return;
    }

    print_cb("\nSTA:%s\n", sta->mac_str);
    switch(type) {
        case TUNNELED_MSG_PAYLOAD_ASSOC_REQ:
            map_print_tunneled_message(print_cb, tmsg->assoc_req_body, tmsg->assoc_req_body_len, type);
        break;
        case TUNNELED_MSG_PAYLOAD_REASSOC_REQ:
            map_print_tunneled_message(print_cb, tmsg->reassoc_req_body, tmsg->reassoc_req_body_len, type);
        break;
        case TUNNELED_MSG_PAYLOAD_BTM_QUERY:
            map_print_tunneled_message(print_cb, tmsg->btm_query_body, tmsg->btm_query_body_len, type);
        break;
        case TUNNELED_MSG_PAYLOAD_WNM_REQ:
            map_print_tunneled_message(print_cb, tmsg->wnm_req_body, tmsg->wnm_req_body_len, type);
        break;
        case TUNNELED_MSG_PAYLOAD_ANQP_REQ:
            map_print_tunneled_message(print_cb, tmsg->anqp_req_body, tmsg->anqp_req_body_len, type);
        break;
        default:
        break;
    }
}

void map_dm_dump_mld(map_printf_cb_t print_cb)
{
    map_ale_info_t *ale;

    map_dm_foreach_agent_ale(ale) {
        print_cb("ALE[%s]\n", ale->al_mac_str);
        print_mld(ale, print_cb, "  ", false);
        print_cb("\n");
    }
}
