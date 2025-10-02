/*
 * Copyright (c) 2019-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <arpa/inet.h>

#include "test.h"

#include "1905_tlvs.h"
#include "map_tlvs.h"

#include "utils.h"    /* print_callback */
#include "platform.h" /* PLATFORM_PRINTF */

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define ETH_CMDU_HDR_LEN    (sizeof(struct ether_header) + sizeof(cmdu_hdr_t))
#define TLVS_START          &packet->data[ETH_CMDU_HDR_LEN]
#define TLVS_LEN            (packet->len - ETH_CMDU_HDR_LEN)

#define MAX_TLV_STRUCT_SIZE 4*1024

#define VARS                         \
    packet_t  *packet;               \
    tlv_hdr_t *tlv;                  \
    uint16_t   tlv_len, f_tlv_len;   \
    uint8_t   *p_tlv, *f_tlv = NULL;

/* For code coverage (dump and compare with yourself)... */
#define VISIT_COMPARE(p_tlv) \
    if (*p_tlv <= TLV_TYPE_L2_NEIGHBOR_DEVICE) {                                    \
        visit_1905_TLV_structure(p_tlv, print_callback, PLATFORM_PRINTF, "prefix"); \
        fail_unless(compare_1905_TLV_structures(p_tlv, p_tlv) == 0);                \
    }

#define READ_PARSE(file)                                                       \
    fail_unless(!!(packet = pcap_read_first_packet(DATA_DIR "/" file)));       \
    tlv = (tlv_hdr_t *)TLVS_START;                                             \
    tlv_len = htons(tlv->len) + sizeof(tlv_hdr_t);                             \
    fail_unless(!!(p_tlv = parse_1905_TLV_from_packet(TLVS_START, TLVS_LEN))); \
    VISIT_COMPARE(p_tlv);

//TODO adapt compare function
#define READ_PARSE_FRAGMENTED(file)                                            \
    fail_unless(!!(p_tlv = read_parse_fragmented_tlv(DATA_DIR "/" file)));     \

#define CHECK_TLV_STRUCT_SIZE                                                            \
    log_test_i("%s struct size: %zu bytes", __FUNCTION__, sizeof(*t));                   \
    fail_unless(sizeof(*t) <= MAX_TLV_STRUCT_SIZE, "struct size %zu bytes", sizeof(*t));

#define FORGE                                                                  \
    fail_unless(!!(f_tlv = forge_1905_TLV_from_structure(p_tlv, &f_tlv_len))); \
    fail_unless(f_tlv_len == tlv_len);                                         \
    fail_unless(!memcmp(tlv, f_tlv, tlv_len));

#define CLEANUP                     \
    free_1905_TLV_structure(p_tlv); \
    free(f_tlv);                    \
    free(packet);

uint8_t *read_parse_fragmented_tlv(const char *file)
{
    packet_t **packets;
    size_t     packets_nr;
    uint8_t   *message = NULL;
    uint16_t   message_offset = 0;
    uint16_t   packet_len;
    uint8_t   *parsed_tlv;

    fail_unless(!!(packets = pcap_read_all_packets(file, &packets_nr)));

    for (size_t i = 0; i < packets_nr; i++) {
        packet_len = packets[i]->len - ETH_CMDU_HDR_LEN;
        message = realloc(message, packet_len + message_offset);
        memcpy(message + message_offset, packets[i]->data + ETH_CMDU_HDR_LEN, packet_len);
        message_offset += packet_len;
    }

    uint8_t *p = message;
    fail_unless(!!(parsed_tlv = parse_1905_TLV_from_packet(p, message_offset)));

    free(message);
    free_packets(packets, packets_nr);

    return parsed_tlv;
}

/*#######################################################################
#                       1905 TLVS                                       #
########################################################################*/
START_TEST(test_00_end_of_message)
{
    VARS
    READ_PARSE("tlv_00_end_of_message.pcap")

    i1905_end_of_message_tlv_t *t = (i1905_end_of_message_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_END_OF_MESSAGE);

    FORGE
    CLEANUP

}
END_TEST

START_TEST(test_01_al_mac_address)
{
    VARS
    READ_PARSE("tlv_01_al_mac_address.pcap")

    i1905_al_mac_address_tlv_t *t = (i1905_al_mac_address_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_AL_MAC_ADDRESS);
    fail_unless(!memcmp(t->al_mac_address, (mac_addr){0xf6, 0x17, 0xb8, 0xae, 0x86, 0xef}, sizeof(mac_addr)));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_02_mac_address)
{
    VARS
    READ_PARSE("tlv_02_mac_address.pcap")

    i1905_mac_address_tlv_t *t = (i1905_mac_address_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_MAC_ADDRESS);
    fail_unless(!memcmp(t->mac_address, (mac_addr){0x08, 0x00, 0x27, 0x8d, 0x68, 0x73}, sizeof(mac_addr)));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_03_device_information)
{
    VARS
    READ_PARSE("tlv_03_device_information.pcap")

    i1905_device_information_tlv_t *t = (i1905_device_information_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_DEVICE_INFORMATION);
    fail_unless(!memcmp(t->al_mac_address, (mac_addr){0xf6, 0x17, 0xb8, 0x86, 0x57, 0x68}, sizeof(mac_addr)));
    fail_unless(t->local_interfaces_nr == 4);

    /* Interface 0 */
    i1905_local_interface_entry_t *e = t->local_interfaces;
    fail_unless(!memcmp(e[0].mac_address, (mac_addr){0xf4, 0x17, 0xb8, 0x86, 0x57, 0x68}, sizeof(mac_addr)));
    fail_unless(e[0].media_type               == MEDIA_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET);
    fail_unless(e[0].media_specific_data_size == 0);

    /* Interface 1 */
    fail_unless(!memcmp(e[1].mac_address, (mac_addr){0xf4, 0x17, 0xb8, 0x86, 0x57, 0x6b}, sizeof(mac_addr)));
    fail_unless(e[1].media_type               == MEDIA_TYPE_IEEE_802_11N_2_4_GHZ);
    fail_unless(e[1].media_specific_data_size == 10);

    i1905_ieee80211_specific_information_t *s = &e[1].media_specific_data.ieee80211;
    fail_unless(!memcmp(s->network_membership, (mac_addr){0xf4, 0x17, 0xb8, 0x86, 0x57, 0x6b}, sizeof(mac_addr)));
    fail_unless(s->role                                == IEEE80211_SPECIFIC_INFO_ROLE_AP);
    fail_unless(s->ap_channel_band                     == 0);
    fail_unless(s->ap_channel_center_frequency_index_1 == 6);
    fail_unless(s->ap_channel_center_frequency_index_2 == 0);

    /* Interface 2 */
    fail_unless(!memcmp(e[2].mac_address, (mac_addr){0xf4, 0x17, 0xb8, 0x86, 0x57, 0x6a}, sizeof(mac_addr)));
    fail_unless(e[2].media_type               == MEDIA_TYPE_IEEE_802_11AC_5_GHZ);
    fail_unless(e[2].media_specific_data_size == 10);

    s = &e[2].media_specific_data.ieee80211;
    fail_unless(!memcmp(s->network_membership, (mac_addr){0xf4, 0x17, 0xb8, 0x86, 0x57, 0x6a}, sizeof(mac_addr)));
    fail_unless(s->role                                == IEEE80211_SPECIFIC_INFO_ROLE_AP);
    fail_unless(s->ap_channel_band                     == 2);
    fail_unless(s->ap_channel_center_frequency_index_1 == 173);
    fail_unless(s->ap_channel_center_frequency_index_2 == 0);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_04_device_bridging_capability)
{
    VARS
    READ_PARSE("tlv_04_device_bridging_capability.pcap")

    i1905_device_bridging_cap_tlv_t *t = (i1905_device_bridging_cap_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type           == TLV_TYPE_DEVICE_BRIDGING_CAPABILITY);
    fail_unless(t->bridging_tuples_nr == 1);

    i1905_bridging_tuple_entry_t *e = t->bridging_tuples;
    fail_unless(e->bridging_tuple_macs_nr == 4);

    i1905_bridging_tuple_mac_entry_t *m = e[0].bridging_tuple_macs;
    fail_unless(!memcmp(m[0].mac_address, (mac_addr){0xf4, 0x17, 0xb8, 0xae, 0x86, 0xf1}, sizeof(mac_addr)));
    fail_unless(!memcmp(m[1].mac_address, (mac_addr){0xf4, 0x17, 0xb8, 0xae, 0x86, 0xf2}, sizeof(mac_addr)));
    fail_unless(!memcmp(m[2].mac_address, (mac_addr){0x7a, 0x17, 0xb8, 0xae, 0x86, 0xf2}, sizeof(mac_addr)));
    fail_unless(!memcmp(m[3].mac_address, (mac_addr){0x7a, 0x17, 0xb8, 0xae, 0x86, 0xf3}, sizeof(mac_addr)));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_06_non_1905_neighbor_device_list)
{
    VARS
    READ_PARSE("tlv_06_non_1905_neighbor_device_list.pcap")

    i1905_non_1905_neighbor_device_list_tlv_t *t = (i1905_non_1905_neighbor_device_list_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST);
    fail_unless(!memcmp(t->local_mac_address, (mac_addr){0xf4, 0x17, 0xb8, 0xae, 0x86, 0xf1}, sizeof(mac_addr)));
    fail_unless(t->non_1905_neighbors_nr == 3);

    i1905_non_1905_neighbor_entry_t *e = t->non_1905_neighbors;
    fail_unless(!memcmp(e[0].mac_address, (mac_addr){0x4e, 0x8f, 0x3b, 0x88, 0xf5, 0x57}, sizeof(mac_addr)));
    fail_unless(!memcmp(e[1].mac_address, (mac_addr){0x70, 0x28, 0x8b, 0x22, 0x23, 0x93}, sizeof(mac_addr)));
    fail_unless(!memcmp(e[2].mac_address, (mac_addr){0xc8, 0xf7, 0x50, 0x4c, 0x29, 0x95}, sizeof(mac_addr)));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_07_neighbor_device_list)
{
    VARS
    READ_PARSE("tlv_07_neighbor_device_list.pcap")

    i1905_neighbor_device_list_tlv_t *t = (i1905_neighbor_device_list_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_NEIGHBOR_DEVICE_LIST);
    fail_unless(!memcmp(t->local_mac_address, (mac_addr){0xf4, 0x17, 0xb8, 0xae, 0x86, 0xf1}, sizeof(mac_addr)));
    fail_unless(t->neighbors_nr == 1);

    i1905_neighbor_entry_t *e = t->neighbors;
    fail_unless(!memcmp(e[0].mac_address, (mac_addr){0xf6, 0x17, 0xb8, 0x86, 0x57, 0x68}, sizeof(mac_addr)));
    fail_unless(e[0].bridge_flag == 0);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_08_link_metric_query)
{
    VARS
    READ_PARSE("tlv_08_link_metric_query.pcap")

    i1905_link_metric_query_tlv_t *t = (i1905_link_metric_query_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type          == TLV_TYPE_LINK_METRIC_QUERY);
    fail_unless(t->destination       == LINK_METRIC_QUERY_TLV_ALL_NEIGHBORS);
    fail_unless(t->link_metrics_type == LINK_METRIC_QUERY_TLV_BOTH_TX_AND_RX_LINK_METRICS);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_09_transmitter_link_metric)
{
    VARS
    READ_PARSE("tlv_09_transmitter_link_metric.pcap")

    i1905_transmitter_link_metric_tlv_t *t = (i1905_transmitter_link_metric_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_TRANSMITTER_LINK_METRIC);
    fail_unless(!memcmp(t->local_al_address,    (mac_addr){0x22, 0xb0, 0x01, 0xbf, 0xa2, 0xad}, sizeof(mac_addr)));
    fail_unless(!memcmp(t->neighbor_al_address, (mac_addr){0xf6, 0x17, 0xb8, 0x86, 0x57, 0x68}, sizeof(mac_addr)));
    fail_unless(t->transmitter_link_metrics_nr == 1);

    i1905_transmitter_link_metric_entry_t *e = t->transmitter_link_metrics;
    fail_unless(!memcmp(e[0].local_interface_address,    (mac_addr){0x20, 0xb0, 0x01, 0xbf, 0xa2, 0xac}, sizeof(mac_addr)));
    fail_unless(!memcmp(e[0].neighbor_interface_address, (mac_addr){0xf4, 0x17, 0xb8, 0x86, 0x57, 0x68}, sizeof(mac_addr)));
    fail_unless(e[0].intf_type               == MEDIA_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET);
    fail_unless(e[0].bridge_flag             == 0);
    fail_unless(e[0].packet_errors           == 0);
    fail_unless(e[0].transmitted_packets     == 145436);
    fail_unless(e[0].mac_throughput_capacity == 1000);
    fail_unless(e[0].link_availability       == 100);
    fail_unless(e[0].phy_rate                == 1000);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_0A_receiver_link_metric)
{
    VARS
    READ_PARSE("tlv_0A_receiver_link_metric.pcap")

    i1905_receiver_link_metric_tlv_t *t = (i1905_receiver_link_metric_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_RECEIVER_LINK_METRIC);
    fail_unless(!memcmp(t->local_al_address,    (mac_addr){0x22, 0xb0, 0x01, 0xbf, 0xa2, 0xad}, sizeof(mac_addr)));
    fail_unless(!memcmp(t->neighbor_al_address, (mac_addr){0xf6, 0x17, 0xb8, 0x86, 0x57, 0x68}, sizeof(mac_addr)));
    fail_unless(t->receiver_link_metrics_nr == 1);

    i1905_receiver_link_metric_entry_t *e = t->receiver_link_metrics;
    fail_unless(!memcmp(e[0].local_interface_address,    (mac_addr){0x20, 0xb0, 0x01, 0xbf, 0xa2, 0xac}, sizeof(mac_addr)));
    fail_unless(!memcmp(e[0].neighbor_interface_address, (mac_addr){0xf4, 0x17, 0xb8, 0x86, 0x57, 0x68}, sizeof(mac_addr)));
    fail_unless(e[0].intf_type        == MEDIA_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET);
    fail_unless(e[0].packet_errors    == 0);
    fail_unless(e[0].packets_received == 158684);
    fail_unless(e[0].rssi             == 255);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_0B_vendor_specific)
{
    VARS
    READ_PARSE("tlv_0B_vendor_specific.pcap")

    i1905_vendor_specific_tlv_t *t = (i1905_vendor_specific_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_VENDOR_SPECIFIC);
    fail_unless(t->vendorOUI[0] == 0x00 && t->vendorOUI[1] == 0x10 && t->vendorOUI[2] == 0x18);
    fail_unless(!memcmp(t->vendorOUI, (uint8_t[]){0x00, 0x10, 0x18}, 3));
    fail_unless(t->m && t->m_nr == 29);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_0C_link_metric_result_code)
{
    VARS
    READ_PARSE("tlv_0C_link_metric_result_code.pcap")

    i1905_link_metric_result_code_tlv_t *t = (i1905_link_metric_result_code_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type    == TLV_TYPE_LINK_METRIC_RESULT_CODE);
    fail_unless(t->result_code == LINK_METRIC_RESULT_CODE_TLV_INVALID_NEIGHBOR);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_0D_searched_role)
{
    VARS
    READ_PARSE("tlv_0D_searched_role.pcap")

    i1905_searched_role_tlv_t *t = (i1905_searched_role_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_SEARCHED_ROLE);
    fail_unless(t->role == IEEE80211_ROLE_REGISTRAR);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_0E_autoconfig_freq_band)
{
    VARS
    READ_PARSE("tlv_0E_autoconfig_freq_band.pcap")

    i1905_autoconfig_freq_band_tlv_t *t = ( i1905_autoconfig_freq_band_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_AUTOCONFIG_FREQ_BAND);
    fail_unless(t->freq_band == IEEE80211_FREQUENCY_BAND_2_4_GHZ);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_0F_supported_role)
{
    VARS
    READ_PARSE("tlv_0F_supported_role.pcap")

    i1905_supported_role_tlv_t *t = (i1905_supported_role_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_SUPPORTED_ROLE);
    fail_unless(t->role == IEEE80211_ROLE_REGISTRAR);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_10_supported_freq_band)
{
    VARS
    READ_PARSE("tlv_10_supported_freq_band.pcap")

    i1905_supported_freq_band_tlv_t *t = (i1905_supported_freq_band_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_SUPPORTED_FREQ_BAND);
    fail_unless(t->freq_band == IEEE80211_FREQUENCY_BAND_5_GHZ);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_11_wsc)
{
    VARS
    READ_PARSE("tlv_11_wsc.pcap")

    i1905_wsc_tlv_t *t = (i1905_wsc_tlv_t  *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_WSC);
    fail_unless(t->wsc_frame != NULL);
    fail_unless(t->wsc_frame_size == 426);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_12_push_button_event_notification)
{
    VARS
    READ_PARSE("tlv_12_push_button_event_notification.pcap")

    i1905_push_button_event_notification_tlv_t *t = (i1905_push_button_event_notification_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION);
    fail_unless(t->media_types_nr == 1);
    fail_unless(t->media_types[0].media_type == MEDIA_TYPE_IEEE_802_11N_2_4_GHZ);
    fail_unless(t->media_types[0].media_specific_data_size == 10);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_13_push_button_join_notification)
{
    VARS
    READ_PARSE("tlv_13_push_button_join_notification.pcap")

    i1905_push_button_join_notification_tlv_t *t = (i1905_push_button_join_notification_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION);
    fail_unless(!memcmp(t->al_mac_address,  (mac_addr){0x02, 0x01, 0x02, 0x03, 0x04, 0x05}, sizeof(mac_addr)));
    fail_unless(!memcmp(t->mac_address,     (mac_addr){0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, sizeof(mac_addr)));
    fail_unless(!memcmp(t->new_mac_address, (mac_addr){0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E}, sizeof(mac_addr)));
    fail_unless(t->message_identifier == 0x1234);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_14_generic_phy_device_information)
{
    VARS
    READ_PARSE("tlv_14_generic_phy_device_information.pcap")

    i1905_generic_phy_device_information_tlv_t *t = (i1905_generic_phy_device_information_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_GENERIC_PHY_DEVICE_INFORMATION);
    fail_unless(!memcmp(t->al_mac_address,  (mac_addr){0x02, 0x01, 0x02, 0x03, 0x04, 0x05}, sizeof(mac_addr)));
    fail_unless(t->local_interfaces_nr == 1);
    fail_unless(!memcmp(t->local_interfaces[0].local_interface_address, (mac_addr){0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, sizeof(mac_addr)));
    fail_unless(!strcmp((char *)t->local_interfaces[0].variant_name, "wireless"));
    fail_unless(t->local_interfaces[0].generic_phy_description_xml_url_len == 16);
    fail_unless(!strcmp(t->local_interfaces[0].generic_phy_description_xml_url, "http://test.com"));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_15_device_identification)
{
    VARS
    READ_PARSE("tlv_15_device_identification.pcap")

    i1905_device_identification_tlv_t *t = (i1905_device_identification_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_DEVICE_IDENTIFICATION);
    fail_unless(!strcmp(t->friendly_name, "Airties Air4960"));
    fail_unless(!strcmp(t->manufacturer_name, "Airties"));
    fail_unless(!strcmp(t->manufacturer_model, "Air4960"));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_16_control_url)
{
    VARS
    READ_PARSE("tlv_16_control_url.pcap")

    i1905_control_url_tlv_t *t = (i1905_control_url_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_CONTROL_URL);
    fail_unless(!strcmp(t->url, "http://test.com"));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_17_ipv4)
{
    VARS
    READ_PARSE("tlv_17_ipv4.pcap")

    i1905_ipv4_tlv_t *t = (i1905_ipv4_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_IPV4);
    fail_unless(t->ipv4_interfaces_nr == 1);
    fail_unless(!memcmp(t->ipv4_interfaces[0].mac_address, (mac_addr){0x02, 0x01, 0x02, 0x03, 0x04, 0x05}, sizeof(mac_addr)));
    fail_unless(t->ipv4_interfaces[0].ipv4_nr == 1);
    fail_unless(t->ipv4_interfaces[0].ipv4[0].type == IPV4_TYPE_DHCP);
    fail_unless(!memcmp(t->ipv4_interfaces[0].ipv4[0].ipv4_address,     (uint8_t[]){0xC0,0xA8,0x01,0x02}, 4));
    fail_unless(!memcmp(t->ipv4_interfaces[0].ipv4[0].ipv4_dhcp_server, (uint8_t[]){0xC0,0xA8,0x01,0x01}, 4));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_18_ipv6)
{
    VARS
    READ_PARSE("tlv_18_ipv6.pcap")

    i1905_ipv6_tlv_t *t = (i1905_ipv6_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_IPV6);
    fail_unless(t->ipv6_interfaces_nr == 1);
    fail_unless(!memcmp(t->ipv6_interfaces[0].mac_address, (mac_addr){0x02, 0x01, 0x02, 0x03, 0x04, 0x05}, sizeof(mac_addr)));
    fail_unless(t->ipv6_interfaces[0].ipv6_nr == 1);
    fail_unless(t->ipv6_interfaces[0].ipv6[0].type == IPV4_TYPE_DHCP);
    fail_unless(!memcmp(t->ipv6_interfaces[0].ipv6_link_local_address,     (uint8_t[]){0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01}, 16));
    fail_unless(!memcmp(t->ipv6_interfaces[0].ipv6[0].ipv6_address,        (uint8_t[]){0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02}, 16));
    fail_unless(!memcmp(t->ipv6_interfaces[0].ipv6[0].ipv6_address_origin, (uint8_t[]){0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03}, 16));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_19_generic_phy_event_notification)
{
    VARS
    READ_PARSE("tlv_19_generic_phy_event_notification.pcap")

    i1905_generic_phy_event_notification_tlv_t *t = (i1905_generic_phy_event_notification_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_GENERIC_PHY_EVENT_NOTIFICATION);
    /* TODO */

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_1A_1905_profile_version)
{
    VARS
    READ_PARSE("tlv_1A_1905_profile_version.pcap")

    i1905_profile_version_tlv_t *t = (i1905_profile_version_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_1905_PROFILE_VERSION);
    fail_unless(t->profile == PROFILE_1905_1A);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_1B_power_off_interface)
{
    VARS
    READ_PARSE("tlv_1B_power_off_interface.pcap")

    i1905_power_off_interface_tlv_t *t = (i1905_power_off_interface_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_POWER_OFF_INTERFACE);
    /* TODO */

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_1C_interface_power_change_information)
{
    VARS
    READ_PARSE("tlv_1C_interface_power_change_information.pcap")

    i1905_interface_power_change_information_tlv_t *t = (i1905_interface_power_change_information_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_INTERFACE_POWER_CHANGE_INFORMATION);
    /* TODO */

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_1D_interface_power_change_status)
{
    VARS
    READ_PARSE("tlv_1D_interface_power_change_status.pcap")

    i1905_interface_power_change_status_tlv_t *t = (i1905_interface_power_change_status_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_INTERFACE_POWER_CHANGE_STATUS);
    /* TODO */

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_1E_l2_neighbor_device)
{
    VARS
    READ_PARSE("tlv_1E_l2_neighbor_device.pcap");

    i1905_l2_neighbor_device_tlv_t *t = (i1905_l2_neighbor_device_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_L2_NEIGHBOR_DEVICE);
    fail_unless(t->local_interfaces_nr == 1);
    fail_unless(!memcmp(t->local_interfaces[0].local_mac_address, (mac_addr){0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, sizeof(mac_addr)));
    fail_unless(t->local_interfaces[0].l2_neighbors_nr == 1);
    fail_unless(!memcmp(t->local_interfaces[0].l2_neighbors[0].l2_neighbor_mac_address, (mac_addr){0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E}, sizeof(mac_addr)));
    fail_unless(t->local_interfaces[0].l2_neighbors[0].behind_mac_addresses_nr == 1);
    fail_unless(!memcmp(t->local_interfaces[0].l2_neighbors[0].behind_mac_addresses[0], (mac_addr){0x00, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E}, sizeof(mac_addr)));

    FORGE
    CLEANUP
}
END_TEST

/*#######################################################################
#                       MAP R1 TLVS                                     #
########################################################################*/
START_TEST(test_80_supported_service)
{
    VARS
    READ_PARSE("tlv_80_supported_service.pcap")

    map_supported_service_tlv_t *t = (map_supported_service_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type    == TLV_TYPE_SUPPORTED_SERVICE);
    fail_unless(t->services_nr == 1);
    fail_unless(t->services[0] == MAP_SERVICE_AGENT);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_81_searched_service)
{
    VARS
    READ_PARSE("tlv_81_searched_service.pcap")

    map_searched_service_tlv_t *t = (map_searched_service_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_SEARCHED_SERVICE);
    fail_unless(t->services_nr == 1);
    fail_unless(t->services[0] == MAP_SERVICE_CONTROLLER);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_82_ap_radio_identifier)
{
    VARS
    READ_PARSE("tlv_82_ap_radio_identifier.pcap")

    map_ap_radio_identifier_tlv_t *t = (map_ap_radio_identifier_tlv_t  *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_AP_RADIO_IDENTIFIER);
    fail_unless(!memcmp(t->radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6A}, sizeof(mac_addr)));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_83_ap_operational_bss)
{
    VARS
    READ_PARSE("tlv_83_ap_operational_bss.pcap")

    map_ap_operational_bss_tlv_t *t = (map_ap_operational_bss_tlv_t  *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_AP_OPERATIONAL_BSS);
    fail_unless(t->radios_nr == 2);

    fail_unless(!memcmp(t->radios[0].radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(t->radios[0].bsss_nr == 1);
    fail_unless(!memcmp(t->radios[0].bsss[0].bssid, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(t->radios[0].bsss[0].ssid_len == 11);
    fail_unless(!memcmp(t->radios[0].bsss[0].ssid, (char *)"frv_test_fh", 11));

    fail_unless(!memcmp(t->radios[1].radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6A}, sizeof(mac_addr)));
    fail_unless(t->radios[1].bsss_nr == 2);
    fail_unless(!memcmp(t->radios[1].bsss[0].bssid, (mac_addr){0x6A, 0x17, 0xB8, 0x86, 0x57, 0x6C}, sizeof(mac_addr)));
    fail_unless(t->radios[1].bsss[0].ssid_len == 11);
    fail_unless(!memcmp(t->radios[1].bsss[0].ssid, (char *)"frv_test_bh", 11));
    fail_unless(!memcmp(t->radios[1].bsss[1].bssid, (mac_addr){0x6A, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(t->radios[1].bsss[1].ssid_len == 11);
    fail_unless(!memcmp(t->radios[1].bsss[1].ssid, (char *)"frv_test_fh", 11));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_84_associated_clients)
{
    VARS
    READ_PARSE("tlv_84_associated_clients.pcap")

    map_assoc_clients_tlv_t *t = (map_assoc_clients_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_ASSOCIATED_CLIENTS);
    fail_unless(t->bsss_nr == 1);
    fail_unless(!memcmp(t->bsss[0].bssid, (mac_addr){0x22, 0xB0, 0x01, 0xBF, 0xA2, 0xB5}, sizeof(mac_addr)));
    fail_unless(t->bsss[0].stas_nr == 1);
    fail_unless(!memcmp(t->bsss[0].stas[0].mac, (mac_addr){0x4E, 0x8F, 0x3B, 0x88, 0xF5, 0x57}, sizeof(mac_addr)));
    fail_unless(t->bsss[0].stas[0].assoc_time == 775);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_85_ap_radio_basic_capabilities)
{
    VARS
    READ_PARSE("tlv_85_ap_radio_basic_capabilities.pcap")

    map_ap_radio_basic_cap_tlv_t *t = (map_ap_radio_basic_cap_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_AP_RADIO_BASIC_CAPABILITIES);
    fail_unless(!memcmp(t->radio_id, (mac_addr){0x22, 0xB0, 0x01, 0xBF, 0xA2, 0xB5}, sizeof(mac_addr)));
    fail_unless(t->max_bss       == 2);
    fail_unless(t->op_classes_nr == 10);
    fail_unless(t->op_classes[0].op_class             == 115);
    fail_unless(t->op_classes[0].eirp                 == 21);
    fail_unless(map_cs_nr(&t->op_classes[0].channels) == 3);
    fail_unless(map_cs_is_set(&t->op_classes[0].channels, 40));
    fail_unless(map_cs_is_set(&t->op_classes[0].channels, 44));
    fail_unless(map_cs_is_set(&t->op_classes[0].channels, 48));

    fail_unless(t->op_classes[9].op_class             == 129);
    fail_unless(t->op_classes[9].eirp                 == 21);
    fail_unless(map_cs_nr(&t->op_classes[9].channels) == 2);
    fail_unless(map_cs_is_set(&t->op_classes[9].channels, 50));
    fail_unless(map_cs_is_set(&t->op_classes[9].channels, 114));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_86_ap_ht_capabilities)
{
    VARS
    READ_PARSE("tlv_86_ap_ht_capabilities.pcap")

    map_ap_ht_cap_tlv_t *t = (map_ap_ht_cap_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_AP_HT_CAPABILITIES);
    fail_unless(!memcmp(t->radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0xAE, 0x86, 0xF2}, sizeof(mac_addr)));
    fail_unless(t->max_supported_tx_streams == 1);
    fail_unless(t->max_supported_rx_streams == 1);
    fail_unless(t->gi_support_20mhz         == 1);
    fail_unless(t->gi_support_40mhz         == 1);
    fail_unless(t->ht_support_40mhz         == 1);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_87_ap_vht_capabilities)
{
    VARS
    READ_PARSE("tlv_87_ap_vht_capabilities.pcap")

    map_ap_vht_cap_tlv_t *t = (map_ap_vht_cap_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_AP_VHT_CAPABILITIES);
    fail_unless(!memcmp(t->radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0xAE, 0x86, 0xF2}, sizeof(mac_addr)));
    fail_unless(t->supported_tx_mcs         == 0xfffa);
    fail_unless(t->supported_rx_mcs         == 0xfffa);
    fail_unless(t->max_supported_tx_streams == 1);
    fail_unless(t->max_supported_rx_streams == 1);
    fail_unless(t->gi_support_80mhz         == 1);
    fail_unless(t->gi_support_160mhz        == 0);
    fail_unless(t->support_80_80_mhz        == 0);
    fail_unless(t->support_160mhz           == 0);
    fail_unless(t->su_beamformer_capable    == 1);
    fail_unless(t->mu_beamformer_capable    == 1);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_88_ap_he_capabilities)
{
    VARS
    READ_PARSE("tlv_88_ap_he_capabilities.pcap")

    map_ap_he_cap_tlv_t *t = (map_ap_he_cap_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_AP_HE_CAPABILITIES);
    fail_unless(!memcmp(t->radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0xAE, 0x86, 0xF1}, sizeof(mac_addr)));
    fail_unless(t->supported_mcs_length == 8);
    fail_unless(!memcmp(t->supported_tx_rx_mcs, (uint16_t[]){0xFFAA, 0xFFAA, 0xFFAA, 0xFFAA}, 8));
    fail_unless(t->max_supported_tx_streams == 3);
    fail_unless(t->max_supported_rx_streams == 3);
    fail_unless(t->support_80_80_mhz        == 0);
    fail_unless(t->support_160mhz           == 1);
    fail_unless(t->su_beamformer_capable    == 1);
    fail_unless(t->mu_beamformer_capable    == 1);
    fail_unless(t->ul_mimo_capable          == 0);
    fail_unless(t->ul_mimo_ofdma_capable    == 0);
    fail_unless(t->dl_mimo_ofdma_capable    == 1);
    fail_unless(t->ul_ofdma_capable         == 1);
    fail_unless(t->dl_ofdma_capable         == 1);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_89_steering_policy)
{
    VARS
    READ_PARSE("tlv_89_steering_policy.pcap")

    map_steering_policy_tlv_t *t = (map_steering_policy_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type                   == TLV_TYPE_STEERING_POLICY);
    fail_unless(t->local_steering_dis_macs_nr == 0);
    fail_unless(t->btm_steering_dis_macs_nr   == 0);
    fail_unless(t->radios_nr                  == 2);

    fail_unless(!memcmp(t->radios[0].radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(t->radios[0].steering_policy               == 0);
    fail_unless(t->radios[0].channel_utilization_threshold == 0);
    fail_unless(t->radios[0].rssi_steering_threshold       == 0);

    fail_unless(!memcmp(t->radios[1].radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6A}, sizeof(mac_addr)));
    fail_unless(t->radios[1].steering_policy               == 0);
    fail_unless(t->radios[1].channel_utilization_threshold == 0);
    fail_unless(t->radios[1].rssi_steering_threshold       == 0);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_89_steering_policy_2)
{
    VARS
    READ_PARSE("tlv_89_steering_policy_2.pcap")

    map_steering_policy_tlv_t *t = (map_steering_policy_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type                   == TLV_TYPE_STEERING_POLICY);
    fail_unless(t->local_steering_dis_macs_nr == 0);
    fail_unless(t->btm_steering_dis_macs_nr   == 1);
    fail_unless(t->radios_nr                  == 0);
    fail_unless(!memcmp(&t->btm_steering_dis_macs[0], (mac_addr){0x4E, 0x8F, 0x3B, 0x88, 0xF5, 0x57}, sizeof(mac_addr)));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_8A_metric_reporting_policy)
{
    VARS
    READ_PARSE("tlv_8A_metric_reporting_policy.pcap")

    map_metric_reporting_policy_tlv_t *t = (map_metric_reporting_policy_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type                  == TLV_TYPE_METRIC_REPORTING_POLICY);
    fail_unless(t->metric_reporting_interval == 1);
    fail_unless(t->radios_nr                 == 2);

    fail_unless(!memcmp(t->radios[0].radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(t->radios[0].reporting_rssi_threshold                == 0);
    fail_unless(t->radios[0].reporting_rssi_margin_override          == 0);
    fail_unless(t->radios[0].channel_utilization_reporting_threshold == 0);
    fail_unless(t->radios[0].associated_sta_policy                   == (MAP_METRIC_POLICY_TRAFFIC_STATS |
                                                                         MAP_METRIC_POLICY_LINK_METRICS  |
                                                                         MAP_METRIC_POLICY_WIFI_6_STATS));

    fail_unless(!memcmp(t->radios[1].radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6A}, sizeof(mac_addr)));
    fail_unless(t->radios[1].reporting_rssi_threshold                == 0);
    fail_unless(t->radios[1].reporting_rssi_margin_override          == 0);
    fail_unless(t->radios[1].channel_utilization_reporting_threshold == 0);
    fail_unless(t->radios[1].associated_sta_policy                   == (MAP_METRIC_POLICY_TRAFFIC_STATS |
                                                                         MAP_METRIC_POLICY_LINK_METRICS  |
                                                                         MAP_METRIC_POLICY_WIFI_6_STATS));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_8B_channel_preference)
{
    VARS
    READ_PARSE("tlv_8B_channel_preference.pcap")

    map_channel_preference_tlv_t *t = (map_channel_preference_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_CHANNEL_PREFERENCE);
    fail_unless(!memcmp(t->radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0xBD, 0xBD, 0xFE}, sizeof(mac_addr)));
    fail_unless(t->op_classes_nr == 20);

    fail_unless(t->op_classes[0].op_class             == 81);
    fail_unless(map_cs_nr(&t->op_classes[0].channels) == 0);
    fail_unless(t->op_classes[0].pref                 == 0xE);
    fail_unless(t->op_classes[0].reason               == 0xA);

    fail_unless(t->op_classes[5].op_class             == 116);
    fail_unless(map_cs_nr(&t->op_classes[5].channels) == 1);
    fail_unless(map_cs_is_set(&t->op_classes[5].channels, 44));
    fail_unless(t->op_classes[5].pref                 == 0);
    fail_unless(t->op_classes[5].reason               == 0);

    fail_unless(t->op_classes[19].op_class    == 130);
    fail_unless(map_cs_nr(&t->op_classes[19].channels) == 0);
    fail_unless(t->op_classes[19].pref                 == 0);
    fail_unless(t->op_classes[19].reason               == 0);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_8C_radio_operation_restriction)
{
    VARS
    READ_PARSE("tlv_8C_radio_operation_restriction.pcap")

    map_radio_operation_restriction_tlv_t *t = (map_radio_operation_restriction_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_RADIO_OPERATION_RESTRICTION);
    fail_unless(!memcmp(t->radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(t->op_classes_nr == 2);

    fail_unless(t->op_classes[0].op_class    == 128);
    fail_unless(t->op_classes[0].channels_nr == 2);
    fail_unless(t->op_classes[0].channels[0].channel          == 44);
    fail_unless(t->op_classes[0].channels[0].freq_restriction == 1);
    fail_unless(t->op_classes[0].channels[1].channel          == 112);
    fail_unless(t->op_classes[0].channels[1].freq_restriction == 2);

    fail_unless(t->op_classes[1].op_class    == 129);
    fail_unless(t->op_classes[1].channels_nr == 1);
    fail_unless(t->op_classes[1].channels[0].channel         == 100);
    fail_unless(t->op_classes[1].channels[0].freq_restriction == 3);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_8D_transmit_power_limit)
{
    VARS
    READ_PARSE("tlv_8D_transmit_power_limit.pcap")

    map_transmit_power_limit_tlv_t *t = (map_transmit_power_limit_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_TRANSMIT_POWER_LIMIT);
    fail_unless(!memcmp(t->radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(t->transmit_power_eirp == 23);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_8E_channel_selection_response)
{
    VARS
    READ_PARSE("tlv_8E_channel_selection_response.pcap")

    map_channel_selection_response_tlv_t *t = (map_channel_selection_response_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_CHANNEL_SELECTION_RESPONSE);
    fail_unless(!memcmp(t->radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(t->channel_selection_response == 0x02);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_8F_operating_channel_report)
{
    VARS
    READ_PARSE("tlv_8F_operating_channel_report.pcap")

    map_operating_channel_report_tlv_t *t = (map_operating_channel_report_tlv_t  *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_OPERATING_CHANNEL_REPORT);
    fail_unless(!memcmp(t->radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0xAE, 0x86, 0xF1}, sizeof(mac_addr)));
    fail_unless(t->transmit_power_eirp == 23);
    fail_unless(t->op_classes_nr == 3);

    fail_unless(t->op_classes[0].op_class == 128);
    fail_unless(t->op_classes[0].channel  == 171);

    fail_unless(t->op_classes[1].op_class == 126);
    fail_unless(t->op_classes[1].channel  == 173);

    fail_unless(t->op_classes[2].op_class == 125);
    fail_unless(t->op_classes[2].channel  == 173);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_90_client_info)
{
    VARS
    READ_PARSE("tlv_90_client_info.pcap")

    map_client_info_tlv_t *t = (map_client_info_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_CLIENT_INFO);
    fail_unless(!memcmp(t->bssid,  (mac_addr){0x6A, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(!memcmp(t->sta_mac,(mac_addr){0xF4, 0x17, 0xB8, 0xAE, 0x86, 0xF1}, sizeof(mac_addr)));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_91_client_capability_report)
{
    VARS
    READ_PARSE("tlv_91_client_capability_report.pcap")

    map_client_cap_report_tlv_t *t = (map_client_cap_report_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type             == TLV_TYPE_CLIENT_CAPABILITY_REPORT);
    fail_unless(t->result_code          == 0);
    fail_unless(t->assoc_frame_body_len == 268);
    fail_unless(t->assoc_frame_body     != NULL);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_92_client_association_event)
{
    VARS
    READ_PARSE("tlv_92_client_association_event.pcap")

    map_client_assoc_event_tlv_t *t = (map_client_assoc_event_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_CLIENT_ASSOCIATION_EVENT);
    fail_unless(!memcmp(t->sta_mac, (mac_addr){0x70, 0x28, 0x8B, 0x22, 0x23, 0x93}, sizeof(mac_addr)));
    fail_unless(!memcmp(t->bssid,   (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(t->association_event == 0);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_93_ap_metric_query)
{
    VARS
    READ_PARSE("tlv_93_ap_metric_query.pcap")

    map_ap_metric_query_tlv_t *t = (map_ap_metric_query_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_AP_METRIC_QUERY);
    fail_unless(t->bssids_nr  == 2);
    fail_unless(!memcmp(t->bssids[0], (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6A}, sizeof(mac_addr)));
    fail_unless(!memcmp(t->bssids[1], (mac_addr){0x6A, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_94_ap_metrics)
{
    VARS
    READ_PARSE("tlv_94_ap_metrics.pcap")

    map_ap_metrics_tlv_t *t = (map_ap_metrics_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_AP_METRICS);
    fail_unless(!memcmp(t->bssid, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(t->channel_util == 40);
    fail_unless(t->stas_nr      == 0);
    fail_unless(t->esp_present  == 0x80);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_95_sta_mac_address)
{
    VARS
    READ_PARSE("tlv_95_sta_mac_address.pcap")

    map_sta_mac_address_tlv_t *t = (map_sta_mac_address_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_STA_MAC_ADDRESS);
    fail_unless(!memcmp(t->sta_mac, (mac_addr){0x70, 0x28, 0x8B, 0x22, 0x23, 0x93}, sizeof(mac_addr)));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_96_associated_sta_link_metrics)
{
    VARS
    READ_PARSE("tlv_96_associated_sta_link_metrics.pcap")

    map_assoc_sta_link_metrics_tlv_t *t = (map_assoc_sta_link_metrics_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_ASSOCIATED_STA_LINK_METRICS);
    fail_unless(!memcmp(t->sta_mac, (mac_addr){0x4E, 0x8F, 0x3B, 0x88, 0xF5, 0x57}, sizeof(mac_addr)));
    fail_unless(t->bsss_nr == 1);
    fail_unless(!memcmp(t->bsss[0].bssid, (mac_addr){0x22, 0xB0, 0x01, 0xBF, 0xA2, 0xB5}, sizeof(mac_addr)));
    fail_unless(t->bsss[0].report_time_interval == 593);
    fail_unless(t->bsss[0].downlink_data_rate   == 541);
    fail_unless(t->bsss[0].uplink_data_rate     == 6);
    fail_unless(t->bsss[0].uplink_rcpi          == 112);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_97_unassociated_sta_link_metrics_query)
{
    VARS
    READ_PARSE("tlv_97_unassociated_sta_link_metrics_query.pcap")

    map_unassoc_sta_link_metrics_query_tlv_t *t = (map_unassoc_sta_link_metrics_query_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type       == TLV_TYPE_UNASSOCIATED_STA_LINK_METRICS_QUERY);
    fail_unless(t->op_class       == 128);
    fail_unless(t->channels_nr    == 1);
    fail_unless(t->channels[0].channel == 112);
    fail_unless(t->channels[0].sta_macs_nr == 1);
    fail_unless(!memcmp(t->channels[0].sta_macs[0], (mac_addr){0x4E, 0x8F, 0x3B, 0x88, 0xF5, 0x57}, sizeof(mac_addr)));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_98_unassociated_sta_link_metrics_response)
{
    VARS
    READ_PARSE("tlv_98_unassociated_sta_link_metrics_response.pcap")

    map_unassoc_sta_link_metrics_response_tlv_t *t = (map_unassoc_sta_link_metrics_response_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_UNASSOCIATED_STA_LINK_METRICS_RESPONSE);
    fail_unless(t->op_class == 81);
    fail_unless(t->stas_nr  == 1);
    fail_unless(!memcmp(t->stas[0].mac, (mac_addr){0x70, 0x28, 0x8B, 0x22, 0x23, 0x93}, sizeof(mac_addr)));
    fail_unless(t->stas[0].channel     == 6);
    fail_unless(t->stas[0].time_delta  == 0);
    fail_unless(t->stas[0].rcpi_uplink == 134);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_99_beacon_metrics_query)
{
    VARS
    READ_PARSE("tlv_99_beacon_metrics_query.pcap")

    map_beacon_metrics_query_tlv_t *t = (map_beacon_metrics_query_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_BEACON_METRICS_QUERY);
    fail_unless(!memcmp(t->sta_mac, (mac_addr){0x4E, 0x8F, 0x3B, 0x88, 0xF5, 0x57}, sizeof(mac_addr)));
    fail_unless(!memcmp(t->bssid, (mac_addr){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, sizeof(mac_addr)));
    fail_unless(t->op_class         == 121);
    fail_unless(t->channel          == 255);
    fail_unless(t->reporting_detail == 0);
    fail_unless(t->element_ids_nr   == 0);
    fail_unless(t->ssid_len         == 11);
    fail_unless(!memcmp(t->ssid, (char *)"frv_test_fh", 11));
    fail_unless(t->ap_channel_reports_nr == 2);
    fail_unless(t->ap_channel_reports[0].op_class             == 121);
    fail_unless(map_cs_nr(&t->ap_channel_reports[0].channels) == 1);
    fail_unless(map_cs_is_set(&t->ap_channel_reports[0].channels, 112));
    fail_unless(t->ap_channel_reports[1].op_class             == 81);
    fail_unless(map_cs_nr(&t->ap_channel_reports[1].channels) == 1);
    fail_unless(map_cs_is_set(&t->ap_channel_reports[1].channels, 6));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_9A_beacon_metrics_response)
{
    VARS
    READ_PARSE("tlv_9A_beacon_metrics_response.pcap")

    map_beacon_metrics_response_tlv_t *t = (map_beacon_metrics_response_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_BEACON_METRICS_RESPONSE);
    fail_unless(!memcmp(t->sta_mac, (mac_addr){0x4E, 0x8F, 0x3B, 0x88, 0xF5, 0x57}, sizeof(mac_addr)));
    fail_unless(t->status_code  == 0);
    fail_unless(t->elements_nr == 2);
    fail_unless(t->elements[0].rcpi == 112);
    fail_unless(!memcmp(t->elements[0].bssid, (mac_addr){0x22, 0xB0, 0x01, 0xBF, 0xA2, 0xB5}, sizeof(mac_addr)));
    fail_unless(t->elements[1].rcpi == 134);
    fail_unless(!memcmp(t->elements[1].bssid, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_9B_steering_request)
{
    VARS
    READ_PARSE("tlv_9B_steering_request.pcap")

    map_steering_request_tlv_t *t = (map_steering_request_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_STEERING_REQUEST);
    fail_unless(!memcmp(t->bssid, (mac_addr){0x22, 0xB0, 0x01, 0xBF, 0xA2, 0xB5}, sizeof(mac_addr)));
    fail_unless(t->flag                 == (MAP_STEERING_REQUEST_FLAG_MANDATE | MAP_STEERING_REQUEST_FLAG_BTM_DISASSOC_IMMINENT | MAP_STEERING_REQUEST_FLAG_BTM_ABRIDGED));
    fail_unless(t->opportunity_wnd      == 0);
    fail_unless(t->disassociation_timer == 6000);
    fail_unless(t->sta_macs_nr          == 1);
    fail_unless(!memcmp(t->sta_macs[0], (mac_addr){0x4E, 0x8F, 0x3B, 0x88, 0xF5, 0x57}, sizeof(mac_addr)));
    fail_unless(t->target_bsss_nr       == 1);
    fail_unless(!memcmp(t->target_bsss[0].bssid, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(t->target_bsss[0].op_class == 81);
    fail_unless(t->target_bsss[0].channel  == 6);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_9C_steering_btm_report)
{
    VARS
    READ_PARSE("tlv_9C_steering_btm_report.pcap")

    map_steering_btm_report_tlv_t *t = (map_steering_btm_report_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_STEERING_BTM_REPORT);
    fail_unless(!memcmp(t->bssid, (mac_addr){0x22, 0xB0, 0x01, 0xBF, 0xA2, 0xB5}, sizeof(mac_addr)));
    fail_unless(!memcmp(t->sta_mac, (mac_addr){0x4E, 0x8F, 0x3B, 0x88, 0xF5, 0x57}, sizeof(mac_addr)));
    fail_unless(t->btm_status_code      == 0);
    fail_unless(t->target_bssid_present == 1);
    fail_unless(!memcmp(t->target_bssid, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_9D_client_association_control_request)
{
    VARS
    READ_PARSE("tlv_9D_client_association_control_request.pcap")

    map_client_assoc_control_request_tlv_t *t = (map_client_assoc_control_request_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_CLIENT_ASSOCIATION_CONTROL_REQUEST);
    fail_unless(!memcmp(t->bssid, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(t->association_control == 0);
    fail_unless(t->validity_period     == 30);
    fail_unless(t->sta_macs_nr         == 1);
    fail_unless(!memcmp(t->sta_macs[0], (mac_addr){0x4E, 0x8F, 0x3B, 0x88, 0xF5, 0x57}, sizeof(mac_addr)));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_9E_backhaul_steering_request)
{
    VARS
    READ_PARSE("tlv_9E_backhaul_steering_request.pcap")

    map_backhaul_steering_request_tlv_t *t = (map_backhaul_steering_request_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_BACKHAUL_STEERING_REQUEST);
    fail_unless(!memcmp(t->bsta_mac,     (mac_addr){0xF4, 0x17, 0xB8, 0xAE, 0x86, 0xF1}, sizeof(mac_addr)));
    fail_unless(!memcmp(t->target_bssid, (mac_addr){0x22, 0xB0, 0x01, 0xBF, 0xA2, 0xB5}, sizeof(mac_addr)));
    fail_unless(t->target_op_class == 121);
    fail_unless(t->target_channel  == 112);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_9F_backhaul_steering_response)
{
    VARS
    READ_PARSE("tlv_9F_backhaul_steering_response.pcap")

    map_backhaul_steering_response_tlv_t *t = (map_backhaul_steering_response_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_BACKHAUL_STEERING_RESPONSE);
    fail_unless(!memcmp(t->bsta_mac,     (mac_addr){0xF4, 0x17, 0xB8, 0xAE, 0x86, 0xF1}, sizeof(mac_addr)));
    fail_unless(!memcmp(t->target_bssid, (mac_addr){0x22, 0xB0, 0x01, 0xBF, 0xA2, 0xB5}, sizeof(mac_addr)));
    fail_unless(t->result == 0);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_A0_higher_layer_data)
{
    VARS
    READ_PARSE("tlv_A0_higher_layer_data.pcap")

    map_higher_layer_data_tlv_t *t = (map_higher_layer_data_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_HIGHER_LAYER_DATA);
    fail_unless(t->protocol    == 0x0D);
    fail_unless(t->payload_len == 4);
    fail_unless(t->payload && !memcmp(t->payload, (uint8_t[]){0x01, 0x02, 0x03, 0x04}, 4));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_A1_ap_capability)
{
    VARS
    READ_PARSE("tlv_A1_ap_capability.pcap")

    map_ap_cap_tlv_t *t = (map_ap_cap_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type                               == TLV_TYPE_AP_CAPABILITY);
    fail_unless(t->operating_unsupported_link_metrics     == 1);
    fail_unless(t->non_operating_unsupported_link_metrics == 0);
    fail_unless(t->agent_initiated_steering               == 0);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_A2_associated_sta_traffic_stats)
{
    VARS
    READ_PARSE("tlv_A2_associated_sta_traffic_stats.pcap")

    map_assoc_sta_traffic_stats_tlv_t *t = (map_assoc_sta_traffic_stats_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_ASSOCIATED_STA_TRAFFIC_STATS);
    fail_unless(!memcmp(t->sta_mac, (mac_addr){0x4E, 0x8F, 0x3B, 0x88, 0xF5, 0x57}, sizeof(mac_addr)));
    fail_unless(t->tx_bytes         == 177364);
    fail_unless(t->rx_bytes         == 232378);
    fail_unless(t->tx_packets       == 385);
    fail_unless(t->rx_packets       == 2215);
    fail_unless(t->tx_packet_errors == 0);
    fail_unless(t->rx_packet_errors == 0);
    fail_unless(t->retransmissions  == 0);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_A3_error_code)
{
    VARS
    READ_PARSE("tlv_A3_error_code.pcap")

    map_error_code_tlv_t *t = (map_error_code_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type    == TLV_TYPE_ERROR_CODE);
    fail_unless(t->reason_code == 2);
    fail_unless(!memcmp(t->sta_mac, (mac_addr){0x70, 0x28, 0x8B, 0x22, 0x23, 0x93}, sizeof(mac_addr)));

    FORGE
    CLEANUP
}
END_TEST

/*#######################################################################
#                       MAP R2 TLVS                                     #
########################################################################*/
START_TEST(test_A4_channel_scan_reporting_policy)
{
    VARS
    READ_PARSE("tlv_A4_channel_scan_reporting_policy.pcap")

    map_channel_scan_reporting_policy_tlv_t *t = (map_channel_scan_reporting_policy_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_CHANNEL_SCAN_REPORTING_POLICY);
    fail_unless(t->report_independent_ch_scans == 0);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_A5_channel_scan_capabilities)
{
    VARS
    READ_PARSE("tlv_A5_channel_scan_capabilities.pcap")

    map_channel_scan_cap_tlv_t *t = (map_channel_scan_cap_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type  == TLV_TYPE_CHANNEL_SCAN_CAPABILITIES);
    fail_unless(t->radios_nr == 2);

    fail_unless(!memcmp(t->radios[0].radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0xAE, 0x86, 0xF2}, sizeof(mac_addr)));
    fail_unless(t->radios[0].boot_only                 == 0x0);
    fail_unless(t->radios[0].scan_impact               == MAP_SCAN_IMPACT_TIME_SLICING);
    fail_unless(t->radios[0].min_scan_interval         == 900);
    fail_unless(t->radios[0].op_classes_nr             == 2);
    fail_unless(t->radios[0].op_classes[0].op_class    == 81);
    fail_unless(map_cs_nr(&t->radios[0].op_classes[0].channels) == 0);
    fail_unless(t->radios[0].op_classes[1].op_class    == 82);
    fail_unless(map_cs_nr(&t->radios[0].op_classes[1].channels) == 0);

    fail_unless(!memcmp(t->radios[1].radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0xAE, 0x86, 0xF1}, sizeof(mac_addr)));
    fail_unless(t->radios[0].boot_only                 == 0x0);
    fail_unless(t->radios[0].scan_impact               == MAP_SCAN_IMPACT_TIME_SLICING);
    fail_unless(t->radios[1].min_scan_interval         == 900);
    fail_unless(t->radios[1].op_classes_nr             == 5);
    fail_unless(t->radios[1].op_classes[0].op_class    == 115);
    fail_unless(map_cs_nr(&t->radios[1].op_classes[0].channels) == 0);
    fail_unless(t->radios[1].op_classes[4].op_class    == 125);
    fail_unless(map_cs_nr(&t->radios[1].op_classes[4].channels) == 2);
    fail_unless(map_cs_is_set(&t->radios[1].op_classes[4].channels, 165));
    fail_unless(map_cs_is_set(&t->radios[1].op_classes[4].channels, 169));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_A6_channel_scan_request)
{
    VARS
    READ_PARSE("tlv_A6_channel_scan_request.pcap");

    map_channel_scan_request_tlv_t *t = (map_channel_scan_request_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type             == TLV_TYPE_CHANNEL_SCAN_REQUEST);
    fail_unless(t->fresh_scan_performed == 0);
    fail_unless(t->radios_nr            == 1);
    fail_unless(!memcmp(t->radios[0].radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0xAE, 0x86, 0xF2}, sizeof(mac_addr)));
    fail_unless(t->radios[0].op_classes_nr == 0);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_A6_channel_scan_request_2)
{
    VARS
    READ_PARSE("tlv_A6_channel_scan_request_2.pcap");

    map_channel_scan_request_tlv_t *t = (map_channel_scan_request_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type             == TLV_TYPE_CHANNEL_SCAN_REQUEST);
    fail_unless(t->fresh_scan_performed == 1);
    fail_unless(t->radios_nr            == 1);
    fail_unless(!memcmp(t->radios[0].radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0xAE, 0x86, 0xF1}, sizeof(mac_addr)));
    fail_unless(t->radios[0].op_classes_nr == 3);

    fail_unless(t->radios[0].op_classes[0].op_class == 118);
    fail_unless(map_cs_nr(&t->radios[0].op_classes[0].channels) == 3);
    fail_unless(map_cs_is_set(&t->radios[0].op_classes[0].channels, 64));
    fail_unless(map_cs_is_set(&t->radios[0].op_classes[0].channels, 100));
    fail_unless(map_cs_is_set(&t->radios[0].op_classes[0].channels, 104));

    fail_unless(t->radios[0].op_classes[1].op_class == 125);
    fail_unless(map_cs_nr(&t->radios[0].op_classes[1].channels) == 1);
    fail_unless(map_cs_is_set(&t->radios[0].op_classes[1].channels, 169));

    fail_unless(t->radios[0].op_classes[2].op_class == 128);
    fail_unless(map_cs_nr(&t->radios[0].op_classes[2].channels) == 0);

    FORGE
    CLEANUP
}
END_TEST


START_TEST(test_A7_channel_scan_result)
{
    VARS
    READ_PARSE("tlv_A7_channel_scan_result.pcap")

    map_channel_scan_result_tlv_t *t = (map_channel_scan_result_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_CHANNEL_SCAN_RESULT);
    fail_unless(!memcmp(t->radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0xAE, 0x86, 0xF1}, sizeof(mac_addr)));
    fail_unless(t->op_class      == 125);
    fail_unless(t->channel       == 173);
    fail_unless(t->scan_status   == 0);
    fail_unless(t->timestamp_len == 28);
    fail_unless(!memcmp(t->timestamp, (char *)"2020-12-21T01:52:41.0Z-05:00", 28));
    fail_unless(t->utilization             == 0);
    fail_unless(t->noise                   == 165);
    fail_unless(t->aggregate_scan_duration == 30);
    fail_unless(t->scan_type               == 1);
    fail_unless(t->neighbors_nr            == 2);

    fail_unless(!memcmp(t->neighbors[0].bssid, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6A}, sizeof(mac_addr)));
    fail_unless(t->neighbors[0].ssid_len              == 11);
    fail_unless(t->neighbors[0].rcpi                  == 176);
    fail_unless(t->neighbors[0].ch_bw_len             == 2);
    fail_unless(t->neighbors[0].bss_load_elem_present == 1);
    fail_unless(t->neighbors[0].channel_utilization   == 3);
    fail_unless(t->neighbors[0].stas_nr               == 0);
    fail_unless(!memcmp(t->neighbors[0].ssid,  (char *)"frv_test_fh", 11));
    fail_unless(!memcmp(t->neighbors[0].ch_bw, (char *)"80", 2));

    fail_unless(!memcmp(t->neighbors[1].bssid, (mac_addr){0x6A, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(t->neighbors[1].ssid_len              == 11);
    fail_unless(t->neighbors[1].rcpi                  == 176);
    fail_unless(t->neighbors[1].ch_bw_len             == 2);
    fail_unless(t->neighbors[1].bss_load_elem_present == 1);
    fail_unless(t->neighbors[1].channel_utilization   == 3);
    fail_unless(t->neighbors[1].stas_nr               == 1);
    fail_unless(!memcmp(t->neighbors[1].ssid,  (char *)"frv_test_bh", 11));
    fail_unless(!memcmp(t->neighbors[1].ch_bw, (char *)"80", 2));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_A7_channel_scan_result_malformed)
{
    packet_t  *packet;
    uint8_t   *p_tlv = NULL;

    fail_unless(!!(packet = pcap_read_first_packet(DATA_DIR "/" "tlv_A7_channel_scan_result_malformed.pcap")));
    p_tlv = parse_1905_TLV_from_packet(TLVS_START, TLVS_LEN);

    /* We should deny malformed TLVs */
    fail_unless(p_tlv == NULL);

    free(packet);
}
END_TEST

START_TEST(test_A8_timestamp)
{
    VARS
    READ_PARSE("tlv_A8_timestamp.pcap")

    map_timestamp_tlv_t *t = (map_timestamp_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type      == TLV_TYPE_TIMESTAMP);
    fail_unless(t->timestamp_len == 28);
    fail_unless(!memcmp(t->timestamp, (char *)"2020-12-21T01:58:38.0Z-05:00", 28));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_AD_cac_request)
{
    VARS
    READ_PARSE("tlv_AD_cac_request.pcap")

    map_cac_request_tlv_t *t = (map_cac_request_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type  == TLV_TYPE_CAC_REQUEST);
    fail_unless(t->radios_nr == 1);
    fail_unless(!memcmp(t->radios[0].radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0xBD, 0xBD, 0xFE}, sizeof(mac_addr)));
    fail_unless(t->radios[0].op_class              == 120);
    fail_unless(t->radios[0].channel               == 64);
    fail_unless(t->radios[0].cac_method            == MAP_CAC_METHOD_CONTINUOUS);
    fail_unless(t->radios[0].cac_completion_action == MAP_CAC_ACTION_RETURN_PREV_OP_CONF);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_AE_cac_termination)
{
    VARS
    READ_PARSE("tlv_AE_cac_termination.pcap")

    map_cac_termination_tlv_t *t = (map_cac_termination_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type  == TLV_TYPE_CAC_TERMINATION);
    fail_unless(t->radios_nr == 1);
    fail_unless(!memcmp(t->radios[0].radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0xBD, 0xBD, 0xFE}, sizeof(mac_addr)));
    fail_unless(t->radios[0].op_class == 120);
    fail_unless(t->radios[0].channel  == 64);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_AF_cac_completion_report)
{
    VARS
    READ_PARSE("tlv_AF_cac_completion_report.pcap")

    map_cac_completion_report_tlv_t *t = (map_cac_completion_report_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type  == TLV_TYPE_CAC_COMPLETION_REPORT);
    fail_unless(t->radios_nr == 1);

    fail_unless(!memcmp(t->radios[0].radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6A}, sizeof(mac_addr)));
    fail_unless(t->radios[0].op_class                   == 128);
    fail_unless(t->radios[0].channel                    == 106);
    fail_unless(t->radios[0].status                     == 0);
    fail_unless(t->radios[0].detected_pairs_nr          == 4);
    fail_unless(t->radios[0].detected_pairs[0].op_class == 121);
    fail_unless(t->radios[0].detected_pairs[0].channel  == 100);
    fail_unless(t->radios[0].detected_pairs[1].op_class == 121);
    fail_unless(t->radios[0].detected_pairs[1].channel  == 104);
    fail_unless(t->radios[0].detected_pairs[2].op_class == 121);
    fail_unless(t->radios[0].detected_pairs[2].channel  == 108);
    fail_unless(t->radios[0].detected_pairs[3].op_class == 121);
    fail_unless(t->radios[0].detected_pairs[3].channel  == 112);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_B1_cac_status_report)
{
    VARS
    READ_PARSE("tlv_B1_cac_status_report.pcap")

    map_cac_status_report_tlv_t *t = (map_cac_status_report_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_CAC_STATUS_REPORT);
    fail_unless(t->available_pairs_nr == 81);
    fail_unless(t->available_pairs[0].op_class                      == 81);
    fail_unless(t->available_pairs[0].channel                       == 1);
    fail_unless(t->available_pairs[0].minutes_since_cac_completion  == 0);
    fail_unless(t->available_pairs[80].op_class                     == 128);
    fail_unless(t->available_pairs[80].channel                      == 171);
    fail_unless(t->available_pairs[80].minutes_since_cac_completion == 0);
    fail_unless(t->non_occupancy_pairs_nr == 1);
    fail_unless(t->non_occupancy_pairs[0].op_class                                 == 115);
    fail_unless(t->non_occupancy_pairs[0].channel                                  == 100);
    fail_unless(t->non_occupancy_pairs[0].seconds_remaining_non_occupancy_duration == 256);
    fail_unless(t->ongoing_cac_pairs_nr == 2);
    fail_unless(t->ongoing_cac_pairs[0].op_class                         == 116);
    fail_unless(t->ongoing_cac_pairs[0].channel                          == 104);
    fail_unless(t->ongoing_cac_pairs[0].seconds_remaining_cac_completion == 4096);
    fail_unless(t->ongoing_cac_pairs[1].op_class                         == 117);
    fail_unless(t->ongoing_cac_pairs[1].channel                          == 108);
    fail_unless(t->ongoing_cac_pairs[1].seconds_remaining_cac_completion == 8192);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_B2_cac_capabilities)
{
    VARS
    READ_PARSE("tlv_B2_cac_capabilities.pcap")

    map_cac_cap_tlv_t *t = (map_cac_cap_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_CAC_CAPABILITIES);
    fail_unless(t->country_code == 0x5553 /* US */);
    fail_unless(t->radios_nr    == 1);
    fail_unless(!memcmp(t->radios[0].radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6A}, sizeof(mac_addr)));
    fail_unless(t->radios[0].cac_methods_nr == 1);
    fail_unless(t->radios[0].cac_methods[0].cac_method    == MAP_CAC_METHOD_MIMO_DIM_REDUCED);
    fail_unless(t->radios[0].cac_methods[0].cac_duration  == 60);
    fail_unless(t->radios[0].cac_methods[0].op_classes_nr == 7);

    fail_unless(t->radios[0].cac_methods[0].op_classes[0].op_class == 118);
    fail_unless(map_cs_nr(&t->radios[0].cac_methods[0].op_classes[0].channels) == 4);
    fail_unless(map_cs_is_set(&t->radios[0].cac_methods[0].op_classes[0].channels, 52));
    fail_unless(map_cs_is_set(&t->radios[0].cac_methods[0].op_classes[0].channels, 64));

    fail_unless(t->radios[0].cac_methods[0].op_classes[6].op_class == 128);
    fail_unless(map_cs_nr(&t->radios[0].cac_methods[0].op_classes[6].channels) == 2);
    fail_unless(map_cs_is_set(&t->radios[0].cac_methods[0].op_classes[6].channels, 58));
    fail_unless(map_cs_is_set(&t->radios[0].cac_methods[0].op_classes[6].channels, 122));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_B3_multiap_profile)
{
    VARS
    READ_PARSE("tlv_B3_multiap_profile.pcap")

    map_multiap_profile_tlv_t *t = (map_multiap_profile_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_MULTIAP_PROFILE);
    fail_unless(t->map_profile == 2);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_B4_profile2_ap_capability)
{
    VARS
    READ_PARSE("tlv_B4_profile2_ap_capability.pcap")

    map_profile2_ap_cap_tlv_t *t = (map_profile2_ap_cap_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type          == TLV_TYPE_PROFILE2_AP_CAPABILITY);
    fail_unless(t->byte_counter_unit == MAP_BYTE_COUNTER_UNIT_KIBI_BYTES);
    fail_unless(t->max_vid_count     == 2);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_B5_default_8021q_settings)
{
    VARS
    READ_PARSE("tlv_B5_default_8021q_settings.pcap")

    map_default_8021q_settings_tlv_t *t = (map_default_8021q_settings_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type        == TLV_TYPE_DEFAULT_8021Q_SETTINGS);
    fail_unless(t->primary_vlan_id == 10);
    fail_unless(t->default_pcp     == 3);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_B6_traffic_separation_policy)
{
    VARS
    READ_PARSE("tlv_B6_traffic_separation_policy.pcap")

    map_traffic_separation_policy_tlv_t *t = (map_traffic_separation_policy_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_TRAFFIC_SEPARATION_POLICY);
    fail_unless(t->ssids_nr == 2);

    fail_unless(t->ssids[0].ssid_len == 11);
    fail_unless(!memcmp(t->ssids[0].ssid, (char *)"frv_test_fh", 11));
    fail_unless(t->ssids[0].vlan_id == 10);

    fail_unless(t->ssids[1].ssid_len == 11);
    fail_unless(!memcmp(t->ssids[1].ssid, (char *)"frv_test_bh", 11));
    fail_unless(t->ssids[1].vlan_id == 20);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_BC_profile2_error_code)
{
    VARS
    READ_PARSE("tlv_BC_profile2_error_code.pcap")

    map_profile2_error_code_tlv_t *t = (map_profile2_error_code_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type    == TLV_TYPE_PROFILE2_ERROR_CODE);
    fail_unless(t->reason_code == MAP_ERROR_CODE2_TS_COMBINED_FH_PROFILE1_BH_UNSUPPORTED);
    fail_unless(!memcmp(t->sta_mac, (mac_addr){0x70, 0x28, 0x8B, 0x22, 0x23, 0x93}, sizeof(mac_addr)));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_BE_ap_radio_advanced_capabilities)
{
    VARS
    READ_PARSE("tlv_BE_ap_radio_advanced_capabilities.pcap")

    map_ap_radio_advanced_cap_tlv_t *t = (map_ap_radio_advanced_cap_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_AP_RADIO_ADVANCED_CAPABILITIES);
    fail_unless(!memcmp(t->radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0xAE, 0x86, 0xF1}, sizeof(mac_addr)));
    fail_unless(t->combined_fh_profile2_bh == 1);
    fail_unless(t->combined_profile1_bh_profile2_bh == 0);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_BF_association_status_notification)
{
    VARS
    READ_PARSE("tlv_BF_association_status_notification.pcap")

    map_assoc_status_notification_tlv_t *t = (map_assoc_status_notification_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type  == TLV_TYPE_ASSOCIATION_STATUS_NOTIFICATION);
    fail_unless(t->bsss_nr == 2);
    fail_unless(!memcmp(t->bsss[0].bssid, (mac_addr){0x6A, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(t->bsss[0].assoc_allowance_status == 0);
    fail_unless(!memcmp(t->bsss[1].bssid, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6A}, sizeof(mac_addr)));
    fail_unless(t->bsss[1].assoc_allowance_status == 1);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_C0_source_info)
{
    VARS
    READ_PARSE("tlv_C0_source_info.pcap")

    map_source_info_tlv_t *t = (map_source_info_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_SOURCE_INFO);
    fail_unless(!memcmp(t->src_mac, (mac_addr){0x4E, 0x8F, 0x3B, 0x88, 0xF5, 0x57}, sizeof(mac_addr)));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_C1_tunneled_message_type)
{
    VARS
    READ_PARSE("tlv_C1_tunneled_message_type.pcap")

    map_tunneled_message_type_tlv_t *t = (map_tunneled_message_type_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type     == TLV_TYPE_TUNNELED_MESSAGE_TYPE);
    fail_unless(t->message_type == TUNNELED_MSG_PAYLOAD_REASSOC_REQ);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_C2_tunneled)
{
    VARS
    READ_PARSE("tlv_C2_tunneled.pcap")

    map_tunneled_tlv_t *t = (map_tunneled_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_TUNNELED);
    fail_unless(t->frame_body_len == 246);
    fail_unless(t->frame_body != NULL);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_C3_profile2_steering_request)
{
    VARS
    READ_PARSE("tlv_C3_profile2_steering_request.pcap")

    map_profile2_steering_request_tlv_t *t = (map_profile2_steering_request_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_PROFILE2_STEERING_REQUEST);
    fail_unless(!memcmp(t->bssid, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(t->flag                 == (MAP_STEERING_REQUEST_FLAG_MANDATE | MAP_STEERING_REQUEST_FLAG_BTM_DISASSOC_IMMINENT | MAP_STEERING_REQUEST_FLAG_BTM_ABRIDGED));
    fail_unless(t->opportunity_wnd      == 0);
    fail_unless(t->disassociation_timer == 6000);
    fail_unless(t->sta_macs_nr          == 1);
    fail_unless(!memcmp(t->sta_macs[0], (mac_addr){0x4E, 0x8F, 0x3B, 0x88, 0xF5, 0x57}, sizeof(mac_addr)));
    fail_unless(t->target_bsss_nr       == 1);
    fail_unless(!memcmp(t->target_bsss[0].bssid, (mac_addr){0x22, 0xB0, 0x01, 0xBf, 0xA2, 0xB5}, sizeof(mac_addr)));
    fail_unless(t->target_bsss[0].op_class == 121);
    fail_unless(t->target_bsss[0].channel  == 112);
    fail_unless(t->target_bsss[0].reason   == 3);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_C4_unsuccessful_association_policy)
{
    VARS
    READ_PARSE("tlv_C4_unsuccessful_association_policy.pcap")

    map_unsuccessful_assoc_policy_tlv_t *t = (map_unsuccessful_assoc_policy_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type           == TLV_TYPE_UNSUCCESSFUL_ASSOCIATION_POLICY);
    fail_unless(t->report_flag        == MAP_UNSUCCESSFUL_ASSOC_REPORT);
    fail_unless(t->max_reporting_rate == 60);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_C5_metric_collection_interval)
{
    VARS
    READ_PARSE("tlv_C5_metric_collection_interval.pcap")

    map_metric_collection_interval_tlv_t *t = (map_metric_collection_interval_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type                   == TLV_TYPE_METRIC_COLLECTION_INTERVAL);
    fail_unless(t->metric_collection_interval == 2219074296);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_C6_radio_metrics)
{
    VARS
    READ_PARSE("tlv_C6_radio_metrics.pcap")

    map_radio_metrics_tlv_t *t = (map_radio_metrics_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_RADIO_METRICS);
    fail_unless(!memcmp(t->radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(t->noise         == 28);
    fail_unless(t->transmit      == 10);
    fail_unless(t->receive_self  == 0);
    fail_unless(t->receive_other == 7);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_C7_ap_extended_metrics)
{
    VARS
    READ_PARSE("tlv_C7_ap_extended_metrics.pcap")

    map_ap_ext_metrics_tlv_t *t = (map_ap_ext_metrics_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_AP_EXTENDED_METRICS);
    fail_unless(!memcmp(t->bssid, (mac_addr){0x6A, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(t->tx_ucast_bytes == 256);
    fail_unless(t->rx_ucast_bytes == 257);
    fail_unless(t->tx_mcast_bytes == 258);
    fail_unless(t->rx_mcast_bytes == 259);
    fail_unless(t->tx_bcast_bytes == 260);
    fail_unless(t->rx_bcast_bytes == 261);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_C8_associated_sta_extended_link_metrics)
{
    VARS
    READ_PARSE("tlv_C8_associated_sta_extended_link_metrics.pcap")

    map_assoc_sta_ext_link_metrics_tlv_t *t = (map_assoc_sta_ext_link_metrics_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_ASSOCIATED_STA_EXTENDED_LINK_METRICS);
    fail_unless(!memcmp(t->sta_mac, (mac_addr){0x70, 0x28, 0x8B, 0x22, 0x23, 0x93}, sizeof(mac_addr)));
    fail_unless(t->bsss_nr == 1);
    fail_unless(!memcmp(t->bsss[0].bssid, (mac_addr){0xF4, 0x17, 0xB8, 0xAE, 0x86, 0xF2}, sizeof(mac_addr)));
    fail_unless(t->bsss[0].last_data_dl_rate == 65);
    fail_unless(t->bsss[0].last_data_ul_rate == 6);
    fail_unless(t->bsss[0].utilization_rx    == 478000);
    fail_unless(t->bsss[0].utilization_tx    == 478000);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_C9_status_code)
{
    VARS
    READ_PARSE("tlv_C9_status_code.pcap")

    map_status_code_tlv_t *t = (map_status_code_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_STATUS_CODE);
    fail_unless(t->status_code == 0x000D);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_CA_reason_code)
{
    VARS
    READ_PARSE("tlv_CA_reason_code.pcap")

    map_reason_code_tlv_t *t = (map_reason_code_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type    == TLV_TYPE_REASON_CODE);
    fail_unless(t->reason_code == 0x0003);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_CB_backhaul_sta_radio_capabilities)
{
    VARS
    READ_PARSE("tlv_CB_backhaul_sta_radio_capabilities.pcap")

    map_backhaul_sta_radio_cap_tlv_t *t = (map_backhaul_sta_radio_cap_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_BACKHAUL_STA_RADIO_CAPABILITIES);
    fail_unless(!memcmp(t->radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0xAE, 0x86, 0xF1}, sizeof(mac_addr)));
    fail_unless(t->bsta_mac_present == 1);
    fail_unless(!memcmp(t->bsta_mac, (mac_addr){0xF6, 0x17, 0xB8, 0xAE, 0x86, 0xF2}, sizeof(mac_addr)));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_D0_backhaul_bss_configuration)
{
    VARS
    READ_PARSE("tlv_D0_backhaul_bss_configuration.pcap")

    map_backhaul_bss_configuration_tlv_t *t = (map_backhaul_bss_configuration_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_BACKHAUL_BSS_CONFIGURATION);
    fail_unless(!memcmp(t->bssid, (mac_addr){0x6A, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(t->p1_bsta_disallowed == 1);
    fail_unless(t->p2_bsta_disallowed == 0);

    FORGE
    CLEANUP
}
END_TEST

/*#######################################################################
#                       MAP R3 TLVS                                     #
########################################################################*/
START_TEST(test_A9_1905_security_capability)
{
    VARS
    READ_PARSE("tlv_A9_1905_layer_security_capability.pcap")

    map_1905_security_cap_tlv_t *t = (map_1905_security_cap_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_1905_LAYER_SECURITY_CAPABILITY);
    fail_unless(t->onboarding_protocol == 0);
    fail_unless(t->mic_algorithm == 0);
    fail_unless(t->encryption_algorithm == 0);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_AA_ap_wifi6_capabilities)
{
    VARS
    READ_PARSE("tlv_AA_ap_wifi6_capabilities.pcap")
    int i, j;

    map_ap_wifi6_cap_tlv_t *t = (map_ap_wifi6_cap_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_AP_WIFI6_CAPABILITIES);
    fail_unless(!memcmp(t->radio_id, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x58, 0x7E}, sizeof(mac_addr)));
    fail_unless(t->roles_nr == 2);
    for (i = 0; i < t->roles_nr; i++) {
        fail_unless(t->cap_data[i].agent_role == i);
        fail_unless(t->cap_data[i].he160 == 1);
        fail_unless(t->cap_data[i].he8080 == 0);
        fail_unless(t->cap_data[i].mcs_nss_nr == 8);
        for (j = 0; j < t->cap_data[i].mcs_nss_nr / 2; j++) {
            fail_unless(t->cap_data[i].mcs_nss[j] == 0xFFAA);
        }
        fail_unless(t->cap_data[i].su_beamformer == 1);
        fail_unless(t->cap_data[i].su_beamformee == 0);
        fail_unless(t->cap_data[i].mu_beamformer == 0);
        fail_unless(t->cap_data[i].beamformee_sts_l80 == 0);
        fail_unless(t->cap_data[i].beamformee_sts_g80 == 0);
        fail_unless(t->cap_data[i].ul_mu_mimo == 0);
        fail_unless(t->cap_data[i].ul_ofdma == 1);
        fail_unless(t->cap_data[i].dl_ofdma == 1);
    }

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_AB_mic)
{
    VARS
    READ_PARSE("tlv_AB_mic.pcap")
    uint8_t integrity_tx_ctr[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    uint8_t mic[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
    uint16_t mic_len = sizeof(mic);
    map_mic_tlv_t *t = (map_mic_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE
    fail_unless(t->tlv_type    == TLV_TYPE_MIC);
    fail_unless(t->gtk_key_id  == 1);
    fail_unless(t->mic_version == 0);
    fail_unless(t->reserved    == 0);
    fail_unless(!memcmp(t->integrity_tx_counter, integrity_tx_ctr, INTEGRITY_TX_COUNTER_LEN));
    fail_unless(!memcmp(t->src_al_mac, (mac_addr){0x02, 0x01, 0x02, 0x03, 0x04, 0x05}, ETHER_ADDR_LEN));
    fail_unless(t->mic_len == mic_len);
    fail_unless(!memcmp(t->mic, mic, t->mic_len));
    FORGE
    CLEANUP
}
END_TEST
START_TEST(test_AC_encrypted_payload)
{
    VARS
    READ_PARSE("tlv_AC_encrypted_payload.pcap")
    uint8_t encryption_tx_counter[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    uint8_t siv_output[] = {0xfc, 0x4c, 0xa5, 0xa1, 0x31, 0xdf, 0xcf, 0xb9, 0xf7, 0xf6, 0xd6, 0x8b, 0xfc, 0xd5, 0x78, 0xd0, 0x0a, 0x74, 0xf3, 0xb5};
    uint16_t siv_len = sizeof(siv_output);
    map_encrypted_payload_tlv_t *t = (map_encrypted_payload_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE
    fail_unless(t->tlv_type == TLV_TYPE_ENCRYPTED_PAYLOAD);
    fail_unless(!memcmp(t->encr_tx_counter, encryption_tx_counter, 6));
    fail_unless(!memcmp(t->src_al_mac, (mac_addr){0x02, 0x01, 0x02, 0x03, 0x04, 0x05}, ETHER_ADDR_LEN));
    fail_unless(!memcmp(t->dst_al_mac, (mac_addr){0xf6, 0x17, 0xb8, 0xae, 0x89, 0xa3}, ETHER_ADDR_LEN));
    fail_unless(t->siv_len == siv_len);
    fail_unless(!memcmp(t->siv_output, siv_output, t->siv_len));
    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_B0_associated_wifi6_sta_status)
{
    VARS
    READ_PARSE("tlv_B0_associated_wifi6_sta_status_report.pcap")

    map_assoc_wifi6_sta_status_tlv_t *t = (map_assoc_wifi6_sta_status_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_ASSOCIATED_WIFI6_STA_STATUS_REPORT);

    fail_unless(!memcmp(t->sta_mac, (mac_addr){0x02, 0x7F, 0x9F, 0xA0, 0xD7, 0x10}, sizeof(mac_addr)));
    fail_unless(t->TID_nr == 3);

    fail_unless(t->TID[0] == 0);
    fail_unless(t->queue_size[0] == 65);

    fail_unless(t->TID[1] == 1);
    fail_unless(t->queue_size[1] == 4);

    fail_unless(t->TID[2] == 6);
    fail_unless(t->queue_size[2] == 19);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_B7_bss_configuration_report)
{
    VARS
    READ_PARSE("tlv_B7_bss_configuration_report.pcap")

    map_bss_configuration_report_tlv_t *t = (map_bss_configuration_report_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_BSS_CONFIGURATION_REPORT);
    fail_unless(t->radios_nr == 2);

    fail_unless(!memcmp(t->radios[0].ruid, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(t->radios[0].bss_nr == 1);

    fail_unless(!memcmp(t->radios[0].bss[0].bssid, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6B}, sizeof(mac_addr)));
    fail_unless(t->radios[0].bss[0].backhaul_bss == 0);
    fail_unless(t->radios[0].bss[0].fronthaul_bss == 1);
    fail_unless(t->radios[0].bss[0].r1_disallowed_status == 0);
    fail_unless(t->radios[0].bss[0].r2_disallowed_status == 1);
    fail_unless(t->radios[0].bss[0].multiple_bssid == 0);
    fail_unless(t->radios[0].bss[0].transmitted_bssid == 0);
    fail_unless(t->radios[0].bss[0].reserved2 == 0);
    fail_unless(t->radios[0].bss[0].ssid_len == 10);
    fail_unless(!strcmp(t->radios[0].bss[0].ssid, "ssid_2g_fh"));

    fail_unless(!memcmp(t->radios[1].ruid, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x57, 0x6A}, sizeof(mac_addr)));
    fail_unless(t->radios[1].bss_nr == 2);

    fail_unless(!memcmp(t->radios[1].bss[0].bssid, (mac_addr){0x82, 0xAA, 0xCC, 0xAA, 0x00, 0x05}, sizeof(mac_addr)));
    fail_unless(t->radios[1].bss[0].backhaul_bss == 0);
    fail_unless(t->radios[1].bss[0].fronthaul_bss == 1);
    fail_unless(t->radios[1].bss[0].r1_disallowed_status == 0);
    fail_unless(t->radios[1].bss[0].r2_disallowed_status == 0);
    fail_unless(t->radios[1].bss[0].multiple_bssid == 1);
    fail_unless(t->radios[1].bss[0].transmitted_bssid == 0);
    fail_unless(t->radios[1].bss[0].reserved2 == 0);
    fail_unless(t->radios[1].bss[0].ssid_len == 10);
    fail_unless(!strcmp(t->radios[1].bss[0].ssid, "ssid_5g_fh"));

    fail_unless(!memcmp(t->radios[1].bss[1].bssid, (mac_addr){0x82, 0xAA, 0xCC, 0xAA, 0x00, 0x06}, sizeof(mac_addr)));
    fail_unless(t->radios[1].bss[1].backhaul_bss == 1);
    fail_unless(t->radios[1].bss[1].fronthaul_bss == 0);
    fail_unless(t->radios[1].bss[1].r1_disallowed_status == 0);
    fail_unless(t->radios[1].bss[1].r2_disallowed_status == 0);
    fail_unless(t->radios[1].bss[1].multiple_bssid == 0);
    fail_unless(t->radios[1].bss[1].transmitted_bssid == 1);
    fail_unless(t->radios[1].bss[1].reserved2 == 0);
    fail_unless(t->radios[1].bss[1].ssid_len == 10);
    fail_unless(!strcmp(t->radios[1].bss[1].ssid, "ssid_5g_bh"));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_B8_bssid)
{
    VARS
    READ_PARSE("tlv_B8_bssid.pcap")

    map_bssid_tlv_t *t = (map_bssid_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_BSSID);
    fail_unless(!memcmp(t->bssid, (mac_addr){0xF4, 0x17, 0xB8, 0x00, 0x01, 0x02}, sizeof(mac_addr)));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_CC_akm_suite_capabilities)
{
    VARS
    READ_PARSE("tlv_CC_akm_suite_capabilities.pcap")

    uint8_t ieee80211_oui[3] = {0x00, 0x0F, 0xAC};
    uint8_t wfa_oui[3]       = {0x50, 0x6F, 0x9A};

    map_akm_suite_cap_tlv_t *t = (map_akm_suite_cap_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_AKM_SUITE_CAPABILITIES);

    fail_unless(t->bh_akm_suites_nr == 4);
    fail_unless(!memcmp(t->bh_akm_suites[2].oui, ieee80211_oui, sizeof(t->bh_akm_suites[2].oui)));
    fail_unless(t->bh_akm_suites[2].akm_suite_type == 8);
    fail_unless(!memcmp(t->bh_akm_suites[3].oui, wfa_oui, sizeof(t->bh_akm_suites[3].oui)));
    fail_unless(t->bh_akm_suites[3].akm_suite_type == 2);

    fail_unless(t->fh_akm_suites_nr == 6);
    fail_unless(!memcmp(t->fh_akm_suites[0].oui, ieee80211_oui, sizeof(t->fh_akm_suites[0].oui)));
    fail_unless(t->fh_akm_suites[0].akm_suite_type == 2);
    fail_unless(!memcmp(t->fh_akm_suites[3].oui, ieee80211_oui, sizeof(t->fh_akm_suites[3].oui)));
    fail_unless(t->fh_akm_suites[3].akm_suite_type == 8);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_CE_1905_encap_eapol)
{
    VARS
    READ_PARSE("tlv_CE_1905_encap_eapol.pcap")

    map_1905_encap_eapol_tlv_t *t = (map_1905_encap_eapol_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_1905_ENCAP_EAPOL);
    fail_unless(t->frame_len == 16);
    fail_unless(t->frame != NULL);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_D1_dpp_message)
{
    VARS
    READ_PARSE("tlv_D1_dpp_message.pcap")

    map_dpp_message_tlv_t *t = (map_dpp_message_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_DPP_MESSAGE);
    fail_unless(t->frame_len == 16);
    fail_unless(t->frame != NULL);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_D2_dpp_cce_indication)
{
    VARS
    READ_PARSE("tlv_D2_dpp_cce_indication.pcap")

    map_dpp_cce_indication_tlv_t *t = (map_dpp_cce_indication_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_DPP_CCE_INDICATION);
    fail_unless(t->advertise == 1);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_CD_1905_encap_dpp)
{
    VARS
    READ_PARSE("tlv_CD_1905_encap_dpp.pcap")

    map_1905_encap_dpp_tlv_t *t = (map_1905_encap_dpp_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_1905_ENCAP_DPP);
    fail_unless(t->enrollee_mac_present == 1);
    fail_unless(t->dpp_frame_indicator == 0);
    fail_unless(!memcmp(t->sta_mac, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x58, 0x7E}, sizeof(mac_addr)));
    fail_unless(t->frame_type == 0x18);
    fail_unless(t->frame_len == 2);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_CD_1905_encap_dpp_no_enrollee_mac)
{
    VARS
    READ_PARSE("tlv_CD_1905_encap_dpp_no_enrollee_mac.pcap")

    map_1905_encap_dpp_tlv_t *t = (map_1905_encap_dpp_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_1905_ENCAP_DPP);
    fail_unless(t->enrollee_mac_present == 0);
    fail_unless(t->dpp_frame_indicator == 1);
    fail_unless(!memcmp(t->sta_mac, (mac_addr){0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, sizeof(mac_addr)));
    fail_unless(t->frame_type == 0xFF);
    fail_unless(t->frame_len == 6);

    FORGE
    CLEANUP
}
END_TEST


START_TEST(test_D3_dpp_chirp_value)
{
    VARS
    READ_PARSE("tlv_D3_dpp_chirp_value.pcap")

    map_dpp_chirp_value_tlv_t *t = (map_dpp_chirp_value_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_DPP_CHIRP_VALUE);
    fail_unless(t->enrollee_mac_present == 1);
    fail_unless(t->hash_validity == 1);
    fail_unless(!memcmp(t->sta_mac, (mac_addr){0xF4, 0x17, 0xB8, 0x86, 0x58, 0x7E}, sizeof(mac_addr)));
    fail_unless(t->hash_len == 16);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_D3_dpp_chirp_value_no_enrollee_mac)
{
    VARS
    READ_PARSE("tlv_D3_dpp_chirp_value_no_enrollee_mac.pcap")

    map_dpp_chirp_value_tlv_t *t = (map_dpp_chirp_value_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_DPP_CHIRP_VALUE);
    fail_unless(t->enrollee_mac_present == 0);
    fail_unless(t->hash_validity == 1);
    fail_unless(!memcmp(t->sta_mac, (mac_addr){0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, sizeof(mac_addr)));
    fail_unless(t->hash_len == 16);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_D4_device_inventory)
{
    VARS
    READ_PARSE("tlv_D4_device_inventory.pcap")

    map_device_inventory_tlv_t *t = (map_device_inventory_tlv_t *)p_tlv;
    int i;
    CHECK_TLV_STRUCT_SIZE

    char *test_serial = "AC2631948026129";
    char *test_version = "4.121.1.3D";
    char *test_env = "Linux 4.1.52";
    char *test_vendor = "Broadcom";
    uint8_t test_mac_list[2][6] = {{0xf4, 0x17, 0xb8, 0xa2, 0x5d, 0xe1},
                                   {0xf4, 0x17, 0xb8, 0xa2, 0x5d, 0xe2}};

    fail_unless(t->tlv_type == TLV_TYPE_DEVICE_INVENTORY);
    fail_unless(t->serial_len > 0);
    fail_unless(memcmp(t->serial, test_serial, t->serial_len) == 0);
    fail_unless(t->version_len > 0);
    fail_unless(memcmp(t->version, test_version, t->version_len) == 0);
    fail_unless(t->environment_len > 0);
    fail_unless(memcmp(t->environment, test_env, t->environment_len) == 0);
    fail_unless(t->radios_nr == 2);

    for (i = 0; i < t->radios_nr; i++) {
        fail_unless(t->radios[i].vendor_len > 0);
        fail_unless(memcmp(t->radios[i].ruid, test_mac_list[i], sizeof(mac_addr)) == 0);
        fail_unless(memcmp(t->radios[i].vendor, test_vendor, t->radios[i].vendor_len) == 0);
    }

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_D5_agent_list)
{
    VARS
    READ_PARSE("tlv_D5_agent_list.pcap")

    map_agent_list_tlv_t *t = (map_agent_list_tlv_t *)p_tlv;
    // int i;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_AGENT_LIST);
    fail_unless(t->agent_nr == 2);

    fail_unless(!memcmp(t->entries[0].al_mac, (mac_addr){0xF6, 0x17, 0xB8, 0x86, 0x57, 0x68}, sizeof(mac_addr)));
    fail_unless(t->entries[0].map_profile == MAP_PROFILE_3);
    fail_unless(t->entries[0].security == 0x01);

    fail_unless(!memcmp(t->entries[1].al_mac, (mac_addr){0xCE, 0xAA, 0xCC, 0xAA, 0x00, 0x00}, sizeof(mac_addr)));
    fail_unless(t->entries[1].map_profile == MAP_PROFILE_2);
    fail_unless(t->entries[1].security == 0x00);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_DD_controller_capability)
{
    VARS
    READ_PARSE("tlv_DD_controller_capability.pcap")

    map_controller_capability_tlv_t *t = (map_controller_capability_tlv_t *)p_tlv;
    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type    == TLV_TYPE_CONTROLLER_CAPABILITY);
    fail_unless(t->capability  == MAP_CONTROLLER_CAP_KIBMIB_COUNTER);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_DF_wifi7_agent_capabilities)
{
    VARS
    READ_PARSE("tlv_DF_wifi7_agent_capabilities.pcap")

    map_wifi7_agent_cap_tlv_t *t = (map_wifi7_agent_cap_tlv_t *)p_tlv;

    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_WIFI7_AGENT_CAPABILITIES);
    fail_unless(t->max_mlds == 0);
    fail_unless(t->ap_max_links == 0);
    fail_unless(t->bsta_max_links == 0);
    fail_unless(t->tid_to_link_map_cap == 0);

    fail_unless(t->radios_nr == 3);

    fail_unless(memcmp(t->radios[0].ruid, (mac_addr){0x00, 0x90, 0x4C, 0x4C, 0x94, 0x0D}, sizeof(mac_addr)) == 0);
    fail_unless(t->radios[0].cap.ap_mld_modes.str      == true);
    fail_unless(t->radios[0].cap.ap_mld_modes.nstr     == false);
    fail_unless(t->radios[0].cap.ap_mld_modes.emlsr    == false);
    fail_unless(t->radios[0].cap.ap_mld_modes.emlmr    == false);
    fail_unless(t->radios[0].cap.bsta_mld_modes.str    == true);
    fail_unless(t->radios[0].cap.bsta_mld_modes.nstr   == false);
    fail_unless(t->radios[0].cap.bsta_mld_modes.emlsr  == false);
    fail_unless(t->radios[0].cap.bsta_mld_modes.emlmr  == false);

    fail_unless(t->radios[0].cap.ap_str_records_nr     == 2);
    fail_unless(memcmp(t->radios[0].cap.ap_str_records[0].ruid, (mac_addr){0x00, 0x90, 0x4C, 0x4D, 0x41, 0x34}, sizeof(mac_addr)) == 0);
    fail_unless(t->radios[0].cap.ap_str_records[0].freq_separation    == 0);
    fail_unless(memcmp(t->radios[0].cap.ap_str_records[1].ruid, (mac_addr){0x00, 0x90, 0x4C, 0x4C, 0x84, 0x72}, sizeof(mac_addr)) == 0);
    fail_unless(t->radios[0].cap.ap_str_records[1].freq_separation    == 0);

    fail_unless(t->radios[0].cap.ap_nstr_records_nr    == 0);
    fail_unless(t->radios[0].cap.ap_emlsr_records      == 0);
    fail_unless(t->radios[0].cap.ap_emlmr_records      == 0);

    fail_unless(t->radios[0].cap.bsta_str_records_nr   == 1);
    fail_unless(memcmp(t->radios[0].cap.bsta_str_records[0].ruid, (mac_addr){0x00, 0x90, 0x4C, 0x4C, 0x84, 0x72}, sizeof(mac_addr)) == 0);
    fail_unless(t->radios[0].cap.bsta_str_records[0].freq_separation  == 0);

    fail_unless(t->radios[0].cap.bsta_nstr_records_nr  == 0);
    fail_unless(t->radios[0].cap.bsta_emlsr_records    == 0);
    fail_unless(t->radios[0].cap.bsta_emlmr_records    == 0);

    fail_unless(memcmp(t->radios[1].ruid, (mac_addr){0x00, 0x90, 0x4C, 0x4D, 0x41, 0x34}, sizeof(mac_addr)) == 0);

    fail_unless(memcmp(t->radios[2].ruid, (mac_addr){0x00, 0x90, 0x4C, 0x4C, 0x84, 0x72}, sizeof(mac_addr)) == 0);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_E0_agent_ap_mld_configuration)
{
    VARS
    READ_PARSE("tlv_E0_agent_ap_mld_configuration.pcap")

    map_agent_ap_mld_conf_tlv_t *t = (map_agent_ap_mld_conf_tlv_t *)p_tlv;

    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_AGENT_AP_MLD_CONFIGURATION);
    fail_unless(t->ap_mld_nr == 2);
    fail_unless(t->ap_mlds[0].ap_mld_mac_valid == 1);
    fail_unless(t->ap_mlds[0].ssid_len == 13);
    fail_unless(!memcmp(t->ap_mlds[0].ssid, (char *)"FrontHaulSSID", 13));
    fail_unless(!memcmp(t->ap_mlds[0].ap_mld_mac, (mac_addr){0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, sizeof(mac_addr)));
    fail_unless(t->ap_mlds[0].str == 1);
    fail_unless(t->ap_mlds[0].emlmr == 0);
    fail_unless(t->ap_mlds[0].aff_ap_nr == 3);
    fail_unless(!memcmp(t->ap_mlds[0].aff_aps[0].radio_id,   (mac_addr){0x00, 0x90, 0x4c, 0x4c, 0x84, 0x7a}, sizeof(mac_addr)));
    fail_unless(!memcmp(t->ap_mlds[0].aff_aps[0].aff_ap_mac, (mac_addr){0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, sizeof(mac_addr)));
    fail_unless(t->ap_mlds[0].aff_aps[0].link_id == 2);
    fail_unless(!memcmp(t->ap_mlds[0].aff_aps[2].radio_id,   (mac_addr){0x00, 0x90, 0x4c, 0x4c, 0x94, 0x1f}, sizeof(mac_addr)));
    fail_unless(!memcmp(t->ap_mlds[0].aff_aps[2].aff_ap_mac, (mac_addr){0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, sizeof(mac_addr)));
    fail_unless(t->ap_mlds[0].aff_aps[2].link_id == 4);
    fail_unless(t->ap_mlds[1].ssid_len == 12);
    fail_unless(!memcmp(t->ap_mlds[1].ssid, (char *)"BackHaulSSID", 12));
    fail_unless(t->ap_mlds[1].aff_ap_nr == 2);
    fail_unless(t->ap_mlds[1].aff_aps[1].link_id == 6);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_E1_backhaul_sta_mld_configuration)
{
    VARS
    READ_PARSE("tlv_E1_backhaul_sta_mld_configuration.pcap")

    map_bsta_mld_conf_tlv_t *t = (map_bsta_mld_conf_tlv_t *)p_tlv;

    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_BACKHAUL_STA_MLD_CONFIGURATION);
    fail_unless(t->bsta_mld_mac_valid == 1);
    fail_unless(t->ap_mld_mac_valid == 0);
    fail_unless(!memcmp(t->bsta_mld_mac, (mac_addr){0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, sizeof(mac_addr)));
    fail_unless(!memcmp(t->ap_mld_mac,   (mac_addr){0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, sizeof(mac_addr)));
    fail_unless(t->str         == 1);
    fail_unless(t->emlmr       == 0);
    fail_unless(t->aff_bsta_nr == 2);
    fail_unless(t->aff_bstas[0].aff_bsta_mac_valid == 1);
    fail_unless(!memcmp(t->aff_bstas[0].radio_id,     (mac_addr){0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x03}, sizeof(mac_addr)));
    fail_unless(!memcmp(t->aff_bstas[0].aff_bsta_mac, (mac_addr){0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5}, sizeof(mac_addr)));
    fail_unless(t->aff_bstas[1].aff_bsta_mac_valid == 0);
    fail_unless(!memcmp(t->aff_bstas[1].radio_id,     (mac_addr){0x02, 0xea, 0xbb, 0xcc, 0xdd, 0x04}, sizeof(mac_addr)));
    fail_unless(!memcmp(t->aff_bstas[1].aff_bsta_mac, (mac_addr){0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, sizeof(mac_addr)));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_E2_associated_sta_mld_configuration)
{
    VARS
    READ_PARSE("tlv_E2_associated_sta_mld_configuration.pcap")

    map_assoc_sta_mld_conf_tlv_t *t = (map_assoc_sta_mld_conf_tlv_t *)p_tlv;

    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_ASSOCIATED_STA_MLD_CONFIGURATION);
    fail_unless(!memcmp(t->sta_mld_mac, (mac_addr){0xe4, 0x60, 0x17, 0x5e, 0x34, 0x4f}, sizeof(mac_addr)));
    fail_unless(!memcmp(t->ap_mld_mac,  (mac_addr){0x00, 0x90, 0x4c, 0x4c, 0x84, 0x7b}, sizeof(mac_addr)));
    fail_unless(t->str        == 1);
    fail_unless(t->emlmr      == 0);
    fail_unless(t->aff_sta_nr == 3);
    fail_unless(!memcmp(t->aff_stas[0].bssid,       (mac_addr){0x7a, 0x90, 0x4c, 0x4c, 0x94, 0x18}, sizeof(mac_addr)));
    fail_unless(!memcmp(t->aff_stas[0].aff_sta_mac, (mac_addr){0xa6, 0x6b, 0xa2, 0xa5, 0xcd, 0x9c}, sizeof(mac_addr)));
    fail_unless(!memcmp(t->aff_stas[2].bssid,       (mac_addr){0x00, 0x90, 0x4c, 0x4c, 0x84, 0x7b}, sizeof(mac_addr)));
    fail_unless(!memcmp(t->aff_stas[2].aff_sta_mac, (mac_addr){0xe4, 0x60, 0x17, 0x5e, 0x34, 0x4f}, sizeof(mac_addr)));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_E4_affiliated_sta_metrics)
{
    VARS
    READ_PARSE("tlv_E4_affiliated_sta_metrics.pcap")

    map_aff_sta_metrics_tlv_t *t = (map_aff_sta_metrics_tlv_t *)p_tlv;

    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_AFFILIATED_STA_METRICS);
    fail_unless(!memcmp(t->sta_mac, (mac_addr){0xe4, 0x60, 0x17, 0x5e, 0x34, 0x4f}, sizeof(mac_addr)));
    fail_unless(t->tx_bytes         == 257);
    fail_unless(t->rx_bytes         == 258);
    fail_unless(t->tx_packets       == 259);
    fail_unless(t->rx_packets       == 260);
    fail_unless(t->tx_packet_errors == 261);
    fail_unless(t->reserved_len     == 998);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_E5_affiliated_ap_metrics)
{
    VARS
    READ_PARSE("tlv_E5_affiliated_ap_metrics.pcap")

    map_aff_ap_metrics_tlv_t *t = (map_aff_ap_metrics_tlv_t *)p_tlv;

    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_AFFILIATED_AP_METRICS);
    fail_unless(!memcmp(t->bssid, (mac_addr){0xe4, 0x60, 0x17, 0x5e, 0x34, 0x4f}, sizeof(mac_addr)));
    fail_unless(t->tx_packets       == 257);
    fail_unless(t->rx_packets       == 258);
    fail_unless(t->tx_packet_errors == 259);
    fail_unless(t->tx_ucast_bytes   == 260);
    fail_unless(t->rx_ucast_bytes   == 261);
    fail_unless(t->tx_mcast_bytes   == 262);
    fail_unless(t->rx_mcast_bytes   == 263);
    fail_unless(t->tx_bcast_bytes   == 264);
    fail_unless(t->rx_bcast_bytes   == 265);
    fail_unless(t->reserved_len     == 988);

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_E8_available_spectrum_inquiry_request)
{

    uint8_t *p_tlv;
    READ_PARSE_FRAGMENTED("tlv_E8_available_spectrum_inquiry_request.pcap")

    map_available_spec_inq_req_tlv_t *t = (map_available_spec_inq_req_tlv_t *)p_tlv;

    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_AVAILABLE_SPECTRUM_INQUIRY_REQUEST);
    fail_unless(t->req_len == 1486);
    fail_unless(!memcmp(t->req, (char *)"{ \"version\": \"1.4\", \"availableSpectrumInquiryRequests\"", 54));

    free_1905_TLV_structure(p_tlv);
}
END_TEST

START_TEST(test_E9_available_spectrum_inquiry_response)
{

    uint8_t *p_tlv;
    READ_PARSE_FRAGMENTED("tlv_E9_available_spectrum_inquiry_response.pcap")

    map_available_spec_inq_resp_tlv_t *t = (map_available_spec_inq_resp_tlv_t *)p_tlv;

    CHECK_TLV_STRUCT_SIZE

    fail_unless(t->tlv_type == TLV_TYPE_AVAILABLE_SPECTRUM_INQUIRY_RESPONSE);
    fail_unless(t->resp_len == 3924);
    fail_unless(!memcmp(t->resp, (char *)"{ \"availableSpectrumInquiryResponses\"", 37));

    free_1905_TLV_structure(p_tlv);
}
END_TEST

/*#######################################################################
#                       VARIOUS                                         #
########################################################################*/
START_TEST(test_FE_unknown)
{
    VARS
    READ_PARSE("tlv_FE_unknown.pcap")

    i1905_unknown_tlv_t *t = (i1905_unknown_tlv_t *)p_tlv;
    fail_unless(t->tlv_type      == TLV_TYPE_UNKNOWN);
    fail_unless(t->real_tlv_type == 0xFE);
    fail_unless(t->v_nr          == 16);
    fail_unless(!memcmp(t->v, (uint8_t[]){0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}, 16));

    FORGE
    CLEANUP
}
END_TEST

START_TEST(test_too_short)
{
    uint8_t  tlv[] = {0x1, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};  /* al mac address type */
    uint8_t *p_tlv;
    size_t   i;

    fail_unless(!(parse_1905_TLV_from_packet(NULL, 10)));
    /* - 0, 1, 2:          too short tlv header
       - 3, 4, 5, 6, 7, 8: too short payload
       - 9:                ok
    */
    for (i = 0; i < sizeof(tlv); i++) {
        fail_unless(!(parse_1905_TLV_from_packet(tlv, i)));
    }

    fail_unless(!!(p_tlv = parse_1905_TLV_from_packet(tlv, i)));

    free_1905_TLV_structure(p_tlv);
}
END_TEST

const char *test_suite_name = "tlvs";
test_case_t test_cases[] = {
    /* 1905 */
    TEST("00_end_of_message",                         test_00_end_of_message                          ),
    TEST("01_al_mac_address",                         test_01_al_mac_address                          ),
    TEST("02_mac_address",                            test_02_mac_address                             ),
    TEST("03_device_information",                     test_03_device_information                      ),
    TEST("04_device_bridging_capability",             test_04_device_bridging_capability              ),
    TEST("06_non_1905_neighbor_device_list",          test_06_non_1905_neighbor_device_list           ),
    TEST("07_neighbor_device_list",                   test_07_neighbor_device_list                    ),
    TEST("08_link_metric_query",                      test_08_link_metric_query                       ),
    TEST("09_transmitter_link_metric",                test_09_transmitter_link_metric                 ),
    TEST("0A_receiver_link_metric",                   test_0A_receiver_link_metric                    ),
    TEST("0B_vendor_specific",                        test_0B_vendor_specific                         ),
    TEST("0C_link_metric_result_code",                test_0C_link_metric_result_code                 ),
    TEST("0D_searched_role",                          test_0D_searched_role                           ),
    TEST("0E_autoconfig_freq_band",                   test_0E_autoconfig_freq_band                    ),
    TEST("0F_supported_role",                         test_0F_supported_role                          ),
    TEST("10_supported_freq_band",                    test_10_supported_freq_band                     ),
    TEST("11_wsc",                                    test_11_wsc                                     ),
    TEST("12_push_button_event_notification",         test_12_push_button_event_notification          ),
    TEST("13_push_button_join_notification",          test_13_push_button_join_notification           ),
    TEST("14_generic_phy_device_information",         test_14_generic_phy_device_information          ),
    TEST("1A_1905_profile_version",                   test_1A_1905_profile_version                    ),
    TEST("15_device_identification",                  test_15_device_identification                   ),
    TEST("16_control_url",                            test_16_control_url                             ),
    TEST("17_ipv4",                                   test_17_ipv4                                    ),
    TEST("18_ipv6 ",                                  test_18_ipv6                                    ),
    TEST("19_generic_phy_event_notification",         test_19_generic_phy_event_notification          ),
    TEST("1B_power_off_interface",                    test_1B_power_off_interface                     ),
    TEST("1C_interface_power_change_information",     test_1C_interface_power_change_information      ),
    TEST("1D_interface_power_change_status",          test_1D_interface_power_change_status           ),
    TEST("1E_l2_neighbor_device",                     test_1E_l2_neighbor_device                      ),

    /* MAP R1 */
    TEST("80_supported_service",                      test_80_supported_service                       ),
    TEST("81_searched_service",                       test_81_searched_service                        ),
    TEST("82_ap_radio_identifier",                    test_82_ap_radio_identifier                     ),
    TEST("83_ap_operational_bss",                     test_83_ap_operational_bss                      ),
    TEST("84_associated_clients",                     test_84_associated_clients                      ),
    TEST("85_ap_radio_basic_capabilities",            test_85_ap_radio_basic_capabilities             ),
    TEST("86_ap_ht_capabilities",                     test_86_ap_ht_capabilities                      ),
    TEST("87_ap_vht_capabilities",                    test_87_ap_vht_capabilities                     ),
    TEST("88_ap_he_capabilities",                     test_88_ap_he_capabilities                      ),
    TEST("89_steering_policy",                        test_89_steering_policy                         ),
    TEST("89_steering_policy_2",                      test_89_steering_policy_2                       ),
    TEST("8A_metric_reporting_policy",                test_8A_metric_reporting_policy                 ),
    TEST("8B_channel_preference",                     test_8B_channel_preference                      ),
    TEST("8C_radio_operation_restriction",            test_8C_radio_operation_restriction             ),
    TEST("8D_transmit_power_limit",                   test_8D_transmit_power_limit                    ),
    TEST("8E_channel_selection_response",             test_8E_channel_selection_response              ),
    TEST("8F_operating_channel_report ",              test_8F_operating_channel_report                ),
    TEST("90_client_info",                            test_90_client_info                             ),
    TEST("91_client_capability_report",               test_91_client_capability_report                ),
    TEST("92_client_association_event",               test_92_client_association_event                ),
    TEST("93_ap_metric_query",                        test_93_ap_metric_query                         ),
    TEST("94_ap_metrics",                             test_94_ap_metrics                              ),
    TEST("95_sta_mac_address",                        test_95_sta_mac_address                         ),
    TEST("96_associated_sta_link_metrics",            test_96_associated_sta_link_metrics             ),
    TEST("97_unassociated_sta_link_metrics_query",    test_97_unassociated_sta_link_metrics_query     ),
    TEST("98_unassociated_sta_link_metrics_response", test_98_unassociated_sta_link_metrics_response  ),
    TEST("99_beacon_metrics_query",                   test_99_beacon_metrics_query                    ),
    TEST("9A_beacon_metrics_response",                test_9A_beacon_metrics_response                 ),
    TEST("9B_steering_request",                       test_9B_steering_request                        ),
    TEST("9C_steering_btm_report",                    test_9C_steering_btm_report                     ),
    TEST("9D_client_association_control_request",     test_9D_client_association_control_request      ),
    TEST("9E_backhaul_steering_request",              test_9E_backhaul_steering_request               ),
    TEST("9F_backhaul_steering_response",             test_9F_backhaul_steering_response              ),
    TEST("A0_higher_layer_data",                      test_A0_higher_layer_data                       ),
    TEST("A1_ap_capability",                          test_A1_ap_capability                           ),
    TEST("A2_associated_sta_traffic_stats",           test_A2_associated_sta_traffic_stats            ),
    TEST("A3_error_code",                             test_A3_error_code                              ),

    /* MAP R2 */
    TEST("A4_channel_scan_reporting_policy",          test_A4_channel_scan_reporting_policy           ),
    TEST("A5_channel_scan_capabilities",              test_A5_channel_scan_capabilities               ),
    TEST("A6_channel_scan_request",                   test_A6_channel_scan_request                    ),
    TEST("A6_channel_scan_request_2",                 test_A6_channel_scan_request_2                  ),
    TEST("A7_channel_scan_result",                    test_A7_channel_scan_result                     ),
    TEST("A7_channel_scan_result_malformed",          test_A7_channel_scan_result_malformed           ),
    TEST("A8_timestamp",                              test_A8_timestamp                               ),
    TEST("AD_cac_request",                            test_AD_cac_request                             ),
    TEST("AE_cac_termination",                        test_AE_cac_termination                         ),
    TEST("AF_cac_completion_report",                  test_AF_cac_completion_report                   ),
    TEST("B1_cac_status_report",                      test_B1_cac_status_report                       ),
    TEST("B2_cac_capabilities",                       test_B2_cac_capabilities                        ),
    TEST("B3_multiap_profile",                        test_B3_multiap_profile                         ),
    TEST("B4_profile2_ap_capability",                 test_B4_profile2_ap_capability                  ),
    TEST("B5_default_8021q_settings",                 test_B5_default_8021q_settings                  ),
    TEST("B6_traffic_separation_policy",              test_B6_traffic_separation_policy               ),
    TEST("BC_profile2_error_code",                    test_BC_profile2_error_code                     ),
    TEST("BE_ap_radio_advanced_capabilities",         test_BE_ap_radio_advanced_capabilities          ),
    TEST("BF_association_status_notification",        test_BF_association_status_notification         ),
    TEST("C0_source_info",                            test_C0_source_info                             ),
    TEST("C1_tunneled_message_type",                  test_C1_tunneled_message_type                   ),
    TEST("C2_tunneled",                               test_C2_tunneled                                ),
    TEST("C3_profile2_steering_request",              test_C3_profile2_steering_request               ),
    TEST("C4_unsuccessful_association_policy",        test_C4_unsuccessful_association_policy         ),
    TEST("C5_metric_collection_interval",             test_C5_metric_collection_interval              ),
    TEST("C6_radio_metrics",                          test_C6_radio_metrics                           ),
    TEST("C7_ap_extended_metrics",                    test_C7_ap_extended_metrics                     ),
    TEST("C8_associated_sta_extended_link_metrics",   test_C8_associated_sta_extended_link_metrics    ),
    TEST("C9_status_code",                            test_C9_status_code                             ),
    TEST("CA_reason_code",                            test_CA_reason_code                             ),
    TEST("CB_backhaul_sta_radio_capabilities",        test_CB_backhaul_sta_radio_capabilities         ),
    TEST("D0_backhaul_bss_configuration",             test_D0_backhaul_bss_configuration              ),

    /* MAP R3 */
    TEST("A9_1905_security_capability",               test_A9_1905_security_capability                ),
    TEST("AA_ap_wifi6_capabilities",                  test_AA_ap_wifi6_capabilities                   ),
    TEST("AB_mic",                                    test_AB_mic                                     ),
    TEST("AC_encrypted_payload",                      test_AC_encrypted_payload                       ),
    TEST("B0_associated_wifi6_sta_status",            test_B0_associated_wifi6_sta_status             ),
    TEST("B7_bss_configuration_report",               test_B7_bss_configuration_report                ),
    TEST("B8_bssid",                                  test_B8_bssid                                   ),
    TEST("CC_akm_suite_capabilities",                 test_CC_akm_suite_capabilities                  ),
    TEST("CE_1905_encap_eapol",                       test_CE_1905_encap_eapol                        ),
    TEST("D1_dpp_message",                            test_D1_dpp_message                             ),
    TEST("D2_dpp_cce_indication",                     test_D2_dpp_cce_indication                      ),
    TEST("CD_1905_encap_dpp",                         test_CD_1905_encap_dpp                          ),
    TEST("CD_1905_encap_dpp_no_enrollee_mac",         test_CD_1905_encap_dpp_no_enrollee_mac          ),
    TEST("D3_dpp_chirp",                              test_D3_dpp_chirp_value                         ),
    TEST("D3_dpp_chirp_value_no_enrollee_mac",        test_D3_dpp_chirp_value_no_enrollee_mac         ),
    TEST("D4_device_inventory",                       test_D4_device_inventory                        ),
    TEST("D5_agent_list",                             test_D5_agent_list                              ),

    /* MAP R4 */
    TEST("DD_controller_capability",                  test_DD_controller_capability                   ),

    /* MAP R6 */
    TEST("DF_wifi7_agent_capabilities",               test_DF_wifi7_agent_capabilities                ),
    TEST("E0_agent_ap_mld_configuration",             test_E0_agent_ap_mld_configuration              ),
    TEST("E1_backhaul_sta_mld_configuration",         test_E1_backhaul_sta_mld_configuration          ),
    TEST("E2_associated_sta_mld_configuration",       test_E2_associated_sta_mld_configuration        ),
    TEST("E4_affiliated_sta_metrics",                 test_E4_affiliated_sta_metrics                  ),
    TEST("E5_affiliated_ap_metrics",                  test_E5_affiliated_ap_metrics                   ),
    /* TODO Implement when the tlv implemented in the agent side */
    /* TEST("E7_eht_operations",                      test_E7_eht_operations                          ), */
    TEST("E8_available_spectrum_inquiry_request",     test_E8_available_spectrum_inquiry_request      ),
    TEST("E9_available_spectrum_inquiry_response",    test_E9_available_spectrum_inquiry_response     ),

    /* Various */
    TEST("FE_unknown",                                test_FE_unknown                                 ),
    TEST("too_short",                                 test_too_short                                  ),
    TEST_CASES_END
};
