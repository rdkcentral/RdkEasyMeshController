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
#include <arpa/inet.h>

#include "test.h"

#include "i1905.h"
#include "al_send.h"
#include "al_datamodel.h"

#include "stub/stub_platform_os.h"

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static mac_addr  g_al_mac           = {0x02, 0x01, 0x02, 0x03, 0x04, 0x05};
static mac_addr  g_src_mac          = {0x00, 0x11, 0x12, 0x13, 0x14, 0x15};
static mac_addr  g_dst_mac          = {0x00, 0x21, 0x22, 0x23, 0x24, 0x25};
static mac_addr  g_lldp_mcast_mac   = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e};

static char     *g_ifname           = "wl0";
static int       g_cb_count;

static uint8_t   g_lldp_payload[24] = {/* chassid_id   */ 0x02, 0x07, 0x04, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05,
                                       /* port_id      */ 0x04, 0x07, 0x03, 0x12, 0x11, 0x12, 0x13, 0x14, 0x15,
                                       /* time_to_live */ 0x06, 0x02, 0x00, 0xb4,
                                       /* end_of_lldp  */ 0x00, 0x00
                                      };

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
static void test_init(i1905_unit_test_send_cb_t send_cb)
{
    DMinit();
    DMalMacSet(g_al_mac);
    PLATFORM_OS_INIT(NULL, NULL, NULL);
    PLATFORM_REGISTER_UNIT_TEST_SEND_CB(send_cb);

    g_cb_count = 0;
}

static void test_fini(void)
{
    PLATFORM_REGISTER_UNIT_TEST_SEND_CB(NULL);
    PLATFORM_OS_FINI();
    DMfini();
}

/*#######################################################################
#                       TEST_OBTAIN_TLV_FROM_1905                       #
########################################################################*/
static void check_local_interface(char *ifname, i1905_local_interface_entry_t *local_interface)
{
    i1905_interface_info_t info;
    PLATFORM_OS_GET_1905_INTERFACE_INFO(ifname, &info);

    fail_unless(!maccmp(local_interface->mac_address, info.mac_address));
    fail_unless(local_interface->media_type == info.interface_type);

    if (INTERFACE_TYPE_GROUP_WLAN == INTERFACE_TYPE_GROUP_GET(local_interface->media_type)) {
        fail_unless(local_interface->media_specific_data_size == 10);
    }
}

START_TEST(test_obtain_tlv_from_1905)
{
    i1905_al_mac_address_tlv_t       *al_mac_address_tlv       = NULL;
    i1905_searched_role_tlv_t        *searched_role_tlv        = NULL;
    i1905_autoconfig_freq_band_tlv_t *autoconfig_freq_band_tlv = NULL;
    i1905_supported_role_tlv_t       *supported_role_tlv       = NULL;
    i1905_device_information_tlv_t   *device_information_tlv   = NULL;
    i1905_supported_freq_band_data_t  s_data                   = { 0 };
    i1905_wsc_data_t                  w_data                   = { 0 };
    map_profile_cfg_t                 profile                  = { 0 };
    i1905_wsc_m2_cfg_t                m2_cfg                   = {.profile = &profile};

    test_init(NULL);

    /* INVALID */
    fail_unless(obtainTLVFrom1905(g_ifname, I1905_GET_ALMAC_TLV, NULL));
    fail_unless(obtainTLVFrom1905(g_ifname, 9999, (void*)0xdeadbeef));


    /* I1905_GET_ALMAC_TLV */
    fail_unless(!!(al_mac_address_tlv = calloc(1, sizeof(*al_mac_address_tlv))));
    fail_unless(!obtainTLVFrom1905(g_ifname, I1905_GET_ALMAC_TLV, al_mac_address_tlv));
    fail_unless(al_mac_address_tlv->tlv_type == TLV_TYPE_AL_MAC_ADDRESS);
    fail_unless(!maccmp(al_mac_address_tlv->al_mac_address, g_al_mac));
    free_1905_TLV_structure((uint8_t*)al_mac_address_tlv);


    /* I1905_GET_SEARCHEDROLE_TLV */
    fail_unless(!!(searched_role_tlv = calloc(1, sizeof(*searched_role_tlv))));
    fail_unless(!obtainTLVFrom1905(g_ifname, I1905_GET_SEARCHEDROLE_TLV, searched_role_tlv));
    fail_unless(searched_role_tlv->tlv_type == TLV_TYPE_SEARCHED_ROLE);
    fail_unless(searched_role_tlv->role == IEEE80211_ROLE_AP);
    free_1905_TLV_structure((uint8_t*)searched_role_tlv);


    /* I1905_GET_FREQUENCYBAND_TLV */
    fail_unless(!!(autoconfig_freq_band_tlv = calloc(1, sizeof(*autoconfig_freq_band_tlv))));
    fail_unless(!obtainTLVFrom1905(g_ifname, I1905_GET_FREQUENCYBAND_TLV, autoconfig_freq_band_tlv));
    fail_unless(autoconfig_freq_band_tlv->tlv_type == TLV_TYPE_AUTOCONFIG_FREQ_BAND);
    fail_unless(autoconfig_freq_band_tlv->freq_band == IEEE80211_FREQUENCY_BAND_5_GHZ); /* Derived from interface list - see stub_platform_os.c */
    free_1905_TLV_structure((uint8_t*)autoconfig_freq_band_tlv);


    /* I1905_GET_SUPPORTEDROLEBAND_TLV */
    fail_unless(!!(supported_role_tlv = calloc(1, sizeof(*supported_role_tlv))));
    fail_unless(!obtainTLVFrom1905(g_ifname, I1905_GET_SUPPORTEDROLE_TLV, supported_role_tlv));
    fail_unless(supported_role_tlv->tlv_type == TLV_TYPE_SUPPORTED_ROLE);
    fail_unless(supported_role_tlv->role == IEEE80211_ROLE_AP);
    free_1905_TLV_structure((uint8_t*)supported_role_tlv);


    /* I1905_GET_SUPPORTEDFREQBAND_TLV */
    fail_unless(!!(s_data.supported_freq_band_tlv = calloc(1, sizeof(*s_data.supported_freq_band_tlv))));
    s_data.freq_band = IEEE80211_FREQUENCY_BAND_2_4_GHZ;
    fail_unless(!obtainTLVFrom1905(g_ifname, I1905_GET_SUPPORTEDFREQBAND_TLV, &s_data));
    fail_unless(s_data.supported_freq_band_tlv->tlv_type == TLV_TYPE_SUPPORTED_FREQ_BAND);
    fail_unless(s_data.supported_freq_band_tlv->freq_band == IEEE80211_FREQUENCY_BAND_2_4_GHZ);
    free_1905_TLV_structure((uint8_t*)s_data.supported_freq_band_tlv);


    /* I1905_GET_DEVICEINFO_TLV */
    /* See stub_platform_os.c for interface list */
    fail_unless(!!(device_information_tlv = calloc(1, sizeof(*device_information_tlv))));
    fail_unless(!obtainTLVFrom1905(g_ifname, I1905_GET_DEVICEINFO_TLV, device_information_tlv));
    fail_unless(device_information_tlv->tlv_type == TLV_TYPE_DEVICE_INFORMATION);
    fail_unless(!maccmp(device_information_tlv->al_mac_address, g_al_mac));
    fail_unless(device_information_tlv->local_interfaces_nr == 6);
    check_local_interface("eth0", &device_information_tlv->local_interfaces[1]);
    check_local_interface("wl0",  &device_information_tlv->local_interfaces[5]);
    free_1905_TLV_structure((uint8_t*)device_information_tlv);


    /* I1905_GET_WSCM1_TLV */
    fail_unless(!obtainTLVFrom1905(g_ifname, I1905_GET_WSCM1_TLV, &w_data));
    fail_unless(!!(w_data.m1.tlv_type == TLV_TYPE_WSC));
    fail_unless(!!w_data.m1.wsc_frame);
    fail_unless(w_data.m1.wsc_frame_size > 0);


    /* I1905_GET_WSCM2_TLV */
    w_data.m2_cfg = &m2_cfg;
    fail_unless(!obtainTLVFrom1905(g_ifname, I1905_GET_WSCM2_TLV, &w_data));
    fail_unless(!!(w_data.m2.tlv_type == TLV_TYPE_WSC));
    fail_unless(!!w_data.m2.wsc_frame);
    fail_unless(w_data.m2.wsc_frame_size > 0);
    free(w_data.m1.wsc_frame);
    free(w_data.m2.wsc_frame);
    free(w_data.wsc_key->key);
    free(w_data.wsc_key);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_1905_RAW_PACKET                            #
########################################################################*/
static void raw_send_cb(char *ifname, uint8_t *payload, uint16_t payload_len)
{
    g_cb_count++;

    fail_unless(!strcmp(ifname, g_ifname));

    fail_unless(payload_len == /* eth */ 14 + /* cmdu */ 8 + /* al_mac_tlv*/ 9 + /* eom_tlv */ 3);

    /* ETH header */
    fail_unless(!maccmp(&payload[0], g_dst_mac));
    fail_unless(!maccmp(&payload[6], g_cb_count == 1 ? g_al_mac : g_src_mac));
    fail_unless((payload[12] << 8) + payload[13] == 0x893a);

    /* CMDU header */
    cmdu_hdr_t *cmdu_hdr = (cmdu_hdr_t *)&payload[14];
    fail_unless(cmdu_hdr->message_version == CMDU_MESSAGE_VERSION_1905_1_2013);
    fail_unless(cmdu_hdr->message_type == htons(CMDU_TYPE_TOPOLOGY_NOTIFICATION));
    fail_unless(cmdu_hdr->message_id == htons(0x123));
    fail_unless(cmdu_hdr->fragment_id == 0);
    fail_unless(cmdu_hdr->indicators == 0x80); /* last fragment */

    /* TLV */
    tlv_hdr_t *tlv_hdr = (tlv_hdr_t*)&payload[22];
    fail_unless(tlv_hdr->type == TLV_TYPE_AL_MAC_ADDRESS);
    fail_unless(tlv_hdr->len == htons(6));
    fail_unless(!maccmp(&tlv_hdr[1], g_al_mac));

    tlv_hdr = (tlv_hdr_t*)&payload[31];
    fail_unless(tlv_hdr->type == TLV_TYPE_END_OF_MESSAGE);
    fail_unless(tlv_hdr->len == htons(0));
}

START_TEST(test_send_1905_raw_packet)
{
    i1905_cmdu_t                cmdu            = {0};
    i1905_al_mac_address_tlv_t  al_mac_addr_tlv = {.tlv_type = TLV_TYPE_AL_MAC_ADDRESS};
    uint8_t                    *tlvs[2]         = {(uint8_t*)&al_mac_addr_tlv, NULL};

    test_init(raw_send_cb);

    /* Create a cmdu */
    maccpy(al_mac_addr_tlv.al_mac_address, g_al_mac);

    cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type    = CMDU_TYPE_TOPOLOGY_NOTIFICATION;
    cmdu.message_id      = 0x123;
    cmdu.relay_indicator = RELAY_INDICATOR_OFF;
    cmdu.list_of_TLVs    = tlvs;
    maccpy(cmdu.cmdu_stream.src_mac_addr, g_src_mac);
    strcpy(cmdu.interface_name, "eth0");

    fail_unless(send1905RawPacket(g_ifname, 0x123, g_dst_mac, &cmdu) == 1);
    fail_unless(g_cb_count == 1);
    fail_unless(forward1905RawPacket(g_ifname, 0x123, g_dst_mac, &cmdu, /* cmdu mac as src mac */true) == 1);
    fail_unless(g_cb_count == 2);

    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_ENCRYPTED_PACKET                      #
########################################################################*/
static void encrypted_send_cb(char *ifname, uint8_t *payload, uint16_t payload_len)
{
    uint16_t siv_len           = 0x0014;
    uint8_t  siv_output[]      = {0xfc, 0x4c, 0xa5, 0xa1, 0x31, 0xdf, 0xcf, 0xb9, 0xf7, 0xf6, 0xd6, 0x8b, 0xfc, 0xd5, 0x78, 0xd0, 0x0a, 0x74, 0xf3, 0xb5};
    uint8_t  encr_tx_counter[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    mac_addr dst_mac           = {0xf6, 0x17, 0xb8, 0xae, 0x89, 0xa3};
    fail_unless(!strcmp(ifname, g_ifname));
    fail_unless(payload_len == /* eth */ 14 + /* cmdu */ 8 + /* encrypted_payload_tlv */ 43 + /* eom_tlv */ 3);
    /* ETH header */
    fail_unless(!maccmp(&payload[0], dst_mac));
    fail_unless(!maccmp(&payload[6], g_al_mac));
    fail_unless((payload[12] << 8) + payload[13] == 0x893a);
    /* CMDU header */
    cmdu_hdr_t *cmdu_hdr = (cmdu_hdr_t *)&payload[14];
    fail_unless(cmdu_hdr->message_version == CMDU_MESSAGE_VERSION_1905_1_2013);
    fail_unless(cmdu_hdr->message_type == htons(CMDU_TYPE_TOPOLOGY_QUERY));
    fail_unless(cmdu_hdr->message_id == htons(0x79cd));
    fail_unless(cmdu_hdr->fragment_id == 0);
    fail_unless(cmdu_hdr->indicators == 0x80); /* last fragment */
    /* TLV */
    tlv_hdr_t *tlv_hdr = (tlv_hdr_t*)&payload[22];
    uint8_t *p = (uint8_t *)&tlv_hdr[1];
    fail_unless(tlv_hdr->type == TLV_TYPE_ENCRYPTED_PAYLOAD);
    fail_unless(tlv_hdr->len == htons(40));
    fail_unless(!memcmp(p, encr_tx_counter, ENCRYPTION_TX_COUNTER_LEN));
    p += ENCRYPTION_TX_COUNTER_LEN;
    fail_unless(!memcmp(p, g_al_mac, ETHER_ADDR_LEN));
    p += ETHER_ADDR_LEN;
    fail_unless(!memcmp(p, dst_mac, ETHER_ADDR_LEN));
    p += ETHER_ADDR_LEN;
    fail_unless((*p << 8) + p[1] == siv_len);
    p += 2;
    fail_unless(!memcmp(p, siv_output, siv_len));
    tlv_hdr = (tlv_hdr_t*)&payload[65];
    fail_unless(tlv_hdr->type == TLV_TYPE_END_OF_MESSAGE);
    fail_unless(tlv_hdr->len == htons(0));
}
START_TEST(test_send_encrypted_packet)
{
    i1905_cmdu_t                cmdu            = {0};
    map_multiap_profile_tlv_t   profile_tlv     = {.tlv_type = TLV_TYPE_MULTIAP_PROFILE, .map_profile = MAP_PROFILE_2};
    uint8_t                    *tlvs[2]         = {(uint8_t*)&profile_tlv, NULL};
    mac_addr dst_mac                            = {0xf6, 0x17, 0xb8, 0xae, 0x89, 0xa3};
    test_init(encrypted_send_cb);
    /* Create a cmdu */
    cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type    = CMDU_TYPE_TOPOLOGY_QUERY;
    cmdu.message_id      = 0x79cd;
    cmdu.relay_indicator = RELAY_INDICATOR_OFF;
    cmdu.list_of_TLVs    = tlvs;
    maccpy(cmdu.cmdu_stream.src_mac_addr, g_al_mac);
    strcpy(cmdu.interface_name, "eth0");
    fail_unless(forward1905RawPacket(g_ifname, 0x123, dst_mac, &cmdu, true) == 1);
    test_fini();
}
END_TEST

/*#######################################################################
#                       TEST_SEND_LLDP_BRIDGE_DISCOVERY_PACKET          #
########################################################################*/
static void lldp_send_cb(char *ifname, uint8_t *payload, uint16_t payload_len)
{
    g_cb_count++;

    fail_unless(!strcmp(ifname, g_ifname));

    fail_unless(payload_len == /* eth */ 14 + /* tlvs */ sizeof(g_lldp_payload));

    /* ETH header */
    fail_unless(!maccmp(&payload[0], g_lldp_mcast_mac));
    fail_unless(!maccmp(&payload[6], g_src_mac));
    fail_unless((payload[12] << 8) + payload[13] == 0x88cc);

    /* TLVS */
    fail_unless(!memcmp(&payload[14], g_lldp_payload, sizeof(g_lldp_payload)));
}

START_TEST(test_send_lldp_bridge_discovery_packet)
{
    i1905_lldp_payload_t *p_payload;

    test_init(lldp_send_cb);

    fail_unless(!!(p_payload = parse_lldp_PAYLOAD_from_packet(g_lldp_payload)));

    fail_unless(sendLLDPBridgeDiscoveryPacket(g_ifname, g_src_mac, p_payload) == 1);

    free_lldp_PAYLOAD_structure(p_payload);
    test_fini();
}
END_TEST


const char *test_suite_name = "al_send";
test_case_t test_cases[] = {
    TEST("obtain_tlv_from_1905",              test_obtain_tlv_from_1905  ),
    TEST("send_1905_raw_packet",              test_send_1905_raw_packet  ),
    TEST("send_encrypted_packet",             test_send_encrypted_packet ),
    TEST("send_lldp_bridge_discovery_packet", test_send_lldp_bridge_discovery_packet  ),
    TEST_CASES_END
};
