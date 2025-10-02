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

#include "1905_cmdus.h"
#include "1905_tlvs.h"
#include "map_tlvs.h"
#include "al.h"
#include "al_utils.h"
#include "al_send.h"

#include "utils.h"    /* print_callback */
#include "platform.h" /* PLATFORM_PRINTF */

#include "stub/stub_platform_os.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define MAX_CMDU    256
#define MAX_PACKETS 256

#define VARS               \
    packet_t **packets;    \
    size_t     packets_nr;

#define READ(file)                                                                    \
    fail_unless(!!(packets = pcap_read_all_packets(DATA_DIR "/" file, &packets_nr))); \
    set_src_dest_mac(packets, packets_nr);

#define READ_PARSE(file)                  \
    READ(file)                            \
    process_packets(packets, packets_nr);

#define INIT                                      \
    log_test_i("######## %s", __FUNCTION__);      \
    start1905AL(g_al_mac, 0, "eth0", NULL, cmdu_cb, NULL);    \
    PLATFORM_REGISTER_UNIT_TEST_SEND_CB(send_cb);

#define SEND_COMPARE                                                          \
    send_cmdus();                                                             \
    compare_cmdu_packets(packets, packets_nr, g_tx_packets, g_tx_packets_nr);

#define CLEANUP                        \
    free_packets(packets, packets_nr); \
    free_rx_cmdus();                   \
    free_tx_packets();                 \
    stop1905AL();

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static mac_addr      g_al_mac = {0x02, 0x01, 0x02, 0x03, 0x04, 0x05};

static mac_addr      g_dest_mac = {0x02, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};

static i1905_cmdu_t *g_rx_cmdus[MAX_CMDU];
static size_t        g_rx_cmdus_nr;

static packet_t     *g_tx_packets[MAX_PACKETS];
static size_t        g_tx_packets_nr;

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
/* Set dest mac to ale mac unless it is 1905 or lldp mcast */
static void set_src_dest_mac(packet_t **p, size_t nr)
{
    size_t i;

    for (i = 0; i < nr; i++) {
        eth_hdr_t *eh = (eth_hdr_t *)p[i]->data;

        if (maccmp(eh->ether_dhost, g_mcast_mac_1905) && maccmp(eh->ether_dhost, g_mcast_mac_lldp)) {
            maccpy(eh->ether_dhost, g_al_mac);
        }
    }
}

static void send_cb(char *if_name, uint8_t *payload, uint16_t payload_len)
{
    packet_t *p = calloc(1, sizeof(packet_t));

    fail_unless(payload_len <= sizeof(p->data));

    strcpy(p->if_name, if_name);
    p->len = payload_len;
    memcpy(p->data, payload, payload_len);

    g_tx_packets[g_tx_packets_nr++] = p;
}

static bool cmdu_cb(i1905_cmdu_t *cmdu)
{
    g_rx_cmdus[g_rx_cmdus_nr++] = cmdu;
    return true;
}

static void process_packets(packet_t **p, size_t nr)
{
    size_t i;

    fail_unless(NULL != g_stub_platform_os_packet_cb);

    for (i = 0; i < nr; i++) {
        g_stub_platform_os_packet_cb("eth0", p[i]->data, p[i]->len);
    }
}

static void check_tlv_sequence(i1905_cmdu_t *cmdu, size_t tlv_len, size_t exp_tlv_nr)
{
    uint8_t *tlv;
    size_t   idx;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        i1905_vendor_specific_tlv_t *t = (i1905_vendor_specific_tlv_t *)tlv;
        uint8_t                     *p = t->m;
        uint16_t                     v;

        fail_unless(t->tlv_type == TLV_TYPE_VENDOR_SPECIFIC);
        fail_unless(t->m_nr     == tlv_len);

        /* Payload is tlv index in 16 bit */
        _E2B(&p, &v);
        fail_unless(idx == v);
    }
    fail_unless(idx == exp_tlv_nr);
}

static void send_cmdus(void)
{
    size_t i;

    for (i = 0; i < g_rx_cmdus_nr; i++) {
        i1905_cmdu_t *cmdu = g_rx_cmdus[i];
        fail_unless(send1905RawPacket("eth0", cmdu->message_id, g_dest_mac, cmdu) == 1);
    }
}

static void set_mid(packet_t **p, size_t nr, uint16_t mid)
{
    size_t i;

    for (i = 0; i < nr; i++) {
        cmdu_hdr_t *ch1 = (cmdu_hdr_t *)(p[i]->data + sizeof(eth_hdr_t));
        ch1->message_id = htons(mid);
    }
}

/* Compare 2 arrays of packets containing CMDU. Can be fragmented and in the wrong order  */
static void compare_cmdu_packets(packet_t **p1, size_t p1_nr, packet_t **p2, size_t p2_nr)
{
    size_t i, j;

    fail_unless(p1_nr == p2_nr);

    /* Fail if there are too short or non CMDU packets */
    for (i = 0; i < p1_nr; i++) {
        eth_hdr_t *eh = (eth_hdr_t *)p1[i]->data;
        fail_unless(p1[i]->len >= sizeof(eth_hdr_t) + sizeof(cmdu_hdr_t));
        fail_unless(eh->ether_type == htons(ETHERTYPE_1905));

        eh = (eth_hdr_t *)p2[i]->data;
        fail_unless(p2[i]->len >= sizeof(eth_hdr_t) + sizeof(cmdu_hdr_t));
        fail_unless(eh->ether_type == htons(ETHERTYPE_1905));
    }

    /* Compare but skip eth source and dest mac. */
    for (i = 0; i < p1_nr; i++) {
        cmdu_hdr_t *ch1 = (cmdu_hdr_t *)(p1[i]->data + sizeof(eth_hdr_t));

        log_test_i("compare cmdu: find packet[%zu] mid[0x%02X] frag_id[%d] len[%d]", i, htons(ch1->message_id), ch1->fragment_id, p1[i]->len);
        for (j = 0; j < p1_nr; j++) {
            cmdu_hdr_t *ch2 = (cmdu_hdr_t *)(p2[j]->data + sizeof(eth_hdr_t));

            log_test_i("              check packet[%zu] mid[0x%02X] frag_id[%d] len[%d]", j, htons(ch2->message_id), ch2->fragment_id, p2[j]->len);
            if (ch1->message_id == ch2->message_id && ch1->fragment_id == ch2->fragment_id) {
                log_test_i("              found!");
                fail_unless(p1[i]->len == p2[j]->len);
                fail_unless(!memcmp(ch1, ch2, p1[i]->len - sizeof(eth_hdr_t)));
                break;
            }
        }
        fail_unless(j < p1_nr);
    }
}

static void free_rx_cmdus(void)
{
    size_t i;

    for (i = 0; i < g_rx_cmdus_nr; i++) {
        free_1905_CMDU_structure(g_rx_cmdus[i]);
        g_rx_cmdus[i] = NULL;
    }

    g_rx_cmdus_nr = 0;
}

static void free_tx_packets(void)
{
    size_t i;

    for (i = 0; i < g_tx_packets_nr; i++) {
        free(g_tx_packets[i]);
        g_tx_packets[i] = NULL;
    }

    g_tx_packets_nr = 0;
}

/*#######################################################################
#                       TEST_UNFRAGMENTED                               #
########################################################################*/
START_TEST(test_unfragmented)
{
    VARS
    INIT
    READ_PARSE("cmdu_topology_response.pcap")

    /* Check result */
    fail_unless(g_rx_cmdus_nr == 1);

    i1905_cmdu_t *cmdu = g_rx_cmdus[0];
    fail_unless(cmdu->message_type == CMDU_TYPE_TOPOLOGY_RESPONSE);
    fail_unless(*cmdu->list_of_TLVs[0] == TLV_TYPE_DEVICE_INFORMATION);
    fail_unless(*cmdu->list_of_TLVs[1] == TLV_TYPE_DEVICE_BRIDGING_CAPABILITY);
    fail_unless(*cmdu->list_of_TLVs[2] == TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST);
    fail_unless(*cmdu->list_of_TLVs[3] == TLV_TYPE_NEIGHBOR_DEVICE_LIST);
    fail_unless(*cmdu->list_of_TLVs[4] == TLV_TYPE_NEIGHBOR_DEVICE_LIST);
    fail_unless(*cmdu->list_of_TLVs[5] == TLV_TYPE_SUPPORTED_SERVICE);
    fail_unless(*cmdu->list_of_TLVs[6] == TLV_TYPE_AP_OPERATIONAL_BSS);
    fail_unless(*cmdu->list_of_TLVs[7] == TLV_TYPE_MULTIAP_PROFILE);
    fail_unless(*cmdu->list_of_TLVs[8] == TLV_TYPE_VENDOR_SPECIFIC);
    fail_unless(cmdu->list_of_TLVs[9]  == NULL);

    SEND_COMPARE
    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_FRAGMENTED_ORDERED                         #
########################################################################*/
/* Fragments are in normal order */
START_TEST(test_fragmented_ordered)
{
    VARS
    INIT
    READ_PARSE("cmdu_fragmented_ordered.pcap")

    /* Check result */
    fail_unless(g_rx_cmdus_nr == 1);

    i1905_cmdu_t *cmdu = g_rx_cmdus[0];
    fail_unless(cmdu->message_id == 0x100);
    check_tlv_sequence(cmdu, 512, 10);

    SEND_COMPARE
    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_FRAGMENTED_REVERSED                        #
########################################################################*/
/* Fragments are in reverse order */
START_TEST(test_fragmented_reversed)
{
    VARS
    INIT
    READ_PARSE("cmdu_fragmented_reversed.pcap")

    /* Check result */
    fail_unless(g_rx_cmdus_nr == 1);

    i1905_cmdu_t *cmdu = g_rx_cmdus[0];
    fail_unless(cmdu->message_id == 0x101);
    check_tlv_sequence(cmdu, 512, 10);

    SEND_COMPARE
    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_FRAGMENTED_SCRAMBLED                       #
########################################################################*/
/* Fragments are scrambled */
START_TEST(test_fragmented_scrambled)
{
    VARS
    INIT
    READ_PARSE("cmdu_fragmented_scrambled.pcap")

    /* Check result */
    fail_unless(g_rx_cmdus_nr == 1);

    i1905_cmdu_t *cmdu = g_rx_cmdus[0];
    fail_unless(cmdu->message_id == 0x102);
    check_tlv_sequence(cmdu, 512, 10);

    SEND_COMPARE
    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_FRAGMENTED_MIXED                           #
########################################################################*/
/* 3 fragmented CMDU with fragments mixed */
START_TEST(test_fragmented_mixed)
{
    VARS
    INIT
    READ_PARSE("cmdu_fragmented_mixed.pcap")

    /* Check result */
    fail_unless(g_rx_cmdus_nr == 3);

    i1905_cmdu_t *cmdu = g_rx_cmdus[0];
    fail_unless(cmdu->message_id == 0x100);
    check_tlv_sequence(cmdu, 512, 10);

    cmdu = g_rx_cmdus[1];
    fail_unless(cmdu->message_id == 0x101);
    check_tlv_sequence(cmdu, 512, 10);

    cmdu = g_rx_cmdus[2];
    fail_unless(cmdu->message_id == 0x102);
    check_tlv_sequence(cmdu, 512, 10);

    SEND_COMPARE
    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_FRAGMENTED_EOM_IN_ALL_FRAG                 #
########################################################################*/
/* Some agents add EOM in all fragments */
START_TEST(test_fragmented_eom_in_all_frag)
{
    VARS
    INIT
    READ_PARSE("cmdu_fragmented_eom_in_all_frag.pcap")

    /* Check result */
    fail_unless(g_rx_cmdus_nr == 1);

    i1905_cmdu_t *cmdu = g_rx_cmdus[0];
    fail_unless(cmdu->message_id == 0x100);
    check_tlv_sequence(cmdu, 512, 10);

    /* Can't do SEND_COMPARE, it will fail... */
    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_FRAGMENTED_LOST                            #
########################################################################*/
/* Fragmented with lost packets, test that they are discarded...
   Currently 8 sets of fragments are stored (not enough??)
*/
#define MAX_CMDU_IN_FLIGHT 8
START_TEST(test_fragmented_lost)
{
    VARS
    INIT
    READ("cmdu_fragmented_ordered.pcap");

    /* Process 10 times without last packet, incremented MID */
    uint16_t mid = 1000;
    int      i;
    for (i = 0; i < MAX_CMDU_IN_FLIGHT + 2; i++) {
        set_mid(packets, packets_nr, mid++);
        process_packets(packets, packets_nr - 1);
        fail_unless(g_rx_cmdus_nr == 0);
    }

    /* Complete one of the packets by sending the last one */
    set_mid(packets, packets_nr, mid - 3);
    process_packets(packets + packets_nr - 1, 1);
    fail_unless(g_rx_cmdus_nr == 1);

    i1905_cmdu_t *cmdu = g_rx_cmdus[0];
    fail_unless(cmdu->message_id == mid - 3);

    /* Complete another (too old) one. Fragments are already discarded. */
    set_mid(packets, packets_nr, mid - MAX_CMDU_IN_FLIGHT - 1);
    process_packets(packets + packets_nr - 1, 1);
    fail_unless(g_rx_cmdus_nr == 1);


    /* Process again 10 times , incremented MID */
    for (i = 0; i < 10; i++) {
        set_mid(packets, packets_nr, mid++);
        process_packets(packets, packets_nr - 1);
        fail_unless(g_rx_cmdus_nr == 1);
    }

    /* Process a complete set of fragments.
       This cmdu should get through
    */
    set_mid(packets, packets_nr, mid);
    process_packets(packets, packets_nr);

    fail_unless(g_rx_cmdus_nr == 2);
    cmdu = g_rx_cmdus[1];
    fail_unless(cmdu->message_id == mid);

    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_FRAGMENTED_DUPLICATE                       #
########################################################################*/
/* One fragment is received 2 times */
START_TEST(test_fragmented_duplicate)
{
    VARS
    INIT
    READ("cmdu_fragmented_ordered.pcap");

    /* Process all but last packet */
    set_mid(packets, packets_nr, 1000);
    process_packets(packets, packets_nr - 1);
    fail_unless(g_rx_cmdus_nr == 0);

    /* Process first packet again (= duplicate) */
    process_packets(packets, 1);
    fail_unless(g_rx_cmdus_nr == 0);

    /* Process last packet */
    process_packets(packets + packets_nr - 1, 1);
    fail_unless(g_rx_cmdus_nr == 1);

    i1905_cmdu_t *cmdu = g_rx_cmdus[0];
    fail_unless(cmdu->message_id == 1000);

    CLEANUP
}
END_TEST

/*#######################################################################
#                   TEST_MULTIPLE_FRAGMENT_TLV                          #
########################################################################*/
/* Big TLV fragmented into multiple packet  */
START_TEST(test_multiple_fragment_tlv)
{
    VARS
    INIT
    READ_PARSE("cmdu_multiple_fragment_tlv.pcap")

    i1905_vendor_specific_tlv_t *tlv;

    /* Check result */
    fail_unless(g_rx_cmdus_nr == 1);

    i1905_cmdu_t *cmdu = g_rx_cmdus[0];
    fail_unless(cmdu->message_id       == 0xf010);

    fail_unless(*cmdu->list_of_TLVs[0] == TLV_TYPE_VENDOR_SPECIFIC);
    fail_unless(*cmdu->list_of_TLVs[1] == TLV_TYPE_VENDOR_SPECIFIC);
    fail_unless(*cmdu->list_of_TLVs[2] == TLV_TYPE_VENDOR_SPECIFIC);

    tlv = (i1905_vendor_specific_tlv_t *)cmdu->list_of_TLVs[2];

    fail_unless(tlv->m && tlv->m_nr == 4003);
    fail_unless(!memcmp(tlv->vendorOUI, (uint8_t[]){0x88, 0x41, 0xFC}, 3));

    SEND_COMPARE
    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_500_TLV                                    #
########################################################################*/
START_TEST(test_500_tlv)
{
    VARS
    INIT
    READ_PARSE("cmdu_500_tlv.pcap")

    /* Check result */
    fail_unless(g_rx_cmdus_nr == 1);

    i1905_cmdu_t *cmdu = g_rx_cmdus[0];
    fail_unless(cmdu->message_id == 0x100);
    check_tlv_sequence(cmdu, 2, 500);

    SEND_COMPARE
    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_1514_BYTES_INCL_EOM_1_TLV                  #
########################################################################*/
/* Max size cmdu with eom in same packet (tlv payload = 1486 bytes) */
START_TEST(test_1514_bytes_incl_eom_1_tlv)
{
    VARS
    INIT
    READ_PARSE("cmdu_1514_bytes_incl_eom_1_tlv.pcap")
    fail_unless(packets[0]->len == 1514);

    /* Check result */
    fail_unless(g_rx_cmdus_nr == 1);

    i1905_cmdu_t *cmdu = g_rx_cmdus[0];
    uint8_t      *tlv;
    size_t       idx;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        i1905_vendor_specific_tlv_t *t = (i1905_vendor_specific_tlv_t *)tlv;

        fail_unless(t->tlv_type == TLV_TYPE_VENDOR_SPECIFIC);
        fail_unless(t->m_nr     == 1486 - 3 /* oui */);
    }
    fail_unless(idx == 1);

    SEND_COMPARE
    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_1514_BYTES_EXCL_EOM_1_TLV                  #
########################################################################*/
/* Max size cmdu with eom in next packet (tlv payload = 1489 bytes) */
START_TEST(test_1514_bytes_excl_eom_1_tlv)
{
    VARS
    INIT
    READ_PARSE("cmdu_1514_bytes_excl_eom_1_tlv.pcap")
    fail_unless(packets[0]->len == 1514);

    /* Check result */
    fail_unless(g_rx_cmdus_nr == 1);

    i1905_cmdu_t *cmdu = g_rx_cmdus[0];
    uint8_t      *tlv;
    size_t       idx;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        i1905_vendor_specific_tlv_t *t = (i1905_vendor_specific_tlv_t *)tlv;

        fail_unless(t->tlv_type == TLV_TYPE_VENDOR_SPECIFIC);
        fail_unless(t->m_nr     == 1489 - 3 /* oui */);
    }
    fail_unless(idx == 1);

    /* TODO: cmdu forge cannot handle this */
    // SEND_COMPARE
    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_1514_BYTES_INCL_EOM_2_TLV                  #
########################################################################*/
/* Max size cmdu with eom in same packet (tlv payload = 1486 bytes) */
START_TEST(test_1514_bytes_incl_eom_2_tlv)
{
    VARS
    INIT
    READ_PARSE("cmdu_1514_bytes_incl_eom_2_tlv.pcap")
    fail_unless(packets[0]->len == 1514);

    /* Check result */
    fail_unless(g_rx_cmdus_nr == 1);

    i1905_cmdu_t *cmdu = g_rx_cmdus[0];
    uint8_t      *tlv;
    size_t       idx;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        i1905_vendor_specific_tlv_t *t = (i1905_vendor_specific_tlv_t *)tlv;

        fail_unless(t->tlv_type == TLV_TYPE_VENDOR_SPECIFIC);
        fail_unless(t->m_nr     == (idx == 0 ? 1280 : 203) - 3 /* oui */);
    }
    fail_unless(idx == 2);

    SEND_COMPARE
    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_1514_BYTES_EXCL_EOM_2_TLV                  #
########################################################################*/
/* Max size cmdu with eom in next packet (tlv payload = 1489 bytes) */
START_TEST(test_1514_bytes_excl_eom_2_tlv)
{
    VARS
    INIT
    READ_PARSE("cmdu_1514_bytes_excl_eom_2_tlv.pcap")
    fail_unless(packets[0]->len == 1514);

    /* Check result */
    fail_unless(g_rx_cmdus_nr == 1);

    i1905_cmdu_t *cmdu = g_rx_cmdus[0];
    uint8_t      *tlv;
    size_t       idx;

    i1905_foreach_tlv_in_cmdu(tlv, cmdu, idx) {
        i1905_vendor_specific_tlv_t *t = (i1905_vendor_specific_tlv_t *)tlv;

        fail_unless(t->tlv_type == TLV_TYPE_VENDOR_SPECIFIC);
        fail_unless(t->m_nr     == (idx == 0 ? 1280 : 206) - 3 /* oui */);
    }
    fail_unless(idx == 2);

    /* TODO: cmdu forge fragments differently */
    // SEND_COMPARE
    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_DUPLICATE                                  #
########################################################################*/
/* Check if duplicate packets (MID) are discarded.
   Currently a new packet is compared with the 16 last ones
*/
#define MAX_DUP_CMDU 16
START_TEST(test_duplicate)
{
    VARS
    INIT
    READ("cmdu_topology_response.pcap")

    /* Double loop:
       - process packets with different MID
       - process packets with same MID (should be dropped)
       - If i == 17, then the duplicate detection will fail
    */
    size_t i, j, exp_cmdus_nr = 0;
    i1905_cmdu_t *cmdu;
    for (i = 0; i <= (MAX_DUP_CMDU + 1); i++) {
        uint16_t mid = (i + 1) * 100;

        /* Process i packets with different MID */
        for (j = 0; j < i; j++) {
            set_mid(packets, packets_nr, mid + j);
            process_packets(packets, packets_nr);
            fail_unless(g_rx_cmdus_nr == ++exp_cmdus_nr);
            cmdu = g_rx_cmdus[exp_cmdus_nr - 1];
            fail_unless(cmdu->message_id == mid + j);
        }

        /* Process same packets again */
        for (j = 0; j < i; j++) {
            set_mid(packets, packets_nr, mid + j);
            process_packets(packets, packets_nr);
            if (i <= MAX_DUP_CMDU) {
                /* Detection succeeded */
                fail_unless(g_rx_cmdus_nr == exp_cmdus_nr);
            } else {
                /* Detection failed */
                fail_unless(g_rx_cmdus_nr == ++exp_cmdus_nr);
                cmdu = g_rx_cmdus[exp_cmdus_nr - 1];
                fail_unless(cmdu->message_id == mid + j);
            }
        }
    }

    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_MULTICAST                                  #
########################################################################*/
START_TEST(test_multicast)
{
    VARS
    INIT
    READ_PARSE("cmdu_topology_discovery.pcap")

    fail_unless(!maccmp(packets[0]->data, g_mcast_mac_1905));

    /* Check result */
    fail_unless(g_rx_cmdus_nr == 1);

    i1905_cmdu_t *cmdu = g_rx_cmdus[0];
    fail_unless(cmdu->message_type    == CMDU_TYPE_TOPOLOGY_DISCOVERY);
    fail_unless(cmdu->relay_indicator == 0);

    SEND_COMPARE
    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_MULTICAST_RELAYED                          #
########################################################################*/
START_TEST(test_multicast_relayed)
{
    VARS
    INIT
    READ_PARSE("cmdu_ap_autoconfiguration_search.pcap")

    fail_unless(!maccmp(packets[0]->data, g_mcast_mac_1905));

    /* Check result */
    fail_unless(g_rx_cmdus_nr == 1);

    i1905_cmdu_t *cmdu = g_rx_cmdus[0];
    fail_unless(cmdu->message_type    == CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH);
    fail_unless(cmdu->relay_indicator == 1);

    /* Should have been forwarded on eth1, eth2, eth3 and wl0 but not on eth0 and lo */
    fail_unless(g_tx_packets_nr == 4);
    fail_unless(!strcmp(g_tx_packets[0]->if_name, "eth1"));
    fail_unless(!strcmp(g_tx_packets[1]->if_name, "eth2"));
    fail_unless(!strcmp(g_tx_packets[2]->if_name, "eth3"));
    fail_unless(!strcmp(g_tx_packets[3]->if_name, "wl0"));

    /* Send and compare first packet only */
    send_cmdus();
    compare_cmdu_packets(packets, packets_nr, g_tx_packets, 1);

    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_VISIT                                      #
########################################################################*/
START_TEST(test_visit)
{
    i1905_cmdu_t                cmdu            = {0};
    i1905_al_mac_address_tlv_t  al_mac_addr_tlv = {.tlv_type = TLV_TYPE_AL_MAC_ADDRESS};
    uint8_t                    *tlvs[2]         = {(uint8_t*)&al_mac_addr_tlv, NULL};

    cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type    = CMDU_TYPE_TOPOLOGY_NOTIFICATION;
    cmdu.message_id      = 0x123;
    cmdu.relay_indicator = RELAY_INDICATOR_OFF;
    cmdu.list_of_TLVs    = tlvs;
    strcpy(cmdu.interface_name, "eth0");

    visit_1905_CMDU_structure(&cmdu, print_callback, PLATFORM_PRINTF, "prefix");
}
END_TEST

/*#######################################################################
#                       TEST_COMPARE                                    #
########################################################################*/
START_TEST(test_compare)
{
    i1905_cmdu_t                cmdu             = {0};
    i1905_cmdu_t                cmdu2            = {0};
    i1905_cmdu_t                cmdu3            = {0};
    i1905_al_mac_address_tlv_t  al_mac_addr_tlv  = {.tlv_type = TLV_TYPE_AL_MAC_ADDRESS};
    i1905_al_mac_address_tlv_t  al_mac_addr_tlv2 = {.tlv_type = TLV_TYPE_AL_MAC_ADDRESS, .al_mac_address = {0x01,}};
    uint8_t                    *tlvs[2]          = {(uint8_t*)&al_mac_addr_tlv, NULL};
    uint8_t                    *tlvs2[2]         = {(uint8_t*)&al_mac_addr_tlv2, NULL};

    cmdu.message_version = CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type    = CMDU_TYPE_TOPOLOGY_NOTIFICATION;
    cmdu.message_id      = 0x123;
    cmdu.relay_indicator = RELAY_INDICATOR_OFF;
    cmdu.list_of_TLVs    = tlvs;
    strcpy(cmdu.interface_name, "eth0");

    /* cmdu2 has different TLV */
    cmdu2              = cmdu;
    cmdu2.list_of_TLVs = tlvs2;

    /* cmdu3 has different header */
    cmdu3            = cmdu;
    cmdu3.message_id = 0x124;

    fail_unless(!compare_1905_CMDU_structures(&cmdu, &cmdu));
    fail_unless(compare_1905_CMDU_structures(&cmdu, &cmdu2));
    fail_unless(compare_1905_CMDU_structures(&cmdu, &cmdu3));
    fail_unless(compare_1905_CMDU_structures(&cmdu, NULL));
}
END_TEST


const char *test_suite_name = "cmdus";
test_case_t test_cases[] = {
    TEST("unfragmented",               test_unfragmented   ),
    TEST("fragmented_ordered",         test_fragmented_ordered  ),
    TEST("fragmented_reversed",        test_fragmented_reversed  ),
    TEST("fragmented_scrambled",       test_fragmented_scrambled  ),
    TEST("fragmented_mixed",           test_fragmented_mixed  ),
    TEST("fragmented_eom_in_all_frag", test_fragmented_eom_in_all_frag  ),
    TEST("fragmented_lost",            test_fragmented_lost  ),
    TEST("fragmented_duplicate",       test_fragmented_duplicate  ),
    TEST("multiple_fragment_tlv",      test_multiple_fragment_tlv  ),
    TEST("500_tlv",                    test_500_tlv  ),
    TEST("1514_bytes_incl_eom_1_tlv",  test_1514_bytes_incl_eom_1_tlv  ),
    TEST("1514_bytes_excl_eom_1_tlv",  test_1514_bytes_excl_eom_1_tlv  ),
    TEST("1514_bytes_incl_eom_2_tlv",  test_1514_bytes_incl_eom_2_tlv  ),
    TEST("1514_bytes_excl_eom_2_tlv",  test_1514_bytes_excl_eom_2_tlv  ),
    TEST("duplicate",                  test_duplicate  ),
    TEST("multicast",                  test_multicast  ),
    TEST("multicast_relayed",          test_multicast_relayed  ),
    TEST("visit",                      test_visit  ),
    TEST("compare",                    test_compare  ),
    TEST_CASES_END
};
