/*
 * Copyright (c) 2017-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef UNITTEST_TEST_H_
#define UNITTEST_TEST_H_

/*#######################################################################
#                       TEST FRAMEWORK                                  #
########################################################################*/
#include <check.h>

/* Prototype of _tcase_add_test changed from check 0.13 */
#if (CHECK_MAJOR_VERSION > 0) || (CHECK_MINOR_VERSION >= 13)
#define CHECK_HAS_TTEST
#endif
#ifdef CHECK_HAS_TTEST
#define TEST(_name, _test) {.name = _name, .test = &_test}
#else
#define TEST(_name, _test) {.name = _name, .function = _test}
#endif
#define TEST_CASES_END     {.name = NULL}

typedef struct {
    const char    *name;
#ifdef CHECK_HAS_TTEST
    const TTest **test;
#else
    TFun          function;
#endif
    double        timeout; // 0 = use default Check timeout of 4s; otherwise use provided value
} test_case_t;

extern const char  *test_suite_name;
extern test_case_t  test_cases[];

/*#######################################################################
#                       USEFUL DEFINES AND TYPEDEFS                     #
########################################################################*/
#include <net/ethernet.h>
#include <net/if.h>

#define STRUCT_PACKED  __attribute__ ((packed))
#define ETHERTYPE_1905 0x893a
#define MAX_PACKET_LEN 1514

typedef struct ether_header eth_hdr_t;

typedef struct {
    uint8_t  message_version;
    uint8_t  resved_field;
    uint16_t message_type;
    uint16_t message_id;
    uint8_t  fragment_id;
    uint8_t  indicators;
} STRUCT_PACKED cmdu_hdr_t;

typedef struct {
    uint8_t  type;
    uint16_t len;
} STRUCT_PACKED tlv_hdr_t;

typedef struct {
    char     if_name[IFNAMSIZ];
    uint16_t len;
    uint8_t  data[MAX_PACKET_LEN];
} packet_t;

/* Validate json message against schema */
void validate_schema(const char *msg, const char *schema);

/* Get first packet from pcap file */
packet_t *pcap_read_first_packet(const char *file);

packet_t **pcap_read_all_packets(const char *file, size_t *packets_nr);

void free_packets(packet_t **p, size_t nr);

#endif /* UNITTEST_TEST_H_ */
