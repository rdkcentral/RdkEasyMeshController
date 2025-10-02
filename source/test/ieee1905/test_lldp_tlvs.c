/*
 * Copyright (c) 2021-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include "test.h"

#include "lldp_tlvs.h"

#include "utils.h"    /* print_callback */
#include "platform.h" /* PLATFORM_PRINTF */

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define VARS                                 \
    uint16_t  f_tlv_len;                     \
    uint8_t  *p_tlv = NULL; /* parsed tlv */ \
    uint8_t  *f_tlv = NULL; /* forged tlv */

/* For code coverage (dump and compare with yourself)... */
#define VISIT_COMPARE(p_tlv) \
    visit_lldp_TLV_structure(p_tlv, print_callback, PLATFORM_PRINTF, "prefix"); \
    fail_unless(compare_lldp_TLV_structures(p_tlv, p_tlv) == 0);                \

#define PARSE(g_f_tlv, tlv_type)                                              \
    fail_unless(!!(p_tlv = parse_lldp_TLV_from_packet(g_f_tlv)));             \
    fail_unless(*p_tlv == tlv_type);                                          \
    fail_unless(!strcmp(convert_lldp_TLV_type_to_string(*p_tlv), #tlv_type)); \
    VISIT_COMPARE(p_tlv);

#define FORGE(g_f_tlv)                                                         \
    fail_unless(!!(f_tlv = forge_lldp_TLV_from_structure(p_tlv, &f_tlv_len))); \
    fail_unless(f_tlv_len == sizeof(g_f_tlv));                                 \
    fail_unless(!memcmp(f_tlv, g_f_tlv, f_tlv_len));

#define CLEANUP                     \
    free_lldp_TLV_structure(p_tlv); \
    free(f_tlv);

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
/* Note: BIT0 of first byte is MSB of TLV length -> tlv_type is shifted one bit */
static uint8_t g_end_of_lldp_tlv[2]  = {0x00, 0x00};
static uint8_t g_chassis_id_tlv[9]   = {0x02, 0x07, 0x04, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05};
static uint8_t g_port_id_tlv[9]      = {0x04, 0x07, 0x03, 0x12, 0x11, 0x12, 0x13, 0x14, 0x15};
static uint8_t g_time_to_live_tlv[4] = {0x06, 0x02, 0x00, 0xb4};

/*#######################################################################
#                       TEST_00_END_OF_LLDP                             #
########################################################################*/
START_TEST(test_00_end_of_lldp)
{
    VARS
    PARSE(g_end_of_lldp_tlv, TLV_TYPE_END_OF_LLDPPDU)
    FORGE(g_end_of_lldp_tlv)
    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_01_CHASSIS_ID                              #
########################################################################*/
START_TEST(test_01_chassis_id)
{
    VARS
    PARSE(g_chassis_id_tlv, TLV_TYPE_CHASSIS_ID)

    lldp_chassis_id_tlv_t *tlv = (lldp_chassis_id_tlv_t *)p_tlv;
    fail_unless(tlv->chassis_id_subtype == CHASSIS_ID_TLV_SUBTYPE_MAC_ADDRESS);
    fail_unless(!memcmp(tlv->chassis_id, (mac_addr){0x02, 0x01, 0x02, 0x03, 0x04, 0x05}, sizeof(mac_addr)));

    FORGE(g_chassis_id_tlv)
    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_02_PORT_ID                                 #
########################################################################*/
START_TEST(test_02_port_id)
{
    VARS
    PARSE(g_port_id_tlv, TLV_TYPE_PORT_ID)

    lldp_port_id_tlv_t *tlv = (lldp_port_id_tlv_t *)p_tlv;
    fail_unless(tlv->port_id_subtype == PORT_ID_TLV_SUBTYPE_MAC_ADDRESS);
    fail_unless(!memcmp(tlv->port_id, (mac_addr){0x12, 0x11, 0x12, 0x13, 0x14, 0x15}, sizeof(mac_addr)));

    FORGE(g_port_id_tlv)
    CLEANUP
}
END_TEST

/*#######################################################################
#                       TEST_03_TIME_TO_LIVE                            #
########################################################################*/
START_TEST(test_03_time_to_live)
{
    VARS
    PARSE(g_time_to_live_tlv, TLV_TYPE_TIME_TO_LIVE)

    lldp_time_to_live_tlv_t *tlv = (lldp_time_to_live_tlv_t *)p_tlv;
    fail_unless(tlv->ttl == 180);

    FORGE(g_time_to_live_tlv)
    CLEANUP
}
END_TEST


const char *test_suite_name = "lldp_tlvs";
test_case_t test_cases[] = {
    TEST("00_end_of_lldp",  test_00_end_of_lldp  ),
    TEST("01_chassis_id",   test_01_chassis_id  ),
    TEST("02_port_id",      test_02_port_id  ),
    TEST("03_time_to_live", test_03_time_to_live  ),
    TEST_CASES_END
};
