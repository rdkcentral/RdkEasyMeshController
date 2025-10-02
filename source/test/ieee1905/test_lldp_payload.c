/*
 * Copyright (c) 2021-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include "test.h"

#include "lldp_payload.h"
#include "lldp_tlvs.h"

#include "utils.h"    /* print_callback */
#include "platform.h" /* PLATFORM_PRINTF */

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
/* Note: BIT0 of first byte is MSB of TLV length -> tlv_type is shifted one bit */
static uint8_t g_lldp_payload[24] = {/* chassid_id   */ 0x02, 0x07, 0x04, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05,
                                     /* port_id      */ 0x04, 0x07, 0x03, 0x12, 0x11, 0x12, 0x13, 0x14, 0x15,
                                     /* time_to_live */ 0x06, 0x02, 0x00, 0xb4,
                                     /* end_of_lldp  */ 0x00, 0x00
                                    };

/*#######################################################################
#                       TEST_PAYLOAD                                    #
########################################################################*/
static void check_tlv(uint8_t *p_tlv)
{
    switch(*p_tlv) {
        case TLV_TYPE_CHASSIS_ID: {
            lldp_chassis_id_tlv_t *tlv = (lldp_chassis_id_tlv_t *)p_tlv;

            fail_unless(tlv->chassis_id_subtype == CHASSIS_ID_TLV_SUBTYPE_MAC_ADDRESS);
            fail_unless(!memcmp(tlv->chassis_id, (mac_addr){0x02, 0x01, 0x02, 0x03, 0x04, 0x05}, sizeof(mac_addr)));

            break;
        }
        case TLV_TYPE_PORT_ID: {
            lldp_port_id_tlv_t *tlv = (lldp_port_id_tlv_t *)p_tlv;

            fail_unless(tlv->port_id_subtype == PORT_ID_TLV_SUBTYPE_MAC_ADDRESS);
            fail_unless(!memcmp(tlv->port_id, (mac_addr){0x12, 0x11, 0x12, 0x13, 0x14, 0x15}, sizeof(mac_addr)));

            break;
        }
        case TLV_TYPE_TIME_TO_LIVE: {
            lldp_time_to_live_tlv_t *tlv = (lldp_time_to_live_tlv_t *)p_tlv;

            fail_unless(tlv->ttl == 180);

            break;
        }
        default: {
            fail_unless(false, "unexpected tlv");

            break;
        }
    }
}

START_TEST(test_payload)
{
    i1905_lldp_payload_t *p_payload;
    uint8_t              *f_payload = NULL;
    uint16_t              f_payload_len;
    int                   c;

    /* Parse */
    fail_unless(!!(p_payload = parse_lldp_PAYLOAD_from_packet(g_lldp_payload)));

    /* Check and count tlv */
    for (c = 0; p_payload->list_of_TLVs[c]; c++) {
        check_tlv(p_payload->list_of_TLVs[c]);
    }
    fail_unless(c == 3);

    /* Visit and compare */
    visit_lldp_PAYLOAD_structure(p_payload, print_callback, PLATFORM_PRINTF, "prefix");
    fail_unless(compare_lldp_PAYLOAD_structures(p_payload, p_payload) == 0);

    /* Forge */
    fail_unless(!!(f_payload = forge_lldp_PAYLOAD_from_structure(p_payload, &f_payload_len)));

    /* Cleanup */
    free_lldp_PAYLOAD_structure(p_payload);
    free(f_payload);
}
END_TEST


const char *test_suite_name = "lldp_payload";
test_case_t test_cases[] = {
    TEST("payload",  test_payload  ),
    TEST_CASES_END
};
