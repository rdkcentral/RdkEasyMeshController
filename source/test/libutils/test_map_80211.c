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

#include "test.h"
#include "map_80211.h"

/*#######################################################################
#                   TEST_PARSE_ASSOC_BODY                               #
########################################################################*/
/* Valid frame bodies - type is autodetected */
static char *g_ssid      = "frv_test_bh";

/* Assoc frame body */
static char *g_assoc     = "11110A00000B6672765F746573745F626801088C129824B048606C2102F918240A24043404640C9504A501301A0100000FAC040100000FAC040100000FAC0280000000000FAC06460532000000003B1D000102030405161718191B1C1D1E737475767778797A7B7C7D7E7F80812D1AEF0117FFFFFFFF000000000000000000000000000000000000007F0900000880000000C001BF0CB1798B0FAAFF0000AAFF0020FF2023030800120000443002C00F438518008C00AAFFAAFF3B1CC7711CC7711CC771DD1E00904C33EF0117FFFFFFFF00000000000000000000000000000000000000DD0500904C0417DD0A00101802000010000000DD070050F202000100DD0A506F9A1B0601800701029704010203049806010203040506";

/* Reassoc frame body (header 6 bytes longer) */
static char *g_reassoc   = "11110A01020304050600000B6672765F746573745F626801088C129824B048606C2102F918240A24043404640C9504A501301A0100000FAC040100000FAC040100000FAC0280000000000FAC06460532000000003B1D000102030405161718191B1C1D1E737475767778797A7B7C7D7E7F80812D1AEF0117FFFFFFFF000000000000000000000000000000000000007F0900000880000000C001BF0CB1798B0FAAFF0000AAFF0020FF2023030800120000443002C00F438518008C00AAFFAAFF3B1CC7711CC7711CC771DD1E00904C33EF0117FFFFFFFF00000000000000000000000000000000000000DD0500904C0417DD0A00101802000010000000DD070050F202000100DD0A506F9A1B0601800701029704010203049806010203040506";

/* IES only */
static char *g_ies       = "000B6672765F746573745F626801088C129824B048606C2102F918240A24043404640C9504A501301A0100000FAC040100000FAC040100000FAC0280000000000FAC06460532000000003B1D000102030405161718191B1C1D1E737475767778797A7B7C7D7E7F80812D1AEF0117FFFFFFFF000000000000000000000000000000000000007F0900000880000000C001BF0CB1798B0FAAFF0000AAFF0020FF2023030800120000443002C00F438518008C00AAFFAAFF3B1CC7711CC7711CC771DD1E00904C33EF0117FFFFFFFF00000000000000000000000000000000000000DD0500904C0417DD0A00101802000010000000DD070050F202000100DD0A506F9A1B0601800701029704010203049806010203040506";

/* Note: an empty EHT CAP IE is added at the end - to be replaced by a captured one */
static char *g_ies_11be  = "000B6672765F746573745F626801088C129824B048606C2102F918240A24043404640C9504A501301A0100000FAC040100000FAC040100000FAC0280000000000FAC06460532000000003B1D000102030405161718191B1C1D1E737475767778797A7B7C7D7E7F80812D1AEF0117FFFFFFFF000000000000000000000000000000000000007F0900000880000000C001BF0CB1798B0FAAFF0000AAFF0020FF2023030800120000443002C00F438518008C00AAFFAAFF3B1CC7711CC7711CC771DD1E00904C33EF0117FFFFFFFF00000000000000000000000000000000000000DD0500904C0417DD0A00101802000010000000DD070050F202000100DD0A506F9A1B0601800701029704010203049806010203040506FF0D6C0B0000000000000000000000";


/* Invalid (removed SSID IE so it is not found + truncated IE at the end) */
static char *g_invalid_1 = "01088C129824B048606C2102F918240A24043404640C9504A501301A0100000FAC040100000FAC040100000FAC0280000000000FAC06460532000000003B1D000102030405161718191B1C1D1E737475767778797A7B7C7D7E7F80812D1AEF0117FFFFFFFF000000000000000000000000000000000000007F0900000880000000C001BF0CB1798B0FAAFF0000AAFF0020FF2023030800120000443002C00F438518008C00AAFFAAFF3B1CC7711CC7711CC771DD1E00904C33EF0117FFFFFFFF00000000000000000000000000000000000000DD0500904C0417DD0A00101802000010000000DD070050F202000100DD0A506F9A1B06018007010297040102030498060102030405069904010203";

static char *g_invalid_2 = "01088C129824B048606C2102F918240A24043404640C9504A501301A0100000FAC040100000FAC040100000FAC0280000000000FAC06460532000000003B1D000102030405161718191B1C1D1E737475767778797A7B7C7D7E7F80812D1AEF0117FFFFFFFF000000000000000000000000000000000000007F0900000880000000C001BF0CB1798B0FAAFF0000AAFF0020FF2023030800120000443002C00F438518008C00AAFFAAFF3B1CC7711CC7711CC771DD1E00904C33EF0117FFFFFFFF00000000000000000000000000000000000000DD0500904C0417DD0A00101802000010000000DD070050F202000100DD0A506F9A1B060180070102970401020304980601020304050699040102";

static char *g_invalid_3 = "01088C129824B048606C2102F918240A24043404640C9504A501301A0100000FAC040100000FAC040100000FAC0280000000000FAC06460532000000003B1D000102030405161718191B1C1D1E737475767778797A7B7C7D7E7F80812D1AEF0117FFFFFFFF000000000000000000000000000000000000007F0900000880000000C001BF0CB1798B0FAAFF0000AAFF0020FF2023030800120000443002C00F438518008C00AAFFAAFF3B1CC7711CC7711CC771DD1E00904C33EF0117FFFFFFFF00000000000000000000000000000000000000DD0500904C0417DD0A00101802000010000000DD070050F202000100DD0A506F9A1B0601800701029704010203049806010203040506990401";

static char *g_invalid_4 = "01088C129824B048606C2102F918240A24043404640C9504A501301A0100000FAC040100000FAC040100000FAC0280000000000FAC06460532000000003B1D000102030405161718191B1C1D1E737475767778797A7B7C7D7E7F80812D1AEF0117FFFFFFFF000000000000000000000000000000000000007F0900000880000000C001BF0CB1798B0FAAFF0000AAFF0020FF2023030800120000443002C00F438518008C00AAFFAAFF3B1CC7711CC7711CC771DD1E00904C33EF0117FFFFFFFF00000000000000000000000000000000000000DD0500904C0417DD0A00101802000010000000DD070050F202000100DD0A506F9A1B06018007010297040102030498060102030405069904";

static char *g_invalid_5 = "01088C129824B048606C2102F918240A24043404640C9504A501301A0100000FAC040100000FAC040100000FAC0280000000000FAC06460532000000003B1D000102030405161718191B1C1D1E737475767778797A7B7C7D7E7F80812D1AEF0117FFFFFFFF000000000000000000000000000000000000007F0900000880000000C001BF0CB1798B0FAAFF0000AAFF0020FF2023030800120000443002C00F438518008C00AAFFAAFF3B1CC7711CC7711CC771DD1E00904C33EF0117FFFFFFFF00000000000000000000000000000000000000DD0500904C0417DD0A00101802000010000000DD070050F202000100DD0A506F9A1B060180070102970401020304980601020304050699";


static int parse_body(map_sta_capability_t *caps, char *body, int freq, char *ssid, mac_addr aff_sta_mac)
{
    uint8_t buf[1024];
    int     len = strlen(body) / 2;

    memset(caps, 0, sizeof(map_sta_capability_t));

    fail_unless(ACU_OK == acu_hex_string_to_buf(body, buf, len));

    return map_80211_parse_assoc_body(caps, buf, len, freq, (uint8_t*)ssid, strlen(ssid), aff_sta_mac);
}

static void check_caps(map_sta_capability_t *caps)
{
    fail_unless(caps->max_tx_spatial_streams == 4);
    fail_unless(caps->max_rx_spatial_streams == 4);
    fail_unless(caps->max_bandwidth          == 80);
    fail_unless(caps->supported_standard     == STD_80211_ANACAX);
    fail_unless(caps->sgi_support            == 0);
    fail_unless(caps->dot11k_support         == 1);
    fail_unless(caps->dot11k_brp_support     == 1);
    fail_unless(caps->dot11k_bra_support     == 1);
    fail_unless(caps->dot11v_btm_support     == 1);
    fail_unless(caps->backhaul_sta           == 1);
    fail_unless(caps->mbo_support            == 0);
    fail_unless(caps->max_phy_rate           == 2402000);
}

static void check_caps_11be(map_sta_capability_t *caps)
{
    fail_unless(caps->max_tx_spatial_streams == 4);
    fail_unless(caps->max_rx_spatial_streams == 4);
    fail_unless(caps->max_bandwidth          == 320);
    fail_unless(caps->supported_standard     == STD_80211_BE);
    fail_unless(caps->sgi_support            == 0);
    fail_unless(caps->dot11k_support         == 1);
    fail_unless(caps->dot11k_brp_support     == 1);
    fail_unless(caps->dot11k_bra_support     == 1);
    fail_unless(caps->dot11v_btm_support     == 1);
    fail_unless(caps->backhaul_sta           == 1);
    fail_unless(caps->mbo_support            == 0);
    fail_unless(caps->max_phy_rate           == 9607800);
}

START_TEST(test_parse_assoc_body)
{
    map_sta_capability_t caps;

    /* Correct parsing */
    fail_unless(!parse_body(&caps, g_assoc, IEEE80211_FREQUENCY_BAND_5_GHZ, g_ssid, NULL));
    check_caps(&caps);

    fail_unless(!parse_body(&caps, g_reassoc, IEEE80211_FREQUENCY_BAND_5_GHZ, g_ssid, NULL));
    check_caps(&caps);

    fail_unless(!parse_body(&caps, g_ies, IEEE80211_FREQUENCY_BAND_5_GHZ, g_ssid, NULL));
    check_caps(&caps);

    fail_unless(!parse_body(&caps, g_ies_11be, IEEE80211_FREQUENCY_BAND_6_GHZ, g_ssid, NULL));
    check_caps_11be(&caps);

    /* SSID not found */
    fail_unless(parse_body(&caps, g_assoc, IEEE80211_FREQUENCY_BAND_5_GHZ, "wrong_ssid", NULL));

    /* Invalid IES */
    fail_unless(parse_body(&caps, g_invalid_1, IEEE80211_FREQUENCY_BAND_5_GHZ, g_ssid, NULL));
    fail_unless(parse_body(&caps, g_invalid_2, IEEE80211_FREQUENCY_BAND_5_GHZ, g_ssid, NULL));
    fail_unless(parse_body(&caps, g_invalid_3, IEEE80211_FREQUENCY_BAND_5_GHZ, g_ssid, NULL));
    fail_unless(parse_body(&caps, g_invalid_4, IEEE80211_FREQUENCY_BAND_5_GHZ, g_ssid, NULL));
    fail_unless(parse_body(&caps, g_invalid_5, IEEE80211_FREQUENCY_BAND_5_GHZ, g_ssid, NULL));
}
END_TEST

/*#######################################################################
#                   TEST_PARSE_MLO_ASSOC_BODY                           #
########################################################################*/
static char *g_mlo_assoc                    = "11010a00000b6672765f746573745f626801088c121824b048606c2102f9162402013a301a0100000fac040100000fac040100000fac08c0000000000fac063b068383848586897f0b80004880010040c0010021ff27230108001000084c3042c06d1b851800cc00aaffaaffaaffaaff7b1cc7711cc7711cc7711cc771ff033bbd06f40120ff156ce200ee6ddb6040e7000e00444444444444444444ffe96b00010900904c4c847ae207007c21000700904c4c941f310501080c1218243048606c2d1aef0117ffffff0000000000000000000000000000000000000000bf0cf6799b0feaff0000eaff0020ff27230108001000084c3042c06d1b851800cc00eaffeaffeaffeaff7b1cc7711cc7711cc7711cc771ff126ce200ec0d1b6040e7000e00333333333333005d22000700904c4d41f53105010402040b162d1aef1117ffff000000000000000000000000000000000000000000ff1d23010800100000223042c00d03851800cc00fafffaff1b1cc7711cc771ff0f6ca200ec01036040e7000e00222222dd09001018020001100000dd070050f202000100";
static char *g_mlo_assoc_frag_ml_ie         = "11010a00000b6672765f746573745f626801088c129824b048606c2102f9182402013a301a0100000fac040100000fac040100000fac08c0000000000fac063b068983848586897f0b00004880010040c0010020ff27230108001000084c3042c06d1b851800cc00aaffaaffaaffaaff7b1cc7711cc7711cc7711cc771ff033bbd06f40120ff156ce200ee6ddb6040e7000e00444444444444444444ffff6b00010900904c4c847ae207009c21000700904c4c941f310501080c1218243048606c2d1aef0117ffffff0000000000000000000000000000000000000000bf0cf6799b0feaff0000eaff0020ff27230108001000084c3042c06d1b851800cc00eaffeaffeaffeaff7b1cc7711cc7711cc7711cc771ff126ce200ec0d1b6040e7000e00333333333333dd1eaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa007d22000700904c4d41f53105010402040b162d1aef1117ffff000000000000000000000000000000000000000000ff1d23010800100000223042c00d03851800cc00fafffaff1b1cc7711cc771ff0f6ca200ec01f22a036040e7000e00222222dd1eaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaadd09001018020001100000dd070050f202000100";
static char *g_mlo_assoc_frag_ml_ie_frag_sp = "11010a00000b6672765f746573745f626801088c129824b048606c2102f9182402013a301a0100000fac040100000fac040100000fac08c0000000000fac063b068983848586897f0b0000488001004040000020ff1a230108001000084c3042c06d1b0518008c00aaffaaffaaffaaffff033bbd06f40120ff156ce200ee6ddb6040e7000e00444444444444444444ffff6b00010900904c4c847ae20700ff21000700904c4c941f3105ddb2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01080c1218243048606c2d1aef0117ffffff0000000000000000000000000000000000000000bf0cf6799b0feaff0000eafff2ff0020ff1a230108001000084c3042fe24c06d1b0518008c00eaffeaffeaffeaffff126ce200ec0d1b6040e7000e0033333333333300ff22000700904c4d41f53105dd8caaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010402040b162d1aef1117ffff000000000000000000000000000000000000000000ff1623010800100000223042c00df236030518008c00fafffaffff0f6ca200ec01036040e7000e00222222dd19bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbdd09001018020001100000dd070050f202000100";

static void check_mlo_caps(map_sta_capability_t *caps, uint8_t band)
{
    if (band == IEEE80211_FREQUENCY_BAND_6_GHZ) {
        fail_unless(caps->eht_support && caps->he_support && !caps->vht_support);
        fail_unless(caps->max_tx_spatial_streams == 4);
    } else if (band == IEEE80211_FREQUENCY_BAND_5_GHZ) {
        fail_unless(caps->eht_support && caps->he_support && caps->vht_support);
        fail_unless(caps->max_tx_spatial_streams == 3);
    } else if (band == IEEE80211_FREQUENCY_BAND_2_4_GHZ) {
        fail_unless(caps->eht_support && caps->he_support && !caps->vht_support);
        fail_unless(caps->max_tx_spatial_streams == 2);
    } else {
        fail_unless(false);
    }

    fail_unless(caps->mld_modes.str);
    fail_unless(!caps->mld_modes.nstr);
    fail_unless(!caps->mld_modes.emlsr);
    fail_unless(!caps->mld_modes.emlmr);
}

START_TEST(test_parse_mlo_assoc_body)
{
    map_sta_capability_t  caps;
    char                 *ssid = "frv_test_bh";
    mac_addr              aff_6G = {0x00, 0x90 , 0x4c, 0x4c, 0x84, 0x7a};
    mac_addr              aff_5G = {0x00, 0x90 , 0x4c, 0x4c, 0x94, 0x1f};
    mac_addr              aff_2G = {0x00, 0x90 , 0x4c, 0x4d, 0x41, 0xf5};

    char                 *assoc[3] = {g_mlo_assoc, g_mlo_assoc_frag_ml_ie, g_mlo_assoc_frag_ml_ie_frag_sp};
    int                   i;

    /* Parse 3 assoc ies */
    for (i = 0; i < 3; i++) {
        fail_unless(!parse_body(&caps, assoc[i], IEEE80211_FREQUENCY_BAND_6_GHZ, ssid, aff_6G));
        check_mlo_caps(&caps, IEEE80211_FREQUENCY_BAND_6_GHZ);

        fail_unless(!parse_body(&caps, assoc[i], IEEE80211_FREQUENCY_BAND_5_GHZ, ssid, aff_5G));
        check_mlo_caps(&caps, IEEE80211_FREQUENCY_BAND_5_GHZ);

        fail_unless(!parse_body(&caps, assoc[i], IEEE80211_FREQUENCY_BAND_2_4_GHZ, ssid, aff_2G));
        check_mlo_caps(&caps, IEEE80211_FREQUENCY_BAND_2_4_GHZ);
    }
}
END_TEST

/*#######################################################################
#                   TEST_GET_MAX_PHY_RATE                               #
########################################################################*/
START_TEST(test_get_max_phy_rate)
{
    map_sta_capability_t caps = { 0 };

    caps.max_bandwidth          = 20;
    caps.max_tx_spatial_streams = 1;
    caps.sgi_support            = 0;

    caps.supported_standard = STD_80211_B;
    fail_unless(map_get_max_phy_rate(&caps) == 11000);

    caps.supported_standard = STD_80211_G;
    fail_unless(map_get_max_phy_rate(&caps) == 54000);

    caps.supported_standard = STD_80211_G;
    fail_unless(map_get_max_phy_rate(&caps) == 54000);

    caps.supported_standard = STD_80211_N;
    fail_unless(map_get_max_phy_rate(&caps) == 65000);

    caps.sgi_support = 1;
    fail_unless(map_get_max_phy_rate(&caps) == 72200);

    caps.max_tx_spatial_streams = 2;
    fail_unless(map_get_max_phy_rate(&caps) == 144000);

    caps.max_bandwidth = 40;
    fail_unless(map_get_max_phy_rate(&caps) == 300000);

    caps.supported_standard = STD_80211_AC;
    fail_unless(map_get_max_phy_rate(&caps) == 400000);

    caps.max_tx_spatial_streams = 3;
    fail_unless(map_get_max_phy_rate(&caps) == 600000);

    caps.max_bandwidth = 80;
    fail_unless(map_get_max_phy_rate(&caps) == 1300000);


    caps.supported_standard = STD_80211_ANACAX;
    caps.max_bandwidth = 20;
    caps.max_tx_spatial_streams = 2;
    fail_unless(map_get_max_phy_rate(&caps) == 286800);

    caps.max_bandwidth = 80;
    fail_unless(map_get_max_phy_rate(&caps) == 1201000);

    caps.max_bandwidth = 160;
    fail_unless(map_get_max_phy_rate(&caps) == 2402000);

    caps.max_tx_spatial_streams = 4;
    fail_unless(map_get_max_phy_rate(&caps) == 4803900);

    /* Invalid */
    caps.max_bandwidth = 200;
    caps.max_tx_spatial_streams = 5;
    fail_unless(map_get_max_phy_rate(&caps) == 4803900);

    caps.supported_standard = STD_80211_N;
    fail_unless(map_get_max_phy_rate(&caps) == 600000);
}
END_TEST

const char *test_suite_name = "map_info";
test_case_t test_cases[] = {
    TEST("parse_assoc_body",     test_parse_assoc_body  ),
    TEST("parse_mlo_assoc_body", test_parse_mlo_assoc_body  ),
    TEST("get_max_phy_rate",     test_get_max_phy_rate  ),
    TEST_CASES_END
};
