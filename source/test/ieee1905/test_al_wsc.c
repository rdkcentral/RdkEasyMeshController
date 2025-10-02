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

#include "al_wsc.h"
#include "al_datamodel.h"
#include "1905_tlvs.h"
#include "map_emex_tlvs.h"
#include "map_config.h"
#include "platform_os.h"

#include "stub/stub_platform_os.h"

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static mac_addr g_controller_al_mac = {0x02, 0x01, 0x02, 0x03, 0x04, 0x05};
static mac_addr g_agent_al_mac      = {0x02, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};

static map_profile_cfg_t g_profile = {
    .type                       =  MAP_PROFILE_TYPE_GUEST,
    .label                      = "test_label",
    .bss_ssid                   = "test_ssid",
    .wpa_key                    = "test_wpa_key",
    .supported_auth_modes       = IEEE80211_AUTH_MODE_WPA2PSK,
    .supported_encryption_types = IEEE80211_ENCRYPTION_MODE_AES,
    .bss_state                  = MAP_FRONTHAUL_BSS,
    .hide                       = true
};

/* Set in configure_ap_cb */
static char     g_ssid[MAX_SSID_LEN];
static char     g_network_key[MAX_WIFI_PASSWORD_LEN];
static uint16_t g_auth_mode;
static uint16_t g_encryption_mode;
static uint8_t  g_map_ext;

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
static void configure_ap_cb(char *if_name, uint8_t *ssid, uint8_t *bssid,
                            uint16_t auth_mode, uint16_t encryption_mode, uint8_t *network_key,
                            uint8_t map_ext)
{
    snprintf(g_ssid,        sizeof(g_ssid),        "%s", ssid);
    snprintf(g_network_key, sizeof(g_network_key), "%s", network_key);
    g_auth_mode       = auth_mode;
    g_encryption_mode = encryption_mode;
    g_map_ext         = map_ext;
}

static uint8_t *get_attr(uint8_t *m, uint16_t size, uint16_t attr_type, uint16_t *attr_len)
{
    uint8_t *p = m;

    while (p - m < size) {
        uint16_t t;

        _E2B(&p, &t);
        _E2B(&p, attr_len);

        if (t == attr_type) {
            return p;
        }
        p += *attr_len;
    }

    return NULL;
}

/* Attributes that are both in M1 and M2 */
static void check_m1_m2(uint8_t *m, uint16_t size)
{
    uint8_t  *a;
    uint16_t  len;

    fail_unless(!!(a = get_attr(m, size, WSC_ATTR_MANUFACTURER, &len)));
    fail_unless(len == strlen(TEST_MANUFACTURER));
    fail_unless(!memcmp(a, (char*)TEST_MANUFACTURER, strlen(TEST_MANUFACTURER)));

    fail_unless(!!(a = get_attr(m, size, WSC_ATTR_MODEL_NAME, &len)));
    fail_unless(len == strlen(TEST_MODEL_NAME));
    fail_unless(!memcmp(a, (char*)TEST_MODEL_NAME, strlen(TEST_MODEL_NAME)));

    fail_unless(!!(a = get_attr(m, size, WSC_ATTR_MODEL_NUMBER, &len)));
    fail_unless(len == strlen(TEST_MODEL_NUMBER));
    fail_unless(!memcmp(a, (char*)TEST_MODEL_NUMBER, strlen(TEST_MODEL_NUMBER)));

    fail_unless(!!(a = get_attr(m, size, WSC_ATTR_SERIAL_NUMBER, &len)));
    fail_unless(len == strlen(TEST_SERIAL_NUMBER));
    fail_unless(!memcmp(a, (char*)TEST_SERIAL_NUMBER, strlen(TEST_SERIAL_NUMBER)));

    /* TODO: check all attributes */
}

static void check_m1(uint8_t *m, uint16_t size)
{
    uint8_t  *a;
    uint16_t  len;

    check_m1_m2(m, size);

    fail_unless(!!(a = get_attr(m, size, WSC_ATTR_MAC_ADDR, &len)));
    fail_unless(len == sizeof(mac_addr));
    fail_unless(!maccmp(a, DMalMacGet()));
}

static void check_m2(uint8_t *m, uint16_t size)
{
    check_m1_m2(m, size);
}

/*#######################################################################
#                       TEST_WSC                                        #
########################################################################*/
START_TEST(test_wsc)
{
    uint8_t         *m1, *m2;
    uint16_t         m1_size, m2_size;
    i1905_wsc_key_t *key;

    /* Init */
    DMinit();
    PLATFORM_OS_INIT(NULL, NULL, NULL);
    PLATFORM_REGISTER_UNIT_TEST_CONFIGURE_AP_CB(configure_ap_cb);


    /* Build M1 (on agent) */
    DMalMacSet(g_agent_al_mac);
    fail_unless(wscBuildM1("eth0", &m1, &m1_size, (void**)&key) == 1);
    check_m1(m1, m1_size);


    /* Build M2 (on controller) */
    DMalMacSet(g_controller_al_mac);
    fail_unless(wscBuildM2(m1, m1_size, &m2, &m2_size, &g_profile, WSC_WFA_MAP_ATTR_FLAG_BACKHAUL_BSS, "eth1") == 1);
    check_m2(m2, m2_size);


    /* Process M2 (on agent) */
    DMalMacSet(g_agent_al_mac);
    fail_unless(wscProcessM2(key, m1, m1_size, m2, m2_size) == 1);

    /* Validate received config */
    fail_unless(!strcmp(g_ssid, g_profile.bss_ssid));
    fail_unless(!strcmp(g_network_key, g_profile.wpa_key));
    fail_unless(g_auth_mode == g_profile.supported_auth_modes);
    fail_unless(g_encryption_mode == g_profile.supported_encryption_types);
    fail_unless(g_map_ext == WSC_WFA_MAP_ATTR_FLAG_BACKHAUL_BSS);


    /* Cleanup */
    free(m1);
    free(key->key);
    free(key);
    wscFreeM2(m2, m2_size);
    DMfini();
    PLATFORM_OS_FINI();
}
END_TEST


const char *test_suite_name = "al_wsc";
test_case_t test_cases[] = {
    TEST("wsc",                         test_wsc  ),
    TEST_CASES_END
};
