/*
 * Copyright (c) 2020-2024 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#include "platform_os.h"
#include "stub_platform_os.h"

#include "al_datamodel.h"

static mac_addr g_lo_mac   = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static mac_addr g_eth0_mac = {0x00, 0x11, 0x11, 0x11, 0x11, 0x11};
static mac_addr g_eth1_mac = {0x00, 0x22, 0x22, 0x22, 0x22, 0x22};
static mac_addr g_eth2_mac = {0x00, 0x33, 0x33, 0x33, 0x33, 0x33};
static mac_addr g_eth3_mac = {0x00, 0x44, 0x44, 0x44, 0x44, 0x44};
static mac_addr g_wl0_mac  = {0x00, 0x55, 0x55, 0x55, 0x55, 0x55};

i1905_packet_cb_t g_stub_platform_os_packet_cb;

uint8_t PLATFORM_OS_INIT(i1905_interface_cb_t interface_cb, i1905_packet_cb_t packet_cb, i1905_key_info_cb_t key_info_cb)
{
    g_stub_platform_os_packet_cb = packet_cb;

    /* Add some interfaces */
    DMinsertInterface("lo",   g_lo_mac);
    DMinsertInterface("eth0", g_eth0_mac);
    DMinsertInterface("eth1", g_eth1_mac);
    DMinsertInterface("eth2", g_eth2_mac);
    DMinsertInterface("eth3", g_eth3_mac);
    DMinsertInterface("wl0",  g_wl0_mac);

    return 1;
}

void PLATFORM_OS_FINI(void)
{
    g_stub_platform_os_packet_cb = NULL;
}

void PLATFORM_OS_DUMP_INTERFACES(map_printf_cb_t print_cb)
{
}

char **PLATFORM_OS_GET_LIST_OF_1905_INTERFACES(uint8_t *nr)
{
    static char *interfaces[] = {"lo", "eth0", "eth1", "eth2", "eth3", "wl0"};
    *nr = 6;

    return interfaces;
}

void PLATFORM_OS_FREE_LIST_OF_1905_INTERFACES(char **interfaces, uint8_t nr)
{
}

void PLATFORM_OS_GET_1905_INTERFACE_INFO(char *if_name, i1905_interface_info_t *info)
{
    memset(info, 0, sizeof(i1905_interface_info_t));

    info->interface_type = INTERFACE_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET;
    info->power_state = INTERFACE_POWER_STATE_ON;

    if (!strcmp(if_name, "lo")) {
        maccpy(info->mac_address, g_lo_mac);
    } else if (!strcmp(if_name, "eth0")) {
        maccpy(info->mac_address, g_eth0_mac);
    } else if (!strcmp(if_name, "eth1")) {
        maccpy(info->mac_address, g_eth1_mac);
    } else if (!strcmp(if_name, "eth2")) {
        maccpy(info->mac_address, g_eth2_mac);
    } else if (!strcmp(if_name, "eth3")) {
        maccpy(info->mac_address, g_eth3_mac);
    } else if (!strcmp(if_name, "wl0")) {
        maccpy(info->mac_address, g_wl0_mac);
        info->interface_type = INTERFACE_TYPE_IEEE_802_11AC_5_GHZ;
    }

    strcpy(info->manufacturer_name, TEST_MANUFACTURER);
    strcpy(info->model_name,        TEST_MODEL_NAME);
    strcpy(info->model_number,      TEST_MODEL_NUMBER);
    strcpy(info->serial_number,     TEST_SERIAL_NUMBER);

    info->is_secured = 1;
}

bool PLATFORM_OS_IS_INTERFACE_UP(char *if_name)
{
    return true;
}

int PLATFORM_OS_GET_IFINDEX(char *if_name)
{
    return 123;
}

void PLATFORM_OS_PACKET_SENT(char *if_name, uint16_t ether_type)
{
}

int PLATFORM_OS_GET_RAW_SEND_FD(void)
{
    return 123;
}

bool PLATFORM_OS_LOG_LEVEL_TRACE(void)
{
    return true;
}

void PLATFORM_OS_SET_LEADER_SELECTED(bool leader_selected)
{
}

/**
 *  Note: Caller is responsible of freeing 'key_info->ptk' for this stub function !!!
 *        Below values are taken from a real example, please do not edit unless you have to.
 */
int PLATFORM_OS_GET_KEY_INFO(uint8_t *al_mac, map_1905_sec_key_info_t *key_info)
{
    uint8_t stub_mac[]        = {0xf6, 0x17, 0xb8, 0xae, 0x89, 0xa3};
    uint8_t stub_tx_counter[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t stub_ptk[]        = {
        0x5f, 0xd7, 0x89, 0xa0, 0x42, 0x82, 0xbf, 0xaf, 0xbe, 0x3e, 0x0d, 0x0f, 0x83, 0x0c, 0xf5, 0x33,
        0xd1, 0x03, 0x1b, 0x8d, 0x86, 0xe5, 0x49, 0x95, 0x3e, 0x62, 0x1e, 0x02, 0x91, 0x18, 0x0b, 0x83
    };
    size_t stub_ptk_len = sizeof(stub_ptk);
    if (memcmp(al_mac, stub_mac, ETHER_ADDR_LEN) == 0) {
        key_info->ptk_len = stub_ptk_len;
        memcpy(key_info->ptk, stub_ptk, stub_ptk_len);
        memcpy(key_info->encr_tx_counter, stub_tx_counter, ENCRYPTION_TX_COUNTER_LEN);

        return 0;
    }

    return -1;
}
