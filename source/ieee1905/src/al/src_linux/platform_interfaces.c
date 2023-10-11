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

/*
 *  Broadband Forum IEEE 1905.1/1a stack
 *
 *  Copyright (c) 2017, Broadband Forum
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  Subject to the terms and conditions of this license, each copyright
 *  holder and contributor hereby grants to those receiving rights under
 *  this license a perpetual, worldwide, non-exclusive, no-charge,
 *  royalty-free, irrevocable (except for failure to satisfy the
 *  conditions of this license) patent license to make, have made, use,
 *  offer to sell, sell, import, and otherwise transfer this software,
 *  where such license applies only to those patent claims, already
 *  acquired or hereafter acquired, licensable by such copyright holder or
 *  contributor that are necessarily infringed by:
 *
 *  (a) their Contribution(s) (the licensed copyrights of copyright holders
 *      and non-copyrightable additions of contributors, in source or binary
 *      form) alone; or
 *
 *  (b) combination of their Contribution(s) with the work of authorship to
 *      which such Contribution(s) was added by such copyright holder or
 *      contributor, if, at the time the Contribution is added, such addition
 *      causes such combination to be necessarily infringed. The patent
 *      license shall not apply to any other combinations which include the
 *      Contribution.
 *
 *  Except as expressly stated above, no rights or licenses from any
 *  copyright holder or contributor is granted under this license, whether
 *  expressly, by implication, estoppel or otherwise.
 *
 *  DISCLAIMER
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 *  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 *  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 *  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 *  DAMAGE.
 */

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <unistd.h>

#define LOG_TAG "interface"

#include "platform.h"
#include "platform_interfaces.h"
#include "platform_os.h"

#include "1905_l2.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define INTF_TYPE_ERROR    (0)
#define INTF_TYPE_ETHERNET (1)
#define INTF_TYPE_WIFI     (2)
#define INTF_TYPE_UNKNOWN  (0xFF)

#define MIN_PAYLOAD_LEN    60

#define max(a, b) ((a) > (b)) ? (a) : (b)

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
#ifdef UNIT_TEST
static i1905_unit_test_send_cb_t         g_unit_test_send_cb;
static i1905_unit_test_configure_ap_cb_t g_unit_test_configure_ap_cb;
#endif /* UNIT_TEST */

/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/

/* This function returns '0' if there was a problem,  otherwise it returns an
*  ID identifying the interface type.
*/

/* FRV: This is not used but might be useful later */
static UNUSED uint8_t get_interface_type(char *interface_name)
{
    /* According to www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-net
    *
    *                                     Regular ethernet          Wifi
    *                                     interface                 interface
    *                                     ================          =========
    *
    *  /sys/class/net/<iface>/type        1                         1
    *
    *  /sys/class/net/<iface>/wireless    <Does not exist>          <Exists>
    */

    uint8_t  ret = INTF_TYPE_ERROR;
    FILE    *fp;
    char     sys_path[100];

    snprintf(sys_path, sizeof(sys_path), "/sys/class/net/%s/type", interface_name);

    if (NULL != (fp = fopen(sys_path, "r"))) {
        char aux[30];

        if (NULL != fgets(aux, sizeof(aux), fp)) {
            int interface_type = atoi(aux);

            switch (interface_type) {
                case 1:
                    snprintf(sys_path, sizeof(sys_path), "/sys/class/net/%s/wireless", interface_name);

                    if(-1 != access(sys_path, F_OK)) {
                        /*  Wireless */
                        ret = INTF_TYPE_WIFI;
                    } else {
                        /* Ethernet */
                        ret = INTF_TYPE_ETHERNET;
                    }
                break;
                default:
                    log_i1905_e("Unknown interface type %d", interface_type);
                    ret = INTF_TYPE_UNKNOWN;
                break;
            }
        }

        fclose(fp);
    }

    return ret;
}

/* Returns an uint32_t obtained by reading the first line of file
*  "/sys/class/net/<interface_name>/<parameter_name>"
*/
static int32_t read_interface_parameter(char *interface_name, char *parameter_name)
{
    int32_t  ret = 0;
    FILE    *fp;
    char     sys_path[100];

    snprintf(sys_path, sizeof(sys_path), "/sys/class/net/%s/%s", interface_name, parameter_name);

    if (NULL != (fp = fopen(sys_path, "r"))) {
        char aux[30];

        if (NULL != fgets(aux, sizeof(aux), fp)) {
            ret = atoi(aux);
        }
        fclose(fp);
    }

    return ret;
}

/* Returns an int32_t obtained by reading the output of
*  "iw dev $INTERFACE station get $MAC | grep $PARAMETER_NAME"
*/
static int32_t read_wifi_neighbor_parameter(char *interface_name, uint8_t *neighbor_interface_address, char *parameter_name)
{
    int32_t  ret = 0;
    FILE    *pipe;
    char    *line;
    size_t   len;
    char     command[200];

    if ((NULL == interface_name) || (NULL == neighbor_interface_address) || (NULL == parameter_name)) {
        return 0;
    }

    snprintf(command, sizeof(command), "iw dev %s station get %02x:%02x:%02x:%02x:%02x:%02x | grep %s",
             interface_name,
             neighbor_interface_address[0], neighbor_interface_address[1], neighbor_interface_address[2],
             neighbor_interface_address[3], neighbor_interface_address[4], neighbor_interface_address[5],
             parameter_name);

    /* Execute the IW query command */
    pipe = popen(command, "r");

    if (!pipe) {
        log_i1905_e("popen() returned with errno=%d (%s)", errno, strerror(errno));
        return 0;
    }

    /* Next read the parameter */
    line = NULL;
    if (-1 != getline(&line, &len, pipe)) {
        char *value;

        /* Remove the last "\n" */
        line[strlen(line)-1] = 0x00;

        value = strstr(line, ":");
        if ((NULL != value) && (1 == sscanf(value+1, "%d", &ret))) {
             log_i1905_d("Neighbor %02x:%02x:%02x:%02x:%02x:%02x (%s) %s = %d",
                         neighbor_interface_address[0], neighbor_interface_address[1], neighbor_interface_address[2],
                         neighbor_interface_address[3], neighbor_interface_address[4], neighbor_interface_address[5],
                         interface_name, parameter_name, ret);
        } else {
             log_i1905_d("Parameter not found");
        }
    }

    free(line);
    pclose(pipe);

    return ret;
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
char **PLATFORM_GET_LIST_OF_1905_INTERFACES(uint8_t *nr)
{
#ifdef _FLAVOUR_AIRTIES_
    return PLATFORM_OS_GET_LIST_OF_1905_INTERFACES(nr);
#endif
}

void PLATFORM_FREE_LIST_OF_1905_INTERFACES(char **x, uint8_t nr)
{
#ifdef _FLAVOUR_AIRTIES_
    return PLATFORM_OS_FREE_LIST_OF_1905_INTERFACES(x, nr);
#endif
}

i1905_interface_info_t *PLATFORM_GET_1905_INTERFACE_INFO(char *interface_name)
{
    i1905_interface_info_t *m;

    uint8_t executed;
    uint8_t i;

    log_i1905_t("Retrieving info for interface %s", interface_name);

    m = malloc(sizeof(i1905_interface_info_t));
    if (NULL == m) {
        log_i1905_e("Not enough memory for the 'interface' structure");
        return NULL;
    }

    /* Give "sane" values in case any of the following parameters can not be filled later */
    m->mac_address[0] = 0x00;
    m->mac_address[1] = 0x00;
    m->mac_address[2] = 0x00;
    m->mac_address[3] = 0x00;
    m->mac_address[4] = 0x00;
    m->mac_address[5] = 0x00;

    memcpy(m->manufacturer_name, "Unknown",          strlen("Unknown")+1);
    memcpy(m->model_name,        "Unknown",          strlen("Unknown")+1);
    memcpy(m->model_number,      "00000000",         strlen("00000000")+1);
    memcpy(m->serial_number,     "00000000",         strlen("00000000")+1);
    memcpy(m->device_name,       "Unknown",          strlen("Unknown")+1);
    memcpy(m->uuid,              "0000000000000000", strlen("0000000000000000")+1);

    m->interface_type                                                = INTERFACE_TYPE_UNKNOWN;
    m->interface_type_data.other.oui[0]                              = 0x00;
    m->interface_type_data.other.oui[1]                              = 0x00;
    m->interface_type_data.other.oui[2]                              = 0x00;
    m->interface_type_data.other.generic_phy_description_xml_url     = NULL;
    m->interface_type_data.other.variant_index                       = 0;
    m->interface_type_data.other.variant_name                        = 0;
    m->interface_type_data.other.media_specific.unsupported.bytes_nr = 0;
    m->interface_type_data.other.media_specific.unsupported.bytes    = NULL;

    m->is_secured                     = 0;
    m->push_button_on_going           = 2;    /* "2" means "unsupported" */
    m->push_button_new_mac_address[0] = 0x00;
    m->push_button_new_mac_address[1] = 0x00;
    m->push_button_new_mac_address[2] = 0x00;
    m->push_button_new_mac_address[3] = 0x00;
    m->push_button_new_mac_address[4] = 0x00;
    m->push_button_new_mac_address[5] = 0x00;

    m->power_state                    = INTERFACE_POWER_STATE_OFF;
    m->neighbor_mac_addresses_nr      = INTERFACE_NEIGHBORS_UNKNOWN;
    m->neighbor_mac_addresses         = NULL;

    m->ipv4_nr                        = 0;
    m->ipv4                           = NULL;
    m->ipv6_nr                        = 0;
    m->ipv6                           = NULL;

    m->vendor_specific_elements_nr    = 0;
    m->vendor_specific_elements       = NULL;

    /* Next, fill all the parameters we can depending on the type of interface we are dealing with: */

    /*********************************************************************
    *********************** SPECIAL INTERFACE ****************************
    *********************************************************************/

    /*  Some "special" interfaces require "special" methods to retrieve their
    *   data. These interfaces have "extended_params" associated.
    *   Let's check if this is the case.
    */
    executed = 0; //_executeInterfaceStub(interface_name, STUB_TYPE_GET_INFO, m);

    if (0 == executed) {
        /*********************************************************************
        *********************** REGULAR INTERFACE ****************************
        *********************************************************************/

        /* This is a "regular" interface. Query the Linux kernel for data */

#ifdef _FLAVOUR_AIRTIES_
        PLATFORM_OS_GET_1905_INTERFACE_INFO(interface_name, m);
#endif

        /* Fill the 'name' field */
        m->name = strdup(interface_name);
        /* interface mac address is queried at start up, (PLATFORM_INIT) instead of fetching everytime */
    }

    /* Avoid calling all log function below when loglevel is not debug */
    if (!PLATFORM_OS_LOG_LEVEL_TRACE()) {
        return m;
    }

    log_i1905_t("  mac_address                 : %02x:%02x:%02x:%02x:%02x:%02x", m->mac_address[0], m->mac_address[1], m->mac_address[2], m->mac_address[3], m->mac_address[4], m->mac_address[5]);
    log_i1905_t("  manufacturer_name           : %s", m->manufacturer_name);
    log_i1905_t("  model_name                  : %s", m->model_name);
    log_i1905_t("  model_number                : %s", m->model_number);
    log_i1905_t("  serial_number               : %s", m->serial_number);
    log_i1905_t("  device_name                 : %s", m->device_name);
    log_i1905_t("  uuid                        : %s", m->uuid);
    log_i1905_t("  interface_type              : %d", m->interface_type);
    if (INTERFACE_TYPE_IEEE_802_11B_2_4_GHZ == m->interface_type ||
        INTERFACE_TYPE_IEEE_802_11G_2_4_GHZ == m->interface_type ||
        INTERFACE_TYPE_IEEE_802_11A_5_GHZ   == m->interface_type ||
        INTERFACE_TYPE_IEEE_802_11N_2_4_GHZ == m->interface_type ||
        INTERFACE_TYPE_IEEE_802_11N_5_GHZ   == m->interface_type ||
        INTERFACE_TYPE_IEEE_802_11AC_5_GHZ  == m->interface_type ||
        INTERFACE_TYPE_IEEE_802_11AD_60_GHZ == m->interface_type ||
        INTERFACE_TYPE_IEEE_802_11AF        == m->interface_type ||
        INTERFACE_TYPE_IEEE_802_11AX        == m->interface_type)
    {
        log_i1905_t("    ieee80211 data");
        log_i1905_t("      bssid                       : %02x:%02x:%02x:%02x:%02x:%02x", m->interface_type_data.ieee80211.bssid[0], m->interface_type_data.ieee80211.bssid[1], m->interface_type_data.ieee80211.bssid[2], m->interface_type_data.ieee80211.bssid[3], m->interface_type_data.ieee80211.bssid[4], m->interface_type_data.ieee80211.bssid[5]);
        log_i1905_t("      ssid                        : %s", m->interface_type_data.ieee80211.ssid);
        log_i1905_t("      role                        : %d", m->interface_type_data.ieee80211.role);
        log_i1905_t("      ap_channel_band             : 0x%02x", m->interface_type_data.ieee80211.ap_channel_band);
        log_i1905_t("      ap_channel_center_f1        : 0x%02x", m->interface_type_data.ieee80211.ap_channel_center_frequency_index_1);
        log_i1905_t("      ap_channel_center_f2        : 0x%02x", m->interface_type_data.ieee80211.ap_channel_center_frequency_index_2);
        log_i1905_t("      authentication_mode         : 0x%04x", m->interface_type_data.ieee80211.authentication_mode);
        log_i1905_t("      encryption_mode             : 0x%04x", m->interface_type_data.ieee80211.encryption_mode);
        log_i1905_t("      network_key                 : %s", m->interface_type_data.ieee80211.network_key);
    } else if (INTERFACE_TYPE_IEEE_1901_WAVELET == m->interface_type ||
               INTERFACE_TYPE_IEEE_1901_FFT     == m->interface_type)
    {
        log_i1905_t("    ieee1901 data");
        log_i1905_t("      network_identifier          : %02x:%02x:%02x:%02x:%02x:%02x:%02x", m->interface_type_data.ieee1901.network_identifier[0], m->interface_type_data.ieee1901.network_identifier[1], m->interface_type_data.ieee1901.network_identifier[2], m->interface_type_data.ieee1901.network_identifier[3], m->interface_type_data.ieee1901.network_identifier[4], m->interface_type_data.ieee1901.network_identifier[5], m->interface_type_data.ieee1901.network_identifier[6]);
    } else if (INTERFACE_TYPE_UNKNOWN == m->interface_type)
    {
        uint16_t  len;
        uint8_t  *data;

        log_i1905_t("    generic interface data");
        log_i1905_t("      OUI                           : %02x:%02x:%02x", m->interface_type_data.other.oui[0], m->interface_type_data.other.oui[1], m->interface_type_data.other.oui[2]);
        log_i1905_t("      URL description               : %s", NULL == m->interface_type_data.other.generic_phy_description_xml_url ? "<none>" : m->interface_type_data.other.generic_phy_description_xml_url);
        log_i1905_t("      variant index                 : %d", m->interface_type_data.other.variant_index);
        log_i1905_t("      variant name                  : %s", NULL == m->interface_type_data.other.variant_name ? "<none>" : m->interface_type_data.other.variant_name);
        if (NULL != (data = forge_media_specific_blob(&m->interface_type_data.other, &len))) {
            if (len > 4) {
                log_i1905_t("      media specific data (%d bytes) : 0x%02x:0x%02x:0x%02x:0x%02x:0x%02x...", len, data[0], data[1], data[2], data[3], data[4]);
            } else {
                log_i1905_t("      media specific data (%d bytes)", len);
            }
            free_media_specific_blob(data);
        }
    }
    log_i1905_t("  is_secure                   : %d", m->is_secured);
    log_i1905_t("  push_button_on_going        : %d", m->push_button_on_going);
    log_i1905_t("  push_button_new_mac_address : %02x:%02x:%02x:%02x:%02x:%02x", m->push_button_new_mac_address[0], m->push_button_new_mac_address[1], m->push_button_new_mac_address[2], m->push_button_new_mac_address[3], m->push_button_new_mac_address[4], m->push_button_new_mac_address[5]);
    log_i1905_t("  power_state                 : %d", m->power_state);
    log_i1905_t("  neighbor_mac_addresses_nr   : %d", m->neighbor_mac_addresses_nr);
    if (m->neighbor_mac_addresses_nr != INTERFACE_NEIGHBORS_UNKNOWN) {
        for (i=0; i<m->neighbor_mac_addresses_nr; i++) {
            log_i1905_t("    - neighbor #%d                : %02x:%02x:%02x:%02x:%02x:%02x", i, m->neighbor_mac_addresses[i][0], m->neighbor_mac_addresses[i][1], m->neighbor_mac_addresses[i][2], m->neighbor_mac_addresses[i][3], m->neighbor_mac_addresses[i][4], m->neighbor_mac_addresses[i][5]);
        }
    }
    log_i1905_t("  IPs                         : %d", m->ipv4_nr+m->ipv6_nr);
    for (i = 0; i < m->ipv4_nr; i++) {
        log_i1905_t("    - IPv4 #%d                    : %d.%d.%d.%d (type = %s, dhcpserver = %d.%d.%d.%d)", i, m->ipv4[i].address[0], m->ipv4[i].address[1], m->ipv4[i].address[2], m->ipv4[i].address[3], m->ipv4[i].type == IPV4_UNKNOWN ? "unknown" : m->ipv4[i].type == IPV4_DHCP ? "dhcp" : m->ipv4[i].type == IPV4_STATIC ? "static" : m->ipv4[i].type == IPV4_AUTOIP ? "auto" : "error", m->ipv4[i].dhcp_server[0], m->ipv4[i].dhcp_server[1], m->ipv4[i].dhcp_server[2], m->ipv4[i].dhcp_server[3]);
    }
    for (i = 0; i < m->ipv6_nr; i++) {
        log_i1905_t("    - IPv6 #%d                    : %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x (type = %s, origin = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x)",
                    i,
                    m->ipv6[i].address[0], m->ipv6[i].address[1], m->ipv6[i].address[2], m->ipv6[i].address[3], m->ipv6[i].address[4], m->ipv6[i].address[5], m->ipv6[i].address[6], m->ipv6[i].address[7], m->ipv6[i].address[8], m->ipv6[i].address[9], m->ipv6[i].address[10], m->ipv6[i].address[11], m->ipv6[i].address[12], m->ipv6[i].address[13], m->ipv6[i].address[14], m->ipv6[i].address[15],
                    m->ipv6[i].type == IPV6_UNKNOWN ? "unknown" : m->ipv6[i].type == IPV6_DHCP ? "dhcp" : m->ipv6[i].type == IPV6_STATIC ? "static" : m->ipv6[i].type == IPV6_SLAAC ? "slaac" : "error",
                    m->ipv6[i].origin[0], m->ipv6[i].origin[1], m->ipv6[i].origin[2], m->ipv6[i].origin[3], m->ipv6[i].origin[4], m->ipv6[i].origin[5], m->ipv6[i].origin[6], m->ipv6[i].origin[7], m->ipv6[i].origin[8], m->ipv6[i].origin[9], m->ipv6[i].origin[10], m->ipv6[i].origin[11], m->ipv6[i].origin[12], m->ipv6[i].origin[13], m->ipv6[i].origin[14], m->ipv6[i].origin[15]);
    }
    log_i1905_t("  vendor_specific_elements_nr : %d", m->vendor_specific_elements_nr);
    for (i = 0; i < m->vendor_specific_elements_nr; i++) {
        log_i1905_t("    - vendor %d", m->vendor_specific_elements_nr);
        log_i1905_t("        OUI                       : %02x:%02x:%02x", m->vendor_specific_elements[i].oui[0], m->vendor_specific_elements[i].oui[1], m->vendor_specific_elements[i].oui[2]);
        log_i1905_t("        vendor_data_len           : %d", m->vendor_specific_elements[i].vendor_data_len);
        log_i1905_t("        vendor_data               : <TODO>"); /* TODO: Dump bytes as done, for example, in PLATFORM_SEND_ALME_REPLY() */
    }
    return m;
}

void PLATFORM_FREE_1905_INTERFACE_INFO(struct interfaceInfo *x)
{
    uint8_t i;

    free(x->name);

    if (INTERFACE_TYPE_UNKNOWN == x->interface_type) {
        if (!(x->interface_type_data.other.oui[0] == 0x00  &&
              x->interface_type_data.other.oui[1] == 0x19  &&
              x->interface_type_data.other.oui[2] == 0xA7  &&
              0 == strcmp("http://handle.itu.int/11.1002/3000/1706", x->interface_type_data.other.generic_phy_description_xml_url) &&
              (x->interface_type_data.other.variant_index == 1 || x->interface_type_data.other.variant_index == 2 || x->interface_type_data.other.variant_index == 3 || x->interface_type_data.other.variant_index == 4)
            )) {
            if (0 != x->interface_type_data.other.media_specific.unsupported.bytes_nr && NULL != x->interface_type_data.other.media_specific.unsupported.bytes) {
                free(x->interface_type_data.other.media_specific.unsupported.bytes);
            }
        }

        free(x->interface_type_data.other.generic_phy_description_xml_url);
        free(x->interface_type_data.other.variant_name);
    }
    if (x->neighbor_mac_addresses_nr > 0  && INTERFACE_NEIGHBORS_UNKNOWN != x->neighbor_mac_addresses_nr && NULL != x->neighbor_mac_addresses) {
       free(x->neighbor_mac_addresses);
    }

    if (x->ipv4_nr > 0 && NULL != x->ipv4) {
        free(x->ipv4);
    }

    if (x->ipv6_nr > 0 && NULL != x->ipv6) {
        free(x->ipv6);
    }

    if (x->vendor_specific_elements_nr > 0) {
        for (i=0; i<x->vendor_specific_elements_nr; i++) {
            if (x->vendor_specific_elements[i].vendor_data_len > 0 && NULL != x->vendor_specific_elements[i].vendor_data) {
                free(x->vendor_specific_elements[i].vendor_data);
            }
        }
        free(x->vendor_specific_elements);
    }

    free(x);
}

i1905_link_metrics_t *PLATFORM_GET_LINK_METRICS(char *local_interface_name, uint8_t *neighbor_interface_address)
{
    i1905_link_metrics_t   *ret;
    i1905_interface_info_t *x;
    int32_t                 tmp;
    uint8_t                 executed;

    ret = malloc(sizeof(i1905_link_metrics_t));
    if (NULL == ret) {
        return NULL;
    }

    /* Obtain the MAC address of the local interface */
    x = PLATFORM_GET_1905_INTERFACE_INFO(local_interface_name);
    if (NULL == x) {
        free(ret);
        return NULL;
    }
    maccpy(ret->local_interface_address, x->mac_address);
    PLATFORM_FREE_1905_INTERFACE_INFO(x);

    /* Copy the remote interface MAC address */
    maccpy(ret->neighbor_interface_address, neighbor_interface_address);

    /* Next, fill all the parameters we can depending on the type of interface we are dealing with: */

    /*********************************************************************
    *********************** SPECIAL INTERFACE ****************************
    **********************************************************************/

    /* Some "special" interfaces require "special" methods to retrieve their
    *  data. These interfaces have "extended_params" associated.
    *  Let's check if this is the case.
    */
    executed = 0; //_executeInterfaceStub(local_interface_name, STUB_TYPE_GET_METRICS, ret);

    if (0 == executed) {
        /*********************************************************************
        *********************** REGULAR INTERFACE ****************************
        *********************************************************************/

        /* This is a "regular" interface. Query the Linux kernel for data */

        /* Obtain how much time the process collecting stats has been running
        *
        *      TODO: This should be set to the amount of seconds ellapsed since
        *      the interface was brought up. However I could not find an easy
        *      way to obtain this information in Linux.
        *      For now, we will simply set this to the amount of seconds since
        *      the system was started, which is typically correct on most
        *      cases.
        */
        ret->measures_window = PLATFORM_GET_TIMESTAMP() / 1000;

        /* Check interface name
        *  TODO: Find a more robust way of identifying a wifi interface. Maybe
        *        checking "/sys"?
        */
        if (strstr(local_interface_name, "wlan") != NULL) {
            /* Obtain the amount of (correct and incorrect) packets transmitted
            *  to 'neighbor_interface_address' in the last
            *  'ret->measures_window' seconds.
            *
            *  This is done by reading the response of the command
            *
            *    "iw dev $INTERFACE station get $NEIGHBOR_MAC | grep "tx packets"" and
            *    "iw dev $INTERFACE station get $NEIGHBOR_MAC | grep "tx failed""
            */
            ret->tx_packet_ok     = read_wifi_neighbor_parameter(local_interface_name, ret->neighbor_interface_address, "\"tx packets\"");
            ret->tx_packet_errors = read_wifi_neighbor_parameter(local_interface_name, ret->neighbor_interface_address, "\"tx failed\"");

            /* Obtain the estimated max MAC xput and PHY rate when transmitting
            *  data from "A" to "B".
            *
            *  This is done by reading the response of the command
            *
            *    "iw dev $INTERFACE station get $NEIGHBOR_MAC | grep speed"
            */
            ret->tx_max_xput = read_wifi_neighbor_parameter(local_interface_name, ret->neighbor_interface_address, "\"tx bitrate\"");
            ret->tx_phy_rate = read_wifi_neighbor_parameter(local_interface_name, ret->neighbor_interface_address, "\"tx bitrate\"");

            /* Obtain the estimated average percentage of time that the link is
            *  available for transmission.
            *
            *    TODO: I'll just say "100% of the time" for now.
            */
            ret->tx_link_availability = 100;

            /* Obtain the amount of (correct and incorrect) packets received
            *  from 'neighbor_interface_address' in the last
            *  'ret->measures_window' seconds.
            *
            *  This is done by reading the response of the command
            *
            *    "iw dev $INTERFACE station get $NEIGHBOR_MAC | grep "rx packets""
            *
            *    TODO: rx errors can't be obtained from this console command.
            *    Right now it's assigned a zero value. Investigate how to
            *    obtain this value.
            */
            ret->rx_packet_ok     = read_wifi_neighbor_parameter(local_interface_name, ret->neighbor_interface_address, "\"rx packets\"");
            ret->rx_packet_errors = 0;


            /* Obtain the estimated RX RSSI
            *
            *  RSSI is a term used to measure the relative quality of a
            *  received signal to a client device, but has no absolute value.
            *  The IEEE 802.11 standard specifies that RSSI can be on a scale
            *  of 0 to up to 255 and that each chipset manufacturer can define
            *  their own “RSSI_Max” value. It’s all up to the manufacturer
            *  (which is why RSSI is a relative index), but you can infer that
            *  the higher the RSSI value is, the better the signal is.
            *
            *  A basic (saturated linear) conversion formula has been
            *  implemented:
            *    RSSI range 0-100 <--> signal -40 to -70 dBm
            *
            *  Feel free to redefine this conversion formula. Maybe to a
            *  logarithmical one.
            */
            tmp = read_wifi_neighbor_parameter(local_interface_name, ret->neighbor_interface_address, "\"signal:\"");

            #define  SIGNAL_MAX  (-40)   /* dBm */
            #define  SIGNAL_MIN  (-70)
            if (tmp >= SIGNAL_MAX) {
                ret->rx_rssi = 100;
            } else if(tmp <= SIGNAL_MIN) {
                ret->rx_rssi = 0;
            } else {
                ret->rx_rssi = (tmp - SIGNAL_MIN)*100/(SIGNAL_MAX - SIGNAL_MIN);
            }
        }
        /* Other interface types, probably ethernet */
        else {
            /* Obtain the amount of (correct and incorrect) packets transmitted
            *  to 'neighbor_interface_address' in the last
            *  'ret->measures_window' seconds.
            *
            *    TODO: In Linux there is no easy way to obtain this
            *    information. We will just report the amount of *total* packets
            *    transmitted from our local interface, no matter the
            *    destination.
            *    This information will only be correct when the local interface
            *    is connected to one single remote interface... however we
            *    better report this than nothing at all.
            *
            *  This is done by reading the contents of files
            *
            *    "/sys/class/net/<interface_name>/statistics/tx_packets" and
            *    "/sys/class/net/<interface_name>/statistics/tx_errors"
            */
            ret->tx_packet_ok     = read_interface_parameter(local_interface_name, "statistics/tx_packets");
            ret->tx_packet_errors = read_interface_parameter(local_interface_name, "statistics/tx_errors");

            /* Obtain the estimatid max MAC xput and PHY rate when transmitting
            *  data from "A" to "B".
            *
            *    TODO: The same considerations as in the previous parameters
            *    apply here.
            *
            *  This is done by reading the contents of file
            *
            *    "/sys/class/net/<interface_name>/speed
            *
            *  NOTE: I'll set both parameters to the same value. Is there a
            *  better way to do this?
            */
            ret->tx_max_xput = read_interface_parameter(local_interface_name, "speed");
            ret->tx_phy_rate = read_interface_parameter(local_interface_name, "speed");

            /* Obtain the estimated average percentage of time that the link is
            *  available for transmission.
            *
            *    TODO: I'll just say "100% of the time" for now.
            */
            ret->tx_link_availability = 100;

            /* Obtain the amount of (correct and incorrect) packets received from
            *  'neighbor_interface_address' in the last 'ret->measures_window'
            *  seconds.
            *
            *    TODO: In Linux there is no easy way to obtain this information. We
            *    will just report the amount of *total* packets received on our
            *    local interface, no matter the origin.
            *    This information will only be correct when the local interface is
            *    connected to one single remote interface... however we better
            *    report this than nothing at all.
            *
            *  This is done by reading the contents of files
            *
            *    "/sys/class/net/<interface_name>/statistics/rx_packets" and
            *    "/sys/class/net/<interface_name>/statistics/rx_errors"
            */
            ret->rx_packet_ok     = read_interface_parameter(local_interface_name, "statistics/rx_packets");
            ret->rx_packet_errors = read_interface_parameter(local_interface_name, "statistics/rx_errors");

            /* TODO: Obtain the estimated RX RSSI */
            ret->rx_rssi = 0;
        }
    }

    return ret;
}

void PLATFORM_FREE_LINK_METRICS(struct linkMetrics *l)
{
    /* This is a simple structure which does not require any special treatment. */
    free(l);
}

i1905_bridge_t *PLATFORM_GET_LIST_OF_BRIDGES(uint8_t *nr)
{
    /* TODO */

    *nr = 0;
    return NULL;
}

void PLATFORM_FREE_LIST_OF_BRIDGES(i1905_bridge_t *x, UNUSED uint8_t nr)
{
    free(x);
}

uint8_t PLATFORM_SEND_RAW_PACKET(char *interface_name, mac_addr dst_mac, mac_addr src_mac,
                                 uint16_t eth_type, uint8_t *payload, uint16_t payload_len)
{
    struct sockaddr_ll   socket_address;
    struct ether_header *eh;
    uint8_t              buffer[MAX_NETWORK_SEGMENT_SIZE];
    int                  fd      = PLATFORM_OS_GET_RAW_SEND_FD();           /* to avoid getting complete interface info */
    int                  ifindex = PLATFORM_OS_GET_IFINDEX(interface_name); /* to avoid getting complete interface info */

    if (fd <= 0 || ifindex <= 0) {
        return 0;
    }

    /* Avoid calling all log function below when loglevel is not debug */
    if (PLATFORM_OS_LOG_LEVEL_TRACE()) {
        int  i, first_time;
        char aux1[200];
        char aux2[10];

        /* Print packet (used for debug purposes) */
        log_i1905_t("Preparing to send RAW packet:");
        log_i1905_t("  - Interface name = %s", interface_name);
        log_i1905_t("  - DST  MAC       = 0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x", dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
        log_i1905_t("  - SRC  MAC       = 0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
        log_i1905_t("  - Ether type     = 0x%04x", eth_type);
        log_i1905_t("  - Payload length = %d", payload_len);

        aux1[0] = 0x0;
        aux2[0] = 0x0;
        first_time = 1;

        for (i = 0; i < payload_len; i++) {
            snprintf(aux2, 6, "0x%02x ", payload[i]);
            strncat(aux1, aux2, 200-strlen(aux1)-1);

            if (0 != i && (0 == (i+1) % 8)) {
                if (1 == first_time) {
                    log_i1905_t("  - Payload        = %s", aux1);
                    first_time = 0;
                } else {
                    log_i1905_t("                     %s", aux1);
                }
                aux1[0] = 0x0;
            }
        }

        if (1 == first_time) {
            log_i1905_t("  - Payload        = %s", aux1);
        } else {
            log_i1905_t("                     %s", aux1);
        }
    }

    /* Empy buffer for first 60 bytes (minimum ethernet payload - see send below) */
    memset(buffer, 0, MIN_PAYLOAD_LEN);

    /* Fill ethernet header */
    eh = (struct ether_header *)buffer;
    maccpy(eh->ether_dhost, dst_mac);
    maccpy(eh->ether_shost, src_mac);
    eh->ether_type = htons(eth_type);

    /* Fill buffer */
    memcpy(buffer + sizeof(*eh), payload, payload_len);

    /* Prepare sockaddr_ll */
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_ifindex  = ifindex;
    socket_address.sll_halen    = sizeof(mac_addr);
    maccpy(socket_address.sll_addr, dst_mac);

    log_i1905_t("Sending data to RAW socket");
    payload_len += sizeof(struct ether_header);

#ifdef UNIT_TEST
    /* Do not send in case of unit test */
    if (g_unit_test_send_cb) {
        g_unit_test_send_cb(interface_name, buffer, payload_len);
    }
    return 1;
#endif /* UNIT_TEST */

    if (sendto(fd, buffer, max(payload_len, MIN_PAYLOAD_LEN),
               0, (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
          log_i1905_e("sendto('%s') returned with errno=%d (%s)", interface_name, errno, strerror(errno));
          return 0;
    }

    /* For statistics... */
    PLATFORM_OS_PACKET_SENT(interface_name, eth_type);
    log_i1905_t("Data sent!");

    return 1;
}

uint8_t PLATFORM_SET_INTERFACE_POWER_MODE(char *interface_name, uint8_t power_mode)
{
    /* TODO */
    switch(power_mode) {
        case INTERFACE_POWER_STATE_ON:
            log_i1905_d("%s --> POWER ON", interface_name);
        break;
        case INTERFACE_POWER_STATE_OFF:
            log_i1905_d("%s --> POWER OFF", interface_name);
        break;
        case INTERFACE_POWER_STATE_SAVE:
            log_i1905_d("%s --> POWER SAVE", interface_name);
        break;
        default:
            log_i1905_e("Unknown power mode for interface %s (%d)", interface_name, power_mode);
            return 0;
        break;
    }

    return INTERFACE_POWER_RESULT_EXPECTED;
}

uint8_t PLATFORM_CONFIGURE_80211_AP(char *interface_name, uint8_t *ssid, uint8_t *bssid,
                                    uint16_t auth_type, uint16_t encryption_type, uint8_t *network_key,
                                    UNUSED uint8_t map_ext)
{
    log_i1905_t("Applying WSC configuration (%s): ", interface_name);
    log_i1905_t("  - SSID            : %s", ssid);
    log_i1905_t("  - BSSID           : %s", acu_mac_string(bssid));
    log_i1905_t("  - AUTH_TYPE       : 0x%04x", auth_type);
    log_i1905_t("  - ENCRYPTION_TYPE : 0x%04x", encryption_type);
    log_i1905_t("  - NETWORK_KEY     : %s", network_key);

#ifdef UNIT_TEST
    if (g_unit_test_configure_ap_cb) {
        g_unit_test_configure_ap_cb(interface_name, ssid, bssid,
                                    auth_type, encryption_type, network_key,
                                    map_ext);
    }
    return 1;
#endif /* UNIT_TEST */

#ifdef _FLAVOUR_AIRTIES_
    log_i1905_w("Configuration update not implemented");
#else
    log_i1905_w("Configuration has no effect on flavour-neutral platform")
#endif

    return 1;
}

#ifdef UNIT_TEST
void PLATFORM_REGISTER_UNIT_TEST_SEND_CB(i1905_unit_test_send_cb_t cb)
{
    g_unit_test_send_cb = cb;
}

void PLATFORM_REGISTER_UNIT_TEST_CONFIGURE_AP_CB(i1905_unit_test_configure_ap_cb_t cb)
{
    g_unit_test_configure_ap_cb = cb;
}
#endif /* UNIT_TEST */
