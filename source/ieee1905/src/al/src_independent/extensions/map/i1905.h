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

#ifndef I1905_LIB_H_
#define I1905_LIB_H_

#include <stdint.h>
#include "map_config.h"

/* Include all exported headers */
#include "1905_cmdus.h"
#include "1905_tlvs.h"
#include "1905_platform.h"
#include "map_tlvs.h"
#include "lldp_tlvs.h"
#include "lldp_payload.h"
#include "packet_tools.h"

/**
 * This data structure is used to provide data needed to create the WSC M2
 *
 * @param[in] profile : map profile containing ssid, key,...
 * @param[in] map_ext : map extension used in WFA MAP WSC attribute
 */

typedef struct {
    const map_profile_cfg_t *profile;
    uint8_t                  map_ext;
} i1905_wsc_m2_cfg_t;

/**
 * This data structure is used as a parameter while constructing or extracting
 * WSC M1/M2 messages using lib1905_get/lib1905_set
 *
 * @param[in] m2_config   : Controller Configuration info required to build M2.
 * @param[in] wd          : Agent Configuration required to process M2.
 * @param[in,out] wsc_key : The key that is generated during M1 construction is
 *                           provided back to the caller as an out parameter.
 *                           The returned key needs to be sent back while processing
 *                           the received M2 as an input parameter.
 * @param[out] m1         : Pointer to M1 returned for GET_1905_WSCM1TLV
 * @param[out] m2         : Pointer to M2 returned for GET_1905_WSCM2TLV
 */

typedef struct {
   i1905_wsc_key_t    *wsc_key;
   i1905_wsc_tlv_t     m1;
   i1905_wsc_tlv_t     m2;
   i1905_wsc_m2_cfg_t *m2_cfg;
} i1905_wsc_data_t;


/**
 * This data structure is used as a parameter while constructing Frequency Band
 * TLV required for Auto-config response message.
 *
 * @param[in] freq_band               : The supported frequency band
 * @param[out] supported_freq_band_tlv: The supported frequency band TLV
 */
typedef struct {
   uint8_t freq_band;
   i1905_supported_freq_band_tlv_t *supported_freq_band_tlv;
} i1905_supported_freq_band_data_t;


/**
 * This enumeration is used as a parameter while getting/setting TLV/CMDU
 * from 1905 AL Entity
 * Multi-AP has extended some of the 1905 messages, this API is used to retrieve
 * or set the 1905 TLVs from/to AL entity
 *
 * @param I1905_GET_SEARCHEDROLE_TLV:       Used to retrieve SearchedRole TLV
 * @param I1905_GET_ALMAC_TLV:              Used to retrieve ALMAC TLV
 * @param I1905_GET_FREQUENCYBAND_TLV:      Used to retrieve Frequency Band TLV
 * @param I1905_GET_SUPPORTEDROLE_TLV:      Used to retrieve supported Role TLV
 * @param I1905_GET_SUPPORTEDFREQBAND_TLV:  Used to retrieve supported Frequency Band TLV
 * @param I1905_GET_WSCM1_TLV:              Used to retrieve WSC M1 TLV
 * @param I1905_GET_WSCM2_TLV:              Used to retrieve WSC M2 TLV
 *
 * @param I1905_SET_WSCM2_TLV:              Used to set WSC M2 TLV to 1905 AL entity
 */
typedef enum {
    I1905_GET_SEARCHEDROLE_TLV,
    I1905_GET_ALMAC_TLV,
    I1905_GET_FREQUENCYBAND_TLV,
    I1905_GET_SUPPORTEDROLE_TLV,
    I1905_GET_SUPPORTEDFREQBAND_TLV,
    I1905_GET_DEVICEINFO_TLV,
    I1905_GET_WSCM1_TLV,
    I1905_GET_WSCM2_TLV,

    I1905_SET_WSCM2_TLV
} i1905_param_t;


/**
 * Initialize 1905 library
 *
 * @param[in] al_mac      : al mac address
 * @param[in] interface_cb: interface callback
 * @param[in] cmdu_cb     : cmdu callback
 *
 * @retval  0 For successful get operation
 */
typedef bool (*i1905_cmdu_cb_t)(i1905_cmdu_t *cmdu);
int i1905_init(uint8_t *al_mac, i1905_interface_cb_t interface_cb, i1905_cmdu_cb_t cmdu_cb);


/**
 * De-initialize 1905 library
 *
 */
void i1905_fini(void);


/**
 * Get list of interfaces 1905 stack is using
 *
 * @param[out] nr: number of interfaces
 *
 * @retval  list of interface names
 */
char **i1905_get_list_of_interfaces(uint8_t *nr);


/**
 * Free list of interfaces retrieved with i1905_get_list_of_interfaces
 *
 * @param[in] interfaces: list of interface names
 * @param[in] nr        : number of interfaces
 *
 * @retval  list of interface names
 */
void i1905_free_list_of_interfaces(char **interfaces, uint8_t nr);


/**
 * Get interface info
 *
 * @param[in] ifname: interface name
 *
 * @retval  interface info
 */
i1905_interface_info_t *i1905_get_interface_info(char *ifname);


/**
 * Free interface info retrieved with i1905_get_interface_info
 *
 * @param[in] info: interface info
 *
 */
void i1905_free_interface_info(i1905_interface_info_t *info);


/**
 * Get list of bridges
 *
 * @param[out] nr: number of bridges
 *
 * @retval  bridges
 */
i1905_bridge_t *i1905_get_list_of_bridges(uint8_t *nr);


/**
 * Free list of bridges retreived with i1905_get_list_of_bridges
 *
 * @param[in] br: bridges
 * @param[in] nr: number of bridges
 *
 * @retval  bridges
 */
void i1905_free_list_of_bridges(i1905_bridge_t *br, uint8_t nr);


/**
 * Dump interfaces known in 1905 library
 *
 * @param[in] print_cb: printff like callback function
 */
void i1905_dump_interfaces(map_printf_cb_t print_cb);


/**
 * Dump interfaces known in 1905 library
 *
 * @param[out] mac: Get 1905 mcast mac address.
 */
void i1905_get_mcast_mac(mac_addr mac);


/**
 * Gets information from 1905 lib
 *
 * @param[in]  ifname   : Interface corresponding to the parameter
 * @param[in]  param    : 1905 parameter Enumeration
 * @param[out] data     : Parameter that is obtained from 1905 library
 * @param[out] data_len : Data length
 *
 * @retval  0  For successful get operation
 * @retval -1  If the input parameters are invalid
 */
int i1905_get(char *ifname, i1905_param_t param, void *data, size_t *data_len);


/**
 * Sets information to 1905 lib
 *
 * @param[in] ifname   : Interface name
 * @param[in] param    : 1905 parameter Enumeration
 * @param[in] data     : Parameter value that is set to 1905 Agent
 * @param[in] data)len : Data length
 *
 * @retval 0   For successful set operation
 * @retval -1  If the input parameters are invalid
 */
int i1905_set(char *ifname, i1905_param_t param, void *data, size_t data_len);


/**
 * Sends 1905 CMDU to the specified destination address
 *
 * @param[in] dmac    : MAC address of the destination 1905.1 device
 * @param[in] cmdu    : payload of the message that needs to be sent
 * @param[in,out] mid : Pointer to message id, if the message id is set to 0,
 *                      it is generated and returned back by the 1905 library
 *                      if the message id is non-zero, the specified mid would
 *                      be used while sending the message
 *
 *
 * @retval 0   For successful set operation
 * @retval -1  If the input parameters are invalid
 */
int i1905_send(i1905_cmdu_t *cmdu, mac_addr dmac, uint16_t *mid);


/**
 * Sends raw 1905 message to the specified destination address
 *
 * @param[in] ifname   : interface to send over
 * @param[in] dmac     : MAC address of the destination 1905.1 device
 * @param[in] smac     : MAC address of the source 1905.1 device
 * @param[in] eth_type : ether type
 * @param[in] data     : message payload
 * @param[in] data_len : length of the message payload
 *
 * @retval 0   For successful set operation
 * @retval -1  If the input parameters are invalid
 */
int i1905_send_raw(char *ifname, mac_addr dmac, mac_addr smac, uint16_t eth_type, uint8_t *data, uint16_t data_len);


/* This api can be used by upper layers to send LLDP message via 1905 library
 * @param ifname[in]  : used for identyfying interface on which message is to be sent by platform
 * @param smac[in]    : source mac address
 * @param payload[in] : containes payload to be sent
 * @retval 0   For successful sending of message
 * @retval -1  If input parameters are invalid
 */
int i1905_send_lldp(char *ifname, mac_addr smac, i1905_lldp_payload_t *payload);


/**
 * Frees the CMDU that is passed to the function
 * This API also performs a deep free of all the TLVs present in the CMDU
 *
 * @param[in] cmdu : CMDU to be freed
 *
 */
void i1905_cmdu_free(i1905_cmdu_t *cmdu);


/**
 * Convert cmdu type to string
 *
 * @param[in] cmdu_type
 */
const char *i1905_cmdu_type_to_string(uint16_t cmdu_type);


/**
 * Convert tlv type to string
 *
 * @param[in] tlv_type
 */
const char *i1905_tlv_type_to_string(uint8_t tlv_type);

/**
 * Get gateway mac address
 *
 */
void i1905_get_gateway_mac_address(mac_addr mac);

#endif /* I1905_LIB_H_ */
