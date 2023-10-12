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

#ifndef PLATFORM_OS_H_
#define PLATFORM_OS_H_

#include <stdbool.h>

#include "platform_interfaces.h"
#include "map_utils.h"

/*#######################################################################
# Device information functions                                          #
########################################################################*/
typedef struct deviceInfo {
    char *friendly_name;               /* NULL-terminated string containing the
                                       *  name that identifies this device on
                                       *  the network.
                                       *  This is the same name devices display
                                       *  on their web interface or when queried
                                       *  by uPnP.
                                       *  Max length = 64 bytes (including the
                                       *  NULL char)
                                       */

    char *manufacturer_name;           /* NULL-terminated string containing the
                                       *  manufacturer name.
                                       *  Max length = 64 bytes (including the
                                       *  NULL char)
                                       */

    char *manufacturer_model;          /* NULL-terminated string containing the
                                       *  manufacturer model.
                                       *  Max length = 64 bytes (including the
                                       *  NULL char)
                                       */

    char *control_url;                 /* NULL-terminated string containing the
                                       *  a control URL (typically a WebUI that
                                       *  can be used to further configure the
                                       *  device).  Example:
                                       *  "http://192.168.1.10/index.html"
                                       */
} i1905_device_info_t;

typedef void (*i1905_packet_cb_t)(char *if_name, uint8_t *packet, uint16_t packet_len);

/* Initialize platform os layer */
uint8_t PLATFORM_OS_INIT(i1905_interface_cb_t interface_cb, i1905_packet_cb_t packet_cb);

/* Fini platform os layer */
void PLATFORM_OS_FINI(void);

/* Dump interfaces */
void PLATFORM_OS_DUMP_INTERFACES(map_printf_cb_t print_cb);

/* Get list of interfaces */
char **PLATFORM_OS_GET_LIST_OF_1905_INTERFACES(uint8_t *nr);

/* Free list of interfaces */
void PLATFORM_OS_FREE_LIST_OF_1905_INTERFACES(char **interfaces, uint8_t nr);

/* Get info about a specific interface */
void PLATFORM_OS_GET_1905_INTERFACE_INFO(char *if_name, i1905_interface_info_t *info);

/* Check if interface is up (to avoid expesive interface info call) */
bool PLATFORM_OS_IS_INTERFACE_UP(char *if_name);

/* Get interface index (to avoid expesive interface info call) */
int PLATFORM_OS_GET_IFINDEX(char *if_name);

/* Indicate that a packet was sent on an interface (for stats) */
void PLATFORM_OS_PACKET_SENT(char *if_name, uint16_t ether_type);

/* Get global raw send socket fd */
int PLATFORM_OS_GET_RAW_SEND_FD(void);

/* Get global gateway mac */
mac_addr* PLATFORM_OS_GET_GATEWAY_MAC(void);

/* Check if log level is at least trace */
bool PLATFORM_OS_LOG_LEVEL_TRACE(void);

#endif /* PLATFORM_OS_H_ */
