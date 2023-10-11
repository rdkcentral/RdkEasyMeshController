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

#ifndef PLATFORM_H_
#define PLATFORM_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <inttypes.h>
#include "map_utils.h"

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

/* Maximum network segment size (assuming eth header with vlan tag) */
#define MAX_NETWORK_SEGMENT_SIZE 1518

#define ETH_8021Q_HDR_SIZE       18
#define CMDU_HDR_SIZE            8
#define TLV_HDR_SIZE             3

#define MAX_CMDU_SIZE            (MAX_NETWORK_SEGMENT_SIZE - ETH_8021Q_HDR_SIZE)
#define MAX_TLV_SIZE             (MAX_CMDU_SIZE            - CMDU_HDR_SIZE)
#define MAX_TLV_PAYLOAD_SIZE     (MAX_TLV_SIZE             - TLV_HDR_SIZE)

/*#######################################################################
# Hardware stuff                                                        #
########################################################################*/

/* The following preprocessor macros must be defined to a platform-dependent
*  value:
*
*    __BYTE_ORDER__            --------> This indicates your CPU endianness.
*                                        It is predefined by gcc(if it is newer than v4.6)
*                                        If it is not predefined, you should set to
*                                        __ORDER_LITTLE_ENDIAN__ or __ORDER_BIG_ENDIAN__
*
*    MAX_NETWORK_SEGMENT_SIZE  --------> This is the maximum packet size that
*                                        is allowed in your platform. It is
*                                        used to 'fragment' CMDUs.  Note that
*                                        even if your platform supports packets
*                                        bigger than 1500 bytes, this macro
*                                        must never be bigger than that.  This
*                                        macro is only present in this file for
*                                        those special cases where, for some
*                                        platform related reason, packets must
*                                        be smaller than 1500.
*
*
*  In the next few lines we are just going to check that these are defined,
*  nothing else.
*  In order to actually define them use the "root" Makefile where these MACROS
*  are sent to the compiler using the "-D flag" (open the "root" Makefile and
*   search for "CCFLAGS" to understand how to do this)
*/

#if !(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) && !(__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
  #error  "You must define __BYTE_ORDER__ as either '__ORDER_LITTLE_ENDIAN__' or '__ORDER_BIG_ENDIAN__'"
#endif

#ifndef  MAX_NETWORK_SEGMENT_SIZE
  #error  "You must define 'MAX_NETWORK_SEGMENT_SIZE' to some value (for example, '1500')"
#endif

/*#######################################################################
# Print and timestamp function                                          #
########################################################################*/
/* Output the provided format string (see 'man 3 printf' on any Linux box) */
void PLATFORM_PRINTF(const char *format, ...);

/* Return the number of milliseconds ellapsed since the program started */
uint64_t PLATFORM_GET_TIMESTAMP(void);


/*#######################################################################
# Initialization functions                                              #
########################################################################*/

/* This function *must* be called before any other "PLATFORM_*()" API function
*
*  Returns "0" if there was a problem. "1" otherwise.
*
*  [PLATFORM PORTING NOTE]
*    Use this function to reserve memory, initialize semaphores, etc...
*/
uint8_t PLATFORM_INIT(void);

#endif /* PLATFORM_H */
