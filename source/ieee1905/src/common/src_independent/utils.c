/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

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
#include <string.h>
#include "platform.h"
#include "utils.h"

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
void print_callback(void (*write_function)(const char *fmt, ...), const char *prefix, size_t size, const char *name, const char *fmt, void *p)
{
   if (0 == memcmp(fmt, "%s", 3)) {
       /* Strings are printed with triple quotes surrounding them */
       write_function("%s%s: \"\"\"%s\"\"\"\n", prefix, name, p);
       return;
   } else if (0 == strncmp(fmt, "%ipv4", 6)) {
       /* This is needed because "size == 4" on IPv4 addresses, but we don't
        *  want them to be treated as 4 bytes integers, so we change the
        *  "fmt" to "%d" and do *not* returns (so that the IPv4 ends up being
        *  printed as a sequence of bytes.
        */
       fmt = "%d";
    } else {
        #define FMT_LINE_SIZE 32
        char fmt_line[FMT_LINE_SIZE];

        snprintf(fmt_line, FMT_LINE_SIZE, "%%s%%s: %s\n", fmt);

        if (1 == size) {
            write_function(fmt_line, prefix, name, *(uint8_t *)p);
            return;
        } else if (2 == size) {
            write_function(fmt_line, prefix, name, *(uint16_t *)p);
            return;
        } else if (4 == size) {
            write_function(fmt_line, prefix, name, *(uint32_t *)p);
            return;
        }
    }

    /* If we get here, it's either an IPv4 address or a sequence of bytes */
    {
        #define AUX1_SIZE 256  // Store a whole output line
        #define AUX2_SIZE  32  // Store a fmt conversion

        size_t   i;
        char     aux1[AUX1_SIZE];
        char     aux2[AUX2_SIZE];
        int      pos1, pos2;
        uint8_t *u8p = p;

        pos1 = snprintf(aux1, AUX1_SIZE, "%%s%%s: ");

        for (i = 0; i < size; i++) {
            /* Write one element to aux2 */
            pos2 = snprintf(aux2, AUX2_SIZE, fmt, u8p[i]);

            /* 'pos2' contains the number of chars in "aux2"
            *  Check if there is enough space left in "aux1"
            *
            *    NOTE: The "+2" is because we are going to append to "aux1"
            *          the contents of "aux2" plus a ", " string (which is
            *          three chars long)
            *          The second "+2" is because of the final "\n"
            */
            if ((pos2 + 2 + 2) > ((AUX1_SIZE - 1) - pos1)) {
                /* No more space left -> add ...*/
                if (pos1 > (AUX1_SIZE - 4)) {
                    pos1 = AUX1_SIZE - 4;
                }
                aux1[pos1    ] = '.';
                aux1[pos1 + 1] = '.';
                aux1[pos1 + 2] = '.';
                aux1[pos1 + 3] = '\0';
                break;
            }

            /* Append string to "aux1" */
            pos1 += snprintf(aux1 + pos1, AUX1_SIZE - pos1, "%s, ", aux2);
        }

        snprintf(aux1 + pos1, AUX1_SIZE - pos1, "\n");
        write_function(aux1, prefix, name);
    }
}
