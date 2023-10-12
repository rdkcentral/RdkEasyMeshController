/*
 * Copyright (c) 2021-2023 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "map_channel_set.h"

/*#######################################################################
#                       FUNCTIONS                                       #
########################################################################*/
void map_cs_set_all(map_channel_set_t *s)
{
    uint8_t i;

    for (i = 1; i < MAP_MAX_CHANNEL; i++) {
        map_cs_set(s, i);
    }
}

void map_cs_unset_all(map_channel_set_t *s)
{
    memset(s, 0, sizeof(map_channel_set_t));
}

void map_cs_copy(map_channel_set_t *d, const map_channel_set_t *s)
{
    *d = *s;
}

int map_cs_compare(map_channel_set_t *a, const map_channel_set_t *b)
{
    return memcmp(a, b, sizeof(map_channel_set_t));
}

void map_cs_or(map_channel_set_t *a, const map_channel_set_t *b)
{
    int c;

    map_cs_foreach(b, c) {
        map_cs_set(a, c);
    }
}

void map_cs_and(map_channel_set_t *a, const map_channel_set_t *b)
{
    int c;

    map_cs_foreach_safe(a, c) {
        if (!map_cs_is_set(b, c)) {
            map_cs_unset(a, c);
        }
    }
}

void map_cs_and_not(map_channel_set_t *a, const map_channel_set_t *b)
{
    int c;

    map_cs_foreach(b, c) {
        map_cs_unset(a, c);
    }
}

char* map_cs_to_string(const map_channel_set_t *s, char delim, char *buf, int len)
{
    uint8_t c;
    int pos = 0;

    buf[0] = 0;

    map_cs_foreach(s, c) {
        pos += snprintf(&buf[pos], len - pos, "%d%c", c, delim);
        if (pos >= len) {
            break;
        }
    }

    /* Remove last delimiter */
    if (pos > 0) {
        buf[pos - 1] = 0;
    }

    return buf;
}

int map_cs_from_string(const char *str, char delim, map_channel_set_t *s)
{
    map_cs_unset_all(s);

    do {
        map_cs_set(s, atoi(str));
        if ((str = strchr(str, delim))) {
           str++;
        }
    } while (str);

    return 0;
}

void map_cs_bw_set(map_channel_bw_set_t *s, uint16_t bw, uint8_t c)
{
    switch (bw) {
        case 20:
            map_cs_set(&(s->channel_set_20), c);
            break;
        case 40:
            map_cs_set(&(s->channel_set_40), c);
            break;
        case 80:
            map_cs_set(&(s->channel_set_80), c);
            break;
        case 160:
            map_cs_set(&(s->channel_set_160), c);
            break;
        case 320:
            map_cs_set(&(s->channel_set_320), c);
            break;
        default:
            break;
    }
}

void map_cs_bw_unset(map_channel_bw_set_t *s, uint16_t bw, uint8_t c)
{
    switch (bw) {
        case 20:
            map_cs_unset(&(s->channel_set_20), c);
            break;
        case 40:
            map_cs_unset(&(s->channel_set_40), c);
            break;
        case 80:
            map_cs_unset(&(s->channel_set_80), c);
            break;
        case 160:
            map_cs_unset(&(s->channel_set_160), c);
            break;
        case 320:
            map_cs_unset(&(s->channel_set_320), c);
            break;
        default:
            break;
    }
}

void map_cs_bw_unset_all(map_channel_bw_set_t *s)
{
    memset(s, 0, sizeof(map_channel_bw_set_t));
}

char* map_cs_bw_to_string(const map_channel_bw_set_t *b, char delim, char *buf, int len)
{
    uint8_t c;
    int pos = 0;
    buf[0] = 0;

    map_cs_foreach(&(b->channel_set_20), c) {
        pos += snprintf(&buf[pos], len - pos, "%d%c%d%c", c, '/', 20, delim);
        if (pos >= len) {
            goto dump;
        }
    }

    map_cs_foreach(&(b->channel_set_40), c) {
        pos += snprintf(&buf[pos], len - pos, "%d%c%d%c", c, '/', 40, delim);
        if (pos >= len) {
            goto dump;
        }
    }

    map_cs_foreach(&(b->channel_set_80), c) {
        pos += snprintf(&buf[pos], len - pos, "%d%c%d%c", c, '/', 80, delim);
        if (pos >= len) {
            goto dump;
        }
    }

    map_cs_foreach(&(b->channel_set_160), c) {
        pos += snprintf(&buf[pos], len - pos, "%d%c%d%c", c, '/', 160, delim);
        if (pos >= len) {
            goto dump;
        }
    }

    map_cs_foreach(&(b->channel_set_320), c) {
        pos += snprintf(&buf[pos], len - pos, "%d%c%d%c", c, '/', 320, delim);
        if (pos >= len) {
            goto dump;
        }
    }

dump:
    /* Remove last delimiter */
    if (pos > 0) {
        buf[pos - 1] = 0;
    }

    return buf;
}
