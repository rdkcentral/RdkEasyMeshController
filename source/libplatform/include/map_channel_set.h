/*
 * Copyright (c) 2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef MAP_CHANNEL_SET_H_
#define MAP_CHANNEL_SET_H_

/* This is a header only implementation */

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define MAP_MAX_CHANNEL 240

#define MAP_CS_BUF_LEN  (MAP_MAX_CHANNEL * 4)
#define MAP_CHANS_W_BW_BUF_LEN (MAP_MAX_CHANNEL * 8)

#if CHAR_BIT != 8
  #error Unexpected value of CHAR_BIT
#endif

#define map_cs_is_valid(c) (c > 0 && c < MAP_MAX_CHANNEL)
#define map_bw_is_valid(bw) (bw == 20 || bw == 40 || bw == 80 || bw == 160)

/* Not allowed to modify channel set in loop */
#define map_cs_foreach(s, c) \
    for (c = 0; c < MAP_MAX_CHANNEL; c++) \
        if (!(s)->channels[c / CHAR_BIT]) { \
            c += (CHAR_BIT - 1); \
            continue; \
        } else if ((s)->channels[c / CHAR_BIT] & ( 1 << (c % CHAR_BIT)))

/* Allowed to modify channel set in loop */
#define map_cs_foreach_safe(s, c) \
    for (c = 0; c < MAP_MAX_CHANNEL; c++) \
        if (map_cs_is_set(s, c))

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
typedef struct {
    uint8_t nr;
    uint8_t channels[MAP_MAX_CHANNEL / CHAR_BIT];
}  map_channel_set_t;

typedef struct {
    map_channel_set_t channel_set_20;
    map_channel_set_t channel_set_40;
    map_channel_set_t channel_set_80;
    map_channel_set_t channel_set_160;
}  map_channel_bw_set_t;


/*#######################################################################
#                       FUNCTIONS                                       #
########################################################################*/
static inline void map_cs_set(map_channel_set_t *s, uint8_t c)
{
    if (map_cs_is_valid(c)) {
        int byte = c / CHAR_BIT, bit = 1 << (c % CHAR_BIT);

        if (!(s->channels[byte] & bit)) {
            s->nr++;
            s->channels[byte] |= bit;
        }
    }
}

static inline void map_cs_unset(map_channel_set_t *s, uint8_t c)
{
    if (map_cs_is_valid(c)) {
        uint8_t byte = c / CHAR_BIT, bit = 1 << (c % CHAR_BIT);

        if (s->channels[byte] & bit) {
            s->nr--;
            s->channels[byte] &= ~bit;
        }
    }
}

static inline bool map_cs_is_set(const map_channel_set_t *s, uint8_t c)
{
    if (map_cs_is_valid(c)) {
        uint8_t byte = c / CHAR_BIT, bit = 1 << (c % CHAR_BIT);

        return (s->channels[byte] & bit);
    }

    return false;
}

static inline int map_cs_nr(const map_channel_set_t *s)
{
    return s->nr;
}

static inline void map_cs_set_all(map_channel_set_t *s)
{
    uint8_t i;

    for (i = 1; i < MAP_MAX_CHANNEL; i++) {
        map_cs_set(s, i);
    }
}

static inline void map_cs_unset_all(map_channel_set_t *s)
{
    memset(s, 0, sizeof(map_channel_set_t));
}

static inline void map_cs_copy(map_channel_set_t *d, const map_channel_set_t *s)
{
    *d = *s;
}

static inline int map_cs_compare(map_channel_set_t *a, const map_channel_set_t *b)
{
    return memcmp(a, b, sizeof(map_channel_set_t));
}

static inline void map_cs_or(map_channel_set_t *a, const map_channel_set_t *b)
{
    int c;

    map_cs_foreach_safe(b, c) {
        map_cs_set(a, c);
    }
}

static inline void map_cs_and(map_channel_set_t *a, const map_channel_set_t *b)
{
    int c;

    map_cs_foreach_safe(a, c) {
        if (!map_cs_is_set(b, c)) {
            map_cs_unset(a, c);
        }
    }
}

static inline char* map_cs_to_string(const map_channel_set_t *s, char delim, char *buf, int len)
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

static inline char* map_cs_bw_to_string(const map_channel_bw_set_t *b, char delim, char *buf, int len)
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

dump:
    /* Remove last delimiter */
    if (pos > 0) {
        buf[pos - 1] = 0;
    }

    return buf;
}

static inline int map_cs_from_string(const char *str, char delim, map_channel_set_t *s)
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

static inline void map_cs_bw_set(map_channel_bw_set_t *s, uint8_t bw, uint8_t c)
{
    if (map_bw_is_valid(bw)) {
        switch(bw)
        {
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
        default:
            return;
        }
    }
}

static inline void map_cs_bw_unset(map_channel_bw_set_t *s, uint8_t bw, uint8_t c)
{
    if (map_bw_is_valid(bw)) {
        switch(bw)
        {
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
        default:
            return;
        }
    }
}

static inline void map_cs_bw_unset_all(map_channel_bw_set_t *s)
{
    memset(s, 0, sizeof(map_channel_bw_set_t));
}

#endif /* MAP_CHANNEL_SET_H_ */
