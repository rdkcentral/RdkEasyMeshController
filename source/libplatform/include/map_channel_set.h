/*
 * Copyright (c) 2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef MAP_CHANNEL_SET_H_
#define MAP_CHANNEL_SET_H_

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
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

/* Not allowed to modify channel set in loop */
#define map_cs_foreach(s, c) \
    for (c = 0; c < MAP_MAX_CHANNEL; c++) \
        if (!(s)->channels[c / CHAR_BIT]) { \
            c += (CHAR_BIT - 1); \
        } else if ((s)->channels[c / CHAR_BIT] & ( 1 << (c % CHAR_BIT)))

/* Allowed to modify channel set in loop */
#define map_cs_foreach_safe(s, c) \
    for (c = 0; c < MAP_MAX_CHANNEL; c++) \
        if ((s)->channels[c / CHAR_BIT] & ( 1 << (c % CHAR_BIT)))

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
    map_channel_set_t channel_set_320;
}  map_channel_bw_set_t;

/*#######################################################################
#                       FUNCTIONS                                       #
########################################################################*/
/* Channel set */
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

void map_cs_set_all(map_channel_set_t *s);

void map_cs_unset_all(map_channel_set_t *s);

void map_cs_copy(map_channel_set_t *d, const map_channel_set_t *s);

int map_cs_compare(map_channel_set_t *a, const map_channel_set_t *b);

void map_cs_or(map_channel_set_t *a, const map_channel_set_t *b);

void map_cs_and(map_channel_set_t *a, const map_channel_set_t *b);

void map_cs_and_not(map_channel_set_t *a, const map_channel_set_t *b);

char* map_cs_to_string(const map_channel_set_t *s, char delim, char *buf, int len);

int map_cs_from_string(const char *str, char delim, map_channel_set_t *s);


/* Channel-bandwidth set */
void map_cs_bw_set(map_channel_bw_set_t *s, uint16_t bw, uint8_t c);

void map_cs_bw_unset(map_channel_bw_set_t *s, uint16_t bw, uint8_t c);

void map_cs_bw_unset_all(map_channel_bw_set_t *s);

char* map_cs_bw_to_string(const map_channel_bw_set_t *b, char delim, char *buf, int len);

#endif /* MAP_CHANNEL_SET_H_ */
