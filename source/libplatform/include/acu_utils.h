/*
 * Copyright (c) 2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

#ifndef __ACU_UTILS_H__
#define __ACU_UTILS_H__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#ifndef UNUSED
#define UNUSED __attribute__((__unused__))
#endif

#define LWHITE		"\033[37;1m"
#define DGREEN		"\033[32;2m"
#define LRED		"\033[31m"
#define LBLUE		"\033[34m"
#define NORM		"\033[0m"
#define BLUE		"\033[34;1m"
#define YELLOW		"\033[33;1m"
#define MAGENTA		"\033[35m"
#define BOLD_ON		"\033[1m"

#define BRED    "\033[1;31m"
#define BGREEN  "\033[1;32m"
#define BYELLOW "\033[1;33m"
#define BBLUE   "\033[1;34m"

#ifdef FALSE
#undef FALSE
#endif
#ifdef TRUE
#undef TRUE
#endif
#define FALSE 0
#define TRUE 1

#define MULT_60(x)		((x) * (60))
#define HOURS_TO_SEC(x)		(MULT_60(x) * (60))
#define HOURS_TO_MIN(x)		MULT_60(x)
#define MIN_TO_SEC(x)		MULT_60(x)
#define MIN_TO_MSEC(x)		((MIN_TO_SEC(x)) * (1000))
#define MIN_TO_USEC(x)		((MIN_TO_MSEC(x)) * (1000))
#define SEC_TO_MIN(x)		((x) / (60))
#define SEC_TO_MSEC(x)		((x) * (1000))
#define SEC_TO_USEC(x)		((SEC_TO_MSEC(x)) * (1000))
#define SEC_TO_NSEC(x)		((SEC_TO_USEC(x)) * (1000))
#define MSEC_TO_USEC(x)		((x) * (1000))
#define MSEC_TO_NSEC(x)		((x) * (1000000))
#define MSEC_TO_SEC(x) 		((x) / (1000))
#define USEC_TO_NSEC(x)		((x) * (1000))
#define NSEC_TO_USEC(x)		((x) / (1000))
#define NSEC_TO_MSEC(x)		((x) / (1000000))

#define MIN(a, b)		(((a) < (b)) ? (a) : (b))
#define MAC_STR_MAX		18
#define KB_TO_BYTES(x)		((x) * (1024))

#if !defined(SFREE)
#define SFREE(_ptr)				\
	do  {					\
		if (_ptr) {			\
			free((void *)_ptr);	\
			_ptr = NULL;		\
		}				\
	} while (0)
#endif /* SFREE */

#if !defined(ARRAY_ELEM_CNT)
#define ARRAY_ELEM_CNT(a)	((sizeof(a)) / (sizeof((a)[0])))
#endif /* ARRAY_ELEM_CNT */

#if !defined(MACF)
#define MACF		"%02x:%02x:%02x:%02x:%02x:%02x"
#endif /* MACF */

#if !defined(ETHER_TO_MACF)
#define ETHER_TO_MACF(mac)				\
	((mac[0]) & (0xff)), ((mac[1]) & (0xff)),	\
	((mac[2]) & (0xff)), ((mac[3]) & (0xff)),	\
	((mac[4]) & (0xff)), ((mac[5]) & (0xff))
#endif /* ETHER_TO_MACF */

#if !defined(NULL_CHECK)
#define NULL_CHECK(param, action)			\
		if (unlikely(param == NULL)) {		\
			errorf(#param" is NULL.");	\
			action;				\
		}
#endif /* NULL_CHECK */

#if !defined(TAILQ_FOREACH_SAFE)
#define	TAILQ_FOREACH_SAFE(var, head, field, next)		\
	for ((var) = ((head)->tqh_first);			\
		(var) && ((next) = ((var)->field.tqe_next), 1);	\
		(var) = (next))
#endif /* TAILQ_FOREACH_SAFE */

#if !defined(STAILQ_FOREACH_SAFE)
#define	STAILQ_FOREACH_SAFE(var, head, field, next)			\
	for ((var) = ((head)->stqh_first);				\
		(var) && ((next) = ((var)->field.stqe_next), 1);	\
		(var) = (next))
#endif /* STAILQ_FOREACH_SAFE */

#if !defined(STAILQ_LAST)
#define STAILQ_LAST(head, type, field)				\
	(STAILQ_EMPTY((head)) ? NULL :				\
	((struct type *)(void *)((char *)((head)->stqh_last) -	\
	__offsetof(struct type, field))))
#endif /* STAILQ_LAST */

#if !defined(__offsetof)
#include <stddef.h> /* Needed for offsetof definiton. */
#define __offsetof(type, member)	(offsetof(type, member))
#endif /* __offsetof */

#if !defined(container_of)
#define container_of(ptr, type, member)					\
	({								\
		const typeof(((type *)0)->member) *__mptr = (ptr);	\
		(type *)((char *)__mptr - offsetof(type, member));	\
	})
#endif /* container_of */

/*
 * Calculates if a point in time is before than the other point, which are
 * obtained by CLOCK_MONOTONIC.
 */
#if !defined(TIME_BEFORE)
#define TIME_BEFORE(a, b)		\
	((a)->tv_sec < (b)->tv_sec ||	\
	(((a)->tv_sec == (b)->tv_sec) && ((a)->tv_nsec < (b)->tv_nsec)))
#endif /* TIME_BEFORE */

/*
 * Calculates the time diff between two points in time obtained from
 * CLOCK_MONOTONIC.
 */
#if !defined(TIMEDIFF)
#define TIMEDIFF(_r, _beg, _end)					\
	do {								\
		_r.tv_sec = (_end.tv_sec - _beg.tv_sec);		\
		_r.tv_nsec = _end.tv_nsec - _beg.tv_nsec;		\
		if (_r.tv_nsec < 0) {					\
			_r.tv_nsec += 1000000000;			\
			_r.tv_sec--;					\
		}							\
	} while (0)
#endif /* TIMEDIFF */

#define ACU_EVLOOP_READ			(1 << 0)
#define ACU_EVLOOP_WRITE		(1 << 1)
#define ACU_EVLOOP_EDGE_TRIGGER		(1 << 2)
#define ACU_EVLOOP_BLOCKING		(1 << 3)

#define ACU_EVLOOP_EVENT_MASK		(ACU_EVLOOP_READ | ACU_EVLOOP_WRITE)

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
/**
 * @brief Enumeration describing the different error codes returned by functions.
 */
typedef enum {
    ACU_OK = 0,     /**< success */
    ACU_EFAIL,      /**< failure */
    ACU_ENOMEM,     /**< out of memory */
    ACU_EINVAL,     /**< invalid arguments */
    ACU_ENOENT      /**< not found */
} acu_retcode_t;


/**
 * @brief Structure representing a MAC address.
 *
 */
#define HAVE_MAC_ADDR
typedef unsigned char mac_addr[6];


/**
 * @brief Structure representing an OUI.
 *
 */
typedef uint8_t mac_addr_oui[3];


/**
 * @brief Structure representing an OUI36
 *
 */
typedef uint8_t mac_addr_oui36[5];


/**
 * @brief Structure representing an MAC range
 *
 */
typedef struct {
    mac_addr from;
    mac_addr to;
} mac_addr_range;


/**
 * @brief representation of a MAC address as a string
 */
#define HAVE_MAC_ADDR_STR
typedef char mac_addr_str[18];

/**
 * @brief representation of a MAC address OUI as a string
 */
typedef char mac_addr_oui_str[9];

typedef struct acu_evloop_timer_s acu_evloop_timer_t;
typedef struct acu_evloop_fd_s acu_evloop_fd_t;

typedef void (*acu_evloop_timer_cb_t)(void *userdata);
typedef void (*acu_evloop_fd_cb_t)(int fd, void *userdata);

/*#######################################################################
#                       INLINE FUNCTIONS                                #
########################################################################*/
struct udelay_params {
	unsigned long usecs; /* in */
	struct timespec ts_beg;
	struct timespec ts_end;
	int cycle;
	unsigned long past;
};

static inline void udelay(struct udelay_params *params)
{
	struct timespec ts_diff;

	clock_gettime(CLOCK_MONOTONIC, &params->ts_beg);
	do {
		clock_gettime(CLOCK_MONOTONIC, &params->ts_end);
		TIMEDIFF(ts_diff, params->ts_beg, params->ts_end);
		if (ts_diff.tv_sec > 0)
			break;
		params->past = NSEC_TO_USEC((unsigned long)ts_diff.tv_nsec);
		params->cycle++;
	} while (params->past <= params->usecs);
}

static inline unsigned time_diff_in_sec(struct timespec ts_beg,
		struct timespec ts_end)
{
	struct timespec diff;

	TIMEDIFF(diff, ts_beg, ts_end);
	return (unsigned)diff.tv_sec;
}

static inline int acu_strncmp(const char *src, const char *dst, int slen)
{
	int i;

	if (slen == 0)
		return -1;
	i = 0;
	do {
		if (src[i] == dst[i])
			continue;
		if (src[i] < dst[i])
			return -1;
		if (src[i] > dst[i])
			return 1;
	} while (++i < slen);
	if (dst[i] == '\0')
		return 0;
	return -1;
}

static inline int acu_ethaddrcmp(const uint8_t *a, const uint8_t *b)
{
	const uint16_t *a2 = (const uint16_t *)a;
	const uint16_t *b2 = (const uint16_t *)b;

	return !!((a2[0] ^ b2[0]) | (a2[1] ^ b2[1]) | (a2[2] ^ b2[2]));
}

/*#######################################################################
#                       MAC ADDRESSES                                   #
########################################################################*/
extern const mac_addr acu_zero_mac;
extern const mac_addr acu_broadcast_mac;

#define acu_maccpy(a, b) memcpy(a, b, sizeof(mac_addr))
#define acu_maccmp(a, b) memcmp(a, b, sizeof(mac_addr))

acu_retcode_t acu_mac_from_string(const char *macstr, mac_addr mac);

acu_retcode_t acu_mac_to_string(const mac_addr mac, mac_addr_str macstr);

acu_retcode_t acu_oui_from_string(const char *ouistr, mac_addr_oui oui);

acu_retcode_t acu_oui_to_string(const mac_addr_oui oui, mac_addr_oui_str ouistr);

char *acu_mac_string(const mac_addr mac);

int acu_mac_hash(const mac_addr mac, int buckets);

void acu_sort_mac_array(mac_addr *macs, size_t macs_nr);

bool acu_mac_in_array(mac_addr mac, mac_addr *macs, size_t macs_nr);

bool acu_mac_in_sorted_array(mac_addr mac, mac_addr *macs, size_t macs_nr);

bool acu_mac_array_equal(mac_addr *macs1, size_t macs_nr1, mac_addr *macs2, size_t macs_nr2);

/*#######################################################################
#                       STRING OPERATIONS                               #
########################################################################*/
acu_retcode_t acu_hex_string_to_buf(const char *const hex, uint8_t *const buf, size_t length);

size_t acu_strlcpy(char *dst, const char *src, size_t max_len);

/*#######################################################################
#                       TIME & TIMESTAMP                                #
########################################################################*/
uint64_t acu_get_timestamp_sec(void);

uint64_t acu_get_timestamp_msec(void);

uint64_t acu_get_timestamp_usec(void);

uint64_t acu_get_timestamp_nsec(void);

uint64_t acu_timestamp_delta_sec(uint64_t previous);

uint64_t acu_timestamp_delta_msec(uint64_t previous);

uint64_t acu_timestamp_delta_usec(uint64_t previous);

uint64_t acu_timestamp_delta_nsec(uint64_t previous);

uint64_t acu_get_epoch_sec(void);

uint64_t acu_get_epoch_msec(void);

extern void acu_evloop_timer_delete(acu_evloop_timer_t *evloop_timer);
extern acu_evloop_timer_t *acu_evloop_timer_add(uint32_t expire_ms,
		uint32_t period_ms, acu_evloop_timer_cb_t cb, void *userdata);

acu_retcode_t acu_evloop_timer_restart(acu_evloop_timer_t *evloop_timer);
acu_retcode_t acu_evloop_timer_change_period(acu_evloop_timer_t *evloop_timer,
		uint32_t period_ms);

acu_retcode_t acu_evloop_timer_remaining(acu_evloop_timer_t *evloop_timer,
		uint32_t *remaining);

extern void acu_evloop_fd_delete(acu_evloop_fd_t *evloop_fd);
extern acu_evloop_fd_t *acu_evloop_fd_add_ex(int fd, unsigned flags,
		acu_evloop_fd_cb_t cb, void *userdata);

static inline acu_evloop_fd_t *acu_evloop_fd_add(int fd,
		acu_evloop_fd_cb_t cb, void *userdata)
{
	return acu_evloop_fd_add_ex(fd, ACU_EVLOOP_READ, cb, userdata);
}

extern int acu_evloop_run(void);
extern void acu_evloop_end(void);
extern void acu_evloop_fini(void);
extern int acu_evloop_init(void);

#endif /* __ACU_UTILS_H__ */
