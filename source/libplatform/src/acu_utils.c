/*
 * Copyright (c) 2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libubox/uloop.h>

#include "acu_utils.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#ifdef CLOCK_BOOTTIME
#define TIMESTAMP_CLOCK_TYPE CLOCK_BOOTTIME
#else
#define TIMESTAMP_CLOCK_TYPE CLOCK_MONOTONIC
#endif

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
const mac_addr acu_zero_mac = { 0, 0, 0, 0, 0, 0 };
const mac_addr acu_broadcast_mac = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/*#######################################################################
#                       MAC ADDRESSES                                   #
########################################################################*/
static int mac_addr_compare(const void *a, const void *b)
{
    return acu_maccmp(a, b);
}

static int hex_to_int(char a)
{
    if (a >= '0' && a <= '9') {
        return a - '0';
    } else if (a >= 'a' && a <= 'f') {
        return a - 'a' + 10;
    } else if (a >= 'A' && a <= 'F') {
        return a - 'A' + 10;
    }
    return -1;
}

/* Mac from/to string is used very often
   -> use optimized version in stead of sscanf/sprintf
*/

/* Convert aa:bb:.. to uint8_t array */
static acu_retcode_t mac_from_string(const char *s, uint8_t *m, size_t l)
{
    size_t i, p = 0;

    if (!s || !m) {
        return ACU_EINVAL;
    }

    for (i = 0; i < l; i++) {
        int a, b, c = (i < (l - 1)) ? ':' : '\0';

        if ((a = hex_to_int(s[p])) < 0 || (b = hex_to_int(s[p + 1])) < 0 || s[p + 2] != c) {
            return ACU_EINVAL;
        }

        m[i] = (a << 4) | b;
        p += 3;
    }

    return ACU_OK;
}

/* Convert uint8_t array to aa:bb:... */
static acu_retcode_t mac_to_string(const uint8_t *m, char *s, size_t l)
{
    static char hex[]={'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
    size_t i, p = 0;

    if (!m || !s) {
        return ACU_EINVAL;
    }

    for (i = 0; i < l; i++) {
        s[p++] = hex[(m[i] >> 4) & 0x0f];
        s[p++] = hex[m[i] & 0x0f];
        s[p++] = (i < (l - 1)) ? ':' : '\0';
    }

    return ACU_OK;
}

acu_retcode_t acu_mac_from_string(const char *macstr, mac_addr mac)
{
    return mac_from_string(macstr, mac, sizeof(mac_addr));
}

acu_retcode_t acu_mac_to_string(const mac_addr mac, mac_addr_str macstr)
{
    return mac_to_string(mac, macstr, sizeof(mac_addr));
}

acu_retcode_t acu_oui_from_string(const char *ouistr, mac_addr_oui oui)
{
    return mac_from_string(ouistr, oui, sizeof(mac_addr_oui));
}

acu_retcode_t acu_oui_to_string(const mac_addr_oui oui, mac_addr_oui_str ouistr)
{
    return mac_to_string(oui, ouistr, sizeof(mac_addr_oui));
}

char *acu_mac_string(const mac_addr mac)
{
    static char macstr[18];

    acu_mac_to_string(mac, macstr);
    return macstr;
}

int acu_mac_hash(const mac_addr mac, int buckets)
{
    unsigned long h = 0, high;
    int i;

    for (i = 0; i < 6; i++) {
        h = (h << 4) + mac[i];
        if ((high = h & 0xF0000000) != 0) {
            h ^= high >> 24;
        }
        h &= ~high;
    }
    return h % buckets;
}

void acu_sort_mac_array(mac_addr *macs, size_t macs_nr)
{
    qsort(macs, macs_nr, sizeof(mac_addr), mac_addr_compare);
}

bool acu_mac_in_array(mac_addr mac, mac_addr *macs, size_t macs_nr)
{
    size_t i;

    for (i = 0; i < macs_nr; i++) {
        if (!acu_maccmp(mac, macs[i])) {
            return true;
        }
    }

    return false;
}

bool acu_mac_in_sorted_array(mac_addr mac, mac_addr *macs, size_t macs_nr)
{
    return (macs_nr > 0) && bsearch(mac, macs, macs_nr, sizeof(mac_addr), mac_addr_compare);
}

bool acu_mac_array_equal(mac_addr *macs1, size_t macs_nr1, mac_addr *macs2, size_t macs_nr2)
{
    return (macs_nr1 == macs_nr2) && !memcmp(macs1, macs2, macs_nr1 * sizeof(mac_addr));
}

/*#######################################################################
#                       STRING OPERATIONS                               #
########################################################################*/
static int hex_to_byte(const char *hexadecimal)
{
    int num1, num2, val;

    num1 = hex_to_int(*hexadecimal);
    ++hexadecimal;
    num2 = hex_to_int(*hexadecimal);
    ++hexadecimal;

    if (num1 < 0 || num2 < 0) {
        return -1;
    }

    val = num2 | (num1 << 4);
    return val;
}

acu_retcode_t acu_hex_string_to_buf(const char *const hex, uint8_t *const buf, size_t length)
{
    acu_retcode_t rc = ACU_EINVAL;
    int num = 0;
    unsigned int i = 0;
    uint8_t *end_pos = buf;
    const char *start_pos = hex;

    if (!hex || !buf) {
        return rc;
    }

    while ((i < length) && (*start_pos != 0) && (*(start_pos + 1) != 0)) {
        num = hex_to_byte(start_pos);
        if (-1 == num) {
            return rc;
        }
        start_pos = start_pos + 2;
        *end_pos = num;
        ++end_pos;
        ++i;
    }

    if ((*start_pos == 0)) {
        rc = ACU_OK;
    }

    return rc;
}

size_t acu_strlcpy(char *dst, const char *src, size_t max_len)
{
    size_t src_len = strlen(src);

    if (src_len + 1 < max_len) {
        memcpy(dst, src, src_len + 1);
    } else if (max_len != 0) {
        memcpy(dst, src, max_len - 1);
        dst[max_len-1] = '\0';
    }

    return src_len;
}

/*#######################################################################
#                       TIME & TIMESTAMP                                #
########################################################################*/
static uint64_t get_time_sec(clockid_t clockid)
{
    struct timespec ts;

    if (0 != clock_gettime(clockid, &ts)) {
        return 0;
    }
    return ts.tv_sec;
}

static uint64_t get_time_msec(clockid_t clockid)
{
    struct timespec ts;

    if (0 != clock_gettime(clockid, &ts)) {
        return 0;
    }
    return SEC_TO_MSEC((uint64_t)ts.tv_sec) + NSEC_TO_MSEC((uint64_t)ts.tv_nsec);
}

static uint64_t get_time_usec(clockid_t clockid)
{
    struct timespec ts;

    if (0 != clock_gettime(clockid, &ts)) {
        return 0;
    }
    return SEC_TO_USEC((uint64_t)ts.tv_sec) + NSEC_TO_USEC((uint64_t)ts.tv_nsec);
}

static uint64_t get_time_nsec(clockid_t clockid)
{
    struct timespec ts;

    if (0 != clock_gettime(clockid, &ts)) {
        return 0;
    }
    return SEC_TO_NSEC((uint64_t)ts.tv_sec) + (uint64_t)ts.tv_nsec;
}

uint64_t acu_get_timestamp_sec(void)
{
    return get_time_sec(TIMESTAMP_CLOCK_TYPE);
}

uint64_t acu_get_timestamp_msec(void)
{
    return get_time_msec(TIMESTAMP_CLOCK_TYPE);
}

uint64_t acu_get_timestamp_usec(void)
{
    return get_time_usec(TIMESTAMP_CLOCK_TYPE);
}

uint64_t acu_get_timestamp_nsec(void)
{
    return get_time_nsec(TIMESTAMP_CLOCK_TYPE);
}

uint64_t acu_timestamp_delta_sec(uint64_t old_ts)
{
    uint64_t new_ts = acu_get_timestamp_sec();

    if (0 == old_ts || 0 == new_ts) {
        return 0;
    }
    return new_ts - old_ts;
}

uint64_t acu_timestamp_delta_msec(uint64_t old_ts)
{
    uint64_t new_ts = acu_get_timestamp_msec();

    if (0 == old_ts || 0 == new_ts) {
        return 0;
    }
    return new_ts - old_ts;
}

uint64_t acu_timestamp_delta_usec(uint64_t old_ts)
{
    uint64_t new_ts = acu_get_timestamp_usec();

    if (0 == old_ts || 0 == new_ts) {
        return 0;
    }
    return new_ts - old_ts;
}

uint64_t acu_timestamp_delta_nsec(uint64_t old_ts)
{
    uint64_t new_ts = acu_get_timestamp_nsec();

    if (0 == old_ts || 0 == new_ts) {
        return 0;
    }
    return new_ts - old_ts;
}

uint64_t acu_get_epoch_sec(void)
{
    return get_time_sec(CLOCK_REALTIME);
}

uint64_t acu_get_epoch_msec(void)
{
    return get_time_msec(CLOCK_REALTIME);
}

uint64_t acu_get_epoch_usec(void)
{
    return get_time_usec(CLOCK_REALTIME);
}

uint64_t acu_get_epoch_nsec(void)
{
    return get_time_nsec(CLOCK_REALTIME);
}

/*#######################################################################
#                       EVLOOP                                          #
########################################################################*/

struct acu_evloop_fd_s {
	struct uloop_fd     u_fd;
	acu_evloop_fd_cb_t  cb;
	void               *userdata;
};

struct acu_evloop_timer_s {
	struct uloop_timeout   u_timeout;
	uint32_t               period_ms;
	acu_evloop_timer_cb_t  cb;
	void                  *userdata;
	bool                   in_cb;
	bool                   deleted;
};

static void acu_evloop_fd_handler(struct uloop_fd *u_fd,
		UNUSED unsigned int events)
{
	acu_evloop_fd_t *evloop_fd = (acu_evloop_fd_t *)u_fd;

	evloop_fd->cb(evloop_fd->u_fd.fd, evloop_fd->userdata);
}

static void acu_evloop_uloop_timeout_handler(struct uloop_timeout *u_timeout)
{
	acu_evloop_timer_t *evloop_timer = (acu_evloop_timer_t *)u_timeout;

	evloop_timer->in_cb = true;
	evloop_timer->cb(evloop_timer->userdata);
	evloop_timer->in_cb = false;

	if (evloop_timer->deleted || 0 == evloop_timer->period_ms) {
		SFREE(evloop_timer);
		return;
	}
	uloop_timeout_set(&evloop_timer->u_timeout, evloop_timer->period_ms);
}

void acu_evloop_timer_delete(acu_evloop_timer_t *evloop_timer)
{
	if (NULL == evloop_timer)
		return;

	/* Can't free evloop_timer when del is called from timer cb */
	if (evloop_timer->in_cb) {
		evloop_timer->deleted = true;
		return;
	}
	uloop_timeout_cancel(&evloop_timer->u_timeout);
	SFREE(evloop_timer);
}

acu_evloop_timer_t *acu_evloop_timer_add(uint32_t expire_ms, uint32_t period_ms,
		acu_evloop_timer_cb_t cb, void *userdata)
{
	acu_evloop_timer_t *evloop_timer;

	evloop_timer = calloc(1, sizeof(acu_evloop_timer_t));
	if (NULL == evloop_timer)
		return NULL;

	evloop_timer->u_timeout.cb = acu_evloop_uloop_timeout_handler;
	evloop_timer->period_ms    = period_ms;
	evloop_timer->cb           = cb;
	evloop_timer->userdata     = userdata;
	if (uloop_timeout_set(&evloop_timer->u_timeout, expire_ms) < 0) {
		SFREE(evloop_timer);
		evloop_timer = NULL;
	}

	return evloop_timer;
}

acu_retcode_t acu_evloop_timer_restart(acu_evloop_timer_t *evloop_timer)
{
	if (evloop_timer == NULL) {
		return ACU_EINVAL;
	}

	/* Only for periodic timer */
	if (evloop_timer->period_ms == 0) {
		return ACU_EINVAL;
	}

	uloop_timeout_set(&evloop_timer->u_timeout, evloop_timer->period_ms);

	return ACU_OK;
}

acu_retcode_t acu_evloop_timer_change_period(acu_evloop_timer_t *evloop_timer,
		uint32_t period_ms)
{
	int new_timeout = period_ms, remaining;

	if (evloop_timer == NULL) {
		return ACU_EINVAL;
	}

	/* Only for periodic timer */
	if (evloop_timer->period_ms == 0 || period_ms == 0) {
		return ACU_EINVAL;
	}

	/* Subtract running time and limit between 0 and period_ms */
	if ((remaining = uloop_timeout_remaining(&evloop_timer->u_timeout)) >= 0) {
		new_timeout -= ((int)evloop_timer->period_ms - remaining);

		if (new_timeout < 0) {
			new_timeout = 0;
		} else if (new_timeout > (int)period_ms) {
			new_timeout = period_ms;
		}
	}

	evloop_timer->period_ms = period_ms;
	uloop_timeout_set(&evloop_timer->u_timeout, new_timeout);

	return ACU_OK;
}

acu_retcode_t acu_evloop_timer_remaining(acu_evloop_timer_t *evloop_timer,
		uint32_t *remaining)
{
	int r = -1;

	if (evloop_timer) {
		/* Returns -1 when timer is not running */
		r = uloop_timeout_remaining(&evloop_timer->u_timeout);
	}

	*remaining = (r >= 0) ? r : 0;

	return (r >= 0) ? ACU_OK : ACU_EINVAL;
}

void acu_evloop_fd_delete(acu_evloop_fd_t *evloop_fd)
{
	if (NULL != evloop_fd) {
		uloop_fd_delete(&evloop_fd->u_fd);
		SFREE(evloop_fd);
	}
}

acu_evloop_fd_t *acu_evloop_fd_add_ex(int fd, UNUSED unsigned flags,
		acu_evloop_fd_cb_t cb, void *userdata)
{
	acu_evloop_fd_t *evloop_fd = calloc(1, sizeof(acu_evloop_fd_t));

	if (NULL == evloop_fd)
		return NULL;

	evloop_fd->u_fd.fd  = fd;
	evloop_fd->u_fd.cb  = acu_evloop_fd_handler;
	evloop_fd->cb       = cb;
	evloop_fd->userdata = userdata;

	if (uloop_fd_add(&evloop_fd->u_fd, ULOOP_READ) < 0)
		SFREE(evloop_fd);

	return evloop_fd;
}

int acu_evloop_run(void)
{
	return uloop_run();
}

void acu_evloop_end(void)
{
	uloop_end();
}

void acu_evloop_fini(void)
{
	uloop_done();
}

int acu_evloop_init(void)
{
	return uloop_init();
}
