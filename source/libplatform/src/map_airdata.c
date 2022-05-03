/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/un.h>

#define LOG_TAG "airdata"

#include "map_airdata.h"
#include "map_utils.h"

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
typedef struct {
    unsigned int  module_type;
    unsigned int  ctl_type;
    const char   *old_val;
    const char   *new_val;
    unsigned int  idx_cnt;
    unsigned int *idxes;
} notify_msg_t;

typedef struct {
    airdata_notify_cb_t *cb;
    void                *userdata;
} notify_cb_elem;

typedef enum {
    IDX_CTRL = 0,
    IDX_LED,
    IDX_MAX,
} notify_cb_elem_idx;

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static const char             *g_airdata_id = "multiap-controller";
#if 0
static DataNotifyFDCallback_f  g_airdata_notify_fd_cb;
static void                   *g_notify_userdata;
static map_fd_t               *g_notify_fd;
#endif
static notify_cb_elem          g_notify_cb_list[IDX_MAX] = {{0}};

#if 0
/*#######################################################################
#                       NOTIFY CALLBACK                                 #
########################################################################*/
static void call_notify_cb(unsigned int module_type, unsigned int ctl_type,
                            const char *old_val, const char *new_val,
                            unsigned int idx_cnt, unsigned int *idxes)
{
    char *ctl_name = NULL;

    /* Get name for logging... */
    DataCtlNameGet(ctl_type, &ctl_name);
    if (module_type == ModuleMultiAPController ||
        module_type == ModuleWiFiMultiAP) {
        g_notify_cb_list[IDX_CTRL].cb(module_type, ctl_type, ctl_name ? ctl_name : "unknown",
                    old_val, new_val, idx_cnt, idxes, g_notify_userdata);
    } else if (ctl_type == CtlIODarkMode) {
        g_notify_cb_list[IDX_LED].cb(module_type, ctl_type, ctl_name ? ctl_name : "unknown",
                    old_val, new_val, idx_cnt, idxes, g_notify_userdata);

    }
    free(ctl_name);
}

static int airdata_notify_cb(UNUSED void *arg, char *format, ...)
{
    unsigned int  module_type = UINT_MAX;
    unsigned int  ctl_type    = UINT_MAX;
    char         *old_val     = NULL;
    char         *new_val     = NULL;
    unsigned int index_count = INT_MAX;
    unsigned int *index = NULL;
    va_list       args;
    int i;

    for (i = 0; i < IDX_MAX; i++) {
        if (g_notify_cb_list[i].cb)
            break;
    }
    if (i == IDX_MAX) {
        return 0;
    }

    va_start(args, format);

    while (*format) {
        switch (*format) {
            case 'm':
                module_type = va_arg(args, unsigned int);
                break;
            case 'c':
                ctl_type = va_arg(args, unsigned int);
                break;
            case 'i':
                index_count = va_arg(args, unsigned int);
                index = va_arg(args, unsigned int *);
                break;
            case 'o':
                old_val = va_arg(args, char *);
                break;
            case 'n':
                new_val = va_arg(args, char *);
                break;
            default:
                va_arg(args, unsigned int);
                break;
        }
        format++;
    }
    va_end(args);

    if (!g_notify_cb_list[IDX_CTRL].cb) {
        return 0;
    }
    /* Filter out following 2 modules */
    if (module_type == ModuleMultiAPController ||
        module_type == ModuleWiFiMultiAP) {
        if (ctl_type != UINT_MAX && old_val && new_val) {
            call_notify_cb(module_type, ctl_type, old_val, new_val, index_count, index);
        }
    }

    if (g_notify_cb_list[IDX_LED].cb && ctl_type != UINT_MAX && old_val && new_val && ctl_type == CtlIODarkMode) {
        call_notify_cb(module_type, ctl_type, old_val, new_val, index_count, index);
    }

    return 0;
}

static void airdata_notify_fd_cb(UNUSED int fd, UNUSED void *userdata)
{
    g_airdata_notify_fd_cb();
}
#endif

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
const char *map_airdata_get_id(void)
{
    return g_airdata_id;
}

int map_airdata_register_notify_cb_led(airdata_notify_cb_t *cb, void *userdata)
{
    g_notify_cb_list[IDX_LED].cb = cb;
    g_notify_cb_list[IDX_LED].userdata = userdata;

    return 0;
}

int map_airdata_register_notify_cb(airdata_notify_cb_t *cb, void *userdata)
{
    g_notify_cb_list[IDX_CTRL].cb = cb;
    g_notify_cb_list[IDX_CTRL].userdata = userdata;

    return 0;
}

int map_airdata_acbus_getval(const char *key, void *keyval)
{
    if (strcmp(key, "Device.X_AIRTIES_Obj.Bus.Instances") == 0) {
        *(char **)keyval = strdup("(Local:AirBus.1),(Northbound:MQTT.2)");
    } else if (strcmp(key, "Device.X_AIRTIES_Obj.Bus.AirBusNumberOfEntries") == 0) {
        *(int *)keyval = 1;
    } else if (strcmp(key, "Device.X_AIRTIES_Obj.Bus.AirBus.1.ClientIdentifiers") == 0) {
        *(char **)keyval = strdup("");
    } else if (strcmp(key, "Device.X_AIRTIES_Obj.Bus.AirBus.1.Topicmaps") == 0) {
        *(char **)keyval = strdup("");
    } else {
        return -1;
    }

    return 0;
}

int map_airdata_acbus_setval(const char *key, void *keyval)
{
    (void) keyval;
    return 0;
}

int map_airdata_init(char *lib_path)
{
    (void) lib_path;
#if 0
    int fd;

    if (DataApiInit(lib_path)) {
        log_lib_e("DataApiInit failed");
        goto fail;
    }
    if (DataCommRelease()) {
        log_lib_e("DataCommRelease failed");
        goto fail;
    }
    if (DataCommInit(g_airdata_id)) {
        log_lib_e("DataCommInit failed");
        goto fail;
    }
    /* Add 'b' to reduce cpu load (no alias list) */
    if (DataNotifyInit(NULL, "ca1fb", airdata_notify_cb, NULL, &fd, &g_airdata_notify_fd_cb)) {
        log_lib_e("DataCommInit failed");
        goto fail;
    }
    if (NULL == (g_notify_fd = map_fd_add(fd, airdata_notify_fd_cb, NULL))) {
        log_lib_e("create notify fd");
        goto fail;
    }

    return 0;

fail:
    return -1;
#else
    return 0;
#endif
}

void map_airdata_fini(void)
{
#if 0
    if (g_notify_fd) {
        map_fd_delete(g_notify_fd);
    }
    if (DataNotifyRelease(NULL)) {
        log_lib_e("DataNotifyRelease failed");
    }
    if (DataCommRelease()) {
        log_lib_e("DataCommRelease failed");
    }
    if (DataApiRelease()) {
        log_lib_e("DataApiRelease failed");
    }
#endif
}
