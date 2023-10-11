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

#ifndef MAP_CONFIG_H_
#define MAP_CONFIG_H_

#include <stdint.h>
#include <stdbool.h>
#include <regex.h>
#include "map_common_defines.h"
#include "map_info.h"

#define TS_ENABLED()                (map_cfg_get()->primary_vlan_id >= 0)
#define WFA_CERT()                  (map_cfg_get()->wfa_cert)
#define WFA_CERT_R1_COMPATIBLE()    (map_cfg_get()->wfa_cert_r1_compatible)
#define MONITOR_MODE()              (!map_cfg_get()->is_master)

typedef enum bandlock_5g_e {
    MAP_BANDLOCK_5G_DISABLED,
    MAP_BANDLOCK_5G_LOW,
    MAP_BANDLOCK_5G_HIGH,
} bandlock_5g_t;

/* Config updated callbacks */
typedef void (*map_cfg_enable_cb_t)(bool enable);
typedef void (*map_cfg_master_state_cb_t)(bool is_master);
typedef void (*map_cfg_update_cb_t)(void);
typedef void (*map_cfg_profile_update_cb_t)(void);
typedef void (*map_cfg_backhaul_profile_update_cb_t)(int idx, bool profile_enabled);
typedef void (*map_cfg_allowed_channel_list_update_cb_t)(uint8_t freq_band);
typedef void (*map_cfg_allowed_bandwidth_update_cb_t)(uint8_t freq_band);
typedef void (*map_cfg_bandlock_5g_cb_t)(bandlock_5g_t type);
typedef void (*map_cfg_radio_channel_cb_t)(int ale_idx, int radio_idx, int channel);
typedef void (*map_cfg_radio_bandwidth_cb_t)(int ale_idx, int radio_idx, int bw);

typedef struct {
    map_cfg_enable_cb_t                      enable_cb;
    map_cfg_master_state_cb_t                master_state_cb;
    map_cfg_update_cb_t                      update_cb;
    map_cfg_profile_update_cb_t              profile_update_cb;
    map_cfg_backhaul_profile_update_cb_t     backhaul_profile_update_cb;
    map_cfg_allowed_channel_list_update_cb_t allowed_channel_list_update_cb;
    map_cfg_allowed_bandwidth_update_cb_t    allowed_bandwidth_update_cb;
    map_cfg_bandlock_5g_cb_t                 bandlock_5g_update_cb;
    map_cfg_radio_channel_cb_t               radio_channel_cb;
    map_cfg_radio_bandwidth_cb_t             radio_bandwidth_cb;
} map_cfg_cbs_t;

typedef enum {
    log_syslog,
    log_stderr,
    log_file_only
} map_log_iface_t;

/* Credential type. See Device.X_AIRTIES_OBJ.MultiapController.SSIDProfile.{i}.Type.
   These enum values are used in the M2 message
*/
typedef enum map_profile_type_e {
    MAP_PROFILE_TYPE_HOME     = 0,
    MAP_PROFILE_TYPE_GUEST    = 1,
    MAP_PROFILE_TYPE_VIDEO    = 2,
    MAP_PROFILE_TYPE_BACKHAUL = 3,
    MAP_PROFILE_TYPE_OTHER    = 255
} map_profile_type_t;

typedef struct map_profile_cfg_s {
    int                     profile_idx;
    bool                    enabled;
    uint8_t                 al_mac[MAC_ADDR_LEN];  /* Used in wfa cert to configure cred for a specific ALE */
    map_profile_type_t      type;
    char                    label[MAX_PROFILE_LABEL_LEN];
    char                    bss_ssid[MAX_WIFI_SSID_LEN];
    char                    wpa_key[MAX_WIFI_PASSWORD_LEN];
    uint16_t                supported_auth_modes;
    uint16_t                supported_encryption_types;
    uint16_t                bss_freq_bands;
    uint8_t                 bss_state;
    uint8_t                 gateway;
    uint8_t                 extender;
    int                     vlan_id;  /* -1: untagged */
    bool                    hide;
} map_profile_cfg_t;

typedef struct map_chan_sel_cfg_s {
    map_channel_set_t allowed_channel_set_2g;
    map_channel_set_t allowed_channel_set_5g;
    map_channel_set_t allowed_channel_set_6g;
    map_channel_set_t default_pref_channel_set_2g;
    map_channel_set_t default_pref_channel_set_5g;
    map_channel_set_t default_pref_channel_set_6g;
    uint16_t          allowed_bandwidth_2g;
    uint16_t          allowed_bandwidth_5g;
    uint16_t          allowed_bandwidth_6g;
    bool              allowed_channel_6g_psc;
    bandlock_5g_t     bandlock_5g;
} map_chan_sel_cfg_t;

typedef struct map_controller_cfg_s {
    unsigned int        num_profiles;       /* Number of enabled profiles */
    unsigned int        num_alloc_profiles; /* Number of allocated profiles */
    map_profile_cfg_t  *profiles;
    map_chan_sel_cfg_t  chan_sel;

    unsigned int        supportedfreq[NUM_FREQ_BANDS];

    uint8_t             al_mac[MAC_ADDR_LEN];
    uint8_t             local_agent_al_mac[MAC_ADDR_LEN];

    uint8_t             map_profile;
    unsigned int        lldp_interval;
    unsigned int        topology_discovery_interval;
    unsigned int        topology_query_interval;
    unsigned int        link_metrics_query_interval;
    unsigned int        ap_capability_query_interval;

    bool                channel_selection_enabled;
    unsigned int        dead_agent_detection_interval;
} map_controller_cfg_t;

typedef struct map_cfg_s {
    unsigned int          init_completed;
    char*                 version;
    unsigned int          enabled;
    unsigned int          is_master;
    map_log_iface_t       log_output;
    unsigned int          library_log_level;
    unsigned int          ieee1905_log_level;
    unsigned int          controller_log_level;
    unsigned int          ssp_log_level;
    int                   al_fd;

    char                 *manufacturer;
    char                 *model_name;
    char                 *model_number;
    char                 *serial_number;

    char                 *interfaces;
    regex_t              *interfaces_regex;

    int                   primary_vlan_id; /* -1: untagged */
    int                   vlan_ifname_offset;
    uint8_t               default_pcp;
    char                 *primary_vlan_pattern;

    bool                  wfa_cert; /* Don't do things that interfere with WFA certification */

    bool                  wfa_cert_r1_compatible;

    map_controller_cfg_t  controller_cfg;
} map_cfg_t;


int map_cfg_init(void);

void map_cfg_fini(void);

void map_cfg_set_cbs(map_cfg_cbs_t *cbs);

int map_cfg_load(const char *version, bool wfa_cert);

int map_cfg_reload(void);

map_cfg_t *map_cfg_get(void);

map_controller_cfg_t *map_controller_cfg_get(void);

int map_cfg_is_enabled(bool *enabled);

int map_cfg_set_master_state(bool master);

int map_profile_realloc(unsigned int num_alloc_profiles);

int map_profile_load(bool *changed, bool dump_profiles);

int map_profile_add(map_profile_cfg_t *profile);

int map_profile_remove(map_profile_cfg_t *profile);

int map_profile_get_by_sidx(unsigned int ssid_idx, map_profile_cfg_t **profile);

int map_profile_save(map_profile_cfg_t *profile);

int map_profile_update(void);

void map_profile_clone(map_profile_cfg_t *dst, map_profile_cfg_t *src);

void map_profile_dump();

#endif /* MAP_CONFIG_H */
