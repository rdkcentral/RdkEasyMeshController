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

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

#define LOG_TAG "config"

#include "collection.h"
#include "cosa_emctl_apis.h"

#include "map_config.h"
#include "map_timer_handler.h"
#include "1905_platform.h"
#include "map_info.h"
#include "map_utils.h"
#include "json-c/json.h"

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
typedef struct {
    map_profile_type_t  type;
    char               *name;
} profile_types_map_t;

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
static map_cfg_t     g_map_cfg;

static map_cfg_cbs_t g_map_cfg_cbs;

/* Credential types mapping, see Device.X_AIRTIES_OBJ.MultiapController.SSIDProfile.{i}.Type */
static profile_types_map_t g_profile_types[] = { {MAP_PROFILE_TYPE_HOME,     "home"    },
                                                 {MAP_PROFILE_TYPE_GUEST,    "guest"   },
                                                 {MAP_PROFILE_TYPE_VIDEO,    "video"   },
                                                 {MAP_PROFILE_TYPE_BACKHAUL, "backhaul"},
                                                 {MAP_PROFILE_TYPE_OTHER,    "other"   } };

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
static int getenv_int(const char *env_str, int def)
{
    char *s = getenv(env_str);
    int   val;

    if (NULL == s) {
        return def;
    }

    return 1 == sscanf(s, "%d", &val) ? val : def;
}

static map_profile_type_t profile_type_from_string(char *s)
{
    size_t i;

    for (i = 0; i<ARRAY_SIZE(g_profile_types); i++) {
        if (!strcasecmp(s, g_profile_types[i].name)) {
            return g_profile_types[i].type;
        }
    }
    return MAP_PROFILE_TYPE_OTHER; /* ?? */
}

static char *profile_type_to_string(map_profile_type_t t)
{
    size_t i;

    for (i = 0; i<ARRAY_SIZE(g_profile_types); i++) {
        if (t == g_profile_types[i].type) {
            return g_profile_types[i].name;
        }
    }
    return "reserved";
}

static bandlock_5g_t bandlock_type_from_string(const char *s)
{
    if (!strcasecmp(s, "low")) {
        return MAP_BANDLOCK_5G_LOW;
    } else if (!strcasecmp(s, "high")) {
        return MAP_BANDLOCK_5G_HIGH;
    } else {
        return MAP_BANDLOCK_5G_DISABLED;
    }
}

static int bandwidth_from_string(const char *s)
{
    if (!strcasecmp(s, "20MHz")) {
        return 20;
    } else if (!strcasecmp(s, "40MHz")) {
        return 40;
    } else if (!strcasecmp(s, "80MHz")) {
        return 80;
    } else if (!strcasecmp(s, "160MHz")) {
        return 160;
    } else {
        return 0; /* Auto */
    }
}

static int convert_log_level(const char *level_str)
{
    /* Log levels are defined in data.xsd type "X_AIRTIES_TypeLogLevel" */
#define NUM_LEVEL 8
    char *strs[NUM_LEVEL]   = {"emerge",   "alert",  "crit",   "error", "warn",      "notice",   "info",   "debug"};
    int   levels[NUM_LEVEL] = {LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG};
    int   i;

    for (i = 0; i<NUM_LEVEL; i++) {
        if (!strcmp(strs[i], level_str)) {
            return levels[i];
        }
    }

    return LOG_ERR;
}

static int comp_interfaces_regex(map_cfg_t *cfg)
{
    if (cfg->interfaces_regex) {
        regfree(cfg->interfaces_regex);
        SFREE(cfg->interfaces_regex);
    }

    if (!(cfg->interfaces_regex = calloc(1, sizeof(regex_t)))) {
        return -1;
    }

    if (regcomp(cfg->interfaces_regex, cfg->interfaces, REG_NOSUB | REG_EXTENDED)) {
        fprintf(stderr, "regcomp failed for regex[%s]\n", cfg->interfaces);
        SFREE(cfg->interfaces_regex);
        return -1;
    }
    return 0;
}

static void dump_profile(map_profile_cfg_t *profile)
{
    log_lib_i("----------------------------------------------");
    if (WFA_CERT()) {
        mac_addr_str mac_str;
        acu_mac_to_string(profile->al_mac, mac_str);
        log_lib_i("|    ALE                 : %s", mac_str);
    }
    log_lib_i("|    Index               : %d",   profile->profile_idx);
    log_lib_i("|    Type                : %s",   profile_type_to_string(profile->type));
    log_lib_i("|    Label               : %s",   profile->label);
    log_lib_i("|    SSID                : %s",   profile->bss_ssid);
    log_lib_i("|    Password            : %s",   profile->wpa_key);
    log_lib_i("|    Authentication mode : %04x", profile->supported_auth_modes);
    log_lib_i("|    Encryption type     : %04x", profile->supported_encryption_types);
    log_lib_i("|    Frequency Bands     : %04x", profile->bss_freq_bands);
    log_lib_i("|    BSS State           : %02x", profile->bss_state);
    log_lib_i("|    Gateway             : %d",   profile->gateway);
    log_lib_i("|    Extender            : %d",   profile->extender);
    log_lib_i("|    VLAN ID             : %d",   profile->vlan_id);
    log_lib_i("----------------------------------------------");
}

static void dump_temp_backhaul_profile(map_controller_cfg_t *cfg)
{
    log_lib_i("----------------------------------------------");
    log_lib_i("| --NEW BACKHAUL PROFILE--");
    log_lib_i("----------------------------------------------");

    dump_profile(&cfg->temp_backhaul_profile);
}

static int list_item_get(char *list, unsigned int idx, char **out)
{
	char *in, *ele, *tok;
	unsigned int i = 0;
	int rc = 0;


	if (!list || !out) {
		goto done;
	}

	*out = NULL;
	in = strdup(list);
	ele = strtok_r(in, ",", &tok);
	for (; ele; i++) {
		if (i == idx) {
		    *out = strdup(ele);
		    break;
		}
		ele = strtok_r(NULL, ",", &tok);
	}

	free(in);

	rc = (*out == NULL);

done:
	return rc;
}

/* Parse channel list.  Can be either:
   - all
   - include list (1,6,11)
   - exclude list (!140,!144)
   - PSC or !NONPSC for 6G band
*/
static int set_chan_list(map_channel_set_t *ch_set, char *list, uint8_t freq_band, bool *ret_psc)
{
    map_channel_set_t ctl_ch_set;
    map_channel_set_t psc_ch_set;
    int idx = 0, ret = 0, channel;
    char *elem = NULL, *p;
    bool exclude = false, psc = false;

    map_cs_unset_all(ch_set);

    /* Get all possible control (20MHz) channels */
    switch(freq_band) {
        case IEEE80211_FREQUENCY_BAND_2_4_GHZ:
            map_get_2G_ctl_channel_set(&ctl_ch_set);
        break;
        case IEEE80211_FREQUENCY_BAND_5_GHZ:
            map_get_5G_ctl_channel_set(&ctl_ch_set);
        break;
        case IEEE80211_FREQUENCY_BAND_6_GHZ:
            map_get_6G_ctl_channel_set(&ctl_ch_set);
        break;
        default:
        break;
    }

    /* Check for "all" */
    if (!strcasecmp(list, "all")) {
        map_cs_copy(ch_set, &ctl_ch_set);
        return 0;
    }

    /* DataListGet return code does not give the difference between
       malloc failure and end of list...
    */
    while (ret == 0 && list_item_get(list, idx, &elem) == 0) {
        /* First element is used to select between include/exclude */
        if ((p = strchr(elem, '!')) && idx == 0) {
            exclude = true;
            map_cs_copy(ch_set, &ctl_ch_set); /* Start with all */
        }

        /* Skip '!' if it was present */
        p = p ? p + 1 : elem;

        /* If 6G, check for PSC first */
        if ((freq_band == IEEE80211_FREQUENCY_BAND_6_GHZ) && ((exclude && !strcasecmp(p, "NONPSC")) || !strcasecmp(p, "PSC"))) {
            psc = true;
            map_get_6G_psc_channel_set(&psc_ch_set);
            if (exclude) {
                map_cs_and(ch_set, &psc_ch_set);
            } else {
                map_cs_or(ch_set, &psc_ch_set);
            }
        } else if (sscanf(p, "%d", &channel) == 1) {
            if (exclude) {
                map_cs_unset(ch_set, channel);
            } else if (map_cs_is_set(&ctl_ch_set, channel)) {
                map_cs_set(ch_set, channel);
            }
        } else {
            ret = -1;
        }

        SFREE(elem);
        idx++;
    }

    /* Empty list or failure -> default to all */
    if (idx == 0 || map_cs_nr(ch_set) == 0 || ret) {
        /* Default to all */
        map_cs_copy(ch_set, &ctl_ch_set);
    }

    if (ret_psc) {
        *ret_psc = psc;
    }

    return ret;
}

/*#######################################################################
#                       CONFIG LOAD                                     #
########################################################################*/
static void get_iface_security_mode(const char *supported_security_modes, uint16_t *auth_mode,
                                    uint16_t *encryption_mode, UNUSED uint8_t profile_idx)
{
    *auth_mode       = 0;
    *encryption_mode = 0;

    if      (strcmp(supported_security_modes,"none") == 0) {
        *auth_mode |= IEEE80211_AUTH_MODE_OPEN;
    } else if (strcmp(supported_security_modes,"wpa2-psk") == 0) {
        *auth_mode |= IEEE80211_AUTH_MODE_WPA2PSK;
    } else if (strcmp(supported_security_modes,"wpa-wpa2-psk") == 0) {
        *auth_mode |= IEEE80211_AUTH_MODE_WPAPSK | IEEE80211_AUTH_MODE_WPA2PSK;
    } else if (strcmp(supported_security_modes,"wpa3-sae") == 0) {
        *auth_mode |= IEEE80211_AUTH_MODE_SAE;
    } else if (strcmp(supported_security_modes,"wpa2-psk-wpa3-sae") == 0) {
        *auth_mode |= IEEE80211_AUTH_MODE_WPA2PSK | IEEE80211_AUTH_MODE_SAE;
    /* Below options are kept for backward compatibility and will be converted */
    } else if (strcmp(supported_security_modes,"wpa3-psk") == 0) {
        *auth_mode |= IEEE80211_AUTH_MODE_SAE;
    } else if (strcmp(supported_security_modes,"wpa2-wpa3-psk") == 0) {
        *auth_mode |= IEEE80211_AUTH_MODE_WPA2PSK | IEEE80211_AUTH_MODE_SAE;
    }

    if (*auth_mode == 0) {
        log_lib_e("invalid auth mode - WPA2-PSK is applied");
        *auth_mode |= IEEE80211_AUTH_MODE_WPA2PSK;
    }

    if (*auth_mode & IEEE80211_AUTH_MODE_OPEN) {
        *encryption_mode |= IEEE80211_ENCRYPTION_MODE_NONE;
    }

    if (*auth_mode & IEEE80211_AUTH_MODE_WPAPSK) {
        *encryption_mode |= IEEE80211_ENCRYPTION_MODE_TKIP;
    }

    // Other than WEP, OPEN, WPA, WPA-PSK, if any other flags are enabled then enable AES
    if ((*auth_mode & IEEE80211_AUTH_MODE_WPA2)    ||
        (*auth_mode & IEEE80211_AUTH_MODE_WPA2PSK) ||
        (*auth_mode & IEEE80211_AUTH_MODE_SAE)) {
        *encryption_mode |= IEEE80211_ENCRYPTION_MODE_AES;
    }
}

static void get_frequency_bands(char* frequency_bands, uint16_t* bss_freq_bands)
{
    char *save_ptr;
    char *p;

    *bss_freq_bands = 0;

    p = strtok_r(frequency_bands, ", ", &save_ptr);
    while(p) {
        if        (!strcmp(p, "2") || !strcasecmp(p, "2G")) {
            *bss_freq_bands |= MAP_M2_BSS_RADIO2G;
        } else if (!strcmp(p, "5") || !strcasecmp(p, "5G")) {
            *bss_freq_bands |= MAP_M2_BSS_RADIO5GL | MAP_M2_BSS_RADIO5GU;
        } else if (!strcasecmp(p, "5L") || !strcasecmp(p, "5GL")) {
            *bss_freq_bands |= MAP_M2_BSS_RADIO5GL;
        } else if (!strcasecmp(p, "5H") || !strcasecmp(p, "5GH") || !strcasecmp(p, "5U") || !strcasecmp(p, "5GU")) {
            *bss_freq_bands |= MAP_M2_BSS_RADIO5GU;
        } else if (!strcmp(p, "6") || !strcasecmp(p, "6G")) {
            *bss_freq_bands |= MAP_M2_BSS_RADIO6G;
        }
        p = strtok_r(NULL, ", ", &save_ptr);
    }
}

static int profile_load(map_profile_cfg_t *profile, uint8_t index)
{
    bool  enable, fh, bh;
    char *type = NULL;
    char *label = NULL;
    char *ssid = NULL;
    char *freq_bands = NULL;
    char *security_mode = NULL;
    char *key_passphrase = NULL;

    if (profile == NULL) {
        return -1;
    }

    /* Fill in profiles */
    memset(profile, 0, sizeof(map_profile_cfg_t));

#if 0
    DataGet(CtlMultiAPControllerProfileEnable, &enable);                /* NOT mandatory */
#endif
    enable = 1;
    if (!enable) {
        return -1;
    }
    if (CosaEmctlProfileGetBackhaul(index, &bh) != 0) {
        log_lib_e("CosaEmctlProfileGetBackhaul failed");
        return -1;
    }
    if (CosaEmctlProfileGetExtender(index, &profile->extender) != 0) {
        log_lib_e("CosaEmctlProfileGetExtender failed");
        return -1;
    }
    if (CosaEmctlProfileGetFrequencyBands(index, &freq_bands) != 0) {
        log_lib_e("CosaEmctlProfileGetFrequencyBands failed");
        return -1;
    }
    if (CosaEmctlProfileGetFronthaul(index, &fh) != 0) {
        log_lib_e("CosaEmctlProfileGetFronthaul failed");
        return -1;
    }
    if (CosaEmctlProfileGetGateway(index, &profile->gateway) != 0) {
        log_lib_e("CosaEmctlProfileGetGateway failed");
        return -1;
    }
    if (CosaEmctlProfileGetKeypassphrase(index, &key_passphrase) != 0) {
        log_lib_e("CosaEmctlProfileGetKeypassphrase failed");
        return -1;
    }
    if (CosaEmctlProfileGetLabel(index, &label) != 0) {
        log_lib_e("CosaEmctlProfileGetLabel failed");
        return -1;
    }
    if (CosaEmctlProfileGetSecurityMode(index, &security_mode) != 0) {
        log_lib_e("CosaEmctlProfileGetSecurityMode failed");
        return -1;
    }
    if (CosaEmctlProfileGetSSID(index, &ssid) != 0) {
        log_lib_e("CosaEmctlProfileGetSSID failed");
        return -1;
    }
    if (CosaEmctlProfileGetType(index, &type) != 0) {
        log_lib_e("CosaEmctlProfileGetType failed");
        return -1;
    }
    if (CosaEmctlProfileGetVLANID(index, &profile->vlan_id) != 0) {
        log_lib_e("CosaEmctlProfileGetVLANID failed");
        return -1;
    }

    profile->profile_idx = index;
    profile->type = profile_type_from_string(type);
    strncpy(profile->label, label, sizeof(profile->label) - 1);

    strncpy(profile->bss_ssid, ssid, sizeof(profile->bss_ssid) - 1);

    get_frequency_bands(freq_bands, &profile->bss_freq_bands);

    get_iface_security_mode(security_mode, &profile->supported_auth_modes, &profile->supported_encryption_types, index);

    strncpy(profile->wpa_key, key_passphrase, sizeof(profile->wpa_key) -1);

    profile->bss_state |= fh ? MAP_FRONTHAUL_BSS : 0;
    profile->bss_state |= bh ? MAP_BACKHAUL_BSS  : 0;

    SFREE(type);
    SFREE(label);
    SFREE(ssid);
    SFREE(freq_bands);
    SFREE(security_mode);
    SFREE(key_passphrase);

    return 0;
}

static int cfg_load(map_cfg_t *cfg, bool init)
{
    char         *log_level_controller = NULL;
    char         *log_level_platform   = NULL;
    char         *log_level_ieee1905   = NULL;
    char         *log_output           = NULL;
    char         *value                = NULL;
    int           vlan_id;
    unsigned int  pcp;

    /* LOAD ONCE */
    if (init) {
#if 0
        /* TODO: convert to PSM */
        DataGet(CtlMultiAPControllerInterfaceList, &cfg->interfaces);   /* Mandatory */
        DataGet(CtlMultiAPControllerPrimaryVLANID, &vlan_id);           /* NOT mandatory */
        DataGet(CtlMultiAPControllerDefaultPCP, &pcp);                  /* NOT mandatory */
        DataGet(CtlMultiAPControllerPrimaryVLANInterfacePattern, &cfg->primary_vlan_pattern);
        DataGet(CtlDeviceInfoManufacturer, &cfg->manufacturer);         /* NOT mandatory */
        DataGet(CtlDeviceInfoModelName, &cfg->model_name);              /* NOT mandatory */
        DataGet(CtlDeviceInfoModelNumber, &cfg->model_number);          /* NOT mandatory */
        DataGet(CtlDeviceInfoSerialNumber, &cfg->serial_number);        /* NOT mandatory */
        DataGet(CtlStoragePath, &cfg->storage_path);                    /* NOT mandatory ? */
#endif
        cfg->interfaces = strdup("^lo$|^eth.*|^wl.*|^sw_.*|^n[rs]gmii.*");
        vlan_id = -1;
        pcp = 0;
        cfg->primary_vlan_pattern = strdup("${ifname}.${pvid}");
        cfg->manufacturer = strdup("AirTies Wireless Networks");
        cfg->model_name = strdup("");
        cfg->model_number = strdup("UBC1322-edge");
        cfg->serial_number = strdup("");
        cfg->storage_path = strdup("/data");
        comp_interfaces_regex(cfg);

        cfg->primary_vlan_id = vlan_id;
        cfg->default_pcp     = pcp;

        /* TODO: there should also be a platform cleanup that frees these at shutdown... */
    }

    /* LOAD ALWAYS */
#if 0
    /* TODO: convert to PSM */
    DataGet(CtlMultiAPControllerEnable, &cfg->enabled);                             /* Mandatory */
    DataGet(CtlMultiAPControllerIsMaster, &cfg->is_master);                         /* Mandatory ? */
    DataGet(CtlMultiAPControllerWfaCertR1Compatible, &cfg->wfa_cert_r1_compatible); /* NOT mandatory */
#endif
    value = getenv("MAP_CONTROLLER_LOG_LEVEL");
    log_level_controller = (value == NULL) ? strdup("error") : strdup(value);
    value = getenv("MAP_PLATFORM_LOG_LEVEL");
    log_level_platform = (value == NULL) ? strdup("error") : strdup(value);
    value = getenv("MAP_IEEE1905_LOG_LEVEL");
    log_level_ieee1905 = (value == NULL) ? strdup("error") : strdup(value);
    value = getenv("MAP_LOG_OUTPUT");
    log_output = (value == NULL) ? strdup("stderr") : strdup(value);
    cfg->enabled = 1;
    cfg->is_master = 1;
    cfg->wfa_cert_r1_compatible = 0;

    cfg->controller_log_level = convert_log_level(log_level_controller);
    cfg->library_log_level    = convert_log_level(log_level_platform);
    cfg->ieee1905_log_level   = convert_log_level(log_level_ieee1905);
    if (!strcmp(log_output, "file_only")) {
        cfg->log_output       = log_file_only;
    } else if (!strcmp(log_output, "syslog")) {
        cfg->log_output       = log_syslog;
    } else {
        cfg->log_output       = log_stderr;
    }


    SFREE(log_level_controller);
    SFREE(log_level_platform);
    SFREE(log_level_ieee1905);
    SFREE(log_output);

    return 0;
}

static int controller_cfg_load(map_controller_cfg_t *cfg, bool init)
{
    /* TODO: use pointers */
    char          controller_mac_str[18];
    char          local_agent_mac_str[18];
    char          str_value[255];
    int           val;

    /* LOAD ONCE */
    if (init) {
        CosaEmctlGetLocalAgentMACAddress(controller_mac_str);
        if (mac_from_string(controller_mac_str, cfg->al_mac)) {
            log_lib_e("getting controller mac failed");
            goto fail;
        }

        CosaEmctlGetMACAddress(local_agent_mac_str);
        if (mac_from_string(local_agent_mac_str, cfg->local_agent_al_mac)) {
            log_lib_e("getting local agent mac failed");
            goto fail;
        }
    }

    /* LOAD ALWAYS */
    CosaEmctlGetTopologyQueryInterval(&cfg->topology_query_interval);
    CosaEmctlGetLinkMetricsQueryInterval(&cfg->link_metrics_query_interval);
    cfg->ap_capability_query_interval = 60;
    CosaEmctlGetDeadAgentDetectionInterval(&cfg->dead_agent_detection_interval);
    CosaEmctlGetConfigureBackhaulStation(&cfg->configure_backhaul_station);
    CosaEmctlGetConfigRenewInterval(&cfg->config_renew_interval);
    CosaEmctlGetConfigRenewMaxRetry(&cfg->config_renew_max_retry);
    CosaEmctlTopologyStableCheckInterval(&cfg->topology_stable_check_interval);

    CosaEmctlGetAllowedChannelList2G(str_value);
    if (set_chan_list(&cfg->allowed_channel_set_2g, str_value, IEEE80211_FREQUENCY_BAND_2_4_GHZ, NULL)) {
        log_lib_e("failed parsing allowed 2G chan list[%s]", str_value);
    }

    CosaEmctlGetAllowedChannelList5G(str_value);
    if (set_chan_list(&cfg->allowed_channel_set_5g, str_value, IEEE80211_FREQUENCY_BAND_5_GHZ, NULL)) {
        log_lib_e("failed parsing allowed 5G chan list[%s]", str_value);
    }

    CosaEmctlGetAllowedChannelList6G(str_value);
    if (set_chan_list(&cfg->allowed_channel_set_6g, str_value, IEEE80211_FREQUENCY_BAND_6_GHZ, &cfg->allowed_channel_6g_psc)) {
        log_lib_e("failed parsing allowed 6G chan list[%s]", str_value);
    }

    CosaEmctlGetDefault2GPreferredChannelList(str_value);
    if (set_chan_list(&cfg->default_pref_channel_set_2g, str_value, IEEE80211_FREQUENCY_BAND_2_4_GHZ, NULL)) {
        log_lib_e("failed parsing pref 2G chan list[%s]", str_value);
    }

    CosaEmctlGetDefault5GPreferredChannelList(str_value);
    if (set_chan_list(&cfg->default_pref_channel_set_5g, str_value, IEEE80211_FREQUENCY_BAND_5_GHZ, NULL)) {
        log_lib_e("failed parsing pref 5G chan list[%s]", str_value);
    }

    CosaEmctlGetDefault6GPreferredChannelList(str_value);
    if (set_chan_list(&cfg->default_pref_channel_set_6g, str_value, IEEE80211_FREQUENCY_BAND_6_GHZ, NULL)) {
        log_lib_e("failed parsing pref 6G chan list[%s]", str_value);
    }

    CosaEmctlGetAllowedBandwidth2G(str_value);
    cfg->allowed_bandwidth_2g = bandwidth_from_string(str_value);
    CosaEmctlGetAllowedBandwidth5G(str_value);
    cfg->allowed_bandwidth_5g = bandwidth_from_string(str_value);
    CosaEmctlGetAllowedBandwidth6G(str_value);
    cfg->allowed_bandwidth_6g = bandwidth_from_string(str_value);

    CosaEmctlGetBandLock5G(str_value);
    cfg->bandlock_5g = bandlock_type_from_string(str_value);

    /* TODO: convert to cosa */
    cfg->map_profile                 = getenv_int("MAP_CONTROLLER_MULTIAP_PROFILE",               MAP_DEFAULT_MULTIAP_PROFILE);
    cfg->lldp_interval               = getenv_int("AL_ENTITY_LLDP_BRIDGE_DISCOVERY_ENV_INTERVAL", MAP_DEFAULT_LLDP_BRIDGE_DISCOVERY_INTERVAL);
    CosaEmctlGetTopologyDiscoveryInterval(&cfg->topology_discovery_interval);
    cfg->channel_selection_enabled   = getenv_int("MAP_CONTROLLER_CHANNEL_SELECTION_ENABLED",     MAP_DEFAULT_CHANNEL_SELECTION_ENABLED);

    val = getenv_int("MAP_CONTROLLER_FREQ_2_4_GHZ", MAP_DEFAULT_FREQ_2_4_GHZ);
    cfg->supportedfreq[IEEE80211_FREQUENCY_BAND_2_4_GHZ] = val ? IEEE80211_FREQUENCY_BAND_2_4_GHZ : 0;

    val = getenv_int("MAP_CONTROLLER_FREQ_5_GHZ",   MAP_DEFAULT_FREQ_5_GHZ);
    cfg->supportedfreq[IEEE80211_FREQUENCY_BAND_5_GHZ] = val ? IEEE80211_FREQUENCY_BAND_5_GHZ : 0;

    val = getenv_int("MAP_CONTROLLER_FREQ_6_GHZ",  MAP_DEFAULT_FREQ_6_GHZ);
    cfg->supportedfreq[IEEE80211_FREQUENCY_BAND_6_GHZ] = val ? IEEE80211_FREQUENCY_BAND_6_GHZ : 0;

    return 0;

fail:
    return -1;
}

static void cfg_free(map_cfg_t *cfg)
{
    free(cfg->version);
    free(cfg->interfaces);
    free(cfg->primary_vlan_pattern);
    free(cfg->manufacturer);
    free(cfg->model_name);
    free(cfg->model_number);
    free(cfg->serial_number);
    free(cfg->storage_path);

    if (cfg->interfaces_regex) {
        regfree(cfg->interfaces_regex);
        free(cfg->interfaces_regex);
    }

    memset(cfg, 0, sizeof(map_cfg_t));
}

static int config_change_profile_update_cb(queue_t *updates)
{
    update_params_t *update;

    if (g_map_cfg_cbs.profile_update_cb) {
        g_map_cfg_cbs.profile_update_cb();
    }
    update = queue_pop(updates);
    while (update != NULL) {
        CosaEmctlProfileConfigChangeNotification(update);
        free(update->type);
        free(update->value);
        free(update);
        update = queue_pop(updates);
    }

    return 0;
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
int map_cfg_init(void)
{
    if (EmctlRegisterConfigChangeCB(&config_change_profile_update_cb) != 0) {
        fprintf(stderr, "failed to register callback\n");
    }
    return 0;
}

void map_cfg_fini(void)
{
    cfg_free(&g_map_cfg);
}

void map_cfg_set_cbs(map_cfg_cbs_t *cbs)
{
    g_map_cfg_cbs = *cbs;
}

int map_cfg_load(const char* version, bool wfa_cert)
{
    /* This function can be called only once */
    if (g_map_cfg.init_completed) {
        return 0;
    }

    if (cfg_load(&g_map_cfg, true)) {
        return -1;
    }

    if (controller_cfg_load(&g_map_cfg.controller_cfg, true)) {
        return -1;
    }

    g_map_cfg.version = strdup(version);
    g_map_cfg.wfa_cert = wfa_cert;
    g_map_cfg.init_completed = 1;

    return 0;
}

int map_cfg_reload(void)
{
    if (cfg_load(&g_map_cfg, false)) {
        return -1;
    }

    if (controller_cfg_load(&g_map_cfg.controller_cfg, false)) {
        return -1;
    }

    return 0;
}

map_cfg_t *map_cfg_get(void)
{
    return &g_map_cfg;
}

int map_cfg_is_enabled(bool *enabled)
{
    *enabled = 1;

    return 0;
}

int map_cfg_set_master_state(bool master)
{
    if (g_map_cfg_cbs.master_state_cb) {
        g_map_cfg_cbs.master_state_cb(master);
    }

    return 0;
}

int map_profile_load(bool *ret_changed, bool dump_profiles)
{
    map_controller_cfg_t *cfg = &map_cfg_get()->controller_cfg;
    unsigned int          profile_count, i, idx = 0;
    bool                  changed = false;

#if 0
    DataGet(CtlMultiAPControllerProfileNOE);
#endif
    profile_count = 3;
    for (i=0; i<profile_count && idx < MAX_NUM_PROFILES; i++) {
        map_profile_cfg_t profile;

        if (profile_load(&profile, i)) {
            continue;
        }
        if (memcmp(&profile, &cfg->profiles[idx], sizeof(map_profile_cfg_t))) {
            cfg->profiles[idx] = profile;
            /* Backhaul profile change will not trigger config renew here. It will be handled in its own routine */
            if (!(profile.bss_state & MAP_BACKHAUL_BSS)) {
                changed = true;
            }
        }

        idx++;
    }

    if (cfg->num_profiles != idx) {
        cfg->num_profiles = idx;
        changed = true;
    }

    if (ret_changed) {
        *ret_changed = changed;
    }

    if (dump_profiles) {
        map_profile_dump(cfg);
    }

    return 0;
}

int map_backhaul_profile_load(uint8_t backhaul_index)
{
    map_controller_cfg_t *cfg = &map_cfg_get()->controller_cfg;
    map_profile_cfg_t     profile;

    if (profile_load(&profile, backhaul_index)) {
        goto fail;
    }
    cfg->temp_backhaul_profile = profile;

    dump_temp_backhaul_profile(cfg);

    return 0;
fail:
    return -1;
}

void map_profile_clone(map_profile_cfg_t *dst, map_profile_cfg_t *src)
{
    if (dst && src) {
        *dst = *src;
    }
}

void map_profile_dump()
{
    map_controller_cfg_t *cfg = &map_cfg_get()->controller_cfg;
    uint8_t               i;

    log_lib_i("----------------------------------------------");
    log_lib_i("| --MAP PROFILES--");
    log_lib_i("----------------------------------------------");

    for (i = 0; i < cfg->num_profiles; i++) {
        log_lib_i("|  --profile %d--", i);
        dump_profile(&cfg->profiles[i]);
    }
}
