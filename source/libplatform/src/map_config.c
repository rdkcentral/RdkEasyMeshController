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
#                       INCLUDES                                        #
########################################################################*/
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

#include <ccsp_message_bus.h>
#include <ccsp_base_api.h>
#include <ccsp_psm_helper.h>

#define LOG_TAG "config"

#include "map_config.h"
#include "map_timer_handler.h"
#include "1905_platform.h"
#include "map_info.h"
#include "map_utils.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define MAP_PSM_PREFIX          "eRT.com.cisco.spvtg.ccsp."
#define MAP_PSM_EMCTL_PREFIX    MAP_PSM_PREFIX "emctl."
#define MAP_PSM_TOPQINT         MAP_PSM_EMCTL_PREFIX "TopologyQueryInterval"
#define MAP_PSM_LMQINT          MAP_PSM_EMCTL_PREFIX "LinkMetricsQueryInterval"
#define MAP_PSM_APCAPQINT       MAP_PSM_EMCTL_PREFIX "APCapabilityQueryInterval"
#define MAP_PSM_DEADAGENTINT    MAP_PSM_EMCTL_PREFIX "DeadAgentDetectionInterval"
#define MAP_PSM_SSIDNOE         MAP_PSM_EMCTL_PREFIX "SSIDNoE"
#define MAP_PSM_CHSL_PREFIX     MAP_PSM_EMCTL_PREFIX "chansel."
#define MAP_PSM_ALLOWEDCL2G     MAP_PSM_CHSL_PREFIX "AllowedChannelList2G"
#define MAP_PSM_ALLOWEDCL5G     MAP_PSM_CHSL_PREFIX "AllowedChannelList5G"
#define MAP_PSM_ALLOWEDCL6G     MAP_PSM_CHSL_PREFIX "AllowedChannelList6G"
#define MAP_PSM_PREFERREDCL2G   MAP_PSM_CHSL_PREFIX "Default2GPreferredChannelList"
#define MAP_PSM_PREFERREDCL5G   MAP_PSM_CHSL_PREFIX "Default5GPreferredChannelList"
#define MAP_PSM_PREFERREDCL6G   MAP_PSM_CHSL_PREFIX "Default6GPreferredChannelList"
#define MAP_PSM_ALLOWEDBW2G     MAP_PSM_CHSL_PREFIX "AllowedBandwidth2G"
#define MAP_PSM_ALLOWEDBW5G     MAP_PSM_CHSL_PREFIX "AllowedBandwidth5G"
#define MAP_PSM_ALLOWEDBW6G     MAP_PSM_CHSL_PREFIX "AllowedBandwidth6G"
#define MAP_PSM_BANDLOCK5G      MAP_PSM_CHSL_PREFIX "BandLock5G"
#define MAP_PSM_SSID_PREFIX     MAP_PSM_EMCTL_PREFIX "ssid.%d."

#define DM_DI_MANUFACTURER      "Device.DeviceInfo.Manufacturer"
#define DM_DI_MODELNAME         "Device.DeviceInfo.ModelName"
#define DM_DI_PRODUCTCLASS      "Device.DeviceInfo.ProductClass"
#define DM_DI_SERIALNUMBER      "Device.DeviceInfo.SerialNumber"

#define MAP_DEF_MANUFACTURER    "Airties"
#define MAP_DEF_MODEL_NAME      "Air4980R"
#define MAP_DEF_MODEL_NUMBER    "US"
#define MAP_DEF_SERIAL_NUMBER   "AX0000111122223"

/*#######################################################################
#                       TYPEDEFS                                        #
########################################################################*/
typedef struct {
    map_profile_type_t  type;
    char               *name;
} profile_types_map_t;

typedef struct profile_ssid_map_s {
    unsigned int        ssid_idx;
    int                 profile_idx;
    map_profile_type_t  type;
    char                label[65];
    uint8_t             bss_state;
} profile_ssid_map_t;

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
extern ANSC_HANDLE   bus_handle;
extern char          g_Subsystem[32];

static map_cfg_t     g_map_cfg;
static map_cfg_cbs_t g_map_cfg_cbs;

static profile_types_map_t g_profile_types[] = {
    {MAP_PROFILE_TYPE_HOME,     "home"    },
    {MAP_PROFILE_TYPE_GUEST,    "guest"   },
    {MAP_PROFILE_TYPE_VIDEO,    "video"   },
    {MAP_PROFILE_TYPE_BACKHAUL, "backhaul"},
    {MAP_PROFILE_TYPE_OTHER,    "other"   }
};

static map_profile_cfg_t g_default_profiles[] = {
    {
        .profile_idx                = 1,
        .enabled                    = true,
        .type                       = MAP_PROFILE_TYPE_HOME,
        .label                      = "Family",
        .bss_ssid                   = "RdkHome",
        .wpa_key                    = "rdk@1234",
        .supported_auth_modes       = IEEE80211_AUTH_MODE_WPA2PSK,
        .supported_encryption_types = IEEE80211_ENCRYPTION_MODE_AES,
        .bss_freq_bands             = MAP_FREQ_BANDS_ALL,
        .bss_state                  = MAP_FRONTHAUL_BSS,
        .gateway                    = true,
        .extender                   = true,
        .hide                       = false,
        .vlan_id                    = -1
    },
    {
        .profile_idx                = 2,
        .enabled                    = true,
        .type                       = MAP_PROFILE_TYPE_GUEST,
        .label                      = "Guest",
        .bss_ssid                   = "RdkGuest",
        .wpa_key                    = "rdk@1234",
        .supported_auth_modes       = IEEE80211_AUTH_MODE_WPA2PSK,
        .supported_encryption_types = IEEE80211_ENCRYPTION_MODE_AES,
        .bss_freq_bands             = MAP_FREQ_BANDS_ALL,
        .bss_state                  = MAP_FRONTHAUL_BSS,
        .gateway                    = true,
        .extender                   = true,
        .hide                       = false,
        .vlan_id                    = -1
    },
    {
        .profile_idx                = 3,
        .enabled                    = true,
        .type                       = MAP_PROFILE_TYPE_BACKHAUL,
        .label                      = "Backhaul",
        .bss_ssid                   = "RdkBH",
        .wpa_key                    = "rdk@1234",
        .supported_auth_modes       = IEEE80211_AUTH_MODE_WPA2PSK,
        .supported_encryption_types = IEEE80211_ENCRYPTION_MODE_AES,
        .bss_freq_bands             = MAP_FREQ_BAND_5G,
        .bss_state                  = MAP_BACKHAUL_BSS,
        .gateway                    = true,
        .extender                   = true,
        .hide                       = true,
        .vlan_id                    = -1
    }
};

static profile_ssid_map_t g_dynamic_mapping[8] = { 0 };

static profile_ssid_map_t g_static_mapping[8] = {
    {
        .profile_idx    = 1,
        .ssid_idx       = 1,
        .type           = MAP_PROFILE_TYPE_HOME,
        .label          = "Home",
        .bss_state      = MAP_FRONTHAUL_BSS
    },
    {
        .profile_idx    = 2,
        .ssid_idx       = 2,
        .type           = MAP_PROFILE_TYPE_HOME,
        .label          = "Home",
        .bss_state      = MAP_FRONTHAUL_BSS
    },
    {
        .profile_idx    = 3,
        .ssid_idx       = 3,
        .type           = MAP_PROFILE_TYPE_GUEST,
        .label          = "Guest",
        .bss_state      = MAP_FRONTHAUL_BSS
    },
    {
        .profile_idx    = 4,
        .ssid_idx       = 4,
        .type           = MAP_PROFILE_TYPE_GUEST,
        .label          = "Guest",
        .bss_state      = MAP_FRONTHAUL_BSS
    },
    {
        .profile_idx    = 5,
        .ssid_idx       = 6,
        .type           = MAP_PROFILE_TYPE_BACKHAUL,
        .label          = "Backhaul",
        .bss_state      = MAP_BACKHAUL_BSS
    }
};

static bool g_sync_with_wifi      = true;
static bool g_use_dynamic_mapping = true;

/*#######################################################################
#                       DATA FUNCTIONS                                  #
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

static int getpsm_val(const char *name, char *buf, size_t len)
{
    int   rc;
    char *value  = NULL;

    if ((name == NULL) || (buf == NULL)) {
        log_lib_e("Invalid parameters");
        return -1;
    }

    rc = PSM_Get_Record_Value2(bus_handle, g_Subsystem, name, NULL, &value);
    if (rc != CCSP_SUCCESS) {
        memset(buf, 0, len);
        log_lib_e("Get record[%s] value failed", name);
        return -1;
    }

    snprintf(buf, len, "%s", value);
    ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(value);

    return 0;
}

static int setpsm_val(const char *name, const char *value)
{
    int rc;

    if ((name == NULL) || (value == NULL)) {
        log_lib_e("Invalid parameters");
        return -1;
    }

    rc = PSM_Set_Record_Value2(bus_handle, g_Subsystem, name, ccsp_string, value);
    if (rc != CCSP_SUCCESS) {
        log_lib_e("Set record value failed");
        return -1;
    }

    return 0;
}

static int getpsm_int(const char *name, int def)
{
    int  rc;
    char value[24];

    rc = getpsm_val(name, value, sizeof(value));
    if (rc != 0) {
        snprintf(value, sizeof(value), "%d", def);
        setpsm_val(name, value);
        return def;
    }

    return atoi(value);
}

static int setpsm_int(const char *name, int value)
{
    char buf[24];

    snprintf(buf, sizeof(buf), "%d", value);

    return setpsm_val(name, buf);
}

static int getpsm_ssid(const char *name, int index, char **value)
{
    int  rc;
    char buf[64];
    char rname[128];

    if (value == NULL) {
        return -1;
    }

    *value = NULL;
    snprintf(rname, sizeof(rname), MAP_PSM_SSID_PREFIX "%s", index, name);
    rc = getpsm_val(rname, buf, sizeof(buf));
    if (rc != 0) {
        return -1;
    }

    *value = strdup(buf);

    return 0;
}

static int setpsm_ssid(const char *name, int index, const char *value)
{
    char rname[128];

    snprintf(rname, sizeof(rname), MAP_PSM_SSID_PREFIX "%s", index, name);

    return setpsm_val(rname, value);
}

static int rmpsm_ssid(const char *name, int index)
{
    int  rc;
    char rname[128];

    snprintf(rname, sizeof(rname), MAP_PSM_SSID_PREFIX "%s", index, name);

    rc = PSM_Del_Record(bus_handle, g_Subsystem, name);
    if (rc != CCSP_SUCCESS) {
        log_lib_e("Remove record failed");
        return -1;
    }

    return 0;
}

static int getpsm_ssid_str(const char *name, int index, char *buf, size_t len)
{
    char rname[128];

    snprintf(rname, sizeof(rname), MAP_PSM_SSID_PREFIX "%s", index, name);

    return getpsm_val(rname, buf, len);
}

static int getparam_val(const char *name, char *buf, size_t len)
{
    int rc;
    int val_cnt = 0;
    int comp_cnt = 0;
    const char *subsys = "eRT.";
    const char *id =  "eRT.com.cisco.spvtg.ccsp.CR";
    componentStruct_t **comps = NULL;
    parameterValStruct_t **val = NULL;
    int retval = -1;

    rc = CcspBaseIf_discComponentSupportingNamespace(bus_handle, id, name,
        subsys, &comps, &comp_cnt);
    if (rc != CCSP_SUCCESS) {
        log_lib_e("Unable to find component");
        goto bail;
    }
    if (comp_cnt != 1) {
        log_lib_e("Invalid search result");
        goto bail;
    }

    rc = CcspBaseIf_getParameterValues(bus_handle, comps[0]->componentName,
        comps[0]->dbusPath, (char **)&name, 1, &val_cnt, &val);
    if (rc != CCSP_SUCCESS) {
        printf("Get parameter values failed");
        goto bail;
    }
    if (val_cnt > 0) {
        if (val[0]->parameterValue && strlen(val[0]->parameterValue) != 0) {
            snprintf(buf, len, "%s", val[0]->parameterValue);
            retval = 0;
        }
    }

bail:
    if (val != NULL) {
        free_parameterValStruct_t(bus_handle, val_cnt, val);
    }
    if (comps != NULL) {
        free_componentStruct_t(bus_handle, comp_cnt, comps);
    }

    return retval;
}

static char *getparam_str(const char *name, const char *def)
{
    int rc;
    char value[128];

    rc = getparam_val(name, value, sizeof(value));
    if (rc != 0) {
        return strdup(def);
    }

    return strdup(value);
}

static int setparam_val(const char *name, enum dataType_e type, const char *value)
{
    int rc;
    int comp_cnt = 0;
    const char *subsys = "eRT.";
    const char *id =  "eRT.com.cisco.spvtg.ccsp.CR";
    componentStruct_t **comps = NULL;
    parameterValStruct_t val = { 0 };
    char *fault = NULL;
    int retval = -1;

    rc = CcspBaseIf_discComponentSupportingNamespace(bus_handle, id, name,
        subsys, &comps, &comp_cnt);
    if (rc != CCSP_SUCCESS) {
        log_lib_e("Unable to find component");
        goto bail;
    }
    if (comp_cnt != 1) {
        log_lib_e("Invalid search result");
        goto bail;
    }

    val.type = type;
    val.parameterValue = strdup(value);
    val.parameterName = strdup(name);
    rc = CcspBaseIf_setParameterValues(bus_handle, comps[0]->componentName,
        comps[0]->dbusPath, 0, 0, &val, 1, TRUE, &fault);
    if (rc != CCSP_SUCCESS) {
        log_lib_e("Set parameter values failed");
        goto bail;
    }
    retval = 0;

bail:
    SFREE(fault);
    SFREE(val.parameterName);
    SFREE(val.parameterValue);
    if (comps != NULL) {
        free_componentStruct_t(bus_handle, comp_cnt, comps);
    }

    return retval;
}

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
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

static uint16_t bandwidth_from_string(const char *s)
{
    if (!strcasecmp(s, "20MHz")) {
        return 20;
    } else if (!strcasecmp(s, "40MHz")) {
        return 40;
    } else if (!strcasecmp(s, "80MHz")) {
        return 80;
    } else if (!strcasecmp(s, "160MHz")) {
        return 160;
    } else if (!strcasecmp(s, "320MHz")) {
        return 320;
    } else {
        return 0; /* Auto */
    }
}

static int convert_log_level(const char *level_str)
{
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
    log_lib_i("|    Enabled             : %d",   profile->enabled);
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
    log_lib_i("|    Hide                : %d",   profile->hide);
    log_lib_i("|    VLAN ID             : %d",   profile->vlan_id);
    log_lib_i("----------------------------------------------");
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
   - NONWB or !WB for 5G band
   - PSC or !NONPSC for 6G band
*/
static int set_chan_list(map_channel_set_t *ch_set, char *list, uint8_t freq_band, bool *ret_psc)
{
    map_channel_set_t ctl_ch_set;
    map_channel_set_t tmp_ch_set, tmp_ch_set2;
    int idx = 0, ret = 0, channel;
    char *elem = NULL, *p;
    bool exclude = false, psc = false;

    map_cs_unset_all(ch_set);

    /* Get all possible control (20MHz) channels */
    switch(freq_band) {
        case BAND_2G:
            map_get_2G_ctl_channel_set(&ctl_ch_set);
        break;
        case BAND_5G:
            map_get_5G_ctl_channel_set(&ctl_ch_set);
        break;
        case BAND_6G:
            map_get_6G_ctl_channel_set(&ctl_ch_set);
        break;
        default:
            return -1;
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

        /* If 5G, check WB first
           If 6G, check for PSC first
        */
        if ((freq_band == BAND_5G) && ((exclude && !strcasecmp(p, "WB")) || !strcasecmp(p, "NONWB"))) {
            map_get_5G_weatherband_channel_set(&tmp_ch_set);
            if (exclude) {
                map_cs_and_not(ch_set, &tmp_ch_set);
            } else {
                map_cs_copy(&tmp_ch_set2, &ctl_ch_set);
                map_cs_and_not(&tmp_ch_set2, &tmp_ch_set);
                map_cs_or(ch_set, &tmp_ch_set2);
            }
        } else if ((freq_band == BAND_6G) && ((exclude && !strcasecmp(p, "NONPSC")) || !strcasecmp(p, "PSC"))) {
            psc = true;
            map_get_6G_psc_channel_set(&tmp_ch_set);
            if (exclude) {
                map_cs_and(ch_set, &tmp_ch_set);
            } else {
                map_cs_or(ch_set, &tmp_ch_set);
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
    if ((*auth_mode & IEEE80211_AUTH_MODE_WPA2PSK) ||
        (*auth_mode & IEEE80211_AUTH_MODE_SAE)) {
        *encryption_mode |= IEEE80211_ENCRYPTION_MODE_AES;
    }
}

static char *get_sec_mode_str(uint16_t auth_mode, char *buf)
{
    if (auth_mode & IEEE80211_AUTH_MODE_OPEN) {
        strcpy(buf, "none");
    } else if ((auth_mode & IEEE80211_AUTH_MODE_WPA2PSK) &&
               (auth_mode & IEEE80211_AUTH_MODE_SAE)) {
        strcpy(buf, "wpa2-psk-wpa3-sae");
    } else if ((auth_mode & IEEE80211_AUTH_MODE_WPAPSK) &&
               (auth_mode & IEEE80211_AUTH_MODE_WPA2PSK)) {
        strcpy(buf, "wpa-wpa2-psk");
    } else if (auth_mode & IEEE80211_AUTH_MODE_SAE) {
        strcpy(buf, "wpa3-sae");
    } else if (auth_mode & IEEE80211_AUTH_MODE_WPA2PSK) {
        strcpy(buf, "wpa2-psk");
    }

    return buf;
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

static char *get_freq_bands_str(uint16_t freq_bands, char *buf)
{
    uint8_t pos;

    pos = 0;
    do {
        if (freq_bands & MAP_M2_BSS_RADIO2G) {
            buf[pos++] = '2';
            freq_bands &= ~MAP_M2_BSS_RADIO2G;
            if (!freq_bands) {
                break;
            }
            buf[pos++] = ',';
        }

        if ((freq_bands & MAP_M2_BSS_RADIO5GL) || (freq_bands & MAP_M2_BSS_RADIO5GU)) {
            buf[pos++] = '5';
            if ((freq_bands & MAP_M2_BSS_RADIO5GL) && !(freq_bands & MAP_M2_BSS_RADIO5GU)) {
                buf[pos++] = 'L';
            } else if (!(freq_bands & MAP_M2_BSS_RADIO5GL) && (freq_bands & MAP_M2_BSS_RADIO5GU)) {
                buf[pos++] = 'H';
            }
            freq_bands &= ~(MAP_M2_BSS_RADIO5GL | MAP_M2_BSS_RADIO5GU);
            if (!freq_bands) {
                break;
            }
            buf[pos++] = ',';
        }

        if (freq_bands & MAP_M2_BSS_RADIO6G) {
            buf[pos++] = '6';
        }
    } while (0);

    buf[pos] = '\0';

    return buf;
}

static int get_mac_addresses(map_controller_cfg_t *cfg)
{
    char value[24];
    mac_addr mac;
    int rc;

    rc = getparam_val("Device.Ethernet.Interface.1.MACAddress", value, sizeof(value));
    if (rc != 0) {
        log_lib_e("Failed to get MACAddress");
        return -1;
    }

    if (mac_from_string(value, mac) < 0) {
        log_lib_e("Invalid MACAddress: %s", value);
        return -1;
    }

    mac[0] |= 1 << 1;
    maccpy(cfg->al_mac, mac);
    ++mac[5];
    // if (!mac[5]) ++mac[4];
    // if (!mac[4]) ++mac[3];
    maccpy(cfg->local_agent_al_mac, mac);

    return 0;
}

static int get_wifi_radio_freqband(unsigned int ssid_idx, uint16_t *band)
{
    char path[128] = {0};
    char value[64] = {0};
    int rc;

    sprintf(path, "Device.WiFi.SSID.%d.LowerLayers", ssid_idx);
    rc = getparam_val(path, value, sizeof(value));
    if (rc != 0) {
        log_lib_e("Failed to get LowerLayers");
        return -1;
    }

    sprintf(path, "%sOperatingFrequencyBand", value);
    rc = getparam_val(path, value, sizeof(value));
    if (rc != 0) {
        log_lib_e("Failed to get OperatingFrequencyBand");
        return -1;
    }
    if (strcmp("5GHz", value) == 0) {
        *band = MAP_FREQ_BAND_5G;
    } else {
        *band = MAP_FREQ_BAND_2G;
    }

    return 0;
}

static int get_wifi_ssid_count(unsigned int *count)
{
    char path[128] = {0};
    char value[64] = {0};
    int rc;

    sprintf(path, "Device.WiFi.SSIDNumberOfEntries");
    rc = getparam_val(path, value, sizeof(value));
    if (rc != 0) {
        log_lib_e("Failed to get SSIDNumberOfEntries");
        return -1;
    }
    *count = (unsigned int)atoi(value);

    return 0;
}

static int get_wifi_ssid_enable(unsigned int ssid_idx, bool *enable)
{
    char path[128] = {0};
    char value[64] = {0};
    int rc;

    sprintf(path, "Device.WiFi.SSID.%d.Enable", ssid_idx);
    rc = getparam_val(path, value, sizeof(value));
    if (rc != 0) {
        log_lib_e("Failed to get SSIDEnable");
        return -1;
    }
    *enable = strcmp("true", value) ? false : true;

    return 0;
}

static int set_wifi_ssid_enable(unsigned int ssid_idx, bool enable)
{
    char path[128] = {0};
    char value[64] = {0};
    int rc;

    strcpy(value, enable == true ? "true" : "false");
    sprintf(path, "Device.WiFi.SSID.%d.Enable", ssid_idx);
    rc = setparam_val(path, ccsp_boolean, value);
    if (rc != 0) {
        log_lib_e("Failed to set SSIDEnable");
        return -1;
    }

    return 0;
}

static int get_wifi_ssid_ssid(unsigned int ssid_idx, char *ssid)
{
    char path[128] = {0};
    char value[64] = {0};
    int rc;

    sprintf(path, "Device.WiFi.SSID.%d.SSID", ssid_idx);
    rc = getparam_val(path, value, sizeof(value));
    if (rc != 0) {
        log_lib_e("Failed to get SSID");
        return -1;
    }
    strcpy(ssid, value);

    return 0;
}

static int set_wifi_ssid_ssid(unsigned int ssid_idx, char *ssid)
{
    char path[128] = {0};
    char value[64] = {0};
    int rc;

    strcpy(value, ssid);
    sprintf(path, "Device.WiFi.SSID.%d.SSID", ssid_idx);
    rc = setparam_val(path, ccsp_string, value);
    if (rc != 0) {
        log_lib_e("Failed to get SSID");
        return -1;
    }

    return 0;
}

static int get_wifi_security_index(unsigned int ssid_idx, unsigned int *ap_index)
{
    char path[128] = {0};
    char value[64] = {0};
    char pattern[64] = {0};
    unsigned int ap_cnt;
    unsigned int i;
    int rc;

    sprintf(path, "Device.WiFi.AccessPointNumberOfEntries");
    rc = getparam_val(path, value, sizeof(value));
    if (rc != 0) {
        log_lib_e("Failed to get AccessPointNumberOfEntries");
        return -1;
    }
    ap_cnt = atoi(value);

    sprintf(pattern, "Device.WiFi.SSID.%u.", ssid_idx);
    for (i = 0; i < ap_cnt; i++) {
        sprintf(path, "Device.WiFi.AccessPoint.%d.SSIDReference", i + 1);
        rc = getparam_val(path, value, sizeof(value));
        if (rc != 0) {
            log_lib_e("Failed to get SSIDReference");
            return -1;
        }
        if (strcmp(pattern, value) == 0) {
            *ap_index = i + 1;
            return 0;
        }
    }

    log_lib_e("Failed to find SSID reference: %d", ssid_idx);

    return -1;
}

static int get_wifi_security_key(unsigned int ap_idx, char *key)
{
    char path[128] = {0};
    char value[64] = {0};
    int rc;

    sprintf(path, "Device.WiFi.AccessPoint.%u.Security.KeyPassphrase", ap_idx);
    rc = getparam_val(path, value, sizeof(value));
    if (rc != 0) {
        log_lib_e("Failed to get KeyPassphrase");
        return -1;
    }
    strcpy(key, value);

    return 0;
}

static int set_wifi_security_key(unsigned int ap_idx, char *key)
{
    char path[128] = {0};
    char value[64] = {0};
    int rc;

    strcpy(value, key);
    sprintf(path, "Device.WiFi.AccessPoint.%u.Security.KeyPassphrase", ap_idx);
    rc = setparam_val(path, ccsp_string, value);
    if (rc != 0) {
        log_lib_e("Failed to set KeyPassphrase");
        return -1;
    }

    return 0;
}

static int get_wifi_security_mode(unsigned int ap_idx, char *mode)
{
    char path[128] = {0};
    char value[64] = {0};
    int rc;

    sprintf(path, "Device.WiFi.AccessPoint.%d.Security.ModeEnabled", ap_idx);
    rc = getparam_val(path, value, sizeof(value));
    if (rc != 0) {
        log_lib_e("Failed to get ModeEnabled");
        return -1;
    }
    if (strcmp(value, "WPA2-Personal") == 0) {
        strcpy(mode, "wpa2-psk");
    } else if (strcmp(value, "WPA3-Personal") == 0) {
        strcpy(mode, "wpa3-sae");
    } else if (strcmp(value, "WPA3-Personal-Transition") == 0) {
        strcpy(mode, "wpa2-psk-wpa3-sae");
    } else if (strcmp(value, "WPA-WPA2-Personal") == 0) {
        strcpy(mode, "wpa-wpa2-psk");
    } else {
        log_lib_e("Unsopperted security mode: %s", value);
        return -1;
    }

    return 0;
}

static int set_wifi_security_mode(unsigned int ap_idx, char *mode)
{
    char path[128] = {0};
    char value[64] = {0};
    int rc;

    if (strcmp(mode, "wpa2-psk") == 0) {
        strcpy(value, "WPA2-Personal");
    } else if (strcmp(mode, "wpa3-sae") == 0) {
        strcpy(value, "WPA3-Personal");
    } else if (strcmp(mode, "wpa2-psk-wpa3-sae") == 0) {
        strcpy(value, "WPA3-Personal-Transition");
    } else if (strcmp(mode, "wpa-wpa2-psk") == 0) {
        strcpy(value, "WPA-WPA2-Personal");
    } else {
        log_lib_e("Unsopperted security mode: %s", value);
        return -1;
    }
    sprintf(path, "Device.WiFi.AccessPoint.%d.Security.ModeEnabled", ap_idx);
    rc = setparam_val(path, ccsp_string, value);
    if (rc != 0) {
        log_lib_e("Failed to get ModeEnabled");
        return -1;
    }

    return 0;
}

static int set_wifi_apply_settings(unsigned int radio_idx)
{
    char path[128] = {0};
    char value[8] = {0};
    int rc;

    value[0] = '1';
    sprintf(path, "Device.WiFi.Radio.%u.X_RDK_ApplySettingSSID", radio_idx);
    rc = setparam_val(path, ccsp_int, value);
    if (rc != 0) {
        log_lib_e("Failed to set X_RDK_ApplySetting");
        return -1;
    }

    return 0;
}

/*#######################################################################
#                       PROFILE SYNC                                    #
########################################################################*/
static int profile_load(map_profile_cfg_t *profile, uint8_t index)
{
    int rc = -1;
    bool  fh, bh, enabled;
    char *type = NULL;
    char *freq_bands = NULL;
    char *security_mode = NULL;
    char *val = NULL;
    bool  hide = false;

    if (profile == NULL) {
        return -1;
    }

    /* Fill in profiles */
    memset(profile, 0, sizeof(map_profile_cfg_t));

    if (getpsm_ssid("Type", index, &type) != 0) {
        log_lib_e("Get Type[%d] failed", index);
        goto bail;
    }
    if (getpsm_ssid("Enabled", index, &val) != 0) {
        log_lib_e("Get Enabled[%d] failed", index);
        return -1;
    }
    enabled = (val[0] == '1');
    SFREE(val);
    if (getpsm_ssid_str("Label", index, profile->label, sizeof(profile->label)) != 0) {
        log_lib_e("Get Label[%d] failed", index);
        goto bail;
    }
    if (getpsm_ssid_str("SSID", index, profile->bss_ssid, sizeof(profile->bss_ssid)) != 0) {
        log_lib_e("Get SSID[%d] failed", index);
        goto bail;
    }
    if (getpsm_ssid("FrequencyBands", index, &freq_bands) != 0) {
        log_lib_e("Get FrequencyBands[%d] failed", index);
        goto bail;
    }
    if (getpsm_ssid("SecurityMode", index, &security_mode) != 0) {
        log_lib_e("Get SecurityMode[%d] failed", index);
        goto bail;
    }
    if (getpsm_ssid_str("Keypassphrase", index, profile->wpa_key, sizeof(profile->wpa_key)) != 0) {
        log_lib_e("Get Keypassphrase[%d] failed", index);
        goto bail;
    }
    if (getpsm_ssid("Fronthaul", index, &val) != 0) {
        log_lib_e("Get Fronthaul[%d] failed", index);
        goto bail;
    }
    fh = (val[0] == '1');
    SFREE(val);
    if (getpsm_ssid("Backhaul", index, &val) != 0) {
        log_lib_e("Get Backhaul[%d] failed", index);
        goto bail;
    } else {
    }
    bh = (val[0] == '1');
    SFREE(val);
    profile->gateway = 1;
    profile->extender = 1;
    if (getpsm_ssid("VLANID", index, &val) != 0) {
        log_lib_e("Get VLANID[%d] failed", index);
        goto bail;
    }
    profile->vlan_id = atoi(val);
    SFREE(val);
    if (getpsm_ssid("Hide", index, &val) != 0) {
        log_lib_e("Get Hide[%d] failed", index);
        return -1;
    }
    hide = (val[0] == '1');
    SFREE(val);
    rc = 0;

    profile->profile_idx = index + 1;
    profile->enabled = enabled;
    profile->type = profile_type_from_string(type);

    get_frequency_bands(freq_bands, &profile->bss_freq_bands);

    get_iface_security_mode(security_mode, &profile->supported_auth_modes,
        &profile->supported_encryption_types, index);

    profile->bss_state |= fh ? MAP_FRONTHAUL_BSS : 0;
    profile->bss_state |= bh ? MAP_BACKHAUL_BSS  : 0;

    /* Force hide for dedicated backhaul interface. */
    profile->hide = bh && !fh ? true : hide;

bail:
    SFREE(type);
    SFREE(freq_bands);
    SFREE(security_mode);

    return rc;
}

static int profile_save(map_profile_cfg_t *profile, uint8_t index)
{
    char buf[24];

    if (profile == NULL) {
        return -1;
    }

    strcpy(buf, profile_type_to_string(profile->type));
    if (setpsm_ssid("Type", index, buf) != 0) {
        log_lib_e("Set Type[%d] failed", index);
    }
    snprintf(buf, sizeof(buf), "%d", profile->enabled);
    if (setpsm_ssid("Enabled", index, buf) != 0) {
        log_lib_e("Set Enabled[%d] failed", index);
    }
    if (setpsm_ssid("Label", index, profile->label) != 0) {
        log_lib_e("Set Label[%d] failed", index);
    }
    if (setpsm_ssid("SSID", index, profile->bss_ssid) != 0) {
        log_lib_e("Set SSID[%d] failed", index);
    }
    get_freq_bands_str(profile->bss_freq_bands, buf);
    if (setpsm_ssid("FrequencyBands", index, buf) != 0) {
        log_lib_e("Set FrequencyBands[%d] failed", index);
    }
    get_sec_mode_str(profile->supported_auth_modes, buf);
    if (setpsm_ssid("SecurityMode", index, buf) != 0) {
        log_lib_e("Set SecurityMode[%d] failed", index);
    }
    if (setpsm_ssid("Keypassphrase", index, profile->wpa_key) != 0) {
        log_lib_e("Set Keypassphrase[%d] failed", index);
    }
    snprintf(buf, sizeof(buf), "%d",
        (profile->bss_state & MAP_FRONTHAUL_BSS) ? 1 : 0);
    if (setpsm_ssid("Fronthaul", index, buf) != 0) {
        log_lib_e("Set Fronthaul[%d] failed", index);
    }
    snprintf(buf, sizeof(buf), "%d",
        (profile->bss_state & MAP_BACKHAUL_BSS) ? 1 : 0);
    if (setpsm_ssid("Backhaul", index, buf) != 0) {
        log_lib_e("Set Backhaul[%d] failed", index);
    }
    snprintf(buf, sizeof(buf), "%d", profile->vlan_id);
    if (setpsm_ssid("VLANID", index, buf) != 0) {
        log_lib_e("Set VLANID[%d] failed", index);
    }
    snprintf(buf, sizeof(buf), "%d", profile->hide);
    if (setpsm_ssid("Hide", index, buf) != 0) {
        log_lib_e("Set Hide[%d] failed", index);
    }

    return 0;
}

static int profile_remove(uint8_t index)
{
    if (rmpsm_ssid("Type", index) != 0) {
        log_lib_e("Remove Type[%d] failed", index);
    }
    if (rmpsm_ssid("Enabled", index) != 0) {
        log_lib_e("Remove Enabled[%d] failed", index);
    }
    if (rmpsm_ssid("Label", index) != 0) {
        log_lib_e("Remove Label[%d] failed", index);
    }
    if (rmpsm_ssid("SSID", index) != 0) {
        log_lib_e("Remove SSID[%d] failed", index);
    }
    if (rmpsm_ssid("FrequencyBands", index) != 0) {
        log_lib_e("Remove FrequencyBands[%d] failed", index);
    }
    if (rmpsm_ssid("SecurityMode", index) != 0) {
        log_lib_e("Remove SecurityMode[%d] failed", index);
    }
    if (rmpsm_ssid("Keypassphrase", index) != 0) {
        log_lib_e("Remove Keypassphrase[%d] failed", index);
    }
    if (rmpsm_ssid("Fronthaul", index) != 0) {
        log_lib_e("Remove Fronthaul[%d] failed", index);
    }
    if (rmpsm_ssid("Backhaul", index) != 0) {
        log_lib_e("Remove Backhaul[%d] failed", index);
    }
    if (rmpsm_ssid("VLANID", index) != 0) {
        log_lib_e("Remove VLANID[%d] failed", index);
    }
    if (rmpsm_ssid("Hide", index) != 0) {
        log_lib_e("Remove Hide[%d] failed", index);
    }

    return 0;
}

static int mapping_get_by_pidx(int profile_idx, unsigned int *ssid_idx)
{
    unsigned int          mapping_cnt;
    profile_ssid_map_t   *mapping;
    unsigned int          i;

    if (g_use_dynamic_mapping) {
        mapping = g_dynamic_mapping;
        mapping_cnt = ARRAY_SIZE(g_dynamic_mapping);
    } else {
        mapping = g_static_mapping;
        mapping_cnt = ARRAY_SIZE(g_static_mapping);
    }

    *ssid_idx = -1;
    for (i = 0; i < mapping_cnt; i++) {
        if (profile_idx == mapping[i].profile_idx) {
            *ssid_idx = mapping[i].ssid_idx;
            break;
        }
    }

    return 0;
}

static int profile_match(map_profile_cfg_t *profile)
{
    profile_ssid_map_t *mapping;
    unsigned int ssid_cnt = 0;
    unsigned int ssid_idx;
    bool ssid_enable;
    char ssid[32];

    if (g_use_dynamic_mapping) {
        mapping = &g_dynamic_mapping[profile->profile_idx - 1];
    } else {
        mapping = &g_static_mapping[profile->profile_idx - 1];
    }
    mapping->profile_idx = profile->profile_idx;
    mapping->ssid_idx = -1;

    if (get_wifi_ssid_count(&ssid_cnt) < 0) {
        log_lib_e("Invalid SSID count: %d", ssid_cnt);
        return 0;
    }

    for (ssid_idx = 1; ssid_idx <= ssid_cnt; ssid_idx++) {
        if (get_wifi_ssid_enable(ssid_idx, &ssid_enable) < 0) {
            log_lib_e("Get SSID enable failed");
            continue;
        }
        if (!ssid_enable) {
            continue;
        }
        if (get_wifi_ssid_ssid(ssid_idx, ssid) < 0) {
            log_lib_e("Get SSID failed");
            continue;
        }
        if (strcmp(profile->bss_ssid, ssid) == 0) {
            mapping->ssid_idx = ssid_idx;
            break;
        }
    }

    return 0;
}

static void profile_create_backhaul(void)
{
    unsigned int profile_cnt;
    map_controller_cfg_t *cfg;
    map_profile_cfg_t *profile;

    cfg = &g_map_cfg.controller_cfg;
    profile_cnt = cfg->num_profiles;
    map_profile_realloc(++profile_cnt);
    profile = &cfg->profiles[profile_cnt - 1];
    profile->profile_idx = profile_cnt;
    profile->enabled = TRUE;
    profile->type = MAP_PROFILE_TYPE_BACKHAUL;
    strncpy(profile->label, "Backhaul", sizeof(profile->label));
    strncpy(profile->bss_ssid, "Backhaul", sizeof(profile->bss_ssid));
    strncpy(profile->wpa_key, "rdk@1234", sizeof(profile->wpa_key));
    get_iface_security_mode("wpa2-psk", &profile->supported_auth_modes,
        &profile->supported_encryption_types, profile->profile_idx);
    profile->bss_freq_bands = MAP_FREQ_BAND_5G;
    profile->bss_state = MAP_BACKHAUL_BSS;
    profile->extender = true;
    profile->gateway = true;
    profile->hide = true;
    profile->vlan_id = -1;

    profile_save(profile, profile_cnt - 1);
    cfg->num_profiles = profile_cnt;

    return;
}

static void wifi_dynamic_mapper(void)
{
    bool ssid_enable = false;
    bool dedicated_backhaul = true;
    unsigned int ap_idx = 0;
    unsigned int ssid_cnt = 0;
    unsigned int ssid_idx;
    unsigned int profile_cnt;
    unsigned int profile_5GHz_cnt = 0;
    char key[64];
    char ssid[32];
    char mode[32];
    uint16_t freqband;
    map_controller_cfg_t *cfg;
    map_profile_cfg_t *profile;
    profile_ssid_map_t *mapping;
    unsigned int i;

    if (get_wifi_ssid_count(&ssid_cnt) < 0) {
        log_lib_e("Invalid SSID count: %d", ssid_cnt);
        return;
    }

    cfg = &g_map_cfg.controller_cfg;
    profile_cnt = cfg->num_profiles;
    for (ssid_idx = 1; ssid_idx <= ssid_cnt; ssid_idx++) {
        if (get_wifi_ssid_enable(ssid_idx, &ssid_enable) < 0) {
            log_lib_e("Get SSID enable failed");
            continue;
        }
        if (!ssid_enable) {
            continue;
        }
        if (get_wifi_radio_freqband(ssid_idx, &freqband) < 0) {
            log_lib_e("Get radio freqband failed");
            continue;
        }
        if (get_wifi_ssid_ssid(ssid_idx, ssid) < 0) {
            log_lib_e("Get SSID failed");
            continue;
        }
        if (get_wifi_security_index(ssid_idx, &ap_idx) < 0) {
            log_lib_e("Get security index failed");
            continue;
        }
        if (get_wifi_security_mode(ap_idx, mode) < 0) {
            log_lib_e("Get security mode failed");
            continue;
        }
        if (get_wifi_security_key(ap_idx, key) < 0) {
            log_lib_e("Get security key failed");
            continue;
        }

        map_profile_realloc(++profile_cnt);
        profile = &cfg->profiles[profile_cnt - 1];
        profile->profile_idx = profile_cnt;
        profile->enabled = true;
        profile->type = MAP_PROFILE_TYPE_OTHER;
        strcpy(profile->bss_ssid, ssid);
        strcpy(profile->wpa_key, key);
        get_iface_security_mode(mode, &profile->supported_auth_modes,
            &profile->supported_encryption_types, profile->profile_idx);
        profile->bss_freq_bands = freqband;
        profile->bss_state = MAP_FRONTHAUL_BSS;
        profile->gateway = true;
        profile->extender = true;
        profile->hide = false;
        profile->vlan_id = -1;

        mapping = &g_dynamic_mapping[profile_cnt - 1];
        mapping->ssid_idx = ssid_idx;
        mapping->profile_idx = profile->profile_idx;

        if (freqband == MAP_FREQ_BAND_5G) {
            profile_5GHz_cnt++;
        }

        profile_save(profile, profile_cnt - 1);
        cfg->num_profiles = profile_cnt;
    }

    if (dedicated_backhaul == true || profile_5GHz_cnt == 0) {
        profile_create_backhaul();
        profile = &cfg->profiles[cfg->num_profiles - 1];

        mapping = &g_dynamic_mapping[cfg->num_profiles - 1];
        mapping->ssid_idx = -1;
        mapping->profile_idx = profile->profile_idx;
    } else {
        if (profile_cnt == 1) {
            profile = &cfg->profiles[0];
            profile->bss_state |= MAP_BACKHAUL_BSS;
            profile_save(profile, 0);
        } else {
            for (i = 0; i < profile_cnt; i++) {
                profile = &cfg->profiles[i];
                if (profile->bss_freq_bands == MAP_FREQ_BAND_5G) {
                    profile->bss_state |= MAP_BACKHAUL_BSS;
                    profile_save(profile, i);
                    break;
                }
            }
        }
    }

    return;
}

static void wifi_static_mapper(void)
{
    bool ssid_enable;
    bool backhaul_found = false;
    unsigned int ap_idx = 0;
    unsigned int ssid_idx;
    unsigned int ssid_cnt = 0;
    unsigned int profile_cnt;
    char key[64];
    char ssid[32];
    char mode[32];
    uint16_t freqband;
    map_controller_cfg_t *cfg;
    map_profile_cfg_t *profile;
    profile_ssid_map_t *mapping;
    unsigned int i;

    if (get_wifi_ssid_count(&ssid_cnt) < 0) {
        log_lib_e("Invalid ssid count: %d", ssid_cnt);
        return;
    }

    cfg = &g_map_cfg.controller_cfg;
    profile_cnt = cfg->num_profiles;
    for (ssid_idx = 1; ssid_idx <= ssid_cnt; ssid_idx++) {
        mapping = NULL;
        for (i = 0; i < ARRAY_SIZE(g_static_mapping); i++) {
            if (g_static_mapping[i].ssid_idx == ssid_idx) {
                mapping = &g_static_mapping[i];
                break;
            }
        }
        if (mapping == NULL) {
            continue;
        }

        if (get_wifi_ssid_enable(ssid_idx, &ssid_enable) < 0) {
            log_lib_e("Get SSID enable failed");
            continue;
        }
        if (!ssid_enable) {
            continue;
        }
        if (get_wifi_radio_freqband(ssid_idx, &freqband) < 0) {
            log_lib_e("Get radio freqband failed");
            continue;
        }
        if (get_wifi_ssid_ssid(ssid_idx, ssid) < 0) {
            log_lib_e("Get SSID failed");
            continue;
        }
        if (get_wifi_security_index(ssid_idx, &ap_idx) < 0) {
            log_lib_e("Get security index failed");
            continue;
        }
        if (get_wifi_security_mode(ap_idx, mode) < 0) {
            log_lib_e("Get security mode failed");
            continue;
        }
        if (get_wifi_security_key(ap_idx, key) < 0) {
            log_lib_e("Get security key failed");
            continue;
        }

        map_profile_realloc(++profile_cnt);
        profile = &cfg->profiles[profile_cnt - 1];
        profile->profile_idx = mapping->profile_idx;
        profile->enabled = true;
        profile->type = mapping->type;
        strcpy(profile->label, mapping->label);
        strcpy(profile->bss_ssid, ssid);
        strcpy(profile->wpa_key, key);
        get_iface_security_mode(mode, &profile->supported_auth_modes,
            &profile->supported_encryption_types, profile->profile_idx);
        profile->bss_freq_bands = freqband;
        profile->bss_state = mapping->bss_state;
        profile->gateway = true;
        profile->extender = true;
        profile->hide = false;
        profile->vlan_id = -1;

        if (profile->bss_state & MAP_BACKHAUL_BSS) {
            backhaul_found = true;
        }

        profile_save(profile, profile_cnt - 1);
        cfg->num_profiles = profile_cnt;
    }

    if (!backhaul_found) {
        profile_create_backhaul();
    }

    return;
}

/*#######################################################################
#                       CONFIG LOAD                                     #
########################################################################*/
static int cfg_load(map_cfg_t *cfg, bool init)
{
    char *log_level_controller = NULL;
    char *log_level_platform   = NULL;
    char *log_level_ieee1905   = NULL;
    char *log_level_ssp        = NULL;
    char *log_output           = NULL;
    char *value                = NULL;

    /* LOAD ONCE */
    if (init) {
        cfg->interfaces = strdup("^lo$|^eth.*|^wl.*|^sw_.*|^n[rs]gmii.*");
        cfg->primary_vlan_pattern = strdup("${ifname}.${pvid}");
        cfg->primary_vlan_id = -1;
        cfg->default_pcp = 0;
        cfg->manufacturer = getparam_str(DM_DI_MANUFACTURER, MAP_DEF_MANUFACTURER);
        cfg->model_name = getparam_str(DM_DI_MODELNAME, MAP_DEF_MODEL_NAME);
        cfg->model_number = getparam_str(DM_DI_PRODUCTCLASS, MAP_DEF_MODEL_NUMBER);
        cfg->serial_number = getparam_str(DM_DI_SERIALNUMBER, MAP_DEF_SERIAL_NUMBER);

        comp_interfaces_regex(cfg);
    }

    /* LOAD ALWAYS */
    cfg->enabled = 1;
    cfg->is_master = 1;
    cfg->wfa_cert_r1_compatible = 0;

    value = getenv("MAP_CONTROLLER_LOG_LEVEL");
    log_level_controller = (value == NULL) ? strdup("error") : strdup(value);
    value = getenv("MAP_PLATFORM_LOG_LEVEL");
    log_level_platform = (value == NULL) ? strdup("error") : strdup(value);
    value = getenv("MAP_IEEE1905_LOG_LEVEL");
    log_level_ieee1905 = (value == NULL) ? strdup("error") : strdup(value);
    value = getenv("MAP_SSP_LOG_LEVEL");
    log_level_ssp = (value == NULL) ? strdup("error") : strdup(value);
    value = getenv("MAP_LOG_OUTPUT");
    log_output = (value == NULL) ? strdup("stderr") : strdup(value);

    cfg->controller_log_level = convert_log_level(log_level_controller);
    cfg->library_log_level    = convert_log_level(log_level_platform);
    cfg->ieee1905_log_level   = convert_log_level(log_level_ieee1905);
    cfg->ssp_log_level        = convert_log_level(log_level_ssp);
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
    SFREE(log_level_ssp);
    SFREE(log_output);

    return 0;
}

static int chan_sel_cfg_load(map_chan_sel_cfg_t *cfg)
{
    char value[64];

    getpsm_val(MAP_PSM_ALLOWEDCL2G, value, sizeof(value));
    if (set_chan_list(&cfg->allowed_channel_set_2g, value, BAND_2G, NULL)) {
        log_lib_e("failed parsing allowed 2G chan list[%s]", value);
    }
    getpsm_val(MAP_PSM_ALLOWEDCL5G, value, sizeof(value));
    if (set_chan_list(&cfg->allowed_channel_set_5g, value, BAND_5G, NULL)) {
        log_lib_e("failed parsing allowed 5G chan list[%s]", value);
    }
    /* !2 */
    getpsm_val(MAP_PSM_ALLOWEDCL6G, value, sizeof(value));
    if (set_chan_list(&cfg->allowed_channel_set_6g, value, BAND_6G, &cfg->allowed_channel_6g_psc)) {
        log_lib_e("failed parsing allowed 6G chan list[%s]", value);
    }

    /* 1,6,11 */
    getpsm_val(MAP_PSM_PREFERREDCL2G, value, sizeof(value));
    if (set_chan_list(&cfg->default_pref_channel_set_2g, value, BAND_2G, NULL)) {
        log_lib_e("failed parsing pref 2G chan list[%s]", value);
    }
    /* !140,!144 */
    getpsm_val(MAP_PSM_PREFERREDCL5G, value, sizeof(value));
    if (set_chan_list(&cfg->default_pref_channel_set_5g, value, BAND_5G, NULL)) {
        log_lib_e("failed parsing pref 5G chan list[%s]", value);
    }
    /* PSC */
    getpsm_val(MAP_PSM_PREFERREDCL6G, value, sizeof(value));
    if (set_chan_list(&cfg->default_pref_channel_set_6g, value, BAND_6G, NULL)) {
        log_lib_e("failed parsing pref 6G chan list[%s]", value);
    }

    getpsm_val(MAP_PSM_ALLOWEDBW2G, value, sizeof(value));
    cfg->allowed_bandwidth_2g = bandwidth_from_string(value);
    getpsm_val(MAP_PSM_ALLOWEDBW5G, value, sizeof(value));
    cfg->allowed_bandwidth_5g = bandwidth_from_string(value);
    getpsm_val(MAP_PSM_ALLOWEDBW6G, value, sizeof(value));
    cfg->allowed_bandwidth_6g = bandwidth_from_string(value);

    getpsm_val(MAP_PSM_BANDLOCK5G, value, sizeof(value));
    cfg->bandlock_5g = bandlock_type_from_string(value);

    return 0;
}

static int controller_cfg_load(map_controller_cfg_t *cfg, bool init)
{
    int  val;

    /* LOAD ONCE */
    if (init) {
        get_mac_addresses(cfg);
    }

    /* LOAD ALWAYS */
    cfg->topology_query_interval = getpsm_int(MAP_PSM_TOPQINT,
        MAP_DEFAULT_TOPOLOGY_QUERY_INTERVAL);
    cfg->link_metrics_query_interval = getpsm_int(MAP_PSM_LMQINT,
        MAP_DEFAULT_LINK_METRICS_QUERY_INTERVAL);
    cfg->ap_capability_query_interval = getpsm_int(MAP_PSM_APCAPQINT,
        MAP_DEFAULT_AP_CAPABILITY_QUERY_INTERVAL);
    cfg->dead_agent_detection_interval = getpsm_int(MAP_PSM_DEADAGENTINT,
        MAP_DEFAULT_DEAD_AGENT_DETECTION_INTERVAL);

    /* FROM ENV */
    cfg->map_profile = getenv_int("MAP_CONTROLLER_MULTIAP_PROFILE",
        MAP_DEFAULT_MULTIAP_PROFILE);
    cfg->lldp_interval = getenv_int("AL_ENTITY_LLDP_BRIDGE_DISCOVERY_ENV_INTERVAL",
        MAP_DEFAULT_LLDP_BRIDGE_DISCOVERY_INTERVAL);
    cfg->topology_discovery_interval = getenv_int("AL_ENTITY_TOPOLOGY_DISCOVERY_INTERVAL",
        MAP_DEFAULT_TOPOLOGY_DISCOVERY_INTERVAL);
    cfg->channel_selection_enabled = getenv_int("MAP_CONTROLLER_CHANNEL_SELECTION_ENABLED",
        MAP_DEFAULT_CHANNEL_SELECTION_ENABLED);

    val = getenv_int("MAP_CONTROLLER_FREQ_2_4_GHZ", MAP_DEFAULT_FREQ_2_4_GHZ);
    cfg->supportedfreq[IEEE80211_FREQUENCY_BAND_2_4_GHZ] =
        val ? IEEE80211_FREQUENCY_BAND_2_4_GHZ : 0;
    val = getenv_int("MAP_CONTROLLER_FREQ_5_GHZ", MAP_DEFAULT_FREQ_5_GHZ);
    cfg->supportedfreq[IEEE80211_FREQUENCY_BAND_5_GHZ] =
        val ? IEEE80211_FREQUENCY_BAND_5_GHZ : 0;
    val = getenv_int("MAP_CONTROLLER_FREQ_6_GHZ", MAP_DEFAULT_FREQ_6_GHZ);
    cfg->supportedfreq[IEEE80211_FREQUENCY_BAND_6_GHZ] =
        val ? IEEE80211_FREQUENCY_BAND_6_GHZ : 0;

    /* CHANNEL SELECTION */
    chan_sel_cfg_load(&cfg->chan_sel);

    return 0;
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
    free(cfg->controller_cfg.profiles);

    if (cfg->interfaces_regex) {
        regfree(cfg->interfaces_regex);
        free(cfg->interfaces_regex);
    }

    memset(cfg, 0, sizeof(map_cfg_t));
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
int map_cfg_init(void)
{
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

map_controller_cfg_t *map_controller_cfg_get(void)
{
    return &g_map_cfg.controller_cfg;
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
    unsigned int          profile_cnt, i, idx = 0;
    bool                  changed = false;

    profile_cnt = getpsm_int(MAP_PSM_SSIDNOE, 0);
    if (!profile_cnt) {
        /* Either sync with Device.WiFi.SSID or use defaults */
        if (g_sync_with_wifi) {
            if (g_use_dynamic_mapping) {
                wifi_dynamic_mapper();
            } else {
                wifi_static_mapper();
            }
        }

        if (!cfg->num_profiles) {
            profile_cnt = ARRAY_SIZE(g_default_profiles);

            /* Reallocate cfg->profiles */
            map_profile_realloc(profile_cnt);

            for (i = 0; i < profile_cnt; i++) {
                cfg->profiles[i] = g_default_profiles[i];
                profile_save(&cfg->profiles[i], i);
            }

            cfg->num_profiles = profile_cnt;
        }

        setpsm_int(MAP_PSM_SSIDNOE, cfg->num_profiles);
        changed = true;
    } else {
        /* Reallocate cfg->profiles */
        map_profile_realloc(profile_cnt);

        for (i=0; i<profile_cnt; i++) {
            map_profile_cfg_t profile;

            if (profile_load(&profile, i)) {
                continue;
            }
            if (memcmp(&profile, &cfg->profiles[idx], sizeof(map_profile_cfg_t))) {
                cfg->profiles[idx] = profile;
                /* Backhaul profile change will not trigger config renew here.
                   It will be handled in its own routine */
                if (!(profile.bss_state & MAP_BACKHAUL_BSS)) {
                    changed = true;
                }
            }

            if (!ret_changed) {
                /* Init call, not config change */
                profile_match(&profile);
            }

            idx++;
        }

        if (cfg->num_profiles != idx) {
            cfg->num_profiles = idx;
            changed = true;
        }
    }

    if (ret_changed) {
        *ret_changed = changed;
    }

    if (dump_profiles) {
        map_profile_dump(cfg);
    }

    return 0;
}

int map_profile_realloc(unsigned int num_alloc_profiles)
{
    map_controller_cfg_t *cfg = &map_cfg_get()->controller_cfg;
    map_profile_cfg_t    *profiles;
    int                   ret = 0;

    if (num_alloc_profiles > cfg->num_alloc_profiles) {
        if ((profiles = realloc(cfg->profiles, num_alloc_profiles * sizeof(map_profile_cfg_t)))) {
            log_lib_i("allocated room for %d profiles", num_alloc_profiles);

            /* Clear any unused profiles */
            if (num_alloc_profiles > cfg->num_profiles) {
                memset(&profiles[cfg->num_profiles], 0, (num_alloc_profiles - cfg->num_profiles) * sizeof(map_profile_cfg_t));
            }

            cfg->profiles           = profiles;
            cfg->num_alloc_profiles = num_alloc_profiles;
        } else {
            /* TBD: delete old profiles?? */
            log_lib_i("failed allocating room for %d profiles", num_alloc_profiles);
            ret = -1;
        }
    }

    return ret;
}

int map_profile_add(map_profile_cfg_t *profile)
{
    map_controller_cfg_t *cfg = &map_cfg_get()->controller_cfg;
    unsigned int          profile_cnt, i;
    unsigned int          ssid_idx;
    char                  mode[24];
    bool                  send_apply = false;

    profile_cnt = cfg->num_profiles;

    for (i = 0; i < profile_cnt; i++) {
        map_profile_cfg_t bp;
        map_profile_cfg_t *pp = &cfg->profiles[i];

        if (strcmp(profile->bss_ssid, pp->bss_ssid) == 0) {
            if (pp->bss_state & MAP_BACKHAUL_BSS) {
                log_lib_e("Modifying backhaul is illegal");
                return -1;
            }

            if (profile->supported_auth_modes != IEEE80211_AUTH_MODE_OPEN &&
                profile->wpa_key[0] == '\0') {
                log_lib_e("Invalid password");
                return -1;
            }

            if (profile->label[0] == '\0') {
                if (pp->label[0] != '\0') {
                    strcpy(profile->label, pp->label);
                } else {
                    snprintf(profile->label, sizeof(profile->label), "ssid%d", i);
                }
            }

            if (profile->type == MAP_PROFILE_TYPE_OTHER) {
                if (pp->type != MAP_PROFILE_TYPE_OTHER) {
                    profile->type = pp->type;
                }
            }

            map_profile_clone(&bp, pp);
            profile_save(profile, i);

            if (g_map_cfg_cbs.profile_update_cb) {
                g_map_cfg_cbs.profile_update_cb();
            }

            mapping_get_by_pidx(pp->profile_idx, &ssid_idx);
            if ((int)ssid_idx <= 0) {
                return 0;
            }

            if (bp.supported_auth_modes != pp->supported_auth_modes) {
                get_sec_mode_str(pp->supported_auth_modes, mode);
                set_wifi_security_mode(ssid_idx, mode);
                send_apply = true;
            }

            if (strcmp(bp.wpa_key, pp->wpa_key) != 0) {
                set_wifi_security_key(ssid_idx, pp->wpa_key);
                send_apply = true;
            }

            if (send_apply) {
                /* Super hack; we need to store radio idx */
                set_wifi_apply_settings((ssid_idx % 2) + 1);
            }

            return 0;
        }
    }

    if (profile->label[0] == '\0') {
        snprintf(profile->label, sizeof(profile->label), "ssid%d", i);
    }
    /* Add new profile */
    profile_save(profile, profile_cnt);

    profile_cnt = cfg->num_profiles + 1;
    setpsm_int(MAP_PSM_SSIDNOE, profile_cnt);

    if (g_map_cfg_cbs.profile_update_cb) {
        g_map_cfg_cbs.profile_update_cb();
    }

    if (0) {
        /* TODO */
        ssid_idx = -1;
        set_wifi_ssid_enable(ssid_idx, true);
        set_wifi_ssid_ssid(ssid_idx, profile->bss_ssid);
        get_sec_mode_str(profile->supported_auth_modes, mode);
        set_wifi_security_mode(ssid_idx, mode);
        set_wifi_security_key(ssid_idx, profile->wpa_key);
        set_wifi_apply_settings((ssid_idx % 2) + 1);
    }

    return 0;
}

int map_profile_remove(map_profile_cfg_t *profile)
{
    map_controller_cfg_t *cfg = &map_cfg_get()->controller_cfg;
    unsigned int          profile_cnt, i;
    int                   update = 0;
    unsigned int          ssid_idx = -1;

    profile_cnt = cfg->num_profiles;

    for (i = 0; i < profile_cnt; i++) {
        map_profile_cfg_t *pp = &cfg->profiles[i];

        if (strcmp(profile->bss_ssid, pp->bss_ssid) == 0) {
            if (pp->bss_state & MAP_BACKHAUL_BSS) {
                log_lib_e("Modifying backhaul is illegal");
                return -1;
            }

            mapping_get_by_pidx(pp->profile_idx, &ssid_idx);

            /* Remove profile */
            for (; i < profile_cnt - 1; i++) {
                map_profile_cfg_t tmp_profile = cfg->profiles[i + 1];

                profile_save(&tmp_profile, i);
            }
            profile_remove(profile_cnt - 1);

            profile_cnt = cfg->num_profiles - 1;;
            setpsm_int(MAP_PSM_SSIDNOE, profile_cnt);

            update = 1;
            break;
        }
    }

    if (update && g_map_cfg_cbs.profile_update_cb) {
        g_map_cfg_cbs.profile_update_cb();
    }

    if (0 && update && (int)ssid_idx > 0) {
        /* TODO */
        set_wifi_ssid_enable(ssid_idx, false);
        /* Super hack; we need to store radio idx */
        set_wifi_apply_settings((ssid_idx % 2) + 1);
    }

    return 0;
}

int map_profile_get_by_sidx(unsigned int ssid_idx, map_profile_cfg_t **profile)
{
    map_controller_cfg_t *cfg = &map_cfg_get()->controller_cfg;
    unsigned int          mapping_cnt;
    profile_ssid_map_t   *mapping;
    unsigned int          profile_cnt;
    int                   profile_idx;
    unsigned int          i;

    if (g_use_dynamic_mapping) {
        mapping = g_dynamic_mapping;
        mapping_cnt = ARRAY_SIZE(g_dynamic_mapping);
    } else {
        mapping = g_static_mapping;
        mapping_cnt = ARRAY_SIZE(g_static_mapping);
    }

    profile_idx = -1;
    for (i = 0; i < mapping_cnt; i++) {
        if (ssid_idx == mapping[i].ssid_idx) {
            profile_idx = mapping[i].profile_idx;
            break;
        }
    }

    *profile = NULL;
    if (profile_idx == -1) {
        return -1;
    }

    profile_cnt = cfg->num_profiles;
    for (i = 0; i < profile_cnt; i++) {
        if (profile_idx == cfg->profiles[i].profile_idx) {
            *profile = &cfg->profiles[i];
            return 0;
        }
    }

    return -1;
}

int map_profile_save(map_profile_cfg_t *profile)
{
    map_controller_cfg_t *cfg = &map_cfg_get()->controller_cfg;
    unsigned int          profile_cnt, i;

    profile_cnt = cfg->num_profiles;

    for (i = 0; i < profile_cnt; i++) {
        map_profile_cfg_t *pp = &cfg->profiles[i];

        if (profile->profile_idx == pp->profile_idx) {
            profile_save(profile, i);
            break;
        }
    }

    return 0;
}

int map_profile_update(void)
{
    if (g_map_cfg_cbs.profile_update_cb) {
        g_map_cfg_cbs.profile_update_cb();
    }

    return 0;
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
    unsigned int          i;

    log_lib_i("----------------------------------------------");
    log_lib_i("| --MAP PROFILES--");
    log_lib_i("----------------------------------------------");

    for (i = 0; i < cfg->num_profiles; i++) {
        log_lib_i("|  --profile %d--", i);
        dump_profile(&cfg->profiles[i]);
    }
}
