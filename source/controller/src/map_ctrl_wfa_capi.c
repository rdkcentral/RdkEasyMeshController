/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdlib.h>
#include <inttypes.h>
#include <ctype.h>

#define LOG_TAG "wfa_capi"

#include "map_ctrl_utils.h"
#include "map_ctrl_cmdu_tx.h"
#include "map_ctrl_defines.h"
#include "map_ctrl_tlv_helper.h"
#include "map_ctrl_wfa_capi.h"

#include "1905_tlvs.h"

/*#######################################################################
#                       CAPI STRINGS                                    #
########################################################################*/
/* See Control_API_specification.pdf v10.12.0
   According to the spec, all names should be case insensitive but in practice they are not...

   -> Status and response as in the examples...
*/

#define CAPI_CMD_DEV_GET_PARAMETER     "dev_get_parameter"
  #define CAPI_PARAM_PARAMETER         "parameter"
  #define CAPI_VAL_ALID                "aLid"
  #define CAPI_RESP_ALID               "aLid"

#define CAPI_CMD_DEV_SET_CONFIG        "dev_set_config"
  #define CAPI_PARAM_BSS_INFO          "bss_info"

#define CAPI_CMD_DEV_SEND_1905         "dev_send_1905"
  #define CAPI_PARAM_DESTALID          "DestALid"
  #define CAPI_PARAM_TLV_TYPE          "tlv_type"
  #define CAPI_PARAM_TLV_LENGTH        "tlv_length"
  #define CAPI_PARAM_TLV_VALUE         "tlv_value"
  #define CAPI_PARAM_MESSAGETYPEVALUE  "MessageTypeValue"
  #define CAPI_RESP_MID                "MID"

#define CAPI_STATUS                    "status"
#define CAPI_STATUS_COMPLETE           "COMPLETE"
#define CAPI_STATUS_INVALID            "INVALID"
#define CAPI_STATUS_ERROR              "ERROR"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define MAX_PARAMS  64

#define MAX_TLVS    32

#define MAX_TLV_LEN (1500 - 8) /* Max CMDU - CMDU header. */

#define DEFAULT_8021Q_SETTINGS_TLV_LEN 3

#define CAPI_DELIM ","

#define CAPI_MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define CAPI_MACSTR "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX"

/*#######################################################################
#                       TYPEDEF                                         #
########################################################################*/
typedef struct {
    int count;

    struct {
        char *name;
        char *val;
    } param[MAX_PARAMS];
} capi_params_t;

/*#######################################################################
#                       HELP FUNCTIONS                                  #
########################################################################*/
static char *capi_find_param_from_idx(capi_params_t *params, int from_idx, char *param)
{
    int i;

    for (i=from_idx; i<params->count; i++) {
        if (!strcasecmp(param, params->param[i].name)) {
            return params->param[i].val;
        }
    }

    return NULL;
}

static char *capi_find_param(capi_params_t *params, char *param)
{
    return capi_find_param_from_idx(params, 0, param);
}

static void capi_response(map_printf_cb_t print_cb, const char *status, const char *format, ...)
{
    char buf[256];
    int  pos = snprintf(buf, sizeof(buf), CAPI_STATUS",%s", status);

    va_list args;
    va_start(args, format);
    vsnprintf(&buf[pos], sizeof(buf) - pos, format, args);
    va_end(args);

    log_ctrl_i("  Response[%s]", buf);
    print_cb("%s", buf);
}

static bool capi_has_tlv(capi_params_t *params)
{
    int i;

    for (i=0; i<params->count; i++) {
        if (strcasestr(params->param[i].name, CAPI_PARAM_TLV_TYPE)) {
            return true;
        }
    }
    return false;
}

/*#######################################################################
#                       BSS_CONFIG                                      #
########################################################################*/
static int capi_handle_bss_config(map_controller_cfg_t* cfg, char *bss_cfg)
{
    /* Example: 02:AA:AA:AA:AA:AA 8x      Multi-AP-24G-1 0x0020 0x0008 maprocks1 0  1
                AL_MAC            OPCLASS SSID           AUTH   ENCR   KEY       BH FH
    */
    map_profile_cfg_t *profile            = NULL;
    uint8_t            alid[MAC_ADDR_LEN] = {0};
    uint16_t           freq_band          = 0;
    char              *p, *save_ptr = NULL;

    if (!bss_cfg) {
        goto fail;
    }

    log_ctrl_i("  Handle bss_config[%s]", bss_cfg);

    if (!(p = strtok_r(bss_cfg, " ", &save_ptr))) {
        log_ctrl_e("  Alid not found in bss_config[%s]", bss_cfg);
        goto fail;
    }

    if (mac_from_string(p, alid)) {
        log_ctrl_e("  Invalid alid[%s]", p);
        goto fail;
    }

    if (!(p = strtok_r(NULL, " ", &save_ptr))) {
        log_ctrl_e("  Operating class not found in bss_config[%s]", bss_cfg);
        goto fail;
    }

    if (!strcasecmp(p, "8x")) {
        freq_band = MAP_M2_BSS_RADIO2G;
    } else if (!strcasecmp(p, "11x")) {
        freq_band = MAP_M2_BSS_RADIO5GL;
    } else if (!strcasecmp(p, "12x")) {
        freq_band = MAP_M2_BSS_RADIO5GU;
    } else {
        log_ctrl_e("  Invalid operating class[%s]", p);
        goto fail;
    }

    /* Next is ssid. If not present, then all matching profiles need to be removed */
    if (!(p = strtok_r(NULL, " ", &save_ptr))) {
        log_ctrl_i("Remove bss_configs");
        return 0; /* Cred where already removed... */
    }

    /* Add... */
    if (map_profile_realloc(cfg->num_profiles + 1)) {
        log_ctrl_e("  Adding profile failed");
        return -1;
    }

    profile = &cfg->profiles[cfg->num_profiles];
    memset(profile, 0, sizeof(map_profile_cfg_t));
    maccpy(profile->al_mac, alid);
    map_strlcpy(profile->bss_ssid, p, sizeof(profile->bss_ssid));
    profile->enabled        = 1;
    profile->bss_freq_bands = freq_band;
    profile->gateway        = 1;
    profile->extender       = 1;
    profile->vlan_id        = -1;

    if (!(p = strtok_r(NULL, " ", &save_ptr))) {
        log_ctrl_e("  Auth type not found in bss_config[%s]", bss_cfg);
        goto fail;
    }

    if (1 != sscanf(p, "%"SCNx16, &profile->supported_auth_modes)) {
        log_ctrl_e("  Invalid auth type[%s]", p);
        goto fail;
    }

    if (!(p = strtok_r(NULL, " ", &save_ptr))) {
        log_ctrl_e("  Encr type not found in bss_config[%s]", bss_cfg);
        goto fail;
    }

    if (1 != sscanf(p, "%"SCNx16, &profile->supported_encryption_types)) {
        log_ctrl_e("  Invalid encr type[%s]", p);
        goto fail;
    }

    if (!(p = strtok_r(NULL, " ", &save_ptr))) {
        log_ctrl_e("  Key not found in bss_config[%s]", bss_cfg);
        goto fail;
    }
    map_strlcpy(profile->wpa_key, p, sizeof(profile->wpa_key) );

    if (!(p = strtok_r(NULL, " ", &save_ptr))) {
        log_ctrl_e("  Backhaul bit not found in bss_config[%s]", bss_cfg);
        goto fail;
    }

    if (strtoul(p, NULL, 10)) {
        profile->bss_state |= MAP_BACKHAUL_BSS;
    }

    if (!(p = strtok_r(NULL, " ", &save_ptr))) {
        log_ctrl_e("  Fronthaul bit not found in bss_config[%s]", bss_cfg);
        goto fail;
    }

    if (strtoul(p, NULL, 10)) {
        profile->bss_state |= MAP_FRONTHAUL_BSS;
    }

    cfg->num_profiles++;

    return 0;

fail:
    return -1;
}

/*#######################################################################
#                       TLV HANDLING                                    #
########################################################################*/
static int capi_get_tlv_length_value(capi_params_t *params, int from_idx, char *postfix, char **length, char **value)
{
    char buf[64];

    snprintf(buf, sizeof(buf), CAPI_PARAM_TLV_LENGTH"%s", postfix);
    *length = capi_find_param_from_idx(params, from_idx, buf);

    snprintf(buf, sizeof(buf), CAPI_PARAM_TLV_VALUE"%s", postfix);
    *value = capi_find_param_from_idx(params, from_idx, buf);

    return *length && *value ? 0 : -1;
}

/* Remove 0x, spaces, { and } */
static int capi_tlv_hex_to_bin(uint8_t *buf, int buf_len, uint16_t *bin_len, char *str)
{
    uint8_t *p = buf, *e = &buf[buf_len];
    char    *q = str;

    while(*q && p < e) {
        char c = q[0], d = q[1];
        if (!strncasecmp(q, "0x", 2)) {
            q+=2;
        } else if (isblank(c) || c == '{' || c == '}') {
            q++;
        } else if (isxdigit(c) && isxdigit(d)) {
            char h[3] = {c, d, 0};
            if (p == e) {
                log_ctrl_e("  TLV too long");
                goto fail;
            }
            if (1 != sscanf(h, "%"SCNx8, p++)) {
                log_ctrl_e("  hex conversion failed");
                goto fail;
            }
            q+=2;
        } else if (isxdigit(c) && (isblank(d) || d == '}')) {
            /* Test case 5.14.4... This is all so inconsitent... */
            *p++ = isdigit(c) ? c - '0' : isupper(c) ? c - 'A' + 10 : c - 'a' + 10;
            q++;
        } else {
            log_ctrl_e("  Invalid TLV value[%s]", str);
            goto fail;
        }
    }

    *bin_len = p - buf;

    return 0;

fail:
    return -1;
}

static uint8_t *capi_parse_default_8021q_settings_tlv(uint16_t length, char *value_str)
{
    /* Example: {0x000A 0x00} */
    map_cfg_t                        *cfg = map_cfg_get();
    map_default_8021q_settings_tlv_t *tlv;
    uint8_t                           buf[DEFAULT_8021Q_SETTINGS_TLV_LEN];
    uint16_t                          bin_length;
    uint16_t                          pvid;
    uint8_t                           pcp;
    uint8_t                          *p = buf;

    log_ctrl_i("  Handle Default 8021Q Settings TLV [%s]", value_str);

    if (DEFAULT_8021Q_SETTINGS_TLV_LEN != length) {
        log_ctrl_e("  Invalid length[%d]", length);
        goto fail;
    }

    if (capi_tlv_hex_to_bin(buf, sizeof(buf), &bin_length, value_str)) {
        goto fail;
    }

    if (DEFAULT_8021Q_SETTINGS_TLV_LEN != bin_length) {
        log_ctrl_e("  Invalid bin length[%d]", bin_length);
        goto fail;
    }

    _E2B(&p, &pvid);
    _E1B(&p, &pcp);

    log_ctrl_i("  Primary_vid[%d] pcp[%d]", pvid, pcp);
    cfg->primary_vlan_id = pvid;
    cfg->default_pcp = pcp;

    if ((tlv = calloc(1, sizeof(map_default_8021q_settings_tlv_t)))) {
        map_fill_default_8021q_settings_tlv(cfg, tlv);
    }

    return (uint8_t*)tlv;

fail:
    return NULL;
}

static uint8_t *capi_parse_traffic_separation_policy_tlv(uint16_t length, char *value_str)
{
    /* Example: {0x02 {0x0E Multi-AP-24G-1 0x000A} {0x0E Multi-AP-24G-2 0x0014}}
                SSID is in plain text -> cannot use capi_tlv_hex_to_bin...
    */
    map_controller_cfg_t                *cfg = get_controller_cfg();
    map_traffic_separation_policy_tlv_t *tlv;
    size_t                               i, j;
    uint8_t                              num_ssid;
    uint16_t                             ssid_len, vid;
    char                                 ssid[MAX_SSID_LEN];
    char                                *p;

    (void) length;

    log_ctrl_i("  Handle Traffic Separation Policy TLV [%s]", value_str);

    if (!(p = strcasestr(value_str, "0x")) || 1 != sscanf(p, "%"SCNx8, &num_ssid)) {
        goto fail;
    }
    log_ctrl_i("  num_ssid[%d]", num_ssid);

    for (i = 0; i < num_ssid; i++) {
        if (!(p = strcasestr(&p[2], "0x")) || 1 != sscanf(p, "%"SCNx16, &ssid_len) || ssid_len > (MAX_SSID_LEN - 1)) {
           goto fail;
        }

        if (!(p = strchr(p, ' '))) {
            goto fail;
        }
        while(*p==' ' || *p=='\t') p++;

        memcpy(ssid, p, ssid_len);
        ssid[ssid_len] = 0;

        p+=ssid_len;

        if (!(p = strcasestr(p, "0x")) || 1 != sscanf(p, "%"SCNx16, &vid)) {
            goto fail;
        }

        log_ctrl_i("  ssid[%s] vid[%d]", ssid, vid);

        /* Set vlan_id in profiles */
        for (j = 0; j<cfg->num_profiles; j++) {
            map_profile_cfg_t *profile = &cfg->profiles[j];
            if (!strcmp(profile->bss_ssid, ssid)) {
                profile->vlan_id = vid;
            }
        }
    }

    if ((tlv = calloc(1, sizeof(map_traffic_separation_policy_tlv_t)))) {
        map_fill_traffic_separation_policy_tlv(cfg, map_cfg_get()->primary_vlan_id, /* max_vid */16, tlv);
    }

    return (uint8_t*)tlv;

fail:
    return NULL;
}

static uint8_t *capi_parse_tlv(char *type_str, char* length_str, char *value_str)
{
    uint8_t   buf[MAX_TLV_LEN];
    uint8_t   type;
    uint16_t  length, bin_length;
    uint8_t  *p = buf;

    if (1 != sscanf(type_str, "%"SCNx8, &type)) {
        log_ctrl_e("  Invalid TLV type[%s]", type_str);
        goto fail;
    }
    _I1B(&type, &p);

    if (1 != sscanf(length_str, "%"SCNx16, &length)) {
        log_ctrl_e("  Invalid TLV length[%s]", length_str);
        goto fail;
    }
    _I2B(&length, &p);

    /* Special handling of Traffic separation TLV
       - update config too
       - TS policy has SSID in plaintext and not in hex
    */
    if (/* 0xB5 */ TLV_TYPE_DEFAULT_8021Q_SETTINGS == type) {
        return capi_parse_default_8021q_settings_tlv(length, value_str);
    } else if (/* 0xB6 */ TLV_TYPE_TRAFFIC_SEPARATION_POLICY == type) {
        return capi_parse_traffic_separation_policy_tlv(length, value_str);
    }

    if (capi_tlv_hex_to_bin(p, sizeof(buf) - (p - buf), &bin_length, value_str)) {
        goto fail;
    }

    if (bin_length != length) {
        log_ctrl_e("  Length mismatch [%d - %d]", bin_length, length);
        goto fail;
    }

    return parse_1905_TLV_from_packet(buf, length + 3 /* add header */);

fail:
    return NULL;
}

/*#######################################################################
#                       CAPI HANDLERS                                   #
########################################################################*/
static int capi_dev_get_parameter(capi_params_t *params, map_printf_cb_t print_cb)
{
    /* Example: dev_get_parameter,program,map,parameter,ALid */

    char *p = capi_find_param(params, CAPI_PARAM_PARAMETER);

    if (!p) {
        log_ctrl_e("  param[%s] not found", CAPI_PARAM_PARAMETER);
        goto fail;
    }

    /* Only "alid" is supported... */
    if (!strcasecmp(CAPI_VAL_ALID, p)) {
        capi_response(print_cb, CAPI_STATUS_COMPLETE, ","CAPI_RESP_ALID","CAPI_MACSTR"", CAPI_MAC2STR(get_controller_cfg()->al_mac));
        return 0;
    }

fail:
    capi_response(print_cb, CAPI_STATUS_INVALID, "");
    return -1;
}

static int capi_dev_set_config(capi_params_t *params, map_printf_cb_t print_cb)
{
    /* Example: dev_set_config,program,map,bss_info1,02:AA:AA:AA:AA:AA 8x Multi-AP-24G-1 0x0020 0x0008 maprocks1 0 1,bss_info2,02:AA:AA:AA:AA:AA 8x Multi-AP-24G-2 0x0020 0x0008 maprocks2 1 0 */

    map_controller_cfg_t *cfg = get_controller_cfg();
    uint8_t              *tlv;
    int                   i;
    bool                  reset_profiles = true;
    char                 *type, *length, *value;

    /* Find all bss_info parameters */
    for (i=0; i<params->count; i++) {
        if (!strcasestr(params->param[i].name, CAPI_PARAM_BSS_INFO)) {
            continue;
        }

        /* From the documentation it is not clear that a new dev_set_config has to replace all.
           A "delete" command is defined but e.g in test 5.4.2 credentials are changed without
           deleting.
        */
        if (reset_profiles) {
            log_ctrl_i("  Clear profiles");
            cfg->num_profiles = 0;
            reset_profiles = false;
        }

        if (capi_handle_bss_config(cfg, params->param[i].val)) {
            log_ctrl_e("  Handle bss_config[%s] failed", params->param[i].val);
            goto fail;
        }
    }

    /* Find all TLV (this is only used for traffic separation tests) */
    for (i=0; i<params->count; i++) {
        char *name = params->param[i].name;
        if (!strcasestr(name, CAPI_PARAM_TLV_TYPE)) {
            continue;
        }

        type = params->param[i].val;
        /* TLV "number" resets after each bss_config -> search length/value after tlv_typex ... " */
        if (capi_get_tlv_length_value(params, i, &name[sizeof(CAPI_PARAM_TLV_TYPE) - 1], &length, &value)) {
            log_ctrl_e("  No length or value found for TLV parameter[%s]", name);
            goto fail;
        }

        if (NULL == (tlv = capi_parse_tlv(type, length, value))) {
            log_ctrl_e("  Invalid TLV type[%s] length[%s] value[%s]", type, length, value);
            goto fail;
        }
        free(tlv);
    }

    map_profile_dump(cfg);

    capi_response(print_cb, CAPI_STATUS_COMPLETE, "");
    return 0;

fail:
    capi_response(print_cb, CAPI_STATUS_INVALID, "");
    return -1;
}

static int capi_dev_send_1905_parse_forge(map_ale_info_t *ale, uint16_t message_type, capi_params_t *params, uint16_t *mid)
{
    i1905_cmdu_t cmdu       = {0};
    uint8_t *tlvs[MAX_TLVS] = {0};
    int      tlv_count = 0;
    int      i;
    int      ret = -1;
    char    *type, *length, *value;

    /* Find and parse all TLV */
    for (i=0; i<params->count && tlv_count<MAX_TLVS - 1; i++) {
        char *name = params->param[i].name;
        if (!strcasestr(name, CAPI_PARAM_TLV_TYPE)) {
            continue;
        }

        type = params->param[i].val;
        if (capi_get_tlv_length_value(params, 0, &name[sizeof(CAPI_PARAM_TLV_TYPE) - 1], &length, &value)) {
            log_ctrl_e("  No length or value found for TLV parameter[%s]", name);
            goto fail;
        }

        if (NULL == (tlvs[tlv_count] = capi_parse_tlv(type, length, value))) {
            log_ctrl_e("  Invalid TLV type[%s] length[%s] value[%s]", type, length, value);
            goto fail;
        }
        tlv_count++;
    }

    if (tlv_count == MAX_TLVS - 1) {
        log_ctrl_e("  Too many TLV");
        goto fail;
    }

    tlvs[tlv_count++] = NULL; /* end of message tlv */

    /* Create and send CMDU */
    cmdu.message_version  = CMDU_MESSAGE_VERSION_1905_1_2013;
    cmdu.message_type     = message_type;
    cmdu.message_id       = 0;
    cmdu.relay_indicator  = 0; /* Always ok? */
    cmdu.list_of_TLVs     = tlvs;

    strncpy(cmdu.interface_name, ale->iface_name, sizeof(cmdu.interface_name));

    if (map_send_cmdu(ale->al_mac, &cmdu, mid)) {
        goto fail;
    }

    ret = 0;

fail:
    for (i = 0; i<tlv_count; i++) {
        free_1905_TLV_structure(tlvs[i]);
    }
    return ret;
}

static int capi_dev_send_1905(capi_params_t *params, map_printf_cb_t print_cb)
{
    /* Example: dev_send_1905,DestALid,00:AA:AA:AA:AA:AA,MessageTypeValue,0x0002 */

    char           *dest_alid_str    = capi_find_param(params, CAPI_PARAM_DESTALID);
    char           *message_type_str = capi_find_param(params, CAPI_PARAM_MESSAGETYPEVALUE);
    mac_addr        dest_alid = {0};
    uint16_t        message_type = 0;
    map_ale_info_t *ale = NULL;
    uint16_t        mid = 0;

    if (!dest_alid_str) {
        log_ctrl_e("  Param[%s] not found", CAPI_PARAM_DESTALID);
        goto fail;
    }

    if (mac_from_string(dest_alid_str, dest_alid)) {
        log_ctrl_e("  Invalid val[%s] for param[%s]", dest_alid_str, CAPI_PARAM_DESTALID);
        goto fail;
    }

    if (!(ale = map_dm_get_ale(dest_alid))) {
        log_ctrl_e("  Ale[%s] not found in DM", dest_alid_str);
        goto fail;
    }

    if (!message_type_str) {
        log_ctrl_e("  Param[%s] not found", CAPI_PARAM_MESSAGETYPEVALUE);
        goto fail;
    }

    if (1 != sscanf(message_type_str, "%"SCNx16, &message_type)) {
        log_ctrl_e("  Invalid val[%s] for param[%s]", message_type_str, CAPI_PARAM_MESSAGETYPEVALUE);
        goto fail;
    }

    switch(message_type) {
        case /* 0x0002 */ CMDU_TYPE_TOPOLOGY_QUERY:
            log_ctrl_i("  Send Topology Query");
            if (map_send_topology_query(ale, &mid)) {
                goto fail;
            }
        break;
        case /* 0x0005 */ CMDU_TYPE_LINK_METRIC_QUERY:
            log_ctrl_i("  Send Link Metrics Query");
            if (capi_dev_send_1905_parse_forge(ale, message_type, params, &mid)) {
                goto fail;
            }
        break;
        case /* 0x000A */ CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW: {
            mac_addr mcast_mac;

            log_ctrl_i("  Send Autoconfig Renew");
            i1905_get_mcast_mac(mcast_mac);

            if (map_send_autoconfig_renew(IEEE80211_FREQUENCY_BAND_2_4_GHZ, &mid)) {
                goto fail;
            }
        }
        break;
        case /* 0x8001 */ CMDU_TYPE_MAP_AP_CAPABILITY_QUERY:
            log_ctrl_i("  Send AP Capability Query");
            if (map_send_ap_capability_query(ale, &mid)) {
                goto fail;
            }
        break;
        case /* 0x8003 */ CMDU_TYPE_MAP_MULTI_AP_POLICY_CONFIG_REQUEST:
            log_ctrl_i("  Send Policy Config Request");
            if (capi_dev_send_1905_parse_forge(ale, message_type, params, &mid)) {
                goto fail;
            }
        break;
        case /* 0x8004 */ CMDU_TYPE_MAP_CHANNEL_PREFERENCE_QUERY:
            log_ctrl_i("  Send Channel Preference Query");
            if (map_send_channel_preference_query(ale, &mid)) {
                goto fail;
            }
        break;
        case /* 0x8006 */ CMDU_TYPE_MAP_CHANNEL_SELECTION_REQUEST:
            log_ctrl_i("  Send Channel Selection Request");
            /* If TLV present, send those, otherwise (test 5.5.1) construct request ourselves
               NOTE: In 5.5.1, BRCM seems to send empty channel request which does not match requirement
                     in testplan (5.5.1 step 5) but test script does not seem to check it.
            */
            if (capi_has_tlv(params)) {
                if (capi_dev_send_1905_parse_forge(ale, message_type, params, &mid)) {
                    goto fail;
                }
            } else {
                map_chan_select_pref_type_t pref_type = {.ale = ale, .radio = NULL, .pref = MAP_CHAN_SEL_PREF_AGENT};
                if (map_send_channel_selection_request(&pref_type, &mid)) {
                    goto fail;
                }
            }
        break;
        case /* 0x8009 */ CMDU_TYPE_MAP_CLIENT_CAPABILITY_QUERY:
            log_ctrl_i("  Send Client Capability Query");
            if (capi_dev_send_1905_parse_forge(ale, message_type, params, &mid)) {
                goto fail;
            }
        break;
        case /* 0x800B */ CMDU_TYPE_MAP_AP_METRICS_QUERY:
            log_ctrl_i("  Send AP Metrics Query");
            if (capi_dev_send_1905_parse_forge(ale, message_type, params, &mid)) {
                goto fail;
            }
        break;
        case /* 0x8013 */ CMDU_TYPE_MAP_COMBINED_INFRASTRUCTURE_METRICS:
            log_ctrl_i("  Send Combined Infrastructure Metrics");
            if (map_send_combined_infrastructure_metrics(ale, &mid)) {
                goto fail;
            }
        break;
        case /* 0x8014 */ CMDU_TYPE_MAP_CLIENT_STEERING_REQUEST:
            log_ctrl_i("  Send Client Steering Request");
            if (capi_dev_send_1905_parse_forge(ale, message_type, params, &mid)) {
                goto fail;
            }
        break;
        case /* 0x8016 */ CMDU_TYPE_MAP_CLIENT_ASSOCIATION_CONTROL_REQUEST:
            log_ctrl_i("  Send Client Association Control Request");
            if (capi_dev_send_1905_parse_forge(ale, message_type, params, &mid)) {
                goto fail;
            }
        break;
        case /* 0x8018 */ CMDU_TYPE_MAP_HIGHER_LAYER_DATA:
            log_ctrl_i("  Send Higher Layer Data");
            if (capi_dev_send_1905_parse_forge(ale, message_type, params, &mid)) {
                goto fail;
            }
        break;
        case /* 0x801B */ CMDU_TYPE_MAP_CHANNEL_SCAN_REQUEST:
            log_ctrl_i("  Send Channel Scan Request");
            if (capi_dev_send_1905_parse_forge(ale, message_type, params, &mid)) {
                goto fail;
            }
        break;
        case /* 0x8020 */ CMDU_TYPE_MAP_CAC_REQUEST:
            log_ctrl_i("  Send CAC Request");
            if (capi_dev_send_1905_parse_forge(ale, message_type, params, &mid)) {
                goto fail;
            }
        break;
        case /* 0x8021 */ CMDU_TYPE_MAP_CAC_TERMINATION:
            log_ctrl_i("  Send CAC Termination");
            if (capi_dev_send_1905_parse_forge(ale, message_type, params, &mid)) {
                goto fail;
            }
        break;
        default:
            log_ctrl_e("  Unhandled message");
            goto fail;
        break;
     }

    capi_response(print_cb, CAPI_STATUS_COMPLETE, ","CAPI_RESP_MID",0x%04X", mid);
    return 0;

fail:
    capi_response(print_cb, CAPI_STATUS_INVALID, "");
    return -1;
}

/*#######################################################################
#                      FUNCTIONS                                        #
########################################################################*/
int map_ctrl_wfa_capi(char *line, map_printf_cb_t print_cb)
{
    capi_params_t  params = {.count = 0};
    char          *save_ptr = NULL;
    char          *cmd = NULL;
    int            pos = strlen(line) - 1;

    log_ctrl_i("CAPI[%s]", line);

    if (!WFA_CERT()) {
        log_ctrl_e("  Wfa_cert is disabled");
        goto fail;
    }

    /* Remove all space/tab/newline at the end */
    while(pos >= 0 && (isblank(line[pos]) || line[pos] == '\n')) {
        line[pos] = 0;
        pos--;
    }

    if (NULL == (cmd = strtok_r(line, CAPI_DELIM, &save_ptr))) {
        log_ctrl_e("  No command found");
        goto fail;
    }
    log_ctrl_i("  Command[%s]", cmd);

    /* Get all params */
    do {
        if (NULL == (params.param[params.count].name = strtok_r(NULL, CAPI_DELIM, &save_ptr))) {
            break;
        }
        if (NULL == (params.param[params.count].val = strtok_r(NULL, CAPI_DELIM, &save_ptr))) {
            log_ctrl_e("  No value for param[%s]", params.param[params.count].name);
            goto fail;
        }
        log_ctrl_i("    param[%d] name[%s] val[%s]", params.count, params.param[params.count].name, params.param[params.count].val);
        params.count++;
    } while(params.count < MAX_PARAMS);

    if (params.count == MAX_PARAMS) {
        log_ctrl_e("  Too may params");
        goto fail;
    }

    /* Handle command */
    if (!strcasecmp(cmd, CAPI_CMD_DEV_GET_PARAMETER)) {
        return capi_dev_get_parameter(&params, print_cb);
    } else if (!strcasecmp(cmd, CAPI_CMD_DEV_SET_CONFIG)) {
        return capi_dev_set_config(&params, print_cb);
    } else if (!strcasecmp(cmd, CAPI_CMD_DEV_SEND_1905)) {
        return capi_dev_send_1905(&params, print_cb);
    }

fail:
    capi_response(print_cb, CAPI_STATUS_INVALID, "");
    return -1;
}
