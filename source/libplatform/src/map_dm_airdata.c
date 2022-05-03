/*
 * Copyright (c) 2021-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#define LOG_TAG "dm_airdata"

#include "map_utils.h"
#include "map_config.h"
#include "map_topology_tree.h"
#include "1905_platform.h"

/* NOTES:
- At this moment object indexes are not preserved
- Indexes start from 0.  In case of TR69 functions +1 is needed
- Local agent is added already during init to assure it gets index 0
*/

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/

/*#######################################################################
#                       PRIVATE FUNCTIONS                               #
########################################################################*/
static inline bool is_controller_mac(mac_addr mac)
{
    return !maccmp(mac, map_cfg_get()->controller_cfg.al_mac);
}

static inline bool is_local_agent(map_ale_info_t *ale)
{
    return ale->is_local;
}

struct stub_radio {
    const char *radio_id_str;
    const char *bss[16];
};

struct stub_ap {
    char *al_mac_str;
    struct stub_radio radio[4];
};

struct stub_ap g_ap_list[16];

static void remove_all_ap_device(void)
{
    memset(&g_ap_list, 0, sizeof(g_ap_list));
}

static int get_device_idx(map_ale_info_t *ale, unsigned int *device_idx)
{
    unsigned int idx;
    int found = 0;

    /* Cached index ? */
    if (ale->airdata_idx >= 0) {
        *device_idx = ale->airdata_idx;
        return 0;
    }

    for (idx = 0; idx < 16; idx++) {
        if (g_ap_list[idx].al_mac_str && strcmp(g_ap_list[idx].al_mac_str, ale->al_mac_str) == 0) {
            found = 1;
            break;
        }
    }
    if (!found) {
        return -1;
    }

    ale->airdata_idx = *device_idx = idx;

    return 0;
}

static int get_radio_idx(unsigned int device_idx, map_radio_info_t *radio, unsigned int *radio_idx)
{
    unsigned int idx;
    int found = 0;

    /* Cached index ? */
    if (radio->airdata_idx >= 0) {
        *radio_idx = radio->airdata_idx;
        return 0;
    }

    for (idx = 0; idx < 4; idx++) {
        if (g_ap_list[device_idx].radio[idx].radio_id_str && strcmp(g_ap_list[device_idx].radio[idx].radio_id_str, radio->radio_id_str) == 0) {
            found = 1;
            break;
        }
    }
    if (!found) {
        return -1;
    }

    radio->airdata_idx = *radio_idx = idx;

    return 0;
}

static int get_ap_idx(unsigned int device_idx, unsigned int radio_idx, map_bss_info_t *bss, unsigned int *ap_idx)
{
    unsigned int idx;
    int found = 0;

    /* Cached index ? */
    if (bss->airdata_idx >= 0) {
        *ap_idx = bss->airdata_idx;
        return 0;
    }

    for (idx = 0; idx < 16; idx++) {
        if (g_ap_list[device_idx].radio[radio_idx].bss[idx] && strcmp(g_ap_list[device_idx].radio[radio_idx].bss[idx], bss->bssid_str) == 0) {
            found = 1;
            break;
        }
    }
    if (!found) {
        return -1;
    }

    bss->airdata_idx = *ap_idx = idx;

    return 0;
}

static int get_device_radio_idx(map_ale_info_t *ale, map_radio_info_t *radio,
                                unsigned int *device_idx, unsigned int *radio_idx)
{
    return (0 == get_device_idx(ale, device_idx)) &&
           (0 == get_radio_idx(*device_idx, radio, radio_idx)) ? 0 : -1;
}

static unsigned int get_device_radio_ap_idx(map_ale_info_t *ale, map_radio_info_t *radio, map_bss_info_t *bss,
                                            unsigned int *device_idx, unsigned int *radio_idx, unsigned int *ap_idx)
{
    return  (0 == get_device_radio_idx(ale, radio, device_idx, radio_idx)) &&
            (0 == get_ap_idx(*device_idx, *radio_idx, bss, ap_idx)) ? 0 : -1;
}

static void invalidate_ale_idx()
{
    map_ale_info_t *ale;

    map_dm_foreach_agent_ale(ale) {
        if (!is_local_agent(ale)) {
            ale->airdata_idx = -1;
        }
    }
}

static void invalidate_radio_idx(map_ale_info_t *ale)
{
    map_radio_info_t *radio;

    map_dm_foreach_radio(ale, radio) {
        radio->airdata_idx = -1;
    }
}

static void invalidate_bss_idx(map_radio_info_t *radio)
{
    map_bss_info_t *bss;

    map_dm_foreach_bss(radio, bss) {
        bss->airdata_idx = -1;
    }
}

static void mark_bsss_removed(map_radio_info_t *radio)
{
    map_bss_info_t *bss;

    map_dm_foreach_bss(radio, bss) {
        bss->airdata_removed = true;
    }
}

static void mark_radios_removed(map_ale_info_t *ale)
{
    map_radio_info_t *radio;

    map_dm_foreach_radio(ale, radio) {
        radio->airdata_removed = true;
        mark_bsss_removed(radio);
    }
}

static bool is_radio_5g_low_high(map_radio_info_t *radio)
{
    return (radio->supported_freq == IEEE80211_FREQUENCY_BAND_5_GHZ) &&
           (radio->band_type_5G & MAP_M2_BSS_RADIO5GL) &&
           (radio->band_type_5G & MAP_M2_BSS_RADIO5GU);
}

/*#######################################################################
#                       DATA HELPERS                                    #
########################################################################*/
/* Strings created in functions below must be according to tr181 */

static char *get_oui_str(mac_addr_oui oui, char *buf, size_t buf_len)
{
    /* Upper case and no separator */
    snprintf(buf, buf_len, "%02hhX%02hhX%02hhX", oui[0], oui[1], oui[2]);

    return buf;
}

static char *get_sw_version_str(uint32_t os_version, char *buf, size_t buf_len)
{
    uint8_t *p = (uint8_t*)&os_version;

    snprintf(buf, buf_len, "%d.%d.%d.%d",
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
             p[0] & 0x7f, p[1], p[2], p[3]);
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
             p[3] & 0x7f, p[2], p[1], p[0]);
#else
  #error Not big and not little endian
#endif

    return buf;
}

static char *get_backhaul_link_type_str(map_ale_info_t *ale)
{
    int iface_group = INTERFACE_TYPE_GROUP_GET(ale->upstream_iface_type);

    if (is_local_agent(ale)) {
        return "None";
    } else if (iface_group == INTERFACE_TYPE_GROUP_WLAN) {
        return "Wi-Fi";
    } else if (iface_group == INTERFACE_TYPE_GROUP_ETHERNET) {
        return "Ethernet";
    } else {
        return "None"; /* Not yet known but that is no valid option */
    }
}

static char *get_freq_band_str(bool is_2g)
{
    return is_2g ? "2.4GHz" : "5GHz";
}

static char* get_radio_standards_str(map_radio_info_t *radio, char *buf, size_t buf_len)
{
    bool is_2g = radio->supported_freq == IEEE80211_FREQUENCY_BAND_2_4_GHZ;

    if (is_2g) {
        snprintf(buf, buf_len, "b,g%s%s", radio->ht_caps ? ",n" : "", radio->he_caps ? ",ax" : "");
    } else {
        snprintf(buf, buf_len, "a%s%s%s", radio->ht_caps ? ",n" : "", radio->vht_caps ? ",ac" : "", radio->he_caps ? ",ax" : "");
    }

    return buf;
}

static char *get_ext_channel_str(int type)
{
    switch(type) {
        case MAP_EXT_CHANNEL_ABOVE: return "AboveControlChannel";
        case MAP_EXT_CHANNEL_BELOW: return "BelowControlChannel";
        default:                    return "None";
    }
}

/* TODO: Do this when radio basic cap tlv is needed as something simular is done in map_ctrl_msg_glue.c
         Preferably as a bit mask so the result below ends up sorted as well.
*/
static char *get_supported_channels_str(map_radio_info_t *radio, char *buf, int buf_len)
{
    map_controller_cfg_t *cfg            = &map_cfg_get()->controller_cfg;
    bandlock_5g_t         bandlock_5g    = cfg->bandlock_5g;
    bool                  is_5g_low_high = is_radio_5g_low_high(radio);
    wifi_channel_set      ch_set;
    int                   i, j, k, pos = 0;
    uint8_t               bw;

    buf[0] = 0;

    if (radio->cap_op_class_list.op_classes_nr == 0) {
        return buf;
    }

    /* Fill supported channel set based on 20MHz operating classes */
    for (i = 0; i < radio->cap_op_class_list.op_classes_nr; i++) {
        map_op_class_t *op_class = &radio->cap_op_class_list.op_classes[i];

        if (get_bw_from_operating_class(op_class->op_class, &bw) || bw != 20) {
            continue;
        }
        if (get_channel_set_for_rclass(op_class->op_class, &ch_set)) {
            continue;
        }

        /* Skip any op class that is not allowed because of 5G bandlock */
        if (is_5g_low_high && bandlock_5g != MAP_BANDLOCK_5G_DISABLED) {
            if ((bandlock_5g == MAP_BANDLOCK_5G_LOW  && !map_is_5g_low_op_class(op_class->op_class)) ||
                (bandlock_5g == MAP_BANDLOCK_5G_HIGH && !map_is_5g_high_op_class(op_class->op_class))) {
                continue;
            }
        }

        /* Add all channels */
        for (j = 0; j < ch_set.length && pos < buf_len; j++) {
            uint8_t channel = ch_set.ch[j];

            /* Check if allowed by config */
            if (!map_is_channel_set(&cfg->allowed_channel_set_2g, channel) &&
                !map_is_channel_set(&cfg->allowed_channel_set_5g, channel)) {
                continue;
            }

            /* Check if in unallowed list */
            for (k = 0; k < op_class->channel_count; k++) {
                if (channel == op_class->channel_list[k]) {
                    break;
                }
            }
            if (k == op_class->channel_count) {
                pos += snprintf(&buf[pos], buf_len - pos, "%d,", channel);
            }
        }
    }

    /* Remove space at the end */
    if (pos > 0 && pos < buf_len) {
        buf[pos - 1] = 0;
    }

    return buf;
}

static char *get_bw_str(int bw)
{
    switch(bw) {
        case 160: return "160MHz";
        case 80:  return "80MHz";
        case 40:  return "40MHz";
        case 20:  return "20MHz";
        default:  return "Auto";
    }
}

/* Find eirp for current op class */
static int get_max_power(map_radio_info_t *radio)
{
    int i;

    for (i = 0; i < radio->cap_op_class_list.op_classes_nr; i++) {
        map_op_class_t *op_class = &radio->cap_op_class_list.op_classes[i];

        if (op_class->op_class == radio->current_op_class) {
            return UINT8_2S_COMPLEMENT_TO_INT(op_class->eirp);
        }
    }
    return 0;
}

/* Get current power in percent (linear scale) */
static int get_pct_power(int max_power, int cur_power)
{
#define NUM_PCT 11
    static uint8_t pct_power[NUM_PCT] = {100, 79, 63, 50, 40, 32, 25, 20, 16, 13, 10};
    int delta                         = max_power - cur_power;

    if (delta < 0) {
        delta = 0;
    } else if (delta >= NUM_PCT) {
        delta = NUM_PCT - 1;
    }

    return pct_power[delta];

}

/*#######################################################################
#                       Device.WiFi.MultiAP.APDevice                    #
########################################################################*/
/* Notes:
   - AssocIeee1905DeviceRef is set to al mac. (We don't have Device.IEEE1905 and written in Telstra spec)
   - ManufacturerOUI cannot be filled in
   - LastContactTime and Backhaul stats set via airbus query
*/

static void create_ale_mac(mac_addr mac, int *ret_idx)
{
    mac_addr_oui      oui       = {mac[0] & 0xfd, mac[1], mac[2]}; /* reset locally admin bit */
    mac_addr_str      mac_str;
    mac_addr_oui_str  oui_str;
    char             *p_mac_str = mac_str;
    char             *p_oui_str = oui_str;
    unsigned int      idx;

    mac_to_string(mac, mac_str);

    for (idx = 0; idx < 16; idx++) {
        if (g_ap_list[idx].al_mac_str == NULL) {
            g_ap_list[idx].al_mac_str = strdup(p_mac_str);
            break;
        }
    }

    if (ret_idx) {
        *ret_idx = idx;
    }

    get_oui_str(oui, oui_str, sizeof(oui_str));

    /* Set MAC */
    fprintf(stderr, BBLUE">>>>create ale[%d]: %s"NORM"\n", idx, p_mac_str);
    fprintf(stderr, BBLUE"  p_oui_str: %s"NORM"\n", p_oui_str);

    return;
}

static void map_dm_airdata_create_ale(map_ale_info_t *ale)
{
    /* Local agent already added */
    if (is_local_agent(ale)) {
        ale->airdata_idx = 0;
        return;
    }

    create_ale_mac(ale->al_mac, &ale->airdata_idx);
}

static void map_dm_airdata_update_ale(map_ale_info_t *ale)
{
    unsigned int       idx1;
    map_device_info_t *d             = &ale->device_info;
    char              *manufacturer  = d->manufacturer_name;
    char              *serial        = d->serial_number;
    char              *product_class = strlen(d->model_number) ? d->model_number : d->model_name;
    UNUSED char        version_buf[32];
    UNUSED char       *version       = get_sw_version_str(d->os_version, version_buf, sizeof(version_buf));
    mac_addr_str       bh_al_mac_buf;
    char              *bh_al_mac_str = bh_al_mac_buf;
    char              *bh_link_type  = get_backhaul_link_type_str(ale);
    bool               onboarded     = ale->ale_onboard_status == ALE_NODE_ONBOARDED;

    if (get_device_idx(ale, &idx1)) {
        log_lib_e("could not find indexes for ale[%s]", ale->al_mac_str);
        return;
    }

    /* Local agent -> empty
       Controller -> replace by local agent
    */
    if (is_local_agent(ale)) {
        bh_al_mac_str[0] = 0;
    } else if (is_controller_mac(ale->upstream_al_mac)) {
        mac_to_string(map_cfg_get()->controller_cfg.local_agent_al_mac, bh_al_mac_str);
    } else {
        mac_to_string(ale->upstream_al_mac, bh_al_mac_str);
    }

    fprintf(stderr, BBLUE">>>>update ale[%d]: %s"NORM"\n", idx1, ale->al_mac_str);
    fprintf(stderr, BBLUE"  manufacturer: %s"NORM"\n", manufacturer);
    fprintf(stderr, BBLUE"  product_class: %s"NORM"\n", product_class);
    fprintf(stderr, BBLUE"  serial: %s"NORM"\n", serial);
    fprintf(stderr, BBLUE"  version: %s"NORM"\n", version);
    fprintf(stderr, BBLUE"  bh_al_mac_str: %s"NORM"\n", bh_al_mac_str);
    fprintf(stderr, BBLUE"  bh_link_type: %s"NORM"\n", bh_link_type);
    fprintf(stderr, BBLUE"  onboarded: %d"NORM"\n", onboarded);

    return;
}

static void map_dm_airdata_remove_ale(map_ale_info_t *ale)
{
    unsigned int idx1;

    if (is_local_agent(ale)) {
        return;
    }

    if (get_device_idx(ale, &idx1)) {
        log_lib_e("could not find indexes for ale[%s]", ale->al_mac_str);
        return;
    }

    free(g_ap_list[idx1].al_mac_str);
    memset(&g_ap_list[idx1], 0, sizeof(g_ap_list[idx1]));

    /* Invalidate radio indexes as they are shifted */
    invalidate_ale_idx();

    /* Mark child objects are removed */
    mark_radios_removed(ale);

    return;
}

/*#######################################################################
#                       Device.WiFi.MultiAP.APDevice.Radio              #
########################################################################*/
static void map_dm_airdata_create_radio(map_radio_info_t *radio)
{
    map_ale_info_t *ale      = radio->ale;
    char           *mac      = radio->radio_id_str; /* Cannot take address of array */
    unsigned int    idx1, idx2;

    if (get_device_idx(ale, &idx1)) {
        log_lib_e("could not find index for ale[%s]", ale->al_mac_str);
        return;
    }

    /* Add object */
    for (idx2 = 0; idx2 < 4; idx2++) {
        if (g_ap_list[idx1].radio[idx2].radio_id_str == NULL) {
            g_ap_list[idx1].radio[idx2].radio_id_str = radio->radio_id_str;
            break;
        }
    }

    radio->airdata_idx = idx2;

    /* Set MAC */

    return;
}

static void map_dm_airdata_update_radio(map_radio_info_t *radio)
{
    map_ale_info_t *ale         = radio->ale;
    unsigned int    idx1, idx2;
    bool            is_2g       = (radio->supported_freq == IEEE80211_FREQUENCY_BAND_2_4_GHZ);
    char           *freq_band   = get_freq_band_str(is_2g);
    char            standards_buf[32];
    char           *standards    = get_radio_standards_str(radio, standards_buf, sizeof(standards_buf));
    char            channels_buf[256];
    char           *channels    = get_supported_channels_str(radio, channels_buf, sizeof(channels_buf));
    unsigned int    c_channel   = radio->configured_channel;
    char           *c_bw        = get_bw_str(radio->configured_bw);
    unsigned int    channel     = radio->current_op_channel;
    char           *ext_channel = get_ext_channel_str(map_get_ext_channel_type(radio->current_op_class));
    char           *bw          = get_bw_str(radio->current_bw);
    int             max_power   = get_max_power(radio);
    int             pct_power   = get_pct_power(max_power, radio->current_tx_pwr);

    if (get_device_radio_idx(ale, radio, &idx1, &idx2)) {
        log_lib_e("could not find indexes for ale[%s] radio[%s]", ale->al_mac_str, radio->radio_id_str);
        return;
    }

    fprintf(stderr, BBLUE">>>>update radio[%d]: %s on ale[%d]: %s"NORM"\n", idx2, radio->radio_id_str, idx1, g_ap_list[idx1].al_mac_str);
    fprintf(stderr, BBLUE"  freq_band: %s"NORM"\n", freq_band);
    fprintf(stderr, BBLUE"  standards: %s"NORM"\n", standards);
    fprintf(stderr, BBLUE"  channels: %s"NORM"\n", channels);
    fprintf(stderr, BBLUE"  c_channel: %d"NORM"\n", c_channel);
    fprintf(stderr, BBLUE"  c_bw: %s"NORM"\n", c_bw);
    if (channel > 0) {
        fprintf(stderr, BBLUE"  channel: %d"NORM"\n", channel);
        fprintf(stderr, BBLUE"  ext_channel: %s"NORM"\n", ext_channel);
        fprintf(stderr, BBLUE"  bw: %s"NORM"\n", bw);
        fprintf(stderr, BBLUE"  pct_power: %d"NORM"\n", pct_power);
    }
    fprintf(stderr, BBLUE"  max_power: %d"NORM"\n", max_power);

    return;
}

static void map_dm_airdata_remove_radio(map_radio_info_t *radio)
{
    map_ale_info_t *ale = radio->ale;
    unsigned int    idx1, idx2;

    if (radio->airdata_removed) {
        return;
    }

    if (get_device_radio_idx(ale, radio, &idx1, &idx2)) {
        log_lib_e("could not find indexes for ale[%s] radio[%s]", ale->al_mac_str, radio->radio_id_str);
        return;
    }

    memset(&g_ap_list[idx1].radio[idx2], 0, sizeof(g_ap_list[idx1].radio[idx2]));

    /* Invalidate radio indexes as they are shifted */
    invalidate_radio_idx(ale);

    /* Mark child objects are removed */
    mark_bsss_removed(radio);

    return;
}

/*#######################################################################
#                       Device.WiFi.MultiAP.APDevice.Radio.AP           #
########################################################################*/
static void map_dm_airdata_create_bss(map_bss_info_t *bss)
{
    map_radio_info_t *radio    = bss->radio;
    map_ale_info_t   *ale      = radio->ale;
    unsigned int      idx1, idx2, idx3;

    if (get_device_radio_idx(ale, radio, &idx1, &idx2)) {
        log_lib_e("could not find indexes for ale[%s] radio[%s] ", ale->al_mac_str, radio->radio_id_str);
        return;
    }

    /* Add object */
    for (idx3 = 0; idx3 < 16; idx3++) {
        if (g_ap_list[idx1].radio[idx2].bss[idx3] == NULL) {
            g_ap_list[idx1].radio[idx2].bss[idx3] = bss->bssid_str;
            break;
        }
    }

    bss->airdata_idx = idx3;

    return;
}

static void map_dm_airdata_update_bss(map_bss_info_t *bss)
{
    map_radio_info_t *radio     = bss->radio;
    map_ale_info_t   *ale       = radio->ale;
    unsigned int      idx1, idx2, idx3;

    if (get_device_radio_ap_idx(ale, radio, bss, &idx1, &idx2, &idx3)) {
        log_lib_e("could not find indexes for ale [%s] radio [%s] ap[%s]", ale->al_mac_str, radio->radio_id_str, bss->bssid_str);
        return;
    }

    return;
}

static void map_dm_airdata_remove_bss(map_bss_info_t *bss)
{
    map_radio_info_t *radio = bss->radio;
    map_ale_info_t   *ale   = radio->ale;
    unsigned int      idx1, idx2, idx3;

    if (bss->airdata_removed) {
        return;
    }

    if (get_device_radio_ap_idx(ale, radio, bss, &idx1, &idx2, &idx3)) {
        log_lib_e("could not find indexes for ale [%s] radio [%s] ap[%s]", ale->al_mac_str, radio->radio_id_str, bss->bssid_str);
        return;
    }

    g_ap_list[idx1].radio[idx2].bss[idx3] = NULL;

    /* Invalidate radio indexes as they are shifted */
    invalidate_bss_idx(radio);

    return;
}

/*#######################################################################
#                       GET BASED ON IDX                                #
########################################################################*/
map_ale_info_t *map_dm_airdata_get_ale(int ale_idx)
{
    map_ale_info_t *ale;

    map_dm_foreach_agent_ale(ale) {
        if (ale->airdata_idx == ale_idx) {
            return ale;
        }
    }

    return NULL;
}

map_radio_info_t *map_dm_airdata_get_radio(map_ale_info_t *ale, int radio_idx)
{
    map_radio_info_t *radio;

    map_dm_foreach_radio(ale, radio) {
        if (radio->airdata_idx == radio_idx) {
            return radio;
        }
    }

    return NULL;
}

/*#######################################################################
#                       Init                                            #
########################################################################*/
static map_dm_cbs_t g_dm_cbs = {
    .ale_create_cb = map_dm_airdata_create_ale,
    .ale_update_cb = map_dm_airdata_update_ale,
    .ale_remove_cb = map_dm_airdata_remove_ale,

    .radio_create_cb = map_dm_airdata_create_radio,
    .radio_update_cb = map_dm_airdata_update_radio,
    .radio_remove_cb = map_dm_airdata_remove_radio,

    .bss_create_cb = map_dm_airdata_create_bss,
    .bss_update_cb = map_dm_airdata_update_bss,
    .bss_remove_cb = map_dm_airdata_remove_bss,
};

int map_dm_airdata_init(void)
{
    uint8_t* mac = map_cfg_get()->controller_cfg.local_agent_al_mac;

    remove_all_ap_device();

    /* Create local agent so it gets index 0 */
    if (maccmp(mac, g_zero_mac) && maccmp(mac, g_wildcard_mac)) {
        create_ale_mac(mac, NULL);
    }

    /* Register dm callbacks */
    map_dm_register_cbs(&g_dm_cbs);

    return 0;
}

void map_dm_airdata_fini(void)
{
    map_dm_unregister_cbs(&g_dm_cbs);

    remove_all_ap_device(); /* Should only remove local agent */
}
