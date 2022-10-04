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

static struct stub_ap g_ap_list[16];

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

static void update_ale_idxs(map_ale_info_t *removed_ale)
{
    map_ale_info_t *ale;
    unsigned int    idx;

    map_dm_foreach_agent_ale(ale) {
        if (!is_local_agent(ale) && ale != removed_ale) {
            ale->airdata_idx = -1;
            get_device_idx(ale, &idx);
        }
    }
}

static void update_radio_idxs(map_ale_info_t *ale, map_radio_info_t *removed_radio)
{
    map_radio_info_t *radio;
    unsigned int      idx;

    map_dm_foreach_radio(ale, radio) {
        if (radio != removed_radio) {
            radio->airdata_idx = -1;
            get_radio_idx(ale->airdata_idx, radio, &idx);
        }
    }
}

static void update_bss_idxs(map_radio_info_t *radio, map_bss_info_t *removed_bss)
{
    map_bss_info_t *bss;
    unsigned int    idx;

    map_dm_foreach_bss(radio, bss) {
        if (bss != removed_bss) {
            bss->airdata_idx = -1;
            get_ap_idx(radio->ale->airdata_idx, radio->airdata_idx, bss, &idx);
        }
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
    log_lib_d(">>>>create ale[%d]: %s\n", idx, p_mac_str);
    log_lib_d("  p_oui_str: %s\n", p_oui_str);

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
    map_device_info_t *d              = &ale->device_info;
    char              *manufacturer   = d->manufacturer_name;
    char              *serial         = d->serial_number;
    char              *product_class  = strlen(d->model_number) ? d->model_number : d->model_name;
    UNUSED char       *version        = ale->inventory_exists ? ale->inventory.version : d->os_version_str;
    mac_addr_str       bh_al_mac_buf;
    char              *bh_al_mac_str  = bh_al_mac_buf;
    char              *bh_link_type   = get_backhaul_link_type_str(ale);
    bool               onboarded      = ale->ale_onboard_status == ALE_NODE_ONBOARDED;

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

    log_lib_d(">>>>update ale[%d]: %s\n", idx1, ale->al_mac_str);
    log_lib_d("  manufacturer: %s\n", manufacturer);
    log_lib_d("  product_class: %s\n", product_class);
    log_lib_d("  serial: %s\n", serial);
    log_lib_d("  version: %s\n", version);
    log_lib_d("  bh_al_mac_str: %s\n", bh_al_mac_str);
    log_lib_d("  bh_link_type: %s\n", bh_link_type);
    log_lib_d("  onboarded: %d\n", onboarded);

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

    /* Update other ale indexes as they are shifted */
    update_ale_idxs(ale);

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
    log_lib_d(">>>>create radio[%d]: %s on ale[%d]: %s\n", idx2, radio->radio_id_str, idx1, g_ap_list[idx1].al_mac_str);
    log_lib_d("  mac: %s\n", mac);

    return;
}

static void map_dm_airdata_update_radio(map_radio_info_t *radio)
{
    map_ale_info_t *ale         = radio->ale;
    unsigned int    idx1, idx2;
    char           *freq_band   = map_get_freq_band_str(radio->supported_freq);
    char            standards_buf[32];
    char           *standards   = get_radio_standards_str(radio, standards_buf, sizeof(standards_buf));
    char            channels_buf[MAP_CS_BUF_LEN];
    char           *channels    = map_cs_to_string(&radio->ctl_channels, ',', channels_buf, sizeof(channels_buf));
    char            channels_with_bw_buf[MAP_CHANS_W_BW_BUF_LEN];
    char           *channels_with_bw = map_cs_bw_to_string(&radio->channels_with_bandwidth, ',', channels_with_bw_buf, sizeof(channels_with_bw_buf));
    unsigned int    c_channel   = radio->chan_sel.channel;
    char           *c_bw        = get_bw_str(radio->chan_sel.bandwidth);
    unsigned int    channel     = radio->current_op_channel;
    char           *ext_channel = get_ext_channel_str(map_get_ext_channel_type(radio->current_op_class));
    char           *bw          = get_bw_str(radio->current_bw);
    int             max_power   = get_max_power(radio);
    int             pct_power   = get_pct_power(max_power, radio->current_tx_pwr);

    if (get_device_radio_idx(ale, radio, &idx1, &idx2)) {
        log_lib_e("could not find indexes for ale[%s] radio[%s]", ale->al_mac_str, radio->radio_id_str);
        return;
    }

    log_lib_d(">>>>update radio[%d]: %s on ale[%d]: %s\n", idx2, radio->radio_id_str, idx1, g_ap_list[idx1].al_mac_str);
    log_lib_d("  freq_band: %s\n", freq_band);
    log_lib_d("  standards: %s\n", standards);
    log_lib_d("  channels: %s\n", channels);
    log_lib_d("  channels_w_bw: %s\n", channels_with_bw);
    log_lib_d("  c_channel: %d\n", c_channel);
    log_lib_d("  c_bw: %s\n", c_bw);
    if (channel > 0) {
        log_lib_d("  channel: %d\n", channel);
        log_lib_d("  ext_channel: %s\n", ext_channel);
        log_lib_d("  bw: %s\n", bw);
        log_lib_d("  pct_power: %d\n", pct_power);
    }
    log_lib_d("  max_power: %d\n", max_power);

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

    /* Update other radio indexes as they are shifted */
    update_radio_idxs(ale, radio);

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

    log_lib_d(">>>>update bssid[%d]: %s on ale[%d]: %s, radio[%d]: %s\n", idx3, bss->bssid_str, idx1, g_ap_list[idx1].al_mac_str, idx2, g_ap_list[idx1].radio[idx2].radio_id_str);

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

    /* Update other bss indexes as they are shifted */
    update_bss_idxs(radio, bss);

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
