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

/*
 *  Broadband Forum IEEE 1905.1/1a stack
 *
 *  Copyright (c) 2017, Broadband Forum
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  Subject to the terms and conditions of this license, each copyright
 *  holder and contributor hereby grants to those receiving rights under
 *  this license a perpetual, worldwide, non-exclusive, no-charge,
 *  royalty-free, irrevocable (except for failure to satisfy the
 *  conditions of this license) patent license to make, have made, use,
 *  offer to sell, sell, import, and otherwise transfer this software,
 *  where such license applies only to those patent claims, already
 *  acquired or hereafter acquired, licensable by such copyright holder or
 *  contributor that are necessarily infringed by:
 *
 *  (a) their Contribution(s) (the licensed copyrights of copyright holders
 *      and non-copyrightable additions of contributors, in source or binary
 *      form) alone; or
 *
 *  (b) combination of their Contribution(s) with the work of authorship to
 *      which such Contribution(s) was added by such copyright holder or
 *      contributor, if, at the time the Contribution is added, such addition
 *      causes such combination to be necessarily infringed. The patent
 *      license shall not apply to any other combinations which include the
 *      Contribution.
 *
 *  Except as expressly stated above, no rights or licenses from any
 *  copyright holder or contributor is granted under this license, whether
 *  expressly, by implication, estoppel or otherwise.
 *
 *  DISCLAIMER
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 *  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 *  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 *  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 *  DAMAGE.
 */

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "platform.h"

#include "al_wsc.h"
#include "al_datamodel.h"
#include "packet_tools.h"

#include "platform_crypto.h"
#include "platform_interfaces.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define ATTR_VERSION           (0x104a)
#define ATTR_MSG_TYPE          (0x1022)
    #define WPS_M1                 (0x04)
    #define WPS_M2                 (0x05)
#define ATTR_UUID_E            (0x1047)
#define ATTR_UUID_R            (0x1048)
#define ATTR_MAC_ADDR          (0x1020)
#define ATTR_ENROLLEE_NONCE    (0x101a)
#define ATTR_REGISTRAR_NONCE   (0x1039)
#define ATTR_PUBLIC_KEY        (0x1032)
#define ATTR_AUTH_TYPE_FLAGS   (0x1004)
    #define WPS_AUTH_OPEN          (0x0001)
    #define WPS_AUTH_WPAPSK        (0x0002)
    #define WPS_AUTH_SHARED        (0x0004) /* deprecated */
    #define WPS_AUTH_WPA           (0x0008)
    #define WPS_AUTH_WPA2          (0x0010)
    #define WPS_AUTH_WPA2PSK       (0x0020)
    #define WPS_AUTH_WEP           (0x0040)
#define ATTR_ENCR_TYPE_FLAGS   (0x1010)
    #define WPS_ENCR_NONE          (0x0001)
    #define WPS_ENCR_WEP           (0x0002) /* deprecated */
    #define WPS_ENCR_TKIP          (0x0004)
    #define WPS_ENCR_AES           (0x0008)
#define ATTR_CONN_TYPE_FLAGS   (0x100d)
    #define WPS_CONN_ESS           (0x01)
    #define WPS_CONN_IBSS          (0x02)
#define ATTR_CONFIG_METHODS    (0x1008)
    #define WPS_CONFIG_VIRT_PUSHBUTTON (0x0280)
    #define WPS_CONFIG_PHY_PUSHBUTTON  (0x0480)
#define ATTR_WPS_STATE         (0x1044)
    #define WPS_STATE_NOT_CONFIGURED (1)
    #define WPS_STATE_CONFIGURED     (2)
#define ATTR_MANUFACTURER      (0x1021)
#define ATTR_MODEL_NAME        (0x1023)
#define ATTR_MODEL_NUMBER      (0x1024)
#define ATTR_SERIAL_NUMBER     (0x1042)
#define ATTR_PRIMARY_DEV_TYPE  (0x1054)
    #define WPS_DEV_COMPUTER                           (1)
        #define WPS_DEV_COMPUTER_PC                       (1)
        #define WPS_DEV_COMPUTER_SERVER                   (2)
        #define WPS_DEV_COMPUTER_MEDIA_CENTER             (3)
        #define WPS_DEV_COMPUTER_ULTRA_MOBILE             (4)
        #define WPS_DEV_COMPUTER_NOTEBOOK                 (5)
        #define WPS_DEV_COMPUTER_DESKTOP                  (6)
        #define WPS_DEV_COMPUTER_MID                      (7)
        #define WPS_DEV_COMPUTER_NETBOOK                  (8)
        #define WPS_DEV_COMPUTER_TABLET                   (9)
    #define WPS_DEV_INPUT                              (2)
        #define WPS_DEV_INPUT_KEYBOARD                    (1)
        #define WPS_DEV_INPUT_MOUSE                       (2)
        #define WPS_DEV_INPUT_JOYSTICK                    (3)
        #define WPS_DEV_INPUT_TRACKBALL                   (4)
        #define WPS_DEV_INPUT_GAMING                      (5)
        #define WPS_DEV_INPUT_REMOTE                      (6)
        #define WPS_DEV_INPUT_TOUCHSCREEN                 (7)
        #define WPS_DEV_INPUT_BIOMETRIC_READER            (8)
        #define WPS_DEV_INPUT_BARCODE_READER              (9)
    #define WPS_DEV_PRINTER                            (3)
        #define WPS_DEV_PRINTER_PRINTER                   (1)
        #define WPS_DEV_PRINTER_SCANNER                   (2)
        #define WPS_DEV_PRINTER_FAX                       (3)
        #define WPS_DEV_PRINTER_COPIER                    (4)
        #define WPS_DEV_PRINTER_ALL_IN_ONE                (5)
    #define WPS_DEV_CAMERA                             (4)
        #define WPS_DEV_CAMERA_DIGITAL_STILL_CAMERA       (1)
        #define WPS_DEV_CAMERA_VIDEO                      (2)
        #define WPS_DEV_CAMERA_WEB                        (3)
        #define WPS_DEV_CAMERA_SECURITY                   (4)
    #define WPS_DEV_STORAGE                            (5)
        #define WPS_DEV_STORAGE_NAS                       (1)
    #define WPS_DEV_NETWORK_INFRA                      (6)
        #define WPS_DEV_NETWORK_INFRA_AP                  (1)
        #define WPS_DEV_NETWORK_INFRA_ROUTER              (2)
        #define WPS_DEV_NETWORK_INFRA_SWITCH              (3)
        #define WPS_DEV_NETWORK_INFRA_GATEWAY             (4)
        #define WPS_DEV_NETWORK_INFRA_BRIDGE              (5)
    #define WPS_DEV_DISPLAY                            (7)
        #define WPS_DEV_DISPLAY_TV                        (1)
        #define WPS_DEV_DISPLAY_PICTURE_FRAME             (2)
        #define WPS_DEV_DISPLAY_PROJECTOR                 (3)
        #define WPS_DEV_DISPLAY_MONITOR                   (4)
    #define WPS_DEV_MULTIMEDIA                         (8)
        #define WPS_DEV_MULTIMEDIA_DAR                    (1)
        #define WPS_DEV_MULTIMEDIA_PVR                    (2)
        #define WPS_DEV_MULTIMEDIA_MCX                    (3)
        #define WPS_DEV_MULTIMEDIA_SET_TOP_BOX            (4)
        #define WPS_DEV_MULTIMEDIA_MEDIA_SERVER           (5)
        #define WPS_DEV_MULTIMEDIA_PORTABLE_VIDEO_PLAYER  (6)
    #define WPS_DEV_GAMING                             (9)
        #define WPS_DEV_GAMING_XBOX                       (1)
        #define WPS_DEV_GAMING_XBOX360                    (2)
        #define WPS_DEV_GAMING_PLAYSTATION                (3)
        #define WPS_DEV_GAMING_GAME_CONSOLE               (4)
        #define WPS_DEV_GAMING_PORTABLE_DEVICE            (5)
    #define WPS_DEV_PHONE                             (10)
        #define WPS_DEV_PHONE_WINDOWS_MOBILE              (1)
        #define WPS_DEV_PHONE_SINGLE_MODE                 (2)
        #define WPS_DEV_PHONE_DUAL_MODE                   (3)
        #define WPS_DEV_PHONE_SP_SINGLE_MODE              (4)
        #define WPS_DEV_PHONE_SP_DUAL_MODE                (5)
    #define WPS_DEV_AUDIO                             (11)
        #define WPS_DEV_AUDIO_TUNER_RECV                  (1)
        #define WPS_DEV_AUDIO_SPEAKERS                    (2)
        #define WPS_DEV_AUDIO_PMP                         (3)
        #define WPS_DEV_AUDIO_HEADSET                     (4)
        #define WPS_DEV_AUDIO_HEADPHONES                  (5)
        #define WPS_DEV_AUDIO_MICROPHONE                  (6)
        #define WPS_DEV_AUDIO_HOME_THEATRE                (7)
#define ATTR_DEV_NAME          (0x1011)
#define ATTR_RF_BANDS          (0x103c)
    #define WPS_RF_24GHZ           (0x01)
    #define WPS_RF_5GHZ            (0x02)
    #define WPS_RF_60GHZ           (0x04)
#define ATTR_ASSOC_STATE       (0x1002)
    #define WPS_ASSOC_NOT_ASSOC     (0)
    #define WPS_ASSOC_CONN_SUCCESS  (1)
#define ATTR_DEV_PASSWORD_ID   (0x1012)
    #define DEV_PW_PUSHBUTTON      (0x0004)
#define ATTR_CONFIG_ERROR      (0x1009)
    #define WPS_CFG_NO_ERROR       (0)
#define ATTR_OS_VERSION        (0x102d)
#define ATTR_VENDOR_EXTENSION  (0x1049)
    #define WPS_VENDOR_ID_WFA_1    (0x00)
    #define WPS_VENDOR_ID_WFA_2    (0x37)
    #define WPS_VENDOR_ID_WFA_3    (0x2A)
    #define WFA_ELEM_VERSION2      (0x00)
    #define WPS_VERSION            (0x20)
    #define WFA_ELEM_MAP_EXT_ATTR  (0x06)
#define ATTR_SSID              (0x1045)
#define ATTR_AUTH_TYPE         (0x1003)
#define ATTR_ENCR_TYPE         (0x100f)
#define ATTR_NETWORK_KEY       (0x1027)
#define ATTR_KEY_WRAP_AUTH     (0x101e)
#define ATTR_ENCR_SETTINGS     (0x1018)
#define ATTR_AUTHENTICATOR     (0x1005)

/* Flags for MultiAp extension subelement  */
#define WFA_MAP_ATTR_FLAG_TEARDOWN                0x10 /* Bit 4 */
#define WFA_MAP_ATTR_FLAG_FRONTHAUL_BSS           0x20 /* Bit 5 */
#define WFA_MAP_ATTR_FLAG_BACKHAUL_BSS            0x40 /* Bit 6 */
#define WFA_MAP_ATTR_FLAG_BACKHAUL_STA            0x80 /* Bit 7 */

/* Keys sizes */
#define WPS_AUTHKEY_LEN    32
#define WPS_KEYWRAPKEY_LEN 16
#define WPS_EMSK_LEN       32


/*#######################################################################
#                       LOCAL FUNCTIONS                                 #
########################################################################*/
/* This is the key derivation function used in the WPS standard to obtain a
*  final hash that is later used for encryption.
*
*  The output is stored in the memory buffer pointed by 'res', which must be
*  "SHA256_MAC_LEN" bytes long (ie. 're_len' must always be "SHA256_MAC_LEN",
*  even if it is an input argument)
*/
static uint8_t wps_key_derivation_function(uint8_t *key, uint8_t *label_prefix, uint32_t label_prefix_len, char *label, uint8_t *res, uint32_t res_len)
{
    uint8_t i_buf[4];
    uint8_t key_bits[4];

    uint8_t   *addr[4];
    uint32_t   len[4];

    uint32_t i, iter;

    uint8_t  hash[SHA256_MAC_LEN] = {0};
    uint8_t *opos;

    uint32_t left;

    uint8_t  *p;
    uint32_t  aux;

    aux = res_len * 8;
    p   = key_bits;

    _I4B(&aux, &p);

    addr[0] = i_buf;
    addr[1] = label_prefix;
    addr[2] = (uint8_t *) label;
    addr[3] = key_bits;
    len[0]  = sizeof(i_buf);
    len[1]  = label_prefix_len;
    len[2]  = strlen(label);
    len[3]  = sizeof(key_bits);

    iter = (res_len + SHA256_MAC_LEN - 1) / SHA256_MAC_LEN;
    opos = res;
    left = res_len;

    for (i = 1; i <= iter; i++) {
        p = i_buf;
        _I4B(&i, &p);

        if (PLATFORM_HMAC_SHA256(key, SHA256_MAC_LEN, 4, addr, len, hash) != 1) {
            log_i1905_e("PLATFORM_HMAC_SHA256 failed");
            return 0;
        }

        if (i < iter) {
            memcpy(opos, hash, SHA256_MAC_LEN);
            opos += SHA256_MAC_LEN;
            left -= SHA256_MAC_LEN;
        } else {
            memcpy(opos, hash, left);
        }
    }
    return 1;
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/

/*#######################################################################
#                       ENROLLEE (TX M1, RX M2)                         #
########################################################################*/
uint8_t wscBuildM1(char *interface_name, uint8_t **m1, uint16_t *m1_size, void **key)
{
    uint8_t              *buffer      = NULL;
    struct interfaceInfo *x           = NULL;
    struct wscKey        *private_key = NULL;
    uint8_t              *p           = NULL;
    uint8_t               aux8;
    uint16_t              aux16;
    uint32_t              aux32;

    if (NULL == interface_name || NULL == m1 || NULL == m1_size || NULL == key) {
        log_i1905_e("Invalid arguments to wscBuildM1()");
        return 0;
    }

    if (NULL == (x = PLATFORM_GET_1905_INTERFACE_INFO(interface_name))) {
        log_i1905_e("Could not retrieve info of interface %s", interface_name);
        return 0;
    }

    if (!(buffer = malloc(1000))) {
        log_i1905_e("malloc() failed");
        goto fail;
    }
    p = buffer;

    /* VERSION */
    {
        aux16 = ATTR_VERSION;                                             _I2B(&aux16,     &p);
        aux16 = 1;                                                        _I2B(&aux16,     &p);
        aux8  = 0x10;                                                     _I1B(&aux8,      &p);
    }

    /* MESSAGE TYPE */
    {
        aux16 = ATTR_MSG_TYPE;                                            _I2B(&aux16,     &p);
        aux16 = 1;                                                        _I2B(&aux16,     &p);
        aux8  = WPS_M1;                                                   _I1B(&aux8,      &p);
    }

    /* UUID */
    {
        aux16 = ATTR_UUID_E;                                              _I2B(&aux16,     &p);
        aux16 = 16;                                                       _I2B(&aux16,     &p);
                                                                          _InB( x->uuid,   &p, 16);
    }

    /* MAC ADDRESS */
    {
        aux16 = ATTR_MAC_ADDR;                                            _I2B(&aux16,           &p);
        aux16 = 6;                                                        _I2B(&aux16,           &p);
#ifdef MULTIAP
                                                                          _InB( DMalMacGet(),  &p, 6);
#else
                                                                          _InB( x->mac_address,  &p, 6);
#endif
    }

    /* ENROLLEE NONCE */
    {
        uint8_t enrollee_nonce[16] = { 0 };

        if (PLATFORM_GET_RANDOM_BYTES(enrollee_nonce, 16) != 1) {
            log_i1905_e("PLATFORM_GET_RANDOM_BYTES failed");
            goto fail;
        }

        aux16 = ATTR_ENROLLEE_NONCE;                                      _I2B(&aux16,           &p);
        aux16 = 16;                                                       _I2B(&aux16,           &p);
                                                                          _InB( enrollee_nonce,  &p, 16);
    }

    /* PUBLIC KEY */
    {
        uint8_t  *priv = NULL, *pub = NULL;
        uint16_t  priv_len = 0, pub_len = 0;

        if (PLATFORM_GENERATE_DH_KEY_PAIR(&priv, &priv_len, &pub, &pub_len) != 1) {
            log_i1905_e("PLATFORM_GENERATE_DH_KEY_PAIR failed");
            goto fail;
        }
        /* TODO: ZERO PAD the pub key (doesn't seem to be really needed though) */

        aux16 = ATTR_PUBLIC_KEY;                                          _I2B(&aux16,       &p);
        aux16 = pub_len;                                                  _I2B(&aux16,       &p);
                                                                          _InB( pub,         &p, pub_len);
        log_i1905_t("  Enrollee privkey  (%3d bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", priv_len,  priv[0], priv[1], priv[2], priv[priv_len-3], priv[priv_len-2], priv[priv_len-1]);
        log_i1905_t("  Enrollee pubkey  (%3d bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", pub_len,  pub[0], pub[1], pub[2], pub[pub_len-3], pub[pub_len-2], pub[pub_len-1]);
        /* The private key is one of the output arguments */
        private_key = malloc(sizeof(struct wscKey));
        if (!private_key) {
            free(priv);
            free(pub);
            goto fail;
        }
        private_key->key = malloc(priv_len);
        if (!private_key->key) {
            free(priv);
            free(pub);
            goto fail;
        }
        private_key->key_len = priv_len;
        memcpy(private_key->key, priv, priv_len);
#ifdef MULTIAP
        memcpy(private_key->mac, DMalMacGet(), 6);
#else
        memcpy(private_key->mac, x->mac_address, 6);
#endif
        free(priv);
        free(pub);
    }

    /* AUTHENTICATION TYPES */
    {
        aux16 = ATTR_AUTH_TYPE_FLAGS;                                     _I2B(&aux16,     &p);
        aux16 = 2;                                                        _I2B(&aux16,     &p);
        aux16 = x->interface_type_data.ieee80211.authentication_mode;     _I2B(&aux16,     &p);
    }

    /* ENCRYPTION TYPES */
    {
        aux16 = ATTR_ENCR_TYPE_FLAGS;                                     _I2B(&aux16,     &p);
        aux16 = 2;                                                        _I2B(&aux16,     &p);
        aux16 = x->interface_type_data.ieee80211.encryption_mode;         _I2B(&aux16,     &p);
    }

    /* CONNECTION TYPES */
    {
        /* Two possible types: ESS or IBSS. In the 1905 context, enrollees will
        *  always want to acts as "ESS" to create an "extended" network where
        *  all APs share the same credentials as the registrar.
        */

        aux16 = ATTR_CONN_TYPE_FLAGS;                                     _I2B(&aux16,     &p);
        aux16 = 1;                                                        _I2B(&aux16,     &p);
        aux8  = WPS_CONN_ESS;                                             _I1B(&aux8,      &p);
    }

    /* CONFIGURATION METHODS */
    {
        /* In the 1905 context, the configuration methods the AP is willing to
        *  offer will always be these two
        */

        aux16 = ATTR_CONFIG_METHODS;                                      _I2B(&aux16,     &p);
        aux16 = 2;                                                        _I2B(&aux16,     &p);
        aux16 = WPS_CONFIG_PHY_PUSHBUTTON | WPS_CONFIG_VIRT_PUSHBUTTON;   _I2B(&aux16,     &p);
    }

    /* WPS STATE */
    {
        aux16 = ATTR_WPS_STATE;                                           _I2B(&aux16,     &p);
        aux16 = 1;                                                        _I2B(&aux16,     &p);
        aux8  = WPS_STATE_NOT_CONFIGURED;                                 _I1B(&aux8,      &p);
    }

    /* MANUFACTURER */
    {
        aux16 = ATTR_MANUFACTURER;                                        _I2B(&aux16,                &p);
        aux16 = strlen(x->manufacturer_name);                             _I2B(&aux16,                &p);
                                                                          _InB( x->manufacturer_name, &p, strlen(x->manufacturer_name));
    }

    /* MODEL NAME */
    {
        aux16 = ATTR_MODEL_NAME;                                          _I2B(&aux16,         &p);
        aux16 = strlen(x->model_name);                                    _I2B(&aux16,         &p);
                                                                          _InB( x->model_name, &p, strlen(x->model_name));
    }

    /* MODEL NUMBER */
    {
        aux16 = ATTR_MODEL_NUMBER;                                        _I2B(&aux16,           &p);
        aux16 = strlen(x->model_number);                                  _I2B(&aux16,           &p);
                                                                          _InB( x->model_number, &p, strlen(x->model_number));
    }

    /* SERIAL NUMBER */
    {
        aux16 = ATTR_SERIAL_NUMBER;                                       _I2B(&aux16,            &p);
        aux16 = strlen(x->serial_number);                                 _I2B(&aux16,            &p);
                                                                          _InB( x->serial_number, &p, strlen(x->serial_number));
    }

    /* PRIMARY DEVICE TYPE */
    {
        /* In the 1905 context, they node sending a M1 message will always be
        *  (at least) a "network router"
        */

        uint8_t oui[4] = {0x00, 0x50, 0xf2, 0x04}; /* Fixed value from the WSC spec for Wifi-Alliance */

        aux16 = ATTR_PRIMARY_DEV_TYPE;                                    _I2B(&aux16,         &p);
        aux16 = 8;                                                        _I2B(&aux16,         &p);
        aux16 = WPS_DEV_NETWORK_INFRA;                                    _I2B(&aux16,         &p);
                                                                          _InB( oui,           &p, 4);
#ifdef MULTIAP
        /* In the MULTIAP context, the node sending a M1 message will always be
        *  (at least) a "network AP"
        */
        aux16 = WPS_DEV_NETWORK_INFRA_AP;                                 _I2B(&aux16,         &p);
#else
        aux16 = WPS_DEV_NETWORK_INFRA_ROUTER;                             _I2B(&aux16,         &p);
#endif
    }

    /* DEVICE NAME */
    {
        aux16 = ATTR_DEV_NAME;                                            _I2B(&aux16,           &p);
        aux16 = strlen(x->device_name);                                   _I2B(&aux16,           &p);
                                                                          _InB( x->device_name,  &p, strlen(x->device_name));
    }

    /* RF BANDS */
    {
        /* TODO
        *  We should here list all supported freq bands (2.4, 5.0, 60 GHz)...
        *  however each interfaces is already "pre-configured" to one specific
        *  freq band... thus we will always report back a single value (instead
        *  of and OR'ed list).
        *  This should probably be improved in the future.
        */
        uint8_t rf_bands = 0;

        if (       INTERFACE_TYPE_IEEE_802_11B_2_4_GHZ ==  x->interface_type ||
                   INTERFACE_TYPE_IEEE_802_11G_2_4_GHZ ==  x->interface_type ||
                   INTERFACE_TYPE_IEEE_802_11N_2_4_GHZ ==  x->interface_type) {
            rf_bands = WPS_RF_24GHZ;
        } else if (INTERFACE_TYPE_IEEE_802_11A_5_GHZ  ==  x->interface_type ||
                   INTERFACE_TYPE_IEEE_802_11N_5_GHZ  ==  x->interface_type ||
                   INTERFACE_TYPE_IEEE_802_11AC_5_GHZ ==  x->interface_type) {
            rf_bands = WPS_RF_5GHZ;
        } else if (INTERFACE_TYPE_IEEE_802_11AD_60_GHZ ==  x->interface_type) {
            rf_bands = WPS_RF_60GHZ;
        }

        aux16 = ATTR_RF_BANDS;                                            _I2B(&aux16,         &p);
        aux16 = 1;                                                        _I2B(&aux16,         &p);
                                                                          _I1B(&rf_bands,      &p);
    }

    /* ASSOCIATION STATE */
    {
        aux16 = ATTR_ASSOC_STATE;                                         _I2B(&aux16,         &p);
        aux16 = 2;                                                        _I2B(&aux16,         &p);
        aux16 = WPS_ASSOC_NOT_ASSOC;                                      _I2B(&aux16,         &p);
    }

    /* DEVICE PASSWORD ID */
    {
        aux16 = ATTR_DEV_PASSWORD_ID;                                     _I2B(&aux16,         &p);
        aux16 = 2;                                                        _I2B(&aux16,         &p);
        aux16 = DEV_PW_PUSHBUTTON;                                        _I2B(&aux16,         &p);
    }

    /* CONFIG ERROR */
    {
        aux16 = ATTR_CONFIG_ERROR;                                        _I2B(&aux16,         &p);
        aux16 = 2;                                                        _I2B(&aux16,         &p);
        aux16 = WPS_CFG_NO_ERROR;                                         _I2B(&aux16,         &p);
    }

    /* OS VERSION */
    {
        /* TODO: Fill with actual properties from the interface */

        uint32_t os_version = 0x00000001;

        aux16 = ATTR_OS_VERSION;                                          _I2B(&aux16,         &p);
        aux16 = 4;                                                        _I2B(&aux16,         &p);
        aux32 = 0x80000000 | os_version;                                  _I4B(&aux32,         &p);
    }

    /* VENDOR EXTENSIONS */
    {
        aux16 = ATTR_VENDOR_EXTENSION;                                    _I2B(&aux16,         &p);
        aux16 = 6;                                                        _I2B(&aux16,         &p);
        aux8  = WPS_VENDOR_ID_WFA_1;                                      _I1B(&aux8,          &p);
        aux8  = WPS_VENDOR_ID_WFA_2;                                      _I1B(&aux8,          &p);
        aux8  = WPS_VENDOR_ID_WFA_3;                                      _I1B(&aux8,          &p);
        aux8  = WFA_ELEM_VERSION2;                                        _I1B(&aux8,          &p);
        aux8  = 1;                                                        _I1B(&aux8,          &p);
        aux8  = WPS_VERSION;                                              _I1B(&aux8,          &p);
    }

    PLATFORM_FREE_1905_INTERFACE_INFO(x);

    *m1      = buffer;
    *m1_size = p-buffer;
    *key     = private_key;

    return 1;

fail:
    PLATFORM_FREE_1905_INTERFACE_INFO(x);

    free(buffer);
    if (private_key) {
        free(private_key->key);
        free(private_key);
    }

    return 0;
}

uint8_t  wscProcessM2(void *key, uint8_t *m1, uint16_t m1_size, uint8_t *m2, uint16_t m2_size)
{
    uint8_t       *p;
    struct wscKey *k;

    /* "Useful data" we want to extract from M2 */
    uint8_t  ssid[MAX_WIFI_SSID_LEN];                   uint8_t ssid_present;
    uint8_t  bssid[ETHER_ADDR_LEN];                     uint8_t bssid_present;
    uint16_t auth_type;                                 uint8_t auth_type_present;
    uint16_t encryption_type;                           uint8_t encryption_type_present;
    uint8_t  network_key[MAX_WIFI_PASSWORD_LEN];        uint8_t network_key_present;

    /* Keys we need to compute to authenticate and decrypt M2 */
    uint8_t authkey   [WPS_AUTHKEY_LEN];
    uint8_t keywrapkey[WPS_KEYWRAPKEY_LEN];
    uint8_t emsk      [WPS_EMSK_LEN];

    /* "Intermediary data" we also need to extract from M2 to obtain the keys
    *  that will let us decrypt the "useful data" from M2
    */
    uint8_t  *m2_nonce = NULL;                uint8_t m2_nonce_present;
    uint8_t  *m2_pubkey = NULL;               uint8_t m2_pubkey_present;
    uint16_t  m2_pubkey_len = 0;
    uint8_t  *m2_encrypted_settings = NULL;   uint8_t m2_encrypted_settings_present;
    uint16_t  m2_encrypted_settings_len = 0;
    uint8_t  *m2_authenticator = NULL;        uint8_t m2_authenticator_present;

    /* "Intermediary data" we also need to extract from M1 to obtain the keys
    *  that will let us decrypt the "useful data" from M2
    */
    uint8_t  *m1_nonce = NULL;           uint8_t m1_nonce_present;
    uint8_t  *m1_pubkey = NULL;          uint8_t m1_pubkey_present;
    uint16_t  m1_pubkey_len = 0;

    /* "Intermediary data" contained in the "key" argument also needed to obtain
    * the keys that will let us decrypt the "useful data" from M2
    */
    uint8_t  *m1_privkey;
    uint16_t  m1_privkey_len;
    uint8_t  *m1_mac;

#ifdef MULTIAP
    uint16_t              elem_len       = 0;
    uint8_t               oui[3]         = {0};
    uint8_t               map_ext        = 0;
    uint8_t              *vendor_elem    = NULL;
    uint8_t               wfa_elem       = 0;
    uint8_t               wfa_elem_len   = 0;
#endif

    if (NULL == m1) {
        log_i1905_e("M1 data missing");
        return 0;
    } else {
        k = (struct wscKey *)key;
    }

    m1_privkey      = k->key;
    m1_privkey_len  = k->key_len;
    m1_mac          = k->mac;

    /* Extract "intermediary data" from M2 */
    m2_nonce_present               = 0;
    m2_pubkey_present              = 0;
    m2_encrypted_settings_present  = 0;
    m2_authenticator_present       = 0;
    p                              = m2;
    while (p - m2 < m2_size) {
        uint16_t attr_type;
        uint16_t attr_len;

        _E2B(&p, &attr_type);
        _E2B(&p, &attr_len);

        if (ATTR_REGISTRAR_NONCE == attr_type) {
            if (16 != attr_len) {
                log_i1905_e("Incorrect length (%d) for ATTR_REGISTRAR_NONCE", attr_len);
                goto Fail;
            }
            m2_nonce = p;

            p += attr_len;
            m2_nonce_present = 1;
        } else if (ATTR_PUBLIC_KEY == attr_type) {
            m2_pubkey_len = attr_len;
            m2_pubkey     = p;

            p += attr_len;
            m2_pubkey_present = 1;
        } else if (ATTR_ENCR_SETTINGS == attr_type) {
            m2_encrypted_settings_len = attr_len;
            m2_encrypted_settings     = p;

            p += attr_len;
            m2_encrypted_settings_present = 1;
        } else if (ATTR_AUTHENTICATOR == attr_type) {
            if (8 != attr_len) {
                log_i1905_e("Incorrect length (%d) for ATTR_AUTHENTICATOR", attr_len);
                goto Fail;
            }
            m2_authenticator = p;

            p += attr_len;
            m2_authenticator_present = 1;
        } else {
            p += attr_len;
        }
    }
    if (0 == m2_nonce_present              ||
        0 == m2_pubkey_present             ||
        0 == m2_encrypted_settings_present ||
        0 == m2_authenticator_present)
    {
        log_i1905_e("Missing attributes in the received M2 message");
        goto Fail;
    }

    /* Extract "intermediary data" from M1 */
    m1_nonce_present  = 0;
    m1_pubkey_present = 0;
    p                 = m1;
    while (p - m1 < m1_size) {
        uint16_t attr_type;
        uint16_t attr_len;

        _E2B(&p, &attr_type);
        _E2B(&p, &attr_len);

        if (ATTR_ENROLLEE_NONCE == attr_type) {
            if (16 != attr_len) {
                log_i1905_e("Incorrect length (%d) for ATTR_REGISTRAR_NONCE", attr_len);
                goto Fail;
            }
            m1_nonce = p;

            p += attr_len;
            m1_nonce_present = 1;
        } else if (ATTR_PUBLIC_KEY == attr_type) {
            m1_pubkey_len = attr_len;
            m1_pubkey     = p;

            p += m1_pubkey_len;
            m1_pubkey_present = 1;
        } else {
            p += attr_len;
        }
    }
    if (0 == m1_nonce_present   ||
        0 == m1_pubkey_present)
    {
        log_i1905_e("Missing attributes in the received M1 message");
        goto Fail;
    }

    /* With all the information we have just extracted from M1 and M2, obtain
    *  the authentication/encryption keys.
    */
    {
        uint8_t  *shared_secret;
        uint16_t  shared_secret_len;

        uint8_t  *addr[3];
        uint32_t  len[3];

        uint8_t   dhkey[SHA256_MAC_LEN];
        uint8_t   kdk  [SHA256_MAC_LEN];

        uint8_t keys[WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN + WPS_EMSK_LEN];

        /* With the enrolle public key (which we received in M1) and our private
        *  key (which we generated above), obtain the Diffie Hellman shared
        *  secret (when receiving M2, the enrollee will be able to obtain this
        *  same shared secret using its private key and ou public key -contained
        *  in M2-)
        */
        if (PLATFORM_COMPUTE_DH_SHARED_SECRET(&shared_secret, &shared_secret_len, m2_pubkey, m2_pubkey_len, m1_privkey, m1_privkey_len) != 1) {
            log_i1905_e("PLATFORM_COMPUTE_DH_SHARED_SECRET failed");
            return 0;
        }
        /* TODO: ZERO PAD the shared_secret (doesn't seem to be really needed
        *  though)

        *  Next, obtain the SHA-256 digest of this shared secret. We will call
        *  this "dhkey"
        */
        addr[0] = shared_secret;
        len[0]  = shared_secret_len;

        if (PLATFORM_SHA256(1, addr, len, dhkey) != 1) {
            log_i1905_e("PLATFORM_SHA256 failed");
            return 0;
        }

        /* Next, concatenate three things (the enrolle nonce contained in M1,
        *  the enrolle MAC address, and the nonce we just generated before, and
        *  calculate its HMAC (hash message authentication code) using "dhkey"
        *  as the secret key.
        */
        addr[0] = m1_nonce;
        addr[1] = m1_mac;
        addr[2] = m2_nonce;
        len[0]  = 16;
        len[1]  = 6;
        len[2]  = 16;

        if (PLATFORM_HMAC_SHA256(dhkey, SHA256_MAC_LEN, 3, addr, len, kdk) != 1) {
            log_i1905_e("PLATFORM_HMAC_SHA256 failed");
            return 0;
        }

        /* Finally, take "kdk" and using a function provided in the "Wi-Fi
        *  simple configuration" standard, obtain THREE KEYS that we will use
        *  later ("authkey", "keywrapkey" and "emsk")
        */
        if(wps_key_derivation_function(kdk, NULL, 0, "Wi-Fi Easy and Secure Key Derivation", keys, sizeof(keys)) != 1) {
            log_i1905_e("wps_key_derivation_function failed");
            return 0;
        }

        memcpy(authkey,    keys,                                        WPS_AUTHKEY_LEN);
        memcpy(keywrapkey, keys + WPS_AUTHKEY_LEN,                      WPS_KEYWRAPKEY_LEN);
        memcpy(emsk,       keys + WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN, WPS_EMSK_LEN);

        log_i1905_t("WPS keys: ");
        log_i1905_t("  Registrar pubkey  (%3d bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", m2_pubkey_len,  m2_pubkey[0], m2_pubkey[1], m2_pubkey[2], m2_pubkey[m2_pubkey_len-3], m2_pubkey[m2_pubkey_len-2], m2_pubkey[m2_pubkey_len-1]);
        log_i1905_t("  Enrollee privkey  (%3d bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", m1_privkey_len,  m1_privkey[0], m1_privkey[1], m1_privkey[2], m1_privkey[m1_privkey_len-3], m1_privkey[m1_privkey_len-2], m1_privkey[m1_privkey_len-1]);
        log_i1905_t("  Enrollee pubkey   (%3d bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", m1_pubkey_len,  m1_pubkey[0], m1_pubkey[1], m1_pubkey[2], m1_pubkey[m1_pubkey_len-3], m1_pubkey[m1_pubkey_len-2], m1_pubkey[m1_pubkey_len-1]);
        log_i1905_t("  Shared secret     (%3d bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", shared_secret_len, shared_secret[0], shared_secret[1], shared_secret[2], shared_secret[shared_secret_len-3], shared_secret[shared_secret_len-2], shared_secret[shared_secret_len-1]);
        log_i1905_t("  DH key            ( 32 bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", dhkey[0], dhkey[1], dhkey[2], dhkey[29], dhkey[30], dhkey[31]);
        log_i1905_t("  Enrollee nonce    ( 16 bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", m1_nonce[0], m1_nonce[1], m1_nonce[2], m1_nonce[13], m1_nonce[14], m1_nonce[15]);
        log_i1905_t("  Registrar nonce   ( 16 bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", m2_nonce[0], m2_nonce[1], m2_nonce[2], m2_nonce[13], m2_nonce[14], m2_nonce[15]);
        log_i1905_t("  KDK               ( 32 bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", kdk[0], kdk[1], kdk[2], kdk[29], kdk[30], kdk[31]);
        log_i1905_t("  authkey           ( 32 bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", authkey[0], authkey[1], authkey[2], authkey[WPS_AUTHKEY_LEN-3], authkey[WPS_AUTHKEY_LEN-2], authkey[WPS_AUTHKEY_LEN-1]);
        log_i1905_t("  keywrapkey        ( 16 bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", keywrapkey[0], keywrapkey[1], keywrapkey[2], keywrapkey[WPS_KEYWRAPKEY_LEN-3], keywrapkey[WPS_KEYWRAPKEY_LEN-2], keywrapkey[WPS_KEYWRAPKEY_LEN-1]);
        log_i1905_t("  emsk              ( 32 bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", emsk[0], emsk[1], emsk[2], emsk[WPS_EMSK_LEN-3], emsk[WPS_EMSK_LEN-2], emsk[WPS_EMSK_LEN-1]);

        free(shared_secret);
    }

    /* With the just computed key, check the message authentication */
    {
        /* Concatenate M1 and M2 (excluding the last 12 bytes, where the
        *  authenticator attribute is contained) and calculate the HMAC, then
        *  check it against the actual authenticator attribute value.
        */
        uint8_t   hash[SHA256_MAC_LEN];

        uint8_t  *addr[2];
        uint32_t  len[2];

        addr[0] = m1;
        addr[1] = m2;
        len[0]  = m1_size;
        len[1]  = m2_size-12;

        if (PLATFORM_HMAC_SHA256(authkey, WPS_AUTHKEY_LEN, 2, addr, len, hash) != 1) {
            log_i1905_e("PLATFORM_HMAC_SHA256 failed");
            return 0;
        }

        if (memcmp(m2_authenticator, hash, 8) != 0) {
            log_i1905_e("Message M2 authentication failed");
            goto Fail;
        }
    }

    /* With the just computed keys, decrypt the message and check the keywrap */
    {
        uint8_t  *plain     = m2_encrypted_settings     + AES_BLOCK_SIZE;;
        uint32_t  plain_len = m2_encrypted_settings_len - AES_BLOCK_SIZE;

        log_i1905_t("AP settings before decryption (%d bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", plain_len, plain[0], plain[1], plain[2], plain[plain_len-3], plain[plain_len-2], plain[plain_len-1]);
        log_i1905_t("IV (%d bytes)                           : 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", AES_BLOCK_SIZE, m2_encrypted_settings[0], m2_encrypted_settings[1], m2_encrypted_settings[2], m2_encrypted_settings[AES_BLOCK_SIZE-3], m2_encrypted_settings[AES_BLOCK_SIZE-2], m2_encrypted_settings[AES_BLOCK_SIZE-1]);
        if (PLATFORM_AES_DECRYPT(keywrapkey, m2_encrypted_settings, plain, plain_len) != 1) {
            log_i1905_e("PLATFORM_AES_DECRYPT failed");
            return 0;
        }
        log_i1905_t("AP settings after  decryption (%d bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", plain_len, plain[0], plain[1], plain[2], plain[plain_len-3], plain[plain_len-2], plain[plain_len-1]);

        /* Remove padding */
        plain_len -= plain[plain_len-1];

        /* Parse contents of decrypted settings */
        ssid_present              = 0;
        bssid_present             = 0;
        auth_type_present         = 0;
        encryption_type_present   = 0;
        network_key_present       = 0;
        p                         = plain;
        while ((uint32_t)(p - plain) < plain_len) {
            uint16_t attr_type;
            uint16_t attr_len;

            _E2B(&p, &attr_type);
            _E2B(&p, &attr_len);

            if (ATTR_SSID == attr_type) {
                _EnB(&p, ssid, attr_len);
                ssid[attr_len] = 0x00;
                ssid_present = 1;
            } else if (ATTR_AUTH_TYPE == attr_type) {
                _E2B(&p, &auth_type);
                auth_type_present = 1;
            } else if (ATTR_ENCR_TYPE == attr_type) {
                _E2B(&p, &encryption_type);
                encryption_type_present = 1;
            } else if (ATTR_NETWORK_KEY == attr_type) {
                _EnB(&p, network_key, attr_len);
                network_key[attr_len] = 0x00;
                network_key_present = 1;
            } else if (ATTR_MAC_ADDR == attr_type) {
                _EnB(&p, bssid, attr_len);
                bssid_present = 1;
            }
#ifdef MULTIAP
            else if (ATTR_VENDOR_EXTENSION == attr_type) {
                uint8_t wfa_oui[3]     = {WPS_VENDOR_ID_WFA_1, WPS_VENDOR_ID_WFA_2, WPS_VENDOR_ID_WFA_3};
                elem_len = attr_len;

                _EnB(&p, oui, sizeof(oui));
                elem_len -= sizeof(oui);

                 /* Collect vendor specific info */
                vendor_elem = p;

                if (!memcmp(oui, wfa_oui, 3)) {
                    while (p - vendor_elem < elem_len) {
                        _E1B(&p, &wfa_elem);
                        _E1B(&p, &wfa_elem_len);

                        if (wfa_elem & WFA_ELEM_MAP_EXT_ATTR) {
                            _E1B(&p, &map_ext);
                            break;
                        } else {
                            p += wfa_elem_len;
                        }
                    }
                }
            }
#endif
            else if (ATTR_KEY_WRAP_AUTH == attr_type) {
                /* This attribute is always the last one contained in the plain
                *  text, thus 4 bytes *before* where "p" is pointing right now
                *  is the end of the plain text blob whose HMAC we are going to
                *  compute to check the keywrap.
                */
                uint8_t  *end_of_hmac = p - 4;
                uint8_t   hash[SHA256_MAC_LEN];
                uint8_t  *addr[1];
                uint32_t  len[1];

                addr[0] = plain;
                len[0]  = end_of_hmac-plain;

                if (PLATFORM_HMAC_SHA256(authkey, WPS_AUTHKEY_LEN, 1, addr, len, hash) != 1) {
                    log_i1905_e("PLATFORM_HMAC_SHA256 failed");
                    return 0;
                }

                if (memcmp(p, hash, 8) != 0) {
                    log_i1905_e("Message M2 keywrap failed (%d)", attr_len);
                    return 0;
                }

                p += attr_len;
            } else {
                p += attr_len;
            }
        }
        if (0 == ssid_present                  ||
            0 == bssid_present                 ||
            0 == auth_type_present             ||
            0 == encryption_type_present       ||
            0 == network_key_present)
        {
            log_i1905_e("Missing attributes in the configuration settings received in the M2 message");
            return 0;
        }
    }

    /* FRV: Removed original code to find bss to configre as not relevant for us if we would ever use this stack
            for agent too
    */

    /* Apply the security settings so that this AP clones the registrar configuration */
    PLATFORM_CONFIGURE_80211_AP(DMmacToInterfaceName(m1_mac), ssid, bssid, auth_type, encryption_type,
                                network_key, map_ext);

    return 1;

Fail:

    return 0;
}

//
//////////////////////////////////////// Registrar functions ///////////////////
//
#ifdef MULTIAP
uint8_t wscBuildM2(uint8_t *m1, uint16_t m1_size, uint8_t **m2, uint16_t *m2_size,
                   const map_profile_cfg_t *profile, uint8_t map_ext, char *recv_iface)
#else
uint8_t wscBuildM2(uint8_t *m1, uint16_t m1_size, uint8_t **m2, uint16_t *m2_size)
#endif

{
    uint8_t  *buffer;
    struct interfaceInfo  *x;

    uint8_t  *p;

    uint8_t   aux8;

    uint16_t  aux16;
    uint32_t  aux32;

    uint8_t  *m1_mac_address = NULL;  uint8_t m1_mac_address_present;
    uint8_t  *m1_nonce = NULL;        uint8_t m1_nonce_present;
    uint8_t  *m1_pubkey = NULL;       uint8_t m1_pubkey_present;
    uint16_t  m1_pubkey_len = 0;

    uint8_t  *local_privkey;
    uint16_t  local_privkey_len;

    uint8_t   authkey   [WPS_AUTHKEY_LEN];
    uint8_t   keywrapkey[WPS_KEYWRAPKEY_LEN];
    uint8_t   emsk      [WPS_EMSK_LEN];

    uint8_t  *priv, *pub;
    uint16_t  priv_len, pub_len;
    uint8_t   registrar_nonce[16];
    uint8_t   registrar_uuid[16];
    uint8_t   rf_bands = 0;
    uint16_t  g_auth_flags = 0;
    uint16_t  g_encrypt_flags = 0;

    char     *registrar_interface_name;

    /* If this node is processing an M1 message, it must mean one of our
    *  interfaces is the network registrar.
    */
#ifndef MULTIAP
    if (NULL == (registrar_interface_name = DMmacToInterfaceName(DMregistrarMacGet())))
#else
    if (NULL == profile) {
        return 0;
    }
    if (NULL == (registrar_interface_name = recv_iface))
#endif
    {
        log_i1905_e("None of this nodes' interfaces matches the registrar MAC address. Ignoring M1 message.");
        return 0;
    }

    /* We first need to extract the following parameters contained in "M1":
    *
    *   - Mac address
    *   - Nounce
    *   - Public key
    */
    m1_mac_address_present = 0;
    m1_nonce_present       = 0;
    m1_pubkey_present      = 0;
    p                      = m1;
    while (p - m1 < m1_size) {
        uint16_t attr_type;
        uint16_t attr_len;

        _E2B(&p, &attr_type);
        _E2B(&p, &attr_len);

        if (ATTR_MAC_ADDR == attr_type) {
            if (6 != attr_len) {
                log_i1905_e("Incorrect length (%d) for ATTR_MAC_ADDR", attr_len);
                return 0;
            }
            m1_mac_address = p;

            p += attr_len;
            m1_mac_address_present = 1;
        } else if (ATTR_ENROLLEE_NONCE == attr_type) {
            if (16 != attr_len) {
                log_i1905_e("Incorrect length (%d) for ATTR_ENROLLEE_NONCE", attr_len);
                return 0;
            }
            m1_nonce = p;

            p += attr_len;
            m1_nonce_present = 1;
        } else if (ATTR_PUBLIC_KEY == attr_type) {
            m1_pubkey_len = attr_len;
            m1_pubkey = p;

            p += attr_len;
            m1_pubkey_present = 1;
        } else if (ATTR_RF_BANDS == attr_type) {
            rf_bands = *p;
            p += attr_len;
        } else if (ATTR_AUTH_TYPE_FLAGS == attr_type) {
            _E2B(&p, &g_auth_flags);
            log_i1905_d(" M1 - AUTH_TYPE : 0x%04x", g_auth_flags);
        } else if (ATTR_ENCR_TYPE_FLAGS == attr_type) {
            _E2B(&p, &g_encrypt_flags);
            log_i1905_d(" M1 - ENCRYPTION_TYPE : 0x%04x", g_encrypt_flags);
        } else {
            p += attr_len;
        }
    }
    if (0 == m1_mac_address_present ||
        0 == m1_nonce_present       ||
        0 == m1_pubkey_present)
    {
        log_i1905_e("Imcomplete M1 message received");
        return 0;
    }

    /* Now we can build "M2" */
    if (NULL == (x = PLATFORM_GET_1905_INTERFACE_INFO(registrar_interface_name))) {
        log_i1905_e("Could not retrieve info of interface %s", registrar_interface_name);
        return 0;
    }

    if (!(buffer = malloc(1280))) {
        log_i1905_e("malloc() failed");
        goto fail;
    }
    p = buffer;

    /* VERSION */
    {
        aux16 = ATTR_VERSION;                                             _I2B(&aux16,     &p);
        aux16 = 1;                                                        _I2B(&aux16,     &p);
        aux8  = 0x10;                                                     _I1B(&aux8,      &p);
    }

    /* MESSAGE TYPE */
    {
        aux16 = ATTR_MSG_TYPE;                                            _I2B(&aux16,     &p);
        aux16 = 1;                                                        _I2B(&aux16,     &p);
        aux8  = WPS_M2;                                                   _I1B(&aux8,      &p);
    }

    /* ENROLLEE NONCE */
    {
        aux16 = ATTR_ENROLLEE_NONCE;                                      _I2B(&aux16,     &p);
        aux16 = 16;                                                       _I2B(&aux16,     &p);
                                                                          _InB( m1_nonce,  &p, 16);
    }

    /* REGISTRAR NONCE */
    {
        if (PLATFORM_GET_RANDOM_BYTES(registrar_nonce, 16) != 1) {
            log_i1905_e("PLATFORM_GET_RANDOM_BYTES failed");
            goto fail;
        }

        aux16 = ATTR_REGISTRAR_NONCE;                                     _I2B(&aux16,           &p);
        aux16 = 16;                                                       _I2B(&aux16,           &p);
                                                                          _InB( registrar_nonce, &p, 16);
    }

    /* UUID */
    {
        if ((x->interface_type == INTERFACE_TYPE_IEEE_802_3U_FAST_ETHERNET) ||
            (x->interface_type == INTERFACE_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET) ||
            (x->interface_type == INTERFACE_TYPE_UNKNOWN))
        {
            if (PLATFORM_GET_RANDOM_BYTES(registrar_uuid, sizeof(registrar_uuid)) != 1) {
                log_i1905_e("PLATFORM_GET_RANDOM_BYTES failed");
                goto fail;
            }
        } else {
            memcpy(registrar_uuid, x->uuid, sizeof(registrar_uuid));
        }

        aux16 = ATTR_UUID_R;                                              _I2B(&aux16,     &p);
        aux16 = 16;                                                       _I2B(&aux16,     &p);
                                                                          _InB(registrar_uuid,   &p, 16);
    }

    /* PUBLIC KEY */
    {
        if (PLATFORM_GENERATE_DH_KEY_PAIR(&priv, &priv_len, &pub, &pub_len) != 1) {
            log_i1905_e("PLATFORM_GENERATE_DH_KEY_PAIR failed");
            goto fail;
        }
        /* TODO: ZERO PAD the pub key (doesn't seem to be really needed though) */

        aux16 = ATTR_PUBLIC_KEY;                                          _I2B(&aux16,       &p);
        aux16 = pub_len;                                                  _I2B(&aux16,       &p);
                                                                          _InB( pub,         &p, pub_len);

        /* We will use it later... save it. */
        local_privkey     = priv;
        local_privkey_len = priv_len;
    }

    /* Key derivation (no bytes are written to the output buffer in the next
    *  block of code, we just obtain three cryptographic keys that are needed later
    */
    {
        uint8_t  *shared_secret;
        uint16_t  shared_secret_len;

        uint8_t  *addr[3];
        uint32_t  len[3];

        uint8_t   dhkey[SHA256_MAC_LEN];
        uint8_t   kdk  [SHA256_MAC_LEN];

        uint8_t   keys[WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN + WPS_EMSK_LEN];

        /* With the enrolle public key (which we received in M1) and our private
        *  key (which we generated above), obtain the Diffie Hellman shared
        *  secret (when receiving M2, the enrollee will be able to obtain this
        *  same shared secret using its private key and our public key
        *  -contained in M2-)
        */
        if (PLATFORM_COMPUTE_DH_SHARED_SECRET(&shared_secret, &shared_secret_len, m1_pubkey, m1_pubkey_len, local_privkey, local_privkey_len) != 1) {
            log_i1905_e("PLATFORM_COMPUTE_DH_SHARED_SECRET failed");
            goto fail;
        }

        /* TODO: ZERO PAD the shared_secret (doesn't seem to be really needed though) */

        /* Next, obtain the SHA-256 digest of this shared secret. We will call this "dhkey" */
        addr[0] = shared_secret;
        len[0]  = shared_secret_len;

        if (PLATFORM_SHA256(1, addr, len, dhkey) != 1) {
            log_i1905_e("PLATFORM_SHA256 failed");
            goto fail;
        }

        /* Next, concatenate three things (the enrollee nonce contained in M1,
        *  the enrolle MAC address -also contained in M1-, and the nonce we just
        *  generated before and calculate its HMAC (hash message authentication
        *  code) using "dhkey" as the secret key.
        */
        addr[0] = m1_nonce;
        addr[1] = m1_mac_address;
        addr[2] = registrar_nonce;
        len[0]  = 16;
        len[1]  = 6;
        len[2]  = 16;

        if (PLATFORM_HMAC_SHA256(dhkey, SHA256_MAC_LEN, 3, addr, len, kdk) != 1) {
            log_i1905_e("PLATFORM_HMAC_SHA256 failed");
            goto fail;
        }

        /* Finally, take "kdk" and using a function provided in the "Wi-Fi
        *  simple configuration" standard, obtain THREE KEYS that we will use
        *  later ("authkey", "keywrapkey" and "emsk")
        */
        if (wps_key_derivation_function(kdk, NULL, 0, "Wi-Fi Easy and Secure Key Derivation", keys, sizeof(keys)) != 1) {
            log_i1905_e("wps_key_derivation_function failed");
            goto fail;
        }

        memcpy(authkey,    keys,                                        WPS_AUTHKEY_LEN);
        memcpy(keywrapkey, keys + WPS_AUTHKEY_LEN,                      WPS_KEYWRAPKEY_LEN);
        memcpy(emsk,       keys + WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN, WPS_EMSK_LEN);

        log_i1905_t("WPS keys: ");
        log_i1905_t("  Enrollee pubkey   (%3d bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", m1_pubkey_len,  m1_pubkey[0], m1_pubkey[1], m1_pubkey[2], m1_pubkey[m1_pubkey_len-3], m1_pubkey[m1_pubkey_len-2], m1_pubkey[m1_pubkey_len-1]);
        log_i1905_t("  Registrar privkey (%3d bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", local_privkey_len,  local_privkey[0], local_privkey[1], local_privkey[2], local_privkey[local_privkey_len-3], local_privkey[local_privkey_len-2], local_privkey[local_privkey_len-1]);
        log_i1905_t("  Registrar pubkey  (%3d bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", pub_len,  pub[0], pub[1], pub[2], pub[pub_len -3], pub[pub_len-2], pub[pub_len-1]);
        log_i1905_t("  Shared secret     (%3d bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", shared_secret_len, shared_secret[0], shared_secret[1], shared_secret[2], shared_secret[shared_secret_len-3], shared_secret[shared_secret_len-2], shared_secret[shared_secret_len-1]);
        log_i1905_t("  DH key            ( 32 bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", dhkey[0], dhkey[1], dhkey[2], dhkey[29], dhkey[30], dhkey[31]);
        log_i1905_t("  Enrollee nonce    ( 16 bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", m1_nonce[0], m1_nonce[1], m1_nonce[2], m1_nonce[13], m1_nonce[14], m1_nonce[15]);
        log_i1905_t("  Registrar nonce   ( 16 bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", registrar_nonce[0], registrar_nonce[1], registrar_nonce[2], registrar_nonce[13], registrar_nonce[14], registrar_nonce[15]);
        log_i1905_t("  KDK               ( 32 bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", kdk[0], kdk[1], kdk[2], kdk[29], kdk[30], kdk[31]);
        log_i1905_t("  authkey           ( 32 bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", authkey[0], authkey[1], authkey[2], authkey[WPS_AUTHKEY_LEN-3], authkey[WPS_AUTHKEY_LEN-2], authkey[WPS_AUTHKEY_LEN-1]);
        log_i1905_t("  keywrapkey        ( 16 bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", keywrapkey[0], keywrapkey[1], keywrapkey[2], keywrapkey[WPS_KEYWRAPKEY_LEN-3], keywrapkey[WPS_KEYWRAPKEY_LEN-2], keywrapkey[WPS_KEYWRAPKEY_LEN-1]);
        log_i1905_t("  emsk              ( 32 bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", emsk[0], emsk[1], emsk[2], emsk[WPS_EMSK_LEN-3], emsk[WPS_EMSK_LEN-2], emsk[WPS_EMSK_LEN-1]);

        free(shared_secret);
    }

    free(priv);
    free(pub);

    /* AUTHENTICATION TYPES */
    {
        aux16 = ATTR_AUTH_TYPE_FLAGS;                                     _I2B(&aux16,      &p);
        aux16 = 2;                                                        _I2B(&aux16,      &p);

        /*
        * FIXME: For controller certification we need to give back
        * the same flags we received in M1.
        */
        aux16 = g_auth_flags;                                             _I2B(&aux16,      &p);
        //aux16 = profile->supported_auth_modes;                             _I2B(&aux16,      &p);
        log_i1905_d(" M2 CLEAR - AUTH_TYPE : 0x%04x", aux16);
    }

    /* ENCRYPTION TYPES */
    {
        aux16 = ATTR_ENCR_TYPE_FLAGS;                                     _I2B(&aux16,     &p);
        aux16 = 2;                                                        _I2B(&aux16,     &p);

        /*
        * FIXME: For controller certification we need to give back
        * the same flags we received in M1.
        */
        aux16 = g_encrypt_flags;                             _I2B(&aux16,      &p);
        //aux16 = profile->supported_encryption_types;                       _I2B(&aux16,     &p)
        log_i1905_d(" M2 CLEAR - ENCRYPTION_TYPE : 0x%04x", aux16);
    }

    /* CONNECTION TYPES */
    {
        /* Two possible types: ESS or IBSS. In the 1905 context, registrars
        *  will always be "ESS", meaning they are willing to have their
        *  credentials cloned by other APs in order to end up with a network
        *  which is "roaming-friendly" ("ESS": "extended service set")
        */

        aux16 = ATTR_CONN_TYPE_FLAGS;                                     _I2B(&aux16,     &p);
        aux16 = 1;                                                        _I2B(&aux16,     &p);
        aux8  = WPS_CONN_ESS;                                             _I1B(&aux8,      &p);
    }

    /* CONFIGURATION METHODS */
    {
        /* In the 1905 context, the configuration methods the AP is willing to
        *  offer will always be these two
        */

        aux16 = ATTR_CONFIG_METHODS;                                      _I2B(&aux16,     &p);
        aux16 = 2;                                                        _I2B(&aux16,     &p);
        aux16 = WPS_CONFIG_PHY_PUSHBUTTON | WPS_CONFIG_VIRT_PUSHBUTTON;   _I2B(&aux16,     &p);
    }

    /* MANUFACTURER */
    {
        aux16 = ATTR_MANUFACTURER;                                        _I2B(&aux16,                &p);
        aux16 = strlen(x->manufacturer_name);                             _I2B(&aux16,                &p);
                                                                          _InB( x->manufacturer_name, &p, strlen(x->manufacturer_name));
    }

    /* MODEL NAME */
    {
        aux16 = ATTR_MODEL_NAME;                                          _I2B(&aux16,         &p);
        aux16 = strlen(x->model_name);                                    _I2B(&aux16,         &p);
                                                                          _InB( x->model_name, &p, strlen(x->model_name));
    }

    /* MODEL NUMBER */
    {
        aux16 = ATTR_MODEL_NUMBER;                                        _I2B(&aux16,           &p);
        aux16 = strlen(x->model_number);                                  _I2B(&aux16,           &p);
                                                                          _InB( x->model_number, &p, strlen(x->model_number));
    }

    /* SERIAL NUMBER */
    {
        aux16 = ATTR_SERIAL_NUMBER;                                       _I2B(&aux16,            &p);
        aux16 = strlen(x->serial_number);                                 _I2B(&aux16,            &p);
                                                                          _InB( x->serial_number, &p, strlen(x->serial_number));
    }

    /* PRIMARY DEVICE TYPE */
    {
        /* In the 1905 context, they node sending a M2 message will always be
        *  (at least) a "network router"
        */

        uint8_t oui[4] = {0x00, 0x50, 0xf2, 0x04}; /* Fixed value from the WSC spec for Wi-Fi Alliance */

        aux16 = ATTR_PRIMARY_DEV_TYPE;                                    _I2B(&aux16,         &p);
        aux16 = 8;                                                        _I2B(&aux16,         &p);
        aux16 = WPS_DEV_NETWORK_INFRA;                                    _I2B(&aux16,         &p);
                                                                          _InB( oui,           &p, 4);
#ifdef MULTIAP
        /* In the MULTIAP context, the node sending a M1 message will always be
        *  (at least) a "network AP"
        */
        aux16 = WPS_DEV_NETWORK_INFRA_AP;                                 _I2B(&aux16,         &p);
#else
        aux16 = WPS_DEV_NETWORK_INFRA_ROUTER;                             _I2B(&aux16,         &p);
#endif
    }

    /* DEVICE NAME */
    {
        aux16 = ATTR_DEV_NAME;                                            _I2B(&aux16,          &p);
        aux16 = strlen(x->device_name);                                   _I2B(&aux16,          &p);
                                                                          _InB( x->device_name, &p, strlen(x->device_name));
    }

    /* RF BANDS */
    {
#ifndef MULTIAP

        rf_bands = 0;

        if (       INTERFACE_TYPE_IEEE_802_11B_2_4_GHZ ==  x->interface_type ||
                   INTERFACE_TYPE_IEEE_802_11G_2_4_GHZ ==  x->interface_type ||
                   INTERFACE_TYPE_IEEE_802_11N_2_4_GHZ ==  x->interface_type) {
            rf_bands = WPS_RF_24GHZ;
        } else if (INTERFACE_TYPE_IEEE_802_11A_5_GHZ  ==  x->interface_type ||
                   INTERFACE_TYPE_IEEE_802_11N_5_GHZ  ==  x->interface_type ||
                   INTERFACE_TYPE_IEEE_802_11AC_5_GHZ ==  x->interface_type) {
            rf_bands = WPS_RF_5GHZ;
        } else if (INTERFACE_TYPE_IEEE_802_11AD_60_GHZ ==  x->interface_type) {
            rf_bands = WPS_RF_60GHZ;
        }
#endif
        aux16 = ATTR_RF_BANDS;                                            _I2B(&aux16,         &p);
        aux16 = 1;                                                        _I2B(&aux16,         &p);
                                                                          _I1B(&rf_bands,      &p);
    }

    /* ASSOCIATION STATE */
    {
        aux16 = ATTR_ASSOC_STATE;                                         _I2B(&aux16,         &p);
        aux16 = 2;                                                        _I2B(&aux16,         &p);
        aux16 = WPS_ASSOC_CONN_SUCCESS;                                   _I2B(&aux16,         &p);
    }

    /* CONFIG ERROR */
    {
        aux16 = ATTR_CONFIG_ERROR;                                        _I2B(&aux16,         &p);
        aux16 = 2;                                                        _I2B(&aux16,         &p);
        aux16 = WPS_CFG_NO_ERROR;                                         _I2B(&aux16,         &p);
    }

    /* DEVICE PASSWORD ID */
    {
        aux16 = ATTR_DEV_PASSWORD_ID;                                     _I2B(&aux16,         &p);
        aux16 = 2;                                                        _I2B(&aux16,         &p);
        aux16 = DEV_PW_PUSHBUTTON;                                        _I2B(&aux16,         &p);
    }

    /* OS VERSION */
    {
        /* TODO: Fill with actual properties from the interface */

        uint32_t os_version = 0x00000001;

        aux16 = ATTR_OS_VERSION;                                          _I2B(&aux16,         &p);
        aux16 = 4;                                                        _I2B(&aux16,         &p);
        aux32 = 0x80000000 | os_version;                                  _I4B(&aux32,         &p);
    }

#ifndef MULTIAP
    /* VENDOR EXTENSIONS */
    {
        aux16 = ATTR_VENDOR_EXTENSION;                                    _I2B(&aux16,         &p);
        aux16 = 6;                                                        _I2B(&aux16,         &p);
        aux8  = WPS_VENDOR_ID_WFA_1;                                      _I1B(&aux8,          &p);
        aux8  = WPS_VENDOR_ID_WFA_2;                                      _I1B(&aux8,          &p);
        aux8  = WPS_VENDOR_ID_WFA_3;                                      _I1B(&aux8,          &p);
        aux8  = WFA_ELEM_VERSION2;                                        _I1B(&aux8,          &p);
        aux8  = 1;                                                        _I1B(&aux8,          &p);
        aux8  = WPS_VERSION;                                              _I1B(&aux8,          &p);
    }
#endif

    /* ENCRYPTED SETTINGS */
    {
        /* This is what we are going to do next:
        *
        *    1. Fill a tmp buffer ("aux") ith credential attributes (SSID,
        *       network key, etc...)
        *
        *    2. Add an HMAC to this tmp buffer (so that the enrollee, when
        *       receiving this buffer in M2, can be sure no one has tampered
        *       with these attributes)
        *
        *    3. Encryp the message + HMAC with AES (so that no one else
        *       snooping can have a look at these attributes)
        */

        uint8_t     plain[1024];
        uint8_t     hash[SHA256_MAC_LEN];
        uint8_t    *iv_start;
        uint8_t    *data_start;
        uint8_t    *r;
        uint8_t     pad_elements_nr;

        uint8_t    *addr[1];
        uint32_t    len[1];

        const char *ssid;
        const char *network_key;
        uint16_t    authentication_mode;
        uint16_t    encryption_mode;

#ifdef MULTIAP

        ssid        = profile->bss_ssid;
        network_key = profile->wpa_key;

        /* FRV: TOTO Check the usage of the global g_auth_flags... */

        if (((profile->supported_auth_modes) & (IEEE80211_AUTH_MODE_SAE | IEEE80211_AUTH_MODE_WPA2PSK)) &&
            ((g_auth_flags)& IEEE80211_AUTH_MODE_SAE))
        {
            authentication_mode = profile->supported_auth_modes;
            encryption_mode = profile->supported_encryption_types;
        }
        else if (((profile->supported_auth_modes)&(IEEE80211_AUTH_MODE_SAE | IEEE80211_AUTH_MODE_WPA2PSK)) &&
                 !((g_auth_flags) & IEEE80211_AUTH_MODE_SAE) && ((g_auth_flags) & IEEE80211_AUTH_MODE_WPA2PSK))
        {
            authentication_mode = IEEE80211_AUTH_MODE_WPA2PSK;
            encryption_mode = profile->supported_encryption_types;
        }
        else
        {
            authentication_mode = profile->supported_auth_modes;
            encryption_mode = profile->supported_encryption_types;
        }
#else
        ssid                = x->interface_type_data.ieee80211.ssid;
        network_key         = x->interface_type_data.ieee80211.network_key;
        authentication_mode = x->interface_type_data.ieee80211.authentication_mode;
        encryption_mode     = x->interface_type_data.ieee80211.encryption_mode;

        /* For ethernet as backhaul use this default encryption type */
        if ((x->interface_type == INTERFACE_TYPE_IEEE_802_3U_FAST_ETHERNET) ||
            (x->interface_type == INTERFACE_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET) ||
            (x->interface_type == INTERFACE_TYPE_UNKNOWN))
        {
            authentication_mode = WPS_AUTH_WPA2PSK;
            encryption_mode    = WPS_ENCR_AES;
        }
#endif
        r = plain;

        /* SSID */
        aux16 = ATTR_SSID;                                                _I2B(&aux16,         &r);
        aux16 = strlen(ssid);                                             _I2B(&aux16,         &r);
                                                                          _InB( ssid,          &r, strlen(ssid));

        /* AUTH TYPE */
        aux16 = ATTR_AUTH_TYPE;                                           _I2B(&aux16,         &r);
        aux16 = 2;                                                        _I2B(&aux16,         &r);
        aux16 = authentication_mode;                                      _I2B(&aux16,         &r);

        /* ENCRYPTION TYPE */
        aux16 = ATTR_ENCR_TYPE;                                           _I2B(&aux16,         &r);
        aux16 = 2;                                                        _I2B(&aux16,         &r);
        aux16 = encryption_mode;                                          _I2B(&aux16,         &r);

        /* NETWORK KEY */
        aux16 = ATTR_NETWORK_KEY;                                         _I2B(&aux16,         &r);
        aux16 = strlen(network_key);                                      _I2B(&aux16,         &r);
                                                                          _InB( network_key,   &r, strlen(network_key));

        /* MAC ADDR */
        aux16 = ATTR_MAC_ADDR;                                            _I2B(&aux16,           &r);
        aux16 = 6;                                                        _I2B(&aux16,           &r);
#if 0
        /*
         * FIXME: For controller certification if test case 5.8.1 fails,
         * we might need to enable this.
         */
        uint8_t empty_mac[6] = {0};
        if (memcmp(x->mac_address, empty_mac, 6) == 0) {
            uint8_t mac_adr[6] = { 0xa6, 0x91, 0xb1, 0x51, 0x25, 0x17}; memcpy(x->mac_address, mac_adr, 6);
        }
#endif
                                                                          _InB( x->mac_address,  &r, 6);
        /* VENDOR EXTENSIONS (WPS + MAP) */
        {
#define MAP_ATTR_LEN  3
            aux16 = ATTR_VENDOR_EXTENSION;                                    _I2B(&aux16,         &r);
            aux16 = 6 + MAP_ATTR_LEN;                                         _I2B(&aux16,         &r);
            aux8  = WPS_VENDOR_ID_WFA_1;                                      _I1B(&aux8,          &r);
            aux8  = WPS_VENDOR_ID_WFA_2;                                      _I1B(&aux8,          &r);
            aux8  = WPS_VENDOR_ID_WFA_3;                                      _I1B(&aux8,          &r);
            aux8  = WFA_ELEM_VERSION2;                                        _I1B(&aux8,          &r);
            aux8  = 1;                                                        _I1B(&aux8,          &r);
            aux8  = WPS_VERSION;                                              _I1B(&aux8,          &r);

#ifdef MULTIAP
            /* MULTIAP VENDOR EXTENSION */
            aux8 = WFA_ELEM_MAP_EXT_ATTR;                                     _I1B(&aux8,          &r);
            aux8 = 1;                                                         _I1B(&aux8,          &r);
            aux8 = map_ext;                                                   _I1B(&aux8,          &r);
#endif
        }

        log_i1905_d("AP configuration settings that we are going to send:");
        log_i1905_d("  - SSID            : %s", ssid);
        log_i1905_d("  - BSSID           : %02x:%02x:%02x:%02x:%02x:%02x", x->mac_address[0], x->mac_address[1], x->mac_address[2], x->mac_address[3], x->mac_address[4], x->mac_address[5]);
        log_i1905_d("  - AUTH_TYPE       : 0x%04x", profile->supported_auth_modes);
        log_i1905_d("  - ENCRYPTION_TYPE : 0x%04x", profile->supported_encryption_types);
        log_i1905_d("  - MAP_EXTENSION   : 0x%02x", map_ext);

        /* Obtain the HMAC of the whole plain buffer using "authkey" as the
        *  secret key.
        */
        addr[0] = plain;
        len[0]  = r-plain;
        if (PLATFORM_HMAC_SHA256(authkey, WPS_AUTHKEY_LEN, 1, addr, len, hash) != 1) {
            log_i1905_e("PLATFORM_HMAC_SHA256 failed");
            goto fail;
        }

        /* ...and add it to the same plain buffer (well, only the first 8 bytes
        * of the hash)
        */
        aux16 = ATTR_KEY_WRAP_AUTH;                                       _I2B(&aux16,         &r);
        aux16 = 8;                                                        _I2B(&aux16,         &r);
                                                                          _InB( hash,          &r, 8);

        /* Finally, encrypt everything with AES and add the resulting blob to
        *  the M2 buffer, as an "ATTR_ENCR_SETTINGS" attribute
        *
        *    Pad the length of the message to encrypt to a multiple of
        *    AES_BLOCK_SIZE. The new padded bytes must have their value equal to
        *    the amount of bytes padded (PKCS#5 v2.0 pad)
        */
        pad_elements_nr = AES_BLOCK_SIZE - ((r-plain) % AES_BLOCK_SIZE);
        for (aux8 = 0; aux8<pad_elements_nr; aux8++) {
            _I1B(&pad_elements_nr, &r);
        }

        /*   Add the attribute header ("type" and "lenght") to the M2 buffer,
        *    followed by the IV and the data to encrypt.
        */
        aux16 = ATTR_ENCR_SETTINGS;                                       _I2B(&aux16,         &p);
        aux16 = AES_BLOCK_SIZE + (r-plain);                               _I2B(&aux16,         &p);
        iv_start   = p;
        if (PLATFORM_GET_RANDOM_BYTES(p, AES_BLOCK_SIZE) != 1) {
            log_i1905_e("PLATFORM_GET_RANDOM_BYTES failed");
            goto fail;
        }
        p+=AES_BLOCK_SIZE;

        data_start = p; _InB(plain, &p, r-plain);
        /*   Encrypt the data IN-PLACE. Note that the "ATTR_ENCR_SETTINGS"
        *    attribute containes both the IV and the encrypted data.
        */
        log_i1905_t("AP settings before encryption (%d bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", (int)(r-plain), data_start[0], data_start[1], data_start[2], data_start[(r-plain)-3], data_start[(r-plain)-2], data_start[(r-plain)-1]);
        log_i1905_t("IV (%d bytes)                           : 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", AES_BLOCK_SIZE, iv_start[0], iv_start[1], iv_start[2], iv_start[AES_BLOCK_SIZE-3], iv_start[AES_BLOCK_SIZE-2], iv_start[AES_BLOCK_SIZE-1]);
        if (PLATFORM_AES_ENCRYPT(keywrapkey, iv_start, data_start, r-plain) != 1) {
            log_i1905_e("PLATFORM_AES_ENCRYPT failed");
            goto fail;
        }
        log_i1905_t("AP settings after  encryption (%d bytes): 0x%02x, 0x%02x, 0x%02x, ..., 0x%02x, 0x%02x, 0x%02x", (int)(r-plain), data_start[0], data_start[1], data_start[2], data_start[(r-plain)-3], data_start[(r-plain)-2], data_start[(r-plain)-1]);
    }

    /* AUTHENTICATOR */
    {
        /* This one is easy: concatenate M1 and M2 (everything in the M2 buffer
        *  up to this point) and calculate the HMAC, then append it to M2 as
        *  a new (and final!) attribute
        */
        uint8_t   hash[SHA256_MAC_LEN];
        uint8_t  *addr[2];
        uint32_t  len[2];

        addr[0] = m1;
        addr[1] = buffer;
        len[0]  = m1_size;
        len[1]  = p-buffer;

        if (PLATFORM_HMAC_SHA256(authkey, WPS_AUTHKEY_LEN, 2, addr, len, hash) != 1) {
            log_i1905_e("PLATFORM_HMAC_SHA256 failed");
            goto fail;
        }

        aux16 = ATTR_AUTHENTICATOR;                                       _I2B(&aux16,         &p);
        aux16 = 8;                                                        _I2B(&aux16,         &p);
                                                                          _InB( hash,          &p,  8);
    }

    PLATFORM_FREE_1905_INTERFACE_INFO(x);

    *m2      = buffer;
    *m2_size = p-buffer;

    return 1;

fail:
    PLATFORM_FREE_1905_INTERFACE_INFO(x);
    free(buffer);

    return 0;
}

uint8_t wscFreeM2(uint8_t *m, uint16_t m_size)
{
    if (0 == m_size || NULL == m) {
        return 1;
    }

    free(m);
    return 1;
}

/*#######################################################################
#                       COMMON FUNCTIONS                                 #
########################################################################*/
uint8_t wscGetType(uint8_t *m, uint16_t m_size)
{
    uint8_t *p = m;

    while (p - m < m_size) {
        uint16_t attr_type;
        uint16_t attr_len;
        uint8_t  msg_type;

        _E2B(&p, &attr_type);
        _E2B(&p, &attr_len);

        if (ATTR_MSG_TYPE == attr_type) {
            if (1 != attr_len) {
                log_i1905_e("Incorrect length (%d) for ATTR_MSG_TYPE", attr_len);
                return WSC_TYPE_UNKNOWN;
            }
            _E1B(&p, &msg_type);

            if (WPS_M1 == msg_type) {
                return WSC_TYPE_M1;
            } else if (WPS_M2 == msg_type) {
                return WSC_TYPE_M2;
            } else {
                return WSC_TYPE_UNKNOWN;
            }
        } else {
            p += attr_len;
        }
    }

    return WSC_TYPE_UNKNOWN;
}
