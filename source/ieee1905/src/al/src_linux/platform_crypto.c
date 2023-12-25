/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

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
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#define LOG_TAG "crypto"

#include "platform.h"
#include "platform_crypto.h"

/*#######################################################################
#                       GLOBALS                                         #
########################################################################*/
/* Diffie Hellman group "1536-bit MODP" parameters as specified in RFC3526
   "section 2"
*/
static uint8_t g_dh1536_p[] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,
        0x21,0x68,0xC2,0x34,0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
        0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
        0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
        0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,
        0xF2,0x5F,0x14,0x37,0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
        0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,0xF4,0x4C,0x42,0xE9,
        0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
        0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,
        0x7C,0x4B,0x1F,0xE6,0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,
        0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,0x98,0xDA,0x48,0x36,
        0x1C,0x55,0xD3,0x9A,0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
        0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,0x1C,0x62,0xF3,0x56,
        0x20,0x85,0x52,0xBB,0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,
        0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,0xF1,0x74,0x6C,0x08,
        0xCA,0x23,0x73,0x27,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    };

static uint8_t g_dh1536_g[] = { 0x02 };

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
uint8_t PLATFORM_GET_RANDOM_BYTES(uint8_t *p, uint16_t len)
{
    FILE     *fd;
    uint32_t  rc;

    fd = fopen("/dev/urandom", "rb");
    if (NULL == fd) {
        log_i1905_e("cannot open /dev/urandom");
        return 0;
    }

    rc = fread(p, 1, len, fd);

    fclose(fd);

    if (len != rc) {
        log_i1905_e("could not obtain enough random bytes");
        return 0;
    } else {
        return 1;
    }
}

uint8_t PLATFORM_GENERATE_DH_KEY_PAIR(uint8_t **priv, uint16_t *priv_len, uint8_t **pub,
                                      uint16_t *pub_len)
{
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    DH *dh = NULL;
#else
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *dh_ctx = NULL;
    EVP_PKEY *param_pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *bn_priv = NULL;
    BIGNUM *bn_pub = NULL;
    int selection = OSSL_KEYMGMT_SELECT_ALL;
#endif

    if (NULL == priv     ||
        NULL == priv_len ||
        NULL == pub      ||
        NULL == pub_len) {
        return 0;
    }

    /* Create prime and generator by converting binary to BIGNUM format */
    p = BN_bin2bn(g_dh1536_p, sizeof(g_dh1536_p), NULL);
    if (p == NULL) {
        goto bail;
    }
    g = BN_bin2bn(g_dh1536_g, sizeof(g_dh1536_g), NULL);
    if (g == NULL) {
        goto bail;
    }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (NULL == (dh = DH_new())) {
        goto bail;
    }
#else
    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld == NULL) {
        goto bail;
    }
#endif

    /* Set prime and generator */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    dh->p = p;
    dh->g = g;
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
    if (DH_set0_pqg(dh, p, NULL, g) != 1) {
        goto bail;
    }
#else
    if (OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_P, p) != 1 ||
        OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_G, g) != 1) {
        goto bail;
    }
    params = OSSL_PARAM_BLD_to_param(param_bld);
    if (params == NULL) {
        goto bail;
    }
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    /* Obtain key pair */
    if (0 == DH_generate_key(dh)) {
        goto bail;
    }
#else
    /* Create DH context */
    dh_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (dh_ctx == NULL) {
        goto bail;
    }
    if (EVP_PKEY_fromdata_init(dh_ctx) != 1) {
        goto bail;
    }
    if (EVP_PKEY_fromdata(dh_ctx, &param_pkey, selection, params) != 1 || param_pkey == NULL) {
        goto bail;
    }

    /* Create key pair */
    pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, param_pkey, NULL);
    if (pkey_ctx == NULL) {
        goto bail;
    }
    if (EVP_PKEY_keygen_init(pkey_ctx) != 1) {
        goto bail;
    }
    if (EVP_PKEY_keygen(pkey_ctx, &pkey) != 1 || pkey == NULL) {
        goto bail;
    }
#endif

    /* Get private key */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    *priv_len = BN_num_bytes(dh->priv_key);
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
    *priv_len = BN_num_bytes(DH_get0_priv_key(dh));
#else
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn_priv) != 1 || bn_priv == NULL) {
        goto bail;
    }
    *priv_len = BN_num_bytes(bn_priv);
#endif
    *priv = (uint8_t *)calloc(1, *priv_len);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    BN_bn2bin(dh->priv_key, *priv);
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
    BN_bn2bin(DH_get0_priv_key(dh), *priv);
#else
    BN_bn2bin(bn_priv, *priv);
#endif

    /* Get public key */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    *pub_len = BN_num_bytes(dh->pub_key);
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
    *pub_len = BN_num_bytes(DH_get0_pub_key(dh));
#else
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, &bn_pub) != 1 || bn_pub == NULL) {
        goto bail;
    }
    *pub_len = BN_num_bytes(bn_pub);
#endif
    *pub = malloc(*pub_len);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    BN_bn2bin(dh->pub_key, *pub);
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
    BN_bn2bin(DH_get0_pub_key(dh), *pub);
#else
    BN_bn2bin(bn_pub, *pub);
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    DH_free(dh);
    /* NOTE: This internally frees "dh->p" and "dh->q", thus no need for us
             to do anything else.
    */
#else
    /* Release resources */
    BN_clear_free(bn_pub);
    BN_clear_free(bn_priv);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(param_pkey);
    EVP_PKEY_CTX_free(dh_ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    BN_clear_free(g);
    BN_clear_free(p);
#endif

    return 1;

bail:
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (dh) {
        DH_free(dh);
    } else {
        BN_clear_free(g);
        BN_clear_free(p);
    }
#else
    if (*pub) {
        free(*pub);
        *pub = NULL;
    }
    BN_clear_free(bn_pub);
    if (*priv) {
        free(*priv);
        *priv = NULL;
    }
    BN_clear_free(bn_priv);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(param_pkey);
    EVP_PKEY_CTX_free(dh_ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    BN_clear_free(g);
    BN_clear_free(p);
#endif

    return 0;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static EVP_PKEY *create_dh_pkey(BIGNUM *p, BIGNUM *g, BIGNUM *bn_priv, BIGNUM *bn_pub)
{
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *dh_ctx = NULL;
    EVP_PKEY *dh_pkey = NULL;
    int selection = EVP_PKEY_KEYPAIR;

    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld == NULL) {
        goto bail;
    }

    /* Set prime, generator and private or public key */
    if (OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_P, p) != 1 ||
        OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_G, g) != 1) {
        goto bail;
    }
    if (bn_priv) {
        if (OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, bn_priv) != 1) {
            goto bail;
        }
    }
    if (bn_pub) {
        if (OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PUB_KEY, bn_pub) != 1) {
            goto bail;
        }
    }
    params = OSSL_PARAM_BLD_to_param(param_bld);
    if (params == NULL) {
        goto bail;
    }

    dh_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (dh_ctx == NULL) {
        goto bail;
    }
    if (EVP_PKEY_fromdata_init(dh_ctx) != 1) {
        goto bail;
    }
    if (EVP_PKEY_fromdata(dh_ctx, &dh_pkey, selection, params) != 1 || dh_pkey == NULL) {
        goto bail;
    }

    /* Release resources */
    EVP_PKEY_CTX_free(dh_ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);

    return dh_pkey;

bail:
    EVP_PKEY_free(dh_pkey);
    EVP_PKEY_CTX_free(dh_ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);

    return NULL;
}
#endif

uint8_t PLATFORM_COMPUTE_DH_SHARED_SECRET(uint8_t **shared_secret, uint16_t *shared_secret_len,
                                          uint8_t *remote_pub, uint16_t remote_pub_len,
                                          uint8_t *local_priv, uint8_t local_priv_len)
{
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
    BIGNUM *bn_priv = NULL;
    BIGNUM *bn_pub = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    DH *dh = NULL;
    size_t rlen;
#else
    EVP_PKEY *dh_priv = NULL;
    EVP_PKEY *dh_pub = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
#endif
    size_t secret_len = 0;

    if (NULL == shared_secret     ||
        NULL == shared_secret_len ||
        NULL == remote_pub        ||
        NULL == local_priv) {
        return 0;
    }

    /* Create prime and generator by converting binary to BIGNUM format */
    p = BN_bin2bn(g_dh1536_p, sizeof(g_dh1536_p), NULL);
    if (p == NULL) {
        goto bail;
    }
    g = BN_bin2bn(g_dh1536_g, sizeof(g_dh1536_g), NULL);
    if (g == NULL) {
        goto bail;
    }
    bn_priv = BN_bin2bn(local_priv, local_priv_len, NULL);
    if (bn_priv == NULL) {
        goto bail;
    }
    bn_pub = BN_bin2bn(remote_pub, remote_pub_len, NULL);
    if (bn_pub == NULL) {
        goto bail;
    }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (NULL == (dh = DH_new())) {
        goto bail;
    }
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    dh->p = p;
    dh->g = g;
    dh->priv_key = bn_priv;
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
    if (DH_set0_pqg(dh, p, NULL, g) != 1) {
        BN_clear_free(bn_priv);
        goto bail;
    }
    if (DH_set0_key(dh, NULL, bn_priv) != 1) {
        goto bail;
    }
#else
    dh_priv = create_dh_pkey(p, g, bn_priv, NULL);
    if (dh_priv == NULL) {
        goto bail;
    }
    dh_pub = create_dh_pkey(p, g, NULL, bn_pub);
    if (dh_pub == NULL) {
        goto bail;
    }
#endif

    /* Allocate output buffer and extract secret onto it */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    rlen = DH_size(dh);
    *shared_secret = malloc(rlen);
    secret_len = DH_compute_key(*shared_secret, bn_pub, dh);
    if (secret_len <= 0) {
        goto bail;
    }

    DH_free(dh);
    BN_clear_free(bn_pub);
#else
    pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, dh_priv, NULL);
    if (pkey_ctx == NULL) {
        goto bail;
    }
    if (EVP_PKEY_derive_init(pkey_ctx) != 1) {
        goto bail;
    }
    if (EVP_PKEY_derive_set_peer(pkey_ctx, dh_pub) != 1) {
        goto bail;
    }
    if (EVP_PKEY_derive(pkey_ctx, NULL, &secret_len) != 1 || secret_len == 0) {
        goto bail;
    }
    *shared_secret = malloc(secret_len);
    if (EVP_PKEY_derive(pkey_ctx, *shared_secret, &secret_len) != 1) {
        goto bail;
    }

    /* Release resources */
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(dh_pub);
    EVP_PKEY_free(dh_priv);
    BN_clear_free(bn_pub);
    BN_clear_free(bn_priv);
    BN_clear_free(g);
    BN_clear_free(p);
#endif

    *shared_secret_len = secret_len;

    return 1;

bail:
    *shared_secret_len = 0;
    if (*shared_secret) {
        free(*shared_secret);
        *shared_secret = NULL;
    }
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (dh) {
        DH_free(dh);
    } else {
        BN_clear_free(bn_priv);
        BN_clear_free(g);
        BN_clear_free(p);
    }
    BN_clear_free(bn_pub);
#else
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(dh_pub);
    EVP_PKEY_free(dh_priv);
    BN_clear_free(bn_pub);
    BN_clear_free(bn_priv);
    BN_clear_free(g);
    BN_clear_free(p);
#endif

    return 0;
}

uint8_t PLATFORM_SHA256(uint8_t num_elem, uint8_t **addr, uint32_t *len, uint8_t *digest)
{
    EVP_MD_CTX   *ctx;
    unsigned int  mac_len;
    uint8_t       res = 1;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return 0;
    }
#else
    EVP_MD_CTX  ctx_aux;
    ctx = &ctx_aux;

    EVP_MD_CTX_init(ctx);
#endif

    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
        res = 0;
    }

    if (1 == res) {
        size_t i;

        for (i = 0; i < num_elem; i++) {
            if (!EVP_DigestUpdate(ctx, addr[i], len[i])) {
                res = 0;
                break;
            }
        }
    }

    if (1 == res) {
        if (!EVP_DigestFinal(ctx, digest, &mac_len)) {
            res = 0;
        }
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_MD_CTX_free(ctx);
#endif

    return res;
}

uint8_t PLATFORM_HMAC_SHA256(uint8_t *key, uint32_t keylen, uint8_t num_elem, uint8_t **addr,
                             uint32_t *len, uint8_t *hmac)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MD_CTX   *ctx;
    EVP_PKEY     *pkey;
    size_t        mdlen = 32;
#else
    HMAC_CTX     *ctx;
    unsigned int  mdlen = 32;
#endif
    size_t        i;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    ctx = EVP_MD_CTX_new();
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
    ctx = HMAC_CTX_new();
#else
    HMAC_CTX  ctx_aux;
    ctx = &ctx_aux;

    HMAC_CTX_init(ctx);
#endif
    if (!ctx) {
        return 0;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, keylen);
    if (pkey == NULL) {
        goto bail;
    }
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        goto bail;
    }

    for (i = 0; i < num_elem; i++) {
        EVP_DigestSignUpdate(ctx, addr[i], len[i]);
    }

    if (EVP_DigestSignFinal(ctx, hmac, &mdlen) != 1) {
        goto bail;
    }
#else
    if (HMAC_Init_ex(ctx, key, keylen, EVP_sha256(), NULL) != 1) {
        goto bail;
    }

    for (i = 0; i < num_elem; i++) {
        HMAC_Update(ctx, addr[i], len[i]);
    }

    if (HMAC_Final(ctx, hmac, &mdlen) != 1) {
        goto bail;
    }
#endif

    /* Release resources */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
    HMAC_CTX_free(ctx);
#else
    HMAC_CTX_cleanup(ctx);
#endif

    return 1;

bail:
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
    HMAC_CTX_free(ctx);
#else
    HMAC_CTX_cleanup(ctx);
#endif

    return 0;
}

uint8_t PLATFORM_AES_ENCRYPT(uint8_t *key, uint8_t *iv, uint8_t *data, uint32_t data_len)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX  _ctx;
#endif
    EVP_CIPHER_CTX *ctx;
    int             clen, len;
    uint8_t         buf[AES_BLOCK_SIZE];

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_init(&_ctx);
    ctx = &_ctx;
#else
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return 0;
    }
#endif
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        return 0;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    clen = data_len;
    if (EVP_EncryptUpdate(ctx, data, &clen, data, data_len) != 1 || clen != (int) data_len) {
        return 0;
    }

    len = sizeof(buf);
    if (EVP_EncryptFinal_ex(ctx, buf, &len) != 1 || len != 0) {
        return 0;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(ctx);
#else
    EVP_CIPHER_CTX_free(ctx);
#endif

    return 1;
}

uint8_t PLATFORM_AES_DECRYPT(uint8_t *key, uint8_t *iv, uint8_t *data, uint32_t data_len)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX _ctx;
#endif
    EVP_CIPHER_CTX *ctx;
    int             plen, len;
    uint8_t         buf[AES_BLOCK_SIZE];

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_init(&_ctx);
    ctx = &_ctx;
#else
    ctx=EVP_CIPHER_CTX_new();
    if (!ctx) {
        return 0;
    }
#endif
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        return 0;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    plen = data_len;
    if (EVP_DecryptUpdate(ctx, data, &plen, data, data_len) != 1 || plen != (int) data_len) {
        return 0;
    }

    len = sizeof(buf);
    if (EVP_DecryptFinal_ex(ctx, buf, &len) != 1 || len != 0) {
        return 0;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(ctx);
#else
    EVP_CIPHER_CTX_free(ctx);
#endif

    return 1;
}
