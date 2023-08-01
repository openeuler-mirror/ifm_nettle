/******************************************************************************
 * bench_gcm_meta.h: gcm_meta for bench
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * li_zengyi <lizengyi@isrc.iscas.ac.cn>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 ********************************************************************************/
#ifndef IFM_NETTLE_BENCH_GCM_META_INCLUDED
#define IFM_NETTLE_BENCH_GCM_META_INCLUDED
#include "gcm_meta.h"
#include "gcm.h"
#include "nettle/nettle-meta.h"

static nettle_set_key_func gcm_aes128_set_nonce_wrapper;
static void gcm_aes128_set_nonce_wrapper(void *ctx, const uint8_t *nonce)
{
    gcm_aes128_set_iv ((struct ifm_gcm_aes128_ctx *)ctx, GCM_IV_SIZE, nonce);
}

static nettle_set_key_func gcm_aes192_set_nonce_wrapper;
static void gcm_aes192_set_nonce_wrapper(void *ctx, const uint8_t *nonce)
{
    gcm_aes192_set_iv ((struct ifm_gcm_aes192_ctx *)ctx, GCM_IV_SIZE, nonce);
}

static nettle_set_key_func gcm_aes256_set_nonce_wrapper;
static void gcm_aes256_set_nonce_wrapper(void *ctx, const uint8_t *nonce)
{
    gcm_aes256_set_iv ((struct ifm_gcm_aes256_ctx *)ctx, GCM_IV_SIZE, nonce);
}

const struct nettle_aead nettle_ifm_gcm_aes128 = {
    "ifm_gcm_aes128", sizeof(struct ifm_gcm_aes128_ctx),
    GCM_BLOCK_SIZE, GCM_AES128_KEY_SIZE,
    GCM_IV_SIZE, GCM_DIGEST_SIZE,
    (nettle_set_key_func *) gcm_aes128_set_key,
    (nettle_set_key_func *) gcm_aes128_set_key,
    gcm_aes128_set_nonce_wrapper,
    (nettle_hash_update_func *) gcm_aes128_update,
    (nettle_crypt_func *) gcm_aes128_encrypt,
    (nettle_crypt_func *) gcm_aes128_decrypt,
    (nettle_hash_digest_func *) gcm_aes128_digest,
};

const struct nettle_aead nettle_ifm_gcm_aes192 = {
    "ifm_gcm_aes192", sizeof(struct ifm_gcm_aes192_ctx),
    GCM_BLOCK_SIZE, GCM_AES192_KEY_SIZE,
    GCM_IV_SIZE, GCM_DIGEST_SIZE,
    (nettle_set_key_func *) gcm_aes192_set_key,
    (nettle_set_key_func *) gcm_aes192_set_key,
    gcm_aes192_set_nonce_wrapper,
    (nettle_hash_update_func *) gcm_aes192_update,
    (nettle_crypt_func *) gcm_aes192_encrypt,
    (nettle_crypt_func *) gcm_aes192_decrypt,
    (nettle_hash_digest_func *) gcm_aes192_digest,
};

const struct nettle_aead nettle_ifm_gcm_aes256 = {
    "ifm_gcm_aes256", sizeof(struct ifm_gcm_aes256_ctx),
    GCM_BLOCK_SIZE, GCM_AES256_KEY_SIZE,
    GCM_IV_SIZE, GCM_DIGEST_SIZE,
    (nettle_set_key_func *) gcm_aes256_set_key,
    (nettle_set_key_func *) gcm_aes256_set_key,
    gcm_aes256_set_nonce_wrapper,
    (nettle_hash_update_func *) gcm_aes256_update,
    (nettle_crypt_func *) gcm_aes256_encrypt,
    (nettle_crypt_func *) gcm_aes256_decrypt,
    (nettle_hash_digest_func *) gcm_aes256_digest,
};
#endif