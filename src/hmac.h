/******************************************************************************
 * ifm_nettle-hmac.h: header for hmac
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * jiaji2023 <jiaji@isrc.iscas.ac.cn>
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
#ifndef IFM_NETTLE_HMAC_H
#define IFM_NETTLE_HMAC_H

#include <stddef.h>
#include <stdint.h>
#include <nettle/nettle-types.h>
#include <nettle/bignum.h>
#include <gmp.h>

#include "hmac_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Namespace mangling */
#define hmac_set_key ifm_hmac_set_key
#define hmac_update ifm_hmac_update
#define hmac_digest ifm_hmac_digest
#define hmac_md5_set_key ifm_hmac_md5_set_key
#define hmac_md5_update ifm_hmac_md5_update
#define hmac_md5_digest ifm_hmac_md5_digest
#define hmac_ripemd160_set_key ifm_hmac_ripemd160_set_key
#define hmac_ripemd160_update ifm_hmac_ripemd160_update
#define hmac_ripemd160_digest ifm_hmac_ripemd160_digest
#define hmac_sha1_set_key ifm_hmac_sha1_set_key
#define hmac_sha1_update ifm_hmac_sha1_update
#define hmac_sha1_digest ifm_hmac_sha1_digest
#define hmac_sha224_set_key ifm_hmac_sha224_set_key
#define hmac_sha224_update  ifm_hmac_sha256_update
#define hmac_sha224_digest ifm_hmac_sha224_digest
#define hmac_sha256_set_key ifm_hmac_sha256_set_key
#define hmac_sha256_update ifm_hmac_sha256_update
#define hmac_sha256_digest ifm_hmac_sha256_digest
#define hmac_sha384_set_key ifm_hmac_sha384_set_key
#define hmac_sha384_update  ifm_hmac_sha512_update
#define hmac_sha384_digest ifm_hmac_sha384_digest
#define hmac_sha512_set_key ifm_hmac_sha512_set_key
#define hmac_sha512_update ifm_hmac_sha512_update
#define hmac_sha512_digest ifm_hmac_sha512_digest
#define hmac_gosthash94_set_key ifm_hmac_gosthash94_set_key
#define hmac_gosthash94_update ifm_hmac_gosthash94_update
#define hmac_gosthash94_digest ifm_hmac_gosthash94_digest
#define hmac_gosthash94cp_set_key ifm_hmac_gosthash94cp_set_key
#define hmac_gosthash94cp_update ifm_hmac_gosthash94cp_update
#define hmac_gosthash94cp_digest ifm_hmac_gosthash94cp_digest
#define hmac_streebog256_set_key ifm_hmac_streebog256_set_key
#define hmac_streebog256_update ifm_hmac_streebog512_update
#define hmac_streebog256_digest ifm_hmac_streebog256_digest
#define hmac_streebog512_set_key ifm_hmac_streebog512_set_key
#define hmac_streebog512_update ifm_hmac_streebog512_update
#define hmac_streebog512_digest ifm_hmac_streebog512_digest
#define hmac_sm3_set_key ifm_hmac_sm3_set_key
#define hmac_sm3_update ifm_hmac_sm3_update
#define hmac_sm3_digest ifm_hmac_sm3_digest

void ifm_hmac_set_key(void *outer, void *inner, void *state,
                      const struct nettle_hash *hash,
                      size_t length, const uint8_t *key);

/* This function is not strictly needed, it's s just the same as the
 * hash update function. */
void ifm_hmac_update(void *state,
                     const struct nettle_hash *hash,
                     size_t length, const uint8_t *data);

void ifm_hmac_digest(const void *outer, const void *inner, void *state,
                     const struct nettle_hash *hash,
                     size_t length, uint8_t *digest);

#define HMAC_SET_KEY(ctx, hash, length, key) \
    ifm_hmac_set_key(&(ctx)->outer, &(ctx)->inner, &(ctx)->state, (hash), (length), (key))

#define HMAC_DIGEST(ctx, hash, length, digest) \
    ifm_hmac_digest(&(ctx)->outer, &(ctx)->inner, &(ctx)->state, (hash), (length), (digest))

/* HMAC using specific hash functions */

/* hmac-md5 */
void ifm_hmac_md5_set_key(struct ifm_hmac_md5_ctx *ctx,
                          size_t key_length, const uint8_t *key);

void ifm_hmac_md5_update(struct ifm_hmac_md5_ctx *ctx,
                         size_t length, const uint8_t *data);

void ifm_hmac_md5_digest(struct ifm_hmac_md5_ctx *ctx,
                         size_t length, uint8_t *digest);


/* hmac-ripemd160 */
void ifm_hmac_ripemd160_set_key(struct ifm_hmac_ripemd160_ctx *ctx,
                                size_t key_length, const uint8_t *key);

void ifm_hmac_ripemd160_update(struct ifm_hmac_ripemd160_ctx *ctx,
                               size_t length, const uint8_t *data);

void ifm_hmac_ripemd160_digest(struct ifm_hmac_ripemd160_ctx *ctx,
                               size_t length, uint8_t *digest);


/* hmac-sha1 */
void ifm_hmac_sha1_set_key(struct ifm_hmac_sha1_ctx *ctx,
                           size_t key_length, const uint8_t *key);

void ifm_hmac_sha1_update(struct ifm_hmac_sha1_ctx *ctx,
                          size_t length, const uint8_t *data);

void ifm_hmac_sha1_digest(struct ifm_hmac_sha1_ctx *ctx,
                          size_t length, uint8_t *digest);

/* hmac-sha256 */
void ifm_hmac_sha256_set_key(struct ifm_hmac_sha256_ctx *ctx,
                             size_t key_length, const uint8_t *key);

void ifm_hmac_sha256_update(struct ifm_hmac_sha256_ctx *ctx,
                            size_t length, const uint8_t *data);

void ifm_hmac_sha256_digest(struct ifm_hmac_sha256_ctx *ctx,
                            size_t length, uint8_t *digest);

/* hmac-sha224 */
void ifm_hmac_sha224_set_key(struct ifm_hmac_sha224_ctx *ctx,
                             size_t key_length, const uint8_t *key);

void ifm_hmac_sha224_digest(struct ifm_hmac_sha224_ctx *ctx,
                            size_t length, uint8_t *digest);

/* hmac-sha512 */
void ifm_hmac_sha512_set_key(struct ifm_hmac_sha512_ctx *ctx,
                             size_t key_length, const uint8_t *key);

void ifm_hmac_sha512_update(struct ifm_hmac_sha512_ctx *ctx,
                            size_t length, const uint8_t *data);

void ifm_hmac_sha512_digest(struct ifm_hmac_sha512_ctx *ctx,
                            size_t length, uint8_t *digest);

/* hmac-sha384 */
void ifm_hmac_sha384_set_key(struct ifm_hmac_sha512_ctx *ctx,
                             size_t key_length, const uint8_t *key);

void ifm_hmac_sha384_digest(struct ifm_hmac_sha512_ctx *ctx,
                            size_t length, uint8_t *digest);

/* hmac-gosthash94 */
void ifm_hmac_gosthash94_set_key(struct ifm_hmac_gosthash94_ctx *ctx,
                                 size_t key_length, const uint8_t *key);

void ifm_hmac_gosthash94_update(struct ifm_hmac_gosthash94_ctx *ctx,
                                size_t length, const uint8_t *data);

void ifm_hmac_gosthash94_digest(struct ifm_hmac_gosthash94_ctx *ctx,
                                size_t length, uint8_t *digest);

void ifm_hmac_gosthash94cp_set_key(struct ifm_hmac_gosthash94cp_ctx *ctx,
                                   size_t key_length, const uint8_t *key);

void ifm_hmac_gosthash94cp_update(struct ifm_hmac_gosthash94cp_ctx *ctx,
                                  size_t length, const uint8_t *data);

void ifm_hmac_gosthash94cp_digest(struct ifm_hmac_gosthash94cp_ctx *ctx,
                                  size_t length, uint8_t *digest);

/* hmac-streebog */
void ifm_hmac_streebog512_set_key(struct ifm_hmac_streebog512_ctx *ctx,
                                  size_t key_length, const uint8_t *key);

void ifm_hmac_streebog512_update(struct ifm_hmac_streebog512_ctx *ctx,
                                 size_t length, const uint8_t *data);

void ifm_hmac_streebog512_digest(struct ifm_hmac_streebog512_ctx *ctx,
                                 size_t length, uint8_t *digest);

void ifm_hmac_streebog256_set_key(struct ifm_hmac_streebog256_ctx *ctx,
                                  size_t key_length, const uint8_t *key);

void ifm_hmac_streebog256_digest(struct ifm_hmac_streebog256_ctx *ctx,
                                 size_t length, uint8_t *digest);

/* hmac-sm3 */
void ifm_hmac_sm3_set_key(struct ifm_hmac_sm3_ctx *ctx,
                          size_t key_length, const uint8_t *key);

void ifm_hmac_sm3_update(struct ifm_hmac_sm3_ctx *ctx,
                         size_t length, const uint8_t *data);

void ifm_hmac_sm3_digest(struct ifm_hmac_sm3_ctx *ctx,
                         size_t length, uint8_t *digest);

#ifdef __cplusplus
}
#endif

#endif // IFM_NETTLE_HMAC_H
