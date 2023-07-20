/******************************************************************************
 * ifm_nettle-hmac.c: add hmac support for ifm_nettle
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
#include <string.h>
#include <nettle/hmac.h>

#include "hmac_meta.h"

void ifm_hmac_set_key(void *outer, void *inner, void *state,
                      const struct nettle_hash *hash,
                      size_t length, const uint8_t *key)
{
    hmac_set_key(outer, inner, state, hash, length, key);
}

/* This function is not strictly needed, it's s just the same as the
 * hash update function. */
void ifm_hmac_update(void *state,
                     const struct nettle_hash *hash,
                     size_t length, const uint8_t *data)
{
    hmac_update(state, hash, length, data);
}

void ifm_hmac_digest(const void *outer, const void *inner, void *state,
                     const struct nettle_hash *hash,
                     size_t length, uint8_t *digest)
{
    hmac_digest(outer, inner, state, hash, length, digest);
}

/* HMAC using specific hash functions */

/* hmac-md5 */
void ifm_hmac_md5_set_key(struct ifm_hmac_md5_ctx *ctx,
                          size_t key_length, const uint8_t *key)
{
    hmac_md5_set_key((struct hmac_md5_ctx *)ctx, key_length, key);
}

void ifm_hmac_md5_update(struct ifm_hmac_md5_ctx *ctx,
                         size_t length, const uint8_t *data)
{
    hmac_md5_update((struct hmac_md5_ctx *)ctx, length, data);
}

void ifm_hmac_md5_digest(struct ifm_hmac_md5_ctx *ctx,
                         size_t length, uint8_t *digest)
{
    hmac_md5_digest((struct hmac_md5_ctx *)ctx, length, digest);
}

/* hmac-ripemd160 */
void ifm_hmac_ripemd160_set_key(struct ifm_hmac_ripemd160_ctx *ctx,
                                size_t key_length, const uint8_t *key)
{
    hmac_ripemd160_set_key((struct hmac_ripemd160_ctx *)ctx, key_length, key);
}

void ifm_hmac_ripemd160_update(struct ifm_hmac_ripemd160_ctx *ctx,
                               size_t length, const uint8_t *data)
{
    hmac_ripemd160_update((struct hmac_ripemd160_ctx *)ctx, length, data);
}

void ifm_hmac_ripemd160_digest(struct ifm_hmac_ripemd160_ctx *ctx,
                               size_t length, uint8_t *digest)
{
    hmac_ripemd160_digest((struct hmac_ripemd160_ctx *)ctx, length, digest);
}

/* hmac-sha1 */
void ifm_hmac_sha1_set_key(struct ifm_hmac_sha1_ctx *ctx,
                           size_t key_length, const uint8_t *key)
{
    hmac_sha1_set_key((struct hmac_sha1_ctx *)ctx, key_length, key);
}

void ifm_hmac_sha1_update(struct ifm_hmac_sha1_ctx *ctx,
                          size_t length, const uint8_t *data)
{
    hmac_sha1_update((struct hmac_sha1_ctx *)ctx, length, data);
}

void ifm_hmac_sha1_digest(struct ifm_hmac_sha1_ctx *ctx,
                          size_t length, uint8_t *digest)
{
    hmac_sha1_digest((struct hmac_sha1_ctx *)ctx, length, digest);
}

/* hmac-sha256 */
void ifm_hmac_sha256_set_key(struct ifm_hmac_sha256_ctx *ctx,
                             size_t key_length, const uint8_t *key)
{
    hmac_sha256_set_key((struct hmac_sha256_ctx *)ctx, key_length, key);
}

void ifm_hmac_sha256_update(struct ifm_hmac_sha256_ctx *ctx,
                            size_t length, const uint8_t *data)
{
    hmac_sha256_update((struct hmac_sha256_ctx *)ctx, length, data);
}

void ifm_hmac_sha256_digest(struct ifm_hmac_sha256_ctx *ctx,
                            size_t length, uint8_t *digest)
{
    hmac_sha256_digest((struct hmac_sha256_ctx *)ctx, length, digest);
}

/* hmac-sha224 */
void ifm_hmac_sha224_set_key(struct ifm_hmac_sha224_ctx *ctx,
                             size_t key_length, const uint8_t *key)
{
    hmac_sha224_set_key((struct hmac_sha224_ctx *)ctx, key_length, key);
}

void ifm_hmac_sha224_digest(struct ifm_hmac_sha224_ctx *ctx,
                            size_t length, uint8_t *digest)
{
    hmac_sha224_digest((struct hmac_sha224_ctx *)ctx, length, digest);
}

/* hmac-sha512 */
void ifm_hmac_sha512_set_key(struct ifm_hmac_sha512_ctx *ctx,
                             size_t key_length, const uint8_t *key)
{
    hmac_sha512_set_key((struct hmac_sha512_ctx *)ctx, key_length, key);
}

void ifm_hmac_sha512_update(struct ifm_hmac_sha512_ctx *ctx,
                            size_t length, const uint8_t *data)
{
    hmac_sha512_update((struct hmac_sha512_ctx *)ctx, length, data);
}

void ifm_hmac_sha512_digest(struct ifm_hmac_sha512_ctx *ctx,
                            size_t length, uint8_t *digest)
{
    hmac_sha512_digest((struct hmac_sha512_ctx *)ctx, length, digest);
}

/* hmac-sha384 */
void ifm_hmac_sha384_set_key(struct ifm_hmac_sha512_ctx *ctx,
                             size_t key_length, const uint8_t *key)
{
    hmac_sha384_set_key((struct hmac_sha512_ctx *)ctx, key_length, key);
}

void ifm_hmac_sha384_digest(struct ifm_hmac_sha512_ctx *ctx,
                            size_t length, uint8_t *digest)
{
    hmac_sha384_digest((struct hmac_sha512_ctx *)ctx, length, digest);
}

/* hmac-gosthash94 */
void ifm_hmac_gosthash94_set_key(struct ifm_hmac_gosthash94_ctx *ctx,
                                 size_t key_length, const uint8_t *key)
{
    hmac_gosthash94_set_key((struct hmac_gosthash94_ctx *)ctx, key_length, key);
}

void ifm_hmac_gosthash94_update(struct ifm_hmac_gosthash94_ctx *ctx,
                                size_t length, const uint8_t *data)
{
    hmac_gosthash94_update((struct hmac_gosthash94_ctx *)ctx, length, data);
}

void ifm_hmac_gosthash94_digest(struct ifm_hmac_gosthash94_ctx *ctx,
                                size_t length, uint8_t *digest)
{
    hmac_gosthash94_digest((struct hmac_gosthash94_ctx *)ctx, length, digest);
}

void ifm_hmac_gosthash94cp_set_key(struct ifm_hmac_gosthash94cp_ctx *ctx,
                                   size_t key_length, const uint8_t *key)
{
    hmac_gosthash94cp_set_key((struct hmac_gosthash94cp_ctx *)ctx, key_length, key);
}

void ifm_hmac_gosthash94cp_update(struct ifm_hmac_gosthash94cp_ctx *ctx,
                                  size_t length, const uint8_t *data)
{
    hmac_gosthash94cp_update((struct hmac_gosthash94cp_ctx *)ctx, length, data);
}

void ifm_hmac_gosthash94cp_digest(struct ifm_hmac_gosthash94cp_ctx *ctx,
                                  size_t length, uint8_t *digest)
{
    hmac_gosthash94cp_digest((struct hmac_gosthash94cp_ctx *)ctx, length, digest);
}

/* hmac-streebog */
void ifm_hmac_streebog512_set_key(struct ifm_hmac_streebog512_ctx *ctx,
                                  size_t key_length, const uint8_t *key)
{
    hmac_streebog512_set_key((struct hmac_streebog512_ctx *)ctx, key_length, key);
}

void ifm_hmac_streebog512_update(struct ifm_hmac_streebog512_ctx *ctx,
                                 size_t length, const uint8_t *data)
{
    hmac_streebog512_update((struct hmac_streebog512_ctx *)ctx, length, data);
}

void ifm_hmac_streebog512_digest(struct ifm_hmac_streebog512_ctx *ctx,
                                 size_t length, uint8_t *digest)
{
    hmac_streebog512_digest((struct hmac_streebog512_ctx *)ctx, length, digest);
}

void ifm_hmac_streebog256_set_key(struct ifm_hmac_streebog256_ctx *ctx,
                                  size_t key_length, const uint8_t *key)
{
    hmac_streebog256_set_key((struct hmac_streebog256_ctx *)ctx, key_length, key);
}

void ifm_hmac_streebog256_digest(struct ifm_hmac_streebog256_ctx *ctx,
                                 size_t length, uint8_t *digest)
{
    hmac_streebog256_digest((struct hmac_streebog256_ctx *)ctx, length, digest);
}

/* hmac-sm3 */
void ifm_hmac_sm3_set_key(struct ifm_hmac_sm3_ctx *ctx,
                          size_t key_length, const uint8_t *key)
{
    hmac_sm3_set_key((struct hmac_sm3_ctx *)ctx, key_length, key);
}

void ifm_hmac_sm3_update(struct ifm_hmac_sm3_ctx *ctx,
                         size_t length, const uint8_t *data)
{
    hmac_sm3_update((struct hmac_sm3_ctx *)ctx, length, data);
}

void ifm_hmac_sm3_digest(struct ifm_hmac_sm3_ctx *ctx,
                         size_t length, uint8_t *digest)
{
    hmac_sm3_digest((struct hmac_sm3_ctx *)ctx, length, digest);
}

