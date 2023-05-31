/******************************************************************************
 * ifm_nettle-gcm.c: gcm
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * li_zengyi <zengyi@isrc.iscas.ac.cn>
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
#include "nettle/gcm.h"
#include "gcm_meta.h"

// gcm
void ifm_gcm_set_key(struct ifm_gcm_key *key, const void *cipher, ifm_cipher_func *f)
{
    gcm_set_key((struct gcm_key*)key, cipher, (nettle_cipher_func *)f);
}

void ifm_gcm_set_iv(struct ifm_gcm_ctx *ctx, const struct ifm_gcm_key *key, size_t length, const uint8_t *iv)
{
    gcm_set_iv((struct gcm_ctx *)ctx, (struct gcm_key *)key, length, iv);
}

void ifm_gcm_update(struct ifm_gcm_ctx *ctx, const struct ifm_gcm_key *key, size_t length, const uint8_t *data)
{
    gcm_update((struct gcm_ctx *)ctx, (struct gcm_key *)key, length, data);
}

void ifm_gcm_encrypt(struct ifm_gcm_ctx *ctx, const struct ifm_gcm_key *key, const void *cipher, ifm_cipher_func *f,
    size_t length, uint8_t *dst, const uint8_t *src)
{
    gcm_encrypt((struct gcm_ctx *)ctx, (struct gcm_key *)key, cipher, (nettle_cipher_func *)f, length, dst, src);
}

void ifm_gcm_decrypt(struct ifm_gcm_ctx *ctx, const struct ifm_gcm_key *key, const void *cipher, ifm_cipher_func *f,
    size_t length, uint8_t *dst, const uint8_t *src)
{
    gcm_decrypt((struct gcm_ctx *)ctx, (struct gcm_key *)key, cipher, (nettle_cipher_func *)f, length, dst, src);
}

void ifm_gcm_digest(struct ifm_gcm_ctx *ctx, const struct ifm_gcm_key *key, const void *cipher, ifm_cipher_func *f,
    size_t length, uint8_t *digest)
{
    gcm_digest((struct gcm_ctx *)ctx, (struct gcm_key *)key, cipher, (nettle_cipher_func *)f, length, digest);
}

// gcm_aes128
void ifm_gcm_aes128_set_key(struct ifm_gcm_aes128_ctx *ctx, const uint8_t *key)
{
    gcm_aes128_set_key((struct gcm_aes128_ctx *)ctx, key);
}

void ifm_gcm_aes128_update(struct ifm_gcm_aes128_ctx *ctx, size_t length, const uint8_t *data)
{
    gcm_aes128_update((struct gcm_aes128_ctx *)ctx, length, data);
}

void ifm_gcm_aes128_set_iv(struct ifm_gcm_aes128_ctx *ctx, size_t length, const uint8_t *iv)
{
    gcm_aes128_set_iv((struct gcm_aes128_ctx *)ctx, length, iv);
}

void ifm_gcm_aes128_encrypt(struct ifm_gcm_aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
    gcm_aes128_encrypt((struct gcm_aes128_ctx *)ctx, length, dst, src);
}

void ifm_gcm_aes128_decrypt(struct ifm_gcm_aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
    gcm_aes128_decrypt((struct gcm_aes128_ctx *)ctx, length, dst, src);
}

void ifm_gcm_aes128_digest(struct ifm_gcm_aes128_ctx *ctx, size_t length, uint8_t *digest)
{
    gcm_aes128_digest((struct gcm_aes128_ctx *)ctx, length, digest);
}

// gcm_aes192
void ifm_gcm_aes192_set_key(struct ifm_gcm_aes192_ctx *ctx, const uint8_t *key)
{
    gcm_aes192_set_key((struct gcm_aes192_ctx *)ctx, key);
}

void ifm_gcm_aes192_update(struct ifm_gcm_aes192_ctx *ctx, size_t length, const uint8_t *data)
{
    gcm_aes192_update((struct gcm_aes192_ctx *)ctx, length, data);
}

void ifm_gcm_aes192_set_iv(struct ifm_gcm_aes192_ctx *ctx, size_t length, const uint8_t *iv)
{
    gcm_aes192_set_iv((struct gcm_aes192_ctx *)ctx, length, iv);
}

void ifm_gcm_aes192_encrypt(struct ifm_gcm_aes192_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
    gcm_aes192_encrypt((struct gcm_aes192_ctx *)ctx, length, dst, src);
}

void ifm_gcm_aes192_decrypt(struct ifm_gcm_aes192_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
    gcm_aes192_decrypt((struct gcm_aes192_ctx *)ctx, length, dst, src);
}

void ifm_gcm_aes192_digest(struct ifm_gcm_aes192_ctx *ctx, size_t length, uint8_t *digest)
{
    gcm_aes192_digest((struct gcm_aes192_ctx *)ctx, length, digest);
}

// gcm_aes256
void ifm_gcm_aes256_set_key(struct ifm_gcm_aes256_ctx *ctx, const uint8_t *key)
{
    gcm_aes256_set_key((struct gcm_aes256_ctx *)ctx, key);
}

void ifm_gcm_aes256_update(struct ifm_gcm_aes256_ctx *ctx, size_t length, const uint8_t *data)
{
    gcm_aes256_update((struct gcm_aes256_ctx *)ctx, length, data);
}

void ifm_gcm_aes256_set_iv(struct ifm_gcm_aes256_ctx *ctx, size_t length, const uint8_t *iv)
{
    gcm_aes256_set_iv((struct gcm_aes256_ctx *)ctx, length, iv);
}

void ifm_gcm_aes256_encrypt(struct ifm_gcm_aes256_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
    gcm_aes256_encrypt((struct gcm_aes256_ctx *)ctx, length, dst, src);
}

void ifm_gcm_aes256_decrypt(struct ifm_gcm_aes256_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
    gcm_aes256_decrypt((struct gcm_aes256_ctx *)ctx, length, dst, src);
}

void ifm_gcm_aes256_digest(struct ifm_gcm_aes256_ctx *ctx, size_t length, uint8_t *digest)
{
    gcm_aes256_digest((struct gcm_aes256_ctx *)ctx, length, digest);
}
