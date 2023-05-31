/******************************************************************************
 * ifm_nettle-gcm.h: gcm
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
#ifndef IFM_NETTLE_GCM_H_INCLUDED
#define IFM_NETTLE_GCM_H_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include "gcm_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

#define gcm_set_key ifm_gcm_set_key
#define gcm_set_iv ifm_gcm_set_iv
#define gcm_update ifm_gcm_update
#define gcm_encrypt ifm_gcm_encrypt
#define gcm_decrypt ifm_gcm_decrypt
#define gcm_digest ifm_gcm_digest

#define gcm_aes128_set_key ifm_gcm_aes128_set_key
#define gcm_aes128_set_iv ifm_gcm_aes128_set_iv
#define gcm_aes128_update ifm_gcm_aes128_update
#define gcm_aes128_encrypt ifm_gcm_aes128_encrypt
#define gcm_aes128_decrypt ifm_gcm_aes128_decrypt
#define gcm_aes128_digest ifm_gcm_aes128_digest

#define gcm_aes192_set_key ifm_gcm_aes192_set_key
#define gcm_aes192_set_iv ifm_gcm_aes192_set_iv
#define gcm_aes192_update ifm_gcm_aes192_update
#define gcm_aes192_encrypt ifm_gcm_aes192_encrypt
#define gcm_aes192_decrypt ifm_gcm_aes192_decrypt
#define gcm_aes192_digest ifm_gcm_aes192_digest

#define gcm_aes256_set_key ifm_gcm_aes256_set_key
#define gcm_aes256_set_iv ifm_gcm_aes256_set_iv
#define gcm_aes256_update ifm_gcm_aes256_update
#define gcm_aes256_encrypt ifm_gcm_aes256_encrypt
#define gcm_aes256_decrypt ifm_gcm_aes256_decrypt
#define gcm_aes256_digest ifm_gcm_aes256_digest

void ifm_gcm_set_key(struct ifm_gcm_key *key, const void *cipher, ifm_cipher_func *f);
void ifm_gcm_set_iv(struct ifm_gcm_ctx *ctx, const struct ifm_gcm_key *key, size_t length, const uint8_t *iv);
void ifm_gcm_update(struct ifm_gcm_ctx *ctx, const struct ifm_gcm_key *key, size_t length, const uint8_t *data);
void ifm_gcm_encrypt(struct ifm_gcm_ctx *ctx, const struct ifm_gcm_key *key, const void *cipher, ifm_cipher_func *f,
    size_t length, uint8_t *dst, const uint8_t *src);
void ifm_gcm_decrypt(struct ifm_gcm_ctx *ctx, const struct ifm_gcm_key *key, const void *cipher, ifm_cipher_func *f,
    size_t length, uint8_t *dst, const uint8_t *src);
void ifm_gcm_digest(struct ifm_gcm_ctx *ctx, const struct ifm_gcm_key *key, const void *cipher, ifm_cipher_func *f,
    size_t length, uint8_t *digest);

void ifm_gcm_aes128_set_key(struct ifm_gcm_aes128_ctx *ctx, const uint8_t *key);
void ifm_gcm_aes128_update(struct ifm_gcm_aes128_ctx *ctx, size_t length, const uint8_t *data);
void ifm_gcm_aes128_set_iv(struct ifm_gcm_aes128_ctx *ctx, size_t length, const uint8_t *iv);
void ifm_gcm_aes128_encrypt(struct ifm_gcm_aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void ifm_gcm_aes128_decrypt(struct ifm_gcm_aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void ifm_gcm_aes128_digest(struct ifm_gcm_aes128_ctx *ctx, size_t length, uint8_t *digest);

void ifm_gcm_aes192_set_key(struct ifm_gcm_aes192_ctx *ctx, const uint8_t *key);
void ifm_gcm_aes192_update(struct ifm_gcm_aes192_ctx *ctx, size_t length, const uint8_t *data);
void ifm_gcm_aes192_set_iv(struct ifm_gcm_aes192_ctx *ctx, size_t length, const uint8_t *iv);
void ifm_gcm_aes192_encrypt(struct ifm_gcm_aes192_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void ifm_gcm_aes192_decrypt(struct ifm_gcm_aes192_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void ifm_gcm_aes192_digest(struct ifm_gcm_aes192_ctx *ctx, size_t length, uint8_t *digest);

void ifm_gcm_aes256_set_key(struct ifm_gcm_aes256_ctx *ctx, const uint8_t *key);
void ifm_gcm_aes256_update(struct ifm_gcm_aes256_ctx *ctx, size_t length, const uint8_t *data);
void ifm_gcm_aes256_set_iv(struct ifm_gcm_aes256_ctx *ctx, size_t length, const uint8_t *iv);
void ifm_gcm_aes256_encrypt(struct ifm_gcm_aes256_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void ifm_gcm_aes256_decrypt(struct ifm_gcm_aes256_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void ifm_gcm_aes256_digest(struct ifm_gcm_aes256_ctx *ctx, size_t length, uint8_t *digest);

#ifdef __cplusplus
}
#endif

#endif /* IFM_NETTLE_GCM_H_INCLUDED */
