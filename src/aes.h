/******************************************************************************
 * aes.h: uadk aes
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * Shankang Ke <shankang@isrc.iscas.ac.cn>
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

#ifndef IFM_NETTLE_AES_H_INCLUDED
#define IFM_NETTLE_AES_H_INCLUDED

#include <stdbool.h>
#include "aes_meta.h"
#ifdef __aarch64__
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_bmm.h"
#include "uadk/v1/wd_cipher.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define aes_set_encrypt_key ifm_aes_set_encrypt_key
#define aes_set_decrypt_key ifm_aes_set_decrypt_key
#define aes_invert_key ifm_aes_invert_key
#define aes_encrypt ifm_aes_encrypt
#define aes_decrypt ifm_aes_decrypt
#define aes128_set_encrypt_key ifm_aes128_set_encrypt_key
#define aes192_set_encrypt_key ifm_aes192_set_encrypt_key
#define aes256_set_encrypt_key ifm_aes256_set_encrypt_key
#define aes128_encrypt ifm_aes128_encrypt
#define aes192_encrypt ifm_aes192_encrypt
#define aes256_encrypt ifm_aes256_encrypt
#define aes128_set_decrypt_key ifm_aes128_set_decrypt_key
#define aes192_set_decrypt_key ifm_aes192_set_decrypt_key
#define aes256_set_decrypt_key ifm_aes256_set_decrypt_key
#define aes128_decrypt ifm_aes128_decrypt
#define aes192_decrypt ifm_aes192_decrypt
#define aes256_decrypt ifm_aes256_decrypt
#define aes128_invert_key ifm_aes128_invert_key
#define aes192_invert_key ifm_aes192_invert_key
#define aes256_invert_key ifm_aes256_invert_key

void ifm_aes128_set_encrypt_key(struct ifm_aes128_ctx *ctx, const uint8_t *key);
void ifm_aes192_set_encrypt_key(struct ifm_aes192_ctx *ctx, const uint8_t *key);
void ifm_aes256_set_encrypt_key(struct ifm_aes256_ctx *ctx, const uint8_t *key);

void ifm_aes128_encrypt(const struct ifm_aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void ifm_aes192_encrypt(const struct ifm_aes192_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void ifm_aes256_encrypt(const struct ifm_aes256_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);

void ifm_aes128_set_decrypt_key(struct ifm_aes128_ctx *ctx, const uint8_t *key);
void ifm_aes192_set_decrypt_key(struct ifm_aes192_ctx *ctx, const uint8_t *key);
void ifm_aes256_set_decrypt_key(struct ifm_aes256_ctx *ctx, const uint8_t *key);

void ifm_aes128_decrypt(const struct ifm_aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void ifm_aes192_decrypt(const struct ifm_aes192_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void ifm_aes256_decrypt(const struct ifm_aes256_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);

void ifm_aes128_invert_key(struct ifm_aes128_ctx *dst, const struct ifm_aes128_ctx *src);
void ifm_aes192_invert_key(struct ifm_aes192_ctx *dst, const struct ifm_aes192_ctx *src);
void ifm_aes256_invert_key(struct ifm_aes256_ctx *dst, const struct ifm_aes256_ctx *src);

/* The older nettle-2.7 AES interface is deprecated, please migrate to
   the newer interface where each algorithm has a fixed key size. */

/* Variable key size between 128 and 256 bits. But the only valid
 * values are 16 (128 bits), 24 (192 bits) and 32 (256 bits). */
#define AES_MIN_KEY_SIZE AES128_KEY_SIZE
#define AES_MAX_KEY_SIZE AES256_KEY_SIZE

#define AES_KEY_SIZE 32

void ifm_aes_set_encrypt_key(struct ifm_aes_ctx *ctx, size_t length, const uint8_t *key) _NETTLE_ATTRIBUTE_DEPRECATED;

void ifm_aes_set_decrypt_key(struct ifm_aes_ctx *ctx, size_t length, const uint8_t *key) _NETTLE_ATTRIBUTE_DEPRECATED;

void ifm_aes_invert_key(struct ifm_aes_ctx *dst, const struct ifm_aes_ctx *src) _NETTLE_ATTRIBUTE_DEPRECATED;

void ifm_aes_encrypt(const struct ifm_aes_ctx *ctx, size_t length, uint8_t *dst,
                     const uint8_t *src) _NETTLE_ATTRIBUTE_DEPRECATED;
void ifm_aes_decrypt(const struct ifm_aes_ctx *ctx, size_t length, uint8_t *dst,
                     const uint8_t *src) _NETTLE_ATTRIBUTE_DEPRECATED;

#ifdef __cplusplus
}
#endif

#endif /* IFM_NETTLE_AES_H_INCLUDED */