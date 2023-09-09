/******************************************************************************
 * This file is an internal include file for nettle
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

#ifndef IFM_NETTLE_AES_COMMON_H_IN_INCLUDED
#define IFM_NETTLE_AES_COMMON_H_IN_INCLUDED

#ifdef __aarch64__
#include "uadk_meta.h"
#include "aes_meta.h"

// 如下公共函数在aes.c中实现
int uadk_aes_init(struct uadk_cipher_st *uadk_ctx);
int alloc_uadk(struct uadk_cipher_st *uadk_ctx, bool force, enum wcrypto_cipher_mode mode);
void free_cipher_uadk(struct uadk_cipher_st *uadk_ctx);
void uadk_aes_do_cipher(struct uadk_cipher_st *uadk_ctx,
                        uint8_t *iiv,
                        uint8_t *dst,
                        const uint8_t *src,
                        size_t length,
                        bool encrypt);
int uadk_aes_set_key(struct uadk_cipher_st *uadk_ctx,
                     const uint8_t *uadk_key,
                     uint16_t key_len);
void uadk_aes_do_cipher(struct uadk_cipher_st *uadk_ctx,
                        uint8_t *iiv,
                        uint8_t *dst,
                        const uint8_t *src,
                        size_t length,
                        bool encrypt);
void ifm_aes128_encrypt(const struct ifm_aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void ifm_aes192_encrypt(const struct ifm_aes192_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void ifm_aes256_encrypt(const struct ifm_aes256_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);

void ifm_aes128_decrypt(const struct ifm_aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void ifm_aes192_decrypt(const struct ifm_aes192_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void ifm_aes256_decrypt(const struct ifm_aes256_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);

#endif

#endif /* IFM_NETTLE_AES_COMMON_H_IN_INCLUDED */