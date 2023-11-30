/******************************************************************************
 * sm4.h: uadk sm4
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * Chen-yufanspace <chenyufan912@gmail.com>
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
#ifndef IFM_NETTLE_SM4_H
#define IFM_NETTLE_SM4_H
#ifdef __aarch64__
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_bmm.h"
#include "uadk/v1/wd_cipher.h"
#endif
#include "sm4_meta.h"
#ifdef __cplusplus
extern "C" {
#endif

#define sm4_set_encrypt_key ifm_sm4_set_encrypt_key
#define sm4_set_decrypt_key ifm_sm4_set_decrypt_key
#define sm4_crypt ifm_sm4_crypt

void ifm_sm4_set_encrypt_key(struct ifm_sm4_ctx *ctx, const uint8_t *key);

void ifm_sm4_set_decrypt_key(struct ifm_sm4_ctx *ctx, const uint8_t *key);

void ifm_sm4_crypt(struct ifm_sm4_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);

#ifdef __cplusplus
}
#endif
#endif