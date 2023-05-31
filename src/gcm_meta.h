/******************************************************************************
 * ifm_nettle-gcm_meta.h: meta for gcm
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
#ifndef IFM_NETTLE_GCM_META_INCLUDED
#define IFM_NETTLE_GCM_META_INCLUDED

#include "aes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GCM_AES128_KEY_SIZE 16
#define GCM_AES192_KEY_SIZE 24
#define GCM_AES256_KEY_SIZE 32

#define GCM_BLOCK_SIZE 16
#define GCM_IV_SIZE (GCM_BLOCK_SIZE - 4)
#define GCM_DIGEST_SIZE 16
#define GCM_TABLE_BITS 8

typedef void ifm_cipher_func(const void *ctx, size_t length, uint8_t *dst, const uint8_t *src);

union ifm_block16 {
    uint8_t b[16];
    unsigned long w[16 / sizeof(unsigned long)] _NETTLE_ATTRIBUTE_DEPRECATED;
    uint64_t u64[2];
};

struct ifm_gcm_key {
    union ifm_block16 h[1 << GCM_TABLE_BITS];
};

struct ifm_gcm_ctx {
    union ifm_block16 iv;
    union ifm_block16 ctr;
    union ifm_block16 x;
    uint64_t auth_size;
    uint64_t data_size;
};

#define IFM_GCM_CTX(type) \
    { struct ifm_gcm_key key; struct ifm_gcm_ctx gcm; type cipher; }

struct ifm_gcm_aes128_ctx IFM_GCM_CTX(struct ifm_aes128_ctx);
struct ifm_gcm_aes192_ctx IFM_GCM_CTX(struct ifm_aes192_ctx);
struct ifm_gcm_aes256_ctx IFM_GCM_CTX(struct ifm_aes256_ctx);

#ifdef __cplusplus
}
#endif

#endif
