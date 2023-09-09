/******************************************************************************
 * aes_meta.c: uadk aes meta
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

#ifndef IFM_NETTLE_AES_META_H_INCLUDED
#define IFM_NETTLE_AES_META_H_INCLUDED

#include <stdbool.h>
#include "nettle-meta.h"
#ifdef __aarch64__
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_bmm.h"
#include "uadk/v1/wd_cipher.h"
#endif

#define IFM_AES128_ROUNDS 10
#define IFM_AES192_ROUNDS 12
#define IFM_AES256_ROUNDS 14

#define AES_BLOCK_SIZE 16

#define AES128_KEY_SIZE 16
#define AES192_KEY_SIZE 24
#define AES256_KEY_SIZE 32

#ifdef __aarch64__
struct uadk_cipher_st {
    struct wd_queue *q;
    void *pool;
    void *ctx;
    struct wcrypto_cipher_op_data opdata;
    enum wcrypto_cipher_mode mode;
    bool set_key;
};
#endif

struct ifm_aes128_ctx {
    uint32_t keys[4 * (IFM_AES128_ROUNDS + 1)];
#ifdef __aarch64__
    uint8_t uadk_key[AES128_KEY_SIZE];
    struct uadk_cipher_st uadk_ctx;
    bool use_uadk;
#endif
};

struct ifm_aes192_ctx {
    uint32_t keys[4 * (IFM_AES192_ROUNDS + 1)];
#ifdef __aarch64__
    uint8_t uadk_key[AES192_KEY_SIZE];
    struct uadk_cipher_st uadk_ctx;
    bool use_uadk;
#endif
};

struct ifm_aes256_ctx {
    uint32_t keys[4 * (IFM_AES256_ROUNDS + 1)];
#ifdef __aarch64__
    uint8_t uadk_key[AES256_KEY_SIZE];
    struct uadk_cipher_st uadk_ctx;
    bool use_uadk;
#endif
};

struct ifm_aes_ctx {
    unsigned key_size; /* In octets */
    union {
        struct ifm_aes128_ctx ctx128;
        struct ifm_aes192_ctx ctx192;
        struct ifm_aes256_ctx ctx256;
    } u;
};

#endif /* IFM_NETTLE_AES_META_H_INCLUDED */