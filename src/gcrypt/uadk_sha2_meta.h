/******************************************************************************
 * uadk_sha2_meta.h: meta for gcry_uadk_sha2
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * xinghailiao <xinghailiao@smail.xtu.edu.cn>
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
#ifndef GCRY_UADK_SHA2_META_INCLUDED
#define GCRY_UADK_SHA2_META_INCLUDED

#include <../uadk_meta.h>
#include <gcrypt.h>

#ifdef __aarch64__
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_bmm.h"
#include "uadk/v1/wd_digest.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __aarch64__
#define SHA256_DIGEST_SIZE 32
#define SHA224_DIGEST_SIZE 28
#define SHA512_DIGEST_SIZE 64
#define SHA384_DIGEST_SIZE 48
#define MAX_HMAC_KEY_SIZE 128
struct uadk_digest_struct {
    struct wd_queue *pq;
    struct wcrypto_digest_ctx_setup setup;
    struct wcrypto_digest_op_data opdata;
    void *pool;
    void *ctx;
    int alg;
};
#endif

typedef struct gcry_uadk_sha2_hd {
    gcry_md_hd_t gcry_hd_t;

#ifdef __aarch64__
    int ctx_len;
    struct uadk_digest_struct uadk_ctx[4]; /* UADK相关的结构体数据 */
    bool use_uadk;
    bool use_gcry;
    void *key;
    size_t keylen;
    uint8_t mode;
#endif
} *gcry_uadk_sha2_hd_t;

#ifdef __cplusplus
}
#endif

#endif