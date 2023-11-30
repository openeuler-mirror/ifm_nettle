/******************************************************************************
 * gcrypt_aes_meta.h: meta for gcry_uadk_aes
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * YihuiTan <202121632838@smail.edu.cn.com>
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

#ifndef GCRY_AES_META_INCLUDED
#define GCRY_AES_META_INCLUDED

#include <gcrypt.h>
#include "uadk_meta.h"

#ifdef __aarch64__
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_bmm.h"
#include "uadk/v1/wd_cipher.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __aarch64__
#define AES_BLOCK_SIZE 16
#define AES128_KEY_SIZE 16
#define AES192_KEY_SIZE 24
#define AES256_KEY_SIZE 32
#define MAX_CIPHER_LENGTH 16 * 1024 * 1024

#define MAX_KEY_SIZE 128
#define CIPHER_IV_SIZE 16
#endif

typedef struct gcry_uadk_aes_hd {
    /* gcry_cipher_hd_t */
    gcry_cipher_hd_t gcry_hd_t;

#ifdef __aarch64__
    struct uadk_cipher_st uadk_ctx; /* UADK相关的结构体数据 */
    enum gcry_cipher_algos alg;
    bool use_uadk;

    void *key;
    size_t keylen;
    void *iv;
    size_t ivlen;
    int mode;
    unsigned int flags;
#endif
} *gcry_uadk_aes_hd_t;

#ifdef __cplusplus
}
#endif

#endif