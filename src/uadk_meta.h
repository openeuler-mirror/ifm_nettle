/******************************************************************************
uadk_meta.h

Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.

Authors:
zhonghao2023 zhonghao@isrc.iscas.ac.cn

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.


This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
Lesser General Public License for more details.


You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
********************************************************************************/
#ifndef IFM_NETTLE_UADK_META_INCLUDED
#define IFM_NETTLE_UADK_META_INCLUDED

#ifdef __aarch64__
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_bmm.h"
#include "uadk/v1/wd_digest.h"
#include "uadk/v1/wd_cipher.h"
#include "uadk/v1/wd_aead.h"
#include "ifm_utils.h"

#define SQE_SIZE    128
#define MAX_BLOCK_SZ    1024 * 1024 * 1        // 每次hash分段的最大长度
#define MAX_BLOCK_NM    128
#define GCM_MAX_BLOCK_SZ    16 * 1024 * 1024
#define AES_MAX_BLOCK_SZ    1024*1024*16
struct uadk_digest_st {
    struct wd_queue *pq;
    struct wcrypto_digest_ctx_setup setup;
    struct wcrypto_digest_op_data opdata;
    struct wcrypto_digest_op_data *p_opdata;
    IFMUadkShareOpdata *p_share_opdata;
    void *pool;
    void *ctx;
};
struct uadk_cipher_st {
    struct wd_queue *q;
    void *pool;
    void *ctx;
    struct wcrypto_cipher_op_data opdata;
    struct wcrypto_cipher_op_data *p_opdata;
    IFMUadkShareOpdata *p_share_opdata;
    IFMUadkShareCtx *p_share_ctx;
    enum wcrypto_cipher_mode mode;
    bool set_key;
};
struct uadk_aead_st {
    struct wd_queue *pq;
    struct wcrypto_aead_ctx_setup  setup;
    struct wcrypto_aead_op_data  opdata;
    struct wcrypto_aead_op_data *p_opdata;
    IFMUadkShareOpdata *p_share_opdata;
    IFMUadkShareCtx *p_share_ctx;
    void *pool;
    void *ctx;
};
#endif

#endif