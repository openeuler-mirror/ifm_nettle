/******************************************************************************
 * ifm_nettle-sm3_meta.h: meta for sm3
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * jiaji2023 <jiaji@isrc.iscas.ac.cn>
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
#ifndef IFM_NETTLE_SM4_META_H
#define IFM_NETTLE_SM4_META_H

#include <stdint.h>
#ifdef __aarch64__
#include "uadk_meta.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE 16

struct ifm_sm4_ctx {
    uint32_t rkey[32];
#ifdef __aarch64__
    uint8_t uadk_key[SM4_KEY_SIZE];
    struct uadk_cipher_st uadk_ctx;
    bool use_uadk;
    bool encrypt;
#endif
};

#ifdef __cplusplus
}
#endif

#endif // IFM_NETTLE_SM4_META_H
