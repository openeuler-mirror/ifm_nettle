/******************************************************************************
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * huangduirong <huangduirong@huawei.com>
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
#ifndef IFM_NETTLE_MD5_META_INCLUDED
#define IFM_NETTLE_MD5_META_INCLUDED

#include <stddef.h>
#include <stdint.h>
#ifdef __aarch64__
#include "uadk_meta.h"
#include "uadk/v1/wd_bmm.h"
#include "uadk/v1/wd_digest.h"
#endif


#ifdef __cplusplus
extern "C" {
#endif

#define MD5_DIGEST_SIZE 16
#define MD5_BLOCK_SIZE 64
/* For backwards compatibility */
#define MD5_DATA_SIZE MD5_BLOCK_SIZE

/* Digest is kept internally as 4 32-bit words. */
#define _MD5_DIGEST_LENGTH 4

struct ifm_md5_ctx
{
    uint32_t state[_MD5_DIGEST_LENGTH];
    uint64_t count;               /* Block count */
    unsigned index;               /* Into buffer */
    uint8_t block[MD5_BLOCK_SIZE]; /* Block buffer */
#ifdef __aarch64__
    struct uadk_digest_st uadk_ctx; /* UADK相关的结构体数据 */
    bool use_uadk;
#endif
};

#ifdef __cplusplus
}
#endif

#endif /* IFM_NETTLE_MD5_META_INCLUDED */