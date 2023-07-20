/******************************************************************************
 * ifm_nettle-hmac_meta.h: meta for hmac
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
#ifndef IFM_NETTLE_HMAC_META_H
#define IFM_NETTLE_HMAC_META_H

#include <nettle/nettle-meta.h>
#include <nettle/streebog.h>
#include <nettle/ripemd160.h>
#include <nettle/sha1.h>
#include <nettle/gosthash94.h>

#include "md5_meta.h"
#include "sha2_meta.h"
#include "sm3_meta.h"

#define ifm_HMAC_CTX(type) \
{ type outer; type inner; type state; }

/* hmac-md5 */
struct ifm_hmac_md5_ctx ifm_HMAC_CTX(struct ifm_md5_ctx);

/* hmac-ripemd160 */
struct ifm_hmac_ripemd160_ctx ifm_HMAC_CTX(struct ripemd160_ctx);

/* hmac-sha1 */
struct ifm_hmac_sha1_ctx ifm_HMAC_CTX(struct sha1_ctx);

/* hmac-sha256 */
struct ifm_hmac_sha256_ctx ifm_HMAC_CTX(struct ifm_sha256_ctx);

/* hmac-sha224 */
#define ifm_hmac_sha224_ctx ifm_hmac_sha256_ctx

/* hmac-sha512 */
struct ifm_hmac_sha512_ctx ifm_HMAC_CTX(struct ifm_sha512_ctx);

/* hmac-sha384 */
#define ifm_hmac_sha384_ctx hmac_sha512_ctx

/* hmac-gosthash94 */
struct ifm_hmac_gosthash94_ctx ifm_HMAC_CTX(struct gosthash94_ctx);

struct ifm_hmac_gosthash94cp_ctx ifm_HMAC_CTX(struct gosthash94cp_ctx);

/* hmac-streebog */
struct ifm_hmac_streebog512_ctx ifm_HMAC_CTX(struct streebog512_ctx);
#define ifm_hmac_streebog256_ctx ifm_hmac_streebog512_ctx

/* hmac-sm3 */
struct ifm_hmac_sm3_ctx ifm_HMAC_CTX(struct ifm_sm3_ctx);


#endif // IFM_NETTLE_HMAC_META_H
