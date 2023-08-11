/******************************************************************************
 * bench_sha2_meta.h: sha2_meta for bench
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * zhonghao2023 <zhonghao@isrc.iscas.ac.cn>
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
#ifndef IFM_NETTLE_BENCH_SHA2_META_INCLUDED
#define IFM_NETTLE_BENCH_SHA2_META_INCLUDED
#include "sha2_meta.h"
#include "sha2.h"
#include "nettle/nettle-meta.h"

const struct nettle_hash nettle_ifm_sha256 = _NETTLE_HASH(ifm_sha256, SHA256);
const struct nettle_hash nettle_ifm_sha224 = {
    "ifm_sha224", sizeof(struct ifm_sha256_ctx),
    SHA224_DIGEST_SIZE,
    SHA224_BLOCK_SIZE,
    (nettle_hash_init_func *) ifm_sha224_init,
    (nettle_hash_update_func *) ifm_sha224_update,
    (nettle_hash_digest_func *) ifm_sha224_digest
};
const struct nettle_hash nettle_ifm_sha384 = {
    "ifm_sha384", sizeof(struct ifm_sha512_ctx),
    SHA384_DIGEST_SIZE,
    SHA384_BLOCK_SIZE,
    (nettle_hash_init_func *) ifm_sha384_init,
    (nettle_hash_update_func *) ifm_sha384_update,
    (nettle_hash_digest_func *) ifm_sha384_digest
};
const struct nettle_hash nettle_ifm_sha512 = _NETTLE_HASH(ifm_sha512, SHA512);

const struct nettle_hash nettle_ifm_sha512_224 = {
    "ifm_sha512-224", sizeof(struct ifm_sha512_ctx),
    SHA512_224_DIGEST_SIZE,
    SHA512_224_BLOCK_SIZE,
    (nettle_hash_init_func *) ifm_sha512_224_init,
    (nettle_hash_update_func *) ifm_sha512_224_update,
    (nettle_hash_digest_func *) ifm_sha512_224_digest
};

const struct nettle_hash nettle_ifm_sha512_256 = {
    "ifm_sha512-256", sizeof(struct ifm_sha512_ctx),
    SHA512_256_DIGEST_SIZE,
    SHA512_256_BLOCK_SIZE,
    (nettle_hash_init_func *) ifm_sha512_256_init,
    (nettle_hash_update_func *) ifm_sha512_256_update,
    (nettle_hash_digest_func *) ifm_sha512_256_digest
};
#endif