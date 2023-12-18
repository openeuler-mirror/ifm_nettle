/******************************************************************************
 * bench_rsa_meta.h: rsa_meta for bench
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * chen-yufanspace <1109674186@qq.com>
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

#ifndef BENCH_RSA_META_H
#define BENCH_RSA_META_H

#include "nettle/nettle-meta.h"
#include "bench_sha2_meta.h"
#include "md5_meta.h"
#include "md5.h"
#include "rsa.h"

#ifdef __cplusplus
extern "C" {
#endif

#define rsa_public_key ifm_rsa_public_key
#define rsa_private_key ifm_rsa_private_key

typedef void nettle_rsa_public_key_init_func(struct rsa_public_key *key);
typedef void nettle_rsa_private_key_init_func(struct rsa_private_key *key);
typedef int nettle_rsa_private_key_prepare_func(struct rsa_private_key *key);
typedef int nettle_rsa_public_key_prepare_func(struct rsa_public_key *key);
typedef void nettle_rsa_public_key_clear_func(struct rsa_public_key *key);
typedef void nettle_rsa_private_key_clear_func(struct rsa_private_key *key);
typedef int nettle_rsa_sign_func(const struct rsa_private_key *key, void *hash, mpz_t signature);
typedef int nettle_rsa_verify_func(const struct rsa_public_key *key, void *hash, const mpz_t signature);
typedef int nettle_rsa_sign_digest_func(const struct rsa_private_key *key, const uint8_t *digest, mpz_t signature);

const struct nettle_hash nettle_ifm_md5 = {
    "ifm_md5", sizeof(struct ifm_md5_ctx),
    MD5_DIGEST_SIZE,
    MD5_BLOCK_SIZE,
    (nettle_hash_init_func *) ifm_md5_init,
    (nettle_hash_update_func *) ifm_md5_update,
    (nettle_hash_digest_func *) ifm_md5_digest
};

struct nettle_rsa {
    const char *name;

    const struct nettle_hash *hash;

    nettle_rsa_public_key_init_func *pubinit;
    nettle_rsa_private_key_init_func *priinit;
    nettle_rsa_public_key_prepare_func *pubpre;
    nettle_rsa_private_key_prepare_func *pripre;
    nettle_rsa_public_key_clear_func *pubclr;
    nettle_rsa_private_key_clear_func *priclr;
    nettle_rsa_sign_func *sign;
    nettle_rsa_verify_func *verify;
    nettle_rsa_sign_digest_func *sign_digest;
};

const struct nettle_rsa nettle_rsa_md5 = {
    "rsa_md5",
    &(nettle_ifm_md5),
    (nettle_rsa_public_key_init_func *) rsa_public_key_init,
    (nettle_rsa_private_key_init_func *) rsa_private_key_init,
    (nettle_rsa_public_key_prepare_func *) rsa_public_key_prepare,
    (nettle_rsa_private_key_prepare_func *) rsa_private_key_prepare,
    (nettle_rsa_public_key_clear_func *) rsa_public_key_clear,
    (nettle_rsa_private_key_clear_func *) rsa_private_key_clear,
    (nettle_rsa_sign_func *) rsa_md5_sign,
    (nettle_rsa_verify_func *) rsa_md5_verify,
    (nettle_rsa_sign_digest_func *) rsa_md5_sign_digest
};

const struct nettle_rsa nettle_rsa_sha256 = {
    "rsa_sha256",
    &(nettle_ifm_sha256),
    (nettle_rsa_public_key_init_func *) rsa_public_key_init,
    (nettle_rsa_private_key_init_func *) rsa_private_key_init,
    (nettle_rsa_public_key_prepare_func *)rsa_public_key_prepare,
    (nettle_rsa_private_key_prepare_func *) rsa_private_key_prepare,
    (nettle_rsa_public_key_clear_func *) rsa_public_key_clear,
    (nettle_rsa_private_key_clear_func *) rsa_private_key_clear,
    (nettle_rsa_sign_func *) rsa_sha256_sign,
    (nettle_rsa_verify_func *) rsa_sha256_verify,
    (nettle_rsa_sign_digest_func *) rsa_sha256_sign_digest
};

const struct nettle_rsa nettle_rsa_sha512 = {
    "rsa_sha512",
    &(nettle_ifm_sha512),
    (nettle_rsa_public_key_init_func *) rsa_public_key_init,
    (nettle_rsa_private_key_init_func *) rsa_private_key_init,
    (nettle_rsa_public_key_prepare_func *)rsa_public_key_prepare,
    (nettle_rsa_private_key_prepare_func *) rsa_private_key_prepare,
    (nettle_rsa_public_key_clear_func *) rsa_public_key_clear,
    (nettle_rsa_private_key_clear_func *) rsa_private_key_clear,
    (nettle_rsa_sign_func *) rsa_sha512_sign,
    (nettle_rsa_verify_func *) rsa_sha512_verify,
    (nettle_rsa_sign_digest_func *) rsa_sha512_sign_digest
};

#ifdef __cplusplus
}
#endif

#endif