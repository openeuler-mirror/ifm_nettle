/******************************************************************************
 * ifm_nettle-rsa.h: header for rsa
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * jiaji2023 <jiaji@isrc.iscas.ac.cn>
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
#ifndef IFM_NETTLE_RSA_INCLUDED
#define IFM_NETTLE_RSA_INCLUDED

#include <gmp.h>
#include <nettle/bignum.h>
#include <nettle/buffer.h>
#include <nettle/nettle-types.h>
#include <nettle/sha1.h>
#include <stddef.h>
#include <stdint.h>

#include "md5_meta.h"
#include "rsa_meta.h"
#include "sha2_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Name mangling */
#define rsa_public_key_init ifm_rsa_public_key_init
#define rsa_public_key_clear ifm_rsa_public_key_clear
#define rsa_public_key_prepare ifm_rsa_public_key_prepare
#define rsa_private_key_init ifm_rsa_private_key_init
#define rsa_private_key_clear ifm_rsa_private_key_clear
#define rsa_private_key_prepare ifm_rsa_private_key_prepare
#define rsa_md5_sign ifm_rsa_md5_sign
#define rsa_md5_verify ifm_rsa_md5_verify
#define rsa_sha1_sign ifm_rsa_sha1_sign
#define rsa_sha1_verify ifm_rsa_sha1_verify
#define rsa_sha256_sign ifm_rsa_sha256_sign
#define rsa_sha256_verify ifm_rsa_sha256_verify
#define rsa_sha512_sign ifm_rsa_sha512_sign
#define rsa_sha512_verify ifm_rsa_sha512_verify
#define rsa_md5_sign_digest ifm_rsa_md5_sign_digest
#define rsa_md5_verify_digest ifm_rsa_md5_verify_digest
#define rsa_sha1_sign_digest ifm_rsa_sha1_sign_digest
#define rsa_sha1_verify_digest ifm_rsa_sha1_verify_digest
#define rsa_sha256_sign_digest ifm_rsa_sha256_sign_digest
#define rsa_sha256_verify_digest ifm_rsa_sha256_verify_digest
#define rsa_sha512_sign_digest ifm_rsa_sha512_sign_digest
#define rsa_sha512_verify_digest ifm_rsa_sha512_verify_digest
#define rsa_generate_keypair ifm_rsa_generate_keypair

/* Calls mpz_init to initialize bignum storage. */
void ifm_rsa_public_key_init(struct ifm_rsa_public_key *key);

/* Calls mpz_clear to deallocate bignum storage. */
void ifm_rsa_public_key_clear(struct ifm_rsa_public_key *key);

int ifm_rsa_public_key_prepare(struct ifm_rsa_public_key *key);

/* Calls mpz_init to initialize bignum storage. */
void ifm_rsa_private_key_init(struct ifm_rsa_private_key *key);

/* Calls mpz_clear to deallocate bignum storage. */
void ifm_rsa_private_key_clear(struct ifm_rsa_private_key *key);

int ifm_rsa_private_key_prepare(struct ifm_rsa_private_key *key);

int ifm_rsa_md5_sign(const struct ifm_rsa_private_key *key, struct ifm_md5_ctx *hash, mpz_t signature);

int ifm_rsa_md5_verify(const struct ifm_rsa_public_key *key, struct ifm_md5_ctx *hash, const mpz_t signature);

int ifm_rsa_sha1_sign(const struct ifm_rsa_private_key *key, struct sha1_ctx *hash, mpz_t signature);

int ifm_rsa_sha1_verify(const struct ifm_rsa_public_key *key, struct sha1_ctx *hash, const mpz_t signature);

int ifm_rsa_sha256_sign(const struct ifm_rsa_private_key *key, struct ifm_sha256_ctx *hash, mpz_t signature);

int ifm_rsa_sha256_verify(const struct ifm_rsa_public_key *key, struct ifm_sha256_ctx *hash, const mpz_t signature);

int ifm_rsa_sha512_sign(const struct ifm_rsa_private_key *key, struct ifm_sha512_ctx *hash, mpz_t signature);

int ifm_rsa_sha512_verify(const struct ifm_rsa_public_key *key, struct ifm_sha512_ctx *hash, const mpz_t signature);

/* Variants taking the digest as argument. */
int ifm_rsa_md5_sign_digest(const struct ifm_rsa_private_key *key, const uint8_t *digest, mpz_t s);

int ifm_rsa_md5_verify_digest(const struct ifm_rsa_public_key *key, const uint8_t *digest, const mpz_t signature);

int ifm_rsa_sha1_sign_digest(const struct ifm_rsa_private_key *key, const uint8_t *digest, mpz_t s);

int ifm_rsa_sha1_verify_digest(const struct ifm_rsa_public_key *key, const uint8_t *digest, const mpz_t signature);

int ifm_rsa_sha256_sign_digest(const struct ifm_rsa_private_key *key, const uint8_t *digest, mpz_t s);

int ifm_rsa_sha256_verify_digest(const struct ifm_rsa_public_key *key, const uint8_t *digest, const mpz_t signature);

int ifm_rsa_sha512_sign_digest(const struct ifm_rsa_private_key *key, const uint8_t *digest, mpz_t s);

int ifm_rsa_sha512_verify_digest(const struct ifm_rsa_public_key *key, const uint8_t *digest, const mpz_t signature);

/* Key generation */

/* Note that the key structs must be initialized first. */
int ifm_rsa_generate_keypair(struct ifm_rsa_public_key *pub, struct ifm_rsa_private_key *key,

                             void *random_ctx, nettle_random_func *random, void *progress_ctx,
                             nettle_progress_func *progress,

                             /* Desired size of modulo, in bits */
                             unsigned n_size,

                             /* Desired size of public exponent, in bits. If
                              * zero, the passed in value pub->e is used. */
                             unsigned e_size);

#ifdef __cplusplus
}
#endif

#endif /* IFM_NETTLE_RSA_INCLUDED */