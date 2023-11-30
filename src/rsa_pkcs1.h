/******************************************************************************
 * ifm_nettle-rsa_pkcs1.h: add rsa pkcs1 support for ifm_nettle
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
#ifndef IFM_NETTLE_RSA_PKCS1_INCLUDED
#define IFM_NETTLE_RSA_PKCS1_INCLUDED
#include <nettle/base16.h>
#include <nettle/bignum.h>
#include <nettle/pkcs1.h>
#include <nettle/rsa.h>
#include <string.h>

#undef md5_init
#undef md5_update
#undef md5_digest
#include "md5.h"
#include "rsa_meta.h"

#undef sha224_init
#undef sha224_digest
#undef sha256_init
#undef sha256_update
#undef sha256_digest
#undef sha384_init
#undef sha384_digest
#undef sha512_init
#undef sha512_update
#undef sha512_digest
#undef sha512_224_init
#undef sha512_224_digest
#undef sha512_256_init
#undef sha512_256_digest

#include "sha2.h"

#ifdef __cplusplus
extern "C" {
#endif

static const uint8_t md5_prefix[] = {
    /* 18 octets prefix, 16 octets hash, 34 total. */
    0x30, 32,                                                /* SEQUENCE */
    0x30, 12,                                                /* SEQUENCE */
    0x06, 8,                                                 /* OBJECT IDENTIFIER */
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0, /* NULL */
    0x04, 16                                                 /* OCTET STRING */
                                                             /* Here comes the raw hash value */
};

static const uint8_t sha256_prefix[] = {
    /* 19 octets prefix, 32 octets hash, total 51 */
    0x30, 49,                                                      /* SEQUENCE */
    0x30, 13,                                                      /* SEQUENCE */
    0x06, 9,                                                       /* OBJECT IDENTIFIER */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0, /* NULL */
    0x04, 32                                                       /* OCTET STRING */
                                                                   /* Here comes the raw hash value */
};

static const uint8_t sha512_prefix[] = {
    /* 19 octets prefix, 64 octets hash, total 83 */
    0x30, 81,                                                      /* SEQUENCE */
    0x30, 13,                                                      /* SEQUENCE */
    0x06, 9,                                                       /* OBJECT IDENTIFIER */
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0, /* NULL */
    0x04, 64                                                       /* OCTET STRING */
                                                                   /* Here comes the raw hash value, 64 octets */
};

uint8_t *uadk_pkcs1_signature_prefix(unsigned key_size, uint8_t *buffer, unsigned id_size, const uint8_t *id,
                                     unsigned digest_size);

int uadk_pkcs1_rsa_md5_encode(mpz_t m, size_t key_size, struct ifm_md5_ctx *hash);

int uadk_pkcs1_rsa_md5_encode_digest(mpz_t m, size_t key_size, const uint8_t *digest);

int uadk_pkcs1_rsa_sha256_encode(mpz_t m, size_t key_size, struct ifm_sha256_ctx *hash);

int uadk_pkcs1_rsa_sha256_encode_digest(mpz_t m, size_t key_size, const uint8_t *digest);

int uadk_pkcs1_rsa_sha512_encode(mpz_t m, size_t key_size, struct ifm_sha512_ctx *hash);

int uadk_pkcs1_rsa_sha512_encode_digest(mpz_t m, size_t key_size, const uint8_t *digest);

#ifdef __cplusplus
}
#endif

#endif