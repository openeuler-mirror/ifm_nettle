/******************************************************************************
 * ifm_nettle-rsa_pkcs1.c: add rsa pkcs1 support for ifm_nettle
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
#ifdef __aarch64__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif
#include "rsa_pkcs1.h"

#define PREFIX_SIZE 11
#define TWO 2
#define THREE 3

#ifdef __aarch64__
// 手动实现nettle库中_pkcs1_signature_prefix的功能
uint8_t *uadk_pkcs1_signature_prefix(unsigned key_size, uint8_t *buffer, unsigned id_size, const uint8_t *id,
                                     unsigned digest_size)
{
    unsigned j;
    if (key_size < PREFIX_SIZE + id_size + digest_size) {
        return NULL;
    }
    j = key_size - digest_size - id_size;

    memcpy(buffer + j, id, id_size);
    buffer[0] = 0;
    buffer[1] = 1;
    buffer[j - 1] = 0;

    if (j < PREFIX_SIZE) {
        fprintf(stderr, "uadk_pkcs1_signature_prefix: j < PREFIX_SIZE\n");
    }
    memset(buffer + TWO, 0xff, j - THREE);

    return buffer + j + id_size;
}

int uadk_pkcs1_rsa_md5_encode(mpz_t m, size_t key_size, struct ifm_md5_ctx *hash)
{
    uint8_t *p;
    uint8_t *em;
    size_t tmp_em_size;
    tmp_em_size = key_size;
    em = malloc(tmp_em_size);

    p = uadk_pkcs1_signature_prefix(key_size, em, sizeof(md5_prefix), md5_prefix, MD5_DIGEST_SIZE);
    if (p) {
        ifm_md5_digest(hash, MD5_DIGEST_SIZE, p);
        nettle_mpz_set_str_256_u(m, key_size, em);
        free(em);
        return 1;
    } else {
        free(em);
        return 0;
    }
}

int uadk_pkcs1_rsa_md5_encode_digest(mpz_t m, size_t key_size, const uint8_t *digest)
{
    uint8_t *p;
    uint8_t *em;
    size_t tmp_em_size;
    tmp_em_size = key_size;
    em = malloc(sizeof(*em) * tmp_em_size);

    p = uadk_pkcs1_signature_prefix(key_size, em, sizeof(md5_prefix), md5_prefix, MD5_DIGEST_SIZE);
    if (p) {
        memcpy(p, digest, MD5_DIGEST_SIZE);
        nettle_mpz_set_str_256_u(m, key_size, em);
        free(em);
        return 1;
    } else {
        free(em);
        return 0;
    }
}

int uadk_pkcs1_rsa_sha256_encode(mpz_t m, size_t key_size, struct ifm_sha256_ctx *hash)
{
    uint8_t *p;
    uint8_t *em;
    size_t tmp_em_size;
    tmp_em_size = key_size;
    em = malloc(sizeof(*em) * tmp_em_size);

    p = uadk_pkcs1_signature_prefix(key_size, em, sizeof(sha256_prefix), sha256_prefix, SHA256_DIGEST_SIZE);
    if (p) {
        ifm_sha256_digest(hash, SHA256_DIGEST_SIZE, p);
        nettle_mpz_set_str_256_u(m, key_size, em);
        free(em);
        return 1;
    } else {
        free(em);
        return 0;
    }
}

int uadk_pkcs1_rsa_sha256_encode_digest(mpz_t m, size_t key_size, const uint8_t *digest)
{
    uint8_t *p;
    uint8_t *em;
    size_t tmp_em_size;
    tmp_em_size = key_size;
    em = malloc(sizeof(*em) * tmp_em_size);

    p = uadk_pkcs1_signature_prefix(key_size, em, sizeof(sha256_prefix), sha256_prefix, SHA256_DIGEST_SIZE);
    if (p) {
        memcpy(p, digest, SHA256_DIGEST_SIZE);
        nettle_mpz_set_str_256_u(m, key_size, em);
        free(em);
        return 1;
    } else {
        free(em);
        return 0;
    }
}

int uadk_pkcs1_rsa_sha512_encode(mpz_t m, size_t key_size, struct ifm_sha512_ctx *hash)
{
    uint8_t *p;
    uint8_t *em;
    size_t tmp_em_size;
    tmp_em_size = key_size;
    em = malloc(sizeof(*em) * tmp_em_size);

    p = uadk_pkcs1_signature_prefix(key_size, em, sizeof(sha512_prefix), sha512_prefix, SHA512_DIGEST_SIZE);
    if (p) {
        ifm_sha512_digest(hash, SHA512_DIGEST_SIZE, p);
        nettle_mpz_set_str_256_u(m, key_size, em);
        free(em);
        return 1;
    } else {
        free(em);
        return 0;
    }
}

int uadk_pkcs1_rsa_sha512_encode_digest(mpz_t m, size_t key_size, const uint8_t *digest)
{
    uint8_t *p;
    uint8_t *em;
    size_t tmp_em_size;
    tmp_em_size = key_size;
    em = malloc(sizeof(*em) * tmp_em_size);

    p = uadk_pkcs1_signature_prefix(key_size, em, sizeof(sha512_prefix), sha512_prefix, SHA512_DIGEST_SIZE);
    if (p) {
        memcpy(p, digest, SHA512_DIGEST_SIZE);
        nettle_mpz_set_str_256_u(m, key_size, em);
        free(em);
        return 1;
    } else {
        free(em);
        return 0;
    }
}
#endif