/******************************************************************************
 * ifm_nettle-rsa_meta.h: meta for rsa
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
#ifndef IFM_NETTLE_RSA_META_INCLUDED
#define IFM_NETTLE_RSA_META_INCLUDED

#include <gmp.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __aarch64__
#include "uadk/v1/wd_bmm.h"
#include "uadk/v1/wd_rsa.h"
#include "uadk_meta.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct ifm_rsa_public_key {
    /* Size of the modulo, in octets. This is also the size of all
     * signatures that are created or verified with this key. */
    size_t size;

    /* Modulo */
    mpz_t n;

    /* Public exponent */
    mpz_t e;

#ifdef __aarch64__
    struct uadk_rsa_st uadk_st;
    bool use_uadk;
#endif
};

struct ifm_rsa_private_key {
    size_t size;

    /* d is filled in by the key generation function; otherwise it's
     * completely unused. */
    mpz_t d;

    /* The two factors */
    mpz_t p;
    mpz_t q;

    /* d % (p-1), i.e. a e = 1 (mod (p-1)) */
    mpz_t a;

    /* d % (q-1), i.e. b e = 1 (mod (q-1)) */
    mpz_t b;

    /* modular inverse of q , i.e. c q = 1 (mod p) */
    mpz_t c;

#ifdef __aarch64__
    struct uadk_rsa_st uadk_st;
    bool use_uadk;
#endif
};

#ifdef __cplusplus
}
#endif

#endif // IFM_NETTLE_RSA_META_INCLUDED
