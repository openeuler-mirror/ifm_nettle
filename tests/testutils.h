/******************************************************************************
 * iSula-libutils: utils library for iSula
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * Haozi007 <liuhao27@huawei.com>
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
#include <gtest/gtest.h>
#include <nettle/nettle-meta.h>
#include <gmp.h>

#include "rsa_meta.h"

#define md5_ctx ifm_md5_ctx
#define sha256_ctx ifm_sha256_ctx
#define sha512_ctx ifm_sha512_ctx
#define rsa_public_key ifm_rsa_public_key
#define rsa_private_key ifm_rsa_private_key

void *
xalloc(size_t size);

struct tstring {
  struct tstring *next;
  size_t length;
  uint8_t data[1];
};

struct tstring *
tstring_alloc (size_t length);

void
tstring_clear(void);

struct tstring *
tstring_data(size_t length, const uint8_t *data);

struct tstring *
tstring_hex(const char *hex);

void
tstring_print_hex(const struct tstring *s);

/* Decodes a NUL-terminated hex string. */

void
print_hex(size_t length, const uint8_t *data);

void
test_hash(const struct nettle_hash *hash,
	  const struct tstring *msg,
	  const struct tstring *digest);


/* String literal of type unsigned char. The GNUC version is safer. */
#if __GNUC__
#define US(s) ({ static const unsigned char us_s[] = s; us_s; })
#else
#define US(s) ((const uint8_t *) (s))
#endif
  
/* LDATA needs to handle NUL characters. */
#define LLENGTH(x) (sizeof(x) - 1)
#define LDATA(x) LLENGTH(x), US(x)
#define LDUP(x) strlen(x), strdup(x)

#define SHEX(x) (tstring_hex(x))
#define SDATA(x) ((const struct tstring *)tstring_data(LLENGTH(x), US(x)))
#define H(x) (SHEX(x)->data)

#define MEMEQ(length, a, b) (!memcmp((a), (b), (length)))

#define SKIP() exit(77)

// 在gtest中，将原有的FAIL修改为abort();
#define ASSERT(x) do { \
    if (!(x))                \
      {                      \
	fprintf(stderr, "Assert failed: %s:%d: %s\n", \
		    __FILE__, __LINE__, #x);                 \
	abort();              \
      }                \
  } while(0)

/************** RSA单元测试用 **************/
namespace rsa_ut {
    void test_rsa_set_key_1(struct rsa_public_key *pub,
                            struct rsa_private_key *key);

    void test_rsa_md5(struct rsa_public_key *pub,
                      struct rsa_private_key *key,
                      mpz_t expected);

    void test_rsa_sha1(struct rsa_public_key *pub,
                       struct rsa_private_key *key,
                       mpz_t expected);

    void test_rsa_sha256(struct rsa_public_key *pub,
                         struct rsa_private_key *key,
                         mpz_t expected);

    void test_rsa_sha512(struct rsa_public_key *pub,
                         struct rsa_private_key *key,
                         mpz_t expected);
}

