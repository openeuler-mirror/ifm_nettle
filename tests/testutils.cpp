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
#include <nettle/base16.h>
#include <nettle/sha1.h>
#include <nettle/knuth-lfib.h>

#include "rsa_meta.h"
#include "rsa.h"
#include "md5_meta.h"
#include "md5.h"
#include "sha2_meta.h"
#include "sha2.h"
#include "testutils.h"

#define md5_ctx ifm_md5_ctx
#define sha256_ctx ifm_sha256_ctx
#define sha512_ctx ifm_sha512_ctx
#define rsa_public_key ifm_rsa_public_key
#define rsa_private_key ifm_rsa_private_key

void *
xalloc(size_t size)
{
  void *p = malloc(size);
  if (size && !p)
   
{
      fprintf(stderr, "Virtual memory exhausted.\n");
      abort();
    }

  return p;
}

static struct tstring *tstring_first = NULL;

struct tstring *
tstring_alloc (size_t length)
{
  struct tstring *s = (struct tstring *)xalloc(sizeof(struct tstring) + length);
  s->length = length;
  s->next = tstring_first;
  /* NUL-terminate, for convenience. */
  s->data[length] = '\0';
  tstring_first = s;
  return s;
}

void
tstring_clear(void)
{
  while (tstring_first)
   
{
      struct tstring *s = tstring_first;
      tstring_first = s->next;
      free(s);
    }
}

struct tstring *
tstring_data(size_t length, const uint8_t *data)
{
  struct tstring *s = tstring_alloc (length);
  memcpy (s->data, data, length);
  return s;
}

struct tstring *
tstring_hex(const char *hex)
{
  struct base16_decode_ctx ctx;
  struct tstring *s;
  size_t length = strlen(hex);

  s = tstring_alloc(BASE16_DECODE_LENGTH (length));
  base16_decode_init (&ctx);
  ASSERT (base16_decode_update (&ctx, &s->length, s->data,
				length, hex));
  ASSERT (base16_decode_final (&ctx));

  return s;
}

void
tstring_print_hex(const struct tstring *s)
{
  print_hex (s->length, s->data);
}

void
print_hex(size_t length, const uint8_t *data)
{
  size_t i;
  
  for (i = 0; i < length; i++)
   
{
      switch (i % 16)
	{
	default:
	  break;
	case 0:
	  printf("\n");
	  break;
	case 8:
	  printf(" ");
	  break;
	}
      printf("%02x", data[i]);
    }
  printf("\n");
}


void test_hash(const struct nettle_hash *hash,
	  const struct tstring *msg,
	  const struct tstring *digest)
{
  void *ctx = xalloc(hash->context_size);
  uint8_t *buffer = (uint8_t *)xalloc(digest->length);
  uint8_t *input;
  unsigned offset;

  /* Here, hash->digest_size zero means arbitrary size. */
  if (hash->digest_size)
    ASSERT (digest->length == hash->digest_size);

  hash->init(ctx);
  hash->update(ctx, msg->length, msg->data);
  hash->digest(ctx, digest->length, buffer);

  if (MEMEQ(digest->length, digest->data, buffer) == 0)
   
{
      fprintf(stdout, "\nGot:\n");
      print_hex(digest->length, buffer);
      fprintf(stdout, "\nExpected:\n");
      print_hex(digest->length, digest->data);
      abort();
    }

  memset(buffer, 0, digest->length);

  hash->update(ctx, msg->length, msg->data);
  ASSERT(digest->length > 0);
  hash->digest(ctx, digest->length - 1, buffer);

  ASSERT(MEMEQ(digest->length - 1, digest->data, buffer));

  ASSERT(buffer[digest->length - 1] == 0);

  input = (uint8_t *)xalloc (msg->length + 16);
  for (offset = 0; offset < 16; offset++)
   
{
      memset (input, 0, msg->length + 16);
      memcpy (input + offset, msg->data, msg->length);
      hash->update (ctx, msg->length, input + offset);
      hash->digest (ctx, digest->length, buffer);
      if (MEMEQ(digest->length, digest->data, buffer) == 0)
	{
	  fprintf(stdout, "hash input address: %p\nGot:\n", input + offset);
	  print_hex(digest->length, buffer);
	  fprintf(stdout, "\nExpected:\n");
	  print_hex(digest->length, digest->data);
	  abort();
	}      
    }
  free(ctx);
  free(buffer);
  free(input);
}

/************** RSA单元测试用 **************/
/* Expects local variables pub, key, rstate, digest, signature */
#define SIGN(hash, msg, expected) do { \
    hash##_update(&hash, LDATA(msg));  \
    ASSERT(rsa_##hash##_sign(key, &hash, signature));    \
    fprintf(stderr, "rsa-%s signature: ", #hash);        \
        mpz_out_str(stderr, 16, signature);              \
        fprintf(stderr, "\n");         \
    ASSERT(mpz_cmp (signature, expected) == 0);          \
                                       \
    hash##_update(&hash, LDATA(msg));  \
    ASSERT(rsa_##hash##_sign_tr(pub, key, &rstate,       \
                  (nettle_random_func *) knuth_lfib_random, \
                  &hash, signature));  \
    ASSERT(mpz_cmp (signature, expected) == 0);          \
                                       \
    hash##_update(&hash, LDATA(msg));  \
    hash##_digest(&hash, sizeof(digest), digest);        \
    ASSERT(rsa_##hash##_sign_digest(key, digest, signature)); \
    ASSERT(mpz_cmp (signature, expected) == 0);          \
                                       \
    ASSERT(rsa_##hash##_sign_digest_tr(pub, key, &rstate,     \
                     (nettle_random_func *)knuth_lfib_random, \
                     digest, signature));                \
    ASSERT(mpz_cmp (signature, expected) == 0);          \
}while (0)

#define VERIFY(key, hash, msg, signature) ( \
    hash##_update(&hash, LDATA(msg)),       \
    rsa_##hash##_verify(key, &hash, signature) \
)

namespace rsa_ut {
    void test_rsa_set_key_1(struct rsa_public_key *pub,
                            struct rsa_private_key *key)
    {
        mpz_set_str(pub->n,
                    "69abd505285af665" "36ddc7c8f027e6f0" "ed435d6748b16088"
                    "4fd60842b3a8d7fb" "bd8a3c98f0cc50ae" "4f6a9f7dd73122cc"
                    "ec8afa3f77134406" "f53721973115fc2d" "8cfbba23b145f28d"
                    "84f81d3b6ae8ce1e" "2850580c026e809b" "cfbb52566ea3a3b3"
                    "df7edf52971872a7" "e35c1451b8636d22" "279a8fb299368238"
                    "e545fbb4cf", 16);
        mpz_set_str(pub->e, "0db2ad57", 16);

        ASSERT (rsa_public_key_prepare(pub));

        mpz_set_str(key->p,
                    "0a66399919be4b4d" "e5a78c5ea5c85bf9" "aba8c013cb4a8732"
                    "14557a12bd67711e" "bb4073fd39ad9a86" "f4e80253ad809e5b"
                    "f2fad3bc37f6f013" "273c9552c9f489", 16);

        mpz_set_str(key->q,
                    "0a294f069f118625" "f5eae2538db9338c" "776a298eae953329"
                    "9fd1eed4eba04e82" "b2593bc98ba8db27" "de034da7daaea795"
                    "2d55b07b5f9a5875" "d1ca5f6dcab897", 16);

        mpz_set_str(key->a,
                    "011b6c48eb592eee" "e85d1bb35cfb6e07" "344ea0b5e5f03a28"
                    "5b405396cbc78c5c" "868e961db160ba8d" "4b984250930cf79a"
                    "1bf8a9f28963de53" "128aa7d690eb87", 16);

        mpz_set_str(key->b,
                    "0409ecf3d2557c88" "214f1af5e1f17853" "d8b2d63782fa5628"
                    "60cf579b0833b7ff" "5c0529f2a97c6452" "2fa1a8878a9635ab"
                    "ce56debf431bdec2" "70b308fa5bf387", 16);

        mpz_set_str(key->c,
                    "04e103ee925cb5e6" "6653949fa5e1a462" "c9e65e1adcd60058"
                    "e2df9607cee95fa8" "daec7a389a7d9afc" "8dd21fef9d83805a"
                    "40d46f49676a2f6b" "2926f70c572c00", 16);

        ASSERT (rsa_private_key_prepare(key));
        ASSERT (pub->size == key->size);
    }

    void test_rsa_md5(struct rsa_public_key *pub,
                      struct rsa_private_key *key,
                      mpz_t expected)
    {
        md5_ctx md5;
        knuth_lfib_ctx rstate;
        uint8_t digest[MD5_DIGEST_SIZE];
        mpz_t signature;

        md5_init(&md5);
        mpz_init(signature);
        knuth_lfib_init(&rstate, 15);

        SIGN(md5, "The magic words are squeamish ossifrage", expected);

        /* Try bad data */
        ASSERT (!VERIFY(pub, md5,
                        "The magick words are squeamish ossifrage", signature));

        /* Try correct data */
        ASSERT (VERIFY(pub, md5,
                       "The magic words are squeamish ossifrage", signature));

        /* Try bad signature */
        mpz_combit(signature, 17);
        ASSERT (!VERIFY(pub, md5,
                        "The magic words are squeamish ossifrage", signature));

        mpz_clear(signature);
    }

    void test_rsa_sha1(struct rsa_public_key *pub,
                       struct rsa_private_key *key,
                       mpz_t expected)
    {
        sha1_ctx sha1;
        knuth_lfib_ctx rstate;
        uint8_t digest[SHA1_DIGEST_SIZE];
        mpz_t signature;

        sha1_init(&sha1);
        mpz_init(signature);
        knuth_lfib_init(&rstate, 16);

        SIGN(sha1, "The magic words are squeamish ossifrage", expected);

        /* Try bad data */
        ASSERT (!VERIFY(pub, sha1,
                        "The magick words are squeamish ossifrage", signature));

        /* Try correct data */
        ASSERT (VERIFY(pub, sha1,
                       "The magic words are squeamish ossifrage", signature));

        /* Try bad signature */
        mpz_combit(signature, 17);
        ASSERT (!VERIFY(pub, sha1,
                        "The magic words are squeamish ossifrage", signature));

        mpz_clear(signature);
    }

    void test_rsa_sha256(struct rsa_public_key *pub,
                         struct rsa_private_key *key,
                         mpz_t expected)
    {
        sha256_ctx sha256;
        knuth_lfib_ctx rstate;
        uint8_t digest[SHA256_DIGEST_SIZE];
        mpz_t signature;

        sha256_init(&sha256);
        mpz_init(signature);
        knuth_lfib_init(&rstate, 17);

        SIGN(sha256, "The magic words are squeamish ossifrage", expected);

        /* Try bad data */
        ASSERT (!VERIFY(pub, sha256,
                        "The magick words are squeamish ossifrage", signature));

        /* Try correct data */
        ASSERT (VERIFY(pub, sha256,
                       "The magic words are squeamish ossifrage", signature));

        /* Try bad signature */
        mpz_combit(signature, 17);
        ASSERT (!VERIFY(pub, sha256,
                        "The magic words are squeamish ossifrage", signature));

        mpz_clear(signature);
    }

    void test_rsa_sha512(struct rsa_public_key *pub,
                         struct rsa_private_key *key,
                         mpz_t expected)
    {
        sha512_ctx sha512;
        knuth_lfib_ctx rstate;
        uint8_t digest[SHA512_DIGEST_SIZE];
        mpz_t signature;

        sha512_init(&sha512);
        mpz_init(signature);
        knuth_lfib_init(&rstate, 18);

        SIGN(sha512, "The magic words are squeamish ossifrage", expected);

        /* Try bad data */
        ASSERT (!VERIFY(pub, sha512,
                        "The magick words are squeamish ossifrage", signature));

        /* Try correct data */
        ASSERT (VERIFY(pub, sha512,
                       "The magic words are squeamish ossifrage", signature));

        /* Try bad signature */
        mpz_combit(signature, 17);
        ASSERT (!VERIFY(pub, sha512,
                        "The magic words are squeamish ossifrage", signature));

        mpz_clear(signature);
    }
}

#undef SIGN
#undef VERIFY
