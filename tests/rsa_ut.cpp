/* rsa_ut.cpp

   Copyright (C) 2002, 2010 Niels Möller

   This file is modified from nettle/rsa-test.c.
   Following 8 test cases are extracted from test_main().

   nettle/rsa-test.c is part of GNU Nettle.

   GNU Nettle is free software: you can redistribute it and/or
   modify it under the terms of either:

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.

   or both in parallel, as here.

   GNU Nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
*/
#include <gtest/gtest.h>
#include <nettle/md5.h>
#include <nettle/sha1.h>
#include <nettle/sha2.h>
#include <nettle/knuth-lfib.h>

#include "rsa_meta.h"
#include "rsa.h"
#include "testutils.h"

#define rsa_public_key ifm_rsa_public_key
#define rsa_private_key ifm_rsa_private_key

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

static void test_rsa_set_key_1(struct rsa_public_key *pub,
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

static void test_rsa_md5(struct rsa_public_key *pub,
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

static void test_rsa_sha1(struct rsa_public_key *pub,
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

static void test_rsa_sha256(struct rsa_public_key *pub,
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

static void test_rsa_sha512(struct rsa_public_key *pub,
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

#undef SIGN
#undef VERIFY

static void ut_rsa_md5_1()
{
    rsa_public_key pub;
    rsa_private_key key;

    mpz_t expected;

    mpz_init(expected);

    rsa_private_key_init(&key);
    rsa_public_key_init(&pub);

    test_rsa_set_key_1(&pub, &key);

    /* Test md5 signatures */
    mpz_set_str(expected,
                "53bf517009fa956e" "3daa6adc95e8663d" "3759002f488bbbad"
                "e49f62792d85dbcc" "293f68e2b68ef89a" "c5bd42d98f845325"
                "3e6c1b76fc337db5" "e0053f255c55faf3" "eb6cc568ad7f5013"
                "5b269a64acb9eaa7" "b7f09d9bd90310e6" "4c58f6dbe673ada2"
                "67c97a9d99e19f9d" "87960d9ce3f0d5ce" "84f401fe7e10fa24"
                "28b9bffcf9", 16);

    test_rsa_md5(&pub, &key, expected);

    rsa_private_key_clear(&key);
    rsa_public_key_clear(&pub);
    mpz_clear(expected);
}

static void ut_rsa_sha1_1()
{
    rsa_public_key pub;
    rsa_private_key key;

    mpz_t expected;

    mpz_init(expected);

    rsa_private_key_init(&key);
    rsa_public_key_init(&pub);

    test_rsa_set_key_1(&pub, &key);

    /* Test sha1 signature */
    mpz_set_str(expected,
                "129b405ed85db88c" "55d35344c4b52854" "496516b4d63d8211"
                "80a0c24d6ced9047" "33065a564bbd33d0" "a5cdfd204b9c6d15"
                "78337207c2f1662d" "c73906c7a0f2bf5c" "af92cef9121957b1"
                "dcb111ff47b92389" "888e384d0cfd1b1e" "e5d7003a8feff3fd"
                "dd6a71d242a79272" "25234d67ba369441" "c12ae555c697754e"
                "a17f93fa92", 16);

    test_rsa_sha1(&pub, &key, expected);

    rsa_private_key_clear(&key);
    rsa_public_key_clear(&pub);
    mpz_clear(expected);
}

static void ut_rsa_sha256_1()
{
    rsa_public_key pub;
    rsa_private_key key;

    mpz_t expected;

    mpz_init(expected);

    rsa_private_key_init(&key);
    rsa_public_key_init(&pub);

    test_rsa_set_key_1(&pub, &key);

    mpz_set_str(expected,
                "13f9e43f7a401a73" "0a74985c01520d76" "bf5f2e2dff91e93b"
                "9267d8c388d6937b" "d4bc6f1fa31618a9" "b5e3a1a875af72f5"
                "0e805dbfebdf4348" "7d49763f0b365e78" "d2c0ea8fb3785897"
                "782289a58f998907" "248c9cdf2c643d7e" "6ba6b55026227773"
                "6f19caa69c4fc6d7" "7e2e5d4cd6b7a82b" "900d201ffd000448"
                "685e5a4f3e", 16);

    test_rsa_sha256(&pub, &key, expected);

    rsa_private_key_clear(&key);
    rsa_public_key_clear(&pub);
    mpz_clear(expected);
}

static void ut_rsa_sha512_1()
{
    rsa_public_key pub;
    rsa_private_key key;

    mpz_t expected;

    mpz_init(expected);

    rsa_private_key_init(&key);
    rsa_public_key_init(&pub);

    test_rsa_set_key_1(&pub, &key);

    mpz_set_str(expected,
                "06327f717f43bcf3" "5994e567e8241963" "8c22e1057a7771e7"
                "a665bb7441a39cc8" "7762f6b1a459cae3" "281462ed3f6aec48"
                "15c2365797a02af6" "8a603adf276c46f6" "e6afb25d07c57f47"
                "c516aff84abda629" "cc83d9364eb3616d" "7d4ddf0e9a25fac5"
                "7d56a252b0cb7b1f" "8266b525e9b893af" "116e7845c0969a9f"
                "603e2543f3", 16);

    test_rsa_sha512(&pub, &key, expected);

    rsa_private_key_clear(&key);
    rsa_public_key_clear(&pub);
    mpz_clear(expected);
}

/* Test detection of invalid keys with even modulo */
static void ut_rsa_md5_2()
{
    rsa_public_key pub;
    rsa_private_key key;

    mpz_t expected;

    mpz_init(expected);

    rsa_private_key_init(&key);
    rsa_public_key_init(&pub);

    mpz_clrbit (pub.n, 0);
    ASSERT (!rsa_public_key_prepare (&pub));

    mpz_clrbit (key.p, 0);
    ASSERT (!rsa_private_key_prepare (&key));

    mpz_set_str(pub.n,
                "013b04440e3eef25" "d51c738d508a7fa8" "b3445180c342af0f"
                "4cb5a789047300e2" "cfc5c5450974cfc2" "448aeaaa7f43c374"
                "c9a3b038b181f2d1" "0f1a2327fd2c087b" "a49bf1086969fd2c"
                "d1df3fd69f81fa4b" "162cc8bbb363fc95" "b7b24b9c53d0c67e"
                "f52b", 16);

    mpz_set_str(pub.e, "3f1a012d", 16);

    ASSERT (rsa_public_key_prepare(&pub));

    mpz_set_str(key.p,
                "0b73c990eeda0a2a" "2c26416052c85560" "0c5c0f5ce86a8326"
                "166acea91786237a" "7ff884e66dbfdd3a" "ab9d9801414c1506"
                "8b", 16);

    mpz_set_str(key.q,
                "1b81c19a62802a41" "9c99283331b0badb" "08eb0c25ffce0fbf"
                "50017850036f32f3" "2132a845b91a5236" "61f7b451d587383f"
                "e1", 16);

    mpz_set_str(key.a,
                "0a912fc93a6cca6b" "3521725a3065b3be" "3c9745e29c93303d"
                "7d29316c6cafa4a2" "89945f964fcdea59" "1f9d248b0b6734be"
                "c9", 16);

    mpz_set_str(key.b,
                "1658eca933251813" "1eb19c77aba13d73" "e0b8f4ce986d7615"
                "764c6b0b03c18146" "46b7f332c43e05c5" "351e09006979ca5b"
                "05", 16);

    mpz_set_str(key.c,
                "0114720dace7b27f" "2bf2850c1804869f" "79a0aad0ec02e6b4"
                "05e1831619db2f10" "bb9b6a8fd5c95df2" "eb78f303ea0c0cc8"
                "06", 16);

    ASSERT (rsa_private_key_prepare(&key));
    ASSERT (pub.size == key.size);

    /* Test md5 signatures */
    mpz_set_str(expected,
                "011b939f6fbacf7f" "7d3217b022d07477" "e582e34d4bbddd4c"
                "31520647417fc8a6" "18b2e196d799cedd" "d8f5c062fd796b0f"
                "72ab46db2ac6ec74" "39d856be3f746cc4" "3e0a15429954736a"
                "60a8b3c6ea93d2cb" "c69085c307d72517" "07d43bf97a3b51eb"
                "9e89", 16);

    test_rsa_md5(&pub, &key, expected);

    rsa_private_key_clear(&key);
    rsa_public_key_clear(&pub);
    mpz_clear(expected);
}

static void ut_rsa_sha1_2()
{
    rsa_public_key pub;
    rsa_private_key key;

    mpz_t expected;

    mpz_init(expected);

    rsa_private_key_init(&key);
    rsa_public_key_init(&pub);

    mpz_clrbit (pub.n, 0);
    ASSERT (!rsa_public_key_prepare (&pub));

    mpz_clrbit (key.p, 0);
    ASSERT (!rsa_private_key_prepare (&key));

    mpz_set_str(pub.n,
                "013b04440e3eef25" "d51c738d508a7fa8" "b3445180c342af0f"
                "4cb5a789047300e2" "cfc5c5450974cfc2" "448aeaaa7f43c374"
                "c9a3b038b181f2d1" "0f1a2327fd2c087b" "a49bf1086969fd2c"
                "d1df3fd69f81fa4b" "162cc8bbb363fc95" "b7b24b9c53d0c67e"
                "f52b", 16);

    mpz_set_str(pub.e, "3f1a012d", 16);

    ASSERT (rsa_public_key_prepare(&pub));

    mpz_set_str(key.p,
                "0b73c990eeda0a2a" "2c26416052c85560" "0c5c0f5ce86a8326"
                "166acea91786237a" "7ff884e66dbfdd3a" "ab9d9801414c1506"
                "8b", 16);

    mpz_set_str(key.q,
                "1b81c19a62802a41" "9c99283331b0badb" "08eb0c25ffce0fbf"
                "50017850036f32f3" "2132a845b91a5236" "61f7b451d587383f"
                "e1", 16);

    mpz_set_str(key.a,
                "0a912fc93a6cca6b" "3521725a3065b3be" "3c9745e29c93303d"
                "7d29316c6cafa4a2" "89945f964fcdea59" "1f9d248b0b6734be"
                "c9", 16);

    mpz_set_str(key.b,
                "1658eca933251813" "1eb19c77aba13d73" "e0b8f4ce986d7615"
                "764c6b0b03c18146" "46b7f332c43e05c5" "351e09006979ca5b"
                "05", 16);

    mpz_set_str(key.c,
                "0114720dace7b27f" "2bf2850c1804869f" "79a0aad0ec02e6b4"
                "05e1831619db2f10" "bb9b6a8fd5c95df2" "eb78f303ea0c0cc8"
                "06", 16);

    ASSERT (rsa_private_key_prepare(&key));
    ASSERT (pub.size == key.size);

    /* Test sha1 signature */
    mpz_set_str(expected,
                "648c49e0ed045547" "08381d0bcd03b7bd" "b0f80a0e9030525d"
                "234327a1c96b8660" "f1c01c6f15ae76d0" "4f53a53806b7e4db"
                "1f789e6e89b538f6" "88fcbd2caa6abef0" "5432d52f3de463a4"
                "a9e6de94f1b7bb68" "3c07edf0924fc93f" "56e1a0dba8f7491c"
                "5c", 16);

    test_rsa_sha1(&pub, &key, expected);

    rsa_private_key_clear(&key);
    rsa_public_key_clear(&pub);
    mpz_clear(expected);
}

static void ut_rsa_sha256_2()
{
    rsa_public_key pub;
    rsa_private_key key;

    mpz_t expected;

    mpz_init(expected);

    rsa_private_key_init(&key);
    rsa_public_key_init(&pub);

    mpz_clrbit (pub.n, 0);
    ASSERT (!rsa_public_key_prepare (&pub));

    mpz_clrbit (key.p, 0);
    ASSERT (!rsa_private_key_prepare (&key));

    mpz_set_str(pub.n,
                "013b04440e3eef25" "d51c738d508a7fa8" "b3445180c342af0f"
                "4cb5a789047300e2" "cfc5c5450974cfc2" "448aeaaa7f43c374"
                "c9a3b038b181f2d1" "0f1a2327fd2c087b" "a49bf1086969fd2c"
                "d1df3fd69f81fa4b" "162cc8bbb363fc95" "b7b24b9c53d0c67e"
                "f52b", 16);

    mpz_set_str(pub.e, "3f1a012d", 16);

    ASSERT (rsa_public_key_prepare(&pub));

    mpz_set_str(key.p,
                "0b73c990eeda0a2a" "2c26416052c85560" "0c5c0f5ce86a8326"
                "166acea91786237a" "7ff884e66dbfdd3a" "ab9d9801414c1506"
                "8b", 16);

    mpz_set_str(key.q,
                "1b81c19a62802a41" "9c99283331b0badb" "08eb0c25ffce0fbf"
                "50017850036f32f3" "2132a845b91a5236" "61f7b451d587383f"
                "e1", 16);

    mpz_set_str(key.a,
                "0a912fc93a6cca6b" "3521725a3065b3be" "3c9745e29c93303d"
                "7d29316c6cafa4a2" "89945f964fcdea59" "1f9d248b0b6734be"
                "c9", 16);

    mpz_set_str(key.b,
                "1658eca933251813" "1eb19c77aba13d73" "e0b8f4ce986d7615"
                "764c6b0b03c18146" "46b7f332c43e05c5" "351e09006979ca5b"
                "05", 16);

    mpz_set_str(key.c,
                "0114720dace7b27f" "2bf2850c1804869f" "79a0aad0ec02e6b4"
                "05e1831619db2f10" "bb9b6a8fd5c95df2" "eb78f303ea0c0cc8"
                "06", 16);

    ASSERT (rsa_private_key_prepare(&key));
    ASSERT (pub.size == key.size);

    mpz_set_str(expected,
                "d759bb28b4d249a2" "f8b67bdbb1ab7f50" "c88712fbcabc2956"
                "1ec6ca3f8fdafe7a" "38433d7da287b8f7" "87857274c1640b2b"
                "e652cd89c501d570" "3980a0af5c6bb60c" "f84feab25b099d06"
                "e2519accb73dac43" "fb8bdad28835f3bd" "84c43678fe2ef41f"
                "af", 16);

    test_rsa_sha256(&pub, &key, expected);

    rsa_private_key_clear(&key);
    rsa_public_key_clear(&pub);
    mpz_clear(expected);
}

static void ut_rsa_sha512_2()
{
    rsa_public_key pub;
    rsa_private_key key;

    mpz_t expected;

    mpz_init(expected);

    rsa_private_key_init(&key);
    rsa_public_key_init(&pub);

    mpz_clrbit (pub.n, 0);
    ASSERT (!rsa_public_key_prepare (&pub));

    mpz_clrbit (key.p, 0);
    ASSERT (!rsa_private_key_prepare (&key));

    mpz_set_str(pub.n,
                "013b04440e3eef25" "d51c738d508a7fa8" "b3445180c342af0f"
                "4cb5a789047300e2" "cfc5c5450974cfc2" "448aeaaa7f43c374"
                "c9a3b038b181f2d1" "0f1a2327fd2c087b" "a49bf1086969fd2c"
                "d1df3fd69f81fa4b" "162cc8bbb363fc95" "b7b24b9c53d0c67e"
                "f52b", 16);

    mpz_set_str(pub.e, "3f1a012d", 16);

    ASSERT (rsa_public_key_prepare(&pub));

    mpz_set_str(key.p,
                "0b73c990eeda0a2a" "2c26416052c85560" "0c5c0f5ce86a8326"
                "166acea91786237a" "7ff884e66dbfdd3a" "ab9d9801414c1506"
                "8b", 16);

    mpz_set_str(key.q,
                "1b81c19a62802a41" "9c99283331b0badb" "08eb0c25ffce0fbf"
                "50017850036f32f3" "2132a845b91a5236" "61f7b451d587383f"
                "e1", 16);

    mpz_set_str(key.a,
                "0a912fc93a6cca6b" "3521725a3065b3be" "3c9745e29c93303d"
                "7d29316c6cafa4a2" "89945f964fcdea59" "1f9d248b0b6734be"
                "c9", 16);

    mpz_set_str(key.b,
                "1658eca933251813" "1eb19c77aba13d73" "e0b8f4ce986d7615"
                "764c6b0b03c18146" "46b7f332c43e05c5" "351e09006979ca5b"
                "05", 16);

    mpz_set_str(key.c,
                "0114720dace7b27f" "2bf2850c1804869f" "79a0aad0ec02e6b4"
                "05e1831619db2f10" "bb9b6a8fd5c95df2" "eb78f303ea0c0cc8"
                "06", 16);

    ASSERT (rsa_private_key_prepare(&key));
    ASSERT (pub.size == key.size);

    mpz_set_str(expected,
                "f761aae6273d6149" "06d8c208fb2897ca" "d798a46af4985b86"
                "51d51e6a3e11cbe0" "84f18ba8979c0f54" "11493f7c6e770560"
                "03db2146b4dbcaa6" "4aae2e02aab9ff7b" "1ddf77dc72145cf1"
                "c26ebde7c708cdc1" "62e167a7ac33967b" "386a40ea4a988d17"
                "47", 16);

    test_rsa_sha512(&pub, &key, expected);

    rsa_private_key_clear(&key);
    rsa_public_key_clear(&pub);
    mpz_clear(expected);
}

TEST(rsa_testcases, test_rsa_md5_1)
{
ut_rsa_md5_1();
}

TEST(rsa_testcases, test_rsa_sha1_1)
{
ut_rsa_sha1_1();
}

TEST(rsa_testcases, test_rsa_sha256_1)
{
ut_rsa_sha256_1();
}

TEST(rsa_testcases, test_rsa_sha512_1)
{
ut_rsa_sha512_1();
}

/* Test detection of invalid keys with even modulo */
TEST(rsa_testcases, test_rsa_md5_2)
{
ut_rsa_md5_2();
}

TEST(rsa_testcases, test_rsa_sha1_2)
{
ut_rsa_sha1_2();
}

TEST(rsa_testcases, test_rsa_sha256_2)
{
ut_rsa_sha256_2();
}

TEST(rsa_testcases, test_rsa_sha512_2)
{
ut_rsa_sha512_2();
}

