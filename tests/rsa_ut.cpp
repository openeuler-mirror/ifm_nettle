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
#include <nettle/sha1.h>
#include <nettle/knuth-lfib.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include "rsa.h"
#include "testutils.h"
#include "sha2.h"
#include "md5.h"
#include "ifm_utils.h"
#include "stub/stub.h"

#define rsa_public_key ifm_rsa_public_key
#define rsa_private_key ifm_rsa_private_key
#define md5_ctx ifm_md5_ctx
#define sha256_ctx ifm_sha256_ctx
#define sha512_ctx ifm_sha512_ctx

/* Expects local variables pub, key, rstate, digest, signature */
#define SIGN(hash, msg, expected) do { \
    hash##_update(&hash, LDATA(msg));  \
    ASSERT(rsa_##hash##_sign(key, &hash, signature));    \
    fprintf(stderr, "rsa-%s signature: ", #hash);        \
        mpz_out_str(stderr, 16, signature);              \
        fprintf(stderr, "\n");         \
    ASSERT(mpz_cmp (signature, expected) == 0);          \
    fprintf(stderr, "rsa_sign_pass\n");                  \
}while (0)

#define SIGN_DIGEST(hash, msg, expected) do { \
    hash##_update(&hash, LDATA(msg));  \
    hash##_digest(&hash, sizeof(digest), digest);        \
    ASSERT(rsa_##hash##_sign_digest(key, digest, signature)); \
    fprintf(stderr, "rsa-%s signature: ", #hash);        \
        mpz_out_str(stderr, 16, signature);              \
        fprintf(stderr, "\n");         \
    ASSERT(mpz_cmp (signature, expected) == 0);          \
    fprintf(stderr, "rsa_sign_digest_pass\n");        \
}while (0)

#define VERIFY(key, hash, msg, signature) ( \
    hash##_update(&hash, LDATA(msg)),       \
    rsa_##hash##_verify(key, &hash, signature), \
    hash##_update(&hash, LDATA(msg)),       \
    hash##_digest(&hash, sizeof(digest), digest),        \
    rsa_##hash##_verify_digest(key, digest, signature)   \
)

static void test_rsa_set_key_1(struct rsa_public_key *pub,
                               struct rsa_private_key *key)
{
    mpz_set_str(pub->n,
            "9eeebbeba0d3abac" "f97b9229d66ec86b"
            "688ffd092aba33d4" "1496744de5ced947"
            "31d5a4a359ae2fc3" "992a58062800fcf2"
            "efb55c6df53b71ee" "b1278e0968c77bf7"
            "76dbdb464086a078" "6778caeb322fc412"
            "3decd5878f1e050e" "2f79080a3785bec0"
            "aaf67b243bf9b21c" "ee359807d3cf280f"
            "4b1025a90d7cb4c8" "d1f63a632692a853", 16);
    mpz_set_str(pub->e, "010001", 16);

    ASSERT (rsa_public_key_prepare(pub));

    mpz_set_str(key->p,
            "cdf1e1ffd77d8e3c" "13a218b61d74367b"
            "f79da4ea8c4545f7" "c0ea9a3d1567b62a"
            "8cfb64cc1d6addd3" "4737c8a7606f5bf8"
            "909900d552895ae7" "a2669f7b495ce757", 16);

    mpz_set_str(key->q,
            "C58fb19f71dcd544" "aa927fb9b0f6eadd"
            "508fdfced9057835" "8aa98d22b3015c08"
            "fd57961f34eaa4da" "340a3900f4afb0ba"
            "56da24995bd7a496" "b8d31e544510d565", 16);

    mpz_set_str(key->a,
            "7a3be0b9ab3b185a" "cc045fca67bcfc41"
            "a3fc6b4fd325a29b" "a4631a5cbb01ad7b"
            "9fe5ee33c01a17c3" "38f8011e66fc7188"
            "1cbad365c9f14085" "4f3cbdd7bcf9694d", 16);

    mpz_set_str(key->b,
            "07c4b3b65252ddab" "fa8d122aaa13bb7e"
            "825975f27b4424ca" "ee2de697d3b41cfb"
            "5982e52b4af8630d" "1578c56f0d300f61"
            "f4625588163d6f82" "61b8237c2acf13a5", 16);

    mpz_set_str(key->c,
            "2a08700c27d87396" "1b9763952b6bcb33"
            "5effe08e5975d273" "fef3f081173809ed"
            "f321d120093a9799" "4b1d1cc14eb9f07c"
            "06080e93656483d2" "34a2a76204807299", 16);

    ASSERT (rsa_private_key_prepare(key));
    ASSERT (pub->size == key->size);
}

static void test_rsa_md5(struct rsa_public_key *pub,
                         struct rsa_private_key *key,
                         mpz_t expected_1, mpz_t expected_2, mpz_t expected_3)
{
    md5_ctx md5;
    knuth_lfib_ctx rstate;
    uint8_t digest[MD5_DIGEST_SIZE];
    mpz_t signature;

    md5_init(&md5);
    mpz_init(signature);
    knuth_lfib_init(&rstate, 15);

    SIGN(md5, "The magic words are squeamish ossifrage", expected_1);

    SIGN_DIGEST(md5, "The magic words are squeamish ossifrage", expected_1);

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

    SIGN(md5, "The magic words are squeamish ossifrage The magic words are squeamish ossifrage", expected_2);
    SIGN_DIGEST(md5, "The magic words are squeamish ossifrage The magic words are squeamish ossifrage", expected_2);
    ASSERT (VERIFY(pub, md5, "The magic words are squeamish ossifrage The magic words are squeamish ossifrage", signature));

    SIGN(md5, "abcdefghbcdefghicdefghijdefg"
		  "hijkefghijklfghijklmghijklmn"
		  "hijklmnoijklmnopjklmnopqklmn", expected_3);
    SIGN_DIGEST(md5, "abcdefghbcdefghicdefghijdefg"
		  "hijkefghijklfghijklmghijklmn"
		  "hijklmnoijklmnopjklmnopqklmn", expected_3);
    ASSERT (VERIFY(pub, md5, "abcdefghbcdefghicdefghijdefg"
		  "hijkefghijklfghijklmghijklmn"
		  "hijklmnoijklmnopjklmnopqklmn", signature));  

    mpz_clear(signature);
}

static void test_rsa_sha1(struct rsa_public_key *pub,
                          struct rsa_private_key *key,
                          mpz_t expected_1, mpz_t expected_2, mpz_t expected_3)
{
    sha1_ctx sha1;
    knuth_lfib_ctx rstate;
    uint8_t digest[SHA1_DIGEST_SIZE];
    mpz_t signature;

    sha1_init(&sha1);
    mpz_init(signature);
    knuth_lfib_init(&rstate, 16);

    SIGN(sha1, "The magic words are squeamish ossifrage", expected_1);

    SIGN_DIGEST(sha1, "The magic words are squeamish ossifrage", expected_1);

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

    SIGN(sha1, "The magic words are squeamish ossifrage The magic words are squeamish ossifrage", expected_2);
    SIGN_DIGEST(sha1, "The magic words are squeamish ossifrage The magic words are squeamish ossifrage", expected_2);
    ASSERT (VERIFY(pub, sha1, "The magic words are squeamish ossifrage The magic words are squeamish ossifrage", signature));

    SIGN(sha1, "abcdefghbcdefghicdefghijdefg"
		  "hijkefghijklfghijklmghijklmn"
		  "hijklmnoijklmnopjklmnopqklmn", expected_3);
    SIGN_DIGEST(sha1, "abcdefghbcdefghicdefghijdefg"
		  "hijkefghijklfghijklmghijklmn"
		  "hijklmnoijklmnopjklmnopqklmn", expected_3);
    ASSERT (VERIFY(pub, sha1, "abcdefghbcdefghicdefghijdefg"
		  "hijkefghijklfghijklmghijklmn"
		  "hijklmnoijklmnopjklmnopqklmn", signature));  
}

static void test_rsa_sha256(struct rsa_public_key *pub,
                            struct rsa_private_key *key,
                            mpz_t expected_1, mpz_t expected_2, mpz_t expected_3)
{
    sha256_ctx sha256;
    knuth_lfib_ctx rstate;
    uint8_t digest[SHA256_DIGEST_SIZE];
    mpz_t signature;

    sha256_init(&sha256);
    mpz_init(signature);
    knuth_lfib_init(&rstate, 17);

    SIGN(sha256, "The magic words are squeamish ossifrage", expected_1);

    SIGN_DIGEST(sha256, "The magic words are squeamish ossifrage", expected_1);

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

    SIGN(sha256, "The magic words are squeamish ossifrage The magic words are squeamish ossifrage", expected_2);
    SIGN_DIGEST(sha256, "The magic words are squeamish ossifrage The magic words are squeamish ossifrage", expected_2);
    ASSERT (VERIFY(pub, sha256, "The magic words are squeamish ossifrage The magic words are squeamish ossifrage", signature));

    SIGN(sha256, "abcdefghbcdefghicdefghijdefg"
		  "hijkefghijklfghijklmghijklmn"
		  "hijklmnoijklmnopjklmnopqklmn", expected_3);
    SIGN_DIGEST(sha256, "abcdefghbcdefghicdefghijdefg"
		  "hijkefghijklfghijklmghijklmn"
		  "hijklmnoijklmnopjklmnopqklmn", expected_3);
    ASSERT (VERIFY(pub, sha256, "abcdefghbcdefghicdefghijdefg"
		  "hijkefghijklfghijklmghijklmn"
		  "hijklmnoijklmnopjklmnopqklmn", signature));  
}

static void test_rsa_sha512(struct rsa_public_key *pub,
                            struct rsa_private_key *key,
                            mpz_t expected_1, mpz_t expected_2, mpz_t expected_3)
{
    sha512_ctx sha512;
    knuth_lfib_ctx rstate;
    uint8_t digest[SHA512_DIGEST_SIZE];
    mpz_t signature;

    sha512_init(&sha512);
    mpz_init(signature);
    knuth_lfib_init(&rstate, 18);

    SIGN(sha512, "The magic words are squeamish ossifrage", expected_1);

    SIGN_DIGEST(sha512, "The magic words are squeamish ossifrage", expected_1);

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

    SIGN(sha512, "The magic words are squeamish ossifrage The magic words are squeamish ossifrage", expected_2);
    SIGN_DIGEST(sha512, "The magic words are squeamish ossifrage The magic words are squeamish ossifrage", expected_2);
    ASSERT (VERIFY(pub, sha512, "The magic words are squeamish ossifrage The magic words are squeamish ossifrage", signature));

    SIGN(sha512, "abcdefghbcdefghicdefghijdefg"
		  "hijkefghijklfghijklmghijklmn"
		  "hijklmnoijklmnopjklmnopqklmn", expected_3);
    SIGN_DIGEST(sha512, "abcdefghbcdefghicdefghijdefg"
		  "hijkefghijklfghijklmghijklmn"
		  "hijklmnoijklmnopjklmnopqklmn", expected_3);
    ASSERT (VERIFY(pub, sha512, "abcdefghbcdefghicdefghijdefg"
		  "hijkefghijklfghijklmghijklmn"
		  "hijklmnoijklmnopjklmnopqklmn", signature));  
}

#undef SIGN
#undef VERIFY

static void ut_rsa_md5_1()
{
    rsa_public_key pub;
    rsa_private_key key;

    mpz_t expected_1, expected_2, expected_3;

    mpz_init(expected_1);
    mpz_init(expected_2);
    mpz_init(expected_3);

    rsa_private_key_init(&key);
    rsa_public_key_init(&pub);
    mpz_clrbit (pub.n, 0);
    ASSERT (!rsa_public_key_prepare (&pub));

    mpz_clrbit (key.p, 0);
    ASSERT (!rsa_private_key_prepare (&key));

    test_rsa_set_key_1(&pub, &key);

    /* Test md5 signatures */
    mpz_set_str(expected_1,
            "8305379796974b6d""1a0f208d4faa97ad"
            "68ca721de91ac27a""1a467aef81f9406d"
            "5b4a55a23b767cf5""7be0604650fde760"
            "248030996bb26ee4""c17afc004f8b57d9"
            "e8988012fde7ed9d""a8adc94654e4f9f2"
            "c036fb8fea641371""35ca60aeb4c3ac8d"
            "885ea035f986719e""85af7e70b3b0f7b5"
            "5a2cf7499cc9ff04""242d58fa5490bd29", 16);

    mpz_set_str(expected_2,
            "53c8b94073a1f642""5d8d9a453ba996d1"
            "4fe24651694fa749""edb3e4a3e400d331"
            "68e69fb15cdadaf2""f4d50962df502f35"
            "68a8d78150f873fd""46ffa01380d45590"
            "0806f9382e3a1137""361ee48ba7bb1ef3"
            "d4190f7ba640d083""dbbdce12c0a1b3d9"
            "22934dea7b63a900""5b03313e684b42b2"
            "a3b96529c467179a""c22418b7b4229701", 16);

    mpz_set_str(expected_3,
            "895b76adea176122""470b8835926a55fc"
            "4219521932f619a2""ed9363d99d243415"
            "6b71a654063d17a3""e9a4d9ca2854692d"
            "edd6c3e3a2e1134b""7506d2c2a2be46f1"
            "74ee26b5a3b4dba3""ef5de0f05f85aba9"
            "68a5b1fff3b0f701""1ab617993fc66e6a"
            "aad81ed9bda0e231""c49e04db52e93d7c"
            "15d910a98153002f""5101ca53e32b93e0", 16);

    test_rsa_md5(&pub, &key, expected_1, expected_2, expected_3);

    rsa_private_key_clear(&key);
    rsa_public_key_clear(&pub);
    mpz_clear(expected_1);
    mpz_clear(expected_2);
    mpz_clear(expected_3);
}

static void ut_rsa_sha1_1()
{
    rsa_public_key pub;
    rsa_private_key key;

    mpz_t expected_1, expected_2, expected_3;

    mpz_init(expected_1);
    mpz_init(expected_2);
    mpz_init(expected_3);

    rsa_private_key_init(&key);
    rsa_public_key_init(&pub);

    test_rsa_set_key_1(&pub, &key);

    /* Test sha1 signature */
    mpz_set_str(expected_1,
            "34fa98a17006d76e""4f410c0d3d9d8a23"
            "4d21bcf86b164011""213ec9547d7dbf11"
            "7d8ef2570e18fb49""18888fe2adfd0986"
            "c05d90b4799ffe53""8fde1feb290a34f5"
            "787bb6e39964d811""562c08b0847a6fbe"
            "919b5ca8e9c07ed2""eccd3b93265ce35a"
            "48010c07f9c35f01""80f6df22b8187b5b"
            "940a184c04484e00""ccf8a0fabe2c185c", 16);

    mpz_set_str(expected_2,
            "65fb67b5bccac272""a41ffb3ccdb32939"
            "7290fd62eb50c684""ab7afece8684ad36"
            "fed37942ac45b275""c5cd219214de7651"
            "bb6f221907dbf9d3""c52a45b52e630a62"
            "977edcecfce3d8f0""ecd4135a854b91aa"
            "cbf51cd9d6a5926e""4017965a582e0acb"
            "614040c4fe365939""4fa13a43f26214bc"
            "d4cfc5f94a22fcce""fee2bc3185a97be4", 16);

    mpz_set_str(expected_3,
            "78ed0b2363358f69""f8c77e1357739d48"
            "623343c4921861b4""c916cf18545dc804"
            "eb9c97c3f79b53b3""08b7330c63feb3c9"
            "39ecad2e7670c321""e805983ab1dd280e"
            "149125304c56e729""b225e48284296c5f"
            "4ff38ff1cbf034c9""90187dc769c4aaa4"
            "25479d9392635751""347a02a7f6828b0e"
            "1052b9f86da1729e""0a3bcf61ebada49a", 16);

    test_rsa_sha1(&pub, &key, expected_1, expected_2, expected_3);

    rsa_private_key_clear(&key);
    rsa_public_key_clear(&pub);
    mpz_clear(expected_1);
    mpz_clear(expected_2);
    mpz_clear(expected_3);
}

static void ut_rsa_sha256_1()
{
    rsa_public_key pub;
    rsa_private_key key;

    mpz_t expected_1, expected_2, expected_3;

    mpz_init(expected_1);
    mpz_init(expected_2);
    mpz_init(expected_3);

    rsa_private_key_init(&key);
    rsa_public_key_init(&pub);

    test_rsa_set_key_1(&pub, &key);

    mpz_set_str(expected_1,
            "518bf7a2444144db""9288c15d9346889d"
            "d2b05709965d0b5d""5569729b6a44d01e"
            "68936c12290bb8a7""af6d66c057d7a5c8"
            "a482a87487d780ce""377b41f1de84b61a"
            "75a31e8590982c7e""b31dd9bc735154c0"
            "54bdf24542bfab6d""6eec389fcfc5264c"
            "ea9ffc965b3046ab""c94cbb4142ba32cb"
            "47c5e9f101460c66""8be57f31cd14134d", 16);

    mpz_set_str(expected_2,
            "25297908eca0e43b""6e2fe7715cf137d5"
            "824ea37af19f6227""0afcd779dd0a9fa0"
            "a8dec6669289d572""788f23a9c14d32be"
            "937c0202db4bd72c""e9a26cd8c754bd6c"
            "2f9e98ba1c650db0""c79ff55a0039b211"
            "95d2f4cb878dd2c0""4f899f127abd474c"
            "c3849c4ff29a1a5b""fa441e2dfe25ef27"
            "92a0667127c8a18c""ff55805198604bd0", 16);

    mpz_set_str(expected_3,
            "54294971710d0f5c""ad2b8602341ec90d"
            "1b455d90e75ee5c3""b81f356eb1d21408"
            "f36bbdd731b9b0c6""7df4354c742372f0"
            "50dce6afd20f265a""6169fad7912ae0d7"
            "954fe802796b8901""07b0cc792f6acfb3"
            "5e1fe9df816601ca""22d5f8589753b51b"
            "df88f8094661e8d1""ccd5a3a076200251"
            "fcbf4aaf112883a5""cf69e5fc85dd6176", 16);

    test_rsa_sha256(&pub, &key, expected_1, expected_2, expected_3);

    rsa_private_key_clear(&key);
    rsa_public_key_clear(&pub);
    mpz_clear(expected_1);
    mpz_clear(expected_2);
    mpz_clear(expected_3);
}

static void ut_rsa_sha512_1()
{
    rsa_public_key pub;
    rsa_private_key key;

    mpz_t expected_1, expected_2, expected_3;

    mpz_init(expected_1);
    mpz_init(expected_2);
    mpz_init(expected_3);

    rsa_private_key_init(&key);
    rsa_public_key_init(&pub);

    test_rsa_set_key_1(&pub, &key);

    mpz_set_str(expected_1,
            "76b74f4789f71bc8""8ff68c4d976f4a08"
            "35efb956b9ffc3be""c8f5f17f83b04f96"
            "e8bc75a8b87606f2""9cde8d8eb95cec34"
            "9dd159b668d748d6""f1cff9ffa4ae3bcc"
            "a75d7417fc4b3b13""4ae801e2b89afec7"
            "8eea8d2dab426159""90cdad79d493952c"
            "a27fea12f8697011""f787573567031370"
            "c2f669c8c6d1ffab""80343b0d2ea9d336", 16);

    mpz_set_str(expected_2,
            "70d66b9a9ad79272""e756de442b610cc2"
            "00fb6a992b089c35""bc295ec82627cb1b"
            "86fe0d7466fb8f81""091b86e190273827"
            "b416859dba7b4292""cb905d3967a4e3d7"
            "8589ee374d2f7a1b""696c6b9cd0d681c5"
            "e7a1158aac42f648""080d7b9e1d57c628"
            "5888b2794e1ef048""268b36780969929e"
            "afac71788ffffc97""ca19b3b920835bd3", 16);

    mpz_set_str(expected_3,
            "720f92c0823e3efc""2897c9a2a28b45bc"
            "7205162ce8ed3712""781ac8b665e49bd5"
            "513987514cdd1f26""6f09ed9da02657af"
            "73e95027a0e70e82""f6a4a1ac32590b18"
            "6cff811a57f591ce""9bfe29ba6704083f"
            "f246ce8be910b9dc""36d0667f52ee1ca1"
            "6d41d75e8b5eb8a1""16ab5b3f16b3a91e"
            "4128c1e1875529ff""41312816d0ce7f32", 16);

    test_rsa_sha512(&pub, &key, expected_1, expected_2, expected_3);

    rsa_private_key_clear(&key);
    rsa_public_key_clear(&pub);
    mpz_clear(expected_1);
    mpz_clear(expected_2);
    mpz_clear(expected_3);
}

//rsa-keygen-test
static void test_rsa_key(struct rsa_public_key *pub, struct rsa_private_key *key)
{
    mpz_t tmp;
    mpz_t phi;

    mpz_init(tmp); mpz_init(phi);

    fprintf(stderr, "Public key: ");
    fprintf(stderr, "\n    n=");
    mpz_out_str(stderr, 16, pub->n);
    fprintf(stderr, "\n    e=");
    mpz_out_str(stderr, 16, pub->e);

    fprintf(stderr, "\n\nPrivate key: ");
    fprintf(stderr, "\n    p=");
    mpz_out_str(stderr, 16, key->p);
    fprintf(stderr, "\n    q=");
    mpz_out_str(stderr, 16, key->q);
    fprintf(stderr, "\n    a=");
    mpz_out_str(stderr, 16, key->a);
    fprintf(stderr, "\n    b=");
    mpz_out_str(stderr, 16, key->b);
    fprintf(stderr, "\n    c=");
    mpz_out_str(stderr, 16, key->c);
    fprintf(stderr, "\n\n");

    /* Check n = p q */
    mpz_mul(tmp, key->p, key->q);
    ASSERT (mpz_cmp(tmp, pub->n)== 0);

    /* Check c q = 1 mod p */
    mpz_mul(tmp, key->c, key->q);
    mpz_fdiv_r(tmp, tmp, key->p);
    ASSERT (mpz_cmp_ui(tmp, 1) == 0);

    /* Check a e = 1 (mod (p-1) ) */
    mpz_sub_ui(phi, key->p, 1);
    mpz_mul(tmp, pub->e, key->a);
    mpz_fdiv_r(tmp, tmp, phi);
    ASSERT (mpz_cmp_ui(tmp, 1) == 0);

    /* Check b e = 1 (mod (q-1) ) */
    mpz_sub_ui(phi, key->q, 1);
    mpz_mul(tmp, pub->e, key->b);
    mpz_fdiv_r(tmp, tmp, phi);
    ASSERT (mpz_cmp_ui(tmp, 1) == 0);

    mpz_clear(tmp); mpz_clear(phi);
}

static void test_rsa_keygen(void)
{
    struct rsa_public_key pub;
    struct rsa_private_key key;

    struct knuth_lfib_ctx lfib;

    mpz_t expected;

    mpz_init(expected);

    rsa_private_key_init(&key);
    rsa_public_key_init(&pub);

    /* Generate a 1024 bit key with random e */
    knuth_lfib_init(&lfib, 13);

    ASSERT (rsa_generate_keypair(&pub, &key,
                    &lfib,
                    (nettle_random_func *) knuth_lfib_random,
                    NULL, NULL,
                    1024, 50));

    test_rsa_key(&pub, &key);

    ASSERT (rsa_public_key_prepare(&pub));
    ASSERT (rsa_private_key_prepare(&key));

    /* Generate a 2000 bit key with fixed e */
    knuth_lfib_init(&lfib, 17);

    mpz_set_ui(pub.e, 17);
    ASSERT (rsa_generate_keypair(&pub, &key,
                    &lfib,
                    (nettle_random_func *) knuth_lfib_random,
                    NULL, NULL,
                    2048, 0));

    test_rsa_key(&pub, &key);

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

TEST(rsa_testcases, test_rsa_keygen)
{
    test_rsa_keygen();
}


//以下用于测试异常分支
#ifdef __aarch64__
extern "C" {
extern int uadk_rsactx_init(struct uadk_rsa_st *uadk_st, mpz_t n);
extern uint8_t *uadk_pkcs1_signature_prefix(unsigned key_size, uint8_t *buffer, unsigned id_size, const uint8_t *id, unsigned digest_size);
extern int uadk_pkcs1_rsa_md5_encode(mpz_t m, size_t key_size, struct md5_ctx *hash);
extern int uadk_pkcs1_rsa_md5_encode_digest(mpz_t m, size_t key_size, const uint8_t *digest);
extern int uadk_pkcs1_rsa_sha256_encode(mpz_t m, size_t key_size, struct sha256_ctx *hash);
extern int uadk_pkcs1_rsa_sha256_encode_digest(mpz_t m, size_t key_size, const uint8_t *digest);
extern int uadk_pkcs1_rsa_sha512_encode(mpz_t m, size_t key_size, struct sha512_ctx *hash);
extern int uadk_pkcs1_rsa_sha512_encode_digest(mpz_t m, size_t key_size, const uint8_t *digest);
extern int check_prime_sufficient(int *i, int *bitsr, int *bitse, int *n, BIGNUM *rsa_p, BIGNUM *rsa_q, BIGNUM *r1, BIGNUM *r2, BN_CTX *ctx);
extern int prime_mul_res(int i, BIGNUM *rsa_p, BIGNUM *rsa_q, BIGNUM *r1, BN_CTX *ctx);
extern int check_prime_useful(int *n, BIGNUM *prime, BIGNUM *r1, BIGNUM *r2, BIGNUM *e_value, BN_CTX *ctx);
}
IFMUadkShareCtx *get_uadk_ctx_stub(UadkQueueAlgType alg_type, int alg, int mode, bool is_shared)
{
        return NULL;
}

uint8_t *uadk_pkcs1_signature_prefix_stub(unsigned key_size, uint8_t *buffer, unsigned id_size, const uint8_t *id, unsigned digest_size)
{
        return NULL;
}

unsigned long BN_get_word_stub(const BIGNUM *a)
{
        return 1;
}

int prime_mul_res_stub(int i, BIGNUM *rsa_p, BIGNUM *rsa_q, BIGNUM *r1, BN_CTX *ctx)
{
        return 0;
}

int BN_rshift_stub(BIGNUM *r, const BIGNUM *a, int n)
{
        return 1;
}

int BN_sub_stub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
        return 1;
}

int ERR_set_mark_stub(void)
{
        return 0;
}

void BN_set_flags_stub(BIGNUM *b, int n)
{
        return;
}

BIGNUM *BN_mod_inverse_stub(BIGNUM *ret, const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)
{
        return NULL;
}

unsigned long ERR_peek_last_error_stub(void)
{
        return 100;
}

TEST(rsa_testcases, test_rsa_exeception1)
{
        Stub s;
        s.set(get_uadk_ctx, get_uadk_ctx_stub);
        struct uadk_rsa_st uadk_st;
        mpz_t n;
        mpz_init(n);
        uadk_rsactx_init(&uadk_st, n);
        mpz_clear(n);
        s.reset(get_uadk_ctx);
}

TEST(rsa_testcases, test_rsa_exeception2)
{
        Stub s;
        s.set(uadk_pkcs1_signature_prefix, uadk_pkcs1_signature_prefix_stub);
        struct md5_ctx hash;
        struct sha256_ctx hash2;
        struct sha512_ctx hash3;
        mpz_t m;
        mpz_init(m);
        uadk_pkcs1_rsa_md5_encode(m, 128, &hash);
        uadk_pkcs1_rsa_md5_encode_digest(m, 128, "The magic words are squeamish ossifrage");
        uadk_pkcs1_rsa_sha256_encode(m, 128, &hash2);
        uadk_pkcs1_rsa_sha256_encode_digest(m, 128, "The magic words are squeamish ossifrage");
        uadk_pkcs1_rsa_sha512_encode(m, 128, &hash3);
        uadk_pkcs1_rsa_sha512_encode_digest(m, 128, "The magic words are squeamish ossifrage");
        mpz_clear(m);
        s.reset(uadk_pkcs1_signature_prefix);
}

TEST(rsa_testcases, test_rsa_exeception3)
{
        Stub s1, s2, s3;
        s1.set(prime_mul_res, prime_mul_res_stub);
        s2.set(BN_get_word, BN_get_word_stub);
        s3.set(BN_rshift, BN_rshift_stub);
        int i=0;
        int bitsr=0;
        int bitse=0;
        int n=0;
        check_prime_sufficient(&i,&bitsr,&bitse,&n,NULL,NULL,NULL,NULL,NULL);
        check_prime_sufficient(&i,&bitsr,&bitse,&n,NULL,NULL,NULL,NULL,NULL);
        check_prime_sufficient(&i,&bitsr,&bitse,&n,NULL,NULL,NULL,NULL,NULL);
        check_prime_sufficient(&i,&bitsr,&bitse,&n,NULL,NULL,NULL,NULL,NULL);
        check_prime_sufficient(&i,&bitsr,&bitse,&n,NULL,NULL,NULL,NULL,NULL);
        s1.reset(prime_mul_res);
        s2.reset(BN_get_word);
        s3.reset(BN_rshift);
}

TEST(rsa_testcases, test_rsa_exeception4)
{
        Stub s1,s2,s3,s4,s5;
        s1.set(BN_sub, BN_sub_stub);
        s2.set(ERR_set_mark, ERR_set_mark_stub);
        s3.set(BN_set_flags, BN_set_flags_stub);
        s4.set(BN_mod_inverse, BN_mod_inverse_stub);
        s5.set(ERR_peek_last_error, ERR_peek_last_error_stub);
        check_prime_useful(NULL, NULL, NULL, NULL, NULL, NULL);
}
#endif