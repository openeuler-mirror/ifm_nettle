/*
   The aes/rijndael block cipher.

   Copyright (C) 2001, 2013 Niels Möller

   This file is part of GNU Nettle.

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
/* This file tests deprecated functions */
#define _NETTLE_ATTRIBUTE_DEPRECATED

#include <gtest/gtest.h>

#include "testutils.h"
#include "aes.h"

#define aes128_ctx ifm_aes128_ctx
#define aes192_ctx ifm_aes192_ctx
#define aes256_ctx ifm_aes256_ctx
#define aes_ctx ifm_aes_ctx

static void test_invert(const struct tstring *key, const struct tstring *cleartext, const struct tstring *ciphertext)
{
    struct aes_ctx encrypt;
    struct aes_ctx decrypt;
    uint8_t *data = (uint8_t *)xalloc(cleartext->length);
    size_t length;
    ASSERT(cleartext->length == ciphertext->length);
    length = cleartext->length;

    memset(&encrypt, 0, sizeof(encrypt));
    memset(&decrypt, 0, sizeof(decrypt));
    aes_set_encrypt_key(&encrypt, key->length, key->data);
    aes_encrypt(&encrypt, length, data, cleartext->data);

    if (!MEMEQ(length, data, ciphertext->data)) {
        fprintf(stderr, "test_invert: Encrypt failed:\nInput:");
        tstring_print_hex(cleartext);
        fprintf(stderr, "\nOutput: ");
        print_hex(length, data);
        fprintf(stderr, "\nExpected:");
        tstring_print_hex(ciphertext);
        fprintf(stderr, "\n");
        FAIL();
    }

    aes_invert_key(&decrypt, &encrypt);
    aes_decrypt(&decrypt, length, data, data);

    if (!MEMEQ(length, data, cleartext->data)) {
        fprintf(stderr, "test_invert: Decrypt failed:\nInput:");
        tstring_print_hex(ciphertext);
        fprintf(stderr, "\nOutput: ");
        print_hex(length, data);
        fprintf(stderr, "\nExpected:");
        tstring_print_hex(cleartext);
        fprintf(stderr, "\n");
        FAIL();
    }
    free(data);
}

/* Old, unified, interface */
static nettle_set_key_func unified_aes128_set_encrypt_key;
static nettle_set_key_func unified_aes128_set_encrypt_key;
static nettle_set_key_func unified_aes192_set_encrypt_key;
static nettle_set_key_func unified_aes192_set_encrypt_key;
static nettle_set_key_func unified_aes256_set_encrypt_key;
static nettle_set_key_func unified_aes256_set_encrypt_key;
static void unified_aes128_set_encrypt_key(void *ctx, const uint8_t *key)
{
    aes_set_encrypt_key((aes_ctx *)ctx, AES128_KEY_SIZE, key);
}
static void unified_aes128_set_decrypt_key(void *ctx, const uint8_t *key)
{
    aes_set_decrypt_key((aes_ctx *)ctx, AES128_KEY_SIZE, key);
}

static void unified_aes192_set_encrypt_key(void *ctx, const uint8_t *key)
{
    aes_set_encrypt_key((aes_ctx *)ctx, AES192_KEY_SIZE, key);
}
static void unified_aes192_set_decrypt_key(void *ctx, const uint8_t *key)
{
    aes_set_decrypt_key((aes_ctx *)ctx, AES192_KEY_SIZE, key);
}

static void unified_aes256_set_encrypt_key(void *ctx, const uint8_t *key)
{
    aes_set_encrypt_key((aes_ctx *)ctx, AES256_KEY_SIZE, key);
}
static void unified_aes256_set_decrypt_key(void *ctx, const uint8_t *key)
{
    aes_set_decrypt_key((aes_ctx *)ctx, AES256_KEY_SIZE, key);
}

#define UNIFIED_AES(bits)                                                                                              \
    {                                                                                                                  \
        "unified-aes" #bits, sizeof(struct aes_ctx), AES_BLOCK_SIZE, AES##bits##_KEY_SIZE,                             \
            unified_aes##bits##_set_encrypt_key, unified_aes##bits##_set_decrypt_key,                                  \
            (nettle_cipher_func *)aes_encrypt, (nettle_cipher_func *)aes_decrypt,                                      \
    }
const struct nettle_cipher nettle_unified_aes128 = UNIFIED_AES(128);
const struct nettle_cipher nettle_unified_aes192 = UNIFIED_AES(192);
const struct nettle_cipher nettle_unified_aes256 = UNIFIED_AES(256);

static void test_cipher2(const struct nettle_cipher *c1, const struct nettle_cipher *c2, const struct tstring *key,
                         const struct tstring *cleartext, const struct tstring *ciphertext)
{
    test_cipher(c1, key, cleartext, ciphertext);
    test_cipher(c2, key, cleartext, ciphertext);
}

TEST(aes_testcases, test_aes_1)
{
    /* 128 bit keys */
    test_cipher2(&nettle_aes128, &nettle_unified_aes128, SHEX("0001020305060708 0A0B0C0D0F101112"),
                 SHEX("506812A45F08C889 B97F5980038B8359"), SHEX("D8F532538289EF7D 06B506A4FD5BE9C9"));
}

TEST(aes_testcases, test_aes_2)
{
    test_cipher2(&nettle_aes128, &nettle_unified_aes128, SHEX("14151617191A1B1C 1E1F202123242526"),
                 SHEX("5C6D71CA30DE8B8B 00549984D2EC7D4B"), SHEX("59AB30F4D4EE6E4F F9907EF65B1FB68C"));
}

TEST(aes_testcases, test_aes_3)
{
    test_cipher2(&nettle_aes128, &nettle_unified_aes128, SHEX("28292A2B2D2E2F30 323334353738393A"),
                 SHEX("53F3F4C64F8616E4 E7C56199F48F21F6"), SHEX("BF1ED2FCB2AF3FD4 1443B56D85025CB1"));
}

TEST(aes_testcases, test_aes_4)
{
    test_cipher2(&nettle_aes128, &nettle_unified_aes128, SHEX("A0A1A2A3A5A6A7A8 AAABACADAFB0B1B2"),
                 SHEX("F5F4F7F684878689 A6A7A0A1D2CDCCCF"), SHEX("CE52AF650D088CA5 59425223F4D32694"));
}

TEST(aes_testcases, test_aes_5)
{
    /* 192 bit keys */
    test_cipher2(&nettle_aes192, &nettle_unified_aes192,
                 SHEX("0001020305060708 0A0B0C0D0F101112"
                      "14151617191A1B1C"),
                 SHEX("2D33EEF2C0430A8A 9EBF45E809C40BB6"), SHEX("DFF4945E0336DF4C 1C56BC700EFF837F"));
}

TEST(aes_testcases, test_aes_6)
{
    /* 256 bit keys */
    test_cipher2(&nettle_aes256, &nettle_unified_aes256,
                 SHEX("0001020305060708 0A0B0C0D0F101112"
                      "14151617191A1B1C 1E1F202123242526"),
                 SHEX("834EADFCCAC7E1B30664B1ABA44815AB"), SHEX("1946DABF6A03A2A2 C3D0B05080AED6FC"));
}

TEST(aes_testcases, test_aes_7)
{
    /* This test case has been problematic with the CBC test case */
    test_cipher2(&nettle_aes256, &nettle_unified_aes256,
                 SHEX("8d ae 93 ff fc 78 c9 44"
                      "2a bd 0c 1e 68 bc a6 c7"
                      "05 c7 84 e3 5a a9 11 8b"
                      "d3 16 aa 54 9b 44 08 9e"),
                 SHEX("a5 ce 55 d4 21 15 a1 c6 4a a4 0c b2 ca a6 d1 37"),
                 /* In the cbc test, I once got the bad value
                  *   "b2 a0 6c d2 2f df 7d 2c  26 d2 42 88 8f 20 74 a2" */
                 SHEX("1f 94 fc 85 f2 36 21 06"
                      "4a ea e3 c9 cc 38 01 0e"));
}

TEST(aes_testcases, test_aes_8)
{
    /* From draft NIST spec on AES modes.
     *
     * F.1 ECB Example Vectors
     * F.1.1 ECB-AES128-Encrypt
     */

    test_cipher2(&nettle_aes128, &nettle_unified_aes128, SHEX("2b7e151628aed2a6abf7158809cf4f3c"),
                 SHEX("6bc1bee22e409f96e93d7e117393172a"
                      "ae2d8a571e03ac9c9eb76fac45af8e51"
                      "30c81c46a35ce411e5fbc1191a0a52ef"
                      "f69f2445df4f9b17ad2b417be66c3710"),
                 SHEX("3ad77bb40d7a3660a89ecaf32466ef97"
                      "f5d3d58503b9699de785895a96fdbaaf"
                      "43b1cd7f598ece23881b00e3ed030688"
                      "7b0c785e27e8ad3f8223207104725dd4"));
}

TEST(aes_testcases, test_aes_9)
{
    /* F.1.3 ECB-AES192-Encrypt */

    test_cipher2(&nettle_aes192, &nettle_unified_aes192, SHEX("8e73b0f7da0e6452c810f32b809079e5 62f8ead2522c6b7b"),
                 SHEX("6bc1bee22e409f96e93d7e117393172a"
                      "ae2d8a571e03ac9c9eb76fac45af8e51"
                      "30c81c46a35ce411e5fbc1191a0a52ef"
                      "f69f2445df4f9b17ad2b417be66c3710"),
                 SHEX("bd334f1d6e45f25ff712a214571fa5cc"
                      "974104846d0ad3ad7734ecb3ecee4eef"
                      "ef7afd2270e2e60adce0ba2face6444e"
                      "9a4b41ba738d6c72fb16691603c18e0e"));
}

TEST(aes_testcases, test_aes_10)
{
    /* F.1.5 ECB-AES256-Encrypt */
    test_cipher2(&nettle_aes256, &nettle_unified_aes256,
                 SHEX("603deb1015ca71be2b73aef0857d7781"
                      "1f352c073b6108d72d9810a30914dff4"),
                 SHEX("6bc1bee22e409f96e93d7e117393172a"
                      "ae2d8a571e03ac9c9eb76fac45af8e51"
                      "30c81c46a35ce411e5fbc1191a0a52ef"
                      "f69f2445df4f9b17ad2b417be66c3710"),
                 SHEX("f3eed1bdb5d2a03c064b5a7e3db181f8"
                      "591ccb10d410ed26dc5ba74a31362870"
                      "b6ed21b99ca6f4f9f153e7b1beafed1d"
                      "23304b7a39f9f3ff067d8d8f9e24ecc7"));
}

TEST(aes_testcases, test_aes_11)
{
    /* Test aes_invert_key with src != dst */
    test_invert(SHEX("0001020305060708 0A0B0C0D0F101112"), SHEX("506812A45F08C889 B97F5980038B8359"),
                SHEX("D8F532538289EF7D 06B506A4FD5BE9C9"));
}

TEST(aes_testcases, test_aes_12)
{
    test_invert(SHEX("0001020305060708 0A0B0C0D0F101112"
                     "14151617191A1B1C"),
                SHEX("2D33EEF2C0430A8A 9EBF45E809C40BB6"), SHEX("DFF4945E0336DF4C 1C56BC700EFF837F"));
}

TEST(aes_testcases, test_aes_13)
{
    test_invert(SHEX("0001020305060708 0A0B0C0D0F101112"
                     "14151617191A1B1C 1E1F202123242526"),
                SHEX("834EADFCCAC7E1B30664B1ABA44815AB"), SHEX("1946DABF6A03A2A2 C3D0B05080AED6FC"));
}