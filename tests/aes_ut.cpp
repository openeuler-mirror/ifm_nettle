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

#include <gtest/gtest.h>

#include "aes.h"
#include "testutils.h"

#define _TEST_DATA_NIST_DRAFT_KEY_128 "2b7e151628aed2a6abf7158809cf4f3c"
#define _TEST_DATA_NIST_DRAFT_KEY_192 "8e73b0f7da0e6452c810f32b809079e5 62f8ead2522c6b7b"
#define _TEST_DATA_NIST_DRAFT_KEY_256 "603deb1015ca71be2b73aef0857d7781 1f352c073b6108d72d9810a30914dff4"
#define _TEST_DATA_NIST_DRAFT_CLEARTEXT "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
#define _TEST_DATA_NIST_DRAFT_CIPHERTEXT_128 "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4"
#define _TEST_DATA_NIST_DRAFT_CIPHERTEXT_192 "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eefef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e"
#define _TEST_DATA_NIST_DRAFT_CIPHERTEXT_256 "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7"
#define _TEST_DATA_CASE_1_KEY "0001020305060708 0A0B0C0D0F101112"
#define _TEST_DATA_CASE_1_CLEARTEXT "506812A45F08C889 B97F5980038B8359"
#define _TEST_DATA_CASE_1_CIPHERTEXT "D8F532538289EF7D 06B506A4FD5BE9C9"
#define _TEST_DATA_CASE_2_KEY "14151617191A1B1C 1E1F202123242526"
#define _TEST_DATA_CASE_2_CLEARTEXT "5C6D71CA30DE8B8B 00549984D2EC7D4B"
#define _TEST_DATA_CASE_2_CIPHERTEXT "59AB30F4D4EE6E4F F9907EF65B1FB68C"
#define _TEST_DATA_CASE_3_KEY "28292A2B2D2E2F30 323334353738393A"
#define _TEST_DATA_CASE_3_CLEARTEXT "53F3F4C64F8616E4 E7C56199F48F21F6"
#define _TEST_DATA_CASE_3_CIPHERTEXT "BF1ED2FCB2AF3FD4 1443B56D85025CB1"
#define _TEST_DATA_CASE_4_KEY "A0A1A2A3A5A6A7A8 AAABACADAFB0B1B2"
#define _TEST_DATA_CASE_4_CLEARTEXT "F5F4F7F684878689 A6A7A0A1D2CDCCCF"
#define _TEST_DATA_CASE_4_CIPHERTEXT "CE52AF650D088CA5 59425223F4D32694"
#define _TEST_DATA_CASE_5_KEY "0001020305060708 0A0B0C0D0F101112 14151617191A1B1C"
#define _TEST_DATA_CASE_5_CLEARTEXT "2D33EEF2C0430A8A 9EBF45E809C40BB6"
#define _TEST_DATA_CASE_5_CIPHERTEXT "DFF4945E0336DF4C 1C56BC700EFF837F"
#define _TEST_DATA_CASE_6_KEY "0001020305060708 0A0B0C0D0F101112 14151617191A1B1C 1E1F202123242526"
#define _TEST_DATA_CASE_6_CLEARTEXT "834EADFCCAC7E1B30664B1ABA44815AB"
#define _TEST_DATA_CASE_6_CIPHERTEXT "1946DABF6A03A2A2 C3D0B05080AED6FC"
#define _TEST_DATA_CASE_7_KEY "8d ae 93 ff fc 78 c9 44 2a bd 0c 1e 68 bc a6 c7 05 c7 84 e3 5a a9 11 8b d3 16 aa 54 9b 44 08 9e"
#define _TEST_DATA_CASE_7_CLEARTEXT "a5 ce 55 d4 21 15 a1 c6 4a a4 0c b2 ca a6 d1 37"
#define _TEST_DATA_CASE_7_CIPHERTEXT "1f 94 fc 85 f2 36 21 06 4a ea e3 c9 cc 38 01 0e"
#define _TEST_DATA_CASE_11_KEY "0001020305060708 0A0B0C0D0F101112"
#define _TEST_DATA_CASE_11_CLEARTEXT "506812A45F08C889 B97F5980038B8359"
#define _TEST_DATA_CASE_11_CIPHERTEXT "D8F532538289EF7D 06B506A4FD5BE9C9"
#define _TEST_DATA_CASE_12_KEY "0001020305060708 0A0B0C0D0F101112 14151617191A1B1C"
#define _TEST_DATA_CASE_12_CLEARTEXT "2D33EEF2C0430A8A 9EBF45E809C40BB6"
#define _TEST_DATA_CASE_12_CIPHERTEXT "DFF4945E0336DF4C 1C56BC700EFF837F"
#define _TEST_DATA_CASE_13_KEY "0001020305060708 0A0B0C0D0F101112 14151617191A1B1C 1E1F202123242526"
#define _TEST_DATA_CASE_13_CLEARTEXT "834EADFCCAC7E1B30664B1ABA44815AB"
#define _TEST_DATA_CASE_13_CIPHERTEXT "1946DABF6A03A2A2 C3D0B05080AED6FC"

enum TestInvertKeySize
{
    aes128,
    aes192,
    aes256
};

static void
check_encrypt(size_t length, uint8_t* data, const struct tstring* cleartext,
    const struct tstring* ciphertext)
{
    if (!MEMEQ(length, data, ciphertext->data))
    {
        fprintf(stderr, "Failed to encrypt:\nData input: ");
        tstring_print_hex(cleartext);
        fprintf(stderr, "\nData output: ");
        print_hex(length, data);
        fprintf(stderr, "\nExpected output: ");
        tstring_print_hex(ciphertext);
        fprintf(stderr, "\n");
        FAIL();
    }
}

static void
check_decrypt(size_t length, uint8_t* data, const struct tstring* cleartext,
    const struct tstring* ciphertext)
{
    if (!MEMEQ(length, data, cleartext->data))
    {
        fprintf(stderr, "Failed to decrypt:\nData input: ");
        tstring_print_hex(ciphertext);
        fprintf(stderr, "\nData output: ");
        print_hex(length, data); \
            fprintf(stderr, "\nExpected output: ");
        tstring_print_hex(cleartext);
        fprintf(stderr, "\n");
        FAIL();
    }
}

static void
test_invert(const struct tstring* key, const TestInvertKeySize key_size,
    const struct tstring* cleartext, const struct tstring* ciphertext)
{
    struct ifm_aes128_ctx encrypt128;
    struct ifm_aes128_ctx decrypt128;
    struct ifm_aes192_ctx encrypt192;
    struct ifm_aes192_ctx decrypt192;
    struct ifm_aes256_ctx encrypt256;
    struct ifm_aes256_ctx decrypt256;
    uint8_t* data = (uint8_t*)xalloc(cleartext->length);
    size_t length;
    ASSERT(cleartext->length == ciphertext->length);
    length = cleartext->length;
    switch (key_size)
    {
    case aes128:
        aes128_set_encrypt_key(&encrypt128, key->data);
        aes128_encrypt(&encrypt128, length, data, cleartext->data);
        break;
    case aes192:
        aes192_set_encrypt_key(&encrypt192, key->data);
        aes192_encrypt(&encrypt192, length, data, cleartext->data);
        break;
    case aes256:
        aes256_set_encrypt_key(&encrypt256, key->data);
        aes256_encrypt(&encrypt256, length, data, cleartext->data);
        break;
    default:
        FAIL();
        break;
    }

    check_encrypt(length, data, cleartext, ciphertext);

    switch (key_size)
    {
    case aes128:
        aes128_invert_key(&decrypt128, &encrypt128);
        aes128_decrypt(&decrypt128, length, data, data);
        break;
    case aes192:
        aes192_invert_key(&decrypt192, &encrypt192);
        aes192_decrypt(&decrypt192, length, data, data);
        break;
    case aes256:
        aes256_invert_key(&decrypt256, &encrypt256);
        aes256_decrypt(&decrypt256, length, data, data);
        break;
    default:
        FAIL();
        break;
    }

    check_decrypt(length, data, cleartext, ciphertext);

    free(data);
}

void
test_cipher(const struct nettle_cipher* cipher, const struct tstring* key,
    const struct tstring* cleartext, const struct tstring* ciphertext)
{
    void* ctx = xalloc(cipher->context_size);
    uint8_t* data = (uint8_t*)xalloc(cleartext->length);
    size_t length;
    ASSERT(cleartext->length == ciphertext->length);
    length = cleartext->length;

    ASSERT(key->length == cipher->key_size);
    cipher->set_encrypt_key(ctx, key->data);
    cipher->encrypt(ctx, length, data, cleartext->data);

    check_encrypt(length, data, cleartext, ciphertext);

    cipher->set_decrypt_key(ctx, key->data);
    cipher->decrypt(ctx, length, data, data);

    check_decrypt(length, data, cleartext, ciphertext);

    free(ctx);
    free(data);
}

TEST(aes_testcases, test_aes_1)
{
    /* 128 bit keys */
    test_cipher(&nettle_aes128, SHEX(_TEST_DATA_CASE_1_KEY),
        SHEX(_TEST_DATA_CASE_1_CLEARTEXT), SHEX(_TEST_DATA_CASE_1_CIPHERTEXT));
}

TEST(aes_testcases, test_aes_2)
{
    test_cipher(&nettle_aes128, SHEX(_TEST_DATA_CASE_2_KEY),
        SHEX(_TEST_DATA_CASE_2_CLEARTEXT), SHEX(_TEST_DATA_CASE_2_CIPHERTEXT));
}

TEST(aes_testcases, test_aes_3)
{
    test_cipher(&nettle_aes128, SHEX(_TEST_DATA_CASE_3_KEY),
        SHEX(_TEST_DATA_CASE_3_CLEARTEXT), SHEX(_TEST_DATA_CASE_3_CIPHERTEXT));
}

TEST(aes_testcases, test_aes_4)
{
    test_cipher(&nettle_aes128, SHEX(_TEST_DATA_CASE_4_KEY),
        SHEX(_TEST_DATA_CASE_4_CLEARTEXT), SHEX(_TEST_DATA_CASE_4_CIPHERTEXT));
}

TEST(aes_testcases, test_aes_5)
{
    /* 192 bit keys */
    test_cipher(&nettle_aes192, SHEX(_TEST_DATA_CASE_5_KEY),
        SHEX(_TEST_DATA_CASE_5_CLEARTEXT), SHEX(_TEST_DATA_CASE_5_CIPHERTEXT));
}

TEST(aes_testcases, test_aes_6)
{
    /* 256 bit keys */
    test_cipher(&nettle_aes256, SHEX(_TEST_DATA_CASE_6_KEY),
        SHEX(_TEST_DATA_CASE_6_CLEARTEXT), SHEX(_TEST_DATA_CASE_6_CIPHERTEXT));
}

TEST(aes_testcases, test_aes_7)
{
    /* This test case has been problematic with the CBC test case */
    test_cipher(&nettle_aes256, SHEX(_TEST_DATA_CASE_7_KEY),
        SHEX(_TEST_DATA_CASE_7_CLEARTEXT), SHEX(_TEST_DATA_CASE_7_CIPHERTEXT));
}

TEST(aes_testcases, test_aes_8)
{
    /* F.1.1 ECB-AES128-Encrypt */
    test_cipher(&nettle_aes128, SHEX(_TEST_DATA_NIST_DRAFT_KEY_128),
        SHEX(_TEST_DATA_NIST_DRAFT_CLEARTEXT), SHEX(_TEST_DATA_NIST_DRAFT_CIPHERTEXT_128));
}

TEST(aes_testcases, test_aes_9)
{
    /* F.1.3 ECB-AES192-Encrypt */
    test_cipher(&nettle_aes192, SHEX(_TEST_DATA_NIST_DRAFT_KEY_192),
        SHEX(_TEST_DATA_NIST_DRAFT_CLEARTEXT), SHEX(_TEST_DATA_NIST_DRAFT_CIPHERTEXT_192));
}

TEST(aes_testcases, test_aes_10)
{
    /* F.1.5 ECB-AES256-Encrypt */
    test_cipher(&nettle_aes256, SHEX(_TEST_DATA_NIST_DRAFT_KEY_256),
        SHEX(_TEST_DATA_NIST_DRAFT_CLEARTEXT), SHEX(_TEST_DATA_NIST_DRAFT_CIPHERTEXT_256));
}


TEST(aes_testcases, test_aes_11)
{
    test_invert(SHEX(_TEST_DATA_CASE_11_KEY), aes128,
        SHEX(_TEST_DATA_CASE_11_CLEARTEXT), SHEX(_TEST_DATA_CASE_11_CIPHERTEXT));
}

TEST(aes_testcases, test_aes_12)
{
    test_invert(SHEX(_TEST_DATA_CASE_12_KEY), aes192,
        SHEX(_TEST_DATA_CASE_12_CLEARTEXT), SHEX(_TEST_DATA_CASE_12_CIPHERTEXT));
}

TEST(aes_testcases, test_aes_13)
{
    test_invert(SHEX(_TEST_DATA_CASE_13_KEY), aes256,
        SHEX(_TEST_DATA_CASE_13_CLEARTEXT), SHEX(_TEST_DATA_CASE_13_CIPHERTEXT));
}