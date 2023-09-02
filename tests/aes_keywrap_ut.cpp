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

#include "testutils.h"
#include "nettle/nist-keywrap.h"
#include "aes.h"

#define aes128_ctx ifm_aes128_ctx
#define aes192_ctx ifm_aes192_ctx
#define aes256_ctx ifm_aes256_ctx

typedef void nettle_nist_keywrap_func(const void *ctx, const uint8_t *iv, size_t cleartext_length, uint8_t *cleartext,
                                      const uint8_t *ciphertext);

typedef int nettle_nist_keyunwrap_func(const void *ctx, const uint8_t *iv, size_t cleartext_length, uint8_t *cleartext,
                                       const uint8_t *ciphertext);

struct nettle_wrap {
    void *ctx;
    nettle_set_key_func *set_encrypt_key;
    nettle_cipher_func *encrypt;
    nettle_set_key_func *set_decrypt_key;
    nettle_cipher_func *decrypt;
};

struct nettle_specific_wrap {
    void *ctx;
    nettle_set_key_func *set_encrypt_key;
    nettle_nist_keywrap_func *keywrap_func;
    nettle_set_key_func *set_decrypt_key;
    nettle_nist_keyunwrap_func *keyunwrap_func;
};

static void test_wrap(struct nettle_wrap *w, const struct tstring *key, const struct tstring *iv,
                      const struct tstring *cleartext, const struct tstring *ciphertext)
{
    uint8_t data[40];
    w->set_encrypt_key(w->ctx, key->data);
    nist_keywrap16(w->ctx, w->encrypt, iv->data, cleartext->length + 8, data, cleartext->data);
    if (!MEMEQ(ciphertext->length, data, ciphertext->data)) {
        fprintf(stderr, "test_wrap: Wrap failed:");
        fprintf(stderr, "\nOutput: ");
        print_hex(ciphertext->length, data);
        fprintf(stderr, "\nExpected:");
        tstring_print_hex(ciphertext);
        fprintf(stderr, "\n");
        FAIL();
    }
}

static void test_unwrap(struct nettle_wrap *w, const struct tstring *key, const struct tstring *iv,
                        const struct tstring *ciphertext, const struct tstring *cleartext)
{
    uint8_t data[32];
    w->set_decrypt_key(w->ctx, key->data);
    nist_keyunwrap16(w->ctx, w->decrypt, iv->data, cleartext->length, data, ciphertext->data);
    if (!MEMEQ(cleartext->length, data, cleartext->data)) {
        fprintf(stderr, "test_unwrap: Wrap failed:");
        fprintf(stderr, "\nOutput: ");
        print_hex(cleartext->length, data);
        fprintf(stderr, "\nExpected:");
        tstring_print_hex(cleartext);
        fprintf(stderr, "\n");
        FAIL();
    }
}

static void test_unwrap_fail(struct nettle_wrap *w, const struct tstring *key, const struct tstring *iv,
                             const struct tstring *ciphertext)
{
    uint8_t data[32];
    w->set_decrypt_key(w->ctx, key->data);
    if (nist_keyunwrap16(w->ctx, w->decrypt, iv->data, ciphertext->length - 8, data, ciphertext->data)) {
        FAIL();
    }
}

static void test_specific_wrap(struct nettle_specific_wrap *w, const struct tstring *key, const struct tstring *iv,
                               const struct tstring *cleartext, const struct tstring *ciphertext)
{
    uint8_t data[40];
    w->set_encrypt_key(w->ctx, key->data);
    w->keywrap_func(w->ctx, iv->data, cleartext->length + 8, data, cleartext->data);
    if (!MEMEQ(ciphertext->length, data, ciphertext->data)) {
        fprintf(stderr, "test_specific_wrap: Wrap failed:");
        fprintf(stderr, "\nOutput: ");
        print_hex(ciphertext->length, data);
        fprintf(stderr, "\nExpected:");
        tstring_print_hex(ciphertext);
        fprintf(stderr, "\n");
        FAIL();
    }
}

static void test_specific_unwrap(struct nettle_specific_wrap *w, const struct tstring *key, const struct tstring *iv,
                                 const struct tstring *ciphertext, const struct tstring *cleartext)
{
    uint8_t data[32];
    w->set_decrypt_key(w->ctx, key->data);
    w->keyunwrap_func(w->ctx, iv->data, cleartext->length, data, ciphertext->data);
    if (!MEMEQ(cleartext->length, data, cleartext->data)) {
        fprintf(stderr, "test_unwrap: Wrap failed:");
        fprintf(stderr, "\nOutput: ");
        print_hex(cleartext->length, data);
        fprintf(stderr, "\nExpected:");
        tstring_print_hex(cleartext);
        fprintf(stderr, "\n");
        FAIL();
    }
}

static void test_specific_unwrap_fail(struct nettle_specific_wrap *w, const struct tstring *key,
                                      const struct tstring *iv, const struct tstring *ciphertext)
{
    uint8_t data[32];
    w->set_decrypt_key(w->ctx, key->data);
    if (w->keyunwrap_func(w->ctx, iv->data, ciphertext->length - 8, data, ciphertext->data)) {
        FAIL();
    }
}

TEST(aes_keywrap_testcases, test_aes_keywrap_1)
{
    struct aes128_ctx ctx_128;
    struct nettle_wrap wrap128;
    memset(&ctx_128, 0, sizeof(ctx_128));
    wrap128.ctx = &ctx_128;
    wrap128.set_encrypt_key = (nettle_set_key_func *)&aes128_set_encrypt_key;
    wrap128.encrypt = (nettle_cipher_func *)&aes128_encrypt;
    test_wrap(&wrap128, SHEX("0001020304050607 08090A0B0C0D0E0F"), SHEX("A6A6A6A6A6A6A6A6"),
              SHEX("0011223344556677 8899AABBCCDDEEFF"), SHEX("1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_2)
{
    struct aes128_ctx ctx_128;
    struct nettle_wrap unwrap128;
    memset(&ctx_128, 0, sizeof(ctx_128));
    unwrap128.ctx = &ctx_128;
    unwrap128.set_decrypt_key = (nettle_set_key_func *)&aes128_set_decrypt_key;
    unwrap128.decrypt = (nettle_cipher_func *)&aes128_decrypt;
    test_unwrap(&unwrap128, SHEX("0001020304050607 08090A0B0C0D0E0F"), SHEX("A6A6A6A6A6A6A6A6"),
                SHEX("1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5"), SHEX("0011223344556677 8899AABBCCDDEEFF"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_3)
{
    struct aes128_ctx ctx_128;
    struct nettle_wrap unwrap128;
    memset(&ctx_128, 0, sizeof(ctx_128));
    unwrap128.ctx = &ctx_128;
    unwrap128.set_decrypt_key = (nettle_set_key_func *)&aes128_set_decrypt_key;
    unwrap128.decrypt = (nettle_cipher_func *)&aes128_decrypt;
    test_unwrap_fail(&unwrap128, SHEX("0001020304050607 08090A0B0C0D0E0F"), SHEX("A6A6A6A6A6A6A6A6"),
                     SHEX("1EA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_4)
{
    struct aes192_ctx ctx_192;
    struct nettle_wrap wrap192;
    memset(&ctx_192, 0, sizeof(ctx_192));
    wrap192.ctx = &ctx_192;
    wrap192.set_encrypt_key = (nettle_set_key_func *)&aes192_set_encrypt_key;
    wrap192.encrypt = (nettle_cipher_func *)&aes192_encrypt;
    test_wrap(&wrap192, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617"), SHEX("A6A6A6A6A6A6A6A6"),
              SHEX("0011223344556677 8899AABBCCDDEEFF"), SHEX("96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_5)
{
    struct aes192_ctx ctx_192;
    struct nettle_wrap unwrap192;
    memset(&ctx_192, 0, sizeof(ctx_192));
    unwrap192.ctx = &ctx_192;
    unwrap192.set_decrypt_key = (nettle_set_key_func *)&aes192_set_decrypt_key;
    unwrap192.decrypt = (nettle_cipher_func *)&aes192_decrypt;
    test_unwrap(&unwrap192, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617"), SHEX("A6A6A6A6A6A6A6A6"),
                SHEX("96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D"), SHEX("0011223344556677 8899AABBCCDDEEFF"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_6)
{
    struct aes192_ctx ctx_192;
    struct nettle_wrap unwrap192;
    memset(&ctx_192, 0, sizeof(ctx_192));
    unwrap192.ctx = &ctx_192;
    unwrap192.set_decrypt_key = (nettle_set_key_func *)&aes192_set_decrypt_key;
    unwrap192.decrypt = (nettle_cipher_func *)&aes192_decrypt;
    test_unwrap_fail(&unwrap192, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617"), SHEX("A6A6A6A6A6A6A6A6"),
                     SHEX("96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5E"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_7)
{
    struct aes256_ctx ctx_256;
    struct nettle_wrap wrap256;
    memset(&ctx_256, 0, sizeof(ctx_256));
    wrap256.ctx = &ctx_256;
    wrap256.set_encrypt_key = (nettle_set_key_func *)&aes256_set_encrypt_key;
    wrap256.encrypt = (nettle_cipher_func *)&aes256_encrypt;
    test_wrap(&wrap256, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F"),
              SHEX("A6A6A6A6A6A6A6A6"), SHEX("0011223344556677 8899AABBCCDDEEFF"),
              SHEX("64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_8)
{
    struct aes256_ctx ctx_256;
    struct nettle_wrap unwrap256;
    memset(&ctx_256, 0, sizeof(ctx_256));
    unwrap256.ctx = &ctx_256;
    unwrap256.set_decrypt_key = (nettle_set_key_func *)&aes256_set_decrypt_key;
    unwrap256.decrypt = (nettle_cipher_func *)&aes256_decrypt;
    test_unwrap(&unwrap256, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F"),
                SHEX("A6A6A6A6A6A6A6A6"), SHEX("64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7"),
                SHEX("0011223344556677 8899AABBCCDDEEFF"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_9)
{
    struct aes256_ctx ctx_256;
    struct nettle_wrap unwrap256;
    memset(&ctx_256, 0, sizeof(ctx_256));
    unwrap256.ctx = &ctx_256;
    unwrap256.set_decrypt_key = (nettle_set_key_func *)&aes256_set_decrypt_key;
    unwrap256.decrypt = (nettle_cipher_func *)&aes256_decrypt;
    test_unwrap_fail(&unwrap256, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F"),
                     SHEX("A6A6A6A6A6A6A6A6"), SHEX("64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE6"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_10)
{
    struct aes192_ctx ctx_192;
    struct nettle_wrap wrap192;
    memset(&ctx_192, 0, sizeof(ctx_192));
    wrap192.ctx = &ctx_192;
    wrap192.set_encrypt_key = (nettle_set_key_func *)&aes192_set_encrypt_key;
    wrap192.encrypt = (nettle_cipher_func *)&aes192_encrypt;
    test_wrap(&wrap192, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617"), SHEX("A6A6A6A6A6A6A6A6"),
              SHEX("0011223344556677 8899AABBCCDDEEFF 0001020304050607"),
              SHEX("031D33264E15D332 68F24EC260743EDC E1C6C7DDEE725A93 6BA814915C6762D2"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_11)
{
    struct aes192_ctx ctx_192;
    struct nettle_wrap unwrap192;
    memset(&ctx_192, 0, sizeof(ctx_192));
    unwrap192.ctx = &ctx_192;
    unwrap192.set_decrypt_key = (nettle_set_key_func *)&aes192_set_decrypt_key;
    unwrap192.decrypt = (nettle_cipher_func *)&aes192_decrypt;
    test_unwrap(&unwrap192, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617"), SHEX("A6A6A6A6A6A6A6A6"),
                SHEX("031D33264E15D332 68F24EC260743EDC E1C6C7DDEE725A93 6BA814915C6762D2"),
                SHEX("0011223344556677 8899AABBCCDDEEFF 0001020304050607"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_12)
{
    struct aes192_ctx ctx_192;
    struct nettle_wrap unwrap192;
    memset(&ctx_192, 0, sizeof(ctx_192));
    unwrap192.ctx = &ctx_192;
    unwrap192.set_decrypt_key = (nettle_set_key_func *)&aes192_set_decrypt_key;
    unwrap192.decrypt = (nettle_cipher_func *)&aes192_decrypt;
    test_unwrap_fail(&unwrap192, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617"), SHEX("A6A6A6A6A6A6A6A6"),
                     SHEX("031D33264E15D332 68F24EC260743EDC E1C6C7DDEE725B93 6BA814915C6762D2"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_13)
{
    struct aes256_ctx ctx_256;
    struct nettle_wrap wrap256;
    memset(&ctx_256, 0, sizeof(ctx_256));
    wrap256.ctx = &ctx_256;
    wrap256.set_encrypt_key = (nettle_set_key_func *)&aes256_set_encrypt_key;
    wrap256.encrypt = (nettle_cipher_func *)&aes256_encrypt;
    test_wrap(&wrap256, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F"),
              SHEX("A6A6A6A6A6A6A6A6"), SHEX("0011223344556677 8899AABBCCDDEEFF 0001020304050607"),
              SHEX("A8F9BC1612C68B3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_14)
{
    struct aes256_ctx ctx_256;
    struct nettle_wrap unwrap256;
    memset(&ctx_256, 0, sizeof(ctx_256));
    unwrap256.ctx = &ctx_256;
    unwrap256.set_decrypt_key = (nettle_set_key_func *)&aes256_set_decrypt_key;
    unwrap256.decrypt = (nettle_cipher_func *)&aes256_decrypt;
    test_unwrap(&unwrap256, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F"),
                SHEX("A6A6A6A6A6A6A6A6"), SHEX("A8F9BC1612C68B3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1"),
                SHEX("0011223344556677 8899AABBCCDDEEFF 0001020304050607"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_15)
{
    struct aes256_ctx ctx_256;
    struct nettle_wrap unwrap256;
    memset(&ctx_256, 0, sizeof(ctx_256));
    unwrap256.ctx = &ctx_256;
    unwrap256.set_decrypt_key = (nettle_set_key_func *)&aes256_set_decrypt_key;
    unwrap256.decrypt = (nettle_cipher_func *)&aes256_decrypt;
    test_unwrap_fail(&unwrap256, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F"),
                     SHEX("A6A6A6A6A6A6A6A6"),
                     SHEX("A8F9BC1612C68B3F F6E6F4FBE30E71E5 769C8B80A32CB895 8CD5D17D6B254DA1"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_16)
{
    struct aes256_ctx ctx_256;
    struct nettle_wrap wrap256;
    memset(&ctx_256, 0, sizeof(ctx_256));
    wrap256.ctx = &ctx_256;
    wrap256.set_encrypt_key = (nettle_set_key_func *)&aes256_set_encrypt_key;
    wrap256.encrypt = (nettle_cipher_func *)&aes256_encrypt;
    test_wrap(&wrap256, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F"),
              SHEX("A6A6A6A6A6A6A6A6"), SHEX("0011223344556677 8899AABBCCDDEEFF 0001020304050607 08090A0B0C0D0E0F"),
              SHEX("28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_17)
{
    struct aes256_ctx ctx_256;
    struct nettle_wrap unwrap256;
    memset(&ctx_256, 0, sizeof(ctx_256));
    unwrap256.ctx = &ctx_256;
    unwrap256.set_decrypt_key = (nettle_set_key_func *)&aes256_set_decrypt_key;
    unwrap256.decrypt = (nettle_cipher_func *)&aes256_decrypt;
    test_unwrap(&unwrap256, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F"),
                SHEX("A6A6A6A6A6A6A6A6"),
                SHEX("28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21"),
                SHEX("0011223344556677 8899AABBCCDDEEFF 0001020304050607 08090A0B0C0D0E0F"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_18)
{
    struct aes256_ctx ctx_256;
    struct nettle_wrap unwrap256;
    memset(&ctx_256, 0, sizeof(ctx_256));
    unwrap256.ctx = &ctx_256;
    unwrap256.set_decrypt_key = (nettle_set_key_func *)&aes256_set_decrypt_key;
    unwrap256.decrypt = (nettle_cipher_func *)&aes256_decrypt;
    test_unwrap_fail(&unwrap256, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F"),
                     SHEX("A6A6A6A6A6A6A6A6"),
                     SHEX("28C9F404C4B810F4 CBCCB35CFB87F816 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_19)
{
    struct aes128_ctx ctx_128;
    struct nettle_specific_wrap swrap128;
    memset(&ctx_128, 0, sizeof(ctx_128));
    swrap128.ctx = &ctx_128;
    swrap128.set_encrypt_key = (nettle_set_key_func *)&aes128_set_encrypt_key;
    swrap128.keywrap_func = (nettle_nist_keywrap_func *)&aes128_keywrap;
    test_specific_wrap(&swrap128, SHEX("0001020304050607 08090A0B0C0D0E0F"), SHEX("A6A6A6A6A6A6A6A6"),
                       SHEX("0011223344556677 8899AABBCCDDEEFF"),
                       SHEX("1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_20)
{
    struct aes128_ctx ctx_128;
    struct nettle_specific_wrap sunwrap128;
    memset(&ctx_128, 0, sizeof(ctx_128));
    sunwrap128.ctx = &ctx_128;
    sunwrap128.set_decrypt_key = (nettle_set_key_func *)&aes128_set_decrypt_key;
    sunwrap128.keyunwrap_func = (nettle_nist_keyunwrap_func *)&aes128_keyunwrap;
    test_specific_unwrap(&sunwrap128, SHEX("0001020304050607 08090A0B0C0D0E0F"), SHEX("A6A6A6A6A6A6A6A6"),
                         SHEX("1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5"),
                         SHEX("0011223344556677 8899AABBCCDDEEFF"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_21)
{
    struct aes128_ctx ctx_128;
    struct nettle_specific_wrap sunwrap128;
    memset(&ctx_128, 0, sizeof(ctx_128));
    sunwrap128.ctx = &ctx_128;
    sunwrap128.set_decrypt_key = (nettle_set_key_func *)&aes128_set_decrypt_key;
    sunwrap128.keyunwrap_func = (nettle_nist_keyunwrap_func *)&aes128_keyunwrap;
    test_specific_unwrap_fail(&sunwrap128, SHEX("0001020304050607 08090A0B0C0D0E0F"), SHEX("A6A6A6A6A6A6A6A6"),
                              SHEX("1FA68B0A8112B446 AEF34BD8FB5A7B82 9D3E862371D2CFE5"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_22)
{
    struct aes192_ctx ctx_192;
    struct nettle_specific_wrap swrap192;
    memset(&ctx_192, 0, sizeof(ctx_192));
    swrap192.ctx = &ctx_192;
    swrap192.set_encrypt_key = (nettle_set_key_func *)&aes192_set_encrypt_key;
    swrap192.keywrap_func = (nettle_nist_keywrap_func *)&aes192_keywrap;
    test_specific_wrap(&swrap192, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617"), SHEX("A6A6A6A6A6A6A6A6"),
                       SHEX("0011223344556677 8899AABBCCDDEEFF"),
                       SHEX("96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_23)
{
    struct aes192_ctx ctx_192;
    struct nettle_specific_wrap sunwrap192;
    memset(&ctx_192, 0, sizeof(ctx_192));
    sunwrap192.ctx = &ctx_192;
    sunwrap192.set_decrypt_key = (nettle_set_key_func *)&aes192_set_decrypt_key;
    sunwrap192.keyunwrap_func = (nettle_nist_keyunwrap_func *)&aes192_keyunwrap;
    test_specific_unwrap(&sunwrap192, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617"),
                         SHEX("A6A6A6A6A6A6A6A6"), SHEX("96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D"),
                         SHEX("0011223344556677 8899AABBCCDDEEFF"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_24)
{
    struct aes192_ctx ctx_192;
    struct nettle_specific_wrap sunwrap192;
    memset(&ctx_192, 0, sizeof(ctx_192));
    sunwrap192.ctx = &ctx_192;
    sunwrap192.set_decrypt_key = (nettle_set_key_func *)&aes192_set_decrypt_key;
    sunwrap192.keyunwrap_func = (nettle_nist_keyunwrap_func *)&aes192_keyunwrap;
    test_specific_unwrap_fail(&sunwrap192, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617"),
                              SHEX("A6A6A6A6A6A6A6A6"), SHEX("96778B25AE6CA435 F92B5B97C050AED2 478AB8A17AD84E5D"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_25)
{
    struct aes256_ctx ctx_256;
    struct nettle_specific_wrap swrap256;
    memset(&ctx_256, 0, sizeof(ctx_256));
    swrap256.ctx = &ctx_256;
    swrap256.set_encrypt_key = (nettle_set_key_func *)&aes256_set_encrypt_key;
    swrap256.keywrap_func = (nettle_nist_keywrap_func *)&aes256_keywrap;
    test_specific_wrap(&swrap256, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F"),
                       SHEX("A6A6A6A6A6A6A6A6"), SHEX("0011223344556677 8899AABBCCDDEEFF"),
                       SHEX("64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_26)
{
    struct aes256_ctx ctx_256;
    struct nettle_specific_wrap sunwrap256;
    memset(&ctx_256, 0, sizeof(ctx_256));
    sunwrap256.ctx = &ctx_256;
    sunwrap256.set_decrypt_key = (nettle_set_key_func *)&aes256_set_decrypt_key;
    sunwrap256.keyunwrap_func = (nettle_nist_keyunwrap_func *)&aes256_keyunwrap;
    test_specific_unwrap(&sunwrap256, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F"),
                         SHEX("A6A6A6A6A6A6A6A6"), SHEX("64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7"),
                         SHEX("0011223344556677 8899AABBCCDDEEFF"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_27)
{
    struct aes256_ctx ctx_256;
    struct nettle_specific_wrap sunwrap256;
    memset(&ctx_256, 0, sizeof(ctx_256));
    sunwrap256.ctx = &ctx_256;
    sunwrap256.set_decrypt_key = (nettle_set_key_func *)&aes256_set_decrypt_key;
    sunwrap256.keyunwrap_func = (nettle_nist_keyunwrap_func *)&aes256_keyunwrap;
    test_specific_unwrap_fail(&sunwrap256, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F"),
                              SHEX("A6A6A6A6A6A6A6A6"), SHEX("64E8C3F9CE0F5BA2 63E9777905818A2A 93C8101E7D6E8AE7"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_28)
{
    struct aes192_ctx ctx_192;
    struct nettle_specific_wrap swrap192;
    memset(&ctx_192, 0, sizeof(ctx_192));
    swrap192.ctx = &ctx_192;
    swrap192.set_encrypt_key = (nettle_set_key_func *)&aes192_set_encrypt_key;
    swrap192.keywrap_func = (nettle_nist_keywrap_func *)&aes192_keywrap;
    test_specific_wrap(&swrap192, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617"), SHEX("A6A6A6A6A6A6A6A6"),
                       SHEX("0011223344556677 8899AABBCCDDEEFF 0001020304050607"),
                       SHEX("031D33264E15D332 68F24EC260743EDC E1C6C7DDEE725A93 6BA814915C6762D2"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_29)
{
    struct aes192_ctx ctx_192;
    struct nettle_specific_wrap sunwrap192;
    memset(&ctx_192, 0, sizeof(ctx_192));
    sunwrap192.ctx = &ctx_192;
    sunwrap192.set_decrypt_key = (nettle_set_key_func *)&aes192_set_decrypt_key;
    sunwrap192.keyunwrap_func = (nettle_nist_keyunwrap_func *)&aes192_keyunwrap;
    test_specific_unwrap(&sunwrap192, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617"),
                         SHEX("A6A6A6A6A6A6A6A6"),
                         SHEX("031D33264E15D332 68F24EC260743EDC E1C6C7DDEE725A93 6BA814915C6762D2"),
                         SHEX("0011223344556677 8899AABBCCDDEEFF 0001020304050607"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_30)
{
    struct aes192_ctx ctx_192;
    struct nettle_specific_wrap sunwrap192;
    memset(&ctx_192, 0, sizeof(ctx_192));
    sunwrap192.ctx = &ctx_192;
    sunwrap192.set_decrypt_key = (nettle_set_key_func *)&aes192_set_decrypt_key;
    sunwrap192.keyunwrap_func = (nettle_nist_keyunwrap_func *)&aes192_keyunwrap;
    test_specific_unwrap_fail(&sunwrap192, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617"),
                              SHEX("A6A6A6A6A6A6A6A6"),
                              SHEX("031D33264E15D332 68F24EC260743EDC E1C6C7DDEF725A93 6BA814915C6762D2"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_31)
{
    struct aes256_ctx ctx_256;
    struct nettle_specific_wrap swrap256;
    memset(&ctx_256, 0, sizeof(ctx_256));
    swrap256.ctx = &ctx_256;
    swrap256.set_encrypt_key = (nettle_set_key_func *)&aes256_set_encrypt_key;
    swrap256.keywrap_func = (nettle_nist_keywrap_func *)&aes256_keywrap;
    test_specific_wrap(&swrap256, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F"),
                       SHEX("A6A6A6A6A6A6A6A6"), SHEX("0011223344556677 8899AABBCCDDEEFF 0001020304050607"),
                       SHEX("A8F9BC1612C68B3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_32)
{
    struct aes256_ctx ctx_256;
    struct nettle_specific_wrap sunwrap256;
    memset(&ctx_256, 0, sizeof(ctx_256));
    sunwrap256.ctx = &ctx_256;
    sunwrap256.set_decrypt_key = (nettle_set_key_func *)&aes256_set_decrypt_key;
    sunwrap256.keyunwrap_func = (nettle_nist_keyunwrap_func *)&aes256_keyunwrap;
    test_specific_unwrap(&sunwrap256, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F"),
                         SHEX("A6A6A6A6A6A6A6A6"),
                         SHEX("A8F9BC1612C68B3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1"),
                         SHEX("0011223344556677 8899AABBCCDDEEFF 0001020304050607"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_33)
{
    struct aes256_ctx ctx_256;
    struct nettle_specific_wrap sunwrap256;
    memset(&ctx_256, 0, sizeof(ctx_256));
    sunwrap256.ctx = &ctx_256;
    sunwrap256.set_decrypt_key = (nettle_set_key_func *)&aes256_set_decrypt_key;
    sunwrap256.keyunwrap_func = (nettle_nist_keyunwrap_func *)&aes256_keyunwrap;
    test_specific_unwrap_fail(&sunwrap256, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F"),
                              SHEX("A6A6A6A6A6A6A6A6"),
                              SHEX("A8F9BC1612C68C3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_34)
{
    struct aes256_ctx ctx_256;
    struct nettle_specific_wrap swrap256;
    memset(&ctx_256, 0, sizeof(ctx_256));
    swrap256.ctx = &ctx_256;
    swrap256.set_encrypt_key = (nettle_set_key_func *)&aes256_set_encrypt_key;
    swrap256.keywrap_func = (nettle_nist_keywrap_func *)&aes256_keywrap;
    test_specific_wrap(&swrap256, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F"),
                       SHEX("A6A6A6A6A6A6A6A6"),
                       SHEX("0011223344556677 8899AABBCCDDEEFF 0001020304050607 08090A0B0C0D0E0F"),
                       SHEX("28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_35)
{
    struct aes256_ctx ctx_256;
    struct nettle_specific_wrap sunwrap256;
    memset(&ctx_256, 0, sizeof(ctx_256));
    sunwrap256.ctx = &ctx_256;
    sunwrap256.set_decrypt_key = (nettle_set_key_func *)&aes256_set_decrypt_key;
    sunwrap256.keyunwrap_func = (nettle_nist_keyunwrap_func *)&aes256_keyunwrap;
    test_specific_unwrap(&sunwrap256, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F"),
                         SHEX("A6A6A6A6A6A6A6A6"),
                         SHEX("28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21"),
                         SHEX("0011223344556677 8899AABBCCDDEEFF 0001020304050607 08090A0B0C0D0E0F"));
}

TEST(aes_keywrap_testcases, test_aes_keywrap_36)
{
    struct aes256_ctx ctx_256;
    struct nettle_specific_wrap sunwrap256;
    memset(&ctx_256, 0, sizeof(ctx_256));
    sunwrap256.ctx = &ctx_256;
    sunwrap256.set_decrypt_key = (nettle_set_key_func *)&aes256_set_decrypt_key;
    sunwrap256.keyunwrap_func = (nettle_nist_keyunwrap_func *)&aes256_keyunwrap;
    test_specific_unwrap_fail(
        &sunwrap256, SHEX("0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F"),
        SHEX("A6A6A6A6A6A6A6A6"),
        SHEX("28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED426 CBC7F0E71A99F43B FB988B9B7A02DD21"));
}