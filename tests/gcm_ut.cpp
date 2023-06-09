/* gcm_ut.cpp

   Copyright (C) 2002, 2010 Niels Möller

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

#ifndef _NETTLE_ATTRIBUTE_DEPRECATED
#define _NETTLE_ATTRIBUTE_DEPRECATED __attribute__((deprecated))
#endif

#include "gcm.h"
#include "testutils.h"

static void
test_gcm_hash (const struct tstring *msg, const struct tstring *ref)
{
    struct ifm_gcm_aes128_ctx ctx;
    const uint8_t z16[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
    uint8_t digest[16];

    ASSERT (ref->length == sizeof(digest));
    gcm_aes128_set_key (&ctx, z16);
    gcm_aes128_set_iv (&ctx, 16, z16);
    gcm_aes128_update (&ctx, msg->length, msg->data);
    gcm_aes128_digest (&ctx, sizeof(digest), digest);
    if (!MEMEQ (ref->length, ref->data, digest))
    {
        fprintf (stderr, "gcm_hash failed, msg: %s\nOutput: ", msg->data);
        print_hex (16, digest);
        fprintf(stderr, "Expected:");
        tstring_print_hex(ref);
        fprintf(stderr, "\n");
        FAIL();
    }
}

void
test_aead(const struct nettle_aead *aead,
	    nettle_hash_update_func *set_nonce,
	    const struct tstring *key,
	    const struct tstring *authtext,
	    const struct tstring *cleartext,
	    const struct tstring *ciphertext,
	    const struct tstring *nonce,
	    const struct tstring *digest)
{
    void *ctx = xalloc(aead->context_size);
    uint8_t *in, *out;
    uint8_t *buffer;
    unsigned in_align;

    ASSERT (cleartext->length == ciphertext->length);
    ASSERT (key->length == aead->key_size);
    ASSERT(aead->block_size > 0);

    buffer = (uint8_t*)xalloc(aead->digest_size);
    in = (uint8_t*)xalloc(cleartext->length + aead->block_size - 1);
    out = (uint8_t*)xalloc(cleartext->length + aead->block_size - 1);

    for (in_align = 0; in_align < aead->block_size; in_align++)
    {
        unsigned out_align = 3*in_align % aead->block_size;
        size_t offset;
        memcpy (in + in_align, cleartext->data, cleartext->length);
        for (offset = 0; offset <= cleartext->length; offset += aead->block_size)
        {
	        aead->set_encrypt_key(ctx, key->data);

            if (set_nonce)
                set_nonce (ctx, nonce->length, nonce->data);
            else
                {
                assert (nonce->length == aead->nonce_size);
                aead->set_nonce(ctx, nonce->data);
                }
            if (aead->update && authtext->length)
                aead->update(ctx, authtext->length, authtext->data);

            if (offset > 0)
                aead->encrypt(ctx, offset, out + out_align, in + in_align);

            if (offset < cleartext->length)
                aead->encrypt(ctx, cleartext->length - offset,
                    out + out_align + offset, in + in_align + offset);

            if (!MEMEQ(cleartext->length, out + out_align, ciphertext->data))
                {
                fprintf(stderr, "aead->encrypt failed (offset = %u):\nclear: ",
                    (unsigned) offset);
                tstring_print_hex(cleartext);
                fprintf(stderr, "  got: ");
                print_hex(cleartext->length, out + out_align);
                fprintf(stderr, "  exp: ");
                tstring_print_hex(ciphertext);
                FAIL();
                }
            if (digest)
                {
                ASSERT (digest->length <= aead->digest_size);
                memset(buffer, 0, aead->digest_size);
                aead->digest(ctx, digest->length, buffer);
                if (!MEMEQ(digest->length, buffer, digest->data))
                {
                fprintf(stderr, "aead->digest failed (offset = %u):\n  got: ",
                    (unsigned) offset);
                print_hex(digest->length, buffer);
                fprintf(stderr, "  exp: ");
                tstring_print_hex(digest);
                FAIL();
                }
                }
            else
                ASSERT(!aead->digest);

            if (aead->set_decrypt_key)
            {
                aead->set_decrypt_key(ctx, key->data);

                if (set_nonce)
                set_nonce (ctx, nonce->length, nonce->data);
                else
                {
                assert (nonce->length == aead->nonce_size);
                aead->set_nonce(ctx, nonce->data);
                }

                if (aead->update && authtext->length)
                aead->update(ctx, authtext->length, authtext->data);

                if (offset > 0)
                aead->decrypt (ctx, offset, out + out_align, out + out_align);

                if (offset < cleartext->length)
                aead->decrypt(ctx, cleartext->length - offset,
                        out + out_align + offset, out + out_align + offset);

                ASSERT(MEMEQ(cleartext->length, out + out_align, cleartext->data));

                if (digest)
                {
                memset(buffer, 0, aead->digest_size);
                aead->digest(ctx, digest->length, buffer);
                ASSERT(MEMEQ(digest->length, buffer, digest->data));
                }
            }
        }
    }
    free(ctx);
    free(in);
    free(out);
    free(buffer);
}

static nettle_set_key_func gcm_aes128_set_nonce_wrapper;
static void gcm_aes128_set_nonce_wrapper (void *ctx, const uint8_t *nonce)
{
  	gcm_aes128_set_iv ((struct ifm_gcm_aes128_ctx *)ctx, GCM_IV_SIZE, nonce);
}

static nettle_set_key_func gcm_aes192_set_nonce_wrapper;
static void gcm_aes192_set_nonce_wrapper (void *ctx, const uint8_t *nonce)
{
  	gcm_aes192_set_iv ((struct ifm_gcm_aes192_ctx *)ctx, GCM_IV_SIZE, nonce);
}

static nettle_set_key_func gcm_aes256_set_nonce_wrapper;
static void gcm_aes256_set_nonce_wrapper (void *ctx, const uint8_t *nonce)
{
  	gcm_aes256_set_iv ((struct ifm_gcm_aes256_ctx *)ctx, GCM_IV_SIZE, nonce);
}

const struct nettle_aead ifm_nettle_gcm_aes128 =
{ 
	"ifm_gcm_aes128", sizeof(struct ifm_gcm_aes128_ctx),
    GCM_BLOCK_SIZE, GCM_AES128_KEY_SIZE,
    GCM_IV_SIZE, GCM_DIGEST_SIZE,
    (nettle_set_key_func *) gcm_aes128_set_key,
    (nettle_set_key_func *) gcm_aes128_set_key,
    gcm_aes128_set_nonce_wrapper,
    (nettle_hash_update_func *) gcm_aes128_update,
    (nettle_crypt_func *) gcm_aes128_encrypt,
    (nettle_crypt_func *) gcm_aes128_decrypt,
    (nettle_hash_digest_func *) gcm_aes128_digest,
};

const struct nettle_aead ifm_nettle_gcm_aes192 =
{ 
	"ifm_gcm_aes192", sizeof(struct ifm_gcm_aes192_ctx),
    GCM_BLOCK_SIZE, GCM_AES192_KEY_SIZE,
    GCM_IV_SIZE, GCM_DIGEST_SIZE,
    (nettle_set_key_func *) gcm_aes192_set_key,
    (nettle_set_key_func *) gcm_aes192_set_key,
    gcm_aes192_set_nonce_wrapper,
    (nettle_hash_update_func *) gcm_aes192_update,
    (nettle_crypt_func *) gcm_aes192_encrypt,
    (nettle_crypt_func *) gcm_aes192_decrypt,
    (nettle_hash_digest_func *) gcm_aes192_digest,
};

const struct nettle_aead ifm_nettle_gcm_aes256 =
{ 
	"ifm_gcm_aes256", sizeof(struct ifm_gcm_aes256_ctx),
    GCM_BLOCK_SIZE, GCM_AES256_KEY_SIZE,
    GCM_IV_SIZE, GCM_DIGEST_SIZE,
    (nettle_set_key_func *) gcm_aes256_set_key,
    (nettle_set_key_func *) gcm_aes256_set_key,
    gcm_aes256_set_nonce_wrapper,
    (nettle_hash_update_func *) gcm_aes256_update,
    (nettle_crypt_func *) gcm_aes256_encrypt,
    (nettle_crypt_func *) gcm_aes256_decrypt,
    (nettle_hash_digest_func *) gcm_aes256_digest,
};

TEST(gcm_testcases, test_gcm_1)
{
    test_aead(&ifm_nettle_gcm_aes128, NULL,
	    SHEX("00000000000000000000000000000000"),
	    SHEX(""),
	    SHEX(""),
	    SHEX(""),
	    SHEX("000000000000000000000000"),
	    SHEX("58e2fccefa7e3061367f1d57a4e7455a"));
}

TEST(gcm_testcases, test_gcm_2)
{
    test_aead(&ifm_nettle_gcm_aes128, NULL,
	    SHEX("00000000000000000000000000000000"),
	    SHEX(""),
	    SHEX("00000000000000000000000000000000"),
	    SHEX("0388dace60b6a392f328c2b971b2fe78"),
	    SHEX("000000000000000000000000"),
	    SHEX("ab6e47d42cec13bdf53a67b21257bddf"));
}

TEST(gcm_testcases, test_gcm_3)
{
  	test_aead(&ifm_nettle_gcm_aes128, NULL,
	    SHEX("feffe9928665731c6d6a8f9467308308"),
	    SHEX(""),
	    SHEX("d9313225f88406e5a55909c5aff5269a"
		 "86a7a9531534f7da2e4c303d8a318a72"
		 "1c3c0c95956809532fcf0e2449a6b525"
		 "b16aedf5aa0de657ba637b391aafd255"),
	    SHEX("42831ec2217774244b7221b784d0d49c"
		 "e3aa212f2c02a4e035c17e2329aca12e"
		 "21d514b25466931c7d8f6a5aac84aa05"
		 "1ba30b396a0aac973d58e091473f5985"),
	    SHEX("cafebabefacedbaddecaf888"),
	    SHEX("4d5c2af327cd64a62cf35abd2ba6fab4"));
}

TEST(gcm_testcases, test_gcm_4)
{
  	test_aead(&ifm_nettle_gcm_aes128, NULL,
	    SHEX("feffe9928665731c6d6a8f9467308308"),
	    SHEX("feedfacedeadbeeffeedfacedeadbeef"
		 "abaddad2"),
	    SHEX("d9313225f88406e5a55909c5aff5269a"
		 "86a7a9531534f7da2e4c303d8a318a72"
		 "1c3c0c95956809532fcf0e2449a6b525"
		 "b16aedf5aa0de657ba637b39"),
	    SHEX("42831ec2217774244b7221b784d0d49c"
		 "e3aa212f2c02a4e035c17e2329aca12e"
		 "21d514b25466931c7d8f6a5aac84aa05"
		 "1ba30b396a0aac973d58e091"),
	    SHEX("cafebabefacedbaddecaf888"),
	    SHEX("5bc94fbc3221a5db94fae95ae7121a47"));
}

TEST(gcm_testcases, test_gcm_5)
{
  	test_aead(&ifm_nettle_gcm_aes128,
	    (nettle_hash_update_func *) gcm_aes128_set_iv,
	    SHEX("feffe9928665731c6d6a8f9467308308"),
	    SHEX("feedfacedeadbeeffeedfacedeadbeef"
		 "abaddad2"),
	    SHEX("d9313225f88406e5a55909c5aff5269a"
		 "86a7a9531534f7da2e4c303d8a318a72"
		 "1c3c0c95956809532fcf0e2449a6b525"
		 "b16aedf5aa0de657ba637b39"),
	    SHEX("61353b4c2806934a777ff51fa22a4755"
		 "699b2a714fcdc6f83766e5f97b6c7423"
		 "73806900e49f24b22b097544d4896b42"
		 "4989b5e1ebac0f07c23f4598"),
	    SHEX("cafebabefacedbad"),
	    SHEX("3612d2e79e3b0785561be14aaca2fccb"));
}

TEST(gcm_testcases, test_gcm_6)
{
  	test_aead(&ifm_nettle_gcm_aes128,
	    (nettle_hash_update_func *) gcm_aes128_set_iv,
	    SHEX("feffe9928665731c6d6a8f9467308308"),
	    SHEX("feedfacedeadbeeffeedfacedeadbeef"
		 "abaddad2"),
	    SHEX("d9313225f88406e5a55909c5aff5269a"
		 "86a7a9531534f7da2e4c303d8a318a72"
		 "1c3c0c95956809532fcf0e2449a6b525"
		 "b16aedf5aa0de657ba637b39"),
	    SHEX("8ce24998625615b603a033aca13fb894"
		 "be9112a5c3a211a8ba262a3cca7e2ca7"
		 "01e4a9a4fba43c90ccdcb281d48c7c6f"
		 "d62875d2aca417034c34aee5"),
	    SHEX("9313225df88406e555909c5aff5269aa"
		 "6a7a9538534f7da1e4c303d2a318a728"
		 "c3c0c95156809539fcf0e2429a6b5254"
		 "16aedbf5a0de6a57a637b39b"),
	    SHEX("619cc5aefffe0bfa462af43c1699d050"));
}

TEST(gcm_testcases, test_gcm_7)
{
  	test_aead(&ifm_nettle_gcm_aes192, NULL,
	    SHEX("00000000000000000000000000000000"
		 "0000000000000000"),
	    SHEX(""),
	    SHEX(""),
	    SHEX(""),
	    SHEX("000000000000000000000000"),
	    SHEX("cd33b28ac773f74ba00ed1f312572435"));
}

TEST(gcm_testcases, test_gcm_8)
{
  	test_aead(&ifm_nettle_gcm_aes192, NULL,
	    SHEX("00000000000000000000000000000000"
		 "0000000000000000"),
	    SHEX(""),
	    SHEX("00000000000000000000000000000000"),
	    SHEX("98e7247c07f0fe411c267e4384b0f600"),
	    SHEX("000000000000000000000000"),
	    SHEX("2ff58d80033927ab8ef4d4587514f0fb"));
}

TEST(gcm_testcases, test_gcm_9)
{
  	test_aead(&ifm_nettle_gcm_aes192, NULL,
	    SHEX("feffe9928665731c6d6a8f9467308308"
		 "feffe9928665731c"),
	    SHEX(""),
	    SHEX("d9313225f88406e5a55909c5aff5269a"
		 "86a7a9531534f7da2e4c303d8a318a72"
		 "1c3c0c95956809532fcf0e2449a6b525"
		 "b16aedf5aa0de657ba637b391aafd255"),
	    SHEX("3980ca0b3c00e841eb06fac4872a2757"
		 "859e1ceaa6efd984628593b40ca1e19c"
		 "7d773d00c144c525ac619d18c84a3f47"
		 "18e2448b2fe324d9ccda2710acade256"),
	    SHEX("cafebabefacedbaddecaf888"),
	    SHEX("9924a7c8587336bfb118024db8674a14"));
}

TEST(gcm_testcases, test_gcm_10)
{
  	test_aead(&ifm_nettle_gcm_aes192, NULL,
	    SHEX("feffe9928665731c6d6a8f9467308308"
		 "feffe9928665731c"),
	    SHEX("feedfacedeadbeeffeedfacedeadbeef"
		 "abaddad2"),
	    SHEX("d9313225f88406e5a55909c5aff5269a"
		 "86a7a9531534f7da2e4c303d8a318a72"
		 "1c3c0c95956809532fcf0e2449a6b525"
		 "b16aedf5aa0de657ba637b39"),
	    SHEX("3980ca0b3c00e841eb06fac4872a2757"
		 "859e1ceaa6efd984628593b40ca1e19c"
		 "7d773d00c144c525ac619d18c84a3f47"
		 "18e2448b2fe324d9ccda2710"),
	    SHEX("cafebabefacedbaddecaf888"),
	    SHEX("2519498e80f1478f37ba55bd6d27618c"));
}

TEST(gcm_testcases, test_gcm_11)
{
  	test_aead(&ifm_nettle_gcm_aes192,
	    (nettle_hash_update_func *) gcm_aes192_set_iv,
	    SHEX("feffe9928665731c6d6a8f9467308308"
		 "feffe9928665731c"),
	    SHEX("feedfacedeadbeeffeedfacedeadbeef"
		 "abaddad2"),
	    SHEX("d9313225f88406e5a55909c5aff5269a"
		 "86a7a9531534f7da2e4c303d8a318a72"
		 "1c3c0c95956809532fcf0e2449a6b525"
		 "b16aedf5aa0de657ba637b39"),
	    SHEX("0f10f599ae14a154ed24b36e25324db8"
		 "c566632ef2bbb34f8347280fc4507057"
		 "fddc29df9a471f75c66541d4d4dad1c9"
		 "e93a19a58e8b473fa0f062f7"),
	    SHEX("cafebabefacedbad"),
	    SHEX("65dcc57fcf623a24094fcca40d3533f8"));
}

TEST(gcm_testcases, test_gcm_12)
{
  	test_aead(&ifm_nettle_gcm_aes192,
	    (nettle_hash_update_func *) gcm_aes192_set_iv,
	    SHEX("feffe9928665731c6d6a8f9467308308"
		 "feffe9928665731c"),
	    SHEX("feedfacedeadbeeffeedfacedeadbeef"
		 "abaddad2"),
	    SHEX("d9313225f88406e5a55909c5aff5269a"
		 "86a7a9531534f7da2e4c303d8a318a72"
		 "1c3c0c95956809532fcf0e2449a6b525"
		 "b16aedf5aa0de657ba637b39"),
	    SHEX("d27e88681ce3243c4830165a8fdcf9ff"
		 "1de9a1d8e6b447ef6ef7b79828666e45"
		 "81e79012af34ddd9e2f037589b292db3"
		 "e67c036745fa22e7e9b7373b"),
	    SHEX("9313225df88406e555909c5aff5269aa"
		 "6a7a9538534f7da1e4c303d2a318a728"
		 "c3c0c95156809539fcf0e2429a6b5254"
		 "16aedbf5a0de6a57a637b39b"),
	    SHEX("dcf566ff291c25bbb8568fc3d376a6d9"));
}

TEST(gcm_testcases, test_gcm_13)
{
  	test_aead(&ifm_nettle_gcm_aes256, NULL,
	    SHEX("00000000000000000000000000000000"
		 "00000000000000000000000000000000"),
	    SHEX(""),
	    SHEX(""),
	    SHEX(""),
	    SHEX("000000000000000000000000"),
	    SHEX("530f8afbc74536b9a963b4f1c4cb738b"));
}

TEST(gcm_testcases, test_gcm_14)
{
  	test_aead(&ifm_nettle_gcm_aes256, NULL,
	    SHEX("00000000000000000000000000000000"
		 "00000000000000000000000000000000"),
	    SHEX(""),
	    SHEX("00000000000000000000000000000000"),
	    SHEX("cea7403d4d606b6e074ec5d3baf39d18"),
	    SHEX("000000000000000000000000"),
	    SHEX("d0d1c8a799996bf0265b98b5d48ab919"));
}

TEST(gcm_testcases, test_gcm_15)
{
    test_aead(&ifm_nettle_gcm_aes256, NULL,
	    SHEX("feffe9928665731c6d6a8f9467308308"
		 "feffe9928665731c6d6a8f9467308308"),
	    SHEX(""),
	    SHEX("d9313225f88406e5a55909c5aff5269a"
		 "86a7a9531534f7da2e4c303d8a318a72"
		 "1c3c0c95956809532fcf0e2449a6b525"
		 "b16aedf5aa0de657ba637b391aafd255"),
	    SHEX("522dc1f099567d07f47f37a32a84427d"
		 "643a8cdcbfe5c0c97598a2bd2555d1aa"
		 "8cb08e48590dbb3da7b08b1056828838"
		 "c5f61e6393ba7a0abcc9f662898015ad"),
	    SHEX("cafebabefacedbaddecaf888"),
	    SHEX("b094dac5d93471bdec1a502270e3cc6c"));
}

TEST(gcm_testcases, test_gcm_16)
{
    test_aead(&ifm_nettle_gcm_aes256, NULL,
	    SHEX("feffe9928665731c6d6a8f9467308308"
		 "feffe9928665731c6d6a8f9467308308"),
	    SHEX("feedfacedeadbeeffeedfacedeadbeef"
		 "abaddad2"),
	    SHEX("d9313225f88406e5a55909c5aff5269a"
		 "86a7a9531534f7da2e4c303d8a318a72"
		 "1c3c0c95956809532fcf0e2449a6b525"
		 "b16aedf5aa0de657ba637b39"),
	    SHEX("522dc1f099567d07f47f37a32a84427d"
		 "643a8cdcbfe5c0c97598a2bd2555d1aa"
		 "8cb08e48590dbb3da7b08b1056828838"
		 "c5f61e6393ba7a0abcc9f662"),
	    SHEX("cafebabefacedbaddecaf888"),
	    SHEX("76fc6ece0f4e1768cddf8853bb2d551b"));
}

TEST(gcm_testcases, test_gcm_17)
{
    test_aead(&ifm_nettle_gcm_aes256,
	    (nettle_hash_update_func *) gcm_aes256_set_iv,
	    SHEX("feffe9928665731c6d6a8f9467308308"
		 "feffe9928665731c6d6a8f9467308308"),
	    SHEX("feedfacedeadbeeffeedfacedeadbeef"
		 "abaddad2"),
	    SHEX("d9313225f88406e5a55909c5aff5269a"
		 "86a7a9531534f7da2e4c303d8a318a72"
		 "1c3c0c95956809532fcf0e2449a6b525"
		 "b16aedf5aa0de657ba637b39"),
	    SHEX("c3762df1ca787d32ae47c13bf19844cb"
		 "af1ae14d0b976afac52ff7d79bba9de0"
		 "feb582d33934a4f0954cc2363bc73f78"
		 "62ac430e64abe499f47c9b1f"),
	    SHEX("cafebabefacedbad"),
	    SHEX("3a337dbf46a792c45e454913fe2ea8f2"));
}

TEST(gcm_testcases, test_gcm_18)
{
    test_aead(&ifm_nettle_gcm_aes256,
	    (nettle_hash_update_func *) gcm_aes256_set_iv,
	    SHEX("feffe9928665731c6d6a8f9467308308"
		 "feffe9928665731c6d6a8f9467308308"),
	    SHEX("feedfacedeadbeeffeedfacedeadbeef"
		 "abaddad2"),
	    SHEX("d9313225f88406e5a55909c5aff5269a"
		 "86a7a9531534f7da2e4c303d8a318a72"
		 "1c3c0c95956809532fcf0e2449a6b525"
		 "b16aedf5aa0de657ba637b39"),
	    SHEX("5a8def2f0c9e53f1f75d7853659e2a20"
		 "eeb2b22aafde6419a058ab4f6f746bf4"
		 "0fc0c3b780f244452da3ebf1c5d82cde"
		 "a2418997200ef82e44ae7e3f"),
	    SHEX("9313225df88406e555909c5aff5269aa"
		 "6a7a9538534f7da1e4c303d2a318a728"
		 "c3c0c95156809539fcf0e2429a6b5254"
		 "16aedbf5a0de6a57a637b39b"),
	    SHEX("a44a8266ee1c8eb0c8b5d4cf5ae9f19a"));
}

TEST(gcm_testcases, test_gcm_19)
{
    test_gcm_hash (SDATA("a"),
		 SHEX("1521c9a442bbf63b 2293a21d4874a5fd"));
}

TEST(gcm_testcases, test_gcm_20)
{
    test_gcm_hash (SDATA("ab"),
		 SHEX("afb4592d2c7c1687 37f27271ee30412a"));
}

TEST(gcm_testcases, test_gcm_21)
{
    test_gcm_hash (SDATA("abc"), 
		 SHEX("9543ca3e1662ba03 9a921ec2a20769be"));
}

TEST(gcm_testcases, test_gcm_22)
{
    test_gcm_hash (SDATA("abcd"),
		 SHEX("8f041cc12bcb7e1b 0257a6da22ee1185"));
}

TEST(gcm_testcases, test_gcm_23)
{
    test_gcm_hash (SDATA("abcde"),
		 SHEX("0b2376e5fed58ffb 717b520c27cd5c35"));
}

TEST(gcm_testcases, test_gcm_24)
{
    test_gcm_hash (SDATA("abcdef"), 
		 SHEX("9679497a1eafa161 4942963380c1a76f"));
}

TEST(gcm_testcases, test_gcm_25)
{
    test_gcm_hash (SDATA("abcdefg"),
		 SHEX("83862e40339536bc 723d9817f7df8282"));
}

TEST(gcm_testcases, test_gcm_26)
{
    test_gcm_hash (SDATA("abcdefgh"), 
		 SHEX("b73bcc4d6815c4dc d7424a04e61b87c5"));
}

TEST(gcm_testcases, test_gcm_27)
{
    test_gcm_hash (SDATA("abcdefghi"), 
		 SHEX("8e7846a383f0b3b2 07b01160a5ef993d"));
}

TEST(gcm_testcases, test_gcm_28)
{
    test_gcm_hash (SDATA("abcdefghij"),
		 SHEX("37651643b6f8ecac 4ea1b320e6ea308c"));
}

TEST(gcm_testcases, test_gcm_29)
{
    test_gcm_hash (SDATA("abcdefghijk"), 
		 SHEX("c1ce10106ee23286 f00513f55e2226b0"));
}

TEST(gcm_testcases, test_gcm_30)
{
    test_gcm_hash (SDATA("abcdefghijkl"),
		 SHEX("c6a3e32a90196cdf b2c7a415d637e6ca"));
}

TEST(gcm_testcases, test_gcm_31)
{
    test_gcm_hash (SDATA("abcdefghijklm"), 
		 SHEX("6cca29389d4444fa 3d20e65497088fd8"));
}

TEST(gcm_testcases, test_gcm_32)
{
    test_gcm_hash (SDATA("abcdefghijklmn"),
		 SHEX("19476a997ec0a824 2022db0f0e8455ce"));
}

TEST(gcm_testcases, test_gcm_33)
{
    test_gcm_hash (SDATA("abcdefghijklmno"), 
		 SHEX("f66931cee7eadcbb d42753c3ac3c4c16"));
}

TEST(gcm_testcases, test_gcm_34)
{
    test_gcm_hash (SDATA("abcdefghijklmnop"),
		 SHEX("a79699ce8bed61f9 b8b1b4c5abb1712e"));
}

TEST(gcm_testcases, test_gcm_35)
{
    test_gcm_hash (SDATA("abcdefghijklmnopq"), 
		 SHEX("65f8245330febf15 6fd95e324304c258"));
}

TEST(gcm_testcases, test_gcm_36)
{
    test_gcm_hash (SDATA("abcdefghijklmnopqr"),
		 SHEX("d07259e85d4fc998 5a662eed41c8ed1d"));
}

TEST(gcm_testcases, test_gcm_37)
{
    test_aead(&ifm_nettle_gcm_aes128, NULL,
	    SHEX("feffe9928665731c6d6a8f9467308308"),
	    SHEX(""),
	    SHEX("d9313225f88406e5a55909c5aff5269a"
		 "86a7a9531534f7da2e4c303d8a318a72"
		 "1c3c0c95956809532fcf0e2449a6b525"
		 "b16aedf5aa0de657ba637b391aafd255"
		 "5ae376bc5e9f6a1b08e34db7a6ee0736"
		 "9ba662ea12f6f197e6bc3ed69d2480f3"
		 "ea5691347f2ba69113eb37910ebc18c8"
		 "0f697234582016fa956ca8f63ae6b473"),
	    SHEX("42831ec2217774244b7221b784d0d49c"
		 "e3aa212f2c02a4e035c17e2329aca12e"
		 "21d514b25466931c7d8f6a5aac84aa05"
		 "1ba30b396a0aac973d58e091473f5985"
		 "874b1178906ddbeab04ab2fe6cce8c57"
		 "8d7e961bd13fd6a8c56b66ca5e576492"
		 "1a48cd8bda04e66343e73055118b69b9"
		 "ced486813846958a11e602c03cfc232b"),
	    SHEX("cafebabefacedbaddecaf888"),
	    SHEX("796836f1246c9d735c5e1be0a715ccc3"));
}
