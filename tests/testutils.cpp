/******************************************************************************
 * iSula-libutils: utils library for iSula
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * Haozi007 <liuhao27@huawei.com>
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

#include "rsa_meta.h"
#include "md5_meta.h"
#include "testutils.h"
#include "cbc.h"

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
    fprintf(stderr, "\n");
	  break;
	case 8:
    fprintf(stderr, " ");
	  break;
	}
    fprintf(stderr, "%02x", data[i]);
    }
  fprintf(stderr, "\n");
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

void
test_cipher(const struct nettle_cipher *cipher,
	    const struct tstring *key,
	    const struct tstring *cleartext,
	    const struct tstring *ciphertext)
{
  void *ctx = xalloc(cipher->context_size);
  uint8_t *data = (uint8_t *)xalloc(cleartext->length);
  size_t length;
  ASSERT (cleartext->length == ciphertext->length);
  length = cleartext->length;

  ASSERT (key->length == cipher->key_size);
  memset(ctx, 0, cipher->context_size);
  cipher->set_encrypt_key(ctx, key->data);
  cipher->encrypt(ctx, length, data, cleartext->data);

  if (!MEMEQ(length, data, ciphertext->data))
    {
      fprintf(stderr, "Encrypt failed:\nInput:");
      tstring_print_hex(cleartext);
      fprintf(stderr, "\nOutput: ");
      print_hex(length, data);
      fprintf(stderr, "\nExpected:");
      tstring_print_hex(ciphertext);
      fprintf(stderr, "\n");
      FAIL();
    }
  cipher->set_decrypt_key(ctx, key->data);
  cipher->decrypt(ctx, length, data, data);

  if (!MEMEQ(length, data, cleartext->data))
    {
      fprintf(stderr, "Decrypt failed:\nInput:");
      tstring_print_hex(ciphertext);
      fprintf(stderr, "\nOutput: ");
      print_hex(length, data);
      fprintf(stderr, "\nExpected:");
      tstring_print_hex(cleartext);
      fprintf(stderr, "\n");
      FAIL();
    }

  free(ctx);
  free(data);
}


void
test_cipher_cbc(const struct nettle_cipher *cipher,
		const struct tstring *key,
		const struct tstring *cleartext,
		const struct tstring *ciphertext,
		const struct tstring *iiv)
{
  void *ctx = xalloc(cipher->context_size);
  uint8_t *data;
  uint8_t *iv = xalloc(cipher->block_size);
  size_t length;

  ASSERT (cleartext->length == ciphertext->length);
  length = cleartext->length;

  ASSERT (key->length == cipher->key_size);
  ASSERT (iiv->length == cipher->block_size);

  data = xalloc(length);  
  memset(ctx, 0, cipher->context_size);
  cipher->set_encrypt_key(ctx, key->data);
  memcpy(iv, iiv->data, cipher->block_size);

  cbc_encrypt(ctx, cipher->encrypt,
	      cipher->block_size, iv,
	      length, data, cleartext->data);

  if (!MEMEQ(length, data, ciphertext->data))
    {
      fprintf(stderr, "CBC encrypt failed:\nInput:");
      tstring_print_hex(cleartext);
      fprintf(stderr, "\nOutput: ");
      print_hex(length, data);
      fprintf(stderr, "\nExpected:");
      tstring_print_hex(ciphertext);
      fprintf(stderr, "\n");
      FAIL();
    }
  cipher->set_decrypt_key(ctx, key->data);
  memcpy(iv, iiv->data, cipher->block_size);

  cbc_decrypt(ctx, cipher->decrypt,
	      cipher->block_size, iv,
	      length, data, data);

  if (!MEMEQ(length, data, cleartext->data))
    {
      fprintf(stderr, "CBC decrypt failed:\nInput:");
      tstring_print_hex(ciphertext);
      fprintf(stderr, "\nOutput: ");
      print_hex(length, data);
      fprintf(stderr, "\nExpected:");
      tstring_print_hex(cleartext);
      fprintf(stderr, "\n");
      FAIL();
    }

  free(ctx);
  free(data);
  free(iv);
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
  uint8_t *data;
  uint8_t *buffer = xalloc(aead->digest_size);
  size_t offset;

  ASSERT (cleartext->length == ciphertext->length);

  ASSERT (key->length == aead->key_size);

  data = xalloc(cleartext->length);
  memset(ctx, 0, aead->context_size);

  ASSERT(aead->block_size > 0);

  for (offset = 0; offset <= cleartext->length; offset += aead->block_size)
    {
      /* encryption */
      aead->set_encrypt_key(ctx, key->data);

      if (nonce->length != aead->nonce_size)
	{
	  ASSERT (set_nonce);
	  set_nonce (ctx, nonce->length, nonce->data);
	}
      else
	aead->set_nonce(ctx, nonce->data);

      if (aead->update && authtext->length)
	aead->update(ctx, authtext->length, authtext->data);

      if (offset > 0)
	aead->encrypt(ctx, offset, data, cleartext->data);

      if (offset < cleartext->length)
	aead->encrypt(ctx, cleartext->length - offset,
		      data + offset, cleartext->data + offset);

      if (digest)
	{
	  ASSERT (digest->length <= aead->digest_size);
	  memset(buffer, 0, aead->digest_size);
	  aead->digest(ctx, digest->length, buffer);
	  ASSERT(MEMEQ(digest->length, buffer, digest->data));
	}
      else
	ASSERT(!aead->digest);

      ASSERT(MEMEQ(cleartext->length, data, ciphertext->data));

      /* decryption */
      if (aead->set_decrypt_key)
	{
	  aead->set_decrypt_key(ctx, key->data);

	  if (nonce->length != aead->nonce_size)
	    {
	      ASSERT (set_nonce);
	      set_nonce (ctx, nonce->length, nonce->data);
	    }
	  else
	    aead->set_nonce(ctx, nonce->data);

	  if (aead->update && authtext->length)
	    aead->update(ctx, authtext->length, authtext->data);

	  if (offset > 0)
	    aead->decrypt (ctx, offset, data, data);

	  if (offset < cleartext->length)
	    aead->decrypt(ctx, cleartext->length - offset,
			  data + offset, data + offset);
	  if (digest)
	    {
	      memset(buffer, 0, aead->digest_size);
	      aead->digest(ctx, digest->length, buffer);
	      ASSERT(MEMEQ(digest->length, buffer, digest->data));
	    }
	  ASSERT(MEMEQ(cleartext->length, data, cleartext->data));
	}
    }
  free(ctx);
  free(data);
  free(buffer);
}
