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
