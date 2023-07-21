/* basic.c  -  basic regression tests
 * Copyright (C) 2001, 2002, 2003, 2005, 2008,
 *               2009 Free Software Foundation, Inc.
 * Copyright (C) 2013 g10 Code GmbH
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <gtest/gtest.h>
#include <stddef.h>
#include <gpg-error.h>
#include "ifm_gcrypt.h"

#define PGM "basic"
#include "gcrypt_ut_common.h"

#if __GNUC__ >= 4
#  define ALWAYS_INLINE __attribute__((always_inline))
#else
#  define ALWAYS_INLINE
#endif

static int in_fips_mode;

static void
show_note (const char *format, ...)
{
  va_list arg_ptr;

  if (!verbose && getenv ("srcdir"))
    fputs ("      ", stderr);  /* To align above "PASS: ".  */
  else
    fprintf (stderr, "%s: ", PGM);
  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  if (*format && format[strlen(format)-1] != '\n')
    putc ('\n', stderr);
  va_end (arg_ptr);
}

static void
fillbuf_count (char *buf, size_t buflen, unsigned char pos)
{
  while (buflen--)
    *((unsigned char *)(buf++)) = pos++;
}

static void
show_md_not_available (int algo)
{
  static int list[100];
  static int listlen;
  int i;

  if (!verbose && algo == GCRY_MD_MD2)
    return;  /* Do not print the diagnostic for that one.  */

  for (i=0; i < listlen; i++)
    if (algo == list[i])
      return; /* Note already printed.  */
  if (listlen < DIM (list))
    list[listlen++] = algo;
  show_note ("hash algorithm %d not available - skipping tests", algo);
}


static void
show_old_hmac_not_available (int algo)
{
  static int list[100];
  static int listlen;
  int i;

  if (!verbose && algo == GCRY_MD_MD2)
    return;  /* Do not print the diagnostic for that one.  */

  for (i=0; i < listlen; i++)
    if (algo == list[i])
      return; /* Note already printed.  */
  if (listlen < DIM (list))
    list[listlen++] = algo;
  show_note ("hash algorithm %d for old HMAC API not available "
             "- skipping tests", algo);
}


static void
show_mac_not_available (int algo)
{
  static int list[100];
  static int listlen;
  int i;

  if (!verbose && algo == GCRY_MD_MD2)
    return;  /* Do not print the diagnostic for that one.  */

  for (i=0; i < listlen; i++)
    if (algo == list[i])
      return; /* Note already printed.  */
  if (listlen < DIM (list))
    list[listlen++] = algo;
  show_note ("MAC algorithm %d not available - skipping tests", algo);
}

static inline ALWAYS_INLINE void
clutter_vector_registers(void)
{
#ifdef CLUTTER_VECTOR_REGISTER_COUNT
  unsigned char data[CLUTTER_VECTOR_REGISTER_COUNT][16];
#if defined(CLUTTER_VECTOR_REGISTER_AARCH64) || \
    defined(CLUTTER_VECTOR_REGISTER_NEON)
  static int init;
  static int have_neon;

  if (!init)
    {
      char *string;

      string = gcry_get_config (0, "hwflist");
      if (string)
	{
	  have_neon = (strstr(string, "arm-neon:") != NULL);
	  xfree(string);
	}
      init = 1;
    }

  if (!have_neon)
    return;
#elif defined(CLUTTER_VECTOR_REGISTER_I386)
  static int init;
  static int have_ssse3;

  if (!init)
    {
      char *string;

      string = gcry_get_config (0, "hwflist");
      if (string)
	{
	  have_ssse3 = (strstr(string, "intel-ssse3:") != NULL);
	  xfree(string);
	}
      init = 1;
    }

  if (!have_ssse3)
    return;
#endif

  prepare_vector_data(data);

#if defined(CLUTTER_VECTOR_REGISTER_AMD64)
  asm volatile("movdqu %[data0], %%xmm0\n"
	       "movdqu %[data1], %%xmm1\n"
	       "movdqu %[data2], %%xmm2\n"
	       "movdqu %[data3], %%xmm3\n"
	       "movdqu %[data4], %%xmm4\n"
	       "movdqu %[data5], %%xmm5\n"
	       "movdqu %[data6], %%xmm6\n"
	       "movdqu %[data7], %%xmm7\n"
	       "movdqu %[data8], %%xmm8\n"
	       "movdqu %[data9], %%xmm9\n"
	       "movdqu %[data10], %%xmm10\n"
	       "movdqu %[data11], %%xmm11\n"
	       "movdqu %[data12], %%xmm12\n"
	       "movdqu %[data13], %%xmm13\n"
	       "movdqu %[data14], %%xmm14\n"
	       "movdqu %[data15], %%xmm15\n"
	      :
	      : [data0] "m" (*data[0]),
	        [data1] "m" (*data[1]),
	        [data2] "m" (*data[2]),
	        [data3] "m" (*data[3]),
	        [data4] "m" (*data[4]),
	        [data5] "m" (*data[5]),
	        [data6] "m" (*data[6]),
	        [data7] "m" (*data[7]),
	        [data8] "m" (*data[8]),
	        [data9] "m" (*data[9]),
	        [data10] "m" (*data[10]),
	        [data11] "m" (*data[11]),
	        [data12] "m" (*data[12]),
	        [data13] "m" (*data[13]),
	        [data14] "m" (*data[14]),
	        [data15] "m" (*data[15])
	      : "memory"
#ifdef __SSE2__
	       ,"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
	        "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14",
	        "xmm15"
#endif
	      );
#elif defined(CLUTTER_VECTOR_REGISTER_I386)
  asm volatile("movdqu %[data0], %%xmm0\n"
	       "movdqu %[data1], %%xmm1\n"
	       "movdqu %[data2], %%xmm2\n"
	       "movdqu %[data3], %%xmm3\n"
	       "movdqu %[data4], %%xmm4\n"
	       "movdqu %[data5], %%xmm5\n"
	       "movdqu %[data6], %%xmm6\n"
	       "movdqu %[data7], %%xmm7\n"
	      :
	      : [data0] "m" (*data[0]),
	        [data1] "m" (*data[1]),
	        [data2] "m" (*data[2]),
	        [data3] "m" (*data[3]),
	        [data4] "m" (*data[4]),
	        [data5] "m" (*data[5]),
	        [data6] "m" (*data[6]),
	        [data7] "m" (*data[7])
	      : "memory"
#ifdef __SSE2__
	       ,"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"
#endif
	      );
#elif defined(CLUTTER_VECTOR_REGISTER_AARCH64)
  asm volatile("mov x0, %[ptr]\n"
	       "ld1 {v0.16b}, [x0], #16\n"
	       "ld1 {v1.16b}, [x0], #16\n"
	       "ld1 {v2.16b}, [x0], #16\n"
	       "ld1 {v3.16b}, [x0], #16\n"
	       "ld1 {v4.16b}, [x0], #16\n"
	       "ld1 {v5.16b}, [x0], #16\n"
	       "ld1 {v6.16b}, [x0], #16\n"
	       "ld1 {v7.16b}, [x0], #16\n"
	       "ld1 {v8.16b}, [x0], #16\n"
	       "ld1 {v9.16b}, [x0], #16\n"
	       "ld1 {v10.16b}, [x0], #16\n"
	       "ld1 {v11.16b}, [x0], #16\n"
	       "ld1 {v12.16b}, [x0], #16\n"
	       "ld1 {v13.16b}, [x0], #16\n"
	       "ld1 {v14.16b}, [x0], #16\n"
	       "ld1 {v15.16b}, [x0], #16\n"
	       "ld1 {v16.16b}, [x0], #16\n"
	       "ld1 {v17.16b}, [x0], #16\n"
	       "ld1 {v18.16b}, [x0], #16\n"
	       "ld1 {v19.16b}, [x0], #16\n"
	       "ld1 {v20.16b}, [x0], #16\n"
	       "ld1 {v21.16b}, [x0], #16\n"
	       "ld1 {v22.16b}, [x0], #16\n"
	       "ld1 {v23.16b}, [x0], #16\n"
	       "ld1 {v24.16b}, [x0], #16\n"
	       "ld1 {v25.16b}, [x0], #16\n"
	       "ld1 {v26.16b}, [x0], #16\n"
	       "ld1 {v27.16b}, [x0], #16\n"
	       "ld1 {v28.16b}, [x0], #16\n"
	       "ld1 {v29.16b}, [x0], #16\n"
	       "ld1 {v30.16b}, [x0], #16\n"
	       "ld1 {v31.16b}, [x0], #16\n"
	       :
	       : [ptr] "r" (data)
	       : "x0", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
	         "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
	         "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
	         "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
	         "memory");
#elif defined(CLUTTER_VECTOR_REGISTER_NEON)
  asm volatile("mov r0, %[ptr]\n"
	       "vld1.64 {q0}, [r0]!\n"
	       "vld1.64 {q1}, [r0]!\n"
	       "vld1.64 {q2}, [r0]!\n"
	       "vld1.64 {q3}, [r0]!\n"
	       "vld1.64 {q4}, [r0]!\n"
	       "vld1.64 {q5}, [r0]!\n"
	       "vld1.64 {q6}, [r0]!\n"
	       "vld1.64 {q7}, [r0]!\n"
	       "vld1.64 {q8}, [r0]!\n"
	       "vld1.64 {q9}, [r0]!\n"
	       "vld1.64 {q10}, [r0]!\n"
	       "vld1.64 {q11}, [r0]!\n"
	       "vld1.64 {q12}, [r0]!\n"
	       "vld1.64 {q13}, [r0]!\n"
	       "vld1.64 {q14}, [r0]!\n"
	       "vld1.64 {q15}, [r0]!\n"
	       :
	       : [ptr] "r" (data)
	       : "r0", "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7",
	         "q8", "q9", "q10", "q11", "q12", "q13", "q14", "q15",
	         "memory");
#endif

#endif /* CLUTTER_VECTOR_REGISTER_COUNT */
}

static void
check_bulk_cipher_modes (void)
{
  static const struct
  {
    int algo;
    int mode;
    const char *key;
    int  keylen;
    const char *iv;
    int ivlen;
    unsigned char t1_hash[20];
  } tv[] = {
    { GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CFB,
      "abcdefghijklmnop", 16,
      "1234567890123456", 16,
/*[0]*/
      { 0x53, 0xda, 0x27, 0x3c, 0x78, 0x3d, 0x54, 0x66, 0x19, 0x63,
        0xd7, 0xe6, 0x20, 0x10, 0xcd, 0xc0, 0x5a, 0x0b, 0x06, 0xcc }
    },
    { GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CFB,
      "abcdefghijklmnopABCDEFG", 24,
      "1234567890123456", 16,
/*[1]*/
      { 0xc7, 0xb1, 0xd0, 0x09, 0x95, 0x04, 0x34, 0x61, 0x2b, 0xd9,
        0xcb, 0xb3, 0xc7, 0xcb, 0xef, 0xea, 0x16, 0x19, 0x9b, 0x3e }
    },
    { GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB,
      "abcdefghijklmnopABCDEFGHIJKLMNOP", 32,
      "1234567890123456", 16,
/*[2]*/
      { 0x31, 0xe1, 0x1f, 0x63, 0x65, 0x47, 0x8c, 0x3f, 0x53, 0xdb,
        0xd9, 0x4d, 0x91, 0x1d, 0x02, 0x9c, 0x05, 0x25, 0x58, 0x29 }
    },
    { GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC,
      "abcdefghijklmnop", 16,
      "1234567890123456", 16,
/*[3]*/
      { 0xdc, 0x0c, 0xc2, 0xd9, 0x6b, 0x47, 0xf9, 0xeb, 0x06, 0xb4,
        0x2f, 0x6e, 0xec, 0x72, 0xbf, 0x55, 0x26, 0x7f, 0xa9, 0x97 }
    },
    { GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CBC,
      "abcdefghijklmnopABCDEFG", 24,
      "1234567890123456", 16,
/*[4]*/
      { 0x2b, 0x90, 0x9b, 0xe6, 0x40, 0xab, 0x6e, 0xc2, 0xc5, 0xb1,
        0x87, 0xf5, 0x43, 0x84, 0x7b, 0x04, 0x06, 0x47, 0xd1, 0x8f }
    },
    { GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC,
      "abcdefghijklmnopABCDEFGHIJKLMNOP", 32,
      "1234567890123456", 16,
/*[5]*/
      { 0xaa, 0xa8, 0xdf, 0x03, 0xb0, 0xba, 0xc4, 0xe3, 0xc1, 0x02,
        0x38, 0x31, 0x8d, 0x86, 0xcb, 0x49, 0x6d, 0xad, 0xae, 0x01 }
    },
    { GCRY_CIPHER_AES, GCRY_CIPHER_MODE_OFB,
      "abcdefghijklmnop", 16,
      "1234567890123456", 16,
/*[6]*/
      { 0x65, 0xfe, 0xde, 0x48, 0xd0, 0xa1, 0xa6, 0xf9, 0x24, 0x6b,
        0x52, 0x5f, 0x21, 0x8a, 0x6f, 0xc7, 0x70, 0x3b, 0xd8, 0x4a }
    },
    { GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_OFB,
      "abcdefghijklmnopABCDEFG", 24,
      "1234567890123456", 16,
/*[7]*/
      { 0x59, 0x5b, 0x02, 0xa2, 0x88, 0xc0, 0xbe, 0x94, 0x43, 0xaa,
        0x39, 0xf6, 0xbd, 0xcc, 0x83, 0x99, 0xee, 0x00, 0xa1, 0x91 }
    },
    { GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_OFB,
      "abcdefghijklmnopABCDEFGHIJKLMNOP", 32,
      "1234567890123456", 16,
/*[8]*/
      { 0x38, 0x8c, 0xe1, 0xe2, 0xbe, 0x67, 0x60, 0xe8, 0xeb, 0xce,
        0xd0, 0xc6, 0xaa, 0xd6, 0xf6, 0x26, 0x15, 0x56, 0xd0, 0x2b }
    },
    { GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CTR,
      "abcdefghijklmnop", 16,
      "1234567890123456", 16,
/*[9]*/
      { 0x9a, 0x48, 0x94, 0xd6, 0x50, 0x46, 0x81, 0xdb, 0x68, 0x34,
        0x3b, 0xc5, 0x9e, 0x66, 0x94, 0x81, 0x98, 0xa0, 0xf9, 0xff }
    },
    { GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CTR,
      "abcdefghijklmnopABCDEFG", 24,
      "1234567890123456", 16,
/*[10]*/
      { 0x2c, 0x2c, 0xd3, 0x75, 0x81, 0x2a, 0x59, 0x07, 0xeb, 0x08,
        0xce, 0x28, 0x4c, 0x0c, 0x6a, 0xa8, 0x8f, 0xa3, 0x98, 0x7e }
    },
    { GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR,
      "abcdefghijklmnopABCDEFGHIJKLMNOP", 32,
      "1234567890123456", 16,
/*[11]*/
      { 0x64, 0xce, 0x73, 0x03, 0xc7, 0x89, 0x99, 0x1f, 0xf1, 0xce,
        0xfe, 0xfb, 0xb9, 0x42, 0x30, 0xdf, 0xbb, 0x68, 0x6f, 0xd3 }
    },
    { GCRY_CIPHER_AES, GCRY_CIPHER_MODE_ECB,
      "abcdefghijklmnop", 16,
      "1234567890123456", 16,
/*[12]*/
      { 0x51, 0xae, 0xf5, 0xac, 0x22, 0xa0, 0xba, 0x11, 0xc5, 0xaa,
        0xb4, 0x70, 0x99, 0xce, 0x18, 0x08, 0x12, 0x9b, 0xb1, 0xc5 }
    },
    { GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_ECB,
      "abcdefghijklmnopABCDEFG", 24,
      "1234567890123456", 16,
/*[13]*/
      { 0x57, 0x91, 0xea, 0x48, 0xd8, 0xbf, 0x9e, 0xc1, 0xae, 0x33,
        0xb3, 0xfd, 0xf7, 0x7a, 0xeb, 0x30, 0xb1, 0x62, 0x0d, 0x82 }
    },
    { GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB,
      "abcdefghijklmnopABCDEFGHIJKLMNOP", 32,
      "1234567890123456", 16,
/*[14]*/
      { 0x2d, 0x71, 0x54, 0xb9, 0xc5, 0x28, 0x76, 0xff, 0x76, 0xb5,
        0x99, 0x37, 0x99, 0x9d, 0xf7, 0x10, 0x6d, 0x86, 0x4f, 0x3f }
    },
    { GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_XTS,
      "abcdefghijklmnopABCDEFGHIJKLMNOP", 32,
      "1234567890123456", 16,
/*[15]*/
      { 0x71, 0x46, 0x40, 0xb0, 0xed, 0x6f, 0xc4, 0x82, 0x2b, 0x3f,
        0xb6, 0xf7, 0x81, 0x08, 0x4c, 0x8b, 0xc1, 0x66, 0x4c, 0x1b }
    },
    { GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_XTS,
      "abcdefghijklmnopABCDEFGHIJKLMNOP_abcdefghijklmnopABCDEFGHIJKLMNO", 64,
      "1234567890123456", 16,
/*[16]*/
      { 0x8e, 0xbc, 0xa5, 0x21, 0x0a, 0x4b, 0x53, 0x14, 0x79, 0x81,
        0x25, 0xad, 0x24, 0x45, 0x98, 0xbd, 0x9f, 0x27, 0x5f, 0x01 }
    },
    { GCRY_CIPHER_AES, GCRY_CIPHER_MODE_OFB,
      "abcdefghijklmnop", 16,
      "1234567890123456", 16,
/*[17]*/
      { 0x65, 0xfe, 0xde, 0x48, 0xd0, 0xa1, 0xa6, 0xf9, 0x24, 0x6b,
        0x52, 0x5f, 0x21, 0x8a, 0x6f, 0xc7, 0x70, 0x3b, 0xd8, 0x4a }
    },
    { GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_OFB,
      "abcdefghijklmnopABCDEFG", 24,
      "1234567890123456", 16,
/*[18]*/
      { 0x59, 0x5b, 0x02, 0xa2, 0x88, 0xc0, 0xbe, 0x94, 0x43, 0xaa,
        0x39, 0xf6, 0xbd, 0xcc, 0x83, 0x99, 0xee, 0x00, 0xa1, 0x91 }
    },
    { GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_OFB,
      "abcdefghijklmnopABCDEFGHIJKLMNOP", 32,
      "1234567890123456", 16,
/*[19]*/
      { 0x38, 0x8c, 0xe1, 0xe2, 0xbe, 0x67, 0x60, 0xe8, 0xeb, 0xce,
        0xd0, 0xc6, 0xaa, 0xd6, 0xf6, 0x26, 0x15, 0x56, 0xd0, 0x2b }
    },
  };
  gcry_cipher_hd_t hde = NULL;
  gcry_cipher_hd_t hdd = NULL;
  unsigned char *buffer_base, *outbuf_base; /* Allocated buffers.  */
  unsigned char *buffer, *outbuf;           /* Aligned buffers.  */
  size_t buflen;
  unsigned char hash[20];
  int i, j, keylen, blklen;
  gcry_error_t err = 0;

  if (verbose)
    fprintf (stderr, "Starting bulk cipher checks.\n");

  buflen = 16*100;  /* We check a 1600 byte buffer.  */
  buffer_base = gcry_xmalloc (buflen+16);
  buffer = buffer_base + (16 - ((size_t)buffer_base & 0x0f));
  outbuf_base = gcry_xmalloc (buflen+16);
  outbuf = outbuf_base + (16 - ((size_t)outbuf_base & 0x0f));


  for (i = 0; i < DIM (tv); i++)
    {
      if (verbose)
        fprintf (stderr, "    checking bulk encryption for %s [%i], mode %d\n",
		 gcry_cipher_algo_name (tv[i].algo),
		 tv[i].algo, tv[i].mode);
      err = gcry_cipher_open (&hde, tv[i].algo, tv[i].mode, 0);
      if (!err)
        err = gcry_cipher_open (&hdd, tv[i].algo, tv[i].mode, 0);
      if (err)
        {
          fail ("gcry_cipher_open failed: %s\n", gpg_strerror (err));
          goto leave;
        }

      keylen = gcry_cipher_get_algo_keylen(tv[i].algo);
      if (!keylen)
        {
          fail ("gcry_cipher_get_algo_keylen failed\n");
          goto leave;
        }

      clutter_vector_registers();
      err = gcry_cipher_setkey (hde, tv[i].key, tv[i].keylen);
      clutter_vector_registers();
      if (!err)
        err = gcry_cipher_setkey (hdd, tv[i].key, tv[i].keylen);
      if (err)
        {
          fail ("gcry_cipher_setkey failed: %s\n", gpg_strerror (err));
          goto leave;
        }

      blklen = gcry_cipher_get_algo_blklen(tv[i].algo);
      if (!blklen)
        {
          fail ("gcry_cipher_get_algo_blklen failed\n");
          goto leave;
        }

      clutter_vector_registers();
      err = gcry_cipher_setiv (hde, tv[i].iv, tv[i].ivlen);
      clutter_vector_registers();
      if (!err)
        err = gcry_cipher_setiv (hdd, tv[i].iv,  tv[i].ivlen);
      if (err)
        {
          fail ("gcry_cipher_setiv failed: %s\n", gpg_strerror (err));
          goto leave;
        }

      /* Fill the buffer with our test pattern.  */
      for (j=0; j < buflen; j++)
        buffer[j] = ((j & 0xff) ^ ((j >> 8) & 0xff));

      clutter_vector_registers();
      err = gcry_cipher_encrypt (hde, outbuf, buflen, buffer, buflen);
      if (err)
        {
          fail ("gcry_cipher_encrypt (algo %d, mode %d) failed: %s\n",
                tv[i].algo, tv[i].mode, gpg_strerror (err));
          goto leave;
        }

      gcry_md_hash_buffer (GCRY_MD_SHA1, hash, outbuf, buflen);
#if 0
      printf ("/*[%d]*/\n", i);
      fputs ("      {", stdout);
      for (j=0; j < 20; j++)
        printf (" 0x%02x%c%s", hash[j], j==19? ' ':',', j == 9? "\n       ":"");
      puts ("}");
#endif

      if (memcmp (hash, tv[i].t1_hash, 20))
        fail ("encrypt mismatch (algo %d, mode %d)\n",
              tv[i].algo, tv[i].mode);

      clutter_vector_registers();
      err = gcry_cipher_decrypt (hdd, outbuf, buflen, NULL, 0);
      if (err)
        {
          fail ("gcry_cipher_decrypt (algo %d, mode %d) failed: %s\n",
                tv[i].algo, tv[i].mode, gpg_strerror (err));
          goto leave;
        }

      if (memcmp (buffer, outbuf, buflen))
        fail ("decrypt mismatch (algo %d, mode %d)\n",
              tv[i].algo, tv[i].mode);

      gcry_cipher_close (hde); hde = NULL;
      gcry_cipher_close (hdd); hdd = NULL;
    }

  if (verbose)
    fprintf (stderr, "Completed bulk cipher checks.\n");
 leave:
  gcry_cipher_close (hde);
  gcry_cipher_close (hdd);
  gcry_free (buffer_base);
  gcry_free (outbuf_base);
}

TEST(gcrypt_basic_cipher_ut, gcrypt_basic_cipher_testcases){
    // check_ciphers ();
    // check_cipher_modes ();
    check_bulk_cipher_modes ();
}
