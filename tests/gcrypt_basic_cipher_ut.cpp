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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <gtest/gtest.h>
#include <stddef.h>
#include <gpg-error.h>
#include "ifm_gcrypt.h"
#include "ifm_utils.h"
#define gcry_md_handle gcry_uadk_md_hd
#define gcry_md_hd_t gcry_uadk_md_hd_t
#define gcry_cipher_handle gcry_uadk_aes_hd
#define gcry_cipher_hd_t gcry_uadk_aes_hd_t

#define PGM "basic"
#include "gcrypt_ut_common.h"

#if __GNUC__ >= 4
#  define ALWAYS_INLINE __attribute__((always_inline))
#else
#  define ALWAYS_INLINE
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif


static int in_fips_mode;

#define MAX_DATA_LEN 1040

// check if realy use uadk, if should use uadk, but do not use, assert fail
static void check_use_uadk(gcry_cipher_hd_t hd, int algo, int mode, int inlen, int ivlen, int keylen)
{
#ifdef __aarch64__
    if (UadkEnabled() == false) {
        ASSERT(hd->use_uadk == false);
        return;
    }
    if (algo != GCRY_CIPHER_AES && algo != GCRY_CIPHER_AES192 && algo != GCRY_CIPHER_AES256) {
        ASSERT(hd->use_uadk == false);
        return;
    }
    if (mode != GCRY_CIPHER_MODE_ECB && mode != GCRY_CIPHER_MODE_CBC &&
        mode != GCRY_CIPHER_MODE_XTS && mode != GCRY_CIPHER_MODE_OFB) {
        ASSERT(hd->use_uadk == false);
        return;
    }
    if (algo == GCRY_CIPHER_AES192 && mode == GCRY_CIPHER_MODE_XTS) {
        ASSERT(hd->use_uadk == false);
        return;
    }
    if (ivlen != 0 && ivlen != CIPHER_IV_SIZE) {
        ASSERT(hd->use_uadk == false);
        return;
    }
    if (inlen >= MAX_CIPHER_LENGTH && inlen % AES_BLOCK_SIZE != 0) {
        ASSERT(hd->use_uadk == false);
        return;
    }
    IFM_ERR("alg [%s] mode [%s] inlen [%d] ivlen [%d] keylen [%d], should use uadk\n", \
            algo, mode, inlen, ivlen, keylen);
    ASSERT(hd->use_uadk == true);
#endif
    return;
}

static void
mismatch (const void *expected, size_t expectedlen,
          const void *computed, size_t computedlen)
{
    const unsigned char *p;

    fprintf (stderr, "expected:");
    for (p = expected; expectedlen; p++, expectedlen--)
        fprintf (stderr, " %02x", *p);
    fprintf (stderr, "\ncomputed:");
    for (p = computed; computedlen; p++, computedlen--)
        fprintf (stderr, " %02x", *p);
    fprintf (stderr, "\n");
}

static void *
hex2buffer (const char *string, size_t *r_length)
{
    const char *s;
    unsigned char *buffer;
    size_t length;

    buffer = xmalloc (strlen(string)/2+1);
    length = 0;
    for (s=string; *s; s +=2 )
    {
        if (!hexdigitp (s) || !hexdigitp (s+1))
            die ("invalid hex digits in \"%s\"\n", string);
        ((unsigned char*)buffer)[length++] = xtoi_2 (s);
    }
    *r_length = length;
    return buffer;
}

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

static unsigned int
get_algo_mode_blklen (int algo, int mode)
{
    unsigned int blklen = gcry_cipher_get_algo_blklen(algo);

    /* Some modes override blklen. */
    switch (mode)
    {
        case GCRY_CIPHER_MODE_STREAM:
        case GCRY_CIPHER_MODE_OFB:
        case GCRY_CIPHER_MODE_CTR:
        case GCRY_CIPHER_MODE_CFB:
        case GCRY_CIPHER_MODE_CFB8:
        case GCRY_CIPHER_MODE_CCM:
        case GCRY_CIPHER_MODE_GCM:
        case GCRY_CIPHER_MODE_EAX:
        case GCRY_CIPHER_MODE_POLY1305:
            return 1;
    }

    return blklen;
}


static unsigned int
get_algo_mode_taglen (int algo, int mode)
{
    switch (mode)
    {
        case GCRY_CIPHER_MODE_CCM:
        case GCRY_CIPHER_MODE_GCM:
        case GCRY_CIPHER_MODE_POLY1305:
            return 16;
        case GCRY_CIPHER_MODE_EAX:
            return gcry_cipher_get_algo_blklen(algo);
    }

    return 0;
}


static int
check_one_cipher_core_reset (gcry_cipher_hd_t hd, int algo, int mode, int pass,
                             int nplain)
{
    static const unsigned char iv[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
    unsigned int ctl_params[3];
    int err;

    gcry_cipher_reset (hd);

    if (mode == GCRY_CIPHER_MODE_OCB || mode == GCRY_CIPHER_MODE_CCM)
    {
        clutter_vector_registers();
        err = gcry_cipher_setiv (hd, iv, sizeof(iv));
        if (err)
        {
            fail ("pass %d, algo %d, mode %d, gcry_cipher_setiv failed: %s\n",
                  pass, algo, mode, gpg_strerror (err));
            gcry_cipher_close (hd);
            return -1;
        }
    }

    if (mode == GCRY_CIPHER_MODE_CCM)
    {
        ctl_params[0] = nplain; /* encryptedlen */
        ctl_params[1] = 0; /* aadlen */
        ctl_params[2] = 16; /* authtaglen */
        err = gcry_cipher_ctl (hd, GCRYCTL_SET_CCM_LENGTHS, ctl_params,
                               sizeof(ctl_params));
        if (err)
        {
            fail ("pass %d, algo %d, mode %d, gcry_cipher_ctl "
                  "GCRYCTL_SET_CCM_LENGTHS failed: %s\n",
                  pass, algo, mode, gpg_strerror (err));
            gcry_cipher_close (hd);
            return -1;
        }
    }

    return 0;
}

/* The core of the cipher check.  In addition to the parameters passed
   to check_one_cipher it also receives the KEY and the plain data.
   PASS is printed with error messages.  The function returns 0 on
   success.  */
static int
check_one_cipher_core (int algo, int mode, int flags,
                       const char *key, size_t nkey,
                       const unsigned char *plain, size_t nplain,
                       int bufshift, int pass)
{
    gcry_cipher_hd_t hd;
    unsigned char *in_buffer, *out_buffer;
    unsigned char *enc_result;
    unsigned char tag_result[16];
    unsigned char tag[16];
    unsigned char *in, *out;
    int keylen;
    gcry_error_t err = 0;
    unsigned int blklen;
    unsigned int piecelen;
    unsigned int pos;
    unsigned int taglen;

    in_buffer = malloc (nplain + 1);
    out_buffer = malloc (nplain + 1);
    enc_result = malloc (nplain);
    if (!in_buffer || !out_buffer || !enc_result)
    {
        fail ("pass %d, algo %d, mode %d, malloc failed\n",
              pass, algo, mode);
        goto err_out_free;
    }

    blklen = get_algo_mode_blklen(algo, mode);
    taglen = get_algo_mode_taglen(algo, mode);

    assert (nkey == 64);
    assert (nplain > 0);
    assert ((nplain % 16) == 0);
    assert (blklen > 0);

    if ((mode == GCRY_CIPHER_MODE_CBC && (flags & GCRY_CIPHER_CBC_CTS)) ||
        mode == GCRY_CIPHER_MODE_XTS)
    {
        /* Input cannot be split in to multiple operations with CTS. */
        blklen = nplain;
    }

    if (!bufshift)
    {
        in = in_buffer;
        out = out_buffer;
    }
    else if (bufshift == 1)
    {
        in = in_buffer+1;
        out = out_buffer;
    }
    else if (bufshift == 2)
    {
        in = in_buffer+1;
        out = out_buffer+1;
    }
    else
    {
        in = in_buffer;
        out = out_buffer+1;
    }

    keylen = gcry_cipher_get_algo_keylen (algo);
    if (!keylen)
    {
        fail ("pass %d, algo %d, mode %d, gcry_cipher_get_algo_keylen failed\n",
              pass, algo, mode);
        goto err_out_free;
    }

    if (keylen < 40 / 8 || keylen > 32)
    {
        fail ("pass %d, algo %d, mode %d, keylength problem (%d)\n", pass, algo, mode, keylen);
        goto err_out_free;
    }

    if (mode == GCRY_CIPHER_MODE_XTS)
    {
        keylen *= 2;
    }

    err = gcry_cipher_open (&hd, algo, mode, flags);
    if (err)
    {
        fail ("pass %d, algo %d, mode %d, gcry_cipher_open failed: %s\n",
              pass, algo, mode, gpg_strerror (err));
        goto err_out_free;
    }

    clutter_vector_registers();
    err = gcry_cipher_setkey (hd, key, keylen);
    if (err)
    {
        fail ("pass %d, algo %d, mode %d, gcry_cipher_setkey failed: %s\n",
              pass, algo, mode, gpg_strerror (err));
        gcry_cipher_close (hd);
        goto err_out_free;
    }

    if (check_one_cipher_core_reset (hd, algo, mode, pass, nplain) < 0)
        goto err_out_free;

    clutter_vector_registers();
    err = gcry_cipher_encrypt (hd, out, nplain, plain, nplain);
    if (err)
    {
        fail ("pass %d, algo %d, mode %d, gcry_cipher_encrypt failed: %s\n",
              pass, algo, mode, gpg_strerror (err));
        gcry_cipher_close (hd);
        goto err_out_free;
    }

    if (taglen > 0)
    {
        clutter_vector_registers();
        err = gcry_cipher_gettag (hd, tag, taglen);
        if (err)
        {
            fail ("pass %d, algo %d, mode %d, gcry_cipher_gettag failed: %s\n",
                  pass, algo, mode, gpg_strerror (err));
            gcry_cipher_close (hd);
            goto err_out_free;
        }

        memcpy(tag_result, tag, taglen);
    }

    memcpy (enc_result, out, nplain);

    if (check_one_cipher_core_reset (hd, algo, mode, pass, nplain) < 0)
        goto err_out_free;

    clutter_vector_registers();
    err = gcry_cipher_decrypt (hd, in, nplain, out, nplain);
    if (err)
    {
        fail ("pass %d, algo %d, mode %d, gcry_cipher_decrypt failed: %s\n",
              pass, algo, mode, gpg_strerror (err));
        gcry_cipher_close (hd);
        goto err_out_free;
    }

    if (taglen > 0)
    {
        clutter_vector_registers();
        err = gcry_cipher_checktag (hd, tag_result, taglen);
        if (err)
        {
            fail ("pass %d, algo %d, mode %d, gcry_cipher_checktag failed: %s\n",
                  pass, algo, mode, gpg_strerror (err));
            gcry_cipher_close (hd);
            goto err_out_free;
        }
    }

    if (memcmp (plain, in, nplain))
        fail ("pass %d, algo %d, mode %d, encrypt-decrypt mismatch\n",
              pass, algo, mode);

    /* Again, using in-place encryption.  */
    if (check_one_cipher_core_reset (hd, algo, mode, pass, nplain) < 0)
        goto err_out_free;

    memcpy (out, plain, nplain);
    clutter_vector_registers();
    err = gcry_cipher_encrypt (hd, out, nplain, NULL, 0);
    if (err)
    {
        fail ("pass %d, algo %d, mode %d, in-place, gcry_cipher_encrypt failed:"
              " %s\n",
              pass, algo, mode, gpg_strerror (err));
        gcry_cipher_close (hd);
        goto err_out_free;
    }

    if (taglen > 0)
    {
        err = gcry_cipher_gettag (hd, tag, taglen);
        if (err)
        {
            fail ("pass %d, algo %d, mode %d, in-place, "
                  "gcry_cipher_gettag failed: %s\n",
                  pass, algo, mode, gpg_strerror (err));
            gcry_cipher_close (hd);
            goto err_out_free;
        }

        if (memcmp (tag_result, tag, taglen))
            fail ("pass %d, algo %d, mode %d, in-place, tag mismatch\n",
                  pass, algo, mode);
    }

    if (memcmp (enc_result, out, nplain))
        fail ("pass %d, algo %d, mode %d, in-place, encrypt mismatch\n",
              pass, algo, mode);

    if (check_one_cipher_core_reset (hd, algo, mode, pass, nplain) < 0)
        goto err_out_free;

    clutter_vector_registers();
    err = gcry_cipher_decrypt (hd, out, nplain, NULL, 0);
    if (err)
    {
        fail ("pass %d, algo %d, mode %d, in-place, gcry_cipher_decrypt failed:"
              " %s\n",
              pass, algo, mode, gpg_strerror (err));
        gcry_cipher_close (hd);
        goto err_out_free;
    }

    if (taglen > 0)
    {
        clutter_vector_registers();
        err = gcry_cipher_checktag (hd, tag_result, taglen);
        if (err)
        {
            fail ("pass %d, algo %d, mode %d, in-place, "
                  "gcry_cipher_checktag failed: %s\n",
                  pass, algo, mode, gpg_strerror (err));
            gcry_cipher_close (hd);
            goto err_out_free;
        }
    }

    if (memcmp (plain, out, nplain))
        fail ("pass %d, algo %d, mode %d, in-place, encrypt-decrypt mismatch\n",
              pass, algo, mode);

    /* Again, splitting encryption in multiple operations. */
    if (check_one_cipher_core_reset (hd, algo, mode, pass, nplain) < 0)
        goto err_out_free;

    piecelen = blklen;
    pos = 0;
    while (pos < nplain)
    {
        if (piecelen > nplain - pos)
            piecelen = nplain - pos;

        clutter_vector_registers();
        err = gcry_cipher_encrypt (hd, out + pos, piecelen, plain + pos,
                                   piecelen);
        if (err)
        {
            fail ("pass %d, algo %d, mode %d, split-buffer (pos: %d, "
                  "piecelen: %d), gcry_cipher_encrypt failed: %s\n",
                  pass, algo, mode, pos, piecelen, gpg_strerror (err));
            gcry_cipher_close (hd);
            goto err_out_free;
        }

        pos += piecelen;
        piecelen = piecelen * 2 - ((piecelen != blklen) ? blklen : 0);
    }

    if (taglen > 0)
    {
        clutter_vector_registers();
        err = gcry_cipher_gettag (hd, tag, taglen);
        if (err)
        {
            fail ("pass %d, algo %d, mode %d, split-buffer (pos: %d, "
                  "piecelen: %d), gcry_cipher_gettag failed: %s\n",
                  pass, algo, mode, pos, piecelen, gpg_strerror (err));
            gcry_cipher_close (hd);
            goto err_out_free;
        }

        if (memcmp (tag_result, tag, taglen))
            fail ("pass %d, algo %d, mode %d, in-place, tag mismatch\n",
                  pass, algo, mode);
    }

    if (memcmp (enc_result, out, nplain))
        fail ("pass %d, algo %d, mode %d, split-buffer, encrypt mismatch\n",
              pass, algo, mode);

    if (check_one_cipher_core_reset (hd, algo, mode, pass, nplain) < 0)
        goto err_out_free;

    piecelen = blklen;
    pos = 0;
    while (pos < nplain)
    {
        if (piecelen > nplain - pos)
            piecelen = nplain - pos;

        clutter_vector_registers();
        err = gcry_cipher_decrypt (hd, in + pos, piecelen, out + pos, piecelen);
        if (err)
        {
            fail ("pass %d, algo %d, mode %d, split-buffer (pos: %d, "
                  "piecelen: %d), gcry_cipher_decrypt failed: %s\n",
                  pass, algo, mode, pos, piecelen, gpg_strerror (err));
            gcry_cipher_close (hd);
            goto err_out_free;
        }

        pos += piecelen;
        piecelen = piecelen * 2 - ((piecelen != blklen) ? blklen : 0);
    }

    if (taglen > 0)
    {
        clutter_vector_registers();
        err = gcry_cipher_checktag (hd, tag_result, taglen);
        if (err)
        {
            fail ("pass %d, algo %d, mode %d, split-buffer (pos: %d, "
                  "piecelen: %d), gcry_cipher_checktag failed: %s\n",
                  pass, algo, mode, pos, piecelen, gpg_strerror (err));
            gcry_cipher_close (hd);
            goto err_out_free;
        }
    }

    if (memcmp (plain, in, nplain))
        fail ("pass %d, algo %d, mode %d, split-buffer, encrypt-decrypt mismatch\n",
              pass, algo, mode);

    /* Again, using in-place encryption and splitting encryption in multiple
     * operations. */
    if (check_one_cipher_core_reset (hd, algo, mode, pass, nplain) < 0)
        goto err_out_free;

    piecelen = blklen;
    pos = 0;
    while (pos < nplain)
    {
        if (piecelen > nplain - pos)
            piecelen = nplain - pos;

        memcpy (out + pos, plain + pos, piecelen);
        clutter_vector_registers();
        err = gcry_cipher_encrypt (hd, out + pos, piecelen, NULL, 0);
        if (err)
        {
            fail ("pass %d, algo %d, mode %d, in-place split-buffer (pos: %d, "
                  "piecelen: %d), gcry_cipher_encrypt failed: %s\n",
                  pass, algo, mode, pos, piecelen, gpg_strerror (err));
            gcry_cipher_close (hd);
            goto err_out_free;
        }

        pos += piecelen;
        piecelen = piecelen * 2 - ((piecelen != blklen) ? blklen : 0);
    }

    if (memcmp (enc_result, out, nplain))
        fail ("pass %d, algo %d, mode %d, in-place split-buffer, encrypt mismatch\n",
              pass, algo, mode);

    if (check_one_cipher_core_reset (hd, algo, mode, pass, nplain) < 0)
        goto err_out_free;

    piecelen = blklen;
    pos = 0;
    while (pos < nplain)
    {
        if (piecelen > nplain - pos)
            piecelen = nplain - pos;

        clutter_vector_registers();
        err = gcry_cipher_decrypt (hd, out + pos, piecelen, NULL, 0);
        if (err)
        {
            fail ("pass %d, algo %d, mode %d, in-place split-buffer (pos: %d, "
                  "piecelen: %d), gcry_cipher_decrypt failed: %s\n",
                  pass, algo, mode, pos, piecelen, gpg_strerror (err));
            gcry_cipher_close (hd);
            goto err_out_free;
        }

        pos += piecelen;
        piecelen = piecelen * 2 - ((piecelen != blklen) ? blklen : 0);
    }

    if (memcmp (plain, out, nplain))
        fail ("pass %d, algo %d, mode %d, in-place split-buffer, encrypt-decrypt"
              " mismatch\n", pass, algo, mode);

    check_use_uadk(hd, algo, mode, nplain, 0, keylen);

    gcry_cipher_close (hd);

    free (enc_result);
    free (out_buffer);
    free (in_buffer);
    return 0;

    err_out_free:
    free (enc_result);
    free (out_buffer);
    free (in_buffer);
    return -1;
}



static int
check_one_cipher_ctr_reset (gcry_cipher_hd_t hd, int algo, int mode,
                            unsigned int ctr_high_bits, int be_ctr,
                            int pass)
{
    unsigned char iv[16] = { 0 };
    unsigned char swap;
    unsigned int ivlen;
    unsigned int ctr_low_bits;
    int err;
    int i;

    /* This should be largest parallel block processing count in any
     * implementation negated. Currently for CTR this is 32 and, for
     * ChaCha20, count is 8. */
    ctr_low_bits = (mode == GCRY_CIPHER_MODE_CTR) ? -32 : -8;

    gcry_cipher_reset (hd);

    if (mode == GCRY_CIPHER_MODE_CTR)
        ivlen = get_algo_mode_blklen(algo, GCRY_CIPHER_MODE_ECB);
    else
        ivlen = 16;

    /* Little-endian fill. */
    for (i = 0; i < 4; i++)
        iv[i + 0] = (ctr_low_bits >> (i * 8)) & 0xff;
    for (i = 0; i < 4; i++)
        iv[i + 4] = (ctr_high_bits >> (i * 8)) & 0xff;

    if (be_ctr)
    {
        /* Swap to big-endian. */
        for (i = 0; i < ivlen / 2; i++)
        {
            swap = iv[i];
            iv[i] = iv[ivlen - (i + 1)];
            iv[ivlen - (i + 1)] = swap;
        }
    }

    clutter_vector_registers();
    if (mode == GCRY_CIPHER_MODE_CTR)
        err = gcry_cipher_setctr (hd, iv, ivlen);
    else
        err = gcry_cipher_setiv (hd, iv, ivlen);

    if (err)
    {
        fail ("pass %d, algo %d, mode %d, gcry_cipher_setiv failed: %s\n",
              pass, algo, mode, gpg_strerror (err));
        gcry_cipher_close (hd);
        return -1;
    }

    return 0;
}

static int
check_one_cipher_ctr_overflow (int algo, int mode, int flags,
                               const char *key, size_t nkey,
                               const unsigned char *plain, size_t nplain,
                               unsigned long ctr_high_bits, int be_ctr,
                               int pass)
{
    gcry_cipher_hd_t hd;
    unsigned char *out;
    unsigned char *enc_result;
    int keylen;
    gcry_error_t err = 0;
    unsigned int firstlen;
    unsigned int leftlen;
    unsigned int blklen;
    unsigned int pos;
    unsigned int i;

    out = malloc (nplain);
    enc_result = malloc (nplain);
    if (!out || !enc_result)
    {
        fail ("pass %d, algo %d, mode %d, malloc failed\n",
              pass, algo, mode);
        goto err_out_free;
    }

    assert (nkey == 64);
    assert (nplain > 0);
    assert ((nplain % 16) == 0);

    keylen = gcry_cipher_get_algo_keylen (algo);
    if (!keylen)
    {
        fail ("pass %d, algo %d, mode %d, gcry_cipher_get_algo_keylen failed\n",
              pass, algo, mode);
        goto err_out_free;
    }

    if (keylen < 40 / 8 || keylen > 32)
    {
        fail ("pass %d, algo %d, mode %d, keylength problem (%d)\n",
              pass, algo, mode, keylen);
        goto err_out_free;
    }

    err = gcry_cipher_open (&hd, algo, mode, flags);
    if (err)
    {
        fail ("pass %d, algo %d, mode %d, gcry_cipher_open failed: %s\n",
              pass, algo, mode, gpg_strerror (err));
        goto err_out_free;
    }

    clutter_vector_registers();
    err = gcry_cipher_setkey (hd, key, keylen);
    if (err)
    {
        fail ("pass %d, algo %d, mode %d, gcry_cipher_setkey failed: %s\n",
              pass, algo, mode, gpg_strerror (err));
        gcry_cipher_close (hd);
        goto err_out_free;
    }

    if (check_one_cipher_ctr_reset (hd, algo, mode, ctr_high_bits, be_ctr,
                                    pass) < 0)
        goto err_out_free;

    /* Non-bulk processing. */
    for (i = 0; i < nplain; i += 16)
    {
        clutter_vector_registers();
        err = gcry_cipher_encrypt (hd, out + i, 16, plain + i, 16);
        if (err)
        {
            fail ("pass %d, algo %d, mode %d, gcry_cipher_encrypt failed: %s\n",
                  pass, algo, mode, gpg_strerror (err));
            gcry_cipher_close (hd);
            goto err_out_free;
        }
    }

    memcpy (enc_result, out, nplain);

    /* Test with different bulk processing sizes. */
    for (blklen = 2 * 16; blklen <= 32 * 16; blklen *= 2)
    {
        /* Move bulk processing start offset, test at different spots to
         * test bulk counter calculation throughly. */
        for (firstlen = 16; firstlen < 8 * 64; firstlen += 16)
        {
            if (check_one_cipher_ctr_reset (hd, algo, mode, ctr_high_bits, be_ctr,
                                            pass) < 0)
                goto err_out_free;

            clutter_vector_registers();
            err = gcry_cipher_encrypt (hd, out, firstlen, plain, firstlen);
            if (err)
            {
                fail ("pass %d, algo %d, mode %d, gcry_cipher_encrypt "
                      "failed: %s\n", pass, algo, mode, gpg_strerror (err));
                gcry_cipher_close (hd);
                goto err_out_free;
            }

            leftlen = nplain - firstlen;
            pos = firstlen;
            while (leftlen)
            {
                unsigned int currlen = leftlen > blklen ? blklen : leftlen;

                clutter_vector_registers();
                err = gcry_cipher_encrypt (hd, out + pos, currlen, plain + pos,
                                           currlen);
                if (err)
                {
                    fail ("pass %d, algo %d, mode %d, block len %d, first len %d,"
                          "gcry_cipher_encrypt failed: %s\n", pass, algo, mode,
                          blklen, firstlen, gpg_strerror (err));
                    gcry_cipher_close (hd);
                    goto err_out_free;
                }

                pos += currlen;
                leftlen -= currlen;
            }

            if (memcmp (enc_result, out, nplain))
                fail ("pass %d, algo %d, mode %d, block len %d, first len %d, "
                      "encrypt mismatch\n", pass, algo, mode, blklen, firstlen);
        }
    }

    gcry_cipher_close (hd);

    free (enc_result);
    free (out);
    return 0;

    err_out_free:
    free (enc_result);
    free (out);
    return -1;
}

static void
check_one_cipher (int algo, int mode, int flags)
{
    size_t medium_buffer_size = 2048 - 16;
    size_t large_buffer_size = 64 * 1024 + 1024 - 16;
    char key[64+1];
    unsigned char *plain;
    int bufshift, i;

    plain = malloc (large_buffer_size + 1);
    if (!plain)
    {
        fail ("pass %d, algo %d, mode %d, malloc failed\n", -1, algo, mode);
        return;
    }

    for (bufshift = 0; bufshift < 4; bufshift++)
    {
        /* Pass 0: Standard test.  */
        memcpy (key, "0123456789abcdef.,;/[]{}-=ABCDEF_"
                     "0123456789abcdef.,;/[]{}-=ABCDEF", 64);
        memcpy (plain, "foobar42FOOBAR17", 16);
        for (i = 16; i < medium_buffer_size; i += 16)
        {
            memcpy (&plain[i], &plain[i-16], 16);
            if (!++plain[i+7])
                plain[i+6]++;
            if (!++plain[i+15])
                plain[i+14]++;
        }

        if (check_one_cipher_core (algo, mode, flags, key, 64, plain,
                                   medium_buffer_size, bufshift,
                                   0+10*bufshift))
            goto out;

        /* Pass 1: Key not aligned.  */
        memmove (key+1, key, 64);
        if (check_one_cipher_core (algo, mode, flags, key+1, 64, plain,
                                   medium_buffer_size, bufshift,
                                   1+10*bufshift))
            goto out;

        /* Pass 2: Key not aligned and data not aligned.  */
        memmove (plain+1, plain, medium_buffer_size);
        if (check_one_cipher_core (algo, mode, flags, key+1, 64, plain+1,
                                   medium_buffer_size, bufshift,
                                   2+10*bufshift))
            goto out;

        /* Pass 3: Key aligned and data not aligned.  */
        memmove (key, key+1, 64);
        if (check_one_cipher_core (algo, mode, flags, key, 64, plain+1,
                                   medium_buffer_size, bufshift,
                                   3+10*bufshift))
            goto out;
    }

    /* Pass 5: Large buffer test.  */
    memcpy (key, "0123456789abcdef.,;/[]{}-=ABCDEF_"
                 "0123456789abcdef.,;/[]{}-=ABCDEF", 64);
    memcpy (plain, "foobar42FOOBAR17", 16);
    for (i = 16; i < large_buffer_size; i += 16)
    {
        memcpy (&plain[i], &plain[i-16], 16);
        if (!++plain[i+7])
            plain[i+6]++;
        if (!++plain[i+15])
            plain[i+14]++;
    }

    if (check_one_cipher_core (algo, mode, flags, key, 64, plain,
                               large_buffer_size, bufshift,
                               50))
        goto out;

    /* Pass 6: Counter overflow tests for ChaCha20 and CTR mode. */
    if (mode == GCRY_CIPHER_MODE_STREAM && algo == GCRY_CIPHER_CHACHA20)
    {
        /* 32bit overflow test (little-endian counter) */
        if (check_one_cipher_ctr_overflow (algo, mode, flags, key, 64, plain,
                                           medium_buffer_size, 0UL,
                                           0, 60))
            goto out;
        /* 64bit overflow test (little-endian counter) */
        if (check_one_cipher_ctr_overflow (algo, mode, flags, key, 64, plain,
                                           medium_buffer_size, 0xffffffffUL,
                                           0, 61))
            goto out;
    }
    else if (mode == GCRY_CIPHER_MODE_CTR)
    {
        /* 32bit overflow test (big-endian counter) */
        if (check_one_cipher_ctr_overflow (algo, mode, flags, key, 64, plain,
                                           medium_buffer_size, 0UL,
                                           1, 62))
            goto out;
        /* 64bit overflow test (big-endian counter) */
        if (check_one_cipher_ctr_overflow (algo, mode, flags, key, 64, plain,
                                           medium_buffer_size, 0xffffffffUL,
                                           1, 63))
            goto out;
    }

    out:
    free (plain);
}



static void
check_ciphers (void)
{
    static const int algos[] = {
#if USE_BLOWFISH
            GCRY_CIPHER_BLOWFISH,
#endif
#if USE_DES
            GCRY_CIPHER_DES,
    GCRY_CIPHER_3DES,
#endif
#if USE_CAST5
            GCRY_CIPHER_CAST5,
#endif
#if USE_AES
            GCRY_CIPHER_AES,
    GCRY_CIPHER_AES192,
    GCRY_CIPHER_AES256,
#endif
#if USE_TWOFISH
            GCRY_CIPHER_TWOFISH,
    GCRY_CIPHER_TWOFISH128,
#endif
#if USE_SERPENT
            GCRY_CIPHER_SERPENT128,
    GCRY_CIPHER_SERPENT192,
    GCRY_CIPHER_SERPENT256,
#endif
#if USE_RFC2268
            GCRY_CIPHER_RFC2268_40,
#endif
#if USE_SEED
            GCRY_CIPHER_SEED,
#endif
#if USE_CAMELLIA
            GCRY_CIPHER_CAMELLIA128,
    GCRY_CIPHER_CAMELLIA192,
    GCRY_CIPHER_CAMELLIA256,
#endif
#if USE_IDEA
            GCRY_CIPHER_IDEA,
#endif
#if USE_GOST28147
            GCRY_CIPHER_GOST28147,
    GCRY_CIPHER_GOST28147_MESH,
#endif
#if USE_SM4
            GCRY_CIPHER_SM4,
#endif
            0
    };
    static const int algos2[] = {
#if USE_ARCFOUR
            GCRY_CIPHER_ARCFOUR,
#endif
#if USE_SALSA20
            GCRY_CIPHER_SALSA20,
    GCRY_CIPHER_SALSA20R12,
#endif
#if USE_CHACHA20
            GCRY_CIPHER_CHACHA20,
#endif
            0
    };
    int i;

    if (verbose)
        fprintf (stderr, "Starting Cipher checks.\n");
    for (i = 0; algos[i]; i++)
    {
        if (gcry_cipher_test_algo (algos[i]) && in_fips_mode)
        {
            if (verbose)
                fprintf (stderr, "  algorithm %d not available in fips mode\n",
                         algos[i]);
            continue;
        }
        if (verbose)
            fprintf (stderr, "  checking %s [%i]\n",
                     gcry_cipher_algo_name (algos[i]),
                     gcry_cipher_map_name (gcry_cipher_algo_name (algos[i])));

        check_one_cipher (algos[i], GCRY_CIPHER_MODE_ECB, 0);
        check_one_cipher (algos[i], GCRY_CIPHER_MODE_CFB, 0);
        check_one_cipher (algos[i], GCRY_CIPHER_MODE_CFB8, 0);
        check_one_cipher (algos[i], GCRY_CIPHER_MODE_OFB, 0);
        check_one_cipher (algos[i], GCRY_CIPHER_MODE_CBC, 0);
        check_one_cipher (algos[i], GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
        check_one_cipher (algos[i], GCRY_CIPHER_MODE_CTR, 0);
        check_one_cipher (algos[i], GCRY_CIPHER_MODE_EAX, 0);
        if (gcry_cipher_get_algo_blklen (algos[i]) == GCRY_CCM_BLOCK_LEN)
            check_one_cipher (algos[i], GCRY_CIPHER_MODE_CCM, 0);
        if (gcry_cipher_get_algo_blklen (algos[i]) == GCRY_GCM_BLOCK_LEN)
            check_one_cipher (algos[i], GCRY_CIPHER_MODE_GCM, 0);
        if (gcry_cipher_get_algo_blklen (algos[i]) == GCRY_OCB_BLOCK_LEN)
            check_one_cipher (algos[i], GCRY_CIPHER_MODE_OCB, 0);
        if (gcry_cipher_get_algo_blklen (algos[i]) == GCRY_XTS_BLOCK_LEN)
            check_one_cipher (algos[i], GCRY_CIPHER_MODE_XTS, 0);
    }

    for (i = 0; algos2[i]; i++)
    {
        if (gcry_cipher_test_algo (algos2[i]) && in_fips_mode)
        {
            if (verbose)
                fprintf (stderr, "  algorithm %d not available in fips mode\n",
                         algos2[i]);
            continue;
        }
        if (verbose)
            fprintf (stderr, "  checking %s\n",
                     gcry_cipher_algo_name (algos2[i]));

        check_one_cipher (algos2[i], GCRY_CIPHER_MODE_STREAM, 0);
        if (algos2[i] == GCRY_CIPHER_CHACHA20)
            check_one_cipher (algos2[i], GCRY_CIPHER_MODE_POLY1305, 0);
    }
    /* we have now run all cipher's selftests */

    if (verbose)
        fprintf (stderr, "Completed Cipher checks.\n");

    /* TODO: add some extra encryption to test the higher level functions */
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

static void
check_ecb_cipher (void)
{
    /* ECB cipher check. Mainly for testing underlying block cipher. */
    static const struct tv
    {
        int algo;
        const char *key;
        int is_weak_key;
        struct
        {
            const char *plaintext;
            int keylen;
            int inlen;
            const char *out;
        } data[MAX_DATA_LEN];
    } tv[] =
            {
                    /* Test vectors from OpenSSL for key lengths of 8 to 200 bits */
                    { GCRY_CIPHER_BLOWFISH,
                            "\xf0\xe1\xd2\xc3\xb4\xa5\x96\x87\x78\x69\x5a\x4b\x3c\x2d\x1e\x0f"
                            "\x00\x11\x22\x33\x44\x55\x66\x77\x88",
                            0,
                            { { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                      1,
                                      8,
                                      "\xf9\xad\x59\x7c\x49\xdb\x00\x5e" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            2,
                                            8,
                                            "\xe9\x1d\x21\xc1\xd9\x61\xa6\xd6" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            3,
                                            8,
                                            "\xe9\xc2\xb7\x0a\x1b\xc6\x5c\xf3" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            4,
                                            8,
                                            "\xbe\x1e\x63\x94\x08\x64\x0f\x05" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            5,
                                            8,
                                            "\xb3\x9e\x44\x48\x1b\xdb\x1e\x6e" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            6,
                                            8,
                                            "\x94\x57\xaa\x83\xb1\x92\x8c\x0d" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            7,
                                            8,
                                            "\x8b\xb7\x70\x32\xf9\x60\x62\x9d" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            8,
                                            8,
                                            "\xe8\x7a\x24\x4e\x2c\xc8\x5e\x82" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            9,
                                            8,
                                            "\x15\x75\x0e\x7a\x4f\x4e\xc5\x77" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            10,
                                            8,
                                            "\x12\x2b\xa7\x0b\x3a\xb6\x4a\xe0" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            11,
                                            8,
                                            "\x3a\x83\x3c\x9a\xff\xc5\x37\xf6" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            12,
                                            8,
                                            "\x94\x09\xda\x87\xa9\x0f\x6b\xf2" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            13,
                                            8,
                                            "\x88\x4f\x80\x62\x50\x60\xb8\xb4" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            14,
                                            8,
                                            "\x1f\x85\x03\x1c\x19\xe1\x19\x68" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            15,
                                            8,
                                            "\x79\xd9\x37\x3a\x71\x4c\xa3\x4f" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            16,
                                            8,
                                            "\x93\x14\x28\x87\xee\x3b\xe1\x5c" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            17,
                                            8,
                                            "\x03\x42\x9e\x83\x8c\xe2\xd1\x4b" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            18,
                                            8,
                                            "\xa4\x29\x9e\x27\x46\x9f\xf6\x7b" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            19,
                                            8,
                                            "\xaf\xd5\xae\xd1\xc1\xbc\x96\xa8" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            20,
                                            8,
                                            "\x10\x85\x1c\x0e\x38\x58\xda\x9f" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            21,
                                            8,
                                            "\xe6\xf5\x1e\xd7\x9b\x9d\xb2\x1f" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            22,
                                            8,
                                            "\x64\xa6\xe1\x4a\xfd\x36\xb4\x6f" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            23,
                                            8,
                                            "\x80\xc7\xd7\xd4\x5a\x54\x79\xad" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            24,
                                            8,
                                            "\x05\x04\x4b\x62\xfa\x52\xd0\x80" },
                                    { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                            0, /* test default key length of 128-bits */
                                            8,
                                            "\x93\x14\x28\x87\xee\x3b\xe1\x5c" },
                                    { }
                            }
                    },
                    /* Test vector from Linux kernel for key length of 448 bits */
                    { GCRY_CIPHER_BLOWFISH,
                            "\xf0\xe1\xd2\xc3\xb4\xa5\x96\x87\x78\x69\x5a\x4b\x3c\x2d\x1e\x0f"
                            "\x00\x11\x22\x33\x44\x55\x66\x77\x04\x68\x91\x04\xc2\xfd\x3b\x2f"
                            "\x58\x40\x23\x64\x1a\xba\x61\x76\x1f\x1f\x1f\x1f\x0e\x0e\x0e\x0e"
                            "\xff\xff\xff\xff\xff\xff\xff\xff",
                            0,
                            { { "\xfe\xdc\xba\x98\x76\x54\x32\x10",
                                      56,
                                      8,
                                      "\xc0\x45\x04\x01\x2e\x4e\x1f\x53" },
                                    { }
                            }
                    },
                    /* Weak-key testing */
                    { GCRY_CIPHER_DES,
                            "\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe",
                            1,
                            { { "\x00\x00\x00\x00\x00\x00\x00\x00",
                                      8,
                                      8,
                                      "\xca\xaa\xaf\x4d\xea\xf1\xdb\xae" },
                                    { }
                            }
                    },
                    /* Weak-key testing */
                    { GCRY_CIPHER_DES,
                            "\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe",
                            2,
                            { { "\x00\x00\x00\x00\x00\x00\x00\x00",
                                      8,
                                      8,
                                      "\xca\xaa\xaf\x4d\xea\xf1\xdb\xae" },
                                    { }
                            }
                    },
                    { GCRY_CIPHER_SM4,
                            "\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10",
                            0,
                            { { "\xaa\xaa\xaa\xaa\xbb\xbb\xbb\xbb\xcc\xcc\xcc\xcc\xdd\xdd\xdd\xdd"
                                "\xee\xee\xee\xee\xff\xff\xff\xff\xaa\xaa\xaa\xaa\xbb\xbb\xbb\xbb",
                                      16,
                                      32,
                                      "\x5e\xc8\x14\x3d\xe5\x09\xcf\xf7\xb5\x17\x9f\x8f\x47\x4b\x86\x19"
                                      "\x2f\x1d\x30\x5a\x7f\xb1\x7d\xf9\x85\xf8\x1c\x84\x82\x19\x23\x04" },
                                    { }
                            }
                    },
                    { GCRY_CIPHER_SM4,
                            "\xfe\xdc\xba\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xab\xcd\xef",
                            0,
                            { { "\xaa\xaa\xaa\xaa\xbb\xbb\xbb\xbb\xcc\xcc\xcc\xcc\xdd\xdd\xdd\xdd"
                                "\xee\xee\xee\xee\xff\xff\xff\xff\xaa\xaa\xaa\xaa\xbb\xbb\xbb\xbb",
                                      16,
                                      32,
                                      "\xc5\x87\x68\x97\xe4\xa5\x9b\xbb\xa7\x2a\x10\xc8\x38\x72\x24\x5b"
                                      "\x12\xdd\x90\xbc\x2d\x20\x06\x92\xb5\x29\xa4\x15\x5a\xc9\xe6\x00" },
                                    { }
                            }
                    },
            };
    gcry_cipher_hd_t hde, hdd;
    unsigned char out[MAX_DATA_LEN];
    int i, j, keylen, algo;
    gcry_error_t err = 0;
    gcry_error_t err2 = 0;

    if (verbose)
        fprintf (stderr, "  Starting ECB checks.\n");

    for (i = 0; i < sizeof (tv) / sizeof (tv[0]); i++)
    {
        algo = tv[i].algo;

        if (gcry_cipher_test_algo (algo) && in_fips_mode)
        {
            if (verbose)
                fprintf (stderr, "  algorithm %d not available in fips mode\n",
                         algo);
            continue;
        }

        if (verbose)
            fprintf (stderr, "    checking ECB mode for %s [%i]\n",
                     gcry_cipher_algo_name (algo),
                     algo);
        err = gcry_cipher_open (&hde, algo, GCRY_CIPHER_MODE_ECB, 0);
        if (!err)
            err2 = gcry_cipher_open (&hdd, algo, GCRY_CIPHER_MODE_ECB, 0);
        if (err || err2)
        {
            fail ("ecb-algo:%d-tv:%d, gcry_cipher_open failed: %s\n", algo, i,
                  gpg_strerror (err ? err : err2));
            if (err2)
                gcry_cipher_close (hde);
            return;
        }

        if (tv[i].is_weak_key == 2)
        {
            err = gcry_cipher_ctl(hde, GCRYCTL_SET_ALLOW_WEAK_KEY, NULL, 1);
            if (!err)
                err = gcry_cipher_ctl(hdd, GCRYCTL_SET_ALLOW_WEAK_KEY, NULL, 1);
            if (err)
            {
                fail ("ecb-algo:%d-tv:%d, gcry_cipher_ctl failed: %s\n",
                      algo, i, gpg_strerror (err));
                gcry_cipher_close (hde);
                gcry_cipher_close (hdd);
                return;
            }
        }

        for (j = 0; tv[i].data[j].inlen; j++)
        {
            keylen = tv[i].data[j].keylen;
            if (!keylen)
            {
                keylen = gcry_cipher_get_algo_keylen(algo);
                if (!keylen)
                {
                    fail ("ecb-algo:%d-tv:%d-data:%d, gcry_cipher_get_algo_keylen failed\n",
                          algo, i, j);
                    gcry_cipher_close (hde);
                    gcry_cipher_close (hdd);
                    return;
                }
            }

            err = gcry_cipher_setkey (hde, tv[i].key, keylen);
            if (!err || (gcry_err_code(err) == GPG_ERR_WEAK_KEY
                         && tv[i].is_weak_key == 2))
                err = gcry_cipher_setkey (hdd, tv[i].key, keylen);
            if (tv[i].is_weak_key == 1)
            {
                if (gcry_err_code(err) != GPG_ERR_WEAK_KEY)
                {
                    fail ("ecb-algo:%d-tv:%d-data:%d, expected gcry_cipher_setkey to fail, but got: %s\n",
                          algo, i, j, gpg_strerror (err));
                    gcry_cipher_close (hde);
                    gcry_cipher_close (hdd);
                    return;
                }
                else
                {
                    continue;
                }
            }
            else if (tv[i].is_weak_key == 2)
            {
                if (gcry_err_code(err) != GPG_ERR_WEAK_KEY)
                {
                    fail ("ecb-algo:%d-tv:%d-data:%d, expected gcry_cipher_setkey to fail, but got: %s\n",
                          algo, i, j, gpg_strerror (err));
                    gcry_cipher_close (hde);
                    gcry_cipher_close (hdd);
                    return;
                }
            }
            else if (err)
            {
                fail ("ecb-algo:%d-tv:%d-data:%d, gcry_cipher_setkey failed: %s\n",
                      algo, i, j, gpg_strerror (err));
                gcry_cipher_close (hde);
                gcry_cipher_close (hdd);
                return;
            }

            err = gcry_cipher_encrypt (hde, out, MAX_DATA_LEN,
                                       tv[i].data[j].plaintext,
                                       tv[i].data[j].inlen);
            if (err)
            {
                fail ("ecb-algo:%d-tv:%d-data:%d, gcry_cipher_encrypt failed: %s\n",
                      algo, i, j, gpg_strerror (err));
                gcry_cipher_close (hde);
                gcry_cipher_close (hdd);
                return;
            }

            if (memcmp (tv[i].data[j].out, out, tv[i].data[j].inlen))
            {
                fail ("ecb-algo:%d-tv:%d-data:%d, encrypt mismatch entry\n",
                      algo, i, j);
            }

            err = gcry_cipher_decrypt (hdd, out, tv[i].data[j].inlen, NULL, 0);
            if (err)
            {
                fail ("ecb-algo:%d-tv:%d-data:%d, gcry_cipher_decrypt failed: %s\n",
                      algo, i, j, gpg_strerror (err));
                gcry_cipher_close (hde);
                gcry_cipher_close (hdd);
                return;
            }

            if (memcmp (tv[i].data[j].plaintext, out, tv[i].data[j].inlen))
            {
                fail ("ecb-algo:%d-tv:%d-data:%d, decrypt mismatch entry\n",
                      algo, i, j);
            }
        }

        gcry_cipher_close (hde);
        gcry_cipher_close (hdd);
    }
    if (verbose)
        fprintf (stderr, "  Completed ECB checks.\n");
}
static void
check_aes128_cbc_cts_cipher (void)
{
    static const char key[128 / 8] = "chicken teriyaki";
    static const unsigned char plaintext[] =
            "I would like the General Gau's Chicken, please, and wonton soup.";
    static const struct tv
    {
        unsigned char out[MAX_DATA_LEN];
        int inlen;
    } tv[] =
            {
                    { "\xc6\x35\x35\x68\xf2\xbf\x8c\xb4\xd8\xa5\x80\x36\x2d\xa7\xff\x7f"
                      "\x97",
                            17 },
                    { "\xfc\x00\x78\x3e\x0e\xfd\xb2\xc1\xd4\x45\xd4\xc8\xef\xf7\xed\x22"
                      "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5",
                            31 },
                    { "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8"
                      "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84",
                            32 },
                    { "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"
                      "\xb3\xff\xfd\x94\x0c\x16\xa1\x8c\x1b\x55\x49\xd2\xf8\x38\x02\x9e"
                      "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5",
                            47 },
                    { "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"
                      "\x9d\xad\x8b\xbb\x96\xc4\xcd\xc0\x3b\xc1\x03\xe1\xa1\x94\xbb\xd8"
                      "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8",
                            48 },
                    { "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"
                      "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8"
                      "\x48\x07\xef\xe8\x36\xee\x89\xa5\x26\x73\x0d\xbc\x2f\x7b\xc8\x40"
                      "\x9d\xad\x8b\xbb\x96\xc4\xcd\xc0\x3b\xc1\x03\xe1\xa1\x94\xbb\xd8",
                            64 },
            };
    gcry_cipher_hd_t hd;
    unsigned char out[MAX_DATA_LEN];
    int i;
    gcry_error_t err = 0;

    if (verbose)
        fprintf (stderr, "  Starting AES128 CBC CTS checks.\n");
    err = gcry_cipher_open (&hd,
                            GCRY_CIPHER_AES,
                            GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
    if (err)
    {
        fail ("aes-cbc-cts, gcry_cipher_open failed: %s\n", gpg_strerror (err));
        return;
    }

    err = gcry_cipher_setkey (hd, key, 128 / 8);
    if (err)
    {
        fail ("aes-cbc-cts, gcry_cipher_setkey failed: %s\n",
              gpg_strerror (err));
        gcry_cipher_close (hd);
        return;
    }

    for (i = 0; i < sizeof (tv) / sizeof (tv[0]); i++)
    {
        err = gcry_cipher_setiv (hd, NULL, 0);
        if (err)
        {
            fail ("aes-cbc-cts, gcry_cipher_setiv failed: %s\n",
                  gpg_strerror (err));
            gcry_cipher_close (hd);
            return;
        }

        if (verbose)
            fprintf (stderr, "    checking encryption for length %i\n", tv[i].inlen);
        err = gcry_cipher_encrypt (hd, out, MAX_DATA_LEN,
                                   plaintext, tv[i].inlen);
        if (err)
        {
            fail ("aes-cbc-cts, gcry_cipher_encrypt failed: %s\n",
                  gpg_strerror (err));
            gcry_cipher_close (hd);
            return;
        }

        if (memcmp (tv[i].out, out, tv[i].inlen))
            fail ("aes-cbc-cts, encrypt mismatch entry %d\n", i);

        err = gcry_cipher_setiv (hd, NULL, 0);
        if (err)
        {
            fail ("aes-cbc-cts, gcry_cipher_setiv failed: %s\n",
                  gpg_strerror (err));
            gcry_cipher_close (hd);
            return;
        }
        if (verbose)
            fprintf (stderr, "    checking decryption for length %i\n", tv[i].inlen);
        err = gcry_cipher_decrypt (hd, out, tv[i].inlen, NULL, 0);
        if (err)
        {
            fail ("aes-cbc-cts, gcry_cipher_decrypt failed: %s\n",
                  gpg_strerror (err));
            gcry_cipher_close (hd);
            return;
        }

        if (memcmp (plaintext, out, tv[i].inlen))
            fail ("aes-cbc-cts, decrypt mismatch entry %d\n", i);
    }

    gcry_cipher_close (hd);
    if (verbose)
        fprintf (stderr, "  Completed AES128 CBC CTS checks.\n");
}

static void
check_cbc_mac_cipher (void)
{
    static const struct tv
    {
        int algo;
        char key[MAX_DATA_LEN];
        unsigned char plaintext[MAX_DATA_LEN];
        size_t plaintextlen;
        char mac[MAX_DATA_LEN];
    }
            tv[] =
            {
                    { GCRY_CIPHER_AES,
                            "chicken teriyaki",
                            "This is a sample plaintext for CBC MAC of sixtyfour bytes.......",
                            0, "\x23\x8f\x6d\xc7\x53\x6a\x62\x97\x11\xc4\xa5\x16\x43\xea\xb0\xb6" },
                    { GCRY_CIPHER_3DES,
                            "abcdefghABCDEFGH01234567",
                            "This is a sample plaintext for CBC MAC of sixtyfour bytes.......",
                            0, "\x5c\x11\xf0\x01\x47\xbd\x3d\x3a" },
                    { GCRY_CIPHER_DES,
                            "abcdefgh",
                            "This is a sample plaintext for CBC MAC of sixtyfour bytes.......",
                            0, "\xfa\x4b\xdf\x9d\xfa\xab\x01\x70" }
            };
    gcry_cipher_hd_t hd;
    unsigned char out[MAX_DATA_LEN];
    int i, blklen, keylen;
    gcry_error_t err = 0;

    if (verbose)
        fprintf (stderr, "  Starting CBC MAC checks.\n");

    for (i = 0; i < sizeof (tv) / sizeof (tv[0]); i++)
    {
        if (gcry_cipher_test_algo (tv[i].algo) && in_fips_mode)
        {
            if (verbose)
                fprintf (stderr, "  algorithm %d not available in fips mode\n",
                         tv[i].algo);
            continue;
        }

        err = gcry_cipher_open (&hd,
                                tv[i].algo,
                                GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_MAC);
        if (!hd)
        {
            fail ("cbc-mac algo %d, gcry_cipher_open failed: %s\n",
                  tv[i].algo, gpg_strerror (err));
            return;
        }

        blklen = gcry_cipher_get_algo_blklen(tv[i].algo);
        if (!blklen)
        {
            fail ("cbc-mac algo %d, gcry_cipher_get_algo_blklen failed\n",
                  tv[i].algo);
            gcry_cipher_close (hd);
            return;
        }

        keylen = gcry_cipher_get_algo_keylen (tv[i].algo);
        if (!keylen)
        {
            fail ("cbc-mac algo %d, gcry_cipher_get_algo_keylen failed\n",
                  tv[i].algo);
            return;
        }

        err = gcry_cipher_setkey (hd, tv[i].key, keylen);
        if (err)
        {
            fail ("cbc-mac algo %d, gcry_cipher_setkey failed: %s\n",
                  tv[i].algo, gpg_strerror (err));
            gcry_cipher_close (hd);
            return;
        }

        err = gcry_cipher_setiv (hd, NULL, 0);
        if (err)
        {
            fail ("cbc-mac algo %d, gcry_cipher_setiv failed: %s\n",
                  tv[i].algo, gpg_strerror (err));
            gcry_cipher_close (hd);
            return;
        }

        if (verbose)
            fprintf (stderr, "    checking CBC MAC for %s [%i]\n",
                     gcry_cipher_algo_name (tv[i].algo),
                     tv[i].algo);
        err = gcry_cipher_encrypt (hd,
                                   out, blklen,
                                   tv[i].plaintext,
                                   tv[i].plaintextlen ?
                                   tv[i].plaintextlen :
                                   strlen ((char*)tv[i].plaintext));
        if (err)
        {
            fail ("cbc-mac algo %d, gcry_cipher_encrypt failed: %s\n",
                  tv[i].algo, gpg_strerror (err));
            gcry_cipher_close (hd);
            return;
        }

#if 0
        {
	int j;
	for (j = 0; j < gcry_cipher_get_algo_blklen (tv[i].algo); j++)
	  printf ("\\x%02x", out[j] & 0xFF);
	printf ("\n");
      }
#endif

        if (memcmp (tv[i].mac, out, blklen))
            fail ("cbc-mac algo %d, encrypt mismatch entry %d\n", tv[i].algo, i);

        gcry_cipher_close (hd);
    }
    if (verbose)
        fprintf (stderr, "  Completed CBC MAC checks.\n");
}

static void
do_check_xts_cipher (int inplace)
{
    /* Note that we use hex strings and not binary strings in TV.  That
       makes it easier to maintain the test vectors.  */
    static const struct
    {
        int algo;
        const char *key;    /* NULL means "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" */
        const char *iv;
        const char *plain;
        const char *ciph;
    } tv[] = {
            /* CAVS; hex/XTSGenAES128.rsp; COUNT=100 */
            { GCRY_CIPHER_AES,
                    "bcb6613c495de4bdad9c19f04e4b3915f9ecb379e1a575b633337e934fca1050",
                    "64981173159d58ac355a20120c8e81f1",
                    "189acacee06dfa7c94484c7dae59e166",
                    "7900191d0f19a97668fdba9def84eedc"
            },
            /* CAVS; hex/XTSGenAES128.rsp; COUNT=101 */
            { GCRY_CIPHER_AES,
                    "b7b93f516aef295eff3a29d837cf1f135347e8a21dae616ff5062b2e8d78ce5e",
                    "873edea653b643bd8bcf51403197ed14",
                    "236f8a5b58dd55f6194ed70c4ac1a17f1fe60ec9a6c454d087ccb77d6b638c47",
                    "22e6a3c6379dcf7599b052b5a749c7f78ad8a11b9f1aa9430cf3aef445682e19"
            },
            /* CAVS; hex/XTSGenAES128.rsp; COUNT=301 */
            { GCRY_CIPHER_AES,
                    "394c97881abd989d29c703e48a72b397a7acf51b59649eeea9b33274d8541df4",
                    "4b15c684a152d485fe9937d39b168c29",
                    "2f3b9dcfbae729583b1d1ffdd16bb6fe2757329435662a78f0",
                    "f3473802e38a3ffef4d4fb8e6aa266ebde553a64528a06463e"
            },
            /* CAVS; hex/XTSGenAES128.rsp; COUNT=500 */
            { GCRY_CIPHER_AES,
                    "783a83ec52a27405dff9de4c57f9c979b360b6a5df88d67ec1a052e6f582a717",
                    "886e975b29bdf6f0c01bb47f61f6f0f5",
                    "b04d84da856b9a59ce2d626746f689a8051dacd6bce3b990aa901e4030648879",
                    "f941039ebab8cac39d59247cbbcb4d816c726daed11577692c55e4ac6d3e6820"
            },
            /* CAVS; hex/XTSGenAES256.rsp; COUNT=1 */
            { GCRY_CIPHER_AES256,
                    "1ea661c58d943a0e4801e42f4b0947149e7f9f8e3e68d0c7505210bd311a0e7c"
                    "d6e13ffdf2418d8d1911c004cda58da3d619b7e2b9141e58318eea392cf41b08",
                    "adf8d92627464ad2f0428e84a9f87564",
                    "2eedea52cd8215e1acc647e810bbc3642e87287f8d2e57e36c0a24fbc12a202e",
                    "cbaad0e2f6cea3f50b37f934d46a9b130b9d54f07e34f36af793e86f73c6d7db"
            },
            /* CAVS; hex/XTSGenAES256.rsp; COUNT=101 */
            { GCRY_CIPHER_AES256,
                    "266c336b3b01489f3267f52835fd92f674374b88b4e1ebd2d36a5f457581d9d0"
                    "42c3eef7b0b7e5137b086496b4d9e6ac658d7196a23f23f036172fdb8faee527",
                    "06b209a7a22f486ecbfadb0f3137ba42",
                    "ca7d65ef8d3dfad345b61ccddca1ad81de830b9e86c7b426d76cb7db766852d9"
                    "81c6b21409399d78f42cc0b33a7bbb06",
                    "c73256870cc2f4dd57acc74b5456dbd776912a128bc1f77d72cdebbf270044b7"
                    "a43ceed29025e1e8be211fa3c3ed002d"
            },
            /* CAVS; hex/XTSGenAES256.rsp; COUNT=401 */
            { GCRY_CIPHER_AES256,
                    "33e89e817ff8d037d6ac5a2296657503f20885d94c483e26449066bd9284d130"
                    "2dbdbb4b66b6b9f4687f13dd028eb6aa528ca91deb9c5f40db93218806033801",
                    "a78c04335ab7498a52b81ed74b48e6cf",
                    "14c3ac31291b075f40788247c3019e88c7b40bac3832da45bbc6c4fe7461371b"
                    "4dfffb63f71c9f8edb98f28ff4f33121",
                    "dead7e587519bc78c70d99279fbe3d9b1ad13cdaae69824e0ab8135413230bfd"
                    "b13babe8f986fbb30d46ab5ec56b916e"
            },
            /* From https://github.com/heisencoder/XTS-AES/blob/master/testvals/ */
            { GCRY_CIPHER_AES,
                    "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
                    "9a785634120000000000000000000000",
                    "000102030405060708090a0b0c0d0e0f10",
                    "7fb2e8beccbb5c118aa52ddca31220bb1b"
            },
            { GCRY_CIPHER_AES,
                    "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
                    "9a785634120000000000000000000000",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
                    "d05bc090a8e04f1b3d3ecdd5baec0fd4edbf9dace45d6f6a7306e64be5dd82"
            },
            { GCRY_CIPHER_AES,
                    "2718281828459045235360287471352631415926535897932384626433832795",
                    "00000000000000000000000000000000",
                    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
                    "20212223",
                    "27A7479BEFA1D476489F308CD4CFA6E288F548E5C4239F91712A587E2B05AC3D"
                    "A96E4BBE"
            },
            { GCRY_CIPHER_AES256,
                    "2718281828459045235360287471352662497757247093699959574966967627"
                    "3141592653589793238462643383279502884197169399375105820974944592",
                    "11000000000000000000000000000000",
                    "3A060A8CAD115A6F44572E3759E43C8F8832FEDC28A8E35B357B5CF3EDBEF788"
                    "CAD8BFCB23",
                    "6D1C78A8BAD91DB2924C507CCEDE835F5BADD157DA0AF55C98BBC28CF676F9FA"
                    "61618FA696"
            },
            { GCRY_CIPHER_AES256,
                    "2718281828459045235360287471352662497757247093699959574966967627"
                    "3141592653589793238462643383279502884197169399375105820974944592",
                    "11000000000000000000000000000000",
                    "3A060A8CAD115A6F44572E3759E43C8F8832FEDC28A8E35B357B5CF3EDBEF788"
                    "CAD8BFCB23",
                    "6D1C78A8BAD91DB2924C507CCEDE835F5BADD157DA0AF55C98BBC28CF676F9FA"
                    "61618FA696"
            },
            { GCRY_CIPHER_AES,
                    "e0e1e2e3e4e5e6e7e8e9eaebecedeeefc0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
                    "21436587a90000000000000000000000",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
                    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                    "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
                    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                    "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
                    "0001020304050607",
                    "38b45812ef43a05bd957e545907e223b954ab4aaf088303ad910eadf14b42be6"
                    "8b2461149d8c8ba85f992be970bc621f1b06573f63e867bf5875acafa04e42cc"
                    "bd7bd3c2a0fb1fff791ec5ec36c66ae4ac1e806d81fbf709dbe29e471fad3854"
                    "9c8e66f5345d7c1eb94f405d1ec785cc6f6a68f6254dd8339f9d84057e01a177"
                    "41990482999516b5611a38f41bb6478e6f173f320805dd71b1932fc333cb9ee3"
                    "9936beea9ad96fa10fb4112b901734ddad40bc1878995f8e11aee7d141a2f5d4"
                    "8b7a4e1e7f0b2c04830e69a4fd1378411c2f287edf48c6c4e5c247a19680f7fe"
                    "41cefbd49b582106e3616cbbe4dfb2344b2ae9519391f3e0fb4922254b1d6d2d"
                    "19c6d4d537b3a26f3bcc51588b32f3eca0829b6a5ac72578fb814fb43cf80d64"
                    "a233e3f997a3f02683342f2b33d25b492536b93becb2f5e1a8b82f5b88334272"
                    "9e8ae09d16938841a21a97fb543eea3bbff59f13c1a18449e398701c1ad51648"
                    "346cbc04c27bb2da3b93a1372ccae548fb53bee476f9e9c91773b1bb19828394"
                    "d55d3e1a20ed69113a860b6829ffa847224604435070221b257e8dff783615d2"
                    "cae4803a93aa4334ab482a0afac9c0aeda70b45a481df5dec5df8cc0f423c77a"
                    "5fd46cd312021d4b438862419a791be03bb4d97c0e59578542531ba466a83baf"
                    "92cefc151b5cc1611a167893819b63fb37ec662bc0fc907db74a94468a55a7bc"
                    "8a6b18e86de60290"
            },
            { GCRY_CIPHER_AES256,
                    "2718281828459045235360287471352662497757247093699959574966967627"
                    "3141592653589793238462643383279502884197169399375105820974944592",
                    "ffffffff000000000000000000000000",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
                    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                    "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
                    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                    "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                    "bf53d2dade78e822a4d949a9bc6766b01b06a8ef70d26748c6a7fc36d80ae4c5"
                    "520f7c4ab0ac8544424fa405162fef5a6b7f229498063618d39f0003cb5fb8d1"
                    "c86b643497da1ff945c8d3bedeca4f479702a7a735f043ddb1d6aaade3c4a0ac"
                    "7ca7f3fa5279bef56f82cd7a2f38672e824814e10700300a055e1630b8f1cb0e"
                    "919f5e942010a416e2bf48cb46993d3cb6a51c19bacf864785a00bc2ecff15d3"
                    "50875b246ed53e68be6f55bd7e05cfc2b2ed6432198a6444b6d8c247fab941f5"
                    "69768b5c429366f1d3f00f0345b96123d56204c01c63b22ce78baf116e525ed9"
                    "0fdea39fa469494d3866c31e05f295ff21fea8d4e6e13d67e47ce722e9698a1c"
                    "1048d68ebcde76b86fcf976eab8aa9790268b7068e017a8b9b749409514f1053"
                    "027fd16c3786ea1bac5f15cb79711ee2abe82f5cf8b13ae73030ef5b9e4457e7"
                    "5d1304f988d62dd6fc4b94ed38ba831da4b7634971b6cd8ec325d9c61c00f1df"
                    "73627ed3745a5e8489f3a95c69639c32cd6e1d537a85f75cc844726e8a72fc00"
                    "77ad22000f1d5078f6b866318c668f1ad03d5a5fced5219f2eabbd0aa5c0f460"
                    "d183f04404a0d6f469558e81fab24a167905ab4c7878502ad3e38fdbe62a4155"
                    "6cec37325759533ce8f25f367c87bb5578d667ae93f9e2fd99bcbc5f2fbba88c"
                    "f6516139420fcff3b7361d86322c4bd84c82f335abb152c4a93411373aaa8220"
            }
    };
    gpg_error_t err = 0;
    gcry_cipher_hd_t hde, hdd;
    int tidx;
    int got_err = 0;

    if (verbose)
        fprintf (stderr, "  Starting XTS checks.\n");

    for (tidx = 0; !got_err && tidx < DIM (tv); tidx++)
    {
        const char *hexkey = tv[tidx].key;
        char *key, *iv, *ciph, *plain, *out;
        size_t keylen, ivlen, ciphlen, plainlen, outlen;

        if (verbose)
            fprintf (stderr, "    checking XTS mode for %s [%i] (tv %d)\n",
                     gcry_cipher_algo_name (tv[tidx].algo), tv[tidx].algo, tidx);

        if (!hexkey)
            hexkey = "000102030405060708090A0B0C0D0E0F"
                     "101112131415161718191A1B1C1D1E1F";

        /* Convert to hex strings to binary.  */
        key   = hex2buffer (hexkey, &keylen);
        iv    = hex2buffer (tv[tidx].iv, &ivlen);
        plain = hex2buffer (tv[tidx].plain, &plainlen);
        ciph  = hex2buffer (tv[tidx].ciph, &ciphlen);
        outlen = plainlen + 5;
        out   = xmalloc (outlen);

        assert (plainlen == ciphlen);
        assert (plainlen <= outlen);
        assert (out);

        err = gcry_cipher_open (&hde, tv[tidx].algo, GCRY_CIPHER_MODE_XTS, 0);
        if (!err)
            err = gcry_cipher_open (&hdd, tv[tidx].algo, GCRY_CIPHER_MODE_XTS, 0);
        if (err)
        {
            fail ("cipher-xts, gcry_cipher_open failed (tv %d): %s\n",
                  tidx, gpg_strerror (err));
            return;
        }

        err = gcry_cipher_setkey (hde, key, keylen);
        if (err && in_fips_mode && memcmp(key, key + keylen/2, keylen/2) == 0)
        {
            /* Since both halves of key are the same, fail to set key in FIPS
               mode is expected. */
            goto next_tv;
        }
        if (!err)
            err = gcry_cipher_setkey (hdd, key, keylen);
        if (err)
        {
            fail ("cipher-xts, gcry_cipher_setkey failed (tv %d): %s\n",
                  tidx, gpg_strerror (err));
            goto err_out;
        }

        err = gcry_cipher_setiv (hde, iv, ivlen);
        if (!err)
            err = gcry_cipher_setiv (hdd, iv, ivlen);
        if (err)
        {
            fail ("cipher-xts, gcry_cipher_setiv failed (tv %d): %s\n",
                  tidx, gpg_strerror (err));
            goto err_out;
        }

        if (inplace)
        {
            memcpy(out, plain, plainlen);
            err = gcry_cipher_encrypt (hde, out, plainlen, NULL, 0);
        }
        else
        {
            err = gcry_cipher_encrypt (hde, out, outlen, plain, plainlen);
        }
        if (err)
        {
            fail ("cipher-xts, gcry_cipher_encrypt failed (tv %d): %s\n",
                  tidx, gpg_strerror (err));
            goto err_out;
        }

        /* Check that the encrypt output matches the expected cipher text.  */
        if (memcmp (ciph, out, plainlen))
        {
            mismatch (ciph, plainlen, out, plainlen);
            fail ("cipher-xts, encrypt data mismatch (tv %d)\n", tidx);
        }

        /* Now for the decryption.  */
        if (inplace)
        {
            err = gcry_cipher_decrypt (hdd, out, plainlen, NULL, 0);
        }
        else
        {
            memcpy(ciph, out, ciphlen);
            err = gcry_cipher_decrypt (hdd, out, plainlen, ciph, ciphlen);
        }
        if (err)
        {
            fail ("cipher-xts, gcry_cipher_decrypt (tv %d) failed: %s\n",
                  tidx, gpg_strerror (err));
            goto err_out;
        }

        /* Check that the decrypt output matches the expected plain text.  */
        if (memcmp (plain, out, plainlen))
        {
            mismatch (plain, plainlen, out, plainlen);
            fail ("cipher-xts, decrypt data mismatch (tv %d)\n", tidx);
        }

        if (0)
        {
            err_out:
            got_err = 1;
        }

        next_tv:
        gcry_cipher_close (hde);
        gcry_cipher_close (hdd);

        xfree (iv);
        xfree (ciph);
        xfree (plain);
        xfree (key);
        xfree (out);
    }

    if (verbose)
        fprintf (stderr, "  Completed XTS checks.\n");
}

static void
check_xts_cipher (void)
{
    /* Check XTS cipher with separate destination and source buffers for
     * encryption/decryption. */
    do_check_xts_cipher(0);

    /* Check XTS cipher with inplace encrypt/decrypt. */
    do_check_xts_cipher(1);
}

static void
check_cipher_modes(void)
{
    if (verbose)
        fprintf (stderr, "Starting Cipher Mode checks.\n");

    check_ecb_cipher ();
    check_aes128_cbc_cts_cipher ();
    check_cbc_mac_cipher ();
    check_xts_cipher ();
    if (verbose)
        fprintf (stderr, "Completed Cipher Mode checks.\n");
}

TEST(gcrypt_basic_cipher_ut, gcrypt_basic_cipher_testcases){
    verbose = 1;
    check_ciphers();
    check_cipher_modes ();
    check_bulk_cipher_modes ();
}
