/* gcrypt_pk_ut.c - Test OAEP
 * Copyright (C) 2011 Free Software Foundation, Inc.
 *
 * Authors:
 * YutingNie yvettemisaki@outlook.com
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
#include <ifm_gcrypt.h>
#define PGM "pkcs1v2"
#include "gcrypt_ut_common.h"


static int in_fips_mode;

static void
show_sexp (const char *prefix, gcry_sexp_t a)
{
  char *buf;
  size_t size;

  if (prefix)
    fputs (prefix, stderr);
  size = gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  buf = gcry_xmalloc (size);

  gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, buf, size);
  fprintf (stderr, "%.*s", (int)size, buf);
  gcry_free (buf);
}


/* Convert STRING consisting of hex characters into its binary
   representation and return it as an allocated buffer. The valid
   length of the buffer is returned at R_LENGTH.  The string is
   delimited by end of string.  The function returns NULL on
   error.  */
static void *
data_from_hex (const char *string, size_t *r_length)
{
  const char *s;
  char *buffer;
  size_t length;

  buffer = gcry_xmalloc (strlen(string)/2+1);
  length = 0;
  for (s=string; *s; s +=2 )
    {
      if (!hexdigitp (s) || !hexdigitp (s+1))
        die ("error parsing hex string `%s'\n", string);
      ((unsigned char*)buffer)[length++] = xtoi_2 (s);
    }
  *r_length = length;
  return buffer;
}


static int
extract_cmp_data (gcry_sexp_t sexp, const char *name, const char *expected,
                  const char *description)
{
  gcry_sexp_t l1;
  const void *a;
  size_t alen;
  void *b;
  size_t blen;
  int rc = 0;

  l1 = gcry_sexp_find_token (sexp, name, 0);
  a = gcry_sexp_nth_data (l1, 1, &alen);
  b = data_from_hex (expected, &blen);
  if (!a)
    {
      info ("%s: parameter \"%s\" missing in key\n", description, name);
      rc = 1;
    }
  else if ( alen != blen || memcmp (a, b, alen) )
    {
      info ("%s: parameter \"%s\" does not match expected value\n",
            description, name);
      rc = 1;
    }
  gcry_free (b);
  gcry_sexp_release (l1);
  return rc;
}


/* Check against the OAEP test vectors from
   ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1d2-vec.zip .  */
static void
check_oaep (void)
{
#include "gcrypt_pk_oaep.h"
  gpg_error_t err;
  int tno, mno;

  for (tno = 0; tno < DIM (tbl); tno++)
    {
      void *rsa_n, *rsa_e, *rsa_d;
      size_t rsa_n_len, rsa_e_len, rsa_d_len;
      gcry_sexp_t sec_key, pub_key;

      if (verbose > 1)
        info ("(%s)\n", tbl[tno].desc);

      rsa_n = data_from_hex (tbl[tno].n, &rsa_n_len);
      rsa_e = data_from_hex (tbl[tno].e, &rsa_e_len);
      rsa_d = data_from_hex (tbl[tno].d, &rsa_d_len);
      err = gcry_sexp_build (&sec_key, NULL,
                             "(private-key (rsa (n %b)(e %b)(d %b)))",
                             (int)rsa_n_len, rsa_n,
                             (int)rsa_e_len, rsa_e,
                             (int)rsa_d_len, rsa_d);
      if (err)
        die ("constructing private key failed: %s\n", gpg_strerror (err));
      err = gcry_sexp_build (&pub_key, NULL,
                             "(public-key (rsa (n %b)(e %b)))",
                             (int)rsa_n_len, rsa_n,
                             (int)rsa_e_len, rsa_e);
      if (err)
        die ("constructing public key failed: %s\n", gpg_strerror (err));
      gcry_free (rsa_n);
      gcry_free (rsa_e);
      gcry_free (rsa_d);

      if (in_fips_mode)
        {
          unsigned int nbits = gcry_pk_get_nbits (pub_key);

          if (nbits < 2048)
            {
              if (verbose > 1)
                info ("... skipped\n");
              goto next;
            }
        }

      for (mno = 0; mno < DIM (tbl[0].m); mno++)
        {
          void *mesg, *seed, *encr;
          size_t mesg_len, seed_len, encr_len;
          gcry_sexp_t plain, ciph;

          if (verbose)
            info ("running test: %s\n", tbl[tno].m[mno].desc);

          mesg = data_from_hex (tbl[tno].m[mno].mesg, &mesg_len);
          seed = data_from_hex (tbl[tno].m[mno].seed, &seed_len);

          err = gcry_sexp_build (&plain, NULL,
                                 "(data (flags oaep)(hash-algo sha1)"
                                 "(value %b)(random-override %b))",
                                 (int)mesg_len, mesg,
                                 (int)seed_len, seed);
          if (err)
            die ("constructing plain data failed: %s\n", gpg_strerror (err));
          gcry_free (mesg);
          gcry_free (seed);

          err = gcry_pk_encrypt (&ciph, plain, pub_key);
          if (err)
            {
              show_sexp ("plain:\n", ciph);
              fail ("gcry_pk_encrypt failed: %s\n", gpg_strerror (err));
            }
          else
            {
              if (extract_cmp_data (ciph, "a", tbl[tno].m[mno].encr,
                                    tbl[tno].m[mno].desc))
                {
                  show_sexp ("encrypt result:\n", ciph);
                  fail ("mismatch in gcry_pk_encrypt\n");
                }
              gcry_sexp_release (ciph);
              ciph = NULL;
            }
          gcry_sexp_release (plain);
          plain = NULL;

          /* Now test the decryption.  */
          seed = data_from_hex (tbl[tno].m[mno].seed, &seed_len);
          encr = data_from_hex (tbl[tno].m[mno].encr, &encr_len);

          err = gcry_sexp_build (&ciph, NULL,
                                 "(enc-val (flags oaep)(hash-algo sha1)"
                                 "(random-override %b)"
                                 "(rsa (a %b)))",
                                 (int)seed_len, seed,
                                 (int)encr_len, encr);
          if (err)
            die ("constructing cipher data failed: %s\n", gpg_strerror (err));
          gcry_free (encr);
          gcry_free (seed);

          err = gcry_pk_decrypt (&plain, ciph, sec_key);
          if (err)
            {
              show_sexp ("ciph:\n", ciph);
              fail ("gcry_pk_decrypt failed: %s\n", gpg_strerror (err));
            }
          else
            {
              if (extract_cmp_data (plain, "value", tbl[tno].m[mno].mesg,
                                    tbl[tno].m[mno].desc))
                {
                  show_sexp ("decrypt result:\n", plain);
                  fail ("mismatch in gcry_pk_decrypt\n");
                }
              gcry_sexp_release (plain);
              plain = NULL;
            }
          gcry_sexp_release (ciph);
          ciph = NULL;
        }

    next:
      gcry_sexp_release (sec_key);
      gcry_sexp_release (pub_key);
    }
}

TEST(gcrypt_pk_testcases, test_gcrypt_pk_algorithm)
{
    check_oaep();
}
