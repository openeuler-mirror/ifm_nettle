/******************************************************************************
 * ifm_gcrypt.h -  GNU Cryptographic Library Interface              -*- c -*-
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * YutingNie yvettemisaki@outlook.com
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

#ifndef _IFM_LIBGCRYPT_H
#define _IFM_LIBGCRYPT_H

#include <stddef.h>
#include <stdint.h>
#include <gcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Define the asymmetric encryption functions. */
#define gcry_md_algo_info ifm_gcry_md_algo_info
#define gcry_md_open ifm_gcry_md_open
#define gcry_pk_verify ifm_gcry_pk_verify
#define gcry_pk_sign ifm_gcry_pk_sign
#define gcry_pk_encrypt ifm_gcry_pk_encrypt
#define gcry_pk_testkey ifm_gcry_pk_testkey
#define gcry_pk_decrypt ifm_gcry_pk_decrypt
#define gcry_pk_genkey ifm_gcry_pk_genkey
#define gcry_pk_ctl ifm_gcry_pk_ctl
#define gcry_pk_algo_info ifm_gcry_pk_algo_info
#define gcry_pk_algo_name ifm_gcry_pk_algo_name
#define gcry_pk_map_name ifm_gcry_pk_map_name
#define gcry_pk_get_nbits ifm_gcry_pk_get_nbits
#define gcry_pk_get_keygrip ifm_gcry_pk_get_keygrip
#define gcry_pk_get_curve ifm_gcry_pk_get_curve
#define gcry_pk_get_param ifm_gcry_pk_get_param
#define gcry_pubkey_get_sexp ifm_gcry_pubkey_get_sexp
#define gcry_pk_get_curve ifm_gcry_pk_get_curve

/* Create a message digest object for algorithm ALGO.  FLAGS may be
   given as an bitwise OR of the gcry_md_flags values.  ALGO may be
   given as 0 if the algorithms to be used are later set using
   gcry_md_enable. */
gcry_error_t ifm_gcry_md_open(gcry_md_hd_t *h, int algo, unsigned int flags);

/* Retrieve various information about the algorithm ALGO. */
gcry_error_t ifm_gcry_md_algo_info(int algo, int what, void *buffer, size_t *nbytes);

/************************************
 *                                  *
 *    Asymmetric Cipher Functions   *
 *                                  *
 ************************************/

/* Encrypt the DATA using the public key PKEY and store the result as
   a newly created S-expression at RESULT. */
gcry_error_t ifm_gcry_pk_encrypt(gcry_sexp_t *result, gcry_sexp_t data, gcry_sexp_t pkey);

/* Decrypt the DATA using the private key SKEY and store the result as
   a newly created S-expression at RESULT. */
gcry_error_t ifm_gcry_pk_decrypt(gcry_sexp_t *result, gcry_sexp_t data, gcry_sexp_t skey);

/* Sign the DATA using the private key SKEY and store the result as
   a newly created S-expression at RESULT. */
gcry_error_t ifm_gcry_pk_sign(gcry_sexp_t *result, gcry_sexp_t data, gcry_sexp_t skey);

/* Check the signature SIGVAL on DATA using the public key PKEY. */
gcry_error_t ifm_gcry_pk_verify(gcry_sexp_t sigval, gcry_sexp_t data, gcry_sexp_t pkey);

/* Check that private KEY is sane. */
gcry_error_t ifm_gcry_pk_testkey(gcry_sexp_t key);

/* Generate a new key pair according to the parameters given in
   S_PARMS.  The new key pair is returned in as an S-expression in
   R_KEY. */
gcry_error_t ifm_gcry_pk_genkey(gcry_sexp_t *r_key, gcry_sexp_t s_parms);

/* Catch all function for miscellaneous operations. */
gcry_error_t ifm_gcry_pk_ctl(int cmd, void *buffer, size_t buflen);

/* Retrieve information about the public key algorithm ALGO. */
gcry_error_t ifm_gcry_pk_algo_info(int algo, int what, void *buffer, size_t *nbytes);

/* Map the public key algorithm whose ID is contained in ALGORITHM to
   a string representation of the algorithm name.  For unknown
   algorithm IDs this functions returns "?". */
const char *ifm_gcry_pk_algo_name (int algorithm) _GCRY_GCC_ATTR_PURE;

/* Map the algorithm NAME to a public key algorithm Id.  Return 0 if
   the algorithm name is not known. */
int ifm_gcry_pk_map_name (const char* name) _GCRY_GCC_ATTR_PURE;

/* Return what is commonly referred as the key length for the given
   public or private KEY. */
unsigned int ifm_gcry_pk_get_nbits (gcry_sexp_t key) _GCRY_GCC_ATTR_PURE;

/* Return the so called KEYGRIP which is the SHA-1 hash of the public
   key parameters expressed in a way depending on the algorithm. */
unsigned char *ifm_gcry_pk_get_keygrip(gcry_sexp_t key, unsigned char *array);

/* Return the name of the curve matching KEY. */
const char *ifm_gcry_pk_get_curve(gcry_sexp_t key, int iterator, unsigned int *r_nbits);

/* Return an S-expression with the parameters of the named ECC curve
   NAME. ALGO must be set to an ECC algorithm. */
gcry_sexp_t ifm_gcry_pk_get_param(int algo, const char *name);

/* Return an S-expression representing the context CTX. */
gcry_error_t ifm_gcry_pubkey_get_sexp(gcry_sexp_t *r_sexp, int mode, gcry_ctx_t ctx);

#ifdef __cplusplus
}
#endif

#endif /* _IFM_LIBGCRYPT_H */
