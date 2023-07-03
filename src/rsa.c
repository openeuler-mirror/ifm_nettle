/******************************************************************************
 * ifm_nettle-rsa.c: add rsa support for ifm_nettle
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * jiaji2023 <jiaji@isrc.iscas.ac.cn>
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
#include <string.h>
#include <nettle/rsa.h>
#include <nettle/sha1.h>
#include <nettle/md5.h>
#include <nettle/sha2.h>

#include "md5_meta.h"
#include "rsa_meta.h"
#include "sha2_meta.h"


void ifm_rsa_public_key_init(struct ifm_rsa_public_key *key)
{
    rsa_public_key_init((struct rsa_public_key *) key);
}

/* Calls mpz_clear to deallocate bignum storage. */
void ifm_rsa_public_key_clear(struct ifm_rsa_public_key *key)
{
    rsa_public_key_clear((struct rsa_public_key *) key);
}

int ifm_rsa_public_key_prepare(struct ifm_rsa_public_key *key)
{
    return rsa_public_key_prepare((struct rsa_public_key *) key);
}

/* Calls mpz_init to initialize bignum storage. */
void ifm_rsa_private_key_init(struct ifm_rsa_private_key *key)
{
    rsa_private_key_init((struct rsa_private_key *) key);
}

/* Calls mpz_clear to deallocate bignum storage. */
void ifm_rsa_private_key_clear(struct ifm_rsa_private_key *key)
{
    rsa_private_key_clear((struct rsa_private_key *) key);
}

int ifm_rsa_private_key_prepare(struct ifm_rsa_private_key *key)
{
    return rsa_private_key_prepare((struct rsa_private_key *) key);
}


/* PKCS#1 style signatures */
int ifm_rsa_pkcs1_sign(const struct ifm_rsa_private_key *key,
                       size_t length, const uint8_t *digest_info,
                       mpz_t s)
{
    return rsa_pkcs1_sign((struct rsa_private_key *) key, length, digest_info, s);
}

int ifm_rsa_pkcs1_sign_tr(const struct ifm_rsa_public_key *pub,
                          const struct ifm_rsa_private_key *key,
                          void *random_ctx, nettle_random_func *random,
                          size_t length, const uint8_t *digest_info,
                          mpz_t s)
{
    return rsa_pkcs1_sign_tr((struct rsa_public_key *) pub, (struct rsa_private_key *) key, random_ctx, random, length,
                             digest_info, s);
}

int ifm_rsa_pkcs1_verify(const struct ifm_rsa_public_key *key,
                         size_t length, const uint8_t *digest_info,
                         const mpz_t signature)
{
    return rsa_pkcs1_verify((struct rsa_public_key *) key, length, digest_info, signature);
}

int ifm_rsa_md5_sign(const struct ifm_rsa_private_key *key,
                     struct ifm_md5_ctx *hash,
                     mpz_t signature)
{
    return rsa_md5_sign((struct rsa_private_key *) key, (struct md5_ctx *) hash, signature);
}

int ifm_rsa_md5_sign_tr(const struct ifm_rsa_public_key *pub,
                        const struct ifm_rsa_private_key *key,
                        void *random_ctx, nettle_random_func *random,
                        struct ifm_md5_ctx *hash, mpz_t s)
{
    return rsa_md5_sign_tr((struct rsa_public_key *) pub, (struct rsa_private_key *) key, random_ctx, random,
                           (struct md5_ctx *) hash, s);
}


int ifm_rsa_md5_verify(const struct ifm_rsa_public_key *key,
                       struct ifm_md5_ctx *hash,
                       const mpz_t signature)
{
    return rsa_md5_verify((struct rsa_public_key *) key, (struct md5_ctx *) hash, signature);
}

int ifm_rsa_sha1_sign(const struct ifm_rsa_private_key *key,
                      struct sha1_ctx *hash,
                      mpz_t signature)
{
    return rsa_sha1_sign((struct rsa_private_key *) key, hash, signature);
}

int ifm_rsa_sha1_sign_tr(const struct ifm_rsa_public_key *pub,
                         const struct ifm_rsa_private_key *key,
                         void *random_ctx, nettle_random_func *random,
                         struct sha1_ctx *hash,
                         mpz_t s)
{
    return rsa_sha1_sign_tr((struct rsa_public_key *) pub, (struct rsa_private_key *) key, random_ctx, random, hash, s);
}

int ifm_rsa_sha1_verify(const struct ifm_rsa_public_key *key,
                        struct sha1_ctx *hash,
                        const mpz_t signature)
{
    return rsa_sha1_verify((struct rsa_public_key *) key, hash, signature);
}

int ifm_rsa_sha256_sign(const struct ifm_rsa_private_key *key,
                        struct ifm_sha256_ctx *hash,
                        mpz_t signature)
{
    return rsa_sha256_sign((struct rsa_private_key *) key, (struct sha256_ctx *) hash, signature);
}

int ifm_rsa_sha256_sign_tr(const struct ifm_rsa_public_key *pub,
                           const struct ifm_rsa_private_key *key,
                           void *random_ctx, nettle_random_func *random,
                           struct ifm_sha256_ctx *hash,
                           mpz_t s)
{
    return rsa_sha256_sign_tr((struct rsa_public_key *) pub, (struct rsa_private_key *) key, random_ctx, random,
                              (struct sha256_ctx *) hash, s);
}

int ifm_rsa_sha256_verify(const struct ifm_rsa_public_key *key,
                          struct ifm_sha256_ctx *hash,
                          const mpz_t signature)
{
    return rsa_sha256_verify((struct rsa_public_key *) key, (struct sha256_ctx *) hash, signature);
}

int ifm_rsa_sha512_sign(const struct ifm_rsa_private_key *key,
                        struct ifm_sha512_ctx *hash,
                        mpz_t signature)
{
    return rsa_sha512_sign((struct rsa_private_key *) key, (struct sha512_ctx *) hash, signature);
}

int ifm_rsa_sha512_sign_tr(const struct ifm_rsa_public_key *pub,
                           const struct ifm_rsa_private_key *key,
                           void *random_ctx, nettle_random_func *random,
                           struct ifm_sha512_ctx *hash,
                           mpz_t s)
{
    return rsa_sha512_sign_tr((struct rsa_public_key *) pub, (struct rsa_private_key *) key, random_ctx, random,
                              (struct sha512_ctx *) hash, s);
}

int ifm_rsa_sha512_verify(const struct ifm_rsa_public_key *key,
                          struct ifm_sha512_ctx *hash,
                          const mpz_t signature)
{
    return rsa_sha512_verify((struct rsa_public_key *) key, (struct sha512_ctx *) hash, signature);
}

/* Variants taking the digest as argument. */
int ifm_rsa_md5_sign_digest(const struct ifm_rsa_private_key *key,
                            const uint8_t *digest,
                            mpz_t s)
{
    return rsa_md5_sign_digest((struct rsa_private_key *) key, digest, s);
}

int ifm_rsa_md5_sign_digest_tr(const struct ifm_rsa_public_key *pub,
                               const struct ifm_rsa_private_key *key,
                               void *random_ctx, nettle_random_func *random,
                               const uint8_t *digest, mpz_t s)
{
    return rsa_md5_sign_digest_tr((struct rsa_public_key *) pub, (struct rsa_private_key *) key, random_ctx, random,
                                  digest, s);
}

int ifm_rsa_md5_verify_digest(const struct ifm_rsa_public_key *key,
                              const uint8_t *digest,
                              const mpz_t signature)
{
    return rsa_md5_verify_digest((struct rsa_public_key *) key, digest, signature);
}

int ifm_rsa_sha1_sign_digest(const struct ifm_rsa_private_key *key,
                             const uint8_t *digest,
                             mpz_t s)
{
    return rsa_sha1_sign_digest((struct rsa_private_key *) key, digest, s);
}

int ifm_rsa_sha1_sign_digest_tr(const struct ifm_rsa_public_key *pub,
                                const struct ifm_rsa_private_key *key,
                                void *random_ctx, nettle_random_func *random,
                                const uint8_t *digest,
                                mpz_t s)
{
    return rsa_sha1_sign_digest_tr((struct rsa_public_key *) pub, (struct rsa_private_key *) key, random_ctx, random,
                                   digest, s);
}

int ifm_rsa_sha1_verify_digest(const struct ifm_rsa_public_key *key,
                               const uint8_t *digest,
                               const mpz_t signature)
{
    return rsa_sha1_verify_digest((struct rsa_public_key *) key, digest, signature);
}

int ifm_rsa_sha256_sign_digest(const struct ifm_rsa_private_key *key,
                               const uint8_t *digest,
                               mpz_t s)
{
    return rsa_sha256_sign_digest((struct rsa_private_key *) key, digest, s);
}

int ifm_rsa_sha256_sign_digest_tr(const struct ifm_rsa_public_key *pub,
                                  const struct ifm_rsa_private_key *key,
                                  void *random_ctx, nettle_random_func *random,
                                  const uint8_t *digest,
                                  mpz_t s)
{
    return rsa_sha256_sign_digest_tr((struct rsa_public_key *) pub, (struct rsa_private_key *) key, random_ctx, random,
                                     digest, s);
}

int ifm_rsa_sha256_verify_digest(const struct ifm_rsa_public_key *key,
                                 const uint8_t *digest,
                                 const mpz_t signature)
{
    return rsa_sha256_verify_digest((struct rsa_public_key *) key, digest, signature);
}

int ifm_rsa_sha512_sign_digest(const struct ifm_rsa_private_key *key,
                               const uint8_t *digest,
                               mpz_t s)
{
    return rsa_sha512_sign_digest((struct rsa_private_key *) key, digest, s);
}

int ifm_rsa_sha512_sign_digest_tr(const struct ifm_rsa_public_key *pub,
                                  const struct ifm_rsa_private_key *key,
                                  void *random_ctx, nettle_random_func *random,
                                  const uint8_t *digest,
                                  mpz_t s)
{
    return rsa_sha512_sign_digest_tr((struct rsa_public_key *) pub, (struct rsa_private_key *) key, random_ctx, random,
                                     digest, s);
}

int ifm_rsa_sha512_verify_digest(const struct ifm_rsa_public_key *key,
                                 const uint8_t *digest,
                                 const mpz_t signature)
{
    return rsa_sha512_verify_digest((struct rsa_public_key *) key, digest, signature);
}

/* PSS style signatures */
int ifm_rsa_pss_sha256_sign_digest_tr(const struct ifm_rsa_public_key *pub,
                                      const struct ifm_rsa_private_key *key,
                                      void *random_ctx, nettle_random_func *random,
                                      size_t salt_length, const uint8_t *salt,
                                      const uint8_t *digest,
                                      mpz_t s)
{
    return rsa_pss_sha256_sign_digest_tr((struct rsa_public_key *) pub, (struct rsa_private_key *) key, random_ctx,
                                         random, salt_length, salt, digest, s);
}

int ifm_rsa_pss_sha256_verify_digest(const struct ifm_rsa_public_key *key,
                                     size_t salt_length,
                                     const uint8_t *digest,
                                     const mpz_t signature)
{
    return rsa_pss_sha256_verify_digest((struct rsa_public_key *) key, salt_length, digest, signature);
}

int ifm_rsa_pss_sha384_sign_digest_tr(const struct ifm_rsa_public_key *pub,
                                      const struct ifm_rsa_private_key *key,
                                      void *random_ctx, nettle_random_func *random,
                                      size_t salt_length, const uint8_t *salt,
                                      const uint8_t *digest,
                                      mpz_t s)
{
    return rsa_pss_sha384_sign_digest_tr((struct rsa_public_key *) pub, (struct rsa_private_key *) key, random_ctx,
                                         random, salt_length, salt, digest, s);
}

int ifm_rsa_pss_sha384_verify_digest(const struct ifm_rsa_public_key *key,
                                     size_t salt_length,
                                     const uint8_t *digest,
                                     const mpz_t signature)
{
    return rsa_pss_sha384_verify_digest((struct rsa_public_key *) key, salt_length, digest, signature);
}

int ifm_rsa_pss_sha512_sign_digest_tr(const struct ifm_rsa_public_key *pub,
                                      const struct ifm_rsa_private_key *key,
                                      void *random_ctx, nettle_random_func *random,
                                      size_t salt_length, const uint8_t *salt,
                                      const uint8_t *digest,
                                      mpz_t s)
{
    return rsa_pss_sha512_sign_digest_tr((struct rsa_public_key *) pub, (struct rsa_private_key *) key, random_ctx,
                                         random, salt_length, salt, digest, s);
}

int ifm_rsa_pss_sha512_verify_digest(const struct ifm_rsa_public_key *key,
                                     size_t salt_length,
                                     const uint8_t *digest,
                                     const mpz_t signature)
{
    return rsa_pss_sha512_verify_digest((struct rsa_public_key *) key, salt_length, digest, signature);
}


/* RSA encryption, using PKCS#1 */
/* These functions uses the v1.5 padding. What should the v2 (OAEP)
 * functions be called? */

/* Returns 1 on success, 0 on failure, which happens if the
 * message is too long for the key. */
int ifm_rsa_encrypt(const struct ifm_rsa_public_key *key,
                    /* For padding */
                    void *random_ctx, nettle_random_func *random,
                    size_t length, const uint8_t *cleartext,
                    mpz_t cipher)
{
    return rsa_encrypt((struct rsa_public_key *) key, random_ctx, random, length, cleartext, cipher);
}

/* Message must point to a buffer of size *LENGTH. KEY->size is enough
 * for all valid messages. On success, *LENGTH is updated to reflect
 * the actual length of the message. Returns 1 on success, 0 on
 * failure, which happens if decryption failed or if the message
 * didn't fit. */
int ifm_rsa_decrypt(const struct ifm_rsa_private_key *key,
                    size_t *length, uint8_t *cleartext,
                    const mpz_t ciphertext)
{
    return rsa_decrypt((struct rsa_private_key *) key, length, cleartext, ciphertext);
}

/* Timing-resistant version, using randomized RSA blinding. */
int ifm_rsa_decrypt_tr(const struct ifm_rsa_public_key *pub,
                       const struct ifm_rsa_private_key *key,
                       void *random_ctx, nettle_random_func *random,
                       size_t *length, uint8_t *message,
                       const mpz_t gibberish)
{
    return rsa_decrypt_tr((struct rsa_public_key *) pub, (struct rsa_private_key *) key, random_ctx, random, length,
                          message, gibberish);
}

/* like rsa_decrypt_tr but with additional side-channel resistance.
 * NOTE: the length of the final message must be known in advance. */
int ifm_rsa_sec_decrypt(const struct ifm_rsa_public_key *pub,
                        const struct ifm_rsa_private_key *key,
                        void *random_ctx, nettle_random_func *random,
                        size_t length, uint8_t *message,
                        const mpz_t gibberish)
{
    return rsa_sec_decrypt((struct rsa_public_key *) pub, (struct rsa_private_key *) key, random_ctx, random, length,
                           message, gibberish);
}

/* Compute x, the e:th root of m. Calling it with x == m is allowed.
   It is required that 0 <= m < n. */
void ifm_rsa_compute_root(const struct ifm_rsa_private_key *key,
                          mpz_t x, const mpz_t m)
{
    rsa_compute_root((struct rsa_private_key *) key, x, m);
}

/* Safer variant, using RSA blinding, and checking the result after
   CRT. It is required that 0 <= m < n. */
int ifm_rsa_compute_root_tr(const struct ifm_rsa_public_key *pub,
                            const struct ifm_rsa_private_key *key,
                            void *random_ctx, nettle_random_func *random,
                            mpz_t x, const mpz_t m)
{
    return rsa_compute_root_tr((struct rsa_public_key *) pub, (struct rsa_private_key *) key, random_ctx, random, x, m);
}

/* Key generation */

/* Note that the key structs must be initialized first. */
int ifm_rsa_generate_keypair(struct ifm_rsa_public_key *pub,
                             struct ifm_rsa_private_key *key,

                             void *random_ctx, nettle_random_func *random,
                             void *progress_ctx, nettle_progress_func *progress,

                             /* Desired size of modulo, in bits */
                             unsigned n_size,

                             /* Desired size of public exponent, in bits. If
                              * zero, the passed in value pub->e is used. */
                             unsigned e_size)
{
    return rsa_generate_keypair((struct rsa_public_key *) pub, (struct rsa_private_key *) key, random_ctx, random,
                                progress_ctx, progress, n_size, e_size);
}

/* Generates a public-key expression if PRIV is NULL. */
int ifm_rsa_keypair_to_sexp(struct nettle_buffer *buffer,
                            const char *algorithm_name, /* NULL means "rsa" */
                            const struct ifm_rsa_public_key *pub,
                            const struct ifm_rsa_private_key *priv)
{
    return rsa_keypair_to_sexp(buffer, algorithm_name, (struct rsa_public_key *) pub, (struct rsa_private_key *) priv);
}

int ifm_rsa_keypair_from_sexp_alist(struct ifm_rsa_public_key *pub,
                                    struct ifm_rsa_private_key *priv,
                                    unsigned limit,
                                    struct sexp_iterator *i)
{
    return rsa_keypair_from_sexp_alist((struct rsa_public_key *) pub, (struct rsa_private_key *) priv, limit, i);
}

/* If PRIV is NULL, expect a public-key expression. If PUB is NULL,
 * expect a private key expression and ignore the parts not needed for
 * the public key. */
/* Keys must be initialized before calling this function, as usual. */
int ifm_rsa_keypair_from_sexp(struct ifm_rsa_public_key *pub,
                              struct ifm_rsa_private_key *priv,
                              unsigned limit,
                              size_t length, const uint8_t *expr)
{
    return rsa_keypair_from_sexp((struct rsa_public_key *) pub, (struct rsa_private_key *) priv, limit, length, expr);
}

int ifm_rsa_public_key_from_der_iterator(struct ifm_rsa_public_key *pub,
                                         unsigned limit,
                                         struct asn1_der_iterator *i)
{
    return rsa_public_key_from_der_iterator((struct rsa_public_key *) pub, limit, i);
}

int ifm_rsa_private_key_from_der_iterator(struct ifm_rsa_public_key *pub,
                                          struct ifm_rsa_private_key *priv,
                                          unsigned limit,
                                          struct asn1_der_iterator *i)
{
    return rsa_private_key_from_der_iterator((struct rsa_public_key *) pub, (struct rsa_private_key *) priv, limit, i);
}

/* For public keys, use PRIV == NULL */
int ifm_rsa_keypair_from_der(struct ifm_rsa_public_key *pub,
                             struct ifm_rsa_private_key *priv,
                             unsigned limit,
                             size_t length, const uint8_t *data)
{
    return rsa_keypair_from_der((struct rsa_public_key *) pub, (struct rsa_private_key *) priv, limit, length, data);
}

/* OpenPGP format. Experimental interface, subject to change. */
int ifm_rsa_keypair_to_openpgp(struct nettle_buffer *buffer,
                               const struct ifm_rsa_public_key *pub,
                               const struct ifm_rsa_private_key *priv,
                               /* A single user id. NUL-terminated utf8. */
                               const char *userid)
{
    return rsa_keypair_to_openpgp(buffer, (struct rsa_public_key *) pub, (struct rsa_private_key *) priv, userid);
}
