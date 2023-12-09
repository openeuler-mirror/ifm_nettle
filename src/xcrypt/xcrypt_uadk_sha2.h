/******************************************************************************
 * One way encryption based on the SHA2-based Unix crypt implementation.
 *
 * Written by Ulrich Drepper <drepper at redhat.com> in 2007 [1].
 * Modified by Zack Weinberg <zackw at panix.com> in 2017, 2018.
 * Composed by Björn Esser <besser82 at fedoraproject.org> in 2018.
 * Modified by Björn Esser <besser82 at fedoraproject.org> in 2020.
 * To the extent possible under law, the named authors have waived all
 * copyright and related or neighboring rights to this work.
 *
 * Added uadk adaptation to libxcrypt sha2 series algorithms
 * Authors:
 * Lingtao Zeng <mccarty_zzz2017@163.com>
 *
 * See https://creativecommons.org/publicdomain/zero/1.0/ for further
 * details.
 *
 * This file is a modified except from [2], lines 648 up to 909.
 *
 * [1]  https://www.akkadia.org/drepper/sha-crypt.html
 * [2]  https://www.akkadia.org/drepper/SHA-crypt.txt
 *
 ********************************************************************************/
#ifndef XCRYPT_UADK_SHA2_H
#define XCRYPT_UADK_SHA2_H

#ifdef __aarch64__
#include "../uadk_meta.h"
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_digest.h"

#define CRYPT_MAX_PASSPHRASE_SIZE 512
#define CRYPT_GENSALT_OUTPUT_SIZE 192

typedef __uint8_t uint8_t;

struct ifm_sha256_buffer {
    uint8_t result[32];
    uint8_t p_bytes[32];
    uint8_t s_bytes[32];
    struct uadk_digest_st uadk_ctx; /* UADK相关的结构体数据 */
    bool use_uadk;
};

struct ifm_sha512_buffer {
    uint8_t result[64];
    uint8_t p_bytes[64];
    uint8_t s_bytes[64];
    struct uadk_digest_st uadk_ctx; /* UADK相关的结构体数据 */
    bool use_uadk;
};

struct ifm_sm3_buffer {
    uint8_t result[32];
    uint8_t p_bytes[32];
    uint8_t s_bytes[32];
    struct uadk_digest_st uadk_ctx; /* UADK相关的结构体数据 */
    bool use_uadk;
};

int update_recycled (struct uadk_digest_st *uadk_ctx, size_t length, const uint8_t *data, int blocksize);
int sha2crypt(const char *phrase, size_t phr_size, const char *setting, size_t set_size,
              uint8_t *output, size_t out_size, void *scratch, size_t scr_size, int algo);

void make_failure_token (const char *setting, char *output, int size);
int check_badsalt_chars (const char *setting);

int uadk_xcrypt_ctx_init(struct uadk_digest_st *uadk_ctx, enum wcrypto_digest_alg algs,
                         int init, uint8_t out_bytes_size);
int uadk_xcrypt_ctx_update(struct uadk_digest_st *uadk_ctx, size_t length, const uint8_t *data, uint8_t out_bytes_size);
void uadk_xcrypt_ctx_digest(struct uadk_digest_st *uadk_ctx, size_t length, uint8_t *digest);
void uadk_xcrypt_ctx_free(struct uadk_digest_st *uadk_ctx);

#endif

char *uadk_crypt_r(const char *__phrase, const char *__setting, struct crypt_data *__data);
char *uadk_crypt_rn(const char *__phrase, const char *__setting, void *__data, int __size);
char *uadk_crypt_ra(const char *__phrase, const char *__setting, void **__data, int *__size);
char *uadk_crypt(const char *__phrase, const char *__setting);

#endif // XCRYPT_UADK_SHA2_H
