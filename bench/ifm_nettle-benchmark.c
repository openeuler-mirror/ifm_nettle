/* nettle-benchmark.c

   Tests the performance of the various algorithms.

   Copyright (C) 2001, 2010, 2014 Niels Möller

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
#include <assert.h>
#include <errno.h>
#include <math.h>
#include <nettle/knuth-lfib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "timing.h"

#include "aes.h"
#include "bench_gcm_meta.h"
#include "bench_rsa_meta.h"
#include "bench_sha2_meta.h"
#include "bench_sm3_meta.h"
#include "cbc.h"
#include "getopt.h"
#include "ifm_crypt.h"
#include "sha2.h"
#include "sm4.h"

static double frequency = 0.0;

/* Process BENCH_BLOCK bytes at a time, for BENCH_INTERVAL seconds. */
#define RANDOM_NUM 26
#define BENCH_INTERVAL 0.1
#define BENCH_BLOCK 10240
#define EXPEND_TEN 10
#define EXPEND_TWO 2
#define BENCH_BLOCKS_LENGTH 7
const size_t BENCH_BLOCKS[BENCH_BLOCKS_LENGTH] = {512,        1024,        4 * 1024,        10240,
                                                  512 * 1024, 1024 * 1024, 10 * 1024 * 1024};

enum GCM_TYPE { UPDATE, ENCRYPT, DECRYPT };

static double overhead = 0.0;
static void die(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int re = vfprintf(stderr, format, args);
    if (re < 0) {
        printf("vf error");
        va_end(args);
        return;
    }
    va_end(args);

    exit(EXIT_FAILURE);
}
/* Returns second per function call */
static double time_function(void (*f)(void *arg), void *arg)
{
    unsigned ncalls;
    double elapsed;

    for (ncalls = EXPEND_TEN;;) {
        unsigned i;
        time_start();
        for (i = 0; i < ncalls; i++) {
            f(arg);
        }
        elapsed = time_end();
        if (elapsed > BENCH_INTERVAL) {
            break;
        } else if (elapsed < BENCH_INTERVAL / EXPEND_TEN) {
            ncalls *= EXPEND_TEN;
        } else {
            ncalls *= EXPEND_TWO;
        }
    }
    return elapsed / ncalls - overhead;
}

struct bench_hash_info {
    void *ctx;
    nettle_hash_update_func *update;
    const uint8_t *data;
    size_t length;
};

struct bench_cipher_info {
    void *ctx;
    nettle_cipher_func *crypt;
    uint8_t *data;
    uint8_t *out;
    size_t length;
};

static void bench_cipher(void *arg)
{
    struct bench_cipher_info *info = arg;
    info->crypt(info->ctx, info->length, info->data, info->data);
}

struct bench_cbc_info {
    void *ctx;
    nettle_cipher_func *crypt;

    const uint8_t *src;
    uint8_t *dst;

    unsigned block_size;
    uint8_t *iv;
    size_t length;
};

static void bench_cbc_encrypt(void *arg)
{
    struct bench_cbc_info *info = arg;
    cbc_encrypt(info->ctx, info->crypt, info->block_size, info->iv, info->length, info->dst, info->src);
}

static void bench_cbc_decrypt(void *arg)
{
    struct bench_cbc_info *info = arg;
    cbc_decrypt(info->ctx, info->crypt, info->block_size, info->iv, info->length, info->dst, info->src);
}

struct bench_aead_info {
    void *ctx;
    nettle_set_key_func *set_key;
    nettle_set_key_func *set_nonce;
    nettle_hash_update_func *update;
    nettle_crypt_func *crypt;
    nettle_hash_digest_func *digest;
    uint8_t *data;
    uint8_t *iv;
    uint8_t *key;
    size_t length;
    size_t contextSize;
};

struct bench_rsa_info {
    struct rsa_private_key key;
    struct rsa_public_key pub;
    // hash函数所需参数
    const struct nettle_hash *hash;
    size_t length;
    const uint8_t *data;
    void *ctx;

    mpz_t signature;
    nettle_rsa_public_key_init_func *pubinit;
    nettle_rsa_private_key_init_func *priinit;
    nettle_rsa_public_key_prepare_func *pubpre;
    nettle_rsa_private_key_prepare_func *pripre;
    nettle_rsa_public_key_clear_func *pubclr;
    nettle_rsa_private_key_clear_func *priclr;
    nettle_rsa_sign_func *sign;
    nettle_rsa_verify_func *verify;
    nettle_rsa_sign_digest_func *sign_digest;
};

static void bench_rsa(void *arg)
{
    struct bench_rsa_info *info = arg;

    info->hash->update(info->ctx, info->length, info->data);
    info->sign(&info->key, info->ctx, info->signature);
    info->hash->update(info->ctx, info->length, info->data);
    info->verify(&info->pub, info->ctx, info->signature);
}

static void bench_hash(void *arg)
{
    struct bench_hash_info *info = arg;
    info->update(info->ctx, info->length, info->data);
}

static void bench_aead(void *arg)
{
    struct bench_aead_info *info = arg;
    memset(info->ctx, 0, info->contextSize);
    info->set_key(info->ctx, info->key);
    info->set_nonce(info->ctx, info->iv);
    info->update(info->ctx, info->length, info->data);
    info->crypt(info->ctx, info->length, info->data, info->data);
    info->digest(info->ctx, GCM_DIGEST_SIZE, info->data);
}

static void bench_aead_crypt(void *arg)
{
    struct bench_aead_info *info = arg;
    info->crypt(info->ctx, info->length, info->data, info->data);
}

static void bench_aead_update(void *arg)
{
    struct bench_aead_info *info = arg;
    info->update(info->ctx, info->length, info->data);
}

static void header(void)
{
    printf("%18s %12s %16s %16s %16s %16s %16s %16s %16s\n", "Algorithm", "mode", "Mbyte(512)/s", "Mbyte(1K)/s",
           "Mbyte(4K)/s", "Mbyte(10K)/s", "Mbyte (512K)/s", "Mbyte(1M)/s", "Mbyte(10M)/s");
}
/* Set data[i] = floor(sqrt(i)) */
static void init_data(uint8_t *data, size_t length)
{
    unsigned i = 0;
    unsigned j = 0;
    unsigned int seed;
    for (i = j = 0; i < length; i++) {
        if (j * j < i) {
            j++;
        }
        data[i] = rand_r(&seed) % RANDOM_NUM + 'a';
    }
}

static void init_gcm_data(unsigned length, uint8_t *key)
{
    unsigned i;
    unsigned int seed;
    for (i = 0; i < length; i++) {
        key[i] = rand_r(&seed) % RANDOM_NUM + 'a';
    }
}

static void init_key(unsigned length, uint8_t *key)
{
    unsigned i;
    unsigned int seed;
    for (i = 0; i < length; i++) {
        key[i] = rand_r(&seed) % RANDOM_NUM + 'a';
    }
}

static void init_rsa_key(struct rsa_public_key *pub, struct rsa_private_key *key, unsigned n_size, unsigned e_size)
{
    mpz_set_str(pub->n,
                "9eeebbeba0d3abac"
                "f97b9229d66ec86b"
                "688ffd092aba33d4"
                "1496744de5ced947"
                "31d5a4a359ae2fc3"
                "992a58062800fcf2"
                "efb55c6df53b71ee"
                "b1278e0968c77bf7"
                "76dbdb464086a078"
                "6778caeb322fc412"
                "3decd5878f1e050e"
                "2f79080a3785bec0"
                "aaf67b243bf9b21c"
                "ee359807d3cf280f"
                "4b1025a90d7cb4c8"
                "d1f63a632692a853",
                16);
    mpz_set_str(pub->e, "010001", 16);

    rsa_public_key_prepare(pub);

    mpz_set_str(key->p,
                "cdf1e1ffd77d8e3c"
                "13a218b61d74367b"
                "f79da4ea8c4545f7"
                "c0ea9a3d1567b62a"
                "8cfb64cc1d6addd3"
                "4737c8a7606f5bf8"
                "909900d552895ae7"
                "a2669f7b495ce757",
                16);

    mpz_set_str(key->q,
                "C58fb19f71dcd544"
                "aa927fb9b0f6eadd"
                "508fdfced9057835"
                "8aa98d22b3015c08"
                "fd57961f34eaa4da"
                "340a3900f4afb0ba"
                "56da24995bd7a496"
                "b8d31e544510d565",
                16);

    mpz_set_str(key->a,
                "7a3be0b9ab3b185a"
                "cc045fca67bcfc41"
                "a3fc6b4fd325a29b"
                "a4631a5cbb01ad7b"
                "9fe5ee33c01a17c3"
                "38f8011e66fc7188"
                "1cbad365c9f14085"
                "4f3cbdd7bcf9694d",
                16);

    mpz_set_str(key->b,
                "07c4b3b65252ddab"
                "fa8d122aaa13bb7e"
                "825975f27b4424ca"
                "ee2de697d3b41cfb"
                "5982e52b4af8630d"
                "1578c56f0d300f61"
                "f4625588163d6f82"
                "61b8237c2acf13a5",
                16);

    mpz_set_str(key->c,
                "2a08700c27d87396"
                "1b9763952b6bcb33"
                "5effe08e5975d273"
                "fef3f081173809ed"
                "f321d120093a9799"
                "4b1d1cc14eb9f07c"
                "06080e93656483d2"
                "34a2a76204807299",
                16);

    rsa_private_key_prepare(key);
}

static void display(const char *name, const char *mode, unsigned block_size, double *time)
{
    printf("%18s %12s", name, mode);
    for (int i = 0; i < BENCH_BLOCKS_LENGTH; i++) {
        printf("%16.2f ", BENCH_BLOCKS[i] / 1024.0 / 1024.0 / (time[i]));
    }
    printf("\n");
}

static void *xalloc(size_t size)
{
    if (size <= 0) {
        printf("memory size error");
    }
    void *p = malloc(size);
    if (!p) {
        die("Virtual memory exhausted.\n");
    }
    return p;
}

static void time_rsa(const struct nettle_rsa *rsa)
{
    struct bench_rsa_info info;
    double times[BENCH_BLOCKS_LENGTH];
    info.ctx = xalloc(rsa->hash->context_size);
    info.hash = rsa->hash;
    info.sign = rsa->sign;
    info.sign_digest = rsa->sign_digest;
    info.verify = rsa->verify;
    rsa->pubinit(&info.pub);
    rsa->priinit(&info.key);
    init_rsa_key(&info.pub, &info.key, 1024, 50);
    size_t length;
    for (int i = 0; i < BENCH_BLOCKS_LENGTH; i++) {
        length = BENCH_BLOCKS[i];
        times[i] = 0;
        info.hash->init(info.ctx);
        mpz_init(info.signature);
        uint8_t *data = xalloc(length);
        init_data(data, length);
        info.data = data;
        info.length = length;
        times[i] += time_function(bench_rsa, &info);
        free(data);
        mpz_clear(info.signature);
    }
    display(rsa->name, "sign & verify", rsa->hash->block_size, times);
    rsa->pubclr(&info.pub);
    rsa->priclr(&info.key);
    free(info.ctx);
}

static void time_hash(const struct nettle_hash *hash)
{
    struct bench_hash_info info;
    double times[BENCH_BLOCKS_LENGTH];
    info.ctx = xalloc(hash->context_size);
    info.update = hash->update;
    for (int i = 0; i < BENCH_BLOCKS_LENGTH; i++) {
        info.length = BENCH_BLOCKS[i];
        uint8_t *data = xalloc(sizeof(uint8_t) * info.length);
        info.data = data;
        init_data(data, info.length);
        hash->init(info.ctx);
        times[i] = time_function(bench_hash, &info);
        free(data);
    }
    display(hash->name, "update", hash->block_size, times);
    free(info.ctx);
}

static int prefix_p(const char *prefix, const char *s)
{
    size_t i;
    for (i = 0; prefix[i]; i++)
        if (prefix[i] != s[i])
            return 0;
    return 1;
}

static int block_cipher_p(const struct nettle_cipher *cipher)
{
    /* Don't use nettle cbc and ctr for openssl ciphers. */
    return cipher->block_size > 0 && !prefix_p("openssl", cipher->name);
}

static void time_cipher(const struct nettle_cipher *cipher)
{
    void *ctx = xalloc(cipher->context_size);
    uint8_t *key = xalloc(cipher->key_size);
    double times[BENCH_BLOCKS_LENGTH];
    uint8_t *data[BENCH_BLOCKS_LENGTH];
    for (int i = 0; i < BENCH_BLOCKS_LENGTH; i++) {
        data[i] = xalloc(sizeof(uint8_t) * BENCH_BLOCKS[i]);
        init_data(data[i], BENCH_BLOCKS[i]);
    }
    uint8_t *src_data[BENCH_BLOCKS_LENGTH];
    for (int i = 0; i < BENCH_BLOCKS_LENGTH; i++) {
        src_data[i] = xalloc(sizeof(uint8_t) * BENCH_BLOCKS[i]);
        init_data(src_data[i], BENCH_BLOCKS[i]);
    }
    memset(ctx, 0, cipher->context_size);

    printf("\n");

    {
        /* Decent initializers are a GNU extension, so don't use it here. */
        struct bench_cipher_info info;
        info.ctx = ctx;
        info.crypt = cipher->encrypt;

        init_key(cipher->key_size, key);
        cipher->set_encrypt_key(ctx, key);

        for (int i = 0; i < BENCH_BLOCKS_LENGTH; i++) {
            info.length = BENCH_BLOCKS[i];
            info.data = src_data[i];
            info.out = data[i];
            times[i] = time_function(bench_cipher, &info);
        }
        display(cipher->name, "ECB encrypt", cipher->block_size, times);
    }

    {
        struct bench_cipher_info info;
        info.ctx = ctx;
        info.crypt = cipher->decrypt;

        init_key(cipher->key_size, key);
        cipher->set_decrypt_key(ctx, key);

        for (int i = 0; i < BENCH_BLOCKS_LENGTH; i++) {
            info.length = BENCH_BLOCKS[i];
            info.data = src_data[i];
            info.out = data[i];
            times[i] = time_function(bench_cipher, &info);
        }
        display(cipher->name, "ECB decrypt", cipher->block_size, times);
    }

    if (block_cipher_p(cipher)) {
        uint8_t *iv = xalloc(cipher->block_size);

        /* Do CBC mode */
        {
            struct bench_cbc_info info;
            memset(ctx, 0, cipher->context_size);
            info.ctx = ctx;
            info.crypt = cipher->encrypt;
            info.block_size = cipher->block_size;
            info.iv = iv;

            memset(iv, 0, cipher->block_size);

            cipher->set_encrypt_key(ctx, key);

            for (int i = 0; i < BENCH_BLOCKS_LENGTH; i++) {
                info.length = BENCH_BLOCKS[i];
                info.dst = data[i];
                info.src = src_data[i];
                times[i] = time_function(bench_cbc_encrypt, &info);
            }
            display(cipher->name, "CBC encrypt", cipher->block_size, times);
        }

        {
            struct bench_cbc_info info;
            memset(ctx, 0, cipher->context_size);
            info.ctx = ctx;
            info.crypt = cipher->decrypt;
            info.block_size = cipher->block_size;
            info.iv = iv;

            memset(iv, 0, cipher->block_size);

            cipher->set_decrypt_key(ctx, key);

            for (int i = 0; i < BENCH_BLOCKS_LENGTH; i++) {
                info.length = BENCH_BLOCKS[i];
                info.dst = data[i];
                info.src = src_data[i];
                times[i] = time_function(bench_cbc_decrypt, &info);
            }
            display(cipher->name, "CBC decrypt", cipher->block_size, times);

            memset(iv, 0, cipher->block_size);

            for (int i = 0; i < BENCH_BLOCKS_LENGTH; i++) {
                info.length = BENCH_BLOCKS[i];
                info.dst = data[i];
                info.src = data[i];
                times[i] = time_function(bench_cbc_decrypt, &info);
            }
            display(cipher->name, "  (in-place)", cipher->block_size, times);
        }

        free(iv);
    }
    free(ctx);
    free(key);
}

static void time_aead_handler(const struct nettle_aead *aead, void (*f)(void *arg), enum GCM_TYPE type)
{
    struct bench_aead_info info;
    double times[BENCH_BLOCKS_LENGTH];
    info.ctx = xalloc(aead->context_size);
    const char *mode;
    switch (type) {
        case UPDATE:
            info.update = aead->update;
            mode = "update";
            break;
        case ENCRYPT:
            info.crypt = aead->encrypt;
            mode = "encrypt";
            break;
        case DECRYPT:
            info.crypt = aead->decrypt;
            mode = "decrypt";
            break;
        default:
            info.update = aead->update;
            mode = "update";
            break;
    }

    for (int i = 0; i < BENCH_BLOCKS_LENGTH; i++) {
        info.length = BENCH_BLOCKS[i];
        uint8_t *data = xalloc(sizeof(uint8_t) * info.length);
        info.data = data;
        init_data(data, info.length);
        memset(info.ctx, 0, aead->context_size);
        uint8_t *keydata = xalloc(sizeof(uint8_t) * aead->key_size);
        init_gcm_data(aead->key_size, keydata);
        aead->set_decrypt_key(info.ctx, keydata);

        uint8_t *ivdata = xalloc(sizeof(uint8_t) * GCM_IV_SIZE);
        init_gcm_data(GCM_IV_SIZE, ivdata);
        aead->set_nonce(info.ctx, ivdata);

        times[i] = time_function(f, &info);

        aead->digest(info.ctx, GCM_DIGEST_SIZE, info.data);

        free(ivdata);
        free(keydata);
        free(data);
    }
    display(aead->name, mode, aead->context_size, times);
}

static void time_aead(const struct nettle_aead *aead)
{
    struct bench_aead_info info;
    info.ctx = xalloc(aead->context_size);

    // uadk中aead不支持一次性处理16M以上的数据量，且暂时无法分段处理
    // update
    time_aead_handler(aead, bench_aead_update, UPDATE);

    // encrypt
    time_aead_handler(aead, bench_aead_crypt, ENCRYPT);

    // decrypt
    time_aead_handler(aead, bench_aead_crypt, DECRYPT);

    // total
    double times[BENCH_BLOCKS_LENGTH];
    for (int i = 0; i < BENCH_BLOCKS_LENGTH; i++) {
        info.length = BENCH_BLOCKS[i];

        memset(info.ctx, 0, aead->context_size);
        info.contextSize = aead->context_size;
        uint8_t *data = xalloc(sizeof(uint8_t) * info.length);
        info.data = data;
        init_data(data, info.length);

        uint8_t *keydata = xalloc(sizeof(uint8_t) * aead->key_size);
        init_gcm_data(aead->key_size, keydata);
        info.key = keydata;

        uint8_t *ivdata = xalloc(sizeof(uint8_t) * GCM_IV_SIZE);
        init_gcm_data(GCM_IV_SIZE, ivdata);
        info.iv = ivdata;

        info.set_key = aead->set_encrypt_key;
        info.set_nonce = aead->set_nonce;
        info.update = aead->update;
        info.crypt = aead->encrypt;
        info.digest = aead->digest;

        times[i] = time_function(bench_aead, &info);

        free(ivdata);
        free(keydata);
        free(data);
    }
    display(aead->name, "total", aead->context_size, times);
    free(info.ctx);
}

// crypt benchmark
struct bench_crypt_info {
    uint8_t *data;
    size_t length;
    char *__settings;
    const char *prefix;
};

static void bench_crypt(void *arg)
{
    struct bench_crypt_info *info = arg;
    crypt((char *)info->data, info->__settings);
}

static void init_crypt_data(uint8_t *data, size_t length)
{
    unsigned i = 0;
    for (i = 0; i < length; i++) {
        data[i] = i % 255 + 1;
    }
}

static void time_crypt(const char *algoname, const char *prefix)
{
    struct bench_crypt_info info;

    double times[BENCH_BLOCKS_LENGTH];
    for (int i = 0; i < BENCH_BLOCKS_LENGTH; i++) {
        info.length = BENCH_BLOCKS[i];

        uint8_t *data = xalloc(sizeof(uint8_t) * info.length);
        info.data = data;
        init_crypt_data(data, info.length);
        info.prefix = prefix;
        info.__settings = crypt_gensalt(info.prefix, 0, NULL, 0);
        times[i] = time_function(bench_crypt, &info);

        free(data);
    }
    display(algoname, "crypt", info.length, times);
}

int main(int argc, char **argv)
{
    unsigned i;
    int c;
    const char *alg;
    const struct nettle_hash *hashes[] = {
        &nettle_ifm_sm3,    &nettle_ifm_sha224,     &nettle_ifm_sha256,     &nettle_ifm_sha384,
        &nettle_ifm_sha512, &nettle_ifm_sha512_224, &nettle_ifm_sha512_256, NULL};

    const struct nettle_cipher *ciphers[] = {&ifm_nettle_sm4, &ifm_nettle_aes128, &ifm_nettle_aes192,
                                             &ifm_nettle_aes256, NULL};

    const struct nettle_aead *aeads[] = {&nettle_ifm_gcm_aes128, &nettle_ifm_gcm_aes192, &nettle_ifm_gcm_aes256, NULL};

    const struct nettle_rsa *rsas[] = {&nettle_rsa_md5, &nettle_rsa_sha256, &nettle_rsa_sha512, NULL};

    enum { OPT_HELP = 300 };
    static const struct option options[] = {
        {"help", no_argument, NULL, OPT_HELP}, {"clock-frequency", required_argument, NULL, 'f'}, {NULL, 0, NULL, 0}};

    while ((c = getopt_long(argc, argv, "f:", options, NULL)) != -1) {
        switch (c) {
            case 'f':
                frequency = atof(optarg);
                if (frequency > 0.0) {
                    break;
                }
            case OPT_HELP:
                printf("Usage: nettle-benchmark [-f clock frequency] [alg...]\n");
                return EXIT_SUCCESS;
            case '?':
                return EXIT_FAILURE;
            default:
                abort();
        }
    }
    time_init();
    printf("\n");

    header();
    do {
        alg = argv[optind];
        for (i = 0; hashes[i]; i++) {
            if (!alg || strstr(hashes[i]->name, alg)) {
                time_hash(hashes[i]);
            }
        }
        for (i = 0; ciphers[i]; i++) {
            if (!alg || strstr(ciphers[i]->name, alg))
                time_cipher(ciphers[i]);
        }

        for (i = 0; aeads[i]; i++) {
            if (!alg || strstr(aeads[i]->name, alg)) {
                time_aead(aeads[i]);
            }
        }

        for (i = 0; rsas[i]; i++) {
            if (!alg || strstr(rsas[i]->name, alg)) {
                time_rsa(rsas[i]);
            }
        }

        time_crypt("uadk_crypt_sha256", "$5$");
        time_crypt("uadk_crypt_sha512", "$6$");
        time_crypt("uadk_crypt_sm3", "$sm3$");
        optind++;
    } while (alg && argv[optind]);
    return 0;
}
