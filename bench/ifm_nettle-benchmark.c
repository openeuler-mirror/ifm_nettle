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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<stdint.h>
#include <time.h>

#include "timing.h"

#include "aes.h"
#include "sha2.h"
#include "bench_sha2_meta.h"
#include "bench_gcm_meta.h"
#include "getopt.h"

static double frequency = 0.0;

/* Process BENCH_BLOCK bytes at a time, for BENCH_INTERVAL seconds. */
#define BENCH_INTERVAL 0.1
#define BENCH_BLOCK 10240
#define EXPEND_TEN 10
#define EXPEND_TWO 2
#define TIME 1048576.0
const size_t BENCH_BLOCKS[7] = {512, 1024, 10240, 512 * 1024, 1024 * 1024, 10 * 1024 * 1024, 20 * 1024 * 1024};
const size_t BENCH_BLOCKS_LENGTH = 7;

enum GCM_TYPE {UPDATE, ENCRYPT, DECRYPT};

static double overhead = 0.0;
static void die(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int re = vfprintf(stderr, format, args);
    if (re < 0) {
        printf("vf error");
        return ;
    }
    va_end(args);

    exit(EXIT_FAILURE);
}
/* Returns second per function call */
static double time_function(void (*f)(void *arg), void *arg)
{
    unsigned ncalls;
    double elapsed;

    for (ncalls = EXPEND_TEN; ;) {
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
    printf("%18s %12s %16s %16s %16s %16s %16s %16s %16s\n", "Algorithm", "mode", "Mbyte(512)/s",
           "Mbyte(1K)/s", "Mbyte(10K)/s", "Mbyte (512K)/s", "Mbyte(1M)/s", "Mbyte(10M)/s", "Mbyte(20M)/s");
}
/* Set data[i] = floor(sqrt(i)) */
static void init_data(uint8_t *data, size_t length)
{
    unsigned i = 0;
    unsigned j = 0;
    for (i = j = 0; i < length;  i++) {
        if (j * j < i) {
            j++;
        }
        data[i] = j;
    }
}

static void init_gcm_data(unsigned length, uint8_t *key)
{
    unsigned i;
    for (i = 0; i < length; i++) {
        key[i] = i;
    }
}

static void display(const char *name, const char *mode, unsigned block_size, double *time)
{
    printf("%18s %12s", name, mode);
    for (int i = 0; i < BENCH_BLOCKS_LENGTH; i++) {
        printf("%16.2f ", BENCH_BLOCKS[i] / (time[i] * TIME));
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

int main(int argc, char **argv)
{
    unsigned i;
    int c;
    const char *alg;
    const struct nettle_hash *hashes[] = {  &nettle_ifm_sha224, &nettle_ifm_sha256,
                                            &nettle_ifm_sha384, &nettle_ifm_sha512,
                                            &nettle_ifm_sha512_224, &nettle_ifm_sha512_256, NULL};
    const struct nettle_aead *aeads[] = {   &nettle_ifm_gcm_aes128, &nettle_ifm_gcm_aes192,
                                            &nettle_ifm_gcm_aes256, NULL};
    enum { OPT_HELP = 300 };
    static const struct option options[] = {    { "help", no_argument, NULL, OPT_HELP },
                                                { "clock-frequency", required_argument, NULL, 'f' },
                                                { NULL, 0, NULL, 0 } };
  
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
        for (i = 0; aeads[i]; i++) {
            if (!alg || strstr(aeads[i]->name, alg)) {
                time_aead(aeads[i]);
            }
        }
        for (i = 0; hashes[i]; i++) {
            if (!alg || strstr(hashes[i]->name, alg)) {
                time_hash(hashes[i]);
            }
        }
        optind++;
    } while (alg && argv[optind]);
    return 0;
}
