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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "crypt.h"
#include "../ifm_utils.h"
#include "xcrypt_uadk_sha2.h"


/**
 *  本代码文件目前存在的问题
 *  1. crypt对于输入长度有限制，不能超过512字符，超过长度将返回一个固定值
 *  因此，超过512字符的输入无法比较crypt和uadk_crypt算法的运行效率
 *
 *  2. sha2crypt函数整体逻辑及实现内容过长，超过50行限制
 *  若强行限制行数将导致出现多个带有很多参数的函数，sha2crypt函数整体逻辑被分散导致理解产生困难
 *
 *  Author:
 *  Lingtao Zeng <mccarty_zzz2017@163.com>
 */

#ifdef __aarch64__
#include "../uadk_meta.h"
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_digest.h"

#define b64t ((const char *) ascii64)

#define LENGTH_OF_NUMBER(n) (sizeof #n - 1)

#define XCRYPT_SHA256_HASH_LENGTH 43
#define XCRYPT_SHA512_HASH_LENGTH 86

int sha_hash_length = XCRYPT_SHA256_HASH_LENGTH;

#define HASH_LENGTH \
    (sizeof (salt_prefix) + sizeof (sha_rounds_prefix) + \
    LENGTH_OF_NUMBER (ROUNDS_MAX) + SALT_LEN_MAX + 1 + sha_hash_length)

const unsigned char ascii64[65] =
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        "\x00";

#define BASE 10
#define ROUND_BASE 16
#define OUTPUT_LAST_SIZE 2
#define OUTPUT_SIZE3 3

// COMMON DEFINTE
static char salt_prefix[] = "$5$";
static char sha_rounds_prefix[] = "rounds=";

int SALT_LEN_MAX = 16;
int ROUNDS_DEFAULT = 5000;
int ROUNDS_MIN = 1000;
int ROUNDS_MAX = 999999999;

#define CRYPT_ALGO_SHA256 5
#define CRYPT_ALGO_SHA512 6

#define XCRYPT_SHA256_BLOCK_SIZE 32
#define XCRYPT_SHA512_BLOCK_SIZE 64

int block_size = XCRYPT_SHA256_BLOCK_SIZE;
uint8_t SHA2_DIGEST_SIZE = 32;
int XCRYPT_SHA2 = WCRYPTO_SHA256;

/**
 * 适配libxcrypt中的sha2XXX_Update_Recycled函数
 * @param *uadk_ctx uadk_ctx结构体
 * @param length data数据长度
 * @param *data 加密数据
 * @param blocksize 步长
 * @return
 */
int update_recycled (struct uadk_digest_st *uadk_ctx, size_t length, const uint8_t *data, int blocksize)
{
    int ret = 0;
    size_t cnt;
    for (cnt = length; cnt >= blocksize; cnt -= blocksize) {
        ret = uadk_xcrypt_ctx_update(uadk_ctx, blocksize, data, (uint8_t)blocksize);
        if (ret) {
            return ret;
        }
    }
    ret = uadk_xcrypt_ctx_update(uadk_ctx, cnt, data, (uint8_t)blocksize);
    if (ret) {
        return ret;
    }
    return ret;
}


/**
 * 适配libxcrypt中的crypt_shaXXXcrypt_rn函数
 * @param *phrase 待加密原文
 * @param phr_size 待加密原文长度
 * @param *setting 加密设置
 * @param set_size 加密设置长度
 * @param *output 最终计算结果输出保存的地址
 * @param out_size 最终计算结果长度
 * @param *scratch ifm_buffer地址
 * @param scr_size ifm_buffer占用空间
 * @param algo hash算法
 * @return
 */
int sha2crypt(const char *phrase, size_t phr_size, const char *setting, size_t set_size,
              uint8_t *output, size_t out_size, void *scratch, size_t scr_size, int algo)
{
    struct ifm_sha512_buffer *buf = scratch;
    if (algo == CRYPT_ALGO_SHA256) { // SHA256算法参数设置
        strcpy(salt_prefix, "$5$");
        block_size = XCRYPT_SHA256_BLOCK_SIZE;
        SHA2_DIGEST_SIZE = XCRYPT_SHA256_BLOCK_SIZE;
        XCRYPT_SHA2 = WCRYPTO_SHA256;
        sha_hash_length = XCRYPT_SHA256_HASH_LENGTH;
    } else {  // SHA512算法参数设置
        strcpy(salt_prefix, "$6$");
        block_size = XCRYPT_SHA512_BLOCK_SIZE;
        SHA2_DIGEST_SIZE = XCRYPT_SHA512_BLOCK_SIZE;
        XCRYPT_SHA2 = WCRYPTO_SHA512;
        sha_hash_length = XCRYPT_SHA512_HASH_LENGTH;
    }

    uint8_t *result = buf->result;
    uint8_t *p_bytes = buf->p_bytes;
    uint8_t *s_bytes = buf->s_bytes;
    char *cp = (char *)output;
    const char *salt = setting;

    int ret;
    size_t salt_size;
    size_t cnt;
    size_t rounds = ROUNDS_DEFAULT; // Default number of rounds.
    int rounds_custom = 0;

    if (strncmp (salt_prefix, salt, sizeof (salt_prefix) - 1) == 0) // Find beginning of salt string.
        salt += sizeof (salt_prefix) - 1; // Skip salt prefix.

    if (strncmp (salt, sha_rounds_prefix, sizeof (sha_rounds_prefix) - 1) == 0) {
        const char *num = salt + sizeof (sha_rounds_prefix) - 1;
        /* Do not allow an explicit setting of zero rounds, nor of the
           default number of rounds, nor leading zeroes on the rounds.  */
        if (!(*num >= '1' && *num <= '9')) {
            errno = EINVAL;
            return errno;
        }

        errno = 0;
        char *endp;
        rounds = strtoul (num, &endp, BASE);
        if (endp == num || *endp != '$'
            || rounds < ROUNDS_MIN
            || rounds > ROUNDS_MAX
            || errno) {
            errno = EINVAL;
            return errno;
        }
        salt = endp + 1;
        rounds_custom = 1;
    }

    salt_size = strcspn (salt, "$:\n"); // The salt ends at the next '$' or the end of the string.
    if (!(salt[salt_size] == '$' || !salt[salt_size])) {
        errno = EINVAL;
        return errno;
    }

    /* Ensure we do not use more salt than SALT_LEN_MAX. */
    if (salt_size > SALT_LEN_MAX)
        salt_size = SALT_LEN_MAX;

    struct uadk_digest_st *uctx = &(buf->uadk_ctx);
    /* Compute alternate SHA256 sum with input PHRASE, SALT, and PHRASE.  The
       final result will be added to the first context.  */
    ret = uadk_xcrypt_ctx_init(&(buf->uadk_ctx), XCRYPT_SHA2, 0, SHA2_DIGEST_SIZE);
    if (ret) {
        return ret;
    }

    /* Add phrase.  */
    ret = uadk_xcrypt_ctx_update(&(buf->uadk_ctx), phr_size, (uint8_t *)phrase, SHA2_DIGEST_SIZE);
    if (ret) {
        uadk_xcrypt_ctx_free(&(buf->uadk_ctx));
        return ret;
    }
    /* Add salt.  */
    ret = uadk_xcrypt_ctx_update(&(buf->uadk_ctx), salt_size, (uint8_t *)salt, SHA2_DIGEST_SIZE);
    if (ret) {
        uadk_xcrypt_ctx_free(&(buf->uadk_ctx));
        return ret;
    }
    /* Add phrase again.  */
    ret = uadk_xcrypt_ctx_update(&(buf->uadk_ctx), phr_size, (uint8_t *)phrase, SHA2_DIGEST_SIZE);
    if (ret) {
        uadk_xcrypt_ctx_free(&(buf->uadk_ctx));
        return ret;
    }
    /* Now get result of this (32 bytes).  */
    if (uctx->opdata.in_bytes > 0) {
        ret = wcrypto_do_digest(uctx->ctx, &(uctx->opdata), NULL);
        if (ret) {
            uadk_xcrypt_ctx_free(&(buf->uadk_ctx));
            return ret;
        }
    }
    uadk_xcrypt_ctx_digest(&(buf->uadk_ctx), SHA2_DIGEST_SIZE, (uint8_t *)result);

    /* Prepare for the real work.  */
    ret = uadk_xcrypt_ctx_init(&(buf->uadk_ctx), XCRYPT_SHA2, 1, SHA2_DIGEST_SIZE);
    if (ret) {
        return ret;
    }
    /* Add the phrase string.  */
    ret = uadk_xcrypt_ctx_update(&(buf->uadk_ctx), phr_size, (uint8_t *)phrase, SHA2_DIGEST_SIZE);
    if (ret) {
        uadk_xcrypt_ctx_free(&(buf->uadk_ctx));
        return ret;
    }
    /* The last part is the salt string.  This must be at most 8
       characters and it ends at the first `$' character (for
       compatibility with existing implementations).  */
    ret = uadk_xcrypt_ctx_update(&(buf->uadk_ctx), salt_size, (uint8_t *)salt, SHA2_DIGEST_SIZE);
    if (ret) {
        uadk_xcrypt_ctx_free(&(buf->uadk_ctx));
        return ret;
    }
    /* Add for any character in the phrase one byte of the alternate sum.  */
    for (cnt = phr_size; cnt > block_size; cnt -= block_size) {
        ret = uadk_xcrypt_ctx_update(&(buf->uadk_ctx), block_size, (uint8_t *) result, SHA2_DIGEST_SIZE);
        if (ret) {
            uadk_xcrypt_ctx_free(&(buf->uadk_ctx));
            return ret;
        }
    }
    ret = uadk_xcrypt_ctx_update(&(buf->uadk_ctx), cnt, (uint8_t *)result, SHA2_DIGEST_SIZE);
    if (ret) {
        uadk_xcrypt_ctx_free(&(buf->uadk_ctx));
        return ret;
    }
    /* Take the binary representation of the length of the phrase and for every
       1 add the alternate sum, for every 0 the phrase.  */
    for (cnt = phr_size; cnt > 0; cnt >>= 1) {
        if ((cnt & 1) != 0) {
            ret = uadk_xcrypt_ctx_update(&(buf->uadk_ctx), block_size, (uint8_t *) result, SHA2_DIGEST_SIZE);
        } else {
            ret = uadk_xcrypt_ctx_update(&(buf->uadk_ctx), phr_size, (uint8_t *) phrase, SHA2_DIGEST_SIZE);
        }
        if (ret) {
            uadk_xcrypt_ctx_free(&(buf->uadk_ctx));
            return ret;
        }
    }
    /* Create intermediate result.  */
    if (uctx->opdata.in_bytes > 0) {
        ret = wcrypto_do_digest(uctx->ctx, &(uctx->opdata), NULL);
        if (ret) {
            uadk_xcrypt_ctx_free(&(buf->uadk_ctx));
            return ret;
        }
    }
    uadk_xcrypt_ctx_digest(&(buf->uadk_ctx), SHA2_DIGEST_SIZE, (uint8_t *)result);

    /* Start computation of P byte sequence.  */
    ret = uadk_xcrypt_ctx_init(&(buf->uadk_ctx), XCRYPT_SHA2, 1, SHA2_DIGEST_SIZE);
    if (ret) {
        return ret;
    }
    /* For every character in the password add the entire password.  */
    for (cnt = 0; cnt < phr_size; ++cnt) {
        ret = uadk_xcrypt_ctx_update(&(buf->uadk_ctx), phr_size, (uint8_t *) phrase, SHA2_DIGEST_SIZE);
        if (ret) {
            uadk_xcrypt_ctx_free(&(buf->uadk_ctx));
            return ret;
        }
    }
    /* Finish the digest.  */
    if (uctx->opdata.in_bytes > 0) {
        ret = wcrypto_do_digest(uctx->ctx, &(uctx->opdata), NULL);
        if (ret) {
            uadk_xcrypt_ctx_free(&(buf->uadk_ctx));
            return ret;
        }
    }
    uadk_xcrypt_ctx_digest(&(buf->uadk_ctx), SHA2_DIGEST_SIZE, (uint8_t *)p_bytes);

    /* Start computation of S byte sequence.  */
    ret = uadk_xcrypt_ctx_init(&(buf->uadk_ctx), XCRYPT_SHA2, 1, SHA2_DIGEST_SIZE);
    if (ret) {
        return ret;
    }
    /* For every character in the password add the entire password.  */
    for (cnt = 0; cnt < (size_t) ROUND_BASE + (size_t) result[0]; ++cnt) {
        ret = uadk_xcrypt_ctx_update(&(buf->uadk_ctx), salt_size, (uint8_t *) salt, SHA2_DIGEST_SIZE);
        if (ret) {
            uadk_xcrypt_ctx_free(&(buf->uadk_ctx));
            return ret;
        }
    }
    /* Finish the digest.  */
    if (uctx->opdata.in_bytes > 0) {
        ret = wcrypto_do_digest(uctx->ctx, &(uctx->opdata), NULL);
        if (ret) {
            uadk_xcrypt_ctx_free(&(buf->uadk_ctx));
            return ret;
        }
    }
    uadk_xcrypt_ctx_digest(&(buf->uadk_ctx), SHA2_DIGEST_SIZE, (uint8_t *)s_bytes);

    /* Repeatedly run the collected hash value through SHA256 to burn
       CPU cycles.  */
    for (cnt = 0; cnt < rounds; ++cnt) {
        /* New context.  */
        ret = uadk_xcrypt_ctx_init(&(buf->uadk_ctx), XCRYPT_SHA2, 1, SHA2_DIGEST_SIZE);
        if (ret) {
            return ret;
        }
        /* Add phrase or last result.  */
        if ((cnt & 1) != 0) {
            ret = update_recycled(&(buf->uadk_ctx), phr_size, (uint8_t *) p_bytes, block_size);
            if (ret) {
                uadk_xcrypt_ctx_free(&(buf->uadk_ctx));
                return ret;
            }
        } else {
            ret = uadk_xcrypt_ctx_update(&(buf->uadk_ctx), block_size, (uint8_t *) result, SHA2_DIGEST_SIZE);
            if (ret) {
                uadk_xcrypt_ctx_free(&(buf->uadk_ctx));
                return ret;
            }
        }
        /* Add salt for numbers not divisible by 3.  */
        if (cnt % 3 != 0) {
            ret = update_recycled(&(buf->uadk_ctx), salt_size, (uint8_t *) s_bytes, block_size);
            if (ret) {
                uadk_xcrypt_ctx_free(&(buf->uadk_ctx));
                return ret;
            }
        }
        /* Add phrase for numbers not divisible by 7.  */
        if (cnt % 7 != 0) {
            ret = update_recycled(&(buf->uadk_ctx), phr_size, (uint8_t *) p_bytes, block_size);
            if (ret) {
                uadk_xcrypt_ctx_free(&(buf->uadk_ctx));
                return ret;
            }
        }
        /* Add phrase or last result.  */
        if ((cnt & 1) != 0) {
            ret = uadk_xcrypt_ctx_update(&(buf->uadk_ctx), block_size, (uint8_t *) result, SHA2_DIGEST_SIZE);
            if (ret) {
                uadk_xcrypt_ctx_free(&(buf->uadk_ctx));
                return ret;
            }
        } else {
            ret = update_recycled(&(buf->uadk_ctx), phr_size, (uint8_t *) p_bytes, block_size);
            if (ret) {
                uadk_xcrypt_ctx_free(&(buf->uadk_ctx));
                return ret;
            }
        }
        /* Create intermediate result.  */
        if (uctx->opdata.in_bytes > 0) {
            ret = wcrypto_do_digest(uctx->ctx, &(uctx->opdata), NULL);
            if (ret) {
                uadk_xcrypt_ctx_free(&(buf->uadk_ctx));
                return ret;
            }
        }
        uadk_xcrypt_ctx_digest(&(buf->uadk_ctx), SHA2_DIGEST_SIZE, (uint8_t *) result);
    }

    uadk_xcrypt_ctx_free(&(buf->uadk_ctx));

    /* Now we can construct the result string. */
    memcpy (cp, salt_prefix, sizeof (salt_prefix) - 1);
    cp += sizeof (salt_prefix) - 1;

    if (rounds_custom==1) {
        int n = snprintf (cp, HASH_LENGTH - (sizeof (salt_prefix) - 1),
                          "%s%zu$", sha_rounds_prefix, rounds);
        cp += n;
    }

    memcpy (cp, salt, salt_size);
    cp += salt_size;
    *cp++ = '$';

#define b64_from_24bit(B2, B1, B0, N)                   \
    do {                                                \
    unsigned int w = ((((unsigned int)(B2)) << 16) |    \
                      (((unsigned int)(B1)) << 8) |     \
                      ((unsigned int)(B0)));            \
    int n = (N);                                        \
    while (n-- > 0) {                                   \
        *cp++ = b64t[w & 0x3f];                         \
        w >>= 6;                                        \
    }                                                 \
    } while (0)
    if (algo == CRYPT_ALGO_SHA256) {
        b64_from_24bit (result[0], result[10], result[20], 4);
        b64_from_24bit (result[21], result[1], result[11], 4);
        b64_from_24bit (result[12], result[22], result[2], 4);
        b64_from_24bit (result[3], result[13], result[23], 4);
        b64_from_24bit (result[24], result[4], result[14], 4);
        b64_from_24bit (result[15], result[25], result[5], 4);
        b64_from_24bit (result[6], result[16], result[26], 4);
        b64_from_24bit (result[27], result[7], result[17], 4);
        b64_from_24bit (result[18], result[28], result[8], 4);
        b64_from_24bit (result[9], result[19], result[29], 4);
        b64_from_24bit (0, result[31], result[30], 3);
    } else {
        b64_from_24bit (result[0], result[21], result[42], 4);
        b64_from_24bit (result[22], result[43], result[1], 4);
        b64_from_24bit (result[44], result[2], result[23], 4);
        b64_from_24bit (result[3], result[24], result[45], 4);
        b64_from_24bit (result[25], result[46], result[4], 4);
        b64_from_24bit (result[47], result[5], result[26], 4);
        b64_from_24bit (result[6], result[27], result[48], 4);
        b64_from_24bit (result[28], result[49], result[7], 4);
        b64_from_24bit (result[50], result[8], result[29], 4);
        b64_from_24bit (result[9], result[30], result[51], 4);
        b64_from_24bit (result[31], result[52], result[10], 4);
        b64_from_24bit (result[53], result[11], result[32], 4);
        b64_from_24bit (result[12], result[33], result[54], 4);
        b64_from_24bit (result[34], result[55], result[13], 4);
        b64_from_24bit (result[56], result[14], result[35], 4);
        b64_from_24bit (result[15], result[36], result[57], 4);
        b64_from_24bit (result[37], result[58], result[16], 4);
        b64_from_24bit (result[59], result[17], result[38], 4);
        b64_from_24bit (result[18], result[39], result[60], 4);
        b64_from_24bit (result[40], result[61], result[19], 4);
        b64_from_24bit (result[62], result[20], result[41], 4);
        b64_from_24bit (0, 0, result[63], 2);
    }
    *cp = '\0';

    return 0;
}

/**
 * 检查输出以及setting参数是否合法
 * @param *setting 加密setting
 * @param *output 输出结果
 * @param *size 输出大小
 * @return
 */
void make_failure_token (const char *setting, char *output, int size)
{
    if (size >= OUTPUT_SIZE3) {
        output[0] = '*';
        output[1] = '0';
        output[OUTPUT_LAST_SIZE] = '\0';

        if (setting && setting[0] == '*' && setting[1] == '0')
            output[1] = '1';
    } else if (size == OUTPUT_LAST_SIZE) {
        /* If there's not enough space for the full failure token, do the
           best we can.  */
        output[0] = '*';
        output[1] = '\0';
    } else if (size == 1) {
        output[0] = '\0';
    }
}

/**
 * 检查setting是否存在非法字符
 * @param *setting 加密setting
 * @return
 */
int check_badsalt_chars (const char *setting)
{
    size_t i;

    for (i = 0; setting[i] != '\0'; i++)
        if ((unsigned char) setting[i] <= 0x20 ||
            (unsigned char) setting[i] >= 0x7f)
            return 1;

    return strcspn (setting, "!*:;\\") != i;
}

/**
 * 初始化 uadk_ctx 相关参数，申请资源
 * @param *uadk_ctx uadk_ctx结构体
 * @param algs 加密算法
 * @param init 是否首次初始化
 * @param out_bytes_size opdata.out_bytes大小
 * @return
 */
int uadk_xcrypt_ctx_init(struct uadk_digest_st *uadk_ctx, enum wcrypto_digest_alg algs,
                         int init, uint8_t out_bytes_size)
{
    static struct wd_queue q;
    static struct wd_blkpool_setup pool_setup;
    static void *pool = NULL;
    static bool q_init = false;
    int ret = 0;
    if (!q_init) {
        memset(&q, 0, sizeof(q));
        q.capa.alg = "digest";
        ret = wd_request_queue(&q);
        if (ret) {
            return ret;
        }

        memset(&pool_setup, 0, sizeof(pool_setup));
        pool_setup.block_size = MAX_BLOCK_SZ; // set pool  inv + key + in + out
        pool_setup.block_num = MAX_BLOCK_NM;
        pool_setup.align_size = SQE_SIZE;
        pool = wd_blkpool_create(&q, &pool_setup);

        q_init = true;
    }

    // init为 0 时初始化相关参数，其余情况不需要重复申请，只需要将需要用到的参数初始化即可
    if (init == 0) {
        uadk_ctx->pool = pool;

        uadk_ctx->setup.alg = algs;
        uadk_ctx->setup.mode = WCRYPTO_DIGEST_NORMAL;
        uadk_ctx->setup.br.alloc = (void *)wd_alloc_blk;
        uadk_ctx->setup.br.free = (void *)wd_free_blk;
        uadk_ctx->setup.br.iova_map = (void *)wd_blk_iova_map;
        uadk_ctx->setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
        uadk_ctx->setup.br.get_bufsize = (void *)wd_blksize;
        uadk_ctx->setup.br.usr = pool;

        uadk_ctx->pq = &q;
        uadk_ctx->ctx = wcrypto_create_digest_ctx(&q, &(uadk_ctx->setup));
        memset(&(uadk_ctx->opdata), 0, sizeof(struct wcrypto_digest_op_data));

        if (!uadk_ctx->opdata.in) {
            uadk_ctx->opdata.in = wd_alloc_blk(uadk_ctx->pool);
        }
        if (!uadk_ctx->opdata.out) {
            uadk_ctx->opdata.out = wd_alloc_blk(uadk_ctx->pool);
        }
    }
    uadk_ctx->opdata.in_bytes = 0;
    uadk_ctx->opdata.out_bytes = out_bytes_size;
    return ret;
}

/**
 * 更新 uadk_ctx 加密相关数据
 * @param *uadk_ctx uadk_ctx结构体
 * @param length 待加密输入长度
 * @param data 输入
 * @param out_bytes_size opdata.out_bytes大小
 * @return
 */
int uadk_xcrypt_ctx_update(struct uadk_digest_st *uadk_ctx, size_t length, const uint8_t *data, uint8_t out_bytes_size)
{
    int ret = 0;
    if (length > 0) {
        const uint8_t *data_pt = NULL;
        size_t total_len = 0;
        if (NULL == uadk_ctx->ctx) {
            uadk_ctx->ctx = wcrypto_create_digest_ctx(uadk_ctx->pq, &(uadk_ctx->setup));
        }
        if (!uadk_ctx->opdata.in) {
            uadk_ctx->opdata.in = wd_alloc_blk(uadk_ctx->pool);
        }
        if (!uadk_ctx->opdata.out) {
            uadk_ctx->opdata.out = wd_alloc_blk(uadk_ctx->pool);
            uadk_ctx->opdata.out_bytes = out_bytes_size;
        }
        do {
            data_pt = data + total_len;
            // 分段输入，每段大小为MAX_BLOCK_SZ
            if (total_len + MAX_BLOCK_SZ <= length) {
                memcpy(uadk_ctx->opdata.in, data_pt, MAX_BLOCK_SZ);
                uadk_ctx->opdata.in_bytes = MAX_BLOCK_SZ;
                uadk_ctx->opdata.has_next = true;
                total_len += MAX_BLOCK_SZ;
            } else {
                memcpy(uadk_ctx->opdata.in + uadk_ctx->opdata.in_bytes, data_pt, length - total_len);
                uadk_ctx->opdata.in_bytes += length - total_len;
                uadk_ctx->opdata.has_next = false;
                total_len = length;
            }
        } while (total_len < length);
    } else {
        return 1;
    }
    return ret;
}

/**
 * 更新 digest 结果
 * @param *uadk_ctx uadk_ctx结构体
 * @param length 待加密输入长度
 * @param *digest 待写入地址
 * @return
 */
void uadk_xcrypt_ctx_digest(struct uadk_digest_st *uadk_ctx, size_t length, uint8_t *digest)
{
    memcpy(digest, uadk_ctx->opdata.out, length);
}

/**
 * 释放资源
 * @param *uadk_ctx uadk_ctx结构体
 * @return
 */
void uadk_xcrypt_ctx_free(struct uadk_digest_st *uadk_ctx)
{
    memset(&(uadk_ctx->opdata), 0, sizeof(struct wcrypto_digest_op_data));

    if (uadk_ctx->opdata.in) {
        wd_free_blk(uadk_ctx->pool, uadk_ctx->opdata.in);
    }
    if (uadk_ctx->opdata.out) {
        wd_free_blk(uadk_ctx->pool, uadk_ctx->opdata.out);
    }

    if (uadk_ctx->ctx) {
        wcrypto_del_digest_ctx(uadk_ctx->ctx);
        uadk_ctx->ctx = NULL;
    }
}
#endif

/**
 * 适配libxcrypt中的crypt_r函数
 * @param *__phrase 待加密原文
 * @param *__setting 配置加密方式
 * @param *__data crypt_data数据结构用于存储结果
 * @return
 */
char *uadk_crypt_r(const char *__phrase, const char *__setting, struct crypt_data *__data)
{
#ifdef __aarch64__
    if (UadkEnabled() == true) {
        make_failure_token (__setting, __data->output, sizeof __data->output);
        if (!__phrase || !__setting) {
            errno = EINVAL;
            return "*0";
        }
        /* Do these strlen() calls before reading prefixes of either
           'phrase' or 'setting', so we get a predictable crash if they are not valid strings. */
        size_t phr_size = strlen (__phrase);
        size_t set_size = strlen (__setting);
        if (phr_size >= CRYPT_MAX_PASSPHRASE_SIZE) {
            errno = ERANGE;
            return "*0";
        }
        if (check_badsalt_chars (__setting)) {
            errno = EINVAL;
            return "*0";
        }
        int ret = 0;
        if (__setting[1] == '5' && phr_size>0) {
            struct ifm_sha256_buffer scratch;
            scratch.use_uadk = true;
            ret = sha2crypt(__phrase, phr_size, __setting, set_size, (unsigned char *)__data->output,
                            sizeof (__data->output), &scratch, sizeof (&scratch), CRYPT_ALGO_SHA256);
            if (ret) {
                return crypt_r(__phrase, __setting, __data);
            }
        } else if (__setting[1] == '6' && phr_size>0) {
            struct ifm_sha512_buffer scratch;
            scratch.use_uadk = true;
            ret = sha2crypt(__phrase, phr_size, __setting, set_size, (unsigned char *)__data->output,
                            sizeof (__data->output), &scratch, sizeof (&scratch), CRYPT_ALGO_SHA512);
            if (ret) {
                return crypt_r(__phrase, __setting, __data);
            }
        } else {
            return crypt_r(__phrase, __setting, __data);
        }
        explicit_bzero (__data->internal, sizeof __data->internal);
#if ENABLE_FAILURE_TOKENS
        return __data->output;
#else
        return __data->output[0] == '*' ? 0 : __data->output;
#endif
    } else {
        return crypt_r(__phrase, __setting, __data);
    }
#else
    return crypt_r(__phrase, __setting, __data);
#endif
}

/**
 * 适配libxcrypt中的crypt_rn函数
 * @param *__phrase 待加密原文
 * @param *__setting 配置加密方式
 * @param *__data crypt_data数据结构用于存储结果
 * @param __size 数据结构大小
 * @return
 */
char *uadk_crypt_rn(const char *__phrase, const char *__setting, void *__data, int __size)
{
    if (__size < 0 || (size_t)__size < sizeof (struct crypt_data)) {
        errno = ERANGE;
        return 0;
    }

    struct crypt_data *nr_crypt_ctx = __data;
    uadk_crypt_r(__phrase, __setting, nr_crypt_ctx);
    return nr_crypt_ctx->output[0] == '*' ? 0 : nr_crypt_ctx->output;
}

/**
 * 适配libxcrypt中的crypt_ra函数
 * @param *__phrase 待加密原文
 * @param *__setting 配置加密方式
 * @param **__data 二维数据结构用于存储结果
 * @param __size 数据结构大小
 * @return
 */
char *uadk_crypt_ra(const char *__phrase, const char *__setting, void **__data, int *__size)
{
    if (!*__data) {
        *__data = malloc (sizeof (struct crypt_data));
        if (!*__data) {
            return 0;
        }
        *__size = sizeof (struct crypt_data);
    }
    if (*__size < 0 || (size_t)*__size < sizeof (struct crypt_data)) {
        void *rdata = malloc (sizeof (struct crypt_data));
        if (!rdata) {
            return 0;
        }
        *__data = rdata;
        *__size = sizeof (struct crypt_data);
    }

    struct crypt_data *nr_crypt_ctx = *__data;
    uadk_crypt_r(__phrase, __setting, nr_crypt_ctx);
    return nr_crypt_ctx->output[0] == '*' ? 0 : nr_crypt_ctx->output;
}

/**
 * 适配libxcrypt中的crypt函数
 * @param *__phrase 待加密原文
 * @param *__setting 配置加密方式
 * @return
 */
char *uadk_crypt(const char *__phrase, const char *__setting)
{
    static struct crypt_data data;
    return uadk_crypt_r(__phrase, __setting, &data);
}