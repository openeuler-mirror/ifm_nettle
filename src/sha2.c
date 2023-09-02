/******************************************************************************
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * huangduirong <huangduirong@huawei.com>
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
#include <stdio.h>
#include <string.h>
#include "nettle/sha2.h"
#include "sha2_meta.h"
#include "ifm_utils.h"
#ifdef __aarch64__
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_digest.h"
#endif

#ifdef __aarch64__
int uadk_ctx_init(struct uadk_digest_st *uadk_ctx, enum wcrypto_digest_alg algs)
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

    return ret;
}

void uadk_ctx_update(struct uadk_digest_st *uadk_ctx, size_t length, const uint8_t *data, __u32 out_bytes_size)
{
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
            memcpy(uadk_ctx->opdata.in, data_pt, length - total_len);
            uadk_ctx->opdata.in_bytes = length - total_len;
            uadk_ctx->opdata.has_next = false;
            total_len = length;
        }
        wcrypto_do_digest(uadk_ctx->ctx, &(uadk_ctx->opdata), NULL);
    } while (total_len < length);
}
void uadk_ctx_digest(struct uadk_digest_st *uadk_ctx, size_t length, uint8_t *digest)
{
    memcpy(digest, uadk_ctx->opdata.out, length);

    if (uadk_ctx->opdata.in) {
        wd_free_blk(uadk_ctx->pool, uadk_ctx->opdata.in);
        uadk_ctx->opdata.in = NULL;
    }
    if (uadk_ctx->opdata.out) {
        wd_free_blk(uadk_ctx->pool, uadk_ctx->opdata.out);
        uadk_ctx->opdata.out = NULL;
    }
    if (uadk_ctx->ctx) {
        wcrypto_del_digest_ctx(uadk_ctx->ctx);
        uadk_ctx->ctx = NULL;
    }
}
/**
 * @ingroup uadk_sha256_init
 * @par 将uadk的sha256算法适配成sha256_init算法，该接口的使用场景以及参数同nettle中的sha256_init接口相同
 */
int uadk_sha256_init(struct ifm_sha256_ctx *ctx)
{
    return uadk_ctx_init(&(ctx->uadk_ctx), WCRYPTO_SHA256);
}

/**
 * @ingroup uadk_sha256_update
 * @par 将uadk的sha256算法适配成sha256_update算法，该接口的使用场景以及参数同nettle中的sha256_update接口相同
 */
void uadk_sha256_update(struct ifm_sha256_ctx *ctx,
                        size_t length,
                        const uint8_t *data)
{
    uadk_ctx_update(&(ctx->uadk_ctx), length, data, SHA256_DIGEST_SIZE);
}

/**
 * @ingroup uadk_sha256_update
 * @par 将uadk的sha256算法适配成sha256_digest算法，该接口的使用场景以及参数同nettle中的sha256_digest接口相同
 */
void uadk_sha256_digest(struct ifm_sha256_ctx *ctx,
                        size_t length,
                        uint8_t *digest)
{
    uadk_ctx_digest(&(ctx->uadk_ctx), length, digest);
    uadk_sha256_init(ctx);
}
/**
 * @ingroup uadk_sha224_init
 * @par 将uadk的sha224算法适配成sha224_init算法，该接口的使用场景以及参数同nettle中的sha224_init接口相同
 */
int uadk_sha224_init(struct ifm_sha224_ctx *ctx)
{
    return uadk_ctx_init(&(ctx->uadk_ctx), WCRYPTO_SHA224);
}

/**
 * @ingroup uadk_sha224_update
 * @par 将uadk的sha224算法适配成sha224_update算法，该接口的使用场景以及参数同nettle中的sha224_update接口相同
 */
void uadk_sha224_update(struct ifm_sha224_ctx *ctx,
                        size_t length,
                        const uint8_t *data)
{
    uadk_ctx_update(&(ctx->uadk_ctx), length, data, SHA224_DIGEST_SIZE);
}

/**
 * @ingroup uadk_sha224_digest
 * @par 将uadk的sha224算法适配成sha224_digest算法，该接口的使用场景以及参数同nettle中的sha224_digest接口相同
 */
void uadk_sha224_digest(struct ifm_sha224_ctx *ctx,
                        size_t length,
                        uint8_t *digest)
{
    uadk_ctx_digest(&(ctx->uadk_ctx), length, digest);
    uadk_sha224_init(ctx);
}
/**
 * @ingroup uadk_sha384_init
 * @par 将uadk的sha384算法适配成sha384_init算法，该接口的使用场景以及参数同nettle中的sha384_init接口相同
 */
int uadk_sha384_init(struct ifm_sha384_ctx *ctx)
{
    return uadk_ctx_init(&(ctx->uadk_ctx), WCRYPTO_SHA384);
}

/**
 * @ingroup uadk_sha384_update
 * @par 将uadk的sha384算法适配成sha384_update算法，该接口的使用场景以及参数同nettle中的sha384_update接口相同
 */
void uadk_sha384_update(struct ifm_sha384_ctx *ctx,
                        size_t length,
                        const uint8_t *data)
{
    uadk_ctx_update(&(ctx->uadk_ctx), length, data, SHA384_DIGEST_SIZE);
}

/**
 * @ingroup uadk_sha384_digest
 * @par 将uadk的sha384算法适配成sha384_digest算法，该接口的使用场景以及参数同nettle中的sha384_digest接口相同
 */
void uadk_sha384_digest(struct ifm_sha384_ctx *ctx,
                        size_t length,
                        uint8_t *digest)
{
    uadk_ctx_digest(&(ctx->uadk_ctx), length, digest);
    uadk_sha384_init(ctx);
}
/**
 * @ingroup uadk_sha512_init
 * @par 将uadk的sha512算法适配成sha512_init算法，该接口的使用场景以及参数同nettle中的sha512_init接口相同
 */
int uadk_sha512_init(struct ifm_sha512_ctx *ctx)
{
    return uadk_ctx_init(&(ctx->uadk_ctx), WCRYPTO_SHA512);
}

/**
 * @ingroup uadk_sha512_update
 * @par 将uadk的sha512算法适配成sha512_update算法，该接口的使用场景以及参数同nettle中的sha512_update接口相同
 */
void uadk_sha512_update(struct ifm_sha512_ctx *ctx,
                        size_t length,
                        const uint8_t *data)
{
   uadk_ctx_update(&(ctx->uadk_ctx), length, data, SHA512_DIGEST_SIZE);
}

/**
 * @ingroup uadk_sha512_digest
 * @par 将uadk的sha512算法适配成sha512_digest算法，该接口的使用场景以及参数同nettle中的sha512_digest接口相同
 */
void uadk_sha512_digest(struct ifm_sha512_ctx *ctx,
                        size_t length,
                        uint8_t *digest)
{
    uadk_ctx_digest(&(ctx->uadk_ctx), length, digest);
    uadk_sha512_init(ctx);
}
/**
 * @ingroup uadk_sha512_224_init
 * @par 将uadk的sha512_224算法适配成sha512_224_init算法，该接口的使用场景以及参数同nettle中的sha512_224_init接口相同
 */
int uadk_sha512_224_init(struct ifm_sha512_224_ctx *ctx)
{
    return uadk_ctx_init(&(ctx->uadk_ctx), WCRYPTO_SHA512_224);
}

/**
 * @ingroup uadk_sha512_224_update
 * @par 将uadk的sha512_224算法适配成sha512_224_update算法，该接口的使用场景以及参数同nettle中的sha512_224_update接口相同
 */
void uadk_sha512_224_update(struct ifm_sha512_224_ctx *ctx,
                            size_t length,
                            const uint8_t *data)
{
    uadk_ctx_update(&(ctx->uadk_ctx), length, data, SHA512_224_DIGEST_SIZE);
}

/**
 * @ingroup uadk_sha512_224_digest
 * @par 将uadk的sha512_224算法适配成sha512_224_digest算法，该接口的使用场景以及参数同nettle中的sha512_224_digest接口相同
 */
void uadk_sha512_224_digest(struct ifm_sha512_224_ctx *ctx,
                            size_t length,
                            uint8_t *digest)
{
    uadk_ctx_digest(&(ctx->uadk_ctx), length, digest);
    uadk_sha512_224_init(ctx);
}
/**
 * @ingroup uadk_sha512_256_init
 * @par 将uadk的sha512_256算法适配成sha512_256_init算法，该接口的使用场景以及参数同nettle中的sha512_256_init接口相同
 */
int uadk_sha512_256_init(struct ifm_sha512_256_ctx *ctx)
{
    return uadk_ctx_init(&(ctx->uadk_ctx), WCRYPTO_SHA512_256);
}

/**
 * @ingroup uadk_sha512_256_update
 * @par 将uadk的sha512_256算法适配成sha512_256_update算法，该接口的使用场景以及参数同nettle中的sha512_256_update接口相同
 */
void uadk_sha512_256_update(struct ifm_sha512_256_ctx *ctx,
                            size_t length,
                            const uint8_t *data)
{
    uadk_ctx_update(&(ctx->uadk_ctx), length, data, SHA512_256_DIGEST_SIZE);
}

/**
 * @ingroup uadk_sha512_256_digest
 * @par 将uadk的sha512_256算法适配成sha512_256_digest算法，该接口的使用场景以及参数同nettle中的sha512_256_digest接口相同
 */
void uadk_sha512_256_digest(struct ifm_sha512_256_ctx *ctx,
                            size_t length,
                            uint8_t *digest)
{
    uadk_ctx_digest(&(ctx->uadk_ctx), length, digest);
    uadk_sha512_256_init(ctx);
}
#endif

void ifm_sha256_init(struct ifm_sha256_ctx *ctx)
{
    struct sha256_ctx nettle_sha256_ctx;
    sha256_init(&nettle_sha256_ctx);
    memcpy(ctx, &nettle_sha256_ctx, sizeof(nettle_sha256_ctx));

#ifdef __aarch64__
    if (UadkEnabled() == false || 0 != uadk_sha256_init(ctx)) {
        ctx->use_uadk = false;
    } else {
        ctx->use_uadk = true;
    }
#endif
}

void ifm_sha256_update(struct ifm_sha256_ctx *ctx,
                       size_t length,
                       const uint8_t *data)
{
#ifdef __aarch64__
    // UADK不支持处理长度为0的字符串
    if (ctx->use_uadk && length >0) {
        uadk_sha256_update(ctx, length, data);
    } else {
        sha256_update((struct sha256_ctx *)ctx, length, data);
        ctx->use_uadk = false;
    }
#else
    sha256_update((struct sha256_ctx *)ctx, length, data);
#endif
}

void ifm_sha256_digest(struct ifm_sha256_ctx *ctx, size_t length, uint8_t *digest)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        uadk_sha256_digest(ctx, length, digest);
    } else {
        sha256_digest((struct sha256_ctx *)ctx, length, digest);
    }
#else
    sha256_digest((struct sha256_ctx *)ctx, length, digest);
#endif
}

void ifm_sha224_init(struct ifm_sha224_ctx *ctx)
{
    struct sha224_ctx nettle_sha224_ctx;
    sha224_init(&nettle_sha224_ctx);
    memcpy(ctx, &nettle_sha224_ctx, sizeof(nettle_sha224_ctx));

#ifdef __aarch64__
    if (UadkEnabled() == false || 0 != uadk_sha224_init(ctx)) {
        ctx->use_uadk = false;
    } else {
        ctx->use_uadk = true;
    }
#endif
}

void ifm_sha224_update(struct ifm_sha224_ctx *ctx, size_t length, const uint8_t *data)
{
#ifdef __aarch64__
    // UADK不支持处理长度为0的字符串
    if (ctx->use_uadk && length > 0) {
        uadk_sha224_update(ctx, length, data);
    } else {
        sha224_update((struct sha224_ctx *)ctx, length, data);
        ctx->use_uadk = false;
    }
#else
    sha224_update((struct sha224_ctx *)ctx, length, data);
#endif
}

void ifm_sha224_digest(struct ifm_sha224_ctx *ctx, size_t length, uint8_t *digest)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        uadk_sha224_digest(ctx, length, digest);
    } else {
        sha224_digest((struct sha224_ctx *)ctx, length, digest);
    }
#else
    sha224_digest((struct sha224_ctx *)ctx, length, digest);
#endif
}

void ifm_sha512_init(struct ifm_sha512_ctx *ctx)
{
    struct sha512_ctx nettle_sha512_ctx;
    sha512_init(&nettle_sha512_ctx);
    memcpy(ctx, &nettle_sha512_ctx, sizeof(nettle_sha512_ctx));

#ifdef __aarch64__
    if (UadkEnabled() == false || 0 != uadk_sha512_init(ctx)) {
        ctx->use_uadk = false;
    } else {
        ctx->use_uadk = true;
    }
#endif
}

void ifm_sha512_update(struct ifm_sha512_ctx *ctx, size_t length, const uint8_t *data)
{
#ifdef __aarch64__
    // UADK不支持处理长度为0的字符串
    if (ctx->use_uadk && length > 0) {
        uadk_sha512_update(ctx, length, data);
    } else {
        sha512_update((struct sha512_ctx *)ctx, length, data);
        ctx->use_uadk = false;
    }
#else
    sha512_update((struct sha512_ctx *)ctx, length, data);
#endif
}

void ifm_sha512_digest(struct ifm_sha512_ctx *ctx, size_t length, uint8_t *digest)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        uadk_sha512_digest(ctx, length, digest);
    } else {
        sha512_digest((struct sha512_ctx *)ctx, length, digest);
    }
#else
    sha512_digest((struct sha512_ctx *)ctx, length, digest);
#endif
}


void ifm_sha384_init(struct ifm_sha384_ctx *ctx)
{
    struct sha384_ctx nettle_sha384_ctx;
    sha384_init(&nettle_sha384_ctx);
    memcpy(ctx, &nettle_sha384_ctx, sizeof(nettle_sha384_ctx));

#ifdef __aarch64__
    if (UadkEnabled() == false || 0 != uadk_sha384_init(ctx)) {
        ctx->use_uadk = false;
    } else {
        ctx->use_uadk = true;
    }
#endif
}

void ifm_sha384_update(struct ifm_sha384_ctx *ctx, size_t length, const uint8_t *data)
{
#ifdef __aarch64__
    // UADK不支持处理长度为0的字符串
    if (ctx->use_uadk && length > 0) {
        uadk_sha384_update(ctx, length, data);
    } else {
        sha384_update((struct sha384_ctx *)ctx, length, data);
        ctx->use_uadk = false;
    }
#else
    sha384_update((struct sha384_ctx *)ctx, length, data);
#endif
}

void ifm_sha384_digest(struct ifm_sha384_ctx *ctx, size_t length, uint8_t *digest)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        uadk_sha384_digest(ctx, length, digest);
    } else {
        sha384_digest((struct sha384_ctx *)ctx, length, digest);
    }
#else
    sha384_digest((struct sha384_ctx *)ctx, length, digest);
#endif
}


void ifm_sha512_224_init(struct ifm_sha512_224_ctx *ctx)
{
    struct sha512_224_ctx nettle_sha512_224_ctx;
    sha512_224_init(&nettle_sha512_224_ctx);
    memcpy(ctx, &nettle_sha512_224_ctx, sizeof(nettle_sha512_224_ctx));

#ifdef __aarch64__
    if (UadkEnabled() == false || 0 != uadk_sha512_224_init(ctx)) {
        ctx->use_uadk = false;
    } else {
        ctx->use_uadk = true;
    }
#endif
}

void ifm_sha512_224_update(struct ifm_sha512_224_ctx *ctx, size_t length, const uint8_t *data)
{
#ifdef __aarch64__
    // UADK不支持处理长度为0的字符串
    if (ctx->use_uadk && length >0) {
        uadk_sha512_224_update(ctx, length, data);
    } else {
        sha512_224_update((struct sha512_224_ctx *)ctx, length, data);
        ctx->use_uadk = false;
    }
#else
    sha512_224_update((struct sha512_224_ctx *)ctx, length, data);
#endif
}

void ifm_sha512_224_digest(struct ifm_sha512_224_ctx *ctx, size_t length, uint8_t *digest)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        uadk_sha512_224_digest(ctx, length, digest);
    } else {
        sha512_224_digest((struct sha512_224_ctx *)ctx, length, digest);
    }
#else
    sha512_224_digest((struct sha512_224_ctx *)ctx, length, digest);
#endif
}

void ifm_sha512_256_init(struct ifm_sha512_256_ctx *ctx)
{
    struct sha512_256_ctx nettle_sha512_256_ctx;
    sha512_256_init(&nettle_sha512_256_ctx);
    memcpy(ctx, &nettle_sha512_256_ctx, sizeof(nettle_sha512_256_ctx));

#ifdef __aarch64__
    if (UadkEnabled() == false || 0 != uadk_sha512_256_init(ctx)) {
        ctx->use_uadk = false;
    } else {
        ctx->use_uadk = true;
    }
#endif
}

void ifm_sha512_256_update(struct ifm_sha512_256_ctx *ctx, size_t length, const uint8_t *data)
{
#ifdef __aarch64__
    // UADK不支持处理长度为0的字符串
    if (ctx->use_uadk && length >0) {
        uadk_sha512_256_update(ctx, length, data);
    } else {
        sha512_256_update((struct sha512_256_ctx *)ctx, length, data);
        ctx->use_uadk = false;
    }
#else
    sha512_256_update((struct sha512_256_ctx *)ctx, length, data);
#endif
}

void ifm_sha512_256_digest(struct ifm_sha512_256_ctx *ctx, size_t length, uint8_t *digest)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        uadk_sha512_256_digest(ctx, length, digest);
    } else {
        sha512_256_digest((struct sha512_256_ctx *)ctx, length, digest);
    }
#else
    sha512_256_digest((struct sha512_256_ctx *)ctx, length, digest);
#endif
}