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
#include "nettle/sm3.h"
#include <stdio.h>
#include <string.h>
#include "ifm_utils.h"
#include "sm3_meta.h"
#ifdef __aarch64__
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_digest.h"
#endif

#ifdef __aarch64__
int uadk_sm3ctx_init(struct uadk_digest_st *uadk_ctx, enum wcrypto_digest_alg algs)
{
    IFMUadkShareCtx *p_share_ctx = NULL;

    memset(uadk_ctx, 0, sizeof(struct uadk_digest_st));
    p_share_ctx = get_uadk_ctx(IFM_UADK_ALG_DIGEST, algs, WCRYPTO_DIGEST_NORMAL, true);
    if (p_share_ctx == NULL) {
        IFM_ERR("uadk_ctx_init get_uadk_ctx failed\n");
        return -1;
    }
    uadk_ctx->ctx = p_share_ctx->ctx;

    return 0;
}

int uadk_sm3ctx_update(struct uadk_digest_st *uadk_ctx, size_t length, const uint8_t *data, __u32 out_bytes_size)
{
    const uint8_t *data_pt = NULL;
    size_t total_len = 0;

    if (!uadk_ctx || !uadk_ctx->ctx) {
        IFM_ERR("uadk_ctx_update: uadk_ctx->ctx is NULL\n");
        return -1;
    }

    if (!uadk_ctx->p_share_opdata) {
        uadk_ctx->p_share_opdata = get_uadk_opdata(IFM_UADK_ALG_DIGEST);
        if (!uadk_ctx->p_share_opdata) {
            IFM_ERR("uadk_ctx_update: get_uadk_opdata failed\n");
            return -1;
        }
        uadk_ctx->p_opdata = (struct wcrypto_digest_op_data *)(uadk_ctx->p_share_opdata->opdata);
        uadk_ctx->p_opdata->out_bytes = out_bytes_size;
    }

    do {
        data_pt = data + total_len;
        // 分段输入，每段大小为MAX_BLOCK_SZ
        if (total_len + MAX_BLOCK_SZ <= length) {
            memcpy(uadk_ctx->p_opdata->in, data_pt, MAX_BLOCK_SZ);
            uadk_ctx->p_opdata->in_bytes = MAX_BLOCK_SZ;
            uadk_ctx->p_opdata->has_next = true;
            total_len += MAX_BLOCK_SZ;
        } else {
            memcpy(uadk_ctx->p_opdata->in, data_pt, length - total_len);
            uadk_ctx->p_opdata->in_bytes = length - total_len;
            uadk_ctx->p_opdata->has_next = false;
            total_len = length;
        }
        if (wcrypto_do_digest(uadk_ctx->ctx, uadk_ctx->p_opdata, NULL) != 0) {
            IFM_ERR("uadk_ctx_update: wcrypto_do_digest failed\n");
            return -1;
        }
    } while (total_len < length);

    return 0;
}

void uadk_sm3ctx_digest(struct uadk_digest_st *uadk_ctx, size_t length, uint8_t *digest)
{
    memcpy(digest, uadk_ctx->p_opdata->out, length);

    free_uadk_opdata(IFM_UADK_ALG_DIGEST, uadk_ctx->p_share_opdata);
}

/**
 * @ingroup uadk_sm3_init
 * @par 将uadk的sm3算法适配成sm3_init算法，该接口的使用场景以及参数同nettle中的sm3_init接口相同
 */
int uadk_sm3_init(struct ifm_sm3_ctx *ctx) { return uadk_sm3ctx_init(&(ctx->uadk_ctx), WCRYPTO_SM3); }

/**
 * @ingroup uadk_sm3_update
 * @par 将uadk的sm3算法适配成sm3_update算法，该接口的使用场景以及参数同nettle中的sm3_update接口相同
 */
int uadk_sm3_update(struct ifm_sm3_ctx *ctx, size_t length, const uint8_t *data)
{
    return uadk_sm3ctx_update(&(ctx->uadk_ctx), length, data, SM3_DIGEST_SIZE);
}

/**
 * @ingroup uadk_sm3_update
 * @par 将uadk的sm3算法适配成sm3_digest算法，该接口的使用场景以及参数同nettle中的sm3_digest接口相同
 */
void uadk_sm3_digest(struct ifm_sm3_ctx *ctx, size_t length, uint8_t *digest)
{
    uadk_sm3ctx_digest(&(ctx->uadk_ctx), length, digest);
    uadk_sm3_init(ctx);
}
#endif

void ifm_sm3_init(struct ifm_sm3_ctx *ctx)
{
    struct sm3_ctx nettle_sm3_ctx;
    sm3_init(&nettle_sm3_ctx);
    memcpy(ctx, &nettle_sm3_ctx, sizeof(nettle_sm3_ctx));

#ifdef __aarch64__
    if (!UadkEnabled() || 0 != uadk_sm3_init(ctx)) {
        ctx->use_uadk = false;
    } else {
        ctx->use_uadk = true;
    }
#endif
}

void ifm_sm3_update(struct ifm_sm3_ctx *ctx, size_t length, const uint8_t *data)
{
#ifdef __aarch64__
    if (ctx->use_uadk && length > 0) {
        uadk_sm3_update(ctx, length, data);
    } else {
        sm3_update((struct sm3_ctx *)ctx, length, data);
        ctx->use_uadk = false;
    }
#else
    sm3_update((struct sm3_ctx *)ctx, length, data);
#endif
}

void ifm_sm3_digest(struct ifm_sm3_ctx *ctx, size_t length, uint8_t *digest)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        uadk_sm3_digest(ctx, length, digest);
    } else {
        sm3_digest((struct sm3_ctx *)ctx, length, digest);
    }
#else
    sm3_digest((struct sm3_ctx *)ctx, length, digest);
#endif
}