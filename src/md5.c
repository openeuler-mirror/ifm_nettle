/******************************************************************************
 * md5.c: support uadk md5
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
#include "nettle/md5.h"
#ifdef __aarch64__
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_digest.h"
#endif
#include "md5_meta.h"
#include "ifm_utils.h"

#ifdef __aarch64__
/**
 * @ingroup uadk_md5_init
 * @par 将uadk的md5算法适配成md5_init算法，该接口的使用场景以及参数同nettle中的md5_init接口相同
 */
int uadk_md5_init(struct ifm_md5_ctx *ctx)
{
    IFMUadkShareCtx *p_share_ctx = NULL;

    memset(&(ctx->uadk_ctx), 0, sizeof(ctx->uadk_ctx));
    p_share_ctx = get_uadk_ctx(IFM_UADK_ALG_DIGEST, WCRYPTO_MD5, WCRYPTO_DIGEST_NORMAL, true);
    if (p_share_ctx == NULL) {
        IFM_ERR("uadk_md5_init get_uadk_ctx failed\n");
        return -1;
    }
    ctx->uadk_ctx.ctx = p_share_ctx->ctx;

    return 0;
}

/**
 * @ingroup uadk_md5_update
 * @par 将源数据拆分成固定大小，然后分别调用wcrypto_do_digest接口提前进行hash计算。
 * 在原有的nettle对应的update接口中，会将数据提前进行压缩计算，因此只要64字节即可满足要求。
 * 但是UADK中没有对应的update接口，因此在update接口中不适合将所有的数据都存储起来。
 */
int uadk_md5_update(struct ifm_md5_ctx *ctx,
                    size_t length,
                    const uint8_t *data)
{
    const uint8_t *data_pt = NULL;
    size_t total_len = 0;

    if (NULL == ctx->uadk_ctx.ctx) {
        if (uadk_md5_init(ctx) != 0) {
            return -1;
        }
    }

    // 接口的使用场景上，会存在多次update然后再digest的情况，因此需考虑无需重复申请的场景
    if (!ctx->uadk_ctx.p_share_opdata) {
        ctx->uadk_ctx.p_share_opdata = get_uadk_opdata(IFM_UADK_ALG_DIGEST);
        if (!ctx->uadk_ctx.p_share_opdata) {
            IFM_ERR("uadk_md5_update: get_uadk_opdata failed\n");
            return -1;
        }
        ctx->uadk_ctx.p_opdata = (struct wcrypto_digest_op_data *)(ctx->uadk_ctx.p_share_opdata->opdata);
        ctx->uadk_ctx.p_opdata->out_bytes = MD5_DIGEST_SIZE;         // MD5的长度是16
    }

    do
    {
        data_pt = data + total_len;
        // 分段输入，每段大小为MAX_BLOCK_SZ
        if (total_len + MAX_BLOCK_SZ <= length)
        {
            memcpy(ctx->uadk_ctx.p_opdata->in, data_pt, MAX_BLOCK_SZ);
            ctx->uadk_ctx.p_opdata->in_bytes = MAX_BLOCK_SZ;
            ctx->uadk_ctx.p_opdata->has_next = true;
            total_len += MAX_BLOCK_SZ;
        }
        else
        {
            memcpy(ctx->uadk_ctx.p_opdata->in, data_pt, length - total_len);
            ctx->uadk_ctx.p_opdata->in_bytes = length - total_len;
            ctx->uadk_ctx.p_opdata->has_next = false;
            total_len = length;
        }
        if (wcrypto_do_digest(ctx->uadk_ctx.ctx, ctx->uadk_ctx.p_opdata, NULL) != 0) {
            IFM_ERR("uadk_md5_update: wcrypto_do_digest failed\n");
            return -1;
        }
    } while (total_len < length);

    return 0;
}

/**
 * @ingroup uadk_md5_digest
 * @par 在update阶段已经提前将数据进行hash，因此在digest阶段只需要将数据复制到digest中，并且进行资源清理。
 */
void uadk_md5_digest(struct ifm_md5_ctx *ctx,
                     size_t length,
                     uint8_t *digest)
{
    memcpy(digest, ctx->uadk_ctx.p_opdata->out, length);

    free_uadk_opdata(IFM_UADK_ALG_DIGEST, ctx->uadk_ctx.p_share_opdata);

    // 参照nettle原有实现逻辑，重新进行init初始化，为下一次的update做准备
    uadk_md5_init(ctx);
}
#endif

void ifm_md5_init(struct ifm_md5_ctx *ctx)
{
    struct md5_ctx nettle_ctx;
    md5_init(&nettle_ctx);
    memcpy(ctx, &nettle_ctx, sizeof(nettle_ctx));

// 对于使用鲲鹏加速的场景下，将原有ctx的内容进行初始化之外，需要额外调用uadk_md5_init初始化UADK所需的配置信息
#ifdef __aarch64__
    if (UadkEnabled() == false || 0 != uadk_md5_init(ctx))
    {
        ctx->use_uadk = false;
    }
    else
    {
        ctx->use_uadk = true;
    }
#endif
}

void ifm_md5_update(struct ifm_md5_ctx *ctx,
                    size_t length,
                    const uint8_t *data)
{
#ifdef __aarch64__
    // UADK不支持处理长度为0的字符串
    if (ctx->use_uadk && length > 0)
    {
        if (uadk_md5_update(ctx, length, data) != 0) {
            md5_update((struct md5_ctx *)ctx, length, data);
            ctx->use_uadk = false;
            return;
        }
    }
    else
    {
        md5_update((struct md5_ctx *)ctx, length, data);
        ctx->use_uadk = false;
    }
#else
    md5_update((struct md5_ctx *)ctx, length, data);
#endif
}

void ifm_md5_digest(struct ifm_md5_ctx *ctx,
                    size_t length,
                    uint8_t *digest)
{
#ifdef __aarch64__
    if (ctx->use_uadk)
    {
        uadk_md5_digest(ctx, length, digest);
    }
    else
    {
        md5_digest((struct md5_ctx *)ctx, length, digest);
    }
#else
    md5_digest((struct md5_ctx *)ctx, length, digest);
#endif
}