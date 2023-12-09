/******************************************************************************
 * aes.c: uadk aes
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * Shankang Ke <shankang@isrc.iscas.ac.cn>
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

/*
 * 当前由于UADK V1接口的限制，AES的实现存在如下约束
 * 1. 不支持数据分段处理，因此最大的数据只支持16M，使用 AES_MAX_BLOCK_SZ 进行限制。
 * 2. 业务使用时，需将入参ctx使用memset置空，则有可能导致未进入该流程初始化，从而在do_cipher时段错误
 */

#ifdef __aarch64__
#include <string.h>
#include "aes_meta.h"
#include "ifm_utils.h"
#include "uadk_meta.h"
#endif

#ifdef __aarch64__

/**
 * @ingroup free_cipher_uadk
 * @par 释放uadk_ctx申请的资源信息
 */
void free_cipher_uadk(struct uadk_cipher_st *uadk_ctx)
{
    free_uadk_opdata(IFM_UADK_ALG_CIPHER, uadk_ctx->p_share_opdata);
    free_uadk_ctx(IFM_UADK_ALG_CIPHER, uadk_ctx->p_share_ctx);
    uadk_ctx->ctx = NULL;
    uadk_ctx->p_share_ctx = NULL;
    uadk_ctx->p_share_opdata = NULL;
    uadk_ctx->set_key = false;
}

/**
 * @ingroup uadk_cipher_init
 * @par nettle没有aes初始化函数，需要在uadk_cipher_set_key时调用此函数初始化UADK，返回0代表成功
 */
int uadk_cipher_init(struct uadk_cipher_st *uadk_ctx)
{
    IFMUadkShareCtx *p_share_ctx = NULL;

    p_share_ctx = get_uadk_ctx(IFM_UADK_ALG_CIPHER, uadk_ctx->alg, uadk_ctx->mode, false);
    if (p_share_ctx == NULL) {
        IFM_ERR("uadk_cipher_init get_uadk_ctx failed\n");
        return -1;
    }
    uadk_ctx->ctx = p_share_ctx->ctx;
    uadk_ctx->p_share_ctx = p_share_ctx;

    return 0;
}

/**
 * @ingroup uadk_cipher_set_key
 * @par 适配uadk的wcrypto_set_cipher_key函数，返回0代表成功
 */
int uadk_cipher_set_key(struct uadk_cipher_st *uadk_ctx, const uint8_t *uadk_key, uint16_t key_len)
{
    int ret = 0;
    if (uadk_ctx == NULL || uadk_key == NULL) {
        return -1;
    }
    ret = uadk_cipher_init(uadk_ctx);
    if (ret != 0) {
        return ret;
    }
    ret = wcrypto_set_cipher_key(uadk_ctx->ctx, (uint8_t *)uadk_key, key_len);
    if (0 == ret) {
        uadk_ctx->set_key = true;
    }
    return ret;
}

/**
 * @ingroup uadk_do_cipher
 * @par 适配uadk的wcrypto_do_cipher函数执行加密、解密运算，对应nettle的encrypt和decrypt接口，
 * @par 模式为CBC到时候，iiv内容不能为空
 */
void uadk_do_cipher(struct uadk_cipher_st *uadk_ctx, uint8_t *iiv, uint8_t *dst, const uint8_t *src, size_t length,
                    bool encrypt)
{
    // length 应大于 0 且为 AES_BLOCK_SIZE 的整数倍，如 16, 32, 48, 64 等等
    if (uadk_ctx == NULL || dst == NULL || src == NULL || length <= 0 || length % AES_BLOCK_SIZE != 0) {
        // 加密失败的情况下，将dst设置为0
        if (dst != NULL) {
            memset(dst, 0, length);
        }
        return;
    }

    uadk_cipher_init(uadk_ctx);

    uadk_ctx->p_share_opdata = get_uadk_opdata(IFM_UADK_ALG_CIPHER);
    if (uadk_ctx->p_share_opdata == NULL) {
        IFM_ERR("uadk_do_cipher get_uadk_opdata failed\n");
        memset(dst, 0, length);
        return;
    }
    uadk_ctx->p_opdata = (struct wcrypto_cipher_op_data *)(uadk_ctx->p_share_opdata->opdata);

    if (encrypt) {
        uadk_ctx->p_opdata->op_type = WCRYPTO_CIPHER_ENCRYPTION;
    } else {
        uadk_ctx->p_opdata->op_type = WCRYPTO_CIPHER_DECRYPTION;
    }

    // 由于当前UADK v1接口不支持cipher的分段，因此最大只能一次性处理AES_MAX_BLOCK_SZ大小的数据
    uadk_ctx->p_opdata->in_bytes = uadk_ctx->p_opdata->out_bytes = length;
    memcpy(uadk_ctx->p_opdata->in, src, uadk_ctx->p_opdata->in_bytes);
    memset(uadk_ctx->p_opdata->out, 0, uadk_ctx->p_opdata->out_bytes);
    // 加密解密模式为CBC的时候，iiv不能为空
    if (NULL != iiv) {
        memcpy(uadk_ctx->p_opdata->iv, iiv, AES128_KEY_SIZE);
        uadk_ctx->p_opdata->iv_bytes = AES128_KEY_SIZE;
    }
    if (0 != wcrypto_do_cipher(uadk_ctx->ctx, uadk_ctx->p_opdata, NULL)) {
        // 加密失败的情况下，将dst设置为0
        if (dst != NULL) {
            memset(dst, 0, length);
        }
        free_cipher_uadk(uadk_ctx);
        return;
    }

    memcpy(dst, uadk_ctx->p_opdata->out, uadk_ctx->p_opdata->out_bytes);

    free_cipher_uadk(uadk_ctx);
}
#endif
