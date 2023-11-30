/******************************************************************************
 * sm4.c: uadk sm4
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * Chen-yufanspace <chenyufan912@gmail.com>
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
#include "nettle_src/sm4.h"
#include <string.h>
#include "aes_common.h"
#include "cipher.h"
#include "ifm_utils.h"
#include "nettle/nettle-meta.h"
#include "sm4_meta.h"

void ifm_sm4_set_encrypt_key(struct ifm_sm4_ctx *ctx, const uint8_t *key)
{
#ifdef __aarch64__
    // 由于nettle中的CBC模式以及ECB模式用的都是uadk_cipher_set_key，但是uadk中需要根据mode不同
    // 设置不同的ctx值，因此在set_key的时候，不调用uadk_cipher_set_key，只是将uadk_key保存下来
    if (UadkEnabled()) {
        ctx->use_uadk = true;
        memset(ctx->uadk_key, 0, sizeof(ctx->uadk_key));
        memcpy(ctx->uadk_key, key, sizeof(ctx->uadk_key));
        ctx->encrypt = true;
        ctx->uadk_ctx.set_key = false;
    } else {
        ctx->use_uadk = false;
        sm4_set_encrypt_key((struct sm4_ctx *)ctx, key);
    }
#else
    sm4_set_encrypt_key((struct sm4_ctx *)ctx, key);
#endif
}

void ifm_sm4_set_decrypt_key(struct ifm_sm4_ctx *ctx, const uint8_t *key)
{
#ifdef __aarch64__
    // 由于nettle中的CBC模式以及ECB模式用的都是uadk_cipher_set_key，但是uadk中需要根据mode不同
    // 设置不同的ctx值，因此在set_key的时候，不调用uadk_cipher_set_key，只是将uadk_key保存下来
    if (UadkEnabled()) {
        ctx->use_uadk = true;
        memset(ctx->uadk_key, 0, sizeof(ctx->uadk_key));
        memcpy(ctx->uadk_key, key, sizeof(ctx->uadk_key));
        ctx->encrypt = false;
        ctx->uadk_ctx.set_key = false;
    } else {
        ctx->use_uadk = false;
        sm4_set_decrypt_key((struct sm4_ctx *)ctx, key);
    }
#else
    sm4_set_decrypt_key((struct sm4_ctx *)ctx, key);
#endif
}

void ifm_sm4_crypt(struct ifm_sm4_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
#ifdef __aarch64__
    // UADK不支持处理长度为0的字符串
    if (ctx->use_uadk == false) {
        sm4_crypt((struct sm4_ctx *)ctx, length, dst, src);
    } else if (ctx->use_uadk == true && length > 0 && length < AES_MAX_BLOCK_SZ) {
        // 实际的ifm_XXX_set_encrypt_key中未调用uadk_cipher_set_key，在此处设置mode之后再调用uadk_cipher_set_key
        if (ctx->uadk_ctx.ctx == NULL || ctx->uadk_ctx.set_key == false) {
            ctx->uadk_ctx.mode = WCRYPTO_CIPHER_ECB;
            ctx->uadk_ctx.alg = WCRYPTO_CIPHER_SM4;
            if (uadk_cipher_set_key(&(ctx->uadk_ctx), ctx->uadk_key, SM4_KEY_SIZE) != 0) {
                IFM_ERR("ifm_sm4_crypt set key failed.\n");
                ctx->use_uadk = false;
                return;
            }
        }
        if (ctx->encrypt)
            uadk_do_cipher((struct uadk_cipher_st *)&(ctx->uadk_ctx), NULL, dst, src, length, true);
        else
            uadk_do_cipher((struct uadk_cipher_st *)&(ctx->uadk_ctx), NULL, dst, src, length, false);
    } else {
        memset(dst, 0, length);
        IFM_ERR("ifm_sm4_crypt failed.\n");
    }
#else
    sm4_crypt((struct sm4_ctx *)ctx, length, dst, src);
#endif
}

const struct nettle_cipher ifm_nettle_sm4 = {"sm4",
                                             sizeof(struct ifm_sm4_ctx),
                                             SM4_BLOCK_SIZE,
                                             SM4_KEY_SIZE,
                                             (nettle_set_key_func *)ifm_sm4_set_encrypt_key,
                                             (nettle_set_key_func *)ifm_sm4_set_decrypt_key,
                                             (nettle_cipher_func *)ifm_sm4_crypt,
                                             (nettle_cipher_func *)ifm_sm4_crypt};
                                            