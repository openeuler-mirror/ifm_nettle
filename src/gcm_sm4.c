/******************************************************************************
 * ifm_nettle-gcm_sm4.c: sm4 gcm
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

#include "gcm_meta.h"
#include "ifm_utils.h"
#include "nettle_src/sm4.h"

#ifdef __aarch64__
extern int uadk_ctx_setup(struct uadk_aead_st *uadk_ctx);
extern int uadk_gcm_init(struct uadk_aead_st *uadk_ctx);
extern void free_uadk(struct uadk_aead_st *uadk_ctx);
extern int uadk_gcm_set_key(struct uadk_aead_st *uadk_ctx, uint8_t *key, size_t length);
extern void uadk_gcm_set_iv(struct uadk_aead_st *uadk_ctx, size_t length, const uint8_t *iv);
extern int uadk_gcm_update(struct uadk_aead_st *uadk_ctx, size_t length, const uint8_t *data);
extern int uadk_gcm_encrypt(struct uadk_aead_st *uadk_ctx, size_t length, uint8_t *dst, const uint8_t *src);
extern int uadk_gcm_decrypt(struct uadk_aead_st *uadk_ctx, size_t length, uint8_t *dst, const uint8_t *src);
extern void uadk_gcm_digest(struct uadk_aead_st *uadk_ctx, size_t length, uint8_t *digest);
#endif

void ifm_gcm_sm4_set_key(struct ifm_gcm_sm4_ctx *ctx, const uint8_t *key)
{
    gcm_sm4_set_key((struct gcm_sm4_ctx *)ctx, key);
    // 对于使用鲲鹏加速的场景下，将原有ctx的内容进行初始化之外，需要额外调用uadk_gcm_init初始化UADK所需的配置信息
#ifdef __aarch64__
    if (!UadkEnabled()) {
        ctx->use_uadk = false;
        return;
    }
    ctx->uadk_ctx.alg = WCRYPTO_CIPHER_SM4;
    ctx->uadk_ctx.mode = WCRYPTO_CIPHER_GCM;
    if ((0 == uadk_gcm_init(&(ctx->uadk_ctx))) &&
        0 == uadk_gcm_set_key(&(ctx->uadk_ctx), (uint8_t *)key, SM4_KEY_SIZE)) {
        ctx->use_uadk = true;
    } else {
        free_uadk(&(ctx->uadk_ctx));
        ctx->use_uadk = false;
    }
#endif
}

void ifm_gcm_sm4_update(struct ifm_gcm_sm4_ctx *ctx, size_t length, const uint8_t *data)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        if (uadk_gcm_update(&(ctx->uadk_ctx), length, data) == FAILED) {
            if (ctx->uadk_ctx.opdata.assoc_size) {
                gcm_sm4_update((struct gcm_sm4_ctx *)ctx, ctx->uadk_ctx.opdata.assoc_size, ctx->uadk_ctx.opdata.in);
            }
            gcm_sm4_update((struct gcm_sm4_ctx *)ctx, length, data);
            free_uadk(&(ctx->uadk_ctx));
            ctx->use_uadk = false;
        }
    } else {
        gcm_sm4_update((struct gcm_sm4_ctx *)ctx, length, data);
    }
#else
    gcm_sm4_update((struct gcm_sm4_ctx *)ctx, length, data);
#endif
}

void ifm_gcm_sm4_set_iv(struct ifm_gcm_sm4_ctx *ctx, size_t length, const uint8_t *iv)
{
#ifdef __aarch64__
    // 当iv的长度不是gcm-aes的标准长度GCM_IV_SIZE，使用nettle执行
    if (ctx->use_uadk && length == GCM_IV_SIZE) {
        uadk_gcm_set_iv(&(ctx->uadk_ctx), length, iv);
    } else {
        ctx->use_uadk = false;
        gcm_sm4_set_iv((struct gcm_sm4_ctx *)ctx, length, iv);
    }
#else
    gcm_sm4_set_iv((struct gcm_sm4_ctx *)ctx, length, iv);
#endif
}

void ifm_gcm_sm4_encrypt(struct ifm_gcm_sm4_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        if (uadk_gcm_encrypt(&(ctx->uadk_ctx), length, dst, src) == FAILED) {
            if (ctx->uadk_ctx.opdata.assoc_size) {
                gcm_sm4_update((struct gcm_sm4_ctx *)ctx, ctx->uadk_ctx.opdata.assoc_size, ctx->uadk_ctx.opdata.in);
            }
            gcm_sm4_encrypt((struct gcm_sm4_ctx *)ctx, length, dst, src);
            free_uadk(&(ctx->uadk_ctx));
            ctx->use_uadk = false;
        }
    } else {
        gcm_sm4_encrypt((struct gcm_sm4_ctx *)ctx, length, dst, src);
    }
#else
    gcm_sm4_encrypt((struct gcm_sm4_ctx *)ctx, length, dst, src);
#endif
}

void ifm_gcm_sm4_decrypt(struct ifm_gcm_sm4_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        if (uadk_gcm_decrypt(&(ctx->uadk_ctx), length, dst, src) == FAILED) {
            if (ctx->uadk_ctx.opdata.assoc_size) {
                gcm_sm4_update((struct gcm_sm4_ctx *)ctx, ctx->uadk_ctx.opdata.assoc_size, ctx->uadk_ctx.opdata.in);
            }
            gcm_sm4_decrypt((struct gcm_sm4_ctx *)ctx, length, dst, src);
            free_uadk(&(ctx->uadk_ctx));
            ctx->use_uadk = false;
        }
    } else {
        gcm_sm4_decrypt((struct gcm_sm4_ctx *)ctx, length, dst, src);
    }
#else
    gcm_sm4_decrypt((struct gcm_sm4_ctx *)ctx, length, dst, src);
#endif
}

void ifm_gcm_sm4_digest(struct ifm_gcm_sm4_ctx *ctx, size_t length, uint8_t *digest)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        uadk_gcm_digest(&(ctx->uadk_ctx), length, digest);
        free_uadk(&(ctx->uadk_ctx));
    } else {
        gcm_sm4_digest((struct gcm_sm4_ctx *)ctx, length, digest);
    }
#else
    gcm_sm4_digest((struct gcm_sm4_ctx *)ctx, length, digest);
#endif
}