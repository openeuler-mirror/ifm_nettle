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
#include "nettle/aes.h"
#include "aes_meta.h"
#include "cipher.h"
#include "ifm_utils.h"

void ifm_aes128_set_encrypt_key(struct ifm_aes128_ctx *ctx, const uint8_t *key)
{
    aes128_set_encrypt_key((struct aes128_ctx *)ctx, key);
#ifdef __aarch64__
    // 由于nettle中的CBC模式以及ECB模式用的都是uadk_cipher_set_key，但是uadk中需要根据mode不同
    // 设置不同的ctx值，因此在set_key的时候，不调用uadk_cipher_set_key，只是将uadk_key保存下来
    if (UadkEnabled()) {
        ctx->use_uadk = true;
        memset(ctx->uadk_key, 0, sizeof(ctx->uadk_key));
        memcpy(ctx->uadk_key, key, sizeof(ctx->uadk_key));
        ctx->uadk_ctx.set_key = false;
    } else {
        ctx->use_uadk = false;
    }
#endif
}

void ifm_aes128_set_decrypt_key(struct ifm_aes128_ctx *ctx, const uint8_t *key)
{
    aes128_set_decrypt_key((struct aes128_ctx *)ctx, key);
#ifdef __aarch64__
    // 由于nettle中的CBC模式以及ECB模式用的都是uadk_cipher_set_key，但是uadk中需要根据mode不同
    // 设置不同的ctx值，因此在set_key的时候，不调用uadk_cipher_set_key，只是将uadk_key保存下来
    if (UadkEnabled()) {
        ctx->use_uadk = true;
        memset(ctx->uadk_key, 0, sizeof(ctx->uadk_key));
        memcpy(ctx->uadk_key, key, sizeof(ctx->uadk_key));
        ctx->uadk_ctx.set_key = false;
    } else {
        ctx->use_uadk = false;
    }
#endif
}

void ifm_aes128_invert_key(struct ifm_aes128_ctx *dst, const struct ifm_aes128_ctx *src)
{
    aes128_invert_key((struct aes128_ctx *)dst, (const struct aes128_ctx *)src);
#ifdef __aarch64__
    if (UadkEnabled() && uadk_cipher_set_key(&(dst->uadk_ctx), src->uadk_key, AES128_KEY_SIZE) == 0) {
        dst->use_uadk = true;
        memcpy(dst->uadk_key, src->uadk_key, sizeof(dst->uadk_key));
        dst->uadk_ctx.set_key = false;
    } else {
        dst->use_uadk = false;
    }
#endif
}

void ifm_aes128_encrypt(struct ifm_aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
#ifdef __aarch64__
    int ret = 0;

    // UADK不支持处理长度为0的字符串
    if (ctx->use_uadk == true && length > 0 && length < AES_MAX_BLOCK_SZ) {
        // 实际的ifm_XXX_set_encrypt_key中未调用uadk_cipher_set_key，在此处设置mode之后再调用uadk_cipher_set_key
        if (ctx->uadk_ctx.ctx == NULL
            || ctx->uadk_ctx.set_key == false) {
            ctx->uadk_ctx.mode = WCRYPTO_CIPHER_ECB;
            ctx->uadk_ctx.alg = WCRYPTO_CIPHER_AES;
            ret = uadk_cipher_set_key(&(ctx->uadk_ctx), ctx->uadk_key, AES128_KEY_SIZE);
            if (ret != 0) {
                IFM_ERR("ifm_aes128_encrypt set key failed.");
                ctx->use_uadk = false;
                aes128_encrypt((const struct aes128_ctx *)ctx, length, dst, src);
                return;
            }
        }
        uadk_do_cipher((struct uadk_cipher_st *)&(ctx->uadk_ctx), NULL, dst, src, length, true);
    } else {
        memset(dst, 0, length);
        aes128_encrypt((const struct aes128_ctx *)ctx, length, dst, src);
    }
#else
    aes128_encrypt((const struct aes128_ctx *)ctx, length, dst, src);
#endif
}

void ifm_aes128_decrypt(struct ifm_aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
#ifdef __aarch64__
    int ret = 0;

    // UADK不支持处理长度为0的字符串
    if (ctx->use_uadk == true && length > 0 && length < AES_MAX_BLOCK_SZ) {
        // 实际的ifm_XXX_set_encrypt_key中未调用uadk_cipher_set_key，在此处设置mode之后再调用uadk_cipher_set_key
        // 如果业务使用时，未将ctx使用memset置空，则有可能导致未进入该流程初始化，从而在do_cipher时段错误
        // 由于有可能在ctx申请之后，重复再设置uadk_key，因此需要考虑ctx不为空但是key不一致的场景。
        if (ctx->uadk_ctx.ctx == NULL
            || ctx->uadk_ctx.set_key == false) {
            ctx->uadk_ctx.mode = WCRYPTO_CIPHER_ECB;
            ctx->uadk_ctx.alg = WCRYPTO_CIPHER_AES;
            ret = uadk_cipher_set_key(&(ctx->uadk_ctx), ctx->uadk_key, AES128_KEY_SIZE);
            if (ret != 0) {
                IFM_ERR("ifm_aes128_decrypt set key failed.");
                ctx->use_uadk = false;
                aes128_decrypt((const struct aes128_ctx *)ctx, length, dst, src);
                return;
            }
        }
        uadk_do_cipher((struct uadk_cipher_st *)&(ctx->uadk_ctx), NULL, dst, src, length, false);
    } else {
        aes128_decrypt((const struct aes128_ctx *)ctx, length, dst, src);
    }
#else
    aes128_decrypt((const struct aes128_ctx *)ctx, length, dst, src);
#endif
}

void ifm_aes192_set_encrypt_key(struct ifm_aes192_ctx *ctx, const uint8_t *key)
{
    aes192_set_encrypt_key((struct aes192_ctx *)ctx, key);
#ifdef __aarch64__
    // 由于nettle中的CBC模式以及ECB模式用的都是uadk_cipher_set_key，但是uadk中需要根据mode不同
    // 设置不同的ctx值，因此在set_key的时候，不调用uadk_cipher_set_key，只是将uadk_key保存下来
    if (UadkEnabled()) {
        ctx->use_uadk = true;
        memset(ctx->uadk_key, 0, sizeof(ctx->uadk_key));
        memcpy(ctx->uadk_key, key, sizeof(ctx->uadk_key));
        ctx->uadk_ctx.set_key = false;
    } else {
        ctx->use_uadk = false;
    }
#endif
}

void ifm_aes192_set_decrypt_key(struct ifm_aes192_ctx *ctx, const uint8_t *key)
{
    aes192_set_decrypt_key((struct aes192_ctx *)ctx, key);
#ifdef __aarch64__
    // 由于nettle中的CBC模式以及ECB模式用的都是uadk_cipher_set_key，但是uadk中需要根据mode不同
    // 设置不同的ctx值，因此在set_key的时候，不调用uadk_cipher_set_key，只是将uadk_key保存下来
    if (UadkEnabled()) {
        ctx->use_uadk = true;
        memset(ctx->uadk_key, 0, sizeof(ctx->uadk_key));
        memcpy(ctx->uadk_key, key, sizeof(ctx->uadk_key));
        ctx->uadk_ctx.set_key = false;
    } else {
        ctx->use_uadk = false;
    }
#endif
}

void ifm_aes192_invert_key(struct ifm_aes192_ctx *dst, const struct ifm_aes192_ctx *src)
{
    aes192_invert_key((struct aes192_ctx *)dst, (const struct aes192_ctx *)src);
#ifdef __aarch64__
    if (UadkEnabled() && uadk_cipher_set_key(&(dst->uadk_ctx), src->uadk_key, AES192_KEY_SIZE) == 0) {
        dst->use_uadk = true;
        memcpy(dst->uadk_key, src->uadk_key, sizeof(dst->uadk_key));
        dst->uadk_ctx.set_key = false;
    } else {
        dst->use_uadk = false;
    }
#endif
}

void ifm_aes192_encrypt(struct ifm_aes192_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
#ifdef __aarch64__
    int ret = 0;

    // UADK不支持处理长度为0的字符串
    if (ctx->use_uadk == true && length > 0 && length < AES_MAX_BLOCK_SZ) {
        // 实际的ifm_XXX_set_encrypt_key中未调用uadk_cipher_set_key，在此处设置mode之后再调用uadk_cipher_set_key
        if (ctx->uadk_ctx.ctx == NULL
            || ctx->uadk_ctx.set_key == false) {
            ctx->uadk_ctx.mode = WCRYPTO_CIPHER_ECB;
            ctx->uadk_ctx.alg = WCRYPTO_CIPHER_AES;
            ret = uadk_cipher_set_key(&(ctx->uadk_ctx), ctx->uadk_key, AES192_KEY_SIZE);
            if (ret != 0) {
                IFM_ERR("ifm_aes192_encrypt set key failed.");
                ctx->use_uadk = false;
                aes192_encrypt((const struct aes192_ctx *)ctx, length, dst, src);
                return;
            }
        }
        uadk_do_cipher((struct uadk_cipher_st *)&(ctx->uadk_ctx), NULL, dst, src, length, true);
    } else {
        aes192_encrypt((const struct aes192_ctx *)ctx, length, dst, src);
    }
#else
    aes192_encrypt((const struct aes192_ctx *)ctx, length, dst, src);
#endif
}

void ifm_aes192_decrypt(struct ifm_aes192_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
#ifdef __aarch64__
    int ret = 0;

    // UADK不支持处理长度为0的字符串
    if (ctx->use_uadk == true && length > 0 && length < AES_MAX_BLOCK_SZ) {
        // 实际的ifm_XXX_set_encrypt_key中未调用uadk_cipher_set_key，在此处设置mode之后再调用uadk_cipher_set_key
        if (ctx->uadk_ctx.ctx == NULL
            || ctx->uadk_ctx.set_key == false) {
            ctx->uadk_ctx.mode = WCRYPTO_CIPHER_ECB;
            ctx->uadk_ctx.alg = WCRYPTO_CIPHER_AES;
            ret = uadk_cipher_set_key(&(ctx->uadk_ctx), ctx->uadk_key, AES192_KEY_SIZE);
            if (ret != 0) {
                IFM_ERR("ifm_aes192_decrypt set key failed.");
                ctx->use_uadk = false;
                aes192_decrypt((const struct aes192_ctx *)ctx, length, dst, src);
                return;
            }
        }
        uadk_do_cipher((struct uadk_cipher_st *)&(ctx->uadk_ctx), NULL, dst, src, length, false);
    } else {
        aes192_decrypt((const struct aes192_ctx *)ctx, length, dst, src);
    }
#else
    aes192_decrypt((const struct aes192_ctx *)ctx, length, dst, src);
#endif
}

void ifm_aes256_set_encrypt_key(struct ifm_aes256_ctx *ctx, const uint8_t *key)
{
    aes256_set_encrypt_key((struct aes256_ctx *)ctx, key);
#ifdef __aarch64__
    // 由于nettle中的CBC模式以及ECB模式用的都是uadk_cipher_set_key，但是uadk中需要根据mode不同
    // 设置不同的ctx值，因此在set_key的时候，不调用uadk_cipher_set_key，只是将uadk_key保存下来
    if (UadkEnabled()) {
        ctx->use_uadk = true;
        memset(ctx->uadk_key, 0, sizeof(ctx->uadk_key));
        memcpy(ctx->uadk_key, key, sizeof(ctx->uadk_key));
        ctx->uadk_ctx.set_key = false;
    } else {
        ctx->use_uadk = false;
    }
#endif
}

void ifm_aes256_set_decrypt_key(struct ifm_aes256_ctx *ctx, const uint8_t *key)
{
    aes256_set_decrypt_key((struct aes256_ctx *)ctx, key);
#ifdef __aarch64__
    // 由于nettle中的CBC模式以及ECB模式用的都是uadk_cipher_set_key，但是uadk中需要根据mode不同
    // 设置不同的ctx值，因此在set_key的时候，不调用uadk_cipher_set_key，只是将uadk_key保存下来
    if (UadkEnabled()) {
        ctx->use_uadk = true;
        memset(ctx->uadk_key, 0, sizeof(ctx->uadk_key));
        memcpy(ctx->uadk_key, key, sizeof(ctx->uadk_key));
        ctx->uadk_ctx.set_key = false;
    } else {
        ctx->use_uadk = false;
    }
#endif
}

void ifm_aes256_invert_key(struct ifm_aes256_ctx *dst, const struct ifm_aes256_ctx *src)
{
    aes256_invert_key((struct aes256_ctx *)dst, (const struct aes256_ctx *)src);
#ifdef __aarch64__
    if (UadkEnabled() && uadk_cipher_set_key(&(dst->uadk_ctx), src->uadk_key, AES256_KEY_SIZE) == 0) {
        dst->use_uadk = true;
        memcpy(dst->uadk_key, src->uadk_key, sizeof(dst->uadk_key));
        dst->uadk_ctx.set_key = false;
    } else {
        dst->use_uadk = false;
    }
#endif
}

void ifm_aes256_encrypt(struct ifm_aes256_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
#ifdef __aarch64__
    int ret = 0;

    // UADK不支持处理长度为0的字符串
    if (ctx->use_uadk == true && length > 0 && length < AES_MAX_BLOCK_SZ) {
        // 实际的ifm_XXX_set_encrypt_key中未调用uadk_cipher_set_key，在此处设置mode之后再调用uadk_cipher_set_key
        if (ctx->uadk_ctx.ctx == NULL
            || ctx->uadk_ctx.set_key == false) {
            ctx->uadk_ctx.mode = WCRYPTO_CIPHER_ECB;
            ctx->uadk_ctx.alg = WCRYPTO_CIPHER_AES;
            ret = uadk_cipher_set_key(&(ctx->uadk_ctx), ctx->uadk_key, AES256_KEY_SIZE);
            if (ret != 0) {
                IFM_ERR("ifm_aes256_encrypt set key failed.");
                ctx->use_uadk = false;
                aes256_encrypt((const struct aes256_ctx *)ctx, length, dst, src);
                return;
            }
        }
        uadk_do_cipher((struct uadk_cipher_st *)&(ctx->uadk_ctx), NULL, dst, src, length, true);
    } else {
        aes256_encrypt((const struct aes256_ctx *)ctx, length, dst, src);
    }
#else
    aes256_encrypt((const struct aes256_ctx *)ctx, length, dst, src);
#endif
}

void ifm_aes256_decrypt(struct ifm_aes256_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
#ifdef __aarch64__
    int ret = 0;

    // UADK不支持处理长度为0的字符串
    if (ctx->use_uadk == true && length > 0 && length < AES_MAX_BLOCK_SZ) {
        // 实际的ifm_XXX_set_encrypt_key中未调用uadk_cipher_set_key，在此处设置mode之后再调用uadk_cipher_set_key
        if (ctx->uadk_ctx.ctx == NULL
            || ctx->uadk_ctx.set_key == false) {
            ctx->uadk_ctx.mode = WCRYPTO_CIPHER_ECB;
            ctx->uadk_ctx.alg = WCRYPTO_CIPHER_AES;
            ret = uadk_cipher_set_key(&(ctx->uadk_ctx), ctx->uadk_key, AES256_KEY_SIZE);
            if (ret != 0) {
                IFM_ERR("ifm_aes256_decrypt set key failed.");
                ctx->use_uadk = false;
                aes256_decrypt((const struct aes256_ctx *)ctx, length, dst, src);
                return;
            }
        }
        uadk_do_cipher((struct uadk_cipher_st *)&(ctx->uadk_ctx), NULL, dst, src, length, false);
    } else {
        aes256_decrypt((const struct aes256_ctx *)ctx, length, dst, src);
    }
#else
    aes256_decrypt((const struct aes256_ctx *)ctx, length, dst, src);
#endif
}

void ifm_aes_set_encrypt_key(struct ifm_aes_ctx *ctx, size_t keySize, const uint8_t *key)
{
    switch (keySize) {
        case AES128_KEY_SIZE:
            ifm_aes128_set_encrypt_key(&ctx->u.ctx128, key);
            break;
        case AES192_KEY_SIZE:
            ifm_aes192_set_encrypt_key(&ctx->u.ctx192, key);
            break;
        case AES256_KEY_SIZE:
            ifm_aes256_set_encrypt_key(&ctx->u.ctx256, key);
            break;
        default:
            return;
    }

    ctx->key_size = keySize;
}

void ifm_aes_set_decrypt_key(struct ifm_aes_ctx *ctx, size_t keySize, const uint8_t *key)
{
    switch (keySize) {
        case AES128_KEY_SIZE:
            ifm_aes128_set_decrypt_key(&ctx->u.ctx128, key);
            break;
        case AES192_KEY_SIZE:
            ifm_aes192_set_decrypt_key(&ctx->u.ctx192, key);
            break;
        case AES256_KEY_SIZE:
            ifm_aes256_set_decrypt_key(&ctx->u.ctx256, key);
            break;
        default:
            return;
    }

    ctx->key_size = keySize;
}

void ifm_aes_invert_key(struct ifm_aes_ctx *dst, const struct ifm_aes_ctx *src)
{
    switch (src->key_size) {
        case AES128_KEY_SIZE:
            ifm_aes128_invert_key(&dst->u.ctx128, &src->u.ctx128);
            break;
        case AES192_KEY_SIZE:
            ifm_aes192_invert_key(&dst->u.ctx192, &src->u.ctx192);
            break;
        case AES256_KEY_SIZE:
            ifm_aes256_invert_key(&dst->u.ctx256, &src->u.ctx256);
            break;
        default:
            return;
    }

    dst->key_size = src->key_size;
}

void ifm_aes_encrypt(struct ifm_aes_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
    switch (ctx->key_size) {
        case AES128_KEY_SIZE:
            ifm_aes128_encrypt(&ctx->u.ctx128, length, dst, src);
            break;
        case AES192_KEY_SIZE:
            ifm_aes192_encrypt(&ctx->u.ctx192, length, dst, src);
            break;
        case AES256_KEY_SIZE:
            ifm_aes256_encrypt(&ctx->u.ctx256, length, dst, src);
            break;
        default:
            return;
    }
}

void ifm_aes_decrypt(struct ifm_aes_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
    switch (ctx->key_size) {
        case AES128_KEY_SIZE:
            ifm_aes128_decrypt(&ctx->u.ctx128, length, dst, src);
            break;
        case AES192_KEY_SIZE:
            ifm_aes192_decrypt(&ctx->u.ctx192, length, dst, src);
            break;
        case AES256_KEY_SIZE:
            ifm_aes256_decrypt(&ctx->u.ctx256, length, dst, src);
            break;
        default:
            return;
    }
}

const struct nettle_cipher ifm_nettle_aes128 = {"aes128",
                                                sizeof(struct ifm_aes128_ctx),
                                                AES_BLOCK_SIZE,
                                                AES128_KEY_SIZE,
                                                (nettle_set_key_func *)ifm_aes128_set_encrypt_key,
                                                (nettle_set_key_func *)ifm_aes128_set_decrypt_key,
                                                (nettle_cipher_func *)ifm_aes128_encrypt,
                                                (nettle_cipher_func *)ifm_aes128_decrypt};

const struct nettle_cipher ifm_nettle_aes192 = {"aes192",
                                                sizeof(struct ifm_aes192_ctx),
                                                AES_BLOCK_SIZE,
                                                AES192_KEY_SIZE,
                                                (nettle_set_key_func *)ifm_aes192_set_encrypt_key,
                                                (nettle_set_key_func *)ifm_aes192_set_decrypt_key,
                                                (nettle_cipher_func *)ifm_aes192_encrypt,
                                                (nettle_cipher_func *)ifm_aes192_decrypt};

const struct nettle_cipher ifm_nettle_aes256 = {"aes256",
                                                sizeof(struct ifm_aes256_ctx),
                                                AES_BLOCK_SIZE,
                                                AES256_KEY_SIZE,
                                                (nettle_set_key_func *)ifm_aes256_set_encrypt_key,
                                                (nettle_set_key_func *)ifm_aes256_set_decrypt_key,
                                                (nettle_cipher_func *)ifm_aes256_encrypt,
                                                (nettle_cipher_func *)ifm_aes256_decrypt};
