/******************************************************************************
 * cbc.c: uadk cbc
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 *
 * Authors:
 * HuangDuirong <huangduirong@huawei.com>
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
*/

#ifdef __aarch64__
#include <string.h>
#include "uadk_meta.h"
#include "ifm_utils.h"
#endif
#include "nettle/cbc.h"
#include "aes_meta.h"
#include "aes_common.h"

void ifm_nettle_cbc_encrypt(const void *ctx, nettle_cipher_func *f,
                            size_t block_size, uint8_t *iv,
                            size_t length, uint8_t *dst,
                            const uint8_t *src)
{
#ifdef __aarch64__
    // 根据回调函数名称确定ctx的类型
    struct ifm_aes128_ctx *ctx_128 = NULL;
    struct ifm_aes192_ctx *ctx_192 = NULL;
    struct ifm_aes256_ctx *ctx_256 = NULL;
    struct uadk_cipher_st *uadk_ctx = NULL;
    uint8_t *uadk_key = NULL;
    uint16_t key_len = 0;
    bool *p_use_uadk = NULL;
    int ret = 0;

    if (f == (nettle_cipher_func *)ifm_aes128_encrypt) {  // NOLINT
        ctx_128 = (struct ifm_aes128_ctx *)ctx;
        uadk_ctx = &(ctx_128->uadk_ctx);
        uadk_key = ctx_128->uadk_key;
        key_len = AES128_KEY_SIZE;
        p_use_uadk = &(ctx_128->use_uadk);
    } else if (f == (nettle_cipher_func *)ifm_aes192_encrypt) {  // NOLINT
        ctx_192 = (struct ifm_aes192_ctx *)ctx;
        uadk_ctx = &(ctx_192->uadk_ctx);
        uadk_key = ctx_192->uadk_key;
        key_len = AES192_KEY_SIZE;
        p_use_uadk = &(ctx_192->use_uadk);
    } else if (f == (nettle_cipher_func *)ifm_aes256_encrypt) {  // NOLINT
        ctx_256 = (struct ifm_aes256_ctx *)ctx;
        uadk_ctx = &(ctx_256->uadk_ctx);
        uadk_key = ctx_256->uadk_key;
        key_len = AES256_KEY_SIZE;
        p_use_uadk = &(ctx_256->use_uadk);
    } else {
        cbc_encrypt(ctx, f, block_size, iv, length, dst, src);
        return;
    }

    // UADK不支持处理长度为0的字符串
    if (*p_use_uadk == true && length > 0 && length < AES_MAX_BLOCK_SZ) {
        // 实际的ifm_XXX_set_encrypt_key中未调用uadk_aes_set_key，在此处设置mode之后再调用uadk_aes_set_key
        if (uadk_ctx->ctx == NULL) {
            uadk_ctx->mode = WCRYPTO_CIPHER_CBC;
            ret = uadk_aes_set_key(uadk_ctx, uadk_key, key_len);
            if (ret != 0) {
                *p_use_uadk = false;
                cbc_encrypt(ctx, f, block_size, iv, length, dst, src);
                return;
            }
        }
        uadk_aes_do_cipher(uadk_ctx, iv, dst, src, length, true);
        // 根据原有nettle中cbc.c的实现，在加密完之后，会将dst最后内容回填到iv中
        memcpy(iv, dst+length-block_size, block_size);
    } else {
        cbc_encrypt(ctx, f, block_size, iv, length, dst, src);
    }
#else
    cbc_encrypt(ctx, f, block_size, iv, length, dst, src);
#endif
}

void ifm_nettle_cbc_decrypt(const void *ctx, nettle_cipher_func *f,
                            size_t block_size, uint8_t *iv,
                            size_t length, uint8_t *dst,
                            const uint8_t *src)
{
#ifdef __aarch64__
    // 根据回调函数名称确定ctx的类型
    struct ifm_aes128_ctx *ctx_128 = NULL;
    struct ifm_aes192_ctx *ctx_192 = NULL;
    struct ifm_aes256_ctx *ctx_256 = NULL;
    struct uadk_cipher_st *uadk_ctx = NULL;
    uint8_t *uadk_key = NULL;
    uint16_t key_len = 0;
    bool *p_use_uadk = NULL;
    int ret = 0;

    if (f == (nettle_cipher_func *)ifm_aes128_encrypt) {  // NOLINT
        ctx_128 = (struct ifm_aes128_ctx *)ctx;
        uadk_ctx = &(ctx_128->uadk_ctx);
        uadk_key = ctx_128->uadk_key;
        key_len = AES128_KEY_SIZE;
        p_use_uadk = &(ctx_128->use_uadk);
    } else if (f == (nettle_cipher_func *)ifm_aes192_encrypt) {  // NOLINT
        ctx_192 = (struct ifm_aes192_ctx *)ctx;
        uadk_ctx = &(ctx_192->uadk_ctx);
        uadk_key = ctx_192->uadk_key;
        key_len = AES192_KEY_SIZE;
        p_use_uadk = &(ctx_192->use_uadk);
    } else if (f == (nettle_cipher_func *)ifm_aes256_encrypt) {  // NOLINT
        ctx_256 = (struct ifm_aes256_ctx *)ctx;
        uadk_ctx = &(ctx_256->uadk_ctx);
        uadk_key = ctx_256->uadk_key;
        key_len = AES256_KEY_SIZE;
        p_use_uadk = &(ctx_256->use_uadk);
    } else {
        cbc_decrypt(ctx, f, block_size, iv, length, dst, src);
        return;
    }

    // UADK不支持处理长度为0的字符串
    if (*p_use_uadk == true && length > 0 && length < AES_MAX_BLOCK_SZ) {
        // 实际的ifm_XXX_set_encrypt_key中未调用uadk_aes_set_key，在此处设置mode之后再调用uadk_aes_set_key
        if (uadk_ctx->ctx == NULL) {
            uadk_ctx->mode = WCRYPTO_CIPHER_CBC;
            ret = uadk_aes_set_key(uadk_ctx, uadk_key, key_len);
            if (ret != 0) {
                *p_use_uadk = false;
                cbc_decrypt(ctx, f, block_size, iv, length, dst, src);
                return;
            }
        }
        uadk_aes_do_cipher(uadk_ctx, iv, dst, src, length, false);
        // 根据原有nettle中cbc.c的实现，在加密完之后，会将dst最后内容回填到iv中
        memcpy(iv, dst+length-block_size, block_size);
    } else {
        cbc_decrypt(ctx, f, block_size, iv, length, dst, src);
    }
#else
    cbc_decrypt(ctx, f, block_size, iv, length, dst, src);
#endif
}

void ifm_nettle_cbc_aes128_encrypt(const struct ifm_aes128_ctx *ctx, uint8_t *iv,
                                   size_t length, uint8_t *dst, const uint8_t *src)
{
    ifm_nettle_cbc_encrypt(ctx, (nettle_cipher_func *) aes128_encrypt, AES_BLOCK_SIZE, iv, length, dst, src);
}

void ifm_nettle_cbc_aes192_encrypt(const struct ifm_aes192_ctx *ctx, uint8_t *iv,
                                   size_t length, uint8_t *dst, const uint8_t *src)
{
    ifm_nettle_cbc_encrypt(ctx, (nettle_cipher_func *) aes192_encrypt, AES_BLOCK_SIZE, iv, length, dst, src);
}

void ifm_nettle_cbc_aes256_encrypt(const struct ifm_aes256_ctx *ctx, uint8_t *iv,
                                   size_t length, uint8_t *dst, const uint8_t *src)
{
    ifm_nettle_cbc_encrypt(ctx, (nettle_cipher_func *) aes256_encrypt, AES_BLOCK_SIZE, iv, length, dst, src);
}

