/******************************************************************************
 * ifm_nettle-gcm.c: gcm
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * li_zengyi <zengyi@isrc.iscas.ac.cn>
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
 * 本代码文件目前存在的问题
 * 1. uadk的输入分段问题。
 *  由于uadk对于aead的算法执行中，没有类似digest中的has_next变量。
 *  因此当输入的数据超出aead的内存块大小时，无法进行处理。分段输入，会得到错误的digest结果
 *
 * 2. uadk的解密过程获取digest问题。
 *  在uadk的aead算法中，解密部分是将附加信息，密文以及auth tag一同输入，然后返回附加消息和
 *  明文。而在nettle的处理中，是输入了附加消息和密文，得到了附加消息和明文，此外通过ghash运
 *  算获取auth tag。也就是说uadk的authtag是输入，而nettle的authtag是输出。因此在uadk的环
 *  境下，如果执行gcm的解密过程，目前暂时无法获得digest
 *
 * 3. uadk的输入长度限制
 *  根据uadk中执行do_aead前的判断，对于此算法一次输入数据的最大限制为16M。
 *
 * 4. uadk无法处理0长字符串
 *  对于某些测试用例，没有输入明文数据，而直接获取并对比authtag的数据。在uadk中暂时不支持，
 *  因为uadk不支持0长字符串，没有输入明文的情况下，在opdata中的in_bytes会设置为0，当调用
 *  do_aead时，会抛出异常。
 * Author:
 * lizengyi <lizengyi.src@foxmail.com>
 */

#include "nettle/gcm.h"
#include "gcm_meta.h"
#include "ifm_utils.h"

#ifdef __aarch64__

int uadk_ctx_setup(struct uadk_aead_st *uadk_ctx)
{
    IFMUadkShareCtx *p_share_ctx = NULL;

    p_share_ctx = get_uadk_ctx(IFM_UADK_ALG_AEAD, uadk_ctx->alg, uadk_ctx->mode, false);
    if (p_share_ctx == NULL) {
        IFM_ERR("uadk_ctx_setup: get_uadk_ctx failed\n");
        return FAILED;
    }
    uadk_ctx->ctx = p_share_ctx->ctx;
    uadk_ctx->p_share_ctx = p_share_ctx;

    if (wcrypto_aead_setauthsize(uadk_ctx->ctx, GCM_DIGEST_SIZE)) {
        IFM_ERR("uadk_ctx_setup: wcrypto_aead_setauthsize failed\n");
        return FAILED;
    }

    return 0;
}

// 非0返回表明init失败
int uadk_gcm_init(struct uadk_aead_st *uadk_ctx)
{
    if (uadk_ctx->p_share_ctx == NULL) {
        if (0 != uadk_ctx_setup(uadk_ctx)) {
            IFM_ERR("uadk_gcm_init: uadk_ctx_setup failed\n");
            return FAILED;
        }
    }

    if (uadk_ctx->p_share_opdata == NULL) {
        uadk_ctx->p_share_opdata = get_uadk_opdata(IFM_UADK_ALG_AEAD);
        if (!uadk_ctx->p_share_opdata) {
            IFM_ERR("uadk_gcm_init: get_uadk_opdata failed\n");
            return -1;
        }
        uadk_ctx->p_opdata = (struct wcrypto_aead_op_data *)(uadk_ctx->p_share_opdata->opdata);
    }

    return 0;
}

void free_uadk(struct uadk_aead_st *uadk_ctx)
{
    free_uadk_opdata(IFM_UADK_ALG_AEAD, uadk_ctx->p_share_opdata);
    free_uadk_ctx(IFM_UADK_ALG_AEAD, uadk_ctx->p_share_ctx);
    uadk_ctx->ctx = NULL;
    uadk_ctx->p_share_ctx = NULL;
    uadk_ctx->p_share_opdata = NULL;
}

int uadk_gcm_set_key(struct uadk_aead_st *uadk_ctx, uint8_t *key, size_t length)
{
    return wcrypto_set_aead_ckey(uadk_ctx->ctx, key, length);
}

void uadk_gcm_set_iv(struct uadk_aead_st *uadk_ctx, size_t length, const uint8_t *iv)
{
    memset(uadk_ctx->p_opdata->iv, 0, GCM_IV_SIZE);
    memcpy(uadk_ctx->p_opdata->iv, iv, length);

    uadk_ctx->p_opdata->iv_bytes = GCM_IV_SIZE;
}

int uadk_gcm_update(struct uadk_aead_st *uadk_ctx, size_t length, const uint8_t *data)
{
    // 当长度超过uadk的aead算法目前支持数据范围，改用nettle执行
    if (uadk_ctx->p_opdata->assoc_size + length > MAX_DATA_SZ) {
        return FAILED;
    }
    // 根据gcm算法，附加数据需要在所有数据之前
    // 支持多次update操作
    memcpy(uadk_ctx->p_opdata->in + uadk_ctx->p_opdata->assoc_size, data, length);
    uadk_ctx->p_opdata->assoc_size += length;
    return 0;
}

int uadk_gcm_encrypt(struct uadk_aead_st *uadk_ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
    if (uadk_ctx->p_opdata->assoc_size + length > MAX_DATA_SZ) {
        return FAILED;
    }

    // 判断此次加密过程是否有附加数据
    // 如有，将明文复制在附加数据之后
    memcpy(uadk_ctx->p_opdata->in + uadk_ctx->p_opdata->assoc_size, src, length);
    uadk_ctx->p_opdata->in_bytes = length;
    uadk_ctx->p_opdata->out_bytes = length + uadk_ctx->p_opdata->assoc_size + wcrypto_aead_getauthsize(uadk_ctx->ctx);
    uadk_ctx->p_opdata->out_buf_bytes = GCM_MAX_BLOCK_SZ;
    uadk_ctx->p_opdata->op_type = WCRYPTO_CIPHER_ENCRYPTION_DIGEST;

    if (0 != wcrypto_do_aead(uadk_ctx->ctx, uadk_ctx->p_opdata, NULL)) {
        IFM_ERR("uadk_gcm_encrypt wcrypto_do_aead failed\n");
    }

    memcpy(dst, uadk_ctx->p_opdata->out + uadk_ctx->p_opdata->assoc_size, length);
    return 0;
}

int uadk_gcm_decrypt(struct uadk_aead_st *uadk_ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
    return uadk_gcm_encrypt(uadk_ctx, length, dst, src);
}

void uadk_gcm_digest(struct uadk_aead_st *uadk_ctx, size_t length, uint8_t *digest)
{
    memcpy(digest,
           uadk_ctx->p_opdata->out + uadk_ctx->p_opdata->out_bytes - wcrypto_aead_getauthsize(uadk_ctx->ctx),
           length);
}

#endif

// gcm
void ifm_gcm_set_key(struct ifm_gcm_key *key, const void *cipher, ifm_cipher_func *f)
{
    gcm_set_key((struct gcm_key*)key, cipher, (nettle_cipher_func *)f);
}

void ifm_gcm_set_iv(struct ifm_gcm_ctx *ctx, const struct ifm_gcm_key *key, size_t length, const uint8_t *iv)
{
    gcm_set_iv((struct gcm_ctx *)ctx, (struct gcm_key *)key, length, iv);
}

void ifm_gcm_update(struct ifm_gcm_ctx *ctx, const struct ifm_gcm_key *key, size_t length, const uint8_t *data)
{
    gcm_update((struct gcm_ctx *)ctx, (struct gcm_key *)key, length, data);
}

void ifm_gcm_encrypt(struct ifm_gcm_ctx *ctx, const struct ifm_gcm_key *key, const void *cipher, ifm_cipher_func *f,
    size_t length, uint8_t *dst, const uint8_t *src)
{
    gcm_encrypt((struct gcm_ctx *)ctx, (struct gcm_key *)key, cipher, (nettle_cipher_func *)f, length, dst, src);
}

void ifm_gcm_decrypt(struct ifm_gcm_ctx *ctx, const struct ifm_gcm_key *key, const void *cipher, ifm_cipher_func *f,
    size_t length, uint8_t *dst, const uint8_t *src)
{
    gcm_decrypt((struct gcm_ctx *)ctx, (struct gcm_key *)key, cipher, (nettle_cipher_func *)f, length, dst, src);
}

void ifm_gcm_digest(struct ifm_gcm_ctx *ctx, const struct ifm_gcm_key *key, const void *cipher, ifm_cipher_func *f,
    size_t length, uint8_t *digest)
{
    gcm_digest((struct gcm_ctx *)ctx, (struct gcm_key *)key, cipher, (nettle_cipher_func *)f, length, digest);
}

// gcm_aes128
void ifm_gcm_aes128_set_key(struct ifm_gcm_aes128_ctx *ctx, const uint8_t *key)
{
    gcm_aes128_set_key((struct gcm_aes128_ctx *)ctx, key);

// 对于使用鲲鹏加速的场景下，将原有ctx的内容进行初始化之外，需要额外调用uadk_gcm_init初始化UADK所需的配置信息
#ifdef __aarch64__
    if (!UadkEnabled()) {
        ctx->use_uadk = false;
        return;
    }
    ctx->uadk_ctx.alg = WCRYPTO_CIPHER_AES;
    ctx->uadk_ctx.mode = WCRYPTO_CIPHER_GCM;
    if ((0 == uadk_gcm_init(&(ctx->uadk_ctx))) &&
        0 == uadk_gcm_set_key(&(ctx->uadk_ctx), (uint8_t *)key, AES128_KEY_SIZE)) {
        ctx->use_uadk = true;
    } else {
        free_uadk(&(ctx->uadk_ctx));
        ctx->use_uadk = false;
    }
#endif
}

void ifm_gcm_aes128_update(struct ifm_gcm_aes128_ctx *ctx, size_t length, const uint8_t *data)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        if (uadk_gcm_update(&(ctx->uadk_ctx), length, data) == FAILED) {
            if (ctx->uadk_ctx.opdata.assoc_size) {
                gcm_aes128_update((struct gcm_aes128_ctx *)ctx,
                    ctx->uadk_ctx.opdata.assoc_size, ctx->uadk_ctx.opdata.in);
            }
            gcm_aes128_update((struct gcm_aes128_ctx *)ctx, length, data);
            free_uadk(&(ctx->uadk_ctx));
            ctx->use_uadk = false;
        }
    } else {
        gcm_aes128_update((struct gcm_aes128_ctx *)ctx, length, data);
    }
#else
    gcm_aes128_update((struct gcm_aes128_ctx *)ctx, length, data);
#endif
}

void ifm_gcm_aes128_set_iv(struct ifm_gcm_aes128_ctx *ctx, size_t length, const uint8_t *iv)
{
#ifdef __aarch64__
    // 当iv的长度不是gcm-aes的标准长度GCM_IV_SIZE，使用nettle执行
    if (ctx->use_uadk && length == GCM_IV_SIZE) {
        uadk_gcm_set_iv(&(ctx->uadk_ctx), length, iv);
    } else {
        ctx->use_uadk = false;
        gcm_aes128_set_iv((struct gcm_aes128_ctx *)ctx, length, iv);
    }
#else
    gcm_aes128_set_iv((struct gcm_aes128_ctx *)ctx, length, iv);
#endif
}

void ifm_gcm_aes128_encrypt(struct ifm_gcm_aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        if (uadk_gcm_encrypt(&(ctx->uadk_ctx), length, dst, src) == FAILED) {
            if (ctx->uadk_ctx.opdata.assoc_size) {
                gcm_aes128_update((struct gcm_aes128_ctx *)ctx,
                    ctx->uadk_ctx.opdata.assoc_size, ctx->uadk_ctx.opdata.in);
            }
            gcm_aes128_encrypt((struct gcm_aes128_ctx *)ctx, length, dst, src);
            free_uadk(&(ctx->uadk_ctx));
            ctx->use_uadk = false;
        }
    } else {
        gcm_aes128_encrypt((struct gcm_aes128_ctx *)ctx, length, dst, src);
    }
#else
    gcm_aes128_encrypt((struct gcm_aes128_ctx *)ctx, length, dst, src);
#endif
}

void ifm_gcm_aes128_decrypt(struct ifm_gcm_aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        if (uadk_gcm_decrypt(&(ctx->uadk_ctx), length, dst, src) == FAILED) {
            if (ctx->uadk_ctx.opdata.assoc_size) {
                gcm_aes128_update((struct gcm_aes128_ctx *)ctx,
                    ctx->uadk_ctx.opdata.assoc_size, ctx->uadk_ctx.opdata.in);
            }
            gcm_aes128_decrypt((struct gcm_aes128_ctx *)ctx, length, dst, src);
            free_uadk(&(ctx->uadk_ctx));
            ctx->use_uadk = false;
        }
    } else {
        gcm_aes128_decrypt((struct gcm_aes128_ctx *)ctx, length, dst, src);
    }
#else
    gcm_aes128_decrypt((struct gcm_aes128_ctx *)ctx, length, dst, src);
#endif
}

void ifm_gcm_aes128_digest(struct ifm_gcm_aes128_ctx *ctx, size_t length, uint8_t *digest)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        uadk_gcm_digest(&(ctx->uadk_ctx), length, digest);
        free_uadk(&(ctx->uadk_ctx));
    } else {
        gcm_aes128_digest((struct gcm_aes128_ctx *)ctx, length, digest);
    }
#else
    gcm_aes128_digest((struct gcm_aes128_ctx *)ctx, length, digest);
#endif
}

// gcm_aes192
void ifm_gcm_aes192_set_key(struct ifm_gcm_aes192_ctx *ctx, const uint8_t *key)
{
    gcm_aes192_set_key((struct gcm_aes192_ctx *)ctx, key);

#ifdef __aarch64__
    if (!UadkEnabled()) {
        ctx->use_uadk = false;
        return;
    }
    ctx->uadk_ctx.alg = WCRYPTO_CIPHER_AES;
    ctx->uadk_ctx.mode = WCRYPTO_CIPHER_GCM;
    if ((0 == uadk_gcm_init(&(ctx->uadk_ctx))) &&
        0 == uadk_gcm_set_key(&(ctx->uadk_ctx), (uint8_t *)key, AES192_KEY_SIZE)) {
        ctx->use_uadk = true;
    } else {
        free_uadk(&(ctx->uadk_ctx));
        ctx->use_uadk = false;
    }
#endif
}

void ifm_gcm_aes192_update(struct ifm_gcm_aes192_ctx *ctx, size_t length, const uint8_t *data)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        if (uadk_gcm_update(&(ctx->uadk_ctx), length, data) == FAILED) {
            if (ctx->uadk_ctx.opdata.assoc_size) {
                gcm_aes192_update((struct gcm_aes192_ctx *)ctx,
                    ctx->uadk_ctx.opdata.assoc_size, ctx->uadk_ctx.opdata.in);
            }
            gcm_aes192_update((struct gcm_aes192_ctx *)ctx, length, data);
            free_uadk(&(ctx->uadk_ctx));
            ctx->use_uadk = false;
        }
    } else {
        gcm_aes192_update((struct gcm_aes192_ctx *)ctx, length, data);
    }
#else
    gcm_aes192_update((struct gcm_aes192_ctx *)ctx, length, data);
#endif
}

void ifm_gcm_aes192_set_iv(struct ifm_gcm_aes192_ctx *ctx, size_t length, const uint8_t *iv)
{
#ifdef __aarch64__
    if (ctx->use_uadk && length == GCM_IV_SIZE) {
        uadk_gcm_set_iv(&(ctx->uadk_ctx), length, iv);
    } else {
        ctx->use_uadk = false;
        gcm_aes192_set_iv((struct gcm_aes192_ctx *)ctx, length, iv);
    }
#else
    gcm_aes192_set_iv((struct gcm_aes192_ctx *)ctx, length, iv);
#endif
}

void ifm_gcm_aes192_encrypt(struct ifm_gcm_aes192_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        if (uadk_gcm_encrypt(&(ctx->uadk_ctx), length, dst, src) == FAILED) {
            if (ctx->uadk_ctx.opdata.assoc_size) {
                gcm_aes192_update((struct gcm_aes192_ctx *)ctx,
                    ctx->uadk_ctx.opdata.assoc_size, ctx->uadk_ctx.opdata.in);
            }
            gcm_aes192_encrypt((struct gcm_aes192_ctx *)ctx, length, dst, src);
            free_uadk(&(ctx->uadk_ctx));
            ctx->use_uadk = false;
        }
    } else {
        gcm_aes192_encrypt((struct gcm_aes192_ctx *)ctx, length, dst, src);
    }
#else
    gcm_aes192_encrypt((struct gcm_aes192_ctx *)ctx, length, dst, src);
#endif
}

void ifm_gcm_aes192_decrypt(struct ifm_gcm_aes192_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        if (uadk_gcm_decrypt(&(ctx->uadk_ctx), length, dst, src) == FAILED) {
            if (ctx->uadk_ctx.opdata.assoc_size) {
                gcm_aes192_update((struct gcm_aes192_ctx *)ctx,
                    ctx->uadk_ctx.opdata.assoc_size, ctx->uadk_ctx.opdata.in);
            }
            gcm_aes192_decrypt((struct gcm_aes192_ctx *)ctx, length, dst, src);
            free_uadk(&(ctx->uadk_ctx));
            ctx->use_uadk = false;
        }
    } else {
        gcm_aes192_decrypt((struct gcm_aes192_ctx *)ctx, length, dst, src);
    }
#else
    gcm_aes192_decrypt((struct gcm_aes192_ctx *)ctx, length, dst, src);
#endif
}

void ifm_gcm_aes192_digest(struct ifm_gcm_aes192_ctx *ctx, size_t length, uint8_t *digest)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        uadk_gcm_digest(&(ctx->uadk_ctx), length, digest);
        free_uadk(&(ctx->uadk_ctx));
    } else {
        gcm_aes192_digest((struct gcm_aes192_ctx *)ctx, length, digest);
    }
#else
    gcm_aes192_digest((struct gcm_aes192_ctx *)ctx, length, digest);
#endif
}

// gcm_aes256
void ifm_gcm_aes256_set_key(struct ifm_gcm_aes256_ctx *ctx, const uint8_t *key)
{
    gcm_aes256_set_key((struct gcm_aes256_ctx *)ctx, key);

#ifdef __aarch64__
    if (!UadkEnabled()) {
        ctx->use_uadk = false;
        return;
    }
    ctx->uadk_ctx.alg = WCRYPTO_CIPHER_AES;
    ctx->uadk_ctx.mode = WCRYPTO_CIPHER_GCM;
    if ((0 == uadk_gcm_init(&(ctx->uadk_ctx))) &&
        0 == uadk_gcm_set_key(&(ctx->uadk_ctx), (uint8_t *)key, AES256_KEY_SIZE)) {
        ctx->use_uadk = true;
    } else {
        free_uadk(&(ctx->uadk_ctx));
        ctx->use_uadk = false;
    }
#endif
}

void ifm_gcm_aes256_update(struct ifm_gcm_aes256_ctx *ctx, size_t length, const uint8_t *data)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        if (uadk_gcm_update(&(ctx->uadk_ctx), length, data) == FAILED) {
            if (ctx->uadk_ctx.opdata.assoc_size) {
                gcm_aes256_update((struct gcm_aes256_ctx *)ctx,
                    ctx->uadk_ctx.opdata.assoc_size, ctx->uadk_ctx.opdata.in);
            }
            gcm_aes256_update((struct gcm_aes256_ctx *)ctx, length, data);
            free_uadk(&(ctx->uadk_ctx));
            ctx->use_uadk = false;
        }
    } else {
        gcm_aes256_update((struct gcm_aes256_ctx *)ctx, length, data);
    }
#else
    gcm_aes256_update((struct gcm_aes256_ctx *)ctx, length, data);
#endif
}

void ifm_gcm_aes256_set_iv(struct ifm_gcm_aes256_ctx *ctx, size_t length, const uint8_t *iv)
{
#ifdef __aarch64__
    if (ctx->use_uadk && length == GCM_IV_SIZE) {
        uadk_gcm_set_iv(&(ctx->uadk_ctx), length, iv);
    } else {
        ctx->use_uadk = false;
        gcm_aes256_set_iv((struct gcm_aes256_ctx *)ctx, length, iv);
    }
#else
    gcm_aes256_set_iv((struct gcm_aes256_ctx *)ctx, length, iv);
#endif
}

void ifm_gcm_aes256_encrypt(struct ifm_gcm_aes256_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        if (uadk_gcm_encrypt(&(ctx->uadk_ctx), length, dst, src) == FAILED) {
            if (ctx->uadk_ctx.opdata.assoc_size) {
                gcm_aes256_update((struct gcm_aes256_ctx *)ctx,
                    ctx->uadk_ctx.opdata.assoc_size, ctx->uadk_ctx.opdata.in);
            }
            gcm_aes256_encrypt((struct gcm_aes256_ctx *)ctx, length, dst, src);
            free_uadk(&(ctx->uadk_ctx));
            ctx->use_uadk = false;
        }
    } else {
        gcm_aes256_encrypt((struct gcm_aes256_ctx *)ctx, length, dst, src);
    }
#else
    gcm_aes256_encrypt((struct gcm_aes256_ctx *)ctx, length, dst, src);
#endif
}

void ifm_gcm_aes256_decrypt(struct ifm_gcm_aes256_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        if (uadk_gcm_decrypt(&(ctx->uadk_ctx), length, dst, src) == FAILED) {
            if (ctx->uadk_ctx.opdata.assoc_size) {
                gcm_aes256_update((struct gcm_aes256_ctx *)ctx,
                    ctx->uadk_ctx.opdata.assoc_size, ctx->uadk_ctx.opdata.in);
            }
            gcm_aes256_decrypt((struct gcm_aes256_ctx *)ctx, length, dst, src);
            free_uadk(&(ctx->uadk_ctx));
            ctx->use_uadk = false;
        }
    } else {
        gcm_aes256_decrypt((struct gcm_aes256_ctx *)ctx, length, dst, src);
    }
#else
    gcm_aes256_decrypt((struct gcm_aes256_ctx *)ctx, length, dst, src);
#endif
}

void ifm_gcm_aes256_digest(struct ifm_gcm_aes256_ctx *ctx, size_t length, uint8_t *digest)
{
#ifdef __aarch64__
    if (ctx->use_uadk) {
        uadk_gcm_digest(&(ctx->uadk_ctx), length, digest);
        free_uadk(&(ctx->uadk_ctx));
    } else {
        gcm_aes256_digest((struct gcm_aes256_ctx *)ctx, length, digest);
    }
#else
    gcm_aes256_digest((struct gcm_aes256_ctx *)ctx, length, digest);
#endif
}
