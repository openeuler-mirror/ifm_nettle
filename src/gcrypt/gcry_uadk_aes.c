/******************************************************************************
 * gcry_uadk_aes.c: gcry_uadk_aes
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * YihuiTan <202121632838@smail.edu.cn.com>
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
 * 1. 不支持数据分段处理，因此最大的数据只支持16M，使用 MAX_CIPHER_LENGTH 进行限制。
 * 2. 只支持GCRY_CIPHER_MODE_ECB，GCRY_CIPHER_MODE_CBC，GCRY_CIPHER_MODE_XTS，GCRY_CIPHER_MODE_OFB四种模式
 * 3. uadk没有flag这种参数，因此只能支持CBC模式下flag=0的情况
*/

#include <gcrypt.h>
#include "../ifm_utils.h"
#include "gcry_uadk_aes.h"

#ifdef __aarch64__
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_bmm.h"
#include "uadk/v1/wd_cipher.h"
#endif

#ifdef __aarch64__

/**
 * @ingroup uadk_aes_open
 * @par 释放uadk_ctx和hd申请的资源信息
 */
void uadk_aes_close(gcry_uadk_aes_hd_t hd)
{
    free_uadk_opdata(IFM_UADK_ALG_CIPHER, hd->uadk_ctx.p_share_opdata);
    free_uadk_ctx(IFM_UADK_ALG_CIPHER, hd->uadk_ctx.p_share_ctx);
    if (hd->iv) {
        free(hd->iv);
        hd->iv = NULL;
    }
    if (hd->key) {
        free(hd->key);
        hd->key = NULL;
    }
}

/**
 * @ingroup uadk_aes_open
 * @par 申请的uadk资源信息，并且进行初始化工作
 */
gcry_error_t uadk_aes_open(gcry_uadk_aes_hd_t *h, int algo, int mode, unsigned int flags)
{
    gcry_uadk_aes_hd_t hd = *h;
    uint8_t uadk_aes_mode = 0;
    uint8_t uadk_cipher_alg = 0;
    IFMUadkShareCtx *p_share_ctx = NULL;
    if (NULL == hd) {
        IFM_ERR("[%s] hd is NULL\n", __func__);
        return -1;
    }
    switch (mode) {
        case GCRY_CIPHER_MODE_ECB:
            uadk_aes_mode = WCRYPTO_CIPHER_ECB;
            break;
        case GCRY_CIPHER_MODE_CBC:
            uadk_aes_mode = WCRYPTO_CIPHER_CBC;
            break;
        case GCRY_CIPHER_MODE_XTS:
            uadk_aes_mode = WCRYPTO_CIPHER_XTS;
            break;
        case GCRY_CIPHER_MODE_OFB:
            uadk_aes_mode = WCRYPTO_CIPHER_OFB;
            break;
        default:
            IFM_ERR("[%s] mode [%d] is invalid\n", __func__, mode);
            return -1;
    }
    // 将libgcrypt的算法模式进行uadk的转化，但是UADK只有WCRYPTO_CIPHER_AES算法表示，三种算法本质只有key长度的不同
    // 当前只支持如下3中算法
    if (algo == GCRY_CIPHER_AES || algo == GCRY_CIPHER_AES192 || algo == GCRY_CIPHER_AES256) {
        uadk_cipher_alg = WCRYPTO_CIPHER_AES;
    } else {
        IFM_ERR("[%s] algo [%d] is invalid\n", __func__, algo);
        return -1;
    }

    p_share_ctx = get_uadk_ctx(IFM_UADK_ALG_CIPHER, uadk_cipher_alg, uadk_aes_mode, false);
    if (p_share_ctx == NULL) {
        IFM_ERR("[%s] uadk_aes_init get_uadk_ctx failed\n", __func__);
        return -1;
    }
    hd->uadk_ctx.ctx = p_share_ctx->ctx;
    hd->uadk_ctx.p_share_ctx = p_share_ctx;
    hd->uadk_ctx.mode = uadk_aes_mode;
    hd->alg = algo;
    hd->flags = flags;
    hd->mode = mode;

    return 0;
}

/**
 * @ingroup uadk_aes_setkey
 * @par 适配uadk的wcrypto_set_cipher_key函数，返回0代表成功
 */
gcry_error_t uadk_aes_setkey(gcry_uadk_aes_hd_t hd, const void *key, size_t keylen)
{
    gcry_error_t ret = 0;
    if (hd == NULL || key == NULL) {
        return -1;
    }
    if (!hd->key) {
        hd->key = malloc(sizeof(u_int8_t)*(MAX_KEY_SIZE));
        if (hd->key == NULL) {
            IFM_ERR("[%s] malloc key failed\n", __func__);
            // 失败时无需释放资源，由上层调用close释放
            return -1;
        }
    }
    hd->keylen = keylen;
    memcpy(hd->key, key, hd->keylen);
    ret =  wcrypto_set_cipher_key(hd->uadk_ctx.ctx, hd->key, hd->keylen);
    return ret;
}

/**
 * @ingroup uadk_aes_setiv
 * @par 设置uadk中的opdata.iv，返回0代表成功
 */
gcry_error_t uadk_aes_setiv(gcry_uadk_aes_hd_t hd, const void *iv, size_t ivlen)
{
    if (hd == NULL || iv == NULL) {
        return -1;
    }
    if (!hd->iv) {
        hd->iv = malloc(sizeof(u_int8_t)*(CIPHER_IV_SIZE));
        // 失败时释放资源
        if (hd->iv == NULL) {
            IFM_ERR("[%s] malloc iv failed\n", __func__);
            return -1;
        }
    }
    if (!hd->uadk_ctx.p_opdata) {
        hd->uadk_ctx.p_share_opdata = get_uadk_opdata(WCRYPTO_CIPHER_AES);
        if (hd->uadk_ctx.p_share_opdata == NULL) {
            IFM_ERR("[%s] get_uadk_opdata failed\n", __func__);
            return -1;
        }
        hd->uadk_ctx.p_opdata = (struct wcrypto_cipher_op_data *)(hd->uadk_ctx.p_share_opdata->opdata);
    }
    hd->ivlen = ivlen;
    memcpy(hd->iv, iv, hd->ivlen);
    // WCRYPTO_CIPHER_ECB模式不能setiv，iv_bytes必须为0
    if (hd->uadk_ctx.mode == WCRYPTO_CIPHER_ECB) {
        memset(hd->uadk_ctx.p_opdata->iv, 0, CIPHER_IV_SIZE);
        hd->uadk_ctx.p_opdata->iv_bytes = 0;
    } else {
        memset(hd->uadk_ctx.p_opdata->iv, 0, CIPHER_IV_SIZE);
        memcpy(hd->uadk_ctx.p_opdata->iv, hd->iv, CIPHER_IV_SIZE);
        hd->uadk_ctx.p_opdata->iv_bytes = CIPHER_IV_SIZE;
    }

    return 0;
}

/**
 * @ingroup uadk_aes_encrypt
 * @par 适配uadk的wcrypto_do_cipher函数执行加密运算，对应libgcrypt中的encrypt接口，
 */
gcry_error_t uadk_aes_encrypt(gcry_uadk_aes_hd_t hd, void *out, size_t outsize, const void *in, size_t inlen)
{
    gcry_error_t ret = 0;
    /* Caller requested in-place encryption.  */
    if (!in) {
        in = out;
        inlen = outsize;
    }
    if (!hd->uadk_ctx.p_opdata) {
        hd->uadk_ctx.p_share_opdata = get_uadk_opdata(WCRYPTO_CIPHER_AES);
        if (hd->uadk_ctx.p_share_opdata == NULL) {
            IFM_ERR("[%s] get_uadk_opdata failed\n", __func__);
            return -1;
        }
        hd->uadk_ctx.p_opdata = (struct wcrypto_cipher_op_data *)(hd->uadk_ctx.p_share_opdata->opdata);
    }
    memcpy(hd->uadk_ctx.p_opdata->in, in, inlen);
    hd->uadk_ctx.p_opdata->in_bytes = inlen;
    hd->uadk_ctx.p_opdata->out_bytes = outsize;
    hd->uadk_ctx.p_opdata->op_type = WCRYPTO_CIPHER_ENCRYPTION;
    memset(out, 0, outsize);
    ret = wcrypto_do_cipher(hd->uadk_ctx.ctx, hd->uadk_ctx.p_opdata, NULL);
    if (0 != ret) {
        // 加密失败的情况下，将out设置为0x42，参考原有的逻辑
        memset(out, 0x42, outsize);
        return ret;
    }
    memcpy(out, hd->uadk_ctx.p_opdata->out, hd->uadk_ctx.p_opdata->out_bytes);
    return ret;
}

/**
 * @ingroup uadk_aes_decrypt
 * @par 适配uadk的wcrypto_do_cipher函数执行加密运算，对应libgcrypt中的decrypt接口，
 */
gcry_error_t uadk_aes_decrypt(gcry_uadk_aes_hd_t hd, void *out, size_t outsize, const void *in, size_t inlen)
{
    gcry_error_t ret = 0;
    /* Caller requested in-place decryption.  */
    if (!in) {
        in = out;
        inlen = outsize;
    }
    if (!hd->uadk_ctx.p_opdata) {
        hd->uadk_ctx.p_share_opdata = get_uadk_opdata(WCRYPTO_CIPHER_AES);
        if (hd->uadk_ctx.p_share_opdata == NULL) {
            IFM_ERR("[%s] get_uadk_opdata failed\n", __func__);
            return -1;
        }
        hd->uadk_ctx.p_opdata = (struct wcrypto_cipher_op_data *)(hd->uadk_ctx.p_share_opdata->opdata);
    }
    memcpy(hd->uadk_ctx.p_opdata->in, in, inlen);
    hd->uadk_ctx.p_opdata->in_bytes = inlen;
    hd->uadk_ctx.p_opdata->out_bytes = outsize;
    hd->uadk_ctx.p_opdata->op_type = WCRYPTO_CIPHER_DECRYPTION;
    memset(out, 0, outsize);
    ret = wcrypto_do_cipher(hd->uadk_ctx.ctx, hd->uadk_ctx.p_opdata, NULL);
    if (0 != ret) {
        // 加密失败的情况下，将out设置为0
        return ret;
    }
    memset(out, 0, outsize);
    memcpy(out, hd->uadk_ctx.p_opdata->out, hd->uadk_ctx.p_opdata->out_bytes);
    return ret;
}
#endif

gcry_error_t gcry_uadk_cipher_open(gcry_uadk_aes_hd_t *hd, int algo, int mode, unsigned int flags)
{
#ifdef __aarch64__
    gcry_error_t ret = 0;
    // 分配hd内存
    *hd = malloc(sizeof(struct gcry_uadk_aes_hd));
    if (NULL == *hd) {
        IFM_ERR("[%s] malloc hd failed\n", __func__);
        return -1;
    }
    memset((*hd), 0, sizeof(struct gcry_uadk_aes_hd));
    if (UadkEnabled() == false) {
        return gcry_cipher_open(&((*hd)->gcry_hd_t), algo, mode, flags);
    } else {
        // 判断UADK支持的条件
        if (algo != GCRY_CIPHER_AES && algo != GCRY_CIPHER_AES192 && algo != GCRY_CIPHER_AES256) {
            IFM_ERR("[%s] algo [%d] is invalid\n", __func__, algo);
            ret = 1;
        }
        if (mode != GCRY_CIPHER_MODE_ECB && mode != GCRY_CIPHER_MODE_CBC &&
            mode != GCRY_CIPHER_MODE_XTS && mode != GCRY_CIPHER_MODE_OFB) {
            IFM_ERR("[%s] mode [%d] is invalid\n", __func__, mode);
            ret = 1;
        }
        if (flags != 0) {
            IFM_ERR("[%s] flags [%d] is invalid\n", __func__, flags);
            ret = 1;
        }
        if (algo == GCRY_CIPHER_AES192 && mode == GCRY_CIPHER_MODE_XTS) {
            IFM_ERR("[%s] algo [%d] and mode [%d] is unsupported\n", __func__, algo, mode);
            ret = 1;
        }
        if (ret == 0) {
            ret = uadk_aes_open(hd, algo, mode, flags);
        }
        if (ret) {
            (*hd)->use_uadk = false;
        } else {
            (*hd)->use_uadk = true;
        }
        return gcry_cipher_open(&((*hd)->gcry_hd_t), algo, mode, flags);
    }
#else
    return gcry_cipher_open((gcry_cipher_hd_t *)hd, algo, mode, flags);
#endif
}

void gcry_uadk_cipher_close(gcry_uadk_aes_hd_t hd)
{
#ifdef __aarch64__
    if (!hd) {
        return;
    }
    // 需要先释放gcry_hd的内容，再释放uadk的内容
    if (UadkEnabled() == true) {
        uadk_aes_close(hd);
    }
    if (hd->gcry_hd_t) {
        gcry_cipher_close(hd->gcry_hd_t);
    }
    if (hd) {
        free(hd);
    }
#else
    gcry_cipher_close((gcry_cipher_hd_t)hd);
#endif
}

gcry_error_t gcry_uadk_cipher_setkey(gcry_uadk_aes_hd_t hd, const void *key, size_t keylen)
{
#ifdef __aarch64__
    gcry_error_t ret = 0;
    ret = gcry_cipher_setkey(hd->gcry_hd_t, key, keylen);
    if (UadkEnabled() == true && hd->use_uadk) {
        ret = uadk_aes_setkey(hd, key, keylen);
        if (ret != 0) {
            hd->use_uadk = false;
        }
    }
    return ret;
#else
    return gcry_cipher_setkey((gcry_cipher_hd_t)hd, key, keylen);
#endif
}

gcry_error_t gcry_uadk_cipher_setiv(gcry_uadk_aes_hd_t hd, const void *iv, size_t ivlen)
{
#ifdef __aarch64__
    gcry_error_t ret = 0;
    ret = gcry_cipher_setiv(hd->gcry_hd_t, iv, ivlen);
    if (ret) {
        IFM_ERR("[%s] gcry_cipher_setiv failed, ret [%d]\n", __func__, ret);
        return ret;
    }
    if (UadkEnabled() == true && hd->use_uadk) {
        // uadk只能处理CIPHER_IV_SIZE = 16的iv长度
        if (ivlen == CIPHER_IV_SIZE) {
            hd->use_uadk = true;
            ret = uadk_aes_setiv(hd, iv, ivlen);
            if (ret != 0) {
                hd->use_uadk = false;
            }
        } else {
            IFM_ERR("[%s] ivlen [%ld] is invalid\n", __func__, ivlen);
            hd->use_uadk = false;
        }
    }
    return ret;
#else
    return gcry_cipher_setiv((gcry_cipher_hd_t)hd, iv, ivlen);
#endif
}

gcry_error_t gcry_uadk_cipher_encrypt(gcry_uadk_aes_hd_t hd, void *out, size_t outsize, const void *in, size_t inlen)
{
#ifdef __aarch64__
    if (UadkEnabled() == true && hd->use_uadk) {
        // length 应大于 0 且为 AES_BLOCK_SIZE 的整数倍，如 16, 32, 48, 64 等等
        if (inlen > 0 && inlen < MAX_CIPHER_LENGTH && inlen % AES_BLOCK_SIZE == 0 && (hd -> iv)) {
            return uadk_aes_encrypt(hd, out, outsize, in, inlen);
        } else {
            IFM_ERR("[%s] inlen [%ld] is invalid, can not use uadk\n", __func__, inlen);
            hd->use_uadk = false;
            return gcry_cipher_encrypt(hd->gcry_hd_t, out, outsize, in, inlen);
        }
    } else {
        return gcry_cipher_encrypt(hd->gcry_hd_t, out, outsize, in, inlen);
    }
#else
    return gcry_cipher_encrypt((gcry_cipher_hd_t)hd, out, outsize, in, inlen);
#endif
}

gcry_error_t gcry_uadk_cipher_decrypt(gcry_uadk_aes_hd_t hd, void *out, size_t outsize, const void *in, size_t inlen)
{
#ifdef __aarch64__
    if (UadkEnabled() == true && hd->use_uadk) {
        // length 应大于 0 且为 AES_BLOCK_SIZE 的整数倍，如 16, 32, 48, 64 等等
        if (inlen > 0 && inlen < MAX_CIPHER_LENGTH && inlen % AES_BLOCK_SIZE == 0 && (hd -> iv)) {
            return uadk_aes_decrypt(hd, out, outsize, in, inlen);
        } else {
            IFM_ERR("[%s] inlen [%ld] is invalid, can not use uadk\n", __func__, inlen);
            hd->use_uadk = false;
            return gcry_cipher_decrypt(hd->gcry_hd_t, out, outsize, in, inlen);
        }
    } else {
        return gcry_cipher_decrypt(hd->gcry_hd_t, out, outsize, in, inlen);
    }
#else
    return gcry_cipher_decrypt((gcry_cipher_hd_t)hd, out, outsize, in, inlen);
#endif
}

gcry_error_t gcry_uadk_cipher_ctl(gcry_uadk_aes_hd_t hd, int cmd, void *buffer, size_t buflen)
{
#ifdef __aarch64__
    // 不管是否能使用uadk都是调用此函数
    return gcry_cipher_ctl (hd->gcry_hd_t, cmd, buffer, buflen);
#else
    return gcry_cipher_ctl((gcry_cipher_hd_t)hd, cmd, buffer, buflen);
#endif
}

gcry_error_t gcry_uadk_cipher_gettag(gcry_uadk_aes_hd_t hd, void *outtag, size_t taglen)
{
#ifdef __aarch64__
    // 不管是否能使用uadk都是调用此函数
    return gcry_cipher_gettag(hd->gcry_hd_t, outtag, taglen);
#else
    return gcry_cipher_gettag((gcry_cipher_hd_t)hd, outtag, taglen);
#endif
}

gcry_error_t gcry_uadk_cipher_checktag(gcry_uadk_aes_hd_t hd, const void *intag, size_t taglen)
{
#ifdef __aarch64__
    // 不管是否能使用uadk都是调用此函数
    return gcry_cipher_checktag(hd->gcry_hd_t, intag, taglen);
#else
    return gcry_cipher_checktag((gcry_cipher_hd_t)hd, intag, taglen);
#endif
}