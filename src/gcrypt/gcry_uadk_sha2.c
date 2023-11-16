/******************************************************************************
 * gcry_uadk_sha2.c: gcry_uadk_sha2
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * xinghailiao <xinghailiao@smail.xtu.edu.cn>
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
#include "gcry_uadk_sha2.h"
#include "../ifm_utils.h"
#include <gcrypt.h>

#ifdef __aarch64__
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_bmm.h"
#include "uadk/v1/wd_digest.h"
#endif

/**
 *  本代码文件目前存在的问题
 *  1. 跑gcry_basic_ut测试部分输入数据长度为1时，结果会不正确，目前原因未知
 *
 *  2. uadk对于密钥的限制有unlikely(msg->key_bytes & WORD_ALIGNMENT_MASK)，且密钥长度不能大于128，
 *  HMAC模式下setkey这类密钥会得到错误的digest，相关测试用例已注释（gcrypt_basic_ut中check_hmac用例10、11、12、16、17、18）
 *
 *  3. SHA384和SHA512运算进行hash得到的digest结果不正确，目前原因未知，所以入口限制算法为SHA224和SHA256
 *  4. 系统中存在一个问题，当上层调用者申请同时并行进行两个数据进行hash时，可能会导致线程不安全，因为wcrypto_do_digest是线程不安全的。
 *  Author:
 *  xinghailiao <xinghailiao@smail.xtu.edu.cn>
 * 
 *  约束：
 *  1. 支持进行分包场景进行hash，但是每次分包必须64字节对齐，最后一段数据可以不需要64字节对齐。
 */

#ifdef __aarch64__
/**
 * 适配libgcrypt中的gcry_md_enable函数，将algo添加到hd
 * @param hd 已经open的hd
 * @param algo 待添加的算法
 * @return
 */
gcry_error_t uadk_md_enable(gcry_uadk_sha2_hd_t hd, enum gcry_md_algos algo) {
    IFMUadkShareCtx *p_share_ctx = NULL;
    enum wcrypto_digest_alg uadk_alg;
    for (int i = 0; i < hd->ctx_len; i++) {
        if (algo == hd->alg_ctx[i].alg) {
            return 0;
        }
    }
    switch (algo) {
        case GCRY_MD_SHA224:
            uadk_alg = WCRYPTO_SHA224;
            break;
        case GCRY_MD_SHA256:
            uadk_alg = WCRYPTO_SHA256;
            break;
        case GCRY_MD_SHA384:
            uadk_alg = WCRYPTO_SHA384;
            break;
        case GCRY_MD_SHA512:
            uadk_alg = WCRYPTO_SHA512;
            break;
        default:
            IFM_ERR("uadk_md_enable algo is invalid\n");
            return -1;
    }

    memset(&(hd->alg_ctx[hd->ctx_len].uadk_ctx), 0, sizeof(struct uadk_digest_st));
    p_share_ctx = get_uadk_ctx(IFM_UADK_ALG_DIGEST, uadk_alg, hd->mode, true);
    if (p_share_ctx == NULL) {
        IFM_ERR("uadk_ctx_init get_uadk_ctx failed\n");
        return -1;
    }
    hd->alg_ctx[hd->ctx_len].uadk_ctx.ctx = p_share_ctx->ctx;
    hd->alg_ctx[hd->ctx_len].alg = algo;
    hd->ctx_len += 1;

    return 0;
}

/**
 * 适配libgcrypt中的gcry_md_open函数，使用algo开启hd
 * @param hd 待开启的结构体
 * @param algo 待开启的算法，可以为0，后续可以使用enable增加
 * @param flags 设置计算hash的模式，HMAC模式或普通模式
 * @return
 */
gcry_error_t uadk_md_open(gcry_uadk_sha2_hd_t *hd, int algo, unsigned int flags) {
    (*hd)->key = NULL;
    (*hd)->keylen = 0;
    (*hd)->ctx_len = 0;
    (*hd)->use_gcry = false;
    if (flags == GCRY_MD_FLAG_HMAC) {
        (*hd)->mode = WCRYPTO_DIGEST_HMAC;
    } else {
        (*hd)->mode = WCRYPTO_DIGEST_NORMAL;
    }
    return uadk_md_enable(*hd, algo);
}

/**
 * 适配libgcrypt中的gcry_md_close函数，释放hd中的资源
 * @param hd 待释放资源的hd
 */
void uadk_md_close(gcry_uadk_sha2_hd_t hd) {
    for (int i = 0; i < hd->ctx_len; i++) {
        free_uadk_opdata(IFM_UADK_ALG_DIGEST, hd->alg_ctx[i].uadk_ctx.p_share_opdata);
        hd->alg_ctx[i].uadk_ctx.p_share_opdata = NULL;
        // 由于digest中的ctx是全局共享，因此无需释放ctx，get_ctx的时候，使用的share参数是true
    }
    hd->ctx_len = 0;
    if (hd->key) {
        free(hd->key);
    }
}

int get_size_by_alg(enum gcry_md_algos alg) {
    __u32 out_bytes_size = 0;
    switch (alg) {
        case GCRY_MD_SHA224:
            out_bytes_size = SHA224_DIGEST_SIZE;
            break;
        case GCRY_MD_SHA256:
            out_bytes_size = SHA256_DIGEST_SIZE;
            break;
        case GCRY_MD_SHA384:
            out_bytes_size = SHA384_DIGEST_SIZE;
            break;
        case GCRY_MD_SHA512:
            out_bytes_size = SHA512_DIGEST_SIZE;
            break;
        default:
            out_bytes_size = 0;
            IFM_ERR("[%s] alg %d is not support, please check the alg is correct or not\n", \
                    __func__, alg);
            break;
    }

    return out_bytes_size;
}

/**
 * 适配libgcrpt中的gcry_md_write函数，根据data和hd中已开启的算法进行hash计算，libgcrypt支持分段写入，uadk分段输入需保证64字节对齐
 * @param hd
 * @param data 写入的数据
 * @param length 数据长度
 */
void uadk_md_write(gcry_uadk_sha2_hd_t hd, const void *data, size_t length) {
    if (NULL == data || 0 >= length) {
        return;
    }
    const void *data_pt = NULL;
    unsigned int total_len = 0;
    for (int i = 0; i < hd->ctx_len; i++) {
        if (!hd->alg_ctx[i].uadk_ctx.p_share_opdata) {
            hd->alg_ctx[i].uadk_ctx.p_share_opdata = get_uadk_opdata(IFM_UADK_ALG_DIGEST);
            if (!hd->alg_ctx[i].uadk_ctx.p_share_opdata) {
                IFM_ERR("uadk_md_write: get_uadk_opdata failed\n");
                return;
            }
            hd->alg_ctx[i].uadk_ctx.p_opdata =
                (struct wcrypto_digest_op_data *)(hd->alg_ctx[i].uadk_ctx.p_share_opdata->opdata);
            hd->alg_ctx[i].uadk_ctx.p_opdata->out_bytes = get_size_by_alg(hd->alg_ctx[i].alg);
        }
        do {
            data_pt = data + total_len;
            if (total_len + MAX_BLOCK_SZ <= length) {
                memcpy(hd->alg_ctx[i].uadk_ctx.p_opdata->in, data_pt, MAX_BLOCK_SZ);
                hd->alg_ctx[i].uadk_ctx.p_opdata->in_bytes = MAX_BLOCK_SZ;
                hd->alg_ctx[i].uadk_ctx.p_opdata->has_next = true;
                total_len += MAX_BLOCK_SZ;
            } else {
                // 该字段为true，表示上次最后一个opdata数据还未处理，先处理历史数据，再处理新数据
                if (hd->alg_ctx[i].uadk_ctx.last_data_todo) {
                    hd->alg_ctx[i].uadk_ctx.last_data_todo = false;
                    hd->alg_ctx[i].uadk_ctx.p_opdata->has_next = true;
                    wcrypto_do_digest(hd->alg_ctx[i].uadk_ctx.ctx, hd->alg_ctx[i].uadk_ctx.p_opdata, NULL);
                }
                memcpy(hd->alg_ctx[i].uadk_ctx.p_opdata->in, data_pt, length - total_len);
                hd->alg_ctx[i].uadk_ctx.p_opdata->in_bytes = length - total_len;
                // 非64字节的，一定是最后一段，但是对于64字节对齐的，无法判断是否最后一段，一次遗留在read时候处理。
                if (hd->alg_ctx[i].uadk_ctx.p_opdata->in_bytes % 64) {
                    hd->alg_ctx[i].uadk_ctx.p_opdata->has_next = false;
                } else {
                    hd->alg_ctx[i].uadk_ctx.last_data_todo = true;
                }
                total_len = length;
            }
            if (!hd->alg_ctx[i].uadk_ctx.last_data_todo && \
                hd->alg_ctx[i].uadk_ctx.p_opdata->in_bytes > 0) {
                wcrypto_do_digest(hd->alg_ctx[i].uadk_ctx.ctx, hd->alg_ctx[i].uadk_ctx.p_opdata, NULL);
            }
        } while (total_len < length);
        data_pt = NULL;
        total_len = 0;
    }
}

/**
 * 适配libgcrypt中的gcry_md_read函数，根据algo返回hash结果
 * 由于再最后一段64字节对齐数据传入的时候，无法确定是否是最后一段，因此对于64字节对齐的最后一段输入，在read的时候再处理
 * @param hd
 * @param algo
 * @return
 */
unsigned char *uadk_md_read(gcry_uadk_sha2_hd_t hd, int algo) {
    for (int i = 0; i < hd->ctx_len; i++) {
        if (hd->alg_ctx[i].alg == algo) {
            if (hd->use_uadk && \
                hd->alg_ctx[i].uadk_ctx.last_data_todo && \
                hd->alg_ctx[i].uadk_ctx.p_opdata->in_bytes > 0) {
                // 该字段为true，表示上次最后一个opdata数据还未处理，先处理历史数据，然后再返回结果
                hd->alg_ctx[i].uadk_ctx.last_data_todo = false;
                hd->alg_ctx[i].uadk_ctx.p_opdata->has_next = false;
                wcrypto_do_digest(hd->alg_ctx[i].uadk_ctx.ctx, hd->alg_ctx[i].uadk_ctx.p_opdata, NULL);
            }
            return hd->alg_ctx[i].uadk_ctx.p_opdata->out;
        }
    }
    return gcry_md_read(hd->gcry_hd_t, algo);
}

/**
 * 适配libgcrypt中的gcry_md_setkey函数，HAMC模式下设置key，uadk对于key有限制
 * @param hd
 * @param key
 * @param keylen
 * @return
 */
gcry_error_t uadk_md_setkey(gcry_uadk_sha2_hd_t hd, const void *key, size_t keylen) {
    gcry_error_t ret = 0;
    if (!hd->key) {
        hd->key = malloc(sizeof(u_int8_t)*(MAX_HMAC_KEY_SIZE));
        if (NULL == hd->key) {
            IFM_ERR("uadk_md_setkey: malloc failed\n");
            return 1;
        }
    }
    hd->keylen = keylen;
    memcpy(hd->key, key, hd->keylen);
    for (int i = 0; i < hd->ctx_len; i++) {
        ret = wcrypto_set_digest_key(hd->alg_ctx[i].uadk_ctx.ctx, hd->key, keylen);
        if (ret) {
            IFM_ERR("uadk_md_setkey: wcrypto_set_digest_key failed, ret: %d\n", ret);
            return ret;
        }
    }
    return ret;
}

/**
 * 适配libgcrypt中的gcry_md_copy函数，深拷贝
 * @param dst 目标hd
 * @param src 原hd
 * @return
 */
gcry_error_t uadk_md_copy(gcry_uadk_sha2_hd_t *dst, gcry_uadk_sha2_hd_t src) {
    gcry_error_t ret = 0;
    (*dst) = malloc(sizeof(struct gcry_uadk_sha2_hd));
    if (!(*dst)) {
        return 1;
    }
    (*dst)->mode = src->mode;
    (*dst)->key = src->key;
    (*dst)->keylen = src->keylen;
    (*dst)->ctx_len = 0;
    (*dst)->use_uadk = src->use_uadk;
    (*dst)->use_gcry = src->use_gcry;
    if (src->use_uadk) {
        for (int i = 0; i < src->ctx_len; i++) {
            ret = uadk_md_enable((*dst), src->alg_ctx[i].alg);
            if (0 != ret) {
                return ret;
            }
            if (!(*dst)->alg_ctx[i].uadk_ctx.p_share_opdata) {
                (*dst)->alg_ctx[i].uadk_ctx.p_share_opdata = get_uadk_opdata(IFM_UADK_ALG_DIGEST);
                if (!(*dst)->alg_ctx[i].uadk_ctx.p_share_opdata) {
                    IFM_ERR("uadk_ctx_update: get_uadk_opdata failed\n");
                    return -1;
                }
                (*dst)->alg_ctx[i].uadk_ctx.p_opdata = \
                    (struct wcrypto_digest_op_data *)((*dst)->alg_ctx[i].uadk_ctx.p_share_opdata->opdata);
                (*dst)->alg_ctx[i].uadk_ctx.p_opdata->out_bytes = get_size_by_alg((*dst)->alg_ctx[i].alg);
            }

            if (src->alg_ctx[i].uadk_ctx.p_opdata->in) {
                (*dst)->alg_ctx[i].uadk_ctx.p_opdata->in_bytes = src->alg_ctx[i].uadk_ctx.p_opdata->in_bytes;
                memcpy((*dst)->alg_ctx[i].uadk_ctx.p_opdata->in, \
                       src->alg_ctx[i].uadk_ctx.p_opdata->in, \
                       src->alg_ctx[i].uadk_ctx.p_opdata->in_bytes);
            }
            (*dst)->alg_ctx[i].uadk_ctx.p_opdata->has_next = src->alg_ctx[i].uadk_ctx.p_opdata->has_next;
            if (src->alg_ctx[i].uadk_ctx.p_opdata->out) {
                memcpy((*dst)->alg_ctx[i].uadk_ctx.p_opdata->out, \
                       src->alg_ctx[i].uadk_ctx.p_opdata->out, \
                       src->alg_ctx[i].uadk_ctx.p_opdata->out_bytes);
            }
            (*dst)->alg_ctx[i].uadk_ctx.last_data_todo = src->alg_ctx[i].uadk_ctx.last_data_todo;
            if ((*dst)->mode == WCRYPTO_DIGEST_HMAC && (*dst)->key && (*dst)->keylen) {
                ret =  wcrypto_set_digest_key((*dst)->alg_ctx[i].uadk_ctx.ctx, (*dst)->key, (*dst)->keylen);
                if (ret) {
                    return ret;
                }
            }
        }
    }
    return ret;
}

/**
 * 适配libgcrypt中的gcry_md_reset函数，重置hd中的uadk结构体的opdata数据
 * @param hd
 */
void uadk_md_reset(gcry_uadk_sha2_hd_t hd) {
    for (int i = 0; i < hd->ctx_len; i++) {
        free_uadk_opdata(IFM_UADK_ALG_DIGEST, hd->alg_ctx[i].uadk_ctx.p_share_opdata);
        hd->alg_ctx[i].uadk_ctx.p_share_opdata = NULL;
        hd->alg_ctx[i].uadk_ctx.last_data_todo = false;
    }
}
#endif

// 创建一个算法摘要算法由algo指定，存储到hd，如果创建失败，则ctx为NULL。
gcry_error_t gcry_uadk_md_open(gcry_uadk_sha2_hd_t *hd, int algo, unsigned int flags) {
#ifdef __aarch64__
    gcry_error_t ret = 0;
    gcry_uadk_sha2_hd_t h = malloc(sizeof(struct gcry_uadk_sha2_hd));
    if (NULL == h) {
        return 1;
    }
    memset(h, 0, sizeof(struct gcry_uadk_sha2_hd));
    *hd = h;

    ret = gcry_md_open(&((*hd)->gcry_hd_t), algo, flags);
    if (ret) {
        IFM_ERR("[%s] gcry_md_open failed, ret %d\n", \
                __func__, ret);
        return ret;
    }
    if (UadkEnabled() == false || (algo != GCRY_MD_SHA224 && algo != GCRY_MD_SHA256)) {
        (*hd)->use_uadk = false;
        return ret;
    }
    ret = uadk_md_open(hd, algo, flags);
    if (0 != ret) {
        IFM_ERR("[%s] uadk_md_open failed, set uadk false\n", __func__);
        (*hd)->use_uadk = false;
    } else {
        (*hd)->use_uadk = true;
    }
    return 0;
#else
    gcry_uadk_sha2_hd_t h = malloc(sizeof(struct gcry_uadk_sha2_hd));
    if (NULL == h) {
        return 1;
    }
    memset(h, 0, sizeof(struct gcry_uadk_sha2_hd));
    *hd = h;
    return gcry_md_open(&((*hd)->gcry_hd_t), algo, flags);
#endif
}

gcry_error_t gcry_uadk_md_enable(gcry_uadk_sha2_hd_t hd, int algo) {
#ifdef __aarch64__
    if (hd->use_uadk) {
        if (algo != GCRY_MD_SHA224 && algo != GCRY_MD_SHA256) {
            if (false == hd->use_gcry) {
                hd->use_gcry = true;
            }
            return gcry_md_enable(hd->gcry_hd_t, algo);
        }
        return uadk_md_enable(hd, algo);
    } else {
        return gcry_md_enable(hd->gcry_hd_t, algo);
    }
#else
    return gcry_md_enable(hd->gcry_hd_t, algo);
#endif
}

// 设置key
gcry_error_t gcry_uadk_md_setkey(gcry_uadk_sha2_hd_t hd, const void *key, size_t keylen) {
#ifdef __aarch64__
    if (hd->use_uadk) {
        gcry_error_t ret = 0;
        // uadk对于长度限制为MAX_HMAC_KEY_SIZE，libgcrypt设置key长度可以大于这个值
        if (keylen > MAX_HMAC_KEY_SIZE || NULL == key || 0 >= keylen) {
            ret =  1;
        } else {
            ret = uadk_md_setkey(hd, key, keylen);
        }
        if (ret) {
            hd->use_uadk = false;
            if (false == hd->use_gcry) {
                hd->use_gcry = true;
            }
            for (int j = 0; j < hd->ctx_len; j++) {
                ret = gcry_md_enable(hd->gcry_hd_t, hd->alg_ctx[j].alg);
                if (ret) {
                    return ret;
                }
            }
        }
        if (hd->use_gcry) {
            ret = gcry_md_setkey(hd->gcry_hd_t, key, keylen);
        }
        return ret;
    } else {
        return gcry_md_setkey(hd->gcry_hd_t, key, keylen);
    }
#else
    return gcry_md_setkey(hd->gcry_hd_t, key, keylen);
#endif
}

// 更新消息摘要。
void gcry_uadk_md_write(gcry_uadk_sha2_hd_t hd, const void *buffer, size_t length) {
#ifdef __aarch64__
    if (hd->use_uadk) {
        uadk_md_write(hd, buffer, length);
        if (hd->use_gcry) {
            gcry_md_write(hd->gcry_hd_t, buffer, length);
        }
    } else {
        gcry_md_write(hd->gcry_hd_t, buffer, length);
    }
#else
    gcry_md_write(hd->gcry_hd_t, buffer, length);
#endif
}

unsigned char *gcry_uadk_md_read(gcry_uadk_sha2_hd_t hd, int algo)
{
#ifdef __aarch64__
    if (hd->use_uadk) {
        return uadk_md_read(hd, algo);
    } else {
        return gcry_md_read(hd->gcry_hd_t, algo);
    }
#else
    return gcry_md_read(hd->gcry_hd_t, algo);
#endif
}

void gcry_uadk_md_close(gcry_uadk_sha2_hd_t hd)
{
#ifdef __aarch64__
    if (NULL == hd) {
        return;
    }
    // open的时候，一定会初始化gcry_hd_t，因此需要先释放gcry_hd_t
    gcry_md_close(hd->gcry_hd_t);
    if (UadkEnabled() == true) {
        uadk_md_close(hd);
    }
    free(hd);
#else
    if (NULL == hd) {
        return;
    }
    gcry_md_close(hd->gcry_hd_t);
    free(hd);
#endif
}

gcry_error_t gcry_uadk_md_copy(gcry_uadk_sha2_hd_t *dst, gcry_uadk_sha2_hd_t src) {
#ifdef __aarch64__
    if (src->use_uadk) {
        gcry_error_t ret = uadk_md_copy(dst, src);
        if (ret) {
            return ret;
        }
        if (src->use_gcry) {
            ret = gcry_md_copy((gcry_md_hd_t *)dst, (gcry_md_hd_t)src);
        }
        return ret;
    } else {
        gcry_error_t ret = gcry_md_copy((gcry_md_hd_t *)dst, (gcry_md_hd_t)src);
        (*dst)->use_uadk = false;
        (*dst)->ctx_len = 0;
        return ret;
    }
#else
    return gcry_md_copy((gcry_md_hd_t *)dst, (gcry_md_hd_t)src);
#endif
}

void gcry_uadk_md_reset(gcry_uadk_sha2_hd_t hd) {
#ifdef __aarch64__
    if (hd->use_uadk) {
        uadk_md_reset(hd);
        if (hd->use_gcry) {
            gcry_md_reset(hd->gcry_hd_t);
        }
    } else {
        gcry_md_reset(hd->gcry_hd_t);
    }
#else
    gcry_md_reset(hd->gcry_hd_t);
#endif
}
