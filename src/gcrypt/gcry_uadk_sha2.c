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
 *  Author:
 *  xinghailiao <xinghailiao@smail.xtu.edu.cn>
 */

#ifdef __aarch64__
/**
 * 适配libgcrypt中的gcry_md_enable函数，将algo添加到hd
 * @param hd 已经open的hd
 * @param algo 待添加的算法
 * @return
 */
gcry_error_t uadk_md_enable(gcry_uadk_sha2_hd_t hd, int algo) {
    gcry_error_t ret = 0;
    static struct wd_queue q;
    static struct wd_blkpool_setup pool_setup;
    static void *pool = NULL;
    static bool init = false;
    if (!init) {
        memset(&q, 0, sizeof(q));
        q.capa.alg = "digest";
        ret = wd_request_queue(&q);
        if (ret) {
            return ret;
        }
        memset(&pool_setup, 0, sizeof(pool_setup));
        pool_setup.block_size = MAX_BLOCK_SZ;
        pool_setup.block_num = MAX_BLOCK_NM;
        pool_setup.align_size = SQE_SIZE;
        pool = wd_blkpool_create(&q, &pool_setup);
        init = true;
    }
    for (int i = 0; i < hd->ctx_len; i++) {
        if (algo == hd->uadk_ctx[i].alg) {
            return 0;
        }
    }

    hd->uadk_ctx[hd->ctx_len].pool = pool;
    hd->uadk_ctx[hd->ctx_len].alg = algo;
    memset(&(hd->uadk_ctx[hd->ctx_len].opdata), 0, sizeof(struct wcrypto_digest_op_data));
    memset(&(hd->uadk_ctx[hd->ctx_len].setup), 0, sizeof(struct wcrypto_digest_ctx_setup));
    switch (algo) {
        case GCRY_MD_SHA224:
            hd->uadk_ctx[hd->ctx_len].setup.alg = WCRYPTO_SHA224;
            hd->uadk_ctx[hd->ctx_len].opdata.out_bytes = SHA224_DIGEST_SIZE;
            break;
        case GCRY_MD_SHA256:
            hd->uadk_ctx[hd->ctx_len].setup.alg = WCRYPTO_SHA256;
            hd->uadk_ctx[hd->ctx_len].opdata.out_bytes = SHA256_DIGEST_SIZE;
            break;
        case GCRY_MD_SHA384:
            hd->uadk_ctx[hd->ctx_len].setup.alg = WCRYPTO_SHA384;
            hd->uadk_ctx[hd->ctx_len].opdata.out_bytes = SHA384_DIGEST_SIZE;
            break;
        case GCRY_MD_SHA512:
            hd->uadk_ctx[hd->ctx_len].setup.alg = WCRYPTO_SHA512;
            hd->uadk_ctx[hd->ctx_len].opdata.out_bytes = SHA512_DIGEST_SIZE;
            break;
    }
    hd->uadk_ctx[hd->ctx_len].setup.mode = hd->mode;
    hd->uadk_ctx[hd->ctx_len].setup.br.alloc = (void *)wd_alloc_blk;
    hd->uadk_ctx[hd->ctx_len].setup.br.free = (void *)wd_free_blk;
    hd->uadk_ctx[hd->ctx_len].setup.br.iova_map = (void *)wd_blk_iova_map;
    hd->uadk_ctx[hd->ctx_len].setup.br.iova_unmap = (void *)wd_blk_iova_unmap;
    hd->uadk_ctx[hd->ctx_len].setup.br.get_bufsize = (void *)wd_blksize;
    hd->uadk_ctx[hd->ctx_len].setup.br.usr = pool;
    hd->uadk_ctx[hd->ctx_len].pq = &q;
    hd->uadk_ctx[hd->ctx_len].ctx = wcrypto_create_digest_ctx(hd->uadk_ctx[hd->ctx_len].pq, &(hd->uadk_ctx[hd->ctx_len].setup));
    if (NULL == hd->uadk_ctx[hd->ctx_len].ctx) {
        ret = 1;
    }
    hd->ctx_len += 1;
    return ret;
}

/**
 * 适配libgcrypt中的gcry_md_open函数，使用algo开启hd
 * @param hd 待开启的结构体
 * @param algo 待开启的算法，可以为0，后续可以使用enable增加
 * @param flags 设置计算hash的模式，HMAC模式或普通模式
 * @return
 */
gcry_error_t uadk_md_open(gcry_uadk_sha2_hd_t *hd, int algo, unsigned int flags) {
    gcry_uadk_sha2_hd_t h = malloc(sizeof(struct gcry_uadk_sha2_hd));
    if (NULL == h) {
        return 1;
    }
    h->gcry_hd_t = NULL;
    h->key = NULL;
    h->keylen = 0;
    h->ctx_len = 0;
    h->use_gcry = false;
    if (flags == GCRY_MD_FLAG_HMAC) {
        h->mode = WCRYPTO_DIGEST_HMAC;
    } else {
        h->mode = WCRYPTO_DIGEST_NORMAL;
    }
    (*hd) = h;
    return uadk_md_enable(*hd, algo);
}

/**
 * 适配libgcrypt中的gcry_md_close函数，释放hd中的资源
 * @param hd 待释放资源的hd
 */
void uadk_md_close(gcry_uadk_sha2_hd_t hd) {
    for (int i = 0; i < hd->ctx_len; i++) {
        if (hd->uadk_ctx[i].opdata.in) {
            wd_free_blk(hd->uadk_ctx[i].pool, hd->uadk_ctx[i].opdata.in);
            hd->uadk_ctx[i].opdata.in = NULL;
        }
        if (hd->uadk_ctx[i].opdata.out) {
            wd_free_blk(hd->uadk_ctx[i].pool, hd->uadk_ctx[i].opdata.out);
            hd->uadk_ctx[i].opdata.out = NULL;
        }
        if (hd->uadk_ctx[i].ctx) {
            wcrypto_del_digest_ctx(hd->uadk_ctx[i].ctx);
            hd->uadk_ctx[i].ctx = NULL;
        }
    }
    hd->ctx_len = 0;
    if(hd->key)
    {
        free(hd->key);
    }
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
        if (!hd->uadk_ctx[i].opdata.in) {
            hd->uadk_ctx[i].opdata.in = wd_alloc_blk(hd->uadk_ctx[i].pool);
            if (NULL == hd->uadk_ctx[i].opdata.in) {
                return;
            }
        }
        if (!hd->uadk_ctx[i].opdata.out) {
            hd->uadk_ctx[i].opdata.out = wd_alloc_blk(hd->uadk_ctx[i].pool);
            if (NULL == hd->uadk_ctx[i].opdata.out) {
                return;
            }
            switch (hd->uadk_ctx[i].alg) {
                case GCRY_MD_SHA224:
                    hd->uadk_ctx[i].opdata.out_bytes = SHA224_DIGEST_SIZE;
                    break;
                case GCRY_MD_SHA256:
                    hd->uadk_ctx[i].opdata.out_bytes = SHA256_DIGEST_SIZE;
                    break;
                case GCRY_MD_SHA384:
                    hd->uadk_ctx[i].opdata.out_bytes = SHA384_DIGEST_SIZE;
                    break;
                case GCRY_MD_SHA512:
                    hd->uadk_ctx[i].opdata.out_bytes = SHA512_DIGEST_SIZE;
                    break;
            }
        }
        do {
            data_pt = data + total_len;
            if (total_len + MAX_BLOCK_SZ <= length) {
                memcpy(hd->uadk_ctx[i].opdata.in, data_pt, MAX_BLOCK_SZ);
                hd->uadk_ctx[i].opdata.in_bytes = MAX_BLOCK_SZ;
                hd->uadk_ctx[i].opdata.has_next = true;
                total_len += MAX_BLOCK_SZ;
            } else {
                memcpy(hd->uadk_ctx[i].opdata.in, data_pt, length - total_len);
                hd->uadk_ctx[i].opdata.in_bytes = length - total_len;
                if (hd->uadk_ctx[i].opdata.in_bytes % 64) {
                    hd->uadk_ctx[i].opdata.has_next = false;
                } else {
                    hd->uadk_ctx[i].opdata.has_next = true;
                }
                total_len = length;
            }
            if (hd->uadk_ctx[i].opdata.in_bytes > 0) {
                wcrypto_do_digest(hd->uadk_ctx[i].ctx, &(hd->uadk_ctx[i].opdata), NULL);
            }
        } while (total_len < length);
        data_pt = NULL;
        total_len = 0;
    }
}

/**
 * 适配libgcrypt中的gcry_md_read函数，根据algo返回hash结果
 * @param hd
 * @param algo
 * @return
 */
unsigned char *uadk_md_read(gcry_uadk_sha2_hd_t hd, int algo) {
    for (int i = 0; i < hd->ctx_len; i++) {
        if (hd->uadk_ctx[i].alg == algo) {
            return hd->uadk_ctx[i].opdata.out;
        }
    }
    return gcry_md_read((gcry_md_hd_t)hd, algo);
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
            return 1;
        }
    }
    hd->keylen = keylen;
    memcpy(hd->key, key, hd->keylen);
    for (int i = 0; i < hd->ctx_len; i++) {
        ret = wcrypto_set_digest_key(hd->uadk_ctx[i].ctx, hd->key, keylen);
        if (ret) {
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
            ret = uadk_md_enable((*dst), src->uadk_ctx[i].alg);
            if (0 != ret) {
                return ret;
            }
            if (src->uadk_ctx[i].opdata.in) {
                if (!(*dst)->uadk_ctx[i].opdata.in) {
                    (*dst)->uadk_ctx[i].opdata.in = wd_alloc_blk((*dst)->uadk_ctx[i].pool);
                    if (!(*dst)->uadk_ctx[i].opdata.in) {
                        return 1;
                    }
                }
                (*dst)->uadk_ctx[i].opdata.in_bytes = src->uadk_ctx[i].opdata.in_bytes;
                memcpy((*dst)->uadk_ctx[i].opdata.in, src->uadk_ctx[i].opdata.in, src->uadk_ctx[i].opdata.in_bytes);
            }
            (*dst)->uadk_ctx[i].opdata.has_next = src->uadk_ctx[i].opdata.has_next;
            if (src->uadk_ctx[i].opdata.out) {
                if (!(*dst)->uadk_ctx[i].opdata.out) {
                    (*dst)->uadk_ctx[i].opdata.out = wd_alloc_blk((*dst)->uadk_ctx[i].pool);
                    if (!(*dst)->uadk_ctx[i].opdata.out) {
                        return 1;
                    }
                }
                memcpy((*dst)->uadk_ctx[i].opdata.out, src->uadk_ctx[i].opdata.out, src->uadk_ctx[i].opdata.out_bytes);
            }
            if ((*dst)->mode == WCRYPTO_DIGEST_HMAC && (*dst)->key && (*dst)->keylen) {
                ret =  wcrypto_set_digest_key((*dst)->uadk_ctx[i].ctx, (*dst)->key, (*dst)->keylen);
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
        if (hd->uadk_ctx[i].opdata.in) {
            wd_free_blk(hd->uadk_ctx[i].pool, hd->uadk_ctx[i].opdata.in);
            hd->uadk_ctx[i].opdata.in = NULL;
        }
        if (hd->uadk_ctx[i].opdata.out) {
            wd_free_blk(hd->uadk_ctx[i].pool, hd->uadk_ctx[i].opdata.out);
            hd->uadk_ctx[i].opdata.out = NULL;
        }
        memset(&(hd->uadk_ctx[i].opdata), 0, sizeof(struct wcrypto_digest_op_data));
    }
}
#endif

// 创建一个算法摘要算法由algo指定，存储到hd，如果创建失败，则ctx为NULL。
gcry_error_t gcry_uadk_md_open(gcry_uadk_sha2_hd_t *hd, int algo, unsigned int flags) {
#ifdef __aarch64__
    gcry_error_t ret = 0;
    if (algo != GCRY_MD_SHA224 && algo != GCRY_MD_SHA256) {
        ret = 1;
    } else {
        ret = uadk_md_open(hd, algo, flags);
    }
    if (UadkEnabled() == false || 0 != ret) {
        ret = gcry_md_open((gcry_md_hd_t *)hd, algo, flags);
        (*hd)->use_uadk = false;
    } else {
        (*hd)->use_uadk = true;
    }
    return ret;
#else
    return gcry_md_open((gcry_md_hd_t *)hd, algo, flags);
#endif
}

gcry_error_t gcry_uadk_md_enable(gcry_uadk_sha2_hd_t hd, int algo) {
#ifdef __aarch64__
    if (hd->use_uadk) {
        gcry_error_t ret = 0;
        if (algo != GCRY_MD_SHA224 && algo != GCRY_MD_SHA256) {
            if (false == hd->use_gcry) {
                unsigned int flags = hd->mode == WCRYPTO_DIGEST_HMAC?GCRY_MD_FLAG_HMAC:0;
                ret = gcry_md_open(&(hd->gcry_hd_t), 0, flags);
                if (ret == 0) {
                    hd->use_gcry = true;
                } else {
                    return ret;
                }
            }
            return gcry_md_enable((gcry_md_hd_t)hd, algo);
        }
        return uadk_md_enable(hd, algo);
    } else {
        return gcry_md_enable((gcry_md_hd_t)hd, algo);
    }
#else
    return gcry_md_enable((gcry_md_hd_t)hd, algo);
#endif
}

// 设置key
gcry_error_t gcry_uadk_md_setkey(gcry_uadk_sha2_hd_t hd, const void *key, size_t keylen) {
#ifdef __aarch64__
    if (hd->use_uadk) {
        gcry_error_t ret = 0;
        if (keylen > MAX_HMAC_KEY_SIZE || NULL == key || 0 >= keylen) { //uadk对于长度限制为MAX_HMAC_KEY_SIZE，libgcrypt设置key长度可以大于这个值
            ret =  1;
        } else {
            ret = uadk_md_setkey(hd, key, keylen);
        }
        if (ret) {
            hd->use_uadk = false;
            if (false == hd->use_gcry) {
                unsigned int flags = hd->mode == WCRYPTO_DIGEST_HMAC? GCRY_MD_FLAG_HMAC:0;
                ret = gcry_md_open(&(hd->gcry_hd_t), 0, flags);
                if (ret) {
                    return ret;
                }
                hd->use_gcry = true;
            }
            for (int j = 0; j < hd->ctx_len; j++) {
                ret = gcry_md_enable((gcry_md_hd_t)hd, hd->uadk_ctx[j].alg);
                if (ret) {
                    return ret;
                }
            }
        }
        if (hd->use_gcry) {
            ret = gcry_md_setkey((gcry_md_hd_t)hd, key, keylen);
        }
        return ret;
    } else {
        return gcry_md_setkey((gcry_md_hd_t)hd, key, keylen);
    }
#else
    return gcry_md_setkey((gcry_md_hd_t)hd, key, keylen);
#endif
}

// 更新消息摘要。
void gcry_uadk_md_write(gcry_uadk_sha2_hd_t hd, const void *buffer, size_t length) {
#ifdef __aarch64__
    if (hd->use_uadk) {
        uadk_md_write(hd, buffer, length);
        if (hd->use_gcry) {
            gcry_md_write((gcry_md_hd_t)hd, buffer, length);
        }
    } else {
        gcry_md_write((gcry_md_hd_t)hd, buffer, length);
    }
#else
    gcry_md_write((gcry_md_hd_t)hd, buffer, length);
#endif
}

unsigned char *gcry_uadk_md_read(gcry_uadk_sha2_hd_t hd, int algo)
{
#ifdef __aarch64__
    if (hd->use_uadk) {
        return uadk_md_read(hd, algo);
    } else {
        return gcry_md_read((gcry_md_hd_t)hd, algo);
    }
#else
    return gcry_md_read((gcry_md_hd_t)hd, algo);
#endif
}

void gcry_uadk_md_close(gcry_uadk_sha2_hd_t hd)
{
#ifdef __aarch64__
    if (hd->use_uadk) {
        if (hd->use_gcry) {
            gcry_md_close((gcry_md_hd_t)hd);
        }
        uadk_md_close(hd);
    } else {
        gcry_md_close((gcry_md_hd_t)hd);
    }
#else
    gcry_md_close((gcry_md_hd_t)hd);
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
            gcry_md_reset((gcry_md_hd_t)hd);
        }
    } else {
        gcry_md_reset((gcry_md_hd_t)hd);
    }
#else
    gcry_md_reset((gcry_md_hd_t)hd);
#endif
}
