/******************************************************************************
 * ifm_utils.c: utils common func in IFM
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
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
#include <stdbool.h>
#include <stdio.h>
#ifdef __aarch64__
#include <stdlib.h>
#include <string.h>
#include "uadk_meta.h"
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_bmm.h"
#include "uadk/v1/wd_digest.h"
#include "uadk/v1/wd_aead.h"
#endif
#include "ifm_utils.h"

#ifdef __aarch64__
static IFMUadkShareResource g_resource[UADK_ALG_SIZE];        // 全局公共资源
static bool is_init[UADK_ALG_SIZE] = {false, false, false};
// 哈希的ctx中不包含key等信息，因此ctx可以共用
IFMUadkAlgMode digest_alg_mode[] = {
    { .alg = WCRYPTO_MD5, .mode = WCRYPTO_DIGEST_NORMAL},
    { .alg = WCRYPTO_SHA256, .mode = WCRYPTO_DIGEST_NORMAL},
    { .alg = WCRYPTO_SHA224, .mode = WCRYPTO_DIGEST_NORMAL},
    { .alg = WCRYPTO_SHA384, .mode = WCRYPTO_DIGEST_NORMAL},
    { .alg = WCRYPTO_SHA512, .mode = WCRYPTO_DIGEST_NORMAL},
    { .alg = WCRYPTO_SHA512_224, .mode = WCRYPTO_DIGEST_NORMAL},
    { .alg = WCRYPTO_SHA512_256, .mode = WCRYPTO_DIGEST_NORMAL}
};
#endif

/**
 * @ingroup UadkEnabled
 * @par 返回当前是否开启UADK的配置，可以通过环境变量IFM_UADK_ENABLE控制，环境变量值为NO的时候，不启用，返回false。
 * 否则默认返回true。
 */
bool UadkEnabled(void)
{
#ifdef __aarch64__
    static bool inited = false;
    static bool enabled = false;

    if (inited) {
        return enabled;
    }

    char *env_ifm_uadk_enable = getenv("IFM_UADK_ENABLE");
    if (env_ifm_uadk_enable != NULL && strcmp(env_ifm_uadk_enable, "NO") == 0) {
        inited = true;
        enabled = false;
    } else {
        inited = true;
        enabled = true;
    }

    // 如果程序启动时候，uadk_init未成功初始化，则也不使能uadk
    if (is_init[IFM_UADK_ALG_DIGEST] == false || g_resource[IFM_UADK_ALG_DIGEST].pool == NULL
        || is_init[IFM_UADK_ALG_CIPHER] == false || g_resource[IFM_UADK_ALG_CIPHER].pool == NULL
        || is_init[IFM_UADK_ALG_AEAD] == false || g_resource[IFM_UADK_ALG_AEAD].pool == NULL) {
        enabled = false;
    }
    IFM_ERR("UADK enbaled is %d\n", enabled);

    return enabled;
#else
    return false;
#endif
}

#ifdef __aarch64__
void set_br(struct wd_mm_br *br, struct wd_pool *pool)
{
    br->alloc = (void *)wd_alloc_blk;
    br->free = (void *)wd_free_blk;
    br->iova_map = (void *)wd_blk_iova_map;
    br->iova_unmap = (void *)wd_blk_iova_unmap;
    br->get_bufsize = (void *)wd_blksize;
    br->usr = pool;
}

IFMUadkShareCtx *get_uadk_ctx(UadkQueueAlgType alg_type, int alg, int mode, bool is_shared)
{
    struct wcrypto_digest_ctx_setup digest_setup;
    struct wcrypto_cipher_ctx_setup  cipher_setup;
    struct wcrypto_aead_ctx_setup  aead_setup;
    void *ctx = NULL;
    IFMUadkShareCtx *new_share_ctx = NULL;
    IFMUadkShareCtx *cur = NULL;
    IFMUadkShareResource *resource = &g_resource[alg_type];

    cur = g_resource[alg_type].first_ctx;
    while (cur) {
        if (cur->alg_mode.alg == alg && cur->alg_mode.mode == mode) {
            if (cur->is_used == false) {
                return cur;
            }
            if (is_shared == true) {
                return cur;
            }
        }
        cur = cur->next;
    }

    new_share_ctx = malloc(sizeof(IFMUadkShareCtx));
    if (NULL == new_share_ctx) {
        IFM_ERR("malloc IFMUadkShareCtxs failed\n");
        return NULL;
    }
    memset(new_share_ctx, 0, sizeof(IFMUadkShareCtx));
    if (resource->alg_type == IFM_UADK_ALG_DIGEST) {
        memset(&digest_setup, 0, sizeof(struct wcrypto_digest_ctx_setup));
        digest_setup.alg = alg;
        digest_setup.mode = mode;
        set_br(&digest_setup.br, resource->pool);

        ctx = wcrypto_create_digest_ctx(&resource->queue, &digest_setup);
        if (ctx == NULL) {
            free(new_share_ctx);
            return NULL;
        }
    } else if (resource->alg_type == IFM_UADK_ALG_CIPHER) {
        memset(&cipher_setup, 0, sizeof(struct wcrypto_cipher_ctx_setup));
        cipher_setup.alg = alg;
        cipher_setup.mode = mode;
        set_br(&cipher_setup.br, resource->pool);

        ctx = wcrypto_create_cipher_ctx(&resource->queue, &cipher_setup);
        if (ctx == NULL) {
            free(new_share_ctx);
            return NULL;
        }
    } else if (resource->alg_type == IFM_UADK_ALG_AEAD) {
        memset(&aead_setup, 0, sizeof(struct wcrypto_aead_ctx_setup));
        aead_setup.calg = alg;
        aead_setup.cmode = mode;
        set_br(&aead_setup.br, resource->pool);

        ctx = wcrypto_create_aead_ctx(&resource->queue, &aead_setup);
        if (ctx == NULL) {
            free(new_share_ctx);
            return NULL;
        }
    }
    new_share_ctx->ctx = ctx;
    new_share_ctx->alg_mode.alg = alg;
    new_share_ctx->alg_mode.mode = mode;
    new_share_ctx->is_used = false;
    if (NULL == resource->first_ctx) {
        resource->first_ctx = new_share_ctx;
    } else {
        cur = resource->first_ctx;
        while (cur->next != NULL) {
            cur = cur->next;
        }
        cur->next = new_share_ctx;
    }

    return new_share_ctx;
}

// 释放一个ctx，只是将标记为设置为未使用
void free_uadk_ctx(UadkQueueAlgType alg_type, IFMUadkShareCtx *ctx)
{
    IFMUadkShareCtx *cur_ctx = NULL;

    if (!ctx) {
        return;
    }
    cur_ctx = g_resource[alg_type].first_ctx;
    while (cur_ctx) {
        if (cur_ctx == ctx) {
            cur_ctx->is_used = false;
            break;
        }
        cur_ctx = cur_ctx->next;
    }
}

int uadk_resource_init(UadkQueueAlgType alg_type, char* alg_name, IFMUadkAlgMode* alg_mode, int alg_mod_num)
{
    int ret = 0;
    void *ctx = NULL;
    static struct wd_blkpool_setup pool_setup;

    memset(&g_resource[alg_type], 0, sizeof(IFMUadkShareResource));
    g_resource[alg_type].queue.capa.alg = alg_name;
    ret = wd_request_queue(&g_resource[alg_type].queue);
    if (ret) {
        return ret;
    }

    memset(&pool_setup, 0, sizeof(pool_setup));
    switch (alg_type) {
        case IFM_UADK_ALG_DIGEST:
            pool_setup.block_size = MAX_BLOCK_SZ;
            break;
        case IFM_UADK_ALG_CIPHER:
            pool_setup.block_size = AES_MAX_BLOCK_SZ;
            break;
        case IFM_UADK_ALG_AEAD:
            pool_setup.block_size = GCM_MAX_BLOCK_SZ;
            break;
    }
    pool_setup.block_num = MAX_BLOCK_NM;
    pool_setup.align_size = SQE_SIZE;

    g_resource[alg_type].pool = wd_blkpool_create(&g_resource[alg_type].queue, &pool_setup);
    g_resource[alg_type].alg_type = alg_type;

    // 初始化ctx
    if (NULL != alg_mode) {
        for (int i = 0; i < alg_mod_num; i++) {
            ctx = get_uadk_ctx(alg_type, alg_mode[i].alg, alg_mode[i].mode, true);
            if (!ctx) {
                IFM_ERR("Init the ctx of %s failed, index: %d", alg_name, i);
                return -1;
            }
        }
    }

    return 0;
}

/**
 * @ingroup uadk_init
 * @par uadk的相关初始化方法，在动态库链接链接时的构造函数调用
 */
int uadk_init()
{
    int ret = 0;
    int alg_num = 0;

    if (!is_init[IFM_UADK_ALG_DIGEST]) {
        alg_num = sizeof(digest_alg_mode) / sizeof(IFMUadkAlgMode);
        uadk_resource_init(IFM_UADK_ALG_DIGEST, "digest", digest_alg_mode, alg_num);
        is_init[IFM_UADK_ALG_DIGEST] = true;
    }
    if (!is_init[IFM_UADK_ALG_CIPHER]) {
        uadk_resource_init(IFM_UADK_ALG_CIPHER, "cipher", NULL, 0);
        is_init[IFM_UADK_ALG_CIPHER] = true;
    }
    if (!is_init[IFM_UADK_ALG_AEAD]) {
        uadk_resource_init(IFM_UADK_ALG_AEAD, "aead", NULL, 0);
        is_init[IFM_UADK_ALG_AEAD] = true;
    }

    return ret;
}

void free_share_opdata(IFMUadkShareOpdata *share_opdata, UadkQueueAlgType alg_type)
{
    struct wcrypto_digest_op_data *digest_opdata = NULL;
    struct wcrypto_cipher_op_data *cipher_opdata = NULL;
    struct wcrypto_aead_op_data *aead_opdata = NULL;

    if (share_opdata == NULL) {
        return;
    }
    if (share_opdata->opdata) {
        switch (alg_type) {
            case IFM_UADK_ALG_DIGEST:
                digest_opdata = (struct wcrypto_digest_op_data *)share_opdata->opdata;
                wd_free_blk(g_resource[alg_type].pool, digest_opdata->in);
                wd_free_blk(g_resource[alg_type].pool, digest_opdata->out);
                break;
            case IFM_UADK_ALG_CIPHER:
                cipher_opdata = (struct wcrypto_cipher_op_data *)share_opdata->opdata;
                wd_free_blk(g_resource[alg_type].pool, cipher_opdata->in);
                wd_free_blk(g_resource[alg_type].pool, cipher_opdata->out);
                wd_free_blk(g_resource[alg_type].pool, cipher_opdata->iv);
                break;
            case IFM_UADK_ALG_AEAD:
                aead_opdata = (struct wcrypto_aead_op_data *)share_opdata->opdata;
                wd_free_blk(g_resource[alg_type].pool, aead_opdata->in);
                wd_free_blk(g_resource[alg_type].pool, aead_opdata->out);
                wd_free_blk(g_resource[alg_type].pool, aead_opdata->iv);
                break;
        }
        free(share_opdata->opdata);
    }
    free(share_opdata);
}

/**
 * @ingroup uadk_free
 * @par uadk的相关释放方法，在动态库链接链接时的构造函数调用
 */
void uadk_free()
{
    IFMUadkShareOpdata *cur_opdata = NULL;
    IFMUadkShareOpdata *tmp_opdata = NULL;
    IFMUadkShareCtx *cur_ctx = NULL;
    IFMUadkShareCtx *tmp_ctx = NULL;

    for (int i = 0; i < UADK_ALG_SIZE; i++) {
        cur_opdata = g_resource[i].first_opdata;
        while (cur_opdata) {
            tmp_opdata = cur_opdata->next;
            free_share_opdata(cur_opdata, i);
            cur_opdata = tmp_opdata;
        }

        cur_ctx = g_resource[i].first_ctx;
        while (cur_ctx) {
            tmp_ctx = cur_ctx->next;
            switch (i) {
                case IFM_UADK_ALG_DIGEST:
                    wcrypto_del_digest_ctx(cur_ctx->ctx);
                    break;
                case IFM_UADK_ALG_CIPHER:
                    wcrypto_del_cipher_ctx(cur_ctx->ctx);
                    break;
                case IFM_UADK_ALG_AEAD:
                    wcrypto_del_aead_ctx(cur_ctx->ctx);
                    break;
                default:
                    break;
            }
            free(cur_ctx);
            cur_ctx = tmp_ctx;
        }

        if (g_resource[i].pool) {
            wd_blkpool_destroy(g_resource[i].pool);
        }

        memset(&g_resource[i], 0, sizeof(g_resource[i]));
    }
}

int alloc_blk(UadkQueueAlgType alg_type, IFMUadkShareOpdata *new_opdata)
{
    struct wcrypto_digest_op_data *digest_opdata = NULL;
    struct wcrypto_cipher_op_data *cipher_opdata = NULL;
    struct wcrypto_aead_op_data *aead_opdata = NULL;

    switch (alg_type) {
        case IFM_UADK_ALG_DIGEST:
            digest_opdata = (struct wcrypto_digest_op_data *)new_opdata->opdata;
            digest_opdata->in = wd_alloc_blk(g_resource[alg_type].pool);
            if (!(digest_opdata->in)) {
                free_share_opdata(new_opdata, alg_type);
                IFM_ERR("wcrypto_digest_op_data wd_alloc_blk in failed\n");
                return -1;
            }
            digest_opdata->out = wd_alloc_blk(g_resource[alg_type].pool);
            if (!(digest_opdata->out)) {
                free_share_opdata(new_opdata, alg_type);
                IFM_ERR("wcrypto_digest_op_data wd_alloc_blk out failed\n");
                return -1;
            }
            break;
        case IFM_UADK_ALG_CIPHER:
            cipher_opdata = (struct wcrypto_cipher_op_data *)new_opdata->opdata;
            cipher_opdata->in = wd_alloc_blk(g_resource[alg_type].pool);
            if (!(cipher_opdata->in)) {
                free_share_opdata(new_opdata, alg_type);
                IFM_ERR("wcrypto_cipher_op_data wd_alloc_blk in failed\n");
                return -1;
            }
            cipher_opdata->out = wd_alloc_blk(g_resource[alg_type].pool);
            if (!(cipher_opdata->out)) {
                free_share_opdata(new_opdata, alg_type);
                IFM_ERR("wcrypto_cipher_op_data wd_alloc_blk out failed\n");
                return -1;
            }
            cipher_opdata->iv = wd_alloc_blk(g_resource[alg_type].pool);
            if (!(cipher_opdata->iv)) {
                free_share_opdata(new_opdata, alg_type);
                IFM_ERR("wcrypto_cipher_op_data wd_alloc_blk iv failed\n");
                return -1;
            }
            break;
        case IFM_UADK_ALG_AEAD:
            aead_opdata = (struct wcrypto_aead_op_data *)new_opdata->opdata;
            aead_opdata->in = wd_alloc_blk(g_resource[alg_type].pool);
            if (!(aead_opdata->in)) {
                free_share_opdata(new_opdata, alg_type);
                IFM_ERR("wcrypto_aead_op_data wd_alloc_blk in failed\n");
                return -1;
            }
            aead_opdata->out = wd_alloc_blk(g_resource[alg_type].pool);
            if (!(aead_opdata->out)) {
                free_share_opdata(new_opdata, alg_type);
                IFM_ERR("wcrypto_aead_op_data wd_alloc_blk out failed\n");
                return -1;
            }
            aead_opdata->iv = wd_alloc_blk(g_resource[alg_type].pool);
            if (!(aead_opdata->iv)) {
                free_share_opdata(new_opdata, alg_type);
                IFM_ERR("wcrypto_aead_op_data wd_alloc_blk iv failed\n");
                return -1;
            }
            break;
    }

    return 0;
}

// 获取一个空的opdata或者新增一个opdata，并插入到链表first_opdata中
IFMUadkShareOpdata *get_uadk_opdata(UadkQueueAlgType alg_type)
{
    IFMUadkShareOpdata *opdata = NULL;
    IFMUadkShareOpdata *new_opdata = NULL;

    opdata = g_resource[alg_type].first_opdata;
    if (opdata) {
        if (false == opdata->is_used) {
            opdata->is_used = true;
            return opdata;
        }
        while (opdata->next) {
            opdata = opdata->next;
            if (false == opdata->is_used) {
                opdata->is_used = true;
                return opdata;
            }
        }
    }
    new_opdata = malloc(sizeof(IFMUadkShareOpdata));
    if (!new_opdata) {
        IFM_ERR("malloc IFMUadkShareOpdata failed\n");
        return NULL;
    }
    memset(new_opdata, 0, sizeof(IFMUadkShareOpdata));
    switch (alg_type) {
        case IFM_UADK_ALG_DIGEST:
            new_opdata->opdata = malloc(sizeof(struct wcrypto_digest_op_data));
            memset(new_opdata->opdata, 0, sizeof(struct wcrypto_digest_op_data));
            break;
        case IFM_UADK_ALG_CIPHER:
            new_opdata->opdata = malloc(sizeof(struct wcrypto_cipher_op_data));
            memset(new_opdata->opdata, 0, sizeof(struct wcrypto_cipher_op_data));
            break;
        case IFM_UADK_ALG_AEAD:
            new_opdata->opdata = malloc(sizeof(struct wcrypto_aead_op_data));
            memset(new_opdata->opdata, 0, sizeof(struct wcrypto_aead_op_data));
            break;
        default:
            break;
    }
    if (!new_opdata->opdata) {
        free(new_opdata);
        IFM_ERR("malloc opdata failed\n");
        return NULL;
    }
    if (0 != alloc_blk(alg_type, new_opdata)) {
        free(new_opdata);
        return NULL;
    }
    new_opdata->is_used = true;

    if (!g_resource[alg_type].first_opdata) {
        g_resource[alg_type].first_opdata = new_opdata;
    } else {
        opdata->next = new_opdata;
    }

    return new_opdata;
}

struct wcrypto_digest_op_data *get_digest_opdata(UadkQueueAlgType alg_type)
{
    IFMUadkShareOpdata *cur_opdata = NULL;

    cur_opdata = get_uadk_opdata(alg_type);
    if (!cur_opdata) {
        IFM_ERR("get_digest_opdata: get_uadk_opdata failed\n");
        return NULL;
    }
    return (struct wcrypto_digest_op_data *)cur_opdata->opdata;
}

struct wcrypto_cipher_op_data *get_cipher_opdata(UadkQueueAlgType alg_type)
{
    IFMUadkShareOpdata *cur_opdata = NULL;

    cur_opdata = get_uadk_opdata(alg_type);
    if (!cur_opdata) {
        IFM_ERR("get_cipher_opdata: get_uadk_opdata failed\n");
        return NULL;
    }
    return (struct wcrypto_cipher_op_data *)cur_opdata->opdata;
}

struct wcrypto_aead_op_data *get_aead_opdata(UadkQueueAlgType alg_type)
{
    IFMUadkShareOpdata *cur_opdata = NULL;

    cur_opdata = get_uadk_opdata(alg_type);
    if (!cur_opdata) {
        IFM_ERR("get_aead_opdata: get_uadk_opdata failed\n");
        return NULL;
    }
    return (struct wcrypto_aead_op_data *)cur_opdata->opdata;
}

// 释放一个opdata，只是将标记为设置为未使用
void free_uadk_opdata(UadkQueueAlgType alg_type, IFMUadkShareOpdata *opdata)
{
    struct wcrypto_digest_op_data *digest_opdata = NULL;
    struct wcrypto_cipher_op_data *cipher_opdata = NULL;
    struct wcrypto_aead_op_data *aead_opdata = NULL;
    IFMUadkShareOpdata *cur_opdata = NULL;

    if (!opdata) {
        return;
    }
    cur_opdata = g_resource[alg_type].first_opdata;
    while (cur_opdata) {
        if (cur_opdata == opdata) {
            cur_opdata->is_used = false;
            switch (alg_type) {
                case IFM_UADK_ALG_DIGEST:
                    // 此处需要考虑后续将in和out的内容设置为0
                    digest_opdata = (struct wcrypto_digest_op_data *)cur_opdata->opdata;
                    memset(digest_opdata->in, 0, digest_opdata->in_bytes);
                    digest_opdata->in_bytes = 0;
                    digest_opdata->out_bytes = 0;
                    digest_opdata->priv = 0;
                    digest_opdata->status = 0;
                    digest_opdata->has_next = 0;
                    break;
                case IFM_UADK_ALG_CIPHER:
                    cipher_opdata = (struct wcrypto_cipher_op_data *)cur_opdata->opdata;
                    memset(cipher_opdata->in, 0, cipher_opdata->in_bytes);
                    cipher_opdata->in_bytes = 0;
                    cipher_opdata->out_bytes = 0;
                    cipher_opdata->iv_bytes = 0;
                    cipher_opdata->priv = 0;
                    cipher_opdata->status = 0;
                    break;
                case IFM_UADK_ALG_AEAD:
                    aead_opdata = (struct wcrypto_aead_op_data *)cur_opdata->opdata;
                    memset(aead_opdata->in, 0, aead_opdata->in_bytes);
                    aead_opdata->in_bytes = 0;
                    aead_opdata->out_bytes = 0;
                    aead_opdata->iv_bytes = 0;
                    aead_opdata->out_buf_bytes = 0;
                    aead_opdata->assoc_size = 0;
                    aead_opdata->priv = 0;
                    aead_opdata->status = 0;
                    break;
                default:
                    break;
            }
            break;
        }
        cur_opdata = cur_opdata->next;
    }
}
#endif

static __attribute__((constructor)) void UadkInitConstructor(void)
{
#ifdef __aarch64__
    uadk_init();
#endif
    IFM_ERR("uadk_init_constructor\n");
}

static __attribute__((destructor)) void UadkInitDestructor(void)
{
#ifdef __aarch64__
    uadk_free();
#endif
    IFM_ERR("uadk_init_destructor\n");
}
