/******************************************************************************
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
#ifndef IFM_NETTLE_UTILS_H_INCLUDED
#define IFM_NETTLE_UTILS_H_INCLUDED

#include <stdbool.h>
#include <stdio.h>
#ifdef __aarch64__
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_digest.h"
#include "uadk/v1/wd_aead.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define FAILED (-1)

#ifndef IFM_ERR
#define IFM_ERR(format, args...) \
    fprintf(stderr, format, ##args)
#endif

// 算法类型数量，当前支持哈希以及对称加密，后续需支持非对称加密
#define UADK_ALG_SIZE    3

#ifdef __aarch64__

// 定义一个枚举类型
typedef enum {
    IFM_UADK_ALG_DIGEST = 0,
    IFM_UADK_ALG_CIPHER,
    IFM_UADK_ALG_AEAD
} UadkQueueAlgType;

typedef struct ifm_uadk_alg_mode {
    int alg;
    int mode;
} IFMUadkAlgMode;

typedef struct ifm_uadk_share_ctx {
    struct ifm_uadk_alg_mode alg_mode;
    void *ctx;
    struct ifm_uadk_share_ctx *next;
    bool is_used;
} IFMUadkShareCtx;

typedef struct ifm_uadk_share_opdata {
    void *opdata;
    struct ifm_uadk_share_opdata *next;
    bool is_used;
} IFMUadkShareOpdata;

// 全局的uadk资源数据结构体，防止由于频繁的资源申请释放导致性能消耗
// 每种算法类型总共一个wd_queue以及一个pool
// 由于ctx中包含key值等信息，因此ctx也需要采用动态链表的方式动态增加
// 同时每一个pool下面对应的会有不同的opdata链表，opdata数量根据实际诉求动态增加，最大MAX_BLOCK_NM
typedef struct ifm_uadk_share_resource {
    UadkQueueAlgType alg_type;
    struct wd_queue queue;
    struct wd_pool *pool;
    // 创建一个ifm_uadk_share_ctx链表
    struct ifm_uadk_share_ctx *first_ctx;
    // 创建一个ifm_uadk_share_opdata链表
    struct ifm_uadk_share_opdata *first_opdata;
} IFMUadkShareResource;

IFMUadkShareCtx *get_uadk_ctx(UadkQueueAlgType alg_type, int alg, int mode, bool is_shared);
void free_uadk_ctx(UadkQueueAlgType alg_type, IFMUadkShareCtx *ctx);
IFMUadkShareOpdata *get_uadk_opdata(UadkQueueAlgType alg_type);
void free_uadk_opdata(UadkQueueAlgType alg_type, IFMUadkShareOpdata *opdata);
#endif

// If enable the uadk
bool UadkEnabled(void);

#ifdef __cplusplus
}
#endif

#endif /* IFM_NETTLE_UTILS_H_INCLUDED */