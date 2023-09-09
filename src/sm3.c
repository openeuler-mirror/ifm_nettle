/******************************************************************************
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
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
#include <stdio.h>
#include "nettle/sm3.h"


/**
 * @ingroup uadk_sm3_init
 * @par 将uadk的sm3算法适配成sm3_init算法，该接口的使用场景以及参数同nettle中的sm3_init接口相同
 */
void uadk_sm3_init(struct sm3_ctx *ctx)
{
    return;
}

/**
 * @ingroup uadk_sm3_update
 * @par 将uadk的sm3算法适配成sm3_update算法，该接口的使用场景以及参数同nettle中的sm3_update接口相同
 */
void uadk_sm3_update(struct sm3_ctx *ctx,
                     size_t length,
                     const uint8_t *data)
{

}

/**
 * @ingroup uadk_sm3_update
 * @par 将uadk的sm3算法适配成sm3_digest算法，该接口的使用场景以及参数同nettle中的sm3_digest接口相同
 */
void uadk_sm3_digest(struct sm3_ctx *ctx,
                     size_t length,
                     uint8_t *digest)
{

}

void ifm_sm3_init(struct sm3_ctx *ctx)
{
    sm3_init(ctx);
}

void ifm_sm3_update(struct sm3_ctx *ctx,
                    size_t length,
                    const uint8_t *data)
{
    sm3_update(ctx, length, data);
}

void ifm_sm3_digest(struct sm3_ctx *ctx,
                    size_t length,
                    uint8_t *digest)
{
    sm3_digest(ctx, length, digest);
}