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
#ifndef IFM_NETTLE_SM3_H_INCLUDED
#define IFM_NETTLE_SM3_H_INCLUDED
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define sm3_init ifm_sm3_init
#define sm3_update ifm_sm3_update
#define sm3_digest ifm_sm3_digest

#define SM3_DIGEST_SIZE 32
#define SM3_BLOCK_SIZE 64

void ifm_sm3_init(struct ifm_sm3_ctx *ctx);

void ifm_sm3_update(struct ifm_sm3_ctx *ctx,
                    size_t length,
                    const uint8_t *data);

void ifm_sm3_digest(struct ifm_sm3_ctx *ctx,
                    size_t length,
                    uint8_t *digest);

#ifdef __cplusplus
}
#endif

#endif /* IFM_NETTLE_SM3_H_INCLUDED */