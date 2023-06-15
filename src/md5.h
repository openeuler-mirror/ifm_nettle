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
#ifndef IFM_NETTLE_MD5_H_INCLUDED
#define IFM_NETTLE_MD5_H_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include "md5_meta.h"
#ifdef __aarch64__
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_bmm.h"
#include "uadk/v1/wd_digest.h"
#endif


#ifdef __cplusplus
extern "C" {
#endif

#define md5_init ifm_md5_init
#define md5_update ifm_md5_update
#define md5_digest ifm_md5_digest

void ifm_md5_init(struct ifm_md5_ctx *ctx);

void ifm_md5_update(struct ifm_md5_ctx *ctx,
                    size_t length,
                    const uint8_t *data);

void ifm_md5_digest(struct ifm_md5_ctx *ctx,
                    size_t length,
                    uint8_t *digest);

#ifdef __cplusplus
}
#endif

#endif /* IFM_NETTLE_MD5_H_INCLUDED */