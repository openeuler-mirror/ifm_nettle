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
#include "nettle/sha2.h"
#include "sha2_meta.h"

/**
 * @ingroup uadk_sha256_init
 * @par 将uadk的sha256算法适配成sha256_init算法，该接口的使用场景以及参数同nettle中的sha256_init接口相同
 */
void uadk_sha256_init(struct sha256_ctx *ctx)
{
    return;
}

/**
 * @ingroup uadk_sha256_update
 * @par 将uadk的sha256算法适配成sha256_update算法，该接口的使用场景以及参数同nettle中的sha256_update接口相同
 */
void uadk_sha256_update(struct sha256_ctx *ctx,
                        size_t length,
                        const uint8_t *data)
{

}

/**
 * @ingroup uadk_sha256_update
 * @par 将uadk的sha256算法适配成sha256_digest算法，该接口的使用场景以及参数同nettle中的sha256_digest接口相同
 */
void uadk_sha256_digest(struct sha256_ctx *ctx,
                        size_t length,
                        uint8_t *digest)
{

}

void ifm_sha256_init(struct ifm_sha256_ctx *ctx)
{
    sha256_init((struct sha256_ctx*) ctx);
}

void ifm_sha256_update(struct ifm_sha256_ctx *ctx,
                       size_t length,
                       const uint8_t *data)
{
    sha256_update((struct sha256_ctx*)ctx, length, data);
}

void ifm_sha256_digest(struct ifm_sha256_ctx *ctx, size_t length, uint8_t *digest)
{
    sha256_digest((struct sha256_ctx*)ctx, length, digest);
}

void ifm_sha224_init(struct ifm_sha224_ctx *ctx)
{
    sha224_init((struct sha224_ctx*) ctx);
}

void ifm_sha224_digest(struct ifm_sha224_ctx *ctx, size_t length, uint8_t *digest)
{
    sha224_digest((struct sha224_ctx*) ctx, length, digest);
}

void ifm_sha512_init(struct ifm_sha512_ctx *ctx)
{
    sha512_init((struct sha512_ctx*) ctx);
}

void ifm_sha512_update(struct ifm_sha512_ctx *ctx, size_t length, const uint8_t *data)
{
    sha512_update((struct sha512_ctx *)ctx, length,data);
}

void ifm_sha512_digest(struct ifm_sha512_ctx *ctx, size_t length, uint8_t *digest)
{
    sha512_digest((struct sha512_ctx *)ctx, length,digest);
}


void ifm_sha384_init(struct ifm_sha384_ctx *ctx)
{
    sha512_init((struct sha384_ctx *)ctx);
}

void ifm_sha384_digest(struct ifm_sha384_ctx *ctx, size_t length, uint8_t *digest)
{
    sha384_digest((struct sha384_ctx *)ctx, length,digest);
}


void ifm_sha512_224_init(struct ifm_sha512_224_ctx *ctx)
{
    sha512_224_init((struct sha512_224_ctx *)ctx);
}

void ifm_sha512_224_digest(struct ifm_sha512_224_ctx *ctx, size_t length, uint8_t *digest)
{
    sha512_224_digest((struct sha512_224_ctx *)ctx, length,digest);
}

void ifm_sha512_256_init(struct ifm_sha512_256_ctx *ctx)
{
    sha512_256_init((struct sha512_256_ctx *)ctx);
}

void ifm_sha512_256_digest(struct ifm_sha512_256_ctx *ctx, size_t length, uint8_t *digest)
{
    sha512_256_digest((struct sha512_256_ctx *)ctx, length,digest);
}