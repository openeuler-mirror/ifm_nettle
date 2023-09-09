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
#ifndef IFM_NETTLE_SHA2_H_INCLUDED
#define IFM_NETTLE_SHA2_H_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include "sha2_meta.h"
#ifdef __cplusplus
extern "C" {
#endif
#define sha224_init ifm_sha224_init
#define sha224_digest ifm_sha224_digest
#define sha256_init ifm_sha256_init
#define sha256_update ifm_sha256_update
#define sha256_digest ifm_sha256_digest
#define sha384_init ifm_sha384_init
#define sha384_digest ifm_sha384_digest
#define sha512_init ifm_sha512_init
#define sha512_update ifm_sha512_update
#define sha512_digest ifm_sha512_digest
#define sha512_224_init   ifm_sha512_224_init
#define sha512_224_digest ifm_sha512_224_digest
#define sha512_256_init   ifm_sha512_256_init
#define sha512_256_digest ifm_sha512_256_digest

void ifm_sha256_init(struct ifm_sha256_ctx *ctx);

void ifm_sha256_update(struct ifm_sha256_ctx *ctx, size_t length, const uint8_t *data);

void ifm_sha256_digest(struct ifm_sha256_ctx *ctx, size_t length, uint8_t *digest);

void ifm_sha224_init(struct ifm_sha224_ctx *ctx);

void ifm_sha224_update(struct ifm_sha224_ctx *ctx, size_t length, const uint8_t *data);

void ifm_sha224_digest(struct ifm_sha224_ctx *ctx, size_t length, uint8_t *digest);

void ifm_sha512_init(struct ifm_sha512_ctx *ctx);

void ifm_sha512_update(struct ifm_sha512_ctx *ctx, size_t length, const uint8_t *data);

void ifm_sha512_digest(struct ifm_sha512_ctx *ctx, size_t length, uint8_t *digest);

void ifm_sha384_init(struct ifm_sha384_ctx *ctx);

void ifm_sha384_update(struct ifm_sha384_ctx *ctx, size_t length, const uint8_t *data);

void ifm_sha384_digest(struct ifm_sha384_ctx *ctx, size_t length, uint8_t *digest);

void ifm_sha512_224_init(struct ifm_sha512_224_ctx *ctx);

void ifm_sha512_224_update(struct ifm_sha512_224_ctx *ctx, size_t length, const uint8_t *data);

void ifm_sha512_224_digest(struct ifm_sha512_224_ctx *ctx, size_t length, uint8_t *digest);

void ifm_sha512_256_init(struct ifm_sha512_256_ctx *ctx);

void ifm_sha512_256_update(struct ifm_sha512_256_ctx *ctx, size_t length, const uint8_t *data);

void ifm_sha512_256_digest(struct ifm_sha512_256_ctx *ctx, size_t length, uint8_t *digest);

#ifdef __cplusplus
}
#endif

#endif /* IFM_NETTLE_SHA2_H_INCLUDED */