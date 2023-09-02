/******************************************************************************
 * cbc.h: uadk aes
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * HuangDuirong <huangduirong@huawei.com>
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

#ifndef IFM_NETTLE_CBC_H_INCLUDED
#define IFM_NETTLE_CBC_H_INCLUDED

#include <stdbool.h>
#include "aes.h"
#ifdef __aarch64__
#include "uadk/v1/wd.h"
#include "uadk/v1/wd_bmm.h"
#include "uadk/v1/wd_cipher.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define cbc_encrypt ifm_nettle_cbc_encrypt
#define cbc_decrypt ifm_nettle_cbc_decrypt
#define cbc_aes128_encrypt ifm_nettle_cbc_aes128_encrypt
#define cbc_aes192_encrypt ifm_nettle_cbc_aes192_encrypt
#define cbc_aes256_encrypt ifm_nettle_cbc_aes256_encrypt

void ifm_nettle_cbc_encrypt(const void *ctx, nettle_cipher_func *f,
                            size_t block_size, uint8_t *iv,
                            size_t length, uint8_t *dst,
                            const uint8_t *src);

void ifm_nettle_cbc_decrypt(const void *ctx, nettle_cipher_func *f,
                            size_t block_size, uint8_t *iv,
                            size_t length, uint8_t *dst,
                            const uint8_t *src);

#define CBC_CTX(type, size) \
{ type ctx; uint8_t iv[size]; }

/* NOTE: Avoid using NULL, as we don't include anything defining it. */
#define CBC_ENCRYPT(self, f, length, dst, src)        \
    (0 ? ((f)(&(self)->ctx, ~(size_t) 0,            \
       (uint8_t *) 0, (const uint8_t *) 0))    \
    : ifm_nettle_cbc_encrypt((void *) &(self)->ctx,            \
          (nettle_cipher_func *) (f),        \
          sizeof((self)->iv), (self)->iv,    \
          (length), (dst), (src)))

#define CBC_DECRYPT(self, f, length, dst, src)        \
    (0 ? ((f)(&(self)->ctx, ~(size_t) 0,            \
       (uint8_t *) 0, (const uint8_t *) 0))    \
    : ifm_nettle_cbc_decrypt((void *) &(self)->ctx,            \
       (nettle_cipher_func *) (f),        \
       sizeof((self)->iv), (self)->iv,    \
       (length), (dst), (src)))

void ifm_nettle_cbc_aes128_encrypt(const struct ifm_aes128_ctx *ctx, uint8_t *iv,
                                   size_t length, uint8_t *dst, const uint8_t *src);

void ifm_nettle_cbc_aes192_encrypt(const struct ifm_aes192_ctx *ctx, uint8_t *iv,
                                   size_t length, uint8_t *dst, const uint8_t *src);

void ifm_nettle_cbc_aes256_encrypt(const struct ifm_aes256_ctx *ctx, uint8_t *iv,
                                   size_t length, uint8_t *dst, const uint8_t *src);


#ifdef __cplusplus
}
#endif

#endif /* IFM_NETTLE_AES_H_INCLUDED */