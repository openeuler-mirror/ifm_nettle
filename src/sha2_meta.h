/******************************************************************************
sha2_meta.h

The sha2 family block cipher.

Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.

Authors:
zhonghao2023 zhonghao@isrc.iscas.ac.cn

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.


This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
Lesser General Public License for more details.


You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
********************************************************************************/
#ifndef IFM_NETTLE_SHA2_META_INCLUDED
#define IFM_NETTLE_SHA2_META_INCLUDED
#include <stddef.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif

/* SHA256 */
#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE 64

#define _SHA256_DIGEST_LENGTH 8

struct ifm_sha256_ctx
{
  uint32_t state[_SHA256_DIGEST_LENGTH];    
  uint64_t count;                           
  unsigned int index;                       
  uint8_t block[SHA256_BLOCK_SIZE];        
};
#define SHA224_DIGEST_SIZE 28
#define SHA224_BLOCK_SIZE SHA256_BLOCK_SIZE
#define ifm_sha224_ctx ifm_sha256_ctx


#define SHA512_DIGEST_SIZE 64
#define SHA512_BLOCK_SIZE 128

#define _SHA512_DIGEST_LENGTH 8

struct ifm_sha512_ctx
{
  uint64_t state[_SHA512_DIGEST_LENGTH];   
  uint64_t count_low, count_high;          
  unsigned int index;                       
  uint8_t block[SHA512_BLOCK_SIZE];      
};

#define SHA384_DIGEST_SIZE 48
#define SHA384_BLOCK_SIZE SHA512_BLOCK_SIZE
#define ifm_sha384_ctx ifm_sha512_ctx


#define SHA512_224_DIGEST_SIZE 28
#define SHA512_224_BLOCK_SIZE SHA512_BLOCK_SIZE
#define ifm_sha512_224_ctx ifm_sha512_ctx

#define SHA512_256_DIGEST_SIZE 32
#define SHA512_256_BLOCK_SIZE SHA512_BLOCK_SIZE
#define ifm_sha512_256_ctx ifm_sha512_ctx


#ifdef __cplusplus
}
#endif

#endif /* IFM_NETTLE_SHA2_META_INCLUDED */