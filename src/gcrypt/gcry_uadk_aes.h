/******************************************************************************
 * gcry_uadk_aes.h: gcry_uadk_aes
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * YihuiTan <202121632838@smail.edu.cn.com>
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
#ifndef GCRY_UADK_AES
#define GCRY_UADK_AES

#include "uadk_aes_meta.h"

gcry_error_t gcry_uadk_cipher_open(gcry_uadk_aes_hd_t *hd, int algo, int mode, unsigned int flags);
gcry_error_t gcry_uadk_cipher_setkey(gcry_uadk_aes_hd_t hd, const void *key, size_t keylen);
gcry_error_t gcry_uadk_cipher_setiv(gcry_uadk_aes_hd_t hd, const void *iv, size_t ivlen);
gcry_error_t gcry_uadk_cipher_encrypt(gcry_uadk_aes_hd_t hd, void *out, size_t outsize, const void *in, size_t inlen);
gcry_error_t gcry_uadk_cipher_decrypt(gcry_uadk_aes_hd_t hd, void *out, size_t outsize, const void *in, size_t inlen);
void gcry_uadk_cipher_close(gcry_uadk_aes_hd_t hd);
gcry_error_t gcry_uadk_cipher_ctl(gcry_uadk_aes_hd_t hd, int cmd, void *buffer, size_t buflen);
gcry_error_t gcry_uadk_cipher_checktag(gcry_uadk_aes_hd_t hd, const void *intag, size_t taglen);
gcry_error_t gcry_uadk_cipher_gettag(gcry_uadk_aes_hd_t hd, void *outtag, size_t taglen);
#endif