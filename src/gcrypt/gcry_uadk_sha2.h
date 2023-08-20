/******************************************************************************
 * gcry_uadk_sha2.h: gcry_uadk_sha2
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * xinghailiao <xinghailiao@smail.xtu.edu.cn>
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
#ifndef GCRY_UADK_SHA2
#define GCRY_UADK_SHA2

#include "uadk_sha2_meta.h"

gcry_error_t gcry_uadk_md_open(gcry_uadk_sha2_hd_t *hd, int algo, unsigned int flags);
gcry_error_t gcry_uadk_md_enable(gcry_uadk_sha2_hd_t hd, int algo);
void gcry_uadk_md_write(gcry_uadk_sha2_hd_t hd, const void *buffer, size_t length);
unsigned char *gcry_uadk_md_read(gcry_uadk_sha2_hd_t hd, int algo);
void gcry_uadk_md_close(gcry_uadk_sha2_hd_t hd);
gcry_error_t gcry_uadk_md_setkey(gcry_uadk_sha2_hd_t hd, const void *key, size_t keylen);
gcry_error_t gcry_uadk_md_copy(gcry_uadk_sha2_hd_t *dst, gcry_uadk_sha2_hd_t src);
void gcry_uadk_md_reset(gcry_uadk_sha2_hd_t hd);

#endif