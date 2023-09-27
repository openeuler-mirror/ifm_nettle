/******************************************************************************
 * This is an adaptation file for the crypt interface in libxcrpt
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * zenglingtao <mccarty_zzz2017@163.com>
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
#ifndef IFM_LIBXCRYPT_H
#define IFM_LIBXCRYPT_H

#include <stdint.h>
#include "crypt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define crypt ifm_crypt
#define crypt_r ifm_crypt_r
#define crypt_rn ifm_crypt_rn
#define crypt_ra ifm_crypt_ra
#define crypt_gensalt ifm_crypt_gensalt
#define crypt_gensalt_rn ifm_crypt_gensalt_rn
#define crypt_gensalt_ra ifm_crypt_gensalt_ra
#define crypt_checksalt ifm_crypt_checksalt
#define crypt_preferred_method ifm_crypt_preferred_method

char *ifm_crypt(const char *__phrase, const char *__setting);
char *ifm_crypt_r(const char *__phrase, const char *__setting, struct crypt_data *__restrict __data);
char *ifm_crypt_rn(const char *__phrase, const char *__setting, void *__data, int __size);
char *ifm_crypt_ra(const char *__phrase, const char *__setting, void **__data, int *__size);
char *ifm_crypt_gensalt(const char *__prefix, unsigned long __count, const char *__rbytes, int __nrbytes);
char *ifm_crypt_gensalt_rn(const char *__prefix, unsigned long __count,
                           const char *__rbytes, int __nrbytes, char *__output, int __output_size);
char *ifm_crypt_gensalt_ra(const char *__prefix, unsigned long __count, const char *__rbytes, int __nrbytes);
int ifm_crypt_checksalt(const char *__setting);
const char *ifm_crypt_preferred_method(void);

#ifdef __cplusplus
}
#endif

#endif /* IFM_LIBXCRYPT_H */