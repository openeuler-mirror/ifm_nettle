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
#include "crypt.h"

char *ifm_crypt(const char *__phrase, const char *__setting)
{
    return crypt(__phrase, __setting);
}

char *ifm_crypt_r(const char *__phrase, const char *__setting, struct crypt_data *__restrict __data)
{
    return crypt_r(__phrase, __setting, __data);
}

char *ifm_crypt_rn(const char *__phrase, const char *__setting, void *__data, int __size)
{
    return crypt_rn(__phrase, __setting, __data, __size);
}

char *ifm_crypt_ra(const char *__phrase, const char *__setting, void **__data, int *__size)
{
    return crypt_ra(__phrase, __setting, __data, __size);
}

char *ifm_crypt_gensalt(const char *__prefix, unsigned long __count, const char *__rbytes, int __nrbytes)
{
    return crypt_gensalt(__prefix, __count, __rbytes, __nrbytes);
}

char *ifm_crypt_gensalt_rn(const char *__prefix, unsigned long __count,
                           const char *__rbytes, int __nrbytes, char *__output, int __output_size)
{
    return crypt_gensalt_rn(__prefix, __count, __rbytes, __nrbytes, __output, __output_size);
}

char *ifm_crypt_gensalt_ra(const char *__prefix, unsigned long __count, const char *__rbytes, int __nrbytes)
{
    return crypt_gensalt_ra(__prefix, __count, __rbytes, __nrbytes);
}

int ifm_crypt_checksalt(const char *__setting)
{
    return crypt_checksalt(__setting);
}

const char *ifm_crypt_preferred_method()
{
    return crypt_preferred_method();
}