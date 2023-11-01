/******************************************************************************
 * ifm_verto_libhv.h: adaptation layer of libhv based on libverto
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 *
 * Authors:
 * Zixiang Yan <ujm456@126.com>
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

#ifndef IFM_VERTO_LIBHV_H_INCLUDED
#define IFM_VERTO_LIBHV_H_INCLUDED

#include "ifm_verto.h"


#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

verto_ctx* verto_new_libhv(void);

verto_ctx* verto_default_libhv(void);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* IFM_VERTO_LIBHV_H_INCLUDED */
