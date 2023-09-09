/******************************************************************************
 * nettle-meta.h
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * Shankang Ke <shankang@isrc.iscas.ac.cn>
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

#ifndef IFM_NETTLE_META_H_INCLUDED
#define IFM_NETTLE_META_H_INCLUDED

#include "nettle/nettle-meta.h"

#ifdef __cplusplus
extern "C" {
#endif

#define nettle_aes128 ifm_nettle_aes128
#define nettle_aes192 ifm_nettle_aes192
#define nettle_aes256 ifm_nettle_aes256

extern const struct nettle_cipher nettle_aes128;
extern const struct nettle_cipher nettle_aes192;
extern const struct nettle_cipher nettle_aes256;

#ifdef __cplusplus
}
#endif

#endif /* IFM_NETTLE_META_H_INCLUDED */