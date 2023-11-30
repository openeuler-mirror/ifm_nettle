/******************************************************************************
 * bench_sm3_meta.h: sm3_meta for bench
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * chen-yufanspace <1109674186@qq.com>
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

#ifndef BENCH_SM3_META_H
#define BENCH_SM3_META_H
#include <nettle/nettle-meta.h>
#include "sm3_meta.h"
#include "sm3.h"

const struct nettle_hash nettle_ifm_sm3 = _NETTLE_HASH(ifm_sm3, SM3);

#endif