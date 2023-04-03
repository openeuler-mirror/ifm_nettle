/******************************************************************************
 * iSula-libutils: utils library for iSula
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 *
 * Authors:
 * Haozi007 <liuhao27@huawei.com>
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
#include <gtest/gtest.h>

#include "sm3.h"
#include "testutils.h"

const struct nettle_hash nettle_ifm_sm3
= _NETTLE_HASH(sm3, SM3);

TEST(sm3_testcases, test_sm3_init_use_nettle)
{
    /* test vectors from:
     * https://datatracker.ietf.org/doc/html/draft-shen-sm3-hash-01
     */
  test_hash(&nettle_ifm_sm3,
            SDATA("abc"),
            SHEX("66c7f0f462eeedd9 d1f2d46bdc10e4e2"
                 "4167c4875cf2f7a2 297da02b8f4ba8e0"));

  test_hash(&nettle_ifm_sm3,
            SDATA("abcdabcdabcdabcdabcdabcdabcdabcd"
                  "abcdabcdabcdabcdabcdabcdabcdabcd"),
            SHEX("debe9ff92275b8a1 38604889c18e5a4d"
                 "6fdb70e5387e5765 293dcba39c0c5732"));
}
