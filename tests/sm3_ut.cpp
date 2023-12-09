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
#include "sm3_meta.h"
#include "testutils.h"

#define sm3_ctx ifm_sm3_ctx

const struct nettle_hash nettle_ifm_sm3
= _NETTLE_HASH(ifm_sm3, SM3);

TEST(sm3_testcases, test_sm3_init_use_nettle_1)
{
    /* test vectors from:
     * https://datatracker.ietf.org/doc/html/draft-shen-sm3-hash-01
     */
  test_hash(&nettle_ifm_sm3,
            SDATA("abc"),
            SHEX("66c7f0f462eeedd9 d1f2d46bdc10e4e2"
                 "4167c4875cf2f7a2 297da02b8f4ba8e0"));
}
TEST(sm3_testcases, test_sm3_init_use_nettle_2)
{
  test_hash(&nettle_ifm_sm3,
            SDATA("abcdabcdabcdabcdabcdabcdabcdabcd"
                  "abcdabcdabcdabcdabcdabcdabcdabcd"),
            SHEX("debe9ff92275b8a1 38604889c18e5a4d"
                 "6fdb70e5387e5765 293dcba39c0c5732"));
}
TEST(sm3_testcases, test_sm3_init_use_nettle_3)
{
  test_hash(&nettle_ifm_sm3,
            SDATA("abcdefg"),
            SHEX("08b7ee8f741bfb63 907fcd0029ae3fd6"
                 "403e6927b50ed9f0 4665b22eab81e9b7"));
}
TEST(sm3_testcases, test_sm3_init_use_nettle_4)
{
  test_hash(&nettle_ifm_sm3,
            SDATA("abcdefghbcdefghicdefghijdefg"
		  "hijkefghijklfghijklmghijklmn"
		  "hijklmnoijklmnopjklmnopqklmn"
		  "opqrlmnopqrsmnopqrstnopqrstu"),
            SHEX("78bcfb586acd983d 7fae8e6930157f15"
                 "62019e2caf68f1c9 8a855f1a95bb89bb"));
}
TEST(sm3_testcases, test_sm3_init_use_nettle_5)
{
  test_hash(&nettle_ifm_sm3,
            SDATA(""),
            SHEX("1ab21d8355cfa17f 8e61194831e81a8f"
                 "22bec8c728fefb74 7ed035eb5082aa2b"));
}
TEST(sm3_testcases, test_sm3_init_use_nettle_6)
{
  test_hash(&nettle_ifm_sm3,
            SDATA("a"),
            SHEX("623476ac18f65a29 09e43c7fec61b49c"
                 "7e764a91a18ccb82 f1917a29c86c5e88"));
}
TEST(sm3_testcases, test_sm3_init_use_nettle_7)
{
  test_hash(&nettle_ifm_sm3,
            SDATA("38"),
            SHEX("fff2433729dcf157 923b7cad7d687f35"
                 "a3ee8155d39f8b65 005f391afd9cff8e"));
}
TEST(sm3_testcases, test_sm3_init_use_nettle_8)
{
  test_hash(&nettle_ifm_sm3,
            SDATA("message digest"),
            SHEX("c522a942e89bd80d 97dd666e7a5531b3"
                 "6188c9817149e9b2 58dfe51ece98ed77"));
}
TEST(sm3_testcases, test_sm3_init_use_nettle_9)
{
  test_hash(&nettle_ifm_sm3,
            SDATA("abcdefghijklmnopqrstuvwxyz"),
            SHEX("b80fe97a4da24afc 277564f66a359ef4"
                 "40462ad28dcc6d63 adb24d5c20a61595"));
}
TEST(sm3_testcases, test_sm3_init_use_nettle_10)
{
  test_hash(&nettle_ifm_sm3,
            SDATA("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            SHEX("22c67ae6b872a676 3357e22a5115f5cd"
                 "8fda75896bf4dc02 69183a332a3ad97e"));
}
TEST(sm3_testcases, test_sm3_init_use_nettle_11)
{
  test_hash(&nettle_ifm_sm3,
            SDATA("12345678901234567890123456789012"
		  "34567890123456789012345678901234"
		  "5678901234567890"),
            SHEX("ad81805321f3e69d 251235bf886a5648"
                 "44873b56dd7dde40 0f055b7dde39307a"));
} 