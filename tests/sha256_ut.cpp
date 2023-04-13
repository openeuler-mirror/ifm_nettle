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

#include "sha2.h"
#include "testutils.h"

const struct nettle_hash nettle_ifm_sha256
= _NETTLE_HASH(sha256, SHA256);

TEST(sha256_testcases, test_sha256_hash_1)
{
  test_hash(&nettle_sha256, SDATA("abc"),
	    SHEX("ba7816bf8f01cfea 414140de5dae2223"
		 "b00361a396177a9c b410ff61f20015ad"));
}

TEST(sha256_testcases, test_sha256_hash_2)
{
  test_hash(&nettle_sha256,
	    SDATA("abcdbcdecdefdefgefghfghighij"
		  "hijkijkljklmklmnlmnomnopnopq"),
	    SHEX("248d6a61d20638b8 e5c026930c3e6039"
		 "a33ce45964ff2167 f6ecedd419db06c1"));
}

TEST(sha256_testcases, test_sha256_hash_3)
{
  test_hash(&nettle_sha256,
	    SDATA("abcdefghbcdefghicdefghijdefg"
		  "hijkefghijklfghijklmghijklmn"
		  "hijklmnoijklmnopjklmnopqklmn"
		  "opqrlmnopqrsmnopqrstnopqrstu"),
	    SHEX("cf5b16a778af8380 036ce59e7b049237"
		 "0b249b11e8f07a51 afac45037afee9d1"));
}

TEST(sha256_testcases, test_sha256_hash_4)
{
  test_hash(&nettle_sha256, SDATA(""),
	    SHEX("e3b0c44298fc1c14 9afbf4c8996fb924"
		 "27ae41e4649b934c a495991b7852b855"));
}

TEST(sha256_testcases, test_sha256_hash_6)
{
  test_hash(&nettle_sha256, SDATA("a"),
	    SHEX("ca978112ca1bbdca fac231b39a23dc4d"
		 "a786eff8147c4e72 b9807785afee48bb"));
}

TEST(sha256_testcases, test_sha256_hash_7)
{
  test_hash(&nettle_sha256, SDATA("38"),
	    SHEX("aea92132c4cbeb26 3e6ac2bf6c183b5d"
		 "81737f179f21efdc 5863739672f0f470"));
}

TEST(sha256_testcases, test_sha256_hash_8)
{
  test_hash(&nettle_sha256, SDATA("message digest"),
	    SHEX("f7846f55cf23e14e ebeab5b4e1550cad"
		 "5b509e3348fbc4ef a3a1413d393cb650"));
}

TEST(sha256_testcases, test_sha256_hash_9)
{
  test_hash(&nettle_sha256, SDATA("abcdefghijklmnopqrstuvwxyz"),
	    SHEX("71c480df93d6ae2f 1efad1447c66c952"
		 "5e316218cf51fc8d 9ed832f2daf18b73"));
}

TEST(sha256_testcases, test_sha256_hash_10)
{
  test_hash(&nettle_sha256,
	    SDATA("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
		  "ghijklmnopqrstuvwxyz0123456789"),
	    SHEX("db4bfcbd4da0cd85 a60c3c37d3fbd880"
		 "5c77f15fc6b1fdfe 614ee0a7c8fdb4c0"));
}

TEST(sha256_testcases, test_sha256_hash_11)
{
  test_hash(&nettle_sha256,
	    SDATA("12345678901234567890123456789012"
		  "34567890123456789012345678901234"
		  "5678901234567890"),
	    SHEX("f371bc4a311f2b00 9eef952dd83ca80e"
		 "2b60026c8e935592 d0f9c308453c813e"));
}
