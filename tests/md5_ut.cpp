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

#include "md5.h"
#define md5_ctx ifm_md5_ctx

#include "testutils.h"


const struct nettle_hash nettle_ifm_md5
= _NETTLE_HASH(md5, MD5);

TEST(md5_testcases, test_md5_hash_1)
{
  test_hash(&nettle_ifm_md5, SDATA(""),
	    SHEX("D41D8CD98F00B204 E9800998ECF8427E"));
}

TEST(md5_testcases, test_md5_hash_2)
{
  test_hash(&nettle_ifm_md5, SDATA("a"),
	    SHEX("0CC175B9C0F1B6A8 31C399E269772661"));
}

TEST(md5_testcases, test_md5_hash_3)
{
  test_hash(&nettle_ifm_md5, SDATA("abc"),
	    SHEX("900150983cd24fb0 D6963F7D28E17F72"));
}

TEST(md5_testcases, test_md5_hash_4)
{
  test_hash(&nettle_ifm_md5, SDATA("message digest"),
	    SHEX("F96B697D7CB7938D 525A2F31AAF161D0"));
}

TEST(md5_testcases, test_md5_hash_5)
{
  test_hash(&nettle_ifm_md5, SDATA("abcdefghijklmnopqrstuvwxyz"),
	    SHEX("C3FCD3D76192E400 7DFB496CCA67E13B"));
}

TEST(md5_testcases, test_md5_hash_6)
{
  test_hash(&nettle_ifm_md5,
	    SDATA("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		  "abcdefghijklmnopqrstuvwxyz"
		  "0123456789"),
	    SHEX("D174AB98D277D9F5 A5611C2C9F419D9F"));
}

TEST(md5_testcases, test_md5_hash_7)
{
  test_hash(&nettle_ifm_md5,
	    SDATA("1234567890123456789012345678901234567890"
		  "1234567890123456789012345678901234567890"),
	    SHEX("57EDF4A22BE3C955 AC49DA2E2107B67A"));
}

TEST(md5_testcases, test_md5_hash_8)
{
  /* Additional test vector, from Daniel Kahn Gillmor */
  test_hash(&nettle_ifm_md5, SDATA("38"),
	    SHEX("a5771bce93e200c3 6f7cd9dfd0e5deaa"));
}

#define M0 \
  /*                                          vv */				\
  "d131dd02 c5e6eec4 693d9a06 98aff95c 2fcab5 87 12467eab 4004583e b8fb7f89"	\
  "55ad3406 09f4b302 83e48883 25 71 415a 085125e8 f7cdc99f d91dbd f2 80373c5b"	\
  /*                             ^^                               ^^ */

#define M1 \
  /*                                          vv */				\
  "d131dd02 c5e6eec4 693d9a06 98aff95c 2fcab5 07 12467eab 4004583e b8fb7f89"	\
  "55ad3406 09f4b302 83e48883 25 f1 415a 085125e8 f7cdc99f d91dbd 72 80373c5b"	\
  /*                             ^^                               ^^ */

#define N0									\
  /*                                          vv */				\
  "960b1dd1 dc417b9c e4d897f4 5a6555d5 35739a c7 f0ebfd0c 3029f166 d109b18f"	\
  "75277f79 30d55ceb 22e8adba 79 cc 155c ed74cbdd 5fc5d36d b19b0a d8 35cca7e3"	\
  /*                             ^^                               ^^ */

#define N1									\
  /*                                          vv */				\
  "960b1dd1 dc417b9c e4d897f4 5a6555d5 35739a 47 f0ebfd0c 3029f166 d109b18f"	\
  "75277f79 30d55ceb 22e8adba 79 4c 155c ed74cbdd 5fc5d36d b19b0a 58 35cca7e3"	\
  /*                             ^^                               ^^ */

  /* Note: The checksum in the paper, 1f160396 efc71ff4 bcff659f
     bf9d0fa3, is incorrect. */

#define H0 "a4c0d35c 95a63a80 5915367d cfe6b751"

#define N2									\
  /*                                          vv */				\
  "d8823e31 56348f5b ae6dacd4 36c919c6 dd53e2 b4 87da03fd 02396306 d248cda0"	\
  "e99f3342 0f577ee8 ce54b670 80 a8 0d1e c69821bc b6a88393 96f965 2b 6ff72a70"	\
  /*                             ^^                               ^^ */

#define N3									\
  /*                                          vv */				\
  "d8823e31 56348f5b ae6dacd4 36c919c6 dd53e2 34 87da03fd 02396306 d248cda0"	\
  "e99f3342 0f577ee8 ce54b670 80 28 0d1e c69821bc b6a88393 96f965 ab 6ff72a70"	\
  /*                             ^^                               ^^ */

  /* Note: Also different from the checksum in the paper */
  
#define H1 "79054025 255fb1a2 6e4bc422 aef54eb4"
  
TEST(md5_testcases, test_md5_hash_9)
{
  test_hash(&nettle_ifm_md5,
	    SHEX(M0 N0), SHEX(H0));
}

TEST(md5_testcases, test_md5_hash_10)
{
  test_hash(&nettle_ifm_md5,
	    SHEX(M1 N1), SHEX(H0));
}

TEST(md5_testcases, test_md5_hash_11)
{
  test_hash(&nettle_ifm_md5,
	    SHEX(M0 N2), SHEX(H1));
}

TEST(md5_testcases, test_md5_hash_12)
{
  test_hash(&nettle_ifm_md5,
	    SHEX(M1 N3), SHEX(H1));
}
