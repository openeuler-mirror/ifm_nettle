/* 
   Copyright (C) 2002, 2010 Niels Möller

   This file is part of GNU Nettle.

   GNU Nettle is free software: you can redistribute it and/or
   modify it under the terms of either:

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.

   or both in parallel, as here.

   GNU Nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
*/
#include <gtest/gtest.h>

#include "sha2.h"
#include "testutils.h"

const struct nettle_hash nettle_ifm_sha512
= _NETTLE_HASH(ifm_sha512, SHA512);

TEST(sha512_testcases, test_sha512_hash_1)
{
  test_hash(&nettle_sha512, SDATA("abc"),
	    SHEX("ddaf35a193617aba cc417349ae204131"
		 "12e6fa4e89a97ea2 0a9eeee64b55d39a"
		 "2192992a274fc1a8 36ba3c23a3feebbd"
		 "454d4423643ce80e 2a9ac94fa54ca49f"));
}

TEST(sha512_testcases, test_sha512_hash_2)
{
  test_hash(&nettle_sha512,
	    SDATA("abcdefghbcdefghicdefghijdefg"
		  "hijkefghijklfghijklmghijklmn"
		  "hijklmnoijklmnopjklmnopqklmn"
		  "opqrlmnopqrsmnopqrstnopqrstu"),
	    SHEX("8e959b75dae313da 8cf4f72814fc143f"
		 "8f7779c6eb9f7fa1 7299aeadb6889018"
		 "501d289e4900f7e4 331b99dec4b5433a"
		 "c7d329eeb6dd2654 5e96e55b874be909"));
}

TEST(sha512_testcases, test_sha512_hash_3)
{
  test_hash(&nettle_sha512,
	    SDATA("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		  "abcdefghijklmnopqrstuvwxyz"
		  "0123456789"),
	    SHEX("1E07BE23C26A86EA37EA810C8EC78093"
		 "52515A970E9253C26F536CFC7A9996C4"
		 "5C8370583E0A78FA4A90041D71A4CEAB"
		 "7423F19C71B9D5A3E01249F0BEBD5894"));
}

TEST(sha512_testcases, test_sha512_hash_4)
{
  test_hash(&nettle_sha512,
	    SDATA("1234567890123456789012345678901234567890"
		  "1234567890123456789012345678901234567890"),
	    SHEX("72EC1EF1124A45B047E8B7C75A932195"
		 "135BB61DE24EC0D1914042246E0AEC3A"
		 "2354E093D76F3048B456764346900CB1"
		 "30D2A4FD5DD16ABB5E30BCB850DEE843"));
}

TEST(sha512_testcases, test_sha512_hash_6)
{
  test_hash(&nettle_sha512,
	    SDATA("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		  "abcdefghijklmnopqrstuvwxyz"
		  "0123456789"
		  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		  "abcdefghijklmnopqrstuvwxyz"
		  "0123456789"
		  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		  "abcdefghijklmnopqrstuvwxyz"
		  "0123456789"),
	    SHEX("5338370f5655f4da14572d4fb471539b"
		 "201485ecfb3d3204048dc6b83e61fab5"
		 "05bcbbd73e644a1a5d159a32a0889cf3"
		 "c9591b69b26d31be56c68838ce3cd63d"));
}

TEST(sha512_testcases, test_sha512_hash_7)
{
  test_hash(&nettle_sha512,
	    SDATA("1234567890123456789012345678901234567890"
		  "1234567890123456789012345678901234567890"	    
		  "1234567890123456789012345678901234567890"
		  "1234567890123456789012345678901234567890"	    
		  "1234567890123456789012345678901234567890"
		  "1234567890123456789012345678901234567890"	    
		  "1234567890123456789012345678901234567890"
		  "1234567890123456789012345678901234567890")	    ,
	    SHEX("33f8901b053e4cc677d3cb4122d96ad9"
		 "b96b13bf76194cf962488bb4de4998a7"
		 "1455cb31582db527adf77a485b81cf5b"
		 "722a5e8638eb6be487400f3aec006e7c"));
}

TEST(sha512_testcases, test_sha512_hash_8)
{
  test_hash(&nettle_sha512, SDATA(""),
	    SHEX("cf83e1357eefb8bd f1542850d66d8007"
		 "d620e4050b5715dc 83f4a921d36ce9ce"
		 "47d0d13c5d85f2b0 ff8318d2877eec2f"
		 "63b931bd47417a81 a538327af927da3e"));
}

TEST(sha512_testcases, test_sha512_hash_9)
{
  test_hash(&nettle_sha512, SDATA("a"),
	    SHEX("1f40fc92da241694 750979ee6cf582f2"
		 "d5d7d28e18335de0 5abc54d0560e0f53"
		 "02860c652bf08d56 0252aa5e74210546"
		 "f369fbbbce8c12cf c7957b2652fe9a75"));
}

TEST(sha512_testcases, test_sha512_hash_10)
{
  test_hash(&nettle_sha512, SDATA("38"),
	    SHEX("caae34a5e8103126 8bcdaf6f1d8c04d3"
		 "7b7f2c349afb705b 575966f63e2ebf0f"
		 "d910c3b05160ba08 7ab7af35d40b7c71"
		 "9c53cd8b947c9611 1f64105fd45cc1b2"));
}

TEST(sha512_testcases, test_sha512_hash_11)
{
  test_hash(&nettle_sha512, SDATA("message digest"),
	    SHEX("107dbf389d9e9f71 a3a95f6c055b9251"
		 "bc5268c2be16d6c1 3492ea45b0199f33"
		 "09e16455ab1e9611 8e8a905d5597b720"
		 "38ddb372a8982604 6de66687bb420e7c"));
}
TEST(sha512_testcases, test_sha512_hash_12)
{
  test_hash(&nettle_sha512, SDATA("abcdefghijklmnopqrstuvwxyz"),
	    SHEX("4dbff86cc2ca1bae 1e16468a05cb9881"
		 "c97f1753bce36190 34898faa1aabe429"
		 "955a1bf8ec483d74 21fe3c1646613a59"
		 "ed5441fb0f321389 f77f48a879c7b1f1"));
}
TEST(sha512_testcases, test_sha512_hash_13)
{
  test_hash(&nettle_sha512,
	    SDATA("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
		  "ghijklmnopqrstuvwxyz0123456789"),
	    SHEX("1e07be23c26a86ea 37ea810c8ec78093"
		 "52515a970e9253c2 6f536cfc7a9996c4"
		 "5c8370583e0a78fa 4a90041d71a4ceab"
		 "7423f19c71b9d5a3 e01249f0bebd5894"));
}
TEST(sha512_testcases, test_sha512_hash_14)
{
  test_hash(&nettle_sha512,
	    SDATA("12345678901234567890123456789012"
		  "34567890123456789012345678901234"
		  "5678901234567890"),
	    SHEX("72ec1ef1124a45b0 47e8b7c75a932195"
		 "135bb61de24ec0d1 914042246e0aec3a"
		 "2354e093d76f3048 b456764346900cb1"
		 "30d2a4fd5dd16abb 5e30bcb850dee843"));
}
