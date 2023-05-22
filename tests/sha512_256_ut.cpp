/* 
   Copyright (C) 2014 Niels Möller

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

const struct nettle_hash nettle_ifm_sha512_256
= _NETTLE_HASH(ifm_sha512_256, SHA512_256);

TEST(sha512_testcases, test_sha512_hash_1)
{
  test_hash(&nettle_sha512_256, SDATA("abc"),
	    SHEX("53048E26 81941EF9 9B2E29B7 6B4C7DAB"
		 "E4C2D0C6 34FC6D46 E0E2F131 07E7AF23"));
}

TEST(sha512_testcases, test_sha512_hash_2)
{
  test_hash(&nettle_sha512_256, SDATA("abcdefghbcdefghicdefghijdefghijk"
				      "efghijklfghijklmghijklmnhijklmno"
				      "ijklmnopjklmnopqklmnopqrlmnopqrs"
				      "mnopqrstnopqrstu"),
	    SHEX("3928E184 FB8690F8 40DA3988 121D31BE"
		 "65CB9D3E F83EE614 6FEAC861 E19B563A"));
}
