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

const struct nettle_hash nettle_ifm_sha512_224
= _NETTLE_HASH(ifm_sha512_224, SHA512_224);

TEST(sha512_testcases, test_sha512_hash_1)
{
  test_hash(&nettle_sha512_224, SDATA("abc"),
	    SHEX("4634270F 707B6A54 DAAE7530 460842E2"
		 "0E37ED26 5CEEE9A4 3E8924AA"));
}

TEST(sha512_testcases, test_sha512_hash_2)
{
  test_hash(&nettle_sha512_224, SDATA("abcdefghbcdefghicdefghijdefghijk"
				      "efghijklfghijklmghijklmnhijklmno"
				      "ijklmnopjklmnopqklmnopqrlmnopqrs"
				      "mnopqrstnopqrstu"),
	    SHEX("23FEC5BB 94D60B23 30819264 0B0C4533"
		 "35D66473 4FE40E72 68674AF9"));
}
