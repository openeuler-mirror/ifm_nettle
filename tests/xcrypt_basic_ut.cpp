/* Test passing invalid arguments to crypt*().

   Written by Zack Weinberg <zackw at panix.com> in 2018.
   To the extent possible under law, Zack Weinberg has waived all
   copyright and related or neighboring rights to this work.

   See https://creativecommons.org/publicdomain/zero/1.0/ for further
   details.  */

#include <errno.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "ifm_crypt.h"

#include "testutils.h"

#define ARRAY_SIZE(a_)  (sizeof (a_) / sizeof ((a_)[0]))

struct testcase
{
    const char *phrase;
    const char *settings;
    const char *except;
};

static const struct testcase testcases[] =
        {
                {
                        "fdqd32",
                        "$5$gsmSDhx1xJByintQ",
                        "$5$gsmSDhx1xJByintQ$.afEgHWOQVqCLQBlLct1fjyB.XLc0XbjbYV0W/YMmL6"
                },
                {
                        "abc",
                        "$5$hmBz9GHejlqmxfev",
                        "$5$hmBz9GHejlqmxfev$wtvkTuY2auRewvfRstHos.6J1iiqFtsjYRcFjg7KT/3"
                },
                {
                        "abc",
                        "$6$rTC/jZ2.yh6gUsQa",
                        "$6$rTC/jZ2.yh6gUsQa$2Or4tx.ckoLVWR9L.m2MTMOay88BrVOfhyxqS4XDLC55367kFlJIf"
                        "KsecsZoJb7jLod5TyWPTFnLx5Pnxo98k0"
                },
                {
                        "",
                        "$5$2xDUEErzY4KLYaDl",
                        "$5$2xDUEErzY4KLYaDl$qJvUwpav1tCqK8as84i4pPK2ouijpgQGoVtNBzYzjw7"
                },
                {
                        "",
                        "$6$Jp5Vsqfp7L39PeST",
                        "$6$Jp5Vsqfp7L39PeST$sqwLE7FksXFv9LNh2tAGNRhlHjIJB9RtVSjdJ6Axqv3fM74RdlUe"
                        "zgLvPnJwUQVd.09WAd64Awmxx0adyRnK9/"
                },
                {
                        "a",
                        "$5$zHK3ww7IGH3BkAgx",
                        "$5$zHK3ww7IGH3BkAgx$4M1jP/iOlgrndiE/RakKH9sIbhIKclMoGXlZA40nAbC"
                },
                {
                        "a",
                        "$6$ZWolmhgLkmH3HTOI",
                        "$6$ZWolmhgLkmH3HTOI$Ut8IkuopyPaI9.ZeyLSYpauNhLYb9P0yud4gNdHkpI6euGG7lJ6148B"
                        "PtPVJs4WQffDTPf5n2UQ7A04PlPT9G1"
                },
                {
                        "message digest",
                        "$5$VwhzPQBRpOicEoNv",
                        "$5$VwhzPQBRpOicEoNv$gpuwUhGBDUkhjaBLjijCmwK0IuLlHucH6Z1V16FWeyC"
                },
                {
                        "message digest",
                        "$6$snJ/oINWshItZth3",
                        "$6$snJ/oINWshItZth3$Oleq0fjcQ9PyB0DB93d6qNU1eACqqFFHnJSjpSjQfMxUU9BnP2nt"
                        "Wnak1L45J0ccQCxEzKC1bPFAeftQqgr1.."
                },
                {
                        "abcdefghijklmnopqrstuvwxyz",
                        "$5$.tPq7lH1SXzzSTxE",
                        "$5$.tPq7lH1SXzzSTxE$UkYN3W9x.DBCsCXDxmRw5xOARkB8fcTb8lcI2s5hKnC"
                },
                 {
                   "lnmpapqfwkhopkmcoqhnwnkuewhsqmgbbuqcljjivswmdkqtbxixmvtrrbljptnsnfwz",
                   "$5$nkuP6YV9xeuK2Cgm",
                   "$5$nkuP6YV9xeuK2Cgm$8yRBGEGxFAtUMN4LGJDhNALgJTxAWvum2XhVUF9sUEB"
                 },
                {
                        "abcdefghijklmnopqrstuvwxyz",
                        "$6$DXSa7ntyzHwxZIA6",
                        "$6$DXSa7ntyzHwxZIA6$VIqsoYi4J0BjvDyyzP8ezKchQJGAMOXktUAo9LavJCJnohdiHMQiOv"
                        "At7RzpN9dJswgXfdKcIQ2ezN.ALDw.O0"
                },
                {
                        "nwlrbbmqbhcdarzowkkyhiddqscdxrjm",
                        "$5$Gn4j23/5pRoIh5SY",
                        "$5$Gn4j23/5pRoIh5SY$QGmXZFfoMag6RajkyRuC9uVX6wpaZc/jxb4/145yc44"
                },
                {
                        "owfrxsjybldbefsarcbynecdyggxxpkl",
                        "$5$wUHWLVSyYyZvadxJ",
                        "$5$wUHWLVSyYyZvadxJ$ebUsiOjwuVfJSzkHodnppy5V/YI8.BDl67qnZe9REO8"
                },
                {
                        "rwblnsadeuguumoqcdrubetokyxhoach",
                        "$5$0ed6o3SNA1bx0tCB",
                        "$5$0ed6o3SNA1bx0tCB$mLLIYlM2bzsucQ9u9alw8wh1rNjsAI6Hk2RDD58xtbB"
                },
                {
                        "wcsgspqoqmsboaguwnnyqxnzlgdgwpbt",
                        "$5$FAF2h1vue3.2uIlO",
                        "$5$FAF2h1vue3.2uIlO$8lR6QSKvs.Ue/KL9M1qVWJ7/O9bi8PeNkqc5FX0bbM8"
                },
                 {
                   "nwlrbbmqbhcdarzowkkyhiddqscdxrjmowfrxsjybldbefsarcbynecdyggxxpklorellnmpapqfwkho",
                   "$6$PwbkjzK1pwCfITbF",
                   "$6$PwbkjzK1pwCfITbF$dE/0AJd.Cq/TBtwAFTs4q243pizNIVnhO6Nkn44D/UXRaSOPH7C9ROMmbOvoQ"
                   "mHwhTyepq6W8LCGQlnyQwh271"
                 },
                {
                        "cgpxiqvkuytdlcgdewhtaciohordtqkv",
                        "$5$pBx/z/Dy.PuOsnMm",
                        "$5$pBx/z/Dy.PuOsnMm$V5dwAGCmmdwgwwjVipV2VWMZjEX3SHEo6dwa274gFp8"
                },
                {
                        "jxkitzyxacbhhkicqcoendtomfgdwdwf",
                        "$5$4ob2S8v4SYy5oQmd",
                        "$5$4ob2S8v4SYy5oQmd$xnY0GsdHFJCTDXOedWwJ9zYmAXHiKBQN8wHJ3Axk.b9"
                },
                {
                        "bsaqxwpqcacehchzvfrkmlnozjkpqpxr",
                        "$5$MACMvWJybUilFKyC",
                        "$5$MACMvWJybUilFKyC$RH0S6acg/wRdNHeMNruy6RZZ/bkTAaFfZC4dj8ecvl7"
                },
                {
                        "ptnsnfwzqfjmafadrrwsofsbcnuvqhff",
                        "$5$3H3s2wLmAfFgyW8g",
                        "$5$3H3s2wLmAfFgyW8g$GYC5mlmY5tWnVjLD1i4GcKVu5Mpu8dZlBJPhZkOCMWA"
                },
                {
                        "qmgbbuqcljjivswmdkqtbxixmvtrrblj",
                        "$5$eHFAG8QMFvDFoAMN",
                        "$5$eHFAG8QMFvDFoAMN$.8daCmJ.M0xtq5ADuCvBlve1DRHcGRlZZ7anxvfANh2"
                },
                {
                        "orellnmpapqfwkhopkmcoqhnwnkuewhs",
                        "$5$qgZWq0Sss0dd2k5W",
                        "$5$qgZWq0Sss0dd2k5W$48sDm1LVyz7DsasaaW.PmmSnpoTsaRYvGWE/udhKhv1"
                },
                {
                        "nwlrbbmqbhcdarzowkkyhiddqscdxrjmowfrxsjybldbefsarcbynecdyggxxpk",
                        "$6$EY1IGIIfrXRsk.oW",
                        "$6$EY1IGIIfrXRsk.oW$aBei/YilXGYOm0Ii1dApd3cvFY8PqK9eYvEhY.B/qnI.92fv1PIzA"
                        "ibSvay5jkb6G8RoBBZyQ1mXXB8Dg6NgI1"
                },
                {
                        "lorellnmpapqfwkhopkmcoqhnwnkuewhsqmgbbuqcljjivswmdkqtbxixmvtrrb",
                        "$6$AUIWwzyaj5JpbFo3",
                        "$6$AUIWwzyaj5JpbFo3$y1IBbpLEZWinCMvAZ2mnFEGDfeYJP/GcqdMqK2lwC3gACSl9iuUKa08"
                        "Qd66Z9ECtgRkDNtypPcagcaUhDiLG90"
                },
                {
                        "ljptnsnfwzqfjmafadrrwsofsbcnuvqhffbsaqxwpqcacehchzvfrkmlnozjkpq",
                        "$6$8kS/BUvu/X8OYTpt",
                        "$6$8kS/BUvu/X8OYTpt$rA.C2GU61RhWC1Vnexcovttm3Haejj5jdt8J.t35huqR2ALC.kcAXN"
                        "0CJ5yfERgc5MkC//go2KvTTWcweWXEq."
                },
                {
                    "djsuyibyebmwsiqyoygyxymzevypzvjegebeocfuftsxdixtigsieehkchzdflilrjqfnxztqrsvbsp"
                    "kyhsenbppkqtpddbuotbbqcwivrfxjujjddntgeiqvdgaijvwcyaubwewpjvygehljxepbpiwuqzdzubdubzva"
                    "fspqpqwuzifwovyddwyvvburczmgyjgfdxvtnunneslsplwuiupfxlzbknhkwppanltcfirjcddsozoyvegurfwc"
                    "sfmoxeqmrjowrghwlkobmeahkgccnaehhsveymqpxhlrnunyfdzrhbasjeuygafoubutpnimuwfjqsjxvkqdorx"
                    "xvrwctdsneogvbpkxlpgdirbfcriqifpgynkrrefxsnvucftpwctgtwmxnupycfgcuqunublmoiitncklefszbex"
                    "rampetvhqnddjeqvuygpnkazqfrpjvoaxdpcwmjobmskskfojnewxgxnnofwltwjwnnvbwjckdmeouuzhyv",
                    "$5$zJEPvQQy9eB9zifP",
                    "$5$zJEPvQQy9eB9zifP$HkzjRzpQ80AQ.xMLL5PsqrLNSGlslPo41Rq4pClxrD8"
                },
                {
                    "djsuyibyebmwsiqyoygyxymzevypzvjegebeocfuftsxdixtigsieehkchzdflilrjqfnxztqrsvbs"
                    "pkyhsenbppkqtpddbuotbbqcwivrfxjujjddntgeiqvdgaijvwcyaubwewpjvygehljxepbpiwuqzdzubdubzva"
                    "fspqpqwuzifwovyddwyvvburczmgyjgfdxvtnunneslsplwuiupfxlzbknhkwppanltcfirjcddsozoyvegurf"
                    "wcsfmoxeqmrjowrghwlkobmeahkgccnaehhsveymqpxhlrnunyfdzrhbasjeuygafoubutpnimuwfjqsjxvkqd"
                    "orxxvrwctdsneogvbpkxlpgdirbfcriqifpgynkrrefxsnvucftpwctgtwmxnupycfgcuqunublmoiitncklefs"
                    "zbexrampetvhqnddjeqvuygpnkazqfrpjvoaxdpcwmjobmskskfojnewxgxnnofwltwjwnnvbwjckdmeouuzhyv",
                    "$6$qSA1tgswUSWJ1ahr",
                    "$6$qSA1tgswUSWJ1ahr$yerC0xLzii63H0tY1H/Zi/A8pFl3tZTa8pFUX0N8nTrgk7kCx2Lb4SpwhmUM"
                    "bKN1sDIblFKRcoHF0BYUsHgMF1"
                },
                {
                    "djsuyibyebmwsiqyoygyxymzevypzvjegebeocfuftsxdixtigsieehkchzdflilrjqfnxztqrsvbsp"
                    "kyhsenbppkqtpddbuotbbqcwivrfxjujjddntgeiqvdgaijvwcyaubwewpjvygehljxepbpiwuqzdzubdubzvaf"
                    "spqpqwuzifwovyddwyvvburczmgyjgfdxvtnunneslsplwuiupfxlzbknhkwppanltcfirjcddsozoyvegurfwc"
                    "sfmoxeqmrjowrghwlkobmeahkgccnaehhsveymqpxhlrnunyfdzrhbasjeuygafoubutpnimuwfjqsjxvkqdorx"
                    "xvrwctdsneogvbpkxlpgdirbfcriqifpgynkrrefxsnvucftpwctgtwmxnupycfgcuqunublmoiitncklefszbex"
                    "rampetvhqnddjeqvuygpnkazqfrpjvoaxdpcwmjobmskskfojnewxgxnnofwltwjwnnvbwjckdmeouuzhyv",
                    "$6$ppI1woUHyg23I9K2",
                    "$6$ppI1woUHyg23I9K2$bhzDcdY2tvRMvn1Vu769kuNS5aEEXBvc2fEU58WwuegEQesX/ezxM8Dz8Xs0"
                    "bop5PbRHaKVckZIxJG4qny1FV0"
                },
                {
                    "djsuyibyebmwsiqyoygyxymzevypzvjegebeocfuftsxdixtigsieehkchzdflilrjqfnxztqrsvbs"
                    "pkyhsenbppkqtpddbuotbbqcwivrfxjujjddntgeiqvdgaijvwcyaubwewpjvygehljxepbpiwuqzdzubdubzv"
                    "afspqpqwuzifwovyddwyvvburczmgyjgfdxvtnunneslsplwuiupfxlzbknhkwppanltcfirjcddsozoyvegur"
                    "fwcsfmoxeqmrjowrghwlkobmeahkgccnaehhsveymqpxhlrnunyfdzrhbasjeuygafoubutpnimuwfjqsjxvkq"
                    "dorxxvrwctdsneogvbpkxlpgdirbfcriqifpgynkrrefxsnvucftpwctgtwmxnupycfgcuqunublmoiitnckle"
                    "fszbexrampetvhqnddjeqvuygpnkazqfrpjvoaxdpcwmjobmskskfojnewxgxnnofwltwjwnnvbwjckdmeouuzhyv",
                    "$5$2hqUE55jLCo45U8M",
                    "$5$2hqUE55jLCo45U8M$/wilsoQxECpxETaR1o08JCvbeW4MwM.Uxgtf8H97JBD"
                }
        };

static void test_crypt()
{
  for (size_t i = 0; i < ARRAY_SIZE (testcases); i++)
  {
    char *res = crypt(testcases[i].phrase, testcases[i].settings);
    if (strlen(res)!=strlen(testcases[i].except) || memcmp(res, testcases[i].except, strlen(res))!=0) {
      printf("FAIL: got: %s\n exp: %s\n", res, testcases[i].except);
      exit(1);
    } else {
      printf("PASS: test %s\n", testcases[i].except);
    }
  }

}



TEST(xcrypt_basic_ut, xcrypt_basic_testcases)
{
    test_crypt();
}
