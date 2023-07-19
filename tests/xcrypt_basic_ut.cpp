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

#define PGM "crypt"
#include "testutils.h"

#define ARRAY_SIZE(a_)  (sizeof (a_) / sizeof ((a_)[0]))

/* The behavior tested below should be consistent for all hashing
   methods.  */
static const char *settings[] =
{
#if INCLUDE_descrypt || INCLUDE_bigcrypt
  "Mp",
#endif
#if INCLUDE_bsdicrypt
  "_J9..MJHn",
#endif
#if INCLUDE_md5crypt
  "$1$MJHnaAke",
#endif
#if INCLUDE_nt
  "$3$",
#endif
#if INCLUDE_sunmd5
  /* exercise all paths of the bug-compatibility logic */
  "$md5,rounds=55349$BPm.fm03$",
  "$md5,rounds=55349$BPm.fm03$x",
  "$md5,rounds=55349$BPm.fm03$$",
  "$md5,rounds=55349$BPm.fm03$$x",
  "$md5$BPm.fm03$",
  "$md5$BPm.fm03$x",
  "$md5$BPm.fm03$$",
  "$md5$BPm.fm03$$x",
#endif
#if INCLUDE_sha1crypt
  "$sha1$248488$ggu.H673kaZ5$",
#endif
#if INCLUDE_sha256crypt
  "$5$MJHnaAkegEVYHsFK",
  "$5$rounds=10191$MJHnaAkegEVYHsFK",
#endif
#if INCLUDE_sha512crypt
  "$6$MJHnaAkegEVYHsFK",
  "$6$rounds=10191$MJHnaAkegEVYHsFK",
#endif
#if INCLUDE_bcrypt_a
  "$2a$05$UBVLHeMpJ/QQCv3XqJx8zO",
#endif
#if INCLUDE_bcrypt
  "$2b$05$UBVLHeMpJ/QQCv3XqJx8zO",
#endif
#if INCLUDE_bcrypt_x
  "$2x$05$UBVLHeMpJ/QQCv3XqJx8zO",
#endif
#if INCLUDE_bcrypt_y
  "$2y$05$UBVLHeMpJ/QQCv3XqJx8zO",
#endif
#if INCLUDE_yescrypt
  "$y$j9T$MJHnaAkegEVYHsFKkmfzJ1",
#endif
#if INCLUDE_scrypt
  "$7$CU..../....MJHnaAkegEVYHsFKkmfzJ1",
#endif
#if INCLUDE_gost_yescrypt
  "$gy$j9T$MJHnaAkegEVYHsFKkmfzJ1",
#endif
};

/* In some of the tests below, a segmentation fault is the expected result.  */
static sigjmp_buf env;
static void
segv_handler(int sig)
{
    siglongjmp (env, sig);
}

static bool error_occurred;

#ifndef XCRYPT_USE_ASAN /* see comments in do_tests */
static void
expect_no_fault(const char *tag,
                 const char *phrase, const char *setting, const char *expect,
                 void (*testfn) (const char *, const char *,
                                 const char *, const char *))
{
  int rv = sigsetjmp (env, 1);
  if (!rv)
    testfn (tag, phrase, setting, expect);
  else
    {
      printf ("FAIL: %s: Unexpected %s\n", tag, strsignal (rv));
      error_occurred = 1;
    }
}
#endif

static void
expect_a_fault(const char *tag,
                const char *phrase, const char *setting, const char *expect,
                void (*testfn) (const char *, const char *,
                                const char *, const char *))
{
  int rv = sigsetjmp (env, 1);
  if (!rv)
    {
      testfn (tag, phrase, setting, expect);
      printf ("ERROR: %s: No signal occurred\n", tag);
      error_occurred = true;
    }
}

static void
check(const char *tag, const char *expect, const char *got)
{
  int err = errno;
  if ((got == 0 && expect != 0)
      || (got != 0 && expect == 0)
      || (got != 0 && expect != 0 && strcmp(got, expect) != 0))
    {
      printf ("FAIL: %s: exp '%s' got '%s'\n",
              tag, expect ? expect : "(nil)",
              got ? got : "(nil)");
      error_occurred = true;
    }
  if ((expect == 0 || expect[0] == '*') && err != EINVAL)
    {
      printf ("FAIL: %s: exp '%s' got '%s'\n",
              tag, strerror (EINVAL), strerror (err));
      error_occurred = true;
    }
}

static void
test_crypt(const char *tag,
            const char *phrase, const char *setting, const char *expect)
{
  char *got = crypt (phrase, setting);
  check (tag, expect, got);
}

static void
test_crypt_r(const char *tag,
              const char *phrase, const char *setting, const char *expect)
{
  struct crypt_data data;
  memset (&data, 0, sizeof data);
  char *got = crypt_r (phrase, setting, &data);
  check (tag, expect, got);
}

static void
test_crypt_rn(const char *tag,
               const char *phrase, const char *setting, const char *expect)
{
  struct crypt_data data;
  memset (&data, 0, sizeof data);

  char *got = crypt_rn (phrase, setting, &data, (int) sizeof data);
  check (tag, expect, got);
}

static void
test_crypt_ra(const char *tag,
               const char *phrase, const char *setting, const char *expect)
{
  /* cheat - crypt_ra doesn't actually care whether its scratch area
     is on the heap as long as it's big enough */
  struct crypt_data data;
  memset (&data, 0, sizeof data);
  void *datap = &data;
  int datas = (int) sizeof data;

  char *got = crypt_ra (phrase, setting, &datap, &datas);
  check (tag, expect, got);
}

#if ENABLE_FAILURE_TOKENS
# define FT0 "*0"
# define FT1 "*1"
#else
# define FT0 0
# define FT1 0
#endif

/* PAGE should point to PAGESIZE bytes of read-write memory followed
   by another PAGESIZE bytes of inaccessible memory.  */

static void
do_tests(char *page, size_t pagesize)
{
  static const char phrase[] =
    "the ritual question of how much is two plus two";

  /* This copy operation intentionally omits the NUL; 'p1' points to a
     sequence of nonzero bytes followed immediately by inaccessible
     memory.  */
  memcpy (page + pagesize - (sizeof phrase - 1), phrase, sizeof phrase - 1);
  const char *p1 = page + pagesize - (sizeof phrase - 1);
  const char *p2 = page + pagesize;
  size_t i;

  /* Our crypt*() functions return NULL / a failure token, with errno set
     to EINVAL, when either the setting or the phrase argument is NULL.
     ASan's interceptors for crypt*() instead crash the program when either
     argument is NULL -- this is arguably a better choice, but for
     compatibility's sake we can't change what our functions do.  There is
     no way to disable interception of specific functions as far as I can
     tell.  Therefore, these tests are skipped when compiled with ASan.  */
#ifndef XCRYPT_USE_ASAN
  /* When SETTING is null, it shouldn't matter what PHRASE is.  */
  expect_no_fault ("0.0.crypt",    0,  0, FT0, test_crypt);
  expect_no_fault ("0.0.crypt_r",  0,  0, FT0, test_crypt_r);
  expect_no_fault ("0.0.crypt_rn", 0,  0, 0,    test_crypt_rn);
  expect_no_fault ("0.0.crypt_ra", 0,  0, 0,    test_crypt_ra);

  expect_no_fault ("''.0.crypt",    "", 0, FT0, test_crypt);
  expect_no_fault ("''.0.crypt_r",  "", 0, FT0, test_crypt_r);
  expect_no_fault ("''.0.crypt_rn", "", 0, 0,    test_crypt_rn);
  expect_no_fault ("''.0.crypt_ra", "", 0, 0,    test_crypt_ra);

  expect_no_fault ("ph.0.crypt",    phrase, 0, FT0, test_crypt);
  expect_no_fault ("ph.0.crypt_r",  phrase, 0, FT0, test_crypt_r);
  expect_no_fault ("ph.0.crypt_rn", phrase, 0, 0,    test_crypt_rn);
  expect_no_fault ("ph.0.crypt_ra", phrase, 0, 0,    test_crypt_ra);

  expect_no_fault ("p1.0.crypt",    p1, 0, FT0, test_crypt);
  expect_no_fault ("p1.0.crypt_r",  p1, 0, FT0, test_crypt_r);
  expect_no_fault ("p1.0.crypt_rn", p1, 0, 0,    test_crypt_rn);
  expect_no_fault ("p1.0.crypt_ra", p1, 0, 0,    test_crypt_ra);

  expect_no_fault ("p2.0.crypt",    p2, 0, FT0, test_crypt);
  expect_no_fault ("p2.0.crypt_r",  p2, 0, FT0, test_crypt_r);
  expect_no_fault ("p2.0.crypt_rn", p2, 0, 0,    test_crypt_rn);
  expect_no_fault ("p2.0.crypt_ra", p2, 0, 0,    test_crypt_ra);

  /* Conversely, when PHRASE is null,
     it shouldn't matter what SETTING is...  */
  expect_no_fault ("0.''.crypt",    0, "", FT0,  test_crypt);
  expect_no_fault ("0.''.crypt_r",  0, "", FT0,  test_crypt_r);
  expect_no_fault ("0.''.crypt_rn", 0, "", 0,    test_crypt_rn);
  expect_no_fault ("0.''.crypt_ra", 0, "", 0,    test_crypt_ra);

  expect_no_fault ("0.'*'.crypt",    0, "*", FT0,  test_crypt);
  expect_no_fault ("0.'*'.crypt_r",  0, "*", FT0,  test_crypt_r);
  expect_no_fault ("0.'*'.crypt_rn", 0, "*", 0,    test_crypt_rn);
  expect_no_fault ("0.'*'.crypt_ra", 0, "*", 0,    test_crypt_ra);

  expect_no_fault ("0.'*0'.crypt",    0, "*0", FT1,  test_crypt);
  expect_no_fault ("0.'*0'.crypt_r",  0, "*0", FT1,  test_crypt_r);
  expect_no_fault ("0.'*0'.crypt_rn", 0, "*0", 0,    test_crypt_rn);
  expect_no_fault ("0.'*0'.crypt_ra", 0, "*0", 0,    test_crypt_ra);

  expect_no_fault ("0.'*1'.crypt",    0, "*1", FT0,  test_crypt);
  expect_no_fault ("0.'*1'.crypt_r",  0, "*1", FT0,  test_crypt_r);
  expect_no_fault ("0.'*1'.crypt_rn", 0, "*1", 0,    test_crypt_rn);
  expect_no_fault ("0.'*1'.crypt_ra", 0, "*1", 0,    test_crypt_ra);

  expect_no_fault ("0.p1.crypt",    0, p1, FT0,  test_crypt);
  expect_no_fault ("0.p1.crypt_r",  0, p1, FT0,  test_crypt_r);
  expect_no_fault ("0.p1.crypt_rn", 0, p1, 0,    test_crypt_rn);
  expect_no_fault ("0.p1.crypt_ra", 0, p1, 0,    test_crypt_ra);

  /* ... except for the case where SETTING is nonnull but there are
     fewer than 2 readable characters at SETTING, in which case we'll
     crash before we get to the null check in do_crypt.  This is a
     bug, but it's impractical to fix without breaking the property
     that 'crypt' _never_ creates a failure token that is equal to the
     setting string, which is more important than this corner case.  */
  expect_a_fault ("0.p2.crypt",    0, p2, FT0,  test_crypt);
  expect_a_fault ("0.p2.crypt_r",  0, p2, FT0,  test_crypt_r);
  expect_a_fault ("0.p2.crypt_rn", 0, p2, 0,    test_crypt_rn);
  expect_a_fault ("0.p2.crypt_ra", 0, p2, 0,    test_crypt_ra);
#endif /* no ASan */

  /* When SETTING is valid, passing an invalid string as PHRASE should
     crash reliably.  */
  for (i = 0; i < ARRAY_SIZE (settings); i++)
    {
      snprintf (page, pagesize, "p1.'%s'.crypt", settings[i]);
      expect_a_fault (page, p1, settings[i], FT0,  test_crypt);

      snprintf (page, pagesize, "p1.'%s'.crypt_r", settings[i]);
      expect_a_fault (page, p1, settings[i], FT0,  test_crypt_r);

      snprintf (page, pagesize, "p1.'%s'.crypt_rn", settings[i]);
      expect_a_fault (page, p1, settings[i], 0,    test_crypt_rn);

      snprintf (page, pagesize, "p1.'%s'.crypt_ra", settings[i]);
      expect_a_fault (page, p1, settings[i], 0,    test_crypt_ra);

      snprintf (page, pagesize, "p2.'%s'.crypt", settings[i]);
      expect_a_fault (page, p2, settings[i], FT0,  test_crypt);

      snprintf (page, pagesize, "p2.'%s'.crypt_r", settings[i]);
      expect_a_fault (page, p2, settings[i], FT0,  test_crypt_r);

      snprintf (page, pagesize, "p2.'%s'.crypt_rn", settings[i]);
      expect_a_fault (page, p2, settings[i], 0,    test_crypt_rn);

      snprintf (page, pagesize, "p2.'%s'.crypt_ra", settings[i]);
      expect_a_fault (page, p2, settings[i], 0,    test_crypt_ra);
    }

  /* Conversely, when PHRASE is valid, passing an invalid string as SETTING
     should crash reliably.  */
  expect_a_fault ("ph.p2.crypt",    phrase, p2, FT0,  test_crypt);
  expect_a_fault ("ph.p2.crypt_r",  phrase, p2, FT0,  test_crypt_r);
  expect_a_fault ("ph.p2.crypt_rn", phrase, p2, 0,    test_crypt_rn);
  expect_a_fault ("ph.p2.crypt_ra", phrase, p2, 0,    test_crypt_ra);

  for (i = 0; i < ARRAY_SIZE (settings); i++)
    {
      p1 = memcpy (page + pagesize - strlen (settings[i]),
                   settings[i], strlen (settings[i]));

      snprintf (page, pagesize, "ph.'%s'.crypt", settings[i]);
      expect_a_fault (page, phrase, p1, FT0, test_crypt);

      snprintf (page, pagesize, "ph.'%s'.crypt_r", settings[i]);
      expect_a_fault (page, phrase, p1, FT0, test_crypt_r);

      snprintf (page, pagesize, "ph.'%s'.crypt_rn", settings[i]);
      expect_a_fault (page, phrase, p1, 0,    test_crypt_rn);

      snprintf (page, pagesize, "ph.'%s'.crypt_ra", settings[i]);
      expect_a_fault (page, phrase, p1, 0,    test_crypt_ra);
    }
}

static void
test_basic_crypt()
{
  /* Set up a two-page region whose first page is read-write and
     whose second page is inaccessible.  */
  long pagesize_l = sysconf (_SC_PAGESIZE);
  if (pagesize_l < 256)
    {
      printf ("ERROR: pagesize of %ld is too small\n", pagesize_l);
    }

  size_t pagesize = (size_t) pagesize_l;
  char *page = mmap (0, pagesize * 2, PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANON, -1, 0);
  if (page == MAP_FAILED)
    {
      perror ("mmap");
    }
  memset (page, 'x', pagesize * 2);
  if (mprotect (page + pagesize, pagesize, PROT_NONE))
    {
      perror ("mprotect");
    }

  struct sigaction sa, os, ob;
  sigfillset (&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  sa.sa_handler = segv_handler;
  if (sigaction (SIGBUS, &sa, &ob) || sigaction (SIGSEGV, &sa, &os))
    {
      perror ("sigaction");
    }

  do_tests (page, pagesize);

  sigaction (SIGBUS, &ob, 0);
  sigaction (SIGSEGV, &os, 0);
}


static void
test_preferred_method()
{
  const char *pm = crypt_preferred_method();
  int retval = 0;

#if defined HASH_ALGORITHM_DEFAULT
  if (pm == NULL)
    {
      printf ("FAIL: crypt_preferred_method returned NULL.\n");
      retval = 1;
    }
  else
    {
      printf ("PASS: crypt_preferred_method returned \"%s\".\n", pm);

      char gs[CRYPT_GENSALT_OUTPUT_SIZE];
      struct crypt_data cd;

      crypt_gensalt_rn (NULL, 0, NULL, 0, gs, sizeof (gs));

      if (strncmp (gs, pm, strlen (pm)))
        {
          printf ("FAIL: crypt_preferred_method: \"%s\" ", pm);
          printf ("differs from default prefix.\n");
          printf ("crypt_gensalt returned: \"%s\".\n", gs);
          retval = 1;
        }
      else
        {
          printf ("PASS: crypt_preferred_method: \"%s\" ", pm);
          printf ("is the same as default prefix used by ");
          printf ("crypt_gensalt.\n");
        }

      crypt_gensalt_rn (pm, 0, NULL, 0, gs, sizeof (gs));

      if (gs[0] == '*')
        {
          printf ("FAIL: crypt_preferred_method: \"%s\" ", pm);
          printf ("is not a valid prefix for crypt_gensalt.\n");
          printf ("crypt_gensalt returned: \"%s\".\n", gs);
          retval = 1;
        }
      else
        {
          printf ("PASS: crypt_preferred_method: \"%s\" ", pm);
          printf ("is a valid prefix for crypt_gensalt.\n");
        }

      if (strncmp (gs, pm, strlen (pm)))
        {
          printf ("FAIL: crypt_preferred_method: \"%s\" ", pm);
          printf ("does not generate a setting for ");
          printf ("the intended method.\n");
          printf ("crypt_gensalt returned: \"%s\".\n", gs);
          retval = 1;
        }
      else
        {
          printf ("PASS: crypt_preferred_method: \"%s\" ", pm);
          printf ("does generate a setting for ");
          printf ("the intended method.\n");
        }

      crypt_r (PASSPHRASE, gs, &cd);

      if (cd.output[0] == '*')
        {
          printf ("FAIL: crypt_preferred_method: \"%s\" ", pm);
          printf ("is not a valid prefix for crypt.\n");
          printf ("crypt returned: \"%s\".\n", gs);
          retval = 1;
        }
      else
        {
          printf ("PASS: crypt_preferred_method: \"%s\" ", pm);
          printf ("is a valid prefix for crypt.\n");
        }

      if (strncmp (cd.output, pm, strlen (pm)))
        {
          printf ("FAIL: crypt_preferred_method: \"%s\" ", pm);
          printf ("does not generate a hash with ");
          printf ("the intended method.\n");
          printf ("crypt returned: \"%s\".\n", gs);
          retval = 1;
        }
      else
        {
          printf ("PASS: crypt_preferred_method: \"%s\" ", pm);
          printf ("does generate a hash with ");
          printf ("the intended method.\n");
        }
    }
#else
  if (pm != NULL)
    {
      printf ("FAIL: crypt_preferred_method returned: \"%s\" ", pm);
      printf ("instead of NULL.\n");
      retval = 1;
    }
  else
    {
      printf ("PASS: crypt_preferred_method returned NULL.");
    }
#endif
}



struct testcase
{
  const char *prefix;
  const int exp_prefix;
  const int exp_gensalt;
  const int exp_crypt;
};

static const struct testcase testcases[] =
{
#if INCLUDE_descrypt || INCLUDE_bigcrypt
  { "",      CRYPT_SALT_INVALID,       CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY },
  { "..",    CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY },
  { "MN",    CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY },
#else
  { "",      CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
  { "..",    CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
  { "MN",    CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_bsdicrypt
  { "_",     CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY },
#else
  { "_",     CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_md5crypt
  { "$1$",   CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY },
#else
  { "$1$",   CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_nt
  { "$3$",   CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY },
#else
  { "$3$",   CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_sunmd5
  { "$md5",  CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY },
#else
  { "$md5",  CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_sha1crypt
  { "$sha1", CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY },
#else
  { "$sha1", CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_sha256crypt
  { "$5$",   CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_METHOD_LEGACY },
#else
  { "$5$",   CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_sha512crypt
  { "$6$",   CRYPT_SALT_OK,            CRYPT_SALT_OK,            CRYPT_SALT_OK            },
#else
  { "$6$",   CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_bcrypt
  { "$2b$",  CRYPT_SALT_OK,            CRYPT_SALT_OK,            CRYPT_SALT_OK            },
#else
  { "$2b$",  CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_bcrypt_a
  { "$2a$",  CRYPT_SALT_OK,            CRYPT_SALT_OK,            CRYPT_SALT_OK            },
#else
  { "$2a$",  CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_bcrypt_x
  { "$2x$",  CRYPT_SALT_METHOD_LEGACY, CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#else
  { "$2x$",  CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_bcrypt_y
  { "$2y$",  CRYPT_SALT_OK,            CRYPT_SALT_OK,            CRYPT_SALT_OK            },
#else
  { "$2y$",  CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_yescrypt
  { "$y$",   CRYPT_SALT_OK,            CRYPT_SALT_OK,            CRYPT_SALT_OK            },
#else
  { "$y$",   CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_scrypt
  { "$7$",   CRYPT_SALT_OK,            CRYPT_SALT_OK,            CRYPT_SALT_OK            },
#else
  { "$7$",   CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif
#if INCLUDE_gost_yescrypt
  { "$gy$",  CRYPT_SALT_OK,            CRYPT_SALT_OK,            CRYPT_SALT_OK            },
#else
  { "$gy$",  CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID,       CRYPT_SALT_INVALID       },
#endif

  /* All of these are invalid. */
  { "$@",       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "%A",       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "A%",       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "$2$",      CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "*0",       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "*1",       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "  ",       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "!!",       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "**",       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "::",       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { ";;",       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "\\\\",     CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "\x01\x01", CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "\x19\x19", CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "\x20\x20", CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "\x7f\x7f", CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "\xfe\xfe", CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
  { "\xff\xff", CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
#if defined HASH_ALGORITHM_DEFAULT
  { NULL,       CRYPT_SALT_INVALID, CRYPT_SALT_OK,      CRYPT_SALT_OK      },
#else
  { NULL,       CRYPT_SALT_INVALID, CRYPT_SALT_INVALID, CRYPT_SALT_INVALID },
#endif
};

static void
test_crypt_checksalt()
{
  char gs_out[CRYPT_GENSALT_OUTPUT_SIZE] = "";
  const char *phr = "police saying freeze";
  struct crypt_data cd;
  const size_t gs_len = CRYPT_GENSALT_OUTPUT_SIZE;

  int status = 0;
  int retval = 0;

  for (size_t i = 0; i < ARRAY_SIZE (testcases); i++)
    {
      /* crypt_checksalt on prefix. */
      retval = crypt_checksalt (testcases[i].prefix);
      if (retval == testcases[i].exp_prefix)
        printf ("PASS (prefix): %s, result: %d\n",
                testcases[i].prefix, retval);
      else
        {
          status = 1;
          printf ("FAIL (prefix): %s, expected: %d, got: %d\n",
                  testcases[i].prefix,
                  testcases[i].exp_prefix, retval);
          continue;
        }

      /* crypt_checksalt on gensalt output. */
      crypt_gensalt_rn (testcases[i].prefix, 0, NULL, 0,
                        gs_out, (int) gs_len);
      retval = crypt_checksalt (gs_out);
      if (retval == testcases[i].exp_gensalt)
        printf ("PASS (gensalt): %s, result: %d\n",
                gs_out, retval);
      else
        {
          status = 1;
          printf ("FAIL (gensalt): %s, expected: %d, got: %d\n",
                  gs_out, testcases[i].exp_gensalt, retval);
          continue;
        }

      /* crypt_checksalt on crypt output. */
      crypt_r (phr, gs_out, &cd);
      retval = crypt_checksalt (cd.output);
      if (retval == testcases[i].exp_crypt)
        printf ("PASS (crypt): %s, result: %d\n",
                cd.output, retval);
      else
        {
          status = 1;
          printf ("FAIL (crypt): %s, expected: %d, got: %d\n",
                  cd.output, testcases[i].exp_crypt, retval);
        }

#if INCLUDE_descrypt && INCLUDE_bigcrypt

      /* Test bigcrypt as well. */
      if (testcases[i].prefix && strlen (testcases[i].prefix) == 2)
        {
          /* Prefix must be at least 14 bytes. */
          char bigcrypt_prefix[CRYPT_GENSALT_OUTPUT_SIZE];
          const char *pad = "............";
          memcpy (bigcrypt_prefix, testcases[i].prefix, 2);
          strncpy (bigcrypt_prefix + 2, pad, gs_len - 2);

          /* crypt_checksalt on prefix. */
          retval = crypt_checksalt (bigcrypt_prefix);
          if (retval == testcases[i].exp_prefix)
            printf ("PASS (prefix): %s, result: %d\n",
                    bigcrypt_prefix, retval);
          else
            {
              status = 1;
              printf ("FAIL (prefix): %s, expected: %d, got: %d\n",
                      bigcrypt_prefix,
                      testcases[i].exp_prefix, retval);
              continue;
            }

          /* crypt_checksalt on gensalt output. */
          crypt_gensalt_rn (bigcrypt_prefix, 0, NULL, 0,
                            gs_out, (int) gs_len);

          /* Add 12 trailing bytes. */
          strncpy (gs_out + 2, pad, gs_len - 2);

          retval = crypt_checksalt (gs_out);
          if (retval == testcases[i].exp_gensalt)
            printf ("PASS (gensalt): %s, result: %d\n",
                    gs_out, retval);
          else
            {
              status = 1;
              printf ("FAIL (gensalt): %s, expected: %d, got: %d\n",
                      gs_out, testcases[i].exp_gensalt, retval);
              continue;
            }

          /* crypt_checksalt on crypt output. */
          crypt_r (phr, gs_out, &cd);
          retval = crypt_checksalt (cd.output);
          if (retval == testcases[i].exp_crypt)
            printf ("PASS (crypt): %s, result: %d\n",
                    cd.output, retval);
          else
            {
              status = 1;
              printf ("FAIL (crypt): %s, expected: %d, got: %d\n",
                      cd.output, testcases[i].exp_crypt, retval);
            }
        }
#endif

    }
}



static const char *const entropy[] =
{
  "\x58\x35\xcd\x26\x03\xab\x2c\x14\x92\x13\x1e\x59\xb0\xbc\xfe\xd5",
  "\x9b\x35\xa2\x45\xeb\x68\x9e\x8f\xd9\xa9\x09\x71\xcc\x4d\x21\x44",
  "\x25\x13\xc5\x94\xc3\x93\x1d\xf4\xfd\xd4\x4f\xbd\x10\xe5\x28\x08",
  "\xa0\x2d\x35\x70\xa8\x0b\xc3\xad\xdf\x61\x69\xb3\x19\xda\x7e\x8d",
  0
};

#if INCLUDE_descrypt
static const char *const des_expected_output[] = { "Mp", "Pp", "ZH", "Uh"};
#endif
#if INCLUDE_bigcrypt && !INCLUDE_descrypt
static const char *const big_expected_output[] =
{
  "Mp............",
  "Pp............",
  "ZH............",
  "Uh............"
};
#endif
#if INCLUDE_bsdicrypt
static const char *const bsdi_expected_output[] =
{
  "_J9..MJHn",
  "_J9..PKXc",
  "_J9..ZAFl",
  "_J9..UqGB"
};
static const char *const bsdi_expected_output_r[] =
{
  "_/.2.MJHn",
  "_/.2.PKXc",
  "_/.2.ZAFl",
  "_/.2.UqGB"
};
static const char *const bsdi_expected_output_l[] =
{
  "_/...MJHn",
  "_/...PKXc",
  "_/...ZAFl",
  "_/...UqGB"
};
static const char *const bsdi_expected_output_h[] =
{
  "_zzzzMJHn",
  "_zzzzPKXc",
  "_zzzzZAFl",
  "_zzzzUqGB"
};
#endif
#if INCLUDE_md5crypt
static const char *const md5_expected_output[] =
{
  "$1$MJHnaAke",
  "$1$PKXc3hCO",
  "$1$ZAFlICwY",
  "$1$UqGBkVu0"
};
#endif
#if INCLUDE_sunmd5
static const char *const sunmd5_expected_output[] =
{
  "$md5,rounds=55349$BPm.fm03$",
  "$md5,rounds=72501$WKoucttX$",
  "$md5,rounds=42259$3HtkHq/x$",
  "$md5,rounds=73773$p.5e9AQf$",
};
static const char *const sunmd5_expected_output_l[] =
{
  "$md5,rounds=55349$BPm.fm03$",
  "$md5,rounds=72501$WKoucttX$",
  "$md5,rounds=42259$3HtkHq/x$",
  "$md5,rounds=73773$p.5e9AQf$",
};
static const char *const sunmd5_expected_output_h[] =
{
  "$md5,rounds=4294924340$BPm.fm03$",
  "$md5,rounds=4294941492$WKoucttX$",
  "$md5,rounds=4294911250$3HtkHq/x$",
  "$md5,rounds=4294942764$p.5e9AQf$",
};
#endif
#if INCLUDE_sha1crypt
static const char *const sha1_expected_output[] =
{
  "$sha1$248488$ggu.H673kaZ5$",
  "$sha1$248421$SWqudaxXA5L0$",
  "$sha1$257243$RAtkIrDxEovH$",
  "$sha1$250464$1j.eVxRfNAPO$",
};
static const char *const sha1_expected_output_l[] =
{
  "$sha1$4$ggu.H673kaZ5$",
  "$sha1$4$SWqudaxXA5L0$",
  "$sha1$4$RAtkIrDxEovH$",
  "$sha1$4$1j.eVxRfNAPO$",
};
static const char *const sha1_expected_output_h[] =
{
  "$sha1$3643984551$ggu.H673kaZ5$",
  "$sha1$4200450659$SWqudaxXA5L0$",
  "$sha1$3946507480$RAtkIrDxEovH$",
  "$sha1$3486175838$1j.eVxRfNAPO$",
};
#endif
#if INCLUDE_sha256crypt
static const char *const sha256_expected_output[] =
{
  "$5$MJHnaAkegEVYHsFK",
  "$5$PKXc3hCOSyMqdaEQ",
  "$5$ZAFlICwYRETzIzIj",
  "$5$UqGBkVu01rurVZqg"
};
static const char *const sha256_expected_output_r[] =
{
  "$5$rounds=10191$MJHnaAkegEVYHsFK",
  "$5$rounds=10191$PKXc3hCOSyMqdaEQ",
  "$5$rounds=10191$ZAFlICwYRETzIzIj",
  "$5$rounds=10191$UqGBkVu01rurVZqg"
};
static const char *const sha256_expected_output_l[] =
{
  "$5$rounds=1000$MJHnaAkegEVYHsFK",
  "$5$rounds=1000$PKXc3hCOSyMqdaEQ",
  "$5$rounds=1000$ZAFlICwYRETzIzIj",
  "$5$rounds=1000$UqGBkVu01rurVZqg"
};
static const char *const sha256_expected_output_h[] =
{
  "$5$rounds=999999999$MJHnaAkegEVYHsFK",
  "$5$rounds=999999999$PKXc3hCOSyMqdaEQ",
  "$5$rounds=999999999$ZAFlICwYRETzIzIj",
  "$5$rounds=999999999$UqGBkVu01rurVZqg"
};
#endif
#if INCLUDE_sha512crypt
static const char *const sha512_expected_output[] =
{
  "$6$MJHnaAkegEVYHsFK",
  "$6$PKXc3hCOSyMqdaEQ",
  "$6$ZAFlICwYRETzIzIj",
  "$6$UqGBkVu01rurVZqg"
};
static const char *const sha512_expected_output_r[] =
{
  "$6$rounds=10191$MJHnaAkegEVYHsFK",
  "$6$rounds=10191$PKXc3hCOSyMqdaEQ",
  "$6$rounds=10191$ZAFlICwYRETzIzIj",
  "$6$rounds=10191$UqGBkVu01rurVZqg"
};
static const char *const sha512_expected_output_l[] =
{
  "$6$rounds=1000$MJHnaAkegEVYHsFK",
  "$6$rounds=1000$PKXc3hCOSyMqdaEQ",
  "$6$rounds=1000$ZAFlICwYRETzIzIj",
  "$6$rounds=1000$UqGBkVu01rurVZqg"
};
static const char *const sha512_expected_output_h[] =
{
  "$6$rounds=999999999$MJHnaAkegEVYHsFK",
  "$6$rounds=999999999$PKXc3hCOSyMqdaEQ",
  "$6$rounds=999999999$ZAFlICwYRETzIzIj",
  "$6$rounds=999999999$UqGBkVu01rurVZqg"
};
#endif
#if INCLUDE_bcrypt
static const char *const bcrypt_b_expected_output[] =
{
  "$2b$05$UBVLHeMpJ/QQCv3XqJx8zO",
  "$2b$05$kxUgPcrmlm9XoOjvxCyfP.",
  "$2b$05$HPNDjKMRFdR7zC87CMSmA.",
  "$2b$05$mAyzaIeJu41dWUkxEbn8hO"
};
static const char *const bcrypt_b_expected_output_l[] =
{
  "$2b$04$UBVLHeMpJ/QQCv3XqJx8zO",
  "$2b$04$kxUgPcrmlm9XoOjvxCyfP.",
  "$2b$04$HPNDjKMRFdR7zC87CMSmA.",
  "$2b$04$mAyzaIeJu41dWUkxEbn8hO"
};
static const char *const bcrypt_b_expected_output_h[] =
{
  "$2b$31$UBVLHeMpJ/QQCv3XqJx8zO",
  "$2b$31$kxUgPcrmlm9XoOjvxCyfP.",
  "$2b$31$HPNDjKMRFdR7zC87CMSmA.",
  "$2b$31$mAyzaIeJu41dWUkxEbn8hO"
};
#endif
#if INCLUDE_bcrypt_a
static const char *const bcrypt_a_expected_output[] =
{
  "$2a$05$UBVLHeMpJ/QQCv3XqJx8zO",
  "$2a$05$kxUgPcrmlm9XoOjvxCyfP.",
  "$2a$05$HPNDjKMRFdR7zC87CMSmA.",
  "$2a$05$mAyzaIeJu41dWUkxEbn8hO"
};
#endif
#if INCLUDE_bcrypt_y
static const char *const bcrypt_y_expected_output[] =
{
  "$2y$05$UBVLHeMpJ/QQCv3XqJx8zO",
  "$2y$05$kxUgPcrmlm9XoOjvxCyfP.",
  "$2y$05$HPNDjKMRFdR7zC87CMSmA.",
  "$2y$05$mAyzaIeJu41dWUkxEbn8hO"
};
#endif
#if INCLUDE_yescrypt
static const char *yescrypt_expected_output[] =
{
  "$y$j9T$MJHnaAkegEVYHsFKkmfzJ1",
  "$y$j9T$PKXc3hCOSyMqdaEQArI62/",
  "$y$j9T$ZAFlICwYRETzIzIjEIC86.",
  "$y$j9T$UqGBkVu01rurVZqgNchTB0"
};
static const char *yescrypt_expected_output_l[] =
{
  "$y$j75$MJHnaAkegEVYHsFKkmfzJ1",
  "$y$j75$PKXc3hCOSyMqdaEQArI62/",
  "$y$j75$ZAFlICwYRETzIzIjEIC86.",
  "$y$j75$UqGBkVu01rurVZqgNchTB0"
};
static const char *yescrypt_expected_output_h[] =
{
  "$y$jFT$MJHnaAkegEVYHsFKkmfzJ1",
  "$y$jFT$PKXc3hCOSyMqdaEQArI62/",
  "$y$jFT$ZAFlICwYRETzIzIjEIC86.",
  "$y$jFT$UqGBkVu01rurVZqgNchTB0"
};
#endif
#if INCLUDE_scrypt
static const char *scrypt_expected_output[] =
{
  "$7$CU..../....MJHnaAkegEVYHsFKkmfzJ1",
  "$7$CU..../....PKXc3hCOSyMqdaEQArI62/",
  "$7$CU..../....ZAFlICwYRETzIzIjEIC86.",
  "$7$CU..../....UqGBkVu01rurVZqgNchTB0"
};
static const char *scrypt_expected_output_l[] =
{
  "$7$BU..../....MJHnaAkegEVYHsFKkmfzJ1",
  "$7$BU..../....PKXc3hCOSyMqdaEQArI62/",
  "$7$BU..../....ZAFlICwYRETzIzIjEIC86.",
  "$7$BU..../....UqGBkVu01rurVZqgNchTB0"
};
static const char *scrypt_expected_output_h[] =
{
  "$7$GU..../....MJHnaAkegEVYHsFKkmfzJ1",
  "$7$GU..../....PKXc3hCOSyMqdaEQArI62/",
  "$7$GU..../....ZAFlICwYRETzIzIjEIC86.",
  "$7$GU..../....UqGBkVu01rurVZqgNchTB0"
};
#endif
#if INCLUDE_gost_yescrypt
static const char *gost_yescrypt_expected_output[] =
{
  "$gy$j9T$MJHnaAkegEVYHsFKkmfzJ1",
  "$gy$j9T$PKXc3hCOSyMqdaEQArI62/",
  "$gy$j9T$ZAFlICwYRETzIzIjEIC86.",
  "$gy$j9T$UqGBkVu01rurVZqgNchTB0"
};
static const char *gost_yescrypt_expected_output_l[] =
{
  "$gy$j75$MJHnaAkegEVYHsFKkmfzJ1",
  "$gy$j75$PKXc3hCOSyMqdaEQArI62/",
  "$gy$j75$ZAFlICwYRETzIzIjEIC86.",
  "$gy$j75$UqGBkVu01rurVZqgNchTB0"
};
static const char *gost_yescrypt_expected_output_h[] =
{
  "$gy$jFT$MJHnaAkegEVYHsFKkmfzJ1",
  "$gy$jFT$PKXc3hCOSyMqdaEQArI62/",
  "$gy$jFT$ZAFlICwYRETzIzIjEIC86.",
  "$gy$jFT$UqGBkVu01rurVZqgNchTB0"
};
#endif

struct testcase1
{
  const char *prefix;
  const char *const *expected_output;
  unsigned int expected_len;
  unsigned int expected_auto_len;
  unsigned long rounds;
};

// For all hashing methods with a linear cost parameter (that is,
// DES/BSD, MD5/Sun, SHA1, SHA256, and SHA512), crypt_gensalt will
// accept any value in the range of 'unsigned long' and clip it to the
// actual valid range.
#define MIN_LINEAR_COST 1
#define MAX_LINEAR_COST ULONG_MAX

static const struct testcase1 testcase1s[] =
{
#if INCLUDE_descrypt
  { "",      des_expected_output,       2,  0, 0 },
  // DES doesn't have variable round count.
#endif
#if INCLUDE_bigcrypt && !INCLUDE_descrypt
  { "",      big_expected_output,       14,  0, 0 },
  // bigcrypt doesn't have variable round count.
#endif
#if INCLUDE_bsdicrypt
  { "_",     bsdi_expected_output,      9,  0, 0 },
  // BSDI/DES always emits a round count.
  // The _r expectation is used to verify that even inputs are
  // made odd, rather than rejected.
  { "_",     bsdi_expected_output_r,    9,  0, 16384 },
  { "_",     bsdi_expected_output_l,    9,  0, MIN_LINEAR_COST },
  { "_",     bsdi_expected_output_h,    9,  0, MAX_LINEAR_COST },
#endif
#if INCLUDE_md5crypt
  { "$1$",   md5_expected_output,      11,  0, 0 },
  // MD5/BSD doesn't have variable round count.
#endif
#if INCLUDE_sunmd5
  { "$md5",  sunmd5_expected_output,   27,  0, 0 },
  // MD5/Sun always emits a round count.
  { "$md5", sunmd5_expected_output_l,  27,  0, MIN_LINEAR_COST },
  { "$md5", sunmd5_expected_output_h,  32,  0, MAX_LINEAR_COST },
#endif
#if INCLUDE_sha1crypt
  { "$sha1", sha1_expected_output,     26, 34, 0 },
  // SHA1/PBKDF always emits a round count.
  { "$sha1", sha1_expected_output_l,   21, 29, MIN_LINEAR_COST },
  { "$sha1", sha1_expected_output_h,   30, 38, MAX_LINEAR_COST },
#endif
#if INCLUDE_sha256crypt
  { "$5$",   sha256_expected_output,   19,  0, 0 },
  { "$5$",   sha256_expected_output_r, 32,  0, 10191 },
  { "$5$",   sha256_expected_output_l, 31,  0, MIN_LINEAR_COST },
  { "$5$",   sha256_expected_output_h, 36,  0, MAX_LINEAR_COST },
#endif
#if INCLUDE_sha512crypt
  { "$6$",   sha512_expected_output,   19,  0, 0 },
  { "$6$",   sha512_expected_output_r, 32,  0, 10191 },
  { "$6$",   sha512_expected_output_l, 31,  0, MIN_LINEAR_COST },
  { "$6$",   sha512_expected_output_h, 36,  0, MAX_LINEAR_COST },
#endif
#if INCLUDE_bcrypt
  { "$2b$",  bcrypt_b_expected_output, 29,  0, 0 },
  // bcrypt always emits a cost parameter.
  // bcrypt's cost parameter is exponential, not linear, and
  // values outside the documented range are errors.
  { "$2b$",  bcrypt_b_expected_output_l, 29,  0, 4 },
  { "$2b$",  bcrypt_b_expected_output_h, 29,  0, 31 },
#endif
  // Salt generation for legacy bcrypt variants uses the same code as
  // the 'b' variant, so we don't bother testing them on non-default
  // rounds.
#if INCLUDE_bcrypt_a
  { "$2a$",  bcrypt_a_expected_output, 29,  0, 0 },
#endif
#if INCLUDE_bcrypt_y
  { "$2y$",  bcrypt_y_expected_output, 29,  0, 0 },
#endif
#if INCLUDE_yescrypt
  { "$y$",   yescrypt_expected_output,   29, 29,  0 },
  { "$y$",   yescrypt_expected_output_l, 29, 29,  1 },
  { "$y$",   yescrypt_expected_output_h, 29, 29, 11 },
#endif
#if INCLUDE_scrypt
  { "$7$",   scrypt_expected_output,   36, 36,  0 },
  { "$7$",   scrypt_expected_output_l, 36, 36,  6 },
  { "$7$",   scrypt_expected_output_h, 36, 36, 11 },
#endif
#if INCLUDE_gost_yescrypt
  { "$gy$",  gost_yescrypt_expected_output,   30, 30,  0 },
  { "$gy$",  gost_yescrypt_expected_output_l, 30, 30,  1 },
  { "$gy$",  gost_yescrypt_expected_output_h, 30, 30, 11 },
#endif
  { 0, 0, 0, 0, 0 }
};

/* The "best available" hashing method.  */
#if INCLUDE_yescrypt
# define EXPECTED_DEFAULT_PREFIX "$y$"
#elif INCLUDE_bcrypt
# define EXPECTED_DEFAULT_PREFIX "$2b$"
#elif INCLUDE_sha512crypt
# define EXPECTED_DEFAULT_PREFIX "$6$"
#endif

#ifndef IN_LIBCRYPT  /* Defined when building libxcrypt. */
# ifdef __REDIRECT_NTH
extern char * __REDIRECT_NTH (crypt_gensalt_r, (const char *__prefix,
                              unsigned long __count, const char *__rbytes,
                              int __nrbytes, char *__output,
                              int __output_size), crypt_gensalt_rn);
# else
#  define crypt_gensalt_r crypt_gensalt_rn
# endif
#endif

#define CRYPT_GENSALT_IMPLEMENTS_DEFAULT_PREFIX DEFAULT_PREFIX_ENABLED

#if CRYPT_GENSALT_IMPLEMENTS_DEFAULT_PREFIX
# ifndef EXPECTED_DEFAULT_PREFIX
#  error "Which hashing algorithm is the default?"
# endif
#else
# ifdef EXPECTED_DEFAULT_PREFIX
#  error "Default hashing algorithm should be available"
# endif
#endif

#define strcpy_or_abort _crypt_strcpy_or_abort
size_t strcpy_or_abort (void *dst, size_t d_size, const void *src);

static void
test_crypt_gensalt()
{
  int status = 0;
  unsigned int ent;
  const struct testcase1 *tcase;
  char output[CRYPT_GENSALT_OUTPUT_SIZE];
  char prev_output[CRYPT_GENSALT_OUTPUT_SIZE];

  for (tcase = testcase1s; tcase->prefix; tcase++)
    {
      memset (prev_output, 0, CRYPT_GENSALT_OUTPUT_SIZE);
      for (ent = 0; ent < ARRAY_SIZE (entropy); ent++)
        {
          memset (output, 0, CRYPT_GENSALT_OUTPUT_SIZE);
          char *salt = crypt_gensalt_rn (tcase->prefix, tcase->rounds,
                                         entropy[ent], 16,
                                         output, CRYPT_GENSALT_OUTPUT_SIZE);
          if (salt == 0)
            {
              if (entropy[ent] == 0 && errno == ENOSYS)
                {
                  fprintf (stderr,
                           "UNSUPPORTED: %s/%lu/auto-entropy -> ENOSYS\n",
                           tcase->prefix, tcase->rounds);
                }
              else
                {
                  fprintf (stderr, "ERROR: %s/%lu/%u -> 0\n",
                           tcase->prefix, tcase->rounds, ent);
                  status = 1;
                }
              continue;
            }
          size_t slen = strlen (salt);
          unsigned int expected_len =
            (!entropy[ent] && tcase->expected_auto_len) ?
            tcase->expected_auto_len : tcase->expected_len;
          if (slen != expected_len)
            {
              fprintf (stderr,
                       "ERROR: %s/%lu/%u -> %s (expected len=%u got %zu)\n",
                       tcase->prefix, tcase->rounds, ent, salt,
                       expected_len, slen);
              status = 1;
            }
          else if (strncmp (salt, tcase->prefix, strlen (tcase->prefix)))
            {
              fprintf (stderr, "ERROR: %s/%lu/%u -> %s (prefix wrong)\n",
                       tcase->prefix, tcase->rounds, ent, salt);
              status = 1;
            }
          else if (!strcmp (salt, prev_output))
            {
              fprintf (stderr, "ERROR: %s/%lu/%u -> %s (same as prev)\n",
                       tcase->prefix, tcase->rounds, ent, salt);
              status = 1;
            }
          else if (entropy[ent] &&  strcmp (salt, tcase->expected_output[ent]))
            {
              fprintf (stderr, "ERROR: %s/%lu/%u -> %s (expected %s)\n",
                       tcase->prefix, tcase->rounds, ent, salt,
                       tcase->expected_output[ent]);
              status = 1;
            }
          else
            fprintf (stderr, "   ok: %s/%lu/%u -> %s\n",
                     tcase->prefix, tcase->rounds, ent, salt);

          strcpy_or_abort (prev_output, CRYPT_GENSALT_OUTPUT_SIZE, salt);

          /* Test if crypt works with this salt. */
          if (!tcase->rounds)
            {
#define PASSW "alexander"
              static struct crypt_data a, b;
              if (!crypt_rn (PASSW, salt, &a, sizeof(a)))
                {
                  fprintf (stderr, "ERROR: %s/%u -> crypt(gensalt) fail\n",
                           tcase->prefix, ent);
                  status = 1;
                }
              else if (!crypt_rn (PASSW, a.output, &b, sizeof(b)))
                {
                  fprintf (stderr, "ERROR: %s/%u -> crypt(crypt(gensalt)) fail\n",
                           tcase->prefix, ent);
                  status = 1;
                }
              else if (strcmp (a.output, b.output))
                {
                  fprintf (stderr, "ERROR: %s/%u -> crypt(gensalt) != crypt(crypt(gensalt))\n",
                           tcase->prefix, ent);
                  status = 1;
                }
              else
                {
                  fprintf (stderr, "   ok: %s/%u -> crypt works with this salt\n",
                           tcase->prefix, ent);
                }
            }
        }
    }
#if CRYPT_GENSALT_IMPLEMENTS_DEFAULT_PREFIX
  /* Passing a null pointer as the prefix argument to crypt_gensalt is
     supposed to tell it to use the "best available" hashing method.  */
  {
    char *setting1, *setting2;
    setting1 = crypt_gensalt_ra (EXPECTED_DEFAULT_PREFIX, 0, entropy[0], 16);
    setting2 = crypt_gensalt_ra (0, 0, entropy[0], 16);
    if ((setting1 == 0 && setting2 != 0) ||
        (setting1 != 0 && setting2 == 0) ||
        (setting1 != 0 && setting2 != 0 && strcmp (setting1, setting2)))
      {
        printf ("FAILED: crypt_gensalt defaulting to $y$\n"
                "  $y$ -> %s\n"
                "  null -> %s\n",
                setting1, setting2);
        status = 1;
      }
    free (setting1);
    free (setting2);
  }
#else
  {
    char *setting = crypt_gensalt_ra (0, 0, entropy[0], 16);
    if (setting)
      {
        printf ("FAILED: crypt_gensalt null -> %s (null expected)\n", setting);
        status = 1;
      }
    free (setting);
  }
#endif
}



TEST(xcrypt_basic_ut, xcrypt_basic_testcases)
{ 
  test_basic_crypt();
  test_preferred_method();
  test_crypt_checksalt();
  test_crypt_gensalt();
}
