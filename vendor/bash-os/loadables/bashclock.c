/* bashclock.c — high-resolution time. Loadable for bash.
 *
 * Bash's built-in time access is whole-seconds (`printf '%(...)T' -1`
 * truncates to seconds, EPOCHSECONDS is integer, EPOCHREALTIME is
 * locale-dependent in formatting). No CLOCK_MONOTONIC access at all,
 * so benchmark harnesses can't get a clock that doesn't jump on
 * settimeofday or NTP step.
 *
 * bashclock exposes clock_gettime(2) directly. Output format is always
 * "<secs>.<nanos>" with a literal '.' regardless of locale, so it
 * composes cleanly with bash's other text processing and with fltexpr.
 *
 * Subcommands:
 *     bashclock now              CLOCK_REALTIME (wallclock)
 *     bashclock mono             CLOCK_MONOTONIC (steady, no NTP step)
 *     bashclock boot             CLOCK_BOOTTIME (mono + suspend time)
 *     bashclock since T0         elapsed seconds since prior `mono`
 *     bashclock sleep SECS       ns-precision sleep (clock_nanosleep)
 *
 * Examples:
 *     t0=$(bashclock mono)
 *     ./expensive-job
 *     elapsed=$(bashclock since "$t0")
 *     echo "took $elapsed seconds"
 *
 *     # Periodic loop with stable cadence (no drift):
 *     while bashclock sleep 0.5; do tick; done
 *
 * Companion docs:
 *     /docs/bash/bashclock.txt
 *
 * --- LICENSE ---
 * MIT License
 *
 * Copyright (c) 2026 bash_linux contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 *
 * Note: when compiled and statically linked into GNU Bash, the resulting
 * combined binary is a derivative work of bash and is governed by GPL-3+.
 * MIT for this source lets it be lifted into other projects.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "loadables.h"

/* Print a struct timespec as "<secs>.<nanos>" with 9-digit ns. Always
   uses '.' as the decimal separator regardless of locale. */
static void
bc_print_ts (struct timespec *ts)
{
  printf ("%lld.%09ld\n",
          (long long) ts->tv_sec,
          (long) ts->tv_nsec);
}

/* Read a "<secs>.<nanos>" string into a struct timespec. Returns 0 on
   success, -1 on parse failure. The fractional part is treated as
   nanoseconds when 9 digits, scaled when fewer. */
static int
bc_parse_ts (const char *s, struct timespec *out)
{
  long long secs = 0;
  long nanos = 0;
  const char *p = s;
  int neg = 0;
  if (*p == '-') { neg = 1; p++; }
  while (*p >= '0' && *p <= '9')
    { secs = secs * 10 + (*p - '0'); p++; }
  if (*p == '.')
    {
      p++;
      int digits = 0;
      while (*p >= '0' && *p <= '9' && digits < 9)
        { nanos = nanos * 10 + (*p - '0'); p++; digits++; }
      /* Pad with zeros if fewer than 9 digits given. */
      while (digits < 9) { nanos *= 10; digits++; }
      /* Skip trailing digits past 9 (sub-ns ignored). */
      while (*p >= '0' && *p <= '9') p++;
    }
  if (*p != '\0' && *p != '\n') return -1;
  out->tv_sec = (time_t) (neg ? -secs : secs);
  out->tv_nsec = nanos;
  return 0;
}

static int
bc_get_clock (clockid_t clk)
{
  struct timespec ts;
  if (clock_gettime (clk, &ts) < 0)
    {
      builtin_error ("clock_gettime: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  bc_print_ts (&ts);
  return EXECUTION_SUCCESS;
}

static int
bc_since (WORD_LIST *args)
{
  if (!args)
    { builtin_error ("since: needs T0"); return EX_USAGE; }
  struct timespec t0, t1;
  if (bc_parse_ts (args->word->word, &t0) < 0)
    { builtin_error ("since: bad T0 format (want SECS.NANOS): %s", args->word->word); return EX_USAGE; }
  if (clock_gettime (CLOCK_MONOTONIC, &t1) < 0)
    { builtin_error ("clock_gettime: %s", strerror (errno)); return EXECUTION_FAILURE; }

  /* Compute t1 - t0, normalize the borrow. */
  long long ds = (long long) t1.tv_sec - (long long) t0.tv_sec;
  long dn = t1.tv_nsec - t0.tv_nsec;
  if (dn < 0) { dn += 1000000000L; ds -= 1; }
  printf ("%lld.%09ld\n", ds, dn);
  return EXECUTION_SUCCESS;
}

static int
bc_sleep (WORD_LIST *args)
{
  if (!args)
    { builtin_error ("sleep: needs SECS"); return EX_USAGE; }
  struct timespec req;
  if (bc_parse_ts (args->word->word, &req) < 0)
    { builtin_error ("sleep: bad SECS format: %s", args->word->word); return EX_USAGE; }
  /* Honor SIGINT / Ctrl-C — don't loop EINTR away. */
  if (clock_nanosleep (CLOCK_MONOTONIC, 0, &req, NULL) != 0)
    {
      if (errno == EINTR) return EXECUTION_FAILURE;
      builtin_error ("clock_nanosleep: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

int
bashclock_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;

  if (strcmp (cmd, "now")   == 0) {
    if (args) { builtin_error ("now: unexpected arg: %s", args->word->word); return EX_USAGE; }
    return bc_get_clock (CLOCK_REALTIME);
  }
  if (strcmp (cmd, "mono")  == 0) {
    if (args) { builtin_error ("mono: unexpected arg: %s", args->word->word); return EX_USAGE; }
    return bc_get_clock (CLOCK_MONOTONIC);
  }
  if (strcmp (cmd, "boot")  == 0) {
    if (args) { builtin_error ("boot: unexpected arg: %s", args->word->word); return EX_USAGE; }
    return bc_get_clock (CLOCK_BOOTTIME);
  }
  if (strcmp (cmd, "since") == 0) return bc_since (args);
  if (strcmp (cmd, "sleep") == 0) return bc_sleep (args);

  builtin_error ("unknown subcommand: %s (try now/mono/boot/since/sleep)", cmd);
  builtin_usage ();
  return EX_USAGE;
}

char *bashclock_doc[] = {
  "High-resolution time access via clock_gettime(2).",
  "",
  "    bashclock now           CLOCK_REALTIME wallclock seconds.nanos",
  "    bashclock mono          CLOCK_MONOTONIC (steady; no NTP step)",
  "    bashclock boot          CLOCK_BOOTTIME (mono + time spent suspended)",
  "    bashclock since T0      elapsed seconds since a prior `mono` reading",
  "    bashclock sleep SECS    ns-precision sleep (clock_nanosleep)",
  "",
  "Output is always SECS.NANOS with literal '.' (locale-independent).",
  "Use with fltexpr to compose with floats; with `bench.sh` for timing.",
  (char *)NULL
};

struct builtin bashclock_struct = {
  "bashclock",
  bashclock_builtin,
  BUILTIN_ENABLED,
  bashclock_doc,
  "bashclock now|mono|boot|since T0|sleep SECS",
  0
};
