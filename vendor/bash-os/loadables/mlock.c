/* SPDX-License-Identifier: MIT */
/* mlock.c — pin/unpin sensitive memory. Loadable for bash.
 *
 * Bash variables holding passwords or other secrets live in the
 * shell's heap until reused. Even after `unset`, the bytes can
 * persist in freed allocations. If the process is swapped out
 * (Linux memory pressure or sleep+suspend), the secrets land on
 * disk in plaintext.
 *
 * mlock(MCL_CURRENT|MCL_FUTURE) prevents the kernel from swapping
 * the process's pages. Pair with `unset` for memory hygiene.
 *
 * Subcommands:
 *
 *   mlock all
 *       mlockall(MCL_CURRENT|MCL_FUTURE) — pin all current pages
 *       and any pages allocated in the future. The right call for
 *       a wrapping a script that processes secrets.
 *
 *   mlock unlock
 *       munlockall — release everything.
 *
 *   mlock check
 *       Print the process's RLIMIT_MEMLOCK (soft+hard) so operators
 *       can see what's available before they try.
 *
 *   mlock try-lock SIZE
 *       Best-effort mlock of a SIZE-byte anonymous mapping, then
 *       munlock and munmap. SIZE is in bytes (decimal); the loadable
 *       caps it at 1 MiB to keep the probe bounded. Lets operators
 *       and tests audit the rlimit-downgrade path (EAGAIN under a
 *       reduced RLIMIT_MEMLOCK) without committing to mlockall.
 *
 * Limitations:
 *   - Won't help against ptrace; an attacker with the same uid +
 *     PTRACE_ATTACH can read locked memory.
 *   - Failure modes: EAGAIN (rlimit too small), EPERM (non-root
 *     under default rlimit), ENOMEM (system pressure). All
 *     reported via builtin_error; non-fatal.
 *
 * See research/bash_linux/SECURITY-REVIEW.md §3.1.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/resource.h>

#include "loadables.h"

static void
bm_print_rlimit_value (char *buf, size_t bufsz, rlim_t v)
{
  if (v == RLIM_INFINITY)
    snprintf (buf, bufsz, "unlimited");
  else
    snprintf (buf, bufsz, "%llu", (unsigned long long) v);
}

static int
bm_check_rlimit_for (size_t needed)
{
  struct rlimit r;
  char soft[64], hard[64];
  if (getrlimit (RLIMIT_MEMLOCK, &r) < 0)
    {
      builtin_error ("getrlimit MEMLOCK: %s", strerror (errno));
      return -1;
    }
  if (r.rlim_cur == RLIM_INFINITY || r.rlim_cur >= (rlim_t) needed)
    return 0;
  bm_print_rlimit_value (soft, sizeof soft, r.rlim_cur);
  bm_print_rlimit_value (hard, sizeof hard, r.rlim_max);
  builtin_error ("rlimit: needed=%zu soft=%s hard=%s - set ulimit -l before continuing",
                 needed, soft, hard);
  errno = EAGAIN;
  return -1;
}

static size_t
bm_current_resident_bytes (void)
{
  FILE *f = fopen ("/proc/self/statm", "r");
  unsigned long total = 0, resident = 0;
  long page = sysconf (_SC_PAGESIZE);
  if (page <= 0)
    page = 4096;
  if (f)
    {
      if (fscanf (f, "%lu %lu", &total, &resident) != 2)
        resident = 0;
      fclose (f);
    }
  if (resident == 0)
    resident = total;
  if (resident == 0)
    resident = 1;
  return (size_t) resident * (size_t) page;
}

static int
bm_all_cmd (WORD_LIST *args)
{
  (void) args;
  if (bm_check_rlimit_for (bm_current_resident_bytes ()) < 0)
    return EXECUTION_FAILURE;
  if (mlockall (MCL_CURRENT | MCL_FUTURE) < 0)
    {
      builtin_error ("mlockall: %s", strerror (errno));
      /* Print the current limit on EAGAIN so operators can diagnose
         a setrlimit-downgrade or restrictive default. */
      if (errno == EAGAIN)
        {
          struct rlimit r;
          if (getrlimit (RLIMIT_MEMLOCK, &r) == 0)
            {
              if (r.rlim_cur == RLIM_INFINITY)
                builtin_error ("  current RLIMIT_MEMLOCK: unlimited");
              else
                builtin_error ("  current RLIMIT_MEMLOCK: soft=%llu hard=%llu",
                               (unsigned long long) r.rlim_cur,
                               (unsigned long long) r.rlim_max);
            }
        }
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

static int
bm_unlock_cmd (WORD_LIST *args)
{
  (void) args;
  if (munlockall () < 0)
    {
      builtin_error ("munlockall: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

static int
bm_check_cmd (WORD_LIST *args)
{
  (void) args;
  struct rlimit r;
  if (getrlimit (RLIMIT_MEMLOCK, &r) < 0)
    {
      builtin_error ("getrlimit MEMLOCK: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  /* RLIM_INFINITY is platform-dependent macro; print -1 then. */
  if (r.rlim_cur == RLIM_INFINITY)
    printf ("soft=unlimited ");
  else
    printf ("soft=%llu ", (unsigned long long) r.rlim_cur);
  if (r.rlim_max == RLIM_INFINITY)
    printf ("hard=unlimited\n");
  else
    printf ("hard=%llu\n", (unsigned long long) r.rlim_max);
  return EXECUTION_SUCCESS;
}

/* Best-effort mlock probe — mmap a small anonymous region, mlock it,
   munlock + munmap. Lets operators (and tests) audit the rlimit-downgrade
   path without committing to mlockall on the whole process. On EAGAIN we
   reuse the bm_all_cmd diagnostic so callers see the active soft+hard
   RLIMIT_MEMLOCK alongside the failure. SIZE is capped at 1 MiB to keep
   the probe bounded and to ensure unprivileged callers do not accidentally
   exhaust a generous default cap. */
#define BM_TRYLOCK_MAX ((size_t) (1u << 20))   /* 1 MiB */

static int
bm_try_lock_cmd (WORD_LIST *args)
{
  if (!args || !args->word || !args->word->word || !*args->word->word)
    {
      builtin_error ("try-lock: SIZE argument required (bytes, 1..%zu)",
                     BM_TRYLOCK_MAX);
      return EX_USAGE;
    }
  const char *s = args->word->word;
  /* strtoull tolerates a leading '-' and wraps the result modulo ULLONG_MAX,
     so without this guard 'try-lock -1' would report a confusing
     'SIZE out of range (got 18446744073709551615)' instead of the documented
     "must be a non-negative decimal integer" path. */
  if (*s == '-')
    {
      builtin_error ("try-lock: SIZE must be a non-negative decimal integer (got '%s')", s);
      return EX_USAGE;
    }
  errno = 0;
  char *end = NULL;
  unsigned long long v = strtoull (s, &end, 10);
  if (errno != 0 || !end || *end != '\0' || end == s)
    {
      builtin_error ("try-lock: SIZE must be a non-negative decimal integer (got '%s')", s);
      return EX_USAGE;
    }
  if (v == 0 || v > (unsigned long long) BM_TRYLOCK_MAX)
    {
      builtin_error ("try-lock: SIZE out of range (1..%zu, got %llu)",
                     BM_TRYLOCK_MAX, v);
      return EX_USAGE;
    }
  size_t size = (size_t) v;
  if (bm_check_rlimit_for (size) < 0)
    return EXECUTION_FAILURE;

  void *p = mmap (NULL, size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED)
    {
      builtin_error ("try-lock: mmap: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  if (mlock (p, size) < 0)
    {
      int saved = errno;
      builtin_error ("try-lock: mlock(%zu): %s", size, strerror (saved));
      if (saved == EAGAIN)
        {
          struct rlimit r;
          if (getrlimit (RLIMIT_MEMLOCK, &r) == 0)
            {
              if (r.rlim_cur == RLIM_INFINITY)
                builtin_error ("  current RLIMIT_MEMLOCK: unlimited");
              else
                builtin_error ("  current RLIMIT_MEMLOCK: soft=%llu hard=%llu",
                               (unsigned long long) r.rlim_cur,
                               (unsigned long long) r.rlim_max);
            }
        }
      munmap (p, size);
      return EXECUTION_FAILURE;
    }
  /* Success path: roundtrip cleanly. munlock failures are reported but
     do not block munmap; we want to release the mapping in any case. */
  if (munlock (p, size) < 0)
    builtin_error ("try-lock: munlock: %s", strerror (errno));
  munmap (p, size);
  printf ("try-lock ok size=%zu\n", size);
  return EXECUTION_SUCCESS;
}

/* Print the current kernel.yama.ptrace_scope level and a human-readable
   description. This lets operators and test suites audit the ptrace
   posture that determines whether same-uid peers can PTRACE_ATTACH and
   read mlocked secret buffers. */
static int
bm_ptrace_scope_cmd (WORD_LIST *args)
{
  (void) args;
  FILE *fp = fopen ("/proc/sys/kernel/yama/ptrace_scope", "r");
  if (!fp)
    {
      builtin_error ("ptrace-scope: open /proc/sys/kernel/yama/ptrace_scope: %s",
                     strerror (errno));
      return EXECUTION_FAILURE;
    }
  int level = -1;
  if (fscanf (fp, "%d", &level) != 1)
    {
      builtin_error ("ptrace-scope: failed to parse level");
      fclose (fp);
      return EXECUTION_FAILURE;
    }
  fclose (fp);

  const char *desc = "unknown";
  switch (level)
    {
    case 0:
      desc = "0 (classic — any process can ptrace any same-uid process)";
      break;
    case 1:
      desc = "1 (restricted — only descendants via PR_SET_PTRACER)";
      break;
    case 2:
      desc = "2 (admin-only — requires CAP_SYS_PTRACE)";
      break;
    case 3:
      desc = "3 (no-attach — no process may ptrace)";
      break;
    }
  printf ("ptrace_scope=%d  %s\n", level, desc);
  return EXECUTION_SUCCESS;
}

extern char *mlock_doc[];

int
mlock_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  if (strcmp (cmd, "--help") == 0 || strcmp (cmd, "-h") == 0) {
      char **d;
      for (d = mlock_doc; *d; d++) puts (*d);
      return EXECUTION_SUCCESS;
  }
  WORD_LIST *args = list->next;
  if (strcmp (cmd, "all")           == 0) return bm_all_cmd           (args);
  if (strcmp (cmd, "unlock")        == 0) return bm_unlock_cmd        (args);
  if (strcmp (cmd, "check")         == 0) return bm_check_cmd         (args);
  if (strcmp (cmd, "try-lock")      == 0) return bm_try_lock_cmd      (args);
  if (strcmp (cmd, "ptrace-scope")  == 0) return bm_ptrace_scope_cmd  (args);
  builtin_error ("unknown subcommand: %s (try all/unlock/check/try-lock/ptrace-scope)", cmd);
  return EX_USAGE;
}

char *mlock_doc[] = {
  "Pin/unpin process memory to prevent swap leakage of secrets.",
  "",
  "    mlock all           mlockall(MCL_CURRENT|MCL_FUTURE)",
  "    mlock unlock        munlockall",
  "    mlock check         print soft+hard RLIMIT_MEMLOCK",
  "    mlock try-lock SIZE bounded mlock/munlock probe (1..1 MiB)",
  "    mlock ptrace-scope  print kernel.yama.ptrace_scope level",
  "",
  "Wrap scripts that handle passwords / keys with `mlock all`",
  "at the start. Doesn't help against ptrace, but defends against",
  "secrets-in-swap leaks under memory pressure.",
  (char *)NULL
};

struct builtin mlock_struct = {
  "mlock",
  mlock_builtin,
  BUILTIN_ENABLED,
  mlock_doc,
  "mlock all|unlock|check|try-lock|ptrace-scope",
  0
};
