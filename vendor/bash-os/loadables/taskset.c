/* SPDX-License-Identifier: MIT */
/* taskset.c — taskset(1) subset over sched_{get,set}affinity(2).
 *
 *   taskset [-c] -p PID
 *   taskset [-c] -p MASK|LIST PID
 *   taskset [-c] MASK|LIST COMMAND [ARG...]
 *   taskset --help | --version
 *
 * v1 covers the CPU-mask and CPU-list forms used by init/service smoke
 * tests and fork-exec callers.
 *
 * Source counterpart:
 *   research/refs/util-linux/schedutils/taskset.c
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "loadables.h"

static int
bts_parse_pid (const char *s, pid_t *out)
{
  char *end = NULL;
  long v;
  if (!s || !*s) return -1;
  errno = 0;
  v = strtol (s, &end, 10);
  if (errno || !end || *end != '\0' || v < 0)
    return -1;
  *out = (pid_t) v;
  return 0;
}

static int
bts_parse_mask (const char *s, cpu_set_t *set)
{
  const char *p = s;
  int bit = 0;
  if (!s || !*s) return -1;
  if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
  if (!*p) return -1;
  for (const char *q = p; *q; q++)
    if (!isxdigit ((unsigned char) *q))
      return -1;

  CPU_ZERO (set);
  for (const char *q = p + strlen (p); q > p; )
    {
      unsigned char c = (unsigned char) *--q;
      int v = (c >= '0' && c <= '9') ? c - '0'
              : (c >= 'a' && c <= 'f') ? c - 'a' + 10
              : c - 'A' + 10;
      for (int n = 0; n < 4; n++, bit++)
        {
          if (bit >= CPU_SETSIZE)
            {
              if (v & (1 << n)) return -1;
              continue;
            }
          if (v & (1 << n))
            CPU_SET (bit, set);
        }
    }
  return 0;
}

static int
bts_parse_cpu_list (const char *s, cpu_set_t *set)
{
  const char *p = s;
  if (!s || !*s) return -1;
  CPU_ZERO (set);
  while (*p)
    {
      char *end = NULL;
      errno = 0;
      long first = strtol (p, &end, 10);
      if (errno || end == p || first < 0 || first >= CPU_SETSIZE)
        return -1;
      long last = first;
      if (*end == '-')
        {
          p = end + 1;
          errno = 0;
          last = strtol (p, &end, 10);
          if (errno || end == p || last < first || last >= CPU_SETSIZE)
            return -1;
        }
      for (long cpu = first; cpu <= last; cpu++)
        CPU_SET ((int) cpu, set);
      if (*end == '\0') break;
      if (*end != ',') return -1;
      p = end + 1;
      if (!*p) return -1;
    }
  return 0;
}

static void
bts_format_mask (const cpu_set_t *set, char *buf, size_t bufsz)
{
  int high = 0;
  for (int cpu = 0; cpu < CPU_SETSIZE; cpu++)
    if (CPU_ISSET (cpu, set))
      high = cpu;

  int nibbles = high / 4 + 1;
  size_t off = 0;
  for (int nib = nibbles - 1; nib >= 0 && off + 1 < bufsz; nib--)
    {
      int v = 0;
      for (int bit = 0; bit < 4; bit++)
        {
          int cpu = nib * 4 + bit;
          if (cpu < CPU_SETSIZE && CPU_ISSET (cpu, set))
            v |= 1 << bit;
        }
      buf[off++] = (char) (v < 10 ? '0' + v : 'a' + v - 10);
    }
  if (off == 0 && bufsz > 1) buf[off++] = '0';
  buf[off < bufsz ? off : bufsz - 1] = '\0';
}

static void
bts_format_cpu_list (const cpu_set_t *set, char *buf, size_t bufsz)
{
  size_t off = 0;
  int first_item = 1;

  if (bufsz == 0) return;
  buf[0] = '\0';

  for (int cpu = 0; cpu < CPU_SETSIZE; cpu++)
    {
      if (!CPU_ISSET (cpu, set)) continue;
      int start = cpu;
      while (cpu + 1 < CPU_SETSIZE && CPU_ISSET (cpu + 1, set))
        cpu++;
      int end = cpu;

      int n;
      if (start == end)
        n = snprintf (buf + off, off < bufsz ? bufsz - off : 0,
                      "%s%d", first_item ? "" : ",", start);
      else
        n = snprintf (buf + off, off < bufsz ? bufsz - off : 0,
                      "%s%d-%d", first_item ? "" : ",", start, end);
      if (n < 0) break;
      if ((size_t) n >= (off < bufsz ? bufsz - off : 0))
        {
          buf[bufsz - 1] = '\0';
          return;
        }
      off += (size_t) n;
      first_item = 0;
    }

  if (first_item && bufsz > 1)
    {
      buf[0] = '0';
      buf[1] = '\0';
    }
}

static int
bts_get_affinity (pid_t pid, cpu_set_t *set)
{
  if (sched_getaffinity (pid, sizeof *set, set) < 0)
    {
      builtin_error ("sched_getaffinity %ld: %s", (long) pid, strerror (errno));
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

static int
bts_set_affinity (pid_t pid, const cpu_set_t *set)
{
  if (sched_setaffinity (pid, sizeof *set, set) < 0)
    {
      builtin_error ("sched_setaffinity %ld: %s", (long) pid, strerror (errno));
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

static int
bts_argv_from_list (WORD_LIST *list, char ***out)
{
  int argc = 0;
  char **argv;
  for (WORD_LIST *p = list; p; p = p->next) argc++;
  argv = calloc ((size_t) argc + 1, sizeof *argv);
  if (!argv)
    {
      builtin_error ("calloc: %s", strerror (errno));
      return -1;
    }
  int i = 0;
  for (WORD_LIST *p = list; p; p = p->next) argv[i++] = p->word->word;
  argv[argc] = NULL;
  *out = argv;
  return argc;
}

static int
bts_run_command (const cpu_set_t *set, WORD_LIST *cmd)
{
  char **argv = NULL;
  if (bts_argv_from_list (cmd, &argv) < 0)
    return EXECUTION_FAILURE;

  struct sigaction chld_dfl, chld_save;
  memset (&chld_dfl, 0, sizeof chld_dfl);
  chld_dfl.sa_handler = SIG_DFL;
  sigemptyset (&chld_dfl.sa_mask);
  sigaction (SIGCHLD, &chld_dfl, &chld_save);

  sigset_t chld_set, prev_mask;
  sigemptyset (&chld_set);
  sigaddset (&chld_set, SIGCHLD);
  sigprocmask (SIG_BLOCK, &chld_set, &prev_mask);

  pid_t pid = fork ();
  if (pid < 0)
    {
      int e = errno;
      sigprocmask (SIG_SETMASK, &prev_mask, NULL);
      sigaction (SIGCHLD, &chld_save, NULL);
      free (argv);
      builtin_error ("fork: %s", strerror (e));
      return EXECUTION_FAILURE;
    }
  if (pid == 0)
    {
      sigprocmask (SIG_SETMASK, &prev_mask, NULL);
      if (sched_setaffinity (0, sizeof *set, set) < 0)
        {
          fprintf (stderr, "taskset: sched_setaffinity: %s\n", strerror (errno));
          _exit (125);
        }
      execvp (argv[0], argv);
      int err = errno;
      fprintf (stderr, "taskset: %s: %s\n", argv[0], strerror (err));
      _exit (err == ENOENT ? 127 : 126);
    }
  free (argv);

  int status = 0;
  pid_t w;
  while ((w = waitpid (pid, &status, 0)) < 0 && errno == EINTR) ;
  sigprocmask (SIG_SETMASK, &prev_mask, NULL);
  sigaction (SIGCHLD, &chld_save, NULL);
  if (w < 0)
    {
      builtin_error ("waitpid: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  if (WIFEXITED (status)) return WEXITSTATUS (status);
  if (WIFSIGNALED (status)) return 128 + WTERMSIG (status);
  return EXECUTION_FAILURE;
}

static void
bts_help (void)
{
  puts ("taskset — taskset(1) subset over sched_getaffinity/sched_setaffinity");
  puts ("usage: taskset [-c] -p PID");
  puts ("       taskset [-c] -p MASK|LIST PID");
  puts ("       taskset [-c] MASK|LIST COMMAND [ARG...]");
  puts ("       taskset --help | --version");
  puts ("");
  puts ("MASK is a hexadecimal CPU affinity mask, with optional 0x prefix.");
  puts ("-c/--cpu-list treats affinity values as CPU lists such as 0,2-3.");
}

int
taskset_builtin (WORD_LIST *list)
{
  if (!list)
    { bts_help (); return EX_USAGE; }

  const char *w = list->word->word;
  if (strcmp (w, "--help") == 0 || strcmp (w, "-h") == 0)
    { bts_help (); return EXECUTION_SUCCESS; }
  if (strcmp (w, "--version") == 0)
    { puts ("taskset 0.1"); return EXECUTION_SUCCESS; }

  int cpu_list = 0;
  if (strcmp (w, "-c") == 0 || strcmp (w, "--cpu-list") == 0)
    {
      cpu_list = 1;
      list = list->next;
      if (!list)
        { builtin_error ("missing argument after %s", w); return EX_USAGE; }
      w = list->word->word;
    }
  else if (strncmp (w, "--cpu-list=", 11) == 0)
    {
      cpu_list = 1;
      w += 11;
      if (!*w)
        { builtin_error ("--cpu-list needs LIST"); return EX_USAGE; }
    }
  else if (strncmp (w, "-c", 2) == 0 && w[2])
    {
      cpu_list = 1;
      w += 2;
    }

  if (strcmp (w, "-p") == 0)
    {
      int argc = 0;
      for (WORD_LIST *p = list->next; p; p = p->next) argc++;
      if (argc != 1 && argc != 2)
        { builtin_error ("usage: taskset -p [MASK] PID"); return EX_USAGE; }

      pid_t pid;
      const char *pid_s = argc == 1 ? list->next->word->word
                                    : list->next->next->word->word;
      if (bts_parse_pid (pid_s, &pid) < 0)
        { builtin_error ("invalid pid: %s", pid_s); return EX_USAGE; }

      cpu_set_t oldset;
      if (bts_get_affinity (pid, &oldset) != EXECUTION_SUCCESS)
        return EXECUTION_FAILURE;
      char oldbuf[CPU_SETSIZE * 6 + 2];
      if (cpu_list)
        {
          bts_format_cpu_list (&oldset, oldbuf, sizeof oldbuf);
          printf ("pid %ld's current affinity list: %s\n", (long) pid, oldbuf);
        }
      else
        {
          bts_format_mask (&oldset, oldbuf, sizeof oldbuf);
          printf ("pid %ld's current affinity mask: %s\n", (long) pid, oldbuf);
        }

      if (argc == 2)
        {
          cpu_set_t newset;
          if ((cpu_list ? bts_parse_cpu_list : bts_parse_mask) (list->next->word->word, &newset) < 0)
            { builtin_error ("invalid %s: %s", cpu_list ? "cpu list" : "mask", list->next->word->word); return EX_USAGE; }
          if (bts_set_affinity (pid, &newset) != EXECUTION_SUCCESS)
            return EXECUTION_FAILURE;
          char newbuf[CPU_SETSIZE * 6 + 2];
          if (cpu_list)
            {
              bts_format_cpu_list (&newset, newbuf, sizeof newbuf);
              printf ("pid %ld's new affinity list: %s\n", (long) pid, newbuf);
            }
          else
            {
              bts_format_mask (&newset, newbuf, sizeof newbuf);
              printf ("pid %ld's new affinity mask: %s\n", (long) pid, newbuf);
            }
        }
      return EXECUTION_SUCCESS;
    }

  if (!list->next)
    { builtin_error ("missing command for mask %s", w); return EX_USAGE; }

  cpu_set_t set;
  if ((cpu_list ? bts_parse_cpu_list : bts_parse_mask) (w, &set) < 0)
    { builtin_error ("invalid %s: %s", cpu_list ? "cpu list" : "mask", w); return EX_USAGE; }
  return bts_run_command (&set, list->next);
}

char *taskset_doc[] = {
  "Run or query commands with a CPU affinity mask.",
  "",
  "    taskset [-c] -p PID",
  "    taskset [-c] -p MASK|LIST PID",
  "    taskset [-c] MASK|LIST COMMAND [ARG...]",
  "",
  "MASK is hexadecimal, with optional 0x prefix. With -c/--cpu-list,",
  "affinity values are CPU lists such as 0,2-3.",
  (char *) NULL
};

struct builtin taskset_struct = {
  "taskset",
  taskset_builtin,
  BUILTIN_ENABLED,
  taskset_doc,
  "taskset [-c] -p [MASK|LIST] PID | [-c] MASK|LIST COMMAND [ARG...]",
  0
};
