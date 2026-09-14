/* SPDX-License-Identifier: MIT */
/* chrt.c — chrt(1) subset over sched_get*/ /* sched_set* syscalls.
 *
 *   chrt -m
 *   chrt -p PID
 *   chrt [policy] PRIO COMMAND [ARG...]
 *   chrt [policy] --pid PRIO PID
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <limits.h>
#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "loadables.h"

#ifndef SCHED_BATCH
#  define SCHED_BATCH 3
#endif
#ifndef SCHED_IDLE
#  define SCHED_IDLE 5
#endif
#ifndef SCHED_DEADLINE
#  define SCHED_DEADLINE 6
#endif
#ifndef SCHED_RESET_ON_FORK
#  define SCHED_RESET_ON_FORK 0x40000000
#endif

struct bchrt_sched_attr {
  uint32_t size;
  uint32_t sched_policy;
  uint64_t sched_flags;
  int32_t sched_nice;
  uint32_t sched_priority;
  uint64_t sched_runtime;
  uint64_t sched_deadline;
  uint64_t sched_period;
};

static void
bchrt_usage_stderr (void)
{
  fprintf (stderr, "Try 'chrt --help' for more information.\n");
}

static void
bchrt_bad_usage (void)
{
  fprintf (stderr, "chrt: bad usage\n");
  bchrt_usage_stderr ();
}

static void
bchrt_help (void)
{
  puts ("Show or change the real-time scheduling attributes of a process.");
  puts ("");
  puts ("Set policy:");
  puts (" chrt [options] <priority> <command> [<arg>...]");
  puts (" chrt [options] --pid <priority> <pid>");
  puts ("");
  puts ("Get policy:");
  puts (" chrt [options] -p <pid>");
  puts ("");
  puts ("Policy options:");
  puts (" -b, --batch          set policy to SCHED_BATCH");
  puts (" -d, --deadline       set policy to SCHED_DEADLINE");
  puts (" -f, --fifo           set policy to SCHED_FIFO");
  puts (" -i, --idle           set policy to SCHED_IDLE");
  puts (" -o, --other          set policy to SCHED_OTHER");
  puts (" -r, --rr             set policy to SCHED_RR (default)");
  puts ("");
  puts ("Scheduling options:");
  puts (" -R, --reset-on-fork       set reset-on-fork flag");
  puts (" -T, --sched-runtime <ns>  runtime parameter for DEADLINE");
  puts (" -P, --sched-period <ns>   period parameter for DEADLINE");
  puts (" -D, --sched-deadline <ns> deadline parameter for DEADLINE");
  puts ("");
  puts ("Other options:");
  puts (" -a, --all-tasks      operate on all the tasks (threads) for a given pid");
  puts (" -m, --max            show min and max valid priorities");
  puts (" -p, --pid            operate on existing given pid");
  puts (" -v, --verbose        display status information");
  puts ("");
  puts (" -h, --help           display this help");
  puts (" -V, --version        display version");
  puts ("");
  puts ("For more details see chrt(1).");
}

static const char *
bchrt_policy_name (int policy)
{
  switch (policy & ~SCHED_RESET_ON_FORK)
    {
    case SCHED_OTHER: return "SCHED_OTHER";
    case SCHED_FIFO: return "SCHED_FIFO";
    case SCHED_RR: return "SCHED_RR";
    case SCHED_BATCH: return "SCHED_BATCH";
    case SCHED_IDLE: return "SCHED_IDLE";
    case SCHED_DEADLINE: return "SCHED_DEADLINE";
    default: return "SCHED_UNKNOWN";
    }
}

static int
bchrt_parse_long (const char *s, long min, long max, long *out)
{
  char *end = NULL;
  long v;
  if (!s || !*s) return -1;
  errno = 0;
  v = strtol (s, &end, 10);
  if (errno || !end || *end != '\0' || v < min || v > max)
    return -1;
  *out = v;
  return 0;
}

static int
bchrt_parse_u64 (const char *s, uint64_t *out)
{
  char *end = NULL;
  unsigned long long v;
  if (!s || !*s) return -1;
  errno = 0;
  v = strtoull (s, &end, 10);
  if (errno || !end || *end != '\0')
    return -1;
  *out = (uint64_t) v;
  return 0;
}

static int
bchrt_parse_pid (const char *s, pid_t *out)
{
  long v;
  if (bchrt_parse_long (s, 0, LONG_MAX, &v) < 0)
    return -1;
  *out = (pid_t) v;
  return 0;
}

static int
bchrt_sys_getscheduler (pid_t pid)
{
#ifdef SYS_sched_getscheduler
  return (int) syscall (SYS_sched_getscheduler, pid);
#else
  (void) pid;
  errno = ENOSYS;
  return -1;
#endif
}

static int
bchrt_sys_getparam (pid_t pid, struct sched_param *sp)
{
#ifdef SYS_sched_getparam
  return (int) syscall (SYS_sched_getparam, pid, sp);
#else
  (void) pid;
  (void) sp;
  errno = ENOSYS;
  return -1;
#endif
}

static int
bchrt_sys_setscheduler (pid_t pid, int policy, const struct sched_param *sp)
{
#ifdef SYS_sched_setscheduler
  return (int) syscall (SYS_sched_setscheduler, pid, policy, sp);
#else
  (void) pid;
  (void) policy;
  (void) sp;
  errno = ENOSYS;
  return -1;
#endif
}

static int
bchrt_get_attr (pid_t pid, struct bchrt_sched_attr *attr)
{
#ifdef SYS_sched_getattr
  memset (attr, 0, sizeof *attr);
  attr->size = sizeof *attr;
  return (int) syscall (SYS_sched_getattr, pid, attr, sizeof *attr, 0);
#else
  (void) pid;
  (void) attr;
  errno = ENOSYS;
  return -1;
#endif
}

static int
bchrt_set_attr (pid_t pid, const struct bchrt_sched_attr *attr)
{
#ifdef SYS_sched_setattr
  return (int) syscall (SYS_sched_setattr, pid, attr, 0);
#else
  (void) pid;
  (void) attr;
  errno = ENOSYS;
  return -1;
#endif
}

static int
bchrt_print_pid (pid_t pid)
{
  errno = 0;
  int policy = bchrt_sys_getscheduler (pid);
  if (policy < 0)
    {
      fprintf (stderr, "chrt: failed to get pid %ld's policy: %s\n",
               (long) pid, strerror (errno));
      return EXECUTION_FAILURE;
    }

  struct sched_param sp;
  memset (&sp, 0, sizeof sp);
  if (bchrt_sys_getparam (pid, &sp) < 0)
    {
      fprintf (stderr, "chrt: failed to get pid %ld's policy: %s\n",
               (long) pid, strerror (errno));
      return EXECUTION_FAILURE;
    }

  printf ("pid %ld's current scheduling policy: %s\n",
          (long) pid, bchrt_policy_name (policy));
  printf ("pid %ld's current scheduling priority: %d\n",
          (long) pid, sp.sched_priority);

  struct bchrt_sched_attr attr;
  if (bchrt_get_attr (pid, &attr) == 0)
    {
      if (attr.sched_runtime)
        printf ("pid %ld's current runtime parameter: %llu\n",
                (long) pid, (unsigned long long) attr.sched_runtime);
      if ((policy & ~SCHED_RESET_ON_FORK) == SCHED_DEADLINE)
        {
          printf ("pid %ld's current deadline parameter: %llu\n",
                  (long) pid, (unsigned long long) attr.sched_deadline);
          printf ("pid %ld's current period parameter: %llu\n",
                  (long) pid, (unsigned long long) attr.sched_period);
        }
    }
  return EXECUTION_SUCCESS;
}

static int
bchrt_print_max (void)
{
  int policies[] = { SCHED_OTHER, SCHED_FIFO, SCHED_RR, SCHED_BATCH,
                     SCHED_IDLE, SCHED_DEADLINE };
  for (size_t i = 0; i < sizeof policies / sizeof policies[0]; i++)
    {
      int minp = sched_get_priority_min (policies[i]);
      int maxp = sched_get_priority_max (policies[i]);
      if (minp < 0 || maxp < 0)
        minp = maxp = 0;
      printf ("%s min/max priority\t: %d/%d\n",
              bchrt_policy_name (policies[i]), minp, maxp);
    }
  return EXECUTION_SUCCESS;
}

static int
bchrt_set_pid (pid_t pid, int policy, int reset_on_fork, int prio,
               uint64_t runtime, uint64_t deadline, uint64_t period)
{
  int base = policy & ~SCHED_RESET_ON_FORK;
  if (reset_on_fork) policy |= SCHED_RESET_ON_FORK;

  if (base == SCHED_DEADLINE)
    {
      struct bchrt_sched_attr attr;
      memset (&attr, 0, sizeof attr);
      attr.size = sizeof attr;
      attr.sched_policy = (uint32_t) policy;
      attr.sched_priority = (uint32_t) prio;
      attr.sched_runtime = runtime;
      attr.sched_deadline = deadline;
      attr.sched_period = period;
      if (bchrt_set_attr (pid, &attr) < 0)
        {
          fprintf (stderr, "chrt: failed to set pid %ld's policy: %s\n",
                   (long) pid, strerror (errno));
          return EXECUTION_FAILURE;
        }
      return EXECUTION_SUCCESS;
    }

  struct sched_param sp;
  memset (&sp, 0, sizeof sp);
  sp.sched_priority = prio;
  if (bchrt_sys_setscheduler (pid, policy, &sp) < 0)
    {
      fprintf (stderr, "chrt: failed to set pid %ld's policy: %s\n",
               (long) pid, strerror (errno));
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

static int
bchrt_argv_from_list (WORD_LIST *list, char ***out)
{
  int argc = 0;
  char **argv;
  for (WORD_LIST *p = list; p; p = p->next) argc++;
  argv = calloc ((size_t) argc + 1, sizeof *argv);
  if (!argv)
    {
      fprintf (stderr, "chrt: calloc: %s\n", strerror (errno));
      return -1;
    }
  int i = 0;
  for (WORD_LIST *p = list; p; p = p->next) argv[i++] = p->word->word;
  argv[argc] = NULL;
  *out = argv;
  return argc;
}

static int
bchrt_run_command (int policy, int reset_on_fork, int prio,
                   uint64_t runtime, uint64_t deadline, uint64_t period,
                   WORD_LIST *cmd)
{
  char **argv = NULL;
  if (bchrt_argv_from_list (cmd, &argv) < 0)
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
      fprintf (stderr, "chrt: fork: %s\n", strerror (e));
      return EXECUTION_FAILURE;
    }
  if (pid == 0)
    {
      sigprocmask (SIG_SETMASK, &prev_mask, NULL);
      if (bchrt_set_pid (0, policy, reset_on_fork, prio,
                         runtime, deadline, period) != EXECUTION_SUCCESS)
        _exit (1);
      execvp (argv[0], argv);
      int err = errno;
      fprintf (stderr, "chrt: %s: %s\n", argv[0], strerror (err));
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
      fprintf (stderr, "chrt: waitpid: %s\n", strerror (errno));
      return EXECUTION_FAILURE;
    }
  if (WIFEXITED (status)) return WEXITSTATUS (status);
  if (WIFSIGNALED (status)) return 128 + WTERMSIG (status);
  return EXECUTION_FAILURE;
}

int
chrt_builtin (WORD_LIST *list)
{
  if (!list)
    {
      bchrt_bad_usage ();
      return EXECUTION_FAILURE;
    }

  int policy = SCHED_RR;
  int pid_mode = 0, max_mode = 0, reset_on_fork = 0;
  uint64_t runtime = 0, deadline = 0, period = 0;

  while (list)
    {
      const char *w = list->word->word;
      if (strcmp (w, "--") == 0) { list = list->next; break; }
      if (strcmp (w, "-h") == 0 || strcmp (w, "--help") == 0)
        { bchrt_help (); return EXECUTION_SUCCESS; }
      if (strcmp (w, "-V") == 0 || strcmp (w, "--version") == 0)
        { puts ("chrt 0.1"); return EXECUTION_SUCCESS; }
      if (strcmp (w, "-m") == 0 || strcmp (w, "--max") == 0)
        { max_mode = 1; list = list->next; continue; }
      if (strcmp (w, "-p") == 0 || strcmp (w, "--pid") == 0)
        { pid_mode = 1; list = list->next; continue; }
      if (strcmp (w, "-o") == 0 || strcmp (w, "--other") == 0)
        { policy = SCHED_OTHER; list = list->next; continue; }
      if (strcmp (w, "-b") == 0 || strcmp (w, "--batch") == 0)
        { policy = SCHED_BATCH; list = list->next; continue; }
      if (strcmp (w, "-i") == 0 || strcmp (w, "--idle") == 0)
        { policy = SCHED_IDLE; list = list->next; continue; }
      if (strcmp (w, "-f") == 0 || strcmp (w, "--fifo") == 0)
        { policy = SCHED_FIFO; list = list->next; continue; }
      if (strcmp (w, "-r") == 0 || strcmp (w, "--rr") == 0)
        { policy = SCHED_RR; list = list->next; continue; }
      if (strcmp (w, "-d") == 0 || strcmp (w, "--deadline") == 0)
        { policy = SCHED_DEADLINE; list = list->next; continue; }
      if (strcmp (w, "-R") == 0 || strcmp (w, "--reset-on-fork") == 0)
        { reset_on_fork = 1; list = list->next; continue; }
      if (strcmp (w, "-a") == 0 || strcmp (w, "--all-tasks") == 0 ||
          strcmp (w, "-v") == 0 || strcmp (w, "--verbose") == 0)
        { list = list->next; continue; }
      if (strcmp (w, "-T") == 0 || strcmp (w, "--sched-runtime") == 0 ||
          strcmp (w, "-P") == 0 || strcmp (w, "--sched-period") == 0 ||
          strcmp (w, "-D") == 0 || strcmp (w, "--sched-deadline") == 0)
        {
          const char *opt = w;
          list = list->next;
          if (!list || bchrt_parse_u64 (list->word->word,
                (strcmp (opt, "-T") == 0 || strcmp (opt, "--sched-runtime") == 0) ? &runtime :
                (strcmp (opt, "-P") == 0 || strcmp (opt, "--sched-period") == 0) ? &period :
                &deadline) < 0)
            {
              fprintf (stderr, "chrt: invalid argument for %s\n", opt);
              return EXECUTION_FAILURE;
            }
          list = list->next;
          continue;
        }
      if (w[0] == '-')
        {
          if (w[1] == '-')
            fprintf (stderr, "chrt: unrecognized option '%s'\n", w);
          else
            fprintf (stderr, "chrt: invalid option -- '%c'\n", w[1]);
          bchrt_usage_stderr ();
          return EXECUTION_FAILURE;
        }
      break;
    }

  if (max_mode)
    return bchrt_print_max ();

  int argc = 0;
  for (WORD_LIST *p = list; p; p = p->next) argc++;

  if (pid_mode)
    {
      if (argc == 1)
        {
          pid_t pid;
          if (bchrt_parse_pid (list->word->word, &pid) < 0)
            { bchrt_bad_usage (); return EXECUTION_FAILURE; }
          return bchrt_print_pid (pid);
        }
      if (argc == 2)
        {
          long prio_l;
          pid_t pid;
          if (bchrt_parse_long (list->word->word, 0, INT_MAX, &prio_l) < 0 ||
              bchrt_parse_pid (list->next->word->word, &pid) < 0)
            { bchrt_bad_usage (); return EXECUTION_FAILURE; }
          return bchrt_set_pid (pid, policy, reset_on_fork, (int) prio_l,
                                runtime, deadline, period);
        }
      bchrt_bad_usage ();
      return EXECUTION_FAILURE;
    }

  if (argc < 2)
    {
      bchrt_bad_usage ();
      return EXECUTION_FAILURE;
    }
  long prio_l;
  if (bchrt_parse_long (list->word->word, 0, INT_MAX, &prio_l) < 0)
    {
      bchrt_bad_usage ();
      return EXECUTION_FAILURE;
    }

  return bchrt_run_command (policy, reset_on_fork, (int) prio_l,
                            runtime, deadline, period, list->next);
}

char *chrt_doc[] = {
  "Show or change process scheduling policy and priority.",
  "",
  "    chrt -m",
  "    chrt -p PID",
  "    chrt [policy] PRIO COMMAND [ARG...]",
  "    chrt [policy] --pid PRIO PID",
  "",
  "Policy flags: -o/-b/-i/-f/-r/-d for OTHER/BATCH/IDLE/FIFO/RR/DEADLINE.",
  (char *) NULL
};

struct builtin chrt_struct = {
  "chrt",
  chrt_builtin,
  BUILTIN_ENABLED,
  chrt_doc,
  "chrt [-m] [-p PID] | [policy] PRIO COMMAND [ARG...]",
  0
};
