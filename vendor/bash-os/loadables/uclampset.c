/* SPDX-License-Identifier: MIT */
/* uclampset.c — uclampset(1) read subset over sched_getattr(2).
 *
 *   uclampset -p PID
 *   uclampset --system
 *   uclampset -m VALUE -p PID     # gated, no write by default
 *   uclampset -M VALUE -p PID     # gated, no write by default
 *
 * Read mode is unprivileged. Set mode mutates scheduler attributes and is
 * deliberately refused unless a future policy gate is added.
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "loadables.h"

struct buclamp_sched_attr {
  uint32_t size;
  uint32_t sched_policy;
  uint64_t sched_flags;
  int32_t sched_nice;
  uint32_t sched_priority;
  uint64_t sched_runtime;
  uint64_t sched_deadline;
  uint64_t sched_period;
  uint32_t sched_util_min;
  uint32_t sched_util_max;
};

static void
buclamp_help (void)
{
  puts ("Usage:");
  puts (" uclampset [options]");
  puts (" uclampset [options] --pid <pid> | --system | <command> <arg>...");
  puts ("");
  puts ("Show or change the utilization clamping attributes.");
  puts ("");
  puts ("Options:");
  puts (" -m <value>           util_min value to set");
  puts (" -M <value>           util_max value to set");
  puts (" -a, --all-tasks      operate on all the tasks (threads) for a given pid");
  puts (" -p, --pid <pid>      operate on existing given pid");
  puts (" -s, --system         operate on system");
  puts (" -R, --reset-on-fork  set reset-on-fork flag");
  puts (" -v, --verbose        display status information");
  puts (" -h, --help           display this help");
  puts (" -V, --version        display version");
  puts ("");
  puts ("Utilization value range is [0:1024]. Use special -1 value to reset to system's default.");
  puts ("");
  puts ("For more details see uclampset(1).");
}

static void
buclamp_try_help (void)
{
  fprintf (stderr, "Try 'uclampset --help' for more information.\n");
}

static int
buclamp_parse_long (const char *s, long min, long max, long *out)
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
buclamp_parse_pid (const char *s, pid_t *out)
{
  long v;
  if (buclamp_parse_long (s, 0, LONG_MAX, &v) < 0)
    return -1;
  *out = (pid_t) v;
  return 0;
}

static int
buclamp_parse_value (const char *s, int *out)
{
  long v;
  if (buclamp_parse_long (s, -1, 1024, &v) < 0)
    return -1;
  *out = (int) v;
  return 0;
}

static int
buclamp_get_attr (pid_t pid, struct buclamp_sched_attr *attr)
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

static const char *
buclamp_proc_root (void)
{
  const char *root = getenv ("BASHOS_PROC_ROOT");
  return (root && *root) ? root : "/proc";
}

static int
buclamp_read_first_line (const char *path, char *buf, size_t bufsz)
{
  FILE *fp = fopen (path, "r");
  if (!fp)
    return -1;
  if (!fgets (buf, (int) bufsz, fp))
    {
      int saved = ferror (fp) ? errno : EINVAL;
      fclose (fp);
      errno = saved;
      return -1;
    }
  fclose (fp);
  buf[strcspn (buf, "\r\n")] = '\0';
  return 0;
}

static void
buclamp_comm_for_pid (pid_t pid, char *buf, size_t bufsz)
{
  char path[128];
  pid_t show_pid = pid == 0 ? getpid () : pid;
  snprintf (path, sizeof path, "/proc/%ld/comm", (long) show_pid);
  if (buclamp_read_first_line (path, buf, bufsz) == 0 && buf[0])
    return;
  snprintf (buf, bufsz, "%ld", (long) show_pid);
}

static int
buclamp_print_pid (pid_t pid)
{
  struct buclamp_sched_attr attr;
  if (buclamp_get_attr (pid, &attr) < 0)
    {
      fprintf (stderr, "uclampset: failed to get pid %ld's uclamp values: %s\n",
               (long) pid, strerror (errno));
      return EXECUTION_FAILURE;
    }

  char comm[128];
  pid_t show_pid = pid == 0 ? getpid () : pid;
  buclamp_comm_for_pid (pid, comm, sizeof comm);
  printf ("%s (%ld) util_clamp: min: %u max: %u\n",
          comm, (long) show_pid, attr.sched_util_min, attr.sched_util_max);
  return EXECUTION_SUCCESS;
}

static int
buclamp_print_system (void)
{
  const char *root = buclamp_proc_root ();
  char min_path[PATH_MAX], max_path[PATH_MAX];
  char minv[64], maxv[64];

  snprintf (min_path, sizeof min_path, "%s/sys/kernel/sched_util_clamp_min", root);
  snprintf (max_path, sizeof max_path, "%s/sys/kernel/sched_util_clamp_max", root);

  if (buclamp_read_first_line (min_path, minv, sizeof minv) < 0)
    {
      fprintf (stderr, "uclampset: cannot read %s: %s\n",
               min_path, strerror (errno));
      return EXECUTION_FAILURE;
    }
  if (buclamp_read_first_line (max_path, maxv, sizeof maxv) < 0)
    {
      fprintf (stderr, "uclampset: cannot read %s: %s\n",
               max_path, strerror (errno));
      return EXECUTION_FAILURE;
    }

  printf ("system util_clamp: min: %s max: %s\n", minv, maxv);
  return EXECUTION_SUCCESS;
}

static int
buclamp_refuse_pid_set (pid_t pid)
{
  pid_t show_pid = pid == 0 ? getpid () : pid;
  fprintf (stderr, "uclampset: failed to set pid %ld's uclamp values: Operation not supported\n",
           (long) show_pid);
  return EXECUTION_FAILURE;
}

static int
buclamp_refuse_system_set (void)
{
  fprintf (stderr, "uclampset: failed to set system uclamp values: Operation not supported\n");
  return EXECUTION_FAILURE;
}

int
uclampset_builtin (WORD_LIST *list)
{
  if (!list)
    {
      buclamp_help ();
      return EXECUTION_SUCCESS;
    }

  int set_mode = 0, system_mode = 0, verbose = 0;
  int util_min = -2, util_max = -2;
  pid_t pid = -1;

  while (list)
    {
      const char *w = list->word->word;
      if (strcmp (w, "--") == 0) { list = list->next; break; }
      if (strcmp (w, "-h") == 0 || strcmp (w, "--help") == 0)
        { buclamp_help (); return EXECUTION_SUCCESS; }
      if (strcmp (w, "-V") == 0 || strcmp (w, "--version") == 0)
        { puts ("uclampset 0.1"); return EXECUTION_SUCCESS; }
      if (strcmp (w, "-s") == 0 || strcmp (w, "--system") == 0)
        { system_mode = 1; list = list->next; continue; }
      if (strcmp (w, "-v") == 0 || strcmp (w, "--verbose") == 0 ||
          strcmp (w, "-a") == 0 || strcmp (w, "--all-tasks") == 0 ||
          strcmp (w, "-R") == 0 || strcmp (w, "--reset-on-fork") == 0)
        { verbose = 1; list = list->next; continue; }
      if (strcmp (w, "-p") == 0 || strcmp (w, "--pid") == 0)
        {
          list = list->next;
          if (!list || buclamp_parse_pid (list->word->word, &pid) < 0)
            {
              fprintf (stderr, "uclampset: invalid pid\n");
              return EXECUTION_FAILURE;
            }
          list = list->next;
          continue;
        }
      if (strncmp (w, "--pid=", 6) == 0)
        {
          if (buclamp_parse_pid (w + 6, &pid) < 0)
            {
              fprintf (stderr, "uclampset: invalid pid\n");
              return EXECUTION_FAILURE;
            }
          list = list->next;
          continue;
        }
      if (strcmp (w, "-m") == 0 || strcmp (w, "-M") == 0)
        {
          int is_min = (w[1] == 'm');
          int value;
          list = list->next;
          if (!list || buclamp_parse_value (list->word->word, &value) < 0)
            {
              fprintf (stderr, "uclampset: invalid util_%s value\n",
                       is_min ? "min" : "max");
              return EXECUTION_FAILURE;
            }
          if (is_min) util_min = value; else util_max = value;
          set_mode = 1;
          list = list->next;
          continue;
        }
      if (w[0] == '-')
        {
          fprintf (stderr, "uclampset: unrecognized option '%s'\n", w);
          buclamp_try_help ();
          return EXECUTION_FAILURE;
        }
      break;
    }

  (void) verbose;
  (void) util_min;
  (void) util_max;

  if (list)
    {
      fprintf (stderr, "uclampset: command mode is not supported in this build\n");
      return EXECUTION_FAILURE;
    }

  if (system_mode)
    {
      if (set_mode)
        return buclamp_refuse_system_set ();
      return buclamp_print_system ();
    }

  if (pid < 0)
    {
      buclamp_help ();
      return EXECUTION_SUCCESS;
    }

  if (set_mode)
    return buclamp_refuse_pid_set (pid);

  return buclamp_print_pid (pid);
}

char *uclampset_doc[] = {
  "Show process utilization clamp values through sched_getattr(2).",
  "",
  "    uclampset -p PID",
  "    uclampset --system",
  "    uclampset -m VALUE -M VALUE -p PID   (set path gated)",
  (char *) NULL
};

struct builtin uclampset_struct = {
  "uclampset",
  uclampset_builtin,
  BUILTIN_ENABLED,
  uclampset_doc,
  "uclampset [-p PID|--system] [-m VALUE] [-M VALUE]",
  0
};
