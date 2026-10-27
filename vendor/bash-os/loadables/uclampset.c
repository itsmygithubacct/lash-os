/* SPDX-License-Identifier: MIT */
/* uclampset.c — uclampset(1) over sched_getattr(2)/sched_setattr(2).
 *
 *   uclampset [-a] -p PID                    show a task's clamps
 *   uclampset --system                       show the system-wide limits
 *   uclampset [-m MIN] [-M MAX] [-R] [-a] -p PID
 *   uclampset [-m MIN] [-M MAX] --system
 *   uclampset [-m MIN] [-M MAX] [-R] COMMAND [ARG]...
 *
 * Policy boundary. Only the utilization clamps (and, with -R, the
 * reset-on-fork bit) are ever requested. A PID setter copies the current
 * attributes from sched_getattr and passes SCHED_FLAG_KEEP_POLICY and
 * SCHED_FLAG_KEEP_PARAMS, so policy, nice, RT priority and deadline
 * parameters are preserved; -R re-submits the current policy with the
 * reset-on-fork flag instead of KEEP_POLICY. The system setter writes only
 * sched_util_clamp_min/max under BASHOS_PROC_ROOT (default /proc).
 *
 * Every value, PID, operand and the min <= max relation is validated, and
 * every target is read, before the first mutation. System files are opened
 * without truncation before any write. A system update orders its two writes
 * so the kernel's own min <= max check never fails midway, and attempts to
 * restore every attempted file if a write fails. Command mode forks;
 * only the child changes its clamps, then execs the literal argv. The
 * calling shell's attributes are never changed.
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "loadables.h"
#include "child-wait.h"
#include "command-run.h"

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

/* <linux/sched.h> values; kept local so older headers still build. */
#define BUCLAMP_FLAG_RESET_ON_FORK  0x01ULL
#define BUCLAMP_FLAG_KEEP_POLICY    0x08ULL
#define BUCLAMP_FLAG_KEEP_PARAMS    0x10ULL
#define BUCLAMP_FLAG_UTIL_CLAMP_MIN 0x20ULL
#define BUCLAMP_FLAG_UTIL_CLAMP_MAX 0x40ULL

#define BUCLAMP_SCALE 1024
#define BUCLAMP_UNSET (-2)
#define BUCLAMP_MAX_TASKS 65536

struct buclamp_opts {
  int util_min, util_max;     /* BUCLAMP_UNSET, -1 (reset) or 0..1024 */
  int reset_on_fork, all_tasks, verbose, system_mode;
  pid_t pid;                  /* -1 when no --pid */
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

static int
buclamp_usage_error (const char *fmt, const char *arg)
{
  fprintf (stderr, "uclampset: ");
  fprintf (stderr, fmt, arg);
  fputc ('\n', stderr);
  fprintf (stderr, "Try 'uclampset --help' for more information.\n");
  return EXECUTION_FAILURE;
}

/* Decimal integer only: no blanks, no fractions, no trailing text. */
static int
buclamp_parse_long (const char *s, long min, long max, long *out)
{
  char *end = NULL;
  long v;
  if (!s || !*s)
    return -1;
  const char *p = s;
  if (*p == '+' || *p == '-')
    p++;
  if (!*p)
    return -1;
  for (; *p; p++)
    if (*p < '0' || *p > '9')
      return -1;
  errno = 0;
  v = strtol (s, &end, 10);
  if (errno || !end || end == s || *end != '\0' || v < min || v > max)
    return -1;
  *out = v;
  return 0;
}

static int
buclamp_parse_pid (const char *s, pid_t *out)
{
  long v;
  if (buclamp_parse_long (s, 0, INT_MAX, &v) < 0)
    return -1;
  *out = (pid_t) v;
  return 0;
}

static int
buclamp_parse_value (const char *s, int *out)
{
  long v;
  if (buclamp_parse_long (s, -1, BUCLAMP_SCALE, &v) < 0)
    return -1;
  *out = (int) v;
  return 0;
}

static int
buclamp_get_attr (pid_t pid, struct buclamp_sched_attr *attr)
{
#ifdef SYS_sched_getattr
  memset (attr, 0, sizeof *attr);
  return (int) syscall (SYS_sched_getattr, (long) pid, attr,
                        (unsigned long) sizeof *attr, 0UL);
#else
  (void) pid;
  (void) attr;
  errno = ENOSYS;
  return -1;
#endif
}

static int
buclamp_set_attr (pid_t pid, struct buclamp_sched_attr *attr)
{
#ifdef SYS_sched_setattr
  return (int) syscall (SYS_sched_setattr, (long) pid, attr, 0UL);
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
  snprintf (path, sizeof path, "/proc/%ld/comm", (long) pid);
  if (buclamp_read_first_line (path, buf, bufsz) == 0 && buf[0])
    return;
  snprintf (buf, bufsz, "%ld", (long) pid);
}

static pid_t
buclamp_show_pid (pid_t pid)
{
  return pid == 0 ? getpid () : pid;
}

static int
buclamp_print_pid (pid_t pid, const char *name)
{
  struct buclamp_sched_attr attr;
  pid_t show_pid = buclamp_show_pid (pid);
  if (buclamp_get_attr (pid, &attr) < 0)
    {
      fprintf (stderr, "uclampset: failed to get pid %ld's uclamp values: %s\n",
               (long) show_pid, strerror (errno));
      return EXECUTION_FAILURE;
    }

  char comm[128];
  if (name)
    snprintf (comm, sizeof comm, "%s", name);
  else
    buclamp_comm_for_pid (show_pid, comm, sizeof comm);
  printf ("%s (%ld) util_clamp: min: %u max: %u\n",
          comm, (long) show_pid, attr.sched_util_min, attr.sched_util_max);
  return EXECUTION_SUCCESS;
}

/* The task IDs to act on: PID alone, or every entry of /proc/PID/task. */
static int
buclamp_collect_tasks (pid_t pid, int all, pid_t **out, size_t *count)
{
  pid_t *tids = NULL;
  size_t n = 0, cap = 0;
  *out = NULL;
  *count = 0;
  if (all && pid == 0)
    pid = getpid ();
  if (!all)
    {
      tids = malloc (sizeof *tids);
      if (!tids)
        return -1;
      tids[0] = pid;
      *out = tids;
      *count = 1;
      return 0;
    }

  char path[64];
  snprintf (path, sizeof path, "/proc/%ld/task", (long) pid);
  DIR *dir = opendir (path);
  if (!dir)
    return -1;
  struct dirent *de;
  errno = 0;
  while ((de = readdir (dir)))
    {
      pid_t tid;
      if (de->d_name[0] == '.' || buclamp_parse_pid (de->d_name, &tid) < 0)
        continue;
      if (n == cap)
        {
          size_t ncap = cap ? cap * 2 : 16;
          pid_t *grown;
          if (ncap > BUCLAMP_MAX_TASKS
              || !(grown = realloc (tids, ncap * sizeof *tids)))
            {
              int saved = ncap > BUCLAMP_MAX_TASKS ? E2BIG : errno;
              closedir (dir);
              free (tids);
              errno = saved;
              return -1;
            }
          tids = grown;
          cap = ncap;
        }
      tids[n++] = tid;
      errno = 0;
    }
  int saved = errno;
  closedir (dir);
  if (saved || n == 0)
    {
      free (tids);
      errno = saved ? saved : ESRCH;
      return -1;
    }
  *out = tids;
  *count = n;
  return 0;
}

static int
buclamp_show_tasks (const struct buclamp_opts *o)
{
  pid_t *tids;
  size_t n;
  if (buclamp_collect_tasks (o->pid, o->all_tasks, &tids, &n) < 0)
    {
      fprintf (stderr, "uclampset: cannot obtain the list of tasks for pid %ld: %s\n",
               (long) buclamp_show_pid (o->pid), strerror (errno));
      return EXECUTION_FAILURE;
    }
  int rc = EXECUTION_SUCCESS;
  for (size_t i = 0; i < n; i++)
    if (buclamp_print_pid (tids[i], NULL) != EXECUTION_SUCCESS)
      rc = EXECUTION_FAILURE;
  free (tids);
  return rc;
}

/* Build the sched_setattr request for one task from its current attributes.
   Returns 0, or -1 after reporting why nothing may be written. */
static int
buclamp_prepare (pid_t pid, const struct buclamp_opts *o,
                 struct buclamp_sched_attr *req)
{
  struct buclamp_sched_attr cur;
  pid_t show_pid = buclamp_show_pid (pid);
  if (buclamp_get_attr (pid, &cur) < 0)
    {
      fprintf (stderr, "uclampset: failed to get pid %ld's uclamp values: %s\n",
               (long) show_pid, strerror (errno));
      return -1;
    }

  /* Linux validates the requested members against the unchanged members.
     A requested -1 exempts that member from the comparison before reset.
     Without CONFIG_UCLAMP_TASK getattr returns 0/0, so an absent real sysctl
     leaves that ambiguous case to setattr for its EOPNOTSUPP response.
     BASHOS_PROC_ROOT redirects system operations only, not this probe. */
  long min = o->util_min == BUCLAMP_UNSET ? (long) cur.sched_util_min : o->util_min;
  long max = o->util_max == BUCLAMP_UNSET ? (long) cur.sched_util_max : o->util_max;
  if (min != -1 && max != -1 && min > max
      && !(cur.sched_util_min == 0 && cur.sched_util_max == 0
           && access ("/proc/sys/kernel/sched_util_clamp_min", F_OK) < 0
           && errno == ENOENT))
    {
      fprintf (stderr, "uclampset: pid %ld's util_min (%ld) must be <= util_max (%ld)\n",
               (long) show_pid, min, max);
      return -1;
    }

  *req = cur;
  req->size = sizeof *req;
  req->sched_flags = BUCLAMP_FLAG_KEEP_PARAMS;
  if (o->reset_on_fork)
    req->sched_flags |= BUCLAMP_FLAG_RESET_ON_FORK;
  else
    req->sched_flags |= BUCLAMP_FLAG_KEEP_POLICY;
  if (o->util_min != BUCLAMP_UNSET)
    {
      req->sched_flags |= BUCLAMP_FLAG_UTIL_CLAMP_MIN;
      req->sched_util_min = (uint32_t) o->util_min;
    }
  if (o->util_max != BUCLAMP_UNSET)
    {
      req->sched_flags |= BUCLAMP_FLAG_UTIL_CLAMP_MAX;
      req->sched_util_max = (uint32_t) o->util_max;
    }
  return 0;
}

static int
buclamp_apply (pid_t pid, struct buclamp_sched_attr *req)
{
  if (buclamp_set_attr (pid, req) < 0)
    {
      fprintf (stderr, "uclampset: failed to set pid %ld's uclamp values: %s\n",
               (long) buclamp_show_pid (pid), strerror (errno));
      return -1;
    }
  return 0;
}

static int
buclamp_set_tasks (const struct buclamp_opts *o)
{
  pid_t *tids;
  size_t n;
  if (buclamp_collect_tasks (o->pid, o->all_tasks, &tids, &n) < 0)
    {
      fprintf (stderr, "uclampset: cannot obtain the list of tasks for pid %ld: %s\n",
               (long) buclamp_show_pid (o->pid), strerror (errno));
      return EXECUTION_FAILURE;
    }
  struct buclamp_sched_attr *reqs = calloc (n, sizeof *reqs);
  if (!reqs)
    {
      fprintf (stderr, "uclampset: %s\n", strerror (errno));
      free (tids);
      return EXECUTION_FAILURE;
    }

  /* Read and validate every task before writing to any of them. */
  int rc = EXECUTION_SUCCESS;
  for (size_t i = 0; i < n; i++)
    if (buclamp_prepare (tids[i], o, &reqs[i]) < 0)
      {
        rc = EXECUTION_FAILURE;
        goto out;
      }
  for (size_t i = 0; i < n; i++)
    {
      if (buclamp_apply (tids[i], &reqs[i]) < 0)
        {
          rc = EXECUTION_FAILURE;
          continue;
        }
      if (o->verbose && buclamp_print_pid (tids[i], NULL) != EXECUTION_SUCCESS)
        rc = EXECUTION_FAILURE;
    }
out:
  free (reqs);
  free (tids);
  return rc;
}

static void
buclamp_system_paths (char *min_path, char *max_path, size_t sz)
{
  const char *root = buclamp_proc_root ();
  snprintf (min_path, sz, "%s/sys/kernel/sched_util_clamp_min", root);
  snprintf (max_path, sz, "%s/sys/kernel/sched_util_clamp_max", root);
}

static int
buclamp_read_sysctl (const char *path, char *raw, size_t rawsz, long *value)
{
  if (buclamp_read_first_line (path, raw, rawsz) < 0)
    {
      fprintf (stderr, "uclampset: cannot read %s: %s\n", path, strerror (errno));
      return -1;
    }
  if (value && buclamp_parse_long (raw, 0, BUCLAMP_SCALE, value) < 0)
    {
      fprintf (stderr, "uclampset: cannot parse %s: '%s'\n", path, raw);
      return -1;
    }
  return 0;
}

static int
buclamp_print_system (void)
{
  char min_path[PATH_MAX], max_path[PATH_MAX];
  char minv[64], maxv[64];
  buclamp_system_paths (min_path, max_path, sizeof min_path);
  if (buclamp_read_sysctl (min_path, minv, sizeof minv, NULL) < 0
      || buclamp_read_sysctl (max_path, maxv, sizeof maxv, NULL) < 0)
    return EXECUTION_FAILURE;
  printf ("system util_clamp: min: %s max: %s\n", minv, maxv);
  return EXECUTION_SUCCESS;
}

struct buclamp_sysctl {
  const char *path;
  int fd, trim;
  long old_value, new_value;
};

/* Open every changed file without truncation before the first write. access()
   alone uses real credentials and cannot predict an effective-credential,
   read-only mount or LSM denial from open(). Keep the descriptors for the
   update and rollback, so a pathname replacement cannot redirect either. */
static int
buclamp_open_sysctl (struct buclamp_sysctl *ctl)
{
  struct stat st;
  ctl->fd = open (ctl->path, O_WRONLY | O_CLOEXEC);
  if (ctl->fd < 0)
    return -1;
  if (fstat (ctl->fd, &st) < 0)
    {
      int saved = errno;
      close (ctl->fd);
      ctl->fd = -1;
      errno = saved;
      return -1;
    }
  /* Real procfs sysctls have size zero and consume one complete write. The
     private regular-file fixture needs its stale suffix removed as well. */
  ctl->trim = S_ISREG (st.st_mode) && st.st_size > 0;
  return 0;
}

static int
buclamp_write_sysctl (struct buclamp_sysctl *ctl, long value)
{
  char buf[32];
  int len = snprintf (buf, sizeof buf, "%ld\n", value);
  if (lseek (ctl->fd, 0, SEEK_SET) < 0)
    return -1;
  ssize_t w;
  do
    w = write (ctl->fd, buf, (size_t) len);
  while (w < 0 && errno == EINTR);
  /* Never send the tail of a short write as a second sysctl request. */
  if (w != len)
    {
      if (w >= 0)
        errno = EIO;
      return -1;
    }
  if (ctl->trim && ftruncate (ctl->fd, len) < 0)
    return -1;
  return 0;
}

static int
buclamp_set_system (const struct buclamp_opts *o)
{
  char min_path[PATH_MAX], max_path[PATH_MAX];
  char raw[64];
  long cur_min, cur_max;
  buclamp_system_paths (min_path, max_path, sizeof min_path);
  if (buclamp_read_sysctl (min_path, raw, sizeof raw, &cur_min) < 0
      || buclamp_read_sysctl (max_path, raw, sizeof raw, &cur_max) < 0)
    return EXECUTION_FAILURE;

  /* For the system limits -1 keeps the current value, as util-linux does. */
  long new_min = o->util_min >= 0 ? o->util_min : cur_min;
  long new_max = o->util_max >= 0 ? o->util_max : cur_max;
  if (new_min > new_max)
    {
      fprintf (stderr, "uclampset: system util_min (%ld) must be <= util_max (%ld)\n",
               new_min, new_max);
      return EXECUTION_FAILURE;
    }

  /* The kernel rejects an intermediate min > max. Raise the ceiling first
     when necessary; otherwise move the floor first. */
  struct buclamp_sysctl ctls[2];
  size_t n = 0;
  if (new_min > cur_max && new_max != cur_max)
    ctls[n++] = (struct buclamp_sysctl) { max_path, -1, 0, cur_max, new_max };
  if (new_min != cur_min)
    ctls[n++] = (struct buclamp_sysctl) { min_path, -1, 0, cur_min, new_min };
  if (new_min <= cur_max && new_max != cur_max)
    ctls[n++] = (struct buclamp_sysctl) { max_path, -1, 0, cur_max, new_max };

  int rc = EXECUTION_SUCCESS;
  for (size_t i = 0; i < n; i++)
    if (buclamp_open_sysctl (&ctls[i]) < 0)
      {
        fprintf (stderr, "uclampset: cannot open %s for writing: %s\n",
                 ctls[i].path, strerror (errno));
        rc = EXECUTION_FAILURE;
        goto out;
      }

  for (size_t i = 0; i < n; i++)
    if (buclamp_write_sysctl (&ctls[i], ctls[i].new_value) < 0)
      {
        fprintf (stderr, "uclampset: cannot write %s: %s\n",
                 ctls[i].path, strerror (errno));
        /* A failed or short write can already have changed a private file.
           Restore that file too, then undo earlier writes in reverse order. */
        for (size_t j = i + 1; j > 0; j--)
          if (buclamp_write_sysctl (&ctls[j - 1], ctls[j - 1].old_value) < 0)
            fprintf (stderr, "uclampset: cannot restore %s to %ld: %s\n",
                     ctls[j - 1].path, ctls[j - 1].old_value, strerror (errno));
        rc = EXECUTION_FAILURE;
        goto out;
      }

out:
  for (size_t i = 0; i < n; i++)
    if (ctls[i].fd >= 0 && close (ctls[i].fd) < 0)
      {
        fprintf (stderr, "uclampset: cannot close %s: %s\n", ctls[i].path, strerror (errno));
        rc = EXECUTION_FAILURE;
      }
  if (rc == EXECUTION_SUCCESS && o->verbose)
    return buclamp_print_system ();
  return rc;
}

static int
buclamp_run_command (const struct buclamp_opts *o, WORD_LIST *list)
{
  struct buclamp_sched_attr req;
  /* The child inherits these attributes: validate them before forking. */
  if (buclamp_prepare (0, o, &req) < 0)
    return EXECUTION_FAILURE;

  int argc = 0;
  for (WORD_LIST *p = list; p; p = p->next)
    argc++;
  char **argv = calloc ((size_t) argc + 1, sizeof *argv);
  if (!argv)
    {
      fprintf (stderr, "uclampset: %s\n", strerror (errno));
      return EXECUTION_FAILURE;
    }
  int i = 0;
  for (WORD_LIST *p = list; p; p = p->next)
    argv[i++] = p->word->word;

  bos_child_wait child_wait;
  if (bos_child_wait_begin (&child_wait) < 0)
    {
      fprintf (stderr, "uclampset: SIGCHLD setup: %s\n", strerror (errno));
      free (argv);
      return EXECUTION_FAILURE;
    }

  maybe_make_export_env ();
  fflush (stdout);
  fflush (stderr);
  pid_t pid = fork ();
  if (pid < 0)
    {
      int e = errno;
      bos_child_wait_end (&child_wait);
      fprintf (stderr, "uclampset: fork: %s\n", strerror (e));
      free (argv);
      return EXECUTION_FAILURE;
    }
  if (pid == 0)
    {
      bos_prepare_child ();
      bos_child_wait_child (&child_wait);
      /* Re-read: a reset-on-fork parent hands the child default values. */
      if (buclamp_prepare (0, o, &req) < 0 || buclamp_apply (0, &req) < 0)
        {
          fflush (stderr);
          _exit (EXECUTION_FAILURE);
        }
      if (o->verbose
          && (buclamp_print_pid (0, argv[0]) != EXECUTION_SUCCESS
              || fflush (stdout) == EOF || ferror (stdout)))
        {
          fprintf (stderr, "uclampset: cannot display command status: %s\n", strerror (errno));
          fflush (stderr);
          _exit (EXECUTION_FAILURE);
        }
      fflush (stdout);
      bos_run_builtin (argv[0], argv, NULL);
      execvp (argv[0], argv);
      int err = errno;
      fprintf (stderr, "uclampset: failed to execute %s: %s\n", argv[0], strerror (err));
      _exit (err == ENOENT ? 127 : 126);
    }
  free (argv);
  int status = 0;
  pid_t w;
  while ((w = waitpid (pid, &status, 0)) < 0 && errno == EINTR)
    ;
  if (w < 0)
    {
      int e = errno;
      bos_child_wait_end (&child_wait);
      fprintf (stderr, "uclampset: waitpid: %s\n", strerror (e));
      return EXECUTION_FAILURE;
    }
  bos_child_wait_end (&child_wait);
  if (WIFEXITED (status))
    return WEXITSTATUS (status);
  if (WIFSIGNALED (status))
    return 128 + WTERMSIG (status);
  return EXECUTION_FAILURE;
}

/* Options that take a value: -p, -m, -M. VALUE is NULL when missing. */
static int
buclamp_take_value (struct buclamp_opts *o, char opt, const char *value)
{
  if (!value)
    {
      char s[2] = { opt, '\0' };
      return buclamp_usage_error ("option requires an argument -- '%s'", s);
    }
  if (opt == 'p')
    {
      if (buclamp_parse_pid (value, &o->pid) < 0)
        {
          fprintf (stderr, "uclampset: invalid PID argument: '%s'\n", value);
          return EXECUTION_FAILURE;
        }
      return EXECUTION_SUCCESS;
    }
  int v;
  if (buclamp_parse_value (value, &v) < 0)
    {
      fprintf (stderr, "uclampset: invalid util_%s argument: '%s'\n",
               opt == 'm' ? "min" : "max", value);
      return EXECUTION_FAILURE;
    }
  if (opt == 'm')
    o->util_min = v;
  else
    o->util_max = v;
  return EXECUTION_SUCCESS;
}

static int
buclamp_main (WORD_LIST *list)
{
  if (!list)
    {
      buclamp_help ();
      return EXECUTION_SUCCESS;
    }

  struct buclamp_opts o = { BUCLAMP_UNSET, BUCLAMP_UNSET, 0, 0, 0, 0, -1 };

  while (list)
    {
      const char *w = list->word->word;
      if (w[0] != '-' || w[1] == '\0')
        break;
      if (strcmp (w, "--") == 0)
        {
          list = list->next;
          break;
        }
      if (w[1] == '-')
        {
          const char *name = w + 2;
          const char *eq = strchr (name, '=');
          size_t nlen = eq ? (size_t) (eq - name) : strlen (name);
#define BUCLAMP_LONG(s) (nlen == sizeof (s) - 1 && strncmp (name, s, nlen) == 0)
          if (BUCLAMP_LONG ("pid"))
            {
              const char *v = eq ? eq + 1 : list->next ? list->next->word->word : NULL;
              if (!eq && list->next)
                list = list->next;
              if (!v)
                return buclamp_usage_error ("option '%s' requires an argument", "--pid");
              if (buclamp_take_value (&o, 'p', v) != EXECUTION_SUCCESS)
                return EXECUTION_FAILURE;
              list = list->next;
              continue;
            }
          if (eq)
            return buclamp_usage_error ("unrecognized option '%s'", w);
          if (BUCLAMP_LONG ("help"))
            { buclamp_help (); return EXECUTION_SUCCESS; }
          else if (BUCLAMP_LONG ("version"))
            { puts ("uclampset 0.2"); return EXECUTION_SUCCESS; }
          else if (BUCLAMP_LONG ("system"))
            o.system_mode = 1;
          else if (BUCLAMP_LONG ("all-tasks"))
            o.all_tasks = 1;
          else if (BUCLAMP_LONG ("reset-on-fork"))
            o.reset_on_fork = 1;
          else if (BUCLAMP_LONG ("verbose"))
            o.verbose = 1;
          else
            return buclamp_usage_error ("unrecognized option '%s'", w);
#undef BUCLAMP_LONG
          list = list->next;
          continue;
        }

      /* A cluster of short options; p, m and M consume the rest or the next word. */
      int consumed_next = 0;
      for (const char *c = w + 1; *c; c++)
        {
          switch (*c)
            {
            case 'h': buclamp_help (); return EXECUTION_SUCCESS;
            case 'V': puts ("uclampset 0.2"); return EXECUTION_SUCCESS;
            case 's': o.system_mode = 1; continue;
            case 'a': o.all_tasks = 1; continue;
            case 'R': o.reset_on_fork = 1; continue;
            case 'v': o.verbose = 1; continue;
            case 'p': case 'm': case 'M':
              {
                const char *v = c[1] ? c + 1
                              : list->next ? list->next->word->word : NULL;
                if (!c[1] && list->next)
                  consumed_next = 1;
                if (buclamp_take_value (&o, *c, v) != EXECUTION_SUCCESS)
                  return EXECUTION_FAILURE;
                goto cluster_done;
              }
            default:
              {
                char s[2] = { *c, '\0' };
                return buclamp_usage_error ("invalid option -- '%s'", s);
              }
            }
        }
    cluster_done:
      list = list->next;
      if (consumed_next)
        list = list->next;
    }

  int set_mode = o.util_min != BUCLAMP_UNSET || o.util_max != BUCLAMP_UNSET;

  /* Reject an invalid explicit pair before any reads. Single-task requests
     are also checked against current values by buclamp_prepare. */
  if (o.util_min >= 0 && o.util_max >= 0 && o.util_min > o.util_max)
    {
      fprintf (stderr, "uclampset: util_min (%d) must be <= util_max (%d)\n",
               o.util_min, o.util_max);
      return EXECUTION_FAILURE;
    }

  if (o.system_mode && o.pid >= 0)
    return buclamp_usage_error ("%s", "--pid and --system are mutually exclusive");
  if ((o.system_mode || o.pid >= 0) && list)
    return buclamp_usage_error ("unexpected operand '%s'", list->word->word);
  if (o.all_tasks && o.pid < 0)
    return buclamp_usage_error ("%s", "--all-tasks requires --pid");
  if (o.system_mode && o.reset_on_fork)
    return buclamp_usage_error ("%s", "--reset-on-fork does not apply to --system");

  if (o.system_mode)
    return set_mode ? buclamp_set_system (&o) : buclamp_print_system ();

  if (o.pid >= 0)
    return set_mode || o.reset_on_fork ? buclamp_set_tasks (&o)
                                       : buclamp_show_tasks (&o);

  if (list)
    {
      if (!set_mode && !o.reset_on_fork)
        return buclamp_usage_error ("%s", "no util value to set for the command (use -m or -M)");
      return buclamp_run_command (&o, list);
    }

  if (set_mode || o.reset_on_fork)
    {
      fprintf (stderr, "uclampset: no cmd to execute: Invalid argument\n");
      return EXECUTION_FAILURE;
    }
  buclamp_help ();
  return EXECUTION_SUCCESS;
}

int
uclampset_builtin (WORD_LIST *list)
{
  /* Report a failed stdout write (EPIPE, ENOSPC) instead of success. */
  return sh_chkwrite (buclamp_main (list));
}

char *uclampset_doc[] = {
  "Show or change utilization clamps through sched_getattr/sched_setattr(2).",
  "",
  "    uclampset [-a] -p PID",
  "    uclampset --system",
  "    uclampset [-m MIN] [-M MAX] [-R] [-a] -p PID",
  "    uclampset [-m MIN] [-M MAX] --system",
  "    uclampset [-m MIN] [-M MAX] [-R] COMMAND [ARG]...",
  "",
  "Values are -1 (default) or 0..1024 and must satisfy min <= max. Only the",
  "clamps change: policy, nice and priority are preserved. Every target is",
  "read and validated before the first write. COMMAND runs in a child; the",
  "calling shell's own clamps never change. The system limits are read from",
  "and written to $BASHOS_PROC_ROOT/sys/kernel (default /proc).",
  (char *) NULL
};

struct builtin uclampset_struct = {
  "uclampset",
  uclampset_builtin,
  BUILTIN_ENABLED,
  uclampset_doc,
  "uclampset [-asRv] [-p PID] [-m MIN] [-M MAX] [COMMAND [ARG]...]",
  0
};
