/* SPDX-License-Identifier: MIT */
/* w.c - minimal w(1)-shape builtin for bash-os.
 *
 * Reads utmp USER_PROCESS records and prints:
 *   USER TTY FROM LOGIN@ IDLE JCPU PCPU WHAT
 *
 * IDLE is approximated from the terminal device access time. JCPU/PCPU/WHAT
 * are approximated from /proc: JCPU sums utime+stime for processes on the
 * same tty_nr, and PCPU comes from the foreground process-group leader when
 * found, otherwise the utmp session leader.
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <utmp.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/stat.h>

#include "loadables.h"

#define BW_PATH "/var/run/utmp"
#define BW_DEV_DIR_DEFAULT "/dev"

typedef struct bw_proc {
  int pid;
  long long tty_nr;
  long long tpgid;
  unsigned long long utime;
  unsigned long long stime;
} bw_proc;

static const char *
bw_env (const char *name, const char *fallback)
{
  const char *s = getenv (name);
  return (s && *s) ? s : fallback;
}

static void
bw_copy_field (char *dst, size_t dstsz, const char *src, size_t srcsz)
{
  size_t n = 0;
  if (dstsz == 0)
    return;
  while (n + 1 < dstsz && n < srcsz && src[n] != '\0')
    {
      dst[n] = src[n];
      n++;
    }
  while (n > 0 && isspace ((unsigned char) dst[n - 1]))
    n--;
  dst[n] = '\0';
}

static int
bw_parse_stat_buf (const char *buf, bw_proc *p)
{
  const char *rp = strrchr (buf, ')');
  char *endp;
  long long nums[12];
  int i;

  if (rp == 0 || rp[1] != ' ')
    return -1;

  const char *s = rp + 2;
  if (*s == '\0')
    return -1;
  s++;                         /* state */

  for (i = 0; i < 12; i++)
    {
      errno = 0;
      nums[i] = strtoll (s, &endp, 10);
      if (s == endp || errno == ERANGE)
        return -1;
      s = endp;
    }

  p->tty_nr = nums[3];         /* field 7 */
  p->tpgid = nums[4];          /* field 8 */
  p->utime = (unsigned long long) nums[10]; /* field 14 */
  p->stime = (unsigned long long) nums[11]; /* field 15 */
  return 0;
}

static int
bw_read_stat (int pid, bw_proc *p)
{
  char path[64];
  char buf[1024];
  int fd;
  ssize_t n;

  snprintf (path, sizeof path, "/proc/%d/stat", pid);
  fd = open (path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return -1;
  n = read (fd, buf, sizeof buf - 1);
  close (fd);
  if (n <= 0)
    return -1;
  buf[n] = '\0';

  memset (p, 0, sizeof *p);
  p->pid = pid;
  return bw_parse_stat_buf (buf, p);
}

static void
bw_read_cmdline (int pid, char *out, size_t cap)
{
  char path[64];
  int fd;
  ssize_t n;

  if (cap == 0)
    return;
  out[0] = '\0';

  snprintf (path, sizeof path, "/proc/%d/cmdline", pid);
  fd = open (path, O_RDONLY | O_CLOEXEC);
  if (fd >= 0)
    {
      n = read (fd, out, cap - 1);
      close (fd);
      if (n > 0)
        {
          ssize_t i;
          for (i = 0; i < n; i++)
            if (out[i] == '\0')
              out[i] = ' ';
          while (n > 0 && out[n - 1] == ' ')
            n--;
          out[n] = '\0';
          if (out[0])
            return;
        }
    }

  snprintf (path, sizeof path, "/proc/%d/comm", pid);
  fd = open (path, O_RDONLY | O_CLOEXEC);
  if (fd >= 0)
    {
      n = read (fd, out, cap - 1);
      close (fd);
      if (n > 0)
        {
          if (out[n - 1] == '\n')
            n--;
          out[n] = '\0';
          if (out[0])
            return;
        }
    }

  snprintf (out, cap, "-");
}

static int
bw_pid_from_name (const char *name)
{
  char *endp;
  long v;

  if (name == 0 || !isdigit ((unsigned char) name[0]))
    return -1;
  errno = 0;
  v = strtol (name, &endp, 10);
  if (errno || *endp != '\0' || v <= 0 || v > 99999999L)
    return -1;
  return (int) v;
}

static void
bw_resolve_tty (const char *raw, char *out, size_t outsz)
{
  int n;

  if (outsz == 0)
    return;
  if (raw == 0 || *raw == '\0')
    {
      out[0] = '\0';
      return;
    }

  if (raw[0] == '/')
    n = snprintf (out, outsz, "%s", raw);
  else
    n = snprintf (out, outsz, "%s/%s",
                  bw_env ("BASHW_DEV_DIR", BW_DEV_DIR_DEFAULT), raw);
  if (n < 0)
    out[0] = '\0';
}

static void
bw_format_duration (time_t secs, char *out, size_t outsz)
{
  long long s;

  if (outsz == 0)
    return;
  if (secs < 0)
    secs = 0;
  s = (long long) secs;

  if (s < 60)
    snprintf (out, outsz, "%llus", (unsigned long long) s);
  else if (s < 60 * 60)
    snprintf (out, outsz, "%02llu:%02llu",
              (unsigned long long) (s / 60),
              (unsigned long long) (s % 60));
  else if (s < 24 * 60 * 60)
    snprintf (out, outsz, "%02llu:%02llu",
              (unsigned long long) (s / 3600),
              (unsigned long long) ((s / 60) % 60));
  else
    snprintf (out, outsz, "%lludays", (unsigned long long) (s / 86400));
}

static void
bw_idle_for_line (const char *line, char *out, size_t outsz)
{
  char path[512];
  struct stat st;
  time_t now;

  if (outsz == 0)
    return;
  snprintf (out, outsz, "?");
  bw_resolve_tty (line, path, sizeof path);
  if (path[0] == '\0' || stat (path, &st) < 0)
    return;
  now = time (NULL);
  if (now == (time_t) -1)
    return;
  bw_format_duration (now - st.st_atime, out, outsz);
}

static void
bw_proc_totals (const bw_proc *leader, unsigned long long *jcpu_ticks,
                unsigned long long *pcpu_ticks, int *fg_pid)
{
  DIR *d;
  struct dirent *de;

  *jcpu_ticks = 0;
  *pcpu_ticks = leader->utime + leader->stime;
  *fg_pid = leader->pid;

  if (leader->tty_nr <= 0)
    {
      *jcpu_ticks = leader->utime + leader->stime;
      return;
    }

  d = opendir ("/proc");
  if (d == 0)
    {
      *jcpu_ticks = leader->utime + leader->stime;
      return;
    }

  while ((de = readdir (d)) != 0)
    {
      int pid = bw_pid_from_name (de->d_name);
      bw_proc p;
      if (pid < 0 || bw_read_stat (pid, &p) < 0)
        continue;
      if (p.tty_nr != leader->tty_nr)
        continue;
      *jcpu_ticks += p.utime + p.stime;
      if (p.tpgid == p.pid)
        {
          *fg_pid = p.pid;
          *pcpu_ticks = p.utime + p.stime;
        }
    }

  closedir (d);
}

int
w_builtin (WORD_LIST *list)
{
  int no_header = 0;
  const char *path = BW_PATH;

  while (list && list->word->word[0] == '-' && list->word->word[1])
    {
      const char *w = list->word->word;
      if (!strcmp (w, "--"))
        { list = list->next; break; }
      if (!strcmp (w, "-h") || !strcmp (w, "--help"))
        {
          builtin_usage ();
          return EXECUTION_SUCCESS;
        }
      if (!strcmp (w, "--version"))
        {
          puts ("w 1.0 (bash-loadable)");
          return EXECUTION_SUCCESS;
        }
      if (!strcmp (w, "-H") || !strcmp (w, "--no-header"))
        {
          no_header = 1;
          list = list->next;
          continue;
        }
      builtin_error ("unknown flag: %s", w);
      builtin_usage ();
      return EX_USAGE;
    }

  if (list)
    {
      path = list->word->word;
      if (list->next)
        {
          builtin_error ("too many operands");
          return EX_USAGE;
        }
    }

  int fd = open (path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    {
      builtin_error ("%s: %s", path, strerror (errno));
      return EXECUTION_FAILURE;
    }

  if (!no_header)
    printf ("%-8s %-8s %-16s %-7s %-5s %-6s %-6s %s\n",
            "USER", "TTY", "FROM", "LOGIN@", "IDLE", "JCPU", "PCPU", "WHAT");

  long clk_tck = sysconf (_SC_CLK_TCK);
  if (clk_tck <= 0)
    clk_tck = 100;

  struct utmp u;
  ssize_t n;
  while ((n = read (fd, &u, sizeof u)) == (ssize_t) sizeof u)
    {
      char user[UT_NAMESIZE + 1];
      char line[UT_LINESIZE + 1];
      char host[UT_HOSTSIZE + 1];
      char login_at[16] = "?";
      char idle[16] = "?";
      char cmd[256];
      bw_proc leader;
      unsigned long long jcpu_ticks = 0, pcpu_ticks = 0;
      unsigned long long jcpu_sec = 0, pcpu_sec = 0;
      int fg_pid;
      time_t t;
      struct tm tm;

      if (u.ut_type != USER_PROCESS)
        continue;

      bw_copy_field (user, sizeof user, u.ut_user, UT_NAMESIZE);
      bw_copy_field (line, sizeof line, u.ut_line, UT_LINESIZE);
      bw_copy_field (host, sizeof host, u.ut_host, UT_HOSTSIZE);
      if (host[0] == '\0')
        strcpy (host, "(none)");
      bw_idle_for_line (line, idle, sizeof idle);

      t = (time_t) u.ut_tv.tv_sec;
      if (localtime_r (&t, &tm) != 0)
        strftime (login_at, sizeof login_at, "%H:%M", &tm);

      if (bw_read_stat (u.ut_pid, &leader) == 0)
        {
          bw_proc_totals (&leader, &jcpu_ticks, &pcpu_ticks, &fg_pid);
          jcpu_sec = jcpu_ticks / (unsigned long) clk_tck;
          pcpu_sec = pcpu_ticks / (unsigned long) clk_tck;
          bw_read_cmdline (fg_pid, cmd, sizeof cmd);
        }
      else
        {
          fg_pid = -1;
          strcpy (cmd, "-");
        }

      printf ("%-8.8s %-8.8s %-16.16s %-7s %-5s %llus  %llus  %.60s\n",
              user, line, host, login_at, idle,
              (unsigned long long) jcpu_sec,
              (unsigned long long) pcpu_sec,
              cmd);
    }

  close (fd);
  return EXECUTION_SUCCESS;
}

char *w_doc[] = {
  "List logged-in users with w(1)-shape output.",
  "",
  "    w [-H|--no-header] [--help|--version] [FILE]",
  "",
  "    -H, --no-header  suppress the column header",
  "    FILE             alternate utmp path (default /var/run/utmp)",
  "",
  "Columns: USER TTY FROM LOGIN@ IDLE JCPU PCPU WHAT. IDLE is approximated",
  "from the terminal device access time; JCPU/PCPU/WHAT are approximated",
  "from /proc when the utmp session leader is still present.",
  (char *)NULL
};

struct builtin w_struct = {
  "w",
  w_builtin,
  BUILTIN_ENABLED,
  w_doc,
  "w [-H|--no-header] [--help|--version] [FILE]",
  0
};
