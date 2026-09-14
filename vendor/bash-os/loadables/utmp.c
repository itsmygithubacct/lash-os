/* SPDX-License-Identifier: MIT */
/* utmp.c — utmp / wtmp / lastlog support for bash-os.
 *
 * Login session tracking: who(1), last(1), lastlog(1) all read from
 * /var/run/utmp, /var/log/wtmp, /var/log/lastlog. Format is fixed-
 * width binary (struct utmp from <utmp.h>). bash can't compose those
 * records from script — needs C.
 *
 * Subcommands:
 *
 *   utmp login USER LINE [HOST]
 *       Record a login. Writes a USER_PROCESS entry to /var/run/utmp
 *       (replacing any LOGIN_PROCESS entry with the same line) and
 *       appends to /var/log/wtmp. Updates /var/log/lastlog for the
 *       calling uid (or USER's uid if running as root).
 *
 *   utmp logout LINE
 *       Record a logout. Marks the utmp entry for LINE as
 *       DEAD_PROCESS (clears USER, sets exit time), and appends a
 *       DEAD_PROCESS marker to wtmp.
 *
 *   utmp boot [WTMP]
 *       Append a BOOT_TIME record to wtmp. Should be called once
 *       early in /init. Optional WTMP path is for isolated fixtures.
 *
 *   utmp shutdown [WTMP]
 *       Append a SHUTDOWN_TIME record (RUN_LVL with `~~` user).
 *       Optional WTMP path is for isolated fixtures.
 *
 *   utmp dump [PATH]
 *       Read records from PATH (default: /var/run/utmp) and print
 *       one per line in `who`-style format:
 *           USER LINE HOST LOGIN_TIME PID
 *
 * Defaults:
 *   utmp:    /var/run/utmp     mode 0644
 *   wtmp:    /var/log/wtmp     mode 0664
 *   lastlog: /var/log/lastlog  mode 0644
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
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <locale.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <utmp.h>
#include <lastlog.h>

#include "loadables.h"

#define BU_UTMP    "/var/run/utmp"
#define BU_WTMP    "/var/log/wtmp"
#define BU_BTMP    "/var/log/btmp"
#define BU_LASTLOG "/var/log/lastlog"

/* Defang a fixed-width utmp string field (ut_user / ut_line / ut_host)
 * into a NUL-terminated stack buffer for safe printf'ing.
 *
 * Closes LOG-PARSER-AUDIT.md Wave 2 lastb.sh #1 (ESC/BEL/BS/other C0
 * controls in ut_user/ut_host reach the operator TTY raw), #3 (embedded
 * NUL silently truncates the displayed value), and last.sh #2 (embedded
 * LF in ut_user/ut_host splits one wtmp record across two stdout lines,
 * skewing the consumer-side USER_FILTER).
 *
 * - All iscntrl() bytes (NUL, LF, CR, ESC, BEL, BS, etc.) and DEL (0x7f)
 *   are replaced by a single space.  TAB is allowed through so column
 *   alignment in dump/btmp output survives.
 * - A NUL byte inside the field is REPLACED by a space rather than
 *   terminating the field, so attacker-embedded NUL ("root\0admin") is
 *   visible to the operator and can't evade grep.
 * - `dst` must be at least `field_sz + 1` bytes; the result is always
 *   NUL-terminated at offset `field_sz`.
 */
static void
bu_scrub_field (char *dst, size_t dst_cap, const char *src, size_t field_sz)
{
  size_t take = (field_sz < dst_cap - 1) ? field_sz : dst_cap - 1;
  for (size_t i = 0; i < take; i++)
    {
      unsigned char c = (unsigned char) src[i];
      if (c == '\t')
        dst[i] = (char) c;
      else if (c == '\0' || c == 0x7f || iscntrl (c))
        dst[i] = ' ';
      else
        dst[i] = (char) c;
    }
  dst[take] = '\0';
}

/* Look up a user's UID by name. Returns -1 on failure. */
static int
bu_uid_for (const char *name)
{
  FILE *f = fopen ("/etc/passwd", "r");
  if (!f) return -1;
  char *line = NULL;
  size_t cap = 0;
  ssize_t n;
  int uid = -1;
  while ((n = getline (&line, &cap, f)) > 0)
    {
      if (line[n - 1] == '\n') line[n - 1] = '\0';
      char *p = line, *fields[7] = { 0 };
      int nf = 0;
      char *start = line;
      while (*p && nf < 7)
        {
          if (*p == ':') { *p = '\0'; fields[nf++] = start; start = p + 1; }
          p++;
        }
      if (nf < 6) continue;
      fields[nf++] = start;
      if (strcmp (fields[0], name) == 0)
        { uid = (int) strtol (fields[2], NULL, 10); break; }
    }
  free (line);
  fclose (f);
  return uid;
}

static void
bu_fill_common (struct utmp *u, const char *user, const char *line, const char *host)
{
  memset (u, 0, sizeof *u);
  if (user) strncpy (u->ut_user, user, UT_NAMESIZE - 1);
  if (line) strncpy (u->ut_line, line, UT_LINESIZE - 1);
  if (host) strncpy (u->ut_host, host, UT_HOSTSIZE - 1);
  u->ut_pid = getppid ();   /* the login session's parent (getty) */
  /* ut_id: trailing 2-4 chars of line is the conventional id. */
  size_t llen = line ? strlen (line) : 0;
  size_t take = llen > 4 ? 4 : llen;
  if (line && take > 0)
    memcpy (u->ut_id, line + (llen - take), take);
  /* Time: split into tv_sec / tv_usec. */
  struct timespec ts;
  clock_gettime (CLOCK_REALTIME, &ts);
  u->ut_tv.tv_sec  = (int32_t) ts.tv_sec;
  u->ut_tv.tv_usec = (int32_t) (ts.tv_nsec / 1000);
}

/* Replace-by-line in utmp: scan for an entry whose ut_line matches,
   overwrite in place; if not found, append.
   flock(LOCK_EX) serializes concurrent logins so two processes
   racing to write the same ut_line don't clobber each other; close()
   releases the lock automatically. */
static int
bu_utmp_write_path (const struct utmp *rec, const char *path)
{
  int fd = open (path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
  if (fd < 0)
    { builtin_error ("open %s: %s", path, strerror (errno)); return -1; }
  if (flock (fd, LOCK_EX) < 0 && errno != ENOSYS)
    { builtin_error ("flock %s: %s", path, strerror (errno)); close (fd); return -1; }
  struct utmp tmp;
  off_t pos = 0;
  ssize_t n;
  while ((n = read (fd, &tmp, sizeof tmp)) == sizeof tmp)
    {
      if (memcmp (tmp.ut_line, rec->ut_line, UT_LINESIZE) == 0)
        {
          /* Found — rewind and overwrite. */
          if (lseek (fd, pos, SEEK_SET) < 0
              || write (fd, rec, sizeof *rec) != sizeof *rec)
            { close (fd); return -1; }
          close (fd);
          return 0;
        }
      pos += sizeof tmp;
    }
  if (n < 0)
    { close (fd); return -1; }
  /* Not found — append. */
  if (lseek (fd, 0, SEEK_END) < 0
      || write (fd, rec, sizeof *rec) != sizeof *rec)
    { close (fd); return -1; }
  close (fd);
  return 0;
}

static int
bu_utmp_write (const struct utmp *rec)
{
  return bu_utmp_write_path (rec, BU_UTMP);
}

/* Append-only to wtmp. */
static int
bu_wtmp_append_path (const struct utmp *rec, const char *path)
{
  int fd = open (path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0664);
  if (fd < 0)
    { builtin_error ("open %s: %s", path, strerror (errno)); return -1; }
  if (write (fd, rec, sizeof *rec) != (ssize_t) sizeof *rec)
    { close (fd); return -1; }
  close (fd);
  return 0;
}

static int
bu_wtmp_append (const struct utmp *rec)
{
  return bu_wtmp_append_path (rec, BU_WTMP);
}

/* lastlog: indexed by uid. Each record is fixed-size. Seek + write.
   flock(LOCK_EX) so two simultaneous logins by the same user don't
   produce a torn write at the lastlog slot. */
static int
bu_lastlog_write_path (int uid, const char *line, const char *host, const char *path)
{
  int fd = open (path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
  if (fd < 0)
    { builtin_error ("open %s: %s", path, strerror (errno)); return -1; }
  if (flock (fd, LOCK_EX) < 0 && errno != ENOSYS)
    { builtin_error ("flock %s: %s", path, strerror (errno)); close (fd); return -1; }
  struct lastlog ll;
  memset (&ll, 0, sizeof ll);
  ll.ll_time = time (NULL);
  if (line) strncpy (ll.ll_line, line, sizeof ll.ll_line - 1);
  if (host) strncpy (ll.ll_host, host, sizeof ll.ll_host - 1);
  if (lseek (fd, (off_t) uid * (off_t) sizeof ll, SEEK_SET) < 0
      || write (fd, &ll, sizeof ll) != sizeof ll)
    { close (fd); return -1; }
  close (fd);
  return 0;
}

static int
bu_lastlog_write (int uid, const char *line, const char *host)
{
  return bu_lastlog_write_path (uid, line, host, BU_LASTLOG);
}

static int
bu_lastlog_dump_path (const char *path)
{
  int fd = open (path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    { builtin_error ("open %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }

  struct lastlog ll;
  ssize_t n;
  unsigned long uid = 0;
  while ((n = read (fd, &ll, sizeof ll)) == (ssize_t) sizeof ll)
    {
      if (ll.ll_time != 0)
        printf ("uid=%lu line=%.*s host=%.*s time=%lld\n",
                uid,
                (int) sizeof ll.ll_line, ll.ll_line,
                (int) sizeof ll.ll_host, ll.ll_host,
                (long long) ll.ll_time);
      uid++;
    }
  if (n < 0)
    { builtin_error ("read %s: %s", path, strerror (errno)); close (fd); return EXECUTION_FAILURE; }
  close (fd);
  return EXECUTION_SUCCESS;
}

static int
bu_lastlog_cmd (WORD_LIST *args)
{
  if (!args || strcmp (args->word->word, "dump") != 0)
    { builtin_error ("lastlog needs dump [PATH]"); return EX_USAGE; }
  args = args->next;
  const char *path = args ? args->word->word : BU_LASTLOG;
  if (args && args->next)
    { builtin_error ("lastlog dump takes at most one PATH"); return EX_USAGE; }
  return bu_lastlog_dump_path (path);
}

static int
bu_login_cmd (WORD_LIST *args)
{
  const char *utmp_path = BU_UTMP;
  const char *wtmp_path = BU_WTMP;
  const char *lastlog_path = BU_LASTLOG;
  while (args && args->word && args->word->word && args->word->word[0] == '-')
    {
      const char *opt = args->word->word;
      if (strcmp (opt, "-u") == 0 || strcmp (opt, "--utmp") == 0)
        {
          if (!args->next) { builtin_error ("%s needs PATH", opt); return EX_USAGE; }
          utmp_path = args->next->word->word;
          args = args->next->next;
        }
      else if (strcmp (opt, "-w") == 0 || strcmp (opt, "--wtmp") == 0)
        {
          if (!args->next) { builtin_error ("%s needs PATH", opt); return EX_USAGE; }
          wtmp_path = args->next->word->word;
          args = args->next->next;
        }
      else if (strcmp (opt, "-l") == 0 || strcmp (opt, "--lastlog") == 0)
        {
          if (!args->next) { builtin_error ("%s needs PATH", opt); return EX_USAGE; }
          lastlog_path = args->next->word->word;
          args = args->next->next;
        }
      else if (strcmp (opt, "--") == 0)
        {
          args = args->next;
          break;
        }
      else
        {
          builtin_error ("login: unknown flag: %s", opt);
          return EX_USAGE;
        }
    }
  if (!args || !args->next)
    { builtin_error ("login needs [-u UTMP] [-w WTMP] [-l LASTLOG] USER LINE [HOST]"); return EX_USAGE; }
  const char *user = args->word->word;
  const char *line = args->next->word->word;
  const char *host = (args->next->next) ? args->next->next->word->word : "";

  struct utmp u;
  bu_fill_common (&u, user, line, host);
  u.ut_type = USER_PROCESS;

  if (bu_utmp_write_path (&u, utmp_path) < 0) return EXECUTION_FAILURE;
  if (bu_wtmp_append_path (&u, wtmp_path) < 0) return EXECUTION_FAILURE;

  int uid = bu_uid_for (user);
  if (uid >= 0)
    bu_lastlog_write_path (uid, line, host, lastlog_path);

  return EXECUTION_SUCCESS;
}

static int
bu_logout_cmd (WORD_LIST *args)
{
  const char *utmp_path = BU_UTMP;
  const char *wtmp_path = BU_WTMP;
  while (args && args->word && args->word->word && args->word->word[0] == '-')
    {
      const char *opt = args->word->word;
      if (strcmp (opt, "-u") == 0 || strcmp (opt, "--utmp") == 0)
        {
          if (!args->next) { builtin_error ("%s needs PATH", opt); return EX_USAGE; }
          utmp_path = args->next->word->word;
          args = args->next->next;
        }
      else if (strcmp (opt, "-w") == 0 || strcmp (opt, "--wtmp") == 0)
        {
          if (!args->next) { builtin_error ("%s needs PATH", opt); return EX_USAGE; }
          wtmp_path = args->next->word->word;
          args = args->next->next;
        }
      else if (strcmp (opt, "--") == 0)
        {
          args = args->next;
          break;
        }
      else
        {
          builtin_error ("logout: unknown flag: %s", opt);
          return EX_USAGE;
        }
    }
  if (!args) { builtin_error ("logout needs [-u UTMP] [-w WTMP] LINE"); return EX_USAGE; }
  const char *line = args->word->word;

  /* Find existing entry and turn it DEAD. flock(LOCK_EX) so a
     concurrent bu_utmp_write doesn't move the same entry under us. */
  int fd = open (utmp_path, O_RDWR | O_CLOEXEC);
  if (fd < 0)
    { builtin_error ("open %s: %s", utmp_path, strerror (errno)); return EXECUTION_FAILURE; }
  if (flock (fd, LOCK_EX) < 0 && errno != ENOSYS)
    { builtin_error ("flock %s: %s", utmp_path, strerror (errno)); close (fd); return EXECUTION_FAILURE; }
  struct utmp u;
  off_t pos = 0;
  ssize_t n;
  int rewrote = 0;
  while ((n = read (fd, &u, sizeof u)) == sizeof u)
    {
      if (strncmp (u.ut_line, line, UT_LINESIZE) == 0
          && (u.ut_type == USER_PROCESS || u.ut_type == LOGIN_PROCESS))
        {
          u.ut_type = DEAD_PROCESS;
          memset (u.ut_user, 0, sizeof u.ut_user);
          memset (u.ut_host, 0, sizeof u.ut_host);
          struct timespec ts;
          clock_gettime (CLOCK_REALTIME, &ts);
          u.ut_tv.tv_sec  = (int32_t) ts.tv_sec;
          u.ut_tv.tv_usec = (int32_t) (ts.tv_nsec / 1000);
          if (lseek (fd, pos, SEEK_SET) < 0
              || write (fd, &u, sizeof u) != sizeof u)
            { close (fd); return EXECUTION_FAILURE; }
          rewrote = 1;
          break;
        }
      pos += sizeof u;
    }
  close (fd);
  if (rewrote)
    bu_wtmp_append_path (&u, wtmp_path);
  return EXECUTION_SUCCESS;
}

static int
bu_boot_cmd (WORD_LIST *args)
{
  const char *path = args ? args->word->word : BU_WTMP;
  struct utmp u;
  bu_fill_common (&u, "reboot", "~", "");
  u.ut_type = BOOT_TIME;
  return bu_wtmp_append_path (&u, path) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bu_shutdown_cmd (WORD_LIST *args)
{
  const char *path = args ? args->word->word : BU_WTMP;
  struct utmp u;
  bu_fill_common (&u, "shutdown", "~", "");
  u.ut_type = RUN_LVL;
  return bu_wtmp_append_path (&u, path) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* btmp — failed-login log. Same on-disk format as wtmp; consumed
 * by `last -f /var/log/btmp` (a.k.a. `lastb`). 0600 (root-only) by
 * convention since it logs failed username attempts which can leak
 * information. See research/bash_linux/SECURITY-REVIEW.md §3.10.
 *
 * Subforms:
 *   utmp btmp USER LINE [HOST]      record a failure (legacy positional)
 *   utmp btmp record [-f PATH] USER LINE [HOST]  same, with explicit verb
 *   utmp btmp read [-f PATH] [-n N]  emit recent failures (lastb-style)
 */
static int
bu_btmp_read (WORD_LIST *args)
{
  int limit = 0;        /* 0 = no limit */
  const char *path = BU_BTMP;
  for (WORD_LIST *p = args; p; p = p->next) {
    if (strcmp (p->word->word, "-n") == 0 && p->next) {
      limit = atoi (p->next->word->word);
      p = p->next;
    } else if (strcmp (p->word->word, "-f") == 0 && p->next) {
      path = p->next->word->word;
      p = p->next;
    }
  }
  int fd = open (path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    if (errno == ENOENT) return EXECUTION_SUCCESS;       /* nothing logged yet */
    builtin_error ("open %s: %s", path, strerror (errno));
    return EXECUTION_FAILURE;
  }
  /* Stream the most recent N records; btmp grows unbounded but a single
     struct utmp at a time keeps the in-memory footprint constant. */
  off_t sz = lseek (fd, 0, SEEK_END);
  if (sz < 0) {
    close (fd);
    return EXECUTION_SUCCESS;
  }
  /* LOG-PARSER-AUDIT.md Wave 2 lastb.sh #4: on a torn-write tail
     (sz % sizeof != 0), still emit every WHOLE record we have and
     diagnose the trailing fragment.  Old code returned EXECUTION_SUCCESS
     with no output, silently dropping the entire visible history. */
  size_t trailing = (size_t) sz % sizeof (struct utmp);
  size_t n_records = (size_t) sz / sizeof (struct utmp);
  if (n_records == 0) {
    if (trailing > 0)
      builtin_warning ("%s: %zu trailing byte(s) past last whole record "
                       "(torn write?) — no records to display",
                       path, trailing);
    close (fd);
    return EXECUTION_SUCCESS;
  }
  size_t start = 0;
  if (limit > 0 && (size_t) limit < n_records) start = n_records - (size_t) limit;
  if (lseek (fd, (off_t) (start * sizeof (struct utmp)), SEEK_SET) < 0) {
    close (fd);
    builtin_error ("lseek: %s", strerror (errno));
    return EXECUTION_FAILURE;
  }
  struct utmp u;
  while (read (fd, &u, sizeof u) == sizeof u) {
    char tbuf[32];
    time_t t = (time_t) u.ut_tv.tv_sec;
    struct tm tm;
    localtime_r (&t, &tm);
    strftime (tbuf, sizeof tbuf, "%Y-%m-%d %H:%M:%S", &tm);
    /* LOG-PARSER-AUDIT.md Wave 2 lastb.sh #1 + #3: scrub
       attacker-controlled ut_user / ut_line / ut_host into stack buffers
       (replacing iscntrl/NUL/DEL with space) before printf, so terminal-
       injection bytes and embedded NULs don't reach the operator TTY raw. */
    char user_s[UT_NAMESIZE + 1];
    char line_s[UT_LINESIZE + 1];
    char host_s[UT_HOSTSIZE + 1];
    bu_scrub_field (user_s, sizeof user_s, u.ut_user, UT_NAMESIZE);
    bu_scrub_field (line_s, sizeof line_s, u.ut_line, UT_LINESIZE);
    bu_scrub_field (host_s, sizeof host_s, u.ut_host, UT_HOSTSIZE);
    printf ("%-8s %-12s %-16s %s\n", user_s, line_s, host_s, tbuf);
  }
  if (trailing > 0)
    builtin_warning ("%s: %zu trailing byte(s) past last whole record "
                     "(torn write?) — %zu whole record(s) emitted above",
                     path, trailing, n_records);
  close (fd);
  return EXECUTION_SUCCESS;
}

static int
bu_btmp_cmd (WORD_LIST *args)
{
  /* Dispatch the explicit verb forms first, fall through to the
     legacy positional 'btmp USER LINE [HOST]' otherwise. */
  if (args && !strcmp (args->word->word, "read"))
    return bu_btmp_read (args->next);
  if (args && !strcmp (args->word->word, "record")) {
    args = args->next;
    /* Fall through to the record path below. */
  }
  const char *path = BU_BTMP;
  if (args && !strcmp (args->word->word, "-f")) {
    if (!args->next)
      { builtin_error ("btmp -f needs PATH"); return EX_USAGE; }
    path = args->next->word->word;
    args = args->next->next;
  }
  if (!args || !args->next)
    { builtin_error ("btmp needs USER LINE [HOST] (or 'read [-n N]')");
      return EX_USAGE; }
  const char *user = args->word->word;
  const char *line = args->next->word->word;
  const char *host = (args->next->next) ? args->next->next->word->word : "";

  struct utmp u;
  bu_fill_common (&u, user, line, host);
  u.ut_type = USER_PROCESS;   /* same as a successful login record */

  /* Append directly — btmp is append-only by convention. */
  int fd = open (path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
  if (fd < 0)
    { builtin_error ("open %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
  if (write (fd, &u, sizeof u) != (ssize_t) sizeof u)
    { close (fd); builtin_error ("btmp write: %s", strerror (errno)); return EXECUTION_FAILURE; }
  close (fd);
  return EXECUTION_SUCCESS;
}

static int
bu_dump_cmd (WORD_LIST *args)
{
  const char *path = args ? args->word->word : BU_UTMP;
  int fd = open (path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    { builtin_error ("open %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
  struct utmp u;
  ssize_t n;
  while ((n = read (fd, &u, sizeof u)) == sizeof u)
    {
      if (u.ut_type != USER_PROCESS) continue;
      char tbuf[32];
      time_t t = (time_t) u.ut_tv.tv_sec;
      struct tm tm;
      localtime_r (&t, &tm);
      strftime (tbuf, sizeof tbuf, "%Y-%m-%d %H:%M:%S", &tm);
      /* LOG-PARSER-AUDIT.md Wave 2 last.sh #2: scrub embedded
         iscntrl/NUL/CR/LF in ut_user / ut_line / ut_host into
         stack buffers before printf.  Without this an embedded LF in
         ut_host splits one wtmp record across two stdout lines and
         skews last.sh's line-oriented USER_FILTER (and any other
         line-oriented downstream consumer of `utmp dump`). */
      char user_s[UT_NAMESIZE + 1];
      char line_s[UT_LINESIZE + 1];
      char host_s[UT_HOSTSIZE + 1];
      bu_scrub_field (user_s, sizeof user_s, u.ut_user, UT_NAMESIZE);
      bu_scrub_field (line_s, sizeof line_s, u.ut_line, UT_LINESIZE);
      bu_scrub_field (host_s, sizeof host_s, u.ut_host, UT_HOSTSIZE);
      printf ("%-8s %-12s %-16s %s pid=%d\n",
              user_s, line_s, host_s, tbuf, u.ut_pid);
    }
  close (fd);
  return EXECUTION_SUCCESS;
}

int
utmp_builtin (WORD_LIST *list)
{
  /* LOG-PARSER-AUDIT.md Wave 2 lastb.sh #2: pin LC_ALL=C so
     iscntrl() (bu_scrub_field) and any later strcasecmp / isspace
     against attacker-controlled ut_user / ut_host bytes stay byte-
     exact regardless of inherited LC_CTYPE.  Current read path is
     byte-exact (memcmp / strncmp); this is a tripwire so a future
     locale-sensitive matcher is loud, not silent. */
  setlocale (LC_ALL, "C");

  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;
  if (strcmp (cmd, "login")    == 0) return bu_login_cmd (args);
  if (strcmp (cmd, "logout")   == 0) return bu_logout_cmd (args);
  if (strcmp (cmd, "boot")     == 0) return bu_boot_cmd (args);
  if (strcmp (cmd, "shutdown") == 0) return bu_shutdown_cmd (args);
  if (strcmp (cmd, "btmp")     == 0) return bu_btmp_cmd (args);
  if (strcmp (cmd, "lastlog")  == 0) return bu_lastlog_cmd (args);
  if (strcmp (cmd, "dump")     == 0) return bu_dump_cmd (args);
  builtin_error ("unknown subcommand: %s", cmd);
  return EX_USAGE;
}

char *utmp_doc[] = {
  "utmp / wtmp / lastlog records for who, last, lastlog.",
  "",
  "    utmp login [-u UTMP] [-w WTMP] [-l LASTLOG] USER LINE [HOST]",
  "    utmp logout [-u UTMP] [-w WTMP] LINE",
  "    utmp boot [WTMP]              append BOOT_TIME to wtmp",
  "    utmp shutdown [WTMP]          append RUN_LVL to wtmp",
  "    utmp dump [PATH]              who-style listing of utmp/wtmp",
  "    utmp lastlog dump [PATH]      dump non-empty lastlog records",
  "    utmp btmp record [-f PATH] USER LINE [HOST]",
  "    utmp btmp read [-f PATH] [-n N]",
  "",
  "Files: /var/run/utmp, /var/log/wtmp, /var/log/lastlog",
  (char *)NULL
};

struct builtin utmp_struct = {
  "utmp",
  utmp_builtin,
  BUILTIN_ENABLED,
  utmp_doc,
  "utmp login|logout|boot|shutdown|dump|lastlog ARGS...",
  0
};
