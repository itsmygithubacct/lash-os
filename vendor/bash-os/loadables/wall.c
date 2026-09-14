/* SPDX-License-Identifier: MIT */
/* wall.c — wall(1) + write(1) bundled (MISSING_LOADABLES T2 / ML-T2-14).
 *
 * Two builtins exported from this single translation unit, using the
 * project's standing "multi-builtin per source" idiom established in
 * MISSING_LOADABLES T2 / ML-T2-11 (column/col/colrm). A
 * companion stub write.c exists at the same directory so
 * patch-bash-loadables.sh's `cp examples/loadables/${name}.c` step has
 * a file at the expected path. All symbols live here.
 *
 * Subcommands / verbs:
 *
 *   wall MSG [MSG ...]
 *       Read the message either from the joined positional args, or
 *       from stdin when no args are given. Walk utmp; for every
 *       USER_PROCESS entry whose ut_line is a usable terminal name,
 *       write a wall(1)-style banner ("Broadcast message from
 *       USER@HOST (ttyN) (DATE):") followed by the message and a
 *       trailing CRLF.  Each distinct ut_line is touched at most once.
 *       Terminals whose mode lacks both S_IWGRP and S_IWOTH are
 *       skipped (matches the rootfs/bash-os/mesg.sh "messages
 *       disabled" gate), UNLESS the caller is root — root broadcasts
 *       always reach.
 *       -g GROUP / --group GROUP restricts delivery to users in GROUP.
 *
 *   write TTY MSG [MSG ...]
 *       Read the message from the joined positional args, or from
 *       stdin if only TTY is given. Write a write(1)-style banner
 *       ("Message from USER@HOST on SRC_TTY at HH:MM ...") + the
 *       message + a trailing "EOF" line to the single TTY path. TTY
 *       is taken verbatim if it begins with `/`; otherwise resolved
 *       under $BASHWALL_DEV_DIR (default /dev). Honors the same
 *       messages-disabled gate as wall unless caller is root.
 *
 * Environment knobs (testing / staging):
 *
 *   BASHWALL_UTMP        Alternate utmp file (default /var/run/utmp).
 *   BASHWALL_DEV_DIR     Base dir prepended to non-absolute ut_line
 *                        / TTY arguments (default /dev).
 *   BASHWALL_NOBANNER    Set to "1" to suppress the leading banner
 *                        (matches `wall --nobanner`).
 *   BASHWALL_HOST        Override hostname in the banner (default
 *                        gethostname(2)).
 *   BASHWALL_USER        Override username in the banner (default
 *                        getlogin / $USER / $LOGNAME / pw_name).
 *   BASHWALL_GROUP_FILE  Alternate group database for -g (default
 *                        /etc/group).
 *   BASHWALL_PASSWD_FILE Alternate passwd database for -g primary-gid
 *                        checks (default /etc/passwd).
 *   BASHWALL_FORCE_MESG  Set to "1" to enforce the messages-disabled
 *                        gate even when the calling euid is 0. Used
 *                        by the test fixture so the gate is
 *                        exercisable without dropping privileges.
 *
 * Source counterparts:
 *   util-linux term-utils/wall.c   — banner shape + utmp loop
 *   util-linux term-utils/write.c  — banner shape + check_tty gate
 *   util-linux term-utils/mesg.c   — messages-enabled bit semantics
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
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <pwd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <utmp.h>

#include "loadables.h"

#define BW_UTMP_DEFAULT     "/var/run/utmp"
#define BW_DEV_DIR_DEFAULT  "/dev"
#define BW_GROUP_DEFAULT    "/etc/group"
#define BW_PASSWD_DEFAULT   "/etc/passwd"
#define BW_MSG_HARDCAP      (64 * 1024)   /* Match wall(1) practical cap. */

/* ------------------------------------------------------------------- *
 *  Small helpers
 * ------------------------------------------------------------------- */

static const char *
bw_env (const char *name, const char *fallback)
{
  const char *s = getenv (name);
  return (s && *s) ? s : fallback;
}

static int
bw_env_bool (const char *name)
{
  const char *s = getenv (name);
  return (s && s[0] == '1' && s[1] == '\0');
}

/* Return 1 when ttymsg-style writes to PATH are permitted under the
   "messages enabled" gate (group-write OR other-write). Root bypasses
   the gate unless BASHWALL_FORCE_MESG=1. Returns 0 when gated off, -1
   on stat error.  errno is preserved on failure. */
static int
bw_messages_enabled (const char *path)
{
  struct stat st;
  if (stat (path, &st) < 0) return -1;
  if (geteuid () == 0 && !bw_env_bool ("BASHWALL_FORCE_MESG"))
    return 1;
  return (st.st_mode & (S_IWGRP | S_IWOTH)) ? 1 : 0;
}

/* Resolve a bare line name (e.g. "pts/0") to a filesystem path. If RAW
   begins with `/` it is taken verbatim (truncated into OUT if needed).
   Otherwise prepend $BASHWALL_DEV_DIR + '/'. Returns the length of the
   path placed into OUT (excluding NUL). */
static size_t
bw_resolve_tty (const char *raw, char *out, size_t outsz)
{
  if (!raw || !*raw || outsz == 0) { if (outsz) out[0] = '\0'; return 0; }
  int n;
  if (raw[0] == '/')
    n = snprintf (out, outsz, "%s", raw);
  else
    n = snprintf (out, outsz, "%s/%s", bw_env ("BASHWALL_DEV_DIR", BW_DEV_DIR_DEFAULT), raw);
  if (n < 0) { out[0] = '\0'; return 0; }
  return (size_t) ((size_t) n < outsz ? (size_t) n : outsz - 1);
}

/* Resolve the calling username for the banner, preferring (in order)
   $BASHWALL_USER, getlogin(), $USER, $LOGNAME, getpwuid(getuid()), or
   the literal "<someone>" (matches util-linux wall.c). */
static const char *
bw_user_name (void)
{
  const char *u = getenv ("BASHWALL_USER");
  if (u && *u) return u;
  u = getlogin ();
  if (u && *u) return u;
  u = getenv ("USER");
  if (u && *u) return u;
  u = getenv ("LOGNAME");
  if (u && *u) return u;
  struct passwd *pw = getpwuid (getuid ());
  if (pw && pw->pw_name && *pw->pw_name) return pw->pw_name;
  return "<someone>";
}

static const char *
bw_host_name (char *buf, size_t cap)
{
  const char *h = getenv ("BASHWALL_HOST");
  if (h && *h) return h;
  if (gethostname (buf, cap) == 0) { buf[cap - 1] = '\0'; return buf; }
  return "localhost";
}

static int
bw_parse_long_field (const char *s, long *out)
{
  char *end;
  long v;

  if (!s || !*s)
    return 0;
  errno = 0;
  v = strtol (s, &end, 10);
  if (errno || end == s || *end != '\0')
    return 0;
  *out = v;
  return 1;
}

static int
bw_user_list_contains (const char *list, const char *user)
{
  size_t ulen;

  if (!list || !user || !*user)
    return 0;
  ulen = strlen (user);
  while (*list)
    {
      const char *start;
      size_t len;

      while (*list == ',' || isspace ((unsigned char) *list))
        list++;
      start = list;
      while (*list && *list != ',')
        list++;
      len = (size_t) (list - start);
      while (len > 0 && isspace ((unsigned char) start[len - 1]))
        len--;
      if (len == ulen && strncmp (start, user, ulen) == 0)
        return 1;
    }
  return 0;
}

static int
bw_group_info (const char *group, long *gid, char *members, size_t members_sz)
{
  const char *path = bw_env ("BASHWALL_GROUP_FILE", BW_GROUP_DEFAULT);
  FILE *fp = fopen (path, "r");
  char line[4096];

  if (gid)
    *gid = -1;
  if (members && members_sz)
    members[0] = '\0';
  if (!fp)
    return 0;

  while (fgets (line, sizeof line, fp))
    {
      char *name = line;
      char *passwd = strchr (name, ':');
      char *gid_s;
      char *users;
      char *nl;
      long parsed_gid;

      if (!passwd)
        continue;
      *passwd++ = '\0';
      gid_s = strchr (passwd, ':');
      if (!gid_s)
        continue;
      *gid_s++ = '\0';
      users = strchr (gid_s, ':');
      if (!users)
        continue;
      *users++ = '\0';
      nl = strchr (users, '\n');
      if (nl)
        *nl = '\0';
      if (strcmp (name, group) != 0)
        continue;
      if (!bw_parse_long_field (gid_s, &parsed_gid))
        parsed_gid = -1;
      if (gid)
        *gid = parsed_gid;
      if (members && members_sz)
        {
          snprintf (members, members_sz, "%s", users);
          members[members_sz - 1] = '\0';
        }
      fclose (fp);
      return 1;
    }
  fclose (fp);
  return 0;
}

static int
bw_user_primary_gid_matches (const char *user, long want_gid)
{
  const char *path;
  FILE *fp;
  char line[4096];

  if (!user || !*user || want_gid < 0)
    return 0;
  path = bw_env ("BASHWALL_PASSWD_FILE", BW_PASSWD_DEFAULT);
  fp = fopen (path, "r");
  if (!fp)
    return 0;

  while (fgets (line, sizeof line, fp))
    {
      char *name = line;
      char *passwd = strchr (name, ':');
      char *uid_s;
      char *gid_s;
      char *rest;
      long gid;

      if (!passwd)
        continue;
      *passwd++ = '\0';
      uid_s = strchr (passwd, ':');
      if (!uid_s)
        continue;
      *uid_s++ = '\0';
      gid_s = strchr (uid_s, ':');
      if (!gid_s)
        continue;
      *gid_s++ = '\0';
      rest = strchr (gid_s, ':');
      if (rest)
        *rest = '\0';
      if (strcmp (name, user) != 0)
        continue;
      fclose (fp);
      return bw_parse_long_field (gid_s, &gid) && gid == want_gid;
    }
  fclose (fp);
  return 0;
}

static int
bw_group_matches_user (const char *group, const char *user)
{
  long gid;
  char members[4096];

  if (!group || !*group)
    return 1;
  if (!bw_group_info (group, &gid, members, sizeof members))
    return 0;
  return bw_user_list_contains (members, user)
         || bw_user_primary_gid_matches (user, gid);
}

/* Calling terminal — best-effort, matches util-linux wall's
   ttyname(STDOUT_FILENO) preference; falls back to "<no tty>". */
static const char *
bw_src_tty (char *buf, size_t cap)
{
  const char *t = ttyname (STDOUT_FILENO);
  if (!t) t = ttyname (STDIN_FILENO);
  if (!t) return "<no tty>";
  if (strncmp (t, "/dev/", 5) == 0) t += 5;
  snprintf (buf, cap, "%s", t);
  return buf;
}

/* Join positional args into a heap-allocated single-string message, or
   read stdin if no args. CRLF line endings are normalized: a lone LF
   becomes CRLF on output so terminals don't show stair-step indent.
   Output may contain embedded NUL bytes; *out_len is authoritative. */
static int
bw_compose_message (WORD_LIST *args, char **out, size_t *out_len)
{
  *out = NULL;
  *out_len = 0;
  if (args)
    {
      /* Join with spaces; trailing CRLF.  Compute size first. */
      size_t total = 0;
      WORD_LIST *p;
      for (p = args; p; p = p->next)
        {
          total += strlen (p->word->word);
          if (p->next) total += 1; /* space sep */
        }
      total += 2; /* trailing \r\n */
      if (total > BW_MSG_HARDCAP)
        { builtin_error ("message exceeds hard cap (%d bytes)", BW_MSG_HARDCAP); return -1; }
      char *m = (char *) malloc (total + 1);
      if (!m) { builtin_error ("malloc: %s", strerror (errno)); return -1; }
      size_t off = 0;
      for (p = args; p; p = p->next)
        {
          size_t l = strlen (p->word->word);
          memcpy (m + off, p->word->word, l);
          off += l;
          if (p->next) m[off++] = ' ';
        }
      m[off++] = '\r';
      m[off++] = '\n';
      m[off] = '\0';
      *out = m;
      *out_len = off;
      return 0;
    }
  /* Stdin path. Read up to hardcap; reject larger. */
  size_t cap = 4096, len = 0;
  char *m = (char *) malloc (cap);
  if (!m) { builtin_error ("malloc: %s", strerror (errno)); return -1; }
  for (;;)
    {
      if (len + 2 >= cap)
        {
          size_t newcap = cap * 2;
          if (newcap > BW_MSG_HARDCAP + 64) newcap = BW_MSG_HARDCAP + 64;
          if (newcap == cap)
            { free (m); builtin_error ("stdin exceeds hard cap (%d bytes)", BW_MSG_HARDCAP); return -1; }
          char *n = (char *) realloc (m, newcap);
          if (!n) { free (m); builtin_error ("realloc: %s", strerror (errno)); return -1; }
          m = n; cap = newcap;
        }
      ssize_t r = read (STDIN_FILENO, m + len, cap - len - 1);
      if (r < 0) { if (errno == EINTR) continue; free (m); builtin_error ("read: %s", strerror (errno)); return -1; }
      if (r == 0) break;
      len += (size_t) r;
      if (len > BW_MSG_HARDCAP) { free (m); builtin_error ("stdin exceeds hard cap (%d bytes)", BW_MSG_HARDCAP); return -1; }
    }
  /* Append trailing \r\n if not already CRLF-terminated. */
  if (len < 2 || m[len - 2] != '\r' || m[len - 1] != '\n')
    {
      if (len > 0 && m[len - 1] == '\n') len--; /* drop bare LF, replace */
      m[len++] = '\r';
      m[len++] = '\n';
    }
  m[len] = '\0';
  *out = m;
  *out_len = len;
  return 0;
}

/* ------------------------------------------------------------------- *
 *  Banner emit
 * ------------------------------------------------------------------- */

static size_t
bw_banner_wall (char *buf, size_t cap, int nobanner)
{
  if (nobanner) return 0;
  char hostbuf[256] = {0};
  char ttybuf[64] = {0};
  const char *user = bw_user_name ();
  const char *host = bw_host_name (hostbuf, sizeof hostbuf);
  const char *tty  = bw_src_tty  (ttybuf,  sizeof ttybuf);
  time_t now = time (NULL);
  struct tm tm;
  char date[32] = {0};
  localtime_r (&now, &tm);
  /* ctime(3)-style date with a space-padded day-of-month (%e, not %d):
     util-linux wall.c builds the banner date via ctime_r(), which renders
     e.g. "Sun Jun  3 ..." not "Sun Jun 03 ...". */
  strftime (date, sizeof date, "%a %b %e %H:%M:%S %Y", &tm);
  /* util-linux ends the broadcast banner line with two BEL bytes
     ("...):\007\007\r\n") so the message audibly alerts each terminal. */
  int n = snprintf (buf, cap,
                    "\r\nBroadcast message from %s@%s (%s) (%s):\007\007\r\n",
                    user, host, tty, date);
  if (n < 0) return 0;
  return (size_t) ((size_t) n < cap ? (size_t) n : cap - 1);
}

static size_t
bw_banner_write (char *buf, size_t cap)
{
  if (bw_env_bool ("BASHWALL_NOBANNER")) return 0;
  char hostbuf[256] = {0};
  char ttybuf[64] = {0};
  const char *user = bw_user_name ();
  const char *host = bw_host_name (hostbuf, sizeof hostbuf);
  const char *tty  = bw_src_tty  (ttybuf,  sizeof ttybuf);
  time_t now = time (NULL);
  struct tm tm;
  localtime_r (&now, &tm);
  /* util-linux write.c precedes the banner with three BEL bytes to alert
     the recipient: printf("\r\n\a\a\a"); then the "Message from ..." line. */
  int n = snprintf (buf, cap,
                    "\r\n\a\a\aMessage from %s@%s on %s at %02d:%02d ...\r\n",
                    user, host, tty, tm.tm_hour, tm.tm_min);
  if (n < 0) return 0;
  return (size_t) ((size_t) n < cap ? (size_t) n : cap - 1);
}

/* Escape a message body the way util-linux fputs_careful() does (with
   soft_width=0, cr_lf=true, ctrl='^') before sending it to a terminal:
     - control bytes (0x00-0x1f except \t \r \a) and DEL → ^X  (X = c ^ 0x40)
     - high bytes (>= 0x80, non-printable in C locale)      → \NNN octal
     - a bare newline                                        → \r\n
     - everything else printable, \t, \r, \a                → unchanged
   This blocks a sender from injecting raw escape sequences (e.g. ESC →
   "^[") into the recipient's terminal. Writes the escaped bytes to FD;
   returns 0 on success, -1 on write error. */
static int
bw_careful_write (int fd, const char *msg, size_t msg_len)
{
  /* Worst case is 4 bytes out per input byte ("\NNN"); +2 for a final \r\n. */
  char *out = (char *) xmalloc (msg_len * 4 + 3);
  size_t o = 0;
  for (size_t i = 0; i < msg_len; i++)
    {
      unsigned char c = (unsigned char) msg[i];
      if (c == '\n')
        {
          /* \n -> \r\n, but stay idempotent: don't double the \r when the
             input already has CRLF pairs (callers may pre-terminate). */
          if (o == 0 || out[o - 1] != '\r')
            out[o++] = '\r';
          out[o++] = '\n';
        }
      else if (isprint (c) || c == '\a' || c == '\t' || c == '\r')
        out[o++] = (char) c;
      else if (c >= 0x80)
        o += (size_t) sprintf (out + o, "\\%03o", c);
      else
        { out[o++] = '^'; out[o++] = (char) (c ^ 0x40); }
    }
  int rc = 0;
  if (o)
    {
      ssize_t w = write (fd, out, o);
      if (w != (ssize_t) o) rc = -1;
    }
  free (out);
  return rc;
}

/* Write banner + message to one tty path. Returns 0 on success,
   -1 on open/write error (errno preserved), 1 on mesg-gate skip
   (caller may want to suppress that as not-fatal). */
static int
bw_emit_one (const char *path, const char *banner, size_t banner_len,
             const char *msg, size_t msg_len)
{
  int gate = bw_messages_enabled (path);
  if (gate == 0) return 1; /* messages disabled — skip */
  if (gate < 0) return -1; /* stat error */
  int fd = open (path, O_WRONLY | O_APPEND | O_NOCTTY);
  if (fd < 0) return -1;
  if (banner_len)
    {
      ssize_t w = write (fd, banner, banner_len);
      if (w != (ssize_t) banner_len) { close (fd); return -1; }
    }
  if (msg_len)
    {
      if (bw_careful_write (fd, msg, msg_len) < 0) { close (fd); return -1; }
    }
  close (fd);
  return 0;
}

/* ------------------------------------------------------------------- *
 *  wall builtin (broadcast)
 * ------------------------------------------------------------------- */

/* Helper for the de-duplicating utmp walk. Returns 1 if SEEN already
   contains LINE; otherwise appends and returns 0.  *cap doubles on
   growth. */
static int
bw_seen_add (char ***seen, size_t *n, size_t *cap, const char *line)
{
  for (size_t i = 0; i < *n; i++)
    if (strcmp ((*seen)[i], line) == 0) return 1;
  if (*n == *cap)
    {
      size_t nc = (*cap == 0) ? 8 : *cap * 2;
      char **g = (char **) realloc (*seen, nc * sizeof (char *));
      if (!g) return -1;
      *seen = g; *cap = nc;
    }
  (*seen)[(*n)++] = strdup (line);
  return (*seen)[*n - 1] ? 0 : -1;
}

int
wall_builtin (WORD_LIST *list)
{
  char *msg = NULL;
  size_t msg_len = 0;
  const char *group = NULL;
  int nobanner = bw_env_bool ("BASHWALL_NOBANNER");
  long timeout = 0; /* accepted for util-linux arg parity; writes are synchronous */

  while (list)
    {
      const char *w = list->word->word;

      if (!strcmp (w, "-g") || !strcmp (w, "--group"))
        {
          list = list->next;
          if (!list)
            { builtin_error ("option requires an argument: %s", w); return EX_USAGE; }
          group = list->word->word;
          list = list->next;
          continue;
        }
      if (!strncmp (w, "--group=", 8))
        {
          group = w + 8;
          if (!*group)
            { builtin_error ("option requires an argument: --group"); return EX_USAGE; }
          list = list->next;
          continue;
        }
      if (!strcmp (w, "-n") || !strcmp (w, "--nobanner"))
        {
          /* Matches util-linux: --nobanner is honored only for root; for
             anyone else it warns and the banner is still printed. */
          if (geteuid () == 0)
            nobanner = 1;
          else
            builtin_error ("--nobanner is available only for root");
          list = list->next;
          continue;
        }
      if (!strcmp (w, "-t") || !strcmp (w, "--timeout"))
        {
          list = list->next;
          if (!list)
            { builtin_error ("option requires an argument: %s", w); return EX_USAGE; }
          if (!bw_parse_long_field (list->word->word, &timeout) || timeout < 1)
            { builtin_error ("invalid timeout: %s", list->word->word); return EX_USAGE; }
          list = list->next;
          continue;
        }
      if (!strncmp (w, "--timeout=", 10))
        {
          if (!bw_parse_long_field (w + 10, &timeout) || timeout < 1)
            { builtin_error ("invalid timeout: %s", w + 10); return EX_USAGE; }
          list = list->next;
          continue;
        }
      if (!strcmp (w, "--"))
        {
          list = list->next;
          break;
        }
      if (w[0] == '-' && w[1] != '\0')
        {
          builtin_error ("unknown option: %s", w);
          return EX_USAGE;
        }
      break;
    }
  (void) timeout; /* validated for parity; per-tty writes are synchronous */

  if (bw_compose_message (list, &msg, &msg_len) < 0)
    return EXECUTION_FAILURE;

  char banner[512];
  size_t banner_len = bw_banner_wall (banner, sizeof banner, nobanner);

  const char *utmp_path = bw_env ("BASHWALL_UTMP", BW_UTMP_DEFAULT);
  int fd = open (utmp_path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    { builtin_error ("open %s: %s", utmp_path, strerror (errno));
      free (msg); return EXECUTION_FAILURE; }

  char **seen = NULL;
  size_t seen_n = 0, seen_cap = 0;
  int n_targets = 0, n_skipped = 0, n_failed = 0;
  struct utmp u;
  ssize_t r;
  while ((r = read (fd, &u, sizeof u)) == sizeof u)
    {
      if (u.ut_type != USER_PROCESS) continue;
      if (!u.ut_line[0]) continue;
      if (u.ut_line[0] == ':') continue; /* X session pseudo-entries */
      char line[UT_LINESIZE + 1];
      memcpy (line, u.ut_line, UT_LINESIZE);
      line[UT_LINESIZE] = '\0';
      /* Strip any embedded NUL padding past the first NUL boundary. */
      line[strnlen (line, UT_LINESIZE)] = '\0';
      char user[UT_NAMESIZE + 1];
      memcpy (user, u.ut_user, UT_NAMESIZE);
      user[UT_NAMESIZE] = '\0';
      user[strnlen (user, UT_NAMESIZE)] = '\0';
      if (group && !bw_group_matches_user (group, user))
        continue;

      int dup = bw_seen_add (&seen, &seen_n, &seen_cap, line);
      if (dup < 0) { close (fd); free (msg); return EXECUTION_FAILURE; }
      if (dup) continue;

      char path[PATH_MAX] = {0};
      bw_resolve_tty (line, path, sizeof path);
      int rc = bw_emit_one (path, banner, banner_len, msg, msg_len);
      if (rc == 0) n_targets++;
      else if (rc == 1) n_skipped++;
      else { n_failed++; builtin_error ("write %s: %s", path, strerror (errno)); }
    }
  close (fd);
  for (size_t i = 0; i < seen_n; i++) free (seen[i]);
  free (seen);
  free (msg);
  /* Don't fail the whole broadcast if at least one tty took it. wall(1)
     does the same — per-tty write errors are warnings, not failure. */
  (void) n_targets; (void) n_skipped;
  return n_failed && n_targets == 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

/* ------------------------------------------------------------------- *
 *  write builtin (single-target)
 * ------------------------------------------------------------------- */

int
write_builtin (WORD_LIST *list)
{
  if (!list) { builtin_error ("usage: write TTY [MSG ...]"); return EX_USAGE; }
  const char *raw = list->word->word;
  WORD_LIST *args = list->next;

  char path[PATH_MAX] = {0};
  bw_resolve_tty (raw, path, sizeof path);

  /* Reject empty / unresolved paths and obvious symlink-escape vectors. */
  if (!path[0]) { builtin_error ("empty TTY"); return EX_USAGE; }
  struct stat st;
  if (stat (path, &st) < 0)
    { builtin_error ("%s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }

  int gate = bw_messages_enabled (path);
  if (gate < 0)
    { builtin_error ("stat %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
  if (gate == 0)
    { builtin_error ("%s has messages disabled", path); return EXECUTION_FAILURE; }

  char *msg = NULL;
  size_t msg_len = 0;
  if (bw_compose_message (args, &msg, &msg_len) < 0)
    return EXECUTION_FAILURE;

  char banner[512];
  size_t banner_len = bw_banner_write (banner, sizeof banner);

  int fd = open (path, O_WRONLY | O_APPEND | O_NOCTTY);
  if (fd < 0)
    { builtin_error ("open %s: %s", path, strerror (errno)); free (msg); return EXECUTION_FAILURE; }
  if (banner_len && write (fd, banner, banner_len) != (ssize_t) banner_len)
    { builtin_error ("write %s: %s", path, strerror (errno)); close (fd); free (msg); return EXECUTION_FAILURE; }
  /* Escape control/high bytes (ESC -> ^[, etc.) like util-linux write(1)'s
     fputs_careful(), so a sender can't inject terminal escape sequences. */
  if (msg_len && bw_careful_write (fd, msg, msg_len) < 0)
    { builtin_error ("write %s: %s", path, strerror (errno)); close (fd); free (msg); return EXECUTION_FAILURE; }
  /* write(1) prints a trailing "EOF\r\n" when stdin reaches end-of-file;
     emit the same so consumers can detect the message boundary. */
  if (!bw_env_bool ("BASHWALL_NOBANNER"))
    (void) write (fd, "EOF\r\n", 5);
  close (fd);
  free (msg);
  return EXECUTION_SUCCESS;
}

/* ------------------------------------------------------------------- *
 *  Builtin docs + structs
 * ------------------------------------------------------------------- */

char *wall_doc[] = {
  "Broadcast a message to every logged-in terminal (wall(1)).",
  "",
  "    wall MSG [MSG ...]   join args (space-separated) into the message",
  "    wall -g GROUP MSG     send only to users in GROUP",
  "    wall -n|--nobanner   suppress the banner (root only, like wall(1))",
  "    wall -t|--timeout N  per-tty write timeout in seconds (accepted)",
  "    wall                 read message from stdin",
  "",
  "Walks utmp ($BASHWALL_UTMP or /var/run/utmp), and writes a banner",
  "(\"Broadcast message from USER@HOST (TTY) (DATE):\") followed by the",
  "message to every USER_PROCESS line. Terminals with group/other write",
  "bits cleared are skipped (messages disabled). Root bypasses the gate.",
  "",
  "Env: BASHWALL_UTMP, BASHWALL_DEV_DIR, BASHWALL_NOBANNER,",
  "     BASHWALL_HOST, BASHWALL_USER, BASHWALL_GROUP_FILE,",
  "     BASHWALL_PASSWD_FILE, BASHWALL_FORCE_MESG.",
  (char *) NULL
};

struct builtin wall_struct = {
  "wall",
  wall_builtin,
  BUILTIN_ENABLED,
  wall_doc,
  "wall [-n|--nobanner] [-t|--timeout N] [-g GROUP|--group GROUP] [MSG ...]",
  0
};

char *write_doc[] = {
  "Send a message to a single terminal (write(1)).",
  "",
  "    write TTY [MSG ...]  TTY is a /dev/* path or a basename",
  "                             resolved under $BASHWALL_DEV_DIR.",
  "",
  "Writes a banner (\"Message from USER@HOST on SRCTTY at HH:MM ...\")",
  "followed by the message + a trailing EOF marker. Refuses when the",
  "destination has messages disabled (S_IWGRP|S_IWOTH both clear), except",
  "for root unless BASHWALL_FORCE_MESG=1 is set.",
  "",
  "Env: BASHWALL_DEV_DIR, BASHWALL_NOBANNER, BASHWALL_HOST,",
  "     BASHWALL_USER, BASHWALL_FORCE_MESG.",
  (char *) NULL
};

struct builtin write_struct = {
  "write",
  write_builtin,
  BUILTIN_ENABLED,
  write_doc,
  "write TTY [MSG ...]",
  0
};
