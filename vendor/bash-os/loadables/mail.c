/* SPDX-License-Identifier: MIT */
/* mail.c — local mail queue + submission daemon. Loadable for bash.
 *
 * MTA track sub-ticket 6.1 (Debian-server-parity). Implements the local
 * queueing + submission path for the bash-os MTA: a durable on-disk
 * outbound queue written with the atomic-rename idiom, a UNIX-socket
 * submission daemon, and queue-inspection ops. Outbound SMTP/MX
 * delivery (6.3), alias compilation (6.2), and DKIM/SPF/DMARC (6.4-6.6)
 * are separate sub-tickets and are NOT implemented here.
 *
 * Subcommands:
 *     mail submit [-f SENDER] [--socket PATH] [--queue DIR] [--direct] [--] RCPT...
 *         Read a message on stdin and submit it. By default connects to
 *         the submission socket (a running mail-mta enqueues it). With
 *         --direct, enqueues straight into the queue dir (no daemon).
 *         Prints the queue-id on success.
 *         Exit: 0 accepted, 75 (EX_TEMPFAIL) socket absent/refused,
 *         67 (EX_NOUSER) no recipients, 2 usage.
 *
 *     mail serve --socket PATH --queue DIR [--conf FILE]
 *         Submission daemon (sv-managed). Binds the AF_UNIX socket,
 *         accepts framed submissions, enqueues each, replies with the
 *         queue-id. Clean exit on SIGINT/SIGTERM (unlinks the socket).
 *
 *     mail queue-list  [--queue DIR]        Postfix-style mailq listing.
 *     mail queue-show  QID [--queue DIR]    Dump envelope+headers+body.
 *     mail queue-delete QID|ALL [--queue DIR]   Remove queue entry(ies).
 *
 * Queue layout (per the MTA design §5):
 *     <queue>/active/<qid>/{envelope,headers,body,meta}
 * Writes stage under <queue>/active/.tmp.<pid>.<ctr>/ and rename(2) the
 * directory into place — a crash leaves only a .tmp dir, swept on reuse.
 *
 * Submission wire framing (length-prefixed, NUL-safe):
 *     "BASHMAIL1\n"
 *     "FROM <len>\n" <len bytes>
 *     "RCPT <len>\n" <len bytes>      (repeatable)
 *     "DATA <len>\n" <len bytes>
 *     "END\n"
 *   reply: "OK <qid>\n"  or  "ERR <code> <message>\n"
 *
 * --- LICENSE ---
 * MIT License. Copyright (c) 2026 bash_linux contributors.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "loadables.h"

#define BM_DEFAULT_SOCKET "/run/bash-os/mail/submit.sock"
#define BM_DEFAULT_QUEUE  "/var/lib/bash-os/mail/queue"
#define BM_DEFAULT_ALIASES    "/etc/aliases"
#define BM_DEFAULT_ALIASES_DB "/etc/aliases.db"
#define BM_DEFAULT_FWD_ROOT   "/home"
#define BM_PATH_MAX       1024
#define BM_MAX_RCPT       1000
#define BM_MAX_ADDR       1024
#define BM_MAX_MSG        (26 * 1024 * 1024)   /* 25 MiB default cap */
#define BM_LISTEN_BACKLOG 16
#define BM_EXPAND_MAXDEPTH 16

/* sysexits subset (sendmail-compatible exit codes) */
#define BM_EX_NOUSER   67
#define BM_EX_UNAVAIL  69   /* permanent delivery failure (5xx) */
#define BM_EX_TEMPFAIL 75
#define BM_EX_CONFIG   78

static volatile sig_atomic_t bm_stop = 0;

static void
bm_sigstop (int sig)
{
  (void) sig;
  bm_stop = 1;
}

/* ---- small I/O helpers --------------------------------------------- */

/* Write all n bytes; -1 on error. */
static int
bm_write_all (int fd, const void *buf, size_t n)
{
  const unsigned char *p = buf;
  while (n > 0)
    {
      ssize_t w = write (fd, p, n);
      if (w < 0)
        {
          if (errno == EINTR) continue;
          return -1;
        }
      p += w;
      n -= (size_t) w;
    }
  return 0;
}

/* Read exactly n bytes; -1 on error/short EOF. */
static int
bm_read_exact (int fd, void *buf, size_t n)
{
  unsigned char *p = buf;
  while (n > 0)
    {
      ssize_t r = read (fd, p, n);
      if (r < 0)
        {
          if (errno == EINTR) continue;
          return -1;
        }
      if (r == 0) return -1;            /* premature EOF */
      p += r;
      n -= (size_t) r;
    }
  return 0;
}

/* Read a single '\n'-terminated line (newline stripped) into buf; -1 on
 * EOF/error/overflow. Used only for short protocol header lines. */
static int
bm_read_line (int fd, char *buf, size_t cap)
{
  size_t i = 0;
  for (;;)
    {
      char c;
      ssize_t r = read (fd, &c, 1);
      if (r < 0) { if (errno == EINTR) continue; return -1; }
      if (r == 0) return -1;
      if (c == '\n') { buf[i] = '\0'; return 0; }
      if (i + 1 >= cap) return -1;
      buf[i++] = c;
    }
}

/* Read all of fd into a malloc'd buffer (NUL-safe), capped at max bytes.
 * Stores pointer+len; returns 0 ok, -1 alloc/IO error, 1 over cap. */
static int
bm_read_all_fd (int fd, unsigned char **out, size_t *outlen, size_t max)
{
  size_t cap = 65536, len = 0;
  unsigned char *buf = malloc (cap);
  if (!buf) return -1;
  for (;;)
    {
      if (len == cap)
        {
          if (cap >= max) { free (buf); return 1; }
          size_t ncap = cap * 2;
          if (ncap > max + 1) ncap = max + 1;
          unsigned char *nb = realloc (buf, ncap);
          if (!nb) { free (buf); return -1; }
          buf = nb; cap = ncap;
        }
      ssize_t r = read (fd, buf + len, cap - len);
      if (r < 0) { if (errno == EINTR) continue; free (buf); return -1; }
      if (r == 0) break;
      len += (size_t) r;
      if (len > max) { free (buf); return 1; }
    }
  *out = buf;
  *outlen = len;
  return 0;
}

/* mkdir -p with mode; EEXIST is success. */
static int
bm_mkdir_p (const char *path, mode_t mode)
{
  char tmp[BM_PATH_MAX];
  size_t n = strlen (path);
  if (n == 0 || n >= sizeof tmp) return -1;
  memcpy (tmp, path, n + 1);
  for (char *p = tmp + 1; *p; p++)
    {
      if (*p == '/')
        {
          *p = '\0';
          if (mkdir (tmp, mode) < 0 && errno != EEXIST) return -1;
          *p = '/';
        }
    }
  if (mkdir (tmp, mode) < 0 && errno != EEXIST) return -1;
  return 0;
}

/* Write buf to dir/name, fsync, 0600. -1 on error. */
static int
bm_write_member (const char *dir, const char *name,
                 const void *buf, size_t n)
{
  char path[BM_PATH_MAX];
  if (snprintf (path, sizeof path, "%s/%s", dir, name) >= (int) sizeof path)
    return -1;
  int fd = open (path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) return -1;
  if (bm_write_all (fd, buf, n) < 0) { close (fd); return -1; }
  (void) fsync (fd);
  if (close (fd) < 0) return -1;
  return 0;
}

/* Recursive remove of a (shallow) queue entry directory. */
static int
bm_rmrf (const char *path)
{
  DIR *d = opendir (path);
  if (d)
    {
      struct dirent *e;
      char child[BM_PATH_MAX];
      while ((e = readdir (d)))
        {
          if (!strcmp (e->d_name, ".") || !strcmp (e->d_name, "..")) continue;
          if (snprintf (child, sizeof child, "%s/%s", path, e->d_name)
              >= (int) sizeof child) continue;
          if (unlink (child) < 0 && errno == EISDIR)
            bm_rmrf (child);
        }
      closedir (d);
    }
  return rmdir (path);
}

/* ---- queue id + enqueue -------------------------------------------- */

/* Generate a Postfix-ish queue id into buf (uppercase hex of time, pid,
 * and a per-process counter). */
static void
bm_make_qid (char *buf, size_t cap)
{
  static unsigned ctr = 0;
  time_t now = time (NULL);
  snprintf (buf, cap, "%08lX%04X%03X",
            (unsigned long) now, (unsigned) (getpid () & 0xffff),
            (unsigned) (ctr++ & 0xfff));
}

/* Build the envelope/meta and atomically install <queue>/<subdir>/<qid>/.
 * extra_meta (or NULL) is appended verbatim to meta (e.g. inbound
 * client_ip/helo lines). On success copies the queue id into qid_out
 * (>= 24 bytes). Returns 0, or -1 on error. */
static int
bm_enqueue_sub (const char *queue, const char *subdir, const char *sender,
                char *const rcpts[], int nrcpt,
                const unsigned char *msg, size_t msglen,
                const char *extra_meta, char *qid_out, size_t qid_cap)
{
  char active[BM_PATH_MAX], tmpdir[BM_PATH_MAX], dest[BM_PATH_MAX];

  if (snprintf (active, sizeof active, "%s/%s", queue, subdir) >= (int) sizeof active)
    return -1;
  if (bm_mkdir_p (active, 0700) < 0) return -1;

  /* Stage under a unique .tmp dir. */
  if (snprintf (tmpdir, sizeof tmpdir, "%s/.tmp.%d.%u", active,
                (int) getpid (), (unsigned) time (NULL)) >= (int) sizeof tmpdir)
    return -1;
  bm_rmrf (tmpdir);                      /* clear any stale stage */
  if (mkdir (tmpdir, 0700) < 0) return -1;

  /* envelope: "from <addr>\n" then "rcpt <addr>\n" per recipient. */
  {
    char *env = NULL; size_t elen = 0;
    FILE *m = open_memstream (&env, &elen);
    if (!m) { bm_rmrf (tmpdir); return -1; }
    fprintf (m, "from %s\n", sender ? sender : "");
    for (int i = 0; i < nrcpt; i++)
      fprintf (m, "rcpt %s\n", rcpts[i]);
    fclose (m);
    int rc = bm_write_member (tmpdir, "envelope", env, elen);
    free (env);
    if (rc < 0) { bm_rmrf (tmpdir); return -1; }
  }

  /* Split message into headers/body at the first blank line. */
  {
    size_t split = msglen;             /* default: all headers, no body */
    size_t bodyoff = msglen;
    for (size_t i = 0; i + 1 < msglen; i++)
      {
        if (msg[i] == '\n' && msg[i + 1] == '\n')
          { split = i + 1; bodyoff = i + 2; break; }
        if (i + 3 < msglen && msg[i] == '\r' && msg[i + 1] == '\n'
            && msg[i + 2] == '\r' && msg[i + 3] == '\n')
          { split = i + 2; bodyoff = i + 4; break; }
      }
    if (bm_write_member (tmpdir, "headers", msg, split) < 0)
      { bm_rmrf (tmpdir); return -1; }
    if (bm_write_member (tmpdir, "body",
                         bodyoff < msglen ? (const void *) (msg + bodyoff) : (const void *) "",
                         bodyoff < msglen ? msglen - bodyoff : 0) < 0)
      { bm_rmrf (tmpdir); return -1; }
  }

  /* Choose a qid and install atomically; retry on collision. */
  for (int attempt = 0; attempt < 16; attempt++)
    {
      char qid[24];
      bm_make_qid (qid, sizeof qid);

      char *meta = NULL; size_t mlen = 0;
      FILE *m = open_memstream (&meta, &mlen);
      if (!m) { bm_rmrf (tmpdir); return -1; }
      fprintf (m, "qid=%s\n", qid);
      fprintf (m, "arrival=%ld\n", (long) time (NULL));
      fprintf (m, "size=%zu\n", msglen);
      fprintf (m, "sender=%s\n", sender ? sender : "");
      fprintf (m, "nrcpt=%d\n", nrcpt);
      if (extra_meta && *extra_meta) fputs (extra_meta, m);
      fclose (m);
      int rc = bm_write_member (tmpdir, "meta", meta, mlen);
      free (meta);
      if (rc < 0) { bm_rmrf (tmpdir); return -1; }

      if (snprintf (dest, sizeof dest, "%s/%s", active, qid) >= (int) sizeof dest)
        { bm_rmrf (tmpdir); return -1; }
      if (rename (tmpdir, dest) == 0)
        {
          snprintf (qid_out, qid_cap, "%s", qid);
          return 0;
        }
      if (errno != EEXIST && errno != ENOTEMPTY)
        { bm_rmrf (tmpdir); return -1; }
      /* collision: regenerate qid (a fresh second/counter) and retry */
    }
  bm_rmrf (tmpdir);
  return -1;
}

/* Convenience: enqueue into <queue>/active/ with no extra meta. */
static int
bm_enqueue (const char *queue, const char *sender, char *const rcpts[],
            int nrcpt, const unsigned char *msg, size_t msglen,
            char *qid_out, size_t qid_cap)
{
  return bm_enqueue_sub (queue, "active", sender, rcpts, nrcpt, msg, msglen,
                         NULL, qid_out, qid_cap);
}

/* ---- argument helpers ---------------------------------------------- */

/* Pull the value following a flag in the WORD_LIST (advances *pp). */
static const char *
bm_opt_val (WORD_LIST **pp)
{
  WORD_LIST *n = (*pp)->next;
  if (!n) return NULL;
  *pp = n;
  return n->word->word;
}

/* ---- submit (client) ----------------------------------------------- */

static int
bm_connect_unix (const char *path)
{
  struct sockaddr_un sa;
  if (strlen (path) >= sizeof sa.sun_path) return -1;
  int fd = socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  memset (&sa, 0, sizeof sa);
  sa.sun_family = AF_UNIX;
  strncpy (sa.sun_path, path, sizeof sa.sun_path - 1);
  if (connect (fd, (struct sockaddr *) &sa, sizeof sa) < 0)
    { close (fd); return -1; }
  return fd;
}

/* Send a framed submission on fd. -1 on write error. */
static int
bm_send_frame (int fd, const char *sender,
               char *const rcpts[], int nrcpt,
               const unsigned char *msg, size_t msglen)
{
  char hdr[64];
  if (bm_write_all (fd, "BASHMAIL1\n", 10) < 0) return -1;
  int n = snprintf (hdr, sizeof hdr, "FROM %zu\n", strlen (sender));
  if (bm_write_all (fd, hdr, n) < 0) return -1;
  if (bm_write_all (fd, sender, strlen (sender)) < 0) return -1;
  for (int i = 0; i < nrcpt; i++)
    {
      n = snprintf (hdr, sizeof hdr, "RCPT %zu\n", strlen (rcpts[i]));
      if (bm_write_all (fd, hdr, n) < 0) return -1;
      if (bm_write_all (fd, rcpts[i], strlen (rcpts[i])) < 0) return -1;
    }
  n = snprintf (hdr, sizeof hdr, "DATA %zu\n", msglen);
  if (bm_write_all (fd, hdr, n) < 0) return -1;
  if (bm_write_all (fd, msg, msglen) < 0) return -1;
  if (bm_write_all (fd, "END\n", 4) < 0) return -1;
  return 0;
}

static int
bm_submit_cmd (WORD_LIST *args)
{
  const char *sender = "";
  const char *sockpath = getenv ("BASHMAIL_SUBMIT_SOCK");
  const char *queue = getenv ("BASHMAIL_QUEUE_DIR");
  int direct = 0;
  char *rcpts[BM_MAX_RCPT];
  int nrcpt = 0;

  if (!sockpath) sockpath = BM_DEFAULT_SOCKET;
  if (!queue) queue = BM_DEFAULT_QUEUE;

  WORD_LIST *p = args;
  for (; p; p = p->next)
    {
      const char *a = p->word->word;
      if (!strcmp (a, "--")) { p = p->next; break; }
      else if (!strcmp (a, "-f")) { const char *v = bm_opt_val (&p); if (!v) { builtin_error ("submit: -f needs an address"); return EX_USAGE; } sender = v; }
      else if (!strcmp (a, "--socket")) { const char *v = bm_opt_val (&p); if (!v) { builtin_error ("submit: --socket needs a path"); return EX_USAGE; } sockpath = v; }
      else if (!strcmp (a, "--queue")) { const char *v = bm_opt_val (&p); if (!v) { builtin_error ("submit: --queue needs a dir"); return EX_USAGE; } queue = v; }
      else if (!strcmp (a, "--direct")) direct = 1;
      else if (a[0] == '-' && a[1]) { builtin_error ("submit: unknown option: %s", a); return EX_USAGE; }
      else break;
    }
  for (; p; p = p->next)
    {
      if (nrcpt >= BM_MAX_RCPT) { builtin_error ("submit: too many recipients"); return EX_USAGE; }
      rcpts[nrcpt++] = p->word->word;
    }

  if (nrcpt == 0)
    { builtin_error ("submit: no recipients"); return BM_EX_NOUSER; }

  unsigned char *msg = NULL; size_t msglen = 0;
  int rr = bm_read_all_fd (0, &msg, &msglen, BM_MAX_MSG);
  if (rr == 1) { builtin_error ("submit: message exceeds size cap"); return BM_EX_TEMPFAIL; }
  if (rr < 0)  { builtin_error ("submit: reading message: %s", strerror (errno)); return EXECUTION_FAILURE; }

  if (direct)
    {
      char qid[24];
      int rc = bm_enqueue (queue, sender, rcpts, nrcpt, msg, msglen, qid, sizeof qid);
      free (msg);
      if (rc < 0) { builtin_error ("submit: enqueue failed: %s", strerror (errno)); return BM_EX_TEMPFAIL; }
      printf ("%s\n", qid);
      return EXECUTION_SUCCESS;
    }

  int fd = bm_connect_unix (sockpath);
  if (fd < 0)
    {
      free (msg);
      builtin_error ("submit: cannot reach %s: %s", sockpath, strerror (errno));
      return BM_EX_TEMPFAIL;
    }
  int sr = bm_send_frame (fd, sender, rcpts, nrcpt, msg, msglen);
  free (msg);
  if (sr < 0) { close (fd); builtin_error ("submit: send failed"); return BM_EX_TEMPFAIL; }

  char reply[256];
  if (bm_read_line (fd, reply, sizeof reply) < 0)
    { close (fd); builtin_error ("submit: no reply from daemon"); return BM_EX_TEMPFAIL; }
  close (fd);

  if (!strncmp (reply, "OK ", 3)) { printf ("%s\n", reply + 3); return EXECUTION_SUCCESS; }
  builtin_error ("submit: rejected: %s", reply[0] ? reply : "(empty)");
  return BM_EX_TEMPFAIL;
}

/* ---- serve (daemon) ------------------------------------------------ */

/* Read one framed submission from fd and enqueue it. Writes the reply
 * line. Returns 0 always (errors are reported in-band to the client). */
static int
bm_serve_one (int cfd, const char *queue, size_t maxmsg)
{
  char line[64];
  char *sender = NULL;
  char *rcpts[BM_MAX_RCPT];
  int nrcpt = 0;
  unsigned char *data = NULL;
  size_t datalen = 0;
  const char *err = NULL;

  if (bm_read_line (cfd, line, sizeof line) < 0 || strcmp (line, "BASHMAIL1"))
    { err = "bad protocol banner"; goto reply; }

  for (;;)
    {
      if (bm_read_line (cfd, line, sizeof line) < 0) { err = "truncated frame"; goto reply; }
      if (!strcmp (line, "END")) break;

      char verb[8]; long len = -1;
      if (sscanf (line, "%7s %ld", verb, &len) != 2 || len < 0)
        { err = "bad frame line"; goto reply; }

      if (!strcmp (verb, "FROM"))
        {
          if (len >= BM_MAX_ADDR) { err = "sender too long"; goto reply; }
          free (sender); sender = malloc ((size_t) len + 1);
          if (!sender) { err = "out of memory"; goto reply; }
          if (bm_read_exact (cfd, sender, (size_t) len) < 0) { err = "short sender"; goto reply; }
          sender[len] = '\0';
        }
      else if (!strcmp (verb, "RCPT"))
        {
          if (len >= BM_MAX_ADDR) { err = "recipient too long"; goto reply; }
          if (nrcpt >= BM_MAX_RCPT) { err = "too many recipients"; goto reply; }
          char *r = malloc ((size_t) len + 1);
          if (!r) { err = "out of memory"; goto reply; }
          if (bm_read_exact (cfd, r, (size_t) len) < 0) { free (r); err = "short recipient"; goto reply; }
          r[len] = '\0';
          rcpts[nrcpt++] = r;
        }
      else if (!strcmp (verb, "DATA"))
        {
          if ((size_t) len > maxmsg) { err = "message too large"; goto reply; }
          free (data); data = malloc ((size_t) len ? (size_t) len : 1);
          if (!data) { err = "out of memory"; goto reply; }
          if (len && bm_read_exact (cfd, data, (size_t) len) < 0) { err = "short data"; goto reply; }
          datalen = (size_t) len;
        }
      else { err = "unknown frame verb"; goto reply; }
    }

  if (nrcpt == 0) { err = "no recipients"; goto reply; }
  if (!data) { data = malloc (1); datalen = 0; }

  {
    char qid[24];
    if (bm_enqueue (queue, sender ? sender : "", rcpts, nrcpt, data, datalen,
                    qid, sizeof qid) < 0)
      { err = "enqueue failed"; goto reply; }
    char ok[64];
    int n = snprintf (ok, sizeof ok, "OK %s\n", qid);
    (void) bm_write_all (cfd, ok, n);
    goto done;
  }

reply:
  {
    char e[256];
    int n = snprintf (e, sizeof e, "ERR 75 %s\n", err ? err : "error");
    (void) bm_write_all (cfd, e, n);
  }
done:
  free (sender);
  free (data);
  for (int i = 0; i < nrcpt; i++) free (rcpts[i]);
  return 0;
}

/* Best-effort chown to mail:mail (ignored if the account is absent). */
static void
bm_chown_mail (const char *path)
{
  struct passwd *pw = getpwnam ("mail");
  struct group  *gr = getgrnam ("mail");
  uid_t uid = pw ? pw->pw_uid : (uid_t) -1;
  gid_t gid = gr ? gr->gr_gid : (gid_t) -1;
  if (uid != (uid_t) -1 || gid != (gid_t) -1)
    (void) chown (path, uid, gid);
}

static int
bm_serve_cmd (WORD_LIST *args)
{
  const char *sockpath = getenv ("BASHMAIL_SUBMIT_SOCK");
  const char *queue = getenv ("BASHMAIL_QUEUE_DIR");
  const char *conf = NULL;
  size_t maxmsg = BM_MAX_MSG;

  if (!sockpath) sockpath = BM_DEFAULT_SOCKET;
  if (!queue) queue = BM_DEFAULT_QUEUE;

  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *a = p->word->word;
      if (!strcmp (a, "--socket")) { const char *v = bm_opt_val (&p); if (!v) { builtin_error ("serve: --socket needs a path"); return EX_USAGE; } sockpath = v; }
      else if (!strcmp (a, "--queue")) { const char *v = bm_opt_val (&p); if (!v) { builtin_error ("serve: --queue needs a dir"); return EX_USAGE; } queue = v; }
      else if (!strcmp (a, "--conf")) { const char *v = bm_opt_val (&p); if (!v) { builtin_error ("serve: --conf needs a path"); return EX_USAGE; } conf = v; }
      else { builtin_error ("serve: unknown option: %s", a); return EX_USAGE; }
    }

  /* Minimal conf read: honor max_message_bytes if present. */
  if (conf)
    {
      FILE *f = fopen (conf, "re");
      if (f)
        {
          char ln[256];
          while (fgets (ln, sizeof ln, f))
            {
              long v;
              if (sscanf (ln, " max_message_bytes = %ld", &v) == 1 && v > 0)
                maxmsg = (size_t) v;
            }
          fclose (f);
        }
    }

  /* Ensure queue + socket parent dirs exist. */
  char active[BM_PATH_MAX];
  snprintf (active, sizeof active, "%s/active", queue);
  if (bm_mkdir_p (active, 0700) < 0)
    { builtin_error ("serve: cannot create queue %s: %s", queue, strerror (errno)); return EXECUTION_FAILURE; }
  {
    char sdir[BM_PATH_MAX];
    snprintf (sdir, sizeof sdir, "%s", sockpath);
    char *slash = strrchr (sdir, '/');
    if (slash) { *slash = '\0'; (void) bm_mkdir_p (sdir, 0750); }
  }

  struct sockaddr_un sa;
  if (strlen (sockpath) >= sizeof sa.sun_path)
    { builtin_error ("serve: socket path too long"); return EXECUTION_FAILURE; }
  int lfd = socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (lfd < 0) { builtin_error ("serve: socket: %s", strerror (errno)); return EXECUTION_FAILURE; }
  memset (&sa, 0, sizeof sa);
  sa.sun_family = AF_UNIX;
  strncpy (sa.sun_path, sockpath, sizeof sa.sun_path - 1);
  (void) unlink (sockpath);            /* clear stale socket */
  if (bind (lfd, (struct sockaddr *) &sa, sizeof sa) < 0)
    { builtin_error ("serve: bind %s: %s", sockpath, strerror (errno)); close (lfd); return EXECUTION_FAILURE; }
  (void) chmod (sockpath, 0660);
  bm_chown_mail (sockpath);
  if (listen (lfd, BM_LISTEN_BACKLOG) < 0)
    { builtin_error ("serve: listen: %s", strerror (errno)); close (lfd); unlink (sockpath); return EXECUTION_FAILURE; }

  struct sigaction act;
  memset (&act, 0, sizeof act);
  act.sa_handler = bm_sigstop;
  sigaction (SIGINT, &act, NULL);
  sigaction (SIGTERM, &act, NULL);
  signal (SIGPIPE, SIG_IGN);

  printf ("mail: serving submissions on %s (queue %s)\n", sockpath, queue);
  fflush (stdout);

  while (!bm_stop)
    {
      int cfd = accept (lfd, NULL, NULL);
      if (cfd < 0)
        {
          if (errno == EINTR) continue;
          if (bm_stop) break;
          continue;
        }
      bm_serve_one (cfd, queue, maxmsg);
      close (cfd);
    }

  close (lfd);
  (void) unlink (sockpath);
  return EXECUTION_SUCCESS;
}

/* ---- queue inspection ---------------------------------------------- */

/* Read a small queue member file (NUL-terminated) into a static-free
 * malloc buffer; returns NULL on error. */
static char *
bm_slurp (const char *dir, const char *name)
{
  char path[BM_PATH_MAX];
  if (snprintf (path, sizeof path, "%s/%s", dir, name) >= (int) sizeof path) return NULL;
  int fd = open (path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return NULL;
  unsigned char *buf = NULL; size_t len = 0;
  if (bm_read_all_fd (fd, &buf, &len, 1 << 20) != 0) { close (fd); free (buf); return NULL; }
  close (fd);
  char *s = realloc (buf, len + 1);
  if (!s) { free (buf); return NULL; }
  s[len] = '\0';
  return s;
}

/* Extract a key=value from a meta blob into out (caller-sized). */
static void
bm_meta_get (const char *meta, const char *key, char *out, size_t cap)
{
  out[0] = '\0';
  size_t klen = strlen (key);
  const char *p = meta;
  while (p && *p)
    {
      if (!strncmp (p, key, klen) && p[klen] == '=')
        {
          const char *v = p + klen + 1;
          const char *e = strchr (v, '\n');
          size_t n = e ? (size_t) (e - v) : strlen (v);
          if (n >= cap) n = cap - 1;
          memcpy (out, v, n); out[n] = '\0';
          return;
        }
      p = strchr (p, '\n');
      if (p) p++;
    }
}

static int
bm_qopt_queue (WORD_LIST *args, const char **queue, const char **arg1)
{
  *arg1 = NULL;
  const char *q = getenv ("BASHMAIL_QUEUE_DIR");
  if (!q) q = BM_DEFAULT_QUEUE;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *a = p->word->word;
      if (!strcmp (a, "--queue")) { const char *v = bm_opt_val (&p); if (!v) return -1; q = v; }
      else if (a[0] == '-' && a[1]) return -1;
      else if (!*arg1) *arg1 = a;
    }
  *queue = q;
  return 0;
}

/* List one queue subdir ("active"/"deferred"); accumulates count+bytes
 * and prints the Postfix-style header once. `deferred` marks entries. */
static void
bm_list_subdir (const char *queue, const char *sub, int deferred,
                long *count, long *total, int *printed_header)
{
  char dir[BM_PATH_MAX];
  snprintf (dir, sizeof dir, "%s/%s", queue, sub);
  DIR *d = opendir (dir);
  if (!d) return;
  struct dirent *e;
  while ((e = readdir (d)))
    {
      if (e->d_name[0] == '.') continue;
      char entry[BM_PATH_MAX];
      if (snprintf (entry, sizeof entry, "%s/%s", dir, e->d_name) >= (int) sizeof entry) continue;
      char *meta = bm_slurp (entry, "meta");
      if (!meta) continue;
      char qid[64], szs[32], snd[BM_MAX_ADDR], arr[32];
      bm_meta_get (meta, "qid", qid, sizeof qid);
      bm_meta_get (meta, "size", szs, sizeof szs);
      bm_meta_get (meta, "sender", snd, sizeof snd);
      bm_meta_get (meta, "arrival", arr, sizeof arr);
      free (meta);
      if (!qid[0]) snprintf (qid, sizeof qid, "%s", e->d_name);
      long sz = atol (szs);
      *total += sz; (*count)++;
      char when[64] = "";
      time_t t = (time_t) atol (arr);
      struct tm tmv;
      if (t > 0 && localtime_r (&t, &tmv))
        strftime (when, sizeof when, "%a %b %e %H:%M:%S", &tmv);
      if (!*printed_header)
        { printf ("-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------\n"); *printed_header = 1; }
      printf ("%-11s%c%7ld %-20s %s\n", qid, deferred ? '*' : ' ', sz, when,
              snd[0] ? snd : "MAILER-DAEMON");
      char *env = bm_slurp (entry, "envelope");
      if (env)
        {
          for (char *p = env; p && *p; )
            {
              char *eol = strchr (p, '\n');
              if (eol) *eol = '\0';
              if (!strncmp (p, "rcpt ", 5)) printf ("%41s%s\n", "", p + 5);
              if (!eol) break;
              p = eol + 1;
            }
          free (env);
        }
    }
  closedir (d);
}

static int
bm_queue_list_cmd (WORD_LIST *args)
{
  const char *queue, *unused;
  if (bm_qopt_queue (args, &queue, &unused) < 0) { builtin_usage (); return EX_USAGE; }

  long count = 0, total = 0;
  int printed_header = 0;
  bm_list_subdir (queue, "active", 0, &count, &total, &printed_header);
  bm_list_subdir (queue, "deferred", 1, &count, &total, &printed_header);

  if (count == 0) { printf ("Mail queue is empty\n"); return EXECUTION_SUCCESS; }
  printf ("\n-- %ld Kbytes in %ld %s.  (* = deferred)\n",
          (total + 1023) / 1024, count, count == 1 ? "Request" : "Requests");
  return EXECUTION_SUCCESS;
}

static int
bm_queue_show_cmd (WORD_LIST *args)
{
  const char *queue, *qid;
  if (bm_qopt_queue (args, &queue, &qid) < 0 || !qid)
    { builtin_error ("queue-show: usage: queue-show QID [--queue DIR]"); return EX_USAGE; }

  char entry[BM_PATH_MAX];
  if (snprintf (entry, sizeof entry, "%s/active/%s", queue, qid) >= (int) sizeof entry)
    return EXECUTION_FAILURE;
  struct stat st;
  if (stat (entry, &st) < 0 || !S_ISDIR (st.st_mode))
    { builtin_error ("queue-show: no such queue id: %s", qid); return EXECUTION_FAILURE; }

  for (const char *m = "envelope"; m; m = NULL)
    { char *s = bm_slurp (entry, m); if (s) { fputs (s, stdout); free (s); } }
  printf ("--\n");
  { char *h = bm_slurp (entry, "headers"); if (h) { fputs (h, stdout); free (h); } }
  { char *b = bm_slurp (entry, "body"); if (b) { fputs (b, stdout); free (b); } }
  return EXECUTION_SUCCESS;
}

static int
bm_queue_delete_cmd (WORD_LIST *args)
{
  static const char *subs[] = { "active", "deferred", "corrupt", NULL };
  const char *queue, *qid;
  if (bm_qopt_queue (args, &queue, &qid) < 0 || !qid)
    { builtin_error ("queue-delete: usage: queue-delete QID|ALL [--queue DIR]"); return EX_USAGE; }

  if (!strcmp (qid, "ALL"))
    {
      long n = 0;
      for (int i = 0; subs[i]; i++)
        {
          char dir[BM_PATH_MAX];
          snprintf (dir, sizeof dir, "%s/%s", queue, subs[i]);
          DIR *d = opendir (dir);
          if (!d) continue;
          struct dirent *e;
          while ((e = readdir (d)))
            {
              if (e->d_name[0] == '.') continue;
              char entry[BM_PATH_MAX];
              if (snprintf (entry, sizeof entry, "%s/%s", dir, e->d_name) >= (int) sizeof entry) continue;
              if (bm_rmrf (entry) == 0) n++;
            }
          closedir (d);
        }
      printf ("mail: deleted %ld message(s)\n", n);
      return EXECUTION_SUCCESS;
    }

  for (int i = 0; subs[i]; i++)
    {
      char entry[BM_PATH_MAX];
      if (snprintf (entry, sizeof entry, "%s/%s/%s", queue, subs[i], qid) >= (int) sizeof entry) continue;
      struct stat st;
      if (stat (entry, &st) == 0 && S_ISDIR (st.st_mode))
        {
          if (bm_rmrf (entry) < 0)
            { builtin_error ("queue-delete: %s: %s", qid, strerror (errno)); return EXECUTION_FAILURE; }
          printf ("mail: deleted %s\n", qid);
          return EXECUTION_SUCCESS;
        }
    }
  builtin_error ("queue-delete: no such queue id: %s", qid);
  return EXECUTION_FAILURE;
}

static int
bm_queue_flush_cmd (WORD_LIST *args)
{
  const char *pidfile = getenv ("BASHMAIL_RUNNER_PID");
  if (!pidfile) pidfile = "/run/bash-os/mail/runner.pid";
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *a = p->word->word;
      if (!strcmp (a, "--pidfile")) { pidfile = bm_opt_val (&p); if (!pidfile) { builtin_error ("queue-flush: --pidfile needs a path"); return EX_USAGE; } }
      else { builtin_error ("queue-flush: unknown option: %s", a); return EX_USAGE; }
    }
  FILE *pf = fopen (pidfile, "re");
  if (!pf) { printf ("queue-flush: no runner (pidfile %s absent)\n", pidfile); return EXECUTION_SUCCESS; }
  long pid = 0; if (fscanf (pf, "%ld", &pid) != 1) pid = 0;
  fclose (pf);
  if (pid <= 0) { builtin_error ("queue-flush: bad pidfile"); return EXECUTION_FAILURE; }
  if (kill ((pid_t) pid, SIGUSR1) < 0)
    { builtin_error ("queue-flush: signal pid %ld: %s", pid, strerror (errno)); return EXECUTION_FAILURE; }
  printf ("queue-flush: woke runner pid %ld\n", pid);
  return EXECUTION_SUCCESS;
}

/* ---- alias resolution (newaliases / expand) ------------------------ */

/* Read an entire file by path into a malloc'd NUL-terminated buffer
 * (<= 1 MiB). NULL on error. */
static char *
bm_read_text (const char *path)
{
  int fd = open (path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return NULL;
  unsigned char *buf = NULL; size_t len = 0;
  if (bm_read_all_fd (fd, &buf, &len, 1 << 20) != 0) { close (fd); free (buf); return NULL; }
  close (fd);
  char *s = realloc (buf, len + 1);
  if (!s) { free (buf); return NULL; }
  s[len] = '\0';
  return s;
}

/* Atomic write-by-path (tmp + rename). -1 on error. */
static int
bm_write_path_atomic (const char *path, const void *data, size_t n, mode_t mode)
{
  char tmp[BM_PATH_MAX];
  if (snprintf (tmp, sizeof tmp, "%s.tmp.%d", path, (int) getpid ()) >= (int) sizeof tmp)
    return -1;
  int fd = open (tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
  if (fd < 0) return -1;
  if (bm_write_all (fd, data, n) < 0) { close (fd); unlink (tmp); return -1; }
  (void) fsync (fd);
  if (close (fd) < 0) { unlink (tmp); return -1; }
  if (rename (tmp, path) < 0) { unlink (tmp); return -1; }
  return 0;
}

/* Trim leading/trailing ASCII whitespace in place; returns a pointer
 * into s. */
static char *
bm_trim (char *s)
{
  while (*s == ' ' || *s == '\t' || *s == '\r') s++;
  char *e = s + strlen (s);
  while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n'))
    *--e = '\0';
  return s;
}

/* ^[A-Za-z0-9_.+-]+$ and contains no "..". */
static int
bm_safe_local (const char *s)
{
  if (!*s) return 0;
  for (const char *p = s; *p; p++)
    if (!(isalnum ((unsigned char) *p) || *p == '_' || *p == '.' || *p == '+' || *p == '-'))
      return 0;
  return strstr (s, "..") == NULL;
}

/* Normalize a recipient to a local part under the local-only policy
 * (mirrors sendmail.sh normalize_local_recipient). 0 + fills out, or -1
 * if remote/invalid. */
static int
bm_normalize_local (const char *addr_in, char *out, size_t cap)
{
  char a[BM_MAX_ADDR];
  snprintf (a, sizeof a, "%s", addr_in);
  char *s = a;
  size_t n = strlen (s);
  if (n && s[0] == ',') { s++; n--; }
  if (n && s[n - 1] == ',') s[--n] = '\0';
  if (*s == '<') s++;
  n = strlen (s);
  if (n && s[n - 1] == '>') s[--n] = '\0';
  if (!*s || strchr (s, '/') || strstr (s, "..")) return -1;

  char *at = strchr (s, '@');
  if (at)
    {
      *at = '\0';
      const char *domain = at + 1;
      char host[256]; host[0] = '\0';
      gethostname (host, sizeof host - 1);
      const char *envh = getenv ("HOSTNAME");
      if (!(!strcmp (domain, "localhost") || !strcmp (domain, "localhost.localdomain")
            || (*host && !strcmp (domain, host))
            || (envh && *envh && !strcmp (domain, envh))))
        return -1;
    }
  if (!bm_safe_local (s)) return -1;
  snprintf (out, cap, "%s", s);
  return 0;
}

/* First-match alias RHS for `user`. Prefers the compiled DB (db arg,
 * then /etc/aliases.db), falling back to the live aliases file. Returns
 * a malloc'd RHS string or NULL when there is no alias. */
static char *
bm_alias_rhs (const char *user, const char *db, const char *aliases)
{
  /* Precedence is strict so tests (which set BASHMAIL_ALIASES[_DB] to a
   * temp path) never fall through to the host's /etc files: an explicit
   * compiled DB wins; else an explicit live source; else the system
   * compiled DB, then the system live source. */
  char *text = NULL;
  if (db && *db)
    text = bm_read_text (db);
  else if (aliases && *aliases)
    text = bm_read_text (aliases);
  else
    {
      text = bm_read_text (BM_DEFAULT_ALIASES_DB);
      if (!text) text = bm_read_text (BM_DEFAULT_ALIASES);
    }
  if (!text) return NULL;

  char *result = NULL;
  for (char *p = text; *p; )
    {
      char *eol = strchr (p, '\n');
      if (eol) *eol = '\0';
      char *hash = strchr (p, '#'); if (hash) *hash = '\0';
      char *colon = strchr (p, ':');
      if (colon)
        {
          *colon = '\0';
          char *key = bm_trim (p);
          char *rhs = bm_trim (colon + 1);
          if (*key && *rhs && !strcmp (key, user)) { result = strdup (rhs); }
        }
      if (result || !eol) break;
      p = eol + 1;
    }
  free (text);
  return result;
}

/* Whitespace-joined .forward targets for `user` (commas -> spaces,
 * comments stripped), or NULL when there is no usable .forward.
 * Rejects symlinks and non-regular files (sendmail.sh parity). */
static char *
bm_forward_targets (const char *user, const char *fwd_root)
{
  const char *root = (fwd_root && *fwd_root) ? fwd_root : BM_DEFAULT_FWD_ROOT;
  char path[BM_PATH_MAX];
  if (snprintf (path, sizeof path, "%s/%s/.forward", root, user) >= (int) sizeof path)
    return NULL;
  struct stat ls;
  if (lstat (path, &ls) < 0 || S_ISLNK (ls.st_mode) || !S_ISREG (ls.st_mode)) return NULL;
  char *text = bm_read_text (path);
  if (!text) return NULL;
  char *out = NULL; size_t olen = 0;
  FILE *m = open_memstream (&out, &olen);
  if (!m) { free (text); return NULL; }
  for (char *p = text; *p; )
    {
      char *eol = strchr (p, '\n');
      if (eol) *eol = '\0';
      char *hash = strchr (p, '#'); if (hash) *hash = '\0';
      for (char *c = p; *c; c++) if (*c == ',') *c = ' ';
      char *t = bm_trim (p);
      if (*t) fprintf (m, "%s ", t);
      if (!eol) break;
      p = eol + 1;
    }
  fclose (m);
  free (text);
  return out;
}

/* Space-delimited membership test ("key" present as a whole token). */
static int
bm_seen_has (const char *seen, const char *key)
{
  size_t klen = strlen (key);
  const char *p = seen;
  while (*p)
    {
      while (*p == ' ') p++;
      const char *start = p;
      while (*p && *p != ' ') p++;
      if ((size_t) (p - start) == klen && !strncmp (start, key, klen)) return 1;
    }
  return 0;
}

static void bm_expand_one (const char *recipient, int depth, const char *seen,
                           int *failed, const char *db, const char *aliases,
                           const char *fwd_root);

/* Tokenize `toks` (comma/space separated; mutated) and expand each. */
static void
bm_expand_tokens (char *toks, int depth, const char *seen, int *failed,
                  const char *db, const char *aliases, const char *fwd_root)
{
  for (char *c = toks; *c; c++) if (*c == ',') *c = ' ';
  char *save = NULL;
  for (char *t = strtok_r (toks, " \t", &save); t; t = strtok_r (NULL, " \t", &save))
    if (*t) bm_expand_one (t, depth, seen, failed, db, aliases, fwd_root);
}

/* Recursive expansion mirroring sendmail.sh expand_recipient. Emits each
 * terminal local recipient to stdout; sets *failed on any error. */
static void
bm_expand_one (const char *recipient, int depth, const char *seen, int *failed,
               const char *db, const char *aliases, const char *fwd_root)
{
  char user[BM_MAX_ADDR];

  if (recipient[0] == '\\')
    {
      if (bm_normalize_local (recipient + 1, user, sizeof user) < 0)
        { builtin_error ("expand: invalid escaped local recipient: %s", recipient); *failed = 1; return; }
      printf ("%s\n", user);
      return;
    }

  if (bm_normalize_local (recipient, user, sizeof user) < 0)
    { builtin_error ("expand: remote or invalid recipient: %s", recipient); *failed = 1; return; }

  if (depth > BM_EXPAND_MAXDEPTH)
    { builtin_error ("expand: alias expansion too deep at %s", user); *failed = 1; return; }

  char key[BM_MAX_ADDR + 16];

  snprintf (key, sizeof key, "alias:%s", user);
  if (bm_seen_has (seen, key))
    { builtin_error ("expand: alias cycle at %s", user); *failed = 1; return; }
  char *rhs = bm_alias_rhs (user, db, aliases);
  if (rhs && *rhs)
    {
      char *nseen = malloc (strlen (seen) + strlen (key) + 2);
      if (!nseen) { free (rhs); *failed = 1; return; }
      sprintf (nseen, "%s %s", seen, key);
      bm_expand_tokens (rhs, depth + 1, nseen, failed, db, aliases, fwd_root);
      free (nseen);
      free (rhs);
      return;
    }
  free (rhs);

  snprintf (key, sizeof key, "forward:%s", user);
  if (bm_seen_has (seen, key))
    { builtin_error ("expand: forward cycle at %s", user); *failed = 1; return; }
  char *fwd = bm_forward_targets (user, fwd_root);
  if (fwd && *fwd)
    {
      char *nseen = malloc (strlen (seen) + strlen (key) + 2);
      if (!nseen) { free (fwd); *failed = 1; return; }
      sprintf (nseen, "%s %s", seen, key);
      bm_expand_tokens (fwd, depth + 1, nseen, failed, db, aliases, fwd_root);
      free (nseen);
      free (fwd);
      return;
    }
  free (fwd);

  printf ("%s\n", user);
}

/* qsort comparator for an array of char* (compares the pointed-to
 * strings, not the pointers). */
static int
bm_cmp_lines (const void *a, const void *b)
{
  return strcmp (*(const char *const *) a, *(const char *const *) b);
}

static int
bm_newaliases_cmd (WORD_LIST *args)
{
  const char *src = getenv ("BASHMAIL_ALIASES");
  const char *db = getenv ("BASHMAIL_ALIASES_DB");
  if (!src || !*src) src = BM_DEFAULT_ALIASES;
  if (!db || !*db) db = BM_DEFAULT_ALIASES_DB;

  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *a = p->word->word;
      if (!strcmp (a, "--aliases")) { const char *v = bm_opt_val (&p); if (!v) { builtin_error ("newaliases: --aliases needs a path"); return EX_USAGE; } src = v; }
      else if (!strcmp (a, "--db")) { const char *v = bm_opt_val (&p); if (!v) { builtin_error ("newaliases: --db needs a path"); return EX_USAGE; } db = v; }
      else { builtin_error ("newaliases: unknown option: %s", a); return EX_USAGE; }
    }

  char *text = bm_read_text (src);
  if (!text)
    { builtin_error ("newaliases: cannot read %s: %s", src, strerror (errno)); return BM_EX_CONFIG; }

  char **lines = NULL; size_t nlines = 0, cap = 0;
  int parse_err = 0;
  for (char *p = text; *p; )
    {
      char *eol = strchr (p, '\n');
      if (eol) *eol = '\0';
      char *raw = p;
      if (eol) p = eol + 1; else p += strlen (p);

      char *hash = strchr (raw, '#'); if (hash) *hash = '\0';
      char *trimmed = bm_trim (raw);
      if (!*trimmed) continue;                       /* blank / comment-only */
      char *colon = strchr (trimmed, ':');
      if (!colon) { parse_err = 1; break; }          /* malformed -> EX_CONFIG */
      *colon = '\0';
      char *key = bm_trim (trimmed);
      char *rhs = bm_trim (colon + 1);
      if (!*key) { parse_err = 1; break; }

      char *line = malloc (strlen (key) + strlen (rhs) + 4);
      if (!line) { parse_err = 1; break; }
      sprintf (line, "%s: %s", key, rhs);
      if (nlines == cap)
        {
          size_t ncap = cap ? cap * 2 : 32;
          char **nl = realloc (lines, ncap * sizeof *lines);
          if (!nl) { free (line); parse_err = 1; break; }
          lines = nl; cap = ncap;
        }
      lines[nlines++] = line;
    }

  if (parse_err)
    {
      for (size_t i = 0; i < nlines; i++) free (lines[i]);
      free (lines); free (text);
      builtin_error ("newaliases: %s: malformed alias entry", src);
      return BM_EX_CONFIG;
    }

  if (nlines > 1) qsort (lines, nlines, sizeof *lines, bm_cmp_lines);

  char *out = NULL; size_t olen = 0;
  FILE *m = open_memstream (&out, &olen);
  if (!m)
    {
      for (size_t i = 0; i < nlines; i++) free (lines[i]);
      free (lines); free (text);
      builtin_error ("newaliases: out of memory");
      return EXECUTION_FAILURE;
    }
  fprintf (m, "# mail-aliases-db v1 (%zu entries)\n", nlines);
  for (size_t i = 0; i < nlines; i++) fprintf (m, "%s\n", lines[i]);
  fclose (m);

  int rc = bm_write_path_atomic (db, out, olen, 0644);
  free (out);
  for (size_t i = 0; i < nlines; i++) free (lines[i]);
  free (lines); free (text);
  if (rc < 0)
    { builtin_error ("newaliases: cannot write %s: %s", db, strerror (errno)); return EXECUTION_FAILURE; }
  return EXECUTION_SUCCESS;
}

static int
bm_expand_cmd (WORD_LIST *args)
{
  const char *db = getenv ("BASHMAIL_ALIASES_DB");
  const char *aliases = getenv ("BASHMAIL_ALIASES");
  const char *fwd_root = getenv ("BASHMAIL_FORWARD_ROOT");
  char *rcpts[BM_MAX_RCPT];
  int nrcpt = 0;

  WORD_LIST *p = args;
  for (; p; p = p->next)
    {
      const char *a = p->word->word;
      if (!strcmp (a, "--")) { p = p->next; break; }
      else if (!strcmp (a, "--aliases-db")) { const char *v = bm_opt_val (&p); if (!v) { builtin_error ("expand: --aliases-db needs a path"); return EX_USAGE; } db = v; }
      else if (!strcmp (a, "--aliases")) { const char *v = bm_opt_val (&p); if (!v) { builtin_error ("expand: --aliases needs a path"); return EX_USAGE; } aliases = v; }
      else if (!strcmp (a, "--forward-root")) { const char *v = bm_opt_val (&p); if (!v) { builtin_error ("expand: --forward-root needs a path"); return EX_USAGE; } fwd_root = v; }
      else if (a[0] == '-' && a[1]) { builtin_error ("expand: unknown option: %s", a); return EX_USAGE; }
      else break;
    }
  for (; p; p = p->next)
    {
      if (nrcpt >= BM_MAX_RCPT) { builtin_error ("expand: too many recipients"); return EX_USAGE; }
      rcpts[nrcpt++] = p->word->word;
    }
  if (nrcpt == 0) { builtin_error ("expand: no recipients"); return EX_USAGE; }

  int failed = 0;
  for (int i = 0; i < nrcpt; i++)
    bm_expand_one (rcpts[i], 0, "", &failed, db, aliases, fwd_root);
  return failed ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

/* ---- outbound SMTP delivery (deliver-fd) --------------------------- */

#include "_mbedtls_ssl.h"
#include "_mbedtls_x509_crt.h"
#include "_mbedtls_net_sockets.h"
#include "_mbedtls_error.h"
#include "_mbedtls_crypto.h"

/* mbedTLS BIO over a blocking socket that carries SO_RCVTIMEO/SNDTIMEO:
 * EAGAIN means a real timeout -> hard error (not WANT_*), so the dialog
 * can't spin forever on a dead peer. */
static int
bm_bio_recv (void *ctx, unsigned char *b, size_t n)
{
  int fd = *(int *) ctx; ssize_t r;
  do { r = read (fd, b, n); } while (r < 0 && errno == EINTR);
  return r < 0 ? MBEDTLS_ERR_NET_RECV_FAILED : (int) r;
}
static int
bm_bio_send (void *ctx, const unsigned char *b, size_t n)
{
  int fd = *(int *) ctx; ssize_t r;
  do { r = write (fd, b, n); } while (r < 0 && errno == EINTR);
  return r < 0 ? MBEDTLS_ERR_NET_SEND_FAILED : (int) r;
}

typedef struct {
  int fd;
  int tls;                       /* 0 plaintext, 1 after STARTTLS handshake */
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt ca;
} bm_smtp;

static int
bm_smtp_write (bm_smtp *c, const void *buf, size_t n)
{
  if (!c->tls) return bm_write_all (c->fd, buf, n);
  const unsigned char *p = buf; size_t left = n;
  while (left)
    {
      int w = mbedtls_ssl_write (&c->ssl, p, left);
      if (w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
      if (w <= 0) return -1;
      p += w; left -= (size_t) w;
    }
  return 0;
}

static int
bm_smtp_getc (bm_smtp *c)
{
  unsigned char ch;
  if (!c->tls)
    {
      ssize_t r; do { r = read (c->fd, &ch, 1); } while (r < 0 && errno == EINTR);
      return r <= 0 ? -1 : (int) ch;
    }
  for (;;)
    {
      int r = mbedtls_ssl_read (&c->ssl, &ch, 1);
      if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
      if (r <= 0) return -1;
      return (int) ch;
    }
}

/* Read a (possibly multiline) SMTP reply. Returns the 3-digit code or -1
 * on I/O error. Appends each reply line to `caps` (for EHLO STARTTLS
 * detection) when non-NULL. */
static int
bm_smtp_reply (bm_smtp *c, char *caps, size_t capcap)
{
  size_t cl = caps ? strlen (caps) : 0;
  int code = -1;
  for (;;)
    {
      char line[1024]; size_t i = 0; int ch;
      while ((ch = bm_smtp_getc (c)) >= 0 && ch != '\n')
        { if (ch == '\r') continue; if (i + 1 < sizeof line) line[i++] = (char) ch; }
      if (ch < 0 && i == 0) return -1;
      line[i] = '\0';
      if (caps && cl + i + 2 < capcap) { memcpy (caps + cl, line, i); cl += i; caps[cl++] = '\n'; caps[cl] = '\0'; }
      if (i >= 3 && isdigit ((unsigned char) line[0])) code = atoi (line);
      if (i < 4 || line[3] != '-') break;     /* '-' = continuation */
      if (ch < 0) break;
    }
  return code;
}

static int
bm_smtp_cmd (bm_smtp *c, const char *cmd, char *caps, size_t capcap)
{
  if (bm_smtp_write (c, cmd, strlen (cmd)) < 0) return -1;
  return bm_smtp_reply (c, caps, capcap);
}

/* Upgrade the connection to TLS (after a 220 STARTTLS reply). Returns 0
 * on a completed handshake, -1 otherwise. */
static int
bm_starttls (bm_smtp *c, int verify_peer, const char *ca_path, const char *peer_name)
{
  mbedtls_ssl_init (&c->ssl);
  mbedtls_ssl_config_init (&c->conf);
  mbedtls_x509_crt_init (&c->ca);
  if (psa_crypto_init () != PSA_SUCCESS) return -1;

  if (verify_peer)
    {
      const char *ca_real = ca_path;
      if (!ca_real)
        {
          if (access ("/etc/bash-os/mail/trust.d/tls-ca/ca.pem", R_OK) == 0)
            ca_real = "/etc/bash-os/mail/trust.d/tls-ca/ca.pem";
          else if (access ("/etc/ssl/cert.pem", R_OK) == 0)
            ca_real = "/etc/ssl/cert.pem";
          else if (access ("/etc/ssl/certs/ca-certificates.crt", R_OK) == 0)
            ca_real = "/etc/ssl/certs/ca-certificates.crt";
        }
      if (!ca_real || mbedtls_x509_crt_parse_file (&c->ca, ca_real) < 0)
        { builtin_error ("deliver-fd: relay_verify=peer but no usable CA bundle"); return -1; }
    }
  if (mbedtls_ssl_config_defaults (&c->conf, MBEDTLS_SSL_IS_CLIENT,
                                   MBEDTLS_SSL_TRANSPORT_STREAM,
                                   MBEDTLS_SSL_PRESET_DEFAULT) != 0)
    return -1;
  mbedtls_ssl_conf_authmode (&c->conf,
      verify_peer ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_NONE);
  mbedtls_ssl_conf_ca_chain (&c->conf, &c->ca, NULL);
  if (mbedtls_ssl_setup (&c->ssl, &c->conf) != 0) return -1;
  if (peer_name && *peer_name) mbedtls_ssl_set_hostname (&c->ssl, peer_name);
  mbedtls_ssl_set_bio (&c->ssl, &c->fd, bm_bio_send, bm_bio_recv, NULL);

  int hs;
  while ((hs = mbedtls_ssl_handshake (&c->ssl)) != 0)
    {
      if (hs == MBEDTLS_ERR_SSL_WANT_READ || hs == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
      char buf[128]; mbedtls_strerror (hs, buf, sizeof buf);
      builtin_error ("deliver-fd: STARTTLS handshake failed: %s", buf);
      return -1;
    }
  c->tls = 1;
  return 0;
}

static void
bm_smtp_close (bm_smtp *c)
{
  if (c->tls)
    {
      mbedtls_ssl_close_notify (&c->ssl);
      mbedtls_ssl_free (&c->ssl);
      mbedtls_ssl_config_free (&c->conf);
      mbedtls_x509_crt_free (&c->ca);
    }
}

/* Send the DATA payload: CRLF-normalize and dot-stuff, then terminate
 * with CRLF "." CRLF. Returns 0 / -1. */
static int
bm_smtp_send_data (bm_smtp *c, const char *msg, size_t n)
{
  size_t i = 0;
  while (i < n)
    {
      size_t j = i; while (j < n && msg[j] != '\n') j++;
      size_t len = j - i;
      if (len && msg[i + len - 1] == '\r') len--;           /* drop CR; re-added below */
      if (len > 0 && msg[i] == '.' && bm_smtp_write (c, ".", 1) < 0) return -1;
      if (len && bm_smtp_write (c, msg + i, len) < 0) return -1;
      if (bm_smtp_write (c, "\r\n", 2) < 0) return -1;
      i = (j < n) ? j + 1 : j;
    }
  return bm_smtp_write (c, ".\r\n", 3);
}

/* Map an SMTP reply code to a delivery exit code. */
static int
bm_classify (int code)
{
  if (code < 0) return BM_EX_TEMPFAIL;          /* I/O / timeout */
  if (code / 100 == 2 || code / 100 == 3) return EXECUTION_SUCCESS;
  if (code / 100 == 4) return BM_EX_TEMPFAIL;
  return BM_EX_UNAVAIL;                          /* 5xx */
}

/* ---- DKIM signing (6.4) ------------------------------------------- */

#include "_mbedtls_sha256.h"
#include "_mbedtls_base64.h"
#include "_mbedtls_pk.h"
#include "_monocypher_monocypher-ed25519.h"

static int
bm_b64 (const unsigned char *in, size_t n, char *out, size_t cap)
{
  size_t olen = 0;
  if (mbedtls_base64_encode ((unsigned char *) out, cap, &olen, in, n) != 0) return -1;
  out[olen] = '\0';
  return (int) olen;
}

static void
bm_sha256 (const void *in, size_t n, unsigned char out[32])
{
  mbedtls_sha256_context hc;
  mbedtls_sha256_init (&hc);
  mbedtls_sha256_starts (&hc, 0);
  mbedtls_sha256_update (&hc, (const unsigned char *) in, n);
  mbedtls_sha256_finish (&hc, out);
  mbedtls_sha256_free (&hc);
}

static int
bm_hexval (int c) { if (c >= '0' && c <= '9') return c - '0'; c |= 0x20; if (c >= 'a' && c <= 'f') return c - 'a' + 10; return -1; }

static int
bm_unhex (const char *hex, unsigned char *out, size_t max)
{
  size_t n = 0; const char *p = hex;
  while (*p && isxdigit ((unsigned char) *p))
    {
      int hi = bm_hexval (*p++); if (!*p) return -1;
      int lo = bm_hexval (*p++);
      if (hi < 0 || lo < 0 || n >= max) return -1;
      out[n++] = (unsigned char) ((hi << 4) | lo);
    }
  return (int) n;
}

/* Relaxed body canonicalization (RFC 6376 §3.4.4) into a malloc'd buffer. */
static char *
bm_canon_body_relaxed (const char *body, size_t *outlen)
{
  size_t cap = strlen (body) + 16;
  char *o = malloc (cap);
  if (!o) return NULL;
  size_t n = 0;
  const char *p = body;
  while (*p)
    {
      const char *eol = p; while (*eol && *eol != '\n') eol++;
      const char *le = eol; if (le > p && le[-1] == '\r') le--;
      int inws = 0;
      for (const char *c = p; c < le; c++)
        {
          if (*c == ' ' || *c == '\t') { inws = 1; continue; }
          if (inws) { o[n++] = ' '; inws = 0; }
          o[n++] = *c;
        }
      o[n++] = '\r'; o[n++] = '\n';
      if (!*eol) break;
      p = eol + 1;
    }
  while (n >= 4 && o[n-1] == '\n' && o[n-2] == '\r' && o[n-3] == '\n' && o[n-4] == '\r')
    n -= 2;
  o[n] = '\0';
  *outlen = n;
  return o;
}

/* Relaxed value canon: unfold, compress WSP→single SP, trim. */
static void
bm_relax_value (const char *v, char *out, size_t cap)
{
  size_t n = 0; int inws = 0, started = 0;
  for (const char *c = v; *c; c++)
    {
      char ch = *c;
      if (ch == '\r' || ch == '\n' || ch == ' ' || ch == '\t') { inws = 1; continue; }
      if (inws && started && n + 1 < cap) out[n++] = ' ';
      inws = 0; started = 1;
      if (n + 1 < cap) out[n++] = ch;
    }
  out[n] = '\0';
}

/* Relaxed canon of header field `name` (case-insensitive) from the
 * \n-separated headers blob, folds handled. Writes "name:value" to out
 * (lowercased name, no CRLF). Returns 1 if found. */
static int
bm_header_canon (const char *headers, const char *name, char *out, size_t cap)
{
  size_t nl = strlen (name);
  const char *p = headers;
  while (*p)
    {
      const char *eol = p; while (*eol && *eol != '\n') eol++;
      if (*p != ' ' && *p != '\t')
        {
          const char *colon = memchr (p, ':', (size_t) (eol - p));
          if (colon && (size_t) (colon - p) == nl && strncasecmp (p, name, nl) == 0)
            {
              char raw[4096]; size_t rn = 0;
              const char *vp = colon + 1;
              const char *lend = eol;
              for (;;)
                {
                  for (const char *c = vp; c < lend && rn + 1 < sizeof raw; c++) raw[rn++] = *c;
                  if (!*lend) break;
                  const char *next = lend + 1;
                  if (*next == ' ' || *next == '\t')
                    { if (rn + 1 < sizeof raw) raw[rn++] = ' '; vp = next;
                      lend = next; while (*lend && *lend != '\n') lend++; continue; }
                  break;
                }
              raw[rn] = '\0';
              char val[4096]; bm_relax_value (raw, val, sizeof val);
              size_t o = 0;
              for (const char *c = name; *c && o + 1 < cap; c++) out[o++] = (char) tolower ((unsigned char) *c);
              if (o + 1 < cap) out[o++] = ':';
              for (const char *c = val; *c && o + 1 < cap; c++) out[o++] = *c;
              out[o] = '\0';
              return 1;
            }
        }
      if (!*eol) break;
      p = eol + 1;
    }
  return 0;
}

/* Build a full "DKIM-Signature: ..." header line (no trailing newline),
 * or NULL on error. alg is "ed25519" or "rsa". The key bytes are read
 * into C memory here and never enter a shell variable. */
static char *
bm_dkim_header (const char *headers, const char *body, const char *selector,
                const char *domain, const char *alg, const char *keypath, long ts)
{
  static const char *cand[] = { "from","to","cc","subject","date","message-id",
                                "mime-version","content-type", NULL };
  size_t cblen; char *cb = bm_canon_body_relaxed (body, &cblen);
  if (!cb) return NULL;
  unsigned char bhraw[32]; bm_sha256 (cb, cblen, bhraw); free (cb);
  char bh[64]; if (bm_b64 (bhraw, 32, bh, sizeof bh) < 0) return NULL;

  char hblock[8192]; size_t hn = 0;
  char hlist[1024]; size_t ln = 0;
  char line[4096];
  int have_from = 0;
  for (int i = 0; cand[i]; i++)
    {
      if (!bm_header_canon (headers, cand[i], line, sizeof line)) continue;
      if (!strcmp (cand[i], "from")) have_from = 1;
      size_t l = strlen (line);
      if (hn + l + 3 >= sizeof hblock) break;
      memcpy (hblock + hn, line, l); hn += l; hblock[hn++] = '\r'; hblock[hn++] = '\n';
      if (ln && ln + 1 < sizeof hlist) hlist[ln++] = ':';
      for (const char *c = cand[i]; *c && ln + 1 < sizeof hlist; c++) hlist[ln++] = *c;
    }
  hblock[hn] = '\0'; hlist[ln] = '\0';
  if (!have_from) return NULL;

  const char *a = (alg && !strcmp (alg, "rsa")) ? "rsa-sha256" : "ed25519-sha256";
  char dkim_nb[2048];
  snprintf (dkim_nb, sizeof dkim_nb,
            "v=1; a=%s; c=relaxed/relaxed; d=%s; s=%s; t=%ld; h=%s; bh=%s; b=",
            a, domain, selector, ts, hlist, bh);
  char dkim_canon[2200];
  { char val[2200]; bm_relax_value (dkim_nb, val, sizeof val);
    snprintf (dkim_canon, sizeof dkim_canon, "dkim-signature:%s", val); }

  char *hashin = malloc (hn + strlen (dkim_canon) + 1);
  if (!hashin) return NULL;
  memcpy (hashin, hblock, hn);
  memcpy (hashin + hn, dkim_canon, strlen (dkim_canon) + 1);
  unsigned char dh[32]; bm_sha256 (hashin, hn + strlen (dkim_canon), dh);
  free (hashin);

  char *keytext = bm_read_text (keypath);
  if (!keytext) { builtin_error ("dkim: cannot read key %s", keypath ? keypath : "(null)"); return NULL; }

  char b64sig[1024]; int ok = 0;
  if (!strcmp (a, "ed25519-sha256"))
    {
      unsigned char seed[32];
      if (bm_unhex (keytext, seed, sizeof seed) != 32)
        builtin_error ("dkim: ed25519 key must be a 32-byte hex seed");
      else
        {
          uint8_t sk[64], pk[32], sig[64];
          crypto_ed25519_key_pair (sk, pk, seed);
          crypto_ed25519_sign (sig, sk, dh, 32);
          crypto_wipe (sk, 64); crypto_wipe (seed, 32);
          ok = bm_b64 (sig, 64, b64sig, sizeof b64sig) >= 0;
        }
    }
  else
    {
      psa_crypto_init ();                              /* RSA pk_sign is PSA-backed */
      mbedtls_pk_context pk; mbedtls_pk_init (&pk);
      if (mbedtls_pk_parse_key (&pk, (const unsigned char *) keytext, strlen (keytext) + 1,
                                NULL, 0) != 0)
        builtin_error ("dkim: cannot parse RSA private key (PEM)");
      else
        {
          unsigned char sig[512]; size_t slen = 0;
          if (mbedtls_pk_sign (&pk, MBEDTLS_MD_SHA256, dh, 32, sig, sizeof sig, &slen) != 0)
            builtin_error ("dkim: RSA sign failed");
          else
            ok = bm_b64 (sig, slen, b64sig, sizeof b64sig) >= 0;
        }
      mbedtls_pk_free (&pk);
    }
  free (keytext);
  if (!ok) return NULL;

  size_t cap = strlen (dkim_nb) + strlen (b64sig) + 32;
  char *hdr = malloc (cap);
  if (!hdr) return NULL;
  snprintf (hdr, cap, "DKIM-Signature: %s%s", dkim_nb, b64sig);
  return hdr;
}

static int
bm_deliver_fd_cmd (WORD_LIST *args)
{
  int fd = -1;
  const char *from = NULL, *queue = getenv ("BASHMAIL_QUEUE_DIR"), *qid = NULL;
  const char *ca = NULL, *ehlo = NULL, *peer_name = NULL;
  const char *dkim_key = NULL, *dkim_sel = NULL, *dkim_dom = NULL, *dkim_alg = "ed25519";
  long dkim_ts = (long) time (NULL);
  int tls_auto = 1, verify_peer = 0, timeout_ms = 120000;
  char *rcpts[BM_MAX_RCPT]; int nrcpt = 0;
  if (!queue) queue = BM_DEFAULT_QUEUE;

  WORD_LIST *p = args;
  for (; p; p = p->next)
    {
      const char *a = p->word->word;
      if (!strcmp (a, "--")) { p = p->next; break; }
      else if (!strcmp (a, "--fd")) { const char *v = bm_opt_val (&p); if (!v) goto usage; fd = atoi (v); }
      else if (!strcmp (a, "--from")) { from = bm_opt_val (&p); if (!from) goto usage; }
      else if (!strcmp (a, "--queue")) { queue = bm_opt_val (&p); if (!queue) goto usage; }
      else if (!strcmp (a, "--qid")) { qid = bm_opt_val (&p); if (!qid) goto usage; }
      else if (!strcmp (a, "--tls")) { const char *v = bm_opt_val (&p); if (!v) goto usage; tls_auto = strcmp (v, "off") != 0; }
      else if (!strcmp (a, "--tls-verify")) { const char *v = bm_opt_val (&p); if (!v) goto usage; verify_peer = !strcmp (v, "peer"); }
      else if (!strcmp (a, "--tls-ca")) { ca = bm_opt_val (&p); if (!ca) goto usage; }
      else if (!strcmp (a, "--ehlo")) { ehlo = bm_opt_val (&p); if (!ehlo) goto usage; }
      else if (!strcmp (a, "--peer-name")) { peer_name = bm_opt_val (&p); if (!peer_name) goto usage; }
      else if (!strcmp (a, "--dkim-key")) { dkim_key = bm_opt_val (&p); if (!dkim_key) goto usage; }
      else if (!strcmp (a, "--dkim-selector")) { dkim_sel = bm_opt_val (&p); if (!dkim_sel) goto usage; }
      else if (!strcmp (a, "--dkim-domain")) { dkim_dom = bm_opt_val (&p); if (!dkim_dom) goto usage; }
      else if (!strcmp (a, "--dkim-alg")) { dkim_alg = bm_opt_val (&p); if (!dkim_alg) goto usage; }
      else if (!strcmp (a, "--dkim-ts")) { const char *v = bm_opt_val (&p); if (!v) goto usage; dkim_ts = atol (v); }
      else if (!strcmp (a, "--timeout")) { const char *v = bm_opt_val (&p); if (!v) goto usage; timeout_ms = atoi (v); }
      else if (a[0] == '-' && a[1]) { builtin_error ("deliver-fd: unknown option: %s", a); return EX_USAGE; }
      else break;
    }
  for (; p; p = p->next) { if (nrcpt < BM_MAX_RCPT) rcpts[nrcpt++] = p->word->word; }

  if (fd < 0 || !from || !qid || nrcpt == 0) { goto usage; }

  char ehlo_buf[256];
  if (!ehlo) { ehlo_buf[0] = '\0'; gethostname (ehlo_buf, sizeof ehlo_buf - 1); ehlo = ehlo_buf[0] ? ehlo_buf : "localhost"; }

  /* Bound every dialog read/write so a stalled peer can't hang us. */
  struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
  setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

  /* Reconstruct the message (headers + blank line + body). */
  char entry[BM_PATH_MAX];
  if (snprintf (entry, sizeof entry, "%s/active/%s", queue, qid) >= (int) sizeof entry)
    return BM_EX_UNAVAIL;
  char *headers = bm_slurp (entry, "headers");
  char *body = bm_slurp (entry, "body");
  if (!headers) { free (body); builtin_error ("deliver-fd: cannot read queue entry %s", qid); return BM_EX_UNAVAIL; }
  if (!body) { body = strdup (""); }

  /* DKIM (6.4): sign over the original headers + body; prepend the
   * resulting DKIM-Signature header to the outgoing message. */
  char *dkim = NULL;
  if (dkim_key && dkim_sel && dkim_dom)
    {
      dkim = bm_dkim_header (headers, body, dkim_sel, dkim_dom, dkim_alg, dkim_key, dkim_ts);
      if (!dkim) { free (headers); free (body); builtin_error ("deliver-fd: DKIM signing failed"); return BM_EX_TEMPFAIL; }
    }

  size_t hlen = strlen (headers), blen = strlen (body);
  size_t dlen = dkim ? strlen (dkim) : 0;
  char *msg = malloc (dlen + 1 + hlen + 1 + blen + 1);
  if (!msg) { free (headers); free (body); free (dkim); return BM_EX_TEMPFAIL; }
  size_t mlen = 0;
  if (dkim) { memcpy (msg, dkim, dlen); mlen += dlen; msg[mlen++] = '\n'; }
  memcpy (msg + mlen, headers, hlen); mlen += hlen; msg[mlen++] = '\n';
  if (blen) { memcpy (msg + mlen, body, blen); mlen += blen; }
  msg[mlen] = '\0';
  free (headers); free (body); free (dkim);

  bm_smtp c = { .fd = fd, .tls = 0 };
  char caps[8192] = "";
  char cmd[BM_MAX_ADDR + 32];
  int code, rc = EXECUTION_SUCCESS;

  code = bm_smtp_reply (&c, NULL, 0);                       /* greeting */
  if (code / 100 != 2) { rc = bm_classify (code); goto done; }

  snprintf (cmd, sizeof cmd, "EHLO %s\r\n", ehlo);
  code = bm_smtp_cmd (&c, cmd, caps, sizeof caps);
  if (code / 100 != 2)
    {
      caps[0] = '\0';
      snprintf (cmd, sizeof cmd, "HELO %s\r\n", ehlo);
      code = bm_smtp_cmd (&c, cmd, NULL, 0);
      if (code / 100 != 2) { rc = bm_classify (code); goto done; }
    }

  if (tls_auto && !c.tls && strstr (caps, "STARTTLS"))
    {
      code = bm_smtp_cmd (&c, "STARTTLS\r\n", NULL, 0);
      if (code / 100 == 2)
        {
          if (bm_starttls (&c, verify_peer, ca, peer_name) < 0) { rc = BM_EX_TEMPFAIL; goto done; }
          caps[0] = '\0';
          snprintf (cmd, sizeof cmd, "EHLO %s\r\n", ehlo);
          code = bm_smtp_cmd (&c, cmd, caps, sizeof caps);
          if (code / 100 != 2) { rc = bm_classify (code); goto done; }
        }
      else if (verify_peer) { rc = BM_EX_TEMPFAIL; goto done; }   /* required but refused */
    }

  snprintf (cmd, sizeof cmd, "MAIL FROM:<%s>\r\n", from);
  code = bm_smtp_cmd (&c, cmd, NULL, 0);
  if (code / 100 != 2) { rc = bm_classify (code); goto done; }

  int naccept = 0, any_temp = 0;
  char accepted[BM_MAX_RCPT];                                /* 1 = RCPT 2xx */
  for (int i = 0; i < nrcpt; i++)
    {
      snprintf (cmd, sizeof cmd, "RCPT TO:<%s>\r\n", rcpts[i]);
      code = bm_smtp_cmd (&c, cmd, NULL, 0);
      accepted[i] = (code / 100 == 2) ? 1 : 0;
      if (accepted[i]) naccept++;
      else if (code < 0 || code / 100 == 4) any_temp = 1;
    }
  if (naccept == 0) { rc = any_temp ? BM_EX_TEMPFAIL : BM_EX_UNAVAIL; goto done; }

  code = bm_smtp_cmd (&c, "DATA\r\n", NULL, 0);
  if (code != 354) { rc = bm_classify (code); goto done; }
  if (bm_smtp_send_data (&c, msg, mlen) < 0) { rc = BM_EX_TEMPFAIL; goto done; }
  code = bm_smtp_reply (&c, NULL, 0);
  if (code / 100 != 2) { rc = bm_classify (code); goto done; }

  for (int i = 0; i < nrcpt; i++)
    if (accepted[i]) printf ("delivered %s\n", rcpts[i]);
  (void) bm_smtp_cmd (&c, "QUIT\r\n", NULL, 0);
  rc = EXECUTION_SUCCESS;

done:
  bm_smtp_close (&c);
  free (msg);
  return rc;

usage:
  builtin_error ("deliver-fd: usage: deliver-fd --fd N --from S --qid QID [--queue DIR] [--tls auto|off] [--tls-verify none|peer] [--tls-ca PEM] [--ehlo NAME] [--peer-name HOST] [--dkim-key PATH --dkim-selector S --dkim-domain D [--dkim-alg ed25519|rsa]] [--timeout MS] -- RCPT...");
  return EX_USAGE;
}

/* ---- DKIM verification (6.6 / inbound) ----------------------------- */

#include "_mbedtls_base64.h"

/* base64-decode into out (<=cap). Returns decoded length or -1. */
static int
bm_unb64 (const char *in, unsigned char *out, size_t cap)
{
  size_t olen = 0;
  if (mbedtls_base64_decode (out, cap, &olen, (const unsigned char *) in, strlen (in)) != 0)
    return -1;
  return (int) olen;
}

/* Extract the value of tag `key` (e.g. "bh") from a DKIM-Signature value
 * blob ("v=1; a=..; bh=..; b=.."). Writes to out; returns 1 if found. */
static int
bm_dkim_tag (const char *sig, const char *key, char *out, size_t cap)
{
  size_t kl = strlen (key);
  const char *p = sig;
  while (*p)
    {
      while (*p == ' ' || *p == ';') p++;
      if (!strncmp (p, key, kl) && p[kl] == '=')
        {
          const char *v = p + kl + 1; size_t o = 0;
          while (*v && *v != ';' && o + 1 < cap)
            { if (*v != ' ' && *v != '\t') out[o++] = *v; v++; }
          out[o] = '\0';
          return 1;
        }
      while (*p && *p != ';') p++;
    }
  return 0;
}

static int
bm_dkim_verify_cmd (WORD_LIST *args)
{
  const char *pubhex = NULL, *pub64 = NULL, *alg = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *a = p->word->word;
      if (!strcmp (a, "--pubkey-hex")) { pubhex = bm_opt_val (&p); if (!pubhex) goto usage; }
      else if (!strcmp (a, "--pubkey-b64")) { pub64 = bm_opt_val (&p); if (!pub64) goto usage; }
      else if (!strcmp (a, "--alg")) { alg = bm_opt_val (&p); if (!alg) goto usage; }
      else { builtin_error ("dkim-verify: unknown option: %s", a); return EX_USAGE; }
    }
  if (!pubhex && !pub64) goto usage;

  /* slurp the message on stdin */
  unsigned char *msg = NULL; size_t mlen = 0;
  if (bm_read_all_fd (0, &msg, &mlen, BM_MAX_MSG) != 0)
    { builtin_error ("dkim-verify: reading message"); return EXECUTION_FAILURE; }
  msg = realloc (msg, mlen + 1); if (!msg) return EXECUTION_FAILURE; msg[mlen] = '\0';

  /* split headers/body at first blank line */
  char *body = (char *) msg + mlen; char *headers = (char *) msg;
  for (size_t i = 0; i + 1 < mlen; i++)
    {
      if (msg[i] == '\n' && msg[i + 1] == '\n') { msg[i + 1] = '\0'; body = (char *) msg + i + 2; break; }
      if (i + 3 < mlen && !memcmp (msg + i, "\r\n\r\n", 4)) { msg[i + 2] = '\0'; body = (char *) msg + i + 4; break; }
    }

  int rc = EXECUTION_FAILURE;
  char dsig[2400];
  if (!bm_header_canon (headers, "dkim-signature", dsig, sizeof dsig))
    { builtin_error ("dkim-verify: no DKIM-Signature header"); free (msg); return EXECUTION_FAILURE; }
  /* dsig is "dkim-signature:v=1; ...; b=...." — point past the colon */
  char *sigval = strchr (dsig, ':'); sigval = sigval ? sigval + 1 : dsig;

  char a_tag[32], bh_tag[128], b_tag[1024], h_tag[1024];
  bm_dkim_tag (sigval, "a", a_tag, sizeof a_tag);
  bm_dkim_tag (sigval, "bh", bh_tag, sizeof bh_tag);
  bm_dkim_tag (sigval, "b", b_tag, sizeof b_tag);
  bm_dkim_tag (sigval, "h", h_tag, sizeof h_tag);
  if (!alg) alg = (strstr (a_tag, "rsa")) ? "rsa" : "ed25519";

  /* 1) body hash */
  size_t cblen; char *cb = bm_canon_body_relaxed (body, &cblen);
  if (!cb) { free (msg); return EXECUTION_FAILURE; }
  unsigned char bhraw[32]; bm_sha256 (cb, cblen, bhraw); free (cb);
  char bh_calc[64]; bm_b64 (bhraw, 32, bh_calc, sizeof bh_calc);
  if (strcmp (bh_calc, bh_tag) != 0)
    { builtin_error ("dkim-verify: body hash mismatch"); free (msg); return EXECUTION_FAILURE; }

  /* 2) header hash over the h= headers + DKIM-Signature(b emptied) */
  char hblock[8192]; size_t hn = 0; char line[4096];
  char hlist[1024]; snprintf (hlist, sizeof hlist, "%s", h_tag);
  for (char *tok = strtok (hlist, ":"); tok; tok = strtok (NULL, ":"))
    {
      while (*tok == ' ') tok++;
      if (bm_header_canon (headers, tok, line, sizeof line))
        {
          size_t l = strlen (line);
          if (hn + l + 3 < sizeof hblock) { memcpy (hblock + hn, line, l); hn += l; hblock[hn++] = '\r'; hblock[hn++] = '\n'; }
        }
    }
  /* DKIM-Signature canon with b= value removed (keep "b=") */
  char dnb[2400]; size_t di = 0;
  for (const char *s = dsig; *s && di + 1 < sizeof dnb; s++)
    {
      dnb[di++] = *s;
      if (s >= dsig + 2 && s[-1] == 'b' && s[0] == '=' && (s == dsig + 1 || s[-2] == ' ' || s[-2] == ';' || s[-2] == ':'))
        break;                                   /* stop right after "b=" */
    }
  dnb[di] = '\0';
  char *hashin = malloc (hn + di + 1);
  if (!hashin) { free (msg); return EXECUTION_FAILURE; }
  memcpy (hashin, hblock, hn); memcpy (hashin + hn, dnb, di + 1);
  unsigned char dh[32]; bm_sha256 (hashin, hn + di, dh);
  free (hashin);

  /* 3) signature verify */
  unsigned char sig[512]; int slen = bm_unb64 (b_tag, sig, sizeof sig);
  if (slen < 0) { builtin_error ("dkim-verify: bad b= base64"); free (msg); return EXECUTION_FAILURE; }

  if (!strcmp (alg, "ed25519"))
    {
      unsigned char pk[32];
      int pl = pubhex ? bm_unhex (pubhex, pk, sizeof pk) : bm_unb64 (pub64, pk, sizeof pk);
      if (pl != 32 || slen != 64) { builtin_error ("dkim-verify: bad ed25519 key/sig length"); free (msg); return EXECUTION_FAILURE; }
      rc = crypto_ed25519_check (sig, pk, dh, 32) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  else
    {
      unsigned char der[1024];
      int dl = pub64 ? bm_unb64 (pub64, der, sizeof der) : bm_unhex (pubhex, der, sizeof der);
      psa_crypto_init ();
      mbedtls_pk_context pk; mbedtls_pk_init (&pk);
      if (dl < 0 || mbedtls_pk_parse_public_key (&pk, der, (size_t) dl) != 0)
        builtin_error ("dkim-verify: cannot parse RSA public key");
      else
        rc = mbedtls_pk_verify (&pk, MBEDTLS_MD_SHA256, dh, 32, sig, (size_t) slen) == 0
               ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
      mbedtls_pk_free (&pk);
    }
  free (msg);
  return rc;

usage:
  builtin_error ("dkim-verify: usage: dkim-verify (--pubkey-hex H | --pubkey-b64 B) [--alg ed25519|rsa]  (message on stdin)");
  return EX_USAGE;
}

/* ---- inbound SMTP server (6.5) ------------------------------------- */

#include "bashcred_privdrop.h"

/* Read one CRLF/LF-terminated line from the connection (CR stripped).
 * Returns length or -1 on EOF/error. */
static int
bm_rx_line (bm_smtp *c, char *buf, size_t cap)
{
  size_t i = 0; int ch;
  while ((ch = bm_smtp_getc (c)) >= 0)
    {
      if (ch == '\n') { if (i && buf[i-1] == '\r') i--; buf[i] = '\0'; return (int) i; }
      if (i + 1 < cap) buf[i++] = (char) ch;
    }
  return -1;
}

/* Handle one inbound SMTP connection: RX dialog, enqueue to incoming/. */
static void
bm_smtpd_one (int cfd, const char *client_ip, const char *queue, const char *ehlo)
{
  bm_smtp c = { .fd = cfd, .tls = 0 };
  char line[4096], mail_from[BM_MAX_ADDR] = "", helo[256] = "";
  char *rcpts[BM_MAX_RCPT]; int nrcpt = 0;

  bm_smtp_write (&c, "220 ", 4);
  bm_smtp_write (&c, ehlo, strlen (ehlo));
  bm_smtp_write (&c, " ESMTP mail\r\n", 17);

  for (;;)
    {
      if (bm_rx_line (&c, line, sizeof line) < 0) break;
      if (!strncasecmp (line, "EHLO", 4) || !strncasecmp (line, "HELO", 4))
        {
          const char *h = line + 4; while (*h == ' ') h++;
          snprintf (helo, sizeof helo, "%s", h);
          char r[512]; int n = snprintf (r, sizeof r, "250-%s\r\n250 SIZE %d\r\n", ehlo, BM_MAX_MSG);
          bm_smtp_write (&c, r, n);
        }
      else if (!strncasecmp (line, "MAIL FROM:", 10))
        {
          const char *a = line + 10; while (*a == ' ' || *a == '<') a++;
          char tmp[BM_MAX_ADDR]; size_t o = 0;
          while (*a && *a != '>' && *a != ' ' && o + 1 < sizeof tmp) tmp[o++] = *a++;
          tmp[o] = '\0'; snprintf (mail_from, sizeof mail_from, "%s", tmp);
          bm_smtp_write (&c, "250 2.1.0 Ok\r\n", 14);
        }
      else if (!strncasecmp (line, "RCPT TO:", 8))
        {
          if (nrcpt < BM_MAX_RCPT)
            {
              const char *a = line + 8; while (*a == ' ' || *a == '<') a++;
              char tmp[BM_MAX_ADDR]; size_t o = 0;
              while (*a && *a != '>' && *a != ' ' && o + 1 < sizeof tmp) tmp[o++] = *a++;
              tmp[o] = '\0';
              rcpts[nrcpt] = strdup (tmp); if (rcpts[nrcpt]) nrcpt++;
            }
          bm_smtp_write (&c, "250 2.1.5 Ok\r\n", 14);
        }
      else if (!strncasecmp (line, "DATA", 4))
        {
          if (nrcpt == 0) { bm_smtp_write (&c, "554 5.5.1 no recipients\r\n", 25); continue; }
          bm_smtp_write (&c, "354 End data with <CR><LF>.<CR><LF>\r\n", 37);
          char *body = NULL; size_t blen = 0;
          FILE *m = open_memstream (&body, &blen);
          if (!m) { bm_smtp_write (&c, "451 4.3.0 internal\r\n", 20); continue; }
          for (;;)
            {
              int n = bm_rx_line (&c, line, sizeof line);
              if (n < 0) break;
              if (n == 1 && line[0] == '.') break;          /* end of DATA */
              const char *p = line;
              if (p[0] == '.' && p[1] == '.') p++;           /* undot-stuff */
              fprintf (m, "%s\n", p);
            }
          fclose (m);
          char extra[BM_MAX_ADDR + 512];
          snprintf (extra, sizeof extra,
                    "source=inbound\nclient_ip=%s\nhelo=%s\nmail_from=%s\n",
                    client_ip, helo, mail_from);
          char qid[24];
          int rc = bm_enqueue_sub (queue, "incoming", mail_from, rcpts, nrcpt,
                                   (const unsigned char *) (body ? body : ""), body ? blen : 0,
                                   extra, qid, sizeof qid);
          free (body);
          if (rc == 0)
            { char r[64]; int n = snprintf (r, sizeof r, "250 2.0.0 Ok: queued as %s\r\n", qid); bm_smtp_write (&c, r, n); }
          else
            bm_smtp_write (&c, "451 4.3.0 queue write failed\r\n", 30);
          /* reset transaction */
          for (int i = 0; i < nrcpt; i++) free (rcpts[i]);
          nrcpt = 0; mail_from[0] = '\0';
        }
      else if (!strncasecmp (line, "RSET", 4))
        { for (int i = 0; i < nrcpt; i++) free (rcpts[i]); nrcpt = 0; mail_from[0] = '\0'; bm_smtp_write (&c, "250 2.0.0 Ok\r\n", 14); }
      else if (!strncasecmp (line, "NOOP", 4))
        bm_smtp_write (&c, "250 2.0.0 Ok\r\n", 14);
      else if (!strncasecmp (line, "QUIT", 4))
        { bm_smtp_write (&c, "221 2.0.0 Bye\r\n", 15); break; }
      else
        bm_smtp_write (&c, "500 5.5.2 unrecognized command\r\n", 32);
    }
  for (int i = 0; i < nrcpt; i++) free (rcpts[i]);
}

static int
bm_smtpd_cmd (WORD_LIST *args)
{
  const char *bind_spec = NULL, *queue = getenv ("BASHMAIL_QUEUE_DIR");
  const char *user = "mail", *ehlo = NULL;
  if (!queue) queue = BM_DEFAULT_QUEUE;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *a = p->word->word;
      if (!strcmp (a, "--bind")) { bind_spec = bm_opt_val (&p); if (!bind_spec) goto usage; }
      else if (!strcmp (a, "--queue")) { queue = bm_opt_val (&p); if (!queue) goto usage; }
      else if (!strcmp (a, "--user")) { user = bm_opt_val (&p); if (!user) goto usage; }
      else if (!strcmp (a, "--ehlo")) { ehlo = bm_opt_val (&p); if (!ehlo) goto usage; }
      else { builtin_error ("smtpd: unknown option: %s", a); return EX_USAGE; }
    }
  if (!bind_spec) goto usage;

  char host[256], ehlo_buf[256];
  const char *colon = strrchr (bind_spec, ':');
  if (!colon) { builtin_error ("smtpd: --bind must be ADDR:PORT"); return EX_USAGE; }
  size_t hl = (size_t) (colon - bind_spec);
  if (hl >= sizeof host) return EXECUTION_FAILURE;
  memcpy (host, bind_spec, hl); host[hl] = '\0';
  const char *port = colon + 1;
  if (!ehlo) { ehlo_buf[0] = '\0'; gethostname (ehlo_buf, sizeof ehlo_buf - 1); ehlo = ehlo_buf[0] ? ehlo_buf : "localhost"; }

  struct addrinfo hints, *res = NULL;
  memset (&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_PASSIVE;
  if (getaddrinfo (host[0] ? host : NULL, port, &hints, &res) != 0 || !res)
    { builtin_error ("smtpd: cannot resolve %s", bind_spec); return EXECUTION_FAILURE; }
  int lfd = socket (res->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (lfd < 0) { freeaddrinfo (res); builtin_error ("smtpd: socket: %s", strerror (errno)); return EXECUTION_FAILURE; }
  int one = 1; setsockopt (lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  if (bind (lfd, res->ai_addr, res->ai_addrlen) < 0)
    { builtin_error ("smtpd: bind %s: %s", bind_spec, strerror (errno)); close (lfd); freeaddrinfo (res); return EXECUTION_FAILURE; }
  freeaddrinfo (res);
  if (listen (lfd, BM_LISTEN_BACKLOG) < 0)
    { builtin_error ("smtpd: listen: %s", strerror (errno)); close (lfd); return EXECUTION_FAILURE; }

  /* Drop privileges after the privileged bind (best-effort; only when root). */
  if (geteuid () == 0 && user && *user)
    {
      bc_user_info info;
      if (bc_lookup_user_by_name (user, &info) == 0)
        {
          char err[BC_PD_ERR_MAX]; gid_t g = info.gid;
          if (bc_privdrop_to_user (info.uid, info.gid, &g, 1, err, sizeof err) != 0)
            { builtin_error ("smtpd: privdrop to %s failed: %s", user, err); close (lfd); return EXECUTION_FAILURE; }
        }
      else
        builtin_error ("smtpd: user %s not found; staying privileged", user);
    }

  char inc[BM_PATH_MAX];
  snprintf (inc, sizeof inc, "%s/incoming", queue); bm_mkdir_p (inc, 0700);
  snprintf (inc, sizeof inc, "%s/rejected", queue); bm_mkdir_p (inc, 0700);

  struct sigaction act; memset (&act, 0, sizeof act);
  act.sa_handler = bm_sigstop;
  sigaction (SIGINT, &act, NULL); sigaction (SIGTERM, &act, NULL);
  signal (SIGPIPE, SIG_IGN);

  printf ("mail: smtpd listening on %s (queue %s)\n", bind_spec, queue);
  fflush (stdout);

  while (!bm_stop)
    {
      struct sockaddr_storage ss; socklen_t sl = sizeof ss;
      int cfd = accept (lfd, (struct sockaddr *) &ss, &sl);
      if (cfd < 0) { if (errno == EINTR) continue; if (bm_stop) break; continue; }
      char ip[INET6_ADDRSTRLEN] = "unknown";
      if (ss.ss_family == AF_INET)
        inet_ntop (AF_INET, &((struct sockaddr_in *) &ss)->sin_addr, ip, sizeof ip);
      else if (ss.ss_family == AF_INET6)
        inet_ntop (AF_INET6, &((struct sockaddr_in6 *) &ss)->sin6_addr, ip, sizeof ip);
      struct timeval tv = { .tv_sec = 120, .tv_usec = 0 };
      setsockopt (cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
      setsockopt (cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
      bm_smtpd_one (cfd, ip, queue, ehlo);
      close (cfd);
    }
  close (lfd);
  return EXECUTION_SUCCESS;

usage:
  builtin_error ("smtpd: usage: smtpd --bind ADDR:PORT [--queue DIR] [--user mail] [--ehlo NAME]");
  return EX_USAGE;
}

/* ---- dispatch ------------------------------------------------------ */

int
mail_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;

  if (!strcmp (cmd, "submit"))       return bm_submit_cmd (args);
  if (!strcmp (cmd, "serve"))        return bm_serve_cmd (args);
  if (!strcmp (cmd, "queue-list"))   return bm_queue_list_cmd (args);
  if (!strcmp (cmd, "queue-show"))   return bm_queue_show_cmd (args);
  if (!strcmp (cmd, "queue-delete")) return bm_queue_delete_cmd (args);
  if (!strcmp (cmd, "queue-flush"))  return bm_queue_flush_cmd (args);
  if (!strcmp (cmd, "newaliases"))   return bm_newaliases_cmd (args);
  if (!strcmp (cmd, "expand"))       return bm_expand_cmd (args);
  if (!strcmp (cmd, "deliver-fd"))   return bm_deliver_fd_cmd (args);
  if (!strcmp (cmd, "smtpd"))        return bm_smtpd_cmd (args);
  if (!strcmp (cmd, "dkim-verify"))  return bm_dkim_verify_cmd (args);

  builtin_error ("unknown subcommand: %s (try submit/serve/queue-list/queue-show/queue-delete/queue-flush/newaliases/expand/deliver-fd/smtpd/dkim-verify)", cmd);
  return EX_USAGE;
}

char *mail_doc[] = {
  "Local mail queue + UNIX-socket submission daemon (MTA 6.1).",
  "",
  "    mail submit [-f SENDER] [--socket PATH] [--queue DIR] [--direct] [--] RCPT...",
  "        Read a message on stdin and submit it. Default connects to the",
  "        submission socket; --direct enqueues straight to the queue dir.",
  "        Prints the queue id. Exit 0 ok, 75 daemon unreachable, 67 no",
  "        recipients, 2 usage.",
  "",
  "    mail serve --socket PATH --queue DIR [--conf FILE]",
  "        Submission daemon: bind the AF_UNIX socket, accept framed",
  "        submissions, enqueue each, reply with the queue id. Clean exit",
  "        on SIGINT/SIGTERM.",
  "",
  "    mail queue-list [--queue DIR]        Postfix-style mailq listing.",
  "    mail queue-show QID [--queue DIR]    Dump envelope+headers+body.",
  "    mail queue-delete QID|ALL [--queue DIR]   Remove queue entry(ies).",
  "    mail queue-flush [--pidfile PATH]    Wake the runner (SIGUSR1) to deliver now.",
  "",
  "    mail newaliases [--aliases FILE] [--db FILE]",
  "        Compile the Debian-format aliases source (default /etc/aliases)",
  "        into a sorted DB (default /etc/aliases.db). Exit 78 on parse error.",
  "",
  "    mail expand [--aliases-db FILE] [--aliases FILE] [--forward-root DIR] [--] RCPT...",
  "        Resolve each recipient to local mailbox(es): alias lookup from the",
  "        compiled DB (live aliases fallback), \\user escape, .forward, with",
  "        alias/forward cycle + depth-16 protection. Prints one local",
  "        recipient per line; exit 1 on any cycle/too-deep/invalid recipient.",
  "",
  "    mail deliver-fd --fd N --from S --qid QID [--queue DIR] [--tls auto|off]",
  "                        [--tls-verify none|peer] [--tls-ca PEM] [--ehlo NAME]",
  "                        [--peer-name HOST] [--timeout MS]",
  "                        [--dkim-key PATH --dkim-selector S --dkim-domain D",
  "                         [--dkim-alg ed25519|rsa]] -- RCPT...",
  "        Run the SMTP (+ opportunistic STARTTLS) dialog on an already-",
  "        connected socket fd, sending the queued message <queue>/active/",
  "        <QID> to RCPTs. With --dkim-*, prepends an RFC 6376 DKIM-Signature",
  "        (relaxed/relaxed; key read in C, never a shell var). Prints",
  "        'delivered <rcpt>' per accepted recipient. Exit 0 delivered, 75",
  "        temp-fail (4xx/conn/TLS), 69 perm-fail (5xx).",
  "",
  "    mail smtpd --bind ADDR:PORT [--queue DIR] [--user mail] [--ehlo NAME]",
  "        Inbound SMTP server: bind (privileged port as root then drop to",
  "        --user via cred), accept, run the RX dialog, and enqueue each",
  "        message into <queue>/incoming/ with client_ip/helo/mail_from meta.",
  "",
  "    mail dkim-verify (--pubkey-hex H | --pubkey-b64 B) [--alg ed25519|rsa]",
  "        Verify the DKIM-Signature of the message on stdin against the given",
  "        public key. Exit 0 valid, 1 invalid, 2 usage.",
  "",
  "Env: BASHMAIL_SUBMIT_SOCK overrides the socket; BASHMAIL_QUEUE_DIR the",
  "queue; BASHMAIL_ALIASES / BASHMAIL_ALIASES_DB / BASHMAIL_FORWARD_ROOT the",
  "alias source / compiled DB / .forward root. Default socket",
  "/run/bash-os/mail/submit.sock, queue /var/lib/bash-os/mail/queue.",
  (char *) NULL
};

struct builtin mail_struct = {
  "mail",
  mail_builtin,
  BUILTIN_ENABLED,
  mail_doc,
  "mail submit|serve|queue-list|queue-show|queue-delete [OPTIONS]",
  0
};
