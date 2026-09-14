/* SPDX-License-Identifier: MIT */
/* sftp.c — sftp + scp client surface over the ssh command-stream
 * transport (ML-T4-05 / Round 1778961001 Doc 17).
 *
 * Goal: ship the user-visible sftp(1) and scp(1) shapes without porting
 * the OpenSSH SFTP wire protocol. Instead, every sftp verb is rewritten
 * into a one-shot `bash -c` command sent through the sshd framed
 * channel (the same protocol ssh.c speaks). Bytes flow over stdin/
 * stdout of that single command; the result is captured and re-emitted
 * locally. The remote shell does the heavy lifting (cat, ls, mkdir,
 * mv, rm, etc.); sftp marshals argv/stdin and surfaces the result
 * with sftp-compatible prompts.
 *
 * Wire protocol (verbatim with ssh/sshd, "BASHSSH1"):
 *   client → server  BASHSSH1\n
 *                    cmd-len NNN\n
 *                    stdin-len MMM\n
 *                    \n
 *                    <NNN bytes of cmd> <MMM bytes of stdin>
 *   server → client  BASHSSH1-RESP\n
 *                    rc N\n
 *                    stdout-len SSS\n
 *                    stderr-len EEE\n
 *                    \n
 *                    <SSS bytes of stdout> <EEE bytes of stderr>
 *
 * --- VERBS ---
 *
 *   sftp HOST [-p PORT] [-l USER] [-i KEY] [--openssh]
 *       Open an interactive sftp session against HOST. Reads commands
 *       from stdin until EOF/quit/bye. State (remote cwd, local cwd)
 *       is tracked client-side and re-applied to each one-shot remote
 *       command.
 *
 *   sftp -b BATCHFILE HOST [...]
 *       Same, but read commands from BATCHFILE (one per line). Empty
 *       lines and lines beginning with `#` are ignored.
 *
 *   sftp scp SRC DST [-r] [-P PORT] [-i KEY] [--openssh]
 *       Dispatched directly by the scp companion builtin. Maps
 *       cp-shape argv to put/get operations.
 *
 * --- SUPPORTED COMMANDS IN INTERACTIVE MODE ---
 *
 *   pwd, lpwd, cd PATH, lcd PATH, ls [PATH], lls [PATH], get REMOTE
 *   [LOCAL], put LOCAL [REMOTE], mkdir PATH, rmdir PATH, rm PATH,
 *   rename SRC DST, chmod MODE PATH, help, ?, quit, bye, exit.
 *
 * --- LIMITS ---
 *
 *   * No SFTP wire protocol (no SSH_FXP_* messages, no extension
 *     negotiation). The remote endpoint is sshd, not sshd-sftp.
 *   * No glob, no resume, no preserve flags, no recursive put/get
 *     unless -r is passed to scp (and the implementation falls
 *     back to `tar -cf - | tar -xf -` over the channel).
 *   * No interactive password prompt — the ssh transport relies
 *     on connection-handle-baked credentials (or --openssh + ssh-agent
 *     for the OpenSSH-backed path).
 *
 * --- LICENSE ---
 * MIT — same boilerplate shape as other project-local loadables.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
# include <unistd.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <libgen.h>
#include <poll.h>
#include <stdint.h>

#include "loadables.h"
#include "command-run.h"

/* ---------- shared blob + I/O helpers (mirrors ssh/sshd) ---------- */

typedef struct {
  char *p;
  size_t n, cap;
} blob;

static int blob_append (blob *b, const void *p, size_t n)
{
  if (!n) return 0;
  if (n >= SIZE_MAX - b->n) { errno = EOVERFLOW; return -1; }
  size_t need = b->n + n + 1;
  if (!b->p || need > b->cap)
    {
      size_t nc = b->cap ? b->cap * 2 : 4096;
      if (nc < b->cap) nc = need;
      while (nc < need) {
        if (nc > SIZE_MAX / 2) { nc = need; break; }
        nc *= 2;
      }
      char *q = realloc (b->p, nc);
      if (!q) return -1;
      b->p = q; b->cap = nc;
    }
  memcpy (b->p + b->n, p, n);
  b->n += n;
  b->p[b->n] = '\0';
  return 0;
}

static void blob_reset (blob *b) { b->n = 0; if (b->p) b->p[0] = '\0'; }
static void blob_free (blob *b) { free (b->p); b->p = NULL; b->n = b->cap = 0; }

static int write_all (int fd, const void *p, size_t n)
{
  const char *s = p;
  while (n)
    {
      ssize_t w = write (fd, s, n);
      if (w < 0 && errno == EINTR) continue;
      if (w < 0) return -1;
      s += w; n -= (size_t) w;
    }
  return 0;
}

static int read_line_fd (int fd, char *buf, size_t sz)
{
  size_t n = 0;
  while (n + 1 < sz)
    {
      char c;
      ssize_t r = read (fd, &c, 1);
      if (r < 0 && errno == EINTR) continue;
      if (r <= 0) return -1;
      buf[n++] = c;
      if (c == '\n') break;
    }
  buf[n] = '\0';
  return 0;
}

static int read_exact_blob (int fd, blob *b, size_t want)
{
  char buf[8192];
  while (want)
    {
      size_t chunk = want < sizeof buf ? want : sizeof buf;
      ssize_t r = read (fd, buf, chunk);
      if (r < 0 && errno == EINTR) continue;
      if (r <= 0) return -1;
      if (blob_append (b, buf, (size_t) r) < 0) return -1;
      want -= (size_t) r;
    }
  return 0;
}

static int read_file_blob (const char *path, blob *out)
{
  int fd = open (path, O_RDONLY);
  if (fd < 0) { builtin_error ("%s: %s", path, strerror (errno)); return -1; }
  char buf[8192];
  for (;;)
    {
      ssize_t r = read (fd, buf, sizeof buf);
      if (r < 0 && errno == EINTR) continue;
      if (r < 0) { builtin_error ("read %s: %s", path, strerror (errno)); close (fd); return -1; }
      if (r == 0) break;
      if (blob_append (out, buf, (size_t) r) < 0) { close (fd); return -1; }
    }
  close (fd);
  return 0;
}

static int write_file_blob (const char *path, const blob *b)
{
  int fd = open (path, O_WRONLY|O_CREAT|O_TRUNC, 0666);
  if (fd < 0) { builtin_error ("%s: %s", path, strerror (errno)); return -1; }
  int rc = write_all (fd, b->p ? b->p : "", b->n);
  if (close (fd) < 0) rc = -1;
  if (rc < 0) builtin_error ("write %s: %s", path, strerror (errno));
  return rc;
}

static int connect_tcp (const char *host, const char *port)
{
  struct addrinfo hints, *res = NULL, *rp;
  memset (&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  int gai = getaddrinfo (host, port, &hints, &res);
  if (gai != 0) { builtin_error ("getaddrinfo %s:%s: %s", host, port, gai_strerror (gai)); return -1; }
  int fd = -1;
  for (rp = res; rp; rp = rp->ai_next)
    {
      fd = socket (rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC, rp->ai_protocol);
      if (fd < 0) continue;
      if (connect (fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
      close (fd); fd = -1;
    }
  freeaddrinfo (res);
  if (fd < 0) builtin_error ("connect %s:%s: %s", host, port, strerror (errno));
  return fd;
}

/* ---------- session state ---------- */

typedef struct {
  char host[256];
  char port[32];
  char user[128];
  char key[512];
  char rcwd[1024];   /* tracked remote cwd; "" = let remote shell decide */
  int openssh;        /* 1 → shell out to ssh(1); 0 → native ssh wire */
} sftp_session;

struct bsftp_child_guard {
  struct sigaction old_action;
  sigset_t old_mask;
};

static void bsftp_child_guard_begin (struct bsftp_child_guard *g)
{
  struct sigaction chld_dfl;
  memset (&chld_dfl, 0, sizeof chld_dfl);
  chld_dfl.sa_handler = SIG_DFL;
  sigemptyset (&chld_dfl.sa_mask);
  sigaction (SIGCHLD, &chld_dfl, &g->old_action);

  sigset_t chld_set;
  sigemptyset (&chld_set);
  sigaddset (&chld_set, SIGCHLD);
  sigprocmask (SIG_BLOCK, &chld_set, &g->old_mask);
}

static void bsftp_child_guard_parent_end (struct bsftp_child_guard *g)
{
  sigprocmask (SIG_SETMASK, &g->old_mask, NULL);
  sigaction (SIGCHLD, &g->old_action, NULL);
}

static void bsftp_child_guard_child_end (struct bsftp_child_guard *g)
{
  sigprocmask (SIG_SETMASK, &g->old_mask, NULL);
}

static int run_local_helper (char *const argv[], const blob *in, blob *out, blob *err, int builtin_ok)
{
  int ip[2] = {-1, -1}, op[2] = {-1, -1}, ep[2] = {-1, -1};
  if (in && pipe (ip) < 0) return 127;
  if (out && pipe (op) < 0)
    { if (ip[0] >= 0) { close (ip[0]); close (ip[1]); } return 127; }
  if (err && pipe (ep) < 0)
    {
      if (ip[0] >= 0) { close (ip[0]); close (ip[1]); }
      if (op[0] >= 0) { close (op[0]); close (op[1]); }
      return 127;
    }

  struct bsftp_child_guard guard;
  bsftp_child_guard_begin (&guard);
  pid_t pid = fork ();
  if (pid < 0)
    {
      bsftp_child_guard_parent_end (&guard);
      if (ip[0] >= 0) { close (ip[0]); close (ip[1]); }
      if (op[0] >= 0) { close (op[0]); close (op[1]); }
      if (ep[0] >= 0) { close (ep[0]); close (ep[1]); }
      return 127;
    }
  if (pid == 0)
    {
      bsftp_child_guard_child_end (&guard);
      bos_prepare_child ();
      if (in)
        { close (ip[1]); dup2 (ip[0], STDIN_FILENO); close (ip[0]); }
      if (out)
        { close (op[0]); dup2 (op[1], STDOUT_FILENO); close (op[1]); }
      if (err)
        { close (ep[0]); dup2 (ep[1], STDERR_FILENO); close (ep[1]); }
      if (builtin_ok) bos_run_builtin (argv[0], (char **) argv, NULL);
      execvp (argv[0], argv);
      _exit (127);
    }

  if (ip[0] >= 0) close (ip[0]);
  if (op[1] >= 0) close (op[1]);
  if (ep[1] >= 0) close (ep[1]);

  /* Drain both output pipes while feeding input: sequential pumping deadlocks
     when a child fills stderr or writes before reading its input. */
  struct pollfd fds[3] = {{ip[1], POLLOUT, 0}, {op[0], POLLIN, 0}, {ep[0], POLLIN, 0}};
  size_t sent = 0;
  int failed = 0;
  struct sigaction ignore = {0}, old_pipe;
  ignore.sa_handler = SIG_IGN;
  sigemptyset (&ignore.sa_mask);
  sigaction (SIGPIPE, &ignore, &old_pipe);
  if (fds[0].fd >= 0) {
    if (!in->n) { close (fds[0].fd); fds[0].fd = -1; }
    else if (fcntl (fds[0].fd, F_SETFL, O_NONBLOCK) < 0) failed = 1;
  }
  char buf[4096];
  while (!failed && (fds[0].fd >= 0 || fds[1].fd >= 0 || fds[2].fd >= 0)) {
    int ready = poll (fds, 3, -1);
    if (ready < 0) { if (errno == EINTR) continue; failed = 1; break; }
    if (fds[0].fd >= 0 && fds[0].revents) {
      ssize_t n = write (fds[0].fd, in->p + sent, in->n - sent);
      if (n > 0) sent += (size_t) n;
      else if (n < 0 && errno != EINTR && errno != EAGAIN) failed = 1;
      if (sent == in->n || failed) { close (fds[0].fd); fds[0].fd = -1; }
    }
    for (int i = 1; i < 3; i++) if (fds[i].fd >= 0 && fds[i].revents) {
      ssize_t n = read (fds[i].fd, buf, sizeof buf);
      if (n > 0) { if (blob_append (i == 1 ? out : err, buf, (size_t) n) < 0) failed = 1; }
      else if (n == 0) { close (fds[i].fd); fds[i].fd = -1; }
      else if (errno != EINTR && errno != EAGAIN) failed = 1;
    }
  }
  for (int i = 0; i < 3; i++) if (fds[i].fd >= 0) close (fds[i].fd);
  sigaction (SIGPIPE, &old_pipe, NULL);
  if (failed) kill (pid, SIGKILL);

  int st = 0;
  pid_t w;
  while ((w = waitpid (pid, &st, 0)) < 0 && errno == EINTR) ;
  bsftp_child_guard_parent_end (&guard);
  if (failed) return 127;
  if (w == pid && WIFEXITED (st)) return WEXITSTATUS (st);
  if (w == pid && WIFSIGNALED (st)) return 128 + WTERMSIG (st);
  return 127;
}

/* ---------- one-shot remote command (native wire) ---------- */

static int run_remote_native (const sftp_session *s, const char *cmd,
                              const blob *in, blob *out, blob *err)
{
  int fd = connect_tcp (s->host, s->port);
  if (fd < 0) return -1;
  size_t cmdlen = strlen (cmd);
  size_t inlen = in ? in->n : 0;
  char hdr[256];
  int hn = snprintf (hdr, sizeof hdr,
                     "BASHSSH1\ncmd-len %zu\nstdin-len %zu\n\n", cmdlen, inlen);
  if (hn < 0 || (size_t) hn >= sizeof hdr
      || write_all (fd, hdr, (size_t) hn) < 0
      || write_all (fd, cmd, cmdlen) < 0
      || (inlen && write_all (fd, in->p, inlen) < 0))
    { builtin_error ("write request: %s", strerror (errno)); close (fd); return -1; }

  char line[256];
  size_t outlen = 0, errlen = 0;
  int rc = 127;
  if (read_line_fd (fd, line, sizeof line) < 0
      || strcmp (line, "BASHSSH1-RESP\n") != 0)
    { builtin_error ("sftp: bad sshd response"); close (fd); return -1; }
  while (read_line_fd (fd, line, sizeof line) == 0)
    {
      if (strcmp (line, "\n") == 0) break;
      if (sscanf (line, "rc %d", &rc) == 1) continue;
      if (sscanf (line, "stdout-len %zu", &outlen) == 1) continue;
      if (sscanf (line, "stderr-len %zu", &errlen) == 1) continue;
    }
  if (read_exact_blob (fd, out, outlen) < 0
      || read_exact_blob (fd, err, errlen) < 0)
    { builtin_error ("sftp: short response"); close (fd); return -1; }
  close (fd);
  return rc;
}

/* ---------- one-shot remote command (openssh wire) ---------- */

static int run_remote_openssh (const sftp_session *s, const char *cmd,
                               const blob *in, blob *out, blob *err)
{
  char target[512];
  if (s->user[0]) snprintf (target, sizeof target, "%s@%s", s->user, s->host);
  else snprintf (target, sizeof target, "%s", s->host);
  const char *ssh_bin = getenv ("BASHSSH_OPENSSH_BIN");
  if (!ssh_bin || !ssh_bin[0]) ssh_bin = "ssh";
  char *argv[16]; int n = 0;
  argv[n++] = (char *) ssh_bin;
  argv[n++] = "-o"; argv[n++] = "BatchMode=yes";
  argv[n++] = "-o"; argv[n++] = "StrictHostKeyChecking=accept-new";
  argv[n++] = "-p"; argv[n++] = (char *) s->port;
  if (s->key[0]) { argv[n++] = "-i"; argv[n++] = (char *) s->key; }
  argv[n++] = target; argv[n++] = (char *) cmd; argv[n] = NULL;
  blob empty = {0};
  return run_local_helper (argv, in ? in : &empty, out, err, 0);
}

static int run_remote (const sftp_session *s, const char *cmd,
                       const blob *in, blob *out, blob *err)
{
  if (s->openssh) return run_remote_openssh (s, cmd, in, out, err);
  return run_remote_native (s, cmd, in, out, err);
}

/* Wrap raw verbs with the session's tracked cwd so the remote shell
 * runs the command in the right working directory. The cwd is single-
 * quoted with embedded "'" escaped to '\'' (POSIX-safe). */
static int build_cmd (const sftp_session *s, const char *verb,
                      char *out, size_t outsz)
{
  if (!s->rcwd[0]) {
    int n = snprintf (out, outsz, "%s", verb);
    return (n < 0 || (size_t) n >= outsz) ? -1 : 0;
  }
  blob esc = {0};
  blob_append (&esc, "'", 1);
  for (const char *p = s->rcwd; *p; p++) {
    if (*p == '\'') blob_append (&esc, "'\\''", 4);
    else blob_append (&esc, p, 1);
  }
  blob_append (&esc, "'", 1);
  int n = snprintf (out, outsz, "cd %s && %s", esc.p ? esc.p : "''", verb);
  blob_free (&esc);
  return (n < 0 || (size_t) n >= outsz) ? -1 : 0;
}

/* Quote a single string for /bin/sh consumption (single-quote wrap). */
static int shquote (const char *in, blob *out)
{
  if (blob_append (out, "'", 1) < 0) return -1;
  for (const char *p = in; *p; p++)
    {
      if (*p == '\'')
        { if (blob_append (out, "'\\''", 4) < 0) return -1; }
      else
        { if (blob_append (out, p, 1) < 0) return -1; }
    }
  return blob_append (out, "'", 1);
}

/* ---------- sftp verb dispatchers ---------- */

static int sftp_pwd (sftp_session *s)
{
  blob out = {0}, err = {0};
  int rc = run_remote (s, "pwd", NULL, &out, &err);
  if (rc == 0 && out.n)
    {
      /* strip trailing newline before assigning as new rcwd if empty */
      while (out.n && (out.p[out.n - 1] == '\n' || out.p[out.n - 1] == '\r'))
        out.p[--out.n] = '\0';
      printf ("Remote working directory: %s\n", out.p ? out.p : "/");
      if (!s->rcwd[0]) snprintf (s->rcwd, sizeof s->rcwd, "%s", out.p ? out.p : "/");
    }
  else if (err.n)
    fwrite (err.p, 1, err.n, stderr);
  blob_free (&out); blob_free (&err);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int sftp_cd (sftp_session *s, const char *path)
{
  if (!path || !*path) { builtin_error ("cd: missing path"); return EX_USAGE; }
  /* Resolve via the remote shell so symlinks/relative paths work,
   * then store the canonical form for subsequent commands. */
  blob q = {0};
  if (shquote (path, &q) < 0) { blob_free (&q); return EXECUTION_FAILURE; }
  char verb[2048];
  snprintf (verb, sizeof verb, "cd %s && pwd", q.p);
  blob_free (&q);
  char cmd[4096];
  if (build_cmd (s, verb, cmd, sizeof cmd) < 0) return EXECUTION_FAILURE;
  blob out = {0}, err = {0};
  int rc = run_remote (s, cmd, NULL, &out, &err);
  if (rc == 0 && out.n)
    {
      while (out.n && (out.p[out.n - 1] == '\n' || out.p[out.n - 1] == '\r'))
        out.p[--out.n] = '\0';
      snprintf (s->rcwd, sizeof s->rcwd, "%s", out.p);
    }
  else if (err.n)
    fwrite (err.p, 1, err.n, stderr);
  blob_free (&out); blob_free (&err);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int sftp_ls (sftp_session *s, const char *path)
{
  blob q = {0};
  char verb[2048];
  if (path && *path)
    {
      if (shquote (path, &q) < 0) { blob_free (&q); return EXECUTION_FAILURE; }
      snprintf (verb, sizeof verb, "ls -la -- %s", q.p);
      blob_free (&q);
    }
  else
    snprintf (verb, sizeof verb, "ls -la");
  char cmd[4096];
  if (build_cmd (s, verb, cmd, sizeof cmd) < 0) return EXECUTION_FAILURE;
  blob out = {0}, err = {0};
  int rc = run_remote (s, cmd, NULL, &out, &err);
  if (out.n) fwrite (out.p, 1, out.n, stdout);
  if (err.n) fwrite (err.p, 1, err.n, stderr);
  blob_free (&out); blob_free (&err);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int sftp_get (sftp_session *s, const char *remote, const char *local)
{
  if (!remote || !*remote) { builtin_error ("get: missing remote path"); return EX_USAGE; }
  blob q = {0};
  if (shquote (remote, &q) < 0) { blob_free (&q); return EXECUTION_FAILURE; }
  char verb[2048];
  snprintf (verb, sizeof verb, "cat -- %s", q.p);
  blob_free (&q);
  char cmd[4096];
  if (build_cmd (s, verb, cmd, sizeof cmd) < 0) return EXECUTION_FAILURE;
  blob out = {0}, err = {0};
  int rc = run_remote (s, cmd, NULL, &out, &err);
  if (rc != 0)
    {
      if (err.n) fwrite (err.p, 1, err.n, stderr);
      blob_free (&out); blob_free (&err);
      return EXECUTION_FAILURE;
    }
  /* Pick a local path: if not given, basename of remote. */
  char lbuf[1024];
  const char *target = local;
  if (!target || !*target)
    {
      char tmp[1024];
      snprintf (tmp, sizeof tmp, "%s", remote);
      const char *base = basename (tmp);
      snprintf (lbuf, sizeof lbuf, "%s", base);
      target = lbuf;
    }
  if (write_file_blob (target, &out) < 0)
    { blob_free (&out); blob_free (&err); return EXECUTION_FAILURE; }
  fprintf (stderr, "Fetched %s to %s (%zu bytes)\n", remote, target, out.n);
  blob_free (&out); blob_free (&err);
  return EXECUTION_SUCCESS;
}

static int sftp_put (sftp_session *s, const char *local, const char *remote)
{
  if (!local || !*local) { builtin_error ("put: missing local path"); return EX_USAGE; }
  blob in = {0};
  if (read_file_blob (local, &in) < 0) { blob_free (&in); return EXECUTION_FAILURE; }

  const char *target = remote;
  char rbuf[1024];
  if (!target || !*target)
    {
      char tmp[1024];
      snprintf (tmp, sizeof tmp, "%s", local);
      const char *base = basename (tmp);
      snprintf (rbuf, sizeof rbuf, "%s", base);
      target = rbuf;
    }
  blob q = {0};
  if (shquote (target, &q) < 0)
    { blob_free (&in); blob_free (&q); return EXECUTION_FAILURE; }
  char verb[2048];
  snprintf (verb, sizeof verb, "cat > %s", q.p);
  blob_free (&q);
  char cmd[4096];
  if (build_cmd (s, verb, cmd, sizeof cmd) < 0)
    { blob_free (&in); return EXECUTION_FAILURE; }
  blob out = {0}, err = {0};
  int rc = run_remote (s, cmd, &in, &out, &err);
  if (rc != 0 && err.n) fwrite (err.p, 1, err.n, stderr);
  if (rc == 0)
    fprintf (stderr, "Uploaded %s to %s (%zu bytes)\n", local, target, in.n);
  blob_free (&in); blob_free (&out); blob_free (&err);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int run_simple (sftp_session *s, const char *verb)
{
  char cmd[4096];
  if (build_cmd (s, verb, cmd, sizeof cmd) < 0) return EXECUTION_FAILURE;
  blob out = {0}, err = {0};
  int rc = run_remote (s, cmd, NULL, &out, &err);
  if (out.n) fwrite (out.p, 1, out.n, stdout);
  if (err.n) fwrite (err.p, 1, err.n, stderr);
  blob_free (&out); blob_free (&err);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int sftp_mkdir (sftp_session *s, const char *path)
{
  if (!path || !*path) { builtin_error ("mkdir: missing path"); return EX_USAGE; }
  blob q = {0};
  if (shquote (path, &q) < 0) { blob_free (&q); return EXECUTION_FAILURE; }
  char verb[2048];
  snprintf (verb, sizeof verb, "mkdir -p -- %s", q.p);
  blob_free (&q);
  return run_simple (s, verb);
}

static int sftp_rmdir (sftp_session *s, const char *path)
{
  if (!path || !*path) { builtin_error ("rmdir: missing path"); return EX_USAGE; }
  blob q = {0};
  if (shquote (path, &q) < 0) { blob_free (&q); return EXECUTION_FAILURE; }
  char verb[2048];
  snprintf (verb, sizeof verb, "rmdir -- %s", q.p);
  blob_free (&q);
  return run_simple (s, verb);
}

static int sftp_rm (sftp_session *s, const char *path)
{
  if (!path || !*path) { builtin_error ("rm: missing path"); return EX_USAGE; }
  blob q = {0};
  if (shquote (path, &q) < 0) { blob_free (&q); return EXECUTION_FAILURE; }
  char verb[2048];
  snprintf (verb, sizeof verb, "rm -f -- %s", q.p);
  blob_free (&q);
  return run_simple (s, verb);
}

static int sftp_rename (sftp_session *s, const char *src, const char *dst)
{
  if (!src || !*src || !dst || !*dst)
    { builtin_error ("rename: usage: rename SRC DST"); return EX_USAGE; }
  blob qs = {0}, qd = {0};
  if (shquote (src, &qs) < 0 || shquote (dst, &qd) < 0)
    { blob_free (&qs); blob_free (&qd); return EXECUTION_FAILURE; }
  char verb[4096];
  snprintf (verb, sizeof verb, "mv -- %s %s", qs.p, qd.p);
  blob_free (&qs); blob_free (&qd);
  return run_simple (s, verb);
}

static int sftp_chmod (sftp_session *s, const char *mode, const char *path)
{
  if (!mode || !path)
    { builtin_error ("chmod: usage: chmod MODE PATH"); return EX_USAGE; }
  /* mode is an octal string; treat as opaque token, no quoting. */
  blob qp = {0};
  if (shquote (path, &qp) < 0) { blob_free (&qp); return EXECUTION_FAILURE; }
  char verb[4096];
  snprintf (verb, sizeof verb, "chmod %s -- %s", mode, qp.p);
  blob_free (&qp);
  return run_simple (s, verb);
}

static void sftp_print_help (void)
{
  fputs (
    "Available commands:\n"
    "  bye | quit | exit         Close the session and exit.\n"
    "  cd PATH                   Change remote directory.\n"
    "  chmod MODE PATH           Change remote permissions.\n"
    "  get REMOTE [LOCAL]        Download remote file.\n"
    "  help | ?                  Print this help.\n"
    "  lcd PATH                  Change local directory.\n"
    "  lls [PATH]                List local directory.\n"
    "  lpwd                      Print local working directory.\n"
    "  ls [PATH]                 List remote directory.\n"
    "  mkdir PATH                Create remote directory.\n"
    "  put LOCAL [REMOTE]        Upload local file.\n"
    "  pwd                       Print remote working directory.\n"
    "  rename SRC DST            Rename remote file.\n"
    "  rm PATH                   Remove remote file.\n"
    "  rmdir PATH                Remove remote directory.\n",
    stdout);
}

/* Split a single sftp command line into argv. Quoting: backslash
 * escapes the next char; otherwise whitespace separates tokens. No
 * embedded variables / glob — matches openssh sftp's quoting model
 * close enough for our verbs. Caller frees argv (entries are owned). */
static int split_line (const char *line, char ***out_argv, int *out_argc)
{
  *out_argv = NULL; *out_argc = 0;
  size_t cap = 8;
  char **argv = calloc (cap, sizeof *argv);
  if (!argv) return -1;
  int argc = 0;
  const char *p = line;
  blob tok = {0};
  int in_tok = 0;
  while (*p)
    {
      if (isspace ((unsigned char) *p))
        {
          if (in_tok)
            {
              if ((size_t) argc + 1 >= cap)
                { cap *= 2; char **q = realloc (argv, cap * sizeof *argv);
                  if (!q) { free (argv); blob_free (&tok); return -1; }
                  argv = q; }
              argv[argc++] = tok.p ? strdup (tok.p) : strdup ("");
              blob_reset (&tok);
              in_tok = 0;
            }
          p++;
          continue;
        }
      if (*p == '\\' && p[1])
        { blob_append (&tok, p + 1, 1); p += 2; in_tok = 1; continue; }
      blob_append (&tok, p, 1);
      in_tok = 1;
      p++;
    }
  if (in_tok)
    {
      if ((size_t) argc + 1 >= cap)
        { cap *= 2; char **q = realloc (argv, cap * sizeof *argv);
          if (!q) { free (argv); blob_free (&tok); return -1; }
          argv = q; }
      argv[argc++] = tok.p ? strdup (tok.p) : strdup ("");
    }
  argv[argc] = NULL;
  blob_free (&tok);
  *out_argv = argv;
  *out_argc = argc;
  return 0;
}

static void free_argv (char **argv, int argc)
{
  for (int i = 0; i < argc; i++) free (argv[i]);
  free (argv);
}

static int sftp_dispatch (sftp_session *s, int argc, char **argv)
{
  if (argc == 0) return EXECUTION_SUCCESS;
  const char *v = argv[0];
  if (!strcmp (v, "bye") || !strcmp (v, "quit") || !strcmp (v, "exit"))
    return 1000;  /* sentinel: stop loop */
  if (!strcmp (v, "help") || !strcmp (v, "?"))
    { sftp_print_help (); return EXECUTION_SUCCESS; }
  if (!strcmp (v, "pwd")) return sftp_pwd (s);
  if (!strcmp (v, "cd"))
    return sftp_cd (s, argc >= 2 ? argv[1] : NULL);
  if (!strcmp (v, "lpwd"))
    {
      char buf[4096];
      if (getcwd (buf, sizeof buf)) printf ("Local working directory: %s\n", buf);
      return EXECUTION_SUCCESS;
    }
  if (!strcmp (v, "lcd"))
    {
      if (argc < 2) { builtin_error ("lcd: missing path"); return EX_USAGE; }
      if (chdir (argv[1]) < 0)
        { builtin_error ("lcd %s: %s", argv[1], strerror (errno));
          return EXECUTION_FAILURE; }
      return EXECUTION_SUCCESS;
    }
  if (!strcmp (v, "ls"))
    return sftp_ls (s, argc >= 2 ? argv[1] : NULL);
  if (!strcmp (v, "lls"))
    {
      char *ls_argv[] = {
        (char *) "ls",
        (char *) "-la",
        (char *) (argc >= 2 ? argv[1] : "."),
        NULL
      };
      int rc = run_local_helper (ls_argv, NULL, NULL, NULL, 1);
      return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  if (!strcmp (v, "get"))
    return sftp_get (s, argc >= 2 ? argv[1] : NULL,
                       argc >= 3 ? argv[2] : NULL);
  if (!strcmp (v, "put"))
    return sftp_put (s, argc >= 2 ? argv[1] : NULL,
                       argc >= 3 ? argv[2] : NULL);
  if (!strcmp (v, "mkdir"))
    return sftp_mkdir (s, argc >= 2 ? argv[1] : NULL);
  if (!strcmp (v, "rmdir"))
    return sftp_rmdir (s, argc >= 2 ? argv[1] : NULL);
  if (!strcmp (v, "rm"))
    return sftp_rm (s, argc >= 2 ? argv[1] : NULL);
  if (!strcmp (v, "rename"))
    return sftp_rename (s, argc >= 2 ? argv[1] : NULL,
                          argc >= 3 ? argv[2] : NULL);
  if (!strcmp (v, "chmod"))
    return sftp_chmod (s, argc >= 2 ? argv[1] : NULL,
                         argc >= 3 ? argv[2] : NULL);
  builtin_error ("unknown command: %s (try `help`)", v);
  return EX_USAGE;
}

/* ---------- argv parsing for `sftp HOST [-p ...]` ---------- */

static const char *nw (WORD_LIST **p)
{
  if (!p || !*p) return NULL;
  const char *w = (*p)->word->word;
  *p = (*p)->next;
  return w;
}

/* parse user@host into session fields; returns 0 on success. */
static int parse_userhost (const char *spec, sftp_session *s)
{
  const char *at = strchr (spec, '@');
  if (at)
    {
      size_t un = (size_t) (at - spec);
      if (un >= sizeof s->user) return -1;
      memcpy (s->user, spec, un);
      s->user[un] = '\0';
      spec = at + 1;
    }
  if (strlen (spec) >= sizeof s->host) return -1;
  snprintf (s->host, sizeof s->host, "%s", spec);
  return 0;
}

/* ---------- sftp interactive entry ---------- */

int
sftp_builtin (WORD_LIST *list)
{
  sftp_session s;
  memset (&s, 0, sizeof s);
  snprintf (s.port, sizeof s.port, "%s", "22");

  const char *host_arg = NULL, *batch = NULL, *w;
  const char *env_transport = getenv ("BASHSSH_TRANSPORT");
  if (env_transport
      && (!strcmp (env_transport, "openssh") || !strcmp (env_transport, "ssh")))
    s.openssh = 1;
  while ((w = nw (&list)))
    {
      if (!strcmp (w, "-p") || !strcmp (w, "-P"))
        { const char *p = nw (&list);
          if (!p) { builtin_error ("missing port after %s", w); return EX_USAGE; }
          snprintf (s.port, sizeof s.port, "%s", p); }
      else if (!strcmp (w, "-l"))
        { const char *u = nw (&list);
          if (!u) { builtin_error ("missing user after -l"); return EX_USAGE; }
          snprintf (s.user, sizeof s.user, "%s", u); }
      else if (!strcmp (w, "-i"))
        { const char *k = nw (&list);
          if (!k) { builtin_error ("missing key after -i"); return EX_USAGE; }
          snprintf (s.key, sizeof s.key, "%s", k); }
      else if (!strcmp (w, "-b"))
        { batch = nw (&list);
          if (!batch) { builtin_error ("missing batch file after -b"); return EX_USAGE; } }
      else if (!strcmp (w, "--openssh") || !strcmp (w, "--ssh")) s.openssh = 1;
      else if (!strcmp (w, "--native")) s.openssh = 0;
      else if (!strcmp (w, "--help") || !strcmp (w, "-h"))
        { sftp_print_help (); return EXECUTION_SUCCESS; }
      else if (w[0] == '-')
        { builtin_error ("unknown option: %s", w); return EX_USAGE; }
      else if (!host_arg) host_arg = w;
      else { builtin_error ("extra argument: %s", w); return EX_USAGE; }
    }
  if (!host_arg)
    { builtin_error ("usage: sftp [-p PORT] [-l USER] [-i KEY] [-b BATCH] [--openssh] HOST"); return EX_USAGE; }
  if (parse_userhost (host_arg, &s) < 0)
    { builtin_error ("bad host spec: %s", host_arg); return EX_USAGE; }

  FILE *in = stdin;
  int batch_owned = 0;
  if (batch)
    {
      in = fopen (batch, "r");
      if (!in) { builtin_error ("%s: %s", batch, strerror (errno)); return EXECUTION_FAILURE; }
      batch_owned = 1;
    }

  /* Establish remote cwd. */
  if (sftp_pwd (&s) != EXECUTION_SUCCESS) {
    if (batch_owned) fclose (in);
    return EXECUTION_FAILURE;
  }

  int interactive = (in == stdin) && isatty (fileno (in));
  int last_rc = EXECUTION_SUCCESS;
  char line[8192];
  for (;;)
    {
      if (interactive) { fputs ("sftp> ", stdout); fflush (stdout); }
      if (!fgets (line, sizeof line, in)) break;
      /* strip trailing newline / leading whitespace */
      size_t L = strlen (line);
      while (L && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = '\0';
      const char *p = line;
      while (*p && isspace ((unsigned char) *p)) p++;
      if (!*p || *p == '#') continue;
      char **argv;
      int argc;
      if (split_line (p, &argv, &argc) < 0) { last_rc = EXECUTION_FAILURE; break; }
      int rc = sftp_dispatch (&s, argc, argv);
      free_argv (argv, argc);
      if (rc == 1000) { last_rc = EXECUTION_SUCCESS; break; }
      last_rc = rc;
    }
  if (batch_owned) fclose (in);
  return last_rc;
}

char *sftp_doc[] = {
  "Interactive sftp(1) client over the sshd command-stream transport.",
  "",
  "    sftp [-p PORT] [-l USER] [-i KEY] [-b BATCH] [--openssh] HOST",
  "",
  "Supported verbs in the interactive prompt:",
  "    pwd, cd, lpwd, lcd, ls, lls, get, put, mkdir, rmdir, rm,",
  "    rename, chmod, help, ?, bye, quit, exit.",
  "",
  "Each verb is rewritten into a one-shot `bash -c` command issued",
  "against the remote sshd. Bytes flow through the command's",
  "stdin/stdout. Remote cwd is tracked client-side and prefixed to",
  "every verb as `cd CWD && ...`.",
  (char *) NULL
};

struct builtin sftp_struct = {
  "sftp",
  sftp_builtin,
  BUILTIN_ENABLED,
  sftp_doc,
  "sftp [-p PORT] [-l USER] [-i KEY] [-b BATCH] [--openssh] HOST",
  0
};

/* ---------- scp dispatch (called from scp.c) ---------- */

/* Parse a "[user@]host:path" or local path. *host_out = NULL when local. */
static int split_remote (const char *spec, char **host_out, char **path_out)
{
  *host_out = NULL; *path_out = NULL;
  const char *colon = strchr (spec, ':');
  if (!colon || colon == spec || strchr (spec, '/') < colon)
    {
      /* No colon, or colon is preceded by /, treat as local. */
      if (colon && strchr (spec, '/') && strchr (spec, '/') < colon)
        { *path_out = strdup (spec); return *path_out ? 0 : -1; }
      if (!colon) { *path_out = strdup (spec); return *path_out ? 0 : -1; }
    }
  size_t hn = (size_t) (colon - spec);
  *host_out = malloc (hn + 1);
  if (!*host_out) return -1;
  memcpy (*host_out, spec, hn);
  (*host_out)[hn] = '\0';
  *path_out = strdup (colon + 1);
  if (!*path_out) { free (*host_out); *host_out = NULL; return -1; }
  return 0;
}

int
bashsftp_scp_dispatch (WORD_LIST *list)
{
  sftp_session s;
  memset (&s, 0, sizeof s);
  snprintf (s.port, sizeof s.port, "%s", "22");
  const char *env_transport = getenv ("BASHSSH_TRANSPORT");
  if (env_transport
      && (!strcmp (env_transport, "openssh") || !strcmp (env_transport, "ssh")))
    s.openssh = 1;

  int recursive = 0;
  const char *src = NULL, *dst = NULL, *w;
  while ((w = nw (&list)))
    {
      if (!strcmp (w, "-r")) recursive = 1;
      else if (!strcmp (w, "-P") || !strcmp (w, "-p"))
        { const char *p = nw (&list);
          if (!p) { builtin_error ("missing port"); return EX_USAGE; }
          snprintf (s.port, sizeof s.port, "%s", p); }
      else if (!strcmp (w, "-i"))
        { const char *k = nw (&list);
          if (!k) { builtin_error ("missing key"); return EX_USAGE; }
          snprintf (s.key, sizeof s.key, "%s", k); }
      else if (!strcmp (w, "-l"))
        { const char *u = nw (&list);
          if (!u) { builtin_error ("missing user"); return EX_USAGE; }
          snprintf (s.user, sizeof s.user, "%s", u); }
      else if (!strcmp (w, "--openssh") || !strcmp (w, "--ssh")) s.openssh = 1;
      else if (!strcmp (w, "--native")) s.openssh = 0;
      else if (w[0] == '-' && w[1])
        { builtin_error ("unknown option: %s", w); return EX_USAGE; }
      else if (!src) src = w;
      else if (!dst) dst = w;
      else { builtin_error ("extra argument: %s", w); return EX_USAGE; }
    }
  if (!src || !dst)
    { builtin_error ("usage: scp [-r] [-P PORT] [-i KEY] SRC DST"); return EX_USAGE; }

  char *src_host = NULL, *src_path = NULL;
  char *dst_host = NULL, *dst_path = NULL;
  if (split_remote (src, &src_host, &src_path) < 0
      || split_remote (dst, &dst_host, &dst_path) < 0)
    { free (src_host); free (src_path); free (dst_host); free (dst_path);
      builtin_error ("scp: out of memory"); return EXECUTION_FAILURE; }

  int rc;
  if (!src_host && dst_host)            /* local → remote: put */
    {
      if (parse_userhost (dst_host, &s) < 0)
        { rc = EXECUTION_FAILURE; goto out; }
      if (recursive)
        {
          /* tar-pipe recursive upload. Keep local helper execution argv-based:
           * no shell, no command string, no popen expansion. */
          blob in = {0}, out = {0}, err = {0};
          char src_dirbuf[1024], src_basebuf[1024];
          snprintf (src_dirbuf, sizeof src_dirbuf, "%s", src_path);
          snprintf (src_basebuf, sizeof src_basebuf, "%s", src_path);
          char *src_dir = dirname (src_dirbuf);
          char *src_base = basename (src_basebuf);
          char *tar_argv[] = {
            (char *) "tar", (char *) "-cf", (char *) "-",
            (char *) "-C", src_dir, src_base, NULL
          };
          int trc = run_local_helper (tar_argv, NULL, &in, &err, 1);
          if (err.n) fwrite (err.p, 1, err.n, stderr);
          blob_free (&err);
          if (trc != 0) { blob_free (&in); rc = EXECUTION_FAILURE; goto out; }
          blob qd = {0}; shquote (dst_path, &qd);
          char verb[2048];
          snprintf (verb, sizeof verb, "mkdir -p %s && tar -xf - -C %s", qd.p, qd.p);
          blob_free (&qd);
          int rrc = run_remote (&s, verb, &in, &out, &err);
          if (err.n) fwrite (err.p, 1, err.n, stderr);
          blob_free (&in); blob_free (&out); blob_free (&err);
          rc = rrc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
        }
      else
        rc = sftp_put (&s, src_path, dst_path);
    }
  else if (src_host && !dst_host)       /* remote → local: get */
    {
      if (parse_userhost (src_host, &s) < 0)
        { rc = EXECUTION_FAILURE; goto out; }
      if (recursive)
        {
          blob out = {0}, err = {0};
          char src_dirbuf[1024], src_basebuf[1024];
          snprintf (src_dirbuf, sizeof src_dirbuf, "%s", src_path);
          snprintf (src_basebuf, sizeof src_basebuf, "%s", src_path);
          blob qdir = {0}, qbase = {0};
          shquote (dirname (src_dirbuf), &qdir);
          shquote (basename (src_basebuf), &qbase);
          char verb[2048];
          snprintf (verb, sizeof verb,
                    "tar -cf - -C %s %s 2>/dev/null", qdir.p, qbase.p);
          blob_free (&qdir); blob_free (&qbase);
          int rrc = run_remote (&s, verb, NULL, &out, &err);
          if (rrc != 0) { if (err.n) fwrite (err.p, 1, err.n, stderr);
                          blob_free (&out); blob_free (&err);
                          rc = EXECUTION_FAILURE; goto out; }
          blob tar_err = {0};
          char *tar_argv[] = {
            (char *) "tar", (char *) "-xf", (char *) "-",
            (char *) "-C", dst_path, NULL
          };
          int prc = run_local_helper (tar_argv, &out, NULL, &tar_err, 1);
          if (tar_err.n) fwrite (tar_err.p, 1, tar_err.n, stderr);
          blob_free (&tar_err);
          blob_free (&out); blob_free (&err);
          rc = prc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
        }
      else
        rc = sftp_get (&s, src_path, dst_path);
    }
  else if (!src_host && !dst_host)
    { builtin_error ("scp: neither path is remote (use cp(1))");
      rc = EX_USAGE; }
  else
    { builtin_error ("scp: remote-to-remote copy not supported in v1");
      rc = EX_USAGE; }

out:
  free (src_host); free (src_path); free (dst_host); free (dst_path);
  return rc;
}
