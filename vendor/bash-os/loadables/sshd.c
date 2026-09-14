/* SPDX-License-Identifier: MIT */
/* sshd.c - Phase 3 Stage 20 native command-stream server.
 *
 * This accepts the framed ssh protocol implemented by ssh.c and
 * executes remote commands, shells, forwarding, and SFTP requests. It is
 * deliberately loopback-oriented by default: wrappers bind 127.0.0.1 unless
 * the operator supplies an explicit listen address. OpenSSH-compatible
 * encrypted transport is provided by the vendored libssh server path.
 */
#include <config.h>
#if defined (HAVE_UNISTD_H)
# include <unistd.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <fnmatch.h>
#include <glob.h>
#include <time.h>
#include <arpa/inet.h>

#include "loadables.h"
#include "bashcred_privdrop.h"

#if defined (__has_include)
# if __has_include ("_libssh_libssh.h")
#  include "_libssh_libssh.h"
#  include "_libssh_server.h"
#  include "_libssh_callbacks.h"
#  if __has_include ("_libssh_sftp.h") && __has_include ("_libssh_sftpserver.h")
#   include "_libssh_sftp.h"
#   include "_libssh_sftpserver.h"
#   define BSSHD_HAVE_LIBSSH_SFTP_SERVER 1
#  endif
#  define BSSHD_HAVE_LIBSSH_SERVER 1
# elif __has_include ("_libssh/libssh.h")
#  include "_libssh/libssh.h"
#  include "_libssh/server.h"
#  include "_libssh/callbacks.h"
#  if __has_include ("_libssh/sftp.h") && __has_include ("_libssh/sftpserver.h")
#   include "_libssh/sftp.h"
#   include "_libssh/sftpserver.h"
#   define BSSHD_HAVE_LIBSSH_SFTP_SERVER 1
#  endif
#  define BSSHD_HAVE_LIBSSH_SERVER 1
# endif
#endif
#ifndef BSSHD_HAVE_LIBSSH_SERVER
# define BSSHD_HAVE_LIBSSH_SERVER 0
#endif
#ifndef BSSHD_HAVE_LIBSSH_SFTP_SERVER
# define BSSHD_HAVE_LIBSSH_SFTP_SERVER 0
#endif

#if BSSHD_HAVE_LIBSSH_SERVER
static int bsshd_libssh_initialized;
static int
bsshd_libssh_ensure_initialized (void)
{
  if (bsshd_libssh_initialized)
    return 0;
  if (ssh_init () != SSH_OK)
    return -1;
  bsshd_libssh_initialized = 1;
  return 0;
}
static int bsshd_channel_write_all (ssh_channel ch, const void *data,
                                    size_t n, int stderr_stream);
#endif

#if BSSHD_HAVE_LIBSSH_SFTP_SERVER
/* The vendored libssh server object exports this even when the local
 * compatibility header hides it behind libssh's WITH_SERVER guard. */
extern void sftp_server_free (sftp_session sftp);
#endif

typedef struct {
  char *p;
  size_t n, cap;
} blob;

typedef struct {
  int enabled;
  bc_user_info user;
  gid_t groups[BC_PD_GROUPS_MAX + 1];
  int ngroups;
} bsshd_target_user;

typedef struct {
  char forced_command[1024];
  int no_pty;
  int no_agent_forwarding;
  int no_port_forwarding;
} bsshd_authz_options;

static void
bsshd_authz_options_clear (bsshd_authz_options *opts)
{
  if (opts)
    memset (opts, 0, sizeof *opts);
}

static int
bsshd_apply_target_current_process (const bsshd_target_user *target,
                                    char *errbuf, size_t errsz)
{
  if (!target || !target->enabled)
    return 0;

  if (setenv ("USER", target->user.name, 1) < 0 ||
      setenv ("LOGNAME", target->user.name, 1) < 0 ||
      setenv ("HOME", target->user.home[0] ? target->user.home : "/", 1) < 0 ||
      setenv ("SHELL", target->user.shell[0] ? target->user.shell : "/bin/bash", 1) < 0)
    {
      snprintf (errbuf, errsz, "target env: %s", strerror (errno));
      return -1;
    }

  if (target->user.home[0] && chdir (target->user.home) < 0)
    {
      snprintf (errbuf, errsz, "chdir %s: %s",
                target->user.home, strerror (errno));
      return -1;
    }

  if (geteuid () == 0)
    {
      char drop_err[BC_PD_ERR_MAX];
      if (bc_privdrop_to_user (target->user.uid, target->user.gid,
                               target->groups, target->ngroups,
                               drop_err, sizeof drop_err) < 0)
        {
          snprintf (errbuf, errsz, "privdrop %s: %s",
                    target->user.name, drop_err);
          return -1;
        }
    }
  else if (geteuid () != target->user.uid || getegid () != target->user.gid)
    {
      snprintf (errbuf, errsz, "cannot switch to %s without root",
                target->user.name);
      return -1;
    }

  return 0;
}

#define BSSHD_AUTH_PUBLICKEY 0x01
#define BSSHD_AUTH_PASSWORD  0x02

#define BSSHD_AUTH_DEV "/dev/bashos-auth"
#define BSSHD_AUTH_IOC_MAGIC 0xBA
#define BSSHD_AUTH_MAX_SECRET 4096
#define BSSHD_AUTH_TOKEN_BYTES 32
#define BSSHD_AUTH_USER_BYTES 64

struct bsshd_auth_handle {
  unsigned int id;
  unsigned int flags;
};

struct bsshd_auth_secret_write {
  unsigned int id;
  unsigned int len;
  unsigned long long user_ptr;
};

#define BSSHD_AUTH_IOC_NEW_SECRET \
  _IOWR(BSSHD_AUTH_IOC_MAGIC, 0x02, struct bsshd_auth_handle)
#define BSSHD_AUTH_IOC_WRITE_SECRET \
  _IOW(BSSHD_AUTH_IOC_MAGIC, 0x03, struct bsshd_auth_secret_write)
#define BSSHD_AUTH_IOC_SEAL_SECRET \
  _IOW(BSSHD_AUTH_IOC_MAGIC, 0x04, struct bsshd_auth_handle)
#define BSSHD_AUTH_IOC_CLEAR_SECRET \
  _IOW(BSSHD_AUTH_IOC_MAGIC, 0x05, struct bsshd_auth_handle)

static volatile sig_atomic_t stop_server;
static volatile sig_atomic_t reload_server;

/* Per-IP failed-handshake accounting for the `run` accept loop
 * (sshd-per-ip-auth-ratelimit, v4.3 SSH server hardening).
 *
 * Each entry tracks one peer IP's failed-handshake count over a
 * sliding window. When the count reaches --auth-fail-max within
 * --auth-fail-window-sec, the peer enters a cooldown of
 * --auth-fail-cooldown-sec during which new connections from that
 * IP are accepted+closed without entering handle_client. A
 * successful handshake clears the counter (the reset/allow path).
 * The table is bounded; when full, the least-recently-active entry
 * is evicted FIFO-style.
 *
 * Defaults: --auth-fail-max=0 means disabled (back-compat — existing
 * `sshd run` invocations are unaffected unless they opt in).
 * Capture is loopback-by-default (per the file docstring) so "per-IP"
 * is mostly per-source-IP for whichever loopback / LAN clients reach
 * the listener. */
#define BSSHD_FAIL_TBL_MAX 16
static struct {
  char ip[48];          /* INET6_ADDRSTRLEN=46 + slack */
  int fails;
  time_t window_start;  /* timestamp of first fail in the current window */
  time_t last_fail;     /* timestamp of most recent fail (for cooldown) */
  int blocked_logged;   /* one-shot diag flag to avoid spam */
} bsshd_fail_tbl[BSSHD_FAIL_TBL_MAX];
static size_t bsshd_fail_n;

static int bsshd_peer_to_str (const struct sockaddr_storage *sa,
                              char *out, size_t outsz)
{
  if (sa->ss_family == AF_INET) {
    const struct sockaddr_in *a = (const struct sockaddr_in *) sa;
    return inet_ntop (AF_INET, &a->sin_addr, out, outsz) ? 0 : -1;
  }
  if (sa->ss_family == AF_INET6) {
    const struct sockaddr_in6 *a = (const struct sockaddr_in6 *) sa;
    return inet_ntop (AF_INET6, &a->sin6_addr, out, outsz) ? 0 : -1;
  }
  return -1;
}

static int bsshd_peer_slot (const char *ip)
{
  for (size_t i = 0; i < bsshd_fail_n; i++)
    if (strcmp (bsshd_fail_tbl[i].ip, ip) == 0)
      return (int) i;
  if (bsshd_fail_n < BSSHD_FAIL_TBL_MAX) {
    int s = (int) bsshd_fail_n++;
    memset (&bsshd_fail_tbl[s], 0, sizeof bsshd_fail_tbl[s]);
    strncpy (bsshd_fail_tbl[s].ip, ip, sizeof bsshd_fail_tbl[s].ip - 1);
    return s;
  }
  /* Evict the entry with the oldest last_fail (FIFO-by-activity). */
  int oldest = 0;
  for (size_t i = 1; i < bsshd_fail_n; i++)
    if (bsshd_fail_tbl[i].last_fail < bsshd_fail_tbl[oldest].last_fail)
      oldest = (int) i;
  memset (&bsshd_fail_tbl[oldest], 0, sizeof bsshd_fail_tbl[oldest]);
  strncpy (bsshd_fail_tbl[oldest].ip, ip, sizeof bsshd_fail_tbl[oldest].ip - 1);
  return oldest;
}

static int bsshd_peer_blocked (int slot, long fail_max, long window_s,
                               long cooldown_s, time_t now)
{
  if (fail_max <= 0) return 0;  /* disabled */
  if (bsshd_fail_tbl[slot].fails < fail_max) return 0;
  /* Cooldown elapsed since last fail — reset/allow path. */
  if (cooldown_s > 0 && now - bsshd_fail_tbl[slot].last_fail >= cooldown_s) {
    bsshd_fail_tbl[slot].fails = 0;
    bsshd_fail_tbl[slot].window_start = 0;
    bsshd_fail_tbl[slot].last_fail = 0;
    bsshd_fail_tbl[slot].blocked_logged = 0;
    return 0;
  }
  /* Stale window without enough new fails — also reset. */
  if (window_s > 0 && now - bsshd_fail_tbl[slot].window_start > window_s
      && bsshd_fail_tbl[slot].fails < fail_max) {
    bsshd_fail_tbl[slot].fails = 0;
    bsshd_fail_tbl[slot].window_start = 0;
    bsshd_fail_tbl[slot].blocked_logged = 0;
    return 0;
  }
  (void) window_s;
  return 1;
}

static void bsshd_peer_record_fail (int slot, long window_s, time_t now)
{
  /* Roll the window forward if the previous window has elapsed. */
  if (window_s > 0
      && bsshd_fail_tbl[slot].fails > 0
      && now - bsshd_fail_tbl[slot].window_start > window_s) {
    bsshd_fail_tbl[slot].fails = 0;
    bsshd_fail_tbl[slot].window_start = 0;
  }
  if (bsshd_fail_tbl[slot].fails == 0)
    bsshd_fail_tbl[slot].window_start = now;
  bsshd_fail_tbl[slot].fails++;
  bsshd_fail_tbl[slot].last_fail = now;
}

static void bsshd_peer_clear (int slot)
{
  bsshd_fail_tbl[slot].fails = 0;
  bsshd_fail_tbl[slot].window_start = 0;
  bsshd_fail_tbl[slot].last_fail = 0;
  bsshd_fail_tbl[slot].blocked_logged = 0;
}

struct bsshd_child_guard {
  struct sigaction old_action;
  sigset_t old_mask;
};

static void bsshd_child_guard_begin (struct bsshd_child_guard *g)
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

static void bsshd_child_guard_parent_end (struct bsshd_child_guard *g)
{
  sigprocmask (SIG_SETMASK, &g->old_mask, NULL);
  sigaction (SIGCHLD, &g->old_action, NULL);
}

static void bsshd_child_guard_child_end (struct bsshd_child_guard *g)
{
  sigprocmask (SIG_SETMASK, &g->old_mask, NULL);
}

static const char *nw (WORD_LIST **p)
{
  if (!p || !*p) return NULL;
  const char *w = (*p)->word->word;
  *p = (*p)->next;
  return w;
}

static void on_term (int sig)
{
  (void) sig;
  stop_server = 1;
}

static void on_hup (int sig)
{
  (void) sig;
  reload_server = 1;
}

static void install_term_handlers (void)
{
  struct sigaction sa;
  memset (&sa, 0, sizeof sa);
  sa.sa_handler = on_term;
  sigemptyset (&sa.sa_mask);
  sigaction (SIGTERM, &sa, NULL);
  sigaction (SIGINT, &sa, NULL);
  memset (&sa, 0, sizeof sa);
  sa.sa_handler = on_hup;
  sigemptyset (&sa.sa_mask);
  sigaction (SIGHUP, &sa, NULL);
}

static void bsshd_install_default_term_handlers (void)
{
  struct sigaction sa;
  memset (&sa, 0, sizeof sa);
  sa.sa_handler = SIG_DFL;
  sigemptyset (&sa.sa_mask);
  sigaction (SIGTERM, &sa, NULL);
  sigaction (SIGINT, &sa, NULL);
  sigaction (SIGHUP, &sa, NULL);
}

static const char *bsshd_runtime_dir (void)
{
  const char *env = getenv ("BASHSSHD_RUN_DIR");
  static char fallback[64];
  if (env && *env)
    return env;
  snprintf (fallback, sizeof fallback, "/tmp/sshd-%ld", (long) getuid ());
  return fallback;
}

static int bsshd_mkdir_if_needed (const char *path, mode_t mode)
{
  if (mkdir (path, mode) == 0 || errno == EEXIST)
    return 0;
  return -1;
}

static int bsshd_ensure_runtime_dir (void)
{
  const char *dir = bsshd_runtime_dir ();
  char sessions[512];
  if (bsshd_mkdir_if_needed (dir, 0700) < 0)
    return -1;
  snprintf (sessions, sizeof sessions, "%s/sessions", dir);
  if (bsshd_mkdir_if_needed (sessions, 0700) < 0)
    return -1;
  return 0;
}

static void bsshd_pidfile_path (char *path, size_t psz)
{
  snprintf (path, psz, "%s/pid", bsshd_runtime_dir ());
}

static void bsshd_write_pidfile (void)
{
  if (bsshd_ensure_runtime_dir () < 0)
    return;
  char path[512], tmp[512];
  bsshd_pidfile_path (path, sizeof path);
  snprintf (tmp, sizeof tmp, "%s.tmp", path);
  FILE *f = fopen (tmp, "w");
  if (!f)
    return;
  fprintf (f, "%ld\n", (long) getpid ());
  if (fclose (f) == 0)
    rename (tmp, path);
  else
    unlink (tmp);
}

static void bsshd_unlink_pidfile (void)
{
  char path[512];
  bsshd_pidfile_path (path, sizeof path);
  unlink (path);
}

static void bsshd_reap_children (void)
{
  int st;
  while (waitpid (-1, &st, WNOHANG) > 0)
    ;
}

static void bsshd_session_path (const char *id, char *path, size_t psz)
{
  snprintf (path, psz, "%s/sessions/%s", bsshd_runtime_dir (), id);
}

static void bsshd_session_record (char *id, size_t idsz,
                                  const char *kind, const char *peer)
{
  if (idsz)
    snprintf (id, idsz, "%ld-%ld", (long) getpid (), (long) time (NULL));
  if (bsshd_ensure_runtime_dir () < 0 || !idsz)
    return;
  char path[512], tmp[512];
  bsshd_session_path (id, path, sizeof path);
  snprintf (tmp, sizeof tmp, "%s.tmp", path);
  FILE *f = fopen (tmp, "w");
  if (!f)
    return;
  fprintf (f, "id=%s\npid=%ld\nkind=%s\npeer=%s\nstarted=%ld\n",
           id, (long) getpid (), kind ? kind : "unknown",
           peer ? peer : "unknown", (long) time (NULL));
  if (fclose (f) == 0)
    rename (tmp, path);
  else
    unlink (tmp);
}

static void bsshd_session_remove (const char *id)
{
  if (!id || !*id)
    return;
  char path[512];
  bsshd_session_path (id, path, sizeof path);
  unlink (path);
}

static int blob_append (blob *b, const void *p, size_t n)
{
  if (!n) return 0;
  if (b->n + n + 1 > b->cap)
    {
      size_t nc = b->cap ? b->cap * 2 : 4096;
      while (nc < b->n + n + 1) nc *= 2;
      char *q = realloc (b->p, nc);
      if (!q) return -1;
      b->p = q; b->cap = nc;
    }
  memcpy (b->p + b->n, p, n);
  b->n += n;
  b->p[b->n] = '\0';
  return 0;
}

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

static int write_blob_temp (const blob *b, char *path, size_t psz)
{
  snprintf (path, psz, "/tmp/sshd-in-XXXXXX");
  int fd = mkstemp (path);
  if (fd < 0) return -1;
  int rc = write_all (fd, b->p ? b->p : "", b->n);
  if (close (fd) < 0) rc = -1;
  return rc;
}

/* --- F06 item 3 slice 1: AcceptEnv allow-list + accepted session env -------
   The client may request environment variables (SSH_CHANNEL_REQUEST_ENV). We
   honor only names matching the AcceptEnv allow-list (sshd_config, one pattern
   per line; fnmatch globs like `LC_*`), fail-closed on everything else (a
   rejected request is replied-default, never silently swallowed). Accepted
   vars are stashed here and applied to the command child in run_local. State is
   file-scope (the encrypted connection handler + run_local share one process,
   reset per channel). */
#define BSSHD_MAX_ACCEPTENV 32
#define BSSHD_MAX_SESSENV   32
static char g_acceptenv[BSSHD_MAX_ACCEPTENV][64];
static int  g_n_acceptenv = 0;
static char *g_sessenv_name[BSSHD_MAX_SESSENV];
static char *g_sessenv_val[BSSHD_MAX_SESSENV];
static int  g_n_sessenv = 0;

/* F06 item 5: cipher/kex/rekey allow-list policy from sshd_config. Empty string
   = unset (use libssh defaults). Applied at bind setup (ciphers/macs/kex) and
   per accepted session (rekey). Unknown/disallowed names → fail-closed (the run
   refuses to start). */
static char g_ssh_ciphers[256];
static char g_ssh_macs[256];
static char g_ssh_kex[256];
static uint64_t g_ssh_rekey_data = 0;   /* bytes; 0 = unset */

/* F06 item 2: multiple HostKey directives (rotation / algorithm choice).
   libssh keeps one host key per algorithm; each is applied at bind. */
#define BSSHD_MAX_HOSTKEYS 8
static char g_hostkeys[BSSHD_MAX_HOSTKEYS][256];
static int  g_n_hostkeys = 0;

/* F06 item 6a: sshd_config security directives. Defaults match the existing
   (un-gated) behaviour so configs without these lines are unaffected. */
static int  g_permit_root = 1;     /* 0=no, 1=yes (default), 2=prohibit-password */
static long g_max_auth_tries = 0;  /* 0 = unlimited; >0 = per-connection cap */
static long g_login_grace_s = 0;   /* 0 = no pre-auth deadline; >0 = seconds */
static int  g_permit_tty = 1;      /* 0 = refuse PTY requests globally */
static char g_banner_path[512];    /* empty = no pre-auth banner */

/* F06 server-side Match: per-connection conditional overrides.
   `Match user PAT | address CIDR | all` gates the directives that follow.
   Overrides use -1 = inherit the global baseline. Applied in the per-connection
   forked child (mutating the globals there is connection-local). v1 overrides
   PermitRootLogin/PermitTTY/AllowTcpForwarding/AllowAgentForwarding; auth-method
   directives in a Match block are not supported (they precede the user check). */
#define BSSHD_MAX_MATCH 16
struct bsshd_match_block {
  int  crit_all;
  char crit_user[64];   /* fnmatch pattern; "" = no user criterion */
  char crit_addr[64];   /* IP or v4 CIDR; "" = no address criterion */
  int  ov_permit_root;  /* -1 inherit; else 0/1/2 */
  int  ov_permit_tty;   /* -1 inherit; else 0/1 */
  int  ov_allow_fwd;    /* -1 inherit; else 0/1 */
  int  ov_allow_agent;  /* -1 inherit; else 0/1 */
};
static struct bsshd_match_block g_match[BSSHD_MAX_MATCH];
static int g_n_match = 0;

/* True if `ip` is inside `cidr` (exact match, or a.b.c.d/N IPv4 prefix; IPv6
   exact-match only). */
static int
bsshd_addr_in_cidr (const char *ip, const char *cidr)
{
  if (!ip || !cidr) return 0;
  const char *slash = strchr (cidr, '/');
  if (!slash) return strcmp (ip, cidr) == 0;          /* bare addr → exact */
  char net[64]; size_t nl = (size_t) (slash - cidr);
  if (nl >= sizeof net) return 0;
  memcpy (net, cidr, nl); net[nl] = '\0';
  int bits = atoi (slash + 1);
  struct in_addr a, n;
  if (inet_pton (AF_INET, ip, &a) == 1 && inet_pton (AF_INET, net, &n) == 1)
    {
      if (bits < 0 || bits > 32) return 0;
      uint32_t mask = bits ? htonl (0xffffffffu << (32 - bits)) : 0;
      return (a.s_addr & mask) == (n.s_addr & mask);
    }
  return 0;   /* non-v4 CIDR unsupported → no match */
}

/* Apply matching Match blocks' overrides to the per-connection effective config. */
static void
bsshd_match_apply (const char *peer_ip, const char *user,
                   int *permit_root, int *permit_tty, int *allow_fwd, int *allow_agent)
{
  for (int i = 0; i < g_n_match; i++)
    {
      struct bsshd_match_block *mb = &g_match[i];
      int matched;
      if (mb->crit_all)
        matched = 1;
      else
        {
          matched = 1;
          if (mb->crit_user[0])
            { if (!user || !user[0] || fnmatch (mb->crit_user, user, 0) != 0) matched = 0; }
          if (matched && mb->crit_addr[0])
            { if (!peer_ip || !peer_ip[0] || !bsshd_addr_in_cidr (peer_ip, mb->crit_addr)) matched = 0; }
          if (!mb->crit_user[0] && !mb->crit_addr[0]) matched = 0;
        }
      if (!matched) continue;
      if (mb->ov_permit_root >= 0) *permit_root = mb->ov_permit_root;
      if (mb->ov_permit_tty  >= 0) *permit_tty  = mb->ov_permit_tty;
      if (mb->ov_allow_fwd   >= 0) *allow_fwd   = mb->ov_allow_fwd;
      if (mb->ov_allow_agent >= 0) *allow_agent = mb->ov_allow_agent;
    }
}

/* A portable, safe env NAME: [A-Za-z_][A-Za-z0-9_]* (no '=', no shell meta). */
static int bsshd_env_name_valid (const char *n)
{
  if (!n || !*n || !(isalpha ((unsigned char) *n) || *n == '_')) return 0;
  for (const char *c = n; *c; c++)
    if (!(isalnum ((unsigned char) *c) || *c == '_')) return 0;
  return 1;
}

static int bsshd_acceptenv_allows (const char *name)
{
  /* OpenSSH default AcceptEnv is empty; we ship a safe locale/term default so
     interactive sessions get sane defaults out of the box. Operators tighten or
     widen via AcceptEnv lines. */
  static const char *defaults[] = { "LANG", "LANGUAGE", "LC_*", "TERM", NULL };
  if (!bsshd_env_name_valid (name)) return 0;
  if (g_n_acceptenv == 0)
    {
      for (int i = 0; defaults[i]; i++)
        if (fnmatch (defaults[i], name, 0) == 0) return 1;
      return 0;
    }
  for (int i = 0; i < g_n_acceptenv; i++)
    if (fnmatch (g_acceptenv[i], name, 0) == 0) return 1;
  return 0;
}

static void bsshd_sessenv_reset (void)
{
  for (int i = 0; i < g_n_sessenv; i++) { free (g_sessenv_name[i]); free (g_sessenv_val[i]); }
  g_n_sessenv = 0;
}

static void bsshd_sessenv_add (const char *n, const char *v)
{
  if (g_n_sessenv >= BSSHD_MAX_SESSENV || !n) return;
  char *dn = strdup (n), *dv = strdup (v ? v : "");
  if (!dn || !dv) { free (dn); free (dv); return; }
  g_sessenv_name[g_n_sessenv] = dn;
  g_sessenv_val[g_n_sessenv] = dv;
  g_n_sessenv++;
}

/* Build the command child's environment as an explicit envp and exec it.
   NB: in this static-musl bash a forked child's setenv() does NOT reach a
   subsequent execl()/execve(environ) — the libssh exec child's USER/LOGNAME and
   the AcceptEnv session vars were silently dropped. So we construct envp by hand
   from the inherited environ (minus any name we override) plus the target login
   vars (when enabled) plus the accepted session vars, and execve with it. On
   success this never returns; on failure it returns and the caller _exit()s. */
extern char **environ;

static void bsshd_exec_child (const char *shell, const char *cmd,
                              const bsshd_target_user *target,
                              const char *xtra_n, const char *xtra_v)
{
  /* names we set explicitly (skip the inherited copies to avoid duplicates) */
  const char *over[5 + BSSHD_MAX_SESSENV];
  int n_over = 0;
  int login = (target && target->enabled);
  if (login) { over[n_over++] = "USER"; over[n_over++] = "LOGNAME";
               over[n_over++] = "HOME"; over[n_over++] = "SHELL"; }
  if (xtra_n) over[n_over++] = xtra_n;
  for (int i = 0; i < g_n_sessenv; i++) over[n_over++] = g_sessenv_name[i];

  int base = 0; for (char **e = environ; e && *e; e++) base++;
  char **envp = calloc ((size_t) base + (size_t) n_over + 1, sizeof *envp);
  if (!envp) return;
  int n = 0;
  for (char **e = environ; e && *e; e++)
    {
      int skip = 0;
      for (int i = 0; i < n_over; i++)
        { size_t kl = strlen (over[i]);
          if (!strncmp (*e, over[i], kl) && (*e)[kl] == '=') { skip = 1; break; } }
      if (!skip) envp[n++] = *e;
    }
  /* append helper: "NAME=VALUE" */
#define BSSHD_ENVP_PUT(nm,vl) do { \
    const char *_nm = (nm), *_vl = (vl) ? (vl) : ""; \
    char *_s = malloc (strlen (_nm) + strlen (_vl) + 2); \
    if (_s) { sprintf (_s, "%s=%s", _nm, _vl); envp[n++] = _s; } } while (0)
  if (login)
    {
      BSSHD_ENVP_PUT ("USER", target->user.name);
      BSSHD_ENVP_PUT ("LOGNAME", target->user.name);
      BSSHD_ENVP_PUT ("HOME", target->user.home[0] ? target->user.home : "/");
      BSSHD_ENVP_PUT ("SHELL", target->user.shell[0] ? target->user.shell : "/bin/bash");
    }
  if (xtra_n) BSSHD_ENVP_PUT (xtra_n, xtra_v);
  for (int i = 0; i < g_n_sessenv; i++)
    BSSHD_ENVP_PUT (g_sessenv_name[i], g_sessenv_val[i]);
#undef BSSHD_ENVP_PUT
  envp[n] = NULL;

  if (cmd)
    {
      char *av0[] = { (char *) shell, "-c", (char *) cmd, (char *) 0 };
      execve (shell, av0, envp);
      { char *av1[] = { (char *) "bash", "-c", (char *) cmd, (char *) 0 }; execve ("/bin/bash", av1, envp); }
      { char *av2[] = { (char *) "sh", "-c", (char *) cmd, (char *) 0 }; execve ("/bin/sh", av2, envp); }
    }
  else                                          /* cmd==NULL → interactive login shell */
    {
      char *av0[] = { (char *) shell, (char *) 0 };
      execve (shell, av0, envp);
      { char *av1[] = { (char *) "bash", (char *) 0 }; execve ("/bin/bash", av1, envp); }
      { char *av2[] = { (char *) "sh", (char *) 0 }; execve ("/bin/sh", av2, envp); }
    }
}

static int run_local (const char *cmd, const char *infile,
                      const bsshd_target_user *target, blob *out, blob *err)
{
  int op[2], ep[2];
  if (pipe (op) < 0 || pipe (ep) < 0) return 127;
  struct bsshd_child_guard guard;
  bsshd_child_guard_begin (&guard);
  pid_t pid = fork ();
  if (pid < 0) { bsshd_child_guard_parent_end (&guard); return 127; }
  if (pid == 0)
    {
      bsshd_child_guard_child_end (&guard);
      close (op[0]); close (ep[0]);
      if (infile)
        {
          int in = open (infile, O_RDONLY);
          if (in < 0) _exit (127);
          dup2 (in, STDIN_FILENO);
          close (in);
        }
      dup2 (op[1], STDOUT_FILENO);
      dup2 (ep[1], STDERR_FILENO);
      close (op[1]); close (ep[1]);
      const char *shell = "/bin/bash";
      if (target && target->enabled)
        {
          char drop_err[BC_PD_ERR_MAX];
          if (target->user.home[0] && chdir (target->user.home) < 0)
            {
              fprintf (stderr, "sshd: chdir %s: %s\n",
                       target->user.home, strerror (errno));
              _exit (127);
            }
          if (geteuid () == 0 &&
              bc_privdrop_to_user (target->user.uid, target->user.gid,
                                   target->groups, target->ngroups,
                                   drop_err, sizeof drop_err) < 0)
            {
              fprintf (stderr, "sshd: privdrop %s: %s\n",
                       target->user.name, drop_err);
              _exit (127);
            }
          if (geteuid () != target->user.uid || getegid () != target->user.gid)
            _exit (127);
          shell = target->user.shell[0] ? target->user.shell : "/bin/bash";
        }
      /* Explicit-envp exec: login vars (USER/LOGNAME/HOME/SHELL) + AcceptEnv
         session vars. setenv()+execl() does not propagate here (see
         bsshd_exec_child). */
      bsshd_exec_child (shell, cmd, target, NULL, NULL);
      _exit (127);
    }
  close (op[1]); close (ep[1]);
  char buf[4096];
  for (;;)
    {
      ssize_t r = read (op[0], buf, sizeof buf);
      if (r < 0 && errno == EINTR) continue;
      if (r <= 0) break;
      if (blob_append (out, buf, (size_t) r) < 0) break;
    }
  for (;;)
    {
      ssize_t r = read (ep[0], buf, sizeof buf);
      if (r < 0 && errno == EINTR) continue;
      if (r <= 0) break;
      if (blob_append (err, buf, (size_t) r) < 0) break;
    }
  close (op[0]); close (ep[0]);
  int st = 0;
  pid_t w;
  while ((w = waitpid (pid, &st, 0)) < 0 && errno == EINTR) ;
  bsshd_child_guard_parent_end (&guard);
  if (w == pid && WIFEXITED (st)) return WEXITSTATUS (st);
  if (w == pid && WIFSIGNALED (st)) return 128 + WTERMSIG (st);
  return 127;
}

static int listen_tcp (const char *addr, const char *port)
{
  struct addrinfo hints, *res = NULL, *rp;
  memset (&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  int gai = getaddrinfo (addr, port, &hints, &res);
  if (gai != 0) { builtin_error ("getaddrinfo %s:%s: %s", addr, port, gai_strerror (gai)); return -1; }
  int fd = -1;
  for (rp = res; rp; rp = rp->ai_next)
    {
      fd = socket (rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC, rp->ai_protocol);
      if (fd < 0) continue;
      int yes = 1;
      setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
      if (bind (fd, rp->ai_addr, rp->ai_addrlen) == 0 && listen (fd, 16) == 0) break;
      close (fd); fd = -1;
    }
  freeaddrinfo (res);
  if (fd < 0) builtin_error ("listen %s:%s: %s", addr, port, strerror (errno));
  return fd;
}

static int connect_tcp (const char *host, const char *port)
{
  struct addrinfo hints, *res = NULL, *rp;
  memset (&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  int gai = getaddrinfo (host, port, &hints, &res);
  if (gai != 0) return -1;
  int fd = -1;
  for (rp = res; rp; rp = rp->ai_next)
    {
      fd = socket (rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC, rp->ai_protocol);
      if (fd < 0) continue;
      if (connect (fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
      close (fd); fd = -1;
    }
  freeaddrinfo (res);
  return fd;
}

#if BSSHD_HAVE_LIBSSH_SERVER
static int
bsshd_listen_forward (const char *addr, int port, int *bound_port)
{
  char portbuf[32];
  snprintf (portbuf, sizeof portbuf, "%d", port);
  int fd = listen_tcp (addr && *addr ? addr : "127.0.0.1", portbuf);
  if (fd < 0)
    return -1;
  if (bound_port)
    {
      struct sockaddr_storage ss;
      socklen_t sl = sizeof ss;
      *bound_port = port;
      if (getsockname (fd, (struct sockaddr *) &ss, &sl) == 0)
        {
          if (ss.ss_family == AF_INET)
            *bound_port = ntohs (((struct sockaddr_in *) &ss)->sin_port);
          else if (ss.ss_family == AF_INET6)
            *bound_port = ntohs (((struct sockaddr_in6 *) &ss)->sin6_port);
        }
    }
  return fd;
}

static int
bsshd_peer_name_port (int fd, char *host, size_t hostlen, int *port)
{
  struct sockaddr_storage ss;
  socklen_t sl = sizeof ss;
  if (host && hostlen)
    snprintf (host, hostlen, "127.0.0.1");
  if (port)
    *port = 0;
  if (getpeername (fd, (struct sockaddr *) &ss, &sl) < 0)
    return -1;
  if (host && hostlen)
    {
      void *src = NULL;
      if (ss.ss_family == AF_INET)
        src = &((struct sockaddr_in *) &ss)->sin_addr;
      else if (ss.ss_family == AF_INET6)
        src = &((struct sockaddr_in6 *) &ss)->sin6_addr;
      if (src)
        inet_ntop (ss.ss_family, src, host, (socklen_t) hostlen);
    }
  if (port)
    {
      if (ss.ss_family == AF_INET)
        *port = ntohs (((struct sockaddr_in *) &ss)->sin_port);
      else if (ss.ss_family == AF_INET6)
        *port = ntohs (((struct sockaddr_in6 *) &ss)->sin6_port);
    }
  return 0;
}

static int
bsshd_pump_fd_channel (int fd, ssh_session session, ssh_channel channel)
{
  char buf[8192];
  int sock_eof = 0;
  for (;;)
    {
      fd_set rfds;
      FD_ZERO (&rfds);
      int sfd = ssh_get_fd (session);
      if (!sock_eof) FD_SET (fd, &rfds);
      FD_SET (sfd, &rfds);
      int maxfd = fd > sfd ? fd : sfd;
      struct timeval tv;
      tv.tv_sec = 0; tv.tv_usec = 100000;
      int sel = select (maxfd + 1, &rfds, NULL, NULL, &tv);
      if (sel < 0 && errno == EINTR) continue;
      if (sel < 0) break;
      if (!sock_eof && FD_ISSET (fd, &rfds))
        {
          ssize_t n = read (fd, buf, sizeof buf);
          if (n <= 0)
            {
              sock_eof = 1;
              ssh_channel_send_eof (channel);
            }
          else
            bsshd_channel_write_all (channel, buf, (size_t) n, 0);
        }
      int avail = ssh_channel_poll_timeout (channel, 0, 0);
      while (avail > 0)
        {
          uint32_t chunk = (uint32_t) (avail < (int) sizeof buf ? avail : (int) sizeof buf);
          int n = ssh_channel_read (channel, buf, chunk, 0);
          if (n <= 0) break;
          write_all (fd, buf, (size_t) n);
          avail -= n;
        }
      if (ssh_channel_is_eof (channel) || !ssh_channel_is_open (channel))
        break;
    }
  return 0;
}
#endif

static int handle_client (int fd, const bsshd_target_user *target)
{
  char line[256];
  size_t cmdlen = 0, inlen = 0;
  if (read_line_fd (fd, line, sizeof line) < 0 || strcmp (line, "BASHSSH1\n") != 0)
    return -1;
  while (read_line_fd (fd, line, sizeof line) == 0)
    {
      if (strcmp (line, "\n") == 0) break;
      if (sscanf (line, "cmd-len %zu", &cmdlen) == 1) continue;
      if (sscanf (line, "stdin-len %zu", &inlen) == 1) continue;
    }
  blob cmd = {0}, in = {0}, out = {0}, err = {0};
  int rc = 127;
  char inpath[64] = "";
  if (read_exact_blob (fd, &cmd, cmdlen) < 0 || read_exact_blob (fd, &in, inlen) < 0)
    goto done;
  if (in.n)
    {
      if (write_blob_temp (&in, inpath, sizeof inpath) < 0) goto done;
    }
  rc = run_local (cmd.p ? cmd.p : "", in.n ? inpath : NULL, target, &out, &err);

done:
  {
    char hdr[256];
    int hn = snprintf (hdr, sizeof hdr, "BASHSSH1-RESP\nrc %d\nstdout-len %zu\nstderr-len %zu\n\n",
                       rc, out.n, err.n);
    if (hn > 0 && (size_t) hn < sizeof hdr)
      {
        write_all (fd, hdr, (size_t) hn);
        write_all (fd, out.p ? out.p : "", out.n);
        write_all (fd, err.p ? err.p : "", err.n);
      }
  }
  if (inpath[0]) unlink (inpath);
  free (cmd.p); free (in.p); free (out.p); free (err.p);
  return 0;
}

/* Write the sshd placeholder host key + .pub at PATH with mode 0600.
   Returns 0 on success, -1 on the primary-file write failure (errno is
   set by the failing fopen).  The .pub sidecar is best-effort: if its
   path overflows or its fopen fails, the primary key still counts as
   written.  Factored out of keygen() so the run() lazy-auto-generation
   path can call the same writer without going through the WORD_LIST
   verb-dispatch shape. */
static int
bsshd_write_placeholder_key (const char *path, const char *type)
{
  if (!path || !*path) { errno = EINVAL; return -1; }
  FILE *f = fopen (path, "w");
  if (!f) return -1;
  chmod (path, 0600);
  fprintf (f, "BASHSSHD-HOSTKEY %s\n", type ? type : "ed25519");
  fclose (f);
  char pub[512];
  int n = snprintf (pub, sizeof pub, "%s.pub", path);
  if (n <= 0 || (size_t) n >= sizeof pub) return 0;  /* primary written; .pub skipped */
  f = fopen (pub, "w");
  if (f)
    {
      fprintf (f, "sshd-%s AAAABASHOSHOSTKEY\n", type ? type : "ed25519");
      fclose (f);
    }
  return 0;
}

static int
bsshd_write_real_hostkey (const char *path, const char *type)
{
  const char *kt_arg = "ed25519";
  const char *bits = NULL;
  if (type && *type && strcmp (type, "ed25519") && strcmp (type, "ED25519"))
    { errno = EINVAL; return -1; }
  struct bsshd_child_guard guard;
  bsshd_child_guard_begin (&guard);
  pid_t pid = fork ();
  if (pid == 0)
    {
      bsshd_child_guard_child_end (&guard);
      int nullfd = open ("/dev/null", O_RDWR);
      if (nullfd >= 0)
        {
          dup2 (nullfd, STDIN_FILENO);
          dup2 (nullfd, STDOUT_FILENO);
          dup2 (nullfd, STDERR_FILENO);
          if (nullfd > STDERR_FILENO) close (nullfd);
        }
      if (bits)
        execlp ("ssh-keygen", "ssh-keygen", "-q", "-t", kt_arg, "-b", bits,
                "-N", "", "-f", path, (char *) NULL);
      else
        execlp ("ssh-keygen", "ssh-keygen", "-q", "-t", kt_arg,
                "-N", "", "-f", path, (char *) NULL);
      _exit (127);
    }
  if (pid > 0)
    {
      int st = 0;
      while (waitpid (pid, &st, 0) < 0 && errno == EINTR) ;
      bsshd_child_guard_parent_end (&guard);
      if (WIFEXITED (st) && WEXITSTATUS (st) == 0)
        { chmod (path, 0600); return 0; }
    }
  else
    bsshd_child_guard_parent_end (&guard);

#if BSSHD_HAVE_LIBSSH_SERVER
  if (bsshd_libssh_ensure_initialized () < 0)
    { errno = EIO; return -1; }
  enum ssh_keytypes_e kt = SSH_KEYTYPE_ED25519;
  int parameter = 0;

  ssh_key key = NULL;
  int rc = ssh_pki_generate (kt, parameter, &key);
  if (rc != SSH_OK && key)
    SSH_KEY_FREE (key);
  if (rc != SSH_OK || !key)
    { errno = EIO; return -1; }
  rc = ssh_pki_export_privkey_file_format (key, NULL, NULL, NULL, path,
                                           SSH_FILE_FORMAT_OPENSSH);
  if (rc != SSH_OK)
    rc = ssh_pki_export_privkey_file_format (key, NULL, NULL, NULL, path,
                                             SSH_FILE_FORMAT_PEM);
  if (rc == SSH_OK)
    {
      chmod (path, 0600);
      char pub[512];
      int n = snprintf (pub, sizeof pub, "%s.pub", path);
      if (n > 0 && (size_t) n < sizeof pub)
        ssh_pki_export_pubkey_file (key, pub);
    }
  ssh_key_free (key);
  if (rc != SSH_OK)
    { errno = EIO; return -1; }
  return 0;
#else
  (void) path; (void) type;
  errno = ENOSYS;
  return -1;
#endif
}

static int keygen (WORD_LIST *args)
{
  const char *path = NULL, *type = "ed25519", *w;
  int encrypted = 0;
  while ((w = nw (&args)))
    {
      if ((!strcmp (w, "-f") || !strcmp (w, "-k")) && args) path = nw (&args);
      else if (!strcmp (w, "-t") && args) type = nw (&args);
      else if (!strcmp (w, "--encrypted")) encrypted = 1;
      else if (!path) path = w;
    }
  if (!path) { builtin_error ("keygen -f PATH"); return EX_USAGE; }
  if ((encrypted ? bsshd_write_real_hostkey (path, type)
                 : bsshd_write_placeholder_key (path, type)) < 0)
    {
      builtin_error ("keygen %s: %s", path, strerror (errno));
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

#if BSSHD_HAVE_LIBSSH_SERVER
static int
bsshd_channel_write_all (ssh_channel ch, const void *data, size_t n, int stderr_stream)
{
  const char *p = (const char *) data;
  while (n)
    {
      uint32_t chunk = n > 32768 ? 32768 : (uint32_t) n;
      int w = stderr_stream ? ssh_channel_write_stderr (ch, p, chunk)
                            : ssh_channel_write (ch, p, chunk);
      if (w == SSH_ERROR)
        return -1;
      if (w == SSH_AGAIN)
        continue;
      if (w <= 0)
        return -1;
      p += w;
      n -= (size_t) w;
    }
  return 0;
}

typedef struct {
  int requested;
} bsshd_agent_req_state;

static void
bsshd_agent_req_cb (ssh_session session, ssh_channel channel, void *userdata)
{
  (void) session;
  (void) channel;
  bsshd_agent_req_state *st = (bsshd_agent_req_state *) userdata;
  if (st)
    st->requested = 1;
}

static int
bsshd_make_agent_listener (char *dir, size_t dirsz, char *path, size_t pathsz,
                           const bsshd_target_user *target)
{
  snprintf (dir, dirsz, "/tmp/sshd-agent-XXXXXX");
  if (!mkdtemp (dir))
    return -1;
  if (chmod (dir, 0700) < 0)
    return -1;
  snprintf (path, pathsz, "%s/agent.sock", dir);
  int fd = socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return -1;
  struct sockaddr_un sa;
  memset (&sa, 0, sizeof sa);
  sa.sun_family = AF_UNIX;
  if (strlen (path) >= sizeof sa.sun_path)
    { close (fd); errno = ENAMETOOLONG; return -1; }
  snprintf (sa.sun_path, sizeof sa.sun_path, "%s", path);
  if (bind (fd, (struct sockaddr *) &sa, sizeof sa) < 0)
    { close (fd); return -1; }
  chmod (path, 0600);
  if (target && target->enabled)
    {
      chown (dir, target->user.uid, target->user.gid);
      chown (path, target->user.uid, target->user.gid);
    }
  if (listen (fd, 4) < 0)
    { close (fd); return -1; }
  return fd;
}

static void
bsshd_cleanup_agent_listener (int lfd, const char *path, const char *dir)
{
  if (lfd >= 0)
    close (lfd);
  if (path && path[0])
    unlink (path);
  if (dir && dir[0])
    rmdir (dir);
}

static int
bsshd_spawn_local (const char *cmd, const char *infile,
                   const bsshd_target_user *target, const char *agent_sock,
                   int *out_fd, int *err_fd)
{
  int op[2], ep[2];
  if (pipe (op) < 0 || pipe (ep) < 0)
    return -1;
  struct bsshd_child_guard guard;
  bsshd_child_guard_begin (&guard);
  pid_t pid = fork ();
  if (pid < 0)
    {
      bsshd_child_guard_parent_end (&guard);
      close (op[0]); close (op[1]); close (ep[0]); close (ep[1]);
      return -1;
    }
  if (pid == 0)
    {
      bsshd_child_guard_child_end (&guard);
      close (op[0]); close (ep[0]);
      if (infile)
        {
          int in = open (infile, O_RDONLY);
          if (in < 0) _exit (127);
          dup2 (in, STDIN_FILENO);
          close (in);
        }
      dup2 (op[1], STDOUT_FILENO);
      dup2 (ep[1], STDERR_FILENO);
      close (op[1]); close (ep[1]);
      const char *shell = "/bin/bash";
      if (target && target->enabled)
        {
          char drop_err[BC_PD_ERR_MAX];
          if (target->user.home[0] && chdir (target->user.home) < 0)
            _exit (127);
          if (geteuid () == 0 &&
              bc_privdrop_to_user (target->user.uid, target->user.gid,
                                   target->groups, target->ngroups,
                                   drop_err, sizeof drop_err) < 0)
            _exit (127);
          if (geteuid () != target->user.uid || getegid () != target->user.gid)
            _exit (127);
          shell = target->user.shell[0] ? target->user.shell : "/bin/bash";
        }
      /* Explicit-envp exec (agent path): login vars + AcceptEnv session vars +
         SSH_AUTH_SOCK for the forwarded agent. setenv()+execl() doesn't
         propagate here (see bsshd_exec_child). */
      bsshd_exec_child (shell, cmd, target,
                        (agent_sock && agent_sock[0]) ? "SSH_AUTH_SOCK" : NULL,
                        (agent_sock && agent_sock[0]) ? agent_sock : NULL);
      _exit (127);
    }
  bsshd_child_guard_parent_end (&guard);
  close (op[1]); close (ep[1]);
  *out_fd = op[0];
  *err_fd = ep[0];
  return pid;
}

static int
bsshd_spawn_pty_shell (const bsshd_target_user *target, int rows, int cols,
                       int *master_fd)
{
  int mfd = posix_openpt (O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (mfd < 0)
    return -1;
  if (grantpt (mfd) < 0 || unlockpt (mfd) < 0)
    { close (mfd); return -1; }
  char *slave = ptsname (mfd);
  if (!slave)
    { close (mfd); return -1; }

  struct bsshd_child_guard guard;
  bsshd_child_guard_begin (&guard);
  pid_t pid = fork ();
  if (pid < 0)
    {
      bsshd_child_guard_parent_end (&guard);
      close (mfd);
      return -1;
    }
  if (pid == 0)
    {
      bsshd_child_guard_child_end (&guard);
      bsshd_install_default_term_handlers ();
      if (setsid () < 0)
        _exit (126);
      int sfd = open (slave, O_RDWR);
      if (sfd < 0)
        _exit (126);
      ioctl (sfd, TIOCSCTTY, 0);
      if (rows > 0 && cols > 0)
        {
          struct winsize ws;
          memset (&ws, 0, sizeof ws);
          ws.ws_row = (unsigned short) rows;
          ws.ws_col = (unsigned short) cols;
          ioctl (sfd, TIOCSWINSZ, &ws);
        }
      if (dup2 (sfd, STDIN_FILENO) < 0 ||
          dup2 (sfd, STDOUT_FILENO) < 0 ||
          dup2 (sfd, STDERR_FILENO) < 0)
        _exit (126);
      if (sfd > STDERR_FILENO)
        close (sfd);
      close (mfd);

      const char *shell = "/bin/bash";
      if (target && target->enabled)
        {
          char drop_err[BC_PD_ERR_MAX];
          if (target->user.home[0] && chdir (target->user.home) < 0)
            _exit (127);
          if (geteuid () == 0 &&
              bc_privdrop_to_user (target->user.uid, target->user.gid,
                                   target->groups, target->ngroups,
                                   drop_err, sizeof drop_err) < 0)
            _exit (127);
          if (geteuid () != target->user.uid || getegid () != target->user.gid)
            _exit (127);
          shell = target->user.shell[0] ? target->user.shell : "/bin/bash";
        }
      /* Interactive login shell via explicit-envp exec (cmd==NULL): login vars +
         AcceptEnv session vars. setenv()+execl() doesn't propagate here. */
      bsshd_exec_child (shell, NULL, target, NULL, NULL);
      _exit (127);
    }
  bsshd_child_guard_parent_end (&guard);
  *master_fd = mfd;
  return pid;
}

/* F06 item 3 slice 3: mid-session window-resize. The client sends a
   window-change channel request on SIGWINCH. This is a message-API server
   (ssh_message_get), which queues channel requests as messages rather than
   dispatching them to channel callbacks — so handle_shell drains the
   SSH_CHANNEL_REQUEST_WINDOW_CHANGE message and resizes the PTY master, making
   the remote shell observe the new geometry (`stty size`, `$LINES`/`$COLUMNS`). */
static int
bsshd_encrypted_handle_shell (ssh_session session, ssh_channel ch,
                              const bsshd_target_user *target,
                              int rows, int cols)
{
  int mfd = -1;
  pid_t pid = bsshd_spawn_pty_shell (target, rows, cols, &mfd);
  if (pid < 0)
    return -1;

  char buf[8192];
  int child_done = 0, channel_eof = 0, status = 0;
  while (!child_done && ssh_channel_is_open (ch))
    {
      pid_t w = waitpid (pid, &status, WNOHANG);
      if (w == pid)
        { child_done = 1; break; }
      if (ssh_channel_is_eof (ch))
        channel_eof = 1;

      fd_set rfds;
      FD_ZERO (&rfds);
      int sfd = ssh_get_fd (session);
      if (mfd >= 0) FD_SET (mfd, &rfds);
      if (!channel_eof && sfd >= 0) FD_SET (sfd, &rfds);
      int maxfd = mfd > sfd ? mfd : sfd;
      struct timeval tv;
      tv.tv_sec = 0; tv.tv_usec = 100000;
      int sel = select (maxfd + 1, &rfds, NULL, NULL, &tv);
      if (sel < 0 && errno == EINTR) continue;
      if (sel < 0) break;

      /* Drain pending channel requests (notably window-change) via the message
         API — this message-based server does not dispatch them to channel
         callbacks during the read loop. Run this EVERY iteration (not only when
         FD_ISSET(sfd) shows fresh socket data): libssh buffers incoming packets
         internally, so a request already read into its buffer during prior shell
         I/O leaves sfd not-readable; gating the drain on FD_ISSET could strand
         such a buffered control request until unrelated socket activity. The
         100ms select timeout means draining every iteration bounds that latency.
         ssh_message_get is non-blocking here, so an empty queue is cheap and
         shell I/O isn't stalled. (NB: this hardens buffered-message servicing
         generally; it did NOT resolve the intermittent f06 second-resize flake,
         which has a deeper cause — see the f06-ssh-shell-resize-flaky-tcg memo.) */
      if (sfd >= 0)
        {
          ssh_set_blocking (session, 0);
          ssh_message m;
          while ((m = ssh_message_get (session)) != NULL)
            {
              if (ssh_message_type (m) == SSH_REQUEST_CHANNEL
                  && ssh_message_subtype (m) == SSH_CHANNEL_REQUEST_WINDOW_CHANGE)
                {
                  int wcols = ssh_message_channel_request_pty_width (m);
                  int wrows = ssh_message_channel_request_pty_height (m);
                  if (mfd >= 0 && wcols > 0 && wrows > 0)
                    {
                      struct winsize ws;
                      memset (&ws, 0, sizeof ws);
                      ws.ws_row = (unsigned short) wrows;
                      ws.ws_col = (unsigned short) wcols;
                      ioctl (mfd, TIOCSWINSZ, &ws);
                    }
                  ssh_message_channel_request_reply_success (m);
                }
              else
                ssh_message_reply_default (m);
              ssh_message_free (m);
            }
          ssh_set_blocking (session, 1);
        }

      if (mfd >= 0 && FD_ISSET (mfd, &rfds))
        {
          ssize_t n = read (mfd, buf, sizeof buf);
          if (n <= 0)
            break;
          if (bsshd_channel_write_all (ch, buf, (size_t) n, 0) < 0)
            break;
        }

      if (channel_eof)
        continue;
      int avail = ssh_channel_poll_timeout (ch, 0, 0);
      while (avail > 0)
        {
          uint32_t chunk = (uint32_t) (avail < (int) sizeof buf ? avail : (int) sizeof buf);
          int n = ssh_channel_read (ch, buf, chunk, 0);
          if (n <= 0) { channel_eof = 1; break; }
          if (write_all (mfd, buf, (size_t) n) < 0)
            { avail = 0; break; }
          avail -= n;
        }
    }

  if (!child_done)
    {
      kill (pid, SIGHUP);
      while (waitpid (pid, &status, 0) < 0 && errno == EINTR)
        ;
    }
  close (mfd);
  int rc = 1;
  if (WIFEXITED (status)) rc = WEXITSTATUS (status);
  else if (WIFSIGNALED (status)) rc = 128 + WTERMSIG (status);
  ssh_channel_request_send_exit_status (ch, rc);
  ssh_channel_send_eof (ch);
  ssh_channel_close (ch);
  return rc;
}

#if BSSHD_HAVE_LIBSSH_SFTP_SERVER
static int
bsshd_encrypted_handle_sftp (ssh_session session, ssh_channel ch,
                             const bsshd_target_user *target)
{
  char target_err[256];
  sftp_session sftp = NULL;
  char buf[32768];

  target_err[0] = '\0';
  if (bsshd_apply_target_current_process (target, target_err,
                                          sizeof target_err) < 0)
    {
      if (target_err[0])
        bsshd_channel_write_all (ch, target_err, strlen (target_err), 1);
      ssh_channel_request_send_exit_status (ch, 127);
      ssh_channel_send_eof (ch);
      ssh_channel_close (ch);
      return 127;
    }

  if (sftp_channel_default_subsystem_request (session, ch, "sftp",
                                              &sftp) != SSH_OK || !sftp)
    {
      ssh_channel_request_send_exit_status (ch, 1);
      ssh_channel_send_eof (ch);
      ssh_channel_close (ch);
      return 1;
    }

  for (;;)
    {
      int n = ssh_channel_read_timeout (ch, buf, sizeof buf, 0, 250);
      if (n == SSH_ERROR)
        break;
      if (n > 0)
        {
          if (sftp_channel_default_data_callback (session, ch, buf,
                                                  (uint32_t) n, 0,
                                                  &sftp) == SSH_ERROR)
            break;
          continue;
        }
      if (ssh_channel_is_closed (ch) || ssh_channel_is_eof (ch))
        break;
    }

  sftp_server_free (sftp);
  ssh_channel_send_eof (ch);
  ssh_channel_close (ch);
  return 0;
}
#endif

static void
bsshd_agent_proxy_close (int *afd, ssh_channel *ach)
{
  if (ach && *ach)
    {
      ssh_channel_close (*ach);
      ssh_channel_free (*ach);
      *ach = NULL;
    }
  if (afd && *afd >= 0)
    {
      close (*afd);
      *afd = -1;
    }
}

static void
bsshd_agent_proxy_pump (ssh_session session, int *afd, ssh_channel *ach)
{
  if (!ach || !*ach || !afd || *afd < 0)
    return;
  int sfd = ssh_get_fd (session);
  if (sfd < 0)
    { bsshd_agent_proxy_close (afd, ach); return; }
  char buf[8192];
  fd_set rfds;
  FD_ZERO (&rfds);
  FD_SET (*afd, &rfds);
  FD_SET (sfd, &rfds);
  int maxfd = *afd > sfd ? *afd : sfd;
  struct timeval tv;
  tv.tv_sec = 0; tv.tv_usec = 0;
  int sel = select (maxfd + 1, &rfds, NULL, NULL, &tv);
  if (sel < 0 && errno != EINTR)
    { bsshd_agent_proxy_close (afd, ach); return; }
  if (sel > 0 && FD_ISSET (*afd, &rfds))
    {
      ssize_t n = read (*afd, buf, sizeof buf);
      if (n <= 0)
        ssh_channel_send_eof (*ach);
      else if (bsshd_channel_write_all (*ach, buf, (size_t) n, 0) < 0)
        { bsshd_agent_proxy_close (afd, ach); return; }
    }
  int avail = ssh_channel_poll_timeout (*ach, 0, 0);
  while (avail > 0)
    {
      uint32_t chunk = (uint32_t) (avail < (int) sizeof buf ? avail : (int) sizeof buf);
      int n = ssh_channel_read (*ach, buf, chunk, 0);
      if (n <= 0)
        break;
      if (write_all (*afd, buf, (size_t) n) < 0)
        { bsshd_agent_proxy_close (afd, ach); return; }
      avail -= n;
    }
  if (*ach && (ssh_channel_is_eof (*ach) || !ssh_channel_is_open (*ach)))
    bsshd_agent_proxy_close (afd, ach);
}

static int
run_local_agent_proxy (ssh_session session, const char *cmd, const char *infile,
                       const bsshd_target_user *target, int enable_agent,
                       blob *out, blob *err)
{
  char agent_dir[64] = "";
  char agent_path[108] = "";
  int lfd = -1;
  if (enable_agent)
    lfd = bsshd_make_agent_listener (agent_dir, sizeof agent_dir,
                                     agent_path, sizeof agent_path, target);

  int ofd = -1, efd = -1;
  pid_t pid = bsshd_spawn_local (cmd, infile, target,
                                 lfd >= 0 ? agent_path : NULL, &ofd, &efd);
  if (pid < 0)
    {
      bsshd_cleanup_agent_listener (lfd, agent_path, agent_dir);
      return 127;
    }

  int afd = -1;
  ssh_channel ach = NULL;
  int out_open = 1, err_open = 1, child_done = 0, status = 0;
  char buf[4096];
  while (out_open || err_open || !child_done)
    {
      fd_set rfds;
      FD_ZERO (&rfds);
      int maxfd = -1;
      if (out_open) { FD_SET (ofd, &rfds); if (ofd > maxfd) maxfd = ofd; }
      if (err_open) { FD_SET (efd, &rfds); if (efd > maxfd) maxfd = efd; }
      if (lfd >= 0 && afd < 0) { FD_SET (lfd, &rfds); if (lfd > maxfd) maxfd = lfd; }
      int sfd = ssh_get_fd (session);
      if (ach && sfd >= 0) { FD_SET (sfd, &rfds); if (sfd > maxfd) maxfd = sfd; }
      struct timeval tv;
      tv.tv_sec = 0; tv.tv_usec = 100000;
      int sel = maxfd >= 0 ? select (maxfd + 1, &rfds, NULL, NULL, &tv) : 0;
      if (sel < 0 && errno != EINTR)
        break;
      if (sel > 0 && out_open && FD_ISSET (ofd, &rfds))
        {
          ssize_t n = read (ofd, buf, sizeof buf);
          if (n <= 0) { close (ofd); out_open = 0; }
          else blob_append (out, buf, (size_t) n);
        }
      if (sel > 0 && err_open && FD_ISSET (efd, &rfds))
        {
          ssize_t n = read (efd, buf, sizeof buf);
          if (n <= 0) { close (efd); err_open = 0; }
          else blob_append (err, buf, (size_t) n);
        }
      if (sel > 0 && lfd >= 0 && afd < 0 && FD_ISSET (lfd, &rfds))
        {
          afd = accept4 (lfd, NULL, NULL, SOCK_CLOEXEC);
          if (afd >= 0)
            {
              ach = ssh_channel_new (session);
              if (!ach || ssh_channel_open_auth_agent (ach) != SSH_OK)
                bsshd_agent_proxy_close (&afd, &ach);
              else
                ssh_channel_set_blocking (ach, 0);
            }
        }
      bsshd_agent_proxy_pump (session, &afd, &ach);
      if (!child_done)
        {
          pid_t w = waitpid (pid, &status, WNOHANG);
          if (w == pid)
            child_done = 1;
          else if (w < 0 && errno == ECHILD)
            child_done = 1;
        }
    }
  if (out_open) close (ofd);
  if (err_open) close (efd);
  bsshd_agent_proxy_close (&afd, &ach);
  bsshd_cleanup_agent_listener (lfd, agent_path, agent_dir);
  if (!child_done)
    waitpid (pid, &status, 0);
  if (WIFEXITED (status))
    return WEXITSTATUS (status);
  if (WIFSIGNALED (status))
    return 128 + WTERMSIG (status);
  return 127;
}

static char *
bsshd_next_ak_token (char **pp)
{
  char *p = *pp;
  while (*p == ' ' || *p == '\t') p++;
  if (!*p || *p == '\n')
    { *pp = p; return NULL; }
  char *start = p;
  int quote = 0, esc = 0;
  while (*p && *p != '\n')
    {
      if (esc)
        { esc = 0; p++; continue; }
      if (*p == '\\')
        { esc = 1; p++; continue; }
      if (*p == '"')
        { quote = !quote; p++; continue; }
      if (!quote && (*p == ' ' || *p == '\t'))
        break;
      p++;
    }
  if (*p)
    *p++ = '\0';
  *pp = p;
  return start;
}

static int
bsshd_host_pattern_match (const char *pat, const char *host)
{
  if (!pat || !host)
    return 0;
  if (*pat == '\0')
    return *host == '\0';
  if (*pat == '*')
    {
      while (pat[1] == '*') pat++;
      if (bsshd_host_pattern_match (pat + 1, host))
        return 1;
      return *host && bsshd_host_pattern_match (pat, host + 1);
    }
  if (*pat == '?')
    return *host && bsshd_host_pattern_match (pat + 1, host + 1);
  return *pat == *host && bsshd_host_pattern_match (pat + 1, host + 1);
}

static int
bsshd_from_allowed (const char *patterns, const char *peer)
{
  if (!patterns || !*patterns || !peer || !*peer)
    return 0;
  char buf[512];
  snprintf (buf, sizeof buf, "%s", patterns);
  char *save = NULL;
  for (char *tok = strtok_r (buf, ",", &save); tok; tok = strtok_r (NULL, ",", &save))
    {
      while (*tok == ' ' || *tok == '\t') tok++;
      int neg = 0;
      if (*tok == '!')
        { neg = 1; tok++; }
      if (bsshd_host_pattern_match (tok, peer))
        return neg ? 0 : 1;
    }
  return 0;
}

static void
bsshd_dequote_option_value (char *s)
{
  if (!s || *s != '"')
    return;
  char *r = s + 1, *w = s;
  int esc = 0;
  while (*r)
    {
      if (esc)
        { *w++ = *r++; esc = 0; continue; }
      if (*r == '\\')
        { esc = 1; r++; continue; }
      if (*r == '"')
        { r++; break; }
      *w++ = *r++;
    }
  *w = '\0';
}

static int
bsshd_apply_authorized_key_options (const char *optspec, const char *peer,
                                    bsshd_authz_options *opts)
{
  if (!optspec || !*optspec)
    return 1;
  char buf[2048];
  snprintf (buf, sizeof buf, "%s", optspec);
  char *p = buf;
  while (*p)
    {
      while (*p == ',' || *p == ' ' || *p == '\t') p++;
      if (!*p)
        break;
      char *start = p;
      int quote = 0, esc = 0;
      while (*p)
        {
          if (esc)
            { esc = 0; p++; continue; }
          if (*p == '\\')
            { esc = 1; p++; continue; }
          if (*p == '"')
            { quote = !quote; p++; continue; }
          if (!quote && *p == ',')
            break;
          p++;
        }
      if (*p)
        *p++ = '\0';
      char *eq = strchr (start, '=');
      if (eq)
        *eq++ = '\0';
      if (!strcmp (start, "no-pty"))
        opts->no_pty = 1;
      else if (!strcmp (start, "no-agent-forwarding"))
        opts->no_agent_forwarding = 1;
      else if (!strcmp (start, "no-port-forwarding"))
        opts->no_port_forwarding = 1;
      else if (!strcmp (start, "command") && eq)
        {
          bsshd_dequote_option_value (eq);
          snprintf (opts->forced_command, sizeof opts->forced_command, "%s", eq);
        }
      else if (!strcmp (start, "from") && eq)
        {
          bsshd_dequote_option_value (eq);
          if (!bsshd_from_allowed (eq, peer))
            return 0;
        }
      else
        {
          /* Keep the bounded subset fail-closed for unknown critical options.
             Options prefixed with no- are security restrictions; unknown ones
             could otherwise silently weaken an operator's authorized_keys line. */
          return 0;
        }
    }
  return 1;
}

static int
bsshd_authorized_key_match (const char *path, const char *peer, ssh_key offered,
                            bsshd_authz_options *out_opts)
{
  FILE *f = fopen (path, "r");
  if (!f)
    return 0;
  char line[8192];
  int matched = 0;
  while (fgets (line, sizeof line, f))
    {
      char *p = line;
      char *options = NULL;
      char *type = NULL;
      char *b64 = NULL;
      enum ssh_keytypes_e kt = SSH_KEYTYPE_UNKNOWN;
      while ((type = bsshd_next_ak_token (&p)))
        {
          kt = ssh_key_type_from_name (type);
          if (kt != SSH_KEYTYPE_UNKNOWN)
            break;
          if (options)
            { type = NULL; break; }
          options = type;
        }
      if (!type || kt == SSH_KEYTYPE_UNKNOWN)
        continue;
      b64 = bsshd_next_ak_token (&p);
      if (!b64)
        continue;
      ssh_key ak = NULL;
      if (ssh_pki_import_pubkey_base64 (b64, kt, &ak) == SSH_OK && ak)
        {
          if (ssh_key_cmp (offered, ak, SSH_KEY_CMP_PUBLIC) == 0)
            {
              bsshd_authz_options tmp;
              bsshd_authz_options_clear (&tmp);
              if (bsshd_apply_authorized_key_options (options, peer, &tmp))
                {
                  if (out_opts)
                    *out_opts = tmp;
                  matched = 1;
                }
            }
          ssh_key_free (ak);
        }
      if (matched)
        break;
    }
  fclose (f);
  return matched;
}

static int
bsshd_auth_pubkey_allowed (const bsshd_target_user *target, const char *user,
                           const char *peer, ssh_key pubkey,
                           bsshd_authz_options *opts)
{
  if (target && target->enabled && strcmp (user ? user : "", target->user.name) != 0)
    return 0;
  const char *authfile = getenv ("BASHSSHD_AUTHORIZED_KEYS");
  char path[512];
  if (!authfile || !*authfile)
    {
      const char *home = NULL;
      if (target && target->enabled)
        home = target->user.home;
      else if (user && *user)
        {
          bc_user_info info;
          if (bc_lookup_user (user, &info) == 0 && info.home[0])
            home = info.home;
        }
      if (!home || !*home)
        home = getenv ("HOME");
      if (!home || !*home)
        return 0;
      snprintf (path, sizeof path, "%s/.ssh/authorized_keys", home);
      authfile = path;
    }
  else if (authfile[0] != '/')
    {
      const char *home = NULL;
      if (target && target->enabled)
        home = target->user.home;
      else if (user && *user)
        {
          bc_user_info info;
          if (bc_lookup_user (user, &info) == 0 && info.home[0])
            home = info.home;
        }
      if (!home || !*home)
        home = getenv ("HOME");
      if (!home || !*home)
        return 0;
      if (authfile[0] == '~' && authfile[1] == '/')
        snprintf (path, sizeof path, "%s/%s", home, authfile + 2);
      else
        snprintf (path, sizeof path, "%s/%s", home, authfile);
      authfile = path;
    }
  return bsshd_authorized_key_match (authfile, peer, pubkey, opts);
}

static int
bsshd_shadow_phc (const char *user, char *out, size_t outsz)
{
  const char *path = getenv ("PHCLIB_SHADOW");
  if (!path || !*path)
    path = "/etc/shadow";
  FILE *f = fopen (path, "r");
  if (!f)
    return -1;
  char line[8192];
  int rc = -1;
  while (fgets (line, sizeof line, f))
    {
      char *save = NULL;
      char *name = strtok_r (line, ":\n", &save);
      char *phc = strtok_r (NULL, ":\n", &save);
      if (!name || !phc || strcmp (name, user) != 0)
        continue;
      if (phc[0] == '!' || phc[0] == '*' || phc[0] == '\0' || strlen (phc) >= outsz)
        break;
      snprintf (out, outsz, "%s", phc);
      rc = 0;
      break;
    }
  fclose (f);
  return rc;
}

static int
bsshd_parse_auth_methods (const char *s, int *out)
{
  if (!s || !*s || !out)
    return -1;
  int methods = 0;
  char buf[128];
  snprintf (buf, sizeof buf, "%s", s);
  char *save = NULL;
  for (char *tok = strtok_r (buf, ",", &save); tok; tok = strtok_r (NULL, ",", &save))
    {
      while (*tok == ' ' || *tok == '\t') tok++;
      char *end = tok + strlen (tok);
      while (end > tok && (end[-1] == ' ' || end[-1] == '\t')) *--end = '\0';
      if (!strcmp (tok, "publickey"))
        methods |= BSSHD_AUTH_PUBLICKEY;
      else if (!strcmp (tok, "password"))
        methods |= BSSHD_AUTH_PASSWORD;
      else
        return -1;
    }
  if (!methods)
    return -1;
  *out = methods;
  return 0;
}

static int
bsshd_fill_target_user (const char *user, bsshd_target_user *target)
{
  if (!user || !*user || !target)
    return -1;
  memset (target, 0, sizeof *target);
  if (bc_lookup_user (user, &target->user) < 0)
    return -1;
  target->groups[target->ngroups++] = target->user.gid;
  int supp = 0;
  bc_load_supplementary_groups (target->user.name,
                                target->groups + target->ngroups,
                                &supp, BC_PD_GROUPS_MAX);
  target->ngroups += supp;
  target->enabled = 1;
  return 0;
}

static int
bsshd_auth_password_allowed (const bsshd_target_user *target, const char *user,
                             const char *password)
{
  if (!user || !*user || !password)
    return 0;
  if (target && target->enabled && strcmp (user, target->user.name) != 0)
    return 0;

  size_t plen = strlen (password);
  if (plen > BSSHD_AUTH_MAX_SECRET)
    return 0;

  char phc[1024];
  if (bsshd_shadow_phc (user, phc, sizeof phc) < 0)
    return 0;

  int afd = open (BSSHD_AUTH_DEV, O_RDWR);
  if (afd < 0)
    return 0;
  struct bsshd_auth_handle h;
  memset (&h, 0, sizeof h);
  if (ioctl (afd, BSSHD_AUTH_IOC_NEW_SECRET, &h) < 0)
    { close (afd); return 0; }
  struct bsshd_auth_secret_write w;
  memset (&w, 0, sizeof w);
  w.id = h.id;
  w.len = (unsigned int) plen;
  w.user_ptr = (unsigned long long) (uintptr_t) password;
  if (ioctl (afd, BSSHD_AUTH_IOC_WRITE_SECRET, &w) < 0 ||
      ioctl (afd, BSSHD_AUTH_IOC_SEAL_SECRET, &h) < 0)
    {
      ioctl (afd, BSSHD_AUTH_IOC_CLEAR_SECRET, &h);
      close (afd);
      return 0;
    }

  struct bsshd_child_guard guard;
  bsshd_child_guard_begin (&guard);
  pid_t pid = fork ();
  if (pid < 0)
    {
      bsshd_child_guard_parent_end (&guard);
      ioctl (afd, BSSHD_AUTH_IOC_CLEAR_SECRET, &h);
      close (afd);
      return 0;
    }
  if (pid == 0)
    {
      bsshd_child_guard_child_end (&guard);
      char fd_s[32], handle_s[32];
      snprintf (fd_s, sizeof fd_s, "%d", afd);
      snprintf (handle_s, sizeof handle_s, "%u", h.id);
      char self[512];
      ssize_t n = readlink ("/proc/self/exe", self, sizeof self - 1);
      if (n > 0)
        {
          self[n] = '\0';
          execl (self, self, "-c", "auth verify-login \"$1\" \"$2\" \"$3\" \"$4\" TOKEN >/dev/null",
                 "sshd-auth", fd_s, handle_s, user, phc, (char *) 0);
        }
      execl ("/bin/bash", "bash", "-c", "auth verify-login \"$1\" \"$2\" \"$3\" \"$4\" TOKEN >/dev/null",
             "sshd-auth", fd_s, handle_s, user, phc, (char *) 0);
      execl ("/bin/sh", "sh", "-c", "auth verify-login \"$1\" \"$2\" \"$3\" \"$4\" TOKEN >/dev/null",
             "sshd-auth", fd_s, handle_s, user, phc, (char *) 0);
      _exit (127);
    }
  bsshd_child_guard_parent_end (&guard);
  int st = 0;
  while (waitpid (pid, &st, 0) < 0 && errno == EINTR)
    ;
  ioctl (afd, BSSHD_AUTH_IOC_CLEAR_SECRET, &h);
  close (afd);
  memset (phc, 0, sizeof phc);
  return WIFEXITED (st) && WEXITSTATUS (st) == 0;
}

/* F06 item 6a: LoginGraceTime. A SIGALRM in the per-connection child means the
   pre-auth phase outran the grace window — exit immediately (the parent reaps
   it like any other failed session). Cancelled with alarm(0) once auth lands. */
static void
bsshd_login_grace_alarm (int sig)
{
  (void) sig;
  _exit (1);
}

/* F06 item 6a: send the pre-auth Banner (if configured) over the session. The
   file is read each connection so an operator edit takes effect on reload.
   Best-effort: a missing/oversized file is silently skipped (parity with
   OpenSSH, which logs but does not refuse to serve). */
static void
bsshd_send_banner (ssh_session session)
{
  if (!g_banner_path[0])
    return;
  FILE *bf = fopen (g_banner_path, "r");
  if (!bf)
    return;
  char buf[4096];
  size_t n = fread (buf, 1, sizeof buf - 1, bf);
  fclose (bf);
  buf[n] = '\0';
  if (n == 0)
    return;
  ssh_string s = ssh_string_from_char (buf);
  if (s)
    {
      ssh_send_issue_banner (session, s);
      ssh_string_free (s);
    }
}

static int
bsshd_encrypted_auth (ssh_session session, const bsshd_target_user *target,
                      int auth_methods, const char *peer,
                      char *authed_user, size_t authed_user_sz,
                      bsshd_authz_options *authz, int *authed_by_password)
{
  int ssh_methods = 0;
  long tries = 0;
  if (auth_methods & BSSHD_AUTH_PUBLICKEY)
    ssh_methods |= SSH_AUTH_METHOD_PUBLICKEY;
  if (auth_methods & BSSHD_AUTH_PASSWORD)
    ssh_methods |= SSH_AUTH_METHOD_PASSWORD;
  if (!ssh_methods)
    ssh_methods = SSH_AUTH_METHOD_PUBLICKEY;
  ssh_set_auth_methods (session, ssh_methods);
  if (authz)
    bsshd_authz_options_clear (authz);
  if (authed_by_password)
    *authed_by_password = 0;
  bsshd_send_banner (session);
  for (;;)
    {
      ssh_message msg = ssh_message_get (session);
      if (!msg)
        return -1;
      int ok = 0;
      if (ssh_message_type (msg) == SSH_REQUEST_AUTH
          && ssh_message_subtype (msg) == SSH_AUTH_METHOD_PUBLICKEY)
        {
          if (!(auth_methods & BSSHD_AUTH_PUBLICKEY))
            {
              ssh_message_auth_set_methods (msg, ssh_methods);
              ssh_message_reply_default (msg);
              ssh_message_free (msg);
              continue;
            }
          const char *user = ssh_message_auth_user (msg);
          ssh_key pubkey = ssh_message_auth_pubkey (msg);
          int state = ssh_message_auth_publickey_state (msg);
          bsshd_authz_options candidate;
          bsshd_authz_options_clear (&candidate);
          ok = pubkey && bsshd_auth_pubkey_allowed (target, user, peer,
                                                    pubkey, &candidate);
          if (ok && state == SSH_PUBLICKEY_STATE_NONE)
            {
              ssh_message_auth_reply_pk_ok_simple (msg);
              ssh_message_free (msg);
              continue;
            }
          if (ok && state == SSH_PUBLICKEY_STATE_VALID)
            {
              if (authed_user && authed_user_sz)
                snprintf (authed_user, authed_user_sz, "%s", user ? user : "");
              if (authz)
                *authz = candidate;
              /* auth-event log line (one per authenticated connection) —
                 counted by the F06 ControlMaster single-auth proof test. */
              fprintf (stderr, "sshd: accepted publickey for %s from %s\n",
                       user && *user ? user : "?",
                       peer && *peer ? peer : "?");
              ssh_message_auth_reply_success (msg, 0);
              ssh_message_free (msg);
	      return 0;
	    }
	}
      else if (ssh_message_type (msg) == SSH_REQUEST_AUTH
               && ssh_message_subtype (msg) == SSH_AUTH_METHOD_PASSWORD
               && (auth_methods & BSSHD_AUTH_PASSWORD))
        {
          const char *user = ssh_message_auth_user (msg);
          const char *password = ssh_message_auth_password (msg);
          ok = bsshd_auth_password_allowed (target, user, password);
          if (ok)
            {
              if (authed_user && authed_user_sz)
                snprintf (authed_user, authed_user_sz, "%s", user ? user : "");
              if (authed_by_password)
                *authed_by_password = 1;
              fprintf (stderr, "sshd: accepted password for %s from %s\n",
                       user && *user ? user : "?",
                       peer && *peer ? peer : "?");
              ssh_message_auth_reply_success (msg, 0);
              ssh_message_free (msg);
              return 0;
            }
        }
      /* F06 item 6a: MaxAuthTries — count each genuinely failed auth request
         (the pubkey PK_OK probe and method-not-allowed paths `continue` above
         and never reach here). Drop the connection once the cap is hit. */
      if (g_max_auth_tries > 0 && ssh_message_type (msg) == SSH_REQUEST_AUTH
          && ++tries >= g_max_auth_tries)
        {
          ssh_message_reply_default (msg);
          ssh_message_free (msg);
          return -1;
        }
      ssh_message_auth_set_methods (msg, ssh_methods);
      ssh_message_reply_default (msg);
      ssh_message_free (msg);
    }
}

static int
bsshd_encrypted_handle_session (ssh_session session,
                                const bsshd_target_user *target,
                                int allow_agent_forwarding,
                                const bsshd_authz_options *authz)
{
  ssh_channel channel = NULL;
  char *cmd_copy = NULL;
  bsshd_agent_req_state agent_req;
  struct ssh_channel_callbacks_struct channel_callbacks;
  memset (&agent_req, 0, sizeof agent_req);
  memset (&channel_callbacks, 0, sizeof channel_callbacks);
  for (;;)
    {
      ssh_message msg = ssh_message_get (session);
      if (!msg)
        return -1;
      if (ssh_message_type (msg) == SSH_REQUEST_CHANNEL_OPEN
          && ssh_message_subtype (msg) == SSH_CHANNEL_SESSION)
        {
          channel = ssh_message_channel_request_open_reply_accept (msg);
          ssh_message_free (msg);
          break;
        }
      ssh_message_reply_default (msg);
      ssh_message_free (msg);
    }
  if (allow_agent_forwarding)
    {
      channel_callbacks.userdata = &agent_req;
      channel_callbacks.channel_auth_agent_req_function = bsshd_agent_req_cb;
      ssh_callbacks_init (&channel_callbacks);
      ssh_set_channel_callbacks (channel, &channel_callbacks);
    }

  for (;;)
    {
      ssh_message msg = ssh_message_get (session);
      if (!msg)
        { ssh_channel_free (channel); return -1; }
      if (ssh_message_type (msg) == SSH_REQUEST_CHANNEL
          && ssh_message_subtype (msg) == SSH_CHANNEL_REQUEST_EXEC)
        {
          const char *cmd = ssh_message_channel_request_command (msg);
          cmd_copy = strdup ((authz && authz->forced_command[0])
                             ? authz->forced_command : (cmd ? cmd : ""));
          ssh_message_channel_request_reply_success (msg);
          ssh_message_free (msg);
          break;
        }
      ssh_message_reply_default (msg);
      ssh_message_free (msg);
    }

  blob in = {0}, out = {0}, err = {0};
  char buf[4096];
  int idle = 0;
  while (!ssh_channel_is_eof (channel) && idle < 20)
    {
      int r = ssh_channel_read_timeout (channel, buf, sizeof buf, 0, 100);
      if (r == SSH_ERROR)
        break;
      if (r > 0)
        {
          blob_append (&in, buf, (size_t) r);
          idle = 0;
        }
      else
        idle++;
    }
  char inpath[64] = "";
  if (in.n)
    write_blob_temp (&in, inpath, sizeof inpath);
  int rc = (allow_agent_forwarding && agent_req.requested)
           ? run_local_agent_proxy (session, cmd_copy ? cmd_copy : "",
                                    in.n ? inpath : NULL, target, 1, &out, &err)
           : run_local (cmd_copy ? cmd_copy : "", in.n ? inpath : NULL,
                        target, &out, &err);
  bsshd_channel_write_all (channel, out.p ? out.p : "", out.n, 0);
  bsshd_channel_write_all (channel, err.p ? err.p : "", err.n, 1);
  ssh_channel_request_send_exit_status (channel, rc);
  ssh_channel_send_eof (channel);
  ssh_channel_close (channel);
  ssh_channel_free (channel);
  if (inpath[0]) unlink (inpath);
  free (cmd_copy); free (in.p); free (out.p); free (err.p);
  return 0;
}

static int
bsshd_encrypted_handle_tcpip_forward (ssh_session session, ssh_message first)
{
  const char *bind_addr = ssh_message_global_request_address (first);
  int requested_port = ssh_message_global_request_port (first);
  int bound_port = requested_port;
  int lfd = bsshd_listen_forward (bind_addr ? bind_addr : "127.0.0.1",
                                  requested_port, &bound_port);
  if (lfd < 0)
    {
      ssh_message_reply_default (first);
      ssh_message_free (first);
      return -1;
    }
  ssh_message_global_request_reply_success (first, (uint16_t) bound_port);
  ssh_message_free (first);

  for (;;)
    {
      fd_set rfds;
      FD_ZERO (&rfds);
      FD_SET (lfd, &rfds);
      int sfd = ssh_get_fd (session);
      FD_SET (sfd, &rfds);
      int maxfd = lfd > sfd ? lfd : sfd;
      struct timeval tv;
      tv.tv_sec = 0; tv.tv_usec = 100000;
      int sel = select (maxfd + 1, &rfds, NULL, NULL, &tv);
      if (sel < 0 && errno == EINTR) continue;
      if (sel < 0) break;
      if (FD_ISSET (sfd, &rfds))
        {
          ssh_message msg = ssh_message_get (session);
          if (!msg) break;
          if (ssh_message_type (msg) == SSH_REQUEST_GLOBAL
              && ssh_message_subtype (msg) == SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD)
            {
              ssh_message_global_request_reply_success (msg, 0);
              ssh_message_free (msg);
              close (lfd);
              return 0;
            }
          ssh_message_reply_default (msg);
          ssh_message_free (msg);
        }
      if (FD_ISSET (lfd, &rfds))
        {
          int cfd = accept4 (lfd, NULL, NULL, SOCK_CLOEXEC);
          if (cfd < 0 && errno == EINTR) continue;
          if (cfd < 0) break;
          char origin[64];
          int origin_port = 0;
          bsshd_peer_name_port (cfd, origin, sizeof origin, &origin_port);
          ssh_channel ch = ssh_channel_new (session);
          if (!ch)
            { close (cfd); continue; }
          if (ssh_channel_open_reverse_forward (ch,
                                                bind_addr ? bind_addr : "127.0.0.1",
                                                bound_port,
                                                origin, origin_port) != SSH_OK)
            {
              ssh_channel_free (ch);
              close (cfd);
              continue;
            }
          bsshd_pump_fd_channel (cfd, session, ch);
          ssh_channel_close (ch);
          ssh_channel_free (ch);
          close (cfd);
        }
    }
  close (lfd);
  return -1;
}

static int
bsshd_encrypted_handle_direct_tcpip (ssh_session session,
                                     const bsshd_target_user *target,
                                     int allow_forwarding,
                                     int allow_agent_forwarding,
                                     const bsshd_authz_options *authz)
{
  ssh_channel channel = NULL;
  int rfd = -1;
  if (authz)
    {
      if (authz->no_port_forwarding)
        allow_forwarding = 0;
      if (authz->no_agent_forwarding)
        allow_agent_forwarding = 0;
    }
  for (;;)
    {
      ssh_message msg = ssh_message_get (session);
      if (!msg)
        return -1;
      if (ssh_message_type (msg) == SSH_REQUEST_GLOBAL
          && ssh_message_subtype (msg) == SSH_GLOBAL_REQUEST_TCPIP_FORWARD)
        {
          if (!allow_forwarding)
            {
              ssh_message_reply_default (msg);
              ssh_message_free (msg);
              continue;
            }
          return bsshd_encrypted_handle_tcpip_forward (session, msg);
        }
      if (ssh_message_type (msg) == SSH_REQUEST_CHANNEL_OPEN
          && ssh_message_subtype (msg) == SSH_CHANNEL_DIRECT_TCPIP)
        {
          if (!allow_forwarding)
            {
              ssh_message_reply_default (msg);
              ssh_message_free (msg);
              continue;
            }
          const char *dst = ssh_message_channel_request_open_destination (msg);
          int dport = ssh_message_channel_request_open_destination_port (msg);
          char portbuf[32];
          snprintf (portbuf, sizeof portbuf, "%d", dport);
          rfd = connect_tcp (dst ? dst : "127.0.0.1", portbuf);
          if (rfd < 0)
            {
              ssh_message_reply_default (msg);
              ssh_message_free (msg);
              return -1;
            }
          channel = ssh_message_channel_request_open_reply_accept (msg);
          ssh_message_free (msg);
          break;
        }
      if (ssh_message_type (msg) == SSH_REQUEST_CHANNEL_OPEN
          && ssh_message_subtype (msg) == SSH_CHANNEL_SESSION)
        {
          bsshd_agent_req_state agent_req;
          struct ssh_channel_callbacks_struct channel_callbacks;
          memset (&agent_req, 0, sizeof agent_req);
          memset (&channel_callbacks, 0, sizeof channel_callbacks);
          ssh_channel sch = ssh_message_channel_request_open_reply_accept (msg);
          ssh_message_free (msg);
          if (!sch) return -1;
          if (allow_agent_forwarding)
            {
              channel_callbacks.userdata = &agent_req;
              channel_callbacks.channel_auth_agent_req_function = bsshd_agent_req_cb;
              ssh_callbacks_init (&channel_callbacks);
              ssh_set_channel_callbacks (sch, &channel_callbacks);
            }
	          char *cmd_copy = NULL;
	          int pty_rows = 24, pty_cols = 80, pty_granted = 0;
	          bsshd_sessenv_reset ();          /* fresh AcceptEnv state per session */
	          for (;;)
	            {
	              msg = ssh_message_get (session);
	              if (!msg)
	                { ssh_channel_free (sch); return -1; }
	              /* F06 item 3 slice 1: env requests — accept only AcceptEnv-allowed
	                 names (fail-closed), stash for the command child. */
	              if (ssh_message_type (msg) == SSH_REQUEST_CHANNEL
	                  && ssh_message_subtype (msg) == SSH_CHANNEL_REQUEST_ENV)
	                {
	                  const char *en = ssh_message_channel_request_env_name (msg);
	                  const char *ev = ssh_message_channel_request_env_value (msg);
	                  if (en && bsshd_acceptenv_allows (en))
	                    { bsshd_sessenv_add (en, ev); ssh_message_channel_request_reply_success (msg); }
	                  else
	                    ssh_message_reply_default (msg);
	                  ssh_message_free (msg);
	                  continue;
	                }
	              if (ssh_message_type (msg) == SSH_REQUEST_CHANNEL
	                  && ssh_message_subtype (msg) == SSH_CHANNEL_REQUEST_PTY)
	                {
                      /* F06 item 6a: PermitTTY no (global) or authz no-pty (per-key). */
                      if (!g_permit_tty || (authz && authz->no_pty))
                        {
                          ssh_message_reply_default (msg);
                          ssh_message_free (msg);
                          continue;
                        }
	                  int w = ssh_message_channel_request_pty_width (msg);
	                  int h = ssh_message_channel_request_pty_height (msg);
	                  if (w > 0) pty_cols = w;
	                  if (h > 0) pty_rows = h;
	                  pty_granted = 1;
	                  ssh_message_channel_request_reply_success (msg);
	                  ssh_message_free (msg);
	                  continue;
	                }
	              if (ssh_message_type (msg) == SSH_REQUEST_CHANNEL
	                  && ssh_message_subtype (msg) == SSH_CHANNEL_REQUEST_SHELL)
	                {
                      if (authz && authz->forced_command[0])
                        {
                          cmd_copy = strdup (authz->forced_command);
                          ssh_message_channel_request_reply_success (msg);
                          ssh_message_free (msg);
                          break;
                        }
	                  /* F06 item 6a: an interactive shell requires a PTY. If none
	                     was granted (PermitTTY no, or the client never requested
	                     one), refuse the shell — the client sees a clean
	                     request-shell failure. `exec` (a command, no tty) is
	                     unaffected. */
	                  if (!pty_granted)
	                    {
	                      ssh_message_reply_default (msg);
	                      ssh_message_free (msg);
	                      continue;
	                    }
	                  ssh_message_channel_request_reply_success (msg);
	                  ssh_message_free (msg);
	                  int rc = bsshd_encrypted_handle_shell (session, sch, target,
	                                                          pty_rows, pty_cols);
	                  ssh_channel_free (sch);
	                  (void) rc;
	                  goto bsshd_next_request;
	                }
	              if (ssh_message_type (msg) == SSH_REQUEST_CHANNEL
	                  && ssh_message_subtype (msg) == SSH_CHANNEL_REQUEST_SUBSYSTEM)
	                {
	                  const char *sub = ssh_message_channel_request_subsystem (msg);
#if BSSHD_HAVE_LIBSSH_SFTP_SERVER
	                  if (sub && strcmp (sub, "sftp") == 0)
	                    {
	                      ssh_message_channel_request_reply_success (msg);
	                      ssh_message_free (msg);
	                      int rc = bsshd_encrypted_handle_sftp (session, sch, target);
	                      ssh_channel_free (sch);
	                      (void) rc;
	                      goto bsshd_next_request;
	                    }
#endif
	                  ssh_message_reply_default (msg);
	                  ssh_message_free (msg);
	                  continue;
	                }
	              if (ssh_message_type (msg) == SSH_REQUEST_CHANNEL
	                  && ssh_message_subtype (msg) == SSH_CHANNEL_REQUEST_EXEC)
	                {
                  const char *cmd = ssh_message_channel_request_command (msg);
                  cmd_copy = strdup ((authz && authz->forced_command[0])
                                     ? authz->forced_command : (cmd ? cmd : ""));
                  ssh_message_channel_request_reply_success (msg);
                  ssh_message_free (msg);
                  break;
                }
              ssh_message_reply_default (msg);
              ssh_message_free (msg);
            }
          blob in = {0}, out = {0}, err = {0};
          char sbuf[4096];
          int idle = 0;
          while (!ssh_channel_is_eof (sch) && idle < 20)
            {
              int n = ssh_channel_read_timeout (sch, sbuf, sizeof sbuf, 0, 100);
              if (n == SSH_ERROR) break;
              if (n > 0) { blob_append (&in, sbuf, (size_t) n); idle = 0; }
              else idle++;
            }
          char inpath[64] = "";
          if (in.n) write_blob_temp (&in, inpath, sizeof inpath);
          int rc = (allow_agent_forwarding && agent_req.requested)
                   ? run_local_agent_proxy (session, cmd_copy ? cmd_copy : "",
                                            in.n ? inpath : NULL, target, 1, &out, &err)
                   : run_local (cmd_copy ? cmd_copy : "", in.n ? inpath : NULL,
                                target, &out, &err);
          bsshd_channel_write_all (sch, out.p ? out.p : "", out.n, 0);
          bsshd_channel_write_all (sch, err.p ? err.p : "", err.n, 1);
          ssh_channel_request_send_exit_status (sch, rc);
          ssh_channel_send_eof (sch);
          ssh_channel_close (sch);
          ssh_channel_free (sch);
          if (inpath[0]) unlink (inpath);
          free (cmd_copy); free (in.p); free (out.p); free (err.p);
          goto bsshd_next_request;
        }
      ssh_message_reply_default (msg);
      ssh_message_free (msg);
    bsshd_next_request:
      continue;
    }
  if (!channel)
    { if (rfd >= 0) close (rfd); return -1; }
  char buf[8192];
  int sock_eof = 0;
  for (;;)
    {
      fd_set rfds;
      FD_ZERO (&rfds);
      int sfd = ssh_get_fd (session);
      if (!sock_eof) FD_SET (rfd, &rfds);
      FD_SET (sfd, &rfds);
      int maxfd = rfd > sfd ? rfd : sfd;
      struct timeval tv;
      tv.tv_sec = 0; tv.tv_usec = 100000;
      int sel = select (maxfd + 1, &rfds, NULL, NULL, &tv);
      if (sel < 0 && errno == EINTR) continue;
      if (sel < 0) break;
      if (!sock_eof && FD_ISSET (rfd, &rfds))
        {
          ssize_t n = read (rfd, buf, sizeof buf);
          if (n <= 0)
            {
              sock_eof = 1;
              ssh_channel_send_eof (channel);
            }
          else
            bsshd_channel_write_all (channel, buf, (size_t) n, 0);
        }
      int avail = ssh_channel_poll_timeout (channel, 0, 0);
      while (avail > 0)
        {
          uint32_t chunk = (uint32_t) (avail < (int) sizeof buf ? avail : (int) sizeof buf);
          int n = ssh_channel_read (channel, buf, chunk, 0);
          if (n <= 0) break;
          write_all (rfd, buf, (size_t) n);
          avail -= n;
        }
      if (ssh_channel_is_eof (channel) || !ssh_channel_is_open (channel))
        break;
    }
  ssh_channel_close (channel);
  ssh_channel_free (channel);
  close (rfd);
  return 0;
}

static void bsshd_reload_config_if_requested (const char *config_path,
                                              const char **addr,
                                              const char **port,
                                              const char **key,
                                              int *key_explicit,
                                              int *auth_methods,
                                              int *allow_forwarding,
                                              int *allow_agent_forwarding);

static int
run_encrypted (const char *addr, const char *port, const char *key,
	       int once, long max_conn, long auth_fail_max,
	       long auth_fail_window_s, long auth_fail_cooldown_s,
	       const bsshd_target_user *target, int auth_methods,
	       int allow_forwarding, int allow_agent_forwarding,
	       const char *config_path)
{
  if (bsshd_libssh_ensure_initialized () < 0)
    { builtin_error ("encrypted: ssh_init failed"); return EXECUTION_FAILURE; }
  ssh_bind bind = ssh_bind_new ();
  if (!bind)
    { builtin_error ("encrypted: ssh_bind_new failed"); return EXECUTION_FAILURE; }
  int no = 0;
  ssh_bind_options_set (bind, SSH_BIND_OPTIONS_PROCESS_CONFIG, &no);
  if (ssh_bind_options_set (bind, SSH_BIND_OPTIONS_BINDADDR, addr) != SSH_OK ||
      ssh_bind_options_set (bind, SSH_BIND_OPTIONS_BINDPORT_STR, port) != SSH_OK ||
      ssh_bind_options_set (bind, SSH_BIND_OPTIONS_HOSTKEY, key) != SSH_OK)
    {
      builtin_error ("encrypted: bind options: %s", ssh_get_error (bind));
      ssh_bind_free (bind);
      return EXECUTION_FAILURE;
    }
  /* F06 item 2: additional configured HostKeys (the primary `key` was applied
     above; libssh keeps one per algorithm, so this stages rotation/choice). */
  for (int hk = 0; hk < g_n_hostkeys; hk++)
    if (ssh_bind_options_set (bind, SSH_BIND_OPTIONS_HOSTKEY, g_hostkeys[hk]) != SSH_OK)
      {
        builtin_error ("encrypted: HostKey %s: %s", g_hostkeys[hk], ssh_get_error (bind));
        ssh_bind_free (bind);
        return EXECUTION_FAILURE;
      }
  /* F06 item 5: apply the crypto allow-lists. A disallowed/unknown algorithm
     name makes ssh_bind_options_set fail → refuse to start (fail-closed). */
  if ((g_ssh_ciphers[0]
       && (ssh_bind_options_set (bind, SSH_BIND_OPTIONS_CIPHERS_C_S, g_ssh_ciphers) != SSH_OK
        || ssh_bind_options_set (bind, SSH_BIND_OPTIONS_CIPHERS_S_C, g_ssh_ciphers) != SSH_OK))
      || (g_ssh_macs[0]
       && (ssh_bind_options_set (bind, SSH_BIND_OPTIONS_HMAC_C_S, g_ssh_macs) != SSH_OK
        || ssh_bind_options_set (bind, SSH_BIND_OPTIONS_HMAC_S_C, g_ssh_macs) != SSH_OK))
      || (g_ssh_kex[0]
       && ssh_bind_options_set (bind, SSH_BIND_OPTIONS_KEY_EXCHANGE, g_ssh_kex) != SSH_OK))
    {
      builtin_error ("encrypted: rejected crypto allow-list (Ciphers/MACs/KexAlgorithms): %s", ssh_get_error (bind));
      ssh_bind_free (bind);
      return EXECUTION_FAILURE;
    }
  if (ssh_bind_listen (bind) != SSH_OK)
    {
      builtin_error ("encrypted: listen %s:%s: %s", addr, port, ssh_get_error (bind));
      ssh_bind_free (bind);
      return EXECUTION_FAILURE;
    }
  stop_server = 0;
  reload_server = 0;
  install_term_handlers ();
  bsshd_write_pidfile ();
  fprintf (stderr, "sshd encrypted listening addr=%s port=%s\n", addr, port);
  long served = 0;
  int lfd = ssh_bind_get_fd (bind);
  while (!stop_server)
    {
      bsshd_reap_children ();
      int key_explicit = 1;
      bsshd_reload_config_if_requested (config_path, &addr, &port, &key,
                                        &key_explicit, &auth_methods,
                                        &allow_forwarding,
                                        &allow_agent_forwarding);
      if (max_conn > 0 && served >= max_conn)
        { fprintf (stderr, "sshd: reached --max-conn limit (%ld)\n", max_conn); break; }
      struct sockaddr_storage peer;
      socklen_t peer_len = sizeof peer;
      int cfd = accept4 (lfd, (struct sockaddr *) &peer, &peer_len, SOCK_CLOEXEC);
      if (cfd < 0 && errno == EINTR) continue;
      if (cfd < 0) break;

      int slot = -1;
      char peer_ip[48] = "";
      if (auth_fail_max > 0
          && bsshd_peer_to_str (&peer, peer_ip, sizeof peer_ip) == 0)
        {
          slot = bsshd_peer_slot (peer_ip);
          time_t now = time (NULL);
          if (bsshd_peer_blocked (slot, auth_fail_max, auth_fail_window_s,
                                  auth_fail_cooldown_s, now))
            {
              close (cfd);
              served++;
              if (once) break;
              continue;
            }
        }

      struct bsshd_child_guard guard;
      bsshd_child_guard_begin (&guard);
      pid_t pid = fork ();
      if (pid < 0)
        {
          bsshd_child_guard_parent_end (&guard);
          close (cfd);
          served++;
          if (once) break;
          continue;
        }
	      if (pid == 0)
	        {
	          bsshd_child_guard_child_end (&guard);
	          bsshd_install_default_term_handlers ();
	          char sid[64], peer_label[64] = "";
          bsshd_peer_to_str (&peer, peer_label, sizeof peer_label);
          bsshd_session_record (sid, sizeof sid, "encrypted", peer_label);
          ssh_session session = ssh_new ();
          if (session && g_ssh_rekey_data > 0)
            ssh_options_set (session, SSH_OPTIONS_REKEY_DATA, &g_ssh_rekey_data);
          bsshd_target_user auth_target;
          const bsshd_target_user *session_target = target;
          bsshd_authz_options authz;
          bsshd_authz_options_clear (&authz);
          char auth_user[BC_PD_NAME_MAX] = "";
          int authed_by_password = 0;
	  int hc = -1;
          /* F06 item 6a: LoginGraceTime — bound the connect→auth window. */
          if (g_login_grace_s > 0)
            {
              signal (SIGALRM, bsshd_login_grace_alarm);
              alarm ((unsigned int) g_login_grace_s);
            }
	  if (session && ssh_bind_accept_fd (bind, session, cfd) == SSH_OK
	      && ssh_handle_key_exchange (session) == SSH_OK
	      && bsshd_encrypted_auth (session, target, auth_methods,
                                       peer_label, auth_user, sizeof auth_user,
                                       &authz, &authed_by_password) == 0)
            {
              alarm (0);   /* authed within grace; disarm the deadline */
              if ((!target || !target->enabled) && auth_user[0]
                  && bsshd_fill_target_user (auth_user, &auth_target) == 0
                  && (geteuid () == 0
                      || auth_target.user.uid != geteuid ()
                      || auth_target.user.gid != getegid ()))
                session_target = &auth_target;
              /* F06 server Match: apply per-connection overrides keyed on the
                 peer address + authed user. This is a forked per-connection
                 child, so mutating the globals / locals here is connection-local
                 and feeds the PermitRootLogin / PermitTTY / forwarding decisions
                 below (and inside the channel handler). */
              if (g_n_match > 0)
                {
                  int er = g_permit_root, et = g_permit_tty;
                  int ef = allow_forwarding, ea = allow_agent_forwarding;
                  bsshd_match_apply (peer_label, auth_user, &er, &et, &ef, &ea);
                  g_permit_root = er; g_permit_tty = et;
                  allow_forwarding = ef; allow_agent_forwarding = ea;
                }
              /* F06 item 6a: PermitRootLogin — gate a uid-0 target.
                 no → always reject; prohibit-password → reject only if the
                 session authed by password (pubkey root still permitted). */
              if (session_target && session_target->user.uid == 0
                  && (g_permit_root == 0
                      || (g_permit_root == 2 && authed_by_password)))
                {
                  fprintf (stderr, "sshd: root login refused (PermitRootLogin)\n");
                  hc = -1;
                }
              else
                hc = bsshd_encrypted_handle_direct_tcpip (session, session_target,
                                                     allow_forwarding,
                                                     allow_agent_forwarding,
                                                     &authz);
            }
          if (session)
            {
              ssh_disconnect (session);
              ssh_free (session);
            }
          close (cfd);
          bsshd_session_remove (sid);
          _exit (hc < 0 ? 1 : 0);
        }
      bsshd_child_guard_parent_end (&guard);
      close (cfd);
      served++;
      if (auth_fail_max > 0 && slot >= 0)
        bsshd_peer_clear (slot);
      if (once) break;
    }
  while (waitpid (-1, NULL, WNOHANG) > 0)
    ;
  bsshd_unlink_pidfile ();
  ssh_bind_free (bind);
  return EXECUTION_SUCCESS;
}
#endif

static char *
bsshd_trim (char *s)
{
  while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
    s++;
  char *end = s + strlen (s);
  while (end > s && (end[-1] == ' ' || end[-1] == '\t' ||
                     end[-1] == '\r' || end[-1] == '\n'))
    *--end = '\0';
  return s;
}

static int
bsshd_config_bool (const char *s, int *out)
{
  if (!s || !out)
    return -1;
  if (!strcasecmp (s, "yes") || !strcasecmp (s, "true") ||
      !strcasecmp (s, "on") || !strcmp (s, "1"))
    { *out = 1; return 0; }
  if (!strcasecmp (s, "no") || !strcasecmp (s, "false") ||
      !strcasecmp (s, "off") || !strcmp (s, "0"))
    { *out = 0; return 0; }
  return -1;
}

#define BSSHD_INCLUDE_MAX_DEPTH 16
static int
bsshd_apply_config (const char *path, const char **addr, const char **port,
                    const char **key, int *key_explicit, int *auth_methods,
                    int *allow_forwarding, int *allow_agent_forwarding, int depth)
{
  FILE *f = fopen (path, "r");
  if (!f)
    { builtin_error ("run: config %s: %s", path, strerror (errno)); return -1; }
  char line[1024];
  int lineno = 0;
  int cur_match = -1;          /* index into g_match, or -1 in the global section */
  if (depth == 0) g_n_match = 0;   /* reset (covers reload); preserve across Include recursion */
  while (fgets (line, sizeof line, f))
    {
      lineno++;
      char *hash = strchr (line, '#');
      if (hash) *hash = '\0';
      char *p = bsshd_trim (line);
      if (!*p)
        continue;
      char *keyw = p;
      while (*p && *p != ' ' && *p != '\t' && *p != '=')
        p++;
      /* F06 server Match: a `Match <criteria...>` line starts a conditional
         block. Handle it here, before the single-token value extraction below
         (criteria are multi-token, e.g. `address 10.0.0.0/24`). keyw is not yet
         NUL-terminated, so match on length: keyw spans [keyw, p). */
      if ((p - keyw) == 5 && strncasecmp (keyw, "Match", 5) == 0)
        {
          char *crit = bsshd_trim (p);
          if (g_n_match >= BSSHD_MAX_MATCH)
            { builtin_error ("run: config %s:%d: too many Match blocks", path, lineno); fclose (f); return -1; }
          cur_match = g_n_match++;
          struct bsshd_match_block *mb = &g_match[cur_match];
          memset (mb, 0, sizeof *mb);
          mb->ov_permit_root = mb->ov_permit_tty = mb->ov_allow_fwd = mb->ov_allow_agent = -1;
          char *save = NULL;
          for (char *tok = strtok_r (crit, " \t", &save); tok; tok = strtok_r (NULL, " \t", &save))
            {
              if (!strcasecmp (tok, "all")) mb->crit_all = 1;
              else if (!strcasecmp (tok, "user"))
                { char *v = strtok_r (NULL, " \t", &save);
                  if (!v) { builtin_error ("run: config %s:%d: Match user needs a pattern", path, lineno); fclose (f); return -1; }
                  snprintf (mb->crit_user, sizeof mb->crit_user, "%s", v); }
              else if (!strcasecmp (tok, "address"))
                { char *v = strtok_r (NULL, " \t", &save);
                  if (!v) { builtin_error ("run: config %s:%d: Match address needs a CIDR/IP", path, lineno); fclose (f); return -1; }
                  snprintf (mb->crit_addr, sizeof mb->crit_addr, "%s", v); }
              else
                { builtin_error ("run: config %s:%d: unsupported Match criterion: %s (want all|user|address)", path, lineno, tok); fclose (f); return -1; }
            }
          if (!mb->crit_all && !mb->crit_user[0] && !mb->crit_addr[0])
            { builtin_error ("run: config %s:%d: empty Match criteria", path, lineno); fclose (f); return -1; }
          continue;
        }
      if (*p)
        *p++ = '\0';
      p = bsshd_trim (p);
      if (*p == '=')
        p = bsshd_trim (p + 1);
      if ((*p == '"' || *p == '\'') && p[strlen (p) - 1] == *p)
        {
          char quote = *p++;
          char *end = strrchr (p, quote);
          if (end) *end = '\0';
        }
      char *value = p;
      char *end = value;
      while (*end && *end != ' ' && *end != '\t')
        end++;
      *end = '\0';
      if (!*value)
        { builtin_error ("run: config %s:%d: missing value for %s", path, lineno, keyw); fclose (f); return -1; }

      /* Inside a Match block, only the per-connection-overridable directives are
         allowed (others apply process-wide and would leak out of the block). */
      if (cur_match >= 0
          && strcasecmp (keyw, "PermitRootLogin") && strcasecmp (keyw, "AllowTcpForwarding")
          && strcasecmp (keyw, "AllowAgentForwarding") && strcasecmp (keyw, "PermitTTY"))
        { builtin_error ("run: config %s:%d: %s not allowed in a Match block (only PermitRootLogin/AllowTcpForwarding/AllowAgentForwarding/PermitTTY)", path, lineno, keyw); fclose (f); return -1; }

      if (!strcasecmp (keyw, "ListenAddress"))
        *addr = strdup (value);
      else if (!strcasecmp (keyw, "Port"))
        *port = strdup (value);
      else if (!strcasecmp (keyw, "HostKey"))
        {
          /* Accumulate for rotation/multi-algorithm; *key tracks the last for
             the -k-less resolve + lazy-gen path. */
          if (g_n_hostkeys < BSSHD_MAX_HOSTKEYS)
            snprintf (g_hostkeys[g_n_hostkeys++], sizeof g_hostkeys[0], "%s", value);
          *key = strdup (value); if (key_explicit) *key_explicit = 1;
        }
      else if (!strcasecmp (keyw, "AuthorizedKeysFile"))
        setenv ("BASHSSHD_AUTHORIZED_KEYS", value, 1);
      else if (!strcasecmp (keyw, "PasswordAuthentication"))
        {
          int yes = 0;
          if (bsshd_config_bool (value, &yes) < 0)
            { builtin_error ("run: config %s:%d: PasswordAuthentication expects yes/no", path, lineno); fclose (f); return -1; }
          if (yes) *auth_methods |= BSSHD_AUTH_PASSWORD;
          else *auth_methods &= ~BSSHD_AUTH_PASSWORD;
        }
      else if (!strcasecmp (keyw, "PubkeyAuthentication"))
        {
          int yes = 0;
          if (bsshd_config_bool (value, &yes) < 0)
            { builtin_error ("run: config %s:%d: PubkeyAuthentication expects yes/no", path, lineno); fclose (f); return -1; }
          if (yes) *auth_methods |= BSSHD_AUTH_PUBLICKEY;
          else *auth_methods &= ~BSSHD_AUTH_PUBLICKEY;
        }
      else if (!strcasecmp (keyw, "AllowTcpForwarding"))
        {
          int v;
          if (!strcasecmp (value, "yes") || !strcasecmp (value, "all") ||
              !strcasecmp (value, "local") || !strcasecmp (value, "remote"))
            v = 1;
          else if (!strcasecmp (value, "no"))
            v = 0;
          else
            { builtin_error ("run: config %s:%d: AllowTcpForwarding expects yes/no/local/remote/all", path, lineno); fclose (f); return -1; }
          if (cur_match >= 0) g_match[cur_match].ov_allow_fwd = v; else *allow_forwarding = v;
        }
      else if (!strcasecmp (keyw, "AllowAgentForwarding"))
        {
          int yes = 0;
          if (bsshd_config_bool (value, &yes) < 0)
            { builtin_error ("run: config %s:%d: AllowAgentForwarding expects yes/no", path, lineno); fclose (f); return -1; }
          if (cur_match >= 0) g_match[cur_match].ov_allow_agent = yes; else *allow_agent_forwarding = yes;
        }
      else if (!strcasecmp (keyw, "AcceptEnv"))
        {
          /* One pattern per line (the parser captures a single token); repeat
             the directive to allow several. fnmatch globs like `LC_*` work. */
          if (g_n_acceptenv >= BSSHD_MAX_ACCEPTENV)
            { builtin_error ("run: config %s:%d: too many AcceptEnv patterns", path, lineno); fclose (f); return -1; }
          snprintf (g_acceptenv[g_n_acceptenv], sizeof g_acceptenv[0], "%s", value);
          g_n_acceptenv++;
        }
      /* F06 item 5: crypto allow-lists. The value is one comma-separated token
         (no spaces), like OpenSSH's `Ciphers a,b,c`. Validation is deferred to
         ssh_bind_options_set at bind time (fail-closed there). */
      else if (!strcasecmp (keyw, "Ciphers"))
        snprintf (g_ssh_ciphers, sizeof g_ssh_ciphers, "%s", value);
      else if (!strcasecmp (keyw, "MACs"))
        snprintf (g_ssh_macs, sizeof g_ssh_macs, "%s", value);
      else if (!strcasecmp (keyw, "KexAlgorithms"))
        snprintf (g_ssh_kex, sizeof g_ssh_kex, "%s", value);
      else if (!strcasecmp (keyw, "RekeyLimit"))
        {
          /* `RekeyLimit <data>[K|M|G]` (single token; an optional time field is
             a documented follow-up — the parser captures one token). */
          char *endp = NULL;
          unsigned long long n = strtoull (value, &endp, 10);
          unsigned long long mul = 1;
          if (endp && *endp)
            { if (*endp == 'K' || *endp == 'k') mul = 1024ULL;
              else if (*endp == 'M' || *endp == 'm') mul = 1024ULL * 1024;
              else if (*endp == 'G' || *endp == 'g') mul = 1024ULL * 1024 * 1024;
              else { builtin_error ("run: config %s:%d: bad RekeyLimit: %s", path, lineno, value); fclose (f); return -1; } }
          g_ssh_rekey_data = (uint64_t) (n * mul);
        }
      /* F06 item 6a: security directives. */
      else if (!strcasecmp (keyw, "PermitRootLogin"))
        {
          int v;
          if (!strcasecmp (value, "yes")) v = 1;
          else if (!strcasecmp (value, "no")) v = 0;
          else if (!strcasecmp (value, "prohibit-password")
                   || !strcasecmp (value, "without-password")) v = 2;
          else { builtin_error ("run: config %s:%d: PermitRootLogin expects yes/no/prohibit-password", path, lineno); fclose (f); return -1; }
          if (cur_match >= 0) g_match[cur_match].ov_permit_root = v; else g_permit_root = v;
        }
      else if (!strcasecmp (keyw, "MaxAuthTries"))
        {
          char *endp = NULL;
          long n = strtol (value, &endp, 10);
          if (endp == value || *endp || n < 1)
            { builtin_error ("run: config %s:%d: MaxAuthTries expects a positive integer", path, lineno); fclose (f); return -1; }
          g_max_auth_tries = n;
        }
      else if (!strcasecmp (keyw, "LoginGraceTime"))
        {
          /* Seconds; an explicit `s` suffix is accepted (OpenSSH's m/h forms are
             a documented follow-up — the parser captures one bare token). 0 = off. */
          char *endp = NULL;
          long n = strtol (value, &endp, 10);
          if (endp == value || (*endp && strcmp (endp, "s")) || n < 0)
            { builtin_error ("run: config %s:%d: LoginGraceTime expects seconds (>=0)", path, lineno); fclose (f); return -1; }
          g_login_grace_s = n;
        }
      else if (!strcasecmp (keyw, "PermitTTY"))
        {
          int yes = 0;
          if (bsshd_config_bool (value, &yes) < 0)
            { builtin_error ("run: config %s:%d: PermitTTY expects yes/no", path, lineno); fclose (f); return -1; }
          if (cur_match >= 0) g_match[cur_match].ov_permit_tty = yes; else g_permit_tty = yes;
        }
      else if (!strcasecmp (keyw, "Banner"))
        {
          if (!strcasecmp (value, "none")) g_banner_path[0] = '\0';
          else snprintf (g_banner_path, sizeof g_banner_path, "%s", value);
        }
      else if (!strcasecmp (keyw, "Include"))
        {
          /* Include glob — recurse (depth-capped), relative to the parent dir for
             non-absolute patterns. Threads the same out-params + shared globals;
             an included file is parsed at its own top level. */
          if (depth < BSSHD_INCLUDE_MAX_DEPTH)
            {
              char dbuf[768]; snprintf (dbuf, sizeof dbuf, "%s", path);
              char *d = strrchr (dbuf, '/'); if (d) *d = '\0'; else snprintf (dbuf, sizeof dbuf, ".");
              char pat[1024];
              if (value[0] == '/') snprintf (pat, sizeof pat, "%s", value);
              else snprintf (pat, sizeof pat, "%s/%s", dbuf, value);
              glob_t g;
              if (glob (pat, GLOB_NOSORT, NULL, &g) == 0)
                for (size_t i = 0; i < g.gl_pathc; i++)
                  if (bsshd_apply_config (g.gl_pathv[i], addr, port, key, key_explicit,
                                          auth_methods, allow_forwarding, allow_agent_forwarding,
                                          depth + 1) < 0)
                    { globfree (&g); fclose (f); return -1; }
              globfree (&g);
            }
        }
      else
        { builtin_error ("run: config %s:%d: unsupported directive: %s", path, lineno, keyw); fclose (f); return -1; }
    }
  fclose (f);
  if ((*auth_methods & (BSSHD_AUTH_PUBLICKEY | BSSHD_AUTH_PASSWORD)) == 0)
    {
      builtin_error ("run: config %s: at least one auth method must remain enabled", path);
      return -1;
    }
  return 0;
}

static void
bsshd_reload_config_if_requested (const char *config_path,
                                  const char **addr, const char **port,
                                  const char **key, int *key_explicit,
                                  int *auth_methods,
                                  int *allow_forwarding,
                                  int *allow_agent_forwarding)
{
  if (!reload_server)
    return;
  reload_server = 0;
  if (!config_path || !*config_path)
    {
      fprintf (stderr, "sshd: reload requested; no config file was supplied\n");
      return;
    }
  const char *new_addr = *addr;
  const char *new_port = *port;
  const char *new_key = *key;
  int new_key_explicit = key_explicit ? *key_explicit : 0;
  int new_auth_methods = auth_methods ? *auth_methods : 0;
  int new_allow_forwarding = allow_forwarding ? *allow_forwarding : 0;
  int new_allow_agent_forwarding = allow_agent_forwarding ? *allow_agent_forwarding : 0;
  if (bsshd_apply_config (config_path, &new_addr, &new_port, &new_key,
                          &new_key_explicit, &new_auth_methods,
                          &new_allow_forwarding,
                          &new_allow_agent_forwarding, 0) < 0)
    {
      fprintf (stderr, "sshd: reload of %s failed; keeping existing settings\n",
               config_path);
      return;
    }
  if (addr) *addr = new_addr;
  if (port) *port = new_port;
  if (key) *key = new_key;
  if (key_explicit) *key_explicit = new_key_explicit;
  if (auth_methods) *auth_methods = new_auth_methods;
  if (allow_forwarding) *allow_forwarding = new_allow_forwarding;
  if (allow_agent_forwarding) *allow_agent_forwarding = new_allow_agent_forwarding;
  fprintf (stderr, "sshd: reloaded config %s\n", config_path);
}

static int run (WORD_LIST *args)
{
  /* Default host-key path is overridable via BASHSSHD_HOSTKEY in the
     environment.  Operators can still override per-invocation via -k
     (which also sets key_explicit so missing-key becomes an error
     matching OpenSSH/Dropbear refusal semantics).  The env override
     stays in the "default" treatment: a missing path triggers lazy
     auto-generation rather than refusal — see the missing-key branch
     below. */
  const char *env_default = getenv ("BASHSSHD_HOSTKEY");
  const char *addr = "127.0.0.1", *port = "22", *w;
  const char *key = (env_default && *env_default)
                    ? env_default
                    : "/etc/bash-os/ssh/host_ed25519";
  const char *target_user = NULL;
  const char *config_path = NULL;
  bsshd_target_user target;
  int once = 0, key_explicit = 0, encrypted = 0;
  int allow_forwarding = 0, allow_agent_forwarding = 0;
  int auth_methods = BSSHD_AUTH_PUBLICKEY;
  long max_conn = 0;  /* 0 = unlimited */
  /* Per-IP auth-fail accounting (default 0/0/0 = disabled). */
  long auth_fail_max = 0, auth_fail_window_s = 60, auth_fail_cooldown_s = 300;
  memset (&target, 0, sizeof target);
  while ((w = nw (&args)))
    {
      if ((!strcmp (w, "-a") || !strcmp (w, "--listen")) && args) addr = nw (&args);
      else if (!strcmp (w, "-p") && args) port = nw (&args);
      else if (!strcmp (w, "-k") && args) { key = nw (&args); key_explicit = 1; }
      else if ((!strcmp (w, "-F") || !strcmp (w, "--config")) && args)
        {
          const char *cfg = nw (&args);
          config_path = cfg;
          if (bsshd_apply_config (cfg, &addr, &port, &key, &key_explicit,
                                  &auth_methods, &allow_forwarding,
                                  &allow_agent_forwarding, 0) < 0)
            return EX_USAGE;
        }
	      else if ((!strcmp (w, "-u") || !strcmp (w, "--user")) && args) target_user = nw (&args);
	      else if (!strcmp (w, "--encrypted")) encrypted = 1;
	      else if (!strcmp (w, "--allow-forwarding")) allow_forwarding = 1;
	      else if (!strcmp (w, "--allow-agent-forwarding")) allow_agent_forwarding = 1;
	      else if (!strcmp (w, "--auth-method") && args)
	        {
	          const char *val = nw (&args);
	          if (bsshd_parse_auth_methods (val, &auth_methods) < 0)
	            { builtin_error ("run: --auth-method expects publickey,password"); return EX_USAGE; }
	        }
	      else if (!strcmp (w, "--help") || !strcmp (w, "-h"))
	        {
	          puts ("run [-a ADDR] [-p PORT] [-k HOSTKEY] [-F CONFIG] [-u USER] [--once] [--max-conn N]");
	          puts ("    [--encrypted]");
	          puts ("    [--auth-method publickey[,password]]");
	          puts ("    [--allow-forwarding] [--allow-agent-forwarding]");
	          puts ("    [--auth-fail-max N] [--auth-fail-window-sec SEC] [--auth-fail-cooldown-sec SEC]");
	          return EXECUTION_SUCCESS;
	        }
      else if (!strcmp (w, "--once")) once = 1;
      else if (!strcmp (w, "--max-conn") && args)
        {
          const char *val = nw (&args);
          char *end = NULL;
          max_conn = strtol (val, &end, 10);
          if (end == val || *end != '\0' || max_conn < 0)
            { builtin_error ("run: --max-conn requires a non-negative integer"); return EX_USAGE; }
        }
      else if (!strcmp (w, "--auth-fail-max") && args)
        {
          const char *val = nw (&args);
          char *end = NULL;
          auth_fail_max = strtol (val, &end, 10);
          if (end == val || *end != '\0' || auth_fail_max < 0)
            { builtin_error ("run: --auth-fail-max requires a non-negative integer"); return EX_USAGE; }
        }
      else if (!strcmp (w, "--auth-fail-window-sec") && args)
        {
          const char *val = nw (&args);
          char *end = NULL;
          auth_fail_window_s = strtol (val, &end, 10);
          if (end == val || *end != '\0' || auth_fail_window_s < 1)
            { builtin_error ("run: --auth-fail-window-sec requires a positive integer"); return EX_USAGE; }
        }
      else if (!strcmp (w, "--auth-fail-cooldown-sec") && args)
        {
          const char *val = nw (&args);
          char *end = NULL;
          auth_fail_cooldown_s = strtol (val, &end, 10);
          if (end == val || *end != '\0' || auth_fail_cooldown_s < 1)
            { builtin_error ("run: --auth-fail-cooldown-sec requires a positive integer"); return EX_USAGE; }
        }
      else { builtin_error ("run: unknown arg: %s", w); return EX_USAGE; }
    }
  if (target_user && target_user[0])
    {
      if (bsshd_fill_target_user (target_user, &target) < 0)
        { builtin_error ("run: user %s not found", target_user); return EXECUTION_FAILURE; }
    }
  /* OpenSSH/Dropbear refuse to start when an explicit -h/-r host key is missing.
   * Preserve that contract on the explicit-`-k` path so operator misconfig
   * is loud.  For the default path (built-in default OR BASHSSHD_HOSTKEY
   * env override), lazy auto-generate an Ed25519 host key on first start
   * so a fresh bash-os boot doesn't refuse without a manual
   * `sshd keygen` step.  Encrypted mode writes a real libssh-readable
   * key; native mode keeps the historical placeholder shape.
   * If the lazy-gen itself fails (parent directory unwritable, etc.),
   * fall back to the prior warning-and-proceed posture for the native
   * listener.  Encrypted startup will still fail when libssh cannot load a
   * host key. */
  if (key && key[0])
    {
      struct stat st;
      if (stat (key, &st) < 0)
        {
          if (key_explicit)
            { builtin_error ("host key %s: %s (run `sshd keygen -f %s` first)",
                             key, strerror (errno), key); return EXECUTION_FAILURE; }
          if ((encrypted ? bsshd_write_real_hostkey (key, "ed25519")
                         : bsshd_write_placeholder_key (key, "ed25519")) == 0)
            fprintf (stderr, "sshd: auto-generated %s host key at %s\n",
                     encrypted ? "encrypted Ed25519" : "placeholder", key);
          else
            fprintf (stderr, "sshd: warning: default host key %s missing (auto-gen failed: %s); v1 transport remains plaintext per docs/SECURITY-SSH.md\n",
                     key, strerror (errno));
        }
      else if (!S_ISREG (st.st_mode))
        { builtin_error ("host key %s: not a regular file", key); return EXECUTION_FAILURE; }
      else if (st.st_mode & (S_IRWXG | S_IRWXO))
        fprintf (stderr, "sshd: warning: host key %s mode %04o is group/other-readable (chmod 600)\n",
                 key, (unsigned) (st.st_mode & 07777));
    }
  if (encrypted)
    {
#if BSSHD_HAVE_LIBSSH_SERVER
	      return run_encrypted (addr, port, key, once, max_conn,
	                            auth_fail_max, auth_fail_window_s,
	                            auth_fail_cooldown_s,
	                            target.enabled ? &target : NULL,
	                            auth_methods,
	                            allow_forwarding,
	                            allow_agent_forwarding,
	                            config_path);
#else
      builtin_error ("run: --encrypted requires the libssh server transport, which is not compiled in");
      return EXECUTION_FAILURE;
#endif
    }
  int lfd = listen_tcp (addr, port);
  if (lfd < 0) return EXECUTION_FAILURE;
  stop_server = 0;
  reload_server = 0;
  install_term_handlers ();
  bsshd_write_pidfile ();
  fprintf (stderr, "sshd listening addr=%s port=%s\n", addr, port);
  long served = 0;
  while (!stop_server)
    {
      bsshd_reap_children ();
      bsshd_reload_config_if_requested (config_path, &addr, &port, &key,
                                        &key_explicit, &auth_methods,
                                        &allow_forwarding,
                                        &allow_agent_forwarding);
      if (max_conn > 0 && served >= max_conn)
        { fprintf (stderr, "sshd: reached --max-conn limit (%ld)\n", max_conn); break; }
      struct sockaddr_storage peer;
      socklen_t peer_len = sizeof peer;
      int cfd = accept4 (lfd, (struct sockaddr *) &peer, &peer_len, SOCK_CLOEXEC);
      if (cfd < 0 && errno == EINTR) continue;
      if (cfd < 0) break;

      /* Per-IP auth-fail rate-limit pre-handshake gate. */
      int slot = -1;
      char peer_ip[48] = "";
      if (auth_fail_max > 0
          && bsshd_peer_to_str (&peer, peer_ip, sizeof peer_ip) == 0)
        {
          slot = bsshd_peer_slot (peer_ip);
          time_t now = time (NULL);
          if (bsshd_peer_blocked (slot, auth_fail_max, auth_fail_window_s,
                                  auth_fail_cooldown_s, now))
            {
              if (!bsshd_fail_tbl[slot].blocked_logged) {
                fprintf (stderr,
                         "sshd: rate-limited peer %s after %d failed attempts "
                         "(window %lds, cooldown %lds)\n",
                         peer_ip, bsshd_fail_tbl[slot].fails,
                         auth_fail_window_s, auth_fail_cooldown_s);
                bsshd_fail_tbl[slot].blocked_logged = 1;
              }
              close (cfd);
              served++;
              if (once) break;
              continue;
            }
        }

      struct bsshd_child_guard guard;
      bsshd_child_guard_begin (&guard);
      pid_t pid = fork ();
      if (pid < 0)
        {
          bsshd_child_guard_parent_end (&guard);
          close (cfd);
          served++;
          if (once) break;
          continue;
        }
	      if (pid == 0)
	        {
	          bsshd_child_guard_child_end (&guard);
	          bsshd_install_default_term_handlers ();
	          char sid[64], peer_label[64] = "";
          bsshd_peer_to_str (&peer, peer_label, sizeof peer_label);
          bsshd_session_record (sid, sizeof sid, "native", peer_label);
          int hc = handle_client (cfd, target.enabled ? &target : NULL);
          close (cfd);
          bsshd_session_remove (sid);
          _exit (hc < 0 ? 1 : 0);
        }
      bsshd_child_guard_parent_end (&guard);
      close (cfd);
      served++;

      /* Reset/allow path: clear on success; record on handshake fail. */
      if (auth_fail_max > 0 && slot >= 0)
        bsshd_peer_clear (slot);

      if (once) break;
    }
  close (lfd);
  while (waitpid (-1, NULL, WNOHANG) > 0)
    ;
  bsshd_unlink_pidfile ();
  return EXECUTION_SUCCESS;
}

static int bsshd_read_pidfile (pid_t *pid)
{
  char path[512], buf[64];
  bsshd_pidfile_path (path, sizeof path);
  int fd = open (path, O_RDONLY);
  if (fd < 0)
    return -1;
  ssize_t n = read (fd, buf, sizeof buf - 1);
  close (fd);
  if (n <= 0)
    return -1;
  buf[n] = '\0';
  char *end = NULL;
  long v = strtol (buf, &end, 10);
  if (end == buf || v <= 0)
    return -1;
  *pid = (pid_t) v;
  return 0;
}

static int status_cmd (WORD_LIST *args)
{
  if (args && nw (&args))
    { builtin_error ("status"); return EX_USAGE; }
  pid_t pid;
  if (bsshd_read_pidfile (&pid) == 0 && kill (pid, 0) == 0)
    {
      printf ("running pid=%ld dir=%s\n", (long) pid, bsshd_runtime_dir ());
      return EXECUTION_SUCCESS;
    }
  printf ("stopped dir=%s\n", bsshd_runtime_dir ());
  return EXECUTION_FAILURE;
}

static int stop_cmd (WORD_LIST *args)
{
  if (args && nw (&args))
    { builtin_error ("stop"); return EX_USAGE; }
  pid_t pid;
  if (bsshd_read_pidfile (&pid) < 0)
    { builtin_error ("stop: no pidfile in %s", bsshd_runtime_dir ()); return EXECUTION_FAILURE; }
  if (kill (pid, SIGTERM) < 0)
    { builtin_error ("stop: pid %ld: %s", (long) pid, strerror (errno)); return EXECUTION_FAILURE; }
  return EXECUTION_SUCCESS;
}

static int reload_cmd (WORD_LIST *args)
{
  if (args && nw (&args))
    { builtin_error ("reload"); return EX_USAGE; }
  pid_t pid;
  if (bsshd_read_pidfile (&pid) < 0)
    { builtin_error ("reload: no pidfile in %s", bsshd_runtime_dir ()); return EXECUTION_FAILURE; }
  if (kill (pid, SIGHUP) < 0)
    { builtin_error ("reload: pid %ld: %s", (long) pid, strerror (errno)); return EXECUTION_FAILURE; }
  return EXECUTION_SUCCESS;
}

static int sessions_cmd (WORD_LIST *args)
{
  if (args && nw (&args))
    { builtin_error ("sessions"); return EX_USAGE; }
  char dir[512];
  snprintf (dir, sizeof dir, "%s/sessions", bsshd_runtime_dir ());
  DIR *d = opendir (dir);
  if (!d)
    return EXECUTION_SUCCESS;
  struct dirent *de;
  while ((de = readdir (d)) != NULL)
    {
      if (de->d_name[0] == '.')
        continue;
      char path[512];
      snprintf (path, sizeof path, "%s/%s", dir, de->d_name);
      FILE *f = fopen (path, "r");
      if (!f)
        continue;
      char line[256], id[80] = "", pid[40] = "", kind[40] = "", peer[80] = "", started[40] = "";
	      while (fgets (line, sizeof line, f))
	        {
	          line[strcspn (line, "\n")] = '\0';
	          if (!strncmp (line, "id=", 3)) snprintf (id, sizeof id, "%s", line + 3);
	          else if (!strncmp (line, "pid=", 4)) snprintf (pid, sizeof pid, "%s", line + 4);
          else if (!strncmp (line, "kind=", 5)) snprintf (kind, sizeof kind, "%s", line + 5);
          else if (!strncmp (line, "peer=", 5)) snprintf (peer, sizeof peer, "%s", line + 5);
          else if (!strncmp (line, "started=", 8)) snprintf (started, sizeof started, "%s", line + 8);
	        }
	      fclose (f);
	      if (pid[0])
	        {
	          char *end = NULL;
	          long v = strtol (pid, &end, 10);
	          if (end != pid && v > 0 && kill ((pid_t) v, 0) < 0 && errno == ESRCH)
	            {
	              unlink (path);
	              continue;
	            }
	        }
	      printf ("%s pid=%s kind=%s peer=%s started=%s\n",
	              id[0] ? id : de->d_name, pid, kind, peer, started);
    }
  closedir (d);
  return EXECUTION_SUCCESS;
}

static int kick_cmd (WORD_LIST *args)
{
  const char *id = nw (&args);
  if (!id || (args && nw (&args)))
    { builtin_error ("kick SESSION_ID"); return EX_USAGE; }
  char path[512];
  bsshd_session_path (id, path, sizeof path);
  FILE *f = fopen (path, "r");
  if (!f)
    { builtin_error ("kick: no such session: %s", id); return EXECUTION_FAILURE; }
  char line[256];
  pid_t pid = -1;
  while (fgets (line, sizeof line, f))
    if (!strncmp (line, "pid=", 4))
      {
        char *end = NULL;
        long v = strtol (line + 4, &end, 10);
        if (end != line + 4 && v > 0)
          pid = (pid_t) v;
        break;
      }
  fclose (f);
  if (pid <= 0)
    { builtin_error ("kick: malformed session: %s", id); return EXECUTION_FAILURE; }
  if (kill (pid, SIGTERM) < 0)
    { builtin_error ("kick: pid %ld: %s", (long) pid, strerror (errno)); return EXECUTION_FAILURE; }
  return EXECUTION_SUCCESS;
}

int sshd_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = nw (&list);
  if (!strcmp (cmd, "keygen")) return keygen (list);
  if (!strcmp (cmd, "run")) return run (list);
  if (!strcmp (cmd, "status")) return status_cmd (list);
  if (!strcmp (cmd, "stop")) return stop_cmd (list);
  if (!strcmp (cmd, "sessions")) return sessions_cmd (list);
  if (!strcmp (cmd, "kick")) return kick_cmd (list);
  if (!strcmp (cmd, "reload")) return reload_cmd (list);
  builtin_error ("unknown verb: %s", cmd);
  return EX_USAGE;
}

char *sshd_doc[] = {
  "sshd native command-stream server",
  "run [-a ADDR] [-p PORT] [-k HOSTKEY] [-F CONFIG] [-u USER] [--once] [--max-conn N]",
  "    [--encrypted]",
  "    [--auth-method publickey[,password]]",
  "    [--allow-forwarding] [--allow-agent-forwarding]",
  "    [--auth-fail-max N] [--auth-fail-window-sec SEC] [--auth-fail-cooldown-sec SEC]",
  "    -F/--config supports ListenAddress, Port, HostKey, AuthorizedKeysFile,",
  "    PasswordAuthentication, PubkeyAuthentication, AllowTcpForwarding,",
  "    and AllowAgentForwarding.",
  "status | stop | reload | sessions | kick SESSION_ID",
  "    Per-IP failed-handshake rate-limit: after N fails within SEC seconds,",
  "    refuse further connections from that IP for the cooldown. Default off.",
  "    Default host-key path: /etc/bash-os/ssh/host_ed25519, overridable",
  "    via BASHSSHD_HOSTKEY in the environment.  Missing default-path key",
  "    is lazy auto-generated on first start (mode 0600; encrypted uses Ed25519).",
  "    Missing explicit -k key still errors out per OpenSSH/Dropbear",
  "    convention; use `sshd keygen -f PATH` to pre-create.",
  NULL
};
struct builtin sshd_struct = {
  "sshd", sshd_builtin, BUILTIN_ENABLED, sshd_doc,
  "sshd <verb> [args...]", 0
};
