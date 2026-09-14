/* SPDX-License-Identifier: MIT */
/* ssh.c - Phase 3 Stage 20 native command-stream client.
 *
 * This carries three transports:
 *   - ssh:// native ssh<->sshd framed command streams
 *   - libssh:// in-process encrypted SSH sessions using vendored libssh
 *   - openssh:// external ssh(1), for encrypted OpenSSH interoperability
 *     when a real SSH client is present in the image or host environment.
 */
#include <config.h>
#if defined (HAVE_UNISTD_H)
# include <unistd.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <fnmatch.h>
#include <glob.h>
#include <time.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "loadables.h"
#if defined (__has_include)
# if __has_include ("_libssh_libssh.h")
#  include "_libssh_libssh.h"
#  include "_libssh_callbacks.h"
#  define BASHSSH_HAVE_LIBSSH 1
#  if __has_include ("_libssh_sftp.h")
#   include "_libssh_sftp.h"
#   define BASHSSH_HAVE_LIBSSH_SFTP 1
#  endif
# elif __has_include ("_libssh/libssh.h")
#  include "_libssh/libssh.h"
#  include "_libssh/callbacks.h"
#  define BASHSSH_HAVE_LIBSSH 1
#  if __has_include ("_libssh/sftp.h")
#   include "_libssh/sftp.h"
#   define BASHSSH_HAVE_LIBSSH_SFTP 1
#  endif
# endif
#endif
#ifndef BASHSSH_HAVE_LIBSSH
# define BASHSSH_HAVE_LIBSSH 0
#endif
#ifndef BASHSSH_HAVE_LIBSSH_SFTP
# define BASHSSH_HAVE_LIBSSH_SFTP 0
#endif
/* OpenSSH HashKnownHosts (|1|salt|hash) verification uses HMAC-SHA1
   over a base64-decoded salt; the project's vendored mbedTLS provides
   both. */
#include "_mbedtls_hmac_sha1.h"
#include "_mbedtls_base64.h"
#include <string.h>

typedef struct {
  char *p;
  size_t n, cap;
} blob;

typedef struct {
  int openssh;
  int libssh;
  int mux;       /* F06 ControlMaster: host[] holds the ControlPath */
  int id;
  char user[128];
  char host[256];
  char port[32];
  char key[512];
} ssh_handle;

#if BASHSSH_HAVE_LIBSSH
# define BASHSSH_MAX_LIBSSH_SESSIONS 32
typedef struct {
  int used;
  int id;
  ssh_session session;
  char user[128];
  char host[256];
  char port[32];
  char key[512];
  int forward_agent;
  char agent_sock[512];
  int agent_fd;
  ssh_channel agent_channel;
  struct ssh_callbacks_struct callbacks;
  pid_t jump_pid;   /* F06: ProxyJump tunnel pump child (0 = none) */
} libssh_slot;

static libssh_slot libssh_slots[BASHSSH_MAX_LIBSSH_SESSIONS];
static int libssh_next_id = 1;
static int libssh_initialized = 0;
static ssh_channel libssh_agent_channel_cb (ssh_session session, void *userdata);

# define BASHSSH_MAX_FORWARDS_DEFAULT 8
typedef struct {
  int used;
  int id;
  int handle_id;
  pid_t pid;
  char kind;
  char spec[512];
} bssh_forward_slot;

static bssh_forward_slot bssh_forwards[32];
static int bssh_next_forward_id = 1;
static volatile sig_atomic_t bssh_forward_stop;

/* F06 ControlMaster: framed request/response protocol spoken over the
   ControlPath AF_UNIX socket between slave invocations and the persistent
   `ssh master` daemon. One frame = 6-byte header (op, flags, u32 len in
   host order — the socket never crosses a host boundary) + len payload
   bytes. Opt-in, libssh/--encrypted only, fail-closed everywhere. */
# define BSSH_CTL_OK         1   /* generic success reply (CHECK adds pid) */
# define BSSH_CTL_ERR        2   /* failure reply; payload = diagnostic */
# define BSSH_CTL_CHECK      3   /* -O check probe */
# define BSSH_CTL_TERMINATE  4   /* -O exit: disconnect + unlink socket */
# define BSSH_CTL_EXEC       5   /* open session channel + exec payload */
# define BSSH_CTL_SHELL      6   /* PTY shell; payload "COLS ROWS TERM" */
# define BSSH_CTL_WINCH      7   /* window change; payload "COLS ROWS" */
# define BSSH_CTL_ENV        8   /* SendEnv NAME=VALUE (before CTL_EXEC) */
# define BSSH_CTL_DATA_IN    9   /* stdin bytes; len 0 = stdin EOF */
# define BSSH_CTL_DATA_OUT  10   /* stdout bytes (master -> slave) */
# define BSSH_CTL_DATA_ERR  11   /* stderr bytes (master -> slave) */
# define BSSH_CTL_EXIT      12   /* payload: u32 remote exit status */
# define BSSH_CTL_SFTP_PUT  13   /* payload "MODE_OCTAL REMOTE"; then DATA_IN */
# define BSSH_CTL_SFTP_GET  14   /* payload REMOTE; master streams DATA_OUT */

# define BSSH_CTL_MAX_PAYLOAD (256u * 1024u)
# define BSSH_MUX_MAX_CLIENTS 16
# define BSSH_MUX_MAX_ENV     16

typedef struct {
  int used;
  int fd;                       /* accepted client socket */
  ssh_channel ch;               /* per-request channel on the shared session */
  int running;                  /* exec/shell request issued on ch */
  char *env[BSSH_MUX_MAX_ENV];  /* pending SendEnv NAME=VALUE pairs */
  int env_n;
} bssh_mux_client;
#endif

struct bssh_child_guard {
  struct sigaction old_action;
  sigset_t old_mask;
};

static void bssh_child_guard_begin (struct bssh_child_guard *g)
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

static void bssh_child_guard_parent_end (struct bssh_child_guard *g)
{
  sigprocmask (SIG_SETMASK, &g->old_mask, NULL);
  sigaction (SIGCHLD, &g->old_action, NULL);
}

static void bssh_child_guard_child_end (struct bssh_child_guard *g)
{
  sigprocmask (SIG_SETMASK, &g->old_mask, NULL);
}

static const char *next_word (WORD_LIST **p)
{
  if (!p || !*p) return NULL;
  const char *w = (*p)->word->word;
  *p = (*p)->next;
  return w;
}

static int bind_or_print (const char *var, const char *val)
{
  if (var) builtin_bind_variable ((char *) var, (char *) val, 0);
  else printf ("%s\n", val);
  return EXECUTION_SUCCESS;
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

static int listen_tcp_local (const char *addr, const char *port)
{
  struct addrinfo hints, *res = NULL, *rp;
  memset (&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  int gai = getaddrinfo (addr, port, &hints, &res);
  if (gai != 0) { builtin_error ("listen %s:%s: %s", addr, port, gai_strerror (gai)); return -1; }
  int fd = -1;
  for (rp = res; rp; rp = rp->ai_next)
    {
      fd = socket (rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC, rp->ai_protocol);
      if (fd < 0) continue;
      int yes = 1;
      setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
      if (bind (fd, rp->ai_addr, rp->ai_addrlen) == 0 && listen (fd, 8) == 0) break;
      close (fd); fd = -1;
    }
  freeaddrinfo (res);
  if (fd < 0) builtin_error ("listen %s:%s: %s", addr, port, strerror (errno));
  return fd;
}

static int parse_handle (const char *h, ssh_handle *out)
{
  memset (out, 0, sizeof *out);
  const char *p = h, *scheme = "ssh://";
  if (strncmp (p, "openssh://", 10) == 0)
    { out->openssh = 1; scheme = "openssh://"; }
  else if (strncmp (p, "libssh://", 9) == 0)
    {
      out->libssh = 1;
      p += 9;
      char *end = NULL;
      long id = strtol (p, &end, 10);
      if (id <= 0 || (end && *end != '\0')) return -1;
      out->id = (int) id;
      return 0;
    }
  else if (strncmp (p, "mux://", 6) == 0)
    {
      /* F06 ControlMaster: a slave handle naming a live ControlPath socket. */
      out->mux = 1;
      p += 6;
      if (!*p || strlen (p) >= sizeof out->host) return -1;
      snprintf (out->host, sizeof out->host, "%s", p);
      return 0;
    }
  else if (strncmp (p, "ssh://", 10) == 0)
    scheme = "ssh://";
  if (strncmp (p, scheme, strlen (scheme)) == 0) p += strlen (scheme);

  char tmp[1024];
  snprintf (tmp, sizeof tmp, "%s", p);
  char *key = strchr (tmp, '|');
  if (key)
    {
      *key++ = '\0';
      snprintf (out->key, sizeof out->key, "%s", key);
    }
  p = tmp;
  const char *at = strchr (p, '@');
  if (at)
    {
      size_t un = (size_t) (at - p);
      if (un >= sizeof out->user) return -1;
      memcpy (out->user, p, un);
      out->user[un] = '\0';
      p = at + 1;
    }
  const char *colon = strrchr (p, ':');
  if (!colon) return -1;
  size_t hn = (size_t) (colon - p);
  if (hn == 0 || hn >= sizeof out->host || strlen (colon + 1) >= sizeof out->port) return -1;
  memcpy (out->host, p, hn); out->host[hn] = '\0';
  strcpy (out->port, colon + 1);
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

static int run_local (const char *cmd, const char *infile, blob *out, blob *err)
{
  int op[2], ep[2];
  if (pipe (op) < 0 || pipe (ep) < 0) return -1;
  struct bssh_child_guard guard;
  bssh_child_guard_begin (&guard);
  pid_t pid = fork ();
  if (pid < 0) { bssh_child_guard_parent_end (&guard); return -1; }
  if (pid == 0)
    {
      bssh_child_guard_child_end (&guard);
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
      execl ("/bin/bash", "bash", "-c", cmd, (char *) 0);
      execl ("/bin/sh", "sh", "-c", cmd, (char *) 0);
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
  bssh_child_guard_parent_end (&guard);
  if (w == pid && WIFEXITED (st)) return WEXITSTATUS (st);
  if (w == pid && WIFSIGNALED (st)) return 128 + WTERMSIG (st);
  return 127;
}

static int run_remote (const char *host, const char *port, const char *cmd, const char *infile, blob *out, blob *err)
{
  blob in = {0};
  if (infile && read_file_blob (infile, &in) < 0) return -1;
  int fd = connect_tcp (host, port);
  if (fd < 0) { free (in.p); return -1; }
  char hdr[256];
  int hn = snprintf (hdr, sizeof hdr, "BASHSSH1\ncmd-len %zu\nstdin-len %zu\n\n", strlen (cmd), in.n);
  if (hn < 0 || (size_t) hn >= sizeof hdr ||
      write_all (fd, hdr, (size_t) hn) < 0 ||
      write_all (fd, cmd, strlen (cmd)) < 0 ||
      write_all (fd, in.p ? in.p : "", in.n) < 0)
    { builtin_error ("write request: %s", strerror (errno)); close (fd); free (in.p); return -1; }
  free (in.p);

  char line[256];
  size_t outlen = 0, errlen = 0;
  int rc = 127;
  if (read_line_fd (fd, line, sizeof line) < 0 || strcmp (line, "BASHSSH1-RESP\n") != 0)
    { builtin_error ("bad ssh response"); close (fd); return -1; }
  while (read_line_fd (fd, line, sizeof line) == 0)
    {
      if (strcmp (line, "\n") == 0) break;
      if (sscanf (line, "rc %d", &rc) == 1) continue;
      if (sscanf (line, "stdout-len %zu", &outlen) == 1) continue;
      if (sscanf (line, "stderr-len %zu", &errlen) == 1) continue;
    }
  if (read_exact_blob (fd, out, outlen) < 0 || read_exact_blob (fd, err, errlen) < 0)
    { builtin_error ("short ssh response"); close (fd); return -1; }
  close (fd);
  return rc;
}

#if BASHSSH_HAVE_LIBSSH
static libssh_slot *libssh_find_slot (int id)
{
  for (size_t i = 0; i < BASHSSH_MAX_LIBSSH_SESSIONS; i++)
    if (libssh_slots[i].used && libssh_slots[i].id == id)
      return &libssh_slots[i];
  return NULL;
}

static int libssh_ensure_initialized (void)
{
  if (libssh_initialized)
    return 0;
  if (ssh_init () != SSH_OK)
    {
      builtin_error ("libssh: ssh_init failed");
      return -1;
    }
  libssh_initialized = 1;
  return 0;
}

static void libssh_clear_slot (libssh_slot *slot)
{
  if (!slot || !slot->used) return;
  if (slot->agent_channel)
    {
      ssh_channel_close (slot->agent_channel);
      ssh_channel_free (slot->agent_channel);
    }
  if (slot->agent_fd >= 0)
    close (slot->agent_fd);
  if (slot->session)
    {
      ssh_disconnect (slot->session);   /* closes the inner fd → pump child EOFs */
      ssh_free (slot->session);
    }
  if (slot->jump_pid > 0)
    {
      /* the pump child exits once its socketpair end EOFs; nudge + reap. */
      kill (slot->jump_pid, SIGTERM);
      waitpid (slot->jump_pid, NULL, 0);
    }
  memset (slot, 0, sizeof *slot);
  slot->agent_fd = -1;
}

static int libssh_store_session (ssh_session session, const char *user,
                                 const char *host, const char *port,
                                 const char *key, int forward_agent, pid_t jump_pid)
{
  libssh_slot *slot = NULL;
  for (size_t i = 0; i < BASHSSH_MAX_LIBSSH_SESSIONS; i++)
    if (!libssh_slots[i].used)
      { slot = &libssh_slots[i]; break; }
  if (!slot)
    {
      builtin_error ("libssh: too many open sessions");
      return -1;
    }

  slot->used = 1;
  slot->agent_fd = -1;
  slot->id = libssh_next_id++;
  if (libssh_next_id <= 0) libssh_next_id = 1;
  slot->session = session;
  snprintf (slot->user, sizeof slot->user, "%s", user ? user : "");
  snprintf (slot->host, sizeof slot->host, "%s", host ? host : "");
  snprintf (slot->port, sizeof slot->port, "%s", port ? port : "");
  snprintf (slot->key, sizeof slot->key, "%s", key ? key : "");
  slot->forward_agent = forward_agent;
  slot->jump_pid = jump_pid;
  if (forward_agent)
    {
      const char *sock = getenv ("SSH_AUTH_SOCK");
      snprintf (slot->agent_sock, sizeof slot->agent_sock, "%s", sock ? sock : "");
      memset (&slot->callbacks, 0, sizeof slot->callbacks);
      slot->callbacks.userdata = slot;
      slot->callbacks.channel_open_request_auth_agent_function = libssh_agent_channel_cb;
      ssh_callbacks_init (&slot->callbacks);
      if (ssh_set_callbacks (session, &slot->callbacks) != SSH_OK)
        {
          builtin_error ("libssh: could not install agent-forward callback: %s",
                         ssh_get_error (session));
          memset (slot, 0, sizeof *slot);
          slot->agent_fd = -1;
          return -1;
        }
    }
  return slot->id;
}

/* F06 ProxyJump: open + pubkey-auth a jump session (runs in the tunnel pump
   child). accept-new host-key TOFU honoring BASHSSH_KNOWN_HOSTS; pubkey auth via
   jkey or the agent/defaults. Returns an authed session, or NULL on any failure
   (diagnostic to stderr, since the caller is a forked child). */
static ssh_session bssh_open_jump (const char *jhost, int jport,
                                   const char *juser, const char *jkey)
{
  ssh_session js = ssh_new ();
  if (!js) return NULL;
  int batch = 1, no = 0, pubkey = SSH_PUBKEY_AUTH_ALL, strict_yes = SSH_STRICT_HOSTKEY_YES;
  bool ident_only = true;
  if (ssh_options_set (js, SSH_OPTIONS_HOST, jhost) != SSH_OK
      || ssh_options_set (js, SSH_OPTIONS_PORT, &jport) != SSH_OK
      || ssh_options_set (js, SSH_OPTIONS_BATCH_MODE, &batch) != SSH_OK
      || ssh_options_set (js, SSH_OPTIONS_PASSWORD_AUTH, &no) != SSH_OK
      || ssh_options_set (js, SSH_OPTIONS_KBDINT_AUTH, &no) != SSH_OK
      || ssh_options_set (js, SSH_OPTIONS_GSSAPI_AUTH, &no) != SSH_OK
      || ssh_options_set (js, SSH_OPTIONS_PUBKEY_AUTH, &pubkey) != SSH_OK
      || ssh_options_set (js, SSH_OPTIONS_IDENTITIES_ONLY, &ident_only) != SSH_OK)
    { ssh_free (js); return NULL; }
  if (juser && *juser) ssh_options_set (js, SSH_OPTIONS_USER, juser);
  { const char *khf = getenv ("BASHSSH_KNOWN_HOSTS");
    if (khf && *khf) { ssh_options_set (js, SSH_OPTIONS_KNOWNHOSTS, khf);
                       ssh_options_set (js, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, "/dev/null"); } }
  ssh_options_set (js, SSH_OPTIONS_STRICTHOSTKEYCHECK, &strict_yes);
  if (ssh_connect (js) != SSH_OK)
    { fprintf (stderr, "ssh: jump connect %s:%d failed: %s\n", jhost, jport, ssh_get_error (js)); ssh_free (js); return NULL; }
  enum ssh_known_hosts_e kh = ssh_session_is_known_server (js);
  if (kh == SSH_KNOWN_HOSTS_UNKNOWN || kh == SSH_KNOWN_HOSTS_NOT_FOUND)
    { if (ssh_session_update_known_hosts (js) != SSH_OK)
        { fprintf (stderr, "ssh: jump known_hosts update failed\n"); ssh_disconnect (js); ssh_free (js); return NULL; } }
  else if (kh != SSH_KNOWN_HOSTS_OK)
    { fprintf (stderr, "ssh: jump host key rejected for %s\n", jhost); ssh_disconnect (js); ssh_free (js); return NULL; }
  int rc;
  if (jkey && jkey[0])
    { ssh_key k = NULL;
      if (ssh_pki_import_privkey_file (jkey, NULL, NULL, NULL, &k) != SSH_OK)
        { fprintf (stderr, "ssh: jump identity %s unreadable\n", jkey); ssh_disconnect (js); ssh_free (js); return NULL; }
      rc = ssh_userauth_publickey (js, NULL, k); ssh_key_free (k); }
  else rc = ssh_userauth_publickey_auto (js, NULL, NULL);
  if (rc != SSH_AUTH_SUCCESS)
    { fprintf (stderr, "ssh: jump auth failed for %s: rc=%d\n", jhost, rc); ssh_disconnect (js); ssh_free (js); return NULL; }
  return js;
}

static int libssh_connect_session (const char *host, const char *port,
                                   const char *user, const char *key,
                                   int forward_agent, const char *jump)
{
  pid_t jump_pid = 0;
  if (libssh_ensure_initialized () < 0)
    return -1;

  if (key && key[0] && access (key, R_OK) < 0)
    {
      builtin_error ("libssh: identity %s: %s", key, strerror (errno));
      return -1;
    }

  ssh_session session = ssh_new ();
  if (!session)
    {
      builtin_error ("libssh: ssh_new failed");
      return -1;
    }

  int rc = SSH_ERROR;
  int port_i = atoi (port ? port : "22");
  int batch = 1;
  /* F06 item 2: StrictHostKeyChecking mode (env, default accept-new). The
     enforcement is the manual ssh_session_is_known_server branch below, not the
     libssh option (we still set the option to keep libssh's own posture sane). */
  int shkc_mode = 0;   /* 0 = accept-new, 1 = yes (strict), 2 = no */
  { const char *m = getenv ("BASHSSH_STRICT_HOST_KEY_CHECKING");
    if (m && (!strcmp (m, "yes") || !strcmp (m, "strict"))) shkc_mode = 1;
    else if (m && (!strcmp (m, "no") || !strcmp (m, "off"))) shkc_mode = 2; }
  int strict = (shkc_mode == 1) ? 1 : 0;
  int no = 0;
  int pubkey = SSH_PUBKEY_AUTH_ALL;
  bool identities_only = true;
  const char *no_agent = "/nonexistent/ssh-agent.sock";
  if (ssh_options_set (session, SSH_OPTIONS_HOST, host) != SSH_OK ||
      ssh_options_set (session, SSH_OPTIONS_PORT, &port_i) != SSH_OK ||
      ssh_options_set (session, SSH_OPTIONS_BATCH_MODE, &batch) != SSH_OK ||
      ssh_options_set (session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &strict) != SSH_OK ||
      ssh_options_set (session, SSH_OPTIONS_IDENTITIES_ONLY, &identities_only) != SSH_OK ||
      ssh_options_set (session, SSH_OPTIONS_IDENTITY_AGENT, no_agent) != SSH_OK ||
      ssh_options_set (session, SSH_OPTIONS_PASSWORD_AUTH, &no) != SSH_OK ||
      ssh_options_set (session, SSH_OPTIONS_KBDINT_AUTH, &no) != SSH_OK ||
      ssh_options_set (session, SSH_OPTIONS_GSSAPI_AUTH, &no) != SSH_OK ||
      ssh_options_set (session, SSH_OPTIONS_PUBKEY_AUTH, &pubkey) != SSH_OK)
    goto fail;
  if (user && user[0] && ssh_options_set (session, SSH_OPTIONS_USER, user) != SSH_OK)
    goto fail;

  /* F06 item 5: client crypto allow-lists from env (fail-closed — a rejected
     set aborts the connect, never silently falls back to defaults). */
  {
    const char *c = getenv ("BASHSSH_CIPHERS");
    const char *m = getenv ("BASHSSH_MACS");
    const char *k = getenv ("BASHSSH_KEX");
    const char *rk = getenv ("BASHSSH_REKEY");
    if ((c && *c && (ssh_options_set (session, SSH_OPTIONS_CIPHERS_C_S, c) != SSH_OK
                  || ssh_options_set (session, SSH_OPTIONS_CIPHERS_S_C, c) != SSH_OK))
        || (m && *m && (ssh_options_set (session, SSH_OPTIONS_HMAC_C_S, m) != SSH_OK
                     || ssh_options_set (session, SSH_OPTIONS_HMAC_S_C, m) != SSH_OK))
        || (k && *k && ssh_options_set (session, SSH_OPTIONS_KEY_EXCHANGE, k) != SSH_OK))
      {
        builtin_error ("connect: rejected crypto allow-list (BASHSSH_CIPHERS/MACS/KEX): %s",
                       ssh_get_error (session));
        goto fail;
      }
    if (rk && *rk)
      { uint64_t rd = (uint64_t) strtoull (rk, NULL, 10);
        if (rd > 0) ssh_options_set (session, SSH_OPTIONS_REKEY_DATA, &rd); }
  }

  /* F06 item 2: honor BASHSSH_KNOWN_HOSTS as the session's user known_hosts
     file — both TOFU writes (ssh_session_update_known_hosts) and verification
     (ssh_session_is_known_server) use it. Pin the global file to /dev/null so a
     system known_hosts doesn't shadow per-session trust. */
  {
    const char *khf = getenv ("BASHSSH_KNOWN_HOSTS");
    if (khf && *khf
        && (ssh_options_set (session, SSH_OPTIONS_KNOWNHOSTS, khf) != SSH_OK
         || ssh_options_set (session, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, "/dev/null") != SSH_OK))
      goto fail;
  }

  /* F06 item 2: pin libssh's internal StrictHostKeyChecking to YES so that
     ssh_session_is_known_server reports the *raw* verdict (OK / UNKNOWN /
     CHANGED / OTHER). Leaving it at the default (OFF=0) makes libssh's own
     dispatch silently downgrade a CHANGED key to OK via its "continue unsafe"
     path (knownhosts.c) and auto-TOFU unknown hosts — both of which would
     defeat the manual policy branch below. We own the policy via shkc_mode. */
  {
    int strict_yes = SSH_STRICT_HOSTKEY_YES;
    if (ssh_options_set (session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &strict_yes) != SSH_OK)
      goto fail;
  }

  /* F06 ProxyJump: tunnel this session's transport through a jump host. A pump
     child owns the jump session + a direct-tcpip channel to the target; this
     (inner) session runs over its end of a socketpair via SSH_OPTIONS_FD, so the
     normal connect/auth/exec/shell path below is unchanged. */
  if (jump && *jump)
    {
      char jspec[512]; snprintf (jspec, sizeof jspec, "%s", jump);
      char *juser = NULL, *jhost = jspec, *jat = strchr (jspec, '@');
      if (jat) { *jat = '\0'; juser = jspec; jhost = jat + 1; }
      int jport = 22; char *jcol = strrchr (jhost, ':');
      if (jcol) { *jcol = '\0'; jport = atoi (jcol + 1); }
      if (!juser || !*juser) juser = (char *) (user && *user ? user : "");
      const char *jkey = (key && key[0]) ? key : NULL;
      int tport = atoi (port ? port : "22");
      int sv[2];
      if (socketpair (AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        { builtin_error ("libssh: ProxyJump socketpair: %s", strerror (errno)); ssh_free (session); return -1; }
      pid_t pid = fork ();
      if (pid < 0)
        { builtin_error ("libssh: ProxyJump fork: %s", strerror (errno)); close (sv[0]); close (sv[1]); ssh_free (session); return -1; }
      if (pid == 0)
        {
          /* default signal disposition so the parent's close-time kill works
             (bash may have left SIGTERM/SIGINT ignored in this child). */
          signal (SIGTERM, SIG_DFL);
          signal (SIGINT, SIG_DFL);
          close (sv[0]);
          ssh_session js = bssh_open_jump (jhost, jport, juser, jkey);
          if (!js) { close (sv[1]); _exit (1); }
          ssh_channel ch = ssh_channel_new (js);
          if (!ch || ssh_channel_open_forward (ch, host, tport, "127.0.0.1", 0) != SSH_OK)
            { fprintf (stderr, "ssh: ProxyJump direct-tcpip to %s:%d failed: %s\n",
                       host, tport, ssh_get_error (js));
              if (ch)
                ssh_channel_free (ch);
              ssh_disconnect (js);
              ssh_free (js);
              close (sv[1]);
              _exit (1); }
          int local_eof = 0; char buf[8192];
          for (;;)
            {
              fd_set rf; FD_ZERO (&rf);
              int sfd = ssh_get_fd (js);
              if (!local_eof) FD_SET (sv[1], &rf);
              FD_SET (sfd, &rf);
              int maxfd = sv[1] > sfd ? sv[1] : sfd;
              struct timeval tv = { 0, 100000 };
              int sel = select (maxfd + 1, &rf, NULL, NULL, &tv);
              if (sel < 0 && errno == EINTR) continue;
              if (sel < 0) break;
              if (!local_eof && FD_ISSET (sv[1], &rf))
                {
                  ssize_t n = read (sv[1], buf, sizeof buf);
                  if (n <= 0) { local_eof = 1; ssh_channel_send_eof (ch); }
                  else { char *q = buf; size_t left = (size_t) n;
                         while (left) { int w = ssh_channel_write (ch, q, (uint32_t) left);
                           if (w == SSH_ERROR) { local_eof = 1; break; }
                           if (w == SSH_AGAIN)
                             continue;
                           q += w;
                           left -= (size_t) w; } } }
              int avail = ssh_channel_poll_timeout (ch, 0, 0);
              while (avail > 0)
                { uint32_t chunk = (uint32_t) (avail < (int) sizeof buf ? avail : (int) sizeof buf);
                  int n = ssh_channel_read (ch, buf, chunk, 0);
                  if (n <= 0)
                    break;
                  if (write_all (sv[1], buf, (size_t) n) < 0)
                    { avail = 0; break; }
                  avail -= n; }
              if (ssh_channel_is_eof (ch) || !ssh_channel_is_open (ch)) break;
            }
          ssh_channel_close (ch); ssh_channel_free (ch);
          ssh_disconnect (js); ssh_free (js); close (sv[1]); _exit (0);
        }
      close (sv[1]);
      jump_pid = pid;
      if (ssh_options_set (session, SSH_OPTIONS_FD, &sv[0]) != SSH_OK)
        { builtin_error ("libssh: ProxyJump SSH_OPTIONS_FD: %s", ssh_get_error (session));
          close (sv[0]); kill (jump_pid, SIGTERM); waitpid (jump_pid, NULL, 0);
          ssh_free (session); return -1; }
    }

  struct bssh_child_guard guard;
  bssh_child_guard_begin (&guard);
  if (ssh_connect (session) != SSH_OK)
    {
      bssh_child_guard_parent_end (&guard);
      goto fail;
    }

  /* F06 item 2: host-key trust policy per StrictHostKeyChecking mode.
       OK            → proceed (all modes)
       OTHER/ERROR   → reject (all modes)
       CHANGED       → reject, unless mode=no (then update + warn)
       UNKNOWN/NEW   → mode=yes → reject (no TOFU); else TOFU record + proceed */
  enum ssh_known_hosts_e kh = ssh_session_is_known_server (session);
  int kh_reject = 0;
  const char *kh_why = "host key rejected";
  if (kh == SSH_KNOWN_HOSTS_OTHER || kh == SSH_KNOWN_HOSTS_ERROR)
    { kh_reject = 1; kh_why = "host key error/other"; }
  else if (kh == SSH_KNOWN_HOSTS_CHANGED)
    {
      if (shkc_mode == 2)   /* no: accept the changed key (insecure) + record */
        {
          fprintf (stderr, "ssh: WARNING: host key changed for %s; accepting (StrictHostKeyChecking=no)\n", host);
          if (ssh_session_update_known_hosts (session) != SSH_OK)
            { kh_reject = 1; kh_why = "could not update changed host key"; }
        }
      else
        { kh_reject = 1; kh_why = "host key CHANGED (possible MITM)"; }
    }
  else if (kh == SSH_KNOWN_HOSTS_UNKNOWN || kh == SSH_KNOWN_HOSTS_NOT_FOUND)
    {
      if (shkc_mode == 1)   /* yes: refuse an unknown host (no TOFU) */
        { kh_reject = 1; kh_why = "unknown host key (StrictHostKeyChecking=yes)"; }
      else if (ssh_session_update_known_hosts (session) != SSH_OK)
        { kh_reject = 1; kh_why = "could not update known_hosts"; }
    }
  if (kh_reject)
    {
      bssh_child_guard_parent_end (&guard);
      builtin_error ("libssh: %s for %s: %s", kh_why, host, ssh_get_error (session));
      ssh_disconnect (session);
      ssh_free (session);
      if (jump_pid > 0) { kill (jump_pid, SIGTERM); waitpid (jump_pid, NULL, 0); }
      return -1;
    }

  if (key && key[0])
    {
      ssh_key auth_key = NULL;
      rc = ssh_pki_import_privkey_file (key, NULL, NULL, NULL, &auth_key);
      if (rc != SSH_OK)
        {
          bssh_child_guard_parent_end (&guard);
          builtin_error ("libssh: could not read identity %s: %s",
                         key, ssh_get_error (session));
          ssh_disconnect (session);
          ssh_free (session);
          if (jump_pid > 0) { kill (jump_pid, SIGTERM); waitpid (jump_pid, NULL, 0); }
          return -1;
        }
      rc = ssh_userauth_publickey (session, NULL, auth_key);
      ssh_key_free (auth_key);
    }
  else
    rc = ssh_userauth_publickey_auto (session, NULL, NULL);
  bssh_child_guard_parent_end (&guard);
  if (rc != SSH_AUTH_SUCCESS)
    {
      builtin_error ("libssh: public-key authentication failed for %s: rc=%d %s",
                     host, rc, ssh_get_error (session));
      ssh_disconnect (session);
      ssh_free (session);
      if (jump_pid > 0) { kill (jump_pid, SIGTERM); waitpid (jump_pid, NULL, 0); }
      return -1;
    }

  /* F06 item 6a parity: surface the server's pre-auth Banner on stderr (as
     OpenSSH does). Populated during userauth; NULL when no Banner is set. */
  {
    char *bnr = ssh_get_issue_banner (session);
    if (bnr)
      { fprintf (stderr, "%s", bnr); ssh_string_free_char (bnr); }
  }

  int id = libssh_store_session (session, user, host, port, key, forward_agent, jump_pid);
  if (id < 0)
    {
      ssh_disconnect (session);
      ssh_free (session);
      if (jump_pid > 0) { kill (jump_pid, SIGTERM); waitpid (jump_pid, NULL, 0); }
    }
  return id;

fail:
  builtin_error ("libssh: connect %s:%s failed: %s",
                 host, port ? port : "22", ssh_get_error (session));
  ssh_free (session);
  if (jump_pid > 0) { kill (jump_pid, SIGTERM); waitpid (jump_pid, NULL, 0); }
  return -1;
}

static int libssh_connect_unix (const char *path)
{
  int fd = socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return -1;
  struct sockaddr_un sa;
  memset (&sa, 0, sizeof sa);
  sa.sun_family = AF_UNIX;
  if (strlen (path) >= sizeof sa.sun_path)
    { close (fd); errno = ENAMETOOLONG; return -1; }
  snprintf (sa.sun_path, sizeof sa.sun_path, "%s", path);
  if (connect (fd, (struct sockaddr *) &sa, sizeof sa) < 0)
    { close (fd); return -1; }
  return fd;
}

static ssh_channel libssh_agent_channel_cb (ssh_session session, void *userdata)
{
  libssh_slot *slot = (libssh_slot *) userdata;
  if (!slot || slot->session != session || !slot->forward_agent || !slot->agent_sock[0])
    return NULL;
  if (slot->agent_channel)
    return NULL;
  int fd = libssh_connect_unix (slot->agent_sock);
  if (fd < 0)
    return NULL;
  ssh_channel ch = ssh_channel_new (session);
  if (!ch)
    { close (fd); return NULL; }
  ssh_channel_set_blocking (ch, 0);
  slot->agent_channel = ch;
  slot->agent_fd = fd;
  return ch;
}

static void libssh_agent_teardown (libssh_slot *slot)
{
  if (!slot) return;
  if (slot->agent_channel)
    {
      ssh_channel_close (slot->agent_channel);
      ssh_channel_free (slot->agent_channel);
      slot->agent_channel = NULL;
    }
  if (slot->agent_fd >= 0)
    {
      close (slot->agent_fd);
      slot->agent_fd = -1;
    }
}

static int libssh_agent_pump (libssh_slot *slot)
{
  if (!slot || !slot->agent_channel || slot->agent_fd < 0)
    return 0;
  char buf[8192];
  int sfd = ssh_get_fd (slot->session);
  if (sfd < 0)
    { libssh_agent_teardown (slot); return -1; }
  fd_set rfds;
  FD_ZERO (&rfds);
  FD_SET (slot->agent_fd, &rfds);
  FD_SET (sfd, &rfds);
  struct timeval tv;
  tv.tv_sec = 0; tv.tv_usec = 0;
  int maxfd = slot->agent_fd > sfd ? slot->agent_fd : sfd;
  int sel = select (maxfd + 1, &rfds, NULL, NULL, &tv);
  if (sel < 0 && errno != EINTR)
    { libssh_agent_teardown (slot); return -1; }
  if (sel > 0 && FD_ISSET (slot->agent_fd, &rfds))
    {
      ssize_t n = read (slot->agent_fd, buf, sizeof buf);
      if (n <= 0)
        ssh_channel_send_eof (slot->agent_channel);
      else
        {
          char *p = buf;
          size_t left = (size_t) n;
          while (left)
            {
              int w = ssh_channel_write (slot->agent_channel, p, (uint32_t) left);
              if (w == SSH_ERROR) { libssh_agent_teardown (slot); return -1; }
              if (w == SSH_AGAIN) break;
              if (w <= 0) break;
              p += w; left -= (size_t) w;
            }
        }
    }
  int avail = ssh_channel_poll_timeout (slot->agent_channel, 0, 0);
  while (avail > 0)
    {
      uint32_t chunk = (uint32_t) (avail < (int) sizeof buf ? avail : (int) sizeof buf);
      int n = ssh_channel_read (slot->agent_channel, buf, chunk, 0);
      if (n <= 0) break;
      if (write_all (slot->agent_fd, buf, (size_t) n) < 0)
        { libssh_agent_teardown (slot); return -1; }
      avail -= n;
    }
  if (ssh_channel_is_eof (slot->agent_channel) || !ssh_channel_is_open (slot->agent_channel))
    libssh_agent_teardown (slot);
  return 0;
}

static int libssh_write_file_to_channel (ssh_channel channel, const char *path)
{
  if (!path)
    {
      ssh_channel_send_eof (channel);
      return 0;
    }

  int fd = open (path, O_RDONLY);
  if (fd < 0)
    {
      builtin_error ("%s: %s", path, strerror (errno));
      return -1;
    }
  char buf[8192];
  for (;;)
    {
      ssize_t r = read (fd, buf, sizeof buf);
      if (r < 0 && errno == EINTR) continue;
      if (r < 0)
        {
          builtin_error ("read %s: %s", path, strerror (errno));
          close (fd);
          return -1;
        }
      if (r == 0) break;
      char *p = buf;
      size_t n = (size_t) r;
      while (n)
        {
          int w = ssh_channel_write (channel, p, (uint32_t) n);
          if (w == SSH_ERROR)
            {
              builtin_error ("libssh: channel write failed");
              close (fd);
              return -1;
            }
          if (w == SSH_AGAIN) continue;
          p += w;
          n -= (size_t) w;
        }
    }
  close (fd);
  ssh_channel_send_eof (channel);
  return 0;
}

/* F06 item 3 slice 1: client SendEnv. exec_cmd collects `--setenv NAME=VALUE`
   pairs here; run_libssh_exec sends each via ssh_channel_request_env before the
   exec request. Best-effort — the server's AcceptEnv allow-list may reject a
   var (channel request failure), which must not abort the exec. */
#define BASHSSH_MAX_SENDENV 32
static char *g_sendenv[BASHSSH_MAX_SENDENV];   /* "NAME=VALUE" (borrowed) */
static int g_sendenv_n = 0;

static void bashssh_send_env (ssh_channel channel)
{
  for (int i = 0; i < g_sendenv_n; i++)
    {
      const char *kv = g_sendenv[i];
      const char *eq = kv ? strchr (kv, '=') : NULL;
      if (!eq) continue;
      char name[128];
      size_t nl = (size_t) (eq - kv);
      if (nl == 0 || nl >= sizeof name) continue;
      memcpy (name, kv, nl);
      name[nl] = '\0';
      ssh_channel_request_env (channel, name, eq + 1);   /* ignore reject */
    }
}

static int run_libssh_exec (const ssh_handle *h, const char *cmd,
                            const char *infile, blob *out, blob *err)
{
  libssh_slot *slot = libssh_find_slot (h->id);
  if (!slot)
    {
      builtin_error ("libssh: unknown or closed handle: %d", h->id);
      return -1;
    }

  ssh_channel channel = ssh_channel_new (slot->session);
  if (!channel)
    {
      builtin_error ("libssh: channel allocation failed: %s",
                     ssh_get_error (slot->session));
      return -1;
    }
  if (ssh_channel_open_session (channel) != SSH_OK)
    {
      builtin_error ("libssh: channel open failed: %s",
                     ssh_get_error (slot->session));
      ssh_channel_free (channel);
      return -1;
    }
  if (slot->forward_agent && ssh_channel_request_auth_agent (channel) != SSH_OK)
    {
      builtin_error ("libssh: agent forwarding request failed: %s",
                     ssh_get_error (slot->session));
      ssh_channel_close (channel);
      ssh_channel_free (channel);
      return -1;
    }
  bashssh_send_env (channel);                 /* SendEnv (best-effort) before exec */
  if (ssh_channel_request_exec (channel, cmd) != SSH_OK)
    {
      builtin_error ("libssh: exec failed: %s", ssh_get_error (slot->session));
      ssh_channel_close (channel);
      ssh_channel_free (channel);
      return -1;
    }
  if (libssh_write_file_to_channel (channel, infile) < 0)
    {
      ssh_channel_close (channel);
      ssh_channel_free (channel);
      return -1;
    }

  char buf[8192];
  for (;;)
    {
      int progressed = 0;
      libssh_agent_pump (slot);
      int avail = ssh_channel_poll_timeout (channel, 100, 0);
      if (avail == SSH_ERROR)
        { builtin_error ("libssh: stdout poll failed"); ssh_channel_free (channel); return -1; }
      while (avail > 0)
        {
          uint32_t chunk = (uint32_t) (avail < (int) sizeof buf ? avail : (int) sizeof buf);
          int r = ssh_channel_read (channel, buf, chunk, 0);
          if (r == SSH_ERROR)
            { builtin_error ("libssh: stdout read failed"); ssh_channel_free (channel); return -1; }
          if (r <= 0) break;
          if (blob_append (out, buf, (size_t) r) < 0)
            { ssh_channel_free (channel); return -1; }
          progressed = 1;
          avail -= r;
        }

      avail = ssh_channel_poll_timeout (channel, 0, 1);
      if (avail == SSH_ERROR)
        { builtin_error ("libssh: stderr poll failed"); ssh_channel_free (channel); return -1; }
      while (avail > 0)
        {
          uint32_t chunk = (uint32_t) (avail < (int) sizeof buf ? avail : (int) sizeof buf);
          int r = ssh_channel_read (channel, buf, chunk, 1);
          if (r == SSH_ERROR)
            { builtin_error ("libssh: stderr read failed"); ssh_channel_free (channel); return -1; }
          if (r <= 0) break;
          if (blob_append (err, buf, (size_t) r) < 0)
            { ssh_channel_free (channel); return -1; }
          progressed = 1;
          avail -= r;
        }

      if (ssh_channel_is_eof (channel))
        break;
      if (!progressed && !ssh_channel_is_open (channel))
        break;
    }
  /* Wait for the server's exit-status to arrive. A single read races the
     channel close — notably with agent forwarding, where the command's agent
     round-trips delay the exit-status message and a one-shot read returns -1
     (reported as 255). Poll the session (which processes the inbound
     exit-status packet) and pump the agent until the status lands or we time
     out (~3s). The common no-agent case resolves on the first iteration. */
  int rc = ssh_channel_get_exit_status (channel);
  for (int i = 0; i < 300 && rc < 0; i++)
    {
      if (slot->agent_channel) libssh_agent_pump (slot);
      ssh_channel_poll_timeout (channel, 10, 0);   /* advance the session */
      rc = ssh_channel_get_exit_status (channel);
    }
  ssh_channel_close (channel);
  ssh_channel_free (channel);
  if (rc < 0) rc = 255;
  return rc;
}

/* F06 item 3 slice 3: interactive shell. SIGWINCH just sets a flag; the relay
   loop reads the new size and forwards it via ssh_channel_change_pty_size. */
static volatile sig_atomic_t g_bashssh_winch = 0;
static void bashssh_winch_handler (int s) { (void) s; g_bashssh_winch = 1; }

static int run_libssh_shell (const ssh_handle *h)
{
  libssh_slot *slot = libssh_find_slot (h->id);
  if (!slot) { builtin_error ("libssh: unknown or closed handle: %d", h->id); return -1; }
  ssh_channel channel = ssh_channel_new (slot->session);
  if (!channel) { builtin_error ("libssh: channel allocation failed"); return -1; }
  if (ssh_channel_open_session (channel) != SSH_OK)
    { builtin_error ("libssh: channel open failed: %s", ssh_get_error (slot->session));
      ssh_channel_free (channel); return -1; }
  if (slot->forward_agent)
    ssh_channel_request_auth_agent (channel);

  int is_tty = isatty (STDIN_FILENO);
  int cols = 80, rows = 24;
  struct winsize ws;
  if (is_tty && ioctl (STDIN_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
    { cols = ws.ws_col; rows = ws.ws_row; }
  const char *term = getenv ("TERM");
  ssh_channel_request_pty_size (channel, term && *term ? term : "xterm", cols, rows);
  if (ssh_channel_request_shell (channel) != SSH_OK)
    { builtin_error ("libssh: shell request failed: %s", ssh_get_error (slot->session));
      ssh_channel_close (channel); ssh_channel_free (channel); return -1; }

  /* local raw mode (restore on every exit path) */
  struct termios orig;
  int raw_set = 0;
  if (is_tty && tcgetattr (STDIN_FILENO, &orig) == 0)
    {
      struct termios raw = orig;
      cfmakeraw (&raw);
      if (tcsetattr (STDIN_FILENO, TCSANOW, &raw) == 0) raw_set = 1;
    }
  struct sigaction sa, oldsa;
  memset (&sa, 0, sizeof sa);
  sa.sa_handler = bashssh_winch_handler;
  sigaction (SIGWINCH, &sa, &oldsa);
  g_bashssh_winch = 0;

  char buf[8192];
  int sfd = ssh_get_fd (slot->session);
  int stdin_open = 1;
  for (;;)
    {
      if (g_bashssh_winch)
        {
          g_bashssh_winch = 0;
          if (is_tty && ioctl (STDIN_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
            ssh_channel_change_pty_size (channel, ws.ws_col, ws.ws_row);
        }
      fd_set rf;
      FD_ZERO (&rf);
      if (stdin_open) FD_SET (STDIN_FILENO, &rf);
      if (sfd >= 0) FD_SET (sfd, &rf);
      int maxfd = sfd > STDIN_FILENO ? sfd : STDIN_FILENO;
      struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
      int sel = select (maxfd + 1, &rf, NULL, NULL, &tv);
      if (sel < 0) { if (errno == EINTR) continue; break; }
      if (slot->forward_agent) libssh_agent_pump (slot);

      if (stdin_open && FD_ISSET (STDIN_FILENO, &rf))
        {
          ssize_t n = read (STDIN_FILENO, buf, sizeof buf);
          if (n > 0) ssh_channel_write (channel, buf, (uint32_t) n);
          else { ssh_channel_send_eof (channel); stdin_open = 0; }
        }
      int avail = ssh_channel_poll_timeout (channel, 0, 0);
      while (avail > 0)
        {
          uint32_t chunk = (uint32_t) (avail < (int) sizeof buf ? avail : (int) sizeof buf);
          int r = ssh_channel_read (channel, buf, chunk, 0);
          if (r <= 0) break;
          if (write (STDOUT_FILENO, buf, (size_t) r) < 0) break;
          avail -= r;
        }
      avail = ssh_channel_poll_timeout (channel, 0, 1);
      while (avail > 0)
        {
          uint32_t chunk = (uint32_t) (avail < (int) sizeof buf ? avail : (int) sizeof buf);
          int r = ssh_channel_read (channel, buf, chunk, 1);
          if (r <= 0) break;
          if (write (STDERR_FILENO, buf, (size_t) r) < 0) break;
          avail -= r;
        }
      if (ssh_channel_is_eof (channel)) break;
      if (!ssh_channel_is_open (channel)) break;
    }

  sigaction (SIGWINCH, &oldsa, NULL);
  if (raw_set) tcsetattr (STDIN_FILENO, TCSANOW, &orig);

  int rc = ssh_channel_get_exit_status (channel);
  for (int i = 0; i < 300 && rc < 0; i++)
    { if (slot->forward_agent) libssh_agent_pump (slot);
      ssh_channel_poll_timeout (channel, 10, 0);
      rc = ssh_channel_get_exit_status (channel); }
  ssh_channel_close (channel);
  ssh_channel_free (channel);
  if (rc < 0) rc = 255;
  return rc;
}

static int libssh_sftp_put (const ssh_handle *h, const char *local,
                            const char *remote, unsigned int mode)
{
#if BASHSSH_HAVE_LIBSSH_SFTP
  libssh_slot *slot = libssh_find_slot (h->id);
  if (!slot)
    {
      builtin_error ("sftp: unknown or closed handle: %d", h->id);
      return -1;
    }
  int lfd = open (local, O_RDONLY);
  if (lfd < 0)
    {
      builtin_error ("sftp put: %s: %s", local, strerror (errno));
      return -1;
    }
  sftp_session sftp = sftp_new (slot->session);
  if (!sftp)
    {
      builtin_error ("sftp: allocation failed: %s", ssh_get_error (slot->session));
      close (lfd);
      return -1;
    }
  if (sftp_init (sftp) != SSH_OK)
    {
      builtin_error ("sftp: init failed: %s", ssh_get_error (slot->session));
      sftp_free (sftp);
      close (lfd);
      return -1;
    }
  sftp_file rf = sftp_open (sftp, remote, O_WRONLY | O_CREAT | O_TRUNC, mode);
  if (!rf)
    {
      builtin_error ("sftp put: %s: %s", remote, ssh_get_error (slot->session));
      sftp_free (sftp);
      close (lfd);
      return -1;
    }
  char buf[8192];
  int rc = 0;
  for (;;)
    {
      ssize_t r = read (lfd, buf, sizeof buf);
      if (r < 0 && errno == EINTR) continue;
      if (r < 0)
        {
          builtin_error ("sftp put: read %s: %s", local, strerror (errno));
          rc = -1;
          break;
        }
      if (r == 0) break;
      char *p = buf;
      size_t n = (size_t) r;
      while (n)
        {
          ssize_t w = sftp_write (rf, p, n);
          if (w < 0)
            {
              builtin_error ("sftp put: write %s: %s", remote,
                             ssh_get_error (slot->session));
              rc = -1;
              break;
            }
          p += w;
          n -= (size_t) w;
        }
      if (rc < 0) break;
    }
  if (sftp_close (rf) != SSH_OK && rc == 0)
    {
      builtin_error ("sftp put: close %s: %s", remote, ssh_get_error (slot->session));
      rc = -1;
    }
  sftp_free (sftp);
  close (lfd);
  return rc;
#else
  (void) h; (void) local; (void) remote; (void) mode;
  builtin_error ("sftp: libssh SFTP support is not compiled in");
  return -1;
#endif
}

static int libssh_sftp_get (const ssh_handle *h, const char *remote,
                            const char *local)
{
#if BASHSSH_HAVE_LIBSSH_SFTP
  libssh_slot *slot = libssh_find_slot (h->id);
  if (!slot)
    {
      builtin_error ("sftp: unknown or closed handle: %d", h->id);
      return -1;
    }
  sftp_session sftp = sftp_new (slot->session);
  if (!sftp)
    {
      builtin_error ("sftp: allocation failed: %s", ssh_get_error (slot->session));
      return -1;
    }
  if (sftp_init (sftp) != SSH_OK)
    {
      builtin_error ("sftp: init failed: %s", ssh_get_error (slot->session));
      sftp_free (sftp);
      return -1;
    }
  sftp_file rf = sftp_open (sftp, remote, O_RDONLY, 0);
  if (!rf)
    {
      builtin_error ("sftp get: %s: %s", remote, ssh_get_error (slot->session));
      sftp_free (sftp);
      return -1;
    }
  int lfd = open (local, O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (lfd < 0)
    {
      builtin_error ("sftp get: %s: %s", local, strerror (errno));
      sftp_close (rf);
      sftp_free (sftp);
      return -1;
    }
  char buf[8192];
  int rc = 0;
  for (;;)
    {
      ssize_t r = sftp_read (rf, buf, sizeof buf);
      if (r < 0)
        {
          builtin_error ("sftp get: read %s: %s", remote,
                         ssh_get_error (slot->session));
          rc = -1;
          break;
        }
      if (r == 0) break;
      if (write_all (lfd, buf, (size_t) r) < 0)
        {
          builtin_error ("sftp get: write %s: %s", local, strerror (errno));
          rc = -1;
          break;
        }
    }
  if (close (lfd) < 0 && rc == 0)
    {
      builtin_error ("sftp get: close %s: %s", local, strerror (errno));
      rc = -1;
    }
  sftp_close (rf);
  sftp_free (sftp);
  return rc;
#else
  (void) h; (void) remote; (void) local;
  builtin_error ("sftp: libssh SFTP support is not compiled in");
  return -1;
#endif
}

static int libssh_forward_local_once (const ssh_handle *h, const char *spec)
{
  libssh_slot *slot = libssh_find_slot (h->id);
  if (!slot)
    {
      builtin_error ("forward: unknown or closed handle: %d", h->id);
      return -1;
    }
  char tmp[512];
  snprintf (tmp, sizeof tmp, "%s", spec);
  char *parts[4] = {0};
  char *p = tmp;
  for (int i = 0; i < 4; i++)
    {
      parts[i] = p;
      char *c = strchr (p, ':');
      if (i < 3)
        {
          if (!c) { builtin_error ("forward: -L expects LADDR:LPORT:RADDR:RPORT"); return -1; }
          *c = '\0';
          p = c + 1;
        }
      else if (c)
        { builtin_error ("forward: -L expects LADDR:LPORT:RADDR:RPORT"); return -1; }
    }
  int lfd = listen_tcp_local (parts[0], parts[1]);
  if (lfd < 0)
    return -1;
  fprintf (stderr, "ssh forward listening %s:%s -> %s:%s\n",
           parts[0], parts[1], parts[2], parts[3]);
  int cfd = accept4 (lfd, NULL, NULL, SOCK_CLOEXEC);
  close (lfd);
  if (cfd < 0)
    { builtin_error ("forward: accept: %s", strerror (errno)); return -1; }
  ssh_channel ch = ssh_channel_new (slot->session);
  if (!ch)
    { close (cfd); builtin_error ("forward: channel allocation failed"); return -1; }
  int rport = atoi (parts[3]);
  if (ssh_channel_open_forward (ch, parts[2], rport, parts[0], atoi (parts[1])) != SSH_OK)
    {
      builtin_error ("forward: open %s:%s: %s", parts[2], parts[3],
                     ssh_get_error (slot->session));
      ssh_channel_free (ch);
      close (cfd);
      return -1;
    }
  int local_eof = 0;
  char buf[8192];
  for (;;)
    {
      fd_set rfds;
      FD_ZERO (&rfds);
      int sfd = ssh_get_fd (slot->session);
      if (!local_eof) FD_SET (cfd, &rfds);
      FD_SET (sfd, &rfds);
      int maxfd = cfd > sfd ? cfd : sfd;
      struct timeval tv;
      tv.tv_sec = 0; tv.tv_usec = 100000;
      int sel = select (maxfd + 1, &rfds, NULL, NULL, &tv);
      if (sel < 0 && errno == EINTR) continue;
      if (sel < 0) break;
      if (!local_eof && FD_ISSET (cfd, &rfds))
        {
          ssize_t n = read (cfd, buf, sizeof buf);
          if (n <= 0)
            {
              local_eof = 1;
              ssh_channel_send_eof (ch);
            }
          else
            {
              char *q = buf;
              size_t left = (size_t) n;
              while (left)
                {
                  int w = ssh_channel_write (ch, q, (uint32_t) left);
                  if (w == SSH_ERROR) { local_eof = 1; break; }
                  if (w == SSH_AGAIN) continue;
                  q += w; left -= (size_t) w;
                }
            }
        }
      int avail = ssh_channel_poll_timeout (ch, 0, 0);
      while (avail > 0)
        {
          uint32_t chunk = (uint32_t) (avail < (int) sizeof buf ? avail : (int) sizeof buf);
          int n = ssh_channel_read (ch, buf, chunk, 0);
          if (n <= 0) break;
          write_all (cfd, buf, (size_t) n);
          avail -= n;
        }
      if (ssh_channel_is_eof (ch) || !ssh_channel_is_open (ch))
        break;
    }
  ssh_channel_close (ch);
  ssh_channel_free (ch);
  close (cfd);
  return 0;
}

static void bssh_forward_term (int sig)
{
  (void) sig;
  bssh_forward_stop = 1;
}

static int bssh_parse_forward_spec (const char *spec, char *parts[4],
                                    char *buf, size_t buflen,
                                    const char *flag)
{
  snprintf (buf, buflen, "%s", spec);
  char *p = buf;
  for (int i = 0; i < 4; i++)
    {
      parts[i] = p;
      char *c = strchr (p, ':');
      if (i < 3)
        {
          if (!c)
            {
              builtin_error ("forward: %s expects ADDR:PORT:ADDR:PORT", flag);
              return -1;
            }
          *c = '\0';
          p = c + 1;
        }
      else if (c)
        {
          builtin_error ("forward: %s expects ADDR:PORT:ADDR:PORT", flag);
          return -1;
        }
    }
  return 0;
}

static int bssh_pump_fd_channel (int fd, ssh_session session, ssh_channel ch)
{
  int local_eof = 0;
  char buf[8192];
  for (;;)
    {
      fd_set rfds;
      FD_ZERO (&rfds);
      int sfd = ssh_get_fd (session);
      if (!local_eof) FD_SET (fd, &rfds);
      FD_SET (sfd, &rfds);
      int maxfd = fd > sfd ? fd : sfd;
      struct timeval tv;
      tv.tv_sec = 0; tv.tv_usec = 100000;
      int sel = select (maxfd + 1, &rfds, NULL, NULL, &tv);
      if (sel < 0 && errno == EINTR) continue;
      if (sel < 0) break;
      if (!local_eof && FD_ISSET (fd, &rfds))
        {
          ssize_t n = read (fd, buf, sizeof buf);
          if (n <= 0)
            {
              local_eof = 1;
              ssh_channel_send_eof (ch);
            }
          else
            {
              char *q = buf;
              size_t left = (size_t) n;
              while (left)
                {
                  int w = ssh_channel_write (ch, q, (uint32_t) left);
                  if (w == SSH_ERROR) { local_eof = 1; break; }
                  if (w == SSH_AGAIN) continue;
                  q += w; left -= (size_t) w;
                }
            }
        }
      int avail = ssh_channel_poll_timeout (ch, 0, 0);
      while (avail > 0)
        {
          uint32_t chunk = (uint32_t) (avail < (int) sizeof buf ? avail : (int) sizeof buf);
          int n = ssh_channel_read (ch, buf, chunk, 0);
          if (n <= 0) break;
          write_all (fd, buf, (size_t) n);
          avail -= n;
        }
      if (ssh_channel_is_eof (ch) || !ssh_channel_is_open (ch))
        break;
    }
  return 0;
}

static int libssh_forward_remote_loop (const ssh_handle *h, const char *spec)
{
  libssh_slot *slot = libssh_find_slot (h->id);
  if (!slot)
    {
      builtin_error ("forward: unknown or closed handle: %d", h->id);
      return -1;
    }
  char tmp[512];
  char *parts[4] = {0};
  if (bssh_parse_forward_spec (spec, parts, tmp, sizeof tmp, "-R") < 0)
    return -1;
  char *end = NULL;
  long rport = strtol (parts[1], &end, 10);
  if (end == parts[1] || *end || rport < 0 || rport > 65535)
    {
      builtin_error ("forward: -R remote port must be 0..65535");
      return -1;
    }
  int bound_port = 0;
  if (ssh_channel_listen_forward (slot->session, parts[0], (int) rport,
                                  &bound_port) != SSH_OK)
    {
      builtin_error ("forward: remote listen %s:%s: %s", parts[0], parts[1],
                     ssh_get_error (slot->session));
      return -1;
    }
  fprintf (stderr, "ssh remote forward listening %s:%d -> %s:%s\n",
           parts[0], bound_port ? bound_port : (int) rport, parts[2], parts[3]);
  bssh_forward_stop = 0;
  signal (SIGTERM, bssh_forward_term);
  signal (SIGINT, bssh_forward_term);
  while (!bssh_forward_stop)
    {
      int dest_port = 0;
      ssh_channel ch = ssh_channel_accept_forward (slot->session, 100, &dest_port);
      if (!ch)
        continue;
      int lfd = connect_tcp (parts[2], parts[3]);
      if (lfd < 0)
        {
          ssh_channel_close (ch);
          ssh_channel_free (ch);
          continue;
        }
      bssh_pump_fd_channel (lfd, slot->session, ch);
      close (lfd);
      ssh_channel_close (ch);
      ssh_channel_free (ch);
    }
  ssh_channel_cancel_forward (slot->session, parts[0], (int) rport);
  return 0;
}

static void bssh_forward_reap (void)
{
  for (size_t i = 0; i < sizeof bssh_forwards / sizeof bssh_forwards[0]; i++)
    if (bssh_forwards[i].used && bssh_forwards[i].pid > 0)
      {
        int st = 0;
        pid_t r = waitpid (bssh_forwards[i].pid, &st, WNOHANG);
        if (r == bssh_forwards[i].pid || (r < 0 && errno == ECHILD))
          memset (&bssh_forwards[i], 0, sizeof bssh_forwards[i]);
      }
}

static int bssh_forward_limit (void)
{
  const char *env = getenv ("BASHSSH_MAX_FORWARDS");
  if (!env || !*env)
    return BASHSSH_MAX_FORWARDS_DEFAULT;
  char *end = NULL;
  long v = strtol (env, &end, 10);
  if (end == env || *end || v < 0 || v > (long) (sizeof bssh_forwards / sizeof bssh_forwards[0]))
    return BASHSSH_MAX_FORWARDS_DEFAULT;
  return (int) v;
}

static int bssh_forward_count_handle (int handle_id)
{
  int n = 0;
  bssh_forward_reap ();
  for (size_t i = 0; i < sizeof bssh_forwards / sizeof bssh_forwards[0]; i++)
    if (bssh_forwards[i].used && bssh_forwards[i].handle_id == handle_id)
      n++;
  return n;
}

static int bssh_forward_spawn_local (const ssh_handle *h, const char *spec)
{
  bssh_forward_reap ();
  int limit = bssh_forward_limit ();
  if (bssh_forward_count_handle (h->id) >= limit)
    {
      builtin_error ("forward: BASHSSH_MAX_FORWARDS limit reached (%d)", limit);
      return -1;
    }
  bssh_forward_slot *slot = NULL;
  for (size_t i = 0; i < sizeof bssh_forwards / sizeof bssh_forwards[0]; i++)
    if (!bssh_forwards[i].used)
      { slot = &bssh_forwards[i]; break; }
  if (!slot)
    { builtin_error ("forward: registry full"); return -1; }

  struct bssh_child_guard guard;
  bssh_child_guard_begin (&guard);
  pid_t pid = fork ();
  if (pid < 0)
    { bssh_child_guard_parent_end (&guard); builtin_error ("forward: fork: %s", strerror (errno)); return -1; }
  if (pid == 0)
    {
      bssh_child_guard_child_end (&guard);
      signal (SIGTERM, SIG_DFL);
      signal (SIGINT, SIG_DFL);
      int rc = libssh_forward_local_once (h, spec);
      _exit (rc == 0 ? 0 : 1);
    }
  bssh_child_guard_parent_end (&guard);
  slot->used = 1;
  slot->id = bssh_next_forward_id++;
  if (bssh_next_forward_id <= 0) bssh_next_forward_id = 1;
  slot->handle_id = h->id;
  slot->pid = pid;
  slot->kind = 'L';
  snprintf (slot->spec, sizeof slot->spec, "%s", spec);
  printf ("%d\n", slot->id);
  return 0;
}

static int bssh_forward_spawn_remote (const ssh_handle *h, const char *spec)
{
  bssh_forward_reap ();
  int limit = bssh_forward_limit ();
  if (bssh_forward_count_handle (h->id) >= limit)
    {
      builtin_error ("forward: BASHSSH_MAX_FORWARDS limit reached (%d)", limit);
      return -1;
    }
  bssh_forward_slot *slot = NULL;
  for (size_t i = 0; i < sizeof bssh_forwards / sizeof bssh_forwards[0]; i++)
    if (!bssh_forwards[i].used)
      { slot = &bssh_forwards[i]; break; }
  if (!slot)
    { builtin_error ("forward: registry full"); return -1; }

  struct bssh_child_guard guard;
  bssh_child_guard_begin (&guard);
  pid_t pid = fork ();
  if (pid < 0)
    { bssh_child_guard_parent_end (&guard); builtin_error ("forward: fork: %s", strerror (errno)); return -1; }
  if (pid == 0)
    {
      bssh_child_guard_child_end (&guard);
      int rc = libssh_forward_remote_loop (h, spec);
      _exit (rc == 0 ? 0 : 1);
    }
  bssh_child_guard_parent_end (&guard);
  slot->used = 1;
  slot->id = bssh_next_forward_id++;
  if (bssh_next_forward_id <= 0) bssh_next_forward_id = 1;
  slot->handle_id = h->id;
  slot->pid = pid;
  slot->kind = 'R';
  snprintf (slot->spec, sizeof slot->spec, "%s", spec);
  printf ("%d\n", slot->id);
  return 0;
}

static int bssh_forward_list (int handle_id)
{
  bssh_forward_reap ();
  for (size_t i = 0; i < sizeof bssh_forwards / sizeof bssh_forwards[0]; i++)
    if (bssh_forwards[i].used && (handle_id <= 0 || bssh_forwards[i].handle_id == handle_id))
      printf ("%d %c %d %s\n", bssh_forwards[i].id, bssh_forwards[i].kind,
              (int) bssh_forwards[i].pid, bssh_forwards[i].spec);
  return 0;
}

static int bssh_forward_cancel (int id)
{
  bssh_forward_reap ();
  for (size_t i = 0; i < sizeof bssh_forwards / sizeof bssh_forwards[0]; i++)
    if (bssh_forwards[i].used && bssh_forwards[i].id == id)
      {
        kill (bssh_forwards[i].pid, SIGTERM);
        for (int j = 0; j < 20; j++)
          {
            int st = 0;
            pid_t r = waitpid (bssh_forwards[i].pid, &st, WNOHANG);
            if (r == bssh_forwards[i].pid || (r < 0 && errno == ECHILD))
              { memset (&bssh_forwards[i], 0, sizeof bssh_forwards[i]); return 0; }
            usleep (50000);
          }
        kill (bssh_forwards[i].pid, SIGKILL);
        waitpid (bssh_forwards[i].pid, NULL, 0);
        memset (&bssh_forwards[i], 0, sizeof bssh_forwards[i]);
        return 0;
      }
  builtin_error ("forward: no active forwards");
  return -1;
}

static void bssh_forward_cancel_handle (int handle_id)
{
  for (size_t i = 0; i < sizeof bssh_forwards / sizeof bssh_forwards[0]; i++)
    if (bssh_forwards[i].used && bssh_forwards[i].handle_id == handle_id)
      bssh_forward_cancel (bssh_forwards[i].id);
}

/* ==================== F06 ControlMaster multiplexing ====================
   Cross-process transport reuse. `ssh master` authenticates one
   ssh_session, forks a detached daemon that owns it and listens on the
   ControlPath AF_UNIX socket, and serves slave requests (exec / PTY shell /
   sftp put+get) by opening one channel per request on the shared transport
   and fanning client sockets onto channels from a select() loop. Slaves
   speak the BSSH_CTL_* frame protocol defined next to the slot table.
   Everything here is opt-in, libssh/--encrypted only, and fail-closed. */

static int bssh_read_exact (int fd, void *buf, size_t n)
{
  char *p = buf;
  while (n)
    {
      ssize_t r = read (fd, p, n);
      if (r < 0 && errno == EINTR) continue;
      if (r <= 0) return -1;
      p += r; n -= (size_t) r;
    }
  return 0;
}

static int bssh_ctl_write_frame (int fd, unsigned char op, const void *payload,
                                 uint32_t len)
{
  unsigned char hdr[6];
  if (len > BSSH_CTL_MAX_PAYLOAD) return -1;
  hdr[0] = op; hdr[1] = 0;
  memcpy (hdr + 2, &len, 4);
  if (write_all (fd, hdr, sizeof hdr) < 0) return -1;
  if (len && write_all (fd, payload, len) < 0) return -1;
  return 0;
}

/* Read one frame. On success *payload is a malloc'd NUL-terminated buffer
   (NULL when len == 0). Partial-read safe; oversized frames are rejected. */
static int bssh_ctl_read_frame (int fd, unsigned char *op, char **payload,
                                uint32_t *len)
{
  unsigned char hdr[6];
  uint32_t l;
  *payload = NULL; *len = 0;
  if (bssh_read_exact (fd, hdr, sizeof hdr) < 0) return -1;
  memcpy (&l, hdr + 2, 4);
  if (l > BSSH_CTL_MAX_PAYLOAD) return -1;
  if (l)
    {
      char *p = malloc ((size_t) l + 1);
      if (!p) return -1;
      if (bssh_read_exact (fd, p, l) < 0) { free (p); return -1; }
      p[l] = '\0';
      *payload = p;
    }
  *op = hdr[0];
  *len = l;
  return 0;
}

/* ControlPath %-token expansion. The supported set is bounded to
   %% %h (host) %p (port) %r (remote user, defaulting to the local user) and
   %C (a stable hex digest over "lhost host port user"); any other token is
   rejected fail-closed, as is an empty %h/%p/%r expansion. */
static int bssh_controlpath_expand (const char *in, const char *host,
                                    const char *port, const char *user,
                                    char *out, size_t outsz)
{
  char localuser[128] = "";
  size_t o = 0;
  if (!in || !*in || !outsz) return -1;
  if (!user || !*user)
    {
      const char *lu = getenv ("USER");
      if (!lu || !*lu) lu = getenv ("LOGNAME");
      if (lu && *lu) snprintf (localuser, sizeof localuser, "%s", lu);
      user = localuser;
    }
  for (const char *p = in; *p; p++)
    {
      const char *rep = NULL;
      char cbuf[48];
      if (*p == '%')
        {
          char t = p[1];
          p++;
          if (t == '%') rep = "%";
          else if (t == 'h') rep = host ? host : "";
          else if (t == 'p') rep = port ? port : "";
          else if (t == 'r') rep = user;
          else if (t == 'C')
            {
              /* deterministic digest; OpenSSH-format parity is not claimed,
                 only stability for a given (lhost, host, port, user). */
              char lhost[256] = "";
              char seed[704];
              unsigned char tag[20];
              static const unsigned char ckey[] = "ssh-controlpath-%C";
              mbedtls_hmac_sha1_context ctx;
              gethostname (lhost, sizeof lhost - 1);
              snprintf (seed, sizeof seed, "%s%s%s%s", lhost,
                        host ? host : "", port ? port : "", user);
              mbedtls_hmac_sha1_init (&ctx);
              if (mbedtls_hmac_sha1_starts (&ctx, ckey, sizeof ckey - 1) != 0
                  || mbedtls_hmac_sha1_update (&ctx, (const unsigned char *) seed,
                                               strlen (seed)) != 0)
                { mbedtls_hmac_sha1_free (&ctx); return -1; }
              mbedtls_hmac_sha1_finish (&ctx, tag);
              mbedtls_hmac_sha1_free (&ctx);
              for (int i = 0; i < 20; i++)
                snprintf (cbuf + i * 2, 3, "%02x", tag[i]);
              rep = cbuf;
            }
          else
            return -1;                  /* unsupported token — fail closed */
          if (!*rep && t != '%')
            return -1;                  /* empty %h/%p/%r — fail closed */
          size_t rl = strlen (rep);
          if (o + rl >= outsz) return -1;
          memcpy (out + o, rep, rl);
          o += rl;
        }
      else
        {
          if (o + 1 >= outsz) return -1;
          out[o++] = *p;
        }
    }
  out[o] = '\0';
  return o ? 0 : -1;
}

/* Fail-closed ControlPath listener: refuses an over-long sun_path, a parent
   directory that is group/world-writable or owned by neither us nor root, a
   live pre-existing master socket (no clobber), and any non-socket object at
   PATH. A dead leftover socket is replaced. The socket is created 0600. */
static int libssh_listen_unix (const char *path)
{
  struct sockaddr_un sa;
  struct stat st, ps;
  char dir[sizeof sa.sun_path];
  if (strlen (path) >= sizeof sa.sun_path)
    {
      builtin_error ("master: ControlPath exceeds the socket path limit (%zu): %s",
                     sizeof sa.sun_path - 1, path);
      return -1;
    }
  snprintf (dir, sizeof dir, "%s", path);
  {
    char *slash = strrchr (dir, '/');
    if (!slash) snprintf (dir, sizeof dir, ".");
    else if (slash == dir) { dir[0] = '/'; dir[1] = '\0'; }
    else *slash = '\0';
  }
  if (stat (dir, &st) < 0 || !S_ISDIR (st.st_mode))
    {
      builtin_error ("master: ControlPath directory %s: %s", dir,
                     strerror (errno ? errno : ENOTDIR));
      return -1;
    }
  if (st.st_mode & (S_IWGRP | S_IWOTH))
    {
      builtin_error ("master: refusing group/world-writable ControlPath directory %s (mode %04o)",
                     dir, (unsigned int) (st.st_mode & 07777));
      return -1;
    }
  if (st.st_uid != geteuid () && st.st_uid != 0)
    {
      builtin_error ("master: ControlPath directory %s is not owned by uid %d or root",
                     dir, (int) geteuid ());
      return -1;
    }
  if (lstat (path, &ps) == 0)
    {
      if (!S_ISSOCK (ps.st_mode))
        {
          builtin_error ("master: refusing to clobber non-socket ControlPath %s", path);
          return -1;
        }
      int pfd = libssh_connect_unix (path);
      if (pfd >= 0)
        {
          close (pfd);
          builtin_error ("master: a live master already owns %s", path);
          return -1;
        }
      if (unlink (path) < 0)          /* dead leftover from a crash */
        {
          builtin_error ("master: cannot replace stale socket %s: %s",
                         path, strerror (errno));
          return -1;
        }
    }
  int fd = socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    { builtin_error ("master: socket: %s", strerror (errno)); return -1; }
  memset (&sa, 0, sizeof sa);
  sa.sun_family = AF_UNIX;
  snprintf (sa.sun_path, sizeof sa.sun_path, "%s", path);
  mode_t om = umask (0177);
  int brc = bind (fd, (struct sockaddr *) &sa, sizeof sa);
  umask (om);
  if (brc < 0 || listen (fd, 8) < 0)
    {
      builtin_error ("master: %s: %s", path, strerror (errno));
      close (fd);
      return -1;
    }
  return fd;
}

/* ---- master daemon: per-client state + the multiplexing event loop ---- */

static volatile sig_atomic_t bssh_master_stop;
static void bssh_master_term (int sig) { (void) sig; bssh_master_stop = 1; }

static void bssh_mux_drop (bssh_mux_client *c)
{
  if (!c->used) return;
  if (c->ch)
    {
      ssh_channel_close (c->ch);
      ssh_channel_free (c->ch);
    }
  if (c->fd >= 0) close (c->fd);
  for (int i = 0; i < c->env_n; i++) free (c->env[i]);
  memset (c, 0, sizeof *c);
  c->fd = -1;
}

/* Channel reached EOF/closed: relay the remote exit status, then drop. */
static void bssh_mux_finish (bssh_mux_client *c)
{
  int rc = ssh_channel_get_exit_status (c->ch);
  for (int i = 0; i < 100 && rc < 0; i++)
    {
      ssh_channel_poll_timeout (c->ch, 10, 0);
      rc = ssh_channel_get_exit_status (c->ch);
    }
  if (rc < 0) rc = 255;
  uint32_t st = (uint32_t) rc;
  bssh_ctl_write_frame (c->fd, BSSH_CTL_EXIT, &st, 4);
  bssh_mux_drop (c);
}

static void bssh_mux_send_err (int fd, const char *what, const char *detail)
{
  char msg[512];
  snprintf (msg, sizeof msg, "%s%s%s", what,
            detail && *detail ? ": " : "", detail && *detail ? detail : "");
  bssh_ctl_write_frame (fd, BSSH_CTL_ERR, msg, (uint32_t) strlen (msg));
}

/* Master-side SFTP PUT: payload "MODE_OCTAL REMOTE"; the client then streams
   CTL_DATA_IN frames terminated by a len-0 frame. Serialized (blocking)
   inside the master — correctness over concurrency for this slice. */
static void bssh_mux_serve_sftp_put (libssh_slot *slot, bssh_mux_client *c,
                                     const char *payload)
{
#if BASHSSH_HAVE_LIBSSH_SFTP
  unsigned int mode = 0600;
  char remote[512];
  if (sscanf (payload, "%o %511[^\n]", &mode, remote) != 2)
    { bssh_mux_send_err (c->fd, "sftp put: bad request", NULL); return; }
  sftp_session sftp = sftp_new (slot->session);
  if (!sftp || sftp_init (sftp) != SSH_OK)
    {
      bssh_mux_send_err (c->fd, "sftp init failed", ssh_get_error (slot->session));
      if (sftp) sftp_free (sftp);
      return;
    }
  sftp_file rf = sftp_open (sftp, remote, O_WRONLY | O_CREAT | O_TRUNC, mode);
  if (!rf)
    {
      bssh_mux_send_err (c->fd, "sftp put open failed", ssh_get_error (slot->session));
      sftp_free (sftp);
      return;
    }
  bssh_ctl_write_frame (c->fd, BSSH_CTL_OK, NULL, 0);
  int rc = 0;
  for (;;)
    {
      unsigned char op; char *pl; uint32_t len;
      if (bssh_ctl_read_frame (c->fd, &op, &pl, &len) < 0) { rc = 1; break; }
      if (op != BSSH_CTL_DATA_IN) { free (pl); rc = 1; break; }
      if (len == 0) { free (pl); break; }
      char *q = pl;
      size_t left = len;
      while (left)
        {
          ssize_t w = sftp_write (rf, q, left);
          if (w < 0) { rc = 1; break; }
          q += w; left -= (size_t) w;
        }
      free (pl);
      if (rc) break;
    }
  if (sftp_close (rf) != SSH_OK && rc == 0) rc = 1;
  sftp_free (sftp);
  uint32_t st = (uint32_t) rc;
  bssh_ctl_write_frame (c->fd, BSSH_CTL_EXIT, &st, 4);
#else
  (void) slot; (void) payload;
  bssh_mux_send_err (c->fd, "sftp: libssh SFTP support is not compiled in", NULL);
#endif
}

/* Master-side SFTP GET: payload REMOTE; master streams CTL_DATA_OUT frames
   and finishes with CTL_EXIT. */
static void bssh_mux_serve_sftp_get (libssh_slot *slot, bssh_mux_client *c,
                                     const char *remote)
{
#if BASHSSH_HAVE_LIBSSH_SFTP
  sftp_session sftp = sftp_new (slot->session);
  if (!sftp || sftp_init (sftp) != SSH_OK)
    {
      bssh_mux_send_err (c->fd, "sftp init failed", ssh_get_error (slot->session));
      if (sftp) sftp_free (sftp);
      return;
    }
  sftp_file rf = sftp_open (sftp, remote, O_RDONLY, 0);
  if (!rf)
    {
      bssh_mux_send_err (c->fd, "sftp get open failed", ssh_get_error (slot->session));
      sftp_free (sftp);
      return;
    }
  bssh_ctl_write_frame (c->fd, BSSH_CTL_OK, NULL, 0);
  int rc = 0;
  char buf[8192];
  for (;;)
    {
      ssize_t r = sftp_read (rf, buf, sizeof buf);
      if (r < 0) { rc = 1; break; }
      if (r == 0) break;
      if (bssh_ctl_write_frame (c->fd, BSSH_CTL_DATA_OUT, buf, (uint32_t) r) < 0)
        { rc = 1; break; }
    }
  sftp_close (rf);
  sftp_free (sftp);
  uint32_t st = (uint32_t) rc;
  bssh_ctl_write_frame (c->fd, BSSH_CTL_EXIT, &st, 4);
#else
  (void) slot; (void) remote;
  bssh_mux_send_err (c->fd, "sftp: libssh SFTP support is not compiled in", NULL);
#endif
}

/* Serve one frame from a client. Returns 0 to continue, 1 to terminate the
   master (CTL_TERMINATE), -1 to drop this client. */
static int bssh_mux_serve_frame (libssh_slot *slot, bssh_mux_client *c)
{
  unsigned char op;
  char *pl;
  uint32_t len;
  int rc = 0;
  if (bssh_ctl_read_frame (c->fd, &op, &pl, &len) < 0)
    return -1;
  switch (op)
    {
    case BSSH_CTL_CHECK:
      {
        char pid[32];
        int n = snprintf (pid, sizeof pid, "%d", (int) getpid ());
        if (bssh_ctl_write_frame (c->fd, BSSH_CTL_OK, pid, (uint32_t) n) < 0)
          rc = -1;
      }
      break;
    case BSSH_CTL_TERMINATE:
      bssh_ctl_write_frame (c->fd, BSSH_CTL_OK, NULL, 0);
      rc = 1;
      break;
    case BSSH_CTL_ENV:
      if (!c->running && pl && strchr (pl, '=') && c->env_n < BSSH_MUX_MAX_ENV)
        {
          c->env[c->env_n++] = pl;
          pl = NULL;                    /* ownership moved to the client */
        }
      break;
    case BSSH_CTL_EXEC:
    case BSSH_CTL_SHELL:
      if (c->running || !pl)
        { rc = -1; break; }
      {
        const char *why = NULL;
        ssh_channel ch = ssh_channel_new (slot->session);
        if (!ch) why = "channel allocation failed";
        else if (ssh_channel_open_session (ch) != SSH_OK)
          why = "channel open failed";
        if (!why && op == BSSH_CTL_EXEC)
          {
            for (int i = 0; i < c->env_n; i++)
              {
                char *eq = strchr (c->env[i], '=');
                if (!eq) continue;
                *eq = '\0';
                ssh_channel_request_env (ch, c->env[i], eq + 1); /* best-effort */
                *eq = '=';
              }
            if (ssh_channel_request_exec (ch, pl) != SSH_OK)
              why = "exec request failed";
          }
        else if (!why)
          {
            int cols = 80, rows = 24;
            char term[64] = "xterm";
            sscanf (pl, "%d %d %63s", &cols, &rows, term);
            ssh_channel_request_pty_size (ch, term, cols, rows);
            if (ssh_channel_request_shell (ch) != SSH_OK)
              why = "shell request failed";
          }
        if (why)
          {
            bssh_mux_send_err (c->fd, why, ssh_get_error (slot->session));
            if (ch)
              {
                ssh_channel_close (ch);
                ssh_channel_free (ch);
              }
            rc = -1;
          }
        else
          {
            c->ch = ch;
            c->running = 1;
            if (bssh_ctl_write_frame (c->fd, BSSH_CTL_OK, NULL, 0) < 0)
              rc = -1;
          }
      }
      break;
    case BSSH_CTL_WINCH:
      if (c->running && pl)
        {
          int cols = 0, rows = 0;
          if (sscanf (pl, "%d %d", &cols, &rows) == 2 && cols > 0 && rows > 0)
            ssh_channel_change_pty_size (c->ch, cols, rows);
        }
      break;
    case BSSH_CTL_DATA_IN:
      if (!c->running)
        { rc = -1; break; }
      if (len == 0)
        ssh_channel_send_eof (c->ch);
      else
        {
          char *q = pl;
          size_t left = len;
          while (left)
            {
              int w = ssh_channel_write (c->ch, q, (uint32_t) left);
              if (w == SSH_ERROR) { rc = -1; break; }
              if (w == SSH_AGAIN) continue;
              q += w; left -= (size_t) w;
            }
        }
      break;
    case BSSH_CTL_SFTP_PUT:
    case BSSH_CTL_SFTP_GET:
      if (c->running || !pl)
        { rc = -1; break; }
      if (op == BSSH_CTL_SFTP_PUT)
        bssh_mux_serve_sftp_put (slot, c, pl);
      else
        bssh_mux_serve_sftp_get (slot, c, pl);
      rc = -1;                          /* one-shot exchange; drop the client */
      break;
    default:
      rc = -1;
      break;
    }
  free (pl);
  return rc;
}

/* The master event loop: fan accepted ControlPath clients onto per-request
   channels over the one shared transport. persist < 0 = stay until -O exit /
   SIGTERM; persist == 0 = exit when the last client closes; persist > 0 =
   linger that many idle seconds. Always exits (and unlinks the socket) when
   the transport drops. */
static void bssh_master_loop (libssh_slot *slot, int lfd, long persist,
                              const char *path)
{
  bssh_mux_client cl[BSSH_MUX_MAX_CLIENTS];
  memset (cl, 0, sizeof cl);
  for (int i = 0; i < BSSH_MUX_MAX_CLIENTS; i++) cl[i].fd = -1;
  signal (SIGPIPE, SIG_IGN);
  signal (SIGTERM, bssh_master_term);
  signal (SIGINT, bssh_master_term);
  signal (SIGHUP, bssh_master_term);
  bssh_master_stop = 0;
  int had_client = 0;
  time_t idle_since = time (NULL);
  while (!bssh_master_stop)
    {
      while (waitpid (-1, NULL, WNOHANG) > 0)
        ;                               /* reap a ProxyJump pump child */
      if (!ssh_is_connected (slot->session))
        break;
      fd_set rf;
      FD_ZERO (&rf);
      FD_SET (lfd, &rf);
      int maxfd = lfd;
      int sfd = ssh_get_fd (slot->session);
      if (sfd >= 0)
        {
          FD_SET (sfd, &rf);
          if (sfd > maxfd) maxfd = sfd;
        }
      for (int i = 0; i < BSSH_MUX_MAX_CLIENTS; i++)
        if (cl[i].used)
          {
            FD_SET (cl[i].fd, &rf);
            if (cl[i].fd > maxfd) maxfd = cl[i].fd;
          }
      struct timeval tv = { 0, 200000 };
      int sel = select (maxfd + 1, &rf, NULL, NULL, &tv);
      if (sel < 0 && errno == EINTR) continue;
      if (sel < 0) break;
      if (FD_ISSET (lfd, &rf))
        {
          int cfd = accept4 (lfd, NULL, NULL, SOCK_CLOEXEC);
          if (cfd >= 0)
            {
              bssh_mux_client *c = NULL;
              for (int i = 0; i < BSSH_MUX_MAX_CLIENTS; i++)
                if (!cl[i].used) { c = &cl[i]; break; }
              if (!c)
                close (cfd);            /* full house — refuse quietly */
              else
                {
                  memset (c, 0, sizeof *c);
                  c->used = 1;
                  c->fd = cfd;
                  had_client = 1;
                }
            }
        }
      int terminate = 0;
      for (int i = 0; i < BSSH_MUX_MAX_CLIENTS; i++)
        if (cl[i].used && FD_ISSET (cl[i].fd, &rf))
          {
            int r = bssh_mux_serve_frame (slot, &cl[i]);
            if (r < 0) bssh_mux_drop (&cl[i]);
            else if (r > 0) terminate = 1;
          }
      /* pump running channels back to their clients */
      for (int i = 0; i < BSSH_MUX_MAX_CLIENTS; i++)
        {
          bssh_mux_client *c = &cl[i];
          if (!c->used || !c->running) continue;
          char buf[8192];
          int dead = 0;
          for (int is_err = 0; is_err <= 1 && !dead; is_err++)
            {
              int avail = ssh_channel_poll_timeout (c->ch, 0, is_err);
              while (avail > 0)
                {
                  uint32_t chunk = (uint32_t) (avail < (int) sizeof buf
                                               ? avail : (int) sizeof buf);
                  int n = ssh_channel_read (c->ch, buf, chunk, is_err);
                  if (n <= 0) break;
                  if (bssh_ctl_write_frame (c->fd,
                                            is_err ? BSSH_CTL_DATA_ERR
                                                   : BSSH_CTL_DATA_OUT,
                                            buf, (uint32_t) n) < 0)
                    { dead = 1; break; }
                  avail -= n;
                }
            }
          if (dead)
            { bssh_mux_drop (c); continue; }
          if (ssh_channel_is_eof (c->ch) || !ssh_channel_is_open (c->ch))
            bssh_mux_finish (c);
        }
      if (terminate)
        break;
      int nclients = 0;
      for (int i = 0; i < BSSH_MUX_MAX_CLIENTS; i++)
        if (cl[i].used) nclients++;
      time_t now = time (NULL);
      if (nclients > 0)
        idle_since = now;
      else if (persist == 0 && had_client)
        break;
      else if (persist > 0 && (long) (now - idle_since) >= persist)
        break;
    }
  unlink (path);                        /* before teardown: no stale socket */
  close (lfd);
  for (int i = 0; i < BSSH_MUX_MAX_CLIENTS; i++)
    bssh_mux_drop (&cl[i]);
  libssh_clear_slot (slot);             /* disconnect + reap jump child */
}

/* ---------------------- slave-side frame exchanges ---------------------- */

/* CTL_CHECK roundtrip. 0 = live master (pid copied out), -1 otherwise. */
static int bssh_mux_check (const char *path, char *pidbuf, size_t pidsz)
{
  unsigned char op;
  char *pl;
  uint32_t len;
  int fd = libssh_connect_unix (path);
  if (fd < 0) return -1;
  if (bssh_ctl_write_frame (fd, BSSH_CTL_CHECK, NULL, 0) < 0)
    { close (fd); return -1; }
  if (bssh_ctl_read_frame (fd, &op, &pl, &len) < 0)
    { close (fd); return -1; }
  int ok = (op == BSSH_CTL_OK);
  if (ok && pidbuf && pidsz)
    snprintf (pidbuf, pidsz, "%s", pl ? pl : "");
  free (pl);
  close (fd);
  return ok ? 0 : -1;
}

static int bssh_mux_live (const char *path)
{
  return bssh_mux_check (path, NULL, 0) == 0;
}

static int bssh_mux_terminate (const char *path)
{
  unsigned char op;
  char *pl;
  uint32_t len;
  int fd = libssh_connect_unix (path);
  if (fd < 0) return -1;
  if (bssh_ctl_write_frame (fd, BSSH_CTL_TERMINATE, NULL, 0) < 0)
    { close (fd); return -1; }
  if (bssh_ctl_read_frame (fd, &op, &pl, &len) < 0)
    { close (fd); return -1; }
  int ok = (op == BSSH_CTL_OK);
  free (pl);
  close (fd);
  return ok ? 0 : -1;
}

/* Wait for the master's CTL_OK acknowledging a request; surface CTL_ERR. */
static int bssh_mux_expect_ok (int fd, const char *what)
{
  unsigned char op;
  char *pl;
  uint32_t len;
  if (bssh_ctl_read_frame (fd, &op, &pl, &len) < 0)
    {
      builtin_error ("master: no reply for %s", what);
      return -1;
    }
  if (op != BSSH_CTL_OK)
    {
      builtin_error ("master: %s: %s", what, pl && *pl ? pl : "rejected");
      free (pl);
      return -1;
    }
  free (pl);
  return 0;
}

/* Handle one master->slave frame during exec. Returns 0 to continue, 1 when
   CTL_EXIT landed (*rc set), -1 on error. */
static int bssh_mux_out_frame (unsigned char op, const char *pl, uint32_t len,
                               blob *out, blob *err, int *rc)
{
  if (op == BSSH_CTL_DATA_OUT)
    return (len && blob_append (out, pl, len) < 0) ? -1 : 0;
  if (op == BSSH_CTL_DATA_ERR)
    return (len && blob_append (err, pl, len) < 0) ? -1 : 0;
  if (op == BSSH_CTL_EXIT)
    {
      uint32_t st = 255;
      if (len >= 4) memcpy (&st, pl, 4);
      *rc = (int) st;
      return 1;
    }
  if (op == BSSH_CTL_ERR)
    {
      builtin_error ("master: %s", pl && *pl ? pl : "remote error");
      return -1;
    }
  return -1;
}

/* exec one command through a live master at PATH. Mirrors run_libssh_exec's
   contract (returns the remote exit status, or -1). */
static int bssh_mux_exec (const char *path, const char *cmd,
                          const char *infile, blob *out, blob *err)
{
  int fd = libssh_connect_unix (path);
  if (fd < 0)
    {
      builtin_error ("exec: no ControlMaster at %s: %s", path, strerror (errno));
      return -1;
    }
  for (int i = 0; i < g_sendenv_n; i++)
    if (g_sendenv[i]
        && bssh_ctl_write_frame (fd, BSSH_CTL_ENV, g_sendenv[i],
                                 (uint32_t) strlen (g_sendenv[i])) < 0)
      {
        builtin_error ("exec: master write failed");
        close (fd);
        return -1;
      }
  if (bssh_ctl_write_frame (fd, BSSH_CTL_EXEC, cmd, (uint32_t) strlen (cmd)) < 0
      || bssh_mux_expect_ok (fd, "exec") < 0)
    { close (fd); return -1; }
  int in_fd = -1, in_eof = 1;
  if (infile)
    {
      in_fd = open (infile, O_RDONLY);
      if (in_fd < 0)
        {
          builtin_error ("%s: %s", infile, strerror (errno));
          close (fd);
          return -1;
        }
      in_eof = 0;
    }
  if (in_eof)
    bssh_ctl_write_frame (fd, BSSH_CTL_DATA_IN, NULL, 0);
  int rc = -1, done = 0, failed = 0;
  while (!done)
    {
      if (!in_eof)
        {
          /* drain whatever the master already sent so its writes can't
             back up while we are still streaming stdin */
          for (;;)
            {
              fd_set rf;
              FD_ZERO (&rf);
              FD_SET (fd, &rf);
              struct timeval tv = { 0, 0 };
              int sel = select (fd + 1, &rf, NULL, NULL, &tv);
              if (sel <= 0) break;
              unsigned char op; char *pl; uint32_t len;
              if (bssh_ctl_read_frame (fd, &op, &pl, &len) < 0)
                { failed = 1; done = 1; break; }
              int hr = bssh_mux_out_frame (op, pl, len, out, err, &rc);
              free (pl);
              if (hr) { done = 1; failed = (hr < 0); break; }
            }
          if (done) break;
          char buf[8192];
          ssize_t n = read (in_fd, buf, sizeof buf);
          if (n < 0 && errno == EINTR) continue;
          if (n > 0)
            {
              if (bssh_ctl_write_frame (fd, BSSH_CTL_DATA_IN, buf, (uint32_t) n) < 0)
                { failed = 1; break; }
            }
          else
            {
              in_eof = 1;
              if (bssh_ctl_write_frame (fd, BSSH_CTL_DATA_IN, NULL, 0) < 0)
                { failed = 1; break; }
            }
        }
      else
        {
          unsigned char op; char *pl; uint32_t len;
          if (bssh_ctl_read_frame (fd, &op, &pl, &len) < 0)
            {
              builtin_error ("exec: master connection lost");
              failed = 1;
              break;
            }
          int hr = bssh_mux_out_frame (op, pl, len, out, err, &rc);
          free (pl);
          if (hr) { done = 1; failed = (hr < 0); }
        }
    }
  if (in_fd >= 0) close (in_fd);
  close (fd);
  return failed ? -1 : rc;
}

/* Interactive PTY shell through a live master (run_libssh_shell parity). */
static int bssh_mux_shell (const char *path)
{
  int fd = libssh_connect_unix (path);
  if (fd < 0)
    {
      builtin_error ("shell: no ControlMaster at %s: %s", path, strerror (errno));
      return -1;
    }
  int is_tty = isatty (STDIN_FILENO);
  int cols = 80, rows = 24;
  struct winsize ws;
  if (is_tty && ioctl (STDIN_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
    { cols = ws.ws_col; rows = ws.ws_row; }
  const char *term = getenv ("TERM");
  char req[128];
  int n = snprintf (req, sizeof req, "%d %d %s", cols, rows,
                    term && *term ? term : "xterm");
  if (n < 0 || n >= (int) sizeof req
      || bssh_ctl_write_frame (fd, BSSH_CTL_SHELL, req, (uint32_t) n) < 0
      || bssh_mux_expect_ok (fd, "shell") < 0)
    { close (fd); return -1; }

  struct termios orig;
  int raw_set = 0;
  if (is_tty && tcgetattr (STDIN_FILENO, &orig) == 0)
    {
      struct termios raw = orig;
      cfmakeraw (&raw);
      if (tcsetattr (STDIN_FILENO, TCSANOW, &raw) == 0) raw_set = 1;
    }
  struct sigaction sa, oldsa;
  memset (&sa, 0, sizeof sa);
  sa.sa_handler = bashssh_winch_handler;
  sigaction (SIGWINCH, &sa, &oldsa);
  g_bashssh_winch = 0;

  int stdin_open = 1, rc = -1;
  char buf[8192];
  for (;;)
    {
      if (g_bashssh_winch)
        {
          g_bashssh_winch = 0;
          if (is_tty && ioctl (STDIN_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
            {
              char wreq[48];
              int wn = snprintf (wreq, sizeof wreq, "%d %d", ws.ws_col, ws.ws_row);
              if (wn > 0)
                bssh_ctl_write_frame (fd, BSSH_CTL_WINCH, wreq, (uint32_t) wn);
            }
        }
      fd_set rf;
      FD_ZERO (&rf);
      if (stdin_open) FD_SET (STDIN_FILENO, &rf);
      FD_SET (fd, &rf);
      int maxfd = fd > STDIN_FILENO ? fd : STDIN_FILENO;
      struct timeval tv = { 0, 100000 };
      int sel = select (maxfd + 1, &rf, NULL, NULL, &tv);
      if (sel < 0) { if (errno == EINTR) continue; break; }
      if (stdin_open && FD_ISSET (STDIN_FILENO, &rf))
        {
          ssize_t r = read (STDIN_FILENO, buf, sizeof buf);
          if (r > 0)
            {
              if (bssh_ctl_write_frame (fd, BSSH_CTL_DATA_IN, buf, (uint32_t) r) < 0)
                break;
            }
          else
            {
              bssh_ctl_write_frame (fd, BSSH_CTL_DATA_IN, NULL, 0);
              stdin_open = 0;
            }
        }
      if (FD_ISSET (fd, &rf))
        {
          unsigned char op; char *pl; uint32_t len;
          if (bssh_ctl_read_frame (fd, &op, &pl, &len) < 0)
            break;
          if (op == BSSH_CTL_DATA_OUT && len)
            write_all (STDOUT_FILENO, pl, len);
          else if (op == BSSH_CTL_DATA_ERR && len)
            write_all (STDERR_FILENO, pl, len);
          else if (op == BSSH_CTL_EXIT)
            {
              uint32_t st = 255;
              if (len >= 4) memcpy (&st, pl, 4);
              rc = (int) st;
              free (pl);
              break;
            }
          free (pl);
        }
    }
  sigaction (SIGWINCH, &oldsa, NULL);
  if (raw_set) tcsetattr (STDIN_FILENO, TCSANOW, &orig);
  close (fd);
  return rc;
}

/* SFTP put/get through a live master (libssh_sftp_put/get parity). */
static int bssh_mux_sftp_put (const char *path, const char *local,
                              const char *remote, unsigned int mode)
{
  int lfd = open (local, O_RDONLY);
  if (lfd < 0)
    {
      builtin_error ("sftp put: %s: %s", local, strerror (errno));
      return -1;
    }
  int fd = libssh_connect_unix (path);
  if (fd < 0)
    {
      builtin_error ("sftp: no ControlMaster at %s: %s", path, strerror (errno));
      close (lfd);
      return -1;
    }
  char req[600];
  int n = snprintf (req, sizeof req, "%o %s", mode, remote);
  if (n < 0 || n >= (int) sizeof req
      || bssh_ctl_write_frame (fd, BSSH_CTL_SFTP_PUT, req, (uint32_t) n) < 0
      || bssh_mux_expect_ok (fd, "sftp put") < 0)
    { close (fd); close (lfd); return -1; }
  int rc = 0;
  char buf[8192];
  for (;;)
    {
      ssize_t r = read (lfd, buf, sizeof buf);
      if (r < 0 && errno == EINTR) continue;
      if (r < 0)
        {
          builtin_error ("sftp put: read %s: %s", local, strerror (errno));
          rc = -1;
          break;
        }
      if (r == 0) break;
      if (bssh_ctl_write_frame (fd, BSSH_CTL_DATA_IN, buf, (uint32_t) r) < 0)
        { rc = -1; break; }
    }
  close (lfd);
  if (rc == 0 && bssh_ctl_write_frame (fd, BSSH_CTL_DATA_IN, NULL, 0) < 0)
    rc = -1;
  if (rc == 0)
    {
      unsigned char op; char *pl; uint32_t len;
      if (bssh_ctl_read_frame (fd, &op, &pl, &len) < 0)
        rc = -1;
      else
        {
          uint32_t st = 1;
          if (op == BSSH_CTL_EXIT && len >= 4) memcpy (&st, pl, 4);
          else if (op == BSSH_CTL_ERR)
            builtin_error ("master: %s", pl && *pl ? pl : "sftp put failed");
          rc = (op == BSSH_CTL_EXIT && st == 0) ? 0 : -1;
          free (pl);
        }
    }
  close (fd);
  return rc;
}

static int bssh_mux_sftp_get (const char *path, const char *remote,
                              const char *local)
{
  int fd = libssh_connect_unix (path);
  if (fd < 0)
    {
      builtin_error ("sftp: no ControlMaster at %s: %s", path, strerror (errno));
      return -1;
    }
  if (bssh_ctl_write_frame (fd, BSSH_CTL_SFTP_GET, remote,
                            (uint32_t) strlen (remote)) < 0
      || bssh_mux_expect_ok (fd, "sftp get") < 0)
    { close (fd); return -1; }
  int lfd = open (local, O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (lfd < 0)
    {
      builtin_error ("sftp get: %s: %s", local, strerror (errno));
      close (fd);
      return -1;
    }
  int rc = -1;
  for (;;)
    {
      unsigned char op; char *pl; uint32_t len;
      if (bssh_ctl_read_frame (fd, &op, &pl, &len) < 0)
        break;
      if (op == BSSH_CTL_DATA_OUT)
        {
          if (len && write_all (lfd, pl, len) < 0)
            {
              builtin_error ("sftp get: write %s: %s", local, strerror (errno));
              free (pl);
              break;
            }
        }
      else if (op == BSSH_CTL_EXIT)
        {
          uint32_t st = 1;
          if (len >= 4) memcpy (&st, pl, 4);
          rc = (st == 0) ? 0 : -1;
          free (pl);
          break;
        }
      else
        {
          if (op == BSSH_CTL_ERR)
            builtin_error ("master: %s", pl && *pl ? pl : "sftp get failed");
          free (pl);
          break;
        }
      free (pl);
    }
  if (close (lfd) < 0 && rc == 0) rc = -1;
  close (fd);
  return rc;
}
#else
static int libssh_connect_session (const char *host, const char *port,
                                   const char *user, const char *key,
                                   int forward_agent, const char *jump)
{
  (void) host; (void) port; (void) user; (void) key; (void) forward_agent; (void) jump;
  builtin_error ("libssh transport is not compiled in");
  return -1;
}

static int run_libssh_exec (const ssh_handle *h, const char *cmd,
                            const char *infile, blob *out, blob *err)
{
  (void) h; (void) cmd; (void) infile; (void) out; (void) err;
  builtin_error ("libssh transport is not compiled in");
  return -1;
}

static int run_libssh_shell (const ssh_handle *h)
{
  (void) h;
  builtin_error ("libssh transport is not compiled in");
  return -1;
}

static int libssh_sftp_put (const ssh_handle *h, const char *local,
                            const char *remote, unsigned int mode)
{
  (void) h; (void) local; (void) remote; (void) mode;
  builtin_error ("libssh transport is not compiled in");
  return -1;
}

static int libssh_sftp_get (const ssh_handle *h, const char *remote,
                            const char *local)
{
  (void) h; (void) remote; (void) local;
  builtin_error ("libssh transport is not compiled in");
  return -1;
}
static int libssh_forward_local_once (const ssh_handle *h, const char *spec)
{
  (void) h; (void) spec;
  builtin_error ("libssh transport is not compiled in");
  return -1;
}
static int bssh_forward_spawn_local (const ssh_handle *h, const char *spec)
{
  (void) h; (void) spec;
  builtin_error ("libssh transport is not compiled in");
  return -1;
}
static int bssh_forward_spawn_remote (const ssh_handle *h, const char *spec)
{
  (void) h; (void) spec;
  builtin_error ("libssh transport is not compiled in");
  return -1;
}
/* F06 ControlMaster stubs: the master/ControlPath surface is libssh-only. */
static int bssh_controlpath_expand (const char *in, const char *host,
                                    const char *port, const char *user,
                                    char *out, size_t outsz)
{
  (void) in; (void) host; (void) port; (void) user; (void) out; (void) outsz;
  builtin_error ("ControlMaster: libssh transport is not compiled in");
  return -1;
}
static int bssh_mux_check (const char *path, char *pidbuf, size_t pidsz)
{
  (void) path; (void) pidbuf; (void) pidsz;
  return -1;
}
static int bssh_mux_live (const char *path)
{
  (void) path;
  return 0;
}
static int bssh_mux_terminate (const char *path)
{
  (void) path;
  return -1;
}
static int bssh_mux_exec (const char *path, const char *cmd,
                          const char *infile, blob *out, blob *err)
{
  (void) path; (void) cmd; (void) infile; (void) out; (void) err;
  builtin_error ("ControlMaster: libssh transport is not compiled in");
  return -1;
}
static int bssh_mux_shell (const char *path)
{
  (void) path;
  builtin_error ("ControlMaster: libssh transport is not compiled in");
  return -1;
}
static int bssh_mux_sftp_put (const char *path, const char *local,
                              const char *remote, unsigned int mode)
{
  (void) path; (void) local; (void) remote; (void) mode;
  builtin_error ("ControlMaster: libssh transport is not compiled in");
  return -1;
}
static int bssh_mux_sftp_get (const char *path, const char *remote,
                              const char *local)
{
  (void) path; (void) remote; (void) local;
  builtin_error ("ControlMaster: libssh transport is not compiled in");
  return -1;
}
#endif

static int run_openssh (const ssh_handle *h, const char *cmd, const char *infile, blob *out, blob *err)
{
  int op[2], ep[2];
  if (pipe (op) < 0 || pipe (ep) < 0)
    return -1;
  char stpath[64];
  snprintf (stpath, sizeof stpath, "/tmp/ssh-rc-XXXXXX");
  int stfd = mkstemp (stpath);
  if (stfd >= 0)
    close (stfd);
  struct bssh_child_guard guard;
  bssh_child_guard_begin (&guard);
  pid_t pid = fork ();
  if (pid < 0)
    { bssh_child_guard_parent_end (&guard); if (stfd >= 0) unlink (stpath); return -1; }
  if (pid == 0)
    {
      bssh_child_guard_child_end (&guard);
      close (op[0]); close (ep[0]);
      if (infile)
        {
          int in = open (infile, O_RDONLY);
          if (in < 0) _exit (127);
          dup2 (in, STDIN_FILENO);
          close (in);
        }
      else
        {
          int in = open ("/dev/null", O_RDONLY);
          if (in >= 0) { dup2 (in, STDIN_FILENO); close (in); }
        }
      dup2 (op[1], STDOUT_FILENO);
      dup2 (ep[1], STDERR_FILENO);
      close (op[1]); close (ep[1]);

      char target[512];
      if (h->user[0])
        snprintf (target, sizeof target, "%s@%s", h->user, h->host);
      else
        snprintf (target, sizeof target, "%s", h->host);

      char *argv[16];
      int n = 0;
      const char *ssh_bin = getenv ("BASHSSH_OPENSSH_BIN");
      if (!ssh_bin || !ssh_bin[0]) ssh_bin = "ssh";
      argv[n++] = (char *) ssh_bin;
      argv[n++] = "-o"; argv[n++] = "BatchMode=yes";
      argv[n++] = "-o"; argv[n++] = "StrictHostKeyChecking=accept-new";
      argv[n++] = "-p"; argv[n++] = (char *) h->port;
      if (h->key[0])
        { argv[n++] = "-i"; argv[n++] = (char *) h->key; }
      argv[n++] = target;
      argv[n++] = (char *) cmd;
      argv[n] = NULL;
      pid_t spid = fork ();
      if (spid == 0)
        {
          execvp (ssh_bin, argv);
          _exit (127);
        }
      int sst = 0, src = 127;
      while (waitpid (spid, &sst, 0) < 0 && errno == EINTR) ;
      if (WIFEXITED (sst)) src = WEXITSTATUS (sst);
      else if (WIFSIGNALED (sst)) src = 128 + WTERMSIG (sst);
      FILE *sf = fopen (stpath, "w");
      if (sf) { fprintf (sf, "%d\n", src); fclose (sf); }
      _exit (src);
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
  while (waitpid (pid, &st, 0) < 0 && errno == EINTR) ;
  bssh_child_guard_parent_end (&guard);
  int file_rc = -1;
  FILE *sf = fopen (stpath, "r");
  if (sf)
    {
      if (fscanf (sf, "%d", &file_rc) != 1)
        file_rc = -1;
      fclose (sf);
    }
  if (stfd >= 0)
    unlink (stpath);
  if (file_rc >= 0)
    return file_rc;
  if (WIFEXITED (st)) return WEXITSTATUS (st);
  if (WIFSIGNALED (st)) return 128 + WTERMSIG (st);
  return 127;
}

static int keygen_cmd (WORD_LIST *args)
{
  const char *type = "ed25519", *path = NULL, *w;
  while ((w = next_word (&args)))
    {
      if ((!strcmp (w, "-t") || !strcmp (w, "-T")) && args) type = next_word (&args);
      else if ((!strcmp (w, "-f") || !strcmp (w, "-o")) && args) path = next_word (&args);
      else if (!path) path = w;
    }
  if (!path) { builtin_error ("keygen: [-t TYPE] -f PATH"); return EX_USAGE; }
  char pub[512];
  snprintf (pub, sizeof pub, "%s.pub", path);
  FILE *f = fopen (path, "w");
  if (!f) { builtin_error ("keygen: %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
  chmod (path, 0600);
  fprintf (f, "BASHSSH-PRIVATE %s\n", type);
  fclose (f);
  f = fopen (pub, "w");
  if (!f) { builtin_error ("keygen: %s: %s", pub, strerror (errno)); return EXECUTION_FAILURE; }
  fprintf (f, "ssh-%s AAAABASHOSPHASE3 %s\n", type, path);
  fclose (f);
  return EXECUTION_SUCCESS;
}

/* Match an OpenSSH HashKnownHosts (|1|salt_b64|hash_b64) host-field
 * against `host`. `field` is the first whitespace-delimited token of
 * a known_hosts line that we've already classified as starting with
 * the `|1|` magic. Returns 1 if HMAC-SHA1(salt, lower(host)) base64-
 * encoded equals the recorded hash, 0 otherwise (including any parse
 * or crypto failure — fail-closed). Host is lowercased before hashing
 * to match OpenSSH's case-insensitive host-label policy.
 *
 * Field shape: "|1|<salt_b64>|<hash_b64>". Length-bounded so a
 * malformed prefix can't run past the field. */
static int
bk_hashed_match (const char *field, const char *host)
{
  if (strncmp (field, "|1|", 3) != 0) return 0;
  const char *salt_b64 = field + 3;
  const char *bar = strchr (salt_b64, '|');
  if (!bar) return 0;
  size_t salt_blen = (size_t) (bar - salt_b64);
  const char *hash_b64 = bar + 1;
  size_t hash_blen = strlen (hash_b64);
  /* Strip any trailing whitespace embedded in the hash_b64 view
     (shouldn't happen — caller passed a NUL-terminated single field —
     but defense-in-depth). */
  while (hash_blen && (hash_b64[hash_blen - 1] == ' ' ||
                       hash_b64[hash_blen - 1] == '\t' ||
                       hash_b64[hash_blen - 1] == '\n' ||
                       hash_b64[hash_blen - 1] == '\r'))
    hash_blen--;
  if (salt_blen == 0 || hash_blen == 0) return 0;

  /* base64-decode the salt. OpenSSH uses a 20-byte salt (SHA-1 block
     size). Allow up to 64 bytes of decoded salt for forward compat. */
  unsigned char salt[64];
  size_t saltlen = 0;
  if (mbedtls_base64_decode (salt, sizeof salt, &saltlen,
                             (const unsigned char *) salt_b64, salt_blen) != 0)
    return 0;
  if (saltlen == 0 || saltlen > sizeof salt) return 0;

  /* Lowercase the host for case-insensitive matching. */
  char lower[256];
  size_t hlen = strlen (host);
  if (hlen >= sizeof lower) return 0;
  for (size_t i = 0; i < hlen; i++)
    lower[i] = (char) tolower ((unsigned char) host[i]);
  lower[hlen] = '\0';

  /* HMAC-SHA1(salt, host). */
  unsigned char tag[20];
  mbedtls_hmac_sha1_context ctx;
  mbedtls_hmac_sha1_init (&ctx);
  if (mbedtls_hmac_sha1_starts (&ctx, salt, saltlen) != 0)
    { mbedtls_hmac_sha1_free (&ctx); return 0; }
  if (mbedtls_hmac_sha1_update (&ctx, (const unsigned char *) lower, hlen) != 0)
    { mbedtls_hmac_sha1_free (&ctx); return 0; }
  mbedtls_hmac_sha1_finish (&ctx, tag);
  mbedtls_hmac_sha1_free (&ctx);

  /* base64-encode the computed tag. mbedtls writes a NUL terminator
     so we can strcmp/length-compare. */
  unsigned char tag_b64[48];
  size_t tag_blen = 0;
  if (mbedtls_base64_encode (tag_b64, sizeof tag_b64, &tag_blen,
                             tag, sizeof tag) != 0)
    return 0;
  if (tag_blen != hash_blen) return 0;
  return memcmp (tag_b64, hash_b64, hash_blen) == 0 ? 1 : 0;
}

static int
bssh_random_bytes (unsigned char *buf, size_t len)
{
  int fd = open ("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (fd < 0) return -1;
  size_t off = 0;
  while (off < len)
    {
      ssize_t n = read (fd, buf + off, len - off);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) { close (fd); return -1; }
      off += (size_t) n;
    }
  close (fd);
  return 0;
}

/* OpenSSH HashKnownHosts encoder companion for ssh-keyscan -H.  The matcher
 * above lowercases before HMAC to match OpenSSH lookup behavior; emit uses the
 * same canonicalization so generated scan lines round-trip through
 * `known-hosts list/remove/verify`. */
static int
bk_hash_host_field (const char *host, char *out, size_t outsz)
{
  unsigned char salt[20], tag[20], salt_b64[48], tag_b64[48];
  size_t salt_blen = 0, tag_blen = 0;
  char lower[512];
  size_t hlen = strlen (host);
  if (hlen >= sizeof lower) return -1;
  if (bssh_random_bytes (salt, sizeof salt) < 0) return -1;
  for (size_t i = 0; i < hlen; i++)
    lower[i] = (char) tolower ((unsigned char) host[i]);
  lower[hlen] = '\0';

  mbedtls_hmac_sha1_context ctx;
  mbedtls_hmac_sha1_init (&ctx);
  if (mbedtls_hmac_sha1_starts (&ctx, salt, sizeof salt) != 0)
    { mbedtls_hmac_sha1_free (&ctx); return -1; }
  if (mbedtls_hmac_sha1_update (&ctx, (const unsigned char *) lower, hlen) != 0)
    { mbedtls_hmac_sha1_free (&ctx); return -1; }
  mbedtls_hmac_sha1_finish (&ctx, tag);
  mbedtls_hmac_sha1_free (&ctx);

  if (mbedtls_base64_encode (salt_b64, sizeof salt_b64, &salt_blen,
                             salt, sizeof salt) != 0)
    return -1;
  if (mbedtls_base64_encode (tag_b64, sizeof tag_b64, &tag_blen,
                             tag, sizeof tag) != 0)
    return -1;
  if (snprintf (out, outsz, "|1|%.*s|%.*s",
                (int) salt_blen, salt_b64, (int) tag_blen, tag_b64)
      >= (int) outsz)
    return -1;
  return 0;
}

static const char *
bssh_keyscan_hostkey_algs (const char *type)
{
  if (!type || !*type) return NULL;
  if (!strcasecmp (type, "rsa"))
    return "rsa-sha2-512,rsa-sha2-256,ssh-rsa";
  if (!strcasecmp (type, "ecdsa"))
    return "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521";
  if (!strcasecmp (type, "ed25519"))
    return "ssh-ed25519";
  if (!strcasecmp (type, "dsa") || !strcasecmp (type, "ssh-dss"))
    return "ssh-dss";
  if (!strncasecmp (type, "ssh-", 4)
      || !strncasecmp (type, "rsa-sha2-", 9)
      || !strncasecmp (type, "ecdsa-sha2-", 12))
    return type;
  return NULL;
}

static void
bssh_keyscan_host_field (const char *host, const char *port, char *out, size_t outsz)
{
  if (port && *port && strcmp (port, "22") != 0)
    snprintf (out, outsz, "[%s]:%s", host, port);
  else
    snprintf (out, outsz, "%s", host);
}

static int
bssh_keyscan_one (const char *host, const char *port, const char *type,
                  int timeout_s, int hash_host, blob *out)
{
#if !BASHSSH_HAVE_LIBSSH
  (void) host; (void) port; (void) type; (void) timeout_s; (void) hash_host; (void) out;
  return 0;
#else
  const char *algs = bssh_keyscan_hostkey_algs (type);
  if (!algs) return 0;
  if (libssh_ensure_initialized () < 0) return 0;

  ssh_session session = ssh_new ();
  if (!session) return 0;

  int port_i = atoi (port && *port ? port : "22");
  int batch = 1;
  int strict = SSH_STRICT_HOSTKEY_OFF;
  int no = 0;
  if (timeout_s <= 0) timeout_s = 5;
  if (ssh_options_set (session, SSH_OPTIONS_HOST, host) != SSH_OK
      || ssh_options_set (session, SSH_OPTIONS_PORT, &port_i) != SSH_OK
      || ssh_options_set (session, SSH_OPTIONS_BATCH_MODE, &batch) != SSH_OK
      || ssh_options_set (session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &strict) != SSH_OK
      || ssh_options_set (session, SSH_OPTIONS_TIMEOUT, &timeout_s) != SSH_OK
      || ssh_options_set (session, SSH_OPTIONS_HOSTKEYS, algs) != SSH_OK
      || ssh_options_set (session, SSH_OPTIONS_PASSWORD_AUTH, &no) != SSH_OK
      || ssh_options_set (session, SSH_OPTIONS_KBDINT_AUTH, &no) != SSH_OK
      || ssh_options_set (session, SSH_OPTIONS_GSSAPI_AUTH, &no) != SSH_OK)
    { ssh_free (session); return 0; }

  if (ssh_connect (session) != SSH_OK)
    { ssh_free (session); return 0; }

  ssh_key key = NULL;
  char *b64 = NULL;
  if (ssh_get_server_publickey (session, &key) != SSH_OK || !key)
    { ssh_disconnect (session); ssh_free (session); return 0; }
  const char *kt = ssh_key_type_to_char (ssh_key_type (key));
  if (!kt || ssh_pki_export_pubkey_base64 (key, &b64) != SSH_OK || !b64)
    {
      ssh_key_free (key);
      ssh_disconnect (session);
      ssh_free (session);
      return 0;
    }

  char host_field[512], scan_field[640], line[4096];
  bssh_keyscan_host_field (host, port && *port ? port : "22",
                           host_field, sizeof host_field);
  if (hash_host)
    {
      if (bk_hash_host_field (host_field, scan_field, sizeof scan_field) < 0)
        snprintf (scan_field, sizeof scan_field, "%s", host_field);
    }
  else
    snprintf (scan_field, sizeof scan_field, "%s", host_field);

  const char *banner = ssh_get_serverbanner (session);
  if (banner && *banner)
    {
      int n = snprintf (line, sizeof line, "# %s:%d %s\n", host, port_i, banner);
      if (n > 0 && n < (int) sizeof line
          && blob_append (out, line, (size_t) n) < 0)
        { ssh_string_free_char (b64); ssh_key_free (key); ssh_disconnect (session); ssh_free (session); return -1; }
    }
  int n = snprintf (line, sizeof line, "%s %s %s\n", scan_field, kt, b64);
  ssh_string_free_char (b64);
  ssh_key_free (key);
  ssh_disconnect (session);
  ssh_free (session);
  if (n <= 0 || n >= (int) sizeof line) return 0;
  return blob_append (out, line, (size_t) n) == 0 ? 0 : -1;
#endif
}

static int
keyscan_cmd (WORD_LIST *args)
{
  const char *host = NULL, *port = "22", *types = "rsa,ecdsa,ed25519";
  const char *outvar = NULL, *w;
  int hash_host = 0, timeout_s = 5;

  while ((w = next_word (&args)))
    {
      if (!strcmp (w, "-H")) hash_host = 1;
      else if (!strcmp (w, "-p") && args) port = next_word (&args);
      else if (!strcmp (w, "-t") && args) types = next_word (&args);
      else if (!strcmp (w, "-T") && args)
        {
          const char *tv = next_word (&args);
          timeout_s = atoi (tv);
          if (timeout_s <= 0) timeout_s = 5;
        }
      else if (!strcmp (w, "-V") && args) outvar = next_word (&args);
      else if (!host && w[0] != '-') host = w;
      else
        { builtin_error ("keyscan HOST [-p PORT] [-t TYPES] [-T TIMEOUT] [-H] [-V OUTVAR]"); return EX_USAGE; }
    }
  if (!host)
    { builtin_error ("keyscan HOST [-p PORT] [-t TYPES] [-T TIMEOUT] [-H] [-V OUTVAR]"); return EX_USAGE; }

  blob out = {0};
  char *copy = strdup (types && *types ? types : "rsa,ecdsa,ed25519");
  if (!copy) return EXECUTION_FAILURE;
  char *save = NULL;
  for (char *tok = strtok_r (copy, ",", &save); tok; tok = strtok_r (NULL, ",", &save))
    {
      while (*tok == ' ' || *tok == '\t') tok++;
      char *end = tok + strlen (tok);
      while (end > tok && (end[-1] == ' ' || end[-1] == '\t')) *--end = '\0';
      if (*tok && bssh_keyscan_one (host, port, tok, timeout_s, hash_host, &out) < 0)
        { free (copy); free (out.p); return EXECUTION_FAILURE; }
    }
  free (copy);
  if (outvar)
    builtin_bind_variable ((char *) outvar, out.p ? out.p : "", 0);
  else if (out.p)
    fputs (out.p, stdout);
  free (out.p);
  return EXECUTION_SUCCESS;
}

/* known-hosts verify rc parity with OpenSSH-style trust prompts:
 *   0 = host matches recorded key (or recorded with no expected key supplied)
 *   1 = host recorded but key differs (mismatch — TOFU break, the dangerous case)
 *   2 = host not in known_hosts (unknown — TOFU decision point)
 */
static int known_hosts_cmd (WORD_LIST *args)
{
  const char *sub = next_word (&args);
  if (!sub) { builtin_error ("known-hosts add|verify HOST [KEY] [-V RC]"); return EX_USAGE; }

  const char *home = getenv ("HOME");
  if (!home) home = "/root";
  char dir[512], path[512];
  const char *configured = getenv ("BASHSSH_KNOWN_HOSTS");
  if (snprintf (dir, sizeof dir, "%s/.ssh", home) >= (int) sizeof dir ||
      (configured && *configured
       ? snprintf (path, sizeof path, "%s", configured)
       : snprintf (path, sizeof path, "%s/known_hosts", dir)) >= (int) sizeof path) {
    builtin_error ("known-hosts path too long"); return EXECUTION_FAILURE;
  }

  if (!strcmp (sub, "add"))
    {
      const char *host = next_word (&args), *key = next_word (&args);
      if (!host || !key) { builtin_error ("known-hosts add HOST KEY"); return EX_USAGE; }
      if (!configured || !*configured) mkdir (dir, 0700);
      FILE *f = fopen (path, "a");
      if (!f) { builtin_error ("known-hosts: %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
      fprintf (f, "%s %s\n", host, key);
      fclose (f);
      chmod (path, 0644);
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (sub, "verify"))
    {
      const char *host = next_word (&args), *expected = NULL, *rcvar = NULL, *w;
      while ((w = next_word (&args)))
        {
          if (!strcmp (w, "-V") && args) rcvar = next_word (&args);
          else if (!expected && w[0] != '-') expected = w;
          else { builtin_error ("known-hosts verify HOST [KEY] [-V RC]"); return EX_USAGE; }
        }
      if (!host) { builtin_error ("known-hosts verify HOST [KEY] [-V RC]"); return EX_USAGE; }
      int rc = 2;
      FILE *f = fopen (path, "r");
      if (f)
        {
          char line[1024];
          size_t hlen = strlen (host);
          while (fgets (line, sizeof line, f))
            {
              char *p = line;
              while (*p == ' ' || *p == '\t') p++;
              if (*p == '\0' || *p == '\n' || *p == '#') continue;
              /* Locate the end of the first whitespace-delimited
                 field (the host token, possibly a |1|salt|hash). */
              char *field_end = p;
              while (*field_end && *field_end != ' ' && *field_end != '\t')
                field_end++;
              if (*field_end != ' ' && *field_end != '\t') continue;
              char saved = *field_end;
              *field_end = '\0';
              int host_matches;
              if (p[0] == '|' && p[1] == '1' && p[2] == '|')
                {
                  /* Hashed entry — HMAC-SHA1(salt, host) base64-equal? */
                  host_matches = bk_hashed_match (p, host);
                }
              else
                {
                  host_matches = (strlen (p) == hlen
                                  && strncmp (p, host, hlen) == 0);
                }
              *field_end = saved;
              if (!host_matches) continue;
              char *kp = field_end;
              while (*kp == ' ' || *kp == '\t') kp++;
              size_t kn = strlen (kp);
              while (kn && (kp[kn - 1] == '\n' || kp[kn - 1] == '\r' ||
                            kp[kn - 1] == ' ' || kp[kn - 1] == '\t'))
                kp[--kn] = '\0';
              if (!expected || strcmp (kp, expected) == 0) { rc = 0; break; }
              rc = 1; /* recorded but mismatched — keep scanning in case of duplicate match */
            }
          fclose (f);
        }
      if (rcvar)
        {
          char rbuf[16];
          snprintf (rbuf, sizeof rbuf, "%d", rc);
          builtin_bind_variable ((char *) rcvar, rbuf, 0);
        }
      return rc;
    }

  /* `ssh-keygen -F HOST` parity: print matching entries, rc 0 if any matched
   * (or any printed when no filter is given), rc 1 if a filter was supplied
   * but matched nothing.  Missing file is treated as empty: rc 1 with filter,
   * rc 0 without.  Hashed entries (|1|salt|hash) are HMAC-matched against
   * the filter via `bk_hashed_match`, matching `ssh-keygen -F HOST`
   * behavior — pre-fix code did a literal `strncmp(field, filter)` so
   * hashed entries were silently invisible to filtered list. */
  if (!strcmp (sub, "list"))
    {
      const char *filter = NULL, *w;
      while ((w = next_word (&args)))
        {
          if (!filter && w[0] != '-') filter = w;
          else { builtin_error ("known-hosts list [HOST]"); return EX_USAGE; }
        }
      FILE *f = fopen (path, "r");
      if (!f) return filter ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
      char line[1024];
      size_t flen = filter ? strlen (filter) : 0;
      int matched = 0;
      while (fgets (line, sizeof line, f))
        {
          char *p = line;
          while (*p == ' ' || *p == '\t') p++;
          if (*p == '\0' || *p == '\n' || *p == '#') continue;
          if (filter)
            {
              /* Isolate the first whitespace-delimited field so we can
                 branch on `|1|`-prefix without re-scanning. */
              char *field_end = p;
              while (*field_end && *field_end != ' ' && *field_end != '\t')
                field_end++;
              if (*field_end != ' ' && *field_end != '\t') continue;
              char saved = *field_end;
              *field_end = '\0';
              int host_matches;
              if (p[0] == '|' && p[1] == '1' && p[2] == '|')
                host_matches = bk_hashed_match (p, filter);
              else
                host_matches = (strlen (p) == flen
                                && strncmp (p, filter, flen) == 0);
              *field_end = saved;
              if (!host_matches) continue;
            }
          fputs (p, stdout);
          matched = 1;
        }
      fclose (f);
      if (filter && !matched) return EXECUTION_FAILURE;
      return EXECUTION_SUCCESS;
    }

  /* `ssh-keygen -R HOST` parity: rewrite the file removing every entry whose
   * host token equals HOST; comments and blank lines are preserved verbatim.
   * Always rc 0 (idempotent — missing file and no-match both succeed); the
   * number of removed entries is reported on stderr. */
  if (!strcmp (sub, "remove"))
    {
      const char *host = next_word (&args);
      if (!host || next_word (&args))
        { builtin_error ("known-hosts remove HOST"); return EX_USAGE; }
      FILE *f = fopen (path, "r");
      if (!f) { fprintf (stderr, "known-hosts: %s not found, nothing to remove\n", path); return EXECUTION_SUCCESS; }
      char tmp[600];
      snprintf (tmp, sizeof tmp, "%s.tmp", path);
      FILE *t = fopen (tmp, "w");
      if (!t) { fclose (f); builtin_error ("%s: %s", tmp, strerror (errno)); return EXECUTION_FAILURE; }
      char line[1024];
      size_t hlen = strlen (host);
      size_t removed = 0;
      while (fgets (line, sizeof line, f))
        {
          char *p = line;
          while (*p == ' ' || *p == '\t') p++;
          if (*p == '\0' || *p == '\n' || *p == '#')
            { fputs (line, t); continue; }
          /* Isolate the first whitespace-delimited field so hashed
             `|1|salt|hash` entries can be HMAC-matched against the
             literal host argument (matching `ssh-keygen -R HOST`).
             Pre-fix code did a literal `strncmp(field, host)` so
             hashed entries were immune to remove. */
          char *field_end = p;
          while (*field_end && *field_end != ' ' && *field_end != '\t')
            field_end++;
          if (*field_end != ' ' && *field_end != '\t')
            { fputs (line, t); continue; }
          char saved = *field_end;
          *field_end = '\0';
          int host_matches;
          if (p[0] == '|' && p[1] == '1' && p[2] == '|')
            host_matches = bk_hashed_match (p, host);
          else
            host_matches = (strlen (p) == hlen
                            && strncmp (p, host, hlen) == 0);
          *field_end = saved;
          if (host_matches) { removed++; continue; }
          fputs (line, t);
        }
      fclose (f); fclose (t);
      if (rename (tmp, path) < 0)
        { unlink (tmp); builtin_error ("rename %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
      chmod (path, 0644);
      fprintf (stderr, "known-hosts: removed %zu entr%s for %s\n",
               removed, removed == 1 ? "y" : "ies", host);
      return EXECUTION_SUCCESS;
    }

  builtin_error ("known-hosts: unknown subcommand: %s", sub);
  return EX_USAGE;
}

/* F06 item 6b: client ssh_config. Resolved values for a connect alias; empty
   string / -1 = unset (so CLI/env can take precedence). */
typedef struct {
  char hostname[256], port[16], user[128], identity[512];
  char ciphers[256], macs[256], kex[256], strict[32], knownhosts[512];
  char jump[256];       /* ProxyJump [user@]host[:port] */
  int  forward_agent;   /* -1 unset, 0 no, 1 yes */
  /* F06 ControlMaster: the only three multiplexing keys we accept */
  char controlmaster[16], controlpath[512], controlpersist[32];
} bssh_ssh_config;

/* Expand a leading ~/ or ~ to $HOME. Other forms (~user) are left as-is. */
static void bssh_tilde_expand (const char *in, char *out, size_t outsz)
{
  const char *home = getenv ("HOME");
  if (in[0] == '~' && (in[1] == '/' || in[1] == '\0') && home && *home)
    snprintf (out, outsz, "%s%s", home, in + 1);
  else
    snprintf (out, outsz, "%s", in);
}

/* Copy a config value into dst only if dst is still empty (first-wins). */
static void bssh_cfg_set_once (char *dst, size_t dsz, const char *val)
{
  if (dst[0] == '\0') snprintf (dst, dsz, "%s", val);
}

#define BSSH_INCLUDE_MAX_DEPTH 16
/* Parse ssh_config at `path`, filling `out` for connect alias `alias` (and
   `muser` = the effective -l user, for `Match user`). first-obtained-value-wins;
   `Host pat...` and `Match host|user|all ...` blocks gate the following
   directives. `Include glob` pulls in more files (relative to the parent dir),
   depth-capped; an included file is parsed at its own top level (its Host/Match
   state does not leak back to the parent). Returns 0 if the file was read, -1 if
   it could not be opened. Unknown keywords are ignored (lenient). */
static int bssh_load_ssh_config (const char *alias, const char *muser,
                                 const char *path, bssh_ssh_config *out, int depth)
{
  FILE *f = fopen (path, "r");
  if (!f) return -1;
  char line[1024];
  int active = 1;   /* global section (before first Host) applies */
  while (fgets (line, sizeof line, f))
    {
      char *p = line;
      char *hash = strchr (p, '#');
      if (hash) *hash = '\0';
      while (*p == ' ' || *p == '\t') p++;
      char *eol = p + strlen (p);
      while (eol > p && (eol[-1] == '\n' || eol[-1] == '\r' ||
                         eol[-1] == ' ' || eol[-1] == '\t')) *--eol = '\0';
      if (!*p) continue;
      /* split keyword / value (whitespace or '=' separated) */
      char *kw = p;
      while (*p && *p != ' ' && *p != '\t' && *p != '=') p++;
      if (*p) { *p++ = '\0'; }
      while (*p == ' ' || *p == '\t' || *p == '=') p++;
      char *val = p;
      if (!*kw) continue;

      if (!strcasecmp (kw, "Host"))
        {
          /* match alias against any space-separated fnmatch pattern */
          active = 0;
          char *tok = strtok (val, " \t");
          while (tok)
            { if (fnmatch (tok, alias, 0) == 0) { active = 1; break; }
              tok = strtok (NULL, " \t"); }
          continue;
        }
      if (!strcasecmp (kw, "Match"))
        {
          /* AND each criterion; `host` matches the alias, `user` the -l user,
             `all` always matches; a comma list within a criterion is OR. An
             unsupported criterion makes the block inactive (lenient). */
          active = 1;
          char *save = NULL;
          for (char *tok = strtok_r (val, " \t", &save); tok; tok = strtok_r (NULL, " \t", &save))
            {
              if (!strcasecmp (tok, "all") || !strcasecmp (tok, "canonical") || !strcasecmp (tok, "final"))
                continue;
              if (!strcasecmp (tok, "host") || !strcasecmp (tok, "user"))
                {
                  int want_host = !strcasecmp (tok, "host");
                  char *pat = strtok_r (NULL, " \t", &save);
                  if (!pat) { active = 0; break; }
                  const char *subj = want_host ? alias : (muser ? muser : "");
                  int m = 0; char pbuf[256]; snprintf (pbuf, sizeof pbuf, "%s", pat);
                  char *ps = NULL;
                  for (char *pp = strtok_r (pbuf, ",", &ps); pp; pp = strtok_r (NULL, ",", &ps))
                    if (fnmatch (pp, subj, 0) == 0) { m = 1; break; }
                  if (!m) { active = 0; break; }
                }
              else { active = 0; break; }     /* unsupported criterion → inactive */
            }
          continue;
        }
      if (!active || !*val) continue;

      if (!strcasecmp (kw, "HostName"))            bssh_cfg_set_once (out->hostname, sizeof out->hostname, val);
      else if (!strcasecmp (kw, "Port"))           bssh_cfg_set_once (out->port, sizeof out->port, val);
      else if (!strcasecmp (kw, "User"))           bssh_cfg_set_once (out->user, sizeof out->user, val);
      else if (!strcasecmp (kw, "IdentityFile"))
        { if (!out->identity[0]) bssh_tilde_expand (val, out->identity, sizeof out->identity); }
      else if (!strcasecmp (kw, "UserKnownHostsFile"))
        { if (!out->knownhosts[0]) bssh_tilde_expand (val, out->knownhosts, sizeof out->knownhosts); }
      else if (!strcasecmp (kw, "Ciphers"))        bssh_cfg_set_once (out->ciphers, sizeof out->ciphers, val);
      else if (!strcasecmp (kw, "MACs"))           bssh_cfg_set_once (out->macs, sizeof out->macs, val);
      else if (!strcasecmp (kw, "KexAlgorithms"))  bssh_cfg_set_once (out->kex, sizeof out->kex, val);
      else if (!strcasecmp (kw, "StrictHostKeyChecking")) bssh_cfg_set_once (out->strict, sizeof out->strict, val);
      else if (!strcasecmp (kw, "Include"))
        {
          /* Include glob[,glob...] — recurse (depth-capped), relative to the
             parent dir for non-absolute patterns. Only when the current block
             matches (active, guaranteed above). */
          if (depth < BSSH_INCLUDE_MAX_DEPTH)
            {
              char dbuf[768]; snprintf (dbuf, sizeof dbuf, "%s", path);
              char *d = strrchr (dbuf, '/'); if (d) *d = '\0'; else snprintf (dbuf, sizeof dbuf, ".");
              char *save = NULL;
              for (char *tok = strtok_r (val, " \t", &save); tok; tok = strtok_r (NULL, " \t", &save))
                {
                  char pat[1024];
                  if (tok[0] == '/') snprintf (pat, sizeof pat, "%s", tok);
                  else snprintf (pat, sizeof pat, "%s/%s", dbuf, tok);
                  glob_t g;
                  if (glob (pat, GLOB_NOSORT, NULL, &g) == 0)
                    for (size_t i = 0; i < g.gl_pathc; i++)
                      bssh_load_ssh_config (alias, muser, g.gl_pathv[i], out, depth + 1);
                  globfree (&g);
                }
            }
        }
      else if (!strcasecmp (kw, "ProxyJump"))      bssh_cfg_set_once (out->jump, sizeof out->jump, val);
      else if (!strcasecmp (kw, "ControlMaster"))  bssh_cfg_set_once (out->controlmaster, sizeof out->controlmaster, val);
      else if (!strcasecmp (kw, "ControlPath"))
        { if (!out->controlpath[0]) bssh_tilde_expand (val, out->controlpath, sizeof out->controlpath); }
      else if (!strcasecmp (kw, "ControlPersist")) bssh_cfg_set_once (out->controlpersist, sizeof out->controlpersist, val);
      else if (!strcasecmp (kw, "ForwardAgent"))
        { if (out->forward_agent < 0)
            out->forward_agent = (!strcasecmp (val, "yes") || !strcasecmp (val, "true")) ? 1 : 0; }
      /* unknown keyword → ignored (lenient) */
    }
  fclose (f);
  return 0;
}

/* Set env var `name` to `val` only if it is currently unset/empty, recording in
   *saved whether we set it (so the caller can unset it afterwards). */
static void bssh_env_apply_once (const char *name, const char *val, int *saved)
{
  *saved = 0;
  if (val && *val)
    {
      const char *cur = getenv (name);
      if (!cur || !*cur) { setenv (name, val, 1); *saved = 1; }
    }
}

/* F06 ControlMaster: parse a ControlMaster=auto|yes|no value.
   Returns 1 yes, 0 no, 2 auto, -2 invalid. */
static int bssh_parse_controlmaster (const char *v)
{
  if (!strcasecmp (v, "yes")) return 1;
  if (!strcasecmp (v, "no")) return 0;
  if (!strcasecmp (v, "auto")) return 2;
  return -2;
}

/* Recognize the bounded -o option set: Control{Master,Path,Persist}=VALUE.
   Returns 1 when handled (outputs filled), 0 when `ov` is not a control
   option, -1 on an invalid value (diagnostic already printed). */
static int bssh_parse_ctl_option (const char *ov, int *cm, const char **path,
                                  const char **persist)
{
  if (!ov) return 0;
  if (!strncasecmp (ov, "ControlMaster=", 14))
    {
      int m = bssh_parse_controlmaster (ov + 14);
      if (m == -2)
        {
          builtin_error ("-o ControlMaster expects auto|yes|no (got %s)", ov + 14);
          return -1;
        }
      *cm = m;
      return 1;
    }
  if (!strncasecmp (ov, "ControlPath=", 12))
    {
      *path = ov + 12;
      return 1;
    }
  if (!strncasecmp (ov, "ControlPersist=", 15))
    {
      if (persist) *persist = ov + 15;
      return 1;
    }
  return 0;
}

static int connect_cmd (WORD_LIST *args)
{
  const char *host = NULL, *var = NULL, *port = NULL, *user = NULL, *key = NULL, *w;
  const char *config_file = NULL, *jump = NULL;
  const char *ctl_path = NULL;
  int cm_mode = -1;   /* -1 unset, 0 no, 1 yes, 2 auto */
  int openssh = 0;
  int libssh = 0;
  int forward_agent = 0;
  const char *env_transport = getenv ("BASHSSH_TRANSPORT");
  if (env_transport && (!strcmp (env_transport, "openssh") || !strcmp (env_transport, "ssh")))
    openssh = 1;
  if (env_transport && (!strcmp (env_transport, "libssh") || !strcmp (env_transport, "encrypted")))
    libssh = 1;
  while ((w = next_word (&args)))
    {
      if (!strcmp (w, "-h") && args) var = next_word (&args);
      else if (!strcmp (w, "-p") && args) port = next_word (&args);
      else if (!strcmp (w, "-i") && args) key = next_word (&args);
      else if (!strcmp (w, "-l") && args) user = next_word (&args);
      else if (!strcmp (w, "-F") && args) config_file = next_word (&args);
      else if (!strcmp (w, "-S") && args)
        { ctl_path = next_word (&args); libssh = 1; openssh = 0; }
      else if (!strcmp (w, "-o") && args)
        {
          /* fail-closed: only the bounded ControlMaster client option set */
          const char *ov = next_word (&args);
          int hr = bssh_parse_ctl_option (ov, &cm_mode, &ctl_path, NULL);
          if (hr < 0) return EX_USAGE;
          if (hr == 0)
            {
              builtin_error ("connect: unsupported -o option: %s (ControlMaster/ControlPath/ControlPersist only)",
                             ov ? ov : "");
              return EX_USAGE;
            }
        }
      else if ((!strcmp (w, "-J") || !strcmp (w, "--jump")) && args)
        { jump = next_word (&args); libssh = 1; openssh = 0; }
      else if (!strcmp (w, "--openssh") || !strcmp (w, "--ssh")) openssh = 1;
      else if (!strcmp (w, "--encrypted") || !strcmp (w, "--libssh"))
        { libssh = 1; openssh = 0; }
      else if (!strcmp (w, "-A") || !strcmp (w, "--forward-agent"))
        { forward_agent = 1; libssh = 1; openssh = 0; }
      else if (!strcmp (w, "--native"))
        { openssh = 0; libssh = 0; }
      else if (!strcmp (w, "--help"))
        {
          puts ("connect HOST [-p PORT] [-l USER] [-i KEY] [-F CONFIG] [-J [user@]jump[:port]] [-A|--forward-agent] [--native|--encrypted|--openssh] [-h VAR]");
          puts ("  -J [user@]jump[:port] proxies the (encrypted) connection through a jump host");
          puts ("  --encrypted uses the vendored libssh client transport");
          puts ("  -A, --forward-agent requests SSH agent forwarding on exec channels");
          puts ("  -F CONFIG resolves HOST as an ssh_config alias (libssh path; else ~/.ssh/config)");
          puts ("  -S CTLPATH, -o ControlMaster=auto|yes|no, -o ControlPath=P route through a live");
          puts ("     `ssh master` ControlPath socket (encrypted only; auto miss connects direct)");
          return EXECUTION_SUCCESS;
        }
      else if (!host) host = w;
    }
  if (!host) { builtin_error ("connect HOST [-p PORT] [-l USER] [-i KEY] [-F CONFIG] [--encrypted|--openssh|--native] [-h VAR]"); return EX_USAGE; }

  /* F06 item 6b: resolve HOST as an ssh_config alias on the libssh path. CLI
     args win; the file fills only what the CLI left unset. The openssh
     transport defers to real ssh's own config, so skip there. */
  int cfg_env_saved[5] = {0};
  static const char *const cfg_env_names[5] = {
    "BASHSSH_CIPHERS", "BASHSSH_MACS", "BASHSSH_KEX",
    "BASHSSH_STRICT_HOST_KEY_CHECKING", "BASHSSH_KNOWN_HOSTS" };
  /* cfg must outlive the libssh_connect_session() call below: host/user/port/
     key/jump may point into it after resolution, so it lives at function scope
     (a block-scoped cfg would dangle once the resolution block closed). */
  bssh_ssh_config cfg;
  memset (&cfg, 0, sizeof cfg);
  cfg.forward_agent = -1;
  if (libssh && !openssh)
    {
      const char *path = config_file;
      char defpath[600];
      if (!path)
        {
          const char *envp = getenv ("BASHSSH_SSH_CONFIG");
          if (envp && *envp) path = envp;
          else { const char *home = getenv ("HOME");
                 if (home && *home) { snprintf (defpath, sizeof defpath, "%s/.ssh/config", home); path = defpath; } }
        }
      if (config_file && access (config_file, R_OK) < 0)
        { builtin_error ("connect: -F %s: %s", config_file, strerror (errno)); return EXECUTION_FAILURE; }
      if (path && bssh_load_ssh_config (host, user, path, &cfg, 0) == 0)
        {
          if (!user && cfg.user[0]) user = cfg.user;
          if (!port && cfg.port[0]) port = cfg.port;
          if (!key  && cfg.identity[0]) key = cfg.identity;
          if (!jump && cfg.jump[0]) jump = cfg.jump;
          if (!forward_agent && cfg.forward_agent == 1)
            forward_agent = 1;
          bssh_env_apply_once (cfg_env_names[0], cfg.ciphers,    &cfg_env_saved[0]);
          bssh_env_apply_once (cfg_env_names[1], cfg.macs,       &cfg_env_saved[1]);
          bssh_env_apply_once (cfg_env_names[2], cfg.kex,        &cfg_env_saved[2]);
          bssh_env_apply_once (cfg_env_names[3], cfg.strict,     &cfg_env_saved[3]);
          bssh_env_apply_once (cfg_env_names[4], cfg.knownhosts, &cfg_env_saved[4]);
          /* HostName overrides the connect target; the alias stays the lookup key. */
          if (cfg.hostname[0]) host = cfg.hostname;
        }
    }
  if (!port) port = "22";

  char handle[512];
  if (libssh)
    {
      /* F06 ControlMaster slave routing (opt-in, encrypted path only).
         yes → require a live master at the expanded ControlPath; auto →
         use it when live, else fall through to the direct process-local
         connect below; no/unset-without-path → direct connect. */
      const char *cmp = ctl_path;
      if (!cmp && cfg.controlpath[0]) cmp = cfg.controlpath;
      int cmm = cm_mode;
      if (cmm < 0 && cfg.controlmaster[0])
        {
          cmm = bssh_parse_controlmaster (cfg.controlmaster);
          if (cmm == -2)
            {
              builtin_error ("connect: ControlMaster in config expects auto|yes|no (got %s)",
                             cfg.controlmaster);
              for (int i = 0; i < 5; i++)
                if (cfg_env_saved[i]) unsetenv (cfg_env_names[i]);
              return EXECUTION_FAILURE;
            }
        }
      if (cmm < 0 && cmp) cmm = 2;      /* a bare ControlPath implies auto */
      if (cmp && cmm > 0)
        {
          char xp[256];
          if (bssh_controlpath_expand (cmp, host, port, user, xp, sizeof xp) < 0)
            {
              builtin_error ("connect: bad ControlPath %s (allowed tokens: %%h %%p %%r %%C %%%%)", cmp);
              for (int i = 0; i < 5; i++)
                if (cfg_env_saved[i]) unsetenv (cfg_env_names[i]);
              return EXECUTION_FAILURE;
            }
          if (bssh_mux_live (xp))
            {
              for (int i = 0; i < 5; i++)
                if (cfg_env_saved[i]) unsetenv (cfg_env_names[i]);
              snprintf (handle, sizeof handle, "mux://%s", xp);
              return bind_or_print (var, handle);
            }
          if (cmm == 1)
            {
              builtin_error ("connect: ControlMaster=yes but no live master at %s", xp);
              for (int i = 0; i < 5; i++)
                if (cfg_env_saved[i]) unsetenv (cfg_env_names[i]);
              return EXECUTION_FAILURE;
            }
          /* auto miss → direct process-local connect (existing behavior) */
        }
      if (forward_agent)
        {
          const char *sock = getenv ("SSH_AUTH_SOCK");
          struct stat st;
          if (!sock || !*sock)
            {
              builtin_error ("forward-agent: no SSH_AUTH_SOCK");
              return EXECUTION_FAILURE;
            }
          if (stat (sock, &st) < 0)
            {
              builtin_error ("forward-agent: %s: %s", sock, strerror (errno));
              return EXECUTION_FAILURE;
            }
          if ((st.st_mode & (S_IROTH | S_IWOTH)) != 0)
            {
              builtin_error ("forward-agent: refusing world-accessible SSH_AUTH_SOCK: %s", sock);
              return EXECUTION_FAILURE;
            }
        }
      int id = libssh_connect_session (host, port, user, key, forward_agent, jump);
      /* F06 item 6b: drop any env we set from the config so it can't leak into
         later commands (the session already captured the values). */
      for (int i = 0; i < 5; i++)
        if (cfg_env_saved[i]) unsetenv (cfg_env_names[i]);
      if (id < 0) return EXECUTION_FAILURE;
      snprintf (handle, sizeof handle, "libssh://%d", id);
    }
  else
    snprintf (handle, sizeof handle, "%s://%s%s%s:%s%s%s",
              openssh ? "openssh" : "ssh",
              user ? user : "", user ? "@" : "", host, port,
              key ? "|" : "", key ? key : "");
  return bind_or_print (var, handle);
}

/* F06 ControlMaster: `ssh master HOST ... -S CTLPATH [--persist N|no]`.
   Authenticates one shared ssh_session in a detached (double-forked) daemon
   that listens on the ControlPath socket and serves slave frame requests.
   Encrypted/libssh only; --persist: unset = stay until -O exit, no/0 = exit
   when the last client closes, N = linger N idle seconds. */
#if BASHSSH_HAVE_LIBSSH
static int master_cmd (WORD_LIST *args)
{
  const char *host = NULL, *port = NULL, *user = NULL, *key = NULL, *w;
  const char *config_file = NULL, *jump = NULL, *var = NULL;
  const char *ctl_path = NULL, *persist_s = NULL;
  int cm_ignored = -1;
  while ((w = next_word (&args)))
    {
      if (!strcmp (w, "-p") && args) port = next_word (&args);
      else if (!strcmp (w, "-l") && args) user = next_word (&args);
      else if (!strcmp (w, "-i") && args) key = next_word (&args);
      else if (!strcmp (w, "-F") && args) config_file = next_word (&args);
      else if ((!strcmp (w, "-J") || !strcmp (w, "--jump")) && args) jump = next_word (&args);
      else if (!strcmp (w, "-S") && args) ctl_path = next_word (&args);
      else if (!strcmp (w, "-h") && args) var = next_word (&args);
      else if (!strcmp (w, "--persist") && args) persist_s = next_word (&args);
      else if (!strcmp (w, "--encrypted") || !strcmp (w, "--libssh"))
        ;                               /* the master is always encrypted */
      else if (!strcmp (w, "-o") && args)
        {
          const char *ov = next_word (&args);
          int hr = bssh_parse_ctl_option (ov, &cm_ignored, &ctl_path, &persist_s);
          if (hr < 0) return EX_USAGE;
          if (hr == 0)
            { builtin_error ("master: unsupported -o option: %s", ov ? ov : ""); return EX_USAGE; }
        }
      else if (!strcmp (w, "--openssh") || !strcmp (w, "--ssh") || !strcmp (w, "--native"))
        {
          builtin_error ("master: the ControlMaster daemon is libssh/--encrypted only");
          return EX_USAGE;
        }
      else if (!strcmp (w, "--help"))
        {
          puts ("master HOST [-p PORT] [-l USER] [-i KEY] [-F CONFIG] [-J jump] -S CTLPATH [--persist N|no] [-h VAR]");
          puts ("  starts the encrypted ControlMaster daemon owning one shared SSH session;");
          puts ("  slaves reuse it via exec/shell/sftp -S CTLPATH or connect -o ControlMaster=auto");
          return EXECUTION_SUCCESS;
        }
      else if (!host && w[0] != '-') host = w;
      else { builtin_error ("master: unknown arg: %s", w); return EX_USAGE; }
    }
  if (!host)
    {
      builtin_error ("master HOST [-p PORT] [-l USER] [-i KEY] [-F CONFIG] [-J jump] -S CTLPATH [--persist N|no]");
      return EX_USAGE;
    }

  /* config resolution: identical contract to connect (CLI wins, the file
     fills only what was left unset; env crypto knobs applied once). */
  int cfg_env_saved[5] = {0};
  static const char *const cfg_env_names[5] = {
    "BASHSSH_CIPHERS", "BASHSSH_MACS", "BASHSSH_KEX",
    "BASHSSH_STRICT_HOST_KEY_CHECKING", "BASHSSH_KNOWN_HOSTS" };
  bssh_ssh_config cfg;
  memset (&cfg, 0, sizeof cfg);
  cfg.forward_agent = -1;
  {
    const char *path = config_file;
    char defpath[600];
    if (!path)
      {
        const char *envp = getenv ("BASHSSH_SSH_CONFIG");
        if (envp && *envp) path = envp;
        else
          {
            const char *home = getenv ("HOME");
            if (home && *home)
              { snprintf (defpath, sizeof defpath, "%s/.ssh/config", home); path = defpath; }
          }
      }
    if (config_file && access (config_file, R_OK) < 0)
      { builtin_error ("master: -F %s: %s", config_file, strerror (errno)); return EXECUTION_FAILURE; }
    if (path && bssh_load_ssh_config (host, user, path, &cfg, 0) == 0)
      {
        if (!user && cfg.user[0]) user = cfg.user;
        if (!port && cfg.port[0]) port = cfg.port;
        if (!key && cfg.identity[0]) key = cfg.identity;
        if (!jump && cfg.jump[0]) jump = cfg.jump;
        if (!ctl_path && cfg.controlpath[0]) ctl_path = cfg.controlpath;
        if (!persist_s && cfg.controlpersist[0]) persist_s = cfg.controlpersist;
        bssh_env_apply_once (cfg_env_names[0], cfg.ciphers,    &cfg_env_saved[0]);
        bssh_env_apply_once (cfg_env_names[1], cfg.macs,       &cfg_env_saved[1]);
        bssh_env_apply_once (cfg_env_names[2], cfg.kex,        &cfg_env_saved[2]);
        bssh_env_apply_once (cfg_env_names[3], cfg.strict,     &cfg_env_saved[3]);
        bssh_env_apply_once (cfg_env_names[4], cfg.knownhosts, &cfg_env_saved[4]);
        if (cfg.hostname[0]) host = cfg.hostname;
      }
  }
  if (!port) port = "22";

  int frc = EXECUTION_FAILURE;
  long persist = -1;                    /* default: stay until -O exit */
  char xp[256];
  int lfd = -1;
  int pfd[2] = { -1, -1 };

  if (!ctl_path)
    {
      builtin_error ("master: -S CTLPATH (or ControlPath) is required");
      goto out;
    }
  if (persist_s)
    {
      if (!strcasecmp (persist_s, "no") || !strcasecmp (persist_s, "false"))
        persist = 0;                    /* exit when the last client closes */
      else if (!strcasecmp (persist_s, "yes") || !strcasecmp (persist_s, "true"))
        persist = -1;
      else
        {
          char *end = NULL;
          long v = strtol (persist_s, &end, 10);
          if (end == persist_s || (*end && strcmp (end, "s") != 0) || v < 0)
            {
              builtin_error ("master: --persist expects seconds, yes, or no: %s", persist_s);
              goto out;
            }
          persist = v;
        }
    }
  if (bssh_controlpath_expand (ctl_path, host, port, user, xp, sizeof xp) < 0)
    {
      builtin_error ("master: bad ControlPath %s (allowed tokens: %%h %%p %%r %%C %%%%)", ctl_path);
      goto out;
    }
  lfd = libssh_listen_unix (xp);        /* all fail-closed path checks */
  if (lfd < 0)
    goto out;
  if (pipe (pfd) < 0)
    {
      builtin_error ("master: pipe: %s", strerror (errno));
      close (lfd);
      unlink (xp);
      goto out;
    }

  {
    struct bssh_child_guard guard;
    bssh_child_guard_begin (&guard);
    pid_t pid = fork ();
    if (pid < 0)
      {
        bssh_child_guard_parent_end (&guard);
        builtin_error ("master: fork: %s", strerror (errno));
        close (pfd[0]); close (pfd[1]);
        close (lfd);
        unlink (xp);
        goto out;
      }
    if (pid == 0)
      {
        /* intermediate child: detach the daemon (double fork → no zombie
           in the calling shell; setsid → no controlling tty). */
        bssh_child_guard_child_end (&guard);
        signal (SIGTERM, SIG_DFL);
        signal (SIGINT, SIG_DFL);
        setsid ();
        pid_t pid2 = fork ();
        if (pid2 != 0)
          _exit (pid2 < 0 ? 1 : 0);
        close (pfd[0]);
        /* the daemon must not hold the caller's stdin/stdout (a command
           substitution would otherwise wait on the inherited pipe end);
           stderr is kept until readiness so connect/auth errors surface. */
        {
          int devnull = open ("/dev/null", O_RDWR);
          if (devnull >= 0)
            {
              dup2 (devnull, STDIN_FILENO);
              dup2 (devnull, STDOUT_FILENO);
              if (devnull > 2) close (devnull);
            }
        }
        for (int i = 3; i < 1024; i++)
          if (i != lfd && i != pfd[1]) close (i);
        int id = libssh_connect_session (host, port, user, key, 0, jump);
        libssh_slot *slot = id >= 0 ? libssh_find_slot (id) : NULL;
        if (!slot)
          {
            close (lfd);
            unlink (xp);
            _exit (1);                  /* diagnostics already on stderr */
          }
        {
          ssize_t wr = write (pfd[1], "O", 1);
          (void) wr;
        }
        close (pfd[1]);
        {
          const char *log = getenv ("BASHSSH_MASTER_LOG");
          int efd = -1;
          if (log && *log)
            efd = open (log, O_WRONLY | O_CREAT | O_APPEND, 0600);
          if (efd < 0)
            efd = open ("/dev/null", O_RDWR);
          if (efd >= 0)
            {
              dup2 (efd, STDERR_FILENO);
              if (efd > 2) close (efd);
            }
        }
        bssh_master_loop (slot, lfd, persist, xp);
        _exit (0);
      }
    /* parent: reap the intermediate, then block on daemon readiness */
    close (pfd[1]);
    pfd[1] = -1;
    close (lfd);
    lfd = -1;
    while (waitpid (pid, NULL, 0) < 0 && errno == EINTR)
      ;
    bssh_child_guard_parent_end (&guard);
  }
  {
    char b = 0;
    ssize_t r;
    while ((r = read (pfd[0], &b, 1)) < 0 && errno == EINTR)
      ;
    close (pfd[0]);
    pfd[0] = -1;
    if (r != 1 || b != 'O')
      {
        builtin_error ("master: could not establish the shared session for %s", host);
        goto out;
      }
  }
  frc = bind_or_print (var, xp);        /* the expanded ControlPath */
out:
  for (int i = 0; i < 5; i++)
    if (cfg_env_saved[i]) unsetenv (cfg_env_names[i]);
  return frc;
}
#else
static int master_cmd (WORD_LIST *args)
{
  (void) args;
  builtin_error ("master: libssh transport is not compiled in");
  return EXECUTION_FAILURE;
}
#endif

/* `ssh -O check|exit -S CTLPATH` (also: master-check / master-exit). */
static int master_ctl_cmd (const char *op, WORD_LIST *args)
{
  const char *path = NULL, *w;
  while ((w = next_word (&args)))
    {
      if (!strcmp (w, "-S") && args) path = next_word (&args);
      else if (!strcmp (w, "-o") && args)
        {
          int cm_ignored = -1;
          const char *ov = next_word (&args);
          int hr = bssh_parse_ctl_option (ov, &cm_ignored, &path, NULL);
          if (hr < 0) return EX_USAGE;
          if (hr == 0)
            { builtin_error ("-O %s: unsupported -o option: %s", op, ov ? ov : ""); return EX_USAGE; }
        }
      else if (!path && w[0] != '-') path = w;
      else { builtin_error ("-O %s: unknown arg: %s", op, w); return EX_USAGE; }
    }
  if (!path)
    { builtin_error ("-O %s requires -S CTLPATH", op); return EX_USAGE; }
  if (strchr (path, '%'))
    {
      /* fail-closed: control ops take the already-expanded socket path */
      builtin_error ("-O %s: %% tokens are not resolvable here; pass the expanded ControlPath", op);
      return EXECUTION_FAILURE;
    }
  if (!strcmp (op, "check"))
    {
      char pidbuf[32] = "";
      if (bssh_mux_check (path, pidbuf, sizeof pidbuf) == 0)
        {
          printf ("Master running (pid=%s)\n", pidbuf);
          return EXECUTION_SUCCESS;
        }
      builtin_error ("no live ControlMaster at %s", path);
      return EXECUTION_FAILURE;
    }
  if (!strcmp (op, "exit"))
    {
      if (bssh_mux_terminate (path) == 0)
        {
          printf ("Exit request sent to master at %s\n", path);
          return EXECUTION_SUCCESS;
        }
      builtin_error ("no live ControlMaster at %s", path);
      return EXECUTION_FAILURE;
    }
  builtin_error ("-O expects check or exit");
  return EX_USAGE;
}

static int exec_cmd (WORD_LIST *args)
{
  const char *pos[2] = { NULL, NULL };
  int npos = 0;
  const char *ovar = NULL, *evar = NULL, *rvar = NULL, *ofile = NULL, *efile = NULL, *ifile = NULL, *w;
  const char *ctl_path = NULL;
  int cm_mode = -1;   /* -1 unset, 0 no, 1 yes, 2 auto */
  g_sendenv_n = 0;                            /* reset SendEnv list per exec */
  while ((w = next_word (&args)))
    {
      if (!strcmp (w, "-i") && args) ifile = next_word (&args);
      else if (!strcmp (w, "-S") && args) ctl_path = next_word (&args);
      else if (!strcmp (w, "-o") && args)
        {
          /* -o stays the stdout capture file unless the value is one of the
             bounded ControlMaster client options (Control*=VALUE). */
          const char *ov = next_word (&args);
          int hr = bssh_parse_ctl_option (ov, &cm_mode, &ctl_path, NULL);
          if (hr < 0) return EX_USAGE;
          if (hr == 0) ofile = ov;
        }
      else if (!strcmp (w, "-e") && args) efile = next_word (&args);
      else if ((!strcmp (w, "-R") || !strcmp (w, "-r")) && args) rvar = next_word (&args);
      else if (!strcmp (w, "--setenv") && args)
        {
          const char *kv = next_word (&args);
          if (!kv || !strchr (kv, '=')) { builtin_error ("exec: --setenv needs NAME=VALUE"); return EX_USAGE; }
          if (g_sendenv_n < BASHSSH_MAX_SENDENV) g_sendenv[g_sendenv_n++] = (char *) kv;
        }
      else if (!strcmp (w, "-V") && args)
        {
          if (!ovar) ovar = next_word (&args);
          else if (!evar) evar = next_word (&args);
          else rvar = next_word (&args);
        }
      else if (npos < 2) pos[npos++] = w;
      else { builtin_error ("exec: unknown arg: %s", w); return EX_USAGE; }
    }
  const char *h = NULL, *cmd = NULL;
  if (ctl_path && cm_mode != 0 && npos == 1)
    cmd = pos[0];                       /* exec -S CTLPATH CMD — master only */
  else
    { h = pos[0]; cmd = pos[1]; }
  if (!cmd || (!h && !ctl_path))
    { builtin_error ("exec [-S CTLPATH] HANDLE CMD [-i IN] [-o OUT] [-e ERR] [-V OUT] [-V ERR] [-V RC] [--setenv NAME=VALUE]"); return EX_USAGE; }

  blob out = {0}, err = {0};
  int rc;
  int routed = 0;
  if (ctl_path && cm_mode != 0)
    {
      /* F06 ControlMaster: route this exec through a live master. yes (or no
         HANDLE to fall back to) requires the master; auto with a HANDLE
         falls through to the handle when the socket is not live. */
      char xp[256];
      if (bssh_controlpath_expand (ctl_path, NULL, NULL, NULL, xp, sizeof xp) < 0)
        {
          builtin_error ("exec: bad ControlPath %s (host-dependent %% tokens resolve on connect/master only)", ctl_path);
          return EXECUTION_FAILURE;
        }
      int live = bssh_mux_live (xp);
      if (!live && (cm_mode == 1 || !h))
        {
          builtin_error ("exec: no live ControlMaster at %s", xp);
          return EXECUTION_FAILURE;
        }
      if (live)
        {
          rc = bssh_mux_exec (xp, cmd, ifile, &out, &err);
          routed = 1;
        }
    }
  if (!routed)
    {
      ssh_handle sh;
      if (parse_handle (h, &sh) < 0)
        { builtin_error ("exec: bad handle: %s", h); return EX_USAGE; }
      if (sh.mux)
        rc = bssh_mux_exec (sh.host, cmd, ifile, &out, &err);
      else if (sh.libssh)
        rc = run_libssh_exec (&sh, cmd, ifile, &out, &err);
      else if (sh.openssh)
        rc = run_openssh (&sh, cmd, ifile, &out, &err);
      else if ((!strcmp (sh.host, "localhost") || !strcmp (sh.host, "127.0.0.1")) && !strcmp (sh.port, "0"))
        rc = run_local (cmd, ifile, &out, &err);
      else
        rc = run_remote (sh.host, sh.port, cmd, ifile, &out, &err);
    }
  if (rc < 0) { free (out.p); free (err.p); return EXECUTION_FAILURE; }

  if (ofile && write_file_blob (ofile, &out) < 0) rc = 1;
  if (efile && write_file_blob (efile, &err) < 0) rc = 1;
  if (ovar) builtin_bind_variable ((char *) ovar, out.p ? out.p : "", 0);
  if (evar) builtin_bind_variable ((char *) evar, err.p ? err.p : "", 0);
  if (rvar)
    {
      char rbuf[32];
      snprintf (rbuf, sizeof rbuf, "%d", rc);
      builtin_bind_variable ((char *) rvar, rbuf, 0);
    }
  if (!ofile && !ovar && out.n) fwrite (out.p, 1, out.n, stdout);
  if (!efile && !evar && err.n) fwrite (err.p, 1, err.n, stderr);
  free (out.p); free (err.p);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* Interactive PTY shell on an established (libssh) handle. F06 item 3 slice 3.
   `ssh.sh`'s no-command path calls `ssh shell "$HANDLE" -h SSH_FD`; the
   trailing `-h VAR` is a vestigial fd-bind and is tolerated/ignored. */
static int shell_cmd (WORD_LIST *args)
{
  const char *hs = NULL, *w;
  const char *ctl_path = NULL;
  int cm_mode = -1;
  while ((w = next_word (&args)))
    {
      if (!strcmp (w, "-h") && args) { next_word (&args); }   /* legacy, ignored */
      else if (!strcmp (w, "-S") && args) ctl_path = next_word (&args);
      else if (!strcmp (w, "-o") && args)
        {
          const char *ov = next_word (&args);
          int hr = bssh_parse_ctl_option (ov, &cm_mode, &ctl_path, NULL);
          if (hr < 0) return EX_USAGE;
          if (hr == 0)
            { builtin_error ("shell: unsupported -o option: %s", ov ? ov : ""); return EX_USAGE; }
        }
      else if (!hs) hs = w;
      else { builtin_error ("shell: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (ctl_path && cm_mode != 0)
    {
      /* F06 ControlMaster: PTY shell through a live master */
      char xp[256];
      if (bssh_controlpath_expand (ctl_path, NULL, NULL, NULL, xp, sizeof xp) < 0)
        {
          builtin_error ("shell: bad ControlPath %s (host-dependent %% tokens resolve on connect/master only)", ctl_path);
          return EXECUTION_FAILURE;
        }
      if (bssh_mux_live (xp))
        {
          int rc = bssh_mux_shell (xp);
          return rc < 0 ? EXECUTION_FAILURE : rc;
        }
      if (cm_mode == 1 || !hs)
        {
          builtin_error ("shell: no live ControlMaster at %s", xp);
          return EXECUTION_FAILURE;
        }
      /* auto miss with a HANDLE → fall through to the handle */
    }
  if (!hs) { builtin_error ("shell [-S CTLPATH] HANDLE   (interactive PTY shell on a libssh handle or ControlMaster)"); return EX_USAGE; }
  ssh_handle sh;
  if (parse_handle (hs, &sh) < 0) { builtin_error ("shell: bad handle: %s", hs); return EX_USAGE; }
  if (sh.mux)
    {
      int rc = bssh_mux_shell (sh.host);
      return rc < 0 ? EXECUTION_FAILURE : rc;
    }
  if (!sh.libssh) { builtin_error ("shell: requires an encrypted libssh handle (connect --encrypted)"); return EX_USAGE; }
  int rc = run_libssh_shell (&sh);
  return rc < 0 ? EXECUTION_FAILURE : rc;   /* propagate the remote exit as $? */
}

static int close_cmd (WORD_LIST *args)
{
  const char *h = next_word (&args);
  if (!h || next_word (&args))
    { builtin_error ("close HANDLE"); return EX_USAGE; }
  ssh_handle sh;
  if (parse_handle (h, &sh) < 0)
    { builtin_error ("close: bad handle: %s", h); return EX_USAGE; }
  if (!sh.libssh)
    return EXECUTION_SUCCESS;
#if BASHSSH_HAVE_LIBSSH
  libssh_slot *slot = libssh_find_slot (sh.id);
  if (!slot)
    return EXECUTION_SUCCESS;
  bssh_forward_cancel_handle (sh.id);
  libssh_clear_slot (slot);
  return EXECUTION_SUCCESS;
#else
  builtin_error ("libssh transport is not compiled in");
  return EXECUTION_FAILURE;
#endif
}

static int sftp_cmd (WORD_LIST *args)
{
  const char *h = next_word (&args);
  const char *ctl_path = NULL;
  if (h && !strcmp (h, "-S") && args)
    {
      /* F06 ControlMaster: sftp -S CTLPATH put|get ... through a master */
      ctl_path = next_word (&args);
      h = NULL;
    }
  const char *op = next_word (&args);
  unsigned int mode = 0600;
  const char *progress_var = NULL;
  if ((!h && !ctl_path) || (h && (!strcmp (h, "--help") || !strcmp (h, "-h"))))
    {
      puts ("sftp HANDLE|-S CTLPATH put LOCAL REMOTE [--mode 0NNN] [-V PROGRESS]");
      puts ("sftp HANDLE|-S CTLPATH get REMOTE LOCAL");
      return h ? EXECUTION_SUCCESS : EX_USAGE;
    }
  if (!op)
    {
      builtin_error ("sftp HANDLE|-S CTLPATH put LOCAL REMOTE [--mode 0NNN] | get REMOTE LOCAL");
      return EX_USAGE;
    }
  ssh_handle sh;
  memset (&sh, 0, sizeof sh);
  if (ctl_path)
    {
      char xp[256];
      if (bssh_controlpath_expand (ctl_path, NULL, NULL, NULL, xp, sizeof xp) < 0)
        {
          builtin_error ("sftp: bad ControlPath %s (host-dependent %% tokens resolve on connect/master only)", ctl_path);
          return EXECUTION_FAILURE;
        }
      if (!bssh_mux_live (xp))
        {
          builtin_error ("sftp: no live ControlMaster at %s", xp);
          return EXECUTION_FAILURE;
        }
      sh.mux = 1;
      snprintf (sh.host, sizeof sh.host, "%s", xp);
    }
  else if (parse_handle (h, &sh) < 0)
    {
      builtin_error ("sftp: bad handle: %s", h);
      return EX_USAGE;
    }
  if (!sh.libssh && !sh.mux)
    {
      builtin_error ("sftp: requires a libssh:// encrypted handle or -S CTLPATH");
      return EXECUTION_FAILURE;
    }
  if (!strcasecmp (op, "put"))
    {
      const char *local = next_word (&args);
      const char *remote = next_word (&args);
      const char *w;
      if (!local || !remote)
        {
          builtin_error ("sftp put: LOCAL REMOTE required");
          return EX_USAGE;
        }
      while ((w = next_word (&args)))
        {
          if (!strcmp (w, "--mode") && args)
            {
              char *end = NULL;
              unsigned long v = strtoul (next_word (&args), &end, 8);
              if (!end || *end || v > 0777)
                {
                  builtin_error ("sftp put: --mode expects an octal mode");
                  return EX_USAGE;
                }
              mode = (unsigned int) v;
            }
          else if (!strcmp (w, "-V") && args)
            progress_var = next_word (&args);
          else
            {
              builtin_error ("sftp put: unknown arg: %s", w);
              return EX_USAGE;
            }
        }
      int rc = sh.mux ? bssh_mux_sftp_put (sh.host, local, remote, mode)
                      : libssh_sftp_put (&sh, local, remote, mode);
      if (progress_var)
        builtin_bind_variable ((char *) progress_var, rc == 0 ? "done" : "failed", 0);
      return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  if (!strcasecmp (op, "get"))
    {
      const char *remote = next_word (&args);
      const char *local = next_word (&args);
      if (!remote || !local || next_word (&args))
        {
          builtin_error ("sftp get: REMOTE LOCAL required");
          return EX_USAGE;
        }
      int rc = sh.mux ? bssh_mux_sftp_get (sh.host, remote, local)
                      : libssh_sftp_get (&sh, remote, local);
      return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  builtin_error ("sftp: unknown operation: %s", op);
  return EX_USAGE;
}

static int forward_cmd (WORD_LIST *args)
{
  const char *h = next_word (&args);
  if (!h || !strcmp (h, "--help") || !strcmp (h, "-h"))
    {
      puts ("forward HANDLE -L LADDR:LPORT:RADDR:RPORT");
      puts ("forward HANDLE -R RADDR:RPORT:LADDR:LPORT");
      puts ("forward HANDLE --list | --cancel ID");
      return h ? EXECUTION_SUCCESS : EX_USAGE;
    }
  ssh_handle sh;
  if (parse_handle (h, &sh) < 0)
    {
      builtin_error ("forward: bad handle: %s", h);
      return EX_USAGE;
    }
  const char *w = next_word (&args);
  if (!w)
    {
      builtin_error ("forward: -L, -R, --list, or --cancel required");
      return EX_USAGE;
    }
  if (!strcmp (w, "--list"))
    {
#if BASHSSH_HAVE_LIBSSH
      if (sh.libssh)
        bssh_forward_list (sh.id);
#endif
      return EXECUTION_SUCCESS;
    }
  if (!strcmp (w, "--cancel") && args)
    {
      const char *idstr = next_word (&args);
      char *end = NULL;
      long id = strtol (idstr, &end, 10);
      if (end == idstr || *end || id <= 0)
        { builtin_error ("forward: --cancel requires ID"); return EX_USAGE; }
#if BASHSSH_HAVE_LIBSSH
      return bssh_forward_cancel ((int) id) == 0
             ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
#else
      builtin_error ("forward: no active forwards");
      return EXECUTION_FAILURE;
#endif
    }
  if (!strcmp (w, "-L") || !strcmp (w, "-R"))
    {
      if (!sh.libssh)
        {
          builtin_error ("forward: requires a libssh:// encrypted handle");
          return EXECUTION_FAILURE;
        }
      const char *spec = next_word (&args);
      if (!spec)
        {
          builtin_error ("forward: %s requires an address spec", w);
          return EX_USAGE;
        }
      if (!strcmp (w, "-L"))
        return bssh_forward_spawn_local (&sh, spec) == 0
               ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
      return bssh_forward_spawn_remote (&sh, spec) == 0
             ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  builtin_error ("forward: unknown arg: %s", w);
  return EX_USAGE;
}

int ssh_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = next_word (&list);
  if (!strcmp (cmd, "keygen")) return keygen_cmd (list);
  if (!strcmp (cmd, "keyscan")) return keyscan_cmd (list);
  if (!strcmp (cmd, "known-hosts")) return known_hosts_cmd (list);
  if (!strcmp (cmd, "connect")) return connect_cmd (list);
  if (!strcmp (cmd, "exec")) return exec_cmd (list);
  if (!strcmp (cmd, "sftp")) return sftp_cmd (list);
  if (!strcmp (cmd, "forward")) return forward_cmd (list);
  if (!strcmp (cmd, "shell")) return shell_cmd (list);
  if (!strcmp (cmd, "close")) return close_cmd (list);
  if (!strcmp (cmd, "master")) return master_cmd (list);
  if (!strcmp (cmd, "master-check")) return master_ctl_cmd ("check", list);
  if (!strcmp (cmd, "master-exit")) return master_ctl_cmd ("exit", list);
  if (!strcmp (cmd, "-O"))
    {
      const char *op = next_word (&list);
      if (op && (!strcmp (op, "check") || !strcmp (op, "exit")))
        return master_ctl_cmd (op, list);
      builtin_error ("-O expects check or exit");
      return EX_USAGE;
    }
  builtin_error ("unknown verb: %s", cmd);
  return EX_USAGE;
}

char *ssh_doc[] = {
  "ssh command-stream, libssh, and OpenSSH-backed client",
  "connect HOST [-p PORT] [-l USER] [-i KEY] [--native|--encrypted|--openssh] [-h VAR]",
  "connect HOST ... [-A|--forward-agent]  request agent forwarding on encrypted exec channels",
  "keyscan HOST [-p PORT] [-t TYPES] [-T TIMEOUT] [-H]",
  "exec HANDLE CMD [-i INFILE] [-o OUTFILE] [-e ERRFILE] [-V OUT] [-V ERR] [-V RC]",
  "sftp HANDLE put LOCAL REMOTE [--mode 0NNN] [-V PROGRESS]",
  "sftp HANDLE get REMOTE LOCAL",
  "forward HANDLE -L LADDR:LPORT:RADDR:RPORT | -R RADDR:RPORT:LADDR:LPORT | --list | --cancel ID",
  "close HANDLE",
  "master HOST [-p PORT] [-l USER] [-i KEY] [-F CONFIG] [-J jump] -S CTLPATH [--persist N|no]",
  "  (encrypted-only ControlMaster daemon; %h %p %r %C tokens in CTLPATH, fail-closed otherwise)",
  "exec|shell|sftp -S CTLPATH ...           route one operation through a live master",
  "connect ... [-S CTLPATH] [-o ControlMaster=auto|yes|no] [-o ControlPath=P]",
  "  (auto miss falls through to a direct process-local connect)",
  "-O check|exit -S CTLPATH                 probe or terminate a master (master-check/master-exit)",
  "known-hosts add HOST KEY",
  "known-hosts verify HOST [KEY] [-V RC]   (rc 0 match, 1 mismatch, 2 unknown)",
  "known-hosts list [HOST]                  (rc 0 if any matched / no filter, 1 if filtered no-match)",
  "known-hosts remove HOST                  (idempotent; rewrites file, preserves comments/blanks)",
  NULL
};
struct builtin ssh_struct = {
  "ssh", ssh_builtin, BUILTIN_ENABLED, ssh_doc,
  "ssh <verb> [args...]", 0
};
