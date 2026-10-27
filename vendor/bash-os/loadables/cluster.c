/* SPDX-License-Identifier: MIT */
/* Local, authenticated membership. One listener is owned by the shell that
 * initializes/joins; the seed owns the roster. See docs/sol-cluster.md. */
#include <config.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include "loadables.h"
#include "child-wait.h"
#include "_monocypher_monocypher.h"

#define BC_MAX 32
#define BC_DEFAULT_DIR "/var/lib/cluster"
#define BC_FILES "cluster_id", "node_id", "port", "listener_pid", "private_key", "members", "state"
enum { BC_JOIN = 1, BC_BEAT, BC_LEAVE, BC_PING, BC_STOP, BC_ROSTER, BC_PONG, BC_ERROR };
/* Byte arrays avoid ABI padding and host byte order. All packets have this
 * exact size; the MAC covers everything preceding mac, including unused rows. */
typedef struct { unsigned char node[32], port[2]; } bc_row;
typedef struct {
  unsigned char magic[8], type, count, port[2], nonce[16], cluster[32], node[32];
  bc_row rows[BC_MAX];
  unsigned char mac[32];
} bc_packet;
typedef struct {
  char dir[PATH_MAX], cluster[33], node[33];
  unsigned char key[32];
  bc_row rows[BC_MAX];
  int count, port, seed, timeout, fd, lock, connected;
  struct sockaddr_in root;
  int64_t seen[BC_MAX], last_reply;
} bc_state;
static volatile sig_atomic_t bc_running;

static int64_t
bc_now (void)
{
  struct timespec t;
  clock_gettime (CLOCK_MONOTONIC, &t);
  return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static const char *
bc_word (WORD_LIST **list)
{
  const char *s;
  if (!list || !*list || !(*list)->word) return NULL;
  s = (*list)->word->word; *list = (*list)->next;
  return s;
}

static int
bc_number (const char *s, int min, int max)
{
  unsigned long n = 0;
  if (!s || !*s) return -1;
  for (; *s; s++) {
    if (*s < '0' || *s > '9') return -1;
    n = n * 10 + (*s - '0');
    if (n > (unsigned)max) return -1;
  }
  return n >= (unsigned)min ? (int)n : -1;
}

static int
bc_setup (bc_state *s)
{
  const char *d = getenv ("BASHCLUSTER_STATE_DIR"), *t;
  char cwd[PATH_MAX];
  int n;
  memset (s, 0, sizeof *s); s->fd = s->lock = -1;
  if (!d || !*d) d = BC_DEFAULT_DIR;
  if (*d == '/') n = snprintf (s->dir, sizeof s->dir, "%s", d);
  else {
    if (!getcwd (cwd, sizeof cwd)) return -1;
    n = snprintf (s->dir, sizeof s->dir, "%s/%s", cwd, d);
  }
  if (n < 0 || n >= (int)sizeof s->dir) return -1;
  /* Bash may reuse or free its getenv buffer for temporary assignments.
     Finish copying the directory before looking up another variable. */
  t = getenv ("BASHCLUSTER_TIMEOUT_MS");
  s->timeout = t ? bc_number (t, 50, 5000) : 500;
  return s->timeout < 0 ? -1 : 0;
}

static int
bc_path (bc_state *s, char *out, size_t size, const char *name)
{
  int n = snprintf (out, size, "%s/%s", s->dir, name);
  return n > 0 && (size_t)n < size ? 0 : -1;
}

static int
bc_read (bc_state *s, const char *name, char *buf, size_t size)
{
  char path[PATH_MAX];
  FILE *f;
  size_t n;
  int bad;
  if (bc_path (s, path, sizeof path, name) < 0 || !(f = fopen (path, "r"))) return -1;
  n = fread (buf, 1, size - 1, f);
  bad = ferror (f) || fgetc (f) != EOF;
  if (ferror (f)) bad = 1;
  if (fclose (f)) bad = 1;
  buf[n] = 0;
  while (n && (buf[n-1] == '\n' || buf[n-1] == '\r')) buf[--n] = 0;
  return bad ? -1 : 0;
}

static int
bc_write (bc_state *s, const char *name, const char *buf)
{
  char path[PATH_MAX], tmp[PATH_MAX];
  FILE *f;
  int fd, bad;
  if (bc_path (s, path, sizeof path, name) < 0 ||
      snprintf (tmp, sizeof tmp, "%s/.%s.tmp", s->dir, name) >= (int)sizeof tmp) return -1;
  fd = open (tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) return -1;
  if (!(f = fdopen (fd, "w"))) { close (fd); unlink (tmp); return -1; }
  bad = fputs (buf, f) == EOF;
  if (fclose (f)) bad = 1;
  if (!bad && rename (tmp, path) == 0) return 0;
  unlink (tmp); return -1;
}

static void
bc_cleanup (bc_state *s)
{
  const char *names[] = { BC_FILES, NULL };
  char path[PATH_MAX];
  for (int i = 0; names[i]; i++)
    {
      if (bc_path (s, path, sizeof path, names[i]) == 0) unlink (path);
      /* Recover our own atomic-write scratch files after SIGKILL as well. */
      int n = snprintf (path, sizeof path, "%s/.%s.tmp", s->dir, names[i]);
      if (n > 0 && n < (int)sizeof path) unlink (path);
    }
}

static int
bc_random (void *data, size_t n)
{
  unsigned char *p = data;
  while (n) {
    ssize_t r = getrandom (p, n, 0);
    if (r < 0 && errno == EINTR) continue;
    if (r <= 0) return -1;
    p += r; n -= r;
  }
  return 0;
}

static void
bc_hex (char *out, const unsigned char *in, int n)
{
  static const char h[] = "0123456789abcdef";
  for (int i = 0; i < n; i++) { out[2*i] = h[in[i] >> 4]; out[2*i+1] = h[in[i] & 15]; }
  out[2*n] = 0;
}

static int
bc_unhex (unsigned char *out, const char *in, int n)
{
  for (int i = 0; i < n; i++) {
    int a, b;
    a = in[2*i] >= '0' && in[2*i] <= '9' ? in[2*i]-'0' :
        in[2*i] >= 'a' && in[2*i] <= 'f' ? in[2*i]-'a'+10 : -1;
    b = in[2*i+1] >= '0' && in[2*i+1] <= '9' ? in[2*i+1]-'0' :
        in[2*i+1] >= 'a' && in[2*i+1] <= 'f' ? in[2*i+1]-'a'+10 : -1;
    if (a < 0 || b < 0) return -1;
    out[i] = a*16 + b;
  }
  return 0;
}

static int
bc_key (bc_state *s, const char *path)
{
  char text[67];
  FILE *f;
  struct stat st;
  size_t n;
  int fd = open (path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0) return -1;
  if (fstat (fd, &st) || !S_ISREG (st.st_mode)) { close (fd); return -1; }
  f = fdopen (fd, "r");
  if (!f) { close (fd); return -1; }
  n = fread (text, 1, sizeof text, f);
  int bad = ferror (f); fclose (f);
  if (bad || (n != 64 && !(n == 65 && text[64] == '\n'))) return -1;
  return bc_unhex (s->key, text, 32);
}

static void bc_port_set (unsigned char p[2], int port) { p[0] = port >> 8; p[1] = port; }
static int bc_port_get (const unsigned char p[2]) { return p[0]*256 + p[1]; }

static int
bc_endpoint (const char *text, struct sockaddr_in *a)
{
  /* Numeric loopback avoids unbounded resolver work and accidental remote use. */
  const char *p;
  int port;
  if (!text || strncmp (text, "127.0.0.1:", 10)) return -1;
  p = text + 10; port = bc_number (p, 1, 65535);
  if (port < 0) return -1;
  memset (a, 0, sizeof *a); a->sin_family = AF_INET;
  a->sin_addr.s_addr = htonl (INADDR_LOOPBACK); a->sin_port = htons (port);
  return 0;
}

static void
bc_packet_init (bc_state *s, bc_packet *p, int type)
{
  memset (p, 0, sizeof *p); memcpy (p->magic, "BCLSTR2", 8);
  p->type = type; memcpy (p->cluster, s->cluster, 32); memcpy (p->node, s->node, 32);
  bc_port_set (p->port, s->port);
}

static int
bc_send (bc_state *s, bc_packet *p, const struct sockaddr_in *to)
{
  crypto_blake2b_keyed (p->mac, 32, s->key, 32, (unsigned char *)p, sizeof *p - 32);
  return sendto (s->fd, p, sizeof *p, MSG_NOSIGNAL, (const struct sockaddr *)to, sizeof *to) == sizeof *p ? 0 : -1;
}

static int
bc_receive (bc_state *s, bc_packet *p, struct sockaddr_in *from)
{
  unsigned char bytes[sizeof *p + 1], mac[32];
  socklen_t len = sizeof *from;
  ssize_t n = recvfrom (s->fd, bytes, sizeof bytes, MSG_DONTWAIT, (struct sockaddr *)from, &len);
  if (n != sizeof *p || len != sizeof *from || from->sin_addr.s_addr != htonl (INADDR_LOOPBACK)) return -1;
  memcpy (p, bytes, sizeof *p);
  if (memcmp (p->magic, "BCLSTR2", 8) || p->count > BC_MAX) return -1;
  crypto_blake2b_keyed (mac, 32, s->key, 32, bytes, sizeof *p - 32);
  return crypto_verify32 (mac, p->mac);
}

static int
bc_socket (int port)
{
  int fd = socket (AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  struct sockaddr_in a;
  if (fd < 0) return -1;
  memset (&a, 0, sizeof a); a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl (INADDR_LOOPBACK); a.sin_port = htons (port);
  if (bind (fd, (struct sockaddr *)&a, sizeof a)) { close (fd); return -1; }
  return fd;
}

static int
bc_rpc (bc_state *s, bc_packet *request, bc_packet *reply, struct sockaddr_in *to, int type)
{
  int64_t end = bc_now () + s->timeout;
  struct pollfd f = { s->fd, POLLIN, 0 };
  struct sockaddr_in from;
  if (bc_random (request->nonce, sizeof request->nonce) < 0 || bc_send (s, request, to) < 0) return -1;
  while (bc_now () < end) {
    int remaining = (int)(end - bc_now ());
    if (remaining <= 0) break;
    int n = poll (&f, 1, remaining);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) break;
    if (bc_receive (s, reply, &from) == 0 && from.sin_port == to->sin_port &&
        !memcmp (reply->nonce, request->nonce, 16) && reply->type == type) return 0;
  }
  errno = ETIMEDOUT; return -1;
}

static int
bc_roster_write (bc_state *s)
{
  char text[BC_MAX * 64], node[33];
  size_t used = 0;
  for (int i = 0; i < s->count; i++) {
    memcpy (node, s->rows[i].node, 32); node[32] = 0;
    used += snprintf (text + used, sizeof text - used, "%s 127.0.0.1:%d\n", node, bc_port_get (s->rows[i].port));
  }
  return bc_write (s, "members", text);
}

static int
bc_snapshot (bc_state *s, bc_packet *p)
{
  unsigned char check[16];
  int own = 0;
  char id[33];
  if (!p->count || memcmp (s->cluster, p->cluster, 32)) return -1;
  for (int i = 0; i < p->count; i++) {
    memcpy (id, p->rows[i].node, 32); id[32] = 0;
    if (bc_unhex (check, id, 16) || !bc_port_get (p->rows[i].port)) return -1;
    for (int j = 0; j < i; j++)
      if (!memcmp (p->rows[i].node, p->rows[j].node, 32) || !memcmp (p->rows[i].port, p->rows[j].port, 2)) return -1;
    if (!memcmp (p->rows[i].node, s->node, 32) && bc_port_get (p->rows[i].port) == s->port) own = 1;
  }
  if (!own || bc_port_get (p->rows[0].port) != ntohs (s->root.sin_port)) return -1;
  if (s->count != p->count || memcmp (s->rows, p->rows, p->count * sizeof (bc_row))) {
    s->count = p->count; memcpy (s->rows, p->rows, s->count * sizeof (bc_row));
    if (bc_roster_write (s)) return -1;
  }
  s->last_reply = bc_now ();
  if (!s->connected && bc_write (s, "state", "initialized\n")) return -1;
  s->connected = 1;
  return 0;
}

static void
bc_remove (bc_state *s, int i)
{
  s->count--;
  memmove (&s->rows[i], &s->rows[i+1], (s->count-i)*sizeof (bc_row));
  memmove (&s->seen[i], &s->seen[i+1], (s->count-i)*sizeof (int64_t));
}

static int
bc_handle (bc_state *s)
{
  bc_packet p, reply;
  struct sockaddr_in from;
  int i, changed = 0;
  unsigned char id[16];
  char node[33];
  if (bc_receive (s, &p, &from)) return 0;
  if (p.count != 0) return 0;
  memcpy (node, p.node, 32); node[32] = 0;
  if (bc_unhex (id, node, 16)) return 0;
  if (p.type != BC_JOIN && memcmp (p.cluster, s->cluster, 32)) return 0;
  bc_packet_init (s, &reply, BC_ERROR); memcpy (reply.nonce, p.nonce, 16);
  if (p.type == BC_PING) reply.type = BC_PONG;
  else if (p.type == BC_STOP && !memcmp (p.node, s->node, 32)) {
    reply.type = BC_PONG; bc_running = 0;
  }
  else if (s->seed && (p.type == BC_JOIN || p.type == BC_BEAT || p.type == BC_LEAVE)) {
    if (bc_port_get (p.port) != ntohs (from.sin_port)) return 0;
    for (i = 0; i < s->count; i++) if (!memcmp (p.node, s->rows[i].node, 32)) break;
    if (i == 0) return 0;
    if (p.type == BC_LEAVE) {
      if (i < s->count && !memcmp (p.port, s->rows[i].port, 2)) { bc_remove (s, i); changed = 1; }
      reply.type = BC_PONG;
    } else {
      if (p.type == BC_JOIN) {
        static const unsigned char zero[32];
        if (memcmp (p.cluster, zero, 32) && memcmp (p.cluster, s->cluster, 32)) return 0;
      }
      /* A node cannot silently move another member's endpoint. */
      if (i < s->count && memcmp (p.port, s->rows[i].port, 2)) return 0;
      for (int j = 0; j < s->count; j++)
        if (j != i && !memcmp (p.port, s->rows[j].port, 2)) return 0;
      if (i == s->count) {
        if (s->count == BC_MAX) return bc_send (s, &reply, &from);
        s->count++; memcpy (s->rows[i].node, p.node, 32); memcpy (s->rows[i].port, p.port, 2); changed = 1;
      }
      s->seen[i] = bc_now ();
      reply.type = BC_ROSTER; reply.count = s->count;
      memcpy (reply.rows, s->rows, s->count * sizeof (bc_row));
    }
  }
  if (changed && bc_roster_write (s)) return -1;
  return bc_send (s, &reply, &from);
}

static void bc_signal (int sig) { (void)sig; bc_running = 0; }

static void
bc_close_inherited (int fd, int lock, int ready)
{
  DIR *d = opendir ("/proc/self/fd");
  struct dirent *e;
  if (d) {
    while ((e = readdir (d))) {
      int n = bc_number (e->d_name, 0, INT_MAX);
      if (n >= 0 && n != fd && n != lock && n != ready && n != dirfd (d)) close (n);
    }
    closedir (d);
  } else {
    long maxfd = sysconf (_SC_OPEN_MAX);
    for (int n = 0; n < maxfd; n++) if (n != fd && n != lock && n != ready) close (n);
  }
  int devnull = open ("/dev/null", O_RDWR);
  if (devnull >= 0) {
    for (int n = 0; n < 3; n++) if (n != fd && n != lock && n != ready) dup2 (devnull, n);
    if (devnull > 2) close (devnull);
  }
}

static int
bc_persist (bc_state *s)
{
  char buf[80];
  if (bc_write (s, "cluster_id", s->cluster) || bc_write (s, "node_id", s->node)) return -1;
  snprintf (buf, sizeof buf, "%d\n", s->port); if (bc_write (s, "port", buf)) return -1;
  snprintf (buf, sizeof buf, "%ld\n", (long)getpid ()); if (bc_write (s, "listener_pid", buf)) return -1;
  bc_hex (buf, s->key, 32); if (bc_write (s, "private_key", buf)) return -1;
  return bc_roster_write (s) || bc_write (s, "state", "initialized\n") ? -1 : 0;
}

static void
bc_service (bc_state *s, int ready, pid_t owner)
{
  bc_packet request, reply;
  int ok = 0;
  int64_t next = 0;
  struct sigaction act;
  memset (&act, 0, sizeof act); act.sa_handler = bc_signal; sigemptyset (&act.sa_mask);
  sigaction (SIGTERM, &act, NULL); sigaction (SIGINT, &act, NULL); sigaction (SIGHUP, &act, NULL);
  signal (SIGCHLD, SIG_DFL); signal (SIGPIPE, SIG_IGN);
  bc_running = 1;
  if (prctl (PR_SET_PDEATHSIG, SIGTERM) < 0 || getppid () != owner) bc_running = 0;
  bc_close_inherited (s->fd, s->lock, ready);
  if (s->seed) ok = 1;
  else if (bc_running) {
    bc_packet_init (s, &request, BC_JOIN);
    if (bc_rpc (s, &request, &reply, &s->root, BC_ROSTER) == 0) {
      memcpy (s->cluster, reply.cluster, 32); s->cluster[32] = 0;
      ok = bc_snapshot (s, &reply) == 0;
    }
  }
  if (!bc_running || (ok && bc_persist (s))) ok = 0;
  char result = ok ? '1' : '0';
  if (write (ready, &result, 1) != 1) ok = 0;
  close (ready);
  s->last_reply = bc_now ();
  while (ok && bc_running) {
    int64_t now = bc_now ();
    if (now >= next) {
      next = now + s->timeout/4;
      if (s->seed) {
        int changed = 0;
        for (int i = s->count-1; i > 0; i--)
          if (now - s->seen[i] >= 3*s->timeout) { bc_remove (s, i); changed = 1; }
        if (changed && bc_roster_write (s)) break;
      } else {
        bc_packet_init (s, &request, BC_BEAT);
        if (bc_random (request.nonce, 16) || bc_send (s, &request, &s->root)) break;
        if (now - s->last_reply >= 3*s->timeout && s->count != 1) {
          memcpy (s->rows[0].node, s->node, 32); bc_port_set (s->rows[0].port, s->port); s->count = 1;
          s->connected = 0;
          if (bc_roster_write (s) || bc_write (s, "state", "disconnected\n")) break;
        }
      }
    }
    struct pollfd pfd = { s->fd, POLLIN, 0 };
    int wait = (int)(next - bc_now ()); if (wait < 0) wait = 0;
    int n = poll (&pfd, 1, wait);
    if (n < 0 && errno != EINTR) break;
    if (n > 0) {
      if (!s->seed) {
        struct sockaddr_in from;
        /* Peek only to dispatch; all actual receives verify size and MAC. */
        unsigned char head[9];
        ssize_t got = recv (s->fd, head, sizeof head, MSG_PEEK | MSG_DONTWAIT);
        if (got == sizeof head && head[8] == BC_ROSTER) {
          if (bc_receive (s, &reply, &from) == 0 && from.sin_port == s->root.sin_port &&
              !memcmp (reply.nonce, request.nonce, 16) && bc_snapshot (s, &reply) < 0) break;
          continue;
        }
      }
      if (bc_handle (s) < 0 && errno != ECONNREFUSED) break;
    }
  }
  if (!s->seed && s->cluster[0]) {
    bc_packet_init (s, &request, BC_LEAVE); bc_send (s, &request, &s->root);
  }
  bc_cleanup (s); close (s->fd); close (s->lock); crypto_wipe (s->key, 32);
  _exit (ok ? 0 : 1);
}

static int
bc_lock (bc_state *s, int create)
{
  char path[PATH_MAX];
  if (bc_path (s, path, sizeof path, "lock")) return -1;
  s->lock = open (path, O_RDWR | O_CLOEXEC | O_NOFOLLOW | (create ? O_CREAT : 0), 0600);
  if (s->lock < 0) return -1;
  if (flock (s->lock, LOCK_EX | LOCK_NB)) { close (s->lock); s->lock = -1; return -1; }
  return 0;
}

static int
bc_load (bc_state *s)
{
  char port[32], path[PATH_MAX];
  if (bc_read (s, "cluster_id", s->cluster, sizeof s->cluster) || strlen (s->cluster) != 32 ||
      bc_read (s, "node_id", s->node, sizeof s->node) || strlen (s->node) != 32 ||
      bc_read (s, "port", port, sizeof port) || (s->port = bc_number (port, 1, 65535)) < 0 ||
      bc_path (s, path, sizeof path, "private_key") || bc_key (s, path)) return -1;
  return 0;
}

static int
bc_start (bc_state *s, WORD_LIST *args, int seed)
{
  const char *w, *key = NULL, *peer = NULL;
  int port = seed ? 5450 : 0, pipefd[2];
  unsigned char random[16];
  struct stat st;
  pid_t child;
  if (!seed) {
    peer = bc_word (&args);
    if (bc_endpoint (peer, &s->root)) { builtin_error ("join needs 127.0.0.1:PORT"); return EX_USAGE; }
  }
  while ((w = bc_word (&args))) {
    if (!strcmp (w, "-p") || !strcmp (w, "--port")) {
      if ((port = bc_number (bc_word (&args), 0, 65535)) < 0) return EX_USAGE;
    } else if (!strcmp (w, "-k") || !strcmp (w, "--key")) {
      if (!(key = bc_word (&args))) return EX_USAGE;
    } else return EX_USAGE;
  }
  /* Reject a duplicate join before touching the live roster. */
  if (!seed && !bc_load (s)) {
    builtin_error ("already initialized; leave before joining again"); return EXECUTION_FAILURE;
  }
  if (key) {
    if (bc_key (s, key)) { builtin_error ("key must contain 64 lowercase hexadecimal digits"); return EXECUTION_FAILURE; }
  } else if (seed) {
    if (bc_random (s->key, 32)) return EXECUTION_FAILURE;
  } else { builtin_error ("join requires -k KEYFILE"); return EX_USAGE; }
  if (mkdir (s->dir, 0700) && errno != EEXIST) goto fail;
  if (lstat (s->dir, &st) || !S_ISDIR (st.st_mode) || st.st_uid != geteuid () || (st.st_mode & 077)) {
    builtin_error ("state directory must be owned and private (0700)"); return EXECUTION_FAILURE;
  }
  if (bc_lock (s, 1)) { builtin_error ("state directory already has a listener"); return EXECUTION_FAILURE; }
  bc_cleanup (s);
  memset (s->cluster, 0, sizeof s->cluster);
  s->fd = bc_socket (port);
  if (s->fd < 0) goto fail;
  struct sockaddr_in local; socklen_t len = sizeof local;
  if (getsockname (s->fd, (struct sockaddr *)&local, &len)) goto fail;
  s->port = ntohs (local.sin_port); s->seed = seed;
  if (bc_random (random, 16)) goto fail;
  bc_hex (s->node, random, 16);
  if (seed) {
    if (bc_random (random, 16)) goto fail;
    bc_hex (s->cluster, random, 16);
    s->count = 1; memcpy (s->rows[0].node, s->node, 32); bc_port_set (s->rows[0].port, s->port);
  }
  if (pipe2 (pipefd, O_CLOEXEC)) goto fail;
  fflush (NULL);
  bos_child_wait waiting;
  if (bos_child_wait_begin (&waiting) < 0) {
    close (pipefd[0]); close (pipefd[1]); goto fail;
  }
  pid_t owner = getpid ();
  child = fork ();
  if (child == 0) {
    bos_child_wait_child (&waiting);
    close (pipefd[0]); bc_service (s, pipefd[1], owner);
  }
  close (pipefd[1]);
  if (child < 0) {
    close (pipefd[0]); bos_child_wait_end (&waiting); goto fail;
  }
  close (s->fd); s->fd = -1; close (s->lock); s->lock = -1;
  struct pollfd pfd = { pipefd[0], POLLIN, 0 };
  char result = 0;
  int polled;
  do { polled = poll (&pfd, 1, s->timeout + 2000); } while (polled < 0 && errno == EINTR);
  if (polled > 0) { if (read (pipefd[0], &result, 1) != 1) result = 0; }
  close (pipefd[0]);
  if (result != '1') {
    /* SIGCHLD is still blocked with default disposition: Bash cannot have
       reaped this raw child, so even an exited child's PID remains ours.
       Never derive a signal target from a state file. */
    kill (child, SIGTERM);
    while (waitpid (child, NULL, 0) < 0 && errno == EINTR) {}
    bos_child_wait_end (&waiting);
    builtin_error ("membership handshake failed or timed out"); return EXECUTION_FAILURE;
  }
  /* A successful service stays alive; release pending unrelated job signals
     back to Bash with its original handler and mask restored. */
  bos_child_wait_end (&waiting);
  if (bc_read (s, "cluster_id", s->cluster, sizeof s->cluster)) return EXECUTION_FAILURE;
  printf ("%s\ncluster_id=%s\nnode_id=%s\nport=%d\nlistener_pid=%ld\n",
          seed ? "initialized" : "joined", s->cluster, s->node, s->port, (long)child);
  return EXECUTION_SUCCESS;
fail:
  builtin_error ("cannot start membership: %s", strerror (errno));
  if (s->fd >= 0) close (s->fd);
  if (s->lock >= 0) close (s->lock);
  return EXECUTION_FAILURE;
}

static int
bc_members (bc_state *s)
{
  char path[PATH_MAX], buf[4096];
  FILE *f;
  size_t n;
  int bad = 0;
  if (bc_path (s, path, sizeof path, "members")) return EXECUTION_FAILURE;
  f = fopen (path, "r");
  if (!f) return errno == ENOENT ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  while ((n = fread (buf, 1, sizeof buf, f))) if (fwrite (buf, 1, n, stdout) != n) { bad = 1; break; }
  if (ferror (f)) bad = 1;
  if (fclose (f)) bad = 1;
  return bad ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
bc_status (bc_state *s)
{
  char state[32], pid[32], port[32], cluster[80], node[80];
  if (bc_read (s, "cluster_id", cluster, sizeof cluster)) { printf ("state=uninitialized\nstate_dir=%s\n", s->dir); return 0; }
  if (bc_read (s, "state", state, sizeof state)) strcpy (state, "stopped");
  if (bc_lock (s, 0) == 0) { close (s->lock); s->lock = -1; strcpy (state, "stopped"); }
  else if (errno != EWOULDBLOCK && errno != EAGAIN) strcpy (state, "stopped");
  if (bc_read (s, "node_id", node, sizeof node) || bc_read (s, "port", port, sizeof port) || bc_read (s, "listener_pid", pid, sizeof pid)) return EXECUTION_FAILURE;
  printf ("state=%s\nstate_dir=%s\ncluster_id=%s\nnode_id=%s\nport=%s\nlistener_pid=%s\n", state, s->dir, cluster, node, port, pid);
  return 0;
}

static int
bc_contact (bc_state *s, const char *target, int stop)
{
  bc_packet request, reply;
  struct sockaddr_in to;
  char endpoint[64];
  int ok;
  if (bc_load (s)) { builtin_error ("no initialized membership"); return EXECUTION_FAILURE; }
  if (stop) { snprintf (endpoint, sizeof endpoint, "127.0.0.1:%d", s->port); target = endpoint; }
  if (bc_endpoint (target, &to)) {
    char path[PATH_MAX], line[128], node[64], host[64];
    FILE *f;
    int found = 0;
    if (bc_path (s, path, sizeof path, "members") || !(f = fopen (path, "r"))) return EXECUTION_FAILURE;
    while (fgets (line, sizeof line, f))
      if (sscanf (line, "%63s %63s", node, host) == 2 && !strcmp (node, target) && !bc_endpoint (host, &to)) { found = 1; break; }
    fclose (f);
    if (!found) { builtin_error ("unknown node or invalid endpoint: %s", target); return EXECUTION_FAILURE; }
  }
  s->fd = bc_socket (0); if (s->fd < 0) return EXECUTION_FAILURE;
  bc_packet_init (s, &request, stop ? BC_STOP : BC_PING);
  ok = bc_rpc (s, &request, &reply, &to, BC_PONG) == 0 && !memcmp (reply.cluster, s->cluster, 32);
  close (s->fd); s->fd = -1;
  if (!ok) { builtin_error ("membership request timed out: %s", target); return EXECUTION_FAILURE; }
  if (stop) {
    int64_t end = bc_now () + s->timeout;
    while (bc_now () < end) {
      if (bc_lock (s, 0) == 0) { bc_cleanup (s); close (s->lock); s->lock = -1; puts ("left cluster"); return 0; }
      struct timespec delay = { 0, 1000000 }; nanosleep (&delay, NULL);
    }
    return EXECUTION_FAILURE;
  }
  printf ("ok %s\n", target); return 0;
}

int
cluster_builtin (WORD_LIST *list)
{
  bc_state s;
  const char *cmd = bc_word (&list), *target;
  int result;
  if (!cmd) { builtin_usage (); return EX_USAGE; }
  if (!strcmp (cmd, "--help")) { builtin_usage (); return list ? EX_USAGE : 0; }
  if (!strcmp (cmd, "--version")) { puts ("cluster 2.0 (bash-loadable)"); return list ? EX_USAGE : 0; }
  if (bc_setup (&s)) { builtin_error ("invalid state path or timeout (50..5000 ms)"); return EXECUTION_FAILURE; }
  if (!strcmp (cmd, "init")) result = bc_start (&s, list, 1);
  else if (!strcmp (cmd, "join")) result = bc_start (&s, list, 0);
  else if (!strcmp (cmd, "ping")) {
    target = bc_word (&list); if (!target || list) return EX_USAGE;
    result = bc_contact (&s, target, 0);
  } else {
    if (list) return EX_USAGE;
    if (!strcmp (cmd, "members")) result = bc_members (&s);
    else if (!strcmp (cmd, "status")) result = bc_status (&s);
    else if (!strcmp (cmd, "leave")) {
      if (bc_lock (&s, 0) == 0) { bc_cleanup (&s); close (s.lock); s.lock = -1; puts ("left cluster"); result = 0; }
      else {
        char path[PATH_MAX]; struct stat st;
        if (!bc_path (&s, path, sizeof path, "cluster_id") && lstat (path, &st) && errno == ENOENT) { puts ("left cluster"); result = 0; }
        else result = bc_contact (&s, NULL, 1);
      }
    } else { builtin_error ("unknown verb: %s", cmd); result = EX_USAGE; }
  }
  crypto_wipe (s.key, sizeof s.key);
  if (fflush (stdout) || ferror (stdout)) { clearerr (stdout); result = EXECUTION_FAILURE; }
  return result;
}

char *cluster_doc[] = {
  "Authenticated loopback membership; listener lifetime follows the owning shell.",
  "cluster init [-p PORT] [-k KEYFILE]",
  "cluster join 127.0.0.1:PORT -k KEYFILE [-p PORT]",
  "cluster leave | status | members",
  "cluster ping NODE|127.0.0.1:PORT",
  "KEYFILE contains 64 lowercase hex digits; init generates private_key by default.",
  "BASHCLUSTER_STATE_DIR selects a private directory; BASHCLUSTER_TIMEOUT_MS=50..5000.",
  NULL
};
struct builtin cluster_struct = {
  "cluster", cluster_builtin, BUILTIN_ENABLED, cluster_doc,
  "cluster init|join|leave|status|members|ping [options]", 0
};
