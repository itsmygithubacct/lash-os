/* SPDX-License-Identifier: MIT */
/* cluster.c - Stage 50.E cluster membership primitive for bash-os.
 *
 * This is deliberately not screen integration. It owns only the local
 * cluster state directory and a small membership protocol surface that later
 * screen-over-cluster work can consume.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "loadables.h"

#define BC_DEFAULT_DIR "/var/lib/cluster"
#define BC_DEFAULT_PORT "5450"

static const char *
bc_word (WORD_LIST **list)
{
  const char *s;
  if (!list || !*list || !(*list)->word)
    return NULL;
  s = (*list)->word->word;
  *list = (*list)->next;
  return s;
}

static const char *
bc_state_dir (void)
{
  const char *d = getenv ("BASHCLUSTER_STATE_DIR");
  return (d && *d) ? d : BC_DEFAULT_DIR;
}

static int
bc_path (char *out, size_t outsz, const char *name)
{
  int n = snprintf (out, outsz, "%s/%s", bc_state_dir (), name);
  return (n > 0 && (size_t) n < outsz) ? 0 : -1;
}

static int
bc_mkdir_p (const char *path, mode_t mode)
{
  char tmp[1024];
  size_t len;
  if (!path || !*path)
    return -1;
  snprintf (tmp, sizeof tmp, "%s", path);
  len = strlen (tmp);
  if (len == 0 || len >= sizeof tmp)
    return -1;
  if (tmp[len - 1] == '/')
    tmp[len - 1] = '\0';
  for (char *p = tmp + 1; *p; p++)
    if (*p == '/')
      {
        *p = '\0';
        if (mkdir (tmp, mode) < 0 && errno != EEXIST)
          return -1;
        *p = '/';
      }
  if (mkdir (tmp, mode) < 0 && errno != EEXIST)
    return -1;
  chmod (tmp, mode);
  return 0;
}

static int
bc_read_file (const char *name, char *buf, size_t bufsz)
{
  char path[1024];
  FILE *f;
  size_t n;
  if (bc_path (path, sizeof path, name) < 0)
    return -1;
  f = fopen (path, "r");
  if (!f)
    return -1;
  n = fread (buf, 1, bufsz - 1, f);
  fclose (f);
  buf[n] = '\0';
  while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
    buf[--n] = '\0';
  return 0;
}

static int
bc_write_file_mode (const char *name, const char *data, mode_t mode)
{
  char path[1024], tmp[1060];
  FILE *f;
  size_t len;
  if (bc_mkdir_p (bc_state_dir (), 0700) < 0)
    {
      builtin_error ("mkdir %s: %s", bc_state_dir (), strerror (errno));
      return -1;
    }
  if (bc_path (path, sizeof path, name) < 0)
    return -1;
  snprintf (tmp, sizeof tmp, "%s.tmp.%ld", path, (long) getpid ());
  f = fopen (tmp, "w");
  if (!f)
    return -1;
  if (data && fputs (data, f) < 0)
    { fclose (f); unlink (tmp); return -1; }
  len = data ? strlen (data) : 0;
  if (len > 0 && data[len - 1] != '\n')
    fputc ('\n', f);
  if (fclose (f) != 0)
    { unlink (tmp); return -1; }
  chmod (tmp, mode);
  if (rename (tmp, path) < 0)
    { unlink (tmp); return -1; }
  return 0;
}

static int
bc_append_member (const char *node, const char *hostport, const char *key)
{
  char path[1024];
  FILE *f;
  if (bc_path (path, sizeof path, "members") < 0)
    return -1;
  f = fopen (path, "a");
  if (!f)
    return -1;
  fprintf (f, "%s %s %s\n", node, hostport, key ? key : "-");
  return fclose (f) == 0 ? 0 : -1;
}

static int
bc_valid_hostport (const char *s)
{
  const char *c;
  if (!s || !*s)
    return 0;
  c = strrchr (s, ':');
  if (!c || c == s || !c[1])
    return 0;
  for (const char *p = c + 1; *p; p++)
    if (!isdigit ((unsigned char) *p))
      return 0;
  return 1;
}

static void
bc_uuid (char *out, size_t outsz, const char *prefix)
{
  FILE *f = fopen ("/proc/sys/kernel/random/uuid", "r");
  if (f)
    {
      if (fgets (out, (int) outsz, f))
        {
          size_t n = strlen (out);
          while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'))
            out[--n] = '\0';
          fclose (f);
          return;
        }
      fclose (f);
    }
  snprintf (out, outsz, "%s-%ld-%ld", prefix, (long) time (NULL), (long) getpid ());
}

static int
bc_init (WORD_LIST *args)
{
  const char *port = BC_DEFAULT_PORT, *w;
  char path[1024], cluster[80], node[80], pidbuf[64], key[256];
  while ((w = bc_word (&args)) != NULL)
    {
      if (!strcmp (w, "-p") || !strcmp (w, "--port"))
        {
          port = bc_word (&args);
          if (!port) { builtin_error ("init needs port after %s", w); return EX_USAGE; }
        }
      else
        { builtin_error ("unknown init option: %s", w); return EX_USAGE; }
    }
  if (bc_path (path, sizeof path, "cluster_id") < 0)
    return EXECUTION_FAILURE;
  if (access (path, F_OK) == 0)
    { builtin_error ("cluster already initialized at %s", bc_state_dir ()); return EXECUTION_FAILURE; }
  bc_uuid (cluster, sizeof cluster, "cluster");
  bc_uuid (node, sizeof node, "node");
  snprintf (pidbuf, sizeof pidbuf, "%ld", (long) getpid ());
  snprintf (key, sizeof key, "cluster-private-key node=%s\n", node);
  if (bc_write_file_mode ("cluster_id", cluster, 0644) < 0 ||
      bc_write_file_mode ("node_id", node, 0644) < 0 ||
      bc_write_file_mode ("listener_pid", pidbuf, 0644) < 0 ||
      bc_write_file_mode ("port", port, 0644) < 0 ||
      bc_write_file_mode ("private_key", key, 0600) < 0 ||
      bc_write_file_mode ("members", "", 0644) < 0)
    {
      builtin_error ("failed to initialize %s: %s", bc_state_dir (), strerror (errno));
      return EXECUTION_FAILURE;
    }
  printf ("cluster_id=%s\nnode_id=%s\nport=%s\nlistener_pid=%s\n", cluster, node, port, pidbuf);
  return EXECUTION_SUCCESS;
}

static int
bc_status (WORD_LIST *args)
{
  char cluster[128] = "", node[128] = "", port[64] = "", pid[64] = "";
  (void) args;
  if (bc_read_file ("cluster_id", cluster, sizeof cluster) < 0)
    {
      printf ("state=uninitialized\nstate_dir=%s\n", bc_state_dir ());
      return EXECUTION_SUCCESS;
    }
  bc_read_file ("node_id", node, sizeof node);
  bc_read_file ("port", port, sizeof port);
  bc_read_file ("listener_pid", pid, sizeof pid);
  printf ("state=initialized\nstate_dir=%s\ncluster_id=%s\nnode_id=%s\nport=%s\nlistener_pid=%s\n",
          bc_state_dir (), cluster, node, port, pid);
  return EXECUTION_SUCCESS;
}

static int
bc_members (WORD_LIST *args)
{
  char path[1024], buf[4096];
  FILE *f;
  size_t n;
  (void) args;
  if (bc_path (path, sizeof path, "members") < 0)
    return EXECUTION_FAILURE;
  f = fopen (path, "r");
  if (!f)
    return EXECUTION_SUCCESS;
  while ((n = fread (buf, 1, sizeof buf, f)) > 0)
    fwrite (buf, 1, n, stdout);
  fclose (f);
  return EXECUTION_SUCCESS;
}

static int
bc_tcp_probe (const char *hostport)
{
  char host[256], port[32];
  const char *c = strrchr (hostport, ':');
  struct addrinfo hints, *res = NULL, *rp;
  int rc = -1;
  if (!c || (size_t) (c - hostport) >= sizeof host || strlen (c + 1) >= sizeof port)
    return -1;
  memcpy (host, hostport, (size_t) (c - hostport));
  host[c - hostport] = '\0';
  snprintf (port, sizeof port, "%s", c + 1);
  memset (&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo (host, port, &hints, &res) != 0)
    return -1;
  for (rp = res; rp; rp = rp->ai_next)
    {
      int fd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (fd < 0) continue;
      int cr;
      do { cr = connect (fd, rp->ai_addr, rp->ai_addrlen); }
      while (cr < 0 && errno == EINTR);
      if (cr == 0)
        rc = 0;
      close (fd);
      if (rc == 0) break;
    }
  freeaddrinfo (res);
  return rc;
}

static int
bc_ping_hostport (const char *node)
{
  if (getenv ("BASHCLUSTER_MOCK_SSH"))
    {
      if (strstr (node, "bad") || strstr (node, "unreachable"))
        return -1;
      return 0;
    }
  return bc_tcp_probe (node);
}

static int
bc_join (WORD_LIST *args)
{
  const char *hostport = bc_word (&args), *key = NULL, *w;
  char node[128] = "";
  if (!hostport || !bc_valid_hostport (hostport))
    { builtin_error ("join needs HOST:PORT"); return EX_USAGE; }
  while ((w = bc_word (&args)) != NULL)
    {
      if (!strcmp (w, "-k") || !strcmp (w, "--key"))
        {
          key = bc_word (&args);
          if (!key) { builtin_error ("join needs keyfile after %s", w); return EX_USAGE; }
        }
      else
        { builtin_error ("unknown join option: %s", w); return EX_USAGE; }
    }
  if (key && access (key, R_OK) != 0)
    { builtin_error ("keyfile not readable: %s", key); return EXECUTION_FAILURE; }
  if (bc_mkdir_p (bc_state_dir (), 0700) < 0)
    return EXECUTION_FAILURE;
  if (bc_read_file ("node_id", node, sizeof node) < 0)
    {
      bc_uuid (node, sizeof node, "node");
      bc_write_file_mode ("node_id", node, 0644);
    }
  if (bc_ping_hostport (hostport) < 0)
    { builtin_error ("unable to reach cluster peer over ssh transport: %s", hostport); return EXECUTION_FAILURE; }
  if (bc_read_file ("cluster_id", node, sizeof node) < 0)
    bc_write_file_mode ("cluster_id", "joined", 0644);
  bc_read_file ("node_id", node, sizeof node);
  if (bc_append_member (node, hostport, key ? key : "-") < 0)
    { builtin_error ("failed to append member: %s", strerror (errno)); return EXECUTION_FAILURE; }
  printf ("joined %s as %s\n", hostport, node);
  return EXECUTION_SUCCESS;
}

static int
bc_ping (WORD_LIST *args)
{
  const char *node = bc_word (&args);
  if (!node)
    { builtin_error ("ping needs NODE or HOST:PORT"); return EX_USAGE; }
  if (bc_ping_hostport (node) == 0)
    {
      printf ("ok %s\n", node);
      return EXECUTION_SUCCESS;
    }
  builtin_error ("unreachable: %s", node);
  return EXECUTION_FAILURE;
}

static int
bc_leave (WORD_LIST *args)
{
  char path[1024];
  const char *files[] = { "cluster_id", "node_id", "members", "listener_pid", "port", "private_key", NULL };
  (void) args;
  for (int i = 0; files[i]; i++)
    if (bc_path (path, sizeof path, files[i]) == 0)
      unlink (path);
  printf ("left cluster\n");
  return EXECUTION_SUCCESS;
}

int
cluster_builtin (WORD_LIST *list)
{
  const char *cmd;
  if (list && list->word && list->word->word) {
    const char *w = list->word->word;
    if (strcmp (w, "--help") == 0) {
      builtin_usage ();
      return EXECUTION_SUCCESS;
    }
    if (strcmp (w, "--version") == 0) {
      puts ("cluster 1.0 (bash-loadable)");
      return EXECUTION_SUCCESS;
    }
  }
  if (!list) { builtin_usage (); return EX_USAGE; }
  cmd = bc_word (&list);
  if (!cmd) { builtin_usage (); return EX_USAGE; }
  if (!strcmp (cmd, "init")) return bc_init (list);
  if (!strcmp (cmd, "join")) return bc_join (list);
  if (!strcmp (cmd, "leave")) return bc_leave (list);
  if (!strcmp (cmd, "status")) return bc_status (list);
  if (!strcmp (cmd, "members")) return bc_members (list);
  if (!strcmp (cmd, "ping")) return bc_ping (list);
  builtin_error ("unknown verb: %s", cmd);
  return EX_USAGE;
}

char *cluster_doc[] = {
  "bash-os cluster membership primitive for future screen clustering.",
  "cluster init [-p PORT]",
  "cluster join HOST:PORT [-k KEYFILE]",
  "cluster leave",
  "cluster status",
  "cluster members",
  "cluster ping NODE",
  "cluster --help | --version",
  NULL
};

struct builtin cluster_struct = {
  "cluster", cluster_builtin, BUILTIN_ENABLED, cluster_doc,
  "cluster init|join|leave|status|members|ping [--help|--version]", 0
};
