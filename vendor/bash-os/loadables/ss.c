/* SPDX-License-Identifier: MIT */
/* bashss.c — ss(8) subset over NETLINK_SOCK_DIAG with /proc/net fallback.
 *
 * v1 verbs (ML-T4-03 surface, do not extend without bumping doc fence):
 *   bashss [-t] [-u] [-x] [-l] [-a] [-n] [-p] [-h | --help] [--version]
 *
 *   -t            TCP
 *   -u            UDP
 *   -x            unix-domain
 *   -l            listen state only (default: -a if no state filter given)
 *   -a            all states (default for inet families when -l not set)
 *   -n            force numeric ports (default; surface for ss compat)
 *   -p            annotate rows with "users:((COMM,pid=N,fd=K))"
 *   -h | --help   usage
 *   --version     surface name + protocol probe summary
 *
 * Sibling surface: bashnetstat (legacy column headers, columns:
 *   Proto Recv-Q Send-Q Local Foreign State).  See bashnetstat.c —
 *   it links against the bss_* helpers exported below.
 *
 * Transport: AF_NETLINK/NETLINK_SOCK_DIAG (preferred) with a
 * /proc/net/{tcp,tcp6,udp,udp6,unix} fallback when the kernel
 * lacks sock_diag (CONFIG_INET_DIAG=n / CONFIG_UNIX_DIAG=n) or
 * the request socket fails to open (no AF_NETLINK, no perms).
 *
 * Source counterparts read for behaviour (NOT ported byte-for-byte):
 *   research/refs/iproute2/misc/ss.c       (148 KB upstream)
 *   research/refs/busybox/networking/netstat.c
 *
 * Cap requirements: ss show verbs require no privilege; sock_diag
 * itself permits unprivileged dumps. Per-pid annotation walks
 * /proc/<pid>/fd which silently skips uid-mismatch dirs without a
 * fatal error.
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
#include <dirent.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>      /* RTA_OK / RTA_DATA / RTA_NEXT / struct rtattr */
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/unix_diag.h>

#include "loadables.h"

/* TCP_LISTEN comes from <netinet/tcp.h> on glibc / musl, but the enum
 * value is stable across libcs. Hard-code the bitmap rather than
 * relying on the libc header to avoid a transitive dependency on
 * netinet/tcp.h that conflicts with linux/tcp.h's earlier inclusion. */
#define BSS_TCP_ESTABLISHED 1
#define BSS_TCP_LISTEN      10
#define BSS_TCPF_LISTEN     (1U << BSS_TCP_LISTEN)
#define BSS_TCPF_ALL        0xfffU

#define BSS_BUFSZ 32768

static const char *
ss_state_name (unsigned char s)
{
  switch (s)
    {
    case  1: return "ESTAB";
    case  2: return "SYN-SENT";
    case  3: return "SYN-RECV";
    case  4: return "FIN-WAIT-1";
    case  5: return "FIN-WAIT-2";
    case  6: return "TIME-WAIT";
    case  7: return "UNCONN";
    case  8: return "CLOSE-WAIT";
    case  9: return "LAST-ACK";
    case 10: return "LISTEN";
    case 11: return "CLOSING";
    default: return "UNKNOWN";
    }
}

/* ----------------------------------------------------------------- */
/* pid/inode map for -p annotation                                     */
/* ----------------------------------------------------------------- */

struct bss_pidmap_entry
{
  unsigned long inode;
  pid_t         pid;
  int           fd;
  char          comm[32];
};

struct bss_pidmap
{
  struct bss_pidmap_entry *v;
  size_t                   n;
  size_t                   cap;
  int                      loaded;
};

static void
bss_pidmap_init (struct bss_pidmap *m)
{
  m->v = NULL;
  m->n = 0;
  m->cap = 0;
  m->loaded = 0;
}

static void
bss_pidmap_free (struct bss_pidmap *m)
{
  free (m->v);
  m->v = NULL;
  m->n = m->cap = 0;
  m->loaded = 0;
}

static int
bss_pidmap_push (struct bss_pidmap *m, unsigned long inode, pid_t pid,
                 int fd, const char *comm)
{
  if (m->n == m->cap)
    {
      size_t nc = m->cap ? m->cap * 2 : 64;
      struct bss_pidmap_entry *nv = realloc (m->v, nc * sizeof *nv);
      if (!nv)
        return -1;
      m->v = nv;
      m->cap = nc;
    }
  m->v[m->n].inode = inode;
  m->v[m->n].pid = pid;
  m->v[m->n].fd = fd;
  strncpy (m->v[m->n].comm, comm ? comm : "?", sizeof m->v[m->n].comm - 1);
  m->v[m->n].comm[sizeof m->v[m->n].comm - 1] = 0;
  m->n++;
  return 0;
}

static void
bss_read_comm (pid_t pid, char *out, size_t outsz)
{
  char path[64];
  snprintf (path, sizeof path, "/proc/%d/comm", (int) pid);
  out[0] = 0;
  FILE *fp = fopen (path, "r");
  if (!fp)
    return;
  if (fgets (out, (int) outsz, fp))
    {
      size_t L = strlen (out);
      while (L && (out[L - 1] == '\n' || out[L - 1] == '\r'))
        out[--L] = 0;
    }
  fclose (fp);
}

static void
bss_pidmap_load (struct bss_pidmap *m)
{
  if (m->loaded)
    return;
  m->loaded = 1;
  DIR *d = opendir ("/proc");
  if (!d)
    return;
  struct dirent *e;
  while ((e = readdir (d)) != NULL)
    {
      const char *n = e->d_name;
      if (!isdigit ((unsigned char) n[0]))
        continue;
      pid_t pid = (pid_t) atoi (n);
      if (pid <= 0)
        continue;
      char comm[32] = { 0 };
      bss_read_comm (pid, comm, sizeof comm);
      char fdpath[64];
      snprintf (fdpath, sizeof fdpath, "/proc/%d/fd", (int) pid);
      DIR *fd_d = opendir (fdpath);
      if (!fd_d)
        continue;
      struct dirent *fe;
      while ((fe = readdir (fd_d)) != NULL)
        {
          if (!isdigit ((unsigned char) fe->d_name[0]))
            continue;
          int fdnum = atoi (fe->d_name);
          char link[80];
          snprintf (link, sizeof link, "/proc/%d/fd/%s", (int) pid,
                    fe->d_name);
          char target[96];
          ssize_t L = readlink (link, target, sizeof target - 1);
          if (L <= 0)
            continue;
          target[L] = 0;
          if (strncmp (target, "socket:[", 8) != 0)
            continue;
          unsigned long inode = strtoul (target + 8, NULL, 10);
          if (inode == 0)
            continue;
          if (bss_pidmap_push (m, inode, pid, fdnum, comm) < 0)
            { closedir (fd_d); closedir (d); return; }
        }
      closedir (fd_d);
    }
  closedir (d);
}

static int
bss_pidmap_lookup (struct bss_pidmap *m, unsigned long inode,
                   char *out, size_t outsz)
{
  if (inode == 0)
    return 0;
  out[0] = 0;
  size_t off = 0;
  int hits = 0;
  for (size_t i = 0; i < m->n; i++)
    {
      if (m->v[i].inode != inode)
        continue;
      int w = snprintf (out + off, outsz - off, "%s((\"%s\",pid=%d,fd=%d))",
                        hits ? "," : " users:", m->v[i].comm,
                        (int) m->v[i].pid, m->v[i].fd);
      if (w < 0 || (size_t) w >= outsz - off)
        break;
      off += (size_t) w;
      hits++;
    }
  return hits;
}

/* ----------------------------------------------------------------- */
/* NETLINK_SOCK_DIAG transport                                          */
/* ----------------------------------------------------------------- */

static int
bss_open_diag (void)
{
  int fd = socket (AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
  if (fd < 0)
    return -1;
  struct sockaddr_nl sa;
  memset (&sa, 0, sizeof sa);
  sa.nl_family = AF_NETLINK;
  if (bind (fd, (struct sockaddr *) &sa, sizeof sa) < 0)
    {
      close (fd);
      return -1;
    }
  return fd;
}

static unsigned
bss_seq (void)
{
  static unsigned s = 0;
  if (s == 0)
    s = 0xbb550000U ^ (unsigned) time (NULL) ^ ((unsigned) getpid () << 8);
  return ++s;
}

static int
bss_send_inet_req (int fd, int family, int proto, unsigned states,
                   unsigned seq)
{
  struct
  {
    struct nlmsghdr        nlh;
    struct inet_diag_req_v2 req;
  } pkt;
  memset (&pkt, 0, sizeof pkt);
  pkt.nlh.nlmsg_len = NLMSG_LENGTH (sizeof pkt.req);
  pkt.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
  pkt.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  pkt.nlh.nlmsg_seq = seq;
  pkt.req.sdiag_family = (unsigned char) family;
  pkt.req.sdiag_protocol = (unsigned char) proto;
  pkt.req.idiag_states = states ? states : BSS_TCPF_ALL;

  struct sockaddr_nl kaddr;
  memset (&kaddr, 0, sizeof kaddr);
  kaddr.nl_family = AF_NETLINK;
  ssize_t n = sendto (fd, &pkt, pkt.nlh.nlmsg_len, 0,
                      (struct sockaddr *) &kaddr, sizeof kaddr);
  return n == (ssize_t) pkt.nlh.nlmsg_len ? 0 : -1;
}

static int
bss_send_unix_req (int fd, unsigned states, unsigned seq)
{
  struct
  {
    struct nlmsghdr      nlh;
    struct unix_diag_req req;
  } pkt;
  memset (&pkt, 0, sizeof pkt);
  pkt.nlh.nlmsg_len = NLMSG_LENGTH (sizeof pkt.req);
  pkt.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
  pkt.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  pkt.nlh.nlmsg_seq = seq;
  pkt.req.sdiag_family = AF_UNIX;
  pkt.req.udiag_states = states ? states : ~0U;
  pkt.req.udiag_show = UDIAG_SHOW_NAME | UDIAG_SHOW_PEER | UDIAG_SHOW_RQLEN;

  struct sockaddr_nl kaddr;
  memset (&kaddr, 0, sizeof kaddr);
  kaddr.nl_family = AF_NETLINK;
  ssize_t n = sendto (fd, &pkt, pkt.nlh.nlmsg_len, 0,
                      (struct sockaddr *) &kaddr, sizeof kaddr);
  return n == (ssize_t) pkt.nlh.nlmsg_len ? 0 : -1;
}

/* Callback receives one nlmsghdr; returns 0 to continue, non-zero to
 * abort the dump. */
typedef int (*bss_cb) (struct nlmsghdr *, void *);

static int
bss_recv_loop (int fd, unsigned wanted_seq, bss_cb cb, void *ctx)
{
  char *buf = malloc (BSS_BUFSZ);
  if (!buf)
    return -1;
  int rc = 0;
  for (;;)
    {
      ssize_t s = recv (fd, buf, BSS_BUFSZ, MSG_TRUNC);
      if (s < 0)
        {
          if (errno == EINTR)
            continue;
          rc = -1;
          break;
        }
      if (s == 0 || s > BSS_BUFSZ)
        { rc = -1; break; }
      struct nlmsghdr *h = (struct nlmsghdr *) buf;
      int done = 0;
      /* Alignment can consume more than the final unpadded message.
       * Reject a negative remainder before inspecting another header. */
      while (s >= (ssize_t) sizeof *h && NLMSG_OK (h, s))
        {
          if (h->nlmsg_seq != wanted_seq)
            { h = NLMSG_NEXT (h, s); continue; }
          if (h->nlmsg_flags & NLM_F_DUMP_INTR)
            { rc = -1; done = 1; break; }
          if (h->nlmsg_type == NLMSG_DONE)
            {
              size_t len = h->nlmsg_len - NLMSG_HDRLEN;
              int error = 0;
              if (len && len < sizeof error) rc = -1;
              else if (len) { memcpy (&error, NLMSG_DATA (h), sizeof error); if (error) rc = -1; }
              done = 1; break;
            }
          if (h->nlmsg_type == NLMSG_ERROR)
            {
              if (h->nlmsg_len < NLMSG_LENGTH (sizeof (struct nlmsgerr)))
                { rc = -1; done = 1; break; }
              struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA (h);
              if (err->error == 0)
                { h = NLMSG_NEXT (h, s); continue; }
              errno = -err->error;
              rc = -1;
              done = 1;
              break;
            }
          if (h->nlmsg_type != SOCK_DIAG_BY_FAMILY || (cb && cb (h, ctx) != 0))
            { rc = -1; done = 1; break; }
          h = NLMSG_NEXT (h, s);
        }
      if (done)
        break;
      if (s != 0) { rc = -1; break; }
    }
  free (buf);
  return rc;
}

/* ----------------------------------------------------------------- */
/* render context                                                       */
/* ----------------------------------------------------------------- */

struct bss_render_ctx
{
  const char        *netid;     /* "tcp" / "udp" / "u_str" / etc.  */
  int                show_pid;
  int                legacy_columns; /* netstat-style headers         */
  struct bss_pidmap *pidmap;
  int                rows;
  FILE              *out;
};

static void
bss_print_header (struct bss_render_ctx *c)
{
  if (c->legacy_columns)
    {
      fprintf (c->out, "Proto Recv-Q Send-Q Local Address               "
              "Foreign Address             State%s\n",
              c->show_pid ? "        PID/Program" : "");
    }
  else
    {
      fprintf (c->out, "Netid  State       Recv-Q  Send-Q   Local Address:Port    "
              " Peer Address:Port%s\n",
              c->show_pid ? "  Process" : "");
    }
}

static void
bss_format_inet (int family, const __be32 *raw, __be16 port_be,
                 char *out, size_t outsz, int is_wildcard_ok)
{
  char abuf[INET6_ADDRSTRLEN] = { 0 };
  unsigned port = ntohs (port_be);
  if (family == AF_INET)
    {
      struct in_addr a;
      a.s_addr = raw[0];
      inet_ntop (AF_INET, &a, abuf, sizeof abuf);
      if (is_wildcard_ok && a.s_addr == 0)
        strcpy (abuf, "0.0.0.0");
    }
  else
    {
      struct in6_addr a6;
      memcpy (&a6, raw, 16);
      inet_ntop (AF_INET6, &a6, abuf, sizeof abuf);
    }
  if (port == 0)
    snprintf (out, outsz, "%s:*", abuf);
  else
    snprintf (out, outsz, "%s:%u", abuf, port);
}

static int
bss_cb_inet (struct nlmsghdr *h, void *vctx)
{
  struct bss_render_ctx *c = vctx;
  if (h->nlmsg_len < NLMSG_LENGTH (sizeof (struct inet_diag_msg))) return -1;
  struct inet_diag_msg *m = (struct inet_diag_msg *) NLMSG_DATA (h);
  if (m->idiag_family != AF_INET && m->idiag_family != AF_INET6) return -1;
  char la[80], pa[80], proc[128] = { 0 };
  bss_format_inet (m->idiag_family, m->id.idiag_src, m->id.idiag_sport,
                   la, sizeof la, 1);
  bss_format_inet (m->idiag_family, m->id.idiag_dst, m->id.idiag_dport,
                   pa, sizeof pa, 1);
  if (c->show_pid)
    bss_pidmap_lookup (c->pidmap, (unsigned long) m->idiag_inode,
                       proc, sizeof proc);
  /* The base message contains queue lengths, including the backlog for
   * listeners. No INET_DIAG_SKMEMINFO attribute is needed for these columns. */
  if (c->legacy_columns)
    {
      fprintf (c->out, "%-5s %-6u %-6u %-26s %-26s %s%s\n",
              c->netid, m->idiag_rqueue, m->idiag_wqueue, la, pa,
              ss_state_name (m->idiag_state), proc);
    }
  else
    {
      fprintf (c->out, "%-6s %-11s %-7u %-7u  %-22s %s%s\n",
              c->netid, ss_state_name (m->idiag_state),
              m->idiag_rqueue, m->idiag_wqueue, la, pa, proc);
    }
  c->rows++;
  return 0;
}

static int
bss_cb_unix (struct nlmsghdr *h, void *vctx)
{
  struct bss_render_ctx *c = vctx;
  struct unix_diag_msg *m = (struct unix_diag_msg *) NLMSG_DATA (h);
  size_t rta_off = NLMSG_LENGTH (sizeof *m) - NLMSG_HDRLEN;
  size_t total = h->nlmsg_len - NLMSG_HDRLEN;
  if (rta_off > total)
    return -1;
  if (m->udiag_family != AF_UNIX)
    return -1;
  struct rtattr *rta = (struct rtattr *)
    ((char *) NLMSG_DATA (h) + (rta_off - 0));
  /* rta is just past the unix_diag_msg base. Use the standard
   * RTA_OK loop with the remaining attr-stream byte count. */
  int len = (int) (total - rta_off);
  const char *path = "";
  char pathbuf[128] = { 0 };
  struct unix_diag_rqlen queues = { 0, 0 };
  while (RTA_OK (rta, len))
    {
      if (rta->rta_type == UNIX_DIAG_RQLEN)
        {
          if (RTA_PAYLOAD (rta) < sizeof queues)
            return -1;
          memcpy (&queues, RTA_DATA (rta), sizeof queues);
        }
      else if (rta->rta_type == UNIX_DIAG_NAME)
        {
          int dl = (int) (rta->rta_len - sizeof (struct rtattr));
          if (dl > 0)
            {
              if (dl >= (int) sizeof pathbuf)
                dl = (int) sizeof pathbuf - 1;
              memcpy (pathbuf, RTA_DATA (rta), (size_t) dl);
              /* Linux abstract sockets use a leading NUL in the
               * path — render as "@" prefix in ss style. */
              if (pathbuf[0] == 0 && dl > 1)
                {
                  pathbuf[0] = '@';
                }
              pathbuf[dl < (int) sizeof pathbuf ? dl : (int) sizeof pathbuf - 1] = 0;
              path = pathbuf;
            }
        }
      rta = RTA_NEXT (rta, len);
    }
  if (len != 0)
    return -1;
  const char *typestr = m->udiag_type == SOCK_STREAM ? "u_str"
                      : m->udiag_type == SOCK_DGRAM  ? "u_dgr"
                      : m->udiag_type == SOCK_SEQPACKET ? "u_seq"
                      : "u_unk";
  char proc[128] = { 0 };
  if (c->show_pid)
    bss_pidmap_lookup (c->pidmap, (unsigned long) m->udiag_ino,
                       proc, sizeof proc);
  if (c->legacy_columns)
    fprintf (c->out, "%-5s %-6u %-6u %-26s %-26s %s%s\n",
            typestr, queues.udiag_rqueue, queues.udiag_wqueue,
            path[0] ? path : "*", "*",
            ss_state_name (m->udiag_state), proc);
  else
    fprintf (c->out, "%-6s %-11s %-7u %-7u  %-22s %s%s\n",
            typestr, ss_state_name (m->udiag_state),
            queues.udiag_rqueue, queues.udiag_wqueue,
            path[0] ? path : "*", "*", proc);
  c->rows++;
  return 0;
}

/* ----------------------------------------------------------------- */
/* /proc/net fallback                                                   */
/* ----------------------------------------------------------------- */

/* Parse a hex addr field "AABBCCDD:PPPP" or "AABB....AABB:PPPP" into a
 * printable "X.X.X.X:N" or "[a:b:c::d]:N" string. */
static int
bss_proc_parse_addr (const char *hex, int family, char *out, size_t outsz)
{
  size_t digits = family == AF_INET ? 8 : 32;
  if (strlen (hex) != digits + 5 || hex[digits] != ':') return -1;
  for (size_t i = 0; i < digits + 5; i++)
    if (i != digits && !isxdigit ((unsigned char) hex[i])) return -1;
  uint32_t raw[4] = { 0 };
  for (size_t i = 0; i < digits / 8; i++)
    {
      char word[9];
      memcpy (word, hex + i * 8, 8); word[8] = 0;
      raw[i] = (uint32_t) strtoul (word, NULL, 16);
    }
  unsigned port = (unsigned) strtoul (hex + digits + 1, NULL, 16);
  bss_format_inet (family, raw, htons (port), out, outsz, 1);
  return 0;
}

static int
bss_proc_inet (const char *path, const char *netid, int family,
               struct bss_render_ctx *c, int listen_only)
{
  FILE *fp = fopen (path, "r");
  if (!fp)
    return -1;
  char line[512];
  /* skip header */
  if (!fgets (line, sizeof line, fp))
    { int rc = ferror (fp) ? -1 : 0; fclose (fp); return rc; }
  int rows = 0;
  while (fgets (line, sizeof line, fp))
    {
      char local[80], remote[80];
      unsigned st = 0, txq = 0, rxq = 0;
      unsigned long inode = 0;
      /* /proc/net/{tcp,udp} columns:
       *   sl  local_address  rem_address  st  tx_queue:rx_queue  ...  inode
       * We deliberately skip the tr/tm field and uid via %*s. */
      char dummy_sl[16];
      char laddr[64], raddr[64];
      unsigned long u0, u1, u2;
      int parsed = sscanf (line,
                           "%15s %63s %63s %x %x:%x %lx:%lx %lx %*u %*u %lu",
                           dummy_sl, laddr, raddr, &st,
                           &txq, &rxq, &u0, &u1, &u2, &inode);
      if (parsed < 10)
        continue;
      if (listen_only && st != (strncmp (netid, "udp", 3) == 0 ? 7U : BSS_TCP_LISTEN))
        continue;
      if (bss_proc_parse_addr (laddr, family, local, sizeof local) < 0
          || bss_proc_parse_addr (raddr, family, remote, sizeof remote) < 0)
        continue;
      char proc[128] = { 0 };
      if (c->show_pid)
        bss_pidmap_lookup (c->pidmap, inode, proc, sizeof proc);
      if (c->legacy_columns)
        fprintf (c->out, "%-5s %-6u %-6u %-26s %-26s %s%s\n",
                netid, rxq, txq, local, remote,
                ss_state_name ((unsigned char) st), proc);
      else
        fprintf (c->out, "%-6s %-11s %-7u %-7u  %-22s %s%s\n",
                netid, ss_state_name ((unsigned char) st), rxq, txq,
                local, remote, proc);
      rows++;
    }
  int rc = ferror (fp) ? -1 : 0;
  fclose (fp);
  c->rows += rows;
  return rc;
}

static int
bss_proc_unix (struct bss_render_ctx *c, int listen_only)
{
  FILE *fp = fopen ("/proc/net/unix", "r");
  if (!fp)
    return -1;
  char line[512];
  /* header */
  if (!fgets (line, sizeof line, fp))
    { int rc = ferror (fp) ? -1 : 0; fclose (fp); return rc; }
  int rows = 0;
  while (fgets (line, sizeof line, fp))
    {
      /* columns: Num RefCount Protocol Flags Type St Inode [Path] */
      unsigned long flags = 0, type = 0, st = 0, inode = 0;
      char path[200] = { 0 };
      int parsed = sscanf (line,
                           "%*s %*x %*x %lx %lx %lx %lu %199[^\n]",
                           &flags, &type, &st, &inode, path);
      if (parsed < 4) continue;
      if (listen_only && !(flags & 0x10000)) continue;
      /* /proc/net/unix uses SS_* socket states, not TCP states. */
      st = flags & 0x10000 ? BSS_TCP_LISTEN : st == 3 ? 1 : st == 2 ? 2 : st == 4 ? 8 : 7;
      const char *typestr = type == SOCK_STREAM ? "u_str"
                          : type == SOCK_DGRAM  ? "u_dgr"
                          : type == SOCK_SEQPACKET ? "u_seq"
                          : "u_unk";
      const char *p = path[0] ? path : "*";
      char proc[128] = { 0 };
      if (c->show_pid)
        bss_pidmap_lookup (c->pidmap, inode, proc, sizeof proc);
      if (c->legacy_columns)
        fprintf (c->out, "%-5s 0      0      %-26s %-26s %s%s\n",
                typestr, p, "*", ss_state_name ((unsigned char) st), proc);
      else
        fprintf (c->out, "%-6s %-11s %-7u %-7u  %-22s %s%s\n",
                typestr, ss_state_name ((unsigned char) st), 0U, 0U,
                p, "*", proc);
      rows++;
    }
  int rc = ferror (fp) ? -1 : 0;
  fclose (fp);
  c->rows += rows;
  return rc;
}

/* ----------------------------------------------------------------- */
/* shared run helper (exported for bashnetstat.c)                       */
/* ----------------------------------------------------------------- */

struct bss_opts
{
  int show_tcp;
  int show_udp;
  int show_unix;
  int listen_only;
  int all_states;
  int show_pid;
  int numeric;       /* surface for compat; always-numeric path. */
  int legacy_columns;
};

static int
bss_do_inet (int fd, int family, int proto, const char *netid,
             struct bss_render_ctx *c, struct bss_opts *o)
{
  unsigned states = o->listen_only ? (1U << (proto == IPPROTO_UDP ? 7 : BSS_TCP_LISTEN)) : BSS_TCPF_ALL;
  unsigned seq = bss_seq ();
  c->netid = netid;
  if (bss_send_inet_req (fd, family, proto, states, seq) < 0)
    return -1;
  return bss_recv_loop (fd, seq, bss_cb_inet, c);
}

static int
bss_do_unix (int fd, struct bss_render_ctx *c, struct bss_opts *o)
{
  unsigned states = o->listen_only ? BSS_TCPF_LISTEN : ~0U;
  unsigned seq = bss_seq ();
  c->netid = "u_str";
  if (bss_send_unix_req (fd, states, seq) < 0)
    return -1;
  return bss_recv_loop (fd, seq, bss_cb_unix, c);
}

/* Buffer each family until its dump completes. A failed dump contributes no
 * rows, so fallback cannot duplicate a partially rendered netlink table. */
static int
bss_table (int family, int proto, const char *netid, const char *path,
           struct bss_render_ctx *ctx, struct bss_opts *o)
{
  char *data = NULL;
  size_t size = 0;
  FILE *out = open_memstream (&data, &size);
  if (!out) return -1;
  ctx->out = out;
  int fd = bss_open_diag ();
  int rc = -1;
  if (fd >= 0)
    {
      rc = family == AF_UNIX ? bss_do_unix (fd, ctx, o)
           : bss_do_inet (fd, family, proto, netid, ctx, o);
      close (fd);
    }
  if (fclose (out) != 0) rc = -1;
  if (rc != 0)
    {
      free (data); data = NULL; size = 0;
      out = open_memstream (&data, &size);
      if (!out) return -1;
      ctx->out = out;
      rc = family == AF_UNIX ? bss_proc_unix (ctx, o->listen_only)
           : bss_proc_inet (path, netid, family, ctx, o->listen_only);
      if (fclose (out) != 0) rc = -1;
    }
  if (rc == 0 && size && fwrite (data, 1, size, stdout) != size) rc = -1;
  free (data);
  ctx->out = stdout;
  return rc;
}

int
bss_run (struct bss_opts *o)
{
  struct bss_pidmap pm;
  bss_pidmap_init (&pm);
  if (o->show_pid) bss_pidmap_load (&pm);
  struct bss_render_ctx ctx = {
    .netid = "?", .show_pid = o->show_pid,
    .legacy_columns = o->legacy_columns, .pidmap = &pm, .rows = 0,
    .out = stdout
  };
  bss_print_header (&ctx);
  int rc = 0;
  if (o->show_tcp)
    {
      if (bss_table (AF_INET, IPPROTO_TCP, "tcp", "/proc/net/tcp", &ctx, o) < 0) rc = -1;
      if (bss_table (AF_INET6, IPPROTO_TCP, "tcp6", "/proc/net/tcp6", &ctx, o) < 0) rc = -1;
    }
  if (o->show_udp)
    {
      if (bss_table (AF_INET, IPPROTO_UDP, "udp", "/proc/net/udp", &ctx, o) < 0) rc = -1;
      if (bss_table (AF_INET6, IPPROTO_UDP, "udp6", "/proc/net/udp6", &ctx, o) < 0) rc = -1;
    }
  if (o->show_unix && bss_table (AF_UNIX, 0, "u_str", NULL, &ctx, o) < 0) rc = -1;
  bss_pidmap_free (&pm);
  return rc;
}

/* ----------------------------------------------------------------- */
/* builtin                                                              */
/* ----------------------------------------------------------------- */

int
ss_builtin (WORD_LIST *list)
{
  struct bss_opts o;
  memset (&o, 0, sizeof o);
  o.numeric = 1;
  /* stdout and its error indicator outlive this invocation in Bash. */
  clearerr (stdout);

  int explicit_family = 0;
  for (WORD_LIST *p = list; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-h") == 0 || strcmp (w, "--help") == 0)
        { builtin_usage (); return EXECUTION_SUCCESS; }
      if (strcmp (w, "--version") == 0)
        {
          int fd = bss_open_diag ();
          printf ("bashss — ss(8) subset (sock_diag=%s)\n",
                  fd >= 0 ? "ok" : "proc-fallback");
          if (fd >= 0) close (fd);
          return fflush (stdout) == 0 && !ferror (stdout)
                 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
        }
      if (w[0] != '-' || w[1] == 0)
        {
          builtin_error ("unknown argument: %s", w);
          builtin_usage ();
          return EX_USAGE;
        }
      for (const char *c = w + 1; *c; c++)
        {
          switch (*c)
            {
            case 't': o.show_tcp = 1; explicit_family = 1; break;
            case 'u': o.show_udp = 1; explicit_family = 1; break;
            case 'x': o.show_unix = 1; explicit_family = 1; break;
            case 'l': o.listen_only = 1; break;
            case 'a': o.all_states = 1; break;
            case 'n': o.numeric = 1; break;
            case 'p': o.show_pid = 1; break;
            default:
              builtin_error ("unknown flag: -%c", *c);
              builtin_usage ();
              return EX_USAGE;
            }
        }
    }

  /* Default when no -t/-u/-x given: ss shows TCP (plus UDP + unix in
   * the netstat-alike "show all" mode).  Match that. */
  if (!explicit_family)
    o.show_tcp = 1;
  if (!o.listen_only && !o.all_states)
    o.all_states = 1;

  int rc = bss_run (&o);
  if (fflush (stdout) == EOF || ferror (stdout))
    rc = -1;
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

char *ss_doc[] = {
  "ss(8) subset over NETLINK_SOCK_DIAG.",
  "",
  "    bashss [-t] [-u] [-x] [-l] [-a] [-n] [-p]",
  "    bashss -h | --help",
  "    bashss --version",
  "",
  "Flags:",
  "    -t    TCP sockets (default if no family flag given)",
  "    -u    UDP sockets",
  "    -x    UNIX-domain sockets",
  "    -l    listen state only",
  "    -a    all states (default when -l not given)",
  "    -n    force numeric ports (default; surface for compat)",
  "    -p    annotate rows with the holding process",
  "",
  "Falls back to /proc/net/{tcp,tcp6,udp,udp6,unix} when sock_diag",
  "is unavailable. Deferred to v2: -i (info), -e (extended), bytecode",
  "filters, JSON output (-j), service-name resolution.",
  (char *) NULL
};

struct builtin bashss_struct = {
  "bashss",
  ss_builtin,
  BUILTIN_ENABLED,
  ss_doc,
  "bashss [-t|-u|-x] [-l|-a] [-n] [-p]",
  0
};
