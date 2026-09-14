/* SPDX-License-Identifier: MIT */
/* baship.c — iproute2 `ip` subset over rtnetlink (AF_NETLINK/NETLINK_ROUTE)
 *
 * Promoted verbs:
 *   baship
 *   baship help
 *   baship [-4|-6] [-br|-o|-j] [-netns NAME] OBJECT [show]
 *   baship -batch FILE|- [-force]
 *   baship link show [IFNAME]
 *   baship link set IFNAME up|down|mtu N|address MAC
 *   baship link add NAME type dummy
 *   baship link add NAME type veth peer NAME
 *   baship link del NAME
 *   baship [-j] link|addr|route|neigh|rule show ...
 *   baship addr show [IFNAME] [to PREFIX] [scope SCOPE]
 *   baship addr add CIDR dev IFNAME
 *   baship addr del CIDR dev IFNAME
 *   baship addr change CIDR dev IFNAME
 *   baship addr replace CIDR dev IFNAME
 *   baship addr flush dev IFNAME [scope SCOPE] [to PREFIX]
 *   baship route show [default] [dev IFNAME] [table TABLE|all]
 *   baship route flush dev IFNAME
 *   baship route add|change|replace|append CIDR|default [via NEXTHOP] [dev IFNAME] [table TABLE] [metric N]
 *   baship route del CIDR|default [via NEXTHOP] [dev IFNAME] [table TABLE] [metric N]
 *   baship [-j] rule show
 *   baship rule add from CIDR [to CIDR] [fwmark MARK[/MASK]] [uidrange A-B] [ipproto PROTO] table TABLE priority N
 *   baship rule del [from CIDR] [to CIDR] [fwmark MARK[/MASK]] [uidrange A-B] [ipproto PROTO] [table TABLE] priority N
 *   baship rule flush
 *   baship neigh show [dev IFNAME]
 *   baship neigh add|change|replace IP lladdr MAC dev IFNAME [nud STATE]
 *   baship neigh del IP [lladdr MAC] dev IFNAME
 *
 * Deferred to v2 (not implemented here): tc, xfrm, monitor mode, the `ip netns`
 * object, IPv6 SLAAC, link kinds beyond dummy/veth, and richer route/neigh/rule
 * selector algebra.
 *
 * Source counterparts read for behaviour (NOT ported byte-for-byte):
 *   research/refs/iproute2/ip/{iplink,ipaddress,iproute,ipneigh}.c
 *   research/refs/busybox/networking/ip.c
 *   research/refs/toybox/toys/pending/ip.c
 *
 * Cap requirements: CAP_NET_ADMIN for set/add/del verbs; show verbs run
 * unprivileged. The kernel enforces this; we surface EPERM with a
 * helpful hint about CAP_NET_ADMIN.
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
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sched.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/fib_rules.h>
#include <linux/if_link.h>
#include <linux/if_arp.h>
#include <linux/neighbour.h>
#include <linux/veth.h>

#include "loadables.h"

#ifndef CLONE_NEWNET
#  define CLONE_NEWNET 0x40000000
#endif

#ifndef NLMSG_TAIL
#define NLMSG_TAIL(nmsg) \
  ((struct rtattr *) (((char *) (nmsg)) + NLMSG_ALIGN ((nmsg)->nlmsg_len)))
#endif

#define BIP_BUFSZ 16384
#define BIP_SEQ_BASE 0xb1700000U

struct bip_ip_opts
{
  int json;
  int brief;
  int oneline;
  int family;
  const char *netns;
};

static int bip_dispatch (WORD_LIST *list, const struct bip_ip_opts *opts);

/* ----------------------------------------------------------------- */
/* netlink primitives                                                  */
/* ----------------------------------------------------------------- */

static int
bip_open (void)
{
  int fd = socket (AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (fd < 0)
    {
      builtin_error ("netlink socket: %s", strerror (errno));
      return -1;
    }
  struct sockaddr_nl sa;
  memset (&sa, 0, sizeof sa);
  sa.nl_family = AF_NETLINK;
  if (bind (fd, (struct sockaddr *) &sa, sizeof sa) < 0)
    {
      builtin_error ("netlink bind: %s", strerror (errno));
      close (fd);
      return -1;
    }
  return fd;
}

static unsigned
bip_seq (void)
{
  static unsigned s = 0;
  if (s == 0)
    s = BIP_SEQ_BASE ^ (unsigned) time (NULL) ^ ((unsigned) getpid () << 8);
  return ++s;
}

struct bip_alias
{
  const char *alias;
  const char *canon;
};

static int
bip_matches (const char *prefix, const char *full)
{
  return prefix && prefix[0] && full
         && strncmp (prefix, full, strlen (prefix)) == 0;
}

static const char *
bip_alias_exact (const char *arg, const struct bip_alias *aliases)
{
  if (!arg || !aliases)
    return NULL;
  for (int i = 0; aliases[i].alias; i++)
    if (strcmp (arg, aliases[i].alias) == 0)
      return aliases[i].canon;
  return NULL;
}

static const char *
bip_match_one (const char *arg, const char *const *cands, const char *ctx)
{
  const char *first = NULL, *second = NULL;
  int matches = 0;

  if (!arg || !*arg)
    {
      builtin_error ("ip: empty %s", ctx ? ctx : "keyword");
      return NULL;
    }

  for (int i = 0; cands && cands[i]; i++)
    if (strcmp (arg, cands[i]) == 0)
      return cands[i];

  for (int i = 0; cands && cands[i]; i++)
    if (bip_matches (arg, cands[i]))
      {
        if (!first)
          first = cands[i];
        else if (!second)
          second = cands[i];
        matches++;
      }

  if (matches == 1)
    return first;
  if (matches > 1)
    {
      builtin_error ("Command line is not complete / ambiguous \"%s\": matches %s, %s",
                     arg, first ? first : "?", second ? second : "?");
      return NULL;
    }

  builtin_error ("ip: \"%s\" is unknown %s, try \"baship help\"",
                 arg, ctx ? ctx : "keyword");
  return NULL;
}

static const char *
bip_match_one_quiet (const char *arg, const char *const *cands, const char *ctx)
{
  const char *first = NULL, *second = NULL;
  int matches = 0;

  if (!arg || !*arg)
    return NULL;
  for (int i = 0; cands && cands[i]; i++)
    if (strcmp (arg, cands[i]) == 0)
      return cands[i];
  for (int i = 0; cands && cands[i]; i++)
    if (bip_matches (arg, cands[i]))
      {
        if (!first)
          first = cands[i];
        else if (!second)
          second = cands[i];
        matches++;
      }
  if (matches == 1)
    return first;
  if (matches > 1)
    builtin_error ("Command line is not complete / ambiguous \"%s\": matches %s, %s",
                   arg, first ? first : "?", second ? second : "?");
  (void) ctx;
  return NULL;
}

static const char *
bip_match_keyword (const char *arg, const char *const *cands,
                   const struct bip_alias *aliases, const char *ctx)
{
  const char *canon = bip_alias_exact (arg, aliases);
  if (canon)
    return canon;
  return bip_match_one (arg, cands, ctx);
}

static const char *const bip_object_cands[] = {
  "link", "address", "route", "rule", "neighbour", NULL
};

static const struct bip_alias bip_object_aliases[] = {
  { "l", "link" },
  { "a", "address" },
  { "addr", "address" },
  { "r", "route" },
  { "ru", "rule" },
  { "n", "neighbour" },
  { "neigh", "neighbour" },
  { "neighbor", "neighbour" },
  { NULL, NULL }
};

static int
bip_netns_switch (const char *name)
{
  char path[256];
  int fd = -1;

  if (!name || !*name)
    {
      builtin_error ("-netns: NAME required");
      return EX_USAGE;
    }
  if (strchr (name, '/'))
    {
      builtin_error ("-netns: bad namespace name: %s", name);
      return EX_USAGE;
    }

  snprintf (path, sizeof path, "/run/netns/%s", name);
  fd = open (path, O_RDONLY | O_CLOEXEC);
  if (fd < 0 && errno == ENOENT)
    {
      snprintf (path, sizeof path, "/var/run/netns/%s", name);
      fd = open (path, O_RDONLY | O_CLOEXEC);
    }
  if (fd < 0)
    {
      builtin_error ("-netns %s: open /run/netns/%s or /var/run/netns/%s: %s",
                     name, name, name, strerror (errno));
      return EXECUTION_FAILURE;
    }
  if (setns (fd, CLONE_NEWNET) != 0)
    {
      int saved = errno;
      close (fd);
      builtin_error ("-netns %s: setns(CLONE_NEWNET): %s", name, strerror (saved));
      return EXECUTION_FAILURE;
    }
  close (fd);
  return EXECUTION_SUCCESS;
}

static WORD_LIST *
bip_words_from_argv (char **argv, int argc)
{
  WORD_LIST *head = NULL, *tail = NULL;

  for (int i = 0; i < argc; i++)
    {
      WORD_LIST *node = calloc (1, sizeof *node);
      WORD_DESC *word = calloc (1, sizeof *word);
      if (!node || !word)
        {
          free (node);
          free (word);
          return head;
        }
      word->word = argv[i];
      word->flags = 0;
      node->word = word;
      if (tail)
        tail->next = node;
      else
        head = node;
      tail = node;
    }
  return head;
}

static void
bip_free_word_nodes (WORD_LIST *list)
{
  while (list)
    {
      WORD_LIST *next = list->next;
      free (list->word);
      free (list);
      list = next;
    }
}

static int
bip_split_batch_line (char *line, char **argv, int max_argc)
{
  int argc = 0;
  char *p = line;

  while (*p && isspace ((unsigned char) *p))
    p++;
  if (*p == '\0' || *p == '\n' || *p == '#')
    return 0;

  while (*p && argc < max_argc)
    {
      while (*p && isspace ((unsigned char) *p))
        p++;
      if (*p == '\0' || *p == '\n')
        break;
      argv[argc++] = p;
      while (*p && !isspace ((unsigned char) *p))
        p++;
      if (*p)
        *p++ = '\0';
    }

  if (argc > 0 && (strcmp (argv[0], "ip") == 0 || strcmp (argv[0], "baship") == 0))
    {
      for (int i = 1; i < argc; i++)
        argv[i - 1] = argv[i];
      argc--;
    }
  return argc;
}

static int
bip_addattr (struct nlmsghdr *n, size_t maxlen, int type,
             const void *data, int alen)
{
  int len = RTA_LENGTH (alen);
  if (NLMSG_ALIGN (n->nlmsg_len) + RTA_ALIGN (len) > maxlen)
    return -1;
  struct rtattr *rta = NLMSG_TAIL (n);
  rta->rta_type = type;
  rta->rta_len = len;
  if (alen > 0 && data)
    memcpy (RTA_DATA (rta), data, alen);
  n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + RTA_ALIGN (len);
  return 0;
}

static int
bip_addattr_u32 (struct nlmsghdr *n, size_t maxlen, int type, unsigned v)
{
  return bip_addattr (n, maxlen, type, &v, sizeof v);
}

static int
bip_addattr_u8 (struct nlmsghdr *n, size_t maxlen, int type, unsigned char v)
{
  return bip_addattr (n, maxlen, type, &v, sizeof v);
}

static int
bip_addattr_str (struct nlmsghdr *n, size_t maxlen, int type, const char *s)
{
  return bip_addattr (n, maxlen, type, s, (int) strlen (s) + 1);
}

static struct rtattr *
bip_addattr_nest_start (struct nlmsghdr *n, size_t maxlen, int type)
{
  struct rtattr *nest = NLMSG_TAIL (n);
  if (bip_addattr (n, maxlen, type, NULL, 0) < 0)
    return NULL;
  return nest;
}

static void
bip_addattr_nest_end (struct nlmsghdr *n, struct rtattr *nest)
{
  nest->rta_len = (unsigned short) ((char *) NLMSG_TAIL (n) - (char *) nest);
}

/* Walk RTA stream starting at @rta with @len bytes; index by rta_type
   into @tb[0..max].  Returns 0 on success.  */
static int
bip_parse_rta (struct rtattr **tb, int max, struct rtattr *rta, int len)
{
  memset (tb, 0, sizeof (struct rtattr *) * (max + 1));
  while (RTA_OK (rta, len))
    {
      if (rta->rta_type <= max)
        tb[rta->rta_type] = rta;
      rta = RTA_NEXT (rta, len);
    }
  return 0;
}

/* Send @n to the kernel and read replies into a caller buffer @buf
   until NLMSG_DONE (dumps) or ACK (modify).  @cb is invoked once per
   reply nlmsghdr; if @cb returns non-zero, walking stops.  */
typedef int (*bip_cb) (struct nlmsghdr *, void *);

static int
bip_talk (int fd, struct nlmsghdr *n, bip_cb cb, void *ctx)
{
  struct sockaddr_nl kaddr;
  memset (&kaddr, 0, sizeof kaddr);
  kaddr.nl_family = AF_NETLINK;
  struct iovec iov = { n, n->nlmsg_len };
  struct msghdr msg;
  memset (&msg, 0, sizeof msg);
  msg.msg_name = &kaddr;
  msg.msg_namelen = sizeof kaddr;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  ssize_t s = sendmsg (fd, &msg, 0);
  if (s < 0)
    {
      builtin_error ("netlink send: %s", strerror (errno));
      return -1;
    }
  unsigned wanted_seq = n->nlmsg_seq;
  char *buf = malloc (BIP_BUFSZ);
  if (!buf)
    {
      builtin_error ("netlink: malloc failed");
      return -1;
    }
  int rc = 0;
  for (;;)
    {
      iov.iov_base = buf;
      iov.iov_len = BIP_BUFSZ;
      s = recvmsg (fd, &msg, 0);
      if (s < 0)
        {
          if (errno == EINTR)
            continue;
          builtin_error ("netlink recv: %s", strerror (errno));
          rc = -1;
          break;
        }
      if (s == 0)
        {
          builtin_error ("netlink: EOF on socket");
          rc = -1;
          break;
        }
      struct nlmsghdr *h = (struct nlmsghdr *) buf;
      int done = 0;
      while (NLMSG_OK (h, (size_t) s))
        {
          if (h->nlmsg_seq != wanted_seq)
            { h = NLMSG_NEXT (h, s); continue; }
          if (h->nlmsg_type == NLMSG_DONE)
            { done = 1; break; }
          if (h->nlmsg_type == NLMSG_ERROR)
            {
              struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA (h);
              if (err->error == 0)
                { done = 1; break; }                /* ACK */
              errno = -err->error;
              builtin_error ("rtnetlink: %s", strerror (errno));
              if (errno == EPERM)
                builtin_error ("(this verb needs CAP_NET_ADMIN; try as uid 0)");
              rc = -1;
              done = 1;
              break;
            }
          if (cb && cb (h, ctx) != 0)
            { done = 1; break; }
          h = NLMSG_NEXT (h, s);
        }
      if (done)
        break;
    }
  free (buf);
  return rc;
}

/* ----------------------------------------------------------------- */
/* CIDR + address helpers                                              */
/* ----------------------------------------------------------------- */

/* Parse "10.0.0.1/24" or "::1/64" into family + raw bytes + prefixlen.
   Bare "10.0.0.1" yields prefix 32 (v4) or 128 (v6).  Returns 0 on
   success, -1 on parse error.  */
static int
bip_parse_cidr (const char *s, int *fam, unsigned char *out, int outsz,
                int *prefix, int *bytes)
{
  char tmp[64];
  if (!s || strlen (s) >= sizeof tmp)
    return -1;
  strncpy (tmp, s, sizeof tmp - 1);
  tmp[sizeof tmp - 1] = 0;
  char *slash = strchr (tmp, '/');
  int p = -1;
  if (slash)
    {
      *slash = 0;
      p = atoi (slash + 1);
      if (p < 0 || p > 128)
        return -1;
    }
  struct in_addr a4;
  struct in6_addr a6;
  if (inet_pton (AF_INET, tmp, &a4) == 1)
    {
      if (outsz < 4) return -1;
      memcpy (out, &a4, 4);
      *fam = AF_INET;
      *bytes = 4;
      *prefix = (p < 0) ? 32 : (p > 32 ? 32 : p);
      return 0;
    }
  if (inet_pton (AF_INET6, tmp, &a6) == 1)
    {
      if (outsz < 16) return -1;
      memcpy (out, &a6, 16);
      *fam = AF_INET6;
      *bytes = 16;
      *prefix = (p < 0) ? 128 : p;
      return 0;
    }
  return -1;
}

static int
bip_iface_index (const char *name)
{
  unsigned idx = if_nametoindex (name);
  if (idx == 0)
    {
      builtin_error ("unknown interface: %s", name);
      return -1;
    }
  return (int) idx;
}

static const char *
bip_family_name (int fam)
{
  return fam == AF_INET ? "inet" : (fam == AF_INET6 ? "inet6" : "?");
}

static int
bip_parse_u32 (const char *s, unsigned *out)
{
  char *end = NULL;
  errno = 0;
  unsigned long v = strtoul (s, &end, 10);
  if (errno || !s || !*s || (end && *end) || v > 0xffffffffUL)
    return -1;
  *out = (unsigned) v;
  return 0;
}

static int
bip_parse_u32_base0 (const char *s, unsigned *out)
{
  char *end = NULL;
  errno = 0;
  unsigned long v = strtoul (s, &end, 0);
  if (errno || !s || !*s || (end && *end) || v > 0xffffffffUL)
    return -1;
  *out = (unsigned) v;
  return 0;
}

static int
bip_parse_table (const char *s, unsigned *out)
{
  if (strcmp (s, "local") == 0)
    { *out = RT_TABLE_LOCAL; return 0; }
  if (strcmp (s, "main") == 0)
    { *out = RT_TABLE_MAIN; return 0; }
  if (strcmp (s, "default") == 0)
    { *out = RT_TABLE_DEFAULT; return 0; }
  return bip_parse_u32 (s, out);
}

static int
bip_parse_ipproto (const char *s, unsigned *out)
{
  if (strcmp (s, "tcp") == 0)
    { *out = IPPROTO_TCP; return 0; }
  if (strcmp (s, "udp") == 0)
    { *out = IPPROTO_UDP; return 0; }
  if (strcmp (s, "icmp") == 0)
    { *out = IPPROTO_ICMP; return 0; }
  if (strcmp (s, "icmpv6") == 0 || strcmp (s, "ipv6-icmp") == 0)
    { *out = IPPROTO_ICMPV6; return 0; }
  if (strcmp (s, "sctp") == 0)
    { *out = IPPROTO_SCTP; return 0; }
#ifdef IPPROTO_UDPLITE
  if (strcmp (s, "udplite") == 0)
    { *out = IPPROTO_UDPLITE; return 0; }
#endif
  if (bip_parse_u32 (s, out) < 0 || *out > 255)
    return -1;
  return 0;
}

static const char *
bip_ipproto_name (unsigned proto, char *buf, size_t bufsz)
{
  switch (proto)
    {
    case IPPROTO_TCP: return "tcp";
    case IPPROTO_UDP: return "udp";
    case IPPROTO_ICMP: return "icmp";
    case IPPROTO_ICMPV6: return "icmpv6";
    case IPPROTO_SCTP: return "sctp";
#ifdef IPPROTO_UDPLITE
    case IPPROTO_UDPLITE: return "udplite";
#endif
    default:
      snprintf (buf, bufsz, "%u", proto);
      return buf;
    }
}

static int
bip_parse_uidrange (const char *s, struct fib_rule_uid_range *range)
{
  char buf[64];
  snprintf (buf, sizeof buf, "%s", s);
  char *dash = strchr (buf, '-');
  unsigned start = 0, end = 0;
  if (dash)
    {
      *dash = '\0';
      if (bip_parse_u32 (buf, &start) < 0 || bip_parse_u32 (dash + 1, &end) < 0)
        return -1;
    }
  else if (bip_parse_u32 (buf, &start) < 0)
    return -1;
  else
    end = start;
  if (end < start)
    return -1;
  range->start = start;
  range->end = end;
  return 0;
}

static int
bip_hex_nibble (char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int
bip_parse_lladdr (const char *s, unsigned char mac[6])
{
  if (!s)
    return -1;
  for (int i = 0; i < 6; i++)
    {
      int hi = bip_hex_nibble (s[0]);
      int lo = bip_hex_nibble (s[1]);
      if (hi < 0 || lo < 0)
        return -1;
      mac[i] = (unsigned char) ((hi << 4) | lo);
      s += 2;
      if (i < 5)
        {
          if (*s != ':')
            return -1;
          s++;
        }
    }
  return *s == '\0' ? 0 : -1;
}

static int
bip_parse_nud (const char *s, unsigned *out)
{
  if (strcmp (s, "none") == 0)
    { *out = NUD_NONE; return 0; }
  if (strcmp (s, "incomplete") == 0)
    { *out = NUD_INCOMPLETE; return 0; }
  if (strcmp (s, "reachable") == 0)
    { *out = NUD_REACHABLE; return 0; }
  if (strcmp (s, "stale") == 0)
    { *out = NUD_STALE; return 0; }
  if (strcmp (s, "delay") == 0)
    { *out = NUD_DELAY; return 0; }
  if (strcmp (s, "probe") == 0)
    { *out = NUD_PROBE; return 0; }
  if (strcmp (s, "failed") == 0)
    { *out = NUD_FAILED; return 0; }
  if (strcmp (s, "noarp") == 0)
    { *out = NUD_NOARP; return 0; }
  if (strcmp (s, "permanent") == 0)
    { *out = NUD_PERMANENT; return 0; }
  return -1;
}

static const char *
bip_table_name (unsigned table, char *buf, size_t bufsz)
{
  if (table == RT_TABLE_LOCAL) return "local";
  if (table == RT_TABLE_MAIN) return "main";
  if (table == RT_TABLE_DEFAULT) return "default";
  snprintf (buf, bufsz, "%u", table);
  return buf;
}

static const char *
bip_operstate_name (unsigned char st)
{
  static const char *names[] = {
    "UNKNOWN", "NOTPRESENT", "DOWN", "LOWERLAYERDOWN",
    "TESTING", "DORMANT", "UP"
  };
  return st < (sizeof names / sizeof names[0]) ? names[st] : "UNKNOWN";
}

static const char *
bip_oper_state_fallback (unsigned ifi_flags)
{
  if (ifi_flags & IFF_UP)
    return (ifi_flags & IFF_RUNNING) ? "UP" : "UP";
  return "DOWN";
}

static const char *
bip_addr_scope_name (unsigned scope, char *buf, size_t bufsz)
{
  if (scope == RT_SCOPE_HOST) return "host";
  if (scope == RT_SCOPE_LINK) return "link";
  if (scope == RT_SCOPE_UNIVERSE) return "global";
  snprintf (buf, bufsz, "%u", scope);
  return buf;
}

static void
bip_lladdr_string (struct rtattr *rta, char *buf, size_t bufsz)
{
  buf[0] = '\0';
  if (!rta || bufsz == 0)
    return;
  unsigned char *m = RTA_DATA (rta);
  int mlen = RTA_PAYLOAD (rta);
  size_t off = 0;
  for (int i = 0; i < mlen && off + 3 < bufsz; i++)
    {
      int n = snprintf (buf + off, bufsz - off, "%02x%s",
                        m[i], i + 1 < mlen ? ":" : "");
      if (n < 0 || (size_t) n >= bufsz - off)
        break;
      off += (size_t) n;
    }
}

static int
bip_flag_emit (int *first, const char *name)
{
  printf ("%s%s", *first ? "" : ",", name);
  *first = 0;
  return 0;
}

static void
bip_emit_link_flags_text (unsigned flags)
{
  int first = 1;
  printf ("<");
  if ((flags & IFF_UP) && !(flags & IFF_RUNNING))
    bip_flag_emit (&first, "NO-CARRIER");
  flags &= ~((unsigned) IFF_RUNNING);
  if (flags & IFF_LOOPBACK) bip_flag_emit (&first, "LOOPBACK");
  if (flags & IFF_BROADCAST) bip_flag_emit (&first, "BROADCAST");
  if (flags & IFF_POINTOPOINT) bip_flag_emit (&first, "POINTOPOINT");
  if (flags & IFF_MULTICAST) bip_flag_emit (&first, "MULTICAST");
  if (flags & IFF_NOARP) bip_flag_emit (&first, "NOARP");
  if (flags & IFF_ALLMULTI) bip_flag_emit (&first, "ALLMULTI");
  if (flags & IFF_PROMISC) bip_flag_emit (&first, "PROMISC");
  if (flags & IFF_MASTER) bip_flag_emit (&first, "MASTER");
  if (flags & IFF_SLAVE) bip_flag_emit (&first, "SLAVE");
  if (flags & IFF_DEBUG) bip_flag_emit (&first, "DEBUG");
  if (flags & IFF_DYNAMIC) bip_flag_emit (&first, "DYNAMIC");
  if (flags & IFF_AUTOMEDIA) bip_flag_emit (&first, "AUTOMEDIA");
  if (flags & IFF_PORTSEL) bip_flag_emit (&first, "PORTSEL");
  if (flags & IFF_NOTRAILERS) bip_flag_emit (&first, "NOTRAILERS");
  if (flags & IFF_UP) bip_flag_emit (&first, "UP");
#ifdef IFF_LOWER_UP
  if (flags & IFF_LOWER_UP) bip_flag_emit (&first, "LOWER_UP");
#endif
#ifdef IFF_DORMANT
  if (flags & IFF_DORMANT) bip_flag_emit (&first, "DORMANT");
#endif
#ifdef IFF_ECHO
  if (flags & IFF_ECHO) bip_flag_emit (&first, "ECHO");
#endif
  printf (">");
}

static void
bip_json_string (const char *s)
{
  putchar ('"');
  for (; s && *s; s++)
    {
      unsigned char c = (unsigned char) *s;
      if (c == '"' || c == '\\')
        printf ("\\%c", c);
      else if (c == '\b')
        printf ("\\b");
      else if (c == '\f')
        printf ("\\f");
      else if (c == '\n')
        printf ("\\n");
      else if (c == '\r')
        printf ("\\r");
      else if (c == '\t')
        printf ("\\t");
      else if (c < 0x20)
        printf ("\\u%04x", c);
      else
        putchar (c);
    }
  putchar ('"');
}

static void
bip_emit_link_flags_json (unsigned flags)
{
  int first = 1;
  printf ("[");
  if ((flags & IFF_UP) && !(flags & IFF_RUNNING))
    {
      printf ("%s\"NO-CARRIER\"", first ? "" : ",");
      first = 0;
    }
  flags &= ~((unsigned) IFF_RUNNING);
#define BIP_JSON_FLAG(bit, name) \
  do { if (flags & (bit)) { printf ("%s\"%s\"", first ? "" : ",", name); first = 0; } } while (0)
  BIP_JSON_FLAG (IFF_LOOPBACK, "LOOPBACK");
  BIP_JSON_FLAG (IFF_BROADCAST, "BROADCAST");
  BIP_JSON_FLAG (IFF_POINTOPOINT, "POINTOPOINT");
  BIP_JSON_FLAG (IFF_MULTICAST, "MULTICAST");
  BIP_JSON_FLAG (IFF_NOARP, "NOARP");
  BIP_JSON_FLAG (IFF_ALLMULTI, "ALLMULTI");
  BIP_JSON_FLAG (IFF_PROMISC, "PROMISC");
  BIP_JSON_FLAG (IFF_MASTER, "MASTER");
  BIP_JSON_FLAG (IFF_SLAVE, "SLAVE");
  BIP_JSON_FLAG (IFF_DEBUG, "DEBUG");
  BIP_JSON_FLAG (IFF_DYNAMIC, "DYNAMIC");
  BIP_JSON_FLAG (IFF_AUTOMEDIA, "AUTOMEDIA");
  BIP_JSON_FLAG (IFF_PORTSEL, "PORTSEL");
  BIP_JSON_FLAG (IFF_NOTRAILERS, "NOTRAILERS");
  BIP_JSON_FLAG (IFF_UP, "UP");
#ifdef IFF_LOWER_UP
  BIP_JSON_FLAG (IFF_LOWER_UP, "LOWER_UP");
#endif
#ifdef IFF_DORMANT
  BIP_JSON_FLAG (IFF_DORMANT, "DORMANT");
#endif
#ifdef IFF_ECHO
  BIP_JSON_FLAG (IFF_ECHO, "ECHO");
#endif
#undef BIP_JSON_FLAG
  printf ("]");
}

/* ----------------------------------------------------------------- */
/* link show                                                            */
/* ----------------------------------------------------------------- */

struct bip_show_ctx
{
  const char *want_ifname;   /* NULL = show all */
  int family;                /* AF_UNSPEC, AF_INET, AF_INET6 */
  int brief;
  int oneline;
  int json;
  int first;
  const struct bip_addr_filter *addr_filter;
};

struct bip_addr_filter
{
  int have_to;
  int to_family;
  unsigned char to_raw[16];
  int to_prefix;
  int to_bytes;
  int have_scope;
  unsigned scope;
};

struct bip_addr_item
{
  int family;
  char local[INET6_ADDRSTRLEN];
  unsigned prefixlen;
  unsigned scope;
  struct bip_addr_item *next;
};

struct bip_iface_item
{
  unsigned ifindex;
  char ifname[IFNAMSIZ];
  unsigned flags;
  unsigned mtu;
  unsigned short iftype;
  int have_operstate;
  unsigned char operstate;
  char address[96];
  char broadcast[96];
  struct bip_addr_item *addrs;
  struct bip_addr_item *addr_tail;
  struct bip_iface_item *next;
};

struct bip_iface_collect_ctx
{
  const char *want_ifname;
  int family;
  const struct bip_addr_filter *addr_filter;
  struct bip_iface_item *ifaces;
  struct bip_iface_item *tail;
};

static int
bip_addr_filter_active (const struct bip_addr_filter *filter)
{
  return filter && (filter->have_to || filter->have_scope);
}

static int
bip_addr_prefix_match (int family, const unsigned char *raw,
                       const unsigned char *prefix, int prefixlen)
{
  int bytes = family == AF_INET ? 4 : (family == AF_INET6 ? 16 : 0);
  if (bytes <= 0 || prefixlen < 0 || prefixlen > bytes * 8)
    return 0;
  int full = prefixlen / 8;
  int rem = prefixlen % 8;
  if (full > 0 && memcmp (raw, prefix, (size_t) full) != 0)
    return 0;
  if (rem)
    {
      unsigned char mask = (unsigned char) (0xffU << (8 - rem));
      if ((raw[full] & mask) != (prefix[full] & mask))
        return 0;
    }
  return 1;
}

static int
bip_addr_matches_filter (int family, const unsigned char *raw, unsigned scope,
                         const struct bip_addr_filter *filter)
{
  if (!bip_addr_filter_active (filter))
    return 1;
  if (filter->have_scope && scope != filter->scope)
    return 0;
  if (filter->have_to)
    {
      if (family != filter->to_family)
        return 0;
      if (!bip_addr_prefix_match (family, raw, filter->to_raw, filter->to_prefix))
        return 0;
    }
  return 1;
}

static int
bip_parse_addr_scope (const char *s, unsigned *scope)
{
  if (strcmp (s, "host") == 0)
    { *scope = RT_SCOPE_HOST; return 0; }
  if (strcmp (s, "link") == 0)
    { *scope = RT_SCOPE_LINK; return 0; }
  if (strcmp (s, "global") == 0)
    { *scope = RT_SCOPE_UNIVERSE; return 0; }
  if (bip_parse_u32 (s, scope) < 0 || *scope > 255)
    return -1;
  return 0;
}

static struct bip_iface_item *
bip_iface_find (struct bip_iface_collect_ctx *ctx, unsigned ifindex)
{
  for (struct bip_iface_item *it = ctx->ifaces; it; it = it->next)
    if (it->ifindex == ifindex)
      return it;
  return NULL;
}

static void
bip_iface_free_all (struct bip_iface_collect_ctx *ctx)
{
  struct bip_iface_item *it = ctx->ifaces;
  while (it)
    {
      struct bip_iface_item *next = it->next;
      struct bip_addr_item *a = it->addrs;
      while (a)
        {
          struct bip_addr_item *anext = a->next;
          free (a);
          a = anext;
        }
      free (it);
      it = next;
    }
  ctx->ifaces = ctx->tail = NULL;
}

static const char *
bip_iface_oper (const struct bip_iface_item *it, char *fallback, size_t fallback_sz)
{
  if (it->have_operstate)
    return bip_operstate_name (it->operstate);
  snprintf (fallback, fallback_sz, "%s", bip_oper_state_fallback (it->flags));
  return fallback;
}

static int
bip_collect_links_cb (struct nlmsghdr *h, void *vctx)
{
  struct bip_iface_collect_ctx *ctx = vctx;
  if (h->nlmsg_type != RTM_NEWLINK)
    return 0;
  struct ifinfomsg *ifi = NLMSG_DATA (h);
  int len = h->nlmsg_len - NLMSG_LENGTH (sizeof *ifi);
  if (len < 0)
    return 0;
  struct rtattr *tb[IFLA_MAX + 1];
  bip_parse_rta (tb, IFLA_MAX, IFLA_RTA (ifi), len);
  const char *ifname = tb[IFLA_IFNAME] ? RTA_DATA (tb[IFLA_IFNAME]) : "?";
  if (ctx->want_ifname && strcmp (ifname, ctx->want_ifname) != 0)
    return 0;

  struct bip_iface_item *it = calloc (1, sizeof *it);
  if (!it)
    return 0;
  it->ifindex = (unsigned) ifi->ifi_index;
  snprintf (it->ifname, sizeof it->ifname, "%s", ifname);
  it->flags = (unsigned) ifi->ifi_flags;
  it->iftype = ifi->ifi_type;
  it->mtu = tb[IFLA_MTU] ? *(unsigned *) RTA_DATA (tb[IFLA_MTU]) : 0;
  if (tb[IFLA_OPERSTATE])
    {
      it->have_operstate = 1;
      it->operstate = *(unsigned char *) RTA_DATA (tb[IFLA_OPERSTATE]);
    }
  bip_lladdr_string (tb[IFLA_ADDRESS], it->address, sizeof it->address);
  bip_lladdr_string (tb[IFLA_BROADCAST], it->broadcast, sizeof it->broadcast);
  if (ctx->tail)
    ctx->tail->next = it;
  else
    ctx->ifaces = it;
  ctx->tail = it;
  return 0;
}

static int
bip_collect_addrs_cb (struct nlmsghdr *h, void *vctx)
{
  struct bip_iface_collect_ctx *ctx = vctx;
  if (h->nlmsg_type != RTM_NEWADDR)
    return 0;
  struct ifaddrmsg *ifa = NLMSG_DATA (h);
  int len = h->nlmsg_len - NLMSG_LENGTH (sizeof *ifa);
  if (len < 0)
    return 0;
  if (ctx->family != AF_UNSPEC && ifa->ifa_family != ctx->family)
    return 0;
  struct bip_iface_item *iface = bip_iface_find (ctx, ifa->ifa_index);
  if (!iface)
    return 0;

  struct rtattr *tb[IFA_MAX + 1];
  bip_parse_rta (tb, IFA_MAX, IFA_RTA (ifa), len);
  void *raw = tb[IFA_LOCAL] ? RTA_DATA (tb[IFA_LOCAL]) :
              (tb[IFA_ADDRESS] ? RTA_DATA (tb[IFA_ADDRESS]) : NULL);
  if (!raw)
    return 0;
  if (!bip_addr_matches_filter (ifa->ifa_family, raw, ifa->ifa_scope,
                                ctx->addr_filter))
    return 0;

  struct bip_addr_item *a = calloc (1, sizeof *a);
  if (!a)
    return 0;
  a->family = ifa->ifa_family;
  a->prefixlen = ifa->ifa_prefixlen;
  a->scope = ifa->ifa_scope;
  if (!inet_ntop (ifa->ifa_family, raw, a->local, sizeof a->local))
    {
      free (a);
      return 0;
    }
  if (iface->addr_tail)
    iface->addr_tail->next = a;
  else
    iface->addrs = a;
  iface->addr_tail = a;
  return 0;
}

static int
bip_collect_ifaces (struct bip_iface_collect_ctx *ctx)
{
  int fd = bip_open ();
  if (fd < 0)
    return -1;
  struct
  {
    struct nlmsghdr n;
    struct ifinfomsg i;
    char attrs[64];
  } req;
  memset (&req, 0, sizeof req);
  req.n.nlmsg_len = NLMSG_LENGTH (sizeof req.i);
  req.n.nlmsg_type = RTM_GETLINK;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.n.nlmsg_seq = bip_seq ();
  req.i.ifi_family = AF_UNSPEC;
  int rc = bip_talk (fd, &req.n, bip_collect_links_cb, ctx);
  close (fd);
  if (rc != 0)
    return -1;

  fd = bip_open ();
  if (fd < 0)
    return -1;
  struct
  {
    struct nlmsghdr n;
    struct ifaddrmsg a;
    char attrs[64];
  } areq;
  memset (&areq, 0, sizeof areq);
  areq.n.nlmsg_len = NLMSG_LENGTH (sizeof areq.a);
  areq.n.nlmsg_type = RTM_GETADDR;
  areq.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  areq.n.nlmsg_seq = bip_seq ();
  areq.a.ifa_family = (unsigned char) ctx->family;
  rc = bip_talk (fd, &areq.n, bip_collect_addrs_cb, ctx);
  close (fd);
  return rc == 0 ? 0 : -1;
}

static void
bip_emit_brief_addr (const struct bip_iface_collect_ctx *ctx)
{
  for (const struct bip_iface_item *it = ctx->ifaces; it; it = it->next)
    {
      if (bip_addr_filter_active (ctx->addr_filter) && !it->addrs)
        continue;
      char fallback[16];
      printf ("%-16s %-14s ", it->ifname,
              bip_iface_oper (it, fallback, sizeof fallback));
      for (const struct bip_addr_item *a = it->addrs; a; a = a->next)
        printf ("%s/%u ", a->local, a->prefixlen);
      printf ("\n");
    }
}

static void
bip_emit_json_addr (const struct bip_iface_collect_ctx *ctx)
{
  int first_iface = 1;
  printf ("[");
  for (const struct bip_iface_item *it = ctx->ifaces; it; it = it->next)
    {
      if (bip_addr_filter_active (ctx->addr_filter) && !it->addrs)
        continue;
      char fallback[16];
      printf ("%s{\"ifindex\":%u,\"ifname\":", first_iface ? "" : ",", it->ifindex);
      first_iface = 0;
      bip_json_string (it->ifname);
      printf (",\"flags\":");
      bip_emit_link_flags_json (it->flags);
      printf (",\"mtu\":%u,\"operstate\":", it->mtu);
      bip_json_string (bip_iface_oper (it, fallback, sizeof fallback));
      printf (",\"link_type\":");
      bip_json_string (it->iftype == ARPHRD_LOOPBACK ? "loopback" : "ether");
      if (it->address[0])
        {
          printf (",\"address\":");
          bip_json_string (it->address);
        }
      if (it->broadcast[0])
        {
          printf (",\"broadcast\":");
          bip_json_string (it->broadcast);
        }
      printf (",\"addr_info\":[");
      int first_addr = 1;
      for (const struct bip_addr_item *a = it->addrs; a; a = a->next)
        {
          char scope_buf[32];
          printf ("%s{\"family\":\"%s\",\"local\":", first_addr ? "" : ",",
                  bip_family_name (a->family));
          first_addr = 0;
          bip_json_string (a->local);
          printf (",\"prefixlen\":%u,\"scope\":", a->prefixlen);
          bip_json_string (bip_addr_scope_name (a->scope, scope_buf, sizeof scope_buf));
          printf ("}");
        }
      printf ("]}");
    }
  printf ("]\n");
}

static void
bip_emit_json_link (const struct bip_iface_collect_ctx *ctx)
{
  int first_iface = 1;
  printf ("[");
  for (const struct bip_iface_item *it = ctx->ifaces; it; it = it->next)
    {
      char fallback[16];
      printf ("%s{\"ifindex\":%u,\"ifname\":", first_iface ? "" : ",", it->ifindex);
      first_iface = 0;
      bip_json_string (it->ifname);
      printf (",\"flags\":");
      bip_emit_link_flags_json (it->flags);
      printf (",\"mtu\":%u,\"operstate\":", it->mtu);
      bip_json_string (bip_iface_oper (it, fallback, sizeof fallback));
      printf (",\"link_type\":");
      bip_json_string (it->iftype == ARPHRD_LOOPBACK ? "loopback" : "ether");
      if (it->address[0])
        {
          printf (",\"address\":");
          bip_json_string (it->address);
        }
      if (it->broadcast[0])
        {
          printf (",\"broadcast\":");
          bip_json_string (it->broadcast);
        }
      printf ("}");
    }
  printf ("]\n");
}

struct bip_route_show_ctx
{
  int family;
  unsigned ifindex;
  int only_default;
  int all_tables;
  unsigned table;
  int brief;
  int json;
  int first;
};

static int
bip_opts_family_or (const struct bip_ip_opts *opts, int default_family)
{
  if (opts && opts->family != AF_UNSPEC)
    return opts->family;
  return default_family;
}

static int
bip_link_show_cb (struct nlmsghdr *h, void *vctx)
{
  struct bip_show_ctx *ctx = vctx;
  if (h->nlmsg_type != RTM_NEWLINK)
    return 0;
  struct ifinfomsg *ifi = NLMSG_DATA (h);
  int len = h->nlmsg_len - NLMSG_LENGTH (sizeof *ifi);
  if (len < 0)
    return 0;
  struct rtattr *tb[IFLA_MAX + 1];
  bip_parse_rta (tb, IFLA_MAX, IFLA_RTA (ifi), len);
  const char *ifname = tb[IFLA_IFNAME] ? RTA_DATA (tb[IFLA_IFNAME]) : "?";
  if (ctx && ctx->want_ifname && strcmp (ifname, ctx->want_ifname) != 0)
    return 0;
  unsigned mtu = tb[IFLA_MTU] ? *(unsigned *) RTA_DATA (tb[IFLA_MTU]) : 0;
  const char *oper = bip_oper_state_fallback ((unsigned) ifi->ifi_flags);
  if (tb[IFLA_OPERSTATE])
    {
      unsigned char st = *(unsigned char *) RTA_DATA (tb[IFLA_OPERSTATE]);
      oper = bip_operstate_name (st);
    }
  if (ctx && ctx->brief)
    {
      char lladdr[96];
      bip_lladdr_string (tb[IFLA_ADDRESS], lladdr, sizeof lladdr);
      printf ("%-16s %-14s ", ifname, oper);
      if (lladdr[0])
        printf ("%s ", lladdr);
      bip_emit_link_flags_text ((unsigned) ifi->ifi_flags);
      printf (" \n");
      return 0;
    }
  printf ("%d: %s: <%s%s%s> mtu %u state %s",
          ifi->ifi_index, ifname,
          (ifi->ifi_flags & IFF_UP) ? "UP," : "",
          (ifi->ifi_flags & IFF_BROADCAST) ? "BROADCAST," : "",
          (ifi->ifi_flags & IFF_LOOPBACK) ? "LOOPBACK" : "MULTICAST",
          mtu, oper);
  if (ctx && ctx->oneline)
    printf (" \\ ");
  else
    printf ("\n");
  if (tb[IFLA_ADDRESS])
    {
      unsigned char *m = RTA_DATA (tb[IFLA_ADDRESS]);
      int mlen = RTA_PAYLOAD (tb[IFLA_ADDRESS]);
      printf ("    link/%s ",
              ifi->ifi_type == ARPHRD_LOOPBACK ? "loopback" : "ether");
      for (int i = 0; i < mlen; i++)
        printf ("%02x%s", m[i], i + 1 < mlen ? ":" : "");
      printf ("\n");
    }
  else if (ctx && ctx->oneline)
    printf ("\n");
  return 0;
}

static int
bip_link_show (const char *ifname, int brief, int oneline, int json)
{
  if (json)
    {
      struct bip_iface_collect_ctx cctx;
      memset (&cctx, 0, sizeof cctx);
      cctx.want_ifname = ifname;
      cctx.family = AF_UNSPEC;
      cctx.addr_filter = NULL;
      if (bip_collect_ifaces (&cctx) != 0)
        {
          bip_iface_free_all (&cctx);
          return EXECUTION_FAILURE;
        }
      bip_emit_json_link (&cctx);
      bip_iface_free_all (&cctx);
      return EXECUTION_SUCCESS;
    }

  int fd = bip_open ();
  if (fd < 0) return EXECUTION_FAILURE;
  struct
  {
    struct nlmsghdr n;
    struct ifinfomsg i;
    char attrs[256];
  } req;
  memset (&req, 0, sizeof req);
  req.n.nlmsg_len = NLMSG_LENGTH (sizeof req.i);
  req.n.nlmsg_type = RTM_GETLINK;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.n.nlmsg_seq = bip_seq ();
  req.i.ifi_family = AF_UNSPEC;
  struct bip_show_ctx ctx = { ifname, AF_UNSPEC, brief, oneline, 0, 1, NULL };
  int rc = bip_talk (fd, &req.n, bip_link_show_cb, &ctx);
  close (fd);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* ----------------------------------------------------------------- */
/* link set                                                             */
/* ----------------------------------------------------------------- */

static int
bip_link_set (const char *ifname, int up, int down, int mtu,
	      const unsigned char *lladdr)
{
  int idx = bip_iface_index (ifname);
  if (idx < 0) return EXECUTION_FAILURE;
  int fd = bip_open ();
  if (fd < 0) return EXECUTION_FAILURE;
  struct
  {
    struct nlmsghdr n;
    struct ifinfomsg i;
    char attrs[128];
  } req;
  memset (&req, 0, sizeof req);
  req.n.nlmsg_len = NLMSG_LENGTH (sizeof req.i);
  req.n.nlmsg_type = RTM_NEWLINK;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.n.nlmsg_seq = bip_seq ();
  req.i.ifi_family = AF_UNSPEC;
  req.i.ifi_index = idx;
  if (up)
    {
      req.i.ifi_change |= IFF_UP;
      req.i.ifi_flags |= IFF_UP;
    }
  if (down)
    {
      req.i.ifi_change |= IFF_UP;
      req.i.ifi_flags &= ~IFF_UP;
    }
  if (mtu > 0)
    {
      unsigned m = (unsigned) mtu;
      bip_addattr (&req.n, sizeof req, IFLA_MTU, &m, sizeof m);
    }
  /* Most drivers refuse a hardware-address change while the interface is UP,
     so callers set the address before bringing it up. */
  if (lladdr)
    bip_addattr (&req.n, sizeof req, IFLA_ADDRESS, lladdr, 6);
  int rc = bip_talk (fd, &req.n, NULL, NULL);
  close (fd);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bip_ifname_ok (const char *name)
{
  return name && *name && strlen (name) < IFNAMSIZ;
}

static int
bip_link_del (const char *ifname)
{
  int idx = bip_iface_index (ifname);
  if (idx < 0) return EXECUTION_FAILURE;
  int fd = bip_open ();
  if (fd < 0) return EXECUTION_FAILURE;
  struct
  {
    struct nlmsghdr n;
    struct ifinfomsg i;
  } req;
  memset (&req, 0, sizeof req);
  req.n.nlmsg_len = NLMSG_LENGTH (sizeof req.i);
  req.n.nlmsg_type = RTM_DELLINK;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.n.nlmsg_seq = bip_seq ();
  req.i.ifi_family = AF_UNSPEC;
  req.i.ifi_index = idx;
  int rc = bip_talk (fd, &req.n, NULL, NULL);
  close (fd);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bip_link_add_veth_peer (struct nlmsghdr *n, size_t maxlen, const char *peername)
{
  int len = RTA_LENGTH (sizeof (struct ifinfomsg));
  if (NLMSG_ALIGN (n->nlmsg_len) + RTA_ALIGN (len) > maxlen)
    return -1;
  struct rtattr *peer = NLMSG_TAIL (n);
  peer->rta_type = VETH_INFO_PEER;
  peer->rta_len = (unsigned short) len;
  struct ifinfomsg *pi = RTA_DATA (peer);
  memset (pi, 0, sizeof *pi);
  pi->ifi_family = AF_UNSPEC;
  n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + RTA_ALIGN (len);
  if (bip_addattr_str (n, maxlen, IFLA_IFNAME, peername) < 0)
    return -1;
  bip_addattr_nest_end (n, peer);
  return 0;
}

static int
bip_link_add (const char *ifname, const char *kind, const char *peername)
{
  if (!bip_ifname_ok (ifname))
    {
      builtin_error ("link add: bad interface name: %s", ifname ? ifname : "");
      return EX_USAGE;
    }
  if (!kind)
    {
      builtin_error ("link add: type dummy|veth required");
      return EX_USAGE;
    }
  if (strcmp (kind, "dummy") != 0 && strcmp (kind, "veth") != 0)
    {
      builtin_error ("link add: kind not supported: %s (supported: dummy, veth)", kind);
      return EX_USAGE;
    }
  if (strcmp (kind, "dummy") == 0 && peername)
    {
      builtin_error ("link add: peer is only supported for type veth");
      return EX_USAGE;
    }
  if (strcmp (kind, "veth") == 0 && !bip_ifname_ok (peername))
    {
      builtin_error ("link add: type veth requires peer NAME");
      return EX_USAGE;
    }

  int fd = bip_open ();
  if (fd < 0) return EXECUTION_FAILURE;
  struct
  {
    struct nlmsghdr n;
    struct ifinfomsg i;
    char attrs[1024];
  } req;
  memset (&req, 0, sizeof req);
  req.n.nlmsg_len = NLMSG_LENGTH (sizeof req.i);
  req.n.nlmsg_type = RTM_NEWLINK;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
  req.n.nlmsg_seq = bip_seq ();
  req.i.ifi_family = AF_UNSPEC;
  int ok = 1;
  if (bip_addattr_str (&req.n, sizeof req, IFLA_IFNAME, ifname) < 0)
    ok = 0;
  struct rtattr *linkinfo = ok ? bip_addattr_nest_start (&req.n, sizeof req, IFLA_LINKINFO) : NULL;
  if (!linkinfo)
    ok = 0;
  if (ok && bip_addattr_str (&req.n, sizeof req, IFLA_INFO_KIND, kind) < 0)
    ok = 0;
  if (ok && strcmp (kind, "veth") == 0)
    {
      struct rtattr *data = bip_addattr_nest_start (&req.n, sizeof req, IFLA_INFO_DATA);
      if (!data || bip_link_add_veth_peer (&req.n, sizeof req, peername) < 0)
        ok = 0;
      if (ok)
        bip_addattr_nest_end (&req.n, data);
    }
  if (ok)
    bip_addattr_nest_end (&req.n, linkinfo);
  if (!ok)
    {
      close (fd);
      builtin_error ("link add: netlink attribute buffer exhausted");
      return EXECUTION_FAILURE;
    }
  int rc = bip_talk (fd, &req.n, NULL, NULL);
  close (fd);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* ----------------------------------------------------------------- */
/* addr show                                                            */
/* ----------------------------------------------------------------- */

static int
bip_addr_show_cb (struct nlmsghdr *h, void *vctx)
{
  struct bip_show_ctx *ctx = vctx;
  if (h->nlmsg_type != RTM_NEWADDR)
    return 0;
  struct ifaddrmsg *ifa = NLMSG_DATA (h);
  int len = h->nlmsg_len - NLMSG_LENGTH (sizeof *ifa);
  if (len < 0)
    return 0;
  if (ctx && ctx->family != AF_UNSPEC && ifa->ifa_family != ctx->family)
    return 0;
  struct rtattr *tb[IFA_MAX + 1];
  bip_parse_rta (tb, IFA_MAX, IFA_RTA (ifa), len);
  char ifname[IFNAMSIZ] = "?";
  if (!if_indextoname (ifa->ifa_index, ifname))
    snprintf (ifname, sizeof ifname, "if%u", ifa->ifa_index);
  if (ctx && ctx->want_ifname && strcmp (ifname, ctx->want_ifname) != 0)
    return 0;
  void *raw = NULL;
  if (tb[IFA_LOCAL])
    raw = RTA_DATA (tb[IFA_LOCAL]);
  else if (tb[IFA_ADDRESS])
    raw = RTA_DATA (tb[IFA_ADDRESS]);
  if (!raw)
    return 0;
  if (!bip_addr_matches_filter (ifa->ifa_family, raw, ifa->ifa_scope,
                                ctx ? ctx->addr_filter : NULL))
    return 0;
  char buf[INET6_ADDRSTRLEN];
  if (!inet_ntop (ifa->ifa_family, raw, buf, sizeof buf))
    return 0;
  if (ctx && ctx->brief)
    {
      printf ("%-16s %-8s %s/%u\n",
              ifname, bip_family_name (ifa->ifa_family), buf, ifa->ifa_prefixlen);
      return 0;
    }
  printf ("%u: %s    %s %s/%u scope %u\n",
          ifa->ifa_index, ifname, bip_family_name (ifa->ifa_family),
          buf, ifa->ifa_prefixlen, ifa->ifa_scope);
  return 0;
}

static int
bip_addr_show (const char *ifname, int family, int brief, int json,
               const struct bip_addr_filter *filter)
{
  if (brief || json)
    {
      struct bip_iface_collect_ctx cctx;
      memset (&cctx, 0, sizeof cctx);
      cctx.want_ifname = ifname;
      cctx.family = family;
      cctx.addr_filter = filter;
      if (bip_collect_ifaces (&cctx) != 0)
        {
          bip_iface_free_all (&cctx);
          return EXECUTION_FAILURE;
        }
      if (json)
        bip_emit_json_addr (&cctx);
      else
        bip_emit_brief_addr (&cctx);
      bip_iface_free_all (&cctx);
      return EXECUTION_SUCCESS;
    }

  int fd = bip_open ();
  if (fd < 0) return EXECUTION_FAILURE;
  struct
  {
    struct nlmsghdr n;
    struct ifaddrmsg a;
    char attrs[64];
  } req;
  memset (&req, 0, sizeof req);
  req.n.nlmsg_len = NLMSG_LENGTH (sizeof req.a);
  req.n.nlmsg_type = RTM_GETADDR;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.n.nlmsg_seq = bip_seq ();
  req.a.ifa_family = (unsigned char) family;
  struct bip_show_ctx ctx = { ifname, family, brief, 0, json, 1, filter };
  int rc = bip_talk (fd, &req.n, bip_addr_show_cb, &ctx);
  close (fd);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* ----------------------------------------------------------------- */
/* addr add / del / change / replace / flush                           */
/* ----------------------------------------------------------------- */

static int
bip_addr_send (int rtm, unsigned nlflags, int fam, unsigned char *raw,
               int alen, int prefix, unsigned ifindex, unsigned scope)
{
  int fd = bip_open ();
  if (fd < 0) return EXECUTION_FAILURE;
  struct
  {
    struct nlmsghdr n;
    struct ifaddrmsg a;
    char attrs[128];
  } req;
  memset (&req, 0, sizeof req);
  req.n.nlmsg_len = NLMSG_LENGTH (sizeof req.a);
  req.n.nlmsg_type = (unsigned short) rtm;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | nlflags;
  req.n.nlmsg_seq = bip_seq ();
  req.a.ifa_family = (unsigned char) fam;
  req.a.ifa_prefixlen = (unsigned char) prefix;
  req.a.ifa_index = ifindex;
  req.a.ifa_scope = (unsigned char) scope;
  bip_addattr (&req.n, sizeof req, IFA_LOCAL, raw, alen);
  bip_addattr (&req.n, sizeof req, IFA_ADDRESS, raw, alen);
  int rc = bip_talk (fd, &req.n, NULL, NULL);
  close (fd);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bip_addr_modify (int rtm, unsigned nlflags, const char *cidr, const char *ifname)
{
  int idx = bip_iface_index (ifname);
  if (idx < 0) return EXECUTION_FAILURE;
  int fam, prefix, alen;
  unsigned char raw[16];
  if (bip_parse_cidr (cidr, &fam, raw, sizeof raw, &prefix, &alen) < 0)
    {
      builtin_error ("bad CIDR: %s", cidr);
      return EX_USAGE;
    }
  unsigned scope = (fam == AF_INET && raw[0] == 127) ? RT_SCOPE_HOST : RT_SCOPE_UNIVERSE;
  return bip_addr_send (rtm, nlflags, fam, raw, alen, prefix, (unsigned) idx, scope);
}

struct bip_addr_flush_item
{
  int family;
  unsigned ifindex;
  unsigned scope;
  int prefixlen;
  int alen;
  unsigned char raw[16];
  struct bip_addr_flush_item *next;
};

struct bip_addr_flush_ctx
{
  unsigned ifindex;
  const struct bip_addr_filter *filter;
  struct bip_addr_flush_item *items;
  struct bip_addr_flush_item *tail;
  unsigned matches;
};

static void
bip_addr_flush_free (struct bip_addr_flush_ctx *ctx)
{
  struct bip_addr_flush_item *it = ctx->items;
  while (it)
    {
      struct bip_addr_flush_item *next = it->next;
      free (it);
      it = next;
    }
  ctx->items = ctx->tail = NULL;
}

static int
bip_addr_flush_collect_cb (struct nlmsghdr *h, void *vctx)
{
  struct bip_addr_flush_ctx *ctx = vctx;
  if (h->nlmsg_type != RTM_NEWADDR)
    return 0;
  struct ifaddrmsg *ifa = NLMSG_DATA (h);
  int len = h->nlmsg_len - NLMSG_LENGTH (sizeof *ifa);
  if (len < 0 || ifa->ifa_index != ctx->ifindex)
    return 0;
  struct rtattr *tb[IFA_MAX + 1];
  bip_parse_rta (tb, IFA_MAX, IFA_RTA (ifa), len);
  void *raw = tb[IFA_LOCAL] ? RTA_DATA (tb[IFA_LOCAL]) :
              (tb[IFA_ADDRESS] ? RTA_DATA (tb[IFA_ADDRESS]) : NULL);
  if (!raw)
    return 0;
  int alen = ifa->ifa_family == AF_INET ? 4 :
             (ifa->ifa_family == AF_INET6 ? 16 : 0);
  if (alen == 0)
    return 0;
  if (!bip_addr_matches_filter (ifa->ifa_family, raw, ifa->ifa_scope, ctx->filter))
    return 0;
  struct bip_addr_flush_item *it = calloc (1, sizeof *it);
  if (!it)
    return 1;
  it->family = ifa->ifa_family;
  it->ifindex = ifa->ifa_index;
  it->scope = ifa->ifa_scope;
  it->prefixlen = ifa->ifa_prefixlen;
  it->alen = alen;
  memcpy (it->raw, raw, (size_t) alen);
  if (ctx->tail)
    ctx->tail->next = it;
  else
    ctx->items = it;
  ctx->tail = it;
  ctx->matches++;
  return 0;
}

static int
bip_addr_flush (const char *ifname, const struct bip_addr_filter *filter)
{
  int idx = bip_iface_index (ifname);
  if (idx < 0) return EXECUTION_FAILURE;
  int fd = bip_open ();
  if (fd < 0) return EXECUTION_FAILURE;
  struct
  {
    struct nlmsghdr n;
    struct ifaddrmsg a;
    char attrs[64];
  } req;
  memset (&req, 0, sizeof req);
  req.n.nlmsg_len = NLMSG_LENGTH (sizeof req.a);
  req.n.nlmsg_type = RTM_GETADDR;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.n.nlmsg_seq = bip_seq ();
  req.a.ifa_family = AF_UNSPEC;
  struct bip_addr_flush_ctx ctx;
  memset (&ctx, 0, sizeof ctx);
  ctx.ifindex = (unsigned) idx;
  ctx.filter = filter;
  int rc = bip_talk (fd, &req.n, bip_addr_flush_collect_cb, &ctx);
  close (fd);
  if (rc != 0)
    {
      bip_addr_flush_free (&ctx);
      return EXECUTION_FAILURE;
    }
  int out = EXECUTION_SUCCESS;
  for (struct bip_addr_flush_item *it = ctx.items; it; it = it->next)
    {
      int drc = bip_addr_send (RTM_DELADDR, 0, it->family, it->raw, it->alen,
                               it->prefixlen, it->ifindex, it->scope);
      if (drc != EXECUTION_SUCCESS)
        out = drc;
    }
  bip_addr_flush_free (&ctx);
  return out;
}

/* ----------------------------------------------------------------- */
/* route show / flush / add / del                                       */
/* ----------------------------------------------------------------- */

static int
bip_route_show_cb (struct nlmsghdr *h, void *vctx)
{
  struct bip_route_show_ctx *ctx = vctx;
  if (h->nlmsg_type != RTM_NEWROUTE)
    return 0;
  struct rtmsg *r = NLMSG_DATA (h);
  int len = h->nlmsg_len - NLMSG_LENGTH (sizeof *r);
  if (len < 0)
    return 0;
  if (r->rtm_family != AF_INET && r->rtm_family != AF_INET6)
    return 0;
  if (ctx && ctx->family != AF_UNSPEC && r->rtm_family != ctx->family)
    return 0;
  if (r->rtm_table != RT_TABLE_MAIN && r->rtm_table != 0)
    {
      /* Some kernels stash the real table in RTA_TABLE; check that
         attribute below before applying the table selector. */
    }
  struct rtattr *tb[RTA_MAX + 1];
  bip_parse_rta (tb, RTA_MAX, RTM_RTA (r), len);
  unsigned table = r->rtm_table;
  if (tb[RTA_TABLE])
    table = *(unsigned *) RTA_DATA (tb[RTA_TABLE]);
  if (ctx && !ctx->all_tables && table != ctx->table)
    return 0;
  if (ctx && ctx->only_default && tb[RTA_DST])
    return 0;
  if (ctx && ctx->ifindex)
    {
      if (!tb[RTA_OIF])
        return 0;
      if (*(unsigned *) RTA_DATA (tb[RTA_OIF]) != ctx->ifindex)
        return 0;
    }
  /* iproute2 has no brief route layout; -br route is intentionally inert. */
  char dst[INET6_ADDRSTRLEN] = "default";
  if (tb[RTA_DST])
    {
      inet_ntop (r->rtm_family, RTA_DATA (tb[RTA_DST]), dst, sizeof dst);
    }
  if (ctx && ctx->json)
    {
      char table_buf[32];
      char scope_buf[32];
      char proto_buf[32];
      printf ("%s{\"dst\":", ctx->first ? "" : ",");
      ctx->first = 0;
      if (tb[RTA_DST])
        {
          char cidr[INET6_ADDRSTRLEN + 8];
          snprintf (cidr, sizeof cidr, "%s/%u", dst, r->rtm_dst_len);
          bip_json_string (cidr);
        }
      else
        bip_json_string ("default");
      if (tb[RTA_OIF])
        {
          unsigned oif = *(unsigned *) RTA_DATA (tb[RTA_OIF]);
          char ifname[IFNAMSIZ];
          if (if_indextoname (oif, ifname))
            {
              printf (",\"dev\":");
              bip_json_string (ifname);
            }
        }
      if (tb[RTA_GATEWAY])
        {
          char gw[INET6_ADDRSTRLEN];
          inet_ntop (r->rtm_family, RTA_DATA (tb[RTA_GATEWAY]), gw, sizeof gw);
          printf (",\"gateway\":");
          bip_json_string (gw);
        }
      if (tb[RTA_PREFSRC])
        {
          char src[INET6_ADDRSTRLEN];
          inet_ntop (r->rtm_family, RTA_DATA (tb[RTA_PREFSRC]), src, sizeof src);
          printf (",\"prefsrc\":");
          bip_json_string (src);
        }
      printf (",\"table\":");
      bip_json_string (bip_table_name (table, table_buf, sizeof table_buf));
      printf (",\"scope\":");
      bip_json_string (bip_addr_scope_name (r->rtm_scope, scope_buf, sizeof scope_buf));
      snprintf (proto_buf, sizeof proto_buf, "%u", r->rtm_protocol);
      printf (",\"protocol\":");
      bip_json_string (proto_buf);
      if (tb[RTA_PRIORITY])
        printf (",\"metric\":%u", *(unsigned *) RTA_DATA (tb[RTA_PRIORITY]));
      printf ("}");
      return 0;
    }
  printf ("%s", dst);
  if (tb[RTA_DST])
    printf ("/%u", r->rtm_dst_len);
  if (tb[RTA_GATEWAY])
    {
      char gw[INET6_ADDRSTRLEN];
      inet_ntop (r->rtm_family, RTA_DATA (tb[RTA_GATEWAY]), gw, sizeof gw);
      printf (" via %s", gw);
    }
  if (tb[RTA_OIF])
    {
      unsigned oif = *(unsigned *) RTA_DATA (tb[RTA_OIF]);
      char ifname[IFNAMSIZ];
      if (if_indextoname (oif, ifname))
        printf (" dev %s", ifname);
    }
  if (tb[RTA_PREFSRC])
    {
      char src[INET6_ADDRSTRLEN];
      inet_ntop (r->rtm_family, RTA_DATA (tb[RTA_PREFSRC]), src, sizeof src);
      printf (" src %s", src);
    }
  if (tb[RTA_PRIORITY])
    printf (" metric %u", *(unsigned *) RTA_DATA (tb[RTA_PRIORITY]));
  printf ("\n");
  return 0;
}

static int
bip_route_show (int family, const char *ifname, int only_default,
                int all_tables, unsigned table, int brief, int json)
{
  unsigned ifindex = 0;
  if (ifname)
    {
      ifindex = if_nametoindex (ifname);
      if (ifindex == 0)
        return EXECUTION_SUCCESS;
    }
  int fd = bip_open ();
  if (fd < 0) return EXECUTION_FAILURE;
  struct
  {
    struct nlmsghdr n;
    struct rtmsg r;
    char attrs[64];
  } req;
  memset (&req, 0, sizeof req);
  req.n.nlmsg_len = NLMSG_LENGTH (sizeof req.r);
  req.n.nlmsg_type = RTM_GETROUTE;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.n.nlmsg_seq = bip_seq ();
  req.r.rtm_family = (unsigned char) family;
  struct bip_route_show_ctx ctx = { family, ifindex, only_default, all_tables, table, brief, json, 1 };
  if (json)
    printf ("[");
  int rc = bip_talk (fd, &req.n, bip_route_show_cb, &ctx);
  if (json)
    printf ("]\n");
  close (fd);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

struct bip_route_flush_ctx
{
  unsigned ifindex;
  unsigned matches;
};

static int
bip_route_flush_count_cb (struct nlmsghdr *h, void *vctx)
{
  struct bip_route_flush_ctx *ctx = vctx;
  if (h->nlmsg_type != RTM_NEWROUTE)
    return 0;
  struct rtmsg *r = NLMSG_DATA (h);
  int len = h->nlmsg_len - NLMSG_LENGTH (sizeof *r);
  if (len < 0)
    return 0;
  if (r->rtm_family != AF_INET && r->rtm_family != AF_INET6)
    return 0;
  struct rtattr *tb[RTA_MAX + 1];
  bip_parse_rta (tb, RTA_MAX, RTM_RTA (r), len);
  unsigned table = r->rtm_table;
  if (tb[RTA_TABLE])
    table = *(unsigned *) RTA_DATA (tb[RTA_TABLE]);
  if (table != RT_TABLE_MAIN)
    return 0;
  if (ctx->ifindex)
    {
      if (!tb[RTA_OIF])
        return 0;
      if (*(unsigned *) RTA_DATA (tb[RTA_OIF]) != ctx->ifindex)
        return 0;
    }
  ctx->matches++;
  return 0;
}

static int
bip_route_flush_dev (const char *ifname)
{
  unsigned idx = if_nametoindex (ifname);
  if (idx == 0)
    return EXECUTION_SUCCESS;

  int fd = bip_open ();
  if (fd < 0) return EXECUTION_FAILURE;
  struct
  {
    struct nlmsghdr n;
    struct rtmsg r;
    char attrs[64];
  } req;
  memset (&req, 0, sizeof req);
  req.n.nlmsg_len = NLMSG_LENGTH (sizeof req.r);
  req.n.nlmsg_type = RTM_GETROUTE;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.n.nlmsg_seq = bip_seq ();
  req.r.rtm_family = AF_UNSPEC;
  bip_addattr_u32 (&req.n, sizeof req, RTA_OIF, idx);
  struct bip_route_flush_ctx ctx = { idx, 0 };
  int rc = bip_talk (fd, &req.n, bip_route_flush_count_cb, &ctx);
  close (fd);
  if (rc != 0)
    return EXECUTION_FAILURE;
  if (ctx.matches == 0)
    return EXECUTION_SUCCESS;

  builtin_error ("route flush dev %s: matched %u route%s; destructive flush is not implemented",
                 ifname, ctx.matches, ctx.matches == 1 ? "" : "s");
  return EXECUTION_FAILURE;
}

static int
bip_route_modify (int rtm, unsigned nlflags, const char *cidr, const char *via,
                  const char *ifname, unsigned table, int have_metric,
                  unsigned metric)
{
  int fam = AF_INET, prefix = 0, alen = 4;
  unsigned char dst[16] = { 0 };
  int is_default = (cidr && strcmp (cidr, "default") == 0);
  if (!is_default && cidr)
    {
      if (bip_parse_cidr (cidr, &fam, dst, sizeof dst, &prefix, &alen) < 0)
        {
          builtin_error ("bad CIDR: %s", cidr);
          return EX_USAGE;
        }
    }
  unsigned char gw[16] = { 0 };
  int have_gw = 0;
  if (via)
    {
      struct in_addr g4;
      struct in6_addr g6;
      if (inet_pton (AF_INET, via, &g4) == 1)
        {
          if (is_default) fam = AF_INET, alen = 4;
          if (fam != AF_INET)
            { builtin_error ("via address family mismatch: %s", via); return EX_USAGE; }
          memcpy (gw, &g4, 4);
          have_gw = 1;
        }
      else if (inet_pton (AF_INET6, via, &g6) == 1)
        {
          if (is_default) fam = AF_INET6, alen = 16;
          if (fam != AF_INET6)
            { builtin_error ("via address family mismatch: %s", via); return EX_USAGE; }
          memcpy (gw, &g6, 16);
          have_gw = 1;
        }
      else
        {
          builtin_error ("bad gateway: %s", via);
          return EX_USAGE;
        }
    }
  int idx = -1;
  if (ifname)
    {
      idx = bip_iface_index (ifname);
      if (idx < 0) return EXECUTION_FAILURE;
    }
  int fd = bip_open ();
  if (fd < 0) return EXECUTION_FAILURE;
  struct
  {
    struct nlmsghdr n;
    struct rtmsg r;
    char attrs[256];
  } req;
  memset (&req, 0, sizeof req);
  req.n.nlmsg_len = NLMSG_LENGTH (sizeof req.r);
  req.n.nlmsg_type = (unsigned short) rtm;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | nlflags;
  req.n.nlmsg_seq = bip_seq ();
  req.r.rtm_family = (unsigned char) fam;
  req.r.rtm_table = table < 256 ? (unsigned char) table : RT_TABLE_UNSPEC;
  req.r.rtm_protocol = (rtm == RTM_NEWROUTE) ? RTPROT_BOOT : RTPROT_UNSPEC;
  req.r.rtm_scope = have_gw ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;
  req.r.rtm_type = RTN_UNICAST;
  req.r.rtm_dst_len = (unsigned char) prefix;
  if (table >= 256)
    bip_addattr_u32 (&req.n, sizeof req, RTA_TABLE, table);
  if (!is_default)
    bip_addattr (&req.n, sizeof req, RTA_DST, dst, alen);
  if (have_gw)
    bip_addattr (&req.n, sizeof req, RTA_GATEWAY, gw, alen);
  if (idx > 0)
    bip_addattr_u32 (&req.n, sizeof req, RTA_OIF, (unsigned) idx);
  if (have_metric)
    bip_addattr_u32 (&req.n, sizeof req, RTA_PRIORITY, metric);
  int rc = bip_talk (fd, &req.n, NULL, NULL);
  close (fd);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* ----------------------------------------------------------------- */
/* rule show / add / del                                               */
/* ----------------------------------------------------------------- */

struct bip_rule_show_ctx
{
  int json;
  int first;
  int family;
  int have_prio;
  unsigned prio;
  int have_table;
  unsigned table;
};

static int
bip_rule_show_cb (struct nlmsghdr *h, void *vctx)
{
  struct bip_rule_show_ctx *ctx = vctx;
  if (h->nlmsg_type != RTM_NEWRULE)
    return 0;
  struct fib_rule_hdr *frh = NLMSG_DATA (h);
  int len = h->nlmsg_len - NLMSG_LENGTH (sizeof *frh);
  if (len < 0)
    return 0;
  if (frh->family != AF_INET && frh->family != AF_INET6 && frh->family != AF_UNSPEC)
    return 0;
  if (ctx && ctx->family != AF_UNSPEC && frh->family != ctx->family)
    return 0;

  struct rtattr *tb[FRA_MAX + 1];
  bip_parse_rta (tb, FRA_MAX,
                 (struct rtattr *) ((char *) frh + NLMSG_ALIGN (sizeof *frh)),
                 len);

  unsigned prio = tb[FRA_PRIORITY] ? *(unsigned *) RTA_DATA (tb[FRA_PRIORITY]) : 0;
  unsigned table = frh->table;
  if (tb[FRA_TABLE])
    table = *(unsigned *) RTA_DATA (tb[FRA_TABLE]);
  if (ctx && ctx->have_prio && prio != ctx->prio)
    return 0;
  if (ctx && ctx->have_table && table != ctx->table)
    return 0;

  char table_buf[32];
  char proto_buf[32];

  if (ctx && ctx->json)
    {
      const char *family = frh->family == AF_INET ? "inet" :
                           (frh->family == AF_INET6 ? "inet6" : "unspec");
      if (!ctx->first)
        printf (",\n");
      ctx->first = 0;
      printf ("{\"priority\":%u,\"family\":\"%s\"", prio, family);
      if (tb[FRA_SRC])
        {
          char src[INET6_ADDRSTRLEN];
          inet_ntop (frh->family, RTA_DATA (tb[FRA_SRC]), src, sizeof src);
          printf (",\"from\":\"%s\",\"from_prefix\":%u", src, frh->src_len);
        }
      else
        printf (",\"from\":\"all\"");
      if (tb[FRA_DST])
        {
          char dst[INET6_ADDRSTRLEN];
          inet_ntop (frh->family, RTA_DATA (tb[FRA_DST]), dst, sizeof dst);
          printf (",\"to\":\"%s\",\"to_prefix\":%u", dst, frh->dst_len);
        }
      if (tb[FRA_FWMARK])
        printf (",\"fwmark\":%u", *(unsigned *) RTA_DATA (tb[FRA_FWMARK]));
      if (tb[FRA_FWMASK])
        printf (",\"fwmask\":%u", *(unsigned *) RTA_DATA (tb[FRA_FWMASK]));
      if (tb[FRA_UID_RANGE])
        {
          struct fib_rule_uid_range *range = RTA_DATA (tb[FRA_UID_RANGE]);
          printf (",\"uidrange_start\":%u,\"uidrange_end\":%u",
                  range->start, range->end);
        }
      if (tb[FRA_IP_PROTO])
        {
          unsigned proto = *(unsigned char *) RTA_DATA (tb[FRA_IP_PROTO]);
          printf (",\"ipproto\":\"%s\",\"ipproto_number\":%u",
                  bip_ipproto_name (proto, proto_buf, sizeof proto_buf), proto);
        }
      if (frh->action == FR_ACT_TO_TBL || table)
        printf (",\"table\":\"%s\"", bip_table_name (table, table_buf, sizeof table_buf));
      else
        printf (",\"action\":%u", frh->action);
      printf ("}");
      return 0;
    }

  printf ("%u:", prio);

  if (tb[FRA_SRC])
    {
      char src[INET6_ADDRSTRLEN];
      inet_ntop (frh->family, RTA_DATA (tb[FRA_SRC]), src, sizeof src);
      printf (" from %s/%u", src, frh->src_len);
    }
  else
    printf (" from all");

  if (tb[FRA_DST])
    {
      char dst[INET6_ADDRSTRLEN];
      inet_ntop (frh->family, RTA_DATA (tb[FRA_DST]), dst, sizeof dst);
      printf (" to %s/%u", dst, frh->dst_len);
    }

  if (tb[FRA_FWMARK])
    {
      unsigned mark = *(unsigned *) RTA_DATA (tb[FRA_FWMARK]);
      if (tb[FRA_FWMASK])
        {
          unsigned mask = *(unsigned *) RTA_DATA (tb[FRA_FWMASK]);
          printf (" fwmark 0x%x/0x%x", mark, mask);
        }
      else
        printf (" fwmark 0x%x", mark);
    }

  if (tb[FRA_UID_RANGE])
    {
      struct fib_rule_uid_range *range = RTA_DATA (tb[FRA_UID_RANGE]);
      printf (" uidrange %u-%u", range->start, range->end);
    }

  if (tb[FRA_IP_PROTO])
    {
      unsigned proto = *(unsigned char *) RTA_DATA (tb[FRA_IP_PROTO]);
      printf (" ipproto %s", bip_ipproto_name (proto, proto_buf, sizeof proto_buf));
    }

  if (frh->action == FR_ACT_TO_TBL || table)
    printf (" lookup %s", bip_table_name (table, table_buf, sizeof table_buf));
  else
    printf (" action %u", frh->action);
  printf ("\n");
  return 0;
}

static int
bip_rule_show (int json, int family, int have_prio, unsigned prio,
               int have_table, unsigned table)
{
  int fd = bip_open ();
  if (fd < 0) return EXECUTION_FAILURE;
  struct
  {
    struct nlmsghdr n;
    struct fib_rule_hdr r;
    char attrs[64];
  } req;
  memset (&req, 0, sizeof req);
  req.n.nlmsg_len = NLMSG_LENGTH (sizeof req.r);
  req.n.nlmsg_type = RTM_GETRULE;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.n.nlmsg_seq = bip_seq ();
  req.r.family = (unsigned char) family;
  struct bip_rule_show_ctx ctx = { json, 1, family, have_prio, prio, have_table, table };
  if (json)
    printf ("[\n");
  int rc = bip_talk (fd, &req.n, bip_rule_show_cb, &ctx);
  if (json)
    printf ("\n]\n");
  close (fd);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bip_rule_modify (int rtm, const char *src_cidr, const char *dst_cidr,
                 const char *fwmark_s, const char *uidrange_s,
                 const char *ipproto_s, const char *table_s,
                 const char *prio_s)
{
  if (!prio_s)
    {
      builtin_error ("rule %s: priority N required",
                     rtm == RTM_NEWRULE ? "add" : "del");
      return EX_USAGE;
    }
  unsigned prio = 0, table = RT_TABLE_MAIN;
  if (bip_parse_u32 (prio_s, &prio) < 0)
    {
      builtin_error ("rule: bad priority: %s", prio_s);
      return EX_USAGE;
    }
  if (table_s && bip_parse_table (table_s, &table) < 0)
    {
      builtin_error ("rule: bad table: %s", table_s);
      return EX_USAGE;
    }
  unsigned fwmark = 0, fwmask = 0xffffffffU;
  int have_fwmark = 0, have_fwmask = 0;
  if (fwmark_s)
    {
      char markbuf[64];
      snprintf (markbuf, sizeof markbuf, "%s", fwmark_s);
      char *slash = strchr (markbuf, '/');
      if (slash)
        {
          *slash = '\0';
          if (bip_parse_u32_base0 (slash + 1, &fwmask) < 0)
            {
              builtin_error ("rule: bad fwmark mask: %s", slash + 1);
              return EX_USAGE;
            }
          have_fwmask = 1;
        }
      if (bip_parse_u32_base0 (markbuf, &fwmark) < 0)
        {
          builtin_error ("rule: bad fwmark: %s", fwmark_s);
          return EX_USAGE;
        }
      have_fwmark = 1;
    }
  struct fib_rule_uid_range uidrange;
  int have_uidrange = 0;
  if (uidrange_s)
    {
      if (bip_parse_uidrange (uidrange_s, &uidrange) < 0)
        {
          builtin_error ("rule: bad uidrange: %s", uidrange_s);
          return EX_USAGE;
        }
      have_uidrange = 1;
    }
  unsigned ipproto = 0;
  int have_ipproto = 0;
  if (ipproto_s)
    {
      if (bip_parse_ipproto (ipproto_s, &ipproto) < 0)
        {
          builtin_error ("rule: bad ipproto: %s", ipproto_s);
          return EX_USAGE;
        }
      have_ipproto = 1;
    }

  int fam = AF_INET;
  unsigned char src[16] = { 0 }, dst[16] = { 0 };
  int src_prefix = 0, src_alen = 0, dst_prefix = 0, dst_alen = 0;
  if (src_cidr)
    {
      if (bip_parse_cidr (src_cidr, &fam, src, sizeof src, &src_prefix, &src_alen) < 0)
        {
          builtin_error ("rule: bad from CIDR: %s", src_cidr);
          return EX_USAGE;
        }
    }
  if (dst_cidr)
    {
      int dfam = AF_INET;
      if (bip_parse_cidr (dst_cidr, &dfam, dst, sizeof dst, &dst_prefix, &dst_alen) < 0)
        {
          builtin_error ("rule: bad to CIDR: %s", dst_cidr);
          return EX_USAGE;
        }
      if (src_cidr && dfam != fam)
        {
          builtin_error ("rule: from/to address family mismatch");
          return EX_USAGE;
        }
      fam = dfam;
    }

  int fd = bip_open ();
  if (fd < 0) return EXECUTION_FAILURE;
  struct
  {
    struct nlmsghdr n;
    struct fib_rule_hdr r;
    char attrs[256];
  } req;
  memset (&req, 0, sizeof req);
  req.n.nlmsg_len = NLMSG_LENGTH (sizeof req.r);
  req.n.nlmsg_type = (unsigned short) rtm;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  if (rtm == RTM_NEWRULE)
    req.n.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
  req.n.nlmsg_seq = bip_seq ();
  req.r.family = (unsigned char) fam;
  req.r.action = FR_ACT_TO_TBL;
  req.r.table = table < 256 ? (unsigned char) table : RT_TABLE_UNSPEC;
  req.r.src_len = (unsigned char) src_prefix;
  req.r.dst_len = (unsigned char) dst_prefix;

  bip_addattr_u32 (&req.n, sizeof req, FRA_PRIORITY, prio);
  if (table >= 256)
    bip_addattr_u32 (&req.n, sizeof req, FRA_TABLE, table);
  if (src_cidr)
    bip_addattr (&req.n, sizeof req, FRA_SRC, src, src_alen);
  if (dst_cidr)
    bip_addattr (&req.n, sizeof req, FRA_DST, dst, dst_alen);
  if (have_fwmark)
    bip_addattr_u32 (&req.n, sizeof req, FRA_FWMARK, fwmark);
  if (have_fwmask)
    bip_addattr_u32 (&req.n, sizeof req, FRA_FWMASK, fwmask);
  if (have_uidrange)
    bip_addattr (&req.n, sizeof req, FRA_UID_RANGE, &uidrange, sizeof uidrange);
  if (have_ipproto)
    bip_addattr_u8 (&req.n, sizeof req, FRA_IP_PROTO, (unsigned char) ipproto);

  int rc = bip_talk (fd, &req.n, NULL, NULL);
  close (fd);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

struct bip_rule_flush_item
{
  int family;
  unsigned action;
  unsigned table;
  unsigned prio;
  int have_src, have_dst, have_fwmark, have_fwmask, have_uidrange, have_ipproto;
  unsigned src_len, dst_len;
  unsigned char src[16], dst[16];
  unsigned fwmark, fwmask;
  struct fib_rule_uid_range uidrange;
  unsigned char ipproto;
  struct bip_rule_flush_item *next;
};

struct bip_rule_flush_ctx
{
  struct bip_rule_flush_item *items;
  struct bip_rule_flush_item *tail;
  unsigned matches;
};

static void
bip_rule_flush_free (struct bip_rule_flush_ctx *ctx)
{
  struct bip_rule_flush_item *it = ctx->items;
  while (it)
    {
      struct bip_rule_flush_item *next = it->next;
      free (it);
      it = next;
    }
  ctx->items = ctx->tail = NULL;
}

static int
bip_rule_flush_collect_cb (struct nlmsghdr *h, void *vctx)
{
  struct bip_rule_flush_ctx *ctx = vctx;
  if (h->nlmsg_type != RTM_NEWRULE)
    return 0;
  struct fib_rule_hdr *frh = NLMSG_DATA (h);
  int len = h->nlmsg_len - NLMSG_LENGTH (sizeof *frh);
  if (len < 0)
    return 0;
  struct rtattr *tb[FRA_MAX + 1];
  bip_parse_rta (tb, FRA_MAX,
                 (struct rtattr *) ((char *) frh + NLMSG_ALIGN (sizeof *frh)),
                 len);
  unsigned prio = tb[FRA_PRIORITY] ? *(unsigned *) RTA_DATA (tb[FRA_PRIORITY]) : 0;
  if (prio == 0 || prio == 32766 || prio == 32767)
    return 0;
  struct bip_rule_flush_item *it = calloc (1, sizeof *it);
  if (!it)
    return 1;
  it->family = frh->family;
  it->action = frh->action;
  it->table = tb[FRA_TABLE] ? *(unsigned *) RTA_DATA (tb[FRA_TABLE]) : frh->table;
  it->prio = prio;
  it->src_len = frh->src_len;
  it->dst_len = frh->dst_len;
  int alen = frh->family == AF_INET ? 4 :
             (frh->family == AF_INET6 ? 16 : 0);
  if (alen && tb[FRA_SRC])
    {
      it->have_src = 1;
      memcpy (it->src, RTA_DATA (tb[FRA_SRC]), (size_t) alen);
    }
  if (alen && tb[FRA_DST])
    {
      it->have_dst = 1;
      memcpy (it->dst, RTA_DATA (tb[FRA_DST]), (size_t) alen);
    }
  if (tb[FRA_FWMARK])
    {
      it->have_fwmark = 1;
      it->fwmark = *(unsigned *) RTA_DATA (tb[FRA_FWMARK]);
    }
  if (tb[FRA_FWMASK])
    {
      it->have_fwmask = 1;
      it->fwmask = *(unsigned *) RTA_DATA (tb[FRA_FWMASK]);
    }
  if (tb[FRA_UID_RANGE])
    {
      it->have_uidrange = 1;
      memcpy (&it->uidrange, RTA_DATA (tb[FRA_UID_RANGE]), sizeof it->uidrange);
    }
  if (tb[FRA_IP_PROTO])
    {
      it->have_ipproto = 1;
      it->ipproto = *(unsigned char *) RTA_DATA (tb[FRA_IP_PROTO]);
    }
  if (ctx->tail)
    ctx->tail->next = it;
  else
    ctx->items = it;
  ctx->tail = it;
  ctx->matches++;
  return 0;
}

static int
bip_rule_delete_item (const struct bip_rule_flush_item *it)
{
  int fd = bip_open ();
  if (fd < 0) return EXECUTION_FAILURE;
  struct
  {
    struct nlmsghdr n;
    struct fib_rule_hdr r;
    char attrs[256];
  } req;
  memset (&req, 0, sizeof req);
  req.n.nlmsg_len = NLMSG_LENGTH (sizeof req.r);
  req.n.nlmsg_type = RTM_DELRULE;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.n.nlmsg_seq = bip_seq ();
  req.r.family = (unsigned char) it->family;
  req.r.action = (unsigned char) it->action;
  req.r.table = it->table < 256 ? (unsigned char) it->table : RT_TABLE_UNSPEC;
  req.r.src_len = (unsigned char) it->src_len;
  req.r.dst_len = (unsigned char) it->dst_len;
  bip_addattr_u32 (&req.n, sizeof req, FRA_PRIORITY, it->prio);
  if (it->table >= 256)
    bip_addattr_u32 (&req.n, sizeof req, FRA_TABLE, it->table);
  if (it->have_src)
    bip_addattr (&req.n, sizeof req, FRA_SRC, it->src, it->family == AF_INET ? 4 : 16);
  if (it->have_dst)
    bip_addattr (&req.n, sizeof req, FRA_DST, it->dst, it->family == AF_INET ? 4 : 16);
  if (it->have_fwmark)
    bip_addattr_u32 (&req.n, sizeof req, FRA_FWMARK, it->fwmark);
  if (it->have_fwmask)
    bip_addattr_u32 (&req.n, sizeof req, FRA_FWMASK, it->fwmask);
  if (it->have_uidrange)
    bip_addattr (&req.n, sizeof req, FRA_UID_RANGE, &it->uidrange, sizeof it->uidrange);
  if (it->have_ipproto)
    bip_addattr_u8 (&req.n, sizeof req, FRA_IP_PROTO, it->ipproto);
  int rc = bip_talk (fd, &req.n, NULL, NULL);
  close (fd);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bip_rule_flush (void)
{
  int fd = bip_open ();
  if (fd < 0) return EXECUTION_FAILURE;
  struct
  {
    struct nlmsghdr n;
    struct fib_rule_hdr r;
    char attrs[64];
  } req;
  memset (&req, 0, sizeof req);
  req.n.nlmsg_len = NLMSG_LENGTH (sizeof req.r);
  req.n.nlmsg_type = RTM_GETRULE;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.n.nlmsg_seq = bip_seq ();
  req.r.family = AF_UNSPEC;
  struct bip_rule_flush_ctx ctx;
  memset (&ctx, 0, sizeof ctx);
  int rc = bip_talk (fd, &req.n, bip_rule_flush_collect_cb, &ctx);
  close (fd);
  if (rc != 0)
    {
      bip_rule_flush_free (&ctx);
      return EXECUTION_FAILURE;
    }
  int out = EXECUTION_SUCCESS;
  for (struct bip_rule_flush_item *it = ctx.items; it; it = it->next)
    {
      int drc = bip_rule_delete_item (it);
      if (drc != EXECUTION_SUCCESS)
        out = drc;
    }
  bip_rule_flush_free (&ctx);
  return out;
}

/* ----------------------------------------------------------------- */
/* neigh show                                                           */
/* ----------------------------------------------------------------- */

static const char *
bip_nud_name (unsigned state)
{
  switch (state)
    {
    case NUD_INCOMPLETE: return "INCOMPLETE";
    case NUD_REACHABLE: return "REACHABLE";
    case NUD_STALE: return "STALE";
    case NUD_DELAY: return "DELAY";
    case NUD_PROBE: return "PROBE";
    case NUD_FAILED: return "FAILED";
    case NUD_NOARP: return "NOARP";
    case NUD_PERMANENT: return "PERMANENT";
    default: return "?";
    }
}

static int
bip_neigh_show_cb (struct nlmsghdr *h, void *vctx)
{
  struct bip_show_ctx *ctx = vctx;
  if (h->nlmsg_type != RTM_NEWNEIGH)
    return 0;
  struct ndmsg *nd = NLMSG_DATA (h);
  int len = h->nlmsg_len - NLMSG_LENGTH (sizeof *nd);
  if (len < 0)
    return 0;
  if (ctx && ctx->family != AF_UNSPEC && nd->ndm_family != ctx->family)
    return 0;
  struct rtattr *tb[NDA_MAX + 1];
  bip_parse_rta (tb, NDA_MAX, (struct rtattr *) ((char *) nd + NLMSG_ALIGN (sizeof *nd)), len);
  char ifname[IFNAMSIZ] = "?";
  if (!if_indextoname (nd->ndm_ifindex, ifname))
    snprintf (ifname, sizeof ifname, "if%u", nd->ndm_ifindex);
  if (ctx && ctx->want_ifname && strcmp (ifname, ctx->want_ifname) != 0)
    return 0;
  if (!tb[NDA_DST])
    return 0;
  char ip[INET6_ADDRSTRLEN] = "?";
  inet_ntop (nd->ndm_family, RTA_DATA (tb[NDA_DST]), ip, sizeof ip);
  if (ctx && ctx->json)
    {
      printf ("%s{\"dst\":", ctx->first ? "" : ",");
      ctx->first = 0;
      bip_json_string (ip);
      printf (",\"dev\":");
      bip_json_string (ifname);
      if (tb[NDA_LLADDR])
        {
          char lladdr[96];
          bip_lladdr_string (tb[NDA_LLADDR], lladdr, sizeof lladdr);
          if (lladdr[0])
            {
              printf (",\"lladdr\":");
              bip_json_string (lladdr);
            }
        }
      printf (",\"state\":[");
      bip_json_string (bip_nud_name (nd->ndm_state));
      printf ("]}");
      return 0;
    }
  printf ("%s dev %s", ip, ifname);
  if (tb[NDA_LLADDR])
    {
      unsigned char *m = RTA_DATA (tb[NDA_LLADDR]);
      int mlen = RTA_PAYLOAD (tb[NDA_LLADDR]);
      printf (" lladdr ");
      for (int i = 0; i < mlen; i++)
        printf ("%02x%s", m[i], i + 1 < mlen ? ":" : "");
    }
  printf (" %s\n", bip_nud_name (nd->ndm_state));
  return 0;
}

static int
bip_neigh_show (const char *ifname, int family, int json)
{
  int fd = bip_open ();
  if (fd < 0) return EXECUTION_FAILURE;
  struct
  {
    struct nlmsghdr n;
    struct ndmsg nd;
    char attrs[64];
  } req;
  memset (&req, 0, sizeof req);
  req.n.nlmsg_len = NLMSG_LENGTH (sizeof req.nd);
  req.n.nlmsg_type = RTM_GETNEIGH;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.n.nlmsg_seq = bip_seq ();
  req.nd.ndm_family = (unsigned char) family;
  struct bip_show_ctx ctx = { ifname, family, 0, 0, json, 1, NULL };
  if (json)
    printf ("[");
  int rc = bip_talk (fd, &req.n, bip_neigh_show_cb, &ctx);
  if (json)
    printf ("]\n");
  close (fd);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bip_neigh_modify (int rtm, unsigned nlflags, const char *ip,
                  const unsigned char *mac, int have_mac,
                  const char *ifname, unsigned nud, int have_nud,
                  int opts_family)
{
  int fam = AF_INET;
  unsigned char raw[16];
  struct in_addr a4;
  struct in6_addr a6;
  int alen = 0;
  if (inet_pton (AF_INET, ip, &a4) == 1)
    {
      fam = AF_INET;
      alen = 4;
      memcpy (raw, &a4, 4);
    }
  else if (inet_pton (AF_INET6, ip, &a6) == 1)
    {
      fam = AF_INET6;
      alen = 16;
      memcpy (raw, &a6, 16);
    }
  else
    {
      builtin_error ("neigh: bad IP address: %s", ip);
      return EX_USAGE;
    }
  if (opts_family != AF_UNSPEC && opts_family != fam)
    {
      builtin_error ("neigh: address family mismatch: %s", ip);
      return EX_USAGE;
    }
  int idx = bip_iface_index (ifname);
  if (idx < 0) return EXECUTION_FAILURE;

  int fd = bip_open ();
  if (fd < 0) return EXECUTION_FAILURE;
  struct
  {
    struct nlmsghdr n;
    struct ndmsg nd;
    char attrs[128];
  } req;
  memset (&req, 0, sizeof req);
  req.n.nlmsg_len = NLMSG_LENGTH (sizeof req.nd);
  req.n.nlmsg_type = (unsigned short) rtm;
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | nlflags;
  req.n.nlmsg_seq = bip_seq ();
  req.nd.ndm_family = (unsigned char) fam;
  req.nd.ndm_ifindex = idx;
  req.nd.ndm_state = (unsigned short) (have_nud ? nud :
                       (rtm == RTM_NEWNEIGH ? NUD_PERMANENT : NUD_NONE));
  bip_addattr (&req.n, sizeof req, NDA_DST, raw, alen);
  if (have_mac)
    bip_addattr (&req.n, sizeof req, NDA_LLADDR, mac, 6);
  int rc = bip_talk (fd, &req.n, NULL, NULL);
  close (fd);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* ----------------------------------------------------------------- */
/* arg parsing + dispatch                                               */
/* ----------------------------------------------------------------- */

static void bip_print_help (void);

static int
bip_link_cmd (WORD_LIST *args, const struct bip_ip_opts *opts)
{
  if (!args)
    return bip_link_show (NULL, opts ? opts->brief : 0,
                          opts ? opts->oneline : 0, opts ? opts->json : 0);
  static const char *const verbs[] = {
    "show", "list", "set", "add", "delete", "help", NULL
  };
  static const struct bip_alias aliases[] = {
    { "ls", "list" },
    { "del", "delete" },
    { NULL, NULL }
  };
  const char *verb_arg = args->word->word;
  const char *verb = bip_match_keyword (verb_arg, verbs, aliases, "link verb");
  if (!verb)
    return EX_USAGE;
  WORD_LIST *rest = args->next;
  if (strcmp (verb, "help") == 0)
    { bip_print_help (); return EXECUTION_SUCCESS; }
  if (strcmp (verb, "show") == 0 || strcmp (verb, "list") == 0)
    {
      static const char *const show_selectors[] = { "dev", NULL };
      const char *iface = rest ? rest->word->word : NULL;
      if (iface)
        {
          const char *sel = bip_match_one_quiet (iface, show_selectors, "link show selector");
          if (sel && strcmp (sel, "dev") == 0)
            {
              if (!rest->next)
                { builtin_error ("link show: dev requires an argument"); return EX_USAGE; }
              iface = rest->next->word->word;
              if (rest->next->next)
                { builtin_error ("link show: unsupported selector %s", rest->next->next->word->word); return EX_USAGE; }
            }
          else if (rest->next)
            { builtin_error ("link show: unsupported selector %s", rest->next->word->word); return EX_USAGE; }
        }
      return bip_link_show (iface, opts ? opts->brief : 0,
                            opts ? opts->oneline : 0, opts ? opts->json : 0);
    }
  if (opts && opts->json)
    {
      builtin_error ("-j is only supported for read-only link show");
      return EX_USAGE;
    }
  if (strcmp (verb, "set") == 0)
    {
      static const char *const set_opts[] = { "up", "down", "mtu", "address", NULL };
      if (!rest)
        { builtin_error ("link set: IFNAME required"); return EX_USAGE; }
      const char *ifname = rest->word->word;
      WORD_LIST *p = rest->next;
      int up = 0, down = 0, mtu = -1, have_lladdr = 0;
      unsigned char lladdr[6];
      while (p)
        {
          const char *w = p->word->word;
          const char *kw = bip_match_one (w, set_opts, "link set option");
          if (!kw)
            return EX_USAGE;
          if (strcmp (kw, "up") == 0) up = 1;
          else if (strcmp (kw, "down") == 0) down = 1;
          else if (strcmp (kw, "mtu") == 0)
            {
              if (!p->next)
                { builtin_error ("link set: mtu needs N"); return EX_USAGE; }
              p = p->next;
              mtu = atoi (p->word->word);
              if (mtu <= 0)
                { builtin_error ("link set: bad mtu %s", p->word->word); return EX_USAGE; }
            }
          else if (strcmp (kw, "address") == 0)
            {
              if (!p->next)
                { builtin_error ("link set: address needs a MAC"); return EX_USAGE; }
              p = p->next;
              if (bip_parse_lladdr (p->word->word, lladdr) < 0)
                { builtin_error ("link set: bad address %s", p->word->word); return EX_USAGE; }
              have_lladdr = 1;
            }
          p = p->next;
        }
      if (!up && !down && mtu < 0 && !have_lladdr)
        { builtin_error ("link set: need up|down|mtu N|address MAC"); return EX_USAGE; }
      return bip_link_set (ifname, up, down, mtu, have_lladdr ? lladdr : NULL);
    }
  if (strcmp (verb, "add") == 0)
    {
      static const char *const add_opts[] = { "type", "peer", NULL };
      if (!rest)
        { builtin_error ("link add: NAME required"); return EX_USAGE; }
      const char *ifname = rest->word->word;
      const char *kind = NULL, *peer = NULL;
      WORD_LIST *p = rest->next;
      while (p)
        {
          const char *w = p->word->word;
          const char *kw = bip_match_one (w, add_opts, "link add option");
          if (!kw)
            return EX_USAGE;
          if (!p->next)
            { builtin_error ("link add: %s needs an argument", w); return EX_USAGE; }
          p = p->next;
          if (strcmp (kw, "type") == 0)
            kind = p->word->word;
          else if (strcmp (kw, "peer") == 0)
            peer = p->word->word;
          p = p->next;
        }
      return bip_link_add (ifname, kind, peer);
    }
  if (strcmp (verb, "delete") == 0)
    {
      if (!rest)
        { builtin_error ("link %s: NAME required", verb_arg); return EX_USAGE; }
      if (rest->next)
        { builtin_error ("link %s: unknown option %s", verb_arg, rest->next->word->word); return EX_USAGE; }
      return bip_link_del (rest->word->word);
    }
  builtin_error ("link: unknown verb %s", verb_arg);
  return EX_USAGE;
}

static int
bip_addr_cmd (WORD_LIST *args, const struct bip_ip_opts *opts)
{
  if (!args)
    return bip_addr_show (NULL, opts ? opts->family : AF_UNSPEC,
                          opts ? opts->brief : 0,
                          opts ? opts->json : 0, NULL);
  static const char *const verbs[] = {
    "show", "list", "flush", "add", "delete", "change", "replace", "help", NULL
  };
  static const struct bip_alias aliases[] = {
    { "ls", "list" },
    { "del", "delete" },
    { NULL, NULL }
  };
  const char *verb_arg = args->word->word;
  const char *verb = bip_match_keyword (verb_arg, verbs, aliases, "addr verb");
  if (!verb)
    return EX_USAGE;
  WORD_LIST *rest = args->next;
  if (strcmp (verb, "help") == 0)
    { bip_print_help (); return EXECUTION_SUCCESS; }
  if (strcmp (verb, "show") == 0 || strcmp (verb, "list") == 0)
    {
      static const char *const show_selectors[] = { "dev", "to", "scope", NULL };
      const char *iface = NULL;
      struct bip_addr_filter filter;
      memset (&filter, 0, sizeof filter);
      WORD_LIST *p = rest;
      while (p)
        {
          const char *w = p->word->word;
          const char *kw = bip_match_one_quiet (w, show_selectors, "addr show selector");
          if (kw && strcmp (kw, "dev") == 0)
            {
              if (!p->next)
                { builtin_error ("addr show: %s requires an argument", w); return EX_USAGE; }
              p = p->next; iface = p->word->word;
            }
          else if (kw && strcmp (kw, "to") == 0)
            {
              if (!p->next)
                { builtin_error ("addr show: %s requires an argument", w); return EX_USAGE; }
              p = p->next;
              if (bip_parse_cidr (p->word->word, &filter.to_family,
                                  filter.to_raw, sizeof filter.to_raw,
                                  &filter.to_prefix, &filter.to_bytes) < 0)
                { builtin_error ("addr show: bad to prefix %s", p->word->word); return EX_USAGE; }
              filter.have_to = 1;
            }
          else if (kw && strcmp (kw, "scope") == 0)
            {
              if (!p->next)
                { builtin_error ("addr show: %s requires an argument", w); return EX_USAGE; }
              p = p->next;
              if (bip_parse_addr_scope (p->word->word, &filter.scope) < 0)
                { builtin_error ("addr show: bad scope %s", p->word->word); return EX_USAGE; }
              filter.have_scope = 1;
            }
          else if (!iface)
            iface = w;
          else
            { builtin_error ("addr show: unsupported selector %s", w); return EX_USAGE; }
          p = p->next;
        }
      return bip_addr_show (iface, opts ? opts->family : AF_UNSPEC,
                            opts ? opts->brief : 0,
                            opts ? opts->json : 0,
                            bip_addr_filter_active (&filter) ? &filter : NULL);
    }
  if (opts && opts->json)
    {
      builtin_error ("-j is only supported for read-only addr show");
      return EX_USAGE;
    }
  if (strcmp (verb, "flush") == 0)
    {
      static const char *const flush_selectors[] = { "dev", "to", "scope", NULL };
      const char *ifname = NULL;
      struct bip_addr_filter filter;
      memset (&filter, 0, sizeof filter);
      WORD_LIST *p = rest;
      if (!p)
        { builtin_error ("addr flush: dev IFNAME required"); return EX_USAGE; }
      while (p)
        {
          const char *w = p->word->word;
          const char *kw = bip_match_one (w, flush_selectors, "addr flush option");
          if (!kw)
            return EX_USAGE;
          if (!p->next)
            { builtin_error ("addr flush: %s requires an argument", w); return EX_USAGE; }
          if (strcmp (kw, "dev") == 0)
            { p = p->next; ifname = p->word->word; }
          else if (strcmp (kw, "to") == 0)
            {
              p = p->next;
              if (bip_parse_cidr (p->word->word, &filter.to_family,
                                  filter.to_raw, sizeof filter.to_raw,
                                  &filter.to_prefix, &filter.to_bytes) < 0)
                { builtin_error ("addr flush: bad to prefix %s", p->word->word); return EX_USAGE; }
              filter.have_to = 1;
            }
          else if (strcmp (kw, "scope") == 0)
            {
              p = p->next;
              if (bip_parse_addr_scope (p->word->word, &filter.scope) < 0)
                { builtin_error ("addr flush: bad scope %s", p->word->word); return EX_USAGE; }
              filter.have_scope = 1;
            }
          p = p->next;
        }
      if (!ifname)
        { builtin_error ("addr flush: dev IFNAME required"); return EX_USAGE; }
      return bip_addr_flush (ifname, bip_addr_filter_active (&filter) ? &filter : NULL);
    }
  if (strcmp (verb, "add") == 0 || strcmp (verb, "delete") == 0
      || strcmp (verb, "change") == 0
      || strcmp (verb, "replace") == 0)
    {
      static const char *const modify_opts[] = { "dev", NULL };
      if (!rest)
        { builtin_error ("addr %s: CIDR required", verb_arg); return EX_USAGE; }
      const char *cidr = rest->word->word;
      const char *ifname = NULL;
      WORD_LIST *p = rest->next;
      while (p)
        {
          const char *w = p->word->word;
          const char *kw = bip_match_one (w, modify_opts, "addr option");
          if (!kw)
            return EX_USAGE;
          if (!p->next)
            { builtin_error ("addr %s: %s requires an argument", verb_arg, w); return EX_USAGE; }
          p = p->next;
          ifname = p->word->word;
          p = p->next;
        }
      if (!ifname)
        { builtin_error ("addr %s: dev IFNAME required", verb_arg); return EX_USAGE; }
      int is_del = (strcmp (verb, "delete") == 0);
      int rtm = is_del ? RTM_DELADDR : RTM_NEWADDR;
      unsigned flags = 0;
      if (strcmp (verb, "add") == 0)
        flags = NLM_F_CREATE | NLM_F_EXCL;
      else if (strcmp (verb, "change") == 0)
        flags = NLM_F_REPLACE;
      else if (strcmp (verb, "replace") == 0)
        flags = NLM_F_CREATE | NLM_F_REPLACE;
      return bip_addr_modify (rtm, flags, cidr, ifname);
    }
  builtin_error ("addr: unknown verb %s", verb_arg);
  return EX_USAGE;
}

static int
bip_route_cmd (WORD_LIST *args, const struct bip_ip_opts *opts)
{
  if (!args)
    return bip_route_show (bip_opts_family_or (opts, AF_INET), NULL, 0,
                           0, RT_TABLE_MAIN, opts ? opts->brief : 0,
                           opts ? opts->json : 0);
  static const char *const verbs[] = {
    "show", "list", "flush", "add", "delete", "change", "replace", "append", "help", NULL
  };
  static const struct bip_alias aliases[] = {
    { "ls", "list" },
    { "del", "delete" },
    { NULL, NULL }
  };
  const char *verb_arg = args->word->word;
  const char *verb = bip_match_keyword (verb_arg, verbs, aliases, "route verb");
  if (!verb)
    return EX_USAGE;
  WORD_LIST *rest = args->next;
  if (strcmp (verb, "help") == 0)
    { bip_print_help (); return EXECUTION_SUCCESS; }
  if (strcmp (verb, "show") == 0 || strcmp (verb, "list") == 0)
    {
      static const char *const show_selectors[] = { "dev", "oif", "default", "table", NULL };
      const char *dev = NULL;
      int only_default = 0;
      int all_tables = 0;
      unsigned table = RT_TABLE_MAIN;
      WORD_LIST *p = rest;
      while (p)
        {
          const char *w = p->word->word;
          const char *kw = bip_match_one (w, show_selectors, "route show selector");
          if (!kw)
            return EX_USAGE;
          if (strcmp (kw, "dev") == 0 || strcmp (kw, "oif") == 0)
            {
              if (!p->next)
                { builtin_error ("route show: %s requires an argument", w); return EX_USAGE; }
              p = p->next; dev = p->word->word;
            }
          else if (strcmp (kw, "default") == 0)
            only_default = 1;
          else if (strcmp (kw, "table") == 0)
            {
              if (!p->next)
                { builtin_error ("route show: %s requires an argument", w); return EX_USAGE; }
              p = p->next;
              if (strcmp (p->word->word, "all") == 0)
                all_tables = 1;
              else if (bip_parse_table (p->word->word, &table) < 0)
                { builtin_error ("route show: bad table %s", p->word->word); return EX_USAGE; }
            }
          p = p->next;
        }
      return bip_route_show (bip_opts_family_or (opts, AF_INET), dev, only_default,
                             all_tables, table, opts ? opts->brief : 0,
                             opts ? opts->json : 0);
    }
  if (opts && opts->json)
    {
      builtin_error ("-j is only supported for read-only route show");
      return EX_USAGE;
    }
  if (strcmp (verb, "flush") == 0)
    {
      static const char *const flush_selectors[] = { "dev", "oif", NULL };
      const char *dev = NULL;
      WORD_LIST *p = rest;
      if (!p)
        { builtin_error ("route flush: dev IFNAME required"); return EX_USAGE; }
      while (p)
        {
          const char *w = p->word->word;
          const char *kw = bip_match_one (w, flush_selectors, "route flush option");
          if (!kw)
            return EX_USAGE;
          if (!p->next)
            { builtin_error ("route flush: %s requires an argument", w); return EX_USAGE; }
          p = p->next; dev = p->word->word;
          p = p->next;
        }
      if (!dev)
        { builtin_error ("route flush: dev IFNAME required"); return EX_USAGE; }
      return bip_route_flush_dev (dev);
    }
  if (strcmp (verb, "add") == 0 || strcmp (verb, "delete") == 0
      || strcmp (verb, "change") == 0
      || strcmp (verb, "replace") == 0 || strcmp (verb, "append") == 0)
    {
      static const char *const modify_opts[] = { "via", "dev", "table", "metric", "priority", NULL };
      if (!rest)
        { builtin_error ("route %s: CIDR|default required", verb_arg); return EX_USAGE; }
      const char *cidr = rest->word->word;
      const char *via = NULL, *dev = NULL;
      unsigned table = RT_TABLE_MAIN, metric = 0;
      int have_metric = 0;
      WORD_LIST *p = rest->next;
      while (p)
        {
          const char *w = p->word->word;
          const char *kw = bip_match_one (w, modify_opts, "route option");
          if (!kw)
            return EX_USAGE;
          if (!p->next)
            { builtin_error ("route %s: %s requires an argument", verb_arg, w); return EX_USAGE; }
          if (strcmp (kw, "via") == 0)
            { p = p->next; via = p->word->word; }
          else if (strcmp (kw, "dev") == 0)
            { p = p->next; dev = p->word->word; }
          else if (strcmp (kw, "table") == 0)
            {
              p = p->next;
              if (bip_parse_table (p->word->word, &table) < 0)
                { builtin_error ("route %s: bad table %s", verb_arg, p->word->word); return EX_USAGE; }
            }
          else if (strcmp (kw, "metric") == 0 || strcmp (kw, "priority") == 0)
            {
              p = p->next;
              if (bip_parse_u32 (p->word->word, &metric) < 0)
                { builtin_error ("route %s: bad metric %s", verb_arg, p->word->word); return EX_USAGE; }
              have_metric = 1;
            }
          p = p->next;
        }
      int is_del = (strcmp (verb, "delete") == 0);
      int rtm = is_del ? RTM_DELROUTE : RTM_NEWROUTE;
      unsigned flags = 0;
      if (strcmp (verb, "add") == 0)
        flags = NLM_F_CREATE | NLM_F_EXCL;
      else if (strcmp (verb, "change") == 0)
        flags = NLM_F_REPLACE;
      else if (strcmp (verb, "replace") == 0)
        flags = NLM_F_CREATE | NLM_F_REPLACE;
      else if (strcmp (verb, "append") == 0)
        flags = NLM_F_CREATE | NLM_F_APPEND;
      if (rtm == RTM_NEWROUTE && !via && !dev)
        { builtin_error ("route %s: need via NEXTHOP or dev IFNAME", verb_arg); return EX_USAGE; }
      return bip_route_modify (rtm, flags, cidr, via, dev, table, have_metric, metric);
    }
  builtin_error ("route: unknown verb %s", verb_arg);
  return EX_USAGE;
}

static int
bip_neigh_cmd (WORD_LIST *args, const struct bip_ip_opts *opts)
{
  if (!args)
    return bip_neigh_show (NULL, opts ? opts->family : AF_UNSPEC,
                           opts ? opts->json : 0);
  static const char *const verbs[] = {
    "show", "list", "add", "delete", "change", "replace", "get", "flush", "help", NULL
  };
  static const struct bip_alias aliases[] = {
    { "ls", "list" },
    { "del", "delete" },
    { NULL, NULL }
  };
  const char *verb_arg = args->word->word;
  const char *verb = bip_match_keyword (verb_arg, verbs, aliases, "neigh verb");
  if (!verb)
    return EX_USAGE;
  WORD_LIST *rest = args->next;
  if (strcmp (verb, "help") == 0)
    { bip_print_help (); return EXECUTION_SUCCESS; }
  if (strcmp (verb, "show") == 0 || strcmp (verb, "list") == 0)
    {
      static const char *const show_selectors[] = { "dev", NULL };
      const char *iface = NULL;
      if (rest)
        {
          const char *w = rest->word->word;
          const char *kw = bip_match_one_quiet (w, show_selectors, "neigh show selector");
          if (kw && strcmp (kw, "dev") == 0)
            {
              if (!rest->next)
                { builtin_error ("neigh show: dev requires an argument"); return EX_USAGE; }
              iface = rest->next->word->word;
              if (rest->next->next)
                { builtin_error ("neigh show: unsupported selector %s", rest->next->next->word->word); return EX_USAGE; }
            }
          else if (!rest->next)
            iface = w;
          else
            { builtin_error ("neigh show: unsupported selector %s", rest->next->word->word); return EX_USAGE; }
        }
      return bip_neigh_show (iface, opts ? opts->family : AF_UNSPEC,
                             opts ? opts->json : 0);
    }
  if (opts && opts->json)
    {
      builtin_error ("-j is only supported for read-only neigh show");
      return EX_USAGE;
    }
  if (strcmp (verb, "add") == 0 || strcmp (verb, "delete") == 0
      || strcmp (verb, "change") == 0
      || strcmp (verb, "replace") == 0)
    {
      static const char *const modify_opts[] = { "lladdr", "dev", "nud", NULL };
      if (!rest)
        { builtin_error ("neigh %s: IP required", verb_arg); return EX_USAGE; }
      const char *ip = rest->word->word;
      const char *ifname = NULL;
      unsigned char mac[6] = { 0 };
      int have_mac = 0, have_nud = 0;
      unsigned nud = NUD_PERMANENT;
      WORD_LIST *p = rest->next;
      while (p)
        {
          const char *w = p->word->word;
          const char *kw = bip_match_one (w, modify_opts, "neigh option");
          if (!kw)
            return EX_USAGE;
          if (!p->next)
            { builtin_error ("neigh %s: %s requires an argument", verb_arg, w); return EX_USAGE; }
          if (strcmp (kw, "lladdr") == 0)
            {
              p = p->next;
              if (bip_parse_lladdr (p->word->word, mac) < 0)
                { builtin_error ("neigh %s: bad lladdr %s", verb_arg, p->word->word); return EX_USAGE; }
              have_mac = 1;
            }
          else if (strcmp (kw, "dev") == 0)
            { p = p->next; ifname = p->word->word; }
          else if (strcmp (kw, "nud") == 0)
            {
              p = p->next;
              if (bip_parse_nud (p->word->word, &nud) < 0)
                { builtin_error ("neigh %s: bad nud state %s", verb_arg, p->word->word); return EX_USAGE; }
              have_nud = 1;
            }
          p = p->next;
        }
      if (!ifname)
        { builtin_error ("neigh %s: dev IFNAME required", verb_arg); return EX_USAGE; }
      int is_del = (strcmp (verb, "delete") == 0);
      if (!is_del && !have_mac)
        { builtin_error ("neigh %s: lladdr MAC required", verb_arg); return EX_USAGE; }
      int rtm = is_del ? RTM_DELNEIGH : RTM_NEWNEIGH;
      unsigned flags = 0;
      if (strcmp (verb, "add") == 0)
        flags = NLM_F_CREATE | NLM_F_EXCL;
      else if (strcmp (verb, "change") == 0)
        flags = NLM_F_REPLACE;
      else if (strcmp (verb, "replace") == 0)
        flags = NLM_F_CREATE | NLM_F_REPLACE;
      return bip_neigh_modify (rtm, flags, ip, mac, have_mac, ifname, nud,
                               have_nud, opts ? opts->family : AF_UNSPEC);
    }
  if (strcmp (verb, "get") == 0 || strcmp (verb, "flush") == 0)
    {
      builtin_error ("neigh %s: not implemented here", verb_arg);
      return EX_USAGE;
    }
  builtin_error ("neigh: unknown verb %s", verb_arg);
  return EX_USAGE;
}

static int
bip_rule_cmd (WORD_LIST *args, const struct bip_ip_opts *opts)
{
  if (!args)
    return bip_rule_show (opts ? opts->json : 0, bip_opts_family_or (opts, AF_INET),
                          0, 0, 0, 0);
  static const char *const verbs[] = {
    "show", "list", "flush", "add", "delete", "help", NULL
  };
  static const struct bip_alias aliases[] = {
    { "ls", "list" },
    { "del", "delete" },
    { NULL, NULL }
  };
  const char *verb_arg = args->word->word;
  const char *verb = bip_match_keyword (verb_arg, verbs, aliases, "rule verb");
  if (!verb)
    return EX_USAGE;
  WORD_LIST *rest = args->next;
  if (strcmp (verb, "help") == 0)
    { bip_print_help (); return EXECUTION_SUCCESS; }
  if (strcmp (verb, "show") == 0 || strcmp (verb, "list") == 0)
    {
      static const char *const show_selectors[] = { "priority", "table", NULL };
      static const struct bip_alias show_aliases[] = {
        { "pref", "priority" },
        { "preference", "priority" },
        { "order", "priority" },
        { "lookup", "table" },
        { NULL, NULL }
      };
      int have_prio = 0, have_table = 0;
      unsigned prio = 0, table = 0;
      WORD_LIST *p = rest;
      while (p)
        {
          const char *w = p->word->word;
          const char *kw = bip_match_keyword (w, show_selectors, show_aliases,
                                              "rule show selector");
          if (!kw)
            return EX_USAGE;
          if (!p->next)
            { builtin_error ("rule show: %s requires an argument", w); return EX_USAGE; }
          if (strcmp (kw, "priority") == 0)
            {
              p = p->next;
              if (bip_parse_u32 (p->word->word, &prio) < 0)
                { builtin_error ("rule show: bad priority %s", p->word->word); return EX_USAGE; }
              have_prio = 1;
            }
          else if (strcmp (kw, "table") == 0)
            {
              p = p->next;
              if (bip_parse_table (p->word->word, &table) < 0)
                { builtin_error ("rule show: bad table %s", p->word->word); return EX_USAGE; }
              have_table = 1;
            }
          p = p->next;
        }
      return bip_rule_show (opts ? opts->json : 0, bip_opts_family_or (opts, AF_INET),
                            have_prio, prio, have_table, table);
    }
  if (opts && opts->json)
    {
      builtin_error ("-j is only supported for read-only rule show");
      return EX_USAGE;
    }
  if (strcmp (verb, "flush") == 0)
    {
      if (rest)
        { builtin_error ("rule flush: unsupported selector %s", rest->word->word); return EX_USAGE; }
      return bip_rule_flush ();
    }
  if (strcmp (verb, "add") == 0 || strcmp (verb, "delete") == 0)
    {
      static const char *const modify_opts[] = {
        "from", "to", "table", "fwmark", "uidrange", "ipproto", "priority", NULL
      };
      static const struct bip_alias modify_aliases[] = {
        { "src", "from" },
        { "dst", "to" },
        { "lookup", "table" },
        { "pref", "priority" },
        { NULL, NULL }
      };
      const char *from = NULL, *to = NULL, *fwmark = NULL, *uidrange = NULL;
      const char *ipproto = NULL, *table = NULL, *prio = NULL;
      WORD_LIST *p = rest;
      while (p)
        {
          const char *w = p->word->word;
          const char *kw = bip_match_keyword (w, modify_opts, modify_aliases,
                                              "rule option");
          if (!kw)
            return EX_USAGE;
          if (!p->next)
            { builtin_error ("rule %s: %s requires an argument", verb_arg, w); return EX_USAGE; }
          if (strcmp (kw, "from") == 0)
            { p = p->next; from = p->word->word; }
          else if (strcmp (kw, "to") == 0)
            { p = p->next; to = p->word->word; }
          else if (strcmp (kw, "table") == 0)
            { p = p->next; table = p->word->word; }
          else if (strcmp (kw, "fwmark") == 0)
            { p = p->next; fwmark = p->word->word; }
          else if (strcmp (kw, "uidrange") == 0)
            { p = p->next; uidrange = p->word->word; }
          else if (strcmp (kw, "ipproto") == 0)
            { p = p->next; ipproto = p->word->word; }
          else if (strcmp (kw, "priority") == 0)
            { p = p->next; prio = p->word->word; }
          p = p->next;
        }
      int rtm = (strcmp (verb, "add") == 0) ? RTM_NEWRULE : RTM_DELRULE;
      return bip_rule_modify (rtm, from, to, fwmark, uidrange, ipproto, table, prio);
    }
  builtin_error ("rule: unknown verb %s", verb_arg);
  return EX_USAGE;
}

static void
bip_print_help (void)
{
  puts ("baship - iproute2 `ip` subset over rtnetlink (NETLINK_ROUTE)");
  puts ("usage:");
  puts ("    baship [ -4 | -6 ] [ -br ] [ -o ] [ -j ] [ -netns NAME ] OBJECT [ show ]");
  puts ("    baship [ -4 | -6 ] [ -j ] [ -netns NAME ] [ -force ] -batch FILE|-");
  puts ("    baship help");
  puts ("    baship [-j] link show [IFNAME]");
  puts ("    baship link set IFNAME up|down|mtu N|address MAC");
  puts ("    baship link add NAME type dummy");
  puts ("    baship link add NAME type veth peer NAME");
  puts ("    baship link del NAME");
  puts ("    baship [-j] addr show [IFNAME] [to PREFIX] [scope SCOPE]");
  puts ("    baship address show [dev IFNAME] [to PREFIX] [scope SCOPE]");
  puts ("    baship addr add|del|change|replace CIDR dev IFNAME");
  puts ("    baship addr flush dev IFNAME [scope SCOPE] [to PREFIX]");
  puts ("    baship [-br|-j] route show [default] [dev IFNAME] [table TABLE|all]");
  puts ("    baship route flush dev IFNAME");
  puts ("    baship route add|del|change|replace|append CIDR|default [via NEXTHOP] [dev IFNAME] [table TABLE] [metric N]");
  puts ("    baship [-j] rule show [priority N] [table TABLE]");
  puts ("    baship rule add from CIDR [to CIDR] [fwmark MARK[/MASK]] [uidrange A-B] [ipproto PROTO] table TABLE priority N");
  puts ("    baship rule del [from CIDR] [to CIDR] [fwmark MARK[/MASK]] [uidrange A-B] [ipproto PROTO] [table TABLE] priority N");
  puts ("    baship rule flush");
  puts ("    baship [-j] neigh show [dev IFNAME]");
  puts ("    baship neigh add|del|change|replace IP [lladdr MAC] dev IFNAME [nud STATE]");
  puts ("unique prefixes are accepted for implemented objects, verbs, and selectors");
  puts ("unsupported Debian ip objects are reported explicitly; tc/xfrm/monitor/ip-netns are not implemented");
}

static int
bip_dispatch (WORD_LIST *list, const struct bip_ip_opts *opts)
{
  if (!list)
    {
      bip_print_help ();
      return EXECUTION_SUCCESS;
    }

  const char *cmd_arg = list->word->word;
  if (strcmp (cmd_arg, "help") == 0)
    {
      bip_print_help ();
      return EXECUTION_SUCCESS;
    }

  const char *cmd = bip_match_keyword (cmd_arg, bip_object_cands,
                                       bip_object_aliases, "object");
  if (!cmd)
    {
      builtin_error ("unsupported ip object: %s", cmd_arg);
      builtin_error ("supported objects: link, addr/address, route, rule, neigh");
      builtin_error ("not implemented here: tc, xfrm, monitor, tunnel, maddr, mroute");
      return EX_USAGE;
    }

  if (opts && opts->json && opts->brief)
    {
      builtin_error ("-j and -br cannot be combined");
      return EX_USAGE;
    }
  if (opts && opts->json && opts->oneline)
    {
      builtin_error ("-j and -o cannot be combined");
      return EX_USAGE;
    }
  if (opts && opts->brief && !(strcmp (cmd, "address") == 0
                               || strcmp (cmd, "link") == 0
                               || strcmp (cmd, "route") == 0))
    {
      builtin_error ("-br is currently supported for addr/address, link, and route only");
      return EX_USAGE;
    }

  if (opts && opts->netns)
    {
      int nrc = bip_netns_switch (opts->netns);
      if (nrc != EXECUTION_SUCCESS)
        return nrc;
    }

  if (strcmp (cmd, "link") == 0)
    return bip_link_cmd (list->next, opts);
  if (strcmp (cmd, "address") == 0)
    return bip_addr_cmd (list->next, opts);
  if (strcmp (cmd, "route") == 0)
    return bip_route_cmd (list->next, opts);
  if (strcmp (cmd, "rule") == 0)
    return bip_rule_cmd (list->next, opts);
  if (strcmp (cmd, "neighbour") == 0)
    return bip_neigh_cmd (list->next, opts);

  builtin_error ("unsupported ip object: %s", cmd_arg);
  return EX_USAGE;
}

static int
bip_run_batch (const char *path, int force, const struct bip_ip_opts *base)
{
  FILE *fp = NULL;
  char line[4096];
  int worst = EXECUTION_SUCCESS;
  unsigned lineno = 0;

  if (!path || !*path)
    {
      builtin_error ("-batch: FILE or - required");
      return EX_USAGE;
    }
  if (strcmp (path, "-") == 0)
    fp = stdin;
  else
    {
      fp = fopen (path, "r");
      if (!fp)
        {
          builtin_error ("-batch %s: %s", path, strerror (errno));
          return EXECUTION_FAILURE;
        }
    }

  while (fgets (line, sizeof line, fp))
    {
      char *argv[128];
      int argc;
      lineno++;
      argc = bip_split_batch_line (line, argv, 128);
      if (argc == 0)
        continue;
      if (argc >= 128)
        {
          builtin_error ("-batch %s:%u: too many words", path, lineno);
          worst = EX_USAGE;
          if (!force)
            break;
          continue;
        }
      WORD_LIST *words = bip_words_from_argv (argv, argc);
      if (!words)
        {
          builtin_error ("-batch %s:%u: out of memory", path, lineno);
          worst = EXECUTION_FAILURE;
          if (!force)
            break;
          continue;
        }
      int rc = bip_dispatch (words, base);
      bip_free_word_nodes (words);
      if (rc != EXECUTION_SUCCESS)
        {
          if (rc > worst)
            worst = rc;
          if (!force)
            break;
        }
    }

  if (ferror (fp))
    {
      builtin_error ("-batch %s: read error: %s", path, strerror (errno));
      if (worst == EXECUTION_SUCCESS)
        worst = EXECUTION_FAILURE;
    }
  if (fp != stdin)
    fclose (fp);
  return worst;
}

int
ip_builtin (WORD_LIST *list)
{
  struct bip_ip_opts opts;
  const char *batch = NULL;
  int force = 0;
  opts.json = 0;
  opts.brief = 0;
  opts.oneline = 0;
  opts.family = AF_UNSPEC;
  opts.netns = NULL;

  while (list)
    {
      const char *w = list->word->word;
      if (strcmp (w, "-j") == 0 || strcmp (w, "-json") == 0
          || strcmp (w, "--json") == 0)
        opts.json = 1;
      else if (strcmp (w, "-br") == 0 || strcmp (w, "-brief") == 0
               || strcmp (w, "--brief") == 0)
        opts.brief = 1;
      else if (strcmp (w, "-o") == 0 || strcmp (w, "-oneline") == 0
               || strcmp (w, "--oneline") == 0)
        opts.oneline = 1;
      else if (strcmp (w, "-4") == 0)
        opts.family = AF_INET;
      else if (strcmp (w, "-6") == 0)
        opts.family = AF_INET6;
      else if (strcmp (w, "-n") == 0 || strcmp (w, "-netns") == 0
               || strcmp (w, "--netns") == 0)
        {
          list = list->next;
          if (!list)
            { builtin_error ("%s needs NAME", w); return EX_USAGE; }
          opts.netns = list->word->word;
        }
      else if (strcmp (w, "-batch") == 0 || strcmp (w, "--batch") == 0)
        {
          list = list->next;
          if (!list)
            { builtin_error ("%s needs FILE or -", w); return EX_USAGE; }
          batch = list->word->word;
        }
      else if (strcmp (w, "-force") == 0 || strcmp (w, "--force") == 0)
        force = 1;
      else if (strcmp (w, "-h") == 0 || strcmp (w, "--help") == 0
               || strcmp (w, "help") == 0)
        {
          bip_print_help ();
          return EXECUTION_SUCCESS;
        }
      else if (w[0] == '-')
        {
          builtin_error ("unsupported ip option: %s", w);
          builtin_error ("supported top-level options: -4, -6, -br, -o, -j, -netns, -batch, -force, -h");
          return EX_USAGE;
        }
      else
        break;
      list = list->next;
    }

  if (batch)
    {
      if (list)
        {
          builtin_error ("-batch cannot be combined with a trailing object: %s",
                         list->word->word);
          return EX_USAGE;
        }
      return bip_run_batch (batch, force, &opts);
    }

  if (!list)
    {
      bip_print_help ();
      return EXECUTION_SUCCESS;
    }
  return bip_dispatch (list, &opts);
}

char *ip_doc[] = {
	  "iproute2 `ip` subset over rtnetlink (NETLINK_ROUTE).",
	  "",
	  "    baship [ -4 | -6 ] [ -br ] [ -o ] [ -j ] [ -netns NAME ] OBJECT [ show ]",
	  "    baship [ -4 | -6 ] [ -j ] [ -netns NAME ] [ -force ] -batch FILE|-",
	  "    baship help",
	  "    baship [-j] link show [IFNAME]",
  "    baship link set IFNAME up|down|mtu N|address MAC",
  "    baship link add NAME type dummy",
  "    baship link add NAME type veth peer NAME",
  "    baship link del NAME",
  "    baship [-j] addr show [IFNAME] [to PREFIX] [scope SCOPE]",
  "    baship address show [dev IFNAME] [to PREFIX] [scope SCOPE]",
  "    baship addr add|del|change|replace CIDR dev IFNAME",
  "    baship addr flush dev IFNAME [scope SCOPE] [to PREFIX]",
	  "    baship [-br|-j] route show [default] [dev IFNAME] [table TABLE|all]",
  "    baship route flush dev IFNAME",
  "    baship route add|del|change|replace|append CIDR|default [via NEXTHOP] [dev IFNAME] [table TABLE] [metric N]",
  "    baship [-j] rule show [priority N] [table TABLE]",
  "    baship rule add from CIDR [to CIDR] [fwmark MARK[/MASK]] [uidrange A-B] [ipproto PROTO] table TABLE priority N",
  "    baship rule del [from CIDR] [to CIDR] [fwmark MARK[/MASK]] [uidrange A-B] [ipproto PROTO] [table TABLE] priority N",
  "    baship rule flush",
	  "    baship [-j] neigh show [dev IFNAME]",
  "    baship neigh add|del|change|replace IP [lladdr MAC] dev IFNAME [nud STATE]",
	  "",
	  "Modify verbs require CAP_NET_ADMIN.",
	  "Unique prefixes are accepted for implemented objects, verbs, and selectors.",
	  "Deferred to v2: tc, xfrm, monitor, ip netns object, IPv6 SLAAC, richer selectors.",
	  (char *) NULL
	};

struct builtin baship_struct = {
  "baship",
  ip_builtin,
  BUILTIN_ENABLED,
	  ip_doc,
	  "baship [-4|-6] [-br] [-o] [-j] [-netns NAME] [-batch FILE|-] link|addr|route|rule|neigh VERB ARGS...",
	  0
	};
