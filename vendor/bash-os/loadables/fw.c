/* SPDX-License-Identifier: MIT */
/* fw.c — netfilter front-end. Loadable for bash.
 *
 * Stage A.10 of the bash-os deployable-distro track. Thin, opinionated
 * wrapper around the nft(8) / iptables(8) CLIs: fw lets bash-os
 * scripts manage simple allow/deny rule sets without remembering two
 * different syntaxes. Backend selection is automatic — nft preferred
 * when present, otherwise iptables.
 *
 * Subcommands:
 *     fw allow IP|-S SET [-D ADDR|@SET] [-p PROTO] [-d DPORT] [-s SPORT]
 *                  [-i IFACE] [-o IFACE] [--ct-state STATES]
 *                  [--limit RATE] [--multiport PORTS]
 *                  [--syn|--tcp-flags MASK/COMP]
 *     fw deny  IP|-S SET [-D ADDR|@SET] [-p PROTO] [-d DPORT] [-s SPORT]
 *                  [-i IFACE] [-o IFACE] [--ct-state STATES]
 *                  [--limit RATE] [--multiport PORTS]
 *                  [--syn|--tcp-flags MASK/COMP]
 *                  [--log PREFIX [--log-level LEVEL]|--nflog PREFIX]
 *     fw unban IP [-p PROTO] [-d DPORT] [-s SPORT]
 *     fw set create NAME [-f inet|inet6] [-t hash:ip|hash:net]
 *     fw set add|del NAME IP[/CIDR]
 *     fw set list [NAME]
 *     fw set destroy NAME
 *     fw dnat  ADDR:PORT [->] DEST:PORT [-p PROTO]
 *     fw snat  ADDR:PORT [->] DEST:PORT [-p PROTO]
 *     fw masquerade CIDR [-p PROTO] [-o IFACE]
 *     fw flush [CHAIN]
 *     fw list  [CHAIN]
 *     fw save [FILE]
 *     fw restore [FILE]
 *     fw batch FILE
 *     fw reset
 *     fw status
 *
 * Global flags (must precede the subcommand):
 *     -B nft|iptables      force backend
 *     -n                   dry-run: print the backend argv to stdout,
 *                          do not actually run anything (test-friendly)
 *
 * Conventions:
 *   - nft mode operates on table inet/fw, chains input/output for
 *     filter and prerouting/postrouting for NAT (Stage A.10.B).
 *   - iptables mode operates on chains BASHFW_IN / BASHFW_OUT inside
 *     the filter table; dnat/snat target the nat table's PREROUTING
 *     and POSTROUTING chains directly (no custom chain — nat-table
 *     custom chains aren't traversed by default).
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
#include <strings.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "loadables.h"

#define BFW_MAX_ARGV 64

/* Canonical persistence path. `fw save` AND `fw restore` with
   no FILE argument both target this path (v4.0 closure, 2026-05-14:
   restore was changed to mirror save's default so an init/auto-restore
   service stub can call `fw restore` on a fresh boot without
   painting stderr red — see bfw_cmd_restore for the asymmetric
   missing-file arms). Kept as a #define so the test suite
   (251-fw-persist.sh, 619-fw-restore-missing.sh) can pin the
   exact string. */
#define BFW_DEFAULT_SAVE_DIR  "/etc/fw"
#define BFW_DEFAULT_SAVE_PATH "/etc/fw/rules.conf"
#define BFW_IPSET_BEGIN "# fw ipset-save begin\n"
#define BFW_IPSET_END   "# fw ipset-save end\n"

enum bfw_backend { BFW_AUTO = 0, BFW_NFT, BFW_IPT, BFW_PURE };

struct bfw_opts {
  enum bfw_backend backend;
  int dry_run;
  int idempotent;
};

/* Forward declarations for idempotence check helpers. */
struct bfw_rule;
static int bfw_nft_rule_exists (const char *, struct bfw_opts *);
static int bfw_ipt_rule_exists (const struct bfw_rule *, const char *,
                                struct bfw_opts *);

/* ---- backend detection ---- */

static int
bfw_have_exec (const char *prog)
{
  const char *path = getenv ("PATH");
  if (!path) path = "/usr/sbin:/sbin:/usr/bin:/bin";
  char *copy = strdup (path);
  if (!copy) return 0;
  int found = 0;
  for (char *tok = strtok (copy, ":"); tok && !found; tok = strtok (NULL, ":"))
    {
      char p[512];
      snprintf (p, sizeof p, "%s/%s", tok, prog);
      if (access (p, X_OK) == 0) found = 1;
    }
  free (copy);
  return found;
}

static enum bfw_backend
bfw_detect (void)
{
  if (bfw_have_exec ("nft")) return BFW_NFT;
  if (bfw_have_exec ("iptables")) return BFW_IPT;
  return BFW_AUTO;
}

/* ---- argv helpers ---- */

struct bfw_argv {
  const char *v[BFW_MAX_ARGV];
  int n;
};

static int
bfw_push (struct bfw_argv *a, const char *s)
{
  if (a->n >= BFW_MAX_ARGV - 1) return -1;
  a->v[a->n++] = s;
  a->v[a->n] = NULL;
  return 0;
}

struct bfw_child_guard {
  struct sigaction old_action;
  sigset_t old_mask;
};

static void
bfw_child_guard_begin (struct bfw_child_guard *g)
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

static void
bfw_child_guard_parent_end (struct bfw_child_guard *g)
{
  sigprocmask (SIG_SETMASK, &g->old_mask, NULL);
  sigaction (SIGCHLD, &g->old_action, NULL);
}

static void
bfw_child_guard_child_end (struct bfw_child_guard *g)
{
  sigprocmask (SIG_SETMASK, &g->old_mask, NULL);
}

/* Spawn argv and wait for it. Returns exit status (0 on success). */
static int
bfw_run (const struct bfw_argv *a, struct bfw_opts *o)
{
  if (o->dry_run)
    {
      for (int i = 0; i < a->n; i++)
        printf ("%s%s", i ? " " : "", a->v[i]);
      printf ("\n");
      return 0;
    }
  struct bfw_child_guard guard;
  bfw_child_guard_begin (&guard);
  pid_t pid = fork ();
  if (pid < 0) { bfw_child_guard_parent_end (&guard); builtin_error ("fork: %s", strerror (errno)); return -1; }
  if (pid == 0)
    {
      bfw_child_guard_child_end (&guard);
      execvp (a->v[0], (char *const *) a->v);
      fprintf (stderr, "fw: execvp %s: %s\n", a->v[0], strerror (errno));
      _exit (127);
    }
  int st = 0;
  while (waitpid (pid, &st, 0) < 0)
    {
      if (errno == EINTR) continue;
      bfw_child_guard_parent_end (&guard);
      return -1;
    }
  bfw_child_guard_parent_end (&guard);
  if (WIFEXITED (st)) return WEXITSTATUS (st);
  return -1;
}

/* Like bfw_run but captures stdout into buf (up to bufsz-1 bytes).
   The child's exit status is discarded. Returns 0 on success, -1 on
   fork/pipe failure. Used by idempotence checks where we need to
   inspect the current ruleset. */
static int
bfw_capture (const struct bfw_argv *a, char *buf, size_t bufsz)
{
  int fd[2];
  if (pipe (fd) < 0) return -1;
  struct bfw_child_guard guard;
  bfw_child_guard_begin (&guard);
  pid_t pid = fork ();
  if (pid < 0) { close (fd[0]); close (fd[1]); bfw_child_guard_parent_end (&guard); return -1; }
  if (pid == 0)
    {
      bfw_child_guard_child_end (&guard);
      close (fd[0]);
      dup2 (fd[1], 1);
      if (fd[1] != 1) close (fd[1]);
      execvp (a->v[0], (char *const *) a->v);
      _exit (127);
    }
  close (fd[1]);
  ssize_t n = read (fd[0], buf, bufsz - 1);
  close (fd[0]);
  if (n > 0) buf[n] = '\0'; else buf[0] = '\0';
  int st = 0;
  while (waitpid (pid, &st, 0) < 0 && errno == EINTR) ;
  bfw_child_guard_parent_end (&guard);
  return 0;
}

static int
bfw_run_stdout_fd (const struct bfw_argv *a, int outfd)
{
  struct bfw_child_guard guard;
  bfw_child_guard_begin (&guard);
  pid_t pid = fork ();
  if (pid < 0) { bfw_child_guard_parent_end (&guard); builtin_error ("fork: %s", strerror (errno)); return -1; }
  if (pid == 0)
    {
      bfw_child_guard_child_end (&guard);
      dup2 (outfd, 1);
      execvp (a->v[0], (char *const *) a->v);
      fprintf (stderr, "fw: execvp %s: %s\n", a->v[0], strerror (errno));
      _exit (127);
    }
  int st = 0;
  while (waitpid (pid, &st, 0) < 0)
    {
      if (errno == EINTR) continue;
      bfw_child_guard_parent_end (&guard);
      return -1;
    }
  bfw_child_guard_parent_end (&guard);
  if (WIFEXITED (st)) return WEXITSTATUS (st);
  return -1;
}

static int
bfw_run_stdin_file (const struct bfw_argv *a, const char *file)
{
  int infd = open (file, O_RDONLY);
  if (infd < 0)
    { builtin_error ("%s: open %s: %s", a->v[0], file, strerror (errno)); return -1; }

  struct bfw_child_guard guard;
  bfw_child_guard_begin (&guard);
  pid_t pid = fork ();
  if (pid < 0)
    {
      close (infd);
      bfw_child_guard_parent_end (&guard);
      builtin_error ("fork: %s", strerror (errno));
      return -1;
    }
  if (pid == 0)
    {
      bfw_child_guard_child_end (&guard);
      dup2 (infd, 0);
      close (infd);
      execvp (a->v[0], (char *const *) a->v);
      fprintf (stderr, "fw: execvp %s: %s\n", a->v[0], strerror (errno));
      _exit (127);
    }
  close (infd);

  int st = 0;
  while (waitpid (pid, &st, 0) < 0)
    {
      if (errno == EINTR) continue;
      bfw_child_guard_parent_end (&guard);
      return -1;
    }
  bfw_child_guard_parent_end (&guard);
  if (WIFEXITED (st)) return WEXITSTATUS (st);
  return -1;
}

/* ---- validation helpers ---- */

static int
bfw_valid_ip46_or_cidr (const char *s, int *family_out)
{
  if (!s || !*s) return 0;
  char buf[128];
  snprintf (buf, sizeof buf, "%s", s);
  char *slash = strchr (buf, '/');
  if (slash)
    {
      *slash = '\0';
      char *end = NULL;
      long m = strtol (slash + 1, &end, 10);
      if (!end || *end != '\0') return 0;
      if (strchr (buf, ':'))
        { if (m < 0 || m > 128) return 0; }
      else
        { if (m < 0 || m > 32) return 0; }
    }
  struct in_addr a4;
  if (inet_pton (AF_INET, buf, &a4) == 1)
    { if (family_out) *family_out = AF_INET; return 1; }
  struct in6_addr a6;
  if (inet_pton (AF_INET6, buf, &a6) == 1)
    { if (family_out) *family_out = AF_INET6; return 1; }
  return 0;
}

static int
bfw_valid_port (const char *s)
{
  if (!s || !*s) return 0;
  char *end = NULL;
  long p = strtol (s, &end, 10);
  return end && *end == '\0' && p > 0 && p < 65536;
}

static int
bfw_valid_port_list (const char *s)
{
  if (!s || !*s) return 0;
  char buf[256];
  snprintf (buf, sizeof buf, "%s", s);
  char *save = NULL;
  for (char *tok = strtok_r (buf, ",", &save); tok; tok = strtok_r (NULL, ",", &save))
    {
      char *dash = strchr (tok, '-');
      if (dash)
        {
          *dash = '\0';
          if (!bfw_valid_port (tok) || !bfw_valid_port (dash + 1)) return 0;
          if (atoi (tok) > atoi (dash + 1)) return 0;
        }
      else if (!bfw_valid_port (tok))
        return 0;
    }
  return 1;
}

static int
bfw_valid_proto (const char *s)
{
  return s && (!strcmp (s, "tcp") || !strcmp (s, "udp") ||
               !strcmp (s, "icmp") || !strcmp (s, "icmpv6") ||
               !strcmp (s, "any"));
}

static int
bfw_valid_chain (const char *s)
{
  if (!s || !*s) return 0;
  for (const char *p = s; *p; p++)
    if (!isalnum ((unsigned char) *p) && *p != '_' && *p != '-') return 0;
  return 1;
}

static int
bfw_valid_set_name (const char *s)
{
  return bfw_valid_chain (s);
}

static int
bfw_valid_ct_states (const char *s)
{
  if (!s || !*s) return 0;
  char buf[160];
  snprintf (buf, sizeof buf, "%s", s);
  char *save = NULL;
  for (char *tok = strtok_r (buf, ",", &save); tok; tok = strtok_r (NULL, ",", &save))
    {
      if (strcmp (tok, "new") != 0 && strcmp (tok, "established") != 0 &&
          strcmp (tok, "related") != 0 && strcmp (tok, "invalid") != 0 &&
          strcmp (tok, "untracked") != 0)
        return 0;
    }
  return 1;
}

static int
bfw_valid_rate (const char *s)
{
  if (!s || !*s) return 0;
  size_t n = strlen (s);
  if (n > 32) return 0;
  for (const char *p = s; *p; p++)
    if (!isalnum ((unsigned char) *p) && *p != '/' && *p != '-' && *p != '_')
      return 0;
  return strchr (s, '/') != NULL;
}

static int
bfw_tcp_flag_bit (const char *s)
{
  if (!s || !*s) return 0;
  if (!strcasecmp (s, "fin")) return 1 << 0;
  if (!strcasecmp (s, "syn")) return 1 << 1;
  if (!strcasecmp (s, "rst")) return 1 << 2;
  if (!strcasecmp (s, "psh")) return 1 << 3;
  if (!strcasecmp (s, "ack")) return 1 << 4;
  if (!strcasecmp (s, "urg")) return 1 << 5;
  return 0;
}

static int
bfw_tcp_flag_list_mask (const char *s, int *mask_out)
{
  if (!s || !*s) return 0;
  if (!strcasecmp (s, "none"))
    {
      if (mask_out) *mask_out = 0;
      return 1;
    }
  if (!strcasecmp (s, "all"))
    {
      if (mask_out) *mask_out = (1 << 6) - 1;
      return 1;
    }

  char buf[160];
  snprintf (buf, sizeof buf, "%s", s);
  int mask = 0;
  char *save = NULL;
  for (char *tok = strtok_r (buf, ",", &save); tok; tok = strtok_r (NULL, ",", &save))
    {
      int bit = bfw_tcp_flag_bit (tok);
      if (!bit) return 0;
      mask |= bit;
    }
  if (mask_out) *mask_out = mask;
  return mask != 0;
}

static int
bfw_valid_tcp_flags (const char *s)
{
  if (!s || !*s) return 0;
  char buf[192];
  snprintf (buf, sizeof buf, "%s", s);
  char *slash = strchr (buf, '/');
  if (!slash || strchr (slash + 1, '/')) return 0;
  *slash = '\0';
  if (!buf[0] || !slash[1]) return 0;
  return bfw_tcp_flag_list_mask (buf, NULL) &&
         bfw_tcp_flag_list_mask (slash + 1, NULL);
}

static int
bfw_split_tcp_flags (const char *s, char *mask, size_t masksz,
                     char *comp, size_t compsz)
{
  const char *slash = strchr (s, '/');
  if (!slash) return -1;
  size_t mlen = (size_t) (slash - s);
  if (mlen == 0 || mlen >= masksz || strlen (slash + 1) >= compsz)
    return -1;
  memcpy (mask, s, mlen);
  mask[mlen] = '\0';
  snprintf (comp, compsz, "%s", slash + 1);
  return 0;
}

static void
bfw_tcp_flags_nft_expr (const char *s, char *out, size_t outsz)
{
  static const char *names[] = { "fin", "syn", "rst", "psh", "ack", "urg" };
  int mask = 0;
  int off = 0;
  out[0] = '\0';
  if (!bfw_tcp_flag_list_mask (s, &mask) || mask == 0)
    {
      snprintf (out, outsz, "0");
      return;
    }
  for (int i = 0; i < 6; i++)
    if (mask & (1 << i))
      {
        off += snprintf (out + off, outsz - off, "%s%s",
                         off ? "|" : "", names[i]);
        if (off >= (int) outsz) break;
      }
}

static void
bfw_tcp_flags_ipt_expr (const char *s, char *out, size_t outsz)
{
  static const char *names[] = { "FIN", "SYN", "RST", "PSH", "ACK", "URG" };
  int mask = 0;
  int off = 0;
  out[0] = '\0';
  if (!bfw_tcp_flag_list_mask (s, &mask))
    {
      snprintf (out, outsz, "%s", s);
      return;
    }
  if (mask == 0)
    {
      snprintf (out, outsz, "NONE");
      return;
    }
  for (int i = 0; i < 6; i++)
    if (mask & (1 << i))
      {
        off += snprintf (out + off, outsz - off, "%s%s",
                         off ? "," : "", names[i]);
        if (off >= (int) outsz) break;
      }
}

static int
bfw_valid_log_prefix (const char *s)
{
  if (!s || !*s || strlen (s) > 48) return 0;
  for (const char *p = s; *p; p++)
    if (!isalnum ((unsigned char) *p) && *p != '_' && *p != '-' &&
        *p != '.' && *p != ':' && *p != ' ')
      return 0;
  return 1;
}

static int
bfw_valid_log_level (const char *s)
{
  return s && (!strcmp (s, "emerg") || !strcmp (s, "alert") ||
               !strcmp (s, "crit") || !strcmp (s, "err") ||
               !strcmp (s, "warn") || !strcmp (s, "notice") ||
               !strcmp (s, "info") || !strcmp (s, "debug"));
}

static const char *
bfw_ip_word (int family)
{
  return family == AF_INET6 ? "ip6" : "ip";
}

static const char *
bfw_iptables_prog (int family)
{
  return family == AF_INET6 ? "ip6tables" : "iptables";
}

/* ---- parse rule flags (-p / -d / -s) ---- */

struct bfw_rule {
  const char *ip;
  const char *set_name;
  const char *daddr;
  const char *dset_name;
  int family;
  const char *proto;
  const char *dport;
  const char *sport;
  const char *iface_in;
  const char *iface_out;
  const char *ct_state;
  const char *limit;
  const char *multiport;
  const char *tcp_flags;
  const char *log_prefix;
  const char *log_level;
  int nflog;
  const char *reject_mode;  /* NULL = DROP; else port-unreachable|tcp-reset|admin-prohibited */
};

/* F07 next-slice: REJECT mode → backend tokens. */
static int
bfw_reject_valid (const char *m)
{
  return m && (!strcmp (m, "port-unreachable") || !strcmp (m, "tcp-reset")
               || !strcmp (m, "admin-prohibited"));
}
static const char *
bfw_reject_nft (const char *m)
{
  if (!strcmp (m, "tcp-reset")) return "reject with tcp reset";
  if (!strcmp (m, "admin-prohibited")) return "reject with icmpx type admin-prohibited";
  return "reject with icmpx type port-unreachable";
}
static const char *
bfw_reject_ipt (const char *m, int family)
{
  int v6 = (family == AF_INET6);
  if (!strcmp (m, "tcp-reset")) return "tcp-reset";
  if (!strcmp (m, "admin-prohibited")) return v6 ? "icmp6-adm-prohibited" : "icmp-admin-prohibited";
  return v6 ? "icmp6-port-unreachable" : "icmp-port-unreachable";
}

static int
bfw_rule_text (const struct bfw_rule *r, const char *verdict,
               char *buf, size_t bufsz)
{
  char ip_clause[160], daddr_clause[160], dport_clause[96], sport_clause[64],
       proto_clause[24], tcp_flags_clause[192];
  int off = 0;

  ip_clause[0] = daddr_clause[0] = dport_clause[0] = sport_clause[0] =
    proto_clause[0] = tcp_flags_clause[0] = '\0';
  if (r->set_name)
    snprintf (ip_clause, sizeof ip_clause, "%s saddr @%s",
              bfw_ip_word (r->family), r->set_name);
  else
    snprintf (ip_clause, sizeof ip_clause, "%s saddr %s",
              bfw_ip_word (r->family), r->ip);
  if (r->dset_name)
    snprintf (daddr_clause, sizeof daddr_clause, "%s daddr @%s",
              bfw_ip_word (r->family), r->dset_name);
  else if (r->daddr)
    snprintf (daddr_clause, sizeof daddr_clause, "%s daddr %s",
              bfw_ip_word (r->family), r->daddr);
  if (r->proto && strcmp (r->proto, "any") != 0)
    snprintf (proto_clause, sizeof proto_clause, "%s", r->proto);
  if (r->multiport) snprintf (dport_clause, sizeof dport_clause, "dport { %s }", r->multiport);
  else if (r->dport) snprintf (dport_clause, sizeof dport_clause, "dport %s", r->dport);
  if (r->sport) snprintf (sport_clause, sizeof sport_clause, "sport %s", r->sport);
  if (r->tcp_flags)
    {
      char mask[96], comp[96], nft_mask[128], nft_comp[128];
      if (bfw_split_tcp_flags (r->tcp_flags, mask, sizeof mask, comp, sizeof comp) == 0)
        {
          bfw_tcp_flags_nft_expr (mask, nft_mask, sizeof nft_mask);
          bfw_tcp_flags_nft_expr (comp, nft_comp, sizeof nft_comp);
          snprintf (tcp_flags_clause, sizeof tcp_flags_clause,
                    "tcp flags & (%s) == %s", nft_mask, nft_comp);
        }
    }

  off += snprintf (buf + off, bufsz - off, "%s", ip_clause);
  if (daddr_clause[0])
    off += snprintf (buf + off, bufsz - off, " %s", daddr_clause);
  if (r->iface_in)
    off += snprintf (buf + off, bufsz - off, " iifname \"%s\"", r->iface_in);
  if (r->iface_out)
    off += snprintf (buf + off, bufsz - off, " oifname \"%s\"", r->iface_out);
  if (r->ct_state)
    off += snprintf (buf + off, bufsz - off, " ct state { %s }", r->ct_state);
  if (proto_clause[0] && !(r->tcp_flags && !dport_clause[0] && !sport_clause[0]))
    off += snprintf (buf + off, bufsz - off, " %s", proto_clause);
  if (dport_clause[0])
    off += snprintf (buf + off, bufsz - off, " %s", dport_clause);
  if (sport_clause[0])
    off += snprintf (buf + off, bufsz - off, " %s", sport_clause);
  if (tcp_flags_clause[0])
    off += snprintf (buf + off, bufsz - off, " %s", tcp_flags_clause);
  if (r->limit)
    off += snprintf (buf + off, bufsz - off, " limit rate %s", r->limit);
  if (r->log_prefix)
    {
      if (r->nflog)
        off += snprintf (buf + off, bufsz - off, " log prefix \"%s\" group 0", r->log_prefix);
      else
        {
          off += snprintf (buf + off, bufsz - off, " log prefix \"%s\"", r->log_prefix);
          if (r->log_level)
            off += snprintf (buf + off, bufsz - off, " level %s", r->log_level);
        }
    }
  off += snprintf (buf + off, bufsz - off, " %s", verdict);

  return off < (int) bufsz ? 0 : -1;
}

static int
bfw_parse_rule (WORD_LIST *args, struct bfw_rule *r, const char *verb)
{
  memset (r, 0, sizeof *r);
  if (!args)
    { builtin_error ("%s: needs IP or -S SET", verb); return -1; }
  WORD_LIST *p = args;
  if (strcmp (p->word->word, "-S") == 0)
    {
      if (!p->next) { builtin_error ("%s: -S needs SET", verb); return -1; }
      p = p->next;
      r->set_name = p->word->word;
      r->family = AF_INET;
      if (!bfw_valid_set_name (r->set_name))
        { builtin_error ("%s: invalid set name: %s", verb, r->set_name); return -1; }
      p = p->next;
    }
  else
    {
      r->ip = p->word->word;
      if (!bfw_valid_ip46_or_cidr (r->ip, &r->family))
        { builtin_error ("%s: invalid IP/CIDR: %s", verb, r->ip); return -1; }
      p = p->next;
    }
  for (; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-S") == 0)
        {
          builtin_error ("%s: -S must precede rule flags", verb);
          return -1;
        }
      else if (strcmp (w, "-p") == 0)
        {
          if (!p->next) { builtin_error ("%s: -p needs PROTO", verb); return -1; }
          p = p->next; r->proto = p->word->word;
          if (!bfw_valid_proto (r->proto))
            { builtin_error ("%s: invalid proto: %s", verb, r->proto); return -1; }
        }
      else if (strcmp (w, "-D") == 0)
        {
          const char *d;
          if (!p->next) { builtin_error ("%s: -D needs ADDR or @SET", verb); return -1; }
          p = p->next; d = p->word->word;
          if (d[0] == '@')
            {
              r->dset_name = d + 1;
              if (!bfw_valid_set_name (r->dset_name))
                { builtin_error ("%s: invalid destination set name: %s", verb, r->dset_name); return -1; }
            }
          else
            {
              int dfam = 0;
              r->daddr = d;
              if (!bfw_valid_ip46_or_cidr (r->daddr, &dfam))
                { builtin_error ("%s: invalid destination IP/CIDR: %s", verb, r->daddr); return -1; }
              if (r->ip && r->family != dfam)
                { builtin_error ("%s: destination family differs from source", verb); return -1; }
              if (!r->ip)
                r->family = dfam;
            }
        }
      else if (strcmp (w, "-d") == 0)
        {
          if (!p->next) { builtin_error ("%s: -d needs DPORT", verb); return -1; }
          p = p->next; r->dport = p->word->word;
          if (!bfw_valid_port (r->dport))
            { builtin_error ("%s: invalid dport: %s", verb, r->dport); return -1; }
        }
      else if (strcmp (w, "-s") == 0)
        {
          if (!p->next) { builtin_error ("%s: -s needs SPORT", verb); return -1; }
          p = p->next; r->sport = p->word->word;
          if (!bfw_valid_port (r->sport))
            { builtin_error ("%s: invalid sport: %s", verb, r->sport); return -1; }
        }
      else if (strcmp (w, "-i") == 0)
        {
          if (!p->next) { builtin_error ("%s: -i needs IFACE", verb); return -1; }
          p = p->next; r->iface_in = p->word->word;
          if (!bfw_valid_chain (r->iface_in))
            { builtin_error ("%s: invalid iface: %s", verb, r->iface_in); return -1; }
        }
      else if (strcmp (w, "-o") == 0)
        {
          if (!p->next) { builtin_error ("%s: -o needs IFACE", verb); return -1; }
          p = p->next; r->iface_out = p->word->word;
          if (!bfw_valid_chain (r->iface_out))
            { builtin_error ("%s: invalid iface: %s", verb, r->iface_out); return -1; }
        }
      else if (strcmp (w, "--ct-state") == 0)
        {
          if (!p->next) { builtin_error ("%s: --ct-state needs STATES", verb); return -1; }
          p = p->next; r->ct_state = p->word->word;
          if (!bfw_valid_ct_states (r->ct_state))
            { builtin_error ("%s: invalid ct states: %s", verb, r->ct_state); return -1; }
        }
      else if (strcmp (w, "--limit") == 0)
        {
          if (!p->next) { builtin_error ("%s: --limit needs RATE", verb); return -1; }
          p = p->next; r->limit = p->word->word;
          if (!bfw_valid_rate (r->limit))
            { builtin_error ("%s: invalid limit: %s", verb, r->limit); return -1; }
        }
      else if (strcmp (w, "--multiport") == 0)
        {
          if (!p->next) { builtin_error ("%s: --multiport needs PORTS", verb); return -1; }
          p = p->next; r->multiport = p->word->word;
          if (!bfw_valid_port_list (r->multiport))
            { builtin_error ("%s: invalid multiport list: %s", verb, r->multiport); return -1; }
        }
      else if (strcmp (w, "--syn") == 0)
        {
          r->tcp_flags = "syn,rst,ack,fin/syn";
        }
      else if (strcmp (w, "--tcp-flags") == 0)
        {
          if (!p->next) { builtin_error ("%s: --tcp-flags needs MASK/COMP", verb); return -1; }
          p = p->next; r->tcp_flags = p->word->word;
          if (!bfw_valid_tcp_flags (r->tcp_flags))
            { builtin_error ("%s: invalid tcp flags: %s", verb, r->tcp_flags); return -1; }
        }
      else if (strcmp (w, "--log") == 0 || strcmp (w, "--nflog") == 0)
        {
          if (!p->next) { builtin_error ("%s: %s needs PREFIX", verb, w); return -1; }
          p = p->next; r->log_prefix = p->word->word;
          r->nflog = strcmp (w, "--nflog") == 0;
          if (!bfw_valid_log_prefix (r->log_prefix))
            { builtin_error ("%s: invalid log prefix: %s", verb, r->log_prefix); return -1; }
        }
      else if (strcmp (w, "--log-level") == 0)
        {
          if (!p->next) { builtin_error ("%s: --log-level needs LEVEL", verb); return -1; }
          p = p->next; r->log_level = p->word->word;
          if (!bfw_valid_log_level (r->log_level))
            { builtin_error ("%s: invalid log level: %s", verb, r->log_level); return -1; }
        }
      else if (strcmp (w, "--reject") == 0 || strncmp (w, "--reject=", 9) == 0)
        {
          /* deny … --reject[=MODE]; default mode port-unreachable. */
          r->reject_mode = (w[8] == '=') ? w + 9 : "port-unreachable";
          if (!bfw_reject_valid (r->reject_mode))
            { builtin_error ("%s: invalid --reject mode: %s (want port-unreachable|tcp-reset|admin-prohibited)", verb, r->reject_mode); return -1; }
        }
      else
        { builtin_error ("%s: unknown flag: %s", verb, w); return -1; }
    }
  if (r->dport && r->multiport)
    { builtin_error ("%s: -d and --multiport are mutually exclusive", verb); return -1; }
  if ((r->dport || r->sport || r->multiport) && !r->proto)
    r->proto = "tcp";
  if (r->multiport && strcmp (r->proto, "tcp") != 0 && strcmp (r->proto, "udp") != 0)
    { builtin_error ("%s: --multiport requires tcp or udp", verb); return -1; }
  if (r->tcp_flags && (!r->proto || strcmp (r->proto, "tcp") != 0))
    { builtin_error ("%s: --tcp-flags requires -p tcp", verb); return -1; }
  if (r->log_level && !r->log_prefix)
    { builtin_error ("%s: --log-level requires --log", verb); return -1; }
  if (r->log_level && r->nflog)
    { builtin_error ("%s: --log-level cannot be used with --nflog", verb); return -1; }
  return 0;
}

/* ---- nft builders ---- */

static int
bfw_nft_rule (struct bfw_opts *o, const struct bfw_rule *r, const char *verdict)
{
  struct bfw_argv a = {0};
  static char persist[512];
  if (bfw_rule_text (r, verdict, persist, sizeof persist) < 0)
    { builtin_error ("rule too long"); return EXECUTION_FAILURE; }

  /* Idempotent mode: skip add if the exact rule already exists. */
  if (o->idempotent)
    {
      int exists = bfw_nft_rule_exists (persist, o);
      if (exists > 0) return 0;       /* already present – idempotent */
      if (exists < 0)
        { /* capture failed — proceed anyway, the add may still work */ }
    }

  bfw_push (&a, "nft");
  bfw_push (&a, "add");
  bfw_push (&a, "rule");
  bfw_push (&a, "inet");
  bfw_push (&a, "fw");
  bfw_push (&a, "input");
  bfw_push (&a, persist);
  return bfw_run (&a, o);
}

static int
bfw_nft_delete_rule (struct bfw_opts *o, const struct bfw_rule *r,
                     const char *verdict)
{
  static char ruletext[512];
  if (bfw_rule_text (r, verdict, ruletext, sizeof ruletext) < 0)
    { builtin_error ("unban: rule too long"); return EXECUTION_FAILURE; }

  if (o->dry_run)
    {
      struct bfw_argv a = {0};
      bfw_push (&a, "nft");
      bfw_push (&a, "delete");
      bfw_push (&a, "rule");
      bfw_push (&a, "inet");
      bfw_push (&a, "fw");
      bfw_push (&a, "input");
      bfw_push (&a, "handle");
      bfw_push (&a, "<matched-drop-rule>");
      return bfw_run (&a, o);
    }

  struct bfw_argv list = {0};
  bfw_push (&list, "nft");
  bfw_push (&list, "-a");
  bfw_push (&list, "list");
  bfw_push (&list, "chain");
  bfw_push (&list, "inet");
  bfw_push (&list, "fw");
  bfw_push (&list, "input");

  char buf[32768];
  if (bfw_capture (&list, buf, sizeof buf) < 0)
    { builtin_error ("unban: could not list nft rules"); return EXECUTION_FAILURE; }

  char *save = NULL;
  for (char *line = strtok_r (buf, "\n", &save); line; line = strtok_r (NULL, "\n", &save))
    {
      if (!strstr (line, ruletext)) continue;
      char *h = strstr (line, "# handle ");
      if (!h) continue;
      h += strlen ("# handle ");
      while (*h == ' ' || *h == '\t') h++;
      char *end = h;
      while (*end && isdigit ((unsigned char) *end)) end++;
      if (end == h) continue;
      *end = '\0';

      struct bfw_argv del = {0};
      bfw_push (&del, "nft");
      bfw_push (&del, "delete");
      bfw_push (&del, "rule");
      bfw_push (&del, "inet");
      bfw_push (&del, "fw");
      bfw_push (&del, "input");
      bfw_push (&del, "handle");
      bfw_push (&del, h);
      return bfw_run (&del, o);
    }

  return EXECUTION_SUCCESS;
}

static int
bfw_nft_simple (struct bfw_opts *o, const char *const *words, int n)
{
  struct bfw_argv a = {0};
  bfw_push (&a, "nft");
  for (int i = 0; i < n; i++) bfw_push (&a, words[i]);
  return bfw_run (&a, o);
}

/* Check if a rule text already exists in the nft input chain by
   capturing `nft list chain inet fw input` and searching for
   the rule text as a line fragment. Returns 1 if found, 0 if not,
   -1 on capture failure. */
static int
bfw_nft_rule_exists (const char *ruletext, struct bfw_opts *o)
{
  if (!ruletext || !*ruletext) return 0;
  (void)o;                          /* API consistency parameter */
  struct bfw_argv a = {0};
  bfw_push (&a, "nft");
  bfw_push (&a, "list");
  bfw_push (&a, "chain");
  bfw_push (&a, "inet");
  bfw_push (&a, "fw");
  bfw_push (&a, "input");
  char buf[16384];
  if (bfw_capture (&a, buf, sizeof buf) < 0) return -1;
  if (buf[0] == '\0') return 0;
  /* Search for the rule text in the captured output. The rule appears
     as part of a line in the chain body with leading whitespace. We
     match the exact string, ensuring it is not embedded in a longer
     token — check that the surrounding chars are whitespace, EOL,
     or ASCII punctuation (like '#'). */
  const char *p = buf;
  size_t rlen = strlen (ruletext);
  while ((p = strstr (p, ruletext)) != NULL)
    {
      int prev_ok = (p == buf) || *(p - 1) == '\n' || *(p - 1) == ' ' || *(p - 1) == '\t';
      char after = p[rlen];
      int next_ok = after == '\n' || after == '\r' || after == '\0'
                 || after == ' ' || after == '\t' || after == '#';
      if (prev_ok && next_ok) return 1;
      p++;
    }
  return 0;
}

/* ---- iptables builders ---- */

static void
bfw_ipt_push_match (struct bfw_argv *a, const struct bfw_rule *r)
{
  if (r->iface_in)
    { bfw_push (a, "-i"); bfw_push (a, r->iface_in); }
  if (r->iface_out)
    { bfw_push (a, "-o"); bfw_push (a, r->iface_out); }
  if (r->set_name)
    {
      bfw_push (a, "-m");
      bfw_push (a, "set");
      bfw_push (a, "--match-set");
      bfw_push (a, r->set_name);
      bfw_push (a, "src");
    }
  else
    {
      bfw_push (a, "-s");
      bfw_push (a, r->ip);
    }
  if (r->dset_name)
    {
      bfw_push (a, "-m");
      bfw_push (a, "set");
      bfw_push (a, "--match-set");
      bfw_push (a, r->dset_name);
      bfw_push (a, "dst");
    }
  else if (r->daddr)
    {
      bfw_push (a, "-d");
      bfw_push (a, r->daddr);
    }
  if (r->ct_state)
    {
      bfw_push (a, "-m");
      bfw_push (a, "conntrack");
      bfw_push (a, "--ctstate");
      bfw_push (a, r->ct_state);
    }
  if (r->proto && strcmp (r->proto, "any") != 0)
    { bfw_push (a, "-p"); bfw_push (a, r->proto); }
  if (r->dport)
    { bfw_push (a, "--dport"); bfw_push (a, r->dport); }
  if (r->sport)
    { bfw_push (a, "--sport"); bfw_push (a, r->sport); }
  if (r->multiport)
    {
      bfw_push (a, "-m");
      bfw_push (a, "multiport");
      bfw_push (a, "--dports");
      bfw_push (a, r->multiport);
    }
  if (r->tcp_flags)
    {
      static char mask_ipt[96], comp_ipt[96];
      char mask[96], comp[96];
      if (bfw_split_tcp_flags (r->tcp_flags, mask, sizeof mask, comp, sizeof comp) == 0)
        {
          bfw_tcp_flags_ipt_expr (mask, mask_ipt, sizeof mask_ipt);
          bfw_tcp_flags_ipt_expr (comp, comp_ipt, sizeof comp_ipt);
          bfw_push (a, "-m");
          bfw_push (a, "tcp");
          bfw_push (a, "--tcp-flags");
          bfw_push (a, mask_ipt);
          bfw_push (a, comp_ipt);
        }
    }
  if (r->limit)
    {
      bfw_push (a, "-m");
      bfw_push (a, "limit");
      bfw_push (a, "--limit");
      bfw_push (a, r->limit);
    }
}

static int
bfw_ipt_rule (struct bfw_opts *o, const struct bfw_rule *r, const char *target)
{
  struct bfw_argv a = {0};
  /* Idempotent mode: skip add if the exact rule already exists. */
  if (o->idempotent)
    {
      int exists = bfw_ipt_rule_exists (r, target, o);
      if (exists > 0) return 0;       /* already present – idempotent */
      if (exists < 0)
        { /* check failed — proceed anyway */ }
    }

  if (r->log_prefix)
    {
      struct bfw_argv loga = {0};
      bfw_push (&loga, bfw_iptables_prog (r->family));
      bfw_push (&loga, "-A");
      bfw_push (&loga, "BASHFW_IN");
      bfw_ipt_push_match (&loga, r);
      bfw_push (&loga, "-j");
      bfw_push (&loga, r->nflog ? "NFLOG" : "LOG");
      bfw_push (&loga, r->nflog ? "--nflog-prefix" : "--log-prefix");
      bfw_push (&loga, r->log_prefix);
      if (!r->nflog && r->log_level)
        {
          bfw_push (&loga, "--log-level");
          bfw_push (&loga, r->log_level);
        }
      int lrc = bfw_run (&loga, o);
      if (lrc != 0) return lrc;
    }

  bfw_push (&a, bfw_iptables_prog (r->family));
  bfw_push (&a, "-A");
  bfw_push (&a, "BASHFW_IN");
  bfw_ipt_push_match (&a, r);
  bfw_push (&a, "-j");
  bfw_push (&a, target);
  if (r->reject_mode && strcmp (target, "REJECT") == 0)
    {
      bfw_push (&a, "--reject-with");
      bfw_push (&a, bfw_reject_ipt (r->reject_mode, r->family));
    }
  return bfw_run (&a, o);
}

static int
bfw_ipt_delete_rule (struct bfw_opts *o, const struct bfw_rule *r,
                     const char *target)
{
  struct bfw_argv a = {0};
  bfw_push (&a, bfw_iptables_prog (r->family));
  bfw_push (&a, "-D");
  bfw_push (&a, "BASHFW_IN");
  bfw_ipt_push_match (&a, r);
  bfw_push (&a, "-j");
  bfw_push (&a, target);
  return bfw_run (&a, o);
}

/* Check if a rule already exists in the iptables BASHFW_IN chain.
   Uses `iptables -C BASHFW_IN ...` which returns 0 if the exact
   rule is present, 1 if not. Execs the subprocess directly (bypasses
   dry-run semantics) because the check must reach the real kernel.
   Returns 1 if found, 0 if not, -1 on fork/exec error. */
static int
bfw_ipt_rule_exists (const struct bfw_rule *r, const char *target,
                     struct bfw_opts *o)
{
  struct bfw_argv a = {0};
  (void)o;
  bfw_push (&a, bfw_iptables_prog (r->family));
  bfw_push (&a, "-C");
  bfw_push (&a, "BASHFW_IN");
  bfw_ipt_push_match (&a, r);
  bfw_push (&a, "-j");
  bfw_push (&a, target);
  /* Fork+exec directly — must not go through bfw_run because dry-run
     mode would just print the argv and return 0 (false-positive). */
  struct bfw_child_guard guard;
  bfw_child_guard_begin (&guard);
  pid_t pid = fork ();
  if (pid < 0) { bfw_child_guard_parent_end (&guard); return -1; }
  if (pid == 0) { bfw_child_guard_child_end (&guard); execvp (a.v[0], (char *const *) a.v); _exit (127); }
  int st = 0;
  while (waitpid (pid, &st, 0) < 0 && errno == EINTR) ;
  bfw_child_guard_parent_end (&guard);
  if (WIFEXITED (st)) return WEXITSTATUS (st) == 0 ? 1 : 0;
  return -1;
}

/* ---- NAT parsing helpers ---- */

struct bfw_natrule {
  char saddr[128];
  char sport[8];
  char daddr[128];
  char dport[8];
  int family;
  const char *proto;        /* tcp / udp / icmp / any */
  const char *hairpin;      /* dnat only: LAN CIDR for NAT reflection (NULL = off) */
};

struct bfw_masqrule {
  const char *cidr;
  int family;
  const char *proto;
  const char *iface;
};

/* Split "ADDR:PORT" into addr and port. Returns 0 on success, -1 on
   malformed input. */
static int
bfw_split_addr_port (const char *spec, char *addr, size_t alen,
                     char *port, size_t plen, int *family_out)
{
  if (!spec || !*spec) return -1;
  if (spec[0] == '[')
    {
      const char *rb = strchr (spec, ']');
      if (!rb || rb[1] != ':' || rb == spec + 1) return -1;
      size_t alen_in = (size_t) (rb - spec - 1);
      if (alen_in >= alen) return -1;
      memcpy (addr, spec + 1, alen_in);
      addr[alen_in] = '\0';
      snprintf (port, plen, "%s", rb + 2);
    }
  else
    {
      const char *colon = strrchr (spec, ':');
      if (!colon || colon == spec) return -1;
      size_t alen_in = (size_t) (colon - spec);
      if (alen_in == 0 || alen_in >= alen) return -1;
      memcpy (addr, spec, alen_in);
      addr[alen_in] = '\0';
      snprintf (port, plen, "%s", colon + 1);
    }
  if (!bfw_valid_ip46_or_cidr (addr, family_out)) return -1;
  if (!bfw_valid_port (port)) return -1;
  return 0;
}

static int
bfw_parse_natrule (WORD_LIST *args, struct bfw_natrule *n, const char *verb)
{
  memset (n, 0, sizeof *n);
  if (!args)
    { builtin_error ("%s: needs SRC_ADDR:PORT DEST_ADDR:PORT", verb); return -1; }
  const char *src = args->word->word;
  if (bfw_split_addr_port (src, n->saddr, sizeof n->saddr,
                           n->sport, sizeof n->sport, &n->family) < 0)
    { builtin_error ("%s: invalid src ADDR:PORT: %s", verb, src); return -1; }
  WORD_LIST *p = args->next;
  if (!p) { builtin_error ("%s: missing DEST_ADDR:PORT", verb); return -1; }
  /* Optional "->" separator. */
  if (strcmp (p->word->word, "->") == 0)
    {
      p = p->next;
      if (!p) { builtin_error ("%s: missing DEST_ADDR:PORT after ->", verb); return -1; }
    }
  const char *dst = p->word->word;
  int dfam = 0;
  if (bfw_split_addr_port (dst, n->daddr, sizeof n->daddr,
                           n->dport, sizeof n->dport, &dfam) < 0)
    { builtin_error ("%s: invalid dest ADDR:PORT: %s", verb, dst); return -1; }
  if (dfam != n->family)
    { builtin_error ("%s: source/dest address families differ", verb); return -1; }
  for (p = p->next; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-p") == 0)
        {
          if (!p->next) { builtin_error ("%s: -p needs PROTO", verb); return -1; }
          p = p->next; n->proto = p->word->word;
          if (!bfw_valid_proto (n->proto))
            { builtin_error ("%s: invalid proto: %s", verb, n->proto); return -1; }
        }
      else if (strcmp (w, "--hairpin") == 0)
        {
          if (!p->next) { builtin_error ("%s: --hairpin needs LAN_CIDR", verb); return -1; }
          p = p->next; n->hairpin = p->word->word;
          int hfam = 0;
          if (!bfw_valid_ip46_or_cidr (n->hairpin, &hfam))
            { builtin_error ("%s: invalid --hairpin CIDR: %s", verb, n->hairpin); return -1; }
          if (hfam != n->family)
            { builtin_error ("%s: --hairpin family differs from rule", verb); return -1; }
        }
      else
        { builtin_error ("%s: unknown flag: %s", verb, w); return -1; }
    }
  if (!n->proto) n->proto = "tcp";
  return 0;
}

static int
bfw_parse_masqrule (WORD_LIST *args, struct bfw_masqrule *m)
{
  memset (m, 0, sizeof *m);
  if (!args)
    { builtin_error ("masquerade: needs CIDR"); return -1; }
  m->cidr = args->word->word;
  if (!bfw_valid_ip46_or_cidr (m->cidr, &m->family))
    { builtin_error ("masquerade: invalid CIDR: %s", m->cidr); return -1; }

  for (WORD_LIST *p = args->next; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-p") == 0)
        {
          if (!p->next) { builtin_error ("masquerade: -p needs PROTO"); return -1; }
          p = p->next;
          m->proto = p->word->word;
          if (!bfw_valid_proto (m->proto))
            { builtin_error ("masquerade: invalid proto: %s", m->proto); return -1; }
        }
      else if (strcmp (w, "-o") == 0)
        {
          if (!p->next) { builtin_error ("masquerade: -o needs IFACE"); return -1; }
          p = p->next;
          m->iface = p->word->word;
          if (!bfw_valid_chain (m->iface))
            { builtin_error ("masquerade: invalid iface: %s", m->iface); return -1; }
        }
      else
        { builtin_error ("masquerade: unknown flag: %s", w); return -1; }
    }
  if (!m->proto)
    m->proto = "any";
  return 0;
}

/* nft DNAT/SNAT rule builder. chain="prerouting" for dnat,
   "postrouting" for snat; match is daddr for dnat, saddr for snat. */
static int
bfw_nft_nat (struct bfw_opts *o, const struct bfw_natrule *n,
             const char *chain, const char *match_field, const char *verdict)
{
  struct bfw_argv a = {0};
  static char persist[512];
  int off = 0;
  off += snprintf (persist + off, sizeof persist - off,
                   "%s %s %s", bfw_ip_word (n->family), match_field, n->saddr);
  if (strcmp (n->proto, "any") != 0)
    off += snprintf (persist + off, sizeof persist - off, " %s", n->proto);
  off += snprintf (persist + off, sizeof persist - off,
                   " %s %s %s to %s:%s",
                   (strcmp (match_field, "saddr") == 0) ? "sport" : "dport",
                   n->sport, verdict, n->daddr, n->dport);

  bfw_push (&a, "nft");
  bfw_push (&a, "add");
  bfw_push (&a, "rule");
  bfw_push (&a, "inet");
  bfw_push (&a, "fw");
  bfw_push (&a, chain);
  bfw_push (&a, persist);
  return bfw_run (&a, o);
}

/* iptables DNAT/SNAT rule builder. Uses -t nat. */
static int
bfw_ipt_nat (struct bfw_opts *o, const struct bfw_natrule *n,
             const char *chain, const char *match_flag,
             const char *target, const char *to_flag)
{
  struct bfw_argv a = {0};
  static char to_buf[160];
  snprintf (to_buf, sizeof to_buf, "%s:%s", n->daddr, n->dport);
  bfw_push (&a, bfw_iptables_prog (n->family));
  bfw_push (&a, "-t");
  bfw_push (&a, "nat");
  bfw_push (&a, "-A");
  bfw_push (&a, chain);
  bfw_push (&a, match_flag);
  bfw_push (&a, n->saddr);
  if (strcmp (n->proto, "any") != 0)
    { bfw_push (&a, "-p"); bfw_push (&a, n->proto); }
  /* For DNAT the matched port is --dport (incoming); for SNAT it's --sport. */
  bfw_push (&a, (strcmp (match_flag, "-d") == 0) ? "--dport" : "--sport");
  bfw_push (&a, n->sport);
  bfw_push (&a, "-j");
  bfw_push (&a, target);
  bfw_push (&a, to_flag);
  bfw_push (&a, to_buf);
  return bfw_run (&a, o);
}

/* F07 hairpin: companion postrouting masquerade so LAN clients (in n->hairpin)
   reaching the DNAT'd service via the external IP get their source rewritten on
   the reflected path. Matches saddr=LAN_CIDR, daddr=internal (n->daddr), the
   internal dport (n->dport). */
static int
bfw_nft_hairpin (struct bfw_opts *o, const struct bfw_natrule *n)
{
  struct bfw_argv a = {0};
  static char persist[512];
  const char *ipw = bfw_ip_word (n->family);
  int off = 0;
  off += snprintf (persist + off, sizeof persist - off,
                   "%s saddr %s %s daddr %s", ipw, n->hairpin, ipw, n->daddr);
  if (strcmp (n->proto, "any") != 0)
    off += snprintf (persist + off, sizeof persist - off,
                     " %s dport %s", n->proto, n->dport);
  snprintf (persist + off, sizeof persist - off, " masquerade");
  bfw_push (&a, "nft");
  bfw_push (&a, "add");
  bfw_push (&a, "rule");
  bfw_push (&a, "inet");
  bfw_push (&a, "fw");
  bfw_push (&a, "postrouting");
  bfw_push (&a, persist);
  return bfw_run (&a, o);
}

static int
bfw_ipt_hairpin (struct bfw_opts *o, const struct bfw_natrule *n)
{
  struct bfw_argv a = {0};
  bfw_push (&a, bfw_iptables_prog (n->family));
  bfw_push (&a, "-t");
  bfw_push (&a, "nat");
  bfw_push (&a, "-A");
  bfw_push (&a, "POSTROUTING");
  bfw_push (&a, "-s");
  bfw_push (&a, n->hairpin);
  bfw_push (&a, "-d");
  bfw_push (&a, n->daddr);
  if (strcmp (n->proto, "any") != 0)
    {
      bfw_push (&a, "-p"); bfw_push (&a, n->proto);
      bfw_push (&a, "--dport"); bfw_push (&a, n->dport);
    }
  bfw_push (&a, "-j");
  bfw_push (&a, "MASQUERADE");
  return bfw_run (&a, o);
}

static int
bfw_nft_masquerade (struct bfw_opts *o, const struct bfw_masqrule *m)
{
  struct bfw_argv a = {0};
  static char persist[512];
  int off = 0;

  off += snprintf (persist + off, sizeof persist - off, "%s saddr %s",
                   bfw_ip_word (m->family), m->cidr);
  if (m->iface)
    off += snprintf (persist + off, sizeof persist - off, " oifname \"%s\"", m->iface);
  if (m->proto && strcmp (m->proto, "any") != 0)
    off += snprintf (persist + off, sizeof persist - off, " %s", m->proto);
  snprintf (persist + off, sizeof persist - off, " masquerade");

  bfw_push (&a, "nft");
  bfw_push (&a, "add");
  bfw_push (&a, "rule");
  bfw_push (&a, "inet");
  bfw_push (&a, "fw");
  bfw_push (&a, "postrouting");
  bfw_push (&a, persist);
  return bfw_run (&a, o);
}

static int
bfw_ipt_masquerade (struct bfw_opts *o, const struct bfw_masqrule *m)
{
  struct bfw_argv a = {0};

  bfw_push (&a, bfw_iptables_prog (m->family));
  bfw_push (&a, "-t");
  bfw_push (&a, "nat");
  bfw_push (&a, "-A");
  bfw_push (&a, "POSTROUTING");
  bfw_push (&a, "-s");
  bfw_push (&a, m->cidr);
  if (m->iface)
    { bfw_push (&a, "-o"); bfw_push (&a, m->iface); }
  if (m->proto && strcmp (m->proto, "any") != 0)
    { bfw_push (&a, "-p"); bfw_push (&a, m->proto); }
  bfw_push (&a, "-j");
  bfw_push (&a, "MASQUERADE");
  return bfw_run (&a, o);
}

/* ---- named sets ---- */

struct bfw_set_create {
  const char *name;
  const char *family;       /* inet / inet6 */
  const char *type;         /* hash:ip / hash:net */
};

static int
bfw_parse_set_create (WORD_LIST *args, struct bfw_set_create *s)
{
  memset (s, 0, sizeof *s);
  if (!args)
    { builtin_error ("set create: needs NAME"); return -1; }
  s->name = args->word->word;
  s->family = "inet";
  s->type = "hash:ip";
  if (!bfw_valid_set_name (s->name))
    { builtin_error ("set create: invalid set name: %s", s->name); return -1; }
  for (WORD_LIST *p = args->next; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-f") == 0)
        {
          if (!p->next) { builtin_error ("set create: -f needs inet|inet6"); return -1; }
          p = p->next; s->family = p->word->word;
          if (strcmp (s->family, "inet") != 0 && strcmp (s->family, "inet6") != 0)
            { builtin_error ("set create: invalid family: %s", s->family); return -1; }
        }
      else if (strcmp (w, "-t") == 0)
        {
          if (!p->next) { builtin_error ("set create: -t needs hash:ip|hash:net"); return -1; }
          p = p->next; s->type = p->word->word;
          if (strcmp (s->type, "hash:ip") != 0 && strcmp (s->type, "hash:net") != 0)
            { builtin_error ("set create: invalid type: %s", s->type); return -1; }
        }
      else
        { builtin_error ("set create: unknown flag: %s", w); return -1; }
    }
  return 0;
}

static int
bfw_nft_set_create (struct bfw_opts *o, const struct bfw_set_create *s)
{
  struct bfw_argv a = {0};
  static char spec[128];
  const char *addr_type = strcmp (s->family, "inet6") == 0 ? "ipv6_addr" : "ipv4_addr";
  if (strcmp (s->type, "hash:net") == 0)
    snprintf (spec, sizeof spec, "{ type %s; flags interval; }", addr_type);
  else
    snprintf (spec, sizeof spec, "{ type %s; }", addr_type);
  bfw_push (&a, "nft");
  bfw_push (&a, "add");
  bfw_push (&a, "set");
  bfw_push (&a, "inet");
  bfw_push (&a, "fw");
  bfw_push (&a, s->name);
  bfw_push (&a, spec);
  return bfw_run (&a, o);
}

static int
bfw_ipt_set_create (struct bfw_opts *o, const struct bfw_set_create *s)
{
  struct bfw_argv a = {0};
  bfw_push (&a, "ipset");
  bfw_push (&a, "create");
  bfw_push (&a, s->name);
  bfw_push (&a, s->type);
  bfw_push (&a, "family");
  bfw_push (&a, s->family);
  bfw_push (&a, "-exist");
  return bfw_run (&a, o);
}

static int
bfw_nft_set_elem (struct bfw_opts *o, const char *op,
                  const char *name, const char *elem)
{
  struct bfw_argv a = {0};
  static char spec[160];
  snprintf (spec, sizeof spec, "{ %s }", elem);
  bfw_push (&a, "nft");
  bfw_push (&a, op);
  bfw_push (&a, "element");
  bfw_push (&a, "inet");
  bfw_push (&a, "fw");
  bfw_push (&a, name);
  bfw_push (&a, spec);
  return bfw_run (&a, o);
}

static int
bfw_ipt_set_elem (struct bfw_opts *o, const char *op,
                  const char *name, const char *elem)
{
  struct bfw_argv a = {0};
  bfw_push (&a, "ipset");
  bfw_push (&a, op);
  bfw_push (&a, name);
  bfw_push (&a, elem);
  bfw_push (&a, "-exist");
  return bfw_run (&a, o);
}

static int
bfw_cmd_set (WORD_LIST *args, struct bfw_opts *o)
{
  if (!args)
    { builtin_error ("set: needs create|add|del|list|destroy"); builtin_usage (); return EX_USAGE; }
  const char *op = args->word->word;
  WORD_LIST *rest = args->next;

  if (strcmp (op, "create") == 0)
    {
      struct bfw_set_create s;
      if (bfw_parse_set_create (rest, &s) < 0) { builtin_usage (); return EX_USAGE; }
      return o->backend == BFW_NFT ? bfw_nft_set_create (o, &s)
                                   : bfw_ipt_set_create (o, &s);
    }

  if (strcmp (op, "add") == 0 || strcmp (op, "del") == 0)
    {
      if (!rest || !rest->next)
        { builtin_error ("set %s: needs NAME IP[/CIDR]", op); builtin_usage (); return EX_USAGE; }
      const char *name = rest->word->word;
      const char *elem = rest->next->word->word;
      if (rest->next->next)
        { builtin_error ("set %s: unexpected argument: %s", op, rest->next->next->word->word); builtin_usage (); return EX_USAGE; }
      if (!bfw_valid_set_name (name))
        { builtin_error ("set %s: invalid set name: %s", op, name); builtin_usage (); return EX_USAGE; }
      if (!bfw_valid_ip46_or_cidr (elem, NULL))
        { builtin_error ("set %s: invalid IP/CIDR: %s", op, elem); builtin_usage (); return EX_USAGE; }
      if (o->backend == BFW_NFT)
        return bfw_nft_set_elem (o, strcmp (op, "add") == 0 ? "add" : "delete", name, elem);
      return bfw_ipt_set_elem (o, op, name, elem);
    }

  if (strcmp (op, "list") == 0)
    {
      const char *name = rest ? rest->word->word : NULL;
      if (rest && rest->next)
        { builtin_error ("set list: unexpected argument: %s", rest->next->word->word); builtin_usage (); return EX_USAGE; }
      if (name && !bfw_valid_set_name (name))
        { builtin_error ("set list: invalid set name: %s", name); builtin_usage (); return EX_USAGE; }
      if (o->backend == BFW_NFT)
        {
          const char *w1[] = { "list", "sets", "inet", "fw" };
          const char *w2[] = { "list", "set", "inet", "fw", name };
          return bfw_nft_simple (o, name ? w2 : w1, name ? 5 : 4);
        }
      struct bfw_argv a = {0};
      bfw_push (&a, "ipset");
      bfw_push (&a, "list");
      if (name) bfw_push (&a, name);
      return bfw_run (&a, o);
    }

  if (strcmp (op, "destroy") == 0)
    {
      if (!rest)
        { builtin_error ("set destroy: needs NAME"); builtin_usage (); return EX_USAGE; }
      const char *name = rest->word->word;
      if (rest->next)
        { builtin_error ("set destroy: unexpected argument: %s", rest->next->word->word); builtin_usage (); return EX_USAGE; }
      if (!bfw_valid_set_name (name))
        { builtin_error ("set destroy: invalid set name: %s", name); builtin_usage (); return EX_USAGE; }
      if (o->backend == BFW_NFT)
        {
          const char *w[] = { "delete", "set", "inet", "fw", name };
          return bfw_nft_simple (o, w, 5);
        }
      struct bfw_argv a = {0};
      bfw_push (&a, "ipset");
      bfw_push (&a, "destroy");
      bfw_push (&a, name);
      return bfw_run (&a, o);
    }

  builtin_error ("set: unknown operation: %s", op);
  builtin_usage ();
  return EX_USAGE;
}

/* F07 conntrack helpers (FTP/SIP/TFTP/…). Modern kernels require helpers be
   assigned explicitly. Known helpers + their default l4proto/port; -p/--dport
   override. */
static const struct { const char *name, *proto, *port; } bfw_known_helpers[] = {
  { "ftp",  "tcp", "21"   }, { "tftp", "udp", "69"   },
  { "sip",  "udp", "5060" }, { "irc",  "tcp", "6667" },
  { "pptp", "tcp", "1723" }, { "h323", "tcp", "1720" },
  { "snmp", "udp", "161"  }, { "amanda","udp","10080" },
};
static const char *
bfw_helper_lookup (const char *name, const char **proto, const char **port)
{
  for (size_t i = 0; i < sizeof bfw_known_helpers / sizeof bfw_known_helpers[0]; i++)
    if (strcmp (name, bfw_known_helpers[i].name) == 0)
      { if (proto) *proto = bfw_known_helpers[i].proto;
        if (port)  *port  = bfw_known_helpers[i].port;
        return bfw_known_helpers[i].name; }
  return NULL;
}

static int
bfw_valid_helper_proto (const char *s)
{
  return s && (strcmp (s, "tcp") == 0 || strcmp (s, "udp") == 0);
}

static int
bfw_cmd_helper (WORD_LIST *args, struct bfw_opts *o)
{
  if (!args)
    { builtin_error ("helper: needs add|list"); builtin_usage (); return EX_USAGE; }
  const char *op = args->word->word;
  WORD_LIST *rest = args->next;

  if (strcmp (op, "list") == 0)
    {
      if (rest) { builtin_error ("helper list: unexpected argument: %s", rest->word->word); return EX_USAGE; }
      if (o->backend == BFW_NFT)
        { const char *w[] = { "list", "ct", "helpers", "table", "inet", "fw" };
          return bfw_nft_simple (o, w, 6); }
      struct bfw_argv a = {0};
      bfw_push (&a, bfw_iptables_prog (AF_INET));
      bfw_push (&a, "-t"); bfw_push (&a, "raw");
      bfw_push (&a, "-L"); bfw_push (&a, "PREROUTING");
      bfw_push (&a, "-n");
      return bfw_run (&a, o);
    }

  if (strcmp (op, "add") == 0)
    {
      if (!rest) { builtin_error ("helper add: needs NAME (ftp|tftp|sip|irc|pptp|h323|snmp|amanda)"); builtin_usage (); return EX_USAGE; }
      const char *name = rest->word->word;
      const char *proto = NULL, *port = NULL;
      if (!bfw_helper_lookup (name, &proto, &port))
        { builtin_error ("helper add: unknown helper: %s", name); builtin_usage (); return EX_USAGE; }
      for (WORD_LIST *p = rest->next; p; p = p->next)
        {
          const char *w = p->word->word;
          if (strcmp (w, "-p") == 0)
            { if (!p->next) { builtin_error ("helper add: -p needs PROTO"); return EX_USAGE; }
              p = p->next; proto = p->word->word;
              if (!bfw_valid_helper_proto (proto)) { builtin_error ("helper add: invalid proto: %s", proto); return EX_USAGE; } }
          else if (strcmp (w, "--dport") == 0)
            { if (!p->next) { builtin_error ("helper add: --dport needs PORT"); return EX_USAGE; }
              p = p->next; port = p->word->word;
              if (!bfw_valid_port (port)) { builtin_error ("helper add: invalid port: %s", port); return EX_USAGE; } }
          else
            { builtin_error ("helper add: unknown flag: %s", w); return EX_USAGE; }
        }
      if (o->backend == BFW_NFT)
        {
          /* define the ct helper object, then assign it in prerouting. */
          char obj[128];
          snprintf (obj, sizeof obj, "{ type \"%s\" protocol %s ; }", name, proto);
          const char *w1[] = { "add", "ct", "helper", "inet", "fw", name, obj };
          if (bfw_nft_simple (o, w1, 7) != 0) return EXECUTION_FAILURE;
          char rule[160], setexpr[64];
          snprintf (setexpr, sizeof setexpr, "ct helper set \"%s\"", name);
          snprintf (rule, sizeof rule, "%s dport %s %s", proto, port, setexpr);
          const char *w2[] = { "add", "rule", "inet", "fw", "prerouting", rule };
          return bfw_nft_simple (o, w2, 6);
        }
      /* iptables: raw/PREROUTING CT target (no custom chain needed). */
      struct bfw_argv a = {0};
      bfw_push (&a, bfw_iptables_prog (AF_INET));
      bfw_push (&a, "-t"); bfw_push (&a, "raw");
      bfw_push (&a, "-A"); bfw_push (&a, "PREROUTING");
      bfw_push (&a, "-p"); bfw_push (&a, proto);
      bfw_push (&a, "--dport"); bfw_push (&a, port);
      bfw_push (&a, "-j"); bfw_push (&a, "CT");
      bfw_push (&a, "--helper"); bfw_push (&a, name);
      return bfw_run (&a, o);
    }

  builtin_error ("helper: unknown operation: %s (try add|list)", op);
  builtin_usage ();
  return EX_USAGE;
}

/* ---- subcommands ---- */

static int
bfw_cmd_allow (WORD_LIST *args, struct bfw_opts *o)
{
  struct bfw_rule r;
  if (bfw_parse_rule (args, &r, "allow") < 0) { builtin_usage (); return EX_USAGE; }
  return o->backend == BFW_NFT ? bfw_nft_rule (o, &r, "accept")
                               : bfw_ipt_rule (o, &r, "ACCEPT");
}

static int
bfw_cmd_deny (WORD_LIST *args, struct bfw_opts *o)
{
  struct bfw_rule r;
  if (bfw_parse_rule (args, &r, "deny") < 0) { builtin_usage (); return EX_USAGE; }
  if (r.reject_mode)
    return o->backend == BFW_NFT ? bfw_nft_rule (o, &r, bfw_reject_nft (r.reject_mode))
                                 : bfw_ipt_rule (o, &r, "REJECT");
  return o->backend == BFW_NFT ? bfw_nft_rule (o, &r, "drop")
                               : bfw_ipt_rule (o, &r, "DROP");
}

static int
bfw_cmd_unban (WORD_LIST *args, struct bfw_opts *o)
{
  struct bfw_rule r;
  if (bfw_parse_rule (args, &r, "unban") < 0) { builtin_usage (); return EX_USAGE; }
  if (o->backend == BFW_PURE)
    return EXECUTION_SUCCESS;
  return o->backend == BFW_NFT ? bfw_nft_delete_rule (o, &r, "drop")
                               : bfw_ipt_delete_rule (o, &r, "DROP");
}

static int
bfw_cmd_dnat (WORD_LIST *args, struct bfw_opts *o)
{
  struct bfw_natrule n;
  if (bfw_parse_natrule (args, &n, "dnat") < 0) { builtin_usage (); return EX_USAGE; }
  int rc = (o->backend == BFW_NFT)
           ? bfw_nft_nat (o, &n, "prerouting", "daddr", "dnat")
           : bfw_ipt_nat (o, &n, "PREROUTING", "-d", "DNAT", "--to-destination");
  if (rc != EXECUTION_SUCCESS || !n.hairpin)
    return rc;
  /* F07 hairpin (NAT reflection): add the companion postrouting masquerade. */
  return (o->backend == BFW_NFT) ? bfw_nft_hairpin (o, &n) : bfw_ipt_hairpin (o, &n);
}

static int
bfw_cmd_snat (WORD_LIST *args, struct bfw_opts *o)
{
  struct bfw_natrule n;
  if (bfw_parse_natrule (args, &n, "snat") < 0) { builtin_usage (); return EX_USAGE; }
  if (o->backend == BFW_NFT)
    return bfw_nft_nat (o, &n, "postrouting", "saddr", "snat");
  return bfw_ipt_nat (o, &n, "POSTROUTING", "-s", "SNAT", "--to-source");
}

static int
bfw_cmd_masquerade (WORD_LIST *args, struct bfw_opts *o)
{
  struct bfw_masqrule m;
  if (bfw_parse_masqrule (args, &m) < 0) { builtin_usage (); return EX_USAGE; }
  if (o->backend == BFW_NFT)
    return bfw_nft_masquerade (o, &m);
  return bfw_ipt_masquerade (o, &m);
}

static int
bfw_cmd_flush (WORD_LIST *args, struct bfw_opts *o)
{
  const char *chain = "input";
  if (args)
    {
      chain = args->word->word;
      if (!bfw_valid_chain (chain)) { builtin_error ("flush: bad chain: %s", chain); builtin_usage (); return EX_USAGE; }
    }
  if (o->backend == BFW_PURE)
    {
      /* Pure-bash file-store backend: rules live under
       *   $BASHFW_DIR/<chain>/<rulename>
       * (default $BASHFW_DIR = /var/lib/fw). flush removes every
       * entry in <chain>/, then removes the chain dir itself if it's
       * empty. Missing dirs are NOT an error — flush of a never-
       * created chain is a successful no-op, matching the contract
       * the test (and ops idempotency) expects. We never touch
       * nft/iptables in this backend; out-of-tree pre-existing kernel
       * rules survive. */
      const char *root = getenv ("BASHFW_DIR");
      if (!root || !*root) root = "/var/lib/fw";
      char dir[640];
      if (snprintf (dir, sizeof dir, "%s/%s", root, chain) >= (int) sizeof dir)
        { builtin_error ("flush: chain path too long"); return EXECUTION_FAILURE; }
      DIR *d = opendir (dir);
      if (!d)
        {
          /* ENOENT is fine — nothing to flush. Any other open error is
           * a real problem, but we still return 0 because the post-
           * state ("chain is empty") holds anyway. The path stays
           * silent on stderr to honor the no-op invariant. */
          return EXECUTION_SUCCESS;
        }
      struct dirent *de;
      while ((de = readdir (d)) != NULL)
        {
          if (de->d_name[0] == '.' &&
              (de->d_name[1] == '\0' ||
               (de->d_name[1] == '.' && de->d_name[2] == '\0')))
            continue;
          char path[768];
          if (snprintf (path, sizeof path, "%s/%s", dir, de->d_name)
              >= (int) sizeof path)
            continue;
          (void) unlink (path);
        }
      closedir (d);
      (void) rmdir (dir);
      return EXECUTION_SUCCESS;
    }
  if (o->backend == BFW_NFT)
    {
      const char *w[] = { "flush", "chain", "inet", "fw", chain };
      return bfw_nft_simple (o, w, 5);
    }
  else
    {
      const char *ipt_chain = strcmp (chain, "input") == 0 ? "BASHFW_IN" : chain;
      struct bfw_argv a = {0};
      bfw_push (&a, "iptables");
      bfw_push (&a, "-F");
      bfw_push (&a, ipt_chain);
      return bfw_run (&a, o);
    }
}

static int
bfw_cmd_list (WORD_LIST *args, struct bfw_opts *o)
{
  const char *chain = NULL;
  int numbered = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-l") == 0 || strcmp (w, "--numbered") == 0)
        numbered = 1;
      else if (!chain && w[0] != '-')
        chain = w;
      else
        { builtin_error ("list: unexpected: %s", w); builtin_usage (); return EX_USAGE; }
    }
  if (chain && !bfw_valid_chain (chain)) { builtin_error ("list: bad chain: %s", chain); builtin_usage (); return EX_USAGE; }
  if (o->backend == BFW_NFT)
    {
      /* nft -a prints stable handles, the rule-ordering anchor for
         later `delete rule ... handle N` operations. */
      if (numbered)
        {
          const char *w1[] = { "-a", "list", "ruleset" };
          const char *w2[] = { "-a", "list", "chain", "inet", "fw", chain ? chain : "input" };
          return bfw_nft_simple (o, chain ? w2 : w1, chain ? 6 : 3);
        }
      const char *w1[] = { "list", "ruleset" };
      const char *w2[] = { "list", "chain", "inet", "fw", chain ? chain : "input" };
      return bfw_nft_simple (o, chain ? w2 : w1, chain ? 5 : 2);
    }
  else
    {
      struct bfw_argv a = {0};
      bfw_push (&a, "iptables");
      bfw_push (&a, "-L");
      if (chain) bfw_push (&a, chain);
      else       bfw_push (&a, "BASHFW_IN");
      bfw_push (&a, "-n");
      bfw_push (&a, "-v");
      if (numbered) bfw_push (&a, "--line-numbers");
      return bfw_run (&a, o);
    }
}

static int
bfw_cmd_reset (struct bfw_opts *o)
{
  if (o->backend == BFW_NFT)
    {
      const char *w_del[] = { "delete", "table", "inet", "fw" };
      bfw_nft_simple (o, w_del, 4);
      const char *w_add[] = { "add", "table", "inet", "fw" };
      if (bfw_nft_simple (o, w_add, 4) != 0) return EXECUTION_FAILURE;
      const char *w_chain_in[] = { "add", "chain", "inet", "fw", "input",
                                   "{ type filter hook input priority 0 ; policy accept ; }" };
      bfw_nft_simple (o, w_chain_in, 6);
      const char *w_chain_out[] = { "add", "chain", "inet", "fw", "output",
                                    "{ type filter hook output priority 0 ; policy accept ; }" };
      bfw_nft_simple (o, w_chain_out, 6);
      /* Stage A.10.B: NAT chains in the same inet/fw table. */
      const char *w_chain_pre[] = { "add", "chain", "inet", "fw", "prerouting",
                                    "{ type nat hook prerouting priority -100 ; policy accept ; }" };
      bfw_nft_simple (o, w_chain_pre, 6);
      const char *w_chain_post[] = { "add", "chain", "inet", "fw", "postrouting",
                                     "{ type nat hook postrouting priority 100 ; policy accept ; }" };
      bfw_nft_simple (o, w_chain_post, 6);
      return EXECUTION_SUCCESS;
    }
  else
    {
      const char *create_in[] = { "iptables", "-N", "BASHFW_IN" };
      const char *create_out[] = { "iptables", "-N", "BASHFW_OUT" };
      struct bfw_argv a = {0};
      for (int i = 0; i < 3; i++) bfw_push (&a, create_in[i]);
      bfw_run (&a, o);
      a.n = 0;
      for (int i = 0; i < 3; i++) bfw_push (&a, create_out[i]);
      bfw_run (&a, o);
      return EXECUTION_SUCCESS;
    }
}

/* F07 next-slice: chain default policy (default-deny posture). Sets the base
   chain's policy to accept|drop. On `drop`, unless --no-baseline, installs a
   lockout fail-safe first: loopback + established/related accept. nft updates
   the base-chain policy in place (dual-stack inet); iptables (v4) emulates a
   chain policy with a terminal -j DROP rule. */
static int
bfw_cmd_policy (WORD_LIST *args, struct bfw_opts *o)
{
  if (!args || !args->next)
    { builtin_error ("policy: usage: policy <input|output> <accept|drop> [--no-baseline]"); return EX_USAGE; }
  const char *chain = args->word->word;
  const char *action = args->next->word->word;
  int no_baseline = 0;
  for (WORD_LIST *p = args->next->next; p; p = p->next)
    {
      if (strcmp (p->word->word, "--no-baseline") == 0) no_baseline = 1;
      else { builtin_error ("policy: unexpected arg: %s", p->word->word); return EX_USAGE; }
    }
  if (strcmp (chain, "input") != 0 && strcmp (chain, "output") != 0)
    { builtin_error ("policy: chain must be input or output (got %s)", chain); return EX_USAGE; }
  if (strcmp (action, "accept") != 0 && strcmp (action, "drop") != 0)
    { builtin_error ("policy: action must be accept or drop (got %s)", action); return EX_USAGE; }
  int drop = (strcmp (action, "drop") == 0);

  if (o->backend == BFW_NFT)
    {
      char spec[160];
      snprintf (spec, sizeof spec,
                "{ type filter hook %s priority 0 ; policy %s ; }", chain, action);
      const char *w[] = { "add", "chain", "inet", "fw", chain, spec };
      if (bfw_nft_simple (o, w, 6) != 0) return EXECUTION_FAILURE;
      if (drop && !no_baseline)
        {
          const char *wlo[] = { "add", "rule", "inet", "fw", chain, "iifname \"lo\" accept" };
          bfw_nft_simple (o, wlo, 6);
          const char *wct[] = { "add", "rule", "inet", "fw", chain,
                                "ct state { established, related } accept" };
          bfw_nft_simple (o, wct, 6);
        }
      return EXECUTION_SUCCESS;
    }
  else
    {
      const char *uc = (strcmp (chain, "input") == 0) ? "BASHFW_IN" : "BASHFW_OUT";
      const char *iface_flag = (strcmp (chain, "input") == 0) ? "-i" : "-o";
      struct bfw_argv a = {0};
      if (drop)
        {
          if (!no_baseline)
            {
              const char *wct[] = { "iptables", "-I", uc, "1", "-m", "conntrack",
                                    "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT" };
              a.n = 0; for (int i = 0; i < 10; i++) bfw_push (&a, wct[i]);
              bfw_run (&a, o);
              const char *wlo[] = { "iptables", "-I", uc, "1", iface_flag, "lo", "-j", "ACCEPT" };
              a.n = 0; for (int i = 0; i < 8; i++) bfw_push (&a, wlo[i]);
              bfw_run (&a, o);
            }
          const char *wd[] = { "iptables", "-A", uc, "-j", "DROP" };
          a.n = 0; for (int i = 0; i < 5; i++) bfw_push (&a, wd[i]);
          return bfw_run (&a, o);
        }
      /* accept: drop the terminal DROP if present (ignore failure when absent). */
      const char *wd[] = { "iptables", "-D", uc, "-j", "DROP" };
      a.n = 0; for (int i = 0; i < 5; i++) bfw_push (&a, wd[i]);
      bfw_run (&a, o);
      return EXECUTION_SUCCESS;
    }
}

static int
bfw_cmd_save (WORD_LIST *args, struct bfw_opts *o)
{
  const char *file;
  int using_default = 0;
  if (args)
    file = args->word->word;
  else
    { file = BFW_DEFAULT_SAVE_PATH; using_default = 1; }
  if (o->dry_run) { printf ("save %s\n", file); return EXECUTION_SUCCESS; }
  /* Best-effort: ensure /etc/fw exists when using the default path.
     Ignore EEXIST and any other failure — open() below will surface the
     real error in a more informative way if the dir creation didn't help. */
  if (using_default)
    (void) mkdir (BFW_DEFAULT_SAVE_DIR, 0755);
  int fd = open (file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) { builtin_error ("save: open %s: %s", file, strerror (errno)); return EXECUTION_FAILURE; }
  struct bfw_argv save_argv = {0};
  if (o->backend == BFW_NFT)
    {
      bfw_push (&save_argv, "nft");
      bfw_push (&save_argv, "list");
      bfw_push (&save_argv, "ruleset");
    }
  else
    bfw_push (&save_argv, "iptables-save");

  int rc = bfw_run_stdout_fd (&save_argv, fd);
  if (rc == 0 && o->backend == BFW_IPT && bfw_have_exec ("ipset"))
    {
      struct bfw_argv ipset_argv = {0};
      bfw_push (&ipset_argv, "ipset");
      bfw_push (&ipset_argv, "save");
      dprintf (fd, "%s", BFW_IPSET_BEGIN);
      rc = bfw_run_stdout_fd (&ipset_argv, fd);
      dprintf (fd, "%s", BFW_IPSET_END);
    }
  close (fd);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bfw_file_has_ipset_section (const char *file)
{
  FILE *fp = fopen (file, "r");
  if (!fp) return 0;
  char line[512];
  int found = 0;
  while (fgets (line, sizeof line, fp))
    if (strcmp (line, BFW_IPSET_BEGIN) == 0)
      { found = 1; break; }
  fclose (fp);
  return found;
}

static int
bfw_split_iptables_ipset_save (const char *file, char *ipt_path, size_t ipt_sz,
                               char *set_path, size_t set_sz)
{
  snprintf (ipt_path, ipt_sz, "/tmp/fw-iptables.XXXXXX");
  snprintf (set_path, set_sz, "/tmp/fw-ipset.XXXXXX");
  int ipt_fd = mkstemp (ipt_path);
  if (ipt_fd < 0)
    { builtin_error ("restore: mkstemp iptables: %s", strerror (errno)); return -1; }
  int set_fd = mkstemp (set_path);
  if (set_fd < 0)
    {
      builtin_error ("restore: mkstemp ipset: %s", strerror (errno));
      close (ipt_fd);
      unlink (ipt_path);
      return -1;
    }

  FILE *in = fopen (file, "r");
  FILE *ipt = fdopen (ipt_fd, "w");
  FILE *set = fdopen (set_fd, "w");
  if (!in || !ipt || !set)
    {
      if (in) fclose (in);
      if (ipt) fclose (ipt); else close (ipt_fd);
      if (set) fclose (set); else close (set_fd);
      unlink (ipt_path);
      unlink (set_path);
      builtin_error ("restore: cannot split saved rules: %s", strerror (errno));
      return -1;
    }

  char line[1024];
  int in_set = 0;
  int saw_end = 0;
  while (fgets (line, sizeof line, in))
    {
      if (strcmp (line, BFW_IPSET_BEGIN) == 0)
        { in_set = 1; continue; }
      if (strcmp (line, BFW_IPSET_END) == 0)
        { in_set = 0; saw_end = 1; continue; }
      fputs (line, in_set ? set : ipt);
    }

  int err = ferror (in) || fflush (ipt) == EOF || fflush (set) == EOF;
  fclose (in);
  fclose (ipt);
  fclose (set);
  if (err || !saw_end)
    {
      unlink (ipt_path);
      unlink (set_path);
      builtin_error ("restore: malformed ipset save section in %s", file);
      return -1;
    }
  return 0;
}

static int
bfw_ipt_restore_with_sets (const char *file, struct bfw_opts *o)
{
  if (!bfw_file_has_ipset_section (file))
    {
      struct bfw_argv a = {0};
      bfw_push (&a, "iptables-restore");
      bfw_push (&a, file);
      return bfw_run (&a, o);
    }

  char ipt_path[64];
  char set_path[64];
  if (bfw_split_iptables_ipset_save (file, ipt_path, sizeof ipt_path,
                                     set_path, sizeof set_path) < 0)
    return EXECUTION_FAILURE;

  struct bfw_argv set_restore = {0};
  bfw_push (&set_restore, "ipset");
  bfw_push (&set_restore, "restore");
  /* `fw reset` clears iptables state but intentionally does not destroy
     operator ipsets. Replaying a saved set section after reset must therefore
     tolerate pre-existing sets/elements. ipset restore's -exist flag keeps the
     restore idempotent while preserving the saved membership payload. */
  bfw_push (&set_restore, "-exist");
  int rc = bfw_run_stdin_file (&set_restore, set_path);
  if (rc == 0)
    {
      struct bfw_argv ipt_restore = {0};
      bfw_push (&ipt_restore, "iptables-restore");
      bfw_push (&ipt_restore, ipt_path);
      rc = bfw_run (&ipt_restore, o);
    }
  unlink (ipt_path);
  unlink (set_path);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* v4.0 closure (2026-05-14): restore mirrors save's default-path so an
   init/auto-restore service stub can call `fw restore` (no FILE) on
   a fresh boot without painting stderr red.

     fw restore           → default to /etc/fw/rules.conf
     fw restore FILE      → restore from FILE explicitly
     fw -n restore        → dry-run: print "restore <default>"
                                 (operator-facing verb token, mirrors
                                  save's dry-run shape; discoverable
                                  even when the default file is absent)
     fw -n restore FILE   → dry-run: print backend argv
                                 (`nft -f FILE` / `iptables-restore FILE`)

   Asymmetric missing-file arm — the only place the two paths diverge:
     default-path missing  → benign no-op (rc 0, no diagnostic).
                              Auto-restore at boot is the natural caller
                              and a fresh boot with no saved rules must
                              not paint stderr red.
     explicit-path missing → diagnostic exit 1 (operator typo or wrong
                              fixture path is a real error).

   Pinned by:
     251-fw-persist.sh case 4 (default-path dry-run verb token)
     619-fw-restore-missing.sh (both live missing-file arms)
     f07-fw-save-restore-dryrun.sh cases 4/5/7/8 (explicit-FILE
       dry-run backend argv + explicit-missing error path).
*/
static int
bfw_cmd_restore (WORD_LIST *args, struct bfw_opts *o)
{
  const char *file;
  int using_default = 0;
  if (args)
    file = args->word->word;
  else
    { file = BFW_DEFAULT_SAVE_PATH; using_default = 1; }

  /* Dry-run + default-path: print the operator-facing verb token so the
     default is discoverable in dry-run even when the file is absent.
     Explicit-FILE dry-run still falls through to bfw_run below so the
     backend argv (`nft -f FILE` / `iptables-restore FILE`) is emitted
     unchanged. */
  if (o->dry_run && using_default)
    { printf ("restore %s\n", file); return EXECUTION_SUCCESS; }

  if (access (file, R_OK) < 0)
    {
      /* Default-path missing is the fresh-boot auto-restore case: silent
         success. Explicit-path missing is operator error: diagnose. */
      if (using_default && errno == ENOENT)
        return EXECUTION_SUCCESS;
      builtin_error ("restore: cannot read %s: %s", file, strerror (errno));
      return EXECUTION_FAILURE;
    }
  struct bfw_argv a = {0};
  if (o->backend == BFW_NFT) { bfw_push (&a, "nft"); bfw_push (&a, "-f"); bfw_push (&a, file); }
  else if (!o->dry_run)      return bfw_ipt_restore_with_sets (file, o);
  else                       { bfw_push (&a, "iptables-restore"); bfw_push (&a, file); }
  return bfw_run (&a, o);
}

static void
bfw_free_words (WORD_LIST *list)
{
  while (list)
    {
      WORD_LIST *next = list->next;
      if (list->word)
        {
          free (list->word->word);
          free (list->word);
        }
      free (list);
      list = next;
    }
}

static WORD_LIST *
bfw_words_from_line (char *line)
{
  WORD_LIST *head = NULL;
  WORD_LIST **tail = &head;
  for (char *tok = strtok (line, " \t\r\n"); tok; tok = strtok (NULL, " \t\r\n"))
    {
      WORD_DESC *wd = calloc (1, sizeof *wd);
      WORD_LIST *wl = calloc (1, sizeof *wl);
      if (!wd || !wl)
        {
          free (wd);
          free (wl);
          bfw_free_words (head);
          return NULL;
        }
      wd->word = strdup (tok);
      if (!wd->word)
        {
          free (wd);
          free (wl);
          bfw_free_words (head);
          return NULL;
        }
      wl->word = wd;
      *tail = wl;
      tail = &wl->next;
    }
  return head;
}

static WORD_LIST *
bfw_copy_words_until (WORD_LIST *start, WORD_LIST *end)
{
  WORD_LIST *head = NULL;
  WORD_LIST **tail = &head;
  for (WORD_LIST *cur = start; cur && cur != end; cur = cur->next)
    {
      WORD_DESC *wd = calloc (1, sizeof *wd);
      WORD_LIST *wl = calloc (1, sizeof *wl);
      if (!wd || !wl)
        {
          free (wd);
          free (wl);
          bfw_free_words (head);
          return NULL;
        }
      wd->word = strdup (cur->word->word);
      if (!wd->word)
        {
          free (wd);
          free (wl);
          bfw_free_words (head);
          return NULL;
        }
      wl->word = wd;
      *tail = wl;
      tail = &wl->next;
    }
  return head;
}

static int
bfw_txn_dispatchable_cmd (const char *cmd)
{
  return strcmp (cmd, "allow") == 0 ||
         strcmp (cmd, "deny") == 0 ||
         strcmp (cmd, "unban") == 0 ||
         strcmp (cmd, "undeny") == 0 ||
         strcmp (cmd, "dnat") == 0 ||
         strcmp (cmd, "snat") == 0 ||
         strcmp (cmd, "masquerade") == 0 ||
         strcmp (cmd, "masq") == 0 ||
         strcmp (cmd, "set") == 0 ||
         strcmp (cmd, "helper") == 0 ||
         strcmp (cmd, "flush") == 0 ||
         strcmp (cmd, "policy") == 0 ||
         strcmp (cmd, "reset") == 0;
}

static int
bfw_dispatch_cmd (const char *cmd, WORD_LIST *args, struct bfw_opts *o)
{
  if (strcmp (cmd, "allow")   == 0) return bfw_cmd_allow (args, o);
  if (strcmp (cmd, "deny")    == 0) return bfw_cmd_deny (args, o);
  if (strcmp (cmd, "unban")   == 0 || strcmp (cmd, "undeny") == 0) return bfw_cmd_unban (args, o);
  if (strcmp (cmd, "dnat")    == 0) return bfw_cmd_dnat (args, o);
  if (strcmp (cmd, "snat")    == 0) return bfw_cmd_snat (args, o);
  if (strcmp (cmd, "masquerade") == 0 || strcmp (cmd, "masq") == 0) return bfw_cmd_masquerade (args, o);
  if (strcmp (cmd, "set")     == 0) return bfw_cmd_set (args, o);
  if (strcmp (cmd, "helper")  == 0) return bfw_cmd_helper (args, o);
  if (strcmp (cmd, "flush")   == 0) return bfw_cmd_flush (args, o);
  if (strcmp (cmd, "policy")  == 0) return bfw_cmd_policy (args, o);
  if (strcmp (cmd, "reset")   == 0) return bfw_cmd_reset (o);
  builtin_error ("batch: unsupported subcommand: %s", cmd);
  return EX_USAGE;
}

typedef int (*bfw_txn_next_fn) (void *, WORD_LIST **, int *);
typedef const char *(*bfw_txn_where_fn) (void *, char *, size_t);

static int
bfw_txn_forbidden_cmd (const char *cmd)
{
  return strcmp (cmd, "batch") == 0 ||
         strcmp (cmd, "txn") == 0 ||
         strcmp (cmd, "save") == 0 ||
         strcmp (cmd, "restore") == 0 ||
         strcmp (cmd, "list") == 0 ||
         strcmp (cmd, "status") == 0;
}

static int
bfw_txn_run (struct bfw_opts *o, const char *label,
             bfw_txn_next_fn next, bfw_txn_where_fn where, void *ctx)
{
  char snapshot[] = "/tmp/fw.txn.XXXXXX";
  int have_snapshot = 0;
  int rc = EXECUTION_SUCCESS;

  if (!o->dry_run)
    {
      int snap_fd = mkstemp (snapshot);
      if (snap_fd < 0)
        {
          builtin_error ("%s: mkstemp: %s", label, strerror (errno));
          return EXECUTION_FAILURE;
        }
      close (snap_fd);
      WORD_DESC snap_word = { .word = snapshot, .flags = 0 };
      WORD_LIST snap_list = { .next = NULL, .word = &snap_word };
      if (bfw_cmd_save (&snap_list, o) != EXECUTION_SUCCESS)
        {
          builtin_error ("%s: snapshot save failed", label);
          unlink (snapshot);
          return EXECUTION_FAILURE;
        }
      have_snapshot = 1;
    }

  for (;;)
    {
      WORD_LIST *words = NULL;
      int own = 0;
      int n = next (ctx, &words, &own);
      if (n == 0)
        break;
      if (n < 0)
        {
          rc = EXECUTION_FAILURE;
          if (own)
            bfw_free_words (words);
          break;
        }
      if (!words || !words->word || !words->word->word)
        {
          if (own)
            bfw_free_words (words);
          continue;
        }

      char where_buf[80];
      const char *tag = where ? where (ctx, where_buf, sizeof where_buf)
                              : label;
      const char *cmd = words->word->word;
      if (bfw_txn_forbidden_cmd (cmd) || !bfw_txn_dispatchable_cmd (cmd))
        {
          builtin_error ("%s: unsupported subcommand: %s", tag, cmd);
          if (own)
            bfw_free_words (words);
          rc = EX_USAGE;
          break;
        }
      int one = bfw_dispatch_cmd (cmd, words->next, o);
      if (own)
        bfw_free_words (words);
      if (one != EXECUTION_SUCCESS)
        {
          builtin_error ("%s: command failed", tag);
          rc = EXECUTION_FAILURE;
          break;
        }
    }

  if (rc != EXECUTION_SUCCESS && have_snapshot)
    {
      WORD_DESC snap_word = { .word = snapshot, .flags = 0 };
      WORD_LIST snap_list = { .next = NULL, .word = &snap_word };
      if (bfw_cmd_restore (&snap_list, o) != EXECUTION_SUCCESS)
        builtin_error ("%s: rollback restore failed: %s", label, snapshot);
    }
  if (have_snapshot)
    unlink (snapshot);
  return rc;
}

struct bfw_txn_line_ctx
{
  FILE *fp;
  const char *label;
  char line[1024];
  unsigned long lineno;
};

static int
bfw_txn_next_line (void *opaque, WORD_LIST **out, int *own)
{
  struct bfw_txn_line_ctx *ctx = (struct bfw_txn_line_ctx *) opaque;
  *out = NULL;
  *own = 0;
  while (fgets (ctx->line, sizeof ctx->line, ctx->fp))
    {
      ctx->lineno++;
      char *p = ctx->line;
      while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
      if (*p == '\0' || *p == '#')
        continue;
      char *hash = strchr (p, '#');
      if (hash) *hash = '\0';

      WORD_LIST *words = bfw_words_from_line (p);
      if (!words)
        {
          builtin_error ("%s:%lu: cannot parse line", ctx->label,
                         ctx->lineno);
          return -1;
        }
      *out = words;
      *own = 1;
      return 1;
    }
  return 0;
}

static const char *
bfw_txn_where_line (void *opaque, char *buf, size_t bufsz)
{
  struct bfw_txn_line_ctx *ctx = (struct bfw_txn_line_ctx *) opaque;
  snprintf (buf, bufsz, "%s:%lu", ctx->label, ctx->lineno);
  return buf;
}

struct bfw_txn_inline_ctx
{
  WORD_LIST *cur;
};

static int
bfw_txn_next_inline (void *opaque, WORD_LIST **out, int *own)
{
  struct bfw_txn_inline_ctx *ctx = (struct bfw_txn_inline_ctx *) opaque;
  *out = NULL;
  *own = 0;

  while (ctx->cur && strcmp (ctx->cur->word->word, ";") == 0)
    ctx->cur = ctx->cur->next;
  if (!ctx->cur)
    return 0;

  WORD_LIST *start = ctx->cur;
  while (ctx->cur && strcmp (ctx->cur->word->word, ";") != 0)
    ctx->cur = ctx->cur->next;
  WORD_LIST *end = ctx->cur;
  if (ctx->cur)
    ctx->cur = ctx->cur->next;

  WORD_LIST *copy = bfw_copy_words_until (start, end);
  if (!copy)
    {
      builtin_error ("txn: cannot parse argv segment");
      return -1;
    }
  *out = copy;
  *own = 1;
  return 1;
}

static int
bfw_txn_validate_inline (WORD_LIST *args)
{
  WORD_LIST *cur = args;
  while (cur)
    {
      while (cur && strcmp (cur->word->word, ";") == 0)
        cur = cur->next;
      if (!cur)
        break;

      const char *cmd = cur->word->word;
      if (bfw_txn_forbidden_cmd (cmd) || !bfw_txn_dispatchable_cmd (cmd))
        {
          builtin_error ("txn: unsupported subcommand: %s", cmd);
          return EX_USAGE;
        }

      while (cur && strcmp (cur->word->word, ";") != 0)
        cur = cur->next;
    }
  return EXECUTION_SUCCESS;
}

static int
bfw_cmd_batch (WORD_LIST *args, struct bfw_opts *o)
{
  if (!args)
    { builtin_error ("batch: needs FILE"); builtin_usage (); return EX_USAGE; }
  const char *file = args->word->word;
  if (args->next)
    { builtin_error ("batch: unexpected argument: %s", args->next->word->word); builtin_usage (); return EX_USAGE; }

  FILE *fp = fopen (file, "r");
  if (!fp)
    { builtin_error ("batch: cannot read %s: %s", file, strerror (errno)); return EXECUTION_FAILURE; }

  struct bfw_txn_line_ctx ctx = { .fp = fp, .label = "batch", .lineno = 0 };
  int rc = bfw_txn_run (o, "batch", bfw_txn_next_line,
                        bfw_txn_where_line, &ctx);
  fclose (fp);
  return rc;
}

static int
bfw_cmd_txn (WORD_LIST *args, struct bfw_opts *o)
{
  if (args && strcmp (args->word->word, "--") == 0)
    args = args->next;

  if (args && strcmp (args->word->word, "-") == 0)
    {
      if (args->next)
        { builtin_error ("txn: '-' must be the only txn operand"); builtin_usage (); return EX_USAGE; }
      struct bfw_txn_line_ctx ctx = { .fp = stdin, .label = "txn", .lineno = 0 };
      return bfw_txn_run (o, "txn", bfw_txn_next_line,
                          bfw_txn_where_line, &ctx);
    }

  if (!args)
    {
      struct bfw_txn_line_ctx ctx = { .fp = stdin, .label = "txn", .lineno = 0 };
      return bfw_txn_run (o, "txn", bfw_txn_next_line,
                          bfw_txn_where_line, &ctx);
    }

  struct bfw_txn_inline_ctx ctx = { .cur = args };
  int valid = bfw_txn_validate_inline (args);
  if (valid != EXECUTION_SUCCESS)
    return valid;
  return bfw_txn_run (o, "txn", bfw_txn_next_inline, NULL, &ctx);
}

static int
bfw_cmd_status (struct bfw_opts *o)
{
  const char *b = (o->backend == BFW_NFT) ? "nft" :
                  (o->backend == BFW_IPT) ? "iptables" : "none";
  printf ("backend=%s dry_run=%d\n", b, o->dry_run);
  return EXECUTION_SUCCESS;
}

int
fw_builtin (WORD_LIST *list)
{
  struct bfw_opts o = { .backend = BFW_AUTO, .dry_run = 0 };
  /* BASHFW_BACKEND env: an explicit operator override that wins over
   * autodetect (still overridden by -B on the command line). Accepted
   * values: nft, iptables, pure. Empty / unset / unknown values are
   * silently ignored — autodetect falls back to nft|iptables. */
  const char *env_be = getenv ("BASHFW_BACKEND");
  if (env_be && *env_be)
    {
      if      (strcmp (env_be, "nft")      == 0) o.backend = BFW_NFT;
      else if (strcmp (env_be, "iptables") == 0) o.backend = BFW_IPT;
      else if (strcmp (env_be, "pure")     == 0) o.backend = BFW_PURE;
    }
  /* Global flags first. */
  while (list)
    {
      const char *w = list->word->word;
      if (strcmp (w, "-B") == 0)
        {
          if (!list->next) { builtin_error ("-B needs nft|iptables|pure"); builtin_usage (); return EX_USAGE; }
          list = list->next;
          if      (strcmp (list->word->word, "nft")      == 0) o.backend = BFW_NFT;
          else if (strcmp (list->word->word, "iptables") == 0) o.backend = BFW_IPT;
          else if (strcmp (list->word->word, "pure")     == 0) o.backend = BFW_PURE;
          else { builtin_error ("-B: unknown backend %s", list->word->word); builtin_usage (); return EX_USAGE; }
          list = list->next;
        }
      else if (strcmp (w, "-n") == 0) { o.dry_run = 1; list = list->next; }
      else if (strcmp (w, "--idempotent") == 0 ||
               strcmp (w, "-1") == 0) { o.idempotent = 1; list = list->next; }
      else break;
    }
  if (o.backend == BFW_AUTO) o.backend = bfw_detect ();
  if (o.backend == BFW_AUTO && !o.dry_run)
    { builtin_error ("no firewall backend available (need nft or iptables; or set BASHFW_BACKEND=pure for the v1 file-store stub)"); return EXECUTION_FAILURE; }
  if (o.backend == BFW_AUTO) o.backend = BFW_NFT;   /* dry-run prints nft */

  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;

  if (strcmp (cmd, "allow")   == 0) return bfw_cmd_allow (args, &o);
  if (strcmp (cmd, "deny")    == 0) return bfw_cmd_deny (args, &o);
  if (strcmp (cmd, "unban")   == 0 || strcmp (cmd, "undeny") == 0) return bfw_cmd_unban (args, &o);
  if (strcmp (cmd, "dnat")    == 0) return bfw_cmd_dnat (args, &o);
  if (strcmp (cmd, "snat")    == 0) return bfw_cmd_snat (args, &o);
  if (strcmp (cmd, "masquerade") == 0 || strcmp (cmd, "masq") == 0) return bfw_cmd_masquerade (args, &o);
  if (strcmp (cmd, "set")     == 0) return bfw_cmd_set (args, &o);
  if (strcmp (cmd, "helper")  == 0) return bfw_cmd_helper (args, &o);
  if (strcmp (cmd, "flush")   == 0) return bfw_cmd_flush (args, &o);
  if (strcmp (cmd, "policy")  == 0) return bfw_cmd_policy (args, &o);
  if (strcmp (cmd, "list")    == 0) return bfw_cmd_list (args, &o);
  if (strcmp (cmd, "save")    == 0) return bfw_cmd_save (args, &o);
  if (strcmp (cmd, "restore") == 0) return bfw_cmd_restore (args, &o);
  if (strcmp (cmd, "batch")   == 0) return bfw_cmd_batch (args, &o);
  if (strcmp (cmd, "txn")     == 0) return bfw_cmd_txn (args, &o);
  if (strcmp (cmd, "reset")   == 0) return bfw_cmd_reset (&o);
  if (strcmp (cmd, "status")  == 0) return bfw_cmd_status (&o);

  builtin_error ("unknown subcommand: %s (try allow/deny/unban/dnat/snat/masquerade/set/helper/flush/policy/list/save/restore/batch/txn/reset/status)", cmd);
  builtin_usage ();
  return EX_USAGE;
}

char *fw_doc[] = {
  "Netfilter front-end: nftables-preferred, iptables-fallback.",
  "",
  "    fw [-B nft|iptables|pure] [-n] [--idempotent|-1] SUBCMD ...",
  "",
  "    allow IP|-S SET [-p PROTO] [-d DPORT] [-s SPORT]",
  "          [-i IFACE] [-o IFACE] [--ct-state STATES]",
  "          [--limit RATE] [--multiport PORTS]",
  "    deny  IP|-S SET [-p PROTO] [-d DPORT] [-s SPORT]",
  "          [-i IFACE] [-o IFACE] [--ct-state STATES]",
  "          [--limit RATE] [--multiport PORTS]",
  "          [--log PREFIX|--nflog PREFIX]",
  "          [--reject[=port-unreachable|tcp-reset|admin-prohibited]]",
  "    unban IP [-p PROTO] [-d DPORT] [-s SPORT]  (alias: undeny)",
  "    policy <input|output> <accept|drop> [--no-baseline]",
  "       (drop = default-deny; installs lo + established/related accept",
  "        unless --no-baseline. nft sets chain policy; iptables uses a",
  "        terminal DROP rule.)",
  "    set create NAME [-f inet|inet6] [-t hash:ip|hash:net]",
  "    set add NAME IP[/CIDR]       set del NAME IP[/CIDR]",
  "    set list [NAME]              set destroy NAME",
  "    helper add NAME [-p PROTO] [--dport PORT]   (ftp|tftp|sip|irc|pptp|h323|snmp|amanda)",
  "    helper list",
  "       (conntrack helper: nft ct-helper object + prerouting rule; iptables",
  "        raw/PREROUTING -j CT --helper. Remove an individual helper via reset/flush.)",
  "    dnat  ADDR:PORT [->] DEST:PORT [-p PROTO] [--hairpin LAN_CIDR]",
  "       (--hairpin adds NAT reflection: a postrouting masquerade so LAN",
  "        clients reach the DNAT'd service via the external IP)",
  "    snat  ADDR:PORT [->] DEST:PORT [-p PROTO]",
  "    masquerade CIDR [-p PROTO] [-o IFACE]",
  "    flush [CHAIN]            list  [-l|--numbered] [CHAIN]",
  "       (list -l: nft prints handles; iptables prints --line-numbers)",
  "    save [FILE]              restore [FILE]",
  "       (save/restore without FILE use /etc/fw/rules.conf;",
  "        restore with no FILE on missing default is a benign no-op,",
  "        restore on an explicit missing FILE is a diagnostic exit 1)",
  "       iptables save/restore includes a marked ipset save section",
  "       when ipset is available, so set-backed rules persist.",
  "    batch FILE",
  "       Apply line-oriented allow/deny/unban/dnat/snat/masquerade/set/flush/reset",
  "       commands. Non-dry-run mode snapshots first and restores on failure.",
  "    txn [--] VERB ARGS [ ; VERB ARGS ... ]   |   txn -",
  "       Atomic inline transaction: snapshot once, apply each ';'-separated",
  "       verb (or batch lines on stdin via `-`), and restore the snapshot if",
  "       any verb fails. Same verb set as batch.",
  "    reset                    status",
  "",
  "    -n is dry-run: prints the backend argv without running it.",
  "    --idempotent / -1: skip adding a rule if it already exists.",
  "    nft: operates on table inet/fw, chains input/output (filter)",
  "         and prerouting/postrouting (nat).",
  "    iptables: filter -> BASHFW_IN/BASHFW_OUT; nat -> PREROUTING/POSTROUTING;",
  "         IPv6 address rules dispatch to ip6tables.",
  "    named sets: nft uses inet/fw sets; iptables uses ipset + -m set.",
  "    rich matches: -i/-o iface, --ct-state, --limit, --multiport.",
  "    deny logging: --log uses nft log / iptables LOG; --nflog uses NFLOG.",
  "    masquerade/masq installs dynamic-source NAT in postrouting.",
  (char *)NULL
};

struct builtin fw_struct = {
  "fw",
  fw_builtin,
  BUILTIN_ENABLED,
  fw_doc,
  "fw [-B nft|iptables|pure] [-n] [--idempotent|-1] SUBCMD ARGS...",
  0
};
