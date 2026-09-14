/* SPDX-License-Identifier: MIT */
/* netids.c — minimal passive network IDS, Suricata/Snort-class.
 *
 * Debian-server-parity AUDIT-6.4 (design
 * research/bash-os/DEBIAN-SERVER-PARITY-IMPL-AUDIT-IDS.md §6.4). Passive
 * NetIDS over offline pcap (`-r PCAP`) or live AF_PACKET capture (`-i IFACE`).
 * Passive alert/pass behavior remains the default; A6 adds opt-in inline
 * blocking for drop/reject rules through fw-style deny requests. `pcre:`
 * remains disabled by default (Q4: packet-path regex is the dominant perf/DoS
 * risk).
 *
 * Verbs:
 *   netids compile -S RULES [--enable-pcre]
 *       Parse + compile the rule file. Prints "compiled N rule(s)". Any
 *       out-of-subset directive fails the whole compile with a diagnostic and
 *       exit 2 (design §2 anti-drift — never silently drop a rule).
 *   netids scan -r PCAP -S RULES [-o EVE] [--enable-pcre]
 *                  [--enable-blocking] [--dry-run]
 *       Read the pcap savefile, decode Ethernet/RAW → IPv4 → TCP/UDP/ICMP,
 *       content-match each packet against the compiled rules, and emit one
 *       schema-level eve.json alert object per line to EVE (default stdout;
 *       "-" = stdout). Prints "N alert(s)" to stderr. NOT byte-compatible
 *       with Suricata eve.json (design §10) — schema-level fields only.
 *   netids scan -i IFACE -S RULES [-o EVE] [--count N] [--timeout SEC]
 *                  [--enable-pcre] [--enable-blocking] [--dry-run]
 *       Live capture through pcap's AF_PACKET frame callback. CAP_NET_RAW
 *       is dropped after socket open by pcap; live frames enter the same
 *       bn_scan_frame() decoder/matcher as offline scan.
 *   netids --version
 *
 * Accepted rule grammar (Suricata subset):
 *   ACTION PROTO SRC_IP SRC_PORT -> DST_IP DST_PORT ( OPTIONS )
 *     ACTION  : alert | pass | drop | reject
 *               drop/reject require --enable-blocking or
 *               BASHNETIDS_ENABLE_BLOCKING=1.
 *     PROTO   : tcp | udp | icmp | ip
 *     IP      : any | A.B.C.D | A.B.C.D/N   (IPv4 only; ! negation + lists
 *                                            deferred)
 *     PORT    : any | N | N:M               (lists deferred)
 *     DIR     : -> | <>
 *     OPTIONS : msg:"..."; content:"..."[; nocase]; pcre:"/.../[ismU]";
 *               sid:N; rev:N;
 *               classtype:..; reference:..;
 *   Multiple content: clauses AND together. content supports |AA BB| hex
 *   and C-style \" \\ escapes. pcre: requires --enable-pcre or
 *   BASHNETIDS_ENABLE_PCRE=1. Rejected at compile (exit 2): lua:, flowbits:,
 *   threshold:, byte_test:, dsize:, unsupported pcre flags, and flow: other
 *   than "flow:established" (and its with-direction forms).
 * PCRE DoS-surface notes live in rootfs/docs/bash/netids.txt; the opt-in
 * wrapper fuzz harness is tests/bash-os/bench/netids-pcre-fuzz-corpus.sh.
 *
 * Host-testable seams (no privilege): rule compile (accept/reject), content
 * decode + match, offline pcap scan over a crafted savefile, offline blocking
 * dry-run events, and parser/source contract checks for live mode. Privileged
 * live capture and firewall mutation are gated in-guest.
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
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "loadables.h"

#define BN_PCAP_MAGIC_USEC 0xa1b2c3d4u
#define BN_PCAP_MAGIC_NSEC 0xa1b23c4du
#define BN_PCAP_MAGIC_SWAP 0xd4c3b2a1u
#define BN_MAX_CONTENT 8
#define BN_MAX_PCRE    4
#define BN_SNAP_CAP    65536
#define BN_DEFAULT_LIVE_COUNT 5
#define BN_DEFAULT_LIVE_TIMEOUT 1.0
#define BN_DEFAULT_PCRE_MATCH_LIMIT 100000u
#define BN_DEFAULT_PCRE_DEPTH_LIMIT 1000u
#define BN_DEFAULT_PCRE_MAX_PATTERN_BYTES 1024u
#define BN_DEFAULT_PCRE_MAX_SUBJECT_BYTES 8192u
#define BN_MAX_BLOCK_DEDUPE 256

/* Private pcap callback surface. The definitions intentionally mirror
 * scripts/loadables/pcap.c; both objects are linked into bash-os bash. */
struct bashpcap_frame {
  const unsigned char *data;
  uint32_t caplen;
  uint32_t origlen;
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t linktype;
};

struct bashpcap_capture_opts {
  const char *iface;
  int count;
  int snaplen;
  double timeout_s;
  int keep_caps;
};

typedef int (*bashpcap_frame_cb) (const struct bashpcap_frame *, void *);
extern int bashpcap_capture_frames (const struct bashpcap_capture_opts *opts,
                                    bashpcap_frame_cb cb, void *userdata);

/* ---- compiled rule model ----------------------------------------- */

struct bn_content { unsigned char bytes[256]; int len; int nocase; };
struct bn_pcre_clause {
  char *pattern;
  uint32_t flags;
  pcre2_code *code;
  pcre2_match_data *mdata;
};

struct bn_rule {
  char action[16];         /* alert | pass | drop | reject */
  int  proto;              /* IPPROTO_TCP/UDP/ICMP, or 0 = ip (any) */
  uint32_t sip, sip_mask;  /* network order; mask 0 = any */
  uint32_t dip, dip_mask;
  int  sport_any, sport_lo, sport_hi;
  int  dport_any, dport_lo, dport_hi;
  int  bidir;              /* <> */
  char msg[256];
  long sid, rev;
  char classtype[64];
  struct bn_content content[BN_MAX_CONTENT];
  int  ncontent;
  struct bn_pcre_clause pcre[BN_MAX_PCRE];
  int npcre;
};

struct bn_block_seen {
  uint32_t sip;
  char action[16];
};

struct bn_scan_ctx {
  FILE *out;
  int blocking_enabled;
  int dry_run;
  int live_mode;
  long alerts;
  long blocks;
  long block_errors;
  struct bn_block_seen seen[BN_MAX_BLOCK_DEDUPE];
  int nseen;
};

/* ---- PCRE2 bounded helper ---------------------------------------- */

static unsigned
bn_env_uint (const char *name, unsigned dflt, unsigned minv, unsigned maxv)
{
  const char *e = getenv (name);
  if (!e || !*e) return dflt;
  char *end = NULL;
  unsigned long v = strtoul (e, &end, 10);
  if (!end || *end || v < minv) return dflt;
  if (v > maxv) return maxv;
  return (unsigned) v;
}

static int
bn_pcre_enabled_env (void)
{
  const char *e = getenv ("BASHNETIDS_ENABLE_PCRE");
  return e && (!strcmp (e, "1") || !strcasecmp (e, "true") || !strcasecmp (e, "yes"));
}

static int
bn_env_truthy (const char *name)
{
  const char *e = getenv (name);
  return e && (!strcmp (e, "1") || !strcasecmp (e, "true") ||
               !strcasecmp (e, "yes") || !strcasecmp (e, "on"));
}

static pcre2_match_context *
bn_pcre_match_ctx (void)
{
  static pcre2_match_context *ctx = NULL;
  if (!ctx)
    ctx = pcre2_match_context_create (NULL);
  if (!ctx)
    return NULL;
  pcre2_set_match_limit (ctx, bn_env_uint ("BASHNETIDS_PCRE_MATCH_LIMIT",
                                           BN_DEFAULT_PCRE_MATCH_LIMIT, 1, 10000000));
  pcre2_set_depth_limit (ctx, bn_env_uint ("BASHNETIDS_PCRE_DEPTH_LIMIT",
                                           BN_DEFAULT_PCRE_DEPTH_LIMIT, 1, 1000000));
  return ctx;
}

static int
bn_parse_pcre_flags (const char *s, uint32_t *flags, char *err, size_t errcap)
{
  uint32_t f = 0;       /* byte-mode by default: packet payloads are not UTF-8 text. */
  for (const char *p = s; *p; p++)
    switch (*p)
      {
      case 'i': f |= PCRE2_CASELESS; break;
      case 's': f |= PCRE2_DOTALL; break;
      case 'm': f |= PCRE2_MULTILINE; break;
      case 'U': f |= PCRE2_UNGREEDY; break;
      default:
        snprintf (err, errcap, "pcre: unsupported flag '%c' (allowed: i,s,m,U)", *p);
        return -1;
      }
  *flags = f;
  return 0;
}

static int
bn_pcre_parse_clause (const char *tok, char **pattern_out, uint32_t *flags_out,
                      char *err, size_t errcap)
{
  const char *q = strchr (tok, '"');
  if (!q) { snprintf (err, errcap, "pcre: missing quoted value"); return -1; }
  q++;
  if (*q != '/') { snprintf (err, errcap, "pcre: expected /pattern/flags"); return -1; }
  const char *p = q + 1;
  char pat[2048];
  size_t n = 0;
  int esc = 0;
  for (; *p; p++)
    {
      if (esc)
        {
          if (n + 2 >= sizeof pat) { snprintf (err, errcap, "pcre: pattern too long"); return -1; }
          pat[n++] = '\\';
          pat[n++] = *p;
          esc = 0;
          continue;
        }
      if (*p == '\\') { esc = 1; continue; }
      if (*p == '/') break;
      if (n + 1 >= sizeof pat) { snprintf (err, errcap, "pcre: pattern too long"); return -1; }
      pat[n++] = *p;
    }
  if (esc) { snprintf (err, errcap, "pcre: trailing escape"); return -1; }
  if (*p != '/') { snprintf (err, errcap, "pcre: missing closing delimiter"); return -1; }
  if (n == 0) { snprintf (err, errcap, "pcre: empty pattern"); return -1; }
  unsigned max_pat = bn_env_uint ("BASHNETIDS_PCRE_MAX_PATTERN_BYTES",
                                  BN_DEFAULT_PCRE_MAX_PATTERN_BYTES, 1, 65535);
  if (n > max_pat)
    { snprintf (err, errcap, "pcre: pattern too long (max %u)", max_pat); return -1; }
  pat[n] = '\0';
  p++;
  char flags[32];
  size_t nf = 0;
  for (; *p && *p != '"'; p++)
    {
      if (nf + 1 >= sizeof flags) { snprintf (err, errcap, "pcre: flags too long"); return -1; }
      flags[nf++] = *p;
    }
  if (*p != '"') { snprintf (err, errcap, "pcre: unterminated quote"); return -1; }
  p++;
  while (*p && isspace ((unsigned char) *p)) p++;
  if (*p) { snprintf (err, errcap, "pcre: trailing garbage after quote"); return -1; }
  flags[nf] = '\0';
  if (bn_parse_pcre_flags (flags, flags_out, err, errcap) < 0)
    return -1;
  *pattern_out = strdup (pat);
  if (!*pattern_out) { snprintf (err, errcap, "pcre: out of memory"); return -1; }
  return 0;
}

static int
bn_pcre_compile_clause (struct bn_pcre_clause *pc, char *err, size_t errcap)
{
  int errcode = 0;
  PCRE2_SIZE erroff = 0;
  pc->code = pcre2_compile ((PCRE2_SPTR) pc->pattern, PCRE2_ZERO_TERMINATED,
                            pc->flags, &errcode, &erroff, NULL);
  if (!pc->code)
    {
      char msg[160];
      pcre2_get_error_message (errcode, (PCRE2_UCHAR *) msg, sizeof msg);
      snprintf (err, errcap, "pcre: compile offset %zu: %s", (size_t) erroff, msg);
      return -1;
    }
  pc->mdata = pcre2_match_data_create_from_pattern (pc->code, NULL);
  if (!pc->mdata)
    { snprintf (err, errcap, "pcre: match-data allocation failed"); return -1; }
  return 0;
}

/* ---- small helpers ----------------------------------------------- */

static int bn_proto_num (const char *p)
{
  if (!strcmp (p, "tcp"))  return IPPROTO_TCP;
  if (!strcmp (p, "udp"))  return IPPROTO_UDP;
  if (!strcmp (p, "icmp")) return IPPROTO_ICMP;
  if (!strcmp (p, "ip"))   return 0;        /* any proto */
  return -1;
}

/* Parse "any" | "A.B.C.D" | "A.B.C.D/N" into net-order ip + mask. */
static int bn_parse_ip (const char *s, uint32_t *ip, uint32_t *mask)
{
  if (!strcmp (s, "any")) { *ip = 0; *mask = 0; return 0; }
  char tmp[64]; snprintf (tmp, sizeof tmp, "%s", s);
  char *slash = strchr (tmp, '/');
  int bits = 32;
  if (slash) { *slash = '\0'; bits = atoi (slash + 1); if (bits < 0 || bits > 32) return -1; }
  struct in_addr a;
  if (inet_pton (AF_INET, tmp, &a) != 1) return -1;
  *ip = a.s_addr;                                   /* network order */
  *mask = bits == 0 ? 0 : htonl (0xffffffffu << (32 - bits));
  return 0;
}

/* Parse "any" | "N" | "N:M" into [lo,hi] + any flag. */
static int bn_parse_port (const char *s, int *any, int *lo, int *hi)
{
  if (!strcmp (s, "any")) { *any = 1; *lo = 0; *hi = 65535; return 0; }
  *any = 0;
  char tmp[32]; snprintf (tmp, sizeof tmp, "%s", s);
  char *colon = strchr (tmp, ':');
  if (colon) { *colon = '\0';
    *lo = tmp[0] ? atoi (tmp) : 0;
    *hi = colon[1] ? atoi (colon + 1) : 65535;
  } else { *lo = *hi = atoi (tmp); }
  if (*lo < 0 || *hi > 65535 || *lo > *hi) return -1;
  return 0;
}

/* Decode a Suricata content string (between the quotes) into raw bytes,
 * expanding |41 42| hex runs and \" \\ \: escapes. Returns byte length. */
static int bn_decode_content (const char *s, unsigned char *out, int cap)
{
  int n = 0, hex = 0;
  for (const char *p = s; *p && n < cap; p++)
    {
      if (*p == '|') { hex = !hex; continue; }
      if (hex)
        {
          if (isspace ((unsigned char) *p)) continue;
          int hi = *p, lo = *(p + 1);
          if (!isxdigit (hi) || !isxdigit (lo)) return -1;
          char b[3] = { (char) hi, (char) lo, 0 };
          out[n++] = (unsigned char) strtol (b, NULL, 16);
          p++;
          continue;
        }
      if (*p == '\\' && p[1]) { p++; out[n++] = (unsigned char) *p; continue; }
      out[n++] = (unsigned char) *p;
    }
  return hex ? -1 : n;            /* unbalanced | is malformed */
}

/* Case-insensitive memmem fallback (musl lacks a portable guarantee). */
static const unsigned char *
bn_memmem (const unsigned char *hay, int hlen,
           const unsigned char *needle, int nlen, int nocase)
{
  if (nlen == 0) return hay;
  for (int i = 0; i + nlen <= hlen; i++)
    {
      int j = 0;
      for (; j < nlen; j++)
        {
          unsigned char a = hay[i + j], b = needle[j];
          if (nocase) { a = (unsigned char) tolower (a); b = (unsigned char) tolower (b); }
          if (a != b) break;
        }
      if (j == nlen) return hay + i;
    }
  return NULL;
}

/* ---- rule compiler (pure / host-testable) ------------------------ */

/* Returns 0 on success; -1 on reject (writes a reason into err). */
static int
bn_compile_rule (const char *line, struct bn_rule *r, int enable_pcre,
                 int enable_blocking, char *err, size_t errcap)
{
  memset (r, 0, sizeof *r);
  /* skip blanks / comments */
  while (*line && isspace ((unsigned char) *line)) line++;
  if (*line == '\0' || *line == '#') { snprintf (err, errcap, "blank"); return -1; }

  /* header: ACTION PROTO SIP SPORT DIR DIP DPORT ( ... ) */
  char action[16], proto[8], sip[64], sport[32], dir[4], dip[64], dport[32];
  const char *paren = strchr (line, '(');
  if (!paren) { snprintf (err, errcap, "missing option block '('"); return -1; }
  char header[512];
  size_t hl = (size_t) (paren - line);
  if (hl >= sizeof header) { snprintf (err, errcap, "header too long"); return -1; }
  memcpy (header, line, hl); header[hl] = '\0';
  if (sscanf (header, "%15s %7s %63s %31s %3s %63s %31s",
              action, proto, sip, sport, dir, dip, dport) != 7)
    { snprintf (err, errcap, "malformed header (need: action proto sip sport dir dip dport)"); return -1; }

  if (strcmp (action, "alert") && strcmp (action, "pass") &&
      strcmp (action, "drop") && strcmp (action, "reject"))
    { snprintf (err, errcap, "action '%s' not in subset (use alert/pass/drop/reject)", action); return -1; }
  if ((!strcmp (action, "drop") || !strcmp (action, "reject")) && !enable_blocking)
    { snprintf (err, errcap, "action '%s' requires --enable-blocking", action); return -1; }
  snprintf (r->action, sizeof r->action, "%s", action);
  r->proto = bn_proto_num (proto);
  if (r->proto < 0) { snprintf (err, errcap, "proto '%s' unsupported (tcp/udp/icmp/ip)", proto); return -1; }
  if (!strcmp (dir, "->")) r->bidir = 0;
  else if (!strcmp (dir, "<>")) r->bidir = 1;
  else { snprintf (err, errcap, "direction '%s' unsupported (-> or <>)", dir); return -1; }
  if (bn_parse_ip (sip, &r->sip, &r->sip_mask) < 0) { snprintf (err, errcap, "bad src ip '%s'", sip); return -1; }
  if (bn_parse_ip (dip, &r->dip, &r->dip_mask) < 0) { snprintf (err, errcap, "bad dst ip '%s'", dip); return -1; }
  if (bn_parse_port (sport, &r->sport_any, &r->sport_lo, &r->sport_hi) < 0) { snprintf (err, errcap, "bad src port '%s'", sport); return -1; }
  if (bn_parse_port (dport, &r->dport_any, &r->dport_lo, &r->dport_hi) < 0) { snprintf (err, errcap, "bad dst port '%s'", dport); return -1; }

  /* options: between the outermost ( ) */
  const char *opts = paren + 1;
  const char *endp = strrchr (opts, ')');
  if (!endp) { snprintf (err, errcap, "unterminated option block"); return -1; }
  size_t ol = (size_t) (endp - opts);
  char obuf[4096];
  if (ol >= sizeof obuf) { snprintf (err, errcap, "option block too long"); return -1; }
  memcpy (obuf, opts, ol); obuf[ol] = '\0';

  /* Reject out-of-subset keywords up front (Q4 + §6.4). */
  static const char *banned[] = { "lua:", "flowbits:", "threshold:",
                                  "byte_test:", "dsize:", NULL };
  for (const char **b = banned; *b; b++)
    if (strstr (obuf, *b))
      { snprintf (err, errcap, "directive '%s' not in first-promotion subset", *b); return -1; }
  if (!enable_pcre && strstr (obuf, "pcre:"))
    { snprintf (err, errcap, "directive 'pcre:' requires --enable-pcre"); return -1; }
  /* flow: only "established" (optionally with a direction) is accepted. */
  {
    const char *fl = strstr (obuf, "flow:");
    if (fl)
      {
        char fv[64] = {0};
        sscanf (fl + 5, "%63[^;]", fv);
        if (!strstr (fv, "established"))
          { snprintf (err, errcap, "flow:'%s' beyond 'established' not supported", fv); return -1; }
      }
  }

  /* Tokenize options on ';'. content may carry a following nocase. */
  char *save = NULL, *tok = strtok_r (obuf, ";", &save);
  for (; tok; tok = strtok_r (NULL, ";", &save))
    {
      while (*tok && isspace ((unsigned char) *tok)) tok++;
      if (*tok == '\0') continue;
      if (!strncmp (tok, "msg:", 4))
        {
          const char *q = strchr (tok, '"');
          if (q) { const char *e = strchr (q + 1, '"');
            if (e) { int len = (int) (e - q - 1);
              if (len >= (int) sizeof r->msg) len = sizeof r->msg - 1;
              memcpy (r->msg, q + 1, len); r->msg[len] = '\0'; } }
        }
      else if (!strncmp (tok, "content:", 8))
        {
          if (r->ncontent >= BN_MAX_CONTENT)
            { snprintf (err, errcap, "too many content clauses (max %d)", BN_MAX_CONTENT); return -1; }
          const char *q = strchr (tok, '"');
          if (!q) { snprintf (err, errcap, "content: missing quoted value"); return -1; }
          const char *e = strrchr (q + 1, '"');
          if (!e) { snprintf (err, errcap, "content: unterminated quote"); return -1; }
          char raw[512]; int rl = (int) (e - q - 1);
          if (rl >= (int) sizeof raw) rl = sizeof raw - 1;
          memcpy (raw, q + 1, rl); raw[rl] = '\0';
          struct bn_content *c = &r->content[r->ncontent];
          c->len = bn_decode_content (raw, c->bytes, (int) sizeof c->bytes);
          if (c->len < 0) { snprintf (err, errcap, "content: malformed value"); return -1; }
          r->ncontent++;
        }
      else if (!strcmp (tok, "nocase"))
        { if (r->ncontent > 0) r->content[r->ncontent - 1].nocase = 1; }
      else if (!strncmp (tok, "pcre:", 5))
        {
          if (r->npcre >= BN_MAX_PCRE)
            { snprintf (err, errcap, "too many pcre clauses (max %d)", BN_MAX_PCRE); return -1; }
          struct bn_pcre_clause *pc = &r->pcre[r->npcre];
          if (bn_pcre_parse_clause (tok, &pc->pattern, &pc->flags, err, errcap) < 0)
            return -1;
          if (bn_pcre_compile_clause (pc, err, errcap) < 0)
            { free (pc->pattern); pc->pattern = NULL;
              if (pc->mdata) { pcre2_match_data_free (pc->mdata); pc->mdata = NULL; }
              if (pc->code) { pcre2_code_free (pc->code); pc->code = NULL; }
              return -1; }
          r->npcre++;
        }
      else if (!strncmp (tok, "sid:", 4))       r->sid = atol (tok + 4);
      else if (!strncmp (tok, "rev:", 4))       r->rev = atol (tok + 4);
      else if (!strncmp (tok, "classtype:", 10))
        snprintf (r->classtype, sizeof r->classtype, "%s", tok + 10);
      /* msg/sid/rev/classtype/reference + content/nocase are the accepted
       * set; reference: and any other benign metadata is ignored, not an
       * error (Suricata treats unknown metadata permissively). The banned
       * list above already rejected the dangerous keywords. */
    }
  if (r->sid <= 0) { snprintf (err, errcap, "missing or invalid sid"); return -1; }
  return 0;
}

/* ---- rule store -------------------------------------------------- */

static struct bn_rule *bn_rules = NULL;
static int bn_nrules = 0, bn_caprules = 0;

static void
bn_rule_free (struct bn_rule *r)
{
  if (!r) return;
  for (int i = 0; i < r->npcre; i++)
    {
      free (r->pcre[i].pattern);
      r->pcre[i].pattern = NULL;
      if (r->pcre[i].mdata) pcre2_match_data_free (r->pcre[i].mdata);
      r->pcre[i].mdata = NULL;
      if (r->pcre[i].code) pcre2_code_free (r->pcre[i].code);
      r->pcre[i].code = NULL;
    }
  r->npcre = 0;
}

static void
bn_rules_free (void)
{
  if (bn_rules)
    for (int i = 0; i < bn_nrules; i++)
      bn_rule_free (&bn_rules[i]);
  free (bn_rules);
  bn_rules = NULL;
  bn_nrules = bn_caprules = 0;
}

/* ---- A7: Aho-Corasick multi-pattern literal content matcher ------ */
/* One automaton over every literal `content:` clause across all loaded rules,
 * so each payload is scanned once instead of O(rules*clauses*bytes). Two
 * automata: case-sensitive (run on the raw payload) and nocase (patterns
 * case-folded, run on a folded payload copy). A hit on pattern id
 * (rule_index*BN_MAX_CONTENT + content_index) stamps a per-payload generation
 * counter; a rule's content portion is satisfied iff every one of its content
 * slots was stamped this generation — exactly the AND-of-substring semantics
 * of the bn_memmem() path it replaces. Alert ordering, nocase, pass/alert,
 * EVE output, and compile rejection are unchanged; `pcre:` never goes through
 * AC (A5 stays a separate regex path). Gated by BASHNETIDS_AC=auto|on|off and
 * BASHNETIDS_AC_MIN_PATTERNS; bounded by BASHNETIDS_AC_MAX_STATES with a
 * deterministic fall-back to bn_memmem() on cap/OOM. BASHNETIDS_AC_VERIFY=1
 * cross-checks every rule's AC verdict against bn_memmem() and fails closed. */

#define BN_AC_DEFAULT_MIN_PATTERNS 32
#define BN_AC_DEFAULT_MAX_STATES   200000

struct bn_acn {                 /* one automaton node (sparse, sorted edges) */
  int fail;
  int nedge, capedge;
  unsigned char *ec;            /* edge labels, kept sorted ascending */
  int           *et;            /* edge targets, parallel to ec */
  int nout, capout;
  int *out;                     /* terminal pattern ids (fail-merged) */
};
struct bn_ac { struct bn_acn *node; int n, cap; };

static struct bn_ac bn_ac_sens, bn_ac_nocase;
static int       bn_ac_active     = 0;    /* automaton built & in use */
static int       bn_ac_has_nocase = 0;
static int       bn_ac_verify     = 0;    /* compare vs bn_memmem, fail closed */
static uint32_t *bn_ac_hit        = NULL; /* per-pattern-slot generation stamp */
static uint32_t  bn_ac_gen        = 0;
static int       bn_ac_npat_slots = 0;    /* bn_nrules * BN_MAX_CONTENT */
static unsigned char *bn_ac_fold  = NULL; /* folded-payload scratch (nocase) */
static int       bn_ac_foldcap    = 0;
static int       bn_ac_max_states = 0;

/* binary search the sorted edge list; -1 = no edge. */
static int
bn_ac_goto (const struct bn_ac *ac, int s, unsigned char c)
{
  const struct bn_acn *nd = &ac->node[s];
  int lo = 0, hi = nd->nedge - 1;
  while (lo <= hi)
    {
      int m = (lo + hi) >> 1;
      if (nd->ec[m] == c) return nd->et[m];
      if (nd->ec[m] < c) lo = m + 1; else hi = m - 1;
    }
  return -1;
}

static int
bn_ac_new_node (struct bn_ac *ac)
{
  if (ac->n == ac->cap)
    {
      int nc = ac->cap ? ac->cap * 2 : 64;
      struct bn_acn *nn = realloc (ac->node, (size_t) nc * sizeof *nn);
      if (!nn) return -1;
      ac->node = nn; ac->cap = nc;
    }
  struct bn_acn *nd = &ac->node[ac->n];
  memset (nd, 0, sizeof *nd);
  return ac->n++;
}

/* insert one pattern (already folded if nocase) with id; -1 on cap/OOM. */
static int
bn_ac_add (struct bn_ac *ac, const unsigned char *pat, int len, int id)
{
  int s = 0;
  for (int i = 0; i < len; i++)
    {
      unsigned char c = pat[i];
      int nx = bn_ac_goto (ac, s, c);
      if (nx < 0)
        {
          if (ac->n >= bn_ac_max_states) return -1;
          nx = bn_ac_new_node (ac);
          if (nx < 0) return -1;
          struct bn_acn *nd = &ac->node[s];   /* re-take after possible realloc */
          if (nd->nedge == nd->capedge)
            {
              int ncp = nd->capedge ? nd->capedge * 2 : 4;
              unsigned char *nec = realloc (nd->ec, (size_t) ncp);
              if (!nec) return -1; nd->ec = nec;
              int *net = realloc (nd->et, (size_t) ncp * sizeof *net);
              if (!net) return -1; nd->et = net;
              nd->capedge = ncp;
            }
          int pos = nd->nedge;
          while (pos > 0 && nd->ec[pos - 1] > c)
            { nd->ec[pos] = nd->ec[pos - 1]; nd->et[pos] = nd->et[pos - 1]; pos--; }
          nd->ec[pos] = c; nd->et[pos] = nx; nd->nedge++;
        }
      s = nx;
    }
  struct bn_acn *nd = &ac->node[s];
  if (nd->nout == nd->capout)
    {
      int ncp = nd->capout ? nd->capout * 2 : 2;
      int *no = realloc (nd->out, (size_t) ncp * sizeof *no);
      if (!no) return -1; nd->out = no; nd->capout = ncp;
    }
  nd->out[nd->nout++] = id;
  return 0;
}

/* BFS fail links + output merge. -1 on OOM. */
static int
bn_ac_build_fail (struct bn_ac *ac)
{
  if (ac->n == 0) return 0;
  int *queue = malloc ((size_t) ac->n * sizeof *queue);
  if (!queue) return -1;
  int qh = 0, qt = 0;
  struct bn_acn *root = &ac->node[0];
  for (int e = 0; e < root->nedge; e++)
    { ac->node[root->et[e]].fail = 0; queue[qt++] = root->et[e]; }
  while (qh < qt)
    {
      int u = queue[qh++];
      for (int e = 0; e < ac->node[u].nedge; e++)
        {
          unsigned char c = ac->node[u].ec[e];
          int v = ac->node[u].et[e];
          int f = ac->node[u].fail, g;
          while ((g = bn_ac_goto (ac, f, c)) < 0 && f != 0) f = ac->node[f].fail;
          if (g < 0 || g == v) g = 0;
          ac->node[v].fail = g;
          struct bn_acn *nf = &ac->node[g];
          if (nf->nout)
            {
              struct bn_acn *nv = &ac->node[v];
              int need = nv->nout + nf->nout;
              if (need > nv->capout)
                {
                  int ncp = nv->capout ? nv->capout : 2;
                  while (ncp < need) ncp *= 2;
                  int *no = realloc (nv->out, (size_t) ncp * sizeof *no);
                  if (!no) { free (queue); return -1; }
                  nv->out = no; nv->capout = ncp;
                }
              for (int k = 0; k < nf->nout; k++) nv->out[nv->nout++] = nf->out[k];
            }
          queue[qt++] = v;
        }
    }
  free (queue);
  return 0;
}

static void
bn_ac_one_free (struct bn_ac *ac)
{
  for (int i = 0; i < ac->n; i++)
    { free (ac->node[i].ec); free (ac->node[i].et); free (ac->node[i].out); }
  free (ac->node);
  ac->node = NULL; ac->n = ac->cap = 0;
}

static void
bn_ac_free (void)
{
  bn_ac_one_free (&bn_ac_sens);
  bn_ac_one_free (&bn_ac_nocase);
  free (bn_ac_hit); bn_ac_hit = NULL;
  free (bn_ac_fold); bn_ac_fold = NULL; bn_ac_foldcap = 0;
  bn_ac_active = 0; bn_ac_has_nocase = 0;
  bn_ac_npat_slots = 0; bn_ac_gen = 0;
}

static int
bn_ac_count_patterns (void)
{
  int n = 0;
  for (int ri = 0; ri < bn_nrules; ri++)
    for (int c = 0; c < bn_rules[ri].ncontent; c++)
      if (bn_rules[ri].content[c].len > 0) n++;
  return n;
}

/* Build both automata + the hit-stamp table from the loaded rule set. */
static int
bn_ac_build (void)
{
  bn_ac_max_states = (int) bn_env_uint ("BASHNETIDS_AC_MAX_STATES",
                       BN_AC_DEFAULT_MAX_STATES, 16, 4000000);
  bn_ac_npat_slots = bn_nrules * BN_MAX_CONTENT;
  bn_ac_hit = calloc ((size_t) (bn_ac_npat_slots ? bn_ac_npat_slots : 1),
                      sizeof *bn_ac_hit);
  if (!bn_ac_hit) return -1;
  bn_ac_gen = 0; bn_ac_has_nocase = 0;
  if (bn_ac_new_node (&bn_ac_sens) < 0) return -1;     /* root = node 0 */
  if (bn_ac_new_node (&bn_ac_nocase) < 0) return -1;   /* root = node 0 */
  for (int ri = 0; ri < bn_nrules; ri++)
    {
      struct bn_rule *r = &bn_rules[ri];
      for (int c = 0; c < r->ncontent; c++)
        {
          struct bn_content *ct = &r->content[c];
          if (ct->len <= 0) continue;          /* empty needle always matches */
          int id = ri * BN_MAX_CONTENT + c;
          if (ct->nocase)
            {
              unsigned char fold[256];
              for (int i = 0; i < ct->len; i++)
                fold[i] = (unsigned char) tolower (ct->bytes[i]);
              if (bn_ac_add (&bn_ac_nocase, fold, ct->len, id) < 0) return -1;
              bn_ac_has_nocase = 1;
            }
          else if (bn_ac_add (&bn_ac_sens, ct->bytes, ct->len, id) < 0)
            return -1;
        }
    }
  if (bn_ac_build_fail (&bn_ac_sens) < 0) return -1;
  if (bn_ac_build_fail (&bn_ac_nocase) < 0) return -1;
  return 0;
}

static void
bn_ac_run (const struct bn_ac *ac, const unsigned char *buf, int len)
{
  int s = 0;
  for (int i = 0; i < len; i++)
    {
      unsigned char c = buf[i];
      int g;
      while ((g = bn_ac_goto (ac, s, c)) < 0 && s != 0) s = ac->node[s].fail;
      s = (g >= 0) ? g : 0;
      const struct bn_acn *nd = &ac->node[s];
      for (int k = 0; k < nd->nout; k++) bn_ac_hit[nd->out[k]] = bn_ac_gen;
    }
}

/* Scan one payload through both automata, advancing the generation stamp. */
static void
bn_ac_scan_payload (const unsigned char *payload, int plen)
{
  if (++bn_ac_gen == 0)            /* wrapped: clear stamps, restart at gen 1 */
    {
      if (bn_ac_hit)
        memset (bn_ac_hit, 0, (size_t) bn_ac_npat_slots * sizeof *bn_ac_hit);
      bn_ac_gen = 1;
    }
  if (plen <= 0) return;
  if (bn_ac_sens.n > 1) bn_ac_run (&bn_ac_sens, payload, plen);
  if (bn_ac_has_nocase)
    {
      if (plen > bn_ac_foldcap)
        {
          unsigned char *nf = realloc (bn_ac_fold, (size_t) plen);
          if (!nf) return;         /* fold OOM: skip (verify mode would catch) */
          bn_ac_fold = nf; bn_ac_foldcap = plen;
        }
      for (int i = 0; i < plen; i++)
        bn_ac_fold[i] = (unsigned char) tolower (payload[i]);
      bn_ac_run (&bn_ac_nocase, bn_ac_fold, plen);
    }
}

/* Content portion of rule satisfied per the current payload's AC hit stamps. */
static int
bn_ac_content_ok (int rule_index)
{
  const struct bn_rule *r = &bn_rules[rule_index];
  int base = rule_index * BN_MAX_CONTENT;
  for (int c = 0; c < r->ncontent; c++)
    {
      if (r->content[c].len <= 0) continue;     /* empty needle: always ok */
      if (bn_ac_hit[base + c] != bn_ac_gen) return 0;
    }
  return 1;
}

/* Compile every rule in a file. Returns 0 on success, -1 on the first reject
 * (with a message already emitted). */
static int
bn_load_rules (const char *path, int enable_pcre, int enable_blocking)
{
  FILE *f = fopen (path, "r");
  if (!f) { builtin_error ("rules: cannot open %s: %s", path, strerror (errno)); return -1; }
  char line[8192]; int lineno = 0;
  while (fgets (line, sizeof line, f))
    {
      lineno++;
      char *nl = strchr (line, '\n'); if (nl) *nl = '\0';
      char *p = line; while (*p && isspace ((unsigned char) *p)) p++;
      if (*p == '\0' || *p == '#') continue;           /* blank/comment */
      if (bn_nrules == bn_caprules)
        { bn_caprules = bn_caprules ? bn_caprules * 2 : 16;
          bn_rules = realloc (bn_rules, (size_t) bn_caprules * sizeof *bn_rules);
          if (!bn_rules) { builtin_error ("rules: out of memory"); fclose (f); return -1; } }
      char err[160];
      if (bn_compile_rule (line, &bn_rules[bn_nrules], enable_pcre,
                           enable_blocking, err, sizeof err) < 0)
        { bn_rule_free (&bn_rules[bn_nrules]);
          builtin_error ("rules: %s:%d: reject: %s", path, lineno, err); fclose (f); return -1; }
      bn_nrules++;
    }
  fclose (f);
  return 0;
}

/* ---- packet matching --------------------------------------------- */

static int
bn_port_ok (int any, int lo, int hi, int port)
{ return any || (port >= lo && port <= hi); }

static int
bn_ip_ok (uint32_t rip, uint32_t mask, uint32_t pip)
{ return mask == 0 || ((pip & mask) == (rip & mask)); }

static int
bn_pcre_match_clause (const struct bn_pcre_clause *pc,
                      const unsigned char *payload, int plen)
{
  if (!pc->code || !pc->mdata) return 0;
  unsigned max_subject = bn_env_uint ("BASHNETIDS_PCRE_MAX_SUBJECT_BYTES",
                                      BN_DEFAULT_PCRE_MAX_SUBJECT_BYTES, 1, BN_SNAP_CAP);
  if (plen > (int) max_subject)
    plen = (int) max_subject;
  int rc = pcre2_match (pc->code, (PCRE2_SPTR) payload, (PCRE2_SIZE) plen,
                        0, 0, pc->mdata, bn_pcre_match_ctx ());
  if (rc >= 0) return 1;
  if (rc == PCRE2_ERROR_NOMATCH || rc == PCRE2_ERROR_MATCHLIMIT ||
      rc == PCRE2_ERROR_DEPTHLIMIT)
    return 0;
  return 0;
}

/* proto/ip/port (and <> reverse) gate — the cheap pre-filter, AC-independent. */
static int
bn_header_match (const struct bn_rule *r, int proto, uint32_t sip, uint32_t dip,
                 int sport, int dport)
{
  if (r->proto != 0 && r->proto != proto) return 0;
  int fwd = bn_ip_ok (r->sip, r->sip_mask, sip) && bn_ip_ok (r->dip, r->dip_mask, dip)
            && bn_port_ok (r->sport_any, r->sport_lo, r->sport_hi, sport)
            && bn_port_ok (r->dport_any, r->dport_lo, r->dport_hi, dport);
  int rev = 0;
  if (r->bidir)
    rev = bn_ip_ok (r->sip, r->sip_mask, dip) && bn_ip_ok (r->dip, r->dip_mask, sip)
          && bn_port_ok (r->sport_any, r->sport_lo, r->sport_hi, dport)
          && bn_port_ok (r->dport_any, r->dport_lo, r->dport_hi, sport);
  return fwd || rev;
}

/* content AND via the literal matcher — the correctness oracle for AC. */
static int
bn_content_memmem_ok (const struct bn_rule *r, const unsigned char *payload, int plen)
{
  for (int i = 0; i < r->ncontent; i++)
    if (!bn_memmem (payload, plen, r->content[i].bytes, r->content[i].len,
                    r->content[i].nocase))
      return 0;
  return 1;
}

static int
bn_pcre_all_ok (const struct bn_rule *r, const unsigned char *payload, int plen)
{
  for (int i = 0; i < r->npcre; i++)
    if (!bn_pcre_match_clause (&r->pcre[i], payload, plen))
      return 0;
  return 1;
}

/* Does rule r match this decoded packet? proto/ips net-order, ports host.
 * Literal-matcher path (AC off / fallback / oracle). */
static int
bn_rule_match (const struct bn_rule *r, int proto, uint32_t sip, uint32_t dip,
               int sport, int dport, const unsigned char *payload, int plen)
{
  return bn_header_match (r, proto, sip, dip, sport, dport)
      && bn_content_memmem_ok (r, payload, plen)
      && bn_pcre_all_ok (r, payload, plen);
}

static int
bn_block_seen (struct bn_scan_ctx *ctx, uint32_t sip, const char *action)
{
  for (int i = 0; i < ctx->nseen; i++)
    if (ctx->seen[i].sip == sip && !strcmp (ctx->seen[i].action, action))
      return 1;
  if (ctx->nseen >= BN_MAX_BLOCK_DEDUPE)
    return -1;
  ctx->seen[ctx->nseen].sip = sip;
  snprintf (ctx->seen[ctx->nseen].action, sizeof ctx->seen[ctx->nseen].action,
            "%s", action);
  ctx->nseen++;
  return 0;
}

static int
bn_run_bashfw_deny (const char *src_ip)
{
  char *const av[] = { (char *) "fw", (char *) "deny", (char *) src_ip, NULL };
  pid_t pid = fork ();
  if (pid < 0)
    { builtin_error ("blocking: fork fw: %s", strerror (errno)); return -1; }
  if (pid == 0)
    {
      execvp (av[0], av);
      fprintf (stderr, "netids: execvp fw: %s\n", strerror (errno));
      _exit (127);
    }
  int st = 0;
  while (waitpid (pid, &st, 0) < 0)
    {
      if (errno == EINTR) continue;
      builtin_error ("blocking: waitpid fw: %s", strerror (errno));
      return -1;
    }
  if (WIFEXITED (st)) return WEXITSTATUS (st);
  return 128;
}

static int
bn_block_event (struct bn_scan_ctx *ctx, const struct bn_rule *r, uint32_t sip,
                uint32_t dip, int proto, int sport, int dport,
                uint32_t ts_sec, uint32_t ts_usec)
{
  if (!ctx || !ctx->blocking_enabled)
    return 0;
  int seen = bn_block_seen (ctx, sip, r->action);
  if (seen > 0) return 0;
  if (seen < 0)
    {
      builtin_error ("blocking: dedupe table full (%d entries)", BN_MAX_BLOCK_DEDUPE);
      ctx->block_errors++;
      return -1;
    }

  char sbuf[INET_ADDRSTRLEN], dbuf[INET_ADDRSTRLEN];
  struct in_addr a; a.s_addr = sip; inet_ntop (AF_INET, &a, sbuf, sizeof sbuf);
  a.s_addr = dip; inet_ntop (AF_INET, &a, dbuf, sizeof dbuf);
  const char *pn = proto == IPPROTO_TCP ? "TCP" : proto == IPPROTO_UDP ? "UDP"
                 : proto == IPPROTO_ICMP ? "ICMP" : "IP";
  int fw_rc = 0;
  if (!ctx->dry_run)
    fw_rc = bn_run_bashfw_deny (sbuf);
  if (fw_rc != 0)
    ctx->block_errors++;
  ctx->blocks++;

  fprintf (ctx->out,
    "{\"timestamp\":%u.%06u,\"event_type\":\"block\",\"proto\":\"%s\","
    "\"src_ip\":\"%s\",\"src_port\":%d,\"dest_ip\":\"%s\",\"dest_port\":%d,"
    "\"action\":\"%s\",\"dry_run\":%s,\"bashfw_argv\":\"fw %sdeny %s\","
    "\"bashfw_rc\":%d,\"alert\":{\"signature\":\"%s\",\"signature_id\":%ld,"
    "\"rev\":%ld,\"category\":\"%s\"}}\n",
    ts_sec, ts_usec, pn, sbuf, sport, dbuf, dport, r->action,
    ctx->dry_run ? "true" : "false", ctx->dry_run ? "-n " : "", sbuf,
    fw_rc, r->msg[0] ? r->msg : "(no msg)", r->sid, r->rev,
    r->classtype[0] ? r->classtype : "uncategorized");
  return fw_rc == 0 ? 0 : -1;
}

/* ---- pcap offline reader ----------------------------------------- */

struct bn_pcap_gh { uint32_t magic; uint16_t vmaj, vmin; int32_t tz; uint32_t sig, snaplen, linktype; };
struct bn_pcap_rh { uint32_t ts_sec, ts_usec, incl_len, orig_len; };

static uint32_t bn_swap32 (uint32_t v)
{ return ((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v >> 8) & 0xff00) | ((v >> 24) & 0xff); }

static int
bn_parse_positive_int (const char *s, int *out)
{
  char *end = NULL;
  if (!s || !*s) return -1;
  errno = 0;
  long v = strtol (s, &end, 10);
  if (errno || (end && *end) || v <= 0 || v > 1000000)
    return -1;
  *out = (int) v;
  return 0;
}

static int
bn_parse_timeout (const char *s, double *out)
{
  char *end = NULL;
  if (!s || !*s) return -1;
  errno = 0;
  double v = strtod (s, &end);
  if (errno || (end && *end) || v < 0.1 || v > 3600.0)
    return -1;
  *out = v;
  return 0;
}

/* Decode one captured frame (Ethernet or RAW IPv4) and test it against every
 * rule, writing alerts to `out`. ts_* for the alert timestamp. */
static int
bn_scan_frame (struct bn_scan_ctx *ctx, uint32_t linktype, const unsigned char *frame, int flen,
               uint32_t ts_sec, uint32_t ts_usec)
{
  const unsigned char *ip = NULL; int iplen = 0;
  if (linktype == 1)              /* LINKTYPE_ETHERNET */
    {
      if (flen < 14) return 0;
      uint16_t et = (uint16_t) ((frame[12] << 8) | frame[13]);
      if (et != 0x0800) return 0;            /* IPv4 only (first promotion) */
      ip = frame + 14; iplen = flen - 14;
    }
  else if (linktype == 101)       /* LINKTYPE_RAW */
    { ip = frame; iplen = flen; }
  else
    return 0;                                /* unsupported linktype */

  if (iplen < 20) return 0;
  if ((ip[0] >> 4) != 4) return 0;           /* IPv4 only */
  int ihl = (ip[0] & 0x0f) * 4;
  if (ihl < 20 || ihl > iplen) return 0;
  int proto = ip[9];
  uint32_t sip, dip; memcpy (&sip, ip + 12, 4); memcpy (&dip, ip + 16, 4);
  uint16_t tot = (uint16_t) ((ip[2] << 8) | ip[3]);
  if (tot > iplen) tot = (uint16_t) iplen;   /* clamp to captured length */
  const unsigned char *l4 = ip + ihl; int l4len = tot - ihl;
  if (l4len < 0) l4len = 0;
  int sport = 0, dport = 0; const unsigned char *payload = l4; int plen = l4len;

  if (proto == IPPROTO_TCP && l4len >= 20)
    { sport = (l4[0] << 8) | l4[1]; dport = (l4[2] << 8) | l4[3];
      int doff = (l4[12] >> 4) * 4; if (doff < 20 || doff > l4len) doff = 20;
      payload = l4 + doff; plen = l4len - doff; }
  else if (proto == IPPROTO_UDP && l4len >= 8)
    { sport = (l4[0] << 8) | l4[1]; dport = (l4[2] << 8) | l4[3];
      payload = l4 + 8; plen = l4len - 8; }
  /* ICMP / other: no ports, whole l4 is payload. */
  if (plen < 0) plen = 0;

  /* AC path: scan the payload once for every literal content pattern. */
  if (bn_ac_active) bn_ac_scan_payload (payload, plen);

  int alerts = 0;
  for (int i = 0; i < bn_nrules; i++)
    {
      struct bn_rule *r = &bn_rules[i];
      if (!strcmp (r->action, "pass")) continue;
      if (bn_ac_active)
        {
          if (!bn_header_match (r, proto, sip, dip, sport, dport)) continue;
          int cok = bn_ac_content_ok (i);
          if (bn_ac_verify
              && cok != bn_content_memmem_ok (r, payload, plen))
            {
              builtin_error ("netids: Aho-Corasick/literal divergence on sid %ld "
                             "(ac=%d) — failing closed", r->sid, cok);
              return -1;
            }
          if (!cok) continue;
          if (!bn_pcre_all_ok (r, payload, plen)) continue;
        }
      else if (!bn_rule_match (r, proto, sip, dip, sport, dport, payload, plen))
        continue;
      if (!strcmp (r->action, "drop") || !strcmp (r->action, "reject"))
        {
          if (bn_block_event (ctx, r, sip, dip, proto, sport, dport, ts_sec, ts_usec) < 0)
            return -1;
          continue;
        }
      if (strcmp (r->action, "alert")) continue;
      char sbuf[INET_ADDRSTRLEN], dbuf[INET_ADDRSTRLEN];
      struct in_addr a; a.s_addr = sip; inet_ntop (AF_INET, &a, sbuf, sizeof sbuf);
      a.s_addr = dip; inet_ntop (AF_INET, &a, dbuf, sizeof dbuf);
      const char *pn = proto == IPPROTO_TCP ? "TCP" : proto == IPPROTO_UDP ? "UDP"
                     : proto == IPPROTO_ICMP ? "ICMP" : "IP";
      /* schema-level eve.json (one object/line) — NOT byte-compat (§10). */
      fprintf (ctx->out,
        "{\"timestamp\":%u.%06u,\"event_type\":\"alert\",\"proto\":\"%s\","
        "\"src_ip\":\"%s\",\"src_port\":%d,\"dest_ip\":\"%s\",\"dest_port\":%d,"
        "\"alert\":{\"signature\":\"%s\",\"signature_id\":%ld,\"rev\":%ld,"
        "\"category\":\"%s\"}}\n",
        ts_sec, ts_usec, pn, sbuf, sport, dbuf, dport,
        r->msg[0] ? r->msg : "(no msg)", r->sid, r->rev,
        r->classtype[0] ? r->classtype : "uncategorized");
      alerts++;
      if (ctx) ctx->alerts++;
    }
  return alerts;
}

static int
bn_scan_pcap (const char *path, struct bn_scan_ctx *ctx)
{
  FILE *f = fopen (path, "rb");
  if (!f) { builtin_error ("scan: cannot open %s: %s", path, strerror (errno)); return -1; }
  struct bn_pcap_gh gh;
  if (fread (&gh, 1, sizeof gh, f) != sizeof gh)
    { builtin_error ("scan: %s: short global header", path); fclose (f); return -1; }
  int swap = 0;
  if (gh.magic == BN_PCAP_MAGIC_SWAP) swap = 1;
  else if (gh.magic != BN_PCAP_MAGIC_USEC && gh.magic != BN_PCAP_MAGIC_NSEC)
    { builtin_error ("scan: %s: bad pcap magic 0x%08x", path, (unsigned) gh.magic);
      fclose (f); return -1; }
  uint32_t linktype = swap ? bn_swap32 (gh.linktype) : gh.linktype;
  int nsec = (gh.magic == BN_PCAP_MAGIC_NSEC) || (swap && gh.magic == BN_PCAP_MAGIC_SWAP);
  (void) nsec;

  static unsigned char frame[BN_SNAP_CAP];
  struct bn_pcap_rh rh;
  long total_alerts = 0, npkts = 0;
  while (fread (&rh, 1, sizeof rh, f) == sizeof rh)
    {
      uint32_t incl = swap ? bn_swap32 (rh.incl_len) : rh.incl_len;
      uint32_t tss  = swap ? bn_swap32 (rh.ts_sec)  : rh.ts_sec;
      uint32_t tsu  = swap ? bn_swap32 (rh.ts_usec) : rh.ts_usec;
      if (incl > BN_SNAP_CAP)
        { builtin_error ("scan: %s: oversize record (%u) — truncating snap", path, incl);
          incl = BN_SNAP_CAP; }
      if (fread (frame, 1, incl, f) != incl) break;     /* truncated tail */
      int n = bn_scan_frame (ctx, linktype, frame, (int) incl, tss, tsu);
      if (n < 0) { fclose (f); return -1; }
      total_alerts += n;
      npkts++;
    }
  fclose (f);
  fprintf (stderr, "netids: %ld packet(s), %ld alert(s), %ld block(s)\n",
           npkts, total_alerts, ctx ? ctx->blocks : 0);
  return (int) total_alerts;
}

struct bn_live_scan_ctx {
  struct bn_scan_ctx *scan;
  long packets;
};

static int
bn_live_frame_cb (const struct bashpcap_frame *frame, void *userdata)
{
  struct bn_live_scan_ctx *ctx = userdata;
  if (!ctx || !frame || !frame->data) return -1;
  int n = bn_scan_frame (ctx->scan, frame->linktype, frame->data,
                         (int) frame->caplen, frame->ts_sec,
                         frame->ts_usec);
  if (n < 0) return -1;
  ctx->packets++;
  (void) frame->origlen;
  return 0;
}

static int
bn_scan_live (const char *iface, struct bn_scan_ctx *scan, int count, double timeout_s)
{
  struct bashpcap_capture_opts opts;
  memset (&opts, 0, sizeof opts);
  opts.iface = iface;
  opts.count = count;
  opts.snaplen = BN_SNAP_CAP - 1;
  opts.timeout_s = timeout_s;
  /* Passive live capture retains A4's post-open CAP_NET_RAW drop. Active
     inline blocking needs CAP_NET_ADMIN in the later fw child, so keep
     capabilities only for non-dry-run blocking scans. */
  opts.keep_caps = (scan && scan->blocking_enabled && !scan->dry_run) ? 1 : 0;

  struct bn_live_scan_ctx ctx;
  memset (&ctx, 0, sizeof ctx);
  ctx.scan = scan;

  int got = bashpcap_capture_frames (&opts, bn_live_frame_cb, &ctx);
  if (got < 0) return -1;
  fprintf (stderr, "netids: %ld live packet(s), %ld alert(s), %ld block(s)\n",
           ctx.packets, scan ? scan->alerts : 0, scan ? scan->blocks : 0);
  return scan && scan->block_errors ? -1 : (int) (scan ? scan->alerts : 0);
}

/* ---- builtin entry ----------------------------------------------- */

static FILE *
bn_open_out (const char *path)
{
  if (!path || !strcmp (path, "-")) return stdout;
  FILE *f = fopen (path, "w");
  return f;
}

int
netids_builtin (WORD_LIST *list)
{
  char *argv[64]; int argc = 0;
  for (WORD_LIST *p = list; p && argc < 64; p = p->next) argv[argc++] = p->word->word;
  if (argc == 0) { builtin_usage (); return EX_USAGE; }
  const char *cmd = argv[0];
  int opt_start = 1;

  if (!strcmp (cmd, "-h") || !strcmp (cmd, "--help"))
    { builtin_usage (); return EXECUTION_SUCCESS; }
  if (argv[0][0] == '-') {
    cmd = "scan";                 /* shorthand: netids -i IFACE ... */
    opt_start = 0;
  }

  if (!strcmp (cmd, "--version") || !strcmp (cmd, "-V"))
    { printf ("netids (bash-os AUDIT-6.4 A5 A6) NetIDS; Suricata subset, "
              "offline -r + live -i, pcre opt-in, blocking opt-in\n"); return EXECUTION_SUCCESS; }
  /* parse -S RULES / -r PCAP / -i IFACE / -o EVE */
  const char *rules = NULL, *pcap = NULL, *iface = NULL, *outp = NULL;
  int enable_pcre = bn_pcre_enabled_env ();
  int enable_blocking = bn_env_truthy ("BASHNETIDS_ENABLE_BLOCKING");
  int dry_run = bn_env_truthy ("NETIDS_DRY_RUN");
  int live_count = BN_DEFAULT_LIVE_COUNT;
  double live_timeout = BN_DEFAULT_LIVE_TIMEOUT;
  int saw_live_count = 0, saw_live_timeout = 0;
  for (int i = opt_start; i < argc; i++)
    {
      if (!strcmp (argv[i], "-S") && i + 1 < argc) rules = argv[++i];
      else if (!strcmp (argv[i], "-r") && i + 1 < argc) pcap = argv[++i];
      else if (!strcmp (argv[i], "-i") && i + 1 < argc) iface = argv[++i];
      else if (!strcmp (argv[i], "-o") && i + 1 < argc) outp = argv[++i];
      else if (!strcmp (argv[i], "--enable-pcre")) enable_pcre = 1;
      else if (!strcmp (argv[i], "--enable-blocking")) enable_blocking = 1;
      else if (!strcmp (argv[i], "--dry-run")) dry_run = 1;
      else if (!strcmp (argv[i], "--version") || !strcmp (argv[i], "-V"))
        { printf ("netids (bash-os AUDIT-6.4 A5 A6) NetIDS; Suricata subset, "
                  "offline -r + live -i, pcre opt-in, blocking opt-in\n"); return EXECUTION_SUCCESS; }
      else if (!strcmp (argv[i], "-h") || !strcmp (argv[i], "--help"))
        { builtin_usage (); return EXECUTION_SUCCESS; }
      else if ((!strcmp (argv[i], "--count") || !strcmp (argv[i], "-c")) && i + 1 < argc)
        {
          if (bn_parse_positive_int (argv[++i], &live_count) < 0)
            { builtin_error ("%s: bad --count value: %s", cmd, argv[i]); return EX_USAGE; }
          saw_live_count = 1;
        }
      else if ((!strcmp (argv[i], "--timeout") || !strcmp (argv[i], "-W")) && i + 1 < argc)
        {
          if (bn_parse_timeout (argv[++i], &live_timeout) < 0)
            { builtin_error ("%s: bad --timeout value: %s", cmd, argv[i]); return EX_USAGE; }
          saw_live_timeout = 1;
        }
      else { builtin_error ("%s: unexpected arg: %s", cmd, argv[i]); return EX_USAGE; }
    }

  if (!strcmp (cmd, "compile"))
    {
      if (!rules) { builtin_error ("compile: -S RULES required"); return EX_USAGE; }
      bn_rules_free ();
      if (bn_load_rules (rules, enable_pcre, enable_blocking) < 0) { bn_rules_free (); return 2; }
      printf ("compiled %d rule(s)\n", bn_nrules);
      bn_rules_free ();
      return EXECUTION_SUCCESS;
    }
  if (!strcmp (cmd, "scan"))
    {
      if (!rules) { builtin_error ("scan: -S RULES required"); return EX_USAGE; }
      if ((pcap && iface) || (!pcap && !iface))
        { builtin_error ("scan: choose exactly one of -r PCAP or -i IFACE"); return EX_USAGE; }
      if (pcap && (saw_live_count || saw_live_timeout))
        { builtin_error ("scan: --count/--timeout are live -i options"); return EX_USAGE; }
      if (enable_blocking && pcap && !dry_run)
        { builtin_error ("scan: offline blocking requires --dry-run or NETIDS_DRY_RUN=1"); return EX_USAGE; }
      bn_rules_free ();
      bn_ac_free ();
      if (bn_load_rules (rules, enable_pcre, enable_blocking) < 0) { bn_rules_free (); return 2; }
      /* A7: optionally build the Aho-Corasick content matcher (auto/on/off). */
      bn_ac_verify = bn_env_truthy ("BASHNETIDS_AC_VERIFY");
      {
        const char *acm = getenv ("BASHNETIDS_AC");
        if (!acm || !*acm) acm = "auto";
        int want_ac;
        if (!strcmp (acm, "off")) want_ac = 0;
        else if (!strcmp (acm, "on")) want_ac = 1;
        else want_ac = (unsigned) bn_ac_count_patterns ()
                       >= bn_env_uint ("BASHNETIDS_AC_MIN_PATTERNS",
                                       BN_AC_DEFAULT_MIN_PATTERNS, 1, 1000000);
        if (want_ac)
          {
            if (bn_ac_build () == 0) bn_ac_active = 1;
            else { bn_ac_free ();
                   builtin_error ("netids: Aho-Corasick build hit limits; "
                                  "using literal matcher"); }
          }
      }
      FILE *out = bn_open_out (outp);
      if (!out) { builtin_error ("scan: cannot open output: %s", strerror (errno));
        bn_rules_free (); bn_ac_free (); return EXECUTION_FAILURE; }
      struct bn_scan_ctx scan;
      memset (&scan, 0, sizeof scan);
      scan.out = out;
      scan.blocking_enabled = enable_blocking;
      scan.dry_run = dry_run;
      scan.live_mode = iface != NULL;
      int rc = pcap ? bn_scan_pcap (pcap, &scan)
                    : bn_scan_live (iface, &scan, live_count, live_timeout);
      if (out != stdout) fclose (out);
      bn_rules_free ();
      bn_ac_free ();
      return rc < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    }

  builtin_error ("unknown verb: %s (try compile/scan/--version)", cmd);
  return EX_USAGE;
}

char *netids_doc[] = {
  "Network IDS (Suricata/Snort-class) — AUDIT-6.4/A5/A6.",
  "",
  "    netids compile -S RULES [--enable-pcre] [--enable-blocking]",
  "        parse+compile; out-of-subset -> exit 2.",
  "    netids scan -r PCAP -S RULES [-o EVE] [--enable-pcre]",
  "        [--enable-blocking --dry-run]",
  "    netids scan -i IFACE -S RULES [-o EVE] [--count N] [--timeout SEC]",
  "        [--enable-pcre] [--enable-blocking] [--dry-run]",
  "    netids -i IFACE -S RULES [-o EVE] [--count N] [--timeout SEC]",
  "        Decode a pcap savefile (Ethernet/RAW, IPv4, TCP/UDP/ICMP), content-",
  "        match live or offline frames, emit schema-level eve.json alerts/block events.",
  "    netids --version",
  "",
  "Suricata subset: 'action proto sip sport -> dip dport (msg/content[+nocase]/",
  "pcre/sid/rev/classtype/reference)'. drop/reject require --enable-blocking or",
  "BASHNETIDS_ENABLE_BLOCKING=1; offline blocking also requires --dry-run or",
  "NETIDS_DRY_RUN=1. pcre requires --enable-pcre or BASHNETIDS_ENABLE_PCRE=1.",
  "Rejected: lua/flowbits/threshold/byte_test/dsize and flow beyond established.",
  "live mode needs CAP_NET_RAW; live firewall mutation needs fw/backend access.",
  "eve.json is schema-level, not byte-compat.",
  "BASHNETIDS_AC=auto|on|off: single-pass Aho-Corasick literal content matcher",
  "(default auto = on when >= BASHNETIDS_AC_MIN_PATTERNS=32 content clauses);",
  "BASHNETIDS_AC_VERIFY=1 cross-checks every verdict vs the literal matcher.",
  (char *) NULL
};

struct builtin netids_struct = {
  "netids",
  netids_builtin,
  BUILTIN_ENABLED,
  netids_doc,
  "netids compile|scan|--version [-S RULES] [-r PCAP|-i IFACE] [-o EVE] [--enable-pcre] [--enable-blocking] [--dry-run]",
  0
};
