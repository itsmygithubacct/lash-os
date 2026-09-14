/* SPDX-License-Identifier: MIT */
/* dns.c — DNS over UDP via hand-rolled RFC 1035. Loadable for bash.
 *
 * /dev/tcp/HOST/PORT does kernel resolution implicitly for connect.
 * For MX/TXT/AAAA/CNAME/PTR/etc. queries, scripts had to fork to dig
 * or drill — neither shipped with pure or bash-os. dns is a
 * minimal stub resolver: builds a query packet, sends UDP to the
 * configured nameserver, parses the response, prints one line per
 * answer record.
 *
 * Subcommands:
 *   dns A     HOST     IPv4 addresses (one per line)
 *   dns AAAA  HOST     IPv6 addresses
 *   dns CNAME HOST     canonical name
 *   dns NS    DOMAIN   nameservers
 *   dns MX    DOMAIN   "PRIORITY HOSTNAME" per line
 *   dns TXT   DOMAIN   one record per line, surrounding quotes stripped
 *   dns PTR   ADDR     reverse lookup; ADDR is dotted IPv4
 *   dns SOA   DOMAIN   "MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINTTL"
 *   dns query HOST TYPE [-s SERVER] [-t TIMEOUT_MS] [-d|--dnssec] [--require-ad] [--validate] [--skew SEC] [--dot [-h DOT_HOST[:PORT]]] [--dot-ca PEM] [--doh [URL]]
 *   dns auth-serve ... [--tsig-key NAME:hmac-sha256:BASE64] [--require-tsig] [--no-rrl]
 *                          [--view NAME:CIDR[,CIDR...]:DIR] [--rpz FILE]
 *   dns resolver-serve ... [--rpz FILE] [--dns64 PREFIX/96]
 *   dns notify --zone NAME --to IP[:PORT]... [--tsig-key NAME:hmac-sha256:BASE64]
 *   dns update --server IP[:PORT] --zone NAME ... [--tsig-key NAME:hmac-sha256:BASE64]
 *   dns slave-verify-chain --zone FILE --key NAME:hmac-sha256:BASE64
 *   dns trust-anchor
 *   dns chain HOST
 *
 * Common flags:
 *   -s SERVER       nameserver (default: first from /etc/resolv.conf)
 *   -t TIMEOUT_MS   socket recv timeout (default 2000)
 *   --validate      run a local iterative RRSIG chain walk back to the
 *                   configured trust anchor. Independent of --require-ad
 *                   (the AD bit is ignored when --validate is set).
 *   --skew SEC      RRSIG inception/expiration skew tolerance in seconds
 *                   (default 300; tests use 0 to remove the grace window)
 *
 * Environment hooks:
 *   BASHDNS_VALIDATE=1     enable -d (DNSSEC RR request + AD-bit reporting)
 *   BASHDNS_REQUIRE_AD=1   enable --require-ad
 *   BASHDNS_TRUST_ANCHOR=PATH  pre-load a trust-anchor file
 *   BASHDNS_FIXTURE_DIR=DIR    swap wire fetch for fixture file reads;
 *                              format <NAME>.<TYPE>.bin (raw DNS reply
 *                              payload). Used by hermetic tests.
 *   BASHDNS_0X20=0             disable DNS-0x20 query-name case
 *                              randomization on real upstream fetches.
 *   BASHDNS_DOT=1              enable --dot from env
 *   BASHDNS_DOT_HOST=HOST[:PORT]  default DoT host (else 1.1.1.1:853)
 *   BASHDNS_DOT_CMD=cmd        replace `crypto tls connect ...`
 *                              for hermetic DoT tests (stub reads
 *                              TCP-framed query on stdin, writes
 *                              TCP-framed reply on stdout)
 *   BASHDNS_DOT_ACCEPT_CMD=cmd replace the server-side TLS accept seam
 *                              for hermetic DoT tests (stub reads/writes
 *                              plaintext TCP-framed DNS)
 *   BASHDNS_DOH=1              enable --doh from env
 *   BASHDNS_DOH_URL=URL        default DoH endpoint
 *                              (else https://cloudflare-dns.com/dns-query)
 *   BASHDNS_DOH_CMD=cmd        replace `curl ...` for hermetic DoH
 *                              tests (stub reads raw DNS query on stdin,
 *                              writes raw DNS reply on stdout)
 *   BASHDNS_SERVER_PORT=N      UDP/TCP nameserver port for hermetic tests
 *                              (default 53)
 *   BASHDNS_RATELIMIT_QPS=N    per-upstream-resolver token-bucket cap
 *                              (default 50; N=0 disables; malformed
 *                              values fall back to the default)
 *
 * Limitations:
 *   - UDP/TCP transport sniffs IPv4 vs IPv6 literals. auth-serve and
 *     resolver-serve default to IPv4 loopback, accept --inet6 for IPv6
 *     loopback, and clear IPV6_V6ONLY by default on IPv6 listeners; use
 *     --v6only for a v6-only listener.
 *   - DNSSEC v2 adds an iterative chain validator for the modern
 *     algorithm subset (5/7/8/10/13/14/15/16). Negative answers are
 *     accepted only with signed NSEC/NSEC3 denial proofs; malformed
 *     bitmaps, unsupported NSEC3 hash algorithms, opt-out, and wildcard
 *     expansion proofs fail closed.
 *   - One query attempt per configured nameserver. `search`/`domain`
 *     and `options ndots:N` are honored for query ordering.
 *   - Response truncation (TC bit) falls back to TCP against the same
 *     nameserver.
 *
 * DNS policy engines (F02, all default-off — absent the flag, behavior is
 * byte-identical to the pre-change answer path):
 *   - Split-horizon views (auth): --view NAME:CIDR[,CIDR...]:DIR (repeatable).
 *     The first view (declaration order) whose CIDR set matches the client
 *     peer answers from that view's DIR/*.zone set; otherwise the global
 *     zones answer. v4 and v6 peers supported.
 *   - RPZ (auth + resolver): --rpz FILE (repeatable). A normal master file
 *     whose owner names encode triggers. Supported triggers: QNAME (exact
 *     and *.suffix) and CLIENT-IP (rpz-client-ip, exact host). Actions:
 *     CNAME "."  -> NXDOMAIN; CNAME "*." -> NODATA;
 *     CNAME "rpz-passthru." -> PASSTHRU; an A/AAAA/CNAME RR -> local data.
 *     Consulted before normal resolution; a match short-circuits.
 *   - DNS64 (resolver): --dns64 PREFIX/96. On an AAAA query with no native
 *     AAAA (NODATA/NXDOMAIN), re-query A and synthesize AAAA into the /96
 *     prefix. TTL preserved; private/special IPv4 space is not synthesized.
 *   Limitation: the TLS-wrapped transports (DoH/DoT/DoQ) carry no peer
 *   sockaddr in struct bda_conn, so split-horizon view selection and RPZ
 *   CLIENT-IP triggers do not match on those transports in this slice
 *   (peer is NULL). RPZ QNAME triggers still apply on all transports.
 *
 * Companion docs:
 *     /docs/bash/dns.txt
 *     /bash-os/dig.sh — wrapper with dig-flavored output
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
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
#include <math.h>
#include <fcntl.h>
#include <time.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <dirent.h>

#include "loadables.h"
#include "_mbedtls_ssl.h"
#include "_mbedtls_x509_crt.h"
#include "_mbedtls_pk.h"
#include "_mbedtls_net_sockets.h"
#include "_mbedtls_error.h"
#include "_mbedtls_crypto.h"
#include "_mbedtls_hmac.h"

#if defined(BASH_OS_DOQ)
#  include <ngtcp2/ngtcp2.h>
#  include <ngtcp2/ngtcp2_crypto.h>
#  include <ngtcp2/ngtcp2_crypto_boringssl.h>
#  include <openssl/ssl.h>
#  include <openssl/rand.h>
#  include <openssl/err.h>
#endif

/* DNS RR type constants. */
#define BD_T_A      1
#define BD_T_NS     2
#define BD_T_CNAME  5
#define BD_T_SOA    6
#define BD_T_PTR    12
#define BD_T_MX     15
#define BD_T_TXT    16
#define BD_T_AAAA   28
#define BD_T_DNAME  39
#define BD_T_DS     43
#define BD_T_RRSIG  46
#define BD_T_NSEC   47
#define BD_T_DNSKEY 48
#define BD_T_NSEC3  50
#define BD_T_NSEC3PARAM 51
#define BD_T_SVCB   64
#define BD_T_HTTPS  65
#define BD_T_TSIG   250

#define BD_T_IXFR   251
#define BD_T_AXFR   252
#define BD_T_ANY    255

#define BD_C_IN     1
#define BD_C_NONE   254
#define BD_C_ANY    255

#define BD_RCODE_NOERROR  0
#define BD_RCODE_FORMERR  1
#define BD_RCODE_NXDOMAIN 3
#define BD_RCODE_NOTIMP   4
#define BD_RCODE_REFUSED  5
#define BD_RCODE_YXDOMAIN 6
#define BD_RCODE_YXRRSET  7
#define BD_RCODE_NXRRSET  8
#define BD_RCODE_NOTAUTH  9

#define BD_NSEC3_MAX_ITERATIONS 150
#define BD_DOH_WIRE_MAX 65535
#define BDA_H2_MAX_FRAME 65535
#define BDA_H2_PREFACE1 "PRI * HTTP/2.0\r\n\r\n"
#define BDA_H2_PREFACE1_LEN 18
#define BDA_H2_PREFACE2 "SM\r\n\r\n"
#define BDA_H2_PREFACE2_LEN 6

/* SvcParamKey numbers (RFC 9460 §14.3.2). */
#define BD_SVCB_MANDATORY      0
#define BD_SVCB_ALPN           1
#define BD_SVCB_NO_DEFAULT_ALPN 2
#define BD_SVCB_PORT           3
#define BD_SVCB_IPV4HINT       4
#define BD_SVCB_ECH            5
#define BD_SVCB_IPV6HINT       6
#define BD_SVCB_DOHPATH        7

/* DNSSEC algorithm IDs (RFC 8624 + IANA). */
#define BD_ALG_RSASHA1        5
#define BD_ALG_RSASHA1_NSEC3  7
#define BD_ALG_RSASHA256      8
#define BD_ALG_RSASHA512     10
#define BD_ALG_ECDSAP256SHA256 13
#define BD_ALG_ECDSAP384SHA384 14
#define BD_ALG_ED25519        15
#define BD_ALG_ED448          16

/* DS digest types. */
#define BD_DS_DIGEST_SHA1    1
#define BD_DS_DIGEST_SHA256  2
#define BD_DS_DIGEST_SHA384  4

#define BD_TRUST_ANCHOR_DEFAULT \
  "root . key-tag=20326 algorithm=8 flags=257 protocol=3 digest-sha256=e06d44b80b8f1d21a... source=built-in-iana-ksk-2017"

static char bd_runtime_trust_anchor[512];

/* Structured trust set populated by trust-anchor-load. Each entry is
   either a DS (parent's hash of child DNSKEY) or a DNSKEY (a key
   trusted by fiat). The chain walker consumes these to bootstrap. */
typedef struct {
  char     owner[256];   /* lowercased, trailing-dot trimmed */
  int      kind;          /* BD_T_DS or BD_T_DNSKEY */
  /* DS fields */
  uint16_t key_tag;
  uint8_t  algorithm;
  uint8_t  digest_type;
  unsigned char digest[64];
  size_t        digest_len;
  /* DNSKEY fields */
  uint16_t flags;
  uint8_t  protocol;
  unsigned char rdata[2048];   /* full DNSKEY rdata (flags||proto||algo||pubkey) */
  size_t        rdata_len;
} bd_trust_t;

#define BD_TRUST_MAX 16
static bd_trust_t bd_trust_set[BD_TRUST_MAX];
static int        bd_trust_count = 0;

static int bd_tc_bit (const unsigned char *reply, size_t rlen);
static int bd_validate_reply (const unsigned char *reply, size_t rlen, uint16_t id);
static int bd_query_tcp (const unsigned char *query, size_t qlen, const char *server,
                         int timeout_ms, unsigned char *reply, size_t reply_sz);
static int bd_query_dot (const unsigned char *query, size_t qlen, const char *dot_host,
                         int port, const char *ca_path, int timeout_ms,
                         unsigned char *reply, size_t reply_sz);
static int bd_query_doh (const unsigned char *query, size_t qlen, const char *url,
                         int timeout_ms, unsigned char *reply, size_t reply_sz);

/* DoT context — set by bd_query_cmd when --dot is in effect so bd_fetch
 * routes wire requests through bd_query_dot rather than UDP. Cleared on
 * return so subsequent invocations of the builtin start clean. */
static struct {
  int        active;
  char       host[256];
  int        port;
  char       ca_path[256];
} bd_dot_ctx;

/* DNS-over-HTTPS context. Explicit only: --doh, BASHDNS_DOH=1, or
 * BASHDNS_DOH_URL. */
static struct {
  int        active;
  char       url[2048];
} bd_doh_ctx;

struct bd_child_guard {
  struct sigaction old_chld;
  sigset_t oldmask;
};

static int
bd_child_guard_begin (struct bd_child_guard *g)
{
  struct sigaction dfl;
  sigset_t block;
  memset (&dfl, 0, sizeof dfl);
  dfl.sa_handler = SIG_DFL;
  sigemptyset (&dfl.sa_mask);
  if (sigaction (SIGCHLD, &dfl, &g->old_chld) < 0)
    return -1;
  sigemptyset (&block);
  sigaddset (&block, SIGCHLD);
  if (sigprocmask (SIG_BLOCK, &block, &g->oldmask) < 0)
    {
      sigaction (SIGCHLD, &g->old_chld, NULL);
      return -1;
    }
  return 0;
}

static void
bd_child_guard_parent_end (struct bd_child_guard *g)
{
  sigprocmask (SIG_SETMASK, &g->oldmask, NULL);
  sigaction (SIGCHLD, &g->old_chld, NULL);
}

static void
bd_child_guard_child_end (struct bd_child_guard *g)
{
  sigprocmask (SIG_SETMASK, &g->oldmask, NULL);
}

/* ---- Per-upstream-resolver rate limit (token bucket) -------------- *
 *
 * Stage 39 hardening (Round 1778631147 w1 Doc 2,
 * `dns-resolver-rate-limit`).
 *
 * Production deployments resolve through a small set of upstream
 * resolvers (one or two in /etc/resolv.conf, plus optional DoT host).
 * Without a cap, a script in a tight loop will hammer that upstream
 * at the bash-fork rate and earn a BFR (block-for-resolver) on the
 * carrier side. A simple token bucket per upstream keeps query rate
 * inside a configurable budget.
 *
 * Configuration:
 *   BASHDNS_RATELIMIT_QPS=N  per-upstream queries-per-second cap
 *                            (default 50; N=0 disables the limiter;
 *                            non-numeric input falls back to 50).
 *
 * Bucket capacity equals the configured QPS, so up to QPS queries
 * may burst without delay before the bucket gates. Refill is
 * monotonic-clock based; CLOCK_MONOTONIC is unaffected by wall-time
 * jumps. Buckets are keyed by upstream string (server IP for UDP/TCP,
 * dot_host for DoT) with a small fixed pool — the LRU slot is reused
 * if more than BD_RL_BUCKETS distinct upstreams appear in one process.
 *
 * Call sites: bd_fetch invokes bd_ratelimit_acquire() once per
 * outbound query, after the fixture-load fast-path. Fixture-backed
 * tests therefore bypass rate limiting entirely (no upstream is
 * contacted); only real UDP/TCP/DoT calls pay the cost. */
#define BD_RL_BUCKETS 8

typedef struct {
  char            key[256];
  double          tokens;
  struct timespec last_refill;
  int             in_use;
  unsigned        seq;        /* LRU stamp */
} bd_rl_bucket_t;

static bd_rl_bucket_t bd_rl_buckets[BD_RL_BUCKETS];
static unsigned       bd_rl_seq = 0;

static double
bd_ratelimit_qps (void)
{
  const char *env = getenv ("BASHDNS_RATELIMIT_QPS");
  if (!env || !*env) return 50.0;
  char *end = NULL;
  errno = 0;
  double v = strtod (env, &end);
  if (end == env || !end || *end != '\0' || errno == ERANGE ||
      !isfinite (v) || v < 0.0 || v > 1000000.0)
    return 50.0;  /* malformed value → silently fall back to default */
  return v;
}

static bd_rl_bucket_t *
bd_ratelimit_bucket (const char *key, double qps)
{
  bd_rl_bucket_t *empty = NULL;
  bd_rl_bucket_t *oldest = &bd_rl_buckets[0];
  for (int i = 0; i < BD_RL_BUCKETS; i++)
    {
      bd_rl_bucket_t *b = &bd_rl_buckets[i];
      if (b->in_use && strcmp (b->key, key) == 0)
        { b->seq = ++bd_rl_seq; return b; }
      if (!empty && !b->in_use) empty = b;
      if (b->seq < oldest->seq) oldest = b;
    }
  bd_rl_bucket_t *slot = empty ? empty : oldest;
  memset (slot, 0, sizeof *slot);
  slot->in_use = 1;
  slot->seq = ++bd_rl_seq;
  strncpy (slot->key, key, sizeof slot->key - 1);
  slot->key[sizeof slot->key - 1] = '\0';
  slot->tokens = qps;  /* start full so a single query is never blocked */
  clock_gettime (CLOCK_MONOTONIC, &slot->last_refill);
  return slot;
}

/* Acquire one token from the per-upstream bucket, sleeping in short
 * increments until a token becomes available. QPS=0 disables. */
static void
bd_ratelimit_acquire (const char *key)
{
  if (!key || !*key) return;
  double qps = bd_ratelimit_qps ();
  if (qps <= 0.0) return;
  bd_rl_bucket_t *b = bd_ratelimit_bucket (key, qps);
  for (;;)
    {
      struct timespec now;
      clock_gettime (CLOCK_MONOTONIC, &now);
      double elapsed = (double) (now.tv_sec - b->last_refill.tv_sec)
                     + (double) (now.tv_nsec - b->last_refill.tv_nsec) / 1e9;
      if (elapsed > 0.0)
        {
          b->tokens += elapsed * qps;
          if (b->tokens > qps) b->tokens = qps;  /* cap burst = qps */
          b->last_refill = now;
        }
      if (b->tokens >= 1.0)
        { b->tokens -= 1.0; return; }
      double wait_s = (1.0 - b->tokens) / qps;
      if (wait_s < 0.001) wait_s = 0.001;
      if (wait_s > 1.0)   wait_s = 1.0;
      struct timespec ts;
      ts.tv_sec  = (time_t) wait_s;
      ts.tv_nsec = (long) ((wait_s - (double) ts.tv_sec) * 1e9);
      nanosleep (&ts, NULL);
    }
}

static int
bd_type_from_name (const char *s, uint16_t *out)
{
  if (strcasecmp (s, "A")     == 0) { *out = BD_T_A;     return 0; }
  if (strcasecmp (s, "AAAA")  == 0) { *out = BD_T_AAAA;  return 0; }
  if (strcasecmp (s, "NS")    == 0) { *out = BD_T_NS;    return 0; }
  if (strcasecmp (s, "CNAME") == 0) { *out = BD_T_CNAME; return 0; }
  if (strcasecmp (s, "DNAME") == 0) { *out = BD_T_DNAME; return 0; }
  if (strcasecmp (s, "SOA")   == 0) { *out = BD_T_SOA;   return 0; }
  if (strcasecmp (s, "PTR")   == 0) { *out = BD_T_PTR;   return 0; }
  if (strcasecmp (s, "MX")    == 0) { *out = BD_T_MX;    return 0; }
  if (strcasecmp (s, "TXT")   == 0) { *out = BD_T_TXT;   return 0; }
  if (strcasecmp (s, "DS")    == 0) { *out = BD_T_DS;    return 0; }
  if (strcasecmp (s, "RRSIG") == 0) { *out = BD_T_RRSIG; return 0; }
  if (strcasecmp (s, "NSEC")  == 0) { *out = BD_T_NSEC;  return 0; }
  if (strcasecmp (s, "DNSKEY")== 0) { *out = BD_T_DNSKEY;return 0; }
  if (strcasecmp (s, "NSEC3") == 0) { *out = BD_T_NSEC3; return 0; }
  if (strcasecmp (s, "NSEC3PARAM") == 0) { *out = BD_T_NSEC3PARAM; return 0; }
  if (strcasecmp (s, "SVCB")  == 0) { *out = BD_T_SVCB;  return 0; }
  if (strcasecmp (s, "HTTPS") == 0) { *out = BD_T_HTTPS; return 0; }
  if (strncasecmp (s, "TYPE", 4) == 0 && isdigit ((unsigned char) s[4]))
    {
      char *end = NULL;
      unsigned long v = strtoul (s + 4, &end, 10);
      if (end && *end == '\0' && v <= 65535UL)
        { *out = (uint16_t) v; return 0; }
    }
  return -1;
}

static const char *
bd_type_name (uint16_t t)
{
  switch (t)
    {
    case BD_T_A: return "A";
    case BD_T_NS: return "NS";
    case BD_T_CNAME: return "CNAME";
    case BD_T_DNAME: return "DNAME";
    case BD_T_SOA: return "SOA";
    case BD_T_PTR: return "PTR";
    case BD_T_MX: return "MX";
    case BD_T_TXT: return "TXT";
    case BD_T_AAAA: return "AAAA";
    case BD_T_DS: return "DS";
    case BD_T_RRSIG: return "RRSIG";
    case BD_T_NSEC: return "NSEC";
    case BD_T_DNSKEY: return "DNSKEY";
    case BD_T_NSEC3: return "NSEC3";
    case BD_T_NSEC3PARAM: return "NSEC3PARAM";
    case BD_T_SVCB: return "SVCB";
    case BD_T_HTTPS: return "HTTPS";
    default: return "TYPE";
    }
}

/* Path used by the resolv.conf parser. Honors BASHDNS_RESOLV_CONF so
 * hermetic tests (and off-network bash-os guests with custom resolver
 * layouts) can point the parser at a fixture without an ENV trick that
 * leaks into the wire fetch. Falls back to /etc/resolv.conf. */
static const char *
bd_resolv_conf_path (void)
{
  const char *p = getenv ("BASHDNS_RESOLV_CONF");
  return (p && *p) ? p : "/etc/resolv.conf";
}

/* Load up to MAX nameservers from BASHDNS_RESOLV_CONF (or
 * /etc/resolv.conf). Returns the count actually written (0..MAX).
 * Each out[i] is a NUL-terminated string of length < 64.
 *
 * Parser rules (RFC 1035 + glibc resolv.conf practice):
 *   - Comment lines starting with '#' or ';' are skipped.
 *   - Blank lines (only whitespace) are skipped.
 *   - Leading whitespace before the keyword is tolerated.
 *   - The keyword must be `nameserver` followed by whitespace — a
 *     token like `nameserverfoo` is NOT matched (word-boundary fix).
 *   - The address ends at whitespace, newline, or a '#' comment marker.
 *   - Addresses longer than 63 bytes are silently dropped.
 *   - Lines with the keyword but no address operand are silently dropped.
 * The query path falls back across parsed nameservers in order; the
 * `resolv-conf` verb exposes the same active/fallback order without
 * sending packets.
 */
static int
bd_load_nameservers (char out[][64], int max)
{
  if (max <= 0) return 0;
  FILE *f = fopen (bd_resolv_conf_path (), "r");
  if (!f) return 0;
  int n = 0;
  char line[256];
  while (n < max && fgets (line, sizeof line, f))
    {
      char *p = line;
      while (*p == ' ' || *p == '\t') p++;
      if (*p == '#' || *p == ';' || *p == '\n' || *p == '\r' || *p == '\0')
        continue;
      if (strncmp (p, "nameserver", 10) != 0) continue;
      /* Word boundary: the byte after `nameserver` must be whitespace.
       * Without this, `nameserverfoo 1.2.3.4` would parse `foo` as the
       * address (and then inet_pton in the caller would reject it). */
      if (p[10] != ' ' && p[10] != '\t') continue;
      p += 10;
      while (*p == ' ' || *p == '\t') p++;
      char *e = p;
      while (*e && *e != ' ' && *e != '\t' && *e != '\n'
             && *e != '\r' && *e != '#') e++;
      *e = '\0';
      if (*p == '\0') continue;
      if (strlen (p) >= 64) continue;
      strcpy (out[n], p);
      n++;
    }
  fclose (f);
  return n;
}

#define BD_SEARCH_MAX 6

typedef struct {
  char domains[BD_SEARCH_MAX][256];
  int count;
  int ndots;
  int attempts;
  int timeout_sec;
  int rotate;
} bd_search_conf_t;

static void
bd_search_conf_add (bd_search_conf_t *conf, const char *domain)
{
  if (!domain || !*domain || conf->count >= BD_SEARCH_MAX) return;
  size_t len = strlen (domain);
  while (len > 0 && domain[len - 1] == '.') len--;
  if (len == 0 || len >= sizeof conf->domains[0]) return;
  for (int i = 0; i < conf->count; i++)
    if (strncasecmp (conf->domains[i], domain, len) == 0
        && conf->domains[i][len] == '\0')
      return;
  memcpy (conf->domains[conf->count], domain, len);
  conf->domains[conf->count][len] = '\0';
  conf->count++;
}

static void
bd_load_search_conf (bd_search_conf_t *conf)
{
  memset (conf, 0, sizeof *conf);
  conf->ndots = 1;
  conf->attempts = 2;
  conf->timeout_sec = 0;
  conf->rotate = 0;
  FILE *f = fopen (bd_resolv_conf_path (), "r");
  if (!f) return;
  int saw_search = 0;
  char line[512];
  while (fgets (line, sizeof line, f))
    {
      char *hash = strchr (line, '#');
      char *semi = strchr (line, ';');
      char *cut = NULL;
      if (hash && semi) cut = hash < semi ? hash : semi;
      else cut = hash ? hash : semi;
      if (cut) *cut = '\0';

      char *p = line;
      while (*p == ' ' || *p == '\t') p++;
      if (*p == '\0' || *p == '\n' || *p == '\r') continue;

      char *kw = p;
      while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
      if (*p) *p++ = '\0';
      while (*p == ' ' || *p == '\t') p++;

      if (strcmp (kw, "search") == 0)
        {
          if (!saw_search)
            {
              conf->count = 0;
              saw_search = 1;
            }
          while (*p)
            {
              while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
              if (!*p) break;
              char *d = p;
              while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
              if (*p) *p++ = '\0';
              bd_search_conf_add (conf, d);
            }
        }
      else if (strcmp (kw, "domain") == 0 && !saw_search && conf->count == 0)
        {
          char *d = p;
          while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
          *p = '\0';
          bd_search_conf_add (conf, d);
        }
      else if (strcmp (kw, "options") == 0)
        {
          while (*p)
            {
              while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
              if (!*p) break;
              char *opt = p;
              while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
              if (*p) *p++ = '\0';
              if (strncmp (opt, "ndots:", 6) == 0)
                {
                  char *end = NULL;
                  long v = strtol (opt + 6, &end, 10);
                  if (end && *end == '\0' && v >= 0 && v <= 15)
                    conf->ndots = (int) v;
                }
              else if (strncmp (opt, "attempts:", 9) == 0)
                {
                  char *end = NULL;
                  long v = strtol (opt + 9, &end, 10);
                  if (end && *end == '\0' && v >= 1 && v <= 5)
                    conf->attempts = (int) v;
                }
              else if (strncmp (opt, "timeout:", 8) == 0)
                {
                  char *end = NULL;
                  long v = strtol (opt + 8, &end, 10);
                  if (end && *end == '\0' && v >= 1 && v <= 30)
                    conf->timeout_sec = (int) v;
                }
              else if (strcmp (opt, "rotate") == 0)
                conf->rotate = 1;
              else if (strcmp (opt, "single-request") == 0
                       || strcmp (opt, "no-tld-query") == 0)
                {
                  /* Accepted no-op: parse real glibc resolv.conf lines
                     without changing dns' independent query model. */
                }
            }
        }
    }
  fclose (f);
}

static int
bd_qname_dot_count (const char *name)
{
  int n = 0;
  for (const char *p = name; *p; p++)
    if (*p == '.') n++;
  return n;
}

static void
bd_query_order_add (char names[][256], int *count, const char *name)
{
  if (!name || !*name || *count >= BD_SEARCH_MAX + 1) return;
  if (strlen (name) >= 256) return;
  for (int i = 0; i < *count; i++)
    if (strcasecmp (names[i], name) == 0)
      return;
  strcpy (names[*count], name);
  (*count)++;
}

static int
bd_build_query_order (const char *qname, uint16_t qtype,
                      char names[][256], int max_names)
{
  (void) max_names;
  int count = 0;
  size_t qlen = strlen (qname);
  if (qtype == BD_T_PTR || qlen == 0 || qname[qlen - 1] == '.')
    {
      bd_query_order_add (names, &count, qname);
      return count;
    }

  bd_search_conf_t conf;
  bd_load_search_conf (&conf);
  if (conf.count == 0)
    {
      bd_query_order_add (names, &count, qname);
      return count;
    }

  int original_first = bd_qname_dot_count (qname) >= conf.ndots;
  if (original_first)
    bd_query_order_add (names, &count, qname);
  for (int i = 0; i < conf.count; i++)
    {
      char expanded[256];
      if ((size_t) snprintf (expanded, sizeof expanded, "%s.%s",
                             qname, conf.domains[i]) < sizeof expanded)
        bd_query_order_add (names, &count, expanded);
    }
  if (!original_first)
    bd_query_order_add (names, &count, qname);
  return count;
}

/* Encode a DNS QNAME: each label preceded by its length byte; ends in
   a 0 byte. Returns bytes written, or -1 on error. */
static int
bd_encode_qname (const char *name, unsigned char *out, size_t out_sz)
{
  size_t off = 0;
  const char *p = name;
  while (*p)
    {
      const char *e = strchr (p, '.');
      size_t len = e ? (size_t) (e - p) : strlen (p);
      if (len == 0) { if (p == name && !p[1]) break; return -1; }
      if (len > 63 || off + 1 + len + 1 > 255) return -1;
      if (off + 1 + len + 1 > out_sz) return -1;
      out[off++] = (unsigned char) len;
      memcpy (out + off, p, len);
      off += len;
      p = e ? e + 1 : p + len;
    }
  out[off++] = 0;  /* root label */
  return (int) off;
}

/* Decode a possibly-compressed DNS name starting at `pkt + *off`. Writes
   ASCII into `out` (max out_sz). Updates *off to point past the name
   (or past the first compression pointer encountered). Returns 0 on
   success, -1 on error. Recursion limit defeats malicious loops. */
static int
bd_decode_name (const unsigned char *pkt, size_t pkt_len, size_t *off,
                char *out, size_t out_sz, int depth)
{
  if (depth > 20) return -1;
  size_t pos = *off;
  size_t out_off = 0;
  int jumped = 0;
  size_t after = 0;  /* return-to position when we follow a pointer */

  for (;;)
    {
      if (pos >= pkt_len) return -1;
      unsigned char b = pkt[pos];
      if ((b & 0xc0) == 0xc0)
        {
          /* Compression pointer. */
          if (pos + 1 >= pkt_len) return -1;
          size_t target = ((b & 0x3f) << 8) | pkt[pos + 1];
          if (!jumped) { after = pos + 2; jumped = 1; }
          pos = target;
          /* Defeat infinite loops via depth count instead. */
          if (--depth < -10) return -1;
          continue;
        }
      else if ((b & 0xc0) != 0)
        {
          return -1;  /* Reserved encodings are not ordinary labels. */
        }
      pos++;
      if (b == 0) break;
      if (pos + b > pkt_len) return -1;
      if (out_off + b + 1 >= out_sz) return -1;
      if (out_off > 0) out[out_off++] = '.';
      memcpy (out + out_off, pkt + pos, b);
      out_off += b;
      pos += b;
    }
  out[out_off] = '\0';
  *off = jumped ? after : pos;
  return 0;
}

/* Skip a name in the packet — returns 0/−1, updates *off past it. */
static int
bd_skip_name (const unsigned char *pkt, size_t pkt_len, size_t *off)
{
  char tmp[256];
  return bd_decode_name (pkt, pkt_len, off, tmp, sizeof tmp, 0);
}

/* Build dns query header + question. Returns total length, or -1. */
static int
bd_build_query (uint16_t id, const char *qname, uint16_t qtype,
                int dnssec, unsigned char *out, size_t out_sz)
{
  if (out_sz < 12 + 256 + 4 + 11) return -1;
  /* Header: id(2) flags(2) qd(2) an(2) ns(2) ar(2) */
  out[0] = id >> 8; out[1] = id & 0xff;
  out[2] = 0x01; out[3] = 0x00;     /* RD = 1, otherwise zero */
  out[4] = 0; out[5] = 1;            /* qdcount = 1 */
  out[6] = out[7] = 0;
  out[8] = out[9] = 0;
  out[10] = 0; out[11] = dnssec ? 1 : 0; /* arcount */
  int qn = bd_encode_qname (qname, out + 12, out_sz - 12 - 4);
  if (qn < 0) return -1;
  size_t off = 12 + qn;
  out[off++] = qtype >> 8; out[off++] = qtype & 0xff;
  out[off++] = 0; out[off++] = 1;    /* QCLASS = IN (1) */
  if (dnssec)
    {
      if (off + 11 > out_sz) return -1;
      out[off++] = 0;                 /* root owner for OPT */
      out[off++] = 0; out[off++] = 41; /* TYPE OPT */
      out[off++] = 4; out[off++] = 0;  /* UDP payload 1024 */
      out[off++] = 0;                 /* ext rcode */
      out[off++] = 0;                 /* EDNS version */
      out[off++] = 0x80; out[off++] = 0x00; /* DO bit */
      out[off++] = 0; out[off++] = 0;  /* rdlen */
    }
  return (int) off;
}

/* Read 16-bit big-endian. */
static uint16_t
bd_rd16 (const unsigned char *p)
{
  return (uint16_t) ((p[0] << 8) | p[1]);
}
static uint32_t
bd_rd32 (const unsigned char *p)
{
  return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) |
         ((uint32_t) p[2] << 8)  |  (uint32_t) p[3];
}

static void
bd_hex (const unsigned char *p, size_t n)
{
  for (size_t i = 0; i < n; i++)
    printf ("%02x", p[i]);
}

static void
bd_rstrip (char *s)
{
  size_t n = strlen (s);
  while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' ||
                   s[n - 1] == ' ' || s[n - 1] == '\t'))
    s[--n] = '\0';
}

static int
bd_truthy (const char *s)
{
  if (!s || !*s) return 0;
  return strcmp (s, "1") == 0 ||
         strcasecmp (s, "yes") == 0 ||
         strcasecmp (s, "true") == 0 ||
         strcasecmp (s, "on") == 0;
}

#ifndef SYS_getrandom
#  if defined(__x86_64__)
#    define SYS_getrandom 318
#  endif
#endif

static void
bd_random_bytes (unsigned char *buf, size_t n)
{
  size_t got = 0;
#ifdef SYS_getrandom
  while (got < n)
    {
      long r = syscall (SYS_getrandom, buf + got, n - got, 0);
      if (r > 0) { got += (size_t) r; continue; }
      if (r < 0 && errno == EINTR) continue;
      break;
    }
  if (got == n) return;
#endif

  int fd = open ("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (fd >= 0)
    {
      while (got < n)
        {
          ssize_t r = read (fd, buf + got, n - got);
          if (r > 0) { got += (size_t) r; continue; }
          if (r < 0 && errno == EINTR) continue;
          break;
        }
      close (fd);
      if (got == n) return;
    }

  struct timespec ts;
  clock_gettime (CLOCK_REALTIME, &ts);
  uint64_t x = ((uint64_t) ts.tv_sec << 32) ^ (uint64_t) ts.tv_nsec ^
               ((uint64_t) getpid () << 16) ^ (uint64_t) (uintptr_t) buf;
  while (got < n)
    {
      x ^= x << 13;
      x ^= x >> 7;
      x ^= x << 17;
      buf[got++] = (unsigned char) (x >> 56);
    }
}

static uint16_t
bd_random_u16 (void)
{
  unsigned char b[2];
  bd_random_bytes (b, sizeof b);
  uint16_t v = (uint16_t) (((uint16_t) b[0] << 8) | b[1]);
  return v ? v : 1;
}

static int
bd_0x20_enabled (void)
{
  const char *env = getenv ("BASHDNS_0X20");
  if (!env || !*env) return 1;
  if (strcmp (env, "0") == 0 ||
      strcasecmp (env, "no") == 0 ||
      strcasecmp (env, "false") == 0 ||
      strcasecmp (env, "off") == 0)
    return 0;
  return 1;
}

static int
bd_0x20_apply (const char *qname, char *out, size_t out_sz)
{
  if (!qname || !out || out_sz == 0) return -1;
  size_t n = strlen (qname);
  if (n + 1 > out_sz) return -1;
  unsigned char rnd[256];
  if (n > sizeof rnd) return -1;
  bd_random_bytes (rnd, n);
  for (size_t i = 0; i < n; i++)
    {
      unsigned char c = (unsigned char) qname[i];
      if (c >= 'a' && c <= 'z')
        out[i] = (rnd[i] & 1) ? (char) (c - 'a' + 'A') : (char) c;
      else if (c >= 'A' && c <= 'Z')
        out[i] = (rnd[i] & 1) ? (char) c : (char) (c - 'A' + 'a');
      else
        out[i] = (char) c;
    }
  out[n] = '\0';
  return 0;
}

static const char *
bd_prepare_wire_qname (const char *qname, char *mixed, size_t mixed_sz,
                       const char **verify_qname)
{
  if (verify_qname) *verify_qname = NULL;
  if (!bd_0x20_enabled ())
    return qname;
  if (bd_0x20_apply (qname, mixed, mixed_sz) < 0)
    return NULL;
  if (verify_qname) *verify_qname = mixed;
  return mixed;
}

static int
bd_0x20_verify (const unsigned char *reply, size_t rlen, const char *sent_qname)
{
  if (!sent_qname || !*sent_qname) return 0;
  if (rlen < 12) return -1;
  if (bd_rd16 (reply + 4) < 1)
    { builtin_error ("query: response missing question"); return -1; }

  size_t off = 12;
  char got[256];
  if (bd_decode_name (reply, rlen, &off, got, sizeof got, 0) < 0)
    { builtin_error ("query: response question malformed"); return -1; }
  if (off + 4 > rlen)
    { builtin_error ("query: response question truncated"); return -1; }

  char want[256];
  if (strlen (sent_qname) >= sizeof want)
    { builtin_error ("query: name too long"); return -1; }
  strcpy (want, sent_qname);
  size_t wn = strlen (want);
  while (wn > 0 && want[wn - 1] == '.')
    want[--wn] = '\0';

  if (strcasecmp (got, want) != 0)
    { builtin_error ("query: response qname mismatch"); return -1; }
  if (strcmp (got, want) != 0)
    { builtin_error ("query: 0x20 case mismatch"); return -1; }
  return 0;
}

static int
bd_valid_hostname (const char *s)
{
  if (!s || !*s) return 0;
  size_t n = strlen (s);
  if (n > 253) return 0;
  for (size_t i = 0; i < n; i++)
    {
      unsigned char c = (unsigned char) s[i];
      if (!(isalnum (c) || c == '-' || c == '.' || c == '_'))
        return 0;
    }
  return 1;
}

/* ---- hex / base64 decoders + name canonicalisation ---------------- */

static int
bd_hexval (int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int
bd_unhex (const char *s, unsigned char *out, size_t out_sz, size_t *out_len)
{
  size_t n = 0;
  while (*s)
    {
      /* Skip every flavour of whitespace, including the trailing
         newline that `crypto sha256 -x` (and most hex-emitters)
         append. The previous form skipped only space/tab and made
         bd_run_hash_match falsely report digest mismatch on otherwise
         correct hashes. */
      while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') s++;
      if (!*s) break;
      int hi = bd_hexval ((unsigned char) s[0]);
      int lo = s[1] ? bd_hexval ((unsigned char) s[1]) : -1;
      if (hi < 0 || lo < 0) return -1;
      if (n >= out_sz) return -1;
      out[n++] = (unsigned char) ((hi << 4) | lo);
      s += 2;
    }
  *out_len = n;
  return 0;
}

static int
bd_b64val (int c)
{
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

static int
bd_unb64 (const char *s, unsigned char *out, size_t out_sz, size_t *out_len)
{
  uint32_t acc = 0;
  int bits = 0;
  size_t n = 0;
  for (; *s; s++)
    {
      unsigned char c = (unsigned char) *s;
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
      if (c == '=') break;
      int v = bd_b64val (c);
      if (v < 0) return -1;
      acc = (acc << 6) | (uint32_t) v;
      bits += 6;
      if (bits >= 8)
        {
          bits -= 8;
          if (n >= out_sz) return -1;
          out[n++] = (unsigned char) ((acc >> bits) & 0xff);
        }
    }
  *out_len = n;
  return 0;
}

/* Lower-case ASCII copy with trailing-dot strip. The root zone is
   normalised to "." (empty input "" or "." both map to "."). Returns
   length, -1 on overflow. */
static int
bd_canon_owner (const char *in, char *out, size_t out_sz)
{
  size_t n = strlen (in);
  if (n + 1 > out_sz) return -1;
  /* Root: "" or "." -> "." */
  if (n == 0 || (n == 1 && in[0] == '.'))
    {
      if (out_sz < 2) return -1;
      out[0] = '.'; out[1] = '\0';
      return 1;
    }
  size_t j = 0;
  for (size_t i = 0; i < n; i++)
    {
      unsigned char c = (unsigned char) in[i];
      if (c >= 'A' && c <= 'Z') c = (unsigned char) (c + 32);
      out[j++] = (char) c;
    }
  /* Strip trailing dot for canonical comparison. */
  if (j > 1 && out[j - 1] == '.') j--;
  out[j] = '\0';
  return (int) j;
}

/* DNS wire-form encoding of the canonicalised name (lowercased,
   length-prefixed labels, terminating root). Returns length or -1. */
static int
bd_name_to_wire (const char *name, unsigned char *out, size_t out_sz)
{
  char canon[256];
  if (bd_canon_owner (name, canon, sizeof canon) < 0) return -1;
  if (canon[0] == '\0' || (canon[0] == '.' && canon[1] == '\0'))
    {
      if (out_sz < 1) return -1;
      out[0] = 0;
      return 1;
    }
  size_t off = 0;
  const char *p = canon;
  while (*p)
    {
      const char *e = strchr (p, '.');
      size_t len = e ? (size_t) (e - p) : strlen (p);
      if (len == 0) { p++; continue; }
      /* Stage 39.G hermetic fixtures use reserved/private NSEC3 hash
         algorithms with base32hex owner labels longer than the public DNS
         63-octet label limit. Preserve those synthetic labels for
         canonical RRset verification; production query encoding still
         rejects overlong labels in bd_encode_qname(). */
      if (len > 255) return -1;
      if (off + 1 + len + 1 > out_sz) return -1;
      out[off++] = (unsigned char) len;
      memcpy (out + off, p, len);
      off += len;
      p = e ? e + 1 : p + len;
    }
  out[off++] = 0;
  return (int) off;
}

/* RFC 4034 §6.1 canonical DNS name ordering: compare names by treating
 * them as a sequence of labels read right-to-left (least-significant
 * label first), each label compared octet-by-octet on its lowercased
 * bytes, shorter label sorting first. Both inputs are canonicalised
 * (lowercase, trailing-dot stripped) first. Returns <0/0/>0. */
static int
bd_canon_name_cmp (const char *a, const char *b)
{
  char ca[256], cb[256];
  if (bd_canon_owner (a, ca, sizeof ca) < 0) return 0;
  if (bd_canon_owner (b, cb, sizeof cb) < 0) return 0;
  /* Root "." has no labels and sorts first. */
  int root_a = (ca[0] == '.' && ca[1] == '\0');
  int root_b = (cb[0] == '.' && cb[1] == '\0');
  if (root_a && root_b) return 0;
  /* Split into label pointer arrays. */
  char ba[256], bb[256];
  strcpy (ba, ca); strcpy (bb, cb);
  char *la[128]; int na = 0;
  char *lb[128]; int nb = 0;
  if (!root_a)
    { char *p = ba; la[na++] = p;
      for (; *p; p++) if (*p == '.') { *p = '\0'; if (na < 128) la[na++] = p + 1; } }
  if (!root_b)
    { char *p = bb; lb[nb++] = p;
      for (; *p; p++) if (*p == '.') { *p = '\0'; if (nb < 128) lb[nb++] = p + 1; } }
  /* Compare from the rightmost (last) label inward. */
  int i = na - 1, j = nb - 1;
  while (i >= 0 && j >= 0)
    {
      int c = strcmp (la[i], lb[j]);
      if (c) return c;
      i--; j--;
    }
  if (i < 0 && j < 0) return 0;
  return (i < 0) ? -1 : 1;   /* shorter (fewer labels) sorts first */
}

/* Compare two canonicalised owner names (case-insensitive ASCII). */
static int
bd_name_eq (const char *a, const char *b)
{
  char ca[256], cb[256];
  if (bd_canon_owner (a, ca, sizeof ca) < 0) return 0;
  if (bd_canon_owner (b, cb, sizeof cb) < 0) return 0;
  return strcmp (ca, cb) == 0;
}

/* RFC 4034 Appendix B keytag for DNSKEY rdata.
   Note: RFC says algorithm 1 (RSAMD5) needs a different formula; we
   reject algo 1 in the validator anyway. */
static uint16_t
bd_dnskey_keytag (const unsigned char *rdata, size_t rdlen)
{
  uint32_t ac = 0;
  for (size_t i = 0; i < rdlen; i++)
    ac += (i & 1) ? rdata[i] : ((uint32_t) rdata[i] << 8);
  ac += (ac >> 16) & 0xFFFF;
  return (uint16_t) (ac & 0xFFFF);
}

/* ---- structured trust-set parser ----------------------------------- */

/* Parse one whitespace-delimited token; advances *pp past the token
   (and any trailing whitespace). Returns NULL when no more tokens. */
static char *
bd_next_token (char **pp)
{
  char *p = *pp;
  while (*p == ' ' || *p == '\t') p++;
  if (!*p) return NULL;
  char *start = p;
  while (*p && *p != ' ' && *p != '\t') p++;
  if (*p) { *p++ = '\0'; }
  *pp = p;
  return start;
}

/* Parse "owner DS keytag algo digesttype hex..." or
   "owner DNSKEY flags proto algo base64...". Returns 0 on success
   (entry filled), -1 on parse error, +1 if the line is metadata-only
   (doesn't match either structured form). */
static int
bd_parse_trust_line (char *line, bd_trust_t *out)
{
  /* Take a working copy so we can mutate. */
  char buf[1024];
  if (strlen (line) >= sizeof buf) return -1;
  strcpy (buf, line);
  char *p = buf;

  char *owner = bd_next_token (&p);
  char *kind  = owner ? bd_next_token (&p) : NULL;
  if (!owner || !kind) return 1;

  /* Skip dig "TTL CLASS" if present: a numeric TTL followed by IN or CH. */
  if (kind[0] >= '0' && kind[0] <= '9')
    {
      char *cls = bd_next_token (&p);
      kind = cls ? bd_next_token (&p) : NULL;
      if (!kind) return 1;
    }
  if (strcasecmp (kind, "IN") == 0 || strcasecmp (kind, "CH") == 0)
    kind = bd_next_token (&p);
  if (!kind) return 1;

  if (strcasecmp (kind, "DS") == 0)
    {
      char *ktag = bd_next_token (&p);
      char *alg  = ktag ? bd_next_token (&p) : NULL;
      char *dt   = alg  ? bd_next_token (&p) : NULL;
      if (!ktag || !alg || !dt) return -1;
      if (bd_canon_owner (owner, out->owner, sizeof out->owner) < 0) return -1;
      out->kind         = BD_T_DS;
      out->key_tag      = (uint16_t) atoi (ktag);
      out->algorithm    = (uint8_t)  atoi (alg);
      out->digest_type  = (uint8_t)  atoi (dt);
      /* Glue the rest of the line back together as the hex digest. */
      char hex[1024];
      hex[0] = '\0';
      char *t;
      while ((t = bd_next_token (&p)))
        {
          size_t cur = strlen (hex);
          size_t ln = strlen (t);
          if (cur + ln + 1 >= sizeof hex) return -1;
          memcpy (hex + cur, t, ln);
          hex[cur + ln] = '\0';
        }
      if (bd_unhex (hex, out->digest, sizeof out->digest, &out->digest_len) < 0)
        return -1;
      return 0;
    }
  if (strcasecmp (kind, "DNSKEY") == 0)
    {
      char *flg = bd_next_token (&p);
      char *prt = flg ? bd_next_token (&p) : NULL;
      char *alg = prt ? bd_next_token (&p) : NULL;
      if (!flg || !prt || !alg) return -1;
      if (bd_canon_owner (owner, out->owner, sizeof out->owner) < 0) return -1;
      out->kind      = BD_T_DNSKEY;
      out->flags     = (uint16_t) atoi (flg);
      out->protocol  = (uint8_t)  atoi (prt);
      out->algorithm = (uint8_t)  atoi (alg);
      char b64[4096];
      b64[0] = '\0';
      char *t;
      while ((t = bd_next_token (&p)))
        {
          size_t cur = strlen (b64);
          size_t ln = strlen (t);
          if (cur + ln + 1 >= sizeof b64) return -1;
          memcpy (b64 + cur, t, ln);
          b64[cur + ln] = '\0';
        }
      unsigned char pk[2000];
      size_t pklen = 0;
      if (bd_unb64 (b64, pk, sizeof pk, &pklen) < 0) return -1;
      /* Reconstruct full DNSKEY rdata: flags(2) || proto(1) || algo(1) || pk. */
      if (4 + pklen > sizeof out->rdata) return -1;
      out->rdata[0] = (unsigned char) (out->flags >> 8);
      out->rdata[1] = (unsigned char) (out->flags & 0xff);
      out->rdata[2] = out->protocol;
      out->rdata[3] = out->algorithm;
      memcpy (out->rdata + 4, pk, pklen);
      out->rdata_len = 4 + pklen;
      out->key_tag = bd_dnskey_keytag (out->rdata, out->rdata_len);
      return 0;
    }
  return 1;
}

static int
bd_load_trust_anchor_line (const char *path, char *out, size_t out_sz)
{
  FILE *f = fopen (path, "r");
  if (!f) { builtin_error ("trust-anchor: %s: %s", path, strerror (errno)); return -1; }

  char first_meta[512];
  first_meta[0] = '\0';
  int saw_structured = 0;
  /* Reset the structured trust set; trust-anchor-load is a wholesale
     replacement, not an append. */
  bd_trust_count = 0;

  char line[2048];
  while (fgets (line, sizeof line, f))
    {
      bd_rstrip (line);
      if (!*line) continue;
      if (line[0] == '#' || line[0] == ';') continue;
      for (char *p = line; *p; p++)
        if ((unsigned char) *p < 0x09 || (unsigned char) *p > 0x7e)
          { builtin_error ("trust-anchor: %s: non-printable byte", path); fclose (f); return -1; }

      if (bd_trust_count >= BD_TRUST_MAX)
        { builtin_error ("trust-anchor: %s: too many entries (max %d)", path, BD_TRUST_MAX);
          fclose (f); return -1; }
      bd_trust_t entry;
      memset (&entry, 0, sizeof entry);
      int r = bd_parse_trust_line (line, &entry);
      if (r < 0)
        { builtin_error ("trust-anchor: %s: malformed DS/DNSKEY line", path); fclose (f); return -1; }
      if (r == 0)
        {
          bd_trust_set[bd_trust_count++] = entry;
          saw_structured = 1;
          if (!*first_meta)
            snprintf (first_meta, sizeof first_meta,
                      "%s . key-tag=%u algorithm=%u %s source=trust-anchor-load",
                      entry.owner[0] ? entry.owner : "root",
                      (unsigned) entry.key_tag, (unsigned) entry.algorithm,
                      entry.kind == BD_T_DS ? "kind=DS" : "kind=DNSKEY");
        }
      else
        {
          /* Metadata-only line (legacy IANA KSK-2017 format). Capture
             the first one for `dns trust-anchor` output. */
          if (!*first_meta)
            {
              if (strstr (line, "key-tag=") == NULL ||
                  strstr (line, "algorithm=") == NULL)
                {
                  builtin_error ("trust-anchor: %s: expected key-tag= and algorithm= metadata", path);
                  fclose (f); return -1;
                }
              if (strlen (line) >= sizeof first_meta)
                { builtin_error ("trust-anchor: %s: line too long", path); fclose (f); return -1; }
              strcpy (first_meta, line);
            }
        }
    }
  fclose (f);

  if (!saw_structured && !*first_meta)
    { builtin_error ("trust-anchor: %s: empty", path); return -1; }
  if (strlen (first_meta) + 1 > out_sz)
    { builtin_error ("trust-anchor: %s: metadata too long", path); return -1; }
  strcpy (out, first_meta);
  return 0;
}

static const char *
bd_active_trust_anchor (char *buf, size_t bufsz)
{
  const char *env = getenv ("BASHDNS_TRUST_ANCHOR");
  if (env && *env && bd_load_trust_anchor_line (env, buf, bufsz) == 0)
    return buf;
  if (bd_runtime_trust_anchor[0])
    return bd_runtime_trust_anchor;
  return BD_TRUST_ANCHOR_DEFAULT;
}

/* dns resolv-conf — print parsed nameservers and resolver options from
 * BASHDNS_RESOLV_CONF (or /etc/resolv.conf) without doing any wire
 * fetch. Output format (TSV):
 *
 *   nameserver\t<IP>\tactive     (first parsed entry)
 *   nameserver\t<IP>\tfallback   (every subsequent entry)
 *   options\t<name>\t<value>      (ndots/attempts/timeout/rotate)
 *
 * Returns EX_USAGE on extra args, EXECUTION_FAILURE when no nameservers
 * were parsed (with a diagnostic naming the path that was tried). */
static int
bd_resolv_conf_cmd (WORD_LIST *args)
{
  if (args)
    { builtin_error ("resolv-conf takes no args"); return EX_USAGE; }
  char list[8][64];
  int n = bd_load_nameservers (list, 8);
  if (n == 0)
    {
      builtin_error ("no nameservers in %s", bd_resolv_conf_path ());
      return EXECUTION_FAILURE;
    }
  for (int i = 0; i < n; i++)
    printf ("nameserver\t%s\t%s\n", list[i], i == 0 ? "active" : "fallback");
  bd_search_conf_t conf;
  bd_load_search_conf (&conf);
  printf ("options\tndots\t%d\n", conf.ndots);
  printf ("options\tattempts\t%d\n", conf.attempts);
  printf ("options\ttimeout\t%d\n", conf.timeout_sec);
  printf ("options\trotate\t%s\n", conf.rotate ? "on" : "off");
  return EXECUTION_SUCCESS;
}

static int
bd_print_trust_anchor_cmd (WORD_LIST *args)
{
  const char *var = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-V") == 0)
        {
          if (!p->next) { builtin_error ("trust-anchor: -V needs VAR"); return EX_USAGE; }
          p = p->next;
          var = p->word->word;
        }
      else
        { builtin_error ("trust-anchor: extra arg %s", w); return EX_USAGE; }
    }

  char buf[512];
  const char *ta = bd_active_trust_anchor (buf, sizeof buf);
  if (var)
    builtin_bind_variable ((char *) var, (char *) ta, 0);
  else
    puts (ta);
  return EXECUTION_SUCCESS;
}

static int
bd_trust_anchor_load_cmd (WORD_LIST *args)
{
  if (!args || args->next)
    { builtin_error ("trust-anchor-load: PATH"); return EX_USAGE; }
  if (geteuid () != 0)
    { builtin_error ("trust-anchor-load: root required"); return EXECUTION_FAILURE; }
  char buf[512];
  if (bd_load_trust_anchor_line (args->word->word, buf, sizeof buf) < 0)
    return EXECUTION_FAILURE;
  strcpy (bd_runtime_trust_anchor, buf);
  return EXECUTION_SUCCESS;
}

/* ==================================================================== *
 *  RFC 5011 automated trust-anchor rollover — state machine (logic).
 *
 *  This is the pure state-transition engine: no daemon, no network.
 *  The deferred resolver daemon periodically fetches the apex DNSKEY
 *  RRset, validates it against the currently-trusted anchor(s), and
 *  then drives one `rfc5011-step` per poll.  We model time via an
 *  injected --now so every transition is deterministic under test.
 *
 *  ---- on-disk layout (the schema.version contract) -----------------
 *
 *  anchor-dir/
 *    root.anchor            active trust anchor(s) — plain DNSKEY/DS
 *                           lines exactly as `trust-anchor-load` reads.
 *    root.anchor.candidate  RFC 5011 pending/revoked keys + timer state.
 *    root.anchor.previous   one prior active set retained for rollback.
 *
 *  root.anchor.candidate line format (schema v1):
 *
 *    ; dns rfc5011 candidate state v1
 *    first-seen=EPOCH state=pending|revoked OWNER DNSKEY FLAGS PROTO ALGO BASE64...
 *
 *  Each non-comment line begins with leading "key=value" metadata
 *  tokens (first-seen=, state=), followed by a standard DNSKEY line in
 *  the exact text form `bd_parse_trust_line` accepts.  The reader
 *  strips the leading metadata, then hands the remainder to
 *  `bd_parse_trust_line`; the writer mirrors that.  Human-readable and
 *  re-parseable across steps.
 *
 *    first-seen=EPOCH   when the key was first observed (PENDING) or,
 *                       once revoked, when the REVOKE bit was first seen
 *                       (i.e. start of the remove hold-down).
 *    state=pending      counting up to add-hold-down -> promote.
 *    state=revoked      counting up to remove-hold-down -> delete.
 *
 *  ---- RFC 5011 semantics implemented --------------------------------
 *
 *  §2.4.1 new key  : observed at apex (the daemon having validated the
 *                    RRset against a trusted key) and not yet known ->
 *                    record as PENDING with first-seen=now.  NOT trusted.
 *  §2.4.1 promote  : a PENDING key still present each step; once
 *                    now - first-seen >= add-hold-down -> move into the
 *                    active set (root.anchor).  Before overwrite, copy
 *                    the current active set to root.anchor.previous.
 *                    Promotion is atomic (temp file + rename).
 *  §2.5   revoke   : a key in the apex set with the REVOKE bit (flags|
 *                    0x0080) that matches a previously-active or pending
 *                    key -> mark REVOKED, start the remove hold-down,
 *                    and untrust it immediately (drop from active).
 *                    After remove-hold-down it is deleted entirely.
 *  §2.4.1 missing  : a PENDING key absent from the apex set before
 *                    promotion -> drop from candidate (timer reset).
 *
 *  ---- simplifications (flagged) -------------------------------------
 *
 *  * One hold-down value drives BOTH addHoldDown and removeHoldDown
 *    (RFC 5011 §2.3 lists them separately but recommends the same
 *    default 30d; --hold-down sets both here).
 *  * We trust the daemon to have validated the DNSKEY RRset and the
 *    REVOKE self-signature BEFORE calling us — this engine does not
 *    re-verify RRSIGs (that is the daemon's job, and `--validate`
 *    already exists for it).  A key only reaches us if "validly signed".
 *  * The "all keys revoked" footgun (§5): we never auto-delete the last
 *    active key.  If a step would leave root.anchor empty we keep the
 *    revoked key listed (still untrusted) and warn, rather than ending
 *    up with no anchor at all.
 * ==================================================================== */

#define BD_R5011_HOLDDOWN_DEFAULT 2592000L   /* 30 days, RFC 5011 §2.3 */
#define BD_R5011_MAX 32

/* DNSKEY REVOKE bit lives in the flags field (RFC 5011 §2.1). */
#define BD_DNSKEY_REVOKE 0x0080

typedef struct {
  bd_trust_t key;          /* the DNSKEY (rdata + keytag + algo + flags) */
  long       first_seen;   /* epoch: pending start, or revoke-seen start */
  int        state;        /* BD_R5011_PENDING | BD_R5011_REVOKED */
} bd_cand_t;

#define BD_R5011_PENDING 0
#define BD_R5011_REVOKED 1

/* Encode a byte buffer to base64 into out (NUL-terminated). Returns the
   string length, or -1 if it would not fit.  Mirrors sz_emit_b64 but
   writes to a caller buffer rather than stdout. */
static int
bd_b64_to_buf (const unsigned char *in, size_t n, char *out, size_t out_sz)
{
  static const char *a =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t need = ((n + 2) / 3) * 4 + 1;
  if (need > out_sz) return -1;
  size_t i = 0, o = 0;
  for (; i + 3 <= n; i += 3)
    { uint32_t v = (in[i] << 16) | (in[i+1] << 8) | in[i+2];
      out[o++] = a[(v>>18)&63]; out[o++] = a[(v>>12)&63];
      out[o++] = a[(v>>6)&63];  out[o++] = a[v&63]; }
  if (n - i == 1)
    { uint32_t v = in[i] << 16;
      out[o++] = a[(v>>18)&63]; out[o++] = a[(v>>12)&63];
      out[o++] = '='; out[o++] = '='; }
  else if (n - i == 2)
    { uint32_t v = (in[i] << 16) | (in[i+1] << 8);
      out[o++] = a[(v>>18)&63]; out[o++] = a[(v>>12)&63];
      out[o++] = a[(v>>6)&63];  out[o++] = '='; }
  out[o] = '\0';
  return (int) o;
}

/* Render a bd_trust_t DNSKEY as a master-file-style line into buf:
   "<owner>. DNSKEY <flags> <proto> <algo> <base64>".  Returns 0 ok. */
static int
bd_trust_to_dnskey_line (const bd_trust_t *t, char *buf, size_t buf_sz)
{
  if (t->kind != BD_T_DNSKEY || t->rdata_len < 4) return -1;
  char b64[4096];
  if (bd_b64_to_buf (t->rdata + 4, t->rdata_len - 4, b64, sizeof b64) < 0)
    return -1;
  const char *owner = t->owner[0] ? t->owner : ".";
  /* canon owner of root is "." already; append a trailing dot for FQDNs. */
  int n;
  if (strcmp (owner, ".") == 0)
    n = snprintf (buf, buf_sz, ". DNSKEY %u %u %u %s",
                  (unsigned) t->flags, (unsigned) t->protocol,
                  (unsigned) t->algorithm, b64);
  else
    n = snprintf (buf, buf_sz, "%s. DNSKEY %u %u %u %s", owner,
                  (unsigned) t->flags, (unsigned) t->protocol,
                  (unsigned) t->algorithm, b64);
  return (n > 0 && (size_t) n < buf_sz) ? 0 : -1;
}

/* Two DNSKEYs are "the same key" iff keytag+algorithm+owner match.
   (RFC 5011 keys are identified by keytag+algorithm; we also require
   the same owner since the anchor set could in principle hold more.) */
static int
bd_key_same (const bd_trust_t *a, const bd_trust_t *b)
{
  return a->key_tag == b->key_tag
      && a->algorithm == b->algorithm
      && bd_name_eq (a->owner, b->owner);
}

/* Read a plain anchor file (root.anchor / .previous) into ts[]. Missing
   file -> 0 entries, returns 0 (not an error: bootstrap state).  Bad
   line -> -1. */
static int
bd_r5011_read_anchor (const char *path, bd_trust_t *ts, int max, int *n)
{
  *n = 0;
  FILE *f = fopen (path, "r");
  if (!f) { if (errno == ENOENT) return 0;
            builtin_error ("rfc5011: %s: %s", path, strerror (errno)); return -1; }
  char line[2048];
  while (fgets (line, sizeof line, f))
    {
      bd_rstrip (line);
      if (!*line || line[0] == '#' || line[0] == ';') continue;
      if (*n >= max)
        { builtin_error ("rfc5011: %s: too many anchors", path); fclose (f); return -1; }
      bd_trust_t e; memset (&e, 0, sizeof e);
      int r = bd_parse_trust_line (line, &e);
      if (r < 0) { builtin_error ("rfc5011: %s: malformed anchor line", path);
                   fclose (f); return -1; }
      if (r == 0) ts[(*n)++] = e;
    }
  fclose (f);
  return 0;
}

/* Read root.anchor.candidate into cands[]. Missing -> 0, returns 0. */
static int
bd_r5011_read_candidates (const char *path, bd_cand_t *cands, int max, int *n)
{
  *n = 0;
  FILE *f = fopen (path, "r");
  if (!f) { if (errno == ENOENT) return 0;
            builtin_error ("rfc5011: %s: %s", path, strerror (errno)); return -1; }
  char line[2560];
  while (fgets (line, sizeof line, f))
    {
      bd_rstrip (line);
      if (!*line || line[0] == '#' || line[0] == ';') continue;
      if (*n >= max)
        { builtin_error ("rfc5011: %s: too many candidates", path); fclose (f); return -1; }
      /* Strip leading key=value metadata tokens, capturing first-seen/state,
         then parse the remainder as a DNSKEY line. */
      long first_seen = -1;
      int  state = BD_R5011_PENDING;
      char *p = line;
      for (;;)
        {
          while (*p == ' ' || *p == '\t') p++;
          if (strncmp (p, "first-seen=", 11) == 0)
            {
              first_seen = atol (p + 11);
              while (*p && *p != ' ' && *p != '\t') p++;
              continue;
            }
          if (strncmp (p, "state=", 6) == 0)
            {
              state = (strncmp (p + 6, "revoked", 7) == 0) ? BD_R5011_REVOKED : BD_R5011_PENDING;
              while (*p && *p != ' ' && *p != '\t') p++;
              continue;
            }
          break;
        }
      if (first_seen < 0)
        { builtin_error ("rfc5011: %s: candidate line missing first-seen=", path);
          fclose (f); return -1; }
      bd_cand_t c; memset (&c, 0, sizeof c);
      int r = bd_parse_trust_line (p, &c.key);
      if (r != 0 || c.key.kind != BD_T_DNSKEY)
        { builtin_error ("rfc5011: %s: malformed candidate DNSKEY", path);
          fclose (f); return -1; }
      c.first_seen = first_seen;
      c.state = state;
      cands[(*n)++] = c;
    }
  fclose (f);
  return 0;
}

/* Always close the stream, including when flushing or syncing fails. */
static int
bd_sync_close (FILE *f)
{
  int rc = fflush (f);
  if (rc == 0) rc = fsync (fileno (f));
  int saved = errno;
  int closed = fclose (f);
  if (rc != 0) { errno = saved; return -1; }
  return closed;
}

/* Atomic write of a plain anchor file (temp + rename). */
static int
bd_r5011_write_anchor (const char *path, const bd_trust_t *ts, int n)
{
  char tmp[1100];
  if ((size_t) snprintf (tmp, sizeof tmp, "%s.tmp.%ld", path, (long) getpid ()) >= sizeof tmp)
    { builtin_error ("rfc5011: path too long: %s", path); return -1; }
  FILE *f = fopen (tmp, "w");
  if (!f) { builtin_error ("rfc5011: %s: %s", tmp, strerror (errno)); return -1; }
  fprintf (f, "; dns rfc5011 active trust anchor v1\n");
  for (int i = 0; i < n; i++)
    {
      char line[4400];
      if (bd_trust_to_dnskey_line (&ts[i], line, sizeof line) < 0)
        { builtin_error ("rfc5011: cannot render anchor line"); fclose (f); unlink (tmp); return -1; }
      fprintf (f, "%s\n", line);
    }
  if (bd_sync_close (f) != 0)
    { builtin_error ("rfc5011: %s: write: %s", tmp, strerror (errno)); unlink (tmp); return -1; }
  if (rename (tmp, path) != 0)
    { builtin_error ("rfc5011: rename %s -> %s: %s", tmp, path, strerror (errno));
      unlink (tmp); return -1; }
  return 0;
}

/* Atomic write of root.anchor.candidate. */
static int
bd_r5011_write_candidates (const char *path, const bd_cand_t *cands, int n)
{
  char tmp[1100];
  if ((size_t) snprintf (tmp, sizeof tmp, "%s.tmp.%ld", path, (long) getpid ()) >= sizeof tmp)
    { builtin_error ("rfc5011: path too long: %s", path); return -1; }
  FILE *f = fopen (tmp, "w");
  if (!f) { builtin_error ("rfc5011: %s: %s", tmp, strerror (errno)); return -1; }
  fprintf (f, "; dns rfc5011 candidate state v1\n");
  for (int i = 0; i < n; i++)
    {
      char line[4400];
      if (bd_trust_to_dnskey_line (&cands[i].key, line, sizeof line) < 0)
        { builtin_error ("rfc5011: cannot render candidate line"); fclose (f); unlink (tmp); return -1; }
      fprintf (f, "first-seen=%ld state=%s %s\n", cands[i].first_seen,
               cands[i].state == BD_R5011_REVOKED ? "revoked" : "pending", line);
    }
  if (bd_sync_close (f) != 0)
    { builtin_error ("rfc5011: %s: write: %s", tmp, strerror (errno)); unlink (tmp); return -1; }
  if (rename (tmp, path) != 0)
    { builtin_error ("rfc5011: rename %s -> %s: %s", tmp, path, strerror (errno));
      unlink (tmp); return -1; }
  return 0;
}

static int
bd_rfc5011_step_cmd (WORD_LIST *args)
{
  const char *dir = NULL, *dnskey_file = NULL;
  long now = -1;
  long holddown = BD_R5011_HOLDDOWN_DEFAULT;
  int have_now = 0;

  for (WORD_LIST *w = args; w; w = w->next)
    {
      const char *a = w->word->word;
      if (strcmp (a, "--anchor-dir") == 0 && w->next)
        { dir = w->next->word->word; w = w->next; }
      else if (strcmp (a, "--dnskey-set") == 0 && w->next)
        { dnskey_file = w->next->word->word; w = w->next; }
      else if (strcmp (a, "--now") == 0 && w->next)
        { now = atol (w->next->word->word); have_now = 1; w = w->next; }
      else if (strcmp (a, "--hold-down") == 0 && w->next)
        { holddown = atol (w->next->word->word); w = w->next; }
      else
        { builtin_error ("rfc5011-step: unexpected arg: %s", a); return EX_USAGE; }
    }
  if (!dir || !dnskey_file || !have_now)
    { builtin_error ("rfc5011-step: --anchor-dir DIR --dnskey-set FILE --now EPOCH [--hold-down SECS]");
      return EX_USAGE; }
  if (holddown < 0)
    { builtin_error ("rfc5011-step: --hold-down must be >= 0"); return EX_USAGE; }

  char active_path[1024], cand_path[1024], prev_path[1024];
  if ((size_t) snprintf (active_path, sizeof active_path, "%s/root.anchor", dir) >= sizeof active_path ||
      (size_t) snprintf (cand_path,   sizeof cand_path,   "%s/root.anchor.candidate", dir) >= sizeof cand_path ||
      (size_t) snprintf (prev_path,   sizeof prev_path,   "%s/root.anchor.previous", dir) >= sizeof prev_path)
    { builtin_error ("rfc5011-step: anchor-dir path too long"); return EX_USAGE; }

  bd_trust_t active[BD_R5011_MAX]; int active_n = 0;
  bd_cand_t  cands[BD_R5011_MAX];  int cand_n = 0;
  bd_trust_t apex[BD_R5011_MAX];   int apex_n = 0;

  if (bd_r5011_read_anchor (active_path, active, BD_R5011_MAX, &active_n) < 0) return EXECUTION_FAILURE;
  if (bd_r5011_read_candidates (cand_path, cands, BD_R5011_MAX, &cand_n) < 0) return EXECUTION_FAILURE;

  /* Load the observed apex DNSKEY set (only DNSKEY entries). */
  {
    int n = 0;
    if (bd_r5011_read_anchor (dnskey_file, apex, BD_R5011_MAX, &n) < 0) return EXECUTION_FAILURE;
    for (int i = 0; i < n; i++)
      if (apex[i].kind == BD_T_DNSKEY) apex[apex_n++] = apex[i];
  }

  int active_changed = 0, cand_changed = 0;

  /* ---- pass 1: process the observed apex set ----------------------- *
   * For each apex DNSKEY decide: revoke / already-active / pending-seen
   * / new-pending. */
  for (int i = 0; i < apex_n; i++)
    {
      bd_trust_t *k = &apex[i];
      int revoked = (k->flags & BD_DNSKEY_REVOKE) != 0;

      if (revoked)
        {
          /* Match against active or candidate by keytag+algo+owner. The
             keytag of a revoked key differs from its unrevoked form
             (the REVOKE bit is inside the flags that feed the keytag),
             so compare by clearing the REVOKE bit and recomputing. */
          bd_trust_t base = *k;
          base.flags &= (uint16_t) ~BD_DNSKEY_REVOKE;
          base.rdata[0] = (unsigned char) (base.flags >> 8);
          base.rdata[1] = (unsigned char) (base.flags & 0xff);
          base.key_tag = bd_dnskey_keytag (base.rdata, base.rdata_len);

          /* Drop from active immediately (untrust now). */
          int was_active = -1;
          for (int j = 0; j < active_n; j++)
            if (bd_key_same (&active[j], &base)) { was_active = j; break; }
          if (was_active >= 0)
            {
              /* Don't auto-empty the anchor set (§5 "all keys revoked"). */
              int other_active = 0;
              for (int j = 0; j < active_n; j++)
                if (j != was_active) other_active++;
              if (other_active == 0)
                {
                  builtin_warning ("rfc5011: refusing to revoke the last active anchor "
                                   "(keytag=%u algo=%u); keeping it trusted",
                                   (unsigned) base.key_tag, (unsigned) base.algorithm);
                  printf ("keytag=%u algo=%u revoke-deferred (last-anchor)\n",
                          (unsigned) base.key_tag, (unsigned) base.algorithm);
                  continue;
                }
              for (int j = was_active; j + 1 < active_n; j++) active[j] = active[j + 1];
              active_n--; active_changed = 1;
            }

          /* Find / create the revoked candidate (start remove hold-down). */
          int ci = -1;
          for (int j = 0; j < cand_n; j++)
            if (bd_key_same (&cands[j].key, &base)) { ci = j; break; }
          if (ci < 0)
            {
              if (cand_n >= BD_R5011_MAX) { builtin_error ("rfc5011: candidate table full"); return EXECUTION_FAILURE; }
              ci = cand_n++;
              memset (&cands[ci], 0, sizeof cands[ci]);
              cands[ci].key = base;
              cands[ci].first_seen = now;
              cands[ci].state = BD_R5011_REVOKED;
              cand_changed = 1;
              printf ("keytag=%u algo=%u revoked (remove hold-down starts)\n",
                      (unsigned) base.key_tag, (unsigned) base.algorithm);
            }
          else if (cands[ci].state != BD_R5011_REVOKED)
            {
              cands[ci].state = BD_R5011_REVOKED;
              cands[ci].first_seen = now;   /* start remove hold-down */
              cand_changed = 1;
              printf ("keytag=%u algo=%u revoked (remove hold-down starts)\n",
                      (unsigned) base.key_tag, (unsigned) base.algorithm);
            }
          continue;
        }

      /* Non-revoked apex key. Already active? */
      int is_active = 0;
      for (int j = 0; j < active_n; j++)
        if (bd_key_same (&active[j], k)) { is_active = 1; break; }
      if (is_active) continue;

      /* Pending already? */
      int ci = -1;
      for (int j = 0; j < cand_n; j++)
        if (bd_key_same (&cands[j].key, k)) { ci = j; break; }
      if (ci >= 0)
        {
          if (cands[ci].state == BD_R5011_REVOKED)
            continue;   /* revoked keys do not un-revoke */
          long elapsed = now - cands[ci].first_seen;
          long left = holddown - elapsed;
          if (left <= 0)
            {
              /* Promotion handled in pass 3 (after we know which pending
                 keys are still present). Mark as ready by leaving it; the
                 promote pass re-derives readiness from first_seen. */
              long days = (left <= 0) ? 0 : (left + 86399) / 86400;
              (void) days;
            }
          else
            {
              long days_left = (left + 86399) / 86400;
              printf ("keytag=%u algo=%u pending %ldd-left\n",
                      (unsigned) k->key_tag, (unsigned) k->algorithm, days_left);
            }
          continue;
        }

      /* Brand-new key: add as PENDING. */
      if (cand_n >= BD_R5011_MAX) { builtin_error ("rfc5011: candidate table full"); return EXECUTION_FAILURE; }
      ci = cand_n++;
      memset (&cands[ci], 0, sizeof cands[ci]);
      cands[ci].key = *k;
      cands[ci].first_seen = now;
      cands[ci].state = BD_R5011_PENDING;
      cand_changed = 1;
      printf ("keytag=%u algo=%u added (pending, first-seen=%ld)\n",
              (unsigned) k->key_tag, (unsigned) k->algorithm, now);
    }

  /* ---- pass 2: PENDING keys missing from the apex set -> drop ------ *
   * §2.4.1: a pending key that disappears before promotion resets. */
  for (int j = 0; j < cand_n; )
    {
      if (cands[j].state != BD_R5011_PENDING) { j++; continue; }
      int present = 0;
      for (int i = 0; i < apex_n; i++)
        if ((apex[i].flags & BD_DNSKEY_REVOKE) == 0 && bd_key_same (&apex[i], &cands[j].key))
          { present = 1; break; }
      if (!present)
        {
          printf ("keytag=%u algo=%u dropped (missing before promotion)\n",
                  (unsigned) cands[j].key.key_tag, (unsigned) cands[j].key.algorithm);
          for (int m = j; m + 1 < cand_n; m++) cands[m] = cands[m + 1];
          cand_n--; cand_changed = 1;
          continue;
        }
      j++;
    }

  /* ---- pass 3: promote PENDING keys that cleared the hold-down ----- */
  {
    int promote_idx[BD_R5011_MAX]; int promote_n = 0;
    for (int j = 0; j < cand_n; j++)
      if (cands[j].state == BD_R5011_PENDING && now - cands[j].first_seen >= holddown)
        promote_idx[promote_n++] = j;

    if (promote_n > 0)
      {
        /* Retain exactly one prior version: snapshot current active set. */
        if (active_n > 0)
          { if (bd_r5011_write_anchor (prev_path, active, active_n) < 0) return EXECUTION_FAILURE; }
        for (int p = 0; p < promote_n; p++)
          {
            bd_cand_t *c = &cands[promote_idx[p]];
            if (active_n >= BD_R5011_MAX) { builtin_error ("rfc5011: active table full"); return EXECUTION_FAILURE; }
            active[active_n++] = c->key;
            active_changed = 1;
            printf ("keytag=%u algo=%u promoted (now active)\n",
                    (unsigned) c->key.key_tag, (unsigned) c->key.algorithm);
          }
        /* Remove promoted entries from candidates (iterate high->low). */
        for (int p = promote_n - 1; p >= 0; p--)
          {
            int idx = promote_idx[p];
            for (int m = idx; m + 1 < cand_n; m++) cands[m] = cands[m + 1];
            cand_n--;
          }
        cand_changed = 1;
      }
  }

  /* ---- pass 4: REVOKED keys past the remove hold-down -> delete ---- */
  for (int j = 0; j < cand_n; )
    {
      if (cands[j].state == BD_R5011_REVOKED && now - cands[j].first_seen >= holddown)
        {
          printf ("keytag=%u algo=%u removed (remove hold-down elapsed)\n",
                  (unsigned) cands[j].key.key_tag, (unsigned) cands[j].key.algorithm);
          for (int m = j; m + 1 < cand_n; m++) cands[m] = cands[m + 1];
          cand_n--; cand_changed = 1;
          continue;
        }
      else if (cands[j].state == BD_R5011_REVOKED)
        {
          long left = holddown - (now - cands[j].first_seen);
          long days_left = (left + 86399) / 86400;
          printf ("keytag=%u algo=%u revoked %ldd-left\n",
                  (unsigned) cands[j].key.key_tag, (unsigned) cands[j].key.algorithm, days_left);
        }
      j++;
    }

  /* ---- persist (atomic) ------------------------------------------- */
  if (active_changed)
    { if (bd_r5011_write_anchor (active_path, active, active_n) < 0) return EXECUTION_FAILURE; }
  if (cand_changed)
    { if (bd_r5011_write_candidates (cand_path, cands, cand_n) < 0) return EXECUTION_FAILURE; }

  return EXECUTION_SUCCESS;
}

static int bd_server_port (void);
static int bd_make_sockaddr (const char *addr, int port,
                             struct sockaddr_storage *ss,
                             socklen_t *slen);
static int bd_sock_family (const struct sockaddr_storage *ss);

/* Send query, recv response. Caller-allocated reply buffer.
   Returns reply length, -1 on error (with builtin_error called). */
static int
bd_query (const char *qname, uint16_t qtype, const char *server,
          int dnssec, int timeout_ms, unsigned char *reply, size_t reply_sz)
{
  unsigned char query[768];
  char mixed_qname[256];
  const char *verify_qname = NULL;
  const char *wire_qname = bd_prepare_wire_qname (qname, mixed_qname,
                                                  sizeof mixed_qname,
                                                  &verify_qname);
  if (!wire_qname) { builtin_error ("query: name too long"); return -1; }
  uint16_t id = bd_random_u16 ();
  int qlen = bd_build_query (id, wire_qname, qtype, dnssec, query, sizeof query);
  if (qlen < 0) { builtin_error ("query: name too long"); return -1; }

  struct sockaddr_storage sa;
  socklen_t sl = 0;
  int dport = bd_server_port ();
  if (bd_make_sockaddr (server, dport, &sa, &sl) < 0)
    { builtin_error ("bad nameserver: %s", server); return -1; }

  int s = socket (bd_sock_family (&sa), SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (s < 0) { builtin_error ("socket: %s", strerror (errno)); return -1; }
  struct timeval tv = { .tv_sec = timeout_ms / 1000,
                         .tv_usec = (timeout_ms % 1000) * 1000 };
  setsockopt (s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  setsockopt (s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

  ssize_t n = sendto (s, query, (size_t) qlen, 0,
                      (struct sockaddr *) &sa, sl);
  if (n < 0) { builtin_error ("sendto %s: %s", server, strerror (errno)); close (s); return -1; }

  n = recvfrom (s, reply, reply_sz, 0, NULL, NULL);
  close (s);
  if (n < 0) { builtin_error ("recvfrom: %s", strerror (errno)); return -1; }
  if (bd_validate_reply (reply, (size_t) n, id) < 0) return -1;
  if (bd_0x20_verify (reply, (size_t) n, verify_qname) < 0) return -1;
  if (bd_tc_bit (reply, (size_t) n))
    {
      int tn = bd_query_tcp (query, (size_t) qlen, server, timeout_ms, reply, reply_sz);
      if (tn < 0) return -1;
      if (bd_validate_reply (reply, (size_t) tn, id) < 0) return -1;
      if (bd_0x20_verify (reply, (size_t) tn, verify_qname) < 0) return -1;
      return tn;
    }
  return (int) n;
}

static int
bd_ad_bit (const unsigned char *reply, size_t rlen)
{
  return rlen >= 4 && (reply[3] & 0x20) != 0;
}

static int
bd_tc_bit (const unsigned char *reply, size_t rlen)
{
  return rlen >= 3 && (reply[2] & 0x02) != 0;
}

static int
bd_validate_reply (const unsigned char *reply, size_t rlen, uint16_t id)
{
  if (rlen < 12) { builtin_error ("short reply"); return -1; }
  uint16_t rid = bd_rd16 (reply);
  if (rid != id) { builtin_error ("response id mismatch"); return -1; }
  int rcode = reply[3] & 0xf;
  if (rcode != 0)
    {
      static const char *rcodes[] = {
        "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"
      };
      const char *rname = (rcode <= 5) ? rcodes[rcode] : "rcode";
      builtin_error ("dns response: %s (%d)", rname, rcode);
      return -1;
    }
  return 0;
}

static int
bd_write_all (int fd, const unsigned char *buf, size_t len)
{
  size_t off = 0;
  while (off < len)
    {
      ssize_t n = write (fd, buf + off, len - off);
      if (n < 0)
        {
          if (errno == EINTR) continue;
          return -1;
        }
      if (n == 0) return -1;
      off += (size_t) n;
    }
  return 0;
}

static int
bd_read_exact (int fd, unsigned char *buf, size_t len)
{
  size_t off = 0;
  while (off < len)
    {
      ssize_t n = read (fd, buf + off, len - off);
      if (n < 0)
        {
          if (errno == EINTR) continue;
          return -1;
        }
      if (n == 0) return -1;
      off += (size_t) n;
    }
  return 0;
}

static int
bd_read_exact_timeout (int fd, unsigned char *buf, size_t len, int timeout_ms)
{
  size_t off = 0;
  struct timespec start, now;
  clock_gettime (CLOCK_MONOTONIC, &start);
  while (off < len)
    {
      clock_gettime (CLOCK_MONOTONIC, &now);
      long elapsed_ms = (long) ((now.tv_sec - start.tv_sec) * 1000L +
                                (now.tv_nsec - start.tv_nsec) / 1000000L);
      long remain_ms = (long) timeout_ms - elapsed_ms;
      if (remain_ms <= 0) { errno = ETIMEDOUT; return -1; }

      fd_set rfds;
      FD_ZERO (&rfds);
      FD_SET (fd, &rfds);
      struct timeval tv = { .tv_sec = remain_ms / 1000,
                            .tv_usec = (remain_ms % 1000) * 1000 };
      int sr = select (fd + 1, &rfds, NULL, NULL, &tv);
      if (sr < 0)
        {
          if (errno == EINTR) continue;
          return -1;
        }
      if (sr == 0) { errno = ETIMEDOUT; return -1; }

      ssize_t n = read (fd, buf + off, len - off);
      if (n < 0)
        {
          if (errno == EINTR) continue;
          return -1;
        }
      if (n == 0) return -1;
      off += (size_t) n;
    }
  return 0;
}

static int
bd_server_port (void)
{
  const char *env = getenv ("BASHDNS_SERVER_PORT");
  if (!env || !*env) return 53;
  char *end = NULL;
  long port = strtol (env, &end, 10);
  if (*end != '\0' || port <= 0 || port > 65535)
    return 53;
  return (int) port;
}

static int
bd_listen_family (const char *addr)
{
  return (addr && strchr (addr, ':')) ? AF_INET6 : AF_INET;
}

static int
bd_make_sockaddr_family (const char *addr, int port, int family,
                         struct sockaddr_storage *ss, socklen_t *slen)
{
  if (!addr || !*addr || port <= 0 || port > 65535 || !ss || !slen)
    return -1;
  if (family == AF_UNSPEC)
    family = bd_listen_family (addr);
  memset (ss, 0, sizeof *ss);
  if (family == AF_INET)
    {
      struct sockaddr_in *sa = (struct sockaddr_in *) ss;
      sa->sin_family = AF_INET;
      sa->sin_port = htons ((uint16_t) port);
      if (inet_pton (AF_INET, addr, &sa->sin_addr) != 1)
        return -1;
      *slen = sizeof *sa;
      return 0;
    }
  if (family == AF_INET6)
    {
      struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) ss;
      sa6->sin6_family = AF_INET6;
      sa6->sin6_port = htons ((uint16_t) port);
      if (inet_pton (AF_INET6, addr, &sa6->sin6_addr) != 1)
        return -1;
      *slen = sizeof *sa6;
      return 0;
    }
  return -1;
}

static int
bd_make_sockaddr (const char *addr, int port, struct sockaddr_storage *ss,
                  socklen_t *slen)
{
  return bd_make_sockaddr_family (addr, port, AF_UNSPEC, ss, slen);
}

static int
bd_sock_family (const struct sockaddr_storage *ss)
{
  return ss ? ss->ss_family : AF_UNSPEC;
}

static int
bd_split_host_port_default (const char *in, char *host, size_t hsz, int *port,
                            int default_port)
{
  if (!in || !*in || !host || hsz == 0 || !port)
    return -1;
  *port = default_port;

  if (in[0] == '[')
    {
      const char *end = strchr (in, ']');
      if (!end || end == in + 1)
        return -1;
      size_t n = (size_t) (end - in - 1);
      if (n >= hsz)
        return -1;
      memcpy (host, in + 1, n);
      host[n] = '\0';
      if (end[1] == '\0')
        return 0;
      if (end[1] != ':' || end[2] == '\0')
        return -1;
      char *pe = NULL;
      long p = strtol (end + 2, &pe, 10);
      if (!pe || *pe || p <= 0 || p > 65535)
        return -1;
      *port = (int) p;
      return 0;
    }

  const char *first_colon = strchr (in, ':');
  const char *last_colon = strrchr (in, ':');
  if (first_colon && first_colon == last_colon)
    {
      size_t n = (size_t) (last_colon - in);
      if (n == 0 || n >= hsz || last_colon[1] == '\0')
        return -1;
      memcpy (host, in, n);
      host[n] = '\0';
      char *pe = NULL;
      long p = strtol (last_colon + 1, &pe, 10);
      if (!pe || *pe || p <= 0 || p > 65535)
        return -1;
      *port = (int) p;
      return 0;
    }

  if (strlen (in) >= hsz)
    return -1;
  strcpy (host, in);
  return 0;
}

static int
bd_set_ipv6_v6only (int fd, int family, int v6only)
{
#if defined (IPV6_V6ONLY)
  if (family == AF_INET6)
    {
      int val = v6only ? 1 : 0;
      if (setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof val) < 0)
        return -1;
    }
#else
  (void) fd;
  (void) family;
  (void) v6only;
#endif
  return 0;
}

static int
bd_bind_dgram_stream (const char *addr, int port, int force_family, int v6only,
                      int *us, int *ts)
{
  struct sockaddr_storage sa;
  socklen_t sl = 0;
  int family = force_family == AF_INET6 ? AF_INET6 : AF_UNSPEC;
  if (bd_make_sockaddr_family (addr, port, family, &sa, &sl) < 0)
    { builtin_error ("bad listen addr: %s", addr ? addr : "(null)"); return -1; }
  family = bd_sock_family (&sa);

  int u = -1, t = -1;
  if (family == AF_INET6)
    {
      u = socket (AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
      t = socket (AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    }
  else
    {
      u = socket (AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
      t = socket (AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    }
  if (u < 0 || t < 0)
    { builtin_error ("socket: %s", strerror (errno)); if (u >= 0) close (u); if (t >= 0) close (t); return -1; }
  int one = 1;
  setsockopt (u, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  setsockopt (t, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  if (bd_set_ipv6_v6only (u, family, v6only) < 0 ||
      bd_set_ipv6_v6only (t, family, v6only) < 0)
    { builtin_error ("setsockopt IPV6_V6ONLY: %s", strerror (errno)); close (u); close (t); return -1; }
  if (bind (u, (struct sockaddr *) &sa, sl) < 0 ||
      bind (t, (struct sockaddr *) &sa, sl) < 0)
    { builtin_error ("bind %s:%d: %s", addr, port, strerror (errno)); close (u); close (t); return -1; }
  *us = u;
  *ts = t;
  return 0;
}

static int
bd_peer_v4 (const struct sockaddr_storage *ss, struct in_addr *out)
{
  if (!ss || !out)
    return -1;
  if (ss->ss_family == AF_INET)
    {
      const struct sockaddr_in *sa = (const struct sockaddr_in *) ss;
      *out = sa->sin_addr;
      return 0;
    }
  if (ss->ss_family == AF_INET6)
    {
      const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6 *) ss;
      const unsigned char *a = sa6->sin6_addr.s6_addr;
      int mapped = 1;
      for (int i = 0; i < 10; i++)
        if (a[i] != 0) { mapped = 0; break; }
      if (mapped && a[10] == 0xff && a[11] == 0xff)
        {
          memcpy (&out->s_addr, a + 12, 4);
          return 0;
        }
    }
  return -1;
}

static int
bd_query_tcp (const unsigned char *query, size_t qlen, const char *server,
              int timeout_ms, unsigned char *reply, size_t reply_sz)
{
  struct sockaddr_storage sa;
  socklen_t sl = 0;
  int dport = bd_server_port ();
  if (bd_make_sockaddr (server, dport, &sa, &sl) < 0)
    { builtin_error ("bad nameserver: %s", server); return -1; }

  int s = socket (bd_sock_family (&sa), SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (s < 0) { builtin_error ("tcp socket: %s", strerror (errno)); return -1; }
  struct timeval tv = { .tv_sec = timeout_ms / 1000,
                         .tv_usec = (timeout_ms % 1000) * 1000 };
  setsockopt (s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  setsockopt (s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
  if (connect (s, (struct sockaddr *) &sa, sl) < 0)
    { builtin_error ("tcp connect %s: %s", server, strerror (errno)); close (s); return -1; }

  if (qlen > 65535) { close (s); builtin_error ("query too large"); return -1; }
  unsigned char hdr[2] = { (unsigned char) (qlen >> 8), (unsigned char) (qlen & 0xff) };
  if (bd_write_all (s, hdr, sizeof hdr) < 0 ||
      bd_write_all (s, query, qlen) < 0)
    { builtin_error ("tcp write %s: %s", server, strerror (errno)); close (s); return -1; }

  unsigned char lenbuf[2];
  if (bd_read_exact (s, lenbuf, sizeof lenbuf) < 0)
    { builtin_error ("tcp read length %s: %s", server, strerror (errno)); close (s); return -1; }
  size_t rlen = ((size_t) lenbuf[0] << 8) | lenbuf[1];
  if (rlen > reply_sz)
    { builtin_error ("tcp reply too large: %lu bytes", (unsigned long) rlen); close (s); return -1; }
  if (bd_read_exact (s, reply, rlen) < 0)
    { builtin_error ("tcp read reply %s: %s", server, strerror (errno)); close (s); return -1; }
  close (s);
  return (int) rlen;
}

/* ---- DNS-over-TLS (RFC 7858) -------------------------------------- *
 *
 * Wraps a TCP-framed DNS query in a TLS 1.2/1.3 session against an
 * authenticating resolver. We dispatch via `bash -c "builtin crypto
 * tls connect HOST:PORT [-c CA]"` for the same reason DNSSEC dispatches
 * to crypto verify verbs (see the comment block above
 * bd_run_verifier): the TLS state machine and trust-anchor parsing live
 * in crypto.c, and a fork-and-pipe keeps dns.c free of mbedTLS
 * baggage while giving crash isolation.
 *
 * Trust contract: crypto's `tls connect` defaults to
 * MBEDTLS_SSL_VERIFY_REQUIRED, auto-loads /etc/ssl/cert.pem when -c is
 * unset, and aborts the handshake on any verification failure. So a
 * misconfigured or attacker-substituted DoT host (bad cert, expired
 * cert, wrong SNI) yields a non-zero exit from the child and we fail
 * closed here without emitting a parsed answer.
 *
 * Tests use BASHDNS_DOT_CMD to substitute a stub that reads a wire
 * fixture instead of contacting a real resolver. The stub semantics
 * mirror crypto: slurp stdin (the TCP-framed query), write the
 * TCP-framed reply to stdout. Verification failures from the stub
 * surface as non-zero exit.
 */
static int
bd_query_dot (const unsigned char *query, size_t qlen, const char *dot_host,
              int port, const char *ca_path, int timeout_ms,
              unsigned char *reply, size_t reply_sz)
{
  if (qlen > 65535) { builtin_error ("dot: query too large"); return -1; }

  const char *override = getenv ("BASHDNS_DOT_CMD");
  /* Compose host:port into a single token in the parent; passed to bash
   * as a positional parameter so the script body remains a constant
   * literal and bash never re-parses dot_host as a shell expression. */
  char hostport[512];
  if (!override || !*override)
    {
      if ((size_t) snprintf (hostport, sizeof hostport, "%s:%d", dot_host, port) >= sizeof hostport)
        { builtin_error ("dot: host too long"); return -1; }
    }

  int pin[2], pout[2];
  if (pipe (pin) < 0)
    { builtin_error ("dot: pipe: %s", strerror (errno)); return -1; }
  if (pipe (pout) < 0)
    { close (pin[0]); close (pin[1]);
      builtin_error ("dot: pipe: %s", strerror (errno)); return -1; }

  struct bd_child_guard guard;
  if (bd_child_guard_begin (&guard) < 0)
    {
      builtin_error ("dot: SIGCHLD guard: %s", strerror (errno));
      close (pin[0]); close (pin[1]); close (pout[0]); close (pout[1]);
      return -1;
    }

  pid_t pid = fork ();
  if (pid < 0)
    { builtin_error ("dot: fork: %s", strerror (errno));
      close (pin[0]); close (pin[1]); close (pout[0]); close (pout[1]);
      bd_child_guard_parent_end (&guard); return -1; }
  if (pid == 0)
    {
      bd_child_guard_child_end (&guard);
      close (pin[1]); close (pout[0]);
      if (dup2 (pin[0], 0) < 0) _exit (127);
      if (dup2 (pout[1], 1) < 0) _exit (127);
      close (pin[0]); close (pout[1]);
      /* Keep stderr connected so handshake/verification diagnostics
       * still reach the user even though we route the answer parsing
       * through stdout.
       *
       * Default path is a constant `-c` script body; dot_host (and the
       * optional CA path) arrive as POSITIONAL parameters via "$@" so
       * bash never re-parses caller-supplied hostnames as shell. The
       * override branch is reserved for the documented BASHDNS_DOT_CMD
       * test hook (e.g. `python3 '/tmp/dot_stub.py'`); operator-set, not
       * part of the production execution path. */
      if (override && *override)
        execlp ("bash", "bash", "-c", override, (char *) NULL);
      else if (ca_path && *ca_path)
        execlp ("bash", "bash", "-c", "builtin crypto tls connect \"$1\" -s \"$2\" -c \"$3\"", "_", hostport, dot_host, ca_path, (char *) NULL);
      else
        execlp ("bash", "bash", "-c", "builtin crypto tls connect \"$1\" -s \"$2\"", "_", hostport, dot_host, (char *) NULL);
      _exit (127);
    }
  close (pin[0]); close (pout[1]);

  /* Write TCP-framed query. */
  unsigned char hdr[2] = { (unsigned char) (qlen >> 8),
                           (unsigned char) (qlen & 0xff) };
  int werr = 0;
  if (bd_write_all (pin[1], hdr, sizeof hdr) < 0) werr = 1;
  else if (bd_write_all (pin[1], query, qlen) < 0) werr = 1;
  close (pin[1]);

  int rc = -1;
  if (!werr)
    {
      unsigned char lenbuf[2];
      if (bd_read_exact_timeout (pout[0], lenbuf, sizeof lenbuf, timeout_ms) == 0)
        {
          size_t rlen = ((size_t) lenbuf[0] << 8) | lenbuf[1];
          if (rlen > reply_sz)
            builtin_error ("dot: reply too large: %lu bytes", (unsigned long) rlen);
          else if (bd_read_exact_timeout (pout[0], reply, rlen, timeout_ms) == 0)
            rc = (int) rlen;
        }
    }
  close (pout[0]);

  int st = 0;
  pid_t wp;

  if (werr || rc < 0)
    {
      /* Timeout/error cleanup with a bounded SIGKILL escalation.
         Send SIGTERM, then poll waitpid with WNOHANG for up to ~500 ms
         in 25 ms slices. If the child still hasn't reaped — e.g., a
         BASHDNS_DOT_CMD wrapper that traps SIGTERM, or a wedged TLS
         subprocess stuck in a non-interruptible syscall — escalate to
         SIGKILL which cannot be ignored, then do a final blocking
         waitpid that the kernel guarantees will return promptly.
         This bounds cleanup latency at ~500 ms plus SIGKILL delivery
         so the parent never hangs indefinitely on a misbehaving DoT
         helper. EINTR retries don't consume the budget. */
      kill (pid, SIGTERM);
      wp = 0;
      for (int i = 0; i < 20; i++)
        {
          wp = waitpid (pid, &st, WNOHANG);
          if (wp < 0 && errno == EINTR) { wp = 0; continue; }
          if (wp != 0) break;                   /* reaped or fatal error */
          struct timespec slp = { 0, 25L * 1000L * 1000L };  /* 25 ms */
          nanosleep (&slp, NULL);
        }
      if (wp == 0)
        {
          /* Still alive after the SIGTERM window — escalate. SIGKILL
             cannot be trapped or ignored, so the blocking waitpid
             returns once the kernel finishes tearing the child down. */
          kill (pid, SIGKILL);
          do {
            wp = waitpid (pid, &st, 0);
          } while (wp < 0 && errno == EINTR);
        }
    }
  else
    {
      do {
        wp = waitpid (pid, &st, 0);
      } while (wp < 0 && errno == EINTR);
    }
  bd_child_guard_parent_end (&guard);

  if (wp < 0)
    { builtin_error ("dot: waitpid: %s", strerror (errno)); return -1; }
  if (!WIFEXITED (st) || WEXITSTATUS (st) != 0)
    {
      builtin_error ("dot: TLS transport failed (rc=%d signal=%d)",
                     WIFEXITED (st) ? WEXITSTATUS (st) : -1,
                     WIFSIGNALED (st) ? WTERMSIG (st) : 0);
      return -1;
    }
  if (rc < 0)
    { builtin_error ("dot: short or empty reply from resolver"); return -1; }
  return rc;
}

/* ---- DNS-over-HTTPS (RFC 8484, POST profile) ---------------------- *
 *
 * Minimal explicit transport: dns still owns DNS packet creation,
 * reply-size bounds, and response-id validation; HTTP/TLS is delegated
 * to curl/crypto in a child process. The production child uses a
 * constant shell body with the endpoint URL passed as a positional
 * parameter. The endpoint is validated before this point to keep
 * curl's HTTPS child command away from shell-significant host text.
 *
 * Tests use BASHDNS_DOH_CMD to substitute a stub that reads the raw DNS
 * query on stdin and writes the raw DNS reply on stdout.
 */
static int
bd_doh_url_valid (const char *url)
{
  if (!url || !*url) return 0;
  if (strncmp (url, "https://", 8) != 0) return 0;
  const char *p = url + 8;
  const char *slash = strchr (p, '/');
  if (!slash || slash == p) return 0;
  size_t hostport_len = (size_t) (slash - p);
  if (hostport_len >= 256) return 0;
  char hostport[256];
  memcpy (hostport, p, hostport_len);
  hostport[hostport_len] = '\0';

  char *colon = strchr (hostport, ':');
  if (colon)
    {
      *colon++ = '\0';
      if (!*colon) return 0;
      for (char *q = colon; *q; q++)
        if (!isdigit ((unsigned char) *q)) return 0;
      long port = strtol (colon, NULL, 10);
      if (port <= 0 || port > 65535) return 0;
    }
  if (!hostport[0]) return 0;
  for (char *q = hostport; *q; q++)
    if (!(isalnum ((unsigned char) *q) || *q == '-' || *q == '.'))
      return 0;
  for (const char *q = slash; *q; q++)
    if ((unsigned char) *q < 0x21 || strchr ("'\"`$\\|;&<>(){}", *q))
      return 0;
  return 1;
}

static int
bd_b64urlval (int c)
{
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '-') return 62;
  if (c == '_') return 63;
  return -1;
}

static int
bd_unb64url (const char *s, size_t slen, unsigned char *out, size_t out_sz,
             size_t *out_len)
{
  uint32_t acc = 0;
  int bits = 0;
  size_t n = 0;
  size_t significant = 0;
  int saw_pad = 0;

  for (size_t i = 0; i < slen; i++)
    {
      unsigned char c = (unsigned char) s[i];
      if (c == '=')
        {
          saw_pad = 1;
          continue;
        }
      if (saw_pad) return -1;
      int v = bd_b64urlval (c);
      if (v < 0) return -1;
      significant++;
      acc = (acc << 6) | (uint32_t) v;
      bits += 6;
      if (bits >= 8)
        {
          bits -= 8;
          if (n >= out_sz) return -2;
          out[n++] = (unsigned char) ((acc >> bits) & 0xff);
        }
    }
  if (significant == 0 || (significant % 4) == 1) return -1;
  *out_len = n;
  return 0;
}

static int
bd_pct_decode (const char *s, size_t slen, char *out, size_t out_sz,
               size_t *out_len)
{
  size_t n = 0;
  for (size_t i = 0; i < slen; i++)
    {
      unsigned char c = (unsigned char) s[i];
      if (c == '%')
        {
          if (i + 2 >= slen) return -1;
          int hi = bd_hexval ((unsigned char) s[i + 1]);
          int lo = bd_hexval ((unsigned char) s[i + 2]);
          if (hi < 0 || lo < 0) return -1;
          c = (unsigned char) ((hi << 4) | lo);
          i += 2;
        }
      if (n + 1 >= out_sz) return -2;
      out[n++] = (char) c;
    }
  out[n] = '\0';
  *out_len = n;
  return 0;
}

static int
bd_doh_content_type_ok (const char *ctype)
{
  if (!ctype) return 0;
  while (*ctype == ' ' || *ctype == '\t') ctype++;
  const char *want = "application/dns-message";
  size_t n = strlen (want);
  if (strncasecmp (ctype, want, n) != 0) return 0;
  ctype += n;
  while (*ctype == ' ' || *ctype == '\t') ctype++;
  return *ctype == '\0' || *ctype == ';';
}

static int
bd_doh_decode_get (const char *path, unsigned char *out_wire,
                   size_t out_sz, size_t *out_len)
{
  const char *q = path ? strchr (path, '?') : NULL;
  if (!q) return 400;
  q++;
  while (*q)
    {
      const char *amp = strchr (q, '&');
      size_t part_len = amp ? (size_t) (amp - q) : strlen (q);
      const char *eq = memchr (q, '=', part_len);
      if (eq && (size_t) (eq - q) == 3 &&
          strncmp (q, "dns", 3) == 0)
        {
          const char *val = eq + 1;
          size_t val_len = part_len - (size_t) (val - q);
          char dec[BD_DOH_WIRE_MAX + 8];
          size_t dec_len = 0;
          int pr = bd_pct_decode (val, val_len, dec, sizeof dec, &dec_len);
          if (pr < 0) return pr == -2 ? 413 : 400;
          int br = bd_unb64url (dec, dec_len, out_wire, out_sz, out_len);
          if (br < 0) return br == -2 ? 413 : 400;
          if (*out_len < 12) return 400;
          return 200;
        }
      if (!amp) break;
      q = amp + 1;
    }
  return 400;
}

static int
bd_doh_decode_request (const char *method, const char *path,
                       const unsigned char *body, size_t body_len,
                       const char *ctype, unsigned char *out_wire,
                       size_t out_sz, size_t *out_len)
{
  if (!method || !out_wire || !out_len) return 400;
  *out_len = 0;
  if (strcasecmp (method, "GET") == 0)
    return bd_doh_decode_get (path, out_wire, out_sz, out_len);
  if (strcasecmp (method, "POST") == 0)
    {
      if (!bd_doh_content_type_ok (ctype)) return 415;
      if (body_len > BD_DOH_WIRE_MAX || body_len > out_sz) return 413;
      if (body_len < 12) return 400;
      memcpy (out_wire, body, body_len);
      *out_len = body_len;
      return 200;
    }
  return 405;
}

static int
bd_doh_encode_response (const unsigned char *wire, size_t wire_len,
                        unsigned char *out_http, size_t out_sz,
                        size_t *out_len)
{
  if (!wire || !out_http || !out_len || wire_len > BD_DOH_WIRE_MAX)
    return -1;
  char hdr[256];
  int hn = snprintf (hdr, sizeof hdr,
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: application/dns-message\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n\r\n",
                     wire_len);
  if (hn < 0 || (size_t) hn >= sizeof hdr) return -1;
  if ((size_t) hn + wire_len > out_sz) return -1;
  memcpy (out_http, hdr, (size_t) hn);
  memcpy (out_http + hn, wire, wire_len);
  *out_len = (size_t) hn + wire_len;
  return 0;
}

static int
bd_read_until_close_timeout (int fd, unsigned char *buf, size_t cap,
                             int timeout_ms, size_t *out_len)
{
  size_t got = 0;
  struct timespec start, now;
  clock_gettime (CLOCK_MONOTONIC, &start);
  for (;;)
    {
      clock_gettime (CLOCK_MONOTONIC, &now);
      long elapsed_ms = (long) ((now.tv_sec - start.tv_sec) * 1000L +
                                (now.tv_nsec - start.tv_nsec) / 1000000L);
      long remain_ms = (long) timeout_ms - elapsed_ms;
      if (remain_ms <= 0) { errno = ETIMEDOUT; return -1; }

      fd_set rfds;
      FD_ZERO (&rfds);
      FD_SET (fd, &rfds);
      struct timeval tv = { .tv_sec = remain_ms / 1000,
                            .tv_usec = (remain_ms % 1000) * 1000 };
      int sr = select (fd + 1, &rfds, NULL, NULL, &tv);
      if (sr < 0)
        {
          if (errno == EINTR) continue;
          return -1;
        }
      if (sr == 0) { errno = ETIMEDOUT; return -1; }

      if (got == cap) { errno = EMSGSIZE; return -1; }
      ssize_t n = read (fd, buf + got, cap - got);
      if (n < 0)
        {
          if (errno == EINTR) continue;
          return -1;
        }
      if (n == 0)
        {
          *out_len = got;
          return 0;
        }
      got += (size_t) n;
    }
}

static int
bd_dot_accept_filter (const unsigned char *in, size_t in_len,
                      unsigned char *out, size_t out_sz, size_t *out_len,
                      int timeout_ms)
{
  const char *override = getenv ("BASHDNS_DOT_ACCEPT_CMD");
  *out_len = 0;
  if (!override || !*override)
    {
      if (in_len > out_sz) return -2;
      memcpy (out, in, in_len);
      *out_len = in_len;
      return 0;
    }

  int pin[2], pout[2];
  if (pipe (pin) < 0) return -1;
  if (pipe (pout) < 0)
    { close (pin[0]); close (pin[1]); return -1; }

  struct bd_child_guard guard;
  if (bd_child_guard_begin (&guard) < 0)
    {
      close (pin[0]); close (pin[1]); close (pout[0]); close (pout[1]);
      return -1;
    }

  pid_t pid = fork ();
  if (pid < 0)
    {
      bd_child_guard_parent_end (&guard);
      close (pin[0]); close (pin[1]); close (pout[0]); close (pout[1]);
      return -1;
    }
  if (pid == 0)
    {
      bd_child_guard_child_end (&guard);
      close (pin[1]); close (pout[0]);
      if (dup2 (pin[0], 0) < 0) _exit (127);
      if (dup2 (pout[1], 1) < 0) _exit (127);
      close (pin[0]); close (pout[1]);
      execlp ("bash", "bash", "-c", override, (char *) NULL);
      _exit (127);
    }

  close (pin[0]); close (pout[1]);
  int werr = 0;
  if (bd_write_all (pin[1], in, in_len) < 0) werr = 1;
  close (pin[1]);

  int rc = -1;
  size_t got = 0;
  if (!werr && bd_read_until_close_timeout (pout[0], out, out_sz,
                                            timeout_ms, &got) == 0)
    rc = 0;
  close (pout[0]);

  int st = 0;
  pid_t wp;
  if (werr || rc < 0)
    kill (pid, SIGTERM);
  do {
    wp = waitpid (pid, &st, 0);
  } while (wp < 0 && errno == EINTR);
  bd_child_guard_parent_end (&guard);

  if (wp < 0) return -1;
  if (!WIFEXITED (st) || WEXITSTATUS (st) != 0) return -3;
  if (rc < 0) return errno == EMSGSIZE ? -2 : -1;
  *out_len = got;
  return 0;
}

static int
bd_query_doh (const unsigned char *query, size_t qlen, const char *url,
              int timeout_ms, unsigned char *reply, size_t reply_sz)
{
  if (!bd_doh_url_valid (url))
    { builtin_error ("doh: URL must be https://HOST[:PORT]/PATH with a simple host"); return -1; }

  const char *override = getenv ("BASHDNS_DOH_CMD");
  int pin[2], pout[2];
  if (pipe (pin) < 0)
    { builtin_error ("doh: pipe: %s", strerror (errno)); return -1; }
  if (pipe (pout) < 0)
    { close (pin[0]); close (pin[1]);
      builtin_error ("doh: pipe: %s", strerror (errno)); return -1; }

  struct bd_child_guard guard;
  if (bd_child_guard_begin (&guard) < 0)
    {
      builtin_error ("doh: SIGCHLD guard: %s", strerror (errno));
      close (pin[0]); close (pin[1]); close (pout[0]); close (pout[1]);
      return -1;
    }

  pid_t pid = fork ();
  if (pid < 0)
    { builtin_error ("doh: fork: %s", strerror (errno));
      close (pin[0]); close (pin[1]); close (pout[0]); close (pout[1]);
      bd_child_guard_parent_end (&guard); return -1; }
  if (pid == 0)
    {
      bd_child_guard_child_end (&guard);
      close (pin[1]); close (pout[0]);
      if (dup2 (pin[0], 0) < 0) _exit (127);
      if (dup2 (pout[1], 1) < 0) _exit (127);
      close (pin[0]); close (pout[1]);
      if (override && *override)
        execlp ("bash", "bash", "-c", override, (char *) NULL);
      else
        {
          char sec[16];
          int timeout_s = (timeout_ms + 999) / 1000;
          if (timeout_s < 1) timeout_s = 1;
          snprintf (sec, sizeof sec, "%d", timeout_s);
          execlp ("bash", "bash", "-c",
                  "builtin curl -fsS --max-time \"$1\" "
                  "-H 'Accept: application/dns-message' "
                  "-H 'Content-Type: application/dns-message' "
                  "--data-binary @- \"$2\"",
                  "_", sec, url, (char *) NULL);
        }
      _exit (127);
    }
  close (pin[0]); close (pout[1]);

  int werr = 0;
  if (bd_write_all (pin[1], query, qlen) < 0) werr = 1;
  close (pin[1]);

  int rc = -1;
  size_t got = 0;
  if (!werr)
    {
      if (bd_read_until_close_timeout (pout[0], reply, reply_sz,
                                       timeout_ms, &got) == 0)
        rc = (int) got;
    }
  close (pout[0]);

  int st = 0;
  pid_t wp = 0;
  if (werr || rc < 0)
    {
      kill (pid, SIGTERM);
      for (int i = 0; i < 20; i++)
        {
          wp = waitpid (pid, &st, WNOHANG);
          if (wp < 0 && errno == EINTR) { wp = 0; continue; }
          if (wp != 0) break;
          struct timespec slp = { 0, 25L * 1000L * 1000L };
          nanosleep (&slp, NULL);
        }
      if (wp == 0)
        {
          kill (pid, SIGKILL);
          do {
            wp = waitpid (pid, &st, 0);
          } while (wp < 0 && errno == EINTR);
        }
    }
  else
    {
      do {
        wp = waitpid (pid, &st, 0);
      } while (wp < 0 && errno == EINTR);
    }
  bd_child_guard_parent_end (&guard);

  if (wp < 0)
    { builtin_error ("doh: waitpid: %s", strerror (errno)); return -1; }
  if (!WIFEXITED (st) || WEXITSTATUS (st) != 0)
    {
      builtin_error ("doh: HTTPS transport failed (rc=%d signal=%d)",
                     WIFEXITED (st) ? WEXITSTATUS (st) : -1,
                     WIFSIGNALED (st) ? WTERMSIG (st) : 0);
      return -1;
    }
  if (rc < 12)
    { builtin_error ("doh: short or empty reply from resolver"); return -1; }
  return rc;
}

/* Walk the answer section, dispatching per qtype. */
static int
bd_emit_answers (const unsigned char *reply, size_t rlen, uint16_t qtype)
{
  uint16_t qd = bd_rd16 (reply + 4);
  uint16_t an = bd_rd16 (reply + 6);
  size_t off = 12;

  /* Skip question section. */
  for (int i = 0; i < qd; i++)
    {
      if (bd_skip_name (reply, rlen, &off) < 0) return -1;
      off += 4;  /* qtype + qclass */
      if (off > rlen) return -1;
    }

  int emitted = 0;
  for (int i = 0; i < an; i++)
    {
      char name[256];
      if (bd_decode_name (reply, rlen, &off, name, sizeof name, 0) < 0) return -1;
      if (off + 10 > rlen) return -1;
      uint16_t typ = bd_rd16 (reply + off); off += 2;
      /* uint16_t cls = bd_rd16(reply + off); */ off += 2;
      /* uint32_t ttl = bd_rd32(reply + off); */ off += 4;
      uint16_t rdlen = bd_rd16 (reply + off); off += 2;
      if (off + rdlen > rlen) return -1;

      /* Filter by qtype where it makes sense. CNAME results count
         everywhere (resolver may chain). For CNAME-typed queries
         we want CNAME records; for A-typed we want A records and
         maybe also CNAME chains. Show only the queried type. */
      if (qtype != BD_T_CNAME && typ == BD_T_CNAME)
        {
          /* Skip CNAME records that the resolver inserted; the
             actual answer follows. */
          off += rdlen;
          continue;
        }
      if (typ != qtype) { off += rdlen; continue; }

      switch (typ)
        {
        case BD_T_A:
          if (rdlen != 4) return -1;
          printf ("%u.%u.%u.%u\n",
                  reply[off], reply[off+1], reply[off+2], reply[off+3]);
          break;
        case BD_T_AAAA:
          {
            if (rdlen != 16) return -1;
            char ip6[64];
            if (!inet_ntop (AF_INET6, reply + off, ip6, sizeof ip6)) return -1;
            puts (ip6);
            break;
          }
        case BD_T_NS:
        case BD_T_CNAME:
        case BD_T_DNAME:
        case BD_T_PTR:
          {
            char target[256];
            size_t toff = off;
            if (bd_decode_name (reply, rlen, &toff, target, sizeof target, 0) < 0) return -1;
            puts (target);
            break;
          }
        case BD_T_MX:
          {
            if (rdlen < 3) return -1;
            uint16_t prio = bd_rd16 (reply + off);
            char target[256];
            size_t toff = off + 2;
            if (bd_decode_name (reply, rlen, &toff, target, sizeof target, 0) < 0) return -1;
            printf ("%u %s\n", prio, target);
            break;
          }
        case BD_T_TXT:
          {
            /* TXT is a series of length-prefixed strings within rdlen. */
            size_t end = off + rdlen;
            size_t toff = off;
            int first = 1;
            while (toff < end)
              {
                size_t tl = reply[toff++];
                if (toff + tl > end) return -1;
                if (!first) putchar (' ');
                fwrite (reply + toff, 1, tl, stdout);
                toff += tl;
                first = 0;
              }
            putchar ('\n');
            break;
          }
        case BD_T_SOA:
          {
            char mname[256], rname[256];
            size_t toff = off;
            size_t rrend = off + rdlen;
            if (bd_decode_name (reply, rlen, &toff, mname, sizeof mname, 0) < 0) return -1;
            if (bd_decode_name (reply, rlen, &toff, rname, sizeof rname, 0) < 0) return -1;
            if (toff + 20 > rrend) return -1;
            uint32_t serial  = bd_rd32 (reply + toff); toff += 4;
            uint32_t refresh = bd_rd32 (reply + toff); toff += 4;
            uint32_t retry   = bd_rd32 (reply + toff); toff += 4;
            uint32_t expire  = bd_rd32 (reply + toff); toff += 4;
            uint32_t minttl  = bd_rd32 (reply + toff);
            printf ("%s %s %u %u %u %u %u\n",
                    mname, rname, serial, refresh, retry, expire, minttl);
            break;
          }
        case BD_T_DS:
          {
            if (rdlen < 4) return -1;
            uint16_t keytag = bd_rd16 (reply + off);
            unsigned alg = reply[off + 2];
            unsigned digest_type = reply[off + 3];
            printf ("%u %u %u ", keytag, alg, digest_type);
            bd_hex (reply + off + 4, rdlen - 4);
            putchar ('\n');
            break;
          }
        case BD_T_DNSKEY:
          {
            if (rdlen < 4) return -1;
            uint16_t flags = bd_rd16 (reply + off);
            unsigned proto = reply[off + 2];
            unsigned alg = reply[off + 3];
            printf ("%u %u %u ", flags, proto, alg);
            bd_hex (reply + off + 4, rdlen - 4);
            putchar ('\n');
            break;
          }
        case BD_T_RRSIG:
          {
            if (rdlen < 18) return -1;
            uint16_t covered = bd_rd16 (reply + off);
            unsigned alg = reply[off + 2];
            unsigned labels = reply[off + 3];
            uint32_t orig_ttl = bd_rd32 (reply + off + 4);
            uint32_t exp = bd_rd32 (reply + off + 8);
            uint32_t inc = bd_rd32 (reply + off + 12);
            uint16_t keytag = bd_rd16 (reply + off + 16);
            char signer[256];
            size_t toff = off + 18;
            if (bd_decode_name (reply, rlen, &toff, signer, sizeof signer, 0) < 0) return -1;
            if (toff > off + rdlen) return -1;
            printf ("%s %u %u %u %u %u %u %s ", bd_type_name (covered), alg,
                    labels, orig_ttl, exp, inc, keytag, signer);
            bd_hex (reply + toff, (off + rdlen) - toff);
            putchar ('\n');
            break;
          }
        case BD_T_NSEC:
          {
            char target[256];
            size_t toff = off;
            if (bd_decode_name (reply, rlen, &toff, target, sizeof target, 0) < 0) return -1;
            if (toff > off + rdlen) return -1;
            printf ("%s ", target);
            bd_hex (reply + toff, (off + rdlen) - toff);
            putchar ('\n');
            break;
          }
        case BD_T_NSEC3:
          {
            if (rdlen < 5) return -1;
            unsigned alg = reply[off];
            unsigned flags = reply[off + 1];
            uint16_t iter = bd_rd16 (reply + off + 2);
            unsigned salt_len = reply[off + 4];
            size_t toff = off + 5;
            if (toff + salt_len + 1 > off + rdlen) return -1;
            printf ("%u %u %u ", alg, flags, iter);
            bd_hex (reply + toff, salt_len);
            toff += salt_len;
            unsigned hash_len = reply[toff++];
            if (toff + hash_len > off + rdlen) return -1;
            putchar (' ');
            bd_hex (reply + toff, hash_len);
            toff += hash_len;
            putchar (' ');
            bd_hex (reply + toff, (off + rdlen) - toff);
            putchar ('\n');
            break;
          }
        case BD_T_SVCB:
        case BD_T_HTTPS:
          {
            /* RFC 9460 §2.2: SvcPriority(2) || TargetName || SvcParams.
             * Each SvcParamKey: key(2) || valueLen(2) || value(valueLen).
             * Keys MUST appear in strict ascending order; on disorder we
             * still parse defensively and emit raw hex for unknown keys.
             */
            size_t rrend = off + rdlen;
            if (off + 2 > rrend) return -1;
            uint16_t prio = bd_rd16 (reply + off);
            char target[256];
            size_t toff = off + 2;
            if (bd_decode_name (reply, rlen, &toff, target, sizeof target, 0) < 0) return -1;
            if (toff > rrend) return -1;
            /* AliasMode form is priority=0 with target only; ServiceMode
             * is priority>0 with optional SvcParams. */
            printf ("%u %s", prio, target[0] ? target : ".");
            while (toff + 4 <= rrend)
              {
                uint16_t key = bd_rd16 (reply + toff);
                uint16_t vlen = bd_rd16 (reply + toff + 2);
                toff += 4;
                if (toff + vlen > rrend) return -1;
                const unsigned char *v = reply + toff;
                switch (key)
                  {
                  case BD_SVCB_ALPN:
                    {
                      /* alpn value is a sequence of length-prefixed
                       * strings (alpn-id list, RFC 9460 §7.1). */
                      printf (" alpn=");
                      size_t ao = 0;
                      int first = 1;
                      while (ao < vlen)
                        {
                          unsigned char al = v[ao++];
                          if (ao + al > vlen) return -1;
                          if (!first) putchar (',');
                          first = 0;
                          fwrite (v + ao, 1, al, stdout);
                          ao += al;
                        }
                      break;
                    }
                  case BD_SVCB_NO_DEFAULT_ALPN:
                    /* Zero-length value flag. */
                    printf (" no-default-alpn");
                    break;
                  case BD_SVCB_PORT:
                    if (vlen != 2) return -1;
                    printf (" port=%u", bd_rd16 (v));
                    break;
                  case BD_SVCB_IPV4HINT:
                    {
                      if (vlen == 0 || (vlen % 4) != 0) return -1;
                      printf (" ipv4hint=");
                      for (size_t k = 0; k + 4 <= vlen; k += 4)
                        {
                          if (k) putchar (',');
                          printf ("%u.%u.%u.%u",
                                  v[k], v[k+1], v[k+2], v[k+3]);
                        }
                      break;
                    }
                  case BD_SVCB_IPV6HINT:
                    {
                      if (vlen == 0 || (vlen % 16) != 0) return -1;
                      printf (" ipv6hint=");
                      for (size_t k = 0; k + 16 <= vlen; k += 16)
                        {
                          char ip6[64];
                          if (!inet_ntop (AF_INET6, v + k, ip6, sizeof ip6)) return -1;
                          if (k) putchar (',');
                          fputs (ip6, stdout);
                        }
                      break;
                    }
                  case BD_SVCB_ECH:
                    printf (" ech=");
                    bd_hex (v, vlen);
                    break;
                  case BD_SVCB_MANDATORY:
                    {
                      if ((vlen % 2) != 0) return -1;
                      printf (" mandatory=");
                      for (size_t k = 0; k + 2 <= vlen; k += 2)
                        {
                          if (k) putchar (',');
                          printf ("%u", bd_rd16 (v + k));
                        }
                      break;
                    }
                  case BD_SVCB_DOHPATH:
                    {
                      /* RFC 9461: UTF-8 URI template. Print verbatim;
                       * embedded ws is unlikely but we still avoid
                       * unfiltered control bytes. */
                      printf (" dohpath=");
                      for (uint16_t k = 0; k < vlen; k++)
                        {
                          unsigned char c = v[k];
                          if (c < 0x20 || c == 0x7f) putchar ('?');
                          else putchar (c);
                        }
                      break;
                    }
                  default:
                    /* Unknown SvcParamKey — emit key=hex(value) form. */
                    printf (" key%u=", (unsigned) key);
                    bd_hex (v, vlen);
                    break;
                  }
                toff += vlen;
              }
            putchar ('\n');
            break;
          }
        default:
          /* Unknown type — emit hex dump as a fallback. */
          for (uint16_t k = 0; k < rdlen; k++)
            printf ("%02x", reply[off + k]);
          putchar ('\n');
          break;
        }
      off += rdlen;
      emitted++;
    }
  return emitted;
}

/* Construct the in-addr.arpa name for a PTR query. Caller buffer
   >= 96. Returns 0 on success, -1 on error. */
static int
bd_to_ptr_name (const char *ip, char *out, size_t out_sz)
{
  unsigned a, b, c, d;
  if (sscanf (ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 ||
      a > 255 || b > 255 || c > 255 || d > 255) return -1;
  if ((size_t) snprintf (out, out_sz, "%u.%u.%u.%u.in-addr.arpa", d, c, b, a) >= out_sz)
    return -1;
  return 0;
}

/* ===================================================================
 * Stage 39 v2 — iterative RRSIG chain validator (--validate)
 *
 * Design notes
 * ------------
 * The validator operates on captured DNS reply payloads (either fetched
 * over the wire by `bd_query` or read from BASHDNS_FIXTURE_DIR for
 * hermetic tests). It collects RRsets from the answer + authority
 * sections, finds the RRSIG that covers the queried RRset, looks up the
 * signing key in the active trust set, builds the canonical message
 * bytes per RFC 4034 §6.2, and dispatches to the appropriate
 * `crypto` verb via popen() + fork. Fork-and-pipe was chosen over
 * an in-process dispatch because (a) it keeps dns.c free of the
 * mbedtls/PEM/DER baggage that crypto.c carries, (b) the verbs
 * already accept stdin-driven message input which is exactly what
 * popen() gives us, and (c) crash isolation: a malformed signature
 * blob crashes the child, not the shell.
 *
 * Algorithm support — v2
 *   5  RSA/SHA-1     -> crypto rsa-verify -a sha1
 *   7  RSASHA1-NSEC3 -> crypto rsa-verify -a sha1
 *   8  RSA/SHA-256   -> crypto rsa-verify -a sha256
 *   10 RSA/SHA-512   -> crypto rsa-verify -a sha512
 *   13 ECDSA P-256   -> crypto ecdsa-p256-verify
 *   14 ECDSA P-384   -> crypto ecdsa-p384-verify
 *   15 Ed25519       -> crypto ed25519-verify
 *   16 Ed448         -> crypto ed448-verify
 *
 * Implemented v2 proof surfaces and fail-closed deferrals
 *   - Authenticated denial of existence: NSEC/NSEC3 NXDOMAIN and NODATA
 *     proofs are implemented for the fixture-backed Stage 39.D surface.
 *   - Wildcard expansion proofs are accepted for signed NSEC/NSEC3
 *     fixture-backed proofs (Stage 39.D.C).
 *   - DNSSEC-validated DNAME proof accepts a validated DNAME RRset as
 *     proof for the unsigned synthesized CNAME rewrite it implies.
 * ===================================================================
 */

/* ---- fixture I/O hook --------------------------------------------- */

/* If BASHDNS_FIXTURE_DIR is set, look for a file
 * "<fixture-dir>/<owner>.<TYPE>.bin" containing a raw DNS reply payload
 * and return its bytes. Names are lowercased and the trailing dot is
 * stripped (root "." becomes the literal "root"). Returns reply length
 * on success, -1 if no fixture exists or read fails. */
static int
bd_fixture_load (const char *qname, uint16_t qtype,
                 unsigned char *reply, size_t reply_sz)
{
  const char *dir = getenv ("BASHDNS_FIXTURE_DIR");
  if (!dir || !*dir) return -1;
  char canon[256];
  if (bd_canon_owner (qname, canon, sizeof canon) < 0) return -1;
  if (canon[0] == '\0') strcpy (canon, "root");
  if (canon[0] == '.' && canon[1] == '\0') strcpy (canon, "root");
  char path[1024];
  if ((size_t) snprintf (path, sizeof path, "%s/%s.%s.bin",
                         dir, canon, bd_type_name (qtype)) >= sizeof path)
    return -1;
  FILE *f = fopen (path, "rb");
  if (!f) return -1;
  size_t n = fread (reply, 1, reply_sz, f);
  fclose (f);
  return (int) n;
}

/* Wire fetch with fixture override. Returns reply length or -1. */
static int
bd_fetch (const char *qname, uint16_t qtype, const char *server,
          int dnssec, int timeout_ms,
          unsigned char *reply, size_t reply_sz)
{
  const char *fixture_dir = getenv ("BASHDNS_FIXTURE_DIR");
  int n = bd_fixture_load (qname, qtype, reply, reply_sz);
  if (n >= 12) return n;
  if (fixture_dir && *fixture_dir)
    return -1;
  /* Real upstream contact: gate per-upstream so we don't BFR a
   * resolver under tight-loop callers (Stage 39 hardening). The
   * fixture path above bypasses the limiter — hermetic tests stay
   * fast — but the rate-limit env hook still tests cleanly when an
   * unreachable -s SERVER is used as the upstream key. */
  if (bd_dot_ctx.active)
    {
      bd_ratelimit_acquire (bd_dot_ctx.host);
      unsigned char query[768];
      char mixed_qname[256];
      const char *verify_qname = NULL;
      const char *wire_qname = bd_prepare_wire_qname (qname, mixed_qname,
                                                      sizeof mixed_qname,
                                                      &verify_qname);
      if (!wire_qname) { builtin_error ("dot: name too long"); return -1; }
      uint16_t id = bd_random_u16 ();
      int qlen = bd_build_query (id, wire_qname, qtype, dnssec, query, sizeof query);
      if (qlen < 0) { builtin_error ("dot: name too long"); return -1; }
      int dn = bd_query_dot (query, (size_t) qlen, bd_dot_ctx.host,
                             bd_dot_ctx.port, bd_dot_ctx.ca_path[0]
                               ? bd_dot_ctx.ca_path : NULL,
                             timeout_ms, reply, reply_sz);
      if (dn < 0) return -1;
      if (bd_validate_reply (reply, (size_t) dn, id) < 0) return -1;
      if (bd_0x20_verify (reply, (size_t) dn, verify_qname) < 0) return -1;
      return dn;
    }
  if (bd_doh_ctx.active)
    {
      bd_ratelimit_acquire (bd_doh_ctx.url);
      unsigned char query[768];
      char mixed_qname[256];
      const char *verify_qname = NULL;
      const char *wire_qname = bd_prepare_wire_qname (qname, mixed_qname,
                                                      sizeof mixed_qname,
                                                      &verify_qname);
      if (!wire_qname) { builtin_error ("doh: name too long"); return -1; }
      uint16_t id = bd_random_u16 ();
      int qlen = bd_build_query (id, wire_qname, qtype, dnssec, query, sizeof query);
      if (qlen < 0) { builtin_error ("doh: name too long"); return -1; }
      int hn = bd_query_doh (query, (size_t) qlen, bd_doh_ctx.url,
                             timeout_ms, reply, reply_sz);
      if (hn < 0) return -1;
      if (bd_validate_reply (reply, (size_t) hn, id) < 0) return -1;
      if (bd_0x20_verify (reply, (size_t) hn, verify_qname) < 0) return -1;
      return hn;
    }
  bd_ratelimit_acquire (server);
  return bd_query (qname, qtype, server, dnssec, timeout_ms, reply, reply_sz);
}

static int
bd_fetch_attempts (const char *qname, uint16_t qtype, const char *server,
                   int dnssec, int timeout_ms, int attempts,
                   unsigned char *reply, size_t reply_sz)
{
  if (attempts < 1) attempts = 1;
  int rlen = -1;
  for (int a = 0; a < attempts; a++)
    {
      rlen = bd_fetch (qname, qtype, server, dnssec, timeout_ms,
                       reply, reply_sz);
      if (rlen >= 0)
        break;
    }
  return rlen;
}

/* ---- Section walker that collects matching RRs ------------------- */

/* A single RR captured from the wire, owner already canonicalised. */
typedef struct {
  char         owner[256];
  uint16_t     type;
  uint16_t     cls;
  uint32_t     ttl;
  size_t       rdata_off;   /* offset into the source packet */
  uint16_t     rdlen;
  unsigned char rdata[2048]; /* canonical-form RDATA copy (decompressed names) */
  uint16_t     rdata_len;
} bd_rr_t;

#define BD_RR_MAX 64

/* Walk a packet section starting at *off (caller positioned past
 * question section), pulling `count` RRs. Stores all RRs whose
 * (owner_canonical, type) matches selectors when match_owner != NULL
 * (NULL = collect everything). RRSIG RRs always pass through.
 *
 * For names embedded in RDATA (NS, CNAME, DNAME, MX target, RRSIG signer,
 * SOA mname/rname) we decompress into rdata[] in canonical wire form
 * (lowercased label letters, terminating root); the original on-wire
 * compressed bytes are *not* preserved. For RRSIG rdata, the signer
 * name is decompressed in place starting at offset 18.
 *
 * Returns the count of stored RRs, or -1 on parse error. */
static int
bd_collect_rrs (const unsigned char *pkt, size_t pkt_len,
                size_t *off, int count,
                const char *match_owner, uint16_t match_type,
                bd_rr_t *out, int out_max)
{
  int kept = 0;
  for (int i = 0; i < count; i++)
    {
      char name[256];
      if (bd_decode_name (pkt, pkt_len, off, name, sizeof name, 0) < 0) return -1;
      if (*off + 10 > pkt_len) return -1;
      uint16_t typ  = bd_rd16 (pkt + *off); *off += 2;
      uint16_t cls  = bd_rd16 (pkt + *off); *off += 2;
      uint32_t ttl  = bd_rd32 (pkt + *off); *off += 4;
      uint16_t rdlen = bd_rd16 (pkt + *off); *off += 2;
      if (*off + rdlen > pkt_len) return -1;

      char canon[256];
      if (bd_canon_owner (name, canon, sizeof canon) < 0) return -1;

      int want = 0;
      if (typ == BD_T_RRSIG) want = 1;
      else if (!match_owner) want = 1;
      else if (typ == match_type && strcmp (canon, match_owner) == 0) want = 1;

      if (want && kept < out_max)
        {
          bd_rr_t *r = &out[kept];
          memset (r, 0, sizeof *r);
          strncpy (r->owner, canon, sizeof r->owner - 1);
          r->type = typ; r->cls = cls; r->ttl = ttl;
          r->rdata_off = *off;
          r->rdlen = rdlen;
          /* Canonicalise embedded names per RFC 4034 §6.2. We handle
           * the types that contain domain names in RDATA: NS, CNAME, DNAME,
           * PTR, SOA, MX, SVCB/HTTPS TargetName, and RRSIG signer name.
           * For everything else we copy RDATA verbatim. RFC 6840 §5.1
           * leaves NSEC/SRV/etc. pre-7.0 ambiguity; we treat them as
           * opaque, matching most common signers. */
          size_t roff = *off;
          size_t rend = *off + rdlen;
          unsigned char *o = r->rdata;
          size_t olen = 0;
          switch (typ)
            {
            case BD_T_NS:
            case BD_T_CNAME:
            case BD_T_DNAME:
            case BD_T_PTR:
              {
                char tgt[256];
                if (bd_decode_name (pkt, pkt_len, &roff, tgt, sizeof tgt, 0) < 0) return -1;
                int wn = bd_name_to_wire (tgt, o, sizeof r->rdata);
                if (wn < 0) return -1;
                olen = (size_t) wn;
                break;
              }
            case BD_T_MX:
              {
                if (rdlen < 3) return -1;
                if (olen + 2 > sizeof r->rdata) return -1;
                memcpy (o, pkt + roff, 2);
                olen += 2;
                size_t toff = roff + 2;
                char tgt[256];
                if (bd_decode_name (pkt, pkt_len, &toff, tgt, sizeof tgt, 0) < 0) return -1;
                int wn = bd_name_to_wire (tgt, o + olen, sizeof r->rdata - olen);
                if (wn < 0) return -1;
                olen += (size_t) wn;
                break;
              }
            case BD_T_SOA:
              {
                size_t toff = roff;
                char m[256], rn[256];
                if (bd_decode_name (pkt, pkt_len, &toff, m, sizeof m, 0) < 0) return -1;
                if (bd_decode_name (pkt, pkt_len, &toff, rn, sizeof rn, 0) < 0) return -1;
                int w1 = bd_name_to_wire (m, o, sizeof r->rdata);
                if (w1 < 0) return -1;
                olen += (size_t) w1;
                int w2 = bd_name_to_wire (rn, o + olen, sizeof r->rdata - olen);
                if (w2 < 0) return -1;
                olen += (size_t) w2;
                if (toff + 20 > rend) return -1;
                if (olen + 20 > sizeof r->rdata) return -1;
                memcpy (o + olen, pkt + toff, 20);
                olen += 20;
                break;
              }
            case BD_T_SVCB:
            case BD_T_HTTPS:
              {
                if (rdlen < 3) return -1;  /* priority(2) + root target */
                if (olen + 2 > sizeof r->rdata) return -1;
                memcpy (o, pkt + roff, 2);
                olen += 2;
                size_t toff = roff + 2;
                char tgt[256];
                if (bd_decode_name (pkt, pkt_len, &toff, tgt, sizeof tgt, 0) < 0) return -1;
                int wn = bd_name_to_wire (tgt, o + olen, sizeof r->rdata - olen);
                if (wn < 0) return -1;
                olen += (size_t) wn;
                if (toff > rend) return -1;
                if (olen + (rend - toff) > sizeof r->rdata) return -1;
                memcpy (o + olen, pkt + toff, rend - toff);
                olen += rend - toff;
                break;
              }
            case BD_T_RRSIG:
              {
                if (rdlen < 18) return -1;
                /* Header (18 bytes) verbatim. */
                memcpy (o, pkt + roff, 18);
                olen = 18;
                size_t toff = roff + 18;
                char signer[256];
                if (bd_decode_name (pkt, pkt_len, &toff, signer, sizeof signer, 0) < 0) return -1;
                int wn = bd_name_to_wire (signer, o + olen, sizeof r->rdata - olen);
                if (wn < 0) return -1;
                olen += (size_t) wn;
                /* Signature bytes — verbatim from after the on-wire
                 * signer name to end of RDATA. */
                if (toff > rend) return -1;
                size_t sig_len = rend - toff;
                if (olen + sig_len > sizeof r->rdata) return -1;
                memcpy (o + olen, pkt + toff, sig_len);
                olen += sig_len;
                break;
              }
            default:
              if (rdlen > sizeof r->rdata) return -1;
              memcpy (o, pkt + roff, rdlen);
              olen = rdlen;
              break;
            }
          r->rdata_len = (uint16_t) olen;
          kept++;
        }
      *off += rdlen;
    }
  return kept;
}

/* Position *off past header + question section. Returns 0/-1. */
static int
bd_skip_question (const unsigned char *pkt, size_t pkt_len, size_t *off)
{
  if (pkt_len < 12) return -1;
  uint16_t qd = bd_rd16 (pkt + 4);
  *off = 12;
  for (int i = 0; i < qd; i++)
    {
      if (bd_skip_name (pkt, pkt_len, off) < 0) return -1;
      *off += 4;
      if (*off > pkt_len) return -1;
    }
  return 0;
}

/* Collect RRs of (owner, type) from answer + authority sections. */
static int
bd_collect_rrset (const unsigned char *pkt, size_t pkt_len,
                  const char *owner, uint16_t type,
                  bd_rr_t *out, int out_max)
{
  if (pkt_len < 12) return -1;
  uint16_t an = bd_rd16 (pkt + 6);
  uint16_t ns = bd_rd16 (pkt + 8);
  size_t off = 12;
  if (bd_skip_question (pkt, pkt_len, &off) < 0) return -1;
  char canon[256];
  if (bd_canon_owner (owner, canon, sizeof canon) < 0) return -1;
  int n = bd_collect_rrs (pkt, pkt_len, &off, an, canon, type, out, out_max);
  if (n < 0) return -1;
  int n2 = bd_collect_rrs (pkt, pkt_len, &off, ns, canon, type, out + n, out_max - n);
  if (n2 < 0) return -1;
  return n + n2;
}

/* ---- canonical-RRset bytes for RRSIG message ---------------------- */

/* Bytewise compare two RRs by canonical RDATA (RFC 4034 §6.3). */
static int
bd_rr_cmp (const void *pa, const void *pb)
{
  const bd_rr_t *a = (const bd_rr_t *) pa;
  const bd_rr_t *b = (const bd_rr_t *) pb;
  size_t la = a->rdata_len, lb = b->rdata_len;
  size_t mn = la < lb ? la : lb;
  int c = memcmp (a->rdata, b->rdata, mn);
  if (c) return c;
  if (la < lb) return -1;
  if (la > lb) return 1;
  return 0;
}


static int
bd_label_count (const char *name)
{
  char canon[256];
  if (bd_canon_owner (name, canon, sizeof canon) < 0) return -1;
  if (canon[0] == '\0' || (canon[0] == '.' && canon[1] == '\0')) return 0;
  int n = 1;
  for (const char *p = canon; *p; p++)
    if (*p == '.') n++;
  return n;
}

static int
bd_suffix_labels (const char *name, unsigned labels, char *out, size_t out_sz)
{
  char canon[256];
  if (bd_canon_owner (name, canon, sizeof canon) < 0 || out_sz == 0) return -1;
  if (labels == 0)
    {
      if (out_sz < 2) return -1;
      strcpy (out, ".");
      return 0;
    }
  int total = bd_label_count (canon);
  if (total < 0 || labels > (unsigned) total) return -1;
  const char *start = canon;
  int skip = total - (int) labels;
  while (skip-- > 0)
    {
      const char *dot = strchr (start, '.');
      if (!dot) return -1;
      start = dot + 1;
    }
  if (strlen (start) + 1 > out_sz) return -1;
  strcpy (out, start);
  return 0;
}

static int
bd_wildcard_owner_from_labels (const char *owner, unsigned labels,
                               char *out, size_t out_sz)
{
  char suffix[256];
  if (bd_suffix_labels (owner, labels, suffix, sizeof suffix) < 0) return -1;
  if (suffix[0] == '.' && suffix[1] == '\0')
    return snprintf (out, out_sz, "*.") > 0 && strlen ("*.") < out_sz ? 0 : -1;
  int n = snprintf (out, out_sz, "*.%s", suffix);
  return n > 0 && (size_t) n < out_sz ? 0 : -1;
}

/* Build the canonical message bytes that RRSIG signs:
 *   RRSIG_RDATA_without_signature ||
 *   for each RR in sorted RRset:
 *     OWNER_WIRE || TYPE(2) || CLASS(2) || ORIG_TTL(4) ||
 *     RDLENGTH(2) || canonical_RDATA
 * The original-TTL field comes from the RRSIG, not the per-RR TTL. */
static int
bd_build_signed_msg (const bd_rr_t *rrsig,
                     bd_rr_t *rrset, int rrset_n,
                     unsigned char *out, size_t out_sz, size_t *out_len)
{
  if (rrsig->rdata_len < 18) return -1;
  /* Locate end of signer name in canonicalised RRSIG rdata. We
   * encoded it ourselves, so we can re-find the terminator. */
  size_t pos = 18;
  while (pos < rrsig->rdata_len)
    {
      uint8_t lab = rrsig->rdata[pos];
      if (lab == 0) { pos++; break; }
      if ((lab & 0xc0) != 0) return -1;  /* no compression in our canonical copy */
      pos += 1 + lab;
      if (pos > rrsig->rdata_len) return -1;
    }
  /* signer-name end = pos; signature bytes follow. */
  size_t header_len = pos;  /* RRSIG fields + signer name; sig stripped */
  if (header_len > out_sz) return -1;
  memcpy (out, rrsig->rdata, header_len);
  size_t off = header_len;

  /* Sort the RRset by canonical RDATA. */
  qsort (rrset, (size_t) rrset_n, sizeof rrset[0], bd_rr_cmp);

  uint32_t orig_ttl = bd_rd32 (rrsig->rdata + 4);
  for (int i = 0; i < rrset_n; i++)
    {
      bd_rr_t *r = &rrset[i];
      unsigned char wire[256];
      char owner_for_sig[256];
      const char *owner_name = r->owner;
      unsigned sig_labels = rrsig->rdata[3];
      int owner_labels = bd_label_count (r->owner);
      if (owner_labels < 0) return -1;
      if (owner_labels > (int) sig_labels)
        {
          if (bd_wildcard_owner_from_labels (r->owner, sig_labels,
                                             owner_for_sig, sizeof owner_for_sig) < 0)
            return -1;
          owner_name = owner_for_sig;
        }
      int wn = bd_name_to_wire (owner_name, wire, sizeof wire);
      if (wn < 0) return -1;
      if (off + (size_t) wn + 10 + r->rdata_len > out_sz) return -1;
      memcpy (out + off, wire, (size_t) wn); off += (size_t) wn;
      out[off++] = (uint8_t) (r->type >> 8);
      out[off++] = (uint8_t) (r->type & 0xff);
      out[off++] = (uint8_t) (r->cls >> 8);
      out[off++] = (uint8_t) (r->cls & 0xff);
      out[off++] = (uint8_t) (orig_ttl >> 24);
      out[off++] = (uint8_t) (orig_ttl >> 16);
      out[off++] = (uint8_t) (orig_ttl >> 8);
      out[off++] = (uint8_t) (orig_ttl & 0xff);
      out[off++] = (uint8_t) (r->rdata_len >> 8);
      out[off++] = (uint8_t) (r->rdata_len & 0xff);
      memcpy (out + off, r->rdata, r->rdata_len);
      off += r->rdata_len;
    }
  *out_len = off;
  return 0;
}

/* Locate the RRSIG that covers (owner, type) in the captured set.
 * Returns the RRSIG bd_rr_t* or NULL. */
static const bd_rr_t *
bd_find_rrsig (const bd_rr_t *rrs, int n, const char *owner, uint16_t type)
{
  char canon[256];
  if (bd_canon_owner (owner, canon, sizeof canon) < 0) return NULL;
  for (int i = 0; i < n; i++)
    {
      if (rrs[i].type != BD_T_RRSIG) continue;
      if (strcmp (rrs[i].owner, canon) != 0) continue;
      if (rrs[i].rdata_len < 18) continue;
      uint16_t covered = bd_rd16 (rrs[i].rdata);
      if (covered == type) return &rrs[i];
    }
  return NULL;
}

/* ---- crypto fork-and-pipe verifier --------------------------- */

/* Convert bytes to lowercase hex. out_sz must be >= 2*n+1. */
static void
bd_to_hex (const unsigned char *in, size_t n, char *out)
{
  static const char *h = "0123456789abcdef";
  for (size_t i = 0; i < n; i++)
    {
      out[2*i]   = h[(in[i] >> 4) & 0xf];
      out[2*i+1] = h[in[i] & 0xf];
    }
  out[2*n] = '\0';
}

/* Decompose an RFC 3110 RSA DNSKEY public-key field into modulus +
 * exponent. Layout: e_len(1 or 3 bytes) || exponent || modulus. */
static int
bd_rsa_split (const unsigned char *pubkey, size_t pklen,
              const unsigned char **mod, size_t *mod_len,
              const unsigned char **exp, size_t *exp_len)
{
  if (pklen < 1) return -1;
  size_t off, elen;
  if (pubkey[0] == 0)
    {
      if (pklen < 3) return -1;
      elen = ((size_t) pubkey[1] << 8) | pubkey[2];
      off = 3;
    }
  else
    {
      elen = pubkey[0];
      off = 1;
    }
  if (off + elen >= pklen) return -1;
  *exp = pubkey + off;
  *exp_len = elen;
  *mod = pubkey + off + elen;
  *mod_len = pklen - off - elen;
  return 0;
}

/* Run `builtin <argv...>` with msg piped on stdin. The bash-os build
 * bakes crypto into the bash binary as a builtin, so reaching it
 * needs a bash shell. The inline `-c` script body is the constant
 * literal `builtin "$@"`; argv elements arrive as POSITIONAL parameters
 * via "$@" so bash never re-parses caller-supplied hex strings as
 * shell. The argv arities produced by bd_verify_sig are 6 (ECDSA /
 * EdDSA: verifier verb -k pk -s sig) or 10 (RSA: verifier rsa-verify
 * -n mod -e exp -s sig -a hash); we dispatch via two arity-specific
 * execlps so the per-line audit annotation stays narrow.
 *
 * Override hook: BASHDNS_VERIFIER_CMD, if set, replaces the entire
 * crypto invocation. Tests use this to inject a fake verifier
 * that always succeeds or fails. Operator-controlled env var; not
 * part of the production execution path. The override script body
 * is executed as `bash -c $override _ <verb> <args...>` — the verifier
 * verb and its hex args are forwarded as positional parameters ("$@")
 * so a real out-of-binary verifier can dispatch on them; fixed-body
 * always-pass/always-fail stubs simply ignore "$@" and behave as before.
 *
 * Returns 0 if child exits 0, -1 otherwise. */
static int
bd_run_verifier (char *const argv[], const unsigned char *msg, size_t msg_len)
{
  const char *override = getenv ("BASHDNS_VERIFIER_CMD");
  int argc = 0;
  if (!override || !*override)
    {
      while (argv[argc]) argc++;
      if (argc != 6 && argc != 10) return -1;
    }

  int p[2];
  if (pipe (p) < 0) { builtin_warning ("validate: pipe: %s", strerror (errno)); return -1; }
  struct bd_child_guard guard;
  if (bd_child_guard_begin (&guard) < 0)
    { close (p[0]); close (p[1]); return -1; }
  pid_t pid = fork ();
  if (pid < 0)
    { builtin_warning ("validate: fork: %s", strerror (errno));
      bd_child_guard_parent_end (&guard);
      close (p[0]); close (p[1]); return -1; }
  if (pid == 0)
    {
      bd_child_guard_child_end (&guard);
      close (p[1]);
      if (dup2 (p[0], 0) < 0) _exit (127);
      close (p[0]);
      int dn = open ("/dev/null", O_WRONLY);
      if (dn >= 0) { dup2 (dn, 1); dup2 (dn, 2); close (dn); }
      if (override && *override)
        {
          /* Forward the verifier verb + its hex args as positional
           * parameters ("$@") so a real out-of-binary verifier (e.g. the
           * signzone self-check harness) can dispatch on them. Fixed-body
           * stubs that ignore "$@" (always-pass/always-fail) keep working
           * unchanged. The script body still never sees caller hex inline. */
          char *ov[16]; int oi = 0;
          ov[oi++] = (char *) "bash"; ov[oi++] = (char *) "-c";
          ov[oi++] = (char *) override; ov[oi++] = (char *) "_";
          for (int i = 0; argv[i] && oi < 15; i++) ov[oi++] = argv[i];
          ov[oi] = NULL;
          execvp ("bash", ov);
        }
      else if (argc == 10)
        execlp ("bash", "bash", "-c", "builtin \"$@\"", "_", argv[0], argv[1], argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8], argv[9], (char *) NULL);
      else /* argc == 6 (validated above) */
        execlp ("bash", "bash", "-c", "builtin \"$@\"", "_", argv[0], argv[1], argv[2], argv[3], argv[4], argv[5], (char *) NULL);
      _exit (127);
    }
  close (p[0]);
  if (bd_write_all (p[1], msg, msg_len) < 0)
    { builtin_warning ("validate: write to verifier: %s", strerror (errno));
      close (p[1]);
      int st; while (waitpid (pid, &st, 0) < 0 && errno == EINTR) ;
      bd_child_guard_parent_end (&guard);
      return -1; }
  close (p[1]);
  int st = 0;
  int wrc;
  while ((wrc = waitpid (pid, &st, 0)) < 0 && errno == EINTR) ;
  bd_child_guard_parent_end (&guard);
  if (wrc < 0) return -1;
  if (!WIFEXITED (st)) return -1;
  return WEXITSTATUS (st) == 0 ? 0 : -1;
}

/* Verify SIG bytes over MSG bytes using DNSKEY rdata + algo via the
 * crypto verb. Returns 0 on success, -1 on failure (verifier
 * disagrees / bad params / unsupported algo). */
static int
bd_verify_sig (uint8_t algo,
               const unsigned char *dnskey_rdata, size_t dnskey_rdlen,
               const unsigned char *sig, size_t sig_len,
               const unsigned char *msg, size_t msg_len)
{
  /* DNSKEY rdata = flags(2) || proto(1) || algo(1) || pubkey */
  if (dnskey_rdlen < 4) return -1;
  const unsigned char *pk = dnskey_rdata + 4;
  size_t pklen = dnskey_rdlen - 4;
  const char *verifier = getenv ("BASHDNS_VERIFIER");
  if (!verifier || !*verifier) verifier = "crypto";

  switch (algo)
    {
    case BD_ALG_RSASHA1:
    case BD_ALG_RSASHA1_NSEC3:
    case BD_ALG_RSASHA256:
    case BD_ALG_RSASHA512:
      {
        const unsigned char *mod = NULL, *exp = NULL;
        size_t mod_len = 0, exp_len = 0;
        if (bd_rsa_split (pk, pklen, &mod, &mod_len, &exp, &exp_len) < 0) return -1;
        char *mod_hex = malloc (2 * mod_len + 1);
        char *exp_hex = malloc (2 * exp_len + 1);
        char *sig_hex = malloc (2 * sig_len + 1);
        if (!mod_hex || !exp_hex || !sig_hex)
          { free (mod_hex); free (exp_hex); free (sig_hex); return -1; }
        bd_to_hex (mod, mod_len, mod_hex);
        bd_to_hex (exp, exp_len, exp_hex);
        bd_to_hex (sig, sig_len, sig_hex);
        const char *hash = (algo == BD_ALG_RSASHA1 || algo == BD_ALG_RSASHA1_NSEC3) ? "sha1"
                         : (algo == BD_ALG_RSASHA256) ? "sha256"
                         : "sha512";
        char *argv[] = {
          (char *) verifier, (char *) "rsa-verify",
          (char *) "-n", mod_hex,
          (char *) "-e", exp_hex,
          (char *) "-s", sig_hex,
          (char *) "-a", (char *) hash,
          NULL
        };
        int rc = bd_run_verifier (argv, msg, msg_len);
        free (mod_hex); free (exp_hex); free (sig_hex);
        return rc;
      }
    case BD_ALG_ECDSAP256SHA256:
      {
        if (pklen != 64 || sig_len != 64) return -1;
        unsigned char pk65[65]; pk65[0] = 0x04; memcpy (pk65 + 1, pk, 64);
        char pk_hex[131], sig_hex[129];
        bd_to_hex (pk65, 65, pk_hex);
        bd_to_hex (sig, 64, sig_hex);
        char *argv[] = {
          (char *) verifier, (char *) "ecdsa-p256-verify",
          (char *) "-k", pk_hex,
          (char *) "-s", sig_hex,
          NULL
        };
        return bd_run_verifier (argv, msg, msg_len);
      }
    case BD_ALG_ECDSAP384SHA384:
      {
        if (pklen != 96 || sig_len != 96) return -1;
        char pk_hex[193], sig_hex[193];
        bd_to_hex (pk, 96, pk_hex);
        bd_to_hex (sig, 96, sig_hex);
        char *argv[] = {
          (char *) verifier, (char *) "ecdsa-p384-verify",
          (char *) "-k", pk_hex,
          (char *) "-s", sig_hex,
          NULL
        };
        return bd_run_verifier (argv, msg, msg_len);
      }
    case BD_ALG_ED25519:
      {
        if (pklen != 32 || sig_len != 64) return -1;
        char pk_hex[65], sig_hex[129];
        bd_to_hex (pk, 32, pk_hex);
        bd_to_hex (sig, 64, sig_hex);
        char *argv[] = {
          (char *) verifier, (char *) "ed25519-verify",
          (char *) "-k", pk_hex,
          (char *) "-s", sig_hex,
          NULL
        };
        return bd_run_verifier (argv, msg, msg_len);
      }
    case BD_ALG_ED448:
      {
        if (pklen != 57 || sig_len != 114) return -1;
        char pk_hex[115], sig_hex[229];
        bd_to_hex (pk, 57, pk_hex);
        bd_to_hex (sig, 114, sig_hex);
        char *argv[] = {
          (char *) verifier, (char *) "ed448-verify",
          (char *) "-k", pk_hex,
          (char *) "-s", sig_hex,
          NULL
        };
        return bd_run_verifier (argv, msg, msg_len);
      }
    default:
      builtin_warning ("validate: unsupported algorithm %u", (unsigned) algo);
      return -1;
    }
}

/* ---- DS digest check (RFC 4509) ---------------------------------- */

/* Run `crypto sha1 -x` / `crypto sha256 -x` over the DS-input
 * bytes (DNSKEY owner wire + DNSKEY rdata) and compare the resulting
 * digest to the DS rdata digest field. Returns 0 on match, -1
 * otherwise. We dispatch via `bash -c "builtin crypto \"$@\""` so
 * the in-binary builtin is reachable from any bash-os runtime; the
 * dynamic hashverb flows in as a positional parameter so bash never
 * re-parses it as a shell expression.
 *
 * BASHDNS_HASH_CMD (operator/test hook): when set, the env value
 * becomes the `bash -c` script body verbatim and hashverb/-x are
 * delivered to it as $1/$2 via "$@". This preserves shell mediation
 * for tests but keeps hashverb out of the script-body string. */
static int
bd_run_hash_match (const char *hashverb,
                   const unsigned char *msg, size_t msg_len,
                   const unsigned char *want_digest, size_t want_len)
{
  const char *override = getenv ("BASHDNS_HASH_CMD");
  int p[2]; int q[2];
  if (pipe (p) < 0) return -1;
  if (pipe (q) < 0) { close (p[0]); close (p[1]); return -1; }
  struct bd_child_guard guard;
  if (bd_child_guard_begin (&guard) < 0)
    { close (p[0]); close (p[1]); close (q[0]); close (q[1]); return -1; }
  pid_t pid = fork ();
  if (pid < 0) {
    bd_child_guard_parent_end (&guard);
    close (p[0]); close (p[1]); close (q[0]); close (q[1]); return -1;
  }
  if (pid == 0)
    {
      bd_child_guard_child_end (&guard);
      close (p[1]); close (q[0]);
      if (dup2 (p[0], 0) < 0) _exit (127);
      if (dup2 (q[1], 1) < 0) _exit (127);
      close (p[0]); close (q[1]);
      int dn = open ("/dev/null", O_WRONLY);
      if (dn >= 0) { dup2 (dn, 2); close (dn); }
      if (override && *override)
        execlp ("bash", "bash", "-c", override, "_", hashverb, "-x", (char *) NULL);
      else
        execlp ("bash", "bash", "-c", "builtin crypto \"$@\"", "_", hashverb, "-x", (char *) NULL);
      _exit (127);
    }
  close (p[0]); close (q[1]);
  if (bd_write_all (p[1], msg, msg_len) < 0)
    {
      close (p[1]); close (q[0]);
      int st;
      while (waitpid (pid, &st, 0) < 0 && errno == EINTR)
        ;
      bd_child_guard_parent_end (&guard);
      return -1;
    }
  close (p[1]);
  /* Read up to 1024 bytes of hex (sha384 output is 96 chars + nl). */
  char hex[1024]; size_t hexlen = 0;
  ssize_t n;
  while ((n = read (q[0], hex + hexlen, sizeof hex - 1 - hexlen)) > 0)
    { hexlen += (size_t) n; if (hexlen >= sizeof hex - 1) break; }
  close (q[0]);
  hex[hexlen] = '\0';
  int st = 0; int wrc;
  while ((wrc = waitpid (pid, &st, 0)) < 0 && errno == EINTR) ;
  bd_child_guard_parent_end (&guard);
  if (wrc < 0) return -1;
  if (!WIFEXITED (st) || WEXITSTATUS (st) != 0) return -1;
  /* Strip whitespace, decode hex. */
  unsigned char got[64]; size_t got_len = 0;
  if (bd_unhex (hex, got, sizeof got, &got_len) < 0) return -1;
  if (got_len != want_len) return -1;
  return memcmp (got, want_digest, want_len) == 0 ? 0 : -1;
}

/* See bd_run_hash_match comment for the trampoline + positional-arg
 * contract; bd_run_hash_bytes shares the same hardening. */
static int
bd_run_hash_bytes (const char *hashverb,
                   const unsigned char *msg, size_t msg_len,
                   unsigned char *out, size_t out_sz, size_t *out_len)
{
  const char *override = getenv ("BASHDNS_HASH_CMD");

  int p[2]; int q[2];
  if (pipe (p) < 0) return -1;
  if (pipe (q) < 0) { close (p[0]); close (p[1]); return -1; }
  struct bd_child_guard guard;
  if (bd_child_guard_begin (&guard) < 0)
    { close (p[0]); close (p[1]); close (q[0]); close (q[1]); return -1; }
  pid_t pid = fork ();
  if (pid < 0) {
    bd_child_guard_parent_end (&guard);
    close (p[0]); close (p[1]); close (q[0]); close (q[1]); return -1;
  }
  if (pid == 0)
    {
      bd_child_guard_child_end (&guard);
      close (p[1]); close (q[0]);
      if (dup2 (p[0], 0) < 0) _exit (127);
      if (dup2 (q[1], 1) < 0) _exit (127);
      close (p[0]); close (q[1]);
      int dn = open ("/dev/null", O_WRONLY);
      if (dn >= 0) { dup2 (dn, 2); close (dn); }
      if (override && *override)
        execlp ("bash", "bash", "-c", override, "_", hashverb, "-x", (char *) NULL);
      else
        execlp ("bash", "bash", "-c", "builtin crypto \"$@\"", "_", hashverb, "-x", (char *) NULL);
      _exit (127);
    }
  close (p[0]); close (q[1]);
  if (bd_write_all (p[1], msg, msg_len) < 0)
    {
      close (p[1]); close (q[0]);
      int st;
      while (waitpid (pid, &st, 0) < 0 && errno == EINTR)
        ;
      bd_child_guard_parent_end (&guard);
      return -1;
    }
  close (p[1]);

  char hex[1024]; size_t hexlen = 0;
  ssize_t n;
  while ((n = read (q[0], hex + hexlen, sizeof hex - 1 - hexlen)) > 0)
    { hexlen += (size_t) n; if (hexlen >= sizeof hex - 1) break; }
  close (q[0]);
  hex[hexlen] = '\0';
  int st = 0; int wrc;
  while ((wrc = waitpid (pid, &st, 0)) < 0 && errno == EINTR) ;
  bd_child_guard_parent_end (&guard);
  if (wrc < 0) return -1;
  if (!WIFEXITED (st) || WEXITSTATUS (st) != 0) return -1;
  return bd_unhex (hex, out, out_sz, out_len);
}

/* For each DS in the trust set targeting this DNSKEY's owner+keytag,
 * check that hash(owner_wire || dnskey_rdata) matches the DS digest.
 * Returns 0 on first match, -1 if no DS matches (caller decides
 * whether absence is fatal). */
static int
bd_ds_check (const char *dnskey_owner,
             uint16_t key_tag, uint8_t algo,
             const unsigned char *dnskey_rdata, size_t dnskey_rdlen,
             const bd_trust_t *ts, int ts_n)
{
  /* Build the DS-input bytes. */
  unsigned char in[3072];
  size_t in_len = 0;
  int wn = bd_name_to_wire (dnskey_owner, in, sizeof in);
  if (wn < 0) return -1;
  in_len = (size_t) wn;
  if (in_len + dnskey_rdlen > sizeof in) return -1;
  memcpy (in + in_len, dnskey_rdata, dnskey_rdlen);
  in_len += dnskey_rdlen;

  char canon[256];
  if (bd_canon_owner (dnskey_owner, canon, sizeof canon) < 0) return -1;

  for (int i = 0; i < ts_n; i++)
    {
      const bd_trust_t *t = &ts[i];
      if (t->kind != BD_T_DS) continue;
      if (strcmp (t->owner, canon) != 0) continue;
      if (t->key_tag != key_tag) continue;
      if (t->algorithm != algo) continue;
      const char *hv;
      if (t->digest_type == BD_DS_DIGEST_SHA1)        hv = "sha1";
      else if (t->digest_type == BD_DS_DIGEST_SHA256) hv = "sha256";
      else if (t->digest_type == BD_DS_DIGEST_SHA384) hv = "sha384";
      else continue;  /* unknown DS digest type: fail closed */
      if (bd_run_hash_match (hv, in, in_len, t->digest, t->digest_len) == 0)
        return 0;
    }
  return -1;
}

/* ---- chain walker ------------------------------------------------- */

#define BD_CHAIN_MAX_DEPTH 16

/* Print a structured fail-closed message + return EXECUTION_FAILURE. */
static int
bd_validate_fail (const char *fmt, ...)
{
  va_list ap;
  fprintf (stderr, "dns: VALIDATE FAILED: ");
  va_start (ap, fmt);
  vfprintf (stderr, fmt, ap);
  va_end (ap);
  fputc ('\n', stderr);
  return EXECUTION_FAILURE;
}

/* Add DNSKEYs from a packet into a fresh trust set after each one is
 * either covered by the parent DS chain (via prior bd_ds_check) or
 * verified by an in-set KSK signing the DNSKEY RRset. */
static int
bd_install_dnskeys (const bd_rr_t *rrs, int n, const char *zone,
                    bd_trust_t *new_ts, int *new_n, int max)
{
  char canon[256];
  if (bd_canon_owner (zone, canon, sizeof canon) < 0) return -1;
  *new_n = 0;
  for (int i = 0; i < n && *new_n < max; i++)
    {
      if (rrs[i].type != BD_T_DNSKEY) continue;
      if (strcmp (rrs[i].owner, canon) != 0) continue;
      bd_trust_t *t = &new_ts[*new_n];
      memset (t, 0, sizeof *t);
      strncpy (t->owner, canon, sizeof t->owner - 1);
      t->kind = BD_T_DNSKEY;
      if (rrs[i].rdata_len < 4) continue;
      t->flags     = bd_rd16 (rrs[i].rdata);
      t->protocol  = rrs[i].rdata[2];
      t->algorithm = rrs[i].rdata[3];
      if (rrs[i].rdata_len > sizeof t->rdata) continue;
      memcpy (t->rdata, rrs[i].rdata, rrs[i].rdata_len);
      t->rdata_len = rrs[i].rdata_len;
      t->key_tag = bd_dnskey_keytag (t->rdata, t->rdata_len);
      (*new_n)++;
    }
  return 0;
}

/* Locate the trust-set DNSKEY entry matching (owner, key_tag, algo). */
static const bd_trust_t *
bd_find_signing_key (const bd_trust_t *ts, int n,
                     const char *owner, uint16_t key_tag, uint8_t algo)
{
  char canon[256];
  if (bd_canon_owner (owner, canon, sizeof canon) < 0) return NULL;
  for (int i = 0; i < n; i++)
    {
      if (ts[i].kind != BD_T_DNSKEY) continue;
      if (strcmp (ts[i].owner, canon) != 0) continue;
      if (ts[i].key_tag != key_tag) continue;
      if (ts[i].algorithm != algo) continue;
      return &ts[i];
    }
  return NULL;
}

/* Verify an RRset (already collected, sorted later by build) by
 * locating its RRSIG, checking time window, building signed message,
 * dispatching to crypto. Returns 0 on success, -1 on failure
 * (with bd_validate_fail called by caller). */
static int
bd_verify_rrset (bd_rr_t *rrs, int rrs_n,
                 const char *owner, uint16_t type,
                 const bd_trust_t *signing_keys, int signing_n,
                 int skew_sec, char *err, size_t err_sz)
{
  const bd_rr_t *rrsig = bd_find_rrsig (rrs, rrs_n, owner, type);
  if (!rrsig)
    { snprintf (err, err_sz, "no RRSIG covers %s/%s", owner, bd_type_name (type)); return -1; }
  if (rrsig->rdata_len < 18)
    { snprintf (err, err_sz, "RRSIG too short for %s/%s", owner, bd_type_name (type)); return -1; }
  uint8_t  algo    = rrsig->rdata[2];
  uint32_t exp     = bd_rd32 (rrsig->rdata + 8);
  uint32_t inc     = bd_rd32 (rrsig->rdata + 12);
  uint16_t key_tag = bd_rd16 (rrsig->rdata + 16);

  /* Algorithm gate — dns v2 supports 5/7/8/10/13/14/15/16.
   * Everything else is
   * rejected up-front so the test surface gets a clean "unsupported
   * algorithm" line instead of a downstream "no DNSKEY found" line. */
  switch (algo)
    {
    case BD_ALG_RSASHA1:
    case BD_ALG_RSASHA1_NSEC3:
    case BD_ALG_RSASHA256:
    case BD_ALG_RSASHA512:
    case BD_ALG_ECDSAP256SHA256:
    case BD_ALG_ECDSAP384SHA384:
    case BD_ALG_ED25519:
    case BD_ALG_ED448:
      break;
    default:
      snprintf (err, err_sz, "unsupported algorithm %u", (unsigned) algo);
      return -1;
    }

  /* Signer name bytes start at offset 18, signature follows. */
  size_t pos = 18;
  while (pos < rrsig->rdata_len)
    {
      uint8_t lab = rrsig->rdata[pos];
      if (lab == 0) { pos++; break; }
      if ((lab & 0xc0) != 0)
        { snprintf (err, err_sz, "RRSIG signer name compression"); return -1; }
      pos += 1 + lab;
      if (pos > rrsig->rdata_len)
        { snprintf (err, err_sz, "RRSIG signer name overflow"); return -1; }
    }
  /* Decode signer name into ASCII for trust-set lookup. */
  char signer[256]; size_t sn_off = 18;
  if (bd_decode_name (rrsig->rdata, rrsig->rdata_len, &sn_off, signer, sizeof signer, 0) < 0)
    { snprintf (err, err_sz, "RRSIG signer name decode"); return -1; }
  size_t header_len = pos;
  size_t sig_len = rrsig->rdata_len - header_len;
  const unsigned char *sig = rrsig->rdata + header_len;

  /* Time window. */
  time_t now = time (NULL);
  if ((time_t) inc - skew_sec > now)
    { snprintf (err, err_sz, "RRSIG not yet valid (inception %lu > now %lu)",
                (unsigned long) inc, (unsigned long) now); return -1; }
  if ((time_t) exp + skew_sec < now)
    { snprintf (err, err_sz, "RRSIG expired (expiration %lu < now %lu)",
                (unsigned long) exp, (unsigned long) now); return -1; }

  const bd_trust_t *key = bd_find_signing_key (signing_keys, signing_n,
                                               signer, key_tag, algo);
  if (!key)
    { snprintf (err, err_sz, "no DNSKEY for signer=%s tag=%u algo=%u in trust set",
                signer, key_tag, algo); return -1; }

  /* Build the canonical RRset (excluding RRSIG itself). */
  bd_rr_t set[BD_RR_MAX]; int set_n = 0;
  for (int i = 0; i < rrs_n && set_n < BD_RR_MAX; i++)
    if (rrs[i].type == type && strcmp (rrs[i].owner, owner) == 0)
      set[set_n++] = rrs[i];
  if (set_n == 0)
    { snprintf (err, err_sz, "RRset %s/%s empty", owner, bd_type_name (type)); return -1; }

  unsigned char msg[16384]; size_t msg_len = 0;
  if (bd_build_signed_msg (rrsig, set, set_n, msg, sizeof msg, &msg_len) < 0)
    { snprintf (err, err_sz, "build signed-message overflow"); return -1; }

  if (bd_verify_sig (algo, key->rdata, key->rdata_len, sig, sig_len, msg, msg_len) < 0)
    { snprintf (err, err_sz, "RRSIG signature verification failed (algo=%u tag=%u)",
                algo, key_tag); return -1; }
  return 0;
}

static int
bd_collect_answer_authority (const unsigned char *pkt, size_t pkt_len,
                             bd_rr_t *out, int out_max)
{
  if (pkt_len < 12) return -1;
  uint16_t an = bd_rd16 (pkt + 6);
  uint16_t ns = bd_rd16 (pkt + 8);
  size_t off = 12;
  if (bd_skip_question (pkt, pkt_len, &off) < 0) return -1;
  int n = bd_collect_rrs (pkt, pkt_len, &off, an, NULL, 0, out, out_max);
  if (n < 0) return -1;
  int n2 = bd_collect_rrs (pkt, pkt_len, &off, ns, NULL, 0, out + n, out_max - n);
  if (n2 < 0) return -1;
  return n + n2;
}

static int
bd_rr_rdata_name (const bd_rr_t *rr, char *out, size_t out_sz)
{
  char tmp[256];
  size_t off = 0;
  if (bd_decode_name (rr->rdata, rr->rdata_len, &off, tmp, sizeof tmp, 0) < 0)
    return -1;
  if (off != rr->rdata_len)
    return -1;
  return bd_canon_owner (tmp, out, out_sz);
}

static int
bd_dname_expected_cname (const char *qname, const char *dname_owner,
                         const char *dname_target,
                         char *out, size_t out_sz)
{
  char qcanon[256], owner[256], target[256];
  if (bd_canon_owner (qname, qcanon, sizeof qcanon) < 0
      || bd_canon_owner (dname_owner, owner, sizeof owner) < 0
      || bd_canon_owner (dname_target, target, sizeof target) < 0)
    return -1;

  if (strcmp (owner, ".") == 0)
    {
      if (strcmp (qcanon, ".") == 0)
        return -1;
      if (strcmp (target, ".") == 0)
        {
          if (snprintf (out, out_sz, "%s", qcanon) >= (int) out_sz)
            return -1;
        }
      else if (snprintf (out, out_sz, "%s.%s", qcanon, target) >= (int) out_sz)
        return -1;
      return 0;
    }

  size_t qlen = strlen (qcanon);
  size_t olen = strlen (owner);
  if (qlen <= olen)
    return -1;
  if (strcmp (qcanon + qlen - olen, owner) != 0)
    return -1;
  if (qcanon[qlen - olen - 1] != '.')
    return -1;

  size_t prefix_len = qlen - olen - 1;
  if (prefix_len == 0 || prefix_len >= out_sz)
    return -1;
  char prefix[256];
  if (prefix_len >= sizeof prefix)
    return -1;
  memcpy (prefix, qcanon, prefix_len);
  prefix[prefix_len] = '\0';

  if (strcmp (target, ".") == 0)
    {
      if (snprintf (out, out_sz, "%s", prefix) >= (int) out_sz)
        return -1;
    }
  else if (snprintf (out, out_sz, "%s.%s", prefix, target) >= (int) out_sz)
    return -1;
  return 0;
}

/* Returns 0 when a DNAME proof validated, 1 when no applicable DNAME was
 * present, and -1 for malformed or bogus DNAME synthesis. */
static int
bd_dname_validate (bd_rr_t *rrs, int rrs_n, const char *qname, uint16_t qtype,
                   const bd_trust_t *active, int active_n, int skew_sec,
                   char *err, size_t err_sz)
{
  char qcanon[256];
  if (bd_canon_owner (qname, qcanon, sizeof qcanon) < 0)
    {
      snprintf (err, err_sz, "cannot canonicalise %s", qname);
      return -1;
    }

  bd_rr_t *best = NULL;
  char best_expected[256];
  size_t best_owner_len = 0;

  for (int i = 0; i < rrs_n; i++)
    {
      if (rrs[i].type != BD_T_DNAME)
        continue;
      char target[256], expected[256];
      if (bd_rr_rdata_name (&rrs[i], target, sizeof target) < 0)
        {
          snprintf (err, err_sz, "malformed DNAME RDATA at %s", rrs[i].owner);
          return -1;
        }
      if (bd_dname_expected_cname (qcanon, rrs[i].owner, target,
                                   expected, sizeof expected) < 0)
        continue;
      size_t owner_len = strlen (rrs[i].owner);
      if (!best || owner_len > best_owner_len)
        {
          best = &rrs[i];
          best_owner_len = owner_len;
          snprintf (best_expected, sizeof best_expected, "%s", expected);
        }
    }

  if (!best)
    return 1;

  char verr[256];
  if (bd_verify_rrset (rrs, rrs_n, best->owner, BD_T_DNAME,
                       active, active_n, skew_sec, verr, sizeof verr) < 0)
    {
      snprintf (err, err_sz, "answer DNAME RRset: %s", verr);
      return -1;
    }

  int saw_cname = 0, matched_cname = 0;
  char actual[256] = "";
  for (int i = 0; i < rrs_n; i++)
    {
      if (rrs[i].type != BD_T_CNAME || strcmp (rrs[i].owner, qcanon) != 0)
        continue;
      saw_cname = 1;
      if (bd_rr_rdata_name (&rrs[i], actual, sizeof actual) < 0)
        {
          snprintf (err, err_sz, "malformed synthesized CNAME at %s", qcanon);
          return -1;
        }
      if (strcmp (actual, best_expected) == 0)
        matched_cname = 1;
    }

  if (!saw_cname)
    {
      snprintf (err, err_sz, "DNAME synthesis mismatch: expected %s got <missing CNAME>",
                best_expected);
      return -1;
    }
  if (!matched_cname)
    {
      snprintf (err, err_sz, "DNAME synthesis mismatch: expected %s got %s",
                best_expected, actual[0] ? actual : "<none>");
      return -1;
    }

  if (qtype != BD_T_CNAME)
    {
      int target_rrset = 0;
      for (int i = 0; i < rrs_n; i++)
        if (rrs[i].type == qtype && strcmp (rrs[i].owner, best_expected) == 0)
          { target_rrset = 1; break; }
      if (target_rrset
          && bd_verify_rrset (rrs, rrs_n, best_expected, qtype,
                              active, active_n, skew_sec, verr, sizeof verr) < 0)
        {
          snprintf (err, err_sz, "DNAME target RRset %s/%s: %s",
                    best_expected, bd_type_name (qtype), verr);
          return -1;
        }
    }

  return 0;
}

static int
bd_name_wire_cmp (const char *a, const char *b)
{
  unsigned char aw[256], bw[256];
  int al = bd_name_to_wire (a, aw, sizeof aw);
  int bl = bd_name_to_wire (b, bw, sizeof bw);
  if (al < 0 || bl < 0) return 0;

  int apos[128], blpos[128], ac = 0, bc = 0;
  for (int off = 0; off < al && ac < (int)(sizeof apos / sizeof apos[0]); )
    {
      apos[ac++] = off;
      int lab = aw[off];
      if (lab == 0) break;
      off += 1 + lab;
    }
  for (int off = 0; off < bl && bc < (int)(sizeof blpos / sizeof blpos[0]); )
    {
      blpos[bc++] = off;
      int lab = bw[off];
      if (lab == 0) break;
      off += 1 + lab;
    }
  if (ac == 0 || bc == 0) return 0;

  /* RFC 4034 section 6.1 canonical DNS name order compares labels from
   * right to left, starting at the root. A whole wire-name memcmp is
   * wrong for NSEC ranges because it compares the leftmost label first. */
  int ai = ac - 1, bi = bc - 1;
  while (ai >= 0 && bi >= 0)
    {
      int alen = aw[apos[ai]];
      int blen = bw[blpos[bi]];
      int mn = alen < blen ? alen : blen;
      int c = memcmp (aw + apos[ai] + 1, bw + blpos[bi] + 1, (size_t) mn);
      if (c < 0) return -1;
      if (c > 0) return 1;
      if (alen < blen) return -1;
      if (alen > blen) return 1;
      ai--; bi--;
    }

  if (ai < 0 && bi < 0) return 0;
  return ai < 0 ? -1 : 1;
}

static int
bd_nsec_range_covers (const char *owner, const char *next, const char *qname)
{
  int on = bd_name_wire_cmp (owner, next);
  int oq = bd_name_wire_cmp (owner, qname);
  int qn = bd_name_wire_cmp (qname, next);
  if (on < 0) return oq < 0 && qn < 0;
  if (on > 0) return oq < 0 || qn < 0;
  return 0;
}

static int
bd_nsec_bitmap_has_type (const unsigned char *bm, size_t bm_len,
                         uint16_t qtype, int *present)
{
  size_t off = 0;
  int prev_window = -1;
  *present = 0;
  while (off < bm_len)
    {
      if (off + 2 > bm_len) return -1;
      int window = bm[off++];
      int len = bm[off++];
      if (len < 1 || len > 32) return -1;
      if (window <= prev_window) return -1;
      if (off + (size_t) len > bm_len) return -1;
      prev_window = window;
      if ((qtype >> 8) == (uint16_t) window)
        {
          int low = qtype & 0xff;
          int octet = low / 8;
          int bit = low % 8;
          if (octet < len && (bm[off + (size_t) octet] & (0x80u >> bit)))
            *present = 1;
        }
      off += (size_t) len;
    }
  return off == bm_len ? 0 : -1;
}

static int
bd_nsec_parse (const bd_rr_t *rr, char *next, size_t next_sz,
               const unsigned char **bitmap, size_t *bitmap_len)
{
  if (rr->rdata_len < 2) return -1;
  size_t off = 0;
  if (bd_decode_name (rr->rdata, rr->rdata_len, &off, next, next_sz, 0) < 0)
    return -1;
  if (off >= rr->rdata_len) return -1;
  *bitmap = rr->rdata + off;
  *bitmap_len = rr->rdata_len - off;
  return 0;
}

static int
bd_nsec3_base32hex (const unsigned char *in, size_t in_len,
                    char *out, size_t out_sz)
{
  static const char alpha[] = "0123456789abcdefghijklmnopqrstuv";
  uint32_t acc = 0;
  int bits = 0;
  size_t j = 0;
  for (size_t i = 0; i < in_len; i++)
    {
      acc = (acc << 8) | in[i];
      bits += 8;
      while (bits >= 5)
        {
          bits -= 5;
          if (j + 1 >= out_sz) return -1;
          out[j++] = alpha[(acc >> bits) & 31u];
        }
    }
  if (bits)
    {
      if (j + 1 >= out_sz) return -1;
      out[j++] = alpha[(acc << (5 - bits)) & 31u];
    }
  out[j] = '\0';
  return 0;
}

static int
bd_nsec3_hash_name (const char *name, uint8_t alg,
                    const unsigned char *salt, size_t salt_len,
                    uint16_t iterations,
                    unsigned char *out, size_t out_sz, size_t *out_len)
{
  if (iterations > BD_NSEC3_MAX_ITERATIONS)
    return -1;

  const char *hashverb;
  size_t expect_len;
  switch (alg)
    {
    case 1: hashverb = "sha1";   expect_len = 20; break;
    case 2: hashverb = "sha256"; expect_len = 32; break;
    case 3: hashverb = "sha512"; expect_len = 64; break;
    default: return -1;
    }

  unsigned char wire[256], buf[512], digest[64];
  int wn = bd_name_to_wire (name, wire, sizeof wire);
  if (wn < 0 || (size_t) wn + salt_len > sizeof buf) return -1;
  memcpy (buf, wire, (size_t) wn);
  memcpy (buf + wn, salt, salt_len);
  size_t digest_len = 0;
  if (bd_run_hash_bytes (hashverb, buf, (size_t) wn + salt_len,
                         digest, sizeof digest, &digest_len) < 0)
    return -1;
  if (digest_len != expect_len) return -1;
  for (uint16_t i = 0; i < iterations; i++)
    {
      if (digest_len + salt_len > sizeof buf) return -1;
      memcpy (buf, digest, digest_len);
      memcpy (buf + digest_len, salt, salt_len);
      if (bd_run_hash_bytes (hashverb, buf, digest_len + salt_len,
                             digest, sizeof digest, &digest_len) < 0)
        return -1;
      if (digest_len != expect_len) return -1;
    }
  if (digest_len > out_sz) return -1;
  memcpy (out, digest, digest_len);
  *out_len = digest_len;
  return 0;
}

static int
bd_nsec3_parse (const bd_rr_t *rr,
                uint8_t *alg, uint8_t *flags, uint16_t *iterations,
                const unsigned char **salt, size_t *salt_len,
                const unsigned char **next, size_t *next_len,
                const unsigned char **bitmap, size_t *bitmap_len)
{
  if (rr->rdata_len < 6) return -1;
  *alg = rr->rdata[0];
  *flags = rr->rdata[1];
  *iterations = bd_rd16 (rr->rdata + 2);
  *salt_len = rr->rdata[4];
  size_t off = 5;
  if (off + *salt_len + 1 > rr->rdata_len) return -1;
  *salt = rr->rdata + off;
  off += *salt_len;
  *next_len = rr->rdata[off++];
  if (*next_len == 0 || off + *next_len > rr->rdata_len) return -1;
  *next = rr->rdata + off;
  off += *next_len;
  if (off >= rr->rdata_len) return -1;
  *bitmap = rr->rdata + off;
  *bitmap_len = rr->rdata_len - off;
  return 0;
}

static int
bd_nsec3_hash_cmp (const unsigned char *a, size_t alen,
                   const unsigned char *b, size_t blen)
{
  size_t mn = alen < blen ? alen : blen;
  int c = memcmp (a, b, mn);
  if (c < 0) return -1;
  if (c > 0) return 1;
  if (alen < blen) return -1;
  if (alen > blen) return 1;
  return 0;
}

static int
bd_nsec3_range_covers_hash (const unsigned char *owner, size_t owner_len,
                            const unsigned char *next, size_t next_len,
                            const unsigned char *hash, size_t hash_len)
{
  int on = bd_nsec3_hash_cmp (owner, owner_len, next, next_len);
  int oh = bd_nsec3_hash_cmp (owner, owner_len, hash, hash_len);
  int hn = bd_nsec3_hash_cmp (hash, hash_len, next, next_len);
  if (on < 0) return oh < 0 && hn < 0;
  if (on > 0) return oh < 0 || hn < 0;
  return 0;
}


static int
bd_nsec3_owner_hash_label (const char *owner, char *out, size_t out_sz)
{
  size_t lab_len = strcspn (owner, ".");
  if (lab_len == 0 || lab_len >= out_sz) return -1;
  memcpy (out, owner, lab_len);
  out[lab_len] = '\0';
  return 0;
}

static int
bd_wildcard_validate (const bd_rr_t *rrs, int n,
                      const char *qname, uint16_t qtype,
                      const bd_trust_t *active, int active_n,
                      int skew_sec, char *err, size_t err_sz)
{
  char qcanon[256], wildcard[256], suffix[256];
  if (bd_canon_owner (qname, qcanon, sizeof qcanon) < 0)
    { snprintf (err, err_sz, "wildcard qname canonicalization failed"); return -1; }

  const bd_rr_t *rrsig = bd_find_rrsig (rrs, n, qcanon, qtype);
  if (!rrsig || rrsig->rdata_len < 18) return 0;
  unsigned sig_labels = rrsig->rdata[3];
  int q_labels = bd_label_count (qcanon);
  if (q_labels < 0)
    { snprintf (err, err_sz, "wildcard qname label count failed"); return -1; }
  if (q_labels <= (int) sig_labels) return 0;

  if (bd_wildcard_owner_from_labels (qcanon, sig_labels, wildcard, sizeof wildcard) < 0
      || bd_suffix_labels (qcanon, sig_labels, suffix, sizeof suffix) < 0)
    { snprintf (err, err_sz, "wildcard owner reconstruction failed"); return -1; }

  int saw_nsec = 0, saw_nsec3 = 0;
  for (int i = 0; i < n; i++)
    {
      if (rrs[i].type != BD_T_NSEC && rrs[i].type != BD_T_NSEC3) continue;
      if (bd_verify_rrset ((bd_rr_t *) rrs, n, rrs[i].owner, rrs[i].type,
                           active, active_n, skew_sec, err, err_sz) < 0)
        return -1;
      if (rrs[i].type == BD_T_NSEC) saw_nsec = 1;
      if (rrs[i].type == BD_T_NSEC3) saw_nsec3 = 1;
    }

  if (saw_nsec)
    {
      int q_covered = 0, ce_seen = 0, malformed = 0;
      for (int i = 0; i < n; i++)
        {
          if (rrs[i].type != BD_T_NSEC) continue;
          char next[256];
          const unsigned char *bm = NULL;
          size_t bm_len = 0;
          int nsec_present = 0;
          if (bd_nsec_parse (&rrs[i], next, sizeof next, &bm, &bm_len) < 0)
            { malformed = 1; continue; }
          if (bd_nsec_bitmap_has_type (bm, bm_len, BD_T_NSEC, &nsec_present) < 0)
            { malformed = 1; continue; }
          if (bd_nsec_range_covers (rrs[i].owner, next, qcanon)) q_covered = 1;
          if (strcmp (rrs[i].owner, suffix) == 0 && nsec_present) ce_seen = 1;
        }
      if (malformed)
        { snprintf (err, err_sz, "wildcard NSEC bitmap malformed"); return -1; }
      if (ce_seen && q_covered) return 0;
      if (!ce_seen)
        { snprintf (err, err_sz, "wildcard closest-encloser proof missing for %s via %s", qcanon, wildcard); return -1; }
      snprintf (err, err_sz, "wildcard NSEC proof missing for %s via %s", qcanon, wildcard);
      return -1;
    }

  if (saw_nsec3)
    {
      uint8_t ref_alg = 0, ref_flags = 0;
      uint16_t ref_iter = 0;
      const unsigned char *ref_salt = NULL;
      size_t ref_salt_len = 0;
      int params_set = 0, q_covered = 0, wildcard_hash_seen = 0, ce_seen = 0;
      unsigned char q_hash[64], wc_hash[64], ce_hash[64];
      size_t q_hash_len = 0, wc_hash_len = 0, ce_hash_len = 0;
      char q_label[64], wc_label[64], ce_label[64];

      for (int i = 0; i < n; i++)
        {
          if (rrs[i].type != BD_T_NSEC3) continue;
          uint8_t alg, flags;
          uint16_t iterations;
          const unsigned char *salt, *next, *bm;
          size_t salt_len, next_len, bm_len;
          if (bd_nsec3_parse (&rrs[i], &alg, &flags, &iterations,
                              &salt, &salt_len, &next, &next_len,
                              &bm, &bm_len) < 0)
            { snprintf (err, err_sz, "wildcard NSEC3 bitmap malformed"); return -1; }
          if (alg < 1 || alg > 3)
            { snprintf (err, err_sz, "NSEC3 unsupported hash algorithm %u", (unsigned) alg); return -1; }
          if (iterations > BD_NSEC3_MAX_ITERATIONS)
            { snprintf (err, err_sz, "NSEC3 iteration count %u exceeds RFC 9276 cap %u",
                        (unsigned) iterations, (unsigned) BD_NSEC3_MAX_ITERATIONS); return -1; }
          if (flags != 0)
            { snprintf (err, err_sz, "NSEC3 opt-out unsupported"); return -1; }
          int dummy = 0;
          if (bd_nsec_bitmap_has_type (bm, bm_len, BD_T_NSEC3, &dummy) < 0)
            { snprintf (err, err_sz, "wildcard NSEC3 bitmap malformed"); return -1; }
          if (!params_set)
            {
              ref_alg = alg; ref_flags = flags; ref_iter = iterations;
              ref_salt = salt; ref_salt_len = salt_len; params_set = 1;
              if (bd_nsec3_hash_name (qcanon, ref_alg, ref_salt, ref_salt_len, ref_iter,
                                      q_hash, sizeof q_hash, &q_hash_len) < 0
                  || bd_nsec3_hash_name (wildcard, ref_alg, ref_salt, ref_salt_len, ref_iter,
                                         wc_hash, sizeof wc_hash, &wc_hash_len) < 0
                  || bd_nsec3_hash_name (suffix, ref_alg, ref_salt, ref_salt_len, ref_iter,
                                         ce_hash, sizeof ce_hash, &ce_hash_len) < 0
                  || bd_nsec3_base32hex (q_hash, q_hash_len, q_label, sizeof q_label) < 0
                  || bd_nsec3_base32hex (wc_hash, wc_hash_len, wc_label, sizeof wc_label) < 0
                  || bd_nsec3_base32hex (ce_hash, ce_hash_len, ce_label, sizeof ce_label) < 0)
                { snprintf (err, err_sz, "wildcard NSEC3 hash failed"); return -1; }
            }
          else if (alg != ref_alg || flags != ref_flags || iterations != ref_iter
                   || salt_len != ref_salt_len || memcmp (salt, ref_salt, salt_len) != 0)
            { snprintf (err, err_sz, "wildcard NSEC3 parameter mismatch"); return -1; }

          char owner_hash[128], next_label[128];
          if (bd_nsec3_owner_hash_label (rrs[i].owner, owner_hash, sizeof owner_hash) < 0
              || bd_nsec3_base32hex (next, next_len, next_label, sizeof next_label) < 0)
            { snprintf (err, err_sz, "wildcard NSEC3 owner-name canonicalization failed"); return -1; }
          if (strcmp (owner_hash, ce_label) == 0) ce_seen = 1;
          if (strcmp (owner_hash, wc_label) == 0) wildcard_hash_seen = 1;
          if (bd_nsec3_range_covers_hash ((const unsigned char *) owner_hash, strlen (owner_hash),
                                          (const unsigned char *) next_label, strlen (next_label),
                                          (const unsigned char *) q_label, strlen (q_label)))
            q_covered = 1;
        }
      if (ce_seen && wildcard_hash_seen && q_covered) return 0;
      snprintf (err, err_sz, "wildcard NSEC3 proof missing for %s via %s", qcanon, wildcard);
      return -1;
    }

  snprintf (err, err_sz, "wildcard expansion proof missing for %s via %s", qcanon, wildcard);
  return -1;
}

static int
bd_negative_validate (const unsigned char *reply, size_t rlen,
                      const char *qname, uint16_t qtype,
                      const bd_trust_t *active, int active_n,
                      int skew_sec)
{
  char qcanon[256], err[256];
  if (bd_canon_owner (qname, qcanon, sizeof qcanon) < 0)
    return bd_validate_fail ("cannot canonicalise %s", qname);

  bd_rr_t rrs[BD_RR_MAX];
  int n = bd_collect_answer_authority (reply, rlen, rrs, BD_RR_MAX);
  if (n < 0)
    return bd_validate_fail ("negative response parse failed");

  int saw_nsec = 0, saw_nsec3 = 0;
  for (int i = 0; i < n; i++)
    {
      if (rrs[i].type != BD_T_NSEC && rrs[i].type != BD_T_NSEC3) continue;
      if (bd_verify_rrset (rrs, n, rrs[i].owner, rrs[i].type,
                           active, active_n, skew_sec, err, sizeof err) < 0)
        return bd_validate_fail ("%s RRset for %s: %s",
                                 bd_type_name (rrs[i].type), rrs[i].owner, err);
      if (rrs[i].type == BD_T_NSEC) saw_nsec = 1;
      if (rrs[i].type == BD_T_NSEC3) saw_nsec3 = 1;
    }

  if (saw_nsec)
    {
      int range_ok = 0, nodata_ok = 0, malformed = 0;
      for (int i = 0; i < n; i++)
        {
          if (rrs[i].type != BD_T_NSEC) continue;
          char next[256];
          const unsigned char *bm = NULL;
          size_t bm_len = 0;
          int q_present = 0, cname_present = 0;
          if (bd_nsec_parse (&rrs[i], next, sizeof next, &bm, &bm_len) < 0)
            { malformed = 1; continue; }
          if (bd_nsec_bitmap_has_type (bm, bm_len, qtype, &q_present) < 0
              || bd_nsec_bitmap_has_type (bm, bm_len, BD_T_CNAME, &cname_present) < 0)
            { malformed = 1; continue; }
          if (strcmp (rrs[i].owner, qcanon) == 0 && !q_present && !cname_present)
            nodata_ok = 1;
          if (bd_nsec_range_covers (rrs[i].owner, next, qcanon))
            range_ok = 1;
        }
      if (malformed)
        return bd_validate_fail ("NSEC bitmap malformed");
      if (range_ok || nodata_ok)
        {
          fprintf (stderr, "dns: VALIDATE OK (NSEC negative proof %s/%s)\n",
                   qname, bd_type_name (qtype));
          return EXECUTION_SUCCESS;
        }
      return bd_validate_fail ("NSEC gap mismatch");
    }

  if (saw_nsec3)
    {
      int ce_ok = 0, range_ok = 0;
      for (int i = 0; i < n; i++)
        {
          if (rrs[i].type != BD_T_NSEC3) continue;
          uint8_t alg, flags;
          uint16_t iterations;
          const unsigned char *salt, *next, *bm;
          size_t salt_len, next_len, bm_len;
          if (bd_nsec3_parse (&rrs[i], &alg, &flags, &iterations,
                              &salt, &salt_len, &next, &next_len,
                              &bm, &bm_len) < 0)
            return bd_validate_fail ("NSEC3 bitmap malformed");
          if (alg < 1 || alg > 3)
            return bd_validate_fail ("NSEC3 unsupported hash algorithm %u", (unsigned) alg);
          if (iterations > BD_NSEC3_MAX_ITERATIONS)
            return bd_validate_fail ("NSEC3 iteration count %u exceeds RFC 9276 cap %u",
                                     (unsigned) iterations,
                                     (unsigned) BD_NSEC3_MAX_ITERATIONS);
          if (flags != 0)
            return bd_validate_fail ("NSEC3 opt-out unsupported");
          int dummy = 0;
          if (bd_nsec_bitmap_has_type (bm, bm_len, qtype, &dummy) < 0)
            return bd_validate_fail ("NSEC3 bitmap malformed");

          char owner_hash[128], ce_label[128], q_label[128], next_label[128];
          size_t lab_len = strcspn (rrs[i].owner, ".");
          if (lab_len == 0 || lab_len >= sizeof owner_hash)
            return bd_validate_fail ("NSEC3 owner-name canonicalization failed");
          memcpy (owner_hash, rrs[i].owner, lab_len);
          owner_hash[lab_len] = '\0';

          unsigned char ce_hash[64], q_hash[64];
          size_t q_hash_len = 0;
          if (bd_nsec3_hash_name (qcanon, alg, salt, salt_len, iterations,
                                  q_hash, sizeof q_hash, &q_hash_len) < 0)
            return bd_validate_fail ("NSEC3 hash failed");
          if (bd_nsec3_base32hex (q_hash, q_hash_len, q_label, sizeof q_label) < 0
              || bd_nsec3_base32hex (next, next_len, next_label, sizeof next_label) < 0)
            return bd_validate_fail ("NSEC3 owner-name canonicalization failed");
          for (const char *suffix = qcanon; suffix && *suffix; )
            {
              size_t ce_hash_len = 0;
              if (bd_nsec3_hash_name (suffix, alg, salt, salt_len, iterations,
                                      ce_hash, sizeof ce_hash, &ce_hash_len) < 0
                  || bd_nsec3_base32hex (ce_hash, ce_hash_len, ce_label, sizeof ce_label) < 0)
                return bd_validate_fail ("NSEC3 hash failed");
              if (strcmp (owner_hash, ce_label) == 0)
                { ce_ok = 1; break; }
              const char *dot = strchr (suffix, '.');
              suffix = dot ? dot + 1 : NULL;
            }
          if (bd_nsec3_range_covers_hash ((const unsigned char *) owner_hash, strlen (owner_hash),
                                          (const unsigned char *) next_label, strlen (next_label),
                                          (const unsigned char *) q_label, strlen (q_label)))
            range_ok = 1;
        }
      if (!ce_ok)
        return bd_validate_fail ("NSEC3 missing closest-encloser");
      if (!range_ok)
        return bd_validate_fail ("NSEC3 gap mismatch");
      fprintf (stderr, "dns: VALIDATE OK (NSEC3 negative proof %s/%s)\n",
               qname, bd_type_name (qtype));
      return EXECUTION_SUCCESS;
    }

  return bd_validate_fail ("no signed NSEC/NSEC3 denial proof");
}

/* Iterative chain walk: descend zone labels from "." down to the
 * answer name, verifying each zone's DNSKEY RRset against the parent
 * DS chain, then verify the leaf RRset. */
static int
bd_chain_validate (const char *qname, uint16_t qtype, const char *server,
                   int timeout_ms, int attempts, int skew_sec)
{
  /* If no trust set was loaded explicitly, try BASHDNS_TRUST_ANCHOR. */
  if (bd_trust_count == 0)
    {
      const char *env_anchor = getenv ("BASHDNS_TRUST_ANCHOR");
      if (env_anchor && *env_anchor)
        {
          char buf[512];
          if (bd_load_trust_anchor_line (env_anchor, buf, sizeof buf) < 0)
            return bd_validate_fail ("BASHDNS_TRUST_ANCHOR=%s could not be parsed", env_anchor);
        }
    }
  if (bd_trust_count == 0)
    return bd_validate_fail ("no trust anchor loaded; call trust-anchor-load PATH first or set BASHDNS_TRUST_ANCHOR");

  /* Build the descent list: ".", "tld.", ..., qname. We walk from the
   * trust anchor at "." and descend by one label at a time. */
  char canon[256];
  if (bd_canon_owner (qname, canon, sizeof canon) < 0)
    return bd_validate_fail ("cannot canonicalise %s", qname);

  /* Collect zones from "." down to the canon name. Each label boundary
   * is a candidate zone cut; we don't know zone apexes a priori
   * without SOA/NS detection, so we attempt DNSKEY fetch at each
   * boundary and tolerate "no DNSKEY at this name" by treating the
   * level as not-a-zone-cut and carrying the parent's trust set
   * forward. The fixture-mode tests pin the expected zone cuts
   * explicitly via the fixtures they ship.
   *
   * Example: canon = "www.example.com"
   *   label boundaries (right-to-left): "com", "example.com", "www.example.com"
   *   descent zones = [ ".", "com", "example.com", "www.example.com" ]
   * Example: canon = "example.com"
   *   descent = [ ".", "com", "example.com" ]
   */
  const char *zones[BD_CHAIN_MAX_DEPTH];
  int zc = 0;
  zones[zc++] = ".";
  int n = (int) strlen (canon);
  int label_starts[64]; int ls_n = 0;
  for (int i = n - 1; i >= 0; i--)
    if (canon[i] == '.') label_starts[ls_n++] = i + 1;
  /* The full canon name (offset 0) is itself the deepest candidate. */
  label_starts[ls_n++] = 0;
  /* label_starts is in descending-zone order: rightmost suffix first. */
  for (int i = 0; i < ls_n; i++)
    {
      if (zc >= BD_CHAIN_MAX_DEPTH)
        return bd_validate_fail ("chain too deep");
      zones[zc++] = canon + label_starts[i];
    }
  /* If the leaf name itself is queried (qtype=DNSKEY/DS at the same
   * name) we will still attempt to verify the answer RRset against
   * the active set after the loop completes. */

  /* Initialise the active trust set from the configured anchors. */
  bd_trust_t active[BD_TRUST_MAX]; int active_n = bd_trust_count;
  memcpy (active, bd_trust_set, (size_t) active_n * sizeof active[0]);

  unsigned char reply[8192];

  /* For each zone, fetch DNSKEY, verify DS-chain bridge, install
   * the new keys as the trust set for the child zone. Names that are
   * not actually zone cuts (no DNSKEY answer) are skipped silently —
   * the chain just keeps the parent's trust set. The leaf RRset
   * still has to be signed by *some* key in the final active set.
   * The trust anchor at zi==0 (".") MUST always have DNSKEY records
   * (otherwise we have no chain at all). */
  for (int zi = 0; zi < zc; zi++)
    {
      const char *zone = zones[zi];
      int rlen = bd_fetch_attempts (zone, BD_T_DNSKEY, server, 1, timeout_ms,
                                    attempts, reply, sizeof reply);
      if (rlen < 12)
        {
          if (zi == 0)
            return bd_validate_fail ("DNSKEY fetch failed for root zone");
          continue;  /* non-zone-cut: keep prior active set */
        }

      bd_rr_t rrs[BD_RR_MAX];
      int rrs_n = bd_collect_rrset (reply, (size_t) rlen, zone, BD_T_DNSKEY,
                                    rrs, BD_RR_MAX);
      if (rrs_n <= 0)
        {
          if (zi == 0)
            return bd_validate_fail ("no DNSKEY RRset for root zone");
          continue;
        }

      /* Install the candidate DNSKEYs into a temporary trust set. */
      bd_trust_t cand[BD_TRUST_MAX]; int cand_n = 0;
      if (bd_install_dnskeys (rrs, rrs_n, zone, cand, &cand_n, BD_TRUST_MAX) < 0
          || cand_n == 0)
        return bd_validate_fail ("DNSKEY install failed for zone %s", zone);

      /* DS bridge: every candidate DNSKEY must either chain to a DS
       * already in the active trust set, OR a DNSKEY-form trust anchor
       * for this zone is in the active set. We require at least one
       * DS-valid (or DNSKEY-anchor-valid) key per zone — applies at
       * zi==0 too, where the root trust anchor is normally a DS. */
      int bridged = 0;
      /* Direct DNSKEY anchor match (operator pinned a DNSKEY). */
      for (int i = 0; i < active_n && !bridged; i++)
        {
          if (active[i].kind != BD_T_DNSKEY) continue;
          if (strcmp (active[i].owner, cand[0].owner) != 0) continue;
          for (int j = 0; j < cand_n; j++)
            if (cand[j].rdata_len == active[i].rdata_len
                && memcmp (cand[j].rdata, active[i].rdata, cand[j].rdata_len) == 0)
              { bridged = 1; break; }
        }
      /* DS-bridged match. */
      for (int i = 0; i < cand_n && !bridged; i++)
        {
          if (bd_ds_check (cand[i].owner, cand[i].key_tag,
                           cand[i].algorithm,
                           cand[i].rdata, cand[i].rdata_len,
                           active, active_n) == 0)
            bridged = 1;
        }
      if (!bridged)
        return bd_validate_fail ("DS digest mismatch for zone %s (no candidate DNSKEY hashes to any active DS)", zone);

      /* Verify the DNSKEY RRset RRSIG using the candidate set itself
       * (a DNSKEY RRset is self-signed by one of its KSKs). */
      char err[256];
      if (bd_verify_rrset (rrs, rrs_n, zone, BD_T_DNSKEY,
                           cand, cand_n, skew_sec, err, sizeof err) < 0)
        return bd_validate_fail ("DNSKEY RRset for %s: %s", zone, err);

      /* Promote candidate -> active trust set for this zone. */
      memcpy (active, cand, (size_t) cand_n * sizeof active[0]);
      active_n = cand_n;

      /* If this is not the final zone, fetch DS for the *next* zone
       * and add it to the active set so the next iteration can bridge.
       * For the root anchor case (only DS in the initial set), we
       * already bridged via the static DS at zi==0; for descent we
       * pull DS from the parent's authority section. */
      if (zi + 1 < zc)
        {
          const char *child = zones[zi + 1];
          int dlen = bd_fetch_attempts (child, BD_T_DS, server, 1, timeout_ms,
                                        attempts, reply, sizeof reply);
          if (dlen < 12)
            continue;  /* no DS for child = not a zone cut; carry on */
          bd_rr_t drr[BD_RR_MAX];
          int drr_n = bd_collect_rrset (reply, (size_t) dlen, child, BD_T_DS,
                                        drr, BD_RR_MAX);
          if (drr_n <= 0)
            continue;  /* same — child not delegated */
          /* Verify DS RRSIG using the parent's active DNSKEYs. */
          if (bd_verify_rrset (drr, drr_n, child, BD_T_DS,
                               active, active_n, skew_sec, err, sizeof err) < 0)
            return bd_validate_fail ("DS RRset for %s: %s", child, err);
          /* Convert each DS RR into a bd_trust_t and append. */
          if (active_n + drr_n > BD_TRUST_MAX)
            return bd_validate_fail ("trust set overflow at zone %s", child);
          for (int i = 0; i < drr_n; i++)
            {
              if (drr[i].type != BD_T_DS) continue;
              if (drr[i].rdata_len < 4) continue;
              bd_trust_t *t = &active[active_n++];
              memset (t, 0, sizeof *t);
              if (bd_canon_owner (drr[i].owner, t->owner, sizeof t->owner) < 0)
                return bd_validate_fail ("DS owner canonicalise failed");
              t->kind = BD_T_DS;
              t->key_tag     = bd_rd16 (drr[i].rdata);
              t->algorithm   = drr[i].rdata[2];
              t->digest_type = drr[i].rdata[3];
              size_t dl = drr[i].rdata_len - 4;
              if (dl > sizeof t->digest) dl = sizeof t->digest;
              memcpy (t->digest, drr[i].rdata + 4, dl);
              t->digest_len = dl;
            }
        }
    }

  /* Leaf answer. */
  int rlen = bd_fetch_attempts (qname, qtype, server, 1, timeout_ms,
                                attempts, reply, sizeof reply);
  if (rlen < 12)
    return bd_validate_fail ("answer fetch failed for %s/%s", qname, bd_type_name (qtype));

  /* NXDOMAIN / NODATA: rcode != 0, or zero answers. v2 stops here. */
  int rcode = reply[3] & 0xf;
  uint16_t an = bd_rd16 (reply + 6);
  if (rcode != 0 || an == 0)
    return bd_negative_validate (reply, (size_t) rlen, qname, qtype,
                                 active, active_n, skew_sec);

  bd_rr_t all_rrs[BD_RR_MAX];
  int all_n = bd_collect_answer_authority (reply, (size_t) rlen, all_rrs, BD_RR_MAX);
  if (all_n < 0)
    return bd_validate_fail ("answer parse failed for %s/%s", qname, bd_type_name (qtype));

  char err[256];
  int dname_rc = bd_dname_validate (all_rrs, all_n, qname, qtype,
                                    active, active_n, skew_sec,
                                    err, sizeof err);
  if (dname_rc < 0)
    return bd_validate_fail ("DNAME proof: %s", err);
  if (dname_rc == 0)
    {
      fprintf (stderr, "dns: VALIDATE OK (chain depth %d, DNAME proof %s/%s)\n",
               zc, qname, bd_type_name (qtype));
      return EXECUTION_SUCCESS;
    }

  bd_rr_t rrs[BD_RR_MAX];
  int rrs_n = bd_collect_rrset (reply, (size_t) rlen, qname, qtype, rrs, BD_RR_MAX);
  if (rrs_n <= 0)
    return bd_validate_fail ("VALIDATE-NEGATIVE-NOT-IMPLEMENTED (no answer RR for %s/%s)",
                             qname, bd_type_name (qtype));
  /* Confirm at least one RRSIG is present in the captured set. */
  int saw_rrsig = 0;
  for (int i = 0; i < rrs_n; i++)
    if (rrs[i].type == BD_T_RRSIG) { saw_rrsig = 1; break; }
  if (!saw_rrsig)
    return bd_validate_fail ("VALIDATE-NEGATIVE-NOT-IMPLEMENTED (no RRSIG over %s/%s)",
                             qname, bd_type_name (qtype));

  /* Type-agnostic leaf verify: SVCB/HTTPS/etc. verify here; SVCB/HTTPS
     TargetName canonicalisation is handled in bd_collect_rrs. */
  if (bd_verify_rrset (rrs, rrs_n, qname, qtype,
                       active, active_n, skew_sec, err, sizeof err) < 0)
    return bd_validate_fail ("answer RRset: %s", err);
  if (bd_wildcard_validate (all_rrs, all_n, qname, qtype,
                            active, active_n, skew_sec, err, sizeof err) < 0)
    return bd_validate_fail ("answer wildcard proof: %s", err);

  fprintf (stderr, "dns: VALIDATE OK (chain depth %d, leaf %s/%s)\n",
           zc, qname, bd_type_name (qtype));
  return EXECUTION_SUCCESS;
}

/* ---- Bash entry ---------------------------------------------------- */

static int
bd_query_cmd (WORD_LIST *args, const char *forced_type)
{
  const char *server = NULL;
  int timeout_ms = 2000;
  int timeout_explicit = 0;
  int dnssec = 0;
  int require_ad = 0;
  int validate = 0;
  int skew_sec = 300;
  int dot = 0;
  int doh = 0;
  const char *dot_host = NULL;
  const char *dot_ca = NULL;
  const char *doh_url = NULL;
  const char *qname = NULL;
  const char *qtype_str = forced_type;

  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-s") == 0)
        { if (!p->next) { builtin_error ("-s needs SERVER"); return EX_USAGE; }
          p = p->next; server = p->word->word; }
      else if (strcmp (w, "-t") == 0)
        { if (!p->next) { builtin_error ("-t needs MS"); return EX_USAGE; }
          p = p->next; timeout_ms = atoi (p->word->word); timeout_explicit = 1;
          if (timeout_ms <= 0 || timeout_ms > 60000)
            { builtin_error ("-t must be 1..60000 ms"); return EX_USAGE; } }
      else if (strcmp (w, "-d") == 0 || strcmp (w, "--dnssec") == 0)
        dnssec = 1;
      else if (strcmp (w, "--require-ad") == 0 ||
               strcmp (w, "--require-ad-bit") == 0)
        { dnssec = 1; require_ad = 1; }
      else if (strcmp (w, "--validate") == 0)
        { dnssec = 1; validate = 1; }
      else if (strcmp (w, "--skew") == 0)
        { if (!p->next) { builtin_error ("--skew needs SEC"); return EX_USAGE; }
          p = p->next; skew_sec = atoi (p->word->word);
          if (skew_sec < 0 || skew_sec > 86400)
            { builtin_error ("--skew must be 0..86400 sec"); return EX_USAGE; } }
      else if (strcmp (w, "--dot") == 0)
        dot = 1;
      else if (strcmp (w, "-h") == 0 || strcmp (w, "--dot-host") == 0)
        { if (!p->next) { builtin_error ("-h needs DOT_HOST[:PORT]"); return EX_USAGE; }
          p = p->next; dot_host = p->word->word; dot = 1; }
      else if (strcmp (w, "--dot-ca") == 0)
        { if (!p->next) { builtin_error ("--dot-ca needs PEM path"); return EX_USAGE; }
          p = p->next; dot_ca = p->word->word; dot = 1; }
      else if (strcmp (w, "--doh") == 0)
        {
          doh = 1;
          if (p->next && strncmp (p->next->word->word, "-", 1) != 0)
            { p = p->next; doh_url = p->word->word; }
        }
      else if (strcmp (w, "--doh-url") == 0)
        { if (!p->next) { builtin_error ("--doh-url needs URL"); return EX_USAGE; }
          p = p->next; doh_url = p->word->word; doh = 1; }
      else if (!qname) qname = w;
      else if (!qtype_str) qtype_str = w;
      else { builtin_error ("query: extra arg %s", w); return EX_USAGE; }
    }
  if (!qname) { builtin_error ("missing host/name"); return EX_USAGE; }
  if (qtype_str && strcasecmp (qtype_str, "PTR") != 0 && !bd_valid_hostname (qname))
    { builtin_error ("invalid host/name: %s", qname); return EX_USAGE; }
  if (!qtype_str) { builtin_error ("missing TYPE"); return EX_USAGE; }
  uint16_t qtype;
  if (bd_type_from_name (qtype_str, &qtype) < 0)
    { builtin_error ("unknown type: %s", qtype_str); return EX_USAGE; }

  if (!dnssec && bd_truthy (getenv ("BASHDNS_VALIDATE")))
    dnssec = 1;
  if (bd_truthy (getenv ("BASHDNS_REQUIRE_AD")))
    { dnssec = 1; require_ad = 1; }
  if (bd_truthy (getenv ("BASHDNS_VALIDATE_CHAIN")))
    { dnssec = 1; validate = 1; }
  if (bd_truthy (getenv ("BASHDNS_DOT")))
    dot = 1;
  if (!dot_host)
    dot_host = getenv ("BASHDNS_DOT_HOST");
  if (bd_truthy (getenv ("BASHDNS_DOH")))
    doh = 1;
  if (!doh_url)
    doh_url = getenv ("BASHDNS_DOH_URL");
  if (doh_url && *doh_url)
    doh = 1;
  if (dot && doh)
    { builtin_error ("--dot and --doh are mutually exclusive"); return EX_USAGE; }

  char server_list[8][64];
  int server_count = 0;
  if (server)
    {
      if (strlen (server) >= sizeof server_list[0])
        { builtin_error ("nameserver too long: %s", server); return EX_USAGE; }
      strcpy (server_list[server_count++], server);
    }
  else if (getenv ("BASHDNS_FIXTURE_DIR") || dot || doh)
    {
      /* Fixture mode, DoT, and DoH bypass UDP nameserver discovery in bd_fetch().
       * Keep a dummy upstream key so the shared fetch/validation paths have
       * a non-NULL server string without requiring a local resolv.conf. */
      strcpy (server_list[server_count++], "0.0.0.0");
    }
  else
    {
      server_count = bd_load_nameservers (server_list, 8);
      if (server_count < 1)
        {
          builtin_error ("no nameserver in %s; pass -s", bd_resolv_conf_path ());
          return EXECUTION_FAILURE;
        }
    }

  bd_search_conf_t resolver_conf;
  bd_load_search_conf (&resolver_conf);
  if (!timeout_explicit && resolver_conf.timeout_sec > 0)
    timeout_ms = resolver_conf.timeout_sec * 1000;
  if (!server && resolver_conf.rotate && server_count > 1)
    {
      char first[64];
      strcpy (first, server_list[0]);
      for (int i = 0; i + 1 < server_count; i++)
        strcpy (server_list[i], server_list[i + 1]);
      strcpy (server_list[server_count - 1], first);
    }

  /* Set up DoT context. RFC 7858 reserves TCP/853. -h accepts either
   * "host" or "host:port"; bare hostnames pick the default 853 port. */
  memset (&bd_dot_ctx, 0, sizeof bd_dot_ctx);
  if (dot)
    {
      const char *eff_host = dot_host && *dot_host ? dot_host : "1.1.1.1";
      const char *colon = strrchr (eff_host, ':');
      const char *brkt  = strrchr (eff_host, ']');
      /* IPv6 literal in brackets ([2606:4700::1111]:853) — only treat
       * the colon as a port separator when it comes after the closing
       * bracket. Bare unbracketed IPv6 colons are rejected to keep the
       * grammar unambiguous. */
      int port = 853;
      const char *host_start = eff_host;
      size_t host_len;
      if (colon && (!brkt || colon > brkt))
        {
          int p_in = atoi (colon + 1);
          if (p_in <= 0 || p_in > 65535)
            { builtin_error ("--dot: bad port: %s", colon + 1); return EX_USAGE; }
          port = p_in;
          host_len = (size_t) (colon - eff_host);
        }
      else
        host_len = strlen (eff_host);
      if (host_len > 0 && eff_host[0] == '[' && host_len >= 2
          && eff_host[host_len - 1] == ']')
        { host_start = eff_host + 1; host_len -= 2; }
      if (host_len == 0 || host_len >= sizeof bd_dot_ctx.host)
        { builtin_error ("--dot: bad host"); return EX_USAGE; }
      memcpy (bd_dot_ctx.host, host_start, host_len);
      bd_dot_ctx.host[host_len] = '\0';
      bd_dot_ctx.port = port;
      if (dot_ca && *dot_ca)
        {
          if (strlen (dot_ca) >= sizeof bd_dot_ctx.ca_path)
            { builtin_error ("--dot-ca: path too long"); return EX_USAGE; }
          /* Reject paths containing a single quote so the bash -c
           * dispatch string in bd_query_dot stays parseable. This
           * fires here (not only inside bd_query_dot's default branch)
           * so the validation holds even under BASHDNS_DOT_CMD stubs. */
          if (strchr (dot_ca, '\'') != NULL)
            { builtin_error ("--dot-ca: CA path may not contain '"); return EX_USAGE; }
          strcpy (bd_dot_ctx.ca_path, dot_ca);
        }
      bd_dot_ctx.active = 1;
    }

  memset (&bd_doh_ctx, 0, sizeof bd_doh_ctx);
  if (doh)
    {
      const char *eff_url = doh_url && *doh_url
        ? doh_url : "https://cloudflare-dns.com/dns-query";
      if (strlen (eff_url) >= sizeof bd_doh_ctx.url)
        { builtin_error ("--doh: URL too long"); return EX_USAGE; }
      if (!bd_doh_url_valid (eff_url))
        {
          builtin_error ("--doh: URL must be https://HOST[:PORT]/PATH with a simple host");
          return EX_USAGE;
        }
      strcpy (bd_doh_ctx.url, eff_url);
      bd_doh_ctx.active = 1;
    }

  /* PTR: rewrite IP → in-addr.arpa name. */
  char ptr_name[96];
  if (qtype == BD_T_PTR)
    {
      if (bd_to_ptr_name (qname, ptr_name, sizeof ptr_name) < 0)
        { builtin_error ("PTR needs dotted IPv4 address"); return EX_USAGE; }
      qname = ptr_name;
    }

  char query_names[BD_SEARCH_MAX + 1][256];
  int query_name_count = bd_build_query_order (qname, qtype, query_names,
                                               BD_SEARCH_MAX + 1);
  if (query_name_count < 1)
    { builtin_error ("could not build resolver query order for %s", qname); return EXECUTION_FAILURE; }

  /* --validate: local iterative chain walk. Independent of --require-ad
   * (the resolver AD bit is ignored in this mode). The chain walker
   * uses bd_fetch() under the hood, which transparently swaps the wire
   * fetch for fixture reads when BASHDNS_FIXTURE_DIR is set. */
  if (validate)
    {
      for (int qi = 0; qi < query_name_count; qi++)
        {
          for (int si = 0; si < server_count; si++)
            {
              const char *eff_server = server_list[si];
              int rc = bd_chain_validate (query_names[qi], qtype, eff_server,
                                          timeout_ms, resolver_conf.attempts,
                                          skew_sec);
              if (rc != EXECUTION_SUCCESS) continue;
              /* Re-fetch the leaf and emit the answer for the caller's
               * consumption. */
              unsigned char rep[8192];
              int rl = bd_fetch_attempts (query_names[qi], qtype, eff_server, 1,
                                          timeout_ms, resolver_conf.attempts,
                                          rep, sizeof rep);
              if (rl < 12) continue;
              /* A validated NXDOMAIN/NODATA negative proof has no answer RR
                 to emit, but validation already succeeded -> return OK. */
              if ((rep[3] & 0xf) != 0 || bd_rd16 (rep + 6) == 0)
                return EXECUTION_SUCCESS;
              int en = bd_emit_answers (rep, (size_t) rl, qtype);
              if (en > 0) return EXECUTION_SUCCESS;
            }
        }
      return EXECUTION_FAILURE;
    }

  unsigned char reply[4096];
  for (int qi = 0; qi < query_name_count; qi++)
    {
      for (int si = 0; si < server_count; si++)
        {
          int rlen = bd_fetch_attempts (query_names[qi], qtype, server_list[si],
                                        dnssec, timeout_ms,
                                        resolver_conf.attempts,
                                        reply, sizeof reply);
          if (rlen < 0) continue;
          if (bd_tc_bit (reply, (size_t) rlen))
            {
              builtin_error ("truncated DNS response; TCP fallback unavailable");
              return EXECUTION_FAILURE;
            }
          if (dnssec)
            {
              if (bd_ad_bit (reply, (size_t) rlen))
                fprintf (stderr, "dns: dnssec AD validated by resolver\n");
              else if (require_ad)
                {
                  builtin_error ("dnssec AD required but resolver did not set AD");
                  return EXECUTION_FAILURE;
                }
              else
                fprintf (stderr, "dns: dnssec records requested; resolver did not set AD (local full-chain validation requires --validate)\n");
            }
          int n = bd_emit_answers (reply, (size_t) rlen, qtype);
          if (n < 0) { builtin_error ("malformed response"); return EXECUTION_FAILURE; }
          if (n > 0) return EXECUTION_SUCCESS;
        }
    }
  return EXECUTION_FAILURE;
}

/* ====================================================================
 * checkzone / checkconf — pure parsing validators (DNS 6.2-foundation).
 *
 * NO daemon, NO socket, NO serving. `dns checkzone PATH` parses an
 * RFC 1035 master file and exits 0 iff it would load; `dns checkconf
 * PATH` validates the bash-os flat `key = value` DNS config. Both print a
 * `file:line: message` diagnostic on the first hard error, mirroring
 * BIND `named-checkzone`'s accept/reject classification for the common
 * subset (exact byte-match is not required — see design §2).
 * ==================================================================== */

#define BZ_MAXLINE   8192
#define BZ_MAXTOK    64
#define BZ_INC_DEPTH 8

static int bz_qualify (const char *name, const char *origin, char *out, size_t out_sz);

/* Owner-name label/length validation for the master-file subset. Accepts
 * the wildcards/specials the zone grammar allows ('@', '*', '.', relative
 * and absolute names). Returns 0 on ok, -1 with *why set on reject. */
static int
bz_check_owner (const char *name, const char **why)
{
  if (!name || !*name) { *why = "empty owner name"; return -1; }
  if (strcmp (name, "@") == 0) return 0;
  if (strcmp (name, ".") == 0) return 0;
  size_t total = strlen (name);
  if (total > 255) { *why = "owner name exceeds 255 octets"; return -1; }
  const char *p = name;
  /* leading "*." wildcard label is legal */
  if (p[0] == '*' && (p[1] == '.' || p[1] == '\0')) p += (p[1] == '.') ? 2 : 1;
  size_t lab = 0;
  for (; *p; p++)
    {
      if (*p == '.')
        {
          if (lab == 0) { *why = "empty label in owner name"; return -1; }
          if (lab > 63) { *why = "label exceeds 63 octets"; return -1; }
          lab = 0;
          continue;
        }
      unsigned char c = (unsigned char) *p;
      if (c <= 0x20 || c == 0x7f) { *why = "control char in owner name"; return -1; }
      lab++;
    }
  if (lab > 63) { *why = "label exceeds 63 octets"; return -1; }
  return 0;
}

/* RDATA-target host name (NS/CNAME/MX/PTR/SRV target). Same rules as owner
 * minus the '@'/'*' specials. */
static int
bz_check_host (const char *name, const char **why)
{
  if (!name || !*name) { *why = "empty host name"; return -1; }
  return bz_check_owner (name, why);
}

/* Is s a base-10 uint32 (RFC 1982 serial / SOA timers)? */
static int
bz_is_u32 (const char *s)
{
  if (!s || !*s) return 0;
  errno = 0;
  char *end = NULL;
  unsigned long long v = strtoull (s, &end, 10);
  if (errno || !end || *end != '\0') return 0;
  return v <= 4294967295ULL;
}

static int
bd_serial_newer (uint32_t a, uint32_t b)
{
  return a != b && (uint32_t) (a - b) < 0x80000000U;
}

static int
bz_is_u16 (const char *s)
{
  if (!s || !*s) return 0;
  char *end = NULL;
  unsigned long v = strtoul (s, &end, 10);
  return end && *end == '\0' && v <= 65535UL;
}

/* TTL field: plain seconds (uint32) or BIND 1w2d3h4m5s style. */
static int
bz_is_ttl (const char *s)
{
  if (!s || !*s) return 0;
  if (bz_is_u32 (s)) return 1;
  /* unit form: at least one <digits><unit> group, units w/d/h/m/s */
  const char *p = s;
  int groups = 0;
  while (*p)
    {
      if (!isdigit ((unsigned char) *p)) return 0;
      while (isdigit ((unsigned char) *p)) p++;
      char u = (char) tolower ((unsigned char) *p);
      if (u != 'w' && u != 'd' && u != 'h' && u != 'm' && u != 's') return 0;
      p++;
      groups++;
    }
  return groups > 0;
}

static int
bz_is_ipv4 (const char *s)
{
  struct in_addr a;
  return s && inet_pton (AF_INET, s, &a) == 1;
}

static int
bz_is_ipv6 (const char *s)
{
  struct in6_addr a;
  return s && inet_pton (AF_INET6, s, &a) == 1;
}

/* Tokenize one logical line (already de-commented and joined across '()')
 * into whitespace-separated tokens, honoring "double quoted" strings which
 * stay a single token (quotes preserved). Returns token count, fills tok[]. */
static int
bz_tokenize (char *line, char *tok[], int max)
{
  int n = 0;
  char *p = line;
  while (*p && n < max)
    {
      while (*p == ' ' || *p == '\t') p++;
      if (!*p) break;
      if (*p == '"')
        {
          tok[n++] = p++;          /* keep opening quote in token */
          while (*p && *p != '"')
            {
              if (*p == '\\' && p[1]) p++;
              p++;
            }
          if (*p == '"') p++;       /* consume closing quote */
        }
      else
        {
          tok[n++] = p;
          while (*p && *p != ' ' && *p != '\t') p++;
        }
      if (*p) { *p = '\0'; p++; }
    }
  return n;
}

/* Strip an unquoted ';' comment in place (quotes protect ';'). */
static void
bz_strip_comment (char *s)
{
  int in_q = 0;
  for (char *p = s; *p; p++)
    {
      if (*p == '"' && (p == s || p[-1] != '\\')) in_q = !in_q;
      else if (*p == ';' && !in_q) { *p = '\0'; return; }
    }
}

/* Validate the RDATA token vector for a known type. rd[] are the tokens
 * after owner/ttl/class/type. Returns 0 ok, -1 reject (*why set). */
static int
bz_check_rdata (uint16_t type, char *rd[], int nrd, const char **why)
{
  switch (type)
    {
    case BD_T_SOA:
      if (nrd != 7) { *why = "SOA needs: mname rname serial refresh retry expire minimum"; return -1; }
      if (bz_check_host (rd[0], why)) return -1;
      if (bz_check_host (rd[1], why)) return -1;
      if (!bz_is_u32 (rd[2])) { *why = "SOA serial not a uint32 (RFC 1982)"; return -1; }
      if (!bz_is_ttl (rd[3])) { *why = "SOA refresh not a valid TTL/uint32"; return -1; }
      if (!bz_is_ttl (rd[4])) { *why = "SOA retry not a valid TTL/uint32"; return -1; }
      if (!bz_is_ttl (rd[5])) { *why = "SOA expire not a valid TTL/uint32"; return -1; }
      if (!bz_is_ttl (rd[6])) { *why = "SOA minimum not a valid TTL/uint32"; return -1; }
      return 0;
    case BD_T_NS:
    case BD_T_CNAME:
    case BD_T_DNAME:
    case BD_T_PTR:
      if (nrd != 1) { *why = "expected exactly one domain name in RDATA"; return -1; }
      return bz_check_host (rd[0], why);
    case BD_T_A:
      if (nrd != 1) { *why = "A needs exactly one address"; return -1; }
      if (!bz_is_ipv4 (rd[0])) { *why = "A RDATA is not a dotted-quad IPv4 address"; return -1; }
      return 0;
    case BD_T_AAAA:
      if (nrd != 1) { *why = "AAAA needs exactly one address"; return -1; }
      if (!bz_is_ipv6 (rd[0])) { *why = "AAAA RDATA is not a valid IPv6 address"; return -1; }
      return 0;
    case BD_T_MX:
      if (nrd != 2) { *why = "MX needs: preference exchange"; return -1; }
      if (!bz_is_u16 (rd[0])) { *why = "MX preference not a uint16"; return -1; }
      return bz_check_host (rd[1], why);
    case BD_T_TXT:
      if (nrd < 1) { *why = "TXT needs at least one string"; return -1; }
      for (int i = 0; i < nrd; i++)
        {
          size_t l = strlen (rd[i]);
          if (rd[i][0] != '"' || l < 2 || rd[i][l - 1] != '"')
            { *why = "TXT RDATA must be quoted character-string(s)"; return -1; }
          if (l - 2 > 255) { *why = "TXT character-string exceeds 255 octets"; return -1; }
        }
      return 0;
    case BD_T_SVCB:
    case BD_T_HTTPS:
      /* SVCB/HTTPS: priority target [params]; minimal shape check. */
      if (nrd < 2) { *why = "SVCB/HTTPS needs: priority target"; return -1; }
      if (!bz_is_u16 (rd[0])) { *why = "SVCB/HTTPS priority not a uint16"; return -1; }
      return bz_check_host (rd[1], why);
    default:
      /* Unknown / not-shape-validated type: accept generically like
       * named-checkzone tolerates types it has no parser for. */
      return 0;
    }
}

typedef struct {
  char (*owner)[256];
  unsigned char *has_cname;
  unsigned char *has_dname;
  int n;
  int cap;
} bz_owner_track_t;

static void
bz_owner_track_free (bz_owner_track_t *t)
{
  if (!t) return;
  free (t->owner);
  free (t->has_cname);
  free (t->has_dname);
  memset (t, 0, sizeof *t);
}

static int
bz_owner_track_grow (bz_owner_track_t *t)
{
  int ncap = t->cap ? t->cap * 2 : 64;
  char (*owner)[256] = calloc ((size_t) ncap, sizeof *owner);
  unsigned char *has_cname = calloc ((size_t) ncap, sizeof *has_cname);
  unsigned char *has_dname = calloc ((size_t) ncap, sizeof *has_dname);
  if (!owner || !has_cname || !has_dname)
    {
      free (owner);
      free (has_cname);
      free (has_dname);
      return -1;
    }
  if (t->n > 0)
    {
      memcpy (owner, t->owner, (size_t) t->n * sizeof *owner);
      memcpy (has_cname, t->has_cname, (size_t) t->n);
      memcpy (has_dname, t->has_dname, (size_t) t->n);
    }
  free (t->owner);
  free (t->has_cname);
  free (t->has_dname);
  t->owner = owner;
  t->has_cname = has_cname;
  t->has_dname = has_dname;
  t->cap = ncap;
  return 0;
}

static int
bz_owner_track_rr (bz_owner_track_t *t, const char *owner, uint16_t type,
                   const char **why)
{
  if (type != BD_T_CNAME && type != BD_T_DNAME) return 0;
  for (int i = 0; i < t->n; i++)
    {
      if (strcmp (t->owner[i], owner)) continue;
      if ((type == BD_T_CNAME && t->has_dname[i])
          || (type == BD_T_DNAME && t->has_cname[i]))
        {
          *why = "DNAME and CNAME cannot share an owner";
          return -1;
        }
      if (type == BD_T_CNAME) t->has_cname[i] = 1;
      else t->has_dname[i] = 1;
      return 0;
    }
  if (t->n >= t->cap && bz_owner_track_grow (t) < 0)
    {
      *why = "out of memory while checking owner type constraints";
      return -1;
    }
  snprintf (t->owner[t->n], sizeof t->owner[t->n], "%s", owner);
  if (type == BD_T_CNAME) t->has_cname[t->n] = 1;
  else t->has_dname[t->n] = 1;
  t->n++;
  return 0;
}

/* SRV is not in bd_type_from_name's table (it serves no query path), so
 * checkzone detects it by name and validates its shape inline below. */

/* Forward decl for $INCLUDE recursion. */
static int bz_parse_file (const char *path, const char *origin_in,
                          int depth, int *saw_soa, int *saw_ns,
                          unsigned long *serial_out,
                          bz_owner_track_t *owners);

/* Parse one master file. Returns 0 ok, nonzero on first hard error
 * (diagnostic already printed). saw_soa/saw_ns/serial accumulate across
 * $INCLUDE so the caller can enforce the one-SOA/one-NS invariants. */
static int
bz_parse_file (const char *path, const char *origin_in, int depth,
               int *saw_soa, int *saw_ns, unsigned long *serial_out,
               bz_owner_track_t *owners)
{
  if (depth > BZ_INC_DEPTH)
    {
      builtin_error ("%s: $INCLUDE nesting exceeds depth cap of %d", path, BZ_INC_DEPTH);
      return -1;
    }
  FILE *f = fopen (path, "r");
  if (!f) { builtin_error ("%s: %s", path, strerror (errno)); return -1; }

  char origin[256];
  snprintf (origin, sizeof origin, "%s", (origin_in && *origin_in) ? origin_in : ".");
  char prev_owner[256] = "";

  char raw[BZ_MAXLINE];
  char logical[BZ_MAXLINE];
  int lineno = 0;
  int rc = 0;

  while (fgets (raw, sizeof raw, f))
    {
      lineno++;
      int start_line = lineno;
      int inherited_owner = raw[0] == ' ' || raw[0] == '\t';
      /* strip trailing newline */
      raw[strcspn (raw, "\r\n")] = '\0';
      bz_strip_comment (raw);

      /* Multi-line '()' grouping: accumulate until parens balance. */
      logical[0] = '\0';
      size_t llen = 0;
      int paren = 0;
      const char *src = raw;
      for (;;)
        {
          for (const char *q = src; *q; q++)
            { if (*q == '(') paren++; else if (*q == ')') paren--; }
          size_t sl = strlen (src);
          if (llen + sl + 2 >= sizeof logical) { builtin_error ("%s:%d: line too long", path, start_line); rc = -1; break; }
          if (llen) logical[llen++] = ' ';
          memcpy (logical + llen, src, sl + 1);
          llen += sl;
          if (paren <= 0) break;
          if (!fgets (raw, sizeof raw, f))
            { builtin_error ("%s:%d: unbalanced '(' at end of file", path, start_line); rc = -1; break; }
          lineno++;
          raw[strcspn (raw, "\r\n")] = '\0';
          bz_strip_comment (raw);
          src = raw;
        }
      if (rc) break;
      if (paren < 0) { builtin_error ("%s:%d: unbalanced ')'", path, start_line); rc = -1; break; }

      /* Drop the now-meaningless '(' ')' grouping chars. */
      for (char *q = logical; *q; q++) if (*q == '(' || *q == ')') *q = ' ';

      char *tok[BZ_MAXTOK];
      int nt = bz_tokenize (logical, tok, BZ_MAXTOK);
      if (nt == 0) continue;   /* blank / comment-only */

      /* Directives. */
      if (tok[0][0] == '$')
        {
          if (strcasecmp (tok[0], "$ORIGIN") == 0)
            {
              if (nt != 2) { builtin_error ("%s:%d: $ORIGIN needs one name", path, start_line); rc = -1; break; }
              const char *why = NULL;
              if (bz_check_owner (tok[1], &why)) { builtin_error ("%s:%d: $ORIGIN: %s", path, start_line, why); rc = -1; break; }
              snprintf (origin, sizeof origin, "%s", tok[1]);
              continue;
            }
          if (strcasecmp (tok[0], "$TTL") == 0)
            {
              if (nt != 2 || !bz_is_ttl (tok[1])) { builtin_error ("%s:%d: $TTL needs a valid TTL", path, start_line); rc = -1; break; }
              continue;
            }
          if (strcasecmp (tok[0], "$INCLUDE") == 0)
            {
              if (nt < 2) { builtin_error ("%s:%d: $INCLUDE needs a path", path, start_line); rc = -1; break; }
              const char *inc_origin = (nt >= 3) ? tok[2] : origin;
              if (bz_parse_file (tok[1], inc_origin, depth + 1, saw_soa, saw_ns,
                                 serial_out, owners))
                { rc = -1; break; }
              continue;
            }
          builtin_error ("%s:%d: unknown directive %s", path, start_line, tok[0]);
          rc = -1; break;
        }

      /* Record line: [owner] [TTL] [CLASS] TYPE rdata...
       * If the line begins with leading whitespace in the raw text, the
       * owner is inherited from the previous record. */
      int idx = 0;
      char owner[256];
      const char *why = NULL;
      if (inherited_owner)
        {
          /* Owner inherited from previous record. */
          if (!prev_owner[0]) { builtin_error ("%s:%d: record has no owner and no prior owner to inherit", path, start_line); rc = -1; break; }
          snprintf (owner, sizeof owner, "%s", prev_owner);
        }
      else
        {
          snprintf (owner, sizeof owner, "%s", tok[0]);
          if (bz_check_owner (owner, &why)) { builtin_error ("%s:%d: %s", path, start_line, why); rc = -1; break; }
          snprintf (prev_owner, sizeof prev_owner, "%s", owner);
          idx = 1;
        }

      /* Optional TTL. */
      if (idx < nt && bz_is_ttl (tok[idx])) idx++;
      /* Optional CLASS (only IN / CH supported). */
      if (idx < nt && (strcasecmp (tok[idx], "IN") == 0 || strcasecmp (tok[idx], "CH") == 0)) idx++;
      /* TTL may also appear after class. */
      if (idx < nt && bz_is_ttl (tok[idx])) idx++;

      if (idx >= nt) { builtin_error ("%s:%d: missing RR type", path, start_line); rc = -1; break; }

      uint16_t type = 0;
      int is_srv = 0;
      if (strcasecmp (tok[idx], "SRV") == 0) { is_srv = 1; }
      else if (bd_type_from_name (tok[idx], &type) != 0)
        {
          /* Unknown type name: accept generically (named tolerance) but
           * require it look like an RR type token (uppercase alnum). */
          for (const char *c = tok[idx]; *c; c++)
            if (!isalnum ((unsigned char) *c))
              { builtin_error ("%s:%d: unrecognized RR type '%s'", path, start_line, tok[idx]); rc = -1; break; }
          if (rc) break;
          /* generic accept; advance and continue */
          idx++;
          continue;
        }
      idx++;

      char **rd = &tok[idx];
      int nrd = nt - idx;

      if (is_srv)
        {
          if (nrd != 4) { builtin_error ("%s:%d: SRV needs: priority weight port target", path, start_line); rc = -1; break; }
          if (!bz_is_u16 (rd[0]) || !bz_is_u16 (rd[1]) || !bz_is_u16 (rd[2]))
            { builtin_error ("%s:%d: SRV priority/weight/port must be uint16", path, start_line); rc = -1; break; }
          if (bz_check_host (rd[3], &why)) { builtin_error ("%s:%d: SRV target: %s", path, start_line, why); rc = -1; break; }
        }
      else
        {
          if (bz_check_rdata (type, rd, nrd, &why))
            { builtin_error ("%s:%d: %s record: %s", path, start_line, bd_type_name (type), why); rc = -1; break; }
          if (type == BD_T_CNAME || type == BD_T_DNAME)
            {
              char fq_owner[512], canon_owner[256];
              if (bz_qualify (owner, origin, fq_owner, sizeof fq_owner) < 0
                  || bd_canon_owner (fq_owner, canon_owner, sizeof canon_owner) < 0)
                { builtin_error ("%s:%d: bad owner name", path, start_line); rc = -1; break; }
              if (bz_owner_track_rr (owners, canon_owner, type, &why))
                { builtin_error ("%s:%d: %s", path, start_line, why); rc = -1; break; }
            }
          if (type == BD_T_SOA)
            {
              if (*saw_soa)
                { builtin_error ("%s:%d: more than one SOA record", path, start_line); rc = -1; break; }
              if (*saw_ns)
                { builtin_error ("%s:%d: SOA must be the first authoritative record", path, start_line); rc = -1; break; }
              *saw_soa = 1;
              *serial_out = strtoul (rd[2], NULL, 10);
            }
          else if (type == BD_T_NS)
            {
              if (!*saw_soa)
                { builtin_error ("%s:%d: NS record before SOA (zone has no SOA as first record)", path, start_line); rc = -1; break; }
              *saw_ns = 1;
            }
          else
            {
              if (!*saw_soa)
                { builtin_error ("%s:%d: record before SOA (SOA must be first authoritative record)", path, start_line); rc = -1; break; }
            }
        }
    }

  fclose (f);
  return rc;
}

static int
bd_checkzone_cmd (WORD_LIST *args)
{
  const char *origin = NULL;
  const char *path = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-o") == 0)
        { if (!p->next) { builtin_error ("checkzone -o needs ORIGIN"); return EX_USAGE; }
          p = p->next; origin = p->word->word; }
      else if (w[0] == '-' && w[1] != '\0')
        { builtin_error ("checkzone: unknown flag %s", w); return EX_USAGE; }
      else if (!path) path = w;
      else { builtin_error ("checkzone: extra arg %s", w); return EX_USAGE; }
    }
  if (!path) { builtin_error ("checkzone: PATH required"); return EX_USAGE; }

  int saw_soa = 0, saw_ns = 0;
  unsigned long serial = 0;
  bz_owner_track_t owners = { 0 };
  int parse_rc = bz_parse_file (path, origin, 0, &saw_soa, &saw_ns, &serial, &owners);
  bz_owner_track_free (&owners);
  if (parse_rc)
    return EXECUTION_FAILURE;
  if (!saw_soa)
    { builtin_error ("%s: zone has no SOA record", path); return EXECUTION_FAILURE; }
  if (!saw_ns)
    { builtin_error ("%s: zone has no NS record", path); return EXECUTION_FAILURE; }

  printf ("zone %s: loaded serial %lu\n", (origin && *origin) ? origin : ".", serial);
  printf ("OK\n");
  return EXECUTION_SUCCESS;
}

/* ---- checkconf ----------------------------------------------------- */

/* Known bash-os DNS config keys (resolver.conf / authoritative.conf flat
 * key=value vocabulary, design §4/§5). Each carries a value-shape kind. */
enum { BC_V_ADDRPORT, BC_V_CIDRLIST, BC_V_HOSTLIST, BC_V_U16, BC_V_U32,
       BC_V_BOOL, BC_V_HEX, BC_V_PATH, BC_V_NAME, BC_V_BYTES, BC_V_STR };

static const struct { const char *key; int kind; } bc_keys[] = {
  { "enabled",           BC_V_BOOL },
  { "listen",            BC_V_ADDRPORT },
  { "port",              BC_V_U16 },
  { "origin",            BC_V_NAME },
  { "forward",           BC_V_ADDRPORT },
  { "allow",             BC_V_CIDRLIST },
  { "allow-query",       BC_V_CIDRLIST },
  { "allow-transfer",    BC_V_CIDRLIST },
  { "allow-update",      BC_V_CIDRLIST },
  { "allow-recursion",   BC_V_CIDRLIST },
  { "also-notify",       BC_V_ADDRPORT },
  { "slave-zone",        BC_V_STR },
  { "tsig-key",          BC_V_STR },
  { "tsig-keys",         BC_V_PATH },
  { "require-tsig",      BC_V_BOOL },
  { "transfer-key",      BC_V_NAME },
  { "notify",            BC_V_BOOL },
  { "recursion",         BC_V_BOOL },
  { "nsec3-salt",        BC_V_HEX },
  { "nsec3-iterations",  BC_V_U16 },
  { "max-cache-size",    BC_V_BYTES },
  { "cache-size",        BC_V_BYTES },
  { "ratelimit-qps",     BC_V_U32 },
  { "case-randomization", BC_V_BOOL },
  { "rrl-responses-per-second", BC_V_U32 },
  { "rrl-window",        BC_V_U32 },
  { "rrl-slip",          BC_V_U32 },
  { "edns-buffer-size",  BC_V_U16 },
  { "zones-dir",         BC_V_PATH },
  { "zone-file",         BC_V_PATH },
  { "directory",         BC_V_PATH },
  { "trust-anchor",      BC_V_PATH },
  { "root-hints",        BC_V_PATH },
  { "querylog",          BC_V_BOOL },
  { "dnssec",            BC_V_BOOL },
  { "sign-key",          BC_V_PATH },
  { "sign-key-wrapped",  BC_V_PATH },
  { "sign-kek-file",     BC_V_PATH },
  { "sign-kek-keyring",  BC_V_STR },
  { "sign-kek-pass",     BC_V_BOOL },
  { "nsec3",             BC_V_BOOL },
  { "primary",           BC_V_ADDRPORT },
  { "zone",              BC_V_NAME },
  { NULL, 0 }
};

static int bc_is_bool (const char *s)
{ return s && (!strcasecmp(s,"yes")||!strcasecmp(s,"no")||!strcasecmp(s,"true")
               ||!strcasecmp(s,"false")||!strcasecmp(s,"on")||!strcasecmp(s,"off")
               ||!strcmp(s,"1")||!strcmp(s,"0")); }

/* ADDR or ADDR:PORT or [v6]:PORT — accept the host's inet_pton view. */
static int bc_is_addrport (const char *s)
{
  if (!s || !*s) return 0;
  char buf[256];
  snprintf (buf, sizeof buf, "%s", s);
  char *host = buf, *port = NULL;
  if (buf[0] == '[')
    { host = buf + 1; char *e = strchr (host, ']'); if (!e) return 0; *e = '\0';
      if (e[1] == ':') port = e + 2; else if (e[1]) return 0; }
  else
    { char *c = strrchr (buf, ':');
      /* a lone ':' with a v4-looking head means host:port; bare v6 has many ':' */
      if (c && strchr (buf, ':') == c) { *c = '\0'; port = c + 1; } }
  if (port && !bz_is_u16 (port)) return 0;
  return bz_is_ipv4 (host) || bz_is_ipv6 (host);
}

static int bc_is_cidr (const char *s)
{
  char buf[128];
  if (!s || strlen (s) >= sizeof buf) return 0;
  snprintf (buf, sizeof buf, "%s", s);
  char *slash = strchr (buf, '/');
  long bits = -1;
  if (slash) { *slash = '\0'; char *e; bits = strtol (slash + 1, &e, 10); if (*e) return 0; }
  if (bz_is_ipv4 (buf)) return bits < 0 || (bits >= 0 && bits <= 32);
  if (bz_is_ipv6 (buf)) return bits < 0 || (bits >= 0 && bits <= 128);
  return 0;
}

/* Comma- or space-separated list; every element must pass `elem`. */
static int bc_check_list (const char *val, int (*elem)(const char *))
{
  char buf[1024];
  if (strlen (val) >= sizeof buf) return 0;
  snprintf (buf, sizeof buf, "%s", val);
  if (!strcasecmp (buf, "none") || !strcasecmp (buf, "any") || buf[0] == '\0') return 1;
  int seen = 0;
  for (char *t = strtok (buf, ", \t"); t; t = strtok (NULL, ", \t"))
    { if (!elem (t)) return 0; seen = 1; }
  return seen;
}

static int bc_is_bytes (const char *s)
{
  if (!s || !*s) return 0;
  char *e = NULL;
  strtoull (s, &e, 10);
  if (e == s) return 0;
  if (*e == '\0') return 1;
  char u = (char) tolower ((unsigned char) *e);
  return (u=='k'||u=='m'||u=='g') && e[1] == '\0';
}

static int
bc_check_value (int kind, const char *val)
{
  const char *why;
  switch (kind)
    {
    case BC_V_ADDRPORT: return bc_is_addrport (val);
    case BC_V_CIDRLIST: return bc_check_list (val, bc_is_cidr);
    case BC_V_HOSTLIST: return bc_check_list (val, bc_is_addrport);
    case BC_V_U16:      return bz_is_u16 (val);
    case BC_V_U32:      return bz_is_u32 (val);
    case BC_V_BOOL:     return bc_is_bool (val);
    case BC_V_BYTES:    return bc_is_bytes (val);
    case BC_V_PATH:     return val && val[0] == '/';
    case BC_V_NAME:     return bz_check_owner (val, &why) == 0;
    case BC_V_HEX:
      if (!val || !*val) return 0;
      if (!strcasecmp (val, "none") || !strcmp (val, "-")) return 1;
      for (const char *c = val; *c; c++) if (!isxdigit ((unsigned char) *c)) return 0;
      return 1;
    case BC_V_STR:      return val && *val;
    default:            return 0;
    }
}

static int
bd_checkconf_cmd (WORD_LIST *args)
{
  const char *path = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (!path) path = w;
      else { builtin_error ("checkconf: extra arg %s", w); return EX_USAGE; }
    }
  if (!path) { builtin_error ("checkconf: PATH required"); return EX_USAGE; }

  FILE *f = fopen (path, "r");
  if (!f) { builtin_error ("%s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }

  char line[BZ_MAXLINE];
  int lineno = 0, nkeys = 0, rc = EXECUTION_SUCCESS;
  while (fgets (line, sizeof line, f))
    {
      lineno++;
      line[strcspn (line, "\r\n")] = '\0';
      char *p = line;
      while (*p == ' ' || *p == '\t') p++;
      if (*p == '\0' || *p == '#' || *p == ';') continue;

      char *eq = strchr (p, '=');
      if (!eq) { builtin_error ("%s:%d: not a 'key = value' line", path, lineno); rc = EXECUTION_FAILURE; break; }
      /* split key */
      char *kend = eq;
      while (kend > p && (kend[-1] == ' ' || kend[-1] == '\t')) kend--;
      *kend = '\0';
      char *val = eq + 1;
      while (*val == ' ' || *val == '\t') val++;
      char *vend = val + strlen (val);
      while (vend > val && (vend[-1] == ' ' || vend[-1] == '\t')) vend--;
      *vend = '\0';

      if (*p == '\0') { builtin_error ("%s:%d: empty key", path, lineno); rc = EXECUTION_FAILURE; break; }

      int found = -1;
      for (int i = 0; bc_keys[i].key; i++)
        if (strcasecmp (p, bc_keys[i].key) == 0) { found = i; break; }
      if (found < 0)
        { builtin_error ("%s:%d: unknown config key '%s'", path, lineno, p); rc = EXECUTION_FAILURE; break; }
      if (*val == '\0')
        { builtin_error ("%s:%d: key '%s' has empty value", path, lineno, p); rc = EXECUTION_FAILURE; break; }
      if (!bc_check_value (bc_keys[found].kind, val))
        { builtin_error ("%s:%d: key '%s' has malformed value '%s'", path, lineno, p, val); rc = EXECUTION_FAILURE; break; }
      nkeys++;
    }
  fclose (f);
  if (rc == EXECUTION_SUCCESS)
    printf ("OK (%d directive%s)\n", nkeys, nkeys == 1 ? "" : "s");
  return rc;
}

/* ====================================================================
 * signzone — offline DNSSEC zone signer (DNS 6.3).
 *
 * NO daemon, NO socket. `dns signzone ZONEFILE` loads an RFC 1035
 * master file, signs every RRset with the zone keys found in -K KEYDIR
 * (BIND `K<zone>.+<alg>+<tag>.{key,private}` convention), emits NSEC (or
 * NSEC3 with --nsec3) denial-of-existence chains, and writes the signed
 * zone to stdout.
 *
 * Crypto is delegated to the in-binary `crypto` builtin via the
 * SAME `bash -c 'builtin ...'` trampoline that bd_run_verifier /
 * bd_run_hash_bytes use for the validator — dns does not link the
 * mbedtls/monocypher C primitives in-process; it shells to crypto's
 * rsa-pkcs1-sign / ecdsa-p256-sign / ecdsa-p384-sign / ed25519-sign
 * verbs. The signing input is the EXACT byte string bd_build_signed_msg
 * produces for the validator, so signing is the structural inverse of
 * verification.
 *
 * --self-check re-runs every produced RRSIG through bd_verify_rrset
 * (the validator) against the matching DNSKEY before emitting the zone;
 * any failure aborts with EXECUTION_FAILURE. This is the in-process
 * sign-then-verify oracle the design mandates.
 * ==================================================================== */

/* Parse a BIND-style TTL/uint32 (plain seconds or 1w2d3h4m5s units). */
static uint32_t
bz_parse_ttl (const char *s)
{
  if (!s || !*s) return 0;
  char *end = NULL;
  unsigned long long v = strtoull (s, &end, 10);
  if (end && *end == '\0') return (uint32_t) v;
  /* unit form */
  uint64_t total = 0;
  const char *p = s;
  while (*p)
    {
      char *e = NULL;
      unsigned long long g = strtoull (p, &e, 10);
      if (e == p) break;
      char u = (char) tolower ((unsigned char) *e);
      uint64_t mult = 1;
      switch (u)
        { case 'w': mult = 604800; break; case 'd': mult = 86400; break;
          case 'h': mult = 3600; break;   case 'm': mult = 60; break;
          case 's': mult = 1; break;      default: return (uint32_t) total; }
      total += g * mult;
      p = e + 1;
    }
  return (uint32_t) total;
}

/* Resolve a master-file owner/target name against the current $ORIGIN:
 *   "@"             -> origin
 *   absolute "a.b." -> as-is (dot stripped by canonicalisation later)
 *   relative "www"  -> "www." + origin
 * Output is suitable for bd_canon_owner / bd_name_to_wire. */
static int
bz_qualify (const char *name, const char *origin, char *out, size_t out_sz)
{
  if (!name || !*name) return -1;
  if (strcmp (name, "@") == 0)
    { if (strlen (origin) + 1 > out_sz) return -1; strcpy (out, origin); return 0; }
  size_t l = strlen (name);
  if (name[l - 1] == '.')
    { if (l + 1 > out_sz) return -1; strcpy (out, name); return 0; }
  /* relative — append origin */
  const char *org = (origin && *origin) ? origin : ".";
  if (strcmp (org, ".") == 0)
    { int n = snprintf (out, out_sz, "%s.", name); return (n > 0 && (size_t) n < out_sz) ? 0 : -1; }
  int n = snprintf (out, out_sz, "%s.%s", name, org);
  return (n > 0 && (size_t) n < out_sz) ? 0 : -1;
}

/* RDATA wire-form builder for the master-file subset, used to load zone
 * records into bd_rr_t for signing (the validator path builds these from
 * the wire; here we build them from text). Returns rdata length or -1.
 * Embedded names are canonicalised (lowercased, root-terminated) per
 * RFC 4034 §6.2, matching bd_collect_rrs. */
static int
bz_build_rdata (uint16_t type, const char *origin, char *rd[], int nrd,
                unsigned char *out, size_t out_sz)
{
  size_t off = 0;
#define BZ_NEED(n) do { if (off + (n) > out_sz) return -1; } while (0)
  if (nrd >= 3 && strcmp (rd[0], "\\#") == 0)
    {
      char *end = NULL;
      unsigned long want = strtoul (rd[1], &end, 10);
      if (!end || *end || want > out_sz) return -1;
      char hex[4096];
      hex[0] = '\0';
      for (int i = 2; i < nrd; i++)
        {
          size_t cur = strlen (hex), add = strlen (rd[i]);
          if (cur + add + 1 > sizeof hex) return -1;
          memcpy (hex + cur, rd[i], add + 1);
        }
      size_t got = 0;
      if (bd_unhex (hex, out, out_sz, &got) < 0 || got != want) return -1;
      return (int) got;
    }
  switch (type)
    {
    case BD_T_A:
      {
        struct in_addr a;
        if (nrd != 1 || inet_pton (AF_INET, rd[0], &a) != 1) return -1;
        BZ_NEED (4);
        memcpy (out, &a.s_addr, 4);
        return 4;
      }
    case BD_T_AAAA:
      {
        struct in6_addr a;
        if (nrd != 1 || inet_pton (AF_INET6, rd[0], &a) != 1) return -1;
        BZ_NEED (16);
        memcpy (out, a.s6_addr, 16);
        return 16;
      }
    case BD_T_NS:
    case BD_T_CNAME:
    case BD_T_DNAME:
    case BD_T_PTR:
      {
        if (nrd != 1) return -1;
        char fq[512];
        if (bz_qualify (rd[0], origin, fq, sizeof fq) < 0) return -1;
        int wn = bd_name_to_wire (fq, out, out_sz);
        return wn;
      }
    case BD_T_MX:
      {
        if (nrd != 2) return -1;
        unsigned long pref = strtoul (rd[0], NULL, 10);
        BZ_NEED (2);
        out[0] = (unsigned char) (pref >> 8);
        out[1] = (unsigned char) (pref & 0xff);
        off = 2;
        char fq[512];
        if (bz_qualify (rd[1], origin, fq, sizeof fq) < 0) return -1;
        int wn = bd_name_to_wire (fq, out + off, out_sz - off);
        if (wn < 0) return -1;
        return (int) off + wn;
      }
    case BD_T_TXT:
      {
        if (nrd < 1) return -1;
        for (int i = 0; i < nrd; i++)
          {
            const char *s = rd[i];
            size_t l = strlen (s);
            /* Strip surrounding quotes if present. */
            if (l >= 2 && s[0] == '"' && s[l - 1] == '"') { s++; l -= 2; }
            if (l > 255) return -1;
            BZ_NEED (1 + l);
            out[off++] = (unsigned char) l;
            memcpy (out + off, s, l);
            off += l;
          }
        return (int) off;
      }
    case BD_T_SOA:
      {
        if (nrd != 7) return -1;
        char fq[512];
        if (bz_qualify (rd[0], origin, fq, sizeof fq) < 0) return -1;
        int wn = bd_name_to_wire (fq, out + off, out_sz - off);
        if (wn < 0) return -1; off += wn;
        if (bz_qualify (rd[1], origin, fq, sizeof fq) < 0) return -1;
        wn = bd_name_to_wire (fq, out + off, out_sz - off);
        if (wn < 0) return -1; off += wn;
        BZ_NEED (20);
        for (int i = 0; i < 5; i++)
          {
            uint32_t v = bz_parse_ttl (rd[2 + i]);
            out[off++] = (unsigned char) (v >> 24);
            out[off++] = (unsigned char) (v >> 16);
            out[off++] = (unsigned char) (v >> 8);
            out[off++] = (unsigned char) (v & 0xff);
          }
        return (int) off;
      }
    default:
      return -1;
#undef BZ_NEED
    }
}

/* ---- zone loader: master file -> bd_rr_t[] ------------------------- */

#define SZ_RR_MAX 4096

/* Load the master file at PATH into rrs[] (capacity rr_max), resolving
 * $ORIGIN/$TTL and relative names. The apex origin is taken from -o
 * ORIGIN (origin_in) when given, else the first $ORIGIN, else ".".
 * Returns the RR count or -1 on parse error (diagnostic printed). The
 * resolved apex is copied into apex_out. */
static int
sz_load_zone (const char *path, const char *origin_in,
              bd_rr_t *rrs, int rr_max, char *apex_out, size_t apex_sz)
{
  FILE *f = fopen (path, "r");
  if (!f) { builtin_error ("signzone: %s: %s", path, strerror (errno)); return -1; }

  char origin[256];
  snprintf (origin, sizeof origin, "%s", (origin_in && *origin_in) ? origin_in : ".");
  int apex_set = (origin_in && *origin_in);
  char prev_owner[256] = "";
  uint32_t default_ttl = 3600;

  char raw[BZ_MAXLINE], logical[BZ_MAXLINE];
  int lineno = 0, n = 0, rc = 0;

  while (fgets (raw, sizeof raw, f))
    {
      lineno++;
      int start_line = lineno;
      /* Leading whitespace on the FIRST physical line of a record means
       * the owner is inherited from the previous record (RFC 1035 §5.1).
       * This is the authoritative signal — checked before de-commenting. */
      int leading_ws = (raw[0] == ' ' || raw[0] == '\t');
      raw[strcspn (raw, "\r\n")] = '\0';
      bz_strip_comment (raw);

      logical[0] = '\0';
      size_t llen = 0; int paren = 0;
      const char *src = raw;
      for (;;)
        {
          for (const char *q = src; *q; q++)
            { if (*q == '(') paren++; else if (*q == ')') paren--; }
          size_t sl = strlen (src);
          if (llen + sl + 2 >= sizeof logical) { builtin_error ("signzone: %s:%d: line too long", path, start_line); rc = -1; break; }
          if (llen) logical[llen++] = ' ';
          memcpy (logical + llen, src, sl + 1); llen += sl;
          if (paren <= 0) break;
          if (!fgets (raw, sizeof raw, f)) { builtin_error ("signzone: %s:%d: unbalanced '('", path, start_line); rc = -1; break; }
          lineno++; raw[strcspn (raw, "\r\n")] = '\0'; bz_strip_comment (raw); src = raw;
        }
      if (rc) break;
      for (char *q = logical; *q; q++) if (*q == '(' || *q == ')') *q = ' ';

      char *tok[BZ_MAXTOK];
      int nt = bz_tokenize (logical, tok, BZ_MAXTOK);
      if (nt == 0) continue;

      if (tok[0][0] == '$')
        {
          if (strcasecmp (tok[0], "$ORIGIN") == 0 && nt == 2)
            { snprintf (origin, sizeof origin, "%s", tok[1]);
              if (!apex_set) apex_set = 1; continue; }
          if (strcasecmp (tok[0], "$TTL") == 0 && nt == 2)
            { default_ttl = bz_parse_ttl (tok[1]); continue; }
          builtin_error ("signzone: %s:%d: unsupported directive %s", path, start_line, tok[0]);
          rc = -1; break;
        }

      int idx = 0;
      char owner[256];
      /* Owner is inherited when the line is indented (leading_ws). When
       * not indented, tok[0] is the owner — even if it happens to be a
       * type/class name spelled in lowercase (e.g. owner "txt"), because
       * RFC 1035 takes the first column literally. */
      int first_is_field = leading_ws;
      if (first_is_field)
        {
          if (!prev_owner[0]) { builtin_error ("signzone: %s:%d: no owner to inherit", path, start_line); rc = -1; break; }
          snprintf (owner, sizeof owner, "%s", prev_owner);
        }
      else
        { snprintf (owner, sizeof owner, "%s", tok[0]);
          snprintf (prev_owner, sizeof prev_owner, "%s", owner); idx = 1; }

      uint32_t ttl = default_ttl;
      if (idx < nt && bz_is_ttl (tok[idx])) { ttl = bz_parse_ttl (tok[idx]); idx++; }
      if (idx < nt && (strcasecmp (tok[idx], "IN") == 0 || strcasecmp (tok[idx], "CH") == 0)) idx++;
      if (idx < nt && bz_is_ttl (tok[idx])) { ttl = bz_parse_ttl (tok[idx]); idx++; }

      if (idx >= nt) { builtin_error ("signzone: %s:%d: missing RR type", path, start_line); rc = -1; break; }
      uint16_t type = 0;
      if (bd_type_from_name (tok[idx], &type) != 0)
        { builtin_error ("signzone: %s:%d: unsupported RR type '%s'", path, start_line, tok[idx]); rc = -1; break; }
      idx++;

      char **rd = &tok[idx];
      int nrd = nt - idx;

      /* Resolve owner against origin. */
      char fq_owner[512];
      if (bz_qualify (owner, origin, fq_owner, sizeof fq_owner) < 0)
        { builtin_error ("signzone: %s:%d: bad owner name", path, start_line); rc = -1; break; }

      /* First SOA owner is the apex when -o was not supplied. */
      if (type == BD_T_SOA && !apex_set)
        { snprintf (origin, sizeof origin, "%s", fq_owner); apex_set = 1; }

      unsigned char rdata[2048];
      int rdlen;
      if (type == BD_T_DNSKEY)
        {
          /* DNSKEY flags proto alg base64 — fold base64 across tokens. */
          if (nrd < 4) { builtin_error ("signzone: %s:%d: malformed DNSKEY", path, start_line); rc = -1; break; }
          unsigned long flags = strtoul (rd[0], NULL, 10);
          unsigned long proto = strtoul (rd[1], NULL, 10);
          unsigned long alg   = strtoul (rd[2], NULL, 10);
          char b64[4096]; b64[0] = '\0';
          for (int i = 3; i < nrd; i++)
            { if (strlen (b64) + strlen (rd[i]) + 1 >= sizeof b64) { rc = -1; break; } strcat (b64, rd[i]); }
          if (rc) { builtin_error ("signzone: %s:%d: DNSKEY too long", path, start_line); break; }
          unsigned char pk[2048]; size_t pklen = 0;
          if (bd_unb64 (b64, pk, sizeof pk, &pklen) < 0)
            { builtin_error ("signzone: %s:%d: bad DNSKEY base64", path, start_line); rc = -1; break; }
          rdata[0] = (unsigned char) (flags >> 8); rdata[1] = (unsigned char) (flags & 0xff);
          rdata[2] = (unsigned char) proto; rdata[3] = (unsigned char) alg;
          if (4 + pklen > sizeof rdata) { rc = -1; break; }
          memcpy (rdata + 4, pk, pklen);
          rdlen = (int) (4 + pklen);
        }
      else
        {
          rdlen = bz_build_rdata (type, origin, rd, nrd, rdata, sizeof rdata);
          if (rdlen < 0)
            { builtin_error ("signzone: %s:%d: bad %s RDATA", path, start_line, bd_type_name (type)); rc = -1; break; }
        }

      if (n >= rr_max) { builtin_error ("signzone: too many records (max %d)", rr_max); rc = -1; break; }
      bd_rr_t *r = &rrs[n];
      memset (r, 0, sizeof *r);
      char canon[256];
      if (bd_canon_owner (fq_owner, canon, sizeof canon) < 0) { rc = -1; break; }
      for (int j = 0; j < n; j++)
        if (!strcmp (rrs[j].owner, canon)
            && ((type == BD_T_CNAME && rrs[j].type == BD_T_DNAME)
                || (type == BD_T_DNAME && rrs[j].type == BD_T_CNAME)))
          {
            builtin_error ("signzone: %s:%d: DNAME and CNAME cannot share owner %s",
                           path, start_line, canon);
            rc = -1;
            break;
          }
      if (rc) break;
      strncpy (r->owner, canon, sizeof r->owner - 1);
      r->type = type; r->cls = 1; r->ttl = ttl;
      memcpy (r->rdata, rdata, (size_t) rdlen);
      r->rdata_len = (uint16_t) rdlen;
      n++;
    }
  fclose (f);
  if (rc) return -1;
  if (!apex_set) { builtin_error ("signzone: no $ORIGIN/-o ORIGIN and no SOA to derive apex"); return -1; }
  snprintf (apex_out, apex_sz, "%s", origin);
  /* Canonicalise apex too. */
  char ac[256];
  if (bd_canon_owner (origin, ac, sizeof ac) < 0) return -1;
  snprintf (apex_out, apex_sz, "%s", ac);
  return n;
}

/* ---- key loader: K<zone>.+<alg>+<tag>.{key,private} ---------------- */

typedef struct {
  char     owner[256];      /* canonical apex */
  uint16_t flags;           /* 256 ZSK / 257 KSK */
  uint8_t  algorithm;
  uint16_t key_tag;
  unsigned char dnskey_rdata[2048];   /* flags||proto||alg||pubkey */
  size_t        dnskey_rdlen;
  /* private material, as lowercase hex ready for crypto verbs */
  char     priv_scalar[8192];  /* ECDSA/EdDSA raw scalar/seed hex */
  char     rsa_n[8192], rsa_e[256], rsa_d[8192], rsa_p[8192], rsa_q[8192];
} sz_key_t;

#define SZ_KEY_MAX 8

/* base64 one field value into hex. Returns 0/-1. */
static int
sz_b64_to_hex (const char *b64, char *hex_out, size_t hex_sz)
{
  unsigned char buf[4096]; size_t blen = 0;
  if (bd_unb64 (b64, buf, sizeof buf, &blen) < 0) return -1;
  if (2 * blen + 1 > hex_sz) return -1;
  bd_to_hex (buf, blen, hex_out);
  return 0;
}

/* Read one BIND .private file into key (algorithm + private material). */
static int
sz_load_private (const char *path, sz_key_t *key)
{
  FILE *f = fopen (path, "r");
  if (!f) { builtin_error ("signzone: %s: %s", path, strerror (errno)); return -1; }
  char line[16384];
  key->priv_scalar[0] = key->rsa_n[0] = key->rsa_e[0] = key->rsa_d[0]
    = key->rsa_p[0] = key->rsa_q[0] = '\0';
  while (fgets (line, sizeof line, f))
    {
      line[strcspn (line, "\r\n")] = '\0';
      char *colon = strchr (line, ':');
      if (!colon) continue;
      *colon = '\0';
      char *val = colon + 1;
      while (*val == ' ' || *val == '\t') val++;
      if (strcasecmp (line, "Algorithm") == 0)
        key->algorithm = (uint8_t) atoi (val);
      else if (strcasecmp (line, "PrivateKey") == 0)
        { if (sz_b64_to_hex (val, key->priv_scalar, sizeof key->priv_scalar) < 0) { fclose (f); return -1; } }
      else if (strcasecmp (line, "Modulus") == 0)
        { if (sz_b64_to_hex (val, key->rsa_n, sizeof key->rsa_n) < 0) { fclose (f); return -1; } }
      else if (strcasecmp (line, "PublicExponent") == 0)
        { if (sz_b64_to_hex (val, key->rsa_e, sizeof key->rsa_e) < 0) { fclose (f); return -1; } }
      else if (strcasecmp (line, "PrivateExponent") == 0)
        { if (sz_b64_to_hex (val, key->rsa_d, sizeof key->rsa_d) < 0) { fclose (f); return -1; } }
      else if (strcasecmp (line, "Prime1") == 0)
        { if (sz_b64_to_hex (val, key->rsa_p, sizeof key->rsa_p) < 0) { fclose (f); return -1; } }
      else if (strcasecmp (line, "Prime2") == 0)
        { if (sz_b64_to_hex (val, key->rsa_q, sizeof key->rsa_q) < 0) { fclose (f); return -1; } }
    }
  fclose (f);
  return 0;
}

/* Read one BIND .key file (DNSKEY master-file line) into key. */
static int
sz_load_pubkey (const char *path, sz_key_t *key)
{
  FILE *f = fopen (path, "r");
  if (!f) { builtin_error ("signzone: %s: %s", path, strerror (errno)); return -1; }
  char line[16384];
  int got = 0;
  while (fgets (line, sizeof line, f))
    {
      if (line[0] == ';') continue;
      line[strcspn (line, "\r\n")] = '\0';
      char *tok[BZ_MAXTOK];
      char work[16384]; snprintf (work, sizeof work, "%s", line);
      int nt = bz_tokenize (work, tok, BZ_MAXTOK);
      if (nt < 5) continue;
      /* owner [TTL] [IN] DNSKEY flags proto alg base64... */
      int idx = 0;
      char canon[256];
      if (bd_canon_owner (tok[0], canon, sizeof canon) < 0) continue;
      snprintf (key->owner, sizeof key->owner, "%s", canon);
      idx = 1;
      while (idx < nt && (bz_is_ttl (tok[idx]) || strcasecmp (tok[idx], "IN") == 0
             || strcasecmp (tok[idx], "CH") == 0))
        idx++;
      if (idx >= nt || strcasecmp (tok[idx], "DNSKEY") != 0) continue;
      idx++;
      if (idx + 4 > nt) continue;
      unsigned long flags = strtoul (tok[idx], NULL, 10);
      unsigned long proto = strtoul (tok[idx + 1], NULL, 10);
      unsigned long alg   = strtoul (tok[idx + 2], NULL, 10);
      char b64[8192]; b64[0] = '\0';
      for (int i = idx + 3; i < nt; i++)
        { if (strlen (b64) + strlen (tok[i]) + 1 >= sizeof b64) break; strcat (b64, tok[i]); }
      unsigned char pk[2048]; size_t pklen = 0;
      if (bd_unb64 (b64, pk, sizeof pk, &pklen) < 0) { fclose (f); return -1; }
      key->flags = (uint16_t) flags;
      key->algorithm = (uint8_t) alg;
      key->dnskey_rdata[0] = (unsigned char) (flags >> 8);
      key->dnskey_rdata[1] = (unsigned char) (flags & 0xff);
      key->dnskey_rdata[2] = (unsigned char) proto;
      key->dnskey_rdata[3] = (unsigned char) alg;
      if (4 + pklen > sizeof key->dnskey_rdata) { fclose (f); return -1; }
      memcpy (key->dnskey_rdata + 4, pk, pklen);
      key->dnskey_rdlen = 4 + pklen;
      key->key_tag = bd_dnskey_keytag (key->dnskey_rdata, key->dnskey_rdlen);
      got = 1;
      break;
    }
  fclose (f);
  return got ? 0 : -1;
}

/* Scan KEYDIR for K<apex>.+<alg>+<tag>.key files, load each key+private
 * pair. Returns count or -1. */
static int
sz_load_keys (const char *keydir, const char *apex,
              sz_key_t *keys, int max)
{
  /* Build prefix "K<apex-with-trailing-dot>." e.g. apex "example.com" ->
   * "Kexample.com." . The apex passed in is canonical (no trailing dot);
   * BIND uses the zone name with a trailing dot. */
  char prefix[300];
  if (strcmp (apex, ".") == 0)
    snprintf (prefix, sizeof prefix, "K.");
  else
    snprintf (prefix, sizeof prefix, "K%s.", apex);

  DIR *d = opendir (keydir);
  if (!d) { builtin_error ("signzone: %s: %s", keydir, strerror (errno)); return -1; }
  struct dirent *de;
  int n = 0;
  while ((de = readdir (d)))
    {
      const char *nm = de->d_name;
      size_t l = strlen (nm);
      if (l < 5 || strcmp (nm + l - 4, ".key") != 0) continue;
      if (strncasecmp (nm, prefix, strlen (prefix)) != 0) continue;
      if (n >= max) { builtin_error ("signzone: too many keys (max %d)", max); closedir (d); return -1; }
      char keypath[1024], privpath[1024];
      snprintf (keypath, sizeof keypath, "%s/%s", keydir, nm);
      snprintf (privpath, sizeof privpath, "%s/%.*s.private", keydir, (int) (l - 4), nm);
      memset (&keys[n], 0, sizeof keys[n]);
      if (sz_load_pubkey (keypath, &keys[n]) < 0)
        { builtin_error ("signzone: failed to load pubkey %s", keypath); closedir (d); return -1; }
      if (sz_load_private (privpath, &keys[n]) < 0)
        { builtin_error ("signzone: failed to load private %s", privpath); closedir (d); return -1; }
      n++;
    }
  closedir (d);
  return n;
}

/* ---- signer: run crypto sign verb, capture raw signature -------
 * Mirrors bd_run_hash_bytes: pipe MSG to the child on stdin, read hex
 * signature from stdout. The verb + its args flow as positional params
 * via the `builtin "$@"` trampoline so no caller data is re-parsed as
 * shell. BASHDNS_SIGNER (test/override) swaps the builtin name;
 * BASHDNS_SIGNER_CMD, if set, replaces the entire `builtin "$@"` script
 * body (the verb+args still arrive as "$@") — mirrors the validator's
 * BASHDNS_VERIFIER_CMD hook for hermetic tests with an out-of-binary
 * signer. */
static int
sz_run_signer (char *const argv[], const unsigned char *msg, size_t msg_len,
               unsigned char *sig_out, size_t sig_sz, size_t *sig_len)
{
  const char *override = getenv ("BASHDNS_SIGNER_CMD");
  int argc = 0; while (argv[argc]) argc++;
  /* assemble: bash -c <body> _ argv... */
  const char *body = (override && *override) ? override : "builtin \"$@\"";
  char *cargv[24];
  int ci = 0;
  cargv[ci++] = (char *) "bash";
  cargv[ci++] = (char *) "-c";
  cargv[ci++] = (char *) body;
  cargv[ci++] = (char *) "_";
  for (int i = 0; i < argc && ci < 22; i++) cargv[ci++] = argv[i];
  cargv[ci] = NULL;

  int p[2], q[2];
  if (pipe (p) < 0) return -1;
  if (pipe (q) < 0) { close (p[0]); close (p[1]); return -1; }
  struct bd_child_guard guard;
  if (bd_child_guard_begin (&guard) < 0)
    { close (p[0]); close (p[1]); close (q[0]); close (q[1]); return -1; }
  pid_t pid = fork ();
  if (pid < 0)
    { bd_child_guard_parent_end (&guard);
      close (p[0]); close (p[1]); close (q[0]); close (q[1]); return -1; }
  if (pid == 0)
    {
      bd_child_guard_child_end (&guard);
      close (p[1]); close (q[0]);
      if (dup2 (p[0], 0) < 0) _exit (127);
      if (dup2 (q[1], 1) < 0) _exit (127);
      close (p[0]); close (q[1]);
      int dn = open ("/dev/null", O_WRONLY);
      if (dn >= 0) { dup2 (dn, 2); close (dn); }
      execvp ("bash", cargv);
      _exit (127);
    }
  close (p[0]); close (q[1]);
  if (bd_write_all (p[1], msg, msg_len) < 0)
    { close (p[1]); close (q[0]); int st;
      while (waitpid (pid, &st, 0) < 0 && errno == EINTR) ;
      bd_child_guard_parent_end (&guard); return -1; }
  close (p[1]);
  char hex[16384]; size_t hexlen = 0; ssize_t rn;
  while ((rn = read (q[0], hex + hexlen, sizeof hex - 1 - hexlen)) > 0)
    { hexlen += (size_t) rn; if (hexlen >= sizeof hex - 1) break; }
  close (q[0]);
  hex[hexlen] = '\0';
  int st = 0, wrc;
  while ((wrc = waitpid (pid, &st, 0)) < 0 && errno == EINTR) ;
  bd_child_guard_parent_end (&guard);
  if (wrc < 0 || !WIFEXITED (st) || WEXITSTATUS (st) != 0) return -1;
  return bd_unhex (hex, sig_out, sig_sz, sig_len);
}

/* Sign MSG with KEY (its algorithm selects the crypto verb), write
 * the raw DNSSEC signature into sig_out. Returns 0/-1. */
static int
sz_sign (const sz_key_t *key, const unsigned char *msg, size_t msg_len,
         unsigned char *sig_out, size_t sig_sz, size_t *sig_len)
{
  const char *signer = getenv ("BASHDNS_SIGNER");
  if (!signer || !*signer) signer = "crypto";
  switch (key->algorithm)
    {
    case BD_ALG_RSASHA1:
    case BD_ALG_RSASHA1_NSEC3:
    case BD_ALG_RSASHA256:
    case BD_ALG_RSASHA512:
      {
        if (!key->rsa_n[0] || !key->rsa_e[0] || !key->rsa_d[0]
            || !key->rsa_p[0] || !key->rsa_q[0]) return -1;
        const char *hash = (key->algorithm == BD_ALG_RSASHA1
                            || key->algorithm == BD_ALG_RSASHA1_NSEC3) ? "sha1"
                         : (key->algorithm == BD_ALG_RSASHA256) ? "sha256"
                         : "sha512";
        char *argv[] = {
          (char *) signer, (char *) "rsa-pkcs1-sign",
          (char *) "-n", (char *) key->rsa_n,
          (char *) "-e", (char *) key->rsa_e,
          (char *) "-d", (char *) key->rsa_d,
          (char *) "-p", (char *) key->rsa_p,
          (char *) "-q", (char *) key->rsa_q,
          (char *) "-H", (char *) hash,
          (char *) "-x", NULL };
        return sz_run_signer (argv, msg, msg_len, sig_out, sig_sz, sig_len);
      }
    case BD_ALG_ECDSAP256SHA256:
      {
        if (!key->priv_scalar[0]) return -1;
        char *argv[] = {
          (char *) signer, (char *) "ecdsa-p256-sign",
          (char *) "-k", (char *) key->priv_scalar,
          (char *) "-x", NULL };
        return sz_run_signer (argv, msg, msg_len, sig_out, sig_sz, sig_len);
      }
    case BD_ALG_ECDSAP384SHA384:
      {
        if (!key->priv_scalar[0]) return -1;
        char *argv[] = {
          (char *) signer, (char *) "ecdsa-p384-sign",
          (char *) "-k", (char *) key->priv_scalar,
          (char *) "-x", NULL };
        return sz_run_signer (argv, msg, msg_len, sig_out, sig_sz, sig_len);
      }
    case BD_ALG_ED25519:
      {
        if (!key->priv_scalar[0]) return -1;
        char *argv[] = {
          (char *) signer, (char *) "ed25519-sign",
          (char *) "-k", (char *) key->priv_scalar,
          (char *) "-x", NULL };
        return sz_run_signer (argv, msg, msg_len, sig_out, sig_sz, sig_len);
      }
    default:
      builtin_error ("signzone: unsupported signing algorithm %u", (unsigned) key->algorithm);
      return -1;
    }
}

/* ---- RRSIG construction -------------------------------------------- */

/* Build an RRSIG bd_rr_t over the RRset `set` (set_n records, all same
 * owner+type) signed with KEY. inception/expiration are epoch seconds.
 * The signing input is produced by bd_build_signed_msg (the validator's
 * canonicaliser) and signed via sz_sign; the resulting RRSIG is appended
 * to out as a bd_rr_t. Returns 0/-1. */
static int
sz_make_rrsig (sz_key_t *key, const char *apex,
               bd_rr_t *set, int set_n,
               uint32_t inception, uint32_t expiration,
               bd_rr_t *out)
{
  if (set_n < 1) return -1;
  uint16_t covered = set[0].type;
  uint32_t orig_ttl = set[0].ttl;
  int labels = bd_label_count (set[0].owner);
  if (labels < 0) return -1;
  /* Wildcard owner: leading "*" label is not counted (RFC 4034 §3.1.3). */
  if (set[0].owner[0] == '*' && set[0].owner[1] == '.') labels -= 1;

  unsigned char signer_wire[256];
  int sw = bd_name_to_wire (apex, signer_wire, sizeof signer_wire);
  if (sw < 0) return -1;

  /* Assemble RRSIG rdata header (no signature): 18 fixed + signer wire. */
  bd_rr_t rrsig;
  memset (&rrsig, 0, sizeof rrsig);
  unsigned char *h = rrsig.rdata;
  size_t o = 0;
  h[o++] = (unsigned char) (covered >> 8); h[o++] = (unsigned char) (covered & 0xff);
  h[o++] = key->algorithm;
  h[o++] = (unsigned char) labels;
  h[o++] = (unsigned char) (orig_ttl >> 24); h[o++] = (unsigned char) (orig_ttl >> 16);
  h[o++] = (unsigned char) (orig_ttl >> 8);  h[o++] = (unsigned char) (orig_ttl & 0xff);
  h[o++] = (unsigned char) (expiration >> 24); h[o++] = (unsigned char) (expiration >> 16);
  h[o++] = (unsigned char) (expiration >> 8);  h[o++] = (unsigned char) (expiration & 0xff);
  h[o++] = (unsigned char) (inception >> 24); h[o++] = (unsigned char) (inception >> 16);
  h[o++] = (unsigned char) (inception >> 8);  h[o++] = (unsigned char) (inception & 0xff);
  h[o++] = (unsigned char) (key->key_tag >> 8); h[o++] = (unsigned char) (key->key_tag & 0xff);
  memcpy (h + o, signer_wire, (size_t) sw); o += (size_t) sw;
  rrsig.rdata_len = (uint16_t) o;   /* header only; bd_build_signed_msg stops at signer end */

  /* Build the canonical signing input (header || sorted RRset). */
  unsigned char msg[16384]; size_t msg_len = 0;
  bd_rr_t work[BD_RR_MAX];
  if (set_n > BD_RR_MAX) return -1;
  memcpy (work, set, sizeof (bd_rr_t) * set_n);
  if (bd_build_signed_msg (&rrsig, work, set_n, msg, sizeof msg, &msg_len) < 0) return -1;

  /* Sign. */
  unsigned char sig[1024]; size_t sig_len = 0;
  if (sz_sign (key, msg, msg_len, sig, sizeof sig, &sig_len) < 0) return -1;

  /* Append signature to the RRSIG rdata. */
  if ((size_t) o + sig_len > sizeof rrsig.rdata) return -1;
  memcpy (rrsig.rdata + o, sig, sig_len);
  rrsig.rdata_len = (uint16_t) (o + sig_len);

  *out = rrsig;
  out->type = BD_T_RRSIG;
  out->cls = 1;
  out->ttl = orig_ttl;
  snprintf (out->owner, sizeof out->owner, "%s", set[0].owner);
  return 0;
}

/* ---- NSEC / NSEC3 type bitmap -------------------------------------- */

/* Build the RFC 4034 §4.1.2 window-block type bitmap for the type set
 * `types[ntypes]` into out (capacity out_sz). Returns bitmap length. */
static int
sz_type_bitmap (const uint16_t *types, int ntypes, unsigned char *out, size_t out_sz)
{
  /* Collect into per-window 32-byte bitmaps; only windows 0..255. */
  unsigned char win[256][32];
  int winmax[256];
  for (int i = 0; i < 256; i++) winmax[i] = -1;
  memset (win, 0, sizeof win);
  for (int i = 0; i < ntypes; i++)
    {
      uint16_t t = types[i];
      int w = t >> 8;
      int bit = t & 0xff;
      win[w][bit / 8] |= (unsigned char) (0x80 >> (bit % 8));
      if (bit / 8 > winmax[w]) winmax[w] = bit / 8;
    }
  size_t off = 0;
  for (int w = 0; w < 256; w++)
    {
      if (winmax[w] < 0) continue;
      int len = winmax[w] + 1;
      if (off + 2 + (size_t) len > out_sz) return -1;
      out[off++] = (unsigned char) w;
      out[off++] = (unsigned char) len;
      memcpy (out + off, win[w], (size_t) len);
      off += (size_t) len;
    }
  return (int) off;
}

/* ---- master-file emission ------------------------------------------ */

static void
sz_emit_b64 (const unsigned char *in, size_t n)
{
  static const char *a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t i = 0;
  for (; i + 3 <= n; i += 3)
    { uint32_t v = (in[i] << 16) | (in[i+1] << 8) | in[i+2];
      putchar (a[(v>>18)&63]); putchar (a[(v>>12)&63]); putchar (a[(v>>6)&63]); putchar (a[v&63]); }
  if (n - i == 1)
    { uint32_t v = in[i] << 16; putchar (a[(v>>18)&63]); putchar (a[(v>>12)&63]); putchar ('='); putchar ('='); }
  else if (n - i == 2)
    { uint32_t v = (in[i] << 16) | (in[i+1] << 8); putchar (a[(v>>18)&63]); putchar (a[(v>>12)&63]); putchar (a[(v>>6)&63]); putchar ('='); }
}

/* Print one record's RDATA in master-file presentation form. Owner/
 * type/ttl are printed by the caller. */
static void
sz_emit_rdata (const bd_rr_t *r)
{
  switch (r->type)
    {
    case BD_T_A:
      { struct in_addr a; memcpy (&a.s_addr, r->rdata, 4);
        char b[64]; inet_ntop (AF_INET, &a, b, sizeof b); printf ("%s", b); break; }
    case BD_T_AAAA:
      { struct in6_addr a; memcpy (a.s6_addr, r->rdata, 16);
        char b[64]; inet_ntop (AF_INET6, &a, b, sizeof b); printf ("%s", b); break; }
    case BD_T_NS: case BD_T_CNAME: case BD_T_DNAME: case BD_T_PTR:
      { char nm[256]; size_t off = 0;
        if (bd_decode_name (r->rdata, r->rdata_len, &off, nm, sizeof nm, 0) >= 0)
          printf ("%s.", nm); break; }
    case BD_T_MX:
      { uint16_t pref = bd_rd16 (r->rdata); char nm[256]; size_t off = 2;
        bd_decode_name (r->rdata, r->rdata_len, &off, nm, sizeof nm, 0);
        printf ("%u %s.", pref, nm); break; }
    case BD_T_SOA:
      { char m[256], rn[256]; size_t off = 0;
        bd_decode_name (r->rdata, r->rdata_len, &off, m, sizeof m, 0);
        bd_decode_name (r->rdata, r->rdata_len, &off, rn, sizeof rn, 0);
        printf ("%s. %s. %u %u %u %u %u", m, rn,
                bd_rd32 (r->rdata + off), bd_rd32 (r->rdata + off + 4),
                bd_rd32 (r->rdata + off + 8), bd_rd32 (r->rdata + off + 12),
                bd_rd32 (r->rdata + off + 16)); break; }
    case BD_T_TXT:
      { size_t off = 0;
        while (off < r->rdata_len)
          { unsigned int l = r->rdata[off++];
            if (off + l > r->rdata_len) break;
            putchar ('"');
            for (unsigned int i = 0; i < l; i++) putchar (r->rdata[off + i]);
            putchar ('"'); off += l; if (off < r->rdata_len) putchar (' '); }
        break; }
    case BD_T_DNSKEY:
      { uint16_t flags = bd_rd16 (r->rdata);
        printf ("%u %u %u ", flags, r->rdata[2], r->rdata[3]);
        sz_emit_b64 (r->rdata + 4, r->rdata_len - 4); break; }
    case BD_T_RRSIG:
      { /* type covered alg labels origttl exp inc keytag signer sig */
        uint16_t covered = bd_rd16 (r->rdata);
        size_t off = 18;
        char signer[256];
        bd_decode_name (r->rdata, r->rdata_len, &off, signer, sizeof signer, 0);
        printf ("%s %u %u %u %u %u %u %s. ",
                bd_type_name (covered), r->rdata[2], r->rdata[3],
                bd_rd32 (r->rdata + 4), bd_rd32 (r->rdata + 8),
                bd_rd32 (r->rdata + 12), bd_rd16 (r->rdata + 16), signer);
        sz_emit_b64 (r->rdata + off, r->rdata_len - off); break; }
    case BD_T_NSEC:
      { char nm[256]; size_t off = 0;
        bd_decode_name (r->rdata, r->rdata_len, &off, nm, sizeof nm, 0);
        printf ("%s.", nm);
        /* type bitmap */
        size_t bp = off;
        while (bp + 2 <= r->rdata_len)
          { int w = r->rdata[bp]; int len = r->rdata[bp + 1]; bp += 2;
            for (int i = 0; i < len && bp + i < r->rdata_len; i++)
              { unsigned char byte = r->rdata[bp + i];
                for (int b = 0; b < 8; b++)
                  if (byte & (0x80 >> b))
                    printf (" %s", bd_type_name ((uint16_t) (w * 256 + i * 8 + b))); }
            bp += len; }
        break; }
    case BD_T_NSEC3:
      { uint8_t alg = r->rdata[0], flags = r->rdata[1];
        uint16_t iters = bd_rd16 (r->rdata + 2);
        uint8_t slen = r->rdata[4];
        printf ("%u %u %u ", alg, flags, iters);
        if (slen == 0) printf ("-");
        else { char sx[129]; bd_to_hex (r->rdata + 5, slen, sx); printf ("%s", sx); }
        size_t off = 5 + slen;
        uint8_t hlen = r->rdata[off++];
        char nh[129];
        bd_nsec3_base32hex (r->rdata + off, hlen, nh, sizeof nh);
        printf (" %s", nh); off += hlen;
        size_t bp = off;
        while (bp + 2 <= r->rdata_len)
          { int w = r->rdata[bp]; int len = r->rdata[bp + 1]; bp += 2;
            for (int i = 0; i < len && bp + i < r->rdata_len; i++)
              { unsigned char byte = r->rdata[bp + i];
                for (int b = 0; b < 8; b++)
                  if (byte & (0x80 >> b))
                    printf (" %s", bd_type_name ((uint16_t) (w * 256 + i * 8 + b))); }
            bp += len; }
        break; }
    case BD_T_NSEC3PARAM:
      { uint8_t alg = r->rdata[0], flags = r->rdata[1];
        uint16_t iters = bd_rd16 (r->rdata + 2);
        uint8_t slen = r->rdata[4];
        printf ("%u %u %u ", alg, flags, iters);
        if (slen == 0) printf ("-");
        else { char sx[129]; bd_to_hex (r->rdata + 5, slen, sx); printf ("%s", sx); }
        break; }
    default:
      { /* generic \# len hex */
        char hx[4096]; bd_to_hex (r->rdata, r->rdata_len, hx);
        printf ("\\# %u %s", r->rdata_len, hx); break; }
    }
}

static void
sz_emit_record (const bd_rr_t *r)
{
  printf ("%s. %u IN %s ", r->owner, r->ttl, bd_type_name (r->type));
  sz_emit_rdata (r);
  putchar ('\n');
}

/* ---- shared in-memory zone signer (offline signzone + online auth-serve) -- */

/* Sign the loaded zone rrs[0..*np) in place: load keys from keydir, inject
   the apex DNSKEY RRset, sign every RRset (DNSKEY by the KSK, the rest by the
   ZSK), and build the NSEC (or NSEC3 with --nsec3) denial chain — appending
   RRSIG/DNSKEY/NSEC[3]/NSEC3PARAM records and updating *np. apex must be the
   raw apex sz_load_zone() produced. orig_n_out (optional) receives the record
   count before RRSIG/NSEC were added. Returns 0, or -1 with err filled; the
   caller owns rrs and frees it on failure. This is the exact code the offline
   `signzone` uses, factored out so the daemon can sign at zone-load without an
   emit/reparse round-trip (the master-file parser cannot read RRSIG back). */
static int
sz_sign_zone_inplace (bd_rr_t *rrs, int *np, const char *apex,
                      const char *keydir, long valid_secs, int use_nsec3,
                      const char *salt_hex, int nsec3_iters,
                      int *orig_n_out, char *err, size_t errsz)
{
  int n = *np;

  sz_key_t keys[SZ_KEY_MAX];
  int nk = sz_load_keys (keydir, apex, keys, SZ_KEY_MAX);
  if (nk < 0) { snprintf (err, errsz, "loading keys from %s failed", keydir); return -1; }
  if (nk == 0) { snprintf (err, errsz, "no keys K%s.+* found in %s", apex, keydir); return -1; }

  /* Pick a ZSK (flags 256) and a KSK (flags 257); fall back to any key. */
  sz_key_t *zsk = NULL, *ksk = NULL;
  for (int i = 0; i < nk; i++)
    { if (keys[i].flags == 256 && !zsk) zsk = &keys[i];
      if (keys[i].flags == 257 && !ksk) ksk = &keys[i]; }
  if (!zsk) zsk = &keys[0];
  if (!ksk) ksk = zsk;

  uint32_t inception = (uint32_t) time (NULL);
  uint32_t expiration = (uint32_t) (inception + valid_secs);

  /* Inject DNSKEY records (from the .key files) at the apex if absent. */
  for (int i = 0; i < nk; i++)
    {
      int present = 0;
      for (int j = 0; j < n; j++)
        if (rrs[j].type == BD_T_DNSKEY && strcmp (rrs[j].owner, apex) == 0
            && rrs[j].rdata_len == keys[i].dnskey_rdlen
            && memcmp (rrs[j].rdata, keys[i].dnskey_rdata, keys[i].dnskey_rdlen) == 0)
          { present = 1; break; }
      if (!present)
        {
          if (n >= SZ_RR_MAX) { snprintf (err, errsz, "RR table full"); return -1; }
          bd_rr_t *r = &rrs[n++];
          memset (r, 0, sizeof *r);
          snprintf (r->owner, sizeof r->owner, "%s", apex);
          r->type = BD_T_DNSKEY; r->cls = 1; r->ttl = 3600;
          memcpy (r->rdata, keys[i].dnskey_rdata, keys[i].dnskey_rdlen);
          r->rdata_len = (uint16_t) keys[i].dnskey_rdlen;
        }
    }

  int orig_n = n;   /* records before we add RRSIG/NSEC */
  if (orig_n_out) *orig_n_out = orig_n;

  /* ---- group into RRsets (owner+type+class) and sign each ---- */
  /* mark[i] = consumed flag */
  char *done = calloc (orig_n, 1);
  if (!done) { snprintf (err, errsz, "oom"); return -1; }

  for (int i = 0; i < orig_n; i++)
    {
      if (done[i]) continue;
      if (rrs[i].type == BD_T_RRSIG) { done[i] = 1; continue; }
      /* gather the RRset */
      bd_rr_t set[BD_RR_MAX]; int set_n = 0;
      for (int j = i; j < orig_n; j++)
        if (!done[j] && rrs[j].type == rrs[i].type
            && strcmp (rrs[j].owner, rrs[i].owner) == 0 && rrs[j].cls == rrs[i].cls)
          { if (set_n < BD_RR_MAX) set[set_n++] = rrs[j]; done[j] = 1; }

      /* DNSKEY RRset is signed by the KSK; everything else by the ZSK. */
      sz_key_t *signer = (rrs[i].type == BD_T_DNSKEY) ? ksk : zsk;
      if (set_n == 0) { snprintf (err, errsz, "empty RRset"); free (done); return -1; }

      bd_rr_t rrsig;
      if (sz_make_rrsig (signer, apex, set, set_n, inception, expiration, &rrsig) < 0)
        { snprintf (err, errsz, "failed to sign %s/%s", set[0].owner, bd_type_name (set[0].type));
          free (done); return -1; }
      if (n >= SZ_RR_MAX) { snprintf (err, errsz, "RR table full"); free (done); return -1; }
      rrs[n++] = rrsig;
    }
  free (done);

  /* ---- denial-of-existence chain ---- */
  /* Collect distinct owner names (canonical) from the pre-denial set. */
  char names[SZ_RR_MAX][256];
  int nnames = 0;
  for (int i = 0; i < orig_n; i++)
    {
      int seen = 0;
      for (int j = 0; j < nnames; j++) if (strcmp (names[j], rrs[i].owner) == 0) { seen = 1; break; }
      if (!seen && nnames < SZ_RR_MAX) snprintf (names[nnames++], 256, "%s", rrs[i].owner);
    }

  if (!use_nsec3)
    {
      /* Canonical name sort (DNSSEC name order: by reversed labels). For
       * the simple flat zones we target, byte-wise label-reversed compare
       * is sufficient; we use the same canonical-owner string but sort by
       * the RFC 4034 §6.1 ordering approximated with reversed-label key. */
      /* Build sort keys: reverse the label order. */
      for (int a = 0; a < nnames; a++)
        for (int b = a + 1; b < nnames; b++)
          if (bd_canon_name_cmp (names[a], names[b]) > 0)
            { char t[256]; strcpy (t, names[a]); strcpy (names[a], names[b]); strcpy (names[b], t); }

      for (int i = 0; i < nnames; i++)
        {
          const char *owner = names[i];
          const char *next  = names[(i + 1) % nnames];
          /* Apex must be the wrap target: ensure last->apex. Because the
           * sort places apex first, names[0] is the apex and the wrap
           * names[last]->names[0] is correct. */
          /* Build the type list present at this owner (+ RRSIG + NSEC). */
          uint16_t types[64]; int nt = 0;
          for (int j = 0; j < n; j++)
            if (strcmp (rrs[j].owner, owner) == 0)
              { uint16_t tt = rrs[j].type; int dup = 0;
                for (int k = 0; k < nt; k++) if (types[k] == tt) dup = 1;
                if (!dup && nt < 62) types[nt++] = tt; }
          /* ensure NSEC present in bitmap */
          { int dup = 0; for (int k = 0; k < nt; k++) if (types[k] == BD_T_NSEC) dup = 1;
            if (!dup && nt < 63) types[nt++] = BD_T_NSEC; }
          /* sort types ascending for canonical bitmap */
          for (int a = 0; a < nt; a++) for (int b = a + 1; b < nt; b++)
            if (types[a] > types[b]) { uint16_t t = types[a]; types[a] = types[b]; types[b] = t; }

          bd_rr_t nsec; memset (&nsec, 0, sizeof nsec);
          snprintf (nsec.owner, sizeof nsec.owner, "%s", owner);
          nsec.type = BD_T_NSEC; nsec.cls = 1; nsec.ttl = 3600;
          unsigned char nw[256];
          int wn = bd_name_to_wire (next, nw, sizeof nw);
          if (wn < 0) { snprintf (err, errsz, "NSEC next-name encode"); return -1; }
          memcpy (nsec.rdata, nw, (size_t) wn);
          int bm = sz_type_bitmap (types, nt, nsec.rdata + wn, sizeof nsec.rdata - wn);
          if (bm < 0) { snprintf (err, errsz, "NSEC bitmap"); return -1; }
          nsec.rdata_len = (uint16_t) (wn + bm);
          if (n >= SZ_RR_MAX) { snprintf (err, errsz, "RR table full"); return -1; }
          rrs[n++] = nsec;
          /* sign the NSEC */
          bd_rr_t one[1]; one[0] = nsec;
          bd_rr_t rrsig;
          if (sz_make_rrsig (zsk, apex, one, 1, inception, expiration, &rrsig) < 0)
            { snprintf (err, errsz, "failed to sign NSEC %s", owner); return -1; }
          if (n >= SZ_RR_MAX) { snprintf (err, errsz, "RR table full"); return -1; }
          rrs[n++] = rrsig;
        }
    }
  else
    {
      /* NSEC3: hash each owner, sort hashes, chain. */
      unsigned char salt[256]; size_t salt_len = 0;
      if (salt_hex && strcmp (salt_hex, "-") != 0)
        { if (bd_unhex (salt_hex, salt, sizeof salt, &salt_len) < 0)
            { snprintf (err, errsz, "bad -s SALT hex"); return -1; } }
      uint16_t iters = (uint16_t) (nsec3_iters > 0 ? nsec3_iters : 0);

      typedef struct { unsigned char h[64]; size_t hlen; char owner[256]; uint16_t types[64]; int nt; } n3_t;
      n3_t *ent = calloc (nnames, sizeof (n3_t));
      if (!ent) { snprintf (err, errsz, "oom"); return -1; }
      for (int i = 0; i < nnames; i++)
        {
          if (bd_nsec3_hash_name (names[i], 1, salt, salt_len, iters,
                                  ent[i].h, sizeof ent[i].h, &ent[i].hlen) < 0)
            { free (ent); snprintf (err, errsz, "NSEC3 hash failed"); return -1; }
          snprintf (ent[i].owner, sizeof ent[i].owner, "%s", names[i]);
          /* types present at this owner */
          int nt = 0;
          for (int j = 0; j < n; j++)
            if (strcmp (rrs[j].owner, names[i]) == 0)
              { uint16_t tt = rrs[j].type; int dup = 0;
                for (int k = 0; k < nt; k++) if (ent[i].types[k] == tt) dup = 1;
                if (!dup && nt < 62) ent[i].types[nt++] = tt; }
          /* apex carries NSEC3PARAM in its bitmap */
          if (strcmp (names[i], apex) == 0)
            { int dup = 0; for (int k = 0; k < nt; k++) if (ent[i].types[k] == BD_T_NSEC3PARAM) dup = 1;
              if (!dup && nt < 62) ent[i].types[nt++] = BD_T_NSEC3PARAM; }
          ent[i].nt = nt;
        }
      /* sort by hash */
      for (int a = 0; a < nnames; a++) for (int b = a + 1; b < nnames; b++)
        if (bd_nsec3_hash_cmp (ent[a].h, ent[a].hlen, ent[b].h, ent[b].hlen) > 0)
          { n3_t t = ent[a]; ent[a] = ent[b]; ent[b] = t; }

      /* Emit NSEC3PARAM at apex. */
      { bd_rr_t pr; memset (&pr, 0, sizeof pr);
        snprintf (pr.owner, sizeof pr.owner, "%s", apex);
        pr.type = BD_T_NSEC3PARAM; pr.cls = 1; pr.ttl = 3600;
        pr.rdata[0] = 1; pr.rdata[1] = 0;
        pr.rdata[2] = (unsigned char) (iters >> 8); pr.rdata[3] = (unsigned char) (iters & 0xff);
        pr.rdata[4] = (unsigned char) salt_len;
        memcpy (pr.rdata + 5, salt, salt_len);
        pr.rdata_len = (uint16_t) (5 + salt_len);
        if (n >= SZ_RR_MAX) { free (ent); snprintf (err, errsz, "RR full"); return -1; }
        rrs[n++] = pr;
        bd_rr_t one[1]; one[0] = pr; bd_rr_t rrsig;
        if (sz_make_rrsig (zsk, apex, one, 1, inception, expiration, &rrsig) < 0)
          { free (ent); snprintf (err, errsz, "sign NSEC3PARAM"); return -1; }
        rrs[n++] = rrsig; }

      for (int i = 0; i < nnames; i++)
        {
          n3_t *e = &ent[i];
          n3_t *nx = &ent[(i + 1) % nnames];
          /* NSEC3 owner name = base32hex(hash) . apex */
          char hlabel[129];
          if (bd_nsec3_base32hex (e->h, e->hlen, hlabel, sizeof hlabel) < 0)
            { free (ent); snprintf (err, errsz, "base32hex"); return -1; }
          char n3owner[512];
          if (strcmp (apex, ".") == 0) snprintf (n3owner, sizeof n3owner, "%s", hlabel);
          else snprintf (n3owner, sizeof n3owner, "%s.%s", hlabel, apex);

          uint16_t types[64]; int nt = e->nt;
          memcpy (types, e->types, sizeof (uint16_t) * nt);
          /* RRSIG type is present at every signed owner */
          { int dup = 0; for (int k = 0; k < nt; k++) if (types[k] == BD_T_RRSIG) dup = 1;
            if (!dup && nt < 63) types[nt++] = BD_T_RRSIG; }
          for (int a = 0; a < nt; a++) for (int b = a + 1; b < nt; b++)
            if (types[a] > types[b]) { uint16_t t = types[a]; types[a] = types[b]; types[b] = t; }

          bd_rr_t nr; memset (&nr, 0, sizeof nr);
          snprintf (nr.owner, sizeof nr.owner, "%s", n3owner);
          nr.type = BD_T_NSEC3; nr.cls = 1; nr.ttl = 3600;
          size_t o = 0;
          nr.rdata[o++] = 1;          /* SHA-1 */
          nr.rdata[o++] = 0;          /* flags (opt-out off) */
          nr.rdata[o++] = (unsigned char) (iters >> 8); nr.rdata[o++] = (unsigned char) (iters & 0xff);
          nr.rdata[o++] = (unsigned char) salt_len;
          memcpy (nr.rdata + o, salt, salt_len); o += salt_len;
          nr.rdata[o++] = (unsigned char) nx->hlen;
          memcpy (nr.rdata + o, nx->h, nx->hlen); o += nx->hlen;
          int bm = sz_type_bitmap (types, nt, nr.rdata + o, sizeof nr.rdata - o);
          if (bm < 0) { free (ent); snprintf (err, errsz, "NSEC3 bitmap"); return -1; }
          o += bm;
          nr.rdata_len = (uint16_t) o;
          if (n >= SZ_RR_MAX) { free (ent); snprintf (err, errsz, "RR full"); return -1; }
          rrs[n++] = nr;
          bd_rr_t one[1]; one[0] = nr; bd_rr_t rrsig;
          if (sz_make_rrsig (zsk, apex, one, 1, inception, expiration, &rrsig) < 0)
            { free (ent); snprintf (err, errsz, "sign NSEC3"); return -1; }
          rrs[n++] = rrsig;
        }
      free (ent);
    }

  *np = n;
  return 0;
}

/* ---- the signzone command ------------------------------------------ */

static int
bd_signzone_cmd (WORD_LIST *args)
{
  const char *zonefile = NULL;
  const char *origin_in = NULL;
  const char *keydir = ".";
  long valid_secs = 2592000;     /* 30 days */
  int use_nsec3 = 0, self_check = 0;
  const char *salt_hex = NULL;
  int nsec3_iters = 0;

  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-o") == 0)
        { if (!p->next) { builtin_error ("signzone: -o needs ORIGIN"); return EX_USAGE; } p = p->next; origin_in = p->word->word; }
      else if (strcmp (w, "-K") == 0)
        { if (!p->next) { builtin_error ("signzone: -K needs KEYDIR"); return EX_USAGE; } p = p->next; keydir = p->word->word; }
      else if (strcmp (w, "-e") == 0)
        { if (!p->next) { builtin_error ("signzone: -e needs SECONDS"); return EX_USAGE; } p = p->next; valid_secs = atol (p->word->word); }
      else if (strcmp (w, "--nsec3") == 0) use_nsec3 = 1;
      else if (strcmp (w, "-s") == 0)
        { if (!p->next) { builtin_error ("signzone: -s needs SALT"); return EX_USAGE; } p = p->next; salt_hex = p->word->word; }
      else if (strcmp (w, "-i") == 0)
        { if (!p->next) { builtin_error ("signzone: -i needs ITERS"); return EX_USAGE; } p = p->next; nsec3_iters = atoi (p->word->word); }
      else if (strcmp (w, "--self-check") == 0) self_check = 1;
      else if (w[0] == '-') { builtin_error ("signzone: unknown flag %s", w); return EX_USAGE; }
      else if (!zonefile) zonefile = w;
      else { builtin_error ("signzone: extra arg %s", w); return EX_USAGE; }
    }
  if (!zonefile) { builtin_error ("signzone: ZONEFILE required"); return EX_USAGE; }

  bd_rr_t *rrs = calloc (SZ_RR_MAX, sizeof (bd_rr_t));
  if (!rrs) { builtin_error ("signzone: out of memory"); return EXECUTION_FAILURE; }
  char apex[256];
  int n = sz_load_zone (zonefile, origin_in, rrs, SZ_RR_MAX, apex, sizeof apex);
  if (n < 0) { free (rrs); return EXECUTION_FAILURE; }

  int orig_n = 0, sig_failures = 0;
  { char serr[256];
    if (sz_sign_zone_inplace (rrs, &n, apex, keydir, valid_secs, use_nsec3,
                              salt_hex, nsec3_iters, &orig_n, serr, sizeof serr) < 0)
      { builtin_error ("signzone: %s", serr); free (rrs); return EXECUTION_FAILURE; }
  }

  /* ---- self-check: verify every RRSIG through the validator ---- */
  if (self_check)
    {
      bd_trust_t ts[BD_TRUST_MAX]; int ts_n = 0;
      if (bd_install_dnskeys (rrs, n, apex, ts, &ts_n, BD_TRUST_MAX) < 0 || ts_n == 0)
        { builtin_error ("signzone: self-check: no DNSKEY to verify against"); free (rrs); return EXECUTION_FAILURE; }
      int checked = 0;
      for (int i = 0; i < n; i++)
        {
          if (rrs[i].type != BD_T_RRSIG) continue;
          uint16_t covered = bd_rd16 (rrs[i].rdata);
          /* Build the RR array: the covered RRset + this RRSIG. */
          bd_rr_t arr[BD_RR_MAX]; int an = 0;
          for (int j = 0; j < n && an < BD_RR_MAX; j++)
            if (rrs[j].type == covered && strcmp (rrs[j].owner, rrs[i].owner) == 0)
              arr[an++] = rrs[j];
          if (an < BD_RR_MAX) arr[an++] = rrs[i];
          char err[256];
          if (bd_verify_rrset (arr, an, rrs[i].owner, covered, ts, ts_n, 86400, err, sizeof err) < 0)
            { builtin_error ("signzone: self-check FAILED for %s/%s: %s",
                             rrs[i].owner, bd_type_name (covered), err);
              sig_failures++; }
          else checked++;
        }
      if (sig_failures)
        { builtin_error ("signzone: self-check found %d bad RRSIG(s)", sig_failures); free (rrs); return EXECUTION_FAILURE; }
      fprintf (stderr, "signzone: self-check OK (%d RRSIG verified)\n", checked);
    }

  /* ---- emit signed zone ---- */
  printf ("; Signed zone %s — %d records (%d original)\n", apex, n, orig_n);
  for (int i = 0; i < n; i++)
    sz_emit_record (&rrs[i]);

  free (rrs);
  return EXECUTION_SUCCESS;
}

/* ---- ds-from-dnskey ------------------------------------------------ */

static int
bd_ds_from_dnskey_cmd (WORD_LIST *args)
{
  const char *digest = "sha256";
  const char *keyfile = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-d") == 0)
        { if (!p->next) { builtin_error ("ds-from-dnskey: -d needs ALG"); return EX_USAGE; } p = p->next; digest = p->word->word; }
      else if (!keyfile) keyfile = w;
      else { builtin_error ("ds-from-dnskey: extra arg %s", w); return EX_USAGE; }
    }
  if (!keyfile) { builtin_error ("ds-from-dnskey: KEYFILE required"); return EX_USAGE; }

  sz_key_t key; memset (&key, 0, sizeof key);
  if (sz_load_pubkey (keyfile, &key) < 0)
    { builtin_error ("ds-from-dnskey: cannot read DNSKEY from %s", keyfile); return EXECUTION_FAILURE; }

  uint8_t dtype; const char *hashverb;
  if (strcmp (digest, "sha1") == 0)   { dtype = 1; hashverb = "sha1"; }
  else if (strcmp (digest, "sha256") == 0) { dtype = 2; hashverb = "sha256"; }
  else if (strcmp (digest, "sha384") == 0) { dtype = 4; hashverb = "sha384"; }
  else { builtin_error ("ds-from-dnskey: -d must be sha1|sha256|sha384"); return EX_USAGE; }

  /* DS digest input = canonical owner wire || DNSKEY rdata. */
  unsigned char buf[2400]; size_t blen = 0;
  unsigned char ow[256];
  int wn = bd_name_to_wire (key.owner, ow, sizeof ow);
  if (wn < 0) { builtin_error ("ds-from-dnskey: owner encode"); return EXECUTION_FAILURE; }
  memcpy (buf, ow, (size_t) wn); blen = (size_t) wn;
  memcpy (buf + blen, key.dnskey_rdata, key.dnskey_rdlen); blen += key.dnskey_rdlen;

  unsigned char dg[64]; size_t dglen = 0;
  if (bd_run_hash_bytes (hashverb, buf, blen, dg, sizeof dg, &dglen) < 0)
    { builtin_error ("ds-from-dnskey: digest failed"); return EXECUTION_FAILURE; }

  char hex[129]; bd_to_hex (dg, dglen, hex);
  /* uppercase for BIND-style DS text */
  for (char *c = hex; *c; c++) *c = (char) toupper ((unsigned char) *c);
  printf ("%s. IN DS %u %u %u %s\n", key.owner, key.key_tag, key.algorithm, dtype, hex);
  return EXECUTION_SUCCESS;
}

/* ---- keytag -------------------------------------------------------- */

static int
bd_keytag_cmd (WORD_LIST *args)
{
  const char *keyfile = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (!keyfile) keyfile = w;
      else { builtin_error ("keytag: extra arg %s", w); return EX_USAGE; }
    }
  if (!keyfile) { builtin_error ("keytag: KEYFILE required"); return EX_USAGE; }
  sz_key_t key; memset (&key, 0, sizeof key);
  if (sz_load_pubkey (keyfile, &key) < 0)
    { builtin_error ("keytag: cannot read DNSKEY from %s", keyfile); return EXECUTION_FAILURE; }
  printf ("%u\n", key.key_tag);
  return EXECUTION_SUCCESS;
}

/* ===================================================================== *
 * DNS-6.1 — resolver daemon (forwarding + caching).
 *
 * A long-running UDP resolver: per query it checks a bounded TTL cache,
 * then local static records (hermetic answers / a tiny local zone), then
 * forwards to an upstream nameserver and caches the reply. Adds a CIDR
 * allow-list per listener and answers CHAOS `version.bind`/`version.server`
 * TXT with a fixed string. Recursion-from-root-hints is a later pass; this
 * is the forwarding-resolver + cache + ACL slice with its acceptance tests.
 * ===================================================================== */

#define BDR_CACHE_MAX 512
#define BDR_MSG_MAX   1500
#define BDR_LOCAL_MAX 64
#define BDR_ACL_MAX   16

#if defined(BASH_OS_DOQ)
#define BDA_DOQ_HAVE_QUIC 1
#define BDA_DOQ_BACKEND "ngtcp2-awslc"
#else
#define BDA_DOQ_HAVE_QUIC 0
#define BDA_DOQ_BACKEND "none"
#endif
#define BDA_DOQ_SELECTED_BACKEND "ngtcp2"
#define BDA_DOQ_BACKEND_VERSION "1.23.0"
#define BDA_DOQ_BUILD_FLAG "BASH_OS_DOQ=1"
#define BDA_DOQ_ALPN "doq"
#define BDA_DOQ_MAX_WIRE BDR_MSG_MAX

#define BD_TSIG_MAX_KEYS 16
#define BD_TSIG_SECRET_MAX 256
#define BD_TSIG_MAC_MAX 64
#define BD_TSIG_HMAC_SHA256_LEN 32
#define BD_TSIG_DEFAULT_FUDGE 300

enum {
  BD_TSIG_OK      = 0,
  BD_TSIG_FORMERR = 1,
  BD_TSIG_NOTAUTH = 9,
  BD_TSIG_BADSIG  = 16,
  BD_TSIG_BADKEY  = 17,
  BD_TSIG_BADTIME = 18
};

typedef struct {
  char name[256];                 /* canonical owner, no trailing dot */
  unsigned char secret[BD_TSIG_SECRET_MAX];
  size_t secret_len;
} bd_tsig_key_t;

typedef struct {
  bd_tsig_key_t keys[BD_TSIG_MAX_KEYS];
  int n;
} bd_tsig_store_t;

struct bdr_cache_ent {
  char          key[320];                 /* "qname|qtype|qclass", qname lc */
  unsigned char reply[BDR_MSG_MAX];
  size_t        rlen;
  time_t        expiry;
  int           used;
};
struct bdr_local {
  char     name[256];                     /* lowercased owner */
  uint16_t type;                          /* 1 A, 16 TXT */
  uint32_t ttl;
  unsigned char rdata[256];
  uint16_t rdlen;
};

/* length-prefixed TCP read/write helpers (defined with the auth-serve code). */
static int bda_readn (int fd, unsigned char *b, size_t n);
static int bda_writen (int fd, const unsigned char *b, size_t n);

static void
bdr_lower (char *s)
{
  for (; *s; s++) if (*s >= 'A' && *s <= 'Z') *s += 32;
}

/* CIDR membership: is ip (network-order in_addr) inside "a.b.c.d/n"? */
static int
bdr_cidr_match (struct in_addr ip, const char *cidr)
{
  char buf[64]; strncpy (buf, cidr, sizeof buf - 1); buf[sizeof buf - 1] = '\0';
  char *slash = strchr (buf, '/');
  int bits = 32;
  if (slash) { *slash = '\0'; bits = atoi (slash + 1); }
  if (bits < 0 || bits > 32) return 0;
  struct in_addr net;
  if (inet_pton (AF_INET, buf, &net) != 1) return 0;
  uint32_t mask = bits == 0 ? 0 : htonl (0xffffffffu << (32 - bits));
  return (ip.s_addr & mask) == (net.s_addr & mask);
}

static int
bdr_cidr_match6 (const struct in6_addr *ip, const char *cidr)
{
  char buf[128]; strncpy (buf, cidr, sizeof buf - 1); buf[sizeof buf - 1] = '\0';
  char *slash = strchr (buf, '/');
  int bits = 128;
  if (slash) { *slash = '\0'; bits = atoi (slash + 1); }
  if (bits < 0 || bits > 128) return 0;
  struct in6_addr net;
  if (inet_pton (AF_INET6, buf, &net) != 1) return 0;
  int full = bits / 8;
  int rem = bits % 8;
  if (full > 0 && memcmp (ip->s6_addr, net.s6_addr, (size_t) full) != 0)
    return 0;
  if (rem > 0)
    {
      unsigned char mask = (unsigned char) (0xffu << (8 - rem));
      if ((ip->s6_addr[full] & mask) != (net.s6_addr[full] & mask))
        return 0;
    }
  return 1;
}

static int
bdr_cidr_match_peer (const struct sockaddr_storage *peer, const char *cidr)
{
  if (!peer || !cidr || !*cidr)
    return 0;
  if (strchr (cidr, ':'))
    {
      if (peer->ss_family != AF_INET6)
        return 0;
      const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6 *) peer;
      return bdr_cidr_match6 (&sa6->sin6_addr, cidr);
    }
  struct in_addr v4;
  return bd_peer_v4 (peer, &v4) == 0 && bdr_cidr_match (v4, cidr);
}

/* Parse the question of a received query: qname (lowercased), qtype, qclass. */
static int
bdr_parse_question (const unsigned char *q, size_t qlen, char *qname, size_t nsz,
                    uint16_t *qtype, uint16_t *qclass)
{
  if (qlen < 12) return -1;
  size_t off = 12;
  if (bd_decode_name (q, qlen, &off, qname, nsz, 0) < 0) return -1;
  if (off + 4 > qlen) return -1;
  *qtype  = bd_rd16 (q + off);
  *qclass = bd_rd16 (q + off + 2);
  bdr_lower (qname);
  return 0;
}

/* Smallest TTL across the answer + authority sections (cache lifetime). */
static uint32_t
bdr_min_ttl (const unsigned char *r, size_t rlen)
{
  if (rlen < 12) return 60;
  uint16_t qd = bd_rd16 (r + 4), an = bd_rd16 (r + 6), ns = bd_rd16 (r + 8);
  size_t off = 12;
  for (int i = 0; i < qd; i++) { if (bd_skip_name (r, rlen, &off) < 0) return 60; off += 4; }
  uint32_t mn = 0xffffffffu; int seen = 0, total = (int) an + (int) ns;
  for (int i = 0; i < total; i++) {
    if (bd_skip_name (r, rlen, &off) < 0) break;
    if (off + 10 > rlen) break;
    off += 4;                              /* type + class */
    uint32_t ttl = bd_rd32 (r + off); off += 4;
    uint16_t rdl = bd_rd16 (r + off); off += 2; off += rdl;
    if (ttl < mn) mn = ttl;
    seen = 1;
  }
  return seen ? (mn ? mn : 60) : 60;
}

/* Forward a raw query to an upstream nameserver; raw reply into `reply`. */
static int
bdr_forward (const unsigned char *q, size_t qlen, const char *upstream,
             int timeout_ms, unsigned char *reply, size_t rsz)
{
  struct sockaddr_storage sa;
  socklen_t sl = 0;
  if (bd_make_sockaddr (upstream, bd_server_port (), &sa, &sl) < 0)
    return -1;
  int s = socket (bd_sock_family (&sa), SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (s < 0) return -1;
  struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
  setsockopt (s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  setsockopt (s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
  if (sendto (s, q, qlen, 0, (struct sockaddr *) &sa, sl) < 0) { close (s); return -1; }
  ssize_t n = recvfrom (s, reply, rsz, 0, NULL, NULL);
  close (s);
  return n < 0 ? -1 : (int) n;
}

/* Build a single-answer reply (QR|RA set) from the query header+question for a
   local static record. Uses a 0xc00c compression pointer to the question name. */
static int
bdr_build_local_reply (const unsigned char *q, size_t qlen, const struct bdr_local *L,
                       unsigned char *out, size_t osz)
{
  /* question length: header(12) + name + 4 */
  size_t off = 12;
  char tmp[256];
  if (bd_decode_name (q, qlen, &off, tmp, sizeof tmp, 0) < 0) return -1;
  off += 4;                                /* qtype + qclass */
  if (off > qlen) return -1;
  size_t qsec = off;
  if (qsec + 12 + L->rdlen > osz) return -1;
  memcpy (out, q, qsec);
  out[2] = 0x84;                           /* QR=1, AA=1 */
  out[3] = 0x80;                           /* RA=1, RCODE=0 */
  out[6] = 0; out[7] = 1;                  /* ANCOUNT = 1 */
  out[8] = 0; out[9] = 0; out[10] = 0; out[11] = 0;
  size_t o = qsec;
  out[o++] = 0xc0; out[o++] = 0x0c;        /* name -> question */
  out[o++] = (unsigned char) (L->type >> 8); out[o++] = (unsigned char) L->type;
  out[o++] = 0; out[o++] = 1;              /* class IN */
  out[o++] = (unsigned char) (L->ttl >> 24); out[o++] = (unsigned char) (L->ttl >> 16);
  out[o++] = (unsigned char) (L->ttl >> 8);  out[o++] = (unsigned char) L->ttl;
  out[o++] = (unsigned char) (L->rdlen >> 8); out[o++] = (unsigned char) L->rdlen;
  memcpy (out + o, L->rdata, L->rdlen); o += L->rdlen;
  return (int) o;
}

/* CHAOS version.bind/version.server TXT reply. */
static int
bdr_build_chaos (const unsigned char *q, size_t qlen, const char *ver,
                 unsigned char *out, size_t osz)
{
  size_t off = 12; char tmp[256];
  if (bd_decode_name (q, qlen, &off, tmp, sizeof tmp, 0) < 0) return -1;
  off += 4;
  size_t qsec = off, vlen = strlen (ver);
  if (vlen > 255 || qsec + 12 + 1 + vlen > osz) return -1;
  memcpy (out, q, qsec);
  out[2] = 0x84; out[3] = 0x00;
  out[6] = 0; out[7] = 1;
  out[8] = 0; out[9] = 0; out[10] = 0; out[11] = 0;
  size_t o = qsec;
  out[o++] = 0xc0; out[o++] = 0x0c;
  out[o++] = 0; out[o++] = 16;             /* TYPE TXT */
  out[o++] = 0; out[o++] = 3;              /* CLASS CHAOS */
  out[o++] = 0; out[o++] = 0; out[o++] = 0; out[o++] = 0;   /* TTL 0 */
  uint16_t rdl = (uint16_t) (1 + vlen);
  out[o++] = (unsigned char) (rdl >> 8); out[o++] = (unsigned char) rdl;
  out[o++] = (unsigned char) vlen;
  memcpy (out + o, ver, vlen); o += vlen;
  return (int) o;
}

/* Raw iterative query: build a DNS query (RD=0) for (qname, qtype/IN), send it
   to `server` at BASHDNS_SERVER_PORT, return the raw reply. Unlike bd_fetch /
   bd_query this does NOT reject rcode!=0 — a resolver must relay NXDOMAIN/
   NODATA verbatim — and bypasses the client rate-limiter/fixture path. */
static int
bdr_query_raw (const char *qname, uint16_t qtype, const char *server,
               int timeout_ms, unsigned char *reply, size_t rsz)
{
  static uint16_t seq = 0; seq++;
  unsigned char q[600]; memset (q, 0, 12);
  q[0] = (unsigned char) (seq >> 8); q[1] = (unsigned char) seq;
  q[4] = 0; q[5] = 1;                       /* QDCOUNT = 1, flags 0 (RD=0) */
  size_t off = 12;
  int wn = bd_name_to_wire (qname, q + off, sizeof q - off);
  if (wn < 0) return -1; off += (size_t) wn;
  if (off + 4 > sizeof q) return -1;
  q[off++] = (unsigned char) (qtype >> 8); q[off++] = (unsigned char) qtype;
  q[off++] = 0; q[off++] = 1;               /* QCLASS = IN */
  struct sockaddr_storage sa;
  socklen_t sl = 0;
  if (bd_make_sockaddr (server, bd_server_port (), &sa, &sl) < 0)
    return -1;
  int s = socket (bd_sock_family (&sa), SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (s < 0) return -1;
  struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
  setsockopt (s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  setsockopt (s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
  if (sendto (s, q, off, 0, (struct sockaddr *) &sa, sl) < 0) { close (s); return -1; }
  ssize_t n = recvfrom (s, reply, rsz, 0, NULL, NULL);
  close (s);
  return n < 0 ? -1 : (int) n;
}

/* Classify one recursion step's reply: 1 = answer present for qtype, 2 = CNAME
   (target -> cname_out), 3 = referral (NS in authority + A glue collected into
   glue[]), 0 = negative / no usable progress. Type numbers are raw (the BDA_*
   enum is defined later in the file): A=1 NS=2 CNAME=5. */
static int
bdr_classify (const unsigned char *r, size_t rlen, uint16_t qtype,
              char *cname_out, size_t cname_sz, char glue[][64], int *nglue, int glue_max)
{
  *nglue = 0; if (cname_out) cname_out[0] = '\0';
  if (rlen < 12) return 0;
  uint16_t qd = bd_rd16 (r + 4), an = bd_rd16 (r + 6), nsc = bd_rd16 (r + 8), arc = bd_rd16 (r + 10);
  size_t off = 12; char nm[256];
  for (int i = 0; i < qd; i++) { if (bd_skip_name (r, rlen, &off) < 0) return 0; off += 4; if (off > rlen) return 0; }
  int has_answer = 0, got_cname = 0;
  for (int i = 0; i < an; i++) {
    if (bd_decode_name (r, rlen, &off, nm, sizeof nm, 0) < 0) return 0;
    if (off + 10 > rlen) return 0;
    uint16_t t = bd_rd16 (r + off); uint16_t rdl = bd_rd16 (r + off + 8); size_t rdat = off + 10;
    if (t == qtype) has_answer = 1;
    else if (t == 5 && !got_cname && cname_out) { size_t c = rdat;
      if (bd_decode_name (r, rlen, &c, cname_out, cname_sz, 0) >= 0) { bdr_lower (cname_out); got_cname = 1; } }
    off = rdat + rdl; if (off > rlen) return 0;
  }
  if (has_answer) return 1;
  if (got_cname) return 2;
  int has_ns = 0;
  for (int i = 0; i < nsc; i++) {
    if (bd_decode_name (r, rlen, &off, nm, sizeof nm, 0) < 0) return 0;
    if (off + 10 > rlen) return 0;
    if (bd_rd16 (r + off) == 2) has_ns = 1;
    off += 10 + bd_rd16 (r + off + 8); if (off > rlen) return 0;
  }
  for (int i = 0; i < arc; i++) {
    if (bd_decode_name (r, rlen, &off, nm, sizeof nm, 0) < 0) break;
    if (off + 10 > rlen) break;
    uint16_t t = bd_rd16 (r + off); uint16_t rdl = bd_rd16 (r + off + 8); size_t rdat = off + 10;
    if (t == 1 && rdl == 4 && *nglue < glue_max) { struct in_addr a; memcpy (&a, r + rdat, 4);
      inet_ntop (AF_INET, &a, glue[*nglue], 64); (*nglue)++; }
    off = rdat + rdl; if (off > rlen) break;
  }
  return (has_ns && *nglue > 0) ? 3 : 0;
}

/* Iterative recursion: resolve (qname0, qtype) from the root-hint servers,
   following referrals (glue) down the delegation chain and CNAMEs, until an
   answer or a negative reply. Returns the final reply length in out[], or -1.
   bd_fetch() targets `server` at BASHDNS_SERVER_PORT (53 in production), so the
   delegation chain shares one port across distinct server IPs. */
static int
bdr_recurse (const char *qname0, uint16_t qtype, char roots[][64], int nroots,
             int timeout_ms, unsigned char *out, size_t osz)
{
  char srv[8][64]; int nsrv = 0;
  for (int i = 0; i < nroots && i < 8; i++) { strncpy (srv[nsrv], roots[i], 63); srv[nsrv][63] = '\0'; nsrv++; }
  char qname[256]; snprintf (qname, sizeof qname, "%s", qname0);
  unsigned char reply[8192];
  for (int step = 0; step < 24 && nsrv > 0; step++) {
    int got = -1;
    for (int si = 0; si < nsrv; si++) {
      int rl = bdr_query_raw (qname, qtype, srv[si], timeout_ms, reply, sizeof reply);
      if (rl >= 12) { got = rl; break; }
    }
    if (got < 0) return -1;
    char cname[256], glue[16][64]; int nglue = 0;
    int kind = bdr_classify (reply, (size_t) got, qtype, cname, sizeof cname, glue, &nglue, 16);
    if (kind == 1 || kind == 0) {                  /* answer or negative -> done */
      if ((size_t) got > osz) return -1;
      memcpy (out, reply, (size_t) got);
      out[2] &= ~0x04; out[3] |= 0x80;             /* clear AA, set RA (recursive answer) */
      return got;
    }
    if (kind == 2) {                               /* CNAME -> restart from roots */
      snprintf (qname, sizeof qname, "%s", cname);
      nsrv = 0; for (int i = 0; i < nroots && i < 8; i++) { strncpy (srv[nsrv], roots[i], 63); srv[nsrv][63] = '\0'; nsrv++; }
      continue;
    }
    nsrv = 0;                                      /* referral -> descend to glue */
    for (int i = 0; i < nglue && i < 8; i++) { strncpy (srv[nsrv], glue[i], 63); srv[nsrv][63] = '\0'; nsrv++; }
  }
  return -1;
}

/* ---- EDNS0 COOKIE (RFC 7873) ---- */

/* Find the client cookie (8 bytes) in the query's OPT COOKIE option (code 10).
   Returns 1 and copies it to cc[] if present, else 0. */
static int
bdr_query_cookie (const unsigned char *q, size_t qlen, unsigned char cc[8])
{
  if (qlen < 12) return 0;
  uint16_t qd = bd_rd16 (q + 4), an = bd_rd16 (q + 6), ns = bd_rd16 (q + 8), ar = bd_rd16 (q + 10);
  size_t off = 12;
  for (int i = 0; i < qd; i++) { if (bd_skip_name (q, qlen, &off) < 0) return 0; off += 4; if (off > qlen) return 0; }
  for (int i = 0; i < an + ns; i++) { if (bd_skip_name (q, qlen, &off) < 0) return 0; if (off + 10 > qlen) return 0; off += 8 + 2 + bd_rd16 (q + off + 8); }
  for (int i = 0; i < ar; i++) {
    if (bd_skip_name (q, qlen, &off) < 0) return 0;
    if (off + 10 > qlen) return 0;
    uint16_t t = bd_rd16 (q + off); uint16_t rdl = bd_rd16 (q + off + 8); size_t rdat = off + 10;
    if (t == 41) {
      size_t p = rdat, end = rdat + rdl;
      while (p + 4 <= end) { uint16_t oc = bd_rd16 (q + p), ol = bd_rd16 (q + p + 2);
        if (oc == 10 && ol >= 8 && p + 4 + 8 <= end) { memcpy (cc, q + p + 4, 8); return 1; }
        p += 4 + ol; }
      return 0;
    }
    off = rdat + rdl;
  }
  return 0;
}

/* The requestor's advertised UDP payload size (OPT class field), or 512 when no
   EDNS OPT is present (RFC 1035 limit). */
static int
bdr_query_udpsize (const unsigned char *q, size_t qlen)
{
  if (qlen < 12) return 512;
  uint16_t qd = bd_rd16 (q + 4), an = bd_rd16 (q + 6), ns = bd_rd16 (q + 8), ar = bd_rd16 (q + 10);
  size_t off = 12;
  for (int i = 0; i < qd; i++) { if (bd_skip_name (q, qlen, &off) < 0) return 512; off += 4; if (off > qlen) return 512; }
  for (int i = 0; i < an + ns; i++) { if (bd_skip_name (q, qlen, &off) < 0) return 512; if (off + 10 > qlen) return 512; off += 8 + 2 + bd_rd16 (q + off + 8); }
  for (int i = 0; i < ar; i++) {
    if (bd_skip_name (q, qlen, &off) < 0) return 512;
    if (off + 10 > qlen) return 512;
    if (bd_rd16 (q + off) == 41) { int sz = bd_rd16 (q + off + 2); return sz < 512 ? 512 : sz; }
    off += 10 + bd_rd16 (q + off + 8);
  }
  return 512;
}

/* Server cookie = FNV-1a(secret || client_cookie || client_ip), 8 bytes. Not a
   cryptographic PRF (RFC 7873 suggests SipHash); adequate for off-path spoof
   mitigation in the bash-os MVP and documented as such. */
static void
bdr_server_cookie (const unsigned char secret[16], const unsigned char cc[8], struct in_addr ip, unsigned char sc[8])
{
  uint64_t h = 1469598103934665603ULL;
  for (int i = 0; i < 16; i++) { h ^= secret[i]; h *= 1099511628211ULL; }
  for (int i = 0; i < 8; i++)  { h ^= cc[i];     h *= 1099511628211ULL; }
  unsigned char *ipb = (unsigned char *) &ip.s_addr;
  for (int i = 0; i < 4; i++)  { h ^= ipb[i];    h *= 1099511628211ULL; }
  for (int i = 0; i < 8; i++) sc[i] = (unsigned char) (h >> (8 * i));
}

static void
bdr_server_cookie_peer (const unsigned char secret[16], const unsigned char cc[8],
                        const struct sockaddr_storage *peer, unsigned char sc[8])
{
  uint64_t h = 1469598103934665603ULL;
  for (int i = 0; i < 16; i++) { h ^= secret[i]; h *= 1099511628211ULL; }
  for (int i = 0; i < 8; i++)  { h ^= cc[i];     h *= 1099511628211ULL; }

  struct in_addr v4;
  if (bd_peer_v4 (peer, &v4) == 0)
    {
      bdr_server_cookie (secret, cc, v4, sc);
      return;
    }
  else if (peer && peer->ss_family == AF_INET6)
    {
      const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6 *) peer;
      const unsigned char *ipb = sa6->sin6_addr.s6_addr;
      for (int i = 0; i < 16; i++) { h ^= ipb[i]; h *= 1099511628211ULL; }
    }
  for (int i = 0; i < 8; i++) sc[i] = (unsigned char) (h >> (8 * i));
}

/* Remove any OPT RR from the additional section (so we can re-add our own). */
static void
bdr_strip_opt (unsigned char *r, size_t *rlen)
{
  if (*rlen < 12) return;
  uint16_t qd = bd_rd16 (r + 4), an = bd_rd16 (r + 6), ns = bd_rd16 (r + 8), ar = bd_rd16 (r + 10);
  size_t off = 12;
  for (int i = 0; i < qd; i++) { if (bd_skip_name (r, *rlen, &off) < 0) return; off += 4; }
  for (int i = 0; i < an + ns; i++) { if (bd_skip_name (r, *rlen, &off) < 0) return; if (off + 10 > *rlen) return; off += 8 + 2 + bd_rd16 (r + off + 8); }
  for (int i = 0; i < ar; i++) {
    size_t rrstart = off;
    if (bd_skip_name (r, *rlen, &off) < 0) return;
    if (off + 10 > *rlen) return;
    uint16_t t = bd_rd16 (r + off); uint16_t rdl = bd_rd16 (r + off + 8); size_t rrend = off + 10 + rdl;
    if (rrend > *rlen) return;
    if (t == 41) {
      memmove (r + rrstart, r + rrend, *rlen - rrend);
      *rlen -= (rrend - rrstart);
      ar--; r[10] = (unsigned char) (ar >> 8); r[11] = (unsigned char) ar;
      return;
    }
    off = rrend;
  }
}

/* Append an OPT RR carrying the COOKIE (client||server, 16 bytes) to resp. */
static int
bdr_append_cookie (unsigned char *r, size_t *rlen, size_t rsz, const unsigned char cc[8], const unsigned char sc[8])
{
  if (*rlen + 11 + 4 + 16 > rsz) return -1;
  size_t o = *rlen;
  r[o++] = 0;                          /* root owner */
  r[o++] = 0; r[o++] = 41;             /* TYPE OPT */
  r[o++] = 0x10; r[o++] = 0x00;        /* UDP payload 4096 */
  r[o++] = 0; r[o++] = 0; r[o++] = 0; r[o++] = 0;   /* ext-rcode/version/flags */
  r[o++] = 0; r[o++] = 4 + 16;         /* RDLEN = one 16-byte COOKIE option */
  r[o++] = 0; r[o++] = 10;             /* OPTION-CODE COOKIE */
  r[o++] = 0; r[o++] = 16;             /* OPTION-LENGTH */
  memcpy (r + o, cc, 8); o += 8;
  memcpy (r + o, sc, 8); o += 8;
  uint16_t ar = bd_rd16 (r + 10) + 1; r[10] = (unsigned char) (ar >> 8); r[11] = (unsigned char) ar;
  *rlen = o;
  return 0;
}

/* Resolver context + the factored per-query resolver (shared by UDP and TCP). */
struct bdr_ctx {
  struct bdr_cache_ent *cache;
  struct bdr_local *local; int nlocal;
  char (*roots)[64]; int nroots; int recurse;
  const char *upstream; const char *version;
  int timeout_ms;
  unsigned char secret[16];
  /* F02 policy engines (default-off; opaque to avoid forward type churn). */
  void *rpz; int nrpz;                  /* struct bda_rpz[] when nrpz>0 */
  int dns64_on; unsigned char dns64_prefix[12];
};

/* RPZ pre-resolution hook (defined after the engine code below). Returns the
   response length on a short-circuiting RPZ action, or BD_RPZ_NO_RESPONSE
   (defined later as -2) to continue normal resolution. */
static int bdr_rpz_hook (struct bdr_ctx *c, const unsigned char *qbuf, size_t qn,
                         const char *qname, const struct sockaddr_storage *client,
                         unsigned char *resp, size_t rsz);
/* DNS64 hook: on an AAAA query with no native AAAA, re-query A and synthesize.
   Returns synthesized rlen (>0) or -1 (nothing synthesized). */
static int bdr_dns64_hook (struct bdr_ctx *c, const unsigned char *qbuf, size_t qn,
                           const char *qname, uint16_t qtype,
                           unsigned char *resp, size_t rsz);
/* Load up to `n` RPZ master files into a freshly malloc'd struct bda_rpz[]
   returned via *out (opaque); *nout receives the loaded count. Returns 0 on
   success (even if some files failed; those are skipped with a warning), -1
   on allocation failure. Free with bdr_resolver_free_rpz. */
static int bdr_resolver_load_rpz (char paths[][512], int n, void **out, int *nout);
static void bdr_resolver_free_rpz (void *rpz, int n);

/* Resolve one query into resp[]. Returns rlen (>0) or -1; *was_hit=1 on a cache
   hit. Handles CHAOS, cache (with RFC 2308 negative-TTL cap), local statics,
   forwarding, recursion, SERVFAIL, and EDNS COOKIE echo. */
static int
bdr_resolve (struct bdr_ctx *c, const unsigned char *qbuf, size_t qn,
             const struct sockaddr_storage *client, unsigned char *resp, size_t rsz, int *was_hit)
{
  *was_hit = 0;
  char qname[256]; uint16_t qtype, qclass;
  if (bdr_parse_question (qbuf, qn, qname, sizeof qname, &qtype, &qclass) < 0) return -1;
  int rl = -1;

  if (qclass == 3 && qtype == 16 &&
      (!strcmp (qname, "version.bind") || !strcmp (qname, "version.server")))
    { rl = bdr_build_chaos (qbuf, qn, c->version, resp, rsz); goto finish; }

  char key[320]; snprintf (key, sizeof key, "%s|%u|%u", qname, qtype, qclass);
  time_t now = time (NULL);

  for (int i = 0; i < BDR_CACHE_MAX; i++)
    if (c->cache[i].used && c->cache[i].expiry > now && !strcmp (c->cache[i].key, key))
      { memcpy (resp, c->cache[i].reply, c->cache[i].rlen); rl = (int) c->cache[i].rlen; *was_hit = 1; goto finish; }

  /* RPZ (F02): consult policy zones before normal resolution. A matching
     action short-circuits; PASSTHRU/none fall through. Default-off. */
  if (c->nrpz > 0 && qclass == 1) {
    int prl = bdr_rpz_hook (c, qbuf, qn, qname, client, resp, rsz);
    if (prl != -2 /* BD_RPZ_NO_RESPONSE */) { rl = prl; if (rl > 0) goto finish; }
  }

  int answered = 0;
  if (qclass == 1)
    for (int i = 0; i < c->nlocal; i++)
      if (c->local[i].type == qtype && !strcmp (c->local[i].name, qname))
        { rl = bdr_build_local_reply (qbuf, qn, &c->local[i], resp, rsz); if (rl > 0) answered = 1; break; }
  if (!answered && c->upstream && c->upstream[0])
    { rl = bdr_forward (qbuf, qn, c->upstream, c->timeout_ms, resp, rsz); if (rl > 0) answered = 1; }
  if (!answered && c->recurse && c->nroots > 0)
    { rl = bdr_recurse (qname, qtype, c->roots, c->nroots, c->timeout_ms, resp, rsz); if (rl > 0) answered = 1; }

  /* DNS64 (F02): if this is an AAAA query that produced no native AAAA
     (NODATA / NXDOMAIN / no answer), re-query A and synthesize AAAA into the
     configured /96 prefix. Default-off. */
  if (c->dns64_on && qclass == 1 && qtype == BD_T_AAAA) {
    int native_aaaa = (answered && rl > 12 && (resp[3] & 0x0f) == 0 && bd_rd16 (resp + 6) > 0);
    if (!native_aaaa) {
      int srl = bdr_dns64_hook (c, qbuf, qn, qname, qtype, resp, rsz);
      if (srl > 0) { rl = srl; answered = 1; }
    }
  }

  if (answered && rl > 0) {
    uint32_t ttl = bdr_min_ttl (resp, (size_t) rl);
    int negative = (resp[3] & 0x0f) != 0 || bd_rd16 (resp + 6) == 0;  /* rcode!=0 or no answers */
    if (negative && ttl > 3600) ttl = 3600;                           /* RFC 2308 negative cap */
    int slot = -1;
    for (int i = 0; i < BDR_CACHE_MAX; i++) if (!c->cache[i].used || c->cache[i].expiry <= now) { slot = i; break; }
    if (slot < 0) slot = 0;
    if ((size_t) rl <= sizeof c->cache[slot].reply) {
      strncpy (c->cache[slot].key, key, sizeof c->cache[slot].key - 1); c->cache[slot].key[sizeof c->cache[slot].key - 1] = '\0';
      memcpy (c->cache[slot].reply, resp, (size_t) rl);
      c->cache[slot].rlen = (size_t) rl; c->cache[slot].expiry = now + ttl; c->cache[slot].used = 1;
    }
  } else if (rsz >= 12) {                          /* SERVFAIL */
    memcpy (resp, qbuf, 12); resp[2] = 0x80; resp[3] = 0x82;
    resp[6] = resp[7] = resp[8] = resp[9] = resp[10] = resp[11] = 0; rl = 12;
  }

finish:
  if (rl <= 0) return -1;
  resp[0] = qbuf[0]; resp[1] = qbuf[1];             /* echo client ID */
  unsigned char cc[8];
  if (bdr_query_cookie (qbuf, qn, cc)) {
    unsigned char sc[8]; bdr_server_cookie_peer (c->secret, cc, client, sc);
    size_t rl2 = (size_t) rl; bdr_strip_opt (resp, &rl2);
    if (bdr_append_cookie (resp, &rl2, rsz, cc, sc) == 0) rl = (int) rl2;
  }
  return rl;
}

/* ---- ephemeral on-disk cache (RFC-style warm restart) ---- */
struct bdr_disk_hdr { uint32_t magic; uint32_t n; };
#define BDR_DISK_MAGIC 0x42435231u                 /* "BCR1" */

static void
bdr_cache_save (struct bdr_cache_ent *cache, const char *path)
{
  if (!path || !*path) return;
  char tmp[640]; snprintf (tmp, sizeof tmp, "%s.tmp", path);
  FILE *f = fopen (tmp, "wb"); if (!f) return;
  time_t now = time (NULL);
  struct bdr_disk_hdr h = { BDR_DISK_MAGIC, 0 };
  fwrite (&h, sizeof h, 1, f);
  uint32_t n = 0;
  for (int i = 0; i < BDR_CACHE_MAX; i++) {
    if (!cache[i].used || cache[i].expiry <= now) continue;
    uint32_t klen = (uint32_t) strlen (cache[i].key);
    uint32_t rlen = (uint32_t) cache[i].rlen;
    int64_t exp = (int64_t) cache[i].expiry;
    fwrite (&exp, sizeof exp, 1, f);
    fwrite (&klen, sizeof klen, 1, f); fwrite (cache[i].key, 1, klen, f);
    fwrite (&rlen, sizeof rlen, 1, f); fwrite (cache[i].reply, 1, rlen, f);
    n++;
  }
  fseek (f, 0, SEEK_SET); h.n = n; fwrite (&h, sizeof h, 1, f);
  fclose (f);
  rename (tmp, path);
}

static int
bdr_cache_load (struct bdr_cache_ent *cache, const char *path)
{
  if (!path || !*path) return 0;
  FILE *f = fopen (path, "rb"); if (!f) return 0;
  struct bdr_disk_hdr h;
  if (fread (&h, sizeof h, 1, f) != 1 || h.magic != BDR_DISK_MAGIC) { fclose (f); return 0; }
  time_t now = time (NULL); int loaded = 0, slot = 0;
  for (uint32_t i = 0; i < h.n && slot < BDR_CACHE_MAX; i++) {
    int64_t exp; uint32_t klen, rlen;
    if (fread (&exp, sizeof exp, 1, f) != 1) break;
    if (fread (&klen, sizeof klen, 1, f) != 1 || klen >= sizeof cache[0].key) break;
    if (fread (cache[slot].key, 1, klen, f) != klen) break; cache[slot].key[klen] = '\0';
    if (fread (&rlen, sizeof rlen, 1, f) != 1 || rlen > sizeof cache[0].reply) break;
    if (fread (cache[slot].reply, 1, rlen, f) != rlen) break;
    if ((time_t) exp <= now) continue;              /* drop already-expired */
    cache[slot].rlen = rlen; cache[slot].expiry = (time_t) exp; cache[slot].used = 1;
    slot++; loaded++;
  }
  fclose (f);
  return loaded;
}

static int
bd_resolver_serve_cmd (WORD_LIST *args)
{
  const char *bind_addr = NULL;
  int port = 0;                            /* 0 -> bd_server_port() */
  int listen_family = AF_UNSPEC, v6only = 0;
  char upstream[64] = "";
  const char *version_str = "dns";
  long max_queries = -1;                   /* -1 = run forever */
  int timeout_ms = 2000;
  static struct bdr_cache_ent cache[BDR_CACHE_MAX];
  static struct bdr_local local[BDR_LOCAL_MAX];
  int nlocal = 0;
  char acl[BDR_ACL_MAX][64]; int nacl = 0;
  char roots[8][64]; int nroots = 0; int recurse = 0;   /* iterative recursion */
  const char *cache_file = NULL;                         /* ephemeral on-disk cache */
  void *rpz = NULL; int nrpz = 0;                        /* RPZ policy zones (default-off) */
  char rpz_paths[8][512]; int nrpz_paths = 0;            /* 8 == BDA_RPZ_MAX (forward-decl ok) */
  int dns64_on = 0; unsigned char dns64_prefix[12];      /* DNS64 /96 prefix (default-off) */
  memset (dns64_prefix, 0, sizeof dns64_prefix);

  for (; args; args = args->next) {
    const char *w = args->word->word;
    if (!strcmp (w, "--listen") && args->next) { bind_addr = args->next->word->word; args = args->next; }
    else if (!strcmp (w, "--inet6")) { listen_family = AF_INET6; }
    else if (!strcmp (w, "--v6only")) { listen_family = AF_INET6; v6only = 1; }
    else if (!strcmp (w, "--port") && args->next) { port = atoi (args->next->word->word); args = args->next; }
    else if (!strcmp (w, "--upstream") && args->next) { strncpy (upstream, args->next->word->word, sizeof upstream - 1); args = args->next; }
    else if (!strcmp (w, "--version") && args->next) { version_str = args->next->word->word; args = args->next; }
    else if (!strcmp (w, "--max-queries") && args->next) { max_queries = atol (args->next->word->word); args = args->next; }
    else if (!strcmp (w, "--timeout") && args->next) { timeout_ms = atoi (args->next->word->word); args = args->next; }
    else if (!strcmp (w, "--recurse")) { recurse = 1; }
    else if (!strcmp (w, "--cache-file") && args->next) { cache_file = args->next->word->word; args = args->next; }
    else if (!strcmp (w, "--root-hints") && args->next) {
      /* comma-separated root server IPs */
      char spec[512]; strncpy (spec, args->next->word->word, sizeof spec - 1); spec[sizeof spec - 1] = '\0';
      char *p = spec, *c;
      while (p && *p && nroots < 8) { c = strchr (p, ','); if (c) *c = '\0';
        strncpy (roots[nroots], p, 63); roots[nroots][63] = '\0'; nroots++; p = c ? c + 1 : NULL; }
      recurse = 1; args = args->next;
    }
    else if (!strcmp (w, "--allow") && args->next) {
      if (nacl < BDR_ACL_MAX) { strncpy (acl[nacl], args->next->word->word, 63); acl[nacl][63] = '\0'; nacl++; }
      args = args->next;
    }
    else if (!strcmp (w, "--rpz") && args->next) {
      if (nrpz_paths >= 8) { builtin_error ("resolver-serve: too many --rpz (max 8)"); return EX_USAGE; }
      snprintf (rpz_paths[nrpz_paths], sizeof rpz_paths[nrpz_paths], "%s", args->next->word->word);
      nrpz_paths++; args = args->next;
    }
    else if (!strcmp (w, "--dns64") && args->next) {
      /* PREFIX/96 — require an explicit /96 and parse the 96-bit prefix. */
      char spec[128]; snprintf (spec, sizeof spec, "%s", args->next->word->word);
      char *slash = strchr (spec, '/');
      if (!slash || atoi (slash + 1) != 96) { builtin_error ("resolver-serve: --dns64 needs PREFIX/96"); return EX_USAGE; }
      *slash = '\0';
      struct in6_addr p6;
      if (inet_pton (AF_INET6, spec, &p6) != 1) { builtin_error ("resolver-serve: --dns64 bad IPv6 prefix: %s", spec); return EX_USAGE; }
      memcpy (dns64_prefix, &p6, 12);                    /* high 96 bits */
      dns64_on = 1; args = args->next;
    }
    else if (!strcmp (w, "--local-a") && args->next && nlocal < BDR_LOCAL_MAX) {
      /* NAME=IP */
      char spec[320]; strncpy (spec, args->next->word->word, sizeof spec - 1); spec[sizeof spec - 1] = '\0';
      char *eq = strchr (spec, '='); if (!eq) { builtin_error ("--local-a needs NAME=IP"); return EX_USAGE; }
      *eq = '\0';
      struct in_addr a;
      if (inet_pton (AF_INET, eq + 1, &a) != 1) { builtin_error ("--local-a bad IP: %s", eq + 1); return EX_USAGE; }
      struct bdr_local *L = &local[nlocal++];
      strncpy (L->name, spec, sizeof L->name - 1); L->name[sizeof L->name - 1] = '\0'; bdr_lower (L->name);
      L->type = 1; L->ttl = 300; memcpy (L->rdata, &a, 4); L->rdlen = 4;
      args = args->next;
    }
    else { builtin_error ("resolver-serve: unknown option: %s", w); return EX_USAGE; }
  }

  if (port == 0) port = bd_server_port ();
  if (!bind_addr)
    bind_addr = (listen_family == AF_INET6) ? "::1" : "127.0.0.1";

  /* Default root hints (IANA root servers a–m) when --recurse is set without
     explicit --root-hints. */
  if (recurse && nroots == 0) {
    static const char *rh[] = { "198.41.0.4", "199.9.14.201", "192.33.4.12",
      "199.7.91.13", "192.203.230.10", "192.5.5.241", "192.112.36.4",
      "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129",
      "199.7.83.42", "202.12.27.33" };
    for (size_t i = 0; i < sizeof rh / sizeof rh[0] && nroots < 8; i++)
      { strncpy (roots[nroots], rh[i], 63); roots[nroots][63] = '\0'; nroots++; }
  }

  /* Load RPZ policy zones (F02, default-off). */
  if (bdr_resolver_load_rpz (rpz_paths, nrpz_paths, &rpz, &nrpz) < 0)
    { builtin_error ("resolver-serve: out of memory loading --rpz"); return EXECUTION_FAILURE; }

  int us = -1, ts = -1;
  if (bd_bind_dgram_stream (bind_addr, port, listen_family, v6only, &us, &ts) < 0)
    { bdr_resolver_free_rpz (rpz, nrpz); return EXECUTION_FAILURE; }
  listen (ts, 8);

  /* Resolver context (shared by the UDP and TCP paths). */
  struct bdr_ctx ctx;
  ctx.cache = cache; ctx.local = local; ctx.nlocal = nlocal;
  ctx.roots = roots; ctx.nroots = nroots; ctx.recurse = recurse;
  ctx.upstream = upstream[0] ? upstream : NULL; ctx.version = version_str;
  ctx.timeout_ms = timeout_ms;
  ctx.rpz = rpz; ctx.nrpz = nrpz;
  ctx.dns64_on = dns64_on; memcpy (ctx.dns64_prefix, dns64_prefix, 12);
  { uint64_t sd = (uint64_t) getpid () ^ ((uint64_t) time (NULL) << 17);
    for (int i = 0; i < 16; i++) ctx.secret[i] = (unsigned char) ((sd >> ((i % 8) * 8)) ^ (uint64_t) (i * 97 + 13)); }

  /* Warm the cache from the ephemeral on-disk snapshot (honors remaining TTLs). */
  if (cache_file) bdr_cache_load (cache, cache_file);

  long queries = 0, hits = 0, misses = 0, denied = 0;
  while (max_queries < 0 || queries < max_queries) {
    fd_set rf; FD_ZERO (&rf); FD_SET (us, &rf); FD_SET (ts, &rf);
    int mx = us > ts ? us : ts;
    if (select (mx + 1, &rf, NULL, NULL, NULL) < 0) { if (errno == EINTR) continue; break; }

    /* ---- UDP ---- */
    if (FD_ISSET (us, &rf)) {
      unsigned char qbuf[BDR_MSG_MAX];
      struct sockaddr_storage from; socklen_t fl = sizeof from;
      ssize_t qn = recvfrom (us, qbuf, sizeof qbuf, 0, (struct sockaddr *) &from, &fl);
      if (qn >= 12) {
        queries++;
        int allowed = 1;
        if (nacl > 0) { allowed = 0; for (int i = 0; i < nacl; i++) if (bdr_cidr_match_peer (&from, acl[i])) { allowed = 1; break; } }
        if (!allowed) denied++;
        else {
          unsigned char resp[BDR_MSG_MAX]; int hit = 0;
          int rl = bdr_resolve (&ctx, qbuf, (size_t) qn, &from, resp, sizeof resp, &hit);
          if (rl > 0) {
            int budget = bdr_query_udpsize (qbuf, (size_t) qn);
            if (rl > budget) {                    /* too big for UDP -> TC=1, client retries TCP */
              unsigned char tc[BDR_MSG_MAX]; size_t qoff = 12; char nmt[256];
              if (bd_decode_name (qbuf, (size_t) qn, &qoff, nmt, sizeof nmt, 0) >= 0) { qoff += 4;
                if (qoff <= (size_t) qn) { memcpy (tc, qbuf, qoff); tc[2] = 0x82; tc[3] = 0x80; /* QR|TC, RA */
                  tc[6] = tc[7] = tc[8] = tc[9] = tc[10] = tc[11] = 0;
                  sendto (us, tc, qoff, 0, (struct sockaddr *) &from, fl); } }
            } else
              sendto (us, resp, (size_t) rl, 0, (struct sockaddr *) &from, fl);
            if (hit) hits++; else misses++;
          } else misses++;
        }
      }
    }

    /* ---- TCP (full answers, no truncation) ---- */
    if (FD_ISSET (ts, &rf)) {
      struct sockaddr_storage cl; socklen_t cll = sizeof cl;
      int c = accept (ts, (struct sockaddr *) &cl, &cll);
      if (c >= 0) {
        queries++;
        struct timeval tv = { 5, 0 }; setsockopt (c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        int allowed = 1;
        if (nacl > 0) { allowed = 0; for (int i = 0; i < nacl; i++) if (bdr_cidr_match_peer (&cl, acl[i])) { allowed = 1; break; } }
        unsigned char lb[2];
        if (allowed && bda_readn (c, lb, 2) == 0) {
          int ml = (lb[0] << 8) | lb[1];
          if (ml >= 12 && ml <= BDR_MSG_MAX) {
            unsigned char qmsg[BDR_MSG_MAX];
            if (bda_readn (c, qmsg, (size_t) ml) == 0) {
              unsigned char resp[BDR_MSG_MAX]; int hit = 0;
              int rl = bdr_resolve (&ctx, qmsg, (size_t) ml, &cl, resp, sizeof resp, &hit);
              if (rl > 0) { unsigned char ol[2] = { (unsigned char) (rl >> 8), (unsigned char) rl };
                if (bda_writen (c, ol, 2) == 0) bda_writen (c, resp, (size_t) rl);
                if (hit) hits++; else misses++; }
            }
          }
        } else if (!allowed) denied++;
        close (c);
      }
    }
  }
  if (cache_file) bdr_cache_save (cache, cache_file);
  close (us); close (ts);
  bdr_resolver_free_rpz (rpz, nrpz);
  fprintf (stderr, "resolver: queries=%ld hits=%ld misses=%ld denied=%ld rpz=%d dns64=%d\n", queries, hits, misses, denied, nrpz, dns64_on);
  return EXECUTION_SUCCESS;
}

/* ===================================================================== *
 * DNS-6.2 — authoritative serving (primary mode).
 *
 * Loads an RFC 1035 master file via sz_load_zone() into an in-memory RR
 * set and answers queries authoritatively (AA bit): exact match, CNAME
 * chase and DNAME subtree synthesis within the zone, '*' wildcards,
 * apex SOA/NS, NODATA (SOA in the
 * authority section), NXDOMAIN, in-bailiwick A/AAAA glue for NS targets,
 * and REFUSED for out-of-zone names. AXFR/IXFR/NOTIFY transfer and rndc
 * control ride on top of this core.
 * ===================================================================== */

/* DNS type numbers used below. */
enum { BDA_A = 1, BDA_NS = 2, BDA_CNAME = 5, BDA_SOA = 6, BDA_PTR = 12,
       BDA_MX = 15, BDA_TXT = 16, BDA_AAAA = 28, BDA_DNAME = 39 };

#define BDA_RR_MAX SZ_RR_MAX     /* zone capacity (shares the signer's cap) */

/* One IXFR journal delta: the RRs deleted and added to advance the zone from
   serial `from` to serial `to` (RFC 1995). del[]/add[] each include the apex
   SOA of their side, so a step is self-describing. */
struct bda_jdelta { bd_rr_t *del; int ndel; bd_rr_t *add; int nadd; uint32_t from, to; };
#define BDA_JRNL_MAX 16                  /* journal depth (oldest deltas evicted) */

struct bda_zone { bd_rr_t *rr; int n; char apex[256]; char path[512]; char origin[256];
                  struct bda_jdelta jrnl[BDA_JRNL_MAX]; int njrnl; };
#define BDA_ZONE_MAX 64                  /* max zones a single auth-serve hosts */
#define BDA_SLAVE_MAX BDA_ZONE_MAX
#define BDA_SLAVE_PRIMARY_MAX 8          /* ordered primaries per slave zone */

/* Forward declaration: defined far below, but the F02 RPZ loader (also above
   its definition) needs it. */
static int bda_load_zone_signed (struct bda_zone *z, const char *path,
                                 const char *origin, const char *sign_key,
                                 int use_nsec3);

/* Lowercase + strip one trailing dot, for owner/qname comparison. */
static void
bda_norm (char *s)
{
  size_t l = strlen (s);
  if (l && s[l - 1] == '.') { s[l - 1] = '\0'; l--; }
  bdr_lower (s);
}

/* Is `qn` equal to or below `apex` (both normalized)? */
static int
bda_in_zone (const char *qn, const char *apex)
{
  if (apex[0] == '\0' || !strcmp (apex, ".")) return 1;     /* root owns all */
  if (!strcmp (qn, apex)) return 1;
  size_t al = strlen (apex), ql = strlen (qn);
  return (ql > al + 1 && qn[ql - al - 1] == '.' && !strcmp (qn + ql - al, apex));
}

/* Normalized owner of record i. */
static void
bda_owner (const struct bda_zone *z, int i, char *out, size_t osz)
{
  snprintf (out, osz, "%s", z->rr[i].owner);
  bda_norm (out);
}

/* Append an RR to out[*off]: owner wire name + type/class/ttl/rdlen/rdata. */
static int
bda_put_rr (unsigned char *out, size_t osz, size_t *off, const char *owner,
            uint16_t type, uint32_t ttl, const unsigned char *rdata, uint16_t rdlen)
{
  unsigned char nm[256];
  int nl = bd_name_to_wire (owner, nm, sizeof nm);
  if (nl < 0 || *off + (size_t) nl + 10 + rdlen > osz) return -1;
  memcpy (out + *off, nm, (size_t) nl); *off += (size_t) nl;
  out[(*off)++] = (unsigned char) (type >> 8); out[(*off)++] = (unsigned char) type;
  out[(*off)++] = 0; out[(*off)++] = 1;                      /* CLASS IN */
  out[(*off)++] = (unsigned char) (ttl >> 24); out[(*off)++] = (unsigned char) (ttl >> 16);
  out[(*off)++] = (unsigned char) (ttl >> 8);  out[(*off)++] = (unsigned char) ttl;
  out[(*off)++] = (unsigned char) (rdlen >> 8); out[(*off)++] = (unsigned char) rdlen;
  memcpy (out + *off, rdata, rdlen); *off += rdlen;
  return 0;
}

static void
bd_tsig_wr16 (unsigned char *p, uint16_t v)
{
  p[0] = (unsigned char) (v >> 8);
  p[1] = (unsigned char) v;
}

static void
bd_tsig_wr32 (unsigned char *p, uint32_t v)
{
  p[0] = (unsigned char) (v >> 24);
  p[1] = (unsigned char) (v >> 16);
  p[2] = (unsigned char) (v >> 8);
  p[3] = (unsigned char) v;
}

static int
bd_tsig_append (unsigned char *out, size_t out_sz, size_t *off,
                const void *buf, size_t len)
{
  if (*off + len > out_sz) return -1;
  memcpy (out + *off, buf, len);
  *off += len;
  return 0;
}

static int
bd_tsig_append_u16 (unsigned char *out, size_t out_sz, size_t *off,
                    uint16_t v)
{
  unsigned char b[2];
  bd_tsig_wr16 (b, v);
  return bd_tsig_append (out, out_sz, off, b, sizeof b);
}

static int
bd_tsig_append_u32 (unsigned char *out, size_t out_sz, size_t *off,
                    uint32_t v)
{
  unsigned char b[4];
  bd_tsig_wr32 (b, v);
  return bd_tsig_append (out, out_sz, off, b, sizeof b);
}

static int
bd_tsig_append_u48 (unsigned char *out, size_t out_sz, size_t *off,
                    uint64_t v)
{
  unsigned char b[6];
  b[0] = (unsigned char) (v >> 40);
  b[1] = (unsigned char) (v >> 32);
  b[2] = (unsigned char) (v >> 24);
  b[3] = (unsigned char) (v >> 16);
  b[4] = (unsigned char) (v >> 8);
  b[5] = (unsigned char) v;
  return bd_tsig_append (out, out_sz, off, b, sizeof b);
}

static int
bd_tsig_name_wire (const char *name, unsigned char *out, size_t out_sz)
{
  return bd_name_to_wire (name, out, out_sz);
}

static const char *
bd_tsig_status_name (int status)
{
  switch (status)
    {
    case BD_TSIG_OK: return "valid";
    case BD_TSIG_FORMERR: return "FORMERR";
    case BD_TSIG_NOTAUTH: return "NOTAUTH";
    case BD_TSIG_BADSIG: return "BADSIG";
    case BD_TSIG_BADKEY: return "BADKEY";
    case BD_TSIG_BADTIME: return "BADTIME";
    default: return "ERROR";
    }
}

static long
bd_tsig_now (void)
{
  const char *e = getenv ("BASHDNS_TSIG_NOW");
  if (e && *e)
    {
      char *end = NULL;
      long v = strtol (e, &end, 10);
      if (end && *end == '\0' && v >= 0) return v;
    }
  return (long) time (NULL);
}

static int
bd_tsig_digest_input (const unsigned char *msg, size_t msg_len,
                      const char *keyname, uint16_t fudge, uint64_t time_signed,
                      uint16_t error, const unsigned char *other, size_t other_len,
                      const unsigned char *prior_mac, size_t prior_mac_len,
                      unsigned char *out, size_t out_sz, size_t *out_len)
{
  size_t off = 0;
  unsigned char namew[256], algw[256];
  int nw = bd_tsig_name_wire (keyname, namew, sizeof namew);
  int aw = bd_tsig_name_wire ("hmac-sha256.", algw, sizeof algw);
  if (nw < 0 || aw < 0 || other_len > 65535 || prior_mac_len > 65535)
    return -1;
  if (prior_mac && prior_mac_len)
    {
      if (bd_tsig_append_u16 (out, out_sz, &off, (uint16_t) prior_mac_len) < 0 ||
          bd_tsig_append (out, out_sz, &off, prior_mac, prior_mac_len) < 0)
        return -1;
    }
  if (bd_tsig_append (out, out_sz, &off, msg, msg_len) < 0 ||
      bd_tsig_append (out, out_sz, &off, namew, (size_t) nw) < 0 ||
      bd_tsig_append_u16 (out, out_sz, &off, BD_C_ANY) < 0 ||
      bd_tsig_append_u32 (out, out_sz, &off, 0) < 0 ||
      bd_tsig_append (out, out_sz, &off, algw, (size_t) aw) < 0 ||
      bd_tsig_append_u48 (out, out_sz, &off, time_signed) < 0 ||
      bd_tsig_append_u16 (out, out_sz, &off, fudge) < 0 ||
      bd_tsig_append_u16 (out, out_sz, &off, error) < 0 ||
      bd_tsig_append_u16 (out, out_sz, &off, (uint16_t) other_len) < 0)
    return -1;
  if (other_len && bd_tsig_append (out, out_sz, &off, other, other_len) < 0)
    return -1;
  *out_len = off;
  return 0;
}

static int
bd_tsig_secret_hex (const bd_tsig_key_t *key, char *out, size_t out_sz)
{
  static const char hx[] = "0123456789abcdef";
  if (!key || key->secret_len * 2 + 1 > out_sz) return -1;
  for (size_t i = 0; i < key->secret_len; i++)
    {
      out[i * 2] = hx[key->secret[i] >> 4];
      out[i * 2 + 1] = hx[key->secret[i] & 15];
    }
  out[key->secret_len * 2] = '\0';
  return 0;
}

static int
bd_tsig_hmac (const bd_tsig_key_t *key, const unsigned char *msg, size_t msg_len,
              unsigned char *mac, size_t mac_sz, size_t *mac_len)
{
  if (!key || mac_sz < BD_TSIG_HMAC_SHA256_LEN) return -1;
  char keyhex[BD_TSIG_SECRET_MAX * 2 + 1];
  if (bd_tsig_secret_hex (key, keyhex, sizeof keyhex) < 0) return -1;
  const char *override = getenv ("BASHDNS_TSIG_HMAC_CMD");
  if (!override || !*override)
    {
      if (mbedtls_hmac_sha256 (key->secret, key->secret_len,
                               msg, msg_len, mac) != 0)
        return -1;
      *mac_len = BD_TSIG_HMAC_SHA256_LEN;
      return 0;
    }

  int p[2], q[2];
  if (pipe (p) < 0) return -1;
  if (pipe (q) < 0) { close (p[0]); close (p[1]); return -1; }
  struct bd_child_guard guard;
  if (bd_child_guard_begin (&guard) < 0)
    { close (p[0]); close (p[1]); close (q[0]); close (q[1]); return -1; }
  pid_t pid = fork ();
  if (pid < 0)
    {
      bd_child_guard_parent_end (&guard);
      close (p[0]); close (p[1]); close (q[0]); close (q[1]);
      return -1;
    }
  if (pid == 0)
    {
      bd_child_guard_child_end (&guard);
      close (p[1]); close (q[0]);
      if (dup2 (p[0], 0) < 0) _exit (127);
      if (dup2 (q[1], 1) < 0) _exit (127);
      close (p[0]); close (q[1]);
      int dn = open ("/dev/null", O_WRONLY);
      if (dn >= 0) { dup2 (dn, 2); close (dn); }
      if (override && *override)
        execlp ("bash", "bash", "-c", override, "_", keyhex, (char *) NULL);
      else
        execlp ("bash", "bash", "-c",
                "builtin crypto hmac-sha256-mbedtls -k \"$1\" -x",
                "_", keyhex, (char *) NULL);
      _exit (127);
    }
  close (p[0]); close (q[1]);
  if (bd_write_all (p[1], msg, msg_len) < 0)
    {
      close (p[1]); close (q[0]);
      int st;
      while (waitpid (pid, &st, 0) < 0 && errno == EINTR)
        ;
      bd_child_guard_parent_end (&guard);
      return -1;
    }
  close (p[1]);

  char hex[1024]; size_t hexlen = 0; ssize_t n;
  while ((n = read (q[0], hex + hexlen, sizeof hex - 1 - hexlen)) > 0)
    { hexlen += (size_t) n; if (hexlen >= sizeof hex - 1) break; }
  close (q[0]);
  hex[hexlen] = '\0';
  int st = 0, wrc;
  while ((wrc = waitpid (pid, &st, 0)) < 0 && errno == EINTR)
    ;
  bd_child_guard_parent_end (&guard);
  if (wrc < 0 || !WIFEXITED (st) || WEXITSTATUS (st) != 0) return -1;
  if (bd_unhex (hex, mac, mac_sz, mac_len) < 0) return -1;
  return (*mac_len == BD_TSIG_HMAC_SHA256_LEN) ? 0 : -1;
}

static int
bd_tsig_ct_eq (const unsigned char *a, const unsigned char *b, size_t n)
{
  unsigned char v = 0;
  for (size_t i = 0; i < n; i++) v |= (unsigned char) (a[i] ^ b[i]);
  return v == 0;
}

static int
bd_tsig_add_key (bd_tsig_store_t *st, const char *name, const char *alg,
                 const char *b64)
{
  if (!st || !name || !alg || !b64 || st->n >= BD_TSIG_MAX_KEYS) return -1;
  char an[256];
  if (bd_canon_owner (alg, an, sizeof an) < 0) return -1;
  if (strcasecmp (an, "hmac-sha256") != 0) return -1;
  bd_tsig_key_t *k = &st->keys[st->n];
  memset (k, 0, sizeof *k);
  if (bd_canon_owner (name, k->name, sizeof k->name) < 0) return -1;
  if (bd_unb64 (b64, k->secret, sizeof k->secret, &k->secret_len) < 0 ||
      k->secret_len == 0)
    return -1;
  st->n++;
  return 0;
}

static int
bd_tsig_add_inline (bd_tsig_store_t *st, const char *spec)
{
  char buf[1024];
  if (!spec || strlen (spec) >= sizeof buf) return -1;
  strcpy (buf, spec);
  char *a = strchr (buf, ':');
  if (!a) return -1;
  *a++ = '\0';
  char *s = strchr (a, ':');
  if (!s) return -1;
  *s++ = '\0';
  return bd_tsig_add_key (st, buf, a, s);
}

static void
bd_tsig_clean_token (char *s)
{
  if (!s) return;
  while (*s == '"' || *s == '\'' || *s == ' ' || *s == '\t') memmove (s, s + 1, strlen (s));
  size_t n = strlen (s);
  while (n > 0 && (s[n - 1] == ';' || s[n - 1] == '}' || s[n - 1] == '"' ||
                   s[n - 1] == '\'' || s[n - 1] == ' ' || s[n - 1] == '\t'))
    s[--n] = '\0';
}

static int
bd_tsig_load_keys (bd_tsig_store_t *st, const char *path)
{
  FILE *f = fopen (path, "r");
  if (!f) { builtin_error ("tsig: open %s: %s", path, strerror (errno)); return -1; }
  char line[1024], name[256] = "", alg[64] = "", secret[512] = "";
  int in_key = 0, rc = 0;
  while (fgets (line, sizeof line, f))
    {
      char *hash = strchr (line, '#'); if (hash) *hash = '\0';
      hash = strchr (line, ';');
      (void) hash; /* semicolons are stripped token-by-token below. */
      char *tok[16]; int nt = 0;
      for (char *p = strtok (line, " \t\r\n{}"); p && nt < 16; p = strtok (NULL, " \t\r\n{}"))
        { bd_tsig_clean_token (p); if (*p) tok[nt++] = p; }
      for (int i = 0; i < nt; i++)
        {
          if (strcasecmp (tok[i], "key") == 0 && i + 1 < nt)
            { in_key = 1; snprintf (name, sizeof name, "%s", tok[++i]); alg[0] = secret[0] = '\0'; continue; }
          if (!in_key) continue;
          if (strcasecmp (tok[i], "algorithm") == 0 && i + 1 < nt)
            { snprintf (alg, sizeof alg, "%s", tok[++i]); continue; }
          if (strcasecmp (tok[i], "secret") == 0 && i + 1 < nt)
            { snprintf (secret, sizeof secret, "%s", tok[++i]); continue; }
        }
      if (in_key && name[0] && alg[0] && secret[0])
        {
          if (bd_tsig_add_key (st, name, alg, secret) < 0) rc = -1;
          in_key = 0; name[0] = alg[0] = secret[0] = '\0';
        }
    }
  fclose (f);
  return rc;
}

static bd_tsig_key_t *
bd_tsig_find_key (bd_tsig_store_t *st, const char *name)
{
  char canon[256];
  if (!st || bd_canon_owner (name, canon, sizeof canon) < 0) return NULL;
  for (int i = 0; i < st->n; i++)
    if (strcasecmp (st->keys[i].name, canon) == 0) return &st->keys[i];
  return NULL;
}

typedef struct {
  char keyname[256];
  char algname[256];
  unsigned char mac[BD_TSIG_MAC_MAX];
  size_t mac_len;
  uint64_t time_signed;
  uint16_t fudge;
  uint16_t orig_id;
  uint16_t error;
  unsigned char other[64];
  size_t other_len;
  size_t rr_start;
} bd_tsig_rr_t;

static int
bd_tsig_next_rr (const unsigned char *msg, size_t msg_len, size_t *off,
                 char *owner, size_t owner_sz, uint16_t *type,
                 uint16_t *class_, uint32_t *ttl, uint16_t *rdlen,
                 size_t *rdata, size_t *rr_start)
{
  *rr_start = *off;
  if (bd_decode_name (msg, msg_len, off, owner, owner_sz, 0) < 0) return -1;
  if (*off + 10 > msg_len) return -1;
  *type = bd_rd16 (msg + *off);
  *class_ = bd_rd16 (msg + *off + 2);
  *ttl = bd_rd32 (msg + *off + 4);
  *rdlen = bd_rd16 (msg + *off + 8);
  *rdata = *off + 10;
  *off = *rdata + *rdlen;
  return (*off <= msg_len) ? 0 : -1;
}

static int
bd_tsig_parse_rdata (const unsigned char *msg, size_t msg_len,
                     const char *owner, size_t rdata, uint16_t rdlen,
                     size_t rr_start, bd_tsig_rr_t *rr)
{
  memset (rr, 0, sizeof *rr);
  if (bd_canon_owner (owner, rr->keyname, sizeof rr->keyname) < 0) return -1;
  size_t off = rdata, end = rdata + rdlen;
  if (bd_decode_name (msg, msg_len, &off, rr->algname, sizeof rr->algname, 0) < 0)
    return -1;
  if (off + 6 + 2 + 2 > end) return -1;
  rr->time_signed = ((uint64_t) msg[off] << 40) | ((uint64_t) msg[off + 1] << 32) |
                    ((uint64_t) msg[off + 2] << 24) | ((uint64_t) msg[off + 3] << 16) |
                    ((uint64_t) msg[off + 4] << 8) | (uint64_t) msg[off + 5];
  off += 6;
  rr->fudge = bd_rd16 (msg + off); off += 2;
  rr->mac_len = bd_rd16 (msg + off); off += 2;
  if (rr->mac_len > sizeof rr->mac || off + rr->mac_len + 2 + 2 + 2 > end)
    return -1;
  memcpy (rr->mac, msg + off, rr->mac_len); off += rr->mac_len;
  rr->orig_id = bd_rd16 (msg + off); off += 2;
  rr->error = bd_rd16 (msg + off); off += 2;
  rr->other_len = bd_rd16 (msg + off); off += 2;
  if (rr->other_len > sizeof rr->other || off + rr->other_len != end) return -1;
  if (rr->other_len) memcpy (rr->other, msg + off, rr->other_len);
  rr->rr_start = rr_start;
  bdr_lower (rr->algname);
  return 0;
}

static int
bd_tsig_find (const unsigned char *msg, size_t msg_len, bd_tsig_rr_t *rr)
{
  if (msg_len < 12) return BD_TSIG_FORMERR;
  uint16_t qd = bd_rd16 (msg + 4), an = bd_rd16 (msg + 6);
  uint16_t ns = bd_rd16 (msg + 8), ar = bd_rd16 (msg + 10);
  size_t off = 12;
  char name[256];
  for (int i = 0; i < qd; i++)
    { if (bd_skip_name (msg, msg_len, &off) < 0) return BD_TSIG_FORMERR;
      if (off + 4 > msg_len) return BD_TSIG_FORMERR; off += 4; }
  for (int i = 0; i < (int) an + (int) ns; i++)
    {
      uint16_t type, class_, rdlen; uint32_t ttl; size_t rdata, start;
      if (bd_tsig_next_rr (msg, msg_len, &off, name, sizeof name, &type, &class_, &ttl, &rdlen, &rdata, &start) < 0)
        return BD_TSIG_FORMERR;
      if (type == BD_T_TSIG) return BD_TSIG_FORMERR;
    }
  if (ar == 0) return BD_TSIG_NOTAUTH;
  for (int i = 0; i < ar; i++)
    {
      uint16_t type, class_, rdlen; uint32_t ttl; size_t rdata, start;
      if (bd_tsig_next_rr (msg, msg_len, &off, name, sizeof name, &type, &class_, &ttl, &rdlen, &rdata, &start) < 0)
        return BD_TSIG_FORMERR;
      if (type == BD_T_TSIG)
        {
          if (i != ar - 1 || off != msg_len) return BD_TSIG_FORMERR;
          return bd_tsig_parse_rdata (msg, msg_len, name, rdata, rdlen, start, rr) == 0
                 ? BD_TSIG_OK : BD_TSIG_FORMERR;
        }
    }
  return BD_TSIG_NOTAUTH;
}

static int
bd_tsig_put_rr (unsigned char *msg, size_t msg_sz, size_t *msg_len,
                const char *keyname, uint64_t time_signed, uint16_t fudge,
                uint16_t orig_id, uint16_t error,
                const unsigned char *other, size_t other_len,
                const unsigned char *mac, size_t mac_len)
{
  if (*msg_len < 12 || other_len > 65535 || mac_len > 65535) return -1;
  size_t off = *msg_len;
  unsigned char namew[256], algw[256], rdata[512];
  int nw = bd_tsig_name_wire (keyname, namew, sizeof namew);
  int aw = bd_tsig_name_wire ("hmac-sha256.", algw, sizeof algw);
  if (nw < 0 || aw < 0) return -1;

  size_t roff = 0;
  if (bd_tsig_append (rdata, sizeof rdata, &roff, algw, (size_t) aw) < 0 ||
      bd_tsig_append_u48 (rdata, sizeof rdata, &roff, time_signed) < 0 ||
      bd_tsig_append_u16 (rdata, sizeof rdata, &roff, fudge) < 0 ||
      bd_tsig_append_u16 (rdata, sizeof rdata, &roff, (uint16_t) mac_len) < 0 ||
      bd_tsig_append (rdata, sizeof rdata, &roff, mac, mac_len) < 0 ||
      bd_tsig_append_u16 (rdata, sizeof rdata, &roff, orig_id) < 0 ||
      bd_tsig_append_u16 (rdata, sizeof rdata, &roff, error) < 0 ||
      bd_tsig_append_u16 (rdata, sizeof rdata, &roff, (uint16_t) other_len) < 0)
    return -1;
  if (other_len && bd_tsig_append (rdata, sizeof rdata, &roff, other, other_len) < 0)
    return -1;
  if (off + (size_t) nw + 10 + roff > msg_sz) return -1;
  memcpy (msg + off, namew, (size_t) nw); off += (size_t) nw;
  bd_tsig_wr16 (msg + off, BD_T_TSIG); off += 2;
  bd_tsig_wr16 (msg + off, BD_C_ANY); off += 2;
  bd_tsig_wr32 (msg + off, 0); off += 4;
  bd_tsig_wr16 (msg + off, (uint16_t) roff); off += 2;
  memcpy (msg + off, rdata, roff); off += roff;
  uint16_t ar = (uint16_t) (bd_rd16 (msg + 10) + 1);
  bd_tsig_wr16 (msg + 10, ar);
  *msg_len = off;
  return 0;
}

static int
bd_tsig_sign (unsigned char *msg, size_t msg_sz, size_t *msg_len,
              const bd_tsig_key_t *key, const unsigned char *prior_mac,
              size_t prior_mac_len, uint64_t now, uint16_t fudge,
              unsigned char *mac_out, size_t *mac_out_len)
{
  if (!key || *msg_len < 12) return -1;
  unsigned char input[70000];
  size_t input_len = 0;
  if (bd_tsig_digest_input (msg, *msg_len, key->name, fudge, now, 0, NULL, 0,
                            prior_mac, prior_mac_len,
                            input, sizeof input, &input_len) < 0)
    return -1;
  unsigned char mac[BD_TSIG_MAC_MAX]; size_t mac_len = 0;
  if (bd_tsig_hmac (key, input, input_len, mac, sizeof mac, &mac_len) < 0)
    return -1;
  uint16_t orig_id = bd_rd16 (msg);
  if (bd_tsig_put_rr (msg, msg_sz, msg_len, key->name, now, fudge, orig_id,
                      0, NULL, 0, mac, mac_len) < 0)
    return -1;
  if (mac_out && mac_out_len)
    {
      memcpy (mac_out, mac, mac_len);
      *mac_out_len = mac_len;
    }
  return 0;
}

static int
bd_tsig_verify (unsigned char *msg, size_t *msg_len, bd_tsig_store_t *store,
                int require, uint64_t now, const unsigned char *prior_mac,
                size_t prior_mac_len, bd_tsig_key_t **key_out,
                unsigned char *mac_out, size_t *mac_out_len)
{
  if (key_out) *key_out = NULL;
  if (mac_out_len) *mac_out_len = 0;
  bd_tsig_rr_t rr;
  int fr = bd_tsig_find (msg, *msg_len, &rr);
  if (fr == BD_TSIG_NOTAUTH)
    return require ? BD_TSIG_NOTAUTH : BD_TSIG_OK;
  if (fr != BD_TSIG_OK) return fr;
  if (strcasecmp (rr.algname, "hmac-sha256") != 0 &&
      strcasecmp (rr.algname, "hmac-sha256.") != 0)
    return BD_TSIG_BADKEY;
  bd_tsig_key_t *key = bd_tsig_find_key (store, rr.keyname);
  if (!key) return BD_TSIG_BADKEY;
  uint64_t delta = now > rr.time_signed ? now - rr.time_signed : rr.time_signed - now;
  if (delta > rr.fudge) return BD_TSIG_BADTIME;
  if (rr.rr_start > *msg_len || *msg_len < 12) return BD_TSIG_FORMERR;
  uint16_t ar = bd_rd16 (msg + 10);
  if (ar == 0) return BD_TSIG_FORMERR;
  unsigned char save10 = msg[10], save11 = msg[11];
  bd_tsig_wr16 (msg + 10, (uint16_t) (ar - 1));
  unsigned char input[70000];
  size_t input_len = 0;
  if (bd_tsig_digest_input (msg, rr.rr_start, rr.keyname, rr.fudge,
                            rr.time_signed, rr.error, rr.other, rr.other_len,
                            prior_mac, prior_mac_len,
                            input, sizeof input, &input_len) < 0)
    { msg[10] = save10; msg[11] = save11; return BD_TSIG_FORMERR; }
  unsigned char want[BD_TSIG_MAC_MAX]; size_t want_len = 0;
  if (bd_tsig_hmac (key, input, input_len, want, sizeof want, &want_len) < 0)
    { msg[10] = save10; msg[11] = save11; return BD_TSIG_BADSIG; }
  if (rr.mac_len != want_len || !bd_tsig_ct_eq (rr.mac, want, want_len))
    { msg[10] = save10; msg[11] = save11; return BD_TSIG_BADSIG; }
  *msg_len = rr.rr_start;
  if (key_out) *key_out = key;
  if (mac_out && mac_out_len)
    {
      memcpy (mac_out, rr.mac, rr.mac_len);
      *mac_out_len = rr.mac_len;
    }
  return BD_TSIG_OK;
}

/* Add in-bailiwick A/AAAA glue for the targets of the NS records we emitted. */
static void
bda_add_glue (struct bda_zone *z, const char *ns_owner, unsigned char *resp, size_t rsz, size_t *off, uint16_t *ar)
{
  /* For each NS at ns_owner, decode target; if in-zone, emit its A/AAAA glue. */
  for (int i = 0; i < z->n; i++) {
    char o[256]; bda_owner (z, i, o, sizeof o);
    if (z->rr[i].type != BDA_NS || strcmp (o, ns_owner)) continue;
    char tgt[256]; size_t toff = 0;
    if (bd_decode_name (z->rr[i].rdata, z->rr[i].rdata_len, &toff, tgt, sizeof tgt, 0) < 0) continue;
    bda_norm (tgt);
    if (!bda_in_zone (tgt, z->apex)) continue;
    for (int j = 0; j < z->n; j++) {
      char oj[256]; bda_owner (z, j, oj, sizeof oj);
      if (strcmp (oj, tgt)) continue;
      if (z->rr[j].type == BDA_A || z->rr[j].type == BDA_AAAA)
        if (bda_put_rr (resp, rsz, off, tgt, z->rr[j].type, z->rr[j].ttl, z->rr[j].rdata, z->rr[j].rdata_len) == 0)
          (*ar)++;
    }
  }
}

/* Does the query carry an EDNS0 OPT record with the DNSSEC OK (DO) bit set?
   Walks past the question (+ any answer/authority RRs) to the additional
   section and inspects the first OPT (type 41); DO is the high bit of the
   OPT TTL flags field (0x8000). Returns 1 if DO is set, else 0. */
static int
bda_query_has_do (const unsigned char *q, size_t qlen)
{
  if (qlen < 12) return 0;
  uint16_t qd = bd_rd16 (q + 4), an = bd_rd16 (q + 6);
  uint16_t ns = bd_rd16 (q + 8), ar = bd_rd16 (q + 10);
  size_t off = 12; char nm[256];
  for (int i = 0; i < qd; i++) { if (bd_decode_name (q, qlen, &off, nm, sizeof nm, 0) < 0) return 0; off += 4; if (off > qlen) return 0; }
  for (int i = 0; i < an + ns; i++) {
    if (bd_decode_name (q, qlen, &off, nm, sizeof nm, 0) < 0) return 0;
    if (off + 10 > qlen) return 0;
    off += 8 + 2 + bd_rd16 (q + off + 8);
  }
  for (int i = 0; i < ar; i++) {
    if (bd_decode_name (q, qlen, &off, nm, sizeof nm, 0) < 0) return 0;
    if (off + 10 > qlen) return 0;
    uint16_t typ = bd_rd16 (q + off);
    uint32_t ttl = bd_rd32 (q + off + 4);
    uint16_t rdl = bd_rd16 (q + off + 8);
    if (typ == 41) return (ttl & 0x8000) ? 1 : 0;
    off += 10 + rdl;
  }
  return 0;
}

/* Append every RRSIG in the zone that covers (owner, covered_type) to resp[],
   bumping *counter. Used for DNSSEC-OK answers (online inline signing). */
static int
bda_put_rrsig (struct bda_zone *z, unsigned char *resp, size_t rsz, size_t *off,
               const char *owner, uint16_t covered, uint16_t *counter)
{
  int put = 0;
  for (int i = 0; i < z->n; i++) {
    if (z->rr[i].type != BD_T_RRSIG || z->rr[i].rdata_len < 2) continue;
    char o[256]; bda_owner (z, i, o, sizeof o);
    if (strcmp (o, owner) || bd_rd16 (z->rr[i].rdata) != covered) continue;
    if (bda_put_rr (resp, rsz, off, owner, BD_T_RRSIG, z->rr[i].ttl, z->rr[i].rdata, z->rr[i].rdata_len) == 0)
      { (*counter)++; put++; }
  }
  return put;
}

/* Append a bare EDNS0 OPT record (DO set, 4096-octet payload) to the additional
   section, echoing the requester's DNSSEC-OK signal per RFC 6891. */
static int
bda_put_opt (unsigned char *resp, size_t rsz, size_t *off, uint16_t *ar)
{
  if (*off + 11 > rsz) return -1;
  unsigned char *p = resp + *off;
  p[0] = 0x00;                       /* root owner */
  p[1] = 0x00; p[2] = 0x29;          /* TYPE = OPT (41) */
  p[3] = 0x10; p[4] = 0x00;          /* requestor UDP payload = 4096 */
  p[5] = 0x00; p[6] = 0x00;          /* extended-rcode, version 0 */
  p[7] = 0x80; p[8] = 0x00;          /* flags: DO set */
  p[9] = 0x00; p[10] = 0x00;         /* RDLEN = 0 */
  *off += 11; (*ar)++;
  return 0;
}

/* Emit the NSEC owned exactly by `name` (+ its RRSIG) into the authority
   section — the authenticated NODATA proof (the qtype is absent from the
   NSEC type bitmap). No-op for NSEC3-signed zones (no type-47 records). */
static void
bda_put_nsec_exact (struct bda_zone *z, unsigned char *resp, size_t rsz, size_t *off,
                    const char *name, uint16_t *ns)
{
  for (int i = 0; i < z->n; i++) {
    if (z->rr[i].type != BD_T_NSEC) continue;
    char o[256]; bda_owner (z, i, o, sizeof o);
    if (strcmp (o, name)) continue;
    if (bda_put_rr (resp, rsz, off, o, BD_T_NSEC, z->rr[i].ttl, z->rr[i].rdata, z->rr[i].rdata_len) == 0) {
      (*ns)++;
      bda_put_rrsig (z, resp, rsz, off, o, BD_T_NSEC, ns);
    }
    return;
  }
}

/* Emit the NSEC that canonically covers `qname` (owner < qname < next, with
   the apex-wrap NSEC closing the chain) + its RRSIG — the authenticated
   NXDOMAIN proof. No-op for NSEC3-signed zones. */
static void
bda_put_nsec_cover (struct bda_zone *z, unsigned char *resp, size_t rsz, size_t *off,
                    const char *qname, uint16_t *ns)
{
  for (int i = 0; i < z->n; i++) {
    if (z->rr[i].type != BD_T_NSEC) continue;
    char o[256]; bda_owner (z, i, o, sizeof o);
    char nxt[256]; size_t no = 0;
    if (bd_decode_name (z->rr[i].rdata, z->rr[i].rdata_len, &no, nxt, sizeof nxt, 0) < 0) continue;
    bda_norm (nxt);
    int owner_lt = bd_canon_name_cmp (o, qname) < 0;     /* owner  < qname */
    int qname_lt = bd_canon_name_cmp (qname, nxt) < 0;   /* qname  < next  */
    int wrap     = bd_canon_name_cmp (nxt, o) <= 0;      /* next <= owner -> wrap NSEC */
    if (owner_lt && (qname_lt || wrap)) {
      if (bda_put_rr (resp, rsz, off, o, BD_T_NSEC, z->rr[i].ttl, z->rr[i].rdata, z->rr[i].rdata_len) == 0) {
        (*ns)++;
        bda_put_rrsig (z, resp, rsz, off, o, BD_T_NSEC, ns);
      }
      return;
    }
  }
}

#define BDA_NSEC3_PROOF_MAX 3

enum bda_nsec3_proof_kind {
  BDA_NSEC3_PROOF_NODATA = 0,
  BDA_NSEC3_PROOF_NXDOMAIN = 1,
  BDA_NSEC3_PROOF_WILDCARD_NODATA = 2
};

struct bda_nsec3_params {
  uint8_t alg;
  uint16_t iterations;
  const unsigned char *salt;
  size_t salt_len;
};

static int
bda_nsec3_params (struct bda_zone *z, struct bda_nsec3_params *p)
{
  for (int i = 0; i < z->n; i++)
    {
      if (z->rr[i].type != BD_T_NSEC3PARAM || z->rr[i].rdata_len < 5) continue;
      p->alg = z->rr[i].rdata[0];
      p->iterations = bd_rd16 (z->rr[i].rdata + 2);
      p->salt_len = z->rr[i].rdata[4];
      if ((size_t) 5 + p->salt_len > z->rr[i].rdata_len) return -1;
      p->salt = z->rr[i].rdata + 5;
      return 0;
    }

  for (int i = 0; i < z->n; i++)
    {
      if (z->rr[i].type != BD_T_NSEC3) continue;
      uint8_t flags;
      const unsigned char *next, *bm;
      size_t next_len, bm_len;
      if (bd_nsec3_parse (&z->rr[i], &p->alg, &flags, &p->iterations,
                          &p->salt, &p->salt_len, &next, &next_len,
                          &bm, &bm_len) == 0)
        return 0;
    }
  return -1;
}

static int
bda_zone_has_nsec3 (struct bda_zone *z)
{
  struct bda_nsec3_params p;
  return bda_nsec3_params (z, &p) == 0;
}

static int
bda_nsec3_hash_label (const char *name, const struct bda_nsec3_params *p,
                      char *label, size_t label_sz)
{
  unsigned char hash[64];
  size_t hash_len = 0;
  if (bd_nsec3_hash_name (name, p->alg, p->salt, p->salt_len, p->iterations,
                          hash, sizeof hash, &hash_len) < 0)
    return -1;
  return bd_nsec3_base32hex (hash, hash_len, label, label_sz);
}

static int
bda_nsec3_rr_params_match (const bd_rr_t *rr, const struct bda_nsec3_params *p,
                           uint8_t *flags_out, const unsigned char **next_out,
                           size_t *next_len_out)
{
  uint8_t alg, flags;
  uint16_t iterations;
  const unsigned char *salt, *next, *bm;
  size_t salt_len, next_len, bm_len;
  if (bd_nsec3_parse (rr, &alg, &flags, &iterations, &salt, &salt_len,
                      &next, &next_len, &bm, &bm_len) < 0)
    return 0;
  if (alg != p->alg || iterations != p->iterations || salt_len != p->salt_len
      || memcmp (salt, p->salt, salt_len) != 0)
    return 0;
  if (flags_out) *flags_out = flags;
  if (next_out) *next_out = next;
  if (next_len_out) *next_len_out = next_len;
  return 1;
}

static int
bda_nsec3_match_label (struct bda_zone *z, const struct bda_nsec3_params *p,
                       const char *label)
{
  for (int i = 0; i < z->n; i++)
    {
      if (z->rr[i].type != BD_T_NSEC3) continue;
      if (!bda_nsec3_rr_params_match (&z->rr[i], p, NULL, NULL, NULL)) continue;
      char o[256], owner_hash[128];
      bda_owner (z, i, o, sizeof o);
      if (bd_nsec3_owner_hash_label (o, owner_hash, sizeof owner_hash) < 0) continue;
      if (strcmp (owner_hash, label) == 0) return i;
    }
  return -1;
}

static int
bda_nsec3_match_name (struct bda_zone *z, const struct bda_nsec3_params *p,
                      const char *name)
{
  char label[128];
  if (bda_nsec3_hash_label (name, p, label, sizeof label) < 0) return -1;
  return bda_nsec3_match_label (z, p, label);
}

static int
bda_nsec3_cover_name (struct bda_zone *z, const struct bda_nsec3_params *p,
                      const char *name)
{
  char label[128];
  if (bda_nsec3_hash_label (name, p, label, sizeof label) < 0) return -1;
  for (int i = 0; i < z->n; i++)
    {
      if (z->rr[i].type != BD_T_NSEC3) continue;
      const unsigned char *next;
      size_t next_len;
      if (!bda_nsec3_rr_params_match (&z->rr[i], p, NULL, &next, &next_len)) continue;
      char o[256], owner_hash[128], next_label[128];
      bda_owner (z, i, o, sizeof o);
      if (bd_nsec3_owner_hash_label (o, owner_hash, sizeof owner_hash) < 0
          || bd_nsec3_base32hex (next, next_len, next_label, sizeof next_label) < 0)
        continue;
      if (bd_nsec3_range_covers_hash ((const unsigned char *) owner_hash, strlen (owner_hash),
                                      (const unsigned char *) next_label, strlen (next_label),
                                      (const unsigned char *) label, strlen (label)))
        return i;
    }
  return -1;
}

static int
bda_nsec3_add_unique (int *idx, int *nidx, int max, int rr_i)
{
  if (rr_i < 0) return 0;
  for (int i = 0; i < *nidx; i++) if (idx[i] == rr_i) return 0;
  if (*nidx >= max) return -1;
  idx[(*nidx)++] = rr_i;
  return 0;
}

static int
bda_nsec3_wildcard_name (const char *ce, char *out, size_t out_sz)
{
  if (ce[0] == '\0' || strcmp (ce, ".") == 0)
    snprintf (out, out_sz, "*");
  else
    snprintf (out, out_sz, "*.%s", ce);
  return out[0] ? 0 : -1;
}

static int
bda_nsec3_closest_encloser (struct bda_zone *z, const char *qname,
                            char *ce, size_t ce_sz,
                            char *nc, size_t nc_sz,
                            int *ce_rr)
{
  struct bda_nsec3_params p;
  if (bda_nsec3_params (z, &p) < 0) return -1;

  char candidate[256], previous[256] = "";
  snprintf (candidate, sizeof candidate, "%s", qname);
  for (;;)
    {
      if (!bda_in_zone (candidate, z->apex)) return -1;
      int mi = bda_nsec3_match_name (z, &p, candidate);
      if (mi >= 0)
        {
          snprintf (ce, ce_sz, "%s", candidate);
          snprintf (nc, nc_sz, "%s", previous);
          if (ce_rr) *ce_rr = mi;
          return 0;
        }
      snprintf (previous, sizeof previous, "%s", candidate);
      char *dot = strchr (candidate, '.');
      if (!dot) return -1;
      memmove (candidate, dot + 1, strlen (dot + 1) + 1);
    }
}

static int
bda_nsec3_select_proof (struct bda_zone *z, const char *qname,
                        enum bda_nsec3_proof_kind kind, const char *wildcard,
                        int *idx, int max)
{
  struct bda_nsec3_params p;
  int nidx = 0;
  if (bda_nsec3_params (z, &p) < 0) return 0;

  if (kind == BDA_NSEC3_PROOF_NODATA)
    {
      bda_nsec3_add_unique (idx, &nidx, max, bda_nsec3_match_name (z, &p, qname));
      return nidx;
    }

  char ce[256], nc[256];
  int ce_i = -1;
  if (bda_nsec3_closest_encloser (z, qname, ce, sizeof ce, nc, sizeof nc, &ce_i) < 0)
    return 0;
  bda_nsec3_add_unique (idx, &nidx, max, ce_i);

  if (kind == BDA_NSEC3_PROOF_WILDCARD_NODATA)
    {
      const char *wc = wildcard;
      char computed_wc[256];
      if (!wc || !*wc)
        {
          if (bda_nsec3_wildcard_name (ce, computed_wc, sizeof computed_wc) < 0) return nidx;
          wc = computed_wc;
        }
      bda_nsec3_add_unique (idx, &nidx, max, bda_nsec3_match_name (z, &p, wc));
      return nidx;
    }

  if (nc[0])
    bda_nsec3_add_unique (idx, &nidx, max, bda_nsec3_cover_name (z, &p, nc));

  char wc[256];
  if (bda_nsec3_wildcard_name (ce, wc, sizeof wc) == 0)
    bda_nsec3_add_unique (idx, &nidx, max, bda_nsec3_cover_name (z, &p, wc));
  return nidx;
}

static void
bda_put_nsec3_proof (struct bda_zone *z, unsigned char *resp, size_t rsz, size_t *off,
                     const int *idx, int nidx, uint16_t *ns)
{
  for (int k = 0; k < nidx; k++)
    {
      int i = idx[k];
      if (i < 0 || i >= z->n || z->rr[i].type != BD_T_NSEC3) continue;
      char o[256];
      bda_owner (z, i, o, sizeof o);
      if (bda_put_rr (resp, rsz, off, o, BD_T_NSEC3, z->rr[i].ttl,
                      z->rr[i].rdata, z->rr[i].rdata_len) == 0)
        {
          (*ns)++;
          bda_put_rrsig (z, resp, rsz, off, o, BD_T_NSEC3, ns);
        }
    }
}

/* Build an authoritative answer for the query in q[] into resp[]. */
static int
bda_answer (struct bda_zone *z, const unsigned char *q, size_t qlen,
            unsigned char *resp, size_t rsz)
{
  char qname[256]; uint16_t qtype, qclass;
  if (bdr_parse_question (q, qlen, qname, sizeof qname, &qtype, &qclass) < 0) return -1;
  bda_norm (qname);
  int do_bit = bda_query_has_do (q, qlen);
  int has_nsec3 = bda_zone_has_nsec3 (z);

  size_t qoff = 12; char tmp[256];
  if (bd_decode_name (q, qlen, &qoff, tmp, sizeof tmp, 0) < 0) return -1;
  qoff += 4;
  if (qoff > rsz) return -1;
  memcpy (resp, q, qoff);
  resp[2] = 0x84; resp[3] = 0x00;                 /* QR=1 AA=1, RCODE=0 */
  size_t off = qoff;
  uint16_t an = 0, ns = 0, ar = 0;

  /* apex SOA (for negative answers). */
  bd_rr_t *soa = NULL;
  for (int i = 0; i < z->n; i++) {
    char o[256]; bda_owner (z, i, o, sizeof o);
    if (z->rr[i].type == BDA_SOA && !strcmp (o, z->apex)) { soa = &z->rr[i]; break; }
  }

  if (qclass != 1 || !bda_in_zone (qname, z->apex)) { resp[3] = 0x05; goto done; }   /* REFUSED */

  /* Delegation: if qname is at/below a non-apex NS owner, this is a zone cut —
     answer with a referral (NS in authority, AA=0, glue in additional) instead
     of from local data, so a recursive resolver can follow the chain down. */
  char deleg[256] = "";
  for (int i = 0; i < z->n; i++) {
    if (z->rr[i].type != BDA_NS) continue;
    char o[256]; bda_owner (z, i, o, sizeof o);
    if (!strcmp (o, z->apex)) continue;             /* apex NS is the zone's own, not a cut */
    if (!bda_in_zone (qname, o)) continue;          /* o must be an ancestor-or-self of qname */
    if (strlen (o) > strlen (deleg)) snprintf (deleg, sizeof deleg, "%s", o);
  }
  if (deleg[0]) {
    resp[2] = 0x80;                                 /* QR=1, AA=0 (referral) */
    for (int i = 0; i < z->n; i++) {
      char o[256]; bda_owner (z, i, o, sizeof o);
      if (z->rr[i].type == BDA_NS && !strcmp (o, deleg))
        if (bda_put_rr (resp, rsz, &off, deleg, BDA_NS, z->rr[i].ttl, z->rr[i].rdata, z->rr[i].rdata_len) == 0) ns++;
    }
    bda_add_glue (z, deleg, resp, rsz, &off, &ar);
    goto done;
  }

  int answered = 0, name_exists = 0, has_cname = 0;
  char cur[256]; snprintf (cur, sizeof cur, "%s", qname);

  for (int chase = 0; chase < 8; chase++) {
    int found = 0, cname_i = -1;
    for (int i = 0; i < z->n; i++) {
      char o[256]; bda_owner (z, i, o, sizeof o);
      if (strcmp (o, cur)) continue;
      name_exists = 1;
      if (z->rr[i].type == qtype) {
        if (bda_put_rr (resp, rsz, &off, cur, qtype, z->rr[i].ttl, z->rr[i].rdata, z->rr[i].rdata_len) == 0) { an++; answered = found = 1; }
      } else if (z->rr[i].type == BDA_CNAME && qtype != BDA_CNAME) cname_i = i;
    }
    if (found) { if (do_bit) bda_put_rrsig (z, resp, rsz, &off, cur, qtype, &an); break; }
    if (cname_i >= 0 && qtype != BDA_CNAME) {
      has_cname = 1;
      if (bda_put_rr (resp, rsz, &off, cur, BDA_CNAME, z->rr[cname_i].ttl, z->rr[cname_i].rdata, z->rr[cname_i].rdata_len) == 0) an++;
      if (do_bit) bda_put_rrsig (z, resp, rsz, &off, cur, BDA_CNAME, &an);
      char tgt[256]; size_t toff = 0;
      if (bd_decode_name (z->rr[cname_i].rdata, z->rr[cname_i].rdata_len, &toff, tgt, sizeof tgt, 0) < 0) break;
      bda_norm (tgt);
      if (!bda_in_zone (tgt, z->apex)) break;
      snprintf (cur, sizeof cur, "%s", tgt);
      continue;
    }
    int dname_i = -1;
    char dname_owner[256] = "";
    for (int i = 0; i < z->n; i++) {
      if (z->rr[i].type != BDA_DNAME) continue;
      char o[256]; bda_owner (z, i, o, sizeof o);
      if (!strcmp (o, cur)) continue;              /* DNAME owner itself is not redirected. */
      if (!bda_in_zone (cur, o)) continue;
      if (dname_i < 0 || strlen (o) > strlen (dname_owner)) {
        dname_i = i;
        snprintf (dname_owner, sizeof dname_owner, "%s", o);
      }
    }
    if (dname_i >= 0) {
      char dtarget[256]; size_t toff = 0;
      if (bd_decode_name (z->rr[dname_i].rdata, z->rr[dname_i].rdata_len, &toff, dtarget, sizeof dtarget, 0) < 0) break;
      bda_norm (dtarget);

      char syn[512];
      size_t cur_len = strlen (cur);
      size_t owner_len = strlen (dname_owner);
      size_t target_len = strlen (dtarget);
      if (owner_len == 0) {
        int n = target_len
          ? snprintf (syn, sizeof syn, "%s.%s", cur, dtarget)
          : snprintf (syn, sizeof syn, "%s", cur);
        if (n < 0 || (size_t) n >= sizeof syn) { resp[3] = 0x06; goto done; }
      } else {
        if (cur_len <= owner_len || cur[cur_len - owner_len - 1] != '.') break;
        size_t prefix_len = cur_len - owner_len;   /* includes the dot before the DNAME owner. */
        if (prefix_len + target_len >= sizeof syn) { resp[3] = 0x06; goto done; }
        memcpy (syn, cur, prefix_len);
        memcpy (syn + prefix_len, dtarget, target_len);
        syn[prefix_len + target_len] = '\0';
      }
      bda_norm (syn);
      if (strlen (syn) > 255) { resp[3] = 0x06; goto done; } /* YXDOMAIN */

      unsigned char cname_rdata[256];
      int cname_len = bd_name_to_wire (syn, cname_rdata, sizeof cname_rdata);
      if (cname_len < 0) { resp[3] = 0x06; goto done; }      /* YXDOMAIN */

      if (bda_put_rr (resp, rsz, &off, dname_owner, BDA_DNAME, z->rr[dname_i].ttl,
                      z->rr[dname_i].rdata, z->rr[dname_i].rdata_len) < 0) break;
      an++;
      if (do_bit) bda_put_rrsig (z, resp, rsz, &off, dname_owner, BDA_DNAME, &an);
      if (bda_put_rr (resp, rsz, &off, cur, BDA_CNAME, z->rr[dname_i].ttl,
                      cname_rdata, (uint16_t) cname_len) < 0) break;
      an++;
      has_cname = 1;
      snprintf (cur, sizeof cur, "%s", syn);
      if (!bda_in_zone (cur, z->apex)) break;
      continue;
    }
    break;
  }

  /* wildcard *.<parent> when the exact name does not exist. */
  int via_wildcard = 0, wildcard_exists = 0; char wc[256] = "";
  if (!answered && !name_exists && !has_cname) {
    const char *dot = strchr (qname, '.');
    if (dot) {
      snprintf (wc, sizeof wc, "*%s", dot);
      for (int i = 0; i < z->n; i++) {
        char o[256]; bda_owner (z, i, o, sizeof o);
        if (strcmp (o, wc)) continue;
        if (z->rr[i].type != BD_T_RRSIG && z->rr[i].type != BD_T_NSEC
            && z->rr[i].type != BD_T_NSEC3)
          wildcard_exists = 1;
        if (z->rr[i].type == qtype)
          if (bda_put_rr (resp, rsz, &off, qname, qtype, z->rr[i].ttl, z->rr[i].rdata, z->rr[i].rdata_len) == 0) { an++; answered = 1; via_wildcard = 1; }
      }
    }
  }
  /* Wildcard-expanded RRset: attach the RRSIG owned by the wildcard, emitted
     under the queried name (its labels field marks it as a wildcard sig). */
  if (via_wildcard && do_bit) {
    for (int i = 0; i < z->n; i++) {
      if (z->rr[i].type != BD_T_RRSIG || z->rr[i].rdata_len < 2) continue;
      char o[256]; bda_owner (z, i, o, sizeof o);
      if (strcmp (o, wc) || bd_rd16 (z->rr[i].rdata) != qtype) continue;
      if (bda_put_rr (resp, rsz, &off, qname, BD_T_RRSIG, z->rr[i].ttl, z->rr[i].rdata, z->rr[i].rdata_len) == 0) an++;
    }
  }

  if (answered || has_cname) {
    for (int i = 0; i < z->n; i++) {
      char o[256]; bda_owner (z, i, o, sizeof o);
      if (z->rr[i].type == BDA_NS && !strcmp (o, z->apex))
        if (bda_put_rr (resp, rsz, &off, z->apex, BDA_NS, z->rr[i].ttl, z->rr[i].rdata, z->rr[i].rdata_len) == 0) ns++;
    }
    if (ns && do_bit) bda_put_rrsig (z, resp, rsz, &off, z->apex, BDA_NS, &ns);
    if (ns) bda_add_glue (z, z->apex, resp, rsz, &off, &ar);
  } else if (name_exists) {                          /* NODATA */
    if (soa && bda_put_rr (resp, rsz, &off, z->apex, BDA_SOA, soa->ttl, soa->rdata, soa->rdata_len) == 0) ns++;
    if (ns && do_bit) {
      bda_put_rrsig (z, resp, rsz, &off, z->apex, BDA_SOA, &ns);
      if (has_nsec3) {
        int proof[BDA_NSEC3_PROOF_MAX];
        int nproof = bda_nsec3_select_proof (z, qname, BDA_NSEC3_PROOF_NODATA,
                                             NULL, proof, BDA_NSEC3_PROOF_MAX);
        bda_put_nsec3_proof (z, resp, rsz, &off, proof, nproof, &ns);
      } else
        bda_put_nsec_exact (z, resp, rsz, &off, qname, &ns);  /* authenticated NODATA */
    }
  } else if (wildcard_exists) {                       /* wildcard NODATA */
    if (soa && bda_put_rr (resp, rsz, &off, z->apex, BDA_SOA, soa->ttl, soa->rdata, soa->rdata_len) == 0) ns++;
    if (ns && do_bit) {
      bda_put_rrsig (z, resp, rsz, &off, z->apex, BDA_SOA, &ns);
      if (has_nsec3) {
        int proof[BDA_NSEC3_PROOF_MAX];
        int nproof = bda_nsec3_select_proof (z, qname, BDA_NSEC3_PROOF_WILDCARD_NODATA,
                                             wc, proof, BDA_NSEC3_PROOF_MAX);
        bda_put_nsec3_proof (z, resp, rsz, &off, proof, nproof, &ns);
      } else
        bda_put_nsec_exact (z, resp, rsz, &off, wc, &ns);
    }
  } else {                                           /* NXDOMAIN */
    resp[3] = 0x03;
    if (soa && bda_put_rr (resp, rsz, &off, z->apex, BDA_SOA, soa->ttl, soa->rdata, soa->rdata_len) == 0) ns++;
    if (ns && do_bit) {
      bda_put_rrsig (z, resp, rsz, &off, z->apex, BDA_SOA, &ns);
      if (has_nsec3) {
        int proof[BDA_NSEC3_PROOF_MAX];
        int nproof = bda_nsec3_select_proof (z, qname, BDA_NSEC3_PROOF_NXDOMAIN,
                                             NULL, proof, BDA_NSEC3_PROOF_MAX);
        bda_put_nsec3_proof (z, resp, rsz, &off, proof, nproof, &ns);
      } else
        bda_put_nsec_cover (z, resp, rsz, &off, qname, &ns);  /* authenticated NXDOMAIN */
    }
  }

  /* Echo an EDNS0 OPT (DO) so the resolver knows the answer is DNSSEC-aware. */
  if (do_bit) bda_put_opt (resp, rsz, &off, &ar);

done:
  resp[6] = (unsigned char) (an >> 8); resp[7] = (unsigned char) an;
  resp[8] = (unsigned char) (ns >> 8); resp[9] = (unsigned char) ns;
  resp[10] = (unsigned char) (ar >> 8); resp[11] = (unsigned char) ar;
  return (int) off;
}

/* Build a full AXFR response (SOA, every RR, trailing SOA) into out[]. Fits
   one TCP message for zones up to ~64 KiB; larger zones return -1 (multi-
   message AXFR is a later refinement). */
static int
bda_build_axfr (struct bda_zone *z, const unsigned char *q, size_t qlen,
                unsigned char *out, size_t osz)
{
  size_t qoff = 12; char tmp[256];
  if (bd_decode_name (q, qlen, &qoff, tmp, sizeof tmp, 0) < 0) return -1;
  qoff += 4;
  if (qoff > qlen) return -1;
  memcpy (out, q, qoff);
  out[2] = 0x84; out[3] = 0x00;
  size_t off = qoff; uint16_t an = 0;
  bd_rr_t *soa = NULL;
  for (int i = 0; i < z->n; i++) { char o[256]; bda_owner (z, i, o, sizeof o);
    if (z->rr[i].type == BDA_SOA && !strcmp (o, z->apex)) { soa = &z->rr[i]; break; } }
  if (!soa) return -1;
  if (bda_put_rr (out, osz, &off, z->apex, BDA_SOA, soa->ttl, soa->rdata, soa->rdata_len) < 0) return -1; an++;
  for (int i = 0; i < z->n; i++) {
    if (z->rr[i].type == BDA_SOA) continue;
    char o[256]; bda_owner (z, i, o, sizeof o);
    if (bda_put_rr (out, osz, &off, o, z->rr[i].type, z->rr[i].ttl, z->rr[i].rdata, z->rr[i].rdata_len) < 0) return -1; an++;
  }
  if (bda_put_rr (out, osz, &off, z->apex, BDA_SOA, soa->ttl, soa->rdata, soa->rdata_len) < 0) return -1; an++;
  out[6] = (unsigned char) (an >> 8); out[7] = (unsigned char) an;
  out[8] = out[9] = out[10] = out[11] = 0;
  return (int) off;
}

static int bda_readn (int fd, unsigned char *b, size_t n)
{ size_t g = 0; while (g < n) { ssize_t r = read (fd, b + g, n - g); if (r <= 0) return -1; g += (size_t) r; } return 0; }
static int bda_writen (int fd, const unsigned char *b, size_t n)
{ size_t p = 0; while (p < n) { ssize_t r = write (fd, b + p, n - p); if (r <= 0) return -1; p += (size_t) r; } return 0; }

struct bda_tls_cfg {
  int enabled;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt cert;
  mbedtls_pk_context key;
};

#if defined(MBEDTLS_SSL_ALPN)
static const char *const bda_doh_alpn[] = { "h2", "http/1.1", NULL };
#endif

struct bda_conn {
  int fd;
  mbedtls_ssl_context *ssl;
};

static int
bda_tls_recv (void *ctx, unsigned char *buf, size_t len)
{
  int fd = *(int *) ctx;
  ssize_t r;
  do { r = read (fd, buf, len); } while (r < 0 && errno == EINTR);
  if (r < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_READ;
    return MBEDTLS_ERR_NET_RECV_FAILED;
  }
  return (int) r;
}

static int
bda_tls_send (void *ctx, const unsigned char *buf, size_t len)
{
  int fd = *(int *) ctx;
  ssize_t w;
  do { w = write (fd, buf, len); } while (w < 0 && errno == EINTR);
  if (w < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_WRITE;
    return MBEDTLS_ERR_NET_SEND_FAILED;
  }
  return (int) w;
}

static int
bda_tls_cfg_init (struct bda_tls_cfg *cfg, const char *cert, const char *key,
                  const char *label, const char *const *alpn)
{
  memset (cfg, 0, sizeof *cfg);
  if (!cert && !key) return 0;
  if (!cert || !key)
    { builtin_error ("%s TLS needs both cert and key", label); return -1; }
  mbedtls_ssl_config_init (&cfg->conf);
  mbedtls_x509_crt_init (&cfg->cert);
  mbedtls_pk_init (&cfg->key);
  if (psa_crypto_init () != PSA_SUCCESS)
    { builtin_error ("%s TLS: psa init failed", label); return -1; }
  int rc = mbedtls_x509_crt_parse_file (&cfg->cert, cert);
  if (rc != 0)
    { builtin_error ("%s TLS: parse cert %s failed rc=%d", label, cert, rc); return -1; }
  rc = mbedtls_pk_parse_keyfile (&cfg->key, key, NULL);
  if (rc != 0)
    { builtin_error ("%s TLS: parse key %s failed rc=%d", label, key, rc); return -1; }
  rc = mbedtls_ssl_config_defaults (&cfg->conf, MBEDTLS_SSL_IS_SERVER,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (rc != 0)
    { builtin_error ("%s TLS: config_defaults failed rc=%d", label, rc); return -1; }
  rc = mbedtls_ssl_conf_own_cert (&cfg->conf, &cfg->cert, &cfg->key);
  if (rc != 0)
    { builtin_error ("%s TLS: own_cert failed rc=%d", label, rc); return -1; }
#if defined(MBEDTLS_SSL_ALPN)
  if (alpn) {
    rc = mbedtls_ssl_conf_alpn_protocols (&cfg->conf, alpn);
    if (rc != 0)
      { builtin_error ("%s TLS: ALPN config failed rc=%d", label, rc); return -1; }
  }
#else
  (void) alpn;
#endif
  cfg->enabled = 1;
  return 0;
}

static void
bda_tls_cfg_free (struct bda_tls_cfg *cfg)
{
  if (!cfg) return;
  mbedtls_ssl_config_free (&cfg->conf);
  mbedtls_x509_crt_free (&cfg->cert);
  mbedtls_pk_free (&cfg->key);
  cfg->enabled = 0;
}

static int
bda_tls_handshake (struct bda_tls_cfg *cfg, mbedtls_ssl_context *ssl, int *fdp,
                   const char *label)
{
  int rc;
  mbedtls_ssl_init (ssl);
  rc = mbedtls_ssl_setup (ssl, &cfg->conf);
  if (rc != 0)
    { builtin_error ("%s TLS: ssl_setup failed rc=%d", label, rc); return -1; }
  mbedtls_ssl_set_bio (ssl, fdp, bda_tls_send, bda_tls_recv, NULL);
  while ((rc = mbedtls_ssl_handshake (ssl)) != 0) {
    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
    builtin_error ("%s TLS: handshake failed rc=%d", label, rc);
    return -1;
  }
  return 0;
}

static int
bda_conn_read_some (struct bda_conn *c, unsigned char *buf, size_t n)
{
  if (c->ssl) {
    for (;;) {
      int r = mbedtls_ssl_read (c->ssl, buf, n);
      if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
      return r;
    }
  }
  ssize_t r;
  do { r = read (c->fd, buf, n); } while (r < 0 && errno == EINTR);
  return (int) r;
}

static int
bda_conn_readn (struct bda_conn *c, unsigned char *b, size_t n)
{
  size_t g = 0;
  while (g < n) {
    int r = bda_conn_read_some (c, b + g, n - g);
    if (r <= 0) return -1;
    g += (size_t) r;
  }
  return 0;
}

static int
bda_conn_writen (struct bda_conn *c, const unsigned char *b, size_t n)
{
  size_t p = 0;
  while (p < n) {
    if (c->ssl) {
      int w = mbedtls_ssl_write (c->ssl, b + p, n - p);
      if (w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
      if (w <= 0) return -1;
      p += (size_t) w;
    } else {
      ssize_t w = write (c->fd, b + p, n - p);
      if (w < 0 && errno == EINTR) continue;
      if (w <= 0) return -1;
      p += (size_t) w;
    }
  }
  return 0;
}

static int
bda_bind_stream (const char *addr, int port)
{
  struct sockaddr_storage sa;
  socklen_t sl = 0;
  if (bd_make_sockaddr (addr, port, &sa, &sl) < 0)
    { builtin_error ("bad listen addr: %s", addr); return -1; }

  int s = socket (bd_sock_family (&sa), SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (s < 0)
    { builtin_error ("socket: %s", strerror (errno)); return -1; }
  int one = 1;
  setsockopt (s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  if (bd_set_ipv6_v6only (s, bd_sock_family (&sa), 0) < 0)
    { builtin_error ("setsockopt IPV6_V6ONLY: %s", strerror (errno)); close (s); return -1; }
  if (bind (s, (struct sockaddr *) &sa, sl) < 0)
    { builtin_error ("bind %s:%d: %s", addr, port, strerror (errno)); close (s); return -1; }
  if (listen (s, 16) < 0)
    { builtin_error ("listen: %s", strerror (errno)); close (s); return -1; }
  return s;
}

static int
bda_parse_listen (const char *spec, char *addr, size_t addr_sz, int *port)
{
  if (!spec || !*spec) return -1;
  if (spec && spec[0] == '[')
    {
      const char *end = strchr (spec, ']');
      if (!end || end == spec + 1 || end[1] != ':' || end[2] == '\0')
        return -1;
      size_t al = (size_t) (end - spec - 1);
      if (al >= addr_sz)
        return -1;
      memcpy (addr, spec + 1, al);
      addr[al] = '\0';
      char *pe = NULL;
      long p = strtol (end + 2, &pe, 10);
      if (!pe || *pe || p <= 0 || p > 65535)
        return -1;
      *port = (int) p;
      return 0;
    }
  const char *colon = strrchr (spec, ':');
  if (!colon || colon == spec || !colon[1]) return -1;
  size_t al = (size_t) (colon - spec);
  if (al >= addr_sz) return -1;
  memcpy (addr, spec, al);
  addr[al] = '\0';
  char *end = NULL;
  long p = strtol (colon + 1, &end, 10);
  if (!end || *end || p <= 0 || p > 65535) return -1;
  *port = (int) p;
  return 0;
}

/* DNS-6.2 NOTIFY-out (RFC 1996). Build a NOTIFY request (opcode 4, QR=0,
   AA=1) carrying the zone as the question (<zone> SOA IN) and, when serial
   >= 0, a minimal SOA RR in the answer section so the secondary can skip the
   transfer if it is already current. Send over UDP to host:dport and, unless
   wait==0, await the secondary's NOTIFY response (QR=1, matching ID) within
   timeout_ms, retrying up to `retries` extra times. Returns 1 on
   ack (or on send when wait==0), 0 on failure. */
static int
bd_notify_send_one (const char *zone, const char *host, int dport,
                    long serial, int timeout_ms, int retries, int wait,
                    bd_tsig_store_t *tsig_store, const bd_tsig_key_t *tsig_key)
{
  unsigned char wire[BDR_MSG_MAX]; size_t off = 12;
  unsigned char qn[256];
  int ql = bd_name_to_wire (zone, qn, sizeof qn);
  if (ql < 0) { builtin_error ("notify: bad zone name: %s", zone); return 0; }
  if (off + (size_t) ql + 4 > sizeof wire) return 0;
  memcpy (wire + off, qn, (size_t) ql); off += (size_t) ql;
  wire[off++] = 0; wire[off++] = 6;            /* QTYPE  = SOA */
  wire[off++] = 0; wire[off++] = 1;            /* QCLASS = IN  */
  uint16_t ancount = 0;
  if (serial >= 0) {
    if (off + (size_t) ql + 10 + 2 + 2 + 16 <= sizeof wire) {
      memcpy (wire + off, qn, (size_t) ql); off += (size_t) ql;   /* owner */
      wire[off++] = 0; wire[off++] = 6;        /* SOA */
      wire[off++] = 0; wire[off++] = 1;        /* IN  */
      wire[off++] = 0; wire[off++] = 0; wire[off++] = 0; wire[off++] = 0; /* TTL 0 */
      size_t rdlen_at = off; off += 2;         /* RDLENGTH placeholder */
      size_t rd0 = off;
      wire[off++] = 0;                         /* mname = root */
      wire[off++] = 0;                         /* rname = root */
      uint32_t s = (uint32_t) serial;
      wire[off++] = (unsigned char) (s >> 24); wire[off++] = (unsigned char) (s >> 16);
      wire[off++] = (unsigned char) (s >> 8);  wire[off++] = (unsigned char) s;
      for (int k = 0; k < 16; k++) wire[off++] = 0; /* refresh retry expire minimum */
      size_t rdl = off - rd0;
      wire[rdlen_at] = (unsigned char) (rdl >> 8); wire[rdlen_at + 1] = (unsigned char) rdl;
      ancount = 1;
    }
  }
  wire[2] = 0x24; wire[3] = 0x00;              /* QR=0 OPCODE=4(NOTIFY) AA=1 */
  wire[4] = 0; wire[5] = 1;                    /* QDCOUNT = 1 */
  wire[6] = (unsigned char) (ancount >> 8); wire[7] = (unsigned char) ancount;
  wire[8] = wire[9] = wire[10] = wire[11] = 0;

  struct sockaddr_storage da;
  socklen_t dl = 0;
  if (bd_make_sockaddr (host, dport, &da, &dl) < 0)
    { builtin_error ("notify: bad target addr: %s", host); return 0; }

  for (int attempt = 0; attempt <= retries; attempt++) {
    uint16_t id = (uint16_t) (getpid () ^ (time (NULL) + dport * 7 + attempt * 131));
    wire[0] = (unsigned char) (id >> 8); wire[1] = (unsigned char) id;
    size_t send_len = off;
    unsigned char req_mac[BD_TSIG_MAC_MAX]; size_t req_mac_len = 0;
    if (tsig_key)
      {
        if (bd_tsig_sign (wire, sizeof wire, &send_len, tsig_key, NULL, 0,
                          (uint64_t) bd_tsig_now (), BD_TSIG_DEFAULT_FUDGE,
                          req_mac, &req_mac_len) < 0)
          return 0;
      }
    int s = socket (bd_sock_family (&da), SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) return 0;
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt (s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt (s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    if (sendto (s, wire, send_len, 0, (struct sockaddr *) &da, dl) < 0) { close (s); continue; }
    if (!wait) { close (s); return 1; }
    unsigned char rb[BDR_MSG_MAX];
    ssize_t rn = recvfrom (s, rb, sizeof rb, 0, NULL, NULL);
    close (s);
    if (rn >= 12 && rb[0] == wire[0] && rb[1] == wire[1] && (rb[2] & 0x80))
      {
        bd_tsig_rr_t rr;
        if (tsig_key && bd_tsig_find (rb, (size_t) rn, &rr) == BD_TSIG_OK)
          {
            size_t rnl = (size_t) rn;
            int v = bd_tsig_verify (rb, &rnl, tsig_store, 1,
                                    (uint64_t) bd_tsig_now (),
                                    req_mac, req_mac_len, NULL, NULL, NULL);
            if (v != BD_TSIG_OK) continue;
          }
        return 1;                              /* QR=1 echo of our ID */
      }
  }
  return 0;
}

static int
bd_notify_cmd (WORD_LIST *args)
{
  const char *zone = NULL;
  char to[BDR_ACL_MAX][80]; int nto = 0;       /* IP[:PORT] secondaries */
  long serial = -1;                            /* -1 -> omit SOA answer */
  int timeout_ms = 2000, retries = 2, wait = 1;
  bd_tsig_store_t tsig_store; memset (&tsig_store, 0, sizeof tsig_store);
  const char *transfer_key_name = NULL;

  for (; args; args = args->next) {
    const char *w = args->word->word;
    if (!strcmp (w, "--zone") && args->next) { zone = args->next->word->word; args = args->next; }
    else if (!strcmp (w, "--to") && args->next) { if (nto < BDR_ACL_MAX) { strncpy (to[nto], args->next->word->word, 79); to[nto][79] = '\0'; nto++; } args = args->next; }
    else if (!strcmp (w, "--serial") && args->next) { serial = atol (args->next->word->word); args = args->next; }
    else if (!strcmp (w, "--timeout") && args->next) { timeout_ms = atoi (args->next->word->word); args = args->next; }
    else if (!strcmp (w, "--retries") && args->next) { retries = atoi (args->next->word->word); args = args->next; }
    else if (!strcmp (w, "--no-wait")) { wait = 0; }
    else if (!strcmp (w, "--tsig-key") && args->next)
      { if (bd_tsig_add_inline (&tsig_store, args->next->word->word) < 0) { builtin_error ("notify: bad --tsig-key"); return EX_USAGE; } args = args->next; }
    else if (!strcmp (w, "--tsig-keys") && args->next)
      { if (bd_tsig_load_keys (&tsig_store, args->next->word->word) < 0) return EXECUTION_FAILURE; args = args->next; }
    else if (!strcmp (w, "--transfer-key") && args->next) { transfer_key_name = args->next->word->word; args = args->next; }
    else { builtin_error ("notify: unknown option: %s", w); return EX_USAGE; }
  }
  if (!zone || !*zone) { builtin_error ("notify: --zone NAME is required"); return EX_USAGE; }
  if (nto == 0) { builtin_error ("notify: at least one --to IP[:PORT] is required"); return EX_USAGE; }
  if (retries < 0) retries = 0;
  bd_tsig_key_t *notify_key = NULL;
  if (transfer_key_name)
    {
      notify_key = bd_tsig_find_key (&tsig_store, transfer_key_name);
      if (!notify_key) { builtin_error ("notify: --transfer-key not found: %s", transfer_key_name); return EX_USAGE; }
    }
  else if (tsig_store.n > 0)
    notify_key = &tsig_store.keys[0];

  int ok = 0, failed = 0;
  for (int t = 0; t < nto; t++) {
    char host[80]; int dport = 53;
    if (bd_split_host_port_default (to[t], host, sizeof host, &dport, 53) < 0)
      { failed++; continue; }
    int got = bd_notify_send_one (zone, host, dport, serial, timeout_ms, retries, wait,
                                  &tsig_store, notify_key);
    if (got) ok++; else failed++;
    printf ("notify %s -> %s:%d %s\n", zone, host, dport,
            got ? (wait ? "ack" : "sent") : (wait ? "no-response" : "send-failed"));
  }
  fprintf (stderr, "notify: zone=%s targets=%d ok=%d failed=%d\n", zone, nto, ok, failed);
  return (failed == 0) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* rndc-shaped control client (DNS-6.2): connect to an auth-serve UNIX control
   socket and run one command (status / stats / serial / reload / stop),
   printing the daemon's reply. */
static int
bd_rndc_cmd (WORD_LIST *args)
{
  const char *sock = NULL, *command = NULL;
  for (; args; args = args->next) {
    const char *w = args->word->word;
    if ((!strcmp (w, "--socket") || !strcmp (w, "-s")) && args->next) { sock = args->next->word->word; args = args->next; }
    else if (!command) command = w;
    else { builtin_error ("rndc: unexpected argument: %s", w); return EX_USAGE; }
  }
  if (!sock)    { builtin_error ("rndc: --socket PATH is required"); return EX_USAGE; }
  if (!command) { builtin_error ("rndc: a command is required (status|stats|serial|reload|stop)"); return EX_USAGE; }

  int s = socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (s < 0) { builtin_error ("socket: %s", strerror (errno)); return EXECUTION_FAILURE; }
  struct sockaddr_un ua; memset (&ua, 0, sizeof ua); ua.sun_family = AF_UNIX;
  if (strlen (sock) >= sizeof ua.sun_path) { builtin_error ("rndc: socket path too long"); close (s); return EXECUTION_FAILURE; }
  strncpy (ua.sun_path, sock, sizeof ua.sun_path - 1);
  struct timeval tv = { 3, 0 };
  setsockopt (s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  if (connect (s, (struct sockaddr *) &ua, sizeof ua) < 0) { builtin_error ("rndc: connect %s: %s", sock, strerror (errno)); close (s); return EXECUTION_FAILURE; }
  char line[160]; int ln = snprintf (line, sizeof line, "%s\n", command);
  if (ln < 0 || (size_t) ln >= sizeof line) { close (s); return EXECUTION_FAILURE; }
  if (write (s, line, (size_t) ln) != ln) { builtin_error ("rndc: write: %s", strerror (errno)); close (s); return EXECUTION_FAILURE; }
  char reply[1024]; ssize_t rn = read (s, reply, sizeof reply - 1);
  close (s);
  if (rn <= 0) { builtin_error ("rndc: no reply from %s", sock); return EXECUTION_FAILURE; }
  reply[rn] = '\0';
  fputs (reply, stdout);
  if (reply[rn - 1] != '\n') fputc ('\n', stdout);
  return (strncmp (reply, "error:", 6) == 0) ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

/* Read the apex SOA serial from a loaded zone, or -1 if absent. The SOA
   rdata is uncompressed wire form: mname rname serial(4) ... */
static long
bda_apex_serial (struct bda_zone *z)
{
  for (int i = 0; i < z->n; i++) {
    char o[256]; bda_owner (z, i, o, sizeof o);
    if (z->rr[i].type == BDA_SOA && !strcmp (o, z->apex)) {
      const unsigned char *rd = z->rr[i].rdata; size_t rl = z->rr[i].rdata_len, p = 0;
      for (int names = 0; names < 2 && p < rl; names++)        /* skip mname, rname */
        { while (p < rl && rd[p] != 0) p += rd[p] + 1; if (p < rl) p++; }
      if (p + 4 <= rl) return (long) bd_rd32 (rd + p);
      return -1;
    }
  }
  return -1;
}

/* IXFR record identity: same owner + type + rdata (TTL is not compared). */
static int
bda_rr_same (struct bda_zone *za, int i, struct bda_zone *zb, int j)
{
  if (za->rr[i].type != zb->rr[j].type) return 0;
  if (za->rr[i].rdata_len != zb->rr[j].rdata_len) return 0;
  char oa[256], ob[256]; bda_owner (za, i, oa, sizeof oa); bda_owner (zb, j, ob, sizeof ob);
  if (strcmp (oa, ob)) return 0;
  return memcmp (za->rr[i].rdata, zb->rr[j].rdata, za->rr[i].rdata_len) == 0;
}

static int
bda_rr_same_ptr (const bd_rr_t *a, const bd_rr_t *b)
{
  if (a->type != b->type || a->rdata_len != b->rdata_len) return 0;
  char oa[256], ob[256];
  snprintf (oa, sizeof oa, "%s", a->owner); bda_norm (oa);
  snprintf (ob, sizeof ob, "%s", b->owner); bda_norm (ob);
  return strcmp (oa, ob) == 0 && memcmp (a->rdata, b->rdata, a->rdata_len) == 0;
}

static void
bda_jdelta_free (struct bda_jdelta *d) { free (d->del); free (d->add); d->del = d->add = NULL; d->ndel = d->nadd = 0; }

/* Record the old->new delta as a journal entry on newz (carrying oldz's prior
   journal forward, oldest evicted past BDA_JRNL_MAX). Ownership of the carried
   deltas moves to newz; oldz->njrnl is zeroed so the caller's free of oldz does
   not double-free. A no-op serial change just carries the journal. */
static void
bda_journal_record (struct bda_zone *oldz, struct bda_zone *newz)
{
  /* carry prior journal */
  int k = 0;
  for (int i = 0; i < oldz->njrnl && k < BDA_JRNL_MAX; i++) newz->jrnl[k++] = oldz->jrnl[i];
  newz->njrnl = k;
  oldz->njrnl = 0;

  uint32_t from = (uint32_t) bda_apex_serial (oldz);
  uint32_t to   = (uint32_t) bda_apex_serial (newz);
  if (from == to) return;                       /* nothing new to journal */

  bd_rr_t *del = calloc (oldz->n > 0 ? oldz->n : 1, sizeof (bd_rr_t));
  bd_rr_t *add = calloc (newz->n > 0 ? newz->n : 1, sizeof (bd_rr_t));
  if (!del || !add) { free (del); free (add); return; }   /* journal best-effort */
  int ndel = 0, nadd = 0;
  for (int i = 0; i < oldz->n; i++) {
    int found = 0;
    for (int j = 0; j < newz->n; j++) if (bda_rr_same (oldz, i, newz, j)) { found = 1; break; }
    if (!found) del[ndel++] = oldz->rr[i];
  }
  for (int j = 0; j < newz->n; j++) {
    int found = 0;
    for (int i = 0; i < oldz->n; i++) if (bda_rr_same (newz, j, oldz, i)) { found = 1; break; }
    if (!found) add[nadd++] = newz->rr[j];
  }

  struct bda_jdelta e = { del, ndel, add, nadd, from, to };
  if (newz->njrnl < BDA_JRNL_MAX) newz->jrnl[newz->njrnl++] = e;
  else { bda_jdelta_free (&newz->jrnl[0]);
         memmove (&newz->jrnl[0], &newz->jrnl[1], (BDA_JRNL_MAX - 1) * sizeof e);
         newz->jrnl[BDA_JRNL_MAX - 1] = e; }
}

static void
bda_journal_free_all (struct bda_zone *z) { for (int i = 0; i < z->njrnl; i++) bda_jdelta_free (&z->jrnl[i]); z->njrnl = 0; }

/* Extract the client's current SOA serial from an IXFR query's authority
   section (RFC 1995). 0 if absent -> forces a full AXFR. */
static uint32_t
bda_ixfr_client_serial (const unsigned char *q, size_t qlen)
{
  if (qlen < 12) return 0;
  uint16_t qd = bd_rd16 (q + 4), ns = bd_rd16 (q + 8);
  size_t off = 12; char nm[256];
  for (int i = 0; i < qd; i++) { if (bd_decode_name (q, qlen, &off, nm, sizeof nm, 0) < 0) return 0; off += 4; if (off > qlen) return 0; }
  for (int i = 0; i < ns; i++) {
    if (bd_decode_name (q, qlen, &off, nm, sizeof nm, 0) < 0) return 0;
    if (off + 10 > qlen) return 0;
    uint16_t typ = bd_rd16 (q + off);
    uint16_t rdl = bd_rd16 (q + off + 8);
    size_t rdat = off + 10;
    if (typ == BDA_SOA) {
      size_t p = rdat, end = rdat + rdl;
      for (int k = 0; k < 2 && p < end; k++) { while (p < end && q[p] != 0) p += q[p] + 1; if (p < end) p++; }
      if (p + 4 <= end) return bd_rd32 (q + p);
      return 0;
    }
    off = rdat + rdl;
  }
  return 0;
}

/* Build an RFC 1995 incremental IXFR response advancing the client from
   client_serial to current. Returns response length, or -2 when no journal
   path exists (caller falls back to AXFR), or -1 on error. */
static int
bda_build_ixfr (struct bda_zone *z, const unsigned char *q, size_t qlen,
                uint32_t client_serial, unsigned char *out, size_t osz)
{
  size_t qoff = 12; char tmp[256];
  if (bd_decode_name (q, qlen, &qoff, tmp, sizeof tmp, 0) < 0) return -1;
  qoff += 4; if (qoff > qlen) return -1;

  bd_rr_t *soa = NULL;
  for (int i = 0; i < z->n; i++) { char o[256]; bda_owner (z, i, o, sizeof o);
    if (z->rr[i].type == BDA_SOA && !strcmp (o, z->apex)) { soa = &z->rr[i]; break; } }
  if (!soa) return -1;
  uint32_t cur = (uint32_t) bda_apex_serial (z);

  /* Order journal steps into a path client_serial -> ... -> cur. */
  struct bda_jdelta *path[BDA_JRNL_MAX]; int plen = 0;
  uint32_t at = client_serial;
  while (at != cur) {
    int adv = 0;
    for (int i = 0; i < z->njrnl; i++)
      if (z->jrnl[i].from == at) { path[plen++] = &z->jrnl[i]; at = z->jrnl[i].to; adv = 1; break; }
    if (!adv || plen >= BDA_JRNL_MAX) return -2;       /* no path -> AXFR */
  }

  memcpy (out, q, qoff);
  out[2] = 0x84; out[3] = 0x00;
  size_t off = qoff; uint16_t an = 0;
  if (bda_put_rr (out, osz, &off, z->apex, BDA_SOA, soa->ttl, soa->rdata, soa->rdata_len) < 0) return -1; an++;
  for (int s = 0; s < plen; s++) {
    struct bda_jdelta *d = path[s];
    /* SOA(old) then deletions */
    for (int i = 0; i < d->ndel; i++) if (d->del[i].type == BDA_SOA)
      { if (bda_put_rr (out, osz, &off, d->del[i].owner, BDA_SOA, d->del[i].ttl, d->del[i].rdata, d->del[i].rdata_len) < 0) return -1; an++; }
    for (int i = 0; i < d->ndel; i++) if (d->del[i].type != BDA_SOA)
      { if (bda_put_rr (out, osz, &off, d->del[i].owner, d->del[i].type, d->del[i].ttl, d->del[i].rdata, d->del[i].rdata_len) < 0) return -1; an++; }
    /* SOA(new) then additions */
    for (int i = 0; i < d->nadd; i++) if (d->add[i].type == BDA_SOA)
      { if (bda_put_rr (out, osz, &off, d->add[i].owner, BDA_SOA, d->add[i].ttl, d->add[i].rdata, d->add[i].rdata_len) < 0) return -1; an++; }
    for (int i = 0; i < d->nadd; i++) if (d->add[i].type != BDA_SOA)
      { if (bda_put_rr (out, osz, &off, d->add[i].owner, d->add[i].type, d->add[i].ttl, d->add[i].rdata, d->add[i].rdata_len) < 0) return -1; an++; }
  }
  if (bda_put_rr (out, osz, &off, z->apex, BDA_SOA, soa->ttl, soa->rdata, soa->rdata_len) < 0) return -1; an++;
  out[6] = (unsigned char) (an >> 8); out[7] = (unsigned char) an;
  out[8] = out[9] = out[10] = out[11] = 0;
  return (int) off;
}

static int
bda_collect_xfr_msg_answers (const unsigned char *msg, size_t msg_len,
                             bd_rr_t *out, int out_max, int *n)
{
  if (msg_len < 12 || *n >= out_max) return -1;
  uint16_t an = bd_rd16 (msg + 6);
  size_t off = 12;
  if (bd_skip_question (msg, msg_len, &off) < 0) return -1;
  int got = bd_collect_rrs (msg, msg_len, &off, an, NULL, 0, out + *n, out_max - *n);
  if (got < 0) return -1;
  *n += got;
  return 0;
}

static int
bda_collect_xfr_answers (const unsigned char *stream, size_t len, int framed,
                         bd_rr_t *out, int out_max)
{
  int n = 0;
  if (!framed)
    return bda_collect_xfr_msg_answers (stream, len, out, out_max, &n) == 0 ? n : -1;
  size_t off = 0;
  while (off + 2 <= len)
    {
      uint16_t ml = bd_rd16 (stream + off);
      off += 2;
      if (ml < 12 || off + ml > len) return -1;
      if (bda_collect_xfr_msg_answers (stream + off, ml, out, out_max, &n) < 0)
        return -1;
      off += ml;
    }
  return (off == len) ? n : -1;
}

static void
bda_zone_init_empty (struct bda_zone *z)
{
  memset (z, 0, sizeof *z);
}

static void
bda_zone_free_one (struct bda_zone *z)
{
  if (!z) return;
  bda_journal_free_all (z);
  free (z->rr);
  z->rr = NULL;
  z->n = 0;
}

static int
bda_zone_clone (const struct bda_zone *src, struct bda_zone *dst)
{
  bda_zone_init_empty (dst);
  dst->rr = calloc ((size_t) (src->n > 0 ? src->n : 1), sizeof (bd_rr_t));
  if (!dst->rr) return -1;
  memcpy (dst->rr, src->rr, (size_t) src->n * sizeof (bd_rr_t));
  dst->n = src->n;
  snprintf (dst->apex, sizeof dst->apex, "%s", src->apex);
  snprintf (dst->path, sizeof dst->path, "%s", src->path);
  snprintf (dst->origin, sizeof dst->origin, "%s", src->origin);
  return 0;
}

static int
bda_zone_remove_rr (struct bda_zone *z, const bd_rr_t *rr)
{
  for (int i = 0; i < z->n; i++)
    if (bda_rr_same_ptr (&z->rr[i], rr))
      {
        if (i + 1 < z->n)
          memmove (&z->rr[i], &z->rr[i + 1], (size_t) (z->n - i - 1) * sizeof (bd_rr_t));
        z->n--;
        return 0;
      }
  return -1;
}

static int
bda_zone_add_rr (struct bda_zone *z, const bd_rr_t *rr)
{
  if (z->n >= BDA_RR_MAX) return -1;
  bd_rr_t *t = realloc (z->rr, (size_t) (z->n + 1) * sizeof (bd_rr_t));
  if (!t) return -1;
  z->rr = t;
  z->rr[z->n++] = *rr;
  return 0;
}

static int
bda_apply_axfr_stream (const unsigned char *stream, size_t len, int framed,
                       struct bda_zone *out)
{
  bd_rr_t *rrs = calloc ((size_t) BDA_RR_MAX + 2, sizeof (bd_rr_t));
  if (!rrs) return -1;
  int n = bda_collect_xfr_answers (stream, len, framed, rrs, BDA_RR_MAX + 2);
  if (n < 2 || rrs[0].type != BDA_SOA || rrs[n - 1].type != BDA_SOA)
    { free (rrs); return -1; }
  char apex[256], tail[256];
  snprintf (apex, sizeof apex, "%s", rrs[0].owner); bda_norm (apex);
  snprintf (tail, sizeof tail, "%s", rrs[n - 1].owner); bda_norm (tail);
  if (strcmp (apex, tail)) { free (rrs); return -1; }
  for (int i = 1; i < n - 1; i++)
    if (rrs[i].type == BDA_SOA) { free (rrs); return -1; }

  bda_zone_init_empty (out);
  out->rr = calloc ((size_t) (n - 1), sizeof (bd_rr_t));
  if (!out->rr) { free (rrs); return -1; }
  out->rr[0] = rrs[0];
  for (int i = 1; i < n - 1; i++) out->rr[i] = rrs[i];
  out->n = n - 1;
  snprintf (out->apex, sizeof out->apex, "%s", apex);
  free (rrs);
  return 0;
}

static int
bda_apply_axfr (const unsigned char *stream, size_t len, struct bda_zone *out)
{
  return bda_apply_axfr_stream (stream, len, 0, out);
}

static int
bda_apply_ixfr_stream (const unsigned char *stream, size_t len, int framed,
                       struct bda_zone *z)
{
  bd_rr_t *rrs = calloc ((size_t) BDA_RR_MAX + 2, sizeof (bd_rr_t));
  if (!rrs) return -1;
  int n = bda_collect_xfr_answers (stream, len, framed, rrs, BDA_RR_MAX + 2);
  if (n < 2 || rrs[0].type != BDA_SOA || rrs[n - 1].type != BDA_SOA)
    { free (rrs); return -1; }
  if (n == 2 || rrs[1].type != BDA_SOA)
    {
      struct bda_zone ax;
      if (bda_apply_axfr_stream (stream, len, framed, &ax) < 0)
        { free (rrs); return -1; }
      bda_zone_free_one (z);
      *z = ax;
      free (rrs);
      return 0;
    }

  struct bda_zone work;
  if (bda_zone_clone (z, &work) < 0) { free (rrs); return -1; }
  int i = 1;
  while (i < n - 1)
    {
      if (rrs[i].type != BDA_SOA) { bda_zone_free_one (&work); free (rrs); return -1; }
      int del_start = i++;
      while (i < n && rrs[i].type != BDA_SOA) i++;
      if (i >= n - 1 || rrs[i].type != BDA_SOA) { bda_zone_free_one (&work); free (rrs); return -1; }
      int add_start = i++;
      while (i < n && rrs[i].type != BDA_SOA) i++;

      for (int d = del_start; d < add_start; d++)
        if (bda_zone_remove_rr (&work, &rrs[d]) < 0)
          { bda_zone_free_one (&work); free (rrs); return -1; }
      for (int a = add_start; a < i; a++)
        if (bda_zone_add_rr (&work, &rrs[a]) < 0)
          { bda_zone_free_one (&work); free (rrs); return -1; }

      if (i == n - 1)
        break;
    }
  if (i != n - 1 || !bda_rr_same_ptr (&rrs[0], &rrs[n - 1]))
    { bda_zone_free_one (&work); free (rrs); return -1; }
  snprintf (work.apex, sizeof work.apex, "%s", rrs[0].owner);
  bda_norm (work.apex);
  bda_zone_free_one (z);
  *z = work;
  free (rrs);
  return 0;
}

static int
bda_apply_ixfr (const unsigned char *stream, size_t len, struct bda_zone *z)
{
  return bda_apply_ixfr_stream (stream, len, 0, z);
}

static int
bda_zone_equal_set (struct bda_zone *a, struct bda_zone *b)
{
  if (a->n != b->n) return 0;
  for (int i = 0; i < a->n; i++)
    {
      int found = 0;
      for (int j = 0; j < b->n; j++)
        if (bda_rr_same (a, i, b, j)) { found = 1; break; }
      if (!found) return 0;
    }
  return 1;
}

static int
bda_soa_fields (struct bda_zone *z, uint32_t *serial, uint32_t *refresh,
                uint32_t *retry, uint32_t *expire, uint32_t *minimum)
{
  for (int i = 0; i < z->n; i++)
    {
      char o[256]; bda_owner (z, i, o, sizeof o);
      if (z->rr[i].type == BDA_SOA && !strcmp (o, z->apex))
        {
          const unsigned char *rd = z->rr[i].rdata;
          size_t rl = z->rr[i].rdata_len, p = 0;
          for (int names = 0; names < 2 && p < rl; names++)
            { while (p < rl && rd[p] != 0) p += rd[p] + 1; if (p < rl) p++; }
          if (p + 20 > rl) return -1;
          if (serial)  *serial  = bd_rd32 (rd + p);
          if (refresh) *refresh = bd_rd32 (rd + p + 4);
          if (retry)   *retry   = bd_rd32 (rd + p + 8);
          if (expire)  *expire  = bd_rd32 (rd + p + 12);
          if (minimum) *minimum = bd_rd32 (rd + p + 16);
          return 0;
        }
    }
  return -1;
}

enum bda_slave_action { BDA_SLAVE_IDLE, BDA_SLAVE_REFRESH_DUE, BDA_SLAVE_RETRY_DUE, BDA_SLAVE_EXPIRED };

struct bda_slave_state {
  time_t last_ok, last_try;
  uint32_t refresh, retry, expire;
  int force;
};

static enum bda_slave_action
bda_slave_next_action (const struct bda_slave_state *s, time_t now)
{
  if (s->force) return BDA_SLAVE_REFRESH_DUE;
  if (s->last_ok <= 0) return BDA_SLAVE_REFRESH_DUE;
  if (s->expire && now >= s->last_ok + (time_t) s->expire) return BDA_SLAVE_EXPIRED;
  if (s->last_try > s->last_ok && s->retry && now >= s->last_try + (time_t) s->retry)
    return BDA_SLAVE_RETRY_DUE;
  if (s->refresh && now >= s->last_ok + (time_t) s->refresh) return BDA_SLAVE_REFRESH_DUE;
  return BDA_SLAVE_IDLE;
}

static const char *
bda_slave_action_name (enum bda_slave_action a)
{
  switch (a)
    {
    case BDA_SLAVE_REFRESH_DUE: return "refresh-due";
    case BDA_SLAVE_RETRY_DUE: return "retry-due";
    case BDA_SLAVE_EXPIRED: return "expired";
    default: return "idle";
    }
}

/* Send a (possibly large) AXFR to fd c as one OR MORE DNS messages on the TCP
   stream (RFC 5936 sec.2.2): records are packed into ~15 KiB messages, the
   first starting with the apex SOA and the last ending with it, so zones that
   exceed a single 64 KiB message still transfer. Returns 0/-1. */
static int
bda_send_axfr (int c, struct bda_zone *z, const unsigned char *q, size_t qlen,
               const bd_tsig_key_t *tsig_key, const unsigned char *prior_mac,
               size_t prior_mac_len)
{
  size_t qoff = 12; char tmp[256];
  if (bd_decode_name (q, qlen, &qoff, tmp, sizeof tmp, 0) < 0) return -1;
  qoff += 4; if (qoff > qlen) return -1;
  bd_rr_t *soa = NULL;
  for (int i = 0; i < z->n; i++) { char o[256]; bda_owner (z, i, o, sizeof o);
    if (z->rr[i].type == BDA_SOA && !strcmp (o, z->apex)) { soa = &z->rr[i]; break; } }
  if (!soa) return -1;

  unsigned char msg[16384];
  const size_t SOFTCAP = 15000;
  size_t off = 0; uint16_t an = 0;
  unsigned char chain_mac[BD_TSIG_MAC_MAX];
  size_t chain_mac_len = 0;
  if (prior_mac && prior_mac_len)
    {
      if (prior_mac_len > sizeof chain_mac) return -1;
      memcpy (chain_mac, prior_mac, prior_mac_len);
      chain_mac_len = prior_mac_len;
    }
#define BDA_MSG_START() do { memcpy (msg, q, qoff); msg[2] = 0x84; msg[3] = 0x00; \
      msg[8] = msg[9] = msg[10] = msg[11] = 0; off = qoff; an = 0; } while (0)
#define BDA_MSG_FLUSH() do { msg[6] = (unsigned char) (an >> 8); msg[7] = (unsigned char) an; \
      if (tsig_key) { size_t _ml = off; unsigned char _mac[BD_TSIG_MAC_MAX]; size_t _macl = 0; \
        if (bd_tsig_sign (msg, sizeof msg, &_ml, tsig_key, chain_mac_len ? chain_mac : NULL, chain_mac_len, \
                          (uint64_t) bd_tsig_now (), BD_TSIG_DEFAULT_FUDGE, _mac, &_macl) < 0) return -1; \
        memcpy (chain_mac, _mac, _macl); chain_mac_len = _macl; off = _ml; } \
      unsigned char ol[2] = { (unsigned char) (off >> 8), (unsigned char) off }; \
      if (bda_writen (c, ol, 2) != 0 || bda_writen (c, msg, off) != 0) return -1; } while (0)

  BDA_MSG_START ();
  if (bda_put_rr (msg, sizeof msg, &off, z->apex, BDA_SOA, soa->ttl, soa->rdata, soa->rdata_len) < 0) return -1; an++;
  for (int i = 0; i < z->n; i++) {
    if (z->rr[i].type == BDA_SOA) continue;
    if (off > SOFTCAP) { BDA_MSG_FLUSH (); BDA_MSG_START (); }
    char o[256]; bda_owner (z, i, o, sizeof o);
    if (bda_put_rr (msg, sizeof msg, &off, o, z->rr[i].type, z->rr[i].ttl, z->rr[i].rdata, z->rr[i].rdata_len) < 0) return -1; an++;
  }
  if (off > SOFTCAP) { BDA_MSG_FLUSH (); BDA_MSG_START (); }
  if (bda_put_rr (msg, sizeof msg, &off, z->apex, BDA_SOA, soa->ttl, soa->rdata, soa->rdata_len) < 0) return -1; an++;
  BDA_MSG_FLUSH ();
#undef BDA_MSG_START
#undef BDA_MSG_FLUSH
  return 0;
}

/* Load a master file into z (allocating + trimming z->rr to the actual record
   count so a multi-zone array stays cheap), recording path+origin for reload.
   Returns 0 on success, -1 on parse/alloc failure (z->rr left NULL). */
static int
bda_load_into (struct bda_zone *z, const char *path, const char *origin)
{
  z->rr = calloc (BDA_RR_MAX, sizeof (bd_rr_t));
  if (!z->rr) return -1;
  z->n = sz_load_zone (path, origin, z->rr, BDA_RR_MAX, z->apex, sizeof z->apex);
  if (z->n < 0) { free (z->rr); z->rr = NULL; return -1; }
  bda_norm (z->apex);
  bd_rr_t *t = realloc (z->rr, (size_t) (z->n > 0 ? z->n : 1) * sizeof (bd_rr_t));
  if (t) z->rr = t;
  snprintf (z->path, sizeof z->path, "%s", path);
  snprintf (z->origin, sizeof z->origin, "%s", origin ? origin : "");
  z->njrnl = 0;
  return 0;
}

/* Pick the most specific hosted zone for qname: the one whose apex is the
   longest in-bailiwick suffix. -1 if none owns the name (-> REFUSED). */
static int
bda_route (struct bda_zone *zones, int nz, const char *qname)
{
  int best = -1; size_t bestlen = 0;
  for (int i = 0; i < nz; i++)
    if (bda_in_zone (qname, zones[i].apex)) {
      size_t al = strlen (zones[i].apex);
      if (best < 0 || al > bestlen) { best = i; bestlen = al; }
    }
  return best;
}

/* Synthesize a REFUSED response (QR=1, RCODE=5) echoing the question — used
   when no hosted zone owns the queried name. */
static int
bda_refused (const unsigned char *q, size_t qlen, unsigned char *resp, size_t rsz)
{
  size_t qoff = 12; char tmp[256];
  if (bd_decode_name (q, qlen, &qoff, tmp, sizeof tmp, 0) < 0) return -1;
  qoff += 4;
  if (qoff > rsz || qoff > qlen) return -1;
  memcpy (resp, q, qoff);
  resp[2] = 0x84; resp[3] = 0x05;                /* QR=1 AA=1 RCODE=REFUSED */
  resp[6] = resp[7] = resp[8] = resp[9] = resp[10] = resp[11] = 0;
  return (int) qoff;
}

/* ===================================================================== *
 * F02 DNS policy engines (default-off): split-horizon views, Response
 * Policy Zones (RPZ), and DNS64 synthesis. Each is a bounded first slice;
 * absent the relevant flag, behavior is byte-identical to the pre-change
 * answer path. See COMPLETED/dns-policy-engines.md.
 * ===================================================================== */

/* ---- Tranche A: split-horizon views (auth side) -------------------- */

/* A view is a named CIDR set plus its own loaded zone array. At answer
   time the first view whose any-CIDR matches the client peer is selected,
   and the query is routed within that view's zones; if no view matches,
   the global (viewless) zones answer as today. */
struct bda_view {
  char name[64];
  char cidrs[BDR_ACL_MAX][64];
  int  ncidr;
  struct bda_zone zones[BDA_ZONE_MAX];
  int  nz;
};
#define BDA_VIEW_MAX 16

/* First view (declaration order) whose CIDR set matches peer, else -1. */
static int
bda_view_select (const struct bda_view *views, int nv,
                 const struct sockaddr_storage *peer)
{
  if (!peer) return -1;
  for (int i = 0; i < nv; i++)
    for (int j = 0; j < views[i].ncidr; j++)
      if (bdr_cidr_match_peer (peer, views[i].cidrs[j]))
        return i;
  return -1;
}

/* Parse NAME:CIDR[,CIDR...]:DIR into view (CIDRs only; DIR returned via
   *dir_out for the caller to load). Returns 0 on success, -1 on malformed. */
static int
bda_view_parse_spec (const char *spec, struct bda_view *v,
                     char *dir_out, size_t dir_sz)
{
  if (!spec || !*spec) return -1;
  memset (v, 0, sizeof *v);
  char buf[1024];
  snprintf (buf, sizeof buf, "%s", spec);
  char *c1 = strchr (buf, ':');
  if (!c1) return -1;
  *c1 = '\0';
  char *cidrs = c1 + 1;
  /* The DIR may itself contain ':' (rare); split on the LAST ':' so an
     absolute DIR is preserved and the middle is the CIDR list. */
  char *c2 = strrchr (cidrs, ':');
  if (!c2) return -1;
  *c2 = '\0';
  const char *dir = c2 + 1;
  if (!*buf || !*cidrs || !*dir) return -1;
  snprintf (v->name, sizeof v->name, "%s", buf);
  snprintf (dir_out, dir_sz, "%s", dir);
  char *p = cidrs;
  while (p && *p && v->ncidr < BDR_ACL_MAX) {
    char *comma = strchr (p, ',');
    if (comma) *comma = '\0';
    if (*p) { snprintf (v->cidrs[v->ncidr], sizeof v->cidrs[v->ncidr], "%s", p); v->ncidr++; }
    p = comma ? comma + 1 : NULL;
  }
  return v->ncidr > 0 ? 0 : -1;
}

/* ---- Tranche B: Response Policy Zones (RPZ) ----------------------- */

/* RPZ actions resolved from a trigger match. */
enum { BD_RPZ_NONE = 0, BD_RPZ_NXDOMAIN, BD_RPZ_NODATA,
       BD_RPZ_PASSTHRU, BD_RPZ_LOCALDATA };

#define BDA_RPZ_MAX        8     /* policy zones per server */
#define BDA_RPZ_LOCAL_MAX  16    /* localdata RRs returned for one trigger */

/* Sentinel from bd_rpz_apply: caller should continue with normal answer. */
#define BD_RPZ_NO_RESPONSE  (-2)

/* One loaded policy zone (its apex is the RPZ origin, e.g. rpz.local). */
struct bda_rpz { struct bda_zone z; };

/* Decode the special CNAME action target ("." / "*." / "rpz-passthru.")
   from a CNAME RR's wire rdata into act. Returns 1 if the CNAME encodes a
   policy action, 0 if it is plain local data (a real CNAME answer). */
static int
bd_rpz_cname_action (const unsigned char *rdata, uint16_t rdlen, int *act)
{
  char tgt[256]; size_t off = 0;
  /* rdata holds a single canonical wire-form domain name. */
  if (bd_decode_name (rdata, rdlen, &off, tgt, sizeof tgt, 0) < 0) return 0;
  /* bd_decode_name yields "" for the root, no trailing dot otherwise. */
  if (tgt[0] == '\0') { *act = BD_RPZ_NXDOMAIN; return 1; }   /* CNAME .   */
  if (!strcasecmp (tgt, "*")) { *act = BD_RPZ_NODATA; return 1; } /* CNAME *. */
  if (!strcasecmp (tgt, "rpz-passthru")) { *act = BD_RPZ_PASSTHRU; return 1; }
  return 0;                                          /* plain local CNAME */
}

/* Collect the RRs at policy owner `owner` in rpz zone z into out[] (up to
   BDA_RPZ_LOCAL_MAX). Returns the count, or resolves a special CNAME action
   into *act (in which case the count is 0). */
static int
bd_rpz_owner_rrs (const struct bda_zone *z, const char *owner,
                  bd_rr_t *out, int *act)
{
  int n = 0;
  for (int i = 0; i < z->n; i++) {
    char o[256]; bda_owner (z, i, o, sizeof o);
    if (strcmp (o, owner)) continue;
    if (z->rr[i].type == BDA_SOA || z->rr[i].type == BDA_NS) continue; /* zone meta */
    if (z->rr[i].type == BDA_CNAME) {
      int a;
      if (bd_rpz_cname_action (z->rr[i].rdata, z->rr[i].rdata_len, &a)) { *act = a; return 0; }
    }
    if (n < BDA_RPZ_LOCAL_MAX) {
      out[n] = z->rr[i];
      /* rewrite owner to the queried name later in apply; keep type/rdata. */
      n++;
    }
  }
  return n;
}

/* Form the RPZ policy owner for a CLIENT-IP trigger from a peer, per the
   RPZ encoding: PREFIXLEN.reversed-address.rpz-client-ip. We only support an
   exact host match (/32 v4, /128 v6) in this first slice. Returns 0 on ok. */
static int
bd_rpz_client_ip_owner (const struct sockaddr_storage *peer,
                        char *out, size_t osz)
{
  if (!peer) return -1;
  if (peer->ss_family == AF_INET) {
    const struct sockaddr_in *s4 = (const struct sockaddr_in *) peer;
    unsigned char *b = (unsigned char *) &s4->sin_addr;
    snprintf (out, osz, "32.%u.%u.%u.%u.rpz-client-ip", b[3], b[2], b[1], b[0]);
    return 0;
  }
  if (peer->ss_family == AF_INET6) {
    const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *) peer;
    const unsigned char *b = s6->sin6_addr.s6_addr;
    char *p = out; size_t left = osz;
    int w = snprintf (p, left, "128"); if (w < 0 || (size_t) w >= left) return -1;
    p += w; left -= (size_t) w;
    /* reversed nibbles, group-grouped (zz:zz...) — simplest exact form is
       full 32-nibble reversed sequence separated by dots, mirroring v4. */
    for (int i = 15; i >= 0; i--) {
      w = snprintf (p, left, ".%x.%x", b[i] & 0x0f, (b[i] >> 4) & 0x0f);
      if (w < 0 || (size_t) w >= left) return -1;
      p += w; left -= (size_t) w;
    }
    w = snprintf (p, left, ".zz.rpz-client-ip");
    if (w < 0 || (size_t) w >= left) return -1;
    return 0;
  }
  return -1;
}

/* Longest-suffix match of qname against a policy zone's QNAME triggers.
   The policy owner is qname relative to the RPZ apex, e.g. for apex
   "rpz.local" a trigger blocking "bad.example" appears as owner
   "bad.example.rpz.local". We strip the apex and compare the remainder to
   qname (exact) or to a "*.suffix" wildcard. Returns the matched owner in
   `mowner` (RPZ-absolute) on success, else NULL-terminates it empty. */
static int
bd_rpz_qname_owner (const struct bda_zone *z, const char *qname,
                    char *mowner, size_t msz)
{
  mowner[0] = '\0';
  size_t apexlen = strlen (z->apex);
  int best = -1; size_t bestlen = 0;
  for (int i = 0; i < z->n; i++) {
    if (z->rr[i].type == BDA_SOA || z->rr[i].type == BDA_NS) continue;
    char o[256]; bda_owner (z, i, o, sizeof o);
    size_t ol = strlen (o);
    if (apexlen == 0) continue;
    if (ol < apexlen) continue;
    if (strcmp (o + ol - apexlen, z->apex)) continue;        /* must end in apex */
    /* relative trigger name (drop ".apex") */
    char rel[256];
    if (ol == apexlen) continue;                             /* apex itself: skip */
    size_t rl = ol - apexlen - 1;                            /* minus the '.' */
    if (rl >= sizeof rel) continue;
    memcpy (rel, o, rl); rel[rl] = '\0';
    int match = 0;
    if (!strcmp (rel, qname)) match = 1;                     /* exact QNAME */
    else if (rl > 2 && rel[0] == '*' && rel[1] == '.') {     /* *.suffix */
      const char *suf = rel + 2;
      size_t sl = strlen (suf), qn = strlen (qname);
      if (qn > sl && qname[qn - sl - 1] == '.' && !strcmp (qname + qn - sl, suf))
        match = 1;
    }
    if (match && (best < 0 || rl > bestlen)) {
      best = i; bestlen = rl;
      snprintf (mowner, msz, "%s", o);
    }
  }
  return best >= 0 ? 0 : -1;
}

/* Evaluate RPZ policy for (qname, peer). On a match, returns the action and
   (for localdata) fills local[]/*nlocal with the RRs to emit. CLIENT-IP
   triggers are evaluated before QNAME triggers (RPZ precedence). */
static int
bd_rpz_match (const struct bda_rpz *rpz, int nrpz, const char *qname,
              const struct sockaddr_storage *peer,
              bd_rr_t *local, int *nlocal)
{
  if (nlocal) *nlocal = 0;
  /* CLIENT-IP first. The policy owner is the encoded client-ip name relative
     to each RPZ apex, so the full owner is "<cipo>.<apex>". */
  if (peer) {
    char cipo[256];
    if (bd_rpz_client_ip_owner (peer, cipo, sizeof cipo) == 0) {
      bda_norm (cipo);
      for (int r = 0; r < nrpz; r++) {
        char full[320];
        if (rpz[r].z.apex[0])
          snprintf (full, sizeof full, "%s.%s", cipo, rpz[r].z.apex);
        else
          snprintf (full, sizeof full, "%s", cipo);
        bda_norm (full);
        int act = BD_RPZ_NONE;
        int n = bd_rpz_owner_rrs (&rpz[r].z, full, local, &act);
        if (act != BD_RPZ_NONE) return act;
        if (n > 0) { if (nlocal) *nlocal = n; return BD_RPZ_LOCALDATA; }
      }
    }
  }
  /* QNAME triggers (longest suffix wins, per policy zone in order). */
  for (int r = 0; r < nrpz; r++) {
    char mowner[256];
    if (bd_rpz_qname_owner (&rpz[r].z, qname, mowner, sizeof mowner) == 0) {
      int act = BD_RPZ_NONE;
      int n = bd_rpz_owner_rrs (&rpz[r].z, mowner, local, &act);
      if (act != BD_RPZ_NONE) return act;
      if (n > 0) { if (nlocal) *nlocal = n; return BD_RPZ_LOCALDATA; }
    }
  }
  return BD_RPZ_NONE;
}

/* Build the policy response for a resolved RPZ action. Returns the response
   length, or BD_RPZ_NO_RESPONSE if the caller should fall through to normal
   resolution (PASSTHRU / NONE), or -1 on a build error. The localdata RRs
   are emitted at the queried owner name. */
static int
bd_rpz_apply (int act, const bd_rr_t *local, int nlocal,
              const unsigned char *q, size_t qlen,
              unsigned char *resp, size_t rsz)
{
  if (act == BD_RPZ_NONE || act == BD_RPZ_PASSTHRU)
    return BD_RPZ_NO_RESPONSE;

  /* Header: echo the question section, set QR/RA. */
  size_t qoff = 12; char tmp[256];
  if (bd_decode_name (q, qlen, &qoff, tmp, sizeof tmp, 0) < 0) return -1;
  qoff += 4;
  if (qoff > rsz || qoff > qlen) return -1;
  memcpy (resp, q, qoff);
  resp[2] = 0x80;                                  /* QR=1, AA=0, RA=0 */
  resp[3] = (act == BD_RPZ_NXDOMAIN) ? 0x03 : 0x00; /* NXDOMAIN / NOERROR */
  resp[6] = resp[7] = resp[8] = resp[9] = resp[10] = resp[11] = 0;
  size_t off = qoff;
  uint16_t an = 0;

  if (act == BD_RPZ_LOCALDATA) {
    char owner[256];
    { size_t no = 12;
      if (bd_decode_name (q, qlen, &no, owner, sizeof owner, 0) < 0) return -1;
      bda_norm (owner); }
    for (int i = 0; i < nlocal; i++)
      if (bda_put_rr (resp, rsz, &off, owner, local[i].type, local[i].ttl,
                      local[i].rdata, local[i].rdata_len) == 0)
        an++;
  }
  resp[6] = (unsigned char) (an >> 8); resp[7] = (unsigned char) an;
  return (int) off;
}

/* ---- Tranche C: DNS64 synthesis (resolver side) ------------------- */

/* Synthesize AAAA RRs from an A reply by embedding each IPv4 into the
   configured /96 prefix. Returns the synthesized reply length, or -1.
   The A reply's question is echoed (with the original AAAA type restored by
   the caller through aaaa_q). RFC 6147: only IPv4 in globally-routable space
   is synthesized; private/special A space is skipped (best-effort guard). */
static int
bd_dns64_is_special_v4 (const unsigned char *ip)
{
  if (ip[0] == 10) return 1;                          /* 10/8       */
  if (ip[0] == 127) return 1;                         /* 127/8      */
  if (ip[0] == 169 && ip[1] == 254) return 1;         /* 169.254/16 */
  if (ip[0] == 192 && ip[1] == 168) return 1;         /* 192.168/16 */
  if (ip[0] == 172 && (ip[1] & 0xf0) == 16) return 1; /* 172.16/12  */
  if (ip[0] == 0) return 1;                           /* 0/8        */
  return 0;
}

/* Walk the A reply's answer section, embed each A into prefix, emit AAAA at
   the same owner into out[] keyed to the original AAAA question (aaaa_q). */
static int
bd_dns64_synthesize (const unsigned char prefix[12],
                     const unsigned char *a_reply, size_t a_len,
                     const unsigned char *aaaa_q, size_t aaaa_qlen,
                     unsigned char *out, size_t osz, size_t *out_len)
{
  if (out_len) *out_len = 0;
  if (a_len < 12) return -1;
  /* Build the response header/question from the original AAAA query. */
  size_t qoff = 12; char tmp[256];
  if (bd_decode_name (aaaa_q, aaaa_qlen, &qoff, tmp, sizeof tmp, 0) < 0) return -1;
  qoff += 4;
  if (qoff > osz || qoff > aaaa_qlen) return -1;
  memcpy (out, aaaa_q, qoff);
  out[2] = 0x81; out[3] = 0x80;                      /* QR=1 RD=1 RA=1 NOERROR */
  out[6] = out[7] = out[8] = out[9] = out[10] = out[11] = 0;
  size_t off = qoff;
  uint16_t an = 0;

  /* Decode the AAAA owner once (the question owner) for the synthesized RRs. */
  char aaaa_owner[256];
  { size_t no = 12;
    if (bd_decode_name (aaaa_q, aaaa_qlen, &no, aaaa_owner, sizeof aaaa_owner, 0) < 0) return -1;
    bda_norm (aaaa_owner); }

  /* Walk the A reply answer section. */
  uint16_t qd = bd_rd16 (a_reply + 4), acount = bd_rd16 (a_reply + 6);
  size_t ro = 12;
  for (int i = 0; i < qd; i++) { if (bd_skip_name (a_reply, a_len, &ro) < 0) return -1; ro += 4; }
  for (int i = 0; i < acount; i++) {
    if (bd_skip_name (a_reply, a_len, &ro) < 0) break;
    if (ro + 10 > a_len) break;
    uint16_t typ = bd_rd16 (a_reply + ro); ro += 2;
    ro += 2;                                          /* class */
    uint32_t ttl = bd_rd32 (a_reply + ro); ro += 4;
    uint16_t rdl = bd_rd16 (a_reply + ro); ro += 2;
    if (ro + rdl > a_len) break;
    if (typ == BDA_A && rdl == 4) {
      const unsigned char *ip = a_reply + ro;
      if (!bd_dns64_is_special_v4 (ip)) {
        unsigned char v6[16];
        memcpy (v6, prefix, 12);
        memcpy (v6 + 12, ip, 4);
        if (bda_put_rr (out, osz, &off, aaaa_owner, BDA_AAAA, ttl, v6, 16) == 0)
          an++;
      }
    }
    ro += rdl;
  }
  out[6] = (unsigned char) (an >> 8); out[7] = (unsigned char) an;
  if (out_len) *out_len = off;
  return an > 0 ? (int) off : -1;                    /* -1: nothing to synthesize */
}

/* ---- Engine globals (set by serve commands; default-off) ---------- */
/* Auth-side engines are reached from bda_answer_wire (DoH/DoT/DoQ) which has
   no per-call config handle, so the active auth-serve publishes them here.
   A single auth-serve process runs at a time per these globals. */
static struct bda_view *g_auth_views = NULL;  static int g_auth_nviews = 0;
static struct bda_rpz  *g_auth_rpz   = NULL;  static int g_auth_nrpz   = 0;

/* Resolver-side RPZ hook (forward-declared near struct bdr_ctx). */
static int
bdr_rpz_hook (struct bdr_ctx *c, const unsigned char *qbuf, size_t qn,
              const char *qname, const struct sockaddr_storage *client,
              unsigned char *resp, size_t rsz)
{
  const struct bda_rpz *rpz = (const struct bda_rpz *) c->rpz;
  int act; bd_rr_t lrr[BDA_RPZ_LOCAL_MAX]; int nlrr = 0;
  act = bd_rpz_match (rpz, c->nrpz, qname, client, lrr, &nlrr);
  return bd_rpz_apply (act, lrr, nlrr, qbuf, qn, resp, rsz);
}

/* Resolver-side DNS64 hook (forward-declared near struct bdr_ctx). Re-issues
   the query as A through the same forward/recurse path and synthesizes AAAA. */
static int
bdr_dns64_hook (struct bdr_ctx *c, const unsigned char *qbuf, size_t qn,
                const char *qname, uint16_t qtype, unsigned char *resp, size_t rsz)
{
  (void) qtype;
  /* Build an A query reusing the original transaction ID. */
  unsigned char aq[BDR_MSG_MAX];
  uint16_t id = bd_rd16 (qbuf);
  int aqlen = bd_build_query (id, qname, BDA_A, 0, aq, sizeof aq);
  if (aqlen < 0) return -1;
  unsigned char areply[BDR_MSG_MAX]; int al = -1;
  if (c->upstream && c->upstream[0])
    al = bdr_forward (aq, (size_t) aqlen, c->upstream, c->timeout_ms, areply, sizeof areply);
  if (al <= 0 && c->recurse && c->nroots > 0)
    al = bdr_recurse (qname, BDA_A, c->roots, c->nroots, c->timeout_ms, areply, sizeof areply);
  if (al <= 12) return -1;
  if ((areply[3] & 0x0f) != 0 || bd_rd16 (areply + 6) == 0) return -1;  /* no A data */
  size_t out_len = 0;
  int srl = bd_dns64_synthesize (c->dns64_prefix, areply, (size_t) al,
                                 qbuf, qn, resp, rsz, &out_len);
  return srl;
}

static int
bdr_resolver_load_rpz (char paths[][512], int n, void **out, int *nout)
{
  *out = NULL; *nout = 0;
  if (n <= 0) return 0;
  if (n > BDA_RPZ_MAX) n = BDA_RPZ_MAX;
  struct bda_rpz *arr = calloc ((size_t) n, sizeof (struct bda_rpz));
  if (!arr) return -1;
  int loaded = 0;
  for (int i = 0; i < n; i++) {
    if (bda_load_zone_signed (&arr[loaded].z, paths[i], NULL, NULL, 0) == 0) loaded++;
    else builtin_warning ("resolver-serve: skipping unparseable --rpz: %s", paths[i]);
  }
  *out = arr; *nout = loaded;
  return 0;
}

static void
bdr_resolver_free_rpz (void *rpz, int n)
{
  if (!rpz) return;
  struct bda_rpz *arr = (struct bda_rpz *) rpz;
  for (int i = 0; i < n; i++) free (arr[i].z.rr);
  free (arr);
}

struct bd_update_msg {
  char zone[256];
  uint16_t ztype, zclass;
  bd_rr_t pre[32]; int npre;
  bd_rr_t upd[64]; int nupd;
};

static int
bd_update_parse_rr (const unsigned char *msg, size_t msg_len, size_t *off,
                    bd_rr_t *rr)
{
  char name[256];
  if (bd_decode_name (msg, msg_len, off, name, sizeof name, 0) < 0) return -1;
  if (*off + 10 > msg_len) return -1;
  uint16_t typ = bd_rd16 (msg + *off); *off += 2;
  uint16_t cls = bd_rd16 (msg + *off); *off += 2;
  uint32_t ttl = bd_rd32 (msg + *off); *off += 4;
  uint16_t rdlen = bd_rd16 (msg + *off); *off += 2;
  if (*off + rdlen > msg_len || rdlen > sizeof rr->rdata) return -1;
  memset (rr, 0, sizeof *rr);
  if (bd_canon_owner (name, rr->owner, sizeof rr->owner) < 0) return -1;
  rr->type = typ; rr->cls = cls; rr->ttl = ttl;
  rr->rdata_off = *off; rr->rdlen = rdlen;
  memcpy (rr->rdata, msg + *off, rdlen);
  rr->rdata_len = rdlen;
  *off += rdlen;
  return 0;
}

static int
bd_update_parse (const unsigned char *msg, size_t msg_len,
                 struct bd_update_msg *u)
{
  if (msg_len < 12) return -1;
  memset (u, 0, sizeof *u);
  if (((msg[2] >> 3) & 0x0f) != 5) return -1;
  uint16_t qd = bd_rd16 (msg + 4), an = bd_rd16 (msg + 6);
  uint16_t ns = bd_rd16 (msg + 8), ar = bd_rd16 (msg + 10);
  if (qd != 1 || an > 32 || ns > 64) return -1;
  size_t off = 12;
  if (bd_decode_name (msg, msg_len, &off, u->zone, sizeof u->zone, 0) < 0)
    return -1;
  if (off + 4 > msg_len) return -1;
  u->ztype = bd_rd16 (msg + off); off += 2;
  u->zclass = bd_rd16 (msg + off); off += 2;
  bda_norm (u->zone);
  for (int i = 0; i < an; i++)
    if (bd_update_parse_rr (msg, msg_len, &off, &u->pre[u->npre++]) < 0)
      return -1;
  for (int i = 0; i < ns; i++)
    if (bd_update_parse_rr (msg, msg_len, &off, &u->upd[u->nupd++]) < 0)
      return -1;
  for (int i = 0; i < ar; i++) {
    bd_rr_t junk;
    if (bd_update_parse_rr (msg, msg_len, &off, &junk) < 0) return -1;
  }
  return off == msg_len ? 0 : -1;
}

static int
bd_update_name_exists (struct bda_zone *z, const char *owner)
{
  for (int i = 0; i < z->n; i++) {
    char o[256]; bda_owner (z, i, o, sizeof o);
    if (!strcmp (o, owner)) return 1;
  }
  return 0;
}

static int
bd_update_rrset_exists (struct bda_zone *z, const char *owner, uint16_t type)
{
  for (int i = 0; i < z->n; i++) {
    char o[256]; bda_owner (z, i, o, sizeof o);
    if (!strcmp (o, owner) && z->rr[i].type == type) return 1;
  }
  return 0;
}

static int
bd_update_rr_matches (bd_rr_t *a, bd_rr_t *b)
{
  return !strcmp (a->owner, b->owner) && a->type == b->type &&
         a->rdata_len == b->rdata_len &&
         memcmp (a->rdata, b->rdata, a->rdata_len) == 0;
}

static int
bd_update_exact_exists (struct bda_zone *z, bd_rr_t *rr)
{
  for (int i = 0; i < z->n; i++)
    if (bd_update_rr_matches (&z->rr[i], rr))
      return 1;
  return 0;
}

static int
bd_update_check_prereq (struct bda_zone *z, struct bd_update_msg *u)
{
  for (int i = 0; i < u->npre; i++) {
    bd_rr_t *r = &u->pre[i];
    if (!bda_in_zone (r->owner, z->apex)) return BD_RCODE_NOTAUTH;
    if (r->ttl != 0) return BD_RCODE_FORMERR;
    if (r->type == BD_T_ANY && r->cls == BD_C_ANY && r->rdata_len == 0) {
      if (!bd_update_name_exists (z, r->owner)) return BD_RCODE_NXDOMAIN;
    } else if (r->type == BD_T_ANY && r->cls == BD_C_NONE && r->rdata_len == 0) {
      if (bd_update_name_exists (z, r->owner)) return BD_RCODE_YXDOMAIN;
    } else if (r->type != BD_T_ANY && r->cls == BD_C_ANY && r->rdata_len == 0) {
      if (!bd_update_rrset_exists (z, r->owner, r->type)) return BD_RCODE_NXRRSET;
    } else if (r->type != BD_T_ANY && r->cls == BD_C_NONE && r->rdata_len == 0) {
      if (bd_update_rrset_exists (z, r->owner, r->type)) return BD_RCODE_YXRRSET;
    } else if (r->type != BD_T_ANY && r->cls == BD_C_IN) {
      if (!bd_update_exact_exists (z, r)) return BD_RCODE_NXRRSET;
    } else {
      return BD_RCODE_FORMERR;
    }
  }
  return BD_RCODE_NOERROR;
}

static int
bda_bump_soa_serial (struct bda_zone *z)
{
  for (int i = 0; i < z->n; i++) {
    char o[256]; bda_owner (z, i, o, sizeof o);
    if (z->rr[i].type != BDA_SOA || strcmp (o, z->apex)) continue;
    unsigned char *rd = z->rr[i].rdata;
    size_t rl = z->rr[i].rdata_len, p = 0;
    for (int names = 0; names < 2 && p < rl; names++)
      { while (p < rl && rd[p] != 0) p += rd[p] + 1; if (p < rl) p++; }
    if (p + 4 > rl) return -1;
    uint32_t s = bd_rd32 (rd + p) + 1;
    rd[p] = (unsigned char) (s >> 24);
    rd[p + 1] = (unsigned char) (s >> 16);
    rd[p + 2] = (unsigned char) (s >> 8);
    rd[p + 3] = (unsigned char) s;
    return 0;
  }
  return -1;
}

static void
bd_update_delete_index (struct bda_zone *z, int idx)
{
  if (idx < 0 || idx >= z->n) return;
  if (idx + 1 < z->n)
    memmove (&z->rr[idx], &z->rr[idx + 1], (size_t) (z->n - idx - 1) * sizeof z->rr[0]);
  z->n--;
}

static int
bd_update_apply_one (struct bda_zone *z, bd_rr_t *r)
{
  if (!bda_in_zone (r->owner, z->apex)) return BD_RCODE_NOTAUTH;
  if (r->ttl == 0 && r->cls == BD_C_ANY && r->type == BD_T_ANY && r->rdata_len == 0) {
    for (int i = z->n - 1; i >= 0; i--) {
      char o[256]; bda_owner (z, i, o, sizeof o);
      if (!strcmp (o, r->owner) && z->rr[i].type != BDA_SOA && z->rr[i].type != BDA_NS)
        bd_update_delete_index (z, i);
    }
    return BD_RCODE_NOERROR;
  }
  if (r->ttl == 0 && r->cls == BD_C_ANY && r->type != BD_T_ANY && r->rdata_len == 0) {
    for (int i = z->n - 1; i >= 0; i--) {
      char o[256]; bda_owner (z, i, o, sizeof o);
      if (!strcmp (o, r->owner) && z->rr[i].type == r->type)
        bd_update_delete_index (z, i);
    }
    return BD_RCODE_NOERROR;
  }
  if (r->ttl == 0 && r->cls == BD_C_NONE && r->type != BD_T_ANY) {
    for (int i = z->n - 1; i >= 0; i--)
      if (bd_update_rr_matches (&z->rr[i], r))
        bd_update_delete_index (z, i);
    return BD_RCODE_NOERROR;
  }
  if (r->cls == BD_C_IN && r->type != BD_T_ANY) {
    if (z->n >= BDA_RR_MAX) return BD_RCODE_REFUSED;
    if (bd_update_exact_exists (z, r)) return BD_RCODE_NOERROR;
    bd_rr_t *grown = realloc (z->rr, (size_t) (z->n + 1) * sizeof (bd_rr_t));
    if (!grown) return BD_RCODE_REFUSED;
    z->rr = grown;
    z->rr[z->n] = *r;
    z->rr[z->n].cls = BD_C_IN;
    z->n++;
    return BD_RCODE_NOERROR;
  }
  return BD_RCODE_FORMERR;
}

static int
bd_update_apply (struct bda_zone *z, struct bd_update_msg *u)
{
  for (int i = 0; i < u->nupd; i++) {
    int rc = bd_update_apply_one (z, &u->upd[i]);
    if (rc != BD_RCODE_NOERROR) return rc;
  }
  if (bda_bump_soa_serial (z) < 0) return BD_RCODE_REFUSED;
  return BD_RCODE_NOERROR;
}

static int
bd_update_response (const unsigned char *req, size_t req_len,
                    unsigned char *resp, size_t rsz, int rcode)
{
  if (req_len < 12 || rsz < 12) return -1;
  memcpy (resp, req, 12);
  resp[2] = (unsigned char) ((req[2] & 0x78) | 0x80);  /* QR + opcode */
  resp[3] = (unsigned char) (rcode & 0x0f);
  resp[4] = resp[5] = resp[6] = resp[7] = resp[8] = resp[9] = resp[10] = resp[11] = 0;
  return 12;
}

static int
bd_update_handle (struct bda_zone *zones, int nz, const unsigned char *req,
                  size_t req_len, unsigned char *resp, size_t rsz)
{
  struct bd_update_msg u;
  int rcode = BD_RCODE_NOERROR;
  if (bd_update_parse (req, req_len, &u) < 0)
    rcode = BD_RCODE_FORMERR;
  else if (u.ztype != BDA_SOA || u.zclass != BD_C_IN)
    rcode = BD_RCODE_FORMERR;
  else {
    int zi = bda_route (zones, nz, u.zone);
    if (zi < 0 || strcmp (zones[zi].apex, u.zone))
      rcode = BD_RCODE_NOTAUTH;
    else {
      rcode = bd_update_check_prereq (&zones[zi], &u);
      if (rcode == BD_RCODE_NOERROR && u.nupd > 0) {
        struct bda_zone oldz;
        memset (&oldz, 0, sizeof oldz);
        oldz.rr = calloc ((size_t) (zones[zi].n > 0 ? zones[zi].n : 1), sizeof (bd_rr_t));
        if (!oldz.rr)
          rcode = BD_RCODE_REFUSED;
        else {
          memcpy (oldz.rr, zones[zi].rr, (size_t) zones[zi].n * sizeof (bd_rr_t));
          oldz.n = zones[zi].n;
          snprintf (oldz.apex, sizeof oldz.apex, "%s", zones[zi].apex);
          for (int j = 0; j < zones[zi].njrnl; j++) oldz.jrnl[j] = zones[zi].jrnl[j];
          oldz.njrnl = zones[zi].njrnl;
          rcode = bd_update_apply (&zones[zi], &u);
          if (rcode == BD_RCODE_NOERROR)
            bda_journal_record (&oldz, &zones[zi]);
          else {
            memcpy (zones[zi].rr, oldz.rr, (size_t) oldz.n * sizeof (bd_rr_t));
            zones[zi].n = oldz.n;
          }
          free (oldz.rr);
        }
      }
    }
  }
  return bd_update_response (req, req_len, resp, rsz, rcode);
}

static int
bd_update_put_rr_wire (unsigned char *out, size_t osz, size_t *off,
                       const char *owner, uint16_t type, uint16_t cls,
                       uint32_t ttl, const unsigned char *rdata, uint16_t rdlen)
{
  unsigned char nm[256];
  int nl = bd_name_to_wire (owner, nm, sizeof nm);
  if (nl < 0 || *off + (size_t) nl + 10 + rdlen > osz) return -1;
  memcpy (out + *off, nm, (size_t) nl); *off += (size_t) nl;
  out[(*off)++] = (unsigned char) (type >> 8); out[(*off)++] = (unsigned char) type;
  out[(*off)++] = (unsigned char) (cls >> 8);  out[(*off)++] = (unsigned char) cls;
  out[(*off)++] = (unsigned char) (ttl >> 24); out[(*off)++] = (unsigned char) (ttl >> 16);
  out[(*off)++] = (unsigned char) (ttl >> 8);  out[(*off)++] = (unsigned char) ttl;
  out[(*off)++] = (unsigned char) (rdlen >> 8); out[(*off)++] = (unsigned char) rdlen;
  if (rdlen) memcpy (out + *off, rdata, rdlen);
  *off += rdlen;
  return 0;
}

static int
bd_update_init_msg (unsigned char *out, size_t osz, size_t *off,
                    const char *zone, uint16_t id)
{
  if (osz < 12) return -1;
  memset (out, 0, 12);
  out[0] = (unsigned char) (id >> 8); out[1] = (unsigned char) id;
  out[2] = 0x28; out[3] = 0x00;             /* opcode UPDATE */
  out[4] = 0; out[5] = 1;                   /* Zone section */
  *off = 12;
  unsigned char zn[256];
  int zl = bd_name_to_wire (zone, zn, sizeof zn);
  if (zl < 0 || *off + (size_t) zl + 4 > osz) return -1;
  memcpy (out + *off, zn, (size_t) zl); *off += (size_t) zl;
  out[(*off)++] = 0; out[(*off)++] = BDA_SOA;
  out[(*off)++] = 0; out[(*off)++] = BD_C_IN;
  return 0;
}

static void
bd_update_set_counts (unsigned char *out, uint16_t pre, uint16_t upd)
{
  out[6] = (unsigned char) (pre >> 8); out[7] = (unsigned char) pre;
  out[8] = (unsigned char) (upd >> 8); out[9] = (unsigned char) upd;
}

static int
bd_update_build_rdata_arg (uint16_t type, const char *zone, WORD_LIST *first,
                           int nrd, unsigned char *rdata, size_t rsz)
{
  char *rd[16];
  if (nrd < 0 || nrd > 16) return -1;
  WORD_LIST *p = first;
  for (int i = 0; i < nrd; i++) {
    if (!p) return -1;
    rd[i] = p->word->word;
    p = p->next;
  }
  return bz_build_rdata (type, zone, rd, nrd, rdata, rsz);
}

static int
bd_update_parse_server (const char *in, char *host, size_t hsz, int *port)
{
  int default_port = (port && *port > 0) ? *port : 53;
  return bd_split_host_port_default (in, host, hsz, port, default_port);
}

static int
bd_update_send_tcp (const char *server, int port, const unsigned char *msg,
                    size_t msg_len, int timeout_ms, unsigned char *reply,
                    size_t reply_sz, size_t *reply_len)
{
  struct sockaddr_storage da;
  socklen_t dl = 0;
  if (bd_make_sockaddr (server, port, &da, &dl) < 0)
    { builtin_error ("update: bad server addr: %s", server); return -1; }
  int s = socket (bd_sock_family (&da), SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (s < 0) return -1;
  struct timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  setsockopt (s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  setsockopt (s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
  if (connect (s, (struct sockaddr *) &da, dl) < 0)
    { close (s); return -1; }
  unsigned char lb[2] = { (unsigned char) (msg_len >> 8), (unsigned char) msg_len };
  if (bda_writen (s, lb, 2) < 0 || bda_writen (s, msg, msg_len) < 0)
    { close (s); return -1; }
  if (bda_readn (s, lb, 2) < 0)
    { close (s); return -1; }
  size_t rl = ((size_t) lb[0] << 8) | lb[1];
  if (rl > reply_sz || bda_readn (s, reply, rl) < 0)
    { close (s); return -1; }
  close (s);
  *reply_len = rl;
  return 0;
}

static const char *
bd_update_rcode_name (int rcode)
{
  switch (rcode) {
    case BD_RCODE_NOERROR: return "NOERROR";
    case BD_RCODE_FORMERR: return "FORMERR";
    case BD_RCODE_NXDOMAIN: return "NXDOMAIN";
    case BD_RCODE_NOTIMP: return "NOTIMP";
    case BD_RCODE_REFUSED: return "REFUSED";
    case BD_RCODE_YXDOMAIN: return "YXDOMAIN";
    case BD_RCODE_YXRRSET: return "YXRRSET";
    case BD_RCODE_NXRRSET: return "NXRRSET";
    case BD_RCODE_NOTAUTH: return "NOTAUTH";
    default: return "RCODE";
  }
}

static int
bd_update_cmd (WORD_LIST *args)
{
  const char *server = NULL, *zone = NULL;
  int port = bd_server_port (), timeout_ms = 2000;
  unsigned char msg[BDR_MSG_MAX], rdata[2048], reply[BDR_MSG_MAX];
  size_t off = 0, reply_len = 0;
  uint16_t pre = 0, upd = 0;
  bd_tsig_store_t tsig_store;
  memset (&tsig_store, 0, sizeof tsig_store);

  for (WORD_LIST *p = args; p; p = p->next) {
    const char *w = p->word->word;
    if (!strcmp (w, "--server") && p->next) { server = p->next->word->word; p = p->next; }
    else if (!strcmp (w, "--zone") && p->next) { zone = p->next->word->word; p = p->next; }
    else if (!strcmp (w, "--port") && p->next) { port = atoi (p->next->word->word); p = p->next; }
    else if (!strcmp (w, "--timeout") && p->next) { timeout_ms = atoi (p->next->word->word); p = p->next; }
    else if (!strcmp (w, "--tsig-key") && p->next)
      { if (bd_tsig_add_inline (&tsig_store, p->next->word->word) < 0) { builtin_error ("update: bad --tsig-key"); return EX_USAGE; } p = p->next; }
    else if (!strcmp (w, "--tsig-keys") && p->next)
      { if (bd_tsig_load_keys (&tsig_store, p->next->word->word) < 0) return EXECUTION_FAILURE; p = p->next; }
    else break;
  }
  if (!server || !zone) { builtin_error ("update: --server IP[:PORT] --zone NAME required"); return EX_USAGE; }
  char host[256];
  if (bd_update_parse_server (server, host, sizeof host, &port) < 0 || port <= 0)
    { builtin_error ("update: bad --server/--port"); return EX_USAGE; }
  if (bd_update_init_msg (msg, sizeof msg, &off, zone, (uint16_t) (getpid () & 0xffff)) < 0)
    return EXECUTION_FAILURE;

  for (WORD_LIST *p = args; p; p = p->next) {
    const char *w = p->word->word;
    if (!strcmp (w, "--server") || !strcmp (w, "--zone") || !strcmp (w, "--port")
        || !strcmp (w, "--timeout") || !strcmp (w, "--tsig-key") || !strcmp (w, "--tsig-keys"))
      { if (!p->next) { builtin_error ("update: %s requires a value", w); return EX_USAGE; }
        p = p->next; continue; }
    if (!strcmp (w, "--prereq") && p->next) {
      const char *kind = p->next->word->word; p = p->next;
      if (!strcmp (kind, "name-exists") && p->next) {
        p = p->next;
        if (bd_update_put_rr_wire (msg, sizeof msg, &off, p->word->word, BD_T_ANY, BD_C_ANY, 0, NULL, 0) < 0) return EXECUTION_FAILURE;
      } else if (!strcmp (kind, "name-not-exists") && p->next) {
        p = p->next;
        if (bd_update_put_rr_wire (msg, sizeof msg, &off, p->word->word, BD_T_ANY, BD_C_NONE, 0, NULL, 0) < 0) return EXECUTION_FAILURE;
      } else if ((!strcmp (kind, "rrset-exists") || !strcmp (kind, "rrset-not-exists")) && p->next && p->next->next) {
        const char *name = p->next->word->word; const char *typ_s = p->next->next->word->word; p = p->next->next;
        uint16_t typ; if (bd_type_from_name (typ_s, &typ) < 0) return EX_USAGE;
        uint16_t cls = !strcmp (kind, "rrset-exists") ? BD_C_ANY : BD_C_NONE;
        if (bd_update_put_rr_wire (msg, sizeof msg, &off, name, typ, cls, 0, NULL, 0) < 0) return EXECUTION_FAILURE;
      } else { builtin_error ("update: bad --prereq"); return EX_USAGE; }
      pre++;
    } else if (!strcmp (w, "--add") && p->next && p->next->next && p->next->next->next) {
      const char *name = p->next->word->word;
      uint32_t ttl = (uint32_t) strtoul (p->next->next->word->word, NULL, 10);
      const char *typ_s = p->next->next->next->word->word;
      p = p->next->next->next;
      uint16_t typ; if (bd_type_from_name (typ_s, &typ) < 0) return EX_USAGE;
      int nrd = (typ == BD_T_MX || typ == BD_T_SOA) ? (typ == BD_T_MX ? 2 : 7) : 1;
      int rdlen = bd_update_build_rdata_arg (typ, zone, p->next, nrd, rdata, sizeof rdata);
      if (rdlen < 0) { builtin_error ("update: bad %s RDATA", typ_s); return EX_USAGE; }
      for (int i = 0; i < nrd; i++) p = p->next;
      if (bd_update_put_rr_wire (msg, sizeof msg, &off, name, typ, BD_C_IN, ttl, rdata, (uint16_t) rdlen) < 0) return EXECUTION_FAILURE;
      upd++;
    } else if (!strcmp (w, "--delete") && p->next) {
      const char *name = p->next->word->word; p = p->next;
      uint16_t typ = BD_T_ANY, cls = BD_C_ANY, rdlen = 0;
      if (p->next && p->next->word->word[0] != '-') {
        p = p->next;
        if (bd_type_from_name (p->word->word, &typ) < 0) return EX_USAGE;
        if (p->next && p->next->word->word[0] != '-') {
          int nrd = (typ == BD_T_MX || typ == BD_T_SOA) ? (typ == BD_T_MX ? 2 : 7) : 1;
          int rl = bd_update_build_rdata_arg (typ, zone, p->next, nrd, rdata, sizeof rdata);
          if (rl < 0) { builtin_error ("update: bad delete RDATA"); return EX_USAGE; }
          for (int i = 0; i < nrd; i++) p = p->next;
          cls = BD_C_NONE; rdlen = (uint16_t) rl;
        }
      }
      if (bd_update_put_rr_wire (msg, sizeof msg, &off, name, typ, cls, 0, rdlen ? rdata : NULL, rdlen) < 0) return EXECUTION_FAILURE;
      upd++;
    } else {
      builtin_error ("update: unexpected arg: %s", w);
      return EX_USAGE;
    }
  }
  if (upd == 0) { builtin_error ("update: at least one --add/--delete is required"); return EX_USAGE; }
  bd_update_set_counts (msg, pre, upd);
  if (tsig_store.n > 0)
    {
      unsigned char mac[BD_TSIG_MAC_MAX];
      size_t mac_len = 0;
      if (bd_tsig_sign (msg, sizeof msg, &off, &tsig_store.keys[0],
                        NULL, 0, (uint64_t) bd_tsig_now (),
                        BD_TSIG_DEFAULT_FUDGE, mac, &mac_len) < 0)
        {
          builtin_error ("update: TSIG signing failed");
          return EXECUTION_FAILURE;
        }
    }
  if (bd_update_send_tcp (host, port, msg, off, timeout_ms, reply, sizeof reply, &reply_len) < 0)
    { builtin_error ("update: send failed"); return EXECUTION_FAILURE; }
  int rcode = reply_len >= 4 ? (reply[3] & 0x0f) : BD_RCODE_FORMERR;
  printf ("rcode=%s\n", bd_update_rcode_name (rcode));
  return rcode == BD_RCODE_NOERROR ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bd_update_fixture_rr (bd_rr_t *r, const char *owner, uint16_t type,
                      uint32_t ttl, const char *zone, char **rd, int nrd)
{
  unsigned char data[2048];
  int dl = bz_build_rdata (type, zone, rd, nrd, data, sizeof data);
  if (dl < 0) return -1;
  memset (r, 0, sizeof *r);
  if (bd_canon_owner (owner, r->owner, sizeof r->owner) < 0) return -1;
  r->type = type; r->cls = BD_C_IN; r->ttl = ttl;
  memcpy (r->rdata, data, (size_t) dl);
  r->rdata_len = (uint16_t) dl;
  return 0;
}

static int
bd_update_codec_cmd (WORD_LIST *args)
{
  (void) args;
  unsigned char msg[2048], rd[256];
  size_t off = 0;
  if (bd_update_init_msg (msg, sizeof msg, &off, "example.test.", 0x2136) < 0)
    return EXECUTION_FAILURE;
  bd_update_put_rr_wire (msg, sizeof msg, &off, "www.example.test.", BD_T_A, BD_C_ANY, 0, NULL, 0);
  bd_update_put_rr_wire (msg, sizeof msg, &off, "absent.example.test.", BD_T_ANY, BD_C_NONE, 0, NULL, 0);
  struct in_addr a; inet_pton (AF_INET, "192.0.2.55", &a); memcpy (rd, &a.s_addr, 4);
  bd_update_put_rr_wire (msg, sizeof msg, &off, "new.example.test.", BD_T_A, BD_C_IN, 300, rd, 4);
  bd_update_put_rr_wire (msg, sizeof msg, &off, "old.example.test.", BD_T_A, BD_C_ANY, 0, NULL, 0);
  bd_update_put_rr_wire (msg, sizeof msg, &off, "dead.example.test.", BD_T_ANY, BD_C_ANY, 0, NULL, 0);
  inet_pton (AF_INET, "192.0.2.9", &a); memcpy (rd, &a.s_addr, 4);
  bd_update_put_rr_wire (msg, sizeof msg, &off, "exact.example.test.", BD_T_A, BD_C_NONE, 0, rd, 4);
  bd_update_set_counts (msg, 2, 4);

  struct bd_update_msg u;
  if (bd_update_parse (msg, off, &u) < 0) return EXECUTION_FAILURE;
  printf ("zone=%s ztype=%u zclass=%u prereq=%d update=%d\n", u.zone, u.ztype, u.zclass, u.npre, u.nupd);
  for (int i = 0; i < u.npre; i++)
    printf ("pre%d owner=%s type=%u class=%u ttl=%u rdlen=%u\n", i + 1, u.pre[i].owner, u.pre[i].type, u.pre[i].cls, u.pre[i].ttl, u.pre[i].rdata_len);
  for (int i = 0; i < u.nupd; i++)
    printf ("upd%d owner=%s type=%u class=%u ttl=%u rdlen=%u\n", i + 1, u.upd[i].owner, u.upd[i].type, u.upd[i].cls, u.upd[i].ttl, u.upd[i].rdata_len);
  return EXECUTION_SUCCESS;
}

static int
bd_update_apply_fixture_cmd (WORD_LIST *args)
{
  (void) args;
  struct bda_zone z; memset (&z, 0, sizeof z);
  z.rr = calloc (16, sizeof (bd_rr_t));
  if (!z.rr) return EXECUTION_FAILURE;
  snprintf (z.apex, sizeof z.apex, "example.test");
  char *soa_rd[] = { "ns.example.test.", "hostmaster.example.test.", "100", "3600", "600", "86400", "60" };
  char *ns_rd[] = { "ns.example.test." };
  char *a1_rd[] = { "192.0.2.10" };
  char *old_rd[] = { "192.0.2.20" };
  if (bd_update_fixture_rr (&z.rr[z.n++], "example.test.", BD_T_SOA, 3600, z.apex, soa_rd, 7) < 0 ||
      bd_update_fixture_rr (&z.rr[z.n++], "example.test.", BD_T_NS, 3600, z.apex, ns_rd, 1) < 0 ||
      bd_update_fixture_rr (&z.rr[z.n++], "www.example.test.", BD_T_A, 300, z.apex, a1_rd, 1) < 0 ||
      bd_update_fixture_rr (&z.rr[z.n++], "old.example.test.", BD_T_A, 300, z.apex, old_rd, 1) < 0)
    { free (z.rr); return EXECUTION_FAILURE; }

  unsigned char msg[2048], rd[256]; size_t off = 0;
  bd_update_init_msg (msg, sizeof msg, &off, "example.test.", 0x2136);
  bd_update_put_rr_wire (msg, sizeof msg, &off, "www.example.test.", BD_T_A, BD_C_ANY, 0, NULL, 0);
  struct in_addr a; inet_pton (AF_INET, "192.0.2.55", &a); memcpy (rd, &a.s_addr, 4);
  bd_update_put_rr_wire (msg, sizeof msg, &off, "new.example.test.", BD_T_A, BD_C_IN, 300, rd, 4);
  bd_update_put_rr_wire (msg, sizeof msg, &off, "old.example.test.", BD_T_A, BD_C_ANY, 0, NULL, 0);
  bd_update_set_counts (msg, 1, 2);
  struct bd_update_msg u;
  if (bd_update_parse (msg, off, &u) < 0) { free (z.rr); return EXECUTION_FAILURE; }
  int pre_rc = bd_update_check_prereq (&z, &u);
  long before = bda_apex_serial (&z);
  int app_rc = bd_update_apply (&z, &u);
  long after = bda_apex_serial (&z);
  printf ("prereq=%s apply=%s serial_before=%ld serial_after=%ld records=%d\n",
          bd_update_rcode_name (pre_rc), bd_update_rcode_name (app_rc), before, after, z.n);
  printf ("www_exists=%d old_exists=%d new_exists=%d\n",
          bd_update_rrset_exists (&z, "www.example.test", BD_T_A),
          bd_update_rrset_exists (&z, "old.example.test", BD_T_A),
          bd_update_rrset_exists (&z, "new.example.test", BD_T_A));
  free (z.rr);
  return (pre_rc == BD_RCODE_NOERROR && app_rc == BD_RCODE_NOERROR) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bd_update_handle_fixture_cmd (WORD_LIST *args)
{
  (void) args;
  struct bda_zone z; memset (&z, 0, sizeof z);
  z.rr = calloc (16, sizeof (bd_rr_t));
  if (!z.rr) return EXECUTION_FAILURE;
  snprintf (z.apex, sizeof z.apex, "example.test");
  char *soa_rd[] = { "ns.example.test.", "hostmaster.example.test.", "100", "3600", "600", "86400", "60" };
  char *ns_rd[] = { "ns.example.test." };
  char *a1_rd[] = { "192.0.2.10" };
  char *old_rd[] = { "192.0.2.20" };
  if (bd_update_fixture_rr (&z.rr[z.n++], "example.test.", BD_T_SOA, 3600, z.apex, soa_rd, 7) < 0 ||
      bd_update_fixture_rr (&z.rr[z.n++], "example.test.", BD_T_NS, 3600, z.apex, ns_rd, 1) < 0 ||
      bd_update_fixture_rr (&z.rr[z.n++], "www.example.test.", BD_T_A, 300, z.apex, a1_rd, 1) < 0 ||
      bd_update_fixture_rr (&z.rr[z.n++], "old.example.test.", BD_T_A, 300, z.apex, old_rd, 1) < 0)
    { free (z.rr); return EXECUTION_FAILURE; }
  struct bda_zone zones[1]; zones[0] = z;

  unsigned char msg[2048], rd[256], resp[2048]; size_t off = 0;
  bd_update_init_msg (msg, sizeof msg, &off, "example.test.", 0x2136);
  bd_update_put_rr_wire (msg, sizeof msg, &off, "www.example.test.", BD_T_A, BD_C_ANY, 0, NULL, 0);
  struct in_addr a; inet_pton (AF_INET, "192.0.2.55", &a); memcpy (rd, &a.s_addr, 4);
  bd_update_put_rr_wire (msg, sizeof msg, &off, "new.example.test.", BD_T_A, BD_C_IN, 300, rd, 4);
  bd_update_put_rr_wire (msg, sizeof msg, &off, "old.example.test.", BD_T_A, BD_C_ANY, 0, NULL, 0);
  bd_update_set_counts (msg, 1, 2);
  int rl = bd_update_handle (zones, 1, msg, off, resp, sizeof resp);
  printf ("response_len=%d rcode=%s serial=%ld records=%d journal=%d\n",
          rl, bd_update_rcode_name (rl >= 4 ? (resp[3] & 0x0f) : BD_RCODE_FORMERR),
          bda_apex_serial (&zones[0]), zones[0].n, zones[0].njrnl);
  bda_journal_free_all (&zones[0]);
  free (zones[0].rr);
  return (rl > 0 && (resp[3] & 0x0f) == BD_RCODE_NOERROR) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bda_answer_wire (struct bda_zone *zones, int nz, const unsigned char *q,
                 size_t qlen, unsigned char *resp, size_t rsz,
                 const struct sockaddr_storage *peer)
{
  /* peer is the client sockaddr when known (plain UDP/TCP and any transport
     that threads it through); it is NULL for the TLS-wrapped transports
     (DoH/DoT/DoQ) in this slice — see bda_conn, which carries no sockaddr.
     When peer is NULL, split-horizon view selection and RPZ CLIENT-IP
     triggers simply do not match, so encrypted transports keep their current
     global-zone behavior. */
  char qname[256]; uint16_t qt, qc;
  if (bdr_parse_question (q, qlen, qname, sizeof qname, &qt, &qc) < 0)
    return -1;
  bda_norm (qname);

  /* RPZ (auth side): consult policy zones before normal answer. */
  if (g_auth_nrpz > 0) {
    int act; bd_rr_t lrr[BDA_RPZ_LOCAL_MAX]; int nlrr = 0;
    act = bd_rpz_match (g_auth_rpz, g_auth_nrpz, qname, peer, lrr, &nlrr);
    int rl = bd_rpz_apply (act, lrr, nlrr, q, qlen, resp, rsz);
    if (rl != BD_RPZ_NO_RESPONSE) return rl;     /* short-circuit (incl. error) */
    /* PASSTHRU / none fall through to normal resolution. */
  }

  /* Split-horizon: select a view by peer; route within its zones. */
  if (peer && g_auth_nviews > 0) {
    int vi = bda_view_select (g_auth_views, g_auth_nviews, peer);
    if (vi >= 0) {
      int zi = bda_route (g_auth_views[vi].zones, g_auth_views[vi].nz, qname);
      return (zi >= 0)
        ? bda_answer (&g_auth_views[vi].zones[zi], q, qlen, resp, rsz)
        : bda_refused (q, qlen, resp, rsz);
    }
  }

  int zi = bda_route (zones, nz, qname);
  return (zi >= 0) ? bda_answer (&zones[zi], q, qlen, resp, rsz)
                   : bda_refused (q, qlen, resp, rsz);
}

static int
bda_http_error (struct bda_conn *c, int status)
{
  const char *reason = "Error";
  switch (status) {
    case 400: reason = "Bad Request"; break;
    case 404: reason = "Not Found"; break;
    case 405: reason = "Method Not Allowed"; break;
    case 413: reason = "Payload Too Large"; break;
    case 415: reason = "Unsupported Media Type"; break;
    case 500: reason = "Internal Server Error"; break;
  }
  char body[96];
  int bl = snprintf (body, sizeof body, "%d %s\n", status, reason);
  char hdr[256];
  int hl = snprintf (hdr, sizeof hdr,
                     "HTTP/1.1 %d %s\r\n"
                     "Content-Type: text/plain\r\n"
                     "Content-Length: %d\r\n"
                     "Connection: close\r\n\r\n",
                     status, reason, bl);
  if (hl < 0 || bl < 0 || (size_t) hl >= sizeof hdr || (size_t) bl >= sizeof body)
    return -1;
  return bda_conn_writen (c, (const unsigned char *) hdr, (size_t) hl) == 0 &&
	         bda_conn_writen (c, (const unsigned char *) body, (size_t) bl) == 0 ? 0 : -1;
}

struct bda_h2_req {
  char method[12];
  char path[1200];
  char ctype[160];
  unsigned char body[BD_DOH_WIRE_MAX];
  size_t body_len;
  uint32_t stream_id;
  int saw_headers;
  int end_stream;
};

static const char *
bda_h2_static_name (uint32_t idx)
{
  switch (idx) {
    case 1: return ":authority";
    case 2: case 3: return ":method";
    case 4: case 5: return ":path";
    case 6: case 7: return ":scheme";
    case 8: case 9: case 10: case 11: case 12: case 13: case 14: return ":status";
    case 25: return "content-length";
    case 28: return "content-type";
    default: return NULL;
  }
}

static int
bda_h2_apply_indexed (struct bda_h2_req *r, uint32_t idx)
{
  switch (idx) {
    case 2: snprintf (r->method, sizeof r->method, "GET"); return 0;
    case 3: snprintf (r->method, sizeof r->method, "POST"); return 0;
    case 4: snprintf (r->path, sizeof r->path, "/"); return 0;
    case 5: snprintf (r->path, sizeof r->path, "/index.html"); return 0;
    default: return 0;
  }
}

static int
bda_hpack_int (const unsigned char *b, size_t len, size_t *off,
               unsigned char first, int prefix, uint32_t *out)
{
  uint32_t mask = (1u << prefix) - 1u;
  uint32_t v = first & mask;
  if (v != mask) { *out = v; return 0; }
  unsigned shift = 0;
  while (*off < len && shift <= 28) {
    unsigned char c = b[(*off)++];
    v += (uint32_t) (c & 0x7f) << shift;
    if ((c & 0x80) == 0) { *out = v; return 0; }
    shift += 7;
  }
  return -1;
}

static int
bda_hpack_string (const unsigned char *b, size_t len, size_t *off,
                  char *out, size_t out_sz)
{
  if (*off >= len || out_sz == 0) return -1;
  unsigned char first = b[(*off)++];
  if (first & 0x80) return -1;                 /* HPACK Huffman is intentionally unsupported here. */
  uint32_t sl = 0;
  if (bda_hpack_int (b, len, off, first, 7, &sl) < 0) return -1;
  if (sl >= out_sz || *off + sl > len) return -1;
  memcpy (out, b + *off, sl);
  out[sl] = '\0';
  *off += sl;
  return 0;
}

static void
bda_h2_apply_header (struct bda_h2_req *r, const char *name, const char *value)
{
  if (!name || !value) return;
  if (!strcasecmp (name, ":method"))
    snprintf (r->method, sizeof r->method, "%s", value);
  else if (!strcasecmp (name, ":path"))
    snprintf (r->path, sizeof r->path, "%s", value);
  else if (!strcasecmp (name, "content-type"))
    snprintf (r->ctype, sizeof r->ctype, "%s", value);
}

static int
bda_h2_decode_headers (const unsigned char *block, size_t blen,
                       struct bda_h2_req *r)
{
  size_t off = 0;
  while (off < blen) {
    unsigned char first = block[off++];
    if (first & 0x80) {                         /* indexed field */
      uint32_t idx = 0;
      if (bda_hpack_int (block, blen, &off, first, 7, &idx) < 0 || idx == 0)
        return -1;
      if (bda_h2_apply_indexed (r, idx) < 0) return -1;
      continue;
    }
    if ((first & 0xe0) == 0x20) {               /* dynamic table size update */
      uint32_t ignored = 0;
      if (bda_hpack_int (block, blen, &off, first, 5, &ignored) < 0)
        return -1;
      continue;
    }

    int prefix = (first & 0xc0) == 0x40 ? 6 : 4;
    uint32_t name_idx = 0;
    char name[160], value[1200];
    if (bda_hpack_int (block, blen, &off, first, prefix, &name_idx) < 0)
      return -1;
    if (name_idx) {
      const char *n = bda_h2_static_name (name_idx);
      if (!n) return -1;
      snprintf (name, sizeof name, "%s", n);
    } else if (bda_hpack_string (block, blen, &off, name, sizeof name) < 0)
      return -1;
    if (bda_hpack_string (block, blen, &off, value, sizeof value) < 0)
      return -1;
    bda_h2_apply_header (r, name, value);
  }
  return 0;
}

static int
bda_h2_read_frame (struct bda_conn *c, unsigned char *payload, size_t payload_sz,
                   uint8_t *type, uint8_t *flags, uint32_t *sid, size_t *plen)
{
  unsigned char h[9];
  if (bda_conn_readn (c, h, sizeof h) < 0) return -1;
  size_t len = ((size_t) h[0] << 16) | ((size_t) h[1] << 8) | h[2];
  if (len > payload_sz) return -2;
  *type = h[3];
  *flags = h[4];
  *sid = ((uint32_t) (h[5] & 0x7f) << 24) | ((uint32_t) h[6] << 16) |
         ((uint32_t) h[7] << 8) | h[8];
  *plen = len;
  if (len && bda_conn_readn (c, payload, len) < 0) return -1;
  return 0;
}

static int
bda_h2_write_frame (struct bda_conn *c, uint8_t type, uint8_t flags,
                    uint32_t sid, const unsigned char *payload, size_t len)
{
  if (len > BDA_H2_MAX_FRAME || sid > 0x7fffffffU) return -1;
  unsigned char h[9];
  h[0] = (unsigned char) (len >> 16);
  h[1] = (unsigned char) (len >> 8);
  h[2] = (unsigned char) len;
  h[3] = type;
  h[4] = flags;
  h[5] = (unsigned char) (sid >> 24);
  h[6] = (unsigned char) (sid >> 16);
  h[7] = (unsigned char) (sid >> 8);
  h[8] = (unsigned char) sid;
  if (bda_conn_writen (c, h, sizeof h) < 0) return -1;
  return len ? bda_conn_writen (c, payload, len) : 0;
}

static int
bda_hpack_put_string (unsigned char *out, size_t out_sz, size_t *off,
                      const char *s)
{
  size_t n = strlen (s);
  if (n > 127 || *off + 1 + n > out_sz) return -1;
  out[(*off)++] = (unsigned char) n;            /* raw string, no Huffman */
  memcpy (out + *off, s, n);
  *off += n;
  return 0;
}

static int
bda_h2_send_doh_response (struct bda_conn *c, uint32_t sid,
                          const unsigned char *wire, size_t wire_len)
{
  char clen[32];
  snprintf (clen, sizeof clen, "%zu", wire_len);
  unsigned char hb[128];
  size_t off = 0;
  hb[off++] = 0x88;                             /* indexed :status 200 */
  hb[off++] = 0x40 | 28;                        /* literal content-type */
  if (bda_hpack_put_string (hb, sizeof hb, &off, "application/dns-message") < 0)
    return -1;
  hb[off++] = 0x40 | 25;                        /* literal content-length */
  if (bda_hpack_put_string (hb, sizeof hb, &off, clen) < 0)
    return -1;
  if (bda_h2_write_frame (c, 1, 0x04, sid, hb, off) < 0) return -1; /* HEADERS END_HEADERS */
  return bda_h2_write_frame (c, 0, 0x01, sid, wire, wire_len);      /* DATA END_STREAM */
}

static int
bda_h2_send_empty_status (struct bda_conn *c, uint32_t sid, int status)
{
  char st[4], clen[] = "0";
  snprintf (st, sizeof st, "%03d", status);
  unsigned char hb[64]; size_t off = 0;
  hb[off++] = 0x40 | 8;                         /* literal :status */
  if (bda_hpack_put_string (hb, sizeof hb, &off, st) < 0) return -1;
  hb[off++] = 0x40 | 25;                        /* literal content-length */
  if (bda_hpack_put_string (hb, sizeof hb, &off, clen) < 0) return -1;
  return bda_h2_write_frame (c, 1, 0x05, sid, hb, off); /* HEADERS END_HEADERS|END_STREAM */
}

static int
bda_h2_handle (struct bda_conn *c, struct bda_zone *zones, int nz,
               const char *doh_path)
{
  if (bda_h2_write_frame (c, 4, 0, 0, NULL, 0) < 0) return -1; /* server SETTINGS */
  struct bda_h2_req req; memset (&req, 0, sizeof req);
  unsigned char payload[BDA_H2_MAX_FRAME];
  for (int frames = 0; frames < 64; frames++) {
    uint8_t type = 0, flags = 0; uint32_t sid = 0; size_t plen = 0;
    int rr = bda_h2_read_frame (c, payload, sizeof payload, &type, &flags, &sid, &plen);
    if (rr < 0) return -1;
    if (type == 4) {                             /* SETTINGS */
      if (sid != 0) return -1;
      if (!(flags & 0x01) && bda_h2_write_frame (c, 4, 0x01, 0, NULL, 0) < 0)
        return -1;
      continue;
    }
    if (type == 6 && plen == 8) {                /* PING */
      if (bda_h2_write_frame (c, 6, flags | 0x01, 0, payload, plen) < 0) return -1;
      continue;
    }
    if (type == 8) continue;                     /* WINDOW_UPDATE */
    if (type == 3) return -1;                    /* RST_STREAM */
    if (type == 1) {                             /* HEADERS */
      if (sid == 0 || req.saw_headers || !(flags & 0x04)) return -1;
      req.stream_id = sid;
      req.saw_headers = 1;
      if (bda_h2_decode_headers (payload, plen, &req) < 0)
        { bda_h2_send_empty_status (c, sid, 400); return -1; }
      if (flags & 0x01) req.end_stream = 1;
    } else if (type == 0) {                      /* DATA */
      if (!req.saw_headers || sid != req.stream_id) return -1;
      if (req.body_len + plen > sizeof req.body)
        { bda_h2_send_empty_status (c, sid, 413); return -1; }
      memcpy (req.body + req.body_len, payload, plen);
      req.body_len += plen;
      if (flags & 0x01) req.end_stream = 1;
    } else {
      continue;
    }
    if (req.saw_headers && req.end_stream) {
      char path_only[1200];
      snprintf (path_only, sizeof path_only, "%s", req.path);
      char *qmark = strchr (path_only, '?');
      if (qmark) *qmark = '\0';
      if (doh_path && *doh_path && strcmp (path_only, doh_path))
        { bda_h2_send_empty_status (c, req.stream_id, 404); return 0; }
      unsigned char wire[BD_DOH_WIRE_MAX]; size_t wire_len = 0;
      int st = bd_doh_decode_request (req.method[0] ? req.method : "POST",
                                      req.path, req.body, req.body_len,
                                      req.ctype[0] ? req.ctype : NULL,
                                      wire, sizeof wire, &wire_len);
      if (st != 200)
        { bda_h2_send_empty_status (c, req.stream_id, st); return 0; }
      unsigned char resp[BD_DOH_WIRE_MAX];
      int rl = bda_answer_wire (zones, nz, wire, wire_len, resp, sizeof resp, NULL);
      if (rl <= 0)
        { bda_h2_send_empty_status (c, req.stream_id, 500); return -1; }
      return bda_h2_send_doh_response (c, req.stream_id, resp, (size_t) rl);
    }
  }
  return -1;
}

static int
bda_doh_read_header (struct bda_conn *c, char *hdr, size_t hdr_sz, size_t *hdr_len)
{
  size_t n = 0;
  while (n + 1 < hdr_sz) {
    unsigned char ch;
    int r = bda_conn_read_some (c, &ch, 1);
    if (r <= 0) return -1;
    hdr[n++] = (char) ch;
    if (n >= 4 && hdr[n - 4] == '\r' && hdr[n - 3] == '\n' &&
        hdr[n - 2] == '\r' && hdr[n - 1] == '\n')
      { hdr[n] = '\0'; *hdr_len = n; return 0; }
  }
  return -2;
}

static int
bda_doh_handle (struct bda_conn *c, struct bda_zone *zones, int nz,
                const char *doh_path)
{
  char hdr[16384]; size_t hdr_len = 0;
  int hr = bda_doh_read_header (c, hdr, sizeof hdr, &hdr_len);
  if (hr == -2) return bda_http_error (c, 413);
  if (hr < 0) return bda_http_error (c, 400);
  if (hdr_len == BDA_H2_PREFACE1_LEN &&
      memcmp (hdr, BDA_H2_PREFACE1, BDA_H2_PREFACE1_LEN) == 0)
    {
      unsigned char rest[BDA_H2_PREFACE2_LEN];
      if (bda_conn_readn (c, rest, sizeof rest) < 0 ||
          memcmp (rest, BDA_H2_PREFACE2, sizeof rest) != 0)
        return -1;
      return bda_h2_handle (c, zones, nz, doh_path);
    }

  char method[12] = "", target[1200] = "", version[16] = "";
  char ctype[160] = "";
  long content_length = 0;
  char *line = hdr;
  char *eol = strstr (line, "\r\n");
  if (!eol) return bda_http_error (c, 400);
  *eol = '\0';
  if (sscanf (line, "%11s %1199s %15s", method, target, version) != 3)
    return bda_http_error (c, 400);
  if (strcmp (version, "HTTP/1.0") && strcmp (version, "HTTP/1.1"))
    return bda_http_error (c, 400);

  char *p = eol + 2;
  while (p < hdr + hdr_len && p[0] != '\r') {
    char *nl = strstr (p, "\r\n");
    if (!nl) break;
    *nl = '\0';
    char *colon = strchr (p, ':');
    if (colon) {
      *colon++ = '\0';
      while (*colon == ' ' || *colon == '\t') colon++;
      if (!strcasecmp (p, "Content-Type")) {
        snprintf (ctype, sizeof ctype, "%s", colon);
      } else if (!strcasecmp (p, "Content-Length")) {
        char *end = NULL;
        long v = strtol (colon, &end, 10);
        if (!end || (*end && *end != ' ' && *end != '\t') || v < 0)
          return bda_http_error (c, 400);
        content_length = v;
      } else if (!strcasecmp (p, "Transfer-Encoding")) {
        return bda_http_error (c, 501);
      }
    }
    p = nl + 2;
  }

  char path_only[1200];
  snprintf (path_only, sizeof path_only, "%s", target);
  char *qmark = strchr (path_only, '?');
  if (qmark) *qmark = '\0';
  if (doh_path && *doh_path && strcmp (path_only, doh_path))
    return bda_http_error (c, 404);

  if (content_length > BD_DOH_WIRE_MAX)
    return bda_http_error (c, 413);
  unsigned char body[BD_DOH_WIRE_MAX];
  if (content_length > 0 &&
      bda_conn_readn (c, body, (size_t) content_length) < 0)
    return bda_http_error (c, 400);

  unsigned char wire[BD_DOH_WIRE_MAX]; size_t wire_len = 0;
  int st = bd_doh_decode_request (method, target, body, (size_t) content_length,
                                  ctype[0] ? ctype : NULL, wire, sizeof wire,
                                  &wire_len);
  if (st != 200)
    return bda_http_error (c, st);

  unsigned char resp[BD_DOH_WIRE_MAX];
  int rl = bda_answer_wire (zones, nz, wire, wire_len, resp, sizeof resp, NULL);
  if (rl <= 0)
    return bda_http_error (c, 500);

  unsigned char http[BD_DOH_WIRE_MAX + 512]; size_t http_len = 0;
  if (bd_doh_encode_response (resp, (size_t) rl, http, sizeof http, &http_len) < 0)
    return bda_http_error (c, 500);
  return bda_conn_writen (c, http, http_len);
}

static int
bda_dot_handle (struct bda_conn *c, struct bda_zone *zones, int nz,
                unsigned char *scratch, size_t scratch_sz)
{
  unsigned char lb[2];
  if (bda_conn_readn (c, lb, 2) < 0) return -1;
  int ml = (lb[0] << 8) | lb[1];
  if (ml < 12 || ml > BDR_MSG_MAX) return -1;
  unsigned char qmsg[BDR_MSG_MAX];
  if (bda_conn_readn (c, qmsg, (size_t) ml) < 0) return -1;
  int rl = bda_answer_wire (zones, nz, qmsg, (size_t) ml, scratch, scratch_sz, NULL);
  if (rl <= 0 || rl > 65535) return -1;
  unsigned char ol[2] = { (unsigned char) (rl >> 8), (unsigned char) rl };
  if (bda_conn_writen (c, ol, 2) < 0) return -1;
  return bda_conn_writen (c, scratch, (size_t) rl);
}

#if BDA_DOQ_HAVE_QUIC
#define BDA_DOQ_CONN_MAX 8
#define BDA_DOQ_STREAM_MAX 8
#define BDA_DOQ_SCIDLEN 18
#define BDA_DOQ_UDP_PAYLOAD 1452

struct bda_doq_conn;

struct bda_doq_stream {
  int used;
  int64_t id;
  unsigned char req[BDA_DOQ_MAX_WIRE];
  size_t req_len;
  unsigned char resp[BDA_DOQ_MAX_WIRE];
  size_t resp_len;
  size_t resp_off;
  int response_ready;
  int fin_sent;
};

struct bda_doq_srv {
  int fd;
  SSL_CTX *ssl_ctx;
  struct sockaddr_storage local_addr;
  socklen_t local_addrlen;
  struct bda_zone *zones;
  int nz;
  struct bda_doq_conn *conns;
};

struct bda_doq_conn {
  int used;
  ngtcp2_crypto_conn_ref conn_ref;
  ngtcp2_conn *conn;
  SSL *ssl;
  ngtcp2_cid initial_dcid;
  ngtcp2_cid server_scid;
  struct sockaddr_storage remote_addr;
  socklen_t remote_addrlen;
  struct sockaddr_storage local_addr;
  socklen_t local_addrlen;
  ngtcp2_ccerr last_error;
  struct bda_doq_srv *srv;
  struct bda_doq_stream streams[BDA_DOQ_STREAM_MAX];
  time_t last_active;
};

static uint64_t
bda_doq_timestamp (void)
{
  struct timespec ts;
  if (clock_gettime (CLOCK_MONOTONIC, &ts) != 0)
    return (uint64_t) time (NULL) * NGTCP2_SECONDS;
  return (uint64_t) ts.tv_sec * NGTCP2_SECONDS + (uint64_t) ts.tv_nsec;
}

static ngtcp2_conn *
bda_doq_get_conn (ngtcp2_crypto_conn_ref *conn_ref)
{
  struct bda_doq_conn *c = (struct bda_doq_conn *) conn_ref->user_data;
  return c ? c->conn : NULL;
}

static int
bda_doq_alpn_select_cb (SSL *ssl, const unsigned char **out,
                        unsigned char *outlen, const unsigned char *in,
                        unsigned int inlen, void *arg)
{
  (void) ssl; (void) arg;
  for (unsigned int off = 0; off < inlen;)
    {
      unsigned int n = in[off++];
      if (off + n > inlen) break;
      if (n == 3 && memcmp (in + off, BDA_DOQ_ALPN, 3) == 0)
        {
          *out = in + off;
          *outlen = (unsigned char) n;
          return SSL_TLSEXT_ERR_OK;
        }
      off += n;
    }
  return SSL_TLSEXT_ERR_NOACK;
}

static int
bda_doq_tls_ctx_init (struct bda_doq_srv *srv, const char *cert,
                      const char *key)
{
  srv->ssl_ctx = SSL_CTX_new (TLS_server_method ());
  if (!srv->ssl_ctx)
    { builtin_error ("DoQ: SSL_CTX_new: %s", ERR_error_string (ERR_get_error (), NULL)); return -1; }
  SSL_CTX_set_options (srv->ssl_ctx,
                       (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
                       SSL_OP_CIPHER_SERVER_PREFERENCE);
  SSL_CTX_set_mode (srv->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
  if (ngtcp2_crypto_boringssl_configure_server_context (srv->ssl_ctx) != 0)
    { builtin_error ("DoQ: ngtcp2 aws-lc server context configure failed"); return -1; }
  SSL_CTX_set_alpn_select_cb (srv->ssl_ctx, bda_doq_alpn_select_cb, NULL);
  if (SSL_CTX_use_PrivateKey_file (srv->ssl_ctx, key, SSL_FILETYPE_PEM) != 1)
    { builtin_error ("DoQ: loading key %s: %s", key, ERR_error_string (ERR_get_error (), NULL)); return -1; }
  if (SSL_CTX_use_certificate_chain_file (srv->ssl_ctx, cert) != 1)
    { builtin_error ("DoQ: loading certificate %s: %s", cert, ERR_error_string (ERR_get_error (), NULL)); return -1; }
  if (SSL_CTX_check_private_key (srv->ssl_ctx) != 1)
    { builtin_error ("DoQ: certificate and key do not match"); return -1; }
  static const unsigned char sid_ctx[] = "dns-doq";
  SSL_CTX_set_session_id_context (srv->ssl_ctx, sid_ctx, sizeof sid_ctx - 1);
  return 0;
}

static void
bda_doq_rand_cb (uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
  (void) rand_ctx;
  if (RAND_bytes (dest, (int) destlen) != 1)
    abort ();
}

static int
bda_doq_get_new_connection_id_cb (ngtcp2_conn *conn, ngtcp2_cid *cid,
                                  ngtcp2_stateless_reset_token *token,
                                  size_t cidlen, void *user_data)
{
  (void) conn; (void) user_data;
  if (RAND_bytes (cid->data, (int) cidlen) != 1)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  cid->datalen = cidlen;
  if (RAND_bytes (token->data, sizeof token->data) != 1)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  return 0;
}

static struct bda_doq_stream *
bda_doq_find_stream (struct bda_doq_conn *c, int64_t stream_id, int create)
{
  for (int i = 0; i < BDA_DOQ_STREAM_MAX; i++)
    if (c->streams[i].used && c->streams[i].id == stream_id)
      return &c->streams[i];
  if (!create) return NULL;
  for (int i = 0; i < BDA_DOQ_STREAM_MAX; i++)
    if (!c->streams[i].used)
      {
        memset (&c->streams[i], 0, sizeof c->streams[i]);
        c->streams[i].used = 1;
        c->streams[i].id = stream_id;
        return &c->streams[i];
      }
  return NULL;
}

static int
bda_doq_recv_stream_data_cb (ngtcp2_conn *conn, uint32_t flags,
                             int64_t stream_id, uint64_t offset,
                             const uint8_t *data, size_t datalen,
                             void *user_data, void *stream_user_data)
{
  struct bda_doq_conn *c = (struct bda_doq_conn *) user_data;
  (void) conn; (void) offset; (void) stream_user_data;
  if (!c || (stream_id & 0x03) != 0)            /* client-initiated bidi only */
    return 0;
  struct bda_doq_stream *s = bda_doq_find_stream (c, stream_id, 1);
  if (!s || s->response_ready)
    return 0;
  if (datalen > sizeof s->req || s->req_len > sizeof s->req - datalen)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  memcpy (s->req + s->req_len, data, datalen);
  s->req_len += datalen;
  ngtcp2_conn_extend_max_stream_offset (c->conn, stream_id, (uint64_t) datalen);
  ngtcp2_conn_extend_max_offset (c->conn, (uint64_t) datalen);
  if (flags & NGTCP2_STREAM_DATA_FLAG_FIN)
    {
      int rl = bda_answer_wire (c->srv->zones, c->srv->nz, s->req, s->req_len,
                                s->resp, sizeof s->resp, NULL);
      if (rl <= 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
      s->resp_len = (size_t) rl;
      s->resp_off = 0;
      s->response_ready = 1;
    }
  return 0;
}

static int
bda_doq_stream_open_cb (ngtcp2_conn *conn, int64_t stream_id, void *user_data)
{
  struct bda_doq_conn *c = (struct bda_doq_conn *) user_data;
  (void) conn;
  if (!c || (stream_id & 0x03) != 0)
    return 0;
  return bda_doq_find_stream (c, stream_id, 1) ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

static int
bda_doq_stream_close_cb (ngtcp2_conn *conn, uint32_t flags,
                         int64_t stream_id, uint64_t app_error_code,
                         void *user_data, void *stream_user_data)
{
  struct bda_doq_conn *c = (struct bda_doq_conn *) user_data;
  (void) conn; (void) app_error_code; (void) flags; (void) stream_user_data;
  if (!c) return 0;
  struct bda_doq_stream *s = bda_doq_find_stream (c, stream_id, 0);
  if (s) memset (s, 0, sizeof *s);
  return 0;
}

static int
bda_doq_conn_init (struct bda_doq_srv *srv, struct bda_doq_conn *c,
                   const ngtcp2_pkt_hd *hd,
                   const struct sockaddr *remote, socklen_t remote_len)
{
  memset (c, 0, sizeof *c);
  c->used = 1;
  c->srv = srv;
  c->remote_addrlen = remote_len;
  memcpy (&c->remote_addr, remote, remote_len);
  c->local_addrlen = srv->local_addrlen;
  memcpy (&c->local_addr, &srv->local_addr, srv->local_addrlen);
  c->initial_dcid = hd->dcid;
  c->server_scid.datalen = BDA_DOQ_SCIDLEN;
  if (RAND_bytes (c->server_scid.data, (int) c->server_scid.datalen) != 1)
    return -1;
  ngtcp2_ccerr_default (&c->last_error);
  c->conn_ref.get_conn = bda_doq_get_conn;
  c->conn_ref.user_data = c;

  c->ssl = SSL_new (srv->ssl_ctx);
  if (!c->ssl)
    return -1;
  SSL_set_app_data (c->ssl, &c->conn_ref);
  SSL_set_accept_state (c->ssl);
#if defined(SSL_set_early_data_enabled)
  SSL_set_early_data_enabled (c->ssl, 0);
#endif

  ngtcp2_path path = {
    .local = { .addr = (struct sockaddr *) &c->local_addr, .addrlen = c->local_addrlen },
    .remote = { .addr = (struct sockaddr *) &c->remote_addr, .addrlen = c->remote_addrlen },
    .user_data = NULL,
  };
  ngtcp2_callbacks callbacks = {
    .recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
    .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    .recv_stream_data = bda_doq_recv_stream_data_cb,
    .stream_open = bda_doq_stream_open_cb,
    .stream_close = bda_doq_stream_close_cb,
    .rand = bda_doq_rand_cb,
    .update_key = ngtcp2_crypto_update_key_cb,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
    .get_new_connection_id2 = bda_doq_get_new_connection_id_cb,
    .get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb,
  };
  ngtcp2_settings settings;
  ngtcp2_settings_default (&settings);
  settings.initial_ts = bda_doq_timestamp ();
  settings.max_tx_udp_payload_size = BDA_DOQ_UDP_PAYLOAD;
  ngtcp2_transport_params params;
  ngtcp2_transport_params_default (&params);
  params.initial_max_stream_data_bidi_remote = BDA_DOQ_MAX_WIRE;
  params.initial_max_stream_data_bidi_local = BDA_DOQ_MAX_WIRE;
  params.initial_max_stream_data_uni = 4096;
  params.initial_max_data = 1024 * 1024;
  params.initial_max_streams_bidi = BDA_DOQ_STREAM_MAX;
  params.initial_max_streams_uni = 0;
  params.max_idle_timeout = 15 * NGTCP2_SECONDS;
  params.active_connection_id_limit = 4;
  params.original_dcid = hd->dcid;
  params.original_dcid_present = 1;

  int rv = ngtcp2_conn_server_new (&c->conn, &hd->scid, &c->server_scid,
                                   &path, hd->version, &callbacks, &settings,
                                   &params, NULL, c);
  if (rv != 0)
    return -1;
  ngtcp2_conn_set_tls_native_handle (c->conn, c->ssl);
  c->last_active = time (NULL);
  return 0;
}

static void
bda_doq_conn_free (struct bda_doq_conn *c)
{
  if (!c || !c->used) return;
  if (c->conn) ngtcp2_conn_del (c->conn);
  if (c->ssl) SSL_free (c->ssl);
  memset (c, 0, sizeof *c);
}

static int
bda_doq_cid_eq (const ngtcp2_cid *cid, const uint8_t *data, size_t len)
{
  return cid->datalen == len && memcmp (cid->data, data, len) == 0;
}

static struct bda_doq_conn *
bda_doq_find_conn (struct bda_doq_srv *srv, const ngtcp2_version_cid *vc)
{
  for (int i = 0; i < BDA_DOQ_CONN_MAX; i++)
    {
      struct bda_doq_conn *c = &srv->conns[i];
      if (!c->used) continue;
      if (bda_doq_cid_eq (&c->server_scid, vc->dcid, vc->dcidlen) ||
          bda_doq_cid_eq (&c->initial_dcid, vc->dcid, vc->dcidlen))
        return c;
    }
  return NULL;
}

static struct bda_doq_conn *
bda_doq_alloc_conn (struct bda_doq_srv *srv)
{
  time_t now = time (NULL);
  for (int i = 0; i < BDA_DOQ_CONN_MAX; i++)
    if (srv->conns[i].used && now - srv->conns[i].last_active > 30)
      bda_doq_conn_free (&srv->conns[i]);
  for (int i = 0; i < BDA_DOQ_CONN_MAX; i++)
    if (!srv->conns[i].used)
      return &srv->conns[i];
  bda_doq_conn_free (&srv->conns[0]);
  return &srv->conns[0];
}

static int
bda_doq_send_packet (struct bda_doq_srv *srv, struct bda_doq_conn *c,
                     const unsigned char *data, size_t len)
{
  ssize_t n;
  do
    n = sendto (srv->fd, data, len, 0, (struct sockaddr *) &c->remote_addr,
                c->remote_addrlen);
  while (n < 0 && errno == EINTR);
  return n == (ssize_t) len ? 0 : -1;
}

static struct bda_doq_stream *
bda_doq_next_response (struct bda_doq_conn *c)
{
  for (int i = 0; i < BDA_DOQ_STREAM_MAX; i++)
    if (c->streams[i].used && c->streams[i].response_ready &&
        !c->streams[i].fin_sent)
      return &c->streams[i];
  return NULL;
}

static int
bda_doq_write (struct bda_doq_srv *srv, struct bda_doq_conn *c)
{
  unsigned char pkt[BDA_DOQ_UDP_PAYLOAD];
  ngtcp2_tstamp ts = bda_doq_timestamp ();
  for (int rounds = 0; rounds < 32; rounds++)
    {
      struct bda_doq_stream *s = bda_doq_next_response (c);
      ngtcp2_vec v;
      ngtcp2_vec *vp = NULL;
      size_t vcnt = 0;
      int64_t sid = -1;
      uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
      if (s)
        {
          sid = s->id;
          v.base = s->resp + s->resp_off;
          v.len = s->resp_len - s->resp_off;
          vp = &v; vcnt = 1;
          flags = NGTCP2_WRITE_STREAM_FLAG_FIN;
        }
      ngtcp2_path_storage ps;
      ngtcp2_path_storage_zero (&ps);
      ngtcp2_pkt_info pi;
      ngtcp2_ssize wdatalen = 0;
      ngtcp2_ssize nw = ngtcp2_conn_writev_stream (c->conn, &ps.path, &pi,
                                                   pkt, sizeof pkt, &wdatalen,
                                                   flags, sid, vp, vcnt, ts);
      if (nw == 0) return 0;
      if (nw == NGTCP2_ERR_WRITE_MORE)
        {
          if (s && wdatalen > 0) s->resp_off += (size_t) wdatalen;
          continue;
        }
      if (nw < 0)
        {
          ngtcp2_ccerr_set_liberr (&c->last_error, (int) nw, NULL, 0);
          return -1;
        }
      if (s && wdatalen > 0)
        {
          s->resp_off += (size_t) wdatalen;
          if (s->resp_off >= s->resp_len)
            s->fin_sent = 1;
        }
      if (bda_doq_send_packet (srv, c, pkt, (size_t) nw) < 0)
        return -1;
    }
  return 0;
}

static int
bda_doq_handle_packet (struct bda_doq_srv *srv)
{
  unsigned char buf[65536];
  struct sockaddr_storage remote;
  struct iovec iov = { .iov_base = buf, .iov_len = sizeof buf };
  struct msghdr msg;
  memset (&msg, 0, sizeof msg);
  msg.msg_name = &remote;
  msg.msg_namelen = sizeof remote;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  ssize_t nread = recvmsg (srv->fd, &msg, MSG_DONTWAIT);
  if (nread < 0)
    return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;

  ngtcp2_version_cid vc;
  int rv = ngtcp2_pkt_decode_version_cid (&vc, buf, (size_t) nread, BDA_DOQ_SCIDLEN);
  if (rv == NGTCP2_ERR_VERSION_NEGOTIATION)
    return 0;
  if (rv != 0)
    return 0;
  struct bda_doq_conn *c = bda_doq_find_conn (srv, &vc);
  if (!c)
    {
      ngtcp2_pkt_hd hd;
      if (ngtcp2_accept (&hd, buf, (size_t) nread) != 0 ||
          hd.type != NGTCP2_PKT_INITIAL)
        return 0;
      c = bda_doq_alloc_conn (srv);
      if (bda_doq_conn_init (srv, c, &hd, (struct sockaddr *) &remote,
                             msg.msg_namelen) < 0)
        { bda_doq_conn_free (c); return -1; }
    }
  c->last_active = time (NULL);
  ngtcp2_path path = {
    .local = { .addr = (struct sockaddr *) &c->local_addr, .addrlen = c->local_addrlen },
    .remote = { .addr = (struct sockaddr *) &remote, .addrlen = msg.msg_namelen },
    .user_data = NULL,
  };
  ngtcp2_pkt_info pi;
  memset (&pi, 0, sizeof pi);
  rv = ngtcp2_conn_read_pkt (c->conn, &path, &pi, buf, (size_t) nread,
                             bda_doq_timestamp ());
  if (rv != 0)
    {
      if (rv == NGTCP2_ERR_CRYPTO)
        ngtcp2_ccerr_set_tls_alert (&c->last_error,
                                    ngtcp2_conn_get_tls_alert2 (c->conn),
                                    NULL, 0);
      else
        ngtcp2_ccerr_set_liberr (&c->last_error, rv, NULL, 0);
      bda_doq_conn_free (c);
      return 0;
    }
  return bda_doq_write (srv, c);
}

static int
bda_bind_doq (const char *addr, int port, struct bda_doq_srv *srv,
              const char *cert, const char *key, struct bda_doq_conn *conns,
              struct bda_zone *zones, int nz)
{
  memset (srv, 0, sizeof *srv);
  srv->fd = -1;
  srv->zones = zones;
  srv->nz = nz;
  srv->conns = conns;
  if (bda_doq_tls_ctx_init (srv, cert, key) < 0)
    return -1;
  int s = socket (AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (s < 0)
    { builtin_error ("DoQ socket: %s", strerror (errno)); return -1; }
  int one = 1;
  setsockopt (s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  struct sockaddr_in sa;
  memset (&sa, 0, sizeof sa);
  sa.sin_family = AF_INET;
  sa.sin_port = htons ((uint16_t) port);
  if (inet_pton (AF_INET, addr, &sa.sin_addr) != 1)
    { builtin_error ("DoQ bad listen addr: %s", addr); close (s); return -1; }
  if (bind (s, (struct sockaddr *) &sa, sizeof sa) < 0)
    { builtin_error ("DoQ bind %s:%d: %s", addr, port, strerror (errno)); close (s); return -1; }
  srv->fd = s;
  srv->local_addrlen = sizeof sa;
  memcpy (&srv->local_addr, &sa, sizeof sa);
  return s;
}

static void
bda_doq_srv_free (struct bda_doq_srv *srv)
{
  if (!srv) return;
  if (srv->conns)
    for (int i = 0; i < BDA_DOQ_CONN_MAX; i++)
      bda_doq_conn_free (&srv->conns[i]);
  if (srv->fd >= 0) close (srv->fd);
  if (srv->ssl_ctx) SSL_CTX_free (srv->ssl_ctx);
  memset (srv, 0, sizeof *srv);
  srv->fd = -1;
}
#else
struct bda_doq_srv { int fd; };
#endif

/* Load a zone, signing it in memory when sign_key is set (DNS-6.3 online
   inline signing). Signing runs on the loaded bd_rr_t[] directly via the
   shared sz_sign_zone_inplace() — the same code the offline `signzone` uses —
   with NO signzone emit/reparse round-trip. The zone is loaded into a full
   BDA_RR_MAX buffer (signing appends RRSIG/DNSKEY/NSEC[3]) and trimmed
   afterwards. Signing uses the RAW apex sz_load_zone() produced, before
   bda_norm() rewrites it. */
static int
bda_load_zone_signed (struct bda_zone *z, const char *path, const char *origin,
                      const char *sign_key, int use_nsec3)
{
  z->rr = calloc (BDA_RR_MAX, sizeof (bd_rr_t));
  if (!z->rr) return -1;
  z->n = sz_load_zone (path, origin, z->rr, BDA_RR_MAX, z->apex, sizeof z->apex);
  if (z->n < 0) { free (z->rr); z->rr = NULL; return -1; }
  if (sign_key) {
    int nn = z->n; char serr[256];
    if (sz_sign_zone_inplace (z->rr, &nn, z->apex, sign_key, 2592000L,
                              use_nsec3, NULL, 0, NULL, serr, sizeof serr) < 0)
      { builtin_warning ("auth-serve: signing %s: %s", path, serr); free (z->rr); z->rr = NULL; return -1; }
    z->n = nn;
  }
  bda_norm (z->apex);
  bd_rr_t *t = realloc (z->rr, (size_t) (z->n > 0 ? z->n : 1) * sizeof (bd_rr_t));
  if (t) z->rr = t;
  snprintf (z->path, sizeof z->path, "%s", path);
  snprintf (z->origin, sizeof z->origin, "%s", origin ? origin : "");
  z->njrnl = 0;
  return 0;
}

static const char *
bda_type_token (uint16_t type, char *buf, size_t bufsz)
{
  const char *name = bd_type_name (type);
  if (strcmp (name, "TYPE") != 0)
    return name;
  snprintf (buf, bufsz, "TYPE%u", (unsigned) type);
  return buf;
}

static int
bda_fprint_abs_name (FILE *f, const char *name)
{
  if (!name || !*name || strcmp (name, ".") == 0)
    return fprintf (f, ".") < 0 ? -1 : 0;
  return fprintf (f, "%s.", name) < 0 ? -1 : 0;
}

static int
bda_fprint_decoded_name (FILE *f, const unsigned char *p, size_t n, size_t *off)
{
  char name[256];
  if (bd_decode_name (p, n, off, name, sizeof name, 0) < 0)
    return -1;
  return bda_fprint_abs_name (f, name);
}

static int
bda_fprint_b64 (FILE *f, const unsigned char *in, size_t n)
{
  static const char *a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t i = 0;
  for (; i + 3 <= n; i += 3)
    {
      uint32_t v = ((uint32_t) in[i] << 16) | ((uint32_t) in[i + 1] << 8) | in[i + 2];
      if (fputc (a[(v >> 18) & 63], f) == EOF ||
          fputc (a[(v >> 12) & 63], f) == EOF ||
          fputc (a[(v >> 6) & 63], f) == EOF ||
          fputc (a[v & 63], f) == EOF)
        return -1;
    }
  if (n - i == 1)
    {
      uint32_t v = (uint32_t) in[i] << 16;
      if (fputc (a[(v >> 18) & 63], f) == EOF ||
          fputc (a[(v >> 12) & 63], f) == EOF ||
          fputs ("==", f) == EOF)
        return -1;
    }
  else if (n - i == 2)
    {
      uint32_t v = ((uint32_t) in[i] << 16) | ((uint32_t) in[i + 1] << 8);
      if (fputc (a[(v >> 18) & 63], f) == EOF ||
          fputc (a[(v >> 12) & 63], f) == EOF ||
          fputc (a[(v >> 6) & 63], f) == EOF ||
          fputc ('=', f) == EOF)
        return -1;
    }
  return 0;
}

static int
bda_fprint_hex (FILE *f, const unsigned char *p, size_t n)
{
  for (size_t i = 0; i < n; i++)
    if (fprintf (f, "%02x", p[i]) < 0)
      return -1;
  return 0;
}

static int
bda_fprint_generic_rdata (FILE *f, const bd_rr_t *r)
{
  if (fprintf (f, "\\# %u ", (unsigned) r->rdata_len) < 0)
    return -1;
  return bda_fprint_hex (f, r->rdata, r->rdata_len);
}

static int
bda_fprint_rdata (FILE *f, const bd_rr_t *r)
{
  switch (r->type)
    {
    case BD_T_A:
      {
        if (r->rdata_len != 4) return -1;
        struct in_addr a;
        memcpy (&a.s_addr, r->rdata, 4);
        char buf[64];
        if (!inet_ntop (AF_INET, &a, buf, sizeof buf)) return -1;
        return fprintf (f, "%s", buf) < 0 ? -1 : 0;
      }
    case BD_T_AAAA:
      {
        if (r->rdata_len != 16) return -1;
        struct in6_addr a;
        memcpy (a.s6_addr, r->rdata, 16);
        char buf[64];
        if (!inet_ntop (AF_INET6, &a, buf, sizeof buf)) return -1;
        return fprintf (f, "%s", buf) < 0 ? -1 : 0;
      }
    case BD_T_NS:
    case BD_T_CNAME:
    case BD_T_DNAME:
    case BD_T_PTR:
      {
        size_t off = 0;
        if (bda_fprint_decoded_name (f, r->rdata, r->rdata_len, &off) < 0)
          return -1;
        return off == r->rdata_len ? 0 : -1;
      }
    case BD_T_MX:
      {
        if (r->rdata_len < 3) return -1;
        if (fprintf (f, "%u ", (unsigned) bd_rd16 (r->rdata)) < 0)
          return -1;
        size_t off = 2;
        if (bda_fprint_decoded_name (f, r->rdata, r->rdata_len, &off) < 0)
          return -1;
        return off == r->rdata_len ? 0 : -1;
      }
    case BD_T_SOA:
      {
        size_t off = 0;
        if (bda_fprint_decoded_name (f, r->rdata, r->rdata_len, &off) < 0 ||
            fputc (' ', f) == EOF ||
            bda_fprint_decoded_name (f, r->rdata, r->rdata_len, &off) < 0)
          return -1;
        if (off + 20 != r->rdata_len) return -1;
        return fprintf (f, " %u %u %u %u %u",
                        bd_rd32 (r->rdata + off),
                        bd_rd32 (r->rdata + off + 4),
                        bd_rd32 (r->rdata + off + 8),
                        bd_rd32 (r->rdata + off + 12),
                        bd_rd32 (r->rdata + off + 16)) < 0 ? -1 : 0;
      }
    case BD_T_DNSKEY:
      {
        if (r->rdata_len < 4) return -1;
        if (fprintf (f, "%u %u %u ",
                     (unsigned) bd_rd16 (r->rdata),
                     (unsigned) r->rdata[2],
                     (unsigned) r->rdata[3]) < 0)
          return -1;
        return bda_fprint_b64 (f, r->rdata + 4, r->rdata_len - 4);
      }
    default:
      return bda_fprint_generic_rdata (f, r);
    }
}

static int
bda_write_zone_rr (FILE *f, const struct bda_zone *z, int i)
{
  char owner[256], typebuf[32];
  bda_owner (z, i, owner, sizeof owner);
  if (bda_fprint_abs_name (f, owner) < 0 ||
      fprintf (f, " %u IN %s ", (unsigned) z->rr[i].ttl,
               bda_type_token (z->rr[i].type, typebuf, sizeof typebuf)) < 0 ||
      bda_fprint_rdata (f, &z->rr[i]) < 0 ||
      fputc ('\n', f) == EOF)
    return -1;
  return 0;
}

static int
bda_mkdir_one (const char *dir)
{
  if (!dir || !*dir) return 0;
  if (mkdir (dir, 0755) == 0 || errno == EEXIST)
    {
      struct stat st;
      if (stat (dir, &st) == 0 && S_ISDIR (st.st_mode))
        return 0;
    }
  return -1;
}

static int
bda_mkdir_for_file (const char *path)
{
  char dir[512];
  if (!path || strlen (path) >= sizeof dir) return -1;
  snprintf (dir, sizeof dir, "%s", path);
  char *last = strrchr (dir, '/');
  if (!last) return 0;
  if (last == dir) return 0;
  *last = '\0';

  char *p = dir;
  if (*p == '/') p++;
  for (; *p; p++)
    {
      if (*p != '/') continue;
      *p = '\0';
      if (bda_mkdir_one (dir) < 0) { *p = '/'; return -1; }
      *p = '/';
    }
  return bda_mkdir_one (dir);
}

static int
bda_write_zone_file (const struct bda_zone *z, const char *path)
{
  if (!z || !path || !*path) return -1;
  if (bda_mkdir_for_file (path) < 0) return -1;

  char tmp[640];
  if (snprintf (tmp, sizeof tmp, "%s.tmpXXXXXX", path) >= (int) sizeof tmp)
    return -1;
  int fd = mkstemp (tmp);
  if (fd < 0) return -1;
  FILE *f = fdopen (fd, "w");
  if (!f) { close (fd); unlink (tmp); return -1; }

  int rc = 0;
  uint32_t ttl = (z->n > 0) ? z->rr[0].ttl : 3600;
  int soa_i = -1;
  for (int i = 0; i < z->n; i++)
    {
      char owner[256];
      bda_owner (z, i, owner, sizeof owner);
      if (z->rr[i].type == BDA_SOA && !strcmp (owner, z->apex))
        {
          ttl = z->rr[i].ttl ? z->rr[i].ttl : ttl;
          soa_i = i;
          break;
        }
    }
  if (fprintf (f, "$ORIGIN ") < 0 ||
      bda_fprint_abs_name (f, z->apex) < 0 ||
      fprintf (f, "\n$TTL %u\n", (unsigned) ttl) < 0)
    rc = -1;
  if (rc == 0 && soa_i >= 0 && bda_write_zone_rr (f, z, soa_i) < 0)
    rc = -1;
  for (int i = 0; rc == 0 && i < z->n; i++)
    {
      if (i == soa_i) continue;
      if (bda_write_zone_rr (f, z, i) < 0)
        rc = -1;
    }
  if (fflush (f) < 0)
    rc = -1;
  if (fclose (f) < 0)
    rc = -1;
  if (rc == 0 && rename (tmp, path) < 0)
    rc = -1;
  if (rc != 0)
    {
      unlink (tmp);
      return -1;
    }
  return 0;
}

static int
bda_slave_file_path (const char *slave_dir, const char *apex, char *buf, size_t buflen)
{
  if (!slave_dir || !*slave_dir || !apex || !*apex || !buf || buflen == 0)
    return -1;
  char safe[320];
  size_t j = 0;
  for (const unsigned char *p = (const unsigned char *) apex; *p; p++)
    {
      if (j + 6 >= sizeof safe) return -1;
      safe[j++] = (isalnum (*p) || *p == '.' || *p == '-' || *p == '_') ? (char) *p : '_';
    }
  if (j == 0 || (j == 1 && safe[0] == '.'))
    {
      memcpy (safe, "root.", 5);
      j = 5;
    }
  else if (safe[j - 1] != '.')
    safe[j++] = '.';
  memcpy (safe + j, "zone", 5);
  int n = snprintf (buf, buflen, "%s/%s", slave_dir, safe);
  return (n > 0 && (size_t) n < buflen) ? 0 : -1;
}

#define BDA_HOST_MAX 128

struct bda_primary {
  char host[BDA_HOST_MAX];
  int port;
  char keyname[256];
  int stealth;
  time_t fail_until;
  unsigned backoff;
};

struct bda_slave {
  char apex[256];
  struct bda_primary primaries[BDA_SLAVE_PRIMARY_MAX];
  int nprimaries;
  int cur_primary;
  unsigned failovers;
  int zone_index;
  time_t last_ok, last_try;
  uint32_t serial, refresh, retry, expire;
  int force, expired;
  int from_catalog;
  char cat_id[256];
};

struct bda_catalog_member {
  char apex[256];
  char id[256];
  char group[64];
};

struct bda_catalog {
  char apex[256];
  char version[64];
  int version_ok;
  struct bda_catalog_member members[BDA_SLAVE_MAX];
  int n;
  int rejected;
};

struct bda_catalog_stats {
  int added;
  int removed;
  int skipped;
};

static int
bda_parse_port_token (const char *port_s, int *port)
{
  char *pe = NULL;
  long n;
  if (!port_s || !*port_s || !port) return -1;
  n = strtol (port_s, &pe, 10);
  if (!pe || *pe || n <= 0 || n > 65535) return -1;
  *port = (int) n;
  return 0;
}

static int
bda_token_is_port (const char *s)
{
  int port = 0;
  return bda_parse_port_token (s, &port) == 0;
}

static int
bda_slave_init_base (struct bda_slave *s, const char *apex)
{
  if (!s || !apex || !*apex)
    return -1;
  memset (s, 0, sizeof *s);
  s->cur_primary = -1;
  s->zone_index = -1;
  if (bd_canon_owner (apex, s->apex, sizeof s->apex) < 0) return -1;
  bda_norm (s->apex);
  if (s->apex[0] == '\0' || (s->apex[0] == '.' && s->apex[1] == '\0'))
    return -1;
  return 0;
}

static int
bda_primary_set (struct bda_primary *p, const char *host, int port,
                 const char *key, int stealth)
{
  struct sockaddr_storage ignored;
  socklen_t ignored_len = 0;
  if (!p || !host || !*host || port <= 0 || port > 65535)
    return -1;
  if (strlen (host) >= sizeof p->host) return -1;
  if (bd_make_sockaddr (host, port, &ignored, &ignored_len) < 0) return -1;
  memset (p, 0, sizeof *p);
  snprintf (p->host, sizeof p->host, "%s", host);
  p->port = port;
  p->stealth = stealth ? 1 : 0;
  if (key && key[0])
    {
      if (bd_canon_owner (key, p->keyname, sizeof p->keyname) < 0) return -1;
      bda_norm (p->keyname);
    }
  return 0;
}

static int
bda_slave_add_primary (struct bda_slave *s, const char *host, int port,
                       const char *key, int stealth)
{
  if (!s || s->nprimaries >= BDA_SLAVE_PRIMARY_MAX) return -1;
  if (bda_primary_set (&s->primaries[s->nprimaries], host, port, key, stealth) < 0)
    return -1;
  if (s->cur_primary < 0) s->cur_primary = 0;
  s->nprimaries++;
  return 0;
}

static int
bda_slave_init (struct bda_slave *s, const char *apex, const char *host,
                int port, const char *key)
{
  if (bda_slave_init_base (s, apex) < 0) return -1;
  return bda_slave_add_primary (s, host, port, key, 0);
}

static int
bda_parse_primary_token (const char *token, const char *default_key,
                         char *host, size_t host_sz, int *port,
                         char *key, size_t key_sz, int *stealth)
{
  char buf[256];
  if (!token || !*token || !host || host_sz == 0 || !port ||
      !key || key_sz == 0 || !stealth || strlen (token) >= sizeof buf)
    return -1;
  snprintf (buf, sizeof buf, "%s", token);
  char *p = buf;
  *stealth = 0;
  *port = 53;
  host[0] = '\0';
  key[0] = '\0';
  if (default_key && default_key[0])
    snprintf (key, key_sz, "%s", default_key);

  if (*p == '~')
    {
      *stealth = 1;
      p++;
      if (!*p) return -1;
    }

  char *hash = strchr (p, '#');
  if (hash)
    {
      *hash++ = '\0';
      if (!*hash) return -1;
      snprintf (key, key_sz, "%s", hash);
    }

  if (*p == '[')
    {
      char *end = strchr (p, ']');
      if (!end || end == p + 1) return -1;
      size_t hn = (size_t) (end - p - 1);
      if (hn >= host_sz) return -1;
      memcpy (host, p + 1, hn);
      host[hn] = '\0';
      char *q = end + 1;
      if (*q)
        {
          if (*q != ':') return -1;
          q++;
          if (!*q || strchr (q, ':') || bda_parse_port_token (q, port) < 0)
            return -1;
        }
    }
  else if (bz_is_ipv6 (p))
    {
      if (hash || strlen (p) >= host_sz) return -1;
      snprintf (host, host_sz, "%s", p);
    }
  else
    {
      char *port_part = strchr (p, ':');
      if (port_part)
        {
          *port_part++ = '\0';
          if (!*port_part || strchr (port_part, ':') ||
              bda_parse_port_token (port_part, port) < 0)
            return -1;
        }
      if (!*p || strlen (p) >= host_sz) return -1;
      snprintf (host, host_sz, "%s", p);
    }

  struct sockaddr_storage ignored;
  socklen_t ignored_len = 0;
  if (bd_make_sockaddr (host, *port, &ignored, &ignored_len) < 0) return -1;
  if (key[0])
    {
      char canon[256];
      if (bd_canon_owner (key, canon, sizeof canon) < 0) return -1;
      bda_norm (canon);
      snprintf (key, key_sz, "%s", canon);
    }
  return 0;
}

static int
bda_parse_slave_zone_legacy (const char *apex, const char *rest, struct bda_slave *s)
{
  int port = 53;
  char host[BDA_HOST_MAX], key[256] = "";
  host[0] = '\0';

  if (rest[0] == '[')
    {
      char *end = strchr (rest, ']');
      if (!end || end == rest + 1) return -1;
      size_t hn = (size_t) (end - rest - 1);
      if (hn >= sizeof host) return -1;
      memcpy (host, rest + 1, hn);
      host[hn] = '\0';
      char *p = end + 1;
      if (*p)
        {
          if (*p != ':') return -1;
          p++;
          char *next = strchr (p, ':');
          if (next) *next = '\0';
          if (*p)
            {
              char *pe = NULL;
              long n = strtol (p, &pe, 10);
              if (!pe || *pe || n <= 0 || n > 65535) return -1;
              port = (int) n;
            }
          if (next && next[1])
            snprintf (key, sizeof key, "%s", next + 1);
        }
    }
  else if (bz_is_ipv6 (rest))
    {
      if (strlen (rest) >= sizeof host) return -1;
      strcpy (host, rest);
    }
  else
    {
      char tmp[256];
      if (strlen (rest) >= sizeof tmp) return -1;
      snprintf (tmp, sizeof tmp, "%s", rest);
      char *host_part = tmp;
      char *port_part = strchr (host_part, ':');
      char *key_part = NULL;
      if (port_part)
        {
          *port_part = '\0';
          port_part++;
          key_part = strchr (port_part, ':');
          if (key_part) { *key_part = '\0'; key_part++; }
        }
      if (!host_part || !*host_part) return -1;
      if (strlen (host_part) >= sizeof host) return -1;
      strcpy (host, host_part);
      if (port_part && *port_part)
        {
          if (bda_parse_port_token (port_part, &port) < 0) return -1;
        }
      if (key_part && *key_part)
        snprintf (key, sizeof key, "%s", key_part);
    }
  return bda_slave_init (s, apex, host, port, key);
}

static int
bda_extract_listwide_key (char *rest, char *key, size_t key_sz)
{
  char *last, *first, *second;
  key[0] = '\0';
  if (!rest || !strchr (rest, ',')) return 0;
  last = strrchr (rest, ',');
  last = last ? last + 1 : rest;
  if (*last == '~') last++;
  if (!*last || strchr (last, '#')) return 0;

  if (*last == '[')
    {
      char *end = strchr (last, ']');
      if (!end) return 0;
      char *p = end + 1;
      if (*p != ':') return 0;
      p++;
      if (!*p) return 0;
      char *extra = strchr (p, ':');
      if (extra)
        {
          if (!extra[1]) return -1;
          snprintf (key, key_sz, "%s", extra + 1);
          *extra = '\0';
        }
      else if (!bda_token_is_port (p))
        {
          snprintf (key, key_sz, "%s", p);
          *(p - 1) = '\0';
        }
      return 0;
    }

  first = strchr (last, ':');
  if (!first) return 0;
  second = strchr (first + 1, ':');
  if (second)
    {
      if (!second[1]) return -1;
      snprintf (key, key_sz, "%s", second + 1);
      *second = '\0';
    }
  else if (!bda_token_is_port (first + 1))
    {
      snprintf (key, key_sz, "%s", first + 1);
      *first = '\0';
    }
  return 0;
}

static int
bda_parse_slave_zone (const char *spec, struct bda_slave *s)
{
  char buf[1024];
  if (!spec || strlen (spec) >= sizeof buf) return -1;
  strcpy (buf, spec);
  char *sep = strchr (buf, ':');
  if (!sep || sep == buf || !sep[1]) return -1;
  *sep = '\0';
  char *apex = buf;
  char *rest = sep + 1;

  if (!strchr (rest, ',') && !strchr (rest, '#') && rest[0] != '~')
    return bda_parse_slave_zone_legacy (apex, rest, s);

  if (bda_slave_init_base (s, apex) < 0) return -1;
  char default_key[256];
  if (bda_extract_listwide_key (rest, default_key, sizeof default_key) < 0)
    return -1;
  if (default_key[0])
    {
      char canon[256];
      if (bd_canon_owner (default_key, canon, sizeof canon) < 0) return -1;
      bda_norm (canon);
      snprintf (default_key, sizeof default_key, "%s", canon);
    }

  char *p = rest;
  while (p)
    {
      char *next = strchr (p, ',');
      if (next) *next++ = '\0';
      if (!*p || s->nprimaries >= BDA_SLAVE_PRIMARY_MAX) return -1;
      char host[BDA_HOST_MAX], key[256];
      int port = 53, stealth = 0;
      if (bda_parse_primary_token (p, default_key, host, sizeof host,
                                   &port, key, sizeof key, &stealth) < 0 ||
          bda_slave_add_primary (s, host, port, key, stealth) < 0)
        return -1;
      p = next;
    }
  return s->nprimaries > 0 ? 0 : -1;
}

static const struct bda_primary *
bda_slave_current_primary (const struct bda_slave *s)
{
  if (!s || s->nprimaries <= 0) return NULL;
  int idx = (s->cur_primary >= 0 && s->cur_primary < s->nprimaries)
            ? s->cur_primary : 0;
  return &s->primaries[idx];
}

static void
bda_primary_endpoint (const struct bda_primary *p, char *buf, size_t bufsz)
{
  if (!buf || bufsz == 0) return;
  if (!p)
    snprintf (buf, bufsz, "none");
  else if (strchr (p->host, ':'))
    snprintf (buf, bufsz, "[%s]:%d", p->host, p->port);
  else
    snprintf (buf, bufsz, "%s:%d", p->host, p->port);
}

static int
bda_txt_first (const bd_rr_t *r, char *out, size_t out_sz)
{
  if (!r || !out || out_sz == 0 || r->type != BDA_TXT || r->rdata_len < 1)
    return -1;
  unsigned int n = r->rdata[0];
  if (1U + n > r->rdata_len) return -1;
  if ((size_t) n >= out_sz) n = (unsigned int) out_sz - 1;
  memcpy (out, r->rdata + 1, n);
  out[n] = '\0';
  return 0;
}

static int
bda_catalog_version_owner (const char *apex, char *out, size_t out_sz)
{
  if (!apex || !out || out_sz == 0) return -1;
  int n = (!strcmp (apex, "."))
          ? snprintf (out, out_sz, "version")
          : snprintf (out, out_sz, "version.%s", apex);
  return (n > 0 && (size_t) n < out_sz) ? 0 : -1;
}

static int
bda_catalog_member_id_owner (const char *owner, const char *apex,
                             char *id, size_t id_sz)
{
  if (!owner || !apex || !id || id_sz == 0) return -1;
  char suffix[300];
  int n = (!strcmp (apex, "."))
          ? snprintf (suffix, sizeof suffix, ".zones")
          : snprintf (suffix, sizeof suffix, ".zones.%s", apex);
  if (n <= 0 || (size_t) n >= sizeof suffix) return -1;
  size_t ol = strlen (owner), sl = strlen (suffix);
  if (ol <= sl || strcmp (owner + ol - sl, suffix)) return -1;
  size_t il = ol - sl;
  if (il == 0 || il >= id_sz) return -1;
  for (size_t i = 0; i < il; i++)
    if (owner[i] == '.')
      return -1;
  memcpy (id, owner, il);
  id[il] = '\0';
  return 0;
}

static int
bda_catalog_group_id_owner (const char *owner, const char *apex,
                            char *id, size_t id_sz)
{
  if (!owner || strncmp (owner, "group.", 6)) return -1;
  return bda_catalog_member_id_owner (owner + 6, apex, id, id_sz);
}

static int
bda_catalog_find_member_id (const struct bda_catalog *cat, const char *id)
{
  for (int i = 0; i < cat->n; i++)
    if (!strcmp (cat->members[i].id, id))
      return i;
  return -1;
}

static int
bda_catalog_find_member_apex (const struct bda_catalog *cat, const char *apex)
{
  for (int i = 0; i < cat->n; i++)
    if (!strcmp (cat->members[i].apex, apex))
      return i;
  return -1;
}

static int
bda_catalog_member_group_ok (const struct bda_catalog_member *m,
                             const char *group)
{
  return !group || !*group || (m && !strcmp (m->group, group));
}

static int
bda_catalog_parse (const struct bda_zone *cat, struct bda_catalog *out)
{
  if (!cat || !out) return -1;
  memset (out, 0, sizeof *out);
  snprintf (out->apex, sizeof out->apex, "%s", cat->apex);
  snprintf (out->version, sizeof out->version, "missing");

  char version_owner[300];
  if (bda_catalog_version_owner (cat->apex, version_owner, sizeof version_owner) < 0)
    return -1;

  for (int i = 0; i < cat->n; i++)
    {
      if (cat->rr[i].type != BDA_TXT) continue;
      char owner[256];
      bda_owner (cat, i, owner, sizeof owner);
      if (strcmp (owner, version_owner)) continue;
      char txt[64];
      if (bda_txt_first (&cat->rr[i], txt, sizeof txt) == 0)
        {
          snprintf (out->version, sizeof out->version, "%s", txt);
          if (!strcmp (txt, "2")) out->version_ok = 1;
        }
      break;
    }

  if (!out->version_ok)
    return 0;

  for (int i = 0; i < cat->n; i++)
    {
      if (cat->rr[i].type != BDA_PTR) continue;
      char owner[256], id[256];
      bda_owner (cat, i, owner, sizeof owner);
      if (bda_catalog_member_id_owner (owner, cat->apex, id, sizeof id) < 0)
        continue;

      char target[256];
      size_t off = 0;
      if (bd_decode_name (cat->rr[i].rdata, cat->rr[i].rdata_len, &off,
                          target, sizeof target, 0) < 0 ||
          off != cat->rr[i].rdata_len ||
          bd_canon_owner (target, target, sizeof target) < 0)
        { out->rejected++; continue; }
      bda_norm (target);
      unsigned char wire[256];
      if (target[0] == '\0' || (target[0] == '.' && target[1] == '\0') ||
          !strcmp (target, cat->apex) ||
          bd_name_to_wire (target, wire, sizeof wire) < 0 ||
          bda_catalog_find_member_id (out, id) >= 0 ||
          bda_catalog_find_member_apex (out, target) >= 0)
        { out->rejected++; continue; }
      if (out->n >= BDA_SLAVE_MAX)
        { out->rejected++; continue; }

      struct bda_catalog_member *m = &out->members[out->n++];
      snprintf (m->apex, sizeof m->apex, "%s", target);
      snprintf (m->id, sizeof m->id, "%s", id);
    }

  for (int i = 0; i < cat->n; i++)
    {
      if (cat->rr[i].type != BDA_TXT) continue;
      char owner[256], id[256], txt[64];
      bda_owner (cat, i, owner, sizeof owner);
      if (bda_catalog_group_id_owner (owner, cat->apex, id, sizeof id) < 0)
        continue;
      int mi = bda_catalog_find_member_id (out, id);
      if (mi < 0) continue;
      if (bda_txt_first (&cat->rr[i], txt, sizeof txt) == 0)
        snprintf (out->members[mi].group, sizeof out->members[mi].group, "%s", txt);
    }

  return 0;
}

static int
bda_zone_array_remove (struct bda_zone *zones, int *nz, int zi,
                       struct bda_slave *slaves, int nslaves)
{
  if (!zones || !nz || zi < 0 || zi >= *nz) return -1;
  bda_zone_free_one (&zones[zi]);
  for (int i = zi; i < *nz - 1; i++)
    zones[i] = zones[i + 1];
  memset (&zones[*nz - 1], 0, sizeof zones[*nz - 1]);
  (*nz)--;
  for (int i = 0; i < nslaves; i++)
    {
      if (slaves[i].zone_index == zi) slaves[i].zone_index = -1;
      else if (slaves[i].zone_index > zi) slaves[i].zone_index--;
    }
  return 0;
}

static int
bda_catalog_slave_index_apex (const struct bda_slave *slaves, int nslaves,
                              const char *apex)
{
  for (int i = 0; i < nslaves; i++)
    if (!strcmp (slaves[i].apex, apex))
      return i;
  return -1;
}

static int
bda_parse_catalog_primary (const char *spec, char *host, size_t host_sz, int *port)
{
  if (!spec || !*spec) return -1;
  return bd_split_host_port_default (spec, host, host_sz, port, 53);
}

static int
bda_catalog_reconcile (const struct bda_catalog *cat,
                       struct bda_slave *slaves, int *nslaves,
                       const char *def_primary, const char *def_key,
                       const char *group,
                       struct bda_zone *zones, int *nz,
                       bd_tsig_store_t *tsig_store,
                       struct bda_catalog_stats *stats, FILE *report)
{
  (void) tsig_store;
  if (!cat || !slaves || !nslaves || !zones || !nz) return -1;
  struct bda_catalog_stats local_stats;
  memset (&local_stats, 0, sizeof local_stats);

  for (int si = 0; si < *nslaves; )
    {
      if (!slaves[si].from_catalog)
        { si++; continue; }
      int mi = bda_catalog_find_member_id (cat, slaves[si].cat_id);
      if (mi >= 0 && bda_catalog_member_group_ok (&cat->members[mi], group))
        { si++; continue; }

      if (report)
        fprintf (report, "remove=%s id=%s\n", slaves[si].apex, slaves[si].cat_id);
      if (slaves[si].zone_index >= 0)
        bda_zone_array_remove (zones, nz, slaves[si].zone_index, slaves, *nslaves);
      for (int j = si; j < *nslaves - 1; j++)
        slaves[j] = slaves[j + 1];
      memset (&slaves[*nslaves - 1], 0, sizeof slaves[*nslaves - 1]);
      (*nslaves)--;
      local_stats.removed++;
    }

  char host[BDA_HOST_MAX] = "";
  int port = 53;
  int have_primary = (def_primary && *def_primary &&
                      bda_parse_catalog_primary (def_primary, host, sizeof host, &port) == 0);

  for (int mi = 0; mi < cat->n; mi++)
    {
      const struct bda_catalog_member *m = &cat->members[mi];
      if (!bda_catalog_member_group_ok (m, group))
        {
          if (report) fprintf (report, "skip=%s id=%s reason=group\n", m->apex, m->id);
          local_stats.skipped++;
          continue;
        }
      if (bda_catalog_slave_index_apex (slaves, *nslaves, m->apex) >= 0)
        continue;
      if (!have_primary)
        {
          builtin_warning ("catalog: skipping %s: missing --catalog-default-primary", m->apex);
          if (report) fprintf (report, "skip=%s id=%s reason=no-primary\n", m->apex, m->id);
          local_stats.skipped++;
          continue;
        }
      if (*nslaves >= BDA_SLAVE_MAX || *nz + local_stats.added >= BDA_ZONE_MAX)
        {
          builtin_warning ("catalog: skipping %s: slave/zone capacity reached", m->apex);
          if (report) fprintf (report, "skip=%s id=%s reason=capacity\n", m->apex, m->id);
          local_stats.skipped++;
          continue;
        }

      struct bda_slave ns;
      if (bda_slave_init (&ns, m->apex, host, port, def_key ? def_key : "") < 0)
        {
          builtin_warning ("catalog: skipping %s: invalid slave target", m->apex);
          if (report) fprintf (report, "skip=%s id=%s reason=invalid\n", m->apex, m->id);
          local_stats.skipped++;
          continue;
        }
      ns.from_catalog = 1;
      snprintf (ns.cat_id, sizeof ns.cat_id, "%s", m->id);
      ns.last_ok = 0;
      ns.last_try = 0;
      slaves[(*nslaves)++] = ns;
      if (report)
        {
          char ep[128];
          bda_primary_endpoint (bda_slave_current_primary (&ns), ep, sizeof ep);
          fprintf (report, "add=%s id=%s primary=%s\n", ns.apex, ns.cat_id, ep);
        }
      local_stats.added++;
    }

  if (stats) *stats = local_stats;
  return 0;
}

static int
bda_find_apex_soa (struct bda_zone *z, bd_rr_t **soa)
{
  for (int i = 0; i < z->n; i++)
    {
      char o[256]; bda_owner (z, i, o, sizeof o);
      if (z->rr[i].type == BDA_SOA && !strcmp (o, z->apex))
        { *soa = &z->rr[i]; return 0; }
    }
  return -1;
}

static int
bda_build_ixfr_query (struct bda_zone *cur, uint16_t id,
                      unsigned char *out, size_t out_sz)
{
  int ql = bd_build_query (id, cur->apex, BD_T_IXFR, 0, out, out_sz);
  if (ql < 0) return -1;
  bd_rr_t *soa = NULL;
  if (bda_find_apex_soa (cur, &soa) < 0) return -1;
  size_t off = (size_t) ql;
  if (bda_put_rr (out, out_sz, &off, cur->apex, BDA_SOA, 0, soa->rdata, soa->rdata_len) < 0)
    return -1;
  out[8] = 0; out[9] = 1;
  return (int) off;
}

static int
bda_slave_read_xfr (int fd, unsigned char *stream, size_t stream_sz, size_t *stream_len)
{
  size_t off = 0;
  *stream_len = 0;
  for (;;)
    {
      unsigned char lb[2];
      if (bda_readn (fd, lb, 2) < 0) break;
      uint16_t ml = bd_rd16 (lb);
      if (ml < 12 || off + 2 + ml > stream_sz) return -1;
      stream[off++] = lb[0]; stream[off++] = lb[1];
      if (bda_readn (fd, stream + off, ml) < 0) return -1;
      off += ml;
      bd_rr_t rrs[BDA_RR_MAX + 2];
      int n = bda_collect_xfr_answers (stream, off, 1, rrs, BDA_RR_MAX + 2);
      if (n >= 2 && rrs[0].type == BDA_SOA && rrs[n - 1].type == BDA_SOA &&
          bda_rr_same_ptr (&rrs[0], &rrs[n - 1]))
        break;
    }
  *stream_len = off;
  return off > 0 ? 0 : -1;
}

static int
bda_slave_count_xfr_frames (const unsigned char *stream, size_t stream_len)
{
  size_t off = 0;
  int n = 0;
  while (off + 2 <= stream_len)
    {
      uint16_t ml = bd_rd16 (stream + off);
      off += 2;
      if (ml < 12 || off + ml > stream_len) return -1;
      off += ml;
      n++;
    }
  return off == stream_len ? n : -1;
}

static int
bda_slave_verify_xfr_chain (const unsigned char *stream, size_t stream_len,
                            bd_tsig_store_t *store, const char *keyname,
                            const unsigned char *query_mac, size_t query_mac_len,
                            unsigned char *out, size_t out_sz, size_t *out_len,
                            int *nmsgs)
{
  if (out_len) *out_len = 0;
  if (nmsgs) *nmsgs = 0;
  if (!stream || !store || !keyname || !*keyname || !query_mac ||
      query_mac_len == 0 || query_mac_len > BD_TSIG_MAC_MAX || !out || !out_len)
    return -BD_TSIG_FORMERR;

  bd_tsig_key_t *expected = bd_tsig_find_key (store, keyname);
  if (!expected) return -BD_TSIG_BADKEY;

  unsigned char prior[BD_TSIG_MAC_MAX];
  memcpy (prior, query_mac, query_mac_len);
  size_t prior_len = query_mac_len;
  unsigned char mac[BD_TSIG_MAC_MAX];
  size_t off = 0, oo = 0;
  int verified = 0;
  unsigned char *frame = malloc (65535);
  if (!frame) return -BD_TSIG_FORMERR;

  while (off + 2 <= stream_len)
    {
      uint16_t ml = bd_rd16 (stream + off);
      off += 2;
      if (ml < 12 || off + ml > stream_len)
        { free (frame); return -BD_TSIG_FORMERR; }
      memcpy (frame, stream + off, ml);
      off += ml;
      size_t frame_len = ml, mac_len = 0;
      bd_tsig_key_t *used = NULL;
      int vr = bd_tsig_verify (frame, &frame_len, store, 1,
                               (uint64_t) bd_tsig_now (),
                               prior_len ? prior : NULL, prior_len,
                               &used, mac, &mac_len);
      if (vr != BD_TSIG_OK)
        { free (frame); return -vr; }
      if (used != expected)
        { free (frame); return -BD_TSIG_BADKEY; }
      if (mac_len == 0 || mac_len > sizeof prior || oo + 2 + frame_len > out_sz)
        { free (frame); return -BD_TSIG_FORMERR; }
      out[oo++] = (unsigned char) (frame_len >> 8);
      out[oo++] = (unsigned char) frame_len;
      memcpy (out + oo, frame, frame_len);
      oo += frame_len;
      memcpy (prior, mac, mac_len);
      prior_len = mac_len;
      verified++;
      if (nmsgs) *nmsgs = verified;
    }
  free (frame);
  if (off != stream_len || verified == 0) return -BD_TSIG_FORMERR;
  *out_len = oo;
  return 0;
}

static int
bda_slave_backoff_cap (const struct bda_slave *s)
{
  unsigned cap = s && s->retry ? s->retry : 300;
  if (cap > 300) cap = 300;
  if (s && s->expire && cap > s->expire) cap = s->expire;
  return cap ? cap : 1;
}

static void
bda_slave_mark_primary_failed (struct bda_slave *s, int idx, time_t now)
{
  if (!s || idx < 0 || idx >= s->nprimaries) return;
  struct bda_primary *p = &s->primaries[idx];
  unsigned cap = bda_slave_backoff_cap (s);
  unsigned next = p->backoff ? p->backoff * 2U : 1U;
  if (next < p->backoff || next > cap) next = cap;
  p->backoff = next;
  p->fail_until = now + (time_t) next;
}

static int
bda_slave_pick_primary (const struct bda_slave *s, time_t now, int after)
{
  if (!s || s->nprimaries <= 0) return -1;
  int start = after + 1;
  if (start < 0 || start >= s->nprimaries) start = 0;
  for (int i = start; i < s->nprimaries; i++)
    if (s->primaries[i].fail_until <= now)
      return i;
  for (int i = 0; i < start; i++)
    if (s->primaries[i].fail_until <= now)
      return i;
  return -1;
}

static int
bda_slave_pick_soonest_primary (const struct bda_slave *s, const int *attempted)
{
  int best = -1;
  if (!s || s->nprimaries <= 0) return -1;
  for (int i = 0; i < s->nprimaries; i++)
    {
      if (attempted && attempted[i]) continue;
      if (best < 0 || s->primaries[i].fail_until < s->primaries[best].fail_until)
        best = i;
    }
  return best;
}

static int
bda_slave_transfer_from_primary (struct bda_slave *s, const struct bda_primary *p,
                                 struct bda_zone *cur, bd_tsig_store_t *tsig_store,
                                 struct bda_zone *newz)
{
  unsigned char q[4096];
  uint16_t id = (uint16_t) (getpid () ^ time (NULL) ^ p->port);
  int ql = cur ? bda_build_ixfr_query (cur, id, q, sizeof q)
               : bd_build_query (id, s->apex, BD_T_AXFR, 0, q, sizeof q);
  if (ql < 0) return -1;
  bd_tsig_key_t *key = NULL;
  unsigned char qmac[BD_TSIG_MAC_MAX];
  size_t qmac_len = 0;
  if (p->keyname[0])
    {
      key = bd_tsig_find_key (tsig_store, p->keyname);
      if (!key) return -1;
    }
  if (key)
    {
      size_t qsz = (size_t) ql;
      if (bd_tsig_sign (q, sizeof q, &qsz, key, NULL, 0,
                        (uint64_t) bd_tsig_now (), BD_TSIG_DEFAULT_FUDGE,
                        qmac, &qmac_len) < 0)
        return -1;
      ql = (int) qsz;
      if (qmac_len == 0 || qmac_len > sizeof qmac) return -1;
    }

  struct sockaddr_storage sa;
  socklen_t sl = 0;
  if (bd_make_sockaddr (p->host, p->port, &sa, &sl) < 0)
    return -1;
  int fd = socket (bd_sock_family (&sa), SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  struct timeval tv = { 3, 0 };
  setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
  if (connect (fd, (struct sockaddr *) &sa, sl) < 0)
    { close (fd); return -1; }
  unsigned char lb[2] = { (unsigned char) (ql >> 8), (unsigned char) ql };
  if (bda_writen (fd, lb, 2) < 0 || bda_writen (fd, q, (size_t) ql) < 0)
    { close (fd); return -1; }
  unsigned char *stream = malloc (1024 * 1024);
  if (!stream) { close (fd); return -1; }
  size_t stream_len = 0;
  int rr = bda_slave_read_xfr (fd, stream, 1024 * 1024, &stream_len);
  close (fd);
  if (rr < 0) { free (stream); return -1; }

  unsigned char *apply_stream = stream;
  size_t apply_len = stream_len;
  unsigned char *verified_stream = NULL;
  if (key)
    {
      verified_stream = malloc (stream_len);
      if (!verified_stream) { free (stream); return -1; }
      int verified_msgs = 0;
      int vr = bda_slave_verify_xfr_chain (stream, stream_len, tsig_store,
                                           p->keyname, qmac, qmac_len,
                                           verified_stream, stream_len,
                                           &apply_len, &verified_msgs);
      if (vr < 0)
        { free (verified_stream); free (stream); return -1; }
      apply_stream = verified_stream;
    }

  int ar = -1;
  if (cur)
    {
      struct bda_zone work;
      if (bda_zone_clone (cur, &work) == 0)
        {
          ar = bda_apply_ixfr_stream (apply_stream, apply_len, 1, &work);
          if (ar == 0) *newz = work;
          else bda_zone_free_one (&work);
        }
    }
  if (ar < 0)
    ar = bda_apply_axfr_stream (apply_stream, apply_len, 1, newz);
  free (verified_stream);
  free (stream);
  if (ar == 0 && strcmp (newz->apex, s->apex))
    {
      bda_zone_free_one (newz);
      return -1;
    }
  return ar;
}

static int
bda_soa_rdata_serial (const unsigned char *rd, size_t rl, uint32_t *serial_out)
{
  size_t p = 0;
  if (!rd || !serial_out) return -1;
  for (int names = 0; names < 2 && p < rl; names++)
    { while (p < rl && rd[p] != 0) p += rd[p] + 1; if (p < rl) p++; }
  if (p + 20 > rl) return -1;
  *serial_out = bd_rd32 (rd + p);
  return 0;
}

static int
bda_primary_soa_serial (const struct bda_slave *s, const struct bda_primary *p,
                        bd_tsig_store_t *tsig_store, uint32_t *serial_out)
{
  if (!s || !p || !serial_out) return -1;
  unsigned char q[4096], reply[8192];
  uint16_t id = (uint16_t) (getpid () ^ time (NULL) ^ p->port ^ 0x5a5a);
  int ql = bd_build_query (id, s->apex, BD_T_SOA, 0, q, sizeof q);
  if (ql < 0) return -1;

  bd_tsig_key_t *key = NULL;
  if (p->keyname[0])
    {
      key = bd_tsig_find_key (tsig_store, p->keyname);
      if (!key) return -1;
      size_t qsz = (size_t) ql;
      if (bd_tsig_sign (q, sizeof q, &qsz, key, NULL, 0,
                        (uint64_t) bd_tsig_now (), BD_TSIG_DEFAULT_FUDGE,
                        NULL, NULL) < 0)
        return -1;
      ql = (int) qsz;
    }

  struct sockaddr_storage sa;
  socklen_t sl = 0;
  if (bd_make_sockaddr (p->host, p->port, &sa, &sl) < 0) return -1;
  int fd = socket (bd_sock_family (&sa), SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  struct timeval tv = { 3, 0 };
  setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
  ssize_t wn = sendto (fd, q, (size_t) ql, 0, (struct sockaddr *) &sa, sl);
  if (wn < 0) { close (fd); return -1; }
  ssize_t rn = recvfrom (fd, reply, sizeof reply, 0, NULL, NULL);
  close (fd);
  if (rn < 12) return -1;
  size_t rlen = (size_t) rn;
  if (bd_rd16 (reply) != id || (reply[3] & 0x0f) != 0) return -1;

  if (key)
    {
      bd_tsig_key_t *resp_key = NULL;
      int vr = bd_tsig_verify (reply, &rlen, tsig_store, 1,
                               (uint64_t) bd_tsig_now (), NULL, 0,
                               &resp_key, NULL, NULL);
      if (vr != BD_TSIG_OK || resp_key != key) return -1;
    }

  bd_rr_t rrs[8];
  int n = bd_collect_rrset (reply, rlen, s->apex, BD_T_SOA, rrs, 8);
  if (n <= 0) return -1;
  for (int i = 0; i < n; i++)
    if (rrs[i].type == BD_T_SOA && strcmp (rrs[i].owner, s->apex) == 0 &&
        bda_soa_rdata_serial (rrs[i].rdata, rrs[i].rdata_len, serial_out) == 0)
      return 0;
  return -1;
}

static int
bda_slave_transfer_once (struct bda_slave *s, struct bda_zone *cur,
                         bd_tsig_store_t *tsig_store, struct bda_zone *newz)
{
  if (!s || s->nprimaries <= 0) return -1;
  time_t now = time (NULL);
  int attempted[BDA_SLAVE_PRIMARY_MAX];
  memset (attempted, 0, sizeof attempted);
  int after = -1;

  for (int tries = 0; tries < s->nprimaries; tries++)
    {
      int idx = bda_slave_pick_primary (s, now, after);
      if (idx < 0)
        idx = bda_slave_pick_soonest_primary (s, attempted);
      if (idx < 0 || attempted[idx])
        {
          idx = -1;
          for (int i = 0; i < s->nprimaries; i++)
            if (!attempted[i]) { idx = i; break; }
          if (idx < 0) break;
        }
      attempted[idx] = 1;
      after = idx;
      if (bda_slave_transfer_from_primary (s, &s->primaries[idx], cur, tsig_store, newz) == 0)
        {
          s->cur_primary = idx;
          s->primaries[idx].fail_until = 0;
          s->primaries[idx].backoff = 0;
          return 0;
        }
      if (s->nprimaries > 1)
        s->failovers++;
      bda_slave_mark_primary_failed (s, idx, now);
    }
  return -1;
}

static int
bda_slave_refresh (struct bda_slave *s, struct bda_zone *zones, int *nz,
                   bd_tsig_store_t *tsig_store, const char *slave_dir)
{
  s->last_try = time (NULL);
  struct bda_zone *cur = (s->zone_index >= 0 && s->zone_index < *nz) ? &zones[s->zone_index] : NULL;
  if (!s->force && s->last_ok > 0 && s->serial != 0)
    {
      const struct bda_primary *p = bda_slave_current_primary (s);
      uint32_t polled = 0;
      if (p && bda_primary_soa_serial (s, p, tsig_store, &polled) == 0 &&
          !bd_serial_newer (polled, s->serial))
        {
          s->last_ok = time (NULL);
          s->expired = 0;
          return 0;
        }
    }
  struct bda_zone nzn;
  if (bda_slave_transfer_once (s, cur, tsig_store, &nzn) < 0)
    return -1;
  if (strcmp (nzn.apex, s->apex))
    { bda_zone_free_one (&nzn); return -1; }
  uint32_t serial = 0, refresh = 0, retry = 0, expire = 0;
  if (bda_soa_fields (&nzn, &serial, &refresh, &retry, &expire, NULL) < 0)
    { bda_zone_free_one (&nzn); return -1; }

  /* Write-on-refresh is OPT-IN: only persist when a store directory is
     configured.  RAM-only (slave_dir empty/NULL) keeps the transferred zone in
     memory only, byte-identical to a cold boot today, and writes nothing. */
  if (slave_dir && *slave_dir)
    {
      char slave_path[512];
      if (bda_slave_file_path (slave_dir, s->apex, slave_path, sizeof slave_path) == 0)
        {
          snprintf (nzn.path, sizeof nzn.path, "%s", slave_path);
          nzn.origin[0] = '\0';
          /* Atomic: bda_write_zone_file() writes a mkstemp tmp then rename(2)s
             over <store>/<apex>.zone; the serialized SOA carries the serial. */
          if (bda_write_zone_file (&nzn, slave_path) < 0)
            builtin_warning ("auth-serve: writing slave zone %s to %s failed: %s",
                             s->apex, slave_path, strerror (errno));
        }
      else
        builtin_warning ("auth-serve: cannot derive slave zone file path for %s", s->apex);
    }

  if (cur)
    {
      bda_journal_record (cur, &nzn);
      bda_zone_free_one (cur);
      zones[s->zone_index] = nzn;
    }
  else
    {
      if (*nz >= BDA_ZONE_MAX) { bda_zone_free_one (&nzn); return -1; }
      s->zone_index = *nz;
      zones[(*nz)++] = nzn;
    }
  s->serial = serial;
  s->refresh = refresh ? refresh : 3600;
  s->retry = retry ? retry : 300;
  s->expire = expire ? expire : 86400;
  s->last_ok = time (NULL);
  s->force = 0;
  s->expired = 0;
  return 0;
}

static int
bda_slave_warm_start (struct bda_slave *s, struct bda_zone *zones, int *nz,
                      const char *slave_dir)
{
  if (*nz >= BDA_ZONE_MAX) return -1;
  /* No store configured (RAM-only default) => nothing to warm-start, and this
     is not a failure: return 0 so the caller does not log a spurious warning. */
  if (!slave_dir || !*slave_dir) return 0;
  char path[512];
  if (bda_slave_file_path (slave_dir, s->apex, path, sizeof path) < 0)
    return -1;
  struct stat st;
  if (stat (path, &st) < 0)
    return 0;

  struct bda_zone nzn;
  if (bda_load_zone_signed (&nzn, path, NULL, NULL, 0) < 0)
    return -1;
  if (strcmp (nzn.apex, s->apex))
    { bda_zone_free_one (&nzn); return -1; }

  uint32_t serial = 0, refresh = 0, retry = 0, expire = 0;
  if (bda_soa_fields (&nzn, &serial, &refresh, &retry, &expire, NULL) < 0)
    { bda_zone_free_one (&nzn); return -1; }

  s->zone_index = *nz;
  zones[(*nz)++] = nzn;
  s->serial = serial;
  s->refresh = refresh ? refresh : 3600;
  s->retry = retry ? retry : 300;
  s->expire = expire ? expire : 86400;
  s->last_ok = st.st_mtime;
  s->last_try = st.st_mtime;
  s->force = 0;
  s->expired = (time (NULL) - s->last_ok >= (time_t) s->expire) ? 1 : 0;
  return 1;
}

static int
bda_slave_for_zone (struct bda_slave *slaves, int nslaves, const char *qname)
{
  for (int i = 0; i < nslaves; i++)
    if (!strcmp (slaves[i].apex, qname)) return i;
  return -1;
}

static int
bda_slave_zone_expired (struct bda_slave *slaves, int nslaves, int zi)
{
  for (int i = 0; i < nslaves; i++)
    if (slaves[i].zone_index == zi) return slaves[i].expired;
  return 0;
}

struct bda_catalog_runtime {
  int enabled;
  int zone_index;
  int reload_secs;
  int reload_user_set;
  time_t next_reload;
  char apex[256];
  char path[512];
  char default_primary[128];
  char default_key[256];
  char group[64];
  struct bda_catalog parsed;
  struct bda_catalog_stats stats;
};

static int
bda_parse_catalog_zone_spec (const char *spec, struct bda_catalog_runtime *rt)
{
  if (!spec || !*spec || !rt) return -1;
  char buf[768];
  if (strlen (spec) >= sizeof buf) return -1;
  snprintf (buf, sizeof buf, "%s", spec);
  char *sep = strchr (buf, ':');
  if (!sep || sep == buf || !sep[1]) return -1;
  *sep = '\0';
  char apex[256];
  if (bd_canon_owner (buf, apex, sizeof apex) < 0) return -1;
  bda_norm (apex);
  if (apex[0] == '\0' || (apex[0] == '.' && apex[1] == '\0')) return -1;
  snprintf (rt->apex, sizeof rt->apex, "%s", apex);
  snprintf (rt->path, sizeof rt->path, "%s", sep + 1);
  rt->enabled = 1;
  rt->zone_index = -1;
  return 0;
}

static int
bda_catalog_reload_floor (int secs)
{
  if (secs <= 0) secs = 3600;
  return secs < 60 ? 60 : secs;
}

static int
bda_catalog_runtime_reload (struct bda_catalog_runtime *rt,
                            struct bda_zone *zones, int *nz,
                            struct bda_slave *slaves, int *nslaves,
                            bd_tsig_store_t *tsig_store,
                            const char *sign_key, int use_nsec3)
{
  if (!rt || !rt->enabled || !zones || !nz || !slaves || !nslaves)
    return -1;
  struct bda_zone nzn;
  bda_zone_init_empty (&nzn);
  if (bda_load_zone_signed (&nzn, rt->path, rt->apex, sign_key, use_nsec3) < 0)
    return -1;
  if (strcmp (nzn.apex, rt->apex))
    {
      bda_zone_free_one (&nzn);
      return -1;
    }

  if (rt->zone_index >= 0 && rt->zone_index < *nz)
    {
      bda_journal_record (&zones[rt->zone_index], &nzn);
      bda_zone_free_one (&zones[rt->zone_index]);
      zones[rt->zone_index] = nzn;
    }
  else
    {
      if (*nz >= BDA_ZONE_MAX)
        { bda_zone_free_one (&nzn); return -1; }
      rt->zone_index = *nz;
      zones[(*nz)++] = nzn;
    }

  uint32_t refresh = 0;
  (void) bda_soa_fields (&zones[rt->zone_index], NULL, &refresh, NULL, NULL, NULL);
  if (!rt->reload_user_set)
    rt->reload_secs = bda_catalog_reload_floor ((int) refresh);
  else
    rt->reload_secs = bda_catalog_reload_floor (rt->reload_secs);

  if (bda_catalog_parse (&zones[rt->zone_index], &rt->parsed) < 0)
    return -1;
  if (bda_catalog_reconcile (&rt->parsed, slaves, nslaves,
                             rt->default_primary[0] ? rt->default_primary : NULL,
                             rt->default_key[0] ? rt->default_key : NULL,
                             rt->group[0] ? rt->group : NULL,
                             zones, nz, tsig_store, &rt->stats, NULL) < 0)
    return -1;
  rt->next_reload = time (NULL) + rt->reload_secs;
  return 0;
}

static int
bd_parse_int_range (const char *s, int min, int max, int *out)
{
  if (!s || !*s) return -1;
  char *end = NULL;
  errno = 0;
  long v = strtol (s, &end, 10);
  if (end == s || !end || *end != '\0' || errno == ERANGE ||
      v < min || v > max)
    return -1;
  *out = (int) v;
  return 0;
}

typedef struct {
  int responses_per_second;
  int window;
  int slip;
} bda_rrl_cfg_t;

#define BDA_RRL_BUCKETS 1024
enum { BDA_RRL_SEND = 0, BDA_RRL_TRUNCATE = 1, BDA_RRL_DROP = 2 };

typedef struct {
  uint32_t        prefix;
  double          tokens;
  struct timespec last_refill;
  unsigned        slip_ctr;
  unsigned        seq;
  int             in_use;
} bda_rrl_bucket_t;

static bda_rrl_bucket_t bda_rrl_buckets[BDA_RRL_BUCKETS];
static unsigned         bda_rrl_seq = 0;

static double
bda_rrl_capacity (const bda_rrl_cfg_t *cfg)
{
  double cap = (double) cfg->responses_per_second *
               (double) (cfg->window > 0 ? cfg->window : 1);
  if (cap < 1.0) cap = 1.0;
  if (cap > 1000000.0) cap = 1000000.0;
  return cap;
}

static bda_rrl_bucket_t *
bda_rrl_bucket (uint32_t prefix, const bda_rrl_cfg_t *cfg)
{
  bda_rrl_bucket_t *empty = NULL;
  bda_rrl_bucket_t *oldest = &bda_rrl_buckets[0];
  for (int i = 0; i < BDA_RRL_BUCKETS; i++)
    {
      bda_rrl_bucket_t *b = &bda_rrl_buckets[i];
      if (b->in_use && b->prefix == prefix)
        { b->seq = ++bda_rrl_seq; return b; }
      if (!empty && !b->in_use) empty = b;
      if (!b->in_use || b->seq < oldest->seq) oldest = b;
    }

  bda_rrl_bucket_t *slot = empty ? empty : oldest;
  memset (slot, 0, sizeof *slot);
  slot->prefix = prefix;
  slot->tokens = bda_rrl_capacity (cfg);
  slot->seq = ++bda_rrl_seq;
  slot->in_use = 1;
  clock_gettime (CLOCK_MONOTONIC, &slot->last_refill);
  return slot;
}

static int
bda_rrl_decide_prefix (const bda_rrl_cfg_t *cfg, uint32_t prefix)
{
  if (!cfg || cfg->responses_per_second <= 0)
    return BDA_RRL_SEND;

  bda_rrl_bucket_t *b = bda_rrl_bucket (prefix, cfg);
  struct timespec now;
  clock_gettime (CLOCK_MONOTONIC, &now);
  double elapsed = (double) (now.tv_sec - b->last_refill.tv_sec)
                 + (double) (now.tv_nsec - b->last_refill.tv_nsec) / 1e9;
  if (elapsed > 0.0)
    {
      b->tokens += elapsed * (double) cfg->responses_per_second;
      double cap = bda_rrl_capacity (cfg);
      if (b->tokens > cap) b->tokens = cap;
      b->last_refill = now;
    }

  if (b->tokens >= 1.0)
    { b->tokens -= 1.0; return BDA_RRL_SEND; }

  b->slip_ctr++;
  if (cfg->slip > 0 && (b->slip_ctr % (unsigned) cfg->slip) == 0)
    return BDA_RRL_TRUNCATE;
  return BDA_RRL_DROP;
}

static int
bda_rrl_decide (const bda_rrl_cfg_t *cfg, struct in_addr src)
{
  return bda_rrl_decide_prefix (cfg, ntohl (src.s_addr) & 0xffffff00U);  /* IPv4 /24 */
}

static int
bda_rrl_decide_peer (const bda_rrl_cfg_t *cfg, const struct sockaddr_storage *peer)
{
  struct in_addr v4;
  if (bd_peer_v4 (peer, &v4) == 0)
    return bda_rrl_decide (cfg, v4);

  if (!cfg || cfg->responses_per_second <= 0)
    return BDA_RRL_SEND;
  if (!peer || peer->ss_family != AF_INET6)
    return bda_rrl_decide_prefix (cfg, 0);

  const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6 *) peer;
  uint32_t h = 2166136261U ^ 0x60000000U;
  for (int i = 0; i < 8; i++)      /* IPv6 /64 bucket, FNV-1a folded. */
    {
      h ^= sa6->sin6_addr.s6_addr[i];
      h *= 16777619U;
    }
  return bda_rrl_decide_prefix (cfg, h);
}

static int
bda_send_truncated_udp (int us, const unsigned char *qbuf, size_t qn,
                        const struct sockaddr *from, socklen_t fl)
{
  unsigned char tc[BDR_MSG_MAX];
  size_t qoff = 12;
  char tmp[256];
  if (bd_decode_name (qbuf, qn, &qoff, tmp, sizeof tmp, 0) < 0)
    return -1;
  qoff += 4;
  if (qoff > qn || qoff > sizeof tc)
    return -1;
  memcpy (tc, qbuf, qoff);
  tc[2] = (unsigned char) ((qbuf[2] & 0x01) | 0x86);  /* QR|AA|TC, preserve RD */
  tc[3] = 0x00;
  tc[6] = tc[7] = tc[8] = tc[9] = tc[10] = tc[11] = 0;
  ssize_t sn = sendto (us, tc, qoff, 0, from, fl);
  return sn == (ssize_t) qoff ? 0 : -1;
}

static int
bda_notify_ack (const unsigned char *q, size_t qlen, unsigned char *resp, size_t rsz)
{
  size_t qoff = 12; char tmp[256];
  if (bd_decode_name (q, qlen, &qoff, tmp, sizeof tmp, 0) < 0) return -1;
  qoff += 4;
  if (qoff > qlen || qoff > rsz) return -1;
  memcpy (resp, q, qoff);
  resp[2] = 0xa4; resp[3] = 0x00;
  resp[6] = resp[7] = resp[8] = resp[9] = resp[10] = resp[11] = 0;
  return (int) qoff;
}

static int
bd_auth_serve_cmd (WORD_LIST *args)
{
  const char *bind_addr = NULL, *origin = NULL, *zones_dir = NULL;
  const char *control = NULL;                    /* rndc-shaped UNIX control socket */
  const char *sign_key = NULL; int use_nsec3 = 0; /* DNS-6.3 online inline signing */
  const char *tls_cert = NULL, *tls_key = NULL;
  const char *doh_cert = NULL, *doh_key = NULL, *doh_path = "/dns-query";
  const char *doq_cert = NULL, *doq_key = NULL;
  char tls_addr[64] = "127.0.0.1", doh_addr[64] = "127.0.0.1", doq_addr[64] = "127.0.0.1";
  int tls_port = 0, doh_port = 0, doq_port = 0;
  char zpaths[BDA_ZONE_MAX][512]; int nzp = 0;   /* explicit --zone FILEs */
  static struct bda_view views[BDA_VIEW_MAX]; int nviews = 0;     /* split-horizon (default-off) */
  char view_specs[BDA_VIEW_MAX][1024]; int nview_specs = 0;       /* deferred parse: load after origin */
  static struct bda_rpz rpz[BDA_RPZ_MAX]; int nrpz = 0;          /* RPZ policy zones (default-off) */
  char rpz_paths[BDA_RPZ_MAX][512]; int nrpz_paths = 0;
  int port = 0; long max_queries = -1;
  int listen_family = AF_UNSPEC, v6only = 0;
  bda_rrl_cfg_t rrl_cfg = { 15, 5, 2 };
  char acl[BDR_ACL_MAX][64]; int nacl = 0;
  char xfer[BDR_ACL_MAX][64]; int nxfer = 0;     /* allow-transfer; empty = deny */
  char update_acl[BDR_ACL_MAX][64]; int nupdate = 0; /* allow-update; empty = deny */
  char notify_to[BDR_ACL_MAX][80]; int nnotify = 0;   /* also-notify secondaries */
  struct bda_slave slaves[BDA_SLAVE_MAX]; int nslaves = 0;
  /* Slave on-disk persistence is OPT-IN, default-OFF: when no store directory
     is configured the secondary runs RAM-only, exactly as a fresh boot does
     today (no zone file written, no warm-start load, full re-AXFR on restart).
     A store is enabled by --slave-zone-store DIR, the legacy --slave-dir DIR,
     or the BASHDNS_SLAVE_DIR environment variable; the first non-empty value
     wins.  When empty, slave_dir stays "" and every persistence call below is
     a no-op via bda_slave_file_path()'s empty-dir guard. */
  const char *slave_dir = getenv ("BASHDNS_SLAVE_DIR");
  if (slave_dir && !*slave_dir) slave_dir = NULL;
  bd_tsig_store_t tsig_store; memset (&tsig_store, 0, sizeof tsig_store);
  int require_tsig = 0;
  const char *transfer_key_name = NULL;
  struct bda_catalog_runtime catalog;
  memset (&catalog, 0, sizeof catalog);
  catalog.zone_index = -1;

  for (; args; args = args->next) {
    const char *w = args->word->word;
    if (!strcmp (w, "--zone") && args->next) { if (nzp < BDA_ZONE_MAX) { snprintf (zpaths[nzp], sizeof zpaths[nzp], "%s", args->next->word->word); nzp++; } args = args->next; }
    else if (!strcmp (w, "--zones-dir") && args->next) { zones_dir = args->next->word->word; args = args->next; }
    else if (!strcmp (w, "--view") && args->next) {
      if (nview_specs >= BDA_VIEW_MAX) { builtin_error ("auth-serve: too many --view (max %d)", BDA_VIEW_MAX); return EX_USAGE; }
      snprintf (view_specs[nview_specs], sizeof view_specs[nview_specs], "%s", args->next->word->word);
      nview_specs++; args = args->next;
    }
    else if (!strcmp (w, "--rpz") && args->next) {
      if (nrpz_paths >= BDA_RPZ_MAX) { builtin_error ("auth-serve: too many --rpz (max %d)", BDA_RPZ_MAX); return EX_USAGE; }
      snprintf (rpz_paths[nrpz_paths], sizeof rpz_paths[nrpz_paths], "%s", args->next->word->word);
      nrpz_paths++; args = args->next;
    }
    else if (!strcmp (w, "--origin") && args->next) { origin = args->next->word->word; args = args->next; }
    else if (!strcmp (w, "--listen") && args->next) { bind_addr = args->next->word->word; args = args->next; }
    else if (!strcmp (w, "--inet6")) { listen_family = AF_INET6; }
    else if (!strcmp (w, "--v6only")) { listen_family = AF_INET6; v6only = 1; }
    else if (!strcmp (w, "--port") && args->next) { port = atoi (args->next->word->word); args = args->next; }
    else if (!strcmp (w, "--max-queries") && args->next) { max_queries = atol (args->next->word->word); args = args->next; }
    else if (!strcmp (w, "--rrl-rps")) {
      if (!args->next || bd_parse_int_range (args->next->word->word, 0, 1000000, &rrl_cfg.responses_per_second) < 0)
        { builtin_error ("auth-serve: --rrl-rps needs 0..1000000"); return EX_USAGE; }
      args = args->next;
    }
    else if (!strcmp (w, "--rrl-window")) {
      if (!args->next || bd_parse_int_range (args->next->word->word, 1, 86400, &rrl_cfg.window) < 0)
        { builtin_error ("auth-serve: --rrl-window needs 1..86400"); return EX_USAGE; }
      args = args->next;
    }
    else if (!strcmp (w, "--rrl-slip")) {
      if (!args->next || bd_parse_int_range (args->next->word->word, 0, 1000000, &rrl_cfg.slip) < 0)
        { builtin_error ("auth-serve: --rrl-slip needs 0..1000000"); return EX_USAGE; }
      args = args->next;
    }
    else if (!strcmp (w, "--no-rrl")) { rrl_cfg.responses_per_second = 0; }
    else if (!strcmp (w, "--allow") && args->next) { if (nacl < BDR_ACL_MAX) { strncpy (acl[nacl], args->next->word->word, 63); acl[nacl][63] = '\0'; nacl++; } args = args->next; }
    else if (!strcmp (w, "--allow-transfer") && args->next) { if (nxfer < BDR_ACL_MAX) { strncpy (xfer[nxfer], args->next->word->word, 63); xfer[nxfer][63] = '\0'; nxfer++; } args = args->next; }
    else if (!strcmp (w, "--allow-update") && args->next) { if (nupdate < BDR_ACL_MAX) { strncpy (update_acl[nupdate], args->next->word->word, 63); update_acl[nupdate][63] = '\0'; nupdate++; } args = args->next; }
    else if (!strcmp (w, "--also-notify") && args->next) { if (nnotify < BDR_ACL_MAX) { strncpy (notify_to[nnotify], args->next->word->word, 79); notify_to[nnotify][79] = '\0'; nnotify++; } args = args->next; }
    else if (!strcmp (w, "--slave-zone") && args->next)
      { if (nslaves >= BDA_SLAVE_MAX || bda_parse_slave_zone (args->next->word->word, &slaves[nslaves]) < 0)
          { builtin_error ("auth-serve: bad --slave-zone APEX:PRIMARY[,PRIMARY...] where PRIMARY=[~]IP[:PORT][#KEYNAME]; bare IPv6 uses default port, use [v6]:PORT[#KEYNAME] for explicit IPv6 port/key"); return EX_USAGE; }
        nslaves++; args = args->next; }
    else if (!strcmp (w, "--slave-dir") && args->next)
      { slave_dir = args->next->word->word; args = args->next; }
    else if (!strcmp (w, "--slave-zone-store") && args->next)
      { /* opt-in persistence store; alias of --slave-dir, explicit and clearer.
           Naming it engages write-on-refresh + load-on-boot for slave zones. */
        slave_dir = args->next->word->word; args = args->next; }
    else if (!strcmp (w, "--catalog-zone") && args->next)
      { if (bda_parse_catalog_zone_spec (args->next->word->word, &catalog) < 0)
          { builtin_error ("auth-serve: bad --catalog-zone CAT_APEX:FILE"); return EX_USAGE; }
        args = args->next; }
    else if (!strcmp (w, "--catalog-default-primary") && args->next)
      { snprintf (catalog.default_primary, sizeof catalog.default_primary, "%s", args->next->word->word); args = args->next; }
    else if (!strcmp (w, "--catalog-default-key") && args->next)
      { snprintf (catalog.default_key, sizeof catalog.default_key, "%s", args->next->word->word); args = args->next; }
    else if (!strcmp (w, "--catalog-group") && args->next)
      { snprintf (catalog.group, sizeof catalog.group, "%s", args->next->word->word); args = args->next; }
    else if (!strcmp (w, "--catalog-reload-secs") && args->next)
      { if (bd_parse_int_range (args->next->word->word, 1, 86400, &catalog.reload_secs) < 0)
          { builtin_error ("auth-serve: --catalog-reload-secs needs 1..86400"); return EX_USAGE; }
        catalog.reload_user_set = 1; args = args->next; }
    else if (!strcmp (w, "--tsig-key") && args->next)
      { if (bd_tsig_add_inline (&tsig_store, args->next->word->word) < 0) { builtin_error ("auth-serve: bad --tsig-key"); return EX_USAGE; } args = args->next; }
    else if (!strcmp (w, "--tsig-keys") && args->next)
      { if (bd_tsig_load_keys (&tsig_store, args->next->word->word) < 0) return EXECUTION_FAILURE; args = args->next; }
    else if (!strcmp (w, "--require-tsig")) { require_tsig = 1; }
    else if (!strcmp (w, "--transfer-key") && args->next) { transfer_key_name = args->next->word->word; args = args->next; }
    else if (!strcmp (w, "--control") && args->next) { control = args->next->word->word; args = args->next; }
    else if (!strcmp (w, "--sign-key") && args->next) { sign_key = args->next->word->word; args = args->next; }
    else if (!strcmp (w, "--nsec3")) { use_nsec3 = 1; }
    else if (!strcmp (w, "--tls-listen") && args->next) {
      if (bda_parse_listen (args->next->word->word, tls_addr, sizeof tls_addr, &tls_port) < 0)
        { builtin_error ("auth-serve: --tls-listen needs ADDR:PORT"); return EX_USAGE; }
      args = args->next;
    }
    else if (!strcmp (w, "--tls-cert") && args->next) { tls_cert = args->next->word->word; args = args->next; }
    else if (!strcmp (w, "--tls-key") && args->next) { tls_key = args->next->word->word; args = args->next; }
    else if (!strcmp (w, "--doh-listen") && args->next) {
      if (bda_parse_listen (args->next->word->word, doh_addr, sizeof doh_addr, &doh_port) < 0)
        { builtin_error ("auth-serve: --doh-listen needs ADDR:PORT"); return EX_USAGE; }
      args = args->next;
    }
	    else if (!strcmp (w, "--doh-path") && args->next) { doh_path = args->next->word->word; args = args->next; }
	    else if (!strcmp (w, "--doh-cert") && args->next) { doh_cert = args->next->word->word; args = args->next; }
	    else if (!strcmp (w, "--doh-key") && args->next) { doh_key = args->next->word->word; args = args->next; }
    else if (!strcmp (w, "--doq-listen")) {
      if (!args->next)
        { builtin_error ("auth-serve: --doq-listen needs ADDR:PORT"); return EX_USAGE; }
      if (bda_parse_listen (args->next->word->word, doq_addr, sizeof doq_addr, &doq_port) < 0)
        { builtin_error ("auth-serve: --doq-listen needs ADDR:PORT"); return EX_USAGE; }
      args = args->next;
    }
	    else if (!strcmp (w, "--doq-cert") && args->next) { doq_cert = args->next->word->word; args = args->next; }
	    else if (!strcmp (w, "--doq-key") && args->next) { doq_key = args->next->word->word; args = args->next; }
	    else { builtin_error ("auth-serve: unknown option: %s", w); return EX_USAGE; }
	  }
  if (nzp == 0 && !zones_dir && nslaves == 0 && !catalog.enabled && nview_specs == 0) { builtin_error ("auth-serve: --zone FILE, --zones-dir DIR, --slave-zone SPEC, --catalog-zone CAT_APEX:FILE, or --view NAME:CIDR:DIR is required"); return EX_USAGE; }
  if (port == 0) port = bd_server_port ();
  if (!bind_addr)
    bind_addr = (listen_family == AF_INET6) ? "::1" : "127.0.0.1";
  if (tls_port > 0 && (!tls_cert || !tls_key))
    { builtin_error ("auth-serve: --tls-listen requires --tls-cert and --tls-key"); return EX_USAGE; }
  if ((doh_cert || doh_key) && (!doh_cert || !doh_key))
    { builtin_error ("auth-serve: DoH TLS needs both --doh-cert and --doh-key"); return EX_USAGE; }
  if (doq_port > 0 && !BDA_DOQ_HAVE_QUIC)
    { builtin_error ("auth-serve: DoQ requires a QUIC stack; this build has none (backend=%s selected=%s build=%s)", BDA_DOQ_BACKEND, BDA_DOQ_SELECTED_BACKEND, BDA_DOQ_BUILD_FLAG); return EX_USAGE; }
  if (doq_port > 0 && (!doq_cert || !doq_key))
    { builtin_error ("auth-serve: --doq-listen requires --doq-cert and --doq-key"); return EX_USAGE; }
  if ((doq_cert || doq_key) && (!doq_cert || !doq_key))
    { builtin_error ("auth-serve: DoQ TLS needs both --doq-cert and --doq-key"); return EX_USAGE; }
  if (require_tsig && tsig_store.n == 0)
    { builtin_error ("auth-serve: --require-tsig needs --tsig-key or --tsig-keys"); return EX_USAGE; }
  /* An empty slave_dir is now the RAM-only (no-persistence) default, not an
     error: secondaries simply re-AXFR on every restart.  Only reject a store
     that was named but is the empty string. */
  if (slave_dir && !*slave_dir)
    { builtin_error ("auth-serve: --slave-zone-store/--slave-dir must not be empty"); return EX_USAGE; }
  bd_tsig_key_t *transfer_key = NULL;
  if (transfer_key_name)
    {
      transfer_key = bd_tsig_find_key (&tsig_store, transfer_key_name);
      if (!transfer_key) { builtin_error ("auth-serve: --transfer-key not found: %s", transfer_key_name); return EX_USAGE; }
    }

  /* Build the hosted-zone set: explicit --zone files first, then every
     *.zone in --zones-dir. A zone that fails to parse is skipped with a
     warning; the daemon still starts if at least one zone loaded. */
  struct bda_zone zones[BDA_ZONE_MAX]; int nz = 0;
  for (int i = 0; i < nzp; i++) {
    if (nz >= BDA_ZONE_MAX) break;
    if (bda_load_zone_signed (&zones[nz], zpaths[i], origin, sign_key, use_nsec3) == 0) nz++;
    else builtin_warning ("auth-serve: skipping unparseable%s zone: %s", sign_key ? "/unsignable" : "", zpaths[i]);
  }
  if (zones_dir) {
    DIR *d = opendir (zones_dir);
    if (!d) builtin_warning ("auth-serve: --zones-dir %s: %s", zones_dir, strerror (errno));
    else {
      struct dirent *de;
      while ((de = readdir (d)) && nz < BDA_ZONE_MAX) {
        size_t l = strlen (de->d_name);
        if (l < 6 || strcmp (de->d_name + l - 5, ".zone")) continue;
        char fp[512]; snprintf (fp, sizeof fp, "%s/%s", zones_dir, de->d_name);
        if (bda_load_zone_signed (&zones[nz], fp, origin, sign_key, use_nsec3) == 0) nz++;
        else builtin_warning ("auth-serve: skipping unparseable%s zone: %s", sign_key ? "/unsignable" : "", fp);
      }
      closedir (d);
    }
  }
  if (catalog.enabled)
    {
      if (bda_catalog_runtime_reload (&catalog, zones, &nz, slaves, &nslaves,
                                      &tsig_store, sign_key, use_nsec3) < 0)
        {
          builtin_error ("auth-serve: failed to load --catalog-zone %s:%s",
                         catalog.apex, catalog.path);
          for (int i = 0; i < nz; i++) free (zones[i].rr);
          return EXECUTION_FAILURE;
        }
    }
  /* warm[si] != 0 marks a slave whose zone was loaded from the persistence
     store at boot (load-on-boot). bda_slave_warm_start returns 1 on a valid
     non-corrupt load (it still flags s->expired for an over-expire copy). */
  char warm[BDA_SLAVE_MAX]; memset (warm, 0, sizeof warm);
  for (int si = 0; si < nslaves; si++)
    {
      int wr = bda_slave_warm_start (&slaves[si], zones, &nz, slave_dir);
      if (wr < 0)
        builtin_warning ("auth-serve: warm-start slave zone %s from %s failed",
                         slaves[si].apex, slave_dir);
      else if (wr > 0)
        warm[si] = 1;
    }
  for (int si = 0; si < nslaves; si++)
    {
      /* Load-on-boot skips the cold full transfer: if the store copy loaded and
         is still inside its SOA refresh window (timer says idle, not expired),
         serve it as-is and let the normal SOA timer drive the next refresh --
         no transfer is attempted at boot.  An expired or refresh-due copy, or
         any zone with no usable store copy, falls through to a real transfer. */
      if (warm[si] && !slaves[si].expired)
        {
          time_t now = time (NULL);
          struct bda_slave_state st = { slaves[si].last_ok, slaves[si].last_try,
                                        slaves[si].refresh, slaves[si].retry,
                                        slaves[si].expire, slaves[si].force };
          if (bda_slave_next_action (&st, now) == BDA_SLAVE_IDLE)
            continue;
        }
      if (bda_slave_refresh (&slaves[si], zones, &nz, &tsig_store, slave_dir) < 0)
        {
          char ep[128];
          bda_primary_endpoint (bda_slave_current_primary (&slaves[si]), ep, sizeof ep);
          builtin_warning ("auth-serve: initial slave transfer failed for %s from %s",
                           slaves[si].apex, ep);
        }
    }
  /* Load split-horizon views (F02): each --view NAME:CIDR,...:DIR loads its
     own *.zone set exactly like --zones-dir. Default-off: no --view means
     nviews stays 0 and the answer path is unchanged. */
  for (int i = 0; i < nview_specs; i++) {
    if (nviews >= BDA_VIEW_MAX) break;
    char vdir[512];
    if (bda_view_parse_spec (view_specs[i], &views[nviews], vdir, sizeof vdir) < 0) {
      builtin_error ("auth-serve: bad --view NAME:CIDR[,CIDR...]:DIR: %s", view_specs[i]);
      for (int k = 0; k < nz; k++) free (zones[k].rr);
      for (int k = 0; k < nviews; k++) for (int z2 = 0; z2 < views[k].nz; z2++) free (views[k].zones[z2].rr);
      return EX_USAGE;
    }
    DIR *vd = opendir (vdir);
    if (!vd) { builtin_warning ("auth-serve: --view %s dir %s: %s", views[nviews].name, vdir, strerror (errno)); }
    else {
      struct dirent *de;
      while ((de = readdir (vd)) && views[nviews].nz < BDA_ZONE_MAX) {
        size_t l = strlen (de->d_name);
        if (l < 6 || strcmp (de->d_name + l - 5, ".zone")) continue;
        char fp[1024]; snprintf (fp, sizeof fp, "%s/%s", vdir, de->d_name);
        if (bda_load_zone_signed (&views[nviews].zones[views[nviews].nz], fp, origin, sign_key, use_nsec3) == 0)
          views[nviews].nz++;
        else builtin_warning ("auth-serve: view %s: skipping unparseable zone: %s", views[nviews].name, fp);
      }
      closedir (vd);
    }
    nviews++;
  }

  /* Load RPZ policy zones (F02): each --rpz FILE is a normal master file
     whose owner names encode triggers. Default-off. */
  for (int i = 0; i < nrpz_paths; i++) {
    if (nrpz >= BDA_RPZ_MAX) break;
    if (bda_load_zone_signed (&rpz[nrpz].z, rpz_paths[i], NULL, NULL, 0) == 0) nrpz++;
    else builtin_warning ("auth-serve: skipping unparseable --rpz: %s", rpz_paths[i]);
  }

  if (nz == 0 && nviews == 0) { builtin_error ("auth-serve: no zones loaded"); return EXECUTION_FAILURE; }

  /* Publish engines for the TLS-wrapped transports (DoH/DoT/DoQ) which reach
     bda_answer_wire without a per-call config handle. peer is NULL there in
     this slice, so split-horizon/RPZ-CLIENT-IP do not match on encrypted
     transports; RPZ QNAME triggers still apply. */
  g_auth_views = nviews > 0 ? views : NULL; g_auth_nviews = nviews;
  g_auth_rpz   = nrpz   > 0 ? rpz   : NULL; g_auth_nrpz   = nrpz;

  int us = -1, ts = -1;
  if (bd_bind_dgram_stream (bind_addr, port, listen_family, v6only, &us, &ts) < 0)
    { for (int i = 0; i < nz; i++) free (zones[i].rr); return EXECUTION_FAILURE; }
  listen (ts, 8);

  /* rndc-shaped local control socket (DNS-6.2): a UNIX stream socket that
     accepts a single text command per connection (status / stats / serial /
     reload / stop) and replies with a text line. Local-only by filesystem
     permission; no TSIG. */
  int cs = -1;
  if (control) {
    cs = socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (cs < 0) { builtin_error ("control socket: %s", strerror (errno)); close (us); close (ts); for (int i = 0; i < nz; i++) free (zones[i].rr); return EXECUTION_FAILURE; }
    struct sockaddr_un ua; memset (&ua, 0, sizeof ua); ua.sun_family = AF_UNIX;
    if (strlen (control) >= sizeof ua.sun_path) { builtin_error ("control path too long: %s", control); close (us); close (ts); close (cs); for (int i = 0; i < nz; i++) free (zones[i].rr); return EXECUTION_FAILURE; }
    strncpy (ua.sun_path, control, sizeof ua.sun_path - 1);
    unlink (control);
    if (bind (cs, (struct sockaddr *) &ua, sizeof ua) < 0) { builtin_error ("bind control %s: %s", control, strerror (errno)); close (us); close (ts); close (cs); for (int i = 0; i < nz; i++) free (zones[i].rr); return EXECUTION_FAILURE; }
    listen (cs, 4);
  }

  struct bda_tls_cfg dot_tls, doh_tls;
  if (bda_tls_cfg_init (&dot_tls, tls_cert, tls_key, "DoT", NULL) < 0)
    { close (us); close (ts); if (cs >= 0) close (cs); for (int i = 0; i < nz; i++) free (zones[i].rr); return EXECUTION_FAILURE; }
#if defined(MBEDTLS_SSL_ALPN)
  const char *const *doh_alpn = bda_doh_alpn;
#else
  const char *const *doh_alpn = NULL;
#endif
  if (bda_tls_cfg_init (&doh_tls, doh_cert, doh_key, "DoH", doh_alpn) < 0)
    { bda_tls_cfg_free (&dot_tls); close (us); close (ts); if (cs >= 0) close (cs); for (int i = 0; i < nz; i++) free (zones[i].rr); return EXECUTION_FAILURE; }

  int tls_s = -1, doh_s = -1;
  if (tls_port > 0) {
    tls_s = bda_bind_stream (tls_addr, tls_port);
    if (tls_s < 0)
      { bda_tls_cfg_free (&dot_tls); bda_tls_cfg_free (&doh_tls); close (us); close (ts); if (cs >= 0) close (cs); for (int i = 0; i < nz; i++) free (zones[i].rr); return EXECUTION_FAILURE; }
  }
  if (doh_port > 0) {
    doh_s = bda_bind_stream (doh_addr, doh_port);
    if (doh_s < 0)
      { if (tls_s >= 0) close (tls_s); bda_tls_cfg_free (&dot_tls); bda_tls_cfg_free (&doh_tls); close (us); close (ts); if (cs >= 0) close (cs); for (int i = 0; i < nz; i++) free (zones[i].rr); return EXECUTION_FAILURE; }
  }
#if BDA_DOQ_HAVE_QUIC
  struct bda_doq_srv doq_srv;
  struct bda_doq_conn doq_conns[BDA_DOQ_CONN_MAX];
  memset (doq_conns, 0, sizeof doq_conns);
  doq_srv.fd = -1;
  if (doq_port > 0 && bda_bind_doq (doq_addr, doq_port, &doq_srv, doq_cert,
                                    doq_key, doq_conns, zones, nz) < 0)
    { if (doh_s >= 0) close (doh_s); if (tls_s >= 0) close (tls_s); bda_tls_cfg_free (&dot_tls); bda_tls_cfg_free (&doh_tls); close (us); close (ts); if (cs >= 0) close (cs); for (int i = 0; i < nz; i++) free (zones[i].rr); return EXECUTION_FAILURE; }
#endif

  /* NOTIFY-out (RFC 1996): on load, tell each --also-notify secondary that
     every hosted zone is available so it polls the SOA and transfers. Carry
     each zone's apex serial; fire-and-forget so an unreachable secondary
     never stalls. */
  for (int t = 0; t < nnotify; t++) {
    char host[80]; int dport = 53;
    if (bd_split_host_port_default (notify_to[t], host, sizeof host, &dport, 53) < 0)
      continue;
    for (int zi = 0; zi < nz; zi++)
      bd_notify_send_one (zones[zi].apex, host, dport, bda_apex_serial (&zones[zi]), 1000, 0, 0,
                          &tsig_store, transfer_key ? transfer_key : (tsig_store.n > 0 ? &tsig_store.keys[0] : NULL));
  }

  long queries = 0, denied = 0, xfers = 0, reloads = 0, slave_refreshes = 0;
  long rrl_dropped = 0, rrl_truncated = 0;
  int stop = 0;
  static unsigned char big[66000];
  while (!stop && (max_queries < 0 || queries < max_queries)) {
    fd_set rf; FD_ZERO (&rf); FD_SET (us, &rf); FD_SET (ts, &rf);
    int mx = us > ts ? us : ts;
    if (cs >= 0) { FD_SET (cs, &rf); if (cs > mx) mx = cs; }
    if (tls_s >= 0) { FD_SET (tls_s, &rf); if (tls_s > mx) mx = tls_s; }
    if (doh_s >= 0) { FD_SET (doh_s, &rf); if (doh_s > mx) mx = doh_s; }
#if BDA_DOQ_HAVE_QUIC
    if (doq_port > 0 && doq_srv.fd >= 0) { FD_SET (doq_srv.fd, &rf); if (doq_srv.fd > mx) mx = doq_srv.fd; }
#endif
    struct timeval slave_tv = { 1, 0 };
    int sr = select (mx + 1, &rf, NULL, NULL, (nslaves > 0 || catalog.enabled) ? &slave_tv : NULL);
    if (sr < 0) { if (errno == EINTR) continue; break; }

    time_t now = time (NULL);
    if (catalog.enabled && catalog.next_reload > 0 && now >= catalog.next_reload)
      {
        if (bda_catalog_runtime_reload (&catalog, zones, &nz, slaves, &nslaves,
                                        &tsig_store, sign_key, use_nsec3) < 0)
          {
            builtin_warning ("auth-serve: catalog reload failed for %s", catalog.path);
            catalog.next_reload = now + bda_catalog_reload_floor (catalog.reload_secs);
          }
      }

    if (nslaves > 0)
      {
        for (int si = 0; si < nslaves; si++)
          {
            struct bda_slave_state st = { slaves[si].last_ok, slaves[si].last_try,
                                          slaves[si].refresh, slaves[si].retry,
                                          slaves[si].expire, slaves[si].force };
            enum bda_slave_action act = bda_slave_next_action (&st, now);
            if (act == BDA_SLAVE_EXPIRED)
              slaves[si].expired = 1;
            else if (act == BDA_SLAVE_REFRESH_DUE || act == BDA_SLAVE_RETRY_DUE)
              {
                if (bda_slave_refresh (&slaves[si], zones, &nz, &tsig_store, slave_dir) == 0)
                  slave_refreshes++;
              }
          }
      }

    if (cs >= 0 && FD_ISSET (cs, &rf)) {
      int c = accept (cs, NULL, NULL);
      if (c >= 0) {
        struct timeval tv = { 2, 0 };
        setsockopt (c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        char cmd[128]; ssize_t cn = read (c, cmd, sizeof cmd - 1);
        if (cn > 0) {
          cmd[cn] = '\0';
          char *nl = strpbrk (cmd, "\r\n"); if (nl) *nl = '\0';
          char reply[4096]; int rl = 0;
          if (!strcmp (cmd, "status")) {
            for (int zi = 0; zi < nz && rl < (int) sizeof reply - 96; zi++)
              rl += snprintf (reply + rl, sizeof reply - rl, "zone %s serial %ld records %d status up\n", zones[zi].apex, bda_apex_serial (&zones[zi]), zones[zi].n);
          }
          else if (!strcmp (cmd, "stats")) {
            rl = snprintf (reply, sizeof reply, "queries %ld denied %ld xfers %ld reloads %ld slave-refreshes %ld rrl-dropped %ld rrl-truncated %ld zones %d catalog-members %d catalog-rejected %d slaves %d",
                           queries, denied, xfers, reloads, slave_refreshes,
                           rrl_dropped, rrl_truncated, nz,
                           catalog.enabled ? catalog.parsed.n : 0,
                           catalog.enabled ? catalog.parsed.rejected : 0,
                           nslaves);
            for (int si = 0; si < nslaves && rl < (int) sizeof reply - 160; si++)
              {
                char ep[128];
                bda_primary_endpoint (bda_slave_current_primary (&slaves[si]), ep, sizeof ep);
                rl += snprintf (reply + rl, sizeof reply - (size_t) rl,
                                " slave-zone=%s primary=%s failovers=%u",
                                slaves[si].apex, ep, slaves[si].failovers);
              }
            if (rl < (int) sizeof reply - 1)
              rl += snprintf (reply + rl, sizeof reply - (size_t) rl, "\n");
          }
          else if (!strcmp (cmd, "serial"))
            rl = snprintf (reply, sizeof reply, "%ld\n", bda_apex_serial (&zones[0]));
          else if (!strcmp (cmd, "reload")) {
            /* Reload every hosted zone from its source file, hot-swapping each
               on success and keeping the prior copy when a file fails. */
            int ok = 0, fail = 0;
            for (int zi = 0; zi < nz; zi++) {
              struct bda_zone nzn;
              if (bda_load_zone_signed (&nzn, zones[zi].path, zones[zi].origin[0] ? zones[zi].origin : NULL, sign_key, use_nsec3) == 0) {
                bda_journal_record (&zones[zi], &nzn);   /* diff old->new for IXFR */
                free (zones[zi].rr); zones[zi] = nzn; ok++;
              } else fail++;
            }
            reloads++;
            if (catalog.enabled &&
                bda_catalog_runtime_reload (&catalog, zones, &nz, slaves, &nslaves,
                                            &tsig_store, sign_key, use_nsec3) < 0)
              builtin_warning ("auth-serve: catalog reload failed for %s", catalog.path);
            rl = snprintf (reply, sizeof reply, "reload: zones %d reloaded %d failed %d serial %ld\n", nz, ok, fail, bda_apex_serial (&zones[0]));
          }
          else if (!strcmp (cmd, "stop") || !strcmp (cmd, "halt")) {
            stop = 1; rl = snprintf (reply, sizeof reply, "stopping\n");
          }
          else
            rl = snprintf (reply, sizeof reply, "error: unknown command: %s\n", cmd);
          if (rl > 0) { ssize_t wn = write (c, reply, (size_t) rl); (void) wn; }
        }
        close (c);
      }
    }

    if (tls_s >= 0 && FD_ISSET (tls_s, &rf)) {
      int cfd = accept (tls_s, NULL, NULL);
      if (cfd >= 0) {
        queries++;
        struct timeval tv = { 5, 0 };
        setsockopt (cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt (cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        mbedtls_ssl_context ssl;
        if (bda_tls_handshake (&dot_tls, &ssl, &cfd, "DoT") == 0) {
          struct bda_conn io = { cfd, &ssl };
          if (bda_dot_handle (&io, zones, nz, big, sizeof big) < 0)
            denied++;
          mbedtls_ssl_close_notify (&ssl);
        } else denied++;
        mbedtls_ssl_free (&ssl);
        close (cfd);
      }
    }

    if (doh_s >= 0 && FD_ISSET (doh_s, &rf)) {
      int cfd = accept (doh_s, NULL, NULL);
      if (cfd >= 0) {
        queries++;
        struct timeval tv = { 5, 0 };
        setsockopt (cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt (cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        mbedtls_ssl_context ssl;
        mbedtls_ssl_context *sslp = NULL;
        if (doh_tls.enabled) {
          if (bda_tls_handshake (&doh_tls, &ssl, &cfd, "DoH") == 0)
            sslp = &ssl;
          else
            denied++;
        }
        if (!doh_tls.enabled || sslp) {
          struct bda_conn io = { cfd, sslp };
          if (bda_doh_handle (&io, zones, nz, doh_path) < 0)
            denied++;
          if (sslp)
            mbedtls_ssl_close_notify (&ssl);
        }
        if (doh_tls.enabled)
          mbedtls_ssl_free (&ssl);
        close (cfd);
      }
    }

#if BDA_DOQ_HAVE_QUIC
    if (doq_port > 0 && doq_srv.fd >= 0 && FD_ISSET (doq_srv.fd, &rf)) {
      queries++;
      if (bda_doq_handle_packet (&doq_srv) < 0)
        denied++;
    }
#endif

    if (FD_ISSET (us, &rf)) {
      unsigned char qbuf[BDR_MSG_MAX];
      struct sockaddr_storage from; socklen_t fl = sizeof from;
      ssize_t qn = recvfrom (us, qbuf, sizeof qbuf, 0, (struct sockaddr *) &from, &fl);
      if (qn >= 12) {
        queries++;
        int allow = 1;
        if (nacl > 0) { allow = 0; for (int i = 0; i < nacl; i++) if (bdr_cidr_match_peer (&from, acl[i])) { allow = 1; break; } }
        if (!allow) denied++;
        else {
          unsigned char resp[BDR_MSG_MAX];
          char qname[256]; uint16_t qt, qc; int rl = -1;
          if (bdr_parse_question (qbuf, (size_t) qn, qname, sizeof qname, &qt, &qc) == 0) {
            bda_norm (qname);
            int opcode = (qbuf[2] >> 3) & 0x0f;
            if (opcode == 4 && qt == BDA_SOA) {
              if (catalog.enabled && !strcmp (qname, catalog.apex)) {
                rl = bda_notify_ack (qbuf, (size_t) qn, resp, sizeof resp);
                if (rl > 0) { resp[0] = qbuf[0]; resp[1] = qbuf[1]; sendto (us, resp, rl, 0, (struct sockaddr *) &from, fl); }
                if (bda_catalog_runtime_reload (&catalog, zones, &nz, slaves, &nslaves,
                                                &tsig_store, sign_key, use_nsec3) < 0)
                  builtin_warning ("auth-serve: catalog reload failed for %s", catalog.path);
                rl = -1;
              } else {
                int si = bda_slave_for_zone (slaves, nslaves, qname);
                if (si >= 0) {
                rl = bda_notify_ack (qbuf, (size_t) qn, resp, sizeof resp);
                if (rl > 0) { resp[0] = qbuf[0]; resp[1] = qbuf[1]; sendto (us, resp, rl, 0, (struct sockaddr *) &from, fl); }
                if (bda_slave_refresh (&slaves[si], zones, &nz, &tsig_store, slave_dir) == 0)
                  slave_refreshes++;
                rl = -1;
                } else {
                  rl = bda_refused (qbuf, (size_t) qn, resp, sizeof resp);
                }
              }
            } else {
              int handled = 0;
              if (nrpz > 0) {                          /* RPZ before normal answer */
                int act; bd_rr_t lrr[BDA_RPZ_LOCAL_MAX]; int nlrr = 0;
                act = bd_rpz_match (rpz, nrpz, qname, &from, lrr, &nlrr);
                int prl = bd_rpz_apply (act, lrr, nlrr, qbuf, (size_t) qn, resp, sizeof resp);
                if (prl != BD_RPZ_NO_RESPONSE) { rl = prl; handled = 1; }
              }
              if (!handled && nviews > 0) {             /* split-horizon view select */
                int vi = bda_view_select (views, nviews, &from);
                if (vi >= 0) {
                  int zi = bda_route (views[vi].zones, views[vi].nz, qname);
                  rl = (zi >= 0)
                       ? bda_answer (&views[vi].zones[zi], qbuf, (size_t) qn, resp, sizeof resp)
                       : bda_refused (qbuf, (size_t) qn, resp, sizeof resp);
                  handled = 1;
                }
              }
              if (!handled) {
                int zi = bda_route (zones, nz, qname);
                rl = (zi >= 0 && !bda_slave_zone_expired (slaves, nslaves, zi))
                     ? bda_answer (&zones[zi], qbuf, (size_t) qn, resp, sizeof resp)
                     : bda_refused (qbuf, (size_t) qn, resp, sizeof resp);
              }
            }
          }
          if (rl > 0) {
            resp[0] = qbuf[0]; resp[1] = qbuf[1];
            int rrl_action = bda_rrl_decide_peer (&rrl_cfg, &from);
            if (rrl_action == BDA_RRL_SEND)
              sendto (us, resp, rl, 0, (struct sockaddr *) &from, fl);
            else if (rrl_action == BDA_RRL_TRUNCATE) {
              if (bda_send_truncated_udp (us, qbuf, (size_t) qn, (struct sockaddr *) &from, fl) == 0)
                rrl_truncated++;
              else
                rrl_dropped++;
            } else {
              rrl_dropped++;
            }
          }
        }
      }
    }

    if (FD_ISSET (ts, &rf)) {
      struct sockaddr_storage cl; socklen_t cll = sizeof cl;
      int c = accept (ts, (struct sockaddr *) &cl, &cll);
      if (c >= 0) {
        queries++;
        struct timeval tv = { 5, 0 };
        setsockopt (c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        unsigned char lb[2];
        if (bda_readn (c, lb, 2) == 0) {
          int ml = (lb[0] << 8) | lb[1];
          if (ml >= 12 && ml <= BDR_MSG_MAX) {
            unsigned char qmsg[BDR_MSG_MAX];
            if (bda_readn (c, qmsg, (size_t) ml) == 0) {
              char qn[256]; uint16_t qt, qc;
              int rl = -1;
              int opcode = (qmsg[2] >> 3) & 0x0f;
              if (opcode == 5) {                         /* RFC 2136 UPDATE */
                int uok = 0;
                for (int i = 0; i < nupdate; i++)
                  if (bdr_cidr_match_peer (&cl, update_acl[i])) { uok = 1; break; }
                size_t qmsg_len = (size_t) ml;
                bd_tsig_key_t *req_key = NULL;
                unsigned char req_mac[BD_TSIG_MAC_MAX]; size_t req_mac_len = 0;
                int tsig_rc = bd_tsig_verify (qmsg, &qmsg_len, &tsig_store,
                                              require_tsig,
                                              (uint64_t) bd_tsig_now (),
                                              NULL, 0, &req_key,
                                              req_mac, &req_mac_len);
                if (!uok) {
                  denied++;
                  rl = bd_update_response (qmsg, (size_t) ml, big, sizeof big, BD_RCODE_REFUSED);
                } else if (tsig_rc != BD_TSIG_OK) {
                  denied++;
                  rl = bd_update_response (qmsg, (size_t) ml, big, sizeof big, BD_RCODE_NOTAUTH);
                } else {
                  struct bd_update_msg parsed;
                  int parsed_ok = bd_update_parse (qmsg, qmsg_len, &parsed) == 0;
                  rl = bd_update_handle (zones, nz, qmsg, qmsg_len, big, sizeof big);
                  if (rl > 0 && (big[3] & 0x0f) == BD_RCODE_NOERROR && parsed_ok) {
                    for (int t = 0; t < nnotify; t++) {
                      char host[80]; int dport = 53;
                      if (bd_split_host_port_default (notify_to[t], host, sizeof host, &dport, 53) < 0)
                        continue;
                      int zi = bda_route (zones, nz, parsed.zone);
                      if (zi >= 0)
                        bd_notify_send_one (zones[zi].apex, host, dport, bda_apex_serial (&zones[zi]), 1000, 0, 0,
                                            &tsig_store, transfer_key ? transfer_key : (tsig_store.n > 0 ? &tsig_store.keys[0] : NULL));
                    }
                  }
                }
              }
              else if (bdr_parse_question (qmsg, (size_t) ml, qn, sizeof qn, &qt, &qc) == 0) {
                bda_norm (qn);
                int zi = bda_route (zones, nz, qn);
                if (qt == BD_T_AXFR || qt == BD_T_IXFR) { /* AXFR / IXFR (TCP only) */
                  int xok = 0;
                  for (int i = 0; i < nxfer; i++) if (bdr_cidr_match_peer (&cl, xfer[i])) { xok = 1; break; }
                  bd_tsig_key_t *req_key = NULL;
                  unsigned char req_mac[BD_TSIG_MAC_MAX]; size_t req_mac_len = 0;
                  size_t qmsg_len = (size_t) ml;
                  int tsig_rc = bd_tsig_verify (qmsg, &qmsg_len, &tsig_store,
                                                require_tsig,
                                                (uint64_t) bd_tsig_now (),
                                                NULL, 0, &req_key,
                                                req_mac, &req_mac_len);
                  const bd_tsig_key_t *resp_key = req_key ? req_key : transfer_key;
                  if (tsig_rc != BD_TSIG_OK)
                    denied++;
                  else if (xok && zi >= 0) {
                    if (qt == 251) {                      /* IXFR: incremental from journal */
                      uint32_t csz = bda_ixfr_client_serial (qmsg, qmsg_len);
                      int il = (csz != 0) ? bda_build_ixfr (&zones[zi], qmsg, qmsg_len, csz, big, sizeof big) : -2;
                      if (il > 0) {                       /* journal path found -> send delta */
                        big[0] = qmsg[0]; big[1] = qmsg[1];
                        if (resp_key) {
                          size_t bl = (size_t) il;
                          if (bd_tsig_sign (big, sizeof big, &bl, resp_key,
                                            req_mac_len ? req_mac : NULL, req_mac_len,
                                            (uint64_t) bd_tsig_now (), BD_TSIG_DEFAULT_FUDGE,
                                            NULL, NULL) < 0)
                            { denied++; il = -1; }
                          else il = (int) bl;
                        }
                        if (il > 0) {
                        unsigned char ol[2] = { (unsigned char) (il >> 8), (unsigned char) il };
                        if (bda_writen (c, ol, 2) == 0) bda_writen (c, big, (size_t) il);
                        xfers++;
                        }
                      } else if (bda_send_axfr (c, &zones[zi], qmsg, qmsg_len,
                                                resp_key, req_mac_len ? req_mac : NULL,
                                                req_mac_len) == 0) xfers++;  /* fall back to AXFR */
                    } else {                              /* AXFR (possibly multi-message) */
                      if (bda_send_axfr (c, &zones[zi], qmsg, qmsg_len,
                                         resp_key, req_mac_len ? req_mac : NULL,
                                         req_mac_len) == 0) xfers++;
                    }
                  }
                  else denied++;
                  rl = -1;                                /* transfers write to c directly */
                } else {
                  int handled = 0;
                  if (nrpz > 0) {                         /* RPZ before normal answer */
                    int act; bd_rr_t lrr[BDA_RPZ_LOCAL_MAX]; int nlrr = 0;
                    act = bd_rpz_match (rpz, nrpz, qn, &cl, lrr, &nlrr);
                    int prl = bd_rpz_apply (act, lrr, nlrr, qmsg, (size_t) ml, big, sizeof big);
                    if (prl != BD_RPZ_NO_RESPONSE) { rl = prl; handled = 1; }
                  }
                  if (!handled && nviews > 0) {            /* split-horizon view select */
                    int vi = bda_view_select (views, nviews, &cl);
                    if (vi >= 0) {
                      int zv = bda_route (views[vi].zones, views[vi].nz, qn);
                      rl = (zv >= 0)
                           ? bda_answer (&views[vi].zones[zv], qmsg, (size_t) ml, big, sizeof big)
                           : bda_refused (qmsg, (size_t) ml, big, sizeof big);
                      handled = 1;
                    }
                  }
                  if (!handled)
                    rl = (zi >= 0 && !bda_slave_zone_expired (slaves, nslaves, zi))
                         ? bda_answer (&zones[zi], qmsg, (size_t) ml, big, sizeof big)
                         : bda_refused (qmsg, (size_t) ml, big, sizeof big);
                }
              }
              if (rl > 0) {
                big[0] = qmsg[0]; big[1] = qmsg[1];
                unsigned char ol[2] = { (unsigned char) (rl >> 8), (unsigned char) rl };
                if (bda_writen (c, ol, 2) == 0) bda_writen (c, big, (size_t) rl);
              }
            }
          }
        }
        close (c);
      }
    }
  }
  close (us); close (ts);
#if BDA_DOQ_HAVE_QUIC
  if (doq_port > 0) bda_doq_srv_free (&doq_srv);
#endif
  if (tls_s >= 0) close (tls_s);
  if (doh_s >= 0) close (doh_s);
  bda_tls_cfg_free (&dot_tls);
  bda_tls_cfg_free (&doh_tls);
  if (cs >= 0) { close (cs); if (control) unlink (control); }
  char slave_summary[1024];
  int ssn = snprintf (slave_summary, sizeof slave_summary, " slaves=%d", nslaves);
  for (int si = 0; si < nslaves && ssn >= 0 && ssn < (int) sizeof slave_summary - 160; si++)
    {
      char ep[128];
      bda_primary_endpoint (bda_slave_current_primary (&slaves[si]), ep, sizeof ep);
      ssn += snprintf (slave_summary + ssn, sizeof slave_summary - (size_t) ssn,
                       " slave-zone=%s primary=%s failovers=%u",
                       slaves[si].apex, ep, slaves[si].failovers);
    }
  fprintf (stderr, "authoritative: zones=%d apex=%s records=%d views=%d rpz=%d queries=%ld denied=%ld xfers=%ld reloads=%ld rrl-dropped=%ld rrl-truncated=%ld%s\n", nz, nz > 0 ? zones[0].apex : "-", nz > 0 ? zones[0].n : 0, nviews, nrpz, queries, denied, xfers, reloads, rrl_dropped, rrl_truncated, slave_summary);
  for (int i = 0; i < nz; i++) { bda_journal_free_all (&zones[i]); free (zones[i].rr); }
  for (int i = 0; i < nviews; i++) for (int z2 = 0; z2 < views[i].nz; z2++) free (views[i].zones[z2].rr);
  for (int i = 0; i < nrpz; i++) free (rpz[i].z.rr);
  g_auth_views = NULL; g_auth_nviews = 0; g_auth_rpz = NULL; g_auth_nrpz = 0;
  return EXECUTION_SUCCESS;
}

/* WORD_LIST builders from the bash builtin API (command.h types come via
   loadables.h); declared here so we can drive bd_rfc5011_step_cmd internally. */
extern WORD_DESC *make_word (const char *);
extern WORD_LIST *make_word_list (WORD_DESC *, WORD_LIST *);
extern void dispose_words (WORD_LIST *);

/* RFC 5011 periodic fetch loop (DNS-6.3): fetch the apex DNSKEY RRset from a
   server, optionally RRSIG-validate it against the current active anchor, then
   drive one rfc5011-step. Completes the automated trust-anchor rollover — the
   state machine (rfc5011-step) already lands the add->pending->promote->revoke
   sequence; this supplies the observed DNSKEY set each poll. Hermetic under
   BASHDNS_FIXTURE_DIR (bd_fetch reads <zone>.DNSKEY.bin). */
static int
bd_rfc5011_poll_cmd (WORD_LIST *args)
{
  const char *dir = NULL, *zone = ".", *server = NULL;
  long now = -1, holddown = -1;
  int validate = 0, timeout_ms = 2000;

  for (WORD_LIST *w = args; w; w = w->next) {
    const char *a = w->word->word;
    if (!strcmp (a, "--anchor-dir") && w->next) { dir = w->next->word->word; w = w->next; }
    else if (!strcmp (a, "--zone") && w->next) { zone = w->next->word->word; w = w->next; }
    else if ((!strcmp (a, "-s") || !strcmp (a, "--server")) && w->next) { server = w->next->word->word; w = w->next; }
    else if (!strcmp (a, "--now") && w->next) { now = atol (w->next->word->word); w = w->next; }
    else if (!strcmp (a, "--hold-down") && w->next) { holddown = atol (w->next->word->word); w = w->next; }
    else if ((!strcmp (a, "-t") || !strcmp (a, "--timeout")) && w->next) { timeout_ms = atoi (w->next->word->word); w = w->next; }
    else if (!strcmp (a, "--validate")) validate = 1;
    else { builtin_error ("rfc5011-poll: unexpected arg: %s", a); return EX_USAGE; }
  }
  if (!dir) { builtin_error ("rfc5011-poll: --anchor-dir DIR [--zone NAME] [-s SERVER] [--now EPOCH] [--hold-down S] [--validate]"); return EX_USAGE; }
  if (now < 0) now = (long) time (NULL);

  unsigned char reply[8192];
  int rlen = bd_fetch (zone, BD_T_DNSKEY, server, 1, timeout_ms, reply, sizeof reply);
  if (rlen < 12) { builtin_error ("rfc5011-poll: DNSKEY fetch for '%s' failed", zone); return EXECUTION_FAILURE; }

  bd_rr_t rrs[BD_RR_MAX];
  int rrs_n = bd_collect_rrset (reply, (size_t) rlen, zone, BD_T_DNSKEY, rrs, BD_RR_MAX);
  if (rrs_n <= 0) { builtin_error ("rfc5011-poll: no DNSKEY RRset for '%s'", zone); return EXECUTION_FAILURE; }

  if (validate) {
    char active_path[1024];
    if ((size_t) snprintf (active_path, sizeof active_path, "%s/root.anchor", dir) >= sizeof active_path)
      { builtin_error ("rfc5011-poll: anchor-dir path too long"); return EXECUTION_FAILURE; }
    bd_trust_t cur[BD_R5011_MAX]; int cur_n = 0;
    if (bd_r5011_read_anchor (active_path, cur, BD_R5011_MAX, &cur_n) < 0) return EXECUTION_FAILURE;
    if (cur_n == 0) { builtin_error ("rfc5011-poll: --validate but no active anchor in %s", active_path); return EXECUTION_FAILURE; }
    char verr[256];
    if (bd_verify_rrset (rrs, rrs_n, zone, BD_T_DNSKEY, cur, cur_n, 0, verr, sizeof verr) < 0)
      { builtin_error ("rfc5011-poll: DNSKEY RRset failed validation: %s (anchor not updated)", verr); return EXECUTION_FAILURE; }
  }

  bd_trust_t obs[BD_R5011_MAX]; int obs_n = 0;
  if (bd_install_dnskeys (rrs, rrs_n, zone, obs, &obs_n, BD_R5011_MAX) < 0 || obs_n == 0)
    { builtin_error ("rfc5011-poll: no usable DNSKEYs in the fetched set"); return EXECUTION_FAILURE; }

  char tmp[96];
  snprintf (tmp, sizeof tmp, "/tmp/dns-5011-%ld.dnskeyset", (long) getpid ());
  if (bd_r5011_write_anchor (tmp, obs, obs_n) < 0) { unlink (tmp); return EXECUTION_FAILURE; }
  fprintf (stderr, "rfc5011-poll: zone=%s fetched=%d validated=%s\n", zone, obs_n, validate ? "yes" : "no");

  char now_s[32], hd_s[32];
  snprintf (now_s, sizeof now_s, "%ld", now);
  WORD_LIST *wl = NULL;
  if (holddown >= 0) {
    snprintf (hd_s, sizeof hd_s, "%ld", holddown);
    wl = make_word_list (make_word (hd_s), wl);
    wl = make_word_list (make_word ("--hold-down"), wl);
  }
  wl = make_word_list (make_word (now_s), wl);
  wl = make_word_list (make_word ("--now"), wl);
  wl = make_word_list (make_word (tmp), wl);
  wl = make_word_list (make_word ("--dnskey-set"), wl);
  wl = make_word_list (make_word (dir), wl);
  wl = make_word_list (make_word ("--anchor-dir"), wl);
  int rc = bd_rfc5011_step_cmd (wl);
  dispose_words (wl);
  unlink (tmp);
  return rc;
}

static int
bd_hex_payload_len (const char *hex, size_t *out_len)
{
  size_t nyb = 0;
  for (const char *p = hex; p && *p; p++)
    {
      unsigned char c = (unsigned char) *p;
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
      if (bd_hexval (c) < 0) return -1;
      nyb++;
    }
  if ((nyb & 1) != 0) return -1;
  *out_len = nyb / 2;
  return 0;
}

static int
bd_doh_codec_cmd (WORD_LIST *args)
{
  if (!args)
    { builtin_error ("doh-codec needs decode|encode"); return EX_USAGE; }
  const char *op = args->word->word;
  args = args->next;

  if (strcmp (op, "decode") == 0)
    {
      if (!args || !args->next || !args->next->next || !args->next->next->next)
        {
          builtin_error ("doh-codec decode METHOD PATH CTYPE BODYHEX");
          return EX_USAGE;
        }
      const char *method = args->word->word;
      const char *path = args->next->word->word;
      const char *ctype = args->next->next->word->word;
      const char *body_hex = args->next->next->next->word->word;
      if (ctype[0] == '-' && ctype[1] == '\0') ctype = NULL;
      if (body_hex[0] == '-' && body_hex[1] == '\0') body_hex = "";

      size_t body_len = 0;
      if (bd_hex_payload_len (body_hex, &body_len) < 0)
        { puts ("status=400"); return EXECUTION_SUCCESS; }
      if (strcasecmp (method, "POST") == 0 && body_len > BD_DOH_WIRE_MAX)
        { puts ("status=413"); return EXECUTION_SUCCESS; }

      unsigned char body[BD_DOH_WIRE_MAX];
      if (body_len > 0 &&
          bd_unhex (body_hex, body, sizeof body, &body_len) < 0)
        { puts ("status=400"); return EXECUTION_SUCCESS; }

      unsigned char wire[BD_DOH_WIRE_MAX];
      size_t wire_len = 0;
      int status = bd_doh_decode_request (method, path, body, body_len,
                                          ctype, wire, sizeof wire, &wire_len);
      printf ("status=%d\n", status);
      if (status == 200)
        {
          printf ("len=%zu\n", wire_len);
          printf ("hex=");
          bd_hex (wire, wire_len);
          putchar ('\n');
        }
      return EXECUTION_SUCCESS;
    }

  if (strcmp (op, "encode") == 0)
    {
      if (!args)
        { builtin_error ("doh-codec encode WIREHEX"); return EX_USAGE; }
      const char *wire_hex = args->word->word;
      size_t wire_len = 0;
      if (bd_hex_payload_len (wire_hex, &wire_len) < 0 ||
          wire_len > BD_DOH_WIRE_MAX)
        { puts ("status=400"); return EXECUTION_SUCCESS; }

      unsigned char wire[BD_DOH_WIRE_MAX];
      if (wire_len > 0 &&
          bd_unhex (wire_hex, wire, sizeof wire, &wire_len) < 0)
        { puts ("status=400"); return EXECUTION_SUCCESS; }

      unsigned char http[BD_DOH_WIRE_MAX + 512];
      size_t http_len = 0;
      if (bd_doh_encode_response (wire, wire_len, http, sizeof http,
                                  &http_len) < 0)
        { puts ("status=500"); return EXECUTION_SUCCESS; }
      if (http_len < sizeof http) http[http_len] = '\0';

      printf ("status=200\n");
      printf ("content_type=%s\n",
              strstr ((const char *) http,
                      "Content-Type: application/dns-message\r\n") ? "application/dns-message" : "");
      printf ("content_length=%zu\n", wire_len);
      printf ("http_len=%zu\n", http_len);
      printf ("body_hex=");
      bd_hex (wire, wire_len);
      putchar ('\n');
      return EXECUTION_SUCCESS;
    }

  builtin_error ("doh-codec: unknown op: %s", op);
  return EX_USAGE;
}

static int
bd_tsig_read_hex_arg (const char *hex, unsigned char *out, size_t out_sz,
                      size_t *out_len, const char *label)
{
  if (bd_hex_payload_len (hex, out_len) < 0 || *out_len > out_sz ||
      (*out_len > 0 && bd_unhex (hex, out, out_sz, out_len) < 0))
    {
      builtin_error ("%s: bad hex", label);
      return -1;
    }
  return 0;
}

static int
bd_tsig_debug_digest_cmd (WORD_LIST *args)
{
  const char *msg_hex = NULL, *keyname = NULL, *prior_hex = NULL, *other_hex = "";
  uint64_t when = 0;
  uint16_t fudge = BD_TSIG_DEFAULT_FUDGE, error = 0;
  for (; args; args = args->next)
    {
      const char *w = args->word->word;
      if (!strcmp (w, "--msg-hex") && args->next) { msg_hex = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--key-name") && args->next) { keyname = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--time") && args->next) { when = (uint64_t) strtoull (args->next->word->word, NULL, 10); args = args->next; }
      else if (!strcmp (w, "--fudge") && args->next) { fudge = (uint16_t) atoi (args->next->word->word); args = args->next; }
      else if (!strcmp (w, "--error") && args->next) { error = (uint16_t) atoi (args->next->word->word); args = args->next; }
      else if (!strcmp (w, "--prior-mac") && args->next) { prior_hex = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--other-hex") && args->next) { other_hex = args->next->word->word; args = args->next; }
      else { builtin_error ("tsig-digest: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!msg_hex || !keyname || when == 0)
    { builtin_error ("tsig-digest --msg-hex HEX --key-name NAME --time EPOCH [--fudge N]"); return EX_USAGE; }
  unsigned char msg[70000], prior[BD_TSIG_MAC_MAX], other[256], out[70000];
  size_t msg_len = 0, prior_len = 0, other_len = 0, out_len = 0;
  if (bd_tsig_read_hex_arg (msg_hex, msg, sizeof msg, &msg_len, "tsig-digest msg") < 0 ||
      bd_tsig_read_hex_arg (other_hex, other, sizeof other, &other_len, "tsig-digest other") < 0)
    return EX_USAGE;
  if (prior_hex && bd_tsig_read_hex_arg (prior_hex, prior, sizeof prior, &prior_len, "tsig-digest prior") < 0)
    return EX_USAGE;
  if (bd_tsig_digest_input (msg, msg_len, keyname, fudge, when, error,
                            other_len ? other : NULL, other_len,
                            prior_len ? prior : NULL, prior_len,
                            out, sizeof out, &out_len) < 0)
    return EXECUTION_FAILURE;
  printf ("hex=");
  bd_hex (out, out_len);
  putchar ('\n');
  printf ("len=%zu\n", out_len);
  return EXECUTION_SUCCESS;
}

static int
bd_tsig_debug_rr_cmd (WORD_LIST *args)
{
  const char *keyname = NULL, *mac_hex = NULL, *other_hex = "";
  uint64_t when = 0;
  uint16_t fudge = BD_TSIG_DEFAULT_FUDGE, error = 0, orig_id = 0x1234;
  for (; args; args = args->next)
    {
      const char *w = args->word->word;
      if (!strcmp (w, "--key-name") && args->next) { keyname = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--mac-hex") && args->next) { mac_hex = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--time") && args->next) { when = (uint64_t) strtoull (args->next->word->word, NULL, 10); args = args->next; }
      else if (!strcmp (w, "--fudge") && args->next) { fudge = (uint16_t) atoi (args->next->word->word); args = args->next; }
      else if (!strcmp (w, "--error") && args->next) { error = (uint16_t) atoi (args->next->word->word); args = args->next; }
      else if (!strcmp (w, "--orig-id") && args->next) { orig_id = (uint16_t) strtoul (args->next->word->word, NULL, 0); args = args->next; }
      else if (!strcmp (w, "--other-hex") && args->next) { other_hex = args->next->word->word; args = args->next; }
      else { builtin_error ("tsig-rr: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!keyname || !mac_hex || when == 0)
    { builtin_error ("tsig-rr --key-name NAME --mac-hex HEX --time EPOCH [--fudge N]"); return EX_USAGE; }
  unsigned char msg[1024]; memset (msg, 0, 12);
  msg[0] = (unsigned char) (orig_id >> 8); msg[1] = (unsigned char) orig_id;
  size_t msg_len = 12, mac_len = 0, other_len = 0;
  unsigned char mac[BD_TSIG_MAC_MAX], other[64];
  if (bd_tsig_read_hex_arg (mac_hex, mac, sizeof mac, &mac_len, "tsig-rr mac") < 0 ||
      bd_tsig_read_hex_arg (other_hex, other, sizeof other, &other_len, "tsig-rr other") < 0)
    return EX_USAGE;
  if (bd_tsig_put_rr (msg, sizeof msg, &msg_len, keyname, when, fudge, orig_id,
                      error, other_len ? other : NULL, other_len, mac, mac_len) < 0)
    return EXECUTION_FAILURE;
  bd_tsig_rr_t rr;
  int fr = bd_tsig_find (msg, msg_len, &rr);
  printf ("status=%s\n", bd_tsig_status_name (fr));
  printf ("rr_hex=");
  bd_hex (msg + 12, msg_len - 12);
  putchar ('\n');
  if (fr == BD_TSIG_OK)
    {
      printf ("key=%s\nalgorithm=%s\ntime=%llu\nfudge=%u\nmac_len=%zu\nerror=%u\nother_len=%zu\n",
              rr.keyname, rr.algname, (unsigned long long) rr.time_signed,
              rr.fudge, rr.mac_len, rr.error, rr.other_len);
    }
  return EXECUTION_SUCCESS;
}

static int
bd_tsig_debug_sign_cmd (WORD_LIST *args)
{
  const char *key_spec = NULL, *msg_hex = NULL, *prior_hex = NULL;
  uint64_t when = 0;
  uint16_t fudge = BD_TSIG_DEFAULT_FUDGE;
  for (; args; args = args->next)
    {
      const char *w = args->word->word;
      if (!strcmp (w, "--key") && args->next) { key_spec = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--msg-hex") && args->next) { msg_hex = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--time") && args->next) { when = (uint64_t) strtoull (args->next->word->word, NULL, 10); args = args->next; }
      else if (!strcmp (w, "--fudge") && args->next) { fudge = (uint16_t) atoi (args->next->word->word); args = args->next; }
      else if (!strcmp (w, "--prior-mac") && args->next) { prior_hex = args->next->word->word; args = args->next; }
      else { builtin_error ("tsig-sign: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!key_spec || !msg_hex)
    { builtin_error ("tsig-sign --key NAME:hmac-sha256:B64 --msg-hex HEX [--time EPOCH]"); return EX_USAGE; }
  if (when == 0) when = (uint64_t) bd_tsig_now ();
  bd_tsig_store_t st; memset (&st, 0, sizeof st);
  if (bd_tsig_add_inline (&st, key_spec) < 0) { builtin_error ("tsig-sign: bad key"); return EX_USAGE; }
  unsigned char msg[70000], prior[BD_TSIG_MAC_MAX], mac[BD_TSIG_MAC_MAX];
  size_t msg_len = 0, prior_len = 0, mac_len = 0;
  if (bd_tsig_read_hex_arg (msg_hex, msg, sizeof msg, &msg_len, "tsig-sign msg") < 0)
    return EX_USAGE;
  if (prior_hex && bd_tsig_read_hex_arg (prior_hex, prior, sizeof prior, &prior_len, "tsig-sign prior") < 0)
    return EX_USAGE;
  if (bd_tsig_sign (msg, sizeof msg, &msg_len, &st.keys[0],
                    prior_len ? prior : NULL, prior_len, when, fudge,
                    mac, &mac_len) < 0)
    return EXECUTION_FAILURE;
  printf ("wire_hex=");
  bd_hex (msg, msg_len);
  putchar ('\n');
  printf ("mac_hex=");
  bd_hex (mac, mac_len);
  putchar ('\n');
  return EXECUTION_SUCCESS;
}

static int
bd_tsig_debug_verify_cmd (WORD_LIST *args)
{
  const char *key_spec = NULL, *msg_hex = NULL, *prior_hex = NULL;
  uint64_t now = 0;
  int require = 0;
  for (; args; args = args->next)
    {
      const char *w = args->word->word;
      if (!strcmp (w, "--key") && args->next) { key_spec = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--msg-hex") && args->next) { msg_hex = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--now") && args->next) { now = (uint64_t) strtoull (args->next->word->word, NULL, 10); args = args->next; }
      else if (!strcmp (w, "--require")) require = 1;
      else if (!strcmp (w, "--prior-mac") && args->next) { prior_hex = args->next->word->word; args = args->next; }
      else { builtin_error ("tsig-verify: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!msg_hex)
    { builtin_error ("tsig-verify --msg-hex HEX [--key NAME:hmac-sha256:B64] [--now EPOCH] [--require]"); return EX_USAGE; }
  if (now == 0) now = (uint64_t) bd_tsig_now ();
  bd_tsig_store_t st; memset (&st, 0, sizeof st);
  if (key_spec && bd_tsig_add_inline (&st, key_spec) < 0)
    { builtin_error ("tsig-verify: bad key"); return EX_USAGE; }
  unsigned char msg[70000], prior[BD_TSIG_MAC_MAX], mac[BD_TSIG_MAC_MAX];
  size_t msg_len = 0, prior_len = 0, mac_len = 0;
  if (bd_tsig_read_hex_arg (msg_hex, msg, sizeof msg, &msg_len, "tsig-verify msg") < 0)
    return EX_USAGE;
  if (prior_hex && bd_tsig_read_hex_arg (prior_hex, prior, sizeof prior, &prior_len, "tsig-verify prior") < 0)
    return EX_USAGE;
  int rc = bd_tsig_verify (msg, &msg_len, &st, require, now,
                           prior_len ? prior : NULL, prior_len,
                           NULL, mac, &mac_len);
  printf ("status=%s\n", bd_tsig_status_name (rc));
  if (rc == BD_TSIG_OK)
    {
      printf ("stripped_hex=");
      bd_hex (msg, msg_len);
      putchar ('\n');
      if (mac_len)
        {
          printf ("mac_hex=");
          bd_hex (mac, mac_len);
          putchar ('\n');
        }
    }
  return EXECUTION_SUCCESS;
}

static int
bd_slave_apply_debug_cmd (WORD_LIST *args)
{
  const char *old_path = NULL, *new_path = NULL, *origin = NULL;
  for (; args; args = args->next)
    {
      const char *w = args->word->word;
      if (!strcmp (w, "--old-zone") && args->next) { old_path = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--new-zone") && args->next) { new_path = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--origin") && args->next) { origin = args->next->word->word; args = args->next; }
      else { builtin_error ("slave-apply: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!old_path || !new_path)
    { builtin_error ("slave-apply --old-zone OLD --new-zone NEW [--origin NAME]"); return EX_USAGE; }

  struct bda_zone oldz, oldcopy, newz, axz, ixz;
  bda_zone_init_empty (&oldz); bda_zone_init_empty (&oldcopy);
  bda_zone_init_empty (&newz); bda_zone_init_empty (&axz); bda_zone_init_empty (&ixz);
  if (bda_load_into (&oldz, old_path, origin) < 0 ||
      bda_load_into (&newz, new_path, origin) < 0 ||
      bda_zone_clone (&oldz, &oldcopy) < 0)
    {
      bda_zone_free_one (&oldz); bda_zone_free_one (&oldcopy); bda_zone_free_one (&newz);
      builtin_error ("slave-apply: failed to load zones");
      return EXECUTION_FAILURE;
    }

  unsigned char q[512], wire[66000];
  int ql = bd_build_query (0x1234, newz.apex, BD_T_AXFR, 0, q, sizeof q);
  int al = ql > 0 ? bda_build_axfr (&newz, q, (size_t) ql, wire, sizeof wire) : -1;
  int aok = al > 0 ? bda_apply_axfr (wire, (size_t) al, &axz) : -1;

  bda_journal_record (&oldz, &newz);
  ql = bd_build_query (0x1235, newz.apex, BD_T_IXFR, 0, q, sizeof q);
  int il = ql > 0 ? bda_build_ixfr (&newz, q, (size_t) ql, (uint32_t) bda_apex_serial (&oldcopy), wire, sizeof wire) : -1;
  if (bda_zone_clone (&oldcopy, &ixz) < 0) il = -1;
  int iok = il > 0 ? bda_apply_ixfr (wire, (size_t) il, &ixz) : -1;

  printf ("axfr_status=%s\n", aok == 0 ? "valid" : "invalid");
  if (aok == 0)
    {
      printf ("axfr_serial=%ld\n", bda_apex_serial (&axz));
      printf ("axfr_records=%d\n", axz.n);
      printf ("axfr_equal=%d\n", bda_zone_equal_set (&axz, &newz));
    }
  printf ("ixfr_status=%s\n", iok == 0 ? "valid" : "invalid");
  if (iok == 0)
    {
      printf ("ixfr_serial=%ld\n", bda_apex_serial (&ixz));
      printf ("ixfr_records=%d\n", ixz.n);
      printf ("ixfr_equal=%d\n", bda_zone_equal_set (&ixz, &newz));
    }

  int rc = (aok == 0 && iok == 0 && bda_zone_equal_set (&axz, &newz) && bda_zone_equal_set (&ixz, &newz))
           ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  bda_zone_free_one (&oldz); bda_zone_free_one (&oldcopy); bda_zone_free_one (&newz);
  bda_zone_free_one (&axz); bda_zone_free_one (&ixz);
  return rc;
}

static void
bd_tsig_save_now_env (int *had, char *buf, size_t bufsz)
{
  const char *old = getenv ("BASHDNS_TSIG_NOW");
  *had = old != NULL;
  if (old)
    snprintf (buf, bufsz, "%s", old);
  else if (bufsz)
    buf[0] = '\0';
}

static void
bd_tsig_set_now_env (long now)
{
  char buf[64];
  snprintf (buf, sizeof buf, "%ld", now);
  setenv ("BASHDNS_TSIG_NOW", buf, 1);
}

static void
bd_tsig_restore_now_env (int had, const char *buf)
{
  if (had)
    setenv ("BASHDNS_TSIG_NOW", buf ? buf : "", 1);
  else
    unsetenv ("BASHDNS_TSIG_NOW");
}

static int
bd_tsig_stream_from_tmp (FILE *f, unsigned char **out, size_t *out_len)
{
  int fd = fileno (f);
  if (fflush (f) != 0) return -1;
  off_t end = lseek (fd, 0, SEEK_END);
  if (end < 0 || lseek (fd, 0, SEEK_SET) < 0) return -1;
  unsigned char *buf = malloc ((size_t) (end ? end : 1));
  if (!buf) return -1;
  size_t got = 0;
  while (got < (size_t) end)
    {
      ssize_t r = read (fd, buf + got, (size_t) end - got);
      if (r <= 0)
        { free (buf); return -1; }
      got += (size_t) r;
    }
  *out = buf;
  *out_len = got;
  return 0;
}

static int
bd_tsig_tamper_framed_msg (unsigned char *stream, size_t stream_len, int msgno)
{
  if (msgno <= 0) return -1;
  size_t off = 0;
  int cur = 0;
  while (off + 2 <= stream_len)
    {
      uint16_t ml = bd_rd16 (stream + off);
      off += 2;
      if (ml < 12 || off + ml > stream_len) return -1;
      cur++;
      if (cur == msgno)
        {
          stream[off + 2] ^= 0x01;       /* flags byte: still parseable, MAC-invalid. */
          return 0;
        }
      off += ml;
    }
  return -1;
}

static int
bd_slave_verify_chain_debug_cmd (WORD_LIST *args)
{
  const char *zone_path = NULL, *origin = NULL, *key_spec = NULL;
  const char *verify_key_spec = NULL;
  long now = bd_tsig_now (), skew = 0;
  int tamper_msg = 0, unsigned_response = 0;

  for (; args; args = args->next)
    {
      const char *w = args->word->word;
      if (!strcmp (w, "--help"))
        {
          puts ("slave-verify-chain --zone FILE --key NAME:hmac-sha256:B64 [--origin NAME] [--now EPOCH] [--tamper-msg N] [--skew SEC] [--verify-key SPEC] [--unsigned-response]");
          return EXECUTION_SUCCESS;
        }
      if (!strcmp (w, "--zone") && args->next) { zone_path = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--origin") && args->next) { origin = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--key") && args->next) { key_spec = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--verify-key") && args->next) { verify_key_spec = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--now") && args->next) { now = atol (args->next->word->word); args = args->next; }
      else if (!strcmp (w, "--tamper-msg") && args->next)
        {
          if (bd_parse_int_range (args->next->word->word, 1, 1000000, &tamper_msg) < 0)
            { builtin_error ("slave-verify-chain: --tamper-msg needs N"); return EX_USAGE; }
          args = args->next;
        }
      else if (!strcmp (w, "--skew") && args->next) { skew = atol (args->next->word->word); args = args->next; }
      else if (!strcmp (w, "--unsigned-response")) unsigned_response = 1;
      else { builtin_error ("slave-verify-chain: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!zone_path || !key_spec)
    { builtin_error ("slave-verify-chain --zone FILE --key NAME:hmac-sha256:B64 [--origin NAME]"); return EX_USAGE; }

  struct bda_zone z, axz;
  bda_zone_init_empty (&z);
  bda_zone_init_empty (&axz);
  bd_tsig_store_t sign_store, verify_store;
  memset (&sign_store, 0, sizeof sign_store);
  memset (&verify_store, 0, sizeof verify_store);
  unsigned char *stream = NULL, *vstream = NULL;
  size_t stream_len = 0, vlen = 0;
  int rc = EXECUTION_FAILURE, total_msgs = 0, verified_msgs = 0;
  int chain_rc = -BD_TSIG_FORMERR, zone_equal = 0;
  int had_env = 0;
  char old_env[64];
  bd_tsig_save_now_env (&had_env, old_env, sizeof old_env);

  if (bda_load_into (&z, zone_path, origin) < 0 ||
      bd_tsig_add_inline (&sign_store, key_spec) < 0 ||
      bd_tsig_add_inline (&verify_store, verify_key_spec ? verify_key_spec : key_spec) < 0)
    goto done;
  bd_tsig_key_t *sign_key = &sign_store.keys[0];

  unsigned char q[4096], qmac[BD_TSIG_MAC_MAX];
  size_t qmac_len = 0;
  int ql = bd_build_query (0x1234, z.apex, BD_T_AXFR, 0, q, sizeof q);
  if (ql < 0) goto done;
  size_t qsz = (size_t) ql;
  if (bd_tsig_sign (q, sizeof q, &qsz, sign_key, NULL, 0,
                    (uint64_t) now, BD_TSIG_DEFAULT_FUDGE,
                    qmac, &qmac_len) < 0)
    goto done;

  if (unsigned_response)
    {
      unsigned char msg[66000];
      int ml = bda_build_axfr (&z, q, qsz, msg, sizeof msg);
      if (ml < 0) goto done;
      stream = malloc ((size_t) ml + 2);
      if (!stream) goto done;
      stream[0] = (unsigned char) (ml >> 8);
      stream[1] = (unsigned char) ml;
      memcpy (stream + 2, msg, (size_t) ml);
      stream_len = (size_t) ml + 2;
    }
  else
    {
      FILE *tf = tmpfile ();
      if (!tf) goto done;
      bd_tsig_set_now_env (now);
      int sr = bda_send_axfr (fileno (tf), &z, q, qsz, sign_key, qmac, qmac_len);
      if (sr == 0)
        sr = bd_tsig_stream_from_tmp (tf, &stream, &stream_len);
      fclose (tf);
      if (sr < 0) goto done;
    }

  total_msgs = bda_slave_count_xfr_frames (stream, stream_len);
  if (total_msgs < 0) goto done;
  if (tamper_msg && bd_tsig_tamper_framed_msg (stream, stream_len, tamper_msg) < 0)
    goto done;

  vstream = malloc (stream_len ? stream_len : 1);
  if (!vstream) goto done;
  bd_tsig_set_now_env (now + skew);
  chain_rc = bda_slave_verify_xfr_chain (stream, stream_len, &verify_store,
                                         sign_key->name, qmac, qmac_len,
                                         vstream, stream_len, &vlen,
                                         &verified_msgs);
  if (chain_rc == 0 && bda_apply_axfr_stream (vstream, vlen, 1, &axz) == 0)
    zone_equal = bda_zone_equal_set (&axz, &z);

  printf ("chain_status=%s\n", chain_rc == 0 ? "valid" : bd_tsig_status_name (-chain_rc));
  printf ("messages=%d\n", total_msgs);
  printf ("verified=%d\n", verified_msgs);
  if (chain_rc == 0)
    printf ("zone_equal=%d\n", zone_equal);
  rc = EXECUTION_SUCCESS;

done:
  bd_tsig_restore_now_env (had_env, old_env);
  free (stream);
  free (vstream);
  bda_zone_free_one (&z);
  bda_zone_free_one (&axz);
  return rc;
}

static int
bd_slave_timer_debug_cmd (WORD_LIST *args)
{
  struct bda_slave_state st;
  memset (&st, 0, sizeof st);
  time_t now = time (NULL);
  for (; args; args = args->next)
    {
      const char *w = args->word->word;
      if (!strcmp (w, "--last-ok") && args->next) { st.last_ok = (time_t) atol (args->next->word->word); args = args->next; }
      else if (!strcmp (w, "--last-try") && args->next) { st.last_try = (time_t) atol (args->next->word->word); args = args->next; }
      else if (!strcmp (w, "--refresh") && args->next) { st.refresh = (uint32_t) strtoul (args->next->word->word, NULL, 10); args = args->next; }
      else if (!strcmp (w, "--retry") && args->next) { st.retry = (uint32_t) strtoul (args->next->word->word, NULL, 10); args = args->next; }
      else if (!strcmp (w, "--expire") && args->next) { st.expire = (uint32_t) strtoul (args->next->word->word, NULL, 10); args = args->next; }
      else if (!strcmp (w, "--now") && args->next) { now = (time_t) atol (args->next->word->word); args = args->next; }
      else if (!strcmp (w, "--force-notify")) st.force = 1;
      else { builtin_error ("slave-timer: unexpected arg: %s", w); return EX_USAGE; }
    }
  enum bda_slave_action act = bda_slave_next_action (&st, now);
  printf ("action=%s\n", bda_slave_action_name (act));
  return EXECUTION_SUCCESS;
}

static int
bda_parse_primary_fail_arg (const char *arg, int *idx, time_t *fail_until,
                            unsigned *backoff)
{
  char buf[128];
  if (!arg || strlen (arg) >= sizeof buf || !idx || !fail_until || !backoff)
    return -1;
  snprintf (buf, sizeof buf, "%s", arg);
  char *a = buf;
  char *b = strchr (a, ':');
  if (!b) return -1;
  *b++ = '\0';
  char *c = strchr (b, ':');
  if (!c) return -1;
  *c++ = '\0';
  char *e = NULL;
  long ni = strtol (a, &e, 10);
  if (!e || *e || ni < 0 || ni >= BDA_SLAVE_PRIMARY_MAX) return -1;
  e = NULL;
  long long nf = strtoll (b, &e, 10);
  if (!e || *e || nf < 0) return -1;
  e = NULL;
  unsigned long nb = strtoul (c, &e, 10);
  if (!e || *e || nb > 86400UL) return -1;
  *idx = (int) ni;
  *fail_until = (time_t) nf;
  *backoff = (unsigned) nb;
  return 0;
}

static int
bd_slave_primary_debug_cmd (WORD_LIST *args)
{
  const char *spec = NULL;
  const char *fail_args[BDA_SLAVE_PRIMARY_MAX];
  int nfail = 0;
  time_t now = time (NULL);
  int after = -1;
  uint32_t retry = 300, expire = 86400;
  int mark[BDA_SLAVE_PRIMARY_MAX];
  int nmark = 0;
  struct bda_slave s;
  memset (&s, 0, sizeof s);

  for (; args; args = args->next)
    {
      const char *w = args->word->word;
      if (!strcmp (w, "--spec") && args->next) { spec = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--now") && args->next) { now = (time_t) atol (args->next->word->word); args = args->next; }
      else if (!strcmp (w, "--after") && args->next) { after = atoi (args->next->word->word); args = args->next; }
      else if (!strcmp (w, "--retry") && args->next) { retry = (uint32_t) strtoul (args->next->word->word, NULL, 10); args = args->next; }
      else if (!strcmp (w, "--expire") && args->next) { expire = (uint32_t) strtoul (args->next->word->word, NULL, 10); args = args->next; }
      else if (!strcmp (w, "--fail") && args->next)
        {
          if (nfail >= BDA_SLAVE_PRIMARY_MAX) return EX_USAGE;
          fail_args[nfail++] = args->next->word->word;
          args = args->next;
        }
      else if (!strcmp (w, "--mark-fail") && args->next)
        {
          if (nmark >= BDA_SLAVE_PRIMARY_MAX) return EX_USAGE;
          mark[nmark++] = atoi (args->next->word->word);
          args = args->next;
        }
      else { builtin_error ("slave-primary: unexpected arg: %s", w); return EX_USAGE; }
    }

  if (!spec)
    { builtin_error ("slave-primary --spec APEX:PRIMARY[,PRIMARY...] [--now EPOCH] [--fail I:UNTIL:BACKOFF] [--mark-fail I]"); return EX_USAGE; }
  if (bda_parse_slave_zone (spec, &s) < 0)
    { builtin_error ("slave-primary: bad --spec"); return EX_USAGE; }
  s.retry = retry;
  s.expire = expire;

  for (int i = 0; i < nfail; i++)
    {
      int idx = -1;
      time_t fail_until = 0;
      unsigned backoff = 0;
      if (bda_parse_primary_fail_arg (fail_args[i], &idx, &fail_until, &backoff) < 0 ||
          idx >= s.nprimaries)
        { builtin_error ("slave-primary: bad --fail"); return EX_USAGE; }
      s.primaries[idx].fail_until = fail_until;
      s.primaries[idx].backoff = backoff;
    }
  for (int i = 0; i < nmark; i++)
    {
      if (mark[i] < 0 || mark[i] >= s.nprimaries)
        { builtin_error ("slave-primary: bad --mark-fail"); return EX_USAGE; }
      bda_slave_mark_primary_failed (&s, mark[i], now);
    }

  int pick = bda_slave_pick_primary (&s, now, after);
  printf ("apex=%s\n", s.apex);
  printf ("count=%d\n", s.nprimaries);
  printf ("current=%d\n", s.cur_primary < 0 ? 0 : s.cur_primary);
  printf ("pick=%d\n", pick);
  printf ("order=");
  int emitted = 0;
  for (int i = 0; i < s.nprimaries; i++)
    if (s.primaries[i].fail_until <= now)
      {
        printf ("%s%d", emitted ? "," : "", i);
        emitted = 1;
      }
  if (!emitted) printf ("none");
  putchar ('\n');

  printf ("notify-targets=");
  emitted = 0;
  for (int i = 0; i < s.nprimaries; i++)
    if (!s.primaries[i].stealth)
      {
        char ep[128];
        bda_primary_endpoint (&s.primaries[i], ep, sizeof ep);
        printf ("%s%s", emitted ? "," : "", ep);
        emitted = 1;
      }
  if (!emitted) printf ("none");
  putchar ('\n');

  for (int i = 0; i < s.nprimaries; i++)
    {
      const struct bda_primary *p = &s.primaries[i];
      char ep[128];
      bda_primary_endpoint (p, ep, sizeof ep);
      printf ("primary[%d]=host=%s port=%d key=%s stealth=%d endpoint=%s fail_until=%lld backoff=%u ready=%d\n",
              i, p->host, p->port, p->keyname, p->stealth, ep,
              (long long) p->fail_until, p->backoff,
              p->fail_until <= now ? 1 : 0);
    }
  return EXECUTION_SUCCESS;
}

static int
bd_catalog_members_debug_cmd (WORD_LIST *args)
{
  const char *zone = NULL, *origin = NULL;
  for (; args; args = args->next)
    {
      const char *w = args->word->word;
      if (!strcmp (w, "--zone") && args->next) { zone = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--origin") && args->next) { origin = args->next->word->word; args = args->next; }
      else { builtin_error ("catalog-members: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!zone)
    { builtin_error ("catalog-members --zone FILE [--origin NAME]"); return EX_USAGE; }

  struct bda_zone catz;
  bda_zone_init_empty (&catz);
  if (bda_load_into (&catz, zone, origin) < 0)
    { builtin_error ("catalog-members: failed to load catalog zone"); return EXECUTION_FAILURE; }
  struct bda_catalog cat;
  if (bda_catalog_parse (&catz, &cat) < 0)
    {
      bda_zone_free_one (&catz);
      builtin_error ("catalog-members: failed to parse catalog zone");
      return EXECUTION_FAILURE;
    }
  printf ("version=%s\n", cat.version);
  if (cat.version_ok)
    for (int i = 0; i < cat.n; i++)
      printf ("member=%s id=%s group=%s\n", cat.members[i].apex,
              cat.members[i].id, cat.members[i].group);
  printf ("rejected=%d\n", cat.rejected);
  bda_zone_free_one (&catz);
  return EXECUTION_SUCCESS;
}

static int
bd_catalog_parse_current (const char *list, struct bda_slave *slaves, int *nslaves)
{
  if (!slaves || !nslaves) return -1;
  *nslaves = 0;
  if (!list || !*list) return 0;
  char buf[8192];
  if (strlen (list) >= sizeof buf) return -1;
  snprintf (buf, sizeof buf, "%s", list);
  char *p = buf;
  while (p && *p)
    {
      char *next = strchr (p, ',');
      if (next) *next++ = '\0';
      if (*p)
        {
          if (*nslaves >= BDA_SLAVE_MAX) return -1;
          char *spec = p;
          char id[256] = "";
          char *at = strchr (p, '@');
          char *colon = strchr (p, ':');
          if (at && (!colon || at < colon))
            {
              size_t il = (size_t) (at - p);
              if (il == 0 || il >= sizeof id) return -1;
              memcpy (id, p, il);
              id[il] = '\0';
              spec = at + 1;
            }
          if (bda_parse_slave_zone (spec, &slaves[*nslaves]) < 0)
            return -1;
          if (id[0])
            {
              slaves[*nslaves].from_catalog = 1;
              snprintf (slaves[*nslaves].cat_id, sizeof slaves[*nslaves].cat_id, "%s", id);
            }
          (*nslaves)++;
        }
      p = next;
    }
  return 0;
}

static int
bd_catalog_reconcile_debug_cmd (WORD_LIST *args)
{
  const char *catalog = NULL, *origin = NULL, *current = NULL;
  const char *default_primary = NULL, *default_key = NULL, *group = NULL;
  for (; args; args = args->next)
    {
      const char *w = args->word->word;
      if (!strcmp (w, "--catalog") && args->next) { catalog = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--origin") && args->next) { origin = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--current") && args->next) { current = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--default-primary") && args->next) { default_primary = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--default-key") && args->next) { default_key = args->next->word->word; args = args->next; }
      else if ((!strcmp (w, "--catalog-group") || !strcmp (w, "--group")) && args->next) { group = args->next->word->word; args = args->next; }
      else { builtin_error ("catalog-reconcile: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!catalog)
    { builtin_error ("catalog-reconcile --catalog FILE [--origin NAME] [--current SPEC,...] [--default-primary IP[:PORT]]"); return EX_USAGE; }

  struct bda_zone zones[BDA_ZONE_MAX];
  memset (zones, 0, sizeof zones);
  int nz = 0;
  if (bda_load_into (&zones[nz], catalog, origin) < 0)
    { builtin_error ("catalog-reconcile: failed to load catalog zone"); return EXECUTION_FAILURE; }
  nz++;
  struct bda_catalog cat;
  if (bda_catalog_parse (&zones[0], &cat) < 0)
    {
      bda_zone_free_one (&zones[0]);
      builtin_error ("catalog-reconcile: failed to parse catalog zone");
      return EXECUTION_FAILURE;
    }
  printf ("version=%s\n", cat.version);

  struct bda_slave slaves[BDA_SLAVE_MAX];
  int nslaves = 0;
  if (bd_catalog_parse_current (current, slaves, &nslaves) < 0)
    {
      bda_zone_free_one (&zones[0]);
      builtin_error ("catalog-reconcile: bad --current list");
      return EX_USAGE;
    }
  struct bda_catalog_stats stats;
  if (bda_catalog_reconcile (&cat, slaves, &nslaves, default_primary,
                             default_key, group, zones, &nz, NULL,
                             &stats, stdout) < 0)
    {
      for (int i = 0; i < nz; i++) bda_zone_free_one (&zones[i]);
      return EXECUTION_FAILURE;
    }
  printf ("summary added=%d removed=%d skipped=%d current=%d rejected=%d\n",
          stats.added, stats.removed, stats.skipped, nslaves, cat.rejected);
  for (int i = 0; i < nz; i++) bda_zone_free_one (&zones[i]);
  return EXECUTION_SUCCESS;
}

enum bda_doq_stream_status {
  BDA_DOQ_STREAM_OK = 0,
  BDA_DOQ_STREAM_BAD_ALPN,
  BDA_DOQ_STREAM_ZERO_LENGTH,
  BDA_DOQ_STREAM_OVERSIZE,
  BDA_DOQ_STREAM_MALFORMED,
  BDA_DOQ_STREAM_ANSWER_ERROR
};

static int
bda_doq_alpn_ok (const char *alpn)
{
  return alpn && strcmp (alpn, BDA_DOQ_ALPN) == 0;
}

static const char *
bda_doq_status_name (int status)
{
  switch (status)
    {
    case BDA_DOQ_STREAM_OK: return "ok";
    case BDA_DOQ_STREAM_BAD_ALPN: return "bad-alpn";
    case BDA_DOQ_STREAM_ZERO_LENGTH: return "zero-length";
    case BDA_DOQ_STREAM_OVERSIZE: return "oversize";
    case BDA_DOQ_STREAM_MALFORMED: return "malformed";
    case BDA_DOQ_STREAM_ANSWER_ERROR: return "answer-error";
    default: return "unknown";
    }
}

static int
bda_doq_handle_stream (struct bda_zone *zones, int nz, const char *alpn,
                       const unsigned char *payload, size_t payload_len,
                       unsigned char *resp, size_t resp_sz, size_t *resp_len)
{
  if (resp_len) *resp_len = 0;
  if (!bda_doq_alpn_ok (alpn)) return BDA_DOQ_STREAM_BAD_ALPN;
  if (payload_len == 0) return BDA_DOQ_STREAM_ZERO_LENGTH;
  if (payload_len > BDA_DOQ_MAX_WIRE) return BDA_DOQ_STREAM_OVERSIZE;
  if (payload_len < 12) return BDA_DOQ_STREAM_MALFORMED;
  if ((payload[2] & 0xf8) != 0 || bd_rd16 (payload + 4) != 1)
    return BDA_DOQ_STREAM_MALFORMED;

  int rl = bda_answer_wire (zones, nz, payload, payload_len, resp, resp_sz, NULL);
  if (rl <= 0) return BDA_DOQ_STREAM_ANSWER_ERROR;
  if (resp_len) *resp_len = (size_t) rl;
  return BDA_DOQ_STREAM_OK;
}

static int
bd_doq_alpn_cmd (WORD_LIST *args)
{
  if (!args)
    { builtin_error ("doq-alpn ALPN"); return EX_USAGE; }
  const char *alpn = args->word->word;
  printf ("backend=%s\n", BDA_DOQ_BACKEND);
  printf ("selected_backend=%s\n", BDA_DOQ_SELECTED_BACKEND);
  printf ("backend_version=%s\n", BDA_DOQ_BACKEND_VERSION);
  printf ("have_quic=%d\n", BDA_DOQ_HAVE_QUIC);
  printf ("alpn=%s\n", alpn);
  printf ("status=%s\n", bda_doq_alpn_ok (alpn) ? "accepted" : "rejected");
  return EXECUTION_SUCCESS;
}

static int
bd_doq_backend_cmd (WORD_LIST *args)
{
  (void) args;
  printf ("backend=%s\n", BDA_DOQ_BACKEND);
  printf ("selected_backend=%s\n", BDA_DOQ_SELECTED_BACKEND);
  printf ("backend_version=%s\n", BDA_DOQ_BACKEND_VERSION);
  printf ("have_quic=%d\n", BDA_DOQ_HAVE_QUIC);
  printf ("build_flag=%s\n", BDA_DOQ_BUILD_FLAG);
  printf ("alpn=%s\n", BDA_DOQ_ALPN);
  return EXECUTION_SUCCESS;
}

static int
bd_doq_stream_cmd (WORD_LIST *args)
{
  const char *origin = NULL, *payload_hex = NULL, *alpn = BDA_DOQ_ALPN;
  char zpaths[BDA_ZONE_MAX][512]; int nzp = 0;
  for (; args; args = args->next)
    {
      const char *w = args->word->word;
      if (!strcmp (w, "--zone") && args->next)
        {
          if (nzp >= BDA_ZONE_MAX)
            { builtin_error ("doq-stream: too many --zone arguments"); return EX_USAGE; }
          snprintf (zpaths[nzp], sizeof zpaths[nzp], "%s", args->next->word->word);
          nzp++;
          args = args->next;
        }
      else if (!strcmp (w, "--origin") && args->next)
        { origin = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--payload-hex") && args->next)
        { payload_hex = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--alpn") && args->next)
        { alpn = args->next->word->word; args = args->next; }
      else
        { builtin_error ("doq-stream: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!payload_hex || nzp == 0)
    { builtin_error ("doq-stream --zone FILE [--origin NAME] [--alpn doq] --payload-hex HEX"); return EX_USAGE; }
  if (payload_hex[0] == '-' && payload_hex[1] == '\0') payload_hex = "";

  printf ("backend=%s\n", BDA_DOQ_BACKEND);
  printf ("selected_backend=%s\n", BDA_DOQ_SELECTED_BACKEND);
  printf ("have_quic=%d\n", BDA_DOQ_HAVE_QUIC);
  printf ("alpn=%s\n", alpn);

  size_t payload_len = 0;
  if (bd_hex_payload_len (payload_hex, &payload_len) < 0)
    {
      printf ("status=400\nerror=bad-hex\n");
      return EXECUTION_SUCCESS;
    }
  printf ("query_len=%zu\n", payload_len);
  if (!bda_doq_alpn_ok (alpn))
    {
      printf ("status=400\nerror=%s\n", bda_doq_status_name (BDA_DOQ_STREAM_BAD_ALPN));
      return EXECUTION_SUCCESS;
    }
  if (payload_len > BDA_DOQ_MAX_WIRE)
    {
      printf ("status=413\nerror=%s\n", bda_doq_status_name (BDA_DOQ_STREAM_OVERSIZE));
      return EXECUTION_SUCCESS;
    }

  unsigned char payload[BDA_DOQ_MAX_WIRE], resp[BDA_DOQ_MAX_WIRE];
  if (payload_len > 0 &&
      bd_unhex (payload_hex, payload, sizeof payload, &payload_len) < 0)
    {
      printf ("status=400\nerror=bad-hex\n");
      return EXECUTION_SUCCESS;
    }

  struct bda_zone zones[BDA_ZONE_MAX];
  memset (zones, 0, sizeof zones);
  int nz = 0;
  for (int i = 0; i < nzp; i++)
    {
      if (bda_load_zone_signed (&zones[nz], zpaths[i], origin, NULL, 0) < 0)
        {
          for (int j = 0; j < nz; j++) bda_zone_free_one (&zones[j]);
          printf ("status=500\nerror=zone-load\n");
          return EXECUTION_SUCCESS;
        }
      nz++;
    }

  size_t resp_len = 0;
  int st = bda_doq_handle_stream (zones, nz, alpn, payload, payload_len,
                                  resp, sizeof resp, &resp_len);
  if (st == BDA_DOQ_STREAM_OK)
    {
      printf ("status=200\nerror=none\n");
      printf ("response_len=%zu\n", resp_len);
      printf ("rcode=%u\n", resp_len >= 4 ? (unsigned) (resp[3] & 0x0f) : 0U);
      printf ("ancount=%u\n", resp_len >= 8 ? (unsigned) bd_rd16 (resp + 6) : 0U);
      printf ("response_hex=");
      bd_hex (resp, resp_len);
      putchar ('\n');
    }
  else
    {
      printf ("status=%d\nerror=%s\n",
              st == BDA_DOQ_STREAM_OVERSIZE ? 413 : 400,
              bda_doq_status_name (st));
    }

  for (int i = 0; i < nz; i++) bda_zone_free_one (&zones[i]);
  return EXECUTION_SUCCESS;
}

#if BDA_DOQ_HAVE_QUIC
struct bda_doq_client {
  ngtcp2_crypto_conn_ref conn_ref;
  int fd;
  struct sockaddr_storage local_addr;
  socklen_t local_addrlen;
  struct sockaddr_storage remote_addr;
  socklen_t remote_addrlen;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  ngtcp2_conn *conn;
  ngtcp2_ccerr last_error;
  int64_t stream_id;
  const unsigned char *req;
  size_t req_len;
  size_t req_off;
  int req_fin_sent;
  unsigned char *resp;
  size_t resp_sz;
  size_t resp_len;
  int resp_fin;
};

static ngtcp2_conn *
bda_doq_client_get_conn (ngtcp2_crypto_conn_ref *conn_ref)
{
  struct bda_doq_client *c = (struct bda_doq_client *) conn_ref->user_data;
  return c ? c->conn : NULL;
}

static int
bda_doq_client_recv_stream_data_cb (ngtcp2_conn *conn, uint32_t flags,
                                    int64_t stream_id, uint64_t offset,
                                    const uint8_t *data, size_t datalen,
                                    void *user_data, void *stream_user_data)
{
  struct bda_doq_client *c = (struct bda_doq_client *) user_data;
  (void) conn; (void) offset; (void) stream_user_data;
  if (!c || stream_id != c->stream_id)
    return 0;
  if (datalen > c->resp_sz || c->resp_len > c->resp_sz - datalen)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  memcpy (c->resp + c->resp_len, data, datalen);
  c->resp_len += datalen;
  ngtcp2_conn_extend_max_stream_offset (c->conn, stream_id, (uint64_t) datalen);
  ngtcp2_conn_extend_max_offset (c->conn, (uint64_t) datalen);
  if (flags & NGTCP2_STREAM_DATA_FLAG_FIN)
    c->resp_fin = 1;
  return 0;
}

static int
bda_doq_client_open_stream (struct bda_doq_client *c)
{
  if (c->stream_id != -1)
    return 0;
  int rv = ngtcp2_conn_open_bidi_stream (c->conn, &c->stream_id, NULL);
  if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED)
    return 0;
  return rv == 0 ? 0 : -1;
}

static int
bda_doq_client_extend_streams_cb (ngtcp2_conn *conn, uint64_t max_streams,
                                  void *user_data)
{
  struct bda_doq_client *c = (struct bda_doq_client *) user_data;
  (void) conn; (void) max_streams;
  return c ? bda_doq_client_open_stream (c) : 0;
}

static int
bda_doq_client_handshake_completed_cb (ngtcp2_conn *conn, void *user_data)
{
  struct bda_doq_client *c = (struct bda_doq_client *) user_data;
  (void) conn;
  return c ? bda_doq_client_open_stream (c) : 0;
}

static int
bda_doq_client_ssl_init (struct bda_doq_client *c, const char *host)
{
  c->ssl_ctx = SSL_CTX_new (TLS_client_method ());
  if (!c->ssl_ctx)
    return -1;
  if (ngtcp2_crypto_boringssl_configure_client_context (c->ssl_ctx) != 0)
    return -1;
  c->ssl = SSL_new (c->ssl_ctx);
  if (!c->ssl)
    return -1;
  c->conn_ref.get_conn = bda_doq_client_get_conn;
  c->conn_ref.user_data = c;
  SSL_set_app_data (c->ssl, &c->conn_ref);
  SSL_set_connect_state (c->ssl);
  const unsigned char alpn[] = "\x03" BDA_DOQ_ALPN;
  if (SSL_set_alpn_protos (c->ssl, alpn, sizeof alpn - 1) != 0)
    return -1;
  if (host && inet_pton (AF_INET, host, &(struct in_addr){0}) != 1)
    SSL_set_tlsext_host_name (c->ssl, host);
  return 0;
}

static int
bda_doq_client_quic_init (struct bda_doq_client *c)
{
  ngtcp2_path path = {
    .local = { .addr = (struct sockaddr *) &c->local_addr, .addrlen = c->local_addrlen },
    .remote = { .addr = (struct sockaddr *) &c->remote_addr, .addrlen = c->remote_addrlen },
  };
  ngtcp2_callbacks callbacks = {
    .client_initial = ngtcp2_crypto_client_initial_cb,
    .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    .recv_retry = ngtcp2_crypto_recv_retry_cb,
    .recv_stream_data = bda_doq_client_recv_stream_data_cb,
    .extend_max_local_streams_bidi = bda_doq_client_extend_streams_cb,
    .handshake_completed = bda_doq_client_handshake_completed_cb,
    .rand = bda_doq_rand_cb,
    .update_key = ngtcp2_crypto_update_key_cb,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
    .get_new_connection_id2 = bda_doq_get_new_connection_id_cb,
    .get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb,
  };
  ngtcp2_cid dcid, scid;
  dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
  scid.datalen = 8;
  if (RAND_bytes (dcid.data, (int) dcid.datalen) != 1 ||
      RAND_bytes (scid.data, (int) scid.datalen) != 1)
    return -1;
  ngtcp2_settings settings;
  ngtcp2_settings_default (&settings);
  settings.initial_ts = bda_doq_timestamp ();
  settings.max_tx_udp_payload_size = BDA_DOQ_UDP_PAYLOAD;
  ngtcp2_transport_params params;
  ngtcp2_transport_params_default (&params);
  params.initial_max_stream_data_bidi_local = BDA_DOQ_MAX_WIRE;
  params.initial_max_stream_data_bidi_remote = BDA_DOQ_MAX_WIRE;
  params.initial_max_stream_data_uni = 4096;
  params.initial_max_data = 1024 * 1024;
  params.initial_max_streams_bidi = BDA_DOQ_STREAM_MAX;
  params.initial_max_streams_uni = 0;
  params.max_idle_timeout = 15 * NGTCP2_SECONDS;
  int rv = ngtcp2_conn_client_new (&c->conn, &dcid, &scid, &path,
                                   NGTCP2_PROTO_VER_V1, &callbacks, &settings,
                                   &params, NULL, c);
  if (rv != 0)
    return -1;
  ngtcp2_conn_set_tls_native_handle (c->conn, c->ssl);
  return 0;
}

static int
bda_doq_client_send_packet (struct bda_doq_client *c, const unsigned char *data,
                            size_t len)
{
  ssize_t n;
  do
    n = send (c->fd, data, len, 0);
  while (n < 0 && errno == EINTR);
  return n == (ssize_t) len ? 0 : -1;
}

static int
bda_doq_client_write (struct bda_doq_client *c)
{
  unsigned char pkt[BDA_DOQ_UDP_PAYLOAD];
  ngtcp2_tstamp ts = bda_doq_timestamp ();
  (void) bda_doq_client_open_stream (c);
  for (int rounds = 0; rounds < 64; rounds++)
    {
      ngtcp2_vec v;
      ngtcp2_vec *vp = NULL;
      size_t vcnt = 0;
      int64_t sid = -1;
      uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
      if (c->stream_id != -1 && !c->req_fin_sent && c->req_off < c->req_len)
        {
          sid = c->stream_id;
          v.base = (uint8_t *) c->req + c->req_off;
          v.len = c->req_len - c->req_off;
          vp = &v; vcnt = 1;
          flags = NGTCP2_WRITE_STREAM_FLAG_FIN;
        }
      ngtcp2_path_storage ps;
      ngtcp2_path_storage_zero (&ps);
      ngtcp2_pkt_info pi;
      memset (&pi, 0, sizeof pi);
      ngtcp2_ssize wdatalen = 0;
      ngtcp2_ssize nw = ngtcp2_conn_writev_stream (c->conn, &ps.path, &pi,
                                                   pkt, sizeof pkt, &wdatalen,
                                                   flags, sid, vp, vcnt, ts);
      if (nw == 0)
        return 0;
      if (nw == NGTCP2_ERR_WRITE_MORE)
        {
          if (wdatalen > 0)
            c->req_off += (size_t) wdatalen;
          continue;
        }
      if (nw < 0)
        {
          ngtcp2_ccerr_set_liberr (&c->last_error, (int) nw, NULL, 0);
          return -1;
        }
      if (wdatalen > 0)
        {
          c->req_off += (size_t) wdatalen;
          if (c->req_off >= c->req_len)
            c->req_fin_sent = 1;
        }
      if (bda_doq_client_send_packet (c, pkt, (size_t) nw) < 0)
        return -1;
    }
  return 0;
}

static int
bda_doq_client_read (struct bda_doq_client *c)
{
  unsigned char buf[65536];
  struct sockaddr_storage remote;
  struct iovec iov = { .iov_base = buf, .iov_len = sizeof buf };
  struct msghdr msg;
  memset (&msg, 0, sizeof msg);
  msg.msg_name = &remote;
  msg.msg_namelen = sizeof remote;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  for (;;)
    {
      msg.msg_namelen = sizeof remote;
      ssize_t nread = recvmsg (c->fd, &msg, MSG_DONTWAIT);
      if (nread < 0)
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
      ngtcp2_path path = {
        .local = { .addr = (struct sockaddr *) &c->local_addr, .addrlen = c->local_addrlen },
        .remote = { .addr = (struct sockaddr *) &c->remote_addr, .addrlen = c->remote_addrlen },
      };
      ngtcp2_pkt_info pi;
      memset (&pi, 0, sizeof pi);
      int rv = ngtcp2_conn_read_pkt (c->conn, &path, &pi, buf, (size_t) nread,
                                     bda_doq_timestamp ());
      if (rv != 0)
        {
          if (rv == NGTCP2_ERR_CRYPTO)
            ngtcp2_ccerr_set_tls_alert (&c->last_error,
                                        ngtcp2_conn_get_tls_alert2 (c->conn),
                                        NULL, 0);
          else
            ngtcp2_ccerr_set_liberr (&c->last_error, rv, NULL, 0);
          return -1;
        }
    }
}

static void
bda_doq_client_free (struct bda_doq_client *c)
{
  if (c->conn) ngtcp2_conn_del (c->conn);
  if (c->ssl) SSL_free (c->ssl);
  if (c->ssl_ctx) SSL_CTX_free (c->ssl_ctx);
  if (c->fd >= 0) close (c->fd);
  memset (c, 0, sizeof *c);
  c->fd = -1;
}

static int
bda_doq_client_query (const char *addr, int port, const unsigned char *req,
                      size_t req_len, unsigned char *resp, size_t resp_sz,
                      size_t *resp_len, int timeout_ms)
{
  struct bda_doq_client c;
  memset (&c, 0, sizeof c);
  c.fd = -1;
  c.stream_id = -1;
  c.req = req;
  c.req_len = req_len;
  c.resp = resp;
  c.resp_sz = resp_sz;
  ngtcp2_ccerr_default (&c.last_error);

  struct sockaddr_in sa;
  memset (&sa, 0, sizeof sa);
  sa.sin_family = AF_INET;
  sa.sin_port = htons ((uint16_t) port);
  if (inet_pton (AF_INET, addr, &sa.sin_addr) != 1)
    return -1;
  c.remote_addrlen = sizeof sa;
  memcpy (&c.remote_addr, &sa, sizeof sa);

  c.fd = socket (AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (c.fd < 0)
    return -1;
  if (connect (c.fd, (struct sockaddr *) &sa, sizeof sa) < 0)
    { bda_doq_client_free (&c); return -1; }
  c.local_addrlen = sizeof c.local_addr;
  if (getsockname (c.fd, (struct sockaddr *) &c.local_addr, &c.local_addrlen) < 0)
    { bda_doq_client_free (&c); return -1; }
  if (bda_doq_client_ssl_init (&c, addr) < 0 ||
      bda_doq_client_quic_init (&c) < 0)
    { bda_doq_client_free (&c); return -1; }

  ngtcp2_tstamp deadline = bda_doq_timestamp () + (uint64_t) timeout_ms * 1000000ULL;
  int rc = -2;
  if (bda_doq_client_write (&c) < 0)
    rc = -1;
  while (rc == -2 && !c.resp_fin)
    {
      ngtcp2_tstamp now = bda_doq_timestamp ();
      if (now >= deadline)
        break;
      ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry2 (c.conn);
      uint64_t wait_ns = deadline - now;
      if (expiry != UINT64_MAX && expiry <= now)
        wait_ns = 0;
      else if (expiry != UINT64_MAX && expiry - now < wait_ns)
        wait_ns = expiry - now;
      if (wait_ns > 100000000ULL)
        wait_ns = 100000000ULL;
      fd_set rf;
      FD_ZERO (&rf);
      FD_SET (c.fd, &rf);
      struct timeval tv = {
        .tv_sec = (time_t) (wait_ns / 1000000000ULL),
        .tv_usec = (suseconds_t) ((wait_ns % 1000000000ULL) / 1000ULL),
      };
      int sr;
      do
        sr = select (c.fd + 1, &rf, NULL, NULL, &tv);
      while (sr < 0 && errno == EINTR);
      if (sr < 0)
        { rc = -1; break; }
      if (sr > 0 && FD_ISSET (c.fd, &rf))
        {
          if (bda_doq_client_read (&c) < 0)
            { rc = -1; break; }
        }
      else
        {
          int rv = ngtcp2_conn_handle_expiry (c.conn, bda_doq_timestamp ());
          if (rv != 0)
            { ngtcp2_ccerr_set_liberr (&c.last_error, rv, NULL, 0); rc = -1; break; }
        }
      if (bda_doq_client_write (&c) < 0)
        { rc = -1; break; }
    }
  if (c.resp_fin)
    {
      if (resp_len) *resp_len = c.resp_len;
      rc = 0;
    }
  bda_doq_client_free (&c);
  return rc;
}
#endif

static int
bd_doq_query_cmd (WORD_LIST *args)
{
  const char *server = NULL, *payload_hex = NULL;
  int timeout_ms = 3000;
  char addr[64] = "127.0.0.1";
  int port = 0;
  for (; args; args = args->next)
    {
      const char *w = args->word->word;
      if (!strcmp (w, "--server") && args->next)
        { server = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--payload-hex") && args->next)
        { payload_hex = args->next->word->word; args = args->next; }
      else if (!strcmp (w, "--timeout-ms") && args->next)
        { timeout_ms = atoi (args->next->word->word); args = args->next; }
      else
        { builtin_error ("doq-query: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!server || !payload_hex)
    { builtin_error ("doq-query --server ADDR:PORT --payload-hex HEX [--timeout-ms MS]"); return EX_USAGE; }
  if (bda_parse_listen (server, addr, sizeof addr, &port) < 0 || port <= 0)
    { builtin_error ("doq-query: --server needs ADDR:PORT"); return EX_USAGE; }
  if (timeout_ms <= 0) timeout_ms = 3000;

  printf ("backend=%s\n", BDA_DOQ_BACKEND);
  printf ("selected_backend=%s\n", BDA_DOQ_SELECTED_BACKEND);
  printf ("have_quic=%d\n", BDA_DOQ_HAVE_QUIC);
  printf ("alpn=%s\n", BDA_DOQ_ALPN);

  size_t payload_len = 0;
  if (bd_hex_payload_len (payload_hex, &payload_len) < 0)
    { printf ("status=400\nerror=bad-hex\n"); return EXECUTION_SUCCESS; }
  printf ("query_len=%zu\n", payload_len);
  if (payload_len == 0 || payload_len > BDA_DOQ_MAX_WIRE)
    { printf ("status=%d\nerror=%s\n", payload_len == 0 ? 400 : 413, payload_len == 0 ? "zero-length" : "oversize"); return EXECUTION_SUCCESS; }

  unsigned char payload[BDA_DOQ_MAX_WIRE], resp[BDA_DOQ_MAX_WIRE];
  if (bd_unhex (payload_hex, payload, sizeof payload, &payload_len) < 0)
    { printf ("status=400\nerror=bad-hex\n"); return EXECUTION_SUCCESS; }

#if BDA_DOQ_HAVE_QUIC
  size_t resp_len = 0;
  int rv = bda_doq_client_query (addr, port, payload, payload_len, resp,
                                 sizeof resp, &resp_len, timeout_ms);
  if (rv == 0)
    {
      printf ("status=200\nerror=none\n");
      printf ("response_len=%zu\n", resp_len);
      printf ("rcode=%u\n", resp_len >= 4 ? (unsigned) (resp[3] & 0x0f) : 0U);
      printf ("ancount=%u\n", resp_len >= 8 ? (unsigned) bd_rd16 (resp + 6) : 0U);
      printf ("response_hex=");
      bd_hex (resp, resp_len);
      putchar ('\n');
    }
  else
    printf ("status=%d\nerror=%s\n", rv == -2 ? 504 : 502,
            rv == -2 ? "timeout" : "quic");
#else
  printf ("status=501\nerror=no-quic\n");
#endif
  return EXECUTION_SUCCESS;
}

static int
bd_dot_accept_frame_cmd (WORD_LIST *args)
{
  if (!args)
    { builtin_error ("dot-accept-frame needs TCPFRAMEHEX"); return EX_USAGE; }
  const char *frame_hex = args->word->word;
  size_t frame_len = 0;
  if (bd_hex_payload_len (frame_hex, &frame_len) < 0)
    { puts ("status=400"); return EXECUTION_SUCCESS; }
  if (frame_len > BD_DOH_WIRE_MAX + 2)
    { puts ("status=413"); return EXECUTION_SUCCESS; }

  unsigned char frame[BD_DOH_WIRE_MAX + 2];
  if (bd_unhex (frame_hex, frame, sizeof frame, &frame_len) < 0)
    { puts ("status=400"); return EXECUTION_SUCCESS; }

  unsigned char out[BD_DOH_WIRE_MAX + 2];
  size_t out_len = 0;
  int fr = bd_dot_accept_filter (frame, frame_len, out, sizeof out,
                                 &out_len, 2000);
  if (fr == -2) { puts ("status=413"); return EXECUTION_SUCCESS; }
  if (fr < 0) { puts ("status=502"); return EXECUTION_SUCCESS; }
  if (out_len < 2)
    { puts ("status=400"); return EXECUTION_SUCCESS; }

  uint16_t msg_len = bd_rd16 (out);
  if ((size_t) msg_len + 2 != out_len)
    { puts ("status=400"); return EXECUTION_SUCCESS; }

  printf ("status=200\n");
  printf ("len=%u\n", msg_len);
  printf ("wire_hex=");
  bd_hex (out + 2, msg_len);
  putchar ('\n');
  printf ("frame_hex=");
  bd_hex (out, out_len);
  putchar ('\n');
  return EXECUTION_SUCCESS;
}

int
dns_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;
  /* Type-name shortcut: dns A foo.com == dns query foo.com A */
  uint16_t dummy;
  if (bd_type_from_name (cmd, &dummy) == 0)
    return bd_query_cmd (args, cmd);
  if (strcmp (cmd, "query") == 0) return bd_query_cmd (args, NULL);
  if (strcmp (cmd, "trust-anchor") == 0)
    return bd_print_trust_anchor_cmd (args);
  if (strcmp (cmd, "trust-anchor-load") == 0)
    return bd_trust_anchor_load_cmd (args);
  if (strcmp (cmd, "resolv-conf") == 0)
    return bd_resolv_conf_cmd (args);
  if (strcmp (cmd, "checkzone") == 0)
    return bd_checkzone_cmd (args);
  if (strcmp (cmd, "checkconf") == 0)
    return bd_checkconf_cmd (args);
  if (strcmp (cmd, "signzone") == 0)
    return bd_signzone_cmd (args);
  if (strcmp (cmd, "ds-from-dnskey") == 0)
    return bd_ds_from_dnskey_cmd (args);
  if (strcmp (cmd, "keytag") == 0)
    return bd_keytag_cmd (args);
  if (strcmp (cmd, "rfc5011-step") == 0)
    return bd_rfc5011_step_cmd (args);
  if (strcmp (cmd, "rfc5011-poll") == 0)
    return bd_rfc5011_poll_cmd (args);
  if (strcmp (cmd, "doh-codec") == 0)
    return bd_doh_codec_cmd (args);
  if (strcmp (cmd, "doq-alpn") == 0)
    return bd_doq_alpn_cmd (args);
  if (strcmp (cmd, "doq-backend") == 0)
    return bd_doq_backend_cmd (args);
  if (strcmp (cmd, "doq-stream") == 0)
    return bd_doq_stream_cmd (args);
  if (strcmp (cmd, "doq-query") == 0)
    return bd_doq_query_cmd (args);
  if (strcmp (cmd, "tsig-digest") == 0)
    return bd_tsig_debug_digest_cmd (args);
  if (strcmp (cmd, "tsig-rr") == 0)
    return bd_tsig_debug_rr_cmd (args);
  if (strcmp (cmd, "tsig-sign") == 0)
    return bd_tsig_debug_sign_cmd (args);
  if (strcmp (cmd, "tsig-verify") == 0)
    return bd_tsig_debug_verify_cmd (args);
  if (strcmp (cmd, "slave-verify-chain") == 0)
    return bd_slave_verify_chain_debug_cmd (args);
  if (strcmp (cmd, "slave-apply") == 0)
    return bd_slave_apply_debug_cmd (args);
  if (strcmp (cmd, "slave-timer") == 0)
    return bd_slave_timer_debug_cmd (args);
  if (strcmp (cmd, "slave-primary") == 0)
    return bd_slave_primary_debug_cmd (args);
  if (strcmp (cmd, "catalog-members") == 0)
    return bd_catalog_members_debug_cmd (args);
  if (strcmp (cmd, "catalog-reconcile") == 0)
    return bd_catalog_reconcile_debug_cmd (args);
  if (strcmp (cmd, "dot-accept-frame") == 0)
    return bd_dot_accept_frame_cmd (args);
  if (strcmp (cmd, "update-codec") == 0)
    return bd_update_codec_cmd (args);
  if (strcmp (cmd, "update-apply-fixture") == 0)
    return bd_update_apply_fixture_cmd (args);
  if (strcmp (cmd, "update-handle-fixture") == 0)
    return bd_update_handle_fixture_cmd (args);
  if (strcmp (cmd, "update") == 0)
    return bd_update_cmd (args);
  if (strcmp (cmd, "resolver-serve") == 0)
    return bd_resolver_serve_cmd (args);
  if (strcmp (cmd, "auth-serve") == 0)
    return bd_auth_serve_cmd (args);
  if (strcmp (cmd, "notify") == 0)
    return bd_notify_cmd (args);
  if (strcmp (cmd, "rndc") == 0)
    return bd_rndc_cmd (args);
  if (strcmp (cmd, "chain") == 0)
    {
      if (!args) { builtin_error ("chain needs NAME"); return EX_USAGE; }
      const char *name = args->word->word;
      printf ("%s\n", name);
      const char *dot = strchr (name, '.');
      while (dot && dot[1]) { printf ("%s\n", dot + 1); dot = strchr (dot + 1, '.'); }
      puts (".");
      return EXECUTION_SUCCESS;
    }
  builtin_error ("unknown subcommand: %s", cmd);
  return EX_USAGE;
}

char *dns_doc[] = {
  "DNS over UDP via hand-rolled RFC 1035.",
  "",
  "    dns A     HOST",
  "    dns AAAA  HOST",
  "    dns CNAME HOST",
  "    dns DNAME HOST",
  "    dns NS    DOMAIN",
  "    dns MX    DOMAIN     prints \"PRIORITY HOSTNAME\" per line",
  "    dns TXT   DOMAIN     one record per line",
  "    dns PTR   IPV4_ADDR",
  "    dns SOA   DOMAIN",
  "    dns query HOST TYPE [-s SERVER] [-t TIMEOUT_MS] [-d|--dnssec] [--require-ad] [--validate] [--skew SEC] [--dot [-h DOT_HOST[:PORT]]] [--dot-ca PEM] [--doh [URL]]",
  "    dns trust-anchor [-V VAR]",
  "    dns trust-anchor-load PATH",
  "    dns chain HOST",
  "    dns checkzone [-o ORIGIN] PATH   validate an RFC 1035 master file (rc 0 ok)",
  "    dns checkconf PATH               validate a bash-os key=value DNS config",
  "    dns signzone [-o ORIGIN] [-K KEYDIR] [-e SECONDS] [--nsec3 [-s SALT] [-i ITERS]] [--self-check] ZONEFILE",
  "        Offline DNSSEC zone signer. Loads keys K<zone>.+<alg>+<tag>.{key,private}",
  "        from KEYDIR (default '.'), signs each RRset (DNSKEY with the KSK, others",
  "        with the ZSK), builds NSEC (default) or NSEC3 (--nsec3) chains, and writes",
  "        the signed master file to stdout. --self-check verifies every produced",
  "        RRSIG through the in-binary validator before emitting (rc 1 on any mismatch).",
  "    dns ds-from-dnskey [-d sha1|sha256|sha384] KEYFILE   print BIND DS text",
  "    dns keytag KEYFILE                print the RFC 4034 App B keytag of a DNSKEY",
  "    dns rfc5011-step --anchor-dir DIR --dnskey-set FILE --now EPOCH [--hold-down SECS]",
  "        RFC 5011 automated trust-anchor rollover state machine (logic only).",
  "        Reads DIR/root.anchor[.candidate][.previous], processes the observed",
  "        apex DNSKEY set FILE at injected time --now, and drives one step:",
  "        new keys -> pending; pending past hold-down (default 30d) -> promoted",
  "        (prior active set retained as root.anchor.previous); REVOKE-bit keys",
  "        -> revoked then removed after hold-down; pending keys that vanish",
  "        before promotion are dropped. Emits one status line per key.",
  "    dns rfc5011-poll --anchor-dir DIR [--zone NAME] [-s SERVER] [--now EPOCH]",
  "                         [--hold-down SECS] [--validate]",
  "        RFC 5011 periodic fetch loop: fetch the apex DNSKEY RRset for NAME",
  "        (default root) from SERVER, optionally RRSIG-validate it against the",
  "        current active anchor (--validate; refuses to update on failure),",
  "        then drive one rfc5011-step. --now defaults to wall-clock.",
  "    dns resolver-serve [--listen ADDR] [--inet6] [--v6only] [--port N] [--upstream IP]",
  "                           [--recurse [--root-hints IP,IP,...]] [--cache-file PATH]",
  "                           [--allow CIDR]... [--local-a NAME=IP]... [--version STR]",
  "                           [--max-queries N]",
  "        Caching DNS resolver daemon (DNS-6.1) on UDP + TCP at ADDR:PORT",
  "        (default 127.0.0.1:53). IPv6 literals select AF_INET6; --inet6",
  "        without --listen uses ::1.",
  "        IPv6 wildcard listeners clear IPV6_V6ONLY by default for dual-stack;",
  "        --v6only forces IPV6_V6ONLY=1.",
  "        Answers from a bounded TTL cache (negative",
  "        answers capped at 1h, RFC 2308), then local static A records, then",
  "        either forwards to --upstream OR, with --recurse, resolves iteratively",
  "        from the root hints (built-in IANA set, or --root-hints). Oversized UDP",
  "        answers set TC so the client retries over TCP. EDNS0 COOKIE (RFC 7873)",
  "        is echoed. --cache-file PATH persists the cache across restarts. Per-",
  "        listener CIDR allow-list; CHAOS version.bind/version.server -> --version.",
  "    dns update --server IP[:PORT] --zone NAME [--prereq KIND NAME [TYPE]]",
  "                   [--add NAME TTL TYPE RDATA...] [--delete NAME [TYPE [RDATA...]]]",
  "                   [--tsig-key NAME:hmac-sha256:BASE64] [--tsig-keys FILE]",
  "        Send an RFC 2136 DNS UPDATE over TCP. Supported prereq KIND values are",
  "        name-exists, name-not-exists, rrset-exists, and rrset-not-exists.",
  "        Adds use CLASS IN; deletes use RFC 2136 ANY/NONE encodings. With",
  "        TSIG keys, UPDATE is signed with the first loaded HMAC-SHA256 key.",
  "    dns auth-serve {--zone FILE}... [--zones-dir DIR] [--origin NAME]",
  "                       [--slave-zone APEX:PRIMARY[,PRIMARY...]]...",
  "                       [--slave-zone-store DIR | --slave-dir DIR]",
  "                       [--catalog-zone CAT_APEX:FILE]",
  "                       [--catalog-default-primary IP[:PORT]]",
  "                       [--catalog-default-key KEYNAME]",
  "                       [--catalog-group NAME] [--catalog-reload-secs N]",
  "                       [--listen ADDR] [--inet6] [--v6only] [--port N]",
  "                       [--allow CIDR]...",
  "                       [--allow-transfer CIDR]... [--allow-update CIDR]...",
  "                       [--also-notify IP[:PORT]]...",
  "                       [--tsig-key NAME:hmac-sha256:BASE64] [--tsig-keys FILE]",
  "                       [--require-tsig] [--transfer-key NAME]",
  "                       [--control PATH] [--sign-key DIR [--nsec3]]",
  "                       [--rrl-rps N] [--rrl-window S] [--rrl-slip M] [--no-rrl]",
  "                       [--tls-listen ADDR:PORT --tls-cert PEM --tls-key PEM]",
  "                       [--doh-listen ADDR:PORT [--doh-path PATH]",
  "                        [--doh-cert PEM --doh-key PEM]]",
  "                       [--doq-listen ADDR:PORT --doq-cert PEM --doq-key PEM]",
  "        Authoritative DNS daemon (DNS-6.2). Hosts one or more zones (repeat",
  "        --zone, and/or --zones-dir DIR for every *.zone in DIR); each query is",
  "        routed to the most specific matching zone.",
  "        IPv6 listener literals select AF_INET6; --inet6 without --listen uses",
  "        ::1. IPv6 wildcard listeners clear IPV6_V6ONLY by default for dual-",
  "        stack; --v6only forces IPV6_V6ONLY=1. Use [::1]:853 bracket syntax",
  "        for IPv6 --tls-listen/--doh-listen/--doq-listen addresses.",
  "        --slave-zone pulls a zone from ordered primary list entries",
  "        PRIMARY=[~]IP[:PORT][#KEYNAME] over TCP IXFR/AXFR.",
  "        Bare IPv6 primaries use the default port; use [v6]:PORT[#KEYNAME]",
  "        or legacy [v6]:PORT:KEYNAME when an IPv6 port/key is explicit.",
  "        On-disk persistence is OPT-IN and default-OFF: with no store the",
  "        secondary is RAM-only (re-AXFRs on every restart). Naming a writable",
  "        store with --slave-zone-store DIR (or legacy --slave-dir DIR, or the",
  "        BASHDNS_SLAVE_DIR env var) persists each transferred zone there as",
  "        <store>/<apex>.zone via tmp+rename(2), warm-starts from that copy on",
  "        boot when still inside SOA expire (skipping the cold AXFR), refreshes",
  "        on SOA timers or inbound NOTIFY, and refuses the zone after SOA expire",
  "        without a successful refresh. Timer refreshes poll primary SOA first",
  "        and skip IXFR/AXFR when the serial is unchanged. A failing primary is skipped by bounded",
  "        per-primary backoff; priority order resumes when it recovers. Prefix",
  "        a primary with ~ to mark it stealth for transfer-only use.",
  "        The legacy APEX:IP[:PORT][:KEYNAME] form remains accepted.",
  "        --catalog-zone consumes a local",
  "        RFC 9432 version=2 catalog zone, auto-adds/removes catalog-owned",
  "        slave members using --catalog-default-primary[/--catalog-default-key],",
  "        optionally filters by --catalog-group, and reparses on catalog SOA",
  "        refresh or --catalog-reload-secs (minimum 60s). Static --slave-zone",
  "        entries are never removed by catalog reconcile. --sign-key DIR signs each",
  "        zone in memory at load (DNS-6.3 online inline signing, keys K<zone>.+*",
  "        in DIR; --nsec3 for NSEC3) and attaches RRSIG to DNSSEC-OK (DO)",
  "        answers. Answers A/AAAA/",
  "        NS/SOA/MX/TXT/PTR/CNAME/DNAME (CNAME chased, DNAME synthesizes",
  "        an owner-substituted CNAME for descendants only, wildcards, in-bailiwick glue,",
  "        NXDOMAIN/NODATA/REFUSED, AA flag) over UDP+TCP. AXFR/IXFR (TCP, IXFR",
  "        served as a full AXFR per RFC 1995) is gated by",
  "        --allow-transfer (deny by default). TSIG HMAC-SHA256 keys can be",
  "        supplied inline or from a key file; --require-tsig refuses unsigned",
  "        transfer/update requests and --transfer-key selects the outbound signing key.",
  "        RFC 2136 UPDATE is accepted over TCP from --allow-update CIDRs",
  "        (deny by default), mutates the in-memory zone, bumps the SOA serial,",
  "        and records the old-to-new delta for IXFR journal service.",
  "        --also-notify sends RFC 1996 NOTIFY to each secondary at load.",
  "        UDP answers are response-rate-limited per IPv4 /24 or IPv6 /64",
  "        by default (15 rps, 5s window, slip every 2nd over-limit answer to TC=1);",
  "        use --rrl-rps/--rrl-window/--rrl-slip or --no-rrl to tune.",
  "        --control PATH opens an rndc-shaped",
  "        UNIX control socket (status/stats/serial/reload/stop). --tls-listen",
  "        adds DNS-over-TLS (RFC 7858) using the same DNS TCP framing.",
  "        --doh-listen adds DNS-over-HTTP(S) on --doh-path (default /dns-query);",
  "        without --doh-cert/--doh-key it is cleartext HTTP for a reverse proxy.",
  "        The listener accepts HTTP/1.1 and HTTP/2 DoH POSTs. Cleartext HTTP/2",
  "        uses prior-knowledge h2c; HTTPS advertises ALPN h2/http/1.1.",
  "        --doq-listen adds DNS-over-QUIC when Bash is built with",
  "        BASH_OS_DOQ=1 and the ngtcp2/aws-lc adapter. Default builds fail",
  "        closed with backend=none. DoQ requires --doq-cert and --doq-key.",
  "        --max-queries N exits after N queries.",
  "    dns catalog-members --zone FILE [--origin NAME]",
  "        Host-safe RFC 9432 catalog parser: prints version=, member=<apex>",
  "        id=<unique> group=<name> rows, and rejected=N.",
  "    dns catalog-reconcile --catalog FILE [--origin NAME]",
  "        [--current SPEC,SPEC,...] [--default-primary IP[:PORT]]",
  "        [--default-key KEYNAME] [--catalog-group NAME]",
  "        Host-safe reconcile planner. Prefix catalog-owned current entries",
  "        as id@APEX:PRIMARY[,PRIMARY...]; plain specs are static.",
  "    dns slave-verify-chain --zone FILE --key NAME:hmac-sha256:BASE64",
  "        Host-safe transfer-in TSIG response-chain verification probe.",
  "    dns notify --zone NAME --to IP[:PORT]... [--serial N] [--timeout MS]",
  "                   [--retries N] [--no-wait]",
  "                   [--tsig-key NAME:hmac-sha256:BASE64] [--tsig-keys FILE]",
  "                   [--transfer-key NAME]",
  "        Send an RFC 1996 NOTIFY (opcode 4, AA) for NAME to each secondary so",
  "        it re-checks the SOA and transfers. --serial embeds the SOA serial in",
  "        the answer section; waits for the NOTIFY response (prints ack/",
  "        no-response) unless --no-wait. With TSIG keys, NOTIFY is signed and",
  "        signed responses are verified. Exit nonzero if any target failed.",
  "    dns rndc --socket PATH COMMAND",
  "        Control an auth-serve daemon via its --control socket. COMMAND is one",
  "        of status, stats, serial, reload (re-read the zone file) or stop;",
  "        prints the daemon's reply. Exit nonzero on error.",
  "    dns resolv-conf",
  "        Print parsed nameservers and options (TSV: nameserver plus options",
  "        ndots/attempts/timeout/rotate). Queries fall back across parsed",
  "        nameservers in order.",
  "        Nameserver rows carry active|fallback state labels.",
  "        Reads BASHDNS_RESOLV_CONF if set, else /etc/resolv.conf.",
  "",
  "Default nameserver: first `nameserver` in /etc/resolv.conf",
  "(BASHDNS_RESOLV_CONF overrides the path for hermetic tests).",
  "Resolver search order honors `search`, `domain`, and `options ndots:N`.",
  "Resolver options attempts:N, timeout:N, rotate are honored; single-request",
  "and no-tld-query are accepted no-ops.",
  "Default timeout: 2000 ms. UDP/TCP transport supports IPv4 and IPv6 literals.",
  "DNSSEC v2: EDNS0 DO request, DNSSEC RR parsing, AD-bit status/requirement, trust-anchor metadata,",
  "iterative RRSIG chain validation via --validate (algos 5/7/8/10/13/14/15/16;",
  "signed NSEC/NSEC3 denial and wildcard proofs are accepted).",
  "SVCB (TYPE 64) and HTTPS (TYPE 65) parsing emits priority, target, alpn, port, ipv4hint, ipv6hint.",
  "DoT (RFC 7858) via --dot wraps the query in TLS through crypto tls connect;",
  "default DoT host is 1.1.1.1:853 and cert verification fails closed.",
  "DoH (RFC 8484 POST) via --doh posts application/dns-message through curl;",
  "default DoH endpoint is https://cloudflare-dns.com/dns-query.",
  "BASHDNS_FIXTURE_DIR=DIR feeds the wire fetch from <NAME>.<TYPE>.bin files for hermetic tests.",
  "BASHDNS_0X20=0 disables default DNS-0x20 query-name case randomization on real fetches.",
  "BASHDNS_DOT_CMD=CMD substitutes the TLS transport for hermetic DoT tests.",
  "BASHDNS_DOH_CMD=CMD substitutes the HTTPS transport for hermetic DoH tests.",
  "BASHDNS_SERVER_PORT=N uses a non-53 UDP/TCP nameserver port for tests.",
  "BASHDNS_RATELIMIT_QPS=N caps per-upstream queries-per-second (default 50; 0 disables).",
  (char *)NULL
};

struct builtin dns_struct = {
  "dns",
  dns_builtin,
  BUILTIN_ENABLED,
  dns_doc,
  "dns A|AAAA|MX|TXT|... HOST [-s SERVER] [-t TIMEOUT_MS] [-d] [--validate] [--skew SEC]",
  0
};
