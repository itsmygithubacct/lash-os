/* SPDX-License-Identifier: MIT */
/* ntp.c — SNTP/NTPv4 client + lightweight daemon. Loadable for bash.
 *
 * Stage A.9 of the bash-os deployable-distro track. Implements a usable
 * subset of RFC 5905: one-shot query (mode 3, client), multi-server
 * median offset, a stateless SNTP server (mode 4), and a
 * sv-compatible run loop that periodically resyncs the wall clock
 * via adjtime(2) for small offsets and clock_settime(2) for larger
 * corrections. Optional kernel discipline uses ntp_adjtime/adjtimex
 * only when explicitly requested.
 *
 * Subcommands:
 *     ntp query SERVER [-t MS] [-p PORT]
 *         Send a single SNTP request, print "offset=<sec>.<ns>
 *         delay=<sec>.<ns> stratum=N server=IP" on success.
 *         SERVER may be nts:HOST for opt-in NTS.
 *
 *     ntp sync [-s SERVER]... [-t MS] [-n] [-l LIMIT] [-P POLLS]
 *         Query each server (at least one), take the median offset,
 *         and apply via clock_settime(CLOCK_REALTIME, ...) unless -n
 *         is given. -l clamps the maximum applied offset (seconds).
 *
 *     ntp run [-d DIR] [-i SECS] [-c CONFIG]
 *         Daemon mode: read CONFIG (defaults to /etc/ntp.conf),
 *         loop calling `sync` every SECS (default 1024s).
 *
 *     ntp serve [-S ADDR[:PORT]] [--stratum N] [--refid STR]
 *                   [--leap 0|1|2|3] [--leapfile PATH] [--strict-leap]
 *                   [--refclock SPEC] [--keyfile PATH] [--once] [--max N]
 *         Stateless SNTP server. Answers mode-3 requests with mode-4
 *         responses using the local CLOCK_REALTIME as response time; an
 *         opt-in refclock derives stratum/refid from a fresh PPS/GPS pulse.
 *
 * Config file format (/etc/ntp.conf):
 *     # comments
 *     server <host-or-ip>             # prefix nts: for opt-in NTS
 *     interval <seconds>            # default sync interval
 *     limit <seconds>               # max single-step (default 1000)
 *     timeout <ms>                  # per-query timeout (default 2000)
 *     polls <N>                     # samples/server, best delay wins (default 4)
 *     step_threshold <seconds>      # daemon slew below this (default 0.128)
 *     discipline <slew|step|kernel> # kernel uses adjtimex/ntp_adjtime
 *     discipline_loop <pll|fll>      # kernel loop status flag (default pll)
 *     leapfile <path>               # NIST/IERS leap-seconds.list source
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
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/random.h>
#if defined (__linux__) && defined (__has_include)
#  if __has_include (<sys/timex.h>)
#    include <sys/timex.h>
#    define BNTP_HAVE_TIMEX 1
#  endif
#endif
#if defined (__linux__) && defined (__has_include)
#  if __has_include (<linux/pps.h>)
#    include <linux/pps.h>
#    include <sys/ioctl.h>
#    define BNTP_HAVE_LINUX_PPS 1
#  endif
#endif

#include "loadables.h"
#include "_bashcrypto_aead.h"
#include "_mbedtls_hmac.h"

#define BNTP_PORT 123
#define BNTP_NTS_KE_PORT 4460
#define BNTP_PKT_LEN 48
#define BNTP_NTS_MAX_PACKET 4096
#define BNTP_EF_UNIQUE_ID 0x0104
#define BNTP_EF_NTS_COOKIE 0x0204
#define BNTP_EF_NTS_COOKIE_PLACEHOLDER 0x0304
#define BNTP_EF_NTS_AUTH 0x0404
/* Seconds from NTP epoch (1900-01-01) to Unix epoch (1970-01-01). */
#define BNTP_UNIX_OFFSET 2208988800UL
#define BNTP_REFCLOCK_MAX_AGE_SEC 2.0
#define BNTP_REFCLOCK_MOCK_MAX 512
#define BNTP_LEAP_MAX_EVENTS 64
#define BNTP_LEAP_DAY 86400ULL
#define BNTP_MAX_KEYS 16
#define BNTP_MAC_SHA256_LEN 32
/* RFC 5905 §10 PANIC threshold. The RFC text gives 1000s; we round up
 * to 1024s to match this daemon's default sync interval. Offsets that
 * exceed this in either direction are refused unless the operator
 * passes --allow-big-jump, on the assumption that a >17-minute step at
 * runtime almost always indicates server misconfiguration or attack
 * rather than legitimate drift. */
#define BNTP_PANIC_THRESHOLD 1024.0
#define BNTP_DEFAULT_POLLS 4
#define BNTP_MAX_POLLS 8
#define BNTP_STEP_THRESHOLD 0.128
#define BNTP_KOD_RATE (-2)

/* NTPv4 packet (RFC 5905 §7.3); only the first 48 bytes (no auth). */
struct bntp_pkt {
  unsigned char li_vn_mode;   /* leap (2) | version (3) | mode (3) */
  unsigned char stratum;
  unsigned char poll;
  signed char   precision;
  unsigned int  root_delay;
  unsigned int  root_dispersion;
  unsigned int  ref_id;
  unsigned int  ref_ts_sec, ref_ts_frac;
  unsigned int  orig_ts_sec, orig_ts_frac;
  unsigned int  recv_ts_sec, recv_ts_frac;
  unsigned int  xmit_ts_sec, xmit_ts_frac;
};

struct bntp_result {
  double offset;            /* server clock - local clock, seconds */
  double delay;             /* round-trip delay, seconds */
  unsigned stratum;
  char server[64];
  char kod[5];
};

struct bntp_server_cfg {
  unsigned char stratum;
  unsigned char leap;
  signed char precision;
  char refid[4];
};

struct bntp_leap_event {
  unsigned long long ntp_ts;
  int tai_utc;
  int li;
};

struct bntp_leap_table {
  unsigned long long last_update;
  unsigned long long expiry;
  int nevents;
  int stale;
  struct bntp_leap_event events[BNTP_LEAP_MAX_EVENTS];
};

struct bntp_clock_state {
  double offset;
  double freq_ppm;
  long freq_scaled;
  long esterror;
  long maxerror;
  unsigned char leap;
};

enum bntp_discipline_mode {
  BNTP_DISC_SLEW = 0,
  BNTP_DISC_STEP,
  BNTP_DISC_KERNEL
};

struct bntp_mac_key {
  unsigned keyid;
  unsigned char key[128];
  size_t key_len;
};

struct bntp_keyring {
  int nkeys;
  struct bntp_mac_key keys[BNTP_MAX_KEYS];
};

struct bntp_refclock_sample {
  struct timespec pulse;
  int valid;
  char refid[4];
};

struct bntp_nts_state {
  int ready;
  char *ntp_host;
  int ntp_port;
  unsigned char c2s[32];
  unsigned char s2c[32];
  unsigned char *cookies[BC_NTS_MAX_COOKIES];
  size_t cookie_lens[BC_NTS_MAX_COOKIES];
  size_t cookie_count;
};

static volatile sig_atomic_t bntp_stop = 0;

static void
bntp_sig (int sig)
{
  (void) sig;
  bntp_stop = 1;
}

static void
bntp_random_bits (unsigned *x)
{
  unsigned v = 0;
  ssize_t n;
  do
    n = getrandom (&v, sizeof v, 0);
  while (n < 0 && errno == EINTR);
  if (n != (ssize_t) sizeof v)
    {
      struct timespec ts;
      clock_gettime (CLOCK_REALTIME, &ts);
      v = (unsigned) ts.tv_nsec ^ (unsigned) ts.tv_sec ^ (unsigned) getpid ();
    }
  *x = v;
}

static int
bntp_random_bytes (unsigned char *buf, size_t len)
{
  size_t off = 0;
  while (off < len)
    {
      ssize_t n;
      do
        n = getrandom (buf + off, len - off, 0);
      while (n < 0 && errno == EINTR);
      if (n < 0)
        break;
      if (n == 0)
        break;
      off += (size_t) n;
    }
  if (off == len)
    return 0;

  struct timespec ts;
  clock_gettime (CLOCK_REALTIME, &ts);
  unsigned x = (unsigned) ts.tv_nsec ^ (unsigned) ts.tv_sec ^ (unsigned) getpid ();
  for (; off < len; off++)
    {
      x = x * 1103515245U + 12345U;
      buf[off] = (unsigned char) (x >> 16);
    }
  return 0;
}

static void
bntp_put_u16 (unsigned char *p, unsigned v)
{
  p[0] = (unsigned char) ((v >> 8) & 0xff);
  p[1] = (unsigned char) (v & 0xff);
}

static unsigned
bntp_get_u16 (const unsigned char *p)
{
  return ((unsigned) p[0] << 8) | (unsigned) p[1];
}

static void
bntp_put_u32 (unsigned char *p, unsigned v)
{
  p[0] = (unsigned char) ((v >> 24) & 0xff);
  p[1] = (unsigned char) ((v >> 16) & 0xff);
  p[2] = (unsigned char) ((v >> 8) & 0xff);
  p[3] = (unsigned char) (v & 0xff);
}

static unsigned
bntp_get_u32 (const unsigned char *p)
{
  return ((unsigned) p[0] << 24) | ((unsigned) p[1] << 16)
         | ((unsigned) p[2] << 8) | (unsigned) p[3];
}

static size_t
bntp_pad4 (size_t n)
{
  return (n + 3U) & ~(size_t) 3U;
}

static int
bntp_append (unsigned char **buf, size_t *len, size_t *cap,
             const unsigned char *src, size_t n)
{
  if (*len > ((size_t) -1) - n)
    return -1;
  if (*len + n > *cap)
    {
      size_t nc = *cap ? *cap * 2 : 128;
      while (nc < *len + n)
        nc *= 2;
      unsigned char *p = realloc (*buf, nc);
      if (!p)
        return -1;
      *buf = p;
      *cap = nc;
    }
  if (n)
    memcpy (*buf + *len, src, n);
  *len += n;
  return 0;
}

static int
bntp_append_ef (unsigned char **buf, size_t *len, size_t *cap,
                unsigned type, const unsigned char *body, size_t body_len)
{
  size_t padded = bntp_pad4 (body_len);
  size_t flen = 4 + padded;
  unsigned char hdr[4];
  if (flen > 65535)
    return -1;
  bntp_put_u16 (hdr, type);
  bntp_put_u16 (hdr + 2, (unsigned) flen);
  if (bntp_append (buf, len, cap, hdr, sizeof hdr) < 0)
    return -1;
  if (bntp_append (buf, len, cap, body, body_len) < 0)
    return -1;
  if (padded > body_len)
    {
      unsigned char z[3] = { 0, 0, 0 };
      if (bntp_append (buf, len, cap, z, padded - body_len) < 0)
        return -1;
    }
  return 0;
}

static unsigned short
bntp_env_port (const char *name, unsigned short fallback)
{
  const char *s = getenv (name);
  char *end = NULL;
  unsigned long v;
  if (!s || !*s) return fallback;
  errno = 0;
  v = strtoul (s, &end, 10);
  if (errno != 0 || !end || *end || v < 1 || v > 65535)
    return fallback;
  return (unsigned short) v;
}

static double
bntp_env_seconds (const char *name, double fallback, double min, double max)
{
  const char *s = getenv (name);
  char *end = NULL;
  double v;
  if (!s || !*s) return fallback;
  errno = 0;
  v = strtod (s, &end);
  if (errno != 0 || !end || *end || v < min || v > max)
    return fallback;
  return v;
}

static int
bntp_bind_client_port (int fd, int family)
{
  unsigned short port = bntp_env_port ("BASHNTP_CLIENT_PORT", 0);
  if (port == 0) return 0;
  if (family == AF_INET)
    {
      struct sockaddr_in sa;
      memset (&sa, 0, sizeof sa);
      sa.sin_family = AF_INET;
      sa.sin_addr.s_addr = htonl (INADDR_ANY);
      sa.sin_port = htons (port);
      if (bind (fd, (struct sockaddr *) &sa, sizeof sa) < 0)
        return -1;
      return 0;
    }
  if (family == AF_INET6)
    {
      struct sockaddr_in6 sa6;
      memset (&sa6, 0, sizeof sa6);
      sa6.sin6_family = AF_INET6;
      sa6.sin6_addr = in6addr_any;
      sa6.sin6_port = htons (port);
      if (bind (fd, (struct sockaddr *) &sa6, sizeof sa6) < 0)
        return -1;
      return 0;
    }
  return 0;
}

/* Convert struct timespec to NTP 64-bit timestamp (sec.frac). */
static void
ts_to_ntp (const struct timespec *ts, unsigned *sec, unsigned *frac)
{
  *sec = htonl ((unsigned) ((unsigned long) ts->tv_sec + BNTP_UNIX_OFFSET));
  /* Fractional part: nanos * 2^32 / 1e9. */
  double f = (double) ts->tv_nsec * 4.294967296;
  *frac = htonl ((unsigned) f);
}

/* Convert NTP 64-bit timestamp (network order) to double seconds since Unix epoch. */
static double
ntp_to_unix (unsigned sec_net, unsigned frac_net)
{
  unsigned long sec = ntohl (sec_net);
  unsigned long frac = ntohl (frac_net);
  if (sec == 0 && frac == 0) return 0.0;
  double t = (double) sec - (double) BNTP_UNIX_OFFSET;
  t += (double) frac / 4294967296.0;
  return t;
}

static double
ts_to_unix (const struct timespec *ts)
{
  return (double) ts->tv_sec + (double) ts->tv_nsec / 1e9;
}

static unsigned long long
bntp_unix_to_ntp_now (void)
{
  struct timespec ts;
  if (clock_gettime (CLOCK_REALTIME, &ts) < 0)
    return 0;
  return (unsigned long long) ts.tv_sec + BNTP_UNIX_OFFSET;
}

static int
bntp_leap_cmp (const void *a, const void *b)
{
  const struct bntp_leap_event *ea = (const struct bntp_leap_event *) a;
  const struct bntp_leap_event *eb = (const struct bntp_leap_event *) b;
  return (ea->ntp_ts > eb->ntp_ts) - (ea->ntp_ts < eb->ntp_ts);
}

static int
bntp_leap_load_text (const char *text, struct bntp_leap_table *tbl)
{
  char *copy, *p;
  int prev_tai = -1;

  memset (tbl, 0, sizeof *tbl);
  if (!text)
    return -1;
  copy = strdup (text);
  if (!copy)
    return -1;
  p = copy;
  while (*p)
    {
      char *eol = strchr (p, '\n');
      if (eol) *eol = '\0';
      char *line = p;
      while (*line == ' ' || *line == '\t') line++;
      if (line[0] == '#' && line[1] == '$')
        tbl->last_update = strtoull (line + 2, NULL, 10);
      else if (line[0] == '#' && line[1] == '@')
        tbl->expiry = strtoull (line + 2, NULL, 10);
      else if (*line && *line != '#')
        {
          char *end = NULL;
          unsigned long long ts = strtoull (line, &end, 10);
          while (end && (*end == ' ' || *end == '\t')) end++;
          if (end && isdigit ((unsigned char) *end) && tbl->nevents < BNTP_LEAP_MAX_EVENTS)
            {
              long tai = strtol (end, NULL, 10);
              struct bntp_leap_event *ev = &tbl->events[tbl->nevents++];
              ev->ntp_ts = ts;
              ev->tai_utc = (int) tai;
              ev->li = (prev_tai >= 0 && ev->tai_utc < prev_tai) ? 2 : 1;
              prev_tai = ev->tai_utc;
            }
        }
      if (!eol) break;
      p = eol + 1;
    }
  free (copy);
  qsort (tbl->events, (size_t) tbl->nevents, sizeof tbl->events[0], bntp_leap_cmp);
  prev_tai = -1;
  for (int i = 0; i < tbl->nevents; i++)
    {
      tbl->events[i].li = (prev_tai >= 0 && tbl->events[i].tai_utc < prev_tai) ? 2 : 1;
      prev_tai = tbl->events[i].tai_utc;
    }
  return tbl->nevents > 0 ? 0 : -1;
}

static int
bntp_leap_load (const char *path, struct bntp_leap_table *tbl)
{
  const char *mock = getenv ("BASHNTP_LEAP_MOCK");
  if (mock && *mock)
    return bntp_leap_load_text (mock, tbl);

  FILE *f = fopen (path ? path : "/etc/ntp.leap", "r");
  char *buf;
  long sz;
  size_t n;
  int rc;
  if (!f)
    return -1;
  if (fseek (f, 0, SEEK_END) < 0 || (sz = ftell (f)) < 0 || sz > 65536
      || fseek (f, 0, SEEK_SET) < 0)
    { fclose (f); return -1; }
  buf = (char *) malloc ((size_t) sz + 1);
  if (!buf)
    { fclose (f); return -1; }
  n = fread (buf, 1, (size_t) sz, f);
  fclose (f);
  buf[n] = '\0';
  rc = bntp_leap_load_text (buf, tbl);
  free (buf);
  return rc;
}

static unsigned char
bntp_leap_for (unsigned long long now_ntp, struct bntp_leap_table *tbl)
{
  tbl->stale = 0;
  if (tbl->expiry && now_ntp > tbl->expiry)
    {
      tbl->stale = 1;
      return 0;
    }
  for (int i = 0; i < tbl->nevents; i++)
    {
      unsigned long long event = tbl->events[i].ntp_ts;
      unsigned long long start = event > BNTP_LEAP_DAY ? event - BNTP_LEAP_DAY : 0;
      if (now_ntp >= start && now_ntp < event)
        return (unsigned char) tbl->events[i].li;
    }
  return 0;
}

static void
bntp_warn_leap (unsigned li, const char *server)
{
  if (li == 1)
    builtin_warning ("query: server %s reports leap insertion pending (LI=1)", server);
  else if (li == 2)
    builtin_warning ("query: server %s reports leap deletion pending (LI=2)", server);
}

static void
bntp_build_response (const struct bntp_pkt *req,
                     const struct timespec *recv_ts,
                     const struct timespec *xmit_ts,
                     const struct bntp_server_cfg *cfg,
                     struct bntp_pkt *out)
{
  memset (out, 0, sizeof *out);
  out->li_vn_mode = (unsigned char) (((cfg->leap & 0x03) << 6) | (4 << 3) | 4);
  out->stratum = cfg->stratum;
  out->poll = req->poll;
  out->precision = cfg->precision;
  memcpy (&out->ref_id, cfg->refid, sizeof cfg->refid);
  ts_to_ntp (recv_ts, &out->ref_ts_sec, &out->ref_ts_frac);
  out->orig_ts_sec = req->xmit_ts_sec;
  out->orig_ts_frac = req->xmit_ts_frac;
  ts_to_ntp (recv_ts, &out->recv_ts_sec, &out->recv_ts_frac);
  ts_to_ntp (xmit_ts, &out->xmit_ts_sec, &out->xmit_ts_frac);
}

/* Compare two doubles for qsort. */
static int
cmp_double (const void *a, const void *b)
{
  double x = *(const double *) a, y = *(const double *) b;
  return (x > y) - (x < y);
}

/* Print "<secs>.<nanos>" with sign. */
static void
print_secs (double v)
{
  int neg = 0;
  if (v < 0) { neg = 1; v = -v; }
  long long sec = (long long) v;
  long ns = (long) ((v - (double) sec) * 1e9);
  if (ns < 0) ns = 0;
  if (ns > 999999999L) ns = 999999999L;
  printf ("%s%lld.%09ld", neg ? "-" : "", sec, ns);
}

static void
bntp_wipe (void *p, size_t n)
{
  volatile unsigned char *q = (volatile unsigned char *) p;
  while (n--)
    *q++ = 0;
}

static void
bntp_nts_state_clear (struct bntp_nts_state *st)
{
  if (!st)
    return;
  free (st->ntp_host);
  st->ntp_host = NULL;
  for (size_t i = 0; i < st->cookie_count && i < BC_NTS_MAX_COOKIES; i++)
    {
      if (st->cookies[i])
        {
          bntp_wipe (st->cookies[i], st->cookie_lens[i]);
          free (st->cookies[i]);
          st->cookies[i] = NULL;
        }
      st->cookie_lens[i] = 0;
    }
  bntp_wipe (st->c2s, sizeof st->c2s);
  bntp_wipe (st->s2c, sizeof st->s2c);
  st->cookie_count = 0;
  st->ntp_port = 0;
  st->ready = 0;
}

static int
bntp_nts_cookie_push (struct bntp_nts_state *st,
                      const unsigned char *cookie, size_t cookie_len)
{
  if (!st || !cookie || cookie_len == 0)
    return -1;
  if (st->cookie_count >= BC_NTS_MAX_COOKIES)
    {
      bntp_wipe (st->cookies[0], st->cookie_lens[0]);
      free (st->cookies[0]);
      for (size_t i = 1; i < st->cookie_count; i++)
        {
          st->cookies[i - 1] = st->cookies[i];
          st->cookie_lens[i - 1] = st->cookie_lens[i];
        }
      st->cookie_count--;
    }
  unsigned char *copy = malloc (cookie_len);
  if (!copy)
    return -1;
  memcpy (copy, cookie, cookie_len);
  st->cookies[st->cookie_count] = copy;
  st->cookie_lens[st->cookie_count] = cookie_len;
  st->cookie_count++;
  return 0;
}

static int
bntp_nts_cookie_pop (struct bntp_nts_state *st,
                     unsigned char **cookie, size_t *cookie_len)
{
  if (!st || st->cookie_count == 0 || !cookie || !cookie_len)
    return -1;
  *cookie = st->cookies[0];
  *cookie_len = st->cookie_lens[0];
  for (size_t i = 1; i < st->cookie_count; i++)
    {
      st->cookies[i - 1] = st->cookies[i];
      st->cookie_lens[i - 1] = st->cookie_lens[i];
    }
  st->cookie_count--;
  st->cookies[st->cookie_count] = NULL;
  st->cookie_lens[st->cookie_count] = 0;
  return 0;
}

static int
bntp_nts_bootstrap (struct bntp_nts_state *st, const char *server,
                    int timeout_ms)
{
  if (!st || !server || !*server)
    return -1;
  if (st->ready && st->cookie_count > 0)
    return 0;

  bntp_nts_state_clear (st);
  struct bc_nts_ke_result nts;
  memset (&nts, 0, sizeof nts);
  if (bc_nts_ke_run (server, NULL, NULL, timeout_ms, &nts) < 0)
    {
      builtin_error ("query: nts-ke failed for %s", server);
      return -1;
    }
  if (nts.cookie_count == 0 || !nts.ntp_host)
    {
      bc_nts_ke_result_free (&nts);
      builtin_error ("query: nts-ke returned no NTP cookie");
      return -1;
    }

  st->ntp_host = nts.ntp_host;
  nts.ntp_host = NULL;
  st->ntp_port = nts.ntp_port;
  memcpy (st->c2s, nts.c2s, sizeof st->c2s);
  memcpy (st->s2c, nts.s2c, sizeof st->s2c);
  for (size_t i = 0; i < nts.cookie_count && i < BC_NTS_MAX_COOKIES; i++)
    {
      st->cookies[st->cookie_count] = nts.cookies[i];
      st->cookie_lens[st->cookie_count] = nts.cookie_lens[i];
      st->cookie_count++;
      nts.cookies[i] = NULL;
      nts.cookie_lens[i] = 0;
    }
  st->ready = 1;
  bc_nts_ke_result_free (&nts);
  return 0;
}

static int
bntp_nts_store_plaintext (struct bntp_nts_state *st,
                          const unsigned char *pt, size_t pt_len)
{
  size_t off = 0;
  int cookies = 0;
  while (off < pt_len)
    {
      if (off + 4 > pt_len)
        return -1;
      unsigned type = bntp_get_u16 (pt + off);
      unsigned flen = bntp_get_u16 (pt + off + 2);
      if (flen < 4 || (flen & 3) || off + flen > pt_len)
        return -1;
      const unsigned char *body = pt + off + 4;
      size_t body_len = flen - 4;
      if (type == BNTP_EF_NTS_COOKIE)
        {
          cookies++;
          if (st && body_len > 0 &&
              bntp_nts_cookie_push (st, body, body_len) < 0)
            return -1;
        }
      off += flen;
    }
  return cookies;
}

static int
bntp_nts_build_request (const struct bntp_pkt *hdr,
                        const unsigned char *cookie, size_t cookie_len,
                        const unsigned char c2s[32],
                        const unsigned char uid[32],
                        unsigned char **pkt_out, size_t *pkt_len_out)
{
  unsigned char *pkt = NULL, *ct = NULL;
  size_t len = 0, cap = 0, ct_len = 0;
  unsigned char nonce[16];
  unsigned char *placeholder = NULL;
  int rc = -1;

  if (!cookie || cookie_len == 0 || !pkt_out || !pkt_len_out)
    return -1;
  if (bntp_random_bytes (nonce, sizeof nonce) < 0)
    return -1;
  if (bntp_append (&pkt, &len, &cap, (const unsigned char *) hdr, BNTP_PKT_LEN) < 0)
    goto done;
  if (bntp_append_ef (&pkt, &len, &cap, BNTP_EF_UNIQUE_ID, uid, 32) < 0)
    goto done;
  if (bntp_append_ef (&pkt, &len, &cap, BNTP_EF_NTS_COOKIE, cookie, cookie_len) < 0)
    goto done;

  placeholder = calloc (cookie_len ? cookie_len : 1, 1);
  if (!placeholder)
    goto done;
  if (bntp_append_ef (&pkt, &len, &cap, BNTP_EF_NTS_COOKIE_PLACEHOLDER,
                      placeholder, cookie_len) < 0)
    goto done;

  struct bc_aead_iov ad[2] = {
    { pkt, len },
    { nonce, sizeof nonce }
  };
  if (bc_aes_siv_cmac_seal (c2s, ad, 2, (const unsigned char *) "", 0,
                            &ct, &ct_len) < 0)
    goto done;

  size_t nonce_pad = bntp_pad4 (sizeof nonce);
  size_t ct_pad = bntp_pad4 (ct_len);
  size_t body_len = 4 + nonce_pad + ct_pad;
  unsigned char *body = calloc (body_len ? body_len : 1, 1);
  if (!body)
    goto done;
  bntp_put_u16 (body, sizeof nonce);
  bntp_put_u16 (body + 2, (unsigned) ct_len);
  memcpy (body + 4, nonce, sizeof nonce);
  memcpy (body + 4 + nonce_pad, ct, ct_len);
  if (bntp_append_ef (&pkt, &len, &cap, BNTP_EF_NTS_AUTH, body, body_len) == 0)
    {
      *pkt_out = pkt;
      *pkt_len_out = len;
      pkt = NULL;
      rc = 0;
    }
  bntp_wipe (body, body_len);
  free (body);

done:
  bntp_wipe (nonce, sizeof nonce);
  if (ct) { bntp_wipe (ct, ct_len); free (ct); }
  if (placeholder) { bntp_wipe (placeholder, cookie_len); free (placeholder); }
  if (pkt) { bntp_wipe (pkt, len); free (pkt); }
  return rc;
}

static int
bntp_nts_verify_response (const unsigned char *pkt, size_t pkt_len,
                          const unsigned char s2c[32],
                          const unsigned char uid[32],
                          struct bntp_nts_state *st)
{
  if (pkt_len < BNTP_PKT_LEN)
    return -1;
  size_t off = BNTP_PKT_LEN;
  int uid_ok = 0;
  int auth_ok = 0;

  while (off < pkt_len)
    {
      if (off + 4 > pkt_len)
        return -1;
      unsigned type = bntp_get_u16 (pkt + off);
      unsigned flen = bntp_get_u16 (pkt + off + 2);
      if (flen < 4 || (flen & 3) || off + flen > pkt_len)
        return -1;
      const unsigned char *body = pkt + off + 4;
      size_t body_len = flen - 4;

      if (type == BNTP_EF_UNIQUE_ID)
        {
          if (body_len >= 32 && memcmp (body, uid, 32) == 0)
            uid_ok = 1;
        }
      else if (type == BNTP_EF_NTS_AUTH)
        {
          if (body_len < 4)
            return -1;
          unsigned nonce_len = bntp_get_u16 (body);
          unsigned ct_len = bntp_get_u16 (body + 2);
          size_t nonce_pad = bntp_pad4 (nonce_len);
          size_t ct_pad = bntp_pad4 (ct_len);
          if (4 + nonce_pad + ct_pad > body_len || ct_len < 16)
            return -1;
          const unsigned char *nonce = body + 4;
          const unsigned char *ct = body + 4 + nonce_pad;
          struct bc_aead_iov ad[2] = {
            { pkt, off },
            { nonce, nonce_len }
          };
          unsigned char *pt = NULL;
          size_t pt_len = 0;
          if (bc_aes_siv_cmac_open (s2c, ad, 2, ct, ct_len, &pt, &pt_len) < 0)
            return -1;
          int cookies = bntp_nts_store_plaintext (uid_ok ? st : NULL, pt, pt_len);
          bntp_wipe (pt, pt_len ? pt_len : 1);
          free (pt);
          if (cookies < 0)
            return -1;
          auth_ok = 1;
          break;
        }
      off += flen;
    }

  return (uid_ok && auth_ok) ? 0 : -1;
}

static int
bntp_one_nts_with_state (const char *server, int port_override, int timeout_ms,
                         struct bntp_result *out, struct bntp_nts_state *st);

static int
bntp_one_nts (const char *server, int port_override, int timeout_ms,
              struct bntp_result *out);

/* Send one SNTP request and parse the response. */
static int
bntp_one (const char *server, int port, int timeout_ms, struct bntp_result *out)
{
  if (strncmp (server, "nts:", 4) == 0)
    return bntp_one_nts (server + 4, port, timeout_ms, out);

  memset (out, 0, sizeof *out);
  struct addrinfo hints, *ai = NULL, *p;
  memset (&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  char portbuf[16];
  snprintf (portbuf, sizeof portbuf, "%d", port);
  int rc = getaddrinfo (server, portbuf, &hints, &ai);
  if (rc != 0)
    {
      builtin_error ("query: getaddrinfo %s: %s", server, gai_strerror (rc));
      return -1;
    }

  int fd = -1;
  struct sockaddr_storage dst;
  socklen_t dstlen = 0;
  int connected = 0;
  for (p = ai; p; p = p->ai_next)
    {
      if ((size_t) p->ai_addrlen > sizeof dst) continue;
      fd = socket (p->ai_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
      if (fd < 0) continue;
      if (bntp_bind_client_port (fd, p->ai_family) < 0)
        {
          builtin_error ("query: bind client port %u: %s",
                         (unsigned) bntp_env_port ("BASHNTP_CLIENT_PORT", 0),
                         strerror (errno));
          close (fd);
          fd = -1;
          continue;
        }
      memcpy (&dst, p->ai_addr, (size_t) p->ai_addrlen);
      dstlen = (socklen_t) p->ai_addrlen;
      do
        rc = connect (fd, (struct sockaddr *) &dst, dstlen);
      while (rc < 0 && errno == EINTR);
      if (rc == 0) connected = 1;
      break;
    }
  if (fd < 0)
    {
      builtin_error ("query: no usable address for %s", server);
      freeaddrinfo (ai);
      return -1;
    }
  freeaddrinfo (ai);

  if (getnameinfo ((struct sockaddr *) &dst, dstlen, out->server, sizeof out->server,
                   NULL, 0, NI_NUMERICHOST) != 0)
    snprintf (out->server, sizeof out->server, "%s", server);

  /* Build the request: LI=0, VN=4, mode=3 (client) = 0x23. */
  struct bntp_pkt pkt;
  memset (&pkt, 0, sizeof pkt);
  pkt.li_vn_mode = 0x23;
  pkt.stratum = 0;
  pkt.poll = 10;
  pkt.precision = -20;

  struct timespec t1, t4;
  clock_gettime (CLOCK_REALTIME, &t1);
  ts_to_ntp (&t1, &pkt.xmit_ts_sec, &pkt.xmit_ts_frac);
  unsigned rnd;
  bntp_random_bits (&rnd);
  pkt.xmit_ts_frac = htonl (ntohl (pkt.xmit_ts_frac) ^ (rnd & 0x0000ffffU));

  ssize_t sn;
  do
    {
      if (connected)
        sn = send (fd, &pkt, BNTP_PKT_LEN, 0);
      else
        sn = sendto (fd, &pkt, BNTP_PKT_LEN, 0, (struct sockaddr *) &dst, dstlen);
    }
  while (sn < 0 && errno == EINTR);
  if (sn < 0)
    {
      builtin_error ("query: send %s: %s", out->server, strerror (errno));
      close (fd);
      return -1;
    }

  struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
  fd_set rfds;
  int sr;
  do
    {
      FD_ZERO (&rfds); FD_SET (fd, &rfds);
      sr = select (fd + 1, &rfds, NULL, NULL, &tv);
    }
  while (sr < 0 && errno == EINTR);
  if (sr <= 0)
    {
      if (sr < 0)
        builtin_error ("query: select %s: %s", out->server, strerror (errno));
      else
        builtin_error ("query: timeout waiting for %s", out->server);
      close (fd);
      return -1;
    }

  struct bntp_pkt resp;
  ssize_t n;
  do
    n = recv (fd, &resp, sizeof resp, 0);
  while (n < 0 && errno == EINTR);
  clock_gettime (CLOCK_REALTIME, &t4);
  close (fd);
  if (n < 0)
    {
      builtin_error ("query: recv %s: %s", out->server, strerror (errno));
      return -1;
    }
  if (n < (ssize_t) BNTP_PKT_LEN)
    {
      builtin_error ("query: short response from %s (%zd bytes)", out->server, n);
      return -1;
    }

  unsigned mode = resp.li_vn_mode & 0x07;
  unsigned li = (resp.li_vn_mode >> 6) & 0x03;
  if (mode != 4)
    {
      builtin_error ("query: bad mode %u from %s", mode, out->server);
      return -1;
    }
  if (li == 3)
    {
      builtin_error ("query: server %s reports alarm (LI=3, unsynced)", out->server);
      return -1;
    }
  bntp_warn_leap (li, out->server);
  if (resp.stratum == 0)
    {
      /* RFC 5905 §7.4: stratum 0 is the canonical Kiss-o'-Death (KoD)
         signal; the reference identifier carries a 4-byte ASCII code
         naming the specific condition (RATE = back off / longer poll;
         DENY or RSTR = refuse service; ACST / AUTH / AUTO / ... =
         other server states). Reporting the code lets operators tell
         "shorten poll" from "stop polling entirely" without
         consulting a packet capture — chrony/openntpd surface the
         same field. The unified pre-2026-05-18 arm collapsed this
         into the same "stratum N (unusable)" message used for the
         stratum>=16 unsynced ceiling, hiding the distinction. */
      const unsigned char *r = (const unsigned char *) &resp.ref_id;
      char code[5] = { (char) r[0], (char) r[1], (char) r[2], (char) r[3], 0 };
      int printable = 1;
      for (int i = 0; i < 4; i++)
        if (code[i] < 0x20 || code[i] > 0x7e) { printable = 0; break; }
      if (printable)
        {
          snprintf (out->kod, sizeof out->kod, "%s", code);
          builtin_error ("query: server %s stratum 0 (Kiss-o'-Death code '%s', RFC 5905 §7.4)",
                         out->server, code);
          if (strcmp (code, "RATE") == 0) return BNTP_KOD_RATE;
        }
      else
        builtin_error ("query: server %s stratum 0 (Kiss-o'-Death, non-printable refid 0x%02x%02x%02x%02x)",
                       out->server, r[0], r[1], r[2], r[3]);
      return -1;
    }
  if (resp.stratum >= 16)
    {
      builtin_error ("query: server %s stratum %u (unusable)", out->server, resp.stratum);
      return -1;
    }

  if (resp.orig_ts_sec != pkt.xmit_ts_sec ||
      resp.orig_ts_frac != pkt.xmit_ts_frac)
    {
      builtin_error ("query: %s: originate timestamp mismatch", out->server);
      return -1;
    }

  /* Reject missing server timestamps (RFC 5905 §8). */
  if ((resp.recv_ts_sec == 0 && resp.recv_ts_frac == 0) ||
      (resp.xmit_ts_sec == 0 && resp.xmit_ts_frac == 0))
    {
      builtin_error ("query: %s: missing server timestamps", out->server);
      return -1;
    }

  double T1 = ts_to_unix (&t1);
  double T4 = ts_to_unix (&t4);
  double T2 = ntp_to_unix (resp.recv_ts_sec, resp.recv_ts_frac);
  double T3 = ntp_to_unix (resp.xmit_ts_sec, resp.xmit_ts_frac);

  out->offset = ((T2 - T1) + (T3 - T4)) / 2.0;
  out->delay = (T4 - T1) - (T3 - T2);

  /* Reject negative round-trip delay (clock step or falsing). */
  if (out->delay < 0.0)
    {
      builtin_error ("query: %s: negative delay (%.0f ms)", out->server, out->delay * 1000.0);
      return -1;
    }

  out->stratum = resp.stratum;
  return 0;
}

static int
bntp_one_nts_with_state (const char *server, int port_override, int timeout_ms,
                         struct bntp_result *out, struct bntp_nts_state *st)
{
  memset (out, 0, sizeof *out);
  if (!st || bntp_nts_bootstrap (st, server, timeout_ms) < 0)
    return -1;
  if (st->cookie_count == 0 || !st->ntp_host)
    {
      builtin_error ("query: nts-ke returned no NTP cookie");
      bntp_nts_state_clear (st);
      return -1;
    }

  int ntp_port = (port_override == BNTP_PORT) ? st->ntp_port : port_override;
  struct addrinfo hints, *ai = NULL, *p;
  memset (&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  char portbuf[16];
  snprintf (portbuf, sizeof portbuf, "%d", ntp_port);
  int rc = getaddrinfo (st->ntp_host, portbuf, &hints, &ai);
  if (rc != 0)
    {
      builtin_error ("query: getaddrinfo %s: %s", st->ntp_host, gai_strerror (rc));
      return -1;
    }

  int fd = -1;
  struct sockaddr_storage dst;
  socklen_t dstlen = 0;
  for (p = ai; p; p = p->ai_next)
    {
      if ((size_t) p->ai_addrlen > sizeof dst) continue;
      fd = socket (p->ai_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
      if (fd < 0) continue;
      if (bntp_bind_client_port (fd, p->ai_family) < 0)
        {
          builtin_error ("query: bind client port %u: %s",
                         (unsigned) bntp_env_port ("BASHNTP_CLIENT_PORT", 0),
                         strerror (errno));
          close (fd);
          fd = -1;
          continue;
        }
      memcpy (&dst, p->ai_addr, (size_t) p->ai_addrlen);
      dstlen = (socklen_t) p->ai_addrlen;
      do
        rc = connect (fd, (struct sockaddr *) &dst, dstlen);
      while (rc < 0 && errno == EINTR);
      if (rc == 0) break;
      close (fd);
      fd = -1;
    }
  freeaddrinfo (ai);
  if (fd < 0)
    {
      builtin_error ("query: no usable NTS NTP address for %s", st->ntp_host);
      return -1;
    }

  if (getnameinfo ((struct sockaddr *) &dst, dstlen, out->server, sizeof out->server,
                   NULL, 0, NI_NUMERICHOST) != 0)
    snprintf (out->server, sizeof out->server, "%s", st->ntp_host);

  struct bntp_pkt pkt;
  memset (&pkt, 0, sizeof pkt);
  pkt.li_vn_mode = 0x23;
  pkt.stratum = 0;
  pkt.poll = 10;
  pkt.precision = -20;

  struct timespec t1, t4;
  clock_gettime (CLOCK_REALTIME, &t1);
  ts_to_ntp (&t1, &pkt.xmit_ts_sec, &pkt.xmit_ts_frac);
  unsigned rnd;
  bntp_random_bits (&rnd);
  pkt.xmit_ts_frac = htonl (ntohl (pkt.xmit_ts_frac) ^ (rnd & 0x0000ffffU));

  unsigned char uid[32];
  bntp_random_bytes (uid, sizeof uid);
  unsigned char *cookie = NULL;
  size_t cookie_len = 0;
  if (bntp_nts_cookie_pop (st, &cookie, &cookie_len) < 0)
    {
      builtin_error ("query: nts-ke returned no NTP cookie");
      close (fd);
      return -1;
    }
  unsigned char *req = NULL;
  size_t req_len = 0;
  if (bntp_nts_build_request (&pkt, cookie, cookie_len,
                              st->c2s, uid, &req, &req_len) < 0)
    {
      builtin_error ("query: failed to build NTS request");
      bntp_wipe (cookie, cookie_len);
      free (cookie);
      close (fd);
      return -1;
    }
  bntp_wipe (cookie, cookie_len);
  free (cookie);

  ssize_t sn;
  do
    sn = send (fd, req, req_len, 0);
  while (sn < 0 && errno == EINTR);
  bntp_wipe (req, req_len);
  free (req);
  if (sn < 0)
    {
      builtin_error ("query: send %s: %s", out->server, strerror (errno));
      close (fd);
      return -1;
    }

  struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
  fd_set rfds;
  int sr;
  do
    {
      FD_ZERO (&rfds); FD_SET (fd, &rfds);
      sr = select (fd + 1, &rfds, NULL, NULL, &tv);
    }
  while (sr < 0 && errno == EINTR);
  if (sr <= 0)
    {
      if (sr < 0)
        builtin_error ("query: select %s: %s", out->server, strerror (errno));
      else
        builtin_error ("query: timeout waiting for %s", out->server);
      close (fd);
      return -1;
    }

  unsigned char respbuf[BNTP_NTS_MAX_PACKET];
  ssize_t n;
  do
    n = recv (fd, respbuf, sizeof respbuf, 0);
  while (n < 0 && errno == EINTR);
  clock_gettime (CLOCK_REALTIME, &t4);
  close (fd);
  if (n < 0)
    {
      builtin_error ("query: recv %s: %s", out->server, strerror (errno));
      return -1;
    }
  if (n < (ssize_t) BNTP_PKT_LEN)
    {
      builtin_error ("query: short response from %s (%zd bytes)", out->server, n);
      return -1;
    }
  if (bntp_nts_verify_response (respbuf, (size_t) n, st->s2c, uid, st) < 0)
    {
      builtin_error ("query: %s: NTS authenticator verification failed", out->server);
      bntp_nts_state_clear (st);
      return -1;
    }

  struct bntp_pkt resp;
  memcpy (&resp, respbuf, BNTP_PKT_LEN);

  unsigned mode = resp.li_vn_mode & 0x07;
  unsigned li = (resp.li_vn_mode >> 6) & 0x03;
  if (mode != 4)
    {
      builtin_error ("query: bad mode %u from %s", mode, out->server);
      return -1;
    }
  if (li == 3)
    {
      builtin_error ("query: server %s reports alarm (LI=3, unsynced)", out->server);
      return -1;
    }
  bntp_warn_leap (li, out->server);
  if (resp.stratum == 0)
    {
      const unsigned char *r = (const unsigned char *) &resp.ref_id;
      char code[5] = { (char) r[0], (char) r[1], (char) r[2], (char) r[3], 0 };
      int printable = 1;
      for (int i = 0; i < 4; i++)
        if (code[i] < 0x20 || code[i] > 0x7e) { printable = 0; break; }
      if (printable)
        {
          snprintf (out->kod, sizeof out->kod, "%s", code);
          builtin_error ("query: server %s stratum 0 (Kiss-o'-Death code '%s', RFC 5905 §7.4)",
                         out->server, code);
          if (strcmp (code, "RATE") == 0) return BNTP_KOD_RATE;
        }
      else
        builtin_error ("query: server %s stratum 0 (Kiss-o'-Death, non-printable refid 0x%02x%02x%02x%02x)",
                       out->server, r[0], r[1], r[2], r[3]);
      return -1;
    }
  if (resp.stratum >= 16)
    {
      builtin_error ("query: server %s stratum %u (unusable)", out->server, resp.stratum);
      return -1;
    }
  if (resp.orig_ts_sec != pkt.xmit_ts_sec ||
      resp.orig_ts_frac != pkt.xmit_ts_frac)
    {
      builtin_error ("query: %s: originate timestamp mismatch", out->server);
      return -1;
    }
  if ((resp.recv_ts_sec == 0 && resp.recv_ts_frac == 0) ||
      (resp.xmit_ts_sec == 0 && resp.xmit_ts_frac == 0))
    {
      builtin_error ("query: %s: missing server timestamps", out->server);
      return -1;
    }

  double T1 = ts_to_unix (&t1);
  double T4 = ts_to_unix (&t4);
  double T2 = ntp_to_unix (resp.recv_ts_sec, resp.recv_ts_frac);
  double T3 = ntp_to_unix (resp.xmit_ts_sec, resp.xmit_ts_frac);
  out->offset = ((T2 - T1) + (T3 - T4)) / 2.0;
  out->delay = (T4 - T1) - (T3 - T2);
  if (out->delay < 0.0)
    {
      builtin_error ("query: %s: negative delay (%.0f ms)", out->server, out->delay * 1000.0);
      return -1;
    }
  out->stratum = resp.stratum;
  return 0;
}

static int
bntp_one_nts (const char *server, int port_override, int timeout_ms,
              struct bntp_result *out)
{
  struct bntp_nts_state st;
  memset (&st, 0, sizeof st);
  int rc = bntp_one_nts_with_state (server, port_override, timeout_ms, out, &st);
  bntp_nts_state_clear (&st);
  return rc;
}

static int
bntp_poll_best (const char *server, int port, int timeout_ms, int polls,
                struct bntp_result *best, struct bntp_nts_state *nts_state)
{
  int got = 0;
  int saw_rate = 0;
  int is_nts = strncmp (server, "nts:", 4) == 0;
  struct bntp_nts_state local_nts;
  if (is_nts && !nts_state)
    {
      memset (&local_nts, 0, sizeof local_nts);
      nts_state = &local_nts;
    }
  if (polls < 1) polls = 1;
  if (polls > BNTP_MAX_POLLS) polls = BNTP_MAX_POLLS;
  for (int i = 0; i < polls; i++)
    {
      struct bntp_result r;
      int rc = is_nts
        ? bntp_one_nts_with_state (server + 4, port, timeout_ms, &r, nts_state)
        : bntp_one (server, port, timeout_ms, &r);
      if (rc == 0)
        {
          if (!got || r.delay < best->delay)
            *best = r;
          got = 1;
        }
      else if (rc == BNTP_KOD_RATE)
        saw_rate = 1;
    }
  if (is_nts && nts_state == &local_nts)
    bntp_nts_state_clear (&local_nts);
  if (got) return 0;
  return saw_rate ? BNTP_KOD_RATE : -1;
}

static int
bntp_query_cmd (WORD_LIST *args)
{
  const char *server = NULL;
  int timeout_ms = 2000, port = bntp_env_port ("BASHNTP_SERVER_PORT", BNTP_PORT);
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-t") == 0)
        {
          if (!p->next) { builtin_error ("query: -t needs MS"); return EX_USAGE; }
          p = p->next; timeout_ms = atoi (p->word->word);
          if (timeout_ms <= 0) timeout_ms = 2000;
        }
      else if (strcmp (w, "-p") == 0)
        {
          if (!p->next) { builtin_error ("query: -p needs PORT"); return EX_USAGE; }
          p = p->next; port = atoi (p->word->word);
          if (port <= 0 || port > 65535) port = BNTP_PORT;
        }
      else if (!server) server = w;
      else { builtin_error ("query: extra arg %s", w); return EX_USAGE; }
    }
  if (!server) { builtin_error ("query: needs SERVER"); return EX_USAGE; }

  struct bntp_result r;
  if (bntp_one (server, port, timeout_ms, &r) != 0) return EXECUTION_FAILURE;
  printf ("offset=");
  print_secs (r.offset);
  printf (" delay=");
  print_secs (r.delay);
  printf (" stratum=%u server=%s\n", r.stratum, r.server);
  return EXECUTION_SUCCESS;
}

static int
bntp_apply_ex (double offset, double limit, int daemon_mode, int step_always,
               double step_threshold)
{
  if (limit > 0 && (offset > limit || offset < -limit))
    {
      builtin_error ("sync: offset %.6f exceeds limit %.6f — not applying", offset, limit);
      return -1;
    }
  struct timespec now;
  if (clock_gettime (CLOCK_REALTIME, &now) < 0)
    {
      builtin_error ("sync: clock_gettime: %s", strerror (errno));
      return -1;
    }
  double abs_offset = offset < 0 ? -offset : offset;
  if (daemon_mode && !step_always && step_threshold > 0 && abs_offset < step_threshold)
    {
      struct timeval delta;
      delta.tv_sec = (time_t) offset;
      delta.tv_usec = (suseconds_t) ((offset - (double) delta.tv_sec) * 1000000.0);
      if (delta.tv_usec < 0 && delta.tv_sec > 0)
        { delta.tv_sec--; delta.tv_usec += 1000000; }
      if (delta.tv_usec > 0 && delta.tv_sec < 0)
        { delta.tv_sec++; delta.tv_usec -= 1000000; }
      if (adjtime (&delta, NULL) < 0)
        {
          builtin_error ("sync: adjtime: %s", strerror (errno));
          return -1;
        }
      return 0;
    }
  double t = ts_to_unix (&now) + offset;
  struct timespec set = { .tv_sec = (time_t) t, .tv_nsec = (long) ((t - (long long) t) * 1e9) };
  if (set.tv_nsec < 0) { set.tv_sec--; set.tv_nsec += 1000000000L; }
  if (clock_settime (CLOCK_REALTIME, &set) < 0)
    {
      builtin_error ("sync: clock_settime: %s", strerror (errno));
      return -1;
    }
  return 0;
}

static int
bntp_drift_read (const char *statedir, struct bntp_clock_state *st)
{
  char path[256];
  FILE *f;
  long scaled = 0;
  if (!statedir)
    return 0;
  snprintf (path, sizeof path, "%s/drift", statedir);
  f = fopen (path, "r");
  if (!f)
    return 0;
  if (fscanf (f, "freq_scaled=%ld", &scaled) == 1)
    {
      st->freq_scaled = scaled;
      st->freq_ppm = (double) scaled / 65536.0;
    }
  fclose (f);
  return 0;
}

static int
bntp_drift_write (const char *statedir, const struct bntp_clock_state *st)
{
  char path[256];
  FILE *f;
  if (!statedir)
    return 0;
  snprintf (path, sizeof path, "%s/drift", statedir);
  f = fopen (path, "we");
  if (!f)
    return -1;
  fprintf (f, "freq_scaled=%ld\nfreq_ppm=%.9f\n", st->freq_scaled, st->freq_ppm);
  fclose (f);
  return 0;
}

static int
bntp_discipline (double offset, struct bntp_clock_state *st,
                 enum bntp_discipline_mode mode, int use_fll, int dry_run,
                 double limit, double step_threshold, const char *statedir)
{
  double abs_offset = offset < 0 ? -offset : offset;
  st->offset = offset;
  bntp_drift_read (statedir, st);
  if (mode == BNTP_DISC_STEP)
    {
      if (dry_run)
        {
          printf ("discipline dry-run mode=step offset=%.9f live_clock_settime=no live_ntp_adjtime=no\n",
                  offset);
          return 0;
        }
      return bntp_apply_ex (offset, limit, 0, 1, step_threshold);
    }
  if (mode == BNTP_DISC_SLEW)
    {
      if (dry_run)
        {
          printf ("discipline dry-run mode=slew offset=%.9f live_clock_settime=no live_ntp_adjtime=no\n",
                  offset);
          return 0;
        }
      return bntp_apply_ex (offset, limit, 1, 0, step_threshold);
    }

#if defined (BNTP_HAVE_TIMEX)
  struct timex tx;
  memset (&tx, 0, sizeof tx);
  if (abs_offset > step_threshold && step_threshold > 0)
    {
      if (dry_run)
        {
          printf ("discipline dry-run mode=kernel step-reset offset=%.9f live_clock_settime=no live_ntp_adjtime=no\n",
                  offset);
          return 0;
        }
      if (bntp_apply_ex (offset, limit, 0, 1, step_threshold) < 0)
        return -1;
      memset (&tx, 0, sizeof tx);
      tx.modes = MOD_STATUS;
      tx.status = use_fll ? STA_FLL : STA_PLL;
      if (adjtimex (&tx) < 0)
        { builtin_error ("run: adjtimex reset: %s", strerror (errno)); return -1; }
      st->freq_scaled = tx.freq;
      st->freq_ppm = (double) tx.freq / 65536.0;
      return bntp_drift_write (statedir, st);
    }

  tx.modes = MOD_OFFSET | MOD_STATUS;
  tx.offset = (long) (offset * 1000000.0);
  tx.status = use_fll ? STA_FLL : STA_PLL;
  tx.freq = st->freq_scaled;
  if (st->leap == 1)
    tx.status |= STA_INS;
  else if (st->leap == 2)
    tx.status |= STA_DEL;
  if (dry_run)
    {
      printf ("discipline dry-run mode=kernel offset_us=%ld modes=MOD_OFFSET|MOD_STATUS status=%s%s%s freq_ppm=%.9f live_clock_settime=no live_ntp_adjtime=no\n",
              tx.offset,
              use_fll ? "STA_FLL" : "STA_PLL",
              (st->leap == 1) ? "|STA_INS" : "",
              (st->leap == 2) ? "|STA_DEL" : "",
              st->freq_ppm);
      return 0;
    }
  int trc = adjtimex (&tx);
  if (trc < 0)
    { builtin_error ("run: adjtimex: %s", strerror (errno)); return -1; }
  st->freq_scaled = tx.freq;
  st->freq_ppm = (double) tx.freq / 65536.0;
  st->esterror = tx.esterror;
  st->maxerror = tx.maxerror;
  bntp_drift_write (statedir, st);
  if (st->leap == 1 || st->leap == 2)
    printf ("discipline kernel leap_state=%d time_status=%d\n", st->leap, trc);
  return 0;
#else
  if (dry_run)
    {
      printf ("discipline dry-run mode=kernel unsupported live_clock_settime=no live_ntp_adjtime=no\n");
      return 0;
    }
  builtin_error ("run: kernel discipline unavailable on this build");
  return -1;
#endif
}

#define BNTP_MAX_SERVERS 16

static int
bntp_sync_cmd (WORD_LIST *args)
{
  const char *servers[BNTP_MAX_SERVERS];
  int nservers = 0;
  int timeout_ms = 2000;
  int port = bntp_env_port ("BASHNTP_SERVER_PORT", BNTP_PORT);
  int polls = BNTP_DEFAULT_POLLS;
  int dry_run = 0;
  int allow_big_jump = 0;
  int step_always = 0;
  double limit = 1000.0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-s") == 0)
        {
          if (!p->next) { builtin_error ("sync: -s needs SERVER"); return EX_USAGE; }
          p = p->next;
          if (nservers >= BNTP_MAX_SERVERS)
            { builtin_error ("sync: too many servers (max %d)", BNTP_MAX_SERVERS); return EX_USAGE; }
          servers[nservers++] = p->word->word;
        }
      else if (strcmp (w, "-t") == 0)
        {
          if (!p->next) return EX_USAGE;
          p = p->next; timeout_ms = atoi (p->word->word);
          if (timeout_ms <= 0) timeout_ms = 2000;
        }
      else if (strcmp (w, "-n") == 0) dry_run = 1;
      else if (strcmp (w, "-P") == 0 || strcmp (w, "--polls") == 0)
        {
          if (!p->next) return EX_USAGE;
          p = p->next; polls = atoi (p->word->word);
          if (polls < 1) polls = 1;
          if (polls > BNTP_MAX_POLLS) polls = BNTP_MAX_POLLS;
        }
      else if (strcmp (w, "-l") == 0)
        {
          if (!p->next) return EX_USAGE;
          p = p->next; limit = strtod (p->word->word, NULL);
          if (limit < 0) limit = 1000.0;
        }
      else if (strcmp (w, "--allow-big-jump") == 0) allow_big_jump = 1;
      else if (strcmp (w, "--step-always") == 0) step_always = 1;
      else { builtin_error ("sync: extra arg %s", w); return EX_USAGE; }
    }
  if (nservers == 0) { builtin_error ("sync: needs at least one -s SERVER"); return EX_USAGE; }

  double offsets[BNTP_MAX_SERVERS];
  struct bntp_nts_state nts_states[BNTP_MAX_SERVERS];
  memset (nts_states, 0, sizeof nts_states);
  int got = 0;
  for (int i = 0; i < nservers; i++)
    {
      struct bntp_result r;
      struct bntp_nts_state *nts_state =
        strncmp (servers[i], "nts:", 4) == 0 ? &nts_states[i] : NULL;
      if (bntp_poll_best (servers[i], port, timeout_ms, polls, &r, nts_state) == 0)
        offsets[got++] = r.offset;
    }
  if (got == 0)
    {
      for (int i = 0; i < nservers; i++)
        bntp_nts_state_clear (&nts_states[i]);
      builtin_error ("sync: no servers responded");
      return EXECUTION_FAILURE;
    }

  qsort (offsets, (size_t) got, sizeof (double), cmp_double);
  double median = (got & 1) ? offsets[got / 2] : (offsets[got / 2 - 1] + offsets[got / 2]) / 2.0;

  if (!allow_big_jump && (median > BNTP_PANIC_THRESHOLD || median < -BNTP_PANIC_THRESHOLD))
    {
      for (int i = 0; i < nservers; i++)
        bntp_nts_state_clear (&nts_states[i]);
      builtin_error ("sync: |offset| %.6f exceeds panic threshold %.0fs — pass --allow-big-jump to override",
                     median, BNTP_PANIC_THRESHOLD);
      return EXECUTION_FAILURE;
    }

  printf ("offset=");
  print_secs (median);
  printf (" servers=%d/%d", got, nservers);
  if (dry_run) printf (" applied=no");
  else
    {
      if (bntp_apply_ex (median, limit, 0, step_always, BNTP_STEP_THRESHOLD) == 0) printf (" applied=yes");
      else
        {
          for (int i = 0; i < nservers; i++)
            bntp_nts_state_clear (&nts_states[i]);
          printf (" applied=no\n");
          return EXECUTION_FAILURE;
        }
    }
  printf ("\n");
  for (int i = 0; i < nservers; i++)
    bntp_nts_state_clear (&nts_states[i]);
  return EXECUTION_SUCCESS;
}

/* Read /etc/ntp.conf or override. */
struct bntp_cfg {
  const char *servers[BNTP_MAX_SERVERS];
  const char *leapfile;
  char *raw;
  int nservers;
  int interval;
  int retry;        /* sleep after zero-response iteration; 0 = use interval */
  int timeout_ms;
  int polls;
  int step_always;
  enum bntp_discipline_mode discipline;
  int discipline_fll;
  double limit;
  double step_threshold;
};

static int
bntp_load_cfg (const char *path, struct bntp_cfg *c)
{
  memset (c, 0, sizeof *c);
  c->interval = 1024;
  c->retry = 0;             /* 0 means "use interval"; bntp_run_cmd defaults it */
  c->timeout_ms = 2000;
  c->polls = BNTP_DEFAULT_POLLS;
  c->limit = 1000.0;
  c->step_threshold = BNTP_STEP_THRESHOLD;
  c->discipline = BNTP_DISC_SLEW;
  c->discipline_fll = 0;
  FILE *f = fopen (path, "re");
  if (!f) return -1;
  fseek (f, 0, SEEK_END);
  long sz = ftell (f);
  fseek (f, 0, SEEK_SET);
  if (sz < 0 || sz > 16384) { fclose (f); return -1; }
  c->raw = malloc ((size_t) sz + 1);
  if (!c->raw) { fclose (f); return -1; }
  size_t n = fread (c->raw, 1, (size_t) sz, f);
  c->raw[n] = '\0';
  fclose (f);

  char *p = c->raw;
  while (*p)
    {
      char *eol = strchr (p, '\n');
      if (eol) *eol = '\0';
      char *line = p;
      while (*line == ' ' || *line == '\t') line++;
      if (*line && *line != '#')
        {
          char *key = line;
          while (*line && *line != ' ' && *line != '\t') line++;
          if (*line) { *line++ = '\0'; while (*line == ' ' || *line == '\t') line++; }
          char *val = line;
          if (strcmp (key, "server") == 0 && *val && c->nservers < BNTP_MAX_SERVERS)
            c->servers[c->nservers++] = val;
          else if (strcmp (key, "leapfile") == 0 && *val)
            c->leapfile = val;
          else if (strcmp (key, "discipline") == 0 && *val)
            {
              if (strcmp (val, "step") == 0) c->discipline = BNTP_DISC_STEP;
              else if (strcmp (val, "kernel") == 0) c->discipline = BNTP_DISC_KERNEL;
              else c->discipline = BNTP_DISC_SLEW;
            }
          else if (strcmp (key, "discipline_loop") == 0 && *val)
            c->discipline_fll = (strcmp (val, "fll") == 0);
          else if (strcmp (key, "interval") == 0 && *val)
            { int v = atoi (val); if (v > 0) c->interval = v; }
          else if (strcmp (key, "retry") == 0 && *val)
            { int v = atoi (val); if (v > 0) c->retry = v; }
          else if (strcmp (key, "timeout") == 0 && *val)
            { int v = atoi (val); if (v > 0) c->timeout_ms = v; }
          else if (strcmp (key, "polls") == 0 && *val)
            { int v = atoi (val); if (v > 0) c->polls = v > BNTP_MAX_POLLS ? BNTP_MAX_POLLS : v; }
          else if (strcmp (key, "limit") == 0 && *val)
            { double v = strtod (val, NULL); if (v >= 0) c->limit = v; }
          else if (strcmp (key, "step_threshold") == 0 && *val)
            { double v = strtod (val, NULL); if (v >= 0) c->step_threshold = v; }
        }
      if (!eol) break;
      p = eol + 1;
    }
  return c->nservers > 0 ? 0 : -1;
}

static int
bntp_run_cmd (WORD_LIST *args)
{
  const char *cfgpath = "/etc/ntp.conf";
  const char *statedir = NULL;
  int port = bntp_env_port ("BASHNTP_SERVER_PORT", BNTP_PORT);
  int interval_override = 0;
  int once = 0;
  int step_always = 0;
  int dry_run_discipline = 0;
  int run_serve = 0;
  const char *run_serve_spec = NULL;
  enum bntp_discipline_mode discipline_override = BNTP_DISC_SLEW;
  int discipline_set = 0;
  int discipline_fll_override = 0;
  int discipline_fll_set = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-c") == 0)
        {
          if (!p->next) return EX_USAGE;
          p = p->next; cfgpath = p->word->word;
        }
      else if (strcmp (w, "-d") == 0)
        {
          if (!p->next) return EX_USAGE;
          p = p->next; statedir = p->word->word;
        }
      else if (strcmp (w, "-i") == 0)
        {
          if (!p->next) return EX_USAGE;
          p = p->next; interval_override = atoi (p->word->word);
        }
      else if (strcmp (w, "--once") == 0) once = 1;
      else if (strcmp (w, "--step-always") == 0) step_always = 1;
      else if (strcmp (w, "--dry-run-discipline") == 0) dry_run_discipline = 1;
      else if (strcmp (w, "--serve") == 0)
        {
          run_serve = 1;
          if (p->next && p->next->word->word[0] != '-')
            { p = p->next; run_serve_spec = p->word->word; }
        }
      else if (strcmp (w, "--discipline") == 0)
        {
          if (!p->next) return EX_USAGE;
          p = p->next;
          if (strcmp (p->word->word, "step") == 0) discipline_override = BNTP_DISC_STEP;
          else if (strcmp (p->word->word, "slew") == 0) discipline_override = BNTP_DISC_SLEW;
          else if (strcmp (p->word->word, "kernel") == 0) discipline_override = BNTP_DISC_KERNEL;
          else { builtin_error ("run: --discipline must be step, slew, or kernel"); return EX_USAGE; }
          discipline_set = 1;
        }
      else if (strcmp (w, "--discipline-loop") == 0)
        {
          if (!p->next) return EX_USAGE;
          p = p->next;
          if (strcmp (p->word->word, "pll") == 0) discipline_fll_override = 0;
          else if (strcmp (p->word->word, "fll") == 0) discipline_fll_override = 1;
          else { builtin_error ("run: --discipline-loop must be pll or fll"); return EX_USAGE; }
          discipline_fll_set = 1;
        }
      else { builtin_error ("run: extra arg %s", w); return EX_USAGE; }
    }

  struct bntp_cfg cfg;
  if (bntp_load_cfg (cfgpath, &cfg) != 0)
    {
      builtin_error ("run: failed to load %s (no servers configured?)", cfgpath);
      return EXECUTION_FAILURE;
    }
  if (interval_override > 0) cfg.interval = interval_override;
  if (cfg.retry <= 0) cfg.retry = cfg.interval;
  if (step_always) cfg.step_always = 1;
  if (discipline_set) cfg.discipline = discipline_override;
  if (discipline_fll_set) cfg.discipline_fll = discipline_fll_override;
  if (cfg.step_always) cfg.discipline = BNTP_DISC_STEP;

  if (statedir)
    {
      mkdir (statedir, 0755);
      /* Snapshot the loaded config so operators (and offline tests)
       * can observe what the daemon thinks its policy is, without
       * having to wait for a successful sync iteration. */
      char cfg_path[256];
      snprintf (cfg_path, sizeof cfg_path, "%s/cfg", statedir);
      FILE *cf = fopen (cfg_path, "we");
      if (cf)
        {
          fprintf (cf, "interval=%d\nretry=%d\ntimeout=%d\npolls=%d\nlimit=%.6f\nstep_threshold=%.6f\nservers=%d\ndiscipline=%s\ndiscipline_loop=%s\nleapfile=%s\nserve=%s\n",
                   cfg.interval, cfg.retry, cfg.timeout_ms, cfg.polls, cfg.limit,
                   cfg.step_threshold, cfg.nservers,
                   cfg.discipline == BNTP_DISC_KERNEL ? "kernel" :
                   cfg.discipline == BNTP_DISC_STEP ? "step" : "slew",
                   cfg.discipline_fll ? "fll" : "pll",
                   cfg.leapfile ? cfg.leapfile : "",
                   run_serve ? (run_serve_spec ? run_serve_spec : "1") : "0");
          fclose (cf);
        }
    }

  struct sigaction sa;
  memset (&sa, 0, sizeof sa);
  sa.sa_handler = bntp_sig;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction (SIGINT, &sa, NULL);
  sigaction (SIGTERM, &sa, NULL);

  time_t next_ok[BNTP_MAX_SERVERS];
  int backoff[BNTP_MAX_SERVERS];
  for (int i = 0; i < BNTP_MAX_SERVERS; i++)
    {
      next_ok[i] = 0;
      backoff[i] = cfg.interval;
    }
  struct bntp_nts_state nts_states[BNTP_MAX_SERVERS];
  memset (nts_states, 0, sizeof nts_states);
  struct bntp_clock_state clock_state;
  memset (&clock_state, 0, sizeof clock_state);
  bntp_drift_read (statedir, &clock_state);

  do
    {
      double offsets[BNTP_MAX_SERVERS];
      int got = 0;
      time_t now_s = time (NULL);
      for (int i = 0; i < cfg.nservers; i++)
        {
          if (next_ok[i] > now_s) continue;
          struct bntp_result r;
          struct bntp_nts_state *nts_state =
            strncmp (cfg.servers[i], "nts:", 4) == 0 ? &nts_states[i] : NULL;
          int rc = bntp_poll_best (cfg.servers[i], port, cfg.timeout_ms,
                                   cfg.polls, &r, nts_state);
          if (rc == 0)
            {
              offsets[got++] = r.offset;
              backoff[i] = cfg.interval;
            }
          else if (rc == BNTP_KOD_RATE)
            {
              if (backoff[i] < 1) backoff[i] = cfg.interval > 0 ? cfg.interval : 1;
              if (backoff[i] < 86400 / 2) backoff[i] *= 2;
              else backoff[i] = 86400;
              next_ok[i] = now_s + backoff[i];
            }
        }
      if (got > 0)
        {
          qsort (offsets, (size_t) got, sizeof (double), cmp_double);
          double median = (got & 1) ? offsets[got / 2] : (offsets[got / 2 - 1] + offsets[got / 2]) / 2.0;
          if (cfg.leapfile)
            {
              struct bntp_leap_table lt;
              if (bntp_leap_load (cfg.leapfile, &lt) == 0)
                clock_state.leap = bntp_leap_for (bntp_unix_to_ntp_now (), &lt);
            }
          if (bntp_discipline (median, &clock_state, cfg.discipline,
                               cfg.discipline_fll,
                               dry_run_discipline, cfg.limit,
                               cfg.step_threshold, statedir) < 0)
            {
              for (int i = 0; i < cfg.nservers; i++)
                bntp_nts_state_clear (&nts_states[i]);
              free (cfg.raw);
              return EXECUTION_FAILURE;
            }
          if (statedir)
            {
              char path[256];
              snprintf (path, sizeof path, "%s/last", statedir);
              FILE *f = fopen (path, "we");
              if (f)
                {
                  fprintf (f, "offset=%.9f\nservers=%d/%d\nwhen=%ld\n",
                           median, got, cfg.nservers, (long) time (NULL));
                  fclose (f);
                }
            }
        }
      if (once || bntp_stop) break;
      /* Retry policy: on a zero-response iteration, sleep `cfg.retry`
       * (default = `cfg.interval`, can be shortened in /etc/ntp.conf
       * via `retry <N>`).  On a successful iteration, sleep `cfg.interval`.
       * This lets operators shorten the post-failure recheck without
       * also shortening successful-poll cadence (chrony-style behavior). */
      int remaining = (got > 0) ? cfg.interval : cfg.retry;
      while (remaining > 0 && !bntp_stop)
        {
          struct timespec rq = { .tv_sec = remaining > 1 ? 1 : remaining, .tv_nsec = 0 };
          while (nanosleep (&rq, &rq) == -1 && errno == EINTR && !bntp_stop)
            ;
          remaining--;
        }
    }
  while (!bntp_stop);

  for (int i = 0; i < cfg.nservers; i++)
    bntp_nts_state_clear (&nts_states[i]);
  free (cfg.raw);
  return EXECUTION_SUCCESS;
}

static int
bntp_nts_selftest_cmd (WORD_LIST *args)
{
  (void) args;
  unsigned char key[32];
  unsigned char cookie[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02 };
  unsigned char uid[32];
  struct bntp_nts_state st;
  memset (&st, 0, sizeof st);
  for (size_t i = 0; i < sizeof key; i++) key[i] = (unsigned char) i;
  for (size_t i = 0; i < sizeof uid; i++) uid[i] = (unsigned char) (0x80U + i);

  struct bntp_pkt req_hdr;
  memset (&req_hdr, 0, sizeof req_hdr);
  req_hdr.li_vn_mode = 0x23;
  req_hdr.poll = 10;
  req_hdr.precision = -20;
  req_hdr.xmit_ts_sec = htonl (BNTP_UNIX_OFFSET + 1000);
  req_hdr.xmit_ts_frac = htonl (0x12345678U);

  unsigned char *req = NULL;
  size_t req_len = 0;
  if (bntp_nts_build_request (&req_hdr, cookie, sizeof cookie, key, uid, &req, &req_len) < 0)
    { builtin_error ("nts-selftest: request build failed"); return EXECUTION_FAILURE; }
  if (req_len < BNTP_PKT_LEN + 4 ||
      bntp_get_u16 (req + BNTP_PKT_LEN) != BNTP_EF_UNIQUE_ID)
    {
      bntp_wipe (req, req_len);
      free (req);
      builtin_error ("nts-selftest: request EF order failed");
      return EXECUTION_FAILURE;
    }
  bntp_wipe (req, req_len);
  free (req);

  struct bntp_pkt resp_hdr;
  struct bntp_server_cfg cfg = {
    .stratum = 2,
    .leap = 0,
    .precision = -20,
    .refid = { 'N', 'T', 'S', 'T' }
  };
  struct timespec recv_ts = { .tv_sec = 1001, .tv_nsec = 0 };
  struct timespec xmit_ts = { .tv_sec = 1001, .tv_nsec = 1000000 };
  bntp_build_response (&req_hdr, &recv_ts, &xmit_ts, &cfg, &resp_hdr);

  unsigned char *resp = NULL, *ct = NULL;
  size_t resp_len = 0, resp_cap = 0, ct_len = 0;
  unsigned char nonce[16] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
  };
  unsigned char new_cookie[] = { 0xde, 0xad, 0xbe, 0xef };
  unsigned char plain[8];
  bntp_put_u16 (plain, BNTP_EF_NTS_COOKIE);
  bntp_put_u16 (plain + 2, sizeof plain);
  memcpy (plain + 4, new_cookie, sizeof new_cookie);
  if (bntp_append (&resp, &resp_len, &resp_cap, (const unsigned char *) &resp_hdr, BNTP_PKT_LEN) < 0 ||
      bntp_append_ef (&resp, &resp_len, &resp_cap, BNTP_EF_UNIQUE_ID, uid, sizeof uid) < 0)
    goto selftest_fail;
  struct bc_aead_iov ad[2] = {
    { resp, resp_len },
    { nonce, sizeof nonce }
  };
  if (bc_aes_siv_cmac_seal (key, ad, 2, plain, sizeof plain, &ct, &ct_len) < 0)
    goto selftest_fail;
  unsigned char body[4 + 16 + 64];
  if (ct_len > 64)
    goto selftest_fail;
  memset (body, 0, sizeof body);
  bntp_put_u16 (body, sizeof nonce);
  bntp_put_u16 (body + 2, (unsigned) ct_len);
  memcpy (body + 4, nonce, sizeof nonce);
  memcpy (body + 4 + bntp_pad4 (sizeof nonce), ct, ct_len);
  if (bntp_append_ef (&resp, &resp_len, &resp_cap, BNTP_EF_NTS_AUTH,
                      body, 4 + bntp_pad4 (sizeof nonce) + bntp_pad4 (ct_len)) < 0)
    goto selftest_fail;
  if (bntp_nts_verify_response (resp, resp_len, key, uid, &st) != 0)
    goto selftest_fail;
  if (st.cookie_count != 1)
    goto selftest_fail;
  uid[0] ^= 1;
  if (bntp_nts_verify_response (resp, resp_len, key, uid, &st) == 0)
    goto selftest_fail;

  bntp_nts_state_clear (&st);
  bntp_wipe (key, sizeof key);
  if (ct) { bntp_wipe (ct, ct_len); free (ct); }
  if (resp) { bntp_wipe (resp, resp_len); free (resp); }
  printf ("nts-selftest ok\n");
  return EXECUTION_SUCCESS;

selftest_fail:
  bntp_nts_state_clear (&st);
  bntp_wipe (key, sizeof key);
  if (ct) { bntp_wipe (ct, ct_len); free (ct); }
  if (resp) { bntp_wipe (resp, resp_len); free (resp); }
  builtin_error ("nts-selftest: failed");
  return EXECUTION_FAILURE;
}

static void
bntp_hex_dump (const unsigned char *p, size_t n)
{
  static const char h[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++)
    {
      putchar (h[p[i] >> 4]);
      putchar (h[p[i] & 0x0f]);
    }
  putchar ('\n');
}

static int
bntp_serve_encode_fixture (void)
{
  struct bntp_pkt req, resp;
  struct bntp_server_cfg cfg = {
    .stratum = 2,
    .leap = 1,
    .precision = -20,
    .refid = { 'L', 'O', 'C', 'L' }
  };
  struct timespec recv_ts = { .tv_sec = 1000, .tv_nsec = 250000000L };
  struct timespec xmit_ts = { .tv_sec = 1000, .tv_nsec = 500000000L };
  memset (&req, 0, sizeof req);
  req.li_vn_mode = 0x23;
  req.poll = 6;
  req.precision = -20;
  req.xmit_ts_sec = htonl (BNTP_UNIX_OFFSET + 999);
  req.xmit_ts_frac = htonl (0x20000000U);
  bntp_build_response (&req, &recv_ts, &xmit_ts, &cfg, &resp);
  bntp_hex_dump ((const unsigned char *) &resp, BNTP_PKT_LEN);
  return EXECUTION_SUCCESS;
}

static int
bntp_refid_from_string (const char *s, char out[4])
{
  size_t n = strlen (s);
  if (n < 1 || n > 4)
    return -1;
  memset (out, ' ', 4);
  for (size_t i = 0; i < n; i++)
    {
      if ((unsigned char) s[i] < 0x20 || (unsigned char) s[i] > 0x7e)
        return -1;
      out[i] = s[i];
    }
  return 0;
}

static double
bntp_timespec_age (const struct timespec *now, const struct timespec *then)
{
  return (double) (now->tv_sec - then->tv_sec)
         + (double) (now->tv_nsec - then->tv_nsec) / 1e9;
}

static void
bntp_timespec_sub_seconds (struct timespec *ts, double seconds)
{
  time_t whole = (time_t) seconds;
  long nsec = (long) ((seconds - (double) whole) * 1e9 + 0.5);
  ts->tv_sec -= whole;
  ts->tv_nsec -= nsec;
  while (ts->tv_nsec < 0)
    {
      ts->tv_nsec += 1000000000L;
      ts->tv_sec--;
    }
  while (ts->tv_nsec >= 1000000000L)
    {
      ts->tv_nsec -= 1000000000L;
      ts->tv_sec++;
    }
}

static int
bntp_read_small_file (const char *path, char *buf, size_t bufsz)
{
  FILE *f;
  size_t n;
  if (!path || !*path || bufsz == 0)
    return -1;
  f = fopen (path, "r");
  if (!f)
    return -1;
  n = fread (buf, 1, bufsz - 1, f);
  if (ferror (f))
    {
      fclose (f);
      return -1;
    }
  buf[n] = '\0';
  fclose (f);
  return 0;
}

static int
bntp_refclock_parse_mock (const char *text, struct bntp_refclock_sample *out)
{
  char buf[BNTP_REFCLOCK_MOCK_MAX];
  char *save = NULL;
  char *tok;
  int valid = 1;
  double age = 0.0;
  long long pulse_sec = 0;
  unsigned long pulse_nsec = 0;
  int have_pulse = 0;
  size_t n;

  if (!text || !*text || !out)
    return -1;
  n = strlen (text);
  if (n >= sizeof buf)
    return -1;
  memcpy (buf, text, n + 1);

  memset (out, 0, sizeof *out);
  if (bntp_refid_from_string ("PPS", out->refid) < 0)
    return -1;

  for (tok = strtok_r (buf, " \t\r\n", &save); tok;
       tok = strtok_r (NULL, " \t\r\n", &save))
    {
      if (strcmp (tok, "fresh") == 0)
        {
          valid = 1;
          age = 0.0;
        }
      else if (strcmp (tok, "stale") == 0 || strcmp (tok, "invalid") == 0)
        valid = 0;
      else if (strncmp (tok, "valid=", 6) == 0)
        {
          char *end = NULL;
          unsigned long v;
          errno = 0;
          v = strtoul (tok + 6, &end, 10);
          if (errno != 0 || !end || *end || v > 1)
            return -1;
          valid = (int) v;
        }
      else if (strncmp (tok, "age=", 4) == 0)
        {
          char *end = NULL;
          errno = 0;
          age = strtod (tok + 4, &end);
          if (errno != 0 || !end || *end || age < 0.0 || age > 86400.0)
            return -1;
        }
      else if (strncmp (tok, "pulse=", 6) == 0)
        {
          char *v = tok + 6;
          char *dot = strchr (v, '.');
          char *end = NULL;
          errno = 0;
          if (dot)
            *dot = '\0';
          pulse_sec = strtoll (v, &end, 10);
          if (errno != 0 || !end || *end || pulse_sec < 0)
            return -1;
          pulse_nsec = 0;
          if (dot)
            {
              char *ns = dot + 1;
              size_t ns_len = strlen (ns);
              if (ns_len < 1 || ns_len > 9)
                return -1;
              errno = 0;
              pulse_nsec = strtoul (ns, &end, 10);
              if (errno != 0 || !end || *end || pulse_nsec > 999999999UL)
                return -1;
              while (ns_len++ < 9)
                pulse_nsec *= 10;
            }
          have_pulse = 1;
        }
      else if (strncmp (tok, "refid=", 6) == 0)
        {
          if (bntp_refid_from_string (tok + 6, out->refid) < 0)
            return -1;
        }
      else
        return -1;
    }

  if (have_pulse)
    {
      out->pulse.tv_sec = (time_t) pulse_sec;
      out->pulse.tv_nsec = (long) pulse_nsec;
    }
  else
    {
      if (clock_gettime (CLOCK_REALTIME, &out->pulse) < 0)
        return -1;
      bntp_timespec_sub_seconds (&out->pulse, age);
    }
  out->valid = valid;
  return valid ? 0 : -1;
}

static int
bntp_refclock_read_mock (const char *arg, struct bntp_refclock_sample *out)
{
  const char *env = getenv ("BASHNTP_REFCLOCK_MOCK");
  char buf[BNTP_REFCLOCK_MOCK_MAX];

  if (env && *env)
    return bntp_refclock_parse_mock (env, out);
  if (arg && *arg)
    {
      if (bntp_read_small_file (arg, buf, sizeof buf) < 0)
        {
          if (out)
            memset (out, 0, sizeof *out);
          return -1;
        }
      return bntp_refclock_parse_mock (buf, out);
    }
  if (out)
    memset (out, 0, sizeof *out);
  return -1;
}

static int
bntp_nmea_sentence_valid (const char *path)
{
  char buf[BNTP_REFCLOCK_MOCK_MAX];
  if (!path || !*path)
    return 1;
  if (bntp_read_small_file (path, buf, sizeof buf) < 0)
    return 0;
  return (strstr (buf, "$GPRMC") || strstr (buf, "$GNRMC")
          || strstr (buf, "$GPZDA") || strstr (buf, "$GNZDA"));
}

static int
bntp_refclock_read_pps_device (const char *path,
                               struct bntp_refclock_sample *out)
{
  const char *env = getenv ("BASHNTP_PPS_DEVICE");
  if (env && *env)
    path = env;
  if (!path || !*path)
    path = "/dev/pps0";
  if (!out)
    return -1;
  memset (out, 0, sizeof *out);

#ifdef BNTP_HAVE_LINUX_PPS
  int fd = open (path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return -1;
  struct pps_fdata fdata;
  memset (&fdata, 0, sizeof fdata);
  if (ioctl (fd, PPS_FETCH, &fdata) < 0)
    {
      close (fd);
      return -1;
    }
  close (fd);
  out->pulse.tv_sec = (time_t) fdata.info.assert_tu.sec;
  out->pulse.tv_nsec = (long) fdata.info.assert_tu.nsec;
  if (out->pulse.tv_nsec < 0 || out->pulse.tv_nsec >= 1000000000L)
    return -1;
  out->valid = 1;
  if (bntp_refid_from_string ("PPS", out->refid) < 0)
    return -1;
  return 0;
#else
  (void) path;
  return -1;
#endif
}

static int
bntp_refclock_read_gps (const char *arg, struct bntp_refclock_sample *out)
{
  const char *nmea = NULL;
  char pps_path[256];
  size_t pps_len;

  if (!arg)
    arg = "";
  nmea = strstr (arg, "+nmea:");
  pps_len = nmea ? (size_t) (nmea - arg) : strlen (arg);
  if (pps_len >= sizeof pps_path)
    return -1;
  memcpy (pps_path, arg, pps_len);
  pps_path[pps_len] = '\0';
  if (nmea && !bntp_nmea_sentence_valid (nmea + 6))
    return -1;
  if (bntp_refclock_read_pps_device (pps_path, out) < 0)
    return -1;
  if (bntp_refid_from_string ("GPS", out->refid) < 0)
    return -1;
  return 0;
}

static int
bntp_refclock_read (const char *spec, struct bntp_refclock_sample *out)
{
  if (!spec || !*spec || !out)
    return -1;
  if (strncmp (spec, "mock:", 5) == 0)
    return bntp_refclock_read_mock (spec + 5, out);
  if (strncmp (spec, "pps:", 4) == 0)
    return bntp_refclock_read_pps_device (spec + 4, out);
  if (strncmp (spec, "gps:", 4) == 0)
    return bntp_refclock_read_gps (spec + 4, out);
  memset (out, 0, sizeof *out);
  return -1;
}

static void
bntp_refclock_apply_sample (struct bntp_server_cfg *cfg,
                            const struct bntp_refclock_sample *sample,
                            const struct timespec *now, double max_age)
{
  if (sample && sample->valid
      && bntp_timespec_age (now, &sample->pulse) >= 0.0
      && bntp_timespec_age (now, &sample->pulse) <= max_age)
    {
      cfg->stratum = 1;
      cfg->leap = 0;
      memcpy (cfg->refid, sample->refid, sizeof cfg->refid);
      return;
    }

  cfg->stratum = 16;
  cfg->leap = 3;
  memcpy (cfg->refid, "DOWN", 4);
}

static void
bntp_refclock_derive_cfg (const char *spec, struct bntp_server_cfg *cfg,
                          const struct timespec *now)
{
  struct bntp_refclock_sample sample;
  double max_age = bntp_env_seconds ("BASHNTP_REFCLOCK_MAX_AGE",
                                     BNTP_REFCLOCK_MAX_AGE_SEC,
                                     0.001, 3600.0);
  if (bntp_refclock_read (spec, &sample) < 0)
    memset (&sample, 0, sizeof sample);
  bntp_refclock_apply_sample (cfg, &sample, now, max_age);
}

static int
bntp_serve_encode_refclock_fixture (const char *refclock_spec, int stale)
{
  struct bntp_pkt req, resp;
  struct bntp_server_cfg cfg = {
    .stratum = 1,
    .leap = 0,
    .precision = -20,
    .refid = { 'L', 'O', 'C', 'L' }
  };
  struct timespec recv_ts = { .tv_sec = 1000, .tv_nsec = 250000000L };
  struct timespec xmit_ts = { .tv_sec = 1000, .tv_nsec = 500000000L };

  memset (&req, 0, sizeof req);
  req.li_vn_mode = 0x23;
  req.poll = 6;
  req.precision = -20;
  req.xmit_ts_sec = htonl (BNTP_UNIX_OFFSET + 999);
  req.xmit_ts_frac = htonl (0x20000000U);

  if (refclock_spec)
    bntp_refclock_derive_cfg (refclock_spec, &cfg, &xmit_ts);
  else
    {
      struct bntp_refclock_sample sample;
      memset (&sample, 0, sizeof sample);
      sample.valid = 1;
      sample.pulse = xmit_ts;
      if (stale)
        bntp_timespec_sub_seconds (&sample.pulse,
                                   BNTP_REFCLOCK_MAX_AGE_SEC + 1.0);
      bntp_refid_from_string ("PPS", sample.refid);
      bntp_refclock_apply_sample (&cfg, &sample, &xmit_ts,
                                  BNTP_REFCLOCK_MAX_AGE_SEC);
    }

  bntp_build_response (&req, &recv_ts, &xmit_ts, &cfg, &resp);
  bntp_hex_dump ((const unsigned char *) &resp, BNTP_PKT_LEN);
  return EXECUTION_SUCCESS;
}

static int
bntp_split_listen (const char *spec, const char **host_out, char *hostbuf,
                   size_t hostbufsz, char *portbuf, size_t portbufsz,
                   unsigned short fallback_port)
{
  const char *host = spec;
  const char *port = NULL;
  size_t hostlen;
  if (!spec || !*spec)
    {
      *host_out = NULL;
      snprintf (portbuf, portbufsz, "%u", (unsigned) fallback_port);
      return 0;
    }

  if (spec[0] == '[')
    {
      const char *end = strchr (spec, ']');
      if (!end)
        return -1;
      hostlen = (size_t) (end - spec - 1);
      if (hostlen + 1 > hostbufsz)
        return -1;
      memcpy (hostbuf, spec + 1, hostlen);
      hostbuf[hostlen] = '\0';
      host = hostbuf;
      if (end[1] == ':' && end[2])
        port = end + 2;
      else if (end[1] != '\0')
        return -1;
    }
  else
    {
      const char *colon = strrchr (spec, ':');
      if (colon && strchr (spec, ':') == colon)
        {
          hostlen = (size_t) (colon - spec);
          if (hostlen == 0 || hostlen + 1 > hostbufsz)
            return -1;
          memcpy (hostbuf, spec, hostlen);
          hostbuf[hostlen] = '\0';
          host = hostbuf;
          if (!colon[1])
            return -1;
          port = colon + 1;
        }
      else if (colon && colon[1])
        {
          struct in6_addr a6;
          char *end = NULL;
          unsigned long v;

          errno = 0;
          v = strtoul (colon + 1, &end, 10);
          /* Accept the host-safe fixture spelling `::1:<high-port>` when the
             full token is not itself a valid IPv6 literal. Brackets remain
             the unambiguous form for low numeric suffixes like `::1:123`. */
          if (errno == 0 && end && *end == '\0' && v >= 1 && v <= 65535
              && inet_pton (AF_INET6, spec, &a6) != 1)
            {
              hostlen = (size_t) (colon - spec);
              if (hostlen == 0 || hostlen + 1 > hostbufsz)
                return -1;
              memcpy (hostbuf, spec, hostlen);
              hostbuf[hostlen] = '\0';
              host = hostbuf;
              port = colon + 1;
            }
          else
            host = spec;
        }
      else
        host = spec;
    }

  if (port)
    {
      char *end = NULL;
      unsigned long v;
      errno = 0;
      v = strtoul (port, &end, 10);
      if (errno != 0 || !end || *end || v < 1 || v > 65535)
        return -1;
      snprintf (portbuf, portbufsz, "%lu", v);
    }
  else
    snprintf (portbuf, portbufsz, "%u", (unsigned) fallback_port);
  *host_out = host;
  return 0;
}

static int
bntp_parse_refid (const char *s, char out[4])
{
  return bntp_refid_from_string (s, out);
}

static unsigned long long
bntp_parse_ntp_now (const char *s)
{
  if (s && *s)
    return strtoull (s, NULL, 10);
  s = getenv ("BASHNTP_LEAP_NOW");
  if (s && *s)
    return strtoull (s, NULL, 10);
  return bntp_unix_to_ntp_now ();
}

static void
bntp_leap_apply_cfg (struct bntp_server_cfg *cfg, const char *leapfile,
                     int strict_leap, int manual_leap, unsigned long long now_ntp,
                     int *stale_out, int *events_out, unsigned long long *expiry_out)
{
  struct bntp_leap_table tbl;
  if (stale_out) *stale_out = 0;
  if (events_out) *events_out = 0;
  if (expiry_out) *expiry_out = 0;
  if (manual_leap || (!leapfile && !getenv ("BASHNTP_LEAP_MOCK")))
    return;
  if (bntp_leap_load (leapfile, &tbl) < 0)
    return;
  cfg->leap = bntp_leap_for (now_ntp, &tbl);
  if (stale_out) *stale_out = tbl.stale;
  if (events_out) *events_out = tbl.nevents;
  if (expiry_out) *expiry_out = tbl.expiry;
  if (tbl.stale && strict_leap)
    {
      cfg->stratum = 16;
      memcpy (cfg->refid, "LEAP", 4);
    }
}

static int
bntp_serve_encode_leap_fixture (const char *leapfile, int strict_leap,
                                int manual_leap, unsigned char manual_li,
                                const char *now_arg)
{
  struct bntp_server_cfg cfg = {
    .stratum = 1,
    .leap = 0,
    .precision = -20,
    .refid = { 'L', 'O', 'C', 'L' }
  };
  int stale = 0, events = 0;
  unsigned long long expiry = 0;
  unsigned long long now_ntp = bntp_parse_ntp_now (now_arg);
  if (manual_leap)
    cfg.leap = manual_li;
  bntp_leap_apply_cfg (&cfg, leapfile, strict_leap, manual_leap, now_ntp,
                       &stale, &events, &expiry);
  unsigned char first = (unsigned char) (((cfg.leap & 0x03) << 6) | (4 << 3) | 4);
  printf ("li=%u stale=%d stratum=%u refid=%c%c%c%c first_byte=%02x expiry=%llu events=%d now=%llu\n",
          cfg.leap, stale, cfg.stratum,
          cfg.refid[0], cfg.refid[1], cfg.refid[2], cfg.refid[3],
          first, expiry, events, now_ntp);
  return EXECUTION_SUCCESS;
}

static int
bntp_hex_value (int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int
bntp_key_parse_secret (const char *s, unsigned char *out, size_t *out_len)
{
  const char *p = s;
  size_t len = strlen (s);
  int hex = 0;
  if (len > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
    { hex = 1; p = s + 2; len -= 2; }
  else if ((len & 1) == 0 && len > 0)
    {
      hex = 1;
      for (size_t i = 0; i < len; i++)
        if (bntp_hex_value ((unsigned char) s[i]) < 0)
          { hex = 0; break; }
    }
  if (hex)
    {
      if ((len & 1) || len / 2 > 128)
        return -1;
      for (size_t i = 0; i < len / 2; i++)
        {
          int hi = bntp_hex_value ((unsigned char) p[i * 2]);
          int lo = bntp_hex_value ((unsigned char) p[i * 2 + 1]);
          if (hi < 0 || lo < 0)
            return -1;
          out[i] = (unsigned char) ((hi << 4) | lo);
        }
      *out_len = len / 2;
      return 0;
    }
  if (len == 0 || len > 128)
    return -1;
  memcpy (out, s, len);
  *out_len = len;
  return 0;
}

static int
bntp_keyfile_load (const char *path, struct bntp_keyring *ring)
{
  FILE *f;
  char line[512];
  memset (ring, 0, sizeof *ring);
  if (!path)
    return 0;
  f = fopen (path, "r");
  if (!f)
    { builtin_error ("serve: keyfile %s: %s", path, strerror (errno)); return -1; }
  while (fgets (line, sizeof line, f))
    {
      char *p = line, *id_s, *type_s, *key_s;
      while (*p == ' ' || *p == '\t') p++;
      if (*p == '#' || *p == '\n' || *p == '\0')
        continue;
      id_s = p;
      while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') p++;
      if (*p) *p++ = '\0';
      while (*p == ' ' || *p == '\t') p++;
      type_s = p;
      while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') p++;
      if (*p) *p++ = '\0';
      while (*p == ' ' || *p == '\t') p++;
      key_s = p;
      key_s[strcspn (key_s, " \t\r\n")] = '\0';
      if (!*id_s || !*type_s || !*key_s)
        continue;
      if (strcasecmp (type_s, "SHA256") != 0 && strcasecmp (type_s, "HMAC-SHA256") != 0)
        continue;
      if (ring->nkeys >= BNTP_MAX_KEYS)
        break;
      char *end = NULL;
      unsigned long id = strtoul (id_s, &end, 10);
      if (!end || *end || id == 0 || id > 0xffffffffUL)
        continue;
      struct bntp_mac_key *k = &ring->keys[ring->nkeys];
      if (bntp_key_parse_secret (key_s, k->key, &k->key_len) == 0)
        {
          k->keyid = (unsigned) id;
          ring->nkeys++;
        }
    }
  fclose (f);
  return 0;
}

static const struct bntp_mac_key *
bntp_key_find (const struct bntp_keyring *ring, unsigned keyid)
{
  for (int i = 0; i < ring->nkeys; i++)
    if (ring->keys[i].keyid == keyid)
      return &ring->keys[i];
  return NULL;
}

static size_t
bntp_reply_with_mac (const struct bntp_keyring *ring,
                     const unsigned char *reqbuf, size_t req_len,
                     const struct bntp_pkt *resp, unsigned char *out,
                     size_t out_cap)
{
  memcpy (out, resp, BNTP_PKT_LEN);
  if (!ring || ring->nkeys == 0 || req_len < BNTP_PKT_LEN + 4
      || out_cap < BNTP_PKT_LEN + 4 + BNTP_MAC_SHA256_LEN)
    return BNTP_PKT_LEN;
  unsigned keyid = bntp_get_u32 (reqbuf + BNTP_PKT_LEN);
  const struct bntp_mac_key *key = bntp_key_find (ring, keyid);
  if (!key)
    return BNTP_PKT_LEN;
  bntp_put_u32 (out + BNTP_PKT_LEN, keyid);
  if (mbedtls_hmac_sha256 (key->key, key->key_len, out, BNTP_PKT_LEN,
                           out + BNTP_PKT_LEN + 4) != 0)
    return BNTP_PKT_LEN;
  return BNTP_PKT_LEN + 4 + BNTP_MAC_SHA256_LEN;
}

static int
bntp_serve_cmd (WORD_LIST *args)
{
  struct bntp_server_cfg cfg = {
    .stratum = 1,
    .leap = 0,
    .precision = -20,
    .refid = { 'L', 'O', 'C', 'L' }
  };
  const char *listen_spec = NULL;
  const char *refclock_spec = NULL;
  const char *leapfile = NULL;
  const char *keyfile = NULL;
  const char *encode_leap_now = NULL;
  int encode_refclock = 0;
  int encode_refclock_stale = 0;
  int encode_leap = 0;
  int stratum_set = 0;
  int manual_leap = 0;
  int strict_leap = 0;
  int once = 0;
  int max = 0;

  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "--encode-fixture") == 0)
        return bntp_serve_encode_fixture ();
      else if (strcmp (w, "--encode-leap-fixture") == 0)
        {
          encode_leap = 1;
          if (p->next && isdigit ((unsigned char) p->next->word->word[0]))
            { p = p->next; encode_leap_now = p->word->word; }
        }
      else if (strcmp (w, "--encode-refclock-fixture") == 0)
        {
          encode_refclock = 1;
          if (p->next
              && (strcmp (p->next->word->word, "valid") == 0
                  || strcmp (p->next->word->word, "fresh") == 0
                  || strcmp (p->next->word->word, "stale") == 0
                  || strcmp (p->next->word->word, "invalid") == 0))
            {
              p = p->next;
              encode_refclock_stale =
                (strcmp (p->word->word, "stale") == 0
                 || strcmp (p->word->word, "invalid") == 0);
            }
        }
      else if (strcmp (w, "-S") == 0 || strcmp (w, "--listen") == 0)
        {
          if (!p->next) { builtin_error ("serve: -S needs ADDR[:PORT]"); return EX_USAGE; }
          p = p->next; listen_spec = p->word->word;
        }
      else if (strcmp (w, "--refclock") == 0)
        {
          if (!p->next) { builtin_error ("serve: --refclock needs SPEC"); return EX_USAGE; }
          p = p->next; refclock_spec = p->word->word;
        }
      else if (strcmp (w, "--leapfile") == 0)
        {
          if (!p->next) { builtin_error ("serve: --leapfile needs PATH"); return EX_USAGE; }
          p = p->next; leapfile = p->word->word;
        }
      else if (strcmp (w, "--strict-leap") == 0) strict_leap = 1;
      else if (strcmp (w, "--keyfile") == 0)
        {
          if (!p->next) { builtin_error ("serve: --keyfile needs PATH"); return EX_USAGE; }
          p = p->next; keyfile = p->word->word;
        }
      else if (strcmp (w, "--stratum") == 0)
        {
          int v;
          if (!p->next) { builtin_error ("serve: --stratum needs N"); return EX_USAGE; }
          p = p->next; v = atoi (p->word->word);
          if (v < 1 || v > 15) { builtin_error ("serve: stratum must be 1..15"); return EX_USAGE; }
          cfg.stratum = (unsigned char) v;
          stratum_set = 1;
        }
      else if (strcmp (w, "--refid") == 0)
        {
          if (!p->next) { builtin_error ("serve: --refid needs STR"); return EX_USAGE; }
          p = p->next;
          if (bntp_parse_refid (p->word->word, cfg.refid) < 0)
            { builtin_error ("serve: --refid must be 1-4 printable ASCII bytes"); return EX_USAGE; }
        }
      else if (strcmp (w, "--leap") == 0)
        {
          int v;
          if (!p->next) { builtin_error ("serve: --leap needs 0..3"); return EX_USAGE; }
          p = p->next; v = atoi (p->word->word);
          if (v < 0 || v > 3) { builtin_error ("serve: leap must be 0..3"); return EX_USAGE; }
          cfg.leap = (unsigned char) v;
          manual_leap = 1;
        }
      else if (strcmp (w, "--once") == 0) once = 1;
      else if (strcmp (w, "--max") == 0)
        {
          if (!p->next) { builtin_error ("serve: --max needs N"); return EX_USAGE; }
          p = p->next; max = atoi (p->word->word);
          if (max < 1) { builtin_error ("serve: --max must be >=1"); return EX_USAGE; }
        }
      else { builtin_error ("serve: extra arg %s", w); return EX_USAGE; }
    }
  if (refclock_spec && stratum_set)
    {
      builtin_error ("serve: --refclock and --stratum are mutually exclusive");
      return EX_USAGE;
    }
  if (encode_refclock)
    return bntp_serve_encode_refclock_fixture (refclock_spec, encode_refclock_stale);
  if (encode_leap)
    return bntp_serve_encode_leap_fixture (leapfile, strict_leap, manual_leap,
                                           cfg.leap, encode_leap_now);
  if (once && max == 0) max = 1;

  struct bntp_keyring keyring;
  if (bntp_keyfile_load (keyfile, &keyring) < 0)
    return EXECUTION_FAILURE;

  unsigned short port = bntp_env_port ("BASHNTP_SERVER_PORT", BNTP_PORT);
  char hostbuf[NI_MAXHOST], portbuf[16];
  const char *host = NULL;
  if (bntp_split_listen (listen_spec, &host, hostbuf, sizeof hostbuf,
                         portbuf, sizeof portbuf, port) < 0)
    { builtin_error ("serve: bad listen address %s", listen_spec ? listen_spec : ""); return EX_USAGE; }

  struct addrinfo hints, *ai = NULL, *p;
  memset (&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = host ? 0 : AI_PASSIVE;
  int rc = getaddrinfo (host, portbuf, &hints, &ai);
  if (rc != 0)
    {
      builtin_error ("serve: getaddrinfo %s:%s: %s", host ? host : "*", portbuf, gai_strerror (rc));
      return EXECUTION_FAILURE;
    }

  int fd = -1;
  for (p = ai; p; p = p->ai_next)
    {
      fd = socket (p->ai_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
      if (fd < 0) continue;
      int one = 1;
      setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
      if (bind (fd, p->ai_addr, p->ai_addrlen) == 0)
        break;
      close (fd);
      fd = -1;
    }
  freeaddrinfo (ai);
  if (fd < 0)
    {
      builtin_error ("serve: bind %s:%s: %s", host ? host : "*", portbuf, strerror (errno));
      return EXECUTION_FAILURE;
    }

  struct sigaction sa;
  memset (&sa, 0, sizeof sa);
  sa.sa_handler = bntp_sig;
  sigemptyset (&sa.sa_mask);
  sigaction (SIGINT, &sa, NULL);
  sigaction (SIGTERM, &sa, NULL);
  bntp_stop = 0;

  int answered = 0;
  while (!bntp_stop && (max == 0 || answered < max))
    {
      unsigned char reqbuf[BNTP_NTS_MAX_PACKET];
      unsigned char respbuf[BNTP_NTS_MAX_PACKET];
      struct bntp_pkt req, resp;
      struct sockaddr_storage src;
      socklen_t sl = sizeof src;
      ssize_t n;
      do
        n = recvfrom (fd, reqbuf, sizeof reqbuf, 0, (struct sockaddr *) &src, &sl);
      while (n < 0 && errno == EINTR && !bntp_stop);
      if (bntp_stop) break;
      if (n < 0)
        {
          builtin_error ("serve: recvfrom: %s", strerror (errno));
          close (fd);
          return EXECUTION_FAILURE;
        }

      struct timespec recv_ts, xmit_ts;
      clock_gettime (CLOCK_REALTIME, &recv_ts);
      if (n < (ssize_t) BNTP_PKT_LEN)
        continue;
      memcpy (&req, reqbuf, BNTP_PKT_LEN);
      if ((req.li_vn_mode & 0x07) != 3)
        continue;
      if (req.xmit_ts_sec == 0 && req.xmit_ts_frac == 0)
        continue;

      clock_gettime (CLOCK_REALTIME, &xmit_ts);
      struct bntp_server_cfg resp_cfg = cfg;
      if (refclock_spec)
        bntp_refclock_derive_cfg (refclock_spec, &resp_cfg, &xmit_ts);
      else if (leapfile || getenv ("BASHNTP_LEAP_MOCK"))
        {
          unsigned long long now_ntp = (unsigned long long) xmit_ts.tv_sec + BNTP_UNIX_OFFSET;
          bntp_leap_apply_cfg (&resp_cfg, leapfile, strict_leap, manual_leap,
                               now_ntp, NULL, NULL, NULL);
        }
      bntp_build_response (&req, &recv_ts, &xmit_ts, &resp_cfg, &resp);
      size_t resp_len = bntp_reply_with_mac (&keyring, reqbuf, (size_t) n,
                                             &resp, respbuf, sizeof respbuf);

      unsigned short cport = bntp_env_port ("BASHNTP_CLIENT_PORT", 0);
      if (cport != 0)
        {
          if (src.ss_family == AF_INET)
            ((struct sockaddr_in *) &src)->sin_port = htons (cport);
          else if (src.ss_family == AF_INET6)
            ((struct sockaddr_in6 *) &src)->sin6_port = htons (cport);
        }

      do
        n = sendto (fd, respbuf, resp_len, 0, (struct sockaddr *) &src, sl);
      while (n < 0 && errno == EINTR && !bntp_stop);
      if (n < 0)
        builtin_warning ("serve: sendto: %s", strerror (errno));
      else
        answered++;
    }
  close (fd);
  return EXECUTION_SUCCESS;
}

extern char *ntp_doc[];

static void
bntp_print_help (void)
{
  for (char **line = ntp_doc; *line; line++)
    printf ("%s\n", *line);
}

int
ntp_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;

  if (strcmp (cmd, "help") == 0 || strcmp (cmd, "-h") == 0 ||
      strcmp (cmd, "--help") == 0)
    {
      bntp_print_help ();
      return EXECUTION_SUCCESS;
    }
  if (strcmp (cmd, "query") == 0) return bntp_query_cmd (args);
  if (strcmp (cmd, "sync")  == 0) return bntp_sync_cmd (args);
  if (strcmp (cmd, "run")   == 0) return bntp_run_cmd (args);
  if (strcmp (cmd, "serve") == 0) return bntp_serve_cmd (args);
  if (strcmp (cmd, "nts-selftest") == 0) return bntp_nts_selftest_cmd (args);

  builtin_error ("unknown subcommand: %s (try query/sync/run/serve)", cmd);
  return EX_USAGE;
}

char *ntp_doc[] = {
  "SNTP/NTPv4 client, stateless server, and lightweight clock-sync daemon.",
  "",
  "    ntp query SERVER [-t MS] [-p PORT]",
  "        One-shot NTP query. SERVER may be nts:HOST for opt-in NTS.",
  "        Prints offset/delay/stratum/server.",
  "",
  "    ntp sync [-s SERVER]... [-t MS] [-n] [-l LIMIT] [-P POLLS]",
  "        Query each server, keep its lowest-delay sample, take the median, apply via",
  "        clock_settime unless -n. -l clamps the max single step.",
  "        Refuses |offset| > 1024s (RFC 5905 panic threshold) unless",
  "        --allow-big-jump is given. --step-always is accepted for scripts.",
  "",
  "    ntp run [-d STATEDIR] [-i SECS] [-c CONFIG] [--once]",
  "        Daemon mode. Reads /etc/ntp.conf (or -c) and loops.",
  "        --discipline slew|step|kernel selects the apply path; default slew.",
  "        --discipline-loop pll|fll selects the kernel status flag; default pll.",
  "        --dry-run-discipline prints the would-apply action and mutates no clock.",
  "        Sleep policy: `interval` after a successful sync,",
  "        `retry` after a zero-response iteration (defaults to interval).",
  "        KoD RATE responses trigger per-server poll backoff.",
  "        With STATEDIR, writes <STATEDIR>/cfg (config snapshot at start)",
  "        and <STATEDIR>/last (latest successful sync record).",
  "",
  "    ntp serve [-S ADDR[:PORT]] [--stratum N] [--refid STR]",
  "                  [--leap 0|1|2|3] [--leapfile PATH] [--strict-leap]",
  "                  [--refclock SPEC] [--keyfile PATH] [--once] [--max N]",
  "        Stateless SNTP server. Replies to mode-3 requests with mode-4",
  "        packets using CLOCK_REALTIME. --refclock pps:/dev/pps0 or",
  "        gps:/dev/ppsN+nmea:/dev/ttyAMA0 derives stratum/refid from",
  "        a fresh PPS/GPS pulse; stale or absent pulses serve stratum 16.",
  "        --leapfile reads NIST/IERS leap-seconds.list rows; --leap N",
  "        remains a manual override. --keyfile enables opt-in SHA256 MAC replies",
  "        when requests carry a known key id.",
  "        BASHNTP_SERVER_PORT overrides the default port; BASHNTP_CLIENT_PORT",
  "        can pin test client ports.",
  "",
  "Config keys: server <host|nts:host>, interval <sec>, retry <sec>,",
  "             timeout <ms>, polls <1-8>, limit <sec>, step_threshold <sec>,",
  "             discipline <slew|step|kernel>, discipline_loop <pll|fll>,",
  "             leapfile <path>.",
  (char *)NULL
};

struct builtin ntp_struct = {
  "ntp",
  ntp_builtin,
  BUILTIN_ENABLED,
  ntp_doc,
  "ntp query SERVER | sync -s SERVER... | run [-d DIR] | serve [-S ADDR[:PORT]]",
  0
};
