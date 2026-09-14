/* SPDX-License-Identifier: MIT */
/* curl.c — curl(1) / wget(1) command surface over http + crypto.
 *
 * MISSING_LOADABLES T1 (ML-T1-08) of the bash-os deployable-distro track.
 * Shell scripts in the wild hard-code `curl -fsSL URL` and `wget URL`;
 * this loadable wraps the http + crypto primitives in the curl
 * argv shape so those scripts work unchanged.
 *
 * Subset implemented (curl side):
 *     -X METHOD | --request METHOD
 *                         HTTP verb (default GET, auto-POST when -d set)
 *     -H "K: V" | --header "K: V"
 *                         add request header (repeatable)
 *     -d DATA | --data DATA | --data-raw DATA | --data-ascii DATA
 *                         request body (POST default unless -X set)
 *     --data-binary DATA  request body; @- reads bytes from stdin
 *     -o FILE | --output FILE | -
 *                         output to FILE or stdout (default stdout)
 *     -D FILE | --dump-header FILE | -
 *                         dump response headers
 *     -w FORMAT | --write-out FORMAT
 *                         write-out; supports %{http_code}
 *     -O                  output to basename of URL
 *     -u USER:PASS | --user USER:PASS
 *                         Basic auth (Authorization header)
 *     -A AGENT | --user-agent AGENT
 *                         User-Agent override
 *     -b COOKIE|FILE | --cookie COOKIE|FILE
 *                         literal Cookie: request header value or cookie jar
 *     -c FILE | --cookie-jar FILE
 *                         write Set-Cookie values to a cookie jar
 *     -k / --insecure     skip TLS cert verification
 *     --cacert PEM        use PEM as the TLS trust anchor for HTTPS
 *     -f / --fail         exit 22 on HTTP status >= 400
 *     -s / --silent       suppress progress + non-error chatter
 *     -S / --show-error   pair with -s to keep error diagnostics
 *     -L / --location     follow 3xx Location: redirects (max 20)
 *     --connect-timeout SEC
 *                         maximum time allowed to connect
 *     -m / --max-time SEC overall timeout for the request
 *     -                   read POST body from stdin when -d @-
 *
 * Parser compatibility:
 *     Supported long options accept --name=value where Debian curl does.
 *     Short options with arguments accept attached spelling (-oFILE, -m10),
 *     and flag-only short options can be bundled before an argument option
 *     (for example: -fsSLo FILE).
 *
 * Deliberately omitted (out of scope, per work-doc):
 *     -F multipart, non-HTTP cookie schemes, --resolve, HTTP/2, OAuth.
 *
 * Transport layer:
 *     http://  — raw TCP socket via getaddrinfo + connect.
 *     https:// — popen() a bash subshell that pipes the request through
 *                `crypto tls connect HOST:PORT -s HOST [-k]`. The
 *                bash-os variant compiles crypto IN (not as a
 *                dynamically-loaded .so), so the child shell has the
 *                builtin available with no `enable -f` dance.
 *
 * Verb dispatch keeps with the rest of the bash-os loadable family:
 * `curl URL` is the default GET; explicit verbs are not exposed
 * because the curl argv idiom doesn't have a leading verb.
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
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "loadables.h"

/* Caps. Response buffer is the dominant memory footprint; curl is
 * meant for small page/file fetches, not multi-GiB downloads. The cap
 * protects against runaway responses without a Content-Length. */
#define BCURL_MAX_RESPONSE   (512 * 1024 * 1024) /* 512 MiB response ceiling. */
#define BCURL_READ_CHUNK      32768
#define BCURL_HEADER_MAX      16384
#define BCURL_HDRBUF_MAX       8192
#define BCURL_MAX_REDIRECTS       20   /* RFC 9110 §15.4 minimum recommendation; user override via --max-redirs */
#define BCURL_DEFAULT_TIMEOUT 300                /* seconds */
#define BCURL_HEADER_SLOTS       32
#define BCURL_VERSION          "0.1"

typedef struct {
  char  scheme[8];
  char  host[256];
  char  port[8];
  char  path[2048];
} bc_url;

typedef struct {
  const char *method;
  const char *url;
  const char *body;
  char       *body_alloc;
  size_t      body_len;
  int         body_set;
  const char *outfile;
  const char *dump_headers;
  const char *write_out;
  const char *user_agent;
  const char *userpass;        /* "user:pass" */
  const char *cookie;          /* literal Cookie: header value or jar path */
  const char *cookie_input;    /* original -b/--cookie value */
  const char *cookie_jar;      /* -c/--cookie-jar output path */
  const char *cacert;          /* --cacert PEM for HTTPS */
  char       *cookie_alloc;    /* loaded jar -> Cookie: value */
  char       *headers[BCURL_HEADER_SLOTS];
  int         nheaders;
  int         use_basename;    /* -O */
  int         follow;          /* -L */
  int         fail_on_error;   /* -f */
  int         silent;          /* -s */
  int         show_error;      /* -S */
  int         insecure;        /* -k */
  int         connect_time;    /* --connect-timeout SEC */
  int         max_time;        /* --max-time SEC */
  int         max_redirs;      /* --max-redirs N (0 = use BCURL_MAX_REDIRECTS) */
  int         features;        /* --features */
} bc_opts;

typedef struct {
  int   status;
  char *headers;               /* malloc'd; raw header block (no trailer CRLFCRLF) */
  size_t hlen;
  unsigned char *body;         /* malloc'd; raw decoded body */
  size_t blen;
  char  location[1024];        /* extracted Location: header if 3xx */
} bc_response;

/* ---- url parser (mirrors http's, with bigger path buffer) ---- */
static int
bc_parse_url (const char *url, bc_url *u)
{
  memset (u, 0, sizeof *u);
  const char *p = strstr (url, "://");
  if (!p) return -1;
  size_t sl = (size_t) (p - url);
  if (sl == 0 || sl >= sizeof u->scheme) return -1;
  memcpy (u->scheme, url, sl);
  p += 3;
  const char *slash = strchr (p, '/');
  const char *end = slash ? slash : url + strlen (url);
  const char *colon = NULL;
  for (const char *q = p; q < end; q++)
    if (*q == ':') { colon = q; break; }
  size_t hl = (size_t) ((colon ? colon : end) - p);
  if (hl == 0 || hl >= sizeof u->host) return -1;
  memcpy (u->host, p, hl);
  if (colon)
    {
      size_t pl = (size_t) (end - colon - 1);
      if (pl == 0 || pl >= sizeof u->port) return -1;
      memcpy (u->port, colon + 1, pl);
    }
  else
    snprintf (u->port, sizeof u->port, "%s",
              strcasecmp (u->scheme, "https") == 0 ? "443" : "80");
  snprintf (u->path, sizeof u->path, "%s", slash ? slash : "/");
  return 0;
}

/* ---- minimal base64 encoder (RFC 4648) for Basic auth ---- */
static const char bc_b64tab[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *
bc_b64encode (const unsigned char *in, size_t n)
{
  size_t out_len = 4 * ((n + 2) / 3) + 1;
  char *out = malloc (out_len);
  if (!out) return NULL;
  size_t i, j = 0;
  for (i = 0; i + 3 <= n; i += 3)
    {
      unsigned v = (in[i] << 16) | (in[i+1] << 8) | in[i+2];
      out[j++] = bc_b64tab[(v >> 18) & 0x3F];
      out[j++] = bc_b64tab[(v >> 12) & 0x3F];
      out[j++] = bc_b64tab[(v >>  6) & 0x3F];
      out[j++] = bc_b64tab[ v        & 0x3F];
    }
  if (i < n)
    {
      unsigned v = in[i] << 16;
      if (i + 1 < n) v |= in[i+1] << 8;
      out[j++] = bc_b64tab[(v >> 18) & 0x3F];
      out[j++] = bc_b64tab[(v >> 12) & 0x3F];
      out[j++] = (i + 1 < n) ? bc_b64tab[(v >> 6) & 0x3F] : '=';
      out[j++] = '=';
    }
  out[j] = '\0';
  return out;
}

/* ---- header buffer helpers ---- */
static int
bc_hdr_append (char *buf, size_t cap, const char *line)
{
  size_t blen = strlen (buf);
  size_t nlen = strlen (line);
  if (blen + nlen + 3 >= cap) return -1;
  memcpy (buf + blen, line, nlen);
  buf[blen + nlen + 0] = '\r';
  buf[blen + nlen + 1] = '\n';
  buf[blen + nlen + 2] = '\0';
  return 0;
}

static int
bc_hdr_has (const char *buf, const char *prefix)
{
  size_t plen = strlen (prefix);
  const char *p = buf;
  while (p && *p)
    {
      if (strncasecmp (p, prefix, plen) == 0) return 1;
      p = strstr (p, "\r\n");
      if (!p) break;
      p += 2;
    }
  return 0;
}

/* ---- request framing ---- */
static char *
bc_build_request (const bc_opts *o, const bc_url *u, size_t *out_len)
{
  char hdrs[BCURL_HDRBUF_MAX];
  hdrs[0] = '\0';

  for (int i = 0; i < o->nheaders; i++)
    if (bc_hdr_append (hdrs, sizeof hdrs, o->headers[i]) < 0)
      { builtin_error ("-H aggregate exceeds %d bytes", BCURL_HDRBUF_MAX); return NULL; }

  /* Basic auth: only injected when -u is set and the caller did not
   * already supply an Authorization header. */
  if (o->userpass && !bc_hdr_has (hdrs, "Authorization:"))
    {
      char *b64 = bc_b64encode ((const unsigned char *) o->userpass,
                                strlen (o->userpass));
      if (!b64) { builtin_error ("out of memory"); return NULL; }
      char line[BCURL_HDRBUF_MAX];
      snprintf (line, sizeof line, "Authorization: Basic %s", b64);
      free (b64);
      if (bc_hdr_append (hdrs, sizeof hdrs, line) < 0)
        { builtin_error ("header buffer exceeded"); return NULL; }
    }

  /* curl -b/--cookie accepts either a literal cookie string or a cookie
   * jar path. curl's bounded v1 implements the literal request-header
   * form only; a caller-supplied Cookie: via -H wins. */
  if (o->cookie && !bc_hdr_has (hdrs, "Cookie:"))
    {
      char line[BCURL_HDRBUF_MAX];
      snprintf (line, sizeof line, "Cookie: %s", o->cookie);
      if (bc_hdr_append (hdrs, sizeof hdrs, line) < 0)
        { builtin_error ("header buffer exceeded"); return NULL; }
    }

  const char *ua = o->user_agent ? o->user_agent : "curl/" BCURL_VERSION;
  size_t body_len = o->body_set ? o->body_len : 0;
  size_t need = strlen (hdrs) + strlen (u->path) + strlen (u->host)
              + body_len + strlen (ua) + 512;
  char *req = malloc (need);
  if (!req) { builtin_error ("out of memory"); return NULL; }

  int n;
  if (body_len)
    n = snprintf (req, need,
                  "%s %s HTTP/1.1\r\n"
                  "Host: %s\r\n"
                  "User-Agent: %s\r\n"
                  "Accept: */*\r\n"
                  "%s"
                  "Content-Length: %zu\r\n"
                  "Connection: close\r\n"
                  "\r\n",
                  o->method, u->path, u->host, ua, hdrs, body_len);
  else
    n = snprintf (req, need,
                  "%s %s HTTP/1.1\r\n"
                  "Host: %s\r\n"
                  "User-Agent: %s\r\n"
                  "Accept: */*\r\n"
                  "%s"
                  "Connection: close\r\n"
                  "\r\n",
                  o->method, u->path, u->host, ua, hdrs);
  if (n < 0 || (size_t) n >= need)
    { free (req); builtin_error ("request framing overflow"); return NULL; }
  if (body_len)
    {
      memcpy (req + n, o->body, body_len);
      n += (int) body_len;
    }
  *out_len = (size_t) n;
  return req;
}

static int
bc_slurp_fd_string (int fd, char **out, size_t *out_len)
{
  size_t cap = 4096, len = 0;
  char *buf = malloc (cap + 1);
  if (!buf) { builtin_error ("out of memory"); return -1; }
  for (;;)
    {
      if (len == cap)
        {
          if (cap >= BCURL_MAX_RESPONSE)
            { free (buf); builtin_error ("stdin body exceeds %d bytes", BCURL_MAX_RESPONSE); return -1; }
          size_t ncap = cap * 2;
          if (ncap > BCURL_MAX_RESPONSE) ncap = BCURL_MAX_RESPONSE;
          char *nb = realloc (buf, ncap + 1);
          if (!nb) { free (buf); builtin_error ("out of memory"); return -1; }
          buf = nb; cap = ncap;
        }
      ssize_t r = read (fd, buf + len, cap - len);
      if (r < 0)
        { if (errno == EINTR) continue;
          free (buf); builtin_error ("read stdin: %s", strerror (errno)); return -1; }
      if (r == 0) break;
      len += (size_t) r;
    }
  buf[len] = '\0';
  *out = buf;
  *out_len = len;
  return 0;
}

/* ---- minimal cookie jar support ---- */
static int
bc_cookie_domain_match (const char *host, const char *domain, int tailmatch)
{
  if (!host || !domain || !*host || !*domain) return 0;
  const char *d = strncmp (domain, "#HttpOnly_", 10) == 0 ? domain + 10 : domain;
  d = d[0] == '.' ? d + 1 : d;
  if (strcasecmp (host, d) == 0) return 1;
  if (!tailmatch) return 0;
  size_t hl = strlen (host), dl = strlen (d);
  return hl > dl && host[hl - dl - 1] == '.' && strcasecmp (host + hl - dl, d) == 0;
}

static int
bc_cookie_path_match (const char *req_path, const char *cookie_path)
{
  if (!cookie_path || !*cookie_path) return 1;
  if (!req_path || !*req_path) req_path = "/";
  size_t n = strlen (cookie_path);
  if (strncmp (req_path, cookie_path, n) != 0) return 0;
  return cookie_path[n - 1] == '/' || req_path[n] == '\0' || req_path[n] == '/';
}

static int
bc_cookie_samesite_value (const char *s, char *out, size_t outsz);

static void
bc_cookie_canon_domain (const char *in, char *out, size_t outsz)
{
  if (!in || !out || outsz == 0) return;
  if (strncmp (in, "#HttpOnly_", 10) == 0) in += 10;
  while (*in == '.') in++;
  size_t n = strlen (in);
  while (n > 0 && in[n - 1] == '.') n--;
  if (n >= outsz) n = outsz - 1;
  for (size_t i = 0; i < n; i++)
    out[i] = (char) tolower ((unsigned char) in[i]);
  out[n] = '\0';
}

static int
bc_cookie_is_ip_literal (const char *host)
{
  if (!host || !*host) return 0;
  for (const char *p = host; *p; p++)
    if (!isdigit ((unsigned char) *p) && *p != '.' && *p != ':')
      return 0;
  return 1;
}

static int
bc_cookie_is_public_suffix (const char *domain)
{
  static const char *exact[] = {
    "com", "org", "net", "edu", "gov", "mil", "int",
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "co.jp", "ne.jp", "or.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "github.io", "appspot.com", "cloudfront.net", "s3.amazonaws.com",
    NULL
  };
  char d[256];
  bc_cookie_canon_domain (domain, d, sizeof d);
  if (!d[0] || bc_cookie_is_ip_literal (d)) return 0;
  for (int i = 0; exact[i]; i++)
    if (strcmp (d, exact[i]) == 0)
      return 1;
  return 0;
}

static int
bc_cookie_accept_domain (const char *host, const char *attr,
                         char *out, size_t outsz, int *tailmatch)
{
  char h[256], d[256];
  bc_cookie_canon_domain (host, h, sizeof h);
  bc_cookie_canon_domain (attr, d, sizeof d);
  if (!h[0] || !d[0]) return 0;
  if (bc_cookie_is_public_suffix (d) && strcmp (h, d) != 0)
    return 0;
  if (!bc_cookie_domain_match (h, d, 1))
    return 0;
  snprintf (out, outsz, "%s", d);
  if (tailmatch) *tailmatch = strcmp (h, d) != 0 || (attr && attr[0] == '.');
  return 1;
}

typedef struct {
  char domain[256];
  char path[256];
  char name[128];
  char value[8];
} bc_samesite_meta;

static int
bc_cookie_same_site (const bc_url *a, const bc_url *b)
{
  char ah[256], bh[256];
  if (!a || !b) return 1;
  bc_cookie_canon_domain (a->host, ah, sizeof ah);
  bc_cookie_canon_domain (b->host, bh, sizeof bh);
  if (!ah[0] || !bh[0]) return 1;
  if (strcmp (ah, bh) == 0) return 1;
  if (bc_cookie_is_ip_literal (ah) || bc_cookie_is_ip_literal (bh))
    return 0;
  const char *adot = strchr (ah, '.');
  const char *bdot = strchr (bh, '.');
  if (!adot || !bdot) return 0;
  return strcmp (adot + 1, bdot + 1) == 0;
}

static const char *
bc_cookie_find_samesite (bc_samesite_meta *meta, int nmeta,
                         const char *domain, const char *path, const char *name)
{
  char d[256];
  bc_cookie_canon_domain (domain, d, sizeof d);
  for (int i = 0; i < nmeta; i++)
    if (strcmp (meta[i].domain, d) == 0
        && strcmp (meta[i].path, path ? path : "") == 0
        && strcmp (meta[i].name, name ? name : "") == 0)
      return meta[i].value;
  return "Lax";
}

static int
bc_cookie_samesite_allows (const char *same, int secure,
                           const char *method, const bc_url *request_url,
                           const bc_url *site_url)
{
  int same_site = bc_cookie_same_site (request_url, site_url);
  if (!same || !*same) same = "Lax";
  if (strcasecmp (same, "None") == 0)
    return secure;
  if (strcasecmp (same, "Strict") == 0)
    return same_site;
  if (same_site) return 1;
  return !method || strcasecmp (method, "GET") == 0
         || strcasecmp (method, "HEAD") == 0
         || strcasecmp (method, "OPTIONS") == 0
         || strcasecmp (method, "TRACE") == 0;
}

static char *
bc_cookie_from_jar (const char *path, const bc_url *u,
                    const bc_url *site_url, const char *method)
{
  int fd = open (path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return NULL;
  char *buf = NULL;
  size_t len = 0;
  if (bc_slurp_fd_string (fd, &buf, &len) < 0)
    { close (fd); return NULL; }
  close (fd);

  char *scan = malloc (len + 1);
  if (!scan) { free (buf); builtin_error ("out of memory"); return NULL; }
  memcpy (scan, buf, len + 1);

  bc_samesite_meta meta[64];
  int nmeta = 0;
  char *msave = NULL;
  for (char *line = strtok_r (scan, "\n", &msave); line; line = strtok_r (NULL, "\n", &msave))
    {
      while (*line == ' ' || *line == '\t' || *line == '\r') line++;
      if (strncmp (line, "# Bashcurl-SameSite\t", 20) != 0) continue;
      char *cols[5] = {0};
      int n = 0;
      for (char *tok = strtok (line + 20, "\t"); tok && n < 5; tok = strtok (NULL, "\t"))
        cols[n++] = tok;
      if (n < 4 || nmeta >= 64) continue;
      bc_cookie_canon_domain (cols[0], meta[nmeta].domain, sizeof meta[nmeta].domain);
      snprintf (meta[nmeta].path, sizeof meta[nmeta].path, "%s", cols[1]);
      snprintf (meta[nmeta].name, sizeof meta[nmeta].name, "%s", cols[2]);
      if (bc_cookie_samesite_value (cols[3], meta[nmeta].value, sizeof meta[nmeta].value))
        nmeta++;
    }
  free (scan);

  char *out = malloc (len + 1);
  if (!out) { free (buf); builtin_error ("out of memory"); return NULL; }
  out[0] = '\0';
  size_t out_len = 0;
  char *save = NULL;
  for (char *line = strtok_r (buf, "\n", &save); line; line = strtok_r (NULL, "\n", &save))
    {
      while (*line == ' ' || *line == '\t' || *line == '\r') line++;
      if (*line == '\0') continue;
      if (*line == '#' && strncmp (line, "#HttpOnly_", 10) != 0) continue;
      char *cols[7] = {0};
      int n = 0;
      for (char *tok = strtok (line, "\t"); tok && n < 7; tok = strtok (NULL, "\t"))
        cols[n++] = tok;
      if (n < 7 || !cols[5] || !cols[6]) continue;
      int tailmatch = strcasecmp (cols[1], "TRUE") == 0 || cols[0][0] == '.';
      int secure = strcasecmp (cols[3], "TRUE") == 0;
      long expires = strtol (cols[4], NULL, 10);
      const char *same = bc_cookie_find_samesite (meta, nmeta, cols[0], cols[2], cols[5]);
      if (!bc_cookie_domain_match (u->host, cols[0], tailmatch)) continue;
      if (!bc_cookie_path_match (u->path, cols[2])) continue;
      if (secure && strcasecmp (u->scheme, "https") != 0) continue;
      if (expires > 0 && expires < (long) time (NULL)) continue;
      if (!bc_cookie_samesite_allows (same, secure, method, u, site_url)) continue;
      size_t need = strlen (cols[5]) + strlen (cols[6]) + 3 + (out_len ? 2 : 0);
      if (out_len + need + 1 > len + 1) continue;
      if (out_len)
        { out[out_len++] = ';'; out[out_len++] = ' '; }
      size_t nl = strlen (cols[5]), vl = strlen (cols[6]);
      memcpy (out + out_len, cols[5], nl); out_len += nl;
      out[out_len++] = '=';
      memcpy (out + out_len, cols[6], vl); out_len += vl;
      out[out_len] = '\0';
    }
  free (buf);
  if (out_len == 0) { free (out); return NULL; }
  return out;
}

static long
bc_cookie_max_age (const char *s)
{
  if (!s || !*s) return 0;
  char *end = NULL;
  long n = strtol (s, &end, 10);
  if (end == s) return 0;
  return n;
}

static long
bc_days_from_civil (int y, unsigned m, unsigned d)
{
  y -= m <= 2;
  const int era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = (unsigned) (y - era * 400);
  const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return (long) era * 146097L + (long) doe - 719468L;
}

static int
bc_cookie_month (const char *m)
{
  static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
  for (int i = 0; i < 12; i++)
    if (strncasecmp (m, months + i * 3, 3) == 0)
      return i + 1;
  return 0;
}

static int
bc_cookie_parse_http_date (const char *s, long *out)
{
  if (!s || !*s || !out) return -1;
  while (*s == ' ' || *s == '\t') s++;

  int day = 0, year = 0, hh = 0, mm = 0, ss = 0;
  char mon[4] = {0};
  if (sscanf (s, "%*3[A-Za-z], %d %3[A-Za-z] %d %d:%d:%d GMT",
              &day, mon, &year, &hh, &mm, &ss) != 6
      && sscanf (s, "%d %3[A-Za-z] %d %d:%d:%d GMT",
                 &day, mon, &year, &hh, &mm, &ss) != 6
      && sscanf (s, "%*[^,], %d-%3[A-Za-z]-%d %d:%d:%d GMT",
                 &day, mon, &year, &hh, &mm, &ss) != 6
      && sscanf (s, "%*3[A-Za-z] %3[A-Za-z] %d %d:%d:%d %d",
                 mon, &day, &hh, &mm, &ss, &year) != 6)
    return -1;
  if (year >= 0 && year < 100)
    year += year >= 70 ? 1900 : 2000;

  int month = bc_cookie_month (mon);
  if (year < 1970 || month < 1 || day < 1 || day > 31
      || hh < 0 || hh > 23 || mm < 0 || mm > 59 || ss < 0 || ss > 60)
    return -1;
  long days = bc_days_from_civil (year, (unsigned) month, (unsigned) day);
  if (days < 0) return -1;
  *out = days * 86400L + hh * 3600L + mm * 60L + ss;
  return 0;
}

static void
bc_trim_cookie_token (char *s)
{
  char *e = s + strlen (s);
  while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r'))
    *--e = '\0';
}

static int
bc_cookie_samesite_value (const char *s, char *out, size_t outsz)
{
  if (!s || !*s || !out || outsz == 0) return 0;
  if (strcasecmp (s, "Strict") == 0)
    snprintf (out, outsz, "Strict");
  else if (strcasecmp (s, "Lax") == 0)
    snprintf (out, outsz, "Lax");
  else if (strcasecmp (s, "None") == 0)
    snprintf (out, outsz, "None");
  else
    return 0;
  return 1;
}

static int
bc_save_cookie_jar (const char *path, const bc_url *u, const char *hdrs)
{
  if (!path) return 0;
  FILE *fp = fopen (path, "wb");
  if (!fp)
    { builtin_error ("%s: %s", path, strerror (errno)); return -1; }
  fprintf (fp, "# Netscape HTTP Cookie File\n");
  fprintf (fp, "# Generated by curl; domain/path/secure/HttpOnly/Max-Age/Expires/SameSite parsing is implemented.\n");

  int wrote = 0;
  const char *p = hdrs;
  while (p && *p)
    {
      if (strncasecmp (p, "Set-Cookie:", 11) == 0)
        {
          const char *v = p + 11;
          while (*v == ' ' || *v == '\t') v++;
          const char *eol = strstr (v, "\r\n");
          size_t n = eol ? (size_t) (eol - v) : strlen (v);
          char line[1024];
          if (n >= sizeof line) n = sizeof line - 1;
          memcpy (line, v, n); line[n] = '\0';

          char *attrs = strchr (line, ';');
          if (attrs) *attrs++ = '\0';
          char *eq = strchr (line, '=');
          if (!eq || eq == line) goto next_line;
          *eq++ = '\0';
          bc_trim_cookie_token (line);
          bc_trim_cookie_token (eq);

          char pathbuf[256] = "/";
          char domainbuf[256];
          snprintf (domainbuf, sizeof domainbuf, "%s", u->host);
          int tailmatch = 0;
          int secure = 0;
          int httponly = 0;
          char samesite[8] = "";
          long expires = 0;
          int drop_cookie = 0;
          for (char *tok = attrs; tok; )
            {
              while (*tok == ' ' || *tok == '\t' || *tok == ';') tok++;
              char *next = strchr (tok, ';');
              if (next) *next++ = '\0';
              bc_trim_cookie_token (tok);
              if (strncasecmp (tok, "Path=", 5) == 0 && tok[5])
                snprintf (pathbuf, sizeof pathbuf, "%s", tok + 5);
              else if (strncasecmp (tok, "Domain=", 7) == 0 && tok[7])
                {
                  const char *d = tok + 7;
                  if (!bc_cookie_accept_domain (u->host, d, domainbuf,
                                                sizeof domainbuf, &tailmatch))
                    drop_cookie = 1;
                }
              else if (strncasecmp (tok, "Max-Age=", 8) == 0)
                {
                  long age = bc_cookie_max_age (tok + 8);
                  if (age <= 0)
                    drop_cookie = 1;
                  else
                    expires = (long) time (NULL) + age;
                }
              else if (strncasecmp (tok, "Expires=", 8) == 0)
                {
                  long when = 0;
                  if (bc_cookie_parse_http_date (tok + 8, &when) == 0)
                    {
                      if (when <= (long) time (NULL))
                        drop_cookie = 1;
                      else if (expires == 0)
                        expires = when;
                    }
                }
              else if (strcasecmp (tok, "Secure") == 0)
                secure = 1;
              else if (strcasecmp (tok, "HttpOnly") == 0)
                httponly = 1;
              else if (strncasecmp (tok, "SameSite=", 9) == 0)
                bc_cookie_samesite_value (tok + 9, samesite, sizeof samesite);
              tok = next;
            }
          if (strcasecmp (samesite, "None") == 0 && !secure)
            drop_cookie = 1;
          if (drop_cookie) goto next_line;
          fprintf (fp, "%s%s\t%s\t%s\t%s\t%ld\t%s\t%s\n",
                   httponly ? "#HttpOnly_" : "", domainbuf,
                   tailmatch ? "TRUE" : "FALSE", pathbuf,
                   secure ? "TRUE" : "FALSE", expires, line, eq);
          if (samesite[0])
            fprintf (fp, "# Bashcurl-SameSite\t%s\t%s\t%s\t%s\n",
                     domainbuf, pathbuf, line, samesite);
          wrote++;
        }
next_line:
      p = strstr (p, "\r\n");
      if (!p) break;
      p += 2;
    }

  if (fclose (fp) != 0)
    { builtin_error ("%s: %s", path, strerror (errno)); return -1; }
  return wrote >= 0 ? 0 : -1;
}

/* ---- network: HTTP (plain TCP) ---- */
static int
bc_connect_tcp (const char *host, const char *port, int timeout_s)
{
  struct addrinfo hints, *ai = NULL, *p;
  memset (&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  /* Retry getaddrinfo on EAI_AGAIN (a *temporary* resolver failure that means
   * "try again") with a short backoff, mirroring crypto's TLS connect: under
   * QEMU slirp the built-in DNS forwarder is intermittently flaky on some names,
   * which would otherwise fail a plain-HTTP fetch on the first hiccup. Permanent
   * errors (EAI_NONAME, ...) still fail at once. */
  int rc;
  for (int attempt = 0; ; attempt++)
    {
      ai = NULL;
      rc = getaddrinfo (host, port, &hints, &ai);
      if (rc != EAI_AGAIN || attempt >= 5) break;   /* up to 6 attempts */
      long ms = 200 + attempt * 200; if (ms > 1000) ms = 1000;
      struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
      nanosleep (&ts, NULL);
    }
  if (rc != 0)
    {
      builtin_error ("getaddrinfo %s:%s: %s", host, port, gai_strerror (rc));
      return -1;
    }
  int fd = -1;
  for (p = ai; p; p = p->ai_next)
    {
      fd = socket (p->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
      if (fd < 0) continue;

      int flags = fcntl (fd, F_GETFL, 0);
      fcntl (fd, F_SETFL, flags | O_NONBLOCK);
      rc = connect (fd, p->ai_addr, p->ai_addrlen);
      if (rc == 0) { fcntl (fd, F_SETFL, flags); break; }
      if (errno != EINPROGRESS) { close (fd); fd = -1; continue; }

      fd_set wfds;
      FD_ZERO (&wfds); FD_SET (fd, &wfds);
      struct timeval tv = { .tv_sec = timeout_s, .tv_usec = 0 };
      int sr = select (fd + 1, NULL, &wfds, NULL, &tv);
      if (sr <= 0) { close (fd); fd = -1; continue; }

      int err = 0; socklen_t el = sizeof err;
      if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err != 0)
        { close (fd); fd = -1; continue; }
      fcntl (fd, F_SETFL, flags);
      break;
    }
  freeaddrinfo (ai);
  if (fd < 0)
    builtin_error ("cannot connect to %s:%s", host, port);
  return fd;
}

static int
bc_write_all (int fd, const char *buf, size_t n)
{
  size_t off = 0;
  while (off < n)
    {
      ssize_t w = write (fd, buf + off, n - off);
      if (w < 0) { if (errno == EINTR) continue; return -1; }
      off += (size_t) w;
    }
  return 0;
}

static unsigned char *
bc_read_until_close (int fd, int timeout_s, size_t *out_len)
{
  size_t cap = BCURL_READ_CHUNK;
  size_t got = 0;
  unsigned char *buf = malloc (cap);
  if (!buf) { builtin_error ("out of memory"); return NULL; }

  time_t deadline = time (NULL) + timeout_s;
  for (;;)
    {
      time_t now = time (NULL);
      if (now >= deadline)
        { builtin_error ("timeout reading response"); free (buf); return NULL; }
      struct timeval tv = { .tv_sec = deadline - now, .tv_usec = 0 };
      fd_set rfds;
      FD_ZERO (&rfds); FD_SET (fd, &rfds);
      int sr = select (fd + 1, &rfds, NULL, NULL, &tv);
      if (sr < 0)  { if (errno == EINTR) continue;
                     builtin_error ("select: %s", strerror (errno));
                     free (buf); return NULL; }
      if (sr == 0) { builtin_error ("timeout reading response");
                     free (buf); return NULL; }

      if (got + BCURL_READ_CHUNK > cap)
        {
          if (cap >= BCURL_MAX_RESPONSE)
            { builtin_error ("response exceeds %d bytes", BCURL_MAX_RESPONSE);
              free (buf); return NULL; }
          size_t ncap = cap * 2;
          if (ncap > BCURL_MAX_RESPONSE) ncap = BCURL_MAX_RESPONSE;
          unsigned char *nb = realloc (buf, ncap);
          if (!nb) { builtin_error ("out of memory"); free (buf); return NULL; }
          buf = nb; cap = ncap;
        }
      ssize_t r = read (fd, buf + got, cap - got);
      if (r < 0) { if (errno == EINTR) continue;
                   builtin_error ("read: %s", strerror (errno));
                   free (buf); return NULL; }
      if (r == 0) break;                       /* clean EOF */
      got += (size_t) r;
    }
  *out_len = got;
  return buf;
}

/* ---- HTTPS transport: tunnel the request through crypto tls connect ---- */
static unsigned char *
bc_https_exchange (const bc_url *u, const char *req, size_t reqlen,
                   int insecure, const char *cacert, int timeout_s,
                   size_t *out_len)
{
  /* Build a bash one-liner that:
   *   1. cats the request from FIFO-fd 0 via a here-doc-style printf
   *   2. pipes it into `crypto tls connect HOST:PORT -s HOST [-k]`
   *
   * We use bidirectional popen-style coupling: fork a child that runs
   * `bash -c CMD`, with parent->child stdin = request, child->parent
   * stdout = response. socketpair would also work; pipe pairs are fine.
   *
   * (void) timeout_s — TLS connect timeout is enforced by crypto
   * internally (its own connect()); we re-check the read clock on the
   * parent side via select() in the read loop below. */
  int in_pipe[2], out_pipe[2];
  if (pipe (in_pipe) < 0)  { builtin_error ("pipe: %s", strerror (errno)); return NULL; }
  if (pipe (out_pipe) < 0) { close (in_pipe[0]); close (in_pipe[1]);
                             builtin_error ("pipe: %s", strerror (errno)); return NULL; }
  struct sigaction chld_dfl, chld_save;
  memset (&chld_dfl, 0, sizeof chld_dfl);
  chld_dfl.sa_handler = SIG_DFL;
  sigemptyset (&chld_dfl.sa_mask);
  sigaction (SIGCHLD, &chld_dfl, &chld_save);

  sigset_t chld_set, prev_mask;
  sigemptyset (&chld_set);
  sigaddset (&chld_set, SIGCHLD);
  sigprocmask (SIG_BLOCK, &chld_set, &prev_mask);

  pid_t pid = fork ();
  if (pid < 0)
    { close (in_pipe[0]); close (in_pipe[1]); close (out_pipe[0]); close (out_pipe[1]);
      sigprocmask (SIG_SETMASK, &prev_mask, NULL);
      sigaction (SIGCHLD, &chld_save, NULL);
      builtin_error ("fork: %s", strerror (errno)); return NULL; }
  if (pid == 0)
    {
      sigprocmask (SIG_SETMASK, &prev_mask, NULL);
      dup2 (in_pipe[0], 0);
      dup2 (out_pipe[1], 1);
      close (in_pipe[0]); close (in_pipe[1]);
      close (out_pipe[0]); close (out_pipe[1]);
      char hostport[320];
      snprintf (hostport, sizeof hostport, "%s:%s", u->host, u->port);
      /* crypto is a builtin (no PATH binary). Use `builtin` to
       * force builtin-lookup dispatch; the wrapping /bin/bash is the
       * bash-os shell that has crypto compiled in. `exec
       * crypto …` would walk PATH for an external crypto and
       * fail with "not found", silently dropping the TLS handshake. */
      if (cacert && *cacert && insecure)
        execl ("/bin/bash", "bash", "-c",
               "builtin crypto tls connect \"$1\" -s \"$2\" -c \"$3\" -k",
               "bash", hostport, u->host, cacert, (char *) NULL);
      else if (cacert && *cacert)
        execl ("/bin/bash", "bash", "-c",
               "builtin crypto tls connect \"$1\" -s \"$2\" -c \"$3\"",
               "bash", hostport, u->host, cacert, (char *) NULL);
      else if (insecure)
        execl ("/bin/bash", "bash", "-c",
               "builtin crypto tls connect \"$1\" -s \"$2\" -k",
               "bash", hostport, u->host, (char *) NULL);
      else
        execl ("/bin/bash", "bash", "-c",
               "builtin crypto tls connect \"$1\" -s \"$2\"",
               "bash", hostport, u->host, (char *) NULL);
      _exit (127);
    }
  close (in_pipe[0]); close (out_pipe[1]);

  /* Push request to child stdin. */
  if (bc_write_all (in_pipe[1], req, reqlen) < 0)
    {
      builtin_error ("write to tls subshell: %s", strerror (errno));
      close (in_pipe[1]); close (out_pipe[0]);
      while (waitpid (pid, NULL, 0) < 0 && errno == EINTR) ;
      sigprocmask (SIG_SETMASK, &prev_mask, NULL);
      sigaction (SIGCHLD, &chld_save, NULL);
      return NULL;
    }
  close (in_pipe[1]);

  unsigned char *resp = bc_read_until_close (out_pipe[0], timeout_s, out_len);
  close (out_pipe[0]);

  int wstat = 0;
  while (waitpid (pid, &wstat, 0) < 0 && errno == EINTR) ;
  sigprocmask (SIG_SETMASK, &prev_mask, NULL);
  sigaction (SIGCHLD, &chld_save, NULL);
  if (!resp) return NULL;
  /* crypto exit-non-zero only matters if response is empty; otherwise
   * the response was already piped through and is usable. */
  if (*out_len == 0 && WIFEXITED (wstat) && WEXITSTATUS (wstat) != 0)
    {
      builtin_error ("tls subshell failed (rc=%d)", WEXITSTATUS (wstat));
      free (resp);
      return NULL;
    }
  return resp;
}

/* ---- response parser: split status/headers/body, handle chunked + Location ---- */
static int
bc_chunked (const char *hdrs)
{
  /* Walk lines, look for Transfer-Encoding: chunked (case-insensitive). */
  const char *p = hdrs;
  while (p && *p)
    {
      if (strncasecmp (p, "Transfer-Encoding:", 18) == 0)
        {
          const char *v = p + 18;
          while (*v == ' ' || *v == '\t') v++;
          if (strncasecmp (v, "chunked", 7) == 0) return 1;
        }
      p = strstr (p, "\r\n");
      if (!p) break;
      p += 2;
    }
  return 0;
}

static long
bc_content_length (const char *hdrs)
{
  const char *p = hdrs;
  while (p && *p)
    {
      if (strncasecmp (p, "Content-Length:", 15) == 0)
        {
          const char *v = p + 15;
          while (*v == ' ' || *v == '\t') v++;
          return strtol (v, NULL, 10);
        }
      p = strstr (p, "\r\n");
      if (!p) break;
      p += 2;
    }
  return -1;
}

static void
bc_extract_location (const char *hdrs, char *out, size_t cap)
{
  out[0] = '\0';
  const char *p = hdrs;
  while (p && *p)
    {
      if (strncasecmp (p, "Location:", 9) == 0)
        {
          const char *v = p + 9;
          while (*v == ' ' || *v == '\t') v++;
          const char *eol = strstr (v, "\r\n");
          size_t n = eol ? (size_t) (eol - v) : strlen (v);
          if (n >= cap) n = cap - 1;
          memcpy (out, v, n);
          out[n] = '\0';
          return;
        }
      p = strstr (p, "\r\n");
      if (!p) break;
      p += 2;
    }
}

/* De-chunk a chunked-transfer body in place; returns new length, or -1 on
 * malformed input. */
static long
bc_dechunk (unsigned char *body, size_t blen)
{
  size_t in = 0, out = 0;
  while (in < blen)
    {
      /* find end-of-size-line */
      size_t i = in;
      while (i < blen && body[i] != '\n') i++;
      if (i >= blen) return -1;
      /* parse hex chunk size (ignore extensions after ';') */
      char szbuf[32]; size_t sl = i - in;
      if (sl >= sizeof szbuf) return -1;
      memcpy (szbuf, body + in, sl); szbuf[sl] = '\0';
      char *semi = strchr (szbuf, ';'); if (semi) *semi = '\0';
      long chunk = strtol (szbuf, NULL, 16);
      in = i + 1; /* past LF */
      if (chunk < 0) return -1;
      if (chunk == 0) return (long) out;
      if (in + (size_t) chunk > blen) return -1;
      memmove (body + out, body + in, (size_t) chunk);
      out += (size_t) chunk;
      in += (size_t) chunk;
      /* trailing CRLF after chunk */
      if (in + 2 > blen) return -1;
      in += 2;
    }
  return (long) out;
}

static int
bc_parse_response (unsigned char *raw, size_t rawlen, bc_response *r)
{
  memset (r, 0, sizeof *r);
  if (rawlen < 12 || memcmp (raw, "HTTP/", 5) != 0)
    { builtin_error ("malformed response (no HTTP/ status line)"); return -1; }
  r->status = atoi ((char *) raw + 9);

  /* find header/body separator */
  size_t i, body = rawlen;
  int found = 0;
  size_t end = rawlen > BCURL_HEADER_MAX ? BCURL_HEADER_MAX : rawlen;
  for (i = 0; i + 4 <= end; i++)
    if (raw[i] == '\r' && raw[i+1] == '\n' && raw[i+2] == '\r' && raw[i+3] == '\n')
      { body = i + 4; found = 1; break; }
  if (!found)
    { builtin_error ("no header/body separator"); return -1; }

  size_t hlen = body - 2;       /* keep trailing \r\n before the blank line */
  r->headers = malloc (hlen + 1);
  if (!r->headers) { builtin_error ("out of memory"); return -1; }
  memcpy (r->headers, raw, hlen);
  r->headers[hlen] = '\0';
  r->hlen = hlen;

  size_t blen = rawlen - body;
  r->body = malloc (blen ? blen : 1);
  if (!r->body) { free (r->headers); builtin_error ("out of memory"); return -1; }
  if (blen) memcpy (r->body, raw + body, blen);
  r->blen = blen;

  if (bc_chunked (r->headers))
    {
      long n = bc_dechunk (r->body, r->blen);
      if (n < 0) { builtin_error ("malformed chunked body");
                   free (r->headers); free (r->body); return -1; }
      r->blen = (size_t) n;
    }
  else
    {
      long cl = bc_content_length (r->headers);
      if (cl >= 0 && (size_t) cl < r->blen)
        r->blen = (size_t) cl;
    }

  if (r->status >= 300 && r->status < 400)
    bc_extract_location (r->headers, r->location, sizeof r->location);

  return 0;
}

static void
bc_response_free (bc_response *r)
{
  if (!r) return;
  free (r->headers); free (r->body);
  r->headers = NULL; r->body = NULL;
}

/* ---- emit body to outfile/stdout ---- */
static int
bc_emit (const bc_opts *o, const bc_url *u, const bc_response *r)
{
  const char *out = o->outfile;
  /* nbuf must match u->path's size (2048) so -Wformat-truncation is
   * silenced for the pathological case of a path with no '/'. */
  char nbuf[2048];
  if (!out && o->use_basename)
    {
      const char *slash = strrchr (u->path, '/');
      const char *base = slash ? slash + 1 : u->path;
      if (!*base) base = "index.html";
      snprintf (nbuf, sizeof nbuf, "%s", base);
      out = nbuf;
    }
  FILE *fp;
  if (!out || strcmp (out, "-") == 0)
    fp = stdout;
  else
    {
      fp = fopen (out, "wb");
      if (!fp)
        { builtin_error ("%s: %s", out, strerror (errno)); return -1; }
    }
  size_t w = fwrite (r->body, 1, r->blen, fp);
  if (fp != stdout) fclose (fp);
  else fflush (fp);
  return (w == r->blen) ? 0 : -1;
}

static int
bc_emit_headers (const bc_opts *o, const bc_response *r)
{
  if (!o->dump_headers) return 0;
  FILE *fp;
  if (strcmp (o->dump_headers, "-") == 0)
    fp = stdout;
  else
    {
      fp = fopen (o->dump_headers, "wb");
      if (!fp)
        { builtin_error ("%s: %s", o->dump_headers, strerror (errno)); return -1; }
    }
  size_t w = fwrite (r->headers, 1, r->hlen, fp);
  if (w == r->hlen)
    w += fwrite ("\r\n", 1, 2, fp);
  if (fp != stdout) fclose (fp);
  else fflush (fp);
  return (w == r->hlen + 2) ? 0 : -1;
}

static int
bc_emit_write_out (const bc_opts *o, const bc_response *r)
{
  if (!o->write_out) return 0;
  const char *fmt = o->write_out;
  while (*fmt)
    {
      if (strncmp (fmt, "%{http_code}", 12) == 0)
        {
          printf ("%03d", r->status);
          fmt += 12;
          continue;
        }
      /* GNU curl -w interprets C-style backslash escapes in the format. */
      if (*fmt == '\\' && fmt[1])
        {
          fmt++;
          switch (*fmt)
            {
            case 'n': putchar ('\n'); break;
            case 't': putchar ('\t'); break;
            case 'r': putchar ('\r'); break;
            case '\\': putchar ('\\'); break;
            default:  putchar ('\\'); putchar (*fmt); break;
            }
          fmt++;
          continue;
        }
      if (fmt[0] == '%' && fmt[1] == '%')   /* %% -> literal % */
        { putchar ('%'); fmt += 2; continue; }
      putchar (*fmt++);
    }
  fflush (stdout);
  return 0;
}

/* ---- single request roundtrip (no redirect handling at this layer) ---- */
static int
bc_one_request (const bc_opts *o, const char *url_override, bc_response *out_resp)
{
  bc_url u;
  const char *use_url = url_override ? url_override : o->url;
  if (bc_parse_url (use_url, &u) < 0)
    { builtin_error ("invalid URL: %s", use_url); return -1; }

  int is_https = (strcasecmp (u.scheme, "https") == 0);
  int is_http  = (strcasecmp (u.scheme, "http")  == 0);
  if (!is_http && !is_https)
    { builtin_error ("unsupported scheme: %s", u.scheme); return -1; }

  size_t reqlen = 0;
  char *req = bc_build_request (o, &u, &reqlen);
  if (!req) return -1;

  int timeout = o->max_time > 0 ? o->max_time : BCURL_DEFAULT_TIMEOUT;
  int connect_timeout = o->connect_time > 0 ? o->connect_time : timeout;
  size_t raw_len = 0;
  unsigned char *raw = NULL;
  if (is_https)
    {
      raw = bc_https_exchange (&u, req, reqlen, o->insecure, o->cacert,
                               timeout, &raw_len);
    }
  else
    {
      int fd = bc_connect_tcp (u.host, u.port, connect_timeout);
      if (fd < 0) { free (req); return -1; }
      if (bc_write_all (fd, req, reqlen) < 0)
        { builtin_error ("write: %s", strerror (errno)); close (fd); free (req); return -1; }
      raw = bc_read_until_close (fd, timeout, &raw_len);
      close (fd);
    }
  free (req);
  if (!raw) return -1;

  int rc = bc_parse_response (raw, raw_len, out_resp);
  free (raw);
  return rc;
}

/* Resolve a relative Location against the current absolute URL.
 * Trivial implementation: absolute (with scheme) wins; otherwise
 * scheme://host[:port] + (loc[0]=='/' ? loc : dir+loc). */
static int
bc_resolve_redirect (const char *cur, const char *loc, char *out, size_t cap)
{
  if (strstr (loc, "://"))
    {
      snprintf (out, cap, "%s", loc);
      return 0;
    }
  bc_url u;
  if (bc_parse_url (cur, &u) < 0) return -1;
  const char *port_sep = "";
  const char *port_str = "";
  /* Only emit :port when non-default for the scheme. */
  int is_https = (strcasecmp (u.scheme, "https") == 0);
  if ((is_https && strcmp (u.port, "443") != 0) ||
      (!is_https && strcmp (u.port, "80")  != 0))
    { port_sep = ":"; port_str = u.port; }
  if (loc[0] == '/')
    snprintf (out, cap, "%s://%s%s%s%s", u.scheme, u.host, port_sep, port_str, loc);
  else
    {
      char dir[2048];
      snprintf (dir, sizeof dir, "%s", u.path);
      char *slash = strrchr (dir, '/');
      if (slash) slash[1] = '\0'; else strcpy (dir, "/");
      snprintf (out, cap, "%s://%s%s%s%s%s", u.scheme, u.host, port_sep, port_str, dir, loc);
    }
  return 0;
}

/* ---- main builtin entrypoint ---- */
static void
bc_usage (void)
{
  builtin_error ("usage: curl [-fsSLkO] [-X METHOD] [-H HDR]... [-d DATA]");
  builtin_error ("                [--data-binary DATA] [-o FILE] [-D FILE] [-w FORMAT]");
  builtin_error ("                [-u USER:PASS] [-A AGENT] [-b COOKIE|FILE] [-c FILE]");
  builtin_error ("                [--cacert PEM] [--connect-timeout SEC] [-m|--max-time SEC]");
  builtin_error ("                [--max-redirs N] [--features] [-V|--version] URL");
  builtin_error ("                supported long aliases accept --name=value");
}

static void
bc_print_caps (void)
{
  puts ("Protocols: http https");
  puts ("Features: basic-auth cacert connect-timeout cookie cookie-jar cookie-policy data-binary fail location max-redirs output-file output-remote-name show-error silent timeout write-out");
}

static void
bc_features (void)
{
  bc_print_caps ();
  puts ("TLS: crypto");
  puts ("Unsupported: ftp smtp scp http2 multipart non-http-cookie-schemes");
}

static void
bc_version (void)
{
  puts ("curl " BCURL_VERSION " (bash-os) curl/" BCURL_VERSION " TLS:crypto");
  bc_print_caps ();
}

static const char *
bc_long_eq (const char *w, const char *name)
{
  size_t n = strlen (name);
  return strncmp (w, name, n) == 0 && w[n] == '=' ? w + n + 1 : NULL;
}

static int
bc_next_arg (WORD_LIST **pp, const char *opt, const char **out)
{
  WORD_LIST *p = *pp;
  if (!p->next)
    {
      builtin_error ("option requires an argument: %s", opt);
      return EX_USAGE;
    }
  p = p->next;
  *pp = p;
  *out = p->word->word;
  return EXECUTION_SUCCESS;
}

static int
bc_add_header_opt (bc_opts *o, const char *arg)
{
  if (o->nheaders >= BCURL_HEADER_SLOTS)
    {
      builtin_error ("too many -H headers");
      return EX_USAGE;
    }
  o->headers[o->nheaders++] = (char *) arg;
  return EXECUTION_SUCCESS;
}

static void
bc_set_data_opt (bc_opts *o, const char *arg)
{
  o->body = arg;
  o->body_len = strlen (o->body);
  o->body_set = 1;
  if (!strcmp (o->method, "GET")) o->method = "POST";
}

static int
bc_set_data_binary_opt (bc_opts *o, const char *arg)
{
  if (!strcmp (arg, "@-"))
    {
      if (bc_slurp_fd_string (STDIN_FILENO, &o->body_alloc, &o->body_len) < 0)
        return EXECUTION_FAILURE;
      o->body = o->body_alloc;
    }
  else if (arg[0] == '@')
    {
      int fd = open (arg + 1, O_RDONLY | O_CLOEXEC);
      if (fd < 0)
        {
          builtin_error ("%s: %s", arg + 1, strerror (errno));
          return EXECUTION_FAILURE;
        }
      if (bc_slurp_fd_string (fd, &o->body_alloc, &o->body_len) < 0)
        {
          close (fd);
          return EXECUTION_FAILURE;
        }
      close (fd);
      o->body = o->body_alloc;
    }
  else
    {
      o->body = arg;
      o->body_len = strlen (arg);
    }
  o->body_set = 1;
  if (!strcmp (o->method, "GET")) o->method = "POST";
  return EXECUTION_SUCCESS;
}

static int
bc_apply_short_options (bc_opts *o, const char *w, WORD_LIST **pp)
{
  for (const char *p = w + 1; *p; p++)
    {
      const char *arg;
      switch (*p)
        {
        case 'f': o->fail_on_error = 1; break;
        case 's': o->silent = 1; break;
        case 'S': o->show_error = 1; break;
        case 'L': o->follow = 1; break;
        case 'k': o->insecure = 1; break;
        case 'O': o->use_basename = 1; break;
        case 'X':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-X", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          o->method = arg;
          return EXECUTION_SUCCESS;
        case 'H':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-H", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          return bc_add_header_opt (o, arg);
        case 'd':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-d", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          bc_set_data_opt (o, arg);
          return EXECUTION_SUCCESS;
        case 'o':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-o", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          o->outfile = arg;
          return EXECUTION_SUCCESS;
        case 'D':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-D", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          o->dump_headers = arg;
          return EXECUTION_SUCCESS;
        case 'w':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-w", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          o->write_out = arg;
          return EXECUTION_SUCCESS;
        case 'u':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-u", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          o->userpass = arg;
          return EXECUTION_SUCCESS;
        case 'A':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-A", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          o->user_agent = arg;
          return EXECUTION_SUCCESS;
        case 'b':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-b", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          o->cookie = arg;
          o->cookie_input = arg;
          return EXECUTION_SUCCESS;
        case 'c':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-c", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          o->cookie_jar = arg;
          return EXECUTION_SUCCESS;
        case 'm':
          arg = p[1] ? p + 1 : NULL;
          if (!arg && bc_next_arg (pp, "-m", &arg) != EXECUTION_SUCCESS) return EX_USAGE;
          o->max_time = atoi (arg);
          return EXECUTION_SUCCESS;
        default:
          builtin_error ("unknown option: -%c", *p);
          return EX_USAGE;
        }
    }
  return EXECUTION_SUCCESS;
}

int
curl_builtin (WORD_LIST *list)
{
  bc_opts o; memset (&o, 0, sizeof o);
  o.method = "GET";

  for (WORD_LIST *p = list; p; p = p->next)
    {
      const char *w = p->word->word;
      const char *v = NULL;
      if (!strcmp (w, "--request"))                  { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) return EX_USAGE; o.method = v; }
      else if ((v = bc_long_eq (w, "--request")))     { o.method = v; }
      else if (!strcmp (w, "--header"))              { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) return EX_USAGE; int hrc = bc_add_header_opt (&o, v); if (hrc != EXECUTION_SUCCESS) return hrc; }
      else if ((v = bc_long_eq (w, "--header")))      { int hrc = bc_add_header_opt (&o, v); if (hrc != EXECUTION_SUCCESS) return hrc; }
      else if (!strcmp (w, "--data") || !strcmp (w, "--data-raw") || !strcmp (w, "--data-ascii"))
        { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) return EX_USAGE; bc_set_data_opt (&o, v); }
      else if ((v = bc_long_eq (w, "--data")) || (v = bc_long_eq (w, "--data-raw")) || (v = bc_long_eq (w, "--data-ascii")))
        { bc_set_data_opt (&o, v); }
      else if (!strcmp (w, "--data-binary"))
        {
          if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) return EX_USAGE;
          if (bc_set_data_binary_opt (&o, v) != EXECUTION_SUCCESS)
            { free (o.body_alloc); return EXECUTION_FAILURE; }
        }
      else if ((v = bc_long_eq (w, "--data-binary"))) { if (bc_set_data_binary_opt (&o, v) != EXECUTION_SUCCESS) { free (o.body_alloc); return EXECUTION_FAILURE; } }
      else if (!strcmp (w, "--output"))              { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) return EX_USAGE; o.outfile = v; }
      else if ((v = bc_long_eq (w, "--output")))      { o.outfile = v; }
      else if (!strcmp (w, "--dump-header"))         { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) return EX_USAGE; o.dump_headers = v; }
      else if ((v = bc_long_eq (w, "--dump-header"))) { o.dump_headers = v; }
      else if (!strcmp (w, "--write-out"))           { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) return EX_USAGE; o.write_out = v; }
      else if ((v = bc_long_eq (w, "--write-out")))   { o.write_out = v; }
      else if (!strcmp (w, "--user"))                { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) return EX_USAGE; o.userpass = v; }
      else if ((v = bc_long_eq (w, "--user")))        { o.userpass = v; }
      else if (!strcmp (w, "--user-agent"))          { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) return EX_USAGE; o.user_agent = v; }
      else if ((v = bc_long_eq (w, "--user-agent")))  { o.user_agent = v; }
      else if (!strcmp (w, "--cookie"))              { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) return EX_USAGE; o.cookie = v; o.cookie_input = v; }
      else if ((v = bc_long_eq (w, "--cookie")))      { o.cookie = v; o.cookie_input = v; }
      else if (!strcmp (w, "--cookie-jar"))          { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) return EX_USAGE; o.cookie_jar = v; }
      else if ((v = bc_long_eq (w, "--cookie-jar")))  { o.cookie_jar = v; }
      else if (!strcmp (w, "--cacert"))              { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) return EX_USAGE; o.cacert = v; }
      else if ((v = bc_long_eq (w, "--cacert")))      { o.cacert = v; }
      else if (!strcmp (w, "-k") || !strcmp (w, "--insecure"))   o.insecure = 1;
      else if (!strcmp (w, "-f") || !strcmp (w, "--fail"))       o.fail_on_error = 1;
      else if (!strcmp (w, "-s") || !strcmp (w, "--silent"))     o.silent = 1;
      else if (!strcmp (w, "-S") || !strcmp (w, "--show-error")) o.show_error = 1;
      else if (!strcmp (w, "-L") || !strcmp (w, "--location"))   o.follow = 1;
      else if (!strcmp (w, "--connect-timeout"))      { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) return EX_USAGE; o.connect_time = atoi (v); }
      else if ((v = bc_long_eq (w, "--connect-timeout"))) { o.connect_time = atoi (v); }
      else if (!strcmp (w, "--max-time"))             { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) return EX_USAGE; o.max_time = atoi (v); }
      else if ((v = bc_long_eq (w, "--max-time")))     { o.max_time = atoi (v); }
      else if (!strcmp (w, "--max-redirs"))           { if (bc_next_arg (&p, w, &v) != EXECUTION_SUCCESS) return EX_USAGE; o.max_redirs = atoi (v); }
      else if ((v = bc_long_eq (w, "--max-redirs")))   { o.max_redirs = atoi (v); }
      else if (!strcmp (w, "--features"))              o.features = 1;
      else if (!strcmp (w, "--version") || !strcmp (w, "-V")) { bc_version (); free (o.body_alloc); return EXECUTION_SUCCESS; }
      else if (!strcmp (w, "-h") || !strcmp (w, "--help"))       { bc_usage (); return EXECUTION_SUCCESS; }
      else if (w[0] == '-' && w[1] != '-' && w[1] != '\0')
        {
          int brc = bc_apply_short_options (&o, w, &p);
          if (brc != EXECUTION_SUCCESS) return brc;
        }
      else if (w[0] == '-' && w[1] != '\0')
        { builtin_error ("unknown option: %s", w); return EX_USAGE; }
      else
        {
          if (o.url) { builtin_error ("extra URL: %s", w); return EX_USAGE; }
          o.url = w;
        }
    }
  if (o.features) { bc_features (); free (o.body_alloc); return EXECUTION_SUCCESS; }
  if (!o.url) { bc_usage (); return EX_USAGE; }

  /* Coalesce silent/show_error: -s -S keeps error diagnostics, -s alone
   * suppresses them. The bash builtin_error path always goes to stderr;
   * we just gate the call. */
  int show_errs = (!o.silent) || o.show_error;

  char cur_url[2048];
  snprintf (cur_url, sizeof cur_url, "%s", o.url);
  bc_url start_url;
  int have_start_url = bc_parse_url (cur_url, &start_url) == 0;
  int cookie_from_file = o.cookie_input && strchr (o.cookie_input, '=') == NULL
                         && have_start_url && access (o.cookie_input, R_OK) == 0;

  bc_response r;
  int redirects = 0;
  int rc;
  for (;;)
    {
      memset (&r, 0, sizeof r);
      if (cookie_from_file)
        {
          bc_url req_url;
          free (o.cookie_alloc);
          o.cookie_alloc = NULL;
          o.cookie = NULL;
          if (bc_parse_url (cur_url, &req_url) == 0)
            {
              o.cookie_alloc = bc_cookie_from_jar (o.cookie_input, &req_url,
                                                   &start_url, o.method);
              if (o.cookie_alloc)
                o.cookie = o.cookie_alloc;
            }
        }
      rc = bc_one_request (&o, cur_url, &r);
      if (rc < 0)
        {
          if (!show_errs)
            { /* swallow the builtin_error diagnostic by not adding more */ }
          free (o.cookie_alloc);
          free (o.body_alloc);
          return EXECUTION_FAILURE;
        }
      if (o.follow && r.status >= 300 && r.status < 400 && r.location[0])
        {
          int rcap = o.max_redirs > 0 ? o.max_redirs : BCURL_MAX_REDIRECTS;
          if (++redirects > rcap)
            { if (show_errs) builtin_error ("too many redirects (>%d)", rcap);
              bc_response_free (&r); free (o.cookie_alloc); free (o.body_alloc); return EXECUTION_FAILURE; }
          char next[2048];
          if (bc_resolve_redirect (cur_url, r.location, next, sizeof next) < 0)
            { if (show_errs) builtin_error ("bad redirect target: %s", r.location);
              bc_response_free (&r); free (o.cookie_alloc); free (o.body_alloc); return EXECUTION_FAILURE; }
          snprintf (cur_url, sizeof cur_url, "%s", next);
          bc_response_free (&r);
          continue;
        }
      break;
    }

  if (o.fail_on_error && r.status >= 400)
    {
      if (show_errs)
        builtin_error ("HTTP %d", r.status);
      bc_response_free (&r);
      free (o.cookie_alloc);
      free (o.body_alloc);
      return 22; /* curl's CURLE_HTTP_RETURNED_ERROR */
    }

  bc_url eu;
  bc_parse_url (cur_url, &eu);
  if (bc_save_cookie_jar (o.cookie_jar, &eu, r.headers) < 0)
    {
      bc_response_free (&r);
      free (o.cookie_alloc);
      free (o.body_alloc);
      return EXECUTION_FAILURE;
    }
  if (bc_emit_headers (&o, &r) < 0)
    {
      bc_response_free (&r);
      free (o.cookie_alloc);
      free (o.body_alloc);
      return EXECUTION_FAILURE;
    }
  if (bc_emit (&o, &eu, &r) < 0)
    {
      bc_response_free (&r);
      free (o.cookie_alloc);
      free (o.body_alloc);
      return EXECUTION_FAILURE;
    }
  if (bc_emit_write_out (&o, &r) < 0)
    {
      bc_response_free (&r);
      free (o.cookie_alloc);
      free (o.body_alloc);
      return EXECUTION_FAILURE;
    }

  bc_response_free (&r);
  free (o.cookie_alloc);
  free (o.body_alloc);
  return EXECUTION_SUCCESS;
}

char *curl_doc[] = {
  "curl(1)-shaped HTTP client over http + crypto.",
  "  curl [-fsSLkO] [-X METHOD] [-H HDR]... [-d DATA]",
  "           [--data-binary DATA] [-o FILE] [-D FILE] [-w FORMAT]",
  "           [-u USER:PASS] [-A AGENT] [-b COOKIE|FILE] [-c FILE]",
  "           [--cacert PEM] [--connect-timeout SEC] [-m|--max-time SEC] [--max-redirs N]",
  "           [--features] [-V|--version] URL",
  "Long aliases and --name=value forms are normalized for supported options.",
  "Attached short arguments such as -oFILE and bundles like -fsSLo FILE work.",
  "Plain http:// uses raw TCP; https:// pipes the framed request through",
  "`crypto tls connect HOST:PORT -s HOST [-c PEM] [-k]` in a bash subshell.",
  "Subset: GET/POST/PUT/etc., common -f/-s/-S/-L/-k/-O bundles, -D, -w %{http_code},",
  "--data-binary (@-/@FILE/literal), Basic auth, -b/--cookie literal or jar input, -c/--cookie-jar output, redirects (default max 20),",
  "chunked + Content-Length decoding. Out of scope: -F multipart,",
  "non-HTTP cookie schemes, --resolve, HTTP/2, OAuth. wget(1) shape lives in wget.sh.",
  (char *) NULL
};

struct builtin curl_struct = {
  "curl",
  curl_builtin,
  BUILTIN_ENABLED,
  curl_doc,
  "curl [opts] URL",
  0
};
