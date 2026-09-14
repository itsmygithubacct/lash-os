/* claude.c -- Claude API (/v1/messages) client as a bash loadable builtin.
 *
 * Talks to the Claude API directly from inside the bash-os guest over the
 * image's own vendored mbedTLS (the same statically-linked stack crypto
 * uses -- no new link dependency). Supports streaming (SSE) and non-streaming
 * (--raw) requests, tool use (--tools passthrough), and self-updating its own
 * .so via the signed bash-os loadable-package pipeline (pkg).
 *
 *   claude prompt [OPTIONS] [MESSAGE]   send a message, print the reply
 *   claude models                       list known model ids
 *   claude version                      print loadable version
 *   claude update [PKGFILE]             verify+install+reload a new .so
 *   claude help                         usage
 *
 * The API key is read from $ANTHROPIC_API_KEY via getenv (never argv/history),
 * copied into an mlock'd buffer, and wiped before return. TLS certificate
 * verification of api.anthropic.com is on by default using the shipped CA
 * bundle (/etc/ssl/cert.pem -> /etc/ssl/certs/ca-certificates.crt).
 *
 * See docs/BASHCLAUDE.md for the full design + wire-protocol reference.
 *
 * SPDX-License-Identifier: MIT (GPL-3+-compatible; the combined bash binary is
 * GPL-3+ as a derivative of bash).
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>     /* strncasecmp */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/time.h>    /* struct timeval */
#include <sys/wait.h>    /* waitpid for `update` */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* Vendored mbedTLS (flattened by patch-bash-loadables.sh; already compiled
 * into the bash binary for crypto). Same include set crypto uses for
 * its TLS client. */
#include "_mbedtls_ssl.h"
#include "_mbedtls_ssl_ciphersuites.h"
#include "_mbedtls_x509_crt.h"
#include "_mbedtls_net_sockets.h"
#include "_mbedtls_error.h"
#include "_mbedtls_crypto.h"

#include "loadables.h"

#define BCL_VERSION            "1.0.0"
#define BCL_DEFAULT_MODEL      "claude-opus-4-8"
#define BCL_DEFAULT_HOST       "api.anthropic.com"
#define BCL_DEFAULT_PORT       443
#define BCL_API_VERSION        "2023-06-01"
#define BCL_DEFAULT_MAX_TOKENS 4096
#define BCL_IO_TIMEOUT_MS      120000   /* 2 min per read/write */

/* ----------------------------------------------------------------------- */
/* Small utilities                                                         */
/* ----------------------------------------------------------------------- */

/* Volatile wipe so the compiler cannot optimise the scrub away. */
static void
bcl_wipe (void *p, size_t n)
{
  volatile unsigned char *v = (volatile unsigned char *) p;
  while (n--) *v++ = 0;
}

/* Growable byte buffer. */
typedef struct { char *b; size_t len, cap; } sbuf;

static int
sb_grow (sbuf *s, size_t need)
{
  if (need > SIZE_MAX - s->len) return -1;
  if (s->len + need <= s->cap) return 0;
  size_t ncap = s->cap ? s->cap : 256;
  while (ncap < s->len + need) {
    if (ncap > SIZE_MAX / 2) { ncap = s->len + need; break; }
    ncap *= 2;
  }
  char *nb = realloc (s->b, ncap);
  if (!nb) return -1;
  s->b = nb; s->cap = ncap;
  return 0;
}

static int sb_putc (sbuf *s, char c) { if (sb_grow (s, 1) < 0) return -1; s->b[s->len++] = c; return 0; }
static int sb_put  (sbuf *s, const char *p, size_t n) { if (!n) return 0; if (sb_grow (s, n) < 0) return -1; memcpy (s->b + s->len, p, n); s->len += n; return 0; }
static int sb_puts (sbuf *s, const char *p) { return sb_put (s, p, strlen (p)); }

static void sb_free (sbuf *s) { free (s->b); s->b = NULL; s->len = s->cap = 0; }

/* Append S as a JSON string body (no surrounding quotes). */
static int
sb_json_escape (sbuf *s, const char *p)
{
  for (; *p; p++)
    {
      unsigned char c = (unsigned char) *p;
      switch (c)
        {
        case '"':  if (sb_puts (s, "\\\"") < 0) return -1; break;
        case '\\': if (sb_puts (s, "\\\\") < 0) return -1; break;
        case '\n': if (sb_puts (s, "\\n")  < 0) return -1; break;
        case '\r': if (sb_puts (s, "\\r")  < 0) return -1; break;
        case '\t': if (sb_puts (s, "\\t")  < 0) return -1; break;
        case '\b': if (sb_puts (s, "\\b")  < 0) return -1; break;
        case '\f': if (sb_puts (s, "\\f")  < 0) return -1; break;
        default:
          if (c < 0x20)
            {
              char u[8];
              snprintf (u, sizeof u, "\\u%04x", c);
              if (sb_puts (s, u) < 0) return -1;
            }
          else if (sb_putc (s, (char) c) < 0) return -1;   /* UTF-8 bytes pass through */
        }
    }
  return 0;
}

static int
bcl_write_all (int fd, const char *p, size_t n)
{
  while (n)
    {
      ssize_t w = write (fd, p, n);
      if (w < 0) { if (errno == EINTR) continue; return -1; }
      p += w; n -= (size_t) w;
    }
  return 0;
}

/* Encode codepoint CP as UTF-8 to stdout. */
static void
bcl_emit_cp (unsigned cp)
{
  char u[4];
  if (cp < 0x80) putchar ((int) cp);
  else if (cp < 0x800) { u[0] = 0xC0 | (cp >> 6); u[1] = 0x80 | (cp & 0x3F); fwrite (u, 1, 2, stdout); }
  else if (cp < 0x10000) { u[0] = 0xE0 | (cp >> 12); u[1] = 0x80 | ((cp >> 6) & 0x3F); u[2] = 0x80 | (cp & 0x3F); fwrite (u, 1, 3, stdout); }
  else { u[0] = 0xF0 | (cp >> 18); u[1] = 0x80 | ((cp >> 12) & 0x3F); u[2] = 0x80 | ((cp >> 6) & 0x3F); u[3] = 0x80 | (cp & 0x3F); fwrite (u, 1, 4, stdout); }
}

static unsigned
bcl_hex4 (const char *p)
{
  unsigned v = 0;
  for (int i = 0; i < 4; i++)
    {
      char c = p[i]; unsigned d;
      if (c >= '0' && c <= '9') d = c - '0';
      else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
      else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
      else return 0;
      v = (v << 4) | d;
    }
  return v;
}

/* Decode a JSON string value to stdout. P points at the first char AFTER the
 * opening quote; END bounds the buffer. Stops at the unescaped closing quote.
 * Returns a pointer past the closing quote, or NULL if unterminated. */
static const char *
bcl_emit_json_string (const char *p, const char *end)
{
  while (p < end)
    {
      char c = *p++;
      if (c == '"') return p;
      if (c != '\\') { putchar (c); continue; }
      if (p >= end) return NULL;
      char e = *p++;
      switch (e)
        {
        case '"':  putchar ('"'); break;
        case '\\': putchar ('\\'); break;
        case '/':  putchar ('/'); break;
        case 'n':  putchar ('\n'); break;
        case 'r':  putchar ('\r'); break;
        case 't':  putchar ('\t'); break;
        case 'b':  putchar ('\b'); break;
        case 'f':  putchar ('\f'); break;
        case 'u':
          {
            if (p + 4 > end) return NULL;
            unsigned cp = bcl_hex4 (p); p += 4;
            if (cp >= 0xD800 && cp <= 0xDBFF && p + 6 <= end && p[0] == '\\' && p[1] == 'u')
              {
                unsigned lo = bcl_hex4 (p + 2); p += 6;
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
              }
            bcl_emit_cp (cp);
          }
          break;
        default: putchar (e); break;
        }
    }
  return NULL;
}

/* ----------------------------------------------------------------------- */
/* TCP + TLS (self-contained; mirrors crypto's mbedTLS client idiom)    */
/* ----------------------------------------------------------------------- */

static int
bcl_tcp_connect (const char *host, int port, int timeout_ms)
{
  char portstr[16];
  snprintf (portstr, sizeof portstr, "%d", port);
  struct addrinfo hints, *res = NULL, *ai;
  memset (&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  int rc = getaddrinfo (host, portstr, &hints, &res);
  if (rc != 0) { builtin_error ("claude: getaddrinfo %s: %s", host, gai_strerror (rc)); return -1; }

  int fd = -1;
  for (ai = res; ai; ai = ai->ai_next)
    {
      fd = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
      if (fd < 0) continue;
      if (timeout_ms > 0)
        {
          struct timeval tv;
          tv.tv_sec = timeout_ms / 1000;
          tv.tv_usec = (timeout_ms % 1000) * 1000;
          setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
          setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        }
      if (connect (fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
      close (fd); fd = -1;
    }
  freeaddrinfo (res);
  if (fd < 0) builtin_error ("claude: connect %s:%d failed: %s", host, port, strerror (errno));
  return fd;
}

static int
bcl_tls_recv (void *ctx, unsigned char *buf, size_t len)
{
  int fd = (int) (intptr_t) ctx;
  ssize_t n;
  do { n = read (fd, buf, len); } while (n < 0 && errno == EINTR);
  if (n < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_READ; return MBEDTLS_ERR_NET_RECV_FAILED; }
  return (int) n;
}

static int
bcl_tls_send (void *ctx, const unsigned char *buf, size_t len)
{
  int fd = (int) (intptr_t) ctx;
  ssize_t n;
  do { n = write (fd, buf, len); } while (n < 0 && errno == EINTR);
  if (n < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_WRITE; return MBEDTLS_ERR_NET_SEND_FAILED; }
  return (int) n;
}

static int
bcl_tls_handshake (int sock, const char *sni, const char *ca_path, int insecure,
                   mbedtls_ssl_context *ssl, mbedtls_ssl_config *conf, mbedtls_x509_crt *ca)
{
  if (psa_crypto_init () != PSA_SUCCESS) { builtin_error ("claude: psa init failed"); return -1; }

  const char *ca_real = ca_path;
  if (!ca_real && !insecure)
    {
      if (access ("/etc/ssl/cert.pem", R_OK) == 0) ca_real = "/etc/ssl/cert.pem";
      else if (access ("/etc/ssl/certs/ca-certificates.crt", R_OK) == 0) ca_real = "/etc/ssl/certs/ca-certificates.crt";
    }
  if (ca_real)
    {
      if (mbedtls_x509_crt_parse_file (ca, ca_real) < 0)
        { builtin_error ("claude: failed to parse CA bundle %s", ca_real); return -1; }
    }
  else if (!insecure)
    { builtin_error ("claude: no TLS trust anchors (set BASHCLAUDE_CA or use -k)"); return -1; }

  if (mbedtls_ssl_config_defaults (conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0)
    { builtin_error ("claude: tls config_defaults failed"); return -1; }
  mbedtls_ssl_conf_authmode (conf, insecure ? MBEDTLS_SSL_VERIFY_NONE : MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain (conf, ca, NULL);

  if (mbedtls_ssl_setup (ssl, conf) != 0) { builtin_error ("claude: ssl_setup failed"); return -1; }
  if (mbedtls_ssl_set_hostname (ssl, sni) != 0) { builtin_error ("claude: set_hostname failed"); return -1; }
  mbedtls_ssl_set_bio (ssl, (void *) (intptr_t) sock, bcl_tls_send, bcl_tls_recv, NULL);

  int hs;
  while ((hs = mbedtls_ssl_handshake (ssl)) != 0)
    {
      if (hs == MBEDTLS_ERR_SSL_WANT_READ || hs == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
      char eb[128]; mbedtls_strerror (hs, eb, sizeof eb);
      uint32_t vr = mbedtls_ssl_get_verify_result (ssl);
      builtin_error ("claude: TLS handshake failed: %s (verify=0x%08x)", eb, (unsigned) vr);
      if (vr != 0 && vr != (uint32_t) -1)
        {
          char vb[512];
          int n = mbedtls_x509_crt_verify_info (vb, sizeof vb, "claude: verify: ", vr);
          if (n > 0) fwrite (vb, 1, (size_t) n, stderr);
        }
      return -1;
    }
  return 0;
}

/* ----------------------------------------------------------------------- */
/* Streaming response processor                                            */
/* ----------------------------------------------------------------------- */

typedef struct {
  int    raw;            /* print de-chunked body verbatim (no SSE parse) */
  int    headers_done;
  int    status;         /* HTTP status code */
  int    is_error;       /* status not 2xx -> route body to stderr */
  int    chunked;        /* Transfer-Encoding: chunked */
  long   chunk_left;     /* bytes left in current chunk (-1 = need size line) */
  sbuf   hdr;            /* header accumulator until \r\n\r\n */
  sbuf   line;           /* current SSE data-line accumulator */
  sbuf   csize;          /* chunked size-line accumulator (separate from line!) */
  sbuf   errbuf;         /* buffered non-2xx body (printed once, on the final attempt) */
  int    saw_text;       /* emitted any assistant text */
} resp_state;

/* Process one complete body text line (LF-terminated, CR stripped). */
static void
resp_body_line (resp_state *st, const char *line, size_t n)
{
  /* SSE: only "data:" lines carry JSON. */
  if (n < 5 || memcmp (line, "data:", 5) != 0) return;
  const char *p = line + 5;
  const char *end = line + n;
  while (p < end && (*p == ' ' || *p == '\t')) p++;
  if (p >= end) return;

  /* Surface API errors that arrive as data frames. */
  if (strstr (p, "\"type\":\"error\"") || strstr (p, "\"type\": \"error\""))
    { fprintf (stderr, "claude: API error: %.*s\n", (int) (end - p), p); st->is_error = 1; return; }

  /* Find a text_delta and emit its decoded text immediately. */
  const char *td = strstr (p, "text_delta");
  if (!td) return;
  const char *t = strstr (td, "\"text\"");
  if (!t) return;
  t += 6;
  while (t < end && (*t == ' ' || *t == ':')) t++;
  if (t >= end || *t != '"') return;
  t++;
  if (bcl_emit_json_string (t, end)) st->saw_text = 1;
  fflush (stdout);
}

/* Feed raw (already de-chunked) body bytes into the SSE / raw sink. */
static void
resp_body_bytes (resp_state *st, const char *p, size_t n)
{
  if (st->raw && !st->is_error) { bcl_write_all (STDOUT_FILENO, p, n); return; }
  /* Non-2xx body: buffer it so a retried attempt can discard it silently and
     only the final attempt's error reaches stderr. */
  if (st->is_error) { sb_put (&st->errbuf, p, n); return; }
  /* SSE line splitter. */
  for (size_t i = 0; i < n; i++)
    {
      char c = p[i];
      if (c == '\n')
        {
          size_t len = st->line.len;
          if (len && st->line.b[len - 1] == '\r') len--;
          /* NUL-terminate at the line boundary: resp_body_line scans with
             strstr(), and st->line.b is reused across lines without a NUL, so
             an unterminated line would over-read into the previous (longer)
             line's stale bytes (UB on untrusted SSE; a leftover "type":"error"
             could spuriously flag a benign line). */
          if (sb_grow (&st->line, 1) == 0) st->line.b[len] = '\0';
          resp_body_line (st, st->line.b ? st->line.b : "", len);
          st->line.len = 0;
        }
      else sb_putc (&st->line, c);
    }
}

/* Feed raw socket bytes (post-TLS) through header strip + de-chunk. */
static void
resp_feed (resp_state *st, const char *buf, size_t n)
{
  size_t i = 0;

  if (!st->headers_done)
    {
      for (; i < n; i++)
        {
          sb_putc (&st->hdr, buf[i]);
          if (st->hdr.len >= 4 && memcmp (st->hdr.b + st->hdr.len - 4, "\r\n\r\n", 4) == 0)
            {
              st->headers_done = 1; i++;
              /* Parse status line. */
              if (st->hdr.len > 12 && memcmp (st->hdr.b, "HTTP/", 5) == 0)
                {
                  const char *sp = memchr (st->hdr.b, ' ', st->hdr.len);
                  if (sp) st->status = atoi (sp + 1);
                }
              st->is_error = (st->status < 200 || st->status >= 300);
              /* Chunked? (case-insensitive scan of header block). */
              for (size_t k = 0; k + 17 <= st->hdr.len; k++)
                if (strncasecmp (st->hdr.b + k, "transfer-encoding", 17) == 0)
                  {
                    const char *v = st->hdr.b + k + 17;
                    const char *he = st->hdr.b + st->hdr.len;
                    if (strncasecmp (v, ": chunked", 9) == 0 ||
                        (memchr (v, 'c', he - v) && strstr (st->hdr.b + k, "chunked")))
                      st->chunked = 1;
                    break;
                  }
              st->chunk_left = st->chunked ? -1 : -2;   /* -2 = identity (read to EOF) */
              break;
            }
        }
      if (!st->headers_done) return;
    }

  /* Body. */
  if (!st->chunked)
    {
      if (i < n) resp_body_bytes (st, buf + i, n - i);
      return;
    }

  /* De-chunk incrementally. */
  while (i < n)
    {
      if (st->chunk_left < 0)
        {
          /* Accumulate the chunk-size line up to LF, in a buffer SEPARATE from
             the SSE data-line accumulator (st->line). They would otherwise
             collide when an SSE event spans a chunk boundary: the partial data
             line would be misread as a hex size and corrupted. */
          char c = buf[i++];
          if (c == '\n')
            {
              size_t len = st->csize.len;
              if (len && st->csize.b[len - 1] == '\r') len--;
              /* Skip CRLF separators between chunk data and next size. */
              if (len == 0) { st->csize.len = 0; continue; }
              sb_putc (&st->csize, '\0');                     /* terminate for strtol */
              long sz = strtol (st->csize.b, NULL, 16);
              st->csize.len = 0;
              if (sz <= 0) { st->headers_done = 2; return; }  /* terminal 0-chunk */
              st->chunk_left = sz;
            }
          else sb_putc (&st->csize, c);
        }
      else
        {
          size_t avail = n - i;
          size_t take = (avail < (size_t) st->chunk_left) ? avail : (size_t) st->chunk_left;
          resp_body_bytes (st, buf + i, take);
          i += take; st->chunk_left -= (long) take;
          if (st->chunk_left == 0) st->chunk_left = -1;   /* expect trailing CRLF then next size */
        }
    }
}

/* Flush any final SSE line left unterminated at end-of-stream. The live API
 * newline-terminates every event, but a stream that ends mid-line (or a
 * fixture without a trailing newline) would otherwise drop its last line.
 * Call once after the read loop completes -- never mid-read, since a partial
 * line there may still be completing. */
static void
resp_finish (resp_state *st)
{
  if (st->raw || st->line.len == 0) return;
  size_t len = st->line.len;
  if (st->line.b[len - 1] == '\r') len--;
  if (sb_grow (&st->line, 1) == 0) st->line.b[len] = '\0';   /* bound strstr() (see resp_body_bytes) */
  resp_body_line (st, st->line.b, len);
  st->line.len = 0;
}

/* Surface a failed response to stderr. For a genuine non-2xx HTTP status,
 * always emit the status code (so an error with an empty body is never a silent
 * rc=1), followed by any buffered error body. A mid-stream SSE error frame on a
 * 200 connection leaves status==200 and is already reported by resp_body_line,
 * so we skip the (misleading) "HTTP 200" line and just flush any trailing body. */
static void
bcl_report_error (const resp_state *st)
{
  if (!st->is_error) return;
  if (st->status < 200 || st->status >= 300)
    fprintf (stderr, "claude: HTTP %d%s\n", st->status,
             st->errbuf.len ? ":" : " (no response body)");
  if (st->errbuf.len) fwrite (st->errbuf.b, 1, st->errbuf.len, stderr);
}

/* ----------------------------------------------------------------------- */
/* Request                                                                 */
/* ----------------------------------------------------------------------- */

typedef struct {
  const char *model, *system, *tools;
  long  max_tokens;
  int   stream, raw, think, insecure;
} bcl_opts;

static int
bcl_build_body (sbuf *body, const bcl_opts *o, const char *msg)
{
  char nbuf[32];
  snprintf (nbuf, sizeof nbuf, "%ld", o->max_tokens);
  if (sb_puts (body, "{\"model\":\"") < 0 || sb_puts (body, o->model) < 0) return -1;
  if (sb_puts (body, "\",\"max_tokens\":") < 0 || sb_puts (body, nbuf) < 0) return -1;
  if (sb_puts (body, ",\"stream\":") < 0 || sb_puts (body, o->stream ? "true" : "false") < 0) return -1;
  if (o->think && sb_puts (body, ",\"thinking\":{\"type\":\"adaptive\"}") < 0) return -1;
  if (o->system && *o->system)
    { if (sb_puts (body, ",\"system\":\"") < 0 || sb_json_escape (body, o->system) < 0 || sb_putc (body, '"') < 0) return -1; }
  if (o->tools && *o->tools)
    { if (sb_puts (body, ",\"tools\":") < 0 || sb_puts (body, o->tools) < 0) return -1; }
  if (sb_puts (body, ",\"messages\":[{\"role\":\"user\",\"content\":\"") < 0) return -1;
  if (sb_json_escape (body, msg) < 0) return -1;
  if (sb_puts (body, "\"}]}") < 0) return -1;
  return 0;
}

/* Which HTTP statuses are worth retrying (rate limit + transient server). */
static int
bcl_status_retryable (int s)
{
  return s == 429 || s == 500 || s == 502 || s == 503 || s == 504 || s == 529;
}

/* Honor a server `Retry-After` header from the accumulated response header
 * block (st->hdr), in the delta-seconds form Anthropic sends on 429/529. The
 * server knows when it will be ready, so this is authoritative over our local
 * exponential default -- but clamped to [1, cap] so a bogus or very large
 * value can't hang the command. Returns 0 when the header is absent or not a
 * positive integer (e.g. the rarely-used HTTP-date form), leaving the caller's
 * exponential backoff in effect. */
static unsigned
bcl_retry_after_secs (const resp_state *st, unsigned cap)
{
  if (!st->hdr.b || st->hdr.len < 13) return 0;
  for (size_t k = 0; k + 12 <= st->hdr.len; k++)
    {
      /* Header names start at line boundaries; the status line is first. */
      if (k && st->hdr.b[k - 1] != '\n') continue;
      if (strncasecmp (st->hdr.b + k, "retry-after:", 12) != 0) continue;
      const char *v = st->hdr.b + k + 12;
      const char *he = st->hdr.b + st->hdr.len;
      while (v < he && (*v == ' ' || *v == '\t')) v++;
      if (v >= he || *v < '0' || *v > '9') return 0;  /* absent/HTTP-date form */
      unsigned secs = 0;
      while (v < he && *v >= '0' && *v <= '9')
        {
          secs = secs * 10 + (unsigned) (*v - '0');
          if (secs > 100000) { secs = cap; break; }   /* overflow guard */
          v++;
        }
      if (secs == 0) return 0;
      return secs > cap ? cap : secs;
    }
  return 0;
}

/* One HTTP attempt over a fresh TLS connection. Returns 0 if a response was
 * received (st populated: status / is_error / errbuf for non-2xx; a 2xx body
 * is streamed to stdout as it arrives), or -1 on a network-layer failure
 * (connect / handshake / write), with builtin_error already emitted. */
static int
bcl_attempt (const char *req, size_t reqlen, int raw, int insecure,
             const char *host, const char *ca, int port, resp_state *st)
{
  memset (st, 0, sizeof *st);
  st->raw = raw; st->status = 200;

  int fd = bcl_tcp_connect (host, port, BCL_IO_TIMEOUT_MS);
  if (fd < 0) return -1;

  mbedtls_ssl_context ssl; mbedtls_ssl_config conf; mbedtls_x509_crt cacrt;
  mbedtls_ssl_init (&ssl); mbedtls_ssl_config_init (&conf); mbedtls_x509_crt_init (&cacrt);

  int net = 0, hs_ok = 0;
  if (bcl_tls_handshake (fd, host, ca, insecure, &ssl, &conf, &cacrt) != 0) { net = -1; goto done; }
  hs_ok = 1;

  size_t off = 0;
  while (off < reqlen)
    {
      int w = mbedtls_ssl_write (&ssl, (const unsigned char *) req + off, reqlen - off);
      if (w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
      if (w <= 0) { builtin_error ("claude: TLS write failed"); net = -1; goto done; }
      off += (size_t) w;
    }

  for (;;)
    {
      unsigned char buf[8192];
      int r = mbedtls_ssl_read (&ssl, buf, sizeof buf);
      if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
      if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || r <= 0) break;
      resp_feed (st, (const char *) buf, (size_t) r);
      if (st->headers_done == 2) break;   /* terminal chunk seen */
    }
  resp_finish (st);

 done:
  if (hs_ok) mbedtls_ssl_close_notify (&ssl);
  mbedtls_ssl_free (&ssl); mbedtls_ssl_config_free (&conf); mbedtls_x509_crt_free (&cacrt);
  close (fd);
  return net;
}

/* POST a fully-formed JSON request BODY (blen bytes) to /v1/messages, with
 * bounded exponential-backoff retry on 429/5xx and transient network failures
 * (retried only before any stdout output, so a partial stream is never
 * duplicated). raw=1 prints the de-chunked body verbatim; raw=0 parses the SSE
 * stream and emits assistant text deltas. BASHCLAUDE_MAX_RETRIES tunes the cap
 * (default 2 retries = 3 attempts; 0 disables). */
static int
bcl_send (const char *body, size_t blen, int raw, int insecure)
{
  const char *key = getenv ("ANTHROPIC_API_KEY");
  if ((!key || !*key))
    {
      builtin_error ("claude: ANTHROPIC_API_KEY is not set");
      return EXECUTION_FAILURE;
    }
  /* Copy the key into an mlock'd buffer; wipe before return. */
  size_t klen = strlen (key);
  char *kbuf = malloc (klen + 1);
  if (!kbuf) { builtin_error ("claude: out of memory"); return EXECUTION_FAILURE; }
  memcpy (kbuf, key, klen + 1);
  if (mlock (kbuf, klen + 1) < 0 && errno == EAGAIN)
    builtin_error ("claude: warning: could not mlock API key (RLIMIT_MEMLOCK too small; run `mlock all` or raise ulimit -l)");

  const char *host = getenv ("BASHCLAUDE_HOST"); if (!host || !*host) host = BCL_DEFAULT_HOST;
  const char *apiver = getenv ("BASHCLAUDE_API_VERSION"); if (!apiver || !*apiver) apiver = BCL_API_VERSION;
  const char *ca = getenv ("BASHCLAUDE_CA"); if (ca && !*ca) ca = NULL;
  const char *ps = getenv ("BASHCLAUDE_PORT");
  int port = (ps && *ps) ? atoi (ps) : BCL_DEFAULT_PORT;

  sbuf req = {0};
  char clen[32]; snprintf (clen, sizeof clen, "%zu", blen);
  sb_puts (&req, "POST /v1/messages HTTP/1.1\r\nHost: "); sb_puts (&req, host);
  sb_puts (&req, "\r\nx-api-key: "); sb_puts (&req, kbuf);
  sb_puts (&req, "\r\nanthropic-version: "); sb_puts (&req, apiver);
  sb_puts (&req, "\r\ncontent-type: application/json\r\naccept: text/event-stream\r\nconnection: close\r\ncontent-length: ");
  sb_puts (&req, clen); sb_puts (&req, "\r\n\r\n");
  sb_put (&req, body, blen);

  int rc = EXECUTION_FAILURE;
  int max_retries = 2;
  const char *mr = getenv ("BASHCLAUDE_MAX_RETRIES");
  if (mr && *mr) { int v = atoi (mr); if (v >= 0 && v <= 10) max_retries = v; }

  resp_state st;
  for (int attempt = 0; ; attempt++)
    {
      int net = bcl_attempt (req.b, req.len, raw, insecure, host, ca, port, &st);
      int retryable = (net < 0) || (st.is_error && bcl_status_retryable (st.status));
      if (retryable && attempt < max_retries)
        {
          unsigned secs = 1u << attempt; if (secs > 8) secs = 8;
          /* A server Retry-After (429/529) is authoritative over our local
             exponential backoff; clamp to 60s so a bogus value can't hang. */
          if (net == 0)
            { unsigned ra = bcl_retry_after_secs (&st, 60u); if (ra) secs = ra; }
          if (net < 0)
            fprintf (stderr, "claude: request failed; retrying in %us (attempt %d/%d)\n",
                     secs, attempt + 1, max_retries);
          else
            /* Always surface the HTTP status on a retry (consistent with the
               non-2xx error report); label 529 as the overloaded condition. */
            fprintf (stderr, "claude: %s (HTTP %d); retrying in %us (attempt %d/%d)\n",
                     st.status == 429 ? "rate limited"
                       : st.status == 529 ? "overloaded" : "server error",
                     st.status, secs, attempt + 1, max_retries);
          sb_free (&st.hdr); sb_free (&st.line); sb_free (&st.csize); sb_free (&st.errbuf);
          sleep (secs);
          continue;
        }
      if (net == 0)
        {
          if (!raw && st.saw_text) putchar ('\n');
          fflush (stdout);
          if (st.is_error)
            { bcl_report_error (&st); rc = EXECUTION_FAILURE; }
          else rc = EXECUTION_SUCCESS;
        }
      /* net < 0: builtin_error already emitted by the attempt. */
      sb_free (&st.hdr); sb_free (&st.line); sb_free (&st.csize); sb_free (&st.errbuf);
      break;
    }

  bcl_wipe (req.b, req.len); sb_free (&req);
  bcl_wipe (kbuf, klen); munlock (kbuf, klen + 1); free (kbuf);
  return rc;
}

/* Build the request body from a single user message + options, then send. */
static int
bcl_do_request (const bcl_opts *o, const char *msg)
{
  sbuf body = {0};
  if (bcl_build_body (&body, o, msg) < 0)
    { builtin_error ("claude: failed to build request"); sb_free (&body); return EXECUTION_FAILURE; }
  int rc = bcl_send (body.b, body.len, o->raw, o->insecure);
  bcl_wipe (body.b, body.len); sb_free (&body);
  return rc;
}

/* `claude api [--stream|--raw] [-k]` — POST a complete JSON request body
 * read from stdin. This is the transport primitive the claude-code agent uses
 * to drive a full multi-turn messages[] array with tool_use / tool_result. */
static int
bcl_cmd_api (WORD_LIST *l)
{
  int raw = 1, insecure = 0;     /* default: full JSON response (agents parse it) */
  for (; l; l = l->next)
    {
      const char *w = l->word->word;
      if      (strcmp (w, "--raw") == 0)    raw = 1;
      else if (strcmp (w, "--stream") == 0) raw = 0;
      else if (strcmp (w, "-k") == 0 || strcmp (w, "--insecure") == 0) insecure = 1;
      else { builtin_error ("claude api: unknown option: %s", w); return EX_USAGE; }
    }
  sbuf body = {0};
  char rb[8192]; ssize_t r;
  while ((r = read (STDIN_FILENO, rb, sizeof rb)) > 0) sb_put (&body, rb, (size_t) r);
  if (body.len == 0) { builtin_error ("claude api: empty request body on stdin"); sb_free (&body); return EX_USAGE; }
  int rc = bcl_send (body.b, body.len, raw, insecure);
  bcl_wipe (body.b, body.len); sb_free (&body);
  return rc;
}

/* `claude parse-response [--raw]` — read a full raw HTTP response (status
 * line + headers + body, identity or chunked) from stdin and run it through the
 * SAME response processor the live request path uses. A test/diagnostic seam so
 * the SSE de-framing + text_delta extraction can be exercised offline without a
 * network round-trip. Default streams text deltas; --raw prints the de-chunked
 * body. Exit status mirrors the HTTP status (non-2xx -> failure). */
static int
bcl_cmd_parse_response (WORD_LIST *l)
{
  int raw = 0;
  for (; l; l = l->next)
    {
      const char *w = l->word->word;
      if (strcmp (w, "--raw") == 0) raw = 1;
      else { builtin_error ("claude parse-response: unknown option: %s", w); return EX_USAGE; }
    }
  resp_state st; memset (&st, 0, sizeof st);
  st.raw = raw; st.status = 200;
  char rb[8192]; ssize_t r;
  while ((r = read (STDIN_FILENO, rb, sizeof rb)) > 0)
    {
      resp_feed (&st, rb, (size_t) r);
      if (st.headers_done == 2) break;
    }
  resp_finish (&st);
  if (!raw && st.saw_text) putchar ('\n');
  fflush (stdout);
  int rc = st.is_error ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
  bcl_report_error (&st);
  sb_free (&st.hdr); sb_free (&st.line); sb_free (&st.csize); sb_free (&st.errbuf);
  return rc;
}

/* ----------------------------------------------------------------------- */
/* Subcommands                                                             */
/* ----------------------------------------------------------------------- */

static const char *
bcl_default_model (void)
{
  const char *m = getenv ("BASHCLAUDE_MODEL");
  return (m && *m) ? m : BCL_DEFAULT_MODEL;
}

static int
bcl_cmd_prompt (WORD_LIST *l)
{
  bcl_opts o;
  o.model = bcl_default_model ();
  o.system = NULL; o.tools = NULL;
  o.max_tokens = BCL_DEFAULT_MAX_TOKENS;
  o.stream = 1; o.raw = 0; o.think = 0; o.insecure = 0;

  sbuf msg = {0};
  int have_msg = 0, dump = 0;
  for (; l; l = l->next)
    {
      const char *w = l->word->word;
      if      (strcmp (w, "-m") == 0 || strcmp (w, "--model") == 0)       { if (!l->next) { builtin_error ("claude: %s needs a value", w); sb_free (&msg); return EX_USAGE; } o.model = l->next->word->word; l = l->next; }
      else if (strcmp (w, "-n") == 0 || strcmp (w, "--max-tokens") == 0)  { if (!l->next) { builtin_error ("claude: %s needs a value", w); sb_free (&msg); return EX_USAGE; } o.max_tokens = strtol (l->next->word->word, NULL, 10); l = l->next; }
      else if (strcmp (w, "-s") == 0 || strcmp (w, "--system") == 0)      { if (!l->next) { builtin_error ("claude: %s needs a value", w); sb_free (&msg); return EX_USAGE; } o.system = l->next->word->word; l = l->next; }
      else if (strcmp (w, "--tools") == 0)                                { if (!l->next) { builtin_error ("claude: --tools needs a value"); sb_free (&msg); return EX_USAGE; } o.tools = l->next->word->word; l = l->next; }
      else if (strcmp (w, "--think") == 0)                                o.think = 1;
      else if (strcmp (w, "--raw") == 0)                                  { o.raw = 1; o.stream = 0; }
      else if (strcmp (w, "--stream") == 0)                               { o.raw = 0; o.stream = 1; }
      else if (strcmp (w, "--dump-request") == 0)                         dump = 1;
      else if (strcmp (w, "-k") == 0 || strcmp (w, "--insecure") == 0)    o.insecure = 1;
      else if (strcmp (w, "--") == 0)                                     { l = l->next; for (; l; l = l->next) { if (have_msg) sb_putc (&msg, ' '); sb_puts (&msg, l->word->word); have_msg = 1; } break; }
      else if (w[0] == '-' && w[1])                                       { builtin_error ("claude: unknown option: %s", w); sb_free (&msg); return EX_USAGE; }
      else                                                                { if (have_msg) sb_putc (&msg, ' '); sb_puts (&msg, w); have_msg = 1; }
    }

  if (o.max_tokens <= 0) { builtin_error ("claude: --max-tokens must be positive"); sb_free (&msg); return EX_USAGE; }

  /* No message argument -> read the user message from stdin. */
  if (!have_msg)
    {
      char rb[4096]; ssize_t r;
      while ((r = read (STDIN_FILENO, rb, sizeof rb)) > 0) sb_put (&msg, rb, (size_t) r);
      /* Trim trailing newlines for convenience. */
      while (msg.len && (msg.b[msg.len - 1] == '\n' || msg.b[msg.len - 1] == '\r')) msg.len--;
      /* Check AFTER trimming so newline-only stdin (e.g. a bare Enter) fails
         closed instead of building an empty user message the API rejects. */
      if (msg.len == 0) { builtin_error ("claude: no message (give one as an argument or on stdin)"); sb_free (&msg); return EX_USAGE; }
    }
  if (sb_putc (&msg, '\0') < 0) { sb_free (&msg); return EXECUTION_FAILURE; }

  /* --dump-request: build the JSON request body and print it instead of
     sending (operator diagnostic + offline coverage of request assembly). */
  if (dump)
    {
      sbuf body = {0};
      if (bcl_build_body (&body, &o, msg.b) < 0)
        { builtin_error ("claude: failed to build request"); sb_free (&body); bcl_wipe (msg.b, msg.len); sb_free (&msg); return EXECUTION_FAILURE; }
      bcl_write_all (STDOUT_FILENO, body.b, body.len);
      putchar ('\n'); fflush (stdout);
      sb_free (&body); bcl_wipe (msg.b, msg.len); sb_free (&msg);
      return EXECUTION_SUCCESS;
    }

  int rc = bcl_do_request (&o, msg.b);
  bcl_wipe (msg.b, msg.len); sb_free (&msg);
  return rc;
}

static int
bcl_cmd_models (void)
{
  fputs (
    "claude-fable-5      most capable (1M ctx)\n"
    "claude-opus-4-8     default; most capable Opus-tier (1M ctx)\n"
    "claude-opus-4-7     previous Opus\n"
    "claude-opus-4-6     older Opus\n"
    "claude-sonnet-4-6   speed/intelligence balance (1M ctx)\n"
    "claude-haiku-4-5    fastest / cheapest (200K ctx)\n",
    stdout);
  return EXECUTION_SUCCESS;
}

/* `claude escape` — read stdin, print it as a complete JSON string token
 * (quotes included, no trailing newline). Lets the claude-code agent build
 * request JSON without hand-rolling shell escaping. NUL bytes truncate. */
static int
bcl_cmd_escape (void)
{
  sbuf in = {0}; char rb[8192]; ssize_t r;
  while ((r = read (STDIN_FILENO, rb, sizeof rb)) > 0) sb_put (&in, rb, (size_t) r);
  if (sb_putc (&in, '\0') < 0) { sb_free (&in); return EXECUTION_FAILURE; }
  sbuf out = {0};
  if (sb_putc (&out, '"') < 0 || sb_json_escape (&out, in.b) < 0 || sb_putc (&out, '"') < 0)
    { sb_free (&in); sb_free (&out); return EXECUTION_FAILURE; }
  bcl_write_all (STDOUT_FILENO, out.b, out.len);
  sb_free (&in); sb_free (&out);
  return EXECUTION_SUCCESS;
}

/* `claude unescape` — read a JSON string literal on stdin (with or without
 * surrounding quotes; leading whitespace tolerated) and print the decoded
 * bytes. The inverse of `escape`; used by claude-code to render assistant text
 * that `json get` returns JSON-encoded. */
static int
bcl_cmd_unescape (void)
{
  sbuf in = {0}; char rb[8192]; ssize_t r;
  while ((r = read (STDIN_FILENO, rb, sizeof rb)) > 0) sb_put (&in, rb, (size_t) r);
  if (in.len == 0) { sb_free (&in); return EXECUTION_SUCCESS; }
  const char *p = in.b, *end = in.b + in.len;
  while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
  if (p < end && *p == '"') (void) bcl_emit_json_string (p + 1, end);
  else bcl_write_all (STDOUT_FILENO, p, (size_t) (end - p));
  fflush (stdout);
  sb_free (&in);
  return EXECUTION_SUCCESS;
}

/* Self-update: verify + install + reload a signed claude package using
 * the real pkg verbs (signature/ABI/arch/digest gated). Runs the bash
 * orchestration via a child bash login shell so the in-image builtins resolve.
 * An explicit PKGFILE is passed through the environment (not argv-interpolated
 * into the snippet) to avoid injection. */
static int
bcl_cmd_update (WORD_LIST *l)
{
  if (l && l->next) { builtin_error ("claude update: at most one PKGFILE argument"); return EX_USAGE; }
  if (l && l->word && l->word->word) setenv ("BASHCLAUDE_UPDATE_PKG", l->word->word, 1);
  else unsetenv ("BASHCLAUDE_UPDATE_PKG");

  static const char *snippet =
    "set -u; dir=${BASHPKG_LOADABLES_DATADIR:-/root/loadables}; "
    "pkg=${BASHCLAUDE_UPDATE_PKG:-}; "
    "if [[ -z $pkg ]]; then "
    "  pkg=$(ls -1t \"$dir\"/bashclaude_*.pkg 2>/dev/null | head -n1); "
    "fi; "
    "if [[ -z ${pkg:-} || ! -r $pkg ]]; then "
    "  printf 'claude update: no bashclaude_*.pkg found in %s (publish with build-loadable-pkg.sh + loadable-fetch.sh)\\n' \"$dir\" >&2; exit 1; "
    "fi; "
    "printf 'claude update: installing %s\\n' \"$pkg\" >&2; "
    "if type -t pkg >/dev/null 2>&1; then "
    "  pkg install \"$pkg\" && pkg load claude; "
    "else "
    "  printf 'claude update: pkg unavailable; this image cannot hot-load .so (needs BASH_OS_DYNAMIC). Rebuild the image to update.\\n' >&2; exit 1; "
    "fi";

  pid_t pid = fork ();
  if (pid < 0) { builtin_error ("claude update: fork: %s", strerror (errno)); return EXECUTION_FAILURE; }
  if (pid == 0)
    {
      execl ("/bin/bash", "bash", "-lc", snippet, (char *) NULL);
      _exit (127);
    }
  int status = 0;
  while (waitpid (pid, &status, 0) < 0 && errno == EINTR) {}
  if (WIFEXITED (status) && WEXITSTATUS (status) == 0) return EXECUTION_SUCCESS;
  return EXECUTION_FAILURE;
}

static int
bcl_cmd_help (void)
{
  fputs (
    "claude -- Claude API (/v1/messages) client builtin\n"
    "\n"
    "  claude prompt [OPTIONS] [MESSAGE]   send a message (stdin if no MESSAGE)\n"
    "  claude api [--stream|--raw] [-k]    POST a full JSON request body (stdin)\n"
    "  claude escape                       JSON-string-escape stdin (no quotes)\n"
    "  claude unescape                     decode a JSON string from stdin\n"
    "  claude models                       list known model ids\n"
    "  claude version                      print version\n"
    "  claude update [PKGFILE]             verify+install+reload a new .so\n"
    "  claude help                         this help\n"
    "\n"
    "prompt options:\n"
    "  -m, --model ID        model (default: $BASHCLAUDE_MODEL or " BCL_DEFAULT_MODEL ")\n"
    "  -n, --max-tokens N    response cap (default 4096)\n"
    "  -s, --system TEXT     system prompt\n"
    "      --think           enable adaptive thinking\n"
    "      --tools JSON      tool-definitions array (passthrough)\n"
    "      --raw             print full JSON response (non-streaming)\n"
    "      --dump-request    print the JSON request body and exit (no send)\n"
    "  -k, --insecure        skip TLS verification (testing only)\n"
    "\n"
    "env: ANTHROPIC_API_KEY (required), BASHCLAUDE_HOST, BASHCLAUDE_API_VERSION,\n"
    "     BASHCLAUDE_MODEL, BASHCLAUDE_CA, BASHCLAUDE_PORT, BASHCLAUDE_MAX_RETRIES\n"
    "     (default 2; retries 429/5xx + transient network errors with backoff,\n"
    "      honoring a server Retry-After header on 429/529, clamped to 60s)\n",
    stdout);
  return EXECUTION_SUCCESS;
}

int
claude_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *verb = list->word->word;
  if (strcmp (verb, "prompt") == 0)   return bcl_cmd_prompt (list->next);
  if (strcmp (verb, "api") == 0)      return bcl_cmd_api (list->next);
  if (strcmp (verb, "parse-response") == 0) return bcl_cmd_parse_response (list->next);
  if (strcmp (verb, "escape") == 0)   return bcl_cmd_escape ();
  if (strcmp (verb, "unescape") == 0) return bcl_cmd_unescape ();
  if (strcmp (verb, "models") == 0)   return bcl_cmd_models ();
  if (strcmp (verb, "update") == 0)   return bcl_cmd_update (list->next);
  if (strcmp (verb, "version") == 0 || strcmp (verb, "--version") == 0) { printf ("claude %s\n", BCL_VERSION); return EXECUTION_SUCCESS; }
  if (strcmp (verb, "help") == 0 || strcmp (verb, "--help") == 0 || strcmp (verb, "-h") == 0) return bcl_cmd_help ();
  builtin_error ("claude: unknown subcommand: %s (try: prompt, models, version, update, help)", verb);
  return EX_USAGE;
}

char *claude_doc[] = {
  "Call the Claude API (/v1/messages) over the image's mbedTLS.",
  "",
  "Subcommands: prompt (default chat, streaming), models, version, update, help.",
  "Reads ANTHROPIC_API_KEY from the environment; verifies api.anthropic.com",
  "against the shipped CA bundle. Self-updates its own .so via 'claude",
  "update' through the signed pkg loadable pipeline.",
  "",
  "See docs/BASHCLAUDE.md for the full reference.",
  (char *) NULL
};

struct builtin claude_struct = {
  "claude",
  claude_builtin,
  BUILTIN_ENABLED,
  claude_doc,
  "claude prompt|models|version|update|help [OPTIONS] [ARGS...]",
  0
};
