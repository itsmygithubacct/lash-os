/* SPDX-License-Identifier: MIT */
/* http.c - small HTTP/1.1 framing helpers for bash-os.
 *
 * TLS I/O still lives in `crypto tls connect`; this builtin provides the
 * URL parsing and request framing needed by git-net.sh without moving HTTP
 * parsing into ad-hoc shell string code.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "loadables.h"

/* Response header size cap (matches httpd's BHD_MAX_HEADER policy).
 * response_body_cmd rejects any HTTP response whose header block exceeds
 * this limit, bounding malicious or malformed responses before extraction. */
#define BHH_MAX_HEADER 16384

/* Request header aggregate cap for `-H` arguments. */
#define BHH_REQ_HEADERS_MAX 2048

typedef struct {
  char scheme[8];
  char host[256];
  char port[8];
  char path[1024];
} bh_url;

static int
parse_url (const char *url, bh_url *u)
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
    snprintf (u->port, sizeof u->port, "%s", strcmp (u->scheme, "http") ? "443" : "80");
  snprintf (u->path, sizeof u->path, "%s", slash ? slash : "/");
  return 0;
}

static int
bind_or_print (const char *var, const char *s)
{
  if (var) builtin_bind_variable ((char *) var, (char *) s, 0);
  else printf ("%s\n", s);
  return EXECUTION_SUCCESS;
}

static int
parse_cmd (WORD_LIST *args)
{
  if (!args) { builtin_error ("parse-url URL [-V VAR]"); return EX_USAGE; }
  const char *url = args->word->word;
  const char *var = NULL;
  for (WORD_LIST *p = args->next; p; p = p->next)
    {
      if (!strcmp (p->word->word, "-V") && p->next)
        { p = p->next; var = p->word->word; }
      else { builtin_error ("parse-url: unexpected arg: %s", p->word->word); return EX_USAGE; }
    }
  bh_url u;
  if (parse_url (url, &u) < 0) { builtin_error ("parse-url: invalid URL"); return EX_USAGE; }
  char out[1400];
  snprintf (out, sizeof out, "scheme=%s host=%s port=%s path=%s",
            u.scheme, u.host, u.port, u.path);
  return bind_or_print (var, out);
}

static int
request_cmd (WORD_LIST *args)
{
  const char *method = "GET", *url = NULL, *body = NULL, *var = NULL;
  char headers[BHH_REQ_HEADERS_MAX] = "";
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (!strcmp (w, "-X") && p->next) { p = p->next; method = p->word->word; }
      else if (!strcmp (w, "-H") && p->next)
        {
          p = p->next;
          if (strlen (headers) + strlen (p->word->word) + 4 >= sizeof headers)
            { builtin_error ("request: headers too large"); return EX_USAGE; }
          strcat (headers, p->word->word);
          strcat (headers, "\r\n");
        }
      else if (!strcmp (w, "-d") && p->next) { p = p->next; body = p->word->word; }
      else if (!strcmp (w, "-V") && p->next) { p = p->next; var = p->word->word; }
      else if (!url) url = w;
      else { builtin_error ("request: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!url) { builtin_error ("request URL [-X METHOD] [-H H] [-d BODY] [-V VAR]"); return EX_USAGE; }
  bh_url u;
  if (parse_url (url, &u) < 0) { builtin_error ("request: invalid URL"); return EX_USAGE; }
  size_t body_len = body ? strlen (body) : 0;
  size_t need = strlen (method) + strlen (u.path) + strlen (u.host) +
                strlen (headers) + body_len + 256;
  char *req = malloc (need);
  if (!req) return EXECUTION_FAILURE;
  snprintf (req, need,
            "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: bash-os/0.1\r\nAccept: */*\r\n%sContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
            method, u.path, u.host, headers, body_len, body ? body : "");
  int rc = bind_or_print (var, req);
  free (req);
  return rc;
}

static int
response_body_cmd (WORD_LIST *args)
{
  const char *in = NULL, *out = NULL, *status_var = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (!strcmp (w, "-o") && p->next) { p = p->next; out = p->word->word; }
      else if (!strcmp (w, "-S") && p->next) { p = p->next; status_var = p->word->word; }
      else if (!in) in = w;
      else { builtin_error ("response-body: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!in || !out) { builtin_error ("response-body RESPONSE_FILE -o BODY_FILE [-S STATUS_VAR]"); return EX_USAGE; }

  FILE *f = fopen (in, "rb");
  if (!f) { builtin_error ("response-body: %s: %s", in, strerror (errno)); return EXECUTION_FAILURE; }
  if (fseek (f, 0, SEEK_END) < 0) { fclose (f); return EXECUTION_FAILURE; }
  long fl = ftell (f);
  if (fl < 0) { fclose (f); return EXECUTION_FAILURE; }
  rewind (f);
  unsigned char *buf = malloc ((size_t) fl + 1);
  if (!buf) { fclose (f); return EXECUTION_FAILURE; }
  size_t got = fread (buf, 1, (size_t) fl, f);
  fclose (f);
  if (got != (size_t) fl) { free (buf); return EXECUTION_FAILURE; }
  buf[got] = '\0';

  int status = 0;
  if (got >= 12 && !memcmp (buf, "HTTP/", 5))
    status = atoi ((char *) buf + 9);
  size_t body = got;
  int sep_found = 0;
  size_t search_end = got > BHH_MAX_HEADER ? BHH_MAX_HEADER : got;
  for (size_t i = 0; i + 4 <= search_end && i + 3 < got; i++)
    if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n')
      { body = i + 4; sep_found = 1; break; }
  if (!sep_found)
    {
      builtin_error ("response-body: no header/body separator found");
      free (buf);
      return EXECUTION_FAILURE;
    }
  /* body == got: empty body after \r\n\r\n is valid (204 No Content etc.).
     nbody = 0 below handles the empty write. */
  FILE *o = fopen (out, "wb");
  if (!o) { builtin_error ("response-body: %s: %s", out, strerror (errno)); free (buf); return EXECUTION_FAILURE; }
  size_t nbody = got - body;
  int ok = fwrite (buf + body, 1, nbody, o) == nbody;
  if (fclose (o) != 0) ok = 0;
  free (buf);
  if (!ok) return EXECUTION_FAILURE;
  if (status_var)
    {
      char s[16];
      snprintf (s, sizeof s, "%d", status);
      builtin_bind_variable ((char *) status_var, s, 0);
    }
  return (status >= 200 && status < 300) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

int
http_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  if (!strcmp (cmd, "parse-url")) return parse_cmd (list->next);
  if (!strcmp (cmd, "request")) return request_cmd (list->next);
  if (!strcmp (cmd, "response-body")) return response_body_cmd (list->next);
  builtin_error ("unknown verb: %s", cmd);
  return EX_USAGE;
}

char *http_doc[] = {
  "HTTP/1.1 URL and request framing helpers.",
  "  http parse-url URL [-V VAR]",
  "  http request URL [-X METHOD] [-H HEADER]... [-d BODY] [-V VAR]",
  "  http response-body RESPONSE_FILE -o BODY_FILE [-S STATUS_VAR]",
  "Pipe request output to: crypto tls connect HOST:PORT -s HOST",
  "-H aggregate: capped at 2048 bytes; response header block: capped at 16384 bytes.",
  (char *) NULL
};

struct builtin http_struct = {
  "http",
  http_builtin,
  BUILTIN_ENABLED,
  http_doc,
  "http parse-url|request|response-body ...",
  0
};
