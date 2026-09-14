/* SPDX-License-Identifier: MIT */
/* httpd.c — an HTTP server primitive as a bash builtin: listen, accept, reply.
 *
 * The appliance's API handlers are bash scripts, and this is the smallest thing
 * that lets them be: one connection at a time, the request parsed into shell
 * variables, its body in a file, the reply from a file or stdin. It is an
 * appliance endpoint, not a web server: no keep-alive, no chunked transfer, no
 * threads, and nothing is decoded — the handler decides what a path means.
 *
 *   httpd listen PORT [-a ADDR] -H VAR
 *       A TCP listen socket (SO_REUSEADDR, backlog 8, ADDR default 0.0.0.0);
 *       its fd number -> VAR. Non-zero on failure.
 *   httpd accept LFD -H CFD -m METHOD -p PATH -q QUERY -B BODYFILE
 *                [-l LENVAR] [-c CTYPEVAR] [-t SECS] [-r REMOTEVAR]
 *       Block for one connection. With -t SECS it polls instead and returns 3
 *       on timeout with nothing bound, so a loop can do housekeeping; -t 0 is
 *       a non-blocking probe costing exactly one poll(), for a daemon that
 *       checks between camera frames. Once a connection is accepted the whole
 *       request must arrive within HTTPD_REQUEST_TIMEOUT_MS (10 s) total, or it
 *       is answered 408 and closed — a trickling client cannot stall the caller
 *       past its watchdog. Reads
 *       the request line and headers (8 KiB cap -> 431; malformed -> 400) and
 *       binds METHOD as sent, PATH (before any '?'), QUERY (after it, "" if
 *       none), the client fd -> CFD (left OPEN for the reply), Content-Length
 *       -> LENVAR ("0" if absent), Content-Type -> CTYPEVAR ("" if absent) and
 *       the peer's IP -> REMOTEVAR. A body of Content-Length bytes is read
 *       into BODYFILE (mode 0600; cap 16 MiB -> 413). BODYFILE is truncated on
 *       EVERY accept, so a GET never leaves a previous POST's body for the
 *       handler to misread. HTTP/1.0 and 1.1; Connection is always close;
 *       Expect is ignored. A bad request is answered and closed HERE, with a
 *       builtin_error and a non-zero return: the handler never sees one.
 *   httpd reply CFD [-s STATUS] [-t CONTENT_TYPE] [-f FILE]
 *       Writes "HTTP/1.1 STATUS reason", Content-Type (default
 *       application/json), Content-Length, Connection: close, a blank line,
 *       then the body: FILE's bytes, else stdin to EOF. CFD is closed after,
 *       success or failure. A failed write (peer gone) returns non-zero but is
 *       not fatal to the caller.
 *   httpd part BODYFILE -b BOUNDARY -o OUTFILE [-n FIELDNAME] [-F FILENAMEVAR] [-l LENVAR]
 *       Extracts ONE part of a multipart/form-data body (what `curl -F
 *       image=@photo.jpg` sends): the part whose Content-Disposition has
 *       name="FIELDNAME", or by default the first part carrying a filename=.
 *       Exactly its bytes — from after its blank line to the CRLF before the
 *       next --BOUNDARY — go to OUTFILE (0600); its filename (unquoted,
 *       basename only) -> FILENAMEVAR, its length -> LENVAR. BOUNDARY is the
 *       bare token (surrounding quotes are stripped). Binary-safe: only the
 *       boundary line ends a part. Returns 0 found, 1 no such part or not
 *       multipart (silently, like grep), EXECUTION_FAILURE with a message on
 *       an I/O error. NOTE: 1 and EXECUTION_FAILURE are the same number; the
 *       message is what tells them apart.
 *
 * Two things a handler author must know:
 *   - `accept` binds variables, so it must run in the current shell — never
 *     as a pipeline element or inside $(...), which are subshells.
 *   - `... | httpd reply $CFD` runs reply in a SUBSHELL: it closes its own copy
 *     of CFD, but the parent shell's copy stays open, leaking one fd per
 *     request. Feed the body with a redirection instead (`httpd reply $CFD
 *     < file`, `<<< "$json"`, or -f FILE), or `shopt -s lastpipe`, or
 *     `exec {CFD}>&-` after a pipeline.
 *
 * SIGPIPE cannot kill the shell: every socket write is send(MSG_NOSIGNAL).
 * EINTR is retried everywhere. Both sockets are CLOEXEC, so commands a
 * handler runs do not inherit them. A Content-Type given to reply may not
 * contain CR or LF — that would be header injection.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <config.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <ctype.h>
#include <strings.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "loadables.h"
#include "bashgetopt.h"

#define HEAD_MAX  (8 * 1024)			/* request line + headers, else 431 */
#define BODY_MAX  (16L * 1024 * 1024)		/* Content-Length, else 413 */
#define CHUNK     (64 * 1024)
/* Once a connection is accepted, the whole request (line + headers + body) must
 * arrive within this budget, total, not per read. accept's caller (detectd)
 * pets the hardware watchdog from the same loop, so a client that connects and
 * sends nothing, or trickles a body, would otherwise hold the loop until the
 * board reboots. On expiry: 408, close, non-zero, nothing bound. Overridable at
 * compile time so the test can shorten it. */
#ifndef HTTPD_REQUEST_TIMEOUT_MS
#define HTTPD_REQUEST_TIMEOUT_MS 10000
#endif

/* ---- I/O helpers: EINTR retried, no SIGPIPE ------------------------------ */
static int
send_all (int fd, const void *buf, size_t n)
{
  const unsigned char *p = buf;
  while (n > 0)
    {
      ssize_t w = send (fd, p, n, MSG_NOSIGNAL);
      if (w < 0) { if (errno == EINTR) continue; return -1; }
      p += w; n -= (size_t) w;
    }
  return 0;
}
static ssize_t
read_retry (int fd, void *buf, size_t n)
{
  ssize_t r;
  do r = read (fd, buf, n); while (r < 0 && errno == EINTR);
  return r;
}
static long
mono_ms (void)
{
  struct timespec t; clock_gettime (CLOCK_MONOTONIC, &t);
  return (long) t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
/* Read, but never block past `deadline` (absolute mono_ms). Returns bytes read
   (0 = peer EOF), -1 on error, -2 on the deadline expiring. */
#define READ_TIMED_OUT (-2)
static ssize_t
read_by (int fd, void *buf, size_t n, long deadline)
{
  for (;;)
    {
      long rem = deadline - mono_ms ();
      struct pollfd pf = { .fd = fd, .events = POLLIN, .revents = 0 };
      int r;
      if (rem <= 0) return READ_TIMED_OUT;
      r = poll (&pf, 1, rem > INT_MAX ? INT_MAX : (int) rem);
      if (r < 0) { if (errno == EINTR) continue; return -1; }
      if (r == 0) return READ_TIMED_OUT;
      { ssize_t got = read (fd, buf, n); if (got < 0 && errno == EINTR) continue; return got; }
    }
}
static int
write_all (int fd, const void *buf, size_t n)		/* to a regular file */
{
  const unsigned char *p = buf;
  while (n > 0)
    {
      ssize_t w = write (fd, p, n);
      if (w < 0) { if (errno == EINTR) continue; return -1; }
      p += w; n -= (size_t) w;
    }
  return 0;
}

static const char *
reason (int s)
{
  switch (s)
    {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 413: return "Payload Too Large";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    default:  return "Status";
    }
}

/* Answer a request the handler will never see, and close. Best-effort. */
static void
refuse (int cfd, int status)
{
  char h[160];
  int n = snprintf (h, sizeof h,
		    "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		    status, reason (status));
  send_all (cfd, h, (size_t) n);
  close (cfd);
}

/* ---- shell variables ------------------------------------------------------ */
static int
set_var (const char *name, const char *value)
{
  if (bind_variable (name, value, 0) == 0)
    { builtin_error ("cannot set %s", name); return -1; }
  return 0;
}
static int
set_long (const char *name, long v)
{
  char b[24];
  snprintf (b, sizeof b, "%ld", v);
  return set_var (name, b);
}
static int
parse_fd (const char *s, const char *what, long *out)
{
  char *end; long v;
  if (s == 0 || *s == 0) { builtin_error ("%s: fd required", what); return -1; }
  v = strtol (s, &end, 10);
  if (*end || v < 0) { builtin_error ("%s: bad fd '%s'", what, s); return -1; }
  *out = v;
  return 0;
}

/* ---- listen --------------------------------------------------------------- */
static int
do_listen (WORD_LIST *list)
{
  const char *addr = "0.0.0.0", *var = 0;
  char *end; long port; int opt, fd, one = 1;
  struct sockaddr_in sa;

  if (list == 0) { builtin_usage (); return (EX_USAGE); }
  port = strtol (list->word->word, &end, 10);
  if (*list->word->word == 0 || *end || port < 0 || port > 65535)
    { builtin_error ("listen: bad port '%s'", list->word->word); return (EX_USAGE); }
  reset_internal_getopt ();
  while ((opt = internal_getopt (list->next, "a:H:")) != -1)
    switch (opt)
      {
      case 'a': addr = list_optarg; break;
      case 'H': var = list_optarg; break;
      default: builtin_usage (); return (EX_USAGE);
      }
  if (var == 0) { builtin_error ("listen: -H VAR is required"); return (EX_USAGE); }
  if (!legal_identifier (var)) { builtin_error ("'%s' is not a valid variable name", var); return (EX_USAGE); }

  memset (&sa, 0, sizeof sa);
  sa.sin_family = AF_INET;
  sa.sin_port = htons ((unsigned short) port);
  if (inet_pton (AF_INET, addr, &sa.sin_addr) != 1)
    { builtin_error ("listen: bad address '%s'", addr); return (EXECUTION_FAILURE); }
  fd = socket (AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) { builtin_error ("listen: socket: %s", strerror (errno)); return (EXECUTION_FAILURE); }
  setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  if (bind (fd, (struct sockaddr *) &sa, sizeof sa) != 0)
    { builtin_error ("listen: bind %s:%ld: %s", addr, port, strerror (errno)); close (fd); return (EXECUTION_FAILURE); }
  if (listen (fd, 8) != 0)
    { builtin_error ("listen: %s", strerror (errno)); close (fd); return (EXECUTION_FAILURE); }
  if (set_long (var, fd) != 0) { close (fd); return (EXECUTION_FAILURE); }
  return (EXECUTION_SUCCESS);
}

/* ---- accept --------------------------------------------------------------- */
/* Wait for POLLIN on lfd for up to secs seconds. 1 = ready, 0 = timeout, -1 = error. */
static int
wait_ready (int lfd, long secs)
{
  struct pollfd pf = { .fd = lfd, .events = POLLIN, .revents = 0 };
  struct timespec t0, t;
  long left = secs * 1000;
  if (secs == 0)				/* -t 0: one poll(), nothing else */
    {
      int r;
      do r = poll (&pf, 1, 0); while (r < 0 && errno == EINTR);
      return r > 0 ? 1 : (r == 0 ? 0 : -1);
    }
  clock_gettime (CLOCK_MONOTONIC, &t0);
  for (;;)
    {
      int r = poll (&pf, 1, (int) left);
      if (r > 0) return 1;
      if (r == 0) return 0;
      if (errno != EINTR) return -1;
      clock_gettime (CLOCK_MONOTONIC, &t);
      left = secs * 1000 - ((t.tv_sec - t0.tv_sec) * 1000 + (t.tv_nsec - t0.tv_nsec) / 1000000);
      if (left <= 0) return 0;
    }
}

/* Case-insensitive "is this header NAME?" — returns the value start, or 0. */
static char *
header_value (char *line, const char *name)
{
  size_t n = strlen (name);
  if (strncasecmp (line, name, n) != 0 || line[n] != ':') return 0;
  line += n + 1;
  while (*line == ' ' || *line == '\t') line++;
  return line;
}

static int
do_accept (WORD_LIST *list)
{
  const char *v_cfd = 0, *v_meth = 0, *v_path = 0, *v_query = 0, *bodyfile = 0;
  const char *v_len = 0, *v_ct = 0, *v_rem = 0;
  long lfd, secs = -1, clen = 0;
  int opt, cfd, bfd = -1, seen_len = 0;
  char *end;
  struct sockaddr_in peer; socklen_t plen = sizeof peer;
  char head[HEAD_MAX + 1], *hend, *body, *line, *next, *method, *target, *version, *query, *ctype = "";
  char remote[INET_ADDRSTRLEN];
  size_t got = 0, sep;

  if (list == 0) { builtin_usage (); return (EX_USAGE); }
  if (parse_fd (list->word->word, "accept", &lfd) != 0) return (EX_USAGE);
  reset_internal_getopt ();
  while ((opt = internal_getopt (list->next, "H:m:p:q:B:l:c:t:r:")) != -1)
    switch (opt)
      {
      case 'H': v_cfd = list_optarg; break;
      case 'm': v_meth = list_optarg; break;
      case 'p': v_path = list_optarg; break;
      case 'q': v_query = list_optarg; break;
      case 'B': bodyfile = list_optarg; break;
      case 'l': v_len = list_optarg; break;
      case 'c': v_ct = list_optarg; break;
      case 'r': v_rem = list_optarg; break;
      case 't':
	secs = strtol (list_optarg, &end, 10);
	if (*list_optarg == 0 || *end || secs < 0) { builtin_error ("accept: bad -t '%s'", list_optarg); return (EX_USAGE); }
	break;
      default: builtin_usage (); return (EX_USAGE);
      }
  if (!v_cfd || !v_meth || !v_path || !v_query || !bodyfile)
    { builtin_error ("accept: -H CFD -m METHOD -p PATH -q QUERY -B BODYFILE are all required"); return (EX_USAGE); }
  {
    /* Validate every name BEFORE a connection is consumed. */
    const char *names[] = { v_cfd, v_meth, v_path, v_query, v_len, v_ct, v_rem };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
      if (names[i] && !legal_identifier (names[i]))
	{ builtin_error ("'%s' is not a valid variable name", names[i]); return (EX_USAGE); }
  }

  if (secs >= 0)
    {
      int r = wait_ready ((int) lfd, secs);
      if (r == 0) return 3;					/* timeout: nothing bound */
      if (r < 0) { builtin_error ("accept: poll: %s", strerror (errno)); return (EXECUTION_FAILURE); }
    }
  do cfd = accept4 ((int) lfd, (struct sockaddr *) &peer, &plen, SOCK_CLOEXEC);
  while (cfd < 0 && errno == EINTR);
  if (cfd < 0) { builtin_error ("accept: %s", strerror (errno)); return (EXECUTION_FAILURE); }
  if (inet_ntop (AF_INET, &peer.sin_addr, remote, sizeof remote) == 0) strcpy (remote, "?");
  long deadline = mono_ms () + HTTPD_REQUEST_TIMEOUT_MS;

  /* The head: read until the blank line, never past HEAD_MAX. The whole read is
     bounded by `deadline`, so a client that stops sending cannot stall us. */
  for (;;)
    {
      ssize_t r;
      if (got >= HEAD_MAX)
	{ refuse (cfd, 431); builtin_error ("accept: request head over %d bytes (431 sent)", HEAD_MAX); return (EXECUTION_FAILURE); }
      r = read_by (cfd, head + got, HEAD_MAX - got, deadline);
      if (r == READ_TIMED_OUT) { refuse (cfd, 408); builtin_error ("accept: request head timed out after %d ms (408 sent)", HTTPD_REQUEST_TIMEOUT_MS); return (EXECUTION_FAILURE); }
      if (r < 0) { close (cfd); builtin_error ("accept: read: %s", strerror (errno)); return (EXECUTION_FAILURE); }
      if (r == 0) { refuse (cfd, 400); builtin_error ("accept: connection closed before the request head (400 sent)"); return (EXECUTION_FAILURE); }
      got += (size_t) r; head[got] = '\0';
      if ((hend = strstr (head, "\r\n\r\n")) != 0) { sep = 4; break; }
      if ((hend = strstr (head, "\n\n")) != 0)     { sep = 2; break; }
    }
  body = hend + sep;			/* body bytes already read, if any */
  *hend = '\0';

  /* Request line: METHOD SP TARGET SP HTTP/1.x — exactly three tokens. */
  line = head;
  next = strchr (line, '\n'); if (next) { *next++ = '\0'; }
  if ((end = strchr (line, '\r'))) *end = '\0';
  method = line;
  target = strchr (method, ' ');
  if (target == 0) { refuse (cfd, 400); builtin_error ("accept: malformed request line (400 sent)"); return (EXECUTION_FAILURE); }
  *target++ = '\0';
  version = strchr (target, ' ');
  if (version == 0) { refuse (cfd, 400); builtin_error ("accept: malformed request line (400 sent)"); return (EXECUTION_FAILURE); }
  *version++ = '\0';
  if (*method == 0 || *target == 0 || strchr (version, ' ')
      || (strcmp (version, "HTTP/1.1") != 0 && strcmp (version, "HTTP/1.0") != 0))
    { refuse (cfd, 400); builtin_error ("accept: malformed request line (400 sent)"); return (EXECUTION_FAILURE); }
  query = strchr (target, '?');
  if (query) *query++ = '\0'; else query = "";

  /* Headers: only Content-Length and Content-Type matter; the rest are parsed
     for shape and ignored. Two different Content-Lengths is a 400, not a guess. */
  for (line = next; line && *line; line = next)
    {
      char *v;
      next = strchr (line, '\n'); if (next) *next++ = '\0';
      if ((end = strchr (line, '\r'))) *end = '\0';
      if (*line == 0) break;
      if (strchr (line, ':') == 0)
	{ refuse (cfd, 400); builtin_error ("accept: malformed header line (400 sent)"); return (EXECUTION_FAILURE); }
      if ((v = header_value (line, "Content-Length")))
	{
	  long n; char *e;
	  n = strtol (v, &e, 10);
	  while (*e == ' ' || *e == '\t') e++;
	  if (*v == 0 || *e || n < 0 || !isdigit ((unsigned char) *v) || (seen_len && n != clen))
	    { refuse (cfd, 400); builtin_error ("accept: bad Content-Length (400 sent)"); return (EXECUTION_FAILURE); }
	  clen = n; seen_len = 1;
	}
      else if ((v = header_value (line, "Content-Type")))
	{
	  ctype = v;
	  for (char *e = ctype + strlen (ctype); e > ctype && (e[-1] == ' ' || e[-1] == '\t'); e--) e[-1] = '\0';
	}
    }
  if (clen > BODY_MAX)
    { refuse (cfd, 413); builtin_error ("accept: Content-Length %ld over %ld (413 sent)", clen, BODY_MAX); return (EXECUTION_FAILURE); }

  /* The body file: truncated on every accept, then exactly clen bytes. */
  bfd = open (bodyfile, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (bfd < 0 || fchmod (bfd, 0600) != 0)
    { refuse (cfd, 500); builtin_error ("accept: %s: %s (500 sent)", bodyfile, strerror (errno)); if (bfd >= 0) close (bfd); return (EXECUTION_FAILURE); }
  {
    size_t have = got - (size_t) (body - head);		/* body bytes in the head buffer */
    long remaining = clen;
    if (have > (size_t) clen) have = (size_t) clen;
    if (have && write_all (bfd, body, have) != 0)
      { close (bfd); close (cfd); builtin_error ("accept: write %s: %s", bodyfile, strerror (errno)); return (EXECUTION_FAILURE); }
    remaining -= (long) have;
    while (remaining > 0)
      {
	char buf[CHUNK];
	ssize_t r = read_by (cfd, buf, remaining < CHUNK ? (size_t) remaining : CHUNK, deadline);
	if (r == READ_TIMED_OUT) { close (bfd); refuse (cfd, 408); builtin_error ("accept: request body timed out after %d ms (408 sent)", HTTPD_REQUEST_TIMEOUT_MS); return (EXECUTION_FAILURE); }
	if (r < 0) { close (bfd); close (cfd); builtin_error ("accept: read body: %s", strerror (errno)); return (EXECUTION_FAILURE); }
	if (r == 0) { close (bfd); refuse (cfd, 400); builtin_error ("accept: body shorter than Content-Length (400 sent)"); return (EXECUTION_FAILURE); }
	if (write_all (bfd, buf, (size_t) r) != 0)
	  { close (bfd); close (cfd); builtin_error ("accept: write %s: %s", bodyfile, strerror (errno)); return (EXECUTION_FAILURE); }
	remaining -= r;
      }
  }
  close (bfd);

  if (set_long (v_cfd, cfd) != 0 || set_var (v_meth, method) != 0 || set_var (v_path, target) != 0
      || set_var (v_query, query) != 0
      || (v_len && set_long (v_len, clen) != 0)
      || (v_ct && set_var (v_ct, ctype) != 0)
      || (v_rem && set_var (v_rem, remote) != 0))
    { close (cfd); return (EXECUTION_FAILURE); }
  return (EXECUTION_SUCCESS);
}

/* ---- reply ---------------------------------------------------------------- */
static int
do_reply (WORD_LIST *list)
{
  const char *ctype = "application/json", *file = 0;
  long cfd, status = 200, clen = 0;
  int opt, rc = EXECUTION_SUCCESS, err = 0, ffd = -1;
  char *end, *buf = 0;
  char hdr[512];

  if (list == 0) { builtin_usage (); return (EX_USAGE); }
  if (parse_fd (list->word->word, "reply", &cfd) != 0) return (EX_USAGE);
  reset_internal_getopt ();
  while ((opt = internal_getopt (list->next, "s:t:f:")) != -1)
    switch (opt)
      {
      case 's':
	status = strtol (list_optarg, &end, 10);
	if (*list_optarg == 0 || *end || status < 100 || status > 999) { builtin_error ("reply: bad status '%s'", list_optarg); return (EX_USAGE); }
	break;
      case 't': ctype = list_optarg; break;
      case 'f': file = list_optarg; break;
      default: builtin_usage (); return (EX_USAGE);
      }
  if (strpbrk (ctype, "\r\n"))
    { builtin_error ("reply: Content-Type may not contain CR or LF"); return (EX_USAGE); }

  /* Body source and its length: a file (streamed, size from fstat) or stdin
     (buffered, since Content-Length must precede it). */
  if (file)
    {
      struct stat st;
      ffd = open (file, O_RDONLY | O_CLOEXEC);
      if (ffd < 0 || fstat (ffd, &st) != 0)
	{ builtin_error ("reply: %s: %s", file, strerror (errno)); if (ffd >= 0) close (ffd); close ((int) cfd); return (EXECUTION_FAILURE); }
      clen = (long) st.st_size;
    }
  else
    {
      size_t cap = CHUNK, len = 0;
      buf = malloc (cap);
      if (buf == 0) { builtin_error ("reply: out of memory"); close ((int) cfd); return (EXECUTION_FAILURE); }
      for (;;)
	{
	  ssize_t r;
	  if (len == cap) { char *n = realloc (buf, cap *= 2); if (n == 0) { free (buf); builtin_error ("reply: out of memory"); close ((int) cfd); return (EXECUTION_FAILURE); } buf = n; }
	  r = read_retry (0, buf + len, cap - len);
	  if (r < 0) { free (buf); builtin_error ("reply: stdin: %s", strerror (errno)); close ((int) cfd); return (EXECUTION_FAILURE); }
	  if (r == 0) break;
	  len += (size_t) r;
	}
      clen = (long) len;
    }

  snprintf (hdr, sizeof hdr, "HTTP/1.1 %ld %s\r\nContent-Type: %s\r\nContent-Length: %ld\r\nConnection: close\r\n\r\n",
	    status, reason ((int) status), ctype, clen);
  if (send_all ((int) cfd, hdr, strlen (hdr)) != 0) { rc = EXECUTION_FAILURE; err = errno; }
  else if (file)
    {
      char chunk[CHUNK];
      long left = clen;
      while (left > 0)
	{
	  ssize_t r = read_retry (ffd, chunk, left < CHUNK ? (size_t) left : CHUNK);
	  if (r <= 0) { rc = EXECUTION_FAILURE; err = r < 0 ? errno : EIO; break; }
	  if (send_all ((int) cfd, chunk, (size_t) r) != 0) { rc = EXECUTION_FAILURE; err = errno; break; }
	  left -= r;
	}
    }
  else if (clen > 0 && send_all ((int) cfd, buf, (size_t) clen) != 0) { rc = EXECUTION_FAILURE; err = errno; }

  if (ffd >= 0) close (ffd);
  free (buf);
  close ((int) cfd);					/* always: the connection is ours to end */
  if (rc != EXECUTION_SUCCESS) builtin_error ("reply: %s", strerror (err));
  return rc;
}

/* ---- part: one part of a multipart/form-data body ------------------------- */
/* Copy the value of parameter PARAM (case-insensitive) from a Content-
   Disposition value into out. A real scanner, not a split on ';': a quoted
   value may contain ';', and "name=" must never match inside "filename=".
   want_base keeps only the basename, against '/' and '\'. Returns 1 if found. */
static int
disp_param (const char *disp, const char *param, int want_base, char *out, size_t outsz)
{
  const char *p = disp;
  size_t pn = strlen (param);
  for (;;)
    {
      const char *key, *v, *vend;
      size_t klen, vlen;
      while (*p == ' ' || *p == '\t' || *p == ';') p++;
      if (*p == 0) return 0;
      key = p;
      while (*p && *p != '=' && *p != ';') p++;
      klen = (size_t) (p - key);
      if (*p != '=') continue;				/* a bare token such as form-data */
      p++;
      if (*p == '"') { v = ++p; while (*p && *p != '"') p++; vend = p; if (*p) p++; }
      else { v = p; while (*p && *p != ';') p++; vend = p; while (vend > v && (vend[-1] == ' ' || vend[-1] == '\t')) vend--; }
      if (klen == pn && strncasecmp (key, param, pn) == 0)
	{
	  if (want_base)
	    { const char *b = vend; while (b > v && b[-1] != '/' && b[-1] != '\\') b--; v = b; }
	  vlen = (size_t) (vend - v);
	  if (vlen >= outsz) vlen = outsz - 1;
	  memcpy (out, v, vlen); out[vlen] = '\0';
	  return 1;
	}
    }
}

static int
do_part (WORD_LIST *list)
{
  const char *bodyfile, *boundary = 0, *outfile = 0, *field = 0, *v_fn = 0, *v_len = 0;
  int opt, fd, rc = 1;					/* 1: no such part */
  char delim[280], needle[284];
  unsigned char *buf = 0;
  size_t len, dl, nl;
  struct stat st;

  if (list == 0) { builtin_usage (); return (EX_USAGE); }
  bodyfile = list->word->word;
  reset_internal_getopt ();
  while ((opt = internal_getopt (list->next, "b:o:n:F:l:")) != -1)
    switch (opt)
      {
      case 'b': boundary = list_optarg; break;
      case 'o': outfile = list_optarg; break;
      case 'n': field = list_optarg; break;
      case 'F': v_fn = list_optarg; break;
      case 'l': v_len = list_optarg; break;
      default: builtin_usage (); return (EX_USAGE);
      }
  if (!boundary || !outfile) { builtin_error ("part: -b BOUNDARY and -o OUTFILE are required"); return (EX_USAGE); }
  if ((v_fn && !legal_identifier (v_fn)) || (v_len && !legal_identifier (v_len)))
    { builtin_error ("part: invalid variable name"); return (EX_USAGE); }
  {
    size_t bl = strlen (boundary);
    if (bl >= 2 && boundary[0] == '"' && boundary[bl - 1] == '"') { boundary++; bl -= 2; }
    if (bl == 0 || bl > 250) { builtin_error ("part: bad boundary"); return (EX_USAGE); }
    dl = (size_t) snprintf (delim, sizeof delim, "--%.*s", (int) bl, boundary);
    nl = (size_t) snprintf (needle, sizeof needle, "\r\n%s", delim);
  }

  /* The whole body: accept capped it at BODY_MAX, so this is bounded. */
  fd = open (bodyfile, O_RDONLY | O_CLOEXEC);
  if (fd < 0) { builtin_error ("part: %s: %s", bodyfile, strerror (errno)); return (EXECUTION_FAILURE); }
  if (fstat (fd, &st) != 0) { builtin_error ("part: %s: %s", bodyfile, strerror (errno)); close (fd); return (EXECUTION_FAILURE); }
  if (st.st_size > BODY_MAX) { builtin_error ("part: %s: larger than the %ld byte cap", bodyfile, BODY_MAX); close (fd); return (EXECUTION_FAILURE); }
  len = (size_t) st.st_size;
  buf = malloc (len + 1);
  if (buf == 0) { builtin_error ("part: out of memory"); close (fd); return (EXECUTION_FAILURE); }
  for (size_t got = 0; got < len; )
    {
      ssize_t r = read_retry (fd, buf + got, len - got);
      if (r < 0) { builtin_error ("part: read %s: %s", bodyfile, strerror (errno)); close (fd); free (buf); return (EXECUTION_FAILURE); }
      if (r == 0) { len = got; break; }
      got += (size_t) r;
    }
  close (fd);

  {
    const unsigned char *end = buf + len, *p = memmem (buf, len, delim, dl);
    while (p)
      {
	const unsigned char *after = p + dl, *hdr, *hend, *body, *bend;
	if (after + 2 <= end && after[0] == '-' && after[1] == '-') break;	/* closing delimiter */
	if (after + 2 > end || after[0] != '\r' || after[1] != '\n') break;	/* malformed */
	hdr = after + 2;
	hend = memmem (hdr, (size_t) (end - hdr), "\r\n\r\n", 4);
	if (hend == 0) break;
	body = hend + 4;
	bend = memmem (body, (size_t) (end - body), needle, nl);		/* CRLF + delimiter */
	if (bend == 0) break;
	{
	  size_t hl = (size_t) (hend - hdr);
	  char *h = malloc (hl + 1), *line, *nx;
	  char name[256] = "", fname[256] = "";
	  int has_name = 0, has_fn = 0;
	  if (h == 0) { builtin_error ("part: out of memory"); free (buf); return (EXECUTION_FAILURE); }
	  memcpy (h, hdr, hl); h[hl] = '\0';
	  for (line = h; line && *line; line = nx)
	    {
	      nx = strstr (line, "\r\n"); if (nx) { *nx = '\0'; nx += 2; }
	      if (strncasecmp (line, "Content-Disposition:", 20) == 0)
		{
		  const char *d = line + 20;
		  while (*d == ' ' || *d == '\t') d++;
		  has_name = disp_param (d, "name", 0, name, sizeof name);
		  has_fn = disp_param (d, "filename", 1, fname, sizeof fname);
		}
	    }
	  free (h);
	  if ((field && has_name && strcmp (name, field) == 0) || (field == 0 && has_fn))
	    {
	      int ofd = open (outfile, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	      if (ofd < 0 || fchmod (ofd, 0600) != 0 || write_all (ofd, body, (size_t) (bend - body)) != 0 || close (ofd) != 0)
		{ builtin_error ("part: %s: %s", outfile, strerror (errno)); if (ofd >= 0) close (ofd); free (buf); return (EXECUTION_FAILURE); }
	      if ((v_fn && set_var (v_fn, fname) != 0) || (v_len && set_long (v_len, (long) (bend - body)) != 0))
		{ free (buf); return (EXECUTION_FAILURE); }
	      rc = 0;
	      break;
	    }
	}
	p = bend + 2;						/* the next delimiter */
      }
  }
  free (buf);
  return rc;
}

/* ---- the builtin ---------------------------------------------------------- */
int
httpd_builtin (WORD_LIST *list)
{
  const char *verb;
  if (list == 0) { builtin_usage (); return (EX_USAGE); }
  verb = list->word->word;
  if (strcmp (verb, "listen") == 0) return do_listen (list->next);
  if (strcmp (verb, "accept") == 0) return do_accept (list->next);
  if (strcmp (verb, "reply") == 0)  return do_reply (list->next);
  if (strcmp (verb, "part") == 0)   return do_part (list->next);
  builtin_error ("unknown verb '%s' (listen|accept|reply|part)", verb);
  return (EX_USAGE);
}

char *httpd_doc[] = {
  "HTTP server primitive: listen, accept one request, reply.",
  "",
  "httpd listen PORT [-a ADDR] -H VAR",
  "    TCP listen socket (SO_REUSEADDR, backlog 8); its fd -> VAR.",
  "httpd accept LFD -H CFD -m METHOD -p PATH -q QUERY -B BODYFILE",
  "             [-l LENVAR] [-c CTYPEVAR] [-t SECS] [-r REMOTEVAR]",
  "    One connection: request line + headers parsed into the variables, the",
  "    body (Content-Length bytes, cap 16 MiB) into BODYFILE, CFD left open.",
  "    -t SECS: return 3 on timeout, nothing bound. Bad requests are answered",
  "    (400/413/431) and closed here, with a non-zero return.",
  "httpd reply CFD [-s STATUS] [-t CONTENT_TYPE] [-f FILE]",
  "    Status line, headers, then FILE's bytes or stdin to EOF; closes CFD.",
  "httpd part BODYFILE -b BOUNDARY -o OUTFILE [-n FIELDNAME] [-F FILENAMEVAR] [-l LENVAR]",
  "    One multipart/form-data part (by field name, else the first with a",
  "    filename) -> OUTFILE. 0 found, 1 no such part, failure on I/O error.",
  "accept must run in the current shell (it binds variables). Do not pipe INTO",
  "reply: `cmd | httpd reply $CFD` leaks the parent's fd — redirect instead.",
  (char *) NULL
};

struct builtin httpd_struct = {
  "httpd", httpd_builtin, BUILTIN_ENABLED, httpd_doc, "httpd listen|accept|reply|part ...", 0
};
