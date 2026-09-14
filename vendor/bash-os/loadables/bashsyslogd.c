/* SPDX-License-Identifier: MIT */
/* bashsyslogd.c - minimal /dev/log receiver for bash-os.
 *
 * First slice: bind an AF_UNIX SOCK_DGRAM socket, receive logger-style
 * messages, and append one line per datagram to a local log file.
 *
 * Tripwire (LOG-PARSER-AUDIT.md Wave 1 #7): this builtin deliberately
 * does NOT parse structured-data elements from the newer syslog
 * protocol. The datagram is opaque post-defang, which means
 * structured-element bounds cannot be attacked because no parser
 * exists. If you add structured-element awareness (a nested
 * `[id key="val"]` walker, anything that splits inside the SD block)
 * you MUST re-run the bashsyslogd checklist in
 * research/bash-os/LOG-PARSER-AUDIT.md and refresh
 * tests/bash-os/700-bashsyslogd-log-parser-audit.sh — the tripwire
 * assertion in that test (test #14) flips fail when the corresponding
 * markers appear.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <locale.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>

#include "loadables.h"

#ifndef SOCK_CLOEXEC
#  define SOCK_CLOEXEC 02000000
#endif

/* Datagram recv buffer cap. RFC3164 recommends 1024 octets; we accept
 * up to BSD_RECV_BUFSZ. Datagrams above this cap are silently
 * truncated by recv() — bsd_run() emits a builtin_warning when a
 * receive fills the buffer exactly (likely-truncation marker). */
#define BSD_RECV_BUFSZ 8192

static volatile sig_atomic_t bsd_stop = 0;
static volatile sig_atomic_t bsd_reload = 0;

static void
bsd_on_signal (int sig)
{
  if (sig == SIGHUP)
    bsd_reload = 1;
  else
    bsd_stop = 1;
}

static void
bsd_install_signal (int sig)
{
  struct sigaction sa;

  memset (&sa, 0, sizeof sa);
  sa.sa_handler = bsd_on_signal;
  sigemptyset (&sa.sa_mask);
  sigaction (sig, &sa, NULL);
}

static int
bsd_set_cloexec (int fd)
{
  int flags = fcntl (fd, F_GETFD);
  if (flags < 0)
    return -1;
  return fcntl (fd, F_SETFD, flags | FD_CLOEXEC);
}

static int
bsd_safe_unlink_socket (const char *path)
{
  struct stat st;

  if (lstat (path, &st) < 0)
    {
      if (errno == ENOENT)
        return 0;
      builtin_error ("lstat %s: %s", path, strerror (errno));
      return -1;
    }

  if (!S_ISSOCK (st.st_mode))
    {
      builtin_error ("refusing to unlink non-socket %s", path);
      return -1;
    }

  if (unlink (path) < 0 && errno != ENOENT)
    {
      builtin_error ("unlink %s: %s", path, strerror (errno));
      return -1;
    }
  return 0;
}

static int
bsd_open_socket (const char *path, mode_t mode)
{
  struct sockaddr_un sun;
  int fd = socket (AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);

  if (fd < 0 && errno == EINVAL)
    fd = socket (AF_UNIX, SOCK_DGRAM, 0);
  if (fd < 0)
    {
      builtin_error ("socket: %s", strerror (errno));
      return -1;
    }
  if (bsd_set_cloexec (fd) < 0)
    {
      builtin_error ("fcntl FD_CLOEXEC: %s", strerror (errno));
      close (fd);
      return -1;
    }

  memset (&sun, 0, sizeof sun);
  sun.sun_family = AF_UNIX;
  if (strlen (path) >= sizeof sun.sun_path)
    {
      builtin_error ("socket path too long: %s", path);
      close (fd);
      return -1;
    }
  snprintf (sun.sun_path, sizeof sun.sun_path, "%s", path);

  if (bsd_safe_unlink_socket (path) < 0)
    {
      close (fd);
      return -1;
    }
  if (bind (fd, (struct sockaddr *) &sun, (socklen_t) sizeof sun) < 0)
    {
      builtin_error ("bind %s: %s", path, strerror (errno));
      close (fd);
      return -1;
    }
  chmod (path, mode);
  return fd;
}

static void
bsd_stamp (char *buf, size_t cap)
{
  time_t now = time (NULL);
  struct tm tmv;

  if (localtime_r (&now, &tmv))
    strftime (buf, cap, "%b %e %H:%M:%S", &tmv);
  else
    snprintf (buf, cap, "Jan  1 00:00:00");
}

static int
bsd_append_line (const char *log_path, const char *msg, ssize_t len)
{
  char ts[32];
  char host[128];
  FILE *fp;

  fp = fopen (log_path, "a");
  if (!fp)
    {
      builtin_error ("open %s: %s", log_path, strerror (errno));
      return -1;
    }

  bsd_stamp (ts, sizeof ts);
  if (gethostname (host, sizeof host) < 0)
    snprintf (host, sizeof host, "bash-os");
  host[sizeof host - 1] = '\0';

  fprintf (fp, "%s %s ", ts, host);
  for (ssize_t i = 0; i < len; i++)
    {
      unsigned char c = (unsigned char) msg[i];
      /* Defang all C0 controls (and DEL) except TAB. Covers NUL/LF/CR
       * plus ESC (0x1b) / BEL (0x07) / BS (0x08) / other C0 codes that
       * would otherwise reach a sysadmin's terminal verbatim when they
       * `cat` /var/log/messages — see LOG-PARSER-AUDIT.md Wave 1 #1. */
      if (c == '\t')
        fputc ((int) c, fp);
      else if (c == '\0' || c == '\n' || c == '\r' || iscntrl (c) || c == 0x7f)
        fputc (' ', fp);
      else
        fputc ((int) c, fp);
    }
  fputc ('\n', fp);
  fclose (fp);
  return 0;
}

/* Sanitiser for the UDP forward path. Writes a defanged copy of MSG
 * into OUT (cap OUT_CAP) using the same control-byte policy as
 * bsd_append_line. Returns the number of bytes written (capped at
 * OUT_CAP). Closes the gap noted in LOG-PARSER-AUDIT.md Wave 1 #5
 * where the local-file path scrubbed but sendto() forwarded raw. */
static ssize_t
bsd_msg_scrub (const char *msg, ssize_t len, char *out, size_t out_cap)
{
  ssize_t lim = (ssize_t) out_cap;
  ssize_t i;

  if (!msg || !out || out_cap == 0 || len <= 0)
    return 0;
  if (len < lim)
    lim = len;
  for (i = 0; i < lim; i++)
    {
      unsigned char c = (unsigned char) msg[i];
      if (c == '\t')
        out[i] = (char) c;
      else if (c == '\0' || c == '\n' || c == '\r' || iscntrl (c) || c == 0x7f)
        out[i] = ' ';
      else
        out[i] = (char) c;
    }
  return lim;
}

/* RFC3164 §4.1.1 PRI parser (same PRI grammar used by the newer
 * syslog protocol, §6.2.1 there). The PRI MUST be the
 * leading token of the datagram in the form "<NNN>" where NNN is 1-3
 * ASCII digits encoding (facility * 8 + severity). Returns the parsed
 * priority value (0..1023, well-formed PRI maxes at 191) or -1 if the
 * datagram does not begin with a well-formed numeric PRI.
 *
 * Walking the FULL ssize_t length (not strlen) keeps this NUL-safe:
 * an embedded NUL in MSG bytes after the PRI cannot truncate the
 * routing decision because the PRI lives at offset 0.
 *
 * Closes LOG-PARSER-AUDIT.md Wave 1 #2: the old text-substring scan
 * matched `<auth.notice>` anywhere in MSG body, letting an attacker
 * misroute datagrams to auth.log/kern.log regardless of real PRI. */
static int
bsd_parse_pri (const char *msg, ssize_t len)
{
  ssize_t i;
  int pri = 0;
  int digits = 0;

  if (!msg || len < 3 || msg[0] != '<')
    return -1;
  for (i = 1; i < len && i < 5; i++)
    {
      unsigned char c = (unsigned char) msg[i];
      if (c == '>')
        {
          if (digits == 0)
            return -1;
          return pri;
        }
      if (!isdigit (c))
        return -1;
      pri = pri * 10 + (c - '0');
      if (++digits > 3)
        return -1;
    }
  return -1;
}

/* Route a datagram to the per-facility log stream. The facility is
 * the upper 5 bits of PRI (pri >> 3); RFC3164 §4.1.1 Table 1 lists
 * facility 0 = kern, facility 4 = auth, facility 10 = authpriv.
 * Walks the full ssize_t length via bsd_parse_pri (NUL-safe routing). */
static const char *
bsd_stream_path (const char *msg, ssize_t len, const char *syslog_path,
                 const char *auth_path, const char *kern_path)
{
  int pri = bsd_parse_pri (msg, len);
  int facility;

  if (pri < 0)
    return syslog_path;
  facility = pri >> 3;
  if (facility == 4 || facility == 10)  /* auth, authpriv */
    return auth_path;
  if (facility == 0)                     /* kern */
    return kern_path;
  return syslog_path;
}

static void
bsd_derive_stream_path (const char *log_path, const char *base,
                        char *out, size_t cap)
{
  const char *slash;
  size_t dirlen;

  if (!log_path || !*log_path)
    {
      snprintf (out, cap, "%s", base);
      return;
    }

  slash = strrchr (log_path, '/');
  if (!slash)
    {
      snprintf (out, cap, "%s", base);
      return;
    }

  dirlen = (size_t) (slash - log_path);
  if (dirlen == 0)
    snprintf (out, cap, "/%s", base);
  else if (dirlen + 1 + strlen (base) < cap)
    {
      memcpy (out, log_path, dirlen);
      out[dirlen] = '/';
      snprintf (out + dirlen + 1, cap - dirlen - 1, "%s", base);
    }
  else
    snprintf (out, cap, "%s", base);
}

static void
bsd_route_local (const char *messages_path, const char *syslog_path,
                 const char *auth_path, const char *kern_path,
                 const char *msg, ssize_t len)
{
  const char *stream_path = bsd_stream_path (msg, len, syslog_path,
                                            auth_path, kern_path);

  bsd_append_line (messages_path, msg, len);
  if (stream_path && strcmp (stream_path, messages_path) != 0)
    bsd_append_line (stream_path, msg, len);
}

/* Parse a HOST:PORT forward target. Accepts two forms:
 *   - plain        host:port           (IPv4 literal or hostname)
 *   - bracketed    [host]:port         (RFC3986 §3.2.2; required for IPv6
 *                                       literals because raw `::1:514` is
 *                                       ambiguous to strrchr)
 * Brackets are stripped before being handed to getaddrinfo. Closes
 * LOG-PARSER-AUDIT.md Wave 1 #4. */
static int
bsd_parse_forward (const char *spec, char *host, size_t host_cap,
                   char *port, size_t port_cap)
{
  const char *colon;
  const char *rbracket;
  size_t hlen;

  if (!spec || !*spec)
    return -1;

  if (spec[0] == '[')
    {
      rbracket = strchr (spec, ']');
      if (!rbracket || rbracket == spec + 1 || rbracket[1] != ':'
          || rbracket[2] == '\0')
        return -1;
      hlen = (size_t) (rbracket - spec - 1);
      if (hlen >= host_cap || strlen (rbracket + 2) >= port_cap)
        return -1;
      memcpy (host, spec + 1, hlen);
      host[hlen] = '\0';
      snprintf (port, port_cap, "%s", rbracket + 2);
      return 0;
    }

  colon = strrchr (spec, ':');
  if (!colon || colon == spec || colon[1] == '\0')
    return -1;

  if ((size_t) (colon - spec) >= host_cap || strlen (colon + 1) >= port_cap)
    return -1;

  memcpy (host, spec, (size_t) (colon - spec));
  host[colon - spec] = '\0';
  snprintf (port, port_cap, "%s", colon + 1);
  return 0;
}

static int
bsd_open_udp_forward (const char *spec, struct sockaddr_storage *addr,
                      socklen_t *addrlen)
{
  char host[256];
  char port[32];
  struct addrinfo hints, *res = NULL, *rp;
  int fd = -1;
  int rc;

  if (bsd_parse_forward (spec, host, sizeof host, port, sizeof port) < 0)
    {
      builtin_error ("bad --forward target: %s", spec ? spec : "");
      return -1;
    }

  memset (&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  rc = getaddrinfo (host, port, &hints, &res);
  if (rc != 0)
    {
      builtin_error ("resolve %s: %s", spec, gai_strerror (rc));
      return -1;
    }

  for (rp = res; rp; rp = rp->ai_next)
    {
      fd = socket (rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC,
                   rp->ai_protocol);
      if (fd < 0 && errno == EINVAL)
        fd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (fd < 0)
        continue;
      if (bsd_set_cloexec (fd) < 0)
        {
          close (fd);
          fd = -1;
          continue;
        }
      memcpy (addr, rp->ai_addr, rp->ai_addrlen);
      *addrlen = (socklen_t) rp->ai_addrlen;
      break;
    }

  freeaddrinfo (res);
  if (fd < 0)
    builtin_error ("udp socket %s: %s", spec, strerror (errno));
  return fd;
}

static void
bsd_mkdir_parent (const char *path)
{
  char buf[512];
  char *slash;

  if (!path || !*path)
    return;
  if (strlen (path) >= sizeof buf)
    return;

  snprintf (buf, sizeof buf, "%s", path);
  slash = strrchr (buf, '/');
  if (!slash || slash == buf)
    return;
  *slash = '\0';
  (void) mkdir (buf, 0755);
}

static off_t
bsd_file_size (const char *path)
{
  struct stat st;

  if (!path || !*path || stat (path, &st) < 0)
    return 0;
  return st.st_size;
}

static int
bsd_hex_value (int c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static char *
bsd_hex_encode (const char *msg, ssize_t len)
{
  static const char hex[] = "0123456789abcdef";
  char *out;
  size_t n;

  if (len <= 0)
    return NULL;
  n = (size_t) len;
  if (n > ((size_t) -1 - 2) / 2)
    return NULL;
  out = malloc (n * 2 + 2);
  if (!out)
    return NULL;
  for (size_t i = 0; i < n; i++)
    {
      unsigned char c = (unsigned char) msg[i];
      out[i * 2] = hex[c >> 4];
      out[i * 2 + 1] = hex[c & 15];
    }
  out[n * 2] = '\n';
  out[n * 2 + 1] = '\0';
  return out;
}

static char *
bsd_hex_decode_line (const char *line, ssize_t *out_len)
{
  size_t len;
  char *out;

  if (!line || !out_len)
    return NULL;
  len = strcspn (line, "\r\n");
  if (len == 0 || (len % 2) != 0)
    return NULL;
  out = malloc (len / 2);
  if (!out)
    return NULL;
  for (size_t i = 0; i < len; i += 2)
    {
      int hi = bsd_hex_value ((unsigned char) line[i]);
      int lo = bsd_hex_value ((unsigned char) line[i + 1]);
      if (hi < 0 || lo < 0)
        {
          free (out);
          return NULL;
        }
      out[i / 2] = (char) ((hi << 4) | lo);
    }
  *out_len = (ssize_t) (len / 2);
  return out;
}

static int
bsd_queue_forward (const char *queue_path, size_t queue_max_bytes,
                   const char *msg, ssize_t len)
{
  char *line;
  size_t need;
  FILE *fp;

  if (!queue_path || !*queue_path || queue_max_bytes == 0 || len <= 0)
    return -1;
  line = bsd_hex_encode (msg, len);
  if (!line)
    return -1;
  need = strlen (line);
  if (need > queue_max_bytes
      || (off_t) need + bsd_file_size (queue_path) > (off_t) queue_max_bytes)
    {
      free (line);
      return -1;
    }

  bsd_mkdir_parent (queue_path);
  fp = fopen (queue_path, "a");
  if (!fp)
    {
      free (line);
      return -1;
    }
  fputs (line, fp);
  fclose (fp);
  free (line);
  return 0;
}

/* UDP forward path. Defangs the datagram via bsd_msg_scrub before
 * sendto() so downstream receivers see the same control-byte policy
 * as the local-file path — closes LOG-PARSER-AUDIT.md Wave 1 #5. */
static int
bsd_forward_udp (int fd, const struct sockaddr_storage *addr,
                 socklen_t addrlen, const char *msg, ssize_t len)
{
  char scrub_buf[BSD_RECV_BUFSZ];
  ssize_t slen;

  if (fd < 0 || len <= 0)
    return -1;
  slen = bsd_msg_scrub (msg, len, scrub_buf, sizeof scrub_buf);
  if (slen <= 0)
    return -1;
  return sendto (fd, scrub_buf, (size_t) slen, 0,
                 (const struct sockaddr *) addr, addrlen) == slen ? 0 : -1;
}

static void
bsd_drain_queue (const char *queue_path, size_t queue_max_bytes, int fd,
                 const struct sockaddr_storage *addr, socklen_t addrlen)
{
  char tmp[640];
  char line[20000];
  FILE *in, *out = NULL;
  int kept = 0;

  if (!queue_path || !*queue_path || fd < 0 || bsd_file_size (queue_path) <= 0)
    return;

  in = fopen (queue_path, "r");
  if (!in)
    return;
  snprintf (tmp, sizeof tmp, "%s.tmp.%ld", queue_path, (long) getpid ());

  while (fgets (line, sizeof line, in))
    {
      ssize_t msg_len = 0;
      char *msg = bsd_hex_decode_line (line, &msg_len);
      if (!msg)
        continue;
      if (bsd_forward_udp (fd, addr, addrlen, msg, msg_len) < 0)
        {
          if (!out)
            out = fopen (tmp, "w");
          if (out && (queue_max_bytes == 0
                      || bsd_file_size (tmp) + (off_t) strlen (line)
                         <= (off_t) queue_max_bytes))
            {
              fputs (line, out);
              kept = 1;
            }
        }
      free (msg);
    }
  fclose (in);
  if (out)
    fclose (out);
  if (kept)
    rename (tmp, queue_path);
  else
    {
      unlink (tmp);
      unlink (queue_path);
    }
}

static char *
bsd_trim (char *s)
{
  char *end;

  while (*s && isspace ((unsigned char) *s))
    s++;
  end = s + strlen (s);
  while (end > s && isspace ((unsigned char) end[-1]))
    *--end = '\0';
  return s;
}

static int
bsd_read_config_forward (const char *config_path, char *out, size_t out_cap)
{
  FILE *fp;
  char line[512];
  int found = 0;

  if (!config_path || !*config_path || !out || out_cap == 0)
    return 0;
  fp = fopen (config_path, "r");
  if (!fp)
    return errno == ENOENT ? 0 : -1;
  while (fgets (line, sizeof line, fp))
    {
      char *s = bsd_trim (line);
      char *eq;
      char quote = 0;

      if (*s == '\0' || *s == '#')
        continue;
      if (strncmp (s, "BASHSYSLOGD_FORWARD", 19) != 0)
        continue;
      s += 19;
      s = bsd_trim (s);
      if (*s != '=')
        continue;
      eq = bsd_trim (s + 1);
      if (*eq == '"' || *eq == '\'')
        quote = *eq++;
      s = eq;
      while (*eq && ((quote && *eq != quote)
                     || (!quote && !isspace ((unsigned char) *eq)
                         && *eq != '#')))
        eq++;
      *eq = '\0';
      snprintf (out, out_cap, "%s", s);
      found = 1;
    }
  fclose (fp);
  return found;
}

static void
bsd_reload_forward (const char *config_path, char *forward_buf,
                    size_t forward_cap, int *udp_fd,
                    struct sockaddr_storage *udp_addr,
                    socklen_t *udp_addrlen)
{
  char next[256];
  int rc;

  rc = bsd_read_config_forward (config_path, next, sizeof next);
  if (rc <= 0)
    return;
  if (strcmp (next, forward_buf) == 0 && *udp_fd >= 0)
    return;

  if (*udp_fd >= 0)
    {
      close (*udp_fd);
      *udp_fd = -1;
    }
  snprintf (forward_buf, forward_cap, "%s", next);
  if (forward_buf[0] != '\0')
    *udp_fd = bsd_open_udp_forward (forward_buf, udp_addr, udp_addrlen);
}

static int
bsd_run (const char *sock_path, const char *log_path, mode_t mode, int once,
         const char *forward, const char *syslog_path,
         const char *auth_path, const char *kern_path,
         const char *config_path, const char *queue_path,
         size_t queue_max_bytes)
{
  int fd = bsd_open_socket (sock_path, mode);
  int udp_fd = -1;
  struct sockaddr_storage udp_addr;
  socklen_t udp_addrlen = 0;
  char forward_buf[256];
  char buf[BSD_RECV_BUFSZ];

  bsd_stop = 0;
  bsd_reload = 0;
  memset (&udp_addr, 0, sizeof udp_addr);
  snprintf (forward_buf, sizeof forward_buf, "%s", forward ? forward : "");

  if (fd < 0)
    return EXECUTION_FAILURE;
  if (config_path && *config_path && !forward_buf[0])
    bsd_read_config_forward (config_path, forward_buf, sizeof forward_buf);
  if (forward_buf[0])
    {
      udp_fd = bsd_open_udp_forward (forward_buf, &udp_addr, &udp_addrlen);
      if (udp_fd < 0)
        builtin_error ("forward target offline; local logging continues");
    }

  bsd_install_signal (SIGTERM);
  bsd_install_signal (SIGINT);
  bsd_install_signal (SIGHUP);
  bsd_drain_queue (queue_path, queue_max_bytes, udp_fd, &udp_addr, udp_addrlen);

  while (!bsd_stop)
    {
      ssize_t n = recv (fd, buf, sizeof buf, 0);
      if (n < 0)
        {
          if (errno == EINTR)
            {
              if (bsd_reload)
                {
                  bsd_reload = 0;
                  bsd_reload_forward (config_path, forward_buf,
                                      sizeof forward_buf, &udp_fd,
                                      &udp_addr, &udp_addrlen);
                  bsd_drain_queue (queue_path, queue_max_bytes, udp_fd,
                                   &udp_addr, udp_addrlen);
                }
              continue;
            }
          builtin_error ("recv %s: %s", sock_path, strerror (errno));
          close (fd);
          unlink (sock_path);
          return EXECUTION_FAILURE;
        }
      if (n > 0)
        {
          /* recv() into a fixed buffer silently truncates datagrams
           * above BSD_RECV_BUFSZ. When recv returns the full buffer
           * size, the datagram either fit exactly or was truncated.
           * Emit a one-shot warning so an operator notices oversized
           * inputs — closes LOG-PARSER-AUDIT.md Wave 1 #3. */
          if ((size_t) n == sizeof buf)
            {
              static int warned_truncation = 0;
              if (!warned_truncation)
                {
                  builtin_warning ("datagram filled %d-byte recv buffer; "
                                   "oversized syslog messages truncated "
                                   "(further warnings suppressed)",
                                   (int) sizeof buf);
                  warned_truncation = 1;
                }
            }
          bsd_route_local (log_path, syslog_path, auth_path, kern_path, buf, n);
          if (forward_buf[0]
              && bsd_forward_udp (udp_fd, &udp_addr, udp_addrlen, buf, n) < 0)
            bsd_queue_forward (queue_path, queue_max_bytes, buf, n);
          if (udp_fd >= 0)
            bsd_drain_queue (queue_path, queue_max_bytes, udp_fd, &udp_addr,
                             udp_addrlen);
        }
      if (once)
        break;
    }

  if (udp_fd >= 0)
    close (udp_fd);
  close (fd);
  unlink (sock_path);
  return EXECUTION_SUCCESS;
}

static int
bsd_parse_mode (const char *s, mode_t *out)
{
  char *end = NULL;
  unsigned long v;

  errno = 0;
  v = strtoul (s, &end, 8);
  if (errno || !end || *end || v > 0777)
    return -1;
  *out = (mode_t) v;
  return 0;
}

static int
bsd_parse_size (const char *s, size_t *out)
{
  char *end = NULL;
  unsigned long v;

  errno = 0;
  v = strtoul (s, &end, 10);
  if (errno || !end || *end)
    return -1;
  *out = (size_t) v;
  return 0;
}

int
bashsyslogd_builtin (WORD_LIST *list)
{
  const char *cmd = "run";
  const char *sock_path = "/dev/log";
  const char *log_path = "/var/log/messages";
  const char *syslog_path = NULL;
  const char *auth_path = NULL;
  const char *kern_path = NULL;
  const char *forward = NULL;
  const char *config_path = NULL;
  const char *queue_path = "/var/spool/bashsyslogd/forward.queue";
  char syslog_buf[512];
  char auth_buf[512];
  char kern_buf[512];
  mode_t mode = 0666;
  size_t queue_max_bytes = 262144;
  int once = 0;

  /* Pin LC_ALL=C so isspace() (bsd_trim) and the PRI / facility-name
   * comparisons stay byte-exact regardless of inherited LC_CTYPE.
   * Closes LOG-PARSER-AUDIT.md Wave 1 #6. */
  setlocale (LC_ALL, "C");

  if (list && list->word && list->word->word
      && (strcmp (list->word->word, "--help") == 0
          || strcmp (list->word->word, "-h") == 0))
    {
      builtin_usage ();
      return EXECUTION_SUCCESS;
    }
  if (list && list->word && list->word->word
      && strcmp (list->word->word, "--version") == 0)
    {
      puts ("bashsyslogd 1.0 (bash-loadable)");
      return EXECUTION_SUCCESS;
    }

  if (list && list->word && list->word->word
      && list->word->word[0] != '-')
    {
      cmd = list->word->word;
      list = list->next;
    }
  if (strcmp (cmd, "run") != 0)
    {
      builtin_error ("unknown verb: %s", cmd);
      return EX_USAGE;
    }

  for (WORD_LIST *p = list; p; p = p->next)
    {
      const char *w = p->word->word;
      if ((strcmp (w, "-s") == 0 || strcmp (w, "--socket") == 0) && p->next)
        {
          p = p->next;
          sock_path = p->word->word;
        }
      else if (strncmp (w, "--socket=", 9) == 0)
        sock_path = w + 9;
      else if ((strcmp (w, "-o") == 0 || strcmp (w, "--output") == 0) && p->next)
        {
          p = p->next;
          log_path = p->word->word;
        }
      else if (strncmp (w, "--output=", 9) == 0)
        log_path = w + 9;
      else if (strcmp (w, "--syslog") == 0 && p->next)
        {
          p = p->next;
          syslog_path = p->word->word;
        }
      else if (strncmp (w, "--syslog=", 9) == 0)
        syslog_path = w + 9;
      else if (strcmp (w, "--auth") == 0 && p->next)
        {
          p = p->next;
          auth_path = p->word->word;
        }
      else if (strncmp (w, "--auth=", 7) == 0)
        auth_path = w + 7;
      else if (strcmp (w, "--kern") == 0 && p->next)
        {
          p = p->next;
          kern_path = p->word->word;
        }
      else if (strncmp (w, "--kern=", 7) == 0)
        kern_path = w + 7;
      else if (strcmp (w, "--mode") == 0 && p->next)
        {
          p = p->next;
          if (bsd_parse_mode (p->word->word, &mode) < 0)
            { builtin_error ("bad --mode: %s", p->word->word); return EX_USAGE; }
        }
      else if (strncmp (w, "--mode=", 7) == 0)
        {
          if (bsd_parse_mode (w + 7, &mode) < 0)
            { builtin_error ("bad --mode: %s", w + 7); return EX_USAGE; }
        }
      else if (strcmp (w, "--forward") == 0 && p->next)
        {
          p = p->next;
          forward = p->word->word;
        }
      else if (strncmp (w, "--forward=", 10) == 0)
        forward = w + 10;
      else if (strcmp (w, "--config") == 0 && p->next)
        {
          p = p->next;
          config_path = p->word->word;
        }
      else if (strncmp (w, "--config=", 9) == 0)
        config_path = w + 9;
      else if (strcmp (w, "--queue") == 0 && p->next)
        {
          p = p->next;
          queue_path = p->word->word;
        }
      else if (strncmp (w, "--queue=", 8) == 0)
        queue_path = w + 8;
      else if (strcmp (w, "--queue-max-bytes") == 0 && p->next)
        {
          p = p->next;
          if (bsd_parse_size (p->word->word, &queue_max_bytes) < 0)
            { builtin_error ("bad --queue-max-bytes: %s", p->word->word); return EX_USAGE; }
        }
      else if (strncmp (w, "--queue-max-bytes=", 18) == 0)
        {
          if (bsd_parse_size (w + 18, &queue_max_bytes) < 0)
            { builtin_error ("bad --queue-max-bytes: %s", w + 18); return EX_USAGE; }
        }
      else if (strcmp (w, "--once") == 0)
        once = 1;
      else
        {
          builtin_error ("unknown flag: %s", w);
          return EX_USAGE;
        }
    }

  if (!syslog_path)
    {
      bsd_derive_stream_path (log_path, "syslog", syslog_buf, sizeof syslog_buf);
      syslog_path = syslog_buf;
    }
  if (!auth_path)
    {
      bsd_derive_stream_path (log_path, "auth.log", auth_buf, sizeof auth_buf);
      auth_path = auth_buf;
    }
  if (!kern_path)
    {
      bsd_derive_stream_path (log_path, "kern.log", kern_buf, sizeof kern_buf);
      kern_path = kern_buf;
    }

  return bsd_run (sock_path, log_path, mode, once, forward, syslog_path,
                  auth_path, kern_path, config_path, queue_path,
                  queue_max_bytes);
}

char *bashsyslogd_doc[] = {
  "Minimal /dev/log syslog receiver for bash-os.",
  "",
  "    bashsyslogd run [-s PATH] [-o FILE] [--syslog FILE] [--auth FILE] [--kern FILE] [--mode OCTAL] [--forward HOST:PORT] [--config FILE] [--queue FILE] [--queue-max-bytes N] [--once]",
  "    bashsyslogd --help | --version",
  "",
  "Binds an AF_UNIX SOCK_DGRAM socket (default /dev/log), appends",
  "received datagrams to FILE (default /var/log/messages), and routes",
  "<auth.*>/<authpriv.*>/<kern.*> facilities to auth.log/kern.log.",
  "Existing socket paths are replaced; non-socket paths are refused.",
  "--forward sends a best-effort UDP copy of each original datagram.",
  "SIGHUP reloads BASHSYSLOGD_FORWARD from --config FILE when set.",
  "Forwarding failures are spooled to a bounded hex queue and retried.",
  (char *) NULL
};

struct builtin bashsyslogd_struct = {
  "bashsyslogd",
  bashsyslogd_builtin,
  BUILTIN_ENABLED,
  bashsyslogd_doc,
  "bashsyslogd run [-s PATH] [-o FILE] [--syslog FILE] [--auth FILE] [--kern FILE] [--mode OCTAL] [--forward HOST:PORT] [--config FILE] [--queue FILE] [--queue-max-bytes N] [--once]",
  0
};
