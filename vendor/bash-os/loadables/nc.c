/* SPDX-License-Identifier: MIT */
/* nc.c — netcat scratch tool for bash-os (ML-T1-07).
 *
 * v1 verbs (operator-facing flags live in /bash-os/nc.sh):
 *   nc connect HOST PORT [-u] [-w SECS]
 *       TCP (default) or UDP client. After the connect, stdin and the
 *       socket are multiplexed via epoll: stdin → socket, socket →
 *       stdout. Closing stdin shuts the write half of the socket; an
 *       EOF/RDHUP on the socket ends the session.
 *
 *   nc listen PORT -s ADDR [-u] [-w SECS]
 *       TCP: bind + listen(1) + accept ONE peer, then multiplex.
 *       UDP: bind + recv datagrams to stdout. The first peer's source
 *       address is cached; stdin is sent back to that peer.
 *       v1 ALWAYS exits after the first connection (-k keep-listen is
 *       deferred). Listen mode requires explicit `-s ADDR`; there is no
 *       implicit wildcard or loopback bind.
 *
 *   nc scan HOST FIRST [LAST] [-w SECS]
 *       TCP `-z` port scan. Non-blocking connect against each port in
 *       [FIRST,LAST]; report one line per OPEN port (`PORT open`).
 *       Exits 0 iff at least one port was open. -w sets the per-port
 *       timeout (default 1s).
 *
 * Multiplexing: epoll(7). poll's listen FDVAR machinery binds an fd
 * into the caller's shell so bash arithmetic redirections can drive
 * it; we don't need that here because the whole transfer happens
 * inside this builtin's invocation. The epoll wiring is the same.
 *
 * Out of scope for v1 (the spec explicitly defers):
 *   -X SOCKS/HTTP proxy   - TLS    - -k keep-listen
 *   - broker / relay mode - named-pipe wiring
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as poll.c / strace.c.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "loadables.h"

#define BASHNC_VERSION "0.1 (TCP/UDP + -z scan; multiplex via epoll)"

#define BNC_IO_BUF 4096

/* Resolve "HOST" + "PORT" (string) into a single sockaddr_storage.
 * type is SOCK_STREAM or SOCK_DGRAM. passive=1 means AI_PASSIVE for
 * server bind.
 */
static int
bnc_resolve (const char *host, const char *port, int type, int passive,
             struct sockaddr_storage *out, socklen_t *outlen, int *family)
{
  struct addrinfo hints, *res = NULL;
  memset (&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = type;
  if (passive) hints.ai_flags = AI_PASSIVE;

  int gai = getaddrinfo (host, port, &hints, &res);
  if (gai != 0)
    {
      builtin_error ("getaddrinfo %s:%s: %s",
                     host ? host : "(null)", port, gai_strerror (gai));
      return -1;
    }
  memcpy (out, res->ai_addr, res->ai_addrlen);
  *outlen = res->ai_addrlen;
  *family = res->ai_family;
  freeaddrinfo (res);
  return 0;
}

/* Set O_NONBLOCK on a fd. Returns 0 on success, -1 on failure. */
static int
bnc_set_nonblock (int fd, int on)
{
  int flags = fcntl (fd, F_GETFL);
  if (flags < 0) return -1;
  if (on) flags |= O_NONBLOCK;
  else    flags &= ~O_NONBLOCK;
  return fcntl (fd, F_SETFL, flags);
}

/* Write a buffer to fd until done or a fatal error. Loops over EINTR
 * and short writes. Returns 0 on success, -1 on error (errno set). */
static int
bnc_write_all (int fd, const void *buf, size_t n)
{
  const unsigned char *p = buf;
  while (n > 0)
    {
      ssize_t w = write (fd, p, n);
      if (w < 0)
        {
          if (errno == EINTR) continue;
          return -1;
        }
      p += (size_t) w;
      n -= (size_t) w;
    }
  return 0;
}

/* TCP multiplex loop. Both halves are streamed bidirectionally:
 *   - stdin → sock (write half)
 *   - sock  → stdout (read half)
 * Closing stdin shuts the socket's write half via shutdown(SHUT_WR).
 * EOF or RDHUP on the socket ends the loop. */
static int
bnc_tcp_pump (int sock)
{
  int epfd = epoll_create1 (EPOLL_CLOEXEC);
  if (epfd < 0) { builtin_error ("epoll_create1: %s", strerror (errno)); return EXECUTION_FAILURE; }

  /* Register stdin (when it's a real fd). */
  int stdin_open = 1;
  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLLRDHUP;
  ev.data.fd = STDIN_FILENO;
  if (epoll_ctl (epfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev) < 0)
    {
      /* stdin may not be epoll-able (e.g. regular file) — treat as
       * already-readable: drain it in one shot below. */
      stdin_open = 0;
    }
  ev.events = EPOLLIN | EPOLLRDHUP;
  ev.data.fd = sock;
  if (epoll_ctl (epfd, EPOLL_CTL_ADD, sock, &ev) < 0)
    { builtin_error ("epoll_ctl sock: %s", strerror (errno)); close (epfd); return EXECUTION_FAILURE; }

  unsigned char buf[BNC_IO_BUF];

  /* If stdin isn't pollable, drain it up front before entering the
   * loop. This keeps `printf hi | nc connect ...` working when
   * stdin is a pipe-from-here-doc that's already EOF. */
  if (!stdin_open)
    {
      ssize_t n;
      while ((n = read (STDIN_FILENO, buf, sizeof buf)) > 0)
        {
          if (bnc_write_all (sock, buf, (size_t) n) < 0)
            { builtin_error ("write sock: %s", strerror (errno)); close (epfd); return EXECUTION_FAILURE; }
        }
      shutdown (sock, SHUT_WR);
    }

  int sock_open = 1;
  while (sock_open || stdin_open)
    {
      struct epoll_event ready[2];
      int n;
      do { n = epoll_wait (epfd, ready, 2, -1); }
      while (n < 0 && errno == EINTR);
      if (n < 0) { builtin_error ("epoll_wait: %s", strerror (errno)); close (epfd); return EXECUTION_FAILURE; }

      for (int i = 0; i < n; i++)
        {
          int fd = ready[i].data.fd;
          int events = ready[i].events;

          if (fd == STDIN_FILENO && stdin_open)
            {
              ssize_t r = read (STDIN_FILENO, buf, sizeof buf);
              if (r > 0)
                {
                  if (bnc_write_all (sock, buf, (size_t) r) < 0)
                    { builtin_error ("write sock: %s", strerror (errno)); close (epfd); return EXECUTION_FAILURE; }
                }
              else
                {
                  /* EOF or error on stdin. Close the write half so the
                   * peer sees an orderly shutdown. */
                  shutdown (sock, SHUT_WR);
                  epoll_ctl (epfd, EPOLL_CTL_DEL, STDIN_FILENO, NULL);
                  stdin_open = 0;
                }
              if ((events & (EPOLLHUP | EPOLLRDHUP)) && stdin_open)
                {
                  shutdown (sock, SHUT_WR);
                  epoll_ctl (epfd, EPOLL_CTL_DEL, STDIN_FILENO, NULL);
                  stdin_open = 0;
                }
            }
          else if (fd == sock && sock_open)
            {
              ssize_t r = read (sock, buf, sizeof buf);
              if (r > 0)
                {
                  if (bnc_write_all (STDOUT_FILENO, buf, (size_t) r) < 0)
                    { builtin_error ("write stdout: %s", strerror (errno)); close (epfd); return EXECUTION_FAILURE; }
                }
              else
                {
                  /* EOF or hup on socket. The session is over. */
                  epoll_ctl (epfd, EPOLL_CTL_DEL, sock, NULL);
                  sock_open = 0;
                }
            }
        }
    }
  close (epfd);
  return EXECUTION_SUCCESS;
}

/* UDP receive-then-respond loop. Once a peer is heard, stdin can be
 * pushed back. Exits when stdin closes AND no more datagrams arrive
 * within a short trailing window — for v1 we exit on first stdin EOF
 * after the first datagram, matching busybox nc semantics. */
static int
bnc_udp_pump (int sock, const struct sockaddr_storage *peer_in,
              socklen_t peer_in_len, int wait_secs)
{
  struct sockaddr_storage peer;
  socklen_t peerlen = 0;
  int have_peer = 0;
  if (peer_in)
    { memcpy (&peer, peer_in, peer_in_len); peerlen = peer_in_len; have_peer = 1; }

  int epfd = epoll_create1 (EPOLL_CLOEXEC);
  if (epfd < 0) { builtin_error ("epoll_create1: %s", strerror (errno)); return EXECUTION_FAILURE; }

  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLLRDHUP;
  ev.data.fd = sock;
  if (epoll_ctl (epfd, EPOLL_CTL_ADD, sock, &ev) < 0)
    { builtin_error ("epoll_ctl sock: %s", strerror (errno)); close (epfd); return EXECUTION_FAILURE; }
  int stdin_open = 1;
  ev.events = EPOLLIN | EPOLLRDHUP;
  ev.data.fd = STDIN_FILENO;
  if (epoll_ctl (epfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev) < 0)
    stdin_open = 0;

  /* Once stdin closes, give the socket up to after_eof_ms to surface
   * a trailing reply before exiting. UDP has no graceful FIN, so we
   * can't block forever; without this drain window a one-shot
   * `printf x | nc connect ... -u` would race ahead of the
   * server's response. -w SECS controls this drain; the default matches
   * the original busybox/toybox-style one-shot behavior. */
  int after_eof_ms = wait_secs > 0 ? wait_secs * 1000 : 1000;

  unsigned char buf[BNC_IO_BUF];
  if (!stdin_open)
    {
      while (1)
        {
          ssize_t r = read (STDIN_FILENO, buf, sizeof buf);
          if (r > 0)
            {
              if (have_peer)
                {
                  ssize_t w = sendto (sock, buf, (size_t) r, 0,
                                      (struct sockaddr *) &peer, peerlen);
                  if (w < 0)
                    { builtin_error ("sendto: %s", strerror (errno)); close (epfd); return EXECUTION_FAILURE; }
                }
              continue;
            }
          if (r < 0 && errno == EINTR)
            continue;
          if (r < 0)
            { builtin_error ("read stdin: %s", strerror (errno)); close (epfd); return EXECUTION_FAILURE; }
          break;
        }
    }

  while (1)
    {
      struct epoll_event ready[2];
      int timeout = stdin_open ? -1 : after_eof_ms;
      int n;
      do { n = epoll_wait (epfd, ready, 2, timeout); }
      while (n < 0 && errno == EINTR);
      if (n < 0) { builtin_error ("epoll_wait: %s", strerror (errno)); close (epfd); return EXECUTION_FAILURE; }
      if (n == 0) break;        /* drain window elapsed (stdin already closed) */

      for (int i = 0; i < n; i++)
        {
          int fd = ready[i].data.fd;
          if (fd == sock)
            {
              struct sockaddr_storage src;
              socklen_t srclen = sizeof src;
              ssize_t r = recvfrom (sock, buf, sizeof buf, 0,
                                    (struct sockaddr *) &src, &srclen);
              if (r < 0)
                { if (errno == EINTR) continue;
                  builtin_error ("recvfrom: %s", strerror (errno)); close (epfd); return EXECUTION_FAILURE; }
              if (!have_peer)
                { memcpy (&peer, &src, srclen); peerlen = srclen; have_peer = 1; }
              if (r > 0)
                if (bnc_write_all (STDOUT_FILENO, buf, (size_t) r) < 0)
                  { builtin_error ("write stdout: %s", strerror (errno)); close (epfd); return EXECUTION_FAILURE; }
            }
          else if (fd == STDIN_FILENO && stdin_open)
            {
              ssize_t r = read (STDIN_FILENO, buf, sizeof buf);
              if (r < 0 && errno == EINTR)
                continue;
              if (r > 0 && have_peer)
                {
                  ssize_t w = sendto (sock, buf, (size_t) r, 0,
                                      (struct sockaddr *) &peer, peerlen);
                  if (w < 0)
                    { builtin_error ("sendto: %s", strerror (errno)); close (epfd); return EXECUTION_FAILURE; }
                }
              else if (r <= 0)
                {
                  /* Drop stdin from epoll; flip to drain-window mode.
                   * Don't exit yet — let the server's reply land. */
                  epoll_ctl (epfd, EPOLL_CTL_DEL, STDIN_FILENO, NULL);
                  stdin_open = 0;
                }
            }
        }
    }
  close (epfd);
  return EXECUTION_SUCCESS;
}

/* `nc connect HOST PORT [-u] [-w SECS]` */
static int
bnc_connect (WORD_LIST *args)
{
  const char *host = NULL;
  const char *port = NULL;
  int udp = 0;
  int wait_secs = 0;          /* 0 = unset; only used for UDP peer-wait */
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-u") == 0) udp = 1;
      else if (strcmp (w, "-w") == 0)
        { if (!p->next) { builtin_error ("-w needs SECS"); return EX_USAGE; }
          p = p->next; wait_secs = atoi (p->word->word); }
      else if (!host) host = w;
      else if (!port) port = w;
      else { builtin_error ("connect: extra arg %s", w); return EX_USAGE; }
    }
  if (!host || !port) { builtin_error ("connect needs HOST PORT [-u] [-w SECS]"); return EX_USAGE; }

  struct sockaddr_storage ss;
  socklen_t sl;
  int fam;
  int sktype = udp ? SOCK_DGRAM : SOCK_STREAM;
  if (bnc_resolve (host, port, sktype, /*passive*/ 0, &ss, &sl, &fam) < 0)
    return EXECUTION_FAILURE;

  int fd = socket (fam, sktype | SOCK_CLOEXEC, 0);
  if (fd < 0) { builtin_error ("socket: %s", strerror (errno)); return EXECUTION_FAILURE; }

  if (wait_secs > 0)
    {
      struct timeval tv = { .tv_sec = wait_secs, .tv_usec = 0 };
      if (setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) < 0)
        builtin_warning ("setsockopt SO_SNDTIMEO: %s", strerror (errno));
      if (setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) < 0)
        builtin_warning ("setsockopt SO_RCVTIMEO: %s", strerror (errno));
    }

  if (!udp)
    {
      if (connect (fd, (struct sockaddr *) &ss, sl) < 0)
        { builtin_error ("connect %s:%s: %s", host, port, strerror (errno));
          close (fd); return EXECUTION_FAILURE; }
      int rc = bnc_tcp_pump (fd);
      close (fd);
      return rc;
    }
  else
    {
      /* UDP "connect" is a sendto-target pin. We don't call connect(2)
       * because that would lock out unsolicited replies. Instead pass
       * the peer addr into the UDP pump. */
      int rc = bnc_udp_pump (fd, &ss, sl, wait_secs);
      close (fd);
      return rc;
    }
}

/* `nc listen PORT -s ADDR [-u] [-w SECS]` */
static int
bnc_listen (WORD_LIST *args)
{
  const char *port = NULL;
  const char *addr = NULL;
  int udp = 0;
  int wait_secs = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-u") == 0) udp = 1;
      else if (strcmp (w, "-s") == 0 || strcmp (w, "-a") == 0)
        { if (!p->next || p->next->word->word[0] == '-')
            { builtin_error ("%s needs ADDR", w); return EX_USAGE; }
          p = p->next; addr = p->word->word; }
      else if (strcmp (w, "-w") == 0)
        { if (!p->next) { builtin_error ("-w needs SECS"); return EX_USAGE; }
          p = p->next; wait_secs = atoi (p->word->word); }
      else if (!port) port = w;
      else { builtin_error ("listen: extra arg %s", w); return EX_USAGE; }
    }
  if (!port) { builtin_error ("listen needs PORT -s ADDR [-u] [-w SECS]"); return EX_USAGE; }
  if (!addr) { builtin_error ("listen needs explicit -s ADDR"); return EX_USAGE; }

  struct sockaddr_storage ss;
  socklen_t sl;
  int fam;
  int sktype = udp ? SOCK_DGRAM : SOCK_STREAM;
  if (bnc_resolve (addr, port, sktype, /*passive*/ 1, &ss, &sl, &fam) < 0)
    return EXECUTION_FAILURE;

  int fd = socket (fam, sktype | SOCK_CLOEXEC, 0);
  if (fd < 0) { builtin_error ("socket: %s", strerror (errno)); return EXECUTION_FAILURE; }
  int yes = 1;
  if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) < 0)
    builtin_warning ("setsockopt SO_REUSEADDR: %s", strerror (errno));

  if (wait_secs > 0)
    {
      struct timeval tv = { .tv_sec = wait_secs, .tv_usec = 0 };
      if (setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) < 0)
        builtin_warning ("setsockopt SO_RCVTIMEO: %s", strerror (errno));
    }

  if (bind (fd, (struct sockaddr *) &ss, sl) < 0)
    { builtin_error ("bind %s:%s: %s", addr, port, strerror (errno));
      close (fd); return EXECUTION_FAILURE; }

  if (!udp)
    {
      if (listen (fd, 1) < 0)
        { builtin_error ("listen: %s", strerror (errno)); close (fd); return EXECUTION_FAILURE; }
      int cfd;
      do { cfd = accept4 (fd, NULL, NULL, SOCK_CLOEXEC); }
      while (cfd < 0 && errno == EINTR);
      close (fd);                /* listener no longer needed for v1 */
      if (cfd < 0) { builtin_error ("accept: %s", strerror (errno)); return EXECUTION_FAILURE; }
      int rc = bnc_tcp_pump (cfd);
      close (cfd);
      return rc;
    }
  else
    {
      int rc = bnc_udp_pump (fd, NULL, 0, wait_secs);
      close (fd);
      return rc;
    }
}

/* Non-blocking TCP probe for one port. Returns 1 if open, 0 if
 * closed/timeout, -1 on hard error. Uses a fresh socket per port. */
static int
bnc_probe_port (const char *host, int port, int wait_secs)
{
  char portstr[8];
  snprintf (portstr, sizeof portstr, "%d", port);
  struct sockaddr_storage ss;
  socklen_t sl;
  int fam;
  if (bnc_resolve (host, portstr, SOCK_STREAM, 0, &ss, &sl, &fam) < 0)
    return -1;
  int fd = socket (fam, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  if (bnc_set_nonblock (fd, 1) < 0) { close (fd); return -1; }

  int rc = connect (fd, (struct sockaddr *) &ss, sl);
  if (rc == 0) { close (fd); return 1; }              /* immediate connect (loopback fast path) */
  if (errno != EINPROGRESS) { close (fd); return 0; }

  /* Wait for writability with timeout — that's how non-blocking
   * connect signals completion. Then check SO_ERROR. */
  int epfd = epoll_create1 (EPOLL_CLOEXEC);
  if (epfd < 0) { close (fd); return -1; }
  struct epoll_event ev = { .events = EPOLLOUT, .data.fd = fd };
  if (epoll_ctl (epfd, EPOLL_CTL_ADD, fd, &ev) < 0) { close (epfd); close (fd); return -1; }
  struct epoll_event ready[1];
  int timeout_ms = (wait_secs > 0 ? wait_secs : 1) * 1000;
  int n;
  do { n = epoll_wait (epfd, ready, 1, timeout_ms); }
  while (n < 0 && errno == EINTR);
  close (epfd);
  if (n <= 0) { close (fd); return 0; }              /* timeout or error */

  int err = 0;
  socklen_t errlen = sizeof err;
  if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0)
    { close (fd); return -1; }
  close (fd);
  return err == 0 ? 1 : 0;
}

/* `nc scan HOST FIRST [LAST] [-w SECS]` */
static int
bnc_scan (WORD_LIST *args)
{
  const char *host = NULL;
  int first = -1, last = -1;
  int wait_secs = 1;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-w") == 0)
        { if (!p->next) { builtin_error ("-w needs SECS"); return EX_USAGE; }
          p = p->next; wait_secs = atoi (p->word->word); }
      else if (!host) host = w;
      else if (first < 0) first = atoi (w);
      else if (last  < 0) last  = atoi (w);
      else { builtin_error ("scan: extra arg %s", w); return EX_USAGE; }
    }
  if (!host || first < 0)
    { builtin_error ("scan needs HOST FIRST [LAST] [-w SECS]"); return EX_USAGE; }
  if (last < 0) last = first;
  if (last < first)
    { builtin_error ("scan: LAST < FIRST"); return EX_USAGE; }
  if (first < 1 || last > 65535)
    { builtin_error ("scan: port range out of bounds"); return EX_USAGE; }

  int any_open = 0;
  for (int p = first; p <= last; p++)
    {
      int got = bnc_probe_port (host, p, wait_secs);
      if (got == 1)
        { printf ("%d open\n", p); any_open = 1; }
    }
  fflush (stdout);
  return any_open ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bnc_version (void)
{
  printf ("nc %s\n", BASHNC_VERSION);
  return EXECUTION_SUCCESS;
}

int
nc_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;
  if (strcmp (cmd, "--version") == 0) return bnc_version ();
  if (strcmp (cmd, "connect")   == 0) return bnc_connect (args);
  if (strcmp (cmd, "listen")    == 0) return bnc_listen  (args);
  if (strcmp (cmd, "scan")      == 0) return bnc_scan    (args);
  builtin_error ("unknown verb: %s", cmd);
  return EX_USAGE;
}

char *nc_doc[] = {
  "Netcat-style TCP/UDP scratch tool (subset).",
  "",
  "    nc connect HOST PORT [-u] [-w SECS]   TCP/UDP client",
  "    nc listen  PORT -s ADDR [-u] [-w SECS]   bind + accept-one (TCP) / recv (UDP)",
  "    nc scan    HOST FIRST [LAST] [-w SECS]   -z TCP port scan",
  "    nc --version",
  "",
  "Multiplexes stdin and the socket via epoll(7). Listen mode requires",
  "explicit `-s ADDR`; use `-s 127.0.0.1` for loopback or `-s 0.0.0.0`",
  "to expose externally. v1 always exits after the first connection (no -k);",
  "SOCKS proxy, TLS, broker mode, and named-pipe wiring are deferred.",
  (char *) NULL
};

struct builtin nc_struct = {
  "nc",
  nc_builtin,
  BUILTIN_ENABLED,
  nc_doc,
  "nc connect|listen|scan|--version ARGS...",
  0
};
