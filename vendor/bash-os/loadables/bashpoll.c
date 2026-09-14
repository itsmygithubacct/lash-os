/* bashpoll.c — multiplexed I/O via epoll(7). Loadable for bash.
 *
 * /dev/tcp/HOST/PORT opens one connection. Bash has no listen/accept,
 * no way to wait on multiple FDs simultaneously. Servers in pure bash
 * either fork-per-client (high cost) or busy-poll with `read -t 0.001`.
 *
 * bashpoll fixes that:
 *   - listen / listen-unix open server sockets, return the fd via FDVAR
 *     (same pattern as bashio open — fd lives in the bash process)
 *   - accept blocks for a client, returns its fd
 *   - connect: outbound TCP without /dev/tcp's path-search overhead
 *   - wait: epoll_wait, prints "FD EVENT[,EVENT]..." per ready fd
 *   - eventfd / signalfd: cross-thread signaling (signalfd lets bash
 *     handle SIGINT in the wait loop without trap glue)
 *
 * Subcommands:
 *   bashpoll listen ADDR:PORT [-q BACKLOG] FDVAR
 *   bashpoll listen-unix /path/sock FDVAR
 *   bashpoll accept LISTEN_FD FDVAR
 *   bashpoll connect HOST:PORT [FDVAR] [-t TIMEOUT_MS]
 *   bashpoll wait [-t TIMEOUT_MS] FD...
 *   bashpoll close FD
 *   bashpoll set-nonblock FD on|off
 *   bashpoll signalfd SIG... FDVAR
 *
 * Companion docs:
 *     /docs/bash/bashpoll.txt
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
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <poll.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "loadables.h"
#include "trap.h"

struct bp_signal_fd {
  int fd;
  sigset_t mask;
  struct bp_signal_fd *next;
};
static struct bp_signal_fd *bp_signal_fds;
static unsigned bp_signal_refs[NSIG];
static unsigned char bp_signal_owned[NSIG];

/* A signal is unblocked only after its last managed signalfd closes, and
   only if this module originally blocked it. Never restore an entire old
   mask: unrelated users may have changed their own bits in the meantime. */
static void
bp_release_signal_fd (struct bp_signal_fd **slot, int close_fd)
{
  struct bp_signal_fd *entry = *slot;
  sigset_t unblock;
  sigemptyset (&unblock);
  *slot = entry->next;
  if (close_fd) close (entry->fd);
  for (int sig = 1; sig < NSIG; sig++)
    if (sigismember (&entry->mask, sig) == 1 && --bp_signal_refs[sig] == 0)
      {
        if (bp_signal_owned[sig]) sigaddset (&unblock, sig);
        bp_signal_owned[sig] = 0;
      }
  free (entry);
  sigprocmask (SIG_UNBLOCK, &unblock, NULL);
}

void
bashpoll_builtin_unload (char *name)
{
  (void) name;
  while (bp_signal_fds) bp_release_signal_fd (&bp_signal_fds, 1);
}

static int
bp_fd_variable_ok (const char *name)
{
  const char *target = name;
  for (int depth = 0; depth < 64; depth++)
    {
      if (!target || !legal_identifier (target)) break;
      SHELL_VAR *v = find_variable_noref (target);
      if (v && (readonly_p (v) || noassign_p (v) || array_p (v) ||
                assoc_p (v) || v->dynamic_value || v->assign_func)) break;
      if (v && nameref_p (v)) { target = nameref_cell (v); continue; }
      return 1;
    }
  builtin_error ("fd variable must be a writable scalar: %s", name);
  return 0;
}

/* Helper: bind FDVAR to fd in caller's shell, OR print to stdout
   (latter is only useful for one-shot subshell consumers). On bind-variable
   failure (bad name), closes the fd and returns -1 to avoid leaking it
   into the caller's shell. */
static int
bp_emit_fd (int fd, const char *fdvar)
{
  if (fdvar)
    {
      char buf[32];
      if (!bp_fd_variable_ok (fdvar)) { close (fd); return -1; }
      snprintf (buf, sizeof buf, "%d", fd);
      SHELL_VAR *v = builtin_bind_variable ((char *) fdvar, buf, 0);
      if (!v || readonly_p (v) || noassign_p (v))
        {
          builtin_error ("could not set variable: %s", fdvar);
          close (fd);
          return -1;
        }
    }
  else
    printf ("%d\n", fd);
  return 0;
}

/* Parse "ADDR:PORT" or "[v6]:PORT" or "PORT" alone. ADDR may be a
   hostname; resolved via getaddrinfo. Returns 0 on success, -1 on
   error (with builtin_error already called). */
static int
bp_parse_addr (const char *spec, struct sockaddr_storage *out, socklen_t *outlen, int passive)
{
  char host[256] = "0.0.0.0";
  char port[16] = "";
  const char *p;
  if (spec[0] == '[')
    {
      const char *end = strchr (spec, ']');
      if (!end || end[1] != ':') { builtin_error ("bad addr: %s", spec); return -1; }
      size_t hl = end - spec - 1;
      if (hl >= sizeof host) { builtin_error ("host too long"); return -1; }
      memcpy (host, spec + 1, hl); host[hl] = '\0';
      strncpy (port, end + 2, sizeof port - 1);
      port[sizeof port - 1] = '\0';
    }
  else if ((p = strchr (spec, ':')) != NULL)
    {
      size_t hl = p - spec;
      if (hl == 0 && passive)
        strcpy (host, "0.0.0.0");
      else if (hl >= sizeof host)
        { builtin_error ("host too long"); return -1; }
      else
        { memcpy (host, spec, hl); host[hl] = '\0'; }
      strncpy (port, p + 1, sizeof port - 1);
      port[sizeof port - 1] = '\0';
    }
  else
    {
      /* Just a port number. */
      strncpy (port, spec, sizeof port - 1);
      port[sizeof port - 1] = '\0';
    }
  if (!port[0]) { builtin_error ("missing port"); return -1; }

  struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
  if (passive) hints.ai_flags = AI_PASSIVE;
  struct addrinfo *res = NULL;
  int gai = getaddrinfo (host, port, &hints, &res);
  if (gai != 0)
    { builtin_error ("getaddrinfo %s:%s: %s", host, port, gai_strerror (gai)); return -1; }
  /* First result wins. */
  memcpy (out, res->ai_addr, res->ai_addrlen);
  *outlen = res->ai_addrlen;
  freeaddrinfo (res);
  return 0;
}

static int
bp_listen (WORD_LIST *args)
{
  const char *addr = NULL, *fdvar = NULL;
  int backlog = 16;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-q") == 0)
        { if (!p->next) { builtin_error ("-q needs BACKLOG"); return EX_USAGE; }
          p = p->next; backlog = atoi (p->word->word); }
      else if (!addr) addr = w;
      else if (!fdvar) fdvar = w;
      else { builtin_error ("listen: extra arg %s", w); return EX_USAGE; }
    }
  if (!addr) { builtin_error ("listen needs ADDR:PORT [FDVAR]"); return EX_USAGE; }

  struct sockaddr_storage ss;
  socklen_t sl;
  if (bp_parse_addr (addr, &ss, &sl, /*passive*/ 1) < 0) return EX_USAGE;
  int fd = socket (ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) { builtin_error ("socket: %s", strerror (errno)); return EXECUTION_FAILURE; }
  int yes = 1;
  if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) < 0)
    builtin_warning ("setsockopt SO_REUSEADDR: %s", strerror (errno));
  if (bind (fd, (struct sockaddr *) &ss, sl) < 0)
    { builtin_error ("bind: %s", strerror (errno)); close (fd); return EXECUTION_FAILURE; }
  if (listen (fd, backlog) < 0)
    { builtin_error ("listen: %s", strerror (errno)); close (fd); return EXECUTION_FAILURE; }
  return bp_emit_fd (fd, fdvar) < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
bp_listen_unix (WORD_LIST *args)
{
  const char *path = NULL, *fdvar = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    if (!path) path = p->word->word;
    else if (!fdvar) fdvar = p->word->word;
    else { builtin_error ("listen-unix: extra arg %s", p->word->word); return EX_USAGE; }
  if (!path) { builtin_error ("listen-unix needs /path/sock [FDVAR]"); return EX_USAGE; }
  if (strlen (path) >= sizeof (((struct sockaddr_un *) 0)->sun_path))
    { builtin_error ("path too long for AF_UNIX"); return EX_USAGE; }

  int fd = socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) { builtin_error ("socket: %s", strerror (errno)); return EXECUTION_FAILURE; }
  struct sockaddr_un sa = { .sun_family = AF_UNIX };
  strcpy (sa.sun_path, path);
  /* Safe stale-socket removal (security review 2026-05-07 #1):
   * lstat → accept missing, accept S_IFSOCK, refuse everything else.
   * Prevents a builtin call with attacker-supplied path from deleting
   * arbitrary filesystem entries. */
  {
    struct stat st;
    if (lstat (path, &st) == 0) {
      if (!S_ISSOCK (st.st_mode)) {
        builtin_error ("listen-unix: refusing to unlink non-socket %s "
                       "(mode=0%o)", path, (unsigned) (st.st_mode & 07777));
        close (fd); return EXECUTION_FAILURE;
      }
      if (unlink (path) < 0 && errno != ENOENT) {
        builtin_error ("listen-unix: unlink %s: %s", path, strerror (errno));
        close (fd); return EXECUTION_FAILURE;
      }
    } else if (errno != ENOENT) {
      builtin_error ("listen-unix: lstat %s: %s", path, strerror (errno));
      close (fd); return EXECUTION_FAILURE;
    }
  }
  if (bind (fd, (struct sockaddr *) &sa, sizeof sa) < 0)
    { builtin_error ("bind %s: %s", path, strerror (errno)); close (fd); return EXECUTION_FAILURE; }
  if (listen (fd, 16) < 0)
    { builtin_error ("listen: %s", strerror (errno)); close (fd); return EXECUTION_FAILURE; }
  return bp_emit_fd (fd, fdvar) < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
bp_accept (WORD_LIST *args)
{
  if (!args) { builtin_error ("accept needs LISTEN_FD [FDVAR]"); return EX_USAGE; }
  int lfd = atoi (args->word->word);
  const char *fdvar = (args->next) ? args->next->word->word : NULL;
  int cfd;
  do { cfd = accept4 (lfd, NULL, NULL, SOCK_CLOEXEC); }
  while (cfd < 0 && errno == EINTR);
  if (cfd < 0) { builtin_error ("accept: %s", strerror (errno)); return EXECUTION_FAILURE; }
  return bp_emit_fd (cfd, fdvar) < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
bp_connect (WORD_LIST *args)
{
  const char *addr = NULL, *fdvar = NULL;
  int timeout_ms = -1;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-t") == 0)
        {
          if (!p->next) { builtin_error ("-t needs MS"); return EX_USAGE; }
          p = p->next;
          timeout_ms = atoi (p->word->word);
        }
      else if (!addr)
        addr = w;
      else if (!fdvar)
        fdvar = w;
      else
        { builtin_error ("connect: extra arg %s", w); return EX_USAGE; }
    }
  if (!addr) { builtin_error ("connect needs HOST:PORT [FDVAR] [-t MS]"); return EX_USAGE; }

  struct sockaddr_storage ss;
  socklen_t sl;
  if (bp_parse_addr (addr, &ss, &sl, /*passive*/ 0) < 0) return EX_USAGE;
  int fd = socket (ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) { builtin_error ("socket: %s", strerror (errno)); return EXECUTION_FAILURE; }

  if (timeout_ms < 0)
    {
      if (connect (fd, (struct sockaddr *) &ss, sl) < 0)
        { builtin_error ("connect %s: %s", addr, strerror (errno)); close (fd); return EXECUTION_FAILURE; }
    }
  else
    {
      int flags = fcntl (fd, F_GETFL);
      if (flags < 0)
        { builtin_error ("fcntl GETFL: %s", strerror (errno)); close (fd); return EXECUTION_FAILURE; }
      if (fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0)
        { builtin_error ("fcntl SETFL: %s", strerror (errno)); close (fd); return EXECUTION_FAILURE; }

      int rc = connect (fd, (struct sockaddr *) &ss, sl);
      if (rc < 0 && errno != EINPROGRESS)
        { builtin_error ("connect %s: %s", addr, strerror (errno)); close (fd); return EXECUTION_FAILURE; }
      if (rc < 0)
        {
          struct pollfd pfd = { .fd = fd, .events = POLLOUT };
          int n;
          do { n = poll (&pfd, 1, timeout_ms); }
          while (n < 0 && errno == EINTR);
          if (n < 0)
            { builtin_error ("connect %s: poll: %s", addr, strerror (errno)); close (fd); return EXECUTION_FAILURE; }
          if (n == 0)
            { builtin_error ("connect %s: %s", addr, strerror (ETIMEDOUT)); close (fd); return EXECUTION_FAILURE; }

          int soerr = 0;
          socklen_t elen = sizeof soerr;
          if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &soerr, &elen) < 0)
            { builtin_error ("connect %s: getsockopt SO_ERROR: %s", addr, strerror (errno)); close (fd); return EXECUTION_FAILURE; }
          if (soerr != 0)
            { builtin_error ("connect %s: %s", addr, strerror (soerr)); close (fd); return EXECUTION_FAILURE; }
        }

      if (fcntl (fd, F_SETFL, flags) < 0)
        { builtin_error ("fcntl SETFL restore: %s", strerror (errno)); close (fd); return EXECUTION_FAILURE; }
    }

  return bp_emit_fd (fd, fdvar) < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
bp_wait (WORD_LIST *args)
{
  int timeout_ms = -1;
  struct bp_interest { int fd; unsigned events; };
  /* A bare FD keeps read readiness; FD:read,write explicitly opts in to
     writable wakeups, which are usually continuous on idle sockets. */
  size_t fds_capacity = 16, n_fds = 0;
  struct bp_interest *fds = malloc (sizeof *fds * fds_capacity);
  if (!fds) { builtin_error ("malloc: %s", strerror (errno)); return EXECUTION_FAILURE; }
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-t") == 0)
        { if (!p->next) { free (fds); builtin_error ("-t needs MS"); return EX_USAGE; }
          p = p->next;
          char *end;
          errno = 0;
          long ms = strtol (p->word->word, &end, 10);
          if (errno || !*p->word->word || *end || ms < -1 || ms > INT_MAX)
            { free (fds); builtin_error ("wait: invalid timeout: %s", p->word->word); return EX_USAGE; }
          timeout_ms = (int) ms; }
      else
        {
          char *end;
          errno = 0;
          long fd = strtol (w, &end, 10);
          unsigned events = EPOLLIN | EPOLLPRI | EPOLLRDHUP;
          if (errno || end == w || fd < 0 || fd > INT_MAX || (*end && *end != ':'))
            { free (fds); builtin_error ("wait: invalid FD: %s", w); return EX_USAGE; }
          if (*end == ':')
            {
              if (strcmp (end + 1, "read") == 0) events = EPOLLIN | EPOLLPRI | EPOLLRDHUP;
              else if (strcmp (end + 1, "write") == 0) events = EPOLLOUT | EPOLLRDHUP;
              else if (strcmp (end + 1, "read,write") == 0 || strcmp (end + 1, "write,read") == 0)
                events |= EPOLLOUT;
              else { free (fds); builtin_error ("wait: expected FD:read, FD:write or FD:read,write"); return EX_USAGE; }
            }
          if (n_fds == fds_capacity)
            {
              size_t nc = fds_capacity * 2;
              struct bp_interest *tmp = realloc (fds, sizeof *fds * nc);
              if (!tmp) { free (fds); builtin_error ("realloc: %s", strerror (errno)); return EXECUTION_FAILURE; }
              fds = tmp; fds_capacity = nc;
            }
          fds[n_fds++] = (struct bp_interest) { .fd = (int) fd, .events = events };
        }
    }
  if (n_fds == 0)
    { free (fds); builtin_error ("wait needs at least one FD"); return EX_USAGE; }

  int epfd = epoll_create1 (EPOLL_CLOEXEC);
  if (epfd < 0)
    { free (fds); builtin_error ("epoll_create1: %s", strerror (errno)); return EXECUTION_FAILURE; }
  for (size_t i = 0; i < n_fds; i++)
    {
      struct epoll_event ev = { .events = fds[i].events, .data.fd = fds[i].fd };
      if (epoll_ctl (epfd, EPOLL_CTL_ADD, fds[i].fd, &ev) < 0)
        {
          builtin_error ("epoll_ctl ADD fd %d: %s", fds[i].fd, strerror (errno));
          close (epfd); free (fds);
          return EXECUTION_FAILURE;
        }
    }

  struct epoll_event revents[64];
  int n;
  do { n = epoll_wait (epfd, revents, 64, timeout_ms); }
  while (n < 0 && errno == EINTR);
  if (n < 0)
    { builtin_error ("epoll_wait: %s", strerror (errno)); close (epfd); free (fds); return EXECUTION_FAILURE; }

  for (int i = 0; i < n; i++)
    {
      printf ("%d ", revents[i].data.fd);
      int first = 1;
      if (revents[i].events & EPOLLIN)     { fputs (first ? "readable" : ",readable", stdout); first = 0; }
      if (revents[i].events & EPOLLOUT)    { fputs (first ? "writable" : ",writable", stdout); first = 0; }
      if (revents[i].events & EPOLLPRI)    { fputs (first ? "pri"      : ",pri"     , stdout); first = 0; }
      if (revents[i].events & EPOLLHUP)    { fputs (first ? "hup"      : ",hup"     , stdout); first = 0; }
      if (revents[i].events & EPOLLRDHUP)  { fputs (first ? "rdhup"    : ",rdhup"   , stdout); first = 0; }
      if (revents[i].events & EPOLLERR)    { fputs (first ? "error"    : ",error"   , stdout); first = 0; }
      if (first) fputs ("none", stdout);
      putchar ('\n');
    }
  fflush (stdout);
  close (epfd);
  free (fds);
  /* Return success even on timeout (caller checks output for fired fds). */
  return EXECUTION_SUCCESS;
}

static int
bp_close (WORD_LIST *args)
{
  if (!args || args->next) { builtin_error ("close: needs FD"); return EX_USAGE; }
  char *end;
  errno = 0;
  long number = strtol (args->word->word, &end, 10);
  if (errno || !*args->word->word || *end || number < 0 || number > INT_MAX)
    { builtin_error ("close: invalid FD: %s", args->word->word); return EX_USAGE; }
  int fd = (int) number;
  struct bp_signal_fd **slot = &bp_signal_fds;
  while (*slot && (*slot)->fd != fd) slot = &(*slot)->next;
  int rc = close (fd), saved = errno;
  if (*slot) bp_release_signal_fd (slot, 0);
  if (rc < 0) { builtin_error ("close: %s", strerror (saved)); return EXECUTION_FAILURE; }
  return EXECUTION_SUCCESS;
}

static int
bp_set_nonblock (WORD_LIST *args)
{
  if (!args || !args->next) { builtin_error ("set-nonblock: needs FD on|off"); return EX_USAGE; }
  int fd = atoi (args->word->word);
  int on = strcmp (args->next->word->word, "on") == 0;
  int flags = fcntl (fd, F_GETFL);
  if (flags < 0) { builtin_error ("fcntl GETFL: %s", strerror (errno)); return EXECUTION_FAILURE; }
  if (on) flags |= O_NONBLOCK;
  else    flags &= ~O_NONBLOCK;
  if (fcntl (fd, F_SETFL, flags) < 0)
    { builtin_error ("fcntl SETFL: %s", strerror (errno)); return EXECUTION_FAILURE; }
  return EXECUTION_SUCCESS;
}

/* listen-udp ADDR:PORT [-i IFACE] [FDVAR] — bind a SOCK_DGRAM socket.
 * SO_REUSEADDR is set so the DHCP client can co-bind a server's :67
 * replies on the same host. SO_BROADCAST is enabled so subsequent
 * recvfrom() picks up broadcast traffic at the bound address.
 *
 * Stage 30.A: -i IFACE pins the listener to a single interface via
 * SO_BINDTODEVICE — listening on 0.0.0.0:PORT without -i accepts
 * datagrams from EVERY iface, including external NICs. With `-i lo`
 * only loopback traffic reaches the socket. Privileged ports (< 1024)
 * with no -i emit a stderr warning since the security default is
 * "loopback only" for unsandboxed listeners.
 */
static int
bp_listen_udp (WORD_LIST *args)
{
  const char *addr = NULL, *fdvar = NULL, *iface = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-i") == 0)
        {
          if (!p->next) { builtin_error ("listen-udp: -i needs IFACE"); return EX_USAGE; }
          p = p->next;
          iface = p->word->word;
        }
      else if (!addr) addr = w;
      else if (!fdvar) fdvar = w;
      else { builtin_error ("listen-udp: extra arg %s", w); return EX_USAGE; }
    }
  if (!addr) { builtin_error ("listen-udp needs ADDR:PORT [-i IFACE] [FDVAR]"); return EX_USAGE; }

  struct sockaddr_storage ss;
  socklen_t sl;
  if (bp_parse_addr (addr, &ss, &sl, /*passive*/ 1) < 0) return EX_USAGE;

  /* Pull the port out for the privileged-port warning below. ss is
     a sockaddr_storage; the port is at the same offset for AF_INET
     (sockaddr_in.sin_port) and AF_INET6 (sockaddr_in6.sin6_port). */
  unsigned short port = 0;
  if (ss.ss_family == AF_INET)
    port = ntohs (((struct sockaddr_in *) &ss)->sin_port);
  else if (ss.ss_family == AF_INET6)
    port = ntohs (((struct sockaddr_in6 *) &ss)->sin6_port);

  int fd = socket (ss.ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) { builtin_error ("socket: %s", strerror (errno)); return EXECUTION_FAILURE; }
  int yes = 1;
  if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) < 0)
    builtin_warning ("setsockopt SO_REUSEADDR: %s", strerror (errno));
  if (setsockopt (fd, SOL_SOCKET, SO_BROADCAST, &yes, sizeof yes) < 0)
    builtin_warning ("setsockopt SO_BROADCAST: %s", strerror (errno));
  if (iface)
    {
      if (setsockopt (fd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen (iface)) < 0)
        {
          builtin_error ("setsockopt SO_BINDTODEVICE %s: %s",
                         iface, strerror (errno));
          close (fd);
          return EXECUTION_FAILURE;
        }
    }
  else if (port > 0 && port < 1024)
    {
      fprintf (stderr,
               "bashpoll listen-udp: warning: bound to *:%u with no -i — "
               "listener is global. Use `-i lo` for local-only services.\n",
               port);
    }
  if (bind (fd, (struct sockaddr *) &ss, sl) < 0)
    { builtin_error ("bind: %s", strerror (errno)); close (fd); return EXECUTION_FAILURE; }
  return bp_emit_fd (fd, fdvar) < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

/* send-udp HOST:PORT [-b] [-i IFACE] [-F FD] [--from ADDR:PORT|--from-port PORT] — write all
 * of stdin to HOST:PORT via SOCK_DGRAM.
 *   --from ADDR:PORT: bind the fresh socket to an explicit local source
 *       address and port before sendto(). The local family must match HOST.
 *   --from-port (-P): bind the fresh socket to PORT (wildcard addr of the
 *       destination's family) so the datagram is sourced from a fixed local
 *       port — e.g. so a peer that connect()s its reply socket back to us only
 *       accepts replies from a known port. Mutually exclusive with -F (the
 *       reused FD already carries its own bind). SO_REUSEADDR is set first.
 *   -b: set SO_BROADCAST (required to send to 255.255.255.255 for DHCP).
 *   -i: SO_BINDTODEVICE — pin the socket to IFACE. Required when sending
 *       to a broadcast address from a host that has no IPv4 address
 *       configured on the interface yet (DHCP DISCOVER's situation).
 *       Without this the kernel returns ENETUNREACH because it has no
 *       route to 255.255.255.255. Requires CAP_NET_RAW; bash-os's root
 *       has it.
 *   -F: send via an existing FD instead of opening a fresh ephemeral
 *       socket. Use the FD returned by `bashpoll listen-udp HOST:PORT
 *       LFD` to give the reply a deterministic source IP:port. Required
 *       for responder fixtures that reply to a peer whose query socket
 *       is connect()ed (e.g. bashntp queries connect to <server>:123;
 *       the kernel only delivers datagrams whose source is exactly
 *       that addr). Without -F, sendto picks an ephemeral source port
 *       and the kernel drops the reply on the peer's connect()ed
 *       socket. -F is mutually exclusive with -b and -i (the existing
 *       FD already carries its own bind/socket-option state).
 * Without -F the socket is opened, used once, and closed. Caller-side
 * state is minimal — no fd to track, no subshell.
 */
static int
bp_send_udp (WORD_LIST *args)
{
  const char *addr = NULL;
  const char *iface = NULL;
  const char *from_addr = NULL;
  int broadcast = 0;
  int from_fd = -1;
  long from_port = -1;   /* --from-port: fix the source port on a fresh socket */
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-b") == 0) broadcast = 1;
      else if (strcmp (w, "-i") == 0)
        { if (!p->next) { builtin_error ("-i needs IFACE"); return EX_USAGE; }
          p = p->next; iface = p->word->word; }
      else if (strcmp (w, "-F") == 0)
        { if (!p->next) { builtin_error ("-F needs FD"); return EX_USAGE; }
          p = p->next; from_fd = atoi (p->word->word);
          if (from_fd < 0) { builtin_error ("-F: bad FD %s", p->word->word); return EX_USAGE; } }
      else if (strcmp (w, "--from") == 0)
        { if (!p->next) { builtin_error ("--from needs ADDR:PORT"); return EX_USAGE; }
          p = p->next; from_addr = p->word->word; }
      else if (strcmp (w, "--from-port") == 0 || strcmp (w, "-P") == 0)
        { if (!p->next) { builtin_error ("--from-port needs PORT"); return EX_USAGE; }
          p = p->next;
          char *end = NULL; from_port = strtol (p->word->word, &end, 10);
          if (!end || *end || from_port < 0 || from_port > 65535)
            { builtin_error ("--from-port: bad PORT %s", p->word->word); return EX_USAGE; } }
      else if (!addr) addr = w;
      else { builtin_error ("send-udp: extra arg %s", w); return EX_USAGE; }
    }
  if (!addr) { builtin_error ("send-udp needs HOST:PORT [-b] [-i IFACE] [-F FD] [--from ADDR:PORT|--from-port PORT]"); return EX_USAGE; }
  if (from_fd >= 0 && (broadcast || iface))
    { builtin_error ("send-udp: -F is mutually exclusive with -b and -i"); return EX_USAGE; }
  if (from_fd >= 0 && (from_addr || from_port >= 0))
    { builtin_error ("send-udp: --from/--from-port are mutually exclusive with -F (the FD already carries its bind)"); return EX_USAGE; }
  if (from_addr && from_port >= 0)
    { builtin_error ("send-udp: --from and --from-port are mutually exclusive"); return EX_USAGE; }

  struct sockaddr_storage ss;
  socklen_t sl;
  if (bp_parse_addr (addr, &ss, &sl, /*passive*/ 0) < 0) return EX_USAGE;

  struct sockaddr_storage from_ss;
  socklen_t from_sl = 0;
  int have_from = 0;
  if (from_addr)
    {
      if (bp_parse_addr (from_addr, &from_ss, &from_sl, /*passive*/ 1) < 0)
        return EX_USAGE;
      if (from_ss.ss_family != ss.ss_family)
        { builtin_error ("send-udp: --from address family does not match destination"); return EX_USAGE; }
      have_from = 1;
    }
  else if (from_port >= 0)
    {
      memset (&from_ss, 0, sizeof from_ss);
      if (ss.ss_family == AF_INET6)
        {
          struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) &from_ss;
          s6->sin6_family = AF_INET6; s6->sin6_addr = in6addr_any;
          s6->sin6_port = htons ((uint16_t) from_port); from_sl = sizeof *s6;
        }
      else
        {
          struct sockaddr_in *s4 = (struct sockaddr_in *) &from_ss;
          s4->sin_family = AF_INET; s4->sin_addr.s_addr = htonl (INADDR_ANY);
          s4->sin_port = htons ((uint16_t) from_port); from_sl = sizeof *s4;
        }
      have_from = 1;
    }

  int fd;
  int own_fd = 0;
  if (from_fd >= 0)
    {
      /* Reuse caller's FD. Verify it's a SOCK_DGRAM socket so misuse
         on a regular file / pipe / TCP socket surfaces immediately
         instead of silently doing the wrong thing. */
      int type = 0;
      socklen_t tl = sizeof type;
      if (getsockopt (from_fd, SOL_SOCKET, SO_TYPE, &type, &tl) < 0)
        { builtin_error ("-F FD %d not a socket: %s", from_fd, strerror (errno));
          return EXECUTION_FAILURE; }
      if (type != SOCK_DGRAM)
        { builtin_error ("-F FD %d is not SOCK_DGRAM", from_fd);
          return EXECUTION_FAILURE; }
      fd = from_fd;
    }
  else
    {
      fd = socket (ss.ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
      if (fd < 0) { builtin_error ("socket: %s", strerror (errno)); return EXECUTION_FAILURE; }
      own_fd = 1;
    }
  if (broadcast)
    {
      int yes = 1;
      if (setsockopt (fd, SOL_SOCKET, SO_BROADCAST, &yes, sizeof yes) < 0)
        { builtin_error ("setsockopt SO_BROADCAST: %s", strerror (errno));
          if (own_fd) close (fd); return EXECUTION_FAILURE; }
    }
  if (iface)
    {
      if (setsockopt (fd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen (iface)) < 0)
        { builtin_error ("setsockopt SO_BINDTODEVICE %s: %s", iface, strerror (errno));
          if (own_fd) close (fd); return EXECUTION_FAILURE; }
    }
  if (have_from)
    {
      /* Fix the source port (e.g. so a peer that connect()s its reply socket
         to us only accepts replies from a known port). SO_REUSEADDR so
         back-to-back runs don't hit EADDRINUSE on recently-used ports. */
      int yes = 1;
      if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) < 0)
        { builtin_error ("setsockopt SO_REUSEADDR: %s", strerror (errno));
          if (own_fd) close (fd); return EXECUTION_FAILURE; }
#ifdef SO_REUSEPORT
      if (setsockopt (fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof yes) < 0)
        builtin_warning ("setsockopt SO_REUSEPORT: %s", strerror (errno));
#endif
      if (bind (fd, (struct sockaddr *) &from_ss, from_sl) < 0)
        { builtin_error ("%s: bind: %s", from_addr ? "--from" : "--from-port", strerror (errno));
          if (own_fd) close (fd); return EXECUTION_FAILURE; }
    }

  /* Slurp stdin into one buffer. Cap at the UDP IPv4 max payload (65507).
     One extra byte allocated as an overflow sentinel — if read fills it,
     stdin had more than fits in a single UDP datagram and we error. */
  size_t cap = 65507;
  unsigned char *buf = malloc (cap + 1);
  if (!buf) { if (own_fd) close (fd); builtin_error ("malloc: %s", strerror (errno)); return EXECUTION_FAILURE; }
  size_t total = 0;
  ssize_t n;
  /* EINTR-safe slurp: on signal interruption mid-read, retry rather
     than treating it as a fatal error or end-of-stream. */
  for (;;)
    {
      if (total >= cap + 1) break;
      n = read (STDIN_FILENO, buf + total, cap + 1 - total);
      if (n > 0) { total += (size_t) n; continue; }
      if (n == 0) break;                       /* EOF */
      if (errno == EINTR) continue;            /* retry */
      free (buf); if (own_fd) close (fd);
      builtin_error ("read stdin: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  if (total > cap)
    { free (buf); if (own_fd) close (fd); builtin_error ("send-udp: payload exceeds %zu bytes", cap); return EXECUTION_FAILURE; }

  ssize_t s;
  do { s = sendto (fd, buf, total, 0, (struct sockaddr *) &ss, sl); }
  while (s < 0 && errno == EINTR);
  free (buf);
  if (own_fd) close (fd);
  if (s < 0)
    { builtin_error ("sendto %s: %s", addr, strerror (errno)); return EXECUTION_FAILURE; }
  return EXECUTION_SUCCESS;
}

/* recv-udp FD [-t MS] [-o ADDRVAR] [-x] — receive ONE datagram from FD.
 *   -t MS: timeout in milliseconds (default: block forever; -1 explicit
 *          forever; 0 non-blocking via poll first)
 *   -o ADDRVAR: bind source "ADDR:PORT" to ADDRVAR in caller's shell.
 *               Without -o, the address is prepended to the payload as
 *               "ADDR:PORT\n<bytes>" — only safe for callers who know
 *               the payload doesn't start with a newline at offset 0.
 *               -o is the recommended form for binary protocols (DHCP).
 *   -x: emit payload as hex (binhex-style, NUL-safe) instead of raw
 *       bytes. Required when capturing through bash's `$(…)` because
 *       command substitution strips NUL bytes — and DHCP packets are
 *       NUL-padded throughout. With -x the caller does
 *       `REPLY_HEX=$(bashpoll recv-udp ... -x)` and decodes via binhex
 *       -d when raw bytes are needed.
 *
 * Datagram payload is written to stdout on success.
 * Return EXECUTION_FAILURE on timeout (=> rc 1 in bash).
 */
static int
bp_recv_udp (WORD_LIST *args)
{
  if (!args) { builtin_error ("recv-udp needs FD [-t MS] [-o ADDRVAR] [-x]"); return EX_USAGE; }
  int fd = atoi (args->word->word);
  int timeout = -1;
  int hex_out = 0;
  const char *addrvar = NULL;
  for (WORD_LIST *p = args->next; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-t") == 0)
        { if (!p->next) { builtin_error ("-t needs MS"); return EX_USAGE; }
          p = p->next; timeout = atoi (p->word->word); }
      else if (strcmp (w, "-o") == 0)
        { if (!p->next) { builtin_error ("-o needs ADDRVAR"); return EX_USAGE; }
          p = p->next; addrvar = p->word->word; }
      else if (strcmp (w, "-x") == 0)
        hex_out = 1;
      else { builtin_error ("recv-udp: unexpected arg %s", w); return EX_USAGE; }
    }

  if (timeout >= 0)
    {
      struct pollfd pfd = { .fd = fd, .events = POLLIN };
      int pr;
      do { pr = poll (&pfd, 1, timeout); } while (pr < 0 && errno == EINTR);
      if (pr < 0) { builtin_error ("poll: %s", strerror (errno)); return EXECUTION_FAILURE; }
      if (pr == 0) return EXECUTION_FAILURE;   /* timeout */
    }

  unsigned char buf[65536];
  struct sockaddr_storage src;
  socklen_t srclen = sizeof src;
  ssize_t n;
  do { n = recvfrom (fd, buf, sizeof buf, MSG_TRUNC,
                     (struct sockaddr *) &src, &srclen); }
  while (n < 0 && errno == EINTR);
  if (n < 0)
    { builtin_error ("recvfrom: %s", strerror (errno)); return EXECUTION_FAILURE; }
  if ((size_t) n > sizeof buf)
    { builtin_error ("recvfrom: oversize datagram (%zd bytes, buffer is %zu)", n, sizeof buf); return EXECUTION_FAILURE; }

  /* Format source address. For IPv4: "1.2.3.4:5678". For IPv6: "[::1]:5678". */
  char host[64], port[8], addrbuf[80];
  if (getnameinfo ((struct sockaddr *) &src, srclen,
                   host, sizeof host, port, sizeof port,
                   NI_NUMERICHOST | NI_NUMERICSERV) != 0)
    {
      strcpy (host, "?"); strcpy (port, "?");
    }
  if (src.ss_family == AF_INET6)
    snprintf (addrbuf, sizeof addrbuf, "[%s]:%s", host, port);
  else
    snprintf (addrbuf, sizeof addrbuf, "%s:%s", host, port);

  if (addrvar)
    builtin_bind_variable ((char *) addrvar, addrbuf, 0);
  else
    {
      /* Inline form: "addr\npayload..." */
      printf ("%s\n", addrbuf);
      fflush (stdout);
    }

  if (hex_out)
    {
      /* Emit payload as hex — NUL-safe through bash $()/var. */
      static const char nibble[] = "0123456789abcdef";
      char *hexbuf = malloc ((size_t) n * 2 + 2);
      if (!hexbuf)
        { builtin_error ("malloc: %s", strerror (errno)); return EXECUTION_FAILURE; }
      for (ssize_t i = 0; i < n; i++)
        {
          hexbuf[i*2]   = nibble[buf[i] >> 4];
          hexbuf[i*2+1] = nibble[buf[i] & 0xf];
        }
      hexbuf[n*2]   = '\n';
      hexbuf[n*2+1] = '\0';
      ssize_t off = 0, total = n*2 + 1;
      while (off < total)
        {
          ssize_t w = write (STDOUT_FILENO, hexbuf + off, (size_t) (total - off));
          if (w < 0) { if (errno == EINTR) continue;
                       free (hexbuf);
                       builtin_error ("write: %s", strerror (errno));
                       return EXECUTION_FAILURE; }
          off += w;
        }
      free (hexbuf);
    }
  else
    {
      /* Write payload bytes verbatim to stdout. */
      ssize_t off = 0;
      while (off < n)
        {
          ssize_t w = write (STDOUT_FILENO, buf + off, (size_t) (n - off));
          if (w < 0) { if (errno == EINTR) continue;
                       builtin_error ("write: %s", strerror (errno));
                       return EXECUTION_FAILURE; }
          off += w;
        }
    }
  return EXECUTION_SUCCESS;
}

static int
bp_clear_cloexec (WORD_LIST *args)
{
  if (!args) { builtin_error ("clear-cloexec needs FD"); return EX_USAGE; }
  int fd = atoi (args->word->word);
  int flags = fcntl (fd, F_GETFD, 0);
  if (flags < 0) { builtin_error ("fcntl GETFD: %s", strerror (errno)); return EXECUTION_FAILURE; }
  if (fcntl (fd, F_SETFD, flags & ~FD_CLOEXEC) < 0)
    { builtin_error ("fcntl SETFD: %s", strerror (errno)); return EXECUTION_FAILURE; }
  return EXECUTION_SUCCESS;
}

static int
bp_signalfd (WORD_LIST *args)
{
  if (!args) { builtin_error ("signalfd: needs SIG... [FDVAR]"); return EX_USAGE; }
  sigset_t mask, before;
  sigemptyset (&mask);
  const char *fdvar = NULL;
  int count = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      int sig = decode_signal (w, DSIG_SIGPREFIX);
      if (sig == NO_SIG && !p->next && count && strncmp (w, "SIG", 3) != 0 &&
          (w[0] < '0' || w[0] > '9'))
        { fdvar = w; break; }
      if (sig <= 0 || sig >= NSIG || sig == SIGKILL || sig == SIGSTOP)
        { builtin_error ("signalfd: invalid or unblockable signal: %s", w); return EX_USAGE; }
      sigaddset (&mask, sig);
      count++;
    }
  if (!count) { builtin_error ("signalfd: needs at least one signal"); return EX_USAGE; }
  if (fdvar && !bp_fd_variable_ok (fdvar)) return EXECUTION_FAILURE;
  struct bp_signal_fd *entry = calloc (1, sizeof *entry);
  if (!entry) { builtin_error ("signalfd: allocation: %s", strerror (errno)); return EXECUTION_FAILURE; }
  if (sigprocmask (SIG_BLOCK, &mask, &before) < 0)
    { free (entry); builtin_error ("sigprocmask: %s", strerror (errno)); return EXECUTION_FAILURE; }
  int fd = signalfd (-1, &mask, SFD_CLOEXEC);
  if (fd < 0)
    {
      int saved = errno;
      sigset_t unblock;
      sigemptyset (&unblock);
      for (int sig = 1; sig < NSIG; sig++)
        if (sigismember (&mask, sig) == 1 && sigismember (&before, sig) == 0)
          sigaddset (&unblock, sig);
      sigprocmask (SIG_UNBLOCK, &unblock, NULL);
      free (entry);
      builtin_error ("signalfd: %s", strerror (saved));
      return EXECUTION_FAILURE;
    }
  for (int sig = 1; sig < NSIG; sig++)
    if (sigismember (&mask, sig) == 1)
      {
        if (!bp_signal_refs[sig]) bp_signal_owned[sig] = sigismember (&before, sig) == 0;
        bp_signal_refs[sig]++;
      }
  entry->fd = fd;
  entry->mask = mask;
  entry->next = bp_signal_fds;
  bp_signal_fds = entry;
  if (bp_emit_fd (fd, fdvar) < 0)
    { bp_release_signal_fd (&bp_signal_fds, 0); return EXECUTION_FAILURE; }
  return EXECUTION_SUCCESS;
}

int
bashpoll_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;
  if (strcmp (cmd, "listen")       == 0) return bp_listen (args);
  if (strcmp (cmd, "listen-unix")  == 0) return bp_listen_unix (args);
  if (strcmp (cmd, "listen-udp")   == 0) return bp_listen_udp (args);
  if (strcmp (cmd, "send-udp")     == 0) return bp_send_udp (args);
  if (strcmp (cmd, "recv-udp")     == 0) return bp_recv_udp (args);
  if (strcmp (cmd, "accept")       == 0) return bp_accept (args);
  if (strcmp (cmd, "connect")      == 0) return bp_connect (args);
  if (strcmp (cmd, "wait")         == 0) return bp_wait (args);
  if (strcmp (cmd, "close")        == 0) return bp_close (args);
  if (strcmp (cmd, "set-nonblock") == 0) return bp_set_nonblock (args);
  if (strcmp (cmd, "clear-cloexec") == 0) return bp_clear_cloexec (args);
  if (strcmp (cmd, "signalfd")     == 0) return bp_signalfd (args);
  builtin_error ("unknown subcommand: %s", cmd);
  return EX_USAGE;
}

char *bashpoll_doc[] = {
  "Multiplexed I/O via epoll(7) + listen/accept/connect.",
  "",
  "    bashpoll listen ADDR:PORT [-q BACKLOG] FDVAR",
  "    bashpoll listen-unix /path/sock FDVAR",
  "    bashpoll listen-udp ADDR:PORT FDVAR",
  "    bashpoll send-udp HOST:PORT [-b] [-i IFACE] [-F FD] [--from ADDR:PORT|--from-port PORT]   # stdin → datagram; -b SO_BROADCAST, -i SO_BINDTODEVICE, -F reuse existing FD, --from* bind source on a fresh socket",
  "    bashpoll recv-udp FD [-t MS] [-o ADDRVAR] [-x]   # one datagram → stdout; -x emits hex (NUL-safe)",
  "    bashpoll accept LISTEN_FD FDVAR",
  "    bashpoll connect HOST:PORT [FDVAR] [-t TIMEOUT_MS]",
  "    bashpoll wait [-t TIMEOUT_MS] FD[:read|write|read,write]...",
  "    bashpoll close FD",
  "    bashpoll set-nonblock FD on|off",
  "    bashpoll clear-cloexec FD",
  "    bashpoll signalfd SIG... FDVAR",
  "",
  "FDVAR receives the new fd in the caller's shell — required to",
  "preserve the fd across the loadable's $(...) subshell trap.",
  "wait outputs `FD events,events,...` per ready descriptor; events",
  "are: readable writable pri hup rdhup error.",
  "Bare FDs request read readiness; add :write or :read,write explicitly.",
  "Close signalfds with bashpoll close to restore only owned mask bits.",
  "Overlapping signalfds retain their shared mask until the last close.",
  "Shell redirection close/dup cannot track this mask ownership.",
  (char *)NULL
};

struct builtin bashpoll_struct = {
  "bashpoll",
  bashpoll_builtin,
  BUILTIN_ENABLED,
  bashpoll_doc,
  "bashpoll listen|listen-unix|listen-udp|send-udp|recv-udp|accept|connect|wait|close|set-nonblock|clear-cloexec|signalfd ARGS...",
  0
};
