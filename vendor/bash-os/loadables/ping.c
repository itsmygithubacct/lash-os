/* bashping.c — raw-socket ICMP echo + IP-TTL probe loadables for bash.
 *
 * Two builtins from one .c file:
 *
 *   bashping       — default mode is ICMP echo (RFC 792). With -T, it
 *                    switches to UDP-based incremental TTL probe
 *                    (BSD-classic traceroute). One builtin, two modes
 *                    via a flag — simpler than registering two
 *                    separate builtin symbols for the static-link
 *                    integration.
 *
 * Modes:
 *   bashping HOST              — 5 ICMP echoes, 1s interval, summary
 *   bashping -T HOST           — traceroute (UDP probe, incremental TTL)
 *
 * Both need raw sockets, which need either uid 0 or CAP_NET_RAW. A
 * setcap on bash itself is the recommended path for non-root users:
 *
 *     setcap cap_net_raw=ep /bin/bash
 *
 * IPv4 and IPv6 are supported. IPv6 uses ICMPv6 echo and the IPv6
 * hop-limit traceroute analogue.
 *
 * Why this exists:
 *   pure ships nothing for reachability testing. /docs/bash/ has no
 *   ping/traceroute manpage because pure can't issue raw sockets via
 *   bash builtins. bashping is bash-os's answer: ~250 LoC of C that
 *   replaces a ~60 KB iputils-ping binary with a ~5 KB builtin.
 *
 * Counterpart reference:
 *   The audited ping source lives in the research refs checkout at iputils/ping/
 *   (not vendored here). bashping keeps a deliberately small operator
 *   subset instead of importing iputils wholesale.
 *
 * Limitations / non-goals at v1:
 *   - No identifier-vs-pid disambiguation for kernel ICMP demux
 *     (Linux's ping_socket(2) for unprivileged ping isn't used; we
 *      stick to SOCK_RAW for portability and full payload control)
 *   - No SOCK_RAW IP_HDRINCL — kernel writes the IP header
 *   - No DSCP / ToS flags
 *   - No record-route / source-route options
 *   - traceroute uses UDP probes by default (BSD-classic style)
 *
 * --- LICENSE ---
 * MIT License
 *
 * Copyright (c) 2026 bash_linux contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software. See the
 * full MIT text for the standard disclaimer.
 *
 * Note: when compiled and statically linked into GNU Bash, the resulting
 * combined binary is a derivative work of bash and is governed by GPL-3+
 * (bash's license). MIT for this source file is GPL-3+-compatible, so
 * the binary's GPL-3+ status is unchanged.
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
#include <math.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>

#include "loadables.h"

/* ---- common helpers ------------------------------------------------- */

static unsigned short
bp_checksum (const void *vbuf, int len)
{
  const unsigned short *buf = vbuf;
  unsigned long sum = 0;
  while (len > 1) { sum += *buf++; len -= 2; }
  if (len == 1) { unsigned short last = 0; *(unsigned char *) &last = *(unsigned char *) buf; sum += last; }
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (unsigned short) ~sum;
}

static double
bp_now_ms (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000.0 + ts.tv_nsec / 1.0e6;
}

static double
bp_mdev (int n, double sum, double sumsq)
{
  if (n <= 1)
    return 0.0;
  double avg = sum / n;
  double var = (sumsq / n) - (avg * avg);
  if (var < 0.0)
    var = 0.0;
  return sqrt (var);
}

/* Forward decl — bp_reply_acceptable is defined further down (next
   to bp_selftest_truncated, which is the test-only caller) but the
   ping recv-loop above bp_selftest_truncated needs it too. */
static int bp_reply_acceptable (const unsigned char *rx, ssize_t r);

static const char *
bp_host_unbracket (const char *host, char *buf, size_t bufsz)
{
  size_t n;
  if (!host || host[0] != '[')
    return host;
  n = strlen (host);
  if (n < 3 || host[n - 1] != ']' || n - 2 >= bufsz)
    return host;
  memcpy (buf, host + 1, n - 2);
  buf[n - 2] = '\0';
  return buf;
}

static int
bp_resolve_sockaddr (const char *host, int family, int socktype, int proto,
                     struct sockaddr_storage *out, socklen_t *outlen)
{
  char hbuf[NI_MAXHOST];
  const char *name = bp_host_unbracket (host, hbuf, sizeof hbuf);
  struct addrinfo hints = { 0 }, *res = NULL;
  hints.ai_family = family;
  hints.ai_socktype = socktype;
  hints.ai_protocol = proto;
  int rc = getaddrinfo (name, NULL, &hints, &res);
  if (rc != 0 || !res)
    return -1;

  struct addrinfo *chosen = NULL;
  struct addrinfo *first6 = NULL;
  struct addrinfo *first4 = NULL;
  for (struct addrinfo *ai = res; ai; ai = ai->ai_next)
    {
      if (!ai->ai_addr || ai->ai_addrlen > (socklen_t) sizeof *out)
        continue;
      if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
        continue;
      if (family == AF_UNSPEC)
        {
          if (ai->ai_family == AF_INET6 && !first6)
            first6 = ai;
          else if (ai->ai_family == AF_INET && !first4)
            first4 = ai;
          continue;
        }
      chosen = ai;
      break;
    }
  if (family == AF_UNSPEC)
    chosen = first6 ? first6 : first4;
  if (!chosen)
    {
      freeaddrinfo (res);
      return -1;
    }

  memset (out, 0, sizeof *out);
  memcpy (out, chosen->ai_addr, chosen->ai_addrlen);
  *outlen = (socklen_t) chosen->ai_addrlen;
  freeaddrinfo (res);
  return 0;
}

/* Strict integer parser for -c/-m/-q flags. Rejects empty, non-decimal,
   trailing-garbage, and out-of-range inputs with builtin_error. Matches
   iputils/busybox behavior: bad numeric arg is a usage error, not silent
   coercion (the old atoi() path silently mapped "abc" or 0 to the clamp). */
static int
bp_parse_int (const char *s, long lo, long hi, long *out, const char *what)
{
  if (!s || !*s)
    { builtin_error ("%s: numeric value required", what); return -1; }
  errno = 0;
  char *end = NULL;
  long v = strtol (s, &end, 10);
  if (errno != 0 || !end || *end != '\0' || end == s)
    { builtin_error ("%s: must be a decimal integer (got '%s')", what, s);
      return -1; }
  if (v < lo || v > hi)
    { builtin_error ("%s: out of range [%ld..%ld] (got %ld)", what, lo, hi, v);
      return -1; }
  *out = v;
  return 0;
}

/* Strict double parser for -W/-i flags (seconds, with subsecond precision).
   NaN-safe range check uses !(v >= lo && v <= hi). */
static int
bp_parse_double (const char *s, double lo, double hi, double *out,
                 const char *what)
{
  if (!s || !*s)
    { builtin_error ("%s: numeric value required", what); return -1; }
  errno = 0;
  char *end = NULL;
  double v = strtod (s, &end);
  if (errno != 0 || !end || *end != '\0' || end == s)
    { builtin_error ("%s: must be a number (got '%s')", what, s); return -1; }
  if (!(v >= lo && v <= hi))
    { builtin_error ("%s: out of range [%g..%g] (got %g)", what, lo, hi, v);
      return -1; }
  *out = v;
  return 0;
}

/* ---- bashping ------------------------------------------------------- */

static int
bashping4_main (int count, double interval_ms, double timeout_ms,
                const char *host, const struct in_addr *dstp, int quiet)
{
  struct in_addr dst = *dstp;

  int sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sock < 0)
    {
      if (errno == EPERM || errno == EACCES)
        builtin_error ("CAP_NET_RAW required (try: sudo setcap cap_net_raw=ep $(which bash))");
      else
        builtin_error ("socket: %s", strerror (errno));
      return 1;
    }

  /* Pretty: print "PING host (ip): N data bytes" header, ping(8)-style. */
  char ip_str[INET_ADDRSTRLEN];
  inet_ntop (AF_INET, &dst, ip_str, sizeof ip_str);
  printf ("PING %s (%s) 56(84) bytes of data.\n", host, ip_str);

  /* Build a 64-byte payload: 8-byte ICMP header + 56-byte data. */
  unsigned char tx[64], rx[1500];
  struct icmphdr *hdr = (struct icmphdr *) tx;
  unsigned short id = (unsigned short) (getpid () & 0xffff);

  int sent = 0, received = 0;
  double rtt_min = 1e18, rtt_max = 0, rtt_sum = 0, rtt_sumsq = 0;
  double run_start = bp_now_ms ();

  for (int seq = 1; seq <= count; seq++)
    {
      memset (tx, 0, sizeof tx);
      hdr->type = ICMP_ECHO;
      hdr->code = 0;
      hdr->un.echo.id = htons (id);
      hdr->un.echo.sequence = htons ((unsigned short) seq);
      /* Stamp send time into the payload so we don't need a sent[]
         table to look up rtt; ping(8) does the same trick. */
      double tsend = bp_now_ms ();
      memcpy (tx + 8, &tsend, sizeof tsend);
      /* Fill the rest with a recognizable pattern. */
      for (size_t i = 8 + sizeof tsend; i < sizeof tx; i++)
        tx[i] = (unsigned char) i;
      hdr->checksum = 0;
      hdr->checksum = bp_checksum (tx, sizeof tx);

      struct sockaddr_in to = { 0 };
      to.sin_family = AF_INET;
      to.sin_addr = dst;
      ssize_t n = sendto (sock, tx, sizeof tx, 0,
                          (struct sockaddr *) &to, sizeof to);
      if (n < 0)
        {
          fprintf (stderr, "  seq %d: sendto: %s\n", seq, strerror (errno));
        }
      else
        {
          sent++;
        }

      /* Wait for echo reply (or timeout). Loop in case we get other
         ICMP traffic on the raw socket. */
      double deadline = bp_now_ms () + timeout_ms;
      for (;;)
        {
          double now = bp_now_ms ();
          if (now >= deadline) { if (!quiet) printf ("  seq %d: timeout\n", seq); break; }
          struct pollfd pfd = { sock, POLLIN, 0 };
          int pr = poll (&pfd, 1, (int) (deadline - now));
          if (pr <= 0) { if (!quiet) printf ("  seq %d: timeout\n", seq); break; }
          struct sockaddr_in from = { 0 };
          socklen_t flen = sizeof from;
          ssize_t r = recvfrom (sock, rx, sizeof rx, 0,
                                (struct sockaddr *) &from, &flen);
          if (r < 0)
            {
              if (errno == EINTR) continue;
              fprintf (stderr, "  seq %d: recvfrom: %s\n", seq, strerror (errno));
              break;
            }
          /* Truncation guard — shared with bashping selftest-truncated
             (bp_selftest_truncated). Adds an IHL sanity check
             (`hlen >= sizeof(struct ip)`) that the old inline form
             didn't have — guards against a hostile-but-non-truncated
             reply with `ip_hl=0` that would otherwise pass the
             per-byte-count gate. */
          if (!bp_reply_acceptable (rx, r)) continue;
          struct ip *iph = (struct ip *) rx;
          int hlen = iph->ip_hl * 4;
          struct icmphdr *rh = (struct icmphdr *) (rx + hlen);
          if (rh->type != ICMP_ECHOREPLY) continue;
          if (ntohs (rh->un.echo.id) != id) continue;
          unsigned short rseq = ntohs (rh->un.echo.sequence);
          /* Look up our timestamp from the payload (we put it there). */
          double tsent;
          memcpy (&tsent, rx + hlen + 8, sizeof tsent);
          double rtt = bp_now_ms () - tsent;
          received++;
          if (rtt < rtt_min) rtt_min = rtt;
          if (rtt > rtt_max) rtt_max = rtt;
          rtt_sum += rtt;
          rtt_sumsq += rtt * rtt;
          char src[INET_ADDRSTRLEN];
          inet_ntop (AF_INET, &iph->ip_src, src, sizeof src);
          if (!quiet)
            printf ("64 bytes from %s: icmp_seq=%u ttl=%d time=%.3f ms\n",
                    src, (unsigned) rseq, iph->ip_ttl, rtt);
          break;
        }

      if (seq < count)
        {
          struct timespec ts = { (time_t) (interval_ms / 1000),
                                 (long) ((long long) interval_ms % 1000) * 1000000L };
          nanosleep (&ts, NULL);
        }
    }

  close (sock);

  double elapsed = bp_now_ms () - run_start;
  double loss = sent > 0 ? 100.0 * (sent - received) / sent : 0.0;
  printf ("\n--- %s ping statistics ---\n", host);
  printf ("%d packets transmitted, %d received, %.0f%% packet loss, time %.0fms\n",
          sent, received, loss, elapsed);
  if (received > 0)
    printf ("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
            rtt_min, rtt_sum / received, rtt_max,
            bp_mdev (received, rtt_sum, rtt_sumsq));

  /* Exit code: 0 if any received, 1 otherwise (matches ping(8)). */
  return received > 0 ? 0 : 1;
}

static int
bp6_build_echo (unsigned short id, unsigned short seq, double tsend,
                unsigned char *tx, size_t txlen)
{
  if (txlen < 64)
    return -1;
  memset (tx, 0, txlen);
  struct icmp6_hdr *hdr = (struct icmp6_hdr *) tx;
  hdr->icmp6_type = ICMP6_ECHO_REQUEST;
  hdr->icmp6_code = 0;
  hdr->icmp6_id = htons (id);
  hdr->icmp6_seq = htons (seq);
  memcpy (tx + 8, &tsend, sizeof tsend);
  for (size_t i = 8 + sizeof tsend; i < txlen; i++)
    tx[i] = (unsigned char) i;
  return 0;
}

static int
bp6_parse_echo_reply (const unsigned char *rx, ssize_t r, unsigned short id,
                      int check_id, unsigned short *seq_out,
                      double *tsent_out)
{
  if (r < (ssize_t) (sizeof (struct icmp6_hdr) + sizeof (double)))
    return 0;
  const struct icmp6_hdr *rh = (const struct icmp6_hdr *) rx;
  if (rh->icmp6_type != ICMP6_ECHO_REPLY || rh->icmp6_code != 0)
    return 0;
  if (check_id && ntohs (rh->icmp6_id) != id)
    return 0;
  if (seq_out)
    *seq_out = ntohs (rh->icmp6_seq);
  if (tsent_out)
    memcpy (tsent_out, rx + 8, sizeof *tsent_out);
  return 1;
}

static int
bp6_trace_type_acceptable (unsigned char type, int *reached_out)
{
  if (reached_out)
    *reached_out = 0;
  if (type == ICMP6_TIME_EXCEEDED)
    return 1;
  if (type == ICMP6_DST_UNREACH)
    {
      if (reached_out)
        *reached_out = 1;
      return 1;
    }
  return 0;
}

static int
bashping6_main (int count, double interval_ms, double timeout_ms,
                const char *host, const struct sockaddr_in6 *dstp, int quiet)
{
  struct sockaddr_in6 dst = *dstp;
  int sock = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  int raw_socket = 1;
  if (sock < 0 && (errno == EPERM || errno == EACCES))
    {
      sock = socket (AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
      raw_socket = 0;
    }
  if (sock < 0)
    {
      if (errno == EPERM || errno == EACCES)
        builtin_error ("CAP_NET_RAW required (try: sudo setcap cap_net_raw=ep $(which bash))");
      else
        builtin_error ("socket: %s", strerror (errno));
      return 1;
    }

  int csum_offset = 2;
  setsockopt (sock, IPPROTO_IPV6, IPV6_CHECKSUM, &csum_offset, sizeof csum_offset);
  int one = 1;
  setsockopt (sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &one, sizeof one);

  char ip_str[INET6_ADDRSTRLEN];
  inet_ntop (AF_INET6, &dst.sin6_addr, ip_str, sizeof ip_str);
  printf ("PING %s (%s) 56 data bytes\n", host, ip_str);

  unsigned char tx[64], rx[1500];
  unsigned short id = (unsigned short) (getpid () & 0xffff);
  int sent = 0, received = 0;
  double rtt_min = 1e18, rtt_max = 0, rtt_sum = 0, rtt_sumsq = 0;
  double run_start = bp_now_ms ();

  for (int seq = 1; seq <= count; seq++)
    {
      double tsend = bp_now_ms ();
      bp6_build_echo (id, (unsigned short) seq, tsend, tx, sizeof tx);
      ssize_t n = sendto (sock, tx, sizeof tx, 0,
                          (struct sockaddr *) &dst, sizeof dst);
      if (n < 0)
        fprintf (stderr, "  seq %d: sendto: %s\n", seq, strerror (errno));
      else
        sent++;

      double deadline = bp_now_ms () + timeout_ms;
      for (;;)
        {
          double now = bp_now_ms ();
          if (now >= deadline) { if (!quiet) printf ("  seq %d: timeout\n", seq); break; }
          struct pollfd pfd = { sock, POLLIN, 0 };
          int pr = poll (&pfd, 1, (int) (deadline - now));
          if (pr <= 0) { if (!quiet) printf ("  seq %d: timeout\n", seq); break; }

          struct sockaddr_in6 from = { 0 };
          unsigned char cbuf[128];
          struct iovec iov = { rx, sizeof rx };
          struct msghdr msg = { 0 };
          msg.msg_name = &from;
          msg.msg_namelen = sizeof from;
          msg.msg_iov = &iov;
          msg.msg_iovlen = 1;
          msg.msg_control = cbuf;
          msg.msg_controllen = sizeof cbuf;
          ssize_t r = recvmsg (sock, &msg, 0);
          if (r < 0)
            {
              if (errno == EINTR) continue;
              fprintf (stderr, "  seq %d: recvmsg: %s\n", seq, strerror (errno));
              break;
            }

          unsigned short rseq = 0;
          double tsent = 0;
          if (!bp6_parse_echo_reply (rx, r, id, raw_socket, &rseq, &tsent))
            continue;

          int hoplimit = 0;
          for (struct cmsghdr *cm = CMSG_FIRSTHDR (&msg); cm;
               cm = CMSG_NXTHDR (&msg, cm))
            if (cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_HOPLIMIT
                && cm->cmsg_len >= CMSG_LEN (sizeof (int)))
              memcpy (&hoplimit, CMSG_DATA (cm), sizeof hoplimit);

          double rtt = bp_now_ms () - tsent;
          received++;
          if (rtt < rtt_min) rtt_min = rtt;
          if (rtt > rtt_max) rtt_max = rtt;
          rtt_sum += rtt;
          rtt_sumsq += rtt * rtt;
          char src[INET6_ADDRSTRLEN];
          inet_ntop (AF_INET6, &from.sin6_addr, src, sizeof src);
          if (!quiet)
            printf ("64 bytes from %s: icmp_seq=%u ttl=%d time=%.3f ms\n",
                    src, (unsigned) rseq, hoplimit, rtt);
          break;
        }

      if (seq < count)
        {
          struct timespec ts = { (time_t) (interval_ms / 1000),
                                 (long) ((long long) interval_ms % 1000) * 1000000L };
          nanosleep (&ts, NULL);
        }
    }

  close (sock);
  double elapsed = bp_now_ms () - run_start;
  double loss = sent > 0 ? 100.0 * (sent - received) / sent : 0.0;
  printf ("\n--- %s ping statistics ---\n", host);
  printf ("%d packets transmitted, %d received, %.0f%% packet loss, time %.0fms\n",
          sent, received, loss, elapsed);
  if (received > 0)
    printf ("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
            rtt_min, rtt_sum / received, rtt_max,
            bp_mdev (received, rtt_sum, rtt_sumsq));
  return received > 0 ? 0 : 1;
}

static int
bashping_main (int count, double interval_ms, double timeout_ms,
               const char *host, int family, int quiet)
{
  struct sockaddr_storage ss;
  socklen_t slen = 0;
  if (bp_resolve_sockaddr (host, family, SOCK_RAW, 0, &ss, &slen) < 0)
    {
      builtin_error ("cannot resolve %s", host);
      return 1;
    }
  if (ss.ss_family == AF_INET)
    return bashping4_main (count, interval_ms, timeout_ms, host,
                           &((struct sockaddr_in *) &ss)->sin_addr, quiet);
  if (ss.ss_family == AF_INET6)
    return bashping6_main (count, interval_ms, timeout_ms, host,
                           (struct sockaddr_in6 *) &ss, quiet);
  builtin_error ("unsupported address family for %s", host);
  return 1;
}

/* Forward decl — body comes after bashtraceroute_main. */
static int bashtraceroute_main (int max_ttl, int probes_per_hop,
                                double timeout_ms, const char *host,
                                int family);

/* ---- truncation validator (shared with the recvfrom loop) -------- */

/* Returns 1 if a `r`-byte buffer at `rx` looks like a structurally
 * valid ICMP echo-reply we'd hand to the rtt-emitter; 0 if too short
 * or shape-inconsistent (the recv loop continues past these and tries
 * the next datagram). Mirrors the inline checks at the recvfrom loop
 * — bp_selftest_truncated exercises this function with synthetic
 * buffers so the truncation safety can be verified without
 * CAP_NET_RAW. */
static int
bp_reply_acceptable (const unsigned char *rx, ssize_t r)
{
    if (r < (ssize_t) (sizeof (struct ip) + 8 + sizeof (double)))
        return 0;
    const struct ip *iph = (const struct ip *) rx;
    int hlen = iph->ip_hl * 4;
    if (hlen < (int) sizeof (struct ip))   /* IHL field nonsense */
        return 0;
    if (r < hlen + 8)
        return 0;
    return 1;
}

/* Returns 1 when an ICMP response has enough bytes for traceroute mode
 * to read the outer IP header, ICMP header, embedded original IP header,
 * and embedded UDP header, and when the embedded UDP destination port
 * matches the probe we sent. */
static int
bp_trace_reply_acceptable (const unsigned char *rx, ssize_t r,
                           unsigned short expected_dport,
                           struct in_addr *src_out, int *reached_out)
{
    if (r < (ssize_t) sizeof (struct ip))
        return 0;
    const struct ip *iph = (const struct ip *) rx;
    int hlen = iph->ip_hl * 4;
    if (hlen < (int) sizeof (struct ip))
        return 0;
    if (r < hlen + 8 + (ssize_t) sizeof (struct ip))
        return 0;

    const struct icmphdr *rh = (const struct icmphdr *) (rx + hlen);
    if (rh->type != ICMP_TIME_EXCEEDED &&
        rh->type != ICMP_DEST_UNREACH)
        return 0;

    const struct ip *origip = (const struct ip *) (rx + hlen + 8);
    int orighl = origip->ip_hl * 4;
    if (orighl < (int) sizeof (struct ip))
        return 0;
    if (r < hlen + 8 + orighl + 8)
        return 0;

    const struct udphdr *origudp =
        (const struct udphdr *) (rx + hlen + 8 + orighl);
    if (ntohs (origudp->uh_dport) != expected_dport)
        return 0;

    if (src_out)
        *src_out = iph->ip_src;
    if (reached_out)
        *reached_out = rh->type == ICMP_DEST_UNREACH;
    return 1;
}

/* ---- selftest-truncated: exercise bp_reply_acceptable directly ----- */

static int
bp_selftest_truncated (void)
{
    /* Each vector: a synthetic buffer + length + expected accept (1) or
     * reject (0). The receive loop guards an 8-byte ICMP header + an
     * 8-byte payload timestamp atop the IPv4 header (default IHL=5,
     * 20 bytes), so the minimum valid r is 20+8+8 = 36 bytes. */
    unsigned char buf[64] = {0};
    /* Build a minimal IPv4 header: version=4, IHL=5 (20 bytes). */
    buf[0] = 0x45;
    struct { const unsigned char *data; ssize_t len; int expect; const char *name; }
    vectors[] = {
        { buf,  0,  0, "0-byte recvfrom (interface error) rejected" },
        { buf,  4,  0, "4-byte truncated reply rejected (less than 36)" },
        { buf, 27,  0, "27-byte reply rejected (one short of minimum)" },
        { buf, 35,  0, "35-byte reply rejected (one byte short)" },
        { buf, 36,  1, "36-byte reply accepted (exact minimum: 20+8+8)" },
        { buf, 56,  1, "56-byte reply accepted (typical default size)" },
    };
    int n = sizeof vectors / sizeof vectors[0];
    int passed = 0;

    printf ("1..%d\n", n);
    /* Build an IHL-too-large variant separately to also exercise the
     * hlen-vs-r consistency arm. */
    for (int i = 0; i < n; i++)
        {
            int got = bp_reply_acceptable (vectors[i].data, vectors[i].len);
            if (got == vectors[i].expect)
                {
                    printf ("ok %d - %s\n", i + 1, vectors[i].name);
                    passed++;
                }
            else
                {
                    printf ("not ok %d - %s (expected %d got %d)\n",
                            i + 1, vectors[i].name, vectors[i].expect, got);
                }
        }
    return passed == n ? 0 : 1;
}

/* ---- selftest-trace-truncated: traceroute receive-shape guard ------ */

static int
bp_selftest_trace_truncated (void)
{
    unsigned short port = 33434;
    unsigned char buf[96] = {0};
    buf[0] = 0x45;              /* outer IPv4, IHL=5 */
    struct ip *iph = (struct ip *) buf;
    iph->ip_src.s_addr = htonl (0x0a000001);
    struct icmphdr *icmp = (struct icmphdr *) (buf + 20);
    icmp->type = ICMP_TIME_EXCEEDED;
    unsigned char *orig = buf + 20 + 8;
    orig[0] = 0x45;             /* embedded original IPv4, IHL=5 */
    struct udphdr *udp = (struct udphdr *) (orig + 20);
    udp->uh_dport = htons (port);

    unsigned char outer_bad[96];
    memcpy (outer_bad, buf, sizeof outer_bad);
    outer_bad[0] = 0x40;        /* IHL=0 */

    unsigned char orig_bad[96];
    memcpy (orig_bad, buf, sizeof orig_bad);
    orig_bad[28] = 0x40;        /* embedded IHL=0 */

    unsigned char wrong_type[96];
    memcpy (wrong_type, buf, sizeof wrong_type);
    ((struct icmphdr *) (wrong_type + 20))->type = ICMP_ECHOREPLY;

    unsigned char wrong_port[96];
    memcpy (wrong_port, buf, sizeof wrong_port);
    ((struct udphdr *) (wrong_port + 48))->uh_dport = htons (port + 1);

    unsigned char reached[96];
    memcpy (reached, buf, sizeof reached);
    ((struct icmphdr *) (reached + 20))->type = ICMP_DEST_UNREACH;

    struct { const unsigned char *data; ssize_t len; unsigned short expect_port;
             int expect; int expect_reached; const char *name; }
    vectors[] = {
        { buf,        0, port, 0, 0, "0-byte traceroute reply rejected" },
        { buf,       27, port, 0, 0, "27-byte reply rejected before ICMP header" },
        { buf,       55, port, 0, 0, "55-byte reply rejected before embedded UDP header" },
        { outer_bad, 56, port, 0, 0, "outer IHL nonsense rejected" },
        { orig_bad,  56, port, 0, 0, "embedded IHL nonsense rejected" },
        { wrong_type,56, port, 0, 0, "unrelated ICMP type rejected" },
        { wrong_port,56, port, 0, 0, "wrong embedded UDP destination port rejected" },
        { buf,       56, port, 1, 0, "56-byte time-exceeded reply accepted" },
        { reached,   56, port, 1, 1, "56-byte destination-unreachable reply marks reached" },
    };
    int n = sizeof vectors / sizeof vectors[0];
    int passed = 0;

    printf ("1..%d\n", n);
    for (int i = 0; i < n; i++)
        {
            struct in_addr src = {0};
            int reached_flag = 0;
            int got = bp_trace_reply_acceptable (vectors[i].data,
                                                 vectors[i].len,
                                                 vectors[i].expect_port,
                                                 &src, &reached_flag);
            if (got == vectors[i].expect &&
                (!got || reached_flag == vectors[i].expect_reached))
                {
                    printf ("ok %d - %s\n", i + 1, vectors[i].name);
                    passed++;
                }
            else
                {
                    printf ("not ok %d - %s (expected accept=%d reached=%d got accept=%d reached=%d)\n",
                            i + 1, vectors[i].name, vectors[i].expect,
                            vectors[i].expect_reached, got, reached_flag);
                }
        }
    return passed == n ? 0 : 1;
}

static int
bp_selftest_ipv6_codec (void)
{
  unsigned char tx[64];
  unsigned char rx[64];
  unsigned short id = 0x1234, seq = 7, got_seq = 0;
  double ts = 42.125, got_ts = 0;
  int passed = 0;
  const int total = 11;

  printf ("1..%d\n", total);
  if (bp6_build_echo (id, seq, ts, tx, sizeof tx) == 0)
    { printf ("ok 1 - ICMPv6 echo request builder accepts 64-byte packet\n"); passed++; }
  else
    printf ("not ok 1 - ICMPv6 echo request builder accepts 64-byte packet\n");

  struct icmp6_hdr *h = (struct icmp6_hdr *) tx;
  if (h->icmp6_type == ICMP6_ECHO_REQUEST && h->icmp6_code == 0)
    { printf ("ok 2 - request type/code are 128/0\n"); passed++; }
  else
    printf ("not ok 2 - request type/code are 128/0\n");
  if (ntohs (h->icmp6_id) == id && ntohs (h->icmp6_seq) == seq)
    { printf ("ok 3 - request identifier and sequence are encoded\n"); passed++; }
  else
    printf ("not ok 3 - request identifier and sequence are encoded\n");
  double stored = 0;
  memcpy (&stored, tx + 8, sizeof stored);
  if (stored == ts)
    { printf ("ok 4 - request payload carries send timestamp\n"); passed++; }
  else
    printf ("not ok 4 - request payload carries send timestamp\n");

  memcpy (rx, tx, sizeof rx);
  ((struct icmp6_hdr *) rx)->icmp6_type = ICMP6_ECHO_REPLY;
  if (bp6_parse_echo_reply (rx, sizeof rx, id, 1, &got_seq, &got_ts)
      && got_seq == seq && got_ts == ts)
    { printf ("ok 5 - synthesized echo reply parses seq and timestamp\n"); passed++; }
  else
    printf ("not ok 5 - synthesized echo reply parses seq and timestamp\n");

  if (!bp6_parse_echo_reply (rx, 7, id, 1, &got_seq, &got_ts))
    { printf ("ok 6 - short ICMPv6 reply rejected\n"); passed++; }
  else
    printf ("not ok 6 - short ICMPv6 reply rejected\n");

  if (!bp6_parse_echo_reply (rx, sizeof rx, id + 1, 1, &got_seq, &got_ts))
    { printf ("ok 7 - wrong identifier rejected\n"); passed++; }
  else
    printf ("not ok 7 - wrong identifier rejected\n");

  if (!bp6_parse_echo_reply (rx, sizeof (struct icmp6_hdr), id, 1,
                             &got_seq, &got_ts))
    { printf ("ok 8 - header-only ICMPv6 reply rejected\n"); passed++; }
  else
    printf ("not ok 8 - header-only ICMPv6 reply rejected\n");

  memcpy (rx, tx, sizeof rx);
  ((struct icmp6_hdr *) rx)->icmp6_type = ICMP6_ECHO_REQUEST;
  if (!bp6_parse_echo_reply (rx, sizeof rx, id, 1, &got_seq, &got_ts))
    { printf ("ok 9 - non-reply ICMPv6 type rejected\n"); passed++; }
  else
    printf ("not ok 9 - non-reply ICMPv6 type rejected\n");

  memcpy (rx, tx, sizeof rx);
  ((struct icmp6_hdr *) rx)->icmp6_type = ICMP6_ECHO_REPLY;
  ((struct icmp6_hdr *) rx)->icmp6_code = 1;
  if (!bp6_parse_echo_reply (rx, sizeof rx, id, 1, &got_seq, &got_ts))
    { printf ("ok 10 - non-zero ICMPv6 echo code rejected\n"); passed++; }
  else
    printf ("not ok 10 - non-zero ICMPv6 echo code rejected\n");

  int reached = -1;
  int ok_trace = bp6_trace_type_acceptable (ICMP6_TIME_EXCEEDED, &reached)
                 && reached == 0
                 && bp6_trace_type_acceptable (ICMP6_DST_UNREACH, &reached)
                 && reached == 1
                 && !bp6_trace_type_acceptable (ICMP6_ECHO_REPLY, &reached)
                 && reached == 0;
  if (ok_trace)
    { printf ("ok 11 - ICMPv6 traceroute type classifier accepts only hop and terminal replies\n"); passed++; }
  else
    printf ("not ok 11 - ICMPv6 traceroute type classifier accepts only hop and terminal replies\n");

  return passed == total ? 0 : 1;
}

/* ---- selftest-checksum: validate bp_checksum against known vectors --------- */

/* Known checksum vectors computed against the RFC 1071 internet checksum.
 * Each entry: { data, len, expected_csum, description }.
 * Vectors verified against the iputils in_cksum() implementation. */
static const unsigned char ck_v1_data[64] = {0};                  /* all zeros */
static const unsigned char ck_v3_data[64] = {                      /* 0xFF/0x00 alternating */
  0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,
  0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,
  0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,
  0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00
};
static const unsigned char ck_v6_data[64] = {                      /* all 0xFF */
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};
/* ICMP echo request header (type=8, code=0, id=0x1234, seq=1) + 56 zero bytes */
static const unsigned char ck_v2_data[64] = {
  8,0,0,0,0x12,0x34,0,1, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

static int
bp_selftest_checksum (void)
{
  /* Each vector: { data, len, expected_csum [computed via python3 ip_checksum], name } */
  struct { const unsigned char *data; int len; unsigned short expected; const char *name; }
  vectors[] = {
    { ck_v1_data, 64, 0xFFFF, "64 zero bytes" },
    { ck_v2_data, 64, 0xE5CA, "ICMP echo + 56 pad" },
    { ck_v3_data, 64, 0x1FE0, "alternating 0xFF/0x00" },
    { ck_v6_data, 64, 0x0000, "all 0xFF (wraparound)" },
    { (unsigned char *) "\x41", 1, 0xBEFF, "single byte 0x41" },
    { (unsigned char *) "\x12\x34", 2, 0xEDCB, "two bytes 0x1234" },
  };
  int n = sizeof vectors / sizeof vectors[0];
  int passed = 0;

  printf ("1..%d\n", n);
  for (int i = 0; i < n; i++)
    {
      unsigned short got = bp_checksum (vectors[i].data, vectors[i].len);
      unsigned short got_wire = ntohs (got);
      if (got_wire == vectors[i].expected)
        {
          printf ("ok %d - %s\n", i + 1, vectors[i].name);
          passed++;
        }
      else
        {
          printf ("not ok %d - %s (expected 0x%04x got 0x%04x)\n",
                  i + 1, vectors[i].name, (unsigned) vectors[i].expected,
                  (unsigned) got_wire);
        }
    }
  return passed == n ? 0 : 1;
}

int
ping_builtin (WORD_LIST *list)
{
  int opt;
  int count = 5;
  int trace_mode = 0;
  int max_ttl = 30;
  int probes_per_hop = 3;
  int quiet = 0;
  int family = AF_UNSPEC;
  double interval_ms = 1000.0;
  double timeout_ms = 1000.0;

  reset_internal_getopt ();
  while ((opt = internal_getopt (list, "46VTc:W:i:m:qQ:")) != -1)
    {
      long lv; double dv;
      switch (opt)
        {
        case '4': family = AF_INET; break;
        case '6': family = AF_INET6; break;
        case 'V':
          printf ("ping from bashping 4.2\n");
          printf ("raw sockets: yes, IDN: no, NLS: no\n");
          return (EXECUTION_SUCCESS);
        case 'T': trace_mode = 1; break;
        case 'c':
          if (bp_parse_int (list_optarg, 1, 10000, &lv, "-c COUNT") < 0)
            return (EX_USAGE);
          count = (int) lv; break;
        case 'W':
          if (bp_parse_double (list_optarg, 0.1, 60.0, &dv, "-W TIMEOUT") < 0)
            return (EX_USAGE);
          timeout_ms = dv * 1000.0; break;
        case 'i':
          if (bp_parse_double (list_optarg, 0.1, 60.0, &dv, "-i INTERVAL") < 0)
            return (EX_USAGE);
          interval_ms = dv * 1000.0; break;
        case 'm':
          if (bp_parse_int (list_optarg, 1, 64, &lv, "-m MAX_TTL") < 0)
            return (EX_USAGE);
          max_ttl = (int) lv; break;
        case 'q': quiet = 1; break;
        case 'Q':
          if (bp_parse_int (list_optarg, 1, 10, &lv, "-Q PROBES") < 0)
            return (EX_USAGE);
          probes_per_hop = (int) lv; break;
        CASE_HELPOPT;
        default:
          builtin_usage ();
          return (EX_USAGE);
        }
    }
  list = loptend;

  if (list == 0)
    {
      builtin_error ("HOST argument required");
      return (EX_USAGE);
    }

  /* Special verb: selftest-checksum exercises bp_checksum with known vectors. */
  if (strcmp (list->word->word, "selftest-checksum") == 0)
    return bp_selftest_checksum ();
  /* Truncation-safety selftest — exercises bp_reply_acceptable() so
   * the receive-loop's length guards can be verified without a raw
   * socket or CAP_NET_RAW. */
  if (strcmp (list->word->word, "selftest-truncated") == 0)
    return bp_selftest_truncated ();
  if (strcmp (list->word->word, "selftest-trace-truncated") == 0)
    return bp_selftest_trace_truncated ();
  if (strcmp (list->word->word, "selftest-ipv6-codec") == 0)
    return bp_selftest_ipv6_codec ();

  const char *host = list->word->word;
  if (list->next != 0)
    {
      builtin_error ("at most one HOST argument is accepted");
      return (EX_USAGE);
    }

  if (trace_mode)
    {
      if (max_ttl <= 0)        max_ttl = 1;
      if (max_ttl > 64)        max_ttl = 64;
      if (probes_per_hop <= 0) probes_per_hop = 1;
      if (probes_per_hop > 10) probes_per_hop = 10;
      if (timeout_ms < 100)    timeout_ms = 100;
      return bashtraceroute_main (max_ttl, probes_per_hop, timeout_ms, host, family) == 0
             ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }

  if (count <= 0) count = 1;
  if (count > 10000) count = 10000;
  if (interval_ms < 100) interval_ms = 100;
  if (timeout_ms < 100) timeout_ms = 100;

  return bashping_main (count, interval_ms, timeout_ms, host, family, quiet) == 0
         ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

char *ping_doc[] = {
  "ICMP echo + UDP traceroute (raw socket). Two modes via -T:",
  "",
  "  bashping HOST                # ICMP echo, 5 probes",
  "  bashping -T HOST             # UDP traceroute, max 30 hops",
  "  bashping selftest-checksum   # unit-test bp_checksum with known vectors",
  "  bashping selftest-ipv6-codec # unit-test ICMPv6 echo encode/decode",
  "  bashping selftest-truncated  # unit-test reply-length truncation guard",
  "  bashping selftest-trace-truncated",
  "                               # unit-test traceroute reply truncation guard",
  "",
  "Requires CAP_NET_RAW (uid 0 has it; for non-root, run:",
  "    sudo setcap cap_net_raw=ep \\$(which bash)",
  ").",
  "",
  "Options:",
  "    -4           force IPv4 resolution",
  "    -6           force IPv6 resolution",
  "    -V           print version and exit",
  "    -c COUNT     ping: number of probes (default 5)",
  "    -W TIMEOUT   per-probe timeout in seconds (default 1)",
  "    -i INTERVAL  ping: inter-probe interval in seconds (default 1)",
  "    -q           ping: quiet output (summary only)",
  "    -T           traceroute mode (UDP probes, incremental TTL)",
  "    -m MAX_TTL   trace: maximum TTL (default 30)",
  "    -Q PROBES    trace: probes per hop (default 3)",
  "",
  "Exit status: 0 on success (any reply / target reached), 1 otherwise.",
  (char *) NULL
};

struct builtin bashping_struct = {
  "bashping",
  ping_builtin,
  BUILTIN_ENABLED,
  ping_doc,
  "bashping [-4|-6] [-T] [-q] [-c N] [-W T] [-i I] [-m MAX_TTL] [-Q PROBES] HOST",
  0
};

/* ---- bashtraceroute ------------------------------------------------- */

static int
bashtraceroute4_main (int max_ttl, int probes_per_hop, double timeout_ms,
                      const char *host, const struct in_addr *dstp)
{
  struct in_addr dst = *dstp;

  /* UDP probe socket (write-only) and ICMP receive socket. */
  int udp = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  int icmp = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (udp < 0 || icmp < 0)
    {
      if (errno == EPERM || errno == EACCES)
        builtin_error ("CAP_NET_RAW required (try: sudo setcap cap_net_raw=ep $(which bash))");
      else
        builtin_error ("socket: %s", strerror (errno));
      if (udp >= 0)  close (udp);
      if (icmp >= 0) close (icmp);
      return 1;
    }

  char ip_str[INET_ADDRSTRLEN];
  inet_ntop (AF_INET, &dst, ip_str, sizeof ip_str);
  printf ("traceroute to %s (%s), %d hops max\n", host, ip_str, max_ttl);

  unsigned short base_port = 33434;
  int reached = 0;
  for (int ttl = 1; ttl <= max_ttl && !reached; ttl++)
    {
      printf ("%2d ", ttl);
      fflush (stdout);
      if (setsockopt (udp, IPPROTO_IP, IP_TTL, &ttl, sizeof ttl) < 0)
        {
          builtin_error ("setsockopt(IP_TTL): %s", strerror (errno));
          break;
        }

      struct in_addr last_src = { 0 };
      double last_rtt = -1;
      int got_any = 0;

      for (int p = 0; p < probes_per_hop; p++)
        {
          struct sockaddr_in to = { 0 };
          to.sin_family = AF_INET;
          to.sin_addr = dst;
          to.sin_port = htons (base_port + ttl - 1);
          unsigned char payload[16] = "TRACEROUTE-PROBE";
          double tsend = bp_now_ms ();
          if (sendto (udp, payload, sizeof payload, 0,
                      (struct sockaddr *) &to, sizeof to) < 0)
            { printf (" * "); continue; }

          double deadline = bp_now_ms () + timeout_ms;
          int matched = 0;
          while (!matched)
            {
              double now = bp_now_ms ();
              if (now >= deadline) break;
              struct pollfd pfd = { icmp, POLLIN, 0 };
              int pr = poll (&pfd, 1, (int) (deadline - now));
              if (pr <= 0) break;
              unsigned char rx[1500];
              struct sockaddr_in from = { 0 };
              socklen_t flen = sizeof from;
              ssize_t r = recvfrom (icmp, rx, sizeof rx, 0,
                                    (struct sockaddr *) &from, &flen);
              if (r < 0) { if (errno == EINTR) continue; break; }
              int trace_reached = 0;
              if (!bp_trace_reply_acceptable (rx, r, base_port + ttl - 1,
                                              &last_src, &trace_reached))
                continue;

              last_rtt = bp_now_ms () - tsend;
              got_any = 1;
              matched = 1;
              if (trace_reached) reached = 1;
            }
          if (!matched) printf (" * "); else printf (" %.3fms ", last_rtt);
        }

      if (got_any)
        {
          char src[INET_ADDRSTRLEN];
          inet_ntop (AF_INET, &last_src, src, sizeof src);
          printf (" %s\n", src);
        }
      else
        {
          printf (" *\n");
        }
    }

  close (udp);
  close (icmp);
  return reached ? 0 : 1;
}

static int
bashtraceroute6_main (int max_ttl, int probes_per_hop, double timeout_ms,
                      const char *host, const struct sockaddr_in6 *dstp)
{
  struct sockaddr_in6 dst = *dstp;
  int udp = socket (AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  int icmp = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  if (udp < 0 || icmp < 0)
    {
      if (errno == EPERM || errno == EACCES)
        builtin_error ("CAP_NET_RAW required (try: sudo setcap cap_net_raw=ep $(which bash))");
      else
        builtin_error ("socket: %s", strerror (errno));
      if (udp >= 0) close (udp);
      if (icmp >= 0) close (icmp);
      return 1;
    }

  char ip_str[INET6_ADDRSTRLEN];
  inet_ntop (AF_INET6, &dst.sin6_addr, ip_str, sizeof ip_str);
  printf ("traceroute to %s (%s), %d hops max\n", host, ip_str, max_ttl);

  unsigned short base_port = 33434;
  int reached = 0;
  for (int ttl = 1; ttl <= max_ttl && !reached; ttl++)
    {
      printf ("%2d ", ttl);
      fflush (stdout);
      if (setsockopt (udp, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof ttl) < 0)
        {
          builtin_error ("setsockopt(IPV6_UNICAST_HOPS): %s", strerror (errno));
          break;
        }

      struct in6_addr last_src = in6addr_any;
      double last_rtt = -1;
      int got_any = 0;

      for (int p = 0; p < probes_per_hop; p++)
        {
          dst.sin6_port = htons (base_port + ttl - 1);
          unsigned char payload[16] = "TRACEROUTE-PROBE";
          double tsend = bp_now_ms ();
          if (sendto (udp, payload, sizeof payload, 0,
                      (struct sockaddr *) &dst, sizeof dst) < 0)
            { printf (" * "); continue; }

          double deadline = bp_now_ms () + timeout_ms;
          int matched = 0;
          while (!matched)
            {
              double now = bp_now_ms ();
              if (now >= deadline) break;
              struct pollfd pfd = { icmp, POLLIN, 0 };
              int pr = poll (&pfd, 1, (int) (deadline - now));
              if (pr <= 0) break;

              unsigned char rx[1500];
              struct sockaddr_in6 from = { 0 };
              socklen_t flen = sizeof from;
              ssize_t r = recvfrom (icmp, rx, sizeof rx, 0,
                                    (struct sockaddr *) &from, &flen);
              if (r < (ssize_t) sizeof (struct icmp6_hdr))
                { if (r < 0 && errno == EINTR) continue; break; }

              const struct icmp6_hdr *rh = (const struct icmp6_hdr *) rx;
              int reached_reply = 0;
              if (!bp6_trace_type_acceptable (rh->icmp6_type,
                                              &reached_reply))
                continue;

              last_src = from.sin6_addr;
              last_rtt = bp_now_ms () - tsend;
              got_any = 1;
              matched = 1;
              if (reached_reply)
                reached = 1;
            }
          if (!matched) printf (" * "); else printf (" %.3fms ", last_rtt);
        }

      if (got_any)
        {
          char src[INET6_ADDRSTRLEN];
          inet_ntop (AF_INET6, &last_src, src, sizeof src);
          printf (" %s\n", src);
        }
      else
        {
          printf (" *\n");
        }
    }

  close (udp);
  close (icmp);
  return reached ? 0 : 1;
}

static int
bashtraceroute_main (int max_ttl, int probes_per_hop, double timeout_ms,
                     const char *host, int family)
{
  struct sockaddr_storage ss;
  socklen_t slen = 0;
  if (bp_resolve_sockaddr (host, family, SOCK_DGRAM, IPPROTO_UDP, &ss, &slen) < 0)
    {
      builtin_error ("cannot resolve %s", host);
      return 1;
    }
  if (ss.ss_family == AF_INET)
    return bashtraceroute4_main (max_ttl, probes_per_hop, timeout_ms, host,
                                 &((struct sockaddr_in *) &ss)->sin_addr);
  if (ss.ss_family == AF_INET6)
    return bashtraceroute6_main (max_ttl, probes_per_hop, timeout_ms, host,
                                 (struct sockaddr_in6 *) &ss);
  builtin_error ("unsupported address family for %s", host);
  return 1;
}

/* bashtraceroute is exposed via `bashping -T` rather than a separate
   builtin name; rationale in the file header. */
