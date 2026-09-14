/* SPDX-License-Identifier: MIT */
/* dhcp6.c — DHCPv6 (RFC 8415) client message builder + parser.
 *
 * Separate protocol from the DHCPv4 dhcp/dhcpd pair (see
 * research/bash-os/F03-DHCPv6-DESIGN.md). Slice 1 is the host-testable wire
 * core: DUID generation, build SOLICIT/REQUEST/RENEW/RELEASE, and parse
 * ADVERTISE/REPLY (any message, generically). Slice 2 adds the live `solicit`
 * exchange (SOLICIT->ADVERTISE->REQUEST->REPLY over UDP). The dhcpd6
 * server is dhcpd6.c.
 *
 * Verbs:
 *   dhcp6 duid-ll MAC
 *       Print a DUID-LL (RFC 8415 §11.4: type 3, hwtype 1 = Ethernet, MAC) hex.
 *   dhcp6 build solicit|request|renew|release|confirm|rebind|decline|information-request
 *       -d CLIENT_DUID_HEX [-s SERVER_DUID_HEX] [-i IAID] [-a IPV6_ADDR]
 *       [-x XID_HEX] [-o CODE[,CODE...]] [-V VAR]
 *       Build a client message: header + CLIENTID + ELAPSED_TIME + IA_NA
 *       (+ IAADDR when -a) + ORO; REQUEST/RENEW/RELEASE/DECLINE add SERVERID.
 *       Prints the message hex (or binds <VAR>=hex with -V).
 *   dhcp6 parse HEX [-V VAR]
 *       Decode a DHCPv6 message: msg-type, xid, client/server DUID, IA_NA
 *       (iaid/t1/t2), IAADDR (address/preferred/valid), DNS servers,
 *       status-code, ORO. Print key=value lines, or bind an assoc array.
 *   dhcp6 --version
 *
 * Wire codec is big-endian TLV; IPv6 via inet_ntop/inet_pton.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "loadables.h"
#include "_d6_hmacmd5.h"

/* message types */
#define D6_SOLICIT 1
#define D6_ADVERTISE 2
#define D6_REQUEST 3
#define D6_CONFIRM 4
#define D6_RENEW 5
#define D6_REBIND 6
#define D6_REPLY 7
#define D6_RELEASE 8
#define D6_DECLINE 9
#define D6_INFOREQ 11

/* option codes */
#define D6O_CLIENTID 1
#define D6O_SERVERID 2
#define D6O_IA_NA 3
#define D6O_IAADDR 5
#define D6O_ORO 6
#define D6O_PREFERENCE 7
#define D6O_ELAPSED_TIME 8
#define D6O_STATUS_CODE 13
#define D6O_RAPID_COMMIT 14
#define D6O_DNS_SERVERS 23
#define D6O_DOMAIN_LIST 24
#define D6O_IA_PD 25
#define D6O_IAPREFIX 26
/* F03 relay (RFC 8415 §19–20) */
#define D6_RELAY_FORW 12
#define D6_RELAY_REPL 13
#define D6O_RELAY_MSG 9
#define D6O_INTERFACE_ID 18
/* F03 RECONFIGURE + RKAP auth */
#define D6_RECONFIGURE 10
#define D6O_AUTH 11
#define D6O_RECONF_MSG 19

#define D6_MAX 1500

/* ---- big-endian helpers ---- */
static unsigned rd16 (const unsigned char *p) { return ((unsigned) p[0] << 8) | p[1]; }
static void wr16 (unsigned char *p, unsigned v) { p[0] = (unsigned char) (v >> 8); p[1] = (unsigned char) v; }
static unsigned rd32 (const unsigned char *p)
{ return ((unsigned) p[0] << 24) | ((unsigned) p[1] << 16) | ((unsigned) p[2] << 8) | p[3]; }
static void wr32 (unsigned char *p, unsigned v)
{ p[0] = (unsigned char) (v >> 24); p[1] = (unsigned char) (v >> 16);
  p[2] = (unsigned char) (v >> 8); p[3] = (unsigned char) v; }

static int hexval (int c)
{ if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1; }

static int hex_decode (const char *hex, unsigned char *out, size_t cap)
{
  size_t n = 0; int hi = -1;
  for (const char *p = hex; *p; p++)
    {
      if (isspace ((unsigned char) *p)) continue;
      int v = hexval ((unsigned char) *p);
      if (v < 0) return -1;
      if (hi < 0) hi = v;
      else { if (n >= cap) return -1; out[n++] = (unsigned char) ((hi << 4) | v); hi = -1; }
    }
  return hi < 0 ? (int) n : -1;
}

static void hex_print (const unsigned char *b, int n, char *out, size_t cap)
{
  size_t o = 0;
  for (int i = 0; i < n && o + 2 < cap; i++) { snprintf (out + o, cap - o, "%02x", b[i]); o += 2; }
  out[o] = '\0';
}

/* ---- option append (build) ---- */
/* append an option header+data; returns new length, or 0 on overflow. */
static size_t d6_opt (unsigned char *buf, size_t p, size_t cap, unsigned code,
                      const unsigned char *data, size_t len)
{
  if (p + 4 + len > cap) return 0;
  wr16 (buf + p, code); wr16 (buf + p + 2, (unsigned) len);
  if (len && data) memcpy (buf + p + 4, data, len);
  return p + 4 + len;
}

/* ---- parsed message ---- */
struct d6_msg {
  int msg_type;
  unsigned xid;                              /* 24-bit transaction id */
  unsigned char client_id[132]; int client_id_len;
  unsigned char server_id[132]; int server_id_len;
  int have_ia_na; unsigned iaid, t1, t2;
  int have_addr; unsigned char addr[16]; unsigned pref_life, valid_life;
  int have_ia_pd; unsigned pd_iaid, pd_t1, pd_t2;
  int have_prefix; unsigned char prefix[16]; int prefix_len; unsigned pd_pref_life, pd_valid_life;
  unsigned char dns[8][16]; int n_dns;
  int have_status; unsigned status_code; char status_msg[128];
  unsigned char oro[64]; int oro_len;
};

/* walk IA_NA sub-options for an IAADDR. data points past iaid/t1/t2. */
static void d6_scan_ia_subopts (const unsigned char *d, int len, struct d6_msg *m)
{
  int p = 0;
  while (p + 4 <= len)
    {
      unsigned code = rd16 (d + p), olen = rd16 (d + p + 2);
      if (p + 4 + (int) olen > len) break;
      const unsigned char *v = d + p + 4;
      if (code == D6O_IAADDR && olen >= 24)
        {
          memcpy (m->addr, v, 16);
          m->pref_life = rd32 (v + 16);
          m->valid_life = rd32 (v + 20);
          m->have_addr = 1;
        }
      else if (code == D6O_STATUS_CODE && olen >= 2)
        { m->have_status = 1; m->status_code = rd16 (v);
          int ml = olen - 2; if (ml > (int) sizeof m->status_msg - 1) ml = sizeof m->status_msg - 1;
          memcpy (m->status_msg, v + 2, ml); m->status_msg[ml] = '\0'; }
      p += 4 + olen;
    }
}

/* walk IA_PD sub-options for an IAPREFIX. data points past iaid/t1/t2.
 * IAPREFIX (RFC 8415 §21.22): preferred(4) valid(4) prefix-len(1) prefix(16). */
static void d6_scan_iapd_subopts (const unsigned char *d, int len, struct d6_msg *m)
{
  int p = 0;
  while (p + 4 <= len)
    {
      unsigned code = rd16 (d + p), olen = rd16 (d + p + 2);
      if (p + 4 + (int) olen > len) break;
      const unsigned char *v = d + p + 4;
      if (code == D6O_IAPREFIX && olen >= 25)
        {
          m->pd_pref_life = rd32 (v);
          m->pd_valid_life = rd32 (v + 4);
          m->prefix_len = v[8];
          memcpy (m->prefix, v + 9, 16);
          m->have_prefix = 1;
        }
      else if (code == D6O_STATUS_CODE && olen >= 2)
        { m->have_status = 1; m->status_code = rd16 (v);
          int ml = olen - 2; if (ml > (int) sizeof m->status_msg - 1) ml = sizeof m->status_msg - 1;
          memcpy (m->status_msg, v + 2, ml); m->status_msg[ml] = '\0'; }
      p += 4 + olen;
    }
}

/* parse a whole DHCPv6 message. returns 0 ok, -1 malformed. */
static int d6_parse (const unsigned char *pkt, int len, struct d6_msg *m)
{
  memset (m, 0, sizeof *m);
  if (len < 4) return -1;
  m->msg_type = pkt[0];
  m->xid = ((unsigned) pkt[1] << 16) | ((unsigned) pkt[2] << 8) | pkt[3];
  int p = 4;
  while (p + 4 <= len)
    {
      unsigned code = rd16 (pkt + p), olen = rd16 (pkt + p + 2);
      if (p + 4 + (int) olen > len) return -1;
      const unsigned char *v = pkt + p + 4;
      switch (code)
        {
        case D6O_CLIENTID:
          { int n = olen < sizeof m->client_id ? (int) olen : (int) sizeof m->client_id;
            memcpy (m->client_id, v, n); m->client_id_len = n; break; }
        case D6O_SERVERID:
          { int n = olen < sizeof m->server_id ? (int) olen : (int) sizeof m->server_id;
            memcpy (m->server_id, v, n); m->server_id_len = n; break; }
        case D6O_IA_NA:
          if (olen >= 12)
            { m->have_ia_na = 1; m->iaid = rd32 (v); m->t1 = rd32 (v + 4); m->t2 = rd32 (v + 8);
              d6_scan_ia_subopts (v + 12, (int) olen - 12, m); }
          break;
        case D6O_IA_PD:
          if (olen >= 12)
            { m->have_ia_pd = 1; m->pd_iaid = rd32 (v); m->pd_t1 = rd32 (v + 4); m->pd_t2 = rd32 (v + 8);
              d6_scan_iapd_subopts (v + 12, (int) olen - 12, m); }
          break;
        case D6O_IAADDR:                       /* tolerate top-level IAADDR too */
          if (olen >= 24) { memcpy (m->addr, v, 16); m->pref_life = rd32 (v + 16);
                            m->valid_life = rd32 (v + 20); m->have_addr = 1; }
          break;
        case D6O_ORO:
          { int n = olen < sizeof m->oro ? (int) olen : (int) sizeof m->oro;
            memcpy (m->oro, v, n); m->oro_len = n; break; }
        case D6O_STATUS_CODE:
          if (olen >= 2) { m->have_status = 1; m->status_code = rd16 (v);
            int ml = olen - 2; if (ml > (int) sizeof m->status_msg - 1) ml = sizeof m->status_msg - 1;
            memcpy (m->status_msg, v + 2, ml); m->status_msg[ml] = '\0'; }
          break;
        case D6O_DNS_SERVERS:
          for (unsigned i = 0; i + 16 <= olen && m->n_dns < 8; i += 16)
            { memcpy (m->dns[m->n_dns], v + i, 16); m->n_dns++; }
          break;
        default: break;
        }
      p += 4 + olen;
    }
  return 0;
}

/* ---- builder ---- */
static const char *d6_type_name (int t)
{
  switch (t) {
    case D6_SOLICIT: return "SOLICIT"; case D6_ADVERTISE: return "ADVERTISE";
    case D6_REQUEST: return "REQUEST"; case D6_CONFIRM: return "CONFIRM";
    case D6_RENEW: return "RENEW"; case D6_REBIND: return "REBIND";
    case D6_REPLY: return "REPLY"; case D6_RELEASE: return "RELEASE";
    case D6_DECLINE: return "DECLINE"; case D6_INFOREQ: return "INFORMATION-REQUEST";
    default: return "UNKNOWN"; }
}
static int d6_type_num (const char *s)
{
  if (!strcmp (s, "solicit")) return D6_SOLICIT;
  if (!strcmp (s, "request")) return D6_REQUEST;
  if (!strcmp (s, "renew")) return D6_RENEW;
  if (!strcmp (s, "rebind")) return D6_REBIND;
  if (!strcmp (s, "release")) return D6_RELEASE;
  if (!strcmp (s, "confirm")) return D6_CONFIRM;
  if (!strcmp (s, "decline")) return D6_DECLINE;
  if (!strcmp (s, "information-request")) return D6_INFOREQ;
  return -1;
}

/* Build a client message. Returns length, or 0 on error.
 * include_ia_na=0 omits IA_NA (INFORMATION-REQUEST); rapid_commit adds the
 * RAPID_COMMIT option; include_ia_pd adds an IA_PD request (prefix delegation). */
static size_t d6_build (unsigned char *buf, size_t cap, int msg_type, unsigned xid,
                        const unsigned char *cid, int cid_len,
                        const unsigned char *sid, int sid_len,
                        unsigned iaid, int have_addr, const unsigned char addr[16],
                        unsigned pref, unsigned valid,
                        int rapid_commit, int include_ia_na,
                        int include_ia_pd, unsigned pd_iaid,
                        const unsigned char *oro, int oro_len)
{
  if (cap < 4) return 0;
  buf[0] = (unsigned char) msg_type;
  buf[1] = (unsigned char) (xid >> 16); buf[2] = (unsigned char) (xid >> 8); buf[3] = (unsigned char) xid;
  size_t p = 4;
  /* CLIENTID */
  if (cid_len > 0) { p = d6_opt (buf, p, cap, D6O_CLIENTID, cid, cid_len); if (!p) return 0; }
  /* SERVERID (REQUEST/RENEW/RELEASE/DECLINE) */
  if (sid_len > 0) { p = d6_opt (buf, p, cap, D6O_SERVERID, sid, sid_len); if (!p) return 0; }
  /* ELAPSED_TIME = 0 */
  { unsigned char et[2] = { 0, 0 }; p = d6_opt (buf, p, cap, D6O_ELAPSED_TIME, et, 2); if (!p) return 0; }
  /* RAPID_COMMIT (SOLICIT only, in practice) */
  if (rapid_commit) { p = d6_opt (buf, p, cap, D6O_RAPID_COMMIT, NULL, 0); if (!p) return 0; }
  /* IA_NA: iaid + t1=0 + t2=0 (+ IAADDR when an address is supplied) */
  if (include_ia_na)
    {
      unsigned char ia[12 + 4 + 24];
      wr32 (ia, iaid); wr32 (ia + 4, 0); wr32 (ia + 8, 0);
      size_t ialen = 12;
      if (have_addr)
        {
          wr16 (ia + ialen, D6O_IAADDR); wr16 (ia + ialen + 2, 24); ialen += 4;
          memcpy (ia + ialen, addr, 16); wr32 (ia + ialen + 16, pref); wr32 (ia + ialen + 20, valid);
          ialen += 24;
        }
      p = d6_opt (buf, p, cap, D6O_IA_NA, ia, ialen); if (!p) return 0;
    }
  /* IA_PD: iaid + t1=0 + t2=0 (no IAPREFIX hint — the server delegates) */
  if (include_ia_pd)
    {
      unsigned char ia[12]; wr32 (ia, pd_iaid); wr32 (ia + 4, 0); wr32 (ia + 8, 0);
      p = d6_opt (buf, p, cap, D6O_IA_PD, ia, 12); if (!p) return 0;
    }
  /* ORO */
  if (oro_len > 0) { p = d6_opt (buf, p, cap, D6O_ORO, oro, oro_len); if (!p) return 0; }
  return p;
}

/* ---- verb: parse output ---- */
static void d6_emit (const struct d6_msg *m, const char *var)
{
  char hexbuf[280], ip6[INET6_ADDRSTRLEN];
#if defined (ARRAY_VARS)
  SHELL_VAR *v = NULL;
  if (var)
    {
      if (valid_identifier ((char *) var) == 0) { sh_invalidid ((char *) var); return; }
      v = find_or_make_array_variable ((char *) var, 3);
      if (!v || readonly_p (v) || noassign_p (v) || assoc_p (v) == 0) { v = NULL; }
      else { if (invisible_p (v)) VUNSETATTR (v, att_invisible); assoc_flush (assoc_cell (v)); }
    }
#define PUT(k,val) do { if (v) bind_assoc_variable (v, (char *) var, (char *) (k), (char *) (val), ASS_FORCE); \
                        else printf ("%s=%s\n", (k), (val)); } while (0)
#else
  (void) var;
#define PUT(k,val) printf ("%s=%s\n", (k), (val))
#endif
  char num[32];
  PUT ("msg_type", d6_type_name (m->msg_type));
  snprintf (num, sizeof num, "0x%06x", m->xid); PUT ("xid", num);
  if (m->client_id_len) { hex_print (m->client_id, m->client_id_len, hexbuf, sizeof hexbuf); PUT ("client_id", hexbuf); }
  if (m->server_id_len) { hex_print (m->server_id, m->server_id_len, hexbuf, sizeof hexbuf); PUT ("server_id", hexbuf); }
  if (m->have_ia_na)
    { snprintf (num, sizeof num, "%u", m->iaid); PUT ("iaid", num);
      snprintf (num, sizeof num, "%u", m->t1); PUT ("t1", num);
      snprintf (num, sizeof num, "%u", m->t2); PUT ("t2", num); }
  if (m->have_addr)
    { if (inet_ntop (AF_INET6, m->addr, ip6, sizeof ip6)) PUT ("address", ip6);
      snprintf (num, sizeof num, "%u", m->pref_life); PUT ("preferred", num);
      snprintf (num, sizeof num, "%u", m->valid_life); PUT ("valid", num); }
  if (m->have_ia_pd)
    { snprintf (num, sizeof num, "%u", m->pd_iaid); PUT ("pd_iaid", num); }
  if (m->have_prefix)
    { char pfx[INET6_ADDRSTRLEN + 8];
      if (inet_ntop (AF_INET6, m->prefix, ip6, sizeof ip6))
        { snprintf (pfx, sizeof pfx, "%s/%d", ip6, m->prefix_len); PUT ("prefix", pfx); }
      snprintf (num, sizeof num, "%u", m->pd_valid_life); PUT ("prefix_valid", num); }
  if (m->n_dns)
    {
      char dnslist[8 * INET6_ADDRSTRLEN] = ""; size_t o = 0;
      for (int i = 0; i < m->n_dns; i++)
        if (inet_ntop (AF_INET6, m->dns[i], ip6, sizeof ip6))
          o += snprintf (dnslist + o, sizeof dnslist - o, "%s%s", o ? "," : "", ip6);
      PUT ("dns", dnslist);
    }
  if (m->have_status)
    { snprintf (num, sizeof num, "%u", m->status_code); PUT ("status", num);
      if (m->status_msg[0]) PUT ("status_msg", m->status_msg); }
  if (m->oro_len >= 2)
    {
      char orolist[256] = ""; size_t o = 0;
      for (int i = 0; i + 2 <= m->oro_len; i += 2)
        o += snprintf (orolist + o, sizeof orolist - o, "%s%u", o ? "," : "", rd16 (m->oro + i));
      PUT ("oro", orolist);
    }
#undef PUT
}

/* ---- live client exchange (slice 2) ---- */

/* DUID-LL (type 3, hwtype 1) from an interface's MAC in /sys/class/net/<if>/address. */
static int d6_iface_duid (const char *iface, unsigned char *duid, int *len)
{
  char path[128]; snprintf (path, sizeof path, "/sys/class/net/%s/address", iface);
  FILE *f = fopen (path, "r"); if (!f) return -1;
  unsigned x[6]; int n = fscanf (f, "%x:%x:%x:%x:%x:%x", &x[0], &x[1], &x[2], &x[3], &x[4], &x[5]);
  fclose (f);
  if (n != 6) return -1;
  wr16 (duid, 3); wr16 (duid + 2, 1);
  for (int i = 0; i < 6; i++) duid[4 + i] = (unsigned char) x[i];
  *len = 10;
  return 0;
}

static unsigned short d6_port (const char *env, unsigned short fb)
{ const char *s = getenv (env); if (!s || !*s) return fb;
  unsigned long v = strtoul (s, NULL, 10); return (v >= 1 && v <= 65535) ? (unsigned short) v : fb; }

/* Receive one DHCPv6 message of `want` type (or any if want<0) with matching xid,
 * within timeout_ms. Returns length, or -1 on timeout/error. */
static int d6_recv (int fd, unsigned char *buf, size_t cap, int timeout_ms, int want, unsigned xid)
{
  for (;;)
    {
      struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
      fd_set rf; FD_ZERO (&rf); FD_SET (fd, &rf);
      int sr = select (fd + 1, &rf, NULL, NULL, &tv);
      if (sr <= 0) return -1;                                  /* timeout / error */
      ssize_t n = recv (fd, buf, cap, 0);
      if (n < 4) continue;
      unsigned rxid = ((unsigned) buf[1] << 16) | ((unsigned) buf[2] << 8) | buf[3];
      if (rxid != xid) continue;
      if (want >= 0 && buf[0] != want) continue;
      return (int) n;
    }
}

/* Full SOLICIT->ADVERTISE->REQUEST->REPLY. dest is the server address
 * (ff02::1:2 multicast by default, or a unicast override). Returns 0 + fills
 * the REPLY in `m`, or -1. */
static int d6_solicit_exchange (const char *iface, const char *dest_str,
                                const unsigned char *cid, int cid_len, unsigned iaid,
                                const unsigned char *oro, int oro_len,
                                int rapid, int want_pd, unsigned pd_iaid,
                                int timeout_ms, struct d6_msg *reply)
{
  unsigned ifindex = iface && *iface ? if_nametoindex (iface) : 0;
  if (iface && *iface && ifindex == 0) { builtin_error ("solicit: no such interface: %s", iface); return -1; }

  struct sockaddr_in6 dst; memset (&dst, 0, sizeof dst);
  dst.sin6_family = AF_INET6;
  dst.sin6_port = htons (d6_port ("BASHDHCP6_SERVER_PORT", 547));
  dst.sin6_scope_id = ifindex;
  if (inet_pton (AF_INET6, dest_str, &dst.sin6_addr) != 1) { builtin_error ("solicit: bad dest %s", dest_str); return -1; }

  int fd = socket (AF_INET6, SOCK_DGRAM, 0);
  if (fd < 0) { builtin_error ("solicit: socket: %s", strerror (errno)); return -1; }
  int one = 1; setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  if (iface && *iface)
    { setsockopt (fd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen (iface));
      setsockopt (fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof ifindex); }
  struct sockaddr_in6 la; memset (&la, 0, sizeof la);
  la.sin6_family = AF_INET6; la.sin6_addr = in6addr_any;
  la.sin6_port = htons (d6_port ("BASHDHCP6_CLIENT_PORT", 546));
  if (bind (fd, (struct sockaddr *) &la, sizeof la) < 0)
    { builtin_error ("solicit: bind [::]:546: %s", strerror (errno)); close (fd); return -1; }

  unsigned xid = (unsigned) (time (NULL) & 0xffffff);
  unsigned char buf[D6_MAX]; size_t n;

  /* SOLICIT (retransmit up to 3×) → ADVERTISE (or REPLY when rapid-commit) */
  n = d6_build (buf, sizeof buf, D6_SOLICIT, xid, cid, cid_len, NULL, 0, iaid, 0, NULL, 0, 0,
                rapid, 1, want_pd, pd_iaid, oro, oro_len);
  if (!n) { close (fd); return -1; }
  struct d6_msg adv; int got = 0, rapid_done = 0;
  for (int try = 0; try < 3 && !got; try++)
    {
      if (sendto (fd, buf, n, 0, (struct sockaddr *) &dst, sizeof dst) < 0)
        { builtin_error ("solicit: sendto: %s", strerror (errno)); close (fd); return -1; }
      unsigned char rb[D6_MAX];
      int rn = d6_recv (fd, rb, sizeof rb, timeout_ms, -1, xid);   /* any matching-xid reply */
      if (rn > 0 && d6_parse (rb, rn, &adv) == 0)
        {
          if (rapid && adv.msg_type == D6_REPLY) { *reply = adv; rapid_done = 1; got = 1; }
          else if (adv.msg_type == D6_ADVERTISE) got = 1;
        }
    }
  if (!got) { builtin_error ("solicit: no ADVERTISE (timeout)"); close (fd); return -1; }
  if (rapid_done) { close (fd); return 0; }                        /* rapid-commit: REPLY is final */
  if (adv.server_id_len <= 0 || (!adv.have_addr && !adv.have_prefix))
    { builtin_error ("solicit: ADVERTISE missing SERVERID/address"); close (fd); return -1; }

  /* REQUEST the advertised address/prefix → REPLY */
  unsigned xid2 = (xid + 1) & 0xffffff;
  n = d6_build (buf, sizeof buf, D6_REQUEST, xid2, cid, cid_len, adv.server_id, adv.server_id_len,
                iaid, adv.have_addr, adv.addr, adv.pref_life ? adv.pref_life : 3600,
                adv.valid_life ? adv.valid_life : 7200,
                0, 1, want_pd, pd_iaid, oro, oro_len);
  if (!n) { close (fd); return -1; }
  got = 0;
  for (int try = 0; try < 3 && !got; try++)
    {
      if (sendto (fd, buf, n, 0, (struct sockaddr *) &dst, sizeof dst) < 0)
        { builtin_error ("solicit: REQUEST sendto: %s", strerror (errno)); close (fd); return -1; }
      unsigned char rb[D6_MAX];
      int rn = d6_recv (fd, rb, sizeof rb, timeout_ms, D6_REPLY, xid2);
      if (rn > 0 && d6_parse (rb, rn, reply) == 0) got = 1;
    }
  close (fd);
  if (!got) { builtin_error ("solicit: no REPLY (timeout)"); return -1; }
  return 0;
}

/* ---- builtin entry ---- */
int dhcp6_builtin (WORD_LIST *list)
{
  char *argv[64]; int argc = 0;
  for (WORD_LIST *p = list; p && argc < 64; p = p->next) argv[argc++] = p->word->word;
  if (argc == 0) { builtin_usage (); return EX_USAGE; }
  const char *cmd = argv[0];

  if (!strcmp (cmd, "--version") || !strcmp (cmd, "-V"))
    { printf ("dhcp6 (bash-os F03 DHCPv6) RFC 8415 client message core\n"); return EXECUTION_SUCCESS; }
  if (!strcmp (cmd, "-h") || !strcmp (cmd, "--help")) { builtin_usage (); return EXECUTION_SUCCESS; }

  if (!strcmp (cmd, "duid-ll"))
    {
      if (argc != 2) { builtin_error ("duid-ll MAC"); return EX_USAGE; }
      unsigned x[6];
      if (sscanf (argv[1], "%x:%x:%x:%x:%x:%x", &x[0], &x[1], &x[2], &x[3], &x[4], &x[5]) != 6)
        { builtin_error ("duid-ll: bad MAC: %s", argv[1]); return EX_USAGE; }
      unsigned char duid[10]; wr16 (duid, 3); wr16 (duid + 2, 1);
      for (int i = 0; i < 6; i++) duid[4 + i] = (unsigned char) x[i];
      char hb[24]; hex_print (duid, 10, hb, sizeof hb); printf ("%s\n", hb);
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (cmd, "build"))
    {
      if (argc < 2) { builtin_error ("build TYPE -d DUID ..."); return EX_USAGE; }
      int mt = d6_type_num (argv[1]);
      if (mt < 0) { builtin_error ("build: unknown message type: %s", argv[1]); return EX_USAGE; }
      unsigned char cid[132], sid[132], addr[16], oro[64];
      int cid_len = 0, sid_len = 0, have_addr = 0, oro_len = 0, rapid = 0, want_pd = 0;
      unsigned iaid = 1, xid = (unsigned) (time (NULL) & 0xffffff), pref = 0, valid = 0, pd_iaid = 1;
      const char *var = NULL;
      for (int i = 2; i < argc; i++)
        {
          if (!strcmp (argv[i], "-d") && i + 1 < argc) { cid_len = hex_decode (argv[++i], cid, sizeof cid); if (cid_len < 0) { builtin_error ("build: bad -d DUID hex"); return EX_USAGE; } }
          else if (!strcmp (argv[i], "-s") && i + 1 < argc) { sid_len = hex_decode (argv[++i], sid, sizeof sid); if (sid_len < 0) { builtin_error ("build: bad -s DUID hex"); return EX_USAGE; } }
          else if (!strcmp (argv[i], "-i") && i + 1 < argc) iaid = (unsigned) strtoul (argv[++i], NULL, 0);
          else if (!strcmp (argv[i], "-x") && i + 1 < argc) xid = (unsigned) (strtoul (argv[++i], NULL, 16) & 0xffffff);
          else if (!strcmp (argv[i], "-a") && i + 1 < argc) { if (inet_pton (AF_INET6, argv[++i], addr) != 1) { builtin_error ("build: bad -a IPv6 addr"); return EX_USAGE; } have_addr = 1; pref = 3600; valid = 7200; }
          else if (!strcmp (argv[i], "-o") && i + 1 < argc)
            { char *t = argv[++i], *save = NULL; for (char *k = strtok_r (t, ",", &save); k && oro_len + 2 <= (int) sizeof oro; k = strtok_r (NULL, ",", &save)) { wr16 (oro + oro_len, (unsigned) atoi (k)); oro_len += 2; } }
          else if (!strcmp (argv[i], "--rapid")) rapid = 1;
          else if (!strcmp (argv[i], "--pd")) { want_pd = 1; if (i + 1 < argc && argv[i + 1][0] != '-') pd_iaid = (unsigned) strtoul (argv[++i], NULL, 0); }
          else if (!strcmp (argv[i], "-V") && i + 1 < argc) var = argv[++i];
          else { builtin_error ("build: unexpected arg: %s", argv[i]); return EX_USAGE; }
        }
      if (cid_len <= 0) { builtin_error ("build: -d CLIENT_DUID required"); return EX_USAGE; }
      if ((mt == D6_REQUEST || mt == D6_RENEW || mt == D6_RELEASE || mt == D6_DECLINE) && sid_len <= 0)
        { builtin_error ("build: %s requires -s SERVER_DUID", argv[1]); return EX_USAGE; }
      int include_ia_na = (mt != D6_INFOREQ);     /* INFORMATION-REQUEST carries no IA */
      unsigned char buf[D6_MAX];
      size_t n = d6_build (buf, sizeof buf, mt, xid, cid, cid_len, sid, sid_len,
                           iaid, have_addr, addr, pref, valid,
                           rapid, include_ia_na, want_pd, pd_iaid, oro, oro_len);
      if (!n) { builtin_error ("build: message too large"); return EXECUTION_FAILURE; }
      char *hb = malloc (n * 2 + 1); if (!hb) return EXECUTION_FAILURE;
      hex_print (buf, (int) n, hb, n * 2 + 1);
      if (var) builtin_bind_variable ((char *) var, hb, 0);
      else printf ("%s\n", hb);
      free (hb);
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (cmd, "parse"))
    {
      const char *hex = NULL, *var = NULL;
      for (int i = 1; i < argc; i++)
        { if (!strcmp (argv[i], "-V") && i + 1 < argc) var = argv[++i];
          else if (!hex) hex = argv[i];
          else { builtin_error ("parse: extra arg: %s", argv[i]); return EX_USAGE; } }
      if (!hex) { builtin_error ("parse HEX [-V VAR]"); return EX_USAGE; }
      unsigned char pkt[D6_MAX];
      int n = hex_decode (hex, pkt, sizeof pkt);
      if (n < 0) { builtin_error ("parse: bad hex"); return EX_USAGE; }
      struct d6_msg m;
      if (d6_parse (pkt, n, &m) < 0) { builtin_error ("parse: malformed DHCPv6 message"); return EXECUTION_FAILURE; }
      d6_emit (&m, var);
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (cmd, "solicit"))
    {
      const char *iface = NULL, *duidhex = NULL, *dest = "ff02::1:2", *var = NULL;
      unsigned iaid = 1, pd_iaid = 1; int timeout_ms = 3000, oro_len = 0, rapid = 0, want_pd = 0;
      unsigned char oro[64];
      wr16 (oro, D6O_DNS_SERVERS); oro_len = 2;            /* default ORO: DNS */
      for (int i = 1; i < argc; i++)
        {
          if (!strcmp (argv[i], "-i") && i + 1 < argc) iface = argv[++i];
          else if (!strcmp (argv[i], "-d") && i + 1 < argc) duidhex = argv[++i];
          else if (!strcmp (argv[i], "-S") && i + 1 < argc) dest = argv[++i];
          else if (!strcmp (argv[i], "--iaid") && i + 1 < argc) iaid = (unsigned) strtoul (argv[++i], NULL, 0);
          else if (!strcmp (argv[i], "-w") && i + 1 < argc) timeout_ms = atoi (argv[++i]) * 1000;
          else if (!strcmp (argv[i], "--rapid")) rapid = 1;
          else if (!strcmp (argv[i], "--pd")) { want_pd = 1; if (i + 1 < argc && argv[i + 1][0] != '-') pd_iaid = (unsigned) strtoul (argv[++i], NULL, 0); }
          else if (!strcmp (argv[i], "-o") && i + 1 < argc)
            { oro_len = 0; char *t = argv[++i], *save = NULL;
              for (char *k = strtok_r (t, ",", &save); k && oro_len + 2 <= (int) sizeof oro; k = strtok_r (NULL, ",", &save))
                { wr16 (oro + oro_len, (unsigned) atoi (k)); oro_len += 2; } }
          else if (!strcmp (argv[i], "-V") && i + 1 < argc) var = argv[++i];
          else { builtin_error ("solicit: unexpected arg: %s", argv[i]); return EX_USAGE; }
        }
      if (!iface && !duidhex) { builtin_error ("solicit: need -i IFACE (for the client DUID) or -d DUID"); return EX_USAGE; }
      unsigned char cid[132]; int cid_len = 0;
      if (duidhex) { cid_len = hex_decode (duidhex, cid, sizeof cid); if (cid_len <= 0) { builtin_error ("solicit: bad -d DUID hex"); return EX_USAGE; } }
      else if (d6_iface_duid (iface, cid, &cid_len) < 0) { builtin_error ("solicit: cannot read MAC for %s (use -d DUID)", iface); return EXECUTION_FAILURE; }
      struct d6_msg reply;
      if (d6_solicit_exchange (iface, dest, cid, cid_len, iaid, oro, oro_len,
                               rapid, want_pd, pd_iaid, timeout_ms, &reply) < 0)
        return EXECUTION_FAILURE;
      d6_emit (&reply, var);
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (cmd, "inforequest"))
    {
      /* stateless config: INFORMATION-REQUEST -> REPLY (no IA, just ORO). */
      const char *iface = NULL, *duidhex = NULL, *dest = "ff02::1:2", *var = NULL;
      int timeout_ms = 3000, oro_len = 0;
      unsigned char oro[64];
      wr16 (oro, D6O_DNS_SERVERS); wr16 (oro + 2, D6O_DOMAIN_LIST); oro_len = 4;
      for (int i = 1; i < argc; i++)
        {
          if (!strcmp (argv[i], "-i") && i + 1 < argc) iface = argv[++i];
          else if (!strcmp (argv[i], "-d") && i + 1 < argc) duidhex = argv[++i];
          else if (!strcmp (argv[i], "-S") && i + 1 < argc) dest = argv[++i];
          else if (!strcmp (argv[i], "-w") && i + 1 < argc) timeout_ms = atoi (argv[++i]) * 1000;
          else if (!strcmp (argv[i], "-o") && i + 1 < argc)
            { oro_len = 0; char *t = argv[++i], *save = NULL;
              for (char *k = strtok_r (t, ",", &save); k && oro_len + 2 <= (int) sizeof oro; k = strtok_r (NULL, ",", &save))
                { wr16 (oro + oro_len, (unsigned) atoi (k)); oro_len += 2; } }
          else if (!strcmp (argv[i], "-V") && i + 1 < argc) var = argv[++i];
          else { builtin_error ("inforequest: unexpected arg: %s", argv[i]); return EX_USAGE; }
        }
      if (!iface && !duidhex) { builtin_error ("inforequest: need -i IFACE or -d DUID"); return EX_USAGE; }
      unsigned char cid[132]; int cid_len = 0;
      if (duidhex) { cid_len = hex_decode (duidhex, cid, sizeof cid); if (cid_len <= 0) { builtin_error ("inforequest: bad -d DUID hex"); return EX_USAGE; } }
      else if (d6_iface_duid (iface, cid, &cid_len) < 0) { builtin_error ("inforequest: cannot read MAC for %s", iface); return EXECUTION_FAILURE; }

      unsigned ifindex = iface && *iface ? if_nametoindex (iface) : 0;
      if (iface && *iface && ifindex == 0) { builtin_error ("inforequest: no such interface: %s", iface); return EXECUTION_FAILURE; }
      struct sockaddr_in6 dst; memset (&dst, 0, sizeof dst);
      dst.sin6_family = AF_INET6; dst.sin6_port = htons (d6_port ("BASHDHCP6_SERVER_PORT", 547));
      dst.sin6_scope_id = ifindex;
      if (inet_pton (AF_INET6, dest, &dst.sin6_addr) != 1) { builtin_error ("inforequest: bad dest %s", dest); return EX_USAGE; }
      int fd = socket (AF_INET6, SOCK_DGRAM, 0);
      if (fd < 0) { builtin_error ("inforequest: socket: %s", strerror (errno)); return EXECUTION_FAILURE; }
      int one = 1; setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
      if (iface && *iface)
        { setsockopt (fd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen (iface));
          setsockopt (fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof ifindex); }
      struct sockaddr_in6 la; memset (&la, 0, sizeof la);
      la.sin6_family = AF_INET6; la.sin6_addr = in6addr_any; la.sin6_port = htons (d6_port ("BASHDHCP6_CLIENT_PORT", 546));
      if (bind (fd, (struct sockaddr *) &la, sizeof la) < 0)
        { builtin_error ("inforequest: bind [::]:546: %s", strerror (errno)); close (fd); return EXECUTION_FAILURE; }
      unsigned xid = (unsigned) (time (NULL) & 0xffffff);
      unsigned char buf[D6_MAX];
      size_t n = d6_build (buf, sizeof buf, D6_INFOREQ, xid, cid, cid_len, NULL, 0,
                           0, 0, NULL, 0, 0, 0, 0 /*no IA_NA*/, 0, 0, oro, oro_len);
      if (!n) { close (fd); return EXECUTION_FAILURE; }
      struct d6_msg reply; int got = 0;
      for (int try = 0; try < 3 && !got; try++)
        {
          if (sendto (fd, buf, n, 0, (struct sockaddr *) &dst, sizeof dst) < 0)
            { builtin_error ("inforequest: sendto: %s", strerror (errno)); close (fd); return EXECUTION_FAILURE; }
          unsigned char rb[D6_MAX];
          int rn = d6_recv (fd, rb, sizeof rb, timeout_ms, D6_REPLY, xid);
          if (rn > 0 && d6_parse (rb, rn, &reply) == 0) got = 1;
        }
      close (fd);
      if (!got) { builtin_error ("inforequest: no REPLY (timeout)"); return EXECUTION_FAILURE; }
      d6_emit (&reply, var);
      return EXECUTION_SUCCESS;
    }

  /* F03 relay: wrap a client message in RELAY-FORW (relay-agent side). */
  if (!strcmp (cmd, "relay-wrap"))
    {
      const char *link = NULL, *peer = NULL, *ifid = NULL, *inner = NULL, *var = NULL;
      int hop = 0;
      for (int i = 1; i < argc; i++)
        {
          if (!strcmp (argv[i], "--link") && i + 1 < argc) link = argv[++i];
          else if (!strcmp (argv[i], "--peer") && i + 1 < argc) peer = argv[++i];
          else if (!strcmp (argv[i], "--interface-id") && i + 1 < argc) ifid = argv[++i];
          else if (!strcmp (argv[i], "--hop") && i + 1 < argc) hop = atoi (argv[++i]);
          else if (!strcmp (argv[i], "-V") && i + 1 < argc) var = argv[++i];
          else if (argv[i][0] != '-' && !inner) inner = argv[i];
          else { builtin_error ("relay-wrap: unexpected arg: %s", argv[i]); return EX_USAGE; }
        }
      if (!inner) { builtin_error ("relay-wrap: needs INNER_HEX [--link ADDR] [--peer ADDR] [--interface-id ID] [--hop N]"); return EX_USAGE; }
      if (hop < 0 || hop > 32) { builtin_error ("relay-wrap: --hop out of range (0..32)"); return EX_USAGE; }
      unsigned char link6[16] = {0}, peer6[16] = {0};
      if (link && inet_pton (AF_INET6, link, link6) != 1) { builtin_error ("relay-wrap: bad --link addr: %s", link); return EX_USAGE; }
      if (peer && inet_pton (AF_INET6, peer, peer6) != 1) { builtin_error ("relay-wrap: bad --peer addr: %s", peer); return EX_USAGE; }
      unsigned char innerb[D6_MAX];
      int innerlen = hex_decode (inner, innerb, sizeof innerb);
      if (innerlen < 4) { builtin_error ("relay-wrap: bad/short INNER_HEX"); return EX_USAGE; }
      unsigned char buf[D6_MAX];
      size_t p = 0;
      buf[p++] = D6_RELAY_FORW; buf[p++] = (unsigned char) hop;
      memcpy (buf + p, link6, 16); p += 16;
      memcpy (buf + p, peer6, 16); p += 16;
      p = d6_opt (buf, p, sizeof buf, D6O_RELAY_MSG, innerb, (size_t) innerlen);
      if (!p) { builtin_error ("relay-wrap: message too large"); return EXECUTION_FAILURE; }
      if (ifid)
        { p = d6_opt (buf, p, sizeof buf, D6O_INTERFACE_ID, (const unsigned char *) ifid, strlen (ifid));
          if (!p) { builtin_error ("relay-wrap: message too large"); return EXECUTION_FAILURE; } }
      char *hb = malloc (p * 2 + 1); if (!hb) return EXECUTION_FAILURE;
      hex_print (buf, (int) p, hb, p * 2 + 1);
      if (var) builtin_bind_variable ((char *) var, hb, 0);
      else printf ("%s\n", hb);
      free (hb);
      return EXECUTION_SUCCESS;
    }

  /* F03 relay: decapsulate a RELAY-FORW/REPL → inner message + link/peer/ifid. */
  if (!strcmp (cmd, "relay-unwrap"))
    {
      const char *hex = NULL, *var = NULL;
      for (int i = 1; i < argc; i++)
        { if (!strcmp (argv[i], "-V") && i + 1 < argc) var = argv[++i];
          else if (argv[i][0] != '-' && !hex) hex = argv[i];
          else { builtin_error ("relay-unwrap: unexpected arg: %s", argv[i]); return EX_USAGE; } }
      if (!hex) { builtin_error ("relay-unwrap RELAY_HEX [-V VAR]"); return EX_USAGE; }
      unsigned char pkt[D6_MAX];
      int n = hex_decode (hex, pkt, sizeof pkt);
      if (n < 0) { builtin_error ("relay-unwrap: bad hex"); return EX_USAGE; }
      if (n < 34) { builtin_error ("relay-unwrap: too short for a relay message"); return EXECUTION_FAILURE; }
      if (pkt[0] != D6_RELAY_FORW && pkt[0] != D6_RELAY_REPL)
        { builtin_error ("relay-unwrap: not a RELAY-FORW/REPL message (type=%u)", pkt[0]); return EXECUTION_FAILURE; }
      char link6[INET6_ADDRSTRLEN] = "", peer6[INET6_ADDRSTRLEN] = "";
      inet_ntop (AF_INET6, pkt + 2, link6, sizeof link6);
      inet_ntop (AF_INET6, pkt + 18, peer6, sizeof peer6);
      const unsigned char *inner = NULL; int inner_len = 0;
      char ifid[256] = ""; int have_ifid = 0;
      for (int q = 34; q + 4 <= n; )
        {
          unsigned code = rd16 (pkt + q), olen = rd16 (pkt + q + 2);
          if (q + 4 + (int) olen > n) break;
          const unsigned char *v = pkt + q + 4;
          if (code == D6O_RELAY_MSG) { inner = v; inner_len = (int) olen; }
          else if (code == D6O_INTERFACE_ID)
            { int l = (int) olen; if (l > (int) sizeof ifid - 1) l = sizeof ifid - 1;
              memcpy (ifid, v, l); ifid[l] = '\0'; have_ifid = 1; }
          q += 4 + olen;
        }
      if (!inner) { builtin_error ("relay-unwrap: no OPTION_RELAY_MSG"); return EXECUTION_FAILURE; }
      char *innerhex = malloc ((size_t) inner_len * 2 + 1); if (!innerhex) return EXECUTION_FAILURE;
      hex_print (inner, inner_len, innerhex, (size_t) inner_len * 2 + 1);
#if defined (ARRAY_VARS)
      SHELL_VAR *av = NULL;
      if (var)
        {
          if (valid_identifier ((char *) var) == 0) { sh_invalidid ((char *) var); free (innerhex); return EXECUTION_FAILURE; }
          av = find_or_make_array_variable ((char *) var, 3);
          if (!av || readonly_p (av) || noassign_p (av) || assoc_p (av) == 0) av = NULL;
          else { if (invisible_p (av)) VUNSETATTR (av, att_invisible); assoc_flush (assoc_cell (av)); }
        }
#define RPUT(k,val) do { if (av) bind_assoc_variable (av, (char *) var, (char *) (k), (char *) (val), ASS_FORCE); \
                         else printf ("%s=%s\n", (k), (val)); } while (0)
#else
      (void) var;
#define RPUT(k,val) printf ("%s=%s\n", (k), (val))
#endif
      char num[16];
      RPUT ("type", pkt[0] == D6_RELAY_FORW ? "RELAY-FORW" : "RELAY-REPL");
      snprintf (num, sizeof num, "%d", pkt[1]); RPUT ("hop", num);
      RPUT ("link", link6);
      RPUT ("peer", peer6);
      if (have_ifid) RPUT ("interface_id", ifid);
      RPUT ("inner", innerhex);
#undef RPUT
      free (innerhex);
      return EXECUTION_SUCCESS;
    }

  /* F03: verify a server RECONFIGURE's RKAP authentication (OPTION_AUTH
     protocol 3 / algo 1 = HMAC-MD5 over the whole message with the digest
     zeroed) and report the requested reconfigure message-type. rc 0 only when
     the HMAC verifies. */
  if (!strcmp (cmd, "reconfigure-verify"))
    {
      const char *hex = NULL, *key_h = NULL, *var = NULL;
      for (int i = 1; i < argc; i++)
        {
          if (!strcmp (argv[i], "--key") && i + 1 < argc) key_h = argv[++i];
          else if (!strcmp (argv[i], "-V") && i + 1 < argc) var = argv[++i];
          else if (argv[i][0] != '-' && !hex) hex = argv[i];
          else { builtin_error ("reconfigure-verify: unexpected arg: %s", argv[i]); return EX_USAGE; }
        }
      if (!hex || !key_h) { builtin_error ("reconfigure-verify HEX --key HEX [-V VAR]"); return EX_USAGE; }
      unsigned char pkt[D6_MAX]; int n = hex_decode (hex, pkt, sizeof pkt);
      if (n < 4) { builtin_error ("reconfigure-verify: bad/short hex"); return EX_USAGE; }
      unsigned char key[64]; int keylen = hex_decode (key_h, key, sizeof key);
      if (keylen <= 0) { builtin_error ("reconfigure-verify: bad --key hex"); return EX_USAGE; }
      if (pkt[0] != D6_RECONFIGURE) { builtin_error ("reconfigure-verify: not a RECONFIGURE message (type=%u)", pkt[0]); return EXECUTION_FAILURE; }
      /* locate OPTION_AUTH + OPTION_RECONF_MSG; remember the digest offset */
      int auth_ok_fields = 0, reconf_mt = -1, digest_off = -1;
      unsigned char rx_digest[16];
      for (int q = 4; q + 4 <= n; )
        {
          unsigned code = rd16 (pkt + q), olen = rd16 (pkt + q + 2);
          if (q + 4 + (int) olen > n) break;
          const unsigned char *v = pkt + q + 4;
          if (code == D6O_AUTH && olen >= 28 && v[0] == 3 && v[1] == 1 && v[11] == 2)
            { /* proto 3, algo 1, authinfo type 2 at v[11]; digest at v[12..27] */
              auth_ok_fields = 1;
              memcpy (rx_digest, v + 12, 16);
              digest_off = (q + 4) + 12;
            }
          else if (code == D6O_RECONF_MSG && olen >= 1)
            reconf_mt = v[0];
          q += 4 + olen;
        }
      int valid = 0;
      if (auth_ok_fields && digest_off >= 0)
        {
          unsigned char tmp[D6_MAX]; memcpy (tmp, pkt, n);
          memset (tmp + digest_off, 0, 16);              /* zero digest for HMAC */
          unsigned char calc[16];
          d6_hmac_md5 (key, (size_t) keylen, tmp, n, calc);
          valid = (memcmp (calc, rx_digest, 16) == 0);
        }
#if defined (ARRAY_VARS)
      SHELL_VAR *av = NULL;
      if (var)
        {
          if (valid_identifier ((char *) var) == 0) { sh_invalidid ((char *) var); return EXECUTION_FAILURE; }
          av = find_or_make_array_variable ((char *) var, 3);
          if (!av || readonly_p (av) || noassign_p (av) || assoc_p (av) == 0) av = NULL;
          else { if (invisible_p (av)) VUNSETATTR (av, att_invisible); assoc_flush (assoc_cell (av)); }
        }
#define VPUT(k,val) do { if (av) bind_assoc_variable (av, (char *) var, (char *) (k), (char *) (val), ASS_FORCE); \
                         else printf ("%s=%s\n", (k), (val)); } while (0)
#else
      (void) var;
#define VPUT(k,val) printf ("%s=%s\n", (k), (val))
#endif
      VPUT ("auth", valid ? "ok" : "fail");
      if (reconf_mt >= 0) VPUT ("reconf", d6_type_name (reconf_mt));
#undef VPUT
      return valid ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }

  builtin_error ("unknown verb: %s (try duid-ll/build/parse/solicit/inforequest/relay-wrap/relay-unwrap/reconfigure-verify/--version)", cmd);
  return EX_USAGE;
}

char *dhcp6_doc[] = {
  "DHCPv6 (RFC 8415) client message builder + parser.",
  "",
  "    dhcp6 duid-ll MAC                      DUID-LL hex from a MAC.",
  "    dhcp6 build TYPE -d CLIENT_DUID [-s SERVER_DUID] [-i IAID]",
  "        [-a IPV6] [-x XID_HEX] [-o CODE,CODE] [-V VAR]",
  "        TYPE: solicit|request|renew|release|confirm|rebind|decline|",
  "        information-request. Emits the message hex (or binds VAR).",
  "    dhcp6 parse HEX [-V VAR]               decode msg-type/xid/DUIDs/",
  "        IA_NA/IAADDR/DNS/status/ORO (print or assoc-array bind).",
  "    dhcp6 relay-wrap --link ADDR --peer ADDR [--interface-id ID]",
  "        [--hop N] INNER_HEX                    build RELAY-FORW(12).",
  "    dhcp6 relay-unwrap RELAY_HEX [-V VAR]  unwrap RELAY-FORW/REPL,",
  "        reporting link/peer/interface-id plus the inner message hex.",
  "    dhcp6 reconfigure-verify HEX --key HEX [-V VAR]",
  "        Verify RKAP OPTION_AUTH on RECONFIGURE(10); rc 0 only on HMAC match.",
  "    dhcp6 solicit -i IFACE [-d DUID] [-S DEST] [--iaid N] [-o CODES]",
  "        [-w SECS] [-V VAR]    Live SOLICIT->ADVERTISE->REQUEST->REPLY; DEST",
  "        defaults to ff02::1:2 (use -S ::1 / a unicast addr to target a host).",
  "        Emits the granted lease (address/DNS/lifetimes) or binds VAR.",
  "    dhcp6 --version",
  "",
  "Wire core, relay, and RECONFIGURE verify are host-testable; `solicit` needs",
  "an IPv6 link / a reachable server.",
  "See research/bash-os/F03-DHCPv6-DESIGN.md.",
  (char *) NULL
};

struct builtin dhcp6_struct = {
  "dhcp6",
  dhcp6_builtin,
  BUILTIN_ENABLED,
  dhcp6_doc,
  "dhcp6 duid-ll|build|parse|solicit|relay-wrap|relay-unwrap|reconfigure-verify|--version ARGS",
  0
};
