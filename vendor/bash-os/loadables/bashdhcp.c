/* SPDX-License-Identifier: MIT */
/* bashdhcp.c - small DHCPv4 client/parser for bash-os.
 *
 * v1 keeps the RFC 2131 DISCOVER/OFFER/REQUEST/ACK path in C and exposes
 * parse-message for fixture tests and operator debugging. Interface
 * configuration intentionally remains in dhcp.sh via bashio.
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
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "loadables.h"

#define BDHCP_MAGIC 0x63825363U
#define BDHCP_MIN_PACKET 240
#define BDHCP_MAX_PACKET 1500

typedef struct bdhcp_lease {
  char ip[16], netmask[16], gateway[16], dns[128], ntp[128], domain[128];
  char server_id[16], broadcast[16], options_raw[1024];
  char next_server[16], tftp_server[128], bootfile[128];  /* PXE: siaddr + opt 66/67 */
  unsigned lease_time, renew_time, rebind_time, mtu;
  unsigned msg_type;
} bdhcp_lease;

static unsigned
rd32 (const unsigned char *p)
{
  return ((unsigned) p[0] << 24) | ((unsigned) p[1] << 16) |
         ((unsigned) p[2] << 8) | (unsigned) p[3];
}

static void
wr32 (unsigned char *p, unsigned v)
{
  p[0] = (unsigned char) (v >> 24);
  p[1] = (unsigned char) (v >> 16);
  p[2] = (unsigned char) (v >> 8);
  p[3] = (unsigned char) v;
}

static void
ip4 (const unsigned char *p, char *out, size_t outsz)
{
  snprintf (out, outsz, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
}

static int
hexval (int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int
hex_decode (const char *hex, unsigned char *out, size_t outsz)
{
  size_t n = 0;
  int hi = -1;
  for (const char *p = hex; *p; p++)
    {
      if (isspace ((unsigned char) *p)) continue;
      int v = hexval ((unsigned char) *p);
      if (v < 0) return -1;
      if (hi < 0) hi = v;
      else
        {
          if (n >= outsz) return -1;
          out[n++] = (unsigned char) ((hi << 4) | v);
          hi = -1;
        }
    }
  return hi < 0 ? (int) n : -1;
}

static int
parse_ip (const char *s, unsigned char out[4])
{
  struct in_addr a;
  if (!s || inet_pton (AF_INET, s, &a) != 1) return -1;
  memcpy (out, &a.s_addr, 4);
  return 0;
}

static unsigned short
env_port (const char *name, unsigned short fallback)
{
  const char *s = getenv (name);
  if (!s || !*s) return fallback;
  char *end = NULL;
  unsigned long v = strtoul (s, &end, 10);
  if (*end || v < 1 || v > 65535)
    {
      builtin_warning ("%s=%s invalid; using %u", name, s, fallback);
      return fallback;
    }
  return (unsigned short) v;
}

static int
env_server_addr (struct sockaddr_in *dst)
{
  const char *s = getenv ("BASHDHCP_SERVER_ADDR");
  if (!s || !*s)
    {
      dst->sin_addr.s_addr = htonl (INADDR_BROADCAST);
      return 0;
    }
  if (inet_pton (AF_INET, s, &dst->sin_addr) != 1)
    {
      builtin_error ("BASHDHCP_SERVER_ADDR invalid IPv4: %s", s);
      return -1;
    }
  return 0;
}

static int
lease_set (bdhcp_lease *l, const char *key, const char *val)
{
  if (strcmp (key, "ip") == 0 || strcmp (key, "address") == 0)
    snprintf (l->ip, sizeof l->ip, "%s", val);
  else if (strcmp (key, "server_id") == 0 || strcmp (key, "server") == 0)
    snprintf (l->server_id, sizeof l->server_id, "%s", val);
  else if (strcmp (key, "netmask") == 0)
    snprintf (l->netmask, sizeof l->netmask, "%s", val);
  else if (strcmp (key, "gateway") == 0)
    snprintf (l->gateway, sizeof l->gateway, "%s", val);
  else if (strcmp (key, "dns") == 0)
    snprintf (l->dns, sizeof l->dns, "%s", val);
  else if (strcmp (key, "lease_time") == 0 || strcmp (key, "lease") == 0)
    l->lease_time = (unsigned) strtoul (val, NULL, 10);
  else if (strcmp (key, "renew_time") == 0 || strcmp (key, "renew") == 0)
    l->renew_time = (unsigned) strtoul (val, NULL, 10);
  return 0;
}

static int
parse_lease_text (const char *text, bdhcp_lease *l)
{
  memset (l, 0, sizeof *l);
  char *copy = strdup (text ? text : "");
  if (!copy) return -1;
  for (char *p = copy; p && *p; )
    {
      while (*p == ' ' || *p == '\t' || *p == '\n' || *p == ';' || *p == ',') p++;
      if (!*p) break;
      char *eq = strchr (p, '=');
      if (!eq) { free (copy); return -1; }
      *eq = '\0';
      char *val = eq + 1;
      char *end = strpbrk (val, "\n;,");
      if (end) *end++ = '\0';
      size_t vlen = strlen (val);
      if (vlen >= 2 && (*val == '"' || *val == '\'') && val[vlen - 1] == *val)
        { val[vlen - 1] = '\0'; val++; }
      lease_set (l, p, val);
      p = end;
    }
  free (copy);
  return l->ip[0] && l->server_id[0] ? 0 : -1;
}

static int
read_lease_arg (const char *arg, bdhcp_lease *l)
{
  if (!arg) return -1;
  FILE *f = fopen (arg, "r");
  if (f)
    {
      char buf[2048];
      size_t n = fread (buf, 1, sizeof buf - 1, f);
      fclose (f);
      buf[n] = '\0';
      return parse_lease_text (buf, l);
    }
  return parse_lease_text (arg, l);
}

static void
hex_append (char *out, size_t outsz, const unsigned char *p, size_t n)
{
  size_t off = strlen (out);
  for (size_t i = 0; i < n && off + 2 < outsz; i++)
    {
      snprintf (out + off, outsz - off, "%02x", p[i]);
      off += 2;
    }
}

static void
ip_list (const unsigned char *p, size_t n, char *out, size_t outsz)
{
  out[0] = '\0';
  size_t off = 0;
  for (size_t i = 0; i + 4 <= n; i += 4)
    {
      char ip[16];
      ip4 (p + i, ip, sizeof ip);
      int w = snprintf (out + off, off < outsz ? outsz - off : 0,
                        "%s%s", off ? " " : "", ip);
      if (w < 0 || off + (size_t) w >= outsz) break;
      off += (size_t) w;
    }
}

static int
parse_msg (const unsigned char *pkt, size_t len, bdhcp_lease *l)
{
  memset (l, 0, sizeof *l);
  if (len < BDHCP_MIN_PACKET) return -1;
  if (rd32 (pkt + 236) != BDHCP_MAGIC) return -1;
  ip4 (pkt + 16, l->ip, sizeof l->ip);
  /* siaddr (BOOTP "next server", off 20) — PXE next-server. 0.0.0.0 → unset. */
  if (rd32 (pkt + 20) != 0) ip4 (pkt + 20, l->next_server, sizeof l->next_server);
  /* Legacy PXE ROMs may carry the bootfile in the 128-byte BOOTP file field
   * (off 108); option 67 (below) overrides it when present. */
  if (pkt[108] && len >= 236)
    snprintf (l->bootfile, sizeof l->bootfile, "%.127s", (const char *) pkt + 108);
  strcpy (l->netmask, "255.255.255.0");
  l->lease_time = 86400;
  size_t p = 240;
  while (p < len)
    {
      unsigned code = pkt[p++];
      if (code == 0) continue;
      if (code == 255) break;
      if (p >= len) return -1;
      unsigned olen = pkt[p++];
      if (p + olen > len) return -1;
      const unsigned char *v = pkt + p;
      switch (code)
        {
        case 1: if (olen == 4) ip4 (v, l->netmask, sizeof l->netmask); break;
        case 3: if (olen >= 4) ip4 (v, l->gateway, sizeof l->gateway); break;
        case 6: ip_list (v, olen, l->dns, sizeof l->dns); break;
        case 12:
          break;
        case 15:
          {
            size_t n = olen < sizeof l->domain - 1 ? olen : sizeof l->domain - 1;
            memcpy (l->domain, v, n); l->domain[n] = '\0';
            break;
          }
        case 26: if (olen == 2) l->mtu = ((unsigned) v[0] << 8) | v[1]; break;
        case 28: if (olen == 4) ip4 (v, l->broadcast, sizeof l->broadcast); break;
        case 42: ip_list (v, olen, l->ntp, sizeof l->ntp); break;
        case 51: if (olen == 4) l->lease_time = rd32 (v); break;
        case 53: if (olen == 1) l->msg_type = v[0]; break;
        case 54: if (olen == 4) ip4 (v, l->server_id, sizeof l->server_id); break;
        case 58: if (olen == 4) l->renew_time = rd32 (v); break;
        case 59: if (olen == 4) l->rebind_time = rd32 (v); break;
        case 66:                /* TFTP server name (PXE) */
          {
            size_t n = olen < sizeof l->tftp_server - 1 ? olen : sizeof l->tftp_server - 1;
            memcpy (l->tftp_server, v, n); l->tftp_server[n] = '\0';
            break;
          }
        case 67:                /* Bootfile name (PXE) — overrides BOOTP file field */
          {
            size_t n = olen < sizeof l->bootfile - 1 ? olen : sizeof l->bootfile - 1;
            memcpy (l->bootfile, v, n); l->bootfile[n] = '\0';
            break;
          }
        default:
          {
            char tmp[8];
            snprintf (tmp, sizeof tmp, "%02x%02x", code, olen);
            strncat (l->options_raw, tmp, sizeof l->options_raw - strlen (l->options_raw) - 1);
            hex_append (l->options_raw, sizeof l->options_raw, v, olen);
            break;
          }
        }
      p += olen;
    }
  if (l->renew_time == 0) l->renew_time = l->lease_time / 2;
  return 0;
}

#if defined (ARRAY_VARS)
static int
bind_field (SHELL_VAR *v, const char *name, const char *key, const char *value)
{
  return bind_assoc_variable (v, name, savestring ((char *) key), value ? value : "", ASS_FORCE) ? 0 : -1;
}

static int
bind_lease (const char *name, const bdhcp_lease *l)
{
  if (!name) return 0;
  if (valid_identifier ((char *) name) == 0) { sh_invalidid ((char *) name); return -1; }
  SHELL_VAR *v = find_or_make_array_variable ((char *) name, 3);
  if (v == 0 || readonly_p (v) || noassign_p (v)) return -1;
  if (assoc_p (v) == 0) { builtin_error ("%s: not an associative array", name); return -1; }
  if (invisible_p (v)) VUNSETATTR (v, att_invisible);
  assoc_flush (assoc_cell (v));
  char num[32];
  bind_field (v, name, "ip", l->ip);
  bind_field (v, name, "netmask", l->netmask);
  bind_field (v, name, "gateway", l->gateway);
  bind_field (v, name, "dns", l->dns);
  bind_field (v, name, "ntp", l->ntp);
  bind_field (v, name, "domain", l->domain);
  bind_field (v, name, "server_id", l->server_id);
  bind_field (v, name, "broadcast", l->broadcast);
  bind_field (v, name, "next_server", l->next_server);
  bind_field (v, name, "tftp_server", l->tftp_server);
  bind_field (v, name, "bootfile", l->bootfile);
  snprintf (num, sizeof num, "%u", l->lease_time); bind_field (v, name, "lease_time", num);
  snprintf (num, sizeof num, "%u", l->renew_time); bind_field (v, name, "renew_time", num);
  snprintf (num, sizeof num, "%u", l->rebind_time); bind_field (v, name, "rebind_time", num);
  snprintf (num, sizeof num, "%u", l->mtu); bind_field (v, name, "mtu", num);
  snprintf (num, sizeof num, "%ld", (long) time (NULL)); bind_field (v, name, "acquired_at", num);
  bind_field (v, name, "options_raw", l->options_raw);
  return 0;
}
#else
static int bind_lease (const char *name, const bdhcp_lease *l) { (void) name; (void) l; return -1; }
#endif

static void
print_lease (const bdhcp_lease *l)
{
  printf ("ip=%s\nnetmask=%s\ngateway=%s\ndns=%s\nntp=%s\ndomain=%s\nserver_id=%s\nlease_time=%u\nrenew_time=%u\n",
          l->ip, l->netmask, l->gateway, l->dns, l->ntp, l->domain,
          l->server_id, l->lease_time, l->renew_time);
  /* PXE fields (slice 1) — only print when present, to keep the default
   * output stable for non-PXE leases. */
  if (l->next_server[0]) printf ("next_server=%s\n", l->next_server);
  if (l->tftp_server[0]) printf ("tftp_server=%s\n", l->tftp_server);
  if (l->bootfile[0])    printf ("bootfile=%s\n", l->bootfile);
}

static int
read_mac (const char *iface, unsigned char mac[6])
{
  char path[256], buf[64];
  snprintf (path, sizeof path, "/sys/class/net/%s/address", iface);
  FILE *f = fopen (path, "r");
  if (!f) { builtin_error ("no such interface: %s", iface); return -1; }
  if (!fgets (buf, sizeof buf, f)) { fclose (f); return -1; }
  fclose (f);
  unsigned x[6];
  if (sscanf (buf, "%x:%x:%x:%x:%x:%x", &x[0], &x[1], &x[2], &x[3], &x[4], &x[5]) != 6)
    return -1;
  for (int i = 0; i < 6; i++) mac[i] = (unsigned char) x[i];
  return 0;
}

static size_t
build_packet (unsigned char *pkt, size_t cap, unsigned type, unsigned xid,
              const unsigned char mac[6], const unsigned char *req_ip,
              const unsigned char *server, const unsigned char *ciaddr)
{
  if (cap < 548) return 0;
  memset (pkt, 0, 548);
  pkt[0] = 1; pkt[1] = 1; pkt[2] = 6;
  wr32 (pkt + 4, xid);
  pkt[10] = 0x80;
  if (ciaddr) memcpy (pkt + 12, ciaddr, 4);
  memcpy (pkt + 28, mac, 6);
  wr32 (pkt + 236, BDHCP_MAGIC);
  size_t p = 240;
#define OPT1(c,v) do { pkt[p++]=(c); pkt[p++]=1; pkt[p++]=(v); } while (0)
  OPT1 (53, type);
  pkt[p++] = 61; pkt[p++] = 7; pkt[p++] = 1; memcpy (pkt + p, mac, 6); p += 6;
  pkt[p++] = 12; pkt[p++] = 7; memcpy (pkt + p, "bash-os", 7); p += 7;
  if (type == 3 && req_ip && server && !ciaddr)
    {
      pkt[p++] = 50; pkt[p++] = 4; memcpy (pkt + p, req_ip, 4); p += 4;
      pkt[p++] = 54; pkt[p++] = 4; memcpy (pkt + p, server, 4); p += 4;
    }
  else if ((type == 3 || type == 7) && server)
    { pkt[p++] = 54; pkt[p++] = 4; memcpy (pkt + p, server, 4); p += 4; }
  if (type != 7)
    {
      pkt[p++] = 55; pkt[p++] = 9;
      unsigned char prl[9] = {1,3,6,15,26,28,42,58,59};
      memcpy (pkt + p, prl, sizeof prl); p += sizeof prl;
    }
  pkt[p++] = 255;
  return 548;
}

static int
recv_dhcp (int fd, unsigned xid, unsigned want_type, unsigned char *out, size_t *outlen, int timeout_ms)
{
  unsigned char buf[BDHCP_MAX_PACKET];
  struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
  fd_set rfds;
  FD_ZERO (&rfds); FD_SET (fd, &rfds);
  int sr = select (fd + 1, &rfds, NULL, NULL, &tv);
  if (sr <= 0) return -1;
  ssize_t n = recv (fd, buf, sizeof buf, 0);
  if (n < 0) return -1;
  if ((size_t) n < BDHCP_MIN_PACKET || rd32 (buf + 4) != xid) return -1;
  bdhcp_lease l;
  if (parse_msg (buf, (size_t) n, &l) < 0 || l.msg_type != want_type) return -1;
  memcpy (out, buf, (size_t) n);
  *outlen = (size_t) n;
  return 0;
}

static int
request_cmd (WORD_LIST *args)
{
  const char *iface = NULL, *hvar = NULL;
  int timeout_ms = 1000;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-i") == 0) { if (!p->next) { builtin_error ("request: -i needs IFACE"); return EX_USAGE; } p = p->next; iface = p->word->word; }
      else if (strcmp (w, "-h") == 0 || strcmp (w, "-V") == 0) { if (!p->next) { builtin_error ("request: -h needs VAR"); return EX_USAGE; } p = p->next; hvar = p->word->word; }
      else if (strcmp (w, "-t") == 0) { if (!p->next) return EX_USAGE; p = p->next; timeout_ms = atoi (p->word->word); if (timeout_ms <= 0) timeout_ms = 1000; }
      else { builtin_error ("request: extra arg %s", w); return EX_USAGE; }
    }
  if (!iface) iface = "eth0";
  unsigned char mac[6];
  if (read_mac (iface, mac) < 0) return EXECUTION_FAILURE;
  unsigned xid = (unsigned) time (NULL) ^ ((unsigned) getpid () << 16);
  int fd = socket (AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) { builtin_error ("socket: %s", strerror (errno)); return EXECUTION_FAILURE; }
  int one = 1;
  setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  setsockopt (fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof one);
  if (setsockopt (fd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen (iface)) < 0)
    { builtin_error ("SO_BINDTODEVICE %s: %s", iface, strerror (errno)); close (fd); return EXECUTION_FAILURE; }
  struct sockaddr_in local = { .sin_family = AF_INET,
                               .sin_port = htons (env_port ("BASHDHCP_CLIENT_PORT", 68)),
                               .sin_addr.s_addr = htonl (INADDR_ANY) };
  if (bind (fd, (struct sockaddr *) &local, sizeof local) < 0)
    { builtin_error ("bind udp/%u: %s", ntohs (local.sin_port), strerror (errno)); close (fd); return EXECUTION_FAILURE; }
  struct sockaddr_in dst = { .sin_family = AF_INET,
                             .sin_port = htons (env_port ("BASHDHCP_SERVER_PORT", 67)) };
  if (env_server_addr (&dst) < 0) { close (fd); return EX_USAGE; }
  unsigned char pkt[548], offer[BDHCP_MAX_PACKET], ack[BDHCP_MAX_PACKET];
  size_t plen = build_packet (pkt, sizeof pkt, 1, xid, mac, NULL, NULL, NULL);
  size_t offer_len = 0, ack_len = 0;
  for (int i = 0; i < 3 && offer_len == 0; i++)
    {
      sendto (fd, pkt, plen, 0, (struct sockaddr *) &dst, sizeof dst);
      if (recv_dhcp (fd, xid, 2, offer, &offer_len, timeout_ms << i) == 0) break;
    }
  if (offer_len == 0) { builtin_error ("no OFFER received"); close (fd); return EXECUTION_FAILURE; }
  bdhcp_lease ol;
  parse_msg (offer, offer_len, &ol);
  struct in_addr yi, srv;
  if (inet_pton (AF_INET, ol.ip, &yi) != 1 || inet_pton (AF_INET, ol.server_id, &srv) != 1)
    { builtin_error ("malformed OFFER"); close (fd); return EXECUTION_FAILURE; }
  plen = build_packet (pkt, sizeof pkt, 3, xid, mac, (unsigned char *) &yi.s_addr, (unsigned char *) &srv.s_addr, NULL);
  for (int i = 0; i < 3 && ack_len == 0; i++)
    {
      sendto (fd, pkt, plen, 0, (struct sockaddr *) &dst, sizeof dst);
      if (recv_dhcp (fd, xid, 5, ack, &ack_len, timeout_ms << i) == 0) break;
    }
  close (fd);
  if (ack_len == 0) { builtin_error ("no ACK after REQUEST"); return EXECUTION_FAILURE; }
  bdhcp_lease al;
  if (parse_msg (ack, ack_len, &al) < 0) return EXECUTION_FAILURE;
  if (bind_lease (hvar, &al) < 0) return EXECUTION_FAILURE;
  if (!hvar) print_lease (&al);
  return EXECUTION_SUCCESS;
}

static int
renew_cmd (WORD_LIST *args)
{
  const char *iface = NULL, *lease_arg = NULL, *hvar = NULL;
  int timeout_ms = 1000;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-i") == 0) { if (!p->next) { builtin_error ("renew: -i needs IFACE"); return EX_USAGE; } p = p->next; iface = p->word->word; }
      else if (strcmp (w, "-h") == 0 || strcmp (w, "-V") == 0) { if (!p->next) { builtin_error ("renew: -h needs VAR"); return EX_USAGE; } p = p->next; hvar = p->word->word; }
      else if (strcmp (w, "-t") == 0) { if (!p->next) return EX_USAGE; p = p->next; timeout_ms = atoi (p->word->word); if (timeout_ms <= 0) timeout_ms = 1000; }
      else if (!lease_arg) lease_arg = w;
      else { builtin_error ("renew: extra arg %s", w); return EX_USAGE; }
    }
  if (!iface) iface = "eth0";
  bdhcp_lease old;
  if (read_lease_arg (lease_arg, &old) < 0) { builtin_error ("renew: LEASE with ip/address and server/server_id required"); return EX_USAGE; }
  unsigned char mac[6], ci[4], srv_ip[4];
  if (read_mac (iface, mac) < 0 || parse_ip (old.ip, ci) < 0 || parse_ip (old.server_id, srv_ip) < 0) return EXECUTION_FAILURE;
  unsigned xid = (unsigned) time (NULL) ^ ((unsigned) getpid () << 16);
  int fd = socket (AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) { builtin_error ("socket: %s", strerror (errno)); return EXECUTION_FAILURE; }
  if (setsockopt (fd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen (iface)) < 0)
    { builtin_error ("SO_BINDTODEVICE %s: %s", iface, strerror (errno)); close (fd); return EXECUTION_FAILURE; }
  struct sockaddr_in local = { .sin_family = AF_INET,
                               .sin_port = htons (env_port ("BASHDHCP_CLIENT_PORT", 68)),
                               .sin_addr.s_addr = htonl (INADDR_ANY) };
  if (bind (fd, (struct sockaddr *) &local, sizeof local) < 0)
    { builtin_error ("bind udp/%u: %s", ntohs (local.sin_port), strerror (errno)); close (fd); return EXECUTION_FAILURE; }
  struct sockaddr_in dst = { .sin_family = AF_INET,
                             .sin_port = htons (env_port ("BASHDHCP_SERVER_PORT", 67)) };
  memcpy (&dst.sin_addr.s_addr, srv_ip, 4);
  unsigned char pkt[548], ack[BDHCP_MAX_PACKET];
  size_t plen = build_packet (pkt, sizeof pkt, 3, xid, mac, NULL, srv_ip, ci);
  size_t ack_len = 0;
  sendto (fd, pkt, plen, 0, (struct sockaddr *) &dst, sizeof dst);
  recv_dhcp (fd, xid, 5, ack, &ack_len, timeout_ms);
  close (fd);
  if (ack_len == 0) { builtin_error ("renew: no ACK"); return EXECUTION_FAILURE; }
  bdhcp_lease nl;
  if (parse_msg (ack, ack_len, &nl) < 0) return EXECUTION_FAILURE;
  if (bind_lease (hvar, &nl) < 0) return EXECUTION_FAILURE;
  if (!hvar) print_lease (&nl);
  return EXECUTION_SUCCESS;
}

static int
release_cmd (WORD_LIST *args)
{
  const char *iface = NULL, *lease_arg = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-i") == 0) { if (!p->next) { builtin_error ("release: -i needs IFACE"); return EX_USAGE; } p = p->next; iface = p->word->word; }
      else if (!lease_arg) lease_arg = w;
      else { builtin_error ("release: extra arg %s", w); return EX_USAGE; }
    }
  if (!iface) iface = "eth0";
  bdhcp_lease l;
  if (read_lease_arg (lease_arg, &l) < 0) { builtin_error ("release: LEASE with ip/address and server/server_id required"); return EX_USAGE; }
  unsigned char mac[6], ci[4], srv_ip[4];
  if (read_mac (iface, mac) < 0 || parse_ip (l.ip, ci) < 0 || parse_ip (l.server_id, srv_ip) < 0) return EXECUTION_FAILURE;
  int fd = socket (AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) { builtin_error ("socket: %s", strerror (errno)); return EXECUTION_FAILURE; }
  if (setsockopt (fd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen (iface)) < 0)
    { builtin_error ("SO_BINDTODEVICE %s: %s", iface, strerror (errno)); close (fd); return EXECUTION_FAILURE; }
  struct sockaddr_in dst = { .sin_family = AF_INET,
                             .sin_port = htons (env_port ("BASHDHCP_SERVER_PORT", 67)) };
  memcpy (&dst.sin_addr.s_addr, srv_ip, 4);
  unsigned char pkt[548];
  size_t plen = build_packet (pkt, sizeof pkt, 7, (unsigned) time (NULL) ^ (unsigned) getpid (), mac, NULL, srv_ip, ci);
  ssize_t s;
  do { s = sendto (fd, pkt, plen, 0, (struct sockaddr *) &dst, sizeof dst); }
  while (s < 0 && errno == EINTR);
  int rc = s < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
  if (rc != EXECUTION_SUCCESS) builtin_error ("release send: %s", strerror (errno));
  close (fd);
  return rc;
}

static int
inform_cmd (WORD_LIST *args)
{
  const char *iface = NULL, *ip = NULL, *hvar = NULL;
  int timeout_ms = 1000;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-i") == 0) { if (!p->next) { builtin_error ("inform: -i needs IFACE"); return EX_USAGE; } p = p->next; iface = p->word->word; }
      else if (strcmp (w, "-a") == 0 || strcmp (w, "--addr") == 0) { if (!p->next) { builtin_error ("inform: -a needs IPv4"); return EX_USAGE; } p = p->next; ip = p->word->word; }
      else if (strcmp (w, "-h") == 0 || strcmp (w, "-V") == 0) { if (!p->next) { builtin_error ("inform: -h needs VAR"); return EX_USAGE; } p = p->next; hvar = p->word->word; }
      else if (strcmp (w, "-t") == 0) { if (!p->next) return EX_USAGE; p = p->next; timeout_ms = atoi (p->word->word); if (timeout_ms <= 0) timeout_ms = 1000; }
      else { builtin_error ("inform: extra arg %s", w); return EX_USAGE; }
    }
  if (!iface) iface = "eth0";
  if (!ip) { builtin_error ("inform: -a IPv4 required"); return EX_USAGE; }
  unsigned char mac[6], ci[4];
  if (read_mac (iface, mac) < 0 || parse_ip (ip, ci) < 0) return EXECUTION_FAILURE;
  unsigned xid = (unsigned) time (NULL) ^ ((unsigned) getpid () << 16);
  int fd = socket (AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) { builtin_error ("socket: %s", strerror (errno)); return EXECUTION_FAILURE; }
  int one = 1;
  if (setsockopt (fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof one) < 0)
    { builtin_error ("SO_BROADCAST: %s", strerror (errno)); close (fd); return EXECUTION_FAILURE; }
  if (setsockopt (fd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen (iface)) < 0)
    { builtin_error ("SO_BINDTODEVICE %s: %s", iface, strerror (errno)); close (fd); return EXECUTION_FAILURE; }
  struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = htons (67), .sin_addr.s_addr = htonl (INADDR_BROADCAST) };
  unsigned char pkt[548], ack[BDHCP_MAX_PACKET];
  size_t plen = build_packet (pkt, sizeof pkt, 8, xid, mac, NULL, NULL, ci);
  size_t ack_len = 0;
  ssize_t s;
  do { s = sendto (fd, pkt, plen, 0, (struct sockaddr *) &dst, sizeof dst); }
  while (s < 0 && errno == EINTR);
  (void) s;
  recv_dhcp (fd, xid, 5, ack, &ack_len, timeout_ms);
  close (fd);
  if (ack_len == 0) return EXECUTION_SUCCESS;
  bdhcp_lease il;
  if (parse_msg (ack, ack_len, &il) < 0) return EXECUTION_FAILURE;
  if (bind_lease (hvar, &il) < 0) return EXECUTION_FAILURE;
  if (!hvar) print_lease (&il);
  return EXECUTION_SUCCESS;
}

static int
parse_cmd (WORD_LIST *args)
{
  const char *hex = NULL, *var = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-V") == 0 || strcmp (w, "-h") == 0)
        { if (!p->next) { builtin_error ("parse-message: -V needs VAR"); return EX_USAGE; } p = p->next; var = p->word->word; }
      else if (!hex) hex = w;
      else { builtin_error ("parse-message: extra arg %s", w); return EX_USAGE; }
    }
  if (!hex) { builtin_error ("parse-message: HEX [-V VAR]"); return EX_USAGE; }
  unsigned char pkt[BDHCP_MAX_PACKET];
  int n = hex_decode (hex, pkt, sizeof pkt);
  if (n < 0) { builtin_error ("parse-message: bad hex"); return EX_USAGE; }
  bdhcp_lease l;
  if (parse_msg (pkt, (size_t) n, &l) < 0) { builtin_error ("parse-message: malformed DHCP message"); return EXECUTION_FAILURE; }
  if (bind_lease (var, &l) < 0) return EXECUTION_FAILURE;
  if (!var) print_lease (&l);
  return EXECUTION_SUCCESS;
}

int
bashdhcp_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;
  if (strcmp (cmd, "request") == 0) return request_cmd (args);
  if (strcmp (cmd, "renew") == 0) return renew_cmd (args);
  if (strcmp (cmd, "inform") == 0) return inform_cmd (args);
  if (strcmp (cmd, "release") == 0) return release_cmd (args);
  if (strcmp (cmd, "parse-message") == 0) return parse_cmd (args);
  builtin_error ("unknown subcommand: %s", cmd);
  return EX_USAGE;
}

char *bashdhcp_doc[] = {
  "DHCPv4 client and message parser.",
  "",
  "    bashdhcp request -i IFACE [-h LEASE_VAR] [-t TIMEOUT_MS]",
  "    bashdhcp renew   -i IFACE [-h LEASE_VAR]",
  "    bashdhcp release -i IFACE LEASE",
  "    bashdhcp parse-message HEX [-V VAR]",
  "",
  "LEASE_VAR is an associative array with ip/netmask/gateway/dns/domain/server_id/lease_time/renew_time.",
  (char *)NULL
};

struct builtin bashdhcp_struct = {
  "bashdhcp",
  bashdhcp_builtin,
  BUILTIN_ENABLED,
  bashdhcp_doc,
  "bashdhcp request|renew|release|parse-message ARGS...",
  0
};
