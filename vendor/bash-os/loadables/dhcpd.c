/* SPDX-License-Identifier: MIT */
/* dhcpd.c — DHCPv4 server (RFC 2131). Loadable for bash.
 *
 * Stage A.11 of the bash-os deployable-distro track; server side of the
 * dhcp client. DHCPv4 feature parity (F03, 2026-06-01): PXE boot options,
 * Option 82 (RFC 3046) echo, multi-subnet pools selected by relay giaddr,
 * giaddr/relay reply routing (RFC 2131 §4.1), and a DDNS lease-exec hook.
 * DHCPv6 (RFC 8415) stays in the separate dhcpd6 loadable; this engine
 * remains DHCPv4/PXE/BINL only.
 *
 * Subcommands:
 *     dhcpd serve [-c CONFIG] [-l LEASEDB] [-i IFACE]
 *         Bind UDP/67, parse the config + lease DB, and answer
 *         DISCOVER → OFFER / REQUEST → ACK / RELEASE forever.
 *         With `proxy-dhcp on`, also bind UDP/4011 and answer offer-only
 *         PXE ProxyDHCP/BINL replies without assigning leases.
 *
 *     dhcpd run [-d STATEDIR] [-c CONFIG] [-l LEASEDB]
 *         sv-friendly wrapper around `serve`.
 *
 *     dhcpd parse-req HEX [-V VAR]   debug: decode a request (exposes
 *         giaddr / vendor-class / opt-82 circuit-id + remote-id).
 *     dhcpd respond HEX [-c CONFIG] [-l LEASEDB] [-V VAR]
 *         Host-testable reply builder: parse a request and emit reply hex.
 *     dhcpd lease-list [-l LEASEDB]
 *     dhcpd lease-add MAC IP [-l LEASEDB]
 *     dhcpd lease-remove MAC [-l LEASEDB]
 *
 * Config file format (/etc/dhcpd.conf):
 *     pool         <first-ip> <last-ip>  # required (or a per-subnet pool)
 *     netmask      <ip>                  # required
 *     gateway      <ip>                  # optional
 *     dns          <ip>[,ip...]          # optional
 *     domain       <name>                # optional
 *     server_id    <ip>                  # required (our IP)
 *     lease        <seconds>             # default 86400
 *     next-server  <ip>                  # PXE: BOOTP siaddr
 *     tftp-server  <name>                # PXE: option 66
 *     bootfile     <name>                # PXE: option 67 + BOOTP file field
 *     pxe-vendor-match on|off            # gate PXE opts on opt-60 PXEClient*
 *     pxe-discovery-control <n>          # PXE option-43 sub-option 6
 *     pxe-boot-server <type> <ip>[,...]  # PXE option-43 sub-option 8; repeatable
 *     pxe-menu-item <type> "<label>"     # PXE option-43 sub-option 9
 *     pxe-menu-prompt <timeout> "<text>" # PXE option-43 sub-option 10
 *     option-43 <hex>                    # raw option-43 payload escape hatch
 *     proxy-dhcp on|off                  # offer-only PXE ProxyDHCP/BINL mode
 *     lease-exec   <command>             # DDNS hook (commit/release; sh -c with
 *                                        #   BASHDHCPD_ACTION/_MAC/_IP/_HOSTNAME/_LEASE_TIME)
 *     subnet <network> <netmask> {       # per-subnet pool/gateway/dns, picked
 *         pool <lo> <hi>; gateway <ip>; dns <ip>   #   by the relay giaddr
 *     }
 *
 * Lease DB (one line per lease):
 *     <mac> <ip> <expiry-unix> [hostname]
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
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>     /* waitpid for the lease-exec hook */
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "loadables.h"

#define BDHCPD_MAGIC 0x63825363U
#define BDHCPD_MIN 240
#define BDHCPD_MAX 1500
#define BDHCPD_DEFAULT_LEASE 86400
#define BDHCPD_PROXY_PORT 4011
#define PXE_DISCOVERY_CONTROL 6
#define PXE_BOOT_SERVERS 8
#define PXE_BOOT_MENU 9
#define PXE_MENU_PROMPT 10
#define PXE_SUBOPT_END 255
#define BDHCPD_PXE43_MAX 255
#define BDHCPD_MAX_PXE_BOOT_SERVERS 16
#define BDHCPD_MAX_PXE_BOOT_IPS 16

static volatile sig_atomic_t bdhcpd_stop = 0;
static void bdhcpd_sig (int s) { (void) s; bdhcpd_stop = 1; }

/* ------ utility ------ */

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

static int
parse_ip4 (const char *s, unsigned char out[4])
{
  struct in_addr a;
  if (!s || inet_pton (AF_INET, s, &a) != 1) return -1;
  memcpy (out, &a.s_addr, 4);
  return 0;
}

static unsigned short
bdhcpd_env_port (const char *name, unsigned short fallback)
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
parse_mac (const char *s, unsigned char out[6])
{
  unsigned x[6];
  if (!s) return -1;
  if (sscanf (s, "%x:%x:%x:%x:%x:%x", &x[0], &x[1], &x[2], &x[3], &x[4], &x[5]) != 6)
    return -1;
  for (int i = 0; i < 6; i++) { if (x[i] > 0xff) return -1; out[i] = (unsigned char) x[i]; }
  return 0;
}

static void
fmt_ip4 (const unsigned char *p, char *out, size_t n)
{
  snprintf (out, n, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
}

static void
fmt_mac (const unsigned char *p, char *out, size_t n)
{
  snprintf (out, n, "%02x:%02x:%02x:%02x:%02x:%02x", p[0], p[1], p[2], p[3], p[4], p[5]);
}

/* ------ hex decode (from dhcp.c, for parse-req verb) ------ */

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

static void
hex_print (const unsigned char *b, int n, char *out, size_t cap)
{
  size_t o = 0;
  for (int i = 0; i < n && o + 2 < cap; i++)
    { snprintf (out + o, cap - o, "%02x", b[i]); o += 2; }
  out[o] = '\0';
}

/* ------ config ------ */

#define BDHCPD_MAX_SUBNETS 8
/* A `subnet <network> <netmask> { pool ...; gateway ...; dns ...; }` block.
 * Selected per-request by matching giaddr (relay) against network/netmask;
 * its pool/netmask/gateway/dns override the global flat config for that
 * client. The global server_id/lease/domain/PXE settings are inherited. */
struct bdhcpd_subnet {
  unsigned char network[4], netmask[4];
  unsigned char pool_lo[4], pool_hi[4], gateway[4];
  char dns[128];
  int have_pool, have_gw;
};

struct bdhcpd_pxe_boot_server {
  unsigned type;
  unsigned char ips[BDHCPD_MAX_PXE_BOOT_IPS][4];
  int n_ips;
};

struct bdhcpd_cfg {
  unsigned char pool_lo[4], pool_hi[4];
  unsigned char netmask[4], gateway[4], server_id[4];
  unsigned char next_server[4];     /* PXE: BOOTP siaddr (opt: next-server) */
  unsigned char pxe43_raw[256];     /* pre-encoded PXE option-43 payload */
  char dns[128];
  char domain[64];
  char tftp_server[128];            /* PXE: option 66 (tftp-server) */
  char bootfile[128];               /* PXE: option 67 + BOOTP file (bootfile) */
  char lease_exec[256];             /* DDNS hook: cmd run on commit/release */
  unsigned lease_time;
  int have_pool, have_mask, have_server_id, have_gw, have_next_server;
  int pxe_vendor_match;             /* only emit PXE opts to PXEClient* (opt 60) */
  int pxe43_len;                    /* option-43 payload length, 0 = absent */
  int pxe43_structured;             /* structured keys override raw option-43 */
  int proxy_dhcp;                   /* offer-only ProxyDHCP/BINL mode */
  struct bdhcpd_pxe_boot_server pxe_boot_server[BDHCPD_MAX_PXE_BOOT_SERVERS];
  int n_pxe_boot_server;
  struct bdhcpd_subnet subnets[BDHCPD_MAX_SUBNETS];
  int n_subnets;
  char *raw;
};

static char *
bdhcpd_cfg_word (char **sp)
{
  char *s = *sp;
  while (*s == ' ' || *s == '\t') s++;
  if (!*s) { *sp = s; return NULL; }
  char *out;
  if (*s == '"')
    {
      out = ++s;
      while (*s && *s != '"') s++;
      if (*s) *s++ = '\0';
    }
  else
    {
      out = s;
      while (*s && *s != ' ' && *s != '\t') s++;
      if (*s) *s++ = '\0';
    }
  while (*s == ' ' || *s == '\t') s++;
  *sp = s;
  return out;
}

static int
bdhcpd_parse_u32 (const char *s, unsigned max, unsigned *out)
{
  if (!s || !*s) return -1;
  char *end = NULL;
  unsigned long v = strtoul (s, &end, 0);
  if (*end || v > max) return -1;
  *out = (unsigned) v;
  return 0;
}

static void
bdhcpd_pxe43_reset_for_structured (struct bdhcpd_cfg *c)
{
  if (c->pxe43_structured) return;
  if (!c->pxe43_structured && c->pxe43_len > 0)
    builtin_warning ("option-43 raw payload ignored because structured PXE keys are present");
  c->pxe43_len = 0;
  c->pxe43_structured = 1;
}

static int
bdhcpd_pxe43_append (struct bdhcpd_cfg *c, unsigned code,
                     const unsigned char *data, size_t len)
{
  if (code > 255 || len > 255) return -1;
  if ((size_t) c->pxe43_len + 2 + len + 1 >= BDHCPD_PXE43_MAX) return -1;
  c->pxe43_raw[c->pxe43_len++] = (unsigned char) code;
  c->pxe43_raw[c->pxe43_len++] = (unsigned char) len;
  if (len > 0)
    {
      memcpy (c->pxe43_raw + c->pxe43_len, data, len);
      c->pxe43_len += (int) len;
    }
  return 0;
}

static void
bdhcpd_pxe43_append_end (struct bdhcpd_cfg *c)
{
  if (c->pxe43_structured && c->pxe43_len < BDHCPD_PXE43_MAX)
    c->pxe43_raw[c->pxe43_len++] = PXE_SUBOPT_END;
}

static struct bdhcpd_pxe_boot_server *
bdhcpd_pxe_boot_server_slot (struct bdhcpd_cfg *c, unsigned type)
{
  for (int i = 0; i < c->n_pxe_boot_server; i++)
    if (c->pxe_boot_server[i].type == type)
      return &c->pxe_boot_server[i];
  if (c->n_pxe_boot_server >= BDHCPD_MAX_PXE_BOOT_SERVERS)
    return NULL;
  struct bdhcpd_pxe_boot_server *bs = &c->pxe_boot_server[c->n_pxe_boot_server++];
  memset (bs, 0, sizeof *bs);
  bs->type = type;
  return bs;
}

static int
bdhcpd_pxe_boot_server_add (struct bdhcpd_cfg *c, unsigned type,
                            const unsigned char ip[4])
{
  struct bdhcpd_pxe_boot_server *bs = bdhcpd_pxe_boot_server_slot (c, type);
  if (!bs || bs->n_ips >= BDHCPD_MAX_PXE_BOOT_IPS)
    return -1;
  memcpy (bs->ips[bs->n_ips++], ip, 4);
  return 0;
}

static int
bdhcpd_pxe43_emit_boot_servers (struct bdhcpd_cfg *c)
{
  if (c->n_pxe_boot_server <= 0)
    return 0;
  unsigned char b[BDHCPD_PXE43_MAX];
  size_t p = 0;
  for (int i = 0; i < c->n_pxe_boot_server; i++)
    {
      const struct bdhcpd_pxe_boot_server *bs = &c->pxe_boot_server[i];
      if (bs->n_ips <= 0)
        continue;
      if (p + 3 + (size_t) bs->n_ips * 4 > sizeof b)
        return -1;
      b[p++] = (unsigned char) (bs->type >> 8);
      b[p++] = (unsigned char) bs->type;
      b[p++] = (unsigned char) bs->n_ips;
      for (int j = 0; j < bs->n_ips; j++)
        {
          memcpy (b + p, bs->ips[j], 4);
          p += 4;
        }
    }
  if (p == 0)
    return 0;
  return bdhcpd_pxe43_append (c, PXE_BOOT_SERVERS, b, p);
}

static int
bdhcpd_load_cfg (const char *path, struct bdhcpd_cfg *c)
{
  memset (c, 0, sizeof *c);
  c->lease_time = BDHCPD_DEFAULT_LEASE;
  FILE *f = fopen (path, "r");
  if (!f) return -1;
  fseek (f, 0, SEEK_END);
  long sz = ftell (f);
  fseek (f, 0, SEEK_SET);
  if (sz < 0 || sz > 32768) { fclose (f); return -1; }
  c->raw = malloc ((size_t) sz + 1);
  if (!c->raw) { fclose (f); return -1; }
  size_t n = fread (c->raw, 1, (size_t) sz, f);
  c->raw[n] = '\0';
  fclose (f);

  char *p = c->raw;
  struct bdhcpd_subnet *cur = NULL;   /* active `subnet <net> <mask> { }` block */
  while (*p)
    {
      char *eol = strchr (p, '\n');
      if (eol) *eol = '\0';
      char *line = p;
      while (*line == ' ' || *line == '\t') line++;
      if (*line && *line != '#')
        {
          char *key = line;
          while (*line && *line != ' ' && *line != '\t') line++;
          if (*line) { *line++ = '\0'; while (*line == ' ' || *line == '\t') line++; }
          char *val = line;
          if (strcmp (key, "subnet") == 0 && *val && c->n_subnets < BDHCPD_MAX_SUBNETS)
            {
              /* "subnet NETWORK NETMASK [{]" — opens a per-subnet block. */
              char *net = val, *sp = val;
              while (*sp && *sp != ' ' && *sp != '\t') sp++;
              if (*sp) { *sp++ = '\0'; while (*sp == ' ' || *sp == '\t') sp++; }
              char *mask = sp;
              while (*sp && *sp != ' ' && *sp != '\t') sp++;
              if (*sp) *sp = '\0';            /* drop a trailing "{" token if present */
              struct bdhcpd_subnet *s = &c->subnets[c->n_subnets];
              memset (s, 0, sizeof *s);
              if (parse_ip4 (net, s->network) == 0 && parse_ip4 (mask, s->netmask) == 0)
                { cur = s; c->n_subnets++; }
            }
          else if (strcmp (key, "}") == 0)
            cur = NULL;
          else if (strcmp (key, "pool") == 0 && *val)
            {
              char *sp = val;
              while (*sp && *sp != ' ' && *sp != '\t') sp++;
              if (*sp) { *sp++ = '\0'; while (*sp == ' ' || *sp == '\t') sp++; }
              unsigned char *lo = cur ? cur->pool_lo : c->pool_lo;
              unsigned char *hi = cur ? cur->pool_hi : c->pool_hi;
              if (parse_ip4 (val, lo) == 0 && parse_ip4 (sp, hi) == 0)
                { if (cur) cur->have_pool = 1; else c->have_pool = 1; }
            }
          else if (strcmp (key, "netmask") == 0)
            { if (cur) parse_ip4 (val, cur->netmask);
              else if (parse_ip4 (val, c->netmask) == 0) c->have_mask = 1; }
          else if (strcmp (key, "gateway") == 0)
            { if (cur) { if (parse_ip4 (val, cur->gateway) == 0) cur->have_gw = 1; }
              else if (parse_ip4 (val, c->gateway) == 0) c->have_gw = 1; }
          else if (strcmp (key, "server_id") == 0 && parse_ip4 (val, c->server_id) == 0)
            c->have_server_id = 1;
          else if (strcmp (key, "dns") == 0)
            { if (cur) snprintf (cur->dns, sizeof cur->dns, "%s", val);
              else snprintf (c->dns, sizeof c->dns, "%s", val); }
          else if (strcmp (key, "domain") == 0)
            snprintf (c->domain, sizeof c->domain, "%s", val);
          else if (strcmp (key, "lease") == 0)
            { unsigned v = (unsigned) strtoul (val, NULL, 10); if (v > 0) c->lease_time = v; }
          else if (strcmp (key, "next-server") == 0 && parse_ip4 (val, c->next_server) == 0)
            c->have_next_server = 1;
          else if (strcmp (key, "tftp-server") == 0)
            snprintf (c->tftp_server, sizeof c->tftp_server, "%s", val);
          else if (strcmp (key, "bootfile") == 0)
            snprintf (c->bootfile, sizeof c->bootfile, "%s", val);
          else if (strcmp (key, "pxe-vendor-match") == 0)
            c->pxe_vendor_match = (strcmp (val, "on") == 0 || strcmp (val, "1") == 0
                                   || strcmp (val, "yes") == 0);
          else if (strcmp (key, "pxe-discovery-control") == 0)
            {
              unsigned v;
              if (bdhcpd_parse_u32 (val, 255, &v) == 0)
                {
                  unsigned char b[1] = { (unsigned char) v };
                  bdhcpd_pxe43_reset_for_structured (c);
                  bdhcpd_pxe43_append (c, PXE_DISCOVERY_CONTROL, b, sizeof b);
                }
            }
          else if (strcmp (key, "pxe-boot-server") == 0)
            {
              char *sp = val;
              char *type_s = bdhcpd_cfg_word (&sp);
              char *ip_s = bdhcpd_cfg_word (&sp);
              unsigned type;
              if (bdhcpd_parse_u32 (type_s, 65535, &type) == 0 && ip_s && *ip_s)
                {
                  bdhcpd_pxe43_reset_for_structured (c);
                  char *save = NULL;
                  for (char *tok = strtok_r (ip_s, ",", &save); tok; tok = strtok_r (NULL, ",", &save))
                    {
                      while (*tok == ' ' || *tok == '\t') tok++;
                      char *end = tok + strlen (tok);
                      while (end > tok && (end[-1] == ' ' || end[-1] == '\t')) *--end = '\0';
                      unsigned char ip[4];
                      if (*tok && parse_ip4 (tok, ip) == 0)
                        bdhcpd_pxe_boot_server_add (c, type, ip);
                    }
                }
            }
          else if (strcmp (key, "pxe-menu-item") == 0)
            {
              char *sp = val;
              char *type_s = bdhcpd_cfg_word (&sp);
              char *label = bdhcpd_cfg_word (&sp);
              unsigned type;
              if (bdhcpd_parse_u32 (type_s, 65535, &type) == 0 && label && *label)
                {
                  size_t ll = strlen (label);
                  if (ll > 0 && ll <= 240)
                    {
                      unsigned char b[242];
                      b[0] = (unsigned char) (type >> 8);
                      b[1] = (unsigned char) type;
                      memcpy (b + 2, label, ll);
                      bdhcpd_pxe43_reset_for_structured (c);
                      bdhcpd_pxe43_append (c, PXE_BOOT_MENU, b, ll + 2);
                    }
                }
            }
          else if (strcmp (key, "pxe-menu-prompt") == 0)
            {
              char *sp = val;
              char *timeout_s = bdhcpd_cfg_word (&sp);
              char *text = bdhcpd_cfg_word (&sp);
              unsigned timeout;
              if (bdhcpd_parse_u32 (timeout_s, 255, &timeout) == 0 && text)
                {
                  size_t tl = strlen (text);
                  if (tl <= 240)
                    {
                      unsigned char b[241];
                      b[0] = (unsigned char) timeout;
                      if (tl > 0) memcpy (b + 1, text, tl);
                      bdhcpd_pxe43_reset_for_structured (c);
                      bdhcpd_pxe43_append (c, PXE_MENU_PROMPT, b, tl + 1);
                    }
                }
            }
          else if (strcmp (key, "option-43") == 0)
            {
              unsigned char tmp[BDHCPD_PXE43_MAX];
              int hn = hex_decode (val, tmp, sizeof tmp);
              if (hn >= 0 && hn < BDHCPD_PXE43_MAX)
                {
                  if (c->pxe43_structured)
                    builtin_warning ("option-43 raw payload ignored because structured PXE keys are present");
                  else
                    {
                      memcpy (c->pxe43_raw, tmp, (size_t) hn);
                      c->pxe43_len = hn;
                    }
                }
            }
          else if (strcmp (key, "proxy-dhcp") == 0)
            c->proxy_dhcp = (strcmp (val, "on") == 0 || strcmp (val, "1") == 0
                             || strcmp (val, "yes") == 0);
          else if (strcmp (key, "lease-exec") == 0)
            snprintf (c->lease_exec, sizeof c->lease_exec, "%s", val);
        }
      if (!eol) break;
      p = eol + 1;
    }
  /* Valid if server_id is set AND there is a usable pool: either the global
   * flat pool+netmask, or at least one `subnet { }` block with its own pool
   * (each subnet carries its netmask from the declaration line). */
  int subnet_pool = 0;
  for (int i = 0; i < c->n_subnets; i++)
    if (c->subnets[i].have_pool) { subnet_pool = 1; break; }
  if (bdhcpd_pxe43_emit_boot_servers (c) < 0)
    {
      free (c->raw); c->raw = NULL;
      return -1;
    }
  bdhcpd_pxe43_append_end (c);
  if (!c->have_server_id ||
      (!c->proxy_dhcp && !(c->have_pool && c->have_mask) && !subnet_pool))
    {
      free (c->raw); c->raw = NULL;
      return -1;
    }
  return 0;
}

/* Select the subnet whose network matches giaddr under its netmask. Returns
 * NULL when giaddr is 0.0.0.0 (direct/non-relayed), no subnets are configured,
 * or none matches — callers then use the global flat pool. */
static const struct bdhcpd_subnet *
bdhcpd_select_subnet (const struct bdhcpd_cfg *c, const unsigned char giaddr[4])
{
  if (c->n_subnets == 0 || rd32 (giaddr) == 0) return NULL;
  unsigned g = rd32 (giaddr);
  for (int i = 0; i < c->n_subnets; i++)
    {
      unsigned net = rd32 (c->subnets[i].network), m = rd32 (c->subnets[i].netmask);
      if ((g & m) == (net & m)) return &c->subnets[i];
    }
  return NULL;
}

/* Resolve the per-request effective config: the global flat cfg with
 * pool/netmask/gateway/dns overridden by the subnet matching giaddr (if any).
 * server_id / lease / domain / PXE are always inherited from the global cfg. */
static void
bdhcpd_effective_cfg (const struct bdhcpd_cfg *g, const unsigned char giaddr[4],
                      struct bdhcpd_cfg *out)
{
  *out = *g;
  const struct bdhcpd_subnet *s = bdhcpd_select_subnet (g, giaddr);
  if (!s) return;
  if (s->have_pool)
    { memcpy (out->pool_lo, s->pool_lo, 4); memcpy (out->pool_hi, s->pool_hi, 4);
      out->have_pool = 1; }
  memcpy (out->netmask, s->netmask, 4); out->have_mask = 1;
  if (s->have_gw) { memcpy (out->gateway, s->gateway, 4); out->have_gw = 1; }
  if (s->dns[0]) snprintf (out->dns, sizeof out->dns, "%s", s->dns);
}

static int
bdhcpd_env_name_is (const char *entry, const char *name)
{
  size_t n = strlen (name);
  return strncmp (entry, name, n) == 0 && entry[n] == '=';
}

/* DDNS / lease-event hook. Runs cfg->lease_exec via `/bin/sh -c` with the
 * lease details in the environment (BASHDHCPD_ACTION = commit|release, _MAC,
 * _IP, _HOSTNAME, _LEASE_TIME). The DNS UPDATE protocol itself stays OUT of
 * the server — operators wire `dns` (or any tool) from the hook script.
 * Fail-safe: a missing/failing/forking-failed hook never affects the DHCP
 * exchange. Blocks briefly on the child (hooks are expected to be quick). */
static void
bdhcpd_run_hook (const struct bdhcpd_cfg *cfg, const char *action,
                 const unsigned char mac[6], const unsigned char ip[4],
                 const char *hostname)
{
  if (!cfg->lease_exec[0]) return;
  char mac_s[24], ip_s[16], lease_s[16];
  fmt_mac (mac, mac_s, sizeof mac_s);
  fmt_ip4 (ip, ip_s, sizeof ip_s);
  snprintf (lease_s, sizeof lease_s, "%u", cfg->lease_time);
  pid_t pid = fork ();
  if (pid < 0) return;
  if (pid == 0)
    {
      extern char **environ;
      size_t ec = 0;
      while (environ && environ[ec]) ec++;
      char **envp = malloc ((ec + 6) * sizeof *envp);
      if (!envp) _exit (127);
      char action_env[64], mac_env[64], ip_env[64], host_env[128], lease_env[64];
      snprintf (action_env, sizeof action_env, "BASHDHCPD_ACTION=%s", action);
      snprintf (mac_env, sizeof mac_env, "BASHDHCPD_MAC=%s", mac_s);
      snprintf (ip_env, sizeof ip_env, "BASHDHCPD_IP=%s", ip_s);
      snprintf (host_env, sizeof host_env, "BASHDHCPD_HOSTNAME=%s",
                hostname && hostname[0] ? hostname : "-");
      snprintf (lease_env, sizeof lease_env, "BASHDHCPD_LEASE_TIME=%s", lease_s);
      size_t j = 0;
      for (size_t i = 0; i < ec; i++)
        if (!bdhcpd_env_name_is (environ[i], "BASHDHCPD_ACTION") &&
            !bdhcpd_env_name_is (environ[i], "BASHDHCPD_MAC") &&
            !bdhcpd_env_name_is (environ[i], "BASHDHCPD_IP") &&
            !bdhcpd_env_name_is (environ[i], "BASHDHCPD_HOSTNAME") &&
            !bdhcpd_env_name_is (environ[i], "BASHDHCPD_LEASE_TIME"))
          envp[j++] = environ[i];
      envp[j++] = action_env;
      envp[j++] = mac_env;
      envp[j++] = ip_env;
      envp[j++] = host_env;
      envp[j++] = lease_env;
      envp[j] = NULL;
      char *argv[] = { (char *) "sh", (char *) "-c", (char *) cfg->lease_exec, NULL };
      execve ("/bin/sh", argv, envp);
      _exit (127);
    }
  int st; (void) waitpid (pid, &st, 0);
}

static unsigned
ip_to_u32 (const unsigned char *p)
{
  return ((unsigned) p[0] << 24) | ((unsigned) p[1] << 16) |
         ((unsigned) p[2] << 8) | (unsigned) p[3];
}

static void
u32_to_ip (unsigned v, unsigned char *out)
{
  out[0] = (v >> 24) & 0xff; out[1] = (v >> 16) & 0xff;
  out[2] = (v >> 8) & 0xff;  out[3] = v & 0xff;
}

/* ------ lease DB ------ */

struct bdhcpd_lease {
  unsigned char mac[6];
  unsigned char ip[4];
  time_t expiry;
  char hostname[64];
};

#define BDHCPD_MAX_LEASES 256

struct bdhcpd_db {
  struct bdhcpd_lease v[BDHCPD_MAX_LEASES];
  int n;
};

static int
bdhcpd_db_load (const char *path, struct bdhcpd_db *db)
{
  db->n = 0;
  FILE *f = fopen (path, "r");
  if (!f) return 0;  /* empty / missing is fine */
  char line[256];
  while (fgets (line, sizeof line, f))
    {
      char macs[32], ips[32], host[64];
      long long exp = 0;
      host[0] = '\0';
      int n = sscanf (line, "%31s %31s %lld %63s", macs, ips, &exp, host);
      if (n < 3) continue;
      if (db->n >= BDHCPD_MAX_LEASES) break;
      struct bdhcpd_lease *l = &db->v[db->n];
      if (parse_mac (macs, l->mac) < 0) continue;
      if (parse_ip4 (ips, l->ip) < 0) continue;
      l->expiry = (time_t) exp;
      snprintf (l->hostname, sizeof l->hostname, "%s", host);
      db->n++;
    }
  fclose (f);
  return 0;
}

static int
bdhcpd_db_save (const char *path, const struct bdhcpd_db *db)
{
  char tmp[512];
  snprintf (tmp, sizeof tmp, "%s.tmp", path);
  FILE *f = fopen (tmp, "w");
  if (!f) return -1;
  for (int i = 0; i < db->n; i++)
    {
      char m[24], ip[16];
      fmt_mac (db->v[i].mac, m, sizeof m);
      fmt_ip4 (db->v[i].ip, ip, sizeof ip);
      fprintf (f, "%s %s %lld %s\n", m, ip, (long long) db->v[i].expiry,
               db->v[i].hostname[0] ? db->v[i].hostname : "-");
    }
  fclose (f);
  return rename (tmp, path);
}

static struct bdhcpd_lease *
bdhcpd_db_find_mac (struct bdhcpd_db *db, const unsigned char mac[6])
{
  for (int i = 0; i < db->n; i++)
    if (memcmp (db->v[i].mac, mac, 6) == 0) return &db->v[i];
  return NULL;
}

static int
bdhcpd_db_remove_mac (struct bdhcpd_db *db, const unsigned char mac[6])
{
  for (int i = 0; i < db->n; i++)
    if (memcmp (db->v[i].mac, mac, 6) == 0)
      {
        if (i < db->n - 1)
          db->v[i] = db->v[db->n - 1];
        db->n--;
        return 1;
      }
  return 0;
}

static int
bdhcpd_db_ip_taken (const struct bdhcpd_db *db, const unsigned char ip[4])
{
  time_t now = time (NULL);
  for (int i = 0; i < db->n; i++)
    if (memcmp (db->v[i].ip, ip, 4) == 0 && db->v[i].expiry > now)
      return 1;
  return 0;
}

/* DHCPDECLINE quarantine — process-static. A client returns DECLINE
   (RFC 2131 §3.1.5) when its ARP probe shows the offered IP is
   already in use elsewhere. We hold that IP out of the pool for
   BASHDHCPD_DECLINE_QUARANTINE_SEC seconds (default 60) so the next
   DISCOVER from any MAC doesn't immediately get re-offered the same
   address. The table is bounded; when full, the oldest entry is
   evicted to make room. */
#define BDHCPD_QUARANTINE_MAX 64
static struct {
  unsigned char ip[4];
  time_t expiry;
} bdhcpd_quarantine[BDHCPD_QUARANTINE_MAX];
static size_t bdhcpd_quarantine_n;

static int
bdhcpd_quarantine_check (const unsigned char ip[4])
{
  time_t now = time (NULL);
  for (size_t i = 0; i < bdhcpd_quarantine_n; i++)
    if (memcmp (bdhcpd_quarantine[i].ip, ip, 4) == 0 &&
        bdhcpd_quarantine[i].expiry > now)
      return 1;
  return 0;
}

static void
bdhcpd_quarantine_add (const unsigned char ip[4], unsigned secs)
{
  time_t now = time (NULL);
  /* If already present, just bump the expiry. */
  for (size_t i = 0; i < bdhcpd_quarantine_n; i++)
    if (memcmp (bdhcpd_quarantine[i].ip, ip, 4) == 0)
      {
        bdhcpd_quarantine[i].expiry = now + secs;
        return;
      }
  if (bdhcpd_quarantine_n >= BDHCPD_QUARANTINE_MAX)
    {
      /* Evict oldest by expiry. */
      size_t oldest = 0;
      for (size_t i = 1; i < bdhcpd_quarantine_n; i++)
        if (bdhcpd_quarantine[i].expiry < bdhcpd_quarantine[oldest].expiry)
          oldest = i;
      memcpy (bdhcpd_quarantine[oldest].ip, ip, 4);
      bdhcpd_quarantine[oldest].expiry = now + secs;
      return;
    }
  memcpy (bdhcpd_quarantine[bdhcpd_quarantine_n].ip, ip, 4);
  bdhcpd_quarantine[bdhcpd_quarantine_n].expiry = now + secs;
  bdhcpd_quarantine_n++;
}

static unsigned
bdhcpd_decline_quarantine_secs (void)
{
  const char *v = getenv ("BASHDHCPD_DECLINE_QUARANTINE_SEC");
  if (v && *v) {
    char *end;
    long n = strtol (v, &end, 10);
    if (end != v && *end == '\0' && n > 0 && n <= 86400)
      return (unsigned) n;
  }
  return 60;  /* Default: 1 minute */
}

static int
bdhcpd_pick_ip (const struct bdhcpd_cfg *cfg, struct bdhcpd_db *db,
                const unsigned char mac[6], unsigned char out[4])
{
  /* Re-use existing assignment if MAC already in db. */
  struct bdhcpd_lease *prev = bdhcpd_db_find_mac (db, mac);
  if (prev)
    {
      memcpy (out, prev->ip, 4);
      return 0;
    }
  unsigned lo = ip_to_u32 (cfg->pool_lo), hi = ip_to_u32 (cfg->pool_hi);
  if (lo > hi) return -1;
  for (unsigned v = lo; v <= hi; v++)
    {
      unsigned char ip[4];
      u32_to_ip (v, ip);
      if (bdhcpd_db_ip_taken (db, ip)) continue;
      if (bdhcpd_quarantine_check (ip)) continue;
      memcpy (out, ip, 4);
      return 0;
    }
  return -1;
}

/* ------ packet build / parse ------ */

struct bdhcpd_req {
  unsigned msg_type;        /* opt 53 */
  unsigned xid;
  unsigned char chaddr[6];
  unsigned char req_ip[4];  /* opt 50 */
  unsigned char server_id[4]; /* opt 54 */
  int have_req_ip, have_server_id;
  char hostname[64];        /* opt 12 */
  char vendor_class[128];   /* opt 60 (e.g. "PXEClient:Arch:00000:...") */
  int have_vendor_class;
  unsigned char opt82[256]; /* opt 82 relay agent info (RFC 3046) — raw */
  int opt82_len;            /* 0 = absent */
  unsigned char giaddr[4];  /* BOOTP giaddr (relay) — off 24 */
};

static int
bdhcpd_parse_req (const unsigned char *pkt, size_t len, struct bdhcpd_req *r)
{
  memset (r, 0, sizeof *r);
  if (len < BDHCPD_MIN) return -1;
  if (pkt[0] != 1) return -1;       /* BOOTREQUEST */
  if (rd32 (pkt + 236) != BDHCPD_MAGIC) return -1;
  r->xid = rd32 (pkt + 4);
  memcpy (r->giaddr, pkt + 24, 4);   /* relay agent IP (0.0.0.0 = direct) */
  memcpy (r->chaddr, pkt + 28, 6);
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
        case 12:
          {
            size_t n = olen < sizeof r->hostname - 1 ? olen : sizeof r->hostname - 1;
            memcpy (r->hostname, v, n); r->hostname[n] = '\0';
            break;
          }
        case 50: if (olen == 4) { memcpy (r->req_ip, v, 4); r->have_req_ip = 1; } break;
        case 53: if (olen == 1) r->msg_type = v[0]; break;
        case 54: if (olen == 4) { memcpy (r->server_id, v, 4); r->have_server_id = 1; } break;
        case 60:                /* vendor class identifier (PXE detection) */
          {
            size_t n = olen < sizeof r->vendor_class - 1 ? olen : sizeof r->vendor_class - 1;
            memcpy (r->vendor_class, v, n); r->vendor_class[n] = '\0';
            r->have_vendor_class = 1;
            break;
          }
        case 82:                /* relay agent information (RFC 3046) — capture raw */
          {
            size_t n = olen < sizeof r->opt82 ? olen : sizeof r->opt82;
            memcpy (r->opt82, v, n); r->opt82_len = (int) n;
            break;
          }
        default: break;
        }
      p += olen;
    }
  return r->msg_type ? 0 : -1;
}

static size_t
bdhcpd_build_reply (unsigned char *pkt, size_t cap, unsigned reply_type,
                    const struct bdhcpd_req *req, const struct bdhcpd_cfg *cfg,
                    const unsigned char yiaddr[4], int offer_only)
{
  if (cap < 548) return 0;
  memset (pkt, 0, 548);
  pkt[0] = 2;                /* BOOTREPLY */
  pkt[1] = 1; pkt[2] = 6;    /* htype=Ethernet, hlen=6 */
  wr32 (pkt + 4, req->xid);
  pkt[10] = 0x80;            /* broadcast */
  if (!offer_only)
    memcpy (pkt + 16, yiaddr, 4);
  /* siaddr (BOOTP "next server"): the PXE next-server when configured, else
   * the DHCP server itself (prior behavior). */
  memcpy (pkt + 20, cfg->have_next_server ? cfg->next_server : cfg->server_id, 4);
  memcpy (pkt + 24, req->giaddr, 4);   /* echo giaddr so the relay can route */
  memcpy (pkt + 28, req->chaddr, 6);
  wr32 (pkt + 236, BDHCPD_MAGIC);
  size_t p = 240;
  pkt[p++] = 53; pkt[p++] = 1; pkt[p++] = (unsigned char) reply_type;
  pkt[p++] = 54; pkt[p++] = 4; memcpy (pkt + p, cfg->server_id, 4); p += 4;
  if (!offer_only)
    {
      pkt[p++] = 51; pkt[p++] = 4; wr32 (pkt + p, cfg->lease_time); p += 4;
      pkt[p++] = 58; pkt[p++] = 4; wr32 (pkt + p, cfg->lease_time / 2); p += 4;
      pkt[p++] = 59; pkt[p++] = 4; wr32 (pkt + p, (cfg->lease_time / 8) * 7); p += 4;
      pkt[p++] = 1;  pkt[p++] = 4; memcpy (pkt + p, cfg->netmask, 4); p += 4;
    }
  if (!offer_only && cfg->have_gw)
    { pkt[p++] = 3; pkt[p++] = 4; memcpy (pkt + p, cfg->gateway, 4); p += 4; }
  if (cfg->dns[0])
    {
      /* DNS list is comma- or space-separated ip4. Pack each IP in 4 bytes. */
      unsigned char tmp[64];
      size_t nips = 0;
      char dns_copy[128];
      snprintf (dns_copy, sizeof dns_copy, "%s", cfg->dns);
      for (char *tok = strtok (dns_copy, " ,;"); tok && nips < 8; tok = strtok (NULL, " ,;"))
        if (parse_ip4 (tok, tmp + nips * 4) == 0) nips++;
      if (nips > 0)
        {
          pkt[p++] = 6; pkt[p++] = (unsigned char) (nips * 4);
          memcpy (pkt + p, tmp, nips * 4); p += nips * 4;
        }
    }
  if (cfg->domain[0])
    {
      size_t dl = strlen (cfg->domain);
      if (dl > 0 && dl < 64)
        {
          pkt[p++] = 15; pkt[p++] = (unsigned char) dl;
          memcpy (pkt + p, cfg->domain, dl); p += dl;
        }
    }
  /* PXE boot options (slice 1). Emit when any PXE config is set, gated on the
   * client's vendor-class (opt 60) starting with "PXEClient" iff
   * pxe-vendor-match is on. siaddr already carries next-server (above). */
  {
    int have_pxe = cfg->tftp_server[0] || cfg->bootfile[0] || cfg->have_next_server
                   || cfg->pxe43_len > 0;
    int vendor_ok = !cfg->pxe_vendor_match
                    || (req->have_vendor_class
                        && strncmp (req->vendor_class, "PXEClient", 9) == 0);
    if (have_pxe && vendor_ok)
      {
        if (offer_only)
          {
            const char *vc = req->have_vendor_class ? req->vendor_class : "PXEClient";
            size_t vl = strlen (vc);
            if (vl > 0 && vl < 255 && p + 2 + vl < 548)
              { pkt[p++] = 60; pkt[p++] = (unsigned char) vl;
                memcpy (pkt + p, vc, vl); p += vl; }
          }
        if (cfg->tftp_server[0])
          {
            size_t tl = strlen (cfg->tftp_server);
            if (tl > 0 && tl < 255 && p + 2 + tl < 548)
              { pkt[p++] = 66; pkt[p++] = (unsigned char) tl;
                memcpy (pkt + p, cfg->tftp_server, tl); p += tl; }
          }
        if (cfg->bootfile[0])
          {
            size_t bl = strlen (cfg->bootfile);
            if (bl > 0 && bl < 255 && p + 2 + bl < 548)
              { pkt[p++] = 67; pkt[p++] = (unsigned char) bl;
                memcpy (pkt + p, cfg->bootfile, bl); p += bl; }
            /* Legacy PXE ROMs read the 128-byte BOOTP "file" field (off 108). */
            size_t fl = bl < 127 ? bl : 127;
            memcpy (pkt + 108, cfg->bootfile, fl);
          }
        if (cfg->pxe43_len > 0 && cfg->pxe43_len < 255
            && p + 2 + (size_t) cfg->pxe43_len < 548)
          {
            pkt[p++] = 43;
            pkt[p++] = (unsigned char) cfg->pxe43_len;
            memcpy (pkt + p, cfg->pxe43_raw, (size_t) cfg->pxe43_len);
            p += (size_t) cfg->pxe43_len;
          }
      }
  }
  /* Relay agent information (RFC 3046 §2.1.1): a server MUST echo option 82
   * back verbatim in its reply so the relay can use it to forward correctly. */
  if (req->opt82_len > 0 && req->opt82_len < 255 && p + 2 + req->opt82_len < 548)
    {
      pkt[p++] = 82; pkt[p++] = (unsigned char) req->opt82_len;
      memcpy (pkt + p, req->opt82, req->opt82_len); p += req->opt82_len;
    }
  pkt[p++] = 255;
  return 548;
}

/* ------ subcommands: lease-list / lease-add / lease-remove ------ */

static int
bdhcpd_cmd_lease_list (WORD_LIST *args)
{
  const char *path = "/var/lib/dhcpd/leases";
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-l") == 0)
        { if (!p->next) return EX_USAGE; p = p->next; path = p->word->word; }
      else { builtin_error ("lease-list: extra arg: %s", w); return EX_USAGE; }
    }
  struct bdhcpd_db db;
  bdhcpd_db_load (path, &db);
  time_t now = time (NULL);
  for (int i = 0; i < db.n; i++)
    {
      char m[24], ip[16];
      fmt_mac (db.v[i].mac, m, sizeof m);
      fmt_ip4 (db.v[i].ip, ip, sizeof ip);
      printf ("%s %s expiry=%lld remaining=%lld hostname=%s\n",
              m, ip,
              (long long) db.v[i].expiry,
              (long long) (db.v[i].expiry - now),
              db.v[i].hostname[0] ? db.v[i].hostname : "-");
    }
  return EXECUTION_SUCCESS;
}

static int
bdhcpd_cmd_lease_add (WORD_LIST *args)
{
  const char *path = "/var/lib/dhcpd/leases";
  const char *mac_s = NULL, *ip_s = NULL;
  long ttl = BDHCPD_DEFAULT_LEASE;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-l") == 0)
        { if (!p->next) return EX_USAGE; p = p->next; path = p->word->word; }
      else if (strcmp (w, "-t") == 0)
        { if (!p->next) return EX_USAGE; p = p->next; ttl = atol (p->word->word); if (ttl <= 0) ttl = BDHCPD_DEFAULT_LEASE; }
      else if (!mac_s) mac_s = w;
      else if (!ip_s)  ip_s = w;
      else { builtin_error ("lease-add: extra arg: %s", w); return EX_USAGE; }
    }
  if (!mac_s || !ip_s) { builtin_error ("lease-add: needs MAC IP"); return EX_USAGE; }
  unsigned char mac[6], ip[4];
  if (parse_mac (mac_s, mac) < 0) { builtin_error ("lease-add: invalid MAC: %s", mac_s); return EX_USAGE; }
  if (parse_ip4 (ip_s, ip) < 0)   { builtin_error ("lease-add: invalid IP: %s", ip_s); return EX_USAGE; }

  /* mkdir -p the directory containing path. */
  char dirbuf[512];
  snprintf (dirbuf, sizeof dirbuf, "%s", path);
  char *slash = strrchr (dirbuf, '/');
  if (slash) { *slash = '\0'; mkdir (dirbuf, 0755); }

  struct bdhcpd_db db;
  bdhcpd_db_load (path, &db);
  bdhcpd_db_remove_mac (&db, mac);
  if (db.n >= BDHCPD_MAX_LEASES) { builtin_error ("lease-add: db full"); return EXECUTION_FAILURE; }
  struct bdhcpd_lease *l = &db.v[db.n++];
  memset (l, 0, sizeof *l);
  memcpy (l->mac, mac, 6);
  memcpy (l->ip, ip, 4);
  l->expiry = time (NULL) + ttl;
  if (bdhcpd_db_save (path, &db) < 0)
    { builtin_error ("lease-add: cannot write %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
  return EXECUTION_SUCCESS;
}

static int
bdhcpd_cmd_lease_remove (WORD_LIST *args)
{
  const char *path = "/var/lib/dhcpd/leases";
  const char *mac_s = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-l") == 0)
        { if (!p->next) return EX_USAGE; p = p->next; path = p->word->word; }
      else if (!mac_s) mac_s = w;
      else { builtin_error ("lease-remove: extra arg: %s", w); return EX_USAGE; }
    }
  if (!mac_s) { builtin_error ("lease-remove: needs MAC"); return EX_USAGE; }
  unsigned char mac[6];
  if (parse_mac (mac_s, mac) < 0) { builtin_error ("lease-remove: invalid MAC: %s", mac_s); return EX_USAGE; }
  struct bdhcpd_db db;
  bdhcpd_db_load (path, &db);
  int removed = bdhcpd_db_remove_mac (&db, mac);
  if (removed)
    {
      if (bdhcpd_db_save (path, &db) < 0)
        { builtin_error ("lease-remove: cannot write %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
    }
  return removed ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* ------ parse-req (offline parser testing / diagnostics) ------ */

static void
print_msg_type (unsigned t)
{
  switch (t)
    {
    case 1: printf ("DISCOVER"); break;
    case 2: printf ("OFFER"); break;
    case 3: printf ("REQUEST"); break;
    case 5: printf ("ACK"); break;
    case 6: printf ("NAK"); break;
    case 7: printf ("RELEASE"); break;
    case 8: printf ("INFORM"); break;
    default: printf ("%u", t); break;
    }
}

/* Render bytes as ASCII when all printable, else "0x"+hex — opt-82 sub-IDs are
 * commonly an interface/port string but may be binary (VLAN+port). */
static void
bdhcpd_render_id (const unsigned char *b, int n, char *out, size_t outsz)
{
  int printable = n > 0;
  for (int i = 0; i < n; i++)
    if (b[i] < 0x20 || b[i] > 0x7e) { printable = 0; break; }
  if (printable && (size_t) n < outsz) { memcpy (out, b, n); out[n] = '\0'; return; }
  size_t o = 0;
  if (outsz > 2) { out[o++] = '0'; out[o++] = 'x'; }
  for (int i = 0; i < n && o + 2 < outsz; i++) { snprintf (out + o, outsz - o, "%02x", b[i]); o += 2; }
  out[o] = '\0';
}

/* Extract relay-agent-info (opt 82) sub-option SUB (1=circuit-id, 2=remote-id)
 * into OUT (rendered). Returns 1 if present. */
static int
bdhcpd_opt82_sub (const struct bdhcpd_req *r, int sub, char *out, size_t outsz)
{
  int p = 0;
  while (p + 2 <= r->opt82_len)
    {
      int sc = r->opt82[p], sl = r->opt82[p + 1];
      if (p + 2 + sl > r->opt82_len) break;
      if (sc == sub) { bdhcpd_render_id (r->opt82 + p + 2, sl, out, outsz); return 1; }
      p += 2 + sl;
    }
  return 0;
}

static int
bdhcpd_cmd_parse_req (WORD_LIST *args)
{
  const char *hex = NULL, *var = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-V") == 0 || strcmp (w, "-h") == 0)
        {
          if (!p->next) { builtin_error ("parse-req: -V needs VAR"); return EX_USAGE; }
          p = p->next; var = p->word->word;
        }
      else if (!hex) hex = w;
      else { builtin_error ("parse-req: extra arg %s", w); return EX_USAGE; }
    }
  if (!hex) { builtin_error ("parse-req: HEX [-V VAR]"); return EX_USAGE; }

  unsigned char pkt[BDHCPD_MAX];
  int n = hex_decode (hex, pkt, sizeof pkt);
  if (n < 0) { builtin_error ("parse-req: bad hex"); return EX_USAGE; }

  struct bdhcpd_req r;
  if (bdhcpd_parse_req (pkt, (size_t) n, &r) < 0)
    { builtin_error ("parse-req: malformed DHCP message"); return EXECUTION_FAILURE; }

  if (var)
    {
      if (!valid_identifier ((char *) var))
        { sh_invalidid ((char *) var); return EX_USAGE; }
      SHELL_VAR *v = find_or_make_array_variable ((char *) var, 3);
      if (!v || readonly_p (v) || noassign_p (v)) return EXECUTION_FAILURE;
      if (assoc_p (v) == 0) { builtin_error ("%s: not an associative array", var); return EXECUTION_FAILURE; }
      if (invisible_p (v)) VUNSETATTR (v, att_invisible);
      assoc_flush (assoc_cell (v));
      char num[32], mac[24];
      fmt_mac (r.chaddr, mac, sizeof mac);
      snprintf (num, sizeof num, "%u", r.msg_type);
      bind_assoc_variable (v, (char *) var, "msg_type", num, ASS_FORCE);
      snprintf (num, sizeof num, "0x%x", r.xid);
      bind_assoc_variable (v, (char *) var, "xid", num, ASS_FORCE);
      bind_assoc_variable (v, (char *) var, "chaddr", mac, ASS_FORCE);
      if (r.hostname[0])
        bind_assoc_variable (v, (char *) var, "hostname", r.hostname, ASS_FORCE);
      if (r.have_req_ip)
        {
          char ip[16];
          fmt_ip4 (r.req_ip, ip, sizeof ip);
          bind_assoc_variable (v, (char *) var, "requested_ip", ip, ASS_FORCE);
        }
      if (r.have_server_id)
        {
          char ip[16];
          fmt_ip4 (r.server_id, ip, sizeof ip);
          bind_assoc_variable (v, (char *) var, "server_id", ip, ASS_FORCE);
        }
      if (r.have_vendor_class)
        bind_assoc_variable (v, (char *) var, "vendor_class", r.vendor_class, ASS_FORCE);
      if (rd32 (r.giaddr) != 0)
        {
          char ip[16]; fmt_ip4 (r.giaddr, ip, sizeof ip);
          bind_assoc_variable (v, (char *) var, "giaddr", ip, ASS_FORCE);
        }
      if (r.opt82_len > 0)
        {
          char id[160];
          snprintf (id, sizeof id, "%d", r.opt82_len);
          bind_assoc_variable (v, (char *) var, "opt82_len", id, ASS_FORCE);
          if (bdhcpd_opt82_sub (&r, 1, id, sizeof id))
            bind_assoc_variable (v, (char *) var, "relay_circuit_id", id, ASS_FORCE);
          if (bdhcpd_opt82_sub (&r, 2, id, sizeof id))
            bind_assoc_variable (v, (char *) var, "relay_remote_id", id, ASS_FORCE);
        }
      return EXECUTION_SUCCESS;
    }

  /* stdout printing path */
  printf ("msg_type=");
  print_msg_type (r.msg_type);
  printf ("  xid=0x%x", r.xid);
  {
    char mac[24];
    fmt_mac (r.chaddr, mac, sizeof mac);
    printf ("  chaddr=%s", mac);
  }
  if (r.hostname[0]) printf ("  hostname=%s", r.hostname);
  if (r.have_req_ip)
    {
      char ip[16];
      fmt_ip4 (r.req_ip, ip, sizeof ip);
      printf ("  requested_ip=%s", ip);
    }
  if (r.have_server_id)
    {
      char ip[16];
      fmt_ip4 (r.server_id, ip, sizeof ip);
      printf ("  server_id=%s", ip);
    }
  if (r.have_vendor_class) printf ("  vendor_class=%s", r.vendor_class);
  if (rd32 (r.giaddr) != 0)
    { char ip[16]; fmt_ip4 (r.giaddr, ip, sizeof ip); printf ("  giaddr=%s", ip); }
  if (r.opt82_len > 0)
    {
      char id[160];
      printf ("  opt82_len=%d", r.opt82_len);
      if (bdhcpd_opt82_sub (&r, 1, id, sizeof id)) printf ("  relay_circuit_id=%s", id);
      if (bdhcpd_opt82_sub (&r, 2, id, sizeof id)) printf ("  relay_remote_id=%s", id);
    }
  printf ("\n");
  return EXECUTION_SUCCESS;
}

static int
bdhcpd_cmd_respond (WORD_LIST *args)
{
  const char *hex = NULL, *var = NULL;
  const char *cfg_path = "/etc/dhcpd.conf";
  const char *db_path = "/var/lib/dhcpd/leases";
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-c") == 0)
        { if (!p->next) return EX_USAGE; p = p->next; cfg_path = p->word->word; }
      else if (strcmp (w, "-l") == 0)
        { if (!p->next) return EX_USAGE; p = p->next; db_path = p->word->word; }
      else if (strcmp (w, "-V") == 0)
        { if (!p->next) return EX_USAGE; p = p->next; var = p->word->word; }
      else if (!hex) hex = w;
      else { builtin_error ("respond: extra arg %s", w); return EX_USAGE; }
    }
  if (!hex) { builtin_error ("respond HEX [-c CONFIG] [-l LEASEDB] [-V VAR]"); return EX_USAGE; }
  if (var && !valid_identifier ((char *) var))
    { sh_invalidid ((char *) var); return EX_USAGE; }

  struct bdhcpd_cfg cfg;
  if (bdhcpd_load_cfg (cfg_path, &cfg) < 0)
    {
      builtin_error ("respond: failed to load %s", cfg_path);
      return EXECUTION_FAILURE;
    }

  unsigned char pkt[BDHCPD_MAX];
  int n = hex_decode (hex, pkt, sizeof pkt);
  if (n < 0)
    { builtin_error ("respond: bad hex"); free (cfg.raw); return EX_USAGE; }

  struct bdhcpd_req req;
  if (bdhcpd_parse_req (pkt, (size_t) n, &req) < 0)
    { builtin_error ("respond: malformed DHCP message"); free (cfg.raw); return EXECUTION_FAILURE; }

  unsigned reply_type = 0;
  if (req.msg_type == 1) reply_type = 2;       /* DISCOVER -> OFFER */
  else if (req.msg_type == 3) reply_type = 5;  /* REQUEST -> ACK */
  else
    { builtin_error ("respond: no reply for message type %u", req.msg_type);
      free (cfg.raw); return EXECUTION_FAILURE; }

  struct bdhcpd_db db;
  bdhcpd_db_load (db_path, &db);
  struct bdhcpd_cfg eff;
  bdhcpd_effective_cfg (&cfg, req.giaddr, &eff);
  unsigned char yip[4] = { 0, 0, 0, 0 };
  if (!eff.proxy_dhcp && bdhcpd_pick_ip (&eff, &db, req.chaddr, yip) < 0)
    {
      builtin_error ("respond: no available IP in pool");
      free (cfg.raw);
      return EXECUTION_FAILURE;
    }

  unsigned char reply[BDHCPD_MAX];
  size_t rl = bdhcpd_build_reply (reply, sizeof reply, reply_type, &req, &eff,
                                  yip, eff.proxy_dhcp);
  if (rl == 0)
    { builtin_error ("respond: no reply (drop)"); free (cfg.raw); return EXECUTION_FAILURE; }

  if (!eff.proxy_dhcp && reply_type == 5)
    {
      bdhcpd_db_remove_mac (&db, req.chaddr);
      if (db.n < BDHCPD_MAX_LEASES)
        {
          struct bdhcpd_lease *l = &db.v[db.n++];
          memset (l, 0, sizeof *l);
          memcpy (l->mac, req.chaddr, 6);
          memcpy (l->ip, yip, 4);
          l->expiry = time (NULL) + eff.lease_time;
          snprintf (l->hostname, sizeof l->hostname, "%s", req.hostname);
          bdhcpd_db_save (db_path, &db);
          bdhcpd_run_hook (&eff, "commit", req.chaddr, yip, req.hostname);
        }
    }

  char *hb = malloc (rl * 2 + 1);
  if (!hb) { free (cfg.raw); return EXECUTION_FAILURE; }
  hex_print (reply, (int) rl, hb, rl * 2 + 1);
  if (var)
    builtin_bind_variable ((char *) var, hb, 0);
  else
    printf ("%s\n", hb);
  free (hb);
  free (cfg.raw);
  return EXECUTION_SUCCESS;
}

/* ------ serve loop ------ */

static int
bdhcpd_sendto_retry (int fd, const void *buf, size_t len,
                     const struct sockaddr *dst, socklen_t dstlen)
{
  ssize_t n;
  do
    n = sendto (fd, buf, len, 0, dst, dstlen);
  while (n < 0 && errno == EINTR);
  if (n < 0) return -1;
  return (size_t) n == len ? 0 : -1;
}

static int
bdhcpd_serve_one (int fd, int proxy_fd, const struct bdhcpd_cfg *cfg,
                  const char *db_path, int max_iter)
{
  struct bdhcpd_db db;
  unsigned char buf[BDHCPD_MAX];
  for (int it = 0; (max_iter <= 0 || it < max_iter) && !bdhcpd_stop; it++)
    {
      struct sockaddr_in src;
      socklen_t srclen = sizeof src;
      struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
      fd_set rfds;
      FD_ZERO (&rfds); FD_SET (fd, &rfds);
      int maxfd = fd;
      if (proxy_fd >= 0) { FD_SET (proxy_fd, &rfds); if (proxy_fd > maxfd) maxfd = proxy_fd; }
      int sr = select (maxfd + 1, &rfds, NULL, NULL, &tv);
      if (sr <= 0) { if (sr < 0 && errno == EINTR) continue; if (max_iter > 0) continue; continue; }
      int recv_fd = (proxy_fd >= 0 && FD_ISSET (proxy_fd, &rfds)) ? proxy_fd : fd;
      ssize_t n = recvfrom (recv_fd, buf, sizeof buf, 0, (struct sockaddr *) &src, &srclen);
      if (n < 0) { if (errno == EINTR) continue; return -1; }
      struct bdhcpd_req req;
      if (bdhcpd_parse_req (buf, (size_t) n, &req) < 0) continue;

      bdhcpd_db_load (db_path, &db);
      /* Resolve the effective (possibly subnet-specific) config for this
       * client by matching the relay giaddr against configured subnets. */
      struct bdhcpd_cfg eff;
      bdhcpd_effective_cfg (cfg, req.giaddr, &eff);
      unsigned char yip[4] = { 0, 0, 0, 0 };

      unsigned char reply[BDHCPD_MAX];
      unsigned reply_type = 0;
      if (req.msg_type == 1) reply_type = 2;       /* DISCOVER -> OFFER */
      else if (req.msg_type == 3) reply_type = 5;  /* REQUEST -> ACK */
      else if (req.msg_type == 4)                  /* DECLINE — RFC 2131 §3.1.5 */
        {
          /* Client observed an ARP conflict on the offered IP.
             Quarantine it so the next pool-pick from any MAC skips
             this address until the operator-tunable
             BASHDHCPD_DECLINE_QUARANTINE_SEC window elapses. Also
             drop any persisted lease that pointed at this MAC, since
             the address is now suspect. */
          if (req.have_req_ip)
            {
              bdhcpd_quarantine_add (req.req_ip,
                                     bdhcpd_decline_quarantine_secs ());
              char ip_s[16], mac_s[24];
              fmt_ip4 (req.req_ip, ip_s, sizeof ip_s);
              fmt_mac (req.chaddr, mac_s, sizeof mac_s);
              builtin_warning ("DECLINE from %s for %s — quarantined %u sec",
                               mac_s, ip_s,
                               bdhcpd_decline_quarantine_secs ());
            }
          bdhcpd_db_remove_mac (&db, req.chaddr);
          bdhcpd_db_save (db_path, &db);
          continue;
        }
      else if (req.msg_type == 7)                  /* RELEASE */
        {
          /* DDNS hook before removal — recover the released IP from the DB. */
          for (int li = 0; li < db.n; li++)
            if (memcmp (db.v[li].mac, req.chaddr, 6) == 0)
              { bdhcpd_run_hook (&eff, "release", req.chaddr, db.v[li].ip,
                                 db.v[li].hostname); break; }
          bdhcpd_db_remove_mac (&db, req.chaddr);
          bdhcpd_db_save (db_path, &db);
          continue;
        }
      else continue;

      if (!eff.proxy_dhcp && bdhcpd_pick_ip (&eff, &db, req.chaddr, yip) < 0)
        {
          char mac_s[24];
          fmt_mac (req.chaddr, mac_s, sizeof mac_s);
          builtin_warning ("no available IP in pool for %s", mac_s);
          continue;
        }

      size_t plen = bdhcpd_build_reply (reply, sizeof reply, reply_type, &req,
                                        &eff, yip, eff.proxy_dhcp);
      if (plen == 0) continue;

      /* RFC 2131 §4.1: a relayed request (giaddr != 0) is answered to the
       * relay agent on UDP/67; a direct request is broadcast to UDP/68. */
      struct sockaddr_in dst;
      memset (&dst, 0, sizeof dst);
      dst.sin_family = AF_INET;
      if (eff.proxy_dhcp && recv_fd == proxy_fd)
        {
          dst.sin_port = src.sin_port;
          dst.sin_addr = src.sin_addr;
        }
      else if (rd32 (req.giaddr) != 0)
        { dst.sin_port = htons (bdhcpd_env_port ("BASHDHCPD_RELAY_PORT", 67));
          memcpy (&dst.sin_addr.s_addr, req.giaddr, 4); }
      else
        { dst.sin_port = htons (bdhcpd_env_port ("BASHDHCPD_CLIENT_PORT", 68));
          dst.sin_addr.s_addr = htonl (INADDR_BROADCAST); }
      if (bdhcpd_sendto_retry (recv_fd, reply, plen, (struct sockaddr *) &dst,
                               sizeof dst) < 0)
        {
          builtin_warning ("sendto reply: %s", strerror (errno));
          continue;
        }

      if (!eff.proxy_dhcp && reply_type == 5)
        {
          /* Persist the lease on ACK. */
          bdhcpd_db_remove_mac (&db, req.chaddr);
          if (db.n < BDHCPD_MAX_LEASES)
            {
              struct bdhcpd_lease *l = &db.v[db.n++];
              memset (l, 0, sizeof *l);
              memcpy (l->mac, req.chaddr, 6);
              memcpy (l->ip, yip, 4);
              l->expiry = time (NULL) + cfg->lease_time;
              snprintf (l->hostname, sizeof l->hostname, "%s", req.hostname);
              bdhcpd_db_save (db_path, &db);
              /* DDNS hook on lease commit (registers the new binding). */
              bdhcpd_run_hook (&eff, "commit", req.chaddr, yip, req.hostname);
            }
          else
            builtin_warning ("lease DB full — ACK sent but not persisted");
        }
    }
  return 0;
}

static int
bdhcpd_open_socket (const char *iface, const char *port_env,
                    unsigned short fallback_port, const char *label)
{
  int fd = socket (AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) { builtin_error ("socket: %s", strerror (errno)); return -1; }
  int one = 1;
  setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  setsockopt (fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof one);
  if (iface && *iface)
    {
      if (setsockopt (fd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen (iface)) < 0)
        {
          /* Non-fatal — many test environments forbid SO_BINDTODEVICE. */
        }
    }
  struct sockaddr_in local = { .sin_family = AF_INET,
                               .sin_port = htons (bdhcpd_env_port (port_env, fallback_port)),
                               .sin_addr.s_addr = htonl (INADDR_ANY) };
  if (bind (fd, (struct sockaddr *) &local, sizeof local) < 0)
    {
      builtin_error ("bind %s: %s", label, strerror (errno));
      close (fd);
      return -1;
    }
  return fd;
}

static int
bdhcpd_cmd_serve (WORD_LIST *args)
{
  const char *cfg_path = "/etc/dhcpd.conf";
  const char *db_path = "/var/lib/dhcpd/leases";
  const char *iface = NULL;
  int once = 0, max_iter = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-c") == 0)
        { if (!p->next) return EX_USAGE; p = p->next; cfg_path = p->word->word; }
      else if (strcmp (w, "-l") == 0)
        { if (!p->next) return EX_USAGE; p = p->next; db_path = p->word->word; }
      else if (strcmp (w, "-i") == 0)
        { if (!p->next) return EX_USAGE; p = p->next; iface = p->word->word; }
      else if (strcmp (w, "--once") == 0) { once = 1; max_iter = 1; }
      else { builtin_error ("serve: extra arg: %s", w); return EX_USAGE; }
    }
  struct bdhcpd_cfg cfg;
  if (bdhcpd_load_cfg (cfg_path, &cfg) < 0)
    {
      builtin_error ("serve: failed to load %s (need pool/netmask/server_id)", cfg_path);
      return EXECUTION_FAILURE;
    }
  /* mkdir -p the lease DB dir. */
  char dirbuf[512];
  snprintf (dirbuf, sizeof dirbuf, "%s", db_path);
  char *slash = strrchr (dirbuf, '/');
  if (slash) { *slash = '\0'; mkdir (dirbuf, 0755); }

  signal (SIGINT, bdhcpd_sig);
  signal (SIGTERM, bdhcpd_sig);

  int fd = bdhcpd_open_socket (iface, "BASHDHCPD_SERVER_PORT", 67, "udp/67");
  if (fd < 0) { free (cfg.raw); return EXECUTION_FAILURE; }
  int proxy_fd = -1;
  if (cfg.proxy_dhcp)
    {
      proxy_fd = bdhcpd_open_socket (iface, "BASHDHCPD_PROXY_PORT",
                                     BDHCPD_PROXY_PORT, "udp/4011");
      if (proxy_fd < 0)
        {
          close (fd);
          free (cfg.raw);
          return EXECUTION_FAILURE;
        }
    }

  int rc = bdhcpd_serve_one (fd, proxy_fd, &cfg, db_path, once ? 1 : max_iter);
  if (proxy_fd >= 0) close (proxy_fd);
  close (fd);
  free (cfg.raw);
  return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bdhcpd_cmd_run (WORD_LIST *args)
{
  const char *statedir = NULL;
  WORD_LIST *passthrough = NULL, **tail = &passthrough;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-d") == 0)
        { if (!p->next) return EX_USAGE; p = p->next; statedir = p->word->word; }
      else
        {
          WORD_LIST *new = make_word_list (make_word (p->word->word), NULL);
          *tail = new;
          tail = &new->next;
        }
    }
  if (statedir) mkdir (statedir, 0755);
  return bdhcpd_cmd_serve (passthrough);
}

/* selftest-decline — TTY-free, no-root exerciser for the quarantine
 * helpers. Calls the same bdhcpd_quarantine_add / _check /
 * decline_quarantine_secs entrypoints that the serve path uses, so a
 * regression in any of them surfaces here without needing a real
 * DHCP exchange (which would require CAP_NET_BIND_SERVICE on udp/67
 * + crafted DECLINE packets). Prints a TAP stream and returns 0 on
 * all-pass / 1 on any failure. */
static int
bdhcpd_cmd_selftest_decline (WORD_LIST *args)
{
  (void) args;
  int n = 0, fails = 0;
  unsigned char ip_a[4] = { 10, 0, 0, 5 };
  unsigned char ip_b[4] = { 10, 0, 0, 6 };

  /* Reset state so repeated invocations within one bash session
     don't carry stale entries. */
  bdhcpd_quarantine_n = 0;
  memset (bdhcpd_quarantine, 0, sizeof bdhcpd_quarantine);

#define D_OK(desc, cond) \
  do { ++n; if (cond) printf ("ok %d - %s\n", n, desc); \
       else { ++fails; printf ("not ok %d - %s\n", n, desc); } } while (0)

  D_OK ("fresh quarantine: unknown IP not quarantined",
        bdhcpd_quarantine_check (ip_a) == 0);
  bdhcpd_quarantine_add (ip_a, 60);
  D_OK ("after add: that IP is quarantined", bdhcpd_quarantine_check (ip_a) == 1);
  D_OK ("a different IP is still not quarantined",
        bdhcpd_quarantine_check (ip_b) == 0);
  bdhcpd_quarantine_add (ip_b, 60);
  D_OK ("after second add: both IPs quarantined",
        bdhcpd_quarantine_check (ip_a) == 1 &&
        bdhcpd_quarantine_check (ip_b) == 1);

  /* Default quarantine duration when env unset. */
  unsetenv ("BASHDHCPD_DECLINE_QUARANTINE_SEC");
  D_OK ("default quarantine duration = 60", bdhcpd_decline_quarantine_secs () == 60);

  /* Env override (legal range). */
  setenv ("BASHDHCPD_DECLINE_QUARANTINE_SEC", "300", 1);
  D_OK ("BASHDHCPD_DECLINE_QUARANTINE_SEC=300 honored",
        bdhcpd_decline_quarantine_secs () == 300);

  /* Out-of-range fall back to default. */
  setenv ("BASHDHCPD_DECLINE_QUARANTINE_SEC", "0", 1);
  D_OK ("BASHDHCPD_DECLINE_QUARANTINE_SEC=0 falls back to default 60",
        bdhcpd_decline_quarantine_secs () == 60);
  setenv ("BASHDHCPD_DECLINE_QUARANTINE_SEC", "garbage", 1);
  D_OK ("BASHDHCPD_DECLINE_QUARANTINE_SEC=garbage falls back to default 60",
        bdhcpd_decline_quarantine_secs () == 60);
  unsetenv ("BASHDHCPD_DECLINE_QUARANTINE_SEC");

  printf ("1..%d\n", n);
#undef D_OK
  return fails ? 1 : 0;
}

int
dhcpd_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;

  if (strcmp (cmd, "serve") == 0)              return bdhcpd_cmd_serve (args);
  if (strcmp (cmd, "run") == 0)                return bdhcpd_cmd_run (args);
  if (strcmp (cmd, "lease-list") == 0)         return bdhcpd_cmd_lease_list (args);
  if (strcmp (cmd, "lease-add") == 0)          return bdhcpd_cmd_lease_add (args);
  if (strcmp (cmd, "lease-remove") == 0)       return bdhcpd_cmd_lease_remove (args);
  if (strcmp (cmd, "parse-req") == 0)          return bdhcpd_cmd_parse_req (args);
  if (strcmp (cmd, "respond") == 0)            return bdhcpd_cmd_respond (args);
  if (strcmp (cmd, "selftest-decline") == 0)   return bdhcpd_cmd_selftest_decline (args);

  builtin_error ("unknown subcommand: %s (try serve/run/respond/lease-list/lease-add/lease-remove/parse-req/selftest-decline)", cmd);
  return EX_USAGE;
}

char *dhcpd_doc[] = {
  "Minimal DHCPv4 server (RFC 2131): one pool, single subnet.",
  "",
  "    dhcpd serve [-c CONFIG] [-l LEASEDB] [-i IFACE] [--once]",
  "    dhcpd run [-d STATEDIR] [-c CONFIG] [-l LEASEDB]",
  "    dhcpd lease-list [-l LEASEDB]",
  "    dhcpd lease-add MAC IP [-l LEASEDB] [-t TTL]",
  "    dhcpd lease-remove MAC [-l LEASEDB]",
  "",
  "    dhcpd parse-req HEX [-V VAR]",
  "    dhcpd respond HEX [-c CONFIG] [-l LEASEDB] [-V VAR]",
  "",
  "Config keys: pool LO HI; netmask IP; gateway IP; dns LIST;",
  "             domain NAME; server_id IP; lease SECS;",
  "             next-server IP; tftp-server NAME; bootfile NAME;",
  "             pxe-vendor-match on|off; pxe-discovery-control N;",
  "             pxe-boot-server TYPE IP[,IP...] (repeatable);",
  "             pxe-menu-item TYPE LABEL;",
  "             pxe-menu-prompt TIMEOUT TEXT; option-43 HEX;",
  "             proxy-dhcp on|off.",
  "Lease DB format: '<mac> <ip> <expiry> [hostname]' per line.",
  (char *)NULL
};

struct builtin dhcpd_struct = {
  "dhcpd",
  dhcpd_builtin,
  BUILTIN_ENABLED,
  dhcpd_doc,
  "dhcpd serve|run|respond|lease-list|lease-add|lease-remove ARGS...",
  0
};
