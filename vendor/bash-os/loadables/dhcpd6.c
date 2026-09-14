/* SPDX-License-Identifier: MIT */
/* dhcpd6.c — DHCPv6 server (RFC 8415). Loadable for bash.
 *
 * Server side of the dhcp6 client; the DHCPv6 counterpart to dhcpd
 * (which is v4-only). Slice 3 of the F03 DHCPv6 track
 * (research/bash-os/F03-DHCPv6-DESIGN.md): answer SOLICIT→ADVERTISE and
 * REQUEST/RENEW→REPLY from a configured IPv6 address pool, keyed by client
 * DUID + IAID, with a flat lease DB. RELEASE frees the lease.
 *
 * Subcommands:
 *   dhcpd6 serve [-c CONFIG] [-l LEASEDB] [-i IFACE] [--once]
 *       Bind UDP/[::]:547, answer DHCPv6 messages (reply to the client's
 *       source link-local address on :546).
 *   dhcpd6 run [-c CONFIG] [-l LEASEDB]      sv-friendly wrapper.
 *   dhcpd6 respond HEX [-c CONFIG] [-l LEASEDB] [-V VAR]
 *       HOST-TESTABLE seam: parse a client message hex, allocate, persist, and
 *       print (or bind) the reply hex — the same path serve() runs, no socket.
 *   dhcpd6 leasequery HEX [-c CONFIG] [-l LEASEDB] [-V VAR]
 *       HOST-TESTABLE RFC 5007 read seam: answer QUERY_BY_ADDRESS and
 *       QUERY_BY_CLIENTID against the existing lease DB, no socket.
 *   dhcpd6 lease-list [-l LEASEDB]
 *
 * Config (/etc/dhcpd6.conf):
 *   server-duid <hex>     # required (e.g. from `dhcp6 duid-ll <mac>`)
 *   pool-start  <ipv6>    # required; addresses handed out start here
 *   pool-size   <n>       # required; number of addresses (start..start+n-1)
 *   dns         <ipv6>    # optional, repeatable
 *   lease-pref  <sec>     # preferred lifetime (default 3600)
 *   lease-valid <sec>     # valid lifetime (default 7200)
 *   t1 <sec> / t2 <sec>   # IA_NA renew/rebind timers (default valid/2, *0.8)
 *
 * Lease DB (one per line):  <duid-hex> <iaid> <addr-hex32> <expiry-unix>
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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "loadables.h"
#include "_d6_hmacmd5.h"

/* msg types / option codes (shared wire constants with dhcp6) */
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
#define D6_LEASEQUERY 14
#define D6_LEASEQUERY_REPLY 15
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
#define D6O_IA_PD 25
#define D6O_IAPREFIX 26
#define D6O_LQ_QUERY 44
#define D6O_CLIENT_DATA 45
#define D6O_CLT_TIME 46
#define D6S_UNSPECFAIL 1
#define D6D_LQ_BY_ADDRESS 1
#define D6D_LQ_BY_CLIENTID 2
/* F03 relay (RFC 8415 §19–20) */
#define D6_RELAY_FORW 12
#define D6_RELAY_REPL 13
#define D6O_RELAY_MSG 9
#define D6O_INTERFACE_ID 18
/* F03 RECONFIGURE + RKAP auth (RFC 8415 §18.3.11/§20.4, §21.11/§21.19) */
#define D6_RECONFIGURE 10
#define D6O_AUTH 11
#define D6O_RECONF_MSG 19
#define D6_MAX 1500
#define D6D_MAX_LEASES 256

static volatile sig_atomic_t d6d_stop = 0;
static void d6d_sig (int s) { (void) s; d6d_stop = 1; }

/* ---- big-endian helpers + hex ---- */
static unsigned rd16 (const unsigned char *p) { return ((unsigned) p[0] << 8) | p[1]; }
static void wr16 (unsigned char *p, unsigned v) { p[0] = (unsigned char) (v >> 8); p[1] = (unsigned char) v; }
static unsigned rd32 (const unsigned char *p)
{ return ((unsigned) p[0] << 24) | ((unsigned) p[1] << 16) | ((unsigned) p[2] << 8) | p[3]; }
static void wr32 (unsigned char *p, unsigned v)
{ p[0]=(unsigned char)(v>>24); p[1]=(unsigned char)(v>>16); p[2]=(unsigned char)(v>>8); p[3]=(unsigned char)v; }
static int hexval (int c)
{ if (c>='0'&&c<='9') return c-'0'; if (c>='a'&&c<='f') return c-'a'+10;
  if (c>='A'&&c<='F') return c-'A'+10;
  return -1; }
static int hex_decode (const char *h, unsigned char *o, size_t cap)
{ size_t n=0; int hi=-1; for (const char *p=h;*p;p++){ if (isspace((unsigned char)*p)) continue;
    int v=hexval((unsigned char)*p); if (v<0) return -1;
    if (hi<0) hi=v; else { if (n>=cap) return -1; o[n++]=(unsigned char)((hi<<4)|v); hi=-1; } }
  return hi<0?(int)n:-1; }
static void hex_print (const unsigned char *b, int n, char *o, size_t cap)
{ size_t k=0; for (int i=0;i<n && k+2<cap;i++){ snprintf(o+k,cap-k,"%02x",b[i]); k+=2; } o[k]='\0'; }

/* add a small offset to a 128-bit address (carry from the low byte up). */
static void addr_add (const unsigned char base[16], unsigned off, unsigned char out[16])
{
  memcpy (out, base, 16);
  for (int i = 15; i >= 0 && off; i--) { unsigned s = out[i] + (off & 0xff); out[i] = (unsigned char) s; off = (off >> 8) + (s >> 8); }
}

/* ---- parsed client request ---- */
struct d6d_req {
  int msg_type; unsigned xid;
  unsigned char client_id[132]; int cid_len;
  unsigned char server_id[132]; int sid_len;
  int have_ia; unsigned iaid;
  int have_pd; unsigned pd_iaid;
  int rapid_commit;
};

static void d6d_scan (const unsigned char *d, int len, struct d6d_req *r);  /* fwd */

static int d6d_parse (const unsigned char *pkt, int len, struct d6d_req *r)
{
  memset (r, 0, sizeof *r);
  if (len < 4) return -1;
  r->msg_type = pkt[0];
  r->xid = ((unsigned) pkt[1] << 16) | ((unsigned) pkt[2] << 8) | pkt[3];
  d6d_scan (pkt + 4, len - 4, r);
  return r->msg_type ? 0 : -1;
}
static void d6d_scan (const unsigned char *d, int len, struct d6d_req *r)
{
  int p = 0;
  while (p + 4 <= len)
    {
      unsigned code = rd16 (d + p), olen = rd16 (d + p + 2);
      if (p + 4 + (int) olen > len) break;
      const unsigned char *v = d + p + 4;
      switch (code)
        {
        case D6O_CLIENTID: { int n = olen < sizeof r->client_id ? (int) olen : (int) sizeof r->client_id;
                             memcpy (r->client_id, v, n); r->cid_len = n; break; }
        case D6O_SERVERID: { int n = olen < sizeof r->server_id ? (int) olen : (int) sizeof r->server_id;
                             memcpy (r->server_id, v, n); r->sid_len = n; break; }
        case D6O_IA_NA: if (olen >= 12) { r->have_ia = 1; r->iaid = rd32 (v); } break;
        case D6O_IA_PD: if (olen >= 12) { r->have_pd = 1; r->pd_iaid = rd32 (v); } break;
        case D6O_RAPID_COMMIT: r->rapid_commit = 1; break;
        default: break;
        }
      p += 4 + olen;
    }
}

/* ---- config ---- */
struct d6d_cfg {
  unsigned char server_duid[132]; int sduid_len;
  unsigned char pool_start[16]; int have_pool;
  unsigned pool_size;
  unsigned char pd_start[16]; int have_pd; int pd_len; unsigned pd_size;
  unsigned char dns[8][16]; int n_dns;
  unsigned pref_life, valid_life, t1, t2;
  char *raw;
};

/* Add `off` delegated-prefixes to a base prefix at the /plen bit boundary. */
static void pfx_add (const unsigned char base[16], unsigned off, int plen, unsigned char out[16])
{
  memcpy (out, base, 16);
  int bit = 128 - plen;                 /* add off << bit */
  int byte = 15 - bit / 8, shift = bit % 8;
  unsigned carry = off << shift;
  for (int i = byte; i >= 0 && carry; i--)
    { unsigned s = out[i] + (carry & 0xff); out[i] = (unsigned char) s; carry = (carry >> 8) + (s >> 8); }
}

static int d6d_load_cfg (const char *path, struct d6d_cfg *c)
{
  memset (c, 0, sizeof *c);
  c->pref_life = 3600; c->valid_life = 7200; c->pool_size = 0;
  FILE *f = fopen (path, "r");
  if (!f) return -1;
  fseek (f, 0, SEEK_END); long sz = ftell (f); fseek (f, 0, SEEK_SET);
  if (sz < 0 || sz > 65536) { fclose (f); return -1; }
  c->raw = malloc ((size_t) sz + 1); if (!c->raw) { fclose (f); return -1; }
  size_t n = fread (c->raw, 1, (size_t) sz, f); c->raw[n] = '\0'; fclose (f);
  char *p = c->raw;
  while (*p)
    {
      char *eol = strchr (p, '\n'); if (eol) *eol = '\0';
      char *line = p; while (*line == ' ' || *line == '\t') line++;
      if (*line && *line != '#')
        {
          char *key = line; while (*line && *line != ' ' && *line != '\t') line++;
          if (*line) { *line++ = '\0'; while (*line == ' ' || *line == '\t') line++; }
          char *val = line;
          if (!strcmp (key, "server-duid")) c->sduid_len = hex_decode (val, c->server_duid, sizeof c->server_duid);
          else if (!strcmp (key, "pool-start")) { if (inet_pton (AF_INET6, val, c->pool_start) == 1) c->have_pool = 1; }
          else if (!strcmp (key, "pool-size")) c->pool_size = (unsigned) strtoul (val, NULL, 10);
          else if (!strcmp (key, "pd-start")) { if (inet_pton (AF_INET6, val, c->pd_start) == 1) c->have_pd = 1; }
          else if (!strcmp (key, "pd-len")) c->pd_len = (int) strtol (val, NULL, 10);
          else if (!strcmp (key, "pd-size")) c->pd_size = (unsigned) strtoul (val, NULL, 10);
          else if (!strcmp (key, "dns")) { if (c->n_dns < 8 && inet_pton (AF_INET6, val, c->dns[c->n_dns]) == 1) c->n_dns++; }
          else if (!strcmp (key, "lease-pref")) c->pref_life = (unsigned) strtoul (val, NULL, 10);
          else if (!strcmp (key, "lease-valid")) c->valid_life = (unsigned) strtoul (val, NULL, 10);
          else if (!strcmp (key, "t1")) c->t1 = (unsigned) strtoul (val, NULL, 10);
          else if (!strcmp (key, "t2")) c->t2 = (unsigned) strtoul (val, NULL, 10);
        }
      if (!eol) break;
      p = eol + 1;
    }
  if (c->t1 == 0) c->t1 = c->valid_life / 2;
  if (c->t2 == 0) c->t2 = (c->valid_life / 5) * 4;
  if (c->have_pd) { if (c->pd_len <= 0 || c->pd_len > 128) c->pd_len = 64; if (c->pd_size == 0) c->pd_size = 1; }
  /* need a server DUID and at least one of an address pool or a PD pool */
  int has_na_pool = c->have_pool && c->pool_size > 0;
  if (c->sduid_len <= 0 || (!has_na_pool && !c->have_pd)) { free (c->raw); c->raw = NULL; return -1; }
  return 0;
}

/* ---- lease DB: "<duidhex> <iaid> <addrhex32> <expiry>" ---- */
/* plen==0 => an IA_NA address lease; plen>0 => an IA_PD delegated-prefix lease.
 * Keying on (duid,iaid,is_pd) keeps the NA and PD iaid spaces separate. */
struct d6d_lease { char duid[266]; unsigned iaid; unsigned char addr[16]; long expiry; int plen; };
struct d6d_db { struct d6d_lease v[D6D_MAX_LEASES]; int n; };

static void d6d_db_load (const char *path, struct d6d_db *db)
{
  memset (db, 0, sizeof *db);
  FILE *f = fopen (path, "r"); if (!f) return;
  char line[512];
  while (fgets (line, sizeof line, f) && db->n < D6D_MAX_LEASES)
    {
      char duid[266], addrh[40]; unsigned iaid; long exp; int plen = 0;
      int got = sscanf (line, "%265s %u %39s %ld %d", duid, &iaid, addrh, &exp, &plen);
      if (got >= 4)
        {
          struct d6d_lease *l = &db->v[db->n];
          snprintf (l->duid, sizeof l->duid, "%s", duid); l->iaid = iaid; l->expiry = exp;
          l->plen = (got >= 5) ? plen : 0;
          if (hex_decode (addrh, l->addr, 16) == 16) db->n++;
        }
    }
  fclose (f);
}
static void d6d_db_save (const char *path, const struct d6d_db *db)
{
  FILE *f = fopen (path, "w"); if (!f) return;
  for (int i = 0; i < db->n; i++)
    { char ah[40]; hex_print (db->v[i].addr, 16, ah, sizeof ah);
      fprintf (f, "%s %u %s %ld %d\n", db->v[i].duid, db->v[i].iaid, ah, db->v[i].expiry, db->v[i].plen); }
  fclose (f);
}

/* Allocate (or reuse) an address for (duid,iaid). Returns 0 + fills addr. */
static int d6d_alloc (const struct d6d_cfg *cfg, struct d6d_db *db,
                      const char *duidh, unsigned iaid, unsigned char out[16])
{
  for (int i = 0; i < db->n; i++)
    if (db->v[i].plen == 0 && db->v[i].iaid == iaid && strcmp (db->v[i].duid, duidh) == 0)
      { memcpy (out, db->v[i].addr, 16); return 0; }
  /* first pool offset not already leased */
  for (unsigned off = 0; off < cfg->pool_size; off++)
    {
      unsigned char cand[16]; addr_add (cfg->pool_start, off, cand);
      int used = 0;
      for (int i = 0; i < db->n; i++) if (db->v[i].plen == 0 && memcmp (db->v[i].addr, cand, 16) == 0) { used = 1; break; }
      if (!used) { memcpy (out, cand, 16); return 0; }
    }
  return -1;   /* pool exhausted */
}

/* Allocate (or reuse) a delegated prefix for (duid,pd_iaid). */
static int d6d_alloc_pd (const struct d6d_cfg *cfg, struct d6d_db *db,
                         const char *duidh, unsigned iaid, unsigned char out[16])
{
  for (int i = 0; i < db->n; i++)
    if (db->v[i].plen > 0 && db->v[i].iaid == iaid && strcmp (db->v[i].duid, duidh) == 0)
      { memcpy (out, db->v[i].addr, 16); return 0; }
  for (unsigned off = 0; off < cfg->pd_size; off++)
    {
      unsigned char cand[16]; pfx_add (cfg->pd_start, off, cfg->pd_len, cand);
      int used = 0;
      for (int i = 0; i < db->n; i++) if (db->v[i].plen > 0 && memcmp (db->v[i].addr, cand, 16) == 0) { used = 1; break; }
      if (!used) { memcpy (out, cand, 16); return 0; }
    }
  return -1;   /* PD pool exhausted */
}

/* ---- reply builder ---- */
static size_t d6d_opt (unsigned char *b, size_t p, size_t cap, unsigned code, const unsigned char *d, size_t len)
{ if (p + 4 + len > cap) return 0; wr16 (b + p, code); wr16 (b + p + 2, (unsigned) len);
  if (len && d) memcpy (b + p + 4, d, len);
  return p + 4 + len; }

/* Build ADVERTISE/REPLY for a request. Emits IA_NA{IAADDR} when include_addr,
 * IA_PD{IAPREFIX} when include_pd, both with STATUS=success. INFOREQ replies
 * carry neither (just SERVERID + CLIENTID + DNS). */
static size_t d6d_build (unsigned char *buf, size_t cap, int reply_type,
                         const struct d6d_req *req, const struct d6d_cfg *cfg,
                         const unsigned char addr[16], int include_addr,
                         const unsigned char prefix[16], int include_pd)
{
  if (cap < 4) return 0;
  buf[0] = (unsigned char) reply_type;
  buf[1] = (unsigned char) (req->xid >> 16); buf[2] = (unsigned char) (req->xid >> 8); buf[3] = (unsigned char) req->xid;
  size_t p = 4;
  /* SERVERID */
  p = d6d_opt (buf, p, cap, D6O_SERVERID, cfg->server_duid, cfg->sduid_len); if (!p) return 0;
  /* CLIENTID (echo) */
  if (req->cid_len > 0) { p = d6d_opt (buf, p, cap, D6O_CLIENTID, req->client_id, req->cid_len); if (!p) return 0; }
  /* IA_NA { iaid, t1, t2, IAADDR{addr,pref,valid}, STATUS=0 } — only if requested */
  if (req->have_ia)
    {
      unsigned char ia[12 + 28 + 6]; size_t ip = 0;
      wr32 (ia, req->iaid); wr32 (ia + 4, cfg->t1); wr32 (ia + 8, cfg->t2); ip = 12;
      if (include_addr)
        { wr16 (ia + ip, D6O_IAADDR); wr16 (ia + ip + 2, 24); ip += 4;
          memcpy (ia + ip, addr, 16); wr32 (ia + ip + 16, cfg->pref_life); wr32 (ia + ip + 20, cfg->valid_life); ip += 24; }
      wr16 (ia + ip, D6O_STATUS_CODE); wr16 (ia + ip + 2, 2); wr16 (ia + ip + 4, 0); ip += 6;  /* success */
      p = d6d_opt (buf, p, cap, D6O_IA_NA, ia, ip); if (!p) return 0;
    }
  /* IA_PD { pd_iaid, t1, t2, IAPREFIX{pref,valid,plen,prefix}, STATUS=0 } */
  if (include_pd)
    {
      unsigned char ia[12 + 29 + 6]; size_t ip = 0;
      wr32 (ia, req->pd_iaid); wr32 (ia + 4, cfg->t1); wr32 (ia + 8, cfg->t2); ip = 12;
      wr16 (ia + ip, D6O_IAPREFIX); wr16 (ia + ip + 2, 25); ip += 4;
      wr32 (ia + ip, cfg->pref_life); wr32 (ia + ip + 4, cfg->valid_life);
      ia[ip + 8] = (unsigned char) cfg->pd_len; memcpy (ia + ip + 9, prefix, 16); ip += 25;
      wr16 (ia + ip, D6O_STATUS_CODE); wr16 (ia + ip + 2, 2); wr16 (ia + ip + 4, 0); ip += 6;
      p = d6d_opt (buf, p, cap, D6O_IA_PD, ia, ip); if (!p) return 0;
    }
  /* rapid-commit echo (only when the client asked and we REPLY) */
  if (req->rapid_commit && reply_type == D6_REPLY)
    { p = d6d_opt (buf, p, cap, D6O_RAPID_COMMIT, NULL, 0); if (!p) return 0; }
  /* DNS_SERVERS */
  if (cfg->n_dns > 0)
    { unsigned char dns[8 * 16]; for (int i = 0; i < cfg->n_dns; i++) memcpy (dns + i * 16, cfg->dns[i], 16);
      p = d6d_opt (buf, p, cap, D6O_DNS_SERVERS, dns, (size_t) cfg->n_dns * 16); if (!p) return 0; }
  return p;
}

struct d6d_lq_req {
  int msg_type; unsigned xid;
  unsigned query_type;
  unsigned char client_id[132]; int cid_len;
  unsigned char addr[16]; int have_addr;
};

static void
d6d_lq_scan_key (const unsigned char *d, int len, struct d6d_lq_req *q)
{
  int p = 0;
  while (p + 4 <= len)
    {
      unsigned code = rd16 (d + p), olen = rd16 (d + p + 2);
      if (p + 4 + (int) olen > len) break;
      const unsigned char *v = d + p + 4;
      if (code == D6O_CLIENTID)
        {
          int n = olen < sizeof q->client_id ? (int) olen : (int) sizeof q->client_id;
          memcpy (q->client_id, v, n); q->cid_len = n;
        }
      else if (code == D6O_IAADDR && olen >= 16)
        {
          memcpy (q->addr, v, 16); q->have_addr = 1;
        }
      else if (code == D6O_CLIENT_DATA)
        d6d_lq_scan_key (v, (int) olen, q);
      p += 4 + olen;
    }
}

static int
d6d_parse_lq (const unsigned char *pkt, int len, struct d6d_lq_req *q)
{
  memset (q, 0, sizeof *q);
  if (len < 4) return -1;
  q->msg_type = pkt[0];
  q->xid = ((unsigned) pkt[1] << 16) | ((unsigned) pkt[2] << 8) | pkt[3];
  if (q->msg_type != D6_LEASEQUERY) return -1;
  int p = 4;
  while (p + 4 <= len)
    {
      unsigned code = rd16 (pkt + p), olen = rd16 (pkt + p + 2);
      if (p + 4 + (int) olen > len) return -1;
      const unsigned char *v = pkt + p + 4;
      if (code == D6O_LQ_QUERY)
        {
          if (olen < 1) return -1;
          q->query_type = v[0];
          if (olen >= 17 && !q->have_addr)
            { memcpy (q->addr, v + 1, 16); q->have_addr = 1; }
          if (olen > 1)
            d6d_lq_scan_key (v + 1, (int) olen - 1, q);
        }
      else if (code == D6O_CLIENT_DATA)
        d6d_lq_scan_key (v, (int) olen, q);
      else if (code == D6O_CLIENTID)
        {
          int n = olen < sizeof q->client_id ? (int) olen : (int) sizeof q->client_id;
          memcpy (q->client_id, v, n); q->cid_len = n;
        }
      p += 4 + olen;
    }
  if (q->query_type == D6D_LQ_BY_ADDRESS && q->have_addr)
    return 0;
  if (q->query_type == D6D_LQ_BY_CLIENTID && q->cid_len > 0)
    return 0;
  return -1;
}

static size_t
d6d_lq_add_status (unsigned char *buf, size_t p, size_t cap, unsigned status,
                   const char *msg)
{
  unsigned char st[128];
  size_t ml = msg ? strlen (msg) : 0;
  if (ml > sizeof st - 2) ml = sizeof st - 2;
  wr16 (st, status);
  if (ml) memcpy (st + 2, msg, ml);
  return d6d_opt (buf, p, cap, D6O_STATUS_CODE, st, 2 + ml);
}

static size_t
d6d_lq_add_lease (unsigned char *cd, size_t cp, size_t cap,
                  const struct d6d_cfg *cfg, const struct d6d_lease *l,
                  long now)
{
  if (l->plen > 0 || l->expiry <= now)
    return cp;
  unsigned char ia[24];
  long remaining_l = l->expiry - now;
  unsigned remaining = remaining_l > 0 ? (unsigned) remaining_l : 0;
  unsigned pref = cfg->pref_life < remaining ? cfg->pref_life : remaining;
  memcpy (ia, l->addr, 16);
  wr32 (ia + 16, pref);
  wr32 (ia + 20, remaining);
  size_t np = d6d_opt (cd, cp, cap, D6O_IAADDR, ia, sizeof ia);
  if (!np) return 0;
  cp = np;
  unsigned char clt[4];
  unsigned elapsed = 0;
  if (cfg->valid_life > remaining)
    elapsed = cfg->valid_life - remaining;
  wr32 (clt, elapsed);
  return d6d_opt (cd, cp, cap, D6O_CLT_TIME, clt, sizeof clt);
}

static size_t
d6d_build_lq_reply (unsigned char *buf, size_t cap, const struct d6d_lq_req *q,
                    const struct d6d_cfg *cfg, const struct d6d_db *db)
{
  if (cap < 4) return 0;
  buf[0] = D6_LEASEQUERY_REPLY;
  buf[1] = (unsigned char) (q->xid >> 16); buf[2] = (unsigned char) (q->xid >> 8); buf[3] = (unsigned char) q->xid;
  size_t p = 4;
  p = d6d_opt (buf, p, cap, D6O_SERVERID, cfg->server_duid, cfg->sduid_len); if (!p) return 0;

  char qduid[266] = "";
  if (q->cid_len > 0)
    hex_print (q->client_id, q->cid_len, qduid, sizeof qduid);
  const char *match_duid = NULL;
  for (int i = 0; i < db->n; i++)
    {
      const struct d6d_lease *l = &db->v[i];
      if (l->plen > 0) continue;
      if (q->query_type == D6D_LQ_BY_ADDRESS && memcmp (l->addr, q->addr, 16) == 0)
        { match_duid = l->duid; break; }
      if (q->query_type == D6D_LQ_BY_CLIENTID && strcmp (l->duid, qduid) == 0)
        { match_duid = l->duid; break; }
    }
  if (!match_duid)
    return d6d_lq_add_status (buf, p, cap, D6S_UNSPECFAIL, "lease not found");

  unsigned char cd[D6_MAX];
  size_t cp = 0;
  unsigned char cid[132];
  int cid_len = hex_decode (match_duid, cid, sizeof cid);
  if (cid_len <= 0) return 0;
  cp = d6d_opt (cd, cp, sizeof cd, D6O_CLIENTID, cid, (size_t) cid_len); if (!cp) return 0;
  long now = time (NULL);
  int added = 0;
  for (int i = 0; i < db->n; i++)
    {
      const struct d6d_lease *l = &db->v[i];
      if (strcmp (l->duid, match_duid) != 0)
        continue;
      if (q->query_type == D6D_LQ_BY_ADDRESS && memcmp (l->addr, q->addr, 16) != 0)
        continue;
      size_t np = d6d_lq_add_lease (cd, cp, sizeof cd, cfg, l, now);
      if (!np) return 0;
      if (np != cp) added = 1;
      cp = np;
    }
  if (!added)
    return d6d_lq_add_status (buf, p, cap, D6S_UNSPECFAIL, "lease not found");
  return d6d_opt (buf, p, cap, D6O_CLIENT_DATA, cd, cp);
}

/* Process one client message → reply. Returns reply length (0 = drop).
 * Persists/removes leases in db (caller saves). */
static size_t d6d_respond (const unsigned char *pkt, int len, const struct d6d_cfg *cfg,
                           struct d6d_db *db, int *dirty, unsigned char *reply, size_t cap)
{
  struct d6d_req req;
  if (d6d_parse (pkt, len, &req) < 0 || req.cid_len <= 0) return 0;
  char duidh[266]; hex_print (req.client_id, req.cid_len, duidh, sizeof duidh);
  *dirty = 0;

  if (req.msg_type == D6_RELEASE)
    {
      /* free every NA/PD lease this client (duid) holds for the released iaids */
      for (int i = 0; i < db->n; )
        if (strcmp (db->v[i].duid, duidh) == 0
            && ((req.have_ia && db->v[i].plen == 0 && db->v[i].iaid == req.iaid)
                || (req.have_pd && db->v[i].plen > 0 && db->v[i].iaid == req.pd_iaid)))
          { db->v[i] = db->v[--db->n]; *dirty = 1; }
        else i++;
      return d6d_build (reply, cap, D6_REPLY, &req, cfg, NULL, 0, NULL, 0);
    }

  /* INFORMATION-REQUEST: stateless config (no IA, no lease). */
  if (req.msg_type == D6_INFOREQ)
    return d6d_build (reply, cap, D6_REPLY, &req, cfg, NULL, 0, NULL, 0);

  if (req.msg_type != D6_SOLICIT && req.msg_type != D6_REQUEST
      && req.msg_type != D6_RENEW && req.msg_type != D6_REBIND) return 0;
  if (!req.have_ia && !req.have_pd) return 0;

  unsigned char addr[16], prefix[16];
  int give_na = 0, give_pd = 0;
  if (req.have_ia && cfg->have_pool && d6d_alloc (cfg, db, duidh, req.iaid, addr) == 0) give_na = 1;
  if (req.have_pd && cfg->have_pd && d6d_alloc_pd (cfg, db, duidh, req.pd_iaid, prefix) == 0) give_pd = 1;
  if (!give_na && !give_pd) return 0;                    /* nothing to offer */

  /* SOLICIT → ADVERTISE, unless rapid-commit → REPLY. REQUEST/RENEW/REBIND → REPLY. */
  int reply_type = (req.msg_type == D6_SOLICIT && !req.rapid_commit) ? D6_ADVERTISE : D6_REPLY;
  if (reply_type == D6_REPLY)
    {
      long now = time (NULL);
      if (give_na)
        { int found = 0;
          for (int i = 0; i < db->n; i++)
            if (db->v[i].plen == 0 && db->v[i].iaid == req.iaid && strcmp (db->v[i].duid, duidh) == 0)
              { db->v[i].expiry = now + cfg->valid_life; found = 1; break; }
          if (!found && db->n < D6D_MAX_LEASES)
            { struct d6d_lease *l = &db->v[db->n++];
              snprintf (l->duid, sizeof l->duid, "%s", duidh); l->iaid = req.iaid; l->plen = 0;
              memcpy (l->addr, addr, 16); l->expiry = now + cfg->valid_life; } }
      if (give_pd)
        { int found = 0;
          for (int i = 0; i < db->n; i++)
            if (db->v[i].plen > 0 && db->v[i].iaid == req.pd_iaid && strcmp (db->v[i].duid, duidh) == 0)
              { db->v[i].expiry = now + cfg->valid_life; found = 1; break; }
          if (!found && db->n < D6D_MAX_LEASES)
            { struct d6d_lease *l = &db->v[db->n++];
              snprintf (l->duid, sizeof l->duid, "%s", duidh); l->iaid = req.pd_iaid; l->plen = cfg->pd_len;
              memcpy (l->addr, prefix, 16); l->expiry = now + cfg->valid_life; } }
      *dirty = 1;
    }
  return d6d_build (reply, cap, reply_type, &req, cfg, addr, give_na, prefix, give_pd);
}

/* F03 relay: if pkt is a RELAY-FORW, peel OPTION_RELAY_MSG (recursing through
   nested relays), answer the inner message, and wrap the reply in a RELAY-REPL
   echoing hop/link/peer + INTERFACE_ID. A plain (non-relay) message is handled
   directly by d6d_respond. Returns reply length, or 0 to drop. */
static size_t d6d_relay_respond (const unsigned char *pkt, int len, const struct d6d_cfg *cfg,
                                 struct d6d_db *db, int *dirty, unsigned char *reply, size_t cap)
{
  if (len < 1) return 0;
  if (pkt[0] != D6_RELAY_FORW)
    return d6d_respond (pkt, len, cfg, db, dirty, reply, cap);
  if (len < 34) return 0;                 /* type(1)+hop(1)+link(16)+peer(16) */
  int hop = pkt[1];
  if (hop > 32) return 0;                 /* RFC 8415 HOP_COUNT_LIMIT — drop */
  const unsigned char *link = pkt + 2, *peer = pkt + 18;
  const unsigned char *inner = NULL, *ifid = NULL;
  int inner_len = 0, ifid_len = 0;
  for (int q = 34; q + 4 <= len; )
    {
      unsigned code = rd16 (pkt + q), olen = rd16 (pkt + q + 2);
      if (q + 4 + (int) olen > len) break;
      if (code == D6O_RELAY_MSG) { inner = pkt + q + 4; inner_len = (int) olen; }
      else if (code == D6O_INTERFACE_ID) { ifid = pkt + q + 4; ifid_len = (int) olen; }
      q += 4 + olen;
    }
  if (!inner || inner_len < 1) return 0;
  /* recurse so nested RELAY-FORW layers peel before reaching the real message */
  unsigned char ireply[D6_MAX];
  size_t irl = d6d_relay_respond (inner, inner_len, cfg, db, dirty, ireply, sizeof ireply);
  if (irl == 0) return 0;
  size_t p = 0;
  if (34 + 4 + irl > cap) return 0;
  reply[p++] = D6_RELAY_REPL; reply[p++] = (unsigned char) hop;
  memcpy (reply + p, link, 16); p += 16;
  memcpy (reply + p, peer, 16); p += 16;
  wr16 (reply + p, D6O_RELAY_MSG); wr16 (reply + p + 2, (unsigned) irl);
  memcpy (reply + p + 4, ireply, irl); p += 4 + irl;
  if (ifid)
    {
      if (p + 4 + (size_t) ifid_len > cap) return 0;
      wr16 (reply + p, D6O_INTERFACE_ID); wr16 (reply + p + 2, (unsigned) ifid_len);
      memcpy (reply + p + 4, ifid, (size_t) ifid_len); p += 4 + (size_t) ifid_len;
    }
  return p;
}

/* ---- socket serve loop ---- */
static unsigned short d6d_port (const char *env, unsigned short fb)
{ const char *s = getenv (env); if (!s || !*s) return fb;
  unsigned long v = strtoul (s, NULL, 10); return (v >= 1 && v <= 65535) ? (unsigned short) v : fb; }

static int d6d_serve (const struct d6d_cfg *cfg, const char *iface, const char *db_path, int once)
{
  int fd = socket (AF_INET6, SOCK_DGRAM, 0);
  if (fd < 0) { builtin_error ("serve: socket: %s", strerror (errno)); return -1; }
  int one = 1; setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  if (iface && *iface) setsockopt (fd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen (iface));
  struct sockaddr_in6 la; memset (&la, 0, sizeof la);
  la.sin6_family = AF_INET6; la.sin6_addr = in6addr_any;
  la.sin6_port = htons (d6d_port ("BASHDHCPD6_SERVER_PORT", 547));
  if (bind (fd, (struct sockaddr *) &la, sizeof la) < 0)
    { builtin_error ("serve: bind [::]:547: %s", strerror (errno)); close (fd); return -1; }
  unsigned short cport = d6d_port ("BASHDHCPD6_CLIENT_PORT", 546);

  signal (SIGINT, d6d_sig); signal (SIGTERM, d6d_sig); d6d_stop = 0;
  unsigned char pkt[D6_MAX], reply[D6_MAX];
  struct d6d_db db;
  for (int it = 0; (once ? it < 64 : 1) && !d6d_stop; it++)
    {
      struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
      fd_set rf; FD_ZERO (&rf); FD_SET (fd, &rf);
      int sr = select (fd + 1, &rf, NULL, NULL, &tv);
      if (sr <= 0) { if (sr < 0 && errno == EINTR) continue; if (once) break; continue; }
      struct sockaddr_in6 src; socklen_t sl = sizeof src;
      ssize_t n = recvfrom (fd, pkt, sizeof pkt, 0, (struct sockaddr *) &src, &sl);
      if (n < 4) continue;
      d6d_db_load (db_path, &db);
      int dirty = 0;
      size_t rl = d6d_relay_respond (pkt, (int) n, cfg, &db, &dirty, reply, sizeof reply);
      if (dirty) d6d_db_save (db_path, &db);
      if (rl == 0) continue;
      src.sin6_port = htons (cport);
      if (sendto (fd, reply, rl, 0, (struct sockaddr *) &src, sl) < 0)
        builtin_warning ("serve: sendto: %s", strerror (errno));
      if (once) break;
    }
  close (fd);
  return 0;
}

/* ---- verbs ---- */
static int d6d_cmd_lease_list (const char *path)
{
  struct d6d_db db; d6d_db_load (path, &db); long now = time (NULL);
  for (int i = 0; i < db.n; i++)
    { char a[INET6_ADDRSTRLEN]; inet_ntop (AF_INET6, db.v[i].addr, a, sizeof a);
      if (db.v[i].plen > 0)
        printf ("%s iaid=%u %s/%d kind=pd expiry=%ld remaining=%ld\n", db.v[i].duid, db.v[i].iaid, a,
                db.v[i].plen, db.v[i].expiry, db.v[i].expiry - now);
      else
        printf ("%s iaid=%u %s kind=na expiry=%ld remaining=%ld\n", db.v[i].duid, db.v[i].iaid, a,
                db.v[i].expiry, db.v[i].expiry - now); }
  return EXECUTION_SUCCESS;
}

int dhcpd6_builtin (WORD_LIST *list)
{
  char *argv[64]; int argc = 0;
  for (WORD_LIST *p = list; p && argc < 64; p = p->next) argv[argc++] = p->word->word;
  if (argc == 0) { builtin_usage (); return EX_USAGE; }
  const char *cmd = argv[0];

  if (!strcmp (cmd, "--version") || !strcmp (cmd, "-V"))
    { printf ("dhcpd6 (bash-os F03 DHCPv6) RFC 8415 server\n"); return EXECUTION_SUCCESS; }
  if (!strcmp (cmd, "-h") || !strcmp (cmd, "--help")) { builtin_usage (); return EXECUTION_SUCCESS; }

  /* F03: build a server-initiated RECONFIGURE(10) authenticated with RKAP
     (OPTION_AUTH protocol 3 / algorithm 1 = HMAC-MD5 over the whole message
     with the digest field zeroed). Its flags differ from the serve/respond
     option set, so it parses argv itself before the shared scan. */
  if (!strcmp (cmd, "reconfigure"))
    {
      const char *cduid_h = NULL, *sduid_h = NULL, *key_h = NULL, *rvar = NULL;
      const char *reconf = "renew"; unsigned xid = 0; int have_xid = 0;
      unsigned long long replay = 0; int have_replay = 0;
      for (int i = 1; i < argc; i++)
        {
          if (!strcmp (argv[i], "--client-duid") && i + 1 < argc) cduid_h = argv[++i];
          else if (!strcmp (argv[i], "--server-duid") && i + 1 < argc) sduid_h = argv[++i];
          else if (!strcmp (argv[i], "--key") && i + 1 < argc) key_h = argv[++i];
          else if (!strcmp (argv[i], "--reconf") && i + 1 < argc) reconf = argv[++i];
          else if (!strcmp (argv[i], "-x") && i + 1 < argc) { xid = (unsigned) (strtoul (argv[++i], NULL, 16) & 0xffffff); have_xid = 1; }
          else if (!strcmp (argv[i], "--replay") && i + 1 < argc) { replay = strtoull (argv[++i], NULL, 0); have_replay = 1; }
          else if (!strcmp (argv[i], "-V") && i + 1 < argc) rvar = argv[++i];
          else { builtin_error ("reconfigure: unexpected arg: %s", argv[i]); return EX_USAGE; }
        }
      if (!cduid_h || !sduid_h || !key_h)
        { builtin_error ("reconfigure: --client-duid, --server-duid and --key (hex) required"); return EX_USAGE; }
      int reconf_mt;
      if (!strcmp (reconf, "renew")) reconf_mt = D6_RENEW;
      else if (!strcmp (reconf, "inforequest") || !strcmp (reconf, "information-request")) reconf_mt = D6_INFOREQ;
      else { builtin_error ("reconfigure: --reconf must be renew|inforequest"); return EX_USAGE; }
      unsigned char cid[132], sid[132], key[64];
      int cidlen = hex_decode (cduid_h, cid, sizeof cid);
      int sidlen = hex_decode (sduid_h, sid, sizeof sid);
      int keylen = hex_decode (key_h, key, sizeof key);
      if (cidlen <= 0 || sidlen <= 0 || keylen <= 0) { builtin_error ("reconfigure: bad hex in duid/key"); return EX_USAGE; }
      unsigned char buf[D6_MAX]; size_t p = 0;
      if (!have_xid) xid = (unsigned) (time (NULL) & 0xffffff);
      buf[p++] = D6_RECONFIGURE;
      buf[p++] = (unsigned char) (xid >> 16); buf[p++] = (unsigned char) (xid >> 8); buf[p++] = (unsigned char) xid;
      wr16 (buf + p, D6O_CLIENTID); wr16 (buf + p + 2, (unsigned) cidlen); memcpy (buf + p + 4, cid, cidlen); p += 4 + cidlen;
      wr16 (buf + p, D6O_SERVERID); wr16 (buf + p + 2, (unsigned) sidlen); memcpy (buf + p + 4, sid, sidlen); p += 4 + sidlen;
      /* OPTION_AUTH: proto(1)+algo(1)+rdm(1)+replay(8)+authinfo[type(1)+digest(16)] = 28 */
      wr16 (buf + p, D6O_AUTH); wr16 (buf + p + 2, 28); p += 4;
      buf[p++] = 3; buf[p++] = 1; buf[p++] = 0;             /* protocol, algorithm, RDM */
      if (!have_replay) replay = (unsigned long long) time (NULL);
      for (int i = 0; i < 8; i++) buf[p + i] = (unsigned char) (replay >> (8 * (7 - i)));
      p += 8;
      buf[p++] = 2;                                          /* authinfo type 2 = HMAC-MD5 digest */
      size_t digest_off = p; memset (buf + p, 0, 16); p += 16;
      wr16 (buf + p, D6O_RECONF_MSG); wr16 (buf + p + 2, 1); buf[p + 4] = (unsigned char) reconf_mt; p += 5;
      unsigned char dig[16];
      d6_hmac_md5 (key, (size_t) keylen, buf, p, dig);       /* HMAC over whole msg, digest zeroed */
      memcpy (buf + digest_off, dig, 16);
      char *hb = malloc (p * 2 + 1); if (!hb) return EXECUTION_FAILURE;
      hex_print (buf, (int) p, hb, p * 2 + 1);
      if (rvar) builtin_bind_variable ((char *) rvar, hb, 0); else printf ("%s\n", hb);
      free (hb);
      return EXECUTION_SUCCESS;
    }

  /* shared option scan */
  const char *cfgp = "/etc/dhcpd6.conf", *db_path = "/var/lib/dhcpd6/leases";
  const char *iface = NULL, *hex = NULL, *var = NULL; int once = 0;
  for (int i = 1; i < argc; i++)
    {
      if (!strcmp (argv[i], "-c") && i + 1 < argc) cfgp = argv[++i];
      else if (!strcmp (argv[i], "-l") && i + 1 < argc) db_path = argv[++i];
      else if (!strcmp (argv[i], "-i") && i + 1 < argc) iface = argv[++i];
      else if (!strcmp (argv[i], "--once")) once = 1;
      else if (!strcmp (argv[i], "-V") && i + 1 < argc) var = argv[++i];
      else if (argv[i][0] != '-' && !hex) hex = argv[i];
      else { builtin_error ("%s: unexpected arg: %s", cmd, argv[i]); return EX_USAGE; }
    }

	  if (!strcmp (cmd, "lease-list")) return d6d_cmd_lease_list (db_path);

	  if (!strcmp (cmd, "leasequery"))
	    {
	      if (!hex) { builtin_error ("leasequery HEX [-c CONFIG] [-l LEASEDB] [-V VAR]"); return EX_USAGE; }
	      struct d6d_cfg cfg;
	      if (d6d_load_cfg (cfgp, &cfg) < 0) { builtin_error ("leasequery: bad/missing config %s (need server-duid + pool-start + pool-size)", cfgp); return EXECUTION_FAILURE; }
	      unsigned char pkt[D6_MAX]; int n = hex_decode (hex, pkt, sizeof pkt);
	      if (n < 0) { builtin_error ("leasequery: bad hex"); free (cfg.raw); return EX_USAGE; }
	      struct d6d_lq_req q;
	      if (d6d_parse_lq (pkt, n, &q) < 0)
	        { builtin_error ("leasequery: malformed/unsupported LEASEQUERY"); free (cfg.raw); return EXECUTION_FAILURE; }
	      struct d6d_db db; d6d_db_load (db_path, &db);
	      unsigned char reply[D6_MAX];
	      size_t rl = d6d_build_lq_reply (reply, sizeof reply, &q, &cfg, &db);
	      free (cfg.raw);
	      if (rl == 0) { builtin_error ("leasequery: no reply (drop)"); return EXECUTION_FAILURE; }
	      char *hb = malloc (rl * 2 + 1); if (!hb) return EXECUTION_FAILURE;
	      hex_print (reply, (int) rl, hb, rl * 2 + 1);
	      if (var) builtin_bind_variable ((char *) var, hb, 0); else printf ("%s\n", hb);
	      free (hb);
	      return EXECUTION_SUCCESS;
	    }

	  if (!strcmp (cmd, "respond"))
	    {
      if (!hex) { builtin_error ("respond HEX [-c CONFIG] [-l LEASEDB]"); return EX_USAGE; }
      struct d6d_cfg cfg;
      if (d6d_load_cfg (cfgp, &cfg) < 0) { builtin_error ("respond: bad/missing config %s (need server-duid + pool-start + pool-size)", cfgp); return EXECUTION_FAILURE; }
      unsigned char pkt[D6_MAX]; int n = hex_decode (hex, pkt, sizeof pkt);
      if (n < 0) { builtin_error ("respond: bad hex"); free (cfg.raw); return EX_USAGE; }
      struct d6d_db db; d6d_db_load (db_path, &db);
      int dirty = 0; unsigned char reply[D6_MAX];
      size_t rl = d6d_relay_respond (pkt, n, &cfg, &db, &dirty, reply, sizeof reply);
      if (dirty) d6d_db_save (db_path, &db);
      free (cfg.raw);
      if (rl == 0) { builtin_error ("respond: no reply (drop)"); return EXECUTION_FAILURE; }
      char *hb = malloc (rl * 2 + 1); if (!hb) return EXECUTION_FAILURE;
      hex_print (reply, (int) rl, hb, rl * 2 + 1);
      if (var) builtin_bind_variable ((char *) var, hb, 0); else printf ("%s\n", hb);
      free (hb);
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (cmd, "serve") || !strcmp (cmd, "run"))
    {
      struct d6d_cfg cfg;
      if (d6d_load_cfg (cfgp, &cfg) < 0) { builtin_error ("serve: bad/missing config %s", cfgp); return EXECUTION_FAILURE; }
      int rc = d6d_serve (&cfg, iface, db_path, once);
      free (cfg.raw);
      return rc < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    }

	  builtin_error ("unknown verb: %s (try serve/run/respond/leasequery/reconfigure/lease-list/--version)", cmd);
	  return EX_USAGE;
	}

char *dhcpd6_doc[] = {
  "DHCPv6 (RFC 8415) server.",
  "",
  "    dhcpd6 serve [-c CONFIG] [-l LEASEDB] [-i IFACE] [--once]",
  "        Bind [::]:547 and answer SOLICIT->ADVERTISE / REQUEST,RENEW->REPLY",
  "        from the configured IPv6 pool (reply to the client's src:546).",
  "    dhcpd6 run [-c CONFIG] [-l LEASEDB]      sv wrapper.",
	  "    dhcpd6 respond HEX [-c CONFIG] [-l LEASEDB] [-V VAR]",
	  "        Host-testable: parse a client message, allocate+persist, emit the",
	  "        reply hex (same path as serve, no socket).",
	  "    dhcpd6 leasequery HEX [-c CONFIG] [-l LEASEDB] [-V VAR]",
	  "        Host-testable RFC 5007 read query: QUERY_BY_ADDRESS and",
	  "        QUERY_BY_CLIENTID over the existing lease DB.",
	  "    dhcpd6 lease-list [-l LEASEDB]",
  "    dhcpd6 reconfigure --client-duid HEX --server-duid HEX --key HEX",
  "        [--reconf renew|inforequest] [--replay N] [-x XID] [-V VAR]",
  "        Build a RECONFIGURE(10) authenticated with RKAP (OPTION_AUTH",
  "        HMAC-MD5 over the whole message, digest zeroed). Emits hex.",
  "    dhcpd6 --version",
  "",
  "Config keys: server-duid <hex>, pool-start <ipv6>, pool-size <n>,",
  "dns <ipv6> (repeatable), lease-pref/lease-valid/t1/t2 <sec>.",
  (char *) NULL
};

struct builtin dhcpd6_struct = {
  "dhcpd6",
  dhcpd6_builtin,
  BUILTIN_ENABLED,
  dhcpd6_doc,
	  "dhcpd6 serve|run|respond|leasequery|lease-list|--version ARGS",
  0
};
