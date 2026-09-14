/* SPDX-License-Identifier: MIT */
/* _d6_hmacmd5.h — compact public-domain MD5 + HMAC-MD5 (RFC 2104), for the F03
 * DHCPv6 Reconfigure Key Authentication Protocol (RFC 8415 §20.4 / OPTION_AUTH
 * protocol 3, algorithm 1 = HMAC-MD5). All-static; safe to include in multiple
 * loadable TUs (each gets its own copy, no symbol clash). MD5 lifted from
 * bashrsync.c's compact implementation.
 */
#ifndef BASHOS_D6_HMACMD5_H
#define BASHOS_D6_HMACMD5_H
#include <stdint.h>
#include <string.h>

typedef struct { uint32_t a, b, c, d; uint64_t bits; unsigned char buf[64]; size_t n; } d6_md5_ctx;

static uint32_t d6_md5_u32 (const unsigned char *p)
{ return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24); }

static void d6_md5_block (d6_md5_ctx *m, const unsigned char *p)
{
  static const uint32_t K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391 };
  static const int S[64] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22, 5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23, 6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21 };
  uint32_t M[16];
  for (int i = 0; i < 16; i++) M[i] = d6_md5_u32 (p + i * 4);
  uint32_t a = m->a, b = m->b, c = m->c, d = m->d;
  for (int i = 0; i < 64; i++)
    {
      uint32_t f; int g;
      if (i < 16)      { f = (b & c) | (~b & d); g = i; }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; }
      else if (i < 48) { f = b ^ c ^ d;          g = (3 * i + 5) & 15; }
      else             { f = c ^ (b | ~d);       g = (7 * i) & 15; }
      f += a + K[i] + M[g];
      a = d; d = c; c = b;
      b += (f << S[i]) | (f >> (32 - S[i]));
    }
  m->a += a; m->b += b; m->c += c; m->d += d;
}
static void d6_md5_init (d6_md5_ctx *m)
{ m->a = 0x67452301; m->b = 0xefcdab89; m->c = 0x98badcfe; m->d = 0x10325476; m->bits = 0; m->n = 0; }
static void d6_md5_update (d6_md5_ctx *m, const unsigned char *p, size_t len)
{
  m->bits += (uint64_t) len * 8;
  while (len)
    { size_t take = 64 - m->n; if (take > len) take = len;
      memcpy (m->buf + m->n, p, take); m->n += take; p += take; len -= take;
      if (m->n == 64) { d6_md5_block (m, m->buf); m->n = 0; } }
}
static void d6_md5_final (d6_md5_ctx *m, unsigned char out[16])
{
  unsigned char pad = 0x80; uint64_t bits = m->bits;
  d6_md5_update (m, &pad, 1);
  unsigned char z = 0; while (m->n != 56) d6_md5_update (m, &z, 1);
  unsigned char lb[8]; for (int i = 0; i < 8; i++) lb[i] = (unsigned char) (bits >> (8 * i));
  memcpy (m->buf + 56, lb, 8); d6_md5_block (m, m->buf);
  uint32_t v[4] = { m->a, m->b, m->c, m->d };
  for (int i = 0; i < 4; i++)
    { out[i*4] = (unsigned char) v[i]; out[i*4+1] = (unsigned char) (v[i] >> 8);
      out[i*4+2] = (unsigned char) (v[i] >> 16); out[i*4+3] = (unsigned char) (v[i] >> 24); }
}
static void d6_md5 (const unsigned char *p, size_t len, unsigned char out[16])
{ d6_md5_ctx m; d6_md5_init (&m); d6_md5_update (&m, p, len); d6_md5_final (&m, out); }

/* HMAC-MD5 (RFC 2104), MD5 block size 64. */
static void d6_hmac_md5 (const unsigned char *key, size_t klen,
                         const unsigned char *msg, size_t mlen, unsigned char out[16])
{
  unsigned char kb[64], ipad[64], opad[64], inner[16], khash[16];
  if (klen > 64) { d6_md5 (key, klen, khash); key = khash; klen = 16; }
  memset (kb, 0, 64); memcpy (kb, key, klen);
  for (int i = 0; i < 64; i++) { ipad[i] = kb[i] ^ 0x36; opad[i] = kb[i] ^ 0x5c; }
  d6_md5_ctx m;
  d6_md5_init (&m); d6_md5_update (&m, ipad, 64); d6_md5_update (&m, msg, mlen); d6_md5_final (&m, inner);
  d6_md5_init (&m); d6_md5_update (&m, opad, 64); d6_md5_update (&m, inner, 16); d6_md5_final (&m, out);
}
#endif /* BASHOS_D6_HMACMD5_H */
