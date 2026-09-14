/* _mbedtls/poly1305.c — Poly1305 (RFC 8439 §2.5).
 *
 * 5×26-bit limb representation, identical to the standard
 * poly1305-donna 32-bit reference. Multiplication by clamped r reduces
 * mod 2^130-5 by folding the high bits back via the *5 trick.
 *
 * Style and constants verified against RFC 8439 §2.5.2.
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include "poly1305.h"
#include <string.h>

static void mb_zeroize(void *buf, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *) buf;
    while (len--) *p++ = 0;
}

#define LE32(p) ( (uint32_t)((p)[0])         |                       \
                  (uint32_t)((p)[1]) <<  8   |                       \
                  (uint32_t)((p)[2]) << 16   |                       \
                  (uint32_t)((p)[3]) << 24 )

#define PUT_LE32(v, p) do {                                          \
    (p)[0] = (unsigned char)((v));                                   \
    (p)[1] = (unsigned char)((v) >>  8);                             \
    (p)[2] = (unsigned char)((v) >> 16);                             \
    (p)[3] = (unsigned char)((v) >> 24);                             \
} while (0)

void mbedtls_poly1305_init(mbedtls_poly1305_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

void mbedtls_poly1305_free(mbedtls_poly1305_context *ctx)
{
    if (!ctx) return;
    mb_zeroize(ctx, sizeof(*ctx));
}

int mbedtls_poly1305_starts(mbedtls_poly1305_context *ctx,
                            const unsigned char key[32])
{
    /* Read 16 LE bytes of r and clamp per RFC 8439 §2.5: clear bits
     *   - r[3] (high nibble each 32-bit word): top 4 bits → 0x0fffffff
     *   - r[7,11,15]: low 2 bits → 0xfffffffc
     *
     * Encoded across 5 26-bit limbs:
     *   t0..t3 = LE32 from key[0..15]
     *   r[0] = (t0)                     & 0x3ffffff
     *   r[1] = ((t0 >> 26) | (t1 <<  6)) & 0x3ffff03
     *   r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff
     *   r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff
     *   r[4] = (t3 >>  8)                & 0x00fffff
     */
    uint32_t t0 = LE32(key + 0);
    uint32_t t1 = LE32(key + 4);
    uint32_t t2 = LE32(key + 8);
    uint32_t t3 = LE32(key + 12);

    ctx->r[0] =  t0                      & 0x03FFFFFF;
    ctx->r[1] = ((t0 >> 26) | (t1 <<  6)) & 0x03FFFF03;
    ctx->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x03FFC0FF;
    ctx->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x03F03FFF;
    ctx->r[4] =  (t3 >>  8)              & 0x000FFFFF;

    ctx->s[0] = LE32(key + 16);
    ctx->s[1] = LE32(key + 20);
    ctx->s[2] = LE32(key + 24);
    ctx->s[3] = LE32(key + 28);

    ctx->acc[0] = ctx->acc[1] = ctx->acc[2] = ctx->acc[3] = ctx->acc[4] = 0;
    ctx->queue_len = 0;
    return 0;
}

/* Process one 16-byte block. If `is_final_short` is non-zero, no high
 * 0x01 byte is appended (final block uses block-length-explicit encoding). */
static void poly1305_blocks(mbedtls_poly1305_context *ctx,
                            const unsigned char *m, size_t bytes,
                            int high_one)
{
    const uint32_t hibit = high_one ? (1U << 24) : 0;
    uint32_t r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2],
             r3 = ctx->r[3], r4 = ctx->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = ctx->acc[0], h1 = ctx->acc[1], h2 = ctx->acc[2],
             h3 = ctx->acc[3], h4 = ctx->acc[4];

    while (bytes >= 16) {
        uint32_t t0 = LE32(m + 0), t1 = LE32(m + 4),
                 t2 = LE32(m + 8), t3 = LE32(m + 12);

        /* h += m */
        h0 +=  t0                      & 0x03FFFFFF;
        h1 += ((t0 >> 26) | (t1 <<  6)) & 0x03FFFFFF;
        h2 += ((t1 >> 20) | (t2 << 12)) & 0x03FFFFFF;
        h3 += ((t2 >> 14) | (t3 << 18)) & 0x03FFFFFF;
        h4 += (t3 >> 8) | hibit;

        /* h *= r mod 2^130 - 5 */
        uint64_t d0 = (uint64_t) h0 * r0 + (uint64_t) h1 * s4 +
                      (uint64_t) h2 * s3 + (uint64_t) h3 * s2 + (uint64_t) h4 * s1;
        uint64_t d1 = (uint64_t) h0 * r1 + (uint64_t) h1 * r0 +
                      (uint64_t) h2 * s4 + (uint64_t) h3 * s3 + (uint64_t) h4 * s2;
        uint64_t d2 = (uint64_t) h0 * r2 + (uint64_t) h1 * r1 +
                      (uint64_t) h2 * r0 + (uint64_t) h3 * s4 + (uint64_t) h4 * s3;
        uint64_t d3 = (uint64_t) h0 * r3 + (uint64_t) h1 * r2 +
                      (uint64_t) h2 * r1 + (uint64_t) h3 * r0 + (uint64_t) h4 * s4;
        uint64_t d4 = (uint64_t) h0 * r4 + (uint64_t) h1 * r3 +
                      (uint64_t) h2 * r2 + (uint64_t) h3 * r1 + (uint64_t) h4 * r0;

        /* (partial) carry chain */
        uint32_t c;
        c = (uint32_t) (d0 >> 26);  h0 = (uint32_t) (d0 & 0x03FFFFFF); d1 += c;
        c = (uint32_t) (d1 >> 26);  h1 = (uint32_t) (d1 & 0x03FFFFFF); d2 += c;
        c = (uint32_t) (d2 >> 26);  h2 = (uint32_t) (d2 & 0x03FFFFFF); d3 += c;
        c = (uint32_t) (d3 >> 26);  h3 = (uint32_t) (d3 & 0x03FFFFFF); d4 += c;
        c = (uint32_t) (d4 >> 26);  h4 = (uint32_t) (d4 & 0x03FFFFFF); h0 += c * 5;
        c =            (h0 >> 26);  h0 &= 0x03FFFFFF;                  h1 += c;

        m += 16; bytes -= 16;
    }

    ctx->acc[0] = h0; ctx->acc[1] = h1; ctx->acc[2] = h2;
    ctx->acc[3] = h3; ctx->acc[4] = h4;
}

int mbedtls_poly1305_update(mbedtls_poly1305_context *ctx,
                            const unsigned char *input, size_t ilen)
{
    /* Drain queue first if it has held-over bytes. */
    if (ctx->queue_len) {
        size_t want = 16 - ctx->queue_len;
        size_t take = ilen < want ? ilen : want;
        memcpy(ctx->queue + ctx->queue_len, input, take);
        ctx->queue_len += take;
        input += take; ilen -= take;
        if (ctx->queue_len == 16) {
            poly1305_blocks(ctx, ctx->queue, 16, 1);
            ctx->queue_len = 0;
        }
    }
    /* Bulk full blocks. */
    if (ilen >= 16) {
        size_t bulk = ilen & ~(size_t) 15;
        poly1305_blocks(ctx, input, bulk, 1);
        input += bulk; ilen -= bulk;
    }
    /* Buffer remainder. */
    if (ilen) {
        memcpy(ctx->queue, input, ilen);
        ctx->queue_len = ilen;
    }
    return 0;
}

int mbedtls_poly1305_finish(mbedtls_poly1305_context *ctx,
                            unsigned char mac[16])
{
    /* Pad final partial block per §2.5.1: pad with 0x01 then zero. */
    if (ctx->queue_len) {
        ctx->queue[ctx->queue_len++] = 0x01;
        while (ctx->queue_len < 16) ctx->queue[ctx->queue_len++] = 0;
        poly1305_blocks(ctx, ctx->queue, 16, 0);
    }

    /* Final reduction: collapse h[0..4] to a tight 130-bit value. */
    uint32_t h0 = ctx->acc[0], h1 = ctx->acc[1], h2 = ctx->acc[2],
             h3 = ctx->acc[3], h4 = ctx->acc[4];
    uint32_t c;
    c =      h1 >> 26;  h1 &= 0x03FFFFFF;  h2 += c;
    c =      h2 >> 26;  h2 &= 0x03FFFFFF;  h3 += c;
    c =      h3 >> 26;  h3 &= 0x03FFFFFF;  h4 += c;
    c =      h4 >> 26;  h4 &= 0x03FFFFFF;  h0 += c * 5;
    c =      h0 >> 26;  h0 &= 0x03FFFFFF;  h1 += c;

    /* h ?>= p, where p = 2^130 - 5. Subtract p; if borrow stays inside,
     * accept the subtracted result (h was >= p). */
    uint32_t g0 = h0 + 5;          c = g0 >> 26; g0 &= 0x03FFFFFF;
    uint32_t g1 = h1 + c;          c = g1 >> 26; g1 &= 0x03FFFFFF;
    uint32_t g2 = h2 + c;          c = g2 >> 26; g2 &= 0x03FFFFFF;
    uint32_t g3 = h3 + c;          c = g3 >> 26; g3 &= 0x03FFFFFF;
    uint32_t g4 = h4 + c - (1U << 26);
    /* If g4 high bit clear, h was < p — keep h. Else use g. */
    uint32_t mask = (g4 >> 31) - 1;          /* 0 if h<p; ~0 if h>=p */
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* Re-pack 5×26 → 4×32-bit. */
    uint32_t f0 =  h0        | (h1 << 26);
    uint32_t f1 = (h1 >>  6) | (h2 << 20);
    uint32_t f2 = (h2 >> 12) | (h3 << 14);
    uint32_t f3 = (h3 >> 18) | (h4 <<  8);

    /* Tag = (h + s) mod 2^128. */
    uint64_t t = (uint64_t) f0 + ctx->s[0]; f0 = (uint32_t) t;
    t = (uint64_t) f1 + ctx->s[1] + (t >> 32); f1 = (uint32_t) t;
    t = (uint64_t) f2 + ctx->s[2] + (t >> 32); f2 = (uint32_t) t;
    t = (uint64_t) f3 + ctx->s[3] + (t >> 32); f3 = (uint32_t) t;

    PUT_LE32(f0, mac +  0);
    PUT_LE32(f1, mac +  4);
    PUT_LE32(f2, mac +  8);
    PUT_LE32(f3, mac + 12);
    return 0;
}

int mbedtls_poly1305_mac(const unsigned char key[32],
                         const unsigned char *input, size_t ilen,
                         unsigned char mac[16])
{
    mbedtls_poly1305_context ctx;
    int ret;
    mbedtls_poly1305_init(&ctx);
    if ((ret = mbedtls_poly1305_starts(&ctx, key)) != 0) goto out;
    if ((ret = mbedtls_poly1305_update(&ctx, input, ilen)) != 0) goto out;
    ret = mbedtls_poly1305_finish(&ctx, mac);
out:
    mbedtls_poly1305_free(&ctx);
    return ret;
}
