/* _mbedtls/sha1.c — SHA-1 implementation (Stage 19.B).
 *
 * FIPS 180-4 §6.1 — algorithm verbatim. C-only path; no SIMD variants.
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include "sha1.h"
#include <string.h>

#define SHA1_BLOCK_SIZE 64

#define MBEDTLS_GET_UINT32_BE(data, offset)                          \
    (((uint32_t) (data)[(offset) + 0] << 24) |                       \
     ((uint32_t) (data)[(offset) + 1] << 16) |                       \
     ((uint32_t) (data)[(offset) + 2] <<  8) |                       \
     ((uint32_t) (data)[(offset) + 3]))

#define MBEDTLS_PUT_UINT32_BE(n, data, offset) do {                  \
    (data)[(offset) + 0] = (unsigned char) ((n) >> 24);              \
    (data)[(offset) + 1] = (unsigned char) ((n) >> 16);              \
    (data)[(offset) + 2] = (unsigned char) ((n) >>  8);              \
    (data)[(offset) + 3] = (unsigned char) ((n));                    \
} while (0)

static void mb_zeroize(void *buf, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *) buf;
    while (len--) *p++ = 0;
}

void mbedtls_sha1_init(mbedtls_sha1_context *ctx)  { memset(ctx, 0, sizeof(*ctx)); }

void mbedtls_sha1_free(mbedtls_sha1_context *ctx)
{
    if (!ctx) return;
    mb_zeroize(ctx, sizeof(*ctx));
}

void mbedtls_sha1_clone(mbedtls_sha1_context *dst,
                        const mbedtls_sha1_context *src) { *dst = *src; }

int mbedtls_sha1_starts(mbedtls_sha1_context *ctx)
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;
    /* SHA-1 IV — FIPS 180-4 §5.3.1. */
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    return 0;
}

#define ROL(x, n) (((x) << (n)) | (((x) & 0xFFFFFFFFu) >> (32 - (n))))
#define R_W(t)  (W[(t) & 0x0F] = ROL(                                \
                  W[((t) - 3)  & 0x0F] ^                             \
                  W[((t) - 8)  & 0x0F] ^                             \
                  W[((t) - 14) & 0x0F] ^                             \
                  W[((t) - 16) & 0x0F], 1))

#define P(a, b, c, d, e, x) do {                                     \
    e += ROL(a, 5) + F(b, c, d) + K + (x);                           \
    b = ROL(b, 30);                                                  \
} while (0)

static int sha1_process_block(mbedtls_sha1_context *ctx,
                              const unsigned char data[SHA1_BLOCK_SIZE])
{
    uint32_t W[16];
    uint32_t A, B, C, D, E;
    int i;

    for (i = 0; i < 16; i++) W[i] = MBEDTLS_GET_UINT32_BE(data, 4 * i);

    A = ctx->state[0]; B = ctx->state[1]; C = ctx->state[2];
    D = ctx->state[3]; E = ctx->state[4];

    {
        uint32_t K = 0x5A827999;
#define F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))   /* Ch */
        P(A, B, C, D, E, W[ 0]); P(E, A, B, C, D, W[ 1]); P(D, E, A, B, C, W[ 2]); P(C, D, E, A, B, W[ 3]);
        P(B, C, D, E, A, W[ 4]); P(A, B, C, D, E, W[ 5]); P(E, A, B, C, D, W[ 6]); P(D, E, A, B, C, W[ 7]);
        P(C, D, E, A, B, W[ 8]); P(B, C, D, E, A, W[ 9]); P(A, B, C, D, E, W[10]); P(E, A, B, C, D, W[11]);
        P(D, E, A, B, C, W[12]); P(C, D, E, A, B, W[13]); P(B, C, D, E, A, W[14]); P(A, B, C, D, E, W[15]);
        P(E, A, B, C, D, R_W(16)); P(D, E, A, B, C, R_W(17)); P(C, D, E, A, B, R_W(18)); P(B, C, D, E, A, R_W(19));
#undef F
    }
    {
        uint32_t K = 0x6ED9EBA1;
#define F(x, y, z) ((x) ^ (y) ^ (z))                /* Parity */
        P(A, B, C, D, E, R_W(20)); P(E, A, B, C, D, R_W(21)); P(D, E, A, B, C, R_W(22)); P(C, D, E, A, B, R_W(23));
        P(B, C, D, E, A, R_W(24)); P(A, B, C, D, E, R_W(25)); P(E, A, B, C, D, R_W(26)); P(D, E, A, B, C, R_W(27));
        P(C, D, E, A, B, R_W(28)); P(B, C, D, E, A, R_W(29)); P(A, B, C, D, E, R_W(30)); P(E, A, B, C, D, R_W(31));
        P(D, E, A, B, C, R_W(32)); P(C, D, E, A, B, R_W(33)); P(B, C, D, E, A, R_W(34)); P(A, B, C, D, E, R_W(35));
        P(E, A, B, C, D, R_W(36)); P(D, E, A, B, C, R_W(37)); P(C, D, E, A, B, R_W(38)); P(B, C, D, E, A, R_W(39));
#undef F
    }
    {
        uint32_t K = 0x8F1BBCDC;
#define F(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))  /* Maj */
        P(A, B, C, D, E, R_W(40)); P(E, A, B, C, D, R_W(41)); P(D, E, A, B, C, R_W(42)); P(C, D, E, A, B, R_W(43));
        P(B, C, D, E, A, R_W(44)); P(A, B, C, D, E, R_W(45)); P(E, A, B, C, D, R_W(46)); P(D, E, A, B, C, R_W(47));
        P(C, D, E, A, B, R_W(48)); P(B, C, D, E, A, R_W(49)); P(A, B, C, D, E, R_W(50)); P(E, A, B, C, D, R_W(51));
        P(D, E, A, B, C, R_W(52)); P(C, D, E, A, B, R_W(53)); P(B, C, D, E, A, R_W(54)); P(A, B, C, D, E, R_W(55));
        P(E, A, B, C, D, R_W(56)); P(D, E, A, B, C, R_W(57)); P(C, D, E, A, B, R_W(58)); P(B, C, D, E, A, R_W(59));
#undef F
    }
    {
        uint32_t K = 0xCA62C1D6;
#define F(x, y, z) ((x) ^ (y) ^ (z))                /* Parity */
        P(A, B, C, D, E, R_W(60)); P(E, A, B, C, D, R_W(61)); P(D, E, A, B, C, R_W(62)); P(C, D, E, A, B, R_W(63));
        P(B, C, D, E, A, R_W(64)); P(A, B, C, D, E, R_W(65)); P(E, A, B, C, D, R_W(66)); P(D, E, A, B, C, R_W(67));
        P(C, D, E, A, B, R_W(68)); P(B, C, D, E, A, R_W(69)); P(A, B, C, D, E, R_W(70)); P(E, A, B, C, D, R_W(71));
        P(D, E, A, B, C, R_W(72)); P(C, D, E, A, B, R_W(73)); P(B, C, D, E, A, R_W(74)); P(A, B, C, D, E, R_W(75));
        P(E, A, B, C, D, R_W(76)); P(D, E, A, B, C, R_W(77)); P(C, D, E, A, B, R_W(78)); P(B, C, D, E, A, R_W(79));
#undef F
    }

    ctx->state[0] += A; ctx->state[1] += B; ctx->state[2] += C;
    ctx->state[3] += D; ctx->state[4] += E;

    mb_zeroize(W, sizeof W);
    return 0;
}

int mbedtls_sha1_update(mbedtls_sha1_context *ctx,
                        const unsigned char *input, size_t ilen)
{
    int ret = 0;
    size_t fill;
    uint32_t left;

    if (ilen == 0) return 0;

    left = ctx->total[0] & 0x3F;
    fill = SHA1_BLOCK_SIZE - left;

    ctx->total[0] += (uint32_t) ilen;
    ctx->total[0] &= 0xFFFFFFFF;
    if (ctx->total[0] < (uint32_t) ilen) ctx->total[1]++;

    if (left && ilen >= fill) {
        memcpy(ctx->buffer + left, input, fill);
        if ((ret = sha1_process_block(ctx, ctx->buffer)) != 0) return ret;
        input += fill; ilen -= fill; left = 0;
    }
    while (ilen >= SHA1_BLOCK_SIZE) {
        if ((ret = sha1_process_block(ctx, input)) != 0) return ret;
        input += SHA1_BLOCK_SIZE; ilen -= SHA1_BLOCK_SIZE;
    }
    if (ilen > 0) memcpy(ctx->buffer + left, input, ilen);
    return 0;
}

int mbedtls_sha1_finish(mbedtls_sha1_context *ctx, unsigned char *output)
{
    int ret;
    uint32_t used = ctx->total[0] & 0x3F;
    uint32_t high, low;

    ctx->buffer[used++] = 0x80;

    if (used <= 56) {
        memset(ctx->buffer + used, 0, 56 - used);
    } else {
        memset(ctx->buffer + used, 0, SHA1_BLOCK_SIZE - used);
        if ((ret = sha1_process_block(ctx, ctx->buffer)) != 0) return ret;
        memset(ctx->buffer, 0, 56);
    }

    high = (ctx->total[0] >> 29) | (ctx->total[1] << 3);
    low  = (ctx->total[0] << 3);
    MBEDTLS_PUT_UINT32_BE(high, ctx->buffer, 56);
    MBEDTLS_PUT_UINT32_BE(low,  ctx->buffer, 60);

    if ((ret = sha1_process_block(ctx, ctx->buffer)) != 0) return ret;

    MBEDTLS_PUT_UINT32_BE(ctx->state[0], output,  0);
    MBEDTLS_PUT_UINT32_BE(ctx->state[1], output,  4);
    MBEDTLS_PUT_UINT32_BE(ctx->state[2], output,  8);
    MBEDTLS_PUT_UINT32_BE(ctx->state[3], output, 12);
    MBEDTLS_PUT_UINT32_BE(ctx->state[4], output, 16);
    return 0;
}

int mbedtls_sha1(const unsigned char *input, size_t ilen, unsigned char *output)
{
    mbedtls_sha1_context ctx;
    int ret;
    mbedtls_sha1_init(&ctx);
    if ((ret = mbedtls_sha1_starts(&ctx)) != 0) goto out;
    if ((ret = mbedtls_sha1_update(&ctx, input, ilen)) != 0) goto out;
    ret = mbedtls_sha1_finish(&ctx, output);
out:
    mbedtls_sha1_free(&ctx);
    return ret;
}
