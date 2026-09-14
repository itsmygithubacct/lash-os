/* _mbedtls/md5.c — MD5 (RFC 1321), Stage 19.B.
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include "md5.h"
#include <string.h>

#define MD5_BLOCK_SIZE 64

/* Little-endian accessors (MD5 spec is LE, unlike SHA-1/2). */
#define MBEDTLS_GET_UINT32_LE(data, offset)                          \
    (((uint32_t) (data)[(offset) + 0])       |                       \
     ((uint32_t) (data)[(offset) + 1] <<  8) |                       \
     ((uint32_t) (data)[(offset) + 2] << 16) |                       \
     ((uint32_t) (data)[(offset) + 3] << 24))

#define MBEDTLS_PUT_UINT32_LE(n, data, offset) do {                  \
    (data)[(offset) + 0] = (unsigned char) ((n));                    \
    (data)[(offset) + 1] = (unsigned char) ((n) >>  8);              \
    (data)[(offset) + 2] = (unsigned char) ((n) >> 16);              \
    (data)[(offset) + 3] = (unsigned char) ((n) >> 24);              \
} while (0)

static void mb_zeroize(void *buf, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *) buf;
    while (len--) *p++ = 0;
}

void mbedtls_md5_init(mbedtls_md5_context *ctx) { memset(ctx, 0, sizeof(*ctx)); }

void mbedtls_md5_free(mbedtls_md5_context *ctx)
{
    if (!ctx) return;
    mb_zeroize(ctx, sizeof(*ctx));
}

void mbedtls_md5_clone(mbedtls_md5_context *dst,
                       const mbedtls_md5_context *src) { *dst = *src; }

int mbedtls_md5_starts(mbedtls_md5_context *ctx)
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    return 0;
}

#define ROL(x, n) (((x) << (n)) | (((x) & 0xFFFFFFFFu) >> (32 - (n))))

#define F(x, y, z) (z ^ (x & (y ^ z)))         /* round 1 */
#define G(x, y, z) (y ^ (z & (x ^ y)))         /* round 2 */
#define H(x, y, z) ((x) ^ (y) ^ (z))           /* round 3 */
#define I(x, y, z) ((y) ^ ((x) | ~(z)))        /* round 4 */

#define P(a, b, c, d, k, s, t, FUNC) do {                            \
    a += FUNC(b, c, d) + X[k] + (uint32_t) (t);                      \
    a = ROL(a, s) + b;                                               \
} while (0)

static int md5_process_block(mbedtls_md5_context *ctx,
                             const unsigned char data[MD5_BLOCK_SIZE])
{
    uint32_t X[16], A, B, C, D;
    int i;
    for (i = 0; i < 16; i++) X[i] = MBEDTLS_GET_UINT32_LE(data, 4 * i);

    A = ctx->state[0]; B = ctx->state[1]; C = ctx->state[2]; D = ctx->state[3];

    /* Round 1 */
    P(A, B, C, D,  0,  7, 0xD76AA478, F); P(D, A, B, C,  1, 12, 0xE8C7B756, F);
    P(C, D, A, B,  2, 17, 0x242070DB, F); P(B, C, D, A,  3, 22, 0xC1BDCEEE, F);
    P(A, B, C, D,  4,  7, 0xF57C0FAF, F); P(D, A, B, C,  5, 12, 0x4787C62A, F);
    P(C, D, A, B,  6, 17, 0xA8304613, F); P(B, C, D, A,  7, 22, 0xFD469501, F);
    P(A, B, C, D,  8,  7, 0x698098D8, F); P(D, A, B, C,  9, 12, 0x8B44F7AF, F);
    P(C, D, A, B, 10, 17, 0xFFFF5BB1, F); P(B, C, D, A, 11, 22, 0x895CD7BE, F);
    P(A, B, C, D, 12,  7, 0x6B901122, F); P(D, A, B, C, 13, 12, 0xFD987193, F);
    P(C, D, A, B, 14, 17, 0xA679438E, F); P(B, C, D, A, 15, 22, 0x49B40821, F);

    /* Round 2 */
    P(A, B, C, D,  1,  5, 0xF61E2562, G); P(D, A, B, C,  6,  9, 0xC040B340, G);
    P(C, D, A, B, 11, 14, 0x265E5A51, G); P(B, C, D, A,  0, 20, 0xE9B6C7AA, G);
    P(A, B, C, D,  5,  5, 0xD62F105D, G); P(D, A, B, C, 10,  9, 0x02441453, G);
    P(C, D, A, B, 15, 14, 0xD8A1E681, G); P(B, C, D, A,  4, 20, 0xE7D3FBC8, G);
    P(A, B, C, D,  9,  5, 0x21E1CDE6, G); P(D, A, B, C, 14,  9, 0xC33707D6, G);
    P(C, D, A, B,  3, 14, 0xF4D50D87, G); P(B, C, D, A,  8, 20, 0x455A14ED, G);
    P(A, B, C, D, 13,  5, 0xA9E3E905, G); P(D, A, B, C,  2,  9, 0xFCEFA3F8, G);
    P(C, D, A, B,  7, 14, 0x676F02D9, G); P(B, C, D, A, 12, 20, 0x8D2A4C8A, G);

    /* Round 3 */
    P(A, B, C, D,  5,  4, 0xFFFA3942, H); P(D, A, B, C,  8, 11, 0x8771F681, H);
    P(C, D, A, B, 11, 16, 0x6D9D6122, H); P(B, C, D, A, 14, 23, 0xFDE5380C, H);
    P(A, B, C, D,  1,  4, 0xA4BEEA44, H); P(D, A, B, C,  4, 11, 0x4BDECFA9, H);
    P(C, D, A, B,  7, 16, 0xF6BB4B60, H); P(B, C, D, A, 10, 23, 0xBEBFBC70, H);
    P(A, B, C, D, 13,  4, 0x289B7EC6, H); P(D, A, B, C,  0, 11, 0xEAA127FA, H);
    P(C, D, A, B,  3, 16, 0xD4EF3085, H); P(B, C, D, A,  6, 23, 0x04881D05, H);
    P(A, B, C, D,  9,  4, 0xD9D4D039, H); P(D, A, B, C, 12, 11, 0xE6DB99E5, H);
    P(C, D, A, B, 15, 16, 0x1FA27CF8, H); P(B, C, D, A,  2, 23, 0xC4AC5665, H);

    /* Round 4 */
    P(A, B, C, D,  0,  6, 0xF4292244, I); P(D, A, B, C,  7, 10, 0x432AFF97, I);
    P(C, D, A, B, 14, 15, 0xAB9423A7, I); P(B, C, D, A,  5, 21, 0xFC93A039, I);
    P(A, B, C, D, 12,  6, 0x655B59C3, I); P(D, A, B, C,  3, 10, 0x8F0CCC92, I);
    P(C, D, A, B, 10, 15, 0xFFEFF47D, I); P(B, C, D, A,  1, 21, 0x85845DD1, I);
    P(A, B, C, D,  8,  6, 0x6FA87E4F, I); P(D, A, B, C, 15, 10, 0xFE2CE6E0, I);
    P(C, D, A, B,  6, 15, 0xA3014314, I); P(B, C, D, A, 13, 21, 0x4E0811A1, I);
    P(A, B, C, D,  4,  6, 0xF7537E82, I); P(D, A, B, C, 11, 10, 0xBD3AF235, I);
    P(C, D, A, B,  2, 15, 0x2AD7D2BB, I); P(B, C, D, A,  9, 21, 0xEB86D391, I);

    ctx->state[0] += A; ctx->state[1] += B; ctx->state[2] += C; ctx->state[3] += D;
    mb_zeroize(X, sizeof X);
    return 0;
}

int mbedtls_md5_update(mbedtls_md5_context *ctx,
                       const unsigned char *input, size_t ilen)
{
    int ret = 0;
    size_t fill;
    uint32_t left;

    if (ilen == 0) return 0;

    left = ctx->total[0] & 0x3F;
    fill = MD5_BLOCK_SIZE - left;

    ctx->total[0] += (uint32_t) ilen;
    ctx->total[0] &= 0xFFFFFFFF;
    if (ctx->total[0] < (uint32_t) ilen) ctx->total[1]++;

    if (left && ilen >= fill) {
        memcpy(ctx->buffer + left, input, fill);
        if ((ret = md5_process_block(ctx, ctx->buffer)) != 0) return ret;
        input += fill; ilen -= fill; left = 0;
    }
    while (ilen >= MD5_BLOCK_SIZE) {
        if ((ret = md5_process_block(ctx, input)) != 0) return ret;
        input += MD5_BLOCK_SIZE; ilen -= MD5_BLOCK_SIZE;
    }
    if (ilen > 0) memcpy(ctx->buffer + left, input, ilen);
    return 0;
}

int mbedtls_md5_finish(mbedtls_md5_context *ctx, unsigned char *output)
{
    int ret;
    uint32_t used = ctx->total[0] & 0x3F;
    uint32_t high, low;

    ctx->buffer[used++] = 0x80;

    if (used <= 56) {
        memset(ctx->buffer + used, 0, 56 - used);
    } else {
        memset(ctx->buffer + used, 0, MD5_BLOCK_SIZE - used);
        if ((ret = md5_process_block(ctx, ctx->buffer)) != 0) return ret;
        memset(ctx->buffer, 0, 56);
    }

    /* MD5 length: 64-bit little-endian. */
    high = (ctx->total[0] >> 29) | (ctx->total[1] << 3);
    low  = (ctx->total[0] << 3);
    MBEDTLS_PUT_UINT32_LE(low,  ctx->buffer, 56);
    MBEDTLS_PUT_UINT32_LE(high, ctx->buffer, 60);

    if ((ret = md5_process_block(ctx, ctx->buffer)) != 0) return ret;

    MBEDTLS_PUT_UINT32_LE(ctx->state[0], output,  0);
    MBEDTLS_PUT_UINT32_LE(ctx->state[1], output,  4);
    MBEDTLS_PUT_UINT32_LE(ctx->state[2], output,  8);
    MBEDTLS_PUT_UINT32_LE(ctx->state[3], output, 12);
    return 0;
}

int mbedtls_md5(const unsigned char *input, size_t ilen, unsigned char *output)
{
    mbedtls_md5_context ctx;
    int ret;
    mbedtls_md5_init(&ctx);
    if ((ret = mbedtls_md5_starts(&ctx)) != 0) goto out;
    if ((ret = mbedtls_md5_update(&ctx, input, ilen)) != 0) goto out;
    ret = mbedtls_md5_finish(&ctx, output);
out:
    mbedtls_md5_free(&ctx);
    return ret;
}
