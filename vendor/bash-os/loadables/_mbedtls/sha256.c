/* _mbedtls/sha256.c — SHA-256 implementation (Stage 19 hash demo).
 *
 * FIPS 180-4 algorithm based on upstream
 * vendor/mbedtls/tf-psa-crypto/drivers/builtin/src/sha256.c. The C-only
 * path (mbedtls_internal_sha256_process_c + the wrappers around it).
 * Stripped: ARMv8-A SIMD path, A64 crypto path,
 * MBEDTLS_SHA256_SMALLER variant, PSA error mappings, mbedtls_platform_
 * zeroize indirection (replaced with explicit-volatile memset).
 *
 * The compression schedule uses a sixteen-word ring and explicit rounds.
 * The wrapper code (init/free/
 * starts/update/finish/sha256) is also upstream with PSA error returns
 * collapsed to MBEDTLS_ERR_SHA256_BAD_INPUT_DATA / 0.
 *
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 * Copyright The Mbed TLS Contributors
 */
#include "sha256.h"
#include <string.h>
#include <stdint.h>

#define SHA256_BLOCK_SIZE 64

/* Keep the default CPU requirement unchanged. On x86 compilers with CPU
   feature detection, a separate copy of the same C body may use BMI2's
   non-destructive rotates; dispatch only after checking the running CPU.
   Other targets and older compilers retain the portable compression path. */
#if (defined (__x86_64__) || defined (__i386__)) && \
    ((defined (__GNUC__) && !defined (__clang__) && __GNUC__ >= 5) || \
     (defined (__clang__) && __clang_major__ >= 5))
#define SHA256_HAVE_BMI2 1
#define SHA256_INLINE static inline __attribute__ ((always_inline))
#else
#define SHA256_INLINE static inline
#endif

/* memcpy permits unaligned words without aliasing assumptions. Describing
   the byte swap on whole words also avoids an expensive byte-lane shuffle
   when a compiler vectorizes the sixteen input loads. */
#if defined (__BYTE_ORDER__) && defined (__GNUC__)
static inline uint32_t sha256_load_be (const unsigned char *p)
{
    uint32_t value;
    memcpy (&value, p, sizeof value);
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap32 (value);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return value;
#else
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) |
           ((uint32_t) p[2] << 8) | (uint32_t) p[3];
#endif
}
#define MBEDTLS_GET_UINT32_BE(data, offset) sha256_load_be ((data) + (offset))
#else
#define MBEDTLS_GET_UINT32_BE(data, offset)                          \
    (((uint32_t) (data)[(offset) + 0] << 24) |                       \
     ((uint32_t) (data)[(offset) + 1] << 16) |                       \
     ((uint32_t) (data)[(offset) + 2] <<  8) |                       \
     ((uint32_t) (data)[(offset) + 3]))
#endif

#define MBEDTLS_PUT_UINT32_BE(n, data, offset) do {                  \
    (data)[(offset) + 0] = (unsigned char) ((n) >> 24);              \
    (data)[(offset) + 1] = (unsigned char) ((n) >> 16);              \
    (data)[(offset) + 2] = (unsigned char) ((n) >>  8);              \
    (data)[(offset) + 3] = (unsigned char) ((n));                    \
} while (0)

/* Explicit-volatile memset to defeat dead-store elimination on
   sensitive state. Replaces upstream mbedtls_platform_zeroize. */
static void mb_zeroize(void *buf, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *) buf;
    while (len--) *p++ = 0;
}

void mbedtls_sha256_init(mbedtls_sha256_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

void mbedtls_sha256_free(mbedtls_sha256_context *ctx)
{
    if (!ctx) return;
    mb_zeroize(ctx, sizeof(*ctx));
}

void mbedtls_sha256_clone(mbedtls_sha256_context *dst,
                          const mbedtls_sha256_context *src)
{
    *dst = *src;
}

int mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224)
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    if (is224) {
        /* SHA-224 initial state — FIPS 180-4 §5.3.2. */
        ctx->state[0] = 0xC1059ED8;
        ctx->state[1] = 0x367CD507;
        ctx->state[2] = 0x3070DD17;
        ctx->state[3] = 0xF70E5939;
        ctx->state[4] = 0xFFC00B31;
        ctx->state[5] = 0x68581511;
        ctx->state[6] = 0x64F98FA7;
        ctx->state[7] = 0xBEFA4FA4;
        ctx->is224 = 1;
    } else {
        /* SHA-256 initial state — FIPS 180-4 §5.3.3. */
        ctx->state[0] = 0x6A09E667;
        ctx->state[1] = 0xBB67AE85;
        ctx->state[2] = 0x3C6EF372;
        ctx->state[3] = 0xA54FF53A;
        ctx->state[4] = 0x510E527F;
        ctx->state[5] = 0x9B05688C;
        ctx->state[6] = 0x1F83D9AB;
        ctx->state[7] = 0x5BE0CD19;
        ctx->is224 = 0;
    }
    return 0;
}

/* Round constants — FIPS 180-4 §4.2.2. */
static const uint32_t K[64] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

#define  SHR(x, n) (((x) & 0xFFFFFFFFu) >> (n))
#define ROTR(x, n) (SHR(x, n) | ((x) << (32 - (n))))
#define S0(x)  (ROTR(x, 7)  ^ ROTR(x, 18) ^  SHR(x,  3))
#define S1(x)  (ROTR(x, 17) ^ ROTR(x, 19) ^  SHR(x, 10))
#define S2(x)  (ROTR(x, 2)  ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S3(x)  (ROTR(x, 6)  ^ ROTR(x, 11) ^ ROTR(x, 25))
#define F0(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))
#define F1(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))

/* The message schedule depends on the preceding sixteen words. A ring
   keeps those words live without retaining the complete 64-word schedule. */
#define W(t) local.W[(t) & 15]
#define R(t) (W(t) = S1(W((t) - 2)) + W((t) - 7) + \
                      S0(W((t) - 15)) + W(t))

#define P(a, b, c, d, e, f, g, h, x, K) do {                          \
    local.temp1 = (h) + S3(e) + F1((e), (f), (g)) + (K) + (x);        \
    local.temp2 = S2(a) + F0((a), (b), (c));                          \
    (d) += local.temp1; (h) = local.temp1 + local.temp2;              \
} while (0)

/* Reuse the round workspace for contiguous input blocks, then erase all
   schedule/state scratch before returning from the compression call. */
SHA256_INLINE int sha256_process_blocks_c(mbedtls_sha256_context *ctx,
                                         const unsigned char *data, size_t blocks)
{
    struct {
        uint32_t temp1, temp2, W[16];
        uint32_t A[8];
    } local;
    unsigned int i;

    while (blocks--) {
        for (i = 0; i < 8; i++) local.A[i] = ctx->state[i];

        for (i = 0; i < 16; i++) local.W[i] = MBEDTLS_GET_UINT32_BE(data, 4 * i);

        /* Constant round indices let the compiler schedule rotations,
           loads and additions without the dynamic schedule-index loop. */
        P(local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], W(0), K[0]);
        P(local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], W(1), K[1]);
        P(local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], W(2), K[2]);
        P(local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], W(3), K[3]);
        P(local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], W(4), K[4]);
        P(local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], W(5), K[5]);
        P(local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], W(6), K[6]);
        P(local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], W(7), K[7]);

        P(local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], W(8), K[8]);
        P(local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], W(9), K[9]);
        P(local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], W(10), K[10]);
        P(local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], W(11), K[11]);
        P(local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], W(12), K[12]);
        P(local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], W(13), K[13]);
        P(local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], W(14), K[14]);
        P(local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], W(15), K[15]);

        P(local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], R(16), K[16]);
        P(local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], R(17), K[17]);
        P(local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], R(18), K[18]);
        P(local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], R(19), K[19]);
        P(local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], R(20), K[20]);
        P(local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], R(21), K[21]);
        P(local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], R(22), K[22]);
        P(local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], R(23), K[23]);

        P(local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], R(24), K[24]);
        P(local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], R(25), K[25]);
        P(local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], R(26), K[26]);
        P(local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], R(27), K[27]);
        P(local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], R(28), K[28]);
        P(local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], R(29), K[29]);
        P(local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], R(30), K[30]);
        P(local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], R(31), K[31]);

        P(local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], R(32), K[32]);
        P(local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], R(33), K[33]);
        P(local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], R(34), K[34]);
        P(local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], R(35), K[35]);
        P(local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], R(36), K[36]);
        P(local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], R(37), K[37]);
        P(local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], R(38), K[38]);
        P(local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], R(39), K[39]);

        P(local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], R(40), K[40]);
        P(local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], R(41), K[41]);
        P(local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], R(42), K[42]);
        P(local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], R(43), K[43]);
        P(local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], R(44), K[44]);
        P(local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], R(45), K[45]);
        P(local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], R(46), K[46]);
        P(local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], R(47), K[47]);

        P(local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], R(48), K[48]);
        P(local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], R(49), K[49]);
        P(local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], R(50), K[50]);
        P(local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], R(51), K[51]);
        P(local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], R(52), K[52]);
        P(local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], R(53), K[53]);
        P(local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], R(54), K[54]);
        P(local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], R(55), K[55]);

        P(local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], R(56), K[56]);
        P(local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], R(57), K[57]);
        P(local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], R(58), K[58]);
        P(local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], local.A[4], R(59), K[59]);
        P(local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], local.A[3], R(60), K[60]);
        P(local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], local.A[2], R(61), K[61]);
        P(local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], local.A[1], R(62), K[62]);
        P(local.A[1], local.A[2], local.A[3], local.A[4], local.A[5], local.A[6], local.A[7], local.A[0], R(63), K[63]);
        for (i = 0; i < 8; i++) ctx->state[i] += local.A[i];
        data += SHA256_BLOCK_SIZE;
    }
    mb_zeroize(&local, sizeof(local));
    return 0;
}

#if defined (SHA256_HAVE_BMI2)
/* The explicit target boundary prevents BMI2 instructions from entering
   the generic path, while always-inlining gives both copies the identical
   schedule, arithmetic, and volatile workspace erasure. */
__attribute__ ((target ("bmi2"), noinline))
static int sha256_process_blocks_bmi2(mbedtls_sha256_context *ctx,
                                     const unsigned char *data, size_t blocks)
{
    return sha256_process_blocks_c(ctx, data, blocks);
}
#endif

static int sha256_process_blocks(mbedtls_sha256_context *ctx,
                                 const unsigned char *data, size_t blocks)
{
#if defined (SHA256_HAVE_BMI2)
    /* The compiler's CPU-feature data is initialized once at startup. */
    if (__builtin_cpu_supports("bmi2"))
        return sha256_process_blocks_bmi2(ctx, data, blocks);
#endif
    return sha256_process_blocks_c(ctx, data, blocks);
}

static int sha256_process_block(mbedtls_sha256_context *ctx,
                                const unsigned char data[SHA256_BLOCK_SIZE])
{
    return sha256_process_blocks(ctx, data, 1);
}

int mbedtls_sha256_update(mbedtls_sha256_context *ctx,
                          const unsigned char *input, size_t ilen)
{
    int ret = 0;
    size_t fill;
    uint32_t left;

    if (ilen == 0) return 0;

    left = ctx->total[0] & 0x3F;
    fill = SHA256_BLOCK_SIZE - left;

    ctx->total[0] += (uint32_t) ilen;
    ctx->total[0] &= 0xFFFFFFFF;
    if (ctx->total[0] < (uint32_t) ilen) ctx->total[1]++;

    if (left && ilen >= fill) {
        memcpy(ctx->buffer + left, input, fill);
        if ((ret = sha256_process_block(ctx, ctx->buffer)) != 0) return ret;
        input += fill; ilen -= fill; left = 0;
    }
    if (ilen >= SHA256_BLOCK_SIZE) {
        size_t blocks = ilen / SHA256_BLOCK_SIZE;
        if ((ret = sha256_process_blocks(ctx, input, blocks)) != 0) return ret;
        input += blocks * SHA256_BLOCK_SIZE;
        ilen -= blocks * SHA256_BLOCK_SIZE;
    }
    if (ilen > 0) memcpy(ctx->buffer + left, input, ilen);
    return 0;
}

int mbedtls_sha256_finish(mbedtls_sha256_context *ctx, unsigned char *output)
{
    int ret;
    uint32_t used = ctx->total[0] & 0x3F;
    uint32_t high, low;

    ctx->buffer[used++] = 0x80;

    if (used <= 56) {
        memset(ctx->buffer + used, 0, 56 - used);
    } else {
        memset(ctx->buffer + used, 0, SHA256_BLOCK_SIZE - used);
        if ((ret = sha256_process_block(ctx, ctx->buffer)) != 0) return ret;
        memset(ctx->buffer, 0, 56);
    }

    high = (ctx->total[0] >> 29) | (ctx->total[1] << 3);
    low  = (ctx->total[0] << 3);
    MBEDTLS_PUT_UINT32_BE(high, ctx->buffer, 56);
    MBEDTLS_PUT_UINT32_BE(low,  ctx->buffer, 60);

    if ((ret = sha256_process_block(ctx, ctx->buffer)) != 0) return ret;

    MBEDTLS_PUT_UINT32_BE(ctx->state[0], output,  0);
    MBEDTLS_PUT_UINT32_BE(ctx->state[1], output,  4);
    MBEDTLS_PUT_UINT32_BE(ctx->state[2], output,  8);
    MBEDTLS_PUT_UINT32_BE(ctx->state[3], output, 12);
    MBEDTLS_PUT_UINT32_BE(ctx->state[4], output, 16);
    MBEDTLS_PUT_UINT32_BE(ctx->state[5], output, 20);
    MBEDTLS_PUT_UINT32_BE(ctx->state[6], output, 24);
    if (ctx->is224) return 0;
    MBEDTLS_PUT_UINT32_BE(ctx->state[7], output, 28);
    return 0;
}

int mbedtls_sha256(const unsigned char *input, size_t ilen,
                   unsigned char *output, int is224)
{
    mbedtls_sha256_context ctx;
    int ret;
    mbedtls_sha256_init(&ctx);
    if ((ret = mbedtls_sha256_starts(&ctx, is224)) != 0) goto out;
    if ((ret = mbedtls_sha256_update(&ctx, input, ilen)) != 0) goto out;
    ret = mbedtls_sha256_finish(&ctx, output);
out:
    mbedtls_sha256_free(&ctx);
    return ret;
}
