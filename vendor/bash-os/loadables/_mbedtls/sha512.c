/* _mbedtls/sha512.c — SHA-384/512 implementation (Stage 19.B).
 *
 * FIPS 180-4 §6.4. Algorithm faithful to upstream
 * vendor/mbedtls/tf-psa-crypto/drivers/builtin/src/sha512.c — C-only path
 * (no A64-crypto or x86-VEX accelerated paths). Stripped: PSA error
 * mappings, mbedtls_platform_zeroize indirection, MBEDTLS_SHA512_SMALLER
 * variant, run-time A64 SHA-512 detection.
 *
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 * Copyright The Mbed TLS Contributors
 */
#include "sha512.h"
#include <string.h>
#include <stdint.h>

#define SHA512_BLOCK_SIZE 128

#define MBEDTLS_GET_UINT64_BE(data, offset)                              \
    (((uint64_t) (data)[(offset) + 0] << 56) |                           \
     ((uint64_t) (data)[(offset) + 1] << 48) |                           \
     ((uint64_t) (data)[(offset) + 2] << 40) |                           \
     ((uint64_t) (data)[(offset) + 3] << 32) |                           \
     ((uint64_t) (data)[(offset) + 4] << 24) |                           \
     ((uint64_t) (data)[(offset) + 5] << 16) |                           \
     ((uint64_t) (data)[(offset) + 6] <<  8) |                           \
     ((uint64_t) (data)[(offset) + 7]))

#define MBEDTLS_PUT_UINT64_BE(n, data, offset) do {                      \
    (data)[(offset) + 0] = (unsigned char) ((n) >> 56);                  \
    (data)[(offset) + 1] = (unsigned char) ((n) >> 48);                  \
    (data)[(offset) + 2] = (unsigned char) ((n) >> 40);                  \
    (data)[(offset) + 3] = (unsigned char) ((n) >> 32);                  \
    (data)[(offset) + 4] = (unsigned char) ((n) >> 24);                  \
    (data)[(offset) + 5] = (unsigned char) ((n) >> 16);                  \
    (data)[(offset) + 6] = (unsigned char) ((n) >>  8);                  \
    (data)[(offset) + 7] = (unsigned char) ((n));                        \
} while (0)

static void mb_zeroize(void *buf, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *) buf;
    while (len--) *p++ = 0;
}

void mbedtls_sha512_init(mbedtls_sha512_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

void mbedtls_sha512_free(mbedtls_sha512_context *ctx)
{
    if (!ctx) return;
    mb_zeroize(ctx, sizeof(*ctx));
}

void mbedtls_sha512_clone(mbedtls_sha512_context *dst,
                          const mbedtls_sha512_context *src)
{
    *dst = *src;
}

int mbedtls_sha512_starts(mbedtls_sha512_context *ctx, int is384)
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    if (is384 == 0) {
        /* SHA-512 IV — FIPS 180-4 §5.3.5. */
        ctx->state[0] = 0x6A09E667F3BCC908ULL;
        ctx->state[1] = 0xBB67AE8584CAA73BULL;
        ctx->state[2] = 0x3C6EF372FE94F82BULL;
        ctx->state[3] = 0xA54FF53A5F1D36F1ULL;
        ctx->state[4] = 0x510E527FADE682D1ULL;
        ctx->state[5] = 0x9B05688C2B3E6C1FULL;
        ctx->state[6] = 0x1F83D9ABFB41BD6BULL;
        ctx->state[7] = 0x5BE0CD19137E2179ULL;
    } else {
        /* SHA-384 IV — FIPS 180-4 §5.3.4. */
        ctx->state[0] = 0xCBBB9D5DC1059ED8ULL;
        ctx->state[1] = 0x629A292A367CD507ULL;
        ctx->state[2] = 0x9159015A3070DD17ULL;
        ctx->state[3] = 0x152FECD8F70E5939ULL;
        ctx->state[4] = 0x67332667FFC00B31ULL;
        ctx->state[5] = 0x8EB44A8768581511ULL;
        ctx->state[6] = 0xDB0C2E0D64F98FA7ULL;
        ctx->state[7] = 0x47B5481DBEFA4FA4ULL;
    }
    ctx->is384 = is384;
    return 0;
}

/* Round constants — FIPS 180-4 §4.2.3. */
static const uint64_t K[80] = {
    0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL, 0xE9B5DBA58189DBBCULL,
    0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL, 0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL,
    0xD807AA98A3030242ULL, 0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
    0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL, 0xC19BF174CF692694ULL,
    0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL, 0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL,
    0x2DE92C6F592B0275ULL, 0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,
    0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL, 0xBF597FC7BEEF0EE4ULL,
    0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL, 0x06CA6351E003826FULL, 0x142929670A0E6E70ULL,
    0x27B70A8546D22FFCULL, 0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,
    0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL, 0x81C2C92E47EDAEE6ULL, 0x92722C851482353BULL,
    0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL, 0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL,
    0xD192E819D6EF5218ULL, 0xD69906245565A910ULL, 0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,
    0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL, 0x34B0BCB5E19B48A8ULL,
    0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL, 0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL,
    0x748F82EE5DEFB2FCULL, 0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,
    0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL, 0xC67178F2E372532BULL,
    0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL, 0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL,
    0x06F067AA72176FBAULL, 0x0A637DC5A2C898A6ULL, 0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,
    0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL, 0x431D67C49C100D4CULL,
    0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL, 0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL,
};

#define  SHR(x, n) ((x) >> (n))
#define ROTR(x, n) (SHR(x, n) | ((x) << (64 - (n))))

#define S0(x)  (ROTR(x,  1) ^ ROTR(x,  8) ^  SHR(x,  7))
#define S1(x)  (ROTR(x, 19) ^ ROTR(x, 61) ^  SHR(x,  6))
#define S2(x)  (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define S3(x)  (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))

#define F0(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))
#define F1(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))

static int sha512_process_block(mbedtls_sha512_context *ctx,
                                const unsigned char data[SHA512_BLOCK_SIZE])
{
    uint64_t W[80], temp1, temp2;
    uint64_t A, B, C, D, E, F, G, H;
    int i;

    for (i = 0; i < 16; i++) W[i] = MBEDTLS_GET_UINT64_BE(data, 8 * i);
    for (i = 16; i < 80; i++) {
        W[i] = S1(W[i - 2]) + W[i - 7] + S0(W[i - 15]) + W[i - 16];
    }

    A = ctx->state[0]; B = ctx->state[1]; C = ctx->state[2]; D = ctx->state[3];
    E = ctx->state[4]; F = ctx->state[5]; G = ctx->state[6]; H = ctx->state[7];

    for (i = 0; i < 80; i++) {
        temp1 = H + S3(E) + F1(E, F, G) + K[i] + W[i];
        temp2 = S2(A) + F0(A, B, C);
        H = G; G = F; F = E; E = D + temp1;
        D = C; C = B; B = A; A = temp1 + temp2;
    }

    ctx->state[0] += A; ctx->state[1] += B; ctx->state[2] += C; ctx->state[3] += D;
    ctx->state[4] += E; ctx->state[5] += F; ctx->state[6] += G; ctx->state[7] += H;

    mb_zeroize(W, sizeof W);
    return 0;
}

int mbedtls_sha512_update(mbedtls_sha512_context *ctx,
                          const unsigned char *input, size_t ilen)
{
    int ret = 0;
    size_t fill;
    unsigned int left;

    if (ilen == 0) return 0;

    left = (unsigned int) (ctx->total[0] & 0x7F);
    fill = SHA512_BLOCK_SIZE - left;

    ctx->total[0] += (uint64_t) ilen;
    if (ctx->total[0] < (uint64_t) ilen) ctx->total[1]++;

    if (left && ilen >= fill) {
        memcpy(ctx->buffer + left, input, fill);
        if ((ret = sha512_process_block(ctx, ctx->buffer)) != 0) return ret;
        input += fill; ilen -= fill; left = 0;
    }
    while (ilen >= SHA512_BLOCK_SIZE) {
        if ((ret = sha512_process_block(ctx, input)) != 0) return ret;
        input += SHA512_BLOCK_SIZE; ilen -= SHA512_BLOCK_SIZE;
    }
    if (ilen > 0) memcpy(ctx->buffer + left, input, ilen);
    return 0;
}

int mbedtls_sha512_finish(mbedtls_sha512_context *ctx, unsigned char *output)
{
    int ret;
    unsigned int used = (unsigned int) (ctx->total[0] & 0x7F);
    uint64_t high, low;

    /* Bit count BEFORE padding — encoded in the final 16 bytes. */
    high = (ctx->total[0] >> 61) | (ctx->total[1] << 3);
    low  = (ctx->total[0] << 3);

    /* Append 0x80 then zero-pad in-buffer until residue == 112. */
    ctx->buffer[used++] = 0x80;

    if (used <= 112) {
        memset(ctx->buffer + used, 0, 112 - used);
    } else {
        memset(ctx->buffer + used, 0, SHA512_BLOCK_SIZE - used);
        if ((ret = sha512_process_block(ctx, ctx->buffer)) != 0) return ret;
        memset(ctx->buffer, 0, 112);
    }

    MBEDTLS_PUT_UINT64_BE(high, ctx->buffer, 112);
    MBEDTLS_PUT_UINT64_BE(low,  ctx->buffer, 120);

    if ((ret = sha512_process_block(ctx, ctx->buffer)) != 0) return ret;

    MBEDTLS_PUT_UINT64_BE(ctx->state[0], output,  0);
    MBEDTLS_PUT_UINT64_BE(ctx->state[1], output,  8);
    MBEDTLS_PUT_UINT64_BE(ctx->state[2], output, 16);
    MBEDTLS_PUT_UINT64_BE(ctx->state[3], output, 24);
    MBEDTLS_PUT_UINT64_BE(ctx->state[4], output, 32);
    MBEDTLS_PUT_UINT64_BE(ctx->state[5], output, 40);
    if (!ctx->is384) {
        MBEDTLS_PUT_UINT64_BE(ctx->state[6], output, 48);
        MBEDTLS_PUT_UINT64_BE(ctx->state[7], output, 56);
    }
    return 0;
}

int mbedtls_sha512(const unsigned char *input, size_t ilen,
                   unsigned char *output, int is384)
{
    mbedtls_sha512_context ctx;
    int ret;
    mbedtls_sha512_init(&ctx);
    if ((ret = mbedtls_sha512_starts(&ctx, is384)) != 0) goto out;
    if ((ret = mbedtls_sha512_update(&ctx, input, ilen)) != 0) goto out;
    ret = mbedtls_sha512_finish(&ctx, output);
out:
    mbedtls_sha512_free(&ctx);
    return ret;
}
