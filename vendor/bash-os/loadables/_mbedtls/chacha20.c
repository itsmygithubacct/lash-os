/* _mbedtls/chacha20.c — ChaCha20 stream cipher (RFC 8439 §2.4). */
#include "chacha20.h"
#include <string.h>

static void mb_zeroize(void *buf, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *) buf;
    while (len--) *p++ = 0;
}

#define U32V(v) ((uint32_t)(v) & 0xFFFFFFFFu)
#define ROL32(x, n) (((x) << (n)) | (((x) & 0xFFFFFFFFu) >> (32 - (n))))

#define QR(a, b, c, d) do {                                          \
    a = U32V(a + b); d = ROL32(d ^ a, 16);                           \
    c = U32V(c + d); b = ROL32(b ^ c, 12);                           \
    a = U32V(a + b); d = ROL32(d ^ a,  8);                           \
    c = U32V(c + d); b = ROL32(b ^ c,  7);                           \
} while (0)

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

void mbedtls_chacha20_block(uint32_t state[16], unsigned char out[64])
{
    uint32_t x[16];
    int i;
    for (i = 0; i < 16; i++) x[i] = state[i];
    /* 10 double-rounds = 20 rounds. */
    for (i = 0; i < 10; i++) {
        QR(x[ 0], x[ 4], x[ 8], x[12]);
        QR(x[ 1], x[ 5], x[ 9], x[13]);
        QR(x[ 2], x[ 6], x[10], x[14]);
        QR(x[ 3], x[ 7], x[11], x[15]);
        QR(x[ 0], x[ 5], x[10], x[15]);
        QR(x[ 1], x[ 6], x[11], x[12]);
        QR(x[ 2], x[ 7], x[ 8], x[13]);
        QR(x[ 3], x[ 4], x[ 9], x[14]);
    }
    for (i = 0; i < 16; i++) {
        uint32_t v = U32V(x[i] + state[i]);
        PUT_LE32(v, out + 4 * i);
    }
}

void mbedtls_chacha20_init(mbedtls_chacha20_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

void mbedtls_chacha20_free(mbedtls_chacha20_context *ctx)
{
    if (!ctx) return;
    mb_zeroize(ctx, sizeof(*ctx));
}

int mbedtls_chacha20_setkey(mbedtls_chacha20_context *ctx,
                            const unsigned char key[32])
{
    /* Constants "expand 32-byte k" in little-endian. */
    ctx->state[0] = 0x61707865;
    ctx->state[1] = 0x3320646e;
    ctx->state[2] = 0x79622d32;
    ctx->state[3] = 0x6b206574;
    /* Key (8 × u32, LE). */
    for (int i = 0; i < 8; i++) ctx->state[4 + i] = LE32(key + 4 * i);
    return 0;
}

int mbedtls_chacha20_starts(mbedtls_chacha20_context *ctx,
                            const unsigned char nonce[12], uint32_t counter)
{
    ctx->state[12] = counter;
    ctx->state[13] = LE32(nonce + 0);
    ctx->state[14] = LE32(nonce + 4);
    ctx->state[15] = LE32(nonce + 8);
    ctx->keystream_used = 64;  /* triggers fresh block on next update */
    return 0;
}

int mbedtls_chacha20_update(mbedtls_chacha20_context *ctx, size_t size,
                            const unsigned char *input, unsigned char *output)
{
    while (size) {
        if (ctx->keystream_used >= 64) {
            mbedtls_chacha20_block(ctx->state, ctx->keystream);
            ctx->state[12] = U32V(ctx->state[12] + 1);
            ctx->keystream_used = 0;
        }
        size_t avail = 64 - ctx->keystream_used;
        size_t take  = size < avail ? size : avail;
        for (size_t i = 0; i < take; i++) {
            output[i] = input[i] ^ ctx->keystream[ctx->keystream_used + i];
        }
        ctx->keystream_used += take;
        input += take; output += take; size -= take;
    }
    return 0;
}

int mbedtls_chacha20_crypt(const unsigned char key[32],
                           const unsigned char nonce[12],
                           uint32_t counter, size_t size,
                           const unsigned char *input, unsigned char *output)
{
    mbedtls_chacha20_context ctx;
    int ret;
    mbedtls_chacha20_init(&ctx);
    if ((ret = mbedtls_chacha20_setkey(&ctx, key)) != 0) goto out;
    if ((ret = mbedtls_chacha20_starts(&ctx, nonce, counter)) != 0) goto out;
    ret = mbedtls_chacha20_update(&ctx, size, input, output);
out:
    mbedtls_chacha20_free(&ctx);
    return ret;
}
