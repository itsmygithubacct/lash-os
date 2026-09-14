/* _mbedtls/hmac_sha1.c — HMAC-SHA1 (Stage 19.B). */
#include "hmac_sha1.h"
#include <string.h>

#define BLOCK MBEDTLS_HMAC_SHA1_BLOCK_SIZE
#define MD    MBEDTLS_HMAC_SHA1_DIGEST_SIZE

void mbedtls_hmac_sha1_init(mbedtls_hmac_sha1_context *ctx)
{
    mbedtls_sha1_init(&ctx->inner);
    memset(ctx->k_opad, 0, sizeof ctx->k_opad);
}

void mbedtls_hmac_sha1_free(mbedtls_hmac_sha1_context *ctx)
{
    if (!ctx) return;
    mbedtls_sha1_free(&ctx->inner);
    volatile unsigned char *p = ctx->k_opad;
    for (int i = 0; i < BLOCK; i++) p[i] = 0;
}

int mbedtls_hmac_sha1_starts(mbedtls_hmac_sha1_context *ctx,
                             const unsigned char *key, size_t keylen)
{
    unsigned char k[BLOCK];
    int ret;

    if (keylen > BLOCK) {
        if ((ret = mbedtls_sha1(key, keylen, k)) != 0) return ret;
        memset(k + MD, 0, BLOCK - MD);
    } else {
        memcpy(k, key, keylen);
        memset(k + keylen, 0, BLOCK - keylen);
    }

    unsigned char k_ipad[BLOCK];
    for (int i = 0; i < BLOCK; i++) {
        k_ipad[i]      = k[i] ^ 0x36;
        ctx->k_opad[i] = k[i] ^ 0x5C;
    }
    if ((ret = mbedtls_sha1_starts(&ctx->inner)) != 0) goto out;
    if ((ret = mbedtls_sha1_update(&ctx->inner, k_ipad, BLOCK)) != 0) goto out;
out:
    {
        volatile unsigned char *vp = k;       for (int i = 0; i < BLOCK; i++) vp[i] = 0;
        volatile unsigned char *vi = k_ipad;  for (int i = 0; i < BLOCK; i++) vi[i] = 0;
    }
    return ret;
}

int mbedtls_hmac_sha1_update(mbedtls_hmac_sha1_context *ctx,
                             const unsigned char *input, size_t ilen)
{
    return mbedtls_sha1_update(&ctx->inner, input, ilen);
}

int mbedtls_hmac_sha1_finish(mbedtls_hmac_sha1_context *ctx,
                             unsigned char *output)
{
    unsigned char inner_digest[MD];
    int ret;
    if ((ret = mbedtls_sha1_finish(&ctx->inner, inner_digest)) != 0) return ret;
    if ((ret = mbedtls_sha1_starts(&ctx->inner)) != 0) goto out;
    if ((ret = mbedtls_sha1_update(&ctx->inner, ctx->k_opad, BLOCK)) != 0) goto out;
    if ((ret = mbedtls_sha1_update(&ctx->inner, inner_digest, MD)) != 0) goto out;
    ret = mbedtls_sha1_finish(&ctx->inner, output);
out:
    {
        volatile unsigned char *vp = inner_digest;
        for (int i = 0; i < MD; i++) vp[i] = 0;
    }
    return ret;
}

int mbedtls_hmac_sha1(const unsigned char *key, size_t keylen,
                      const unsigned char *input, size_t ilen,
                      unsigned char *output)
{
    mbedtls_hmac_sha1_context ctx;
    int ret;
    mbedtls_hmac_sha1_init(&ctx);
    if ((ret = mbedtls_hmac_sha1_starts(&ctx, key, keylen)) != 0) goto out;
    if ((ret = mbedtls_hmac_sha1_update(&ctx, input, ilen)) != 0) goto out;
    ret = mbedtls_hmac_sha1_finish(&ctx, output);
out:
    mbedtls_hmac_sha1_free(&ctx);
    return ret;
}
