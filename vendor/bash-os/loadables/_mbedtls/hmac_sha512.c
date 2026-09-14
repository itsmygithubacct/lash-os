/* _mbedtls/hmac_sha512.c — HMAC-SHA512 (Stage 19.B).
 * FIPS 198-1 wrapper around the staged SHA-512 primitive.
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include "hmac_sha512.h"
#include <string.h>

#define BLOCK MBEDTLS_HMAC_SHA512_BLOCK_SIZE   /* 128 */
#define MD    MBEDTLS_HMAC_SHA512_DIGEST_SIZE  /* 64  */

void mbedtls_hmac_sha512_init(mbedtls_hmac_sha512_context *ctx)
{
    mbedtls_sha512_init(&ctx->inner);
    memset(ctx->k_opad, 0, sizeof ctx->k_opad);
}

void mbedtls_hmac_sha512_free(mbedtls_hmac_sha512_context *ctx)
{
    if (!ctx) return;
    mbedtls_sha512_free(&ctx->inner);
    volatile unsigned char *p = ctx->k_opad;
    for (int i = 0; i < BLOCK; i++) p[i] = 0;
}

int mbedtls_hmac_sha512_starts(mbedtls_hmac_sha512_context *ctx,
                               const unsigned char *key, size_t keylen)
{
    unsigned char k[BLOCK];
    int ret;

    if (keylen > BLOCK) {
        if ((ret = mbedtls_sha512(key, keylen, k, 0)) != 0) return ret;
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

    if ((ret = mbedtls_sha512_starts(&ctx->inner, 0)) != 0) goto out;
    if ((ret = mbedtls_sha512_update(&ctx->inner, k_ipad, BLOCK)) != 0) goto out;

out:
    {
        volatile unsigned char *vp = k;       for (int i = 0; i < BLOCK; i++) vp[i] = 0;
        volatile unsigned char *vi = k_ipad;  for (int i = 0; i < BLOCK; i++) vi[i] = 0;
    }
    return ret;
}

int mbedtls_hmac_sha512_update(mbedtls_hmac_sha512_context *ctx,
                               const unsigned char *input, size_t ilen)
{
    return mbedtls_sha512_update(&ctx->inner, input, ilen);
}

int mbedtls_hmac_sha512_finish(mbedtls_hmac_sha512_context *ctx,
                               unsigned char *output)
{
    unsigned char inner_digest[MD];
    int ret;

    if ((ret = mbedtls_sha512_finish(&ctx->inner, inner_digest)) != 0) return ret;

    if ((ret = mbedtls_sha512_starts(&ctx->inner, 0)) != 0) goto out;
    if ((ret = mbedtls_sha512_update(&ctx->inner, ctx->k_opad, BLOCK)) != 0) goto out;
    if ((ret = mbedtls_sha512_update(&ctx->inner, inner_digest, MD)) != 0) goto out;
    ret = mbedtls_sha512_finish(&ctx->inner, output);

out:
    {
        volatile unsigned char *vp = inner_digest;
        for (int i = 0; i < MD; i++) vp[i] = 0;
    }
    return ret;
}

int mbedtls_hmac_sha512(const unsigned char *key, size_t keylen,
                        const unsigned char *input, size_t ilen,
                        unsigned char *output)
{
    mbedtls_hmac_sha512_context ctx;
    int ret;
    mbedtls_hmac_sha512_init(&ctx);
    if ((ret = mbedtls_hmac_sha512_starts(&ctx, key, keylen)) != 0) goto out;
    if ((ret = mbedtls_hmac_sha512_update(&ctx, input, ilen)) != 0) goto out;
    ret = mbedtls_hmac_sha512_finish(&ctx, output);
out:
    mbedtls_hmac_sha512_free(&ctx);
    return ret;
}


int mbedtls_hmac_sha384(const unsigned char *key, size_t keylen,
                        const unsigned char *input, size_t ilen,
                        unsigned char *output)
{
    unsigned char k[BLOCK];
    unsigned char k_ipad[BLOCK];
    unsigned char inner_digest[48];
    mbedtls_sha512_context ctx;
    int ret;

    if (keylen > BLOCK) {
        if ((ret = mbedtls_sha512(key, keylen, k, 1)) != 0) return ret;
        memset(k + 48, 0, BLOCK - 48);
    } else {
        memcpy(k, key, keylen);
        memset(k + keylen, 0, BLOCK - keylen);
    }

    mbedtls_sha512_init(&ctx);
    for (int i = 0; i < BLOCK; i++) {
        k_ipad[i] = k[i] ^ 0x36;
        k[i] ^= 0x5c;
    }

    if ((ret = mbedtls_sha512_starts(&ctx, 1)) != 0) goto out;
    if ((ret = mbedtls_sha512_update(&ctx, k_ipad, BLOCK)) != 0) goto out;
    if ((ret = mbedtls_sha512_update(&ctx, input, ilen)) != 0) goto out;
    if ((ret = mbedtls_sha512_finish(&ctx, inner_digest)) != 0) goto out;
    if ((ret = mbedtls_sha512_starts(&ctx, 1)) != 0) goto out;
    if ((ret = mbedtls_sha512_update(&ctx, k, BLOCK)) != 0) goto out;
    if ((ret = mbedtls_sha512_update(&ctx, inner_digest, sizeof inner_digest)) != 0) goto out;
    ret = mbedtls_sha512_finish(&ctx, output);

out:
    mbedtls_sha512_free(&ctx);
    {
        volatile unsigned char *vp = k;
        for (int i = 0; i < BLOCK; i++) vp[i] = 0;
        vp = k_ipad;
        for (int i = 0; i < BLOCK; i++) vp[i] = 0;
        vp = inner_digest;
        for (int i = 0; i < 48; i++) vp[i] = 0;
    }
    return ret;
}
