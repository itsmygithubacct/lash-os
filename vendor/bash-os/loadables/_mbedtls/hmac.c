/* _mbedtls/hmac.c — HMAC-SHA256 (Stage 19.B primitive #2).
 *
 * FIPS 198-1 HMAC construction. Self-contained: only depends on the
 * mbedtls SHA-256 primitives staged at _mbedtls/sha256.{h,c} —
 * deliberately bypasses upstream's mbedtls_md_* dispatch layer so we
 * don't drag in the md function-table machinery.
 *
 * Algorithm (FIPS 198-1):
 *   1. K' = SHA256(K) if |K| > B, else K right-padded with 0 to B bytes
 *   2. K_ipad = K' XOR 0x36...
 *   3. K_opad = K' XOR 0x5C...
 *   4. HMAC = SHA256(K_opad || SHA256(K_ipad || message))
 *
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include "hmac.h"
#include <string.h>

#define BLOCK MBEDTLS_HMAC_SHA256_BLOCK_SIZE   /* 64 */
#define MD    MBEDTLS_HMAC_SHA256_DIGEST_SIZE  /* 32 */

void mbedtls_hmac_sha256_init(mbedtls_hmac_sha256_context *ctx)
{
    mbedtls_sha256_init(&ctx->inner);
    memset(ctx->k_opad, 0, sizeof ctx->k_opad);
}

void mbedtls_hmac_sha256_free(mbedtls_hmac_sha256_context *ctx)
{
    if (!ctx) return;
    mbedtls_sha256_free(&ctx->inner);
    /* Defeat dead-store elimination on k_opad — it's effectively the
       authentication key once xored into the outer pad. */
    volatile unsigned char *p = ctx->k_opad;
    for (int i = 0; i < BLOCK; i++) p[i] = 0;
}

int mbedtls_hmac_sha256_starts(mbedtls_hmac_sha256_context *ctx,
                               const unsigned char *key, size_t keylen)
{
    unsigned char k[BLOCK];
    int ret;

    /* K' = key right-padded (or hash-shrunk if longer than block). */
    if (keylen > BLOCK) {
        if ((ret = mbedtls_sha256(key, keylen, k, 0)) != 0) return ret;
        memset(k + MD, 0, BLOCK - MD);
    } else {
        memcpy(k, key, keylen);
        memset(k + keylen, 0, BLOCK - keylen);
    }

    /* Compute k_ipad on stack; persist k_opad in the context for finish. */
    unsigned char k_ipad[BLOCK];
    for (int i = 0; i < BLOCK; i++) {
        k_ipad[i]      = k[i] ^ 0x36;
        ctx->k_opad[i] = k[i] ^ 0x5C;
    }

    /* Start inner = SHA256(k_ipad || ...). */
    if ((ret = mbedtls_sha256_starts(&ctx->inner, 0)) != 0) goto out;
    if ((ret = mbedtls_sha256_update(&ctx->inner, k_ipad, BLOCK)) != 0) goto out;

out:
    /* Wipe stack copies. k_opad stays in ctx until finish. */
    {
        volatile unsigned char *vp = k;       for (int i = 0; i < BLOCK; i++) vp[i] = 0;
        volatile unsigned char *vi = k_ipad;  for (int i = 0; i < BLOCK; i++) vi[i] = 0;
    }
    return ret;
}

int mbedtls_hmac_sha256_update(mbedtls_hmac_sha256_context *ctx,
                               const unsigned char *input, size_t ilen)
{
    return mbedtls_sha256_update(&ctx->inner, input, ilen);
}

int mbedtls_hmac_sha256_finish(mbedtls_hmac_sha256_context *ctx,
                               unsigned char *output)
{
    unsigned char inner_digest[MD];
    int ret;

    /* Finalize inner hash → SHA256(k_ipad || msg). */
    if ((ret = mbedtls_sha256_finish(&ctx->inner, inner_digest)) != 0) return ret;

    /* Outer hash: SHA256(k_opad || inner_digest). Reuse the same
       context (free + re-init isn't needed; sha256_starts resets). */
    if ((ret = mbedtls_sha256_starts(&ctx->inner, 0)) != 0) goto out;
    if ((ret = mbedtls_sha256_update(&ctx->inner, ctx->k_opad, BLOCK)) != 0) goto out;
    if ((ret = mbedtls_sha256_update(&ctx->inner, inner_digest, MD)) != 0) goto out;
    ret = mbedtls_sha256_finish(&ctx->inner, output);

out:
    {
        volatile unsigned char *vp = inner_digest;
        for (int i = 0; i < MD; i++) vp[i] = 0;
    }
    return ret;
}

int mbedtls_hmac_sha256(const unsigned char *key, size_t keylen,
                        const unsigned char *input, size_t ilen,
                        unsigned char *output)
{
    mbedtls_hmac_sha256_context ctx;
    int ret;
    mbedtls_hmac_sha256_init(&ctx);
    if ((ret = mbedtls_hmac_sha256_starts(&ctx, key, keylen)) != 0) goto out;
    if ((ret = mbedtls_hmac_sha256_update(&ctx, input, ilen)) != 0) goto out;
    ret = mbedtls_hmac_sha256_finish(&ctx, output);
out:
    mbedtls_hmac_sha256_free(&ctx);
    return ret;
}
