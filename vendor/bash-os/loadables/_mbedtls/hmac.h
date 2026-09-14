/* _mbedtls/hmac.h — HMAC-SHA256 (Stage 19.B primitive #2).
 *
 * Self-contained FIPS 198-1 HMAC wrapper around the mbedtls SHA-256
 * primitives in _mbedtls/sha256.{c,h}. Same API shape as mbedtls's
 * md.h family but specialized to SHA-256 (no algorithm dispatch);
 * Stage 19.D will generalize to the full md family if/when other
 * hashes are migrated.
 *
 * Naming `hmac_sha256_*` rather than `mbedtls_md_hmac_*` keeps the
 * implementation small (no md function-table indirection); upstream's
 * md.c is generic across SHA-1/SHA-224/SHA-256/SHA-384/SHA-512/MD5
 * and pulls 200+ LoC of dispatch glue we don't need yet.
 */
#ifndef MBEDTLS_HMAC_H
#define MBEDTLS_HMAC_H

#include <stddef.h>
#include "sha256.h"

#define MBEDTLS_HMAC_SHA256_BLOCK_SIZE  64   /* SHA-256 block bytes */
#define MBEDTLS_HMAC_SHA256_DIGEST_SIZE 32   /* SHA-256 output bytes */

typedef struct {
    mbedtls_sha256_context inner;
    unsigned char          k_opad[MBEDTLS_HMAC_SHA256_BLOCK_SIZE];
} mbedtls_hmac_sha256_context;

void mbedtls_hmac_sha256_init  (mbedtls_hmac_sha256_context *ctx);
void mbedtls_hmac_sha256_free  (mbedtls_hmac_sha256_context *ctx);

int  mbedtls_hmac_sha256_starts (mbedtls_hmac_sha256_context *ctx,
                                 const unsigned char *key, size_t keylen);
int  mbedtls_hmac_sha256_update (mbedtls_hmac_sha256_context *ctx,
                                 const unsigned char *input, size_t ilen);
int  mbedtls_hmac_sha256_finish (mbedtls_hmac_sha256_context *ctx,
                                 unsigned char *output);

/* One-shot: HMAC-SHA256(key, input) → 32 bytes. */
int  mbedtls_hmac_sha256        (const unsigned char *key, size_t keylen,
                                 const unsigned char *input, size_t ilen,
                                 unsigned char *output);

#endif /* MBEDTLS_HMAC_H */
