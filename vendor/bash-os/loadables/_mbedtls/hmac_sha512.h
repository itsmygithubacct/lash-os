/* _mbedtls/hmac_sha512.h — HMAC-SHA512 (Stage 19.B continuation).
 *
 * Parallel of _mbedtls/hmac.h (HMAC-SHA256). FIPS 198-1 around the staged
 * SHA-512 primitive. Block size 128, digest size 64.
 */
#ifndef MBEDTLS_HMAC_SHA512_H
#define MBEDTLS_HMAC_SHA512_H

#include <stddef.h>
#include "sha512.h"

#define MBEDTLS_HMAC_SHA512_BLOCK_SIZE  128
#define MBEDTLS_HMAC_SHA512_DIGEST_SIZE 64

typedef struct {
    mbedtls_sha512_context inner;
    unsigned char          k_opad[MBEDTLS_HMAC_SHA512_BLOCK_SIZE];
} mbedtls_hmac_sha512_context;

void mbedtls_hmac_sha512_init  (mbedtls_hmac_sha512_context *ctx);
void mbedtls_hmac_sha512_free  (mbedtls_hmac_sha512_context *ctx);

int  mbedtls_hmac_sha512_starts (mbedtls_hmac_sha512_context *ctx,
                                 const unsigned char *key, size_t keylen);
int  mbedtls_hmac_sha512_update (mbedtls_hmac_sha512_context *ctx,
                                 const unsigned char *input, size_t ilen);
int  mbedtls_hmac_sha512_finish (mbedtls_hmac_sha512_context *ctx,
                                 unsigned char *output);

int  mbedtls_hmac_sha512        (const unsigned char *key, size_t keylen,
                                 const unsigned char *input, size_t ilen,
                                 unsigned char *output);
int  mbedtls_hmac_sha384        (const unsigned char *key, size_t keylen,
                                 const unsigned char *input, size_t ilen,
                                 unsigned char *output);

#endif /* MBEDTLS_HMAC_SHA512_H */
