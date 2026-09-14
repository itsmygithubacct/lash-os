/* _mbedtls/hmac_sha1.h — HMAC-SHA1 (Stage 19.B). */
#ifndef MBEDTLS_HMAC_SHA1_H
#define MBEDTLS_HMAC_SHA1_H

#include <stddef.h>
#include "sha1.h"

#define MBEDTLS_HMAC_SHA1_BLOCK_SIZE  64
#define MBEDTLS_HMAC_SHA1_DIGEST_SIZE 20

typedef struct {
    mbedtls_sha1_context inner;
    unsigned char        k_opad[MBEDTLS_HMAC_SHA1_BLOCK_SIZE];
} mbedtls_hmac_sha1_context;

void mbedtls_hmac_sha1_init  (mbedtls_hmac_sha1_context *ctx);
void mbedtls_hmac_sha1_free  (mbedtls_hmac_sha1_context *ctx);

int  mbedtls_hmac_sha1_starts (mbedtls_hmac_sha1_context *ctx,
                               const unsigned char *key, size_t keylen);
int  mbedtls_hmac_sha1_update (mbedtls_hmac_sha1_context *ctx,
                               const unsigned char *input, size_t ilen);
int  mbedtls_hmac_sha1_finish (mbedtls_hmac_sha1_context *ctx,
                               unsigned char *output);

int  mbedtls_hmac_sha1        (const unsigned char *key, size_t keylen,
                               const unsigned char *input, size_t ilen,
                               unsigned char *output);

#endif /* MBEDTLS_HMAC_SHA1_H */
