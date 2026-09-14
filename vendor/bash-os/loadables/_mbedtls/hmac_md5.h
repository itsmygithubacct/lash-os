/* _mbedtls/hmac_md5.h — HMAC-MD5 (Stage 19.B). RFC 2104 / RFC 1321.
 * Legacy: TLS 1.0 PRF, IKE, MIME content-MD5. NOT for new use.
 */
#ifndef MBEDTLS_HMAC_MD5_H
#define MBEDTLS_HMAC_MD5_H

#include <stddef.h>
#include "md5.h"

#define MBEDTLS_HMAC_MD5_BLOCK_SIZE  64
#define MBEDTLS_HMAC_MD5_DIGEST_SIZE 16

typedef struct {
    mbedtls_md5_context inner;
    unsigned char       k_opad[MBEDTLS_HMAC_MD5_BLOCK_SIZE];
} mbedtls_hmac_md5_context;

void mbedtls_hmac_md5_init  (mbedtls_hmac_md5_context *ctx);
void mbedtls_hmac_md5_free  (mbedtls_hmac_md5_context *ctx);

int  mbedtls_hmac_md5_starts (mbedtls_hmac_md5_context *ctx,
                              const unsigned char *key, size_t keylen);
int  mbedtls_hmac_md5_update (mbedtls_hmac_md5_context *ctx,
                              const unsigned char *input, size_t ilen);
int  mbedtls_hmac_md5_finish (mbedtls_hmac_md5_context *ctx,
                              unsigned char *output);

int  mbedtls_hmac_md5        (const unsigned char *key, size_t keylen,
                              const unsigned char *input, size_t ilen,
                              unsigned char *output);

#endif
