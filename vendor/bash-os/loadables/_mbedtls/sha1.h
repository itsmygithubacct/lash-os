/* _mbedtls/sha1.h — SHA-1 API surface (Stage 19.B continuation).
 *
 * Subset of upstream
 * vendor/mbedtls/tf-psa-crypto/drivers/builtin/include/sha1.h.
 * SHA-1 is retained for legacy compatibility (HMAC-SHA1 used in TLS 1.0/1.1,
 * IKE, X.509 fingerprint hashes, git's pack/object tree). Not for new use.
 */
#ifndef MBEDTLS_SHA1_H
#define MBEDTLS_SHA1_H

#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_ERR_SHA1_BAD_INPUT_DATA  -0x0073

typedef struct mbedtls_sha1_context {
    uint32_t total[2];        /* number of bytes processed */
    uint32_t state[5];        /* intermediate digest state  */
    unsigned char buffer[64]; /* data block being processed */
} mbedtls_sha1_context;

void mbedtls_sha1_init  (mbedtls_sha1_context *ctx);
void mbedtls_sha1_free  (mbedtls_sha1_context *ctx);
void mbedtls_sha1_clone (mbedtls_sha1_context *dst,
                         const mbedtls_sha1_context *src);

int  mbedtls_sha1_starts (mbedtls_sha1_context *ctx);
int  mbedtls_sha1_update (mbedtls_sha1_context *ctx,
                          const unsigned char *input, size_t ilen);
int  mbedtls_sha1_finish (mbedtls_sha1_context *ctx,
                          unsigned char *output);

/* One-shot. 20-byte digest written to output. */
int  mbedtls_sha1        (const unsigned char *input, size_t ilen,
                          unsigned char *output);

#endif /* MBEDTLS_SHA1_H */
