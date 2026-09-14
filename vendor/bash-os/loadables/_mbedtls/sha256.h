/* _mbedtls/sha256.h — SHA-256 API surface (Stage 19 hash demo).
 *
 * Subset of upstream vendor/mbedtls/tf-psa-crypto/drivers/builtin/include/
 * sha256.h. SHA-224 and SHA-256 are supported. PSA error
 * mappings replaced with simple int returns.
 *
 * Stage 19.B will replace this with the full upstream header once the
 * mbedTLS subset can build cleanly; for now this is the minimal API
 * surface bashcrypto's sha256 verb routes through.
 */
#ifndef MBEDTLS_SHA256_H
#define MBEDTLS_SHA256_H

#include <stddef.h>
#include <stdint.h>

/* SHA-256 input data was malformed. */
#define MBEDTLS_ERR_SHA256_BAD_INPUT_DATA  -0x0074

typedef struct mbedtls_sha256_context {
    uint32_t total[2];        /* number of bytes processed */
    uint32_t state[8];        /* intermediate digest state */
    unsigned char buffer[64]; /* data block being processed */
    int       is224;          /* SHA-224 flag */
} mbedtls_sha256_context;

void mbedtls_sha256_init  (mbedtls_sha256_context *ctx);
void mbedtls_sha256_free  (mbedtls_sha256_context *ctx);
void mbedtls_sha256_clone (mbedtls_sha256_context *dst,
                           const mbedtls_sha256_context *src);

int  mbedtls_sha256_starts (mbedtls_sha256_context *ctx, int is224);
int  mbedtls_sha256_update (mbedtls_sha256_context *ctx,
                            const unsigned char *input, size_t ilen);
int  mbedtls_sha256_finish (mbedtls_sha256_context *ctx,
                            unsigned char *output);

/* One-shot: hash `input` of length `ilen`, write 28 or 32 bytes to `output`. */
int  mbedtls_sha256        (const unsigned char *input, size_t ilen,
                            unsigned char *output, int is224);

#endif /* MBEDTLS_SHA256_H */
