/* _mbedtls/sha512.h — SHA-384/512 API surface (Stage 19.B continuation).
 *
 * Subset of upstream
 * vendor/mbedtls/tf-psa-crypto/drivers/builtin/include/sha512.h.
 * SHA-384 supported via the is384 flag (truncates SHA-512 + uses SHA-384
 * IV per FIPS 180-4 §5.3.4); the verb surface only exposes SHA-512 today.
 */
#ifndef MBEDTLS_SHA512_H
#define MBEDTLS_SHA512_H

#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_ERR_SHA512_BAD_INPUT_DATA  -0x0075

typedef struct mbedtls_sha512_context {
    uint64_t total[2];         /* number of bytes processed */
    uint64_t state[8];         /* intermediate digest state  */
    unsigned char buffer[128]; /* data block being processed */
    int       is384;           /* SHA-384 flag */
} mbedtls_sha512_context;

void mbedtls_sha512_init  (mbedtls_sha512_context *ctx);
void mbedtls_sha512_free  (mbedtls_sha512_context *ctx);
void mbedtls_sha512_clone (mbedtls_sha512_context *dst,
                           const mbedtls_sha512_context *src);

int  mbedtls_sha512_starts (mbedtls_sha512_context *ctx, int is384);
int  mbedtls_sha512_update (mbedtls_sha512_context *ctx,
                            const unsigned char *input, size_t ilen);
int  mbedtls_sha512_finish (mbedtls_sha512_context *ctx,
                            unsigned char *output);

/* One-shot. is384=0 → 64-byte digest; is384=1 → 48-byte digest. */
int  mbedtls_sha512        (const unsigned char *input, size_t ilen,
                            unsigned char *output, int is384);

#endif /* MBEDTLS_SHA512_H */
