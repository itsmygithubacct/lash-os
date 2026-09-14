/* _mbedtls/chacha20.h — ChaCha20 stream cipher (RFC 8439).
 *
 * 256-bit key, 96-bit nonce, 32-bit counter. Self-contained, C-only.
 * Output: keystream blocks (64 bytes each) XORed with input.
 */
#ifndef MBEDTLS_CHACHA20_H
#define MBEDTLS_CHACHA20_H

#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA  -0x0051

typedef struct mbedtls_chacha20_context {
    uint32_t state[16];
    unsigned char keystream[64];
    size_t keystream_used;     /* 0..64 — bytes consumed from current block */
} mbedtls_chacha20_context;

void mbedtls_chacha20_init  (mbedtls_chacha20_context *ctx);
void mbedtls_chacha20_free  (mbedtls_chacha20_context *ctx);

int  mbedtls_chacha20_setkey  (mbedtls_chacha20_context *ctx,
                               const unsigned char key[32]);
int  mbedtls_chacha20_starts  (mbedtls_chacha20_context *ctx,
                               const unsigned char nonce[12],
                               uint32_t counter);
int  mbedtls_chacha20_update  (mbedtls_chacha20_context *ctx, size_t size,
                               const unsigned char *input,
                               unsigned char *output);

/* One-shot. */
int  mbedtls_chacha20_crypt   (const unsigned char key[32],
                               const unsigned char nonce[12],
                               uint32_t counter, size_t size,
                               const unsigned char *input,
                               unsigned char *output);

/* Internal: produce 64 bytes of keystream into out for state at counter. */
void mbedtls_chacha20_block   (uint32_t state[16], unsigned char out[64]);

#endif /* MBEDTLS_CHACHA20_H */
