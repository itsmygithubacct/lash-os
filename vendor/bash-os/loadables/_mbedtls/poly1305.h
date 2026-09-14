/* _mbedtls/poly1305.h — Poly1305 one-time MAC (RFC 8439 §2.5).
 *
 * 32-byte key (16 r || 16 s), variable-length input, 16-byte tag output.
 * Stand-alone use is rare — typically composed with ChaCha20 for the
 * AEAD construction in chachapoly.c.
 */
#ifndef MBEDTLS_POLY1305_H
#define MBEDTLS_POLY1305_H

#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA  -0x0057

typedef struct mbedtls_poly1305_context {
    uint32_t r[5];        /* clamped 130-bit r (radix 2^26 limbs) */
    uint32_t s[4];        /* 128-bit s — added at finish */
    uint32_t acc[5];      /* 130-bit accumulator (radix 2^26)    */
    unsigned char queue[16];
    size_t queue_len;
} mbedtls_poly1305_context;

void mbedtls_poly1305_init  (mbedtls_poly1305_context *ctx);
void mbedtls_poly1305_free  (mbedtls_poly1305_context *ctx);

int  mbedtls_poly1305_starts (mbedtls_poly1305_context *ctx,
                              const unsigned char key[32]);
int  mbedtls_poly1305_update (mbedtls_poly1305_context *ctx,
                              const unsigned char *input, size_t ilen);
int  mbedtls_poly1305_finish (mbedtls_poly1305_context *ctx,
                              unsigned char mac[16]);

int  mbedtls_poly1305_mac    (const unsigned char key[32],
                              const unsigned char *input, size_t ilen,
                              unsigned char mac[16]);

#endif /* MBEDTLS_POLY1305_H */
