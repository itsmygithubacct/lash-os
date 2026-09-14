/* _mbedtls/md5.h — MD5 API surface (Stage 19.B continuation).
 *
 * MD5 is broken for collision resistance. Retained for legacy fingerprint
 * compatibility (HMAC-MD5 in TLS 1.0 PRF, IKE, MIME content-MD5, /etc/shadow
 * legacy hashes). NOT for new use.
 */
#ifndef MBEDTLS_MD5_H
#define MBEDTLS_MD5_H

#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_ERR_MD5_BAD_INPUT_DATA  -0x0070

typedef struct mbedtls_md5_context {
    uint32_t total[2];        /* number of bytes processed */
    uint32_t state[4];        /* intermediate digest state  */
    unsigned char buffer[64]; /* data block being processed */
} mbedtls_md5_context;

void mbedtls_md5_init  (mbedtls_md5_context *ctx);
void mbedtls_md5_free  (mbedtls_md5_context *ctx);
void mbedtls_md5_clone (mbedtls_md5_context *dst,
                        const mbedtls_md5_context *src);

int  mbedtls_md5_starts (mbedtls_md5_context *ctx);
int  mbedtls_md5_update (mbedtls_md5_context *ctx,
                         const unsigned char *input, size_t ilen);
int  mbedtls_md5_finish (mbedtls_md5_context *ctx,
                         unsigned char *output);

int  mbedtls_md5        (const unsigned char *input, size_t ilen,
                         unsigned char *output);

#endif /* MBEDTLS_MD5_H */
