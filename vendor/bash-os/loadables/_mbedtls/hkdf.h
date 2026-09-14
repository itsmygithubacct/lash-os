/* _mbedtls/hkdf.h — HKDF-SHA256 (Stage 19.B primitive #4).
 *
 * RFC 5869 extract-and-expand using the staged mbedTLS HMAC-SHA256
 * helper. This intentionally exposes only SHA-256 while the bash-os
 * mbedTLS migration is still moving one primitive at a time.
 */
#ifndef MBEDTLS_HKDF_H
#define MBEDTLS_HKDF_H

#include <stddef.h>

#define MBEDTLS_HKDF_SHA256_DIGEST_SIZE 32
#define MBEDTLS_HKDF_SHA256_MAX_OUTPUT  (255u * MBEDTLS_HKDF_SHA256_DIGEST_SIZE)

int mbedtls_hkdf_sha256_extract(const unsigned char *salt, size_t salt_len,
                                const unsigned char *ikm, size_t ikm_len,
                                unsigned char prk[MBEDTLS_HKDF_SHA256_DIGEST_SIZE]);

int mbedtls_hkdf_sha256_expand(const unsigned char prk[MBEDTLS_HKDF_SHA256_DIGEST_SIZE],
                               const unsigned char *info, size_t info_len,
                               unsigned char *okm, size_t okm_len);

int mbedtls_hkdf_sha256(const unsigned char *salt, size_t salt_len,
                        const unsigned char *ikm, size_t ikm_len,
                        const unsigned char *info, size_t info_len,
                        unsigned char *okm, size_t okm_len);

#endif /* MBEDTLS_HKDF_H */
