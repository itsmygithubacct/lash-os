/* _mbedtls/ecdsa_p256.h — compact P-256 ECDSA facade.
 *
 * Wraps mbedTLS's p256-m driver with bashcrypto-friendly wire formats:
 * private key = 32-byte scalar, public key = 0x04 || X || Y, signature
 * = raw r || s. Hashing and optional DER wrapping are handled by
 * bashcrypto.c so this helper stays small.
 */
#ifndef MBEDTLS_ECDSA_P256_H
#define MBEDTLS_ECDSA_P256_H

#include <stddef.h>

int mbedtls_ecdsa_p256_keygen(unsigned char sk[32]);
int mbedtls_ecdsa_p256_public(unsigned char pk65[65], const unsigned char sk[32]);
int mbedtls_ecdsa_p256_sign_raw(unsigned char sig64[64],
                                const unsigned char sk[32],
                                const unsigned char *digest, size_t digest_len);
int mbedtls_ecdsa_p256_verify_raw(const unsigned char pk65[65],
                                  const unsigned char sig64[64],
                                  const unsigned char *digest, size_t digest_len);

#endif /* MBEDTLS_ECDSA_P256_H */
