/* _mbedtls/rsa.h — RSA-PKCS1-v1.5 verify (Stage 19.B continuation).
 *
 * Verify-only surface: enough to validate cert-chain signatures issued by
 * RSA CAs. No keygen, no sign, no OAEP/PSS. Public exponent is read from
 * the key (no fixed e=65537 assumption). Modulus length 1..512 bytes
 * (8192-bit ceiling — covers all real-world key sizes).
 *
 * PKCS#1 v1.5 EMSA-PKCS1-v1_5 (RFC 8017 §9.2):
 *   EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo(hash_algo, hash)
 *   PS = 0xFF * (k - tlen - 3), where k = modulus byte length, tlen = sizeof DigestInfo
 *
 * Hash algorithms supported: SHA-256, SHA-384, SHA-512, SHA-1.
 */
#ifndef MBEDTLS_RSA_H
#define MBEDTLS_RSA_H

#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_ERR_RSA_BAD_INPUT_DATA  -0x4080
#define MBEDTLS_ERR_RSA_VERIFY_FAILED   -0x4380

/* Match mbedTLS md.h values without requiring this shim header to include md.h. */
typedef enum {
    MBEDTLS_RSA_MD_SHA1   = 0x05,
    MBEDTLS_RSA_MD_SHA224 = 0x08,
    MBEDTLS_RSA_MD_SHA256 = 0x09,
    MBEDTLS_RSA_MD_SHA384 = 0x0a,
    MBEDTLS_RSA_MD_SHA512 = 0x0b
} mbedtls_rsa_md_id_t;

/* Verify a PKCS#1 v1.5 signature.
 *
 * Inputs:
 *   n_be, n_len        modulus n (big-endian, n_len bytes)
 *   e_be, e_len        public exponent (big-endian, e_len bytes)
 *   md_id              hash algorithm used to produce `digest`
 *   digest, digest_len already-computed hash of the message
 *   sig_be             signature, big-endian, n_len bytes long
 *
 * Returns 0 on valid signature, MBEDTLS_ERR_RSA_VERIFY_FAILED on
 * mismatch, MBEDTLS_ERR_RSA_BAD_INPUT_DATA on argument problems.
 */
int mbedtls_rsa_min_pkcs1_verify (const unsigned char *n_be, size_t n_len,
                              const unsigned char *e_be, size_t e_len,
                              mbedtls_rsa_md_id_t md_id,
                              const unsigned char *digest, size_t digest_len,
                              const unsigned char *sig_be);

#endif /* MBEDTLS_RSA_H */
