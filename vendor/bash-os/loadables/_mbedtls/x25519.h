/* _mbedtls/x25519.h — X25519 ECDH key exchange (Stage 19.B primitive #4).
 *
 * RFC 7748 §5 — Curve25519 / X25519. Used by TLS 1.3 ECDHE (the
 * mandatory key-exchange group) and bashcrypto's existing
 * `x25519-keygen/pub/shared` verbs.
 *
 * This is a self-contained reference implementation in portable C —
 * no SIMD, no ASM. Constant-time scalar multiplication via Montgomery
 * ladder with cswap. Intended to mirror the upstream
 * `mbedtls_ecdh_*` interface for X25519 once the full mbedtls ECDH
 * subset is vendored, but provides an immediate API surface for
 * Stage 19.D primitive consolidation.
 */
#ifndef MBEDTLS_X25519_H
#define MBEDTLS_X25519_H

/* Compute the shared secret via X25519:
 *   shared = clamp(scalar) · u(point)
 * Both `scalar` and `point` are 32 bytes (little-endian per RFC 7748).
 * Returns 0 on success, -1 on bad params. */
int mbedtls_x25519(unsigned char shared[32],
                   const unsigned char scalar[32],
                   const unsigned char point[32]);

/* Compute X25519 public key from a 32-byte private key:
 *   public = clamp(private) · 9
 * (The standard X25519 base point is u=9.) */
int mbedtls_x25519_base(unsigned char public_key[32],
                        const unsigned char private_key[32]);

#endif /* MBEDTLS_X25519_H */
