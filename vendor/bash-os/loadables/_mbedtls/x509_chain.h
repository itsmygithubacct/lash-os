/* _mbedtls/x509_chain.h — X.509 cert-chain validation driver (Stage 19.B).
 *
 * Walks an array of mbedtls_x509_crt_min{} structures from leaf upward,
 * verifying:
 *   - issuer DN of cert N == subject DN of cert N+1 (byte-exact)
 *   - validity window of each cert covers `time_now`
 *   - cert N's signature verifies against cert N+1's public key
 *   - top of chain matches one of the trust anchors (by subject DN +
 *     public-key bit-equality)
 *
 * What's intentionally NOT covered (caller's responsibility):
 *   - Hostname / SAN matching (compare server SNI against leaf's
 *     SubjectAltName extension)
 *   - Path-length / name-constraints extensions
 *   - Certificate Transparency / OCSP / CRL
 *   - Key-usage / extended-key-usage flags
 *   - PSS-padded signatures (this driver only routes PKCS#1 v1.5 to RSA
 *     verify; PSS-signed certs return BAD_SIG)
 */
#ifndef MBEDTLS_X509_CHAIN_H
#define MBEDTLS_X509_CHAIN_H

#include <stddef.h>
#include <stdint.h>
#include "x509_crt_min.h"

/* Verification flags bitfield. 0 = chain valid. */
#define MBEDTLS_X509_BADCRT_NOT_TRUSTED       (1u << 0)
#define MBEDTLS_X509_BADCRT_EXPIRED           (1u << 1)
#define MBEDTLS_X509_BADCRT_NOT_YET_VALID     (1u << 2)
#define MBEDTLS_X509_BADCRT_NAME_CHAIN_BROKEN (1u << 3)
#define MBEDTLS_X509_BADCRT_BAD_SIG           (1u << 4)
#define MBEDTLS_X509_BADCRT_BAD_PK            (1u << 5)
#define MBEDTLS_X509_BADCRT_INTERNAL_ERROR    (1u << 6)

/* Minimal "now" representation: seconds since UNIX epoch. The validity-
 * window comparison parses cert UTCTime / GeneralizedTime into the same
 * unit and compares numerically. */
typedef int64_t mbedtls_x509_time_t;

/*
 * Parse an X.509 cert validity-time blob (UTCTime or GeneralizedTime)
 * into Unix seconds. Handles:
 *   UTCTime:        YYMMDDHHMMSSZ      (RFC 5280 maps YY: 00-49 → 2000-2049,
 *                                       50-99 → 1950-1999)
 *   GeneralizedTime: YYYYMMDDHHMMSSZ
 *
 * Returns 0 on success; negative on bad format. Out is set on success.
 */
int mbedtls_x509_time_parse(const mbedtls_asn1_buf *time_buf,
                            mbedtls_x509_time_t *out);

/*
 * Verify a chain. `chain[0]` is the leaf, `chain[n_certs-1]` is the
 * highest cert presented by the server (typically an intermediate; some
 * servers send the root too, which is harmless).
 *
 * `trust_anchors[]` is a list of root certs. The chain is accepted if
 * its top cert's signature is verified against (a) cert above it in the
 * chain or (b) a trust anchor whose subject DN + pubkey match the
 * issuer of the topmost chain cert.
 *
 * `time_now`: current Unix seconds. Pass 0 to skip validity-window
 * checks (test/insecure mode only — never in production).
 *
 * On return: *flags has the OR of every BADCRT_* the driver detected.
 * Function returns 0 if *flags == 0, MBEDTLS_ERR_X509_INVALID_FORMAT
 * otherwise.
 */
int mbedtls_x509_chain_verify(
    const mbedtls_x509_crt_min *chain, size_t n_certs,
    const mbedtls_x509_crt_min *trust_anchors, size_t n_ta,
    mbedtls_x509_time_t time_now,
    uint32_t *flags);

/*
 * Parse an ECDSA DER signature (SEQUENCE { INTEGER r, INTEGER s }) into
 * a fixed-width raw buffer r||s of `key_size` * 2 bytes (32+32 = 64 for
 * P-256, 48+48 = 96 for P-384). Leading-zero-padding rules per RFC 5480
 * are handled (DER positive-int may have a leading 0x00 byte that's
 * stripped here, and r/s shorter than `key_size` are zero-padded).
 *
 * Returns 0 on success.
 */
int mbedtls_ecdsa_sig_asn1_to_raw(const unsigned char *der, size_t der_len,
                                  unsigned char *raw_out, size_t key_size);

#endif /* MBEDTLS_X509_CHAIN_H */
