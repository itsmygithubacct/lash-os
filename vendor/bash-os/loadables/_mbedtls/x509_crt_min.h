/* _mbedtls/x509_crt_min.h — minimal X.509 v3 cert parser (Stage 19.B).
 *
 * Parses RFC 5280 Certificate / TBSCertificate enough to extract the
 * fields that TLS handshake validation needs: issuer/subject, validity
 * window, public key (RSA modulus+exponent OR EC pubkey), signature
 * algorithm, and TBS-bytes for signature verification.
 *
 * NOT a full X.509 implementation. Skipped for simplicity:
 *   - Extension parsing (we only locate it; callers walk if they care)
 *   - Name canonicalization (we keep the DER as-is for issuer-equals-subject
 *     checks; suffices for chain hops since RFC 5280 §4.1.2.4 mandates
 *     identical encoding)
 *   - CRL / OCSP
 *   - Path-length / name constraints
 */
#ifndef MBEDTLS_X509_CRT_MIN_H
#define MBEDTLS_X509_CRT_MIN_H

#include <stddef.h>
#include <stdint.h>
#include "asn1.h"

#define MBEDTLS_ERR_X509_INVALID_FORMAT      -0x2080
#define MBEDTLS_ERR_X509_UNKNOWN_VERSION     -0x2086
#define MBEDTLS_ERR_X509_UNKNOWN_PK_ALG      -0x2200
#define MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG     -0x2280

/* Public-key types we recognize. */
typedef enum {
    MBEDTLS_PK_NONE  = 0,
    MBEDTLS_PK_RSA   = 1,
    MBEDTLS_PK_ECDSA = 2
} mbedtls_pk_type_t;

/* Signature algorithms we recognize. */
typedef enum {
    MBEDTLS_SIG_NONE                  = 0,
    MBEDTLS_SIG_RSA_SHA1              = 1,
    MBEDTLS_SIG_RSA_SHA256            = 2,
    MBEDTLS_SIG_RSA_SHA384            = 3,
    MBEDTLS_SIG_RSA_SHA512            = 4,
    MBEDTLS_SIG_ECDSA_SHA256          = 5,
    MBEDTLS_SIG_ECDSA_SHA384          = 6,
    MBEDTLS_SIG_ECDSA_SHA512          = 7
} mbedtls_sig_alg_t;

typedef struct {
    /* Outer Certificate envelope. */
    mbedtls_asn1_buf raw;       /* full Certificate DER */

    /* TBSCertificate envelope (used for sig verification). */
    mbedtls_asn1_buf tbs;       /* SEQUENCE start..end of TBS */

    /* Fields. */
    int               version;        /* 1, 2, or 3 */
    mbedtls_asn1_buf  serial;          /* opaque DER value bytes */
    mbedtls_asn1_buf  issuer;          /* Name DER (untouched) */
    mbedtls_asn1_buf  subject;         /* Name DER (untouched) */
    mbedtls_asn1_buf  not_before_raw;  /* "YYMMDDHHMMSSZ" or "YYYYMMDDHHMMSSZ" */
    mbedtls_asn1_buf  not_after_raw;

    /* Public key material. */
    mbedtls_pk_type_t pk_type;
    /* RSA */
    mbedtls_asn1_buf  rsa_n;        /* modulus (big-endian, no leading 0) */
    mbedtls_asn1_buf  rsa_e;        /* exponent */
    /* ECDSA */
    mbedtls_asn1_buf  ec_curve_oid; /* named-curve OID */
    mbedtls_asn1_buf  ec_pub;       /* uncompressed point: 0x04 || X || Y */

    /* Signature. */
    mbedtls_sig_alg_t sig_alg;
    mbedtls_asn1_buf  sig_value;    /* BIT STRING body (sans unused-bits byte) */
} mbedtls_x509_crt_min;

/* Parse a single DER-encoded certificate. `der`/`derlen` must be the full
 * Certificate (outer SEQUENCE). On success, all crt fields point into
 * the input buffer (caller keeps it alive). Returns 0 / negative error. */
int mbedtls_x509_crt_min_parse(const unsigned char *der, size_t derlen,
                               mbedtls_x509_crt_min *crt);

#endif
