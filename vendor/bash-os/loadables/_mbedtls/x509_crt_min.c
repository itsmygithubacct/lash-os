/* _mbedtls/x509_crt_min.c — minimal X.509 v3 cert parser, Stage 19.B.
 *
 * Maps RFC 5280 §4.1 Certificate ASN.1 onto C struct fields. The parser
 * walks the DER once, recording byte-range views; no copy, no allocation.
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include "x509_crt_min.h"
#include <string.h>

/* ---- OID database (just the algorithms we recognize) -------------- */

/* RFC 8017 §A.2.4 — RSA signature OIDs (rsaEncryption + sha*WithRSAEncryption). */
static const unsigned char OID_RSA_ENCRYPTION[]    = { 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01 };
static const unsigned char OID_SHA1_WITH_RSA[]     = { 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x05 };
static const unsigned char OID_SHA256_WITH_RSA[]   = { 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B };
static const unsigned char OID_SHA384_WITH_RSA[]   = { 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0C };
static const unsigned char OID_SHA512_WITH_RSA[]   = { 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0D };
/* RFC 5480 — ECDSA. */
static const unsigned char OID_EC_PUBKEY[]         = { 0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01 };
static const unsigned char OID_ECDSA_SHA256[]      = { 0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02 };
static const unsigned char OID_ECDSA_SHA384[]      = { 0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x03 };
static const unsigned char OID_ECDSA_SHA512[]      = { 0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x04 };

#define OID_EQ(buf, lit) (mbedtls_asn1_oid_eq((buf), (lit), sizeof (lit)) == 0)

static mbedtls_sig_alg_t classify_sig_alg(const mbedtls_asn1_buf *oid)
{
    if (OID_EQ(oid, OID_SHA256_WITH_RSA)) return MBEDTLS_SIG_RSA_SHA256;
    if (OID_EQ(oid, OID_SHA384_WITH_RSA)) return MBEDTLS_SIG_RSA_SHA384;
    if (OID_EQ(oid, OID_SHA512_WITH_RSA)) return MBEDTLS_SIG_RSA_SHA512;
    if (OID_EQ(oid, OID_SHA1_WITH_RSA))   return MBEDTLS_SIG_RSA_SHA1;
    if (OID_EQ(oid, OID_ECDSA_SHA256))    return MBEDTLS_SIG_ECDSA_SHA256;
    if (OID_EQ(oid, OID_ECDSA_SHA384))    return MBEDTLS_SIG_ECDSA_SHA384;
    if (OID_EQ(oid, OID_ECDSA_SHA512))    return MBEDTLS_SIG_ECDSA_SHA512;
    return MBEDTLS_SIG_NONE;
}

/* ---- SubjectPublicKeyInfo parse ---------------------------------- */
/*
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm    AlgorithmIdentifier,
 *   subjectPublicKey BIT STRING
 * }
 *
 * For RSA: BIT STRING wraps RSAPublicKey ::= SEQUENCE { modulus INTEGER, exponent INTEGER }
 * For ECDSA: AlgorithmIdentifier carries the named-curve OID as the
 *   parameters; the BIT STRING body is the uncompressed point bytes.
 */
static int parse_spki(unsigned char **p, const unsigned char *end,
                      mbedtls_x509_crt_min *crt)
{
    size_t spki_len;
    int ret = mbedtls_asn1_get_tag(p, end, &spki_len,
                                   MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) return ret;
    const unsigned char *spki_end = *p + spki_len;

    /* AlgorithmIdentifier — special-case for ECDSA where parameters
     * carries the curve OID we want to keep. */
    size_t alg_len;
    ret = mbedtls_asn1_get_tag(p, spki_end, &alg_len,
                               MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) return ret;
    const unsigned char *alg_end = *p + alg_len;
    mbedtls_asn1_buf algo_oid;
    ret = mbedtls_asn1_get_oid(p, alg_end, &algo_oid);
    if (ret != 0) return ret;

    if (OID_EQ(&algo_oid, OID_RSA_ENCRYPTION)) {
        crt->pk_type = MBEDTLS_PK_RSA;
        /* Parameters MUST be NULL for rsaEncryption. */
        if (*p < alg_end) {
            ret = mbedtls_asn1_get_null(p, alg_end);
            if (ret != 0) return ret;
        }
    } else if (OID_EQ(&algo_oid, OID_EC_PUBKEY)) {
        crt->pk_type = MBEDTLS_PK_ECDSA;
        /* Parameters: ECParameters ::= CHOICE { namedCurve OBJECT IDENTIFIER, ... } */
        if (*p < alg_end) {
            ret = mbedtls_asn1_get_oid(p, alg_end, &crt->ec_curve_oid);
            if (ret != 0) return ret;
        }
    } else {
        return MBEDTLS_ERR_X509_UNKNOWN_PK_ALG;
    }

    /* subjectPublicKey BIT STRING */
    int unused_bits;
    mbedtls_asn1_buf bitstr;
    ret = mbedtls_asn1_get_bit_string(p, spki_end, &bitstr, &unused_bits);
    if (ret != 0)        return ret;
    if (unused_bits != 0) return MBEDTLS_ERR_X509_INVALID_FORMAT;

    if (crt->pk_type == MBEDTLS_PK_RSA) {
        /* RSAPublicKey ::= SEQUENCE { modulus INTEGER, exponent INTEGER } */
        unsigned char *q  = (unsigned char *) bitstr.p;
        const unsigned char *qend = bitstr.p + bitstr.len;
        size_t inner_len;
        ret = mbedtls_asn1_get_tag(&q, qend, &inner_len,
                                   MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (ret != 0) return ret;
        const unsigned char *inner_end = q + inner_len;
        ret = mbedtls_asn1_get_mpi_bytes(&q, inner_end, (const unsigned char **) &crt->rsa_n.p, &crt->rsa_n.len);
        if (ret != 0) return ret;
        ret = mbedtls_asn1_get_mpi_bytes(&q, inner_end, (const unsigned char **) &crt->rsa_e.p, &crt->rsa_e.len);
        if (ret != 0) return ret;
    } else { /* ECDSA */
        /* Uncompressed point: 0x04 || X || Y. */
        if (bitstr.len < 1 || bitstr.p[0] != 0x04)
            return MBEDTLS_ERR_X509_INVALID_FORMAT;
        crt->ec_pub.p = bitstr.p;
        crt->ec_pub.len = bitstr.len;
    }

    /* Skip any trailing bytes inside SPKI envelope (shouldn't be any). */
    if (*p < spki_end) *p = (unsigned char *) spki_end;
    return 0;
}

/* ---- TBSCertificate parse --------------------------------------- */
/*
 * TBSCertificate ::= SEQUENCE {
 *   version            [0] EXPLICIT Version DEFAULT v1,
 *   serialNumber       INTEGER,
 *   signature          AlgorithmIdentifier,
 *   issuer             Name,
 *   validity           SEQUENCE { notBefore Time, notAfter Time },
 *   subject            Name,
 *   subjectPublicKeyInfo SubjectPublicKeyInfo,
 *   issuerUniqueID  [1] IMPLICIT BIT STRING OPTIONAL,
 *   subjectUniqueID [2] IMPLICIT BIT STRING OPTIONAL,
 *   extensions      [3] EXPLICIT SEQUENCE OF Extension OPTIONAL
 * }
 */
static int parse_tbs(unsigned char **p, const unsigned char *end,
                     mbedtls_x509_crt_min *crt)
{
    /* Version: optional [0] EXPLICIT INTEGER. */
    crt->version = 1;  /* default v1 */
    if (end - *p > 0 &&
        **p == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0)) {
        size_t version_len;
        int ret = mbedtls_asn1_get_tag(p, end, &version_len,
                                       MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0);
        if (ret != 0) return ret;
        const unsigned char *vend = *p + version_len;
        int v;
        ret = mbedtls_asn1_get_int(p, vend, &v);
        if (ret != 0)    return ret;
        if (v > 2)       return MBEDTLS_ERR_X509_UNKNOWN_VERSION;
        crt->version = (int) v + 1;  /* DER encodes 0/1/2 = v1/v2/v3 */
    }

    /* serialNumber — keep raw bytes (some certs have very large serials). */
    {
        size_t ser_len;
        int ret = mbedtls_asn1_get_tag(p, end, &ser_len, MBEDTLS_ASN1_INTEGER);
        if (ret != 0) return ret;
        crt->serial.p   = *p;
        crt->serial.len = ser_len;
        *p += ser_len;
    }

    /* signature AlgorithmIdentifier — must match the outer signatureAlgorithm. */
    mbedtls_asn1_buf inner_alg_oid, inner_alg_params;
    int ret = mbedtls_asn1_get_alg(p, end, &inner_alg_oid, &inner_alg_params);
    if (ret != 0) return ret;
    /* (We re-read the outer signatureAlgorithm later and store sig_alg there.) */
    (void) inner_alg_oid;

    /* issuer Name — keep DER as-is. */
    {
        const unsigned char *issuer_start = *p;
        size_t name_len;
        ret = mbedtls_asn1_get_tag(p, end, &name_len,
                                   MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (ret != 0) return ret;
        crt->issuer.p   = (unsigned char *) issuer_start;
        crt->issuer.len = (*p - issuer_start) + name_len;
        *p += name_len;
    }

    /* validity SEQUENCE { notBefore Time, notAfter Time } */
    {
        size_t v_len;
        ret = mbedtls_asn1_get_tag(p, end, &v_len,
                                   MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (ret != 0) return ret;
        const unsigned char *v_end = *p + v_len;

        /* Each Time is UTCTime or GeneralizedTime. We just keep the raw
         * value bytes (caller does the parse). */
        for (int i = 0; i < 2; i++) {
            int tag = **p;
            if (tag != MBEDTLS_ASN1_UTC_TIME &&
                tag != MBEDTLS_ASN1_GENERALIZED_TIME)
                return MBEDTLS_ERR_X509_INVALID_FORMAT;
            size_t t_len;
            ret = mbedtls_asn1_get_tag(p, v_end, &t_len, tag);
            if (ret != 0) return ret;
            mbedtls_asn1_buf *slot = (i == 0) ? &crt->not_before_raw : &crt->not_after_raw;
            slot->p   = *p;
            slot->len = t_len;
            *p += t_len;
        }
    }

    /* subject Name */
    {
        const unsigned char *subj_start = *p;
        size_t name_len;
        ret = mbedtls_asn1_get_tag(p, end, &name_len,
                                   MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (ret != 0) return ret;
        crt->subject.p   = (unsigned char *) subj_start;
        crt->subject.len = (*p - subj_start) + name_len;
        *p += name_len;
    }

    /* SubjectPublicKeyInfo */
    ret = parse_spki(p, end, crt);
    if (ret != 0) return ret;

    /* Skip any optional uniqueIDs / extensions. */
    *p = (unsigned char *) end;
    return 0;
}

int mbedtls_x509_crt_min_parse(const unsigned char *der, size_t derlen,
                               mbedtls_x509_crt_min *crt)
{
    memset(crt, 0, sizeof(*crt));

    unsigned char *p = (unsigned char *) der;
    const unsigned char *end = der + derlen;

    crt->raw.p   = (unsigned char *) der;
    crt->raw.len = derlen;

    /* Outer Certificate ::= SEQUENCE { ... } */
    size_t cert_len;
    int ret = mbedtls_asn1_get_tag(&p, end, &cert_len,
                                   MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) return ret;
    if (cert_len + (p - der) != derlen) return MBEDTLS_ERR_X509_INVALID_FORMAT;

    /* TBSCertificate — capture for sig verification. */
    const unsigned char *tbs_start = p;
    size_t tbs_len;
    ret = mbedtls_asn1_get_tag(&p, end, &tbs_len,
                               MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) return ret;
    crt->tbs.p   = (unsigned char *) tbs_start;
    crt->tbs.len = (p - tbs_start) + tbs_len;

    const unsigned char *tbs_end = p + tbs_len;
    ret = parse_tbs(&p, tbs_end, crt);
    if (ret != 0) return ret;
    p = (unsigned char *) tbs_end;

    /* signatureAlgorithm */
    mbedtls_asn1_buf sig_oid, sig_params;
    ret = mbedtls_asn1_get_alg(&p, end, &sig_oid, &sig_params);
    if (ret != 0) return ret;
    crt->sig_alg = classify_sig_alg(&sig_oid);
    if (crt->sig_alg == MBEDTLS_SIG_NONE) return MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG;

    /* signatureValue BIT STRING */
    int unused_bits;
    ret = mbedtls_asn1_get_bit_string(&p, end, &crt->sig_value, &unused_bits);
    if (ret != 0)        return ret;
    if (unused_bits != 0) return MBEDTLS_ERR_X509_INVALID_FORMAT;

    return 0;
}
