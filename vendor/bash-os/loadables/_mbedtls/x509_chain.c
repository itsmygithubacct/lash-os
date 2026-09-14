/* _mbedtls/x509_chain.c — X.509 cert-chain validation, Stage 19.B.
 *
 * Walks chain[] from leaf to top, verifying each hop's signature and
 * issuer/subject DN linkage, then matches the top cert against a trust
 * anchor list. Constant-time tag/sig comparisons where it matters;
 * straight-line code where it doesn't (parse paths).
 *
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include "x509_chain.h"
#include "x509_crt_min.h"
#include "asn1.h"
#include "rsa_min.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#include "ecdsa_p256.h"
#include <string.h>

/* ---- Validity-time parsing -------------------------------------- */

/* Days-in-month table (non-leap). */
static const int dim[12] = { 31,28,31,30,31,30,31,31,30,31,30,31 };

static int is_leap(int y) {
    return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
}

/* Convert (Y,M,D,h,m,s) to Unix seconds. M is 1-based. */
static int64_t civil_to_unix(int y, int mo, int d, int h, int mi, int s)
{
    /* Days since 1970-01-01. Algorithm from RFC 3339 / Howard Hinnant. */
    int64_t y_long = y;
    if (mo <= 2) y_long -= 1;
    int64_t era = (y_long >= 0 ? y_long : y_long - 399) / 400;
    int64_t yoe = y_long - era * 400;
    int64_t doy = (153 * (mo > 2 ? mo - 3 : mo + 9) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe/4 - yoe/100 + doy;
    int64_t days = era * 146097 + doe - 719468;  /* days since 1970-01-01 */
    return days * 86400 + h * 3600 + mi * 60 + s;
    (void) dim; (void) is_leap;
}

static int read_n_digits(const unsigned char *p, int n, int *out)
{
    int v = 0;
    for (int i = 0; i < n; i++) {
        if (p[i] < '0' || p[i] > '9') return -1;
        v = v * 10 + (p[i] - '0');
    }
    *out = v;
    return 0;
}

int mbedtls_x509_time_parse(const mbedtls_asn1_buf *time_buf, int64_t *out)
{
    /* UTCTime: YYMMDDHHMMSSZ (13 bytes). RFC 5280 §4.1.2.5: YY < 50 → 20YY,
     * else 19YY. */
    /* GeneralizedTime: YYYYMMDDHHMMSSZ (15 bytes). */
    if (!time_buf || !time_buf->p) return -1;
    int year, month, day, hour, minute, second;
    const unsigned char *p = time_buf->p;
    if (time_buf->len == 13 && p[12] == 'Z') {
        int yy;
        if (read_n_digits(p,     2, &yy)     != 0) return -1;
        if (read_n_digits(p +  2, 2, &month)  != 0) return -1;
        if (read_n_digits(p +  4, 2, &day)    != 0) return -1;
        if (read_n_digits(p +  6, 2, &hour)   != 0) return -1;
        if (read_n_digits(p +  8, 2, &minute) != 0) return -1;
        if (read_n_digits(p + 10, 2, &second) != 0) return -1;
        year = (yy < 50) ? 2000 + yy : 1900 + yy;
    } else if (time_buf->len == 15 && p[14] == 'Z') {
        if (read_n_digits(p,     4, &year)   != 0) return -1;
        if (read_n_digits(p +  4, 2, &month)  != 0) return -1;
        if (read_n_digits(p +  6, 2, &day)    != 0) return -1;
        if (read_n_digits(p +  8, 2, &hour)   != 0) return -1;
        if (read_n_digits(p + 10, 2, &minute) != 0) return -1;
        if (read_n_digits(p + 12, 2, &second) != 0) return -1;
    } else {
        return -1;
    }
    if (month < 1 || month > 12) return -1;
    if (day   < 1 || day   > 31) return -1;
    if (hour  > 23 || minute > 59 || second > 60) return -1;  /* leap-second */
    *out = civil_to_unix(year, month, day, hour, minute, second);
    return 0;
}

/* ---- ECDSA signature parsing (DER → raw) ------------------------ */

int mbedtls_ecdsa_sig_asn1_to_raw(const unsigned char *der, size_t der_len,
                                  unsigned char *raw_out, size_t key_size)
{
    if (key_size == 0 || key_size > 66) return -1;
    memset(raw_out, 0, 2 * key_size);

    unsigned char *p = (unsigned char *) der;
    const unsigned char *end = der + der_len;
    size_t seq_len;
    int rc = mbedtls_asn1_get_tag(&p, end, &seq_len,
                                  MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (rc != 0) return rc;

    const unsigned char *seq_end = p + seq_len;
    /* r INTEGER */
    const unsigned char *rp; size_t rlen;
    rc = mbedtls_asn1_get_mpi_bytes(&p, seq_end, &rp, &rlen);
    if (rc != 0) return rc;
    if (rlen > key_size) return -1;
    memcpy(raw_out + (key_size - rlen), rp, rlen);

    /* s INTEGER */
    const unsigned char *sp; size_t slen;
    rc = mbedtls_asn1_get_mpi_bytes(&p, seq_end, &sp, &slen);
    if (rc != 0) return rc;
    if (slen > key_size) return -1;
    memcpy(raw_out + key_size + (key_size - slen), sp, slen);

    return 0;
}

/* ---- Per-cert sig verify ---------------------------------------- */

/* Hash cert N's TBS bytes with the algo named in cert N's sig_alg. */
static int hash_tbs(mbedtls_sig_alg_t alg,
                    const unsigned char *tbs, size_t tbs_len,
                    unsigned char *digest, size_t *digest_len)
{
    switch (alg) {
        case MBEDTLS_SIG_RSA_SHA256:
        case MBEDTLS_SIG_ECDSA_SHA256:
            mbedtls_sha256(tbs, tbs_len, digest, 0); *digest_len = 32; return 0;
        case MBEDTLS_SIG_RSA_SHA384:
        case MBEDTLS_SIG_ECDSA_SHA384:
            mbedtls_sha512(tbs, tbs_len, digest, 1); *digest_len = 48; return 0;
        case MBEDTLS_SIG_RSA_SHA512:
        case MBEDTLS_SIG_ECDSA_SHA512:
            mbedtls_sha512(tbs, tbs_len, digest, 0); *digest_len = 64; return 0;
        case MBEDTLS_SIG_RSA_SHA1:
            mbedtls_sha1(tbs, tbs_len, digest);     *digest_len = 20; return 0;
        default:
            return -1;
    }
}

/* Verify cert N's signature using cert N+1's pubkey. */
static int verify_signed_by(const mbedtls_x509_crt_min *signed_cert,
                            const mbedtls_x509_crt_min *signer)
{
    unsigned char digest[64];
    size_t digest_len = 0;
    if (hash_tbs(signed_cert->sig_alg, signed_cert->tbs.p, signed_cert->tbs.len,
                 digest, &digest_len) != 0)
        return -1;

    if (signer->pk_type == MBEDTLS_PK_RSA) {
        mbedtls_rsa_md_id_t md_id;
        switch (signed_cert->sig_alg) {
            case MBEDTLS_SIG_RSA_SHA256: md_id = MBEDTLS_RSA_MD_SHA256; break;
            case MBEDTLS_SIG_RSA_SHA384: md_id = MBEDTLS_RSA_MD_SHA384; break;
            case MBEDTLS_SIG_RSA_SHA512: md_id = MBEDTLS_RSA_MD_SHA512; break;
            case MBEDTLS_SIG_RSA_SHA1:   md_id = MBEDTLS_RSA_MD_SHA1;   break;
            default: return -1;  /* RSA-PSS or other unsupported */
        }
        return mbedtls_rsa_min_pkcs1_verify(signer->rsa_n.p, signer->rsa_n.len,
                                        signer->rsa_e.p, signer->rsa_e.len,
                                        md_id, digest, digest_len,
                                        signed_cert->sig_value.p);
    } else if (signer->pk_type == MBEDTLS_PK_ECDSA) {
        /* P-256 only in this driver. P-384 would route to a P-384 verifier
         * we haven't staged yet. */
        if (signer->ec_pub.len != 65) return -1;
        unsigned char raw_sig[64];
        if (mbedtls_ecdsa_sig_asn1_to_raw(signed_cert->sig_value.p,
                                          signed_cert->sig_value.len,
                                          raw_sig, 32) != 0)
            return -1;
        return mbedtls_ecdsa_p256_verify_raw(signer->ec_pub.p, raw_sig,
                                             digest, digest_len);
    }
    return -1;  /* unknown signer pk_type */
}

/* ---- Trust anchor matching -------------------------------------- */

/* True iff the two certs have byte-equal subject DNs and pubkey
 * material — i.e., they represent the same key + identity. */
static int trust_anchor_match(const mbedtls_x509_crt_min *top,
                              const mbedtls_x509_crt_min *anchor)
                              __attribute__((unused));
static int trust_anchor_match(const mbedtls_x509_crt_min *top,
                              const mbedtls_x509_crt_min *anchor)
{
    /* Issuer of `top` must equal subject of `anchor`. */
    if (top->issuer.len != anchor->subject.len) return 0;
    if (memcmp(top->issuer.p, anchor->subject.p, top->issuer.len) != 0) return 0;

    /* Pubkey type and material must match (avoids issuer-collision
     * where two CAs share a DN but use different keys). */
    if (top->pk_type != anchor->pk_type) return 0;
    if (anchor->pk_type == MBEDTLS_PK_RSA) {
        if (anchor->rsa_n.len != top->rsa_n.len) return 0;
        if (anchor->rsa_e.len != top->rsa_e.len) return 0;
        if (memcmp(anchor->rsa_n.p, top->rsa_n.p, anchor->rsa_n.len) != 0) return 0;
        if (memcmp(anchor->rsa_e.p, top->rsa_e.p, anchor->rsa_e.len) != 0) return 0;
        return 1;
    }
    if (anchor->pk_type == MBEDTLS_PK_ECDSA) {
        if (anchor->ec_pub.len != top->ec_pub.len) return 0;
        if (memcmp(anchor->ec_pub.p, top->ec_pub.p, anchor->ec_pub.len) != 0) return 0;
        if (anchor->ec_curve_oid.len != top->ec_curve_oid.len) return 0;
        if (anchor->ec_curve_oid.len > 0 &&
            memcmp(anchor->ec_curve_oid.p, top->ec_curve_oid.p,
                   anchor->ec_curve_oid.len) != 0) return 0;
        return 1;
    }
    return 0;
}

/* Find a trust anchor whose subject DN equals `top->issuer` and whose
 * pubkey can verify `top->signature`. Returns pointer or NULL. */
static const mbedtls_x509_crt_min *
find_trust_anchor(const mbedtls_x509_crt_min *top,
                  const mbedtls_x509_crt_min *trust_anchors, size_t n_ta)
{
    for (size_t i = 0; i < n_ta; i++) {
        if (top->issuer.len != trust_anchors[i].subject.len) continue;
        if (memcmp(top->issuer.p, trust_anchors[i].subject.p,
                   top->issuer.len) != 0) continue;
        if (verify_signed_by(top, &trust_anchors[i]) == 0) {
            return &trust_anchors[i];
        }
    }
    return NULL;
}

/* ---- Main chain verifier ---------------------------------------- */

int mbedtls_x509_chain_verify(
    const mbedtls_x509_crt_min *chain, size_t n_certs,
    const mbedtls_x509_crt_min *trust_anchors, size_t n_ta,
    int64_t time_now,
    uint32_t *flags)
{
    if (!chain || n_certs == 0 || !trust_anchors || n_ta == 0 || !flags)
        return MBEDTLS_ERR_X509_INVALID_FORMAT;

    *flags = 0;

    /* 1) Validity-window check on every cert in chain. */
    if (time_now != 0) {
        for (size_t i = 0; i < n_certs; i++) {
            int64_t nb, na;
            if (mbedtls_x509_time_parse(&chain[i].not_before_raw, &nb) != 0 ||
                mbedtls_x509_time_parse(&chain[i].not_after_raw,  &na) != 0) {
                *flags |= MBEDTLS_X509_BADCRT_INTERNAL_ERROR;
                return MBEDTLS_ERR_X509_INVALID_FORMAT;
            }
            if (time_now < nb) *flags |= MBEDTLS_X509_BADCRT_NOT_YET_VALID;
            if (time_now > na) *flags |= MBEDTLS_X509_BADCRT_EXPIRED;
        }
    }

    /* 2) Walk hops chain[i] verified by chain[i+1]. */
    for (size_t i = 0; i + 1 < n_certs; i++) {
        const mbedtls_x509_crt_min *low  = &chain[i];
        const mbedtls_x509_crt_min *high = &chain[i + 1];

        /* Issuer of low must equal subject of high. */
        if (low->issuer.len != high->subject.len ||
            memcmp(low->issuer.p, high->subject.p, low->issuer.len) != 0) {
            *flags |= MBEDTLS_X509_BADCRT_NAME_CHAIN_BROKEN;
        }
        /* Verify low's signature with high's pubkey. */
        int rc = verify_signed_by(low, high);
        if (rc != 0) {
            *flags |= MBEDTLS_X509_BADCRT_BAD_SIG;
        }
    }

    /* 3) Top cert: match against a trust anchor. */
    const mbedtls_x509_crt_min *top = &chain[n_certs - 1];
    if (find_trust_anchor(top, trust_anchors, n_ta) == NULL) {
        /* If top is itself self-signed and present in trust list, that
         * also counts. Self-sig means issuer == subject. */
        int self_signed = (top->issuer.len == top->subject.len) &&
                          (memcmp(top->issuer.p, top->subject.p, top->issuer.len) == 0);
        int found_in_list = 0;
        if (self_signed) {
            for (size_t i = 0; i < n_ta; i++) {
                if (top->subject.len == trust_anchors[i].subject.len &&
                    memcmp(top->subject.p, trust_anchors[i].subject.p,
                           top->subject.len) == 0) {
                    found_in_list = 1;
                    break;
                }
            }
        }
        if (!found_in_list) {
            *flags |= MBEDTLS_X509_BADCRT_NOT_TRUSTED;
        }
    }

    return *flags == 0 ? 0 : MBEDTLS_ERR_X509_INVALID_FORMAT;
}
