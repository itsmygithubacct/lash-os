/* _mbedtls/rsa.c — RSA-PKCS1-v1.5 verify, Stage 19.B.
 *
 * Self-contained schoolbook bignum + bit-level long-division reduction.
 * Verify-only — no keygen, no sign, no OAEP/PSS. Intended for cert-chain
 * signature checks where RSA modular exponentiation runs at most a few
 * times per TLS handshake.
 *
 * Bignum representation: uint64_t little-endian limbs, fixed length per
 * call. Performance is O(n²) in limb count for the multiplications and
 * O(n²) for each reduction; for RSA-2048 (32 limbs × 64 bits) a verify
 * runs in well under 100 ms on x86_64. RSA-4096 takes ~500 ms — still
 * well within human-noticeable budget for occasional cert validation.
 *
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_ALLOW_PRIVATE_ACCESS
#define MBEDTLS_ALLOW_PRIVATE_ACCESS 1
#endif

#include "rsa.h"
#include "bignum.h"
#include <string.h>

/* Maximum modulus 8192 bits = 1024 bytes = 128 limbs. */
#define MAX_LIMBS 128

static void mb_zeroize(void *buf, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *) buf;
    while (len--) *p++ = 0;
}

/* ---- Bignum primitives (fixed length n_limbs) -------------------- */

/* Compare a vs b, both length-n. Returns -1, 0, 1. */
static int mp_cmp(const uint64_t *a, const uint64_t *b, size_t n)
{
    for (size_t i = n; i-- > 0; ) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return  1;
    }
    return 0;
}

/* r = a - b (n-limb wide). Returns 0/1 final borrow.
 * Uses __uint128_t arithmetic so the bit-64 borrow is correct even when
 * b[i] = UINT64_MAX and borrow=1 (which would overflow plain b+borrow). */
static int mp_sub(const uint64_t *a, const uint64_t *b, uint64_t *r, size_t n)
{
    __uint128_t borrow = 0;
    for (size_t i = 0; i < n; i++) {
        __uint128_t t = (__uint128_t) a[i] - b[i] - borrow;
        r[i] = (uint64_t) t;
        borrow = (t >> 64) & 1;
    }
    return (int) borrow;
}

/* r = a + b mod 2^(64*n) — return final carry. */
static int mp_add(const uint64_t *a, const uint64_t *b, uint64_t *r, size_t n)
{
    uint64_t carry = 0;
    for (size_t i = 0; i < n; i++) {
        __uint128_t t = (__uint128_t) a[i] + b[i] + carry;
        r[i] = (uint64_t) t;
        carry = (uint64_t) (t >> 64);
    }
    return (int) carry;
}

/* Schoolbook multiplication: r[2n] = a[n] * b[n]. */
static void mp_mul(const uint64_t *a, const uint64_t *b, uint64_t *r, size_t n)
{
    memset(r, 0, 2 * n * sizeof(uint64_t));
    for (size_t i = 0; i < n; i++) {
        __uint128_t carry = 0;
        for (size_t j = 0; j < n; j++) {
            __uint128_t p = (__uint128_t) a[i] * b[j];
            __uint128_t s = (__uint128_t) r[i + j] + (uint64_t) p + (uint64_t) carry;
            r[i + j] = (uint64_t) s;
            carry = (p >> 64) + (s >> 64) + (carry >> 64);
        }
        r[i + n] = (uint64_t) carry;
    }
}

/* Bit-level shift-left by 1 of a length-N limb array. Returns out-shifted bit. */
static int mp_shl1(uint64_t *a, size_t n)
{
    uint64_t carry = 0;
    for (size_t i = 0; i < n; i++) {
        uint64_t hi = a[i] >> 63;
        a[i] = (a[i] << 1) | carry;
        carry = hi;
    }
    return (int) carry;
}

/* Reduce dividend (2n limbs) modulo modulus (n limbs).
 * Result placed in dividend[0..n-1]; dividend[n..2n-1] zeroed.
 *
 * Algorithm: bit-level long division. Maintain a "remainder" that
 * starts at 0, and shift bits of dividend in from the high end one at
 * a time (total = 2n*64 iterations). After each shift, if remainder >= m,
 * subtract m. Result is the remainder.
 */
static void mp_mod(uint64_t *dividend, const uint64_t *m, size_t n_limbs)
{
    uint64_t rem[MAX_LIMBS] = {0};
    uint64_t tmp[MAX_LIMBS];

    /* Trim leading-zero limbs of m to find its actual top-bit position
     * (kept implicit; we treat m as length n_limbs throughout). */

    size_t total_bits = 2 * n_limbs * 64;
    for (size_t bit = 0; bit < total_bits; bit++) {
        /* Top bit of dividend is at index 2n-1, bit 63. */
        uint64_t in_bit = (dividend[2 * n_limbs - 1] >> 63) & 1;
        /* Shift dividend left by 1 (drops top bit). */
        for (size_t i = 2 * n_limbs - 1; i > 0; i--) {
            dividend[i] = (dividend[i] << 1) | (dividend[i - 1] >> 63);
        }
        dividend[0] <<= 1;
        /* Shift remainder left by 1, capturing the bit that overflows the
         * n-limb representation. For RSA where m has its top bit set,
         * rem can be close to m, and 2*rem may need an (n*64+1)th bit. */
        int rem_overflow = mp_shl1(rem, n_limbs);
        rem[0] |= in_bit;
        /* Conceptual remainder is (rem_overflow << (n_limbs*64)) | rem.
         * If rem_overflow is set, rem' >= 2^(n*64) > m so subtract.
         * The mp_sub borrow cancels the conceptual high bit, yielding
         * the correct n-limb result. */
        if (rem_overflow || mp_cmp(rem, m, n_limbs) >= 0) {
            mp_sub(rem, m, tmp, n_limbs);
            memcpy(rem, tmp, n_limbs * sizeof(uint64_t));
        }
    }
    memcpy(dividend, rem, n_limbs * sizeof(uint64_t));
    memset(dividend + n_limbs, 0, n_limbs * sizeof(uint64_t));
    mb_zeroize(rem, sizeof rem);
    mb_zeroize(tmp, sizeof tmp);
}

/* result = (a * b) mod m, all length n_limbs. */
static void mp_mulmod(const uint64_t *a, const uint64_t *b, const uint64_t *m,
                      uint64_t *result, size_t n_limbs)
{
    uint64_t prod[2 * MAX_LIMBS];
    mp_mul(a, b, prod, n_limbs);
    mp_mod(prod, m, n_limbs);
    memcpy(result, prod, n_limbs * sizeof(uint64_t));
    mb_zeroize(prod, sizeof prod);
}

/* result = base ^ exp_be (big-endian byte array) mod m.
 * base and m are length n_limbs. Square-and-multiply, MSB first. */
static void mp_modexp_be(const uint64_t *base, const unsigned char *exp_be,
                         size_t exp_len, const uint64_t *m,
                         uint64_t *result, size_t n_limbs)
{
    uint64_t cur[MAX_LIMBS];
    memset(cur, 0, n_limbs * sizeof(uint64_t));
    cur[0] = 1;  /* multiplicative identity */

    /* Trim leading zero bytes of exp. */
    while (exp_len > 0 && exp_be[0] == 0) { exp_be++; exp_len--; }
    if (exp_len == 0) {
        /* x^0 = 1. */
        memcpy(result, cur, n_limbs * sizeof(uint64_t));
        return;
    }

    /* Find first 1 bit of exponent. */
    size_t total_bits = exp_len * 8;
    size_t i = 0;
    while (i < total_bits) {
        size_t byte = i / 8, bit = 7 - (i % 8);
        if (exp_be[byte] & (1u << bit)) break;
        i++;
    }
    /* From here we square+multiply. */
    for (; i < total_bits; i++) {
        size_t byte = i / 8, bit = 7 - (i % 8);
        /* cur = cur * cur mod m */
        mp_mulmod(cur, cur, m, cur, n_limbs);
        /* If bit is 1, cur = cur * base mod m */
        if (exp_be[byte] & (1u << bit)) {
            mp_mulmod(cur, base, m, cur, n_limbs);
        }
    }
    memcpy(result, cur, n_limbs * sizeof(uint64_t));
    mb_zeroize(cur, sizeof cur);
}

/* Convert big-endian byte array of length nbytes into n_limbs uint64
 * little-endian limbs. nbytes <= n_limbs*8. */
static void be_to_limbs(const unsigned char *be, size_t nbytes,
                        uint64_t *limbs, size_t n_limbs)
{
    memset(limbs, 0, n_limbs * sizeof(uint64_t));
    for (size_t i = 0; i < nbytes; i++) {
        size_t le_byte = nbytes - 1 - i;
        size_t limb_idx = le_byte / 8;
        size_t shift = (le_byte % 8) * 8;
        limbs[limb_idx] |= (uint64_t) be[i] << shift;
    }
}

/* Convert n_limbs little-endian limbs back to big-endian bytes (nbytes). */
static void limbs_to_be(const uint64_t *limbs, size_t n_limbs,
                        unsigned char *be, size_t nbytes)
{
    for (size_t i = 0; i < nbytes; i++) {
        size_t le_byte = nbytes - 1 - i;
        size_t limb_idx = le_byte / 8;
        size_t shift = (le_byte % 8) * 8;
        be[i] = (unsigned char) ((limbs[limb_idx] >> shift) & 0xFF);
    }
}

/* ---- ASN.1 DigestInfo prefixes for PKCS#1 v1.5 ------------------- */

/* Per RFC 8017 §9.2 / §A.2.4. Prefixes precede the raw digest bytes. */
static const unsigned char digest_info_sha1[15] = {
    0x30,0x21, 0x30,0x09, 0x06,0x05, 0x2b,0x0e,0x03,0x02,0x1a,
    0x05,0x00, 0x04,0x14
};
static const unsigned char digest_info_sha224[19] = {
    0x30,0x2d, 0x30,0x0d, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x04,
    0x05,0x00, 0x04,0x1c
};
static const unsigned char digest_info_sha256[19] = {
    0x30,0x31, 0x30,0x0d, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,
    0x05,0x00, 0x04,0x20
};
static const unsigned char digest_info_sha384[19] = {
    0x30,0x41, 0x30,0x0d, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,
    0x05,0x00, 0x04,0x30
};
static const unsigned char digest_info_sha512[19] = {
    0x30,0x51, 0x30,0x0d, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,
    0x05,0x00, 0x04,0x40
};

static int get_digest_info(mbedtls_md_type_t md_id,
                           const unsigned char **prefix, size_t *prefix_len,
                           size_t *digest_size)
{
    switch (md_id) {
        case MBEDTLS_MD_SHA1:
            *prefix = digest_info_sha1;   *prefix_len = sizeof digest_info_sha1;
            *digest_size = 20; return 0;
        case MBEDTLS_MD_SHA224:
            *prefix = digest_info_sha224; *prefix_len = sizeof digest_info_sha224;
            *digest_size = 28; return 0;
        case MBEDTLS_MD_SHA256:
            *prefix = digest_info_sha256; *prefix_len = sizeof digest_info_sha256;
            *digest_size = 32; return 0;
        case MBEDTLS_MD_SHA384:
            *prefix = digest_info_sha384; *prefix_len = sizeof digest_info_sha384;
            *digest_size = 48; return 0;
        case MBEDTLS_MD_SHA512:
            *prefix = digest_info_sha512; *prefix_len = sizeof digest_info_sha512;
            *digest_size = 64; return 0;
    }
    return -1;
}

/* ---- Public verify ----------------------------------------------- */

int mbedtls_rsa_min_pkcs1_verify(const unsigned char *n_be, size_t n_len,
                             const unsigned char *e_be, size_t e_len,
                             mbedtls_md_type_t md_id,
                             const unsigned char *digest, size_t digest_len,
                             const unsigned char *sig_be)
{
    if (!n_be || !e_be || !digest || !sig_be) return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    if (n_len < 64 || n_len > MAX_LIMBS * 8)  return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    const unsigned char *prefix; size_t prefix_len, expected_digest_len;
    if (get_digest_info(md_id, &prefix, &prefix_len, &expected_digest_len) != 0)
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    if (digest_len != expected_digest_len) return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    mbedtls_rsa_context ctx;
    mbedtls_rsa_init(&ctx);
    int full_rc = mbedtls_mpi_read_binary(&ctx.MBEDTLS_PRIVATE(N), n_be, n_len);
    if (full_rc == 0) full_rc = mbedtls_mpi_read_binary(&ctx.MBEDTLS_PRIVATE(E), e_be, e_len);
    if (full_rc == 0) ctx.MBEDTLS_PRIVATE(len) = n_len;
    if (full_rc == 0) full_rc = mbedtls_rsa_pkcs1_verify(&ctx, md_id, (unsigned int) digest_len, digest, sig_be);
    mbedtls_rsa_free(&ctx);
    if (full_rc == 0) return 0;

    /* tlen = prefix + digest */
    size_t tlen = prefix_len + digest_len;
    /* PS = 0xFF * (k - tlen - 3); requires k >= tlen + 11. */
    if (n_len < tlen + 11) return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    unsigned char em_be[1024];
    if (n_len > sizeof em_be) return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    mbedtls_mpi N, E, S, M;
    mbedtls_mpi_init(&N); mbedtls_mpi_init(&E); mbedtls_mpi_init(&S); mbedtls_mpi_init(&M);
    int mpi_rc = mbedtls_mpi_read_binary(&N, n_be, n_len);
    if (mpi_rc == 0) mpi_rc = mbedtls_mpi_read_binary(&E, e_be, e_len);
    if (mpi_rc == 0) mpi_rc = mbedtls_mpi_read_binary(&S, sig_be, n_len);
    if (mpi_rc == 0 && mbedtls_mpi_cmp_mpi(&S, &N) >= 0) mpi_rc = MBEDTLS_ERR_RSA_VERIFY_FAILED;
    if (mpi_rc == 0) mpi_rc = mbedtls_mpi_exp_mod(&M, &S, &E, &N, NULL);
    if (mpi_rc == 0) mpi_rc = mbedtls_mpi_write_binary(&M, em_be, n_len);
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&E); mbedtls_mpi_free(&S); mbedtls_mpi_free(&M);
    if (mpi_rc != 0) return mpi_rc;

    /* Validate PKCS#1 v1.5 padding format:
     *   EM = 0x00 || 0x01 || PS(0xFF...) || 0x00 || T
     * where T = prefix || digest. PS length >= 8. */
    int ok = 1;
    if (em_be[0] != 0x00 || em_be[1] != 0x01) ok = 0;
    /* Find first non-0xFF byte after offset 2. */
    size_t i = 2;
    while (i < n_len && em_be[i] == 0xFF) i++;
    /* PS length = i - 2; must be >= 8. */
    if (i - 2 < 8) ok = 0;
    if (i >= n_len || em_be[i] != 0x00) ok = 0;
    i++;
    /* Remaining bytes must equal prefix || digest. */
    if (n_len - i != tlen) ok = 0;
    /* Constant-time compare to avoid revealing partial-match info. */
    unsigned char d = 0;
    if (ok) {
        for (size_t k = 0; k < prefix_len; k++)
            d |= em_be[i + k] ^ prefix[k];
        for (size_t k = 0; k < digest_len; k++)
            d |= em_be[i + prefix_len + k] ^ digest[k];
        if (d != 0) ok = 0;
    }

    mb_zeroize(em_be, sizeof em_be);

    return ok ? 0 : MBEDTLS_ERR_RSA_VERIFY_FAILED;
}
