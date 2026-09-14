/* _mbedtls/hkdf.c — HKDF-SHA256 (RFC 5869).
 *
 * HKDF-Extract:
 *   PRK = HMAC-SHA256(salt, IKM)
 *
 * HKDF-Expand:
 *   T(0) = empty
 *   T(n) = HMAC-SHA256(PRK, T(n-1) || info || n)
 *   OKM  = first L bytes of T(1) || T(2) || ...
 *
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include "hkdf.h"
#include "hmac.h"
#include <string.h>

#define HASHLEN MBEDTLS_HKDF_SHA256_DIGEST_SIZE

static void
hkdf_wipe(unsigned char *buf, size_t len)
{
    volatile unsigned char *p = buf;
    while (len--) *p++ = 0;
}

int mbedtls_hkdf_sha256_extract(const unsigned char *salt, size_t salt_len,
                                const unsigned char *ikm, size_t ikm_len,
                                unsigned char prk[HASHLEN])
{
    unsigned char zero_salt[HASHLEN];

    if (ikm_len != 0 && ikm == NULL) return -1;
    if (salt_len != 0 && salt == NULL) return -1;

    if (salt == NULL || salt_len == 0) {
        memset(zero_salt, 0, sizeof zero_salt);
        salt = zero_salt;
        salt_len = sizeof zero_salt;
    }

    int ret = mbedtls_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    if (salt == zero_salt) hkdf_wipe(zero_salt, sizeof zero_salt);
    return ret;
}

int mbedtls_hkdf_sha256_expand(const unsigned char prk[HASHLEN],
                               const unsigned char *info, size_t info_len,
                               unsigned char *okm, size_t okm_len)
{
    if (prk == NULL || okm == NULL) return -1;
    if (info_len != 0 && info == NULL) return -1;
    if (okm_len > MBEDTLS_HKDF_SHA256_MAX_OUTPUT) return -1;

    unsigned char t[HASHLEN];
    size_t t_len = 0;
    size_t done = 0;
    unsigned int counter = 1;
    int ret = 0;

    while (done < okm_len) {
        mbedtls_hmac_sha256_context ctx;
        unsigned char c = (unsigned char) counter;

        mbedtls_hmac_sha256_init(&ctx);
        if ((ret = mbedtls_hmac_sha256_starts(&ctx, prk, HASHLEN)) != 0) goto out_ctx;
        if (t_len != 0 &&
            (ret = mbedtls_hmac_sha256_update(&ctx, t, t_len)) != 0) goto out_ctx;
        if (info_len != 0 &&
            (ret = mbedtls_hmac_sha256_update(&ctx, info, info_len)) != 0) goto out_ctx;
        if ((ret = mbedtls_hmac_sha256_update(&ctx, &c, 1)) != 0) goto out_ctx;
        ret = mbedtls_hmac_sha256_finish(&ctx, t);

out_ctx:
        mbedtls_hmac_sha256_free(&ctx);
        if (ret != 0) break;

        t_len = HASHLEN;
        size_t take = okm_len - done;
        if (take > HASHLEN) take = HASHLEN;
        memcpy(okm + done, t, take);
        done += take;
        counter++;
    }

    hkdf_wipe(t, sizeof t);
    return ret;
}

int mbedtls_hkdf_sha256(const unsigned char *salt, size_t salt_len,
                        const unsigned char *ikm, size_t ikm_len,
                        const unsigned char *info, size_t info_len,
                        unsigned char *okm, size_t okm_len)
{
    unsigned char prk[HASHLEN];
    int ret = mbedtls_hkdf_sha256_extract(salt, salt_len, ikm, ikm_len, prk);
    if (ret == 0)
        ret = mbedtls_hkdf_sha256_expand(prk, info, info_len, okm, okm_len);
    hkdf_wipe(prk, sizeof prk);
    return ret;
}
