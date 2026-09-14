/* _mbedtls/tls13_keys.c — TLS 1.3 key schedule (RFC 8446 §7.1).
 *
 * SHA-256-only. The schedule is a fixed sequence of HKDF-Extract /
 * HKDF-Expand-Label calls; this file just stitches them together.
 *
 * The design intent is that callers feed in transcript hashes computed
 * with mbedtls_sha256_* over the running handshake message stream, and
 * receive ready-to-use traffic secrets back. The actual record-layer
 * encryption (AEAD with sequence-mixed nonce) lives elsewhere.
 *
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include "tls13_keys.h"
#include "hkdf.h"
#include "sha256.h"
#include "hmac.h"
#include <string.h>

#define HASH_LEN MBEDTLS_TLS13_HASH_LEN  /* 32 */

static void mb_zeroize(void *buf, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *) buf;
    while (len--) *p++ = 0;
}

/*
 * Build the HkdfLabel struct on the stack:
 *   uint16 length;
 *   opaque label<7..255>   = "tls13 " || label
 *   opaque context<0..255> = context
 *
 * label_with_prefix len = 6 + label_len bytes; the 8-bit length prefix
 * makes the encoded chunk 1 + 6 + label_len bytes. Same for context:
 * 1 + context_len bytes.
 *
 * Total HkdfLabel size: 2 + 1 + 6 + label_len + 1 + context_len.
 */
int mbedtls_tls13_hkdf_expand_label(
    const unsigned char *secret, size_t secret_len,
    const unsigned char *label,  size_t label_len,
    const unsigned char *context, size_t context_len,
    unsigned char *out, size_t out_len)
{
    static const char prefix[] = "tls13 ";
    const size_t prefix_len = 6;

    if (label_len > 255 - prefix_len) return -1;
    if (context_len > 255)             return -1;
    if (out_len > 65535)               return -1;

    /* Max envelope: 2 + 1 + 255 + 1 + 255 = 514 bytes. */
    unsigned char hkdf_label[514];
    size_t pos = 0;

    /* uint16 length, big-endian */
    hkdf_label[pos++] = (unsigned char) (out_len >> 8);
    hkdf_label[pos++] = (unsigned char) (out_len & 0xFF);

    /* opaque label<7..255> = "tls13 " + label */
    hkdf_label[pos++] = (unsigned char) (prefix_len + label_len);
    memcpy(hkdf_label + pos, prefix, prefix_len); pos += prefix_len;
    if (label_len > 0) {
        memcpy(hkdf_label + pos, label, label_len);
        pos += label_len;
    }

    /* opaque context<0..255> */
    hkdf_label[pos++] = (unsigned char) context_len;
    if (context_len > 0) {
        memcpy(hkdf_label + pos, context, context_len);
        pos += context_len;
    }

    /* mbedtls_hkdf_sha256_expand requires a 32-byte PRK. TLS 1.3
     * HKDF-Expand-Label is always invoked with a HASH_LEN-byte secret. */
    if (secret_len != HASH_LEN) return -1;
    int rc = mbedtls_hkdf_sha256_expand(secret,
                                        hkdf_label, pos,
                                        out, out_len);
    mb_zeroize(hkdf_label, sizeof hkdf_label);
    return rc;
}

int mbedtls_tls13_derive_secret(
    const unsigned char *secret, size_t secret_len,
    const unsigned char *label, size_t label_len,
    const unsigned char *transcript_hash, size_t transcript_hash_len,
    unsigned char *out, size_t out_len)
{
    return mbedtls_tls13_hkdf_expand_label(
        secret, secret_len,
        label, label_len,
        transcript_hash, transcript_hash_len,
        out, out_len);
}

int mbedtls_tls13_traffic_key_iv(
    const unsigned char *secret,
    unsigned char *key_out, size_t key_len,
    unsigned char iv_out[12])
{
    int rc = mbedtls_tls13_hkdf_expand_label(
        secret, HASH_LEN,
        (const unsigned char *) "key", 3,
        NULL, 0,
        key_out, key_len);
    if (rc != 0) return rc;
    return mbedtls_tls13_hkdf_expand_label(
        secret, HASH_LEN,
        (const unsigned char *) "iv", 2,
        NULL, 0,
        iv_out, 12);
}

int mbedtls_tls13_finished_key(
    const unsigned char *secret,
    unsigned char *finished_key)
{
    return mbedtls_tls13_hkdf_expand_label(
        secret, HASH_LEN,
        (const unsigned char *) "finished", 8,
        NULL, 0,
        finished_key, HASH_LEN);
}

/* SHA-256 of the empty string — used as the "context" for the initial
 * Derive-Secret step in the key schedule. Pre-computed since it doesn't
 * depend on input. (FIPS 180-4 §A.1.) */
static const unsigned char SHA256_OF_EMPTY[32] = {
    0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
    0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
    0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
    0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
};

/*
 * Schedule (RFC 8446 §7.1, no-PSK 1-RTT path):
 *
 *   PSK = 0
 *   DHE = ecdhe_shared
 *
 *   early_secret      = HKDF-Extract(salt=0, IKM=PSK)
 *   derived_secret_es = Derive-Secret(early_secret, "derived", "")
 *   handshake_secret  = HKDF-Extract(salt=derived_secret_es, IKM=DHE)
 *
 *   client_hs_secret  = Derive-Secret(handshake_secret, "c hs traffic", H(CH..SH))
 *   server_hs_secret  = Derive-Secret(handshake_secret, "s hs traffic", H(CH..SH))
 *
 *   derived_secret_hs = Derive-Secret(handshake_secret, "derived", "")
 *   master_secret     = HKDF-Extract(salt=derived_secret_hs, IKM=0)
 */
int mbedtls_tls13_schedule_handshake_secrets(
    const unsigned char *ecdhe_shared, size_t ecdhe_shared_len,
    const unsigned char transcript_ch_sh[32],
    unsigned char early_secret[32],
    unsigned char handshake_secret[32],
    unsigned char client_hs_secret[32],
    unsigned char server_hs_secret[32])
{
    int rc;
    unsigned char zero32[32] = {0};
    unsigned char salt32[32] = {0};
    unsigned char derived[32];

    /* early_secret = HKDF-Extract(salt=0, IKM=zero PSK).
     * RFC 5869: with empty salt, salt is treated as HashLen zeros. */
    rc = mbedtls_hkdf_sha256_extract(salt32, 32, zero32, 32, early_secret);
    if (rc != 0) return rc;

    /* derived = Derive-Secret(early_secret, "derived", "") */
    rc = mbedtls_tls13_derive_secret(
        early_secret, 32,
        (const unsigned char *) "derived", 7,
        SHA256_OF_EMPTY, 32,
        derived, 32);
    if (rc != 0) return rc;

    /* handshake_secret = HKDF-Extract(salt=derived, IKM=DHE) */
    rc = mbedtls_hkdf_sha256_extract(derived, 32,
                                     ecdhe_shared, ecdhe_shared_len,
                                     handshake_secret);
    if (rc != 0) goto out;

    /* c hs traffic */
    rc = mbedtls_tls13_derive_secret(
        handshake_secret, 32,
        (const unsigned char *) "c hs traffic", 12,
        transcript_ch_sh, 32,
        client_hs_secret, 32);
    if (rc != 0) goto out;

    /* s hs traffic */
    rc = mbedtls_tls13_derive_secret(
        handshake_secret, 32,
        (const unsigned char *) "s hs traffic", 12,
        transcript_ch_sh, 32,
        server_hs_secret, 32);

out:
    mb_zeroize(derived, sizeof derived);
    return rc;
}

int mbedtls_tls13_schedule_master_secret(
    const unsigned char handshake_secret[32],
    unsigned char master_secret[32])
{
    int rc;
    unsigned char zero32[32] = {0};
    unsigned char derived[32];

    /* derived = Derive-Secret(handshake_secret, "derived", "") */
    rc = mbedtls_tls13_derive_secret(
        handshake_secret, 32,
        (const unsigned char *) "derived", 7,
        SHA256_OF_EMPTY, 32,
        derived, 32);
    if (rc != 0) return rc;

    /* master_secret = HKDF-Extract(salt=derived, IKM=0) */
    rc = mbedtls_hkdf_sha256_extract(derived, 32, zero32, 32, master_secret);
    mb_zeroize(derived, sizeof derived);
    return rc;
}

int mbedtls_tls13_derive_app_secrets(
    const unsigned char master_secret[32],
    const unsigned char transcript_handshake[32],
    unsigned char client_app_secret[32],
    unsigned char server_app_secret[32])
{
    int rc = mbedtls_tls13_derive_secret(
        master_secret, 32,
        (const unsigned char *) "c ap traffic", 12,
        transcript_handshake, 32,
        client_app_secret, 32);
    if (rc != 0) return rc;
    return mbedtls_tls13_derive_secret(
        master_secret, 32,
        (const unsigned char *) "s ap traffic", 12,
        transcript_handshake, 32,
        server_app_secret, 32);
}
