/* _mbedtls/tls13_record.c — TLS 1.3 record layer (RFC 8446 §5).
 *
 * AEAD-protected record framing. AAD is the 5-byte TLSCiphertext header;
 * the inner plaintext carries (real_fragment || content_type || zero_pad);
 * decrypt strips trailing 0x00 to find the type byte (RFC 8446 §5.2 and
 * §5.4 for padding).
 *
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_ALLOW_PRIVATE_ACCESS
#define MBEDTLS_ALLOW_PRIVATE_ACCESS 1
#endif

#include "tls13_record.h"
#include "gcm.h"
#include "chachapoly.h"
#include <string.h>

static void mb_zeroize(void *buf, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *) buf;
    while (len--) *p++ = 0;
}

void mbedtls_tls13_record_nonce(
    const unsigned char iv[MBEDTLS_TLS13_AEAD_IV_LEN],
    uint64_t seq,
    unsigned char nonce_out[MBEDTLS_TLS13_AEAD_IV_LEN])
{
    /* nonce = iv XOR (seq encoded as 12-byte big-endian, right-aligned).
     * The high (iv_len - 8) = 4 bytes of seq are zero, so they leave
     * iv[0..3] unchanged. */
    memcpy(nonce_out, iv, MBEDTLS_TLS13_AEAD_IV_LEN);
    /* Spread seq across the trailing 8 bytes (iv[4..11]). */
    for (int i = 0; i < 8; i++) {
        nonce_out[MBEDTLS_TLS13_AEAD_IV_LEN - 1 - i] ^= (unsigned char) (seq >> (8 * i));
    }
}

int mbedtls_tls13_record_init(mbedtls_tls13_record_ctx *ctx,
                              mbedtls_tls13_cipher_t cipher,
                              const unsigned char *key, size_t key_len,
                              const unsigned char iv[MBEDTLS_TLS13_AEAD_IV_LEN])
{
    if (!ctx || !key || !iv) return MBEDTLS_ERR_TLS13_RECORD_BAD_CIPHER;
    switch (cipher) {
        case MBEDTLS_TLS13_CIPHER_AES_128_GCM:
            if (key_len != 16) return MBEDTLS_ERR_TLS13_RECORD_BAD_CIPHER;
            break;
        case MBEDTLS_TLS13_CIPHER_AES_256_GCM:
            if (key_len != 32) return MBEDTLS_ERR_TLS13_RECORD_BAD_CIPHER;
            break;
        case MBEDTLS_TLS13_CIPHER_CHACHA20_POLY1305:
            if (key_len != 32) return MBEDTLS_ERR_TLS13_RECORD_BAD_CIPHER;
            break;
        default:
            return MBEDTLS_ERR_TLS13_RECORD_BAD_CIPHER;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->cipher = cipher;
    ctx->key_len = key_len;
    memcpy(ctx->key, key, key_len);
    memcpy(ctx->iv,  iv,  MBEDTLS_TLS13_AEAD_IV_LEN);
    ctx->seq = 0;
    return 0;
}

void mbedtls_tls13_record_free(mbedtls_tls13_record_ctx *ctx)
{
    if (!ctx) return;
    mb_zeroize(ctx, sizeof(*ctx));
}

/* Build the 5-byte TLSCiphertext header into out. */
static void build_header(unsigned char out[MBEDTLS_TLS13_RECORD_HEADER_LEN],
                         size_t encrypted_record_len)
{
    out[0] = MBEDTLS_TLS13_RECORD_TYPE_APPLICATION_DATA; /* always 0x17 in TLS 1.3 */
    out[1] = 0x03;
    out[2] = 0x03;  /* legacy_version = TLS 1.2 (0x0303) on the wire */
    out[3] = (unsigned char) (encrypted_record_len >> 8);
    out[4] = (unsigned char) (encrypted_record_len & 0xFF);
}

int mbedtls_tls13_record_encrypt(
    mbedtls_tls13_record_ctx *ctx,
    const unsigned char *inner_pt, size_t inner_pt_len,
    unsigned char inner_type, size_t pad_len,
    unsigned char *record_out, size_t record_out_cap,
    size_t *record_len_out)
{
    if (!ctx || !record_out || !record_len_out) return MBEDTLS_ERR_TLS13_RECORD_BAD_HEADER;
    if (inner_pt_len > 16384) return MBEDTLS_ERR_TLS13_RECORD_OVERFLOW;
    /* Inner plaintext = inner_pt || type || padding(zeros) */
    size_t inner_total = inner_pt_len + 1 + pad_len;
    /* TLSCiphertext.encrypted_record = AEAD(inner_total) → ciphertext same len + 16 tag */
    size_t encrypted_record_len = inner_total + MBEDTLS_TLS13_AEAD_TAG_LEN;
    /* Total = 5-byte header + encrypted_record_len. */
    size_t total = MBEDTLS_TLS13_RECORD_HEADER_LEN + encrypted_record_len;
    if (encrypted_record_len > 16384 + 256)  /* RFC 8446 §5.2 max */
        return MBEDTLS_ERR_TLS13_RECORD_OVERFLOW;
    if (total > record_out_cap) return MBEDTLS_ERR_TLS13_RECORD_OVERFLOW;

    /* Build header (it's also the AAD). */
    build_header(record_out, encrypted_record_len);

    /* Assemble inner plaintext into the output buffer (just past the header). */
    unsigned char *body = record_out + MBEDTLS_TLS13_RECORD_HEADER_LEN;
    if (inner_pt_len > 0) memcpy(body, inner_pt, inner_pt_len);
    body[inner_pt_len] = inner_type;
    if (pad_len > 0) memset(body + inner_pt_len + 1, 0, pad_len);

    /* Derive the per-record nonce. */
    unsigned char nonce[MBEDTLS_TLS13_AEAD_IV_LEN];
    mbedtls_tls13_record_nonce(ctx->iv, ctx->seq, nonce);

    /* AEAD-encrypt in place. The output space already has inner_total
     * bytes of plaintext at body[0..inner_total-1]; we encrypt to
     * tmp_ct[] then copy back, then append tag. (Some AEADs allow
     * in-place; we use a copy step for simplicity.) */
    unsigned char tmp_ct[16384 + 256 + 1 + 256];
    if (inner_total > sizeof tmp_ct) return MBEDTLS_ERR_TLS13_RECORD_OVERFLOW;

    int rc;
    unsigned char tag[MBEDTLS_TLS13_AEAD_TAG_LEN];
    if (ctx->cipher == MBEDTLS_TLS13_CIPHER_CHACHA20_POLY1305) {
        mbedtls_chachapoly_context cp;
        mbedtls_chachapoly_init(&cp);
        rc = mbedtls_chachapoly_setkey(&cp, ctx->key);
        if (rc == 0)
            rc = mbedtls_chachapoly_encrypt_and_tag(
                &cp, inner_total, nonce,
                record_out, MBEDTLS_TLS13_RECORD_HEADER_LEN,  /* AAD */
                body, tmp_ct, tag);
        mbedtls_chachapoly_free(&cp);
    } else {
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
                                ctx->key, (unsigned int) ctx->key_len * 8);
        if (rc == 0)
            rc = mbedtls_gcm_crypt_and_tag(
                &gcm, MBEDTLS_GCM_ENCRYPT, inner_total,
                nonce, MBEDTLS_TLS13_AEAD_IV_LEN,
                record_out, MBEDTLS_TLS13_RECORD_HEADER_LEN, /* AAD */
                body, tmp_ct, MBEDTLS_TLS13_AEAD_TAG_LEN, tag);
        mbedtls_gcm_free(&gcm);
    }
    if (rc != 0) goto out;
    memcpy(body, tmp_ct, inner_total);
    memcpy(body + inner_total, tag, MBEDTLS_TLS13_AEAD_TAG_LEN);

    *record_len_out = total;
    ctx->seq++;
    rc = 0;
out:
    mb_zeroize(nonce, sizeof nonce);
    mb_zeroize(tmp_ct, inner_total);
    return rc;
}

int mbedtls_tls13_record_decrypt(
    mbedtls_tls13_record_ctx *ctx,
    const unsigned char *record_in, size_t record_in_len,
    unsigned char *inner_pt_out, size_t inner_pt_out_cap,
    size_t *inner_pt_len_out,
    unsigned char *inner_type_out)
{
    if (!ctx || !record_in || !inner_pt_out || !inner_pt_len_out || !inner_type_out)
        return MBEDTLS_ERR_TLS13_RECORD_BAD_HEADER;
    if (record_in_len < MBEDTLS_TLS13_RECORD_HEADER_LEN + MBEDTLS_TLS13_AEAD_TAG_LEN)
        return MBEDTLS_ERR_TLS13_RECORD_BAD_LENGTH;

    /* Parse header. */
    unsigned char opaque_type = record_in[0];
    size_t announced_len = ((size_t) record_in[3] << 8) | record_in[4];
    if (announced_len + MBEDTLS_TLS13_RECORD_HEADER_LEN != record_in_len)
        return MBEDTLS_ERR_TLS13_RECORD_BAD_LENGTH;
    /* TLS 1.3 records on the wire always have outer type = 0x17, except
     * for early plaintext bookkeeping records (CCS / handshake). The
     * record layer treats all incoming as encrypted; the handshake
     * driver decides if a CCS / unencrypted handshake should be passed
     * through unmodified. */
    (void) opaque_type;

    size_t inner_total = announced_len - MBEDTLS_TLS13_AEAD_TAG_LEN;
    if (inner_total > inner_pt_out_cap + 1)  /* +1 for the type byte */
        return MBEDTLS_ERR_TLS13_RECORD_OVERFLOW;

    const unsigned char *ct  = record_in + MBEDTLS_TLS13_RECORD_HEADER_LEN;
    const unsigned char *tag = ct + inner_total;

    unsigned char nonce[MBEDTLS_TLS13_AEAD_IV_LEN];
    mbedtls_tls13_record_nonce(ctx->iv, ctx->seq, nonce);

    /* Decrypt to scratch. The recovered buffer is `inner` =
     * fragment || content_type || zero_pad. */
    static unsigned char inner[16384 + 256 + 1 + 256];
    int rc;
    if (ctx->cipher == MBEDTLS_TLS13_CIPHER_CHACHA20_POLY1305) {
        mbedtls_chachapoly_context cp;
        mbedtls_chachapoly_init(&cp);
        rc = mbedtls_chachapoly_setkey(&cp, ctx->key);
        if (rc == 0)
            rc = mbedtls_chachapoly_auth_decrypt(
                &cp, inner_total, nonce,
                record_in, MBEDTLS_TLS13_RECORD_HEADER_LEN,  /* AAD */
                tag, ct, inner);
        mbedtls_chachapoly_free(&cp);
    } else {
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
                                ctx->key, (unsigned int) ctx->key_len * 8);
        if (rc == 0)
            rc = mbedtls_gcm_auth_decrypt(
                &gcm, inner_total,
                nonce, MBEDTLS_TLS13_AEAD_IV_LEN,
                record_in, MBEDTLS_TLS13_RECORD_HEADER_LEN, /* AAD */
                tag, MBEDTLS_TLS13_AEAD_TAG_LEN,
                ct, inner);
        mbedtls_gcm_free(&gcm);
    }

    mb_zeroize(nonce, sizeof nonce);
    if (rc != 0) {
        mb_zeroize(inner, inner_total);
        return MBEDTLS_ERR_TLS13_RECORD_BAD_TAG;
    }

    /* Strip trailing zero padding to find the content_type byte
     * (RFC 8446 §5.4). */
    size_t i = inner_total;
    while (i > 0 && inner[i - 1] == 0x00) i--;
    if (i == 0) {
        mb_zeroize(inner, inner_total);
        return MBEDTLS_ERR_TLS13_RECORD_BAD_INNER_TYPE;
    }
    *inner_type_out = inner[i - 1];
    size_t fragment_len = i - 1;

    if (fragment_len > inner_pt_out_cap) {
        mb_zeroize(inner, inner_total);
        return MBEDTLS_ERR_TLS13_RECORD_OVERFLOW;
    }
    if (fragment_len > 0) memcpy(inner_pt_out, inner, fragment_len);
    *inner_pt_len_out = fragment_len;

    mb_zeroize(inner, inner_total);
    ctx->seq++;
    return 0;
}
