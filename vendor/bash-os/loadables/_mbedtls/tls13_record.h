/* _mbedtls/tls13_record.h — TLS 1.3 record layer (RFC 8446 §5).
 *
 * Sits between the bash-side socket I/O and the handshake / application
 * layer. Responsibilities:
 *   - Encrypt outgoing records: TLSPlaintext.fragment + content_type
 *     + optional zero padding → AEAD-protected TLSCiphertext.
 *   - Decrypt incoming records: TLSCiphertext.encrypted_record →
 *     TLSPlaintext.fragment + content_type, validating the AEAD tag.
 *   - Derive per-record nonce by XORing the IV with the per-direction
 *     sequence number (RFC 8446 §5.3).
 *
 * Cipher suites supported in this build (matches what the primitive
 * layer ships):
 *   - TLS_AES_128_GCM_SHA256       (key 16, iv 12, tag 16)
 *   - TLS_AES_256_GCM_SHA384       (key 32, iv 12, tag 16)
 *   - TLS_CHACHA20_POLY1305_SHA256 (key 32, iv 12, tag 16)
 *
 * The caller (handshake driver) feeds in:
 *   - traffic key + iv (derived via mbedtls_tls13_traffic_key_iv)
 *   - cipher choice (AES-128-GCM | AES-256-GCM | ChaCha20-Poly1305)
 *   - sequence number, owned per direction, reset on key update
 *
 * Frame layout (TLS 1.3, RFC 8446 §5.2):
 *
 *   TLSCiphertext = {
 *     opaque_type      ContentType  (1 byte; always 0x17 = application_data on the wire)
 *     legacy_version   ProtocolVersion (2 bytes; always 0x03 0x03 for TLS 1.2 compat)
 *     length           uint16        (2 bytes; size of encrypted_record)
 *     encrypted_record opaque[length]   // AEAD output: PT||tag
 *   }
 *
 *   TLSInnerPlaintext = {
 *     content           opaque[];     // the real fragment
 *     type              ContentType;  // 1 byte: handshake / application_data / alert
 *     zeros             uint8 padding[];  // optional trailing 0x00 bytes
 *   }
 *
 * The 5-byte TLSCiphertext header (opaque_type || legacy_version ||
 * length) is the AEAD AAD.
 */
#ifndef MBEDTLS_TLS13_RECORD_H
#define MBEDTLS_TLS13_RECORD_H

#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_TLS13_RECORD_HEADER_LEN  5
#define MBEDTLS_TLS13_AEAD_TAG_LEN       16
#define MBEDTLS_TLS13_AEAD_IV_LEN        12

#define MBEDTLS_TLS13_RECORD_TYPE_HANDSHAKE        0x16
#define MBEDTLS_TLS13_RECORD_TYPE_APPLICATION_DATA 0x17
#define MBEDTLS_TLS13_RECORD_TYPE_ALERT            0x15
#define MBEDTLS_TLS13_RECORD_TYPE_CHANGE_CIPHER_SPEC 0x14  /* compatibility-only */

/* Errors. */
#define MBEDTLS_ERR_TLS13_RECORD_BAD_HEADER     -0x6E80
#define MBEDTLS_ERR_TLS13_RECORD_BAD_LENGTH     -0x6E82
#define MBEDTLS_ERR_TLS13_RECORD_BAD_TAG        -0x6E84
#define MBEDTLS_ERR_TLS13_RECORD_BAD_INNER_TYPE -0x6E86
#define MBEDTLS_ERR_TLS13_RECORD_BAD_CIPHER     -0x6E88
#define MBEDTLS_ERR_TLS13_RECORD_OVERFLOW       -0x6E8A

typedef enum {
    MBEDTLS_TLS13_CIPHER_AES_128_GCM       = 1,
    MBEDTLS_TLS13_CIPHER_AES_256_GCM       = 2,
    MBEDTLS_TLS13_CIPHER_CHACHA20_POLY1305 = 3
} mbedtls_tls13_cipher_t;

/* Per-direction encryption context. */
typedef struct {
    mbedtls_tls13_cipher_t cipher;
    unsigned char key[32];          /* used: 16 for AES-128, 32 for AES-256/ChaCha */
    size_t        key_len;
    unsigned char iv[MBEDTLS_TLS13_AEAD_IV_LEN];
    uint64_t      seq;              /* big-endian counter mixed into the nonce */
} mbedtls_tls13_record_ctx;

/*
 * Initialise a record context with the given traffic key + iv. Resets
 * the sequence counter to 0. Caller derived key+iv via
 * mbedtls_tls13_traffic_key_iv() from the appropriate traffic secret.
 */
int mbedtls_tls13_record_init(mbedtls_tls13_record_ctx *ctx,
                              mbedtls_tls13_cipher_t cipher,
                              const unsigned char *key, size_t key_len,
                              const unsigned char iv[MBEDTLS_TLS13_AEAD_IV_LEN]);

void mbedtls_tls13_record_free(mbedtls_tls13_record_ctx *ctx);

/*
 * Encrypt a single record. Inputs:
 *   inner_pt          : the actual fragment bytes (handshake message,
 *                       application data, alert, etc.)
 *   inner_pt_len      : length of inner_pt
 *   inner_type        : 0x16 / 0x17 / 0x15
 *   pad_len           : number of trailing 0x00 bytes to insert after
 *                       the type byte (0 is fine; useful for traffic
 *                       analysis padding when non-zero).
 *
 * Outputs:
 *   record_out        : full TLSCiphertext = 5-byte header + ciphertext
 *                       + 16-byte tag. Buffer must be at least
 *                       MBEDTLS_TLS13_RECORD_HEADER_LEN + inner_pt_len
 *                       + 1 + pad_len + MBEDTLS_TLS13_AEAD_TAG_LEN.
 *   record_len_out    : actual size written.
 *
 * Side effect: ctx->seq is incremented.
 */
int mbedtls_tls13_record_encrypt(
    mbedtls_tls13_record_ctx *ctx,
    const unsigned char *inner_pt, size_t inner_pt_len,
    unsigned char inner_type, size_t pad_len,
    unsigned char *record_out, size_t record_out_cap,
    size_t *record_len_out);

/*
 * Decrypt a single record. Inputs:
 *   record_in         : full TLSCiphertext (header + body)
 *   record_in_len     : its size; must be >= 5 + 16 (header + tag)
 *
 * Outputs:
 *   inner_pt_out      : caller-provided buffer; written with the inner
 *                       fragment (not including type byte / padding).
 *   inner_pt_len_out  : how many bytes are in inner_pt_out.
 *   inner_type_out    : the recovered content_type (0x14/0x15/0x16/0x17).
 *
 * Side effect on success: ctx->seq is incremented.
 * On tag mismatch: returns MBEDTLS_ERR_TLS13_RECORD_BAD_TAG, ctx->seq
 * is NOT incremented (caller decides to abort the connection).
 */
int mbedtls_tls13_record_decrypt(
    mbedtls_tls13_record_ctx *ctx,
    const unsigned char *record_in, size_t record_in_len,
    unsigned char *inner_pt_out, size_t inner_pt_out_cap,
    size_t *inner_pt_len_out,
    unsigned char *inner_type_out);

/*
 * Derive the next per-record AEAD nonce from the IV + sequence counter.
 *   nonce[12] = iv[12] XOR (seq padded to 12 bytes BE-aligned to low end)
 * RFC 8446 §5.3.
 *
 * Exposed for unit tests; the encrypt/decrypt routines call this
 * internally.
 */
void mbedtls_tls13_record_nonce(
    const unsigned char iv[MBEDTLS_TLS13_AEAD_IV_LEN],
    uint64_t seq,
    unsigned char nonce_out[MBEDTLS_TLS13_AEAD_IV_LEN]);

#endif /* MBEDTLS_TLS13_RECORD_H */
