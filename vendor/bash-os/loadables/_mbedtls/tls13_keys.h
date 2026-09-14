/* _mbedtls/tls13_keys.h — TLS 1.3 key schedule (RFC 8446 §7.1).
 *
 * The key schedule is a directed acyclic graph of HKDF-Extract/Expand
 * calls. Inputs: PSK (or 0), DHE shared secret (or 0), transcript hashes.
 * Outputs: traffic keys + IVs for the four directions:
 *   - client_handshake_traffic_secret  -> handshake key/iv (client->server)
 *   - server_handshake_traffic_secret  -> handshake key/iv (server->client)
 *   - client_application_traffic_secret_0 -> application key/iv (client->server)
 *   - server_application_traffic_secret_0 -> application key/iv (server->client)
 *
 * Plus the Finished MAC keys and resumption secrets.
 *
 * This implementation is SHA-256-only (HASH_LEN = 32). RFC 8446 only
 * mandates the SHA-256 ciphersuites for TLS 1.3 client; SHA-384 is
 * additional and can be parameterized later.
 */
#ifndef MBEDTLS_TLS13_KEYS_H
#define MBEDTLS_TLS13_KEYS_H

#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_TLS13_HASH_LEN 32      /* SHA-256 output bytes */

/*
 * HKDF-Expand-Label (RFC 8446 §7.1):
 *
 *   HKDF-Expand-Label(Secret, Label, Context, Length) =
 *       HKDF-Expand(Secret, HkdfLabel, Length)
 *
 *   where HkdfLabel is:
 *       struct {
 *           uint16 length = Length;
 *           opaque label<7..255> = "tls13 " + Label;
 *           opaque context<0..255> = Context;
 *       } HkdfLabel;
 *
 * label points to bytes WITHOUT the "tls13 " prefix; this routine adds it.
 * label_len must be ≤ 249 (so total label-with-prefix ≤ 255).
 * context_len must be ≤ 255.
 *
 * Returns 0 on success, negative on error.
 */
int mbedtls_tls13_hkdf_expand_label(
    const unsigned char *secret, size_t secret_len,
    const unsigned char *label,  size_t label_len,
    const unsigned char *context, size_t context_len,
    unsigned char *out, size_t out_len);

/*
 * Derive-Secret(Secret, Label, Messages) =
 *     HKDF-Expand-Label(Secret, Label, Hash(Messages), Hash.length)
 *
 * Where Hash(Messages) is the transcript hash. Caller passes the already-
 * computed transcript hash (32 bytes for SHA-256).
 */
int mbedtls_tls13_derive_secret(
    const unsigned char *secret, size_t secret_len,
    const unsigned char *label, size_t label_len,
    const unsigned char *transcript_hash, size_t transcript_hash_len,
    unsigned char *out, size_t out_len);

/*
 * Compute traffic key + iv from a traffic secret per RFC 8446 §7.3:
 *   key = HKDF-Expand-Label(secret, "key", "", key_len)
 *   iv  = HKDF-Expand-Label(secret, "iv",  "", 12)
 *
 * key_len: 16 for AES-128-GCM / ChaCha20-Poly1305, 32 for AES-256-GCM.
 */
int mbedtls_tls13_traffic_key_iv(
    const unsigned char *secret,
    unsigned char *key_out, size_t key_len,
    unsigned char iv_out[12]);

/*
 * Derive Finished MAC key from a handshake traffic secret:
 *   finished_key = HKDF-Expand-Label(secret, "finished", "", Hash.length)
 */
int mbedtls_tls13_finished_key(
    const unsigned char *secret,
    unsigned char *finished_key);

/*
 * Stitch together the §7.1 schedule for the standard 1-RTT path
 * (no PSK, no early data). Inputs:
 *   ecdhe_shared       : 32-byte X25519 shared secret (or other ECDHE)
 *   ecdhe_shared_len   : usually 32
 *   transcript_ch_sh   : Hash(ClientHello || ServerHello)
 *   transcript_handshake : Hash(CH..ServerHello..EncryptedExtensions..
 *                              Certificate..CertificateVerify..Finished)
 *
 * Outputs (each 32 bytes for SHA-256):
 *   client_hs_secret, server_hs_secret  — handshake traffic secrets
 *   master_secret                        — derived from the same chain
 *
 * Application secrets are derived from master_secret + Hash(...Finished)
 * via mbedtls_tls13_derive_app_secrets() once the handshake completes.
 */
int mbedtls_tls13_schedule_handshake_secrets(
    const unsigned char *ecdhe_shared, size_t ecdhe_shared_len,
    const unsigned char transcript_ch_sh[32],
    unsigned char early_secret[32],
    unsigned char handshake_secret[32],
    unsigned char client_hs_secret[32],
    unsigned char server_hs_secret[32]);

int mbedtls_tls13_schedule_master_secret(
    const unsigned char handshake_secret[32],
    unsigned char master_secret[32]);

int mbedtls_tls13_derive_app_secrets(
    const unsigned char master_secret[32],
    const unsigned char transcript_handshake[32],
    unsigned char client_app_secret[32],
    unsigned char server_app_secret[32]);

#endif /* MBEDTLS_TLS13_KEYS_H */
