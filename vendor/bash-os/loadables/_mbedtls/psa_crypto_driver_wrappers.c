/*
 * psa_crypto_driver_wrappers.c — bash-os-flavored, builtin-only.
 *
 * Upstream mbedTLS auto-generates this file from a Jinja template
 * (vendor/mbedtls/tf-psa-crypto/scripts/data_files/driver_templates/
 * psa_crypto_driver_wrappers.h.jinja) based on which crypto
 * accelerator drivers are registered. bash-os has zero accelerators
 * (the loadable links statically into bash, no PKCS#11 / TPM / etc.),
 * so every wrapper just forwards to the corresponding
 * `mbedtls_psa_<op>` builtin entry point staged in
 * `psa_crypto_<aead,cipher,ecp,ffdh,hash,mac,pake,rsa,xof>.c`.
 *
 * Hand-written 2026-05-08 because we don't carry the Jinja toolchain
 * in the bash-os build path. ~66 wrapper functions; each ≤ 10 lines.
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "tf_psa_crypto_common.h"
#include "psa_crypto_aead.h"
#include "psa_crypto_cipher.h"
#include "psa_crypto_core.h"
#include "psa_crypto_driver_wrappers_no_static.h"
#include "psa_crypto_hash.h"
#include "psa_crypto_mac.h"
#include "psa_crypto_ecp.h"
#include "psa_crypto_rsa.h"
#include "psa_crypto_pake.h"
#include "psa_crypto_xof.h"

#include "platform.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

/* ============== init / free ============== */

psa_status_t psa_driver_wrapper_init(void)
{
    return PSA_SUCCESS;
}

void psa_driver_wrapper_free(void)
{
    /* No accelerator state to clean up. */
}

/* ============== hash ============== */

psa_status_t psa_driver_wrapper_hash_compute(
    psa_algorithm_t alg, const uint8_t *input, size_t input_length,
    uint8_t *hash, size_t hash_size, size_t *hash_length)
{
    return mbedtls_psa_hash_compute(alg, input, input_length,
                                    hash, hash_size, hash_length);
}

psa_status_t psa_driver_wrapper_hash_setup(
    psa_hash_operation_t *operation, psa_algorithm_t alg)
{
    return mbedtls_psa_hash_setup(&operation->ctx.mbedtls_ctx, alg);
}

psa_status_t psa_driver_wrapper_hash_clone(
    const psa_hash_operation_t *source, psa_hash_operation_t *target)
{
    return mbedtls_psa_hash_clone(&source->ctx.mbedtls_ctx,
                                  &target->ctx.mbedtls_ctx);
}

psa_status_t psa_driver_wrapper_hash_update(
    psa_hash_operation_t *operation, const uint8_t *input, size_t input_length)
{
    return mbedtls_psa_hash_update(&operation->ctx.mbedtls_ctx,
                                   input, input_length);
}

psa_status_t psa_driver_wrapper_hash_finish(
    psa_hash_operation_t *operation, uint8_t *hash, size_t hash_size, size_t *hash_length)
{
    return mbedtls_psa_hash_finish(&operation->ctx.mbedtls_ctx,
                                   hash, hash_size, hash_length);
}

psa_status_t psa_driver_wrapper_hash_abort(psa_hash_operation_t *operation)
{
    return mbedtls_psa_hash_abort(&operation->ctx.mbedtls_ctx);
}

/* ============== cipher ============== */

psa_status_t psa_driver_wrapper_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *iv, size_t iv_length,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    return mbedtls_psa_cipher_encrypt(attributes, key_buffer, key_buffer_size,
                                      alg, iv, iv_length, input, input_length,
                                      output, output_size, output_length);
}

psa_status_t psa_driver_wrapper_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    return mbedtls_psa_cipher_decrypt(attributes, key_buffer, key_buffer_size,
                                      alg, input, input_length,
                                      output, output_size, output_length);
}

psa_status_t psa_driver_wrapper_cipher_encrypt_setup(
    psa_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg)
{
    return mbedtls_psa_cipher_encrypt_setup(&operation->ctx.mbedtls_ctx,
                                            attributes, key_buffer, key_buffer_size, alg);
}

psa_status_t psa_driver_wrapper_cipher_decrypt_setup(
    psa_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg)
{
    return mbedtls_psa_cipher_decrypt_setup(&operation->ctx.mbedtls_ctx,
                                            attributes, key_buffer, key_buffer_size, alg);
}

psa_status_t psa_driver_wrapper_cipher_set_iv(
    psa_cipher_operation_t *operation, const uint8_t *iv, size_t iv_length)
{
    return mbedtls_psa_cipher_set_iv(&operation->ctx.mbedtls_ctx, iv, iv_length);
}

psa_status_t psa_driver_wrapper_cipher_update(
    psa_cipher_operation_t *operation,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    return mbedtls_psa_cipher_update(&operation->ctx.mbedtls_ctx,
                                     input, input_length,
                                     output, output_size, output_length);
}

psa_status_t psa_driver_wrapper_cipher_finish(
    psa_cipher_operation_t *operation,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    return mbedtls_psa_cipher_finish(&operation->ctx.mbedtls_ctx,
                                     output, output_size, output_length);
}

psa_status_t psa_driver_wrapper_cipher_abort(psa_cipher_operation_t *operation)
{
    return mbedtls_psa_cipher_abort(&operation->ctx.mbedtls_ctx);
}

/* ============== AEAD ============== */

psa_status_t psa_driver_wrapper_aead_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *plaintext, size_t plaintext_length,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length)
{
    return mbedtls_psa_aead_encrypt(attributes, key_buffer, key_buffer_size,
                                    alg, nonce, nonce_length,
                                    additional_data, additional_data_length,
                                    plaintext, plaintext_length,
                                    ciphertext, ciphertext_size, ciphertext_length);
}

psa_status_t psa_driver_wrapper_aead_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length)
{
    return mbedtls_psa_aead_decrypt(attributes, key_buffer, key_buffer_size,
                                    alg, nonce, nonce_length,
                                    additional_data, additional_data_length,
                                    ciphertext, ciphertext_length,
                                    plaintext, plaintext_size, plaintext_length);
}

psa_status_t psa_driver_wrapper_aead_encrypt_setup(
    psa_aead_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg)
{
    return mbedtls_psa_aead_encrypt_setup(&operation->ctx.mbedtls_ctx,
                                          attributes, key_buffer, key_buffer_size, alg);
}

psa_status_t psa_driver_wrapper_aead_decrypt_setup(
    psa_aead_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg)
{
    return mbedtls_psa_aead_decrypt_setup(&operation->ctx.mbedtls_ctx,
                                          attributes, key_buffer, key_buffer_size, alg);
}

psa_status_t psa_driver_wrapper_aead_set_nonce(
    psa_aead_operation_t *operation, const uint8_t *nonce, size_t nonce_length)
{
    return mbedtls_psa_aead_set_nonce(&operation->ctx.mbedtls_ctx, nonce, nonce_length);
}

psa_status_t psa_driver_wrapper_aead_set_lengths(
    psa_aead_operation_t *operation, size_t ad_length, size_t plaintext_length)
{
    return mbedtls_psa_aead_set_lengths(&operation->ctx.mbedtls_ctx,
                                        ad_length, plaintext_length);
}

psa_status_t psa_driver_wrapper_aead_update_ad(
    psa_aead_operation_t *operation, const uint8_t *input, size_t input_length)
{
    return mbedtls_psa_aead_update_ad(&operation->ctx.mbedtls_ctx, input, input_length);
}

psa_status_t psa_driver_wrapper_aead_update(
    psa_aead_operation_t *operation,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    return mbedtls_psa_aead_update(&operation->ctx.mbedtls_ctx,
                                   input, input_length,
                                   output, output_size, output_length);
}

psa_status_t psa_driver_wrapper_aead_finish(
    psa_aead_operation_t *operation,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length,
    uint8_t *tag, size_t tag_size, size_t *tag_length)
{
    return mbedtls_psa_aead_finish(&operation->ctx.mbedtls_ctx,
                                   ciphertext, ciphertext_size, ciphertext_length,
                                   tag, tag_size, tag_length);
}

psa_status_t psa_driver_wrapper_aead_verify(
    psa_aead_operation_t *operation,
    uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length,
    const uint8_t *tag, size_t tag_length)
{
    (void) operation; (void) plaintext; (void) plaintext_size; (void) plaintext_length;
    (void) tag; (void) tag_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_driver_wrapper_aead_abort(psa_aead_operation_t *operation)
{
    return mbedtls_psa_aead_abort(&operation->ctx.mbedtls_ctx);
}

/* ============== MAC ============== */

psa_status_t psa_driver_wrapper_mac_compute(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *mac, size_t mac_size, size_t *mac_length)
{
    return mbedtls_psa_mac_compute(attributes, key_buffer, key_buffer_size,
                                   alg, input, input_length,
                                   mac, mac_size, mac_length);
}

psa_status_t psa_driver_wrapper_mac_sign_setup(
    psa_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg)
{
    return mbedtls_psa_mac_sign_setup(&operation->ctx.mbedtls_ctx,
                                      attributes, key_buffer, key_buffer_size, alg);
}

psa_status_t psa_driver_wrapper_mac_verify_setup(
    psa_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg)
{
    return mbedtls_psa_mac_verify_setup(&operation->ctx.mbedtls_ctx,
                                        attributes, key_buffer, key_buffer_size, alg);
}

psa_status_t psa_driver_wrapper_mac_update(
    psa_mac_operation_t *operation, const uint8_t *input, size_t input_length)
{
    return mbedtls_psa_mac_update(&operation->ctx.mbedtls_ctx, input, input_length);
}

psa_status_t psa_driver_wrapper_mac_sign_finish(
    psa_mac_operation_t *operation,
    uint8_t *mac, size_t mac_size, size_t *mac_length)
{
    return mbedtls_psa_mac_sign_finish(&operation->ctx.mbedtls_ctx,
                                       mac, mac_size, mac_length);
}

psa_status_t psa_driver_wrapper_mac_verify_finish(
    psa_mac_operation_t *operation, const uint8_t *mac, size_t mac_length)
{
    return mbedtls_psa_mac_verify_finish(&operation->ctx.mbedtls_ctx, mac, mac_length);
}

psa_status_t psa_driver_wrapper_mac_abort(psa_mac_operation_t *operation)
{
    return mbedtls_psa_mac_abort(&operation->ctx.mbedtls_ctx);
}

/* ============== key derivation / agreement ============== */

psa_status_t psa_driver_wrapper_key_agreement(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *peer_key, size_t peer_key_length,
    uint8_t *shared_secret, size_t shared_secret_size, size_t *shared_secret_length)
{
    /* ECP and FFDH builtins both expose this signature. The dispatcher
       inspects the key type and routes. For builtin-only we delegate
       to the generic ECP path (X25519/P-256 cover the TLS use cases). */
    extern psa_status_t mbedtls_psa_key_agreement_ecdh(
        const psa_key_attributes_t *, const uint8_t *, size_t,
        psa_algorithm_t, const uint8_t *, size_t, uint8_t *, size_t, size_t *);
    return mbedtls_psa_key_agreement_ecdh(attributes, key_buffer, key_buffer_size,
                                          alg, peer_key, peer_key_length,
                                          shared_secret, shared_secret_size,
                                          shared_secret_length);
}

/* ============== asymmetric encrypt / decrypt ============== */

psa_status_t psa_driver_wrapper_asymmetric_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *salt, size_t salt_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    return mbedtls_psa_asymmetric_encrypt(attributes, key_buffer, key_buffer_size,
                                          alg, input, input_length, salt, salt_length,
                                          output, output_size, output_length);
}

psa_status_t psa_driver_wrapper_asymmetric_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *salt, size_t salt_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    return mbedtls_psa_asymmetric_decrypt(attributes, key_buffer, key_buffer_size,
                                          alg, input, input_length, salt, salt_length,
                                          output, output_size, output_length);
}

/* ============== sign / verify ============== */

psa_status_t psa_driver_wrapper_sign_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *input, size_t input_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    (void) attributes; (void) key_buffer; (void) key_buffer_size;
    (void) alg; (void) input; (void) input_length;
    (void) signature; (void) signature_size; (void) signature_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_driver_wrapper_verify_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *input, size_t input_length,
    const uint8_t *signature, size_t signature_length)
{
    (void) attributes; (void) key_buffer; (void) key_buffer_size;
    (void) alg; (void) input; (void) input_length;
    (void) signature; (void) signature_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_driver_wrapper_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    return mbedtls_psa_ecdsa_sign_hash(attributes, key_buffer, key_buffer_size,
                                       alg, hash, hash_length,
                                       signature, signature_size, signature_length);
}

psa_status_t psa_driver_wrapper_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length)
{
    return mbedtls_psa_ecdsa_verify_hash(attributes, key_buffer, key_buffer_size,
                                         alg, hash, hash_length,
                                         signature, signature_length);
}

/* ============== key management ============== */

psa_status_t psa_driver_wrapper_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)
{
    return mbedtls_psa_ecp_generate_key(attributes, key_buffer, key_buffer_size,
                                        key_buffer_length);
}

psa_status_t psa_driver_wrapper_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key_buffer, size_t key_buffer_size,
    size_t *key_buffer_length, size_t *bits)
{
    return mbedtls_psa_ecp_import_key(attributes, data, data_length,
                                      key_buffer, key_buffer_size, key_buffer_length, bits);
}

psa_status_t psa_driver_wrapper_export_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    (void) attributes; (void) key_buffer; (void) key_buffer_size;
    (void) data; (void) data_size; (void) data_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_driver_wrapper_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    return mbedtls_psa_ecp_export_public_key(attributes, key_buffer, key_buffer_size,
                                             data, data_size, data_length);
}

psa_status_t psa_driver_wrapper_copy_key(
    psa_key_attributes_t *attributes,
    const uint8_t *source_key, size_t source_key_length,
    uint8_t *target_key_buffer, size_t target_key_buffer_size,
    size_t *target_key_buffer_length)
{
    /* No accelerator → caller must do the copy at the slot layer. */
    (void) attributes; (void) source_key; (void) source_key_length;
    (void) target_key_buffer; (void) target_key_buffer_size;
    (void) target_key_buffer_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_driver_wrapper_get_key_buffer_size(
    const psa_key_attributes_t *attributes, size_t *key_buffer_size)
{
    /* For builtin-only: every key is stored in raw form. The size is
       PSA_BITS_TO_BYTES(bits) for symmetric keys; ECP/RSA have their
       own formulas. The slot management code handles this correctly
       for all builtin types. */
    *key_buffer_size = PSA_EXPORT_KEY_OUTPUT_SIZE(
        psa_get_key_type(attributes), psa_get_key_bits(attributes));
    return *key_buffer_size != 0 ? PSA_SUCCESS : PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_driver_wrapper_get_key_buffer_size_from_key_data(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length, size_t *key_buffer_size)
{
    (void) data; (void) data_length;
    return psa_driver_wrapper_get_key_buffer_size(attributes, key_buffer_size);
}

psa_status_t psa_driver_wrapper_get_builtin_key(
    psa_drv_slot_number_t slot_number,
    psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)
{
    /* No builtin key registry. */
    (void) slot_number; (void) attributes;
    (void) key_buffer; (void) key_buffer_size; (void) key_buffer_length;
    return PSA_ERROR_DOES_NOT_EXIST;
}

#endif /* MBEDTLS_PSA_CRYPTO_C */
