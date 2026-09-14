/* _mbedtls/crypto_config.h — bash-os PSA crypto-layer profile.
 *
 * Pairs with `_mbedtls/mbedtls_config.h`. The TLS layer (which is
 * compiled with `MBEDTLS_USE_PSA_CRYPTO`) routes every cipher/hash/
 * key-exchange call through the PSA dispatch layer; this file gates
 * which PSA algorithms get compiled in.
 *
 * Profile matches the bash-os primitive set already shipped under
 * `_mbedtls/`:
 *   Hashes:    SHA-256, SHA-384, SHA-512, SHA-1, MD5
 *   HMAC:      HMAC over each of the above
 *   AEAD:      AES-128/256-GCM, ChaCha20-Poly1305
 *   KDF:       HKDF (Extract/Expand) for TLS 1.3, TLS-1.2 PRF
 *   Asymmetric: ECDH (X25519, P-256, P-384), ECDSA sign/verify (P-256/384),
 *               RSA-PKCS1.5/PSS sign/verify
 *
 * ===================================================================
 * Replaced upstream's 2073-line / 82-PSA_WANT default with this tight
 * trim. The default was kitchen-sink — every PSA primitive on, including
 * dead-code paths the bash-os build will never reach (CCM, CFB, OFB,
 * XTS, JPAKE, FFDH, deterministic-ECDSA-with-keygen, RSA-OAEP,
 * RIPEMD-160, ARIA, Camellia, DES, etc.). Stripping these saves
 * substantial ROM in the static binary.
 * ===================================================================
 *
 * See: docs/STAGE-19B-MIGRATION-MAP.md §3.E.
 */

#ifndef PSA_CRYPTO_CONFIG_H
#define PSA_CRYPTO_CONFIG_H

/* ---------------------------------------------------------------------
 * Hash algorithms
 * ---------------------------------------------------------------------*/

#define PSA_WANT_ALG_SHA_256                 1
#define PSA_WANT_ALG_SHA_384                 1
#define PSA_WANT_ALG_SHA_512                 1
#define PSA_WANT_ALG_SHA_1                   1   /* legacy cert chains */
#define PSA_WANT_ALG_MD5                     1   /* legacy fingerprints only */
/* #define PSA_WANT_ALG_SHA_224              -- unused */
/* #define PSA_WANT_ALG_RIPEMD160            -- unused */
/* #define PSA_WANT_ALG_SHA3_256             -- unused */
/* #define PSA_WANT_ALG_SHA3_384             -- unused */
/* #define PSA_WANT_ALG_SHA3_512             -- unused */

/* ---------------------------------------------------------------------
 * MAC + KDFs
 * ---------------------------------------------------------------------*/

#define PSA_WANT_ALG_HMAC                    1
#define PSA_WANT_ALG_HKDF                    1
#define PSA_WANT_ALG_HKDF_EXTRACT            1
#define PSA_WANT_ALG_HKDF_EXPAND             1

/* TLS 1.2 master-secret derivation. Off: TLS 1.3 only.
 * If you re-enable MBEDTLS_SSL_PROTO_TLS1_2 in the main config, flip
 * this back ON. */
#define PSA_WANT_ALG_TLS12_PRF               1   /* on while TLS 1.2 stays in main config */

/* OFF — niche / unused. */
/* #define PSA_WANT_ALG_TLS12_PSK_TO_MS      */
/* #define PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS */
/* #define PSA_WANT_ALG_PBKDF2_HMAC          -- bashcrypto has Argon2id */
/* #define PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128 */
/* #define PSA_WANT_ALG_CMAC                 -- unused */

/* ---------------------------------------------------------------------
 * Symmetric ciphers — AEAD only
 * ---------------------------------------------------------------------*/

#define PSA_WANT_ALG_GCM                     1
#define PSA_WANT_ALG_CHACHA20_POLY1305       1

/* OFF — unused or legacy. */
/* #define PSA_WANT_ALG_CCM                  -- PSK suites only         */
/* #define PSA_WANT_ALG_CCM_STAR_NO_TAG      */
/* #define PSA_WANT_ALG_CBC_NO_PADDING       -- non-AEAD; insecure mode */
/* #define PSA_WANT_ALG_CBC_PKCS7            */
/* PSA_WANT_ALG_CTR: PERMANENT requirement of the minimal-dynamic link model
 * (packaging spec 19 foundation; not experimental). With PSA_WANT_KEY_TYPE_AES on
 * but no cipher alg, the generated PSA driver-wrapper references
 * mbedtls_psa_cipher_* that psa_crypto_cipher.c never defines. A fully-static
 * link GCs that dead wrapper; a minimal-dynamic (enable -f capable) bash
 * -rdynamic-exports it and the link fails on the undefined refs. CTR (not a
 * flagged-insecure mode) makes MBEDTLS_PSA_BUILTIN_CIPHER define the symbols and
 * resolves the inconsistency for BOTH link models, so it is kept on permanently. */
#define PSA_WANT_ALG_CTR                     1
/* #define PSA_WANT_ALG_CFB                  */
/* #define PSA_WANT_ALG_OFB                  */
/* #define PSA_WANT_ALG_XTS                  */
/* #define PSA_WANT_ALG_ECB_NO_PADDING       */
/* #define PSA_WANT_ALG_STREAM_CIPHER        */

/* ---------------------------------------------------------------------
 * Asymmetric — ECDH + ECDSA sign/verify + RSA sign/verify
 * ---------------------------------------------------------------------*/

#define PSA_WANT_ALG_ECDH                    1
#define PSA_WANT_ALG_ECDSA                   1
#define PSA_HAVE_ALG_ECDSA_VERIFY          1
#define PSA_HAVE_ALG_SOME_ECDSA            1
#define PSA_HAVE_ALG_ECDSA_SIGN            1
/* #define PSA_WANT_ALG_DETERMINISTIC_ECDSA  */

#define PSA_WANT_ALG_RSA_PKCS1V15_VERIFY     1
#define PSA_WANT_ALG_RSA_PKCS1V15_SIGN       1
/* #define PSA_WANT_ALG_RSA_PKCS1V15_CRYPT   */
#define PSA_WANT_ALG_RSA_PSS              1
/* #define PSA_WANT_ALG_RSA_OAEP             */

/* OFF — Diffie-Hellman classic. Modern servers all support ECDHE. */
/* #define PSA_WANT_ALG_FFDH                 */
/* #define PSA_WANT_ALG_JPAKE                */

/* ---------------------------------------------------------------------
 * Key types
 * ---------------------------------------------------------------------*/

#define PSA_WANT_KEY_TYPE_AES                1
#define PSA_WANT_KEY_TYPE_CHACHA20           1

#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY     1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC 1   /* ECDHE keypair gen */
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT 1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE 1
/* OFF — we don't import EC private keys from disk; ECDHE generates fresh. */
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE 1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT 1

#define PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY     1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC 1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT 1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE 1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT 1

#define PSA_WANT_KEY_TYPE_HMAC               1
#define PSA_WANT_KEY_TYPE_DERIVE             1   /* HKDF input keys */
#define PSA_WANT_KEY_TYPE_RAW_DATA           1   /* opaque buffers */

/* OFF — DES/ARIA/Camellia: all unused. */
/* #define PSA_WANT_KEY_TYPE_DES             */
/* #define PSA_WANT_KEY_TYPE_ARIA            */
/* #define PSA_WANT_KEY_TYPE_CAMELLIA        */

/* ---------------------------------------------------------------------
 * EC curves — modern internet TLS landscape
 *   secp256r1 (P-256)   — ECDHE-ECDSA default + most cert chains
 *   secp384r1 (P-384)   — Suite B-style high-assurance certs
 *   curve25519 (X25519) — TLS 1.3 favourite
 *
 * P-521 / X448: niche — keep OFF unless a specific peer requires.
 * Brainpool / K1 curves / deprecated SECP_R1_192/224: OFF.
 * ---------------------------------------------------------------------*/

#define PSA_WANT_ECC_SECP_R1_256             1
#define PSA_WANT_ECC_SECP_R1_384             1
#define PSA_WANT_ECC_MONTGOMERY_255          1   /* X25519 */
/* #define PSA_WANT_ECC_SECP_R1_521          -- niche */
/* #define PSA_WANT_ECC_MONTGOMERY_448       -- X448 (rare)        */
/* #define PSA_WANT_ECC_SECP_R1_192          -- deprecated         */
/* #define PSA_WANT_ECC_SECP_R1_224          -- deprecated         */
/* #define PSA_WANT_ECC_SECP_K1_192          -- niche               */
/* #define PSA_WANT_ECC_SECP_K1_224          */
/* #define PSA_WANT_ECC_SECP_K1_256          */
/* #define PSA_WANT_ECC_BRAINPOOL_P_R1_256   */
/* #define PSA_WANT_ECC_BRAINPOOL_P_R1_384   */
/* #define PSA_WANT_ECC_BRAINPOOL_P_R1_512   */

/* ---------------------------------------------------------------------
 * mbedTLS legacy compat — until PSA random is fully internal
 *
 * NOTE: these `MBEDTLS_*` defines historically lived in mbedtls_config.h
 * but were moved here in upstream's PSA reorganization. Keep them in
 * one place pinned to the crypto layer.
 * ---------------------------------------------------------------------*/

/* Built-in entropy source: /dev/urandom via the default Linux platform
 * adapter. Bash-os mounts devtmpfs at /dev so /dev/urandom is available
 * before any TLS handshake fires. */
#define MBEDTLS_PSA_BUILTIN_GET_ENTROPY
#define MBEDTLS_ENTROPY_HAVE_SOURCES
#define MBEDTLS_ENTROPY_TRUE_SOURCES 1
#define MBEDTLS_PSA_CRYPTO_RNG_STRENGTH 256
#define MBEDTLS_PSA_CRYPTO_RNG_HASH PSA_ALG_SHA_512
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_BASIC
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_IMPORT
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_GENERATE
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_DERIVE
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_EXPORT
#define MBEDTLS_PSA_BUILTIN_ALG_ECDSA
#define MBEDTLS_PSA_BUILTIN_ALG_ECDH
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_BASIC
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_IMPORT
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_GENERATE
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR_EXPORT
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_AES
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_CHACHA20
/* Builtin symmetric cipher (2026-06-09): this config lists MBEDTLS_PSA_BUILTIN_*
 * explicitly rather than auto-deriving from PSA_WANT_*. psa_crypto_cipher.c gates
 * mbedtls_psa_cipher_* (encrypt/decrypt_setup, set_iv, update, finish, abort) on
 * #if defined(MBEDTLS_PSA_BUILTIN_CIPHER); without it those symbols are undefined
 * yet still referenced by the generated PSA driver-wrappers, so a -rdynamic
 * (enable -f capable) bash fails to link. Define it + the CTR alg builtin to match
 * PSA_WANT_ALG_CTR above. */
#define MBEDTLS_PSA_BUILTIN_CIPHER
#define MBEDTLS_PSA_BUILTIN_ALG_CTR              1
#define MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_VERIFY
#define MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN
#define MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS
#define MBEDTLS_PSA_BUILTIN_ALG_SHA_1
#define MBEDTLS_PSA_BUILTIN_ALG_SHA_256
#define MBEDTLS_PSA_BUILTIN_ALG_SHA_384
#define MBEDTLS_PSA_BUILTIN_ALG_SHA_512
#define MBEDTLS_PSA_BUILTIN_ALG_HMAC
#define MBEDTLS_PSA_BUILTIN_ALG_HKDF
#define MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT
#define MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND
#define MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF
#define MBEDTLS_PSA_BUILTIN_ALG_GCM
#define MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305

#define MBEDTLS_CTR_DRBG_C               /* AES-CTR DRBG, faster than HMAC-DRBG */
#define MBEDTLS_ENTROPY_C
/* OFF — bash-os has no NV storage to seed from. The Linux platform
 * adapter reads /dev/urandom directly each handshake, which musl
 * routes via the getrandom(2) syscall when present. */
/* #define MBEDTLS_ENTROPY_NV_SEED */

/* ---------------------------------------------------------------------
 * ASN.1 / PK / cipher legacy core (called by the PSA layer transitively)
 * ---------------------------------------------------------------------*/

#define MBEDTLS_ASN1_PARSE_C
/* OFF — we never write ASN.1 (no cert/CSR creation). */
#define MBEDTLS_ASN1_WRITE_C

#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C               /* parse server cert pubkeys */
#define MBEDTLS_PK_WRITE_C

#define MBEDTLS_OID_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_GENPRIME
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_LIGHT
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15                /* matches PSA_WANT_ALG_RSA_PKCS1V15_VERIFY */
/* OFF — TLS 1.3 cert verify can use PSS, but rare on real cert chains.
 * Re-enable if a target peer's cert is PSS-signed. */
#define MBEDTLS_PKCS1_V21

#define MBEDTLS_GCM_C
#define MBEDTLS_CCM_GCM_CAN_AES
#define MBEDTLS_AES_C
#define MBEDTLS_BLOCK_CIPHER_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CMAC_C
#define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_CIPHER_MODE_WITH_PADDING
#define MBEDTLS_CIPHER_PADDING_PKCS7
#define MBEDTLS_CHACHAPOLY_C
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C

#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C                 /* required for SHA-384 PSA path */
#define MBEDTLS_SHA512_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_MD5_C
#define MBEDTLS_SHA3_C
#define MBEDTLS_SHA3_WANT_SHAKE256
#define MBEDTLS_HKDF_C

/* MD layer dispatch — needed for the legacy mbedtls_md_* surface that
 * X.509 cert-chain validation transitively touches. */
#define MBEDTLS_MD_C
#define MBEDTLS_MD_LIGHT

/* OFF — broken / unused / deprecated. */
/* #define MBEDTLS_MD2_C       -- broken               */
/* #define MBEDTLS_MD4_C       -- broken               */
/* #define MBEDTLS_RIPEMD160_C -- unused               */
/* #define MBEDTLS_SHA224_C    -- unused               */
/* #define MBEDTLS_ARIA_C      -- unused               */
/* #define MBEDTLS_CAMELLIA_C  -- unused               */
/* #define MBEDTLS_DES_C       -- broken               */
/* #define MBEDTLS_BLOWFISH_C  -- niche                */
/* #define MBEDTLS_DHM_C       -- FFDH; unused per profile */
/* #define MBEDTLS_NIST_KW_C   -- key wrap; unused     */
/* #define MBEDTLS_CCM_C       -- unused (PSK suites)  */

#endif /* PSA_CRYPTO_CONFIG_H */
