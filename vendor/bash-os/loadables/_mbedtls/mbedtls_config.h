/* _mbedtls/mbedtls_config.h — bash-os TLS-client production profile.
 *
 * Stage 19.B feature gates for the static-musl, RAM-only, single-process
 * bash-os runtime. Picked up by every `#include "build_info.h"`
 * (which the flatten machinery rewrites to `_mbedtls_build_info.h`).
 *
 * Pairs with `_mbedtls/crypto_config.h` (PSA layer).
 *
 * Profile:
 *   - TLS 1.2 + TLS 1.3 client and small server endpoint (no DTLS)
 *   - Cipher suites driven by `crypto_config.h` (AES-GCM + ChaCha20-Poly1305)
 *   - X.509 read-only (no CRL, no CSR, no certificate writing)
 *   - Cert-chain validation against pinned PEM or system CA bundle
 *   - PSA crypto path (MBEDTLS_USE_PSA_CRYPTO) — TLS calls PSA, not legacy
 *     mbedtls_md_/mbedtls_cipher_/mbedtls_pk_ dispatchers
 *
 * ===================================================================
 * Static-musl trim — what's intentionally OFF and why
 * ===================================================================
 *   THREADING_C, *_PTHREAD          — enabled for libssh's mbedTLS backend;
 *                                    bash-os itself remains single-threaded
 *   NET_C, FS_IO, TIMING_C          — bash-os has bashpoll/bashio for
 *                                    sockets and files; mbedtls_ssl_set_bio
 *                                    bridges read/write callbacks to
 *                                    bash-side fds; cert bytes arrive via
 *                                    bashcrypto's argv/buffer path
 *   PLATFORM_MEMORY                 — use musl's malloc directly, no
 *                                    indirection, no calloc shim
 *   PLATFORM_NO_STD_FUNCTIONS       — keep the stdlib path; musl provides
 *                                    snprintf/memcpy/etc. as expected
 *   *_SELF_TEST                     — strips test code (~30 KB ROM win)
 *   DEPRECATED_REMOVED              — strips ABI surface that's gated as
 *                                    deprecated upstream (~5 KB ROM win;
 *                                    nothing in bashcrypto.c calls the
 *                                    deprecated APIs)
 *   ENTROPY_NV_SEED                 — bash-os doesn't have persistent
 *                                    storage; entropy comes from
 *                                    /dev/urandom each boot via the
 *                                    default platform path
 *   PSA_CRYPTO_STORAGE_C, PSA_ITS_  — RAM-only; no key persistence
 *
 * ===================================================================
 * Replaced upstream's 1189-line default config with this ~175-line
 * trim. Original (49 active defines) was the full kitchen-sink:
 * DTLS, PSK, RSA-key-exchange, renegotiation, session
 * tickets, cookies, NET_C, FS_IO, TIMING_C, X509_WRITE_C, CRL_PARSE_C,
 * CSR paths, debug strings — ~1.2 MB of ROM in the static binary that
 * bash-os doesn't use.
 *
 * If the binary needs further trimming after the first build measures
 * ROM impact:
 *   - Drop `MBEDTLS_PEM_PARSE_C`         (force DER-only inputs)
 *   - Drop `MBEDTLS_AES_ROM_TABLES`      (~8 KB ROM, ~2x slower AES soft path)
 *   - Drop `MBEDTLS_ECP_NIST_OPTIM`      (~5 KB ROM, slower P-256 verify)
 *   - Drop `MBEDTLS_SSL_KEEP_PEER_CERTIFICATE` (no cert inspection post-handshake)
 * ===================================================================
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

#define MBEDTLS_CIPHER_MODE_WITH_PADDING
#define MBEDTLS_CIPHER_PADDING_PKCS7

/* Required upstream version-compat marker. */
#define MBEDTLS_CONFIG_VERSION 0x04000000

/* ---------------------------------------------------------------------
 * System support
 * ---------------------------------------------------------------------*/

#define MBEDTLS_HAVE_ASM                 /* musl + gcc support inline asm */
#define MBEDTLS_HAVE_TIME                /* musl: time(2)         */
#define MBEDTLS_HAVE_TIME_DATE           /* musl: gmtime_r(3) — cert validity */

/* libssh's mbedTLS backend expects threading hooks to exist even when the
 * bash-os caller is single-threaded. */
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_PTHREAD
/* #define MBEDTLS_NET_C             */
#define MBEDTLS_FS_IO
/* #define MBEDTLS_TIMING_C          */
/* #define MBEDTLS_PLATFORM_MEMORY   */
/* #define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS */

/* Strip the deprecated-API surface entirely. */
#define MBEDTLS_DEPRECATED_REMOVED

/* No selftests baked into the binary — bash-os uses its own RFC/NIST
 * vector TAP tests (`tests/bash-os/138-148-stage19b-*`) for coverage. */
/* #define MBEDTLS_SELF_TEST */

/* ---------------------------------------------------------------------
 * TLS protocol surface — client + small static server endpoint
 * ---------------------------------------------------------------------*/

#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_HAVE_AEAD
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_PROTO_TLS1_3

/* TLS 1.3 specifics. */
/* #define MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
/* OFF — bash-os has no PSK persistence across boots. */
/* #define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED          */
/* #define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED */

/* TLS 1.2 key exchanges. (TLS 1.3 cipher suites are fixed.) */
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
/* OFF — modern internet servers all support ECDHE; DHE-RSA is rarely
 * needed and adds avoidable FFDH big-int cost in the small guest. */
/* #define MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED */
/* OFF — non-PFS RSA key transport is deprecated; rare to require. */
/* #define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED */

/* Server-side TLS is enabled for bashhttpd `-c CERT -k KEY`.
 * DTLS / PSK / renegotiation / ECJPAKE remain OFF. */
#define MBEDTLS_SSL_SRV_C
/* #define MBEDTLS_SSL_PROTO_DTLS                  */
/* #define MBEDTLS_SSL_DTLS_ANTI_REPLAY            */
/* #define MBEDTLS_SSL_DTLS_HELLO_VERIFY           */
/* #define MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE      */
/* #define MBEDTLS_SSL_DTLS_CONNECTION_ID          */
/* #define MBEDTLS_KEY_EXCHANGE_PSK_ENABLED        */
/* #define MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED  */
/* #define MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED    */
/* #define MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED    */
/* #define MBEDTLS_SSL_RENEGOTIATION               */
/* #define MBEDTLS_SSL_COOKIE_C                    */
/* #define MBEDTLS_SSL_TICKET_C                    */
/* #define MBEDTLS_SSL_CACHE_C                     */
/* #define MBEDTLS_SSL_SESSION_TICKETS             */
/* #define MBEDTLS_SSL_CONTEXT_SERIALIZATION       */

/* TLS extensions we want. */
#define MBEDTLS_SSL_SERVER_NAME_INDICATION
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE   /* keep cert chain for callers */
#define MBEDTLS_SSL_EXTENDED_MASTER_SECRET  /* RFC 7627; mandatory in modern TLS 1.2 */
#define MBEDTLS_SSL_ALPN                    /* DoH HTTPS can negotiate h2/http/1.1 */
/* OFF — niche extensions. */
/* #define MBEDTLS_SSL_ENCRYPT_THEN_MAC  */
/* #define MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */
#define MBEDTLS_SSL_KEYING_MATERIAL_EXPORT
/* #define MBEDTLS_SSL_ALL_ALERT_MESSAGES */

/* TLS record buffers — 16 KB matches the spec maximum. Trim to 8192
 * if RAM gets tight. */
#define MBEDTLS_SSL_IN_CONTENT_LEN              16384
#define MBEDTLS_SSL_OUT_CONTENT_LEN             16384

/* ---------------------------------------------------------------------
 * X.509 — read-only cert chain validation
 * ---------------------------------------------------------------------*/

#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_PEM_PARSE_C              /* CA bundles ship as PEM */
#define MBEDTLS_BASE64_C                 /* PEM transitively needs this */

/* OFF — no CRL, no CSR, no cert writing. */
/* #define MBEDTLS_X509_CRL_PARSE_C  */
/* #define MBEDTLS_X509_CSR_PARSE_C  */
/* #define MBEDTLS_X509_CREATE_C     */
/* #define MBEDTLS_X509_CRT_WRITE_C  */
/* #define MBEDTLS_X509_CSR_WRITE_C  */
/* #define MBEDTLS_X509_RSASSA_PSS_SUPPORT  -- RSA-PSS rare on certs */
/* #define MBEDTLS_PKCS7_C */

/* ---------------------------------------------------------------------
 * PSA crypto layer (mbedTLS 4.x routes TLS through PSA)
 * ---------------------------------------------------------------------*/

#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_PSA_CRYPTO_CLIENT
#define MBEDTLS_USE_PSA_CRYPTO
#define MBEDTLS_PSA_CRYPTO_CONFIG        /* honour `crypto_config.h` */

/* OFF — RAM-only, no key persistence, no SE. */
/* #define MBEDTLS_PSA_CRYPTO_STORAGE_C */
/* #define MBEDTLS_PSA_ITS_FILE_C       */
/* #define MBEDTLS_PSA_CRYPTO_SE_C      */

/* ---------------------------------------------------------------------
 * Diagnostics — minimal in production
 * ---------------------------------------------------------------------*/

/* Stub mbedtls_strerror() to "" — saves ~30 KB of error-string tables. */
#define MBEDTLS_ERROR_STRERROR_DUMMY

/* OFF — flip ON during migration bring-up; OFF before any cutover. */
/* #define MBEDTLS_DEBUG_C  */
/* #define MBEDTLS_ERROR_C  */
/* #define MBEDTLS_VERSION_FEATURES */

#define MBEDTLS_VERSION_C                /* `bashcrypto mbedtls-version` */

/* ---------------------------------------------------------------------
 * Performance / size knobs
 * ---------------------------------------------------------------------*/

#define MBEDTLS_AES_ROM_TABLES           /* +8 KB ROM, ~2x faster AES */
#define MBEDTLS_ECP_NIST_OPTIM           /* speed win on P-256/384/521 */
#define MBEDTLS_MPI_MAX_SIZE     1024    /* 8192-bit RSA cap; covers all CAs */
#define MBEDTLS_ECP_WINDOW_SIZE  4       /* 2..6; speed/RAM trade */
#define MBEDTLS_ECP_FIXED_POINT_OPTIM 1  /* +3 KB ROM, ~2x faster ECDSA verify */

/* OFF — single-shot TLS handshake doesn't need restartable ECC. */
/* #define MBEDTLS_ECP_RESTARTABLE */

/* ---------------------------------------------------------------------
 * Sanity gate
 * ---------------------------------------------------------------------*/

/* Every TLS protocol switch above must have its corresponding PSA
 * algorithm enabled in `crypto_config.h`. Cross-config consistency
 * (e.g. `MBEDTLS_SSL_PROTO_TLS1_3` requires `PSA_WANT_ALG_TLS13_HKDF`)
 * is checked by the migration session's bring-up audit, not statically
 * here. */

#endif /* MBEDTLS_CONFIG_H */
