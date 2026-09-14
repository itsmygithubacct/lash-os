/* _mbedtls/build_info.h — minimal version metadata (Stage 19.A.4).
 *
 * Upstream's vendor/mbedtls/include/mbedtls/build_info.h chains into
 * mbedtls_config.h + config_adjust_x509.h + config_adjust_ssl.h +
 * the rest of the TLS feature web. For 19.A.4 we hardcode just the
 * version macros + force MBEDTLS_VERSION_C so upstream version.c
 * compiles standalone. Stage 19.B replaces this with the upstream
 * tree once the full mbedTLS subset is vendored.
 *
 * Mirror of vendor/mbedtls/include/mbedtls/build_info.h:42-50.
 */
#ifndef MBEDTLS_BUILD_INFO_H
#define MBEDTLS_BUILD_INFO_H

#define MBEDTLS_VERSION_MAJOR  4
#define MBEDTLS_VERSION_MINOR  1
#define MBEDTLS_VERSION_PATCH  0
#define MBEDTLS_VERSION_NUMBER         0x04010000
#define MBEDTLS_VERSION_STRING         "4.1.0"
#define MBEDTLS_VERSION_STRING_FULL    "Mbed TLS 4.1.0"

#define MBEDTLS_VERSION_C

#include "mbedtls_config.h"
#include "crypto_config.h"
#if defined(TF_PSA_CRYPTO_INCLUDE_AFTER_RAW_CONFIG)
#include TF_PSA_CRYPTO_INCLUDE_AFTER_RAW_CONFIG
#endif

#endif /* MBEDTLS_BUILD_INFO_H */
