/* _mbedtls/version.h — flattened public version API (Stage 19.A.4).
 *
 * Stripped from upstream vendor/mbedtls/include/mbedtls/version.h.
 * Drops mbedtls_version_check_feature (lives in version_features.c
 * upstream which we are NOT vendoring at Stage 19.A — pulls in the
 * full TLS feature checker).
 */
#ifndef MBEDTLS_VERSION_H
#define MBEDTLS_VERSION_H

#include "build_info.h"

#if defined(MBEDTLS_VERSION_C)

unsigned int mbedtls_version_get_number(void);
const char  *mbedtls_version_get_string(void);
const char  *mbedtls_version_get_string_full(void);

#endif /* MBEDTLS_VERSION_C */

#endif /* MBEDTLS_VERSION_H */
