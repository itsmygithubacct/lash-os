/* SPDX-License-Identifier: MIT */
#ifndef BASHOS_AUTHCRYPTO_ARGON2ID_H
#define BASHOS_AUTHCRYPTO_ARGON2ID_H

#include <stddef.h>
#include <stdint.h>

int bashos_auth_argon2id_raw (const unsigned char *pass, size_t pass_len,
                              const unsigned char *salt, size_t salt_len,
                              uint32_t passes, uint32_t mem_kib,
                              uint32_t lanes, unsigned char *out,
                              size_t out_len, int quiet_mlock,
                              const char *warn_prefix);

#endif /* BASHOS_AUTHCRYPTO_ARGON2ID_H */
