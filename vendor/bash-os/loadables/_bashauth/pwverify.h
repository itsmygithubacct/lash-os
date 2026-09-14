/* SPDX-License-Identifier: MIT */
#ifndef BASHAUTH_PWVERIFY_H
#define BASHAUTH_PWVERIFY_H

#include <stddef.h>

int bashos_verify_phc_secret (const unsigned char *pw, size_t pw_len,
                              const char *phc);

#endif /* BASHAUTH_PWVERIFY_H */
