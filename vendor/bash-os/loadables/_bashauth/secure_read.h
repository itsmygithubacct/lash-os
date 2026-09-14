/* SPDX-License-Identifier: MIT */
#ifndef BASHAUTH_SECURE_READ_H
#define BASHAUTH_SECURE_READ_H

#include <stddef.h>

#define BASHOS_AUTH_PASSWORD_MAX 4096

int bashos_secure_read_password (const char *prompt, unsigned char **out,
                                 size_t *out_len);
void bashos_secure_free_password (unsigned char *buf);

#endif /* BASHAUTH_SECURE_READ_H */
