/* SPDX-License-Identifier: MIT */
#ifndef BASHOS_BASHCRYPTO_AEAD_H
#define BASHOS_BASHCRYPTO_AEAD_H

#include <stddef.h>

struct bc_aead_iov {
  const unsigned char *ptr;
  size_t len;
};

#define BC_NTS_MAX_COOKIES 8

struct bc_nts_ke_result {
  char *ntp_host;
  int ntp_port;
  unsigned short aead_id;
  unsigned char c2s[32];
  unsigned char s2c[32];
  unsigned char *cookies[BC_NTS_MAX_COOKIES];
  size_t cookie_lens[BC_NTS_MAX_COOKIES];
  size_t cookie_count;
};

int bc_aes_siv_cmac_seal(const unsigned char key[32],
                         const struct bc_aead_iov *ad, size_t ad_count,
                         const unsigned char *pt, size_t pt_len,
                         unsigned char **out, size_t *out_len);

int bc_aes_siv_cmac_open(const unsigned char key[32],
                         const struct bc_aead_iov *ad, size_t ad_count,
                         const unsigned char *in, size_t in_len,
                         unsigned char **pt, size_t *pt_len);

int bc_nts_ke_run(const char *host_port,
                  const char *ca_path,
                  const char *sni,
                  int timeout_ms,
                  struct bc_nts_ke_result *out);

void bc_nts_ke_result_free(struct bc_nts_ke_result *r);

#endif
