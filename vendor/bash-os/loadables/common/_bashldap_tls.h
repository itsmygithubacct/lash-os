/* SPDX-License-Identifier: MIT */
#ifndef BASHLDAP_TLS_H
#define BASHLDAP_TLS_H

#include "_mbedtls_ssl.h"
#include "_mbedtls_x509_crt.h"

int bc_tls_handshake (int sock, const char *sni, const char *ca_path,
                      int insecure, mbedtls_ssl_context *ssl,
                      mbedtls_ssl_config *conf, mbedtls_x509_crt *ca);

#endif /* BASHLDAP_TLS_H */
