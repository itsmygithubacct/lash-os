#ifndef BASH_OS_LIBSSH_CONFIG_H
#define BASH_OS_LIBSSH_CONFIG_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#define HAVE_CONFIG_H 1
#define HAVE_STRTOULL 1
#define HAVE_SNPRINTF 1
#define HAVE_GETADDRINFO 1
#define HAVE_GAI_STRERROR 1
#define HAVE_NETDB_H 1
#define HAVE_SYS_SOCKET_H 1
#define HAVE_ARPA_INET_H 1
#define HAVE_NETINET_IN_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_TERMIOS_H 1
#define HAVE_UNISTD_H 1
#define HAVE_COMPILER__FUNC__ 1
#define HAVE_GCC_VOLATILE_MEMORY_PROTECTION 1
#define HAVE_LIBMBEDCRYPTO 1
#define HAVE_ECC 1
#define MBEDTLS_ALLOW_PRIVATE_ACCESS 1
#define WITH_SERVER 1
#define WITH_SFTP 1
#define WITH_GEX 1
#define GLOBAL_CONF_DIR "/etc/ssh"
#define GLOBAL_CLIENT_CONFIG "/etc/ssh/ssh_config"
#define GLOBAL_BIND_CONFIG "/etc/ssh/libssh_server_config"

#include <stddef.h>
void *memset(void *, int, size_t);
void *memcpy(void *, const void *, size_t);
int memcmp(const void *, const void *, size_t);
size_t strlen(const char *);
int strcmp(const char *, const char *);
int strncmp(const char *, const char *, size_t);
char *strchr(const char *, int);
char *strstr(const char *, const char *);
char *strdup(const char *);

#define LIBSSH_VERSION_MAJOR 0
#define LIBSSH_VERSION_MINOR 11
#define LIBSSH_VERSION_PATCH 2

#endif
