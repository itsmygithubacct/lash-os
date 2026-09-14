#ifndef _LIBSSH_VERSION_H
#define _LIBSSH_VERSION_H

#define SSH_VERSION_INT(a, b, c) ((a) << 16 | (b) << 8 | (c))
#define SSH_VERSION_DOT(a, b, c) a ##.## b ##.## c
#define SSH_VERSION(a, b, c) SSH_VERSION_DOT(a, b, c)

#define LIBSSH_VERSION_MAJOR 0
#define LIBSSH_VERSION_MINOR 11
#define LIBSSH_VERSION_MICRO 2
#define LIBSSH_VERSION_PATCH 2

#define LIBSSH_VERSION_INT SSH_VERSION_INT(LIBSSH_VERSION_MAJOR, \
                                           LIBSSH_VERSION_MINOR, \
                                           LIBSSH_VERSION_MICRO)
#define LIBSSH_VERSION SSH_VERSION(LIBSSH_VERSION_MAJOR, \
                                   LIBSSH_VERSION_MINOR, \
                                   LIBSSH_VERSION_MICRO)

#endif
