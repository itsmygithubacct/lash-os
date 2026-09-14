/* SPDX-License-Identifier: MIT */
#ifndef BOS_PB_TRANSPORT_H
#define BOS_PB_TRANSPORT_H
#include "ptybroker.h"
#include <stdint.h>
#define PB_MAGIC 0x42505431u
enum { PB_STATUS=1, PB_RESIZE, PB_INPUT, PB_CAPTURE, PB_TERMINATE,
       PB_OPEN_CONTROL, PB_OPEN_OBSERVER, PB_REPLY=32 };
struct pb_packet {
    uint32_t magic, type, size, error;
    uint64_t offset;
    unsigned char data[PB_CHUNK];
};
#define PB_HEADER offsetof(struct pb_packet, data)
struct pb_ready { int32_t error; struct pb_status status; };
int pb_path(const char *, const char *, char *, size_t);
int pb_connect(const char *, const char *);
int64_t pb_now(void);
int pb_wait(int fd, short events, int64_t deadline);
int pb_packet_send(int fd, const struct pb_packet *, int64_t deadline);
int pb_packet_recv(int fd, struct pb_packet *, int64_t deadline);
int pb_fd_write(int fd, const void *, size_t, int64_t deadline);
#endif
