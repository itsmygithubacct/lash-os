/* Private host/guest console protocol. Both endpoints are little-endian x86_64. */
#ifndef LASH_SANDBOX_PROTOCOL_H
#define LASH_SANDBOX_PROTOCOL_H
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum { SB_INPUT = 1, SB_OUTPUT, SB_ERROR, SB_EOF, SB_EXIT, SB_WINDOW, SB_READY };
#define SB_CHUNK 8192
#define SB_QUEUE (128 * 1024)
#define SB_CONFIG_MAGIC 0x3148534cU
struct sb_config {
    uint32_t magic, argc, terminal, network;
    uint16_t rows, cols;
    char term[64];
};
struct sb_queue {
    size_t start, end;
    unsigned char data[SB_QUEUE];
};
static size_t sb_size(const struct sb_queue *q) {
    return q->end - q->start;
}
static size_t sb_room(const struct sb_queue *q) {
    return SB_QUEUE - sb_size(q);
}
static void sb_consume(struct sb_queue *q, size_t n) {
    q->start += n;
    if (q->start == q->end)
        q->start = q->end = 0;
}
static int sb_append(struct sb_queue *q, const void *data, size_t size) {
    if (sb_room(q) < size) {
        errno = ENOBUFS;
        return -1;
    }
    if (SB_QUEUE - q->end < size) {
        memmove(q->data, q->data + q->start, sb_size(q));
        q->end -= q->start;
        q->start = 0;
    }
    if (size)
        memcpy(q->data + q->end, data, size);
    q->end += size;
    return 0;
}
static int sb_packet(struct sb_queue *q, uint32_t type, const void *data, uint32_t size) {
    uint32_t header[2] = {type, size};
    if (size > SB_CHUNK || sb_room(q) < sizeof(header) + size) {
        errno = ENOBUFS;
        return -1;
    }
    sb_append(q, header, sizeof(header));
    return sb_append(q, data, size);
}
/* Returns 1 for a complete frame, 0 for incomplete, -1 for invalid framing. */
static int sb_peek(struct sb_queue *q, uint32_t *type, uint32_t *size, void **data) {
    if (sb_size(q) < 8)
        return 0;
    memcpy(type, q->data + q->start, 4);
    memcpy(size, q->data + q->start + 4, 4);
    if (*size > SB_CHUNK) {
        errno = EPROTO;
        return -1;
    }
    if (sb_size(q) < 8 + *size)
        return 0;
    *data = q->data + q->start + 8;
    return 1;
}
static int sb_receive(int fd, struct sb_queue *q) {
    unsigned char data[SB_CHUNK];
    size_t room = sb_room(q);
    if (!room)
        return 1;
    ssize_t n = read(fd, data, room < sizeof(data) ? room : sizeof(data));
    if (n > 0)
        return sb_append(q, data, n) ? -1 : 1;
    if (n < 0 && (errno == EAGAIN || errno == EINTR))
        return 1;
    return (int)n;
}
static int sb_flush(int fd, struct sb_queue *q) {
    if (!sb_size(q))
        return 0;
    ssize_t n = write(fd, q->data + q->start, sb_size(q));
    if (n > 0) {
        sb_consume(q, n);
        return 0;
    }
    if (n < 0 && (errno == EAGAIN || errno == EINTR))
        return 0;
    return -1;
}
static int sb_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL);
    return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
static inline int sb_write_all(int fd, const void *buffer, size_t size) {
    const unsigned char *p = buffer;
    while (size) {
        ssize_t n = write(fd, p, size);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        p += n;
        size -= n;
    }
    return 0;
}
#endif
