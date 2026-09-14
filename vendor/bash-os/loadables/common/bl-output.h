/* SPDX-License-Identifier: MIT */
/* Per-invocation output buffering without changing Bash's stdout buffering. */
#ifndef BASH_OS_BL_OUTPUT_H
#define BASH_OS_BL_OUTPUT_H
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    int fd, error, terminal;
    size_t used;
    unsigned char data[65536];
} bl_output;

static void
bl_output_init (bl_output *out, FILE *stream)
{
    out->fd = fileno (stream);
    out->terminal = isatty (out->fd);
    out->used = 0;
    out->error = fflush (stream) == EOF ? (errno ? errno : EIO) : 0;
}

static void
bl_output_flush (bl_output *out)
{
    size_t offset = 0;
    while (!out->error && offset < out->used) {
        ssize_t n = write (out->fd, out->data + offset, out->used - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { out->error = n < 0 ? errno : EIO; break; }
        offset += (size_t) n;
    }
    out->used = 0;
}

static void
bl_output_write (bl_output *out, const void *bytes, size_t length)
{
    const unsigned char *data = bytes;
    while (length && !out->error) {
        size_t n = sizeof out->data - out->used;
        if (n > length) n = length;
        memcpy (out->data + out->used, data, n);
        out->used += n;
        int newline = out->terminal && memchr (data, '\n', n) != NULL;
        data += n; length -= n;
        if (out->used == sizeof out->data || newline) bl_output_flush (out);
    }
}

static void
bl_output_byte (bl_output *out, unsigned char byte)
{
    bl_output_write (out, &byte, 1);
}
#endif
