/* SPDX-License-Identifier: MIT */
/* Bounded gzip streams shared by gzip and tar. No external compressor. */
#ifndef BASHOS_GZIP_STREAM_H
#define BASHOS_GZIP_STREAM_H
#include <zlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

static int bgz_write(int fd, const unsigned char *p, size_t len)
{
    if (fd < 0) return 0; /* gzip -t */
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (!n) errno = EIO; builtin_error("write: %s", strerror(errno)); return 1; }
        p += n; len -= (size_t)n;
    }
    return 0;
}

static int bgz_encode(int in, int out, int level, const char *name, unsigned long mtime)
{
    z_stream z = {0};
    if (deflateInit2(&z, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        builtin_error("cannot initialize gzip compressor"); return 1;
    }
    gz_header header = {0};
    header.os = 3; header.time = mtime; header.name = (Bytef *)name;
    deflateSetHeader(&z, &header);
    unsigned char src[32768], dst[32768];
    int rc = 0, done = 0;
    while (!done) {
        ssize_t n = read(in, src, sizeof src);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { builtin_error("read: %s", strerror(errno)); rc = 1; break; }
        z.next_in = src; z.avail_in = (uInt)n;
        int flush = n ? Z_NO_FLUSH : Z_FINISH, status;
        do {
            z.next_out = dst; z.avail_out = sizeof dst;
            status = deflate(&z, flush);
            if (status != Z_OK && status != Z_STREAM_END) { rc = 1; break; }
            if (bgz_write(out, dst, sizeof dst - z.avail_out)) { rc = 1; break; }
        } while (z.avail_in || !z.avail_out || (!n && status != Z_STREAM_END));
        if (rc) break;
        done = !n;
    }
    deflateEnd(&z);
    return rc;
}

static int bgz_decode(int in, int out, unsigned long *mtime)
{
    z_stream z = {0};
    if (inflateInit2(&z, 15 + 16) != Z_OK) {
        builtin_error("cannot initialize gzip decompressor"); return 1;
    }
    unsigned char src[32768], dst[32768];
    gz_header header = {0};
    inflateGetHeader(&z, &header);
    int rc = 0, ended = 0, first = 1;
    for (;;) {
        if (!z.avail_in) {
            ssize_t n = read(in, src, sizeof src);
            if (n < 0 && errno == EINTR) continue;
            if (n < 0) { builtin_error("read: %s", strerror(errno)); rc = 1; break; }
            if (!n) {
                if (!ended) { builtin_error("unexpected end of gzip input"); rc = 1; }
                break;
            }
            z.next_in = src; z.avail_in = (uInt)n;
        }
        if (ended) {
            /* Concatenated gzip members are a single decompressed stream. */
            Bytef *next = z.next_in; uInt remaining = z.avail_in;
            inflateReset(&z);
            z.next_in = next; z.avail_in = remaining;
            ended = 0;
        }
        z.next_out = dst; z.avail_out = sizeof dst;
        int status = inflate(&z, Z_NO_FLUSH);
        if (first && header.done) { if (mtime) *mtime = header.time; first = 0; }
        if (bgz_write(out, dst, sizeof dst - z.avail_out)) { rc = 1; break; }
        if (status == Z_STREAM_END) ended = 1;
        else if (status != Z_OK && status != Z_BUF_ERROR) {
            builtin_error("invalid gzip data: %s", z.msg ? z.msg : "decompression failed"); rc = 1; break;
        }
        else if (status == Z_BUF_ERROR && z.avail_in) {
            builtin_error("invalid gzip data"); rc = 1; break;
        }
    }
    inflateEnd(&z);
    return rc;
}
#endif
