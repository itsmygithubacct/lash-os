/* SPDX-License-Identifier: MIT */
/* zcat.c — POSIX zcat(1) wrapper using libz directly.
 *
 *   zcat [FILE...]
 *
 * Decompresses gzip-format input from FILE(s) (or stdin) to stdout.
 * libz is already linked into bash-os via zlib's EXTRA_LIBS. Use its
 * streaming inflater to retain output produced before an integrity error.
 * POSIX shape — no extension sniffing, gzip-only. For xz/zstd use
 * `zlib -d -f xz` directly.
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <zlib.h>

#include "loadables.h"

enum bz_result { BZ_OK, BZ_INPUT_ERROR, BZ_FATAL_ERROR };

static int
bz_write_all (const unsigned char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write (STDOUT_FILENO, buf, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        buf += n;
        len -= (size_t) n;
    }
    return 0;
}

/* Retain unread bytes when a gzip magic number spans two reads. */
static ssize_t
bz_read_more (int fd, z_stream *s, unsigned char *buf, size_t size)
{
    ssize_t n;
    if (s->avail_in)
        memmove (buf, s->next_in, s->avail_in);
    s->next_in = buf;
    do {
        n = read (fd, buf + s->avail_in, size - s->avail_in);
    } while (n < 0 && errno == EINTR);
    if (n > 0) s->avail_in += (uInt) n;
    return n;
}

static enum bz_result
bz_pump (int fd, const char *name)
{
    z_stream s;
    unsigned char inbuf[8192], outbuf[8192];
    int at_header = 1, seen_member = 0, eof = 0;
    enum bz_result result = BZ_FATAL_ERROR;

    memset (&s, 0, sizeof s);
    /* Accept gzip only, without zlib autodetection or transparent copying. */
    int ret = inflateInit2 (&s, MAX_WBITS + 16);
    if (ret != Z_OK) {
        builtin_error ("%s: %s", name, zError (ret));
        return BZ_FATAL_ERROR;
    }

    for (;;) {
        if (at_header) {
            while (s.avail_in < 2 && !eof) {
                ssize_t n = bz_read_more (fd, &s, inbuf, sizeof inbuf);
                if (n < 0) goto read_error;
                if (n == 0) eof = 1;
            }
            if (s.avail_in < 2) {
                if (seen_member) result = BZ_OK;
                else builtin_error ("%s: unexpected end of file", name);
                break;
            }
            if (s.next_in[0] != 0x1f || s.next_in[1] != 0x8b) {
                if (!seen_member) {
                    builtin_error ("%s: not in gzip format", name);
                    result = BZ_INPUT_ERROR;
                    break;
                }
                /* Preserve gzread's treatment of trailing non-member data.
                 * Consume it so another '-' starts at the same stdin EOF. */
                while (!eof) {
                    s.avail_in = 0;
                    ssize_t n = bz_read_more (fd, &s, inbuf, sizeof inbuf);
                    if (n < 0) goto read_error;
                    if (n == 0) eof = 1;
                }
                result = BZ_OK;
                break;
            }
            if (seen_member) {
                /* inflateReset retains next_in and avail_in. */
                ret = inflateReset (&s);
                if (ret != Z_OK) {
                    builtin_error ("%s: %s", name, zError (ret));
                    break;
                }
            }
            at_header = 0;
        }

        if (s.avail_in == 0 && !eof) {
            ssize_t n = bz_read_more (fd, &s, inbuf, sizeof inbuf);
            if (n < 0) goto read_error;
            if (n == 0) eof = 1;
        }
        uInt available = s.avail_in;
        s.next_out = outbuf;
        s.avail_out = sizeof outbuf;
        ret = inflate (&s, Z_NO_FLUSH);
        size_t produced = sizeof outbuf - s.avail_out;

        /* Even Z_DATA_ERROR can accompany decoded bytes. Write those bytes
         * before diagnosing a CRC or length failure, just as gzip does. */
        if (bz_write_all (outbuf, produced) < 0) {
            builtin_error ("write: %s", strerror (errno));
            break;
        }
        if (ret == Z_STREAM_END) {
            seen_member = 1;
            at_header = 1;
            continue;
        }
        if (ret != Z_OK && ret != Z_BUF_ERROR) {
            builtin_error ("%s: %s", name, s.msg ? s.msg : zError (ret));
            break;
        }
        if (produced == 0 && s.avail_in == available) {
            builtin_error ("%s: %s", name,
                           eof ? "unexpected end of file" : "invalid gzip stream");
            break;
        }
    }

done:
    inflateEnd (&s);
    return result;

read_error:
    builtin_error ("%s: %s", name, strerror (errno));
    goto done;
}

int
zcat_builtin (WORD_LIST *list)
{
    if (!list)
        return bz_pump (STDIN_FILENO, "stdin") == BZ_OK
               ? EXECUTION_SUCCESS : EXECUTION_FAILURE;

    int rc = EXECUTION_SUCCESS;
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *path = p->word->word;
        int is_stdin = !strcmp (path, "-");
        int fd = is_stdin ? STDIN_FILENO : open (path, O_RDONLY);
        if (fd < 0) {
            builtin_error ("%s: %s", path, strerror (errno));
            rc = EXECUTION_FAILURE;
            continue;
        }
        enum bz_result result = bz_pump (fd, is_stdin ? "stdin" : path);
        if (!is_stdin) close (fd);
        if (result != BZ_OK) {
            rc = EXECUTION_FAILURE;
            /* Missing/non-gzip named inputs are recoverable. Integrity and
             * stdin failures stop this invocation, without exiting Bash. */
            if (result == BZ_FATAL_ERROR || is_stdin) break;
        }
    }
    return rc;
}

char *zcat_doc[] = {
    "Decompress gzip files to stdout (POSIX zcat).",
    "",
    "    zcat [FILE...]",
    "",
    "Reads each FILE (or stdin if none given, or `-` in the list) as",
    "gzip-format and writes the decompressed bytes to stdout. For xz,",
    "zstd, or zlib formats use `zlib -d -f FORMAT` directly.",
    (char *)NULL
};

struct builtin zcat_struct = {
    "zcat",
    zcat_builtin,
    BUILTIN_ENABLED,
    zcat_doc,
    "zcat [FILE...]",
    0
};
