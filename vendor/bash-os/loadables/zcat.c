/* SPDX-License-Identifier: MIT */
/* zcat.c — POSIX zcat(1) wrapper using libz directly.
 *
 *   zcat [FILE...]
 *
 * Decompresses gzip-format input from FILE(s) (or stdin) to stdout.
 * libz is already linked into bash-os via zlib's EXTRA_LIBS, so
 * this is a thin gzopen/gzread wrapper. POSIX shape — no extension
 * sniffing, gzip-only. For xz/zstd use `zlib -d -f xz` directly.
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <zlib.h>

#include "loadables.h"

#define BZ_GZIP_MIN_HEADER 10

static int
bz_pump (gzFile gf)
{
    char buf[8192];
    int n;
    while ((n = gzread (gf, buf, sizeof buf)) > 0) {
        char *p = buf; size_t left = (size_t) n;
        while (left > 0) {
            ssize_t w = write (STDOUT_FILENO, p, left);
            if (w < 0) {
                if (errno == EINTR) continue;
                builtin_error ("write: %s", strerror (errno));
                return -1;
            }
            p += w; left -= (size_t) w;
        }
    }
    if (n < 0) {
        int err;
        const char *msg = gzerror (gf, &err);
        builtin_error ("gzread: %s", msg);
        return -1;
    }
    /* gzread returned 0 — either real EOF or zlib gave up early on a
     * truncated stream. Distinguish via gzerror(): a clean termination
     * leaves err == Z_OK / Z_STREAM_END; a truncated header or mid-
     * stream cut leaves Z_BUF_ERROR / Z_DATA_ERROR / etc. Surface that
     * as a non-zero rc so 267-zcat-stdin.sh case 6 (8-byte truncated
     * header) is rejected instead of silently returning success. */
    {
        int err = Z_OK;
        const char *msg = gzerror (gf, &err);
        if (err != Z_OK && err != Z_STREAM_END) {
            builtin_error ("gzread: %s", msg && *msg ? msg : "truncated stream");
            return -1;
        }
        if (!gzeof (gf)) {
            builtin_error ("gzread: stream ended before end-of-file marker");
            return -1;
        }
    }
    return 0;
}

static int
bz_write_all_fd (int fd, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write (fd, buf, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        buf += n;
        len -= (size_t) n;
    }
    return 0;
}

static int
bz_magic_ok (const unsigned char *buf, size_t n)
{
    return n >= 2 && buf[0] == 0x1f && buf[1] == 0x8b;
}

static gzFile
bz_gzopen_checked_path (const char *path)
{
    int fd = open (path, O_RDONLY);
    if (fd < 0) {
        builtin_error ("%s: %s", path, strerror (errno));
        return NULL;
    }

    unsigned char hdr[BZ_GZIP_MIN_HEADER];
    ssize_t n = read (fd, hdr, sizeof hdr);
    if (n < 0) {
        builtin_error ("%s: %s", path, strerror (errno));
        close (fd);
        return NULL;
    }
    if (!bz_magic_ok (hdr, (size_t) n) || n < BZ_GZIP_MIN_HEADER) {
        builtin_error ("%s: not in gzip format", path);
        close (fd);
        return NULL;
    }
    if (lseek (fd, 0, SEEK_SET) < 0) {
        builtin_error ("%s: %s", path, strerror (errno));
        close (fd);
        return NULL;
    }

    gzFile gf = gzdopen (fd, "rb");
    if (!gf) {
        builtin_error ("%s: %s", path, strerror (errno));
        close (fd);
    }
    return gf;
}

static gzFile
bz_gzopen_checked_stdin (int *empty)
{
    char tmpl[] = "/tmp/zcat.XXXXXX";
    int fd = mkstemp (tmpl);
    if (fd < 0) {
        builtin_error ("mkstemp: %s", strerror (errno));
        return NULL;
    }
    unlink (tmpl);

    unsigned char hdr[BZ_GZIP_MIN_HEADER];
    size_t got = 0;
    while (got < sizeof hdr) {
        ssize_t n = read (STDIN_FILENO, hdr + got, sizeof hdr - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            builtin_error ("stdin: %s", strerror (errno));
            close (fd);
            return NULL;
        }
        if (n == 0) break;
        got += (size_t) n;
    }

    if (got == 0) {
        *empty = 1;
        close (fd);
        return NULL;
    }
    if (!bz_magic_ok (hdr, got) || got < BZ_GZIP_MIN_HEADER) {
        builtin_error ("stdin: not in gzip format");
        close (fd);
        return NULL;
    }
    if (bz_write_all_fd (fd, (const char *) hdr, got) < 0) {
        builtin_error ("stdin: %s", strerror (errno));
        close (fd);
        return NULL;
    }

    char buf[8192];
    for (;;) {
        ssize_t n = read (STDIN_FILENO, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR) continue;
            builtin_error ("stdin: %s", strerror (errno));
            close (fd);
            return NULL;
        }
        if (n == 0) break;
        if (bz_write_all_fd (fd, buf, (size_t) n) < 0) {
            builtin_error ("stdin: %s", strerror (errno));
            close (fd);
            return NULL;
        }
    }
    if (lseek (fd, 0, SEEK_SET) < 0) {
        builtin_error ("stdin: %s", strerror (errno));
        close (fd);
        return NULL;
    }

    gzFile gf = gzdopen (fd, "rb");
    if (!gf) {
        builtin_error ("gzdopen stdin: %s", strerror (errno));
        close (fd);
    }
    return gf;
}

int
zcat_builtin (WORD_LIST *list)
{
    /* No FILE → read stdin. */
    if (!list) {
        int empty = 0;
        gzFile gf = bz_gzopen_checked_stdin (&empty);
        if (!gf) return empty ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
        int rc = bz_pump (gf);
        gzclose (gf);
        return rc < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    }

    int rc = EXECUTION_SUCCESS;
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *path = p->word->word;
        gzFile gf;
        if (!strcmp (path, "-")) {
            int empty = 0;
            gf = bz_gzopen_checked_stdin (&empty);
            if (empty) continue;
        } else {
            gf = bz_gzopen_checked_path (path);
        }
        if (!gf) {
            rc = EXECUTION_FAILURE;
            continue;
        }
        if (bz_pump (gf) < 0) rc = EXECUTION_FAILURE;
        gzclose (gf);
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
