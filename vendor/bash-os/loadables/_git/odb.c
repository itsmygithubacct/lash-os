/* SPDX-License-Identifier: MIT */
/* _git/odb.c — git objects: hashing and loose storage.
 *
 * The lookup across loose objects, packs and alternates is in store.c; this
 * file is the loose object format and the hashing that names an object.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
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
#include <sys/stat.h>
#include <ctype.h>
#include <stdint.h>
#include <limits.h>
#include <zlib.h>

/* sha1dc — collision-detecting SHA-1. Vendored under _sha1dc/, flattened
   to builtins/_sha1dc_*.{c,h} by stage-helpers.py at build time. */
#include "_sha1dc_sha1.h"

#include "loadables.h"

#include "odb.h"

const char *
bgit_type_name (enum bgit_type t)
{
    switch (t) {
    case BGIT_BLOB:   return "blob";
    case BGIT_TREE:   return "tree";
    case BGIT_COMMIT: return "commit";
    case BGIT_TAG:    return "tag";
    default:          return "unknown";
    }
}

int
bgit_type_valid_name (const char *name)
{
    return (strcmp (name, "blob") == 0
            || strcmp (name, "tree") == 0
            || strcmp (name, "commit") == 0
            || strcmp (name, "tag") == 0);
}

int
bgit_type_printable (const char *name)
{
    if (!name || !*name)
        return 0;
    for (const unsigned char *p = (const unsigned char *) name; *p; p++)
        if (*p <= ' ' || *p == 0x7f)
            return 0;
    return 1;
}

int
bgit_all_hex (const char *s)
{
    if (!s || !*s)
        return 0;
    for (const char *p = s; *p; p++)
        if (!isxdigit ((unsigned char) *p))
            return 0;
    return 1;
}

void
bgit_sha_to_hex (const unsigned char *sha, char *out)
{
    /* One table lookup per byte, the form index.c used. */
    static const char pairs[] =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    for (int i = 0; i < 20; i++)
        memcpy (out + 2*i, pairs + 2*sha[i], 2);
    out[40] = '\0';
}

int
bgit_hex_to_sha (const char *hex, unsigned char *sha)
{
    if (strlen (hex) != 40) return -1;
    for (int i = 0; i < 20; i++) {
        int hi = hex[2*i],   lo = hex[2*i+1];
        hi = (hi >= '0' && hi <= '9') ? hi - '0'
             : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10
             : (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1;
        lo = (lo >= '0' && lo <= '9') ? lo - '0'
             : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10
             : (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1;
        if (hi < 0 || lo < 0) return -1;
        sha[i] = (unsigned char) ((hi << 4) | lo);
    }
    return 0;
}

long
bgit_parse_header (const unsigned char *data, size_t len,
                   enum bgit_type *type, size_t *payload_size)
{
    /* Find space. */
    size_t i = 0;
    while (i < len && data[i] != ' ') i++;
    if (i >= len) return -1;
    if (i == 4 && memcmp (data, "blob", 4) == 0)        *type = BGIT_BLOB;
    else if (i == 4 && memcmp (data, "tree", 4) == 0)   *type = BGIT_TREE;
    else if (i == 6 && memcmp (data, "commit", 6) == 0) *type = BGIT_COMMIT;
    else if (i == 3 && memcmp (data, "tag", 3) == 0)    *type = BGIT_TAG;
    else                                                return -1;
    /* Parse size up to NUL. */
    size_t j = i + 1;
    size_t sz = 0;
    if (j >= len || data[j] < '0' || data[j] > '9') return -1;
    if (data[j] == '0' && j + 1 < len && data[j + 1] != '\0') return -1;
    while (j < len && data[j] != '\0') {
        if (data[j] < '0' || data[j] > '9') return -1;
        size_t digit = (size_t) (data[j] - '0');
        if (sz > (SIZE_MAX - digit) / 10) return -1;
        sz = sz * 10 + digit;
        j++;
    }
    if (j >= len || j >= LONG_MAX) return -1;
    *payload_size = sz;
    return (long) (j + 1);
}

int
bgit_sha1 (const unsigned char *data, size_t n, unsigned char digest[20])
{
    SHA1_CTX ctx;
    SHA1DCInit (&ctx);
    SHA1DCSetSafeHash (&ctx, 0);   /* always emit canonical SHA-1 */
    SHA1DCUpdate (&ctx, (const char *) data, n);
    return SHA1DCFinal (digest, &ctx) == 0 ? 0 : -1;
}

int
bgit_deflate (const unsigned char *data, size_t n,
              unsigned char **out, size_t *out_len)
{
    z_stream s = {0};
    if (deflateInit (&s, Z_DEFAULT_COMPRESSION) != Z_OK) return -1;
    size_t cap = deflateBound (&s, n);
    unsigned char *buf = malloc (cap);
    if (!buf) { deflateEnd (&s); return -1; }
    s.next_in = (unsigned char *) data;
    s.avail_in = (uInt) n;
    s.next_out = buf;
    s.avail_out = (uInt) cap;
    int rc = deflate (&s, Z_FINISH);
    if (rc != Z_STREAM_END) {
        free (buf);
        deflateEnd (&s);
        return -1;
    }
    *out = buf;
    *out_len = cap - s.avail_out;
    deflateEnd (&s);
    return 0;
}

int
bgit_read_loose_at (const char *objects_dir, const char *sha,
                    unsigned char **out, size_t *out_len)
{
    if (!sha || strlen (sha) != 40) return -1;
    char path[4096];
    if (snprintf (path, sizeof path, "%s/%c%c/%s", objects_dir,
                  sha[0], sha[1], sha + 2) >= (int) sizeof path)
        return -1;
    int fd = open (path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat (fd, &st) < 0 || st.st_size < 0) { close (fd); return -1; }
    unsigned char *raw = malloc ((size_t) st.st_size ? (size_t) st.st_size : 1);
    if (!raw) { close (fd); return -1; }
    ssize_t got = 0;
    while (got < st.st_size) {
        ssize_t r = read (fd, raw + got, (size_t) (st.st_size - got));
        if (r < 0) {
            if (errno == EINTR) continue;
            free (raw); close (fd); return -1;
        }
        if (r == 0) break;
        got += r;
    }
    close (fd);

    /* Inflate. Loose objects use zlib format (window bits 15). */
    z_stream s = {0};
    if (inflateInit (&s) != Z_OK) {
        free (raw);
        return -1;
    }
    s.next_in = raw;
    s.avail_in = (uInt) got;
    size_t cap = (size_t) got * 4 + 256;
    unsigned char *buf = malloc (cap);
    if (!buf) { free (raw); inflateEnd (&s); return -1; }
    size_t total = 0;
    int z_rc;
    do {
        if (total + 4096 > cap) {
            cap = cap * 2 + 4096;
            unsigned char *nb = realloc (buf, cap);
            if (!nb) { free (buf); free (raw); inflateEnd (&s); return -1; }
            buf = nb;
        }
        s.next_out = buf + total;
        s.avail_out = (uInt) (cap - total);
        z_rc = inflate (&s, Z_NO_FLUSH);
        if (z_rc != Z_OK && z_rc != Z_STREAM_END) {
            free (buf); free (raw); inflateEnd (&s); return -1;
        }
        total = cap - s.avail_out;
    } while (z_rc != Z_STREAM_END);
    inflateEnd (&s);
    free (raw);
    *out = buf;
    *out_len = total;
    return 0;
}

int
bgit_write_loose_at (const char *objects_dir, const char *sha,
                     const unsigned char *deflated, size_t dlen)
{
    char dir[4096], path[4096], tmp[4096];
    mkdir (objects_dir, 0755);
    snprintf (dir, sizeof dir, "%s/%c%c", objects_dir, sha[0], sha[1]);
    snprintf (path, sizeof path, "%s/%s", dir, sha + 2);
    /* If already present, success. */
    struct stat st;
    if (stat (path, &st) == 0) return 0;
    if (mkdir (dir, 0755) < 0 && errno != EEXIST) {
        builtin_error ("mkdir %s: %s", dir, strerror (errno));
        return -1;
    }
    snprintf (tmp, sizeof tmp, "%s.tmpXXXXXX", path);
    int fd = mkstemp (tmp);
    if (fd < 0) {
        builtin_error ("mkstemp %s: %s", tmp, strerror (errno));
        return -1;
    }
    fchmod (fd, 0444);  /* git uses 0444 for loose objects */
    size_t off = 0;
    while (off < dlen) {
        ssize_t w = write (fd, deflated + off, dlen - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            builtin_error ("write %s: %s", tmp, strerror (errno));
            close (fd); unlink (tmp);
            return -1;
        }
        off += w;
    }
    fdatasync (fd);
    close (fd);
    if (rename (tmp, path) < 0) {
        builtin_error ("rename %s -> %s: %s", tmp, path, strerror (errno));
        unlink (tmp);
        return -1;
    }
    return 0;
}

int
bgit_write_object (const char *objects_dir, const char *type,
                   const unsigned char *content, size_t clen, int do_write,
                   char sha_hex[41])
{
    /* Header: "TYPE LEN\0" */
    char hdr[64];
    int hl = snprintf (hdr, sizeof hdr, "%s %zu", type, clen);
    if (hl <= 0 || hl >= (int) sizeof hdr) return -1;
    size_t pre_len = (size_t) hl + 1 + clen;  /* +1 for NUL */
    unsigned char *pre = malloc (pre_len);
    if (!pre) { builtin_error ("malloc"); return -1; }
    memcpy (pre, hdr, (size_t) hl);
    pre[hl] = '\0';
    memcpy (pre + hl + 1, content, clen);

    unsigned char digest[20];
    int collision = bgit_sha1 (pre, pre_len, digest);
    bgit_sha_to_hex (digest, sha_hex);
    if (collision < 0) {
        free (pre);
        builtin_error ("sha1dc: collision attempt detected for %s — refusing to write", sha_hex);
        return -1;
    }

    if (do_write) {
        unsigned char *deflated;
        size_t dlen;
        if (bgit_deflate (pre, pre_len, &deflated, &dlen) < 0) {
            free (pre);
            builtin_error ("deflate failed");
            return -1;
        }
        free (pre);
        int rc = bgit_write_loose_at (objects_dir, sha_hex, deflated, dlen);
        free (deflated);
        return rc;
    }
    free (pre);
    return 0;
}

int
bgit_slurp_fd (int fd, unsigned char **out, size_t *out_len)
{
    size_t cap = 8192, n = 0;
    unsigned char *buf = malloc (cap);
    if (!buf) return -1;
    ssize_t r;
    while ((r = read (fd, buf + n, cap - n)) > 0) {
        n += r;
        if (n == cap) {
            cap *= 2;
            unsigned char *nb = realloc (buf, cap);
            if (!nb) { free (buf); return -1; }
            buf = nb;
        }
    }
    if (r < 0) { free (buf); return -1; }
    *out = buf;
    *out_len = n;
    return 0;
}

int
bgit_slurp_file (const char *path, unsigned char **out, size_t *out_len)
{
    int fd = open (path, O_RDONLY);
    if (fd < 0) {
        builtin_error ("hash: %s: %s", path, strerror (errno));
        return -1;
    }

    size_t cap = 8192, n = 0;
    unsigned char *buf = malloc (cap);
    if (!buf) { close (fd); return -1; }

    ssize_t r;
    while ((r = read (fd, buf + n, cap - n)) > 0) {
        n += r;
        if (n == cap) {
            cap *= 2;
            unsigned char *nb = realloc (buf, cap);
            if (!nb) { free (buf); close (fd); return -1; }
            buf = nb;
        }
    }
    close (fd);
    if (r < 0) {
        builtin_error ("hash: %s: %s", path, strerror (errno));
        free (buf);
        return -1;
    }

    *out = buf;
    *out_len = n;
    return 0;
}
