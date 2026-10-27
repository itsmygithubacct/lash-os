/* SPDX-License-Identifier: MIT */
/* _git/index.c — git index (.git/index) reading and writing.
 *
 * Moved out of the index builtin so the git builtins share one
 * implementation. See index.h for the contract; the behaviour, including
 * every message, is the same as when the builtin held this code.
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
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "loadables.h"

#include "index.h"
#include "odb.h"

uint32_t
bgit_be32 (const unsigned char *buf, size_t off)
{
    return ((uint32_t) buf[off] << 24) | ((uint32_t) buf[off+1] << 16) |
           ((uint32_t) buf[off+2] <<  8) | ((uint32_t) buf[off+3]);
}

uint16_t
bgit_be16 (const unsigned char *buf, size_t off)
{
    return (uint16_t) (((uint16_t) buf[off] << 8) | (uint16_t) buf[off+1]);
}

static void
bgit_put_be32 (unsigned char *buf, uint32_t v)
{
    buf[0] = (unsigned char) (v >> 24); buf[1] = (unsigned char) (v >> 16);
    buf[2] = (unsigned char) (v >> 8);  buf[3] = (unsigned char) v;
}

static void
bgit_put_be16 (unsigned char *buf, uint16_t v)
{
    buf[0] = (unsigned char) (v >> 8); buf[1] = (unsigned char) v;
}

int
bgit_index_parse_mode (const char *s, uint32_t *out)
{
    char *end = NULL;
    unsigned long v;

    if (!s || !*s)
        return -1;
    errno = 0;
    v = strtoul (s, &end, 8);
    if (errno || !end || *end != '\0' || v > UINT32_MAX)
        return -1;
    *out = (uint32_t) v;
    return 0;
}

int
bgit_index_parse_stage (const char *s, int *out)
{
    char *end = NULL;
    long v;

    if (!s || !*s)
        return -1;
    errno = 0;
    v = strtol (s, &end, 10);
    if (errno || !end || *end != '\0' || v < 0 || v > 3)
        return -1;
    *out = (int) v;
    return 0;
}

int
bgit_index_path_valid (const char *path)
{
    if (!path || !*path) return 0;
    for (const char *part = path; ; ) {
        const char *slash = strchr (part, '/');
        size_t len = slash ? (size_t) (slash - part) : strlen (part);
        if (!len || (len == 1 && part[0] == '.') ||
            (len == 2 && !memcmp (part, "..", 2)) ||
            (len == 4 && !strncasecmp (part, ".git", 4)))
            return 0;
        if (!slash) return 1;
        part = slash + 1;
    }
}

void
bgit_index_entry_set_stat (bgit_index_entry *e, const struct stat *st)
{
    e->ctime_sec  = (uint32_t) st->st_ctim.tv_sec;
    e->ctime_nsec = (uint32_t) st->st_ctim.tv_nsec;
    e->mtime_sec  = (uint32_t) st->st_mtim.tv_sec;
    e->mtime_nsec = (uint32_t) st->st_mtim.tv_nsec;
    e->dev = (uint32_t) st->st_dev;
    e->ino = (uint32_t) st->st_ino;
    e->mode = (uint32_t) st->st_mode;
    e->uid = (uint32_t) st->st_uid;
    e->gid = (uint32_t) st->st_gid;
    e->size = (uint32_t) st->st_size;
}

void
bgit_index_free_entries (bgit_index_entry *e, size_t n)
{
    for (size_t i = 0; i < n; i++) free (e[i].path);
    free (e);
}

/* ---- the trailer checksum ------------------------------------------------

   The last 20 bytes of an index are the SHA-1 of everything before them.
   That digest guards against a torn or corrupted file; it authenticates
   nothing, since whoever can write the index can write a matching trailer,
   and git itself does not verify it on an ordinary read. Collision
   detection buys nothing here, and SHA1DC with it on is the larger part of
   reading a big index, so the trailer is computed by plain SHA-1 (FIPS
   180-4), with the message schedule kept in a rolling 16-word window.
   Object ids, where collisions do matter, still go through SHA1DC. */

#define BGIT_ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define BGIT_SHA1_W(t) \
    (w[(t) & 15] = BGIT_ROL32 (w[((t) + 13) & 15] ^ w[((t) + 8) & 15] ^ \
                               w[((t) + 2) & 15] ^ w[(t) & 15], 1))
#define BGIT_SHA1_STEP(a, b, c, d, e, f, k, x) \
    do { e += BGIT_ROL32 (a, 5) + (f) + (k) + (x); b = BGIT_ROL32 (b, 30); } while (0)
#define BGIT_SHA1_F1(b, c, d) ((d) ^ ((b) & ((c) ^ (d))))
#define BGIT_SHA1_F2(b, c, d) ((b) ^ (c) ^ (d))
#define BGIT_SHA1_F3(b, c, d) (((b) & (c)) | ((d) & ((b) | (c))))
#define BGIT_SHA1_R0(a, b, c, d, e, t) \
    BGIT_SHA1_STEP (a, b, c, d, e, BGIT_SHA1_F1 (b, c, d), 0x5A827999u, w[t])
#define BGIT_SHA1_R1(a, b, c, d, e, t) \
    BGIT_SHA1_STEP (a, b, c, d, e, BGIT_SHA1_F1 (b, c, d), 0x5A827999u, BGIT_SHA1_W (t))
#define BGIT_SHA1_R2(a, b, c, d, e, t) \
    BGIT_SHA1_STEP (a, b, c, d, e, BGIT_SHA1_F2 (b, c, d), 0x6ED9EBA1u, BGIT_SHA1_W (t))
#define BGIT_SHA1_R3(a, b, c, d, e, t) \
    BGIT_SHA1_STEP (a, b, c, d, e, BGIT_SHA1_F3 (b, c, d), 0x8F1BBCDCu, BGIT_SHA1_W (t))
#define BGIT_SHA1_R4(a, b, c, d, e, t) \
    BGIT_SHA1_STEP (a, b, c, d, e, BGIT_SHA1_F2 (b, c, d), 0xCA62C1D6u, BGIT_SHA1_W (t))
#define BGIT_SHA1_FIVE(R, t) \
    R (a, b, c, d, e, (t));     R (e, a, b, c, d, (t) + 1); \
    R (d, e, a, b, c, (t) + 2); R (c, d, e, a, b, (t) + 3); \
    R (b, c, d, e, a, (t) + 4)

static void
bgit_index_sha1_blocks (uint32_t h[5], const unsigned char *p, size_t blocks)
{
    while (blocks--) {
        uint32_t w[16];
        for (int i = 0; i < 16; i++)
            w[i] = bgit_be32 (p, (size_t) i * 4);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        BGIT_SHA1_FIVE (BGIT_SHA1_R0, 0);  BGIT_SHA1_FIVE (BGIT_SHA1_R0, 5);
        BGIT_SHA1_FIVE (BGIT_SHA1_R0, 10);
        BGIT_SHA1_R0 (a, b, c, d, e, 15);  BGIT_SHA1_R1 (e, a, b, c, d, 16);
        BGIT_SHA1_R1 (d, e, a, b, c, 17);  BGIT_SHA1_R1 (c, d, e, a, b, 18);
        BGIT_SHA1_R1 (b, c, d, e, a, 19);
        BGIT_SHA1_FIVE (BGIT_SHA1_R2, 20); BGIT_SHA1_FIVE (BGIT_SHA1_R2, 25);
        BGIT_SHA1_FIVE (BGIT_SHA1_R2, 30); BGIT_SHA1_FIVE (BGIT_SHA1_R2, 35);
        BGIT_SHA1_FIVE (BGIT_SHA1_R3, 40); BGIT_SHA1_FIVE (BGIT_SHA1_R3, 45);
        BGIT_SHA1_FIVE (BGIT_SHA1_R3, 50); BGIT_SHA1_FIVE (BGIT_SHA1_R3, 55);
        BGIT_SHA1_FIVE (BGIT_SHA1_R4, 60); BGIT_SHA1_FIVE (BGIT_SHA1_R4, 65);
        BGIT_SHA1_FIVE (BGIT_SHA1_R4, 70); BGIT_SHA1_FIVE (BGIT_SHA1_R4, 75);
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
        p += 64;
    }
}

/* The SHA-1 of DATA[0..LEN), into DIGEST. */
static void
bgit_index_sha1 (const unsigned char *data, size_t len, unsigned char digest[20])
{
    uint32_t h[5] = { 0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u,
                      0xC3D2E1F0u };
    size_t whole = len / 64;
    bgit_index_sha1_blocks (h, data, whole);
    unsigned char tail[128];
    size_t rest = len - whole * 64;
    memcpy (tail, data + whole * 64, rest);
    tail[rest] = 0x80;
    size_t tail_len = rest < 56 ? 64 : 128;
    memset (tail + rest + 1, 0, tail_len - rest - 1);
    uint64_t bits = (uint64_t) len * 8;
    for (int i = 0; i < 8; i++)
        tail[tail_len - 1 - i] = (unsigned char) (bits >> (8 * i));
    bgit_index_sha1_blocks (h, tail, tail_len / 64);
    for (int i = 0; i < 5; i++)
        bgit_put_be32 (digest + i * 4, h[i]);
}

/* Slurp file. Caller frees. A directory is refused rather than sized by
   ftell, which reports LONG_MAX for one; anything else is read to its end,
   so a file that grows or shrinks while it is read is taken as it ends. */
static unsigned char *
bgit_index_slurp (const char *path, size_t *out_len)
{
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat (fd, &st) < 0) { int e = errno; close (fd); errno = e; return NULL; }
    if (S_ISDIR (st.st_mode)) { close (fd); errno = EISDIR; return NULL; }
    size_t cap = S_ISREG (st.st_mode) && st.st_size > 0 &&
                 (uint64_t) st.st_size < SIZE_MAX - 1 ? (size_t) st.st_size + 1 : 65536;
    size_t len = 0;
    unsigned char *buf = malloc (cap);
    if (!buf) { close (fd); errno = ENOMEM; return NULL; }
    for (;;) {
        if (len == cap) {
            if (cap > SIZE_MAX / 2) { free (buf); close (fd); errno = EFBIG; return NULL; }
            unsigned char *grown = realloc (buf, cap * 2);
            if (!grown) { free (buf); close (fd); errno = ENOMEM; return NULL; }
            buf = grown;
            cap *= 2;
        }
        ssize_t got = read (fd, buf + len, cap - len);
        if (got < 0) {
            if (errno == EINTR) continue;
            int e = errno;
            free (buf); close (fd); errno = e;
            return NULL;
        }
        if (got == 0) break;
        len += (size_t) got;
    }
    close (fd);
    *out_len = len;
    return buf;
}

/* Keep one bounded, owned snapshot of successfully checksum-validated bytes.
   Every parse still reads and validates entries anew. Only exact equality of
   the entire file, including its trailer, reuses the earlier checksum result;
   no pathname, metadata, parsed entries or borrowed paths are cached. */
#define BGIT_INDEX_CHECKSUM_CACHE_LIMIT ((size_t) 8 * 1024 * 1024)
static unsigned char *bgit_index_verified_bytes;
static size_t bgit_index_verified_len;

static int
bgit_index_checksum_cached (const unsigned char *buf, size_t len)
{
    return bgit_index_verified_bytes && len == bgit_index_verified_len &&
           memcmp (buf, bgit_index_verified_bytes, len) == 0;
}

static void
bgit_index_remember_verified (const unsigned char *buf, size_t len)
{
    if (len > BGIT_INDEX_CHECKSUM_CACHE_LIMIT) return;
    int saved_errno = errno;
    if (len != bgit_index_verified_len) {
        /* Release first to retain no more than one snapshot. An optional
           allocation failure leaves ordinary checksum validation active. */
        free (bgit_index_verified_bytes);
        bgit_index_verified_bytes = NULL;
        bgit_index_verified_len = 0;
        bgit_index_verified_bytes = malloc (len);
    }
    if (bgit_index_verified_bytes) {
        memcpy (bgit_index_verified_bytes, buf, len);
        bgit_index_verified_len = len;
    }
    errno = saved_errno;
}

void
bgit_index_cache_release (void)
{
    free (bgit_index_verified_bytes);
    bgit_index_verified_bytes = NULL;
    bgit_index_verified_len = 0;
}

int
bgit_index_read_views (const char *path, bgit_index_view **out, size_t *n_out,
                       unsigned char **backing)
{
    size_t flen;
    return bgit_index_read_views_len (path, out, n_out, backing, &flen);
}

int
bgit_index_read_views_len (const char *path, bgit_index_view **out,
                           size_t *n_out, unsigned char **backing,
                           size_t *len_out)
{
    size_t flen;
    unsigned char *buf = bgit_index_slurp (path, &flen);
    if (!buf) {
        builtin_error ("read %s: %s", path, strerror (errno));
        return -1;
    }
    if (flen < 32) {
        free (buf);
        builtin_error ("index too short (%zu bytes)", flen);
        return -1;
    }
    if (memcmp (buf, "DIRC", 4) != 0) {
        free (buf);
        builtin_error ("bad magic (not 'DIRC')");
        return -1;
    }
    uint32_t ver = bgit_be32 (buf, 4);
    if (ver != 2 && ver != 3) {
        free (buf);
        builtin_error ("unsupported index version %u (only 2,3)", ver);
        return -1;
    }
    uint32_t n_entries = bgit_be32 (buf, 8);
    if (n_entries > (flen - 32) / 64) {
        free (buf); builtin_error ("truncated index (entry count)"); return -1;
    }
    bgit_index_view *entries = calloc (n_entries ? n_entries : 1, sizeof *entries);
    if (!entries) { free (buf); return -1; }

    size_t off = 12;
    for (uint32_t i = 0; i < n_entries; i++) {
        if (off + 62 > flen - 20) { /* -20 for trailer */
            free (buf); free (entries);
            builtin_error ("truncated index");
            return -1;
        }
        bgit_index_view *e = &entries[i];
        e->disk = buf + off;
        uint16_t flags = bgit_be16 (buf, off + 60);
        off += 62;

        /* v3+ CE_EXTENDED (0x4000) entries carry a second 16-bit flags
           field (flags2) before the path — git's create_from_disk reads it
           via get_be16(flagsp + sizeof(uint16_t)). Decoding preserves
           skip-worktree and intent-to-add for subsequent writes.
           extended_len feeds the 8-byte padding so the on-disk size matches
           git's ondisk_data_size(). */
        size_t extended_len = 0;
        if (ver >= 3 && (flags & 0x4000)) {
            if (off + 2 > flen - 20) {
                free (buf); free (entries);
                builtin_error ("truncated index (extended flags)");
                return -1;
            }
            off += 2;
            extended_len = 2;
        }

        size_t path_len = flags & 0xFFF;
        const unsigned char *nul = memchr (buf + off, 0, flen - 20 - off);
        if (path_len == 0xFFF && nul) path_len = (size_t) (nul - buf - off);
        if (!nul || (size_t) (nul - buf - off) != path_len) {
            free (buf); free (entries);
            builtin_error ("truncated index (path)");
            return -1;
        }
        e->path = (char *) buf + off;
        if (!bgit_index_path_valid (e->path)) {
            builtin_error ("invalid index path '%s'", e->path);
            free (buf); free (entries);
            return -1;
        }
        off += path_len;
        /* Pad to 8-byte boundary. The entry start is 12 bytes into the
           file, so total entry length so far = 62 (+2 if extended) +
           path_len. Pad to multiple of 8 with NULs (at least 1 NUL). */
        size_t entry_len = 62 + extended_len + path_len;
        size_t pad = (8 - (entry_len % 8));
        if (pad == 0) pad = 8;
        if (pad > flen - 20 - off) {
            free (buf); free (entries);
            builtin_error ("truncated index (padding)"); return -1;
        }
        for (size_t j = 0; j < pad; j++) {
            if (buf[off + j] != 0) {
                free (buf); free (entries);
                builtin_error ("invalid index padding"); return -1;
            }
        }
        off += pad;
    }

    /* Validate SHA-1 trailer: last 20 bytes = sha1 of buf[0 .. flen-21].
       Git computes the trailer over the entire index body including headers
       and all entries (everything before the trailer itself). */
    if (flen < 20) {
        free (buf); free (entries);
        builtin_error ("index too short (no trailer)");
        return -1;
    }
    if (!bgit_index_checksum_cached (buf, flen)) {
        unsigned char computed[20];
        bgit_index_sha1 (buf, flen - 20, computed);
        if (memcmp (computed, buf + flen - 20, 20) != 0) {
            free (buf); free (entries);
            builtin_error ("index checksum mismatch");
            return -1;
        }
        bgit_index_remember_verified (buf, flen);
    }

    *backing = buf;
    *out = entries;
    *n_out = n_entries;
    *len_out = flen;
    return 0;
}

/* When the index itself was last written, for the racy-entry rule. */
static uint32_t bgit_index_stamp_sec, bgit_index_stamp_nsec;
static int bgit_index_stamped;

int
bgit_index_racy (const bgit_index_entry *entry)
{
    /* An entry written in the same second as the index itself, or later,
       cannot be told from a changed one by its stat data, so only its
       content can say. git draws the line by seconds, since it compares
       timestamps by seconds. */
    if (!bgit_index_stamped || !bgit_index_stamp_sec) return 0;
    return entry->mtime_sec >= bgit_index_stamp_sec;
}

void
bgit_index_stamp (const char *path)
{
    struct stat st;
    if (stat (path, &st) < 0) return;
    bgit_index_stamp_sec = (uint32_t) st.st_mtim.tv_sec;
    bgit_index_stamp_nsec = (uint32_t) st.st_mtim.tv_nsec;
    bgit_index_stamped = 1;
}

void
bgit_index_unstamp (void)
{
    bgit_index_stamp_sec = bgit_index_stamp_nsec = 0;
    bgit_index_stamped = 0;
}

int
bgit_index_read (const char *path, bgit_index_entry **out, size_t *n_out)
{
    bgit_index_view *views;
    size_t n;
    unsigned char *backing;
    if (bgit_index_read_views (path, &views, &n, &backing) < 0) return -1;
    return bgit_index_decode_views (path, views, n, backing, out, n_out);
}

/* Printed name: bytes through the first NUL in WINDOW, or all of WINDOW
   when it has none. Does not read past WINDOW. */
static int
bgit_index_listing_path (bgit_index_entry *e, const char *prefix, size_t prefix_n,
                         const unsigned char *window, size_t window_n)
{
    const unsigned char *nul = window_n ? memchr (window, 0, window_n) : NULL;
    size_t n = nul ? (size_t) (nul - window) : window_n;
    if (prefix_n > SIZE_MAX - n - 1) return -1;
    e->path = malloc (prefix_n + n + 1);
    if (!e->path) return -1;
    if (prefix_n) memcpy (e->path, prefix, prefix_n);
    if (n) memcpy (e->path + prefix_n, window, n);
    e->path[prefix_n + n] = 0;
    return 0;
}

/* Git's decode_varint. On overflow the value is 0 and *off stays at the
   first byte, which is then part of the name. A read at the end of the
   mapped page fails: that byte is not in the mapping. */
static int
bidx_decode_varint (const unsigned char *buf, size_t limit, size_t *off,
                    size_t *val_out)
{
    size_t start = *off;
    if (start >= limit) return -1;
    unsigned c = buf[(*off)++];
    size_t val = c & 0x7f;
    int overflow = 0;
    while (c & 0x80) {
        if (val >= (SIZE_MAX >> 7)) { overflow = 1; break; }
        if (*off >= limit) return -1;
        c = buf[(*off)++];
        val = ((val + 1) << 7) + (c & 0x7f);
    }
    if (overflow) { *off = start; val = 0; }
    *val_out = val;
    return 0;
}

/* Bytes of one region. A load or store that is not entirely inside one
   region misses. */
struct bidx_span {
    uint64_t base;
    unsigned char *data;
    size_t len;
};

struct bidx_mem {
    struct bidx_span mmap, pool;
};

static unsigned char *
bidx_span_at (struct bidx_span *s, uint64_t addr, size_t n)
{
    if (!n || n > s->len || addr < s->base) return NULL;
    uint64_t rel = addr - s->base;
    if (rel > s->len - n) return NULL;
    return s->data + (size_t) rel;
}

static unsigned char *
bidx_mem_at (struct bidx_mem *m, uint64_t addr, size_t n)
{
    unsigned char *p = bidx_span_at (&m->mmap, addr, n);
    if (p) return p;
    return bidx_span_at (&m->pool, addr, n);
}

static int
bidx_load (struct bidx_mem *m, uint64_t addr, unsigned char *dst, size_t n)
{
    unsigned char *p = bidx_mem_at (m, addr, n);
    if (!p) return -1;
    memcpy (dst, p, n);
    return 0;
}

static int
bidx_store (struct bidx_mem *m, uint64_t addr, const unsigned char *src, size_t n)
{
    unsigned char *p = bidx_mem_at (m, addr, n);
    if (!p) return 1; /* wild store: glibc writes it, the model ignores it */
    memcpy (p, src, n);
    return 0;
}

static int
bidx_w32 (struct bidx_mem *m, uint64_t at, uint32_t v)
{
    unsigned char b[4];
    b[0] = (unsigned char) v;
    b[1] = (unsigned char) (v >> 8);
    b[2] = (unsigned char) (v >> 16);
    b[3] = (unsigned char) (v >> 24);
    return bidx_store (m, at, b, 4) < 0 ? -1 : 0;
}

static uint32_t
bidx_r32 (const unsigned char *p)
{
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) |
           ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

/* glibc's overlap memcpy for a wrapped size, bounded to the mapped page
   and the cache pool. A load from anywhere else is the undefined read
   git performs; refuse it instead of issuing that read. */
static int
bidx_overlap_memcpy (struct bidx_mem *m, uint64_t dest, uint64_t src, uint64_t size)
{
    unsigned char ymm0[32], ymm5[32], ymm6[32], ymm7[32], ymm8[32];
    unsigned char chunk[32];
    if (bidx_load (m, src, ymm0, 32) < 0) return -1;
    if (bidx_load (m, src + 0x20, ymm5, 32) < 0) return -1;
    if (bidx_load (m, src + 0x40, ymm6, 32) < 0) return -1;
    if (bidx_load (m, src + 0x60, ymm7, 32) < 0) return -1;
    if (bidx_load (m, src + size - 0x20, ymm8, 32) < 0) return -1;
    uint64_t rcx = (dest + size - 0x81) & ~(uint64_t) 0x1f;
    uint64_t rsi = src - dest + rcx;
    int settled = 0;
    for (int n = 0; n < 8; n++) {
        if (bidx_load (m, rsi + 0x60, chunk, 32) < 0) return -1;
        bidx_store (m, rcx + 0x60, chunk, 32);
        if (bidx_load (m, rsi + 0x40, chunk, 32) < 0) return -1;
        bidx_store (m, rcx + 0x40, chunk, 32);
        if (bidx_load (m, rsi + 0x20, chunk, 32) < 0) return -1;
        bidx_store (m, rcx + 0x20, chunk, 32);
        if (bidx_load (m, rsi, chunk, 32) < 0) return -1;
        bidx_store (m, rcx, chunk, 32);
        rsi -= 0x80;
        rcx -= 0x80;
        if (!(dest < rcx)) { settled = 1; break; }
    }
    if (!settled) return -1;
    bidx_store (m, dest, ymm0, 32);
    bidx_store (m, dest + 0x20, ymm5, 32);
    bidx_store (m, dest + 0x40, ymm6, 32);
    bidx_store (m, dest + 0x60, ymm7, 32);
    bidx_store (m, dest + size - 0x20, ymm8, 32);
    return 0;
}

/* First cache entry's address mod 32, for a 20-entry index whose
   repository path is 13 bytes shorter than the index path. Measured for
   git 2.47.3 and glibc 2.41. '0' is 8, '1' is 24. Index is path length
   minus 29, covering lengths 29 through 480. */
static const char bidx_pool_mod_tab[] =
"11111111111000000000001111111111001110000000000011111100000111110000011111111111"
"00011111111111111111100000000000111000111000000011111000000000001110001111100000"
"11111000000111110000001110000000111110000000000011100000011000000000000000000000"
"11100011100000001111100000000000111000111000000011111000000111110001110001100000"
"11111000000000001110001111111111000001111111111100000011100000001111100000000000"
"1110001110000000111110000000000011100011100000001111";

static int
bidx_pool_mod_known (size_t path_len, uint32_t count, int *mod)
{
    if (count != 20 || path_len < 29 ||
        path_len >= 29 + sizeof bidx_pool_mod_tab - 1)
        return 0;
    *mod = bidx_pool_mod_tab[path_len - 29] == '1' ? 24 : 8;
    return 1;
}

static int
bidx_v4_overlap_one (const unsigned char *buf, size_t limit, uint32_t count,
                     int pool_mod, bgit_index_entry **out, size_t *ext_off)
{
    const uint64_t mmap_base = 0x7f0000000000ULL;
    const uint64_t pool_base = 0x560000000000ULL + (unsigned) pool_mod;
    const size_t name_off = 0x6c;
    unsigned char *pool = NULL;
    uint64_t *addr = NULL;
    bgit_index_entry *entries = NULL;
    struct bidx_mem mem;
    size_t pool_len = 0, off = 12;
    uint64_t cursor;

    *out = NULL;
    if (!count || count > 1000000) return -1;
    pool_len = (size_t) count * 192;
    pool = malloc (pool_len);
    addr = calloc (count, sizeof *addr);
    if (!pool || !addr) goto fail;
    memset (pool, 0xa5, pool_len);
    mem.mmap.base = mmap_base;
    mem.mmap.data = (unsigned char *) buf;
    mem.mmap.len = limit;
    mem.pool.base = pool_base;
    mem.pool.data = pool;
    mem.pool.len = pool_len;
    cursor = pool_base;

    for (uint32_t i = 0; i < count; i++) {
        size_t start = off, name_at, flen, copy = 0;
        unsigned ext = 0;
        unsigned flags;
        uint64_t ce, prev = 0;
        size_t strip = 0, alloc, raw_sz;
        if (off > limit || limit - off < 62) goto fail;
        flags = bgit_be16 (buf, off + 60);
        name_at = off + 62;
        if (flags & 0x4000) {
            if (limit - name_at < 2) goto fail;
            ext = bgit_be16 (buf, name_at);
            name_at += 2;
            if (ext & ~0x6000u) goto fail;
            flags |= ext << 16;
        }
        if (bidx_decode_varint (buf, limit, &name_at, &strip) < 0) goto fail;
        if (i) {
            unsigned char nb[4];
            uint32_t prev_len;
            prev = addr[i - 1];
            if (bidx_load (&mem, prev + 0x40, nb, 4) < 0) goto fail;
            prev_len = bidx_r32 (nb);
            if (prev_len < strip) goto fail;
            copy = prev_len - strip;
        }
        flen = flags & 0xfff;
        if (flen == 0xfff) {
            size_t n = 0;
            while (name_at + n < limit && buf[name_at + n] != 0) n++;
            if (name_at + n >= limit) goto fail;
            if (n > SIZE_MAX - copy) goto fail;
            flen = n + copy;
        }
        if (flen > pool_len || copy > pool_len) goto fail;
        if (name_off > SIZE_MAX - flen - 1) goto fail;
        raw_sz = name_off + flen + 1;
        alloc = (raw_sz + 7) & ~(size_t) 7;
        ce = cursor;
        if (alloc > pool_len || ce + alloc > pool_base + pool_len) goto fail;
        cursor += alloc;
        addr[i] = ce;
        if (bidx_w32 (&mem, ce + 0x10, bgit_be32 (buf, off + 0)) ||
            bidx_w32 (&mem, ce + 0x14, bgit_be32 (buf, off + 4)) ||
            bidx_w32 (&mem, ce + 0x18, bgit_be32 (buf, off + 8)) ||
            bidx_w32 (&mem, ce + 0x1c, bgit_be32 (buf, off + 12)) ||
            bidx_w32 (&mem, ce + 0x20, bgit_be32 (buf, off + 16)) ||
            bidx_w32 (&mem, ce + 0x24, bgit_be32 (buf, off + 20)) ||
            bidx_w32 (&mem, ce + 0x34, bgit_be32 (buf, off + 24)) ||
            bidx_w32 (&mem, ce + 0x28, bgit_be32 (buf, off + 28)) ||
            bidx_w32 (&mem, ce + 0x2c, bgit_be32 (buf, off + 32)) ||
            bidx_w32 (&mem, ce + 0x30, bgit_be32 (buf, off + 36)) ||
            bidx_w32 (&mem, ce + 0x3c, 1) ||
            bidx_w32 (&mem, ce + 0x38, flags & ~0xfffu) ||
            bidx_w32 (&mem, ce + 0x40, (uint32_t) flen) ||
            bidx_w32 (&mem, ce + 0x44, 0) ||
            bidx_w32 (&mem, ce + 0x68, 1))
            goto fail;
        {
            unsigned char oid[32];
            memset (oid, 0, sizeof oid);
            memcpy (oid, buf + off + 40, 20);
            if (bidx_store (&mem, ce + 0x48, oid, 32)) goto fail;
        }
        if (copy) {
            unsigned char *got = bidx_mem_at (&mem, prev + name_off, copy);
            if (!got || bidx_store (&mem, ce + name_off, got, copy)) goto fail;
        }
        {
            uint64_t suffix = (uint64_t) flen + 1 - (uint64_t) copy;
            uint64_t src = mmap_base + name_at;
            uint64_t dest = ce + name_off + copy;
            if ((uint64_t) flen + 1 < (uint64_t) copy) {
                if (bidx_overlap_memcpy (&mem, dest, src, suffix) < 0) goto fail;
            } else {
                unsigned char *got;
                if (suffix > limit || name_at > limit - (size_t) suffix) goto fail;
                got = bidx_mem_at (&mem, src, (size_t) suffix);
                if (!got || bidx_store (&mem, dest, got, (size_t) suffix)) goto fail;
            }
            if ((uint64_t) flen + 1 < (uint64_t) copy) {
                uint64_t drop = (uint64_t) copy - flen - 1;
                if ((uint64_t) (name_at - start) < drop) goto fail;
                off = start + (size_t) ((uint64_t) (name_at - start) - drop);
            } else if ((uint64_t) (name_at - start) + (uint64_t) flen + 1 - copy >
                       SIZE_MAX - start) {
                goto fail;
            } else {
                off = start + (name_at - start) + flen + 1 - copy;
            }
        }
    }

    entries = calloc (count, sizeof *entries);
    if (!entries) goto fail;
    for (uint32_t i = 0; i < count; i++) {
        unsigned char hdr[0x70], *name;
        uint32_t mode, fl, nl, algo;
        size_t room, nlen;
        const unsigned char *nul;
        uint64_t ce = addr[i];
        if (bidx_load (&mem, ce, hdr, 0x70) < 0) goto fail;
        mode = bidx_r32 (hdr + 0x34);
        fl = bidx_r32 (hdr + 0x38);
        nl = bidx_r32 (hdr + 0x40);
        algo = bidx_r32 (hdr + 0x68);
        if (algo != 0 && algo != 1) goto fail;
        if (ce + name_off < ce || ce + name_off > pool_base + pool_len) goto fail;
        room = (size_t) (pool_base + pool_len - (ce + name_off));
        if ((uint64_t) nl > room) goto fail;
        name = bidx_mem_at (&mem, ce + name_off, room);
        if (!name) goto fail;
        nul = memchr (name, 0, room);
        if (!nul) goto fail;
        nlen = (size_t) (nul - name);
        entries[i].mode = mode;
        memcpy (entries[i].sha, hdr + 0x48, 20);
        entries[i].flags = (uint16_t) fl;
        entries[i].flags2 = (uint16_t) (fl >> 16);
        entries[i].path = malloc (nlen + 1);
        if (!entries[i].path) goto fail;
        memcpy (entries[i].path, name, nlen);
        entries[i].path[nlen] = 0;
    }
    free (pool);
    free (addr);
    *out = entries;
    *ext_off = off;
    return 0;
fail:
    free (pool);
    free (addr);
    if (entries)
        bgit_index_free_entries (entries, count);
    return -1;
}

static int
bidx_listings_match (bgit_index_entry *a, bgit_index_entry *b, size_t n,
                     size_t oa, size_t ob)
{
    if (oa != ob) return 0;
    for (size_t i = 0; i < n; i++) {
        if (a[i].mode != b[i].mode || a[i].flags != b[i].flags ||
            a[i].flags2 != b[i].flags2 || memcmp (a[i].sha, b[i].sha, 20) ||
            strcmp (a[i].path, b[i].path))
            return 0;
    }
    return 1;
}

/* Reparse a version-4 index whose declared name is shorter than the
   prefix copied from the previous entry. Git still lists it: the suffix
   copy wraps and glibc's overlap path rewrites the cache entries. */
static int
bgit_v4_overlap_listing (const char *path, const unsigned char *buf, size_t limit,
                         uint32_t count, bgit_index_entry **out, size_t *ext_off)
{
    int mod = 0;
    if (bidx_pool_mod_known (strlen (path), count, &mod))
        return bidx_v4_overlap_one (buf, limit, count, mod, out, ext_off);
    bgit_index_entry *a = NULL, *b = NULL;
    size_t oa = 0, ob = 0;
    if (bidx_v4_overlap_one (buf, limit, count, 8, &a, &oa) < 0) return -1;
    if (bidx_v4_overlap_one (buf, limit, count, 24, &b, &ob) < 0) {
        bgit_index_free_entries (a, count);
        return -1;
    }
    if (!bidx_listings_match (a, b, count, oa, ob)) {
        bgit_index_free_entries (a, count);
        bgit_index_free_entries (b, count);
        return -1;
    }
    bgit_index_free_entries (b, count);
    *out = a;
    *ext_off = oa;
    return 0;
}


/* Git's listing reader deliberately does not check the trailer, padding,
   path safety or entry order. Keep it separate from the strict shared API.
   mmap readers can see zeroes through the end of the last page; emulate
   those bytes in owned memory, without ever reading beyond an allocation.
   A last entry may end in that tail. A later entry that would start at or
   past the page is refused: Git's listing there is not stable, and a
   partial listing must not be printed. */
int
bgit_index_read_listing (const char *path, bgit_index_entry **out, size_t *n_out,
                         unsigned char **backing, size_t *flen_out,
                         size_t *extensions_out)
{
    size_t flen;
    unsigned char *buf = bgit_index_slurp (path, &flen);
    if (!buf) { builtin_error ("read %s: %s", path, strerror (errno)); return -1; }
    if (flen < 32 || memcmp (buf, "DIRC", 4)) goto invalid;
    uint32_t version = bgit_be32 (buf, 4), count = bgit_be32 (buf, 8);
    if (version < 2 || version > 4) goto invalid;
    long pagesize = sysconf (_SC_PAGESIZE);
    size_t page = pagesize > 0 ? (size_t) pagesize : 4096;
    if (flen > SIZE_MAX - page) goto invalid;
    size_t limit = ((flen + page - 1) / page) * page;
    if (count > (limit - 12) / 64) goto invalid;
    unsigned char *padded = realloc (buf, limit);
    if (!padded) { free (buf); return -1; }
    buf = padded;
    memset (buf + flen, 0, limit - flen);
    bgit_index_entry *entries = calloc (count ? count : 1, sizeof *entries);
    if (!entries) { free (buf); return -1; }
    size_t off = 12, parsed = 0, previous_len = 0;
    for (; parsed < count; parsed++) {
        size_t start = off;
        if (off > limit || limit - off < 62) goto bad_entries;
        const unsigned char *disk = buf + off;
        bgit_index_entry *e = &entries[parsed];
        e->ctime_sec = bgit_be32 (disk, 0);
        e->ctime_nsec = bgit_be32 (disk, 4);
        e->mtime_sec = bgit_be32 (disk, 8);
        e->mtime_nsec = bgit_be32 (disk, 12);
        e->dev = bgit_be32 (disk, 16);
        e->ino = bgit_be32 (disk, 20);
        e->mode = bgit_be32 (disk, 24);
        e->uid = bgit_be32 (disk, 28);
        e->gid = bgit_be32 (disk, 32);
        e->size = bgit_be32 (disk, 36);
        memcpy (e->sha, disk + 40, 20);
        e->flags = bgit_be16 (disk, 60);
        off += 62;
        if (e->flags & 0x4000) {
            if (limit - off < 2) goto bad_entries;
            e->flags2 = bgit_be16 (buf, off); off += 2;
            if (e->flags2 & ~0x6000) goto bad_entries;
        }
        int last = parsed + 1 == count;
        if (version == 4) {
            /* OFS_DELTA-style integer: bytes already read represent one
               less than the high part whenever another byte follows.
               The 12-bit field is the full name length, not the suffix.
               The first entry has no previous name, so its strip is
               consumed and ignored, as Git does. Advance by the whole
               declared suffix, even when a NUL appears earlier. */
            size_t strip = 0;
            /* Overflow leaves the cursor on the first byte and a value of
               0. That byte is then part of the name, as Git's decode_varint
               does. A byte past the mapped page is refused. */
            if (bidx_decode_varint (buf, limit, &off, &strip) < 0)
                goto bad_entries;
            size_t copy_len = 0;
            if (parsed) {
                if (strip > previous_len) goto bad_entries;
                copy_len = previous_len - strip;
            }
            size_t have = parsed ? strlen (entries[parsed - 1].path) : 0;
            size_t prefix = copy_len < have ? copy_len : have;
            size_t flags_len = e->flags & 0xfff;
            size_t span = 0, window_n = 0;
            int clip = 0;
            if (flags_len == 0xfff) {
                const unsigned char *nul = memchr (buf + off, 0, limit - off);
                if (!nul) {
                    if (!last) goto bad_entries;
                    clip = 1;
                    window_n = limit - off;
                } else {
                    window_n = (size_t) (nul - buf - off);
                    span = window_n + 1;
                    previous_len = copy_len + window_n;
                }
            } else {
                if (flags_len + 1 < copy_len) {
                    /* Git copies a wrapped size. glibc's overlap path
                       rewrites earlier cache entries and still lists.
                       Reparse the whole index that way, in owned memory. */
                    bgit_index_free_entries (entries, count);
                    entries = NULL;
                    if (bgit_v4_overlap_listing (path, buf, limit, count,
                                                 &entries, &off) < 0)
                        goto bad_entries;
                    goto listed;
                }
                span = flags_len + 1 - copy_len;
                if (span > limit - off) {
                    if (!last) goto bad_entries;
                    clip = 1;
                    window_n = limit - off;
                } else
                    window_n = span;
                previous_len = flags_len;
            }
            if (copy_len > have) {
                e->path = strdup (entries[parsed - 1].path);
                if (!e->path) goto bad_entries;
            } else if (bgit_index_listing_path (e, parsed ? entries[parsed - 1].path : NULL,
                                                prefix, buf + off, window_n) < 0)
                goto bad_entries;
            off = clip ? flen : off + span;
            continue;
        }
        size_t namelen = e->flags & 0xfff;
        if (namelen == 0xfff) {
            const unsigned char *nul = memchr (buf + off, 0, limit - off);
            if (!nul) {
                if (!last) goto bad_entries;
                if (bgit_index_listing_path (e, NULL, 0, buf + off, limit - off) < 0)
                    goto bad_entries;
                off = flen;
                continue;
            }
            namelen = (size_t) (nul - buf - off);
        }
        /* Explicit length: Git copies that many bytes plus one and stops
           the printed name at the first NUL inside them. */
        if (namelen + 1 > limit - off) {
            if (!last) goto bad_entries;
            if (bgit_index_listing_path (e, NULL, 0, buf + off, limit - off) < 0)
                goto bad_entries;
            off = flen;
            continue;
        }
        if (namelen > SIZE_MAX - 2) goto bad_entries;
        e->path = malloc (namelen + 2);
        if (!e->path) goto bad_entries;
        memcpy (e->path, buf + off, namelen + 1);
        e->path[namelen + 1] = 0;
        off += namelen + 1;
        size_t consumed = off - start;
        if (consumed > SIZE_MAX - 7) goto bad_entries;
        size_t padded_size = (consumed + 7) & ~(size_t) 7;
        if (padded_size > limit - start) {
            if (!last) goto bad_entries;
            off = flen;
        } else
            off = start + padded_size;
    }
listed:
    bgit_index_stamp (path);
    *out = entries; *n_out = count; *backing = buf;
    *flen_out = flen; *extensions_out = off;
    return 0;
bad_entries:
    if (entries)
        bgit_index_free_entries (entries, count);
invalid:
    builtin_error ("%s: invalid or truncated index", path);
    free (buf);
    return -1;
}

/* A shared index is named by this checksum. Verify its contents before
   trusting that name, even though ordinary ls-files does not hash trailers. */
int
bgit_index_verify_checksum (const unsigned char *buf, size_t len)
{
    if (len < 32) return -1;
    if (bgit_index_checksum_cached (buf, len)) return 0;
    unsigned char computed[20];
    bgit_index_sha1 (buf, len - 20, computed);
    if (memcmp (computed, buf + len - 20, 20)) return -1;
    bgit_index_remember_verified (buf, len);
    return 0;
}

int
bgit_index_decode_views (const char *path, bgit_index_view *views, size_t n,
                         unsigned char *backing, bgit_index_entry **out,
                         size_t *n_out)
{
    bgit_index_stamp (path);
    bgit_index_entry *entries = calloc (n ? n : 1, sizeof *entries);
    if (!entries) { free (views); free (backing); return -1; }
    for (size_t i = 0; i < n; i++) {
        const unsigned char *disk = views[i].disk;
        bgit_index_entry *e = &entries[i];
        e->ctime_sec  = bgit_be32 (disk, 0);
        e->ctime_nsec = bgit_be32 (disk, 4);
        e->mtime_sec  = bgit_be32 (disk, 8);
        e->mtime_nsec = bgit_be32 (disk, 12);
        e->dev        = bgit_be32 (disk, 16);
        e->ino        = bgit_be32 (disk, 20);
        e->mode       = bgit_be32 (disk, 24);
        e->uid        = bgit_be32 (disk, 28);
        e->gid        = bgit_be32 (disk, 32);
        e->size       = bgit_be32 (disk, 36);
        memcpy (e->sha, disk + 40, 20);
        e->flags = bgit_be16 (disk, 60);
        if (bgit_be32 (backing, 4) >= 3 && (e->flags & 0x4000))
            e->flags2 = bgit_be16 (disk, 62);
        e->path = strdup (views[i].path);
        if (!e->path) {
            bgit_index_free_entries (entries, i);
            free (views); free (backing);
            return -1;
        }
    }
    free (views); free (backing);
    *out = entries;
    *n_out = n;
    return 0;
}

int
bgit_index_write (const char *path, bgit_index_entry *entries, size_t n)
{
    return bgit_index_write_ext (path, entries, n, NULL, 0);
}

int
bgit_index_write_ext (const char *path, bgit_index_entry *entries, size_t n,
                      const unsigned char *ext, size_t ext_len)
{
    if (n > UINT32_MAX) { builtin_error ("too many index entries"); return -1; }
    /* Build buffer in memory, then mkstemp + rename. */
    size_t cap = 4096, len = 0;
    unsigned char *buf = malloc (cap);
    if (!buf) return -1;

    uint32_t version = 2;
    for (size_t i = 0; i < n; i++) {
        if (entries[i].flags2 & ~0x6000) {
            builtin_error ("unknown extended index flags");
            free (buf);
            return -1;
        }
        if (entries[i].flags2) version = 3;
    }
    /* Header */
    memcpy (buf + len, "DIRC", 4); len += 4;
    bgit_put_be32 (buf + len, version); len += 4;
    bgit_put_be32 (buf + len, (uint32_t) n); len += 4;

    for (size_t i = 0; i < n; i++) {
        bgit_index_entry *e = &entries[i];
        if (!bgit_index_path_valid (e->path)) {
            builtin_error ("invalid index path '%s'", e->path ? e->path : "");
            free (buf);
            return -1;
        }
        size_t path_len = strlen (e->path);
        if (path_len > SIZE_MAX - 72) { free (buf); return -1; }
        size_t entry_len = 62 + (e->flags2 ? 2 : 0) + path_len;
        size_t pad = (8 - (entry_len % 8));
        if (pad == 0) pad = 8;
        size_t need = entry_len + pad;
        if (need > SIZE_MAX - len - 20) { free (buf); return -1; }
        if (len + need > cap) {
            while (len + need > cap) {
                if (cap > SIZE_MAX / 2) { cap = len + need; break; }
                cap *= 2;
            }
            unsigned char *nb = realloc (buf, cap);
            if (!nb) { free (buf); return -1; }
            buf = nb;
        }
        bgit_put_be32 (buf + len, e->ctime_sec);   len += 4;
        bgit_put_be32 (buf + len, e->ctime_nsec);  len += 4;
        bgit_put_be32 (buf + len, e->mtime_sec);   len += 4;
        bgit_put_be32 (buf + len, e->mtime_nsec);  len += 4;
        bgit_put_be32 (buf + len, e->dev);         len += 4;
        bgit_put_be32 (buf + len, e->ino);         len += 4;
        bgit_put_be32 (buf + len, e->mode);        len += 4;
        bgit_put_be32 (buf + len, e->uid);         len += 4;
        bgit_put_be32 (buf + len, e->gid);         len += 4;
        /* An entry racy against the index we read is written with size
           zero, as git writes it: the next process then sees the size
           disagree and reads the file rather than trusting the stat. */
        bgit_put_be32 (buf + len, bgit_index_racy (e) ? 0 : e->size);
        len += 4;
        memcpy (buf + len, e->sha, 20);            len += 20;
        /* Emit CE_EXTENDED only when its following flags word is present. */
        uint16_t flags = (uint16_t) ((e->flags & 0xB000)
            | (path_len > 0xFFF ? 0xFFF : path_len));
        if (e->flags2) flags |= 0x4000;
        bgit_put_be16 (buf + len, flags);          len += 2;
        if (e->flags2) {
            bgit_put_be16 (buf + len, e->flags2); len += 2;
        }
        memcpy (buf + len, e->path, path_len);     len += path_len;
        memset (buf + len, 0, pad);                len += pad;
    }

    /* Extension records the caller has laid out, then the trailer: the
       SHA-1 of everything before it. */
    if (ext_len > SIZE_MAX - len - 20) { free (buf); return -1; }
    if (len + ext_len + 20 > cap) {
        cap = len + ext_len + 20;
        unsigned char *nb = realloc (buf, cap);
        if (!nb) { free (buf); return -1; }
        buf = nb;
    }
    if (ext_len) memcpy (buf + len, ext, ext_len);
    len += ext_len;
    unsigned char digest[20];
    bgit_index_sha1 (buf, len, digest);
    if (len + 20 > cap) {
        cap = len + 20;
        unsigned char *nb = realloc (buf, cap);
        if (!nb) { free (buf); return -1; }
        buf = nb;
    }
    memcpy (buf + len, digest, 20); len += 20;

    /* Atomic write. */
    char tmp[4096];
    if (snprintf (tmp, sizeof tmp, "%s.tmpXXXXXX", path) >= (int) sizeof tmp) {
        free (buf); builtin_error ("index path too long"); return -1;
    }
    int fd = mkstemp (tmp);
    if (fd < 0) { free (buf); builtin_error ("mkstemp: %s", strerror (errno)); return -1; }
    fchmod (fd, 0644);
    size_t off = 0;
    while (off < len) {
        ssize_t w = write (fd, buf + off, len - off);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            builtin_error ("write %s: %s", tmp, w < 0 ? strerror (errno) : "short write");
            close (fd); unlink (tmp); free (buf); return -1;
        }
        off += w;
    }
    int sync_rc = fdatasync (fd);
    int sync_errno = errno;
    int close_rc = close (fd);
    if (sync_rc < 0 || close_rc < 0) {
        builtin_error ("%s %s: %s", sync_rc < 0 ? "fdatasync" : "close", tmp,
                       strerror (sync_rc < 0 ? sync_errno : errno));
        unlink (tmp); free (buf); return -1;
    }
    if (rename (tmp, path) < 0) {
        unlink (tmp); free (buf);
        builtin_error ("rename: %s", strerror (errno));
        return -1;
    }
    free (buf);
    return 0;
}

int
bgit_index_line_to_entry (const char *line, const char *working_root,
                          bgit_index_entry *out)
{
    /* Split: mode sha stage path */
    char mode_s[16], sha_s[64], stage_s[16];
    int stage;
    int prefix_len = 0;
    if (sscanf (line, "%15s %63s %15s %n", mode_s, sha_s, stage_s, &prefix_len) < 3) {
        return -1;
    }
    if (bgit_index_parse_stage (stage_s, &stage) < 0)
        return -2;
    const char *path = line + prefix_len;
    /* Trim trailing newline */
    size_t pl = strlen (path);
    while (pl > 0 && (path[pl-1] == '\n' || path[pl-1] == '\r')) pl--;
    if (pl == 0) return -1;

    memset (out, 0, sizeof *out);
    if (bgit_index_parse_mode (mode_s, &out->mode) < 0) return -1;
    if (bgit_hex_to_sha (sha_s, out->sha) < 0) return -1;
    out->flags = (uint16_t) (((stage & 0x3) << 12) | (pl > 0xFFF ? 0xFFF : pl));
    out->path = malloc (pl + 1);
    if (!out->path) return -1;
    memcpy (out->path, path, pl);
    out->path[pl] = '\0';
    if (!bgit_index_path_valid (out->path)) {
        free (out->path);
        out->path = NULL;
        return -1;
    }

    /* If working_root + path resolves, populate stat fields. */
    if (working_root) {
        char fp[8192];
        snprintf (fp, sizeof fp, "%s/%s", working_root, out->path);
        struct stat st;
        if (stat (fp, &st) == 0) {
            bgit_index_entry_set_stat (out, &st);
        }
    }
    return 0;
}

int
bgit_index_path_cmp (const void *a, const void *b)
{
    const bgit_index_entry *ea = a, *eb = b;
    int r = strcmp (ea->path, eb->path);
    if (r != 0)
        return r;
    int sa = (ea->flags >> 12) & 0x3;
    int sb = (eb->flags >> 12) & 0x3;
    return sa - sb;
}

int
bgit_index_remove_path (bgit_index_entry **entries, size_t *n, const char *path)
{
    size_t w = 0;
    int removed = 0;

    for (size_t r = 0; r < *n; r++) {
        if (strcmp ((*entries)[r].path, path) == 0) {
            free ((*entries)[r].path);
            removed = 1;
            continue;
        }
        if (w != r)
            (*entries)[w] = (*entries)[r];
        w++;
    }
    *n = w;
    return removed;
}

int
bgit_index_info_line_to_entry (char *line, bgit_index_entry *out,
                               int *is_remove)
{
    char *tab = strchr (line, '\t');
    char *path;
    char *tok[3] = { NULL, NULL, NULL };
    int ntok = 0;
    char *save = NULL;
    uint32_t mode;
    const char *sha_s;
    int stage = 0;

    *is_remove = 0;
    if (!tab)
        return -1;
    *tab = '\0';
    path = tab + 1;
    size_t pl = strlen (path);
    while (pl > 0 && (path[pl-1] == '\n' || path[pl-1] == '\r')) {
        path[--pl] = '\0';
    }
    if (!bgit_index_path_valid (path))
        return -1;

    for (char *p = strtok_r (line, " ", &save);
         p && ntok < 3;
         p = strtok_r (NULL, " ", &save)) {
        tok[ntok++] = p;
    }
    if (strtok_r (NULL, " ", &save) != NULL)
        return -1;
    if (ntok != 2 && ntok != 3)
        return -1;
    if (bgit_index_parse_mode (tok[0], &mode) < 0)
        return -1;

    if (ntok == 2) {
        sha_s = tok[1];                 /* mode SP sha1 TAB path */
    } else if (strlen (tok[1]) == 40 &&
               bgit_index_parse_stage (tok[2], &stage) == 0) {
        sha_s = tok[1];                 /* mode SP sha1 SP stage TAB path */
    } else {
        sha_s = tok[2];                 /* mode SP type SP sha1 TAB path */
        stage = 0;
    }

    memset (out, 0, sizeof *out);
    out->mode = mode;
    if (bgit_hex_to_sha (sha_s, out->sha) < 0)
        return -1;
    if (mode == 0) {
        *is_remove = 1;
        out->path = strdup (path);
        return out->path ? 0 : -1;
    }
    if (stage < 0 || stage > 3)
        return -1;
    out->flags = (uint16_t) (((stage & 0x3) << 12) | (pl > 0xFFF ? 0xFFF : pl));
    out->path = strdup (path);
    return out->path ? 0 : -1;
}

/* ---- resolve-undo ------------------------------------------------------- */

/* Where an index's extensions begin, which is after its entries. The file
   is returned mapped; the caller frees it. Silent. */
static int
bgit_index_after_entries (const char *path, unsigned char **buf_out,
                          size_t *flen_out, size_t *off_out)
{
    size_t flen;
    unsigned char *buf = bgit_index_slurp (path, &flen);
    if (!buf) return -1;
    if (flen < 32 || memcmp (buf, "DIRC", 4) != 0) { free (buf); return -1; }
    uint32_t ver = bgit_be32 (buf, 4);
    if (ver != 2 && ver != 3) { free (buf); return -1; }
    uint32_t n_entries = bgit_be32 (buf, 8);

    size_t off = 12;
    for (uint32_t i = 0; i < n_entries; i++) {
        if (off + 62 > flen - 20) { free (buf); return -1; }
        uint16_t flags = bgit_be16 (buf, off + 60);
        off += 62;
        size_t extended_len = 0;
        if (ver >= 3 && (flags & 0x4000)) {
            if (off + 2 > flen - 20) { free (buf); return -1; }
            off += 2;
            extended_len = 2;
        }
        size_t path_len = flags & 0xFFF;
        const unsigned char *nul = memchr (buf + off, 0, flen - 20 - off);
        if (path_len == 0xFFF && nul) path_len = (size_t) (nul - buf - off);
        if (!nul || (size_t) (nul - buf - off) != path_len) {
            free (buf);
            return -1;
        }
        off += path_len;
        size_t entry_len = 62 + extended_len + path_len;
        size_t pad = 8 - (entry_len % 8);
        if (pad > flen - 20 - off) { free (buf); return -1; }
        off += pad;
    }
    *buf_out = buf;
    *flen_out = flen;
    *off_out = off;
    return 0;
}

/* Room for one more id in a growing list. Returns 0, or -1. */
static int
bgit_index_ids_room (char (**ids)[41], size_t n, size_t *cap)
{
    if (n < *cap) return 0;
    size_t next = *cap ? *cap * 2 : 16;
    char (*grown)[41] = realloc (*ids, next * sizeof *grown);
    if (!grown) return -1;
    *ids = grown;
    *cap = next;
    return 0;
}

/* The extension holds, for each path whose conflict was resolved, the three
   stage modes as octal text and one object id for every mode that is not
   zero. Nothing else here reads it; fsck counts those ids as held. */
int
bgit_index_resolve_undo (const char *path, char (**out)[41], size_t *n_out)
{
    *out = NULL;
    *n_out = 0;
    unsigned char *buf = NULL;
    size_t flen = 0, off = 0;
    if (bgit_index_after_entries (path, &buf, &flen, &off) < 0) return -1;

    char (*ids)[41] = NULL;
    size_t n = 0, cap = 0;
    while (off + 8 <= flen - 20) {
        uint32_t size = bgit_be32 (buf, off + 4);
        const unsigned char *body = buf + off + 8;
        if (size > flen - 20 - off - 8) break;
        if (memcmp (buf + off, "REUC", 4) == 0) {
            size_t at = 0;
            while (at < size) {
                /* the path, then three modes, then an id per mode that is set */
                const unsigned char *end = memchr (body + at, 0, size - at);
                if (!end) break;
                at = (size_t) (end - body) + 1;
                int set[3] = { 0, 0, 0 };
                int ok = 1;
                for (int stage = 0; stage < 3 && ok; stage++) {
                    end = at < size ? memchr (body + at, 0, size - at) : NULL;
                    if (!end) { ok = 0; break; }
                    set[stage] = (end - (body + at)) > 0 && body[at] != '0';
                    at = (size_t) (end - body) + 1;
                }
                if (!ok) break;
                for (int stage = 0; stage < 3; stage++) {
                    if (!set[stage]) continue;
                    if (at + 20 > size) { ok = 0; break; }
                    if (bgit_index_ids_room (&ids, n, &cap) < 0) {
                        free (ids);
                        free (buf);
                        return -1;
                    }
                    bgit_sha_to_hex (body + at, ids[n]);
                    n++;
                    at += 20;
                }
                if (!ok) break;
            }
        }
        off += 8 + size;
    }
    free (buf);
    *out = ids;
    *n_out = n;
    return 0;
}

/* The trees an index has already worked out for the paths it holds (its
   cache-tree extension), which git counts as held even before a commit
   names them. An entry is
       <name>\0<entries> <subtrees>\n[<20-byte id>]
   laid out from the top down; a negative entry count means the tree is not
   worked out yet and no id follows. */
int
bgit_index_cache_tree (const char *path, char (**out)[41], size_t *n_out)
{
    *out = NULL;
    *n_out = 0;
    unsigned char *buf = NULL;
    size_t flen = 0, off = 0;
    if (bgit_index_after_entries (path, &buf, &flen, &off) < 0) return -1;

    char (*ids)[41] = NULL;
    size_t n = 0, cap = 0;
    while (off + 8 <= flen - 20) {
        uint32_t size = bgit_be32 (buf, off + 4);
        const unsigned char *body = buf + off + 8;
        if (size > flen - 20 - off - 8) break;
        if (memcmp (buf + off, "TREE", 4) == 0) {
            size_t at = 0;
            while (at < size) {
                const unsigned char *end = memchr (body + at, 0, size - at);
                if (!end) break;
                at = (size_t) (end - body) + 1;
                /* "<entries> <subtrees>\n" */
                const unsigned char *line =
                    at < size ? memchr (body + at, '\n', size - at) : NULL;
                if (!line) break;
                char counts[64];
                size_t line_len = (size_t) (line - (body + at));
                if (line_len >= sizeof counts) break;
                memcpy (counts, body + at, line_len);
                counts[line_len] = '\0';
                at = (size_t) (line - body) + 1;
                long entries = strtol (counts, NULL, 10);
                if (entries < 0) continue;      /* not worked out yet */
                if (at + 20 > size) break;
                if (bgit_index_ids_room (&ids, n, &cap) < 0) {
                    free (ids);
                    free (buf);
                    return -1;
                }
                bgit_sha_to_hex (body + at, ids[n]);
                n++;
                at += 20;
            }
        }
        off += 8 + size;
    }
    free (buf);
    *out = ids;
    *n_out = n;
    return 0;
}
