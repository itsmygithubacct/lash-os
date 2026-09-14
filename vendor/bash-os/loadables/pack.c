/* SPDX-License-Identifier: MIT */
/* pack.c — git packfile reader.
 *
 * Phase W W-2. Loose-object support is in obj (W-1a/W-1b); pack
 * reads `.git/objects/pack/pack-<sha>.{pack,idx}` and resolves
 * OFS_DELTA + REF_DELTA chains so repos that have run `git gc` are
 * usable.
 *
 * Verbs:
 *   pack list-objects IDX
 *       Enumerate every SHA in the .idx file (one per line).
 *   pack cat PACK IDX SHA
 *       Decompress + delta-resolve the object at SHA in PACK,
 *       emit raw content (no header) on stdout.
 *   pack list-packs REPO
 *       List every <repo>/.git/objects/pack/pack-*.idx file.
 *   pack unpack PACK REPO
 *       Unpack a fetched .pack into loose objects under REPO/.git/objects/.
 *   pack create OUTFILE [--idx IDXFILE] [-r REPO] SHA [SHA...]
 *       (Stage 10 W-2 follow-up, 2026-05-07.) Inverse of unpack: build
 *       a pack v2 file from a list of loose-object SHAs. With --idx,
 *       also writes the paired v2 .idx. Always emits full bases (no
 *       delta encoding); the receive-pack server can still apply
 *       pack-deltas on its end.
 *
 * Format references:
 *   .idx v2:  https://git-scm.com/docs/pack-format
 *     header: \377tOc + 4-byte BE version (2)
 *     fanout: 256 × 4-byte BE cumulative count by first SHA byte
 *     sha[]:  N × 20 bytes
 *     crc[]:  N × 4 bytes
 *     ofs[]:  N × 4 bytes (high-bit set → index into 64-bit overflow)
 *     ofs64[]: optional 8-byte BE entries
 *     trailer: pack SHA-1 + idx SHA-1 (40 bytes)
 *
 *   .pack:
 *     header: "PACK" + 4-byte BE version + 4-byte BE object count
 *     N objects: variable-length size header + zlib data (or delta data)
 *     trailer: 20-byte pack SHA-1
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
#include <limits.h>
#include <stdint.h>
#include <sys/stat.h>
#include <dirent.h>
#include <zlib.h>

#include "loadables.h"
#include "_sha1dc_sha1.h"

enum bp_obj_type {
    BP_COMMIT = 1, BP_TREE = 2, BP_BLOB = 3, BP_TAG = 4,
    BP_OFS_DELTA = 6, BP_REF_DELTA = 7
};

/* Maximum delta chain depth for OFS_DELTA/REF_DELTA resolution.
 * Prevents stack overflow from maliciously deep delta chains.
 * Real git defaults to 50; we match that limit. */
#define BP_MAX_DELTA_DEPTH 50

static const char *
bp_type_name (int t)
{
    switch (t) {
    case BP_COMMIT: return "commit";
    case BP_TREE:   return "tree";
    case BP_BLOB:   return "blob";
    case BP_TAG:    return "tag";
    default:        return "delta";
    }
}

/* --- big-endian readers --- */
static uint32_t
bp_be32 (const unsigned char *b)
{
    return ((uint32_t) b[0] << 24) | ((uint32_t) b[1] << 16) |
           ((uint32_t) b[2] <<  8) | ((uint32_t) b[3]);
}

static uint64_t
bp_be64 (const unsigned char *b)
{
    return ((uint64_t) b[0] << 56) | ((uint64_t) b[1] << 48) |
           ((uint64_t) b[2] << 40) | ((uint64_t) b[3] << 32) |
           ((uint64_t) b[4] << 24) | ((uint64_t) b[5] << 16) |
           ((uint64_t) b[6] <<  8) | ((uint64_t) b[7]);
}

/* --- mmap-style file slurp (we just read the whole file). ---
 *
 * Guards added:
 *   - st.st_size is off_t (signed). On a directory, pipe, or special
 *     file fstat() can return a negative or unusually large size that,
 *     cast directly to size_t for malloc(), wraps to a huge unsigned
 *     value (or fails with ENOMEM on 32-bit hosts, but only after
 *     wasting the allocator dance). Reject early.
 *   - 0-byte files are accepted: malloc(0) is implementation-defined,
 *     so we allocate a 1-byte buffer to guarantee a non-NULL return
 *     for the caller and report length 0 honestly.
 */
static unsigned char *
bp_slurp (const char *path, size_t *out_len)
{
    int fd = open (path, O_RDONLY);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat (fd, &st) < 0) { close (fd); return NULL; }
    if (st.st_size < 0) { close (fd); errno = EINVAL; return NULL; }
    size_t need = (size_t) st.st_size;
    if ((off_t) need != st.st_size) {
        /* off_t > size_t on a hypothetical 32-bit host with 64-bit
         * off_t. Truncation would silently lose high bits. */
        close (fd); errno = EFBIG; return NULL;
    }
    unsigned char *buf = malloc (need ? need : 1);
    if (!buf) { close (fd); return NULL; }
    size_t got = 0;
    while (got < need) {
        ssize_t r = read (fd, buf + got, need - got);
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; break; }
        got += (size_t) r;
    }
    close (fd);
    *out_len = got;
    return buf;
}

/* hex helpers */
static void
bp_sha_to_hex (const unsigned char *sha, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (int i = 0; i < 20; i++) {
        out[2*i] = d[sha[i] >> 4]; out[2*i+1] = d[sha[i] & 0xF];
    }
    out[40] = '\0';
}

static int
bp_sha1 (const unsigned char *data, size_t n, unsigned char digest[20])
{
    SHA1_CTX ctx;
    SHA1DCInit (&ctx);
    SHA1DCSetSafeHash (&ctx, 0);
    SHA1DCUpdate (&ctx, (const char *) data, n);
    return SHA1DCFinal (digest, &ctx) == 0 ? 0 : -1;
}

static int
bp_deflate (const unsigned char *data, size_t n, unsigned char **out, size_t *out_len)
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
    if (rc != Z_STREAM_END) { free (buf); deflateEnd (&s); return -1; }
    *out = buf;
    *out_len = cap - s.avail_out;
    deflateEnd (&s);
    return 0;
}

static int
bp_write_loose (const char *repo, const char *sha, const unsigned char *deflated, size_t dlen)
{
    char objdir[4096], dir[4096], path[4096], tmp[4096];
    char dotgit[4096];
    snprintf (dotgit, sizeof dotgit, "%s/.git", repo);
    mkdir (dotgit, 0755);
    snprintf (objdir, sizeof objdir, "%s/.git/objects", repo);
    mkdir (objdir, 0755);
    snprintf (dir, sizeof dir, "%s/%c%c", objdir, sha[0], sha[1]);
    snprintf (path, sizeof path, "%s/%s", dir, sha + 2);
    struct stat st;
    if (stat (path, &st) == 0) return 0;
    if (mkdir (dir, 0755) < 0 && errno != EEXIST) {
        builtin_error ("mkdir %s: %s", dir, strerror (errno));
        return -1;
    }
    snprintf (tmp, sizeof tmp, "%s.tmpXXXXXX", path);
    int fd = mkstemp (tmp);
    if (fd < 0) { builtin_error ("mkstemp %s: %s", tmp, strerror (errno)); return -1; }
    fchmod (fd, 0444);
    size_t off = 0;
    while (off < dlen) {
        ssize_t w = write (fd, deflated + off, dlen - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            builtin_error ("write %s: %s", tmp, strerror (errno));
            close (fd); unlink (tmp); return -1;
        }
        off += (size_t) w;
    }
    fdatasync (fd);
    close (fd);
    if (rename (tmp, path) < 0) {
        builtin_error ("rename %s -> %s: %s", tmp, path, strerror (errno));
        unlink (tmp); return -1;
    }
    return 0;
}

static int
bp_hex_to_sha (const char *hex, unsigned char *sha)
{
    if (strlen (hex) != 40) return -1;
    for (int i = 0; i < 20; i++) {
        int hi = hex[2*i], lo = hex[2*i+1];
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

/* --- list-objects: walk every SHA in idx ------------------------------- */
static int
bp_list_objects_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("list-objects: IDX path required"); return EX_USAGE; }
    const char *idx_path = args->word->word;
    size_t ilen;
    unsigned char *idx = bp_slurp (idx_path, &ilen);
    if (!idx) { builtin_error ("read %s: %s", idx_path, strerror (errno)); return EXECUTION_FAILURE; }
    /* v2 magic */
    if (ilen < 8 || memcmp (idx, "\377tOc", 4) != 0) {
        free (idx);
        builtin_error ("not a v2 idx (or unsupported v1)");
        return EXECUTION_FAILURE;
    }
    uint32_t ver = bp_be32 (idx + 4);
    if (ver != 2) {
        free (idx);
        builtin_error ("unsupported idx version %u", ver);
        return EXECUTION_FAILURE;
    }
    /* Fanout (256×4 = 1024 bytes at offset 8) must fit. Without this
     * gate, the bp_be32 at `idx + 1028` below reads OOB on any idx
     * with 8 ≤ ilen < 1032. The subsequent truncation check at
     * `ilen < 1032 + sha_bytes` would still typically reject (since
     * the OOB-read `n` lands in zero-padded heap and `sha_bytes` is
     * 0, making the check `ilen < 1032` which holds), but the OOB
     * read itself is the defect — it's UB and triggers ASan / will
     * surface as a real read past malloc'd bounds on hardened
     * allocators. */
    if (ilen < 1032) {
        free (idx);
        builtin_error ("idx truncated (fanout)");
        return EXECUTION_FAILURE;
    }
    /* fanout @ +8, 256×4 = 1024 bytes; total objects = fanout[255] */
    uint32_t n = bp_be32 (idx + 8 + 255 * 4);
    /* SHAs start at offset 8 + 1024 = 1032. The original
     *   `ilen < 1032 + n * 20U`
     * does the multiplication in uint32_t arithmetic — for n > ~2.1e8
     * (4 GiB / 20) the product wraps and the truncation check passes
     * incorrectly, so the indexed read at `idx + 1032 + i*20` walks
     * past the buffer. Promote to size_t and add a multiplication-
     * overflow guard. */
    size_t sha_bytes = (size_t) n * 20;
    if (n != 0 && sha_bytes / 20 != (size_t) n) {
        free (idx);
        builtin_error ("idx object count %u overflows size", n);
        return EXECUTION_FAILURE;
    }
    if (sha_bytes > SIZE_MAX - 1032) {
        free (idx);
        builtin_error ("idx object count %u overflows size", n);
        return EXECUTION_FAILURE;
    }
    if (ilen < 1032 + sha_bytes) {
        free (idx);
        builtin_error ("idx truncated");
        return EXECUTION_FAILURE;
    }
    char hex[41];
    for (uint32_t i = 0; i < n; i++) {
        bp_sha_to_hex (idx + 1032 + (size_t) i * 20, hex);
        puts (hex);
    }
    free (idx);
    return EXECUTION_SUCCESS;
}

/* --- pack object lookup: idx → offset ----------------------------------
 *
 * Returns pack offset for SHA, or (uint64_t)-1 if not found OR if the
 * idx is too small / malformed for the indexed read. Every memory
 * dereference is gated by an explicit size check derived from
 * fanout[255]; a malicious idx with an inflated fanout count, missing
 * CRC/offset tables, or a 64-bit-overflow index pointing past the file
 * returns "not found" rather than reading OOB.
 */
static uint64_t
bp_lookup_offset (const unsigned char *idx, size_t ilen, const unsigned char *sha)
{
    if (ilen < 1032) return (uint64_t) -1;
    uint32_t hi = sha[0];
    uint32_t lo = (hi == 0) ? 0 : bp_be32 (idx + 8 + (hi - 1) * 4);
    uint32_t up = bp_be32 (idx + 8 + hi * 4);
    uint32_t total = bp_be32 (idx + 8 + 255 * 4);
    /* Fanout monotonicity: lo <= up <= total. A forged idx with
     * lo > up would skip the search loop silently; with up > total
     * the SHA-table read at `idx + 1032 + i*20` for i in [lo, up)
     * could walk past the SHA table into the CRC32 / offsets region
     * and silently match a CRC byte sequence. */
    if (lo > up || up > total) return (uint64_t) -1;
    /* Compute the size the SHA + CRC + 32-bit offsets tables need with
     * a multiplication-overflow guard (28 bytes per object). */
    size_t obj_bytes = (size_t) total * 28;
    if (total != 0 && obj_bytes / 28 != (size_t) total) return (uint64_t) -1;
    if (obj_bytes > SIZE_MAX - 1032) return (uint64_t) -1;
    size_t base_size = 1032 + obj_bytes;
    if (ilen < base_size) return (uint64_t) -1;
    /* Linear search in [lo, up). Could binary-search but range is small. */
    for (uint32_t i = lo; i < up; i++) {
        const unsigned char *cand = idx + 1032 + (size_t) i * 20;
        if (memcmp (cand, sha, 20) == 0) {
            const unsigned char *ofs = idx + 1032 + (size_t) total * 24;
            uint32_t v = bp_be32 (ofs + (size_t) i * 4);
            if (v & 0x80000000U) {
                /* 64-bit overflow; index = v & 0x7FFFFFFF. The 64-bit
                 * table sits at `ofs + total*4` and must accommodate
                 * `(idx64 + 1) * 8` bytes before any trailer. Bound
                 * (idx64 + 1) * 8 against the residual room in idx
                 * with explicit multiplication-overflow guards (idx64
                 * is uint32 up to ~2.1G; * 8 can overflow size_t on
                 * 32-bit hosts). */
                uint32_t idx64 = v & 0x7FFFFFFFU;
                const unsigned char *ofs64 = ofs + (size_t) total * 4;
                size_t hdr_offset = (size_t) (ofs64 - idx);
                if (hdr_offset > ilen) return (uint64_t) -1;
                size_t room = ilen - hdr_offset;
                size_t need = (size_t) idx64;
                if (need > (SIZE_MAX / 8) - 1) return (uint64_t) -1;
                need = (need + 1) * 8;
                if (need > room) return (uint64_t) -1;
                return bp_be64 (ofs64 + (size_t) idx64 * 8);
            }
            return v;
        }
    }
    return (uint64_t) -1;
}

/* --- read variable-length size + type from pack at offset --------------
 *
 * Wire format: first byte holds the 3-bit type + 4 low bits of size, with
 * the high bit set when more size bytes follow; each continuation byte
 * contributes 7 bits LSB-first. A well-formed header for a 64-bit size
 * is therefore at most 10 bytes (4 + 9*7 = 67 bits, capping the highest
 * useful shift at 60). A malformed pack with more continuation bytes
 * would shift past the width of `uint64_t` — undefined behavior under
 * the C standard — and could either crash or quietly read garbage off
 * the stack. The iteration + shift caps below bail with -1 on either
 * trip, so a forged header rejects cleanly rather than invoking UB. */
static int
bp_read_obj_header (const unsigned char *pack, size_t plen, uint64_t off,
                    int *type_out, uint64_t *size_out, uint64_t *new_off)
{
    if (off >= plen) return -1;
    unsigned char b = pack[off++];
    int type = (b >> 4) & 0x7;
    uint64_t size = b & 0xF;
    int shift = 4;
    int iters = 0;
    while (b & 0x80) {
        if (off >= plen) return -1;
        if (iters >= 9 || shift >= 64) return -1;
        b = pack[off++];
        size |= (uint64_t) (b & 0x7F) << shift;
        shift += 7;
        iters++;
    }
    *type_out = type;
    *size_out = size;
    *new_off = off;
    return 0;
}

/* Inflate src[srcn] into a malloc'd buffer of expected size (may be
   larger; we just decompress until Z_STREAM_END). Returns 0 + sets *out,
   *bytes_used (input bytes consumed). */
static int
bp_inflate (const unsigned char *src, size_t srcn, size_t expected,
            unsigned char **out, size_t *out_len, size_t *bytes_used)
{
    z_stream s = {0};
    if (inflateInit (&s) != Z_OK) return -1;
    s.next_in = (unsigned char *) src;
    s.avail_in = (uInt) srcn;
    size_t cap = expected + 64;
    if (cap < 64) cap = 64;
    unsigned char *buf = malloc (cap);
    size_t total = 0;
    int rc;
    do {
        if (total + 4096 > cap) {
            cap = cap * 2 + 4096;
            unsigned char *nb = realloc (buf, cap);
            if (!nb) { free (buf); inflateEnd (&s); return -1; }
            buf = nb;
        }
        s.next_out = buf + total;
        s.avail_out = (uInt) (cap - total);
        rc = inflate (&s, Z_NO_FLUSH);
        if (rc != Z_OK && rc != Z_STREAM_END) {
            free (buf); inflateEnd (&s); return -1;
        }
        total = cap - s.avail_out;
    } while (rc != Z_STREAM_END);
    *bytes_used = srcn - s.avail_in;
    inflateEnd (&s);
    *out = buf;
    *out_len = total;
    return 0;
}

/* Read variable-length integer (delta header). LSB first; high bit set
   continues. Returns value, advances off.
 *
 * A well-formed 64-bit varint is at most 10 bytes (9*7 = 63 bits + the
 * final 7-bit payload at shift=63). A malformed delta with more
 * continuation bytes would shift past the width of uint64_t — UB
 * under the C standard. The cap below stops reading after 10 bytes
 * (the 10th byte's `b & 0x80` is implicitly ignored); the caller
 * detects the malformed value via the downstream src_size/tgt_size
 * sanity checks (mismatch with baselen / oversized malloc fails). */
static uint64_t
bp_read_varint (const unsigned char *p, size_t n, size_t *off)
{
    uint64_t v = 0;
    int shift = 0;
    int iters = 0;
    while (*off < n && iters < 10 && shift < 64) {
        unsigned char b = p[(*off)++];
        v |= (uint64_t) (b & 0x7F) << shift;
        if (!(b & 0x80)) return v;
        shift += 7;
        iters++;
    }
    return v;
}

/* Apply git delta to base. Returns 0 + sets *out, *out_len on success. */
static int
bp_apply_delta (const unsigned char *base, size_t baselen,
                const unsigned char *delta, size_t deltan,
                unsigned char **out, size_t *out_len)
{
    size_t off = 0;
    uint64_t src_size = bp_read_varint (delta, deltan, &off);
    uint64_t tgt_size = bp_read_varint (delta, deltan, &off);
    if (src_size != baselen) return -1;
    /* Defensive size cap on tgt_size:
     * - tgt_size > SIZE_MAX would silently truncate when passed to
     *   malloc(size_t) on 32-bit hosts. Reject explicitly.
     * - A maliciously large tgt_size (e.g., near UINT64_MAX) would
     *   make every `bo + ... > tgt_size` check below pass trivially,
     *   masking the real bounds. The downstream copy/literal checks
     *   stay sound under the SIZE_MAX cap. */
    if (tgt_size > SIZE_MAX) return -1;
    unsigned char *buf = malloc ((size_t) tgt_size);
    if (!buf && tgt_size > 0) return -1;
    size_t bo = 0;
    while (off < deltan) {
        /* Each iteration consumes at least the op byte; bounds: off<deltan. */
        unsigned char op = delta[off++];
        if (op & 0x80) {
            /* Copy from base. The op byte's low 4 bits index up to 4
             * `copy_off` bytes from the delta; bits 4-6 index up to 3
             * `copy_size` bytes. Each indexed byte must lie inside
             * the delta buffer — without the per-byte bounds check
             * here a short malformed delta could read past `delta`. */
            uint64_t copy_off = 0, copy_size = 0;
            for (int i = 0; i < 4; i++) {
                if (op & (1 << i)) {
                    if (off >= deltan) { free (buf); return -1; }
                    copy_off  |= (uint64_t) delta[off++] << (i * 8);
                }
            }
            for (int i = 0; i < 3; i++) {
                if (op & (1 << (4 + i))) {
                    if (off >= deltan) { free (buf); return -1; }
                    copy_size |= (uint64_t) delta[off++] << (i * 8);
                }
            }
            if (copy_size == 0) copy_size = 0x10000;
            /* Overflow-safe bounds: rewrite `a + b > limit` as
             * `b > limit || a > limit - b` so a malicious
             * copy_off near UINT64_MAX cannot wrap the addition
             * and pass the original `> baselen` test. Same shape
             * for the output-buffer side. */
            if (copy_size > baselen || copy_off > baselen - copy_size) {
                free (buf); return -1;
            }
            if (copy_size > tgt_size || bo > tgt_size - copy_size) {
                free (buf); return -1;
            }
            memcpy (buf + bo, base + copy_off, (size_t) copy_size);
            bo += (size_t) copy_size;
        } else if (op > 0) {
            /* Insert literal. op = byte count. Overflow-safe bounds:
             * `op` is unsigned char (0..127 after the high-bit branch
             * above peeled off >=128), and `off` is size_t. The
             * original `off + op > deltan` could wrap if `off` were
             * near SIZE_MAX; checking `op > deltan - off` after the
             * `off <= deltan` invariant from the outer-loop guard
             * is wrap-safe. */
            if ((size_t) op > deltan - off) { free (buf); return -1; }
            if ((size_t) op > tgt_size - bo) { free (buf); return -1; }
            memcpy (buf + bo, delta + off, op);
            off += op;
            bo += op;
        } else {
            free (buf); return -1;
        }
    }
    *out = buf;
    *out_len = bo;
    return 0;
}

/* Read object at offset `off` in pack. Recursively resolves deltas
   (OFS_DELTA + REF_DELTA via REPO/.git/objects/<aa>/<bbbb...> for
   loose-object base or via same-pack lookup for ofs-delta).  DEPTH
   tracks the current delta chain length; returns -1 when it exceeds
   BP_MAX_DELTA_DEPTH to prevent stack overflow. */
static int
bp_read_object_at (const unsigned char *pack, size_t plen,
                   const unsigned char *idx, size_t ilen,
                   const char *repo,
                   uint64_t off,
                   int *type_out, unsigned char **out, size_t *out_len,
                   int depth)
{
    if (depth > BP_MAX_DELTA_DEPTH) return -1;
    int type;
    uint64_t expected;
    uint64_t cur;
    if (bp_read_obj_header (pack, plen, off, &type, &expected, &cur) < 0) return -1;

    if (type == BP_COMMIT || type == BP_TREE || type == BP_BLOB || type == BP_TAG) {
        size_t used;
        if (bp_inflate (pack + cur, plen - cur, (size_t) expected, out, out_len, &used) < 0)
            return -1;
        *type_out = type;
        return 0;
    }
    if (type == BP_OFS_DELTA) {
        /* base offset = current offset - varint (negative).
         * Three defects guarded here:
         *   1. cur could already be at plen (the header consumed all
         *      remaining bytes). Reading pack[cur++] would walk OOB.
         *   2. The continuation-byte loop didn't bounds-check cur, so
         *      a forged OFS_DELTA pointing at the end of the pack
         *      with the continuation bit set would read indefinitely.
         *   3. The arithmetic `((base_off_delta + 1) << 7) | ...` can
         *      overflow uint64_t for >9 iterations. Cap iterations at
         *      10 (max sensible varint width). */
        if (cur >= plen) return -1;
        unsigned char b = pack[cur++];
        uint64_t base_off_delta = b & 0x7F;
        int iters = 0;
        while (b & 0x80) {
            if (cur >= plen) return -1;
            if (iters >= 9) return -1;
            base_off_delta = ((base_off_delta + 1) << 7) | (pack[cur] & 0x7F);
            b = pack[cur++];
            iters++;
        }
        /* base_off must reference a position strictly before the
         * current OFS_DELTA header — git's wire format guarantees this
         * (delta points back). A malicious pack with base_off_delta
         * greater than off would underflow base_off and the recursive
         * call would then chase a wild pointer that the plen check
         * happens to bound — but the call still recurses with a bogus
         * offset that may legally collide with a real header far
         * downstream. Reject explicitly. */
        if (base_off_delta == 0 || base_off_delta > off) return -1;
        uint64_t base_off = off - base_off_delta;
        size_t used;
        unsigned char *delta;
        size_t dlen;
        if (bp_inflate (pack + cur, plen - cur, (size_t) expected, &delta, &dlen, &used) < 0)
            return -1;
        int base_type;
        unsigned char *base;
        size_t base_len;
        if (bp_read_object_at (pack, plen, idx, ilen, repo, base_off,
                               &base_type, &base, &base_len, depth + 1) < 0) {
            free (delta); return -1;
        }
        int rc = bp_apply_delta (base, base_len, delta, dlen, out, out_len);
        free (delta); free (base);
        if (rc < 0) return -1;
        *type_out = base_type;
        return 0;
    }
    if (type == BP_REF_DELTA) {
        if (cur + 20 > plen) return -1;
        unsigned char base_sha[20];
        memcpy (base_sha, pack + cur, 20);
        cur += 20;
        size_t used;
        unsigned char *delta;
        size_t dlen;
        if (bp_inflate (pack + cur, plen - cur, (size_t) expected, &delta, &dlen, &used) < 0)
            return -1;
        /* Look up base in same pack first. */
        uint64_t base_off = bp_lookup_offset (idx, ilen, base_sha);
        unsigned char *base; size_t base_len; int base_type;
        if (base_off != (uint64_t) -1) {
            if (bp_read_object_at (pack, plen, idx, ilen, repo, base_off,
                                   &base_type, &base, &base_len, depth + 1) < 0) {
                free (delta); return -1;
            }
        } else {
            /* Try loose object. */
            char hex[41]; bp_sha_to_hex (base_sha, hex);
            char path[4096];
            snprintf (path, sizeof path, "%s/.git/objects/%c%c/%s",
                      repo ? repo : ".", hex[0], hex[1], hex + 2);
            size_t fn;
            unsigned char *raw = bp_slurp (path, &fn);
            if (!raw) { free (delta); return -1; }
            unsigned char *infl;
            size_t inflen, used2;
            if (bp_inflate (raw, fn, 0, &infl, &inflen, &used2) < 0) {
                free (raw); free (delta); return -1;
            }
            free (raw);
            /* Strip "<type> <size>\0" header. */
            size_t hi = 0;
            while (hi < inflen && infl[hi] != '\0') hi++;
            if (hi >= inflen) { free (infl); free (delta); return -1; }
            /* Parse type from header */
            base_type = BP_BLOB;
            if (memcmp (infl, "commit", 6) == 0) base_type = BP_COMMIT;
            else if (memcmp (infl, "tree", 4) == 0) base_type = BP_TREE;
            else if (memcmp (infl, "blob", 4) == 0) base_type = BP_BLOB;
            else if (memcmp (infl, "tag", 3) == 0) base_type = BP_TAG;
            base = malloc (inflen - hi - 1);
            base_len = inflen - hi - 1;
            memcpy (base, infl + hi + 1, base_len);
            free (infl);
        }
        int rc = bp_apply_delta (base, base_len, delta, dlen, out, out_len);
        free (delta); free (base);
        if (rc < 0) return -1;
        *type_out = base_type;
        return 0;
    }
    return -1;
}

static int bp_verify_idx (const unsigned char *idx, size_t ilen,
                          const unsigned char *expected_pack_sha20);

/* --- cat verb ---------------------------------------------------------- */
static int
bp_cat_cmd (WORD_LIST *args)
{
    if (!args || !args->next || !args->next->next) {
        builtin_error ("cat: PACK IDX SHA [-r REPO]"); return EX_USAGE;
    }
    const char *pack_path = args->word->word;
    const char *idx_path  = args->next->word->word;
    const char *sha_hex   = args->next->next->word->word;
    const char *repo = NULL;
    for (WORD_LIST *p = args->next->next->next; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-r") == 0 && p->next) { repo = p->next->word->word; p = p->next; }
        else { builtin_error ("cat: unexpected '%s'", w); return EX_USAGE; }
    }

    unsigned char sha[20];
    if (bp_hex_to_sha (sha_hex, sha) < 0) { builtin_error ("bad sha"); return EX_USAGE; }
    size_t ilen, plen;
    unsigned char *idx = bp_slurp (idx_path, &ilen);
    if (!idx) { builtin_error ("read %s: %s", idx_path, strerror (errno)); return EXECUTION_FAILURE; }
    unsigned char *pack = bp_slurp (pack_path, &plen);
    if (!pack) { free (idx); builtin_error ("read %s: %s", pack_path, strerror (errno)); return EXECUTION_FAILURE; }
    if (plen < 32 || memcmp (pack, "PACK", 4) != 0) {
        free (idx); free (pack);
        builtin_error ("cat: not a packfile");
        return EXECUTION_FAILURE;
    }
    uint32_t pack_ver = bp_be32 (pack + 4);
    if (pack_ver != 2 && pack_ver != 3) {
        free (idx); free (pack);
        builtin_error ("cat: unsupported pack version %u", pack_ver);
        return EXECUTION_FAILURE;
    }
    if (plen < 40) {
        free (idx); free (pack);
        builtin_error ("cat: too short (no trailer)");
        return EXECUTION_FAILURE;
    }
    unsigned char pack_sha[20];
    if (bp_sha1 (pack, plen - 20, pack_sha) < 0) {
        free (idx); free (pack);
        builtin_error ("cat: SHA-1 init failed");
        return EXECUTION_FAILURE;
    }
    if (memcmp (pack_sha, pack + plen - 20, 20) != 0) {
        free (idx); free (pack);
        builtin_error ("cat: packfile SHA-1 mismatch (corrupt)");
        return EXECUTION_FAILURE;
    }
    if (bp_verify_idx (idx, ilen, pack + plen - 20) < 0) {
        free (idx); free (pack);
        return EXECUTION_FAILURE;
    }

    uint64_t off = bp_lookup_offset (idx, ilen, sha);
    if (off == (uint64_t) -1) {
        free (idx); free (pack);
        builtin_error ("cat: %s not in idx", sha_hex);
        return EXECUTION_FAILURE;
    }
    int type;
    unsigned char *content;
    size_t clen;
    if (bp_read_object_at (pack, plen, idx, ilen, repo, off, &type, &content, &clen, 0) < 0) {
        free (idx); free (pack);
        builtin_error ("cat: read failed for %s", sha_hex);
        return EXECUTION_FAILURE;
    }
    fwrite (content, 1, clen, stdout);
    free (content); free (idx); free (pack);
    (void) type;
    return EXECUTION_SUCCESS;
}

/* --- list-packs verb --------------------------------------------------- */
static int
bp_list_packs_cmd (WORD_LIST *args)
{
    const char *repo = args ? args->word->word : ".";
    char dir[4096];
    snprintf (dir, sizeof dir, "%s/.git/objects/pack", repo);
    DIR *d = opendir (dir);
    if (!d) { builtin_error ("opendir %s: %s", dir, strerror (errno)); return EXECUTION_FAILURE; }
    struct dirent *de;
    while ((de = readdir (d)) != NULL) {
        const char *n = de->d_name;
        size_t l = strlen (n);
        if (l > 4 && memcmp (n + l - 4, ".idx", 4) == 0) {
            printf ("%s/%s\n", dir, n);
        }
    }
    closedir (d);
    return EXECUTION_SUCCESS;
}

static int
bp_unpack_cmd (WORD_LIST *args)
{
    if (!args || !args->next) {
        builtin_error ("unpack: PACK REPO");
        return EX_USAGE;
    }
    const char *pack_path = args->word->word;
    const char *repo = args->next->word->word;
    size_t plen;
    unsigned char *pack = bp_slurp (pack_path, &plen);
    if (!pack) { builtin_error ("read %s: %s", pack_path, strerror (errno)); return EXECUTION_FAILURE; }
    if (plen < 32 || memcmp (pack, "PACK", 4) != 0) {
        free (pack);
        builtin_error ("unpack: not a packfile");
        return EXECUTION_FAILURE;
    }
    uint32_t ver = bp_be32 (pack + 4);
    uint32_t count = bp_be32 (pack + 8);
    if (ver != 2 && ver != 3) {
        free (pack);
        builtin_error ("unpack: unsupported pack version %u", ver);
        return EXECUTION_FAILURE;
    }

    /* Validate pack SHA-1 trailer: last 20 bytes = sha1 of all preceding bytes. */
    if (plen < 40) {
        free (pack);
        builtin_error ("unpack: too short (no trailer)");
        return EXECUTION_FAILURE;
    }
    {
        SHA1_CTX ctx;
        SHA1DCInit (&ctx);
        SHA1DCSetSafeHash (&ctx, 0);
        SHA1DCUpdate (&ctx, (const char *) pack, plen - 20);
        unsigned char computed[20];
        SHA1DCFinal (computed, &ctx);
        if (memcmp (computed, pack + plen - 20, 20) != 0) {
            free (pack);
            builtin_error ("unpack: packfile SHA-1 mismatch (corrupt)");
            return EXECUTION_FAILURE;
        }
    }

    size_t off = 12;
    uint32_t written = 0;
    for (uint32_t i = 0; i < count; i++) {
        size_t obj_off = off;
        int wire_type;
        uint64_t expected, data_off;
        if (bp_read_obj_header (pack, plen, obj_off, &wire_type, &expected, &data_off) < 0) {
            free (pack);
            builtin_error ("unpack: bad object header");
            return EXECUTION_FAILURE;
        }
        size_t zoff = (size_t) data_off;
        if (wire_type == BP_OFS_DELTA) {
            if (zoff >= plen) { free (pack); return EXECUTION_FAILURE; }
            unsigned char b = pack[zoff++];
            int iters = 0;
            while (b & 0x80) {
                if (zoff >= plen) { free (pack); return EXECUTION_FAILURE; }
                if (iters >= 9) { free (pack); return EXECUTION_FAILURE; }
                b = pack[zoff++];
                iters++;
            }
        } else if (wire_type == BP_REF_DELTA) {
            /* `zoff + 20 > plen` is overflow-unsafe if zoff is close
             * to SIZE_MAX (a malformed object header could push it
             * there). Rewrite as `20 > plen - zoff` after the
             * `zoff <= plen` invariant from the OFS arm just above. */
            if (zoff > plen || 20 > plen - zoff) { free (pack); return EXECUTION_FAILURE; }
            zoff += 20;
        }

        unsigned char *infl = NULL;
        size_t infl_len = 0, used = 0;
        if (bp_inflate (pack + zoff, plen - zoff, (size_t) expected, &infl, &infl_len, &used) < 0) {
            free (pack);
            builtin_error ("unpack: inflate failed");
            return EXECUTION_FAILURE;
        }
        free (infl);
        off = zoff + used;

        int type;
        unsigned char *content = NULL;
        size_t clen = 0;
        if (bp_read_object_at (pack, plen, NULL, 0, repo, obj_off, &type, &content, &clen, 0) < 0) {
            free (pack);
            builtin_error ("unpack: delta resolution failed at object %u", i + 1);
            return EXECUTION_FAILURE;
        }
        const char *tn = bp_type_name (type);
        char hdr[64];
        int hn = snprintf (hdr, sizeof hdr, "%s %zu", tn, clen);
        if (hn <= 0 || (size_t) hn + 1 >= sizeof hdr) {
            free (content); free (pack); return EXECUTION_FAILURE;
        }
        size_t prelen = (size_t) hn + 1 + clen;
        unsigned char *pre = malloc (prelen);
        if (!pre) { free (content); free (pack); return EXECUTION_FAILURE; }
        memcpy (pre, hdr, (size_t) hn);
        pre[hn] = '\0';
        memcpy (pre + hn + 1, content, clen);
        free (content);

        unsigned char digest[20];
        if (bp_sha1 (pre, prelen, digest) < 0) {
            free (pre); free (pack);
            builtin_error ("unpack: SHA-1 collision detected");
            return EXECUTION_FAILURE;
        }
        char hex[41];
        bp_sha_to_hex (digest, hex);
        unsigned char *deflated = NULL;
        size_t dlen = 0;
        if (bp_deflate (pre, prelen, &deflated, &dlen) < 0) {
            free (pre); free (pack); return EXECUTION_FAILURE;
        }
        free (pre);
        if (bp_write_loose (repo, hex, deflated, dlen) < 0) {
            free (deflated); free (pack); return EXECUTION_FAILURE;
        }
        free (deflated);
        written++;
    }
    free (pack);
    printf ("%u\n", written);
    return EXECUTION_SUCCESS;
}

/* --- create: build a pack v2 from a list of loose-object SHAs ---------- *
 *
 * Stage 10 W-2 follow-up (2026-05-07).  Symmetric inverse of `unpack`:
 * given OUTFILE + repo + SHA list, produce a pack v2 file with header
 * + per-object (variable-length type/size header + zlib body) + 20-byte
 * SHA-1 trailer.  Used by `git push` to assemble the receive-pack request
 * body; also useful for `git gc`-style local repacks.
 *
 * Out-of-scope (deferred): delta encoding (we always emit full base
 * objects).  A receive-pack server can still apply pack-deltas on its
 * end; for client-to-server push of small commit ranges, full-base is
 * fine and simpler to audit.
 */

/* Encode a pack object header byte stream.  Format:
 *   first byte: cont(1) | type(3) | size_low4(4)
 *   subsequent: cont(1) | size_next7(7)   (LSB-first)
 * Caller's `out` must hold ≥ 16 bytes (max for a 64-bit size).
 */
static void
bp_encode_obj_header (int type, size_t size, unsigned char *out, size_t *out_len)
{
    size_t i = 0;
    unsigned char b = (unsigned char) (((type & 0x7) << 4) | (size & 0xf));
    size >>= 4;
    if (size) b |= 0x80;
    out[i++] = b;
    while (size) {
        b = (unsigned char) (size & 0x7f);
        size >>= 7;
        if (size) b |= 0x80;
        out[i++] = b;
    }
    *out_len = i;
}

/* Read a loose object: inflate, parse "type SP size NUL content".
 * Sets *type_out (BP_COMMIT/TREE/BLOB/TAG) and a fresh malloc()'d
 * *content_out of length *clen_out (caller frees).  Returns 0 on
 * success, -1 otherwise. */
static int
bp_read_loose (const char *repo, const char *sha_hex, int *type_out,
               unsigned char **content_out, size_t *clen_out)
{
    if (strlen (sha_hex) != 40) return -1;
    char path[4096];
    snprintf (path, sizeof path, "%s/.git/objects/%c%c/%s",
              repo, sha_hex[0], sha_hex[1], sha_hex + 2);
    size_t rn = 0;
    unsigned char *raw = bp_slurp (path, &rn);
    if (!raw) return -1;
    unsigned char *infl = NULL;
    size_t inflen = 0, used = 0;
    int rc = bp_inflate (raw, rn, 0, &infl, &inflen, &used);
    free (raw);
    if (rc < 0) return -1;

    /* Parse header: "type SP size NUL ..." */
    unsigned char *sp = memchr (infl, ' ', inflen);
    if (!sp) { free (infl); return -1; }
    *sp = '\0';
    int type = 0;
    if      (!strcmp ((char *) infl, "commit")) type = BP_COMMIT;
    else if (!strcmp ((char *) infl, "tree"))   type = BP_TREE;
    else if (!strcmp ((char *) infl, "blob"))   type = BP_BLOB;
    else if (!strcmp ((char *) infl, "tag"))    type = BP_TAG;
    else { free (infl); return -1; }

    unsigned char *nul = memchr (sp + 1, '\0', inflen - (size_t) (sp + 1 - infl));
    if (!nul) { free (infl); return -1; }
    size_t hdr_len = (size_t) (nul - infl) + 1;
    size_t clen = inflen - hdr_len;
    unsigned char *content = malloc (clen ? clen : 1);
    if (!content) { free (infl); return -1; }
    if (clen) memcpy (content, infl + hdr_len, clen);
    free (infl);
    *type_out = type;
    *content_out = content;
    *clen_out = clen;
    return 0;
}

/* Append n bytes from p into a growing buffer (out, out_len, out_cap).
 * Realloc-on-demand. Returns 0 on success, -1 on alloc failure. */
static int
bp_buf_append (unsigned char **out, size_t *out_len, size_t *out_cap,
               const void *p, size_t n)
{
    if (*out_len + n > *out_cap) {
        size_t nc = *out_cap ? *out_cap * 2 : 4096;
        while (*out_len + n > nc) nc *= 2;
        unsigned char *nb = realloc (*out, nc);
        if (!nb) return -1;
        *out = nb;
        *out_cap = nc;
    }
    memcpy (*out + *out_len, p, n);
    *out_len += n;
    return 0;
}

static int
bp_buf_append_be32 (unsigned char **out, size_t *out_len, size_t *out_cap,
                    uint32_t v)
{
    unsigned char b[4];
    b[0] = (unsigned char) ((v >> 24) & 0xff);
    b[1] = (unsigned char) ((v >> 16) & 0xff);
    b[2] = (unsigned char) ((v >>  8) & 0xff);
    b[3] = (unsigned char) ( v        & 0xff);
    return bp_buf_append (out, out_len, out_cap, b, sizeof b);
}

static int
bp_buf_append_be64 (unsigned char **out, size_t *out_len, size_t *out_cap,
                    uint64_t v)
{
    unsigned char b[8];
    b[0] = (unsigned char) ((v >> 56) & 0xff);
    b[1] = (unsigned char) ((v >> 48) & 0xff);
    b[2] = (unsigned char) ((v >> 40) & 0xff);
    b[3] = (unsigned char) ((v >> 32) & 0xff);
    b[4] = (unsigned char) ((v >> 24) & 0xff);
    b[5] = (unsigned char) ((v >> 16) & 0xff);
    b[6] = (unsigned char) ((v >>  8) & 0xff);
    b[7] = (unsigned char) ( v        & 0xff);
    return bp_buf_append (out, out_len, out_cap, b, sizeof b);
}

struct bp_idx_entry {
    unsigned char sha[20];
    uint32_t crc;
    uint64_t off;
};

static int
bp_idx_entry_cmp (const void *a, const void *b)
{
    const struct bp_idx_entry *aa = (const struct bp_idx_entry *) a;
    const struct bp_idx_entry *bb = (const struct bp_idx_entry *) b;
    return memcmp (aa->sha, bb->sha, 20);
}

static uint32_t
bp_crc32_bytes (const unsigned char *p, size_t n)
{
    uLong crc = crc32 (0L, Z_NULL, 0);
    size_t off = 0;
    while (off < n) {
        size_t left = n - off;
        uInt chunk = left > UINT_MAX ? UINT_MAX : (uInt) left;
        crc = crc32 (crc, p + off, chunk);
        off += chunk;
    }
    return (uint32_t) crc;
}

static int
bp_write_idx_v2 (const char *idx_path, struct bp_idx_entry *ents, size_t n,
                 const unsigned char pack_sha[20])
{
    unsigned char *idx = NULL;
    size_t idx_len = 0, idx_cap = 0;
    uint64_t *ofs64 = NULL;
    size_t n64 = 0, cap64 = 0;

    if (n > UINT32_MAX) {
        builtin_error ("create: too many objects for idx v2");
        return -1;
    }

    qsort (ents, n, sizeof *ents, bp_idx_entry_cmp);

    if (bp_buf_append (&idx, &idx_len, &idx_cap, "\377tOc", 4) < 0) goto oom;
    if (bp_buf_append_be32 (&idx, &idx_len, &idx_cap, 2) < 0) goto oom;

    size_t pos = 0;
    for (uint32_t b = 0; b < 256; b++) {
        while (pos < n && ents[pos].sha[0] <= (unsigned char) b)
            pos++;
        if (bp_buf_append_be32 (&idx, &idx_len, &idx_cap,
                                (uint32_t) pos) < 0)
            goto oom;
    }

    for (size_t i = 0; i < n; i++)
        if (bp_buf_append (&idx, &idx_len, &idx_cap,
                           ents[i].sha, sizeof ents[i].sha) < 0)
            goto oom;

    for (size_t i = 0; i < n; i++)
        if (bp_buf_append_be32 (&idx, &idx_len, &idx_cap,
                                ents[i].crc) < 0)
            goto oom;

    for (size_t i = 0; i < n; i++) {
        uint32_t out;
        if (ents[i].off >= 0x80000000ULL) {
            if (n64 > 0x7fffffffU) {
                builtin_error ("create: too many 64-bit idx offsets");
                free (idx); free (ofs64);
                return -1;
            }
            if (n64 == cap64) {
                cap64 = cap64 ? cap64 * 2 : 8;
                uint64_t *no = realloc (ofs64, cap64 * sizeof *ofs64);
                if (!no) goto oom;
                ofs64 = no;
            }
            ofs64[n64] = ents[i].off;
            out = 0x80000000U | (uint32_t) n64;
            n64++;
        } else {
            out = (uint32_t) ents[i].off;
        }
        if (bp_buf_append_be32 (&idx, &idx_len, &idx_cap, out) < 0)
            goto oom;
    }

    for (size_t i = 0; i < n64; i++)
        if (bp_buf_append_be64 (&idx, &idx_len, &idx_cap, ofs64[i]) < 0)
            goto oom;

    if (bp_buf_append (&idx, &idx_len, &idx_cap, pack_sha, 20) < 0)
        goto oom;
    unsigned char idx_sha[20];
    if (bp_sha1 (idx, idx_len, idx_sha) < 0) {
        builtin_error ("create: idx SHA-1 collision attack detected");
        free (idx); free (ofs64);
        return -1;
    }
    if (bp_buf_append (&idx, &idx_len, &idx_cap, idx_sha, 20) < 0)
        goto oom;

    char tmp[4096];
    int nr = snprintf (tmp, sizeof tmp, "%s.tmpXXXXXX", idx_path);
    if (nr < 0 || (size_t) nr >= sizeof tmp) {
        builtin_error ("create: idx path too long: %s", idx_path);
        free (idx); free (ofs64);
        return -1;
    }
    int fd = mkstemp (tmp);
    if (fd < 0) {
        builtin_error ("create: mkstemp %s: %s", tmp, strerror (errno));
        free (idx); free (ofs64);
        return -1;
    }
    fchmod (fd, 0444);
    size_t off = 0;
    while (off < idx_len) {
        ssize_t w = write (fd, idx + off, idx_len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            builtin_error ("create: write %s: %s", tmp, strerror (errno));
            close (fd); unlink (tmp);
            free (idx); free (ofs64);
            return -1;
        }
        off += (size_t) w;
    }
    fdatasync (fd);
    close (fd);
    if (rename (tmp, idx_path) < 0) {
        builtin_error ("create: rename %s -> %s: %s",
                       tmp, idx_path, strerror (errno));
        unlink (tmp);
        free (idx); free (ofs64);
        return -1;
    }

    free (idx); free (ofs64);
    return 0;

oom:
    builtin_error ("create: out of memory");
    free (idx); free (ofs64);
    return -1;
}

static int
bp_create_cmd (WORD_LIST *args)
{
    if (!args) {
        builtin_error ("create: OUTFILE [--idx IDXFILE] [-r REPO] SHA [SHA...]");
        return EX_USAGE;
    }
    const char *outfile = args->word->word;
    const char *idx_path = NULL;
    const char *repo = ".";
    const char **shas = NULL;
    size_t n_shas = 0, sha_cap = 0;

    for (WORD_LIST *p = args->next; p; p = p->next) {
        if (!strcmp (p->word->word, "--idx")) {
            if (!p->next) {
                builtin_error ("create: --idx requires IDXFILE");
                free (shas);
                return EX_USAGE;
            }
            p = p->next; idx_path = p->word->word; continue;
        }
        if (!strcmp (p->word->word, "-r") && p->next) {
            p = p->next; repo = p->word->word; continue;
        }
        if (strlen (p->word->word) != 40) {
            builtin_error ("create: invalid SHA '%s' (expected 40 hex chars)", p->word->word);
            free (shas);
            return EX_USAGE;
        }
        if (n_shas == sha_cap) {
            sha_cap = sha_cap ? sha_cap * 2 : 8;
            const char **ns = realloc (shas, sha_cap * sizeof *shas);
            if (!ns) { free (shas); return EXECUTION_FAILURE; }
            shas = ns;
        }
        shas[n_shas++] = p->word->word;
    }
    if (n_shas == 0) {
        builtin_error ("create: no SHAs given");
        free (shas);
        return EX_USAGE;
    }
    if (n_shas > UINT32_MAX) {
        builtin_error ("create: too many objects for pack v2");
        free (shas);
        return EXECUTION_FAILURE;
    }

    struct bp_idx_entry *ents = NULL;
    if (idx_path) {
        ents = calloc (n_shas, sizeof *ents);
        if (!ents) { free (shas); return EXECUTION_FAILURE; }
    }

    /* Build pack image in memory: header + objects. SHA-1 over the whole
     * thing goes at the end, then write the file atomically via a tmp+rename. */
    unsigned char *body = NULL;
    size_t body_len = 0, body_cap = 0;

    /* Header: "PACK" + be32(version=2) + be32(count). */
    if (bp_buf_append (&body, &body_len, &body_cap, "PACK", 4) < 0) goto oom;
    unsigned char be4[4] = { 0, 0, 0, 2 };
    if (bp_buf_append (&body, &body_len, &body_cap, be4, 4) < 0) goto oom;
    be4[0] = (unsigned char) ((n_shas >> 24) & 0xff);
    be4[1] = (unsigned char) ((n_shas >> 16) & 0xff);
    be4[2] = (unsigned char) ((n_shas >>  8) & 0xff);
    be4[3] = (unsigned char) ( n_shas        & 0xff);
    if (bp_buf_append (&body, &body_len, &body_cap, be4, 4) < 0) goto oom;

    for (size_t i = 0; i < n_shas; i++) {
        int type;
        unsigned char *content = NULL;
        size_t clen = 0;
        if (ents && bp_hex_to_sha (shas[i], ents[i].sha) < 0) {
            builtin_error ("create: invalid SHA '%s' (expected 40 hex chars)", shas[i]);
            free (body); free (shas); free (ents);
            return EX_USAGE;
        }
        if (bp_read_loose (repo, shas[i], &type, &content, &clen) < 0) {
            builtin_error ("create: cannot read loose object %s in %s", shas[i], repo);
            free (body); free (shas); free (ents);
            return EXECUTION_FAILURE;
        }
        uint64_t obj_off = (uint64_t) body_len;
        unsigned char ohdr[16];
        size_t ohdr_len = 0;
        bp_encode_obj_header (type, clen, ohdr, &ohdr_len);
        if (bp_buf_append (&body, &body_len, &body_cap, ohdr, ohdr_len) < 0) {
            free (content); goto oom;
        }
        unsigned char *zbuf = NULL;
        size_t zlen = 0;
        if (bp_deflate (content, clen, &zbuf, &zlen) < 0) {
            free (content);
            builtin_error ("create: deflate failed for %s", shas[i]);
            free (body); free (shas); free (ents);
            return EXECUTION_FAILURE;
        }
        free (content);
        if (bp_buf_append (&body, &body_len, &body_cap, zbuf, zlen) < 0) {
            free (zbuf); goto oom;
        }
        free (zbuf);
        if (ents) {
            ents[i].off = obj_off;
            ents[i].crc = bp_crc32_bytes (body + obj_off,
                                          body_len - (size_t) obj_off);
        }
    }

    /* Trailer: SHA-1 of everything written so far. */
    unsigned char digest[20];
    if (bp_sha1 (body, body_len, digest) < 0) {
        builtin_error ("create: SHA-1 collision attack detected");
        free (body); free (shas); free (ents);
        return EXECUTION_FAILURE;
    }
    if (bp_buf_append (&body, &body_len, &body_cap, digest, 20) < 0) goto oom;

    /* Atomic write via tmp + rename. */
    char tmp[4096];
    snprintf (tmp, sizeof tmp, "%s.tmpXXXXXX", outfile);
    int fd = mkstemp (tmp);
    if (fd < 0) {
        builtin_error ("create: mkstemp %s: %s", tmp, strerror (errno));
        free (body); free (shas); free (ents);
        return EXECUTION_FAILURE;
    }
    fchmod (fd, 0444);
    size_t off = 0;
    while (off < body_len) {
        ssize_t w = write (fd, body + off, body_len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            builtin_error ("create: write %s: %s", tmp, strerror (errno));
            close (fd); unlink (tmp);
            free (body); free (shas); free (ents);
            return EXECUTION_FAILURE;
        }
        off += (size_t) w;
    }
    fdatasync (fd);
    close (fd);
    if (rename (tmp, outfile) < 0) {
        builtin_error ("create: rename %s -> %s: %s", tmp, outfile, strerror (errno));
        unlink (tmp);
        free (body); free (shas); free (ents);
        return EXECUTION_FAILURE;
    }
    if (idx_path && bp_write_idx_v2 (idx_path, ents, n_shas, digest) < 0) {
        free (body); free (shas); free (ents);
        return EXECUTION_FAILURE;
    }
    free (body); free (shas); free (ents);
    printf ("%zu\n", n_shas);
    return EXECUTION_SUCCESS;

oom:
    builtin_error ("create: out of memory");
    free (body); free (shas); free (ents);
    return EXECUTION_FAILURE;
}

/* Verify .idx file structural integrity + cryptographic trailer.
 *
 * Returns 0 on success, -1 on any failure (with builtin_error called).
 * If expected_pack_sha20 is non-NULL, also cross-checks the .idx
 * trailer's embedded pack-SHA-1 (the first 20 bytes of the 40-byte
 * trailer) against it.
 *
 * Checks:
 *   - magic "\xfftOc" + version 2
 *   - fanout monotonicity (each entry >= previous)
 *   - exact-size match: 1032 + n*28 + overflow*8 + 40 bytes (the SHA
 *     table + CRC32 table + 32-bit offsets table account for n*28;
 *     the 64-bit-overflow table is sized by scanning the offsets table
 *     for entries with the high bit set — the largest 64-bit index +1
 *     is the count). Implicitly verifies CRC table presence + bounds.
 *   - SHA-1 over idx[0..ilen-20] matches idx[ilen-20..ilen]
 *   - optional embedded pack-SHA cross-check
 *
 * When a pack is provided, every idx CRC32 entry is validated against the
 * corresponding packed object bytes.
 */
static int
bp_verify_idx (const unsigned char *idx, size_t ilen,
               const unsigned char *expected_pack_sha20)
{
    if (ilen < 8) {
        builtin_error ("verify-idx: too short (no header)");
        return -1;
    }
    if (memcmp (idx, "\377tOc", 4) != 0) {
        builtin_error ("verify-idx: not a v2 idx (bad magic)");
        return -1;
    }
    uint32_t ver = bp_be32 (idx + 4);
    if (ver != 2) {
        builtin_error ("verify-idx: unsupported version %u", ver);
        return -1;
    }
    if (ilen < 8 + 1024) {
        builtin_error ("verify-idx: too short (fanout truncated)");
        return -1;
    }
    /* Fanout monotonicity. */
    uint32_t prev = 0;
    for (int i = 0; i < 256; i++) {
        uint32_t cur = bp_be32 (idx + 8 + i * 4);
        if (cur < prev) {
            builtin_error ("verify-idx: fanout not monotonic at byte %d", i);
            return -1;
        }
        prev = cur;
    }
    uint32_t n = bp_be32 (idx + 8 + 255 * 4);
    /* Required size for SHA + CRC + 32-bit offsets + trailer (28 bytes
     * per object + 1032 + 40). Defensive multiplication-overflow guard
     * — uses the canonical `prod / a != b` shape so it stays meaningful
     * on 32-bit hosts (where size_t == uint32_t and 4 GiB * 28 wraps),
     * without tripping -Wtype-limits on 64-bit (where the comparison
     * would be tautologically false). The 1032 + obj_bytes + 40 add
     * could itself wrap if obj_bytes were near SIZE_MAX (the mul-
     * overflow guard above doesn't bound that high), so we sanity-
     * cap obj_bytes below before composing base_size. */
    size_t obj_bytes = (size_t) n * 28;
    if (n != 0 && obj_bytes / 28 != (size_t) n) {
        builtin_error ("verify-idx: object count %u overflows size", n);
        return -1;
    }
    if (obj_bytes > SIZE_MAX - 1072) {
        builtin_error ("verify-idx: object count %u overflows size", n);
        return -1;
    }
    size_t base_size = 1032 + obj_bytes + 40;
    if (ilen < base_size) {
        builtin_error ("verify-idx: too short for fanout count %u "
                       "(got %zu, need >= %zu)", n, ilen, base_size);
        return -1;
    }
    /* Walk the 32-bit offsets table to find the highest 64-bit overflow
     * index. The 64-bit table sits between the 32-bit offsets table
     * and the 40-byte trailer; its size is (max_idx64 + 1) * 8. */
    const unsigned char *ofs_table = idx + 1032 + (size_t) n * 24;
    uint32_t overflow_count = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t v = bp_be32 (ofs_table + i * 4);
        if (v & 0x80000000U) {
            uint32_t idx64 = v & 0x7FFFFFFFU;
            if (idx64 + 1 > overflow_count)
                overflow_count = idx64 + 1;
        }
    }
    if ((size_t) overflow_count > (SIZE_MAX - base_size) / 8) {
        builtin_error ("verify-idx: 64-bit overflow count %u overflows size",
                       overflow_count);
        return -1;
    }
    size_t expected_size = base_size + (size_t) overflow_count * 8;
    if (ilen != expected_size) {
        builtin_error ("verify-idx: size mismatch (got %zu, expected %zu "
                       "for n=%u overflow=%u)",
                       ilen, expected_size, n, overflow_count);
        return -1;
    }
    /* Cryptographic trailer: SHA-1 over idx[0..ilen-20]. */
    unsigned char computed[20];
    if (bp_sha1 (idx, ilen - 20, computed) < 0) {
        builtin_error ("verify-idx: SHA-1 init failed");
        return -1;
    }
    if (memcmp (computed, idx + ilen - 20, 20) != 0) {
        builtin_error ("verify-idx: idx trailer SHA-1 mismatch (corrupt)");
        return -1;
    }
    /* Optional pack-SHA cross-check: the .idx trailer's first 20 bytes
     * must equal the .pack file's trailer SHA-1. */
    if (expected_pack_sha20 &&
        memcmp (idx + ilen - 40, expected_pack_sha20, 20) != 0) {
        builtin_error ("verify-idx: embedded pack SHA-1 != pack trailer SHA-1");
        return -1;
    }
    return 0;
}

struct bp_crc_offset {
    uint64_t off;
    uint32_t index;
};

static int
bp_crc_offset_cmp (const void *a, const void *b)
{
    const struct bp_crc_offset *aa = (const struct bp_crc_offset *) a;
    const struct bp_crc_offset *bb = (const struct bp_crc_offset *) b;
    if (aa->off < bb->off) return -1;
    if (aa->off > bb->off) return 1;
    return 0;
}

static int
bp_verify_idx_crc32 (const unsigned char *idx, size_t ilen,
                     const unsigned char *pack, size_t plen)
{
    if (plen < 32 || memcmp (pack, "PACK", 4) != 0) {
        builtin_error ("verify-idx: pack too short or bad magic");
        return -1;
    }
    uint32_t pack_ver = bp_be32 (pack + 4);
    if (pack_ver != 2 && pack_ver != 3) {
        builtin_error ("verify-idx: unsupported pack version %u", pack_ver);
        return -1;
    }
    uint32_t n = bp_be32 (idx + 8 + 255 * 4);
    uint32_t pack_n = bp_be32 (pack + 8);
    if (pack_n != n) {
        builtin_error ("verify-idx: pack object count %u != idx object count %u",
                       pack_n, n);
        return -1;
    }

    const unsigned char *crc_table = idx + 1032 + (size_t) n * 20;
    const unsigned char *ofs_table = idx + 1032 + (size_t) n * 24;
    const unsigned char *ofs64_table = idx + 1032 + (size_t) n * 28;
    size_t ofs64_room = (ilen - 40) - (size_t) (ofs64_table - idx);
    struct bp_crc_offset *offs = calloc (n ? n : 1, sizeof *offs);
    if (!offs) {
        builtin_error ("verify-idx: out of memory");
        return -1;
    }

    for (uint32_t i = 0; i < n; i++) {
        uint32_t v = bp_be32 (ofs_table + (size_t) i * 4);
        uint64_t off;
        if (v & 0x80000000U) {
            uint32_t idx64 = v & 0x7FFFFFFFU;
            if ((size_t) idx64 > (ofs64_room / 8) - 1) {
                free (offs);
                builtin_error ("verify-idx: 64-bit offset index out of range");
                return -1;
            }
            off = bp_be64 (ofs64_table + (size_t) idx64 * 8);
        } else {
            off = v;
        }
        if (off < 12 || off >= plen - 20) {
            free (offs);
            builtin_error ("verify-idx: object offset out of pack bounds");
            return -1;
        }
        offs[i].off = off;
        offs[i].index = i;
    }

    qsort (offs, n, sizeof *offs, bp_crc_offset_cmp);
    for (uint32_t sorted = 0; sorted < n; sorted++) {
        uint64_t start = offs[sorted].off;
        uint64_t end = (sorted + 1 < n) ? offs[sorted + 1].off : (uint64_t) (plen - 20);
        if (end <= start) {
            free (offs);
            builtin_error ("verify-idx: object offsets not strictly increasing");
            return -1;
        }
        uLong crc = crc32 (0L, Z_NULL, 0);
        uint64_t pos = start;
        while (pos < end) {
            uint64_t left = end - pos;
            uInt chunk = left > UINT_MAX ? UINT_MAX : (uInt) left;
            crc = crc32 (crc, pack + pos, chunk);
            pos += chunk;
        }
        uint32_t stored = bp_be32 (crc_table + (size_t) offs[sorted].index * 4);
        if ((uint32_t) crc != stored) {
            free (offs);
            builtin_error ("verify-idx: CRC32 mismatch for object %u",
                           offs[sorted].index);
            return -1;
        }
    }

    free (offs);
    return 0;
}

static int
bp_verify_idx_cmd (WORD_LIST *args)
{
    if (!args) {
        builtin_error ("verify-idx: IDX [PACK]");
        return EX_USAGE;
    }
    const char *idx_path = args->word->word;
    const char *pack_path = (args->next ? args->next->word->word : NULL);
    if (args->next && args->next->next) {
        builtin_error ("verify-idx: extra arg %s", args->next->next->word->word);
        return EX_USAGE;
    }
    size_t ilen;
    unsigned char *idx = bp_slurp (idx_path, &ilen);
    if (!idx) {
        builtin_error ("verify-idx: read %s: %s", idx_path, strerror (errno));
        return EXECUTION_FAILURE;
    }
    unsigned char pack_sha[20];
    const unsigned char *expected = NULL;
    unsigned char *pack = NULL;
    size_t plen = 0;
    if (pack_path) {
        pack = bp_slurp (pack_path, &plen);
        if (!pack) {
            free (idx);
            builtin_error ("verify-idx: read %s: %s", pack_path, strerror (errno));
            return EXECUTION_FAILURE;
        }
        if (plen < 20) {
            free (idx); free (pack);
            builtin_error ("verify-idx: pack too short (no trailer)");
            return EXECUTION_FAILURE;
        }
        memcpy (pack_sha, pack + plen - 20, 20);
        expected = pack_sha;
    }
    int rc = bp_verify_idx (idx, ilen, expected);
    if (rc == 0 && pack)
        rc = bp_verify_idx_crc32 (idx, ilen, pack, plen);
    free (idx);
    free (pack);
    return rc < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

int
pack_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    if (!strcmp (cmd, "list-objects")) return bp_list_objects_cmd (args);
    if (!strcmp (cmd, "cat"))          return bp_cat_cmd (args);
    if (!strcmp (cmd, "list-packs"))   return bp_list_packs_cmd (args);
    if (!strcmp (cmd, "unpack"))       return bp_unpack_cmd (args);
    if (!strcmp (cmd, "create"))       return bp_create_cmd (args);
    if (!strcmp (cmd, "verify-idx"))   return bp_verify_idx_cmd (args);
    builtin_error ("unknown verb: %s", cmd);
    return EX_USAGE;
}

char *pack_doc[] = {
    "Read + write git packfiles (resolves OFS_DELTA + REF_DELTA chains).",
    "",
    "    pack list-objects IDX",
    "        Enumerate every SHA in the .idx file.",
    "    pack cat PACK IDX SHA [-r REPO]",
    "        Decompress + delta-resolve; emit raw object content.",
    "    pack list-packs [REPO]",
    "        List <repo>/.git/objects/pack/pack-*.idx files.",
    "    pack unpack PACK REPO",
    "        Unpack a fetched packfile into loose objects.",
    "    pack create OUTFILE [--idx IDXFILE] [-r REPO] SHA [SHA...]",
    "        Build a pack v2 from local loose objects (full bases, no",
    "        deltas). Used by 'git push' to assemble the receive-pack",
    "        request body. Output is atomic via tmp+rename. With --idx,",
    "        also write the paired v2 .idx: SHA-sorted fanout, CRC,",
    "        offset tables, and pack-SHA + idx-SHA trailer.",
    "    pack verify-idx IDX [PACK]",
    "        Validate a v2 .idx file: header + magic + version, fanout",
    "        monotonicity, exact-size match against fanout count plus",
    "        the 64-bit overflow table (verifies the CRC32 table's",
    "        presence + bounds implicitly), and SHA-1 trailer over",
    "        idx[0..ilen-20]. When PACK is given, also cross-checks",
    "        the idx trailer's embedded pack SHA-1 against the pack's",
    "        own trailer SHA-1 and validates per-object CRC32 table",
    "        entries against the corresponding packed object bytes.",
    (char *)NULL
};

struct builtin pack_struct = {
    "pack",
    pack_builtin,
    BUILTIN_ENABLED,
    pack_doc,
    "pack list-objects|cat|list-packs|unpack|create|verify-idx ARGS",
    0
};
