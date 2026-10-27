/* SPDX-License-Identifier: MIT */
/* _git/pack.c — git packfiles: reading, delta resolution, writing, .idx.
 *
 * Moved out of the pack builtin so the git builtins share one packfile
 * implementation. See pack.h for the contract; the behaviour, including
 * every message, is the same as when the builtin held this code. Hashing,
 * deflate and hex conversion come from odb.h, which had the same code.
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
#include <limits.h>
#include <stdint.h>
#include <sys/stat.h>
#include <zlib.h>

#include "loadables.h"

#include "pack.h"
#include "odb.h"

const char *
bgit_pack_type_name (int t)
{
    switch (t) {
    case BGIT_PACK_COMMIT: return "commit";
    case BGIT_PACK_TREE:   return "tree";
    case BGIT_PACK_BLOB:   return "blob";
    case BGIT_PACK_TAG:    return "tag";
    default:               return "delta";
    }
}

uint32_t
bgit_pack_be32 (const unsigned char *b)
{
    return ((uint32_t) b[0] << 24) | ((uint32_t) b[1] << 16) |
           ((uint32_t) b[2] <<  8) | ((uint32_t) b[3]);
}

uint64_t
bgit_pack_be64 (const unsigned char *b)
{
    return ((uint64_t) b[0] << 56) | ((uint64_t) b[1] << 48) |
           ((uint64_t) b[2] << 40) | ((uint64_t) b[3] << 32) |
           ((uint64_t) b[4] << 24) | ((uint64_t) b[5] << 16) |
           ((uint64_t) b[6] <<  8) | ((uint64_t) b[7]);
}

/* --- file slurp ---
 *
 * Guards:
 *   - st.st_size is off_t (signed). On a directory, pipe, or special
 *     file fstat() can return a negative or unusually large size that,
 *     cast directly to size_t for malloc(), wraps to a huge unsigned
 *     value (or fails with ENOMEM on 32-bit hosts, but only after
 *     wasting the allocator dance). Reject early.
 *   - 0-byte files are accepted: malloc(0) is implementation-defined,
 *     so we allocate a 1-byte buffer to guarantee a non-NULL return
 *     for the caller and report length 0 honestly.
 */
unsigned char *
bgit_pack_slurp (const char *path, size_t *out_len)
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

/* Repeated object reads may reuse only a successful pack checksum result,
   and only after comparing every byte of the newly read private buffer with
   this owned snapshot (including the trailer). No pathname, timestamp, index
   or decoded-object state is cached. Keep at most 8 MiB until replacement,
   dynamic builtin unload, or process exit in a static build. */
#define BGIT_PACK_CHECKSUM_CACHE_LIMIT ((size_t) 8 * 1024 * 1024)
static unsigned char *bgit_verified_pack;
static size_t bgit_verified_pack_len;

int
bgit_pack_checksum_cached (const unsigned char *pack, size_t plen)
{
    return bgit_verified_pack && plen == bgit_verified_pack_len &&
           memcmp (pack, bgit_verified_pack, plen) == 0;
}

void
bgit_pack_remember_verified (const unsigned char *pack, size_t plen)
{
    if (plen > BGIT_PACK_CHECKSUM_CACHE_LIMIT) return;
    int saved_errno = errno;
    if (plen != bgit_verified_pack_len) {
        /* Release first so two snapshots never contribute to the RAM cap.
           Allocation failure simply leaves normal validation in use. */
        free (bgit_verified_pack);
        bgit_verified_pack = NULL;
        bgit_verified_pack_len = 0;
        bgit_verified_pack = malloc (plen);
    }
    if (bgit_verified_pack) {
        memcpy (bgit_verified_pack, pack, plen);
        bgit_verified_pack_len = plen;
    }
    errno = saved_errno;
}

/* The objects kept from delta chains, thrown away with the rest. */
static void bgit_pack_objects_forget (void);

void
bgit_pack_cache_release (void)
{
    bgit_pack_objects_forget ();

    free (bgit_verified_pack);
    bgit_verified_pack = NULL;
    bgit_verified_pack_len = 0;
}

int
bgit_pack_write_loose (const char *repo, const char *sha,
                       const unsigned char *deflated, size_t dlen)
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

/* --- pack object lookup: idx → offset ----------------------------------
 *
 * Returns pack offset for SHA, or (uint64_t)-1 if not found OR if the
 * idx is too small / malformed for the indexed read. Every memory
 * dereference is gated by an explicit size check derived from
 * fanout[255]; a malicious idx with an inflated fanout count, missing
 * CRC/offset tables, or a 64-bit-overflow index pointing past the file
 * returns "not found" rather than reading OOB.
 */
uint64_t
bgit_pack_lookup_offset (const unsigned char *idx, size_t ilen,
                         const unsigned char *sha)
{
    if (ilen < 1032) return (uint64_t) -1;
    uint32_t hi = sha[0];
    uint32_t lo = (hi == 0) ? 0 : bgit_pack_be32 (idx + 8 + (hi - 1) * 4);
    uint32_t up = bgit_pack_be32 (idx + 8 + hi * 4);
    uint32_t total = bgit_pack_be32 (idx + 8 + 255 * 4);
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
            uint32_t v = bgit_pack_be32 (ofs + (size_t) i * 4);
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
                return bgit_pack_be64 (ofs64 + (size_t) idx64 * 8);
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
int
bgit_pack_read_obj_header (const unsigned char *pack, size_t plen, uint64_t off,
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
        if ((uint64_t) (b & 0x7F) > (UINT64_MAX >> shift)) return -1;
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
   larger; we just decompress until Z_STREAM_END). Z_FINISH lets zlib omit
   its sliding-window allocation when the advertised size fits in one pass.
   Unknown sizes and larger streams still grow and resume normally. Returns
   0 + sets *out, *bytes_used (input bytes consumed). */
int
bgit_pack_inflate (const unsigned char *src, size_t srcn, size_t expected,
                   unsigned char **out, size_t *out_len, size_t *bytes_used)
{
    z_stream s = {0};
    if (inflateInit (&s) != Z_OK) return -1;
    /* The size an object's header claims is not to be trusted with a
       malloc: a pack from the other end of a fetch can claim anything at
       all, and asking for it is how a clone is turned into an
       out-of-memory. Deflate cannot turn one byte into more than about a
       thousand, so what the input could possibly hold bounds the first
       allocation; anything larger than that grows as it actually
       arrives. */
    size_t ceiling = srcn > (SIZE_MAX - 64) / 1032 ? SIZE_MAX - 64
                                                   : srcn * 1032 + 64;
    size_t cap = expected <= SIZE_MAX - 64 ? expected + 64 : expected;
    if (cap > ceiling) cap = ceiling;
    if (cap < 64) cap = 64;
    unsigned char *buf = malloc (cap);
    if (!buf) { inflateEnd (&s); return -1; }
    size_t total = 0, consumed = 0;
    int rc;
    do {
        if (total == cap) {
            if (cap > (SIZE_MAX - 4096) / 2) {
                free (buf); inflateEnd (&s); return -1;
            }
            cap = cap * 2 + 4096;
            unsigned char *nb = realloc (buf, cap);
            if (!nb) { free (buf); inflateEnd (&s); return -1; }
            buf = nb;
        }
        size_t input = srcn - consumed;
        size_t output = cap - total;
        s.next_in = (unsigned char *) src + consumed;
        s.avail_in = input > UINT_MAX ? UINT_MAX : (uInt) input;
        s.next_out = buf + total;
        s.avail_out = output > UINT_MAX ? UINT_MAX : (uInt) output;
        uInt available_in = s.avail_in, available_out = s.avail_out;
        rc = inflate (&s, Z_FINISH);
        size_t read_count = available_in - s.avail_in;
        size_t write_count = available_out - s.avail_out;
        consumed += read_count;
        total += write_count;
        if ((rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) ||
            (rc != Z_STREAM_END && read_count == 0 && write_count == 0)) {
            free (buf); inflateEnd (&s); return -1;
        }
    } while (rc != Z_STREAM_END);
    *bytes_used = consumed;
    inflateEnd (&s);
    *out = buf;
    *out_len = total;
    return 0;
}

/* A delta size must terminate and fit in uint64_t; truncating high bits
   could make an invalid source size equal a small real base. */
static int
bgit_pack_read_varint (const unsigned char *p, size_t n, size_t *off,
                       uint64_t *out)
{
    uint64_t v = 0;
    for (int shift = 0; *off < n && shift < 64; shift += 7) {
        unsigned char b = p[(*off)++];
        if ((uint64_t) (b & 0x7F) > (UINT64_MAX >> shift)) return -1;
        v |= (uint64_t) (b & 0x7F) << shift;
        if (!(b & 0x80)) { *out = v; return 0; }
    }
    return -1;
}

/* How much of the base a block covers, and how far the rolling hash
   reaches: git's own delta encoder works in sixteens, and so does this. */
#define BGIT_DELTA_BLOCK 16
/* 33 to the fifteenth, so a byte can be taken off the front of the rolling
   hash by subtracting what it contributed. */
#define BGIT_DELTA_POW 0x0c3525e1u

struct bgit_delta_index {
    const unsigned char *base;
    size_t baselen;
    uint32_t mask;          /* one less than the table size */
    uint32_t *heads;        /* slot -> block number plus one, 0 when empty */
    uint32_t *nexts;        /* block number -> the next in its slot, plus one */
    uint32_t *offs;         /* block number -> where it starts in the base */
    size_t n_blocks;
};

static uint32_t
bgit_delta_hash (const unsigned char *p)
{
    uint32_t hash = 0;
    for (int i = 0; i < BGIT_DELTA_BLOCK; i++)
        hash = hash * 33 + p[i];
    return hash;
}

static uint32_t
bgit_delta_slot (uint32_t hash, uint32_t mask)
{
    return (hash ^ (hash >> 15)) & mask;
}

bgit_delta_index *
bgit_delta_index_create (const unsigned char *base, size_t baselen)
{
    if (baselen < BGIT_DELTA_BLOCK) return NULL;
    size_t n_blocks = baselen / BGIT_DELTA_BLOCK;
    size_t table = 1;
    while (table < n_blocks * 2) table <<= 1;
    if (table > (size_t) 1 << 24) table = (size_t) 1 << 24;
    bgit_delta_index *index = calloc (1, sizeof *index);
    if (!index) return NULL;
    index->base = base;
    index->baselen = baselen;
    index->mask = (uint32_t) (table - 1);
    index->n_blocks = n_blocks;
    index->heads = calloc (table, sizeof *index->heads);
    index->nexts = calloc (n_blocks, sizeof *index->nexts);
    index->offs = calloc (n_blocks, sizeof *index->offs);
    if (!index->heads || !index->nexts || !index->offs) {
        bgit_delta_index_free (index);
        return NULL;
    }
    /* Indexed from the end backwards, so the chain in each slot comes out
       with the earliest block first: a match found early in the base
       encodes into fewer bytes. */
    for (size_t b = n_blocks; b-- > 0; ) {
        size_t off = b * BGIT_DELTA_BLOCK;
        uint32_t slot = bgit_delta_slot (bgit_delta_hash (base + off),
                                         index->mask);
        index->offs[b] = (uint32_t) off;
        index->nexts[b] = index->heads[slot];
        index->heads[slot] = (uint32_t) b + 1;
    }
    return index;
}

void
bgit_delta_index_free (bgit_delta_index *index)
{
    if (!index) return;
    free (index->heads);
    free (index->nexts);
    free (index->offs);
    free (index);
}

/* A size, seven bits to a byte, low bits first, as a delta writes one. */
static int
bgit_delta_size (unsigned char **out, size_t *len, size_t *cap, size_t size)
{
    unsigned char bytes[16];
    size_t n = 0;
    do {
        unsigned char byte = (unsigned char) (size & 0x7f);
        size >>= 7;
        if (size) byte |= 0x80;
        bytes[n++] = byte;
    } while (size && n < sizeof bytes);
    return bgit_pack_buf_append (out, len, cap, bytes, n);
}

/* The bytes that were not found in the base, written out as they are, in
   runs of no more than a hundred and twenty-seven. */
static int
bgit_delta_literals (unsigned char **out, size_t *len, size_t *cap,
                     const unsigned char *from, size_t n)
{
    while (n) {
        unsigned char run = (unsigned char) (n > 127 ? 127 : n);
        if (bgit_pack_buf_append (out, len, cap, &run, 1) < 0 ||
            bgit_pack_buf_append (out, len, cap, from, run) < 0)
            return -1;
        from += run;
        n -= run;
    }
    return 0;
}

/* A run the base already holds, named by where it is and how long it is. */
static int
bgit_delta_copy (unsigned char **out, size_t *len, size_t *cap, size_t off,
                 size_t size)
{
    unsigned char command[8];
    size_t n = 1;
    command[0] = 0x80;
    for (int i = 0; i < 4; i++)
        if ((off >> (i * 8)) & 0xff) {
            command[n++] = (unsigned char) ((off >> (i * 8)) & 0xff);
            command[0] |= (unsigned char) (1 << i);
        }
    /* A size of nothing at all is what sixty-five thousand five hundred
       and thirty-six is written as. */
    if (size != 0x10000)
        for (int i = 0; i < 3; i++)
            if ((size >> (i * 8)) & 0xff) {
                command[n++] = (unsigned char) ((size >> (i * 8)) & 0xff);
                command[0] |= (unsigned char) (1 << (4 + i));
            }
    return bgit_pack_buf_append (out, len, cap, command, n);
}

int
bgit_delta_create (const bgit_delta_index *index, const unsigned char *target,
                   size_t targetlen, size_t max, unsigned char **out,
                   size_t *out_len)
{
    if (!index || !target) return -1;
    unsigned char *delta = NULL;
    size_t len = 0, cap = 0;
    if (bgit_delta_size (&delta, &len, &cap, index->baselen) < 0 ||
        bgit_delta_size (&delta, &len, &cap, targetlen) < 0) {
        free (delta);
        return -1;
    }

    const unsigned char *base = index->base;
    size_t at = 0, pending = 0;
    uint32_t hash = 0;
    int rolling = 0;
    while (at < targetlen) {
        size_t best_off = 0, best_len = 0;
        if (at + BGIT_DELTA_BLOCK <= targetlen) {
            if (!rolling) {
                hash = bgit_delta_hash (target + at);
                rolling = 1;
            }
            uint32_t slot = bgit_delta_slot (hash, index->mask);
            int looked = 0;
            for (uint32_t b = index->heads[slot]; b && looked < 64;
                 b = index->nexts[b - 1], looked++) {
                size_t off = index->offs[b - 1];
                if (memcmp (base + off, target + at, BGIT_DELTA_BLOCK))
                    continue;
                size_t run = BGIT_DELTA_BLOCK;
                while (off + run < index->baselen && at + run < targetlen &&
                       run < 0x10000 && base[off + run] == target[at + run])
                    run++;
                if (run > best_len) {
                    best_len = run;
                    best_off = off;
                    if (run >= 0x10000) break;
                }
            }
        }

        if (best_len < BGIT_DELTA_BLOCK) {
            pending++;
            if (at + BGIT_DELTA_BLOCK < targetlen) {
                /* One byte off the front, one on the end. */
                hash = (hash - target[at] * BGIT_DELTA_POW) * 33 +
                       target[at + BGIT_DELTA_BLOCK];
            } else
                rolling = 0;
            at++;
            /* Nothing is written until a run ends, so the length is
               checked with what is waiting counted in. */
            if (len + pending > max) {
                free (delta);
                return -1;
            }
            continue;
        }

        if (bgit_delta_literals (&delta, &len, &cap, target + at - pending,
                                 pending) < 0 ||
            bgit_delta_copy (&delta, &len, &cap, best_off, best_len) < 0) {
            free (delta);
            return -1;
        }
        pending = 0;
        at += best_len;
        rolling = 0;
        if (len > max) {
            free (delta);
            return -1;
        }
    }

    if (bgit_delta_literals (&delta, &len, &cap, target + at - pending,
                             pending) < 0) {
        free (delta);
        return -1;
    }
    if (len > max) {
        free (delta);
        return -1;
    }
    *out = delta;
    *out_len = len;
    return 0;
}

int
bgit_pack_apply_delta (const unsigned char *base, size_t baselen,
                       const unsigned char *delta, size_t deltan,
                       unsigned char **out, size_t *out_len)
{
    size_t off = 0;
    uint64_t src_size, tgt_size;
    if (bgit_pack_read_varint (delta, deltan, &off, &src_size) < 0 ||
        bgit_pack_read_varint (delta, deltan, &off, &tgt_size) < 0)
        return -1;
    if (src_size != baselen) return -1;
    /* Defensive size cap on tgt_size:
     * - tgt_size > SIZE_MAX would silently truncate when passed to
     *   malloc(size_t) on 32-bit hosts. Reject explicitly.
     * - A maliciously large tgt_size (e.g., near UINT64_MAX) would
     *   make every `bo + ... > tgt_size` check below pass trivially,
     *   masking the real bounds. The downstream copy/literal checks
     *   stay sound under the SIZE_MAX cap. */
    if (tgt_size > SIZE_MAX) return -1;
    /* A copy's size has three bytes, so it can copy up to 0xffffff bytes,
       bounded also by the actual base. 0x10000 is only the default when
       no size bytes are present, not the maximum. Keep impossible size
       claims away from malloc without rejecting valid large copies. */
    size_t max_copy = baselen < 0xffffff ? baselen : 0xffffff;
    if (max_copy < 1) max_copy = 1;  /* literals produce at most one per byte */
    size_t ceiling = deltan > SIZE_MAX / max_copy ? SIZE_MAX
                                                  : deltan * max_copy;
    if (tgt_size > ceiling) return -1;
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
    if (bo != tgt_size) { free (buf); return -1; }
    *out = buf;
    *out_len = bo;
    return 0;
}

int bgit_pack_read_object_at (const unsigned char *pack, size_t plen,
                              const unsigned char *idx, size_t ilen,
                              const char *repo, uint64_t off, int *type_out,
                              unsigned char **out, size_t *out_len, int depth);

/* The objects a chain of deltas leans on, kept for a moment. Resolving a
   pack asks for the same base over and over — every object in a chain of
   fifty asks for the ones under it — so an object just built is kept
   until the room is wanted for another. Bounded in both count and bytes,
   and thrown away with the rest of the pack caches. */
#define BGIT_PACK_CACHE_SLOTS 256
#define BGIT_PACK_CACHE_BYTES (8u * 1024u * 1024u)

static struct bgit_pack_cached {
    const unsigned char *pack;
    size_t plen;
    uint64_t off;
    int type;
    unsigned char *data;
    size_t len;
    unsigned long used;
} bgit_pack_cache[BGIT_PACK_CACHE_SLOTS];
static size_t bgit_pack_cache_bytes;
static unsigned long bgit_pack_cache_clock;

static int
bgit_pack_cache_take (const unsigned char *pack, size_t plen, uint64_t off,
                      int *type, unsigned char **out, size_t *len)
{
    for (size_t i = 0; i < BGIT_PACK_CACHE_SLOTS; i++) {
        struct bgit_pack_cached *slot = &bgit_pack_cache[i];
        if (!slot->data || slot->pack != pack || slot->plen != plen ||
            slot->off != off)
            continue;
        unsigned char *copy = malloc (slot->len ? slot->len : 1);
        if (!copy) return 0;
        memcpy (copy, slot->data, slot->len);
        slot->used = ++bgit_pack_cache_clock;
        *type = slot->type;
        *out = copy;
        *len = slot->len;
        return 1;
    }
    return 0;
}

static void
bgit_pack_cache_drop (struct bgit_pack_cached *slot)
{
    bgit_pack_cache_bytes -= slot->len;
    free (slot->data);
    memset (slot, 0, sizeof *slot);
}

static void
bgit_pack_cache_keep (const unsigned char *pack, size_t plen, uint64_t off,
                      int type, const unsigned char *data, size_t len)
{
    if (len > BGIT_PACK_CACHE_BYTES / 4) return;
    struct bgit_pack_cached *slot = NULL;
    for (size_t i = 0; i < BGIT_PACK_CACHE_SLOTS; i++) {
        struct bgit_pack_cached *held = &bgit_pack_cache[i];
        if (!held->data) { slot = held; break; }
        if (!slot || held->used < slot->used) slot = held;
    }
    if (!slot) return;
    if (slot->data) bgit_pack_cache_drop (slot);
    slot->data = malloc (len ? len : 1);
    if (!slot->data) return;
    memcpy (slot->data, data, len);
    slot->pack = pack;
    slot->plen = plen;
    slot->off = off;
    slot->type = type;
    slot->len = len;
    slot->used = ++bgit_pack_cache_clock;
    bgit_pack_cache_bytes += len;
    /* Room made by throwing away whatever was asked for longest ago. */
    while (bgit_pack_cache_bytes > BGIT_PACK_CACHE_BYTES) {
        struct bgit_pack_cached *oldest = NULL;
        for (size_t i = 0; i < BGIT_PACK_CACHE_SLOTS; i++) {
            struct bgit_pack_cached *held = &bgit_pack_cache[i];
            if (held->data && held != slot &&
                (!oldest || held->used < oldest->used))
                oldest = held;
        }
        if (!oldest) break;
        bgit_pack_cache_drop (oldest);
    }
}

static void
bgit_pack_objects_forget (void)
{
    for (size_t i = 0; i < BGIT_PACK_CACHE_SLOTS; i++)
        if (bgit_pack_cache[i].data) bgit_pack_cache_drop (&bgit_pack_cache[i]);
}

/* Read the base an object leans on, from what is kept if it is there. */
static int
bgit_pack_read_base (const unsigned char *pack, size_t plen,
                     const unsigned char *idx, size_t ilen, const char *repo,
                     uint64_t off, int *type, unsigned char **out, size_t *len,
                     int depth)
{
    if (bgit_pack_cache_take (pack, plen, off, type, out, len)) return 0;
    if (bgit_pack_read_object_at (pack, plen, idx, ilen, repo, off, type, out,
                                  len, depth) < 0)
        return -1;
    bgit_pack_cache_keep (pack, plen, off, *type, *out, *len);
    return 0;
}

int
bgit_pack_read_object_at (const unsigned char *pack, size_t plen,
                          const unsigned char *idx, size_t ilen,
                          const char *repo, uint64_t off,
                          int *type_out, unsigned char **out, size_t *out_len,
                          int depth)
{
    if (depth > BGIT_PACK_MAX_DELTA_DEPTH) return -1;
    int type;
    uint64_t expected;
    uint64_t cur;
    if (bgit_pack_read_obj_header (pack, plen, off, &type, &expected, &cur) < 0)
        return -1;

    if (type == BGIT_PACK_COMMIT || type == BGIT_PACK_TREE ||
        type == BGIT_PACK_BLOB || type == BGIT_PACK_TAG) {
        size_t used;
        if (bgit_pack_inflate (pack + cur, plen - cur, (size_t) expected, out,
                               out_len, &used) < 0)
            return -1;
        if (*out_len != expected) { free (*out); *out = NULL; return -1; }
        *type_out = type;
        return 0;
    }
    if (type == BGIT_PACK_OFS_DELTA) {
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
            if (base_off_delta >= (UINT64_MAX >> 7)) return -1;
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
        if (bgit_pack_inflate (pack + cur, plen - cur, (size_t) expected,
                               &delta, &dlen, &used) < 0)
            return -1;
        if (dlen != expected) { free (delta); return -1; }
        int base_type;
        unsigned char *base;
        size_t base_len;
        if (bgit_pack_read_base (pack, plen, idx, ilen, repo, base_off,
                                 &base_type, &base, &base_len, depth + 1) < 0) {
            free (delta); return -1;
        }
        int rc = bgit_pack_apply_delta (base, base_len, delta, dlen, out, out_len);
        free (delta); free (base);
        if (rc < 0) return -1;
        *type_out = base_type;
        return 0;
    }
    if (type == BGIT_PACK_REF_DELTA) {
        if (cur + 20 > plen) return -1;
        unsigned char base_sha[20];
        memcpy (base_sha, pack + cur, 20);
        cur += 20;
        size_t used;
        unsigned char *delta;
        size_t dlen;
        if (bgit_pack_inflate (pack + cur, plen - cur, (size_t) expected,
                               &delta, &dlen, &used) < 0)
            return -1;
        if (dlen != expected) { free (delta); return -1; }
        /* Look up base in same pack first. */
        uint64_t base_off = bgit_pack_lookup_offset (idx, ilen, base_sha);
        unsigned char *base; size_t base_len; int base_type;
        if (base_off != (uint64_t) -1) {
            if (bgit_pack_read_base (pack, plen, idx, ilen, repo, base_off,
                                     &base_type, &base, &base_len,
                                     depth + 1) < 0) {
                free (delta); return -1;
            }
        } else {
            /* Try loose object. */
            char hex[41]; bgit_sha_to_hex (base_sha, hex);
            if (bgit_pack_read_loose (repo ? repo : ".", hex, &base_type,
                                      &base, &base_len) < 0) {
                free (delta); return -1;
            }
        }
        int rc = bgit_pack_apply_delta (base, base_len, delta, dlen, out, out_len);
        free (delta); free (base);
        if (rc < 0) return -1;
        *type_out = base_type;
        return 0;
    }
    return -1;
}

/* Encode a pack object header byte stream.  Format:
 *   first byte: cont(1) | type(3) | size_low4(4)
 *   subsequent: cont(1) | size_next7(7)   (LSB-first)
 */
void
bgit_pack_encode_obj_header (int type, size_t size, unsigned char *out,
                             size_t *out_len)
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

int
bgit_pack_read_loose (const char *repo, const char *sha_hex, int *type_out,
                      unsigned char **content_out, size_t *clen_out)
{
    if (strlen (sha_hex) != 40) return -1;
    char path[4096];
    snprintf (path, sizeof path, "%s/.git/objects/%c%c/%s",
              repo, sha_hex[0], sha_hex[1], sha_hex + 2);
    size_t rn = 0;
    unsigned char *raw = bgit_pack_slurp (path, &rn);
    if (!raw) return -1;
    unsigned char *infl = NULL;
    size_t inflen = 0, used = 0;
    int rc = bgit_pack_inflate (raw, rn, 0, &infl, &inflen, &used);
    free (raw);
    if (rc < 0) return -1;

    enum bgit_type kind;
    size_t clen;
    long hdr_len = bgit_parse_header (infl, inflen, &kind, &clen);
    if (hdr_len < 0 || used != rn || clen != inflen - (size_t) hdr_len) {
        free (infl); return -1;
    }
    int type = kind == BGIT_BLOB ? BGIT_PACK_BLOB
               : kind == BGIT_TREE ? BGIT_PACK_TREE
               : kind == BGIT_COMMIT ? BGIT_PACK_COMMIT : BGIT_PACK_TAG;
    unsigned char *content = malloc (clen ? clen : 1);
    if (!content) { free (infl); return -1; }
    if (clen) memcpy (content, infl + hdr_len, clen);
    free (infl);
    *type_out = type;
    *content_out = content;
    *clen_out = clen;
    return 0;
}

int
bgit_pack_buf_append (unsigned char **out, size_t *out_len, size_t *out_cap,
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
bgit_pack_buf_append_be32 (unsigned char **out, size_t *out_len,
                           size_t *out_cap, uint32_t v)
{
    unsigned char b[4];
    b[0] = (unsigned char) ((v >> 24) & 0xff);
    b[1] = (unsigned char) ((v >> 16) & 0xff);
    b[2] = (unsigned char) ((v >>  8) & 0xff);
    b[3] = (unsigned char) ( v        & 0xff);
    return bgit_pack_buf_append (out, out_len, out_cap, b, sizeof b);
}

static int
bgit_pack_buf_append_be64 (unsigned char **out, size_t *out_len,
                           size_t *out_cap, uint64_t v)
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
    return bgit_pack_buf_append (out, out_len, out_cap, b, sizeof b);
}

static int
bgit_pack_idx_entry_cmp (const void *a, const void *b)
{
    const struct bgit_pack_idx_entry *aa = (const struct bgit_pack_idx_entry *) a;
    const struct bgit_pack_idx_entry *bb = (const struct bgit_pack_idx_entry *) b;
    return memcmp (aa->sha, bb->sha, 20);
}

/* Read more of the stream into a growing buffer. Returns how many bytes
   arrived, 0 at the end of it, or -1. */
static ssize_t
bgit_pack_stream_more (int fd, unsigned char **buf, size_t *len, size_t *cap)
{
    if (*len + 65536 > *cap) {
        size_t next = *cap ? *cap * 2 : 131072;
        while (next < *len + 65536) next *= 2;
        unsigned char *grown = realloc (*buf, next);
        if (!grown) return -1;
        *buf = grown;
        *cap = next;
    }
    for (;;) {
        ssize_t got = read (fd, *buf + *len, *cap - *len);
        if (got < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        *len += (size_t) got;
        return got;
    }
}

int
bgit_pack_read_stream (int fd, const unsigned char *already, size_t already_len,
                       unsigned char **out, size_t *out_len)
{
    unsigned char *buf = NULL;
    size_t len = 0, cap = 0;
    *out = NULL;
    *out_len = 0;

    if (already_len &&
        bgit_pack_buf_append (&buf, &len, &cap, already, already_len) < 0) {
        free (buf);
        return -1;
    }
    while (len < 12) {
        ssize_t got = bgit_pack_stream_more (fd, &buf, &len, &cap);
        if (got <= 0) { free (buf); return -1; }
    }
    if (memcmp (buf, "PACK", 4) || bgit_pack_be32 (buf + 4) != 2) {
        free (buf);
        return -1;
    }
    uint32_t objects = bgit_pack_be32 (buf + 8);

    /* Walk the objects as they arrive. A header or a deflated stream that
       runs off the end means the rest has not come yet, not that the pack
       is wrong, so read more and try that object again. */
    uint64_t at = 12;
    for (uint32_t done = 0; done < objects; ) {
        int type = 0;
        uint64_t size = 0, next = at;
        int short_of_data = 0;
        if (bgit_pack_read_obj_header (buf, len, at, &type, &size, &next) < 0)
            short_of_data = 1;
        if (!short_of_data && type == BGIT_PACK_OFS_DELTA) {
            /* A base offset is bytes with the top bit set, then one
               without; its value does not matter here. */
            while (next < len && (buf[next] & 0x80)) next++;
            if (next < len) next++;
            else short_of_data = 1;
        } else if (!short_of_data && type == BGIT_PACK_REF_DELTA) {
            if (next + 20 <= len) next += 20;
            else short_of_data = 1;
        }
        unsigned char *data = NULL;
        size_t data_len = 0, used = 0;
        if (!short_of_data &&
            bgit_pack_inflate (buf + next, len - (size_t) next, (size_t) size,
                               &data, &data_len, &used) < 0)
            short_of_data = 1;
        free (data);
        if (short_of_data) {
            ssize_t got = bgit_pack_stream_more (fd, &buf, &len, &cap);
            if (got <= 0) { free (buf); return -1; }
            continue;
        }
        at = next + used;
        done++;
    }
    while (len < at + 20) {
        ssize_t got = bgit_pack_stream_more (fd, &buf, &len, &cap);
        if (got <= 0) { free (buf); return -1; }
    }
    *out = buf;
    *out_len = (size_t) at + 20;
    return 0;
}

uint32_t
bgit_pack_crc32 (const unsigned char *p, size_t n)
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

int
bgit_pack_write_idx_v2 (const char *idx_path, struct bgit_pack_idx_entry *ents,
                        size_t n, const unsigned char pack_sha[20])
{
    unsigned char *idx = NULL;
    size_t idx_len = 0, idx_cap = 0;
    uint64_t *ofs64 = NULL;
    size_t n64 = 0, cap64 = 0;

    if (n > UINT32_MAX) {
        builtin_error ("create: too many objects for idx v2");
        return -1;
    }

    qsort (ents, n, sizeof *ents, bgit_pack_idx_entry_cmp);

    if (bgit_pack_buf_append (&idx, &idx_len, &idx_cap, "\377tOc", 4) < 0) goto oom;
    if (bgit_pack_buf_append_be32 (&idx, &idx_len, &idx_cap, 2) < 0) goto oom;

    size_t pos = 0;
    for (uint32_t b = 0; b < 256; b++) {
        while (pos < n && ents[pos].sha[0] <= (unsigned char) b)
            pos++;
        if (bgit_pack_buf_append_be32 (&idx, &idx_len, &idx_cap,
                                       (uint32_t) pos) < 0)
            goto oom;
    }

    for (size_t i = 0; i < n; i++)
        if (bgit_pack_buf_append (&idx, &idx_len, &idx_cap,
                                  ents[i].sha, sizeof ents[i].sha) < 0)
            goto oom;

    for (size_t i = 0; i < n; i++)
        if (bgit_pack_buf_append_be32 (&idx, &idx_len, &idx_cap,
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
        if (bgit_pack_buf_append_be32 (&idx, &idx_len, &idx_cap, out) < 0)
            goto oom;
    }

    for (size_t i = 0; i < n64; i++)
        if (bgit_pack_buf_append_be64 (&idx, &idx_len, &idx_cap, ofs64[i]) < 0)
            goto oom;

    if (bgit_pack_buf_append (&idx, &idx_len, &idx_cap, pack_sha, 20) < 0)
        goto oom;
    unsigned char idx_sha[20];
    if (bgit_sha1 (idx, idx_len, idx_sha) < 0) {
        builtin_error ("create: idx SHA-1 collision attack detected");
        free (idx); free (ofs64);
        return -1;
    }
    if (bgit_pack_buf_append (&idx, &idx_len, &idx_cap, idx_sha, 20) < 0)
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
 */
int
bgit_pack_verify_idx (const unsigned char *idx, size_t ilen,
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
    uint32_t ver = bgit_pack_be32 (idx + 4);
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
        uint32_t cur = bgit_pack_be32 (idx + 8 + i * 4);
        if (cur < prev) {
            builtin_error ("verify-idx: fanout not monotonic at byte %d", i);
            return -1;
        }
        prev = cur;
    }
    uint32_t n = bgit_pack_be32 (idx + 8 + 255 * 4);
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
        uint32_t v = bgit_pack_be32 (ofs_table + i * 4);
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
    if (bgit_sha1 (idx, ilen - 20, computed) < 0) {
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

struct bgit_pack_crc_offset {
    uint64_t off;
    uint32_t index;
};

static int
bgit_pack_crc_offset_cmp (const void *a, const void *b)
{
    const struct bgit_pack_crc_offset *aa = (const struct bgit_pack_crc_offset *) a;
    const struct bgit_pack_crc_offset *bb = (const struct bgit_pack_crc_offset *) b;
    if (aa->off < bb->off) return -1;
    if (aa->off > bb->off) return 1;
    return 0;
}

int
bgit_pack_verify_idx_crc32 (const unsigned char *idx, size_t ilen,
                            const unsigned char *pack, size_t plen)
{
    if (plen < 32 || memcmp (pack, "PACK", 4) != 0) {
        builtin_error ("verify-idx: pack too short or bad magic");
        return -1;
    }
    uint32_t pack_ver = bgit_pack_be32 (pack + 4);
    if (pack_ver != 2 && pack_ver != 3) {
        builtin_error ("verify-idx: unsupported pack version %u", pack_ver);
        return -1;
    }
    uint32_t n = bgit_pack_be32 (idx + 8 + 255 * 4);
    uint32_t pack_n = bgit_pack_be32 (pack + 8);
    if (pack_n != n) {
        builtin_error ("verify-idx: pack object count %u != idx object count %u",
                       pack_n, n);
        return -1;
    }

    const unsigned char *crc_table = idx + 1032 + (size_t) n * 20;
    const unsigned char *ofs_table = idx + 1032 + (size_t) n * 24;
    const unsigned char *ofs64_table = idx + 1032 + (size_t) n * 28;
    size_t ofs64_room = (ilen - 40) - (size_t) (ofs64_table - idx);
    struct bgit_pack_crc_offset *offs = calloc (n ? n : 1, sizeof *offs);
    if (!offs) {
        builtin_error ("verify-idx: out of memory");
        return -1;
    }

    for (uint32_t i = 0; i < n; i++) {
        uint32_t v = bgit_pack_be32 (ofs_table + (size_t) i * 4);
        uint64_t off;
        if (v & 0x80000000U) {
            uint32_t idx64 = v & 0x7FFFFFFFU;
            if ((size_t) idx64 > (ofs64_room / 8) - 1) {
                free (offs);
                builtin_error ("verify-idx: 64-bit offset index out of range");
                return -1;
            }
            off = bgit_pack_be64 (ofs64_table + (size_t) idx64 * 8);
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

    qsort (offs, n, sizeof *offs, bgit_pack_crc_offset_cmp);
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
        uint32_t stored = bgit_pack_be32 (crc_table + (size_t) offs[sorted].index * 4);
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
