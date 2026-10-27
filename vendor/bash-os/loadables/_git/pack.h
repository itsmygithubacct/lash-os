/* SPDX-License-Identifier: MIT */
/* _git/pack.h — git packfiles: reading, delta resolution, writing, .idx.
 *
 * Format references (implemented from the published descriptions):
 *   .idx v2:
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
 * These functions report their own failures with builtin_error, except the
 * silent ones noted below, so a caller only has to choose an exit status.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_PACK_H
#define BASH_OS_GIT_PACK_H

#include <stddef.h>
#include <stdint.h>

/* Object types as the pack wire format numbers them. */
enum bgit_pack_type {
    BGIT_PACK_COMMIT = 1, BGIT_PACK_TREE = 2, BGIT_PACK_BLOB = 3,
    BGIT_PACK_TAG = 4, BGIT_PACK_OFS_DELTA = 6, BGIT_PACK_REF_DELTA = 7
};

/* Maximum delta chain depth for OFS_DELTA/REF_DELTA resolution. Prevents
   stack overflow from maliciously deep delta chains. Real git defaults to
   50; we match that limit. */
#define BGIT_PACK_MAX_DELTA_DEPTH 50

/* "commit" / "tree" / "blob" / "tag", or "delta" for a delta type. */
const char *bgit_pack_type_name (int type);

/* Big-endian readers over a pointer into pack or idx bytes. */
uint32_t bgit_pack_be32 (const unsigned char *b);
uint64_t bgit_pack_be64 (const unsigned char *b);

/* Read a whole file into a malloc'd buffer. Silent: sets errno and returns
   NULL, so the caller words its own message. Caller frees. */
unsigned char *bgit_pack_slurp (const char *path, size_t *out_len);

/* The last pack whose SHA-1 trailer was verified, kept so a loop of reads
   over one pack checksums it once. The comparison is over every byte,
   trailer included; nothing else about the pack is remembered. */
int bgit_pack_checksum_cached (const unsigned char *pack, size_t plen);
void bgit_pack_remember_verified (const unsigned char *pack, size_t plen);
void bgit_pack_cache_release (void);

/* Write a deflated loose object under REPO, creating .git/objects and the
   fanout directory as needed. An object already present is left alone. */
int bgit_pack_write_loose (const char *repo, const char *sha,
                           const unsigned char *deflated, size_t dlen);

/* Read a loose object, silently, returning its type and content without the
   header. Caller frees *content_out. Returns 0, or -1. */
int bgit_pack_read_loose (const char *repo, const char *sha_hex, int *type_out,
                          unsigned char **content_out, size_t *clen_out);

/* Pack offset of SHA from the idx, or (uint64_t)-1 when it is absent or the
   idx is too small or malformed for the indexed read. Silent. */
uint64_t bgit_pack_lookup_offset (const unsigned char *idx, size_t ilen,
                                  const unsigned char *sha);

/* Decode an object's type and size header at OFF. Returns 0, or -1 for a
   header no git would have written. Silent. */
int bgit_pack_read_obj_header (const unsigned char *pack, size_t plen,
                               uint64_t off, int *type_out, uint64_t *size_out,
                               uint64_t *new_off);

/* Inflate SRC into a malloc'd buffer, reporting how much input it used.
   EXPECTED is a size hint. Caller frees *out. Silent. */
int bgit_pack_inflate (const unsigned char *src, size_t srcn, size_t expected,
                       unsigned char **out, size_t *out_len, size_t *bytes_used);

/* Apply a git delta to a base. Caller frees *out. Silent. */
int bgit_pack_apply_delta (const unsigned char *base, size_t baselen,
                           const unsigned char *delta, size_t deltan,
                           unsigned char **out, size_t *out_len);

/* A delta turns one object into another by copying runs from it and
   writing the rest out. Making one asks the same question over and over —
   where in the base does this run appear — so what the base offers is
   worked out once, kept in an index, and asked of every target after
   that. The index borrows BASE, which must outlive it. */
typedef struct bgit_delta_index bgit_delta_index;

bgit_delta_index *bgit_delta_index_create (const unsigned char *base,
                                          size_t baselen);
void bgit_delta_index_free (bgit_delta_index *index);

/* A git delta that turns the index's base into TARGET. Gives up, with -1
   and nothing allocated, when what it has written already passes MAX —
   a delta no smaller than that is not worth keeping. Caller frees *out. */
int bgit_delta_create (const bgit_delta_index *index,
                       const unsigned char *target, size_t targetlen,
                       size_t max, unsigned char **out, size_t *out_len);

/* Read the object at OFF, resolving OFS_DELTA within the pack and REF_DELTA
   against the pack or a loose base under REPO. DEPTH bounds the delta chain.
   Caller frees *out. Silent. */
int bgit_pack_read_object_at (const unsigned char *pack, size_t plen,
                              const unsigned char *idx, size_t ilen,
                              const char *repo, uint64_t off, int *type_out,
                              unsigned char **out, size_t *out_len, int depth);

/* Encode an object's type and size header. OUT needs at least 16 bytes. */
void bgit_pack_encode_obj_header (int type, size_t size, unsigned char *out,
                                  size_t *out_len);

/* Append bytes to a growing malloc'd buffer. Returns 0, or -1. */
int bgit_pack_buf_append (unsigned char **out, size_t *out_len, size_t *out_cap,
                          const void *p, size_t n);

/* Read one whole packfile from FD, and no more than that. A stream
   carrying a pack does not end where the pack does — the far end goes on
   waiting for an answer — so the pack is parsed as it arrives and the
   reading stops after its last object and the twenty bytes of checksum
   that follow. ALREADY is what has been read off FD already and belongs
   to the pack, which is what whatever read the packets before it has in
   hand. Caller frees *out. Returns 0, or -1. */
int bgit_pack_read_stream (int fd, const unsigned char *already,
                           size_t already_len, unsigned char **out,
                           size_t *out_len);

/* CRC-32 of a byte range, as the idx CRC table stores it. */
uint32_t bgit_pack_crc32 (const unsigned char *p, size_t n);

/* One object's idx entry, for writing a .idx. */
struct bgit_pack_idx_entry {
    unsigned char sha[20];
    uint32_t crc;
    uint64_t off;
};

/* Write a v2 .idx for ENTS (sorted here) paired with a pack whose trailer
   SHA-1 is PACK_SHA. Atomic via mkstemp and rename. */
int bgit_pack_write_idx_v2 (const char *idx_path,
                            struct bgit_pack_idx_entry *ents, size_t n,
                            const unsigned char pack_sha[20]);

/* Validate a v2 .idx: magic, version, fanout monotonicity, an exact size for
   its object and overflow counts, and the SHA-1 trailer. With
   EXPECTED_PACK_SHA20, also check the embedded pack id. */
int bgit_pack_verify_idx (const unsigned char *idx, size_t ilen,
                          const unsigned char *expected_pack_sha20);

/* Check every CRC-32 in the idx against the packed object bytes. */
int bgit_pack_verify_idx_crc32 (const unsigned char *idx, size_t ilen,
                                const unsigned char *pack, size_t plen);

#endif /* BASH_OS_GIT_PACK_H */
