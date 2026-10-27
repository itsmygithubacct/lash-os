/* SPDX-License-Identifier: MIT */
/* _git/index.h — git index (.git/index) reading and writing.
 *
 * Format (v2): big-endian 32-bit fields, except where noted.
 *   Header: "DIRC" + version (4 bytes BE) + entry_count (4 bytes BE)
 *   N entries:
 *     ctime_sec, ctime_nsec, mtime_sec, mtime_nsec (4×4 bytes)
 *     dev, ino, mode, uid, gid, file_size                  (6×4 bytes)
 *     sha1[20]
 *     flags (2 bytes BE; low 12 = path length, capped at 0xFFF)
 *     path (NUL-terminated; total entry padded to 8-byte boundary,
 *           with at least 1 NUL pad byte)
 *   Trailer: 20-byte SHA-1 of all preceding bytes
 *
 * v3 adds a second flags field on entries marked CE_EXTENDED. Reads accept
 * v2 and v3; writes use v3 when extended flags need preserving.
 *
 * These functions report their own failures with builtin_error, so a caller
 * only has to choose an exit status.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_INDEX_H
#define BASH_OS_GIT_INDEX_H

#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

/* One decoded index entry, with its own path. */
typedef struct {
    uint32_t ctime_sec, ctime_nsec;
    uint32_t mtime_sec, mtime_nsec;
    uint32_t dev, ino, mode, uid, gid, size;
    unsigned char sha[20];
    uint16_t flags;     /* low 12 bits: path length (capped 0xFFF); high 4: stage etc. */
    uint16_t flags2;    /* v3: skip-worktree (0x4000), intent-to-add (0x2000) */
    char *path;
} bgit_index_entry;

/* A validated on-disk entry and its path, both borrowed from the backing
   buffer that bgit_index_read_views returns. Reading commands need no more
   than this; editing commands decode complete entries instead. */
typedef struct {
    const unsigned char *disk;
    const char *path;
} bgit_index_view;

/* Big-endian readers, for callers walking the on-disk bytes of a view. */
uint32_t bgit_be32 (const unsigned char *buf, size_t off);
uint16_t bgit_be16 (const unsigned char *buf, size_t off);

/* Parse an octal mode, or a stage between 0 and 3. Return 0, or -1. */
int bgit_index_parse_mode (const char *s, uint32_t *out);
int bgit_index_parse_stage (const char *s, int *out);

/* A repository-relative path: no empty, dot, parent or .git components. */
int bgit_index_path_valid (const char *path);

/* Copy ctime, mtime, dev, ino, mode, uid, gid and size from ST. */
void bgit_index_entry_set_stat (bgit_index_entry *e, const struct stat *st);

/* Free N entries and their paths. */
void bgit_index_free_entries (bgit_index_entry *e, size_t n);

/* An entry written in the same clock tick as the index itself cannot be
   trusted by its stat data alone: the file may have been changed again
   within that tick, with the same size, and nothing would show. git calls
   such an entry racily clean and reads the content instead. The index's own
   timestamp is remembered when it is read, and an entry at or after it is
   racy. */
int bgit_index_racy (const bgit_index_entry *entry);

/* Parse and validate the index at PATH, including its SHA-1 trailer.
   *out and *backing are two allocations a reading caller frees together. */
int bgit_index_read_views (const char *path, bgit_index_view **out,
                           size_t *n_out, unsigned char **backing);

/* The same, also giving the length of BACKING, the whole file, for a caller
   that goes on to the extensions between the entries and the trailer. */
int bgit_index_read_views_len (const char *path, bgit_index_view **out,
                               size_t *n_out, unsigned char **backing,
                               size_t *len_out);

/* Git-compatible listing parser, including v4 names. No trailer, path,
   padding or order validation: mutation callers validate decoded entries.
   BACKING retains the raw file for extensions; EXTENSIONS is their offset. */
int bgit_index_read_listing (const char *path, bgit_index_entry **out,
                             size_t *n_out, unsigned char **backing,
                             size_t *len_out, size_t *extensions);
int bgit_index_verify_checksum (const unsigned char *buf, size_t len);

/* The same, decoded into entries that own their paths, for editing. */
int bgit_index_read (const char *path, bgit_index_entry **out, size_t *n_out);

/* The second half of bgit_index_read, for a caller that inspects the views
   first: decode N views read from PATH into entries, record PATH's
   timestamp for the racy-entry rule, and free VIEWS and BACKING either way. */
int bgit_index_decode_views (const char *path, bgit_index_view *views,
                             size_t n, unsigned char *backing,
                             bgit_index_entry **out, size_t *n_out);

/* Forget the timestamp of the last index read, before writing an index
   that was not read in this call. */
void bgit_index_unstamp (void);
void bgit_index_stamp (const char *path);

/* Write ENTRIES to PATH as index v2, atomically, with the SHA-1 trailer. */
int bgit_index_write (const char *path, bgit_index_entry *entries, size_t n);

/* The same, with EXT_LEN bytes of complete extension records (signature,
   size, data) placed between the entries and the trailer. */
int bgit_index_write_ext (const char *path, bgit_index_entry *entries,
                          size_t n, const unsigned char *ext, size_t ext_len);

/* qsort comparator: by path, then by stage, the order git writes. */
int bgit_index_path_cmp (const void *a, const void *b);

/* Drop every entry with this path, whatever its stage. Returns 1 if any
   entry was removed. */
int bgit_index_remove_path (bgit_index_entry **entries, size_t *n,
                            const char *path);

/* Parse one "<mode> <sha> <stage> <path>" line. With WORKING_ROOT, stat
   WORKING_ROOT/path for the stat fields. Returns 0, -1 for a malformed
   line, or -2 for a bad stage. */
int bgit_index_line_to_entry (const char *line, const char *working_root,
                             bgit_index_entry *out);

/* Parse one `git update-index --index-info` line, which comes in three
   shapes: "mode SP sha TAB path", "mode SP sha SP stage TAB path" and
   "mode SP type SP sha TAB path". Mode 0 means remove, reported through
   IS_REMOVE. LINE is modified in place. Returns 0, or -1. */
int bgit_index_info_line_to_entry (char *line, bgit_index_entry *out,
                                   int *is_remove);

/* Release the verified-checksum snapshot held between calls. */
/* The object ids an index keeps for a conflict that has been resolved, in
   its resolve-undo extension, as 40 hex digits plus NUL. What fsck counts
   as held so a resolved conflict's sides are not called lost. Caller frees
   *out. Returns 0, or -1. Silent. */
int bgit_index_resolve_undo (const char *path, char (**out)[41], size_t *n);

/* The trees an index has already worked out for the paths it holds, in its
   cache-tree extension, as 40 hex digits plus NUL. git counts those as held
   before any commit names them. Caller frees *out. Returns 0, or -1.
   Silent. */
int bgit_index_cache_tree (const char *path, char (**out)[41], size_t *n);

void bgit_index_cache_release (void);

#endif /* BASH_OS_GIT_INDEX_H */
