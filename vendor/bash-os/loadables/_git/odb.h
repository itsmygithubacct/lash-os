/* SPDX-License-Identifier: MIT */
/* _git/odb.h — git objects: hashing, loose storage, and the object store.
 *
 * The lower half is the loose object format and the hashing that names an
 * object. The upper half is the store: one lookup across a repository's own
 * objects directory, its alternates, and every pack in them.
 *
 * Unless a function is marked silent, it reports its own failures with
 * builtin_error, in git's wording, so a caller only has to choose an exit
 * status.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_ODB_H
#define BASH_OS_GIT_ODB_H

#include <stddef.h>

#include "repo.h"

/* Object types, in the order git's object header names them. */
enum bgit_type { BGIT_BLOB, BGIT_TREE, BGIT_COMMIT, BGIT_TAG, BGIT_UNKNOWN };

/* "blob" / "tree" / "commit" / "tag", or "unknown". */
const char *bgit_type_name (enum bgit_type type);

/* 1 if NAME is one of git's four object types. */
int bgit_type_valid_name (const char *name);

/* 1 if NAME is acceptable as a `hash --literally` type: non-empty, and no
   control characters, spaces or DEL, which the object header cannot hold. */
int bgit_type_printable (const char *name);

/* 1 if S is non-empty and entirely hexadecimal. */
int bgit_all_hex (const char *s);

/* Format a 20-byte object id as 40 hex digits plus NUL. */
void bgit_sha_to_hex (const unsigned char *sha, char *out);

/* Parse 40 hex digits into a 20-byte object id. Returns 0, or -1 if HEX is
   not exactly 40 hexadecimal digits. */
int bgit_hex_to_sha (const char *hex, unsigned char *sha);

/* Parse the "<type> <size>\0" object header. Returns the offset of the
   payload, or -1 if the header is not one git would have written. Silent. */
long bgit_parse_header (const unsigned char *data, size_t len,
                        enum bgit_type *type, size_t *payload_size);

/* Hash through sha1dc. DIGEST always receives the canonical SHA-1; the
   return value is -1 when a collision attack was detected, so a caller can
   refuse to write the object. Silent. */
int bgit_sha1 (const unsigned char *data, size_t n, unsigned char digest[20]);

/* Deflate DATA into a malloc'd buffer. Caller frees *out. Silent. */
int bgit_deflate (const unsigned char *data, size_t n,
                  unsigned char **out, size_t *out_len);

/* Read the loose object SHA (40 hex digits) from one objects directory.
   *out holds the object as stored, header included. Caller frees. Silent,
   since a caller usually tries several directories. */
int bgit_read_loose_at (const char *objects_dir, const char *sha,
                        unsigned char **out, size_t *out_len);

/* Write deflated bytes as a loose object under OBJECTS_DIR, atomically and
   mode 0444 as git does. An object already present is left alone. */
int bgit_write_loose_at (const char *objects_dir, const char *sha,
                         const unsigned char *deflated, size_t dlen);

/* Build "<type> <len>\0<content>", hash it, and with DO_WRITE store it under
   OBJECTS_DIR. SHA_HEX receives the object id even when nothing is written. */
int bgit_write_object (const char *objects_dir, const char *type,
                       const unsigned char *content, size_t clen, int do_write,
                       char sha_hex[41]);

/* Read all of FD into a malloc'd buffer. Caller frees *out. Silent. */
int bgit_slurp_fd (int fd, unsigned char **out, size_t *out_len);

/* Read all of PATH into a malloc'd buffer. Caller frees *out. */
int bgit_slurp_file (const char *path, unsigned char **out, size_t *out_len);

/* ---- the object store: loose objects, every pack, and alternates ----
 *
 * One lookup over everything a repository can read: its own objects
 * directory, the alternates it names, and every pack in each of them. Packs
 * are memory-mapped, so a large repository costs address space, not copies.
 */

typedef struct bgit_pack_file bgit_pack_file;

/* One objects/xx directory, listed once and kept: naming a commit by an
   abbreviation asks which objects start with two given digits, and a log
   over a long history asks it thousands of times. */
typedef struct {
    char prefix[3];
    size_t dir;               /* which object directory it came from */
    char (*names)[39];        /* the other 38 digits, in order */
    size_t n;
} bgit_loose_dir;

typedef struct {
    char **object_dirs;
    size_t n_object_dirs;
    bgit_pack_file *packs;
    size_t n_packs;
    int packs_scanned;
    bgit_loose_dir *listed;
    size_t n_listed, cap_listed;
    /* Set by a caller that words its own messages, such as the git builtin,
       which says "fatal: ..." the way git does. */
    int quiet;
} bgit_odb;

/* Open the store for REPO. Packs are indexed on first use. */
int bgit_odb_open (const bgit_repo *repo, bgit_odb *odb);

/* Close it, unmapping every pack. */
void bgit_odb_release (bgit_odb *odb);

/* Resolve a full object id or a unique abbreviation of at least 4 digits,
   over loose objects and packs. Writes 40 hex digits plus NUL into FULL.
   Returns 0; -1 with git's message for unknown, ambiguous or malformed. */
int bgit_odb_resolve (bgit_odb *odb, const char *name, char full[41]);

/* 1 if the full object id is present, loose or packed. Silent. */
int bgit_odb_has (bgit_odb *odb, const char *sha);

/* Read an object by id or unique abbreviation. Returns its type and payload
   without the object header; caller frees *data. */
int bgit_odb_read (bgit_odb *odb, const char *name, enum bgit_type *type,
                   unsigned char **data, size_t *len);

/* 1 if a pack in the store holds the full object id. Silent. */
int bgit_odb_packed (bgit_odb *odb, const char *sha);

/* Every object the store holds, loose and packed, as 40 hex digits plus NUL,
   sorted and without repeats. What a command that has to look at all of them
   starts from. Caller frees *out. Returns 0, or -1. Silent. */
int bgit_odb_list (bgit_odb *odb, char (**out)[41], size_t *n);

/* Where the loose object SHA is kept, in the objects directory that holds
   it. Returns 0 and fills OUT, or -1 when no directory has it. Silent. */
int bgit_odb_loose_path (bgit_odb *odb, const char *sha, char *out,
                         size_t outsz);

#endif /* BASH_OS_GIT_ODB_H */
