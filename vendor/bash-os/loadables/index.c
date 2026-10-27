/* SPDX-License-Identifier: MIT */
/* index.c — read/write `.git/index`.
 *
 * The .git/index file is git's staging area — what `git add` writes, what
 * `git commit` reads to build a tree, and what `git status` cross-references
 * for the ctime/mtime fast-path. The format itself lives in _git/index.c,
 * shared with the other git builtins; this file is the command surface.
 *
 * Verbs:
 *   index read PATH [-V VAR]
 *       Print one line per entry: "<mode> <sha> <stage> <path>", the mode
 *       in at least six octal digits as `git ls-files --stage` prints it.
 *       With -V, bind a bash array instead.
 *
 *   index write PATH (entries on stdin: "<mode> <sha> <stage> <path>")
 *       Build binary index, atomic write (mkstemp + rename). Computes
 *       SHA-1 trailer. The path is everything after the one space or tab
 *       that follows the stage, up to the newline.
 *
 *   index --index-info [-z] PATH
 *       Import git update-index --index-info stdin forms and write PATH,
 *       applying each record as git applies it.
 *
 *   index add PATH BLOB_SHA WORKING_PATH [STAGE]
 *       Add/replace entry. lstat() WORKING_PATH for ctime/mtime/size.
 *
 *   index remove PATH WORKING_PATH
 *       Remove the entry, every stage of it. Re-writes the index.
 *
 *   index update-stat PATH WORKING_PATH
 *       Refresh stat fields for an existing entry without changing SHA.
 *
 *   index list PATH
 *       Print "<mode> <sha> <stage> <path>" lines. Synonym for read.
 *
 * An index is read whole and checked before anything is printed or
 * changed: first by _git/index.c (header, entry framing, padding, paths,
 * trailer) for shared callers. This command uses a separate listing reader
 * matching Git's leniency, with split-index and sparse-index expansion.
 * Editing validates the outgoing paths, order, flags and IDs and holds the
 * index lock through atomic replacement. Object IDs retain SHA1DC.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "loadables.h"
#include "arrayfunc.h"

#include "_git_index.h"
#include "_git_odb.h"
#include "_git_tree.h"

/* Static builds retain the checksum snapshot until replacement or exit. */
void
index_builtin_unload (char *name)
{
    (void) name;
    bgit_index_cache_release ();
}

#define BIDX_STAGE(flags) (((flags) >> 12) & 0x3)
#define BIDX_EXTENDED     0x4000
/* The bits of the v3 second flags word git defines: skip-worktree and
   intent-to-add. */
#define BIDX_FLAGS2_KNOWN 0x6000
#define BIDX_GITLINK      0160000

/* ---- git's path rules ---------------------------------------------------

   The paths git will not put in an index, as git on Linux decides them,
   where core.protectNTFS is on by default and core.protectHFS is off. A
   component may not be empty, ".", "..", or ".git" in any case. With NTFS
   protection it may not be what NTFS takes for ".git" either (".git" or
   "git~1", then only dots and spaces up to a '/' or '\'), and a symbolic
   link may not have a name NTFS takes for ".gitmodules". A trailing '/' is
   allowed only with a directory mode. */

/* NAME begins ".git" or "git~1", case aside, followed by nothing but dots
   and spaces up to the end of the component. */
static int
bidx_ntfs_dotgit (const char *name)
{
    const char *p;
    if (name[0] == '.' && strncasecmp (name + 1, "git", 3) == 0)
        p = name + 4;
    else if (strncasecmp (name, "git", 3) == 0 && name[3] == '~' && name[4] == '1')
        p = name + 5;
    else
        return 0;
    for (;; p++) {
        if (*p == '\0' || *p == '/' || *p == '\\') return 1;
        if (*p != '.' && *p != ' ') return 0;
    }
}

/* What NTFS may store ".gitmodules" as: the name itself, the short forms
   "gitmod~1" to "gitmod~4", or a hashed short form of up to six letters of
   "gi7eba" and a '~' with digits, in eight characters. Then only dots and
   spaces, to the end of the path or an NTFS stream separator ':'. */
static int
bidx_ntfs_dotgitmodules (const char *name)
{
    static const char hashed[] = "gi7eba";
    size_t at;
    if (name[0] == '.' && strncasecmp (name + 1, "gitmodules", 10) == 0)
        at = 11;
    else if (strncasecmp (name, "gitmod", 6) == 0 && name[6] == '~' &&
             name[7] >= '1' && name[7] <= '4')
        at = 8;
    else {
        int tilde = 0;
        for (at = 0; at < 8; at++) {
            unsigned char c = (unsigned char) name[at];
            if (c == '\0') return 0;
            if (tilde) {
                if (c < '0' || c > '9') return 0;
            } else if (c == '~') {
                at++;
                if (name[at] < '1' || name[at] > '9') return 0;
                tilde = 1;
            } else if (at >= 6 || (c & 0x80) || tolower (c) != hashed[at]) {
                return 0;
            }
        }
    }
    for (;; at++) {
        char c = name[at];
        if (c == '\0' || c == ':') return 1;
        if (c != ' ' && c != '.') return 0;
    }
}

/* A component that starts with '.', given what follows the dot. */
static int
bidx_dotfile_ok (const char *rest, uint32_t mode)
{
    if (rest[0] == '\0' || rest[0] == '/') return 0;            /* "." */
    if (rest[0] == '.' && (rest[1] == '\0' || rest[1] == '/'))
        return 0;                                               /* ".." */
    if (strncasecmp (rest, "git", 3) == 0) {
        if (rest[3] == '\0' || rest[3] == '/') return 0;        /* ".git" */
        if (S_ISLNK (mode) && strncasecmp (rest + 3, "modules", 7) == 0 &&
            (rest[10] == '\0' || rest[10] == '/'))
            return 0;                                           /* ".gitmodules" */
    }
    return 1;
}

static int
bidx_ntfs_component_bad (const char *p, uint32_t mode)
{
    return bidx_ntfs_dotgit (p) || (S_ISLNK (mode) && bidx_ntfs_dotgitmodules (p));
}

static int
bidx_path_ok (const char *path, uint32_t mode)
{
    const char *p = path;
    for (;;) {
        /* the first character of a component */
        if (bidx_ntfs_component_bad (p, mode)) return 0;
        char c = *p++;
        if (c == '/' || (c == '.' && !bidx_dotfile_ok (p, mode))) return 0;
        if (c == '\0') return S_ISDIR (mode);
        /* the rest of it; NTFS also takes a '\' to start a component */
        for (;;) {
            c = *p++;
            if (c == '\0') return 1;
            if (c == '/') break;
            if (c == '\\' && bidx_ntfs_component_bad (p, mode)) return 0;
        }
    }
}

/* The mode git records for MODE: a symbolic link, a sparse directory for
   exactly 040000, a gitlink for any other directory or gitlink mode, and
   otherwise a regular file, 755 if its owner may execute it and 644 if
   not. */
static uint32_t
bidx_canonical_mode (uint32_t mode)
{
    if (S_ISLNK (mode)) return S_IFLNK;
    if (mode == S_IFDIR) return S_IFDIR;
    if (S_ISDIR (mode) || (mode & S_IFMT) == BIDX_GITLINK) return BIDX_GITLINK;
    return S_IFREG | ((mode & 0100) ? 0755 : 0644);
}

/* ---- output ------------------------------------------------------------- */

/* Bash keeps stdout line buffered, so a listing written through stdio
   costs a system call per line. Lines are gathered here and written to the
   descriptor directly, after stdout has been flushed, which leaves the
   stdout stream as it was found: no error flag set for the next builtin. */
typedef struct {
    int fd;
    int failed;
    size_t used;
    char buf[65536];
} bidx_out;

static int
bidx_flush (bidx_out *o)
{
    size_t off = 0;
    while (off < o->used) {
        ssize_t w = write (o->fd, o->buf + off, o->used - off);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            if (w == 0) errno = EIO;
            sh_wrerror ();
            o->failed = 1;
            o->used = 0;
            return -1;
        }
        off += (size_t) w;
    }
    o->used = 0;
    return 0;
}

static int
bidx_put (bidx_out *o, const char *p, size_t n)
{
    while (n) {
        if (o->used == sizeof o->buf && bidx_flush (o) < 0) return -1;
        size_t room = sizeof o->buf - o->used;
        size_t k = n < room ? n : room;
        memcpy (o->buf + o->used, p, k);
        o->used += k;
        p += k;
        n -= k;
    }
    return 0;
}

/* The longest "<mode> <sha> <stage> " prefix, with the NUL that
   bgit_sha_to_hex writes after the digits: 11 + 1 + 41 + 3. */
#define BIDX_PREFIX_MAX 56

static size_t
bidx_prefix (char *line, uint32_t mode, const unsigned char *sha, int stage)
{
    char octal[12];
    size_t digits = 0, len = 0;
    do {
        octal[digits++] = (char) ('0' + (mode & 7));
        mode >>= 3;
    } while (mode);
    while (digits < 6) octal[digits++] = '0';
    while (digits) line[len++] = octal[--digits];
    line[len++] = ' ';
    bgit_sha_to_hex (sha, line + len);
    len += 40;
    line[len++] = ' ';
    line[len++] = (char) ('0' + stage);
    line[len++] = ' ';
    return len;
}

/* ---- locking ------------------------------------------------------------ */

typedef struct {
    char *path;
} bidx_lock;

/* Create "<PATH>.lock" exclusively, as git does, or say who holds it. */
static int
bidx_lock_take (bidx_lock *lock, const char *path)
{
    size_t need = strlen (path) + sizeof ".lock";
    lock->path = malloc (need);
    if (!lock->path) { builtin_error ("%s", strerror (ENOMEM)); return -1; }
    snprintf (lock->path, need, "%s.lock", path);
    int fd = open (lock->path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
    if (fd < 0) {
        if (errno == EEXIST)
            builtin_error ("Unable to create '%s': File exists.", lock->path);
        else
            builtin_error ("cannot create '%s': %s", lock->path, strerror (errno));
        free (lock->path);
        lock->path = NULL;
        return -1;
    }
    close (fd);
    return 0;
}

static void
bidx_lock_drop (bidx_lock *lock)
{
    if (!lock->path) return;
    unlink (lock->path);
    free (lock->path);
    lock->path = NULL;
}

/* ---- resolve-undo -------------------------------------------------------

   When a conflict's stages leave the index, git keeps their modes and ids
   in the REUC extension, which is how `git checkout -m` brings a resolved
   conflict back. Each record is the path and a NUL, three octal modes each
   ended by a NUL, and the 20-byte id of every stage whose mode is not
   zero; records are in path order, one per path. The changing verbs keep
   the records an index already has and add those their own removals
   displace, as git does. */

typedef struct {
    char *path;
    uint32_t mode[3];
    unsigned char sha[3][20];
} bidx_undo_rec;

typedef struct {
    bidx_undo_rec *rec;
    size_t n, cap;
} bidx_undo;

static void
bidx_undo_free (bidx_undo *u)
{
    for (size_t i = 0; i < u->n; i++) free (u->rec[i].path);
    free (u->rec);
    memset (u, 0, sizeof *u);
}

/* The record for PATH, made empty if there is none. */
static bidx_undo_rec *
bidx_undo_get (bidx_undo *u, const char *path)
{
    size_t lo = 0, hi = u->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int r = strcmp (path, u->rec[mid].path);
        if (r == 0) return &u->rec[mid];
        if (r < 0) hi = mid; else lo = mid + 1;
    }
    if (u->n == u->cap) {
        size_t cap = u->cap ? u->cap * 2 : 8;
        if (cap > SIZE_MAX / sizeof *u->rec) return NULL;
        bidx_undo_rec *grown = realloc (u->rec, cap * sizeof *grown);
        if (!grown) return NULL;
        u->rec = grown;
        u->cap = cap;
    }
    char *copy = strdup (path);
    if (!copy) return NULL;
    memmove (u->rec + lo + 1, u->rec + lo, (u->n - lo) * sizeof *u->rec);
    memset (&u->rec[lo], 0, sizeof u->rec[lo]);
    u->rec[lo].path = copy;
    u->n++;
    return &u->rec[lo];
}

/* Keep what E, a conflict stage leaving the index, held. */
static int
bidx_undo_note (bidx_undo *u, const bgit_index_entry *e)
{
    int stage = BIDX_STAGE (e->flags);
    if (!stage) return 0;
    bidx_undo_rec *r = bidx_undo_get (u, e->path);
    if (!r) return -1;
    r->mode[stage - 1] = e->mode;
    memcpy (r->sha[stage - 1], e->sha, 20);
    return 0;
}

/* Read the records of a REUC extension's SIZE bytes of DATA into U. A
   path given twice keeps its last record. Returns 0, or -1. */
static int
bidx_undo_parse (bidx_undo *u, const unsigned char *data, size_t size)
{
    size_t at = 0;
    while (at < size) {
        const unsigned char *nul = memchr (data + at, 0, size - at);
        if (!nul) return -1;
        const char *path = (const char *) data + at;
        at = (size_t) (nul - data) + 1;
        uint32_t mode[3];
        for (int i = 0; i < 3; i++) {
            nul = memchr (data + at, 0, size - at);
            if (!nul || nul == data + at) return -1;
            uint64_t v = 0;
            for (const unsigned char *p = data + at; p < nul; p++) {
                if (*p < '0' || *p > '7') return -1;
                v = v * 8 + (uint64_t) (*p - '0');
                if (v > UINT32_MAX) return -1;
            }
            mode[i] = (uint32_t) v;
            at = (size_t) (nul - data) + 1;
        }
        bidx_undo_rec *r = bidx_undo_get (u, path);
        if (!r) return -1;
        for (int i = 0; i < 3; i++) {
            r->mode[i] = mode[i];
            if (!mode[i]) continue;
            if (size - at < 20) return -1;
            memcpy (r->sha[i], data + at, 20);
            at += 20;
        }
    }
    return 0;
}

/* U as a complete REUC extension record, or NULL with *LEN 0 when there
   is nothing to keep. *FAILED is set if it could not be laid out. */
static unsigned char *
bidx_undo_ext (const bidx_undo *u, size_t *len, int *failed)
{
    *len = 0;
    if (!u || !u->n) return NULL;
    char modes[3][12];
    size_t size = 0;
    for (size_t i = 0; i < u->n; i++) {
        size += strlen (u->rec[i].path) + 1;
        for (int k = 0; k < 3; k++)
            size += (size_t) snprintf (modes[k], sizeof modes[k], "%o", (unsigned) u->rec[i].mode[k]) + 1
                    + (u->rec[i].mode[k] ? 20 : 0);
    }
    unsigned char *buf = size <= UINT32_MAX ? malloc (8 + size) : NULL;
    if (!buf) { *failed = 1; return NULL; }
    memcpy (buf, "REUC", 4);
    buf[4] = (unsigned char) (size >> 24); buf[5] = (unsigned char) (size >> 16);
    buf[6] = (unsigned char) (size >> 8);  buf[7] = (unsigned char) size;
    size_t at = 8;
    for (size_t i = 0; i < u->n; i++) {
        const bidx_undo_rec *r = &u->rec[i];
        size_t pl = strlen (r->path) + 1;
        memcpy (buf + at, r->path, pl);
        at += pl;
        for (int k = 0; k < 3; k++) {
            int w = snprintf (modes[k], sizeof modes[k], "%o", (unsigned) r->mode[k]);
            memcpy (buf + at, modes[k], (size_t) w + 1);
            at += (size_t) w + 1;
        }
        for (int k = 0; k < 3; k++) {
            if (!r->mode[k]) continue;
            memcpy (buf + at, r->sha[k], 20);
            at += 20;
        }
    }
    *len = at;
    return buf;
}

/* ---- checking and loading ----------------------------------------------- */

/* Where the entries end and the extensions begin: the last entry is padded
   with one to eight NULs to a multiple of eight bytes, as the reader has
   already checked. */
static size_t
bidx_entries_end (const bgit_index_view *views, size_t n, const unsigned char *backing)
{
    if (!n) return 12;
    const bgit_index_view *last = &views[n - 1];
    size_t used = (size_t) ((const unsigned char *) last->path - last->disk)
                  + strlen (last->path);
    return (size_t) (last->disk - backing) + used + (8 - used % 8);
}

/* What bgit_index_read_views leaves to its callers. VIEWS, N, BACKING and
   FLEN are as it returned them. Extended entry flags survive rewrites.
   Returns 0, or -1 with a message. */
static int
bidx_check (const char *path, const bgit_index_view *views, size_t n,
            const unsigned char *backing, size_t flen, int for_edit)
{
    (void) for_edit;
    uint32_t version = bgit_be32 (backing, 4);
    for (size_t i = 0; i < n; i++) {
        uint16_t flags = bgit_be16 (views[i].disk, 60);
        if (flags & BIDX_EXTENDED) {
            uint16_t flags2 = version >= 3 ? bgit_be16 (views[i].disk, 62) : 0;
            if (version < 3 || (flags2 & ~BIDX_FLAGS2_KNOWN)) {
                builtin_error ("%s: unknown index entry format 0x%08x", path,
                               ((unsigned) flags << 16) | flags2);
                return -1;
            }
        }
        if (i) {
            /* update-index --index-info can add a conflict stage beside
               stage 0. Preserve that state, requiring unique sorted stages. */
            int prev = BIDX_STAGE (bgit_be16 (views[i - 1].disk, 60));
            int r = strcmp (views[i - 1].path, views[i].path);
            if (r > 0 || (r == 0 && prev >= BIDX_STAGE (flags))) {
                builtin_error ("%s: %s at '%s'", path,
                               r > 0 ? "unordered index entries"
                                     : "repeated or unordered stages",
                               views[i].path);
                return -1;
            }
        }
    }

    size_t off = bidx_entries_end (views, n, backing);
    /* Extension records — signature, 32-bit size, data — fill the rest up
       to the trailer exactly. git skips one it does not know if the
       signature starts with a capital; any other marks an index that
       cannot be read correctly without it. */
    size_t end = flen - 20;
    while (off < end) {
        if (end - off < 8 || bgit_be32 (backing, off + 4) > end - off - 8) {
            builtin_error ("%s: truncated index extension", path);
            return -1;
        }
        const unsigned char *sig = backing + off;
        if (sig[0] < 'A' || sig[0] > 'Z') {
            builtin_error ("%s: index uses %c%c%c%c extension, which we do not "
                           "understand", path, isprint (sig[0]) ? sig[0] : '?',
                           isprint (sig[1]) ? sig[1] : '?',
                           isprint (sig[2]) ? sig[2] : '?',
                           isprint (sig[3]) ? sig[3] : '?');
            return -1;
        }
        off += 8 + (size_t) bgit_be32 (backing, off + 4);
    }
    return 0;
}

/* Resolve repository-dependent index formats without invoking external git. */
static int
bidx_repo_for_index (const char *path, bgit_repo *repo)
{
    if (bgit_repo_discover (".", repo) == 0) return 0;
    char *dir = strdup (path);
    if (!dir) return -1;
    char *slash = strrchr (dir, '/');
    if (slash) *slash = 0;
    else strcpy (dir, ".");
    int rc = bgit_repo_open (*dir ? dir : "/", repo);
    free (dir);
    if (rc < 0) builtin_error ("%s: repository required for split/sparse index", path);
    return rc;
}

static uint64_t
bidx_be64 (const unsigned char *p)
{
    return ((uint64_t) bgit_be32 (p, 0) << 32) | bgit_be32 (p, 4);
}

/* Walk an on-disk EWAH bitmap as Git's ewah_each_bit does. bit_size and
   the stored RLW index are not consulted: Git ignores both while reading.
   WHICH is "delete" or "replacement". A set bit at or past COUNT is the
   fatal Git prints for that bitmap. Returns -2 after printing it, or -1
   when the declared words do not fit in the extension. A literal past
   the copied words is the read ewah_each_bit performs past that buffer.
   On a two-word bitmap the position Git prints is the first set bit of
   the allocator word after the 16-byte copy. That position is not in the
   index: the same delete bitmap was "position for delete 69" for one
   index path and "position for delete 72" for a longer path. The read is
   not performed. When the walk has already reached COUNT, the overrun is
   refused. Any other overrun stops the walk. */
static int
bidx_bitmap_fatal (const char *which, size_t pos, size_t count)
{
    fprintf (stderr, "fatal: position for %s %d exceeds base index size %d\n",
             which, (int) pos, (int) count);
    return -2;
}

static int
bidx_bitmap (const unsigned char **cursor, size_t *remaining,
             unsigned char *bits, size_t count, const char *which)
{
    const unsigned char *p = *cursor;
    if (*remaining < 12) return -1;
    size_t words = bgit_be32 (p, 4);
    if (words > (*remaining - 12) / 8) return -1;
    size_t bytes = 12 + words * 8;
    size_t word = 0, pos = 0;
    while (word < words) {
        uint64_t rlw = bidx_be64 (p + 8 + 8 * word);
        word++;
        uint32_t run = (uint32_t) ((rlw >> 1) & 0xffffffffu);
        uint32_t literals = (uint32_t) (rlw >> 33);
        uint64_t run_bits = (uint64_t) run * 64;
        if (rlw & 1) {
            size_t at = pos >= count ? pos : count;
            if (pos >= count || run_bits > (uint64_t) (count - pos))
                return bidx_bitmap_fatal (which, at, count);
            for (uint64_t b = 0; b < run_bits; b++)
                bits[pos + (size_t) b] = 1;
            pos += (size_t) run_bits;
        } else if (run_bits > SIZE_MAX - pos) {
            pos = SIZE_MAX;
        } else {
            pos += (size_t) run_bits;
        }
        for (uint32_t lit = 0; lit < literals; lit++) {
            if (word >= words) {
                if (words == 2 && pos >= count)
                    return -1;
                goto consume;
            }
            uint64_t value = bidx_be64 (p + 8 + 8 * word);
            word++;
            for (int bit = 0; bit < 64; bit++) {
                if (((value >> bit) & 1) && pos >= count)
                    return bidx_bitmap_fatal (which, pos, count);
                if ((value >> bit) & 1) bits[pos] = 1;
                if (pos < SIZE_MAX) pos++;
            }
        }
    }
consume:
    *cursor += bytes; *remaining -= bytes;
    return 0;
}

static int bidx_read_format (const char *, int, int, const unsigned char *,
                             bgit_index_entry **, size_t *, bidx_undo *);

/* The 12-bit field is the stored name length. 0xfff means the length is
   the C string. A name whose first byte is NUL can still have length 1. */
static size_t
bidx_ce_namelen (const bgit_index_entry *e)
{
    size_t n = e->flags & 0xfff;
    if (n == 0xfff)
        return e->path ? strlen (e->path) : 0;
    return n;
}

static int
bidx_split (const char *path, const unsigned char *link, size_t length,
             bgit_index_entry **entries, size_t *n, int depth)
{
    static const unsigned char zero[20] = {0};
    if (length < 20 || depth) return -1;
    if (!memcmp (link, zero, 20)) return 0;
    bgit_repo repo;
    if (bidx_repo_for_index (path, &repo) < 0) return -1;
    char hex[41]; bgit_sha_to_hex (link, hex);
    size_t dirlen = strlen (repo.git_dir);
    char *shared = malloc (dirlen + 54);
    if (!shared) { bgit_repo_release (&repo); return -1; }
    snprintf (shared, dirlen + 54, "%s/sharedindex.%s", repo.git_dir, hex);
    bgit_repo_release (&repo);
    bgit_index_entry *base = NULL;
    size_t nb = 0;
    bidx_undo unused = {0};
    int rc = bidx_read_format (shared, 1, depth + 1, link, &base, &nb, &unused);
    bidx_undo_free (&unused);
    if (rc < 0) { free (shared); return -1; }
    free (shared);
    unsigned char *deleted = calloc (nb ? nb : 1, 1);
    unsigned char *replaced = calloc (nb ? nb : 1, 1);
    if (!deleted || !replaced) goto fail;
    const unsigned char *cursor = link + 20;
    size_t remaining = length - 20;
    int br = bidx_bitmap (&cursor, &remaining, deleted, nb, "delete");
    if (br == 0)
        br = bidx_bitmap (&cursor, &remaining, replaced, nb, "replacement");
    if (br == -2) goto fatal;
    if (br < 0 || remaining) goto fail;
    /* Replace runs before delete. An entry with both bits is replaced and
       then dropped; Git lists that result and does not die. */
    size_t replacements = 0;
    for (size_t i = 0; i < nb; i++)
        replacements += replaced[i];
    if (replacements > *n || nb > SIZE_MAX / sizeof *base - *n) goto fail;
    /* Git rejects these before it lists. The entry number is the base
       position for a replacement and the split-index position for an
       addition. Status stays 1; the fatal line is already printed. */
    size_t named = 0;
    for (size_t i = 0; i < nb; i++) {
        if (!replaced[i]) continue;
        if (named >= *n) break;
        if (bidx_ce_namelen (&(*entries)[named]) != 0) {
            fprintf (stderr, "fatal: corrupt link extension, entry %d should have "
                     "zero length name\n", (int) i);
            goto fatal;
        }
        named++;
    }
    for (; named < *n; named++) {
        if (bidx_ce_namelen (&(*entries)[named]) == 0) {
            fprintf (stderr, "fatal: corrupt link extension, entry %d should have "
                     "non-zero length name\n", (int) named);
            goto fatal;
        }
    }
    bgit_index_entry *joined = calloc (nb + *n ? nb + *n : 1, sizeof *joined);
    if (!joined) goto fail;
    size_t used = 0, source = 0;
    for (size_t i = 0; i < nb; i++) {
        if (replaced[i]) {
            char *name = base[i].path;
            base[i] = (*entries)[source];
            free (base[i].path);
            base[i].path = name;
            (*entries)[source++].path = NULL;
        }
        if (!deleted[i]) { joined[used++] = base[i]; base[i].path = NULL; }
    }
    for (; source < *n; source++) {
        joined[used++] = (*entries)[source]; (*entries)[source].path = NULL;
    }
    bgit_index_free_entries (base, nb);
    bgit_index_free_entries (*entries, *n);
    free (deleted); free (replaced);
    if (used > 1) qsort (joined, used, sizeof *joined, bgit_index_path_cmp);
    *entries = joined; *n = used;
    return 0;
fatal:
    free (deleted); free (replaced);
    bgit_index_free_entries (base, nb);
    return -2;
fail:
    free (deleted); free (replaced);
    bgit_index_free_entries (base, nb);
    return -1;
}

/* Git's cache_tree_update dies when a subtree consumes no entries.
   A directory of mode 040000 whose stored length matches the base does
   not: that child returns 1. verify_cache failures skip the die and
   expansion still runs. */
static int
bidx_update_one (bgit_index_entry *e, size_t n, size_t i,
                 const char *base, size_t baselen, int *die)
{
    if (*die) return -1;
    if (i < n && e[i].path) {
        size_t nl = bidx_ce_namelen (&e[i]);
        if (e[i].mode == 040000 && nl == baselen &&
            strncmp (e[i].path, base, baselen) == 0)
            return 1;
    }
    size_t start = i;
    while (i < n) {
        if (!e[i].path) break;
        size_t nl = bidx_ce_namelen (&e[i]);
        size_t plen = strlen (e[i].path);
        if (nl <= baselen || plen < baselen ||
            memcmp (base, e[i].path, baselen))
            break;
        const char *slash = strchr (e[i].path + baselen, '/');
        if (!slash) { i++; continue; }
        size_t sublen = (size_t) (slash - (e[i].path + baselen));
        int sub = bidx_update_one (e, n, i, e[i].path, baselen + sublen + 1, die);
        if (*die || sub < 0) return -1;
        if (sub == 0) { *die = 1; return -1; }
        i += (size_t) sub;
    }
    if (i < start || i - start > (size_t) 0x7fffffff) return -1;
    return (int) (i - start);
}

static int
bidx_empty_subtree (bgit_index_entry *e, size_t n)
{
    if (n > 0x7fffffff) return 0;
    for (size_t i = 0; i < n; i++)
        if (BIDX_STAGE (e[i].flags))
            return 0;
    for (size_t i = 0; i + 1 < n; i++) {
        if (!e[i].path || !e[i + 1].path) continue;
        size_t this_len = bidx_ce_namelen (&e[i]);
        size_t next_len = bidx_ce_namelen (&e[i + 1]);
        size_t next_strlen = strlen (e[i + 1].path);
        if (this_len < next_len && this_len <= next_strlen &&
            e[i + 1].path[this_len] == '/' &&
            strncmp (e[i].path, e[i + 1].path, this_len) == 0)
            return 0;
    }
    int die = 0;
    bidx_update_one (e, n, 0, "", 0, &die);
    return die;
}

static int
bidx_sparse (const char *path, bgit_index_entry **entries, size_t *n)
{
    size_t dirs = 0;
    for (size_t i = 0; i < *n; i++) dirs += (*entries)[i].mode == 040000;
    if (!dirs) return 0;
    bgit_repo repo;
    if (bidx_repo_for_index (path, &repo) < 0) return -1;
    bgit_odb odb;
    if (bgit_odb_open (&repo, &odb) < 0) { bgit_repo_release (&repo); return -1; }
    /* The missing-tree diagnostic is printed by the caller, in Git's words. */
    odb.quiet = 1;
    bgit_repo_release (&repo);
    bgit_index_entry *expanded = NULL;
    size_t used = 0;
    int rc = -1;
    for (size_t i = 0; i < *n; i++) {
        bgit_index_entry *entry = &(*entries)[i], *tree = NULL;
        size_t count = 1;
        if (entry->mode == 040000) {
            uint32_t ce_flags = ((uint32_t) entry->flags2 << 16) |
                                (entry->flags & ~0x0fffu);
            if (!(entry->flags2 & 0x4000))
                fprintf (stderr, "warning: index entry is a directory, but not sparse (%08x)\n",
                         ce_flags);
            size_t prefix = strlen (entry->path);
            if (!prefix) goto done;
            char id[41]; bgit_sha_to_hex (entry->sha, id);
            if (bgit_read_tree (&odb, id, &tree, &count) < 0) {
                /* Git prints both lines, drops this directory, and lists
                   the rest with status 0. The name has no trailing slash. */
                size_t show = prefix;
                if (show && entry->path[show - 1] == '/') show--;
                fprintf (stderr, "error: invalid object %06o %s for '%.*s'\n",
                         040000u, id, (int) show, entry->path);
                fprintf (stderr, "error: Could not read %s\n", id);
                count = 0;
                tree = NULL;
            }
            for (size_t j = 0; j < count; j++) {
                size_t tail = strlen (tree[j].path);
                if (prefix > SIZE_MAX - tail - 1) { bgit_index_free_entries (tree, count); goto done; }
                char *name = malloc (prefix + tail + 1);
                if (!name) { bgit_index_free_entries (tree, count); goto done; }
                memcpy (name, entry->path, prefix);
                memcpy (name + prefix, tree[j].path, tail + 1);
                free (tree[j].path); tree[j].path = name;
                /* The stored length is the full path, not the tree-relative
                   suffix. cache_tree_update compares that length. */
                size_t full = prefix + tail;
                tree[j].flags = (tree[j].flags & (uint16_t) ~0x0fffu) |
                                (uint16_t) (full >= 0xfff ? 0xfff : full);
                tree[j].flags2 = 0x4000;
            }
        }
        if (count > SIZE_MAX / sizeof *expanded - used) { bgit_index_free_entries (tree, count); goto done; }
        bgit_index_entry *grown = realloc (expanded, (used + count ? used + count : 1) * sizeof *expanded);
        if (!grown) { bgit_index_free_entries (tree, count); goto done; }
        expanded = grown;
        if (tree) {
            memcpy (expanded + used, tree, count * sizeof *tree);
            free (tree);
        } else if (count) {
            expanded[used] = *entry; entry->path = NULL;
        }
        used += count;
    }
    bgit_index_free_entries (*entries, *n);
    *entries = expanded; *n = used; expanded = NULL; used = 0;
    /* Git inserts expanded entries in place and does not re-sort. */
    rc = 0;
done:
    bgit_odb_release (&odb);
    bgit_index_free_entries (expanded, used);
    return rc;
}

/* A directory record in an untracked-cache extension: file count, directory
   count, a name, that many file names, then the child directories. A count
   this parser does not trust is not a refusal. */
#define BIDX_UNTR_MAX 10000

static int
bidx_untr_varint (const unsigned char **pp, const unsigned char *limit, size_t *out)
{
    const unsigned char *p = *pp;
    unsigned c;
    size_t val;
    if (p >= limit) return -1;
    c = *p++;
    val = c & 0x7f;
    while (c & 0x80) {
        if (val >= (SIZE_MAX >> 7)) return -1;
        if (p >= limit) return -1;
        c = *p++;
        val = ((val + 1) << 7) + (c & 0x7f);
    }
    *pp = p;
    *out = val;
    return 0;
}

static int
bidx_untr_dir (const unsigned char **pp, const unsigned char *limit,
               size_t *seen, int depth)
{
    const unsigned char *p = *pp, *eos;
    size_t files, dirs, i;
    if (depth > 64) return -1;
    if (bidx_untr_varint (&p, limit, &files) < 0) return -1;
    if (bidx_untr_varint (&p, limit, &dirs) < 0) return -1;
    if (files > BIDX_UNTR_MAX || dirs > BIDX_UNTR_MAX) return -1;
    eos = memchr (p, 0, (size_t) (limit - p));
    if (!eos) return -1;
    p = eos + 1;
    for (i = 0; i < files; i++) {
        eos = memchr (p, 0, (size_t) (limit - p));
        if (!eos) return -1;
        p = eos + 1;
    }
    if (*seen >= BIDX_UNTR_MAX) return -1;
    (*seen)++;
    for (i = 0; i < dirs; i++)
        if (bidx_untr_dir (&p, limit, seen, depth + 1) < 0) return -1;
    *pp = p;
    return 0;
}

/* 1 when ewah_each_bit would spin on a 1-run or walk far past the words
   it copied. 0 when this header is not that shape. VISIBLE and DECLARED
   are byte counts from P, not pointers, so a declared end past the file
   is never formed as an address. */
static int
bidx_ewah_spins (const unsigned char *p, size_t visible, size_t declared)
{
    size_t words, need, see, word;
    if (visible < 8 || declared < 8) return 0;
    words = bgit_be32 (p, 4);
    if (words > (SIZE_MAX - 12) / 8) return 0;
    need = 12 + words * 8;
    /* ewah_read_mmap fails, and each_bit is not called, when the declared
       extension does not hold the words and the RLW index. */
    if (declared < need) return 0;
    see = (visible - 8) / 8;
    if (see > words) see = words;
    word = 0;
    while (word < see) {
        uint64_t rlw = bidx_be64 (p + 8 + 8 * word);
        uint32_t run = (uint32_t) ((rlw >> 1) & 0xffffffffu);
        uint32_t literals = (uint32_t) (rlw >> 33);
        word++;
        /* A 1-run calls the callback once per bit. Past 2^28 words of
           run this does not finish: the measured hangs are runs of about
           2^31. A 0-run only adds to the position. */
        if ((rlw & 1) && run > (1u << 28)) return 1;
        /* A literal count past the copied words reads off the allocation.
           Counts at or below 2^20 were listed; the measured SIGSEGV is
           hundreds of millions of literals. */
        if (literals > (1u << 20) && (size_t) literals > words - word) return 1;
        if ((size_t) literals > see - word) break;
        word += literals;
    }
    return 0;
}

/* BODY is the in-file prefix of an UNTR body, IN_FILE bytes of it.
   DECLARED is the size field. Returns 1 only when the extension parses
   and one of its three bitmaps is a measured hang or SIGSEGV. */
static int
bidx_untr_spins (const unsigned char *body, size_t in_file, size_t declared)
{
    const unsigned char *p, *limit, *eos;
    size_t ident, total, seen, guard, at;
    int i;
    if (declared <= 1 || !in_file) return 0;
    if (declared - 1 < in_file) {
        if (body[declared - 1] != 0) return 0;
        guard = declared - 1;
    } else {
        guard = in_file;
    }
    limit = body + guard;
    p = body;
    if (bidx_untr_varint (&p, limit, &ident) < 0) return 0;
    if (ident > (size_t) (limit - p)) return 0;
    p += ident;
    /* Two on-disk stat records and dir_flags are 76 bytes, then two
       SHA-1 ids. The exclude string follows. */
    if ((size_t) (limit - p) < 117) return 0;
    p += 116;
    eos = memchr (p, 0, (size_t) (limit - p));
    if (!eos) return 0;
    p = eos + 1;
    if (bidx_untr_varint (&p, limit, &total) < 0) return 0;
    if (!total || total > BIDX_UNTR_MAX) return 0;
    seen = 0;
    if (bidx_untr_dir (&p, limit, &seen, 0) < 0) return 0;
    if (seen != total) return 0;
    at = (size_t) (p - body);
    for (i = 0; i < 3; i++) {
        size_t words, need, visible, declared_left;
        if (at > in_file || at > declared - 1) return 0;
        visible = in_file - at;
        declared_left = (declared - 1) - at;
        if (bidx_ewah_spins (body + at, visible, declared_left)) return 1;
        if (visible < 8 || declared_left < 8) return 0;
        words = bgit_be32 (body + at, 4);
        if (words > (SIZE_MAX - 12) / 8) return 0;
        need = 12 + words * 8;
        if (declared_left < need || need > SIZE_MAX - at) return 0;
        at += need;
    }
    return 0;
}

static int
bidx_read_format (const char *path, int for_edit, int depth,
                   const unsigned char *expected_checksum, bgit_index_entry **out, size_t *n_out, bidx_undo *undo)
{
    bgit_index_entry *entries = NULL;
    unsigned char *raw = NULL;
    size_t n = 0, length, off;
    if (bgit_index_read_listing (path, &entries, &n, &raw, &length, &off) < 0) return -1;
    /* Corrupt shared files must never be silently used. Ordinary listing
       follows Git and does not treat the trailer as authentication. */
    if (depth && (bgit_index_verify_checksum (raw, length) < 0 ||
                  memcmp (raw + length - 20, expected_checksum, 20))) goto bad;
    const unsigned char *link = NULL;
    size_t linklen = 0;
    int sparse = 0;
    long pagesize = sysconf (_SC_PAGESIZE);
    size_t page = pagesize > 0 ? (size_t) pagesize : 4096;
    size_t map_end = length > SIZE_MAX - page ? length
                     : ((length + page - 1) / page) * page;
    while (off <= length - 20 && length - 20 - off >= 8) {
        const unsigned char *sig = raw + off;
        size_t size = bgit_be32 (sig, 4), available = length - off - 8;
        /* read_untracked_extension sets end = data + sz and loads end[-1]
           whenever sz > 1. That load is a SIGSEGV once the byte is 256 KiB
           past the mapped page. A load in the mappings after the page,
           including a declared end of 262144 on a one-page file, is a
           listing. A 1-run longer than 2^28 words does not finish, and a
           literal count past the copied words above 2^20 is the SIGSEGV
           measured when the trailer lands in that bitmap. TREE, REUC, link
           and FSMN stop on their own remaining-size checks. */
        if (!memcmp (sig, "UNTR", 4) && size > 1) {
            int far = size > SIZE_MAX - 8 || off > SIZE_MAX - 8 - size;
            if (!far) {
                size_t touch = off + 8 + size - 1;
                far = touch >= map_end && touch - map_end >= 262144;
            }
            if (far) goto bad;
            {
                size_t in_file = size < available ? size : available;
                if (bidx_untr_spins (sig + 8, in_file, size)) goto bad;
            }
        }
        if (!memcmp (sig, "link", 4)) {
            if (link || size > available) goto bad;
            link = sig + 8; linklen = size;
        } else if (!memcmp (sig, "sdir", 4)) {
            sparse = 1;
        } else if (sig[0] < 'A' || sig[0] > 'Z') {
            goto bad;
        } else if (for_edit && !memcmp (sig, "REUC", 4)) {
            if (size > available || bidx_undo_parse (undo, sig + 8, size) < 0) goto bad;
        }
        if (size > length - off - 8) break;
        off += 8 + size;
    }
    if (link) {
        int sr = bidx_split (path, link, linklen, &entries, &n, depth);
        if (sr == -2) goto printed;
        if (sr < 0) goto bad;
    }
    int collapsed = sparse;
    for (size_t i = 0; !collapsed && i < n; i++)
        if (entries[i].mode == 040000)
            collapsed = 1;
    /* ensure_full_index runs cache_tree_update before expansion, and
       again after. A die there prints nothing else and lists nothing. */
    if (collapsed && bidx_empty_subtree (entries, n)) {
        fprintf (stderr, "fatal: index cache-tree records empty sub-tree\n");
        goto printed;
    }
    if (collapsed && bidx_sparse (path, &entries, &n) < 0) goto bad;
    if (collapsed && bidx_empty_subtree (entries, n)) {
        fprintf (stderr, "fatal: index cache-tree records empty sub-tree\n");
        goto printed;
    }
    if (for_edit) {
        for (size_t i = 0; i < n; i++) {
            if (!bidx_path_ok (entries[i].path, entries[i].mode) || S_ISDIR (entries[i].mode) ||
                (i && bgit_index_path_cmp (&entries[i - 1], &entries[i]) >= 0)) goto bad;
        }
    }
    free (raw);
    bgit_index_stamp (path);
    *out = entries; *n_out = n;
    return 0;
bad:
    builtin_error ("%s: invalid index or shared/sparse index data", path);
printed:
    free (raw); bgit_index_free_entries (entries, n);
    return -1;
}

/* Read and check PATH for a change, with its resolve-undo records in
   UNDO. With MISSING_OK, a PATH that does not exist is an empty index. */
static int
bidx_load (const char *path, int missing_ok, bgit_index_entry **out,
           size_t *n_out, bidx_undo *undo)
{
    struct stat st;
    *out = NULL;
    *n_out = 0;
    memset (undo, 0, sizeof *undo);
    if (missing_ok && stat (path, &st) < 0 && errno == ENOENT) {
        *out = calloc (1, sizeof **out);
        return *out ? 0 : -1;
    }
    if (bidx_read_format (path, 1, 0, NULL, out, n_out, undo) < 0) {
        bidx_undo_free (undo);
        return -1;
    }
    return 0;
}

/* ---- an index being changed --------------------------------------------- */

/* Entries live in POOL; ORDER lists the live ones in index order, by path
   and then stage. Inserting or removing moves ORDER's indices, not whole
   entries. */
typedef struct {
    bgit_index_entry *pool;
    size_t pool_n, pool_cap;
    size_t *order;
    size_t n, cap;
    bidx_undo *undo;    /* where removed conflict stages are noted */
    int failed;         /* a note could not be made */
    int changed;        /* an entry was added, replaced or removed */
} bidx_set;

#define BIDX_AT(s, i) (&(s)->pool[(s)->order[(i)]])

static int
bidx_set_init (bidx_set *s, bgit_index_entry *entries, size_t n)
{
    s->pool = entries;
    s->undo = NULL;
    s->failed = 0;
    s->changed = 0;
    s->pool_n = s->pool_cap = n;
    s->n = n;
    s->cap = n ? n : 16;
    s->order = malloc (s->cap * sizeof *s->order);
    if (!s->order) return -1;
    for (size_t i = 0; i < n; i++) s->order[i] = i;
    return 0;
}

static void
bidx_set_free (bidx_set *s)
{
    for (size_t i = 0; i < s->pool_n; i++) free (s->pool[i].path);
    free (s->pool);
    free (s->order);
    memset (s, 0, sizeof *s);
}

/* The entries in index order, with their paths, leaving S empty. */
static bgit_index_entry *
bidx_set_take (bidx_set *s, size_t *n_out)
{
    bgit_index_entry *out = malloc ((s->n ? s->n : 1) * sizeof *out);
    if (!out) return NULL;
    for (size_t i = 0; i < s->n; i++) {
        out[i] = *BIDX_AT (s, i);
        BIDX_AT (s, i)->path = NULL;
    }
    *n_out = s->n;
    bidx_set_free (s);
    return out;
}

/* git's order: the bytes of NAME[0..LEN) against those of PATH, a prefix
   first, then the stage. */
static int
bidx_cmp (const char *name, size_t len, int stage, const bgit_index_entry *e)
{
    size_t elen = strlen (e->path);
    int r = memcmp (name, e->path, len < elen ? len : elen);
    if (r) return r;
    if (len != elen) return len < elen ? -1 : 1;
    return stage - BIDX_STAGE (e->flags);
}

/* Find (NAME[0..LEN), STAGE). Returns 1 with *POS at it, or 0 with *POS
   where it would go. */
static int
bidx_find (const bidx_set *s, const char *name, size_t len, int stage, size_t *pos)
{
    size_t lo = 0, hi = s->n;
    /* Indexes are mostly built in order, so try the end first. */
    if (hi && bidx_cmp (name, len, stage, BIDX_AT (s, hi - 1)) > 0) {
        *pos = hi;
        return 0;
    }
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int r = bidx_cmp (name, len, stage, BIDX_AT (s, mid));
        if (r == 0) { *pos = mid; return 1; }
        if (r < 0) hi = mid; else lo = mid + 1;
    }
    *pos = lo;
    return 0;
}

static void
bidx_remove_at (bidx_set *s, size_t pos)
{
    bgit_index_entry *e = BIDX_AT (s, pos);
    if (s->undo && bidx_undo_note (s->undo, e) < 0) s->failed = 1;
    free (e->path);
    e->path = NULL;
    memmove (s->order + pos, s->order + pos + 1, (s->n - pos - 1) * sizeof *s->order);
    s->n--;
    s->changed = 1;
}

/* Insert E, whose path S takes over, at POS. */
static int
bidx_insert_at (bidx_set *s, size_t pos, const bgit_index_entry *e)
{
    if (s->pool_n == s->pool_cap) {
        size_t cap = s->pool_cap ? s->pool_cap * 2 : 16;
        if (cap > SIZE_MAX / sizeof *s->pool) return -1;
        bgit_index_entry *pool = realloc (s->pool, cap * sizeof *pool);
        if (!pool) return -1;
        s->pool = pool;
        s->pool_cap = cap;
    }
    if (s->n == s->cap) {
        size_t cap = s->cap * 2;
        if (cap > SIZE_MAX / sizeof *s->order) return -1;
        size_t *order = realloc (s->order, cap * sizeof *order);
        if (!order) return -1;
        s->order = order;
        s->cap = cap;
    }
    s->pool[s->pool_n] = *e;
    memmove (s->order + pos + 1, s->order + pos, (s->n - pos) * sizeof *s->order);
    s->order[pos] = s->pool_n++;
    s->n++;
    s->changed = 1;
    return 0;
}

/* Remove every stage of NAME. Returns how many entries went. */
static size_t
bidx_remove_name (bidx_set *s, const char *name)
{
    size_t pos, gone = 0, len = strlen (name);
    bidx_find (s, name, len, 0, &pos);
    while (pos < s->n && strcmp (BIDX_AT (s, pos)->path, name) == 0) {
        bidx_remove_at (s, pos);
        gone++;
    }
    return gone;
}

/* Entries at E's stage that have E's path as a directory: "a/b" for "a".
   They sort right after where E goes, at POS. */
static int
bidx_conflict_below (bidx_set *s, const char *name, size_t len, int stage,
                     size_t pos, int replace)
{
    int found = 0;
    while (pos < s->n) {
        const bgit_index_entry *p = BIDX_AT (s, pos);
        size_t plen = strlen (p->path);
        if (len >= plen || memcmp (name, p->path, len) != 0) break;
        if (BIDX_STAGE (p->flags) != stage || p->path[len] != '/') { pos++; continue; }
        found = 1;
        if (!replace) break;
        bidx_remove_at (s, pos);
    }
    return found;
}

/* Entries at E's stage named by a leading directory of E's path: "a" for
   "a/b". As in git, the search stops at the first directory that already
   has an entry at this stage beneath it, and skips the search entirely
   when E sorts after the last entry with no '/' where they part. */
static int
bidx_conflict_above (bidx_set *s, const char *name, size_t len, int stage,
                     int replace)
{
    int found = 0;
    if (s->n) {
        const char *last = BIDX_AT (s, s->n - 1)->path;
        size_t k = 0;
        while (name[k] && name[k] == last[k]) k++;
        if ((unsigned char) name[k] > (unsigned char) last[k] && name[k] != '/')
            return 0;
    }
    for (;;) {
        do {
            if (len == 0) return found;
        } while (name[--len] != '/');
        size_t pos;
        if (bidx_find (s, name, len, stage, &pos)) {
            found = 1;
            if (!replace) return found;
            bidx_remove_at (s, pos);
            continue;
        }
        for (; pos < s->n; pos++) {
            const bgit_index_entry *p = BIDX_AT (s, pos);
            if (strlen (p->path) <= len || p->path[len] != '/' ||
                memcmp (p->path, name, len) != 0)
                break;
            if (BIDX_STAGE (p->flags) == stage) return found;
        }
    }
}

enum { BIDX_ADD_OK = 0, BIDX_ADD_NOMEM = -1, BIDX_ADD_PATH = -2,
       BIDX_ADD_CONFLICT = -3 };

/* Add E as git adds an entry. The same path and stage is replaced in
   place. Otherwise a stage-0 entry first displaces the path's other
   stages, and an entry at the same stage that is E's parent directory or
   lies beneath E's path is either removed (REPLACE) or refused. S takes
   E's path in every case. */
static int
bidx_add (bidx_set *s, bgit_index_entry *e, int replace)
{
    size_t len = strlen (e->path), pos;
    int stage = BIDX_STAGE (e->flags);
    if (bidx_find (s, e->path, len, stage, &pos)) {
        bgit_index_entry *old = BIDX_AT (s, pos);
        free (old->path);
        *old = *e;
        s->changed = 1;
        return BIDX_ADD_OK;
    }
    if (stage == 0)
        while (pos < s->n && strcmp (BIDX_AT (s, pos)->path, e->path) == 0)
            bidx_remove_at (s, pos);
    if (!bidx_path_ok (e->path, e->mode)) {
        free (e->path);
        return BIDX_ADD_PATH;
    }
    int below = bidx_conflict_below (s, e->path, len, stage, pos, replace);
    int above = bidx_conflict_above (s, e->path, len, stage, replace);
    if (below || above) {
        if (!replace) { free (e->path); return BIDX_ADD_CONFLICT; }
        bidx_find (s, e->path, len, stage, &pos);
    }
    if (bidx_insert_at (s, pos, e) < 0) {
        free (e->path);
        return BIDX_ADD_NOMEM;
    }
    return BIDX_ADD_OK;
}

/* Write ENTRIES, with UNDO's records if any, to PATH and release LOCK. */
static int
bidx_store (const char *path, bgit_index_entry *entries, size_t n,
            const bidx_undo *undo, bidx_lock *lock)
{
    /* Validate the final state: an index-info stream may insert a null ID
       and remove it again before committing. Never install a null entry. */
    static const unsigned char null_oid[20] = {0};
    for (size_t i = 0; i < n; i++) {
        if (memcmp (entries[i].sha, null_oid, sizeof null_oid) == 0) {
            builtin_error ("%s: cache entry has null sha1: %s", path,
                           entries[i].path);
            bidx_lock_drop (lock);
            return EXECUTION_FAILURE;
        }
    }
    size_t ext_len;
    int failed = 0;
    unsigned char *ext = bidx_undo_ext (undo, &ext_len, &failed);
    for (size_t i = 0; !failed && i < n; i++) {
        if (!S_ISDIR (entries[i].mode)) continue;
        unsigned char *grown = realloc (ext, ext_len + 8);
        if (!grown) { failed = 1; break; }
        ext = grown;
        memcpy (ext + ext_len, "sdir\0\0\0\0", 8);
        ext_len += 8;
        break;
    }
    int rc = failed ? -1 : bgit_index_write_ext (path, entries, n, ext, ext_len);
    free (ext);
    bidx_lock_drop (lock);
    return rc < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

/* Stdin closed early by an error is not the end of the input. */
static int
bidx_input_failed (const char *verb)
{
    if (!ferror (stdin)) return 0;
    builtin_error ("%s: read error: %s", verb, strerror (errno));
    clearerr (stdin);
    return 1;
}

/* ---- verbs -------------------------------------------------------------- */

static int
bidx_bind_check (const char *var)
{
    if (!legal_identifier ((char *) var)) {
        builtin_error ("read: '%s': not a valid identifier", var);
        return EX_USAGE;
    }
    SHELL_VAR *v = find_variable_noref ((char *) var);
    SHELL_VAR *target = find_variable ((char *) var);
    if ((v && (readonly_p (v) || noassign_p (v))) ||
        (target && (readonly_p (target) || noassign_p (target)))) {
        builtin_error ("read: %s: readonly variable", var);
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bidx_read_cmd (WORD_LIST *args)
{
    const char *path = NULL, *var = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-V") == 0) {
            if (!p->next) { builtin_error ("read: -V needs a variable name"); return EX_USAGE; }
            var = p->next->word->word;
            p = p->next;
        } else if (w[0] == '-' && w[1] != '\0') {
            builtin_error ("read: unknown flag %s", w); return EX_USAGE;
        } else {
            if (path) { builtin_error ("read: too many"); return EX_USAGE; }
            path = w;
        }
    }
    if (!path) { builtin_error ("read: PATH required"); return EX_USAGE; }
    if (var) {
        int rc = bidx_bind_check (var);
        if (rc != EXECUTION_SUCCESS) return rc;
    }

    bgit_index_entry *entries = NULL;
    size_t n = 0;
    bidx_undo undo = {0};
    if (bidx_read_format (path, 0, 0, NULL, &entries, &n, &undo) < 0)
        return EXECUTION_FAILURE;

    int rc = EXECUTION_SUCCESS;
    if (var) {
        SHELL_VAR *arr;
        unbind_variable ((char *) var);
        arr = find_or_make_array_variable ((char *) var, 1);
        if (!arr || !array_p (arr)) {
            builtin_error ("read: %s: cannot make an array", var);
            bgit_index_free_entries (entries, n);
            return EXECUTION_FAILURE;
        }
        ARRAY *a = array_cell (arr);
        size_t cap = 0;
        char *line = NULL;
        for (size_t i = 0; i < n; i++) {
            const char *name = *entries[i].path ? entries[i].path : "./";
            size_t pathlen = strlen (name);
            if (pathlen + BIDX_PREFIX_MAX + 1 > cap) {
                cap = pathlen + BIDX_PREFIX_MAX + 1;
                char *grown = realloc (line, cap);
                if (!grown) { rc = EXECUTION_FAILURE; break; }
                line = grown;
            }
            uint16_t flags = entries[i].flags;
            size_t len = bidx_prefix (line, entries[i].mode,
                                      entries[i].sha, BIDX_STAGE (flags));
            memcpy (line + len, name, pathlen + 1);
            array_insert (a, (arrayind_t) i, line);
        }
        free (line);
    } else {
        bidx_out *o = malloc (sizeof *o);
        if (!o) { bgit_index_free_entries (entries, n); return EXECUTION_FAILURE; }
        fflush (stdout);
        o->fd = fileno (stdout);
        o->failed = 0;
        o->used = 0;
        for (size_t i = 0; i < n && !o->failed; i++) {
            uint16_t flags = entries[i].flags;
            const char *name = *entries[i].path ? entries[i].path : "./";
            size_t pathlen = strlen (name);
            uint32_t mode = entries[i].mode;
            if (sizeof o->buf - o->used < pathlen + BIDX_PREFIX_MAX + 1) {
                if (bidx_flush (o) < 0) break;
                if (sizeof o->buf < pathlen + BIDX_PREFIX_MAX + 1) {
                    /* a path longer than the buffer goes through in pieces */
                    char prefix[BIDX_PREFIX_MAX];
                    size_t len = bidx_prefix (prefix, mode, entries[i].sha, BIDX_STAGE (flags));
                    if (bidx_put (o, prefix, len) < 0 ||
                        bidx_put (o, name, pathlen) < 0 ||
                        bidx_put (o, "\n", 1) < 0)
                        break;
                    continue;
                }
            }
            char *line = o->buf + o->used;
            size_t len = bidx_prefix (line, mode, entries[i].sha, BIDX_STAGE (flags));
            memcpy (line + len, name, pathlen);
            len += pathlen;
            line[len++] = '\n';
            o->used += len;
        }
        if (!o->failed) bidx_flush (o);
        if (o->failed) rc = EXECUTION_FAILURE;
        free (o);
    }
    bgit_index_free_entries (entries, n);
    return rc;
}

/* Parse "<mode> <sha> <stage> <path>" for write. Fields are separated by
   spaces or tabs; exactly one separates the stage from the path, which
   runs to the end of LINE. Returns 0, -1 malformed, -2 bad stage, -3 bad
   path. */
static int
bidx_write_line (char *line, bgit_index_entry *out)
{
    char *fields[3];
    char *p = line;
    size_t len = strlen (line);
    if (len && line[len - 1] == '\n') line[--len] = '\0';
    for (int i = 0; i < 3; i++) {
        while (*p == ' ' || *p == '\t') p++;
        fields[i] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (!*p || p == fields[i]) return -1;
        *p++ = '\0';
    }
    if (!*p) return -1;
    uint32_t mode;
    int stage;
    memset (out, 0, sizeof *out);
    if (bgit_index_parse_mode (fields[0], &mode) < 0 || mode == 0 ||
        bgit_hex_to_sha (fields[1], out->sha) < 0)
        return -1;
    if (bgit_index_parse_stage (fields[2], &stage) < 0) return -2;
    out->mode = bidx_canonical_mode (mode);
    if (!bidx_path_ok (p, out->mode) || p[strlen (p) - 1] == '/') return -3;
    size_t pl = strlen (p);
    out->flags = (uint16_t) ((stage << 12) | (pl > 0xFFF ? 0xFFF : pl));
    out->path = strdup (p);
    return out->path ? 0 : -1;
}

static int
bidx_write_cmd (WORD_LIST *args)
{
    const char *path = args ? args->word->word : NULL;
    if (!path) { builtin_error ("write: PATH required"); return EX_USAGE; }
    if (args->next) { builtin_error ("write: too many"); return EX_USAGE; }
    bgit_index_unstamp ();

    size_t cap = 16, n = 0;
    bgit_index_entry *entries = calloc (cap, sizeof (bgit_index_entry));
    if (!entries) return EXECUTION_FAILURE;
    char *line = NULL; size_t line_cap = 0;
    clearerr (stdin);
    while (getline (&line, &line_cap, stdin) > 0) {
        if (n + 1 > cap) {
            if (cap > SIZE_MAX / 2 / sizeof *entries) {
                free (line); bgit_index_free_entries (entries, n); return EXECUTION_FAILURE;
            }
            cap *= 2;
            bgit_index_entry *ne = realloc (entries, cap * sizeof *entries);
            if (!ne) { free (line); bgit_index_free_entries (entries, n); return EXECUTION_FAILURE; }
            entries = ne;
        }
        int parse_rc = bidx_write_line (line, &entries[n]);
        if (parse_rc < 0) {
            if (parse_rc == -2)
                builtin_error ("write: bad stage");
            else if (parse_rc == -3)
                builtin_error ("write: invalid path: %s", line);
            else
                builtin_error ("write: malformed line: %s", line);
            free (line);
            bgit_index_free_entries (entries, n);
            return EX_USAGE;
        }
        n++;
    }
    free (line);
    if (bidx_input_failed ("write")) {
        bgit_index_free_entries (entries, n);
        return EXECUTION_FAILURE;
    }
    if (n > 1) qsort (entries, n, sizeof (bgit_index_entry), bgit_index_path_cmp);
    for (size_t i = 1; i < n; i++) {
        if (bgit_index_path_cmp (&entries[i - 1], &entries[i]) == 0) {
            builtin_error ("write: '%s' given twice at stage %d", entries[i].path,
                           BIDX_STAGE (entries[i].flags));
            bgit_index_free_entries (entries, n);
            return EX_USAGE;
        }
    }

    bidx_lock lock;
    if (bidx_lock_take (&lock, path) < 0) {
        bgit_index_free_entries (entries, n);
        return EXECUTION_FAILURE;
    }
    bgit_index_entry *previous = NULL;
    size_t previous_n = 0;
    bidx_undo undo = {0};
    if (bidx_load (path, 1, &previous, &previous_n, &undo) < 0) {
        bidx_lock_drop (&lock);
        bgit_index_free_entries (entries, n);
        return EXECUTION_FAILURE;
    }
    bgit_index_free_entries (previous, previous_n);
    bidx_undo_free (&undo);
    bgit_index_unstamp ();
    int rc = bidx_store (path, entries, n, NULL, &lock);
    bgit_index_free_entries (entries, n);
    return rc;
}

/* Undo git's C-style quoting of SRC, which starts with '"'. Text after the
   closing quote is ignored, as git ignores it; an escaped NUL ends the
   name, as it does for git. Returns a new string, or NULL if the quoting
   is bad. */
static char *
bidx_unquote (const char *src)
{
    char *out = malloc (strlen (src) + 1), *o = out;
    const char *p = src + 1;
    if (!out) return NULL;
    for (;;) {
        char c = *p++;
        if (c == '"') { *o = '\0'; return out; }
        if (c == '\0') break;
        if (c != '\\') { *o++ = c; continue; }
        switch ((c = *p++)) {
        case 'a': *o++ = '\a'; continue;
        case 'b': *o++ = '\b'; continue;
        case 'f': *o++ = '\f'; continue;
        case 'n': *o++ = '\n'; continue;
        case 'r': *o++ = '\r'; continue;
        case 't': *o++ = '\t'; continue;
        case 'v': *o++ = '\v'; continue;
        case '\\': case '"': *o++ = c; continue;
        case '0': case '1': case '2': case '3':
            if (p[0] < '0' || p[0] > '7' || p[1] < '0' || p[1] > '7') break;
            *o++ = (char) (((c - '0') << 6) | ((p[0] - '0') << 3) | (p[1] - '0'));
            p += 2;
            continue;
        default:
            break;
        }
        break;
    }
    free (out);
    return NULL;
}

enum { BIDX_INFO_OK = 0, BIDX_INFO_MALFORMED = -1, BIDX_INFO_QUOTING = -2,
       BIDX_INFO_NOMEM = -3 };

/* One `git update-index --index-info` record, in any of its shapes:
       mode SP sha TAB path
       mode SP type SP sha TAB path
       mode SP sha SP stage TAB path
   read as git reads them: the mode from the front, then from the first
   tab backwards an optional stage digit 0-3 after a space, and forty hex
   digits after a space; what lies between the mode and the id is not
   examined. Unless NUL_TERMINATED, a path that starts with '"' is
   unquoted. *PATH is a new string. */
static int
bidx_info_line (char *line, int nul_terminated, uint32_t *mode,
                unsigned char sha[20], int *stage, char **path)
{
    char *end;
    errno = 0;
    unsigned long v = strtoul (line, &end, 8);
    if (end == line || *end != ' ' || errno || v > UINT32_MAX)
        return BIDX_INFO_MALFORMED;
    *mode = (uint32_t) v;
    char *tab = strchr (end, '\t');
    if (!tab || tab - end < 41) return BIDX_INFO_MALFORMED;
    char *name = tab + 1;
    *stage = 0;
    if (tab[-2] == ' ' && tab[-1] >= '0' && tab[-1] <= '3') {
        *stage = tab[-1] - '0';
        tab -= 2;
    }
    if (tab - line < 41 || tab[-41] != ' ') return BIDX_INFO_MALFORMED;
    char hex[41];
    memcpy (hex, tab - 40, 40);
    hex[40] = '\0';
    if (bgit_hex_to_sha (hex, sha) < 0) return BIDX_INFO_MALFORMED;
    if (!nul_terminated && name[0] == '"') {
        *path = bidx_unquote (name);
        return *path ? BIDX_INFO_OK : BIDX_INFO_QUOTING;
    }
    *path = strdup (name);
    return *path ? BIDX_INFO_OK : BIDX_INFO_NOMEM;
}

/* Apply one --index-info record, LINE without its terminator, to S.
   Returns EXECUTION_SUCCESS, EX_USAGE for input git also rejects, or
   EXECUTION_FAILURE. */
static int
bidx_info_apply (bidx_set *s, char *line, int nul_terminated)
{
    uint32_t mode;
    int stage;
    unsigned char sha[20];
    char *name = NULL;
    int parsed = bidx_info_line (line, nul_terminated, &mode, sha, &stage, &name);
    if (parsed == BIDX_INFO_MALFORMED) {
        builtin_error ("--index-info: malformed line: %s", line);
        return EX_USAGE;
    }
    if (parsed == BIDX_INFO_QUOTING) {
        builtin_error ("--index-info: bad quoting of path name: %s", line);
        return EX_USAGE;
    }
    if (parsed != BIDX_INFO_OK) return EXECUTION_FAILURE;
    if (!*name || !bidx_path_ok (name, mode) || name[strlen (name) - 1] == '/') {
        builtin_error ("--index-info: ignoring path '%s'", name);
        free (name);
        return EXECUTION_SUCCESS;
    }
    if (mode == 0) {
        bidx_remove_name (s, name);
        free (name);
        return EXECUTION_SUCCESS;
    }
    bgit_index_entry e;
    memset (&e, 0, sizeof e);
    memcpy (e.sha, sha, sizeof e.sha);
    e.mode = bidx_canonical_mode (mode);
    size_t pl = strlen (name);
    e.flags = (uint16_t) ((stage << 12) | (pl > 0xFFF ? 0xFFF : pl));
    e.path = name;
    int added = bidx_add (s, &e, 1);
    if (added == BIDX_ADD_PATH) {
        builtin_error ("--index-info: unable to update '%s': invalid path", line);
        return EX_USAGE;
    }
    return added == BIDX_ADD_OK ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static void bidx_settle_racy (bgit_index_entry *entries, size_t n,
                              const bgit_index_entry *target);

static int
bidx_index_info_cmd (WORD_LIST *args)
{
    int nul_terminated = 0;
    if (args && strcmp (args->word->word, "-z") == 0) {
        nul_terminated = 1;
        args = args->next;
    }
    const char *path = args ? args->word->word : NULL;
    if (!path) { builtin_error ("--index-info: PATH required"); return EX_USAGE; }
    if (args->next) { builtin_error ("--index-info: too many"); return EX_USAGE; }
    bgit_index_unstamp ();

    bidx_lock lock;
    if (bidx_lock_take (&lock, path) < 0) return EXECUTION_FAILURE;
    bgit_index_entry *entries;
    size_t n;
    bidx_set set;
    bidx_undo undo;
    if (bidx_load (path, 1, &entries, &n, &undo) < 0) {
        bidx_lock_drop (&lock);
        return EXECUTION_FAILURE;
    }
    if (bidx_set_init (&set, entries, n) < 0) {
        bgit_index_free_entries (entries, n);
        bidx_undo_free (&undo);
        bidx_lock_drop (&lock);
        return EXECUTION_FAILURE;
    }
    set.undo = &undo;

    int rc = EXECUTION_SUCCESS;
    char *line = NULL;
    size_t line_cap = 0;
    ssize_t got;
    clearerr (stdin);
    while ((got = getdelim (&line, &line_cap, nul_terminated ? '\0' : '\n', stdin)) > 0) {
        if (line[got - 1] == (nul_terminated ? '\0' : '\n')) line[got - 1] = '\0';
        rc = bidx_info_apply (&set, line, nul_terminated);
        if (rc != EXECUTION_SUCCESS) break;
    }
    free (line);
    if (rc == EXECUTION_SUCCESS && bidx_input_failed ("--index-info"))
        rc = EXECUTION_FAILURE;
    if (rc == EXECUTION_SUCCESS && set.failed)
        rc = EXECUTION_FAILURE;
    if (rc == EXECUTION_SUCCESS && !set.changed) {
        /* git leaves an index that nothing changed as it was */
        bidx_set_free (&set);
        bidx_undo_free (&undo);
        bidx_lock_drop (&lock);
        return rc;
    }
    if (rc == EXECUTION_SUCCESS && !(entries = bidx_set_take (&set, &n)))
        rc = EXECUTION_FAILURE;
    if (rc != EXECUTION_SUCCESS) {
        bidx_set_free (&set);
        bidx_undo_free (&undo);
        bidx_lock_drop (&lock);
        return rc;
    }
    bidx_settle_racy (entries, n, NULL);
    rc = bidx_store (path, entries, n, &undo, &lock);
    bgit_index_free_entries (entries, n);
    bidx_undo_free (&undo);
    return rc;
}

/* Whether the file at E's path, relative to the current directory as the
   verbs' working paths are, still has E's stat data, and so would be
   taken as unchanged by its stat data alone. */
static int
bidx_stat_matches (const bgit_index_entry *e, const struct stat *st)
{
    return e->mtime_sec == (uint32_t) st->st_mtim.tv_sec &&
           e->mtime_nsec == (uint32_t) st->st_mtim.tv_nsec &&
           e->ctime_sec == (uint32_t) st->st_ctim.tv_sec &&
           e->ctime_nsec == (uint32_t) st->st_ctim.tv_nsec &&
           e->ino == (uint32_t) st->st_ino && e->dev == (uint32_t) st->st_dev &&
           e->uid == (uint32_t) st->st_uid && e->gid == (uint32_t) st->st_gid &&
           e->size == (uint32_t) st->st_size &&
           e->mode == bidx_canonical_mode (st->st_mode);
}

/* Whether the content behind E hashes to E's id, as git compares a file or
   link with its blob. A gitlink, or anything unreadable, does not. */
static int
bidx_content_matches (const bgit_index_entry *e, const struct stat *st)
{
    unsigned char *data = NULL;
    size_t len = 0;
    if (S_ISLNK (st->st_mode)) {
        if (st->st_size < 0 || st->st_size > (off_t) INT_MAX - 1) return 0;
        data = malloc ((size_t) st->st_size + 1);
        if (!data) return 0;
        ssize_t got = readlink (e->path, (char *) data, (size_t) st->st_size + 1);
        if (got < 0 || got > st->st_size) { free (data); return 0; }
        len = (size_t) got;
    } else if (S_ISREG (st->st_mode) && S_ISREG (e->mode)) {
        int fd = open (e->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) return 0;
        int rc = bgit_slurp_fd (fd, &data, &len);
        close (fd);
        if (rc < 0) return 0;
    } else {
        return 0;
    }
    char hex[41], want[41];
    int ok = bgit_write_object (NULL, "blob", data, len, 0, hex) == 0;
    free (data);
    bgit_sha_to_hex (e->sha, want);
    return ok && strcmp (hex, want) == 0;
}

/* git's racy-entry rule at write time, settled here rather than by
   bgit_index_write. An entry the old index held whose mtime is not before
   that index's own (bgit_index_racy) might have changed again within the
   same second without its stat data showing it. git checks: a file whose
   stat data no longer match will be noticed anyway, and one that still
   matches is written with size zero only if its content differs from the
   entry's id, so the next reader looks at it. The same here, except that a
   path that cannot be examined at all is given size zero, in case the
   current directory is not the work tree. TARGET, the entry this call has
   just recorded from the file, is left as recorded, as git's own refresh
   leaves it. */
static void
bidx_settle_racy (bgit_index_entry *entries, size_t n, const bgit_index_entry *target)
{
    for (size_t i = 0; i < n; i++) {
        bgit_index_entry *e = &entries[i];
        if (e == target || !bgit_index_racy (e)) continue;
        struct stat st;
        if (lstat (e->path, &st) < 0) { e->size = 0; continue; }
        if (!bidx_stat_matches (e, &st)) continue;
        if (!bidx_content_matches (e, &st)) e->size = 0;
    }
    bgit_index_unstamp ();
}

static int
bidx_add_cmd (WORD_LIST *args)
{
    if (!args || !args->next || !args->next->next ||
        (args->next->next->next && args->next->next->next->next)) {
        builtin_error ("add: PATH BLOB_SHA WORKING_PATH [STAGE]");
        return EX_USAGE;
    }
    const char *idxpath = args->word->word;
    const char *blobsha = args->next->word->word;
    const char *workp   = args->next->next->word->word;
    int stage = 0;
    if (args->next->next->next &&
        bgit_index_parse_stage (args->next->next->next->word->word, &stage) < 0) {
        builtin_error ("bad stage");
        return EX_USAGE;
    }
    bgit_index_entry e;
    memset (&e, 0, sizeof e);
    if (bgit_hex_to_sha (blobsha, e.sha) < 0) { builtin_error ("bad blob sha"); return EX_USAGE; }
    struct stat st;
    if (lstat (workp, &st) < 0) { builtin_error ("stat %s: %s", workp, strerror (errno)); return EX_USAGE; }
    if (!S_ISREG (st.st_mode) && !S_ISLNK (st.st_mode)) {
        builtin_error ("add: %s: not a regular file or symbolic link", workp);
        return EX_USAGE;
    }
    bgit_index_unstamp ();

    bidx_lock lock;
    if (bidx_lock_take (&lock, idxpath) < 0) return EXECUTION_FAILURE;
    bgit_index_entry *entries;
    size_t n;
    bidx_set set;
    bidx_undo undo;
    if (bidx_load (idxpath, 1, &entries, &n, &undo) < 0) { bidx_lock_drop (&lock); return EXECUTION_FAILURE; }
    if (bidx_set_init (&set, entries, n) < 0) {
        bgit_index_free_entries (entries, n);
        bidx_undo_free (&undo);
        bidx_lock_drop (&lock);
        return EXECUTION_FAILURE;
    }
    set.undo = &undo;
    bgit_index_entry_set_stat (&e, &st);
    e.mode = bidx_canonical_mode (st.st_mode);
    size_t pl = strlen (workp);
    e.flags = (uint16_t) ((stage << 12) | (pl > 0xFFF ? 0xFFF : pl));
    e.path = strdup (workp);
    int added = e.path ? bidx_add (&set, &e, 0) : BIDX_ADD_NOMEM;
    if (added == BIDX_ADD_OK && set.failed) added = BIDX_ADD_NOMEM;
    if (added == BIDX_ADD_OK && !(entries = bidx_set_take (&set, &n))) added = BIDX_ADD_NOMEM;
    if (added != BIDX_ADD_OK) {
        if (added == BIDX_ADD_PATH)
            builtin_error ("add: invalid path '%s'", workp);
        else if (added == BIDX_ADD_CONFLICT)
            builtin_error ("add: '%s' appears as both a file and as a directory", workp);
        bidx_set_free (&set);
        bidx_undo_free (&undo);
        bidx_lock_drop (&lock);
        return EXECUTION_FAILURE;
    }
    bgit_index_entry *target = NULL;
    for (size_t i = 0; i < n && !target; i++)
        if (BIDX_STAGE (entries[i].flags) == stage && strcmp (entries[i].path, workp) == 0)
            target = &entries[i];
    bidx_settle_racy (entries, n, target);
    int rc = bidx_store (idxpath, entries, n, &undo, &lock);
    bgit_index_free_entries (entries, n);
    bidx_undo_free (&undo);
    return rc;
}

static int
bidx_remove_cmd (WORD_LIST *args)
{
    if (!args || !args->next || args->next->next) { builtin_error ("remove: PATH WORKING_PATH"); return EX_USAGE; }
    const char *idxpath = args->word->word;
    const char *workp   = args->next->word->word;
    bgit_index_unstamp ();

    bidx_lock lock;
    if (bidx_lock_take (&lock, idxpath) < 0) return EXECUTION_FAILURE;
    bgit_index_entry *entries; size_t n;
    bidx_set set;
    bidx_undo undo;
    if (bidx_load (idxpath, 0, &entries, &n, &undo) < 0) { bidx_lock_drop (&lock); return EXECUTION_FAILURE; }
    if (bidx_set_init (&set, entries, n) < 0) {
        bgit_index_free_entries (entries, n);
        bidx_undo_free (&undo);
        bidx_lock_drop (&lock);
        return EXECUTION_FAILURE;
    }
    set.undo = &undo;
    int rc = EXECUTION_SUCCESS;
    if (!bidx_remove_name (&set, workp)) {
        builtin_error ("remove: '%s' is not in the index", workp);
        rc = EXECUTION_FAILURE;
    } else if (set.failed || !(entries = bidx_set_take (&set, &n))) {
        rc = EXECUTION_FAILURE;
    }
    if (rc != EXECUTION_SUCCESS) {
        bidx_set_free (&set);
        bidx_undo_free (&undo);
        bidx_lock_drop (&lock);
        return rc;
    }
    bidx_settle_racy (entries, n, NULL);
    rc = bidx_store (idxpath, entries, n, &undo, &lock);
    bgit_index_free_entries (entries, n);
    bidx_undo_free (&undo);
    return rc;
}

static int
bidx_update_stat_cmd (WORD_LIST *args)
{
    if (!args || !args->next || args->next->next) { builtin_error ("update-stat: PATH WORKING_PATH"); return EX_USAGE; }
    const char *idxpath = args->word->word;
    const char *workp   = args->next->word->word;

    struct stat st;
    if (lstat (workp, &st) < 0) { builtin_error ("stat %s: %s", workp, strerror (errno)); return EX_USAGE; }
    bgit_index_unstamp ();

    bidx_lock lock;
    if (bidx_lock_take (&lock, idxpath) < 0) return EXECUTION_FAILURE;
    bgit_index_entry *entries; size_t n;
    bidx_undo undo;
    if (bidx_load (idxpath, 0, &entries, &n, &undo) < 0) { bidx_lock_drop (&lock); return EXECUTION_FAILURE; }

    /* Only a merged (stage 0) entry describes a file in the work tree. */
    bgit_index_entry *target = NULL;
    for (size_t i = 0; i < n && !target; i++)
        if (BIDX_STAGE (entries[i].flags) == 0 && strcmp (entries[i].path, workp) == 0)
            target = &entries[i];
    if (!target) {
        bgit_index_free_entries (entries, n);
        bidx_undo_free (&undo);
        bidx_lock_drop (&lock);
        builtin_error ("update-stat: path not in index: %s", workp);
        return EXECUTION_FAILURE;
    }
    /* The mode is the entry's, as git records it, not the file's raw one. */
    uint32_t mode = target->mode;
    bgit_index_entry_set_stat (target, &st);
    target->mode = mode;
    bidx_settle_racy (entries, n, target);
    int rc = bidx_store (idxpath, entries, n, &undo, &lock);
    bgit_index_free_entries (entries, n);
    bidx_undo_free (&undo);
    return rc;
}

int
index_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    if (!strcmp (cmd, "read"))   return bidx_read_cmd (args);
    if (!strcmp (cmd, "list"))   return bidx_read_cmd (args);
    if (!strcmp (cmd, "write"))  return bidx_write_cmd (args);
    if (!strcmp (cmd, "--index-info") || !strcmp (cmd, "index-info"))
        return bidx_index_info_cmd (args);
    if (!strcmp (cmd, "add"))    return bidx_add_cmd (args);
    if (!strcmp (cmd, "remove")) return bidx_remove_cmd (args);
    if (!strcmp (cmd, "update-stat")) return bidx_update_stat_cmd (args);
    builtin_error ("unknown verb: %s", cmd);
    return EX_USAGE;
}

char *index_doc[] = {
    "Read/write .git/index v2 binary format.",
    "",
    "    index read PATH [-V VAR]",
    "        Print '<mode> <sha> <stage> <path>' lines, or bind array VAR.",
    "    index list PATH",
    "        Synonym for read.",
    "    index write PATH (entries on stdin)",
    "        Atomic write; computes the SHA-1 trailer. One space or tab",
    "        separates the stage from the path.",
    "    index --index-info [-z] PATH (git update-index --index-info stdin)",
    "        Import mode/sha/stage TAB path records as git applies them;",
    "        mode 0 removes a path. -z: NUL-terminated records.",
    "    index add PATH BLOB_SHA WORKING_PATH [STAGE]",
    "        Add/replace entry; lstat WORKING_PATH for ctime/mtime/size.",
    "    index remove PATH WORKING_PATH",
    "        Remove every stage of an entry.",
    "    index update-stat PATH WORKING_PATH",
    "        Refresh stat fields without changing SHA.",
    "",
    "    Changing verbs hold PATH.lock as git does and replace PATH",
    "    atomically. Versions 2 and 3 are read; version 2 is written.",
    (char *)NULL
};

struct builtin index_struct = {
    "index",
    index_builtin,
    BUILTIN_ENABLED,
    index_doc,
    "index read|list|write|--index-info|add|remove|update-stat ARGS",
    0
};
