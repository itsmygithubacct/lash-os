/* SPDX-License-Identifier: MIT */
/* index.c — read/write `.git/index` v2 binary format.
 *
 * Phase W W-3 of bash-os git primitives. The .git/index file is git's
 * staging area — what `git add` writes, what `git commit` reads to build
 * a tree, and what `git status` cross-references for the ctime/mtime
 * fast-path.
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
 * Verbs:
 *   index read PATH [-V VAR]
 *       Print one line per entry: "<mode> <sha> <stage> <path>".
 *       With -V, bind a bash array.
 *
 *   index write PATH (entries on stdin: "<mode> <sha> <stage> <path>")
 *       Build binary index, atomic write (mkstemp + rename). Computes
 *       SHA-1 trailer via sha1dc.
 *
 *   index --index-info PATH
 *       Import git update-index --index-info stdin forms and write PATH.
 *
 *   index add PATH BLOB_SHA WORKING_PATH [STAGE]
 *       Add/replace entry. stat() WORKING_PATH for ctime/mtime/size.
 *
 *   index remove PATH WORKING_PATH
 *       Remove entry by path. Re-writes the index.
 *
 *   index update-stat PATH WORKING_PATH
 *       Refresh stat fields for an existing entry without changing SHA.
 *
 *   index list PATH
 *       Print "<mode> <sha> <stage> <path>" lines. Synonym for read.
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
#include <stdint.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "loadables.h"
#include "arrayfunc.h"
#include "_sha1dc_sha1.h"

/* Read big-endian 32-bit from buf+off. */
static uint32_t
bidx_be32 (const unsigned char *buf, size_t off)
{
    return ((uint32_t) buf[off] << 24) | ((uint32_t) buf[off+1] << 16) |
           ((uint32_t) buf[off+2] <<  8) | ((uint32_t) buf[off+3]);
}

static uint16_t
bidx_be16 (const unsigned char *buf, size_t off)
{
    return (uint16_t) (((uint16_t) buf[off] << 8) | (uint16_t) buf[off+1]);
}

static void
bidx_put_be32 (unsigned char *buf, uint32_t v)
{
    buf[0] = (unsigned char) (v >> 24); buf[1] = (unsigned char) (v >> 16);
    buf[2] = (unsigned char) (v >> 8);  buf[3] = (unsigned char) v;
}

static void
bidx_put_be16 (unsigned char *buf, uint16_t v)
{
    buf[0] = (unsigned char) (v >> 8); buf[1] = (unsigned char) v;
}

/* hex helpers */
static void
bidx_sha_to_hex (const unsigned char *sha, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (int i = 0; i < 20; i++) {
        out[2*i]   = d[sha[i] >> 4];
        out[2*i+1] = d[sha[i] & 0xF];
    }
    out[40] = '\0';
}

static int
bidx_hex_to_sha (const char *hex, unsigned char *sha)
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

static int
bidx_parse_mode (const char *s, uint32_t *out)
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

static int
bidx_parse_stage (const char *s, int *out)
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

/* In-memory index entry. */
typedef struct {
    uint32_t ctime_sec, ctime_nsec;
    uint32_t mtime_sec, mtime_nsec;
    uint32_t dev, ino, mode, uid, gid, size;
    unsigned char sha[20];
    uint16_t flags;     /* low 12 bits: path length (capped 0xFFF); high 4: stage etc. */
    char *path;
} bidx_entry;

static void
bidx_entry_set_stat (bidx_entry *e, const struct stat *st)
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

/* Free entry list. */
static void
bidx_free_entries (bidx_entry *e, size_t n)
{
    for (size_t i = 0; i < n; i++) free (e[i].path);
    free (e);
}

/* Slurp file. Caller frees. */
static unsigned char *
bidx_slurp (const char *path, size_t *out_len)
{
    FILE *f = fopen (path, "rb");
    if (!f) return NULL;
    if (fseek (f, 0, SEEK_END) != 0) { fclose (f); return NULL; }
    long sz = ftell (f);
    if (sz < 0 || fseek (f, 0, SEEK_SET) != 0) { fclose (f); return NULL; }
    unsigned char *buf = malloc (sz ? (size_t) sz : 1);
    if (!buf) { fclose (f); return NULL; }
    if (fread (buf, 1, (size_t) sz, f) != (size_t) sz) {
        free (buf); fclose (f); return NULL;
    }
    fclose (f);
    *out_len = (size_t) sz;
    return buf;
}

/* Parse index file. Returns 0 + sets *out, *n_out on success. */
static int
bidx_parse (const char *path, bidx_entry **out, size_t *n_out)
{
    size_t flen;
    unsigned char *buf = bidx_slurp (path, &flen);
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
    uint32_t ver = bidx_be32 (buf, 4);
    if (ver != 2 && ver != 3) {
        free (buf);
        builtin_error ("unsupported index version %u (only 2,3)", ver);
        return -1;
    }
    uint32_t n_entries = bidx_be32 (buf, 8);
    if (n_entries > (flen - 32) / 64) {
        free (buf); builtin_error ("truncated index (entry count)"); return -1;
    }
    bidx_entry *entries = calloc (n_entries ? n_entries : 1, sizeof (bidx_entry));
    if (!entries) { free (buf); return -1; }

    size_t off = 12;
    for (uint32_t i = 0; i < n_entries; i++) {
        if (off + 62 > flen - 20) { /* -20 for trailer */
            free (buf); bidx_free_entries (entries, i);
            builtin_error ("truncated index");
            return -1;
        }
        bidx_entry *e = &entries[i];
        e->ctime_sec  = bidx_be32 (buf, off);      off += 4;
        e->ctime_nsec = bidx_be32 (buf, off);      off += 4;
        e->mtime_sec  = bidx_be32 (buf, off);      off += 4;
        e->mtime_nsec = bidx_be32 (buf, off);      off += 4;
        e->dev        = bidx_be32 (buf, off);      off += 4;
        e->ino        = bidx_be32 (buf, off);      off += 4;
        e->mode       = bidx_be32 (buf, off);      off += 4;
        e->uid        = bidx_be32 (buf, off);      off += 4;
        e->gid        = bidx_be32 (buf, off);      off += 4;
        e->size       = bidx_be32 (buf, off);      off += 4;
        memcpy (e->sha, buf + off, 20);            off += 20;
        e->flags      = bidx_be16 (buf, off);      off += 2;

        /* v3+ CE_EXTENDED (0x4000) entries carry a second 16-bit flags
           field (flags2) before the path — git's create_from_disk reads it
           via get_be16(flagsp + sizeof(uint16_t)). index doesn't model
           the extended-flag semantics (skip-worktree / intent-to-add), but
           it MUST consume the 2 bytes or every following entry misaligns.
           extended_len feeds the 8-byte padding so the on-disk size matches
           git's ondisk_data_size(). */
        size_t extended_len = 0;
        if (ver >= 3 && (e->flags & 0x4000)) {
            if (off + 2 > flen - 20) {
                free (buf); bidx_free_entries (entries, i);
                builtin_error ("truncated index (extended flags)");
                return -1;
            }
            off += 2;
            extended_len = 2;
        }

        size_t path_len = e->flags & 0xFFF;
        const unsigned char *nul = memchr (buf + off, 0, flen - 20 - off);
        if (path_len == 0xFFF && nul) path_len = (size_t) (nul - buf - off);
        if (!nul || (size_t) (nul - buf - off) != path_len) {
            free (buf); bidx_free_entries (entries, i);
            builtin_error ("truncated index (path)");
            return -1;
        }
        e->path = malloc (path_len + 1);
        if (!e->path) { free (buf); bidx_free_entries (entries, i); return -1; }
        memcpy (e->path, buf + off, path_len);
        e->path[path_len] = '\0';
        off += path_len;
        /* Pad to 8-byte boundary. The entry start is 12 bytes into the
           file, so total entry length so far = 62 (+2 if extended) +
           path_len. Pad to multiple of 8 with NULs (at least 1 NUL). */
        size_t entry_len = 62 + extended_len + path_len;
        size_t pad = (8 - (entry_len % 8));
        if (pad == 0) pad = 8;
        if (pad > flen - 20 - off) {
            free (buf); bidx_free_entries (entries, i + 1);
            builtin_error ("truncated index (padding)"); return -1;
        }
        for (size_t j = 0; j < pad; j++) {
            if (buf[off + j] != 0) {
                free (buf); bidx_free_entries (entries, i + 1);
                builtin_error ("invalid index padding"); return -1;
            }
        }
        off += pad;
    }

    /* Validate SHA-1 trailer: last 20 bytes = sha1 of buf[0 .. flen-21].
       Git computes the trailer over the entire index body including headers
       and all entries (everything before the trailer itself). */
    if (flen < 20) {
        free (buf); bidx_free_entries (entries, n_entries);
        builtin_error ("index too short (no trailer)");
        return -1;
    }
    unsigned char stored[20];
    memcpy (stored, buf + flen - 20, 20);
    SHA1_CTX ctx;
    SHA1DCInit (&ctx);
    SHA1DCSetSafeHash (&ctx, 0);
    SHA1DCUpdate (&ctx, (const char *) buf, flen - 20);
    unsigned char computed[20];
    SHA1DCFinal (computed, &ctx);
    if (memcmp (computed, stored, 20) != 0) {
        free (buf); bidx_free_entries (entries, n_entries);
        builtin_error ("index checksum mismatch");
        return -1;
    }

    free (buf);
    *out = entries;
    *n_out = n_entries;
    return 0;
}

/* Write entries back to PATH atomically, computing SHA-1 trailer. */
static int
bidx_write (const char *path, bidx_entry *entries, size_t n)
{
    if (n > UINT32_MAX) { builtin_error ("too many index entries"); return -1; }
    /* Build buffer in memory, then mkstemp + rename. */
    size_t cap = 4096, len = 0;
    unsigned char *buf = malloc (cap);
    if (!buf) return -1;

    /* Header */
    memcpy (buf + len, "DIRC", 4); len += 4;
    bidx_put_be32 (buf + len, 2); len += 4;
    bidx_put_be32 (buf + len, (uint32_t) n); len += 4;

    for (size_t i = 0; i < n; i++) {
        bidx_entry *e = &entries[i];
        size_t path_len = strlen (e->path);
        if (path_len > SIZE_MAX - 70) { free (buf); return -1; }
        size_t entry_len = 62 + path_len;
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
        bidx_put_be32 (buf + len, e->ctime_sec);   len += 4;
        bidx_put_be32 (buf + len, e->ctime_nsec);  len += 4;
        bidx_put_be32 (buf + len, e->mtime_sec);   len += 4;
        bidx_put_be32 (buf + len, e->mtime_nsec);  len += 4;
        bidx_put_be32 (buf + len, e->dev);         len += 4;
        bidx_put_be32 (buf + len, e->ino);         len += 4;
        bidx_put_be32 (buf + len, e->mode);        len += 4;
        bidx_put_be32 (buf + len, e->uid);         len += 4;
        bidx_put_be32 (buf + len, e->gid);         len += 4;
        bidx_put_be32 (buf + len, e->size);        len += 4;
        memcpy (buf + len, e->sha, 20);            len += 20;
        /* We always emit version 2, which has no flags2 field, so
           CE_EXTENDED (0x4000) must be cleared — keep only assume-valid
           (0x8000) and the 2-bit stage (0x3000). This mirrors git's
           do_write_index, which strips CE_EXTENDED when writing v2;
           leaving it set would make git try to read a flags2 that isn't
           there. */
        uint16_t flags = (uint16_t) ((e->flags & 0xB000)
            | (path_len > 0xFFF ? 0xFFF : path_len));
        bidx_put_be16 (buf + len, flags);          len += 2;
        memcpy (buf + len, e->path, path_len);     len += path_len;
        memset (buf + len, 0, pad);                len += pad;
    }

    /* Trailer: SHA-1 of body via sha1dc. */
    SHA1_CTX ctx;
    SHA1DCInit (&ctx);
    SHA1DCSetSafeHash (&ctx, 0);
    SHA1DCUpdate (&ctx, (const char *) buf, len);
    unsigned char digest[20];
    SHA1DCFinal (digest, &ctx);  /* may detect collision; we accept anyway */
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
        if (w <= 0) { if (w < 0 && errno == EINTR) continue; close (fd); unlink (tmp); free (buf); return -1; }
        off += w;
    }
    int sync_rc = fdatasync (fd);
    int close_rc = close (fd);
    if (sync_rc < 0 || close_rc < 0) { unlink (tmp); free (buf); return -1; }
    if (rename (tmp, path) < 0) {
        unlink (tmp); free (buf);
        builtin_error ("rename: %s", strerror (errno));
        return -1;
    }
    free (buf);
    return 0;
}

/* ---- verb implementations ---- */

static int
bidx_read_cmd (WORD_LIST *args)
{
    const char *path = NULL, *var = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-V") == 0 && p->next) { var = p->next->word->word; p = p->next; }
        else if (w[0] == '-' && w[1] != '\0') {
            builtin_error ("read: unknown flag %s", w); return EX_USAGE;
        } else { if (path) { builtin_error ("read: too many"); return EX_USAGE; } path = w; }
    }
    if (!path) { builtin_error ("read: PATH required"); return EX_USAGE; }
    bidx_entry *entries; size_t n;
    if (bidx_parse (path, &entries, &n) < 0) return EXECUTION_FAILURE;

    SHELL_VAR *arr = NULL;
    if (var) {
        unbind_variable ((char *) var);
        arr = find_or_make_array_variable ((char *) var, 1);
    }
    for (size_t i = 0; i < n; i++) {
        char hex[41];
        bidx_sha_to_hex (entries[i].sha, hex);
        int stage = (entries[i].flags >> 12) & 0x3;
        char line[8192];
        snprintf (line, sizeof line, "%o %s %d %s",
                  entries[i].mode, hex, stage, entries[i].path);
        if (arr) {
            ARRAY *a = array_cell (arr);
            array_insert (a, (arrayind_t) i, line);
        } else {
            puts (line);
        }
    }
    bidx_free_entries (entries, n);
    return EXECUTION_SUCCESS;
}

/* Parse one "<mode> <sha> <stage> <path>" line into an entry. Stat
   WORKING_PATH (if given) for ctime/mtime/size; else zero them. */
static int
bidx_line_to_entry (const char *line, const char *working_root, bidx_entry *out)
{
    /* Split: mode sha stage path */
    char mode_s[16], sha_s[64], stage_s[16];
    int stage;
    int prefix_len = 0;
    if (sscanf (line, "%15s %63s %15s %n", mode_s, sha_s, stage_s, &prefix_len) < 3) {
        return -1;
    }
    if (bidx_parse_stage (stage_s, &stage) < 0)
        return -2;
    const char *path = line + prefix_len;
    /* Trim trailing newline */
    size_t pl = strlen (path);
    while (pl > 0 && (path[pl-1] == '\n' || path[pl-1] == '\r')) pl--;
    if (pl == 0) return -1;

    memset (out, 0, sizeof *out);
    if (bidx_parse_mode (mode_s, &out->mode) < 0) return -1;
    if (bidx_hex_to_sha (sha_s, out->sha) < 0) return -1;
    out->flags = (uint16_t) (((stage & 0x3) << 12) | (pl > 0xFFF ? 0xFFF : pl));
    out->path = malloc (pl + 1);
    if (!out->path) return -1;
    memcpy (out->path, path, pl);
    out->path[pl] = '\0';

    /* If working_root + path resolves, populate stat fields. */
    if (working_root) {
        char fp[8192];
        snprintf (fp, sizeof fp, "%s/%s", working_root, out->path);
        struct stat st;
        if (stat (fp, &st) == 0) {
            bidx_entry_set_stat (out, &st);
        }
    }
    return 0;
}

/* Sort entries by path (qsort comparator). */
static int
bidx_path_cmp (const void *a, const void *b)
{
    const bidx_entry *ea = a, *eb = b;
    int r = strcmp (ea->path, eb->path);
    if (r != 0)
        return r;
    int sa = (ea->flags >> 12) & 0x3;
    int sb = (eb->flags >> 12) & 0x3;
    return sa - sb;
}

static int
bidx_write_cmd (WORD_LIST *args)
{
    const char *path = args ? args->word->word : NULL;
    if (!path) { builtin_error ("write: PATH required"); return EX_USAGE; }

    /* Read lines from stdin. */
    size_t cap = 16, n = 0;
    bidx_entry *entries = calloc (cap, sizeof (bidx_entry));
    if (!entries) return EXECUTION_FAILURE;
    char *line = NULL; size_t line_cap = 0;
    ssize_t got;
    clearerr (stdin);
    while ((got = getline (&line, &line_cap, stdin)) > 0) {
        if (n + 1 > cap) {
            if (cap > SIZE_MAX / 2 / sizeof *entries) {
                free (line); bidx_free_entries (entries, n); return EXECUTION_FAILURE;
            }
            cap *= 2;
            bidx_entry *ne = realloc (entries, cap * sizeof *entries);
            if (!ne) { free (line); bidx_free_entries (entries, n); return EXECUTION_FAILURE; }
            entries = ne;
        }
        int parse_rc = bidx_line_to_entry (line, NULL, &entries[n]);
        if (parse_rc < 0) {
            if (parse_rc == -2)
                builtin_error ("write: bad stage");
            else
                builtin_error ("write: malformed line: %s", line);
            free (line);
            bidx_free_entries (entries, n);
            return EX_USAGE;
        }
        n++;
    }
    free (line);
    if (n > 1) qsort (entries, n, sizeof (bidx_entry), bidx_path_cmp);

    int rc = bidx_write (path, entries, n);
    bidx_free_entries (entries, n);
    return rc < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
bidx_remove_path_entries (bidx_entry **entries, size_t *n, const char *path)
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

static int
bidx_index_info_line_to_entry (char *line, bidx_entry *out, int *is_remove)
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
    if (pl == 0)
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
    if (bidx_parse_mode (tok[0], &mode) < 0)
        return -1;

    if (ntok == 2) {
        sha_s = tok[1];                 /* mode SP sha1 TAB path */
    } else if (strlen (tok[1]) == 40 && bidx_parse_stage (tok[2], &stage) == 0) {
        sha_s = tok[1];                 /* mode SP sha1 SP stage TAB path */
    } else {
        sha_s = tok[2];                 /* mode SP type SP sha1 TAB path */
        stage = 0;
    }

    memset (out, 0, sizeof *out);
    out->mode = mode;
    if (bidx_hex_to_sha (sha_s, out->sha) < 0)
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

static int
bidx_index_info_cmd (WORD_LIST *args)
{
    const char *path = args ? args->word->word : NULL;
    bidx_entry *entries = NULL;
    size_t n = 0, cap = 0;
    char *line = NULL;
    size_t line_cap = 0;

    if (!path) { builtin_error ("--index-info: PATH required"); return EX_USAGE; }
    if (args->next) { builtin_error ("--index-info: too many"); return EX_USAGE; }

    if (access (path, R_OK) == 0) {
        if (bidx_parse (path, &entries, &n) < 0)
            return EXECUTION_FAILURE;
        cap = n ? n : 16;
        if (cap != n) {
            bidx_entry *ne = realloc (entries, cap * sizeof (bidx_entry));
            if (!ne) { bidx_free_entries (entries, n); return EXECUTION_FAILURE; }
            entries = ne;
        }
    } else {
        cap = 16;
        entries = calloc (cap, sizeof (bidx_entry));
        if (!entries)
            return EXECUTION_FAILURE;
    }

    clearerr (stdin);
    while (getline (&line, &line_cap, stdin) > 0) {
        bidx_entry e;
        int is_remove = 0;
        if (bidx_index_info_line_to_entry (line, &e, &is_remove) < 0) {
            builtin_error ("--index-info: malformed line: %s", line);
            free (line);
            bidx_free_entries (entries, n);
            return EX_USAGE;
        }
        if (is_remove) {
            bidx_remove_path_entries (&entries, &n, e.path);
            free (e.path);
            continue;
        }

        int stage = (e.flags >> 12) & 0x3;
        ssize_t found = -1;
        for (size_t i = 0; i < n; i++) {
            int cur_stage = (entries[i].flags >> 12) & 0x3;
            if (cur_stage == stage && strcmp (entries[i].path, e.path) == 0) {
                found = (ssize_t) i;
                break;
            }
        }
        if (found >= 0) {
            free (entries[found].path);
            entries[found] = e;
        } else {
            if (n + 1 > cap) {
                if (cap > SIZE_MAX / 2 / sizeof *entries) {
                    free (e.path); free (line); bidx_free_entries (entries, n); return EXECUTION_FAILURE;
                }
                cap *= 2;
                bidx_entry *ne = realloc (entries, cap * sizeof (bidx_entry));
                if (!ne) {
                    free (e.path);
                    free (line);
                    bidx_free_entries (entries, n);
                    return EXECUTION_FAILURE;
                }
                entries = ne;
            }
            entries[n++] = e;
        }
    }
    free (line);
    if (n > 1) qsort (entries, n, sizeof (bidx_entry), bidx_path_cmp);

    int rc = bidx_write (path, entries, n);
    bidx_free_entries (entries, n);
    return rc < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
bidx_add_cmd (WORD_LIST *args)
{
    if (!args || !args->next || !args->next->next) {
        builtin_error ("add: PATH BLOB_SHA WORKING_PATH [STAGE]");
        return EX_USAGE;
    }
    const char *idxpath = args->word->word;
    const char *blobsha = args->next->word->word;
    const char *workp   = args->next->next->word->word;
    int stage = 0;
    if (args->next->next->next &&
        bidx_parse_stage (args->next->next->next->word->word, &stage) < 0) {
        builtin_error ("bad stage");
        return EX_USAGE;
    }

    /* Stat working path. */
    struct stat st;
    if (stat (workp, &st) < 0) { builtin_error ("stat %s: %s", workp, strerror (errno)); return EX_USAGE; }

    bidx_entry *entries = NULL;
    size_t n = 0;
    /* Parse existing index if it exists. */
    if (access (idxpath, R_OK) == 0) {
        if (bidx_parse (idxpath, &entries, &n) < 0) return EXECUTION_FAILURE;
    }
    /* Replace or append. */
    int found = -1;
    for (size_t i = 0; i < n; i++) {
        if (strcmp (entries[i].path, workp) == 0) { found = (int) i; break; }
    }
    if (found < 0) {
        if (n >= SIZE_MAX / sizeof *entries - 1 || n >= INT_MAX) {
            bidx_free_entries (entries, n); return EXECUTION_FAILURE;
        }
        bidx_entry *ne = realloc (entries, (n + 1) * sizeof (bidx_entry));
        if (!ne) { bidx_free_entries (entries, n); return EXECUTION_FAILURE; }
        entries = ne;
        memset (&entries[n], 0, sizeof (bidx_entry));
        entries[n].path = strdup (workp);
        if (!entries[n].path) { bidx_free_entries (entries, n); return EXECUTION_FAILURE; }
        found = (int) n;
        n++;
    }
    bidx_entry *e = &entries[found];
    bidx_entry_set_stat (e, &st);
    if (bidx_hex_to_sha (blobsha, e->sha) < 0) {
        bidx_free_entries (entries, n);
        builtin_error ("bad blob sha"); return EX_USAGE;
    }
    e->flags = (uint16_t) (((stage & 0x3) << 12) | (strlen (e->path) > 0xFFF ? 0xFFF : strlen (e->path)));

    if (n > 1) qsort (entries, n, sizeof (bidx_entry), bidx_path_cmp);
    int rc = bidx_write (idxpath, entries, n);
    bidx_free_entries (entries, n);
    return rc < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
bidx_remove_cmd (WORD_LIST *args)
{
    if (!args || !args->next) { builtin_error ("remove: PATH WORKING_PATH"); return EX_USAGE; }
    const char *idxpath = args->word->word;
    const char *workp   = args->next->word->word;
    bidx_entry *entries; size_t n;
    if (bidx_parse (idxpath, &entries, &n) < 0) return EXECUTION_FAILURE;
    int found = -1;
    for (size_t i = 0; i < n; i++) {
        if (strcmp (entries[i].path, workp) == 0) { found = (int) i; break; }
    }
    if (found < 0) {
        bidx_free_entries (entries, n);
        return EXECUTION_FAILURE;
    }
    free (entries[found].path);
    if ((size_t) (found + 1) < n) {
        memmove (entries + found, entries + found + 1, (n - found - 1) * sizeof (bidx_entry));
    }
    n--;
    int rc = bidx_write (idxpath, entries, n);
    bidx_free_entries (entries, n);
    return rc < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
bidx_update_stat_cmd (WORD_LIST *args)
{
    if (!args || !args->next) { builtin_error ("update-stat: PATH WORKING_PATH"); return EX_USAGE; }
    const char *idxpath = args->word->word;
    const char *workp   = args->next->word->word;

    struct stat st;
    if (stat (workp, &st) < 0) { builtin_error ("stat %s: %s", workp, strerror (errno)); return EX_USAGE; }

    bidx_entry *entries; size_t n;
    if (bidx_parse (idxpath, &entries, &n) < 0) return EXECUTION_FAILURE;

    int found = -1;
    for (size_t i = 0; i < n; i++) {
        if (strcmp (entries[i].path, workp) == 0) { found = (int) i; break; }
    }
    if (found < 0) {
        bidx_free_entries (entries, n);
        builtin_error ("update-stat: path not in index: %s", workp);
        return EXECUTION_FAILURE;
    }

    bidx_entry_set_stat (&entries[found], &st);
    int rc = bidx_write (idxpath, entries, n);
    bidx_free_entries (entries, n);
    return rc < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
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
    "        Print '<mode> <sha> <stage> <path>' lines.",
    "    index list PATH",
    "        Synonym for read.",
    "    index write PATH (entries on stdin)",
    "        Atomic write; computes SHA-1 trailer via sha1dc.",
    "    index --index-info PATH (git update-index --index-info stdin)",
    "        Import mode/sha/stage TAB path records; mode 0 removes a path.",
    "    index add PATH BLOB_SHA WORKING_PATH [STAGE]",
    "        Add/replace entry; stat WORKING_PATH for ctime/mtime/size.",
    "    index remove PATH WORKING_PATH",
    "        Remove entry by path.",
    "    index update-stat PATH WORKING_PATH",
    "        Refresh stat fields without changing SHA.",
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
