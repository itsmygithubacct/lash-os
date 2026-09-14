/* SPDX-License-Identifier: MIT */
/* buf.c — line-array text buffer for bash.
 *
 * Phase V (editor primitives) — V-1. Foundation for nano + script-
 * level line-oriented editing. Provides:
 *   - NUL-safe lines (length tracked; never strlen on data)
 *   - O(1) append, O(n) middle-insert (line array shift)
 *   - Atomic save (mkstemp + fchmod + fdatasync + rename + parent-dir fsync)
 *   - 32-slot handle table; handles are small ints stored in a caller var
 *   - Dirty flag + filename tracking
 *
 * Verbs:
 *   buf new [-h HVAR]
 *       Allocate a fresh empty buffer. Slot int → HVAR (or stdout).
 *
 *   buf load HANDLE PATH
 *       Replace buffer contents from PATH (lines split on \n).
 *       Last line without trailing \n is preserved as-is.
 *
 *   buf save HANDLE [PATH]
 *       Atomic write to PATH (or buffer's stored filename).
 *       Trailing \n added between lines (and after last if it had one
 *       on load — tracked via had_trailing_nl flag).
 *
 *   buf insert-line HANDLE INDEX TEXT
 *       Insert TEXT as a new line at INDEX (0..n_lines).
 *       TEXT may contain NUL via hex if -X is given.
 *
 *   buf delete-line HANDLE INDEX
 *       Remove line at INDEX. Subsequent lines shift up.
 *
 *   buf mutate -j JOURNALFD -h HANDLE -- VERB ARGS...
 *       Apply insert-line/delete-line/insert-at/delete-at and emit a
 *       NUL-safe undo record tuple to JOURNALFD for the applied op.
 *
 *   buf line HANDLE INDEX [-V VAR] [-X]
 *       Print line content (or bind to VAR). With -X, output as hex
 *       (NUL-safe transit through bash variables).
 *
 *   buf len HANDLE INDEX
 *       Print byte length of line INDEX.
 *
 *   buf lines HANDLE
 *       Print number of lines.
 *
 *   buf text HANDLE [LINENO N] [-F FD] [-X]
 *       Print/dump full buffer or N-line range joined with \n.
 *       -F writes raw bytes to FD; -X hex-encodes to stdout.
 *
 *   buf set-name HANDLE PATH
 *       Set the filename used by save when no path given.
 *
 *   buf dirty HANDLE
 *       Exit 0 if dirty, 1 otherwise.
 *
 *   buf clean HANDLE
 *       Clear dirty flag.
 *
 *   buf free HANDLE
 *       Release the buffer + slot.
 *
 * Mutation verbs (insert-line, delete-line, load) set the dirty flag.
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
#include <sys/types.h>
#include <sys/mman.h>

#include "loadables.h"

#define BB_HANDLES_MAX 32

/* A line is in exactly one of two states:
 *   mapped : data == NULL, map != NULL  — content is a span inside the
 *            buffer's read-only mmap; nothing is copied to the heap, so the
 *            bytes stay file-backed and the OS pages them in on demand. This
 *            is what lets a file larger than RAM be loaded/viewed/saved with
 *            a resident set far below the file size.
 *   heap   : data != NULL, map == NULL  — ordinary owned heap buffer; every
 *            mutating path materializes a mapped line into this state first
 *            (per-line copy-on-write).
 * A zero-length line may have both NULL (empty content). free(data) is always
 * safe because mapped lines keep data == NULL; the mmap itself is released
 * once via munmap at buffer free / reload. */
typedef struct {
    char       *data;       /* owned heap buffer; NULL while still mapped */
    const char *map;        /* span into the buffer's mmap; NULL once on heap */
    size_t      length;     /* exact byte count */
    size_t      capacity;   /* heap capacity; 0 while mapped */
} bb_line;

/* Sparse line-index stride: in the paged state we keep the byte offset of
   every BB_CKPT_STRIDE-th line, not one record per line, so a freshly-loaded
   file's index is O(n_lines / stride) — sublinear, which matters on a
   RAM-only/no-swap target where anonymous heap can't be evicted. Line K is
   resolved by jumping to checkpoint K/stride and scanning forward over the
   (already-mmapped) content. The first edit realizes the full record array. */
#define BB_CKPT_STRIDE 1024

typedef struct {
    /* Realized state: a flat record array (lines/n_lines/capacity). Paged
       state: lines==NULL, capacity==0, n_lines holds the TOTAL line count and
       ckpt[] holds the sparse checkpoints. n_lines is the total in BOTH
       states, so callers read it uniformly. */
    bb_line *lines;
    size_t   n_lines;
    size_t   capacity;
    char    *filename;          /* malloc'd or NULL */
    void    *map_base;          /* mmap base for span-backed lines, or NULL */
    size_t   map_size;          /* mmap length for munmap */
    int      paged;             /* 1 = sparse checkpoint index; 0 = record array */
    size_t  *ckpt;              /* paged: byte offset of every stride-th line */
    size_t   n_ckpt;            /* paged: number of checkpoint entries */
    int      dirty;
    int      had_trailing_nl;   /* true if file ended with \n at load */
} bb_buf;

/* Read accessor: the line's bytes live in the heap copy if materialized,
   otherwise in the mmap span. Either may be NULL for a zero-length line. */
static const char *
bb_line_ptr (const bb_line *L)
{
    return L->data ? L->data : L->map;
}

/* Copy-on-write: pull a still-mapped line into an owned heap buffer so it can
   be edited in place. No-op for already-heap (or empty) lines. */
static int
bb_line_materialize (bb_line *L)
{
    if (L->data || !L->map) return 0;
    char *nb = malloc (L->length + 1);
    if (!nb) return -1;
    memcpy (nb, L->map, L->length);
    nb[L->length] = '\0';
    L->data = nb;
    L->capacity = L->length + 1;
    L->map = NULL;
    return 0;
}

/* --- Sparse (paged) line-index resolution -------------------------------
 * Valid only while b->paged. Resolve the byte offset + length of line K by
 * jumping to its checkpoint and scanning forward over the mmap. O(stride). */
static void
bb_span (const bb_buf *b, size_t k, size_t *off, size_t *len)
{
    const char *m = b->map_base;
    size_t msz = b->map_size;
    size_t c = k / BB_CKPT_STRIDE;
    size_t pos = b->ckpt[c];
    size_t remaining = k - c * BB_CKPT_STRIDE;
    while (remaining--) {
        const char *nl = memchr (m + pos, '\n', msz - pos);
        if (!nl) break;                 /* defensive: K < n_lines guarantees one */
        pos = (size_t) (nl - m) + 1;
    }
    const char *nl = memchr (m + pos, '\n', msz - pos);
    *off = pos;
    *len = nl ? (size_t) (nl - (m + pos)) : (msz - pos);
}

/* Unified single-line read accessor (both states). 0 on success, -1 if K is
   out of range. *ptr may be NULL only for a zero-length realized line. */
static int
bb_resolve (const bb_buf *b, size_t k, const char **ptr, size_t *len)
{
    if (k >= b->n_lines) return -1;
    if (b->paged) {
        size_t off;
        bb_span (b, k, &off, len);
        *ptr = (const char *) b->map_base + off;
        return 0;
    }
    *ptr = bb_line_ptr (&b->lines[k]);
    *len = b->lines[k].length;
    return 0;
}

/* Sequential in-order iterator used by text/save so a full-buffer walk is one
   O(n_lines) pass in BOTH states (resolving each line via bb_span would be
   O(n_lines * stride)). Caller controls the line count; bb_iter_next assumes
   the current index is in range. */
typedef struct {
    bb_buf *b;
    size_t  pos;     /* paged: byte offset of the current line */
    size_t  idx;     /* realized: current array index */
} bb_iter;

static void
bb_iter_init (bb_iter *it, bb_buf *b, size_t start)
{
    it->b = b;
    it->idx = start;
    it->pos = 0;
    if (b->paged && start < b->n_lines) {
        size_t off, len;
        bb_span (b, start, &off, &len);
        it->pos = off;
    }
}

static void
bb_iter_next (bb_iter *it, const char **ptr, size_t *len)
{
    bb_buf *b = it->b;
    if (b->paged) {
        const char *m = b->map_base;
        const char *nl = memchr (m + it->pos, '\n', b->map_size - it->pos);
        *ptr = m + it->pos;
        *len = nl ? (size_t) (nl - (m + it->pos)) : (b->map_size - it->pos);
        it->pos = nl ? (size_t) (nl - m) + 1 : b->map_size;
    } else {
        *ptr = bb_line_ptr (&b->lines[it->idx]);
        *len = b->lines[it->idx].length;
    }
    it->idx++;
}

static bb_buf *bb_handles[BB_HANDLES_MAX] = {0};

static int
bb_alloc_handle (bb_buf *b)
{
    for (int i = 0; i < BB_HANDLES_MAX; i++) {
        if (!bb_handles[i]) { bb_handles[i] = b; return i; }
    }
    return -1;
}

static bb_buf *
bb_get (const char *s)
{
    char *end;
    long h = strtol (s, &end, 10);
    if (*end != '\0' || h < 0 || h >= BB_HANDLES_MAX) return NULL;
    return bb_handles[h];
}

/* ---- Public C API for cross-loadable callers (undo, clip) ----
 * These functions take a slot int (the user-visible handle) and return
 * 0 on success, -1 on error. They do their own dirty-flag bookkeeping.
 * Declarations matched in undo.c / clip.c. */

int bb_pub_n_lines (int slot);
int bb_pub_get_line (int slot, size_t index,
                     const unsigned char **out_bytes, size_t *out_len);
int bb_pub_insert_line (int slot, size_t index,
                        const unsigned char *bytes, size_t len);
int bb_pub_delete_line (int slot, size_t index);
int bb_pub_insert_at (int slot, size_t index, size_t col,
                      const unsigned char *bytes, size_t len);
int bb_pub_delete_at (int slot, size_t index, size_t col, size_t n);
int bb_pub_set_dirty (int slot, int dirty);

int
bb_pub_n_lines (int slot)
{
    if (slot < 0 || slot >= BB_HANDLES_MAX || !bb_handles[slot]) return -1;
    return (int) bb_handles[slot]->n_lines;
}

int
bb_pub_get_line (int slot, size_t index,
                 const unsigned char **out_bytes, size_t *out_len)
{
    if (slot < 0 || slot >= BB_HANDLES_MAX || !bb_handles[slot]) return -1;
    bb_buf *b = bb_handles[slot];
    const char *ptr;
    size_t len;
    if (bb_resolve (b, index, &ptr, &len) < 0) return -1;
    *out_bytes = (const unsigned char *) ptr;
    *out_len = len;
    return 0;
}

static int
bb_get_index (const char *s)
{
    char *end;
    long h = strtol (s, &end, 10);
    if (*end != '\0' || h < 0 || h >= BB_HANDLES_MAX) return -1;
    return (int) h;
}

/* Hex codec for -X mode. */
static unsigned char *
bb_hex_decode (const char *hex, size_t *out_len)
{
    size_t hl = strlen (hex);
    if (hl % 2 != 0) return NULL;
    size_t bl = hl / 2;
    unsigned char *out = malloc (bl + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < bl; i++) {
        int hi = hex[2*i], lo = hex[2*i+1];
        hi = (hi >= '0' && hi <= '9') ? hi - '0'
             : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10
             : (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1;
        lo = (lo >= '0' && lo <= '9') ? lo - '0'
             : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10
             : (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1;
        if (hi < 0 || lo < 0) { free (out); return NULL; }
        out[i] = (unsigned char) ((hi << 4) | lo);
    }
    out[bl] = '\0';
    *out_len = bl;
    return out;
}

/* Hex-encode N bytes into a caller-supplied buffer of at least 2*N bytes.
   Does not NUL-terminate (callers that need a C string pass a 2*N+1 buffer
   and terminate themselves). Used by the streaming text -X path so it can
   reuse one growable scratch buffer across lines instead of allocating a
   whole-buffer join. */
static void
bb_hex_encode_into (char *out, const unsigned char *data, size_t n)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2*i] = d[data[i] >> 4];
        out[2*i + 1] = d[data[i] & 0xF];
    }
}

static char *
bb_hex_encode (const unsigned char *data, size_t n)
{
    char *out = malloc (2 * n + 1);
    if (!out) return NULL;
    bb_hex_encode_into (out, data, n);
    out[2*n] = '\0';
    return out;
}

/* Append N bytes to a growable accumulator (the current-line buffer used by
   the streaming loader). *cap doubles as needed; returns -1 on OOM with the
   existing buffer left intact. */
static int
bb_part_append (char **buf, size_t *len, size_t *cap,
                const char *src, size_t n)
{
    if (n == 0) return 0;
    if (*len + n > *cap) {
        size_t c = *cap ? *cap : 256;
        while (c < *len + n) c *= 2;
        char *nb = realloc (*buf, c);
        if (!nb) return -1;
        *buf = nb;
        *cap = c;
    }
    memcpy (*buf + *len, src, n);
    *len += n;
    return 0;
}

static int
bb_write_all (int fd, const char *s, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t w = write (fd, s + off, n - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t) w;
    }
    return 0;
}

static int
bb_journal_write (int fd, char type, long line, long col,
                  const unsigned char *payload, size_t paylen)
{
    char *hex = bb_hex_encode (payload, paylen);
    if (!hex) return -1;
    int need_col = (type == 'A' || type == 'R');
    int n = snprintf (NULL, 0, need_col ? "%c %ld %ld %s -X\n"
                                        : "%c %ld %s -X\n",
                      type, line, col, hex);
    if (n < 0) { free (hex); return -1; }
    char *linebuf = malloc ((size_t) n + 1);
    if (!linebuf) { free (hex); return -1; }
    if (need_col)
        snprintf (linebuf, (size_t) n + 1, "%c %ld %ld %s -X\n",
                  type, line, col, hex);
    else
        snprintf (linebuf, (size_t) n + 1, "%c %ld %s -X\n",
                  type, line, hex);
    int rc = bb_write_all (fd, linebuf, (size_t) n);
    free (linebuf);
    free (hex);
    return rc;
}

/* Set a single line's content. Replaces existing content entirely, so any
   prior mmap span is simply dropped (the line becomes heap-owned). */
static int
bb_line_set (bb_line *L, const unsigned char *bytes, size_t len)
{
    if (L->capacity < len + 1) {
        size_t cap = L->capacity ? L->capacity : 64;
        while (cap < len + 1) cap *= 2;
        char *nb = realloc (L->data, cap);
        if (!nb) return -1;
        L->data = nb;
        L->capacity = cap;
    }
    if (len) memcpy (L->data, bytes, len);
    L->length = len;
    L->map = NULL;
    return 0;
}

/* Hand ownership of a heap buffer directly to a line slot, with no copy.
   Used by the streaming loader so a completed line takes over the
   accumulator buffer instead of memcpy'ing it — this is what keeps a single
   huge line from transiently holding the bytes twice (accumulator + final
   copy). The caller must drop its reference (set its pointer to NULL) after
   the call. */
static void
bb_line_adopt (bb_line *L, char *buf, size_t len, size_t cap)
{
    free (L->data);
    L->data = buf;
    L->length = len;
    L->capacity = cap;
    L->map = NULL;
}

/* Insert empty line slot at INDEX (0..n_lines), shifting subsequent
   lines down. Returns ptr to the new slot (its data/length/capacity
   are zero). */
static bb_line *
bb_grow_line_at (bb_buf *b, size_t index)
{
    if (index > b->n_lines) return NULL;
    if (b->n_lines + 1 > b->capacity) {
        if (b->capacity > SIZE_MAX / 2 / sizeof (bb_line)) return NULL;
        size_t cap = b->capacity ? b->capacity * 2 : 16;
        bb_line *nl = realloc (b->lines, cap * sizeof (bb_line));
        if (!nl) return NULL;
        b->lines = nl;
        b->capacity = cap;
    }
    if (index < b->n_lines) {
        memmove (b->lines + index + 1, b->lines + index,
                 (b->n_lines - index) * sizeof (bb_line));
    }
    b->lines[index].data = NULL;
    b->lines[index].map = NULL;
    b->lines[index].length = 0;
    b->lines[index].capacity = 0;
    b->n_lines++;
    return &b->lines[index];
}

static void
bb_rollback_line_insert (bb_buf *b, size_t index)
{
    if (!b || index >= b->n_lines) return;
    free (b->lines[index].data);
    if (index + 1 < b->n_lines) {
        memmove (b->lines + index, b->lines + index + 1,
                 (b->n_lines - index - 1) * sizeof (bb_line));
    }
    b->n_lines--;
    if (b->capacity > b->n_lines) {
        b->lines[b->n_lines].data = NULL;
        b->lines[b->n_lines].map = NULL;
        b->lines[b->n_lines].length = 0;
        b->lines[b->n_lines].capacity = 0;
    }
}

/* Promote a paged (sparse-index) buffer to the realized record array: walk the
   mmap once and emit one mapped span record per line, exactly as a non-paged
   mmap load would have. Called before any edit; reads stay sparse. The records
   reference the mmap (no content copy) — only the array itself is new RAM, so
   editing a huge file pays the O(n_lines) index cost while load/view/save of
   an unedited file never does. On OOM the partial array is dropped and the
   buffer stays paged (so reads keep working) and the caller sees -1. */
static int
bb_realize (bb_buf *b)
{
    if (!b->paged) return 0;
    const char *m = b->map_base;
    size_t msz = b->map_size;
    size_t total = b->n_lines;
    b->n_lines = 0;                 /* bb_grow_line_at rebuilds the count */
    size_t start = 0;
    for (size_t i = 0; i < msz; i++) {
        if (m[i] != '\n') continue;
        bb_line *L = bb_grow_line_at (b, b->n_lines);
        if (!L) goto oom;
        L->map = m + start;
        L->length = i - start;
        start = i + 1;
    }
    if (start < msz) {              /* trailing partial line (no final \n) */
        bb_line *L = bb_grow_line_at (b, b->n_lines);
        if (!L) goto oom;
        L->map = m + start;
        L->length = msz - start;
    }
    free (b->ckpt);
    b->ckpt = NULL;
    b->n_ckpt = 0;
    b->paged = 0;
    return 0;
oom:
    for (size_t i = 0; i < b->n_lines; i++) free (b->lines[i].data);
    free (b->lines);
    b->lines = NULL;
    b->capacity = 0;
    b->n_lines = total;             /* restore paged invariant: n_lines = total */
    return -1;
}

/* Public-API counterparts: implemented after the static helpers they
   depend on are visible. */
int
bb_pub_insert_line (int slot, size_t index,
                    const unsigned char *bytes, size_t len)
{
    if (slot < 0 || slot >= BB_HANDLES_MAX || !bb_handles[slot]) return -1;
    bb_buf *b = bb_handles[slot];
    if (bb_realize (b) < 0) return -1;
    if (index > b->n_lines) return -1;
    bb_line *L = bb_grow_line_at (b, index);
    if (!L) return -1;
    if (bb_line_set (L, bytes, len) < 0) {
        bb_rollback_line_insert (b, index);
        return -1;
    }
    b->dirty = 1;
    return 0;
}

int
bb_pub_delete_line (int slot, size_t index)
{
    if (slot < 0 || slot >= BB_HANDLES_MAX || !bb_handles[slot]) return -1;
    bb_buf *b = bb_handles[slot];
    if (bb_realize (b) < 0) return -1;
    if (index >= b->n_lines) return -1;
    free (b->lines[index].data);
    if (index + 1 < b->n_lines) {
        memmove (b->lines + index, b->lines + index + 1,
                 (b->n_lines - index - 1) * sizeof (bb_line));
    }
    b->n_lines--;
    b->dirty = 1;
    return 0;
}

int
bb_pub_insert_at (int slot, size_t index, size_t col,
                  const unsigned char *bytes, size_t len)
{
    if (slot < 0 || slot >= BB_HANDLES_MAX || !bb_handles[slot]) return -1;
    bb_buf *b = bb_handles[slot];
    if (bb_realize (b) < 0) return -1;
    if (index >= b->n_lines) return -1;
    bb_line *L = &b->lines[index];
    if (col > L->length) return -1;
    if (bb_line_materialize (L) < 0) return -1;   /* copy-on-write before in-place edit */
    if (L->capacity < L->length + len + 1) {
        size_t cap = L->capacity ? L->capacity : 64;
        while (cap < L->length + len + 1) cap *= 2;
        char *nb = realloc (L->data, cap);
        if (!nb) return -1;
        L->data = nb;
        L->capacity = cap;
    }
    if (col < L->length)
        memmove (L->data + col + len, L->data + col, L->length - col);
    if (len)
        memcpy (L->data + col, bytes, len);
    L->length += len;
    L->data[L->length] = '\0';
    b->dirty = 1;
    return 0;
}

int
bb_pub_delete_at (int slot, size_t index, size_t col, size_t n)
{
    if (slot < 0 || slot >= BB_HANDLES_MAX || !bb_handles[slot]) return -1;
    bb_buf *b = bb_handles[slot];
    if (bb_realize (b) < 0) return -1;
    if (index >= b->n_lines) return -1;
    bb_line *L = &b->lines[index];
    if (col > L->length || n > L->length - col) return -1;
    if (n && bb_line_materialize (L) < 0) return -1;   /* copy-on-write before in-place edit */
    if (n && col + n < L->length)
        memmove (L->data + col, L->data + col + n, L->length - col - n);
    L->length -= n;
    if (L->data) L->data[L->length] = '\0';
    b->dirty = 1;
    return 0;
}

int
bb_pub_set_dirty (int slot, int dirty)
{
    if (slot < 0 || slot >= BB_HANDLES_MAX || !bb_handles[slot]) return -1;
    bb_handles[slot]->dirty = dirty ? 1 : 0;
    return 0;
}

/* Free a buffer (lines + filename). */
static void
bb_free_buf (bb_buf *b)
{
    if (!b) return;
    /* In the paged state lines==NULL while n_lines holds the total, so guard
       the per-line free on the array pointer, not n_lines. */
    if (b->lines) {
        for (size_t i = 0; i < b->n_lines; i++) free (b->lines[i].data);
        free (b->lines);
    }
    free (b->ckpt);
    if (b->map_base) munmap (b->map_base, b->map_size);
    free (b->filename);
    free (b);
}

/* ----- verb implementations ----- */

static int
bb_new_cmd (WORD_LIST *args)
{
    const char *hvar = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-h") == 0 && p->next) { hvar = p->next->word->word; p = p->next; }
        else { builtin_error ("new: unexpected arg '%s'", w); return EX_USAGE; }
    }
    bb_buf *b = calloc (1, sizeof (bb_buf));
    if (!b) { builtin_error ("calloc"); return EXECUTION_FAILURE; }
    int slot = bb_alloc_handle (b);
    if (slot < 0) {
        free (b);
        builtin_error ("new: handle table full (%d slots)", BB_HANDLES_MAX);
        return EXECUTION_FAILURE;
    }
    char buf[16];
    snprintf (buf, sizeof buf, "%d", slot);
    if (hvar) {
        builtin_bind_variable ((char *) hvar, buf, 0);
    } else {
        printf ("%s\n", buf);
    }
    return EXECUTION_SUCCESS;
}

static int
bb_load_cmd (WORD_LIST *args)
{
    if (!args || !args->next) { builtin_error ("load: HANDLE PATH"); return EX_USAGE; }
    bb_buf *b = bb_get (args->word->word);
    if (!b) { builtin_error ("load: bad handle"); return EX_USAGE; }
    const char *path = args->next->word->word;
    int fd = open (path, O_RDONLY);
    if (fd < 0) {
        builtin_error ("load %s: %s", path, strerror (errno));
        return EXECUTION_FAILURE;
    }
    /* Free existing lines and release any prior mapping / checkpoint index.
       In the paged state b->lines is NULL (n_lines is the total), so guard the
       per-line free on the array pointer. */
    if (b->lines) {
        for (size_t i = 0; i < b->n_lines; i++) free (b->lines[i].data);
    }
    b->n_lines = 0;
    free (b->ckpt); b->ckpt = NULL; b->n_ckpt = 0; b->paged = 0;
    if (b->map_base) { munmap (b->map_base, b->map_size); b->map_base = NULL; b->map_size = 0; }

    /* Fast path: memory-map a regular file read-only and build a SPARSE line
       index — the byte offset of every BB_CKPT_STRIDE-th line — instead of a
       per-line record array. Nothing is copied and the index is sublinear in
       the line count, so a file far larger than RAM loads/views/saves with a
       tiny resident set even when it has millions of tiny lines (which matters
       on a no-swap target where a per-line heap array could not be evicted).
       Line K is resolved on demand by scanning forward from checkpoint K/stride
       over the mmap; the first edit realizes the full record array (bb_realize)
       and per-line copy-on-write takes over. Falls through to the streaming
       heap reader below for non-regular files (pipes, procfs), empty files, or
       mmap failure. */
    {
        struct stat lst;
        if (fstat (fd, &lst) == 0 && S_ISREG (lst.st_mode) && lst.st_size > 0) {
            size_t msz = (size_t) lst.st_size;
            void *base = mmap (NULL, msz, PROT_READ, MAP_PRIVATE, fd, 0);
            if (base != MAP_FAILED) {
                const char *m = base;
                size_t ckcap = 1, ckn = 1;
                size_t *ck = malloc (ckcap * sizeof (size_t));
                if (!ck) { munmap (base, msz); close (fd); builtin_error ("load: malloc"); return EXECUTION_FAILURE; }
                ck[0] = 0;                       /* line 0 starts at offset 0 */
                size_t nl_count = 0;
                for (size_t i = 0; i < msz; i++) {
                    if (m[i] != '\n') continue;
                    nl_count++;
                    if (nl_count % BB_CKPT_STRIDE == 0) {
                        /* line nl_count (0-based) starts at i+1 — a checkpoint */
                        if (ckn >= ckcap) {
                            size_t nc = ckcap * 2;
                            size_t *t = realloc (ck, nc * sizeof (size_t));
                            if (!t) { free (ck); munmap (base, msz); close (fd); builtin_error ("load: realloc"); return EXECUTION_FAILURE; }
                            ck = t; ckcap = nc;
                        }
                        ck[ckn++] = i + 1;
                    }
                }
                int trailing = (m[msz - 1] != '\n');   /* msz>0 guaranteed here */
                b->map_base = base;
                b->map_size = msz;
                b->ckpt = ck;
                b->n_ckpt = ckn;
                b->n_lines = nl_count + (trailing ? 1 : 0);   /* total lines */
                b->paged = 1;                                  /* lines[] stays empty */
                b->had_trailing_nl = !trailing;
                close (fd);
                free (b->filename);
                b->filename = strdup (path);
                b->dirty = 0;
                return EXECUTION_SUCCESS;
            }
            /* mmap failed (e.g. ENOMEM on address space) — fall through. */
        }
    }

    /* Streaming split: read fixed-size chunks and emit lines on every '\n'
       as we go, carrying the bytes of the line currently being assembled in
       a small growable accumulator (`part`). Peak transient memory is one
       chunk plus the longest single line, instead of a second whole-file
       buffer the size of the input. The line array itself is unavoidable —
       buf is a random-access in-RAM editor buffer. */
    char chunk[65536];
    char  *part = NULL;     /* bytes of the in-progress (not-yet-flushed) line */
    size_t plen = 0, pcap = 0;
    int    any_data = 0;
    unsigned char last_byte = 0;
    ssize_t got;
    int rc = EXECUTION_SUCCESS;

    while ((got = read (fd, chunk, sizeof chunk)) != 0) {
        if (got < 0) {
            if (errno == EINTR) continue;   /* retry; matches save-path EINTR posture */
            break;
        }
        any_data = 1;
        last_byte = (unsigned char) chunk[got - 1];
        size_t seg = 0;
        for (size_t i = 0; i < (size_t) got; i++) {
            if (chunk[i] != '\n') continue;
            /* Complete a line: accumulated `part` + chunk[seg..i). */
            if (bb_part_append (&part, &plen, &pcap, chunk + seg, i - seg) < 0) {
                builtin_error ("load: realloc"); rc = EXECUTION_FAILURE; goto done;
            }
            bb_line *L = bb_grow_line_at (b, b->n_lines);
            if (!L) { rc = EXECUTION_FAILURE; goto done; }
            /* The line takes over the accumulator buffer (no copy); start a
               fresh accumulator for the next line. */
            bb_line_adopt (L, part, plen, pcap);
            part = NULL; plen = 0; pcap = 0;
            seg = i + 1;
        }
        /* Tail of the chunk with no trailing '\n' carries into the next read. */
        if ((size_t) got > seg &&
            bb_part_append (&part, &plen, &pcap, chunk + seg, (size_t) got - seg) < 0) {
            builtin_error ("load: realloc"); rc = EXECUTION_FAILURE; goto done;
        }
    }
    if (got < 0) {
        builtin_error ("load read %s: %s", path, strerror (errno));
        rc = EXECUTION_FAILURE; goto done;
    }
    /* Final partial line: present iff the file did not end with '\n'. When it
       did, the last flush left plen == 0 and we emit nothing extra. */
    if (plen > 0) {
        bb_line *L = bb_grow_line_at (b, b->n_lines);
        if (!L) { rc = EXECUTION_FAILURE; goto done; }
        bb_line_adopt (L, part, plen, pcap);
        part = NULL; plen = 0; pcap = 0;
    }
    b->had_trailing_nl = (any_data && last_byte == '\n');

done:
    free (part);
    close (fd);
    if (rc != EXECUTION_SUCCESS) return rc;

    free (b->filename);
    b->filename = strdup (path);
    b->dirty = 0;
    return EXECUTION_SUCCESS;
}

static int
bb_save_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("save: HANDLE [PATH]"); return EX_USAGE; }
    bb_buf *b = bb_get (args->word->word);
    if (!b) { builtin_error ("save: bad handle"); return EX_USAGE; }
    const char *path = args->next ? args->next->word->word : b->filename;
    if (!path) { builtin_error ("save: no filename"); return EX_USAGE; }

    /* Atomic: write to PATH.tmpXXXXXX, fchmod/fchown to match (or 0644
       default for new files), fsync, rename. */
    char tmp_path[4096];
    snprintf (tmp_path, sizeof tmp_path, "%s.tmpXXXXXX", path);
    int fd = mkstemp (tmp_path);
    if (fd < 0) {
        builtin_error ("save mkstemp: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    /* Match original perms if file existed; else 0644. */
    struct stat st;
    mode_t mode = 0644;
    int have_st = (stat (path, &st) == 0);
    if (have_st) mode = st.st_mode & 07777;
    fchmod (fd, mode);
    if (have_st && geteuid () == 0)
        (void) fchown (fd, st.st_uid, st.st_gid);

    bb_iter sit;
    bb_iter_init (&sit, b, 0);
    for (size_t i = 0; i < b->n_lines; i++) {
        const char *src;
        size_t slen;
        bb_iter_next (&sit, &src, &slen);   /* heap copy or mmap span, both states */
        if (slen > 0) {
            ssize_t off = 0;
            while ((size_t) off < slen) {
                ssize_t w = write (fd, src + off, slen - (size_t) off);
                if (w < 0) {
                    if (errno == EINTR) continue;
                    builtin_error ("save write: %s", strerror (errno));
                    close (fd); unlink (tmp_path);
                    return EXECUTION_FAILURE;
                }
                off += w;
            }
        }
        /* Newline between lines, and after last only if file had a
           trailing newline at load (or if user explicitly added one).
           EINTR-retry on the 1-byte write — the previous "if errno != EINTR
           bail" arm silently dropped the newline on EINTR success exits. */
        int emit_nl = (i + 1 < b->n_lines) || b->had_trailing_nl;
        if (emit_nl) {
            ssize_t w;
            while ((w = write (fd, "\n", 1)) != 1) {
                if (w < 0 && errno == EINTR) continue;
                builtin_error ("save write: %s", strerror (errno));
                close (fd); unlink (tmp_path);
                return EXECUTION_FAILURE;
            }
        }
    }
    fdatasync (fd);
    close (fd);
    if (rename (tmp_path, path) < 0) {
        builtin_error ("save rename %s -> %s: %s", tmp_path, path, strerror (errno));
        unlink (tmp_path);
        return EXECUTION_FAILURE;
    }
    /* fsync the containing directory so the rename itself is durable
       across power loss. Without this, POSIX permits a crash after a
       successful rename() return to roll back to the pre-rename state
       (file data is durable via fdatasync above, but the directory
       entry pointing at it is not). Best-effort: open(O_DIRECTORY)
       failures are non-fatal — the data is already on disk. */
    {
        const char *slash = strrchr (path, '/');
        const char *dirpath = ".";
        char dirbuf[4096];
        if (slash) {
            size_t dlen = (slash == path) ? 1 : (size_t) (slash - path);
            if (dlen < sizeof dirbuf) {
                memcpy (dirbuf, path, dlen);
                dirbuf[dlen] = '\0';
                dirpath = dirbuf;
            }
        }
        /* O_CLOEXEC defense-in-depth: the dfd is open across an
           fsync syscall that can block on slow devices; if a bash
           trap forks during that window the dfd would leak to the
           child without CLOEXEC. The window is small but the cost
           of closing it is one flag. Matches the O_CLOEXEC posture
           in auth.c:65 and io.c:143/395/421. */
        int dfd = open (dirpath, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd >= 0) {
            (void) fsync (dfd);
            close (dfd);
        }
    }
    free (b->filename);
    b->filename = strdup (path);
    b->dirty = 0;
    return EXECUTION_SUCCESS;
}

static int
bb_insert_line_cmd (WORD_LIST *args)
{
    if (!args || !args->next || !args->next->next) {
        builtin_error ("insert-line: HANDLE INDEX TEXT [-X]");
        return EX_USAGE;
    }
    bb_buf *b = bb_get (args->word->word);
    if (!b) { builtin_error ("insert-line: bad handle"); return EX_USAGE; }
    if (bb_realize (b) < 0) { builtin_error ("insert-line: realize"); return EXECUTION_FAILURE; }
    long index = strtol (args->next->word->word, NULL, 10);
    if (index < 0 || (size_t) index > b->n_lines) {
        builtin_error ("insert-line: index %ld out of range [0..%zu]", index, b->n_lines);
        return EX_USAGE;
    }
    const char *text = args->next->next->word->word;
    int hex_mode = 0;
    /* Look for -X anywhere after TEXT. */
    for (WORD_LIST *p = args->next->next->next; p; p = p->next) {
        if (strcmp (p->word->word, "-X") == 0) hex_mode = 1;
    }
    const unsigned char *bytes;
    size_t len;
    unsigned char *decoded = NULL;
    if (hex_mode) {
        decoded = bb_hex_decode (text, &len);
        if (!decoded) { builtin_error ("insert-line: bad hex input"); return EX_USAGE; }
        bytes = decoded;
    } else {
        bytes = (const unsigned char *) text;
        len = strlen (text);
    }
    bb_line *L = bb_grow_line_at (b, (size_t) index);
    if (!L) { free (decoded); builtin_error ("insert-line: alloc"); return EXECUTION_FAILURE; }
    if (bb_line_set (L, bytes, len) < 0) {
        bb_rollback_line_insert (b, (size_t) index);
        free (decoded);
        builtin_error ("insert-line: alloc");
        return EXECUTION_FAILURE;
    }
    free (decoded);
    b->dirty = 1;
    return EXECUTION_SUCCESS;
}

static int
bb_delete_line_cmd (WORD_LIST *args)
{
    if (!args || !args->next) { builtin_error ("delete-line: HANDLE INDEX"); return EX_USAGE; }
    bb_buf *b = bb_get (args->word->word);
    if (!b) { builtin_error ("delete-line: bad handle"); return EX_USAGE; }
    if (bb_realize (b) < 0) { builtin_error ("delete-line: realize"); return EXECUTION_FAILURE; }
    long index = strtol (args->next->word->word, NULL, 10);
    if (index < 0 || (size_t) index >= b->n_lines) {
        builtin_error ("delete-line: index %ld out of range [0..%zu)", index, b->n_lines);
        return EX_USAGE;
    }
    free (b->lines[index].data);
    if ((size_t) index + 1 < b->n_lines) {
        memmove (b->lines + index, b->lines + index + 1,
                 (b->n_lines - (size_t) index - 1) * sizeof (bb_line));
    }
    b->n_lines--;
    b->dirty = 1;
    return EXECUTION_SUCCESS;
}

static int
bb_insert_at_cmd (WORD_LIST *args)
{
    if (!args || !args->next || !args->next->next || !args->next->next->next) {
        builtin_error ("insert-at: HANDLE LINENO COL TEXT [-X]");
        return EX_USAGE;
    }
    int slot = bb_get_index (args->word->word);
    bb_buf *b = bb_get (args->word->word);
    if (!b || slot < 0) { builtin_error ("insert-at: bad handle"); return EX_USAGE; }
    if (bb_realize (b) < 0) { builtin_error ("insert-at: realize"); return EXECUTION_FAILURE; }
    char *end = NULL;
    long lineno = strtol (args->next->word->word, &end, 10);
    if (*end || lineno < 0 || (size_t) lineno >= b->n_lines) {
        builtin_error ("insert-at: line out of range");
        return EX_USAGE;
    }
    end = NULL;
    long col = strtol (args->next->next->word->word, &end, 10);
    if (*end || col < 0 || (size_t) col > b->lines[lineno].length) {
        builtin_error ("insert-at: column out of range");
        return EX_USAGE;
    }
    const char *text = args->next->next->next->word->word;
    int hex_mode = 0;
    for (WORD_LIST *p = args->next->next->next->next; p; p = p->next) {
        if (strcmp (p->word->word, "-X") == 0) hex_mode = 1;
        else { builtin_error ("insert-at: unexpected arg '%s'", p->word->word); return EX_USAGE; }
    }
    const unsigned char *bytes = (const unsigned char *) text;
    size_t len = strlen (text);
    unsigned char *decoded = NULL;
    if (hex_mode) {
        decoded = bb_hex_decode (text, &len);
        if (!decoded) { builtin_error ("insert-at: bad hex input"); return EX_USAGE; }
        bytes = decoded;
    }
    if (bb_pub_insert_at (slot, (size_t) lineno, (size_t) col, bytes, len) < 0) {
        free (decoded);
        builtin_error ("insert-at: failed");
        return EXECUTION_FAILURE;
    }
    free (decoded);
    return EXECUTION_SUCCESS;
}

static int
bb_delete_at_cmd (WORD_LIST *args)
{
    if (!args || !args->next || !args->next->next || !args->next->next->next) {
        builtin_error ("delete-at: HANDLE LINENO COL N");
        return EX_USAGE;
    }
    int slot = bb_get_index (args->word->word);
    bb_buf *b = bb_get (args->word->word);
    if (!b || slot < 0) { builtin_error ("delete-at: bad handle"); return EX_USAGE; }
    if (bb_realize (b) < 0) { builtin_error ("delete-at: realize"); return EXECUTION_FAILURE; }
    char *end = NULL;
    long lineno = strtol (args->next->word->word, &end, 10);
    if (*end || lineno < 0 || (size_t) lineno >= b->n_lines) {
        builtin_error ("delete-at: line out of range");
        return EX_USAGE;
    }
    end = NULL;
    long col = strtol (args->next->next->word->word, &end, 10);
    if (*end || col < 0) {
        builtin_error ("delete-at: bad column");
        return EX_USAGE;
    }
    end = NULL;
    long n = strtol (args->next->next->next->word->word, &end, 10);
    if (*end || n < 0) {
        builtin_error ("delete-at: bad length");
        return EX_USAGE;
    }
    if (bb_pub_delete_at (slot, (size_t) lineno, (size_t) col, (size_t) n) < 0) {
        builtin_error ("delete-at: range out of bounds");
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bb_mutate_cmd (WORD_LIST *args)
{
    int journal_fd = -1;
    const char *handle_s = NULL;
    WORD_LIST *p = args;
    for (; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-j") == 0 && p->next) {
            char *end = NULL;
            long fd = strtol (p->next->word->word, &end, 10);
            if (*end || fd < 0) { builtin_error ("mutate: bad journal fd"); return EX_USAGE; }
            journal_fd = (int) fd;
            p = p->next;
        } else if (strcmp (w, "-h") == 0 && p->next) {
            handle_s = p->next->word->word;
            p = p->next;
        } else if (strcmp (w, "--") == 0) {
            p = p->next;
            break;
        } else {
            builtin_error ("mutate: unexpected arg '%s'", w);
            return EX_USAGE;
        }
    }
    if (journal_fd < 0 || !handle_s || !p) {
        builtin_error ("mutate: -j JOURNALFD -h HANDLE -- VERB ARGS...");
        return EX_USAGE;
    }
    int slot = bb_get_index (handle_s);
    bb_buf *b = bb_get (handle_s);
    if (!b || slot < 0) { builtin_error ("mutate: bad handle"); return EX_USAGE; }
    if (bb_realize (b) < 0) { builtin_error ("mutate: realize"); return EXECUTION_FAILURE; }

    const char *verb = p->word->word;
    WORD_LIST *a = p->next;
    if (strcmp (verb, "insert-line") == 0) {
        if (!a || !a->next) { builtin_error ("mutate insert-line: INDEX TEXT [-X]"); return EX_USAGE; }
        char *end = NULL;
        long index = strtol (a->word->word, &end, 10);
        if (*end || index < 0 || (size_t) index > b->n_lines) {
            builtin_error ("mutate insert-line: index out of range");
            return EX_USAGE;
        }
        const char *text = a->next->word->word;
        int hex_mode = 0;
        for (WORD_LIST *q = a->next->next; q; q = q->next) {
            if (strcmp (q->word->word, "-X") == 0) hex_mode = 1;
            else { builtin_error ("mutate insert-line: unexpected arg '%s'", q->word->word); return EX_USAGE; }
        }
        size_t len = strlen (text);
        const unsigned char *bytes = (const unsigned char *) text;
        unsigned char *decoded = NULL;
        if (hex_mode) {
            decoded = bb_hex_decode (text, &len);
            if (!decoded) { builtin_error ("mutate insert-line: bad hex"); return EX_USAGE; }
            bytes = decoded;
        }
        if (bb_pub_insert_line (slot, (size_t) index, bytes, len) < 0) {
            free (decoded);
            builtin_error ("mutate insert-line: failed");
            return EXECUTION_FAILURE;
        }
        if (bb_journal_write (journal_fd, 'I', index, 0, bytes, len) < 0) {
            free (decoded);
            builtin_error ("mutate insert-line: journal write failed");
            return EXECUTION_FAILURE;
        }
        free (decoded);
        return EXECUTION_SUCCESS;
    }

    if (strcmp (verb, "delete-line") == 0) {
        if (!a) { builtin_error ("mutate delete-line: INDEX"); return EX_USAGE; }
        char *end = NULL;
        long index = strtol (a->word->word, &end, 10);
        if (*end || index < 0 || (size_t) index >= b->n_lines) {
            builtin_error ("mutate delete-line: index out of range");
            return EX_USAGE;
        }
        bb_line *L = &b->lines[index];
        unsigned char *copy = malloc (L->length + 1);
        if (!copy) { builtin_error ("mutate delete-line: alloc"); return EXECUTION_FAILURE; }
        if (L->length) memcpy (copy, bb_line_ptr (L), L->length);  /* ptr may be NULL for a 0-len mapped line */
        copy[L->length] = '\0';
        size_t len = L->length;
        if (bb_pub_delete_line (slot, (size_t) index) < 0) {
            free (copy);
            builtin_error ("mutate delete-line: failed");
            return EXECUTION_FAILURE;
        }
        if (bb_journal_write (journal_fd, 'D', index, 0, copy, len) < 0) {
            free (copy);
            builtin_error ("mutate delete-line: journal write failed");
            return EXECUTION_FAILURE;
        }
        free (copy);
        return EXECUTION_SUCCESS;
    }

    if (strcmp (verb, "insert-at") == 0) {
        if (!a || !a->next || !a->next->next) {
            builtin_error ("mutate insert-at: LINENO COL TEXT [-X]");
            return EX_USAGE;
        }
        char *end = NULL;
        long lineno = strtol (a->word->word, &end, 10);
        if (*end || lineno < 0 || (size_t) lineno >= b->n_lines) {
            builtin_error ("mutate insert-at: line out of range");
            return EX_USAGE;
        }
        end = NULL;
        long col = strtol (a->next->word->word, &end, 10);
        if (*end || col < 0 || (size_t) col > b->lines[lineno].length) {
            builtin_error ("mutate insert-at: column out of range");
            return EX_USAGE;
        }
        const char *text = a->next->next->word->word;
        int hex_mode = 0;
        for (WORD_LIST *q = a->next->next->next; q; q = q->next) {
            if (strcmp (q->word->word, "-X") == 0) hex_mode = 1;
            else { builtin_error ("mutate insert-at: unexpected arg '%s'", q->word->word); return EX_USAGE; }
        }
        size_t len = strlen (text);
        const unsigned char *bytes = (const unsigned char *) text;
        unsigned char *decoded = NULL;
        if (hex_mode) {
            decoded = bb_hex_decode (text, &len);
            if (!decoded) { builtin_error ("mutate insert-at: bad hex"); return EX_USAGE; }
            bytes = decoded;
        }
        if (bb_pub_insert_at (slot, (size_t) lineno, (size_t) col, bytes, len) < 0) {
            free (decoded);
            builtin_error ("mutate insert-at: failed");
            return EXECUTION_FAILURE;
        }
        if (bb_journal_write (journal_fd, 'A', lineno, col, bytes, len) < 0) {
            free (decoded);
            builtin_error ("mutate insert-at: journal write failed");
            return EXECUTION_FAILURE;
        }
        free (decoded);
        return EXECUTION_SUCCESS;
    }

    if (strcmp (verb, "delete-at") == 0) {
        if (!a || !a->next || !a->next->next) {
            builtin_error ("mutate delete-at: LINENO COL N");
            return EX_USAGE;
        }
        char *end = NULL;
        long lineno = strtol (a->word->word, &end, 10);
        if (*end || lineno < 0 || (size_t) lineno >= b->n_lines) {
            builtin_error ("mutate delete-at: line out of range");
            return EX_USAGE;
        }
        end = NULL;
        long col = strtol (a->next->word->word, &end, 10);
        if (*end || col < 0 || (size_t) col > b->lines[lineno].length) {
            builtin_error ("mutate delete-at: column out of range");
            return EX_USAGE;
        }
        end = NULL;
        long n = strtol (a->next->next->word->word, &end, 10);
        if (*end || n < 0 || (size_t) n > b->lines[lineno].length - (size_t) col) {
            builtin_error ("mutate delete-at: range out of bounds");
            return EX_USAGE;
        }
        unsigned char *copy = malloc ((size_t) n + 1);
        if (!copy) { builtin_error ("mutate delete-at: alloc"); return EXECUTION_FAILURE; }
        if (n) memcpy (copy, bb_line_ptr (&b->lines[lineno]) + col, (size_t) n);  /* base may be NULL for a 0-len mapped line */
        copy[n] = '\0';
        if (bb_pub_delete_at (slot, (size_t) lineno, (size_t) col, (size_t) n) < 0) {
            free (copy);
            builtin_error ("mutate delete-at: failed");
            return EXECUTION_FAILURE;
        }
        if (bb_journal_write (journal_fd, 'R', lineno, col, copy, (size_t) n) < 0) {
            free (copy);
            builtin_error ("mutate delete-at: journal write failed");
            return EXECUTION_FAILURE;
        }
        free (copy);
        return EXECUTION_SUCCESS;
    }

    builtin_error ("mutate: unsupported verb '%s'", verb);
    return EX_USAGE;
}

static int
bb_line_cmd (WORD_LIST *args)
{
    if (!args || !args->next) { builtin_error ("line: HANDLE INDEX [-V VAR] [-X]"); return EX_USAGE; }
    bb_buf *b = bb_get (args->word->word);
    if (!b) { builtin_error ("line: bad handle"); return EX_USAGE; }
    long index = strtol (args->next->word->word, NULL, 10);
    if (index < 0 || (size_t) index >= b->n_lines) {
        builtin_error ("line: index %ld out of range [0..%zu)", index, b->n_lines);
        return EX_USAGE;
    }
    const char *var = NULL;
    int hex_mode = 0;
    for (WORD_LIST *p = args->next->next; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-V") == 0 && p->next) { var = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-X") == 0) hex_mode = 1;
        else { builtin_error ("line: unexpected arg '%s'", w); return EX_USAGE; }
    }
    const char *src;             /* heap copy or mmap span, both states */
    size_t slen;
    (void) bb_resolve (b, (size_t) index, &src, &slen);  /* index already range-checked */
    char *out;
    if (hex_mode) {
        out = bb_hex_encode ((const unsigned char *) src, slen);
        if (!out) { builtin_error ("line: alloc"); return EXECUTION_FAILURE; }
    } else {
        out = malloc (slen + 1);
        if (!out) { builtin_error ("line: alloc"); return EXECUTION_FAILURE; }
        if (slen) memcpy (out, src, slen);
        out[slen] = '\0';
    }
    if (var) {
        builtin_bind_variable ((char *) var, out, 0);
    } else {
        if (slen > 0) fwrite (out, 1, hex_mode ? strlen (out) : slen, stdout);
        putchar ('\n');
    }
    free (out);
    return EXECUTION_SUCCESS;
}

static int
bb_len_cmd (WORD_LIST *args)
{
    if (!args || !args->next) { builtin_error ("len: HANDLE INDEX"); return EX_USAGE; }
    bb_buf *b = bb_get (args->word->word);
    if (!b) { builtin_error ("len: bad handle"); return EX_USAGE; }
    long index = strtol (args->next->word->word, NULL, 10);
    if (index < 0 || (size_t) index >= b->n_lines) {
        builtin_error ("len: index out of range");
        return EX_USAGE;
    }
    const char *src;
    size_t slen;
    (void) bb_resolve (b, (size_t) index, &src, &slen);
    printf ("%zu\n", slen);
    return EXECUTION_SUCCESS;
}

static int
bb_lines_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("lines: HANDLE"); return EX_USAGE; }
    bb_buf *b = bb_get (args->word->word);
    if (!b) { builtin_error ("lines: bad handle"); return EX_USAGE; }
    printf ("%zu\n", b->n_lines);
    return EXECUTION_SUCCESS;
}

static int
bb_text_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("text: HANDLE [LINENO N] [-F FD] [-X]"); return EX_USAGE; }
    bb_buf *b = bb_get (args->word->word);
    if (!b) { builtin_error ("text: bad handle"); return EX_USAGE; }
    int hex_mode = 0;
    int out_fd = STDOUT_FILENO;
    long start_l = 0;
    long count_l = (long) b->n_lines;
    int have_range = 0;
    for (WORD_LIST *p = args->next; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-X") == 0) hex_mode = 1;
        else if (strcmp (w, "-F") == 0 && p->next) {
            char *end = NULL;
            long fd = strtol (p->next->word->word, &end, 10);
            if (*end || fd < 0) { builtin_error ("text: bad fd"); return EX_USAGE; }
            out_fd = (int) fd;
            p = p->next;
        } else if (!have_range && p->next) {
            char *end = NULL;
            start_l = strtol (w, &end, 10);
            if (*end || start_l < 0) { builtin_error ("text: bad LINENO"); return EX_USAGE; }
            end = NULL;
            count_l = strtol (p->next->word->word, &end, 10);
            if (*end || count_l < 0) { builtin_error ("text: bad N"); return EX_USAGE; }
            have_range = 1;
            p = p->next;
        } else {
            builtin_error ("text: unexpected arg '%s'", w);
            return EX_USAGE;
        }
    }
    if ((size_t) start_l > b->n_lines) {
        builtin_error ("text: start out of range");
        return EX_USAGE;
    }
    size_t start = (size_t) start_l;
    size_t count = (size_t) count_l;
    if (start + count > b->n_lines) count = b->n_lines - start;
    if (hex_mode && out_fd != STDOUT_FILENO) {
        builtin_error ("text: -X and -F are mutually exclusive");
        return EX_USAGE;
    }
    /* Stream the range out line-by-line instead of building one joined
       whole-buffer copy. A separating '\n' is emitted between lines, and
       after the last line iff the source carried a trailing newline — the
       same byte sequence the former whole-buffer join produced. The raw
       (-F / stdout) path writes each line directly from its own storage, so
       a single huge line goes out with zero extra allocation; the -X path
       reuses one growable hex scratch buffer across lines. */
    bb_iter it;
    bb_iter_init (&it, b, start);
    if (hex_mode) {
        char  *hex = NULL;
        size_t hexcap = 0;
        for (size_t i = start; i < start + count; i++) {
            const char *lp;
            size_t len;
            bb_iter_next (&it, &lp, &len);
            if (len) {
                if (2 * len > hexcap) {
                    size_t c = hexcap ? hexcap : 256;
                    while (c < 2 * len) c *= 2;
                    char *nb = realloc (hex, c);
                    if (!nb) { free (hex); builtin_error ("text: alloc"); return EXECUTION_FAILURE; }
                    hex = nb; hexcap = c;
                }
                bb_hex_encode_into (hex, (const unsigned char *) lp, len);
                fwrite (hex, 1, 2 * len, stdout);
            }
            if (i + 1 < start + count ||
                (i + 1 == b->n_lines && b->had_trailing_nl))
                fwrite ("0a", 1, 2, stdout);   /* hex of the separating '\n' */
        }
        putchar ('\n');                        /* terminate the hex string */
        free (hex);
    } else {
        for (size_t i = start; i < start + count; i++) {
            const char *lp;
            size_t len;
            bb_iter_next (&it, &lp, &len);
            if (len && bb_write_all (out_fd, lp, len) < 0) {
                builtin_error ("text: write: %s", strerror (errno));
                return EXECUTION_FAILURE;
            }
            if (i + 1 < start + count ||
                (i + 1 == b->n_lines && b->had_trailing_nl)) {
                if (bb_write_all (out_fd, "\n", 1) < 0) {
                    builtin_error ("text: write: %s", strerror (errno));
                    return EXECUTION_FAILURE;
                }
            }
        }
    }
    return EXECUTION_SUCCESS;
}

static int
bb_dirty_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("dirty: HANDLE"); return EX_USAGE; }
    bb_buf *b = bb_get (args->word->word);
    if (!b) return EX_USAGE;
    return b->dirty ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bb_clean_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("clean: HANDLE"); return EX_USAGE; }
    bb_buf *b = bb_get (args->word->word);
    if (!b) return EX_USAGE;
    b->dirty = 0;
    return EXECUTION_SUCCESS;
}

static int
bb_set_name_cmd (WORD_LIST *args)
{
    if (!args || !args->next) { builtin_error ("set-name: HANDLE PATH"); return EX_USAGE; }
    bb_buf *b = bb_get (args->word->word);
    if (!b) return EX_USAGE;
    free (b->filename);
    b->filename = strdup (args->next->word->word);
    return EXECUTION_SUCCESS;
}

static int
bb_free_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("free: HANDLE"); return EX_USAGE; }
    int idx = bb_get_index (args->word->word);
    if (idx < 0 || !bb_handles[idx]) return EX_USAGE;
    bb_free_buf (bb_handles[idx]);
    bb_handles[idx] = NULL;
    return EXECUTION_SUCCESS;
}

int
buf_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    if (!strcmp (cmd, "new"))         return bb_new_cmd (args);
    if (!strcmp (cmd, "load"))        return bb_load_cmd (args);
    if (!strcmp (cmd, "save"))        return bb_save_cmd (args);
    if (!strcmp (cmd, "insert-line")) return bb_insert_line_cmd (args);
    if (!strcmp (cmd, "delete-line")) return bb_delete_line_cmd (args);
    if (!strcmp (cmd, "insert-at"))   return bb_insert_at_cmd (args);
    if (!strcmp (cmd, "delete-at"))   return bb_delete_at_cmd (args);
    if (!strcmp (cmd, "mutate"))      return bb_mutate_cmd (args);
    if (!strcmp (cmd, "line"))        return bb_line_cmd (args);
    if (!strcmp (cmd, "len"))         return bb_len_cmd (args);
    if (!strcmp (cmd, "lines"))       return bb_lines_cmd (args);
    if (!strcmp (cmd, "text"))        return bb_text_cmd (args);
    if (!strcmp (cmd, "dirty"))       return bb_dirty_cmd (args);
    if (!strcmp (cmd, "clean"))       return bb_clean_cmd (args);
    if (!strcmp (cmd, "set-name"))    return bb_set_name_cmd (args);
    if (!strcmp (cmd, "free"))        return bb_free_cmd (args);
    builtin_error ("unknown verb: %s", cmd);
    return EX_USAGE;
}

char *buf_doc[] = {
    "Line-array text buffer for scripted editing + nano.",
    "",
    "    buf new [-h HVAR]              allocate; emit slot int",
    "    buf load HANDLE PATH           replace contents from file",
    "    buf save HANDLE [PATH]         atomic write to PATH (or set-name)",
    "    buf insert-line H I TEXT [-X]  insert at index I",
    "    buf delete-line H I            remove line I",
    "    buf insert-at H L C TEXT [-X]  insert bytes into line L at C",
    "    buf delete-at H L C N          delete N bytes in line L at C",
    "    buf mutate -j FD -h H -- VERB ARGS",
    "                                      apply edit + emit undo tuple",
    "    buf line H I [-V VAR] [-X]     print/bind line I",
    "    buf len H I                    line I's byte length",
    "    buf lines H                    line count",
    "    buf text H [L N] [-F FD] [-X]  buffer/range joined with \\n",
    "    buf dirty H                    rc 0 if dirty, 1 if not",
    "    buf clean H                    clear dirty flag",
    "    buf set-name H PATH            set filename for save",
    "    buf free H                     release",
    "",
    "Lines are NUL-safe (length tracked, never strlen on data).",
    "Save uses mkstemp + fdatasync(fd) + rename + fsync(parent-dir) —",
    "atomic and durable across power loss.",
    "",
    "UTF-8 / NUL policy:",
    "  - On-disk: byte-exact load/save. No transcoding, no BOM injection,",
    "    no line-ending translation. A file containing NUL bytes survives",
    "    a `load -> save` round-trip unchanged byte-for-byte.",
    "  - In-memory: lines are opaque byte arrays; length is tracked",
    "    separately so embedded NULs and arbitrary 8-bit data are preserved.",
    "  - All indices (INDEX in insert-line/delete-line/line/len) and the",
    "    value of `len H I` are BYTE-indexed, not grapheme- or",
    "    code-point-indexed. A 4-byte UTF-8 emoji counts as 4 bytes for",
    "    `len`. buf does NOT interpret UTF-8 (no normalization, no",
    "    grapheme clustering; libgrapheme is not linked); higher-level",
    "    editors layer grapheme awareness on top.",
    "  - `line -V VAR` and `line -V VAR -X`: bash variables are C strings,",
    "    so plain `-V VAR` truncates the bound value at the first NUL byte.",
    "    Use `-X` (hex transit) to round-trip NUL-bearing content through",
    "    a bash variable losslessly.",
    "  - `line H I` and `text H` direct-to-stdout: fwrite preserves every",
    "    byte including NULs; redirect to a file to capture them byte-exact.",
    "  - `insert-line H I TEXT` reads TEXT from argv (also a C string), so",
    "    TEXT cannot contain a literal NUL on its own. Use `insert-line H I",
    "    HEXTEXT -X` or `insert-at H L C HEXTEXT -X` to insert",
    "    NUL-bearing or arbitrary-binary content.",
    "  - `mutate -j FD -h H -- ...` writes journal rows as hex payload",
    "    tuples suitable for `undo record HANDLE TYPE LINENO [COL]",
    "    HEXPAYLOAD -X`, so scripted frontends can keep buffer mutation",
    "    and undo recording in one primitive call.",
    (char *)NULL
};

struct builtin buf_struct = {
    "buf",
    buf_builtin,
    BUILTIN_ENABLED,
    buf_doc,
    "buf new|load|save|insert-line|delete-line|insert-at|delete-at|mutate|line|len|lines|text|dirty|clean|set-name|free ARGS",
    0
};
