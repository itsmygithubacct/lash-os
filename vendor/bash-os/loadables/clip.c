/* SPDX-License-Identifier: MIT */
/* clip.c — cut/copy/paste with 16-slot yank ring.
 *
 * Phase V V-3 of bash-os editor primitives. Operates on a buf
 * handle for cut + paste; copy doesn't touch the buffer. Each cut/copy
 * pushes a new newest entry and makes it active, so prior yanks rotate
 * back via yank-prev.
 *
 * Verbs:
 *   clip new [-h HVAR]
 *       Allocate a fresh yank-ring state. Slot int → HVAR (or stdout).
 *
 *   clip cut-line HANDLE BUF_SLOT INDEX
 *       Move line INDEX from buf BUF_SLOT into a new entry. The line is
 *       deleted from the buffer.
 *
 *   clip copy-line HANDLE BUF_SLOT INDEX
 *       Same as cut-line but doesn't remove from buffer.
 *
 *   clip cut-range HANDLE BUF_SLOT START END
 *       Move lines [START..END) into a new entry, in order. Deletes them.
 *       END is clipped to the line count; START must name a line.
 *   clip cut-range HANDLE BUF_SLOT FROM_LINE FROM_COL TO_LINE TO_COL
 *       Move a byte range into a new entry, deleting it from BUF_SLOT.
 *       The entry holds one piece per buffer line the range touches.
 *
 *   clip copy-range HANDLE BUF_SLOT START END
 *       Same without delete.
 *   clip copy-range HANDLE BUF_SLOT FROM_LINE FROM_COL TO_LINE TO_COL
 *       Copy a byte range into a new entry without deleting it.
 *
 *   clip paste HANDLE BUF_SLOT INDEX [COL]
 *       Insert the active entry's pieces as lines at INDEX, or splice them
 *       in at byte column COL of line INDEX (the first piece joins the
 *       prefix, the last joins the old tail).
 *
 *   clip yank-prev HANDLE      rotate active toward older entries
 *   clip yank-next HANDLE      rotate active toward newer entries
 *       Both wrap between the oldest and the newest entry.
 *
 *   clip text HANDLE [-F FD] [-N SLOT] [-X]
 *       Write each piece of the active entry, or of physical slot SLOT,
 *       followed by '\n'. -X prints the pieces joined by '\n' as hex.
 *   clip clear HANDLE          empty active entry (it stays in the ring)
 *   clip free HANDLE           release state + slot
 *
 * Ring: 16 physical slots, filled in order. Once full, a new entry replaces
 * the oldest one, wherever yank-prev/yank-next left the active pointer.
 *
 * Failure: a cut, copy or paste either completes or leaves the buffer bytes,
 * its dirty flag and the ring as they were (allocation failure included).
 *
 * Empty regions: copy-range H B I I records an entry with no pieces, and a
 * zero-length byte range records one empty piece. Pasting no pieces changes
 * nothing; pasting one empty piece as lines inserts one empty line.
 *
 * Bytes: columns are byte offsets, as in buf. Ranges may split a UTF-8
 * sequence; the bytes still move exactly, so pasting a cut back at the same
 * place restores the original. Handles are reused integers, as in buf:
 * a freed buf or clip handle is rejected until the slot is reallocated.
 * `new -h` publishes only to a legal shell identifier. An empty name, a
 * hyphenated name, a leading digit or an array subscript is rejected before
 * a handle is allocated. copy-line and cut-line compare INDEX with the line
 * count before forming the exclusive endpoint, so LONG_MAX does not overflow.
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
#include <limits.h>
#include <stdint.h>

#include "loadables.h"

/* ---- buf public C API ---- */
extern int bb_pub_n_lines (int slot);
extern int bb_pub_get_line (int slot, size_t index,
                            const unsigned char **out_bytes, size_t *out_len);
extern int bb_pub_insert_at (int slot, size_t index, size_t col,
                             const unsigned char *bytes, size_t len);
extern int bb_pub_delete_at (int slot, size_t index, size_t col, size_t n);
extern int bb_pub_set_dirty (int slot, int dirty);
extern int bb_pub_dirty (int slot);
extern int bb_pub_get_lines (int slot, size_t start, size_t count,
                             const unsigned char **out_bytes, size_t *out_lens);
extern int bb_pub_insert_lines (int slot, size_t index, size_t count,
                                const unsigned char *block, size_t start,
                                const size_t *ends);
extern int bb_pub_delete_lines (int slot, size_t index, size_t count);

#define BC_HANDLES_MAX 32
#define BC_RING_SIZE   16

/* One yank entry. Every line is stored followed by '\n' in one contiguous
   block, so `text` is a single write of the block and building an entry costs
   a fixed number of allocations however many lines it holds. ends[i] is the
   offset of line i's terminator; line i starts after line i-1's terminator.
   Lines may themselves contain '\n' or NUL bytes: lengths come from ends[],
   never from scanning. An entry with n_lines == 0 is empty. */
typedef struct {
    unsigned char *bytes;
    size_t        *ends;
    size_t         n_lines;
    size_t         size;       /* bytes in use, terminators included */
} bc_slot;

typedef struct {
    bc_slot slots[BC_RING_SIZE];
    int     head;              /* newest entry */
    int     active;            /* current paste/text entry in [0..fill) */
    int     fill;              /* how many slots populated (≤ ring size) */
} bc_state;

static bc_state *bc_handles[BC_HANDLES_MAX] = {0};

static int
bc_alloc_handle (bc_state *s)
{
    for (int i = 0; i < BC_HANDLES_MAX; i++) {
        if (!bc_handles[i]) { bc_handles[i] = s; return i; }
    }
    return -1;
}

/* Handles follow buf's number rules: nonnegative decimal, no empty string,
   trailing junk or overflow, so "" can never select handle 0. */
static int
bc_get_index (const char *s)
{
    char *end;
    errno = 0;
    long h = strtol (s, &end, 10);
    if (end == s || *end != '\0' || errno == ERANGE || h < 0 || h >= BC_HANDLES_MAX)
        return -1;
    return (int) h;
}

static bc_state *
bc_get (const char *s, const char *verb)
{
    int h = bc_get_index (s);
    bc_state *st = h < 0 ? NULL : bc_handles[h];
    if (!st) builtin_error ("%s: bad clip handle '%s'", verb, s);
    return st;
}

static int
bc_parse_long_arg (const char *s, const char *what, long min, long max, long *out)
{
    char *end = NULL;
    errno = 0;
    long v = strtol (s, &end, 10);
    if (s == end || *end != '\0' || errno == ERANGE || v < min || v > max) {
        builtin_error ("%s: invalid integer '%s'", what, s);
        return -1;
    }
    *out = v;
    return 0;
}

static int
bc_count_args (WORD_LIST *p)
{
    int n = 0;
    for (; p; p = p->next) n++;
    return n;
}

static void
bc_slot_clear (bc_slot *S)
{
    free (S->bytes); free (S->ends);
    S->bytes = NULL; S->ends = NULL; S->n_lines = 0; S->size = 0;
}

static const unsigned char *
bc_slot_line (const bc_slot *S, size_t i, size_t *len)
{
    size_t start = i ? S->ends[i - 1] + 1 : 0;
    *len = S->ends[i] - start;
    return S->bytes + start;
}

/* An entry under construction. Pieces are first resolved to (pointer, length)
   pairs so the block can be allocated once at its exact size; nothing is
   published to the ring until the whole command has succeeded. */
typedef struct {
    bc_slot              slot;
    const unsigned char **ptrs;
    size_t               cap;
} bc_build;

static int
bc_build_init (bc_build *B, size_t n_lines)
{
    memset (B, 0, sizeof *B);
    if (n_lines == 0) return 0;
    if (n_lines > SIZE_MAX / sizeof *B->ptrs) { errno = ENOMEM; return -1; }
    B->slot.ends = malloc (n_lines * sizeof *B->slot.ends);
    B->ptrs = malloc (n_lines * sizeof *B->ptrs);
    if (!B->slot.ends || !B->ptrs) {
        free (B->slot.ends); free (B->ptrs);
        B->slot.ends = NULL; B->ptrs = NULL;
        errno = ENOMEM;
        return -1;
    }
    B->cap = n_lines;
    return 0;
}

/* Record a piece; ends[] temporarily holds its length. */
static int
bc_build_add (bc_build *B, const unsigned char *bytes, size_t len)
{
    size_t i = B->slot.n_lines;
    if (i >= B->cap || len >= SIZE_MAX - B->slot.size) { errno = ENOMEM; return -1; }
    B->ptrs[i] = bytes;
    B->slot.ends[i] = len;
    B->slot.size += len + 1;
    B->slot.n_lines++;
    return 0;
}

/* Record COUNT whole buffer lines from START in one sequential walk. */
static int
bc_build_lines (bc_build *B, int buf_slot, size_t start, size_t count)
{
    size_t i = B->slot.n_lines;
    if (count > B->cap - i) { errno = ENOMEM; return -1; }
    if (count && bb_pub_get_lines (buf_slot, start, count,
                                   B->ptrs + i, B->slot.ends + i) < 0)
        return -1;
    for (size_t j = 0; j < count; j++) {
        size_t len = B->slot.ends[i + j];
        if (len >= SIZE_MAX - B->slot.size) { errno = ENOMEM; return -1; }
        B->slot.size += len + 1;
    }
    B->slot.n_lines += count;
    return 0;
}

/* Copy every recorded piece into one block. The source pointers are released
   before returning, so the caller may then mutate the buffer they came from. */
static int
bc_build_finish (bc_build *B)
{
    bc_slot *S = &B->slot;
    int rc = 0;
    if (S->n_lines) {
        S->bytes = malloc (S->size);
        if (!S->bytes) { errno = ENOMEM; rc = -1; }
        else {
            size_t off = 0;
            for (size_t i = 0; i < S->n_lines; i++) {
                size_t len = S->ends[i];
                if (len) memcpy (S->bytes + off, B->ptrs[i], len);
                off += len;
                S->bytes[off] = '\n';
                S->ends[i] = off++;
            }
        }
    }
    free (B->ptrs);
    B->ptrs = NULL;
    if (rc < 0) bc_slot_clear (S);
    return rc;
}

static void
bc_build_discard (bc_build *B)
{
    free (B->ptrs);
    B->ptrs = NULL;
    bc_slot_clear (&B->slot);
}

/* Publish a finished entry as the newest one: it fills the next free slot or,
   once the ring is full, replaces the oldest entry (the one after head),
   regardless of where yank-prev/yank-next left the active pointer. */
static void
bc_push (bc_state *s, bc_slot *entry)
{
    int next = (s->fill < BC_RING_SIZE) ? s->fill : (s->head + 1) % BC_RING_SIZE;
    if (s->fill < BC_RING_SIZE) s->fill++;
    bc_slot_clear (&s->slots[next]);
    s->slots[next] = *entry;
    memset (entry, 0, sizeof *entry);
    s->head = s->active = next;
}

/* ---- verb implementations ---- */

/* Avoid Bash's fatal readonly-assignment path before publishing a handle.
   builtin_bind_variable creates a shell variable for any string, including
   "" and "bad-name", so the caller must already have required a legal
   identifier. */
static int
bc_bind (const char *name, char *value)
{
    SHELL_VAR *v = find_variable (name);
    if (v && (readonly_p (v) || noassign_p (v))) {
        builtin_error ("%s: variable is not assignable", name);
        return -1;
    }
    v = builtin_bind_variable ((char *) name, value, 0);
    return !v || readonly_p (v) || noassign_p (v) ? -1 : 0;
}

static int
bc_new_cmd (WORD_LIST *args)
{
    const char *hvar = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-h") == 0 && p->next) { hvar = p->next->word->word; p = p->next; }
        else { builtin_error ("new: unexpected arg '%s'", w); return EX_USAGE; }
    }
    /* Reject before allocation. A bad destination must not consume a slot. */
    if (hvar && legal_identifier (hvar) == 0) {
        sh_invalidid (hvar);
        return EX_USAGE;
    }
    bc_state *s = calloc (1, sizeof (bc_state));
    if (!s) { builtin_error ("new: %s", strerror (ENOMEM)); return EXECUTION_FAILURE; }
    int slot = bc_alloc_handle (s);
    if (slot < 0) {
        free (s);
        builtin_error ("new: handle table full (%d slots)", BC_HANDLES_MAX);
        return EXECUTION_FAILURE;
    }
    char buf[16];
    snprintf (buf, sizeof buf, "%d", slot);
    int rc = EXECUTION_SUCCESS;
    if (hvar) {
        if (bc_bind (hvar, buf) < 0) rc = EXECUTION_FAILURE;
    } else {
        printf ("%s\n", buf);
        rc = sh_chkwrite (EXECUTION_SUCCESS);
    }
    if (rc != EXECUTION_SUCCESS) {
        bc_handles[slot] = NULL;
        free (s);
    }
    return rc;
}

static int
bc_buf_lines (const char *verb, int buf_slot)
{
    int n = bb_pub_n_lines (buf_slot);
    if (n < 0) builtin_error ("%s: buf slot %d invalid", verb, buf_slot);
    return n;
}

/* Byte range [FROM_L:FROM_C, TO_L:TO_C). The entry is copied first; the buffer
   is then changed by steps ordered so that only the first can fail, so a
   failure leaves both the buffer and the ring exactly as they were. */
static int
bc_byte_range (const char *verb, bc_state *s, int buf_slot, WORD_LIST *a, int do_delete)
{
    long from_l, from_c, to_l, to_c;
    if (bc_parse_long_arg (a->word->word, "FROM_LINE", 0, LONG_MAX, &from_l) < 0 ||
        bc_parse_long_arg (a->next->word->word, "FROM_COL", 0, LONG_MAX, &from_c) < 0 ||
        bc_parse_long_arg (a->next->next->word->word, "TO_LINE", 0, LONG_MAX, &to_l) < 0 ||
        bc_parse_long_arg (a->next->next->next->word->word, "TO_COL", 0, LONG_MAX, &to_c) < 0)
        return EX_USAGE;
    if (to_l < from_l || (to_l == from_l && to_c < from_c)) {
        builtin_error ("%s: invalid range", verb);
        return EX_USAGE;
    }
    int n = bc_buf_lines (verb, buf_slot);
    if (n < 0) return EX_USAGE;
    if (from_l >= n || to_l >= n) { builtin_error ("%s: range line out of bounds", verb); return EX_USAGE; }

    const unsigned char *first, *last;
    size_t first_len, last_len;
    if (bb_pub_get_line (buf_slot, (size_t) from_l, &first, &first_len) < 0 ||
        bb_pub_get_line (buf_slot, (size_t) to_l, &last, &last_len) < 0) {
        builtin_error ("%s: cannot read buf slot %d", verb, buf_slot);
        return EXECUTION_FAILURE;
    }
    if ((size_t) from_c > first_len || (size_t) to_c > last_len) {
        builtin_error ("%s: range column out of bounds", verb);
        return EX_USAGE;
    }

    bc_build B;
    if (bc_build_init (&B, (size_t) (to_l - from_l) + 1) < 0) goto alloc_error;
    if (from_l == to_l) {
        bc_build_add (&B, first + from_c, (size_t) (to_c - from_c));
    } else {
        if (bc_build_add (&B, first + from_c, first_len - (size_t) from_c) < 0 ||
            bc_build_lines (&B, buf_slot, (size_t) from_l + 1,
                            (size_t) (to_l - from_l - 1)) < 0 ||
            bc_build_add (&B, last, (size_t) to_c) < 0) {
            bc_build_discard (&B);
            builtin_error ("%s: cannot read buf slot %d", verb, buf_slot);
            return EXECUTION_FAILURE;
        }
    }
    if (bc_build_finish (&B) < 0) goto alloc_error;

    if (do_delete) {
        if (from_l == to_l) {
            if (to_c > from_c &&
                bb_pub_delete_at (buf_slot, (size_t) from_l, (size_t) from_c,
                                  (size_t) (to_c - from_c)) < 0)
                goto edit_error;
        } else {
            /* Append the last line's suffix to the first line, then drop
               the first line's old suffix and the following lines. After the
               append the buffer is realized and the first line is heap-owned,
               so the remaining deletions cannot fail. */
            if (bb_pub_insert_at (buf_slot, (size_t) from_l, first_len,
                                  last + to_c, last_len - (size_t) to_c) < 0)
                goto edit_error;
            if (bb_pub_delete_at (buf_slot, (size_t) from_l, (size_t) from_c,
                                  first_len - (size_t) from_c) < 0)
                goto edit_error;
            if (bb_pub_delete_lines (buf_slot, (size_t) from_l + 1,
                                     (size_t) (to_l - from_l)) < 0)
                goto edit_error;
        }
    }
    bc_push (s, &B.slot);
    return EXECUTION_SUCCESS;
edit_error:
    bc_build_discard (&B);
    builtin_error ("%s: cannot edit buf slot %d", verb, buf_slot);
    return EXECUTION_FAILURE;
alloc_error:
    bc_build_discard (&B);
    builtin_error ("%s: %s", verb, strerror (ENOMEM));
    return EXECUTION_FAILURE;
}

static int
bc_cut_or_copy (const char *verb, WORD_LIST *args, int do_delete, int range_mode)
{
    int argc = bc_count_args (args);
    if (range_mode ? (argc != 4 && argc != 6) : argc != 3) {
        builtin_error ("%s: needs HANDLE BUF_SLOT %s", verb,
                       range_mode ? "START END or FROM_L FROM_C TO_L TO_C" : "INDEX");
        return EX_USAGE;
    }
    bc_state *s = bc_get (args->word->word, verb);
    if (!s) return EX_USAGE;
    long buf_slot_l, start, end;
    if (bc_parse_long_arg (args->next->word->word, "BUF_SLOT", 0, INT_MAX, &buf_slot_l) < 0)
        return EX_USAGE;
    int buf_slot = (int) buf_slot_l;
    if (argc == 6)
        return bc_byte_range (verb, s, buf_slot, args->next->next, do_delete);
    if (bc_parse_long_arg (args->next->next->word->word, "INDEX", 0, LONG_MAX, &start) < 0)
        return EX_USAGE;
    if (range_mode) {
        if (bc_parse_long_arg (args->next->next->next->word->word, "END", 0, LONG_MAX, &end) < 0)
            return EX_USAGE;
        if (end < start) {
            builtin_error ("%s: invalid index range %ld..%ld", verb, start, end);
            return EX_USAGE;
        }
    }
    int n = bc_buf_lines (verb, buf_slot);
    if (n < 0) return EX_USAGE;
    if (start >= n) {
        builtin_error ("%s: line %ld out of range (%d lines)", verb, start, n);
        return EXECUTION_FAILURE;
    }
    /* One line. start is already below the line count, and that count fits
       in int, so start + 1 cannot overflow. Forming the endpoint earlier
       overflowed when INDEX was LONG_MAX. */
    if (!range_mode)
        end = start + 1;
    else if (end > n)
        end = n;

    bc_build B;
    if (bc_build_init (&B, (size_t) (end - start)) < 0) {
        builtin_error ("%s: %s", verb, strerror (ENOMEM));
        return EXECUTION_FAILURE;
    }
    if (bc_build_lines (&B, buf_slot, (size_t) start, (size_t) (end - start)) < 0) {
        bc_build_discard (&B);
        builtin_error ("%s: cannot read buf slot %d", verb, buf_slot);
        return EXECUTION_FAILURE;
    }
    if (bc_build_finish (&B) < 0) {
        builtin_error ("%s: %s", verb, strerror (ENOMEM));
        return EXECUTION_FAILURE;
    }
    /* One bulk deletion: it fails only when realizing a paged buffer
       fails, which leaves the buffer unchanged. */
    if (do_delete && end > start &&
        bb_pub_delete_lines (buf_slot, (size_t) start, (size_t) (end - start)) < 0) {
        bc_build_discard (&B);
        builtin_error ("%s: cannot delete lines %ld..%ld", verb, start, end);
        return EXECUTION_FAILURE;
    }
    bc_push (s, &B.slot);
    return EXECUTION_SUCCESS;
}

/* Remove lines [index, index+count) that a failed paste had inserted, and
   restore the dirty flag the paste found. */
static void
bc_unpaste (int buf_slot, size_t index, size_t count, int was_dirty)
{
    bb_pub_delete_lines (buf_slot, index, count);
    bb_pub_set_dirty (buf_slot, was_dirty);
}

static int
bc_paste_cmd (WORD_LIST *args)
{
    int argc = bc_count_args (args);
    if (argc != 3 && argc != 4) {
        builtin_error ("paste: HANDLE BUF_SLOT LINENO [COL]"); return EX_USAGE;
    }
    bc_state *s = bc_get (args->word->word, "paste");
    if (!s) return EX_USAGE;
    long buf_slot_l, index, col = -1;
    if (bc_parse_long_arg (args->next->word->word, "BUF_SLOT", 0, INT_MAX, &buf_slot_l) < 0 ||
        bc_parse_long_arg (args->next->next->word->word, "LINENO", 0, LONG_MAX, &index) < 0 ||
        (argc == 4 &&
         bc_parse_long_arg (args->next->next->next->word->word, "COL", 0, LONG_MAX, &col) < 0))
        return EX_USAGE;
    int buf_slot = (int) buf_slot_l;
    int n = bc_buf_lines ("paste", buf_slot);
    if (n < 0) return EX_USAGE;
    if (s->fill == 0) { builtin_error ("paste: yank ring is empty"); return EXECUTION_FAILURE; }
    const bc_slot *S = &s->slots[s->active];
    if (index > n || (col >= 0 && index >= n)) {
        builtin_error ("paste: line %ld out of range", index); return EX_USAGE;
    }
    size_t k = S->n_lines, len;
    int was_dirty = bb_pub_dirty (buf_slot);

    if (col < 0) {
        /* One all-or-nothing insertion of every piece. */
        if (k && bb_pub_insert_lines (buf_slot, (size_t) index, k, S->bytes, 0, S->ends) < 0) {
            builtin_error ("paste: insert failed at line %ld", index);
            return EXECUTION_FAILURE;
        }
        return EXECUTION_SUCCESS;
    }

    const unsigned char *line; size_t line_len;
    if (bb_pub_get_line (buf_slot, (size_t) index, &line, &line_len) < 0) {
        builtin_error ("paste: cannot read line %ld", index);
        return EXECUTION_FAILURE;
    }
    if ((size_t) col > line_len) { builtin_error ("paste: column %ld out of range", col); return EX_USAGE; }
    size_t first_len;
    const unsigned char *first = k ? bc_slot_line (S, 0, &first_len) : NULL;
    if (k == 0 || (k == 1 && first_len == 0)) return EXECUTION_SUCCESS;
    size_t at = (size_t) index, c = (size_t) col, tail_len = line_len - c;
    if (k > 1) {
        /* Pieces 1..k-1 become new lines in one insertion; the old tail is
           then appended to the last of them from the still-unmodified
           source line. */
        if (bb_pub_insert_lines (buf_slot, at + 1, k - 1, S->bytes,
                                 S->ends[0] + 1, S->ends + 1) < 0)
            goto insert_error;
        bc_slot_line (S, k - 1, &len);
        if (bb_pub_get_line (buf_slot, at, &line, &line_len) < 0 ||
            bb_pub_insert_at (buf_slot, at + k - 1, len, line + c, tail_len) < 0) {
            bc_unpaste (buf_slot, at + 1, k - 1, was_dirty);
            goto insert_error;
        }
    }
    /* prefix + first + tail; for k > 1 the tail then moves out. The insert
       leaves the line heap-owned, so trimming it cannot fail. */
    if (bb_pub_insert_at (buf_slot, at, c, first, first_len) < 0) {
        bc_unpaste (buf_slot, at + 1, k - 1, was_dirty);
        goto insert_error;
    }
    if (k > 1 && bb_pub_delete_at (buf_slot, at, c + first_len, tail_len) < 0) {
        builtin_error ("paste: cannot trim line %zu", at);
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
insert_error:
    builtin_error ("paste: insert failed at line %zu", at);
    return EXECUTION_FAILURE;
}

static int
bc_rotate (WORD_LIST *args, int delta)
{
    const char *verb = delta < 0 ? "yank-prev" : "yank-next";
    if (bc_count_args (args) != 1) { builtin_error ("%s: HANDLE", verb); return EX_USAGE; }
    bc_state *s = bc_get (args->word->word, verb);
    if (!s) return EX_USAGE;
    if (s->fill == 0) { builtin_error ("%s: yank ring is empty", verb); return EXECUTION_FAILURE; }
    s->active = (s->active + delta + s->fill) % s->fill;
    return EXECUTION_SUCCESS;
}

static int
bc_write_all (int fd, const unsigned char *bytes, size_t len)
{
    while (len) {
        ssize_t n = write (fd, bytes, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) { errno = EIO; return -1; }
        bytes += n;
        len -= (size_t) n;
    }
    return 0;
}

static int
bc_text_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("text: HANDLE [-F FD] [-N SLOT] [-X]"); return EX_USAGE; }
    bc_state *s = bc_get (args->word->word, "text");
    if (!s) return EX_USAGE;
    int hex_mode = 0;
    int out_fd = STDOUT_FILENO;
    int slot_index = -1;
    for (WORD_LIST *p = args->next; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-X") == 0) hex_mode = 1;
        else if (strcmp (w, "-F") == 0 && p->next) {
            long fd;
            if (bc_parse_long_arg (p->next->word->word, "FD", 0, INT_MAX, &fd) < 0)
                return EX_USAGE;
            out_fd = (int) fd;
            p = p->next;
        } else if (strcmp (w, "-N") == 0 && p->next) {
            long n;
            if (bc_parse_long_arg (p->next->word->word, "SLOT", 0, BC_RING_SIZE - 1, &n) < 0)
                return EX_USAGE;
            slot_index = (int) n;
            p = p->next;
        } else {
            builtin_error ("text: unexpected arg '%s'", w);
            return EX_USAGE;
        }
    }
    if (hex_mode && out_fd != STDOUT_FILENO) {
        builtin_error ("text: -X and -F are mutually exclusive");
        return EX_USAGE;
    }
    if (slot_index >= s->fill) {
        builtin_error ("text: slot %d is not in use", slot_index);
        return EXECUTION_FAILURE;
    }
    if (s->fill == 0) return EXECUTION_SUCCESS;  /* empty — print nothing */
    if (slot_index < 0) slot_index = s->active;
    const bc_slot *S = &s->slots[slot_index];
    if (hex_mode) {
        /* Lines joined by '\n' without the final terminator, then '\n'. */
        static const char d[] = "0123456789abcdef";
        char hex[8192];
        size_t total = S->size ? S->size - 1 : 0;
        for (size_t off = 0; off < total; ) {
            size_t n = total - off < sizeof hex / 2 ? total - off : sizeof hex / 2;
            for (size_t i = 0; i < n; i++) {
                hex[2*i] = d[S->bytes[off + i] >> 4];
                hex[2*i+1] = d[S->bytes[off + i] & 0xF];
            }
            fwrite (hex, 1, 2 * n, stdout);
            off += n;
        }
        putchar ('\n');
        return sh_chkwrite (EXECUTION_SUCCESS);
    }
    if (S->size && bc_write_all (out_fd, S->bytes, S->size) < 0) {
        builtin_error ("text: write: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bc_clear_cmd (WORD_LIST *args)
{
    if (bc_count_args (args) != 1) { builtin_error ("clear: HANDLE"); return EX_USAGE; }
    bc_state *s = bc_get (args->word->word, "clear");
    if (!s) return EX_USAGE;
    if (s->fill > 0) bc_slot_clear (&s->slots[s->active]);
    return EXECUTION_SUCCESS;
}

static int
bc_free_cmd (WORD_LIST *args)
{
    if (bc_count_args (args) != 1) { builtin_error ("free: HANDLE"); return EX_USAGE; }
    bc_state *s = bc_get (args->word->word, "free");
    if (!s) return EX_USAGE;
    for (int i = 0; i < BC_RING_SIZE; i++) bc_slot_clear (&s->slots[i]);
    bc_handles[bc_get_index (args->word->word)] = NULL;
    free (s);
    return EXECUTION_SUCCESS;
}

int
clip_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    if (!strcmp (cmd, "new"))         return bc_new_cmd (args);
    if (!strcmp (cmd, "cut-line"))    return bc_cut_or_copy (cmd, args, 1, 0);
    if (!strcmp (cmd, "copy-line"))   return bc_cut_or_copy (cmd, args, 0, 0);
    if (!strcmp (cmd, "cut-range"))   return bc_cut_or_copy (cmd, args, 1, 1);
    if (!strcmp (cmd, "copy-range"))  return bc_cut_or_copy (cmd, args, 0, 1);
    if (!strcmp (cmd, "paste"))       return bc_paste_cmd (args);
    if (!strcmp (cmd, "yank-prev"))   return bc_rotate (args, -1);
    if (!strcmp (cmd, "yank-next"))   return bc_rotate (args, +1);
    if (!strcmp (cmd, "text"))        return bc_text_cmd (args);
    if (!strcmp (cmd, "clear"))       return bc_clear_cmd (args);
    if (!strcmp (cmd, "free"))        return bc_free_cmd (args);
    builtin_error ("unknown verb: %s", cmd);
    return EX_USAGE;
}

char *clip_doc[] = {
    "Cut/copy/paste with 16-slot yank ring; operates on buf handles.",
    "",
    "    clip new [-h HVAR]",
    "    clip cut-line H BUF I            move line",
    "    clip copy-line H BUF I",
    "    clip cut-range H BUF START END",
    "    clip copy-range H BUF START END",
    "    clip cut-range H BUF FL FC TL TC  byte range [FL:FC, TL:TC)",
    "    clip copy-range H BUF FL FC TL TC",
    "    clip paste H BUF I [COL]          insert at line or byte column",
    "    clip yank-prev H                 rotate active back",
    "    clip yank-next H                 rotate active forward",
    "    clip text H [-F FD] [-N SLOT] [-X] print/dump slot",
    "    clip clear H                     empty active slot",
    "    clip free H                      release",
    "",
    "UTF-8 / NUL policy: clip operates on buf line byte arrays",
    "and inherits buf's byte-indexed, NUL-safe semantics. Lines with",
    "embedded NULs round-trip cut/copy/paste byte-exact via the in-memory",
    "ring; use `text -X` for hex transit when surfacing slot contents",
    "through a bash variable. Byte columns may split a UTF-8 sequence.",
    "",
    "Each cut/copy becomes the newest, active entry; a full ring replaces",
    "its oldest entry. A failed cut, copy or paste changes neither the",
    "buffer nor the ring.",
    (char *)NULL
};

struct builtin clip_struct = {
    "clip",
    clip_builtin,
    BUILTIN_ENABLED,
    clip_doc,
    "clip new|cut-line|copy-line|cut-range|copy-range|paste|yank-prev|yank-next|text|clear|free ARGS",
    0
};
