/* SPDX-License-Identifier: MIT */
/* clip.c — cut/copy/paste with 16-slot yank ring.
 *
 * Phase V V-3 of bash-os editor primitives. Operates on a buf
 * handle for cut + paste; copy doesn't touch the buffer. Each cut/copy
 * advances the active slot, so prior yanks rotate back via yank-prev.
 *
 * Verbs:
 *   clip new [-h HVAR]
 *       Allocate a fresh yank-ring state. Slot int → HVAR.
 *
 *   clip cut-line HANDLE BUF_SLOT INDEX
 *       Move line INDEX from buf BUF_SLOT into active yank slot,
 *       advancing the active pointer. The line is deleted from the
 *       buffer.
 *
 *   clip copy-line HANDLE BUF_SLOT INDEX
 *       Same as cut-line but doesn't remove from buffer.
 *
 *   clip cut-range HANDLE BUF_SLOT START END
 *       Move lines [START..END) into active slot, in order. Deletes them.
 *   clip cut-range HANDLE BUF_SLOT FROM_LINE FROM_COL TO_LINE TO_COL
 *       Move a byte range into the active slot, deleting it from BUF_SLOT.
 *
 *   clip copy-range HANDLE BUF_SLOT START END
 *       Same without delete.
 *   clip copy-range HANDLE BUF_SLOT FROM_LINE FROM_COL TO_LINE TO_COL
 *       Copy a byte range into the active slot without deleting it.
 *
 *   clip paste HANDLE BUF_SLOT INDEX [COL]
 *       Insert all lines from active slot at INDEX, or bytes at INDEX COL.
 *
 *   clip yank-prev HANDLE      rotate active back  (decrement)
 *   clip yank-next HANDLE      rotate active forward
 *
 *   clip text HANDLE [-F FD] [-N SLOT] [-X]
 *       Print/dump active slot, or slot SLOT. -X hex-encodes to stdout.
 *   clip clear HANDLE          empty active slot
 *   clip free HANDLE           release state + slot
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

#include "loadables.h"

/* ---- buf public C API ---- */
extern int bb_pub_n_lines (int slot);
extern int bb_pub_get_line (int slot, size_t index,
                            const unsigned char **out_bytes, size_t *out_len);
extern int bb_pub_insert_line (int slot, size_t index,
                               const unsigned char *bytes, size_t len);
extern int bb_pub_delete_line (int slot, size_t index);
extern int bb_pub_insert_at (int slot, size_t index, size_t col,
                             const unsigned char *bytes, size_t len);
extern int bb_pub_delete_at (int slot, size_t index, size_t col, size_t n);

#define BC_HANDLES_MAX 32
#define BC_RING_SIZE   16

typedef struct {
    unsigned char **lines;     /* malloc'd array of malloc'd byte buffers */
    size_t         *lengths;
    size_t          n_lines;
} bc_slot;

typedef struct {
    bc_slot slots[BC_RING_SIZE];
    int     active;            /* current write/paste slot in [0..fill) */
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

static bc_state *
bc_get (const char *s)
{
    char *end;
    long h = strtol (s, &end, 10);
    if (*end != '\0' || h < 0 || h >= BC_HANDLES_MAX) return NULL;
    return bc_handles[h];
}

static int
bc_get_index (const char *s)
{
    char *end;
    long h = strtol (s, &end, 10);
    if (*end != '\0' || h < 0 || h >= BC_HANDLES_MAX) return -1;
    return (int) h;
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

static void
bc_slot_clear (bc_slot *S)
{
    for (size_t i = 0; i < S->n_lines; i++) free (S->lines[i]);
    free (S->lines); free (S->lengths);
    S->lines = NULL; S->lengths = NULL; S->n_lines = 0;
}

static int
bc_slot_append (bc_slot *S, const unsigned char *bytes, size_t len)
{
    unsigned char *cp = malloc (len + 1);
    if (!cp) return -1;
    memcpy (cp, bytes, len); cp[len] = '\0';
    unsigned char **nl = realloc (S->lines, (S->n_lines + 1) * sizeof *nl);
    if (!nl) { free (cp); return -1; }
    S->lines = nl;
    size_t *nL = realloc (S->lengths, (S->n_lines + 1) * sizeof *nL);
    if (!nL) { free (cp); return -1; }
    S->lengths = nL;
    S->lines[S->n_lines] = cp;
    S->lengths[S->n_lines] = len;
    S->n_lines++;
    return 0;
}

static char *
bc_hex_encode (const unsigned char *data, size_t n)
{
    static const char d[] = "0123456789abcdef";
    char *out = malloc (2 * n + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < n; i++) {
        out[2*i] = d[data[i] >> 4];
        out[2*i+1] = d[data[i] & 0xF];
    }
    out[2*n] = '\0';
    return out;
}

/* ---- verb implementations ---- */

static int
bc_new_cmd (WORD_LIST *args)
{
    const char *hvar = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-h") == 0 && p->next) { hvar = p->next->word->word; p = p->next; }
        else { builtin_error ("new: unexpected arg '%s'", w); return EX_USAGE; }
    }
    bc_state *s = calloc (1, sizeof (bc_state));
    if (!s) { builtin_error ("calloc"); return EXECUTION_FAILURE; }
    int slot = bc_alloc_handle (s);
    if (slot < 0) { free (s); builtin_error ("handle table full"); return EXECUTION_FAILURE; }
    char buf[16];
    snprintf (buf, sizeof buf, "%d", slot);
    if (hvar) builtin_bind_variable ((char *) hvar, buf, 0);
    else      printf ("%s\n", buf);
    return EXECUTION_SUCCESS;
}

/* Advance to next ring slot, clearing it for new content. */
static void
bc_advance_slot (bc_state *s)
{
    int next = (s->fill < BC_RING_SIZE) ? s->fill : (s->active + 1) % BC_RING_SIZE;
    if (s->fill < BC_RING_SIZE) s->fill++;
    s->active = next;
    bc_slot_clear (&s->slots[s->active]);
}

static int
bc_cut_or_copy (WORD_LIST *args, int do_delete, int range_mode)
{
    if (!args || !args->next || !args->next->next ||
        (range_mode && !args->next->next->next)) {
        builtin_error ("needs HANDLE BUF_SLOT %s",
                       range_mode ? "START END or FROM_L FROM_C TO_L TO_C" : "INDEX");
        return EX_USAGE;
    }
    bc_state *s = bc_get (args->word->word);
    if (!s) { builtin_error ("bad handle"); return EX_USAGE; }
    long buf_slot_l, start, end;
    if (bc_parse_long_arg (args->next->word->word, "BUF_SLOT", 0, INT_MAX, &buf_slot_l) < 0 ||
        bc_parse_long_arg (args->next->next->word->word, "INDEX", 0, LONG_MAX, &start) < 0)
        return EX_USAGE;
    int buf_slot = (int) buf_slot_l;
    if (range_mode && args->next->next->next &&
        args->next->next->next->next && args->next->next->next->next->next) {
        long from_c, to_l, to_c;
        if (bc_parse_long_arg (args->next->next->next->word->word, "FROM_COL", 0, LONG_MAX, &from_c) < 0 ||
            bc_parse_long_arg (args->next->next->next->next->word->word, "TO_LINE", 0, LONG_MAX, &to_l) < 0 ||
            bc_parse_long_arg (args->next->next->next->next->next->word->word, "TO_COL", 0, LONG_MAX, &to_c) < 0)
            return EX_USAGE;
        long from_l = start;
        if (to_l < from_l || (to_l == from_l && to_c < from_c)) {
            builtin_error ("invalid range");
            return EX_USAGE;
        }
        int n = bb_pub_n_lines (buf_slot);
        if (n < 0) { builtin_error ("buf slot %d invalid", buf_slot); return EX_USAGE; }
        if (from_l >= n || to_l >= n) { builtin_error ("range line out of bounds"); return EX_USAGE; }

        const unsigned char *first, *last;
        size_t first_len, last_len;
        if (bb_pub_get_line (buf_slot, (size_t) from_l, &first, &first_len) < 0 ||
            bb_pub_get_line (buf_slot, (size_t) to_l, &last, &last_len) < 0)
            return EXECUTION_FAILURE;
        if ((size_t) from_c > first_len || (size_t) to_c > last_len) {
            builtin_error ("range column out of bounds");
            return EX_USAGE;
        }

        bc_advance_slot (s);
        if (from_l == to_l) {
            if (bc_slot_append (&s->slots[s->active],
                                first + from_c, (size_t) (to_c - from_c)) < 0)
                return EXECUTION_FAILURE;
            if (do_delete &&
                bb_pub_delete_at (buf_slot, (size_t) from_l, (size_t) from_c,
                                  (size_t) (to_c - from_c)) < 0)
                return EXECUTION_FAILURE;
            return EXECUTION_SUCCESS;
        }

        if (bc_slot_append (&s->slots[s->active],
                            first + from_c, first_len - (size_t) from_c) < 0)
            return EXECUTION_FAILURE;
        for (long i = from_l + 1; i < to_l; i++) {
            const unsigned char *bytes; size_t len;
            if (bb_pub_get_line (buf_slot, (size_t) i, &bytes, &len) < 0 ||
                bc_slot_append (&s->slots[s->active], bytes, len) < 0)
                return EXECUTION_FAILURE;
        }
        if (bc_slot_append (&s->slots[s->active], last, (size_t) to_c) < 0)
            return EXECUTION_FAILURE;

        if (do_delete) {
            size_t prefix_len = (size_t) from_c;
            size_t suffix_len = last_len - (size_t) to_c;
            unsigned char *joined = malloc (prefix_len + suffix_len + 1);
            if (!joined) return EXECUTION_FAILURE;
            memcpy (joined, first, prefix_len);
            memcpy (joined + prefix_len, last + to_c, suffix_len);
            joined[prefix_len + suffix_len] = '\0';
            for (long i = to_l; i >= from_l; i--) {
                if (bb_pub_delete_line (buf_slot, (size_t) i) < 0) {
                    free (joined);
                    return EXECUTION_FAILURE;
                }
            }
            if (bb_pub_insert_line (buf_slot, (size_t) from_l,
                                    joined, prefix_len + suffix_len) < 0) {
                free (joined);
                return EXECUTION_FAILURE;
            }
            free (joined);
        }
        return EXECUTION_SUCCESS;
    } else if (range_mode) {
        if (bc_parse_long_arg (args->next->next->next->word->word, "END", 0, LONG_MAX, &end) < 0)
            return EX_USAGE;
    } else {
        end = start + 1;
    }
    if (start < 0 || end < start) {
        builtin_error ("invalid index range %ld..%ld", start, end);
        return EX_USAGE;
    }
    int n = bb_pub_n_lines (buf_slot);
    if (n < 0) { builtin_error ("buf slot %d invalid", buf_slot); return EX_USAGE; }
    if (end > n) end = n;
    if (start >= n) return EXECUTION_FAILURE;

    bc_advance_slot (s);
    /* Copy into active slot first. */
    for (long i = start; i < end; i++) {
        const unsigned char *bytes; size_t len;
        if (bb_pub_get_line (buf_slot, (size_t) i, &bytes, &len) < 0) {
            builtin_error ("get_line %ld failed", i);
            return EXECUTION_FAILURE;
        }
        if (bc_slot_append (&s->slots[s->active], bytes, len) < 0) {
            builtin_error ("alloc");
            return EXECUTION_FAILURE;
        }
    }
    /* Then delete (in reverse so indexes stay valid). */
    if (do_delete) {
        for (long i = end - 1; i >= start; i--) {
            if (bb_pub_delete_line (buf_slot, (size_t) i) < 0) {
                builtin_error ("delete_line %ld failed", i);
                return EXECUTION_FAILURE;
            }
        }
    }
    return EXECUTION_SUCCESS;
}

static int
bc_paste_cmd (WORD_LIST *args)
{
    if (!args || !args->next || !args->next->next) {
        builtin_error ("paste: HANDLE BUF_SLOT LINENO [COL]"); return EX_USAGE;
    }
    bc_state *s = bc_get (args->word->word);
    if (!s) { builtin_error ("paste: bad handle"); return EX_USAGE; }
    long buf_slot_l, index;
    if (bc_parse_long_arg (args->next->word->word, "BUF_SLOT", 0, INT_MAX, &buf_slot_l) < 0 ||
        bc_parse_long_arg (args->next->next->word->word, "LINENO", 0, LONG_MAX, &index) < 0)
        return EX_USAGE;
    int buf_slot = (int) buf_slot_l;
    if (s->fill == 0) return EXECUTION_FAILURE;
    bc_slot *S = &s->slots[s->active];
    int n = bb_pub_n_lines (buf_slot);
    if (n < 0) { builtin_error ("paste: buf slot %d invalid", buf_slot); return EX_USAGE; }
    if (index < 0 || index > n) {
        builtin_error ("paste: index %ld out of range", index); return EX_USAGE;
    }
    if (args->next->next->next) {
        long col;
        if (bc_parse_long_arg (args->next->next->next->word->word, "COL", 0, LONG_MAX, &col) < 0)
            return EX_USAGE;
        if (index >= n) { builtin_error ("paste: line out of range"); return EX_USAGE; }
        const unsigned char *line; size_t line_len;
        if (bb_pub_get_line (buf_slot, (size_t) index, &line, &line_len) < 0)
            return EXECUTION_FAILURE;
        if ((size_t) col > line_len) { builtin_error ("paste: column out of range"); return EX_USAGE; }

        size_t tail_len = line_len - (size_t) col;
        unsigned char *tail = malloc (tail_len + 1);
        if (!tail) return EXECUTION_FAILURE;
        memcpy (tail, line + col, tail_len);
        tail[tail_len] = '\0';

        if (bb_pub_delete_at (buf_slot, (size_t) index, (size_t) col, tail_len) < 0) {
            free (tail);
            return EXECUTION_FAILURE;
        }
        if (S->n_lines > 0 &&
            bb_pub_insert_at (buf_slot, (size_t) index, (size_t) col,
                              S->lines[0], S->lengths[0]) < 0) {
            free (tail);
            return EXECUTION_FAILURE;
        }
        for (size_t i = 1; i < S->n_lines; i++) {
            if (bb_pub_insert_line (buf_slot, (size_t) index + i,
                                    S->lines[i], S->lengths[i]) < 0) {
                free (tail);
                return EXECUTION_FAILURE;
            }
        }
        size_t last_line = (size_t) index + (S->n_lines ? S->n_lines - 1 : 0);
        const unsigned char *last; size_t last_len;
        if (bb_pub_get_line (buf_slot, last_line, &last, &last_len) < 0 ||
            bb_pub_insert_at (buf_slot, last_line, last_len, tail, tail_len) < 0) {
            free (tail);
            return EXECUTION_FAILURE;
        }
        free (tail);
        return EXECUTION_SUCCESS;
    }
    /* Insert each line in order at successive positions. */
    for (size_t i = 0; i < S->n_lines; i++) {
        if (bb_pub_insert_line (buf_slot, (size_t) (index + (long) i),
                                S->lines[i], S->lengths[i]) < 0) {
            builtin_error ("paste: insert failed at %zu", i);
            return EXECUTION_FAILURE;
        }
    }
    return EXECUTION_SUCCESS;
}

static int
bc_rotate (WORD_LIST *args, int delta)
{
    if (!args) { builtin_error ("yank: HANDLE"); return EX_USAGE; }
    bc_state *s = bc_get (args->word->word);
    if (!s) { builtin_error ("yank: bad handle"); return EX_USAGE; }
    if (s->fill == 0) return EXECUTION_FAILURE;
    s->active = (s->active + delta + s->fill) % s->fill;
    return EXECUTION_SUCCESS;
}

static int
bc_text_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("text: HANDLE [-F FD] [-N SLOT] [-X]"); return EX_USAGE; }
    bc_state *s = bc_get (args->word->word);
    if (!s) { builtin_error ("text: bad handle"); return EX_USAGE; }
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
    if (s->fill == 0) return EXECUTION_SUCCESS;  /* empty — print nothing */
    if (slot_index < 0) slot_index = s->active;
    if (slot_index < 0 || slot_index >= s->fill) return EXECUTION_SUCCESS;
    bc_slot *S = &s->slots[slot_index];
    if (hex_mode) {
        size_t total = 0;
        for (size_t i = 0; i < S->n_lines; i++) {
            total += S->lengths[i];
            if (i + 1 < S->n_lines) total++;  /* \n separator */
        }
        unsigned char *all = malloc (total + 1);
        if (!all) { builtin_error ("text: alloc"); return EXECUTION_FAILURE; }
        size_t off = 0;
        for (size_t i = 0; i < S->n_lines; i++) {
            memcpy (all + off, S->lines[i], S->lengths[i]);
            off += S->lengths[i];
            if (i + 1 < S->n_lines) all[off++] = '\n';
        }
        char *hex = bc_hex_encode (all, total);
        if (hex) { fputs (hex, stdout); putchar ('\n'); free (hex); }
        free (all);
    } else {
        for (size_t i = 0; i < S->n_lines; i++) {
            size_t off = 0;
            while (off < S->lengths[i]) {
                ssize_t w = write (out_fd, S->lines[i] + off, S->lengths[i] - off);
                if (w < 0) {
                    if (errno == EINTR) continue;
                    builtin_error ("text: write: %s", strerror (errno));
                    return EXECUTION_FAILURE;
                }
                off += (size_t) w;
            }
            while (write (out_fd, "\n", 1) < 0) {
                if (errno == EINTR) continue;
                builtin_error ("text: write: %s", strerror (errno));
                return EXECUTION_FAILURE;
            }
        }
    }
    return EXECUTION_SUCCESS;
}

static int
bc_clear_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("clear: HANDLE"); return EX_USAGE; }
    bc_state *s = bc_get (args->word->word);
    if (!s) { builtin_error ("clear: bad handle"); return EX_USAGE; }
    if (s->fill > 0) bc_slot_clear (&s->slots[s->active]);
    return EXECUTION_SUCCESS;
}

static int
bc_free_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("free: HANDLE"); return EX_USAGE; }
    int idx = bc_get_index (args->word->word);
    if (idx < 0 || !bc_handles[idx]) return EX_USAGE;
    bc_state *s = bc_handles[idx];
    for (int i = 0; i < BC_RING_SIZE; i++) bc_slot_clear (&s->slots[i]);
    free (s);
    bc_handles[idx] = NULL;
    return EXECUTION_SUCCESS;
}

int
clip_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    if (!strcmp (cmd, "new"))         return bc_new_cmd (args);
    if (!strcmp (cmd, "cut-line"))    return bc_cut_or_copy (args, 1, 0);
    if (!strcmp (cmd, "copy-line"))   return bc_cut_or_copy (args, 0, 0);
    if (!strcmp (cmd, "cut-range"))   return bc_cut_or_copy (args, 1, 1);
    if (!strcmp (cmd, "copy-range"))  return bc_cut_or_copy (args, 0, 1);
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
    "through a bash variable.",
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
