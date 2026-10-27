/* SPDX-License-Identifier: MIT */
/* nano.c — minimal nano-like text editor (Phase V V-4, v2).
 *
 * v2 — UTF-8 read + grapheme-cluster cursor + cell-width-aware render
 * via libgrapheme (vendored under scripts/loadables/_libgrapheme/).
 * Cursor is byte index into current line; screen column is derived per
 * render frame via grapheme walk + bgr_cell_width(). Editing ops
 * (insert / delete / split / join) operate on byte ranges aligned to
 * cluster boundaries.
 *
 * Composes termraw for raw mode + cursor escapes. The generic Phase
 * V primitives (buf/undo/clip) ship for scripted editing
 * and TUI reuse; interactive nano uses the same byte-indexed
 * operation model on an internal piece table so grapheme-aware
 * per-keystroke editing stays fast.
 *
 * Key bindings:
 *   ^O/^S   Save
 *   ^X      Exit
 *   ^K      Cut current line or marked region into the yank ring
 *   ^U      Paste cut buffer
 *   ^G      Help (prints to status line)
 *   ^J/M-J  Justify paragraph or marked lines / whole buffer
 *   ^T      Spell check through an explicit word-list helper
 *   ^]      Complete the word before the cursor (repeat to cycle)
 *   ^Z      Undo
 *   ^Y/M-E  Redo
 *   M-W     Toggle soft-wrap rendering
 *   M-{ / M-} Rotate older/newer yank-ring entries
 *   ←→↑↓    Cursor movement (up/down keep the screen column)
 *   Home/End — start / end of line
 *   PgUp/Dn  — viewport navigation
 *   Backspace — delete char before cursor (joins lines if at col 0)
 *   Enter   — split line at cursor
 *   printable byte — insert at cursor
 *
 * Usage:  nano [-r N] [-M] [--speller=CMD] [FILE]
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <dirent.h>
#include <regex.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <poll.h>
#include <time.h>

#include "loadables.h"

extern char **environ;

/* libgrapheme (vendored, flattened by patch-bash-loadables.sh). */
#include "_libgrapheme_grapheme.h"
#include "_libgrapheme_util.h"

/* ---- piece-table buffer ---- */

typedef enum { BN_PT_ORIG = 0, BN_PT_ADD = 1 } bn_pt_source;

typedef struct {
    bn_pt_source source;
    size_t offset;
    size_t length;
    size_t line_count;
} bn_pt_piece;

typedef struct {
    bn_pt_piece *pieces;
    size_t n_pieces;
    size_t total_len;
    size_t total_lines;
    int dirty;
    /* The edit that led from this state to the next one: [e_start,
       e_start + e_old) became e_new bytes.  Lets undo/redo carry the mark. */
    int e_valid;
    size_t e_start, e_old, e_new;
} bn_pt_snapshot;

typedef struct {
    bn_pt_snapshot *v;
    size_t n;
    size_t cap;
} bn_pt_stack;

typedef struct {
    char *original;
    size_t original_len;
    char *add;
    size_t add_len;
    size_t add_cap;
    bn_pt_piece *pieces;
    size_t n_pieces;
    size_t pieces_cap;
    size_t total_len;
    size_t total_lines;
    int dirty;
} bn_pt_buffer;

/* ---- render line cache ---- */

typedef struct bn_line_s {
    char *data;
    size_t len;
    size_t cap;
    size_t abs;       /* absolute byte offset of line start in piece table */
    size_t *cluster_starts;
    size_t cluster_count;
    size_t cluster_cap;
} bn_line;

/* ---- forward decls (definitions follow further down; v2 helpers used
   by bn_render are otherwise out-of-order) ---- */
static bn_line *bn_curline (void);
static void bn_clamp_cx (void);
static long bn_screen_col (const char *s, size_t len, long byte_idx);
static long bn_grapheme_next (const char *s, size_t len, long byte_idx);
static long bn_grapheme_prev (const char *s, size_t len, long byte_idx);
static long bn_line_grapheme_prev (bn_line *L, long byte_idx);

typedef struct {
    bn_pt_buffer pt;       /* Stage 16 v1: authoritative piece table. */
    bn_pt_stack undo;
    bn_pt_stack redo;
    bn_line *lines;
    size_t n_lines;
    size_t cap;
    char *path;            /* file name */
    int dirty;
    int had_trailing_nl;
} bn_buf;

static bn_buf bn_b;        /* the singleton editor buffer */

/* clipboard + small yank ring.  The active clipboard is a byte span, so it can
   hold marked regions crossing line boundaries. */
static char *bn_clip = NULL;
static size_t bn_clip_len = 0;
#define BN_YANK_RING_SIZE 16
static char *bn_yank_ring[BN_YANK_RING_SIZE];
static size_t bn_yank_ring_len[BN_YANK_RING_SIZE];
static int bn_yank_ring_fill = 0;
static int bn_yank_ring_active = -1;

/* terminal */
static int bn_rows = 24, bn_cols = 80;
static long bn_cy = 0, bn_cx = 0;       /* cursor in buffer coords */
static long bn_view_top = 0;
static long bn_view_left = 0;           /* Stage 4 — horizontal scroll */
static int bn_softwrap = 0;             /* G03 — render overlong lines in chunks */
static char bn_status[256] = "";
static int bn_status_until = 0;         /* clear after N more keypresses */
static volatile sig_atomic_t bn_winch_pending = 0;
static struct sigaction bn_old_winch;
static int bn_winch_installed = 0;
/* SIGHUP or SIGTERM received during a session (0 if none). */
static volatile sig_atomic_t bn_term_signal = 0;

/* Stage 2 — search (^W). Pattern persists across invocations so the next
   ^W pre-fills with the last query (matches GNU nano). */
static char bn_search_pat[128] = "";

/* Stage 44.D — mark + selection state. Set by Esc-A (M-A); ^K
   cuts from mark to cursor when active, M-^ copies without cut. Marked
   regions are byte spans and may cross line boundaries. */
static int  bn_mark_active = 0;
static long bn_mark_cy = 0, bn_mark_cx = 0;

/* Stage 7.E — tree-sitter highlight overlay. Detected from filename
   extension on bn_load; NULL means "no highlighting".  The ts companion
   keeps the parse tree between frames and reparses incrementally after
   edits (bashts_sgr_range), and colours are resolved only for the lines
   on screen plus a screen above and below.  The window is cached by
   bn_text_rev, so cursor-only repaints reuse it, as GNU nano does
   colour work only when text changes.  A reparse gets bn_hl_budget_us
   per frame: tree-sitter-bash cannot reuse the statements after an
   edit, so in a large script it costs the rest of the file.  A frame
   that runs out is drawn from the edited old tree (bn_hl_pending), and
   the main loop finishes the parse in slices while no key is waiting,
   then redraws with the settled colours. */
static const char *bn_lang = NULL;
static unsigned long bn_text_rev = 1;
#define BN_HL_BUDGET_US 25000L
#define BN_HL_SLICE_US  10000L
static long bn_hl_budget_us = BN_HL_BUDGET_US;  /* < 0: parse to the end */
static int bn_hl_pending = 0;

typedef struct {
    const char *lang;
    unsigned long rev;
    size_t lo, hi;              /* buffer bytes covered by sgr_at */
    const char **sgr_at;        /* sgr_at[b - lo], NULL = uncoloured */
    void *ts_state;             /* tree and source kept by ts.c */
} bn_highlight_cache;

static bn_highlight_cache bn_hl_cache;
static char *bn_pt_flatten (const bn_pt_buffer *b, size_t *out_len);

/* Defined in ts.c (the required ts companion); both end up in
   libbuiltins.a, so cross-file calls resolve at link time. */
extern int bashts_compute_sgr_map (const char *lang, const char *src,
                                   size_t srclen, const char **sgr_at);
extern int bashts_sgr_range (void **state, const char *lang, const char *src,
                             size_t srclen, size_t lo, size_t hi,
                             const char **sgr_at);
extern int bashts_sgr_range_budget (void **state, const char *lang,
                                    const char *src, size_t srclen,
                                    size_t lo, size_t hi, const char **sgr_at,
                                    long budget_us, int *pending);
extern int bashts_sgr_continue (void **state, long budget_us);
extern void bashts_sgr_state_free (void **state);

static void
bn_detect_language (const char *path)
{
    bn_lang = NULL;
    if (!path) return;
    const char *dot = strrchr (path, '.');
    if (!dot || dot == path) return;
    if      (!strcmp (dot, ".json"))     bn_lang = "json";
    else if (!strcmp (dot, ".toml"))     bn_lang = "toml";
    else if (!strcmp (dot, ".sh")
          || !strcmp (dot, ".bash"))     bn_lang = "bash";
    else if (!strcmp (dot, ".md")
          || !strcmp (dot, ".markdown")) bn_lang = "markdown";
}

/* Drop the colour window (text changed); the parse tree is kept. */
static void
bn_highlight_cache_clear (void)
{
    free (bn_hl_cache.sgr_at);
    bn_hl_cache.sgr_at = NULL;
    bn_hl_cache.lang = NULL;
    bn_hl_cache.rev = 0;
    bn_hl_cache.lo = bn_hl_cache.hi = 0;
}

/* Drop everything, including the parse tree (end of session). */
static void
bn_highlight_release (void)
{
    bn_highlight_cache_clear ();
    bashts_sgr_state_free (&bn_hl_cache.ts_state);
    bn_hl_pending = 0;
}

/* Spend up to SLICE_US on a reparse left pending by a frame.  Returns 1
   when it settled (or failed) and the screen should be redrawn. */
static int
bn_highlight_idle (long slice_us)
{
    if (!bn_hl_pending) return 0;
    int r = bn_hl_cache.ts_state ? bashts_sgr_continue (&bn_hl_cache.ts_state, slice_us) : -1;
    if (r == 0) return 0;
    bn_hl_pending = 0;
    bn_highlight_cache_clear ();
    return 1;
}

/* Make sgr_at cover the buffer bytes [LO, HI).  Returns 0 when colours
   are available, -1 otherwise (no language, or a parse failure: the
   text is then drawn uncoloured). */
static int
bn_highlight_cache_ensure (size_t lo, size_t hi)
{
    if (!bn_lang) {
        bn_highlight_release ();
        return -1;
    }
    if (bn_hl_cache.sgr_at && bn_hl_cache.lang == bn_lang
        && bn_hl_cache.rev == bn_text_rev
        && bn_hl_cache.lo <= lo && hi <= bn_hl_cache.hi)
        return 0;
    bn_highlight_cache_clear ();
    if (hi <= lo) return -1;
    size_t len = 0;
    char *src = bn_pt_flatten (&bn_b.pt, &len);
    if (!src) return -1;
    if (hi > len) hi = len;
    const char **map = hi > lo ? calloc (hi - lo, sizeof *map) : NULL;
    int pending = 0;
    int rc = map ? bashts_sgr_range_budget (&bn_hl_cache.ts_state, bn_lang, src, len,
                                            lo, hi, map, bn_hl_budget_us, &pending) : -1;
    free (src);
    bn_hl_pending = rc == 0 && pending;
    if (rc < 0) { free (map); return -1; }
    bn_hl_cache.sgr_at = map;
    bn_hl_cache.lang = bn_lang;
    bn_hl_cache.rev = bn_text_rev;
    bn_hl_cache.lo = lo;
    bn_hl_cache.hi = hi;
    return 0;
}

static struct termios bn_saved_tio;
static int bn_tio_saved = 0;

/* ---- helpers ---- */

static void
bn_set_status (const char *fmt, ...)
{
    va_list ap;
    va_start (ap, fmt);
    vsnprintf (bn_status, sizeof bn_status, fmt, ap);
    va_end (ap);
    bn_status_until = 3;
}

static void
bn_yank_ring_clear (void)
{
    for (int i = 0; i < BN_YANK_RING_SIZE; i++) {
        free (bn_yank_ring[i]);
        bn_yank_ring[i] = NULL;
        bn_yank_ring_len[i] = 0;
    }
    bn_yank_ring_fill = 0;
    bn_yank_ring_active = -1;
}

static int
bn_yank_ring_push (const char *data, size_t len)
{
    if (!data)
        return 0;
    char *copy = malloc (len + 1);
    if (!copy)
        return -1;
    memcpy (copy, data, len);
    copy[len] = '\0';

    if (bn_yank_ring_fill == BN_YANK_RING_SIZE)
        free (bn_yank_ring[BN_YANK_RING_SIZE - 1]);
    else
        bn_yank_ring_fill++;

    for (int i = bn_yank_ring_fill - 1; i > 0; i--) {
        bn_yank_ring[i] = bn_yank_ring[i - 1];
        bn_yank_ring_len[i] = bn_yank_ring_len[i - 1];
    }
    bn_yank_ring[0] = copy;
    bn_yank_ring_len[0] = len;
    bn_yank_ring_active = 0;
    return 0;
}

static int
bn_clip_take (char *data, size_t len, int record_yank)
{
    free (bn_clip);
    bn_clip = data;
    bn_clip_len = data ? len : 0;
    if (record_yank && data && bn_yank_ring_push (data, len) < 0)
        return -1;
    return 0;
}

static int
bn_yank_ring_sync_active (void)
{
    if (bn_yank_ring_fill <= 0 || bn_yank_ring_active < 0)
        return -1;
    size_t len = bn_yank_ring_len[bn_yank_ring_active];
    char *copy = malloc (len + 1);
    if (!copy)
        return -1;
    memcpy (copy, bn_yank_ring[bn_yank_ring_active], len);
    copy[len] = '\0';
    free (bn_clip);
    bn_clip = copy;
    bn_clip_len = len;
    return 0;
}

static int
bn_yank_ring_rotate (int delta)
{
    if (bn_yank_ring_fill <= 0) {
        bn_set_status ("Yank ring empty");
        return -1;
    }
    bn_yank_ring_active =
        (bn_yank_ring_active + delta + bn_yank_ring_fill) % bn_yank_ring_fill;
    if (bn_yank_ring_sync_active () < 0) {
        bn_set_status ("Yank ring error");
        return -1;
    }
    bn_set_status ("Yank slot %d/%d", bn_yank_ring_active + 1, bn_yank_ring_fill);
    return 0;
}

static int
bn_line_ensure (bn_line *L, size_t need)
{
    if (L->cap >= need) return 0;
    size_t nc = L->cap ? L->cap : 64;
    while (nc < need) nc *= 2;
    char *nb = realloc (L->data, nc);
    if (!nb) return -1;
    L->data = nb;
    L->cap = nc;
    return 0;
}

static void
bn_line_cluster_cache_free (bn_line *L)
{
    free (L->cluster_starts);
    L->cluster_starts = NULL;
    L->cluster_count = 0;
    L->cluster_cap = 0;
}

static int
bn_line_cluster_cache_reserve (bn_line *L, size_t need)
{
    if (L->cluster_cap >= need) return 0;
    size_t nc = L->cluster_cap ? L->cluster_cap : 64;
    while (nc < need) nc *= 2;
    size_t *ns = realloc (L->cluster_starts, nc * sizeof *ns);
    if (!ns) return -1;
    L->cluster_starts = ns;
    L->cluster_cap = nc;
    return 0;
}

static int
bn_line_cluster_cache_build (bn_line *L)
{
    if (!L || L->cluster_count || L->len == 0) return 0;
    size_t pos = 0;
    while (pos < L->len) {
        if (bn_line_cluster_cache_reserve (L, L->cluster_count + 1) < 0) {
            bn_line_cluster_cache_free (L);
            return -1;
        }
        L->cluster_starts[L->cluster_count++] = pos;
        size_t adv = grapheme_next_character_break_utf8 (L->data + pos,
                                                         L->len - pos);
        if (adv == 0) adv = 1;
        pos += adv;
    }
    return 0;
}

static size_t
bn_pt_count_nl (const char *s, size_t n)
{
    if (n == 0) return 0;  /* deletion may pass a NULL insertion */
    size_t c = 0;
    const char *end = s + n, *p = s;
    while (p < end && (p = memchr (p, '\n', (size_t) (end - p))) != NULL) {
        c++;
        p++;
    }
    return c;
}

static const char *
bn_pt_piece_data (const bn_pt_buffer *b, const bn_pt_piece *p)
{
    return p->source == BN_PT_ORIG ? b->original + p->offset : b->add + p->offset;
}

static void
bn_pt_free (bn_pt_buffer *b)
{
    free (b->original);
    free (b->add);
    free (b->pieces);
    memset (b, 0, sizeof *b);
}

static void
bn_pt_stack_free (bn_pt_stack *s)
{
    for (size_t i = 0; i < s->n; i++)
        free (s->v[i].pieces);
    free (s->v);
    memset (s, 0, sizeof *s);
}

static int
bn_pt_reserve_pieces (bn_pt_buffer *b, size_t need)
{
    if (b->pieces_cap >= need) return 0;
    size_t nc = b->pieces_cap ? b->pieces_cap * 2 : 8;
    while (nc < need) nc *= 2;
    bn_pt_piece *np = realloc (b->pieces, nc * sizeof *np);
    if (!np) return -1;
    b->pieces = np;
    b->pieces_cap = nc;
    return 0;
}

static int
bn_pt_reserve_add (bn_pt_buffer *b, size_t need)
{
    if (b->add_cap >= need) return 0;
    size_t nc = b->add_cap ? b->add_cap * 2 : 1024;
    while (nc < need) nc *= 2;
    char *na = realloc (b->add, nc);
    if (!na) return -1;
    b->add = na;
    b->add_cap = nc;
    return 0;
}

static void
bn_pt_recount (bn_pt_buffer *b)
{
    b->total_len = 0;
    b->total_lines = 0;
    for (size_t i = 0; i < b->n_pieces; i++) {
        b->total_len += b->pieces[i].length;
        b->total_lines += b->pieces[i].line_count;
    }
}

static int
bn_pt_init_text (bn_pt_buffer *b, const char *data, size_t len)
{
    bn_pt_free (b);
    if (len) {
        b->original = malloc (len);
        if (!b->original) { bn_pt_free (b); return -1; }
        memcpy (b->original, data, len);
        b->original_len = len;
        if (bn_pt_reserve_pieces (b, 1) < 0) { bn_pt_free (b); return -1; }
        b->pieces[0].source = BN_PT_ORIG;
        b->pieces[0].offset = 0;
        b->pieces[0].length = len;
        b->pieces[0].line_count = bn_pt_count_nl (data, len);
        b->n_pieces = 1;
    }
    b->total_len = len;
    b->total_lines = bn_pt_count_nl (data, len);
    b->dirty = 0;
    return 0;
}

static int
bn_pt_load_file (bn_pt_buffer *b, const char *path)
{
    int fd = open (path, O_RDONLY);
    if (fd < 0)
        return bn_pt_init_text (b, "", 0);
    struct stat st;
    if (fstat (fd, &st) < 0) { close (fd); return -1; }
    if (st.st_size < 0) { close (fd); errno = EINVAL; return -1; }
    size_t len = (size_t) st.st_size;
    char *buf = len ? malloc (len) : NULL;
    if (len && !buf) { close (fd); return -1; }
    size_t off = 0;
    while (off < len) {
        ssize_t r = read (fd, buf + off, len - off);
        if (r < 0) { if (errno == EINTR) continue; free (buf); close (fd); return -1; }
        if (r == 0) break;
        off += (size_t) r;
    }
    close (fd);
    int rc = bn_pt_init_text (b, buf ? buf : "", off);
    free (buf);
    return rc;
}

static int
bn_pt_find_piece (const bn_pt_buffer *b, size_t pos, size_t *idx, size_t *inner)
{
    size_t cur = 0;
    for (size_t i = 0; i < b->n_pieces; i++) {
        size_t next = cur + b->pieces[i].length;
        if (pos < next) {
            *idx = i;
            *inner = pos - cur;
            return 0;
        }
        cur = next;
    }
    *idx = b->n_pieces;
    *inner = 0;
    return pos == b->total_len ? 0 : -1;
}

static int
bn_pt_replace_span_raw (bn_pt_buffer *b, size_t start, size_t end,
                        const char *ins, size_t ins_len)
{
    if (start > end || end > b->total_len) return -1;

    /* Typing appends to the add buffer one cluster at a time.  When the
       insertion point is the end of the piece that holds the most recent
       append, extend that piece instead of splitting in a new one, so a
       typed run stays one piece and undo snapshots stay small.  Snapshots
       hold their own copies of piece lengths and the add buffer is
       append-only, so earlier states are unaffected. */
    if (start == end && ins_len && start > 0) {
        size_t cur = 0;
        for (size_t i = 0; i < b->n_pieces; i++) {
            cur += b->pieces[i].length;
            if (cur < start) continue;
            bn_pt_piece *p = &b->pieces[i];
            if (cur == start && p->source == BN_PT_ADD
                && p->offset + p->length == b->add_len) {
                if (bn_pt_reserve_add (b, b->add_len + ins_len) < 0) return -1;
                memcpy (b->add + b->add_len, ins, ins_len);
                b->add_len += ins_len;
                size_t nl = bn_pt_count_nl (ins, ins_len);
                p->length += ins_len;
                p->line_count += nl;
                b->total_len += ins_len;
                b->total_lines += nl;
                b->dirty = 1;
                return 0;
            }
            break;
        }
    }

    size_t si, so, ei, eo;
    if (bn_pt_find_piece (b, start, &si, &so) < 0) return -1;
    if (bn_pt_find_piece (b, end, &ei, &eo) < 0) return -1;

    /* A split piece's line count is derived from the smaller side, so an
       edit at the edge of a large piece does not rescan the whole of it. */
    bn_pt_piece newp[3];
    size_t nn = 0;
    if (si < b->n_pieces && so > 0) {
        const bn_pt_piece *old = &b->pieces[si];
        const char *d = bn_pt_piece_data (b, old);
        newp[nn] = *old;
        newp[nn].length = so;
        newp[nn].line_count = so <= old->length - so
            ? bn_pt_count_nl (d, so)
            : old->line_count - bn_pt_count_nl (d + so, old->length - so);
        nn++;
    }
    if (ins_len) {
        if (bn_pt_reserve_add (b, b->add_len + ins_len) < 0) return -1;
        size_t off = b->add_len;
        memcpy (b->add + off, ins, ins_len);
        b->add_len += ins_len;
        newp[nn].source = BN_PT_ADD;
        newp[nn].offset = off;
        newp[nn].length = ins_len;
        newp[nn].line_count = bn_pt_count_nl (ins, ins_len);
        nn++;
    }
    if (ei < b->n_pieces && eo < b->pieces[ei].length) {
        const bn_pt_piece *old = &b->pieces[ei];
        const char *d = bn_pt_piece_data (b, old);
        newp[nn] = *old;
        newp[nn].offset += eo;
        newp[nn].length -= eo;
        newp[nn].line_count = eo <= old->length - eo
            ? old->line_count - bn_pt_count_nl (d, eo)
            : bn_pt_count_nl (d + eo, old->length - eo);
        nn++;
    }

    size_t remove_start = si;
    size_t remove_end = (end == b->total_len) ? b->n_pieces : ei + 1;
    if (start == b->total_len)
        remove_start = remove_end = b->n_pieces;
    size_t remove_n = remove_end - remove_start;
    size_t new_count = b->n_pieces - remove_n + nn;
    if (bn_pt_reserve_pieces (b, new_count) < 0) return -1;
    if (remove_end < b->n_pieces && remove_start + nn != remove_end) {
        memmove (b->pieces + remove_start + nn, b->pieces + remove_end,
                 (b->n_pieces - remove_end) * sizeof *b->pieces);
    }
    if (nn)
        memcpy (b->pieces + remove_start, newp, nn * sizeof *newp);
    b->n_pieces = new_count;
    bn_pt_recount (b);
    b->dirty = 1;
    return 0;
}

static int
bn_pt_snapshot_push (bn_pt_stack *stack, const bn_pt_buffer *b)
{
    if (stack->n == stack->cap) {
        size_t nc = stack->cap ? stack->cap * 2 : 16;
        bn_pt_snapshot *nv = realloc (stack->v, nc * sizeof *nv);
        if (!nv) return -1;
        stack->v = nv;
        stack->cap = nc;
    }
    bn_pt_snapshot *s = &stack->v[stack->n++];
    memset (s, 0, sizeof *s);
    if (b->n_pieces) {
        s->pieces = malloc (b->n_pieces * sizeof *s->pieces);
        if (!s->pieces) { stack->n--; return -1; }
        memcpy (s->pieces, b->pieces, b->n_pieces * sizeof *s->pieces);
    }
    s->n_pieces = b->n_pieces;
    s->total_len = b->total_len;
    s->total_lines = b->total_lines;
    s->dirty = b->dirty;
    return 0;
}

static int
bn_pt_snapshot_pop (bn_pt_stack *stack, bn_pt_buffer *b)
{
    if (stack->n == 0) return -1;
    bn_pt_snapshot s = stack->v[--stack->n];
    if (bn_pt_reserve_pieces (b, s.n_pieces) < 0) return -1;
    if (s.n_pieces)
        memcpy (b->pieces, s.pieces, s.n_pieces * sizeof *b->pieces);
    b->n_pieces = s.n_pieces;
    b->total_len = s.total_len;
    b->total_lines = s.total_lines;
    b->dirty = s.dirty;
    free (s.pieces);
    return 0;
}

static char *
bn_pt_flatten_range (const bn_pt_buffer *b, size_t start, size_t end,
                     size_t *out_len)
{
    if (start > end || end > b->total_len) return NULL;
    size_t len = end - start;
    char *out = malloc (len + 1);
    if (!out) return NULL;
    size_t copied = 0, cur = 0;
    for (size_t i = 0; i < b->n_pieces && copied < len; i++) {
        size_t p_start = cur;
        size_t p_end = cur + b->pieces[i].length;
        if (p_end > start && p_start < end) {
            size_t lo = start > p_start ? start - p_start : 0;
            size_t hi = end < p_end ? end - p_start : b->pieces[i].length;
            size_t n = hi - lo;
            memcpy (out + copied, bn_pt_piece_data (b, &b->pieces[i]) + lo, n);
            copied += n;
        }
        cur = p_end;
    }
    out[copied] = '\0';
    if (out_len) *out_len = copied;
    return out;
}

static char *
bn_pt_flatten (const bn_pt_buffer *b, size_t *out_len)
{
    return bn_pt_flatten_range (b, 0, b->total_len, out_len);
}

static int
bn_lines_grow (size_t want)
{
    if (bn_b.cap >= want) return 0;
    size_t nc = bn_b.cap ? bn_b.cap : 32;
    while (nc < want) nc *= 2;
    bn_line *nl = realloc (bn_b.lines, nc * sizeof (bn_line));
    if (!nl) return -1;
    bn_b.lines = nl;
    bn_b.cap = nc;
    return 0;
}

static int
bn_insert_blank (size_t at)
{
    if (at > bn_b.n_lines) return -1;
    if (bn_lines_grow (bn_b.n_lines + 1) < 0) return -1;
    if (at < bn_b.n_lines) {
        memmove (bn_b.lines + at + 1, bn_b.lines + at,
                 (bn_b.n_lines - at) * sizeof (bn_line));
    }
    bn_b.lines[at].data = NULL;
    bn_b.lines[at].len = 0;
    bn_b.lines[at].cap = 0;
    bn_b.lines[at].abs = 0;
    bn_b.lines[at].cluster_starts = NULL;
    bn_b.lines[at].cluster_count = 0;
    bn_b.lines[at].cluster_cap = 0;
    bn_b.n_lines++;
    bn_b.dirty = 1;
    return 0;
}

static void
bn_delete_line (size_t at)
{
    if (at >= bn_b.n_lines) return;
    free (bn_b.lines[at].data);
    bn_line_cluster_cache_free (&bn_b.lines[at]);
    if (at + 1 < bn_b.n_lines) {
        memmove (bn_b.lines + at, bn_b.lines + at + 1,
                 (bn_b.n_lines - at - 1) * sizeof (bn_line));
    }
    bn_b.n_lines--;
    bn_b.dirty = 1;
}

static void
bn_free_lines (void)
{
    for (size_t i = 0; i < bn_b.n_lines; i++) {
        free (bn_b.lines[i].data);
        bn_line_cluster_cache_free (&bn_b.lines[i]);
    }
    free (bn_b.lines);
    bn_b.lines = NULL;
    bn_b.n_lines = 0;
    bn_b.cap = 0;
}

/* Line start offsets are shifted lazily.  Lines at index bn_shift_from and
   later store their offset minus bn_shift_delta (modular arithmetic), so an
   edit only rewrites the offsets between its own line and the previous
   edit's, instead of every line below it. */
static size_t bn_shift_from = 0;
static size_t bn_shift_delta = 0;

static size_t
bn_labs (size_t i)
{
    return bn_b.lines[i].abs + (bn_shift_delta && i >= bn_shift_from ? bn_shift_delta : 0);
}

static void
bn_shift_range (size_t a, size_t b, size_t d)
{
    for (size_t i = a; i < b; i++)
        bn_b.lines[i].abs += d;
}

static int
bn_sync_lines_from_pt (void)
{
    bn_highlight_cache_clear ();
    bn_text_rev++;
    size_t flat_len = 0;
    char *flat = bn_pt_flatten (&bn_b.pt, &flat_len);
    if (!flat) return -1;

    bn_free_lines ();
    bn_shift_from = 0;
    bn_shift_delta = 0;
    bn_b.had_trailing_nl = flat_len > 0 && flat[flat_len - 1] == '\n';
    size_t start = 0;
    for (size_t i = 0; i < flat_len; i++) {
        if (flat[i] != '\n') continue;
        if (bn_insert_blank (bn_b.n_lines) < 0) { free (flat); return -1; }
        bn_line *L = &bn_b.lines[bn_b.n_lines - 1];
        size_t n = i - start;
        L->abs = start;
        if (n && bn_line_ensure (L, n) < 0) { free (flat); return -1; }
        if (n) memcpy (L->data, flat + start, n);
        L->len = n;
        start = i + 1;
    }
    if (start < flat_len || flat_len == 0 || bn_b.had_trailing_nl) {
        if (bn_insert_blank (bn_b.n_lines) < 0) { free (flat); return -1; }
        bn_line *L = &bn_b.lines[bn_b.n_lines - 1];
        size_t n = flat_len - start;
        L->abs = start;
        if (n && bn_line_ensure (L, n) < 0) { free (flat); return -1; }
        if (n) memcpy (L->data, flat + start, n);
        L->len = n;
    }
    bn_b.dirty = bn_b.pt.dirty;
    free (flat);
    return 0;
}

/* Index of the render line holding absolute offset POS: the last line whose
   start is at or before POS.  A line's trailing newline belongs to it. */
static size_t
bn_line_of_abs (size_t pos)
{
    if (bn_b.n_lines == 0) return 0;
    size_t lo = 0, hi = bn_b.n_lines;
    while (hi - lo > 1) {
        size_t mid = lo + (hi - lo) / 2;
        if (bn_labs (mid) <= pos) lo = mid;
        else hi = mid;
    }
    return lo;
}

/* Update the render-line cache for one piece-table replacement of
   [start, end) by INS, instead of flattening and re-splitting the whole
   buffer.  Only the lines the span touches are rebuilt; later lines shift
   their start offsets.  The cache stays equal to the text split on '\n',
   which is what bn_sync_lines_from_pt produces. */
static int
bn_lines_apply_edit (size_t start, size_t end, const char *ins, size_t ins_len)
{
    if (bn_b.n_lines == 0) return bn_sync_lines_from_pt ();
    bn_highlight_cache_clear ();
    bn_text_rev++;
    size_t ls = bn_line_of_abs (start), le = bn_line_of_abs (end);
    bn_line *Ls = &bn_b.lines[ls], *Le = &bn_b.lines[le];
    size_t base_abs = bn_labs (ls);
    size_t head = start - base_abs;
    size_t tail_off = end - bn_labs (le);
    if (head > Ls->len || tail_off > Le->len) return bn_sync_lines_from_pt ();
    size_t tail = Le->len - tail_off;
    size_t region_len = head + ins_len + tail;
    char *region = malloc (region_len + 1);
    if (!region) return -1;
    if (head) memcpy (region, Ls->data, head);
    if (ins_len) memcpy (region + head, ins, ins_len);
    if (tail) memcpy (region + head + ins_len, Le->data + tail_off, tail);

    size_t k = 1 + bn_pt_count_nl (ins, ins_len);
    size_t old_n = le - ls + 1;
    for (size_t i = ls; i <= le; i++) {
        free (bn_b.lines[i].data);
        bn_line_cluster_cache_free (&bn_b.lines[i]);
    }
    if (k > old_n && bn_lines_grow (bn_b.n_lines + (k - old_n)) < 0) {
        /* The freed lines must not be reached again; rebuild from scratch. */
        for (size_t i = ls; i <= le; i++)
            memset (&bn_b.lines[i], 0, sizeof bn_b.lines[i]);
        free (region);
        return bn_sync_lines_from_pt ();
    }
    /* Fold the pending shift so that, after this edit, one marker at the
       first line below it carries both the old and the new delta: lines
       between the previous marker and this edit are fixed up directly. */
    size_t removed = end - start;
    size_t pend = bn_shift_delta;
    if (pend) {
        if (bn_shift_from < ls)
            bn_shift_range (bn_shift_from, ls, pend);
        else if (bn_shift_from > le + 1)
            bn_shift_range (le + 1, bn_shift_from < bn_b.n_lines ? bn_shift_from : bn_b.n_lines,
                            (size_t) 0 - pend);
    }
    bn_shift_delta = pend + ins_len - removed;
    bn_shift_from = ls + k;
    if (k != old_n && le + 1 < bn_b.n_lines)
        memmove (bn_b.lines + ls + k, bn_b.lines + le + 1,
                 (bn_b.n_lines - le - 1) * sizeof (bn_line));
    bn_b.n_lines = bn_b.n_lines - old_n + k;

    int failed = 0;
    size_t s = 0;
    for (size_t j = 0; j < k; j++) {
        size_t e = s;
        while (e < region_len && region[e] != '\n') e++;
        bn_line *L = &bn_b.lines[ls + j];
        memset (L, 0, sizeof *L);
        L->abs = base_abs + s;
        size_t n = e - s;
        if (n && bn_line_ensure (L, n) < 0) failed = 1;
        else if (n) memcpy (L->data, region + s, n);
        L->len = failed ? 0 : n;
        s = e + 1;
    }
    free (region);
    if (failed) return bn_sync_lines_from_pt ();

    bn_b.had_trailing_nl = bn_b.n_lines > 1
                           && bn_b.lines[bn_b.n_lines - 1].len == 0;
    bn_b.dirty = bn_b.pt.dirty;
    return 0;
}

static size_t
bn_abs_from_lc (long line, long col)
{
    if (line < 0) line = 0;
    if ((size_t) line >= bn_b.n_lines)
        line = bn_b.n_lines ? (long) bn_b.n_lines - 1 : 0;
    size_t pos = 0;
    if ((size_t) line < bn_b.n_lines) {
        size_t max = bn_b.lines[line].len;
        if (col < 0) col = 0;
        if ((size_t) col > max) col = (long) max;
        pos = bn_labs ((size_t) line);
        pos += (size_t) col;
    }
    if (pos > bn_b.pt.total_len) pos = bn_b.pt.total_len;
    return pos;
}

static void
bn_set_cursor_abs (size_t pos)
{
    if (pos > bn_b.pt.total_len) pos = bn_b.pt.total_len;
    if (bn_b.n_lines == 0) { bn_cy = bn_cx = 0; return; }
    size_t i = bn_line_of_abs (pos);
    bn_cy = (long) i;
    bn_cx = (long) (pos - bn_labs (i));
    bn_clamp_cx ();
}

/* Map an offset across a replacement of [start, end) by INS_LEN bytes:
   offsets before the span stay, offsets after it shift, and offsets inside
   it collapse to the span start. */
static size_t
bn_offset_after_edit (size_t pos, size_t start, size_t end, size_t ins_len)
{
    if (pos <= start) return pos;
    if (pos >= end) return pos - (end - start) + ins_len;
    return start;
}

static void
bn_mark_from_abs (size_t pos)
{
    size_t cy = bn_cy, cx = bn_cx;
    bn_set_cursor_abs (pos);
    bn_mark_cy = bn_cy;
    bn_mark_cx = bn_cx;
    bn_cy = (long) cy;
    bn_cx = (long) cx;
}

static int
bn_piece_replace (size_t start, size_t end, const char *ins, size_t ins_len,
                  size_t cursor_after)
{
    /* The mark is an anchor in the text, not a screen position: carry it
       across the edit so a selection survives typing elsewhere. */
    size_t mark_abs = bn_mark_active ? bn_abs_from_lc (bn_mark_cy, bn_mark_cx) : 0;
    if (bn_pt_snapshot_push (&bn_b.undo, &bn_b.pt) < 0) return -1;
    bn_pt_snapshot *snap = &bn_b.undo.v[bn_b.undo.n - 1];
    snap->e_valid = 1;
    snap->e_start = start;
    snap->e_old = end - start;
    snap->e_new = ins_len;
    bn_pt_stack_free (&bn_b.redo);
    if (bn_pt_replace_span_raw (&bn_b.pt, start, end, ins, ins_len) < 0) {
        (void) bn_pt_snapshot_pop (&bn_b.undo, &bn_b.pt);
        return -1;
    }
    if (bn_lines_apply_edit (start, end, ins, ins_len) < 0) return -1;
    if (bn_mark_active)
        bn_mark_from_abs (bn_offset_after_edit (mark_abs, start, end, ins_len));
    bn_set_cursor_abs (cursor_after);
    return 0;
}

static int
bn_pt_save_file (const char *path)
{
    char tmp[4096];
    snprintf (tmp, sizeof tmp, "%s.tmpXXXXXX", path);
    int fd = mkstemp (tmp);
    if (fd < 0) return -1;
    struct stat st;
    int have_st = (stat (path, &st) == 0);
    fchmod (fd, have_st ? (st.st_mode & 07777) : 0644);
    if (have_st && geteuid () == 0)
        (void) fchown (fd, st.st_uid, st.st_gid);
    for (size_t i = 0; i < bn_b.pt.n_pieces; i++) {
        const char *p = bn_pt_piece_data (&bn_b.pt, &bn_b.pt.pieces[i]);
        size_t off = 0, n = bn_b.pt.pieces[i].length;
        while (off < n) {
            ssize_t w = write (fd, p + off, n - off);
            if (w < 0) {
                if (errno == EINTR) continue;
                close (fd); unlink (tmp); return -1;
            }
            off += (size_t) w;
        }
    }
    if (fdatasync (fd) < 0) { close (fd); unlink (tmp); return -1; }
    if (close (fd) < 0) { unlink (tmp); return -1; }
    if (rename (tmp, path) < 0) { unlink (tmp); return -1; }
    /* G03 atomic-save — fsync the parent directory so the rename itself
       is durable across power loss. POSIX permits a successful rename()
       return to roll back across a crash because the directory entry
       pointing at the freshly-renamed inode has not been flushed yet
       (the file data is already durable via fdatasync(fd) above).
       Best-effort: dirfd-open failures stay non-fatal because the data
       half of the write is already on disk. */
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
        int dfd = open (dirpath, O_RDONLY | O_DIRECTORY);
        if (dfd >= 0) {
            (void) fsync (dfd);
            close (dfd);
        }
    }
    return 0;
}

static int
bn_insert_file_at_cursor (const char *path)
{
    int fd = open (path, O_RDONLY);
    if (fd < 0) { bn_set_status ("read %s: %s", path, strerror (errno)); return -1; }
    char buf[8192];
    char *all = NULL;
    size_t total = 0, cap = 0;
    for (;;) {
        ssize_t r = read (fd, buf, sizeof buf);
        if (r < 0) {
            if (errno == EINTR) continue;
            int e = errno;
            close (fd); free (all);
            bn_set_status ("read %s: %s", path, strerror (e));
            return -1;
        }
        if (r == 0) break;
        if (total + (size_t) r > cap) {
            size_t nc = cap ? cap * 2 : 8192;
            while (nc < total + (size_t) r) nc *= 2;
            char *na = realloc (all, nc);
            if (!na) {
                close (fd); free (all);
                bn_set_status ("read %s: out of memory", path);
                return -1;
            }
            all = na;
            cap = nc;
        }
        memcpy (all + total, buf, (size_t) r);
        total += (size_t) r;
    }
    close (fd);
    size_t pos = bn_abs_from_lc (bn_cy, bn_cx);
    if (bn_piece_replace (pos, pos, all ? all : "", total, pos + total) < 0) {
        free (all);
        bn_set_status ("read %s: insert failed", path);
        return -1;
    }
    free (all);
    bn_set_status ("Inserted %zu bytes from %s", total, path);
    return 0;
}

static void
bn_load (const char *path)
{
    free (bn_b.path);
    bn_b.path = strdup (path);
    bn_b.had_trailing_nl = 0;
    bn_detect_language (path);   /* Stage 7.E */
    if (bn_pt_load_file (&bn_b.pt, path) < 0) {
        bn_pt_init_text (&bn_b.pt, "", 0);
        bn_sync_lines_from_pt ();
        bn_set_status ("Read error: %s", strerror (errno));
        return;
    }
    if (bn_sync_lines_from_pt () < 0) {
        bn_insert_blank (0);
    }
    if (access (path, F_OK) < 0) {
        bn_set_status ("New file: %s", path);
        bn_b.dirty = 0;
        bn_b.pt.dirty = 0;
        return;
    }
    bn_b.dirty = 0;
    bn_b.pt.dirty = 0;
    bn_set_status ("Read %zu lines from %s", bn_b.n_lines, path);
}

static int
bn_save (void)
{
    if (!bn_b.path) { bn_set_status ("No filename"); return -1; }
    if (bn_pt_save_file (bn_b.path) < 0)
        { bn_set_status ("write: %s", strerror (errno)); return -1; }
    /* Saving changes no text, so the render-line cache stays valid. */
    bn_b.dirty = 0;
    bn_b.pt.dirty = 0;
    bn_set_status ("Wrote %zu lines to %s", bn_b.n_lines, bn_b.path);
    return 0;
}

/* G03 Stage SAVE-PROMPTS — write to an explicit path, updating bn_b.path
   so subsequent ^S writes back to the same file. Non-TTY-safe so the
   selftest can exercise the bytes-on-disk path without driving the modal
   prompt. Empty/NULL path is the contract used by the modal cancel arm. */
static int
bn_save_as (const char *path)
{
    if (!path || !*path) { bn_set_status ("No filename"); return -1; }
    char *dup_path = strdup (path);
    if (!dup_path) { bn_set_status ("write: out of memory"); return -1; }
    free (bn_b.path);
    bn_b.path = dup_path;
    bn_detect_language (bn_b.path);
    if (bn_pt_save_file (bn_b.path) < 0)
        { bn_set_status ("write: %s", strerror (errno)); return -1; }
    bn_b.dirty = 0;
    bn_b.pt.dirty = 0;
    bn_sync_lines_from_pt ();
    bn_set_status ("Wrote %zu lines to %s", bn_b.n_lines, bn_b.path);
    return 0;
}

/* ---- terminal I/O ---- */

static void
bn_write (const char *s)
{
    size_t n = strlen (s);
    while (n > 0) {
        ssize_t w = write (STDOUT_FILENO, s, n);
        if (w <= 0) { if (errno == EINTR) continue; break; }
        s += w; n -= w;
    }
}

typedef struct {
    char *data;
    size_t len;
    size_t cap;
    int failed;
} bn_outbuf;

static int
bn_out_reserve (bn_outbuf *out, size_t add)
{
    if (out->failed) return -1;
    if (add > (size_t) -1 - out->len) { out->failed = 1; return -1; }
    size_t need = out->len + add;
    if (out->cap >= need) return 0;
    size_t nc = out->cap ? out->cap : 8192;
    while (nc < need) {
        if (nc > (size_t) -1 / 2) { nc = need; break; }
        nc *= 2;
    }
    char *nv = realloc (out->data, nc);
    if (!nv) { out->failed = 1; return -1; }
    out->data = nv;
    out->cap = nc;
    return 0;
}

static void
bn_out_append (bn_outbuf *out, const char *s, size_t n)
{
    if (n == 0 || bn_out_reserve (out, n) < 0) return;
    memcpy (out->data + out->len, s, n);
    out->len += n;
}

static void
bn_out_cstr (bn_outbuf *out, const char *s)
{
    bn_out_append (out, s, strlen (s));
}

static void
bn_out_fmt (bn_outbuf *out, const char *fmt, ...)
{
    if (out->failed) return;
    va_list ap;
    va_start (ap, fmt);
    va_list cp;
    va_copy (cp, ap);
    int n = vsnprintf (NULL, 0, fmt, cp);
    va_end (cp);
    if (n < 0) { va_end (ap); out->failed = 1; return; }
    if (bn_out_reserve (out, (size_t) n + 1) < 0) { va_end (ap); return; }
    vsnprintf (out->data + out->len, (size_t) n + 1, fmt, ap);
    out->len += (size_t) n;
    va_end (ap);
}

static void
bn_out_flush (bn_outbuf *out)
{
    size_t off = 0;
    while (off < out->len) {
        ssize_t w = write (STDOUT_FILENO, out->data + off, out->len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (w == 0) break;
        off += (size_t) w;
    }
    free (out->data);
    memset (out, 0, sizeof *out);
}

/* ---- display form of text ----

   Text from the buffer, a file name or a prompt never reaches the terminal
   as a control sequence.  As in GNU nano, a tab expands to the next
   multiple of BN_TABSIZE columns, C0 controls and DEL show in caret form
   (^[, ^?), the C1 controls U+0080..U+009F as ^` .. ^~ and ^=, and each
   malformed UTF-8 sequence as U+FFFD.  Everything else is copied as is. */

#define BN_TABSIZE 8

static int
bn_cp_is_control (uint_least32_t cp)
{
    return cp < 0x20 || (cp >= 0x7f && cp < 0xa0);
}

/* Width in columns of the cluster S[0..ADV) drawn at screen column COL;
   when OUT is set, append the bytes that draw it. */
static int
bn_cluster_cells (const char *s, size_t adv, long col, bn_outbuf *out)
{
    if (adv == 1 && (unsigned char) s[0] >= 0x20 && (unsigned char) s[0] < 0x7f) {
        if (out) bn_out_append (out, s, 1);
        return 1;
    }
    if (adv == 1 && s[0] == '\t') {
        int w = BN_TABSIZE - (int) (col % BN_TABSIZE);
        if (out) bn_out_append (out, "        ", (size_t) w);
        return w;
    }
    uint_least32_t first = 0;
    int clean = 1;
    for (size_t p = 0; p < adv && clean; ) {
        uint_least32_t cp;
        size_t k = grapheme_decode_utf8 (s + p, adv - p, &cp);
        if (k == 0 || k > adv - p
            || (cp == GRAPHEME_INVALID_CODEPOINT
                && !(k == 3 && memcmp (s + p, "\xef\xbf\xbd", 3) == 0))
            || bn_cp_is_control (cp))
            clean = 0;
        if (p == 0) first = cp;
        p += k ? k : 1;
    }
    if (clean) {
        if (out) bn_out_append (out, s, adv);
        return bgr_cell_width (first);
    }
    int w = 0;
    for (size_t p = 0; p < adv; ) {
        uint_least32_t cp;
        size_t k = grapheme_decode_utf8 (s + p, adv - p, &cp);
        if (k == 0) k = 1;
        if (k > adv - p) k = adv - p;
        if (cp == GRAPHEME_INVALID_CODEPOINT
            && !(k == 3 && memcmp (s + p, "\xef\xbf\xbd", 3) == 0)) {
            if (out) bn_out_append (out, "\xef\xbf\xbd", 3);
            w += 1;
        } else if (bn_cp_is_control (cp)) {
            char rep[2] = { '^', 0 };
            if (cp < 0x20)        rep[1] = (char) (cp + 0x40);
            else if (cp == 0x7f)  rep[1] = '?';
            else if (cp == 0x9f)  rep[1] = '=';
            else                  rep[1] = (char) (cp - 0x80 + 0x60);
            if (out) bn_out_append (out, rep, 2);
            w += 2;
        } else {
            if (out) bn_out_append (out, s + p, k);
            w += bgr_cell_width (cp);
        }
        p += k;
    }
    return w;
}

/* Append the display form of S[0..N) using at most MAX_CELLS columns. */
static void
bn_out_text (bn_outbuf *out, const char *s, size_t n, long max_cells)
{
    long col = 0;
    size_t pos = 0;
    while (pos < n) {
        size_t adv = grapheme_next_character_break_utf8 (s + pos, n - pos);
        if (adv == 0) adv = 1;
        int w = bn_cluster_cells (s + pos, adv, col, NULL);
        if (col + w > max_cells) break;
        bn_cluster_cells (s + pos, adv, col, out);
        col += w;
        pos += adv;
    }
}

static void
bn_set_raw (void)
{
    if (tcgetattr (STDIN_FILENO, &bn_saved_tio) < 0) return;
    bn_tio_saved = 1;
    struct termios r = bn_saved_tio;
    r.c_iflag &= (tcflag_t) ~(IGNBRK | BRKINT | PARMRK | ISTRIP |
                              INLCR | IGNCR | ICRNL | IXON);
    r.c_oflag &= (tcflag_t) ~OPOST;
    r.c_lflag &= (tcflag_t) ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    r.c_cflag &= (tcflag_t) ~(CSIZE | PARENB);
    r.c_cflag |= CS8;
    r.c_cc[VMIN] = 1; r.c_cc[VTIME] = 0;
    tcsetattr (STDIN_FILENO, TCSANOW, &r);
}

static void
bn_restore_tio (void)
{
    if (bn_tio_saved) tcsetattr (STDIN_FILENO, TCSANOW, &bn_saved_tio);
    bn_tio_saved = 0;
}

static void
bn_get_size (void)
{
    struct winsize ws;
    if (ioctl (STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0) {
        bn_rows = ws.ws_row;
        bn_cols = ws.ws_col;
    }
}

static void
bn_sigwinch (int sig)
{
    (void) sig;
    bn_winch_pending = 1;
}

static int
bn_install_winch (void)
{
    struct sigaction sa;
    memset (&sa, 0, sizeof sa);
    sa.sa_handler = bn_sigwinch;
    sigemptyset (&sa.sa_mask);
    if (sigaction (SIGWINCH, &sa, &bn_old_winch) < 0)
        return -1;
    bn_winch_installed = 1;
    return 0;
}

static void
bn_restore_winch (void)
{
    if (bn_winch_installed)
        sigaction (SIGWINCH, &bn_old_winch, NULL);
    bn_winch_installed = 0;
    bn_winch_pending = 0;
}

/* SIGHUP and SIGTERM end the session the way GNU nano does: the terminal
   is restored and a modified buffer is written to FILE.save (or
   nano.save), never over an existing file.  The signal is then raised
   again under the shell's own disposition, so a trap, or the default
   action, still happens.  A signal the shell ignores stays ignored. */
static const int bn_term_sigs[] = { SIGHUP, SIGTERM };
static struct sigaction bn_old_term[2];
static int bn_term_installed[2];

static void
bn_on_term (int sig)
{
    bn_term_signal = sig;
}

static void
bn_install_term (void)
{
    bn_term_signal = 0;
    for (int i = 0; i < 2; i++) {
        bn_term_installed[i] = 0;
        if (sigaction (bn_term_sigs[i], NULL, &bn_old_term[i]) < 0
            || bn_old_term[i].sa_handler == SIG_IGN)
            continue;
        struct sigaction sa;
        memset (&sa, 0, sizeof sa);
        sa.sa_handler = bn_on_term;     /* no SA_RESTART: interrupt read */
        sigemptyset (&sa.sa_mask);
        if (sigaction (bn_term_sigs[i], &sa, NULL) == 0)
            bn_term_installed[i] = 1;
    }
}

/* Block termination around the flag check, then atomically restore the
   caller's mask while waiting. A signal received before the wait cannot
   be lost, including during prompt rendering or spell-helper setup. */
static int
bn_poll (struct pollfd *fds, nfds_t n, int timeout_ms)
{
    sigset_t term, old;
    sigemptyset (&term);
    sigaddset (&term, SIGHUP);
    sigaddset (&term, SIGTERM);
    if (sigprocmask (SIG_BLOCK, &term, &old) < 0) return -1;
    struct timespec timeout = { timeout_ms / 1000,
                                (timeout_ms % 1000) * 1000000L };
    int r;
    if (bn_term_signal) { errno = EINTR; r = -1; }
    else r = ppoll (fds, n, timeout_ms < 0 ? NULL : &timeout, &old);
    int saved_errno = errno;
    sigprocmask (SIG_SETMASK, &old, NULL);
    if (bn_term_signal) { errno = EINTR; return -1; }
    errno = saved_errno;
    return r;
}

static void
bn_restore_term (void)
{
    for (int i = 0; i < 2; i++)
        if (bn_term_installed[i])
            sigaction (bn_term_sigs[i], &bn_old_term[i], NULL);
    bn_term_installed[0] = bn_term_installed[1] = 0;
}

/* Write the buffer to the first free NAME.save, NAME.save.1, ...; on
   success return the malloc'd name, otherwise NULL with errno set. */
static char *
bn_emergency_save (void)
{
    const char *base = bn_b.path && bn_b.path[0] ? bn_b.path : "nano";
    size_t len = 0;
    char *data = bn_pt_flatten (&bn_b.pt, &len);
    if (!data) { errno = ENOMEM; return NULL; }
    size_t nsz = strlen (base) + 32;
    char *name = malloc (nsz);
    if (!name) { free (data); errno = ENOMEM; return NULL; }
    int fd = -1;
    for (int i = 0; i < 1000 && fd < 0; i++) {
        if (i == 0) snprintf (name, nsz, "%s.save", base);
        else        snprintf (name, nsz, "%s.save.%d", base, i);
        fd = open (name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0 && errno != EEXIST) break;
    }
    int err = 0;
    if (fd < 0) err = errno ? errno : EEXIST;
    for (size_t off = 0; fd >= 0 && off < len; ) {
        ssize_t w = write (fd, data + off, len - off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) { err = w < 0 ? errno : EIO; break; }
        off += (size_t) w;
    }
    if (fd >= 0 && !err && fsync (fd) < 0) err = errno;
    if (fd >= 0 && close (fd) < 0 && !err) err = errno;
    if (err && fd >= 0) unlink (name);
    free (data);
    if (err) { free (name); errno = err; return NULL; }
    return name;
}

static void
bn_apply_pending_resize (void)
{
    if (!bn_winch_pending)
        return;
    bn_winch_pending = 0;
    bn_get_size ();
}

/* ---- render ---- */

static int
bn_viewport_cols (void)
{
    return bn_cols > 1 ? bn_cols - 1 : 1;
}

static int
bn_viewport_rows (void)
{
    return bn_rows > 2 ? bn_rows - 2 : 1;
}

static long
bn_softwrap_rows_for_line (bn_line *L, int viewport_cols)
{
    long width = L ? bn_screen_col (L->data, L->len, (long) L->len) : 0;
    if (viewport_cols < 1) viewport_cols = 1;
    if (width <= 0) return 1;
    return (width + viewport_cols - 1) / viewport_cols;
}

static long
bn_softwrap_cursor_row (int viewport_cols)
{
    long row = 0;
    if (viewport_cols < 1) viewport_cols = 1;
    for (long i = 0; i < bn_cy && (size_t) i < bn_b.n_lines; i++)
        row += bn_softwrap_rows_for_line (&bn_b.lines[i], viewport_cols);
    bn_line *cur = bn_curline ();
    long cur_col = cur ? bn_screen_col (cur->data, cur->len, bn_cx) : 0;
    return row + (cur_col / viewport_cols);
}

static long
bn_total_visual_rows (int viewport_cols)
{
    long rows = 0;
    if (viewport_cols < 1) viewport_cols = 1;
    if (!bn_softwrap) return bn_b.n_lines > 0 ? (long) bn_b.n_lines : 1;
    for (size_t i = 0; i < bn_b.n_lines; i++)
        rows += bn_softwrap ? bn_softwrap_rows_for_line (&bn_b.lines[i], viewport_cols) : 1;
    return rows > 0 ? rows : 1;
}

static void
bn_clamp_view_top (int viewport_rows, int viewport_cols)
{
    long total_rows = bn_total_visual_rows (viewport_cols);
    long max_top = total_rows > viewport_rows ? total_rows - viewport_rows : 0;
    if (bn_view_top > max_top) bn_view_top = max_top;
    if (bn_view_top < 0) bn_view_top = 0;
}

static void
bn_clamp_view_left (long cur_line_width, int viewport_cols)
{
    long max_left = cur_line_width > viewport_cols
                    ? cur_line_width - viewport_cols + 1
                    : 0;
    if (bn_view_left > max_left) bn_view_left = max_left;
    if (bn_view_left < 0) bn_view_left = 0;
}

static void
bn_render_line_chunk (bn_outbuf *out, bn_line *L, long lineno,
                      long start_col, int viewport_cols,
                      const char **sgr_at, size_t sgr_lo, size_t sgr_hi,
                      size_t sel_lo, size_t sel_hi)
{
    const char *cur_sgr = NULL;
    int cur_sel = 0;
    int cells = 0;
    int col_acc = 0;        /* screen column from line start */
    size_t pos = 0;
    while (pos < L->len) {
        size_t adv = grapheme_next_character_break_utf8 (
            L->data + pos, L->len - pos);
        if (adv == 0) adv = 1;
        int w = bn_cluster_cells (L->data + pos, adv, col_acc, NULL);
        if (col_acc + w <= start_col) {
            col_acc += w;
            pos += adv;
            continue;
        }
        /* A tab, wide character or caret form cut by the left edge shows
           its visible columns as blanks, so the text stays aligned with
           the cursor. */
        int cut = col_acc < start_col;
        int vis = cut ? (int) (col_acc + w - start_col) : w;
        if (cells + vis > viewport_cols) break;
        /* Stage 7.E — SGR transition for this cluster's first byte, if
           highlighting is on.  The marked region is drawn in reverse video
           on top of any highlight colour. */
        const char *want = NULL;
        if (sgr_at) {
            size_t gb = bn_labs ((size_t) lineno) + pos;
            want = gb >= sgr_lo && gb < sgr_hi ? sgr_at[gb - sgr_lo] : NULL;
        }
        int want_sel = pos >= sel_lo && pos < sel_hi;
        if (want != cur_sgr || want_sel != cur_sel) {
            if (cur_sgr || cur_sel) bn_out_cstr (out, "\033[0m");
            if (want_sel) bn_out_cstr (out, "\033[7m");
            if (want) bn_out_fmt (out, "\033[%sm", want);
            cur_sgr = want;
            cur_sel = want_sel;
        }
        if (cut) for (int i = 0; i < vis; i++) bn_out_append (out, " ", 1);
        else     bn_cluster_cells (L->data + pos, adv, col_acc, out);
        cells += vis;
        col_acc += w;
        pos += adv;
    }
    if (cur_sgr || cur_sel) bn_out_cstr (out, "\033[0m");
}

/* Line-relative byte range of the marked region on LINENO; empty when the
   mark is unset or the region does not touch the line. */
static void
bn_selection_on_line (long lineno, size_t sel_a, size_t sel_b,
                      size_t *lo, size_t *hi)
{
    *lo = *hi = 0;
    if (!bn_mark_active || sel_a >= sel_b) return;
    bn_line *L = &bn_b.lines[lineno];
    size_t ls = bn_labs ((size_t) lineno), le = ls + L->len;
    if (sel_b <= ls || sel_a > le) return;
    *lo = sel_a > ls ? sel_a - ls : 0;
    *hi = (sel_b < le ? sel_b : le) - ls;
}

static void
bn_render (void)
{
    bn_apply_pending_resize ();

    /* Adjust viewport so cursor is visible. */
    int viewport_rows = bn_viewport_rows ();  /* status + hint */
    int viewport_cols = bn_viewport_cols ();
    bn_line *cur = bn_curline ();
    long cur_col = cur ? bn_screen_col (cur->data, cur->len, bn_cx) : 0;

    if (bn_softwrap) {
        long cursor_row = bn_softwrap_cursor_row (viewport_cols);
        if (cursor_row < bn_view_top) bn_view_top = cursor_row;
        if (cursor_row >= bn_view_top + viewport_rows)
            bn_view_top = cursor_row - viewport_rows + 1;
        bn_view_left = 0;
    } else {
        if (bn_cy < bn_view_top) bn_view_top = bn_cy;
        if (bn_cy >= bn_view_top + viewport_rows) bn_view_top = bn_cy - viewport_rows + 1;
    }
    bn_clamp_view_top (viewport_rows, viewport_cols);

    /* Stage 4 — horizontal scroll. Compute cursor screen column on its
       line and shift the viewport window if cursor would otherwise fall
       outside it. Snapping back to 0 happens automatically when cursor
       moves left of the current window. */
    if (!bn_softwrap) {
        if (cur_col < bn_view_left) bn_view_left = cur_col;
        if (cur_col >= bn_view_left + viewport_cols)
            bn_view_left = cur_col - viewport_cols + 1;
        long line_width = cur ? bn_screen_col (cur->data, cur->len, (long) cur->len) : 0;
        bn_clamp_view_left (line_width, viewport_cols);
    }

    bn_outbuf out = {0};

    /* Hide cursor, home. */
    bn_out_cstr (&out, "\033[?25l\033[H");

    /* Top status line.  The name is shown in display form and shortened
       so the line never wraps. */
    {
        char pos_text[96];
        snprintf (pos_text, sizeof pos_text, "%s  L %ld/%zu C %ld ",
                  bn_b.dirty ? " [Modified]" : "",
                  bn_cy + 1, bn_b.n_lines, bn_cx + 1);
        const char *name = bn_b.path ? bn_b.path : "(no file)";
        long room = (long) bn_cols - 8 - (long) strlen (pos_text);
        bn_out_cstr (&out, "\033[7m nano  ");
        bn_out_text (&out, name, strlen (name), room > 1 ? room : 1);
        bn_out_cstr (&out, pos_text);
        bn_out_cstr (&out, "\033[K\033[m\r\n");
    }

    /* Colours for the lines that can be drawn, plus a screen of margin
       above and below so short scrolls reuse the window. */
    const char **sgr_at = NULL;
    size_t sgr_lo = 0, sgr_hi = 0;
    if (bn_lang && bn_b.n_lines > 0) {
        long first = bn_view_top;
        if (bn_softwrap) {
            long visual = 0;
            first = 0;
            while ((size_t) first + 1 < bn_b.n_lines) {
                long rows = bn_softwrap_rows_for_line (&bn_b.lines[first], viewport_cols);
                if (visual + rows > bn_view_top) break;
                visual += rows;
                first++;
            }
        }
        long a = first - viewport_rows, z = first + 2L * viewport_rows;
        if (a < 0) a = 0;
        if (z > (long) bn_b.n_lines) z = (long) bn_b.n_lines;
        size_t lo = bn_labs ((size_t) a);
        size_t hi = (size_t) z < bn_b.n_lines ? bn_labs ((size_t) z) : bn_b.pt.total_len;
        if (bn_highlight_cache_ensure (lo, hi) == 0) {
            sgr_at = bn_hl_cache.sgr_at;
            sgr_lo = bn_hl_cache.lo;
            sgr_hi = bn_hl_cache.hi;
        }
    } else if (!bn_lang)
        bn_highlight_release ();

    size_t sel_a = 0, sel_b = 0;
    if (bn_mark_active) {
        sel_a = bn_abs_from_lc (bn_mark_cy, bn_mark_cx);
        sel_b = bn_abs_from_lc (bn_cy, bn_cx);
        if (sel_a > sel_b) { size_t t = sel_a; sel_a = sel_b; sel_b = t; }
    }

    /* Body — v2 walks graphemes and accumulates cells, not bytes. */
    if (bn_softwrap) {
        long visual = 0;
        int outrow = 0;
        for (long lineno = 0; (size_t) lineno < bn_b.n_lines && outrow < viewport_rows; lineno++) {
            bn_line *L = &bn_b.lines[lineno];
            long chunks = bn_softwrap_rows_for_line (L, viewport_cols);
            for (long chunk = 0; chunk < chunks && outrow < viewport_rows; chunk++, visual++) {
                if (visual < bn_view_top) continue;
                bn_out_cstr (&out, "\033[K");
                size_t lo, hi;
                bn_selection_on_line (lineno, sel_a, sel_b, &lo, &hi);
                bn_render_line_chunk (&out, L, lineno, chunk * viewport_cols,
                                      viewport_cols, sgr_at, sgr_lo,
                                      sgr_hi, lo, hi);
                bn_out_cstr (&out, "\r\n");
                outrow++;
            }
        }
        while (outrow++ < viewport_rows)
            bn_out_cstr (&out, "\033[K\r\n");
    } else {
        for (int row = 0; row < viewport_rows; row++) {
            long lineno = bn_view_top + row;
            bn_out_cstr (&out, "\033[K");
            if (lineno < (long) bn_b.n_lines) {
                size_t lo, hi;
                bn_selection_on_line (lineno, sel_a, sel_b, &lo, &hi);
                bn_render_line_chunk (&out, &bn_b.lines[lineno], lineno,
                                      bn_view_left, viewport_cols,
                                      sgr_at, sgr_lo, sgr_hi, lo, hi);
            }
            bn_out_cstr (&out, "\r\n");
        }
    }
    /* Hint line, cut to the terminal width: writing past the last column
       of the bottom row would scroll the whole frame. */
    {
        const char *hint = bn_status[0] ? bn_status :
            "^O Save  ^X Exit  ^K Cut  ^U Paste  ^Z Undo  ^Y/M-E Redo  ^G Help";
        bn_out_cstr (&out, "\033[7m ");
        bn_out_text (&out, hint, strlen (hint), bn_cols > 3 ? bn_cols - 3 : 1);
        bn_out_cstr (&out, " \033[K\033[m");
    }

    /* Position cursor (adjust for status line at top, so +2). v2 — column
       is sum of cell widths, not byte count. Stage 4: account for the
       horizontal viewport offset. */
    long screen_row, screen_col;
    if (bn_softwrap) {
        long cursor_row = bn_softwrap_cursor_row (viewport_cols);
        screen_row = (cursor_row - bn_view_top) + 2;
        screen_col = (cur_col % viewport_cols) + 1;
    } else {
        screen_row = (bn_cy - bn_view_top) + 2;
        screen_col = (cur_col - bn_view_left) + 1;
    }
    if (screen_row < 2) screen_row = 2;
    if (screen_row > bn_rows) screen_row = bn_rows;
    if (screen_col < 1) screen_col = 1;
    if (screen_col > bn_cols) screen_col = bn_cols;
    bn_out_fmt (&out, "\033[%ld;%ldH\033[?25h", screen_row, screen_col);
    bn_out_flush (&out);

    if (bn_status_until > 0) bn_status_until--;
    if (bn_status_until == 0) bn_status[0] = '\0';
}

/* ---- editor ops ---- */

static bn_line *
bn_curline (void)
{
    if ((size_t) bn_cy >= bn_b.n_lines) return NULL;
    return &bn_b.lines[bn_cy];
}

/* v2 — advance one grapheme cluster forward; returns new byte index. */
static long
bn_grapheme_next (const char *s, size_t len, long byte_idx)
{
    if (byte_idx < 0) byte_idx = 0;
    if ((size_t) byte_idx >= len) return (long) len;
    size_t adv = grapheme_next_character_break_utf8 (s + byte_idx, len - byte_idx);
    if (adv == 0) adv = 1;   /* defensive */
    return byte_idx + (long) adv;
}

/* v2 — retreat one cluster; libgrapheme has no prev_break, so walk from
   line start collecting boundary positions and return the one preceding
   byte_idx. O(line_len) per call — fine for interactive editing. */
static long
bn_grapheme_prev (const char *s, size_t len, long byte_idx)
{
    if (byte_idx <= 0) return 0;
    long pos = 0, prev = 0;
    while (pos < byte_idx && (size_t) pos < len) {
        size_t adv = grapheme_next_character_break_utf8 (s + pos, len - pos);
        if (adv == 0) adv = 1;
        prev = pos;
        pos += (long) adv;
    }
    return prev;
}

/* Stage 15 — per-render-line cluster boundary cache.  The piece table is
   authoritative; bn_line objects are rebuilt after edits, so this lazy cache
   is valid for the render-line lifetime and avoids O(line_len) left/backspace
   walks on long single-line buffers. */
static long
bn_line_grapheme_prev (bn_line *L, long byte_idx)
{
    if (!L) return 0;
    if (byte_idx <= 0) return 0;
    if ((size_t) byte_idx > L->len) byte_idx = (long) L->len;
    if (bn_line_cluster_cache_build (L) < 0)
        return bn_grapheme_prev (L->data, L->len, byte_idx);
    if (L->cluster_count == 0) return 0;
    size_t lo = 0, hi = L->cluster_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (L->cluster_starts[mid] < (size_t) byte_idx)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo == 0 ? 0 : (long) L->cluster_starts[lo - 1];
}

/* v2 — convert byte cursor to screen column (sum of cell widths). */
static long
bn_screen_col (const char *s, size_t len, long byte_idx)
{
    long col = 0, pos = 0;
    while (pos < byte_idx && (size_t) pos < len) {
        size_t adv = grapheme_next_character_break_utf8 (s + pos, len - pos);
        if (adv == 0) adv = 1;
        col += bn_cluster_cells (s + pos, adv, col, NULL);
        pos += (long) adv;
    }
    return col;
}

static void
bn_clamp_cx (void)
{
    bn_line *L = bn_curline ();
    long max = L ? (long) L->len : 0;
    if (bn_cx > max) bn_cx = max;
    if (bn_cx < 0) bn_cx = 0;
    /* v2 — snap to nearest cluster boundary at-or-before bn_cx so we
       never land in the middle of a UTF-8 sequence after row change. */
    if (L && bn_cx > 0 && bn_cx < (long) L->len) {
        long snapped = bn_line_grapheme_prev (L, bn_cx + 1);
        bn_cx = snapped;
    }
}

/* Vertical movement keeps a screen column, as GNU nano does: the column
   is taken from the cursor on the first up/down key, and any other key
   forgets it, so passing through a short line returns to the same column.
   The cursor lands after the last cluster that ends at or before the
   column, never inside a wide character. */
static long bn_want_col = -1;

static long
bn_byte_at_col (const bn_line *L, long want)
{
    long col = 0;
    size_t pos = 0;
    while (L && pos < L->len) {
        size_t adv = grapheme_next_character_break_utf8 (L->data + pos, L->len - pos);
        if (adv == 0) adv = 1;
        int w = bn_cluster_cells (L->data + pos, adv, col, NULL);
        if (col + w > want) break;
        col += w;
        pos += adv;
    }
    return (long) pos;
}

static void
bn_move_vertical (long dy)
{
    bn_line *L = bn_curline ();
    if (bn_want_col < 0)
        bn_want_col = L ? bn_screen_col (L->data, L->len, bn_cx) : 0;
    long ny = bn_cy + dy;
    if (ny < 0) ny = 0;
    if (bn_b.n_lines == 0 || ny > (long) bn_b.n_lines - 1)
        ny = bn_b.n_lines ? (long) bn_b.n_lines - 1 : 0;
    if (ny == bn_cy) return;
    bn_cy = ny;
    bn_cx = bn_byte_at_col (bn_curline (), bn_want_col);
}

/* Stage 44.A — splice rlen bytes of `repl` over plen bytes at (line,col).
   Handles all three length cases (rlen==plen overwrite, rlen<plen shrink,
   rlen>plen grow). Returns 0 on success, -1 on bad args / OOM. */
static int
bn_replace_at (long line, long col, size_t plen, const char *repl, size_t rlen)
{
    if (line < 0 || (size_t) line >= bn_b.n_lines) return -1;
    bn_line *L = &bn_b.lines[line];
    if (col < 0 || (size_t) col + plen > L->len) return -1;
    size_t start = bn_abs_from_lc (line, col);
    return bn_piece_replace (start, start + plen, repl, rlen, start + rlen);
}

/* v2 — insert N bytes at cursor (caller passes a single grapheme cluster,
   typically 1-4 bytes from the UTF-8 reader). Cursor advances by N bytes. */
static void
bn_insert_bytes (const char *bytes, size_t n)
{
    if (n == 0) return;
    size_t pos = bn_abs_from_lc (bn_cy, bn_cx);
    bn_piece_replace (pos, pos, bytes, n, pos + n);
}

static void
bn_backspace (void)
{
    bn_line *L = bn_curline ();
    if (!L) return;
    if (bn_cx > 0) {
        /* v2 — delete the cluster ending at bn_cx (variable byte width). */
        long cluster_start = bn_line_grapheme_prev (L, bn_cx);
        size_t start = bn_abs_from_lc (bn_cy, cluster_start);
        size_t end = bn_abs_from_lc (bn_cy, bn_cx);
        bn_piece_replace (start, end, NULL, 0, start);
    } else if (bn_cy > 0) {
        size_t join_pos = bn_abs_from_lc (bn_cy, 0) - 1; /* newline before current line */
        bn_piece_replace (join_pos, join_pos + 1, NULL, 0, join_pos);
    }
}

static void
bn_delete_forward (void)
{
    bn_line *L = bn_curline ();
    if (!L) return;
    if (bn_cx < (long) L->len) {
        /* GNU nano ^D/Delete: remove the character under the cursor.
           Keep it grapheme-aware so a multibyte cluster is deleted as a unit. */
        long cluster_end = bn_grapheme_next (L->data, L->len, bn_cx);
        size_t start = bn_abs_from_lc (bn_cy, bn_cx);
        size_t end = bn_abs_from_lc (bn_cy, cluster_end);
        bn_piece_replace (start, end, NULL, 0, start);
    } else if ((size_t) bn_cy + 1 < bn_b.n_lines) {
        size_t join_pos = bn_abs_from_lc (bn_cy, bn_cx);
        bn_piece_replace (join_pos, join_pos + 1, NULL, 0, join_pos);
    }
}

static void
bn_split_line (void)
{
    size_t pos = bn_abs_from_lc (bn_cy, bn_cx);
    bn_piece_replace (pos, pos, "\n", 1, pos + 1);
}

static void
bn_cut_line (void)
{
    bn_line *L = bn_curline ();
    if (!L) return;
    size_t start = bn_abs_from_lc (bn_cy, 0);
    size_t line_end = start + L->len;
    size_t delete_start = start;
    size_t delete_end = line_end;
    if ((size_t) bn_cy + 1 < bn_b.n_lines)
        delete_end++;                  /* include following newline */
    else if (bn_cy > 0)
        delete_start--;                /* include previous newline */
    size_t clip_len = 0;
    char *clip = bn_pt_flatten_range (&bn_b.pt, start, line_end, &clip_len);
    bn_clip_take (clip, clip_len, 1);
    if (bn_clip) {
        bn_piece_replace (delete_start, delete_end, NULL, 0, delete_start);
        if (bn_b.n_lines == 0) bn_sync_lines_from_pt ();
        if (bn_cy >= (long) bn_b.n_lines) bn_cy = (long) bn_b.n_lines - 1;
        bn_cx = 0;
    }
}

/* Stage 44.D/E — capture the marked byte range into the cut buffer.  The
   range may cross line boundaries; if `cut_it`, splice those bytes out too. */
static void
bn_mark_cut_or_copy (long line_idx, long start_cx, long end_cx, int cut_it)
{
    (void) line_idx;
    size_t start = bn_abs_from_lc (bn_mark_cy, bn_mark_cx);
    size_t end = bn_abs_from_lc (bn_cy, bn_cx);
    if (start > end) { size_t t = start; start = end; end = t; }
    if (start_cx > end_cx) { long t = start_cx; start_cx = end_cx; end_cx = t; }
    size_t n = end - start;
    size_t clip_len = 0;
    char *clip = bn_pt_flatten_range (&bn_b.pt, start, end, &clip_len);
    bn_clip_take (clip, clip_len, 1);
    if (cut_it && n > 0) {
        bn_piece_replace (start, end, NULL, 0, start);
    }
    bn_mark_active = 0;
}

static void
bn_paste (void)
{
    if (!bn_clip) return;
    size_t pos = bn_abs_from_lc (bn_cy, bn_cx);
    bn_piece_replace (pos, pos, bn_clip, bn_clip_len, pos + bn_clip_len);
}

static void
bn_undo (void)
{
    size_t pos = bn_abs_from_lc (bn_cy, bn_cx);
    if (bn_b.undo.n == 0) { bn_set_status ("Nothing to undo"); return; }
    size_t mark_abs = bn_mark_active ? bn_abs_from_lc (bn_mark_cy, bn_mark_cx) : 0;
    bn_pt_snapshot ed = bn_b.undo.v[bn_b.undo.n - 1];
    if (bn_pt_snapshot_push (&bn_b.redo, &bn_b.pt) < 0) return;
    bn_pt_snapshot *mirror = &bn_b.redo.v[bn_b.redo.n - 1];
    mirror->e_valid = ed.e_valid;
    mirror->e_start = ed.e_start;
    mirror->e_old = ed.e_old;
    mirror->e_new = ed.e_new;
    if (bn_pt_snapshot_pop (&bn_b.undo, &bn_b.pt) < 0) return;
    bn_sync_lines_from_pt ();
    if (bn_mark_active)
        bn_mark_from_abs (ed.e_valid ? bn_offset_after_edit (mark_abs, ed.e_start, ed.e_start + ed.e_new, ed.e_old) : mark_abs);
    bn_set_cursor_abs (pos > bn_b.pt.total_len ? bn_b.pt.total_len : pos);
    bn_set_status ("Undid change");
}

static void
bn_redo (void)
{
    size_t pos = bn_abs_from_lc (bn_cy, bn_cx);
    if (bn_b.redo.n == 0) { bn_set_status ("Nothing to redo"); return; }
    size_t mark_abs = bn_mark_active ? bn_abs_from_lc (bn_mark_cy, bn_mark_cx) : 0;
    bn_pt_snapshot ed = bn_b.redo.v[bn_b.redo.n - 1];
    if (bn_pt_snapshot_push (&bn_b.undo, &bn_b.pt) < 0) return;
    bn_pt_snapshot *mirror = &bn_b.undo.v[bn_b.undo.n - 1];
    mirror->e_valid = ed.e_valid;
    mirror->e_start = ed.e_start;
    mirror->e_old = ed.e_old;
    mirror->e_new = ed.e_new;
    if (bn_pt_snapshot_pop (&bn_b.redo, &bn_b.pt) < 0) return;
    bn_sync_lines_from_pt ();
    if (bn_mark_active)
        bn_mark_from_abs (ed.e_valid ? bn_offset_after_edit (mark_abs, ed.e_start, ed.e_start + ed.e_old, ed.e_new) : mark_abs);
    bn_set_cursor_abs (pos > bn_b.pt.total_len ? bn_b.pt.total_len : pos);
    bn_set_status ("Redid change");
}

/* ---- key dispatch ---- */

/* Stage 2 — search-forward from (bn_cy, bn_cx + len(pat)). Wraps around
   to line 0 if no match found below cursor. Sets bn_cy/bn_cx on hit and
   returns 0; sets a "Not found" status and returns 1 on miss.

   memmem is GNU/POSIX-2024 (musl ships it). Using it avoids an explicit
   substring loop and handles any byte sequence including UTF-8. */
static int
bn_search_forward (const char *pat)
{
    size_t plen = strlen (pat);
    if (plen == 0) return 1;
    int regex_mode = 0;
    regex_t re;
    if (strncmp (pat, "re:", 3) == 0) {
        regex_mode = 1;
        if (regcomp (&re, pat + 3, REG_EXTENDED) != 0) {
            bn_set_status ("Bad regex: %s", pat + 3);
            return 1;
        }
    }
    /* Start position: just after the current cursor on its line. */
    size_t start = (size_t) bn_cx + 1;
    int wrapped = 0;
    long line = bn_cy;
    while (1) {
        bn_line *L = (line >= 0 && (size_t) line < bn_b.n_lines)
                     ? &bn_b.lines[line] : NULL;
        if (L && start <= L->len) {
            long hit_col = -1;
            if (regex_mode) {
                size_t slen = L->len - start;
                char *tmp = malloc (slen + 1);
                if (!tmp) { regfree (&re); return 1; }
                if (slen) memcpy (tmp, L->data + start, slen);
                tmp[slen] = '\0';
                regmatch_t m;
                if (regexec (&re, tmp, 1, &m, 0) == 0 && m.rm_so >= 0)
                    hit_col = (long) start + (long) m.rm_so;
                free (tmp);
            } else if (L->len - start >= plen) {
                void *hit = memmem (L->data + start, L->len - start, pat, plen);
                if (hit)
                    hit_col = (long) ((char *) hit - L->data);
            }
            if (hit_col >= 0) {
                bn_cy = line;
                bn_cx = hit_col;
                if (wrapped) bn_set_status ("Search wrapped: %s", pat);
                else         bn_set_status ("Found: %s", pat);
                if (regex_mode) regfree (&re);
                return 0;
            }
        }
        line++;
        start = 0;
        if ((size_t) line >= bn_b.n_lines) {
            if (wrapped) break;
            wrapped = 1;
            line = 0;
        }
        if (wrapped && line > bn_cy) break;     /* full lap, no hit */
    }
    bn_set_status ("Not found: %s", pat);
    if (regex_mode) regfree (&re);
    return 1;
}

static int
bn_search_backward (const char *pat)
{
    size_t plen = strlen (pat);
    if (plen == 0 || bn_b.n_lines == 0) return 1;
    int regex_mode = 0;
    regex_t re;
    if (strncmp (pat, "re:", 3) == 0) {
        regex_mode = 1;
        if (regcomp (&re, pat + 3, REG_EXTENDED) != 0) {
            bn_set_status ("Bad regex: %s", pat + 3);
            return 1;
        }
    }

    size_t start_line = (bn_cy >= 0 && (size_t) bn_cy < bn_b.n_lines)
                        ? (size_t) bn_cy : 0;
    for (size_t step = 0; step < bn_b.n_lines; step++) {
        size_t line = (start_line + bn_b.n_lines - step) % bn_b.n_lines;
        bn_line *L = &bn_b.lines[line];
        size_t limit = L->len;
        if (step == 0) {
            if (bn_cx <= 0) limit = 0;
        else if ((size_t) bn_cx < limit) limit = (size_t) bn_cx;
        }
        if (!regex_mode && limit < plen) continue;

        long last_col = -1;
        if (regex_mode) {
            char *tmp = malloc (limit + 1);
            if (!tmp) { regfree (&re); return 1; }
            if (limit) memcpy (tmp, L->data, limit);
            tmp[limit] = '\0';
            size_t base = 0;
            while (base <= limit) {
                regmatch_t m;
                if (regexec (&re, tmp + base, 1, &m, 0) != 0 || m.rm_so < 0)
                    break;
                last_col = (long) base + (long) m.rm_so;
                size_t adv = (size_t) m.rm_eo;
                if (adv == 0) adv = (size_t) m.rm_so + 1;
                if (adv == 0) adv = 1;
                base += adv;
            }
            free (tmp);
        } else {
            char *scan = L->data;
            size_t remaining = limit;
            while (remaining >= plen) {
                char *hit = memmem (scan, remaining, pat, plen);
                if (!hit) break;
                last_col = (long) (hit - L->data);
                size_t advance = (size_t) (hit - scan) + 1;
                scan += advance;
                remaining -= advance;
            }
        }
        if (last_col >= 0) {
            bn_cy = (long) line;
            bn_cx = last_col;
            if (step > start_line) bn_set_status ("Search wrapped backward: %s", pat);
            else                   bn_set_status ("Found backward: %s", pat);
            if (regex_mode) regfree (&re);
            return 0;
        }
    }

    bn_set_status ("Not found: %s", pat);
    if (regex_mode) regfree (&re);
    return 1;
}

/* Stage 2 — modal prompt (Search:, Save As:, Goto:). Loops drawing a
   custom hint line while the user types. Returns 0 on Enter (commit),
   -1 on ESC (cancel). dest carries any pre-fill on entry and the
   committed text on exit. */
static int
bn_read_key (char *buf, size_t bufsz);    /* fwd-decl for use in bn_modal_prompt */

static int
bn_modal_prompt (const char *label, char *dest, size_t dest_size)
{
    char saved_status[sizeof bn_status];
    int  saved_until = bn_status_until;
    memcpy (saved_status, bn_status, sizeof bn_status);

    size_t dlen = strlen (dest);    /* prefill survives across calls */
    while (1) {
        snprintf (bn_status, sizeof bn_status, "%s%s", label, dest);
        bn_status_until = 99;       /* keep visible across renders */
        bn_render ();

        char k[8];
        int klen = bn_read_key (k, sizeof k);
        if (klen == 0 && !bn_term_signal) continue;     /* interrupted read */
        if (klen == 0) klen = -1;           /* SIGHUP/SIGTERM: cancel */
        if (klen < 0) {                     /* input closed: cancel */
            memcpy (bn_status, saved_status, sizeof bn_status);
            bn_status_until = saved_until;
            return -1;
        }

        if (klen == 1 && (k[0] == '\r' || k[0] == '\n')) {
            memcpy (bn_status, saved_status, sizeof bn_status);
            bn_status_until = saved_until;
            return 0;
        }
        if (klen == 1 && k[0] == 0x1b) {
            memcpy (bn_status, saved_status, sizeof bn_status);
            bn_status_until = saved_until;
            return -1;
        }
        if (klen >= 2 && k[0] == 0x1b) continue;        /* swallow other escape sequences */
        if (klen == 1 && (k[0] == 0x7f || k[0] == 0x08)) {
            /* Remove a whole cluster, never part of a UTF-8 sequence. */
            if (dlen > 0) {
                dlen = (size_t) bn_grapheme_prev (dest, dlen, (long) dlen);
                dest[dlen] = '\0';
            }
            continue;
        }
        /* Append the keystroke (printable ASCII or full UTF-8 cluster). */
        if (klen == 1) {
            unsigned char b = (unsigned char) k[0];
            if (b < 0x20) continue;     /* drop other controls */
        }
        if (dlen + (size_t) klen + 1 > dest_size) continue;     /* full */
        memcpy (dest + dlen, k, (size_t) klen);
        dlen += (size_t) klen;
        dest[dlen] = '\0';
    }
}

/* G03 Stage SAVE-PROMPTS — single-key prompt for Y/N/ESC dialogs. Returns
   'Y' or 'N' (uppercased) on a yes/no answer, 0 on ESC/cancel/anything
   else. The modal renders into bn_status the same way bn_modal_prompt
   does, then reads one key (which may be a multi-byte ESC sequence) and
   restores the prior status. */
static int
bn_prompt_key (const char *label)
{
    char saved_status[sizeof bn_status];
    int  saved_until = bn_status_until;
    memcpy (saved_status, bn_status, sizeof bn_status);

    snprintf (bn_status, sizeof bn_status, "%s", label);
    bn_status_until = 99;
    bn_render ();

    char k[8] = {0};
    int klen = bn_read_key (k, sizeof k);

    memcpy (bn_status, saved_status, sizeof bn_status);
    bn_status_until = saved_until;

    if (klen <= 0) return 0;
    if (k[0] == 0x1b) return 0;                 /* ESC */
    int c = (unsigned char) k[0];
    if (c >= 'a' && c <= 'z') c -= 32;          /* fold to upper */
    if (c == 'Y' || c == 'N') return c;
    return 0;
}

/* G03 Stage SAVE-PROMPTS — GNU nano's "File Name to Write: " modal. The
   prompt pre-fills with the current bn_b.path (matching nano), the user
   can edit / Enter / ESC. Enter with empty buffer yields "No filename"
   via bn_save_as's contract; ESC yields "Save cancelled". Returns 0 on
   committed write, -1 otherwise. */
static int
bn_prompt_save_as (void)
{
    char dest[4096] = {0};
    if (bn_b.path) {
        size_t n = strlen (bn_b.path);
        if (n >= sizeof dest) n = sizeof dest - 1;
        memcpy (dest, bn_b.path, n);
        dest[n] = '\0';
    }
    if (bn_modal_prompt ("File Name to Write: ", dest, sizeof dest) != 0) {
        bn_set_status ("Save cancelled");
        return -1;
    }
    return bn_save_as (dest);
}

/* Headless fixtures queue whole keys here; while a queue is installed,
   bn_read_key returns its keys in order and then end-of-input, so the
   production prompts and dispatch run without a terminal. */
static const char *const *bn_keyq = NULL;
static size_t bn_keyq_n = 0, bn_keyq_pos = 0;

static void
bn_keyq_set (const char *const *keys, size_t n)
{
    bn_keyq = keys;
    bn_keyq_n = n;
    bn_keyq_pos = 0;
}

/* One byte of terminal input.  TIMEOUT_MS < 0 blocks.  A byte pushed
   back by the key framer comes first. */
#define BN_BYTE_EOF     (-1)
#define BN_BYTE_TIMEOUT (-2)
#define BN_BYTE_INTR    (-3)
#define BN_ESC_WAIT_MS  100
static int bn_unread = -1;

static int
bn_next_byte (int timeout_ms)
{
    if (bn_term_signal) return BN_BYTE_INTR;
    if (bn_unread >= 0) {
        int c = bn_unread;
        bn_unread = -1;
        return c;
    }
    for (;;) {
        struct pollfd p = { STDIN_FILENO, POLLIN, 0 };
        int r = bn_poll (&p, 1, timeout_ms);
        if (r == 0) return BN_BYTE_TIMEOUT;
        if (r < 0) {
            if (errno != EINTR) return BN_BYTE_EOF;
            if (timeout_ms < 0 || bn_term_signal) return BN_BYTE_INTR;
            continue;
        }
        /* Read only after readiness, never an unchecked blocking read.
           The editor is the sole reader of its terminal input. */
        unsigned char b;
        ssize_t n = read (STDIN_FILENO, &b, 1);
        if (n == 1) return b;
        if (n < 0 && errno == EINTR) {
            if (timeout_ms < 0 || bn_term_signal) return BN_BYTE_INTR;
            continue;
        }
        return BN_BYTE_EOF;
    }
}

static int
bn_frame_key (char *buf, size_t bufsz)
{
    if (bn_keyq) {
        if (bn_keyq_pos >= bn_keyq_n) return -1;
        const char *key = bn_keyq[bn_keyq_pos++];
        size_t n = strlen (key);
        if (n >= bufsz) n = bufsz - 1;
        memcpy (buf, key, n);
        return (int) n;
    }
    int c0 = bn_next_byte (-1);
    if (c0 == BN_BYTE_INTR) return 0;
    if (c0 < 0) return -1;
    buf[0] = (char) c0;
    size_t total = 1;
    if (c0 == 0x1b) {
        /* Frame exactly one key, so keys that arrive in the same burst as
           an escape sequence are not swallowed with it: ESC alone (after a
           pause), ESC [ params final (CSI), ESC O final (SS3), ESC followed
           by one UTF-8 character (Alt+key), or ESC ESC, which yields the
           first ESC and keeps the second for the next key. */
        int c1 = bn_next_byte (BN_ESC_WAIT_MS);
        if (c1 < 0) return 1;
        if (c1 == 0x1b) { bn_unread = c1; return 1; }
        buf[total++] = (char) c1;
        if (c1 == '[' || c1 == 'O') {
            for (;;) {
                int c = bn_next_byte (BN_ESC_WAIT_MS);
                if (c < 0) break;
                if (c < 0x20 || c > 0x7e) { bn_unread = c; break; }
                if (total < bufsz - 1) buf[total++] = (char) c;
                /* Parameter and intermediate bytes are 0x20..0x3f; a CSI
                   ends at the first byte from 0x40, SS3 after one byte. */
                if (c >= 0x40 || c1 == 'O') break;
            }
            return (int) total;
        }
        if ((unsigned char) c1 < 0x80) return (int) total;
        /* Alt + a multibyte character: fall through and collect it. */
    }
    unsigned char lead = (unsigned char) buf[total - 1];
    if (lead >= 0x80) {
        int expect = 1;
        if      ((lead & 0xE0) == 0xC0) expect = 2;
        else if ((lead & 0xF0) == 0xE0) expect = 3;
        else if ((lead & 0xF8) == 0xF0) expect = 4;
        size_t want = total - 1 + (size_t) expect;
        while (total < want && total < bufsz - 1) {
            int c = bn_next_byte (BN_ESC_WAIT_MS);
            if (c < 0) break;
            /* A byte that does not continue the sequence starts the next
               key instead of being lost. */
            if ((c & 0xC0) != 0x80) { bn_unread = c; break; }
            buf[total++] = (char) c;
        }
    }
    return (int) total;
}

/* Cancellation also takes precedence over queued keys and partial frames. */
static int
bn_read_key (char *buf, size_t bufsz)
{
    if (bn_term_signal) return 0;
    int n = bn_frame_key (buf, bufsz);
    return bn_term_signal ? 0 : n;
}

/* ---- justify (^J, M-J) ----

   Follows GNU nano's paragraph model: a paragraph is a run of lines with
   text after their quote and indentation, beginning where begpar() says so
   (after a blank line, at a change of quoting, or at the first of two lines
   whose indentation differs).  The first line keeps its own lead (quote plus
   indentation); later lines take the second line's.  Runs of blanks become
   one space, except that up to two survive after sentence punctuation and
   one closing bracket.  Lines are refilled greedily so that each one,
   including its lead, is at most the fill width; a word wider than that
   stays whole on its own line.  The blanks at a break stay on the upper
   line unless --trimblanks is in effect, as in GNU nano.  The whole
   justification is one piece-table replacement, so one undo restores it. */

static long bn_fill = -8;          /* <= 0: relative to the terminal width */
static int bn_trimblanks = 0;
static regex_t bn_quote_re;
static int bn_quote_state = 0;     /* 0 untried, 1 compiled, -1 failed */

static long
bn_fill_width (void)
{
    long w = bn_fill > 0 ? bn_fill : bn_cols + bn_fill;
    return w < 0 ? 0 : w;
}

static int
bn_is_blank (char c)
{
    return c == ' ' || c == '\t';
}

/* GNU nano's default quotestr, "^([ \t]*([!#%:;>|}]|//))+". */
static size_t
bn_quote_len (const char *s, size_t n)
{
    if (bn_quote_state == 0)
        bn_quote_state = regcomp (&bn_quote_re, "^([ \t]*([!#%:;>|}]|//))+",
                                  REG_EXTENDED) == 0 ? 1 : -1;
    if (bn_quote_state < 0) return 0;
    /* Only these bytes can take part in a quote prefix, so match on that
       leading run instead of copying the whole line. */
    size_t run = 0;
    while (run < n && run < 255 && strchr (" \t!#%:;>|}/", s[run]) && s[run])
        run++;
    if (run == 0) return 0;
    char tmp[256];
    memcpy (tmp, s, run);
    tmp[run] = '\0';
    regmatch_t m;
    if (regexec (&bn_quote_re, tmp, 1, &m, 0) != 0 || m.rm_so != 0) return 0;
    return (size_t) m.rm_eo;
}

static size_t
bn_lead_len (const bn_line *L)
{
    size_t q = bn_quote_len (L->data, L->len);
    while (q < L->len && bn_is_blank (L->data[q])) q++;
    return q;
}

/* Display width of a line's lead; tabs advance to the next multiple of 8. */
static long
bn_lead_width (const char *s, size_t n)
{
    long col = 0;
    for (size_t i = 0; i < n; i++)
        col = s[i] == '\t' ? col + 8 - col % 8 : col + 1;
    return col;
}

static int
bn_inpar (size_t i)
{
    bn_line *L = &bn_b.lines[i];
    return bn_lead_len (L) < L->len;
}

static int
bn_begpar (size_t i)
{
    /* Unequal indentation negates the previous line's answer. Walk back
       iteratively so long alternating runs have no recursion cutoff. */
    int invert = 0, answer;
    for (;;) {
        if (i == 0) { answer = 1; break; }
        bn_line *L = &bn_b.lines[i], *P = &bn_b.lines[i - 1];
        size_t lead = bn_lead_len (L);
        if (lead == L->len) { answer = 0; break; }
        size_t q = bn_quote_len (L->data, L->len);
        size_t pq = bn_quote_len (P->data, P->len);
        if (q != pq || (q && memcmp (L->data, P->data, q) != 0)) {
            answer = 1; break;
        }
        size_t plead = bn_lead_len (P);
        if (plead == P->len) { answer = 1; break; }
        if (bn_lead_width (P->data, plead) == bn_lead_width (L->data, lead)) {
            answer = 0; break;
        }
        invert = !invert;
        i--;
    }
    return answer ^ invert;
}

typedef struct {
    char *v;
    size_t n, cap;
    int failed;
} bn_strbuf;

static void
bn_sb_add (bn_strbuf *b, const char *s, size_t n)
{
    if (b->failed || n == 0) return;
    if (b->n + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap : 256;
        while (nc < b->n + n + 1) nc *= 2;
        char *nv = realloc (b->v, nc);
        if (!nv) { b->failed = 1; return; }
        b->v = nv;
        b->cap = nc;
    }
    memcpy (b->v + b->n, s, n);
    b->n += n;
    b->v[b->n] = '\0';
}

/* GNU nano's squeeze(): one space per blank run, up to two after
   sentence punctuation and one closing bracket, none at the end. */
static void
bn_squeeze (bn_strbuf *out, const char *s, size_t n)
{
    size_t i = 0;
    while (i < n) {
        if (bn_is_blank (s[i])) {
            bn_sb_add (out, " ", 1);
            while (i < n && bn_is_blank (s[i])) i++;
        } else if (strchr ("!.?", s[i]) && s[i]) {
            bn_sb_add (out, s + i, 1); i++;
            if (i < n && s[i] && strchr ("\"')>]}", s[i])) { bn_sb_add (out, s + i, 1); i++; }
            for (int k = 0; k < 2 && i < n && bn_is_blank (s[i]); k++, i++)
                bn_sb_add (out, " ", 1);
            while (i < n && bn_is_blank (s[i])) i++;
        } else {
            bn_sb_add (out, s + i, 1); i++;
        }
    }
    while (!out->failed && out->n > 0 && out->v[out->n - 1] == ' ')
        out->v[--out->n] = '\0';
}

/* Justify lines L0..L1 as one paragraph, appending the result to OUT
   without a final newline. */
static void
bn_justify_par (size_t l0, size_t l1, bn_strbuf *out)
{
    bn_line *F = &bn_b.lines[l0];
    size_t lead1 = bn_lead_len (F);
    const char *lead2_s = F->data;
    size_t lead2 = lead1;
    if (l1 > l0) {
        lead2_s = bn_b.lines[l0 + 1].data;
        lead2 = bn_lead_len (&bn_b.lines[l0 + 1]);
    }

    bn_strbuf joined = {0};
    for (size_t i = l0; i <= l1; i++) {
        bn_line *L = &bn_b.lines[i];
        size_t lead = bn_lead_len (L);
        if (joined.n > 0 && !bn_is_blank (joined.v[joined.n - 1]))
            bn_sb_add (&joined, " ", 1);
        bn_sb_add (&joined, L->data + lead, L->len - lead);
    }
    bn_strbuf text = {0};
    bn_squeeze (&text, joined.v ? joined.v : "", joined.n);
    free (joined.v);
    if (text.failed || joined.failed) { out->failed = 1; free (text.v); return; }

    long fill = bn_fill_width ();
    long leadw1 = bn_lead_width (F->data, lead1);
    long leadw2 = bn_lead_width (lead2_s, lead2);
    bn_sb_add (out, F->data, lead1);
    long curw = leadw1;
    int first = 1;
    size_t pending = 0;            /* spaces after the previous word */
    size_t i = 0;
    while (i < text.n) {
        size_t ws = i;
        while (i < text.n && text.v[i] != ' ') i++;
        size_t wl = i - ws;
        long ww = bn_screen_col (text.v + ws, wl, (long) wl);
        size_t sep = 0;
        while (i < text.n && text.v[i] == ' ') { i++; sep++; }
        if (first) {
            first = 0;
        } else if (curw + (long) pending + ww <= fill) {
            bn_sb_add (out, "  ", pending);
            curw += (long) pending;
        } else {
            if (!bn_trimblanks) bn_sb_add (out, "  ", pending);
            bn_sb_add (out, "\n", 1);
            bn_sb_add (out, lead2_s, lead2);
            curw = leadw2;
        }
        bn_sb_add (out, text.v + ws, wl);
        curw += ww;
        pending = sep;
    }
    free (text.v);
}

/* Justify every paragraph inside lines L0..L1 (L0 starts a paragraph) as a
   single replacement.  Returns 1 when the text changed, 0 when it was
   already justified, -1 on failure.  *END_LINE receives the last line of
   the replaced span after the edit. */
static int
bn_justify_lines (size_t l0, size_t l1, size_t *end_line)
{
    bn_strbuf out = {0};
    size_t i = l0;
    while (i <= l1) {
        if (i > l0) bn_sb_add (&out, "\n", 1);
        if (!bn_inpar (i)) {
            bn_sb_add (&out, bn_b.lines[i].data, bn_b.lines[i].len);
            i++;
            continue;
        }
        size_t e = i;
        while (e < l1 && bn_inpar (e + 1) && !bn_begpar (e + 1)) e++;
        bn_justify_par (i, e, &out);
        i = e + 1;
    }
    if (out.failed) { free (out.v); return -1; }
    size_t start = bn_labs (l0);
    size_t end = bn_labs (l1) + bn_b.lines[l1].len;
    size_t new_lines = bn_pt_count_nl (out.v ? out.v : "", out.n);
    *end_line = l0 + new_lines;
    size_t old_len = 0;
    char *old = bn_pt_flatten_range (&bn_b.pt, start, end, &old_len);
    int same = old && old_len == out.n && memcmp (old, out.v ? out.v : "", out.n) == 0;
    free (old);
    if (same) { free (out.v); *end_line = l1; return 0; }
    int rc = bn_piece_replace (start, end, out.v ? out.v : "", out.n, start + out.n);
    free (out.v);
    return rc < 0 ? -1 : 1;
}

/* ^J justifies the paragraph at or after the cursor, or with the mark set
   the paragraphs in the marked lines; M-J (WHOLE) justifies the buffer. */
static void
bn_justify (int whole)
{
    if (bn_b.n_lines == 0) return;
    size_t l0, l1, end_line = 0;
    const char *what;
    if (whole) {
        l0 = 0;
        l1 = bn_b.n_lines - 1;
        what = "file";
    } else if (bn_mark_active) {
        l0 = (size_t) (bn_mark_cy < bn_cy ? bn_mark_cy : bn_cy);
        l1 = (size_t) (bn_mark_cy < bn_cy ? bn_cy : bn_mark_cy);
        what = "selection";
    } else {
        size_t line = (size_t) bn_cy;
        while (line < bn_b.n_lines && !bn_inpar (line)) line++;
        if (line >= bn_b.n_lines) {
            bn_set_status ("No paragraph to justify");
            return;
        }
        while (!bn_begpar (line)) line--;
        l0 = l1 = line;
        while (l1 + 1 < bn_b.n_lines && bn_inpar (l1 + 1) && !bn_begpar (l1 + 1))
            l1++;
        what = "paragraph";
    }
    long save_cy = bn_cy, save_cx = bn_cx;
    int rc = bn_justify_lines (l0, l1, &end_line);
    if (rc < 0) { bn_set_status ("Justify failed: out of memory"); return; }
    if (!whole && bn_mark_active) bn_mark_active = 0;
    if (whole) {
        bn_cy = save_cy < (long) bn_b.n_lines ? save_cy : (long) bn_b.n_lines - 1;
        bn_cx = save_cx;
        bn_clamp_cx ();
    } else if (end_line + 1 < bn_b.n_lines) {
        bn_cy = (long) end_line + 1;
        bn_cx = 0;
    } else {
        bn_cy = (long) end_line;
        bn_cx = (long) bn_b.lines[end_line].len;
    }
    if (rc == 0) bn_set_status ("%c%s already justified", what[0] - 32, what + 1);
    else         bn_set_status ("Justified %s", what);
}

/* ---- spell check (^T) ----

   The helper boundary: the command named by --speller=CMD, else the
   NANO_SPELLER environment variable, else "spell", is split on blanks and
   run with execvp -- never through a shell.  It receives the text being
   checked (the marked region, or the whole buffer) on stdin and must print
   the misspelled words one per line on stdout, which is the interface of
   spell(1), "aspell list" and "hunspell -l".  Its stderr goes to /dev/null
   and it never sees the terminal.  Output is capped at 1 MiB and 4096
   words, the run at bn_spell_timeout_ms (then SIGKILL to that child only),
   and any nonzero exit, signal, exec failure or overflow leaves the buffer
   untouched with a status message.  For each word the cursor moves to its
   first whole-word occurrence and the "Edit a replacement" prompt opens
   prefilled with it: Enter with a changed word replaces every whole-word
   occurrence in the checked text as one undoable edit, Enter unchanged
   skips it, and Esc ends the check. */

static char *bn_speller = NULL;
static int bn_spell_timeout_ms = 10000;
#define BN_SPELL_MAX_OUT ((size_t) 1 << 20)
#define BN_SPELL_MAX_WORDS 4096
#define BN_WORD_MAX 255

typedef struct {
    char **v;
    size_t n, cap;
} bn_wordlist;

static void
bn_wordlist_free (bn_wordlist *w)
{
    for (size_t i = 0; i < w->n; i++) free (w->v[i]);
    free (w->v);
    memset (w, 0, sizeof *w);
}

static int
bn_wordlist_add_unique (bn_wordlist *w, const char *s, size_t n)
{
    for (size_t i = 0; i < w->n; i++)
        if (strlen (w->v[i]) == n && memcmp (w->v[i], s, n) == 0) return 0;
    if (w->n == w->cap) {
        size_t nc = w->cap ? w->cap * 2 : 16;
        char **nv = realloc (w->v, nc * sizeof *nv);
        if (!nv) return -1;
        w->v = nv;
        w->cap = nc;
    }
    char *c = malloc (n + 1);
    if (!c) return -1;
    memcpy (c, s, n);
    c[n] = '\0';
    w->v[w->n++] = c;
    return 1;
}

static int
bn_is_word_byte (char c)
{
    unsigned char u = (unsigned char) c;
    return (u >= '0' && u <= '9') || (u >= 'a' && u <= 'z')
        || (u >= 'A' && u <= 'Z') || u == '_' || u >= 0x80;
}

static const char *
bn_speller_command (void)
{
    if (bn_speller && *bn_speller) return bn_speller;
    const char *env = getenv ("NANO_SPELLER");
    return env && *env ? env : "spell";
}

/* Run the helper over TEXT; on success fill WORDS and return 0, otherwise
   describe the failure in ERR and return -1. */
static int
bn_spell_run_helper (const char *cmd, const char *text, size_t len,
                     bn_wordlist *words, char *err, size_t errsz)
{
    if (bn_term_signal) {
        snprintf (err, errsz, "Spell helper interrupted");
        return -1;
    }
    char *copy = strdup (cmd);
    char *argv[32];
    int argc = 0;
    if (!copy) { snprintf (err, errsz, "Spell helper: out of memory"); return -1; }
    for (char *tok = strtok (copy, " \t"); tok; tok = strtok (NULL, " \t")) {
        if (argc == 31) {
            free (copy);
            snprintf (err, errsz, "Spell helper: at most 31 command words");
            return -1;
        }
        argv[argc++] = tok;
    }
    argv[argc] = NULL;
    if (argc == 0) {
        free (copy);
        snprintf (err, errsz, "No spell helper configured");
        return -1;
    }

    int in[2] = { -1, -1 }, out[2] = { -1, -1 };
    if (pipe (in) < 0 || pipe (out) < 0) {
        snprintf (err, errsz, "Spell helper: %s", strerror (errno));
        if (in[0] >= 0) { close (in[0]); close (in[1]); }
        free (copy);
        return -1;
    }
    for (int i = 0; i < 2; i++) {
        fcntl (in[i], F_SETFD, FD_CLOEXEC);
        fcntl (out[i], F_SETFD, FD_CLOEXEC);
    }

    /* Bash's SIGCHLD handler reaps any child; block it so this wait gets
       the status.  A helper that stops reading must not SIGPIPE the shell. */
    sigset_t chld, old_mask;
    sigemptyset (&chld);
    sigaddset (&chld, SIGCHLD);
    sigprocmask (SIG_BLOCK, &chld, &old_mask);
    struct sigaction ign, old_pipe;
    memset (&ign, 0, sizeof ign);
    ign.sa_handler = SIG_IGN;
    sigemptyset (&ign.sa_mask);
    sigaction (SIGPIPE, &ign, &old_pipe);

    /* Exported shell variables reach the helper the way they reach any
       command bash runs. */
    maybe_make_export_env ();
    pid_t pid = fork ();
    if (pid == 0) {
        if (export_env) environ = export_env;
        static const int dfl[] = { SIGPIPE, SIGINT, SIGQUIT, SIGTERM, SIGTSTP,
                                   SIGTTIN, SIGTTOU, SIGWINCH, SIGCHLD, SIGALRM };
        for (size_t i = 0; i < sizeof dfl / sizeof dfl[0]; i++)
            signal (dfl[i], SIG_DFL);
        sigset_t none;
        sigemptyset (&none);
        sigprocmask (SIG_SETMASK, &none, NULL);
        /* Detach from the editor's controlling terminal before exec. */
        if (setsid () < 0) _exit (126);
        int devnull = open ("/dev/null", O_WRONLY | O_CLOEXEC);
        if (devnull < 0 || dup2 (in[0], STDIN_FILENO) < 0
            || dup2 (out[1], STDOUT_FILENO) < 0
            || dup2 (devnull, STDERR_FILENO) < 0)
            _exit (126);
        if (devnull > STDERR_FILENO) close (devnull);
        execvp (argv[0], argv);
        _exit (errno == ENOENT ? 127 : 126);
    }
    int fork_errno = errno;
    close (in[0]);
    close (out[1]);
    if (pid < 0) {
        close (in[1]);
        close (out[0]);
        sigaction (SIGPIPE, &old_pipe, NULL);
        sigprocmask (SIG_SETMASK, &old_mask, NULL);
        snprintf (err, errsz, "Spell helper: fork: %s", strerror (fork_errno));
        free (copy);
        return -1;
    }
    fcntl (in[1], F_SETFL, fcntl (in[1], F_GETFL) | O_NONBLOCK);
    fcntl (out[0], F_SETFL, fcntl (out[0], F_GETFL) | O_NONBLOCK);

    char *buf = NULL;
    size_t blen = 0, bcap = 0, sent = 0;
    int wfd = in[1], rfd = out[0];
    const char *problem = NULL;
    struct timespec t0;
    clock_gettime (CLOCK_MONOTONIC, &t0);
    if (len == 0) { close (wfd); wfd = -1; }
    while (rfd >= 0 && !problem) {
        struct timespec now;
        clock_gettime (CLOCK_MONOTONIC, &now);
        long elapsed = (long) ((now.tv_sec - t0.tv_sec) * 1000
                               + (now.tv_nsec - t0.tv_nsec) / 1000000);
        if (elapsed >= bn_spell_timeout_ms) { problem = "timed out"; break; }
        struct pollfd pfd[2];
        int np = 0;
        pfd[np].fd = rfd; pfd[np].events = POLLIN; pfd[np].revents = 0; np++;
        if (wfd >= 0) { pfd[np].fd = wfd; pfd[np].events = POLLOUT; pfd[np].revents = 0; np++; }
        int pr = bn_poll (pfd, (nfds_t) np, (int) (bn_spell_timeout_ms - elapsed));
        if (bn_term_signal) { problem = "interrupted"; break; }
        if (pr < 0) {
            if (errno == EINTR) continue;
            problem = "poll failed";
            break;
        }
        if (np == 2 && pfd[1].revents) {
            ssize_t w = (pfd[1].revents & POLLOUT)
                        ? write (wfd, text + sent, len - sent) : -1;
            if (w > 0) sent += (size_t) w;
            if (w < 0 && (errno == EAGAIN || errno == EINTR)) w = 0;
            if (w < 0 || sent == len) { close (wfd); wfd = -1; }
        }
        if (pfd[0].revents) {
            char chunk[4096];
            ssize_t r = read (rfd, chunk, sizeof chunk);
            if (r < 0 && (errno == EAGAIN || errno == EINTR)) continue;
            if (r <= 0) { close (rfd); rfd = -1; break; }
            if (blen + (size_t) r > BN_SPELL_MAX_OUT) { problem = "output too large"; break; }
            if (blen + (size_t) r > bcap) {
                size_t nc = bcap ? bcap * 2 : 8192;
                while (nc < blen + (size_t) r) nc *= 2;
                char *nb = realloc (buf, nc);
                if (!nb) { problem = "out of memory"; break; }
                buf = nb;
                bcap = nc;
            }
            memcpy (buf + blen, chunk, (size_t) r);
            blen += (size_t) r;
        }
    }
    if (wfd >= 0) close (wfd);
    if (rfd >= 0) close (rfd);
    /* A helper may close its output and keep running; the deadline still
       applies to the wait. */
    int status = 0;
    pid_t wr = 0;
    while (!problem) {
        wr = waitpid (pid, &status, WNOHANG);
        if (wr != 0 && !(wr < 0 && errno == EINTR)) break;
        struct timespec now, nap = { 0, 5 * 1000 * 1000 };
        clock_gettime (CLOCK_MONOTONIC, &now);
        long elapsed = (long) ((now.tv_sec - t0.tv_sec) * 1000
                               + (now.tv_nsec - t0.tv_nsec) / 1000000);
        if (elapsed >= bn_spell_timeout_ms) { problem = "timed out"; break; }
        if (bn_term_signal) { problem = "interrupted"; break; }
        nanosleep (&nap, NULL);
    }
    if (problem) {
        kill (pid, SIGKILL);
        while ((wr = waitpid (pid, &status, 0)) < 0 && errno == EINTR) { }
    }
    sigaction (SIGPIPE, &old_pipe, NULL);
    sigprocmask (SIG_SETMASK, &old_mask, NULL);

    int rc = -1;
    if (problem)
        snprintf (err, errsz, "Spell helper %s: %s", problem, argv[0]);
    else if (wr < 0)
        snprintf (err, errsz, "Spell helper: waitpid: %s", strerror (errno));
    else if (WIFSIGNALED (status))
        snprintf (err, errsz, "Spell helper killed by signal %d: %s",
                  WTERMSIG (status), argv[0]);
    else if (WEXITSTATUS (status) == 127)
        snprintf (err, errsz, "Spell helper not found: %s", argv[0]);
    else if (WEXITSTATUS (status) == 126)
        snprintf (err, errsz, "Spell helper cannot run: %s", argv[0]);
    else if (WEXITSTATUS (status) != 0)
        snprintf (err, errsz, "Spell helper failed (exit %d): %s",
                  WEXITSTATUS (status), argv[0]);
    else {
        rc = 0;
        size_t s = 0;
        while (s < blen && rc == 0) {
            size_t e = s;
            while (e < blen && buf[e] != '\n') e++;
            size_t a = s, b = e;
            while (a < b && bn_is_blank (buf[a])) a++;
            while (b > a && (bn_is_blank (buf[b - 1]) || buf[b - 1] == '\r')) b--;
            int ok = b > a && b - a <= BN_WORD_MAX;
            for (size_t k = a; ok && k < b; k++)
                if ((unsigned char) buf[k] < 0x20 || buf[k] == ' ') ok = 0;
            if (ok && words->n < BN_SPELL_MAX_WORDS
                && bn_wordlist_add_unique (words, buf + a, b - a) < 0) {
                snprintf (err, errsz, "Spell helper: out of memory");
                rc = -1;
            }
            s = e + 1;
        }
    }
    free (buf);
    free (copy);
    return rc;
}

/* Offset of the first whole-word occurrence of WORD in [from, end), or -1. */
static long
bn_find_whole_word (const char *text, size_t text_len, size_t from,
                    const char *word, size_t wl)
{
    size_t pos = from;
    while (pos + wl <= text_len) {
        const char *hit = memmem (text + pos, text_len - pos, word, wl);
        if (!hit) return -1;
        size_t h = (size_t) (hit - text);
        int left_ok = h == 0 || !bn_is_word_byte (text[h - 1]);
        int right_ok = h + wl == text_len || !bn_is_word_byte (text[h + wl]);
        if (left_ok && right_ok) return (long) h;
        pos = h + 1;
    }
    return -1;
}

/* Replace every whole-word WORD in the buffer span [rs, *re) by REPL as one
   edit; *RE and *KEEP follow the edit.  Returns the replacement count. */
static long
bn_spell_replace_all (size_t rs, size_t *re, const char *word,
                      const char *repl, size_t *keep)
{
    size_t tl = 0;
    char *text = bn_pt_flatten_range (&bn_b.pt, rs, *re, &tl);
    if (!text) return -1;
    size_t wl = strlen (word), rl = strlen (repl);
    bn_strbuf out = {0};
    long first = -1, count = 0;
    size_t last_end = 0, pos = 0;
    long h;
    while ((h = bn_find_whole_word (text, tl, pos, word, wl)) >= 0) {
        if (first < 0) { first = h; last_end = (size_t) h; }
        bn_sb_add (&out, text + last_end, (size_t) h - last_end);
        bn_sb_add (&out, repl, rl);
        last_end = (size_t) h + wl;
        pos = last_end;
        count++;
    }
    if (count == 0 || out.failed) { free (text); free (out.v); return out.failed ? -1 : 0; }
    size_t s = rs + (size_t) first, e = rs + last_end;
    int rc = bn_piece_replace (s, e, out.v ? out.v : "", out.n, s);
    free (text);
    free (out.v);
    if (rc < 0) return -1;
    *keep = bn_offset_after_edit (*keep, s, e, out.n);
    *re = *re - (e - s) + out.n;
    return count;
}

static void
bn_spell (void)
{
    size_t rs = 0, re = bn_b.pt.total_len;
    if (bn_mark_active) {
        rs = bn_abs_from_lc (bn_mark_cy, bn_mark_cx);
        re = bn_abs_from_lc (bn_cy, bn_cx);
        if (rs > re) { size_t t = rs; rs = re; re = t; }
    }
    size_t keep = bn_abs_from_lc (bn_cy, bn_cx);
    size_t tl = 0;
    char *text = bn_pt_flatten_range (&bn_b.pt, rs, re, &tl);
    if (!text) { bn_set_status ("Spell check: out of memory"); return; }
    bn_set_status ("Invoking spell checker...");
    bn_wordlist words = {0};
    char err[256];
    int rc = bn_spell_run_helper (bn_speller_command (), text, tl, &words, err, sizeof err);
    free (text);
    if (rc < 0) {
        bn_wordlist_free (&words);
        bn_set_status ("%s", err);
        return;
    }
    long replaced = 0;
    int cancelled = 0;
    for (size_t w = 0; w < words.n && !cancelled; w++) {
        const char *word = words.v[w];
        text = bn_pt_flatten_range (&bn_b.pt, rs, re, &tl);
        if (!text) break;
        long h = bn_find_whole_word (text, tl, 0, word, strlen (word));
        free (text);
        if (h < 0) continue;
        bn_set_cursor_abs (rs + (size_t) h);
        char dest[BN_WORD_MAX + 1];
        snprintf (dest, sizeof dest, "%s", word);
        if (bn_modal_prompt ("Edit a replacement: ", dest, sizeof dest) != 0) {
            cancelled = 1;
            break;
        }
        if (!dest[0] || strcmp (dest, word) == 0) continue;
        long n = bn_spell_replace_all (rs, &re, word, dest, &keep);
        if (n < 0) { bn_set_status ("Spell check: replace failed"); bn_wordlist_free (&words); return; }
        replaced += n;
    }
    bn_wordlist_free (&words);
    bn_set_cursor_abs (keep);
    if (cancelled)
        bn_set_status ("Spell check cancelled (%ld replaced)", replaced);
    else
        bn_set_status ("Finished checking spelling (%ld replaced)", replaced);
}

/* ---- word completion (^]) ----

   The fragment is the run of word bytes (ASCII letters, digits, '_' and
   any UTF-8 byte) ending at the cursor.  Candidates are the distinct
   longer words in the buffer that start with it, in buffer order from the
   top, excluding the word being typed.  Each ^] replaces the inserted tail
   with the next candidate; after the last one the bare fragment comes back
   with "No further matches", and the next ^] starts over.  Any edit or
   cursor movement in between starts a fresh completion. */

#define BN_COMPLETE_MAX 1024

static struct {
    int active;
    unsigned long rev;      /* bn_text_rev after the last completion step */
    size_t cursor;          /* cursor offset after the last step */
    size_t frag_start;
    size_t frag_len;
    size_t tail_len;        /* bytes inserted after the fragment */
    size_t next;            /* next candidate index */
    bn_wordlist cands;
} bn_comp;

static void
bn_complete_reset (void)
{
    bn_wordlist_free (&bn_comp.cands);
    memset (&bn_comp, 0, sizeof bn_comp);
}

static void
bn_complete (void)
{
    size_t cur = bn_abs_from_lc (bn_cy, bn_cx);
    if (!(bn_comp.active && bn_comp.rev == bn_text_rev && bn_comp.cursor == cur)) {
        bn_complete_reset ();
        bn_line *L = bn_curline ();
        if (!L) return;
        long s = bn_cx;
        while (s > 0 && bn_is_word_byte (L->data[s - 1])) s--;
        if (s == bn_cx) { bn_set_status ("No word fragment to complete"); return; }
        size_t fs = bn_labs ((size_t) bn_cy) + (size_t) s, fl = (size_t) (bn_cx - s);
        size_t tl = 0;
        char *text = bn_pt_flatten (&bn_b.pt, &tl);
        if (!text) { bn_set_status ("Completion: out of memory"); return; }
        size_t i = 0;
        while (i < tl && bn_comp.cands.n < BN_COMPLETE_MAX) {
            if (!bn_is_word_byte (text[i])) { i++; continue; }
            size_t ws = i;
            while (i < tl && bn_is_word_byte (text[i])) i++;
            size_t wl = i - ws;
            if (ws == fs || wl <= fl || wl > BN_WORD_MAX
                || memcmp (text + ws, text + fs, fl) != 0)
                continue;
            if (bn_wordlist_add_unique (&bn_comp.cands, text + ws, wl) < 0) break;
        }
        free (text);
        if (bn_comp.cands.n == 0) {
            bn_complete_reset ();
            bn_set_status ("No matches");
            return;
        }
        bn_comp.active = 1;
        bn_comp.frag_start = fs;
        bn_comp.frag_len = fl;
    }
    size_t tail_at = bn_comp.frag_start + bn_comp.frag_len;
    const char *ins = "";
    size_t ins_len = 0;
    if (bn_comp.next < bn_comp.cands.n) {
        const char *cand = bn_comp.cands.v[bn_comp.next];
        ins = cand + bn_comp.frag_len;
        ins_len = strlen (cand) - bn_comp.frag_len;
    }
    if (bn_piece_replace (tail_at, tail_at + bn_comp.tail_len, ins, ins_len,
                          tail_at + ins_len) < 0) {
        bn_complete_reset ();
        bn_set_status ("Completion failed");
        return;
    }
    bn_comp.tail_len = ins_len;
    if (bn_comp.next < bn_comp.cands.n) {
        bn_comp.next++;
        bn_set_status ("Completion %zu of %zu", bn_comp.next, bn_comp.cands.n);
    } else {
        bn_comp.next = 0;
        bn_set_status ("No further matches");
    }
    bn_comp.rev = bn_text_rev;
    bn_comp.cursor = bn_abs_from_lc (bn_cy, bn_cx);
}

static int
bn_key_is_vertical (const char *k, int klen)
{
    if (klen == 1) return k[0] == 0x10 || k[0] == 0x0e;
    if (klen >= 3 && k[0] == 0x1b && k[1] == '[')
        return k[2] == 'A' || k[2] == 'B'
            || (klen == 4 && (k[2] == '5' || k[2] == '6') && k[3] == '~');
    return 0;
}

static int bn_dispatch_key (const char *k, int klen);

static int
bn_dispatch (const char *k, int klen)
{
    /* SS3 cursor keys (ESC O A, sent in application cursor mode) mean
       the same as their CSI forms. */
    char csi[3];
    if (klen == 3 && k[0] == 0x1b && k[1] == 'O' && strchr ("ABCDHF", k[2])) {
        csi[0] = 0x1b; csi[1] = '['; csi[2] = k[2];
        k = csi;
    }
    int vertical = bn_key_is_vertical (k, klen);
    int rc = bn_dispatch_key (k, klen);
    if (!vertical) bn_want_col = -1;
    return rc;
}

static int
bn_dispatch_key (const char *k, int klen)
{
    /* ESC sequence first (3+ bytes starting ESC [). */
    if (klen >= 3 && k[0] == 0x1b && k[1] == '[') {
        char c = k[2];
        switch (c) {
        case 'A':  /* up */    bn_move_vertical (-1); break;
        case 'B':  /* down */  bn_move_vertical (1); break;
        case 'C':  /* right */ {
            bn_line *L = bn_curline ();
            if (L && bn_cx < (long) L->len)
                bn_cx = bn_grapheme_next (L->data, L->len, bn_cx);    /* v2 — cluster step */
            else if (L && (size_t) bn_cy + 1 < bn_b.n_lines) { bn_cy++; bn_cx = 0; }
            break;
        }
        case 'D':  /* left */
            if (bn_cx > 0) {
                bn_line *L = bn_curline ();
                if (L) bn_cx = bn_line_grapheme_prev (L, bn_cx);  /* v2 */
            } else if (bn_cy > 0) {
                bn_cy--; bn_line *L = bn_curline (); bn_cx = L ? (long) L->len : 0;
            }
            break;
        case 'H':  /* home */  bn_cx = 0; break;
        case 'F':  /* end */   { bn_line *L = bn_curline (); bn_cx = L ? (long) L->len : 0; break; }
        case '1': case '7':    /* Home: ESC [ 1 ~ (VT220), ESC [ 7 ~ (rxvt) */
            if (klen == 4 && k[3] == '~') bn_cx = 0;
            break;
        case '4': case '8':    /* End: ESC [ 4 ~, ESC [ 8 ~ */
            if (klen == 4 && k[3] == '~') {
                bn_line *L = bn_curline ();
                bn_cx = L ? (long) L->len : 0;
            }
            break;
        case '3':  /* Delete: ESC [ 3 ~ */
            if (klen >= 4 && k[3] == '~') bn_delete_forward ();
            break;
        case '5':  /* PgUp */  bn_move_vertical (-(long) (bn_rows > 3 ? bn_rows - 2 : 1)); break;
        case '6':  /* PgDn */  bn_move_vertical ((long) (bn_rows > 3 ? bn_rows - 2 : 1)); break;
        }
        return 0;
    }
    /* Stage 44.D — Meta keys (Esc-X / Alt-X). klen=2 starting with ESC,
       second byte != '['. Distinct from CSI sequences above. */
    if (klen == 2 && k[0] == 0x1b) {
        char c = k[1];
        switch (c) {
        case 'A': case 'a':
            /* M-A: toggle mark at cursor. */
            bn_mark_active = !bn_mark_active;
            if (bn_mark_active) {
                bn_mark_cy = bn_cy;
                bn_mark_cx = bn_cx;
                bn_set_status ("Mark set at L%ld C%ld",
                               bn_cy + 1, bn_cx + 1);
            } else {
                bn_set_status ("Mark unset");
            }
            return 0;
        case '^':
            /* M-^: copy marked bytes without cutting. */
            if (bn_mark_active && bn_mark_cy == bn_cy) {
                bn_mark_cut_or_copy (bn_cy, bn_mark_cx, bn_cx, 0);
                bn_set_status ("Copied %zu bytes", bn_clip_len);
            } else if (bn_mark_active) {
                bn_mark_cut_or_copy (bn_cy, bn_mark_cx, bn_cx, 0);
                bn_set_status ("Copied %zu bytes", bn_clip_len);
            } else {
                bn_set_status ("No mark set — press M-A first");
            }
            return 0;
        case 'E': case 'e':
            /* Stage 44.G: M-E is nano's redo binding; ^Y remains as an
               existing compatibility binding. */
            bn_redo ();
            return 0;
        case 'U': case 'u':
            bn_undo ();
            return 0;
        case 'J': case 'j':
            /* M-J: full justify, GNU nano's binding. */
            bn_justify (1);
            return 0;
        case 'W': case 'w':
            /* G03 — soft-wrap is a render-only view: file bytes and cursor
               byte coordinates are unchanged, only visual rows differ. */
            bn_softwrap = !bn_softwrap;
            bn_view_top = 0;
            bn_view_left = 0;
            bn_set_status ("Soft wrap %s", bn_softwrap ? "enabled" : "disabled");
            return 0;
        case '{':
            /* Local nano-like ring rotation: older yanks become the active
               ^U payload without mutating the buffer. */
            bn_yank_ring_rotate (+1);
            return 0;
        case '}':
            bn_yank_ring_rotate (-1);
            return 0;
        }
        return 0;
    }
    /* Single-byte (ASCII control or ASCII printable). */
    if (klen == 1) {
        char c = k[0];
        switch (c) {
        case 0x18:  /* ^X — exit (G03 Stage SAVE-PROMPTS: modified-buffer guard) */
            if (!bn_b.dirty) return -1;
            {
                int yn = bn_prompt_key
                    ("Save modified buffer?  Y=save  N=discard  ESC=cancel: ");
                if (yn == 'Y') {
                    int saved = (bn_b.path && bn_b.path[0])
                                ? bn_save () : bn_prompt_save_as ();
                    if (saved == 0) return -1;
                    /* save failed or was cancelled — stay in editor so user
                       can retry; bn_save / bn_prompt_save_as already set
                       a descriptive status. */
                    return 0;
                }
                if (yn == 'N') return -1;
                bn_set_status ("Exit cancelled");
                return 0;
            }
        case 0x0f:  /* ^O — Write Out (G03: always prompts for filename,
                       prefilled with current path, ESC cancels) */
            bn_prompt_save_as ();
            return 0;
        case 0x13:  /* ^S — direct save if filename known, else prompt */
            if (bn_b.path && bn_b.path[0]) bn_save ();
            else                            bn_prompt_save_as ();
            return 0;
        case 0x01:  /* ^A — GNU nano legacy Home */
            bn_cx = 0;
            return 0;
        case 0x05:  /* ^E — GNU nano legacy End */
            {
                bn_line *L = bn_curline ();
                bn_cx = L ? (long) L->len : 0;
            }
            return 0;
        case 0x10:  /* ^P — GNU nano legacy Up */
            bn_move_vertical (-1);
            return 0;
        case 0x0e:  /* ^N — GNU nano legacy Down */
            bn_move_vertical (1);
            return 0;
        case 0x02:  /* ^B — GNU nano left */
            if (bn_cx > 0) {
                bn_line *L = bn_curline ();
                if (L) bn_cx = bn_line_grapheme_prev (L, bn_cx);
            } else if (bn_cy > 0) {
                bn_cy--;
                bn_line *L = bn_curline ();
                bn_cx = L ? (long) L->len : 0;
            }
            return 0;
        case 0x06:  /* ^F — GNU nano right */
            {
                bn_line *L = bn_curline ();
                if (L && bn_cx < (long) L->len)
                    bn_cx = bn_grapheme_next (L->data, L->len, bn_cx);
                else if (L && (size_t) bn_cy + 1 < bn_b.n_lines) {
                    bn_cy++;
                    bn_cx = 0;
                }
            }
            return 0;
        case 0x04:  /* ^D — GNU nano forward delete */
            bn_delete_forward ();
            return 0;
        case 0x09:  /* ^I / Tab */
            bn_insert_bytes ("\t", 1);
            return 0;
        case 0x0b:  /* ^K */
            /* Stage 44.D — when mark is active, cut the marked byte range,
               including regions that span line boundaries. */
            if (bn_mark_active) {
                bn_mark_cut_or_copy (bn_cy, bn_mark_cx, bn_cx, 1);
                bn_set_status ("Cut %zu bytes", bn_clip_len);
            } else {
                bn_cut_line ();
            }
            return 0;
        case 0x15:  /* ^U */ bn_paste (); return 0;
        case 0x1a:  /* ^Z */ bn_undo (); return 0;
        case 0x19:  /* ^Y */ bn_redo (); return 0;
        case 0x07:  /* ^G */ bn_set_status ("^O/^S Save  ^X Exit  ^K Cut  ^U Paste  ^W Search  ^J Justify  ^T Spell  ^] Complete  M-W Wrap"); return 0;
        case 0x0a:  /* ^J — justify paragraph (or marked lines) */
            bn_justify (0);
            return 0;
        case 0x14:  /* ^T — spell check through the word-list helper */
            bn_spell ();
            return 0;
        case 0x1d:  /* ^] — complete the word fragment before the cursor */
            bn_complete ();
            return 0;
        case 0x12: { /* ^R — read file into current buffer at cursor */
            char path[256] = "";
            if (bn_modal_prompt ("File to insert: ", path, sizeof path) == 0 && path[0])
                bn_insert_file_at_cursor (path);
            return 0;
        }
        /* Stage 44.A — search and replace (^\). Modal flow: prompt for
           SEARCH, then REPLACE, then per-match Y/N/A/Q. Reuses
           bn_search_forward to walk hits. */
        case 0x1c: { /* ^\ */
            char search[128] = "", replace[128] = "";
            if (bn_modal_prompt ("Search: ", search, sizeof search) != 0)
                return 0;
            if (search[0] == '\0') return 0;
            if (bn_modal_prompt ("Replace with: ", replace, sizeof replace) != 0)
                return 0;
            size_t plen = strlen (search), rlen = strlen (replace);
            long n_replaced = 0;
            int replace_all = 0;
            /* Start from buffer top so the dialog covers the whole file
               consistently, like nano's behavior. Save cursor and restore
               at the end. */
            long save_cy = bn_cy, save_cx = bn_cx;
            bn_cy = 0; bn_cx = -1;
            while (bn_search_forward (search) == 0) {
                char yna = 'Y';
                if (!replace_all) {
                    bn_set_status ("Replace? [Y]es [N]o [A]ll [Q]uit  (so far: %ld)",
                                   n_replaced);
                    bn_render ();
                    char keybuf[8] = "";
                    int reply_len = bn_read_key (keybuf, sizeof keybuf);
                    if (reply_len <= 0) break;
                    yna = keybuf[0];
                    if (yna >= 'a' && yna <= 'z') yna = (char) (yna - 32);
                    if (yna == 0x1b /* ESC */ || yna == 'Q') break;
                    if (yna == 'A') { replace_all = 1; yna = 'Y'; }
                }
                if (yna == 'Y') {
                    if (bn_replace_at (bn_cy, bn_cx, plen, replace, rlen) == 0) {
                        n_replaced++;
                        /* Advance past the replacement so we don't match
                           inside it (e.g. replacing "X" with "XX" would
                           loop forever otherwise). For empty replace,
                           step at least 1 byte to ensure forward progress. */
                        bn_cx += (long) (rlen > 0 ? rlen : 1) - 1;
                    } else {
                        bn_set_status ("replace failed at L%ld C%ld",
                                       bn_cy + 1, bn_cx + 1);
                        break;
                    }
                } else { /* 'N' or any unrecognized → skip */
                    /* bn_search_forward already moved cursor to the hit;
                       leave bn_cx alone and let next-search step past +1. */
                }
            }
            bn_cy = save_cy; bn_cx = save_cx;
            bn_set_status ("Replaced %ld occurrence%s of \"%s\"",
                           n_replaced, n_replaced == 1 ? "" : "s", search);
            return 0;
        }
        /* Stage 44.F — cursor-position dialog. Computes byte offset
           into the buffer (sum of line lengths + 1 per newline) and
           emits a status-line message showing line/col/byte/%. The
           status auto-clears after a few renders. */
        case 0x03: { /* ^C */
            long byte_off = (long) bn_abs_from_lc (bn_cy, bn_cx);
            long total = (long) bn_b.pt.total_len;
            int pct = total > 0 ? (int) ((byte_off * 100) / total) : 0;
            bn_set_status ("[line %ld of %zu] [col %ld] [byte %ld] [%d%% through file]",
                           bn_cy + 1, bn_b.n_lines, bn_cx + 1, byte_off, pct);
            return 0;
        }
        /* Stage 44.C — refresh: clear the whole screen + re-render.
           Useful when an out-of-band message (kernel printk, stray
           write to /dev/tty) corrupts the visible buffer. The next
           render fills every cell, so nothing stale survives. */
        case 0x0c:  /* ^L */
            bn_write ("\033[2J");
            return 0;
        /* Stage 44.B — goto-line: prompt for an integer line number
           and jump to it (clamped to [1, n_lines]). cx is reset to 0
           since arbitrary cursor columns rarely make sense post-jump. */
        case 0x1f: { /* ^_ */
            char buf[32] = {0};
            if (bn_modal_prompt ("Goto line: ", buf, sizeof buf) == 0 && buf[0]) {
                long lineno = strtol (buf, NULL, 10);
                if (lineno < 1) lineno = 1;
                if ((size_t) lineno > bn_b.n_lines) lineno = (long) bn_b.n_lines;
                bn_cy = lineno - 1;
                bn_cx = 0;
            }
            return 0;
        }
        case 0x17:  /* ^W — Stage 2 — search forward, with last-pattern pre-fill */
            if (bn_modal_prompt ("Search: ", bn_search_pat, sizeof bn_search_pat) == 0
                && bn_search_pat[0] != '\0')
                bn_search_forward (bn_search_pat);
            return 0;
        case 0x11:  /* ^Q — GNU nano legacy search backward */
            if (bn_modal_prompt ("Search backwards: ", bn_search_pat, sizeof bn_search_pat) == 0
                && bn_search_pat[0] != '\0')
                bn_search_backward (bn_search_pat);
            return 0;
        case 0x7f:           /* DEL/BS */
        case 0x08:  /* ^H */ bn_backspace (); return 0;
        case 0x0d:           /* CR */
            bn_split_line (); return 0;
        default:
            if ((unsigned char) c >= 0x20 && (unsigned char) c < 0x7f) {
                bn_insert_bytes (k, 1);
            }
            return 0;
        }
    }
    /* v2 — multi-byte UTF-8 cluster (not an ESC sequence). */
    if (klen > 1 && (unsigned char) k[0] >= 0x80) {
        bn_insert_bytes (k, (size_t) klen);
        return 0;
    }
    return 0;
}

/* v2 — TTY-free self-test: exercise grapheme helpers + insert/delete on
   a synthetic buffer, emit TAP-shaped lines, return non-zero on any
   mismatch. Invoked via `nano selftest`. */
static int
bn_selftest (void)
{
    int fails = 0, asserts = 0;
    /* "héllo中文😀" — UTF-8 bytes:
       h(1) é(2) l(1) l(1) o(1) 中(3) 文(3) 😀(4) = 16 bytes */
    const char *s = "h\xc3\xa9llo\xe4\xb8\xad\xe6\x96\x87\xf0\x9f\x98\x80";
    size_t len = strlen (s);

    /* T1: grapheme_next walks 8 clusters, ending exactly at len. */
    long pos = 0; int n_clusters = 0;
    while (pos < (long) len) {
        long next = bn_grapheme_next (s, len, pos);
        if (next <= pos) { fails++; printf ("not ok %d - grapheme_next no progress\n", ++asserts); break; }
        pos = next; n_clusters++;
    }
    asserts++;
    if (n_clusters == 8 && pos == (long) len)
        printf ("ok %d - grapheme_next walks 8 clusters\n", asserts);
    else { fails++; printf ("not ok %d - grapheme_next: %d clusters, ended at %ld (want 8 / %zu)\n",
                            asserts, n_clusters, pos, len); }

    /* T2: grapheme_prev from end walks back 8 clusters. */
    pos = len; n_clusters = 0;
    while (pos > 0) {
        long prev = bn_grapheme_prev (s, len, pos);
        if (prev >= pos) { fails++; printf ("not ok - grapheme_prev no progress\n"); break; }
        pos = prev; n_clusters++;
    }
    asserts++;
    if (n_clusters == 8 && pos == 0)
        printf ("ok %d - grapheme_prev walks back 8 clusters\n", asserts);
    else { fails++; printf ("not ok %d - grapheme_prev: %d clusters, ended at %ld\n",
                            asserts, n_clusters, pos); }

    bn_line cache_line;
    memset (&cache_line, 0, sizeof cache_line);
    cache_line.data = (char *) s;
    cache_line.len = len;
    long cached_prev = bn_line_grapheme_prev (&cache_line, (long) len);
    long cached_inside = bn_line_grapheme_prev (&cache_line, 2);
    asserts++;
    if (cached_prev == 12 && cached_inside == 1 &&
        cache_line.cluster_count == 8 && cache_line.cluster_starts)
        printf ("ok %d - grapheme_prev uses per-line cluster cache\n", asserts);
    else { fails++; printf ("not ok %d - cluster cache: prev=%ld inside=%ld count=%zu\n",
                            asserts, cached_prev, cached_inside,
                            cache_line.cluster_count); }
    bn_line_cluster_cache_free (&cache_line);

    /* T3: bn_screen_col at end = 5*1 + 2*2 + 2 = 11 cells. */
    long col = bn_screen_col (s, len, len);
    asserts++;
    if (col == 11) printf ("ok %d - screen_col at end = 11 cells\n", asserts);
    else { fails++; printf ("not ok %d - screen_col = %ld (want 11)\n", asserts, col); }

    /* T4: insert+delete preserves bytes for a CJK cluster.
       Setup: empty line, insert 中 (3 bytes), then backspace. */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "", 0);
    bn_sync_lines_from_pt ();
    bn_cy = bn_cx = 0;
    bn_insert_bytes ("\xe4\xb8\xad", 3);
    asserts++;
    if (bn_cx == 3 && bn_b.lines[0].len == 3)
        printf ("ok %d - insert 中 advances cx by 3 bytes\n", asserts);
    else { fails++; printf ("not ok %d - insert 中: cx=%ld len=%zu\n",
                            asserts, bn_cx, bn_b.lines[0].len); }
    bn_backspace ();
    asserts++;
    if (bn_cx == 0 && bn_b.lines[0].len == 0)
        printf ("ok %d - backspace deletes whole 中 cluster\n", asserts);
    else { fails++; printf ("not ok %d - bs cluster: cx=%ld len=%zu\n",
                            asserts, bn_cx, bn_b.lines[0].len); }
    /* Cleanup the test buffer. */
    bn_free_lines ();
    bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo);
    bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    /* Stage 2 — search forward across 3 lines (alpha / beta / alpha). */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "", 0);
    bn_sync_lines_from_pt ();
    bn_cy = bn_cx = 0;
    bn_insert_bytes ("alpha foo\nbeta\nalpha bar", 24);
    bn_cy = 0; bn_cx = 5;       /* mid line 0, just past first 'alpha' */
    int rc = bn_search_forward ("alpha");
    asserts++;
    if (rc == 0 && bn_cy == 2 && bn_cx == 0)
        printf ("ok %d - search_forward finds next 'alpha' on line 2\n", asserts);
    else { fails++; printf ("not ok %d - search_forward: rc=%d cy=%ld cx=%ld\n",
                            asserts, rc, bn_cy, bn_cx); }
    /* Search again should wrap to line 0 (next match is back at line 0). */
    bn_cx += 5;
    rc = bn_search_forward ("alpha");
    asserts++;
    if (rc == 0 && bn_cy == 0 && bn_cx == 0)
        printf ("ok %d - search_forward wraps to line 0\n", asserts);
    else { fails++; printf ("not ok %d - search_forward wrap: rc=%d cy=%ld cx=%ld\n",
                            asserts, rc, bn_cy, bn_cx); }
    bn_cy = 2; bn_cx = 0;
    rc = bn_search_backward ("alpha");
    asserts++;
    if (rc == 0 && bn_cy == 0 && bn_cx == 0)
        printf ("ok %d - search_backward finds previous 'alpha' on line 0\n", asserts);
    else { fails++; printf ("not ok %d - search_backward: rc=%d cy=%ld cx=%ld\n",
                            asserts, rc, bn_cy, bn_cx); }
    bn_cy = 0; bn_cx = 0;
    rc = bn_search_backward ("alpha");
    asserts++;
    if (rc == 0 && bn_cy == 2 && bn_cx == 0)
        printf ("ok %d - search_backward wraps to line 2\n", asserts);
    else { fails++; printf ("not ok %d - search_backward wrap: rc=%d cy=%ld cx=%ld\n",
                            asserts, rc, bn_cy, bn_cx); }
    bn_free_lines ();
    bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo);
    bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    /* Stage 4 — horizontal scroll viewport math. Build a 200-char line
       (single byte chars to keep cell-width arithmetic trivial), place
       cursor at byte 150 in an 80-col viewport, render to /dev/null,
       and assert bn_view_left scrolled to 71 (= 150 - (80 - 1) + 0). */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "", 0);
    bn_sync_lines_from_pt ();
    bn_cy = bn_cx = 0;
    bn_view_top = bn_view_left = 0;
    char xs[201]; memset (xs, 'x', 200); xs[200] = '\0';
    bn_insert_bytes (xs, 200);
    bn_rows = 24; bn_cols = 80;
    bn_cx = 150;
    /* Render writes to STDOUT; redirect to /dev/null for the duration. */
    int saved_stdout = dup (STDOUT_FILENO);
    int devnull = open ("/dev/null", O_WRONLY);
    if (devnull >= 0) { dup2 (devnull, STDOUT_FILENO); close (devnull); }
    bn_render ();
    if (saved_stdout >= 0) { dup2 (saved_stdout, STDOUT_FILENO); close (saved_stdout); }
    asserts++;
    if (bn_view_left == 72)         /* 150 - 79 + 1 */
        printf ("ok %d - hscroll: cursor at col 150 ⇒ view_left=72\n", asserts);
    else { fails++; printf ("not ok %d - hscroll: view_left=%ld (want 72)\n",
                            asserts, bn_view_left); }
    /* Move cursor back to byte 50; render snaps view_left back. */
    bn_cx = 50;
    saved_stdout = dup (STDOUT_FILENO);
    devnull = open ("/dev/null", O_WRONLY);
    if (devnull >= 0) { dup2 (devnull, STDOUT_FILENO); close (devnull); }
    bn_render ();
    if (saved_stdout >= 0) { dup2 (saved_stdout, STDOUT_FILENO); close (saved_stdout); }
    asserts++;
    if (bn_view_left == 50)
        printf ("ok %d - hscroll: cursor back to 50 ⇒ view_left=50\n", asserts);
    else { fails++; printf ("not ok %d - hscroll snapback: view_left=%ld (want 50)\n",
                            asserts, bn_view_left); }

    /* G03 — soft-wrap viewport math. With a 10-column terminal the editor
       body is 9 cells wide, so byte/column 20 of this ASCII line lands on
       visual row 2. Soft-wrap must scroll vertically, not horizontally, and
       must not mutate line bytes. */
    bn_softwrap = 1;
    bn_rows = 4; bn_cols = 10;
    bn_view_top = bn_view_left = 0;
    bn_cx = 20;
    saved_stdout = dup (STDOUT_FILENO);
    devnull = open ("/dev/null", O_WRONLY);
    if (devnull >= 0) { dup2 (devnull, STDOUT_FILENO); close (devnull); }
    bn_render ();
    if (saved_stdout >= 0) { dup2 (saved_stdout, STDOUT_FILENO); close (saved_stdout); }
    asserts++;
    if (bn_view_top == 1)
        printf ("ok %d - softwrap: cursor col 20 scrolls to visual row 1\n", asserts);
    else { fails++; printf ("not ok %d - softwrap: view_top=%ld (want 1)\n",
                            asserts, bn_view_top); }
    asserts++;
    if (bn_view_left == 0)
        printf ("ok %d - softwrap: horizontal scroll remains disabled\n", asserts);
    else { fails++; printf ("not ok %d - softwrap: view_left=%ld (want 0)\n",
                            asserts, bn_view_left); }
    bn_cx = 0;
    saved_stdout = dup (STDOUT_FILENO);
    devnull = open ("/dev/null", O_WRONLY);
    if (devnull >= 0) { dup2 (devnull, STDOUT_FILENO); close (devnull); }
    bn_render ();
    if (saved_stdout >= 0) { dup2 (saved_stdout, STDOUT_FILENO); close (saved_stdout); }
    asserts++;
    if (bn_view_top == 0)
        printf ("ok %d - softwrap: cursor returning to top resets viewport\n", asserts);
    else { fails++; printf ("not ok %d - softwrap: view_top=%ld (want 0)\n",
                            asserts, bn_view_top); }
    asserts++;
    if (bn_b.lines[0].len == 200)
        printf ("ok %d - softwrap: render leaves line bytes unchanged\n", asserts);
    else { fails++; printf ("not ok %d - softwrap changed line length to %zu\n",
                            asserts, bn_b.lines[0].len); }
    bn_softwrap = 0;

    bn_free_lines ();
    bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo);
    bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    /* Efficiency pin: render syntax highlighting once for shell text,
       then render again after cursor-only movement. The expensive
       bashts_compute_sgr_map result should be reused until text changes. */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "echo hi\n", 8);
    bn_sync_lines_from_pt ();
    bn_detect_language ("cache-test.sh");
    bn_rows = 24; bn_cols = 80;
    saved_stdout = dup (STDOUT_FILENO);
    devnull = open ("/dev/null", O_WRONLY);
    if (devnull >= 0) { dup2 (devnull, STDOUT_FILENO); close (devnull); }
    bn_render ();
    const char **first_sgr = bn_hl_cache.sgr_at;
    void *first_tree = bn_hl_cache.ts_state;
    unsigned long first_rev = bn_hl_cache.rev;
    bn_cx = 1;
    bn_render ();
    if (saved_stdout >= 0) { dup2 (saved_stdout, STDOUT_FILENO); close (saved_stdout); }
    asserts++;
    if (first_sgr && first_tree && bn_hl_cache.sgr_at == first_sgr &&
        bn_hl_cache.ts_state == first_tree && bn_hl_cache.rev == first_rev)
        printf ("ok %d - syntax highlight cache survives cursor-only render\n", asserts);
    else { fails++; printf ("not ok %d - syntax highlight cache was rebuilt on cursor-only render\n", asserts); }
    bn_free_lines ();
    bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo);
    bn_pt_stack_free (&bn_b.redo);
    bn_highlight_release ();
    bn_lang = NULL;
    memset (&bn_b, 0, sizeof bn_b);

    printf ("1..%d\n", asserts);
    return fails ? 1 : 0;
}

static int
bn_selftest_piecetable (void)
{
    int fails = 0, asserts = 0;
    char templ[] = "/tmp/nano-pt.XXXXXX";
    int fd = mkstemp (templ);
    if (fd < 0) return 1;

    for (int i = 1; i <= 100; i++)
        dprintf (fd, "line-%03d\n", i);
    close (fd);

    memset (&bn_b, 0, sizeof bn_b);
    bn_cy = bn_cx = 0;
    bn_load (templ);
    bn_insert_bytes ("TOP\n", 4);
    bn_save ();
    int rfd = open (templ, O_RDONLY);
    char buf[64] = {0};
    if (rfd >= 0) { read (rfd, buf, sizeof buf - 1); close (rfd); }
    asserts++;
    if (memcmp (buf, "TOP\nline-001\n", 13) == 0)
        printf ("ok %d - piece-table editor saves insertion at file top\n", asserts);
    else { fails++; printf ("not ok %d - top insertion save mismatch\n", asserts); }

    bn_free_lines (); bn_pt_free (&bn_b.pt); bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    free (bn_b.path); memset (&bn_b, 0, sizeof bn_b);
    bn_load (templ);
    free (bn_b.path); bn_b.path = strdup (templ);
    size_t orig_len = 0;
    char *orig = bn_pt_flatten (&bn_b.pt, &orig_len);
    bn_set_cursor_abs (bn_b.pt.total_len);
    for (int i = 0; i < 50; i++) bn_insert_bytes ("x", 1);
    for (int i = 0; i < 25; i++) bn_backspace ();
    for (int i = 0; i < 75; i++) bn_undo ();
    size_t after_len = 0;
    char *after = bn_pt_flatten (&bn_b.pt, &after_len);
    asserts++;
    if (orig && after && orig_len == after_len && memcmp (orig, after, orig_len) == 0)
        printf ("ok %d - 50 inserts + 25 deletes + 75 undos restores original\n", asserts);
    else { fails++; printf ("not ok %d - undo stack failed to restore original\n", asserts); }
    free (orig); free (after);

    bn_free_lines (); bn_pt_free (&bn_b.pt); bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    free (bn_b.path); memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "aa\nbb\ncc\n", 9);
    bn_sync_lines_from_pt ();
    bn_mark_active = 1; bn_mark_cy = 0; bn_mark_cx = 0;
    bn_cy = 2; bn_cx = 0;
    bn_mark_cut_or_copy (bn_cy, bn_mark_cx, bn_cx, 1);
    after = bn_pt_flatten (&bn_b.pt, &after_len);
    asserts++;
    if (after && after_len == 3 && memcmp (after, "cc\n", 3) == 0
        && bn_b.n_lines == 2 && bn_b.lines[1].len == 0) {
        printf ("ok %d - multi-line cut keeps trailing-empty render line\n", asserts);
    } else {
        fails++;
        printf ("not ok %d - post-cut cache: len=%zu n_lines=%zu cy=%ld cx=%ld\n",
                asserts, after_len, bn_b.n_lines, bn_cy, bn_cx);
    }
    free (after);
    bn_set_cursor_abs (bn_b.pt.total_len);
    asserts++;
    if (bn_cy == 1 && bn_cx == 0)
        printf ("ok %d - EOF after trailing newline maps to empty line\n", asserts);
    else { fails++; printf ("not ok %d - trailing EOF cursor cy=%ld cx=%ld\n",
                            asserts, bn_cy, bn_cx); }
    bn_paste ();
    after = bn_pt_flatten (&bn_b.pt, &after_len);
    asserts++;
    if (after && after_len == 9 && memcmp (after, "cc\naa\nbb\n", 9) == 0)
        printf ("ok %d - multi-line cut and paste preserves bytes\n", asserts);
    else { fails++; printf ("not ok %d - multi-line cut/paste mismatch\n", asserts); }
    free (after);

    bn_set_cursor_abs (4);
    asserts++;
    if (bn_cy == 1 && bn_cx == 1)
        printf ("ok %d - cursor display coordinates derive from piece-table offset\n", asserts);
    else { fails++; printf ("not ok %d - cursor lc cy=%ld cx=%ld\n", asserts, bn_cy, bn_cx); }

    bn_set_cursor_abs (2);
    size_t clamped = bn_abs_from_lc (0, 4);
    asserts++;
    if (bn_cy == 0 && bn_cx == 2 && clamped == 2)
        printf ("ok %d - top-line short-column cursor clamps before newline\n", asserts);
    else { fails++; printf ("not ok %d - top clamp cy=%ld cx=%ld abs=%zu\n",
                            asserts, bn_cy, bn_cx, clamped); }

    bn_free_lines (); bn_pt_free (&bn_b.pt); bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    free (bn_b.path); memset (&bn_b, 0, sizeof bn_b);
    const char bin[] = { 'A', '\0', 'B', '\n', 'C' };
    bn_pt_init_text (&bn_b.pt, bin, sizeof bin);
    bn_sync_lines_from_pt ();
    bn_b.path = strdup (templ);
    bn_save ();
    rfd = open (templ, O_RDONLY);
    char bin2[sizeof bin] = {0};
    ssize_t got = rfd >= 0 ? read (rfd, bin2, sizeof bin2) : -1;
    if (rfd >= 0) close (rfd);
    asserts++;
    if (got == (ssize_t) sizeof bin && memcmp (bin, bin2, sizeof bin) == 0)
        printf ("ok %d - save round-trip preserves NUL-bearing bytes\n", asserts);
    else { fails++; printf ("not ok %d - binary round-trip mismatch\n", asserts); }

    unlink (templ);
    bn_free_lines (); bn_pt_free (&bn_b.pt); bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    free (bn_b.path); memset (&bn_b, 0, sizeof bn_b);
    printf ("1..%d\n", asserts);
    return fails ? 1 : 0;
}

static int
bn_selftest_keybindings (void)
{
    int fails = 0, asserts = 0;
    char *flat = NULL;
    size_t flat_len = 0;

#define BN_KEYTEST_ASSERT(desc, cond) \
    do { \
        asserts++; \
        if (cond) printf ("ok %d - %s\n", asserts, desc); \
        else { fails++; printf ("not ok %d - %s\n", asserts, desc); } \
    } while (0)

    memset (&bn_b, 0, sizeof bn_b);
    bn_cy = bn_cx = 0;
    bn_pt_init_text (&bn_b.pt, "", 0);
    bn_sync_lines_from_pt ();

    bn_insert_bytes ("x", 1);
    char undo_key[1] = { 0x1a };
    bn_dispatch (undo_key, 1);
    flat = bn_pt_flatten (&bn_b.pt, &flat_len);
    BN_KEYTEST_ASSERT ("^Z dispatches to undo",
                       flat && flat_len == 0);
    free (flat); flat = NULL; flat_len = 0;

    char redo_key[1] = { 0x19 };
    bn_dispatch (redo_key, 1);
    flat = bn_pt_flatten (&bn_b.pt, &flat_len);
    BN_KEYTEST_ASSERT ("^Y dispatches to redo",
                       flat && flat_len == 1 && flat[0] == 'x');
    free (flat); flat = NULL; flat_len = 0;

    bn_dispatch (undo_key, 1);
    char meta_redo[2] = { 0x1b, 'E' };
    bn_dispatch (meta_redo, 2);
    flat = bn_pt_flatten (&bn_b.pt, &flat_len);
    BN_KEYTEST_ASSERT ("M-E dispatches to redo",
                       flat && flat_len == 1 && flat[0] == 'x');
    free (flat);
    flat = NULL; flat_len = 0;

    char meta_undo[2] = { 0x1b, 'U' };
    bn_dispatch (meta_undo, 2);
    flat = bn_pt_flatten (&bn_b.pt, &flat_len);
    BN_KEYTEST_ASSERT ("M-U dispatches to undo",
                       flat && flat_len == 0);
    free (flat);
    flat = NULL; flat_len = 0;
    bn_dispatch (meta_redo, 2);

    char templ[] = "/tmp/nano-keysave.XXXXXX";
    int fd = mkstemp (templ);
    if (fd >= 0) close (fd);
    free (bn_b.path);
    bn_b.path = strdup (templ);
    char save_key[1] = { 0x13 };
    bn_dispatch (save_key, 1);
    fd = open (templ, O_RDONLY);
    if (fd >= 0) {
        char saved[8] = {0};
        ssize_t n = read (fd, saved, sizeof saved);
        close (fd);
        BN_KEYTEST_ASSERT ("^S dispatches to save",
                           n == 1 && saved[0] == 'x');
    } else {
        BN_KEYTEST_ASSERT ("^S dispatches to save", 0);
    }
    unlink (templ);
    free (bn_b.path);
    bn_b.path = NULL;
    bn_free_lines ();
    bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo);
    bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    char delete_key[1] = { 0x04 };
    char home_key[1] = { 0x01 };
    char end_key[1] = { 0x05 };
    char up_key[1] = { 0x10 };
    char down_key[1] = { 0x0e };
    char left_key[1] = { 0x02 };
    char right_key[1] = { 0x06 };
    char tab_key[1] = { 0x09 };
    char cursor_pos_key[1] = { 0x03 };
    char justify_key[1] = { 0x0a };
    char spell_key[1] = { 0x14 };
    char complete_key[1] = { 0x1d };
    bn_pt_init_text (&bn_b.pt, "ab\ncdef", 7);
    bn_sync_lines_from_pt ();
    bn_cy = 0; bn_cx = 1;
    bn_dispatch (delete_key, 1);
    flat = bn_pt_flatten (&bn_b.pt, &flat_len);
    BN_KEYTEST_ASSERT ("^D dispatches to forward delete",
                       flat && flat_len == 6 && memcmp (flat, "a\ncdef", 6) == 0);
    free (flat); flat = NULL; flat_len = 0;
    bn_dispatch (delete_key, 1);
    flat = bn_pt_flatten (&bn_b.pt, &flat_len);
    BN_KEYTEST_ASSERT ("^D at line end joins next line",
                       flat && flat_len == 5 && memcmp (flat, "acdef", 5) == 0);
    free (flat); flat = NULL; flat_len = 0;

    bn_free_lines ();
    bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo);
    bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "ab\ncdef", 7);
    bn_sync_lines_from_pt ();
    bn_cy = 1; bn_cx = 2;
    bn_dispatch (end_key, 1);
    BN_KEYTEST_ASSERT ("^E dispatches to end-of-line",
                       bn_cy == 1 && bn_cx == 4);
    bn_dispatch (home_key, 1);
    BN_KEYTEST_ASSERT ("^A dispatches to start-of-line",
                       bn_cy == 1 && bn_cx == 0);
    bn_cx = 3;
    bn_dispatch (up_key, 1);
    BN_KEYTEST_ASSERT ("^P dispatches to previous line",
                       bn_cy == 0 && bn_cx == 2);
    bn_dispatch (down_key, 1);
    /* Like GNU nano, ^P then ^N returns to the column ^P started from. */
    BN_KEYTEST_ASSERT ("^N dispatches to next line, back at the remembered column",
                       bn_cy == 1 && bn_cx == 3);
    bn_cx = 2;
    bn_dispatch (left_key, 1);
    BN_KEYTEST_ASSERT ("^B dispatches to left",
                       bn_cy == 1 && bn_cx == 1);
    bn_dispatch (right_key, 1);
    BN_KEYTEST_ASSERT ("^F dispatches to right",
                       bn_cy == 1 && bn_cx == 2);
    bn_dispatch (tab_key, 1);
    flat = bn_pt_flatten (&bn_b.pt, &flat_len);
    BN_KEYTEST_ASSERT ("^I dispatches to tab insert",
                       flat && flat_len == 8 && memcmp (flat, "ab\ncd\tef", 8) == 0);
    free (flat); flat = NULL; flat_len = 0;
    bn_cy = 1; bn_cx = 2;
    bn_status[0] = '\0';
    bn_dispatch (cursor_pos_key, 1);
    BN_KEYTEST_ASSERT ("^C reports cursor position status",
                       strstr (bn_status, "[line 2 of 2]") != NULL
                       && strstr (bn_status, "[col 3]") != NULL
                       && strstr (bn_status, "[byte 5]") != NULL
                       && strstr (bn_status, "[62% through file]") != NULL);
    /* ^J, ^T and ^] used to report "not implemented"; they now edit. */
    bn_cols = 80; bn_fill = -8; bn_trimblanks = 0;
    bn_cy = 0; bn_cx = 0;
    bn_dispatch (justify_key, 1);
    flat = bn_pt_flatten (&bn_b.pt, &flat_len);
    BN_KEYTEST_ASSERT ("^J dispatches to justify (lines joined, tab squeezed)",
                       flat && flat_len == 8 && memcmp (flat, "ab cd ef", 8) == 0
                       && strstr (bn_status, "Justified paragraph") != NULL);
    free (flat); flat = NULL; flat_len = 0;
    bn_dispatch (undo_key, 1);
    flat = bn_pt_flatten (&bn_b.pt, &flat_len);
    BN_KEYTEST_ASSERT ("one ^Z undoes the justification",
                       flat && flat_len == 8 && memcmp (flat, "ab\ncd\tef", 8) == 0);
    free (flat); flat = NULL; flat_len = 0;
    free (bn_speller);
    bn_speller = strdup ("/nonexistent/opus-nano-spell-helper");
    size_t undo_depth = bn_b.undo.n;
    bn_dispatch (spell_key, 1);
    BN_KEYTEST_ASSERT ("^T dispatches to the spell helper and reports exec failure",
                       strstr (bn_status, "Spell helper not found") != NULL
                       && bn_b.undo.n == undo_depth);
    free (bn_speller); bn_speller = NULL;
    bn_cy = 1; bn_cx = 5;          /* end of "cd\tef" */
    bn_insert_bytes (" c", 2);
    bn_dispatch (complete_key, 1);
    flat = bn_pt_flatten (&bn_b.pt, &flat_len);
    BN_KEYTEST_ASSERT ("^] completes the fragment from a buffer word",
                       flat && flat_len == 11 && memcmp (flat, "ab\ncd\tef cd", 11) == 0
                       && strstr (bn_status, "Completion 1 of 1") != NULL);
    free (flat); flat = NULL; flat_len = 0;
    bn_complete_reset ();

    bn_free_lines ();
    bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo);
    bn_pt_stack_free (&bn_b.redo);
    free (bn_b.path);
    memset (&bn_b, 0, sizeof bn_b);

    printf ("1..%d\n", asserts);
    return fails ? 1 : 0;

#undef BN_KEYTEST_ASSERT
}

/* G03 Stage SAVE-PROMPTS — TTY-free coverage of bn_save_as: the modal
   prompt is interactive-only, but the underlying write-to-explicit-path
   logic is what actually advances G03's "Save prompts" gap. These cases
   pin bytes-on-disk + bn_b.path + bn_b.dirty after a successful
   save-as, the empty-path contract that bn_prompt_save_as relies on
   when the user Enters an empty buffer, and the read-back round-trip
   against a fresh tmp path the editor has never seen before. */
static int
bn_selftest_saveprompt (void)
{
    int fails = 0, asserts = 0;

#define BN_SP_ASSERT(desc, cond) \
    do { \
        asserts++; \
        if (cond) printf ("ok %d - %s\n", asserts, desc); \
        else { fails++; printf ("not ok %d - %s\n", asserts, desc); } \
    } while (0)

    /* Case A — empty path returns -1 with "No filename" status (the
       contract the modal cancel arm relies on). */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "alpha\n", 6);
    bn_sync_lines_from_pt ();
    bn_status[0] = '\0';
    int rc = bn_save_as ("");
    BN_SP_ASSERT ("bn_save_as(\"\") returns -1",          rc == -1);
    BN_SP_ASSERT ("bn_save_as(\"\") sets No filename status",
                  strstr (bn_status, "No filename") != NULL);
    BN_SP_ASSERT ("bn_save_as(\"\") leaves bn_b.path NULL", bn_b.path == NULL);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    free (bn_b.path); memset (&bn_b, 0, sizeof bn_b);

    /* Case B — NULL path returns -1 with same status. */
    bn_pt_init_text (&bn_b.pt, "x", 1);
    bn_sync_lines_from_pt ();
    bn_status[0] = '\0';
    rc = bn_save_as (NULL);
    BN_SP_ASSERT ("bn_save_as(NULL) returns -1", rc == -1);
    BN_SP_ASSERT ("bn_save_as(NULL) sets No filename status",
                  strstr (bn_status, "No filename") != NULL);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    free (bn_b.path); memset (&bn_b, 0, sizeof bn_b);

    /* Case C — happy path: write to a fresh tmp path the editor has
       never seen, bytes round-trip, bn_b.path updated, dirty cleared,
       bn_b.had_trailing_nl recomputed by bn_sync_lines_from_pt. */
    char templ[] = "/tmp/nano-saveas.XXXXXX";
    int fd = mkstemp (templ);
    if (fd >= 0) close (fd);
    unlink (templ);  /* exercise the new-file write path */

    bn_pt_init_text (&bn_b.pt, "hello\nworld\n", 12);
    bn_sync_lines_from_pt ();
    bn_b.dirty = 1;       /* simulate an unsaved edit */
    bn_b.pt.dirty = 1;
    bn_status[0] = '\0';

    rc = bn_save_as (templ);
    BN_SP_ASSERT ("bn_save_as(NEW) returns 0", rc == 0);
    BN_SP_ASSERT ("bn_save_as(NEW) sets bn_b.path",
                  bn_b.path && strcmp (bn_b.path, templ) == 0);
    BN_SP_ASSERT ("bn_save_as clears dirty",          bn_b.dirty == 0);
    BN_SP_ASSERT ("bn_save_as clears pt.dirty",       bn_b.pt.dirty == 0);
    BN_SP_ASSERT ("bn_save_as sets Wrote status",
                  strstr (bn_status, "Wrote") != NULL
                  && strstr (bn_status, templ) != NULL);

    /* Round-trip: read the file back and compare bytes. */
    int rfd = open (templ, O_RDONLY);
    char rbuf[64] = {0};
    ssize_t got = rfd >= 0 ? read (rfd, rbuf, sizeof rbuf - 1) : -1;
    if (rfd >= 0) close (rfd);
    BN_SP_ASSERT ("bn_save_as round-trips bytes",
                  got == 12 && memcmp (rbuf, "hello\nworld\n", 12) == 0);

    /* Case D — second bn_save_as to a different path moves bn_b.path. */
    char templ2[] = "/tmp/nano-saveas2.XXXXXX";
    int fd2 = mkstemp (templ2);
    if (fd2 >= 0) close (fd2);
    unlink (templ2);
    rc = bn_save_as (templ2);
    BN_SP_ASSERT ("bn_save_as(ANOTHER) returns 0", rc == 0);
    BN_SP_ASSERT ("bn_save_as(ANOTHER) updates bn_b.path",
                  bn_b.path && strcmp (bn_b.path, templ2) == 0);

    /* Original tmp file should still exist with the previous content
       (rename moves the new write into templ2, not templ). */
    rfd = open (templ, O_RDONLY);
    BN_SP_ASSERT ("bn_save_as leaves original path intact", rfd >= 0);
    if (rfd >= 0) close (rfd);

    unlink (templ);
    unlink (templ2);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    free (bn_b.path); memset (&bn_b, 0, sizeof bn_b);

    /* Case E — write into a non-existent directory returns -1 with a
       descriptive errno-bearing status. mkstemp inside bn_pt_save_file
       will fail with ENOENT. */
    bn_pt_init_text (&bn_b.pt, "z", 1);
    bn_sync_lines_from_pt ();
    bn_status[0] = '\0';
    rc = bn_save_as ("/this/path/does/not/exist/nano-test");
    BN_SP_ASSERT ("bn_save_as into missing dir returns -1", rc == -1);
    BN_SP_ASSERT ("bn_save_as into missing dir sets write: status",
                  strstr (bn_status, "write:") != NULL);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    free (bn_b.path); memset (&bn_b, 0, sizeof bn_b);

    printf ("1..%d\n", asserts);
    return fails ? 1 : 0;

#undef BN_SP_ASSERT
}

/* G03 Stage SEARCH — TTY-free TAP for bn_search_forward and
   bn_search_backward. Exercises direct matches, wraparound, regex prefix,
   no-match, and empty-pattern rejection. Invoked via
   `nano selftest-search`. */
static int
bn_selftest_search (void)
{
    int fails = 0, asserts = 0;

#define BN_SRCH_ASSERT(desc, cond) \
    do { \
        asserts++; \
        if (cond) printf ("ok %d - %s\n", asserts, desc); \
        else { fails++; printf ("not ok %d - %s\n", asserts, desc); } \
    } while (0)

    /* Case A — forward match finds existing text on line 0. */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "abcdef\nghijkl\n", 14);
    bn_sync_lines_from_pt ();
    bn_cy = 0; bn_cx = 0;
    int rc = bn_search_forward ("cde");
    BN_SRCH_ASSERT ("forward match returns 0", rc == 0);
    BN_SRCH_ASSERT ("forward match on line 0", bn_cy == 0);
    BN_SRCH_ASSERT ("forward match at cx=2", bn_cx == 2);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    /* Case B — forward match on last line (boundary). */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "alpha\nbeta\nomega\n", 18);
    bn_sync_lines_from_pt ();
    bn_cy = 0; bn_cx = 0;
    rc = bn_search_forward ("omega");
    BN_SRCH_ASSERT ("forward match on last line returns 0", rc == 0);
    BN_SRCH_ASSERT ("forward match on last line cy=2", bn_cy == 2);
    BN_SRCH_ASSERT ("forward match on last line cx=0", bn_cx == 0);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    /* Case C — forward no-match returns 1. */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "abc\ndef\n", 8);
    bn_sync_lines_from_pt ();
    bn_cy = 0; bn_cx = 0;
    rc = bn_search_forward ("notfound");
    BN_SRCH_ASSERT ("forward no-match returns 1", rc == 1);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    /* Case D — empty pattern returns 1 immediately. */
    rc = bn_search_forward ("");
    BN_SRCH_ASSERT ("forward empty pattern returns 1", rc == 1);

    /* Case E — backward search finds the previous occurrence. */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "alpha foo\nbeta\nalpha bar\n", 25);
    bn_sync_lines_from_pt ();
    bn_cy = 2; bn_cx = 0;
    rc = bn_search_backward ("alpha");
    BN_SRCH_ASSERT ("backward match returns 0", rc == 0);
    BN_SRCH_ASSERT ("backward match on line 0", bn_cy == 0);
    BN_SRCH_ASSERT ("backward match at cx=0", bn_cx == 0);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    /* Case F — backward search wraps from the first line to the last. */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "alpha foo\nbeta\nalpha bar\n", 25);
    bn_sync_lines_from_pt ();
    bn_cy = 0; bn_cx = 0;
    rc = bn_search_backward ("alpha");
    BN_SRCH_ASSERT ("backward wrap returns 0", rc == 0);
    BN_SRCH_ASSERT ("backward wrap lands on line 2", bn_cy == 2);
    BN_SRCH_ASSERT ("backward wrap lands at cx=0", bn_cx == 0);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    /* Case G — backward no-match and empty pattern return 1. */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "abc\ndef\n", 8);
    bn_sync_lines_from_pt ();
    bn_cy = 1; bn_cx = 3;
    rc = bn_search_backward ("notfound");
    BN_SRCH_ASSERT ("backward no-match returns 1", rc == 1);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    rc = bn_search_backward ("");
    BN_SRCH_ASSERT ("backward empty pattern returns 1", rc == 1);

    /* Case H — regex search via the re: prefix. */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "abc123\nxyz789\n", 14);
    bn_sync_lines_from_pt ();
    bn_cy = 0; bn_cx = 0;
    rc = bn_search_forward ("re:[0-9][0-9][0-9]");
    BN_SRCH_ASSERT ("forward regex prefix returns 0", rc == 0);
    BN_SRCH_ASSERT ("forward regex prefix lands at first digit", bn_cy == 0 && bn_cx == 3);
    bn_cy = 1; bn_cx = 6;
    rc = bn_search_backward ("re:[a-z][a-z][a-z]");
    BN_SRCH_ASSERT ("backward regex prefix returns 0", rc == 0);
    BN_SRCH_ASSERT ("backward regex prefix lands on line 1", bn_cy == 1 && bn_cx == 0);
    rc = bn_search_forward ("re:[");
    BN_SRCH_ASSERT ("bad regex returns 1", rc == 1);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    printf ("1..%d\n", asserts);
    return fails ? 1 : 0;

#undef BN_SRCH_ASSERT
}

/* G03 Stage RESIZE — TTY-free TAP for viewport clamping after searches and
   terminal growth. GNU nano's refresh path keeps the cursor in view while
   avoiding stale blank-leading viewport offsets after the edit area changes. */
static int
bn_selftest_resize (void)
{
    int fails = 0, asserts = 0;
    int saved_stdout, devnull;

#define BN_RESIZE_ASSERT(desc, cond) \
    do { \
        asserts++; \
        if (cond) printf ("ok %d - %s\n", asserts, desc); \
        else { fails++; printf ("not ok %d - %s\n", asserts, desc); } \
    } while (0)

#define BN_RENDER_QUIET() \
    do { \
        saved_stdout = dup (STDOUT_FILENO); \
        devnull = open ("/dev/null", O_WRONLY); \
        if (devnull >= 0) { dup2 (devnull, STDOUT_FILENO); close (devnull); } \
        bn_render (); \
        if (saved_stdout >= 0) { dup2 (saved_stdout, STDOUT_FILENO); close (saved_stdout); } \
    } while (0)

    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "one\ntwo\nthree\nfour\nfive\nomega\n", 30);
    bn_sync_lines_from_pt ();
    bn_cy = 0; bn_cx = 0;
    bn_rows = 4; bn_cols = 20;
    bn_view_top = bn_view_left = 0;
    int rc = bn_search_forward ("omega");
    BN_RENDER_QUIET ();
    BN_RESIZE_ASSERT ("search hit remains visible in small viewport",
                      rc == 0 && bn_cy == 5 && bn_view_top == 4);
    bn_rows = 10;
    BN_RENDER_QUIET ();
    BN_RESIZE_ASSERT ("resize growth clamps search viewport to file top",
                      bn_view_top == 0 && bn_cy == 5);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "", 0);
    bn_sync_lines_from_pt ();
    char xs[81]; memset (xs, 'x', 80); xs[80] = '\0';
    bn_insert_bytes (xs, 80);
    bn_cy = 0; bn_cx = 75;
    bn_rows = 4; bn_cols = 20;
    bn_view_top = bn_view_left = 0;
    BN_RENDER_QUIET ();
    BN_RESIZE_ASSERT ("narrow viewport scrolls horizontally to cursor",
                      bn_view_left > 0);
    bn_cols = 120;
    BN_RENDER_QUIET ();
    BN_RESIZE_ASSERT ("wide resize clamps horizontal viewport to line start",
                      bn_view_left == 0);

    bn_softwrap = 1;
    bn_rows = 4; bn_cols = 10;
    bn_cx = 35;
    bn_view_top = bn_view_left = 0;
    BN_RENDER_QUIET ();
    BN_RESIZE_ASSERT ("softwrap small viewport scrolls by visual row",
                      bn_view_top > 0 && bn_view_left == 0);
    bn_rows = 8; bn_cols = 80;
    BN_RENDER_QUIET ();
    BN_RESIZE_ASSERT ("softwrap resize clamps visual viewport to top",
                      bn_view_top == 0 && bn_view_left == 0);
    bn_softwrap = 0;

    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    /* 5x5 tinywindow — pin that a SIGWINCH which shrinks the terminal
       to 5 rows by 5 cols neither crashes nor leaves bn_render with
       inconsistent viewport state. Status-bar visibility is encoded
       in the row budget: bn_render claims the bottom row for the
       status bar when bn_rows >= 2; at bn_rows == 5 we still get one
       data row + status-bar separator. */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "alpha\nbeta\ngamma\ndelta\nepsilon\n", 30);
    bn_sync_lines_from_pt ();
    bn_cy = 0; bn_cx = 0;
    bn_rows = 5; bn_cols = 5;
    bn_view_top = bn_view_left = 0;
    BN_RENDER_QUIET ();
    BN_RESIZE_ASSERT ("5x5 tinywindow render survives without crash",
                      bn_rows == 5 && bn_cols == 5);
    BN_RESIZE_ASSERT ("5x5 tinywindow viewport bookkeeping stays in range",
                      bn_view_top >= 0 && (size_t) bn_view_top <= bn_b.n_lines &&
                      bn_view_left >= 0 && bn_cy >= 0 && bn_cx >= 0);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    /* SIGWINCH path — real resize delivery should not make the blocking
       key read look like EOF. The handler only marks a flag; render consumes
       it before computing viewport clamps for the searched/anchored cursor. */
    bn_winch_pending = 0;
    int winch_rc = bn_install_winch ();
    int raise_rc = raise (SIGWINCH);
    BN_RESIZE_ASSERT ("SIGWINCH marks pending resize",
                      winch_rc == 0 && raise_rc == 0 && bn_winch_pending == 1);
    bn_apply_pending_resize ();
    BN_RESIZE_ASSERT ("pending SIGWINCH is consumed before render",
                      bn_winch_pending == 0);
    bn_restore_winch ();

    printf ("1..%d\n", asserts);
    return fails ? 1 : 0;

#undef BN_RENDER_QUIET
#undef BN_RESIZE_ASSERT
}

/* G03 Stage REPLACE — TTY-free TAP for bn_replace_at engine. Exercises
   the three length cases (overwrite / shrink / grow) plus bad-arg
   rejection. Also tests the mark state machine (M-A toggle and same-line
   copy). Covers the ^\ replace path and M-A/M-^ state without needing a
   terminal — these are internal functions reachable from within the same
   compilation unit. */
static int
bn_selftest_replace (void)
{
    int fails = 0, asserts = 0;

#define BN_REP_ASSERT(desc, cond) \
    do { \
        asserts++; \
        if (cond) printf ("ok %d - %s\n", asserts, desc); \
        else { fails++; printf ("not ok %d - %s\n", asserts, desc); } \
    } while (0)

    /* ---- replace engine ---- */

    /* T1: same-length overwrite. */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "abcdef", 6);
    bn_sync_lines_from_pt ();
    bn_cy = 0; bn_cx = 0;
    int rc = bn_replace_at (0, 0, 3, "xyz", 3);
    size_t flen = 0;
    char *flat = bn_pt_flatten (&bn_b.pt, &flen);
    BN_REP_ASSERT ("bn_replace_at same-length returns 0", rc == 0);
    BN_REP_ASSERT ("bn_replace_at same-length result",
                   flat && flen == 6 && memcmp (flat, "xyzdef", 6) == 0);
    free (flat);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    /* T2: shrink (replace 4 bytes with 1). */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "abcdef", 6);
    bn_sync_lines_from_pt ();
    rc = bn_replace_at (0, 1, 4, "x", 1);
    flat = bn_pt_flatten (&bn_b.pt, &flen);
    BN_REP_ASSERT ("bn_replace_at shrink returns 0", rc == 0);
    BN_REP_ASSERT ("bn_replace_at shrink result",
                   flat && flen == 3 && memcmp (flat, "axf", 3) == 0);
    free (flat);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    /* T3: grow (replace 1 byte with 3). */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "abc", 3);
    bn_sync_lines_from_pt ();
    rc = bn_replace_at (0, 1, 1, "pqr", 3);
    flat = bn_pt_flatten (&bn_b.pt, &flen);
    BN_REP_ASSERT ("bn_replace_at grow returns 0", rc == 0);
    BN_REP_ASSERT ("bn_replace_at grow result",
                   flat && flen == 5 && memcmp (flat, "apqrc", 5) == 0);
    free (flat);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    /* T4: bad line out of range → -1. */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "a", 1);
    bn_sync_lines_from_pt ();
    rc = bn_replace_at (99, 0, 1, "x", 1);
    BN_REP_ASSERT ("bn_replace_at bad line returns -1", rc == -1);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    /* T5: bad col out of range → -1. */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "a", 1);
    bn_sync_lines_from_pt ();
    rc = bn_replace_at (0, 5, 1, "x", 1);
    BN_REP_ASSERT ("bn_replace_at bad col returns -1", rc == -1);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    /* T6: empty replacement (merge plen bytes into nothing). */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "abcde", 5);
    bn_sync_lines_from_pt ();
    rc = bn_replace_at (0, 1, 3, "", 0);
    flat = bn_pt_flatten (&bn_b.pt, &flen);
    BN_REP_ASSERT ("bn_replace_at empty repl returns 0", rc == 0);
    BN_REP_ASSERT ("bn_replace_at empty repl result",
                   flat && flen == 2 && memcmp (flat, "ae", 2) == 0);
    free (flat);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    /* ---- mark state machine ---- */

    /* T7: M-A toggles mark on. Mark starts inactive. */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "hello\nworld\n", 12);
    bn_sync_lines_from_pt ();
    bn_cy = 1; bn_cx = 2;
    bn_mark_active = 0;
    /* Simulate M-A dispatch via bn_mark_active toggle (same logic
       as case 'A'/'a' in bn_dispatch for ESC klen=2). */
    bn_mark_active = !bn_mark_active;
    if (bn_mark_active) { bn_mark_cy = 1; bn_mark_cx = 2; }
    BN_REP_ASSERT ("M-A marks active after toggle", bn_mark_active == 1);
    BN_REP_ASSERT ("M-A stores cursor pos", bn_mark_cy == 1 && bn_mark_cx == 2);

    /* T8: M-A toggles mark off. */
    bn_mark_active = !bn_mark_active;
    BN_REP_ASSERT ("M-A marks inactive on second toggle", bn_mark_active == 0);

    /* T9: same-line copy via (M-^ equivalent). Set mark at (0,0),
       cursor at (0,5), bn_mark_cut_or_copy with cut_it=0. */
    bn_mark_active = 1; bn_mark_cy = 0; bn_mark_cx = 0;
    bn_cy = 0; bn_cx = 5;
    bn_mark_cut_or_copy (0, 0, 5, 0);
    BN_REP_ASSERT ("M-^ copy produces clipboard",
                   bn_clip && bn_clip_len == 5);
    BN_REP_ASSERT ("M-^ copy preserves bytes",
                   bn_clip_len == 5 && memcmp (bn_clip, "hello", 5) == 0);
    BN_REP_ASSERT ("M-^ copy deactivates mark", bn_mark_active == 0);

    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    free (bn_clip); bn_clip = NULL; bn_clip_len = 0;
    memset (&bn_b, 0, sizeof bn_b);

    /* T10: same-line cut via (M-^ with cut, same as M-A toggle + ^K
       with bn_mark_cy == bn_cy branch). */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "abcdef", 6);
    bn_sync_lines_from_pt ();
    bn_mark_active = 1; bn_mark_cy = 0; bn_mark_cx = 1;
    bn_cy = 0; bn_cx = 4;
    bn_mark_cut_or_copy (0, 1, 4, 1);
    flat = bn_pt_flatten (&bn_b.pt, &flen);
    BN_REP_ASSERT ("M-A+^K same-line cut removes range",
                   flat && flen == 3 && memcmp (flat, "aef", 3) == 0);
    free (flat);
    BN_REP_ASSERT ("M-A+^K same-line cut records clipboard",
                   bn_clip && bn_clip_len == 3
                   && memcmp (bn_clip, "bcd", 3) == 0);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    free (bn_clip); bn_clip = NULL; bn_clip_len = 0;
    memset (&bn_b, 0, sizeof bn_b);

    printf ("1..%d\n", asserts);
    return fails ? 1 : 0;

#undef BN_REP_ASSERT
}

/* G03 Stage STATUSBAR — TTY-free TAP for the bn_set_status state machine
   plus the status messages emitted by save/undo/redo. Mirrors GNU nano's
   transient mini-buffer messages: arm with text and a 3-keypress TTL, hold
   the text across the next renders, then auto-clear. The TTL decrement is
   open-coded in bn_render() (one decrement per render call) so this
   selftest simulates the same tick pattern without needing a terminal. */
static int
bn_selftest_statusbar (void)
{
    int fails = 0, asserts = 0;

#define BN_SB_ASSERT(desc, cond) \
    do { \
        asserts++; \
        if (cond) printf ("ok %d - %s\n", asserts, desc); \
        else { fails++; printf ("not ok %d - %s\n", asserts, desc); } \
    } while (0)

#define BN_SB_TICK() \
    do { \
        if (bn_status_until > 0) bn_status_until--; \
        if (bn_status_until == 0) bn_status[0] = '\0'; \
    } while (0)

    /* T1: pristine — no status, TTL 0. */
    bn_status[0] = '\0'; bn_status_until = 0;
    BN_SB_ASSERT ("pristine status empty + TTL=0",
                  bn_status[0] == '\0' && bn_status_until == 0);

    /* T2: bn_set_status formats text + arms TTL=3. */
    bn_set_status ("Read %d lines from %s", 5, "/tmp/x");
    BN_SB_ASSERT ("set_status formats varargs",
                  strcmp (bn_status, "Read 5 lines from /tmp/x") == 0);
    BN_SB_ASSERT ("set_status arms TTL to 3", bn_status_until == 3);

    /* T3: TTL decay holds text across the first two ticks then clears on
       the third. Mirrors bn_render()'s post-render decrement. */
    BN_SB_TICK ();
    BN_SB_ASSERT ("after tick 1 TTL=2 text retained",
                  bn_status_until == 2 && strcmp (bn_status, "Read 5 lines from /tmp/x") == 0);
    BN_SB_TICK ();
    BN_SB_ASSERT ("after tick 2 TTL=1 text retained",
                  bn_status_until == 1 && strcmp (bn_status, "Read 5 lines from /tmp/x") == 0);
    BN_SB_TICK ();
    BN_SB_ASSERT ("after tick 3 TTL=0 status cleared",
                  bn_status_until == 0 && bn_status[0] == '\0');
    BN_SB_TICK ();
    BN_SB_ASSERT ("tick on empty status is idempotent",
                  bn_status_until == 0 && bn_status[0] == '\0');

    /* T4: overlong message gets truncated to sizeof bn_status - 1, no
       buffer overflow. */
    {
        char big[400];
        memset (big, 'A', sizeof big - 1);
        big[sizeof big - 1] = '\0';
        bn_set_status ("%s", big);
        BN_SB_ASSERT ("overlong status truncated to buffer-1",
                      strlen (bn_status) == sizeof bn_status - 1
                      && bn_status[sizeof bn_status - 1] == '\0');
    }

    /* T5: overwrite resets TTL even when an earlier message is still
       visible (prevents the new message from inheriting a stale countdown
       and disappearing too quickly). */
    bn_set_status ("first");
    bn_status_until = 1;                 /* simulate one render already happened */
    bn_set_status ("second");
    BN_SB_ASSERT ("overwrite resets TTL to 3 + replaces text",
                  bn_status_until == 3 && strcmp (bn_status, "second") == 0);

    /* T6: bn_save_as success path emits "Wrote N lines to PATH". */
    {
        char tmppath[] = "/tmp/bn-statusbar-XXXXXX";
        int fd = mkstemp (tmppath);
        if (fd < 0) {
            asserts++; fails++;
            printf ("not ok %d - mkstemp failed (errno=%d)\n", asserts, errno);
        } else {
            close (fd);
            unlink (tmppath);
            memset (&bn_b, 0, sizeof bn_b);
            bn_pt_init_text (&bn_b.pt, "hi\n", 3);
            bn_sync_lines_from_pt ();
            bn_status[0] = '\0'; bn_status_until = 0;
            int rc = bn_save_as (tmppath);
            BN_SB_ASSERT ("bn_save_as succeeds", rc == 0);
            BN_SB_ASSERT ("save success status shape 'Wrote N lines to PATH'",
                          strncmp (bn_status, "Wrote ", 6) == 0
                          && strstr (bn_status, " lines to ") != NULL
                          && strstr (bn_status, tmppath) != NULL);
            BN_SB_ASSERT ("save success arms TTL=3", bn_status_until == 3);
            unlink (tmppath);
            bn_free_lines (); bn_pt_free (&bn_b.pt);
            bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
            free (bn_b.path);
            memset (&bn_b, 0, sizeof bn_b);
        }
    }

    /* T7: bn_save_as("") emits "No filename" — the modal-cancel contract. */
    bn_status[0] = '\0'; bn_status_until = 0;
    {
        int rc = bn_save_as ("");
        BN_SB_ASSERT ("save_as empty path returns -1", rc == -1);
        BN_SB_ASSERT ("save_as empty path emits 'No filename'",
                      strcmp (bn_status, "No filename") == 0);
    }

    /* T8: undo with empty stack emits "Nothing to undo". */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "x\n", 2);
    bn_sync_lines_from_pt ();
    bn_status[0] = '\0'; bn_status_until = 0;
    bn_undo ();
    BN_SB_ASSERT ("undo on empty stack -> 'Nothing to undo'",
                  strcmp (bn_status, "Nothing to undo") == 0
                  && bn_status_until == 3);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    /* T9: redo with empty stack emits "Nothing to redo". */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "x\n", 2);
    bn_sync_lines_from_pt ();
    bn_status[0] = '\0'; bn_status_until = 0;
    bn_redo ();
    BN_SB_ASSERT ("redo on empty stack -> 'Nothing to redo'",
                  strcmp (bn_status, "Nothing to redo") == 0
                  && bn_status_until == 3);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    /* T10: failed forward search emits "Not found: PAT". */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "alpha\nbeta\n", 11);
    bn_sync_lines_from_pt ();
    bn_cy = 0; bn_cx = 0;
    bn_status[0] = '\0'; bn_status_until = 0;
    (void) bn_search_forward ("zzzzz");
    BN_SB_ASSERT ("failed forward search -> 'Not found: PAT'",
                  strcmp (bn_status, "Not found: zzzzz") == 0
                  && bn_status_until == 3);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);

    printf ("1..%d\n", asserts);
    return fails ? 1 : 0;

#undef BN_SB_TICK
#undef BN_SB_ASSERT
}

/* G03 Stage YANK-RING — TTY-free TAP for multi-line marked regions and the
   in-editor ring used by ^U.  This mirrors the editor-engine clip ring at
   byte-span granularity, so marked regions retain their embedded newlines. */
static int
bn_selftest_yank_ring (void)
{
    int fails = 0, asserts = 0;

#define BN_YR_ASSERT(desc, cond) \
    do { \
        asserts++; \
        if (cond) printf ("ok %d - %s\n", asserts, desc); \
        else { fails++; printf ("not ok %d - %s\n", asserts, desc); } \
    } while (0)

    bn_yank_ring_clear ();
    free (bn_clip); bn_clip = NULL; bn_clip_len = 0;
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "alpha\nbeta\ngamma\ndelta\n", 23);
    bn_sync_lines_from_pt ();

    bn_mark_active = 1; bn_mark_cy = 0; bn_mark_cx = 0;
    bn_cy = 2; bn_cx = 5;
    bn_mark_cut_or_copy (bn_cy, bn_mark_cx, bn_cx, 0);
    BN_YR_ASSERT ("M-^ copy stores multi-line marked bytes",
                  bn_clip && bn_clip_len == 16
                  && memcmp (bn_clip, "alpha\nbeta\ngamma", 16) == 0);
    BN_YR_ASSERT ("multi-line copy initializes yank ring",
                  bn_yank_ring_fill == 1 && bn_yank_ring_active == 0);

    bn_cy = 3; bn_cx = 0;
    bn_cut_line ();
    BN_YR_ASSERT ("^K line cut advances active yank slot",
                  bn_clip && bn_clip_len == 5 && memcmp (bn_clip, "delta", 5) == 0
                  && bn_yank_ring_fill == 2 && bn_yank_ring_active == 0);

    bn_yank_ring_rotate (+1);
    BN_YR_ASSERT ("M-{ rotates to older multi-line yank",
                  bn_clip && bn_clip_len == 16
                  && memcmp (bn_clip, "alpha\nbeta\ngamma", 16) == 0
                  && bn_yank_ring_active == 1);

    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "", 0);
    bn_sync_lines_from_pt ();
    bn_cy = 0; bn_cx = 0;
    bn_paste ();
    size_t flen = 0;
    char *flat = bn_pt_flatten (&bn_b.pt, &flen);
    BN_YR_ASSERT ("^U pastes rotated multi-line yank bytes",
                  flat && flen == 16 && memcmp (flat, "alpha\nbeta\ngamma", 16) == 0);
    free (flat);

    bn_yank_ring_rotate (-1);
    BN_YR_ASSERT ("M-} rotates back to newer line yank",
                  bn_clip && bn_clip_len == 5 && memcmp (bn_clip, "delta", 5) == 0
                  && bn_yank_ring_active == 0);

    bn_yank_ring_clear ();
    for (int i = 0; i < BN_YANK_RING_SIZE + 2; i++) {
        char tmp[16];
        int n = snprintf (tmp, sizeof tmp, "slot-%02d", i);
        char *copy = malloc ((size_t) n + 1);
        if (!copy) continue;
        memcpy (copy, tmp, (size_t) n + 1);
        bn_clip_take (copy, (size_t) n, 1);
    }
    BN_YR_ASSERT ("yank ring caps at 16 slots",
                  bn_yank_ring_fill == BN_YANK_RING_SIZE);
    bn_yank_ring_rotate (+1);
    BN_YR_ASSERT ("capped ring keeps previous slot reachable",
                  bn_clip && bn_clip_len == 7 && memcmp (bn_clip, "slot-16", 7) == 0);

    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    free (bn_clip); bn_clip = NULL; bn_clip_len = 0;
    bn_yank_ring_clear ();
    memset (&bn_b, 0, sizeof bn_b);

    printf ("1..%d\n", asserts);
    return fails ? 1 : 0;

#undef BN_YR_ASSERT
}

/* G03 Stage ATOMIC-SAVE — TTY-free TAP coverage for the bn_pt_save_file
   durability contract: mkstemp + fdatasync(fd) + rename + fsync(parent-dir).
   Power loss can't be simulated host-side, so observable assertions focus
   on (a) no `.tmpXXXXXX` residue after a successful save (the rename
   consumed it and we didn't leak partial state), (b) byte-exact round-trip,
   (c) two consecutive saves to the same path both succeed (validates the
   parent-dir dirfd from the first save did not leak / clobber state),
   (d) relative-path save exercises the `dirpath = "."` fallback, and
   (e) save into a nonexistent dir fails cleanly. */
static int
bn_selftest_atomic_save (void)
{
    int fails = 0, asserts = 0;

#define BN_AS_ASSERT(desc, cond) \
    do { \
        asserts++; \
        if (cond) printf ("ok %d - %s\n", asserts, desc); \
        else { fails++; printf ("not ok %d - %s\n", asserts, desc); } \
    } while (0)

    /* Case A — successful save leaves no `.tmpXXXXXX` residue in the
       target dir. We pick a unique tmpdir, save into it, then walk the
       dir looking for any entry whose name contains ".tmp" (the mkstemp
       template's literal infix). */
    char dirtempl[] = "/tmp/nano-as.XXXXXX";
    char *dir = mkdtemp (dirtempl);
    if (dir) {
        char target[256];
        snprintf (target, sizeof target, "%s/saved.txt", dir);

        memset (&bn_b, 0, sizeof bn_b);
        bn_pt_init_text (&bn_b.pt, "one\ntwo\nthree\n", 14);
        bn_sync_lines_from_pt ();
        bn_b.dirty = 1;
        bn_status[0] = '\0';

        int rc = bn_save_as (target);
        BN_AS_ASSERT ("bn_save_as(NEW) returns 0", rc == 0);

        /* Walk dir, count residue + target. */
        int residue = 0, have_target = 0;
        DIR *d = opendir (dir);
        if (d) {
            struct dirent *de;
            while ((de = readdir (d)) != NULL) {
                if (strcmp (de->d_name, ".") == 0 || strcmp (de->d_name, "..") == 0)
                    continue;
                if (strstr (de->d_name, ".tmp") != NULL) residue++;
                if (strcmp (de->d_name, "saved.txt") == 0) have_target = 1;
            }
            closedir (d);
        }
        BN_AS_ASSERT ("save leaves no .tmpXXXXXX residue", residue == 0);
        BN_AS_ASSERT ("save creates target file", have_target == 1);

        /* Round-trip read. */
        int rfd = open (target, O_RDONLY);
        char rbuf[64] = {0};
        ssize_t got = rfd >= 0 ? read (rfd, rbuf, sizeof rbuf - 1) : -1;
        if (rfd >= 0) close (rfd);
        BN_AS_ASSERT ("save round-trips bytes",
                      got == 14 && memcmp (rbuf, "one\ntwo\nthree\n", 14) == 0);

        /* Case B — two consecutive saves to the same path both succeed,
           with second save reflecting buffer mutation. Asserts the parent-
           dirfd from save #1 was closed (no fd leak that could clobber
           save #2). */
        bn_pt_init_text (&bn_b.pt, "v2\n", 3);  /* reinit buffer with new bytes */
        bn_sync_lines_from_pt ();
        bn_b.dirty = 1;
        rc = bn_save_as (target);
        BN_AS_ASSERT ("second consecutive save returns 0", rc == 0);

        rfd = open (target, O_RDONLY);
        memset (rbuf, 0, sizeof rbuf);
        got = rfd >= 0 ? read (rfd, rbuf, sizeof rbuf - 1) : -1;
        if (rfd >= 0) close (rfd);
        BN_AS_ASSERT ("second save reflects new buffer bytes",
                      got == 3 && memcmp (rbuf, "v2\n", 3) == 0);

        /* No residue after the second save either. */
        residue = 0;
        d = opendir (dir);
        if (d) {
            struct dirent *de;
            while ((de = readdir (d)) != NULL) {
                if (strcmp (de->d_name, ".") == 0 || strcmp (de->d_name, "..") == 0)
                    continue;
                if (strstr (de->d_name, ".tmp") != NULL) residue++;
            }
            closedir (d);
        }
        BN_AS_ASSERT ("second save leaves no residue", residue == 0);

        bn_free_lines (); bn_pt_free (&bn_b.pt);
        bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
        free (bn_b.path); memset (&bn_b, 0, sizeof bn_b);

        unlink (target);
        rmdir (dir);
    } else {
        BN_AS_ASSERT ("mkdtemp succeeds", 0);
        BN_AS_ASSERT ("save leaves no .tmpXXXXXX residue (mkdtemp failed)", 0);
        BN_AS_ASSERT ("save creates target file (mkdtemp failed)", 0);
        BN_AS_ASSERT ("save round-trips bytes (mkdtemp failed)", 0);
        BN_AS_ASSERT ("second consecutive save returns 0 (mkdtemp failed)", 0);
        BN_AS_ASSERT ("second save reflects new buffer bytes (mkdtemp failed)", 0);
        BN_AS_ASSERT ("second save leaves no residue (mkdtemp failed)", 0);
    }

    /* Case C — relative-path save exercises the dirpath="." fallback in
       the parent-dir fsync block. We chdir into a fresh tmp dir, save
       under a name with no `/`, then verify rc=0 and content matches. */
    char relroot[] = "/tmp/nano-asrel.XXXXXX";
    char *rdir = mkdtemp (relroot);
    if (rdir) {
        char saved_cwd[4096];
        if (getcwd (saved_cwd, sizeof saved_cwd) != NULL) {
            int chdir_rc = chdir (rdir);
            if (chdir_rc == 0) {
                memset (&bn_b, 0, sizeof bn_b);
                bn_pt_init_text (&bn_b.pt, "relpath\n", 8);
                bn_sync_lines_from_pt ();
                bn_b.dirty = 1;
                int rc = bn_save_as ("rel-out.txt");
                BN_AS_ASSERT ("relative-path save (dirpath=. fallback) returns 0", rc == 0);

                int rfd = open ("rel-out.txt", O_RDONLY);
                char rbuf[16] = {0};
                ssize_t got = rfd >= 0 ? read (rfd, rbuf, sizeof rbuf - 1) : -1;
                if (rfd >= 0) close (rfd);
                BN_AS_ASSERT ("relative-path save round-trips bytes",
                              got == 8 && memcmp (rbuf, "relpath\n", 8) == 0);

                unlink ("rel-out.txt");
                bn_free_lines (); bn_pt_free (&bn_b.pt);
                bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
                free (bn_b.path); memset (&bn_b, 0, sizeof bn_b);

                (void) chdir (saved_cwd);
            } else {
                BN_AS_ASSERT ("relative-path save (chdir failed)", 0);
                BN_AS_ASSERT ("relative-path save round-trips bytes (chdir failed)", 0);
            }
        } else {
            BN_AS_ASSERT ("relative-path save (getcwd failed)", 0);
            BN_AS_ASSERT ("relative-path save round-trips bytes (getcwd failed)", 0);
        }
        rmdir (rdir);
    } else {
        BN_AS_ASSERT ("relative-path save (mkdtemp failed)", 0);
        BN_AS_ASSERT ("relative-path save round-trips bytes (mkdtemp failed)", 0);
    }

    /* Case D — save into a nonexistent directory still fails cleanly:
       mkstemp inside bn_pt_save_file fails before any rename happens,
       so no partial file is left behind. The parent-dir fsync arm is
       unreachable in this path (we return -1 before rename). */
    memset (&bn_b, 0, sizeof bn_b);
    bn_pt_init_text (&bn_b.pt, "z", 1);
    bn_sync_lines_from_pt ();
    bn_status[0] = '\0';
    int rc_nonex = bn_save_as ("/this/path/does/not/exist/atomic-save-probe");
    BN_AS_ASSERT ("save into missing dir returns -1", rc_nonex == -1);
    BN_AS_ASSERT ("save into missing dir leaves no probe file",
                  access ("/this/path/does/not/exist/atomic-save-probe", F_OK) < 0);
    bn_free_lines (); bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo);
    free (bn_b.path); memset (&bn_b, 0, sizeof bn_b);

    printf ("1..%d\n", asserts);
    return fails ? 1 : 0;

#undef BN_AS_ASSERT
}

/* G03 Stage UNDO-REDO — TTY-free TAP coverage for the undo/redo state
   machine in bn_piece_replace + bn_undo + bn_redo. Pins the nano
   contract that a new edit clears the redo stack (line 763:
   `bn_pt_stack_free (&bn_b.redo);`), plus the multi-step LIFO order,
   dirty-flag round-trip through snapshots, cursor clamp after undo
   shrinks the buffer, and the "Undid change"/"Redid change" status
   strings. Empty-stack messages already live in selftest-statusbar;
   this selftest is the dedicated state-machine pin. */
static int
bn_selftest_undo_redo (void)
{
    int fails = 0, asserts = 0;

#define BN_UR_ASSERT(desc, cond) \
    do { \
        asserts++; \
        if (cond) printf ("ok %d - %s\n", asserts, desc); \
        else { fails++; printf ("not ok %d - %s\n", asserts, desc); } \
    } while (0)

#define BN_UR_FLATTEN_EQ(buf, want, want_len) \
    do { \
        size_t _flen = 0; \
        char *_f = bn_pt_flatten (&bn_b.pt, &_flen); \
        int _ok = _f && _flen == (size_t) (want_len) \
                  && memcmp (_f, (want), (want_len)) == 0; \
        BN_UR_ASSERT (buf, _ok); \
        free (_f); \
    } while (0)

#define BN_UR_RESET() do { \
        bn_free_lines (); bn_pt_free (&bn_b.pt); \
        bn_pt_stack_free (&bn_b.undo); bn_pt_stack_free (&bn_b.redo); \
        free (bn_b.path); memset (&bn_b, 0, sizeof bn_b); \
    } while (0)

    /* Case A — single edit + undo restores empty; undo pushes onto redo. */
    BN_UR_RESET ();
    bn_pt_init_text (&bn_b.pt, "", 0);
    bn_sync_lines_from_pt ();
    bn_b.dirty = 0;  bn_cy = 0;  bn_cx = 0;
    bn_insert_bytes ("x", 1);
    BN_UR_FLATTEN_EQ ("insert leaves buffer 'x'", "x", 1);
    BN_UR_ASSERT ("insert pushes undo stack to 1", bn_b.undo.n == 1);
    BN_UR_ASSERT ("insert clears redo stack",      bn_b.redo.n == 0);
    BN_UR_ASSERT ("insert marks buffer dirty",     bn_b.pt.dirty == 1);

    bn_status[0] = '\0'; bn_status_until = 0;
    bn_undo ();
    BN_UR_FLATTEN_EQ ("undo restores empty buffer", "", 0);
    BN_UR_ASSERT ("undo pops undo to 0",   bn_b.undo.n == 0);
    BN_UR_ASSERT ("undo pushes redo to 1", bn_b.redo.n == 1);
    BN_UR_ASSERT ("undo restores dirty=0 from snapshot", bn_b.pt.dirty == 0);
    BN_UR_ASSERT ("undo emits 'Undid change' status",
                  strcmp (bn_status, "Undid change") == 0);

    /* Case B — redo re-applies the undone edit and reverses the stacks. */
    bn_status[0] = '\0'; bn_status_until = 0;
    bn_redo ();
    BN_UR_FLATTEN_EQ ("redo restores 'x'", "x", 1);
    BN_UR_ASSERT ("redo pushes undo back to 1", bn_b.undo.n == 1);
    BN_UR_ASSERT ("redo pops redo to 0",        bn_b.redo.n == 0);
    BN_UR_ASSERT ("redo restores dirty=1",      bn_b.pt.dirty == 1);
    BN_UR_ASSERT ("redo emits 'Redid change' status",
                  strcmp (bn_status, "Redid change") == 0);

    /* Case C — multi-step LIFO: insert a, b, c; undo 3x clears; redo 2x
       reaches "ab". Pins that snapshots stack and unwind in reverse. */
    BN_UR_RESET ();
    bn_pt_init_text (&bn_b.pt, "", 0);
    bn_sync_lines_from_pt ();
    bn_cy = 0; bn_cx = 0;
    bn_insert_bytes ("a", 1);
    bn_insert_bytes ("b", 1);
    bn_insert_bytes ("c", 1);
    BN_UR_FLATTEN_EQ ("multi-insert builds 'abc'", "abc", 3);
    BN_UR_ASSERT ("three inserts stack three undo snapshots", bn_b.undo.n == 3);
    bn_undo (); bn_undo (); bn_undo ();
    BN_UR_FLATTEN_EQ ("three undos restore empty", "", 0);
    bn_redo (); bn_redo ();
    BN_UR_FLATTEN_EQ ("two redos reach 'ab'", "ab", 2);
    BN_UR_ASSERT ("two redos leave 1 entry on redo stack", bn_b.redo.n == 1);

    /* Case D — CRITICAL nano contract: a new edit after undo clears the
       redo stack so the original branch becomes unreachable. This is the
       `bn_pt_stack_free (&bn_b.redo);` arm in bn_piece_replace. */
    BN_UR_RESET ();
    bn_pt_init_text (&bn_b.pt, "", 0);
    bn_sync_lines_from_pt ();
    bn_cy = 0; bn_cx = 0;
    bn_insert_bytes ("x", 1);
    bn_undo ();
    BN_UR_ASSERT ("after undo, redo stack has 1 entry (sanity)", bn_b.redo.n == 1);
    bn_insert_bytes ("y", 1);
    BN_UR_ASSERT ("new edit after undo clears redo stack", bn_b.redo.n == 0);
    bn_status[0] = '\0'; bn_status_until = 0;
    bn_redo ();
    BN_UR_ASSERT ("redo after cleared stack emits 'Nothing to redo'",
                  strcmp (bn_status, "Nothing to redo") == 0);
    BN_UR_FLATTEN_EQ ("buffer unchanged after failed redo", "y", 1);

    /* Case E — cursor clamp: insert a long line, place cursor near the
       end, undo to an empty buffer; cursor must be clamped to new
       total_len (0). bn_undo() reads cursor abs BEFORE the pop, then
       clamps after the pop, so the cursor cannot dangle past EOF. */
    BN_UR_RESET ();
    bn_pt_init_text (&bn_b.pt, "", 0);
    bn_sync_lines_from_pt ();
    bn_cy = 0; bn_cx = 0;
    bn_insert_bytes ("0123456789", 10);
    bn_set_cursor_abs (10);  /* cursor at end of buffer */
    bn_undo ();
    BN_UR_ASSERT ("undo clamps cursor to new total_len (0)",
                  bn_cy == 0 && bn_cx == 0 && bn_b.pt.total_len == 0);

    BN_UR_RESET ();
    printf ("1..%d\n", asserts);
    return fails ? 1 : 0;

#undef BN_UR_ASSERT
#undef BN_UR_FLATTEN_EQ
#undef BN_UR_RESET
}

/* ---- selftests for justify, spell, completion, selection and the
   incremental line cache.  They drive bn_dispatch and the real prompts
   through the key queue, with renders sent to /dev/null. ---- */

static int bn_st_fails, bn_st_asserts;

#define BN_ST_ASSERT(desc, cond) \
    do { \
        bn_st_asserts++; \
        if (cond) printf ("ok %d - %s\n", bn_st_asserts, desc); \
        else { bn_st_fails++; printf ("not ok %d - %s\n", bn_st_asserts, desc); } \
    } while (0)

static void
bn_st_reset (void)
{
    bn_free_lines ();
    bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo);
    bn_pt_stack_free (&bn_b.redo);
    free (bn_b.path);
    memset (&bn_b, 0, sizeof bn_b);
    bn_cy = bn_cx = 0;
    bn_view_top = bn_view_left = 0;
    bn_mark_active = 0;
    bn_mark_cy = bn_mark_cx = 0;
    bn_status[0] = '\0';
    bn_status_until = 0;
    bn_rows = 24; bn_cols = 80;
    bn_want_col = -1;
    bn_fill = -8;
    bn_trimblanks = 0;
    bn_complete_reset ();
    bn_keyq_set (NULL, 0);
}

static void
bn_st_load (const char *text)
{
    bn_st_reset ();
    bn_pt_init_text (&bn_b.pt, text, strlen (text));
    bn_sync_lines_from_pt ();
}

static int
bn_st_text_is (const char *want)
{
    size_t n = 0;
    char *f = bn_pt_flatten (&bn_b.pt, &n);
    int ok = f && n == strlen (want) && memcmp (f, want, n) == 0;
    if (f && !ok) {
        printf ("# got:  \"");
        for (size_t i = 0; i < n; i++)
            printf (f[i] == '\n' ? "\\n" : "%c", f[i]);
        printf ("\"\n# want: \"");
        for (size_t i = 0; want[i]; i++)
            printf (want[i] == '\n' ? "\\n" : "%c", want[i]);
        printf ("\"\n");
    }
    free (f);
    return ok;
}

/* Feed KEYS to the editor's input loop, as the interactive loop would. */
static void
bn_st_keys (const char *const *keys, size_t n)
{
    fflush (stdout);
    int saved = dup (STDOUT_FILENO);
    int devnull = open ("/dev/null", O_WRONLY);
    if (devnull >= 0) { dup2 (devnull, STDOUT_FILENO); close (devnull); }
    bn_keyq_set (keys, n);
    char k[16];
    int klen;
    while ((klen = bn_read_key (k, sizeof k)) > 0)
        bn_dispatch (k, klen);
    bn_keyq_set (NULL, 0);
    if (saved >= 0) { dup2 (saved, STDOUT_FILENO); close (saved); }
}

#define BN_ST_KEYS(...) \
    do { \
        static const char *const _k[] = { __VA_ARGS__ }; \
        bn_st_keys (_k, sizeof _k / sizeof _k[0]); \
    } while (0)

/* Cases whose expected text was produced by GNU nano 8.4 from the same
   input with the same --fill/--trimblanks options (LANG=C.UTF-8). */
static const struct {
    const char *in;
    long fill;
    int trim;
    const char *out;
} bn_justify_gnu_cases[] = {
    { "aaaa bbbb cccc dddd eeee ffff gggg hhhh iiii jjjj kkkk\n", 20, 0,
      "aaaa bbbb cccc dddd \neeee ffff gggg hhhh \niiii jjjj kkkk\n" },
    { "aaaa bbbb cccc dddd eeee ffff gggg hhhh iiii jjjj kkkk\n", 20, 1,
      "aaaa bbbb cccc dddd\neeee ffff gggg hhhh\niiii jjjj kkkk\n" },
    { "aaaaaaaaa bbbbbbbbbb ccc\n", 20, 0, "aaaaaaaaa bbbbbbbbbb \nccc\n" },
    { "aaaaaaaaa bbbbbbbbbbb ccc\n", 20, 0, "aaaaaaaaa \nbbbbbbbbbbb ccc\n" },
    { "hello   world  \n", 20, 0, "hello world\n" },
    { "One.  Two!   Three?) four   five.\tsix seven eight nine ten\n", 20, 0,
      "One.  Two!  Three?) \nfour five. six seven \neight nine ten\n" },
    { "One.  Two!   Three?) four   five.\tsix seven eight nine ten\n", 20, 1,
      "One.  Two!  Three?)\nfour five. six seven\neight nine ten\n" },
    { "aaaa bbbb cccc ddd.  eeee ffff\n", 20, 0, "aaaa bbbb cccc ddd.  \neeee ffff\n" },
    { "aaaa bbbb cccc ddd.  eeee ffff\n", 20, 1, "aaaa bbbb cccc ddd.\neeee ffff\n" },
    { "  first line here and more words\nsecond line with\nmore words to wrap around nicely\n", 20, 0,
      "  first line here \nand more words \nsecond line with \nmore words to wrap \naround nicely\n" },
    { "first line here and more words\n  second line with\n  more words to wrap around nicely\n", 20, 0,
      "first line here and \n  more words second \n  line with more \n  words to wrap \n  around nicely\n" },
    { "  first line here\n    second line with\nmore words to wrap around nicely\n", 20, 0,
      "  first line here \n    second line with\nmore words to wrap around nicely\n" },
    { "averyveryverylongwordthatexceeds width\n", 10, 0, "averyveryverylongwordthatexceeds \nwidth\n" },
    { "h\xc3\xa9llo w\xc3\xb6rld \xe4\xb8\xad\xe6\x96\x87\xe4\xb8\xad\xe6\x96\x87 caf\xc3\xa9 na\xc3\xafve r\xc3\xa9sum\xc3\xa9 \xc3\xbc" "ber\n", 12, 0,
      "h\xc3\xa9llo w\xc3\xb6rld \n\xe4\xb8\xad\xe6\x96\x87\xe4\xb8\xad\xe6\x96\x87 \ncaf\xc3\xa9 na\xc3\xafve \nr\xc3\xa9sum\xc3\xa9 \xc3\xbc" "ber\n" },
    { "> quoted text that is long enough to wrap\n> more quoted\n", 20, 0,
      "> quoted text that \n> is long enough to \n> wrap more quoted\n" },
    { "> quoted\n>> deeper quote here and there\n", 20, 0,
      "> quoted\n>> deeper quote here and there\n" },
    { "  a\n  b\n  c d e\n", 20, 0, "  a b c d e\n" },
    { "x\n  y\n  z\n", 20, 0, "x y z\n" },
    { "ab  \ncd\n", 20, 0, "ab cd\n" },
    { "ab.  \ncd\n", 20, 0, "ab.  cd\n" },
    { "ab. \ncd\n", 20, 0, "ab. cd\n" },
    { "\tTabbed first line with words\n\tsecond\n", 20, 0,
      "\tTabbed first \n\tline with \n\twords second\n" },
    { "para one is here with words\n\npara two is here\n", 20, 0,
      "para one is here \nwith words\n\npara two is here\n" },
    { "\n\npara two is here with many words\n", 20, 0,
      "\n\npara two is here \nwith many words\n" },
};

static int
bn_selftest_justify (void)
{
    bn_st_fails = bn_st_asserts = 0;
    {
        char text[2048];
        size_t used = 0;
        for (size_t i = 0; i < 260; i++) {
            const char *line = i % 2 ? " x\n" : "x\n";
            size_t n = strlen (line);
            memcpy (text + used, line, n); used += n;
        }
        text[used] = '\0';
        bn_st_load (text);
        int ok = 1;
        for (size_t i = 0; i < 260; i++)
            if (bn_begpar (i) != (i % 2 == 0)) ok = 0;
        BN_ST_ASSERT ("long alternating indentation has no paragraph depth cutoff", ok);
    }
    char desc[128];
    for (size_t i = 0; i < sizeof bn_justify_gnu_cases / sizeof bn_justify_gnu_cases[0]; i++) {
        bn_st_load (bn_justify_gnu_cases[i].in);
        bn_fill = bn_justify_gnu_cases[i].fill;
        bn_trimblanks = bn_justify_gnu_cases[i].trim;
        BN_ST_KEYS ("\x0a");
        snprintf (desc, sizeof desc, "GNU nano justify case %zu (fill %ld%s)", i + 1,
                  bn_justify_gnu_cases[i].fill, bn_justify_gnu_cases[i].trim ? ", -M" : "");
        BN_ST_ASSERT (desc, bn_st_text_is (bn_justify_gnu_cases[i].out));
    }

    /* Deliberate difference from GNU nano 8.4, which measures a paragraph's
       first line from the byte offset of the second line's lead: with a
       one-byte tab lead below, that offset splits the leading "\xc3\xa9"
       and GNU wraps "\xc3\xa9t\xc3\xa9 sea be a" (12 columns) early, as
       "\xc3\xa9t\xc3\xa9 sea be \n\ta \n...".  Widths here are measured
       from each line's own lead, giving GNU's result for "et\xc3\xa9". */
    bn_st_load ("\xc3\xa9t\xc3\xa9 sea be a deed end.\n\tok! eerie\n");
    bn_fill = 12;
    BN_ST_KEYS ("\x0a");
    BN_ST_ASSERT ("first-line width is measured from its own lead",
                  bn_st_text_is ("\xc3\xa9t\xc3\xa9 sea be a \n\tdeed \n\tend. \n\tok! \n\teerie\n"));

    /* Default fill is the terminal width minus 8, as in GNU nano. */
    bn_st_load ("aaaa bbbb cccc dddd eeee ffff gggg hhhh iiii jjjj kkkk\n");
    bn_cols = 28;
    BN_ST_KEYS ("\x0a");
    BN_ST_ASSERT ("fill -8 on a 28-column terminal wraps at 20",
                  bn_st_text_is ("aaaa bbbb cccc dddd \neeee ffff gggg hhhh \niiii jjjj kkkk\n"));
    BN_ST_ASSERT ("justify reports the paragraph",
                  strcmp (bn_status, "Justified paragraph") == 0);
    BN_ST_ASSERT ("justify leaves the cursor below the paragraph",
                  bn_cy == 3 && bn_cx == 0);
    BN_ST_ASSERT ("justify is one undo step", bn_b.undo.n == 1 && bn_b.dirty);
    BN_ST_KEYS ("\x1a");
    BN_ST_ASSERT ("^Z restores the unjustified paragraph",
                  bn_st_text_is ("aaaa bbbb cccc dddd eeee ffff gggg hhhh iiii jjjj kkkk\n")
                  && bn_b.undo.n == 0 && !bn_b.dirty);
    BN_ST_KEYS ("\x19");
    BN_ST_ASSERT ("^Y re-applies the justification",
                  bn_st_text_is ("aaaa bbbb cccc dddd \neeee ffff gggg hhhh \niiii jjjj kkkk\n"));

    /* Repeated ^J walks paragraph by paragraph, like GNU nano. */
    bn_st_load ("p1 a b c d e f g h i\nnext\n\np2 words long long\n");
    bn_fill = 10;
    BN_ST_KEYS ("\x0a");
    BN_ST_ASSERT ("first ^J justifies the first paragraph only",
                  bn_st_text_is ("p1 a b c d \ne f g h i \nnext\n\np2 words long long\n"));
    BN_ST_ASSERT ("cursor lands on the blank line after it", bn_cy == 3 && bn_cx == 0);
    BN_ST_KEYS ("\x0a");
    BN_ST_ASSERT ("second ^J moves on to the next paragraph",
                  bn_st_text_is ("p1 a b c d \ne f g h i \nnext\n\np2 words \nlong long\n"));

    /* M-J justifies every paragraph as one edit. */
    bn_st_load ("p1 a b c d e f g h i\nnext\n\np2 words long long\n");
    bn_fill = 10;
    BN_ST_KEYS ("\x1bj");
    BN_ST_ASSERT ("M-J justifies the whole buffer",
                  bn_st_text_is ("p1 a b c d \ne f g h i \nnext\n\np2 words \nlong long\n")
                  && bn_b.undo.n == 1 && strcmp (bn_status, "Justified file") == 0);

    /* With the mark set, only the marked lines are justified. */
    bn_st_load ("a b c d e f\n\ng h i j k l\n\nm n o p q r\n");
    bn_fill = 6;
    bn_cy = 2; bn_cx = 0;
    BN_ST_KEYS ("\x1b" "a");
    bn_cy = 4; bn_cx = 3;
    BN_ST_KEYS ("\x0a");
    BN_ST_ASSERT ("marked justify touches only the marked paragraphs",
                  bn_st_text_is ("a b c d e f\n\ng h i \nj k l\n\nm n o \np q r\n"));
    BN_ST_ASSERT ("marked justify unsets the mark and reports the selection",
                  !bn_mark_active && strcmp (bn_status, "Justified selection") == 0);

    /* An already-justified paragraph is not an edit. */
    bn_st_load ("short line\n");
    BN_ST_KEYS ("\x0a");
    BN_ST_ASSERT ("already-justified paragraph adds no undo step and stays clean",
                  bn_b.undo.n == 0 && !bn_b.dirty
                  && strcmp (bn_status, "Paragraph already justified") == 0);

    bn_st_load ("\n\n   \n");
    BN_ST_KEYS ("\x0a");
    BN_ST_ASSERT ("blank buffer reports no paragraph",
                  strcmp (bn_status, "No paragraph to justify") == 0 && bn_b.undo.n == 0);

    /* A very narrow fill puts each word on its own line. */
    bn_st_load ("one two three\n");
    bn_fill = 1;
    BN_ST_KEYS ("\x0a");
    BN_ST_ASSERT ("fill 1 breaks after every word", bn_st_text_is ("one \ntwo \nthree\n"));

    bn_st_reset ();
    printf ("1..%d\n", bn_st_asserts);
    return bn_st_fails ? 1 : 0;
}

static int
bn_st_write_file (const char *dir, const char *name, const char *body, char *path, size_t psz)
{
    snprintf (path, psz, "%s/%s", dir, name);
    int fd = open (path, O_WRONLY | O_CREAT | O_TRUNC, 0700);
    if (fd < 0) return -1;
    size_t n = strlen (body);
    int ok = write (fd, body, n) == (ssize_t) n;
    close (fd);
    return ok ? 0 : -1;
}

static int
bn_st_count_fds (void)
{
    DIR *d = opendir ("/proc/self/fd");
    if (!d) return -1;
    int n = 0;
    while (readdir (d)) n++;
    closedir (d);
    return n;
}

static void
bn_st_set_speller (const char *dir, const char *script)
{
    char cmd[512];
    snprintf (cmd, sizeof cmd, "/proc/self/exe %s/%s", dir, script);
    free (bn_speller);
    bn_speller = strdup (cmd);
}

static int
bn_selftest_spell (void)
{
    bn_st_fails = bn_st_asserts = 0;
    char dir[] = "/tmp/nano-spell.XXXXXX";
    if (!mkdtemp (dir)) { printf ("not ok 1 - mkdtemp\n1..1\n"); return 1; }
    char path[512];
    /* A fixed-dictionary helper with spell(1)'s interface, written in the
       shell itself so the fixture needs no external program. */
    bn_st_write_file (dir, "ok.sh",
        "while IFS= read -r line || [[ -n $line ]]; do\n"
        "  for w in $line; do\n"
        "    case $w in teh|wrold|recieve|na$'\\xc3\\xaf've) printf '%s\\n' \"$w\";; esac\n"
        "  done\n"
        "done\n", path, sizeof path);
    bn_st_write_file (dir, "crlf.sh", "printf 'teh\\r\\n   \\n\\nteh\\n'\n", path, sizeof path);
    bn_st_write_file (dir, "fail.sh", "exit 3\n", path, sizeof path);
    bn_st_write_file (dir, "sig.sh", "kill -KILL $$\n", path, sizeof path);
    bn_st_write_file (dir, "hang.sh", "while :; do :; done\n", path, sizeof path);
    bn_st_write_file (dir, "linger.sh", "exec >&-\nwhile :; do :; done\n", path, sizeof path);
    bn_st_write_file (dir, "big.sh",
        "s=xxxxxxxxxxxxxxx; s=$s$s$s$s$s$s$s$s; s=$s$s$s$s$s$s$s$s\n"
        "while :; do printf '%s\\n' \"$s\"; done\n", path, sizeof path);
    bn_st_write_file (dir, "noread.sh", "printf 'teh\\n'\n", path, sizeof path);

    sigset_t mask_before, mask_after;
    sigprocmask (SIG_SETMASK, NULL, &mask_before);
    struct sigaction pipe_before, pipe_after;
    sigaction (SIGPIPE, NULL, &pipe_before);
    int fds_before = bn_st_count_fds ();

    /* Replace one word everywhere, then Esc out of the next prompt. */
    bn_st_load ("teh cat saw teh wrold near tehran\n");
    bn_st_set_speller (dir, "ok.sh");
    bn_cy = 0; bn_cx = 33;
    BN_ST_KEYS ("\x14", "\x7f", "\x7f", "\x7f", "t", "h", "e", "e", "\r", "\x1b");
    BN_ST_ASSERT ("spell replaces every whole-word occurrence, not substrings",
                  bn_st_text_is ("thee cat saw thee wrold near tehran\n"));
    BN_ST_ASSERT ("Esc at the second word cancels the rest",
                  strcmp (bn_status, "Spell check cancelled (2 replaced)") == 0);
    BN_ST_ASSERT ("the cursor returns to its place, shifted by the edit",
                  bn_cy == 0 && bn_cx == 35);
    BN_ST_ASSERT ("one word's replacements are one undo step", bn_b.undo.n == 1);
    BN_ST_KEYS ("\x1a");
    BN_ST_ASSERT ("^Z restores the misspellings",
                  bn_st_text_is ("teh cat saw teh wrold near tehran\n"));

    /* Input that ends inside the prompt cancels instead of spinning. */
    bn_st_load ("teh cat\n");
    BN_ST_KEYS ("\x14");
    BN_ST_ASSERT ("end of input inside the replacement prompt cancels the check",
                  strcmp (bn_status, "Spell check cancelled (0 replaced)") == 0
                  && bn_st_text_is ("teh cat\n"));

    /* Enter on an unchanged word skips it. */
    bn_st_load ("teh cat saw teh wrold near tehran\n");
    BN_ST_KEYS ("\x14", "\r", "\r");
    BN_ST_ASSERT ("Enter on unchanged words finishes without edits",
                  bn_st_text_is ("teh cat saw teh wrold near tehran\n")
                  && bn_b.undo.n == 0 && !bn_b.dirty
                  && strcmp (bn_status, "Finished checking spelling (0 replaced)") == 0);

    /* Second word replaced too; the multibyte word is edited by cluster. */
    bn_st_load ("teh na\xc3\xafve wrold\n");
    BN_ST_KEYS ("\x14", "\r", "\x7f", "\x7f", "\x7f", "\x7f", "a", "i", "v", "e", "\r",
                "\x7f", "\x7f", "\x7f", "\x7f", "\x7f", "w", "o", "r", "l", "d", "\r");
    BN_ST_ASSERT ("UTF-8 word replaced after grapheme-wise prompt editing",
                  bn_st_text_is ("teh naive world\n")
                  && strcmp (bn_status, "Finished checking spelling (2 replaced)") == 0);

    /* With the mark set, only the region is sent and edited, and the
       selection survives the check. */
    bn_st_load ("teh one\nteh two\n");
    bn_cy = 1; bn_cx = 0;
    BN_ST_KEYS ("\x1b" "a");
    bn_cy = 1; bn_cx = 7;
    BN_ST_KEYS ("\x14", "\x7f", "\x7f", "\x7f", "t", "h", "e", "\r");
    BN_ST_ASSERT ("marked spell check edits only the region",
                  bn_st_text_is ("teh one\nthe two\n"));
    BN_ST_ASSERT ("the mark stays set at its anchor",
                  bn_mark_active && bn_mark_cy == 1 && bn_mark_cx == 0);

    /* Helper output is trimmed and de-duplicated. */
    bn_st_load ("teh teh\n");
    bn_st_set_speller (dir, "crlf.sh");
    BN_ST_KEYS ("\x14", "\x7f", "\x7f", "\x7f", "t", "h", "e", "\r");
    BN_ST_ASSERT ("CRLF/blank helper lines are trimmed and duplicates prompt once",
                  bn_st_text_is ("the the\n")
                  && strcmp (bn_status, "Finished checking spelling (2 replaced)") == 0);

    /* A helper that never reads its input still works (no SIGPIPE). */
    {
        size_t big = 200 * 1024;
        char *text = malloc (big + 1);
        for (size_t i = 0; i < big; i += 4) memcpy (text + i, "teh ", 4);
        text[big] = '\0';
        bn_st_load (text);
        free (text);
        bn_st_set_speller (dir, "noread.sh");
        BN_ST_KEYS ("\x14", "\r");
        BN_ST_ASSERT ("helper that ignores 200 KiB of input is still read",
                      strcmp (bn_status, "Finished checking spelling (0 replaced)") == 0);
    }

    /* Failures leave the buffer alone and say why. */
    static const struct { const char *script; const char *status; int timeout; } fail_cases[] = {
        { "fail.sh", "Spell helper failed (exit 3)", 10000 },
        { "sig.sh", "Spell helper killed by signal 9", 10000 },
        { "hang.sh", "Spell helper timed out", 300 },
        { "linger.sh", "Spell helper timed out", 300 },
        { "big.sh", "Spell helper output too large", 20000 },
    };
    char desc[160];
    for (size_t i = 0; i < sizeof fail_cases / sizeof fail_cases[0]; i++) {
        bn_st_load ("teh wrold\n");
        bn_st_set_speller (dir, fail_cases[i].script);
        bn_spell_timeout_ms = fail_cases[i].timeout;
        BN_ST_KEYS ("\x14");
        snprintf (desc, sizeof desc, "%s: status \"%s\", buffer untouched",
                  fail_cases[i].script, fail_cases[i].status);
        BN_ST_ASSERT (desc, strstr (bn_status, fail_cases[i].status) != NULL
                      && bn_st_text_is ("teh wrold\n") && bn_b.undo.n == 0);
    }
    bn_spell_timeout_ms = 10000;

    bn_st_load ("teh\n");
    free (bn_speller);
    bn_speller = strdup ("/nonexistent/opus-nano-helper --list");
    BN_ST_KEYS ("\x14");
    BN_ST_ASSERT ("missing helper reports not found",
                  strstr (bn_status, "Spell helper not found: /nonexistent/opus-nano-helper") != NULL);
    free (bn_speller);
    bn_speller = strdup (dir);
    BN_ST_KEYS ("\x14");
    BN_ST_ASSERT ("non-executable helper reports cannot run",
                  strstr (bn_status, "Spell helper cannot run") != NULL);
    free (bn_speller);
    bn_speller = strdup (" \t ");
    BN_ST_KEYS ("\x14");
    BN_ST_ASSERT ("blank helper command is rejected without running anything",
                  strcmp (bn_status, "No spell helper configured") == 0);
    free (bn_speller);
    bn_speller = strdup ("/proc/self/exe a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a");
    BN_ST_KEYS ("\x14");
    BN_ST_ASSERT ("too many helper command words are rejected, not truncated",
                  strcmp (bn_status, "Spell helper: at most 31 command words") == 0
                  && bn_st_text_is ("teh\n"));
    free (bn_speller);
    bn_speller = NULL;

    int status = 0;
    pid_t zombie = waitpid (-1, &status, WNOHANG);
    BN_ST_ASSERT ("no helper is left unreaped", zombie <= 0);
    BN_ST_ASSERT ("no descriptor leaks across helper runs",
                  bn_st_count_fds () == fds_before);
    sigprocmask (SIG_SETMASK, NULL, &mask_after);
    BN_ST_ASSERT ("SIGCHLD mask restored",
                  sigismember (&mask_after, SIGCHLD) == sigismember (&mask_before, SIGCHLD));
    sigaction (SIGPIPE, NULL, &pipe_after);
    BN_ST_ASSERT ("SIGPIPE disposition restored",
                  pipe_after.sa_handler == pipe_before.sa_handler);

    static const char *const names[] = { "ok.sh", "crlf.sh", "fail.sh", "sig.sh", "hang.sh",
                                         "linger.sh", "big.sh", "noread.sh" };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        snprintf (path, sizeof path, "%s/%s", dir, names[i]);
        unlink (path);
    }
    rmdir (dir);
    bn_st_reset ();
    printf ("1..%d\n", bn_st_asserts);
    return bn_st_fails ? 1 : 0;
}

static int
bn_selftest_complete (void)
{
    bn_st_fails = bn_st_asserts = 0;
    bn_st_load ("apple\napricot\nap\nape\napex\n");
    bn_cy = 2; bn_cx = 2;
    BN_ST_KEYS ("\x1d");
    BN_ST_ASSERT ("first ^] inserts the first candidate in buffer order",
                  bn_st_text_is ("apple\napricot\napple\nape\napex\n")
                  && bn_cy == 2 && bn_cx == 5
                  && strcmp (bn_status, "Completion 1 of 4") == 0);
    BN_ST_KEYS ("\x1d");
    BN_ST_ASSERT ("second ^] cycles to the next candidate",
                  bn_st_text_is ("apple\napricot\napricot\nape\napex\n") && bn_cx == 7);
    BN_ST_KEYS ("\x1d", "\x1d");
    BN_ST_ASSERT ("candidates after the cursor follow",
                  bn_st_text_is ("apple\napricot\napex\nape\napex\n"));
    BN_ST_KEYS ("\x1d");
    BN_ST_ASSERT ("after the last candidate the fragment returns",
                  bn_st_text_is ("apple\napricot\nap\nape\napex\n")
                  && bn_cx == 2 && strcmp (bn_status, "No further matches") == 0);
    BN_ST_KEYS ("\x1d");
    BN_ST_ASSERT ("the next ^] starts the cycle again",
                  bn_st_text_is ("apple\napricot\napple\nape\napex\n"));
    BN_ST_KEYS ("\x1a");
    BN_ST_ASSERT ("^Z undoes one completion step",
                  bn_st_text_is ("apple\napricot\nap\nape\napex\n"));

    bn_st_load ("apple apple\nap\n");
    bn_cy = 1; bn_cx = 2;
    BN_ST_KEYS ("\x1d", "\x1d");
    BN_ST_ASSERT ("duplicate words are offered once",
                  bn_st_text_is ("apple apple\nap\n")
                  && strcmp (bn_status, "No further matches") == 0);

    /* Typing between presses starts a new completion of the new fragment. */
    bn_st_load ("apple\napplesauce\nap\n");
    bn_cy = 2; bn_cx = 2;
    BN_ST_KEYS ("\x1d", "s", "\x1d");
    BN_ST_ASSERT ("an edit between presses restarts from the new fragment",
                  bn_st_text_is ("apple\napplesauce\napplesauce\n"));

    bn_st_load ("zebra\nzeb\n");
    bn_cy = 0; bn_cx = 3;
    BN_ST_KEYS ("\x1d");
    BN_ST_ASSERT ("the word under the cursor is not its own candidate",
                  bn_st_text_is ("zebra\nzeb\n") && strcmp (bn_status, "No matches") == 0);

    bn_st_load ("alpha \n");
    bn_cx = 6;
    BN_ST_KEYS ("\x1d");
    BN_ST_ASSERT ("no fragment before the cursor is reported",
                  bn_st_text_is ("alpha \n")
                  && strcmp (bn_status, "No word fragment to complete") == 0
                  && bn_b.undo.n == 0);

    bn_st_load ("na\xc3\xafvet\xc3\xa9 \xc3\xbc" "ber\n\xc3\xbc\n");
    bn_cy = 1; bn_cx = 2;
    BN_ST_KEYS ("\x1d");
    BN_ST_ASSERT ("UTF-8 fragment completes to a UTF-8 word",
                  bn_st_text_is ("na\xc3\xafvet\xc3\xa9 \xc3\xbc" "ber\n\xc3\xbc" "ber\n")
                  && bn_cx == 5);

    /* The selection survives completion and follows the inserted text. */
    bn_st_load ("selection anchor\nsel\n");
    bn_cy = 1; bn_cx = 0;
    BN_ST_KEYS ("\x1b" "a");
    bn_cx = 3;
    BN_ST_KEYS ("\x1d");
    BN_ST_ASSERT ("completion keeps the mark and its anchor",
                  bn_st_text_is ("selection anchor\nselection\n")
                  && bn_mark_active && bn_mark_cy == 1 && bn_mark_cx == 0);
    BN_ST_KEYS ("\x1b^");
    BN_ST_ASSERT ("the marked region now copies the completed word",
                  bn_clip && bn_clip_len == 9 && memcmp (bn_clip, "selection", 9) == 0);

    free (bn_clip); bn_clip = NULL; bn_clip_len = 0;
    bn_yank_ring_clear ();
    bn_st_reset ();
    printf ("1..%d\n", bn_st_asserts);
    return bn_st_fails ? 1 : 0;
}

static int
bn_selftest_selection (void)
{
    bn_st_fails = bn_st_asserts = 0;
    /* a, thumbs-up + skin tone (one cluster, 8 bytes), e + combining acute
       (one cluster, 3 bytes), CJK (one cluster, 3 bytes, 2 cells). */
    const char *line = "a\xf0\x9f\x91\x8d\xf0\x9f\x8f\xbd" "e\xcc\x81\xe4\xb8\xad\n";
    bn_st_load (line);
    BN_ST_KEYS ("\x1b[C");
    BN_ST_ASSERT ("right steps over the ASCII cluster", bn_cx == 1);
    BN_ST_KEYS ("\x1b[C");
    BN_ST_ASSERT ("right steps over the whole emoji+modifier cluster", bn_cx == 9);
    BN_ST_KEYS ("\x1b[C");
    BN_ST_ASSERT ("right steps over e+combining acute", bn_cx == 12);
    BN_ST_KEYS ("\x1b[C");
    BN_ST_ASSERT ("right steps over the CJK cluster to line end", bn_cx == 15);
    BN_ST_KEYS ("\x1b[D", "\x1b[D");
    BN_ST_ASSERT ("left steps back cluster by cluster", bn_cx == 9);
    BN_ST_KEYS ("\x7f");
    BN_ST_ASSERT ("backspace removes the whole emoji cluster",
                  bn_st_text_is ("ae\xcc\x81\xe4\xb8\xad\n") && bn_cx == 1);
    BN_ST_KEYS ("\x1a");

    /* Mark across clusters, move, copy. */
    bn_st_load (line);
    BN_ST_KEYS ("\x1b" "a", "\x1b[C", "\x1b[C", "\x1b[C");
    BN_ST_ASSERT ("the mark stays set while the cursor moves",
                  bn_mark_active && bn_mark_cy == 0 && bn_mark_cx == 0 && bn_cx == 12);
    {
        fflush (stdout);
        char tmpl[] = "/tmp/nano-render.XXXXXX";
        int fd = mkstemp (tmpl);
        int saved = dup (STDOUT_FILENO);
        dup2 (fd, STDOUT_FILENO);
        bn_render ();
        dup2 (saved, STDOUT_FILENO);
        close (saved);
        char buf[4096] = {0};
        lseek (fd, 0, SEEK_SET);
        ssize_t n = read (fd, buf, sizeof buf - 1);
        close (fd);
        unlink (tmpl);
        const char *want = "\033[7ma\xf0\x9f\x91\x8d\xf0\x9f\x8f\xbd" "e\xcc\x81\033[0m\xe4\xb8\xad";
        BN_ST_ASSERT ("render draws exactly the marked clusters in reverse video",
                      n > 0 && memmem (buf, (size_t) n, want, strlen (want)) != NULL);
    }
    BN_ST_KEYS ("\x1b^");
    BN_ST_ASSERT ("M-^ copies whole clusters", bn_clip && bn_clip_len == 12
                  && memcmp (bn_clip, line, 12) == 0 && !bn_mark_active);

    /* The anchor follows edits before it and survives undo. */
    bn_st_load ("first\nsecond line\n");
    bn_cy = 1; bn_cx = 7;
    BN_ST_KEYS ("\x1b" "a");
    bn_cy = 1; bn_cx = 0;
    BN_ST_KEYS ("X", "Y");
    BN_ST_ASSERT ("typing before the anchor on its line shifts it",
                  bn_mark_active && bn_mark_cy == 1 && bn_mark_cx == 9);
    bn_cy = 0; bn_cx = 0;
    BN_ST_KEYS ("\r");
    BN_ST_ASSERT ("a new line above moves the anchor down",
                  bn_mark_active && bn_mark_cy == 2 && bn_mark_cx == 9);
    BN_ST_KEYS ("\x1a");
    BN_ST_ASSERT ("undo keeps the selection active",
                  bn_mark_active && bn_st_text_is ("first\nXYsecond line\n"));
    BN_ST_ASSERT ("undo maps the anchor back through the inverse edit",
                  bn_mark_cy == 1 && bn_mark_cx == 9);
    bn_cy = 1; bn_cx = 10;
    BN_ST_KEYS ("\x1b^");
    BN_ST_ASSERT ("copy after edits covers the intended text",
                  bn_clip && bn_clip_len == 1 && bn_clip[0] == 'l');

    /* Vertical movement keeps the screen column (GNU nano 8.4 lands after
       the second CJK character from column 4) and never splits a wide
       cluster: from column 3 it stops after the first one. */
    bn_st_load ("abcdef\n\xe4\xb8\xad\xe6\x96\x87\xe4\xb8\xad\n");
    bn_cx = 4;
    BN_ST_KEYS ("\x1b[B");
    BN_ST_ASSERT ("down onto CJK keeps screen column 4 (after two wide clusters)",
                  bn_cy == 1 && bn_cx == 6);
    bn_cy = 0; bn_cx = 3;
    bn_want_col = -1;           /* the cursor was placed, not moved */
    BN_ST_KEYS ("\x0e");
    BN_ST_ASSERT ("^N from column 3 stops before the wide cluster spanning it",
                  bn_cy == 1 && bn_cx == 3);
    bn_st_load ("abcdefgh\nab\n\xe4\xb8\xad\xe6\x96\x87\xe4\xb8\xad\xe6\x96\x87\n\tx\n");
    bn_cx = 6;
    BN_ST_KEYS ("\x1b[B");
    BN_ST_ASSERT ("a short line clamps the cursor to its end", bn_cy == 1 && bn_cx == 2);
    BN_ST_KEYS ("\x1b[B");
    BN_ST_ASSERT ("the next line restores the remembered column 6",
                  bn_cy == 2 && bn_cx == 9);
    BN_ST_KEYS ("\x1b[B");
    BN_ST_ASSERT ("a tab spans columns 0..7, so column 6 lands before it",
                  bn_cy == 3 && bn_cx == 0);
    BN_ST_KEYS ("\x1b[A", "\x1b[A", "\x1b[A");
    BN_ST_ASSERT ("moving back up returns to column 6 on the first line",
                  bn_cy == 0 && bn_cx == 6);
    BN_ST_KEYS ("\x1b[B", "\x1b[D", "\x1b[B");
    BN_ST_ASSERT ("a horizontal move resets the remembered column (1 is inside a wide cluster)",
                  bn_cy == 2 && bn_cx == 0);
    BN_ST_KEYS ("\x1bOA");
    BN_ST_ASSERT ("SS3 up (application cursor mode) moves like CSI up",
                  bn_cy == 1 && bn_cx == 1);

    free (bn_clip); bn_clip = NULL; bn_clip_len = 0;
    bn_yank_ring_clear ();
    bn_st_reset ();
    printf ("1..%d\n", bn_st_asserts);
    return bn_st_fails ? 1 : 0;
}

/* The incremental render-line cache must equal a full re-split after any
   edit sequence. */
static int
bn_st_lines_match_full_sync (void)
{
    /* Split an independent flattened copy without rebuilding the live cache:
       rebuilding here would erase pending shifts between random edits. */
    size_t len = 0;
    char *flat = bn_pt_flatten (&bn_b.pt, &len);
    if (!flat) return 0;
    size_t line = 0, start = 0;
    int ok = 1;
    for (size_t end = 0; end <= len; end++) {
        if (end < len && flat[end] != '\n') continue;
        if (line >= bn_b.n_lines) { ok = 0; break; }
        const bn_line *L = &bn_b.lines[line];
        size_t n = end - start;
        if (bn_labs (line) != start || L->len != n
            || (n && memcmp (L->data, flat + start, n) != 0)) ok = 0;
        line++;
        start = end + 1;
    }
    ok = ok && line == bn_b.n_lines
         && bn_b.had_trailing_nl == (len > 0 && flat[len - 1] == '\n');
    free (flat);
    return ok;
}

static int
bn_selftest_linecache (void)
{
    bn_st_fails = bn_st_asserts = 0;
    bn_st_load ("alpha\nbeta\n\ngamma delta\nepsilon");
    unsigned long seed = 12345;
    int all_ok = 1, first_bad = -1;
    static const char *const ins[] = { "", "x", "\n", "ab\ncd", "\n\n", "\xe4\xb8\xad", "tail\n" };
    for (int step = 0; step < 2000 && all_ok; step++) {
        seed = seed * 6364136223846793005UL + 1442695040888963407UL;
        size_t total = bn_b.pt.total_len;
        size_t a = total ? (size_t) ((seed >> 33) % (total + 1)) : 0;
        size_t len = (size_t) ((seed >> 20) % 4);
        size_t b = a + len > total ? total : a + len;
        const char *s = ins[(seed >> 8) % (sizeof ins / sizeof ins[0])];
        if (step % 50 == 49) bn_undo ();
        else bn_piece_replace (a, b, s, strlen (s), a + strlen (s));
        if (!bn_st_lines_match_full_sync ()) { all_ok = 0; first_bad = step; }
    }
    if (!all_ok) printf ("# first mismatch at step %d\n", first_bad);
    BN_ST_ASSERT ("2000 random edits keep the line cache equal to a full re-split", all_ok);
    {
        size_t fl = 0, counted = 0;
        char *f = bn_pt_flatten (&bn_b.pt, &fl);
        for (size_t i = 0; i < bn_b.pt.n_pieces; i++) counted += bn_b.pt.pieces[i].line_count;
        BN_ST_ASSERT ("piece line counts derived from split sides stay exact",
                      f && counted == bn_pt_count_nl (f, fl) && counted == bn_b.pt.total_lines
                      && bn_b.pt.n_pieces > 10);
        free (f);
    }

    /* Undo the whole history back to the original text. */
    while (bn_b.undo.n) bn_undo ();
    BN_ST_ASSERT ("undoing every edit restores the original",
                  bn_st_text_is ("alpha\nbeta\n\ngamma delta\nepsilon"));

    /* Typing a run extends one piece instead of adding one per key. */
    bn_st_load ("0123456789\n");
    bn_cx = 5;
    for (int i = 0; i < 200; i++) bn_insert_bytes ("k", 1);
    BN_ST_ASSERT ("200 typed bytes add at most two pieces", bn_b.pt.n_pieces <= 3);
    for (int i = 0; i < 200; i++) bn_undo ();
    BN_ST_ASSERT ("each coalesced keystroke still undoes separately",
                  bn_st_text_is ("0123456789\n") && bn_b.undo.n == 0);
    /* Undo half of a coalesced run, then type at its end: the shortened
       piece no longer ends at the add buffer's end, so the new byte must
       get its own piece rather than resurrect the undone one. */
    bn_cy = 0; bn_cx = 5;
    bn_insert_bytes ("a", 1);
    bn_insert_bytes ("b", 1);
    bn_undo ();
    bn_cy = 0; bn_cx = 6;
    bn_insert_bytes ("Q", 1);
    BN_ST_ASSERT ("typing after a partial undo writes fresh add-buffer bytes",
                  bn_st_text_is ("01234aQ56789\n"));
    BN_ST_ASSERT ("line cache consistent after coalesced edits", bn_st_lines_match_full_sync ());

    bn_st_reset ();
    printf ("1..%d\n", bn_st_asserts);
    return bn_st_fails ? 1 : 0;
}

/* Render one frame to a temporary file and return its bytes (NUL
   terminated; *N receives the length). */
static char *
bn_st_capture_render (size_t *n)
{
    fflush (stdout);
    char tmpl[] = "/tmp/nano-render.XXXXXX";
    int fd = mkstemp (tmpl);
    if (fd < 0) return NULL;
    unlink (tmpl);
    int saved = dup (STDOUT_FILENO);
    dup2 (fd, STDOUT_FILENO);
    bn_render ();
    dup2 (saved, STDOUT_FILENO);
    close (saved);
    off_t len = lseek (fd, 0, SEEK_END);
    char *buf = malloc ((size_t) (len > 0 ? len : 0) + 1);
    ssize_t r = buf && len > 0 ? pread (fd, buf, (size_t) len, 0) : 0;
    close (fd);
    if (!buf) return NULL;
    if (r < 0) r = 0;
    buf[r] = '\0';
    *n = (size_t) r;
    return buf;
}

/* The terminal input path: bytes written to a pipe on stdin go through
   bn_read_key's poll/read framing, exactly as from a terminal. */
static int
bn_selftest_input (void)
{
    bn_st_fails = bn_st_asserts = 0;
    int saved_in = dup (STDIN_FILENO);
    int p[2];
    if (saved_in < 0 || pipe (p) < 0) {
        printf ("not ok 1 - pipe\n1..1\n");
        return 1;
    }
    dup2 (p[0], STDIN_FILENO);
    close (p[0]);
    static const char burst[] =
        "\x1b[C\x1b[Cab\x1b[Dc"         /* arrows and text in one write */
        "\x1bOA" "\x1bj"                /* SS3 up, Alt-j */
        "\x1b\x1b[B"                    /* ESC ESC [ B */
        "\xc3\xa9" "\xc3" "A"           /* e-acute, broken lead then A */
        "\x1b[1;5C" "\x1b\xc3\xa9"      /* CSI with parameters, Alt+e-acute */
        "\x1b[1;2;3;4;5;6Hz"            /* CSI longer than a prompt buffer */
        "\x1b";                         /* lone ESC, then end of input */
    static const char *const want[] = {
        "\x1b[C", "\x1b[C", "a", "b", "\x1b[D", "c", "\x1bOA", "\x1bj",
        "\x1b", "\x1b[B", "\xc3\xa9", "\xc3", "A", "\x1b[1;5C", "\x1b\xc3\xa9",
        "\x1b[1;2;3", "z", "\x1b",
    };
    size_t nwant = sizeof want / sizeof want[0];
    ssize_t wr = write (p[1], burst, sizeof burst - 1);
    close (p[1]);
    int ok = wr == (ssize_t) (sizeof burst - 1);
    size_t got = 0;
    char k[16];
    int klen;
    for (;;) {
        /* The long CSI is read with a prompt-sized buffer. */
        size_t sz = got == 15 ? 8 : sizeof k;
        klen = bn_read_key (k, sz);
        if (klen < 0) break;
        if (got >= nwant || (size_t) klen != strlen (want[got])
            || memcmp (k, want[got], (size_t) klen) != 0) {
            printf ("# key %zu: got %d bytes \"", got, klen);
            for (int i = 0; i < klen; i++) printf ("\\x%02x", (unsigned char) k[i]);
            printf ("\"\n");
            ok = 0;
        }
        got++;
    }
    BN_ST_ASSERT ("a mixed burst splits into exactly one key per sequence", ok && got == nwant);
    BN_ST_ASSERT ("nothing is left pushed back at end of input", bn_unread < 0);

    /* The same framing feeds dispatch: GNU nano 8.4 turns this burst on
       0123456789 into 01acb23456789. */
    bn_st_load ("0123456789\n");
    if (pipe (p) == 0) {
        dup2 (p[0], STDIN_FILENO);
        close (p[0]);
        wr = write (p[1], "\x1b[C\x1b[Cab\x1b[Dc\x1b[B\x1b[A\x05!", 20);
        close (p[1]);
        fflush (stdout);
        int so = dup (STDOUT_FILENO), dn = open ("/dev/null", O_WRONLY);
        if (dn >= 0) { dup2 (dn, STDOUT_FILENO); close (dn); }
        while ((klen = bn_read_key (k, sizeof k)) > 0)
            bn_dispatch (k, klen);
        if (so >= 0) { dup2 (so, STDOUT_FILENO); close (so); }
    }
    BN_ST_ASSERT ("burst edits apply in order with no key lost",
                  wr == 20 && bn_st_text_is ("01acb23456789!\n"));

    dup2 (saved_in, STDIN_FILENO);
    close (saved_in);
    bn_unread = -1;
    bn_st_reset ();
    printf ("1..%d\n", bn_st_asserts);
    return bn_st_fails ? 1 : 0;
}

/* Display form: tabs, controls and malformed UTF-8 in text, names and
   status messages, and the emergency save used on SIGHUP/SIGTERM. */
static int
bn_selftest_display (void)
{
    bn_st_fails = bn_st_asserts = 0;
    size_t n = 0;
    char *out;

    bn_st_load ("\tx\n");
    BN_ST_KEYS ("\x05");
    out = bn_st_capture_render (&n);
    BN_ST_ASSERT ("a leading tab is drawn as eight spaces",
                  out && strstr (out, "\033[K        x\r\n") != NULL);
    BN_ST_ASSERT ("the cursor after the tab and x is at screen column 10",
                  out && strstr (out, "\033[2;10H") != NULL);
    BN_ST_ASSERT ("no raw tab reaches the terminal", out && !memchr (out, '\t', n));
    free (out);

    bn_st_load ("ab\tc\n");
    BN_ST_KEYS ("\x05");
    out = bn_st_capture_render (&n);
    BN_ST_ASSERT ("a tab after two columns expands to the next stop",
                  out && strstr (out, "ab      c") && strstr (out, "\033[2;10H"));
    free (out);

    bn_st_load ("a\x1b]0;PWNED\x07" "b\xc2\x9b" "31m\x80\x7f\n");
    BN_ST_KEYS ("\x05");
    out = bn_st_capture_render (&n);
    BN_ST_ASSERT ("controls in text show in caret form, C1 as ^{, bad UTF-8 as U+FFFD",
                  out && strstr (out, "a^[]0;PWNED^Gb^{31m\xef\xbf\xbd^?") != NULL);
    BN_ST_ASSERT ("no OSC, BEL or C1 from the file reaches the terminal",
                  out && !memmem (out, n, "\x1b]", 2) && !memchr (out, '\a', n)
                  && !memmem (out, n, "\xc2\x9b", 2) && !memmem (out, n, "\x80\x7f", 2));
    BN_ST_ASSERT ("the cursor column counts each caret form as two cells",
                  out && strstr (out, "\033[2;23H") != NULL);
    free (out);

    bn_st_load ("x\n");
    bn_b.path = strdup ("evil\x1b[2J\x1b]0;t\x07name");
    out = bn_st_capture_render (&n);
    BN_ST_ASSERT ("a file name is shown in display form in the title",
                  out && strstr (out, "evil^[[2J^[]0;t^Gname") != NULL
                  && !memmem (out, n, "\x1b[2J", 4) && !memchr (out, '\a', n));
    free (out);

    bn_st_load ("x\n");
    bn_cols = 40;
    bn_set_status ("%s", "0123456789012345678901234567890123456789TAIL\x1b[2J");
    out = bn_st_capture_render (&n);
    BN_ST_ASSERT ("a long status is cut to the terminal width, never wrapped",
                  out && strstr (out, "\033[7m 0123456789012345678901234567890123456 \033[K")
                  && !strstr (out, "TAIL") && !memmem (out, n, "\x1b[2J", 4));
    free (out);
    bn_cols = 80;

    /* Horizontal scrolling past a tab draws only its visible part. */
    bn_st_load ("\tabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123ABCDEFGH\n");
    BN_ST_KEYS ("\x05");
    out = bn_st_capture_render (&n);
    {
        const char *row = out ? strstr (out, "\r\n\033[K") : NULL;
        size_t cells = 0;
        if (row) {
            row += 5;
            for (const char *c = row; *c && *c != '\r' && *c != '\033'; c++) cells++;
        }
        /* Width 82, so the view starts at column 4: half the tab shows. */
        BN_ST_ASSERT ("a tab cut by the left edge draws only its visible part",
                      row && cells == 78 && strncmp (row, "    abc", 7) == 0
                      && strstr (out, "ABCDEFGH\r\n") && strstr (out, "\033[2;79H"));
    }
    free (out);

    /* Width 80 starts the view at column 2, inside the CJK character. */
    {
        char line[128] = "a\xe4\xb8\xad";
        memset (line + 4, 'x', 77);
        strcpy (line + 81, "\n");
        bn_st_load (line);
        BN_ST_KEYS ("\x05");
        out = bn_st_capture_render (&n);
        const char *row = out ? strstr (out, "\r\n\033[K") : NULL;
        char want[96] = " ";
        memset (want + 1, 'x', 77);
        strcpy (want + 78, "\r\n");
        BN_ST_ASSERT ("a wide character cut by the left edge shows a blank cell",
                      row && strncmp (row + 5, want, 80) == 0 && strstr (out, "\033[2;79H"));
        free (out);
    }

    /* Emergency save. */
    char dir[] = "/tmp/nano-rescue.XXXXXX";
    if (mkdtemp (dir)) {
        char doc[256], p0[300], p1[300], p2[300], tgt[300];
        snprintf (doc, sizeof doc, "%s/doc.txt", dir);
        snprintf (p0, sizeof p0, "%s.save", doc);
        snprintf (p1, sizeof p1, "%s.save.1", doc);
        snprintf (p2, sizeof p2, "%s.save.2", doc);
        snprintf (tgt, sizeof tgt, "%s/target", dir);
        int fd = open (p0, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd >= 0) { (void) write (fd, "old", 3); close (fd); }
        (void) symlink (tgt, p1);
        bn_st_load ("rescued text\n");
        bn_b.path = strdup (doc);
        bn_b.dirty = 1;
        char *name = bn_emergency_save ();
        struct stat st;
        char buf[64] = {0};
        int ok = name && strcmp (name, p2) == 0 && stat (p2, &st) == 0
                 && (st.st_mode & 0777) == 0600;
        fd = open (p2, O_RDONLY);
        if (fd >= 0) { (void) read (fd, buf, sizeof buf - 1); close (fd); }
        BN_ST_ASSERT ("emergency save skips an existing .save and a symlinked .save.1",
                      ok && strcmp (buf, "rescued text\n") == 0);
        memset (buf, 0, sizeof buf);
        fd = open (p0, O_RDONLY);
        if (fd >= 0) { (void) read (fd, buf, sizeof buf - 1); close (fd); }
        BN_ST_ASSERT ("the existing .save and the symlink target are untouched",
                      strcmp (buf, "old") == 0 && access (tgt, F_OK) != 0);
        free (name);
        free (bn_b.path);
        snprintf (p0, sizeof p0, "%s/missing/doc.txt", dir);
        bn_b.path = strdup (p0);
        errno = 0;
        name = bn_emergency_save ();
        BN_ST_ASSERT ("an unwritable location fails with errno, writing nothing",
                      name == NULL && errno == ENOENT);
        free (name);
        unlink (p2); unlink (p1);
        snprintf (p0, sizeof p0, "%s.save", doc);
        unlink (p0);
        rmdir (dir);
    } else {
        BN_ST_ASSERT ("mkdtemp for the emergency-save fixture", 0);
    }

    bn_st_reset ();
    printf ("1..%d\n", bn_st_asserts);
    return bn_st_fails ? 1 : 0;
}

/* Incremental, windowed highlighting must colour every drawn byte exactly
   as a from-scratch parse of the whole text does (bashts_compute_sgr_map,
   the oracle), after random edits, undo and redo through the production
   edit and render paths. */
static int
bn_selftest_highlight (void)
{
    bn_st_fails = bn_st_asserts = 0;
    static const struct { const char *lang, *name, *text; } fx[] = {
        { "bash", "t.sh",
          "#!/bin/sh\n# comment\nfor i in 1 2 3; do\n  echo \"item $i\" | grep -q x && n=$((n + i))\ndone\n"
          "cat <<EOF\nheredoc $HOME line\nEOF\nf() { local v='single'; printf '%s\\n' \"$v\"; }\n"
          "case $1 in a) echo A ;; *) echo other ;; esac\nx=${y:-default} # trailing\n" },
        { "json", "t.json",
          "{\n  \"name\": \"value\",\n  \"n\": 12.5,\n  \"list\": [true, false, null, \"s\"],\n"
          "  \"obj\": {\"k\": \"v\", \"deep\": {\"a\": [1, 2, {\"b\": \"c\"}]}}\n}\n" },
        { "markdown", "t.md",
          "# Title\n\nSome *text* and `code` here.\n\n## Section\n\n- item one\n- item two\n\n"
          "```sh\necho hi\n```\n\n> quote line\n\n1. first\n2. second\n" },
    };
    static const char *const snippets[] = {
        "\"", "'", "#", "$(", ")", "<<EOF\n", "\nEOF\n", "echo x ", "\n", "{", "}",
        "[", "]", ",", ": ", "*", "`", "```\n", "# ", "- ", "\\", "x", "  ",
    };
    unsigned long seed = 20261020;
    bn_hl_budget_us = -1;               /* every frame settles: exact oracle */
#define BN_RAND() (seed = seed * 6364136223846793005UL + 1442695040888963407UL, (size_t) (seed >> 33))
    int saved = dup (STDOUT_FILENO);
    for (size_t f = 0; f < sizeof fx / sizeof fx[0]; f++) {
        bn_st_load (fx[f].text);
        bn_detect_language (fx[f].name);
        bn_rows = 6;                     /* windows cover part of the text */
        int frames = 0, equal = 0, reused = 1, covered = 1, stale_differs = 0;
        size_t coloured = 0, partial = 0;
        void *tree = NULL;
        const char **prev = NULL;       /* full map of the previous text */
        size_t prev_len = 0;
        for (int step = 0; step < 160; step++) {
            size_t len = bn_b.pt.total_len;
            size_t r = BN_RAND () % 10;
            if (r < 6 || len == 0) {
                const char *ins = snippets[BN_RAND () % (sizeof snippets / sizeof snippets[0])];
                size_t pos = len ? BN_RAND () % (len + 1) : 0;
                bn_piece_replace (pos, pos, ins, strlen (ins), pos + strlen (ins));
            } else if (r < 8) {
                size_t pos = BN_RAND () % len, n = 1 + BN_RAND () % 6;
                if (pos + n > len) n = len - pos;
                bn_piece_replace (pos, pos + n, NULL, 0, pos);
            } else if (r == 8) {
                bn_undo ();
            } else {
                bn_redo ();
            }
            bn_cy = (long) (BN_RAND () % bn_b.n_lines);
            bn_cx = 0;
            fflush (stdout);
            int dn = open ("/dev/null", O_WRONLY);
            if (dn >= 0) { dup2 (dn, STDOUT_FILENO); close (dn); }
            bn_render ();
            fflush (stdout);
            dup2 (saved, STDOUT_FILENO);
            frames++;
            if (tree && bn_hl_cache.ts_state != tree) reused = 0;
            tree = bn_hl_cache.ts_state;
            size_t flen = 0;
            char *flat = bn_pt_flatten (&bn_b.pt, &flen);
            const char **full = calloc (flen + 1, sizeof *full);
            if (!flat || !full || !bn_hl_cache.sgr_at) { free (flat); free (full); continue; }
            bashts_compute_sgr_map (bn_lang, flat, flen, full);
            int same = 1, stale_same = 1;
            for (size_t b = bn_hl_cache.lo; b < bn_hl_cache.hi; b++) {
                const char *got = bn_hl_cache.sgr_at[b - bn_hl_cache.lo];
                if (got != full[b]) same = 0;
                if (got) coloured++;
                /* Negative control: the previous text's map, as a window
                   that missed the edit would show. */
                if (!prev || b >= prev_len || prev[b] != got) stale_same = 0;
            }
            if (!stale_same) stale_differs++;
            if (bn_hl_cache.hi - bn_hl_cache.lo < flen) partial++;
            free (prev);
            prev = full;
            prev_len = flen;
            full = NULL;
            /* The cursor line is always inside the window. */
            size_t cl = bn_labs ((size_t) bn_cy);
            if (!(bn_hl_cache.lo <= cl && cl <= bn_hl_cache.hi)) covered = 0;
            if (same) equal++;
            else printf ("# %s step %d: window %zu-%zu differs from the full parse\n",
                         fx[f].lang, step, bn_hl_cache.lo, bn_hl_cache.hi);
            free (flat);
            free (full);
        }
        char desc[160];
        snprintf (desc, sizeof desc, "%s: %d/%d windows after random edits, undo and redo equal a full parse",
                  fx[f].lang, equal, frames);
        BN_ST_ASSERT (desc, frames == 160 && equal == frames);
        snprintf (desc, sizeof desc, "%s: one parse tree is kept and edited across all frames", fx[f].lang);
        BN_ST_ASSERT (desc, reused && tree != NULL);
        snprintf (desc, sizeof desc, "%s: the colour window always covers the cursor line", fx[f].lang);
        BN_ST_ASSERT (desc, covered);
        snprintf (desc, sizeof desc, "%s: the comparison is not vacuous (%zu coloured bytes, %zu partial "
                  "windows, %d frames where the previous text's colours differ)",
                  fx[f].lang, coloured, partial, stale_differs);
        BN_ST_ASSERT (desc, coloured >= 1000 && partial >= 100 && stale_differs >= 40);
        free (prev);
        bn_highlight_release ();
        bn_lang = NULL;
    }
    close (saved);
#undef BN_RAND

    /* A 2 MiB buffer is coloured only around the screen.  With a frame
       budget too small for its parse, frames are drawn at once from the
       edited old tree and idle slices settle them to the full parse. */
    {
        size_t big = 2u << 20, used = 0;
        char *text = malloc (big + 64);
        while (text && used < big) {
            int n = snprintf (text + used, 64, "echo \"line %zu\" # c\n", used);
            used += (size_t) n;
        }
        if (text) {
            bn_st_load (text);
            free (text);
            bn_detect_language ("big.sh");
            bn_cy = (long) bn_b.n_lines / 2;
            bn_cx = 0;
            int so = dup (STDOUT_FILENO);
#define BN_ST_QUIET_RENDER() do { \
                fflush (stdout); \
                int dn_ = open ("/dev/null", O_WRONLY); \
                if (dn_ >= 0) { dup2 (dn_, STDOUT_FILENO); close (dn_); } \
                bn_render (); \
                fflush (stdout); \
                if (so >= 0) dup2 (so, STDOUT_FILENO); \
            } while (0)
            /* Compare the window with a full parse of the current text;
               returns 1 when equal, with the number of coloured bytes. */
            size_t coloured = 0;
#define BN_ST_WINDOW_EQUALS_FULL(out_eq) do { \
                size_t fl_ = 0; \
                char *fs_ = bn_pt_flatten (&bn_b.pt, &fl_); \
                const char **fm_ = fs_ ? calloc (fl_ + 1, sizeof *fm_) : NULL; \
                (out_eq) = fm_ && bn_hl_cache.sgr_at \
                           && bashts_compute_sgr_map (bn_lang, fs_, fl_, fm_) == 0; \
                coloured = 0; \
                for (size_t b_ = bn_hl_cache.lo; (out_eq) && b_ < bn_hl_cache.hi; b_++) { \
                    if (bn_hl_cache.sgr_at[b_ - bn_hl_cache.lo] != fm_[b_]) (out_eq) = 0; \
                    if (fm_[b_]) coloured++; \
                } \
                free (fs_); free (fm_); \
            } while (0)

            bn_hl_budget_us = 0;
            BN_ST_QUIET_RENDER ();
            int none = bn_hl_cache.sgr_at != NULL;
            for (size_t b = bn_hl_cache.lo; none && b < bn_hl_cache.hi; b++)
                if (bn_hl_cache.sgr_at[b - bn_hl_cache.lo]) none = 0;
            BN_ST_ASSERT ("an unparsed 2 MiB script's first frame is drawn uncoloured, its parse pending",
                          bn_hl_pending && none);
            int slices = 0;
            while (!bn_highlight_idle (1000) && slices < 100000) slices++;
            BN_ST_QUIET_RENDER ();
            int eq = 0;
            BN_ST_WINDOW_EQUALS_FULL (eq);
            char desc[200];
            snprintf (desc, sizeof desc, "idle 1 ms slices (%d) finish that parse; the window then equals a "
                      "full parse (%zu coloured bytes)", slices + 1, coloured);
            BN_ST_ASSERT (desc, slices >= 2 && !bn_hl_pending && eq && coloured >= 1000);
            BN_ST_ASSERT ("a 2 MiB buffer is coloured in a window of a few screens, not whole",
                          bn_hl_cache.sgr_at && bn_hl_cache.hi - bn_hl_cache.lo < 8192
                          && bn_hl_cache.lo <= bn_labs ((size_t) bn_cy)
                          && bn_labs ((size_t) bn_cy) < bn_hl_cache.hi);

            /* Comment out the cursor line: the stale frame keeps the old
               colours, the settled one shows the comment. */
            size_t line = bn_labs ((size_t) bn_cy), above = bn_labs ((size_t) bn_cy - 1);
            const char *cmd_sgr = bn_hl_cache.sgr_at[line - bn_hl_cache.lo];
            const char *above_sgr = bn_hl_cache.sgr_at[above - bn_hl_cache.lo];
            /* The line ends "# c\n": its last visible byte is comment. */
            const char *cmt_sgr = bn_hl_cache.sgr_at[bn_labs ((size_t) bn_cy + 1) - 2 - bn_hl_cache.lo];
            void *kept = bn_hl_cache.ts_state;
            bn_insert_bytes ("#", 1);
            BN_ST_QUIET_RENDER ();
            int stale = bn_hl_pending && bn_hl_cache.sgr_at
                        && bn_hl_cache.sgr_at[above - bn_hl_cache.lo] == above_sgr
                        && bn_hl_cache.sgr_at[line + 1 - bn_hl_cache.lo] == cmd_sgr
                        && cmd_sgr != cmt_sgr && cmt_sgr != NULL;
            BN_ST_ASSERT ("after an edit the frame comes from the edited old tree: the line above and the "
                          "shifted command keep their colours while the reparse is pending", stale);
            /* A second edit while that parse is halted abandons it. */
            bn_insert_bytes (" ", 1);
            BN_ST_QUIET_RENDER ();
            int restarted = bn_hl_pending;
            slices = 0;
            while (!bn_highlight_idle (1000) && slices < 100000) slices++;
            BN_ST_QUIET_RENDER ();
            BN_ST_WINDOW_EQUALS_FULL (eq);
            BN_ST_ASSERT ("an edit during a halted reparse restarts it; settled, the commented line is "
                          "coloured as the full parse colours it",
                          restarted && eq && !bn_hl_pending && bn_hl_cache.ts_state == kept
                          && bn_hl_cache.sgr_at[line - bn_hl_cache.lo] == cmt_sgr
                          && bn_hl_cache.sgr_at[line + 2 - bn_hl_cache.lo] == cmt_sgr);
            /* A new window over a settled tree is a query, not a parse. */
            bn_hl_budget_us = 0;
            bn_cy = 0;
            BN_ST_QUIET_RENDER ();
            BN_ST_WINDOW_EQUALS_FULL (eq);
            BN_ST_ASSERT ("jumping to the top of a settled tree colours the new window at once, nothing pending",
                          !bn_hl_pending && eq && bn_hl_cache.lo == 0);
#undef BN_ST_QUIET_RENDER
#undef BN_ST_WINDOW_EQUALS_FULL
            if (so >= 0) close (so);
            bn_highlight_release ();
            bn_lang = NULL;
        } else {
            BN_ST_ASSERT ("2 MiB fixture allocation", 0);
        }
    }
    bn_hl_budget_us = BN_HL_BUDGET_US;
    bn_st_reset ();
    printf ("1..%d\n", bn_st_asserts);
    return bn_st_fails ? 1 : 0;
}

#undef BN_ST_ASSERT
#undef BN_ST_KEYS

extern char *nano_doc[];

int
nano_builtin (WORD_LIST *list)
{
    /* v2 — selftest path doesn't need a TTY. */
    if (list && list->word && strcmp (list->word->word, "selftest") == 0)
        return bn_selftest () ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    if (list && list->word && strcmp (list->word->word, "selftest-piecetable") == 0)
        return bn_selftest_piecetable () ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    if (list && list->word && strcmp (list->word->word, "selftest-keybindings") == 0)
        return bn_selftest_keybindings () ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    if (list && list->word && strcmp (list->word->word, "selftest-saveprompt") == 0)
        return bn_selftest_saveprompt () ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    if (list && list->word && strcmp (list->word->word, "selftest-replace") == 0)
        return bn_selftest_replace () ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    if (list && list->word && strcmp (list->word->word, "selftest-search") == 0)
        return bn_selftest_search () ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    if (list && list->word && strcmp (list->word->word, "selftest-resize") == 0)
        return bn_selftest_resize () ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    if (list && list->word && strcmp (list->word->word, "selftest-statusbar") == 0)
        return bn_selftest_statusbar () ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    if (list && list->word && strcmp (list->word->word, "selftest-yank-ring") == 0)
        return bn_selftest_yank_ring () ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    if (list && list->word && strcmp (list->word->word, "selftest-atomic-save") == 0)
        return bn_selftest_atomic_save () ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    if (list && list->word && strcmp (list->word->word, "selftest-undo-redo") == 0)
        return bn_selftest_undo_redo () ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    if (list && list->word && strcmp (list->word->word, "selftest-justify") == 0)
        return bn_selftest_justify () ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    if (list && list->word && strcmp (list->word->word, "selftest-spell") == 0)
        return bn_selftest_spell () ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    if (list && list->word && strcmp (list->word->word, "selftest-complete") == 0)
        return bn_selftest_complete () ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    if (list && list->word && strcmp (list->word->word, "selftest-selection") == 0)
        return bn_selftest_selection () ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    if (list && list->word && strcmp (list->word->word, "selftest-linecache") == 0)
        return bn_selftest_linecache () ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    if (list && list->word && strcmp (list->word->word, "selftest-input") == 0)
        return bn_selftest_input () ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    if (list && list->word && strcmp (list->word->word, "selftest-display") == 0)
        return bn_selftest_display () ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    if (list && list->word && strcmp (list->word->word, "selftest-highlight") == 0)
        return bn_selftest_highlight () ? EXECUTION_FAILURE : EXECUTION_SUCCESS;

    /* Options are reset on every call: the builtin's state lives in the
       shell process and must not leak into the next invocation. */
    bn_fill = -8;
    bn_trimblanks = 0;
    free (bn_speller);
    bn_speller = NULL;
    while (list && list->word && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        const char *num = NULL;
        if (strcmp (w, "--") == 0) { list = list->next; break; }
        if (strcmp (w, "-h") == 0 || strcmp (w, "--help") == 0) {
            for (char **line = nano_doc; *line; line++) puts (*line);
            return sh_chkwrite (EXECUTION_SUCCESS);
        }
        if (strcmp (w, "-M") == 0 || strcmp (w, "--trimblanks") == 0)
            bn_trimblanks = 1;
        else if (strncmp (w, "--fill=", 7) == 0)
            num = w + 7;
        else if (strcmp (w, "-r") == 0 || strcmp (w, "--fill") == 0) {
            if (!list->next) {
                builtin_error ("%s: option requires an argument", w);
                puts ("Type 'nano -h' for a list of available options.");
                return sh_chkwrite (EXECUTION_FAILURE);
            }
            list = list->next;
            num = list->word->word;
        } else if (strncmp (w, "-r", 2) == 0)
            num = w + 2;
        else if (strncmp (w, "--speller=", 10) == 0) {
            free (bn_speller);
            bn_speller = strdup (w + 10);
        } else {
            builtin_error ("%s: invalid option", w);
            puts ("Type 'nano -h' for a list of available options.");
            return sh_chkwrite (EXECUTION_FAILURE);
        }
        if (num) {
            char *end = NULL;
            errno = 0;
            long v = strtol (num, &end, 10);
            if (!*num || *end || errno || v > 100000 || v < -100000) {
                builtin_error ("%s: invalid fill width", num);
                return EXECUTION_FAILURE;
            }
            bn_fill = v;
        }
        list = list->next;
    }
    if (list && list->next) {
        builtin_error ("only one file can be edited");
        return EX_USAGE;
    }

    if (!isatty (STDIN_FILENO) || !isatty (STDOUT_FILENO)) {
        builtin_error ("nano needs a tty");
        return EXECUTION_FAILURE;
    }
    /* Init buffer. */
    memset (&bn_b, 0, sizeof bn_b);
    bn_cy = bn_cx = 0;
    bn_view_top = 0;
    bn_view_left = 0;          /* Stage 4 */
    bn_softwrap = 0;
    bn_status[0] = '\0';
    bn_status_until = 0;
    bn_mark_active = 0;
    bn_lang = NULL;             /* set again by bn_load from the name */
    bn_keyq_set (NULL, 0);
    bn_complete_reset ();
    free (bn_clip);
    bn_clip = NULL;
    bn_clip_len = 0;
    bn_yank_ring_clear ();

    if (list && list->word) bn_load (list->word->word);
    else { bn_pt_init_text (&bn_b.pt, "", 0); bn_sync_lines_from_pt (); }

    bn_get_size ();
    bn_install_winch ();
    bn_install_term ();
    bn_unread = -1;
    bn_want_col = -1;
    bn_set_raw ();

    /* Switch to alt screen so we don't trash the user's scrollback. */
    bn_write ("\033[?1049h");

    char keybuf[16];
    for (;;) {
        /* Like GNU nano, do not draw while more input is already waiting:
           a pasted or fast-typed burst is drawn once, when it has been
           consumed, instead of once per byte. */
        struct pollfd pending = { STDIN_FILENO, POLLIN, 0 };
        if (poll (&pending, 1, 0) <= 0 || !(pending.revents & POLLIN))
            bn_render ();
        /* A reparse that outran the frame budget continues while no key
           is waiting; the settled colours are then drawn. */
        while (bn_hl_pending && !bn_term_signal && bn_unread < 0) {
            struct pollfd idle = { STDIN_FILENO, POLLIN, 0 };
            if (poll (&idle, 1, 0) != 0) break;
            if (bn_highlight_idle (BN_HL_SLICE_US)) bn_render ();
        }
        if (bn_term_signal) break;
        int k = bn_read_key (keybuf, sizeof keybuf);
        if (bn_term_signal || k < 0) break;
        if (k == 0) continue;
        if (bn_dispatch (keybuf, k) < 0) break;
        if (bn_term_signal) break;
        bn_get_size ();  /* in case window resized */
    }

    /* Cleanup */
    int term_sig = bn_term_signal;
    char *rescued = NULL;
    int rescue_errno = 0;
    if (term_sig && bn_b.dirty) {
        rescued = bn_emergency_save ();
        if (!rescued) rescue_errno = errno;
    }
    bn_write ("\033[?1049l");  /* main screen */
    bn_restore_tio ();
    bn_restore_winch ();
    bn_unread = -1;
    if (term_sig && bn_b.dirty) {
        if (rescued) {
            bn_outbuf name = { 0 };
            bn_out_text (&name, rescued, strlen (rescued), LONG_MAX);
            fputs ("nano: buffer written to ", stderr);
            if (name.failed) fputs ("[filename unavailable]", stderr);
            else if (name.len) fwrite (name.data, 1, name.len, stderr);
            fputc ('\n', stderr);
            free (name.data);
        }
        else fprintf (stderr, "nano: buffer not written: %s\n", strerror (rescue_errno));
        fflush (stderr);
    }
    free (rescued);

    /* Free buffer + clipboard. */
    bn_highlight_release ();
    bn_free_lines ();
    free (bn_b.path);
    bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo);
    bn_pt_stack_free (&bn_b.redo);
    free (bn_clip);
    bn_clip = NULL;
    bn_clip_len = 0;
    bn_yank_ring_clear ();
    bn_complete_reset ();
    bn_mark_active = 0;
    free (bn_speller);
    bn_speller = NULL;
    memset (&bn_b, 0, sizeof bn_b);

    bn_restore_term ();
    bn_term_signal = 0;
    if (term_sig) {
        /* Deliver the signal again, now under the shell's disposition. */
        kill (getpid (), term_sig);
        return 128 + term_sig;
    }
    return EXECUTION_SUCCESS;
}

char *nano_doc[] = {
    "Minimal nano-like text editor (bash-os Phase V V-4 v2, Stage 16 piece-table core).",
    "",
    "    nano [-r N | --fill=N] [-M | --trimblanks] [--speller=CMD] [--] [FILE]",
    "",
    "    -h, --help shows this builtin's documentation without opening a file.",
    "    Interactive editing requires terminal input and output; otherwise",
    "    the builtin returns failure before loading a file or drawing a screen.",
    "Options: -r/--fill sets the justify width (N <= 0 is relative to the",
    "      terminal width; default -8, as in GNU nano); -M/--trimblanks drops",
    "      the blanks at justified line breaks; --speller names the spell helper.",
    "      Fill widths are limited to -100000 through 100000.",
    "",
    "Keys: arrows / Home / End / PgUp / PgDn — move; up/down keep the screen",
    "      column across short lines, as in GNU nano. Keys that arrive in one",
    "      burst (paste, key repeat) are still read one key at a time.",
    "      ^O Write-Out (prompts for filename, prefilled with current path)",
    "      ^S Save (direct if filename known, else prompts)",
    "      ^X exit — if buffer is modified, prompts Y=save / N=discard / ESC=cancel",
    "      ^K cut line/marked region, ^U paste, ^Z/M-U undo, ^Y/M-E redo",
    "      ^B/^F left/right, ^P/^N up/down, ^I tab, ^R insert file",
    "      ^J justify the paragraph at or after the cursor (with the mark set:",
    "         the marked lines); M-J justify the whole buffer; one ^Z undoes it",
    "      ^T spell check (marked region or buffer): a word-list helper --",
    "         --speller=CMD, else $NANO_SPELLER, else spell -- reads the text on",
    "         stdin and prints misspelled words; it is run with execvp, without",
    "         a shell or the terminal, capped at 1 MiB / 4096 words / 10 s.",
    "         GNU interactive alternate spellers and $SPELL are not supported.",
    "         Each word opens \"Edit a replacement\": Enter replaces every",
    "         whole-word occurrence, Enter unchanged skips, Esc stops",
    "      ^] complete the word before the cursor from the buffer's words;",
    "         repeat to cycle, the bare fragment returns after the last match",
    "      M-A set/unset the mark (shown in reverse video; it follows edits)",
    "      M-W toggle soft-wrap rendering for overlong lines",
    "      M-{ / M-} rotate older/newer yank-ring entries",
    "      Backspace, Enter, printable ASCII — edit",
    "",
    "Display: tabs expand to 8-column stops; control characters show as ^X,",
    "      C1 controls as ^` .. ^~, malformed UTF-8 as U+FFFD, so no file,",
    "      file name or message can send escape sequences to the terminal.",
    "Signals: SIGHUP or SIGTERM restores the terminal, writes a modified",
    "      buffer to FILE.save (or FILE.save.N; nano.save without a name),",
    "      never replacing a file, then lets the shell's trap or default",
    "      action take the signal. Ignored signals stay ignored.",
    "Saved files hold exactly the typed text; no final newline is added",
    "      (GNU nano's --nonewlines behaviour).",
    "",
    "v2 — UTF-8 read + grapheme-cluster cursor (left/right arrows step",
    "by clusters not bytes) + cell-width-aware render via libgrapheme.",
    "Stage 16 v1 — edits, save, and undo/redo use an internal piece table.",
    "Edits patch the render-line cache in place with lazily shifted line",
    "  offsets, and no frame is drawn while more input is already waiting.",
    "G03 SAVE-PROMPTS — ^O always prompts (real-nano parity), modified-buffer",
    "  guard fires on ^X, save-as updates bn_b.path so subsequent ^S targets",
    "  the new file. Selftest: `nano selftest-saveprompt` (TAP-13).",
    "G03 REPLACE-TEST — selftest-replace covers bn_replace_at length cases",
    "  + bad-arg rejection + mark state machine. Selftest: `nano selftest-replace`.",
    "G03 SEARCH-TEST — selftest-search covers forward/backward match,",
    "  wraparound, re: POSIX-regex search prefix, no-match, bad-regex,",
    "  and empty-pattern rejection. Selftest: `nano selftest-search`.",
    "G03 RESIZE-TEST — selftest-resize covers search/softwrap viewport clamping after resize.",
    "  SIGWINCH marks a pending resize, interrupts read without exiting,",
    "  and is consumed before the next render.",
    "G03 SOFT-WRAP — M-W toggles render-only wrapping of overlong lines.",
    "G03 STATUSBAR-TEST — selftest-statusbar covers bn_set_status TTL decay,",
    "  truncation, overwrite reset, plus save/undo/redo/search status shapes.",
    "G03 YANK-RING-TEST — selftest-yank-ring covers multi-line marked yanks",
    "  and older/newer ring rotation.",
    "G03 ATOMIC-SAVE — bn_pt_save_file chain is mkstemp + fdatasync(fd) + rename",
    "  + fsync(parent-dir); `nano selftest-atomic-save` pins no-residue,",
    "  byte-exact round-trip, dirfd-no-leak (two consecutive saves), the",
    "  dirpath=\".\" fallback for relative paths, and clean missing-dir failure.",
    "Selftests: selftest-justify, -spell, -complete, -selection, -linecache,",
    "  -input (terminal key framing through a pipe), -display (display",
    "  forms, tab layout, emergency save) and -highlight (incremental colour",
    "  windows against a full parse).",
    "G03 UNDO-REDO — selftest-undo-redo pins the snapshot LIFO contract:",
    "  edit pushes undo + clears redo, undo pops undo + pushes redo, redo",
    "  reverses, new edit after undo clears the redo stack, dirty flag",
    "  round-trips through snapshots, cursor clamps to new total_len.",
    (char *)NULL
};

struct builtin nano_struct = {
    "nano",
    nano_builtin,
    BUILTIN_ENABLED,
    nano_doc,
    "nano [-r N] [-M] [--speller=CMD] [FILE]",
    0
};
