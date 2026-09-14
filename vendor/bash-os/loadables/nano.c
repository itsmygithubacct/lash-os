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
 *   ^Z      Undo
 *   ^Y/M-E  Redo
 *   M-W     Toggle soft-wrap rendering
 *   M-{ / M-} Rotate older/newer yank-ring entries
 *   ←→↑↓    Cursor movement
 *   Home/End — start / end of line
 *   PgUp/Dn  — viewport navigation
 *   Backspace — delete char before cursor (joins lines if at col 0)
 *   Enter   — split line at cursor
 *   printable byte — insert at cursor
 *
 * Usage:  nano [FILE]
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
#include <fcntl.h>
#include <dirent.h>
#include <regex.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "loadables.h"

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

/* Stage 2 — search (^W). Pattern persists across invocations so the next
   ^W pre-fills with the last query (matches GNU nano). */
static char bn_search_pat[128] = "";

/* Stage 44.D — mark + selection state. Set by Esc-A (M-A); ^K
   cuts from mark to cursor when active, M-^ copies without cut. Marked
   regions are byte spans and may cross line boundaries. */
static int  bn_mark_active = 0;
static long bn_mark_cy = 0, bn_mark_cx = 0;

/* Stage 7.E — tree-sitter highlight overlay. Detected from filename
   extension on bn_load; NULL means "no highlighting". The render path
   uses a cached per-byte SGR-code map keyed by bn_text_rev, mirroring
   GNU nano's approach of doing expensive color work only when text
   changes rather than on every cursor-only repaint. */
static const char *bn_lang = NULL;
static unsigned long bn_text_rev = 1;

typedef struct {
    const char *lang;
    unsigned long rev;
    const char **sgr_at;
    long *line_off;
    size_t total_bytes;
} bn_highlight_cache;

static bn_highlight_cache bn_hl_cache;

/* Forward decl — defined in ts.c, both end up in libbuiltins.a
   so cross-file calls resolve at link time. */
extern int bashts_compute_sgr_map (const char *lang, const char *src,
                                   size_t srclen, const char **sgr_at);

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

static void
bn_highlight_cache_clear (void)
{
    free (bn_hl_cache.sgr_at);
    free (bn_hl_cache.line_off);
    memset (&bn_hl_cache, 0, sizeof bn_hl_cache);
}

static int
bn_highlight_cache_ensure (void)
{
    if (!bn_lang) {
        bn_highlight_cache_clear ();
        return 0;
    }
    if (bn_hl_cache.sgr_at && bn_hl_cache.line_off &&
        bn_hl_cache.lang == bn_lang && bn_hl_cache.rev == bn_text_rev)
        return 0;

    bn_highlight_cache_clear ();
    bn_hl_cache.lang = bn_lang;
    bn_hl_cache.rev = bn_text_rev;

    long off = 0;
    bn_hl_cache.line_off = calloc (bn_b.n_lines + 1, sizeof *bn_hl_cache.line_off);
    if (!bn_hl_cache.line_off) return -1;
    for (size_t i = 0; i < bn_b.n_lines; i++) {
        bn_hl_cache.line_off[i] = off;
        off += (long) bn_b.lines[i].len + 1;  /* +1 for synthetic newline */
    }
    bn_hl_cache.line_off[bn_b.n_lines] = off;
    bn_hl_cache.total_bytes = (size_t) off;

    char *src = malloc (bn_hl_cache.total_bytes + 1);
    if (!src) {
        bn_highlight_cache_clear ();
        return -1;
    }
    size_t k = 0;
    for (size_t i = 0; i < bn_b.n_lines; i++) {
        if (bn_b.lines[i].len)
            memcpy (src + k, bn_b.lines[i].data, bn_b.lines[i].len);
        k += bn_b.lines[i].len;
        src[k++] = '\n';
    }
    src[k] = '\0';

    bn_hl_cache.sgr_at = calloc (bn_hl_cache.total_bytes + 1, sizeof *bn_hl_cache.sgr_at);
    if (!bn_hl_cache.sgr_at) {
        free (src);
        bn_highlight_cache_clear ();
        return -1;
    }
    /* Best-effort: a parse failure leaves all entries NULL -> no color. */
    bashts_compute_sgr_map (bn_lang, src, bn_hl_cache.total_bytes, bn_hl_cache.sgr_at);
    free (src);
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
    size_t c = 0;
    for (size_t i = 0; i < n; i++)
        if (s[i] == '\n') c++;
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

    size_t si, so, ei, eo;
    if (bn_pt_find_piece (b, start, &si, &so) < 0) return -1;
    if (bn_pt_find_piece (b, end, &ei, &eo) < 0) return -1;

    bn_pt_piece newp[3];
    size_t nn = 0;
    if (si < b->n_pieces && so > 0) {
        newp[nn] = b->pieces[si];
        newp[nn].length = so;
        newp[nn].line_count = bn_pt_count_nl (bn_pt_piece_data (b, &newp[nn]),
                                              newp[nn].length);
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
        newp[nn] = b->pieces[ei];
        newp[nn].offset += eo;
        newp[nn].length -= eo;
        newp[nn].line_count = bn_pt_count_nl (bn_pt_piece_data (b, &newp[nn]),
                                              newp[nn].length);
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

static int
bn_sync_lines_from_pt (void)
{
    bn_highlight_cache_clear ();
    bn_text_rev++;
    size_t flat_len = 0;
    char *flat = bn_pt_flatten (&bn_b.pt, &flat_len);
    if (!flat) return -1;

    bn_free_lines ();
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
        pos = bn_b.lines[line].abs;
        pos += (size_t) col;
    }
    if (pos > bn_b.pt.total_len) pos = bn_b.pt.total_len;
    return pos;
}

static void
bn_set_cursor_abs (size_t pos)
{
    if (pos > bn_b.pt.total_len) pos = bn_b.pt.total_len;
    size_t cur = 0;
    for (size_t i = 0; i < bn_b.n_lines; i++) {
        size_t end = cur + bn_b.lines[i].len;
        if (pos <= end || i + 1 == bn_b.n_lines) {
            bn_cy = (long) i;
            bn_cx = (long) (pos < cur ? 0 : pos - cur);
            bn_clamp_cx ();
            return;
        }
        cur = end + 1;
    }
    bn_cy = bn_cx = 0;
}

static int
bn_piece_replace (size_t start, size_t end, const char *ins, size_t ins_len,
                  size_t cursor_after)
{
    if (bn_pt_snapshot_push (&bn_b.undo, &bn_b.pt) < 0) return -1;
    bn_pt_stack_free (&bn_b.redo);
    if (bn_pt_replace_span_raw (&bn_b.pt, start, end, ins, ins_len) < 0) {
        (void) bn_pt_snapshot_pop (&bn_b.undo, &bn_b.pt);
        return -1;
    }
    if (bn_sync_lines_from_pt () < 0) return -1;
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
    bn_b.dirty = 0;
    bn_b.pt.dirty = 0;
    bn_sync_lines_from_pt ();
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
                      const char **sgr_at, long *line_off,
                      size_t total_bytes)
{
    const char *cur_sgr = NULL;
    int cells = 0;
    int col_acc = 0;        /* screen column from line start */
    size_t pos = 0;
    while (pos < L->len) {
        size_t adv = grapheme_next_character_break_utf8 (
            L->data + pos, L->len - pos);
        if (adv == 0) adv = 1;
        uint_least32_t cp = 0xFFFD;
        grapheme_decode_utf8 (L->data + pos, adv, &cp);
        int w = bgr_cell_width (cp);
        if (col_acc + w <= start_col) {
            col_acc += w;
            pos += adv;
            continue;
        }
        if (cells + w > viewport_cols) break;
        /* Stage 7.E — SGR transition for this cluster's first byte, if
           highlighting is on. */
        if (sgr_at && line_off) {
            long gb = line_off[lineno] + (long) pos;
            const char *want = (gb >= 0 && (size_t) gb < total_bytes)
                               ? sgr_at[gb] : NULL;
            if (want != cur_sgr) {
                if (cur_sgr) bn_out_cstr (out, "\033[0m");
                if (want) bn_out_fmt (out, "\033[%sm", want);
                cur_sgr = want;
            }
        }
        bn_out_append (out, L->data + pos, adv);
        cells += w;
        col_acc += w;
        pos += adv;
    }
    if (cur_sgr) bn_out_cstr (out, "\033[0m");
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

    /* Top status line */
    bn_out_fmt (&out,
                "\033[7m nano  %s%s  L %ld/%zu C %ld \033[K\033[m\r\n",
                bn_b.path ? bn_b.path : "(no file)",
                bn_b.dirty ? " [Modified]" : "",
                bn_cy + 1, bn_b.n_lines, bn_cx + 1);

    const char **sgr_at = NULL;
    size_t      total_bytes = 0;
    long       *line_off = NULL;       /* global byte offset of each line */
    if (bn_highlight_cache_ensure () == 0) {
        sgr_at = bn_hl_cache.sgr_at;
        line_off = bn_hl_cache.line_off;
        total_bytes = bn_hl_cache.total_bytes;
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
                bn_render_line_chunk (&out, L, lineno, chunk * viewport_cols,
                                      viewport_cols, sgr_at, line_off,
                                      total_bytes);
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
            if (lineno < (long) bn_b.n_lines)
                bn_render_line_chunk (&out, &bn_b.lines[lineno], lineno,
                                      bn_view_left, viewport_cols,
                                      sgr_at, line_off, total_bytes);
            bn_out_cstr (&out, "\r\n");
        }
    }
    /* Hint line */
    bn_out_fmt (&out,
                "\033[7m %s \033[K\033[m",
                bn_status[0] ? bn_status :
                "^O Save  ^X Exit  ^K Cut  ^U Paste  ^Z Undo  ^Y/M-E Redo  ^G Help");

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
        uint_least32_t cp = 0xFFFD;
        grapheme_decode_utf8 (s + pos, adv, &cp);
        col += bgr_cell_width (cp);
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
    if (bn_pt_snapshot_push (&bn_b.redo, &bn_b.pt) < 0) return;
    if (bn_pt_snapshot_pop (&bn_b.undo, &bn_b.pt) < 0) return;
    bn_sync_lines_from_pt ();
    bn_set_cursor_abs (pos > bn_b.pt.total_len ? bn_b.pt.total_len : pos);
    bn_set_status ("Undid change");
}

static void
bn_redo (void)
{
    size_t pos = bn_abs_from_lc (bn_cy, bn_cx);
    if (bn_b.redo.n == 0) { bn_set_status ("Nothing to redo"); return; }
    if (bn_pt_snapshot_push (&bn_b.undo, &bn_b.pt) < 0) return;
    if (bn_pt_snapshot_pop (&bn_b.redo, &bn_b.pt) < 0) return;
    bn_sync_lines_from_pt ();
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
        if (klen <= 0) continue;

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
            if (dlen > 0) dest[--dlen] = '\0';
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

static int
bn_read_key (char *buf, size_t bufsz)
{
    /* Read one key. ESC sequences: read up to 6 bytes. UTF-8 multi-byte
       sequences (high bit set, not ESC): read continuation bytes per
       leading-bits length. */
    ssize_t n = read (STDIN_FILENO, buf, 1);
    if (n < 0 && errno == EINTR)
        return 0;
    if (n <= 0)
        return -1;
    if (buf[0] == 0x1b) {
        /* Try to read the rest of an escape sequence (non-blocking). */
        struct termios old, t;
        tcgetattr (STDIN_FILENO, &old);
        t = old;
        t.c_cc[VMIN] = 0; t.c_cc[VTIME] = 1;  /* 100 ms */
        tcsetattr (STDIN_FILENO, TCSANOW, &t);
        size_t total = 1;
        while (total < bufsz - 1) {
            ssize_t r = read (STDIN_FILENO, buf + total, 1);
            if (r < 0 && errno == EINTR)
                continue;
            if (r <= 0) break;
            total++;
        }
        tcsetattr (STDIN_FILENO, TCSANOW, &old);
        return (int) total;
    }
    /* v2 — multi-byte UTF-8: accumulate continuation bytes. */
    unsigned char b0 = (unsigned char) buf[0];
    if (b0 >= 0x80) {
        int expect = 1;
        if      ((b0 & 0xE0) == 0xC0) expect = 2;
        else if ((b0 & 0xF0) == 0xE0) expect = 3;
        else if ((b0 & 0xF8) == 0xF0) expect = 4;
        else return 1;   /* invalid lead — treat as single byte */
        size_t total = 1;
        while ((int) total < expect && total < bufsz) {
            ssize_t r = read (STDIN_FILENO, buf + total, 1);
            if (r < 0 && errno == EINTR)
                continue;
            if (r <= 0) break;
            if (((unsigned char) buf[total] & 0xC0) != 0x80) break;
            total++;
        }
        return (int) total;
    }
    return 1;
}

static int
bn_dispatch (const char *k, int klen)
{
    /* ESC sequence first (3+ bytes starting ESC [). */
    if (klen >= 3 && k[0] == 0x1b && k[1] == '[') {
        char c = k[2];
        switch (c) {
        case 'A':  /* up */    if (bn_cy > 0) { bn_cy--; bn_clamp_cx (); } break;
        case 'B':  /* down */  if ((size_t) bn_cy + 1 < bn_b.n_lines) { bn_cy++; bn_clamp_cx (); } break;
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
        case '3':  /* Delete: ESC [ 3 ~ */
            if (klen >= 4 && k[3] == '~') bn_delete_forward ();
            break;
        case '5':  /* PgUp */  bn_cy -= (bn_rows - 2); if (bn_cy < 0) bn_cy = 0; bn_clamp_cx (); break;
        case '6':  /* PgDn */  bn_cy += (bn_rows - 2);
            if ((size_t) bn_cy >= bn_b.n_lines) bn_cy = (long) bn_b.n_lines - 1;
            bn_clamp_cx (); break;
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
            if (bn_cy > 0) { bn_cy--; bn_clamp_cx (); }
            return 0;
        case 0x0e:  /* ^N — GNU nano legacy Down */
            if ((size_t) bn_cy + 1 < bn_b.n_lines) { bn_cy++; bn_clamp_cx (); }
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
        case 0x07:  /* ^G */ bn_set_status ("^O/^S Save  ^X Exit  ^K Cut  ^U Paste  ^D Del  ^W Search  M-W Wrap"); return 0;
        case 0x0a:  /* ^J — justify deferred in v1 */
            bn_set_status ("justify not implemented");
            return 0;
        case 0x14:  /* ^T — spell deferred in v1 */
            bn_set_status ("spell not implemented");
            return 0;
        case 0x1d:  /* ^] — word completion deferred in v1 */
            bn_set_status ("completion not implemented");
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
    long *first_offsets = bn_hl_cache.line_off;
    unsigned long first_rev = bn_hl_cache.rev;
    bn_cx = 1;
    bn_render ();
    if (saved_stdout >= 0) { dup2 (saved_stdout, STDOUT_FILENO); close (saved_stdout); }
    asserts++;
    if (first_sgr && first_offsets && bn_hl_cache.sgr_at == first_sgr &&
        bn_hl_cache.line_off == first_offsets && bn_hl_cache.rev == first_rev)
        printf ("ok %d - syntax highlight cache survives cursor-only render\n", asserts);
    else { fails++; printf ("not ok %d - syntax highlight cache was rebuilt on cursor-only render\n", asserts); }
    bn_free_lines ();
    bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo);
    bn_pt_stack_free (&bn_b.redo);
    bn_highlight_cache_clear ();
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
    BN_KEYTEST_ASSERT ("^N dispatches to next line",
                       bn_cy == 1 && bn_cx == 2);
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
    bn_dispatch (justify_key, 1);
    BN_KEYTEST_ASSERT ("^J reports deferred justify",
                       strstr (bn_status, "justify not implemented") != NULL);
    bn_dispatch (spell_key, 1);
    BN_KEYTEST_ASSERT ("^T reports deferred spell",
                       strstr (bn_status, "spell not implemented") != NULL);
    bn_dispatch (complete_key, 1);
    BN_KEYTEST_ASSERT ("^] reports deferred completion",
                       strstr (bn_status, "completion not implemented") != NULL);

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
    free (bn_clip);
    bn_clip = NULL;
    bn_clip_len = 0;
    bn_yank_ring_clear ();

    if (list && list->word) bn_load (list->word->word);
    else { bn_pt_init_text (&bn_b.pt, "", 0); bn_sync_lines_from_pt (); }

    bn_get_size ();
    bn_install_winch ();
    bn_set_raw ();

    /* Switch to alt screen so we don't trash the user's scrollback. */
    bn_write ("\033[?1049h");

    char keybuf[16];
    for (;;) {
        bn_render ();
        int k = bn_read_key (keybuf, sizeof keybuf);
        if (k < 0) break;
        if (k == 0) continue;
        if (bn_dispatch (keybuf, k) < 0) break;
        bn_get_size ();  /* in case window resized */
    }

    /* Cleanup */
    bn_write ("\033[?1049l");  /* main screen */
    bn_restore_tio ();
    bn_restore_winch ();

    /* Free buffer + clipboard. */
    bn_highlight_cache_clear ();
    bn_free_lines ();
    free (bn_b.path);
    bn_pt_free (&bn_b.pt);
    bn_pt_stack_free (&bn_b.undo);
    bn_pt_stack_free (&bn_b.redo);
    free (bn_clip);
    bn_clip = NULL;
    bn_clip_len = 0;
    bn_yank_ring_clear ();
    memset (&bn_b, 0, sizeof bn_b);

    return EXECUTION_SUCCESS;
}

char *nano_doc[] = {
    "Minimal nano-like text editor (bash-os Phase V V-4 v2, Stage 16 piece-table core).",
    "",
    "    nano [FILE]",
    "",
    "Keys: arrows / Home / End / PgUp / PgDn — move",
    "      ^O Write-Out (prompts for filename, prefilled with current path)",
    "      ^S Save (direct if filename known, else prompts)",
    "      ^X exit — if buffer is modified, prompts Y=save / N=discard / ESC=cancel",
    "      ^K cut line/marked region, ^U paste, ^Z/M-U undo, ^Y/M-E redo",
    "      ^B/^F left/right, ^P/^N up/down, ^I tab, ^R insert file",
    "      ^J/^T/^] report deferred justify/spell/completion",
    "      M-W toggle soft-wrap rendering for overlong lines",
    "      M-{ / M-} rotate older/newer yank-ring entries",
    "      Backspace, Enter, printable ASCII — edit",
    "",
    "v2 — UTF-8 read + grapheme-cluster cursor (left/right arrows step",
    "by clusters not bytes) + cell-width-aware render via libgrapheme.",
    "Stage 16 v1 — edits, save, and undo/redo use an internal piece table.",
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
    "nano [FILE]",
    0
};
