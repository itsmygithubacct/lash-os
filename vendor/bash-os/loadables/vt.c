/* SPDX-License-Identifier: MIT */
/* vt.c — VT100/xterm-style terminal emulator (Plan C-3).
 *
 * Parses bytes from a child pty into a 2D grid; supports cursor
 * movement, line wrapping, ED/EL clears, SGR colors, alternate screen,
 * scroll regions, UTF-8/grapheme cell width, diff rendering, and OSC
 * title handling.
 *
 * Sub-phases per master plan §7.3 (incremental):
 *   3a (this drop) — skeleton: new / feed / render / free
 *   3b (this drop) — ECMA-48 parser state machine
 *   3c (this drop) — print + cursor moves (CUP/CUU/CUD/CUF/CUB)
 *   3d (this drop) — erase (ED/EL)
 *   3e (landed) — SGR colors (parse/store; render -A)
 *   3f (landed) — alt screen + DEC modes
 *   3g (landed) — scroll regions
 *   3h (landed) — UTF-8 + grapheme width via libgrapheme
 *   3i (landed) — diff render
 *   3j (landed) — OSC + miscellany
 *   vttest (landed) — DECOM/DECAWM/DECALN/reverse-wrap, SCS
 *                     G0/G1 + ENQ answerback, blink/conceal/DECSCNM
 *
 * Verbs:
 *   vt new -h H [-W cols] [-H rows]    allocate grid + state
 *   vt feed H BYTES                     parse + apply bytes
 *   vt feed-fd H FD [-N MAX]            read from FD (drains 1
 *                                            chunk; non-blocking-friendly)
 *   vt render H [-A] [-F FD]            dump grid (optionally with SGR)
 *   vt cursor H                         print "ROW COL" (1-indexed)
 *   vt response H [-V VAR]              drain DA/DSR reply buffer
 *   vt size H                           print "ROWS COLS"
 *   vt free H
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
#include <stdint.h>
#include <stdarg.h>

#include "loadables.h"

/* libgrapheme (vendored under scripts/loadables/_libgrapheme/, flattened
 * by patch-bash-loadables.sh into builtins/_libgrapheme_*.{c,h}). */
#include "_libgrapheme_grapheme.h"
#include "_libgrapheme_util.h"

/* ---- grid + state ---- */

/* Cell flags */
#define BVT_CELL_FLAG_CONT           0x1   /* continuation of a wide (2-cell) char */
#define BVT_CELL_FLAG_SOFT_WRAP_NEXT 0x2   /* row continues logically on next row */

/* SGR attribute bits stored in cells. */
#define BVT_ATTR_BOLD       0x01
#define BVT_ATTR_UNDERLINE  0x02
#define BVT_ATTR_REVERSE    0x04
#define BVT_ATTR_ITALIC     0x08
#define BVT_ATTR_STRIKE     0x10
#define BVT_ATTR_FAINT      0x20
#define BVT_ATTR_FG_RGB     0x40
#define BVT_ATTR_BG_RGB     0x80
#define BVT_ATTR_BLINK      0x0100
#define BVT_ATTR_CONCEAL    0x0200

/* Stage 14: combiners moved to a per-VT side-arena. The cell carries
   a 1-based offset into that arena plus a count. offset==0 means "no
   combiners attached" — slot 0 is reserved as the sentinel. Cluster
   assembly uses BVT_CLUSTER_MAX_COMBINERS as the in-flight buffer cap
   (defensive; real ZWJ families top out around 10). */
#define BVT_CLUSTER_MAX_COMBINERS 32

/* Stage 1 — DEC private mode flags. Apps inside the pty (vim, tmux,
   nano, htop) flip these via CSI ? N h / CSI ? N l. The terminal
   emulator tracks them so per-client diff and bash-screen mouse
   forwarding can answer "is the inner app expecting mouse events?". */
#define BVT_MODE_MOUSE_X10        (1u << 0)   /* DECSET ?9 */
#define BVT_MODE_MOUSE_X11        (1u << 1)   /* DECSET ?1000 */
#define BVT_MODE_MOUSE_BTNEVENT   (1u << 2)   /* DECSET ?1002 */
#define BVT_MODE_MOUSE_ANYEVENT   (1u << 3)   /* DECSET ?1003 */
#define BVT_MODE_FOCUS_EVENTS     (1u << 4)   /* DECSET ?1004 */
#define BVT_MODE_MOUSE_UTF8       (1u << 5)   /* DECSET ?1005 */
#define BVT_MODE_MOUSE_SGR        (1u << 6)   /* DECSET ?1006 */
#define BVT_MODE_MOUSE_URXVT      (1u << 7)   /* DECSET ?1015 */
#define BVT_MODE_MOUSE_SGR_PIXEL  (1u << 8)   /* DECSET ?1016 */
#define BVT_MODE_BRACKETED_PASTE  (1u << 9)   /* DECSET ?2004 */

typedef struct {
    uint32_t cp;                  /* base codepoint of cluster */
    uint16_t fg, bg;              /* color (0-255 indexed) */
    uint16_t attrs;               /* BVT_ATTR_* bitset */
    uint8_t  flags;               /* see BVT_CELL_FLAG_* */
    uint16_t combiner_offset;     /* 1-based; 0 = no combiners */
    uint8_t  combiner_count;
    uint8_t  fg_rgb[3];
    uint8_t  bg_rgb[3];
} bvt_cell;

typedef struct {
    bvt_cell *cells;              /* logical line cells, not pre-wrapped rows */
    size_t len;
    size_t cap;
    int soft_wrap_next;           /* next evicted row appends to this line */
} bvt_scroll_line;

/* Parser state per ECMA-48 / Paul Williams' reference. */
typedef enum {
    VT_GROUND, VT_ESCAPE, VT_ESCAPE_INTERMEDIATE,
    VT_CSI_ENTRY, VT_CSI_PARAM, VT_CSI_INTERMEDIATE, VT_CSI_IGNORE,
    VT_OSC_STRING, VT_DCS_STRING, VT_SOS_STRING
} bvt_state;

typedef struct {
    int rows, cols;
    bvt_cell *grid;             /* row-major (current) */
    bvt_cell *alt_grid;          /* 3f alt screen — switched via DECSET 1049 */
    bvt_cell *prev_grid;         /* 3i — last rendered snapshot for diff */
    int alt_active;              /* 1 if alt-screen is the current display */
    int cy, cx;                 /* cursor */
    int saved_cy, saved_cx;     /* DECSC/DECRC */
    int alt_saved_cy, alt_saved_cx;  /* per-screen save */
    int cursor_visible;          /* DECSET ?25 */
    int bracketed_paste;         /* DECSET ?2004 (mirror of mode_flags bit; kept for back-compat) */
    uint32_t mode_flags;         /* Stage 1 — BVT_MODE_* bitfield */
    int scroll_top, scroll_bot;  /* DECSTBM region (inclusive) */
    bvt_state state;
    int params[16];             /* CSI param accumulator */
    int n_params;
    int param_pending;
    int csi_private;             /* '?', '>', etc. private-mode prefix */
    int csi_intermediate;        /* ECMA-48 intermediate byte, e.g. CSI SP q */
    uint16_t fg, bg;
    uint16_t attrs;
    uint8_t  fg_rgb[3];
    uint8_t  bg_rgb[3];
    int origin_mode;              /* DECSET ?6 */
    int autowrap;                 /* DECSET ?7 */
    int pending_wrap;             /* VT-style delayed autowrap */
    int reverse_video;            /* DECSET ?5 */
    int reverse_wraparound;       /* DECSET ?45 */
    int charset_g0;               /* SCS, 'B' ASCII or '0' DEC graphics */
    int charset_g1;
    int gl_active;                /* 0=G0, 1=G1 selected into GL */
    int esc_intermediate;         /* ESC intermediate byte for SCS/DECALN */
    bvt_cell last_printed;
    int have_last_printed;
    uint8_t *tab_stops;          /* per-column HTS/TBC model */
    char *response_buf;          /* DA/DSR replies pending for caller */
    size_t response_len;
    size_t response_cap;
    int cursor_style;            /* DECSCUSR, 0..6 */
    /* OSC accumulator (for window title etc.) */
    char osc_buf[512];
    size_t osc_len;
    char title[256];             /* 3j — OSC 0/2 window title */
    int osc52_mode;               /* 1=consume, 0=passthrough */
    /* 3h — UTF-8 incremental decoder. */
    unsigned char utf8_buf[4];
    int utf8_len;                /* bytes accumulated for current codepoint */
    int utf8_expect;             /* total expected bytes for current codepoint */
    /* 3h — pending grapheme cluster being assembled. */
    uint32_t cluster_base;       /* base codepoint of pending cluster */
    uint32_t cluster_combiners[BVT_CLUSTER_MAX_COMBINERS];
    int cluster_n_comb;
    uint16_t cluster_state;      /* libgrapheme is_character_break state */
    int cluster_pending;         /* 1 = cluster_base is valid, awaiting next cp */
    /* Stage 14 — combiner side-arena. Bump allocator; reclaimed on
       full-grid clear (bvt_clear_grid resets size to 0). Slot 0 is
       reserved so that cell.combiner_offset==0 unambiguously means
       "no combiners". */
    uint32_t *cluster_arena;
    size_t    cluster_arena_size;
    size_t    cluster_arena_cap;
    /* Stages 5+12 — logical-line scrollback. Rows evicted by whole-screen
       scrolls are stored as logical lines, with soft-wrapped rows joined.
       Rendering reflows against the current column count, so resize does
       not discard history. */
    bvt_scroll_line *scrollback_lines;
    int scrollback_capacity;
    int scrollback_size;
    int scrollback_head;          /* next write slot */
} bvt_t;

#define BVT_HANDLES_MAX 32
static bvt_t *bvt_handles[BVT_HANDLES_MAX] = {0};
static int bvt_cmd_osc52_mode = -1;

extern char *get_string_value (const char *);

static int bvt_response_append (bvt_t *t, const char *fmt, ...);

static int
bvt_alloc_handle (bvt_t *t)
{
    for (int i = 0; i < BVT_HANDLES_MAX; i++)
        if (!bvt_handles[i]) { bvt_handles[i] = t; return i; }
    return -1;
}

static bvt_t *
bvt_get (const char *s)
{
    char *end;
    long h = strtol (s, &end, 10);
    if (*end != '\0' || h < 0 || h >= BVT_HANDLES_MAX) return NULL;
    return bvt_handles[h];
}

static int
bvt_get_index (const char *s)
{
    char *end;
    long h = strtol (s, &end, 10);
    if (*end != '\0' || h < 0 || h >= BVT_HANDLES_MAX) return -1;
    return (int) h;
}

/* Stage 14 — combiner arena. Bump allocator. Slot 0 is the sentinel
   (offset 0 in cell == "no combiners"); the first real slot lives at
   arena[0] and is referenced by cell.combiner_offset == 1.

   bvt_arena_alloc returns the 1-based offset. Returns 0 if growth
   fails (ENOMEM); callers gracefully degrade (cell loses combiners,
   base codepoint still renders). */
static uint16_t
bvt_arena_alloc (bvt_t *t, const uint32_t *combiners, int count)
{
    if (count <= 0) return 0;
    if (count > 0xFE) count = 0xFE;          /* fits in uint8_t with headroom */
    size_t need = t->cluster_arena_size + (size_t) count;
    if (need > t->cluster_arena_cap) {
        size_t newcap = t->cluster_arena_cap ? t->cluster_arena_cap * 2 : 256;
        while (newcap < need) newcap *= 2;
        uint32_t *p = realloc (t->cluster_arena, newcap * sizeof (uint32_t));
        if (!p) return 0;
        t->cluster_arena = p;
        t->cluster_arena_cap = newcap;
    }
    uint16_t off = (uint16_t) (t->cluster_arena_size + 1);     /* 1-based */
    for (int i = 0; i < count; i++)
        t->cluster_arena[t->cluster_arena_size + (size_t) i] = combiners[i];
    t->cluster_arena_size += (size_t) count;
    return off;
}

static void
bvt_clear_cell (bvt_cell *c)
{
    /* Stage 14: the cell's arena slot is intentionally not freed here.
       Bump-only allocator: slots are never reclaimed individually, and
       even bvt_clear_grid leaves the arena intact (the inactive grid
       may still reference its slots). Per-session upper bound is one
       slot per cluster ever displayed; in practice tens to a few hundred
       uint32_t per long session. A future stage can add mark-and-sweep
       compaction if this becomes a real problem. */
    c->cp = ' '; c->fg = 7; c->bg = 0; c->attrs = 0; c->flags = 0;
    c->combiner_offset = 0;
    c->combiner_count = 0;
    memset (c->fg_rgb, 0, sizeof c->fg_rgb);
    memset (c->bg_rgb, 0, sizeof c->bg_rgb);
}

static void
bvt_reset_style (bvt_t *t)
{
    t->fg = 7;
    t->bg = 0;
    t->attrs = 0;
    memset (t->fg_rgb, 0, sizeof t->fg_rgb);
    memset (t->bg_rgb, 0, sizeof t->bg_rgb);
}

static int
bvt_clamp_byte (int v)
{
    if (v < 0) return 0;
    if (v > 255) return 255;
    return v;
}

static uint16_t
bvt_rgb_to_256 (int rr, int gg, int bb)
{
    int r6 = (bvt_clamp_byte (rr) * 6) / 256;
    int g6 = (bvt_clamp_byte (gg) * 6) / 256;
    int b6 = (bvt_clamp_byte (bb) * 6) / 256;
    return (uint16_t) (16 + 36 * r6 + 6 * g6 + b6);
}

static void
bvt_set_default_tabs (bvt_t *t)
{
    if (!t->tab_stops) return;
    memset (t->tab_stops, 0, (size_t) t->cols);
    for (int c = 8; c < t->cols; c += 8)
        t->tab_stops[c] = 1;
}

static void
bvt_next_tab (bvt_t *t)
{
    for (int c = t->cx + 1; c < t->cols; c++) {
        if (t->tab_stops && t->tab_stops[c]) {
            t->cx = c;
            return;
        }
    }
    t->cx = t->cols - 1;
}

static void
bvt_clear_grid (bvt_t *t)
{
    for (int i = 0; i < t->rows * t->cols; i++) bvt_clear_cell (&t->grid[i]);
    /* Stage 14: deliberately DO NOT reset cluster_arena_size here. We're
       clearing the ACTIVE grid only — the inactive grid (alt or main, per
       which screen is current) may still hold combiner_offset references
       into the arena. Resetting size would let new allocations overwrite
       slots referenced by the inactive grid, corrupting combiners on
       screen swap. The bump-only allocator means a long session leaks
       slots from cleared cells, but the upper bound is one slot per
       cluster ever displayed — bounded, not unbounded. A future stage
       can add a mark-and-sweep compactor if leakage becomes an issue. */
}

static bvt_cell *
bvt_cell_at (bvt_t *t, int row, int col)
{
    if (row < 0 || row >= t->rows || col < 0 || col >= t->cols) return NULL;
    return &t->grid[row * t->cols + col];
}

static void
bvt_scrollback_line_free (bvt_scroll_line *line)
{
    if (!line) return;
    free (line->cells);
    line->cells = NULL;
    line->len = line->cap = 0;
    line->soft_wrap_next = 0;
}

static int
bvt_scrollback_line_append (bvt_scroll_line *line, const bvt_cell *cells, size_t n)
{
    if (n == 0) {
        line->soft_wrap_next = 0;
        return 0;
    }
    if (line->len + n > line->cap) {
        size_t nc = line->cap ? line->cap * 2 : 80;
        while (nc < line->len + n) nc *= 2;
        bvt_cell *p = realloc (line->cells, nc * sizeof (bvt_cell));
        if (!p) return -1;
        line->cells = p;
        line->cap = nc;
    }
    memcpy (line->cells + line->len, cells, n * sizeof (bvt_cell));
    line->len += n;
    return 0;
}

static int
bvt_scrollback_enable (bvt_t *t, int lines)
{
    if (lines < 0) return -1;
    for (int i = 0; i < t->scrollback_capacity; i++)
        bvt_scrollback_line_free (&t->scrollback_lines[i]);
    free (t->scrollback_lines);
    t->scrollback_lines = NULL;
    t->scrollback_capacity = t->scrollback_size = t->scrollback_head = 0;
    if (lines == 0) return 0;
    t->scrollback_lines = calloc ((size_t) lines, sizeof (bvt_scroll_line));
    if (!t->scrollback_lines) return -1;
    t->scrollback_capacity = lines;
    return 0;
}

static int
bvt_scrollback_oldest_index (bvt_t *t)
{
    if (t->scrollback_capacity <= 0 || t->scrollback_size <= 0) return 0;
    return (t->scrollback_head - t->scrollback_size + t->scrollback_capacity)
        % t->scrollback_capacity;
}

static bvt_scroll_line *
bvt_scrollback_line_at (bvt_t *t, int n)
{
    if (n < 0 || n >= t->scrollback_size || t->scrollback_capacity <= 0) return NULL;
    int idx = (bvt_scrollback_oldest_index (t) + n) % t->scrollback_capacity;
    return &t->scrollback_lines[idx];
}

static int
bvt_scrollback_append_row (bvt_t *t, const bvt_cell *row)
{
    if (t->scrollback_capacity <= 0) return 0;
    int soft = (row[t->cols - 1].flags & BVT_CELL_FLAG_SOFT_WRAP_NEXT) != 0;
    int last = t->cols - 1;
    if (!soft) {
        while (last >= 0) {
            const bvt_cell *c = &row[last];
            if (!(c->flags & BVT_CELL_FLAG_CONT) && c->cp != ' ' && c->cp != 0)
                break;
            last--;
        }
    }
    size_t n = (last >= 0) ? (size_t) (last + 1) : 0;

    bvt_scroll_line *line = NULL;
    if (t->scrollback_size > 0) {
        bvt_scroll_line *prev = bvt_scrollback_line_at (t, t->scrollback_size - 1);
        if (prev && prev->soft_wrap_next) line = prev;
    }
    if (!line) {
        int idx = t->scrollback_head;
        if (t->scrollback_size == t->scrollback_capacity) {
            bvt_scrollback_line_free (&t->scrollback_lines[idx]);
        } else {
            t->scrollback_size++;
        }
        t->scrollback_head = (t->scrollback_head + 1) % t->scrollback_capacity;
        line = &t->scrollback_lines[idx];
    }
    if (bvt_scrollback_line_append (line, row, n) < 0) return -1;
    line->soft_wrap_next = soft;
    return 0;
}

/* ---- parser actions ---- */

static void
bvt_scroll_up (bvt_t *t)
{
    /* Scroll the active region (scroll_top..scroll_bot) up by 1. */
    int top = t->scroll_top, bot = t->scroll_bot;
    if (top < 0) top = 0;
    if (bot >= t->rows) bot = t->rows - 1;
    if (top >= bot) {
        /* Pathological — fall back to whole-screen scroll. */
        if (top == 0) bvt_scrollback_append_row (t, t->grid);
        memmove (t->grid, t->grid + t->cols,
                 (size_t) ((t->rows - 1) * t->cols) * sizeof (bvt_cell));
        for (int i = (t->rows - 1) * t->cols; i < t->rows * t->cols; i++)
            bvt_clear_cell (&t->grid[i]);
        return;
    }
    if (top == 0) bvt_scrollback_append_row (t, &t->grid[top * t->cols]);
    memmove (&t->grid[top * t->cols], &t->grid[(top + 1) * t->cols],
             (size_t) ((bot - top) * t->cols) * sizeof (bvt_cell));
    for (int col = 0; col < t->cols; col++)
        bvt_clear_cell (&t->grid[bot * t->cols + col]);
}

static void
bvt_clear_pending_wrap (bvt_t *t)
{
    t->pending_wrap = 0;
}

static void
bvt_apply_pending_wrap (bvt_t *t)
{
    if (!t->pending_wrap) return;
    if (t->autowrap) {
        /* The wrap is real now — mark the row as logically continuing on
           the next row so scrollback eviction joins the pieces.  Flagging
           here (not when pending_wrap is set) keeps rows that fill the
           last column but are then hard-terminated by CR/LF from being
           soft-joined to the following line. */
        bvt_cell *last = bvt_cell_at (t, t->cy, t->cols - 1);
        if (last) last->flags |= BVT_CELL_FLAG_SOFT_WRAP_NEXT;
        t->cx = 0;
        t->cy++;
        if (t->cy > t->scroll_bot) {
            bvt_scroll_up (t);
            t->cy = t->scroll_bot;
        }
    }
    t->pending_wrap = 0;
}

static uint32_t
bvt_dec_special_graphic (uint32_t cp)
{
    switch (cp) {
    case '`': return 0x25C6; /* black diamond */
    case 'a': return 0x2592; /* checkerboard */
    case 'f': return 0x00B0; /* degree */
    case 'g': return 0x00B1; /* plus/minus */
    case 'j': return 0x2518; /* lower-right corner */
    case 'k': return 0x2510; /* upper-right corner */
    case 'l': return 0x250C; /* upper-left corner */
    case 'm': return 0x2514; /* lower-left corner */
    case 'n': return 0x253C; /* crossing lines */
    case 'o': return 0x23BA; /* scanline 1 */
    case 'p': return 0x23BB; /* scanline 3 */
    case 'q': return 0x2500; /* horizontal line */
    case 'r': return 0x23BC; /* scanline 7 */
    case 's': return 0x23BD; /* scanline 9 */
    case 't': return 0x251C; /* left tee */
    case 'u': return 0x2524; /* right tee */
    case 'v': return 0x2534; /* bottom tee */
    case 'w': return 0x252C; /* top tee */
    case 'x': return 0x2502; /* vertical line */
    case 'y': return 0x2264; /* less/equal */
    case 'z': return 0x2265; /* greater/equal */
    case '{': return 0x03C0; /* pi */
    case '|': return 0x2260; /* not equal */
    case '}': return 0x00A3; /* pound sterling */
    case '~': return 0x00B7; /* middle dot */
    default: return cp;
    }
}

static uint32_t
bvt_translate_gl (bvt_t *t, uint32_t cp)
{
    int charset = t->gl_active ? t->charset_g1 : t->charset_g0;
    if (charset == '0' && cp >= 0x60 && cp <= 0x7E)
        return bvt_dec_special_graphic (cp);
    return cp;
}

static void
bvt_decaln (bvt_t *t)
{
    bvt_clear_grid (t);
    for (int i = 0; i < t->rows * t->cols; i++)
        t->grid[i].cp = 'E';
    t->cy = 0;
    t->cx = 0;
    bvt_clear_pending_wrap (t);
}

/* 3h — write an assembled grapheme cluster (base codepoint + N combining
   marks, N unbounded post-Stage-14 up to BVT_CLUSTER_MAX_COMBINERS) into
   the grid, honoring cell width. Width 0 attaches the base as a combiner
   to the prior cell (degenerate path; cluster assembly normally absorbs
   marks before reaching here). Width 2 occupies two cells: the base
   lands at [cy][cx] and the next cell carries BVT_CELL_FLAG_CONT. */
static void
bvt_print_cluster (bvt_t *t, uint32_t base_cp,
                   const uint32_t *combiners, int n_comb)
{
    if (n_comb > BVT_CLUSTER_MAX_COMBINERS) n_comb = BVT_CLUSTER_MAX_COMBINERS;
    base_cp = bvt_translate_gl (t, base_cp);
    int width = bgr_cell_width (base_cp);
    if (width == 0) {
        /* Standalone combining-mark or zero-width cluster. Attach to prior
           cell if there is one; otherwise drop silently (degenerate). */
        if (t->cx > 0) {
            bvt_cell *prev = bvt_cell_at (t, t->cy, t->cx - 1);
            if (prev) {
                /* Append base_cp to prev's existing combiner slot.
                   Re-allocate a fresh slot covering old + new (bump-only
                   allocator means the old slot's bytes are leaked
                   transiently). On ENOMEM keep prev's existing combiners
                   intact rather than zeroing them. */
                uint32_t buf[BVT_CLUSTER_MAX_COMBINERS];
                int n = 0;
                for (int i = 0; i < prev->combiner_count
                                 && n < BVT_CLUSTER_MAX_COMBINERS; i++)
                    buf[n++] = t->cluster_arena[prev->combiner_offset - 1 + i];
                if (n < BVT_CLUSTER_MAX_COMBINERS) buf[n++] = base_cp;
                uint16_t off = bvt_arena_alloc (t, buf, n);
                if (off) {
                    prev->combiner_offset = off;
                    prev->combiner_count = (uint8_t) n;
                }
                /* else: arena alloc failed; prev keeps its old combiner
                   slot, the new combining mark is silently dropped. */
            }
        }
        return;
    }
    bvt_apply_pending_wrap (t);
    if (width == 2 && t->cols < 2)
        width = 1;
    /* Width 1 or 2 — wrap if needed before placement. */
    if (width == 2 && t->cx + 1 >= t->cols) {
        if (t->autowrap) {
            t->cx = 0;
            t->cy++;
            if (t->cy > t->scroll_bot) {
                bvt_scroll_up (t);
                t->cy = t->scroll_bot;
            }
        } else {
            t->cx = (t->cols > 1) ? t->cols - 2 : 0;
        }
    }
    bvt_cell *c = bvt_cell_at (t, t->cy, t->cx);
    if (!c) return;
    /* If we're overwriting the CONT half of a wide cell, also clear the base. */
    if (c->flags & BVT_CELL_FLAG_CONT && t->cx > 0) {
        bvt_cell *base = bvt_cell_at (t, t->cy, t->cx - 1);
        if (base) bvt_clear_cell (base);
    }
    if (t->cx + 1 < t->cols) {
        bvt_cell *next = bvt_cell_at (t, t->cy, t->cx + 1);
        if (next && (next->flags & BVT_CELL_FLAG_CONT))
            bvt_clear_cell (next);
    }
    c->cp = base_cp; c->fg = t->fg; c->bg = t->bg; c->attrs = t->attrs;
    memcpy (c->fg_rgb, t->fg_rgb, sizeof c->fg_rgb);
    memcpy (c->bg_rgb, t->bg_rgb, sizeof c->bg_rgb);
    c->flags = 0;
    if (n_comb > 0) {
        c->combiner_offset = bvt_arena_alloc (t, combiners, n_comb);
        c->combiner_count = (uint8_t) (c->combiner_offset ? n_comb : 0);
    } else {
        c->combiner_offset = 0;
        c->combiner_count = 0;
    }
    t->last_printed = *c;
    t->have_last_printed = 1;
    t->cx++;
    if (width == 2) {
        bvt_cell *cont = bvt_cell_at (t, t->cy, t->cx);
        if (cont) {
            bvt_clear_cell (cont);
            cont->cp = 0;          /* sentinel: no glyph here */
            cont->flags = BVT_CELL_FLAG_CONT;
            cont->fg = t->fg; cont->bg = t->bg; cont->attrs = t->attrs;
            memcpy (cont->fg_rgb, t->fg_rgb, sizeof cont->fg_rgb);
            memcpy (cont->bg_rgb, t->bg_rgb, sizeof cont->bg_rgb);
        }
        t->cx++;
    }
    if (t->cx >= t->cols) {
        if (t->autowrap) {
            /* Delayed DECAWM: do NOT mark the row soft-wrapped yet — the
               wrap may still be cancelled by CR/LF/cursor motion.  The
               SOFT_WRAP_NEXT flag is set in bvt_apply_pending_wrap when
               the wrap actually happens (xterm reflow semantics). */
            t->cx = t->cols - 1;
            t->pending_wrap = 1;
        } else {
            t->cx = t->cols - 1;
        }
    }
}

/* 3h — flush any pending cluster to the grid, then reset the assembly state. */
static void
bvt_emit_cluster (bvt_t *t)
{
    if (!t->cluster_pending) return;
    bvt_print_cluster (t, t->cluster_base, t->cluster_combiners, t->cluster_n_comb);
    t->cluster_pending = 0;
    t->cluster_n_comb = 0;
    t->cluster_state = 0;
}

/* 3h — accept a decoded codepoint, run cluster boundary detection, emit
   the previous cluster on a break. Stashes orphan combiners into the
   pending cluster's combiners[] array. */
static void
bvt_handle_cp (bvt_t *t, uint32_t cp)
{
    if (!t->cluster_pending) {
        t->cluster_base = cp;
        t->cluster_n_comb = 0;
        t->cluster_state = 0;
        t->cluster_pending = 1;
        return;
    }
    /* libgrapheme expects the previous codepoint, then the candidate. */
    uint32_t prev = (t->cluster_n_comb > 0)
        ? t->cluster_combiners[t->cluster_n_comb - 1]
        : t->cluster_base;
    if (grapheme_is_character_break (prev, cp, &t->cluster_state)) {
        /* Boundary — emit current cluster, then start a new one with cp. */
        bvt_emit_cluster (t);
        t->cluster_base = cp;
        t->cluster_n_comb = 0;
        t->cluster_state = 0;
        t->cluster_pending = 1;
    } else {
        /* No break — cp belongs to the current cluster as a combiner.
           Stage 14: assembly cap raised from 3 to BVT_CLUSTER_MAX_COMBINERS
           (32) so ZWJ families (👨‍👩‍👧‍👦 = 7 cps), skin-tone-modified
           emojis, and complex Indic conjuncts retain their full byte
           sequences. Defensive cap remains — runaway combiner streams
           are silently truncated rather than blowing the buffer. */
        if (t->cluster_n_comb < BVT_CLUSTER_MAX_COMBINERS)
            t->cluster_combiners[t->cluster_n_comb++] = cp;
    }
}

/* 3h — feed one byte of UTF-8 input. Returns the decoded codepoint when
   a complete sequence is in hand, or -1 if more bytes are still expected.
   On invalid sequences emits U+FFFD and returns it. */
static int32_t
bvt_decode_byte (bvt_t *t, unsigned char b)
{
    /* New sequence: determine expected length from leading bits. */
    if (t->utf8_len == 0) {
        if (b < 0x80) {
            return (int32_t) b;                                     /* ASCII fast path */
        } else if ((b & 0xE0) == 0xC0) { t->utf8_expect = 2; }     /* 110xxxxx */
        else if ((b & 0xF0) == 0xE0) { t->utf8_expect = 3; }       /* 1110xxxx */
        else if ((b & 0xF8) == 0xF0) { t->utf8_expect = 4; }       /* 11110xxx */
        else { return 0xFFFD; }                                     /* invalid lead */
        t->utf8_buf[0] = b;
        t->utf8_len = 1;
        return -1;
    }
    /* Continuation byte expected. */
    if ((b & 0xC0) != 0x80) {
        /* Invalid continuation — emit replacement for the partial sequence,
           reset state, then re-feed the offending byte by returning -2 (caller
           re-enters with the byte at GROUND state). For simplicity, emit
           U+FFFD and consume. */
        t->utf8_len = 0; t->utf8_expect = 0;
        return 0xFFFD;
    }
    t->utf8_buf[t->utf8_len++] = b;
    if (t->utf8_len < t->utf8_expect) return -1;
    /* Complete — decode via libgrapheme. */
    uint_least32_t cp = 0xFFFD;
    grapheme_decode_utf8 ((const char *) t->utf8_buf, (size_t) t->utf8_len, &cp);
    t->utf8_len = 0; t->utf8_expect = 0;
    return (int32_t) cp;
}

/* Legacy single-codepoint path (control chars, internal callers). */
static void
bvt_print_char (bvt_t *t, uint32_t cp)
{
    /* Standalone codepoint — bypass cluster assembly to keep print-then-
       move ordering predictable. Used by the SOS ignore stub and tests. */
    bvt_print_cluster (t, cp, NULL, 0);
}

static void
bvt_execute_c0 (bvt_t *t, unsigned char c)
{
    switch (c) {
    case 0x05: {
        const char *answer = get_string_value ("BASHVT_ANSWERBACK");
        if (answer && *answer)
            bvt_response_append (t, "%s", answer);
        break;
    }
    case 0x0E:
        t->gl_active = 1;
        bvt_clear_pending_wrap (t);
        break;
    case 0x0F:
        t->gl_active = 0;
        bvt_clear_pending_wrap (t);
        break;
    case '\b': {
        bvt_clear_pending_wrap (t);
        if (t->cx > 0) {
            t->cx--;
        } else if (t->reverse_wraparound) {
            int top = t->origin_mode ? t->scroll_top : 0;
            if (t->cy > top) {
                t->cy--;
                t->cx = t->cols - 1;
            }
        }
        break;
    }
    case '\t':
        bvt_clear_pending_wrap (t);
        bvt_next_tab (t);
        break;
    case '\r':
        t->cx = 0;
        bvt_clear_pending_wrap (t);
        break;
    case '\n':
    case '\v':
    case '\f':
        bvt_clear_pending_wrap (t);
        t->cy++;
        if (t->cy > t->scroll_bot) {
            bvt_scroll_up (t);
            t->cy = t->scroll_bot;
        }
        break;
    /* BEL ignored. */
    }
}

static int
bvt_p (bvt_t *t, int idx, int dflt)
{
    return idx < t->n_params ? (t->params[idx] ? t->params[idx] : dflt) : dflt;
}

static int
bvt_response_append (bvt_t *t, const char *fmt, ...)
{
    char tmp[64];
    va_list ap;
    va_start (ap, fmt);
    int n = vsnprintf (tmp, sizeof tmp, fmt, ap);
    va_end (ap);
    if (n < 0) return -1;
    size_t need = (size_t) n;
    if (need >= sizeof tmp) need = sizeof tmp - 1;
    if (t->response_len + need + 1 > t->response_cap) {
        size_t nc = t->response_cap ? t->response_cap * 2 : 128;
        while (nc < t->response_len + need + 1) nc *= 2;
        char *p = realloc (t->response_buf, nc);
        if (!p) return -1;
        t->response_buf = p;
        t->response_cap = nc;
    }
    memcpy (t->response_buf + t->response_len, tmp, need);
    t->response_len += need;
    t->response_buf[t->response_len] = '\0';
    return 0;
}

static void
bvt_clamp_cursor (bvt_t *t)
{
    int top = t->origin_mode ? t->scroll_top : 0;
    int bot = t->origin_mode ? t->scroll_bot : t->rows - 1;
    if (top < 0) top = 0;
    if (bot >= t->rows) bot = t->rows - 1;
    if (top > bot) { top = 0; bot = t->rows - 1; }
    if (t->cy < top) t->cy = top;
    if (t->cy > bot) t->cy = bot;
    if (t->cx < 0) t->cx = 0;
    if (t->cx >= t->cols) t->cx = t->cols - 1;
    /* 3h — if landing on a wide-char continuation cell, snap to the base. */
    if (t->cx > 0) {
        bvt_cell *cur = &t->grid[t->cy * t->cols + t->cx];
        if (cur->flags & BVT_CELL_FLAG_CONT) t->cx--;
    }
}

static void
bvt_row_clear_range (bvt_t *t, int row, int start, int end)
{
    if (row < 0 || row >= t->rows) return;
    if (start < 0) start = 0;
    if (end > t->cols) end = t->cols;
    for (int c = start; c < end; c++)
        bvt_clear_cell (&t->grid[row * t->cols + c]);
}

static void
bvt_insert_chars (bvt_t *t, int n)
{
    if (n < 1) n = 1;
    if (n > t->cols - t->cx) n = t->cols - t->cx;
    if (n <= 0) return;
    bvt_cell *row = &t->grid[t->cy * t->cols];
    memmove (&row[t->cx + n], &row[t->cx],
             (size_t) (t->cols - t->cx - n) * sizeof (bvt_cell));
    bvt_row_clear_range (t, t->cy, t->cx, t->cx + n);
}

static void
bvt_delete_chars (bvt_t *t, int n)
{
    if (n < 1) n = 1;
    if (n > t->cols - t->cx) n = t->cols - t->cx;
    if (n <= 0) return;
    bvt_cell *row = &t->grid[t->cy * t->cols];
    memmove (&row[t->cx], &row[t->cx + n],
             (size_t) (t->cols - t->cx - n) * sizeof (bvt_cell));
    bvt_row_clear_range (t, t->cy, t->cols - n, t->cols);
}

static void
bvt_erase_chars (bvt_t *t, int n)
{
    if (n < 1) n = 1;
    if (n > t->cols - t->cx) n = t->cols - t->cx;
    bvt_row_clear_range (t, t->cy, t->cx, t->cx + n);
}

static void
bvt_repeat_last_char (bvt_t *t, int n)
{
    if (n < 1) n = 1;
    bvt_cell src;
    if (t->have_last_printed)
        src = t->last_printed;
    else
        bvt_clear_cell (&src);
    src.flags &= ~(BVT_CELL_FLAG_CONT | BVT_CELL_FLAG_SOFT_WRAP_NEXT);
    int width = bgr_cell_width (src.cp ? src.cp : ' ');
    if (width < 1) width = 1;
    if (width > 2) width = 2;
    for (int k = 0; k < n; k++) {
        if (width == 2 && t->cx + 1 >= t->cols) {
            t->cx = 0; t->cy++;
            if (t->cy > t->scroll_bot) { bvt_scroll_up (t); t->cy = t->scroll_bot; }
        }
        bvt_cell *dst = bvt_cell_at (t, t->cy, t->cx);
        if (!dst) return;
        *dst = src;
        dst->flags &= ~(BVT_CELL_FLAG_CONT | BVT_CELL_FLAG_SOFT_WRAP_NEXT);
        t->cx++;
        if (width == 2) {
            bvt_cell *cont = bvt_cell_at (t, t->cy, t->cx);
            if (cont) {
                bvt_clear_cell (cont);
                cont->cp = 0;
                cont->flags = BVT_CELL_FLAG_CONT;
                cont->fg = src.fg; cont->bg = src.bg; cont->attrs = src.attrs;
                memcpy (cont->fg_rgb, src.fg_rgb, sizeof cont->fg_rgb);
                memcpy (cont->bg_rgb, src.bg_rgb, sizeof cont->bg_rgb);
            }
            t->cx++;
        }
        if (t->cx >= t->cols) {
            bvt_cell *last = bvt_cell_at (t, t->cy, t->cols - 1);
            if (last) last->flags |= BVT_CELL_FLAG_SOFT_WRAP_NEXT;
            t->cx = 0; t->cy++;
        }
        if (t->cy > t->scroll_bot) {
            bvt_scroll_up (t);
            t->cy = t->scroll_bot;
        }
    }
}

static void
bvt_csi_dispatch (bvt_t *t, unsigned char final_byte)
{
    /* Apply pending param (last one) */
    if (t->param_pending) {
        t->param_pending = 0;
    }
    int p1 = bvt_p (t, 0, 1);
    int p2 = bvt_p (t, 1, 1);
    switch (final_byte) {
    case 'A': bvt_clear_pending_wrap (t); t->cy -= p1; bvt_clamp_cursor (t); break;     /* CUU */
    case 'B': bvt_clear_pending_wrap (t); t->cy += p1; bvt_clamp_cursor (t); break;     /* CUD */
    case 'C': bvt_clear_pending_wrap (t); t->cx += p1; bvt_clamp_cursor (t); break;     /* CUF */
    case 'D': bvt_clear_pending_wrap (t); t->cx -= p1; bvt_clamp_cursor (t); break;     /* CUB */
    case 'G': bvt_clear_pending_wrap (t); t->cx = bvt_p (t, 0, 1) - 1; bvt_clamp_cursor (t); break;  /* CHA */
    case 'd':
        bvt_clear_pending_wrap (t);
        t->cy = (t->origin_mode ? t->scroll_top : 0) + bvt_p (t, 0, 1) - 1;
        bvt_clamp_cursor (t);
        break;                                                    /* VPA */
    case '`': bvt_clear_pending_wrap (t); t->cx = bvt_p (t, 0, 1) - 1; bvt_clamp_cursor (t); break;  /* HPA */
    case 'H': case 'f':                                      /* CUP / HVP */
        bvt_clear_pending_wrap (t);
        t->cy = (t->origin_mode ? t->scroll_top : 0) + p1 - 1;
        t->cx = p2 - 1;
        bvt_clamp_cursor (t);
        break;
    case '@':                                                /* ICH */
        bvt_insert_chars (t, p1);
        break;
    case 'J': {                                              /* ED */
        int mode = bvt_p (t, 0, 0);
        int from, to;
        if (mode == 0)        { from = t->cy * t->cols + t->cx; to = t->rows * t->cols; }
        else if (mode == 1)   { from = 0; to = t->cy * t->cols + t->cx + 1; }
        else if (mode == 2)   { from = 0; to = t->rows * t->cols; }
        else                  { break; }
        for (int i = from; i < to; i++) bvt_clear_cell (&t->grid[i]);
        break;
    }
    case 'K': {                                              /* EL */
        int mode = bvt_p (t, 0, 0);
        int from, to;
        if (mode == 0)        { from = t->cx; to = t->cols; }
        else if (mode == 1)   { from = 0; to = t->cx + 1; }
        else                  { from = 0; to = t->cols; }
        for (int i = from; i < to; i++) bvt_clear_cell (&t->grid[t->cy * t->cols + i]);
        break;
    }
    case 'm': {                                              /* SGR — 3e */
        if (t->n_params == 0) { bvt_reset_style (t); break; }
        for (int i = 0; i < t->n_params; i++) {
            int p = t->params[i];
            if (p == 0) bvt_reset_style (t);
            else if (p == 1) t->attrs |= BVT_ATTR_BOLD;
            else if (p == 2) t->attrs |= BVT_ATTR_FAINT;
            else if (p == 3) t->attrs |= BVT_ATTR_ITALIC;
            else if (p == 4) t->attrs |= BVT_ATTR_UNDERLINE;
            else if (p == 5) t->attrs |= BVT_ATTR_BLINK;
            else if (p == 7) t->attrs |= BVT_ATTR_REVERSE;
            else if (p == 8) t->attrs |= BVT_ATTR_CONCEAL;
            else if (p == 9) t->attrs |= BVT_ATTR_STRIKE;
            else if (p == 22) t->attrs &= ~(BVT_ATTR_BOLD | BVT_ATTR_FAINT);
            else if (p == 23) t->attrs &= ~BVT_ATTR_ITALIC;
            else if (p == 24) t->attrs &= ~BVT_ATTR_UNDERLINE;
            else if (p == 25) t->attrs &= ~BVT_ATTR_BLINK;
            else if (p == 27) t->attrs &= ~BVT_ATTR_REVERSE;
            else if (p == 28) t->attrs &= ~BVT_ATTR_CONCEAL;
            else if (p == 29) t->attrs &= ~BVT_ATTR_STRIKE;
            else if (p >= 30 && p <= 37) {
                t->fg = (uint16_t) (p - 30);
                t->attrs &= ~BVT_ATTR_FG_RGB;
            }
            else if (p == 38 && i + 1 < t->n_params) {
                /* 38;5;N (256-color) or 38;2;R;G;B (RGB) */
                int sub = t->params[i + 1];
                if (sub == 5 && i + 2 < t->n_params) {
                    t->fg = (uint16_t) (t->params[i + 2] & 0xFF);
                    t->attrs &= ~BVT_ATTR_FG_RGB;
                    i += 2;
                } else if (sub == 2 && i + 4 < t->n_params) {
                    int rr = t->params[i + 2], gg = t->params[i + 3], bb = t->params[i + 4];
                    t->fg_rgb[0] = (uint8_t) bvt_clamp_byte (rr);
                    t->fg_rgb[1] = (uint8_t) bvt_clamp_byte (gg);
                    t->fg_rgb[2] = (uint8_t) bvt_clamp_byte (bb);
                    t->fg = bvt_rgb_to_256 (rr, gg, bb);
                    t->attrs |= BVT_ATTR_FG_RGB;
                    i += 4;
                }
            }
            else if (p == 39) { t->fg = 7; t->attrs &= ~BVT_ATTR_FG_RGB; }
            else if (p >= 40 && p <= 47) {
                t->bg = (uint16_t) (p - 40);
                t->attrs &= ~BVT_ATTR_BG_RGB;
            }
            else if (p == 48 && i + 1 < t->n_params) {
                int sub = t->params[i + 1];
                if (sub == 5 && i + 2 < t->n_params) {
                    t->bg = (uint16_t) (t->params[i + 2] & 0xFF);
                    t->attrs &= ~BVT_ATTR_BG_RGB;
                    i += 2;
                } else if (sub == 2 && i + 4 < t->n_params) {
                    int rr = t->params[i + 2], gg = t->params[i + 3], bb = t->params[i + 4];
                    t->bg_rgb[0] = (uint8_t) bvt_clamp_byte (rr);
                    t->bg_rgb[1] = (uint8_t) bvt_clamp_byte (gg);
                    t->bg_rgb[2] = (uint8_t) bvt_clamp_byte (bb);
                    t->bg = bvt_rgb_to_256 (rr, gg, bb);
                    t->attrs |= BVT_ATTR_BG_RGB;
                    i += 4;
                }
            }
            else if (p == 49) { t->bg = 0; t->attrs &= ~BVT_ATTR_BG_RGB; }
            else if (p >= 90 && p <= 97) {
                t->fg = (uint16_t) (p - 90 + 8);
                t->attrs &= ~BVT_ATTR_FG_RGB;
            }
            else if (p >= 100 && p <= 107) {
                t->bg = (uint16_t) (p - 100 + 8);
                t->attrs &= ~BVT_ATTR_BG_RGB;
            }
        }
        break;
    }
    case 'P':                                                /* DCH */
        bvt_delete_chars (t, p1);
        break;
    case 'X':                                                /* ECH */
        bvt_erase_chars (t, p1);
        break;
    case 'b':                                                /* REP */
        bvt_repeat_last_char (t, p1);
        break;
    case 'g': {                                              /* TBC */
        int mode = bvt_p (t, 0, 0);
        if (mode == 0 && t->tab_stops && t->cx >= 0 && t->cx < t->cols)
            t->tab_stops[t->cx] = 0;
        else if (mode == 3 && t->tab_stops)
            memset (t->tab_stops, 0, (size_t) t->cols);
        break;
    }
    case 's':
        bvt_clear_pending_wrap (t);
        t->saved_cy = t->cy; t->saved_cx = t->cx;
        break;  /* SCO save */
    case 'u':
        bvt_clear_pending_wrap (t);
        t->cy = t->saved_cy; t->cx = t->saved_cx;
        bvt_clamp_cursor (t);
        break;  /* SCO restore */
    case 'c':                                                /* DA */
        if (t->csi_private == '>' )
            bvt_response_append (t, "\033[>0;0;0c");
        else
            bvt_response_append (t, "\033[?1;2c");
        break;
    case 'n': {                                              /* DSR */
        int mode = bvt_p (t, 0, 0);
        if (mode == 5)
            bvt_response_append (t, "\033[0n");
        else if (mode == 6)
            bvt_response_append (t, "\033[%d;%dR", t->cy + 1, t->cx + 1);
        break;
    }
    case 'q':                                                /* DECSCUSR */
        if (t->csi_intermediate == ' ') {
            int style = bvt_p (t, 0, 0);
            if (style < 0) style = 0;
            if (style > 6) style = 6;
            t->cursor_style = style;
        }
        break;
    case 'r': {  /* DECSTBM — set top/bottom margins (3g) */
        int top = bvt_p (t, 0, 1) - 1;
        int bot = bvt_p (t, 1, t->rows) - 1;
        if (top < 0) top = 0;
        if (bot >= t->rows) bot = t->rows - 1;
        if (top < bot) {
            t->scroll_top = top;
            t->scroll_bot = bot;
            t->cy = t->origin_mode ? t->scroll_top : 0;
            t->cx = 0;  /* DECSTBM also homes cursor */
            bvt_clear_pending_wrap (t);
        }
        break;
    }
    case 'L': {  /* IL — Insert N blank lines at cursor (3g) */
        int n_ins = bvt_p (t, 0, 1);
        if (t->cy < t->scroll_top || t->cy > t->scroll_bot) break;
        for (int k = 0; k < n_ins; k++) {
            for (int row = t->scroll_bot; row > t->cy; row--) {
                memcpy (&t->grid[row * t->cols],
                        &t->grid[(row - 1) * t->cols],
                        (size_t) t->cols * sizeof (bvt_cell));
            }
            for (int col = 0; col < t->cols; col++)
                bvt_clear_cell (&t->grid[t->cy * t->cols + col]);
        }
        break;
    }
    case 'M': {  /* DL — Delete N lines at cursor (3g) */
        int n_del = bvt_p (t, 0, 1);
        if (t->cy < t->scroll_top || t->cy > t->scroll_bot) break;
        for (int k = 0; k < n_del; k++) {
            for (int row = t->cy; row < t->scroll_bot; row++) {
                memcpy (&t->grid[row * t->cols],
                        &t->grid[(row + 1) * t->cols],
                        (size_t) t->cols * sizeof (bvt_cell));
            }
            for (int col = 0; col < t->cols; col++)
                bvt_clear_cell (&t->grid[t->scroll_bot * t->cols + col]);
        }
        break;
    }
    case 'S': {  /* SU — scroll up N (3g) */
        int n_su = bvt_p (t, 0, 1);
        for (int k = 0; k < n_su; k++) {
            memmove (&t->grid[t->scroll_top * t->cols],
                     &t->grid[(t->scroll_top + 1) * t->cols],
                     (size_t) ((t->scroll_bot - t->scroll_top) * t->cols) * sizeof (bvt_cell));
            for (int col = 0; col < t->cols; col++)
                bvt_clear_cell (&t->grid[t->scroll_bot * t->cols + col]);
        }
        break;
    }
    case 'T': {  /* SD — scroll down N (3g) */
        int n_sd = bvt_p (t, 0, 1);
        for (int k = 0; k < n_sd; k++) {
            for (int row = t->scroll_bot; row > t->scroll_top; row--)
                memcpy (&t->grid[row * t->cols],
                        &t->grid[(row - 1) * t->cols],
                        (size_t) t->cols * sizeof (bvt_cell));
            for (int col = 0; col < t->cols; col++)
                bvt_clear_cell (&t->grid[t->scroll_top * t->cols + col]);
        }
        break;
    }
    case 'h':  /* SM / DECSET — set mode (3f) */
    case 'l': {  /* RM / DECRST — reset mode */
        int set = (final_byte == 'h');
        if (t->csi_private == '?') {
            for (int i = 0; i < t->n_params; i++) {
                int p = t->params[i];
                if (p == 5) {
                    t->reverse_video = set;
                }
                else if (p == 6) {
                    t->origin_mode = set;
                    t->cy = set ? t->scroll_top : 0;
                    t->cx = 0;
                    bvt_clear_pending_wrap (t);
                }
                else if (p == 7) {
                    t->autowrap = set;
                    bvt_clear_pending_wrap (t);
                }
                else if (p == 25)        t->cursor_visible  = set;
                else if (p == 45) {
                    t->reverse_wraparound = set;
                }
                else if (p == 1049 && set != t->alt_active) {
                    /* Swap grid <-> alt_grid; t->grid always = active. */
                    bvt_cell *tmp = t->grid;
                    t->grid = t->alt_grid;
                    t->alt_grid = tmp;
                    if (set) {
                        /* Entering alt — save main cursor; clear alt. */
                        t->saved_cy = t->cy; t->saved_cx = t->cx;
                        for (int k = 0; k < t->rows * t->cols; k++)
                            bvt_clear_cell (&t->grid[k]);
                        t->cy = 0; t->cx = 0;
                    } else {
                        /* Leaving alt — restore main cursor. */
                        t->cy = t->saved_cy; t->cx = t->saved_cx;
                    }
                    bvt_clear_pending_wrap (t);
                    t->alt_active = set;
                }
                else if (p == 2004) {
                    t->bracketed_paste = set;
                    if (set) t->mode_flags |=  BVT_MODE_BRACKETED_PASTE;
                    else     t->mode_flags &= ~BVT_MODE_BRACKETED_PASTE;
                }
                /* Stage 1 — mouse + focus modes. */
                else {
                    uint32_t bit = 0;
                    switch (p) {
                    case 9:    bit = BVT_MODE_MOUSE_X10;       break;
                    case 1000: bit = BVT_MODE_MOUSE_X11;       break;
                    case 1002: bit = BVT_MODE_MOUSE_BTNEVENT;  break;
                    case 1003: bit = BVT_MODE_MOUSE_ANYEVENT;  break;
                    case 1004: bit = BVT_MODE_FOCUS_EVENTS;    break;
                    case 1005: bit = BVT_MODE_MOUSE_UTF8;      break;
                    case 1006: bit = BVT_MODE_MOUSE_SGR;       break;
                    case 1015: bit = BVT_MODE_MOUSE_URXVT;     break;
                    case 1016: bit = BVT_MODE_MOUSE_SGR_PIXEL; break;
                    default:   break;   /* unknown DECSET — silently ignore */
                    }
                    if (bit) {
                        if (set) t->mode_flags |=  bit;
                        else     t->mode_flags &= ~bit;
                    }
                }
            }
        }
        break;
    }
    /* Other CSIs not yet implemented are silently ignored. */
    }
    t->csi_private = 0;
    t->csi_intermediate = 0;
}

static void
bvt_esc_intermediate_dispatch (bvt_t *t, unsigned char intermediate,
                               unsigned char final_byte)
{
    if (intermediate == '#' && final_byte == '8') {
        bvt_decaln (t);
    } else if ((intermediate == '(' || intermediate == ')')
               && (final_byte == 'B' || final_byte == '0')) {
        if (intermediate == '(')
            t->charset_g0 = final_byte;
        else
            t->charset_g1 = final_byte;
    }
}

/* ---- parser state machine ---- */

static void
bvt_feed_byte (bvt_t *t, unsigned char b)
{
    switch (t->state) {
    case VT_GROUND:
        if (b == 0x1B)      { bvt_emit_cluster (t); t->state = VT_ESCAPE; }
        else if (b < 0x20)  { bvt_emit_cluster (t); bvt_execute_c0 (t, b); }
        else if (b == 0x7F) ; /* ignore DEL */
        else {
            /* 3h — UTF-8 incremental decode + cluster assembly. */
            int32_t cp = bvt_decode_byte (t, b);
            if (cp >= 0) bvt_handle_cp (t, (uint32_t) cp);
        }
        break;
    case VT_ESCAPE:
        if (b == '[') {
            t->n_params = 0;
            for (int i = 0; i < 16; i++) t->params[i] = 0;
            t->param_pending = 0;
            t->csi_private = 0;
            t->csi_intermediate = 0;
            t->state = VT_CSI_ENTRY;
        } else if (b == ']') {
            t->osc_len = 0;
            t->state = VT_OSC_STRING;
        } else if (b == 'P') {
            t->state = VT_DCS_STRING;
        } else if (b == 'X' || b == '^' || b == '_') {
            t->state = VT_SOS_STRING;
        } else if (b >= 0x20 && b <= 0x2F) {
            t->esc_intermediate = (int) b;
            t->state = VT_ESCAPE_INTERMEDIATE;
        } else if (b == '7') {
            bvt_clear_pending_wrap (t);
            t->saved_cy = t->cy; t->saved_cx = t->cx; t->state = VT_GROUND;
        } else if (b == '8') {
            bvt_clear_pending_wrap (t);
            t->cy = t->saved_cy; t->cx = t->saved_cx; t->state = VT_GROUND;
        } else if (b == 'H') {
            bvt_clear_pending_wrap (t);
            if (t->tab_stops && t->cx >= 0 && t->cx < t->cols)
                t->tab_stops[t->cx] = 1;
            t->state = VT_GROUND;
        } else if (b == 'c') {
            /* RIS — full reset */
            bvt_clear_grid (t);
            t->cy = t->cx = 0;
            bvt_reset_style (t);
            t->origin_mode = 0;
            t->autowrap = 1;
            t->pending_wrap = 0;
            t->reverse_video = 0;
            t->reverse_wraparound = 0;
            t->charset_g0 = 'B';
            t->charset_g1 = 'B';
            t->gl_active = 0;
            t->esc_intermediate = 0;
            t->have_last_printed = 0;
            bvt_set_default_tabs (t);
            t->response_len = 0;
            if (t->response_buf) t->response_buf[0] = '\0';
            t->state = VT_GROUND;
        } else {
            t->state = VT_GROUND;
        }
        break;
    case VT_ESCAPE_INTERMEDIATE:
        if (b >= 0x20 && b <= 0x2F) {
            t->esc_intermediate = (int) b;
        } else if (b >= 0x30 && b <= 0x7E) {
            bvt_esc_intermediate_dispatch (t, (unsigned char) t->esc_intermediate, b);
            t->esc_intermediate = 0;
            t->state = VT_GROUND;
        } else if (b < 0x20) {
            bvt_execute_c0 (t, b);
        } else {
            t->esc_intermediate = 0;
            t->state = VT_GROUND;
        }
        break;
    case VT_CSI_ENTRY:
    case VT_CSI_PARAM:
        if (b >= '0' && b <= '9') {
            t->params[t->n_params] = t->params[t->n_params] * 10 + (b - '0');
            t->param_pending = 1;
            t->state = VT_CSI_PARAM;
        } else if (b == ';') {
            if (t->n_params < 15) t->n_params++;
            t->params[t->n_params] = 0;
            t->param_pending = 0;
            t->state = VT_CSI_PARAM;
        } else if (b == '?' || b == '>' || b == '!' || b == '<') {
            /* Private-mode prefix; remember for the dispatch step. */
            t->csi_private = (int) b;
            t->state = VT_CSI_PARAM;
        } else if (b >= 0x20 && b <= 0x2F) {
            t->csi_intermediate = (int) b;
            t->state = VT_CSI_INTERMEDIATE;
        } else if (b >= 0x40 && b <= 0x7E) {
            /* Final byte */
            if (t->param_pending && t->n_params < 16) t->n_params++;
            bvt_csi_dispatch (t, b);
            t->state = VT_GROUND;
        } else if (b < 0x20) {
            bvt_execute_c0 (t, b);
        } else {
            t->state = VT_CSI_IGNORE;
        }
        break;
    case VT_CSI_INTERMEDIATE:
        if (b >= 0x20 && b <= 0x2F) {
            t->csi_intermediate = (int) b;
        } else if (b >= 0x40 && b <= 0x7E) {
            if (t->param_pending && t->n_params < 16) t->n_params++;
            bvt_csi_dispatch (t, b);
            t->state = VT_GROUND;
        } else if (b < 0x20) {
            bvt_execute_c0 (t, b);
        } else {
            t->state = VT_CSI_IGNORE;
        }
        break;
    case VT_CSI_IGNORE:
        if (b >= 0x40 && b <= 0x7E) t->state = VT_GROUND;
        break;
    case VT_OSC_STRING:
        /* Terminate on BEL or ST (ESC \). */
        if (b == 0x07 /* BEL */ || b == 0x1B) {
            if (t->osc_len < sizeof t->osc_buf) t->osc_buf[t->osc_len] = '\0';
            else t->osc_buf[sizeof t->osc_buf - 1] = '\0';
            /* 3j: dispatch — OSC 0/2 sets window title.
               Format: "0;TITLE" or "2;TITLE".
               OSC 52 clipboard handling is policy-controlled:
               --osc52=off passes BEL-terminated sequences through to
               stdout; --osc52=on consumes and exposes the selector and
               base64 payload via shell variables. */
            if (t->osc_len > 2 && (t->osc_buf[0] == '0' || t->osc_buf[0] == '2')
                && t->osc_buf[1] == ';') {
                size_t copy = t->osc_len - 2;
                if (copy >= sizeof t->title) copy = sizeof t->title - 1;
                memcpy (t->title, t->osc_buf + 2, copy);
                t->title[copy] = '\0';
            } else if (t->osc_len > 3 && t->osc_buf[0] == '5'
                       && t->osc_buf[1] == '2' && t->osc_buf[2] == ';') {
                if (t->osc52_mode == 0) {
                    fwrite ("\033]", 1, 2, stdout);
                    fwrite (t->osc_buf, 1, t->osc_len, stdout);
                    if (b == 0x07)
                        fputc (0x07, stdout);
                    else
                        fputc (0x1B, stdout);
                    fflush (stdout);
                } else {
                    char *target = t->osc_buf + 3;
                    char *payload = strchr (target, ';');
                    if (payload) {
                        *payload++ = '\0';
                        builtin_bind_variable ("BASHVT_CLIPBOARD_TARGET", target, 0);
                        builtin_bind_variable ("BASHVT_CLIPBOARD", payload, 0);
                    } else {
                        builtin_bind_variable ("BASHVT_CLIPBOARD_TARGET", "", 0);
                        builtin_bind_variable ("BASHVT_CLIPBOARD", target, 0);
                    }
                }
            }
            t->osc_len = 0;
            t->state = (b == 0x1B) ? VT_ESCAPE : VT_GROUND;
        } else if (t->osc_len < sizeof t->osc_buf - 1) {
            t->osc_buf[t->osc_len++] = (char) b;
        }
        break;
    case VT_DCS_STRING:
    case VT_SOS_STRING:
        /* Consume until ST (ESC \) — ignored */
        if (b == 0x1B) t->state = VT_ESCAPE;
        break;
    default:
        t->state = VT_GROUND;
        break;
    }
}

/* ---- verbs ---- */

static int
bvt_new_cmd (WORD_LIST *args)
{
    const char *hvar = NULL;
    int rows = 24, cols = 80;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (strcmp (w, "-h") == 0 && p->next) { hvar = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-W") == 0 && p->next) { cols = atoi (p->next->word->word); p = p->next; }
        else if (strcmp (w, "-H") == 0 && p->next) { rows = atoi (p->next->word->word); p = p->next; }
        else { builtin_error ("new: unexpected '%s'", w); return EX_USAGE; }
    }
    if (rows < 1 || cols < 1 || rows > 1024 || cols > 1024) {
        builtin_error ("new: bad dimensions"); return EX_USAGE;
    }
    bvt_t *t = calloc (1, sizeof (bvt_t));
    if (!t) { builtin_error ("calloc"); return EXECUTION_FAILURE; }
    t->rows = rows; t->cols = cols;
    t->grid     = calloc ((size_t) (rows * cols), sizeof (bvt_cell));
    t->alt_grid = calloc ((size_t) (rows * cols), sizeof (bvt_cell));
    t->prev_grid= calloc ((size_t) (rows * cols), sizeof (bvt_cell));
    t->tab_stops = calloc ((size_t) cols, sizeof (uint8_t));
    if (!t->grid || !t->alt_grid || !t->prev_grid || !t->tab_stops) {
        free (t->grid); free (t->alt_grid); free (t->prev_grid); free (t->tab_stops); free (t);
        builtin_error ("grid alloc"); return EXECUTION_FAILURE;
    }
    bvt_clear_grid (t);
    /* Also pre-clear alt + prev so render diff works clean from start. */
    for (int i = 0; i < rows * cols; i++) {
        bvt_clear_cell (&t->alt_grid[i]);
        bvt_clear_cell (&t->prev_grid[i]);
        /* Mark prev as 'sentinel different' so first diff emits everything. */
        t->prev_grid[i].cp = 0xFFFFFFFF;
    }
    bvt_reset_style (t);
    bvt_set_default_tabs (t);
    t->state = VT_GROUND;
    t->cursor_visible = 1;
    t->autowrap = 1;
    t->charset_g0 = 'B';
    t->charset_g1 = 'B';
    t->gl_active = 0;
    t->osc52_mode = 1;
    t->scroll_top = 0;
    t->scroll_bot = rows - 1;

    int slot = bvt_alloc_handle (t);
    if (slot < 0) {
        free (t->grid); free (t->alt_grid); free (t->prev_grid);
        free (t->cluster_arena);    /* Stage 14: arena lives on bvt_t */
        free (t->tab_stops);
        free (t->response_buf);
        free (t);
        builtin_error ("handle table full"); return EXECUTION_FAILURE;
    }
    char buf[16]; snprintf (buf, sizeof buf, "%d", slot);
    if (hvar) builtin_bind_variable ((char *) hvar, buf, 0);
    else      printf ("%s\n", buf);
    return EXECUTION_SUCCESS;
}

static bvt_t *
bvt_clone_alloc (bvt_t *src)
{
    bvt_t *t = calloc (1, sizeof (bvt_t));
    if (!t) return NULL;
    *t = *src;
    t->grid = t->alt_grid = t->prev_grid = NULL;
    t->cluster_arena = NULL;
    t->scrollback_lines = NULL;
    t->tab_stops = NULL;
    t->response_buf = NULL;
    size_t cells = (size_t) (src->rows * src->cols);
    t->grid = malloc (cells * sizeof (bvt_cell));
    t->alt_grid = malloc (cells * sizeof (bvt_cell));
    t->prev_grid = malloc (cells * sizeof (bvt_cell));
    if (!t->grid || !t->alt_grid || !t->prev_grid) goto fail;
    memcpy (t->grid, src->grid, cells * sizeof (bvt_cell));
    memcpy (t->alt_grid, src->alt_grid, cells * sizeof (bvt_cell));
    memcpy (t->prev_grid, src->grid, cells * sizeof (bvt_cell));
    if (src->cluster_arena_cap) {
        t->cluster_arena = malloc (src->cluster_arena_cap * sizeof (uint32_t));
        if (!t->cluster_arena) goto fail;
        memcpy (t->cluster_arena, src->cluster_arena,
                src->cluster_arena_size * sizeof (uint32_t));
    }
    if (src->tab_stops) {
        t->tab_stops = malloc ((size_t) src->cols);
        if (!t->tab_stops) goto fail;
        memcpy (t->tab_stops, src->tab_stops, (size_t) src->cols);
    }
    if (src->response_len > 0) {
        t->response_cap = src->response_len + 1;
        t->response_buf = malloc (t->response_cap);
        if (!t->response_buf) goto fail;
        memcpy (t->response_buf, src->response_buf, src->response_len);
        t->response_buf[src->response_len] = '\0';
    }
    if (src->scrollback_capacity > 0) {
        t->scrollback_lines = calloc ((size_t) src->scrollback_capacity,
                                      sizeof (bvt_scroll_line));
        if (!t->scrollback_lines) goto fail;
        for (int i = 0; i < src->scrollback_capacity; i++) {
            bvt_scroll_line *sl = &src->scrollback_lines[i];
            bvt_scroll_line *dl = &t->scrollback_lines[i];
            dl->soft_wrap_next = sl->soft_wrap_next;
            if (sl->len) {
                dl->cells = malloc (sl->len * sizeof (bvt_cell));
                if (!dl->cells) goto fail;
                memcpy (dl->cells, sl->cells, sl->len * sizeof (bvt_cell));
                dl->len = dl->cap = sl->len;
            }
        }
    }
    return t;
fail:
    if (t->scrollback_lines) {
        for (int i = 0; i < t->scrollback_capacity; i++)
            bvt_scrollback_line_free (&t->scrollback_lines[i]);
    }
    free (t->scrollback_lines);
    free (t->cluster_arena);
    free (t->tab_stops);
    free (t->response_buf);
    free (t->grid); free (t->alt_grid); free (t->prev_grid);
    free (t);
    return NULL;
}

static int
bvt_clone_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("clone: SRC -h DST"); return EX_USAGE; }
    bvt_t *src = bvt_get (args->word->word);
    if (!src) { builtin_error ("clone: bad source handle"); return EX_USAGE; }
    const char *hvar = NULL;
    for (WORD_LIST *p = args->next; p; p = p->next) {
        if (!strcmp (p->word->word, "-h") && p->next) {
            hvar = p->next->word->word; p = p->next;
        } else {
            builtin_error ("clone: unexpected '%s'", p->word->word);
            return EX_USAGE;
        }
    }
    bvt_emit_cluster (src);
    bvt_t *dst = bvt_clone_alloc (src);
    if (!dst) { builtin_error ("clone: alloc"); return EXECUTION_FAILURE; }
    int slot = bvt_alloc_handle (dst);
    if (slot < 0) {
        for (int i = 0; i < dst->scrollback_capacity; i++)
            bvt_scrollback_line_free (&dst->scrollback_lines[i]);
        free (dst->scrollback_lines);
        free (dst->grid); free (dst->alt_grid); free (dst->prev_grid);
        free (dst->cluster_arena); free (dst->tab_stops); free (dst->response_buf); free (dst);
        builtin_error ("handle table full"); return EXECUTION_FAILURE;
    }
    char buf[16]; snprintf (buf, sizeof buf, "%d", slot);
    if (hvar) builtin_bind_variable ((char *) hvar, buf, 0);
    else      printf ("%s\n", buf);
    return EXECUTION_SUCCESS;
}

static int
bvt_feed_cmd (WORD_LIST *args)
{
    if (!args || !args->next) { builtin_error ("feed: HANDLE BYTES"); return EX_USAGE; }
    bvt_t *t = bvt_get (args->word->word);
    if (!t) { builtin_error ("feed: bad handle"); return EX_USAGE; }
    int old_osc52_mode = t->osc52_mode;
    if (bvt_cmd_osc52_mode >= 0)
        t->osc52_mode = bvt_cmd_osc52_mode;
    const char *bytes = args->next->word->word;
    size_t n = strlen (bytes);
    for (size_t i = 0; i < n; i++) bvt_feed_byte (t, (unsigned char) bytes[i]);
    t->osc52_mode = old_osc52_mode;
    /* Stage 13: cluster state persists across feed calls so a cluster
       split across two feeds (e.g. base in one feed, combiner in the
       next) combines correctly. Callers must invoke `vt flush H`
       (or `render` / `diff`, which auto-flush) to materialize the
       pending cluster into the grid. */
    return EXECUTION_SUCCESS;
}

static int
bvt_feed_fd_cmd (WORD_LIST *args)
{
    if (!args || !args->next) { builtin_error ("feed-fd: HANDLE FD [-N MAX]"); return EX_USAGE; }
    bvt_t *t = bvt_get (args->word->word);
    if (!t) { builtin_error ("feed-fd: bad handle"); return EX_USAGE; }
    int old_osc52_mode = t->osc52_mode;
    if (bvt_cmd_osc52_mode >= 0)
        t->osc52_mode = bvt_cmd_osc52_mode;
    int fd = atoi (args->next->word->word);
    size_t cap = 4096;
    if (args->next->next) {
        WORD_LIST *p = args->next->next;
        if (strcmp (p->word->word, "-N") == 0 && p->next)
            cap = (size_t) atoi (p->next->word->word);
    }
    unsigned char *buf = malloc (cap);
    if (!buf) {
        t->osc52_mode = old_osc52_mode;
        return EXECUTION_FAILURE;
    }
    ssize_t r = read (fd, buf, cap);
    if (r < 0) {
        t->osc52_mode = old_osc52_mode;
        free (buf); builtin_error ("read: %s", strerror (errno)); return EXECUTION_FAILURE;
    }
    for (ssize_t i = 0; i < r; i++) bvt_feed_byte (t, buf[i]);
    t->osc52_mode = old_osc52_mode;
    free (buf);
    /* Stage 13: pending cluster persists across feed-fd calls; caller
       flushes via `vt flush H` or implicitly via render/diff. */
    char nb[32]; snprintf (nb, sizeof nb, "%zd", r);
    builtin_bind_variable ("BVT_LAST_BYTES", nb, 0);
    return EXECUTION_SUCCESS;
}

static int
bvt_buf_reserve (char **buf, size_t *cap, size_t off, size_t need)
{
    if (need > SIZE_MAX - off)
        return -1;
    size_t want = off + need;
    if (want <= *cap)
        return 0;
    size_t ncap = *cap ? *cap : 1024;
    while (ncap < want) {
        if (ncap > SIZE_MAX / 2) {
            ncap = want;
            break;
        }
        ncap *= 2;
    }
    char *p = realloc (*buf, ncap);
    if (!p)
        return -1;
    *buf = p;
    *cap = ncap;
    return 0;
}

static int
bvt_buf_append_mem (char **buf, size_t *cap, size_t *off, const char *s, size_t n)
{
    if (n == 0)
        return 0;
    if (bvt_buf_reserve (buf, cap, *off, n) < 0)
        return -1;
    memcpy (*buf + *off, s, n);
    *off += n;
    return 0;
}

static int
bvt_buf_append_char (char **buf, size_t *cap, size_t *off, char ch)
{
    if (bvt_buf_reserve (buf, cap, *off, 1) < 0)
        return -1;
    (*buf)[(*off)++] = ch;
    return 0;
}

static int
bvt_cell_style_is_default (const bvt_cell *cell)
{
    return cell->fg == 7 && cell->bg == 0 && cell->attrs == 0;
}

static int
bvt_cell_style_equal (const bvt_cell *a, const bvt_cell *b)
{
    if (a->fg != b->fg || a->bg != b->bg || a->attrs != b->attrs)
        return 0;
    if ((a->attrs & BVT_ATTR_FG_RGB) &&
        memcmp (a->fg_rgb, b->fg_rgb, sizeof a->fg_rgb) != 0)
        return 0;
    if ((a->attrs & BVT_ATTR_BG_RGB) &&
        memcmp (a->bg_rgb, b->bg_rgb, sizeof a->bg_rgb) != 0)
        return 0;
    return 1;
}

static int
bvt_cell_visual_equal (const bvt_cell *a, const bvt_cell *b)
{
    return a->cp == b->cp &&
        bvt_cell_style_equal (a, b) &&
        a->flags == b->flags &&
        a->combiner_offset == b->combiner_offset &&
        a->combiner_count == b->combiner_count;
}

static void
bvt_effective_cell_style (bvt_t *t, const bvt_cell *src, bvt_cell *dst)
{
    *dst = *src;
    if (!t->reverse_video)
        return;

    uint16_t fg = dst->fg;
    dst->fg = dst->bg;
    dst->bg = fg;

    uint8_t rgb[3];
    memcpy (rgb, dst->fg_rgb, sizeof rgb);
    memcpy (dst->fg_rgb, dst->bg_rgb, sizeof dst->fg_rgb);
    memcpy (dst->bg_rgb, rgb, sizeof dst->bg_rgb);

    int had_fg_rgb = (dst->attrs & BVT_ATTR_FG_RGB) != 0;
    int had_bg_rgb = (dst->attrs & BVT_ATTR_BG_RGB) != 0;
    dst->attrs &= ~(BVT_ATTR_FG_RGB | BVT_ATTR_BG_RGB);
    if (had_fg_rgb) dst->attrs |= BVT_ATTR_BG_RGB;
    if (had_bg_rgb) dst->attrs |= BVT_ATTR_FG_RGB;
}

static size_t
bvt_format_sgr (const bvt_cell *cell, char *buf, size_t len)
{
    size_t off = 0;
    int n;

    n = snprintf (buf + off, len - off, "\033[0");
    if (n < 0) return 0;
    off += (size_t) n;
    if (cell->attrs & BVT_ATTR_BOLD) {
        n = snprintf (buf + off, len - off, ";1");
        if (n < 0) return 0;
        off += (size_t) n;
    }
    if (cell->attrs & BVT_ATTR_FAINT) {
        n = snprintf (buf + off, len - off, ";2");
        if (n < 0) return 0;
        off += (size_t) n;
    }
    if (cell->attrs & BVT_ATTR_ITALIC) {
        n = snprintf (buf + off, len - off, ";3");
        if (n < 0) return 0;
        off += (size_t) n;
    }
    if (cell->attrs & BVT_ATTR_UNDERLINE) {
        n = snprintf (buf + off, len - off, ";4");
        if (n < 0) return 0;
        off += (size_t) n;
    }
    if (cell->attrs & BVT_ATTR_BLINK) {
        n = snprintf (buf + off, len - off, ";5");
        if (n < 0) return 0;
        off += (size_t) n;
    }
    if (cell->attrs & BVT_ATTR_REVERSE) {
        n = snprintf (buf + off, len - off, ";7");
        if (n < 0) return 0;
        off += (size_t) n;
    }
    if (cell->attrs & BVT_ATTR_CONCEAL) {
        n = snprintf (buf + off, len - off, ";8");
        if (n < 0) return 0;
        off += (size_t) n;
    }
    if (cell->attrs & BVT_ATTR_STRIKE) {
        n = snprintf (buf + off, len - off, ";9");
        if (n < 0) return 0;
        off += (size_t) n;
    }
    if (cell->attrs & BVT_ATTR_FG_RGB) {
        n = snprintf (buf + off, len - off, ";38;2;%u;%u;%u",
                      (unsigned) cell->fg_rgb[0],
                      (unsigned) cell->fg_rgb[1],
                      (unsigned) cell->fg_rgb[2]);
        if (n < 0) return 0;
        off += (size_t) n;
    } else if (cell->fg != 7) {
        if (cell->fg <= 7)
            n = snprintf (buf + off, len - off, ";%u", 30u + (unsigned) cell->fg);
        else if (cell->fg <= 15)
            n = snprintf (buf + off, len - off, ";%u", 90u + (unsigned) cell->fg - 8u);
        else
            n = snprintf (buf + off, len - off, ";38;5;%u", (unsigned) cell->fg);
        if (n < 0) return 0;
        off += (size_t) n;
    }
    if (cell->attrs & BVT_ATTR_BG_RGB) {
        n = snprintf (buf + off, len - off, ";48;2;%u;%u;%u",
                      (unsigned) cell->bg_rgb[0],
                      (unsigned) cell->bg_rgb[1],
                      (unsigned) cell->bg_rgb[2]);
        if (n < 0) return 0;
        off += (size_t) n;
    } else if (cell->bg != 0) {
        if (cell->bg <= 7)
            n = snprintf (buf + off, len - off, ";%u", 40u + (unsigned) cell->bg);
        else if (cell->bg <= 15)
            n = snprintf (buf + off, len - off, ";%u", 100u + (unsigned) cell->bg - 8u);
        else
            n = snprintf (buf + off, len - off, ";48;5;%u", (unsigned) cell->bg);
        if (n < 0) return 0;
        off += (size_t) n;
    }
    n = snprintf (buf + off, len - off, "m");
    if (n < 0) return 0;
    off += (size_t) n;
    return off;
}

static int
bvt_render_cell_append (bvt_t *t, bvt_cell *cell, char **out, size_t *cap, size_t *off)
{
    if (cell->flags & BVT_CELL_FLAG_CONT)
        return 0;
    if (bvt_buf_reserve (out, cap, *off, (size_t) (1 + cell->combiner_count) * 4) < 0)
        return -1;
    uint32_t cp = cell->cp ? cell->cp : ' ';
    if (cp == 0xFFFFFFFFu) cp = ' ';
    *off += grapheme_encode_utf8 (cp, *out + *off, 4);
    for (int k = 0; k < cell->combiner_count; k++) {
        uint32_t comb = t->cluster_arena[cell->combiner_offset - 1 + k];
        *off += grapheme_encode_utf8 (comb, *out + *off, 4);
    }
    return 0;
}

static int
bvt_render_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("render: HANDLE [-A] [-F FD]"); return EX_USAGE; }
    const char *handle = NULL;
    int ansi = 0;
    int fd = STDOUT_FILENO;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-A") == 0) {
            ansi = 1;
        } else if (strcmp (w, "-F") == 0) {
            if (!p->next) {
                builtin_error ("render: -F requires FD");
                return EX_USAGE;
            }
            fd = atoi (p->next->word->word);
            p = p->next;
        } else if (!handle) {
            handle = w;
        } else {
            builtin_error ("render: unexpected '%s'", w);
            return EX_USAGE;
        }
    }
    if (!handle) { builtin_error ("render: HANDLE [-A] [-F FD]"); return EX_USAGE; }
    bvt_t *t = bvt_get (handle);
    if (!t) { builtin_error ("render: bad handle"); return EX_USAGE; }
    /* Stage 13: auto-flush pending cluster so it's visible on screen.
       Without this, a partially-fed cluster would be invisible until
       the next feed completes it. */
    bvt_emit_cluster (t);
    size_t cap = 0;
    char *out = NULL;
    size_t off = 0;
    bvt_cell cur_style;
    bvt_clear_cell (&cur_style);
    for (int r = 0; r < t->rows; r++) {
        /* Find end-of-line (rightmost non-blank). Treat CONT cells as blank
           since they belong to the wide cell to their left. */
        int last = -1;
        for (int c = 0; c < t->cols; c++) {
            bvt_cell *cell = &t->grid[r * t->cols + c];
            if (cell->flags & BVT_CELL_FLAG_CONT) continue;
            if (cell->cp != ' ' && cell->cp != 0) last = c;
            else if (ansi && !bvt_cell_style_is_default (cell)) last = c;
        }
        for (int c = 0; c <= last; c++) {
            bvt_cell *cell = &t->grid[r * t->cols + c];
            if (cell->flags & BVT_CELL_FLAG_CONT) continue;       /* skip wide-char cont */
            bvt_cell effective;
            bvt_effective_cell_style (t, cell, &effective);
            if (ansi && !bvt_cell_style_equal (&cur_style, &effective)) {
                char sgr[96];
                size_t n = bvt_format_sgr (&effective, sgr, sizeof (sgr));
                if (bvt_buf_append_mem (&out, &cap, &off, sgr, n) < 0) {
                    free (out);
                    return EXECUTION_FAILURE;
                }
                cur_style.fg = effective.fg;
                cur_style.bg = effective.bg;
                cur_style.attrs = effective.attrs;
                memcpy (cur_style.fg_rgb, effective.fg_rgb, sizeof cur_style.fg_rgb);
                memcpy (cur_style.bg_rgb, effective.bg_rgb, sizeof cur_style.bg_rgb);
            }
            if (bvt_render_cell_append (t, cell, &out, &cap, &off) < 0) {
                free (out);
                return EXECUTION_FAILURE;
            }
        }
        if (ansi && !bvt_cell_style_is_default (&cur_style)) {
            if (bvt_buf_append_mem (&out, &cap, &off, "\033[0m", 4) < 0) {
                free (out);
                return EXECUTION_FAILURE;
            }
            bvt_clear_cell (&cur_style);
        }
        if (bvt_buf_append_char (&out, &cap, &off, '\n') < 0) {
            free (out);
            return EXECUTION_FAILURE;
        }
    }
    /* EINTR-tolerant + partial-write loop; mirrors the bvt_diff write
     * path at the bottom of this file. A signal arriving mid-write
     * must not truncate the rendered grid. */
    size_t wpos = 0;
    while (wpos < off) {
        ssize_t w = write (fd, out + wpos, off - wpos);
        if (w < 0) { if (errno == EINTR) continue; break; }
        wpos += (size_t) w;
    }
    free (out);
    return EXECUTION_SUCCESS;
}

static size_t
bvt_render_cell_to_buf (bvt_t *t, bvt_cell *cell, char *out, size_t off)
{
    if (cell->flags & BVT_CELL_FLAG_CONT) return off;
    uint32_t cp = cell->cp ? cell->cp : ' ';
    if (cp == 0xFFFFFFFFu) cp = ' ';
    off += grapheme_encode_utf8 (cp, out + off, 16);
    for (int k = 0; k < cell->combiner_count; k++) {
        uint32_t comb = t->cluster_arena[cell->combiner_offset - 1 + k];
        off += grapheme_encode_utf8 (comb, out + off, 16);
    }
    return off;
}

static int
bvt_scrollback_enable_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("scrollback-enable: HANDLE -L LINES"); return EX_USAGE; }
    bvt_t *t = bvt_get (args->word->word);
    if (!t) { builtin_error ("scrollback-enable: bad handle"); return EX_USAGE; }
    int lines = -1;
    for (WORD_LIST *p = args->next; p; p = p->next) {
        if (!strcmp (p->word->word, "-L") && p->next) {
            lines = atoi (p->next->word->word); p = p->next;
        } else {
            builtin_error ("scrollback-enable: unexpected '%s'", p->word->word);
            return EX_USAGE;
        }
    }
    if (lines < 0) { builtin_error ("scrollback-enable: -L LINES required"); return EX_USAGE; }
    if (bvt_scrollback_enable (t, lines) < 0) {
        builtin_error ("scrollback-enable: alloc");
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bvt_scrollback_size_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("scrollback-size: HANDLE"); return EX_USAGE; }
    bvt_t *t = bvt_get (args->word->word);
    if (!t) { builtin_error ("scrollback-size: bad handle"); return EX_USAGE; }
    printf ("%d\n", t->scrollback_size);
    return EXECUTION_SUCCESS;
}

static int
bvt_scrollback_row_cmd (WORD_LIST *args)
{
    if (!args || !args->next) { builtin_error ("scrollback-row: HANDLE N [-F FD]"); return EX_USAGE; }
    bvt_t *t = bvt_get (args->word->word);
    if (!t) { builtin_error ("scrollback-row: bad handle"); return EX_USAGE; }
    /* Match render/diff behavior: callers that inspect scrollback after a
       feed should see a complete terminal state, including a final pending
       grapheme cluster that may trigger the last soft-wrap eviction. */
    bvt_emit_cluster (t);
    int n = atoi (args->next->word->word);
    int fd = STDOUT_FILENO;
    for (WORD_LIST *p = args->next->next; p; p = p->next) {
        if (!strcmp (p->word->word, "-F") && p->next) { fd = atoi (p->next->word->word); p = p->next; }
    }
    bvt_scroll_line *line = bvt_scrollback_line_at (t, n);
    if (!line) { builtin_error ("scrollback-row: bad row"); return EX_USAGE; }
    size_t cap = line->len * 64 + 64;
    char *out = malloc (cap);
    if (!out) return EXECUTION_FAILURE;
    size_t off = (size_t) snprintf (out, cap, "%d ", n);
    for (size_t i = 0; i < line->len; i++)
        off = bvt_render_cell_to_buf (t, &line->cells[i], out, off);
    out[off++] = '\n';
    /* EINTR-tolerant + partial-write loop. */
    size_t wpos = 0;
    while (wpos < off) {
        ssize_t w = write (fd, out + wpos, off - wpos);
        if (w < 0) { if (errno == EINTR) continue; break; }
        wpos += (size_t) w;
    }
    free (out);
    return EXECUTION_SUCCESS;
}

static int
bvt_scrollback_render_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("scrollback-render: HANDLE [-F FD] [-N ROWS]"); return EX_USAGE; }
    bvt_t *t = bvt_get (args->word->word);
    if (!t) { builtin_error ("scrollback-render: bad handle"); return EX_USAGE; }
    bvt_emit_cluster (t);
    int fd = STDOUT_FILENO;
    int max_rows = t->rows;
    for (WORD_LIST *p = args->next; p; p = p->next) {
        if (!strcmp (p->word->word, "-F") && p->next) { fd = atoi (p->next->word->word); p = p->next; }
        else if (!strcmp (p->word->word, "-N") && p->next) { max_rows = atoi (p->next->word->word); p = p->next; }
        else { builtin_error ("scrollback-render: unexpected '%s'", p->word->word); return EX_USAGE; }
    }
    if (max_rows < 1) max_rows = t->rows;
    size_t cap = (size_t) (t->scrollback_size * (t->cols * 16 + 4) + 64);
    if (cap < 1024) cap = 1024;
    char *out = malloc (cap);
    if (!out) return EXECUTION_FAILURE;
    size_t rows_cap = 64;
    size_t *row_starts = malloc (rows_cap * sizeof (size_t));
    if (!row_starts) { free (out); return EXECUTION_FAILURE; }
    size_t off = 0;
    int visual_rows = 0;
    row_starts[0] = 0;
    for (int li = 0; li < t->scrollback_size; li++) {
        bvt_scroll_line *line = bvt_scrollback_line_at (t, li);
        if (!line) continue;
        int col = 0;
        for (size_t ci = 0; ci < line->len; ci++) {
            bvt_cell *cell = &line->cells[ci];
            if (cell->flags & BVT_CELL_FLAG_CONT) continue;
            int w = bgr_cell_width (cell->cp ? cell->cp : ' ');
            if (w < 1) w = 1;
            if (col > 0 && col + w > t->cols) {
                if (off + 2 >= cap) {
                    cap *= 2;
                    char *nb = realloc (out, cap);
                    if (!nb) { free (row_starts); free (out); return EXECUTION_FAILURE; }
                    out = nb;
                }
                out[off++] = '\n';
                visual_rows++;
                if ((size_t) (visual_rows + 1) >= rows_cap) {
                    rows_cap *= 2;
                    size_t *nr = realloc (row_starts, rows_cap * sizeof (size_t));
                    if (!nr) { free (row_starts); free (out); return EXECUTION_FAILURE; }
                    row_starts = nr;
                }
                row_starts[visual_rows] = off;
                col = 0;
            }
            if (off + 512 >= cap) {
                cap *= 2;
                char *nb = realloc (out, cap);
                if (!nb) { free (row_starts); free (out); return EXECUTION_FAILURE; }
                out = nb;
            }
            off = bvt_render_cell_to_buf (t, cell, out, off);
            col += w;
        }
        if (off + 2 >= cap) {
            cap *= 2;
            char *nb = realloc (out, cap);
            if (!nb) { free (row_starts); free (out); return EXECUTION_FAILURE; }
            out = nb;
        }
        out[off++] = '\n';
        visual_rows++;
        if ((size_t) (visual_rows + 1) >= rows_cap) {
            rows_cap *= 2;
            size_t *nr = realloc (row_starts, rows_cap * sizeof (size_t));
            if (!nr) { free (row_starts); free (out); return EXECUTION_FAILURE; }
            row_starts = nr;
        }
        row_starts[visual_rows] = off;
    }
    int start_row = visual_rows > max_rows ? visual_rows - max_rows : 0;
    size_t start_off = row_starts[start_row];
    /* EINTR-tolerant + partial-write loop. */
    size_t wpos = start_off;
    while (wpos < off) {
        ssize_t w = write (fd, out + wpos, off - wpos);
        if (w < 0) { if (errno == EINTR) continue; break; }
        wpos += (size_t) w;
    }
    free (row_starts);
    free (out);
    return EXECUTION_SUCCESS;
}

static int
bvt_cursor_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("cursor: HANDLE"); return EX_USAGE; }
    bvt_t *t = bvt_get (args->word->word);
    if (!t) { builtin_error ("cursor: bad handle"); return EX_USAGE; }
    /* Stage 13: auto-flush pending cluster so the reported cursor
       reflects the post-commit position, matching pre-Stage-13
       behavior for callers that don't track cluster-pending state. */
    bvt_emit_cluster (t);
    printf ("%d %d\n", t->cy + 1, t->cx + 1);
    return EXECUTION_SUCCESS;
}

static int
bvt_size_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("size: HANDLE"); return EX_USAGE; }
    bvt_t *t = bvt_get (args->word->word);
    if (!t) { builtin_error ("size: bad handle"); return EX_USAGE; }
    printf ("%d %d\n", t->rows, t->cols);
    return EXECUTION_SUCCESS;
}

/* 3j: OSC 0/2 window title.   vt title H [-V VAR] */
static int
bvt_title_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("title: HANDLE [-V VAR]"); return EX_USAGE; }
    bvt_t *t = bvt_get (args->word->word);
    if (!t) { builtin_error ("title: bad handle"); return EX_USAGE; }
    const char *var = NULL;
    for (WORD_LIST *p = args->next; p; p = p->next) {
        if (strcmp (p->word->word, "-V") == 0 && p->next) {
            var = p->next->word->word; p = p->next;
        }
    }
    if (var) builtin_bind_variable ((char *) var, t->title, 0);
    else     printf ("%s\n", t->title);
    return EXECUTION_SUCCESS;
}

/* Query-response drain. DA/DSR parser replies accumulate here instead of
   writing directly to the pty; callers decide where to forward them. */
static int
bvt_response_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("response: HANDLE [-V VAR]"); return EX_USAGE; }
    bvt_t *t = bvt_get (args->word->word);
    if (!t) { builtin_error ("response: bad handle"); return EX_USAGE; }
    const char *var = NULL;
    for (WORD_LIST *p = args->next; p; p = p->next) {
        if (strcmp (p->word->word, "-V") == 0 && p->next) {
            var = p->next->word->word; p = p->next;
        } else {
            builtin_error ("response: unexpected '%s'", p->word->word);
            return EX_USAGE;
        }
    }
    if (var) {
        builtin_bind_variable ((char *) var,
                               t->response_buf ? t->response_buf : "", 0);
    } else if (t->response_len > 0 && t->response_buf) {
        fwrite (t->response_buf, 1, t->response_len, stdout);
    }
    t->response_len = 0;
    if (t->response_buf) t->response_buf[0] = '\0';
    return EXECUTION_SUCCESS;
}

/* 3i: diff render — emit only changed cells with ANSI cursor positioning,
   then snapshot grid → prev_grid for next diff. */
static int
bvt_diff_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("diff: HANDLE [-F FD]"); return EX_USAGE; }
    bvt_t *t = bvt_get (args->word->word);
    if (!t) { builtin_error ("diff: bad handle"); return EX_USAGE; }
    /* Stage 13: auto-flush like render. */
    bvt_emit_cluster (t);
    int fd = STDOUT_FILENO;
    for (WORD_LIST *p = args->next; p; p = p->next) {
        if (strcmp (p->word->word, "-F") == 0 && p->next) {
            fd = atoi (p->next->word->word); p = p->next;
        }
    }
    /* Build output buffer. For each row, find runs of changed cells;
       emit cursor-position + characters + reset. Skip whole-row no-change.
       3h: skip CONT cells (wide-char continuation), encode UTF-8. */
    char *out = malloc ((size_t) (t->rows * t->cols * 32 + 64));
    if (!out) return EXECUTION_FAILURE;
    size_t off = 0;
    for (int r = 0; r < t->rows; r++) {
        int c = 0;
        while (c < t->cols) {
            bvt_cell *cur = &t->grid[r * t->cols + c];
            bvt_cell *prev = &t->prev_grid[r * t->cols + c];
            /* Stage 14: same arena offset + count == same combiner
               sequence (arena slots are immutable once allocated; a
               new alloc gets a new offset). False positive only if a
               cell is rewritten with the identical sequence — the
               redraw is visually a no-op so harmless. */
            if (bvt_cell_visual_equal (cur, prev)) {
                c++; continue;
            }
            /* Emit cursor position + run. */
            int run_start = c;
            while (c < t->cols) {
                bvt_cell *cur2 = &t->grid[r * t->cols + c];
                bvt_cell *prev2 = &t->prev_grid[r * t->cols + c];
                if (bvt_cell_visual_equal (cur2, prev2)) break;
                c++;
            }
            off += (size_t) snprintf (out + off, 32, "\033[%d;%dH", r + 1, run_start + 1);
            for (int k = run_start; k < c; k++) {
                bvt_cell *cell = &t->grid[r * t->cols + k];
                if (cell->flags & BVT_CELL_FLAG_CONT) continue;     /* skip wide-char cont */
                uint32_t cp = cell->cp;
                if (cp == 0 || cp == 0xFFFFFFFF) cp = ' ';
                off += grapheme_encode_utf8 (cp, out + off, 16);
                for (int kk = 0; kk < cell->combiner_count; kk++) {
                    uint32_t comb = t->cluster_arena[cell->combiner_offset - 1 + kk];
                    off += grapheme_encode_utf8 (comb, out + off, 16);
                }
            }
        }
    }
    /* Snapshot. */
    memcpy (t->prev_grid, t->grid, (size_t) (t->rows * t->cols) * sizeof (bvt_cell));
    size_t wpos = 0;
    while (wpos < off) {
        ssize_t w = write (fd, out + wpos, off - wpos);
        if (w < 0) { if (errno == EINTR) continue; break; }
        wpos += (size_t) w;
    }
    free (out);
    return EXECUTION_SUCCESS;
}

static int
bvt_free_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("free: HANDLE"); return EX_USAGE; }
    int idx = bvt_get_index (args->word->word);
    if (idx < 0 || !bvt_handles[idx]) return EX_USAGE;
    free (bvt_handles[idx]->grid);
    free (bvt_handles[idx]->alt_grid);
    free (bvt_handles[idx]->prev_grid);
    free (bvt_handles[idx]->cluster_arena);    /* Stage 14 */
    free (bvt_handles[idx]->tab_stops);
    free (bvt_handles[idx]->response_buf);
    for (int i = 0; i < bvt_handles[idx]->scrollback_capacity; i++)
        bvt_scrollback_line_free (&bvt_handles[idx]->scrollback_lines[i]);
    free (bvt_handles[idx]->scrollback_lines);
    free (bvt_handles[idx]);
    bvt_handles[idx] = NULL;
    return EXECUTION_SUCCESS;
}

/* Stage 1 — print or bind a string, honoring the optional `-V VAR`
   tail argument. Used by mode + every color verb. */
static int
bvt_emit_or_bind (WORD_LIST *tail, const char *s)
{
    for (; tail; tail = tail->next) {
        if (strcmp (tail->word->word, "-V") == 0 && tail->next) {
            builtin_bind_variable ((char *) tail->next->word->word, (char *) s, 0);
            return EXECUTION_SUCCESS;
        }
    }
    fputs (s, stdout);
    fputc ('\n', stdout);
    return EXECUTION_SUCCESS;
}

/* Stage 1 — list active DEC private modes by name. */
static int
bvt_mode_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("mode: HANDLE [-V VAR]"); return EX_USAGE; }
    bvt_t *t = bvt_get (args->word->word);
    if (!t) { builtin_error ("mode: bad handle"); return EX_USAGE; }
    char buf[256]; size_t off = 0;
    static const struct { uint32_t bit; const char *name; } map[] = {
        { BVT_MODE_MOUSE_X10,       "mouse-x10" },
        { BVT_MODE_MOUSE_X11,       "mouse-x11" },
        { BVT_MODE_MOUSE_BTNEVENT,  "mouse-btn" },
        { BVT_MODE_MOUSE_ANYEVENT,  "mouse-any" },
        { BVT_MODE_FOCUS_EVENTS,    "focus" },
        { BVT_MODE_MOUSE_UTF8,      "mouse-utf8" },
        { BVT_MODE_MOUSE_SGR,       "mouse-sgr" },
        { BVT_MODE_MOUSE_URXVT,     "mouse-urxvt" },
        { BVT_MODE_MOUSE_SGR_PIXEL, "mouse-sgr-pixel" },
        { BVT_MODE_BRACKETED_PASTE, "bracketed-paste" },
    };
    for (size_t i = 0; i < sizeof (map) / sizeof (map[0]); i++) {
        if (!(t->mode_flags & map[i].bit)) continue;
        size_t need = strlen (map[i].name) + (off ? 1 : 0);
        if (off + need + 1 > sizeof (buf)) break;
        if (off) buf[off++] = ' ';
        memcpy (buf + off, map[i].name, strlen (map[i].name));
        off += strlen (map[i].name);
    }
#define BVT_APPEND_MODE(name) do { \
        const char *bvt_name_ = (name); \
        size_t bvt_len_ = strlen (bvt_name_); \
        size_t bvt_need_ = bvt_len_ + (off ? 1 : 0); \
        if (off + bvt_need_ + 1 <= sizeof (buf)) { \
            if (off) buf[off++] = ' '; \
            memcpy (buf + off, bvt_name_, bvt_len_); \
            off += bvt_len_; \
        } \
    } while (0)
    if (t->origin_mode) BVT_APPEND_MODE ("origin");
    if (t->autowrap) BVT_APPEND_MODE ("autowrap");
    if (t->reverse_video) BVT_APPEND_MODE ("reverse-video");
    if (t->reverse_wraparound) BVT_APPEND_MODE ("reverse-wrap");
#undef BVT_APPEND_MODE
    buf[off] = '\0';
    return bvt_emit_or_bind (args->next, buf);
}

/* Stage 1 — encode a synthetic mouse event so bash-screen's eventual
   forwarder + tests can roundtrip without a real mouse. SGR encoding
   if ?1006 is active; legacy X10 (CSI M Cb Cx Cy) otherwise. */
static int
bvt_mouse_encode_cmd (WORD_LIST *args)
{
    if (!args || !args->next || !args->next->next || !args->next->next->next) {
        builtin_error ("mouse-encode: HANDLE BUTTON ROW COL [release]");
        return EX_USAGE;
    }
    bvt_t *t = bvt_get (args->word->word);
    if (!t) { builtin_error ("mouse-encode: bad handle"); return EX_USAGE; }
    int button = atoi (args->next->word->word);
    int row    = atoi (args->next->next->word->word);
    int col    = atoi (args->next->next->next->word->word);
    int release = 0;
    WORD_LIST *p = args->next->next->next->next;
    if (p && strcmp (p->word->word, "release") == 0) { release = 1; p = p->next; }
    if (button < 0 || row < 1 || col < 1) {
        builtin_error ("mouse-encode: bad coords"); return EX_USAGE;
    }
    char buf[64];
    if (t->mode_flags & BVT_MODE_MOUSE_SGR) {
        snprintf (buf, sizeof (buf), "\033[<%d;%d;%d%c", button, col, row,
                  release ? 'm' : 'M');
    } else if (t->mode_flags & (BVT_MODE_MOUSE_X11 | BVT_MODE_MOUSE_BTNEVENT |
                                BVT_MODE_MOUSE_ANYEVENT | BVT_MODE_MOUSE_X10)) {
        /* Legacy X10: CSI M then 3 bytes (button+32, col+32, row+32). */
        unsigned char b = (unsigned char) (button + 32 + (release ? 3 : 0));
        unsigned char x = (unsigned char) (col + 32);
        unsigned char y = (unsigned char) (row + 32);
        snprintf (buf, sizeof (buf), "\033[M%c%c%c", b, x, y);
    } else {
        return EXECUTION_FAILURE;       /* no mouse mode active */
    }
    return bvt_emit_or_bind (p, buf);
}

/* Stage 1 — color helpers. Validate ranges, format SGR string, emit/bind.
   bg=1 selects 48;... otherwise 38;... */
static int
bvt_color_cube_emit (int bg, int r, int g, int b, WORD_LIST *tail)
{
    if (r < 0 || r > 5 || g < 0 || g > 5 || b < 0 || b > 5) {
        builtin_error ("color-cube: each of R G B must be 0..5"); return EX_USAGE;
    }
    char buf[32];
    snprintf (buf, sizeof (buf), "\033[%d;5;%dm", bg ? 48 : 38, 16 + 36 * r + 6 * g + b);
    return bvt_emit_or_bind (tail, buf);
}

static int
bvt_color_grayscale_emit (int bg, int n, WORD_LIST *tail)
{
    if (n < 0 || n > 23) {
        builtin_error ("color-grayscale: N must be 0..23"); return EX_USAGE;
    }
    char buf[32];
    snprintf (buf, sizeof (buf), "\033[%d;5;%dm", bg ? 48 : 38, 232 + n);
    return bvt_emit_or_bind (tail, buf);
}

static int
bvt_color_rgb_emit (int bg, int r, int g, int b, WORD_LIST *tail)
{
    if (r < 0 || r > 255 || g < 0 || g > 255 || b < 0 || b > 255) {
        builtin_error ("color-rgb: each of R G B must be 0..255"); return EX_USAGE;
    }
    char buf[32];
    snprintf (buf, sizeof (buf), "\033[%d;2;%d;%d;%dm", bg ? 48 : 38, r, g, b);
    return bvt_emit_or_bind (tail, buf);
}

static int
bvt_color_cmd (const char *verb, WORD_LIST *args)
{
    /* "color-cube R G B [-V VAR]"; "color-grayscale N [-V VAR]";
       "color-rgb R G B [-V VAR]"; "color-bg-..." mirror w/ bg=1;
       "color-reset [-V VAR]". */
    int bg = (strncmp (verb, "color-bg-", 9) == 0);
    const char *kind = verb + (bg ? 9 : 6);    /* skip "color-" or "color-bg-" */
    if (!strcmp (kind, "reset")) {
        return bvt_emit_or_bind (args, "\033[0m");
    }
    if (!strcmp (kind, "cube")) {
        if (!args || !args->next || !args->next->next) {
            builtin_error ("%s: R G B [-V VAR] (each 0..5)", verb); return EX_USAGE;
        }
        int r = atoi (args->word->word);
        int g = atoi (args->next->word->word);
        int b = atoi (args->next->next->word->word);
        return bvt_color_cube_emit (bg, r, g, b, args->next->next->next);
    }
    if (!strcmp (kind, "grayscale")) {
        if (!args) { builtin_error ("%s: N [-V VAR] (0..23)", verb); return EX_USAGE; }
        int n = atoi (args->word->word);
        return bvt_color_grayscale_emit (bg, n, args->next);
    }
    if (!strcmp (kind, "rgb")) {
        if (!args || !args->next || !args->next->next) {
            builtin_error ("%s: R G B [-V VAR] (each 0..255)", verb); return EX_USAGE;
        }
        int r = atoi (args->word->word);
        int g = atoi (args->next->word->word);
        int b = atoi (args->next->next->word->word);
        return bvt_color_rgb_emit (bg, r, g, b, args->next->next->next);
    }
    builtin_error ("unknown color verb: %s", verb);
    return EX_USAGE;
}

/* Stage 3 — resize the grid. Allocate new grid + alt + prev sized to
   rows×cols; copy the overlapping region from the old grids; clear the
   newly-introduced cells; free the old buffers; clamp cursor and saved
   cursor; reset scroll region; mark prev_grid sentinel-different so
   the next diff redraws the entire screen. The combiner arena keeps
   its existing slots (cells reference them by offset, which survives). */
static int
bvt_resize_cmd (WORD_LIST *args)
{
    if (!args || !args->next) {
        builtin_error ("resize: HANDLE -W cols -H rows"); return EX_USAGE;
    }
    bvt_t *t = bvt_get (args->word->word);
    if (!t) { builtin_error ("resize: bad handle"); return EX_USAGE; }
    /* Resize changes the wrap boundary. Materialize any pending grapheme
       cluster under the old dimensions first so scrollback preserves the
       pre-resize logical line. */
    bvt_emit_cluster (t);
    bvt_clear_pending_wrap (t);
    int new_rows = t->rows, new_cols = t->cols;
    for (WORD_LIST *p = args->next; p; p = p->next) {
        const char *w = p->word->word;
        if      (strcmp (w, "-W") == 0 && p->next) { new_cols = atoi (p->next->word->word); p = p->next; }
        else if (strcmp (w, "-H") == 0 && p->next) { new_rows = atoi (p->next->word->word); p = p->next; }
        else { builtin_error ("resize: unexpected '%s'", w); return EX_USAGE; }
    }
    if (new_rows < 1 || new_cols < 1 || new_rows > 1024 || new_cols > 1024) {
        builtin_error ("resize: bad dimensions"); return EX_USAGE;
    }
    if (new_rows == t->rows && new_cols == t->cols) return EXECUTION_SUCCESS;

    size_t total = (size_t) (new_rows * new_cols);
    bvt_cell *ng = calloc (total, sizeof (bvt_cell));
    bvt_cell *na = calloc (total, sizeof (bvt_cell));
    bvt_cell *np = calloc (total, sizeof (bvt_cell));
    uint8_t *ntabs = calloc ((size_t) new_cols, sizeof (uint8_t));
    if (!ng || !na || !np || !ntabs) {
        free (ng); free (na); free (np); free (ntabs);
        builtin_error ("resize: alloc"); return EXECUTION_FAILURE;
    }
    for (size_t i = 0; i < total; i++) { bvt_clear_cell (&ng[i]); bvt_clear_cell (&na[i]); }
    for (int c = 8; c < new_cols; c += 8)
        ntabs[c] = 1;
    if (t->tab_stops) {
        int copy_tabs = (new_cols < t->cols) ? new_cols : t->cols;
        memcpy (ntabs, t->tab_stops, (size_t) copy_tabs);
    }

    /* Copy overlap. The "active" grid (t->grid) goes to ng; alt → na. */
    int copy_rows = (new_rows < t->rows) ? new_rows : t->rows;
    int copy_cols = (new_cols < t->cols) ? new_cols : t->cols;
    for (int r = 0; r < copy_rows; r++) {
        for (int c = 0; c < copy_cols; c++) {
            ng[r * new_cols + c] = t->grid    [r * t->cols + c];
            na[r * new_cols + c] = t->alt_grid[r * t->cols + c];
        }
    }
    /* prev_grid: deliberately fill with the cp=0xFFFFFFFF sentinel so
       the very next diff redraws every cell. */
    for (size_t i = 0; i < total; i++) np[i].cp = 0xFFFFFFFFu;

    free (t->grid); free (t->alt_grid); free (t->prev_grid); free (t->tab_stops);
    t->grid = ng; t->alt_grid = na; t->prev_grid = np;
    t->tab_stops = ntabs;
    t->rows = new_rows; t->cols = new_cols;

    /* Clamp cursor + saved-cursor positions. */
    if (t->cy >= new_rows) t->cy = new_rows - 1;
    if (t->cx >= new_cols) t->cx = new_cols - 1;
    if (t->saved_cy >= new_rows) t->saved_cy = new_rows - 1;
    if (t->saved_cx >= new_cols) t->saved_cx = new_cols - 1;
    if (t->alt_saved_cy >= new_rows) t->alt_saved_cy = new_rows - 1;
    if (t->alt_saved_cx >= new_cols) t->alt_saved_cx = new_cols - 1;
    /* If cursor lands on a CONT cell, back up one. */
    bvt_cell *cur = bvt_cell_at (t, t->cy, t->cx);
    if (cur && (cur->flags & BVT_CELL_FLAG_CONT) && t->cx > 0) t->cx--;

    /* Reset scroll region to the full new height. */
    t->scroll_top = 0;
    t->scroll_bot = new_rows - 1;
    bvt_clamp_cursor (t);
    return EXECUTION_SUCCESS;
}

/* Stage 13: explicit pending-cluster flush. Callers (e.g. bash-screen
   after a quiet period) invoke this to materialize a cluster that
   started in one feed and never received a follow-up byte. render
   and diff auto-flush for free. */
static int
bvt_flush_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("flush: HANDLE"); return EX_USAGE; }
    bvt_t *t = bvt_get (args->word->word);
    if (!t) { builtin_error ("flush: bad handle"); return EX_USAGE; }
    bvt_emit_cluster (t);
    return EXECUTION_SUCCESS;
}

int
vt_builtin (WORD_LIST *list)
{
    extern char *vt_doc[];
    if (!list) { builtin_usage (); return EX_USAGE; }
    if (!strcmp (list->word->word, "--help") || !strcmp (list->word->word, "-h"))
    {
        char *const *dp;
        for (dp = vt_doc; *dp; dp++)
            puts (*dp);
        return (EX_USAGE);
    }
    bvt_cmd_osc52_mode = -1;
    while (list && !strncmp (list->word->word, "--osc52=", 8)) {
        const char *v = list->word->word + 8;
        if (!strcmp (v, "off"))
            bvt_cmd_osc52_mode = 0;
        else if (!strcmp (v, "on"))
            bvt_cmd_osc52_mode = 1;
        else {
            builtin_error ("--osc52: expected on or off");
            return EX_USAGE;
        }
        list = list->next;
    }
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    int rc;
    if (!strcmp (cmd, "new"))      rc = bvt_new_cmd (args);
    else if (!strcmp (cmd, "clone"))    rc = bvt_clone_cmd (args);
    else if (!strcmp (cmd, "feed"))     rc = bvt_feed_cmd (args);
    else if (!strcmp (cmd, "feed-fd"))  rc = bvt_feed_fd_cmd (args);
    else if (!strcmp (cmd, "render"))   rc = bvt_render_cmd (args);
    else if (!strcmp (cmd, "diff"))     rc = bvt_diff_cmd (args);
    else if (!strcmp (cmd, "title"))    rc = bvt_title_cmd (args);
    else if (!strcmp (cmd, "response")) rc = bvt_response_cmd (args);
    else if (!strcmp (cmd, "cursor"))   rc = bvt_cursor_cmd (args);
    else if (!strcmp (cmd, "size"))     rc = bvt_size_cmd (args);
    else if (!strcmp (cmd, "free"))     rc = bvt_free_cmd (args);
    else if (!strcmp (cmd, "flush"))    rc = bvt_flush_cmd (args);
    else if (!strcmp (cmd, "resize"))   rc = bvt_resize_cmd (args);
    else if (!strcmp (cmd, "scrollback-enable")) rc = bvt_scrollback_enable_cmd (args);
    else if (!strcmp (cmd, "scrollback-size"))   rc = bvt_scrollback_size_cmd   (args);
    else if (!strcmp (cmd, "scrollback-row"))    rc = bvt_scrollback_row_cmd    (args);
    else if (!strcmp (cmd, "scrollback-render")) rc = bvt_scrollback_render_cmd (args);
    /* Stage 1 — DEC mode introspection + mouse encoding + color helpers. */
    else if (!strcmp (cmd, "mode"))         rc = bvt_mode_cmd (args);
    else if (!strcmp (cmd, "mouse-encode")) rc = bvt_mouse_encode_cmd (args);
    else if (!strncmp (cmd, "color-", 6))   rc = bvt_color_cmd (cmd, args);
    else {
        builtin_error ("unknown verb: %s", cmd);
        rc = EX_USAGE;
    }
    bvt_cmd_osc52_mode = -1;
    return rc;
}

char *vt_doc[] = {
    "VT100/xterm-style terminal emulator (parses bytes → 2D grid).",
    "Global option: --osc52=on|off (consume clipboard OSC 52 or pass through).",
    "",
    "    vt new -h H [-W cols] [-H rows]",
    "        Allocate emulator (default 80×24); slot int → H.",
    "    vt feed H BYTES",
    "        Parse bytes (CSI / SGR / OSC / SCS / DEC private handlers wired).",
    "    vt feed-fd H FD [-N MAX]",
        "        Read up to MAX bytes from FD; bind BVT_LAST_BYTES.",
    "    vt clone SRC -h DST",
    "        Allocate a per-client VT snapshot. The diff baseline is",
    "        initialized to the cloned grid so later diff emits only",
    "        post-attach changes.",
    "    vt render H [-A] [-F FD]",
    "        Dump current grid as text; -A preserves cell SGR attributes.",
    "    vt diff H [-F FD]",
    "        Emit only changed cells (since last diff/render snapshot)",
    "        with cursor positioning. Used by bash-screen for redraws.",
    "    vt title H [-V VAR]",
    "        Print or bind the OSC 0/2 window title.",
    "    vt response H [-V VAR]",
    "        Print/bind and drain DA/DSR/ENQ replies accumulated by the parser.",
    "    vt cursor H        → 'ROW COL' (1-indexed)",
    "    vt size H          → 'ROWS COLS'",
    "    vt resize H -W cols -H rows",
    "        Resize the grid (Stage 3). Overlapping cells are preserved;",
    "        new cells are blank; cursor is clamped; scroll region resets;",
    "        prev_grid is sentinel-marked so the next diff redraws everything.",
    "    vt scrollback-enable H -L LINES",
    "        Enable logical-line scrollback. Evicted soft-wrapped rows are",
    "        joined; render reflows at the current width after resize.",
    "    vt scrollback-size H",
    "    vt scrollback-row H N [-F FD]",
    "    vt scrollback-render H [-F FD] [-N ROWS]",
    "    vt flush H",
    "        Materialize any pending grapheme cluster into the grid.",
    "        Stage 13 (2026-05): cluster state persists across feed/feed-fd",
    "        calls so a base + combiner split between two reads still",
    "        combines correctly. Render/diff auto-flush; this verb is",
    "        for callers who need to consult the grid via cursor/size",
    "        between feeds.",
    "    vt mode H [-V VAR]",
    "        List active DEC private modes by name (mouse-x10, mouse-x11,",
    "        mouse-btn, mouse-any, focus, mouse-utf8, mouse-sgr,",
    "        mouse-urxvt, mouse-sgr-pixel, bracketed-paste, origin,",
    "        autowrap, reverse-video, reverse-wrap).",
    "    vt mouse-encode H BUTTON ROW COL [release] [-V VAR]",
    "        Emit a mouse-event escape using whichever encoding is",
    "        active (SGR if ?1006h, else legacy X10).",
    "    vt color-cube R G B [-V VAR]",
    "    vt color-bg-cube R G B [-V VAR]",
    "        SGR for the 6×6×6 cube cell (each of R G B in 0..5).",
    "    vt color-grayscale N [-V VAR]",
    "    vt color-bg-grayscale N [-V VAR]",
    "        SGR for grayscale step N (0..23).",
    "    vt color-rgb R G B [-V VAR]",
    "    vt color-bg-rgb R G B [-V VAR]",
    "        Truecolor SGR (each of R G B in 0..255).",
    "    vt color-reset [-V VAR]",
    "        SGR reset (\\033[0m).",
    "    vt free H",
    "",
    "Sub-phases shipped: 3a (skeleton), 3b (parser), 3c (cursor moves),",
    "3d (ED/EL), 3e (full SGR incl. 256-color + RGB), 3f (alt-screen +",
    "DECSET 25/2004/1049), 3g (DECSTBM scroll region + IL/DL/SU/SD),",
    "3h (UTF-8 + grapheme-cluster + cell-width via libgrapheme),",
    "3i (diff render), 3j (OSC 0/2 title), Stage 5/12 clone +",
    "logical-line scrollback reflow, vttest cursor/charset/attribute slices.",
    (char *)NULL
};

struct builtin vt_struct = {
    "vt",
    vt_builtin,
    BUILTIN_ENABLED,
    vt_doc,
    "vt new|clone|feed|feed-fd|flush|resize|render|diff|scrollback-*|title|cursor|size|mode|mouse-encode|color-*|free ARGS",
    0
};
