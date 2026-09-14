/* SPDX-License-Identifier: MIT */
/* tiv.c — terminal image viewer (truecolor) as a bash builtin.
 *
 *   tiv [OPTION]... FILE
 *
 * Decodes an image (PNG/JPEG/GIF/BMP/TGA via the vendored stb_image) and prints
 * it to the terminal. The default renderer packs two vertical pixels into each
 * character cell using the upper-half-block glyph "▀" (U+2580): the top pixel
 * becomes the foreground color, the bottom pixel the background — 24-bit
 * truecolor by default, with 256-color / 16-color / greyscale / ASCII fallbacks.
 *
 * A C port of pancake's `tiv`/`stiv` (copyleft 2013-2015) and the half-block
 * refinement from tiv.py; reference under research/refs/tiv. Image decoding
 * uses stb_image instead of the original's libjpeg, so many formats work.
 *
 * Options:
 *   -w, --width N      output width in columns (default: terminal width / 80)
 *   -H, --height N     output height in terminal rows (default: keep aspect)
 *   -m, --mode MODE    rgb (default) | 256 | ansi | grey | ascii
 *   -i, --invert       invert colors
 *       --full         use the full terminal width
 *       --base64       FILE / stdin holds base64-encoded image data
 *   -h, --help    -V, --version
 *   FILE = path, or "-" for standard input.
 *
 * --- LICENSE --- MIT for this port (stb_image is public domain). When linked
 * into bash the combined binary is governed by bash's GPL-3+.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "_stb_stb_image.h"
#include "_bashtiv_blocks.h"        /* btv_half/quad/sext/oct glyph tables */
#include "loadables.h"

#define UHALF "\xe2\x96\x80"        /* ▀ U+2580 upper half block */
/* Bound the untrusted stdin/--base64 slurp (mirrors kitty's
   BK_MAX_INPUT_BYTES) so a pipe can't force unbounded allocation before the
   image is decoded; staying <= this also keeps the later (int) cast safe. The
   regular-file path is unaffected (stb_image reads incrementally). */
#define TIV_MAX_INPUT_BYTES (64ULL * 1024 * 1024)

extern char *tiv_doc[];
static void tiv_help (void) { for (int i = 0; tiv_doc[i]; i++) puts (tiv_doc[i]); }

typedef enum { M_RGB, M_256, M_ANSI, M_GREY, M_ASCII } tiv_mode;
/* sub-cell glyph density: more sub-pixels per cell = more detail at the SAME
   font size. half 1x2, quad 2x2, sextant 2x3, octant 2x4. */
typedef enum { G_HALF, G_QUAD, G_SEXT, G_OCT } tiv_glyph;

/* --- color reducers (from pancake's stiv.c) --------------------------- */
static int
tiv_reduce8 (int r, int g, int b)
{
    static const int col[8][3] = {
        { 0x00,0x00,0x00 }, { 0xd0,0x10,0x10 }, { 0x10,0xe0,0x10 }, { 0xf7,0xf5,0x3a },
        { 0x10,0x10,0xf0 }, { 0xfb,0x3d,0xf8 }, { 0x10,0xf0,0xf0 }, { 0xf0,0xf0,0xf0 }
    };
    if (r < 30 && g < 30 && b < 30) return 0;
    if (r > 200 && g > 200 && b > 200) return 7;
    int sel = 0; long best = -1;
    for (int i = 0; i < 8; i++) {
        long d = (long) abs (col[i][0] - r) * r
               + (long) abs (col[i][1] - g) * g
               + (long) abs (col[i][2] - b) * b;
        if (best == -1 || d < best) { best = d; sel = i; }
    }
    return sel;
}

static int
tiv_rgb256 (int r, int g, int b)
{
    if (r < 0) r = 0; if (r > 255) r = 255;
    if (g < 0) g = 0; if (g > 255) g = 255;
    if (b < 0) b = 0; if (b > 255) b = 255;
    return 16 + (int)(r / 50.6) * 36 + (int)(g / 50.6) * 6 + (int)(b / 50.6);
}

/* --- emit one cell (top pixel c, bottom pixel d) ---------------------- */
static void
tiv_cell (tiv_mode m, const unsigned char *c, const unsigned char *d)
{
    switch (m) {
    case M_RGB:
        printf ("\033[38;2;%d;%d;%d;48;2;%d;%d;%dm" UHALF,
                c[0], c[1], c[2], d[0], d[1], d[2]);
        break;
    case M_256:
        printf ("\033[38;5;%d;48;5;%dm" UHALF,
                tiv_rgb256 (c[0], c[1], c[2]), tiv_rgb256 (d[0], d[1], d[2]));
        break;
    case M_ANSI:
        printf ("\033[3%d;4%dm" UHALF, tiv_reduce8 (c[0], c[1], c[2]),
                tiv_reduce8 (d[0], d[1], d[2]));
        break;
    case M_GREY: {
        int g1 = (c[0] + c[1] + c[2]) / 3, g2 = (d[0] + d[1] + d[2]) / 3;
        int k1 = 232 + g1 * 23 / 255, k2 = 232 + g2 * 23 / 255;
        printf ("\033[38;5;%d;48;5;%dm" UHALF, k1, k2);
        break;
    }
    case M_ASCII: {
        static const char *pal = " `.,-:+*%$#";
        int n = (int) strlen (pal);
        int p = ((c[0]+c[1]+c[2]) / 3 + (d[0]+d[1]+d[2]) / 3) / 2;
        int idx = p * n / 256;
        if (idx >= n) idx = n - 1;
        putchar (pal[idx]);
        break;
    }
    }
}

/* --- emit a two-color cell (fg/bg) with an arbitrary block glyph -------
   Used by the dense (quad/sextant/octant) path; mirrors tiv_cell's color
   reduction but takes a pre-chosen glyph and a foreground/background pair.
   M_ASCII never reaches here (the caller routes ascii to the half path). */
static void
tiv_emit (tiv_mode m, const unsigned char *fg, const unsigned char *bg, const char *glyph)
{
    switch (m) {
    case M_RGB:
        printf ("\033[38;2;%d;%d;%d;48;2;%d;%d;%dm%s",
                fg[0], fg[1], fg[2], bg[0], bg[1], bg[2], glyph);
        break;
    case M_256:
        printf ("\033[38;5;%d;48;5;%dm%s",
                tiv_rgb256 (fg[0], fg[1], fg[2]), tiv_rgb256 (bg[0], bg[1], bg[2]), glyph);
        break;
    case M_ANSI:
        printf ("\033[3%d;4%dm%s", tiv_reduce8 (fg[0], fg[1], fg[2]),
                tiv_reduce8 (bg[0], bg[1], bg[2]), glyph);
        break;
    case M_GREY: {
        int g1 = (fg[0] + fg[1] + fg[2]) / 3, g2 = (bg[0] + bg[1] + bg[2]) / 3;
        printf ("\033[38;5;%d;48;5;%dm%s", 232 + g1 * 23 / 255, 232 + g2 * 23 / 255, glyph);
        break;
    }
    case M_ASCII:
        break;
    }
}

/* --- area-average resize (good downscale, fine upscale) --------------- */
static unsigned char *
tiv_resize (const unsigned char *src, int sw, int sh, int dw, int dh)
{
    unsigned char *dst = (unsigned char *) malloc ((size_t) dw * dh * 3);
    if (!dst) return NULL;
    for (int dy = 0; dy < dh; dy++) {
        int sy0 = (int) ((long) dy * sh / dh);
        int sy1 = (int) ((long) (dy + 1) * sh / dh);
        if (sy1 <= sy0) sy1 = sy0 + 1;
        if (sy1 > sh) sy1 = sh;
        for (int dx = 0; dx < dw; dx++) {
            int sx0 = (int) ((long) dx * sw / dw);
            int sx1 = (int) ((long) (dx + 1) * sw / dw);
            if (sx1 <= sx0) sx1 = sx0 + 1;
            if (sx1 > sw) sx1 = sw;
            unsigned long r = 0, g = 0, b = 0, n = 0;
            for (int sy = sy0; sy < sy1; sy++)
                for (int sx = sx0; sx < sx1; sx++) {
                    const unsigned char *p = src + ((size_t) sy * sw + sx) * 3;
                    r += p[0]; g += p[1]; b += p[2]; n++;
                }
            unsigned char *o = dst + ((size_t) dy * dw + dx) * 3;
            if (n) { o[0] = r / n; o[1] = g / n; o[2] = b / n; }
            else   { o[0] = o[1] = o[2] = 0; }
        }
    }
    return dst;
}

/* --- minimal base64 decode (in place into a fresh buffer) ------------- */
static unsigned char *
tiv_b64 (const unsigned char *in, size_t inlen, size_t *outlen)
{
    static signed char T[256];
    static int init = 0;
    if (!init) {
        memset (T, -1, sizeof T);
        const char *a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 64; i++) T[(unsigned char) a[i]] = (signed char) i;
        init = 1;
    }
    unsigned char *out = (unsigned char *) malloc (inlen / 4 * 3 + 4);
    if (!out) return NULL;
    size_t o = 0; unsigned int val = 0; int bits = 0;
    for (size_t i = 0; i < inlen; i++) {
        signed char v = T[in[i]];
        if (v < 0) continue;                 /* skip whitespace / '=' */
        val = (val << 6) | v; bits += 6;
        if (bits >= 8) { bits -= 8; out[o++] = (unsigned char) ((val >> bits) & 0xff); }
    }
    *outlen = o;
    return out;
}

/* --- read an entire stream into memory -------------------------------- */
static unsigned char *
tiv_slurp (FILE *f, size_t *len, size_t max)
{
    size_t cap = 1 << 16, n = 0;
    unsigned char *buf;
    if (cap > max) cap = max ? max : 1;
    buf = (unsigned char *) malloc (cap);
    if (!buf) return NULL;
    for (;;) {
        if (n == cap) {
            unsigned char *nb;
            if (cap >= max) {                 /* at the limit: more data => too large */
                unsigned char probe;
                if (fread (&probe, 1, 1, f) == 1) { free (buf); errno = EFBIG; return NULL; }
                break;
            }
            cap = (cap > max / 2) ? max : cap * 2;
            nb = (unsigned char *) realloc (buf, cap);
            if (!nb) { free (buf); return NULL; }
            buf = nb;
        }
        size_t r = fread (buf + n, 1, cap - n, f);
        n += r;
        if (r == 0) { if (ferror (f)) { free (buf); return NULL; } break; }
    }
    *len = n;
    return buf;
}

static void
tiv_term_size (int *cols, int *rows)
{
    struct winsize ws;
    *cols = 80; *rows = 24;
    if (ioctl (STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
        *cols = ws.ws_col; *rows = ws.ws_row;
    }
}

static tiv_mode
tiv_parse_mode (const char *s)
{
    switch (s[0]) {
    case 'a': return (s[1] == 'n') ? M_ANSI : M_ASCII;
    case 'g': return M_GREY;
    case '2': return M_256;
    default:  return M_RGB;
    }
}

static tiv_glyph
tiv_parse_glyph (const char *s)
{
    switch (s[0]) {
    case 'q': return G_QUAD;     /* quad    2x2 */
    case 's': return G_SEXT;     /* sextant 2x3 */
    case 'o': return G_OCT;      /* octant  2x4 */
    default:  return G_HALF;     /* half    1x2 */
    }
}

int
tiv_builtin (WORD_LIST *list)
{
    int want_w = 0, want_h = 0, full = 0, invert = 0, b64 = 0, end_opts = 0;
    tiv_mode mode = M_RGB;
    tiv_glyph glyph = G_HALF;
    const char *file = NULL;

    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (!end_opts && !strcmp (w, "--")) { end_opts = 1; continue; }
        if (!end_opts && (!strcmp (w, "-h") || !strcmp (w, "--help"))) { tiv_help (); return EXECUTION_SUCCESS; }
        if (!end_opts && (!strcmp (w, "-V") || !strcmp (w, "--version"))) {
            puts ("tiv 1.1 (bash-os terminal image viewer, stb_image)"); return EXECUTION_SUCCESS;
        }
        if (!end_opts && (!strcmp (w, "-i") || !strcmp (w, "--invert"))) { invert = 1; continue; }
        if (!end_opts && !strcmp (w, "--full")) { full = 1; continue; }
        if (!end_opts && !strcmp (w, "--base64")) { b64 = 1; continue; }
        if (!end_opts && (!strcmp (w, "-w") || !strcmp (w, "--width"))) {
            if (!p->next) { builtin_error ("option requires an argument: -w"); return EX_USAGE; }
            p = p->next; want_w = atoi (p->word->word); continue;
        }
        if (!end_opts && (!strcmp (w, "-H") || !strcmp (w, "--height"))) {
            if (!p->next) { builtin_error ("option requires an argument: -H"); return EX_USAGE; }
            p = p->next; want_h = atoi (p->word->word); continue;
        }
        if (!end_opts && (!strcmp (w, "-m") || !strcmp (w, "--mode"))) {
            if (!p->next) { builtin_error ("option requires an argument: -m"); return EX_USAGE; }
            p = p->next; mode = tiv_parse_mode (p->word->word); continue;
        }
        if (!end_opts && (!strcmp (w, "-g") || !strcmp (w, "--glyph"))) {
            if (!p->next) { builtin_error ("option requires an argument: -g"); return EX_USAGE; }
            p = p->next; glyph = tiv_parse_glyph (p->word->word); continue;
        }
        if (!end_opts && w[0] == '-' && w[1] && strcmp (w, "-")) {
            builtin_error ("invalid option: %s", w); builtin_usage (); return EX_USAGE;
        }
        if (file) { builtin_error ("only one FILE allowed"); return EX_USAGE; }
        file = w;
    }
    if (!file && b64) file = "-";
    if (!file) { builtin_error ("FILE required (or - for stdin)"); builtin_usage (); return EX_USAGE; }

    /* --- decode --- */
    int iw = 0, ih = 0, ich = 0;
    unsigned char *img = NULL;
    if (!b64 && strcmp (file, "-") != 0) {
        img = stbi_load (file, &iw, &ih, &ich, 3);
    } else {
        FILE *f = strcmp (file, "-") ? fopen (file, "rb") : stdin;
        if (!f) { builtin_error ("%s: %s", file, strerror (errno)); return EXECUTION_FAILURE; }
        size_t rawlen = 0;
        unsigned char *raw = tiv_slurp (f, &rawlen, TIV_MAX_INPUT_BYTES);
        int slurp_errno = errno;
        if (f != stdin) fclose (f);
        if (!raw) {
            if (slurp_errno == EFBIG)
                builtin_error ("input too large (max %llu bytes)",
                               (unsigned long long) TIV_MAX_INPUT_BYTES);
            else
                builtin_error ("read error");
            return EXECUTION_FAILURE;
        }
        unsigned char *data = raw; size_t dlen = rawlen; unsigned char *dec = NULL;
        if (b64) {
            size_t blen = 0;
            dec = tiv_b64 (raw, rawlen, &blen);
            if (!dec) { free (raw); builtin_error ("base64 decode failed"); return EXECUTION_FAILURE; }
            data = dec; dlen = blen;
        }
        img = stbi_load_from_memory (data, (int) dlen, &iw, &ih, &ich, 3);
        free (dec); free (raw);
    }
    if (!img) { builtin_error ("%s: %s", file, stbi_failure_reason () ? stbi_failure_reason () : "decode failed"); return EXECUTION_FAILURE; }

    /* --- target dimensions --- */
    int tcols, trows;
    tiv_term_size (&tcols, &trows);
    int is_tty = isatty (STDOUT_FILENO);
    int width = want_w > 0 ? want_w : (full ? tcols : (is_tty ? tcols : 80));
    if (width < 1) width = 1;
    int rows;
    if (want_h > 0) rows = want_h;
    else rows = (int) ((long) width * ih / iw + 1) / 2;     /* 2 px per row */
    if (rows < 1) rows = 1;
    /* fit to terminal height (leave a line) when interactive */
    if (is_tty && want_h <= 0 && rows > trows - 1 && trows > 1) {
        rows = trows - 1;
        int nw = (int) ((long) rows * 2 * iw / ih);
        if (nw > 0 && (want_w <= 0)) {
            width = full ? (nw < tcols ? nw : tcols) : (nw < width ? nw : width);
            if (width < 1) width = 1;
        }
    }
    /* Sub-pixel geometry: a cell stays 1-wide x 2-tall *visually* (same font),
       but a denser glyph samples more pixels per cell. ASCII has no blocks, so
       it always uses the half-block luminance ramp. */
    int gw = 1, gh = 2;
    const char *const *table = btv_half;
    if (mode != M_ASCII) {
        switch (glyph) {
        case G_QUAD: gw = 2; gh = 2; table = btv_quad; break;
        case G_SEXT: gw = 2; gh = 3; table = btv_sext; break;
        case G_OCT:  gw = 2; gh = 4; table = btv_oct;  break;
        case G_HALF: default: gw = 1; gh = 2; table = btv_half; break;
        }
    }
    int pw = width * gw, ph = rows * gh;

    /* --- resize + optional invert --- */
    unsigned char *pix = tiv_resize (img, iw, ih, pw, ph);
    stbi_image_free (img);
    if (!pix) { builtin_error ("out of memory resizing"); return EXECUTION_FAILURE; }
    if (invert)
        for (size_t i = 0; i < (size_t) pw * ph * 3; i++) pix[i] = (unsigned char) (255 - pix[i]);

    /* --- render (buffered) --- */
    setvbuf (stdout, NULL, _IOFBF, 1 << 16);
    if (mode == M_ASCII || glyph == G_HALF) {
        /* original half-block / ascii path (gw=1, gh=2) */
        static const unsigned char black[3] = { 0, 0, 0 };
        for (int y = 0; y < ph; y += 2) {
            for (int x = 0; x < width; x++) {
                const unsigned char *c = pix + ((size_t) y * width + x) * 3;
                const unsigned char *d = (y + 1 < ph) ? pix + ((size_t) (y + 1) * width + x) * 3 : black;
                tiv_cell (mode, c, d);
            }
            fputs (mode == M_ASCII ? "\n" : "\033[0m\n", stdout);
        }
    } else {
        /* dense sub-cell path: per cell, split sub-pixels into two colors by a
           luminance threshold, set bit i for each sub-pixel in the fg group,
           and emit table[mask] in fg/bg. */
        int ncells = gw * gh;                 /* <= 8 (octant) */
        for (int cy = 0; cy < rows; cy++) {
            for (int cx = 0; cx < width; cx++) {
                unsigned char sub[8][3];
                int lum[8], lo = 1 << 30, hi = -1;
                for (int i = 0; i < ncells; i++) {
                    int sx = cx * gw + (i % gw), sy = cy * gh + (i / gw);
                    const unsigned char *p = pix + ((size_t) sy * pw + sx) * 3;
                    sub[i][0] = p[0]; sub[i][1] = p[1]; sub[i][2] = p[2];
                    lum[i] = (p[0] * 299 + p[1] * 587 + p[2] * 114) / 1000;
                    if (lum[i] < lo) lo = lum[i];
                    if (lum[i] > hi) hi = lum[i];
                }
                if (hi - lo < 1) {            /* flat cell -> solid background */
                    tiv_emit (mode, sub[0], sub[0], " ");
                    continue;
                }
                int thr = (lo + hi) / 2, mask = 0;
                unsigned long fr = 0, fg = 0, fb = 0, fn = 0, br = 0, bg = 0, bb = 0, bn = 0;
                for (int i = 0; i < ncells; i++) {
                    if (lum[i] >= thr) { mask |= 1 << i; fr += sub[i][0]; fg += sub[i][1]; fb += sub[i][2]; fn++; }
                    else               {                 br += sub[i][0]; bg += sub[i][1]; bb += sub[i][2]; bn++; }
                }
                unsigned char fc[3] = { (unsigned char) (fr / fn), (unsigned char) (fg / fn), (unsigned char) (fb / fn) };
                unsigned char bc[3] = { bn ? (unsigned char) (br / bn) : 0,
                                        bn ? (unsigned char) (bg / bn) : 0,
                                        bn ? (unsigned char) (bb / bn) : 0 };
                tiv_emit (mode, fc, bc, table[mask]);
            }
            fputs ("\033[0m\n", stdout);
        }
    }
    fflush (stdout);
    free (pix);
    return EXECUTION_SUCCESS;
}

char *tiv_doc[] = {
    "Display an image in the terminal (truecolor by default).",
    "",
    "    tiv [OPTION]... FILE",
    "",
    "Decodes FILE (PNG/JPEG/GIF/BMP/TGA; - = stdin) and prints it with block",
    "glyphs. The default half-block glyph shows two vertical pixels per cell;",
    "denser glyphs (-g) pack more detail into the SAME font size by using more",
    "sub-pixels per cell, each cell drawn in two colors (fg/bg).",
    "",
    "Options:",
    "    -w, --width N    output width in columns (default: terminal width / 80)",
    "    -H, --height N   output height in terminal rows (default: keep aspect)",
    "    -m, --mode MODE  color: rgb (default) | 256 | ansi | grey | ascii",
    "    -g, --glyph G    density: half (default,1x2) | quad (2x2) | sextant",
    "                     (2x3) | octant (2x4). Denser needs a modern terminal",
    "                     (sextant: Unicode 13; octant: Unicode 16). Ignored for",
    "                     -m ascii.",
    "    -i, --invert     invert colors",
    "        --full       use the full terminal width",
    "        --base64     FILE / stdin holds base64-encoded image data",
    "    -h, --help       show this help",
    "    -V, --version    show version",
    (char *) NULL
};

struct builtin tiv_struct = {
    "tiv",
    tiv_builtin,
    BUILTIN_ENABLED,
    tiv_doc,
    "tiv [-w N] [-H N] [-m MODE] [-g GLYPH] [-i] [--full] [--base64] FILE",
    0
};
