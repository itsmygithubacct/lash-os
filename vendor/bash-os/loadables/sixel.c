/* SPDX-License-Identifier: MIT */
/* sixel.c - emit an image as DEC SIXEL graphics (true per-pixel) as a bash
 * builtin. Companion to tiv (cell glyphs) and kitty (Kitty protocol):
 * SIXEL is the pixel protocol that many VTE-based terminals (and xterm -ti
 * vt340, foot, mlterm, wezterm) render — and it passes through tmux >= 3.4,
 * unlike the Kitty graphics protocol.
 *
 * Decodes via the vendored stb_image, area-averages to the target pixel size,
 * quantizes to a fixed 6x6x6 (216) color cube, and emits SIXEL. Intentionally a
 * one-way emitter: no terminal probing, no shell evaluation of filenames.
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
#include "loadables.h"

#define BSX_MAX_INPUT_BYTES (64ULL * 1024 * 1024)
#define BSX_MAX_DIM 4096

extern char *sixel_doc[];
static void bsx_help (void) { for (int i = 0; sixel_doc[i]; i++) puts (sixel_doc[i]); }

/* --- area-average resize (RGB, 3 bytes/px) --------------------------- */
static unsigned char *
bsx_resize (const unsigned char *src, int sw, int sh, int dw, int dh)
{
    unsigned char *dst = (unsigned char *) malloc ((size_t) dw * dh * 3);
    if (!dst) return NULL;
    for (int dy = 0; dy < dh; dy++) {
        int sy0 = (int) ((long) dy * sh / dh), sy1 = (int) ((long) (dy + 1) * sh / dh);
        if (sy1 <= sy0) sy1 = sy0 + 1; if (sy1 > sh) sy1 = sh;
        for (int dx = 0; dx < dw; dx++) {
            int sx0 = (int) ((long) dx * sw / dw), sx1 = (int) ((long) (dx + 1) * sw / dw);
            if (sx1 <= sx0) sx1 = sx0 + 1; if (sx1 > sw) sx1 = sw;
            unsigned long r = 0, g = 0, b = 0, n = 0;
            for (int sy = sy0; sy < sy1; sy++)
                for (int sx = sx0; sx < sx1; sx++) {
                    const unsigned char *p = src + ((size_t) sy * sw + sx) * 3;
                    r += p[0]; g += p[1]; b += p[2]; n++;
                }
            unsigned char *o = dst + ((size_t) dy * dw + dx) * 3;
            if (n) { o[0] = r / n; o[1] = g / n; o[2] = b / n; } else o[0] = o[1] = o[2] = 0;
        }
    }
    return dst;
}

/* read a whole stream, bounded */
static unsigned char *
bsx_slurp (FILE *f, size_t *outlen, unsigned long long cap)
{
    size_t cap0 = 1 << 16, len = 0;
    unsigned char *buf = (unsigned char *) malloc (cap0);
    if (!buf) return NULL;
    for (;;) {
        if (len == cap0) {
            if ((unsigned long long) cap0 >= cap) { free (buf); errno = EFBIG; return NULL; }
            cap0 <<= 1; unsigned char *nb = (unsigned char *) realloc (buf, cap0);
            if (!nb) { free (buf); return NULL; } buf = nb;
        }
        size_t got = fread (buf + len, 1, cap0 - len, f);
        len += got;
        if (got == 0) { if (ferror (f)) { free (buf); return NULL; } break; }
    }
    *outlen = len; return buf;
}

/* minimal base64 decode */
static unsigned char *
bsx_b64 (const unsigned char *in, size_t inlen, size_t *outlen)
{
    static signed char T[256]; static int init = 0;
    if (!init) { memset (T, -1, sizeof T);
        const char *a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 64; i++) T[(unsigned char) a[i]] = (signed char) i; init = 1; }
    unsigned char *out = (unsigned char *) malloc (inlen / 4 * 3 + 4);
    if (!out) return NULL;
    size_t o = 0; unsigned int val = 0; int bits = 0;
    for (size_t i = 0; i < inlen; i++) {
        signed char v = T[in[i]]; if (v < 0) continue;
        val = (val << 6) | v; bits += 6;
        if (bits >= 8) { bits -= 8; out[o++] = (unsigned char) ((val >> bits) & 0xff); }
    }
    *outlen = o; return out;
}

static void
bsx_term_pixels (int *xpix, int *ypix)
{
    struct winsize ws;
    *xpix = 0; *ypix = 0;
    if (ioctl (STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        if (ws.ws_xpixel > 0) *xpix = ws.ws_xpixel;
        if (ws.ws_ypixel > 0) *ypix = ws.ws_ypixel;
    }
}

/* 6x6x6 color cube: channel level l(0..5) -> 8-bit center and sixel 0..100 */
static inline int bsx_lvl (int v) { int l = v * 6 / 256; return l > 5 ? 5 : l; }

int
sixel_builtin (WORD_LIST *list)
{
    int want_w = 0, want_h = 0, b64 = 0, end_opts = 0;
    const char *file = NULL;

    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (!end_opts && !strcmp (w, "--")) { end_opts = 1; continue; }
        if (!end_opts && (!strcmp (w, "-h") || !strcmp (w, "--help"))) { bsx_help (); return EXECUTION_SUCCESS; }
        if (!end_opts && (!strcmp (w, "-V") || !strcmp (w, "--version"))) {
            puts ("sixel 1.0 (bash-os sixel image emitter, stb_image)"); return EXECUTION_SUCCESS; }
        if (!end_opts && !strcmp (w, "--base64")) { b64 = 1; continue; }
        if (!end_opts && (!strcmp (w, "-w") || !strcmp (w, "--width"))) {
            if (!p->next) { builtin_error ("option requires an argument: -w"); return EX_USAGE; }
            p = p->next; want_w = atoi (p->word->word); continue; }
        if (!end_opts && (!strcmp (w, "-H") || !strcmp (w, "--height"))) {
            if (!p->next) { builtin_error ("option requires an argument: -H"); return EX_USAGE; }
            p = p->next; want_h = atoi (p->word->word); continue; }
        if (!end_opts && w[0] == '-' && w[1] && strcmp (w, "-")) {
            builtin_error ("invalid option: %s", w); builtin_usage (); return EX_USAGE; }
        if (file) { builtin_error ("only one FILE allowed"); return EX_USAGE; }
        file = w;
    }
    if (!file && b64) file = "-";
    if (!file) { builtin_error ("FILE required (or - for stdin)"); builtin_usage (); return EX_USAGE; }

    int iw = 0, ih = 0, ich = 0;
    unsigned char *img = NULL;
    if (!b64 && strcmp (file, "-") != 0) {
        img = stbi_load (file, &iw, &ih, &ich, 3);
    } else {
        FILE *f = strcmp (file, "-") ? fopen (file, "rb") : stdin;
        if (!f) { builtin_error ("%s: %s", file, strerror (errno)); return EXECUTION_FAILURE; }
        size_t rawlen = 0; unsigned char *raw = bsx_slurp (f, &rawlen, BSX_MAX_INPUT_BYTES);
        int e = errno; if (f != stdin) fclose (f);
        if (!raw) { builtin_error (e == EFBIG ? "input too large" : "read error"); return EXECUTION_FAILURE; }
        unsigned char *data = raw, *dec = NULL; size_t dlen = rawlen;
        if (b64) { size_t bl = 0; dec = bsx_b64 (raw, rawlen, &bl);
            if (!dec) { free (raw); builtin_error ("base64 decode failed"); return EXECUTION_FAILURE; }
            data = dec; dlen = bl; }
        img = stbi_load_from_memory (data, (int) dlen, &iw, &ih, &ich, 3);
        free (dec); free (raw);
    }
    if (!img) { builtin_error ("%s: %s", file, stbi_failure_reason () ? stbi_failure_reason () : "decode failed"); return EXECUTION_FAILURE; }

    /* target pixel size: -w/-H, else terminal pixels, else image (capped) */
    int txp, typ; bsx_term_pixels (&txp, &typ);
    int W = want_w > 0 ? want_w : (txp > 0 ? txp : (iw < 800 ? iw : 800));
    if (W > BSX_MAX_DIM) W = BSX_MAX_DIM; if (W < 1) W = 1;
    int H = want_h > 0 ? want_h : (int) ((long) W * ih / iw);
    if (H > BSX_MAX_DIM) H = BSX_MAX_DIM; if (H < 1) H = 1;

    unsigned char *pix = bsx_resize (img, iw, ih, W, H);
    stbi_image_free (img);
    if (!pix) { builtin_error ("out of memory resizing"); return EXECUTION_FAILURE; }

    /* per-pixel 6x6x6 cube index */
    unsigned char *idx = (unsigned char *) malloc ((size_t) W * H);
    if (!idx) { free (pix); builtin_error ("out of memory"); return EXECUTION_FAILURE; }
    for (size_t i = 0; i < (size_t) W * H; i++) {
        const unsigned char *p = pix + i * 3;
        idx[i] = (unsigned char) (bsx_lvl (p[0]) * 36 + bsx_lvl (p[1]) * 6 + bsx_lvl (p[2]));
    }
    free (pix);

    setvbuf (stdout, NULL, _IOFBF, 1 << 16);
    /* header + raster attributes (pixel aspect 1:1, size WxH) */
    printf ("\033Pq\"1;1;%d;%d", W, H);
    /* palette: 216 cube colors, sixel scale 0..100 */
    for (int c = 0; c < 216; c++) {
        int rl = c / 36, gl = (c / 6) % 6, bl = c % 6;
        printf ("#%d;2;%d;%d;%d", c, rl * 100 / 5, gl * 100 / 5, bl * 100 / 5);
    }

    char *row = (char *) malloc ((size_t) W + 1);
    char *used = (char *) malloc (216);
    if (!row || !used) { free (row); free (used); free (idx); builtin_error ("out of memory"); return EXECUTION_FAILURE; }

    for (int y = 0; y < H; y += 6) {
        int rows = (H - y < 6) ? (H - y) : 6;
        memset (used, 0, 216);
        for (int r = 0; r < rows; r++)
            for (int x = 0; x < W; x++) used[idx[(size_t)(y + r) * W + x]] = 1;
        int first = 1;
        for (int c = 0; c < 216; c++) {
            if (!used[c]) continue;
            if (!first) putchar ('$');      /* overlay this color on the same band */
            first = 0;
            putchar ('#'); printf ("%d", c);
            /* build the sixel char row for color c */
            for (int x = 0; x < W; x++) {
                int bits = 0;
                for (int r = 0; r < rows; r++)
                    if (idx[(size_t)(y + r) * W + x] == c) bits |= 1 << r;
                row[x] = (char) (0x3f + bits);
            }
            /* RLE emit */
            for (int x = 0; x < W;) {
                int run = 1;
                while (x + run < W && row[x + run] == row[x]) run++;
                if (run >= 4) printf ("!%d%c", run, row[x]);
                else for (int k = 0; k < run; k++) putchar (row[x]);
                x += run;
            }
        }
        putchar ('-');                       /* graphics newline: next 6-px band */
    }
    fputs ("\033\\", stdout);                /* ST: end sixel */
    fflush (stdout);
    free (row); free (used); free (idx);
    return EXECUTION_SUCCESS;
}

char *sixel_doc[] = {
    "Display an image as SIXEL graphics (true per-pixel).",
    "",
    "    sixel [OPTION]... FILE",
    "",
    "Decodes FILE (PNG/JPEG/GIF/BMP/TGA; - = stdin), scales to the target pixel",
    "size, quantizes to a 6x6x6 (216) color cube, and emits DEC SIXEL. Works in",
    "sixel-capable terminals (xterm -ti vt340, foot, mlterm, wezterm, recent VTE)",
    "and passes through tmux >= 3.4. For Kitty-protocol terminals use kitty;",
    "for any terminal use tiv (cell glyphs).",
    "",
    "Options:",
    "    -w, --width N    output width in pixels (default: terminal px, else 800)",
    "    -H, --height N   output height in pixels (default: keep aspect)",
    "        --base64     FILE / stdin holds base64-encoded image data",
    "    -h, --help       show this help",
    "    -V, --version    show version",
    (char *) NULL
};

struct builtin sixel_struct = {
    "sixel",
    sixel_builtin,
    BUILTIN_ENABLED,
    sixel_doc,
    "sixel [-w N] [-H N] [--base64] FILE",
    0
};
