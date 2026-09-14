/* SPDX-License-Identifier: MIT */
/* kitty.c - Kitty graphics protocol image emitter as a bash builtin.
 *
 *   kitty [OPTION]... FILE
 *
 * Decodes an image through the vendored stb_image reader and emits Kitty
 * direct-RGB graphics APC commands. This is intentionally a one-way emitter:
 * no terminal probing, no file/shared-memory Kitty transports, and no shell
 * evaluation of filenames or option values.
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
#include <limits.h>
#include <stdint.h>
#include <sys/ioctl.h>

#include "_stb_stb_image.h"
#include "loadables.h"

#define BK_MAX_DIM 10000
#define BK_DEFAULT_MAX_PIXELS 4194304ULL
#define BK_RAW_CHUNK 3072U
#define BK_ESC "\033"
/* Cap the untrusted stdin/--base64 slurp so a pipe can't force unbounded
   allocation before any decode/pixel limit applies (a 10000x10000 RGBA source
   compresses to well under this; raise via taste, not attacker input). */
#define BK_MAX_INPUT_BYTES (64ULL * 1024 * 1024)
/* Kitty control keys are 32-bit integers (graphics-protocol.rst). */
#define BK_U32_MAX 4294967295ULL

extern char *kitty_doc[];
static void
bk_help (void)
{
    for (int i = 0; kitty_doc[i]; i++)
        puts (kitty_doc[i]);
}

typedef struct bk_opts {
    int want_w;
    int want_h;
    int full;
    int b64;
    int raw_apc;
    int static_cursor;
    int tmux;          /* wrap each APC in tmux passthrough; -1=auto($TMUX) */
    int have_id;
    int have_placement;
    int have_z;
    unsigned long long id;
    unsigned long long placement;
    int z_index;
    unsigned long long max_pixels;
    const char *file;
} bk_opts;

typedef struct bk_term {
    int cols;
    int rows;
    int xpixels;
    int ypixels;
} bk_term;

static int
bk_mul_ull (unsigned long long a, unsigned long long b, unsigned long long *out)
{
    if (a != 0 && b > ULLONG_MAX / a)
        return -1;
    *out = a * b;
    return 0;
}

static int
bk_parse_u64 (const char *s, const char *label, unsigned long long *out)
{
    char *end = NULL;
    unsigned long long v;

    if (!s || !*s) {
        builtin_error ("invalid %s: %s", label, s ? s : "");
        return -1;
    }
    errno = 0;
    v = strtoull (s, &end, 10);
    if (errno || end == s || *end || v == 0) {
        builtin_error ("invalid %s: %s", label, s);
        return -1;
    }
    *out = v;
    return 0;
}

/* Parse a Kitty 32-bit control key. min is 1 for the image id (i=0 is illegal
   per the protocol) and 0 for the placement id (p=0 is legal: "no placement").
   Rejects values above the protocol's 32-bit ceiling so we never emit an
   out-of-range control value. */
static int
bk_parse_u32 (const char *s, const char *label, unsigned long long min,
              unsigned long long *out)
{
    char *end = NULL;
    unsigned long long v;

    if (!s || !*s) {
        builtin_error ("invalid %s: %s", label, s ? s : "");
        return -1;
    }
    errno = 0;
    v = strtoull (s, &end, 10);
    if (errno || end == s || *end || v < min || v > BK_U32_MAX) {
        builtin_error ("invalid %s: %s", label, s);
        return -1;
    }
    *out = v;
    return 0;
}

static int
bk_parse_pos_int (const char *s, const char *label, int *out)
{
    unsigned long long v;

    if (bk_parse_u64 (s, label, &v) != 0)
        return -1;
    if (v > (unsigned long long) INT_MAX) {
        builtin_error ("invalid %s: %s", label, s);
        return -1;
    }
    *out = (int) v;
    return 0;
}

static int
bk_parse_i32 (const char *s, const char *label, int *out)
{
    char *end = NULL;
    long v;

    if (!s || !*s) {
        builtin_error ("invalid %s: %s", label, s ? s : "");
        return -1;
    }
    errno = 0;
    v = strtol (s, &end, 10);
    if (errno || end == s || *end || v < INT_MIN || v > INT_MAX) {
        builtin_error ("invalid %s: %s", label, s);
        return -1;
    }
    *out = (int) v;
    return 0;
}

/* Read all of f, growing the buffer up to `max` bytes. If the input exceeds
   `max`, free and fail with errno=EFBIG so the caller can report "too large"
   distinctly from a read error. Bounds untrusted stdin/base64 input. */
static unsigned char *
bk_slurp (FILE *f, size_t *len, size_t max)
{
    size_t cap = 1U << 16, n = 0;
    unsigned char *buf;

    if (cap > max)
        cap = max ? max : 1;
    buf = (unsigned char *) malloc (cap);
    if (!buf)
        return NULL;

    for (;;) {
        if (n == cap) {
            unsigned char *nb;
            if (cap >= max) {                 /* at the limit: is there more? */
                unsigned char probe;
                if (fread (&probe, 1, 1, f) == 1) {
                    free (buf);
                    errno = EFBIG;
                    return NULL;
                }
                break;                        /* exactly `max` bytes, clean EOF */
            }
            cap = (cap > max / 2) ? max : cap * 2;
            nb = (unsigned char *) realloc (buf, cap);
            if (!nb) {
                free (buf);
                return NULL;
            }
            buf = nb;
        }
        size_t r = fread (buf + n, 1, cap - n, f);
        n += r;
        if (r == 0) {
            if (ferror (f)) {
                free (buf);
                return NULL;
            }
            break;                            /* EOF */
        }
    }
    *len = n;
    return buf;
}

static unsigned char *
bk_b64_decode (const unsigned char *in, size_t inlen, size_t *outlen)
{
    static signed char table[256];
    static int init = 0;
    unsigned char *out;
    size_t o = 0;
    unsigned int val = 0; int bits = 0;

    if (!init) {
        const char *a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        memset (table, -1, sizeof table);
        for (int i = 0; i < 64; i++)
            table[(unsigned char) a[i]] = (signed char) i;
        init = 1;
    }

    out = (unsigned char *) malloc (inlen / 4 * 3 + 4);
    if (!out)
        return NULL;
    for (size_t i = 0; i < inlen; i++) {
        signed char v;
        if (in[i] == '=')
            continue;
        v = table[in[i]];
        if (v < 0)
            continue;
        val = (val << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (unsigned char) ((val >> bits) & 0xff);
        }
    }
    *outlen = o;
    return out;
}

static unsigned char *
bk_load_image (const char *file, int is_b64, int *iw, int *ih)
{
    int ich = 0;

    if (!is_b64 && strcmp (file, "-") != 0)
        return stbi_load (file, iw, ih, &ich, 3);

    FILE *f = strcmp (file, "-") ? fopen (file, "rb") : stdin;
    if (!f) {
        builtin_error ("%s: %s", file, strerror (errno));
        return NULL;
    }

    size_t rawlen = 0;
    unsigned char *raw = bk_slurp (f, &rawlen, BK_MAX_INPUT_BYTES);
    int slurp_errno = errno;
    if (f != stdin)
        fclose (f);
    if (!raw) {
        if (slurp_errno == EFBIG)
            builtin_error ("input too large (max %llu bytes)",
                           (unsigned long long) BK_MAX_INPUT_BYTES);
        else
            builtin_error ("read error");
        return NULL;
    }

    unsigned char *data = raw;
    unsigned char *dec = NULL;
    size_t dlen = rawlen;
    if (is_b64) {
        size_t blen = 0;
        dec = bk_b64_decode (raw, rawlen, &blen);
        if (!dec) {
            free (raw);
            builtin_error ("base64 decode failed");
            return NULL;
        }
        data = dec;
        dlen = blen;
    }

    if (dlen > (size_t) INT_MAX) {
        free (dec);
        free (raw);
        builtin_error ("input too large");
        return NULL;
    }

    unsigned char *img = stbi_load_from_memory (data, (int) dlen, iw, ih, &ich, 3);
    free (dec);
    free (raw);
    return img;
}

static void
bk_term_size (bk_term *term)
{
    struct winsize ws;

    term->cols = 80;
    term->rows = 24;
    term->xpixels = 0;
    term->ypixels = 0;
    if (ioctl (STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        if (ws.ws_col > 0)
            term->cols = ws.ws_col;
        if (ws.ws_row > 0)
            term->rows = ws.ws_row;
        if (ws.ws_xpixel > 0)
            term->xpixels = ws.ws_xpixel;
        if (ws.ws_ypixel > 0)
            term->ypixels = ws.ws_ypixel;
    }
}

static int
bk_aspect_rows (int cols, int iw, int ih, const bk_term *term)
{
    if (cols < 1)
        cols = 1;
    if (iw < 1 || ih < 1)
        return 1;

    if (term->xpixels > 0 && term->ypixels > 0 &&
        term->cols > 0 && term->rows > 0) {
        double cell_w = (double) term->xpixels / (double) term->cols;
        double cell_h = (double) term->ypixels / (double) term->rows;
        double v = ((double) cols * (double) ih * cell_w) /
                   ((double) iw * cell_h);
        int r;
        if (v <= 1.0)
            return 1;
        if (v > (double) INT_MAX)
            return INT_MAX;
        r = (int) v;
        if ((double) r < v)
            r++;
        return r < 1 ? 1 : r;
    }

    {
        unsigned long long n = (unsigned long long) cols * (unsigned long long) ih;
        unsigned long long d = (unsigned long long) iw * 2ULL;
        unsigned long long r = (n + d - 1ULL) / d;
        if (r < 1)
            r = 1;
        if (r > (unsigned long long) INT_MAX)
            return INT_MAX;
        return (int) r;
    }
}

static unsigned char *
bk_resize (const unsigned char *src, int sw, int sh, int dw, int dh)
{
    unsigned long long px;
    size_t bytes;
    unsigned char *dst;

    if (bk_mul_ull ((unsigned long long) dw, (unsigned long long) dh, &px) != 0 ||
        px > ((unsigned long long) ((size_t) -1) / 3ULL))
        return NULL;
    bytes = (size_t) px * 3U;
    dst = (unsigned char *) malloc (bytes);
    if (!dst)
        return NULL;

    for (int dy = 0; dy < dh; dy++) {
        int sy0 = (int) ((long long) dy * sh / dh);
        int sy1 = (int) ((long long) (dy + 1) * sh / dh);
        if (sy1 <= sy0)
            sy1 = sy0 + 1;
        if (sy1 > sh)
            sy1 = sh;
        for (int dx = 0; dx < dw; dx++) {
            int sx0 = (int) ((long long) dx * sw / dw);
            int sx1 = (int) ((long long) (dx + 1) * sw / dw);
            unsigned long r = 0, g = 0, b = 0, n = 0;
            unsigned char *o;

            if (sx1 <= sx0)
                sx1 = sx0 + 1;
            if (sx1 > sw)
                sx1 = sw;
            for (int sy = sy0; sy < sy1; sy++) {
                for (int sx = sx0; sx < sx1; sx++) {
                    const unsigned char *p = src + ((size_t) sy * sw + sx) * 3U;
                    r += p[0];
                    g += p[1];
                    b += p[2];
                    n++;
                }
            }
            o = dst + ((size_t) dy * dw + dx) * 3U;
            if (n) {
                o[0] = (unsigned char) (r / n);
                o[1] = (unsigned char) (g / n);
                o[2] = (unsigned char) (b / n);
            } else {
                o[0] = o[1] = o[2] = 0;
            }
        }
    }
    return dst;
}

static int
bk_scaled_dims (int sw, int sh, unsigned long long max_pixels, int *dw, int *dh)
{
    unsigned long long px;

    if (sw < 1 || sh < 1 || max_pixels < 1)
        return -1;
    if (bk_mul_ull ((unsigned long long) sw, (unsigned long long) sh, &px) != 0)
        return -1;
    if (sw <= BK_MAX_DIM && sh <= BK_MAX_DIM && px <= max_pixels) {
        *dw = sw;
        *dh = sh;
        return 0;
    }

    int lo = 1, hi = 999999, best = 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        unsigned long long tw = ((unsigned long long) sw * (unsigned long long) mid) / 1000000ULL;
        unsigned long long th = ((unsigned long long) sh * (unsigned long long) mid) / 1000000ULL;
        unsigned long long tpx;

        if (tw < 1)
            tw = 1;
        if (th < 1)
            th = 1;
        if (tw <= BK_MAX_DIM && th <= BK_MAX_DIM &&
            bk_mul_ull (tw, th, &tpx) == 0 && tpx <= max_pixels) {
            best = mid;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }

    {
        unsigned long long tw = ((unsigned long long) sw * (unsigned long long) best) / 1000000ULL;
        unsigned long long th = ((unsigned long long) sh * (unsigned long long) best) / 1000000ULL;
        if (tw < 1)
            tw = 1;
        if (th < 1)
            th = 1;
        if (tw > (unsigned long long) INT_MAX || th > (unsigned long long) INT_MAX)
            return -1;
        *dw = (int) tw;
        *dh = (int) th;
    }
    return 0;
}

static size_t
bk_b64_encode_raw (const unsigned char *in, size_t n, char *out)
{
    static const char alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0, o = 0;

    while (i + 3 <= n) {
        unsigned int v = ((unsigned int) in[i] << 16) |
                         ((unsigned int) in[i + 1] << 8) |
                         (unsigned int) in[i + 2];
        out[o++] = alpha[(v >> 18) & 63U];
        out[o++] = alpha[(v >> 12) & 63U];
        out[o++] = alpha[(v >> 6) & 63U];
        out[o++] = alpha[v & 63U];
        i += 3;
    }
    if (i < n) {
        unsigned int v = (unsigned int) in[i] << 16;
        out[o++] = alpha[(v >> 18) & 63U];
        if (i + 1 < n) {
            v |= (unsigned int) in[i + 1] << 8;
            out[o++] = alpha[(v >> 12) & 63U];
            out[o++] = alpha[(v >> 6) & 63U];
        } else {
            out[o++] = alpha[(v >> 12) & 63U];
        }
    }
    return o;
}

static int
bk_write_b64_chunk (const unsigned char *data, size_t len)
{
    char out[4096];
    size_t n;

    if (len > BK_RAW_CHUNK)
        return -1;
    n = bk_b64_encode_raw (data, len, out);
    if (n > sizeof out)
        return -1;
    return fwrite (out, 1, n, stdout) == n ? 0 : -1;
}

/* APC introducer. Inside tmux, wrap each Kitty APC in tmux's DCS passthrough
   (ESC P tmux ; <inner> ESC \) and double every ESC of the inner sequence so
   tmux forwards it verbatim to the outer Kitty/Ghostty terminal. The base64
   payload has no ESC, so only the framing (this intro + the terminator) needs
   doubling. Requires `set -g allow-passthrough on` in the tmux server. */
static int
bk_apc_intro (const bk_opts *opt)
{
    const char *s = opt->tmux ? BK_ESC "Ptmux;" BK_ESC BK_ESC "_G" : BK_ESC "_G";
    return fputs (s, stdout) == EOF ? -1 : 0;
}

static int
bk_write_apc_end (const bk_opts *opt)
{
    /* Plain ST, or (tmux) doubled inner ST followed by the tmux passthrough ST. */
    const char *s = opt->tmux ? BK_ESC BK_ESC "\\" BK_ESC "\\" : BK_ESC "\\";
    return fputs (s, stdout) == EOF ? -1 : 0;
}

static int
bk_write_first_apc (const bk_opts *opt, int w, int h, int cols, int rows, int chunked)
{
    if (bk_apc_intro (opt) != 0)
        return -1;
    if (printf ("a=T,f=24,t=d,s=%d,v=%d,c=%d,r=%d,q=2",
                w, h, cols, rows) < 0)
        return -1;
    if (opt->have_id && printf (",i=%llu", opt->id) < 0)
        return -1;
    if (opt->have_placement && printf (",p=%llu", opt->placement) < 0)
        return -1;
    if (opt->have_z && printf (",z=%d", opt->z_index) < 0)
        return -1;
    if (opt->static_cursor && fputs (",C=1", stdout) == EOF)
        return -1;
    if (chunked && fputs (",m=1", stdout) == EOF)
        return -1;
    return putchar (';') == EOF ? -1 : 0;
}

static int
bk_write_follow_apc (const bk_opts *opt, int final)
{
    if (bk_apc_intro (opt) != 0)
        return -1;
    return printf ("m=%d,q=2;", final ? 0 : 1) < 0 ? -1 : 0;
}

static int
bk_emit_kitty_rgb (const unsigned char *rgb, int w, int h, int cols, int rows,
                   const bk_opts *opt)
{
    unsigned long long px, bytes64;
    size_t bytes, off = 0;
    int chunked;

    if (w < 1 || h < 1 || cols < 1 || rows < 1)
        return -1;
    if (bk_mul_ull ((unsigned long long) w, (unsigned long long) h, &px) != 0 ||
        px > opt->max_pixels ||
        px > ((unsigned long long) ((size_t) -1) / 3ULL) ||
        bk_mul_ull (px, 3ULL, &bytes64) != 0 ||
        bytes64 > (unsigned long long) ((size_t) -1))
        return -1;
    bytes = (size_t) bytes64;
    chunked = bytes > BK_RAW_CHUNK;

    setvbuf (stdout, NULL, _IOFBF, 1 << 16);
    if (!chunked) {
        if (bk_write_first_apc (opt, w, h, cols, rows, 0) != 0 ||
            bk_write_b64_chunk (rgb, bytes) != 0 ||
            bk_write_apc_end (opt) != 0)
            return -1;
    } else {
        int first = 1;
        while (off < bytes) {
            size_t span = bytes - off;
            int final;
            if (span > BK_RAW_CHUNK)
                span = BK_RAW_CHUNK;
            final = (off + span == bytes);
            if (first) {
                if (bk_write_first_apc (opt, w, h, cols, rows, 1) != 0)
                    return -1;
                first = 0;
            } else if (bk_write_follow_apc (opt, final) != 0) {
                return -1;
            }
            if (bk_write_b64_chunk (rgb + off, span) != 0 ||
                bk_write_apc_end (opt) != 0)
                return -1;
            off += span;
        }
    }
    if (!opt->raw_apc && putchar ('\n') == EOF)
        return -1;
    return fflush (stdout) == 0 && !ferror (stdout) ? 0 : -1;
}

static int
bk_parse_args (WORD_LIST *list, bk_opts *opt)
{
    int end_opts = 0;
    const char *env;

    memset (opt, 0, sizeof *opt);
    opt->max_pixels = BK_DEFAULT_MAX_PIXELS;
    opt->tmux = -1;   /* auto: resolved from $TMUX after parsing */
    env = getenv ("BASHKITTY_MAX_PIXELS");
    if (env && *env && bk_parse_u64 (env, "BASHKITTY_MAX_PIXELS", &opt->max_pixels) != 0)
        return -1;

    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (!end_opts && !strcmp (w, "--")) {
            end_opts = 1;
            continue;
        }
        if (!end_opts && (!strcmp (w, "-h") || !strcmp (w, "--help"))) {
            bk_help ();
            return 1;
        }
        if (!end_opts && (!strcmp (w, "-V") || !strcmp (w, "--version"))) {
            puts ("kitty 1.0 (bash-os Kitty graphics direct RGB emitter)");
            return 1;
        }
        if (!end_opts && !strcmp (w, "--full")) {
            opt->full = 1;
            continue;
        }
        if (!end_opts && !strcmp (w, "--base64")) {
            opt->b64 = 1;
            continue;
        }
        if (!end_opts && !strcmp (w, "--raw-apc")) {
            opt->raw_apc = 1;
            continue;
        }
        if (!end_opts && !strcmp (w, "--static-cursor")) {
            opt->static_cursor = 1;
            continue;
        }
        if (!end_opts && !strcmp (w, "--tmux")) {
            opt->tmux = 1;
            continue;
        }
        if (!end_opts && !strcmp (w, "--no-tmux")) {
            opt->tmux = 0;
            continue;
        }
        if (!end_opts && (!strcmp (w, "-w") || !strcmp (w, "--width"))) {
            if (!p->next) {
                builtin_error ("option requires an argument: %s", w);
                return -1;
            }
            p = p->next;
            if (bk_parse_pos_int (p->word->word, "width", &opt->want_w) != 0)
                return -1;
            continue;
        }
        if (!end_opts && (!strcmp (w, "-H") || !strcmp (w, "--height"))) {
            if (!p->next) {
                builtin_error ("option requires an argument: %s", w);
                return -1;
            }
            p = p->next;
            if (bk_parse_pos_int (p->word->word, "height", &opt->want_h) != 0)
                return -1;
            continue;
        }
        if (!end_opts && !strcmp (w, "--id")) {
            if (!p->next) {
                builtin_error ("option requires an argument: --id");
                return -1;
            }
            p = p->next;
            if (bk_parse_u32 (p->word->word, "id", 1, &opt->id) != 0)
                return -1;
            opt->have_id = 1;
            continue;
        }
        if (!end_opts && !strcmp (w, "--placement")) {
            if (!p->next) {
                builtin_error ("option requires an argument: --placement");
                return -1;
            }
            p = p->next;
            if (bk_parse_u32 (p->word->word, "placement", 0, &opt->placement) != 0)
                return -1;
            opt->have_placement = 1;
            continue;
        }
        if (!end_opts && !strcmp (w, "--z-index")) {
            if (!p->next) {
                builtin_error ("option requires an argument: --z-index");
                return -1;
            }
            p = p->next;
            if (bk_parse_i32 (p->word->word, "z-index", &opt->z_index) != 0)
                return -1;
            opt->have_z = 1;
            continue;
        }
        if (!end_opts && !strcmp (w, "--max-pixels")) {
            if (!p->next) {
                builtin_error ("option requires an argument: --max-pixels");
                return -1;
            }
            p = p->next;
            if (bk_parse_u64 (p->word->word, "max-pixels", &opt->max_pixels) != 0)
                return -1;
            continue;
        }
        if (!end_opts && w[0] == '-' && w[1] && strcmp (w, "-")) {
            builtin_error ("invalid option: %s", w);
            builtin_usage ();
            return -1;
        }
        if (opt->file) {
            builtin_error ("only one FILE allowed");
            return -1;
        }
        opt->file = w;
    }
    if (!opt->file && opt->b64)
        opt->file = "-";
    if (!opt->file) {
        builtin_error ("FILE required (or - for stdin)");
        builtin_usage ();
        return -1;
    }
    if (opt->tmux < 0)              /* auto: wrap when running under tmux */
        opt->tmux = getenv ("TMUX") != NULL;
    return 0;
}

int
kitty_builtin (WORD_LIST *list)
{
    bk_opts opt;
    bk_term term;
    int prc, iw = 0, ih = 0, ow = 0, oh = 0;
    int cols, rows;
    unsigned char *img, *pix;

    prc = bk_parse_args (list, &opt);
    if (prc > 0)
        return EXECUTION_SUCCESS;
    if (prc < 0)
        return EX_USAGE;

    img = bk_load_image (opt.file, opt.b64, &iw, &ih);
    if (!img) {
        builtin_error ("%s: %s", opt.file,
                       stbi_failure_reason () ? stbi_failure_reason () : "decode failed");
        return EXECUTION_FAILURE;
    }
    if (iw < 1 || ih < 1) {
        stbi_image_free (img);
        builtin_error ("invalid image dimensions");
        return EXECUTION_FAILURE;
    }

    if (bk_scaled_dims (iw, ih, opt.max_pixels, &ow, &oh) != 0) {
        stbi_image_free (img);
        builtin_error ("image too large");
        return EXECUTION_FAILURE;
    }
    if (ow != iw || oh != ih) {
        pix = bk_resize (img, iw, ih, ow, oh);
        stbi_image_free (img);
        if (!pix) {
            builtin_error ("out of memory resizing");
            return EXECUTION_FAILURE;
        }
    } else {
        pix = img;
    }

    bk_term_size (&term);
    cols = opt.want_w > 0 ? opt.want_w : (opt.full ? term.cols : (isatty (STDOUT_FILENO) ? term.cols : 80));
    if (cols < 1)
        cols = 1;
    rows = opt.want_h > 0 ? opt.want_h : bk_aspect_rows (cols, ow, oh, &term);
    if (rows < 1)
        rows = 1;

    if (bk_emit_kitty_rgb (pix, ow, oh, cols, rows, &opt) != 0) {
        if (pix == img)
            stbi_image_free (img);
        else
            free (pix);
        builtin_error ("write error");
        return EXECUTION_FAILURE;
    }

    if (pix == img)
        stbi_image_free (img);
    else
        free (pix);
    return EXECUTION_SUCCESS;
}

char *kitty_doc[] = {
    "Display an image using Kitty graphics direct RGB APC output.",
    "",
    "    kitty [OPTION]... FILE",
    "",
    "Decodes FILE (PNG/JPEG/GIF/BMP/TGA; - = stdin) and emits the Kitty",
    "graphics protocol with direct RGB pixel data (a=T,f=24,t=d). Terminals",
    "without Kitty-compatible graphics should use tiv/tiv instead.",
    "",
    "Options:",
    "    -w, --width N       display width in terminal columns",
    "    -H, --height N      display height in terminal rows",
    "        --full          use full terminal width",
    "        --base64        FILE/stdin contains base64-encoded image data",
    "        --id N          Kitty image id",
    "        --placement N   Kitty placement id",
    "        --z-index N     Kitty placement z-index",
    "        --static-cursor emit C=1 so the cursor does not move",
    "        --max-pixels N  maximum emitted pixels before downscale",
    "        --raw-apc       emit only APC commands, no trailing newline",
    "        --tmux          wrap APCs in tmux passthrough (needs allow-passthrough",
    "                        on; auto-enabled when $TMUX is set)",
    "        --no-tmux       never wrap, even under $TMUX",
    "    -h, --help          show this help",
    "    -V, --version       show version",
    (char *) NULL
};

struct builtin kitty_struct = {
    "kitty",
    kitty_builtin,
    BUILTIN_ENABLED,
    kitty_doc,
    "kitty [-w N] [-H N] [--full] [--base64] [--raw-apc] FILE",
    0
};
