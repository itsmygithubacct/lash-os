/* SPDX-License-Identifier: MIT */
/* termpixel — terminal-pixel graphics/runtime substrate (C loadable).
 *
 * A C-native subset of the termpixel_pong Python reference: an RGB pixel
 * canvas rendered with the upper-half-block glyph "\xe2\x96\x80" (U+2580, two
 * vertical pixels per character cell, 24-bit ANSI, run-length batched), simple
 * drawing primitives, a 3x5 bitmap font, raw-tty key input with CSI arrow
 * decoding, and monotonic frame pacing. No Python/pygame/socket/sound/recording.
 *
 * The helper API is declared in termpixel.h so sibling loadables
 * (termpixel_pong.c) reuse the renderer. See
 * research/bash-os/IMPL-PLANS/termpixel/01-termpixel-c-loadable.md.
 */
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <signal.h>
#include <sys/ioctl.h>

#include "termpixel.h"
#include "loadables.h"

#define UHALF "\xe2\x96\x80"            /* U+2580 upper half block */

/* ----------------------------------------------------------------- canvas */

int
btp_canvas_init (btp_canvas *c, int width, int height)
{
    if (!c || width <= 0 || height <= 0) return -1;
    if (height & 1) return -1;          /* height must be even (half-block) */
    c->width = width;
    c->height = height;
    c->rgb = calloc ((size_t) width * height * 3, 1);
    if (!c->rgb) return -1;
    return 0;
}

void
btp_canvas_free (btp_canvas *c)
{
    if (c && c->rgb) { free (c->rgb); c->rgb = NULL; }
}

void
btp_clear (btp_canvas *c, unsigned r, unsigned g, unsigned b)
{
    if (!c || !c->rgb) return;
    size_t n = (size_t) c->width * c->height;
    unsigned char *p = c->rgb;
    for (size_t i = 0; i < n; i++) { *p++ = r; *p++ = g; *p++ = b; }
}

void
btp_set_pixel (btp_canvas *c, int x, int y, unsigned r, unsigned g, unsigned b)
{
    if (!c || !c->rgb || x < 0 || y < 0 || x >= c->width || y >= c->height) return;
    unsigned char *p = c->rgb + ((size_t) y * c->width + x) * 3;
    p[0] = r; p[1] = g; p[2] = b;
}

void
btp_draw_rect (btp_canvas *c, int x, int y, int w, int h,
               unsigned r, unsigned g, unsigned b, int filled)
{
    if (!c || w <= 0 || h <= 0) return;
    if (filled) {
        for (int yy = y; yy < y + h; yy++)
            for (int xx = x; xx < x + w; xx++)
                btp_set_pixel (c, xx, yy, r, g, b);
    } else {
        for (int xx = x; xx < x + w; xx++) {
            btp_set_pixel (c, xx, y, r, g, b);
            btp_set_pixel (c, xx, y + h - 1, r, g, b);
        }
        for (int yy = y; yy < y + h; yy++) {
            btp_set_pixel (c, x, yy, r, g, b);
            btp_set_pixel (c, x + w - 1, yy, r, g, b);
        }
    }
}

void
btp_draw_line (btp_canvas *c, int x0, int y0, int x1, int y1,
               unsigned r, unsigned g, unsigned b)
{
    int dx = abs (x1 - x0), dy = -abs (y1 - y0);
    int sx = x0 < x1 ? 1 : -1, sy = y0 < y1 ? 1 : -1;
    int err = dx + dy;
    for (;;) {
        btp_set_pixel (c, x0, y0, r, g, b);
        if (x0 == x1 && y0 == y1) break;
        int e2 = 2 * err;
        if (e2 >= dy) { err += dy; x0 += sx; }
        if (e2 <= dx) { err += dx; y0 += sy; }
    }
}

void
btp_draw_circle (btp_canvas *c, int cx, int cy, int radius,
                 unsigned r, unsigned g, unsigned b, int filled)
{
    if (radius < 0) return;
    if (filled) {
        for (int yy = -radius; yy <= radius; yy++)
            for (int xx = -radius; xx <= radius; xx++)
                if (xx * xx + yy * yy <= radius * radius)
                    btp_set_pixel (c, cx + xx, cy + yy, r, g, b);
        return;
    }
    int x = radius, y = 0, err = 1 - radius;
    while (x >= y) {
        btp_set_pixel (c, cx + x, cy + y, r, g, b);
        btp_set_pixel (c, cx + y, cy + x, r, g, b);
        btp_set_pixel (c, cx - y, cy + x, r, g, b);
        btp_set_pixel (c, cx - x, cy + y, r, g, b);
        btp_set_pixel (c, cx - x, cy - y, r, g, b);
        btp_set_pixel (c, cx - y, cy - x, r, g, b);
        btp_set_pixel (c, cx + y, cy - x, r, g, b);
        btp_set_pixel (c, cx + x, cy - y, r, g, b);
        y++;
        if (err < 0) err += 2 * y + 1;
        else { x--; err += 2 * (y - x) + 1; }
    }
}

/* ------------------------------------------------------------------- font */
/* 3x5 glyphs, 5 rows x 3 cols, low 3 bits per row (bit2=left .. bit0=right). */
static const unsigned char *
btp_glyph3x5 (char ch)
{
    static const unsigned char blank[5] = { 0, 0, 0, 0, 0 };
    /* digits 0-9 */
    static const unsigned char D[10][5] = {
        {7,5,5,5,7},{2,6,2,2,7},{7,1,7,4,7},{7,1,3,1,7},{5,5,7,1,1},
        {7,4,7,1,7},{7,4,7,5,7},{7,1,2,2,2},{7,5,7,5,7},{7,5,7,1,7} };
    /* A-Z */
    static const unsigned char L[26][5] = {
        {2,5,7,5,5},{6,5,6,5,6},{3,4,4,4,3},{6,5,5,5,6},{7,4,6,4,7}, /*A-E*/
        {7,4,6,4,4},{3,4,5,5,3},{5,5,7,5,5},{7,2,2,2,7},{1,1,1,5,2}, /*F-J*/
        {5,5,6,5,5},{4,4,4,4,7},{5,7,7,5,5},{5,7,7,7,5},{2,5,5,5,2}, /*K-O*/
        {6,5,6,4,4},{2,5,5,7,3},{6,5,6,5,5},{3,4,2,1,6},{7,2,2,2,2}, /*P-T*/
        {5,5,5,5,7},{5,5,5,5,2},{5,5,7,7,5},{5,5,2,5,5},{5,5,2,2,2}, /*U-Y*/
        {7,1,2,4,7} };                                               /*Z*/
    if (ch >= '0' && ch <= '9') return D[ch - '0'];
    if (ch >= 'A' && ch <= 'Z') return L[ch - 'A'];
    if (ch >= 'a' && ch <= 'z') return L[ch - 'a'];
    switch (ch) {
        case ':': { static const unsigned char g[5] = {0,2,0,2,0}; return g; }
        case '-': { static const unsigned char g[5] = {0,0,7,0,0}; return g; }
        case '.': { static const unsigned char g[5] = {0,0,0,0,2}; return g; }
        default:  return blank;
    }
}

void
btp_draw_text3x5 (btp_canvas *c, const char *s, int x, int y,
                  unsigned r, unsigned g, unsigned b)
{
    if (!s) return;
    for (; *s; s++, x += 4) {
        const unsigned char *gl = btp_glyph3x5 (*s);
        for (int row = 0; row < 5; row++)
            for (int col = 0; col < 3; col++)
                if (gl[row] & (4 >> col))
                    btp_set_pixel (c, x + col, y + row, r, g, b);
    }
}

/* ----------------------------------------------------------------- render */
struct sbuf { char *p; size_t len, cap; };
static int
sb_need (struct sbuf *b, size_t extra)
{
    if (b->len + extra + 1 <= b->cap) return 0;
    size_t cap = b->cap ? b->cap * 2 : 4096;
    while (cap < b->len + extra + 1) cap *= 2;
    char *np = realloc (b->p, cap);
    if (!np) return -1;
    b->p = np; b->cap = cap;
    return 0;
}
static int sb_puts (struct sbuf *b, const char *s) {
    size_t n = strlen (s);
    if (sb_need (b, n)) return -1;
    memcpy (b->p + b->len, s, n); b->len += n; return 0;
}
static int sb_fg (struct sbuf *b, int rgb) {
    char e[32]; int n = snprintf (e, sizeof e, "\033[38;2;%d;%d;%dm",
        (rgb >> 16) & 255, (rgb >> 8) & 255, rgb & 255);
    if (sb_need (b, (size_t) n)) return -1;
    memcpy (b->p + b->len, e, n); b->len += n; return 0;
}
static int sb_bg (struct sbuf *b, int rgb) {
    char e[32]; int n = snprintf (e, sizeof e, "\033[48;2;%d;%d;%dm",
        (rgb >> 16) & 255, (rgb >> 8) & 255, rgb & 255);
    if (sb_need (b, (size_t) n)) return -1;
    memcpy (b->p + b->len, e, n); b->len += n; return 0;
}

int
btp_render_ansi_fd (const btp_canvas *c, int fd)
{
    if (!c || !c->rgb || (c->height & 1)) return -1;
    struct sbuf b = { 0 };
    int w = c->width;
    for (int y = 0; y < c->height; y += 2) {
        int cur_fg = -1, cur_bg = -1;     /* reset per row */
        for (int x = 0; x < w; x++) {
            const unsigned char *t = c->rgb + ((size_t) y * w + x) * 3;
            const unsigned char *u = c->rgb + ((size_t) (y + 1) * w + x) * 3;
            int top = (t[0] << 16) | (t[1] << 8) | t[2];
            int bot = (u[0] << 16) | (u[1] << 8) | u[2];
            if (top == bot) {
                /* equal: paint cell background, emit a space (fg irrelevant) */
                if (bot != cur_bg) { if (sb_bg (&b, bot)) goto oom; cur_bg = bot; }
                if (sb_puts (&b, " ")) goto oom;
            } else {
                if (top != cur_fg) { if (sb_fg (&b, top)) goto oom; cur_fg = top; }
                if (bot != cur_bg) { if (sb_bg (&b, bot)) goto oom; cur_bg = bot; }
                if (sb_puts (&b, UHALF)) goto oom;
            }
        }
        if (sb_puts (&b, "\033[0m\n")) goto oom;
    }
    {
        size_t off = 0;
        while (off < b.len) {
            ssize_t w2 = write (fd, b.p + off, b.len - off);
            if (w2 < 0) { if (errno == EINTR) continue; free (b.p); return -1; }
            off += (size_t) w2;
        }
    }
    free (b.p);
    return 0;
oom:
    free (b.p);
    return -1;
}

/* -------------------------------------------------------------- tty/input */
static volatile sig_atomic_t btp_signaled = 0;
static btp_tty_state *btp_active_tty = NULL;
static void btp_sig (int sig) { (void) sig; btp_signaled = 1;
    if (btp_active_tty) btp_tty_restore (btp_active_tty); }

int
btp_tty_enter_raw (btp_tty_state *st, int fd)
{
    if (!st) return -1;
    st->fd = fd; st->active = 0;
    if (!isatty (fd)) return -1;
    if (tcgetattr (fd, &st->saved) < 0) return -1;
    struct termios raw = st->saved;
    raw.c_lflag &= ~(ICANON | ECHO);     /* keep ISIG so Ctrl-C still signals */
    raw.c_iflag &= ~(ICRNL | INLCR);
    raw.c_cc[VMIN] = 0; raw.c_cc[VTIME] = 0;
    if (tcsetattr (fd, TCSANOW, &raw) < 0) return -1;
    st->active = 1;
    btp_active_tty = st;
    btp_signaled = 0;
    signal (SIGINT, btp_sig);
    signal (SIGTERM, btp_sig);
    (void) write (fd, "\033[?25l", 6);    /* hide cursor */
    return 0;
}

int
btp_tty_restore (btp_tty_state *st)
{
    if (!st || !st->active) return 0;
    (void) write (st->fd, "\033[0m\033[?25h", 9);   /* reset color, show cursor */
    tcsetattr (st->fd, TCSANOW, &st->saved);
    st->active = 0;
    if (btp_active_tty == st) btp_active_tty = NULL;
    signal (SIGINT, SIG_DFL);
    signal (SIGTERM, SIG_DFL);
    return 0;
}

static int
btp_poll_byte (int fd, int timeout_ms, unsigned char *out)
{
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int rv = poll (&pfd, 1, timeout_ms);
    if (rv <= 0) return rv;              /* 0 timeout, -1 error */
    ssize_t n = read (fd, out, 1);
    if (n == 0) return -1;               /* EOF */
    if (n < 0) return -1;
    return 1;
}

int
btp_read_key (int fd, int timeout_ms, char *name, size_t name_cap)
{
    if (!name || name_cap < 2) return -1;
    unsigned char ch;
    int rv = btp_poll_byte (fd, timeout_ms, &ch);
    if (rv <= 0) return rv;
    switch (ch) {
        case '\r': case '\n': snprintf (name, name_cap, "ENTER"); return 1;
        case ' ':  snprintf (name, name_cap, "SPACE"); return 1;
        case '\t': snprintf (name, name_cap, "TAB"); return 1;
        case 127: case 8: snprintf (name, name_cap, "BACKSPACE"); return 1;
        case 3:    snprintf (name, name_cap, "CTRL_C"); return 1;
        case 27: {                       /* ESC: maybe a CSI sequence */
            unsigned char b1;
            if (btp_poll_byte (fd, 50, &b1) != 1) { snprintf (name, name_cap, "ESCAPE"); return 1; }
            if (b1 == '[' || b1 == 'O') {
                unsigned char b2;
                if (btp_poll_byte (fd, 50, &b2) != 1) { snprintf (name, name_cap, "ESCAPE"); return 1; }
                switch (b2) {
                    case 'A': snprintf (name, name_cap, "UP_ARROW"); return 1;
                    case 'B': snprintf (name, name_cap, "DOWN_ARROW"); return 1;
                    case 'C': snprintf (name, name_cap, "RIGHT_ARROW"); return 1;
                    case 'D': snprintf (name, name_cap, "LEFT_ARROW"); return 1;
                    default:  snprintf (name, name_cap, "ESCAPE"); return 1;
                }
            }
            snprintf (name, name_cap, "ESCAPE");
            return 1;
        }
        default:
            if (ch >= 32 && ch < 127) { name[0] = (char) ch; name[1] = '\0'; return 1; }
            snprintf (name, name_cap, "KEY_%u", (unsigned) ch);
            return 1;
    }
}

int
btp_sleep_until_monotonic (struct timespec deadline)
{
#ifdef CLOCK_MONOTONIC
    while (clock_nanosleep (CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL) == EINTR)
        ;
    return 0;
#else
    return -1;
#endif
}

/* -------------------------------------------------------------- builtin */
static void
btp_demo_frame (btp_canvas *c, int f)
{
    btp_clear (c, 12, 12, 24);
    int w = c->width, h = c->height;
    int x = (f * 3) % (w > 8 ? w - 8 : 1);
    btp_draw_rect (c, 0, 0, w, h, 60, 60, 90, 0);
    btp_draw_circle (c, x + 4, h / 2, 3, 240, 200, 40, 1);
    btp_draw_line (c, 0, h - 1, w - 1, 0, 80, 200, 120);
    btp_draw_text3x5 (c, "BASHOS", 2, 2, 255, 255, 255);
}

static int
btp_parse_int (const char *s, int *out)
{
    char *end; long v = strtol (s, &end, 10);
    if (*s == '\0' || *end != '\0') return -1;
    *out = (int) v; return 0;
}

int
termpixel_builtin (WORD_LIST *list)
{
    if (!list) { builtin_error ("subcommand required (try --help)"); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *p = list->next;
    int width = 80, height = 80, frames = 60, timeout = -1;

    if (!strcmp (cmd, "--help") || !strcmp (cmd, "-h")) { builtin_usage (); return EXECUTION_SUCCESS; }
    if (!strcmp (cmd, "--version") || !strcmp (cmd, "-V")) { printf ("termpixel 1.0\n"); return EXECUTION_SUCCESS; }

    for (; p; p = p->next) {
        const char *a = p->word->word;
        if ((!strcmp (a, "--width") || !strcmp (a, "-w")) && p->next) { p = p->next; if (btp_parse_int (p->word->word, &width)) { builtin_error ("bad --width"); return EX_USAGE; } }
        else if ((!strcmp (a, "--height") || !strcmp (a, "-H")) && p->next) { p = p->next; if (btp_parse_int (p->word->word, &height)) { builtin_error ("bad --height"); return EX_USAGE; } }
        else if (!strcmp (a, "--frames") && p->next) { p = p->next; if (btp_parse_int (p->word->word, &frames)) { builtin_error ("bad --frames"); return EX_USAGE; } }
        else if (!strcmp (a, "--timeout") && p->next) { p = p->next; if (btp_parse_int (p->word->word, &timeout)) { builtin_error ("bad --timeout"); return EX_USAGE; } }
        else { builtin_error ("unknown option: %s", a); return EX_USAGE; }
    }

    if (!strcmp (cmd, "probe")) {
        struct winsize ws; int have = ioctl (1, TIOCGWINSZ, &ws) == 0;
        const char *ct = getenv ("COLORTERM");
        printf ("cols=%d rows=%d truecolor=%s tty=%s\n",
                have ? ws.ws_col : -1, have ? ws.ws_row : -1,
                (ct && (strstr (ct, "truecolor") || strstr (ct, "24bit"))) ? "yes" : "maybe",
                isatty (0) ? "yes" : "no");
        return EXECUTION_SUCCESS;
    }

    if (!strcmp (cmd, "selftest")) {
        btp_canvas c;
        if (btp_canvas_init (&c, 7, 7) == 0) { btp_canvas_free (&c); builtin_error ("odd height not rejected"); return EXECUTION_FAILURE; }
        if (btp_canvas_init (&c, 16, 16) != 0) { builtin_error ("canvas init failed"); return EXECUTION_FAILURE; }
        btp_clear (&c, 0, 0, 0);
        btp_draw_rect (&c, 1, 1, 6, 6, 255, 0, 0, 1);
        btp_draw_circle (&c, 8, 8, 4, 0, 255, 0, 0);
        btp_draw_line (&c, 0, 0, 15, 15, 0, 0, 255);
        btp_draw_text3x5 (&c, "07", 2, 2, 255, 255, 255);
        int fd = open ("/dev/null", O_WRONLY);
        int rr = btp_render_ansi_fd (&c, fd >= 0 ? fd : 1);
        if (fd >= 0) close (fd);
        btp_canvas_free (&c);
        if (rr != 0) { builtin_error ("render failed"); return EXECUTION_FAILURE; }
        printf ("termpixel selftest OK\n");
        return EXECUTION_SUCCESS;
    }

    if (!strcmp (cmd, "render-demo")) {
        btp_canvas c;
        if (btp_canvas_init (&c, width, height) != 0) { builtin_error ("bad canvas %dx%d (height must be even)", width, height); return EX_USAGE; }
        btp_demo_frame (&c, 0);
        int rr = btp_render_ansi_fd (&c, 1);
        btp_canvas_free (&c);
        return rr == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }

    if (!strcmp (cmd, "demo")) {
        btp_canvas c;
        if (btp_canvas_init (&c, width, height) != 0) { builtin_error ("bad canvas (height must be even)"); return EX_USAGE; }
        struct timespec t; clock_gettime (CLOCK_MONOTONIC, &t);
        for (int f = 0; f < frames && !btp_signaled; f++) {
            btp_demo_frame (&c, f);
            (void) write (1, "\033[H", 3);          /* home */
            if (btp_render_ansi_fd (&c, 1) != 0) break;
            t.tv_nsec += 33333333L;                 /* ~30 fps */
            if (t.tv_nsec >= 1000000000L) { t.tv_nsec -= 1000000000L; t.tv_sec++; }
            btp_sleep_until_monotonic (t);
        }
        btp_canvas_free (&c);
        return EXECUTION_SUCCESS;
    }

    if (!strcmp (cmd, "key-read")) {
        int fd = open ("/dev/tty", O_RDONLY);
        int use = fd >= 0 ? fd : 0;
        btp_tty_state st; int raw = btp_tty_enter_raw (&st, use) == 0;
        char name[32];
        int rv = btp_read_key (use, timeout < 0 ? 1000 : timeout, name, sizeof name);
        if (raw) btp_tty_restore (&st);
        if (fd >= 0) close (fd);
        if (rv == 1) { printf ("%s\n", name); return EXECUTION_SUCCESS; }
        if (rv == 0) { printf ("TIMEOUT\n"); return EXECUTION_SUCCESS; }
        printf ("EOF\n"); return EXECUTION_SUCCESS;
    }

    builtin_error ("unknown subcommand: %s", cmd);
    return EX_USAGE;
}

char *termpixel_doc[] = {
    "Terminal-pixel graphics/runtime substrate (RGB half-block renderer).",
    "",
    "    termpixel SUBCOMMAND [OPTIONS]",
    "",
    "Subcommands:",
    "    selftest               run internal checks, exit 0 on success",
    "    probe                  print terminal size / truecolor / tty status",
    "    render-demo [-w W] [-H H]   render one demo frame (H must be even)",
    "    demo [-w W] [-H H] [--frames N]  bounded animation to stdout",
    "    key-read [--timeout MS]     read one key from /dev/tty (or stdin)",
    "    --help | --version",
    "",
    "Canvas height must be even; output is W x (H/2) cells using the upper",
    "half-block glyph with 24-bit ANSI. The C helper API (termpixel.h) is",
    "reused by sibling game loadables such as termpixel_pong.",
    (char *) NULL
};

struct builtin termpixel_struct = {
    "termpixel",
    termpixel_builtin,
    BUILTIN_ENABLED,
    termpixel_doc,
    "termpixel selftest|probe|render-demo|demo|key-read [options]",
    0
};
