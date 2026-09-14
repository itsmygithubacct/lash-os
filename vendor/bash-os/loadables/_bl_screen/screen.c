/* SPDX-License-Identifier: MIT */
/* _bl_screen/screen.c — implementation of the ncurses-subset screen model.
 * See screen.h for the public contract and design notes. License: MIT. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <signal.h>
#include <poll.h>
#include <sys/ioctl.h>

#include "screen.h"
#include "_bl_key_bl_key.h"

/* ===================================================================== */
/* cell + window model                                                   */
/* ===================================================================== */

typedef struct {
    uint32_t ch;      /* code point (0x20 = blank) */
    uint16_t attr;    /* BLS_A_* */
    int32_t  fg, bg;  /* BLS_DEFAULT / BLS_RGB / BLS_PALETTE */
} cell;

static const cell BLANK = { 0x20, BLS_A_NORMAL, BLS_DEFAULT, BLS_DEFAULT };

struct bls_win {
    int   begy, begx;     /* origin on the physical screen */
    int   h, w;           /* size in cells */
    int   cury, curx;     /* draw cursor within the window */
    unsigned attr;        /* current draw attribute */
    int32_t  fg, bg;      /* current draw color */
    cell *cells;          /* h*w grid (row-major) */
    int   touched;        /* force full re-copy at next refresh */
};

/* ===================================================================== */
/* global screen state                                                   */
/* ===================================================================== */

static struct {
    int    fd;            /* tty fd (read + write) */
    int    own_fd;        /* close on end (opened /dev/tty) */
    pid_t  owner_pid;     /* process that called bls_init (fork guard) */
    int    rows, cols;
    int    active;
    int    color_mode;

    struct termios saved;
    int    saved_valid;

    cell  *newscr;        /* virtual screen (what should appear) */
    cell  *curscr;        /* physical mirror (what is shown) */
    int   *new_first, *new_last;   /* per-line dirty range in newscr (-1 = clean) */

    /* physical cursor + running rendition tracked during doupdate */
    int      pcy, pcx;
    int      pcursor_known;
    unsigned cur_attr;
    int32_t  cur_fg, cur_bg;

    /* output accumulation */
    char  *ob;
    size_t ob_len, ob_cap;

    int    timeout_ms;

    bls_win *stdscr;
} S;

static volatile sig_atomic_t g_winch = 0;

/* ===================================================================== */
/* output buffer                                                         */
/* ===================================================================== */

static void
ob_putn(const char *s, size_t n)
{
    if (S.ob_len + n + 1 > S.ob_cap) {
        size_t nc = S.ob_cap ? S.ob_cap : 8192;
        while (S.ob_len + n + 1 > nc) nc *= 2;
        char *np = (char *) realloc(S.ob, nc);
        if (!np) return;
        S.ob = np; S.ob_cap = nc;
    }
    memcpy(S.ob + S.ob_len, s, n);
    S.ob_len += n;
}

static void ob_puts(const char *s) { ob_putn(s, strlen(s)); }

static void
ob_flush(void)
{
    const char *p = S.ob; size_t left = S.ob_len;
    while (left > 0) {
        ssize_t w = write(S.fd, p, left);
        if (w < 0) { if (errno == EINTR) continue; break; }
        p += w; left -= (size_t) w;
    }
    S.ob_len = 0;
}

/* unbuffered write of a fixed sequence (used by restore paths) */
static void
raw_write(int fd, const char *s)
{
    size_t left = strlen(s); const char *p = s;
    while (left > 0) {
        ssize_t w = write(fd, p, left);
        if (w < 0) { if (errno == EINTR) continue; break; }
        p += w; left -= (size_t) w;
    }
}

/* ===================================================================== */
/* UTF-8                                                                 */
/* ===================================================================== */

/* decode one code point from s (len bytes); returns bytes consumed, sets *cp. */
static int
utf8_decode(const char *s, int len, uint32_t *cp)
{
    unsigned char c = (unsigned char) s[0];
    if (c < 0x80) { *cp = c; return 1; }
    int n; uint32_t v;
    if ((c & 0xE0) == 0xC0) { n = 2; v = c & 0x1F; }
    else if ((c & 0xF0) == 0xE0) { n = 3; v = c & 0x0F; }
    else if ((c & 0xF8) == 0xF0) { n = 4; v = c & 0x07; }
    else { *cp = c; return 1; }              /* invalid lead: pass through */
    if (n > len) { *cp = c; return 1; }
    for (int i = 1; i < n; i++) {
        unsigned char cc = (unsigned char) s[i];
        if ((cc & 0xC0) != 0x80) { *cp = c; return 1; }
        v = (v << 6) | (cc & 0x3F);
    }
    *cp = v; return n;
}

static void
ob_put_cp(uint32_t cp)
{
    char b[4];
    if (cp < 0x80) { b[0] = (char) cp; ob_putn(b, 1); }
    else if (cp < 0x800) {
        b[0] = (char) (0xC0 | (cp >> 6)); b[1] = (char) (0x80 | (cp & 0x3F));
        ob_putn(b, 2);
    } else if (cp < 0x10000) {
        b[0] = (char) (0xE0 | (cp >> 12)); b[1] = (char) (0x80 | ((cp >> 6) & 0x3F));
        b[2] = (char) (0x80 | (cp & 0x3F)); ob_putn(b, 3);
    } else {
        b[0] = (char) (0xF0 | (cp >> 18)); b[1] = (char) (0x80 | ((cp >> 12) & 0x3F));
        b[2] = (char) (0x80 | ((cp >> 6) & 0x3F)); b[3] = (char) (0x80 | (cp & 0x3F));
        ob_putn(b, 4);
    }
}

/* ===================================================================== */
/* color down-conversion                                                 */
/* ===================================================================== */

/* RGB → xterm 256 palette index (6x6x6 cube + grays). */
static int
rgb_to_256(int32_t rgb)
{
    int r = (rgb >> 16) & 0xff, g = (rgb >> 8) & 0xff, b = rgb & 0xff;
    if (r == g && g == b) {                       /* gray ramp */
        if (r < 8) return 16;
        if (r > 248) return 231;
        return 232 + (r - 8) / 10;
    }
    int qr = r * 5 / 255, qg = g * 5 / 255, qb = b * 5 / 255;
    return 16 + 36 * qr + 6 * qg + qb;
}

/* RGB → nearest of the 8 base ANSI colors (0..7); brightness sets bold-bright. */
static int
rgb_to_16(int32_t rgb, int *bright)
{
    int r = (rgb >> 16) & 0xff, g = (rgb >> 8) & 0xff, b = rgb & 0xff;
    int idx = (r > 127 ? 1 : 0) | (g > 127 ? 2 : 0) | (b > 127 ? 4 : 0);
    *bright = (r > 191 || g > 191 || b > 191);
    return idx;
}

/* append the SGR fragment for one color (fg: is_fg=1). No leading ';'. */
static void
sgr_color(char *buf, size_t cap, size_t *len, int is_fg, int32_t color)
{
    char frag[40]; int idx; int bright = 0;
    if (color == BLS_DEFAULT) {
        snprintf(frag, sizeof frag, ";%d", is_fg ? 39 : 49);
    } else if (color >= BLS_PAL_BASE) {
        idx = color - BLS_PAL_BASE;               /* palette index 0..255 */
        if (S.color_mode == BLS_MODE_16 && idx < 16) {
            int base = idx & 7, hi = idx >= 8;
            snprintf(frag, sizeof frag, ";%d", (is_fg ? 30 : 40) + base + (hi ? 60 : 0));
        } else {
            snprintf(frag, sizeof frag, ";%d;5;%d", is_fg ? 38 : 48, idx);
        }
    } else {                                       /* truecolor RGB */
        if (S.color_mode == BLS_MODE_TRUECOLOR) {
            snprintf(frag, sizeof frag, ";%d;2;%d;%d;%d", is_fg ? 38 : 48,
                     (color >> 16) & 0xff, (color >> 8) & 0xff, color & 0xff);
        } else if (S.color_mode == BLS_MODE_256) {
            snprintf(frag, sizeof frag, ";%d;5;%d", is_fg ? 38 : 48, rgb_to_256(color));
        } else {
            idx = rgb_to_16(color, &bright);
            snprintf(frag, sizeof frag, ";%d", (is_fg ? 30 : 40) + idx + (bright ? 60 : 0));
        }
    }
    size_t fl = strlen(frag);
    if (*len + fl < cap) { memcpy(buf + *len, frag, fl); *len += fl; }
}

/* Emit an SGR to transition the running rendition to (attr,fg,bg). Always a
   reset-then-rebuild ("\033[0;...m") — simple and bulletproof; transitions are
   rare relative to cells. Updates S.cur_*. */
static void
set_rendition(unsigned attr, int32_t fg, int32_t bg)
{
    if (attr == S.cur_attr && fg == S.cur_fg && bg == S.cur_bg) return;
    char buf[96]; size_t len = 0;
    memcpy(buf, "\033[0", 3); len = 3;
    if (attr & BLS_A_BOLD)      { memcpy(buf + len, ";1", 2); len += 2; }
    if (attr & BLS_A_DIM)       { memcpy(buf + len, ";2", 2); len += 2; }
    if (attr & BLS_A_ITALIC)    { memcpy(buf + len, ";3", 2); len += 2; }
    if (attr & BLS_A_UNDERLINE) { memcpy(buf + len, ";4", 2); len += 2; }
    if (attr & BLS_A_BLINK)     { memcpy(buf + len, ";5", 2); len += 2; }
    if (attr & BLS_A_REVERSE)   { memcpy(buf + len, ";7", 2); len += 2; }
    sgr_color(buf, sizeof buf, &len, 1, fg);
    sgr_color(buf, sizeof buf, &len, 0, bg);
    buf[len++] = 'm';
    ob_putn(buf, len);
    S.cur_attr = attr; S.cur_fg = fg; S.cur_bg = bg;
}

/* ===================================================================== */
/* cursor                                                                */
/* ===================================================================== */

static void
go_to(int y, int x)
{
    if (S.pcursor_known && y == S.pcy && x == S.pcx) return;
    char b[24];
    if (S.pcursor_known && y == S.pcy) {
        if (x == 0) { ob_puts("\r"); S.pcx = 0; return; }
        if (x == S.pcx + 1) { /* will be advanced by the char itself */ }
    }
    snprintf(b, sizeof b, "\033[%d;%dH", y + 1, x + 1);
    ob_puts(b);
    S.pcy = y; S.pcx = x; S.pcursor_known = 1;
}

/* ===================================================================== */
/* terminal size + signals                                               */
/* ===================================================================== */

static void
query_size(void)
{
    struct winsize ws;
    S.rows = 24; S.cols = 80;
    if (S.fd >= 0 && ioctl(S.fd, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0) {
        S.rows = ws.ws_row; S.cols = ws.ws_col;
    }
}

static void winch_handler(int sig) { (void) sig; g_winch = 1; }

static void
fatal_handler(int sig)
{
    bls_end();
    signal(sig, SIG_DFL);
    raise(sig);
}

/* ===================================================================== */
/* screen (re)allocation                                                 */
/* ===================================================================== */

static int
alloc_screens(void)
{
    size_t n = (size_t) S.rows * (size_t) S.cols;
    cell *a = (cell *) malloc(n * sizeof(cell));
    cell *b = (cell *) malloc(n * sizeof(cell));
    int  *f = (int *) malloc((size_t) S.rows * sizeof(int));
    int  *l = (int *) malloc((size_t) S.rows * sizeof(int));
    if (!a || !b || !f || !l) { free(a); free(b); free(f); free(l); return -1; }
    for (size_t i = 0; i < n; i++) { a[i] = BLANK; b[i] = BLANK; }
    for (int i = 0; i < S.rows; i++) { f[i] = -1; l[i] = -1; }
    S.newscr = a; S.curscr = b; S.new_first = f; S.new_last = l;
    return 0;
}

static void
free_screens(void)
{
    free(S.newscr); free(S.curscr); free(S.new_first); free(S.new_last);
    S.newscr = S.curscr = NULL; S.new_first = S.new_last = NULL;
}

/* Resize: realloc to the new size, blank curscr (physical state unknown after
   a resize), clear the terminal, and mark everything dirty for a full redraw. */
static void
handle_resize(void)
{
    bls_win *std = S.stdscr;
    free_screens();
    query_size();
    if (alloc_screens() != 0) return;
    if (std) {
        cell *nc = (cell *) malloc((size_t) S.rows * S.cols * sizeof(cell));
        if (nc) {
            for (int y = 0; y < S.rows; y++)
                for (int x = 0; x < S.cols; x++)
                    nc[y * S.cols + x] = (y < std->h && x < std->w)
                        ? std->cells[y * std->w + x] : BLANK;
            free(std->cells);
            std->cells = nc; std->h = S.rows; std->w = S.cols;
            std->touched = 1;
        }
    }
    ob_puts("\033[2J");
    S.pcursor_known = 0;
    S.cur_attr = 0xFFFF;   /* force next set_rendition */
}

/* ===================================================================== */
/* lifecycle                                                             */
/* ===================================================================== */

static void
detect_color_mode(void)
{
    const char *ct = getenv("COLORTERM");
    const char *tm = getenv("TERM");
    if (ct && (strstr(ct, "truecolor") || strstr(ct, "24bit"))) { S.color_mode = BLS_MODE_TRUECOLOR; return; }
    if (tm && strstr(tm, "256")) { S.color_mode = BLS_MODE_256; return; }
    if (tm && strcmp(tm, "linux") == 0) { S.color_mode = BLS_MODE_16; return; }
    /* default assumption for modern xterm-class emulators */
    S.color_mode = BLS_MODE_TRUECOLOR;
}

int
bls_init(void)
{
    if (S.active) return 0;
    memset(&S, 0, sizeof S);
    S.timeout_ms = -1;

    if (isatty(STDIN_FILENO)) { S.fd = STDIN_FILENO; S.own_fd = 0; }
    else {
        int fd = open("/dev/tty", O_RDWR);
        if (fd < 0) return -1;
        S.fd = fd; S.own_fd = 1;
    }

    struct termios cur;
    if (tcgetattr(S.fd, &cur) < 0) { if (S.own_fd) close(S.fd); return -1; }
    S.saved = cur; S.saved_valid = 1;
    cur.c_iflag &= (tcflag_t) ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
    cur.c_oflag &= (tcflag_t) ~OPOST;
    cur.c_lflag &= (tcflag_t) ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
    cur.c_cflag &= (tcflag_t) ~(CSIZE|PARENB);
    cur.c_cflag |= CS8;
    cur.c_cc[VMIN] = 1; cur.c_cc[VTIME] = 0;
    if (tcsetattr(S.fd, TCSANOW, &cur) < 0) { if (S.own_fd) close(S.fd); return -1; }

    detect_color_mode();
    query_size();
    if (alloc_screens() != 0) { tcsetattr(S.fd, TCSANOW, &S.saved); if (S.own_fd) close(S.fd); return -1; }

    S.stdscr = bls_newwin(S.rows, S.cols, 0, 0);
    if (!S.stdscr) { free_screens(); tcsetattr(S.fd, TCSANOW, &S.saved); if (S.own_fd) close(S.fd); return -1; }

    bl_key_reset();
    S.cur_attr = 0xFFFF; S.pcursor_known = 0;
    S.owner_pid = getpid();
    S.active = 1;

    /* alt screen + hide cursor + home + clear */
    ob_puts("\033[?1049h\033[?25l\033[H\033[2J");
    ob_flush();

    signal(SIGWINCH, winch_handler);
    signal(SIGTERM, fatal_handler);
    signal(SIGHUP,  fatal_handler);
    atexit(bls_end);
    return 0;
}

void
bls_end(void)
{
    if (!S.active) return;
    /* A command-substitution / pipeline subshell is a fork that inherits the
       active screen; when it exits, its atexit(bls_end) must NOT reset the
       terminal or it would drop the parent out of raw/alt-screen mid-session.
       Only the process that called bls_init() owns teardown. */
    if (S.owner_pid && getpid() != S.owner_pid) return;
    S.active = 0;
    /* leave alt screen, show cursor, reset rendition — unbuffered, signal-safe */
    raw_write(S.fd, "\033[0m\033[?25h\033[?1049l");
    if (S.saved_valid) tcsetattr(S.fd, TCSANOW, &S.saved);
    bls_delwin(S.stdscr); S.stdscr = NULL;
    free_screens();
    free(S.ob); S.ob = NULL; S.ob_cap = S.ob_len = 0;
    if (S.own_fd && S.fd >= 0) close(S.fd);
    S.fd = -1;
}

int bls_lines(void) { return S.rows; }
int bls_cols(void)  { return S.cols; }
int bls_tty_fd(void){ return S.fd; }
int bls_color_mode(void) { return S.color_mode; }
void bls_set_color_mode(int m) { if (m >= BLS_MODE_16 && m <= BLS_MODE_TRUECOLOR) S.color_mode = m; }

int
bls_resized(void)
{
    if (g_winch) { g_winch = 0; return 1; }
    return 0;
}

/* ===================================================================== */
/* windows + drawing                                                     */
/* ===================================================================== */

bls_win *bls_stdscr(void) { return S.stdscr; }

bls_win *
bls_newwin(int h, int w, int y, int x)
{
    if (h <= 0 || w <= 0) return NULL;
    bls_win *win = (bls_win *) calloc(1, sizeof *win);
    if (!win) return NULL;
    win->cells = (cell *) malloc((size_t) h * w * sizeof(cell));
    if (!win->cells) { free(win); return NULL; }
    for (int i = 0; i < h * w; i++) win->cells[i] = BLANK;
    win->begy = y; win->begx = x; win->h = h; win->w = w;
    win->fg = BLS_DEFAULT; win->bg = BLS_DEFAULT;
    win->touched = 1;
    return win;
}

void
bls_delwin(bls_win *win)
{
    if (!win) return;
    free(win->cells);
    free(win);
}

static cell *
cell_at(bls_win *w, int y, int x)
{
    if (y < 0 || x < 0 || y >= w->h || x >= w->w) return NULL;
    return &w->cells[y * w->w + x];
}

void
bls_erase(bls_win *w)
{
    if (!w) return;
    for (int i = 0; i < w->h * w->w; i++) w->cells[i] = BLANK;
    w->cury = w->curx = 0;
    w->touched = 1;
}

void bls_move(bls_win *w, int y, int x) { if (w) { w->cury = y; w->curx = x; } }

void bls_attron(bls_win *w, unsigned a)  { if (w) w->attr |= a; }
void bls_attroff(bls_win *w, unsigned a) { if (w) w->attr &= ~a; }
void bls_attrset(bls_win *w, unsigned a) { if (w) w->attr = a; }
void bls_setfg(bls_win *w, int32_t c)    { if (w) w->fg = c; }
void bls_setbg(bls_win *w, int32_t c)    { if (w) w->bg = c; }

static void
put_cp(bls_win *w, uint32_t cp)
{
    if (cp == '\n') { w->cury++; w->curx = 0; return; }
    if (cp == '\r') { w->curx = 0; return; }
    if (cp == '\t') { int n = 8 - (w->curx % 8); while (n-- > 0) put_cp(w, ' '); return; }
    cell *c = cell_at(w, w->cury, w->curx);
    if (c) { c->ch = cp; c->attr = (uint16_t) w->attr; c->fg = w->fg; c->bg = w->bg; }
    w->curx++;
    if (w->curx >= w->w) { w->curx = 0; w->cury++; }
}

void bls_addch(bls_win *w, uint32_t cp) { if (w) put_cp(w, cp); }

void
bls_addnstr(bls_win *w, const char *s, int n)
{
    if (!w || !s) return;
    int len = (int) strlen(s);
    int limit = (n < 0 || n > len) ? len : n;
    int i = 0;
    while (i < limit) {
        uint32_t cp;
        int used = utf8_decode(s + i, limit - i, &cp);
        put_cp(w, cp);
        i += used;
    }
}

void bls_addstr(bls_win *w, const char *s) { bls_addnstr(w, s, -1); }

/* Apply one SGR parameter list (the numbers between ESC[ and 'm') to w. */
static void
apply_sgr(bls_win *w, const int *p, int np)
{
    if (np == 0) { w->attr = BLS_A_NORMAL; w->fg = BLS_DEFAULT; w->bg = BLS_DEFAULT; return; }
    for (int i = 0; i < np; i++) {
        int v = p[i];
        switch (v) {
            case 0:  w->attr = BLS_A_NORMAL; w->fg = BLS_DEFAULT; w->bg = BLS_DEFAULT; break;
            case 1:  w->attr |= BLS_A_BOLD; break;
            case 2:  w->attr |= BLS_A_DIM; break;
            case 3:  w->attr |= BLS_A_ITALIC; break;
            case 4:  w->attr |= BLS_A_UNDERLINE; break;
            case 5: case 6: w->attr |= BLS_A_BLINK; break;
            case 7:  w->attr |= BLS_A_REVERSE; break;
            case 21: case 22: w->attr &= ~(BLS_A_BOLD | BLS_A_DIM); break;
            case 23: w->attr &= ~BLS_A_ITALIC; break;
            case 24: w->attr &= ~BLS_A_UNDERLINE; break;
            case 25: w->attr &= ~BLS_A_BLINK; break;
            case 27: w->attr &= ~BLS_A_REVERSE; break;
            case 39: w->fg = BLS_DEFAULT; break;
            case 49: w->bg = BLS_DEFAULT; break;
            case 38: case 48: {
                int is_fg = (v == 38);
                if (i + 1 < np && p[i + 1] == 5 && i + 2 < np) {
                    int idx = p[i + 2]; i += 2;
                    if (is_fg) w->fg = BLS_PALETTE(idx); else w->bg = BLS_PALETTE(idx);
                } else if (i + 1 < np && p[i + 1] == 2 && i + 4 < np) {
                    int32_t c = BLS_RGB(p[i + 2], p[i + 3], p[i + 4]); i += 4;
                    if (is_fg) w->fg = c; else w->bg = c;
                }
                break;
            }
            default:
                if (v >= 30 && v <= 37)        w->fg = BLS_PALETTE(v - 30);
                else if (v >= 90 && v <= 97)   w->fg = BLS_PALETTE(v - 90 + 8);
                else if (v >= 40 && v <= 47)   w->bg = BLS_PALETTE(v - 40);
                else if (v >= 100 && v <= 107) w->bg = BLS_PALETTE(v - 100 + 8);
                break;
        }
    }
}

void
bls_addstr_ansi(bls_win *w, const char *s, int n)
{
    if (!w || !s) return;
    int len = (n < 0) ? (int) strlen(s) : n;
    w->attr = BLS_A_NORMAL; w->fg = BLS_DEFAULT; w->bg = BLS_DEFAULT;
    int i = 0;
    while (i < len) {
        unsigned char c = (unsigned char) s[i];
        if (c == 0x1b) {                       /* escape */
            if (i + 1 < len && s[i + 1] == '[') {
                int j = i + 2, params[32], np = 0, cur = 0, seen = 0;
                while (j < len) {
                    unsigned char d = (unsigned char) s[j];
                    if (d >= '0' && d <= '9') { cur = cur * 10 + (d - '0'); seen = 1; j++; }
                    else if (d == ';') { if (np < 32) params[np++] = cur; cur = 0; seen = 1; j++; }
                    else break;
                }
                if (seen && np < 32) params[np++] = cur;
                if (j < len && s[j] == 'm') apply_sgr(w, params, np);  /* SGR only */
                i = (j < len) ? j + 1 : len;   /* consume the whole CSI */
            } else if (i + 1 < len) {
                i += 2;                         /* two-char escape: ignore */
            } else {
                i += 1;
            }
            continue;
        }
        if (c == '\t') { put_cp(w, '\t'); i++; continue; }
        if (c < 0x20 || c == 0x7f) {           /* C0 / DEL → caret notation */
            put_cp(w, '^');
            put_cp(w, (uint32_t) (c == 0x7f ? '?' : (c ^ 0x40)));
            i++; continue;
        }
        uint32_t cp; int used = utf8_decode(s + i, len - i, &cp);
        put_cp(w, cp); i += used;
    }
}

void
bls_mvaddstr(bls_win *w, int y, int x, const char *s)
{
    if (!w) return;
    w->cury = y; w->curx = x;
    bls_addstr(w, s);
}

int
bls_printw(bls_win *w, const char *fmt, ...)
{
    if (!w) return -1;
    char buf[2048];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    bls_addstr(w, buf);
    return n;
}

void
bls_hline(bls_win *w, uint32_t cp, int n)
{
    if (!w) return;
    if (cp == 0) cp = 0x2500;        /* ─ */
    int y = w->cury, x = w->curx;
    for (int i = 0; i < n; i++) {
        cell *c = cell_at(w, y, x + i);
        if (c) { c->ch = cp; c->attr = (uint16_t) w->attr; c->fg = w->fg; c->bg = w->bg; }
    }
}

void
bls_vline(bls_win *w, uint32_t cp, int n)
{
    if (!w) return;
    if (cp == 0) cp = 0x2502;        /* │ */
    int y = w->cury, x = w->curx;
    for (int i = 0; i < n; i++) {
        cell *c = cell_at(w, y + i, x);
        if (c) { c->ch = cp; c->attr = (uint16_t) w->attr; c->fg = w->fg; c->bg = w->bg; }
    }
}

void
bls_box(bls_win *w, uint32_t verch, uint32_t horch)
{
    if (!w) return;
    uint32_t v = verch ? verch : 0x2502;   /* │ */
    uint32_t hz = horch ? horch : 0x2500;  /* ─ */
    int h = w->h, ww = w->w;
    for (int x = 1; x < ww - 1; x++) {
        cell *t = cell_at(w, 0, x), *b = cell_at(w, h - 1, x);
        if (t) { t->ch = hz; t->attr = (uint16_t) w->attr; t->fg = w->fg; t->bg = w->bg; }
        if (b) { b->ch = hz; b->attr = (uint16_t) w->attr; b->fg = w->fg; b->bg = w->bg; }
    }
    for (int y = 1; y < h - 1; y++) {
        cell *l = cell_at(w, y, 0), *r = cell_at(w, y, ww - 1);
        if (l) { l->ch = v; l->attr = (uint16_t) w->attr; l->fg = w->fg; l->bg = w->bg; }
        if (r) { r->ch = v; r->attr = (uint16_t) w->attr; r->fg = w->fg; r->bg = w->bg; }
    }
    uint32_t corners[4] = { 0x250C, 0x2510, 0x2514, 0x2518 };  /* ┌┐└┘ */
    int cy[4] = { 0, 0, h - 1, h - 1 }, cx[4] = { 0, ww - 1, 0, ww - 1 };
    for (int i = 0; i < 4; i++) {
        cell *c = cell_at(w, cy[i], cx[i]);
        if (c) { c->ch = corners[i]; c->attr = (uint16_t) w->attr; c->fg = w->fg; c->bg = w->bg; }
    }
}

void
bls_clrtoeol(bls_win *w)
{
    if (!w) return;
    for (int x = w->curx; x < w->w; x++) {
        cell *c = cell_at(w, w->cury, x);
        if (c) *c = BLANK;
    }
}

void
bls_clrtobot(bls_win *w)
{
    if (!w) return;
    bls_clrtoeol(w);
    for (int y = w->cury + 1; y < w->h; y++)
        for (int x = 0; x < w->w; x++) {
            cell *c = cell_at(w, y, x);
            if (c) *c = BLANK;
        }
}

void bls_touchwin(bls_win *w) { if (w) w->touched = 1; }

/* ===================================================================== */
/* refresh: wnoutrefresh (window → newscr) + doupdate (diff → terminal)  */
/* ===================================================================== */

static int
cell_eq(const cell *a, const cell *b)
{
    return a->ch == b->ch && a->attr == b->attr && a->fg == b->fg && a->bg == b->bg;
}

static int
is_blank(const cell *c)
{
    return c->ch == 0x20 && c->attr == BLS_A_NORMAL
        && c->fg == BLS_DEFAULT && c->bg == BLS_DEFAULT;
}

/* copy a window's cells into newscr at its origin, marking the dirty range. */
static void
wnoutrefresh(bls_win *w)
{
    for (int y = 0; y < w->h; y++) {
        int sy = w->begy + y;
        if (sy < 0 || sy >= S.rows) continue;
        int dirty_lo = -1, dirty_hi = -1;
        for (int x = 0; x < w->w; x++) {
            int sx = w->begx + x;
            if (sx < 0 || sx >= S.cols) continue;
            cell *dst = &S.newscr[sy * S.cols + sx];
            cell *src = &w->cells[y * w->w + x];
            if (w->touched || !cell_eq(dst, src)) {
                *dst = *src;
                if (dirty_lo < 0) dirty_lo = sx;
                dirty_hi = sx;
            }
        }
        if (dirty_lo >= 0) {
            if (S.new_first[sy] < 0 || dirty_lo < S.new_first[sy]) S.new_first[sy] = dirty_lo;
            if (dirty_hi > S.new_last[sy]) S.new_last[sy] = dirty_hi;
        }
    }
    w->touched = 0;
}

/* TransformLine: emit the minimal output to make curscr line == newscr line. */
static void
transform_line(int y)
{
    cell *nl = &S.newscr[y * S.cols];
    cell *ol = &S.curscr[y * S.cols];

    int first = -1, last = -1;
    for (int x = 0; x < S.cols; x++)
        if (!cell_eq(&nl[x], &ol[x])) { if (first < 0) first = x; last = x; }
    if (first < 0) return;                 /* nothing actually changed */

    /* clr_eol optimization: if newscr[c..cols-1] is all blank-default for some
       c <= last, stop emitting at c-1 and clear to EOL instead of spaces. */
    int blank_from = S.cols;
    { int k = S.cols - 1; while (k >= 0 && is_blank(&nl[k])) k--; blank_from = k + 1; }
    int emit_to = last;
    int use_clr = 0;
    if (blank_from <= last && (last - blank_from + 1) >= 4) {
        emit_to = blank_from - 1;
        use_clr = 1;
    }

    go_to(y, first);
    for (int x = first; x <= emit_to; x++) {
        set_rendition(nl[x].attr, nl[x].fg, nl[x].bg);
        ob_put_cp(nl[x].ch);
        ol[x] = nl[x];
        S.pcx = x + 1;                     /* char auto-advances the cursor */
    }
    if (use_clr) {
        set_rendition(BLS_A_NORMAL, BLS_DEFAULT, BLS_DEFAULT);  /* clr_eol uses current bg */
        ob_puts("\033[K");
        for (int x = blank_from; x < S.cols; x++) ol[x] = BLANK;
    }
}

void
bls_refresh(bls_win *w)
{
    if (!S.active || !w) return;

    if (g_winch) { g_winch = 0; handle_resize(); }

    wnoutrefresh(w);

    int nonempty = S.rows;
    for (int y = 0; y < nonempty; y++) {
        if (S.new_first[y] >= 0) {
            transform_line(y);
            S.new_first[y] = -1; S.new_last[y] = -1;
        }
    }

    /* park the cursor at the window's logical cursor; reset rendition. */
    set_rendition(BLS_A_NORMAL, BLS_DEFAULT, BLS_DEFAULT);
    int cy = w->begy + w->cury, cx = w->begx + w->curx;
    if (cy >= 0 && cy < S.rows && cx >= 0 && cx < S.cols) go_to(cy, cx);

    ob_flush();
}

/* ===================================================================== */
/* input                                                                 */
/* ===================================================================== */

void bls_timeout(int ms) { S.timeout_ms = ms; }

int
bls_getch(void)
{
    if (S.fd < 0) return BLS_KEY_NONE;
    /* Always poll (timeout_ms = -1 blocks indefinitely) so a SIGWINCH-
       interrupted wait surfaces as BLS_ERR and the caller redraws at the
       fresh size, rather than getting swallowed inside a blocking read(). */
    struct pollfd pfd = { S.fd, POLLIN, 0 };
    int pr = poll(&pfd, 1, S.timeout_ms);
    if (pr < 0) return BLS_ERR;            /* EINTR (e.g. resize) */
    if (pr == 0) return BLS_ERR;           /* timeout */
    return bl_read_key(S.fd);
}

int
bls_getnstr(bls_win *w, int y, int x, const char *prompt, char *buf, int n)
{
    if (!S.active || !w || n < 1) return -1;
    int plen = prompt ? (int) strlen(prompt) : 0;
    int len = 0;
    buf[0] = '\0';
    raw_write(S.fd, "\033[?25h");           /* show cursor while editing */
    for (;;) {
        bls_attrset(w, BLS_A_NORMAL);
        bls_setfg(w, BLS_DEFAULT); bls_setbg(w, BLS_DEFAULT);
        if (prompt) bls_mvaddstr(w, y, x, prompt);
        bls_mvaddstr(w, y, x + plen, buf);
        bls_move(w, y, x + plen + len);
        bls_clrtoeol(w);
        bls_refresh(w);

        int k = bl_read_key(S.fd);
        if (k == BL_KEY_NONE) { len = -1; break; }
        if (k == '\r' || k == '\n' || k == BL_KEY_RET) break;
        if (k == BL_KEY_ESC || k == 0x03) { len = -1; break; }
        if (k == BL_KEY_BS || k == 0x7f || k == 0x08) {
            if (len > 0) { len--; buf[len] = '\0'; }
            continue;
        }
        if (k >= 0x20 && k < 0x7f && len < n - 1) {
            buf[len++] = (char) k; buf[len] = '\0';
        }
    }
    raw_write(S.fd, "\033[?25l");           /* hide cursor again */
    if (len < 0) buf[0] = '\0';
    return len;
}
