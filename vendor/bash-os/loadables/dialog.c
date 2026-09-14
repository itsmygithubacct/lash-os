/* SPDX-License-Identifier: MIT */
/* dialog.c — dialog(1) / whiptail(1) widget surface for bash-os
 *
 * In-process widget set built on termraw's ANSI primitives. Provides
 * the minimum dialog/whiptail command-line surface that interactive
 * runbooks reach for:
 *
 *   dialog --yesno      TEXT HEIGHT WIDTH
 *   dialog --msgbox     TEXT HEIGHT WIDTH
 *   dialog --infobox    TEXT HEIGHT WIDTH
 *   dialog --inputbox   TEXT HEIGHT WIDTH [INIT]
 *   dialog --passwordbox TEXT HEIGHT WIDTH [INIT]
 *   dialog --menu       TEXT HEIGHT WIDTH MENU_HEIGHT TAG ITEM [TAG ITEM …]
 *   dialog --inputmenu  TEXT HEIGHT WIDTH MENU_HEIGHT TAG ITEM [TAG ITEM …]
 *   dialog --checklist  TEXT HEIGHT WIDTH MENU_HEIGHT TAG ITEM STATUS [TAG ITEM STATUS …]
 *   dialog --radiolist  TEXT HEIGHT WIDTH MENU_HEIGHT TAG ITEM STATUS [TAG ITEM STATUS …]
 *   dialog --treeview   TEXT HEIGHT WIDTH MENU_HEIGHT TAG ITEM STATUS DEPTH [...]
 *   dialog --form       TEXT HEIGHT WIDTH FORM_HEIGHT LABEL Y X ITEM Y X FLEN ILEN [...]
 *   dialog --mixedform  TEXT HEIGHT WIDTH FORM_HEIGHT LABEL Y X ITEM Y X FLEN ILEN ITYPE [...]
 *   dialog --gauge      TEXT HEIGHT WIDTH [INIT_PCT]
 *   dialog --pause      TEXT HEIGHT WIDTH SECONDS
 *   dialog --textbox    FILE HEIGHT WIDTH
 *   dialog --tailbox    FILE HEIGHT WIDTH
 *
 * Optional leading flags (parsed before the widget switch):
 *   --title TITLE   — window title rendered at top of box
 *   --backtitle T   — background banner (rendered when interactive)
 *   --no-cancel     — suppress Cancel button on input widgets
 *   --defaultno     — yes/no default is No
 *   --separate-output — checklist output: one tag per line (default = quoted)
 *   --stdout        — write result strings to stdout instead of stderr
 *   --output-fd N   — write result strings to an already-open fd N
 *   --ok-label / --cancel-label / --yes-label / --no-label TEXT
 *   --default-item TAG / --default-button NAME / --notags
 *
 * Exit codes follow dialog(1) convention:
 *   0   OK / Yes selected
 *   1   No / Cancel selected
 *   255 ESC pressed (interactive only)
 *
 * Result strings (input value, menu tag/text, checklist list) are written
 * to stderr by default so they don't get tangled up in the on-screen
 * rendering when the caller does
 * `result=$(dialog --inputbox ... 2>&1 >/dev/tty)`.  --stdout and
 * --output-fd N flip only that result channel; rendering still goes to
 * /dev/tty or stderr.
 *
 * Operating modes:
 *   - Interactive (TTY available): use termraw-style raw termios +
 *     ANSI cursor positioning to render boxes; read keypresses from
 *     /dev/tty; honor arrow-keys, Enter, Tab, Esc, space; --inputmenu
 *     additionally accepts r/R to rename the current item.
 *   - Non-interactive (no /dev/tty, OR stdin is a pipe): render-only
 *     to stderr (banner + box body), then consume input tokens from
 *     stdin. --yesno reads first byte ('y'/'Y' → 0, else 1). --menu /
 *     --inputmenu / --radiolist reads a whitespace-delimited tag from stdin and
 *     emits it to stderr; --inputmenu also accepts a deterministic
 *     `RENAMED TAG NEW_TEXT` line and emits that rename record after
 *     validating TAG. --checklist reads tags one per line until
 *     EOF and emits them space-separated (or one-per-line under
 *     --separate-output). --inputbox / --passwordbox read one line.
 *     --form is the type-0 editable subset of --mixedform. --mixedform
 *     accepts ITYPE 0 normal, 1 hidden/password, 2 readonly; it reads one line
 *     per editable field and emits final values one per line; readonly fields
 *     keep their initial value and consume no input.
 *     The interactive --inputbox / --passwordbox path and --mixedform path
 *     support cursor movement, printable insertion, Backspace/Delete deletion,
 *     horizontal viewporting, and password masking. --mixedform additionally
 *     supports Tab/Up/Down navigation and readonly skip.
 *     --gauge consumes "NN%\n" or bare "NN\n" lines until EOF.
 *     --treeview behaves like a radiolist with an extra DEPTH column.
 *     --pause waits SECONDS, or returns immediately when SECONDS is 0.
 *     --textbox renders a file body and consumes one acknowledgement token;
 *     --tailbox renders current file content and returns.
 *
 * The non-interactive path is what makes the test suite tractable:
 * `printf 'y\n' | dialog --yesno foo 5 30` is a deterministic
 * input/output pair with no termios state to mock.
 *
 * --- LICENSE ---
 * MIT License
 *
 * Copyright (c) 2026 bash_linux contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software. See the
 * full MIT text for the standard disclaimer.
 *
 * When statically linked into GNU Bash the combined binary is governed
 * by GPL-3+ (bash's license); MIT is GPL-3+-compatible.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <limits.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <poll.h>

#include "loadables.h"

/* Shared CSI/SS3 key decoder (the inline ESC/CSI parser body was lifted
 * to scripts/loadables/_bl_key/bl_key.{c,h} in 2026-05-18 so less /
 * more / nano / vi / top / dialog / whiptail / screen can share one
 * arrow/PgUp/PgDn/Home/End/Delete parser). bd_keypress() now delegates
 * to bl_read_key() and maps BL_KEY_* back to the legacy string
 * vocabulary used at the existing call sites. */
#include "_bl_key_bl_key.h"

/* ----------------------------------------------------------------------
 * Option block — populated by leading --title / --backtitle / etc. flags
 * before the widget switch dispatches on --yesno / --msgbox / ...
 * ---------------------------------------------------------------------- */
typedef struct {
    const char *title;          /* --title TEXT, NULL if unset */
    const char *backtitle;      /* --backtitle TEXT, NULL if unset */
    int         no_cancel;      /* --no-cancel: suppress Cancel button */
    int         default_no;     /* --defaultno: yes/no default = No */
    int         separate_out;   /* --separate-output: checklist one-per-line */
    int         out_fd;         /* result channel, default STDERR_FILENO */
    const char *ok_label;       /* --ok-label TEXT */
    const char *cancel_label;   /* --cancel-label TEXT */
    const char *yes_label;      /* --yes-label TEXT */
    const char *no_label;       /* --no-label TEXT */
    const char *default_item;   /* --default-item TAG */
    const char *default_button; /* --default-button ok|cancel|yes|no|extra */
    int         notags;         /* --notags: emit/display item text */
} bd_opts;

/* ----------------------------------------------------------------------
 * I/O helpers
 *
 * Render to /dev/tty when available, else stderr. dialog(1) writes its
 * boxes to stderr by default so result strings on stdout stay clean —
 * we do the same. Tty fd is separate from the result-output fd so a
 * --inputbox result can be cleanly captured via 2>&1 >/dev/tty.
 * ---------------------------------------------------------------------- */
static int   bd_tty_fd       = -1;
static int   bd_tty_should_close = 0;
static int   bd_interactive  = 0;
static int   bd_no_terminal  = 0;  /* set if no tty AND stderr isn't one either */

static void
bd_open_tty(void)
{
    if (!isatty(STDIN_FILENO)) {
        bd_tty_fd = STDERR_FILENO;
        bd_tty_should_close = 0;
        bd_interactive = 0;
        bd_no_terminal = !isatty(STDERR_FILENO);
        return;
    }

    int fd = open("/dev/tty", O_RDWR | O_NOCTTY);
    if (fd >= 0) {
        bd_tty_fd = fd;
        bd_tty_should_close = 1;
        bd_interactive = isatty(fd);
        bd_no_terminal = 0;
        return;
    }
    if (isatty(STDIN_FILENO) && isatty(STDERR_FILENO)) {
        bd_tty_fd = STDERR_FILENO;
        bd_tty_should_close = 0;
        bd_interactive = 1;
        bd_no_terminal = 0;
        return;
    }
    bd_tty_fd = STDERR_FILENO;
    bd_tty_should_close = 0;
    bd_interactive = 0;
    bd_no_terminal = !isatty(STDERR_FILENO);
}

static void
bd_close_tty(void)
{
    if (bd_tty_should_close && bd_tty_fd >= 0) close(bd_tty_fd);
    bd_tty_fd = -1;
    bd_tty_should_close = 0;
}

/* Write a buffer to the render fd. Loops over EINTR / short writes. */
static void
bd_render(const char *buf, size_t len)
{
    if (bd_no_terminal) return;   /* nothing usable to render to */
    if (bd_tty_fd < 0) return;
    while (len > 0) {
        ssize_t w = write(bd_tty_fd, buf, len);
        if (w < 0) {
            if (errno == EINTR) continue;
            return;
        }
        buf += w;
        len -= (size_t) w;
    }
}

static void
bd_render_s(const char *s) { bd_render(s, strlen(s)); }

/* Write a result record to the selected output fd. This is deliberately
 * separate from bd_render(): --stdout / --output-fd must not move the visual
 * render channel away from /dev/tty or stderr. */
static void
bd_write_fd(int fd, const char *buf, size_t len)
{
    if (fd < 0 || !buf) return;
    while (len > 0) {
        ssize_t w = write(fd, buf, len);
        if (w < 0) {
            if (errno == EINTR) continue;
            return;
        }
        if (w == 0) return;
        buf += w;
        len -= (size_t) w;
    }
}

static void
bd_emit(const bd_opts *o, const char *s)
{
    int fd = o ? o->out_fd : STDERR_FILENO;
    if (!s) s = "";
    bd_write_fd(fd, s, strlen(s));
}

static void
bd_emit_ch(const bd_opts *o, char c)
{
    int fd = o ? o->out_fd : STDERR_FILENO;
    bd_write_fd(fd, &c, 1);
}

static void
bd_emit_line(const bd_opts *o, const char *s)
{
    bd_emit(o, s);
    bd_emit_ch(o, '\n');
}

static const char *
bd_label_or(const char *label, const char *fallback)
{
    return (label && *label) ? label : fallback;
}

static const char *
bd_menu_result(const bd_opts *o, const char *tag, const char *item)
{
    return (o && o->notags) ? item : tag;
}

static int
bd_default_yesno_is_no(const bd_opts *o)
{
    if (o && o->default_button && *o->default_button) {
        if (!strcmp(o->default_button, "no")
            || !strcmp(o->default_button, "cancel")
            || !strcmp(o->default_button, "extra"))
            return 1;
        if (!strcmp(o->default_button, "yes")
            || !strcmp(o->default_button, "ok"))
            return 0;
    }
    return o && o->default_no;
}

static int
bd_valid_default_button(const char *s)
{
    return s
        && (!strcmp(s, "ok") || !strcmp(s, "cancel")
            || !strcmp(s, "yes") || !strcmp(s, "no")
            || !strcmp(s, "extra"));
}

static int
bd_parse_fd_arg(const char *s, int *out)
{
    long v = 0;
    if (!s || !*s) return -1;
    for (const unsigned char *p = (const unsigned char *) s; *p; p++) {
        if (!isdigit(*p)) return -1;
        v = v * 10 + (*p - '0');
        if (v > INT_MAX) return -1;
    }
    *out = (int) v;
    return 0;
}

static void
bd_render_button(const char *label, int selected)
{
    char buf[256];
    snprintf(buf, sizeof buf, selected ? "[<%.220s>]" : " <%.220s> ", label);
    bd_render_s(buf);
}

/* ----------------------------------------------------------------------
 * Termios save/restore (interactive widgets). The shared dialog widgets
 * all need raw-mode reads for keypress handling but must restore cooked
 * mode before returning. We save once per invocation and restore in the
 * widget tail. SIGINT handling: dialog(1) treats Ctrl-C as Cancel; we
 * follow suit by trapping SIGINT to restore termios + exit 1.
 * ---------------------------------------------------------------------- */
static struct termios bd_saved_termios;
static int            bd_saved_valid = 0;

static int
bd_enter_raw(void)
{
    if (!bd_interactive || bd_tty_fd < 0) return 0;
    if (tcgetattr(bd_tty_fd, &bd_saved_termios) < 0) return -1;
    bd_saved_valid = 1;
    struct termios raw = bd_saved_termios;
    raw.c_iflag &= (tcflag_t) ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR
                                | IGNCR | ICRNL | IXON);
    raw.c_oflag &= (tcflag_t) ~(OPOST);
    raw.c_lflag &= (tcflag_t) ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    raw.c_cflag &= (tcflag_t) ~(CSIZE | PARENB);
    raw.c_cflag |= CS8;
    raw.c_cc[VMIN]  = 1;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(bd_tty_fd, TCSANOW, &raw) < 0) return -1;
    return 0;
}

static void
bd_leave_raw(void)
{
    if (!bd_saved_valid || bd_tty_fd < 0) return;
    tcsetattr(bd_tty_fd, TCSANOW, &bd_saved_termios);
    bd_saved_valid = 0;
}

/* Decode one logical keypress. Returns the same name vocabulary as
 * bashtermraw_keypress: UP / DOWN / LEFT / RIGHT / RET / TAB / ESC /
 * SPACE / BS / HOME / END / PGUP / PGDN / DEL / INS / F1..F4 /
 * printable ASCII / "?" for unrecognized.
 *
 * v2 (2026-05-18): the raw CSI/SS3 parser body moved to the shared
 * _bl_key helper. This wrapper maps BL_KEY_* back to the legacy
 * string names the dialog widgets dispatch on. Coverage extended
 * beyond the legacy parser (which only handled arrows) to include
 * Home / End / PgUp / PgDn / Del / Ins / F1..F4 so future widgets
 * can opt in without re-touching the decoder. */
static const char *
bd_keypress(void)
{
    static char buf[16];
    if (bd_tty_fd < 0) return "?";
    int k = bl_read_key(bd_tty_fd);
    switch (k) {
        case BL_KEY_NONE:  return "?";
        case BL_KEY_ESC:   return "ESC";
        case BL_KEY_UP:    return "UP";
        case BL_KEY_DOWN:  return "DOWN";
        case BL_KEY_LEFT:  return "LEFT";
        case BL_KEY_RIGHT: return "RIGHT";
        case BL_KEY_HOME:  return "HOME";
        case BL_KEY_END:   return "END";
        case BL_KEY_BS:    return "BS";
        case BL_KEY_RET:   return "RET";
        case BL_KEY_DEL:   return "DEL";
        case BL_KEY_PGUP:  return "PGUP";
        case BL_KEY_PGDN:  return "PGDN";
        case BL_KEY_INS:   return "INS";
        case BL_KEY_TAB:   return "TAB";
        case BL_KEY_F1:    return "F1";
        case BL_KEY_F2:    return "F2";
        case BL_KEY_F3:    return "F3";
        case BL_KEY_F4:    return "F4";
        default: break;
    }
    if (k == 0x20) return "SPACE";
    if (k >= 0x20 && k < 0x7f) {
        buf[0] = (char) k;
        buf[1] = '\0';
        return buf;
    }
    return "?";
}

/* ----------------------------------------------------------------------
 * Box-drawing helpers. Geometry: the caller passes HEIGHT/WIDTH; we
 * center inside the current terminal. Falls back to a small default
 * geometry when winsize is unavailable.
 * ---------------------------------------------------------------------- */
typedef struct {
    int rows, cols;
    int top,  left;
    int h,    w;
} bd_box;

static void
bd_term_size(int *rows, int *cols)
{
    struct winsize ws;
    if (bd_tty_fd >= 0 && ioctl(bd_tty_fd, TIOCGWINSZ, &ws) == 0
        && ws.ws_row > 0 && ws.ws_col > 0) {
        *rows = ws.ws_row;
        *cols = ws.ws_col;
        return;
    }
    *rows = 24;
    *cols = 80;
}

static void
bd_layout(bd_box *b, int h, int w)
{
    bd_term_size(&b->rows, &b->cols);
    if (h <= 0) h = 8;
    if (w <= 0) w = 40;
    if (h > b->rows - 2) h = b->rows - 2;
    if (w > b->cols - 2) w = b->cols - 2;
    b->h    = h;
    b->w    = w;
    b->top  = (b->rows - h) / 2 + 1;
    b->left = (b->cols - w) / 2 + 1;
}

/* Emit CSI cup ROW;COL H. */
static void
bd_cup(int row, int col)
{
    char seq[32];
    if (row < 1) row = 1;
    if (col < 1) col = 1;
    snprintf(seq, sizeof seq, "\033[%d;%dH", row, col);
    bd_render_s(seq);
}

static void
bd_clear_screen(void) { bd_render_s("\033[2J\033[H"); }

static void
bd_draw_backtitle(const bd_opts *o)
{
    if (!bd_interactive || !o || !o->backtitle || !*o->backtitle) return;
    int rows, cols;
    bd_term_size(&rows, &cols);
    (void) rows;
    int n = (int) strlen(o->backtitle);
    if (n > cols) n = cols;
    bd_cup(1, 1);
    bd_render(o->backtitle, (size_t) n);
}

/* Draw the box frame using ASCII (portable across utf8/non-utf8 locales
 * and any vt-100 compatible terminal). dialog uses BOX_DRAWING ACS chars
 * by default but ASCII renders correctly everywhere. */
static void
bd_draw_frame(const bd_box *b, const char *title)
{
    if (!bd_interactive) return;
    /* Top */
    bd_cup(b->top, b->left);
    bd_render_s("+");
    for (int i = 0; i < b->w - 2; i++) bd_render_s("-");
    bd_render_s("+");
    /* Sides + interior fill (spaces, so any prior screen content under
     * the box is wiped). */
    for (int r = 1; r < b->h - 1; r++) {
        bd_cup(b->top + r, b->left);
        bd_render_s("|");
        for (int c = 0; c < b->w - 2; c++) bd_render_s(" ");
        bd_render_s("|");
    }
    /* Bottom */
    bd_cup(b->top + b->h - 1, b->left);
    bd_render_s("+");
    for (int i = 0; i < b->w - 2; i++) bd_render_s("-");
    bd_render_s("+");
    /* Title in the top border. */
    if (title && *title) {
        int tlen = (int) strlen(title);
        if (tlen > b->w - 4) tlen = b->w - 4;
        int tcol = b->left + (b->w - tlen - 2) / 2;
        bd_cup(b->top, tcol);
        bd_render_s(" ");
        bd_render(title, (size_t) tlen);
        bd_render_s(" ");
    }
}

/* Render TEXT inside the box, line-wrapping on spaces at width-4. */
static void
bd_draw_text(const bd_box *b, const char *text)
{
    if (!bd_interactive) return;
    int max_w = b->w - 4;
    if (max_w < 1) return;
    int row = b->top + 1;
    int max_row = b->top + b->h - 3;
    const char *p = text;
    while (*p && row <= max_row) {
        int n = 0;
        const char *line = p;
        while (line[n] && line[n] != '\n' && n < max_w) n++;
        if (line[n] && line[n] != '\n' && n == max_w) {
            int back = n;
            while (back > 0 && line[back] != ' ') back--;
            if (back > 0) n = back;
        }
        bd_cup(row, b->left + 2);
        bd_render(line, (size_t) n);
        row++;
        p = line + n;
        while (*p == ' ') p++;
        if (*p == '\n') p++;
    }
}

/* ----------------------------------------------------------------------
 * Stdin helpers for non-interactive mode.
 * ---------------------------------------------------------------------- */
static int
bd_read_line(char *buf, size_t cap)
{
    size_t i = 0;
    while (i + 1 < cap) {
        char c;
        ssize_t n = read(STDIN_FILENO, &c, 1);
        if (n <= 0) break;
        if (c == '\n') break;
        buf[i++] = c;
    }
    buf[i] = '\0';
    return (int) i;
}

/* ----------------------------------------------------------------------
 * Widget implementations
 * ---------------------------------------------------------------------- */

static int
bd_widget_yesno(const bd_opts *o, const char *text, int h, int w)
{
    if (!bd_interactive) {
        char line[64];
        int n = bd_read_line(line, sizeof line);
        if (n == 0 && line[0] == '\0')
            return bd_default_yesno_is_no(o) ? 1 : 0;
        if (line[0] == 'y' || line[0] == 'Y') return 0;
        return 1;
    }
    bd_box b;
    bd_layout(&b, h, w);
    bd_clear_screen();
    bd_draw_backtitle(o);
    bd_draw_frame(&b, o->title ? o->title : "Question");
    bd_draw_text(&b, text);

    /* Two buttons on the last interior row. */
    int btn_row = b.top + b.h - 2;
    const char *yes_label = bd_label_or(o ? o->yes_label : NULL, "Yes");
    const char *no_label  = bd_label_or(o ? o->no_label : NULL, "No");
    int yes_w = (int) strlen(yes_label) + 4;
    int no_w  = (int) strlen(no_label) + 4;
    int total_w = yes_w + no_w + 2;
    int yes_col = b.left + (b.w - total_w) / 2;
    if (yes_col < b.left + 2) yes_col = b.left + 2;
    int no_col = yes_col + yes_w + 2;
    int sel = bd_default_yesno_is_no(o) ? 1 : 0;
    if (bd_enter_raw() < 0) {
        bd_leave_raw();
        return 1;
    }
    for (;;) {
        bd_cup(btn_row, yes_col);
        bd_render_button(yes_label, sel == 0);
        bd_cup(btn_row, no_col);
        bd_render_button(no_label, sel == 1);
        const char *k = bd_keypress();
        if (!strcmp(k, "RET")) {
            bd_leave_raw();
            bd_clear_screen();
            return sel == 0 ? 0 : 1;
        }
        if (!strcmp(k, "ESC")) {
            bd_leave_raw();
            bd_clear_screen();
            return 255;
        }
        if (!strcmp(k, "TAB") || !strcmp(k, "LEFT") || !strcmp(k, "RIGHT")) {
            sel = 1 - sel;
            continue;
        }
        if (!strcmp(k, "y") || !strcmp(k, "Y")) {
            bd_leave_raw(); bd_clear_screen(); return 0;
        }
        if (!strcmp(k, "n") || !strcmp(k, "N")) {
            bd_leave_raw(); bd_clear_screen(); return 1;
        }
    }
}

static int
bd_widget_msgbox(const bd_opts *o, const char *text, int h, int w, int is_info)
{
    if (!bd_interactive) {
        /* msgbox waits for input; infobox does not. */
        if (!is_info) {
            char line[8];
            bd_read_line(line, sizeof line);
        }
        return 0;
    }
    bd_box b;
    bd_layout(&b, h, w);
    bd_clear_screen();
    bd_draw_backtitle(o);
    bd_draw_frame(&b, o->title ? o->title : (is_info ? "Info" : "Message"));
    bd_draw_text(&b, text);
    if (is_info) return 0;

    int btn_row = b.top + b.h - 2;
    const char *ok_label = bd_label_or(o ? o->ok_label : NULL, "OK");
    int ok_w = (int) strlen(ok_label) + 4;
    bd_cup(btn_row, b.left + (b.w - ok_w) / 2);
    bd_render_button(ok_label, 1);
    if (bd_enter_raw() < 0) { bd_leave_raw(); return 0; }
    for (;;) {
        const char *k = bd_keypress();
        if (!strcmp(k, "RET") || !strcmp(k, "SPACE")) {
            bd_leave_raw(); bd_clear_screen(); return 0;
        }
        if (!strcmp(k, "ESC")) {
            bd_leave_raw(); bd_clear_screen(); return 255;
        }
    }
}

static int
bd_widget_inputbox(const bd_opts *o, const char *text, int h, int w,
                   const char *init, int is_password)
{
    if (!bd_interactive) {
        char line[1024];
        bd_read_line(line, sizeof line);
        /* Result string goes to the selected dialog result channel. */
        bd_emit_line(o, line);
        return 0;
    }
    bd_box b;
    bd_layout(&b, h, w);
    bd_clear_screen();
    bd_draw_backtitle(o);
    bd_draw_frame(&b, o->title ? o->title : (is_password ? "Password" : "Input"));
    bd_draw_text(&b, text);

    char buf[1024];
    size_t bl = 0;
    size_t cur = 0;
    if (init) {
        strncpy(buf, init, sizeof buf - 1);
        buf[sizeof buf - 1] = '\0';
        bl = strlen(buf);
    } else {
        buf[0] = '\0';
    }
    cur = bl;
    int input_row = b.top + b.h - 3;
    if (bd_enter_raw() < 0) { bd_leave_raw(); return 1; }
    for (;;) {
        if (cur > bl) cur = bl;
        int field_w = b.w - 4;
        if (field_w < 0) field_w = 0;
        size_t start = 0;
        if (field_w > 0) {
            if (cur >= (size_t) field_w)
                start = cur - (size_t) field_w + 1;
            if (start + (size_t) field_w > bl && bl > (size_t) field_w)
                start = bl - (size_t) field_w;
        }
        size_t end = bl;
        if (field_w > 0 && end > start + (size_t) field_w)
            end = start + (size_t) field_w;
        bd_cup(input_row, b.left + 2);
        for (int i = 0; i < b.w - 4; i++) bd_render_s(" ");
        bd_cup(input_row, b.left + 2);
        if (is_password) {
            for (size_t i = start; i < end; i++) bd_render_s("*");
        } else {
            bd_render(buf + start, end - start);
        }
        size_t visible = cur > start ? cur - start : 0;
        if (field_w > 0 && visible >= (size_t) field_w)
            visible = (size_t) field_w - 1;
        bd_cup(input_row, b.left + 2 + (int) visible);
        const char *k = bd_keypress();
        if (!strcmp(k, "RET")) {
            bd_leave_raw();
            bd_clear_screen();
            bd_emit_line(o, buf);
            return 0;
        }
        if (!strcmp(k, "ESC")) {
            bd_leave_raw(); bd_clear_screen(); return 255;
        }
        if (!strcmp(k, "LEFT")) {
            if (cur > 0) cur--;
            continue;
        }
        if (!strcmp(k, "RIGHT")) {
            if (cur < bl) cur++;
            continue;
        }
        if (!strcmp(k, "HOME")) {
            cur = 0;
            continue;
        }
        if (!strcmp(k, "END")) {
            cur = bl;
            continue;
        }
        if (!strcmp(k, "BS")) {
            if (cur > 0) {
                memmove(buf + cur - 1, buf + cur, bl - cur + 1);
                cur--;
                bl--;
            }
            continue;
        }
        if (!strcmp(k, "DEL")) {
            if (cur < bl) {
                memmove(buf + cur, buf + cur + 1, bl - cur);
                bl--;
            }
            continue;
        }
        if (!strcmp(k, "SPACE")) {
            if (bl + 1 >= sizeof buf) continue;
            memmove(buf + cur + 1, buf + cur, bl - cur + 1);
            buf[cur++] = ' ';
            bl++;
            continue;
        }
        if (strlen(k) == 1 && k[0] >= 0x20 && k[0] < 0x7f && bl + 1 < sizeof buf) {
            memmove(buf + cur + 1, buf + cur, bl - cur + 1);
            buf[cur++] = k[0];
            bl++;
        }
    }
}

/* Shared menu/inputmenu/checklist/radiolist/treeview body.
 * Mode: 0=menu (single, exit on Enter); 1=checklist (multi, space toggles,
 * Enter commits); 2=radiolist (single, space picks, Enter commits);
 * 3=treeview (radiolist plus per-row indentation depth);
 * 4=inputmenu (menu selection plus pipe-driven or interactive Rename
 * contract).
 * items_per_row: 2 for menu/inputmenu (TAG ITEM),
 * 3 for checklist/radiolist (TAG ITEM STATUS).
 *
 * Non-interactive contract:
 *   menu/inputmenu — read one tag from stdin, emit to the result channel
 *               inputmenu also accepts: RENAMED TAG NEW_TEXT
 *   radiolist/treeview — same as menu (single selection)
 *   checklist — read tags one-per-line from stdin until EOF, emit result list
 *               separated by spaces, OR one-per-line under --separate-output
 */
static int
bd_widget_menu_like(const bd_opts *o, const char *text, int h, int w,
                    int menu_h, WORD_LIST *items, int mode)
{
    int items_per_row = (mode == 0 || mode == 4) ? 2 : (mode == 3 ? 4 : 3);
    /* Count items. */
    int nrows = 0;
    WORD_LIST *p = items;
    while (p) { nrows++; p = p->next; }
    nrows /= items_per_row;
    if (nrows <= 0) {
        builtin_error("menu: no items supplied");
        return 1;
    }

    /* Collect into flat arrays for indexed access. */
    const char **tags = malloc(sizeof(char *) * (size_t) nrows);
    const char **itext = malloc(sizeof(char *) * (size_t) nrows);
    int         *picked = calloc((size_t) nrows, sizeof(int));
    int         *depths = calloc((size_t) nrows, sizeof(int));
    if (!tags || !itext || !picked || !depths) {
        free(tags); free(itext); free(picked); free(depths);
        return 1;
    }
    p = items;
    for (int i = 0; i < nrows; i++) {
        tags[i]  = p->word->word; p = p->next;
        itext[i] = p->word->word; p = p->next;
        if (items_per_row == 3) {
            const char *st = p->word->word;
            picked[i] = (!strcmp(st, "on") || !strcmp(st, "ON") || !strcmp(st, "1"));
            p = p->next;
        } else if (items_per_row == 4) {
            const char *st = p->word->word;
            picked[i] = (!strcmp(st, "on") || !strcmp(st, "ON") || !strcmp(st, "1"));
            p = p->next;
            depths[i] = atoi(p->word->word);
            if (depths[i] < 0) depths[i] = 0;
            if (depths[i] > 32) depths[i] = 32;
            p = p->next;
        }
    }
    int default_idx = -1;
    if (o && o->default_item && *o->default_item) {
        for (int i = 0; i < nrows; i++) {
            if (!strcmp(o->default_item, tags[i])) {
                default_idx = i;
                break;
            }
        }
    }

    int rc = 0;
    if (!bd_interactive) {
        if (mode == 1) {
            /* Checklist: read lines until EOF, mark matching tags. */
            char line[256];
            int  marked = 0;
            for (;;) {
                int n = bd_read_line(line, sizeof line);
                if (n == 0) {
                    /* EOF after zero bytes — done. Distinguish from a
                     * blank line followed by more data: bd_read_line
                     * returns 0 on EOF AND on blank line; we use a
                     * short read on stdin pipe as terminator. */
                    char probe;
                    ssize_t pn = read(STDIN_FILENO, &probe, 1);
                    if (pn <= 0) break;
                    /* Put it back into our processing loop. */
                    line[0] = probe;
                    n = 1;
                    if (probe != '\n') {
                        int extra = bd_read_line(line + 1, sizeof line - 1);
                        n += extra;
                    }
                    if (n == 0) break;
                }
                if (n == 0) break;
                for (int i = 0; i < nrows; i++) {
                    if (!strcmp(line, tags[i])) { picked[i] = 1; marked++; break; }
                }
            }
            int any_picked = 0;
            for (int i = 0; i < nrows; i++) {
                if (picked[i]) { any_picked = 1; break; }
            }
            if (!any_picked && marked == 0 && default_idx >= 0)
                picked[default_idx] = 1;
            /* Emit picked entries to the selected result channel. */
            int first = 1;
            for (int i = 0; i < nrows; i++) {
                if (!picked[i]) continue;
                const char *res = bd_menu_result(o, tags[i], itext[i]);
                if (o->separate_out) {
                    bd_emit_line(o, res);
                } else {
                    if (!first) bd_emit_ch(o, ' ');
                    bd_emit(o, res);
                    first = 0;
                }
            }
            if (!o->separate_out && !first) bd_emit_ch(o, '\n');
            (void) marked;
        } else {
            /* Menu / inputmenu / radiolist: read one result line. */
            char line[256];
            int n = bd_read_line(line, sizeof line);
            (void) n;
            /* Trim trailing whitespace. */
            size_t L = strlen(line);
            while (L > 0 && (line[L-1] == ' ' || line[L-1] == '\t' || line[L-1] == '\r')) {
                line[--L] = '\0';
            }

            if (mode == 4 && !strncmp(line, "RENAMED", 7)
                && (line[7] == ' ' || line[7] == '\t')) {
                char *tag = line + 8;
                while (*tag == ' ' || *tag == '\t') tag++;
                char *new_text = tag;
                while (*new_text && *new_text != ' ' && *new_text != '\t') new_text++;
                if (*new_text) {
                    *new_text++ = '\0';
                    while (*new_text == ' ' || *new_text == '\t') new_text++;
                }
                int found = -1;
                for (int i = 0; i < nrows; i++) {
                    if (!strcmp(tag, tags[i])) { found = i; break; }
                }
                if (found < 0 || !*tag) {
                    rc = 1;
                } else {
                    bd_emit(o, "RENAMED ");
                    bd_emit(o, tags[found]);
                    bd_emit_ch(o, ' ');
                    bd_emit_line(o, new_text);
                    rc = 0;
                }
                free(tags); free(itext); free(picked); free(depths);
                return rc;
            }

            int found = -1;
            if (line[0] == '\0' && default_idx >= 0) {
                found = default_idx;
            } else {
                for (int i = 0; i < nrows; i++) {
                    if (!strcmp(line, tags[i])) { found = i; break; }
                }
            }
            if (found < 0) {
                /* No match: dialog returns 1 (Cancel). */
                rc = 1;
            } else {
                bd_emit_line(o, bd_menu_result(o, tags[found], itext[found]));
                rc = 0;
            }
        }
        free(tags); free(itext); free(picked); free(depths);
        return rc;
    }

    /* --- Interactive path --------------------------------------------- */
    bd_box b;
    bd_layout(&b, h, w);
    int viewport = menu_h;
    if (viewport <= 0 || viewport > b.h - 6) viewport = b.h - 6;
    if (viewport > nrows) viewport = nrows;

    int cur = default_idx >= 0 ? default_idx : 0, top = 0;
    bd_clear_screen();
    bd_draw_backtitle(o);
    bd_draw_frame(&b, o->title ? o->title : "Menu");
    bd_draw_text(&b, text);
    if (bd_enter_raw() < 0) {
        bd_leave_raw();
        free(tags); free(itext); free(picked); free(depths);
        return 1;
    }
    for (;;) {
        for (int v = 0; v < viewport; v++) {
            int idx = top + v;
            bd_cup(b.top + 3 + v, b.left + 2);
            for (int c = 0; c < b.w - 4; c++) bd_render_s(" ");
            if (idx >= nrows) continue;
            bd_cup(b.top + 3 + v, b.left + 2);
            if (idx == cur) bd_render_s("> ");
            else            bd_render_s("  ");
            if (items_per_row == 3 || items_per_row == 4) {
                bd_render_s(picked[idx] ? "[*] " : "[ ] ");
            }
            if (items_per_row == 4) {
                for (int d = 0; d < depths[idx]; d++)
                    bd_render_s("  ");
            }
            if (!o->notags) {
                bd_render_s(tags[idx]);
                bd_render_s("  ");
            }
            bd_render_s(itext[idx]);
        }
        const char *k = bd_keypress();
        if (!strcmp(k, "UP")) {
            if (cur > 0) cur--;
            if (cur < top) top = cur;
        } else if (!strcmp(k, "DOWN")) {
            if (cur < nrows - 1) cur++;
            if (cur >= top + viewport) top = cur - viewport + 1;
        } else if (!strcmp(k, "SPACE")) {
            if (mode == 1) picked[cur] = !picked[cur];
            else if (mode == 2 || mode == 3) {
                for (int i = 0; i < nrows; i++) picked[i] = 0;
                picked[cur] = 1;
            }
        } else if (mode == 4 && (!strcmp(k, "r") || !strcmp(k, "R"))) {
            char renamed[1024];
            size_t rlen = 0;
            renamed[0] = '\0';
            int input_row = b.top + b.h - 3;
            int input_col = b.left + 2;
            for (int c = 0; c < b.w - 4; c++) {
                bd_cup(input_row, input_col + c);
                bd_render_s(" ");
            }
            bd_cup(input_row, input_col);
            bd_render_s("Rename: ");
            for (;;) {
                const char *rk = bd_keypress();
                if (!strcmp(rk, "RET")) {
                    bd_leave_raw(); bd_clear_screen();
                    bd_emit(o, "RENAMED ");
                    bd_emit(o, tags[cur]);
                    bd_emit_ch(o, ' ');
                    bd_emit_line(o, renamed);
                    free(tags); free(itext); free(picked); free(depths);
                    return 0;
                }
                if (!strcmp(rk, "ESC")) {
                    bd_leave_raw(); bd_clear_screen();
                    free(tags); free(itext); free(picked); free(depths);
                    return 255;
                }
                if (!strcmp(rk, "BS")) {
                    if (rlen > 0) {
                        rlen--;
                        renamed[rlen] = '\0';
                    }
                } else if (!strcmp(rk, "SPACE") && rlen + 1 < sizeof renamed) {
                    renamed[rlen++] = ' ';
                    renamed[rlen] = '\0';
                } else if (strlen(rk) == 1 && rk[0] >= 0x20 && rk[0] < 0x7f
                           && rlen + 1 < sizeof renamed) {
                    renamed[rlen++] = rk[0];
                    renamed[rlen] = '\0';
                }
                for (int c = 0; c < b.w - 12; c++) {
                    bd_cup(input_row, input_col + 8 + c);
                    bd_render_s(" ");
                }
                bd_cup(input_row, input_col + 8);
                bd_render_s(renamed);
            }
        } else if (!strcmp(k, "RET")) {
            bd_leave_raw(); bd_clear_screen();
            if (mode == 0 || mode == 4) {
                bd_emit_line(o, bd_menu_result(o, tags[cur], itext[cur]));
            } else if (mode == 1) {
                int first = 1;
                for (int i = 0; i < nrows; i++) {
                    if (!picked[i]) continue;
                    const char *res = bd_menu_result(o, tags[i], itext[i]);
                    if (o->separate_out) {
                        bd_emit_line(o, res);
                    } else {
                        if (!first) bd_emit_ch(o, ' ');
                        bd_emit(o, res); first = 0;
                    }
                }
                if (!o->separate_out && !first) bd_emit_ch(o, '\n');
            } else {
                /* radiolist */
                for (int i = 0; i < nrows; i++) {
                    if (picked[i]) {
                        bd_emit_line(o, bd_menu_result(o, tags[i], itext[i]));
                        break;
                    }
                }
            }
            free(tags); free(itext); free(picked); free(depths);
            return 0;
        } else if (!strcmp(k, "ESC")) {
            bd_leave_raw(); bd_clear_screen();
            free(tags); free(itext); free(picked); free(depths);
            return 255;
        }
    }
}

/* Form field tuples:
 *   --form      LABEL Y X ITEM Y X FLEN ILEN
 *   --mixedform LABEL Y X ITEM Y X FLEN ILEN ITYPE
 *
 * The deterministic non-interactive contract is intentionally stronger
 * than the current interactive one: --form reads one line for each field;
 * --mixedform reads one line for each editable field (itype 0 normal, 1
 * hidden/password), keeps readonly fields (itype 2), and emits all final field
 * values one per line. Unsupported ITYPE values are rejected instead of being
 * treated as editable fields. The interactive path renders the form, lets the
 * user edit ITYPE 0/1 fields, skips readonly fields during navigation, and
 * returns final values on Enter.
 */
static int
bd_widget_form_like(const bd_opts *o, const char *text, int h, int w,
                    int form_h, WORD_LIST *fields, int mixed)
{
    (void) form_h;
    const int tuple_words = mixed ? 9 : 8;
    const char *widget_name = mixed ? "mixedform" : "form";
    int nwords = 0;
    WORD_LIST *p = fields;
    while (p) { nwords++; p = p->next; }
    if (nwords <= 0 || nwords % tuple_words != 0) {
        if (mixed)
            builtin_error("mixedform: field tuples must be LABEL Y X ITEM Y X FLEN ILEN ITYPE");
        else
            builtin_error("form: field tuples must be LABEL Y X ITEM Y X FLEN ILEN");
        return 2;
    }

    int nrows = nwords / tuple_words;
    const char **labels = malloc(sizeof(char *) * (size_t) nrows);
    char       **values = calloc((size_t) nrows, sizeof(char *));
    int         *types  = calloc((size_t) nrows, sizeof(int));
    int         *flens  = calloc((size_t) nrows, sizeof(int));
    int         *ilens  = calloc((size_t) nrows, sizeof(int));
    size_t      *curs   = calloc((size_t) nrows, sizeof(size_t));
    if (!labels || !values || !types || !flens || !ilens || !curs) {
        free(labels); free(values); free(types); free(flens); free(ilens); free(curs);
        return 1;
    }

    p = fields;
    for (int i = 0; i < nrows; i++) {
        labels[i] = p->word->word; p = p->next; /* label */
        p = p->next;                            /* label y */
        p = p->next;                            /* label x */
        values[i] = strdup(p->word->word); p = p->next; /* item */
        p = p->next;                            /* item y */
        p = p->next;                            /* item x */
        flens[i] = atoi(p->word->word); p = p->next; /* field len */
        ilens[i] = atoi(p->word->word); p = p->next; /* input len */
        if (mixed) {
            types[i] = atoi(p->word->word); p = p->next;
        } else {
            types[i] = 0;
        }
        if (!values[i]) {
            for (int j = 0; j < i; j++) free(values[j]);
            free(labels); free(values); free(types); free(flens); free(ilens); free(curs);
            return 1;
        }
        curs[i] = strlen(values[i]);
        if (flens[i] < 1) flens[i] = 1;
        if (ilens[i] < 0) ilens[i] = 0;
        if (types[i] < 0 || types[i] > 2) {
            builtin_error("%s: unsupported field type %d (want 0, 1, or 2)",
                          widget_name, types[i]);
            for (int j = 0; j <= i; j++) free(values[j]);
            free(labels); free(values); free(types); free(flens); free(ilens); free(curs);
            return 2;
        }
    }

    if (!bd_interactive) {
        char line[1024];
        for (int i = 0; i < nrows; i++) {
            if (types[i] == 2) continue;
            int n = bd_read_line(line, sizeof line);
            if (n > 0) {
                char *copy = strdup(line);
                if (!copy) {
                    for (int j = 0; j < nrows; j++) free(values[j]);
                    free(labels); free(values); free(types); free(flens); free(ilens); free(curs);
                    return 1;
                }
                free(values[i]);
                values[i] = copy;
                curs[i] = strlen(values[i]);
            }
        }
        for (int i = 0; i < nrows; i++) {
            bd_emit_line(o, values[i]);
        }
        for (int i = 0; i < nrows; i++) free(values[i]);
        free(labels); free(values); free(types); free(flens); free(ilens); free(curs);
        return 0;
    }

    bd_box b;
    bd_layout(&b, h, w);
    bd_clear_screen();
    bd_draw_backtitle(o);
    bd_draw_frame(&b, o->title ? o->title : "Form");
    bd_draw_text(&b, text);
    int max_rows = b.h - 5;
    if (max_rows < 1) max_rows = 1;
    int cur = -1;
    for (int i = 0; i < nrows; i++) {
        if (types[i] != 2) { cur = i; break; }
    }
    if (cur < 0) cur = 0;
    bd_cup(b.top + b.h - 2, b.left + b.w / 2 - 3);
    bd_render_s("[<OK>]");
    if (bd_enter_raw() < 0) {
        bd_leave_raw();
        for (int i = 0; i < nrows; i++) free(values[i]);
        free(labels); free(values); free(types); free(flens); free(ilens); free(curs);
        return 1;
    }
    for (;;) {
        int cursor_row = b.top + 3;
        int cursor_col = b.left + 2;
        for (int i = 0; i < nrows && i < max_rows; i++) {
            int row = b.top + 3 + i;
            bd_cup(row, b.left + 2);
            for (int c = 0; c < b.w - 4; c++) bd_render_s(" ");
            bd_cup(row, b.left + 2);
            bd_render_s(i == cur ? "> " : "  ");
            bd_render_s(labels[i]);
            bd_render_s(": ");
            int used = 4 + (int) strlen(labels[i]);
            int room = b.w - 4 - used;
            if (room < 0) room = 0;
            int field_w = flens[i] < room ? flens[i] : room;
            if (field_w < 0) field_w = 0;
            size_t vl = strlen(values[i]);
            if (curs[i] > vl) curs[i] = vl;
            size_t start = 0;
            if (field_w > 0) {
                if (curs[i] >= (size_t) field_w)
                    start = curs[i] - (size_t) field_w + 1;
                if (start + (size_t) field_w > vl && vl > (size_t) field_w)
                    start = vl - (size_t) field_w;
            }
            size_t end = vl;
            if (field_w > 0 && end > start + (size_t) field_w)
                end = start + (size_t) field_w;
            if (types[i] == 1) {
                for (size_t j = start; j < end; j++) bd_render_s("*");
            } else {
                bd_render(values[i] + start, end - start);
            }
            if (i == cur) {
                size_t visible = 0;
                if (curs[i] > start) visible = curs[i] - start;
                if (field_w > 0 && visible >= (size_t) field_w)
                    visible = (size_t) field_w - 1;
                cursor_row = row;
                cursor_col = b.left + 2 + used + (int) visible;
            }
        }
        bd_cup(cursor_row, cursor_col);
        const char *k = bd_keypress();
        if (!strcmp(k, "RET")) {
            bd_leave_raw();
            bd_clear_screen();
            for (int i = 0; i < nrows; i++) {
                bd_emit_line(o, values[i]);
            }
            for (int i = 0; i < nrows; i++) free(values[i]);
            free(labels); free(values); free(types); free(flens); free(ilens); free(curs);
            return 0;
        }
        if (!strcmp(k, "ESC")) {
            bd_leave_raw();
            bd_clear_screen();
            for (int i = 0; i < nrows; i++) free(values[i]);
            free(labels); free(values); free(types); free(flens); free(ilens); free(curs);
            return 255;
        }
        if (!strcmp(k, "TAB") || !strcmp(k, "DOWN")) {
            for (int step = 1; step <= nrows; step++) {
                int next = (cur + step) % nrows;
                if (types[next] != 2) { cur = next; break; }
            }
            continue;
        }
        if (!strcmp(k, "UP")) {
            for (int step = 1; step <= nrows; step++) {
                int next = (cur - step + nrows) % nrows;
                if (types[next] != 2) { cur = next; break; }
            }
            continue;
        }
        if (types[cur] == 2)
            continue;
        size_t vl = strlen(values[cur]);
        if (curs[cur] > vl) curs[cur] = vl;
        if (!strcmp(k, "LEFT")) {
            if (curs[cur] > 0) curs[cur]--;
            continue;
        }
        if (!strcmp(k, "RIGHT")) {
            if (curs[cur] < vl) curs[cur]++;
            continue;
        }
        if (!strcmp(k, "HOME")) {
            curs[cur] = 0;
            continue;
        }
        if (!strcmp(k, "END")) {
            curs[cur] = vl;
            continue;
        }
        if (!strcmp(k, "BS")) {
            if (curs[cur] > 0) {
                memmove(values[cur] + curs[cur] - 1,
                        values[cur] + curs[cur],
                        vl - curs[cur] + 1);
                curs[cur]--;
            }
            continue;
        }
        if (!strcmp(k, "DEL")) {
            if (curs[cur] < vl)
                memmove(values[cur] + curs[cur],
                        values[cur] + curs[cur] + 1,
                        vl - curs[cur]);
            continue;
        }
        if (!strcmp(k, "SPACE")) {
            size_t max_input = ilens[cur] > 0 ? (size_t) ilens[cur] : 1023;
            if (vl >= max_input) continue;
            char *nv = realloc(values[cur], vl + 2);
            if (!nv) continue;
            values[cur] = nv;
            memmove(values[cur] + curs[cur] + 1,
                    values[cur] + curs[cur],
                    vl - curs[cur] + 1);
            values[cur][curs[cur]++] = ' ';
            continue;
        }
        if (strlen(k) == 1 && k[0] >= 0x20 && k[0] < 0x7f) {
            size_t max_input = ilens[cur] > 0 ? (size_t) ilens[cur] : 1023;
            if (vl >= max_input) continue;
            char *nv = realloc(values[cur], vl + 2);
            if (!nv) continue;
            values[cur] = nv;
            memmove(values[cur] + curs[cur] + 1,
                    values[cur] + curs[cur],
                    vl - curs[cur] + 1);
            values[cur][curs[cur]++] = k[0];
            continue;
        }
    }
}

static int
bd_widget_mixedform(const bd_opts *o, const char *text, int h, int w,
                    int form_h, WORD_LIST *fields)
{
    return bd_widget_form_like(o, text, h, w, form_h, fields, 1);
}

static int
bd_widget_form(const bd_opts *o, const char *text, int h, int w,
               int form_h, WORD_LIST *fields)
{
    return bd_widget_form_like(o, text, h, w, form_h, fields, 0);
}

static int
bd_widget_gauge(const bd_opts *o, const char *text, int h, int w, int init_pct)
{
    if (!bd_interactive) {
        /* Drain percent lines from stdin; emit nothing (gauge has no
         * output result — it's a visual progress widget). */
        char line[64];
        int last = init_pct;
        for (;;) {
            int n = bd_read_line(line, sizeof line);
            if (n == 0) break;
            int p = atoi(line);
            if (p >= 0 && p <= 100) last = p;
        }
        (void) last;
        return 0;
    }
    bd_box b;
    bd_layout(&b, h, w);
    bd_clear_screen();
    bd_draw_backtitle(o);
    bd_draw_frame(&b, o->title ? o->title : "Progress");
    bd_draw_text(&b, text);
    int bar_row = b.top + b.h - 3;
    int bar_w   = b.w - 4;
    int pct = init_pct;
    char line[64];
    for (;;) {
        bd_cup(bar_row, b.left + 2);
        int fill = (pct * bar_w) / 100;
        for (int i = 0; i < fill;     i++) bd_render_s("#");
        for (int i = fill; i < bar_w; i++) bd_render_s("-");
        char pcttxt[16];
        snprintf(pcttxt, sizeof pcttxt, " %3d%% ", pct);
        bd_cup(bar_row + 1, b.left + (b.w - 6) / 2);
        bd_render_s(pcttxt);
        int n = bd_read_line(line, sizeof line);
        if (n == 0) break;
        int p = atoi(line);
        if (p >= 0 && p <= 100) pct = p;
    }
    bd_clear_screen();
    return 0;
}

static int
bd_widget_pause(const bd_opts *o, const char *text, int h, int w, int seconds)
{
    if (seconds < 0) seconds = 0;
    if (!bd_interactive) {
        while (seconds > 0) {
            seconds = sleep((unsigned int) seconds);
        }
        return 0;
    }

    bd_box b;
    bd_layout(&b, h, w);
    bd_clear_screen();
    bd_draw_backtitle(o);
    bd_draw_frame(&b, o->title ? o->title : "Pause");
    bd_draw_text(&b, text);

    int row = b.top + b.h - 2;
    while (seconds > 0) {
        char msg[64];
        snprintf(msg, sizeof msg, " %d ", seconds);
        bd_cup(row, b.left + (b.w - (int) strlen(msg)) / 2);
        bd_render_s(msg);
        seconds = sleep((unsigned int) seconds);
        if (seconds > 0) continue;
        break;
    }
    bd_clear_screen();
    return 0;
}

static int
bd_read_file_body(const char *file, char **out, size_t *out_len)
{
    int fd = open(file, O_RDONLY);
    if (fd < 0) {
        builtin_error("%s: %s", file, strerror(errno));
        return -1;
    }

    size_t cap = 8192;
    size_t len = 0;
    char *buf = malloc(cap + 1);
    if (!buf) {
        close(fd);
        return -1;
    }

    for (;;) {
        if (len == cap) {
            size_t ncap = cap * 2;
            if (ncap < cap) {
                free(buf);
                close(fd);
                return -1;
            }
            char *nbuf = realloc(buf, ncap + 1);
            if (!nbuf) {
                free(buf);
                close(fd);
                return -1;
            }
            buf = nbuf;
            cap = ncap;
        }
        ssize_t n = read(fd, buf + len, cap - len);
        if (n < 0) {
            if (errno == EINTR) continue;
            builtin_error("%s: %s", file, strerror(errno));
            free(buf);
            close(fd);
            return -1;
        }
        if (n == 0) break;
        len += (size_t) n;
    }
    close(fd);
    buf[len] = '\0';
    *out = buf;
    *out_len = len;
    return 0;
}

static int
bd_text_line_count(const char *data, size_t len)
{
    int lines = 1;
    if (len == 0) return 1;
    for (size_t i = 0; i < len; i++) {
        if (data[i] == '\n' && i + 1 < len) lines++;
    }
    return lines;
}

static void
bd_text_line_at(const char *data, size_t len, int want, const char **start, size_t *llen)
{
    int cur = 0;
    size_t off = 0;
    while (off < len && cur < want) {
        if (data[off++] == '\n') cur++;
    }
    size_t end = off;
    while (end < len && data[end] != '\n') end++;
    if (end > off && data[end - 1] == '\r') end--;
    *start = data + off;
    *llen = end >= off ? end - off : 0;
}

static void
bd_draw_textbox_page(const bd_opts *o, const char *data, size_t len,
                     int h, int w, int top_line, int follow)
{
    bd_box b;
    bd_layout(&b, h, w);
    bd_clear_screen();
    bd_draw_backtitle(o);
    bd_draw_frame(&b, o && o->title ? o->title : (follow ? "Tailbox" : "Textbox"));
    int visible = b.h - 2;
    int max_w = b.w - 4;
    if (visible < 1 || max_w < 1) return;
    for (int row = 0; row < visible; row++) {
        const char *line = "";
        size_t llen = 0;
        bd_text_line_at(data, len, top_line + row, &line, &llen);
        if (llen > (size_t) max_w) llen = (size_t) max_w;
        bd_cup(b.top + 1 + row, b.left + 2);
        bd_render(line, llen);
    }
}

static int
bd_widget_textbox(const bd_opts *o, const char *file, int h, int w, int follow)
{
    char *data = NULL;
    size_t len = 0;
    if (bd_read_file_body(file, &data, &len) < 0)
        return 2;

    if (!bd_interactive) {
        bd_render(data, len);
        if (!follow) {
            char line[8];
            bd_read_line(line, sizeof line);
        }
        free(data);
        return 0;
    }

    bd_box b;
    bd_layout(&b, h, w);
    int visible = b.h - 2;
    if (visible < 1) visible = 1;
    int line_count = bd_text_line_count(data, len);
    int top_line = 0;
    if (follow && line_count > visible)
        top_line = line_count - visible;

    if (bd_enter_raw() < 0) {
        bd_leave_raw();
        free(data);
        return 1;
    }
    for (;;) {
        if (top_line < 0) top_line = 0;
        if (top_line > line_count - 1) top_line = line_count - 1;
        bd_draw_textbox_page(o, data, len, h, w, top_line, follow);
        const char *k = bd_keypress();
        if (!strcmp(k, "RET") || !strcmp(k, "q") || !strcmp(k, "Q")) {
            bd_leave_raw();
            bd_clear_screen();
            free(data);
            return 0;
        }
        if (!strcmp(k, "ESC")) {
            bd_leave_raw();
            bd_clear_screen();
            free(data);
            return 255;
        }
        if (!strcmp(k, "UP")) {
            top_line--;
        } else if (!strcmp(k, "DOWN")) {
            top_line++;
        } else if (!strcmp(k, "PGUP")) {
            top_line -= visible;
        } else if (!strcmp(k, "PGDN")) {
            top_line += visible;
        } else if (!strcmp(k, "HOME")) {
            top_line = 0;
        } else if (!strcmp(k, "END")) {
            top_line = line_count - visible;
        }
        if (top_line < 0) top_line = 0;
        if (line_count > visible && top_line > line_count - visible)
            top_line = line_count - visible;
    }
}

/* ----------------------------------------------------------------------
 * Argument parsing / dispatch
 *
 * Pre-widget flags are consumed off the front of the WORD_LIST. Then
 * the first remaining word is a --widget switch and the rest are its
 * positional args.
 * ---------------------------------------------------------------------- */

/* Pop one WORD_LIST element by stepping the head pointer. Returns the
 * word or NULL when list is empty. */
static const char *
bd_pop(WORD_LIST **list)
{
    if (!*list) return NULL;
    const char *w = (*list)->word->word;
    *list = (*list)->next;
    return w;
}

static int
bd_dispatch(WORD_LIST *list)
{
    bd_opts o = { 0 };
    o.out_fd = STDERR_FILENO;

    /* Leading flags. */
    while (list) {
        const char *w = list->word->word;
        if (!strcmp(w, "--title")) {
            list = list->next;
            if (!list) { builtin_error("--title requires argument"); return 2; }
            o.title = list->word->word;
            list = list->next;
        } else if (!strcmp(w, "--backtitle")) {
            list = list->next;
            if (!list) { builtin_error("--backtitle requires argument"); return 2; }
            o.backtitle = list->word->word;
            list = list->next;
        } else if (!strcmp(w, "--no-cancel") || !strcmp(w, "--nocancel")) {
            o.no_cancel = 1;
            list = list->next;
        } else if (!strcmp(w, "--defaultno")) {
            o.default_no = 1;
            list = list->next;
        } else if (!strcmp(w, "--separate-output")) {
            o.separate_out = 1;
            list = list->next;
        } else if (!strcmp(w, "--stdout")) {
            o.out_fd = STDOUT_FILENO;
            list = list->next;
        } else if (!strcmp(w, "--output-fd")) {
            list = list->next;
            if (!list) { builtin_error("--output-fd requires argument"); return 2; }
            if (bd_parse_fd_arg(list->word->word, &o.out_fd) < 0) {
                builtin_error("--output-fd requires non-negative integer");
                return 2;
            }
            list = list->next;
        } else if (!strcmp(w, "--ok-label")) {
            list = list->next;
            if (!list) { builtin_error("--ok-label requires argument"); return 2; }
            o.ok_label = list->word->word;
            list = list->next;
        } else if (!strcmp(w, "--cancel-label")) {
            list = list->next;
            if (!list) { builtin_error("--cancel-label requires argument"); return 2; }
            o.cancel_label = list->word->word;
            list = list->next;
        } else if (!strcmp(w, "--yes-label")) {
            list = list->next;
            if (!list) { builtin_error("--yes-label requires argument"); return 2; }
            o.yes_label = list->word->word;
            list = list->next;
        } else if (!strcmp(w, "--no-label")) {
            list = list->next;
            if (!list) { builtin_error("--no-label requires argument"); return 2; }
            o.no_label = list->word->word;
            list = list->next;
        } else if (!strcmp(w, "--default-item")) {
            list = list->next;
            if (!list) { builtin_error("--default-item requires argument"); return 2; }
            o.default_item = list->word->word;
            list = list->next;
        } else if (!strcmp(w, "--default-button")) {
            list = list->next;
            if (!list) { builtin_error("--default-button requires argument"); return 2; }
            if (!bd_valid_default_button(list->word->word)) {
                builtin_error("--default-button must be ok, cancel, yes, no, or extra");
                return 2;
            }
            o.default_button = list->word->word;
            list = list->next;
        } else if (!strcmp(w, "--notags")) {
            o.notags = 1;
            list = list->next;
        } else if (!strcmp(w, "--clear") || !strcmp(w, "--colors")
                   || !strcmp(w, "--no-shadow") || !strcmp(w, "--ascii-lines")) {
            /* No-op compat flags. */
            list = list->next;
        } else {
            break;
        }
    }
    if (!list) {
        builtin_error("no widget specified");
        return 2;
    }

    const char *widget = bd_pop(&list);

    if (!strcmp(widget, "--textbox") || !strcmp(widget, "--tailbox")) {
        const char *file = bd_pop(&list);
        const char *hs   = bd_pop(&list);
        const char *ws   = bd_pop(&list);
        if (!file || !hs || !ws) {
            builtin_error("%s: FILE HEIGHT WIDTH required", widget);
            return 2;
        }
        bd_open_tty();
        int rc = bd_widget_textbox(&o, file, atoi(hs), atoi(ws),
                                   !strcmp(widget, "--tailbox"));
        bd_close_tty();
        return rc;
    }

    /* Common positional parse: TEXT HEIGHT WIDTH (always first three for
     * the widgets we ship). */
    const char *text = bd_pop(&list);
    const char *hs   = bd_pop(&list);
    const char *ws   = bd_pop(&list);
    if (!text || !hs || !ws) {
        builtin_error("%s: TEXT HEIGHT WIDTH required", widget);
        return 2;
    }
    int h = atoi(hs);
    int w = atoi(ws);

    bd_open_tty();
    int rc;

    if (!strcmp(widget, "--yesno")) {
        rc = bd_widget_yesno(&o, text, h, w);
    } else if (!strcmp(widget, "--msgbox")) {
        rc = bd_widget_msgbox(&o, text, h, w, 0);
    } else if (!strcmp(widget, "--infobox")) {
        rc = bd_widget_msgbox(&o, text, h, w, 1);
    } else if (!strcmp(widget, "--inputbox")) {
        const char *init = bd_pop(&list);
        rc = bd_widget_inputbox(&o, text, h, w, init, 0);
    } else if (!strcmp(widget, "--passwordbox")) {
        const char *init = bd_pop(&list);
        rc = bd_widget_inputbox(&o, text, h, w, init, 1);
    } else if (!strcmp(widget, "--menu")
               || !strcmp(widget, "--inputmenu")
               || !strcmp(widget, "--checklist")
               || !strcmp(widget, "--radiolist")
               || !strcmp(widget, "--treeview")) {
        const char *mhs = bd_pop(&list);
        if (!mhs) {
            builtin_error("%s: MENU_HEIGHT required", widget);
            bd_close_tty();
            return 2;
        }
        int mh = atoi(mhs);
        int mode = (!strcmp(widget, "--menu"))       ? 0
                 : (!strcmp(widget, "--checklist"))  ? 1
                 : (!strcmp(widget, "--radiolist"))  ? 2
                 : (!strcmp(widget, "--treeview"))   ? 3 : 4;
        rc = bd_widget_menu_like(&o, text, h, w, mh, list, mode);
    } else if (!strcmp(widget, "--form") || !strcmp(widget, "--mixedform")) {
        const char *fhs = bd_pop(&list);
        if (!fhs) {
            builtin_error("%s: FORM_HEIGHT required", widget);
            bd_close_tty();
            return 2;
        }
        if (!strcmp(widget, "--form"))
            rc = bd_widget_form(&o, text, h, w, atoi(fhs), list);
        else
            rc = bd_widget_mixedform(&o, text, h, w, atoi(fhs), list);
    } else if (!strcmp(widget, "--gauge")) {
        const char *ps = bd_pop(&list);
        int init_pct = ps ? atoi(ps) : 0;
        rc = bd_widget_gauge(&o, text, h, w, init_pct);
    } else if (!strcmp(widget, "--pause")) {
        const char *ss = bd_pop(&list);
        if (!ss) {
            builtin_error("%s: SECONDS required", widget);
            bd_close_tty();
            return 2;
        }
        rc = bd_widget_pause(&o, text, h, w, atoi(ss));
    } else {
        builtin_error("unknown widget: %s", widget);
        bd_close_tty();
        return 2;
    }

    bd_close_tty();
    return rc;
}

/* ----------------------------------------------------------------------
 * Bash builtin entrypoints — dialog and whiptail share the same
 * dispatch path (whiptail is a feature subset of dialog; we expose both
 * names so caller scripts written for either work unmodified).
 * ---------------------------------------------------------------------- */

extern char * const dialog_doc[];
extern char * const whiptail_doc[];

int
dialog_builtin(WORD_LIST *list)
{
    if (!list) {
        builtin_usage();
        return EX_USAGE;
    }
    if (!strcmp(list->word->word, "--help") || !strcmp(list->word->word, "-h")) {
        char *const *dp;
        for (dp = (char *const *) dialog_doc; *dp; dp++) puts(*dp);
        return EX_USAGE;
    }
    return bd_dispatch(list);
}

int
whiptail_builtin(WORD_LIST *list)
{
    return dialog_builtin(list);
}

char * const dialog_doc[] = {
    "dialog / whiptail widget surface for bash-os TUI scripts.",
    "",
    "Widgets:",
    "    --yesno      TEXT HEIGHT WIDTH",
    "    --msgbox     TEXT HEIGHT WIDTH",
    "    --infobox    TEXT HEIGHT WIDTH",
    "    --inputbox   TEXT HEIGHT WIDTH [INIT]",
    "    --passwordbox TEXT HEIGHT WIDTH [INIT]",
    "    --menu       TEXT HEIGHT WIDTH MENU_H TAG ITEM [TAG ITEM ...]",
    "    --inputmenu  TEXT HEIGHT WIDTH MENU_H TAG ITEM [TAG ITEM ...]",
    "    --checklist  TEXT HEIGHT WIDTH MENU_H TAG ITEM STATUS [...]",
    "    --radiolist  TEXT HEIGHT WIDTH MENU_H TAG ITEM STATUS [...]",
    "    --treeview   TEXT HEIGHT WIDTH MENU_H TAG ITEM STATUS DEPTH [...]",
    "    --form       TEXT HEIGHT WIDTH FORM_H LABEL Y X ITEM Y X FLEN ILEN [...]",
    "    --mixedform  TEXT HEIGHT WIDTH FORM_H LABEL Y X ITEM Y X FLEN ILEN ITYPE [...]",
    "    --gauge      TEXT HEIGHT WIDTH [INIT_PCT]",
    "    --pause      TEXT HEIGHT WIDTH SECONDS",
    "    --textbox    FILE HEIGHT WIDTH",
    "    --tailbox    FILE HEIGHT WIDTH",
    "",
    "Leading flags (before the widget):",
    "    --title TEXT       window title",
    "    --backtitle TEXT   background banner",
    "    --no-cancel        suppress Cancel button on input widgets",
    "    --defaultno        yes/no default is No",
    "    --separate-output  checklist output: one tag per line",
    "    --stdout           write result strings to stdout",
    "    --output-fd N      write result strings to fd N",
    "    --ok-label TEXT    relabel OK buttons",
    "    --cancel-label TEXT relabel Cancel buttons",
    "    --yes-label TEXT   relabel Yes buttons",
    "    --no-label TEXT    relabel No buttons",
    "    --default-item TAG default menu/checklist item",
    "    --default-button NAME default button: ok, cancel, yes, no, extra",
    "    --notags           emit/display item text instead of tag",
    "",
    "Exit: 0=OK/Yes, 1=No/Cancel, 255=ESC. Result strings go to stderr",
    "by default (dialog convention), stdout under --stdout, or fd N under",
    "--output-fd N. When no /dev/tty is available, runs in non-",
    "interactive mode: widgets consume input tokens from stdin and emit",
    "results without rendering; --inputmenu accepts",
    "RENAMED TAG NEW_TEXT for deterministic rename records. --mixedform",
    "ITYPE values are 0 normal, 1 hidden/password, 2 readonly. --form",
    "is the editable type-0 subset of --mixedform. --textbox/--tailbox",
    "display file content read-only.",
    (char *) NULL
};

char * const whiptail_doc[] = {
    "whiptail-compatible alias for dialog. See `help dialog`.",
    (char *) NULL
};

struct builtin dialog_struct = {
    "dialog",
    dialog_builtin,
    BUILTIN_ENABLED,
    (char **) dialog_doc,
    "dialog [--title T] --WIDGET TEXT HEIGHT WIDTH [WIDGET ARGS ...]",
    0
};

struct builtin whiptail_struct = {
    "whiptail",
    whiptail_builtin,
    BUILTIN_ENABLED,
    (char **) whiptail_doc,
    "whiptail [--title T] --WIDGET TEXT HEIGHT WIDTH [WIDGET ARGS ...]",
    0
};
