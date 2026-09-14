/* SPDX-License-Identifier: MIT */
/* bashtermpixel.h — terminal-pixel graphics/runtime substrate for bash-os
 * games and demos. C-native subset of the termpixel_pong Python reference:
 * RGB pixel buffer, upper-half-block ANSI renderer, simple primitives, a 3x5
 * font, raw-tty input, and frame pacing. Sibling loadables (e.g.
 * termpixel_pong.c) include this header instead of duplicating the renderer.
 *
 * See research/bash-os/IMPL-PLANS/termpixel/01-bashtermpixel-c-loadable.md.
 */
#ifndef BASHTERMPIXEL_H
#define BASHTERMPIXEL_H

#include <stddef.h>
#include <time.h>
#include <termios.h>

/* RGB pixel canvas. width x height pixels; rendered as width x (height/2)
 * terminal cells (two vertical pixels per cell). Caller owns the struct. */
typedef struct btp_canvas {
    int            width;
    int            height;        /* must be even */
    unsigned char *rgb;           /* width*height*3, row-major */
} btp_canvas;

int  btp_canvas_init(btp_canvas *c, int width, int height);
void btp_canvas_free(btp_canvas *c);
void btp_clear(btp_canvas *c, unsigned r, unsigned g, unsigned b);
void btp_set_pixel(btp_canvas *c, int x, int y, unsigned r, unsigned g, unsigned b);
void btp_draw_rect(btp_canvas *c, int x, int y, int w, int h,
                   unsigned r, unsigned g, unsigned b, int filled);
void btp_draw_line(btp_canvas *c, int x0, int y0, int x1, int y1,
                   unsigned r, unsigned g, unsigned b);
void btp_draw_circle(btp_canvas *c, int cx, int cy, int radius,
                     unsigned r, unsigned g, unsigned b, int filled);
/* 3x5 bitmap font; advances 4px/char. Renders [A-Z0-9 :.-] (others -> blank). */
void btp_draw_text3x5(btp_canvas *c, const char *s, int x, int y,
                      unsigned r, unsigned g, unsigned b);
/* Render the canvas to fd using 24-bit ANSI + U+2580, run-length batched.
 * Returns 0 on success, -1 on write error. */
int  btp_render_ansi_fd(const btp_canvas *c, int fd);

/* Terminal/input helpers. btp owns terminal hygiene (raw mode, cursor hide,
 * color reset, restore on every exit path). */
typedef struct btp_tty_state {
    int            fd;
    int            active;
    struct termios saved;
} btp_tty_state;

int btp_tty_enter_raw(btp_tty_state *st, int fd);   /* hides cursor, raw mode */
int btp_tty_restore(btp_tty_state *st);             /* shows cursor, resets    */
/* Read one key into name[] (e.g. "UP_ARROW","ENTER","SPACE","ESCAPE", or the
 * literal UTF-8/ascii char). Returns 1 on a key, 0 on timeout, -1 on EOF/error.
 * timeout_ms < 0 blocks. A lone ESC resolves to ESCAPE after ~50ms. */
int btp_read_key(int fd, int timeout_ms, char *name, size_t name_cap);
/* Absolute monotonic sleep (frame pacing). Returns 0 on success. */
int btp_sleep_until_monotonic(struct timespec deadline);

#endif /* BASHTERMPIXEL_H */
