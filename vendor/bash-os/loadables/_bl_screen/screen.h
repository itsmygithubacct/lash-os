/* SPDX-License-Identifier: MIT */
/* _bl_screen/screen.h — ncurses-subset screen model for bash-os TUI loadables.
 *
 * bash-os ships no ncurses (not linkable in the static-musl guest) and no
 * terminfo (it targets known ANSI/ECMA-48 terminals: linux console + xterm
 * family). This vendored helper ports the ESSENTIAL ncurses value — a cell
 * grid (WINDOW) drawn into a virtual screen, reconciled against a physical
 * mirror by a diff-optimized refresh (the doupdate/TransformLine idea) that
 * emits only the cells that changed — with hardcoded escape sequences and
 * 24-bit truecolor (down-converted to 256/16 per terminal capability).
 *
 * Packaging: vendored under the `_<lib>/` convention. patch-bash-loadables.sh
 * flattens `_bl_screen/screen.{c,h}` to `builtins/_bl_screen_screen.{c,h}` and
 * links the `.o` into bash. Consumers include the flattened name:
 *
 *   #include "_bl_screen_screen.h"   // this API
 *   #include "_bl_key_bl_key.h"      // input (composed, not duplicated)
 *
 * Single global screen (no multi-SCREEN/newterm). Input comes from _bl_key.
 *
 * License: MIT, matching the rest of the project. When statically linked into
 * bash the combined binary is governed by bash's GPL-3+.
 */
#ifndef _BL_SCREEN_SCREEN_H
#define _BL_SCREEN_SCREEN_H

#include <stdint.h>
#include <stdarg.h>

/* --- attributes (OR together) ----------------------------------------- */
#define BLS_A_NORMAL     0x00u
#define BLS_A_BOLD       0x01u
#define BLS_A_DIM        0x02u
#define BLS_A_ITALIC     0x04u
#define BLS_A_UNDERLINE  0x08u
#define BLS_A_BLINK      0x10u
#define BLS_A_REVERSE    0x20u

/* --- color: a 32-bit value used for fg and bg --------------------------
 *   BLS_DEFAULT        terminal default (SGR 39/49)
 *   BLS_RGB(r,g,b)     24-bit truecolor (0x000000..0xFFFFFF)
 *   BLS_PALETTE(n)     ANSI palette index 0..255 (n in 0..255)
 * The emitter down-converts RGB to the active color mode. */
#define BLS_DEFAULT      (-1)
#define BLS_PAL_BASE     0x40000000
#define BLS_PALETTE(n)   (BLS_PAL_BASE + ((n) & 0xff))
#define BLS_RGB(r,g,b)   ((int32_t)((((r)&0xff)<<16) | (((g)&0xff)<<8) | ((b)&0xff)))

/* --- color modes (auto-detected at init from $COLORTERM/$TERM) --------- */
enum { BLS_MODE_16 = 0, BLS_MODE_256, BLS_MODE_TRUECOLOR };

/* getch sentinels: shares the _bl_key code space. */
#define BLS_KEY_NONE 0       /* EOF */
#define BLS_ERR      (-1)    /* timeout (no key within bls_timeout window) */

typedef struct bls_win bls_win;

/* --- lifecycle --------------------------------------------------------- */
int   bls_init(void);          /* open tty, raw+altscreen+hide-cursor, alloc
                                  screens, install restore-on-exit. 0/-1. */
void  bls_end(void);           /* restore (idempotent; also on signal/atexit) */
int   bls_lines(void);         /* rows (re-queried on SIGWINCH) */
int   bls_cols(void);          /* cols */
int   bls_resized(void);       /* test-and-clear: did a SIGWINCH arrive? */
void  bls_set_color_mode(int mode);
int   bls_color_mode(void);
int   bls_tty_fd(void);

/* --- windows ----------------------------------------------------------- */
bls_win *bls_stdscr(void);                    /* full-screen window */
bls_win *bls_newwin(int h, int w, int y, int x);
void     bls_delwin(bls_win *);

/* --- drawing (into the window's virtual cells) ------------------------- */
void  bls_erase(bls_win *);
void  bls_move(bls_win *, int y, int x);
void  bls_addch(bls_win *, uint32_t cp);      /* Unicode code point */
void  bls_addstr(bls_win *, const char *s);   /* UTF-8 */
void  bls_addnstr(bls_win *, const char *s, int n);
/* Like bls_addnstr but PARSES embedded ANSI: SGR (\033[...m) updates the cell
   rendition (bold/dim/italic/underline/blink/reverse, 16/256/truecolor fg+bg);
   other CSI/escape sequences are consumed and ignored; C0 controls render in
   caret notation (^X), tabs expand. This is the `less -R`-class content path
   for pass-through pagers. Resets rendition to normal at the call start. */
void  bls_addstr_ansi(bls_win *, const char *s, int n);
void  bls_mvaddstr(bls_win *, int y, int x, const char *s);
int   bls_printw(bls_win *, const char *fmt, ...);
void  bls_hline(bls_win *, uint32_t cp, int n);
void  bls_vline(bls_win *, uint32_t cp, int n);
void  bls_box(bls_win *, uint32_t verch, uint32_t horch);  /* 0 → default glyphs */
void  bls_clrtoeol(bls_win *);
void  bls_clrtobot(bls_win *);

/* --- attributes / color ------------------------------------------------ */
void  bls_attron(bls_win *, unsigned attr);
void  bls_attroff(bls_win *, unsigned attr);
void  bls_attrset(bls_win *, unsigned attr);
void  bls_setfg(bls_win *, int32_t color);
void  bls_setbg(bls_win *, int32_t color);

/* --- the point: diff newscr vs curscr, emit only changes --------------- */
void  bls_refresh(bls_win *);
void  bls_touchwin(bls_win *);   /* force full redraw on next refresh */

/* --- input (thin wrapper over _bl_key) --------------------------------- */
int   bls_getch(void);           /* key code, BLS_KEY_NONE on EOF, BLS_ERR on timeout */
void  bls_timeout(int ms);       /* -1 block (default), 0 nonblock, >0 ms */

/* Prompt for a line at (y,x) in window w (drawn through the cell model so the
   diff engine and curscr stay consistent). Echoes input, handles backspace.
   Returns input length, or -1 if cancelled (ESC). Always blocks regardless of
   bls_timeout. The cursor is shown for the duration and hidden again after. */
int   bls_getnstr(bls_win *w, int y, int x, const char *prompt, char *buf, int n);

#endif /* _BL_SCREEN_SCREEN_H */
