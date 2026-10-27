/* SPDX-License-Identifier: MIT */
/* tui.c — script-facing front end to the _bl_screen TUI engine.
 *
 *   tui SUBCOMMAND [args...]
 *
 * Lets a pure-bash script build a curses-style full-screen UI without ncurses,
 * driving the shared _bl_screen cell/diff engine (truecolor, only-changed-cells
 * refresh) that also backs ncdu / top. State (the screen) persists in
 * the bash process between calls, so a script does `tui init` once, draws
 * with move/addstr/attr/refresh in a loop, reads keys with `getkey`, and ends
 * with `tui end`.
 *
 * Subcommands:
 *   init                         enter raw + alt-screen; alloc the screen (0/1)
 *   end                          restore terminal (idempotent)
 *   lines | cols                 print the screen height / width
 *   resized                      rc 0 (and print 1) if a SIGWINCH arrived, else 1/print 0
 *   colormode [16|256|truecolor] get/set the color mode
 *   erase                        blank the screen buffer
 *   move Y X                     position the draw cursor
 *   addstr [-y Y] [-x X] STR     write text (UTF-8) at the cursor / (Y,X)
 *   addansi STR                  write text honoring embedded ANSI SGR (less -R)
 *   attr A...                    set attributes: normal bold dim italic underline blink reverse
 *   fg COLOR | bg COLOR          set color: default | NAME | N(0-255) | #RRGGBB | R,G,B
 *   hline [CH] N | vline [CH] N  draw a run of CH (default ─ / │)
 *   box                          draw a border around the screen
 *   clrtoeol | clrtobot          clear to end of line / screen
 *   refresh                      flush only the changed cells to the terminal
 *   timeout MS                   getkey wait: -1 block, 0 nonblock, >0 ms
 *   getkey                       read one key; print a token (UP/DOWN/.../C-A/'q');
 *                                rc 0 key, rc 1 EOF, rc 2 timeout
 *   getstr [-y Y] [-x X] PROMPT  prompt for a line; print it (rc 1 if cancelled)
 *
 * --- LICENSE --- MIT, same boilerplate as top.c. */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>

#include "_bl_screen_screen.h"
#include "_bl_key_bl_key.h"
#include "loadables.h"

/* Strict decimal parsing: do not turn malformed API input into coordinates. */
static int
btui_number (const char *s, int lo, int hi, int *out)
{
    char *end;
    if (!s || !*s || isspace ((unsigned char) *s)) return 0;
    errno = 0;
    long value = strtol (s, &end, 10);
    if (errno || *end || value < lo || value > hi) return 0;
    *out = (int) value;
    return 1;
}

static int
btui_color (const char *s, int32_t *out)
{
    if (!strcmp (s, "default")) { *out = BLS_DEFAULT; return 1; }
    if (s[0] == '#' && strlen (s) == 7) {
        for (int i = 1; i < 7; i++) if (!isxdigit ((unsigned char) s[i])) return 0;
        *out = (int32_t) strtol (s + 1, NULL, 16); return 1;
    }
    if (strchr (s, ',')) {
        char *end; const char *p = s; int rgb[3];
        for (int i = 0; i < 3; i++) {
            if (!isdigit ((unsigned char) *p)) return 0;
            errno = 0; long v = strtol (p, &end, 10);
            if (errno || v < 0 || v > 255 || *end != (i == 2 ? '\0' : ',')) return 0;
            rgb[i] = (int) v; p = end + (i != 2);
        }
        *out = BLS_RGB (rgb[0], rgb[1], rgb[2]); return 1;
    }
    static const char *nm[] = { "black","red","green","yellow","blue","magenta","cyan","white" };
    for (int i = 0; i < 8; i++) if (!strcmp (s, nm[i])) { *out = BLS_PALETTE (i); return 1; }
    int v;
    if (!btui_number (s, 0, 255, &v)) return 0;
    *out = BLS_PALETTE (v); return 1;
}

/* A line glyph is exactly one printable Unicode scalar, not its first byte. */
static int
btui_glyph (const char *s, uint32_t *cp)
{
    const unsigned char *p = (const unsigned char *) s;
    size_t n = strlen (s); uint32_t v; int bytes;
    if (n == 1 && p[0] >= 32 && p[0] != 127) { *cp = p[0]; return p[0] < 128; }
    if (n == 2 && p[0] >= 0xc2 && p[0] <= 0xdf) { v = p[0] & 31; bytes = 2; }
    else if (n == 3 && p[0] >= 0xe0 && p[0] <= 0xef) { v = p[0] & 15; bytes = 3; }
    else if (n == 4 && p[0] >= 0xf0 && p[0] <= 0xf4) { v = p[0] & 7; bytes = 4; }
    else return 0;
    for (int i = 1; i < bytes; i++) {
        if ((p[i] & 0xc0) != 0x80) return 0;
        v = (v << 6) | (p[i] & 63);
    }
    if ((bytes == 3 && v < 0x800) || (bytes == 4 && v < 0x10000) ||
        (v >= 0x80 && v < 0xa0) || (v >= 0xd800 && v <= 0xdfff) || v > 0x10ffff) return 0;
    *cp = v; return 1;
}

static int
btui_output (void)
{
    return fflush (stdout) == EOF || ferror (stdout) ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static const char *
btui_keyname (int k, char *buf, size_t cap)
{
    switch (k) {
        case BL_KEY_UP:    return "UP";
        case BL_KEY_DOWN:  return "DOWN";
        case BL_KEY_LEFT:  return "LEFT";
        case BL_KEY_RIGHT: return "RIGHT";
        case BL_KEY_HOME:  return "HOME";
        case BL_KEY_END:   return "END";
        case BL_KEY_PGUP:  return "PGUP";
        case BL_KEY_PGDN:  return "PGDN";
        case BL_KEY_INS:   return "INS";
        case BL_KEY_DEL:   return "DEL";
        case BL_KEY_BS:    return "BS";
        case BL_KEY_RET:   return "RET";
        case BL_KEY_TAB:   return "TAB";
        case BL_KEY_ESC:   return "ESC";   /* == 27 */
        case BL_KEY_F1:    return "F1";
        case BL_KEY_F2:    return "F2";
        case BL_KEY_F3:    return "F3";
        case BL_KEY_F4:    return "F4";
    }
    if (k == '\r' || k == '\n') return "RET";
    if (k == '\t') return "TAB";
    if (k == 0x7f) return "BS";
    if (k >= 1 && k <= 26) { snprintf (buf, cap, "C-%c", 'A' + k - 1); return buf; }
    if (k >= 0x20 && k < 0x7f) { buf[0] = (char) k; buf[1] = '\0'; return buf; }
    snprintf (buf, cap, "\\x%02x", k & 0xff);
    return buf;
}

static int
btui_attr_bit (const char *s)
{
    if (!strcmp (s, "normal"))    return BLS_A_NORMAL;
    if (!strcmp (s, "bold"))      return BLS_A_BOLD;
    if (!strcmp (s, "dim"))       return BLS_A_DIM;
    if (!strcmp (s, "italic"))    return BLS_A_ITALIC;
    if (!strcmp (s, "underline")) return BLS_A_UNDERLINE;
    if (!strcmp (s, "blink"))     return BLS_A_BLINK;
    if (!strcmp (s, "reverse"))   return BLS_A_REVERSE;
    return -1;
}

/* count WORD_LIST args after the subcommand into a small argv */
static int
btui_argv (WORD_LIST *l, const char **av, int max)
{
    int n = 0;
    for (; l && n < max; l = l->next) av[n++] = l->word->word;
    return l ? -1 : n;
}

int
tui_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *rest = list->next;
    const char *av[8];
    int ac = btui_argv (rest, av, 8);
    bls_win *w = bls_stdscr ();
    int min = 0, max = 0;
    if (!strcmp (cmd, "move")) min = max = 2;
    else if (!strcmp (cmd, "fg") || !strcmp (cmd, "bg") || !strcmp (cmd, "timeout")) min = max = 1;
    else if (!strcmp (cmd, "colormode")) max = 1;
    else if (!strcmp (cmd, "hline") || !strcmp (cmd, "vline")) { min = 1; max = 2; }
    else if (!strcmp (cmd, "addstr") || !strcmp (cmd, "addansi")) { min = 1; max = 6; }
    else if (!strcmp (cmd, "getstr")) max = 6;
    if (strcmp (cmd, "attr") && (ac < min || ac > max)) {
        builtin_error ("%s: wrong number of arguments", cmd); return EX_USAGE;
    }
    clearerr (stdout);

    if (!strcmp (cmd, "init"))
        return bls_init () == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    if (!strcmp (cmd, "end"))      { bls_end (); return EXECUTION_SUCCESS; }
    if (!strcmp (cmd, "lines"))    { printf ("%d\n", bls_lines ()); return btui_output (); }
    if (!strcmp (cmd, "cols"))     { printf ("%d\n", bls_cols ()); return btui_output (); }
    if (!strcmp (cmd, "resized")) {
        int r = bls_resized (); printf ("%d\n", r);
        return btui_output () == EXECUTION_SUCCESS && r ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
    if (!strcmp (cmd, "colormode")) {
        if (ac >= 1) {
            if (!strcmp (av[0], "16")) bls_set_color_mode (BLS_MODE_16);
            else if (!strcmp (av[0], "256")) bls_set_color_mode (BLS_MODE_256);
            else if (!strcmp (av[0], "truecolor")) bls_set_color_mode (BLS_MODE_TRUECOLOR);
            else { builtin_error ("colormode: 16|256|truecolor"); return EX_USAGE; }
        }
        const char *m[] = { "16", "256", "truecolor" };
        puts (m[bls_color_mode ()]);
        return btui_output ();
    }
    if (!strcmp (cmd, "timeout")) {
        if (ac < 1) { builtin_error ("timeout MS"); return EX_USAGE; }
        int ms;
        if (!btui_number (av[0], -1, INT_MAX, &ms)) goto bad_value;
        bls_timeout (ms); return EXECUTION_SUCCESS;
    }

    /* Everything below needs an active screen. Distinguish an unknown
       subcommand (usage error, rc 2) from a known draw command issued before
       init (not-initialized, rc 1) — the former must win even when !w. */
    {
        static const char *draws[] = {
            "erase", "refresh", "box", "clrtoeol", "clrtobot", "move",
            "fg", "bg", "attr", "hline", "vline", "addstr", "addansi",
            "getkey", "getstr", NULL
        };
        int known = 0;
        for (int i = 0; draws[i]; i++) if (!strcmp (cmd, draws[i])) { known = 1; break; }
        if (!known) {
            builtin_error ("unknown subcommand: %s", cmd);
            builtin_usage ();
            return EX_USAGE;
        }
    }
    if (!w) { builtin_error ("not initialized (run: tui init)"); return EXECUTION_FAILURE; }

    if (!strcmp (cmd, "erase"))    { bls_erase (w); return EXECUTION_SUCCESS; }
    if (!strcmp (cmd, "refresh"))  { return bls_refresh_checked (w) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE; }
    if (!strcmp (cmd, "box"))      { bls_box (w, 0, 0); return EXECUTION_SUCCESS; }
    if (!strcmp (cmd, "clrtoeol")) { bls_clrtoeol (w); return EXECUTION_SUCCESS; }
    if (!strcmp (cmd, "clrtobot")) { bls_clrtobot (w); return EXECUTION_SUCCESS; }
    if (!strcmp (cmd, "move")) {
        if (ac < 2) { builtin_error ("move Y X"); return EX_USAGE; }
        int y, x;
        if (!btui_number (av[0], -32768, 32767, &y) || !btui_number (av[1], -32768, 32767, &x)) goto bad_value;
        bls_move (w, y, x); return EXECUTION_SUCCESS;
    }
    if (!strcmp (cmd, "fg")) {
        if (ac < 1) { builtin_error ("fg COLOR"); return EX_USAGE; }
        int32_t c; if (!btui_color (av[0], &c)) goto bad_value;
        bls_setfg (w, c); return EXECUTION_SUCCESS;
    }
    if (!strcmp (cmd, "bg")) {
        if (ac < 1) { builtin_error ("bg COLOR"); return EX_USAGE; }
        int32_t c; if (!btui_color (av[0], &c)) goto bad_value;
        bls_setbg (w, c); return EXECUTION_SUCCESS;
    }
    if (!strcmp (cmd, "attr")) {
        unsigned a = BLS_A_NORMAL;
        for (WORD_LIST *arg = rest; arg; arg = arg->next) {
            int b = btui_attr_bit (arg->word->word);
            if (b < 0) { builtin_error ("attr: bad attribute '%s'", arg->word->word); return EX_USAGE; }
            a |= (unsigned) b;
        }
        bls_attrset (w, a); return EXECUTION_SUCCESS;
    }
    if (!strcmp (cmd, "hline") || !strcmp (cmd, "vline")) {
        uint32_t ch = 0; int n;
        if (ac == 2) { if (!btui_glyph (av[0], &ch) || !btui_number (av[1], 0, 32767, &n)) goto bad_value; }
        else if (ac == 1) { if (!btui_number (av[0], 0, 32767, &n)) goto bad_value; }
        else { builtin_error ("%s [CH] N", cmd); return EX_USAGE; }
        if (cmd[0] == 'h') bls_hline (w, ch, n); else bls_vline (w, ch, n);
        return EXECUTION_SUCCESS;
    }
    if (!strcmp (cmd, "addstr") || !strcmp (cmd, "addansi")) {
        int y = 0, x = 0, has_y = 0, has_x = 0, i = 0;
        while (i < ac && av[i][0] == '-' && av[i][1] && !av[i][2]) {
            if (av[i][1] == 'y' && i + 1 < ac) { if (!btui_number (av[++i], -32768, 32767, &y)) goto bad_value; has_y = 1; }
            else if (av[i][1] == 'x' && i + 1 < ac) { if (!btui_number (av[++i], -32768, 32767, &x)) goto bad_value; has_x = 1; }
            else if (!strcmp (av[i], "--")) { i++; break; }
            else goto bad_value;
            i++;
        }
        if (i + 1 != ac) { builtin_error ("%s [-y Y] [-x X] STR", cmd); return EX_USAGE; }
        if (has_y || has_x) {
            int cy = has_y ? y : 0, cx = has_x ? x : 0;
            bls_move (w, cy, cx);
        }
        if (!strcmp (cmd, "addansi")) bls_addstr_ansi (w, av[i], -1);
        else bls_addstr (w, av[i]);
        return EXECUTION_SUCCESS;
    }
    if (!strcmp (cmd, "getkey")) {
        int k = bls_getch ();
        if (k == BLS_KEY_NONE) return EXECUTION_FAILURE;       /* EOF */
        if (k == BLS_ERR) return 2;                            /* timeout */
        char buf[16];
        puts (btui_keyname (k, buf, sizeof buf));
        return btui_output ();
    }
    if (!strcmp (cmd, "getstr")) {
        int y = 0, x = 0, has_y = 0, has_x = 0, i = 0;
        while (i < ac && av[i][0] == '-' && av[i][1] && !av[i][2]) {
            if (av[i][1] == 'y' && i + 1 < ac) { if (!btui_number (av[++i], -32768, 32767, &y)) goto bad_value; has_y = 1; }
            else if (av[i][1] == 'x' && i + 1 < ac) { if (!btui_number (av[++i], -32768, 32767, &x)) goto bad_value; has_x = 1; }
            else if (!strcmp (av[i], "--")) { i++; break; }
            else goto bad_value;
            i++;
        }
        if (ac - i > 1) goto bad_value;
        const char *prompt = (i < ac) ? av[i] : "";
        char buf[1024];
        int r = bls_getnstr (w, has_y ? y : bls_lines () - 1, has_x ? x : 0,
                             prompt, buf, sizeof buf);
        if (r < 0) return EXECUTION_FAILURE;
        puts (buf);
        return btui_output ();
    }

bad_value:
    builtin_error ("%s: invalid argument", cmd);
    builtin_usage ();
    return EX_USAGE;
}

char *tui_doc[] = {
    "Script-facing front end to the _bl_screen TUI engine (ncurses-free).",
    "",
    "    tui SUBCOMMAND [args...]",
    "",
    "Build a full-screen, truecolor, diff-refreshed UI from a bash script with no",
    "ncurses. State persists between calls: `tui init` once, draw in a loop,",
    "`tui end` to restore the terminal.",
    "",
    "  init | end | lines | cols | resized | colormode [16|256|truecolor]",
    "  erase | move Y X | addstr [-y Y][-x X] STR | addansi STR",
    "  attr {normal|bold|dim|italic|underline|blink|reverse}...",
    "  fg COLOR | bg COLOR   (default|NAME|N|#RRGGBB|R,G,B)",
    "  hline [CH] N | vline [CH] N | box | clrtoeol | clrtobot | refresh",
    "  timeout MS | getkey | getstr [-y Y][-x X] PROMPT",
    "",
    "Coordinates: -32768..32767; line length: 0..32767; timeout: -1..INT_MAX.",
    "Use -- before text beginning with an option. Invalid arguments return 2.",
    "refresh returns 1 on output failure; restore the destination and retry.",
    "",
    "getkey prints a token (UP/DOWN/LEFT/RIGHT/HOME/END/PGUP/PGDN/RET/TAB/ESC/",
    "BS/DEL/F1..F4/C-A.. or the literal char); rc 0 key, 1 EOF, 2 timeout.",
    (char *) NULL
};

struct builtin tui_struct = {
    "tui",
    tui_builtin,
    BUILTIN_ENABLED,
    tui_doc,
    "tui SUBCOMMAND [args...]",
    0
};
