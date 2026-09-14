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

#include "_bl_screen_screen.h"
#include "_bl_key_bl_key.h"
#include "loadables.h"

static int32_t
btui_color (const char *s)
{
    if (!s || !strcmp (s, "default")) return BLS_DEFAULT;
    if (s[0] == '#' && strlen (s) == 7) {
        unsigned r, g, b;
        if (sscanf (s + 1, "%2x%2x%2x", &r, &g, &b) == 3) return BLS_RGB (r, g, b);
    }
    if (strchr (s, ',')) {
        int r, g, b;
        if (sscanf (s, "%d,%d,%d", &r, &g, &b) == 3) return BLS_RGB (r, g, b);
    }
    static const char *nm[] = { "black","red","green","yellow","blue","magenta","cyan","white" };
    for (int i = 0; i < 8; i++) if (!strcmp (s, nm[i])) return BLS_PALETTE (i);
    char *e; long v = strtol (s, &e, 10);
    if (e != s && !*e && v >= 0 && v <= 255) return BLS_PALETTE ((int) v);
    return BLS_DEFAULT;
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
    return n;
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

    if (!strcmp (cmd, "init"))
        return bls_init () == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    if (!strcmp (cmd, "end"))      { bls_end (); return EXECUTION_SUCCESS; }
    if (!strcmp (cmd, "lines"))    { printf ("%d\n", bls_lines ()); return EXECUTION_SUCCESS; }
    if (!strcmp (cmd, "cols"))     { printf ("%d\n", bls_cols ()); return EXECUTION_SUCCESS; }
    if (!strcmp (cmd, "resized")) {
        int r = bls_resized (); printf ("%d\n", r);
        return r ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
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
        return EXECUTION_SUCCESS;
    }
    if (!strcmp (cmd, "timeout")) {
        if (ac < 1) { builtin_error ("timeout MS"); return EX_USAGE; }
        bls_timeout (atoi (av[0])); return EXECUTION_SUCCESS;
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
    if (!strcmp (cmd, "refresh"))  { bls_refresh (w); return EXECUTION_SUCCESS; }
    if (!strcmp (cmd, "box"))      { bls_box (w, 0, 0); return EXECUTION_SUCCESS; }
    if (!strcmp (cmd, "clrtoeol")) { bls_clrtoeol (w); return EXECUTION_SUCCESS; }
    if (!strcmp (cmd, "clrtobot")) { bls_clrtobot (w); return EXECUTION_SUCCESS; }
    if (!strcmp (cmd, "move")) {
        if (ac < 2) { builtin_error ("move Y X"); return EX_USAGE; }
        bls_move (w, atoi (av[0]), atoi (av[1])); return EXECUTION_SUCCESS;
    }
    if (!strcmp (cmd, "fg")) {
        if (ac < 1) { builtin_error ("fg COLOR"); return EX_USAGE; }
        bls_setfg (w, btui_color (av[0])); return EXECUTION_SUCCESS;
    }
    if (!strcmp (cmd, "bg")) {
        if (ac < 1) { builtin_error ("bg COLOR"); return EX_USAGE; }
        bls_setbg (w, btui_color (av[0])); return EXECUTION_SUCCESS;
    }
    if (!strcmp (cmd, "attr")) {
        unsigned a = BLS_A_NORMAL;
        for (int i = 0; i < ac; i++) {
            int b = btui_attr_bit (av[i]);
            if (b < 0) { builtin_error ("attr: bad attribute '%s'", av[i]); return EX_USAGE; }
            a |= (unsigned) b;
        }
        bls_attrset (w, a); return EXECUTION_SUCCESS;
    }
    if (!strcmp (cmd, "hline") || !strcmp (cmd, "vline")) {
        uint32_t ch = 0; int n;
        if (ac >= 2) { ch = (uint32_t) (unsigned char) av[0][0]; n = atoi (av[1]); }
        else if (ac == 1) { n = atoi (av[0]); }
        else { builtin_error ("%s [CH] N", cmd); return EX_USAGE; }
        if (cmd[0] == 'h') bls_hline (w, ch, n); else bls_vline (w, ch, n);
        return EXECUTION_SUCCESS;
    }
    if (!strcmp (cmd, "addstr") || !strcmp (cmd, "addansi")) {
        int y = -1, x = -1, i = 0;
        while (i < ac && av[i][0] == '-' && av[i][1] && !av[i][2]) {
            if (av[i][1] == 'y' && i + 1 < ac) { y = atoi (av[++i]); }
            else if (av[i][1] == 'x' && i + 1 < ac) { x = atoi (av[++i]); }
            else break;
            i++;
        }
        if (i >= ac) { builtin_error ("%s [-y Y] [-x X] STR", cmd); return EX_USAGE; }
        if (y >= 0 || x >= 0) {
            int cy = y >= 0 ? y : 0, cx = x >= 0 ? x : 0;
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
        return EXECUTION_SUCCESS;
    }
    if (!strcmp (cmd, "getstr")) {
        int y = -1, x = -1, i = 0;
        while (i < ac && av[i][0] == '-' && av[i][1] && !av[i][2]) {
            if (av[i][1] == 'y' && i + 1 < ac) { y = atoi (av[++i]); }
            else if (av[i][1] == 'x' && i + 1 < ac) { x = atoi (av[++i]); }
            else break;
            i++;
        }
        const char *prompt = (i < ac) ? av[i] : "";
        char buf[1024];
        int r = bls_getnstr (w, y >= 0 ? y : bls_lines () - 1, x >= 0 ? x : 0,
                             prompt, buf, sizeof buf);
        if (r < 0) return EXECUTION_FAILURE;
        puts (buf);
        return EXECUTION_SUCCESS;
    }

    builtin_error ("unknown subcommand: %s", cmd);
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
