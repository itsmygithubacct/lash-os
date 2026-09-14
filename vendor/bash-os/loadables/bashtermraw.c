/* bashtermraw.c — termios primitives + ANSI key decoder for bash.
 *
 * Lets a bash-os script build a TUI without ncurses: toggle raw mode,
 * read decoded keypresses, query terminal size, position the cursor,
 * clear lines. The state machine handles enough of the xterm/kitty
 * keypress vocabulary to cover an interactive editor or pager.
 *
 * Subcommands:
 *   bashtermraw raw                  — save current termios, set raw mode
 *                                       (no echo, no canon, VMIN=1 VTIME=0)
 *   bashtermraw cooked               — restore termios saved by `raw`,
 *                                       or fall back to a sane canonical
 *                                       default if no save
 *   bashtermraw size                 — echo "ROWS COLS" (TIOCGWINSZ)
 *   bashtermraw keypress             — read one key, echo the name
 *                                       (UP / DOWN / F1 / C-x / TAB / RET
 *                                       / ESC / BS / DEL / printable char)
 *   bashtermraw cup ROW COL          — write CSI cursor-position ANSI
 *   bashtermraw clr-eol              — write CSI K (clear to EOL)
 *   bashtermraw clr-screen           — write CSI 2J + cursor home
 *   bashtermraw clear [-x|--no-scrollback]
 *                                    — clear screen, home cursor, optionally
 *                                       erase scrollback
 *   bashtermraw reset                — RIS + recovery sequences + sane termios
 *   bashtermraw show [on|off]        — show/hide cursor (CSI ?25 h/l)
 *
 * All terminal-side writes go to /dev/tty when available so bashtermraw
 * keeps working under stdout redirection (`bashtermraw cup 5 3 > /dev/null`
 * still moves the cursor on the user-visible terminal).
 *
 * Bracketed paste (DEC private mode 2004):
 *   - `bashtermraw paste on`  emits CSI ?2004 h
 *   - `bashtermraw paste off` emits CSI ?2004 l
 *   - `bashtermraw keypress` decodes the wrap markers as
 *     PASTE-START (CSI 200~) and PASTE-END (CSI 201~)
 *
 * Limitations / non-goals at v1:
 *   - No mouse mode
 *   - keypress timeout is fixed at 50ms after ESC (long enough for a
 *     CSI sequence to arrive on a slow pty, short enough that a user
 *     pressing ESC alone gets recognized as ESC)
 *   - No SIGWINCH handler — caller traps SIGWINCH and re-reads `size`
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
 * Note: when compiled and statically linked into GNU Bash, the resulting
 * combined binary is a derivative work of bash and is governed by GPL-3+
 * (bash's license). MIT for this source file is GPL-3+-compatible.
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
#include <termios.h>
#include <sys/ioctl.h>
#include <poll.h>

#include "loadables.h"

/* --- termios state -------------------------------------------------------
 * Static save: a single saved-termios slot. Sufficient for the
 * interactive single-shell case. Multi-shell coordination is out of
 * scope; the saved state belongs to the bash process that called -raw. */
static struct termios btr_saved;
static int            btr_saved_valid = 0;

/* Pick the right fd for terminal I/O. /dev/tty is the controlling
 * terminal regardless of stdin/stdout redirection. Falls back to
 * STDIN_FILENO if /dev/tty isn't accessible (background script,
 * detached daemon, etc.). Caller must close() the returned fd when
 * done IF it's not stdin. */
static int
btr_open_tty_quiet (int *out_fd, int *out_should_close, int quiet)
{
  int fd = open ("/dev/tty", O_RDWR | O_NOCTTY);
  if (fd >= 0) { *out_fd = fd; *out_should_close = 1; return 0; }
  /* Fallback: use stdin. */
  if (isatty (STDIN_FILENO))
    { *out_fd = STDIN_FILENO; *out_should_close = 0; return 0; }
  if (!quiet)
    builtin_error ("not connected to a terminal");
  return -1;
}

static int
btr_open_tty (int *out_fd, int *out_should_close)
{
  return btr_open_tty_quiet (out_fd, out_should_close, 0);
}

static int
btr_raw (void)
{
  int fd, close_fd;
  if (btr_open_tty (&fd, &close_fd) < 0) return 1;

  struct termios cur;
  if (tcgetattr (fd, &cur) < 0)
    {
      builtin_error ("tcgetattr: %s", strerror (errno));
      if (close_fd) close (fd);
      return 1;
    }
  btr_saved = cur;
  btr_saved_valid = 1;

  /* Raw mode per cfmakeraw(3): clear ICANON, ECHO, IGNBRK, BRKINT,
     PARMRK, ISTRIP, INLCR, IGNCR, ICRNL, IXON, OPOST, ECHONL, ISIG;
     set CS8; VMIN=1, VTIME=0 (blocking byte-at-a-time read). */
  cur.c_iflag &= (tcflag_t) ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR
                              | IGNCR | ICRNL | IXON);
  cur.c_oflag &= (tcflag_t) ~(OPOST);
  cur.c_lflag &= (tcflag_t) ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
  cur.c_cflag &= (tcflag_t) ~(CSIZE | PARENB);
  cur.c_cflag |= CS8;
  cur.c_cc[VMIN] = 1;
  cur.c_cc[VTIME] = 0;
  if (tcsetattr (fd, TCSANOW, &cur) < 0)
    {
      builtin_error ("tcsetattr: %s", strerror (errno));
      if (close_fd) close (fd);
      return 1;
    }
  if (close_fd) close (fd);
  return 0;
}

static int
btr_cooked_quiet (int quiet)
{
  int fd, close_fd;
  if (btr_open_tty_quiet (&fd, &close_fd, quiet) < 0) return 1;

  struct termios target;
  if (btr_saved_valid)
    {
      target = btr_saved;
    }
  else
    {
      /* No prior raw call: synthesize a sane canonical mode. */
      if (tcgetattr (fd, &target) < 0) target = (struct termios) { 0 };
      target.c_iflag |= ICRNL | IXON | BRKINT;
      target.c_iflag &= (tcflag_t) ~(INLCR | IGNCR | ISTRIP);
      target.c_oflag |= OPOST | ONLCR;
      target.c_lflag |= ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ISIG | IEXTEN;
      target.c_cflag &= (tcflag_t) ~CSIZE;
      target.c_cflag |= CS8 | CREAD;
    }
  if (tcsetattr (fd, TCSANOW, &target) < 0)
    {
      if (!quiet)
        builtin_error ("tcsetattr: %s", strerror (errno));
      if (close_fd) close (fd);
      return 1;
    }
  if (close_fd) close (fd);
  return 0;
}

static int
btr_cooked (void)
{
  return btr_cooked_quiet (0);
}

static int
btr_size (void)
{
  int fd, close_fd;
  if (btr_open_tty (&fd, &close_fd) < 0) return 1;
  struct winsize ws;
  if (ioctl (fd, TIOCGWINSZ, &ws) < 0)
    {
      builtin_error ("ioctl(TIOCGWINSZ): %s", strerror (errno));
      if (close_fd) close (fd);
      return 1;
    }
  printf ("%u %u\n", (unsigned) ws.ws_row, (unsigned) ws.ws_col);
  if (close_fd) close (fd);
  return 0;
}

static int
btr_stty_g (void)
{
  int fd, close_fd;
  if (btr_open_tty (&fd, &close_fd) < 0) return 1;
  struct termios t;
  if (tcgetattr (fd, &t) < 0)
    {
      builtin_error ("tcgetattr: %s", strerror (errno));
      if (close_fd) close (fd);
      return 1;
    }
  struct winsize ws = {0};
  (void) ioctl (fd, TIOCGWINSZ, &ws);
  printf ("bashtermraw2:%lx:%lx:%lx:%lx:",
          (unsigned long) t.c_iflag, (unsigned long) t.c_oflag,
          (unsigned long) t.c_cflag, (unsigned long) t.c_lflag);
  for (int i = 0; i < NCCS; i++)
    {
      if (i) putchar (',');
      printf ("%u", (unsigned) t.c_cc[i]);
    }
  printf (":%lu:%lu:%u:%u\n",
          (unsigned long) cfgetispeed (&t), (unsigned long) cfgetospeed (&t),
          (unsigned) ws.ws_row, (unsigned) ws.ws_col);
  if (close_fd) close (fd);
  return 0;
}

static int
btr_parse_ulong (const char *s, int base, unsigned long *out)
{
  char *end = NULL;
  errno = 0;
  unsigned long v = strtoul (s, &end, base);
  if (errno || end == s || *end != '\0') return -1;
  *out = v;
  return 0;
}

static int
btr_stty_set (const char *state)
{
  if (!state || strncmp (state, "bashtermraw2:", 13) != 0)
    {
      builtin_error ("stty-set: unsupported state string");
      return 1;
    }

  char copy[1024];
  if (strlen (state) >= sizeof copy)
    {
      builtin_error ("stty-set: state string too long");
      return 1;
    }
  strcpy (copy, state);

  char *save = NULL;
  char *tok = strtok_r (copy, ":", &save); /* bashtermraw2 */
  unsigned long vals[8] = {0};
  for (int i = 0; i < 4; i++)
    {
      tok = strtok_r (NULL, ":", &save);
      if (!tok || btr_parse_ulong (tok, 16, &vals[i]) < 0)
        {
          builtin_error ("stty-set: malformed flag field");
          return 1;
        }
    }
  char *ccs = strtok_r (NULL, ":", &save);
  char *is = strtok_r (NULL, ":", &save);
  char *os = strtok_r (NULL, ":", &save);
  char *rows_s = strtok_r (NULL, ":", &save);
  char *cols_s = strtok_r (NULL, ":", &save);
  if (!ccs || !is || !os || !rows_s || !cols_s)
    {
      builtin_error ("stty-set: incomplete state string");
      return 1;
    }
  if (btr_parse_ulong (is, 10, &vals[4]) < 0 ||
      btr_parse_ulong (os, 10, &vals[5]) < 0 ||
      btr_parse_ulong (rows_s, 10, &vals[6]) < 0 ||
      btr_parse_ulong (cols_s, 10, &vals[7]) < 0)
    {
      builtin_error ("stty-set: malformed speed/size field");
      return 1;
    }

  int fd, close_fd;
  if (btr_open_tty (&fd, &close_fd) < 0) return 1;
  struct termios t;
  if (tcgetattr (fd, &t) < 0)
    {
      builtin_error ("tcgetattr: %s", strerror (errno));
      if (close_fd) close (fd);
      return 1;
    }
  t.c_iflag = (tcflag_t) vals[0];
  t.c_oflag = (tcflag_t) vals[1];
  t.c_cflag = (tcflag_t) vals[2];
  t.c_lflag = (tcflag_t) vals[3];

  char *ccsave = NULL;
  char *cc = strtok_r (ccs, ",", &ccsave);
  for (int i = 0; i < NCCS; i++)
    {
      unsigned long cv;
      if (!cc || btr_parse_ulong (cc, 10, &cv) < 0 || cv > 255)
        {
          builtin_error ("stty-set: malformed cc field");
          if (close_fd) close (fd);
          return 1;
        }
      t.c_cc[i] = (cc_t) cv;
      cc = strtok_r (NULL, ",", &ccsave);
    }
  (void) cfsetispeed (&t, (speed_t) vals[4]);
  (void) cfsetospeed (&t, (speed_t) vals[5]);
  if (tcsetattr (fd, TCSANOW, &t) < 0)
    {
      builtin_error ("tcsetattr: %s", strerror (errno));
      if (close_fd) close (fd);
      return 1;
    }

  if (vals[6] > 0 || vals[7] > 0)
    {
      struct winsize ws;
      memset (&ws, 0, sizeof ws);
      ws.ws_row = (unsigned short) vals[6];
      ws.ws_col = (unsigned short) vals[7];
      (void) ioctl (fd, TIOCSWINSZ, &ws);
    }
  if (close_fd) close (fd);
  return 0;
}

/* --- Keypress decoder ----------------------------------------------------
 * Reads one logical keypress event from /dev/tty (in whatever mode the
 * terminal is currently in — this builtin is most useful right after
 * `bashtermraw raw`). Decodes:
 *
 *   0x09         → TAB
 *   0x0d / 0x0a  → RET
 *   0x1b         → ESC (or start of CSI / SS3 if more bytes follow within 50ms)
 *   0x7f / 0x08  → BS
 *   0x01..0x1a   → C-a..C-z (excluding TAB, RET, ESC, BS already mapped)
 *   ESC [ A      → UP
 *   ESC [ B      → DOWN
 *   ESC [ C      → RIGHT
 *   ESC [ D      → LEFT
 *   ESC [ H      → HOME
 *   ESC [ F      → END
 *   ESC [ 1~     → HOME (some terms)
 *   ESC [ 2~     → INS
 *   ESC [ 3~     → DEL
 *   ESC [ 4~     → END (some terms)
 *   ESC [ 5~     → PGUP
 *   ESC [ 6~     → PGDN
 *   ESC [ 11~..15~ → F1..F5
 *   ESC [ 17~..21~ → F6..F10
 *   ESC [ 23~..24~ → F11..F12
 *   ESC O P/Q/R/S  → F1..F4 (xterm ss3)
 *   ESC <printable> → M-x (Alt-x)
 *   printable      → returned as-is (single char)
 *
 * Output: one line on stdout, the key name (or character).
 */

/* Read one byte with `to_ms` timeout. Returns 1 on success (byte in *out),
 * 0 on timeout, -1 on error. */
static int
btr_read_byte (int fd, int to_ms, unsigned char *out)
{
  struct pollfd pfd = { fd, POLLIN, 0 };
  int pr = poll (&pfd, 1, to_ms);
  if (pr < 0) return -1;
  if (pr == 0) return 0;
  ssize_t n = read (fd, out, 1);
  if (n == 1) return 1;
  if (n == 0) return 0;
  return -1;
}

static int
btr_keypress (void)
{
  int fd, close_fd;
  if (btr_open_tty (&fd, &close_fd) < 0) return 1;

  unsigned char b;
  /* Block on first byte. */
  ssize_t n = read (fd, &b, 1);
  if (n != 1)
    {
      if (close_fd) close (fd);
      return 1;
    }

  /* Plain control chars first. */
  if (b == 0x09) { puts ("TAB");           if (close_fd) close (fd); return 0; }
  if (b == 0x0d || b == 0x0a) { puts ("RET"); if (close_fd) close (fd); return 0; }
  if (b == 0x7f || b == 0x08) { puts ("BS"); if (close_fd) close (fd); return 0; }

  if (b == 0x1b)
    {
      /* Look for a follow-up byte within 50ms. If none, plain ESC. */
      unsigned char b2;
      int r = btr_read_byte (fd, 50, &b2);
      if (r <= 0) { puts ("ESC"); if (close_fd) close (fd); return 0; }

      if (b2 == '[' || b2 == 'O')
        {
          int csi_o = (b2 == 'O');
          /* Collect bytes until a final byte (0x40..0x7e) arrives. */
          char param[32]; size_t plen = 0;
          unsigned char fb = 0;
          for (;;)
            {
              unsigned char c;
              int rr = btr_read_byte (fd, 200, &c);
              if (rr <= 0) break;
              if (c >= 0x40 && c <= 0x7e) { fb = c; break; }
              if (plen + 1 < sizeof param) param[plen++] = (char) c;
            }
          param[plen] = '\0';

          if (csi_o)
            {
              /* SS3: ESC O <fb>. F1..F4 are P Q R S. Arrows in app mode
                 are A B C D (same as CSI). */
              switch (fb)
                {
                case 'P': puts ("F1"); break;
                case 'Q': puts ("F2"); break;
                case 'R': puts ("F3"); break;
                case 'S': puts ("F4"); break;
                case 'A': puts ("UP"); break;
                case 'B': puts ("DOWN"); break;
                case 'C': puts ("RIGHT"); break;
                case 'D': puts ("LEFT"); break;
                case 'H': puts ("HOME"); break;
                case 'F': puts ("END"); break;
                default:  printf ("SS3-%c\n", fb);
                }
              if (close_fd) close (fd);
              return 0;
            }

          /* CSI: ESC [ <param> <fb> */
          if (plen == 0)
            {
              switch (fb)
                {
                case 'A': puts ("UP"); break;
                case 'B': puts ("DOWN"); break;
                case 'C': puts ("RIGHT"); break;
                case 'D': puts ("LEFT"); break;
                case 'H': puts ("HOME"); break;
                case 'F': puts ("END"); break;
                case 'Z': puts ("S-TAB"); break;
                default:  printf ("CSI-%c\n", fb);
                }
              if (close_fd) close (fd);
              return 0;
            }

          /* CSI <num>~ — function-key family. */
          if (fb == '~')
            {
              int code = atoi (param);
              switch (code)
                {
                case  1: puts ("HOME"); break;
                case  2: puts ("INS");  break;
                case  3: puts ("DEL");  break;
                case  4: puts ("END");  break;
                case  5: puts ("PGUP"); break;
                case  6: puts ("PGDN"); break;
                case 11: puts ("F1");   break;
                case 12: puts ("F2");   break;
                case 13: puts ("F3");   break;
                case 14: puts ("F4");   break;
                case 15: puts ("F5");   break;
                case 17: puts ("F6");   break;
                case 18: puts ("F7");   break;
                case 19: puts ("F8");   break;
                case 20: puts ("F9");   break;
                case 21: puts ("F10");  break;
                case 23: puts ("F11");  break;
                case 24: puts ("F12");  break;
                /* Bracketed paste (DEC private mode 2004). The terminal
                   wraps every paste in CSI 200~ ... CSI 201~ when the
                   caller has enabled `bashtermraw paste on`. Decode
                   the delimiters so a TUI loop can switch into a
                   "accept literal characters" branch between them. */
                case 200: puts ("PASTE-START"); break;
                case 201: puts ("PASTE-END");   break;
                default: printf ("CSI-%d~\n", code);
                }
              if (close_fd) close (fd);
              return 0;
            }

          /* Modifiers: e.g. ESC [ 1;5A (C-Up). Param is "1;5", fb is 'A'.
             Best-effort decode. */
          {
            int npar1 = 0, npar2 = 0;
            sscanf (param, "%d;%d", &npar1, &npar2);
            const char *base = NULL;
            switch (fb)
              {
              case 'A': base = "UP"; break;
              case 'B': base = "DOWN"; break;
              case 'C': base = "RIGHT"; break;
              case 'D': base = "LEFT"; break;
              case 'H': base = "HOME"; break;
              case 'F': base = "END"; break;
              default:  base = NULL;
              }
            if (base && npar2 > 1)
              {
                /* Modifier code: 2=Shift, 3=Alt, 4=Shift-Alt, 5=Ctrl,
                   6=Shift-Ctrl, 7=Alt-Ctrl, 8=Shift-Alt-Ctrl. */
                const char *prefix = "";
                switch (npar2)
                  {
                  case 2: prefix = "S-"; break;
                  case 3: prefix = "M-"; break;
                  case 4: prefix = "M-S-"; break;
                  case 5: prefix = "C-"; break;
                  case 6: prefix = "C-S-"; break;
                  case 7: prefix = "C-M-"; break;
                  case 8: prefix = "C-M-S-"; break;
                  }
                printf ("%s%s\n", prefix, base);
              }
            else if (base)
              printf ("%s\n", base);
            else
              printf ("CSI-%s%c\n", param, fb);
            if (close_fd) close (fd);
            return 0;
          }
        }

      /* ESC followed by a printable: M-<char>. */
      if (b2 >= 0x20 && b2 < 0x7f)
        {
          printf ("M-%c\n", b2);
          if (close_fd) close (fd);
          return 0;
        }
      /* ESC + control char: M-C-<char>. */
      if (b2 < 0x20)
        {
          printf ("M-C-%c\n", b2 + '@');
          if (close_fd) close (fd);
          return 0;
        }
      printf ("ESC-0x%02x\n", b2);
      if (close_fd) close (fd);
      return 0;
    }

  if (b < 0x20)
    {
      /* Other Ctrl-chars: C-A..C-Z map to 0x01..0x1a. */
      printf ("C-%c\n", b + '@');
      if (close_fd) close (fd);
      return 0;
    }

  if (b < 0x7f)
    {
      /* Printable ASCII — return as-is. */
      printf ("%c\n", b);
      if (close_fd) close (fd);
      return 0;
    }

  /* High-bit byte: fragment of UTF-8 or 8-bit input. Echo as 0x.. */
  printf ("0x%02x\n", b);
  if (close_fd) close (fd);
  return 0;
}

/* --- Cursor / line manipulation ------------------------------------------ */

static int
btr_write_seq_quiet (const char *seq, int quiet)
{
  int fd, close_fd;
  if (btr_open_tty_quiet (&fd, &close_fd, quiet) < 0) return 1;
  /* In raw mode the tty doesn't translate \n→\r\n, so write as-is. */
  size_t left = strlen (seq);
  const char *p = seq;
  while (left > 0)
    {
      ssize_t w = write (fd, p, left);
      if (w < 0)
        {
          if (errno == EINTR) continue;
          if (!quiet)
            builtin_error ("write: %s", strerror (errno));
          if (close_fd) close (fd);
          return 1;
        }
      p += w;
      left -= (size_t) w;
    }
  if (close_fd) close (fd);
  return 0;
}

static int
btr_write_seq (const char *seq)
{
  return btr_write_seq_quiet (seq, 0);
}

static int
btr_cup (int row, int col)
{
  /* CSI R;C H — 1-indexed. */
  char seq[32];
  if (row < 1) row = 1;
  if (col < 1) col = 1;
  snprintf (seq, sizeof seq, "\033[%d;%dH", row, col);
  return btr_write_seq (seq);
}

static int
btr_clr_eol (void)   { return btr_write_seq ("\033[K"); }
static int
btr_clr_screen (void){ return btr_write_seq ("\033[2J\033[H"); }
static int
btr_cursor_show (int on) { return btr_write_seq (on ? "\033[?25h" : "\033[?25l"); }

/* Bracketed paste mode (DEC private mode 2004). When on, the terminal
   wraps pasted text in CSI 200~ ... CSI 201~ so a TUI can distinguish
   it from typed input. The keypress decoder surfaces these as
   PASTE-START / PASTE-END key names. */
static int
btr_bracketed_paste (int on) { return btr_write_seq (on ? "\033[?2004h" : "\033[?2004l"); }

/* clear — erase-scrollback + cursor-home + erase-display. The xterm
   E3 capability (CSI 3 J) is needed for the scrollback wipe; without
   it `clear` only blanks the visible viewport. Most modern terminals
   (xterm, gnome-terminal, kitty, alacritty, foot, st) honor it. */
static int
btr_clear (WORD_LIST *args)
{
  int scrollback = 1;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (!strcmp (w, "-x"))
        scrollback = 1;
      else if (!strcmp (w, "--no-scrollback"))
        scrollback = 0;
      else
        {
          builtin_error ("clear: unsupported option: %s", w);
          return 1;
        }
    }
  return btr_write_seq (scrollback ? "\033[3J\033[H\033[2J" : "\033[H\033[2J");
}

/* reset — RIS (Reset to Initial State, ESC c). Stronger than `clear`:
   resets character set, scrolling region, attributes, alt-screen state,
   plus everything `clear` does. Then restore sane canonical termios
   (delegates to btr_cooked, which knows the right defaults). */
static int
btr_reset (WORD_LIST *args)
{
  int quiet = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (!strcmp (w, "-q"))
        quiet = 1;
      else
        {
          builtin_error ("reset: unsupported option: %s", w);
          return 1;
        }
    }
  /* RIS first, then busybox/toybox-style recovery sequences: select
     US-ASCII G0, reset SGR, clear to end of display, show cursor, and
     explicitly re-enable autowrap for terminals that leave it off. */
  if (btr_write_seq_quiet ("\033c\033(B\033[m\033[J\033[?25h\033[?7h", quiet) != 0) return 1;
  /* Then sane termios. btr_cooked falls back to ICANON/ECHO/etc
     synthesis when no prior `raw` save exists, which is exactly what
     a from-scratch reset wants. */
  return btr_cooked_quiet (quiet);
}

/* --- bash builtin entry --------------------------------------------------- */

extern char *bashtermraw_doc[];

int
bashtermraw_builtin (WORD_LIST *list)
{
  if (list == 0)
    {
      builtin_usage ();
      return (EX_USAGE);
    }

  if (list && (!strcmp (list->word->word, "--help") || !strcmp (list->word->word, "-h")))
    {
      char *const *dp;
      for (dp = bashtermraw_doc; *dp; dp++)
        puts (*dp);
      return (EX_USAGE);
    }

  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;

  if (strcmp (cmd, "raw") == 0)        return btr_raw () == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  if (strcmp (cmd, "cooked") == 0)     return btr_cooked () == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  if (strcmp (cmd, "size") == 0)       return btr_size () == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  if (strcmp (cmd, "stty-g") == 0)     return btr_stty_g () == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  if (strcmp (cmd, "stty-set") == 0)
    {
      if (!args) { builtin_error ("stty-set: STATE argument required"); return (EX_USAGE); }
      return btr_stty_set (args->word->word) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  if (strcmp (cmd, "keypress") == 0)   return btr_keypress () == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  if (strcmp (cmd, "clr-eol") == 0)    return btr_clr_eol () == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  if (strcmp (cmd, "clr-screen") == 0) return btr_clr_screen () == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  if (strcmp (cmd, "clear") == 0)      return btr_clear (args) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
  if (strcmp (cmd, "reset") == 0)      return btr_reset (args) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;

  if (strcmp (cmd, "cup") == 0)
    {
      if (!args || !args->next)
        {
          builtin_error ("cup: ROW and COL arguments required");
          return (EX_USAGE);
        }
      int row = atoi (args->word->word);
      int col = atoi (args->next->word->word);
      return btr_cup (row, col) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  if (strcmp (cmd, "show") == 0)
    {
      int on = 1;
      if (args)
        {
          const char *v = args->word->word;
          if (strcmp (v, "off") == 0 || strcmp (v, "0") == 0) on = 0;
          else if (strcmp (v, "on") == 0 || strcmp (v, "1") == 0) on = 1;
          else { builtin_error ("show: argument must be on|off"); return (EX_USAGE); }
        }
      return btr_cursor_show (on) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  if (strcmp (cmd, "paste") == 0)
    {
      if (!args)
        {
          builtin_error ("paste: argument must be on|off");
          return (EX_USAGE);
        }
      const char *v = args->word->word;
      int on;
      if (strcmp (v, "off") == 0 || strcmp (v, "0") == 0) on = 0;
      else if (strcmp (v, "on") == 0 || strcmp (v, "1") == 0) on = 1;
      else { builtin_error ("paste: argument must be on|off"); return (EX_USAGE); }
      return btr_bracketed_paste (on) == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }

  builtin_error ("unknown subcommand: %s", cmd);
  builtin_usage ();
  return (EX_USAGE);
}

char *bashtermraw_doc[] = {
  "termios primitives + ANSI key decoder for bash-os TUI scripts.",
  "",
  "Subcommands:",
  "    raw                save current termios + switch to raw mode",
  "                       (no echo, no canon, VMIN=1 VTIME=0)",
  "    cooked             restore termios saved by `raw`, or a sane",
  "                       canonical default if none saved",
  "    size               echo \"ROWS COLS\" (TIOCGWINSZ)",
  "    stty-g             echo saveable full termios state string",
  "    stty-set STATE     restore state emitted by stty-g",
  "    keypress           read one key, echo decoded name on stdout",
  "                       (UP / DOWN / F1 / C-x / TAB / RET / ESC /",
  "                       BS / DEL / S-UP / C-LEFT / M-a / printable /",
  "                       PASTE-START / PASTE-END for bracketed paste)",
  "    cup ROW COL        write CSI cursor-position (1-indexed)",
  "    clr-eol            CSI K (clear from cursor to EOL)",
  "    clr-screen         CSI 2J + CSI H (clear screen + home)",
  "    clear [-x|--no-scrollback]",
  "                       erase-scrollback + cursor-home + erase-display",
  "                       (CSI 3J + CSI H + CSI 2J; --no-scrollback omits 3J)",
  "    reset [-q]         RIS/recovery sequences + restore sane canonical termios.",
  "                       Stronger than clear; recovers from corruption.",
  "    show [on|off]      show/hide cursor (CSI ?25 h/l), default on",
  "    paste on|off       enable/disable bracketed paste mode",
  "                       (CSI ?2004 h/l); when on, `keypress` decodes",
  "                       paste boundaries as PASTE-START / PASTE-END",
  "",
  "Terminal I/O goes to /dev/tty (or stdin if /dev/tty is unavailable),",
  "so `bashtermraw cup 5 3 > /dev/null` still moves the visible cursor.",
  "",
  "Typical TUI loop:",
  "    bashtermraw raw",
  "    trap 'bashtermraw cooked' EXIT",
  "    while k=$(bashtermraw keypress); do",
  "        case \"$k\" in",
  "            UP)    ... ;;",
  "            q)     break ;;",
  "        esac",
  "    done",
  (char *) NULL
};

struct builtin bashtermraw_struct = {
  "bashtermraw",
  bashtermraw_builtin,
  BUILTIN_ENABLED,
  bashtermraw_doc,
  "bashtermraw raw|cooked|size|stty-g|stty-set STATE|keypress|cup ROW COL|clr-eol|clr-screen|clear|reset|show [on|off]|paste on|off",
  0
};
