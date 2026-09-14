/* SPDX-License-Identifier: MIT */
/* mouse.c - terminal mouse event decoder for bash-os.
 *
 * Phase 3 slice from PROPOSAL_NCURSES_INPUT.md. Supports the terminal
 * encodings bash-os needs before consumer cutover: SGR 1006
 * ("\033[<b;x;yM/m"), urxvt 1015 ("\033[b;x;yM/m"), and legacy X10
 * ("\033[M Cb Cx Cy"). Decoded events are printed as stable records.
 *
 * Surface:
 *   mouse decode HEX...
 *   mouse enable [1006|1015|x10|all]
 *   mouse disable [1006|1015|x10|all]
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "loadables.h"

#define BM_MAX_BYTES 128

static int
bm_hexval (int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int
bm_parse_hex (WORD_LIST *list, unsigned char *buf, size_t *out_len)
{
  size_t n = 0;
  for (; list; list = list->next)
    {
      const char *w = list->word->word;
      size_t len = strlen (w);
      if (len >= 2 && w[0] == '0' && (w[1] == 'x' || w[1] == 'X'))
        { w += 2; len -= 2; }
      if (len == 0 || len % 2 != 0)
        return -1;
      for (size_t i = 0; i < len; i += 2)
        {
          int hi = bm_hexval ((unsigned char) w[i]);
          int lo = bm_hexval ((unsigned char) w[i + 1]);
          if (hi < 0 || lo < 0 || n >= BM_MAX_BYTES)
            return -1;
          buf[n++] = (unsigned char) ((hi << 4) | lo);
        }
    }
  *out_len = n;
  return n ? 0 : -1;
}

static const char *
bm_button_name (int b, int release)
{
  if (release) return "release";
  switch (b & 3) {
  case 0: return "button1";
  case 1: return "button2";
  case 2: return "button3";
  default: return "release";
  }
}

static const char *
bm_kind (int b, int release)
{
  if (release) return "release";
  if (b & 64) return (b & 1) ? "wheel_down" : "wheel_up";
  if (b & 32) return "drag";
  return "press";
}

static void
bm_print (const char *proto, int b, int x, int y, int release)
{
  printf ("mouse protocol=%s kind=%s button=%s x=%d y=%d mods=%s%s%s code=%d\n",
          proto, bm_kind (b, release), bm_button_name (b, release), x, y,
          (b & 4) ? "shift" : "",
          (b & 8) ? "alt" : "",
          (b & 16) ? "ctrl" : "",
          b);
}

static int
bm_parse_uint (const unsigned char *buf, size_t len, size_t *pos, int *out)
{
  int v = 0;
  size_t p = *pos;
  if (p >= len || !isdigit (buf[p]))
    return -1;
  while (p < len && isdigit (buf[p]))
    {
      v = v * 10 + (buf[p] - '0');
      p++;
      if (v > 1000000) return -1;
    }
  *pos = p;
  *out = v;
  return 0;
}

static int
bm_decode_sgr (const unsigned char *buf, size_t len)
{
  size_t p = 3;
  int b, x, y;
  if (len < 9 || buf[0] != 0x1b || buf[1] != '[' || buf[2] != '<')
    return -1;
  if (bm_parse_uint (buf, len, &p, &b) < 0 || p >= len || buf[p++] != ';')
    return -1;
  if (bm_parse_uint (buf, len, &p, &x) < 0 || p >= len || buf[p++] != ';')
    return -1;
  if (bm_parse_uint (buf, len, &p, &y) < 0 || p >= len)
    return -1;
  if (p != len - 1 || (buf[p] != 'M' && buf[p] != 'm'))
    return -1;
  bm_print ("1006", b, x, y, buf[p] == 'm');
  return 0;
}

static int
bm_decode_1015 (const unsigned char *buf, size_t len)
{
  size_t p = 2;
  int b, x, y;
  if (len < 8 || buf[0] != 0x1b || buf[1] != '[' || buf[2] == '<')
    return -1;
  if (bm_parse_uint (buf, len, &p, &b) < 0 || p >= len || buf[p++] != ';')
    return -1;
  if (bm_parse_uint (buf, len, &p, &x) < 0 || p >= len || buf[p++] != ';')
    return -1;
  if (bm_parse_uint (buf, len, &p, &y) < 0 || p >= len)
    return -1;
  if (p != len - 1 || buf[p] != 'M')
    return -1;
  bm_print ("1015", b, x, y, (b & 3) == 3);
  return 0;
}

static int
bm_decode_x10 (const unsigned char *buf, size_t len)
{
  int b, x, y;
  if (len != 6 || buf[0] != 0x1b || buf[1] != '[' || buf[2] != 'M')
    return -1;
  b = (int) buf[3] - 32;
  x = (int) buf[4] - 32;
  y = (int) buf[5] - 32;
  if (b < 0 || x < 0 || y < 0)
    return -1;
  bm_print ("x10", b, x, y, (b & 3) == 3);
  return 0;
}

static int
bm_decode (const unsigned char *buf, size_t len)
{
  if (bm_decode_sgr (buf, len) == 0) return 0;
  if (bm_decode_1015 (buf, len) == 0) return 0;
  if (bm_decode_x10 (buf, len) == 0) return 0;
  return -1;
}

static const char *
bm_next (WORD_LIST **p)
{
  if (!p || !*p) return NULL;
  const char *w = (*p)->word->word;
  *p = (*p)->next;
  return w;
}

static void
bm_mode (const char *verb, const char *mode)
{
  int enable = !strcmp (verb, "enable");
  const char *set = enable ? "h" : "l";
  if (!mode || !strcmp (mode, "all") || !strcmp (mode, "x10"))
    printf ("\033[?1000%s", set);
  if (!mode || !strcmp (mode, "all") || !strcmp (mode, "1015"))
    printf ("\033[?1015%s", set);
  if (!mode || !strcmp (mode, "all") || !strcmp (mode, "1006"))
    printf ("\033[?1006%s", set);
}

int
mouse_builtin (WORD_LIST *list)
{
  const char *cmd = bm_next (&list);
  if (!cmd || !strcmp (cmd, "--help") || !strcmp (cmd, "-h"))
    {
      builtin_usage ();
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (cmd, "decode"))
    {
      unsigned char buf[BM_MAX_BYTES];
      size_t len = 0;
      if (bm_parse_hex (list, buf, &len) < 0 || bm_decode (buf, len) < 0)
        { builtin_error ("usage: mouse decode HEX..."); return EX_USAGE; }
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (cmd, "enable") || !strcmp (cmd, "disable"))
    {
      const char *mode = bm_next (&list);
      if (list || (mode && strcmp (mode, "all") && strcmp (mode, "x10")
                   && strcmp (mode, "1006") && strcmp (mode, "1015")))
        { builtin_error ("usage: mouse %s [1006|1015|x10|all]", cmd); return EX_USAGE; }
      bm_mode (cmd, mode);
      return EXECUTION_SUCCESS;
    }

  builtin_error ("unknown command: %s", cmd);
  builtin_usage ();
  return EX_USAGE;
}

char *mouse_doc[] = {
  "Decode terminal mouse events and emit DEC mouse mode toggles.",
  "",
  "    mouse decode HEX...",
  "    mouse enable [1006|1015|x10|all]",
  "    mouse disable [1006|1015|x10|all]",
  "",
  "Decoders cover SGR 1006, urxvt 1015, and X10 mouse records.",
  (char *)NULL
};

struct builtin mouse_struct = {
  "mouse",
  mouse_builtin,
  BUILTIN_ENABLED,
  mouse_doc,
  "mouse decode HEX... | enable|disable [1006|1015|x10|all]",
  0
};
