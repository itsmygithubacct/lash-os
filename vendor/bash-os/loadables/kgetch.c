/* SPDX-License-Identifier: MIT */
/* kgetch.c - ncurses-style key sequence matcher for bash-os.
 *
 * Phase 2 slice from PROPOSAL_NCURSES_INPUT.md. This builtin exposes a
 * small, testable key decoder without cutting existing consumers over from
 * _bl_key. It preserves the bash-os timing invariants: bare ESC gets a
 * 50 ms grace by default, and ESC-prefixed sequence matching has a total
 * cap of max(400 ms, ESCDELAY * 8).
 *
 * Surface:
 *   kgetch read [FD]       read one key from FD/stdin, print NAME CODE
 *   kgetch decode HEX...   decode hex bytes, print NAME CODE
 *   kgetch --help
 *
 * Terminfo phase-1 integration is represented by a simple fixture loader:
 * if BASHKGETCH_TERMINFO or BASHTINFO_PATH points at a text file containing
 * lines like "key_f5=\\E[15~" or "key_s_up=\\x1b[1;2A", those sequences
 * are layered over the built-in ANSI fallback table. The real tinfo
 * binary parser can later feed the same trie without changing callers.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "loadables.h"

enum {
  BK_NONE = 0,
  BK_ESC = 27,
  BK_UP = 0x101,
  BK_DOWN = 0x102,
  BK_LEFT = 0x103,
  BK_RIGHT = 0x104,
  BK_HOME = 0x105,
  BK_END = 0x106,
  BK_BS = 0x107,
  BK_RET = 0x108,
  BK_DEL = 0x109,
  BK_PGUP = 0x10a,
  BK_PGDN = 0x10b,
  BK_INS = 0x10c,
  BK_TAB = 0x10d,
  BK_F1 = 0x110,
  BK_F2 = 0x111,
  BK_F3 = 0x112,
  BK_F4 = 0x113,
  BK_F5 = 0x114,
  BK_F6 = 0x115,
  BK_F7 = 0x116,
  BK_F8 = 0x117,
  BK_F9 = 0x118,
  BK_F10 = 0x119,
  BK_F11 = 0x11a,
  BK_F12 = 0x11b,
  BK_S_UP = 0x130,
  BK_S_DOWN = 0x131,
  BK_S_LEFT = 0x132,
  BK_S_RIGHT = 0x133,
  BK_PASTE_START = 0x120,
  BK_PASTE_END = 0x121
};

typedef struct {
  unsigned char seq[64];
  size_t len;
  int code;
  char name[32];
} bk_entry;

static bk_entry bk_entries[160];
static size_t bk_nentries;
static int bk_loaded;

static long
bk_now_ms (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static int
bk_read_to (int fd, int ms, unsigned char *out)
{
  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN;
  pfd.revents = 0;
  int pr = poll (&pfd, 1, ms);
  if (pr <= 0)
    return pr;
  ssize_t n;
  do
    n = read (fd, out, 1);
  while (n < 0 && errno == EINTR);
  return n == 1 ? 1 : -1;
}

static int
bk_code_for_name (const char *name)
{
  if (!strcmp (name, "key_up")) return BK_UP;
  if (!strcmp (name, "key_down")) return BK_DOWN;
  if (!strcmp (name, "key_left")) return BK_LEFT;
  if (!strcmp (name, "key_right")) return BK_RIGHT;
  if (!strcmp (name, "key_home")) return BK_HOME;
  if (!strcmp (name, "key_end")) return BK_END;
  if (!strcmp (name, "key_dc")) return BK_DEL;
  if (!strcmp (name, "key_ppage")) return BK_PGUP;
  if (!strcmp (name, "key_npage")) return BK_PGDN;
  if (!strcmp (name, "key_ic")) return BK_INS;
  if (!strcmp (name, "key_f1")) return BK_F1;
  if (!strcmp (name, "key_f2")) return BK_F2;
  if (!strcmp (name, "key_f3")) return BK_F3;
  if (!strcmp (name, "key_f4")) return BK_F4;
  if (!strcmp (name, "key_f5")) return BK_F5;
  if (!strcmp (name, "key_f6")) return BK_F6;
  if (!strcmp (name, "key_f7")) return BK_F7;
  if (!strcmp (name, "key_f8")) return BK_F8;
  if (!strcmp (name, "key_f9")) return BK_F9;
  if (!strcmp (name, "key_f10")) return BK_F10;
  if (!strcmp (name, "key_f11")) return BK_F11;
  if (!strcmp (name, "key_f12")) return BK_F12;
  if (!strcmp (name, "key_s_up")) return BK_S_UP;
  if (!strcmp (name, "key_s_down")) return BK_S_DOWN;
  if (!strcmp (name, "key_s_left")) return BK_S_LEFT;
  if (!strcmp (name, "key_s_right")) return BK_S_RIGHT;
  if (!strcmp (name, "paste_start")) return BK_PASTE_START;
  if (!strcmp (name, "paste_end")) return BK_PASTE_END;
  return 0;
}

static const char *
bk_name_for_code (int code)
{
  for (size_t i = 0; i < bk_nentries; i++)
    if (bk_entries[i].code == code)
      return bk_entries[i].name;
  switch (code) {
  case BK_NONE: return "none";
  case BK_ESC: return "esc";
  case BK_BS: return "backspace";
  case BK_RET: return "enter";
  case BK_TAB: return "tab";
  default: return "char";
  }
}

static int
bk_add (const char *name, int code, const unsigned char *seq, size_t len)
{
  if (!name || !seq || len == 0 || len > sizeof bk_entries[0].seq
      || bk_nentries >= sizeof bk_entries / sizeof bk_entries[0])
    return -1;
  bk_entry *e = &bk_entries[bk_nentries++];
  memset (e, 0, sizeof *e);
  memcpy (e->seq, seq, len);
  e->len = len;
  e->code = code;
  snprintf (e->name, sizeof e->name, "%s", name);
  return 0;
}

static void
bk_add_lit (const char *name, int code, const char *seq)
{
  (void) bk_add (name, code, (const unsigned char *) seq, strlen (seq));
}

static int
hexval (int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static size_t
bk_unescape (const char *s, unsigned char *out, size_t cap)
{
  size_t n = 0;
  for (size_t i = 0; s[i] && n < cap; i++)
    {
      if (s[i] == '\\')
        {
          if (s[i + 1] == 'E' || s[i + 1] == 'e')
            { out[n++] = 0x1b; i++; continue; }
          if (s[i + 1] == 'n')
            { out[n++] = '\n'; i++; continue; }
          if (s[i + 1] == 'r')
            { out[n++] = '\r'; i++; continue; }
          if (s[i + 1] == 't')
            { out[n++] = '\t'; i++; continue; }
          if (s[i + 1] == 'x' && hexval ((unsigned char) s[i + 2]) >= 0
              && hexval ((unsigned char) s[i + 3]) >= 0)
            {
              out[n++] = (unsigned char) ((hexval ((unsigned char) s[i + 2]) << 4)
                                          | hexval ((unsigned char) s[i + 3]));
              i += 3;
              continue;
            }
          if (s[i + 1])
            { out[n++] = (unsigned char) s[++i]; continue; }
        }
      if (s[i] == '^' && s[i + 1] == '[')
        { out[n++] = 0x1b; i++; continue; }
      out[n++] = (unsigned char) s[i];
    }
  return n;
}

static void
bk_load_fixture (const char *path)
{
  if (!path || !*path)
    return;
  FILE *fp = fopen (path, "r");
  if (!fp)
    return;
  char line[512];
  while (fgets (line, sizeof line, fp))
    {
      char *p = line;
      while (isspace ((unsigned char) *p)) p++;
      if (*p == '\0' || *p == '#') continue;
      char *eq = strchr (p, '=');
      if (!eq) continue;
      *eq++ = '\0';
      char *name = p;
      char *end = name + strlen (name);
      while (end > name && isspace ((unsigned char) end[-1])) *--end = '\0';
      while (isspace ((unsigned char) *eq)) eq++;
      char *ve = eq + strlen (eq);
      while (ve > eq && (ve[-1] == '\n' || ve[-1] == '\r'
                         || isspace ((unsigned char) ve[-1]))) *--ve = '\0';
      int code = bk_code_for_name (name);
      if (!code) continue;
      unsigned char seq[64];
      size_t len = bk_unescape (eq, seq, sizeof seq);
      if (len) bk_add (name, code, seq, len);
    }
  fclose (fp);
}

static void
bk_load_entries (void)
{
  if (bk_loaded)
    return;
  bk_loaded = 1;

  bk_add_lit ("key_up", BK_UP, "\033[A");
  bk_add_lit ("key_down", BK_DOWN, "\033[B");
  bk_add_lit ("key_right", BK_RIGHT, "\033[C");
  bk_add_lit ("key_left", BK_LEFT, "\033[D");
  bk_add_lit ("key_home", BK_HOME, "\033[H");
  bk_add_lit ("key_end", BK_END, "\033[F");
  bk_add_lit ("key_f1", BK_F1, "\033OP");
  bk_add_lit ("key_f2", BK_F2, "\033OQ");
  bk_add_lit ("key_f3", BK_F3, "\033OR");
  bk_add_lit ("key_f4", BK_F4, "\033OS");
  bk_add_lit ("key_home", BK_HOME, "\033[1~");
  bk_add_lit ("key_ic", BK_INS, "\033[2~");
  bk_add_lit ("key_dc", BK_DEL, "\033[3~");
  bk_add_lit ("key_end", BK_END, "\033[4~");
  bk_add_lit ("key_ppage", BK_PGUP, "\033[5~");
  bk_add_lit ("key_npage", BK_PGDN, "\033[6~");
  bk_add_lit ("key_f1", BK_F1, "\033[11~");
  bk_add_lit ("key_f2", BK_F2, "\033[12~");
  bk_add_lit ("key_f3", BK_F3, "\033[13~");
  bk_add_lit ("key_f4", BK_F4, "\033[14~");
  bk_add_lit ("key_f5", BK_F5, "\033[15~");
  bk_add_lit ("key_f6", BK_F6, "\033[17~");
  bk_add_lit ("key_f7", BK_F7, "\033[18~");
  bk_add_lit ("key_f8", BK_F8, "\033[19~");
  bk_add_lit ("key_f9", BK_F9, "\033[20~");
  bk_add_lit ("key_f10", BK_F10, "\033[21~");
  bk_add_lit ("key_f11", BK_F11, "\033[23~");
  bk_add_lit ("key_f12", BK_F12, "\033[24~");
  bk_add_lit ("key_s_up", BK_S_UP, "\033[1;2A");
  bk_add_lit ("key_s_down", BK_S_DOWN, "\033[1;2B");
  bk_add_lit ("key_s_right", BK_S_RIGHT, "\033[1;2C");
  bk_add_lit ("key_s_left", BK_S_LEFT, "\033[1;2D");
  bk_add_lit ("paste_start", BK_PASTE_START, "\033[200~");
  bk_add_lit ("paste_end", BK_PASTE_END, "\033[201~");

  bk_load_fixture (getenv ("BASHKGETCH_TERMINFO"));
  bk_load_fixture (getenv ("BASHTINFO_PATH"));
}

static int
bk_has_prefix (const unsigned char *buf, size_t len)
{
  for (size_t i = 0; i < bk_nentries; i++)
    if (bk_entries[i].len >= len && memcmp (bk_entries[i].seq, buf, len) == 0)
      return 1;
  return 0;
}

static int
bk_exact (const unsigned char *buf, size_t len)
{
  for (size_t i = bk_nentries; i > 0; i--)
    if (bk_entries[i - 1].len == len && memcmp (bk_entries[i - 1].seq, buf, len) == 0)
      return bk_entries[i - 1].code;
  return 0;
}

static int
bk_has_longer (const unsigned char *buf, size_t len)
{
  for (size_t i = 0; i < bk_nentries; i++)
    if (bk_entries[i].len > len && memcmp (bk_entries[i].seq, buf, len) == 0)
      return 1;
  return 0;
}

static int
bk_decode_buf (const unsigned char *buf, size_t len)
{
  if (len == 0) return BK_NONE;
  if (len == 1)
    {
      if (buf[0] == 0x1b) return BK_ESC;
      if (buf[0] == 0x7f || buf[0] == 0x08) return BK_BS;
      if (buf[0] == 0x0d || buf[0] == 0x0a) return BK_RET;
      if (buf[0] == 0x09) return BK_TAB;
      return (int) buf[0];
    }
  int code = bk_exact (buf, len);
  return code ? code : BK_ESC;
}

static int
bk_read_key (int fd)
{
  unsigned char b;
  ssize_t n;
  do
    n = read (fd, &b, 1);
  while (n < 0 && errno == EINTR);
  if (n <= 0) return BK_NONE;
  if (b != 0x1b)
    return bk_decode_buf (&b, 1);

  int escdelay = 50;
  const char *ed = getenv ("BASHESCDELAY");
  if (!ed || !*ed) ed = getenv ("BASHKGETCH_ESCDELAY");
  if (ed && *ed)
    {
      char *end = NULL;
      long v = strtol (ed, &end, 10);
      if (end && *end == '\0' && v >= 0 && v <= 5000)
        escdelay = (int) v;
    }
  int cap = escdelay * 8;
  if (cap < 400) cap = 400;

  unsigned char seq[64];
  size_t len = 0;
  seq[len++] = b;
  if (bk_read_to (fd, escdelay, &b) <= 0)
    return BK_ESC;
  seq[len++] = b;

  long start = bk_now_ms ();
  for (;;)
    {
      int exact = bk_exact (seq, len);
      if (exact && !bk_has_longer (seq, len))
        return exact;
      if (!bk_has_prefix (seq, len))
        return exact ? exact : BK_ESC;
      long elapsed = bk_now_ms () - start;
      if (elapsed >= cap)
        return BK_ESC;
      if (len >= sizeof seq)
        return exact ? exact : BK_ESC;
      int rem = cap - (int) elapsed;
      int slice = rem < 50 ? rem : 50;
      if (bk_read_to (fd, slice, &b) <= 0)
        return exact ? exact : BK_ESC;
      seq[len++] = b;
    }
}

static void
bk_print (int code)
{
  printf ("%s %d\n", bk_name_for_code (code), code);
}

static int
parse_hex_args (WORD_LIST *list, unsigned char *buf, size_t *out_len)
{
  size_t n = 0;
  for (; list; list = list->next)
    {
      const char *w = list->word->word;
      size_t len = strlen (w);
      if (len == 0) continue;
      if (len >= 2 && w[0] == '0' && (w[1] == 'x' || w[1] == 'X'))
        { w += 2; len -= 2; }
      if (len == 2)
        {
          int hi = hexval ((unsigned char) w[0]);
          int lo = hexval ((unsigned char) w[1]);
          if (hi < 0 || lo < 0 || n >= 64) return -1;
          buf[n++] = (unsigned char) ((hi << 4) | lo);
        }
      else
        {
          if (len % 2 != 0) return -1;
          for (size_t i = 0; i < len; i += 2)
            {
              int hi = hexval ((unsigned char) w[i]);
              int lo = hexval ((unsigned char) w[i + 1]);
              if (hi < 0 || lo < 0 || n >= 64) return -1;
              buf[n++] = (unsigned char) ((hi << 4) | lo);
            }
        }
    }
  *out_len = n;
  return 0;
}

static const char *
bk_nw (WORD_LIST **p)
{
  if (!p || !*p) return NULL;
  const char *w = (*p)->word->word;
  *p = (*p)->next;
  return w;
}

int
kgetch_builtin (WORD_LIST *list)
{
  bk_load_entries ();
  const char *cmd = bk_nw (&list);
  if (!cmd || !strcmp (cmd, "--help") || !strcmp (cmd, "-h"))
    {
      builtin_usage ();
      return EXECUTION_SUCCESS;
    }
  if (!strcmp (cmd, "decode"))
    {
      unsigned char buf[64];
      size_t len = 0;
      if (parse_hex_args (list, buf, &len) < 0 || len == 0)
        { builtin_error ("usage: kgetch decode HEX..."); return EX_USAGE; }
      bk_print (bk_decode_buf (buf, len));
      return EXECUTION_SUCCESS;
    }
  if (!strcmp (cmd, "read"))
    {
      int fd = STDIN_FILENO;
      const char *fd_s = bk_nw (&list);
      if (fd_s)
        {
          char *end = NULL;
          long v = strtol (fd_s, &end, 10);
          if (!end || *end || v < 0 || v > 1024 || list)
            { builtin_error ("usage: kgetch read [FD]"); return EX_USAGE; }
          fd = (int) v;
        }
      bk_print (bk_read_key (fd));
      return EXECUTION_SUCCESS;
    }
  builtin_error ("unknown command: %s", cmd);
  builtin_usage ();
  return EX_USAGE;
}

char *kgetch_doc[] = {
  "Decode one terminal key using a terminfo-style trie.",
  "",
  "    kgetch read [FD]",
  "    kgetch decode HEX...",
  "",
  "Defaults preserve bash-os input timing: ESC grace is 50 ms and",
  "ESC-prefixed matching has total cap max(400 ms, ESCDELAY*8).",
  "BASHKGETCH_TERMINFO or BASHTINFO_PATH may name a text fixture with",
  "key_* escape strings layered over the ANSI fallback table.",
  (char *)NULL
};

struct builtin kgetch_struct = {
  "kgetch",
  kgetch_builtin,
  BUILTIN_ENABLED,
  kgetch_doc,
  "kgetch read [FD] | kgetch decode HEX...",
  0
};
