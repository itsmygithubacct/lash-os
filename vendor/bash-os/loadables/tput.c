/* SPDX-License-Identifier: MIT */
/* tput.c - small terminfo-shaped capability builtin for bash-os.
 *
 * This is Stage 45.B's compact v1 surface: a curated ANSI/xterm
 * capability table for the terminal names bash-os actually ships with.
 * Operators can add simple key=value terminal sidecars without pulling
 * in the full compiled terminfo database parser.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>

#include "loadables.h"

#define BTP_MAX_SIDE_CAPS 96
#define BTP_MAX_NAME 64
#define BTP_MAX_VALUE 256
#define BTP_DEFAULT_DIR "/etc/bash-os/terminfo.d"
#define BTP_COMPAT_DIR "/etc/bash-os/terminfo"

static const char *terms[] = {
  "xterm-256color", "xterm", "screen-256color", "tmux-256color", "linux", "vt100", "dumb", NULL
};

static const char *caps[] = {
  "clear", "home", "cup", "cuu", "cud", "cuf", "cub", "el", "el1", "ed",
  "bold", "smso", "dim", "smul", "rmul", "rev", "blink", "invis", "sgr0",
  "sgr", "sitm", "ritm", "setaf", "setab", "civis", "cnorm", "smcup",
  "rmcup", "smkx", "rmkx", "smacs", "rmacs", "acsc", "sc", "rc",
  "hpa", "vpa", "ich", "dch", "dl", "il", "kf1", "kf2", "kf3", "kf4",
  "kf5", "kf6", "kf7", "kf8", "kf9", "kf10", "kf11", "kf12", "cols",
  "lines", "colors", "longname", "reset", "init", NULL
};

typedef struct {
  char key[BTP_MAX_NAME];
  char val[BTP_MAX_VALUE];
} sidecap;

typedef struct {
  int loaded;
  int found;
  int ncap;
  char name[BTP_MAX_NAME];
  sidecap caps[BTP_MAX_SIDE_CAPS];
} sideterm;

static int
safe_term_name (const char *term)
{
  const unsigned char *p = (const unsigned char *) term;
  if (!term || !*term || strlen (term) >= BTP_MAX_NAME)
    return 0;
  for (; *p; p++)
    if (!(isalnum (*p) || *p == '-' || *p == '_' || *p == '.' || *p == '+'))
      return 0;
  return 1;
}

static char *
trim_ws (char *s)
{
  char *e;
  while (*s && isspace ((unsigned char) *s))
    s++;
  e = s + strlen (s);
  while (e > s && isspace ((unsigned char) e[-1]))
    *--e = '\0';
  return s;
}

static int
hexval (int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static void
decode_escapes (const char *in, char *out, size_t outsz)
{
  size_t o = 0;
  while (*in && o + 1 < outsz)
    {
      if (*in == '\\')
        {
          int h1, h2;
          in++;
          if (!*in) break;
          switch (*in)
            {
            case 'E': case 'e': out[o++] = '\033'; in++; continue;
            case 'n': out[o++] = '\n'; in++; continue;
            case 'r': out[o++] = '\r'; in++; continue;
            case 't': out[o++] = '\t'; in++; continue;
            case 'b': out[o++] = '\b'; in++; continue;
            case 'f': out[o++] = '\f'; in++; continue;
            case '\\': out[o++] = '\\'; in++; continue;
            case 'x':
              h1 = hexval ((unsigned char) in[1]);
              h2 = hexval ((unsigned char) in[2]);
              if (h1 >= 0 && h2 >= 0)
                {
                  out[o++] = (char) ((h1 << 4) | h2);
                  in += 3;
                  continue;
                }
              break;
            }
        }
      out[o++] = *in++;
    }
  out[o] = '\0';
}

static const char *
side_dir_primary (void)
{
  const char *d = getenv ("BASHTPUT_TERMINFO_DIR");
  return (d && *d) ? d : BTP_DEFAULT_DIR;
}

static int
load_side_from_dir (sideterm *st, const char *dir, const char *term)
{
  char path[512], line[512];
  FILE *f;
  int saw_name = 0;
  snprintf (path, sizeof path, "%s/%s", dir, term);
  f = fopen (path, "r");
  if (!f)
    return 0;
  st->found = 1;
  snprintf (st->name, sizeof st->name, "%s", term);
  while (fgets (line, sizeof line, f))
    {
      char *s = trim_ws (line);
      char *eq, *key, *val;
      if (!*s || *s == '#')
        continue;
      eq = strchr (s, '=');
      if (!eq)
        continue;
      *eq = '\0';
      key = trim_ws (s);
      val = trim_ws (eq + 1);
      if (!safe_term_name (key))
        continue;
      if (!strcmp (key, "name"))
        {
          snprintf (st->name, sizeof st->name, "%s", val);
          saw_name = 1;
          continue;
        }
      if (st->ncap < BTP_MAX_SIDE_CAPS)
        {
          snprintf (st->caps[st->ncap].key, sizeof st->caps[st->ncap].key, "%s", key);
          decode_escapes (val, st->caps[st->ncap].val, sizeof st->caps[st->ncap].val);
          st->ncap++;
        }
    }
  fclose (f);
  if (!saw_name)
    snprintf (st->name, sizeof st->name, "%s", term);
  return 1;
}

static int
load_side_term (sideterm *st, const char *term)
{
  memset (st, 0, sizeof *st);
  st->loaded = 1;
  if (!safe_term_name (term))
    return 0;
  if (load_side_from_dir (st, side_dir_primary (), term))
    return 1;
  if (strcmp (side_dir_primary (), BTP_COMPAT_DIR) &&
      load_side_from_dir (st, BTP_COMPAT_DIR, term))
    return 1;
  return 0;
}

static const char *
side_lookup (const sideterm *st, const char *cap)
{
  int i;
  if (!st || !st->found || !cap)
    return NULL;
  for (i = 0; i < st->ncap; i++)
    if (!strcmp (st->caps[i].key, cap))
      return st->caps[i].val;
  return NULL;
}

static int
known_term (const char *term)
{
  int i;
  if (!term || !*term) return 1;
  for (i = 0; terms[i]; i++)
    if (!strcmp (term, terms[i])) return 1;
  return 0;
}

static int
known_cap (const char *cap)
{
  int i;
  if (!cap) return 0;
  for (i = 0; caps[i]; i++)
    if (!strcmp (cap, caps[i])) return 1;
  if (!strcmp (cap, "clear_screen") || !strcmp (cap, "cursor_home")
      || !strcmp (cap, "cursor_address") || !strcmp (cap, "cursor_up")
      || !strcmp (cap, "cursor_down") || !strcmp (cap, "cursor_right")
      || !strcmp (cap, "cursor_left") || !strcmp (cap, "clr_eol")
      || !strcmp (cap, "clr_bol") || !strcmp (cap, "clr_eos")
      || !strcmp (cap, "rmso") || !strcmp (cap, "enter_standout_mode")
      || !strcmp (cap, "exit_standout_mode") || !strcmp (cap, "enter_bold_mode")
      || !strcmp (cap, "enter_italics_mode") || !strcmp (cap, "exit_italics_mode")
      || !strcmp (cap, "save_cursor") || !strcmp (cap, "restore_cursor")
      || !strcmp (cap, "parm_ich") || !strcmp (cap, "parm_dch")
      || !strcmp (cap, "parm_delete_line") || !strcmp (cap, "parm_insert_line")
      || !strcmp (cap, "column_address") || !strcmp (cap, "row_address")
      || !strcmp (cap, "key_f1") || !strcmp (cap, "key_f2")
      || !strcmp (cap, "key_f3") || !strcmp (cap, "key_f4")
      || !strcmp (cap, "key_f5") || !strcmp (cap, "key_f6")
      || !strcmp (cap, "key_f7") || !strcmp (cap, "key_f8")
      || !strcmp (cap, "key_f9") || !strcmp (cap, "key_f10")
      || !strcmp (cap, "key_f11") || !strcmp (cap, "key_f12")
      || !strcmp (cap, "columns") || !strcmp (cap, "rows"))
    return 1;
  return 0;
}

static int
side_known_cap (const char *term, const char *cap)
{
  sideterm st;
  if (!term || !*term || !cap)
    return 0;
  return load_side_term (&st, term) && side_lookup (&st, cap) != NULL;
}

static int
bind_or_print (const char *var, const char *s, int newline)
{
  if (var)
    {
      builtin_bind_variable ((char *) var, (char *) s, 0);
      return EXECUTION_SUCCESS;
    }
  fputs (s, stdout);
  if (newline) putchar ('\n');
  return EXECUTION_SUCCESS;
}

static int
side_expand (const char *tmpl, WORD_LIST *args, char *out, size_t outsz)
{
  int p[9] = {0};
  int i = 0, inc = 0;
  size_t o = 0;
  while (args && i < 9)
    {
      p[i++] = atoi (args->word->word);
      args = args->next;
    }
  for (i = 0; i < 9; i++)
    p[i] += inc;
  while (*tmpl && o + 1 < outsz)
    {
      if (*tmpl == '%' && tmpl[1])
        {
          tmpl++;
          if (*tmpl == 'i')
            {
              int j;
              inc = 1;
              for (j = 0; j < 9; j++)
                p[j]++;
              tmpl++;
              continue;
            }
          if (*tmpl == 'p' && tmpl[1] >= '1' && tmpl[1] <= '9')
            {
              int idx = tmpl[1] - '1';
              tmpl += 2;
              if (*tmpl == '%' && tmpl[1] == 'd')
                {
                  int n = snprintf (out + o, outsz - o, "%d", p[idx]);
                  if (n < 0) return -1;
                  o += (size_t) n;
                  if (o >= outsz) o = outsz - 1;
                  tmpl += 2;
                  continue;
                }
            }
          if (*tmpl == '%')
            {
              out[o++] = *tmpl++;
              continue;
            }
        }
      out[o++] = *tmpl++;
    }
  out[o] = '\0';
  return 0;
}

static int
emit_side_cap (const sideterm *st, const char *cap, WORD_LIST *args,
               const char *var)
{
  char buf[512];
  const char *tmpl = side_lookup (st, cap);
  if (!tmpl)
    return -1;
  if (side_expand (tmpl, args, buf, sizeof buf) < 0)
    return EX_USAGE;
  return bind_or_print (var, buf, 0);
}

extern char *tput_doc[];   /* forward decl */

static int
emit_cap (const char *cap, WORD_LIST *args, const char *var, const char *term)
{
  char buf[128];
  int n, r, c;
  sideterm st;

  memset (&st, 0, sizeof st);
  if (!term || !*term)
    term = "xterm-256color";
  if (!known_term (term) && !load_side_term (&st, term))
    {
      fprintf (stderr, "tput: unknown terminal: %s\n", term ? term : "");
      return 3;
    }
  if (st.found)
    {
      int rc = emit_side_cap (&st, cap, args, var);
      if (rc >= 0)
        return rc;
    }
  if (!strcmp (term, "dumb") && strcmp (cap, "cols") && strcmp (cap, "lines")
      && strcmp (cap, "colors") && strcmp (cap, "longname"))
    return bind_or_print (var, "", 0);

  if (!strcmp (cap, "clear") || !strcmp (cap, "clear_screen"))
    return bind_or_print (var, "\033[2J\033[H", 0);
  if (!strcmp (cap, "reset") || !strcmp (cap, "init"))
    return bind_or_print (var, "\033[0m\033[2J\033[H", 0);
  if (!strcmp (cap, "home") || !strcmp (cap, "cursor_home"))
    return bind_or_print (var, "\033[H", 0);
  if (!strcmp (cap, "cup") || !strcmp (cap, "cursor_address"))
    {
      if (!args || !args->next) { builtin_error ("cup needs ROW COL"); return EX_USAGE; }
      r = atoi (args->word->word);
      c = atoi (args->next->word->word);
      snprintf (buf, sizeof buf, "\033[%d;%dH", r + 1, c + 1);
      return bind_or_print (var, buf, 0);
    }
  if (!strcmp (cap, "cuu") || !strcmp (cap, "cursor_up"))
    { n = args ? atoi (args->word->word) : 1; snprintf (buf, sizeof buf, "\033[%dA", n); return bind_or_print (var, buf, 0); }
  if (!strcmp (cap, "cud") || !strcmp (cap, "cursor_down"))
    { n = args ? atoi (args->word->word) : 1; snprintf (buf, sizeof buf, "\033[%dB", n); return bind_or_print (var, buf, 0); }
  if (!strcmp (cap, "cuf") || !strcmp (cap, "cursor_right"))
    { n = args ? atoi (args->word->word) : 1; snprintf (buf, sizeof buf, "\033[%dC", n); return bind_or_print (var, buf, 0); }
  if (!strcmp (cap, "cub") || !strcmp (cap, "cursor_left"))
    { n = args ? atoi (args->word->word) : 1; snprintf (buf, sizeof buf, "\033[%dD", n); return bind_or_print (var, buf, 0); }
  if (!strcmp (cap, "el") || !strcmp (cap, "clr_eol"))
    return bind_or_print (var, "\033[K", 0);
  if (!strcmp (cap, "el1") || !strcmp (cap, "clr_bol"))
    return bind_or_print (var, "\033[1K", 0);
  if (!strcmp (cap, "ed") || !strcmp (cap, "clr_eos"))
    return bind_or_print (var, "\033[J", 0);
  if (!strcmp (cap, "bold") || !strcmp (cap, "smso"))
    return bind_or_print (var, "\033[1m", 0);
  if (!strcmp (cap, "enter_standout_mode"))
    return bind_or_print (var, "\033[1m", 0);
  if (!strcmp (cap, "enter_bold_mode"))
    return bind_or_print (var, "\033[1m", 0);
  if (!strcmp (cap, "dim"))
    return bind_or_print (var, "\033[2m", 0);
  if (!strcmp (cap, "sitm") || !strcmp (cap, "enter_italics_mode"))
    return bind_or_print (var, "\033[3m", 0);
  if (!strcmp (cap, "ritm") || !strcmp (cap, "exit_italics_mode"))
    return bind_or_print (var, "\033[23m", 0);
  if (!strcmp (cap, "smul"))
    return bind_or_print (var, "\033[4m", 0);
  if (!strcmp (cap, "rmul"))
    return bind_or_print (var, "\033[24m", 0);
  if (!strcmp (cap, "rev"))
    return bind_or_print (var, "\033[7m", 0);
  if (!strcmp (cap, "blink"))
    return bind_or_print (var, "\033[5m", 0);
  if (!strcmp (cap, "invis"))
    return bind_or_print (var, "\033[8m", 0);
  if (!strcmp (cap, "sgr0") || !strcmp (cap, "rmso"))
    return bind_or_print (var, "\033[0m", 0);
  if (!strcmp (cap, "exit_standout_mode"))
    return bind_or_print (var, "\033[0m", 0);
  if (!strcmp (cap, "sgr"))
    {
      int p[9] = {0};
      int i = 0, off = 0;
      while (args && i < 9)
        {
          p[i++] = atoi (args->word->word) ? 1 : 0;
          args = args->next;
        }
      off += snprintf (buf + off, sizeof buf - (size_t) off, "\033[0");
      if (p[0]) off += snprintf (buf + off, sizeof buf - (size_t) off, ";1");
      if (p[1]) off += snprintf (buf + off, sizeof buf - (size_t) off, ";4");
      if (p[2]) off += snprintf (buf + off, sizeof buf - (size_t) off, ";7");
      if (p[3]) off += snprintf (buf + off, sizeof buf - (size_t) off, ";5");
      if (p[4]) off += snprintf (buf + off, sizeof buf - (size_t) off, ";2");
      if (p[5]) off += snprintf (buf + off, sizeof buf - (size_t) off, ";1");
      if (p[6]) off += snprintf (buf + off, sizeof buf - (size_t) off, ";8");
      if (p[8]) off += snprintf (buf + off, sizeof buf - (size_t) off, ";10");
      snprintf (buf + off, sizeof buf - (size_t) off, "m");
      return bind_or_print (var, buf, 0);
    }
  if (!strcmp (cap, "civis"))
    return bind_or_print (var, "\033[?25l", 0);
  if (!strcmp (cap, "cnorm"))
    return bind_or_print (var, "\033[?25h", 0);
  if (!strcmp (cap, "smcup"))
    return bind_or_print (var, "\033[?1049h", 0);
  if (!strcmp (cap, "rmcup"))
    return bind_or_print (var, "\033[?1049l", 0);
  if (!strcmp (cap, "smkx"))
    return bind_or_print (var, "\033[?1h\033=", 0);
  if (!strcmp (cap, "rmkx"))
    return bind_or_print (var, "\033[?1l\033>", 0);
  if (!strcmp (cap, "smacs"))
    return bind_or_print (var, "\033(0", 0);
  if (!strcmp (cap, "rmacs"))
    return bind_or_print (var, "\033(B", 0);
  if (!strcmp (cap, "acsc"))
    return bind_or_print (var, "``aaffggjjkkllmmnnooppqqrrssttuuvvwwxxyyzz{{||}}~~", 0);
  if (!strcmp (cap, "sc") || !strcmp (cap, "save_cursor"))
    return bind_or_print (var, "\0337", 0);
  if (!strcmp (cap, "rc") || !strcmp (cap, "restore_cursor"))
    return bind_or_print (var, "\0338", 0);
  if (!strcmp (cap, "hpa") || !strcmp (cap, "column_address"))
    {
      if (!args) { builtin_error ("%s needs COL", cap); return EX_USAGE; }
      c = atoi (args->word->word);
      snprintf (buf, sizeof buf, "\033[%dG", c + 1);
      return bind_or_print (var, buf, 0);
    }
  if (!strcmp (cap, "vpa") || !strcmp (cap, "row_address"))
    {
      if (!args) { builtin_error ("%s needs ROW", cap); return EX_USAGE; }
      r = atoi (args->word->word);
      snprintf (buf, sizeof buf, "\033[%dd", r + 1);
      return bind_or_print (var, buf, 0);
    }
  if (!strcmp (cap, "ich") || !strcmp (cap, "parm_ich"))
    { n = args ? atoi (args->word->word) : 1; snprintf (buf, sizeof buf, "\033[%d@", n); return bind_or_print (var, buf, 0); }
  if (!strcmp (cap, "dch") || !strcmp (cap, "parm_dch"))
    { n = args ? atoi (args->word->word) : 1; snprintf (buf, sizeof buf, "\033[%dP", n); return bind_or_print (var, buf, 0); }
  if (!strcmp (cap, "dl") || !strcmp (cap, "parm_delete_line"))
    { n = args ? atoi (args->word->word) : 1; snprintf (buf, sizeof buf, "\033[%dM", n); return bind_or_print (var, buf, 0); }
  if (!strcmp (cap, "il") || !strcmp (cap, "parm_insert_line"))
    { n = args ? atoi (args->word->word) : 1; snprintf (buf, sizeof buf, "\033[%dL", n); return bind_or_print (var, buf, 0); }
  if (!strncmp (cap, "kf", 2) || !strncmp (cap, "key_f", 5))
    {
      const char *num = !strncmp (cap, "kf", 2) ? cap + 2 : cap + 5;
      n = atoi (num);
      switch (n)
        {
        case 1: return bind_or_print (var, "\033OP", 0);
        case 2: return bind_or_print (var, "\033OQ", 0);
        case 3: return bind_or_print (var, "\033OR", 0);
        case 4: return bind_or_print (var, "\033OS", 0);
        case 5: return bind_or_print (var, "\033[15~", 0);
        case 6: return bind_or_print (var, "\033[17~", 0);
        case 7: return bind_or_print (var, "\033[18~", 0);
        case 8: return bind_or_print (var, "\033[19~", 0);
        case 9: return bind_or_print (var, "\033[20~", 0);
        case 10: return bind_or_print (var, "\033[21~", 0);
        case 11: return bind_or_print (var, "\033[23~", 0);
        case 12: return bind_or_print (var, "\033[24~", 0);
        }
    }
  if (!strcmp (cap, "setaf") || !strcmp (cap, "setab"))
    {
      int fg = !strcmp (cap, "setaf");
      if (!args) { builtin_error ("%s needs COLOR", cap); return EX_USAGE; }
      n = atoi (args->word->word);
      if (n < 0 || n > 255) { builtin_error ("%s color must be 0..255", cap); return EX_USAGE; }
      if (n < 8) snprintf (buf, sizeof buf, "\033[%dm", (fg ? 30 : 40) + n);
      else if (n < 16) snprintf (buf, sizeof buf, "\033[%dm", (fg ? 90 : 100) + n - 8);
      else snprintf (buf, sizeof buf, "\033[%d;5;%dm", fg ? 38 : 48, n);
      return bind_or_print (var, buf, 0);
    }
  if (!strcmp (cap, "cols") || !strcmp (cap, "columns"))
    return bind_or_print (var, getenv ("COLUMNS") ? getenv ("COLUMNS") : "80", 1);
  if (!strcmp (cap, "lines") || !strcmp (cap, "rows"))
    return bind_or_print (var, getenv ("LINES") ? getenv ("LINES") : "24", 1);
  if (!strcmp (cap, "colors"))
    return bind_or_print (var, !strcmp (term, "vt100") || !strcmp (term, "dumb") ? "0" : "256", 1);
  if (!strcmp (cap, "longname"))
    {
      if (st.found)
        return bind_or_print (var, st.name, 1);
      if (!strcmp (term, "dumb"))
        return bind_or_print (var, "80-column dumb tty", 1);
      snprintf (buf, sizeof buf, "%s terminal", term ? term : "xterm-256color");
      return bind_or_print (var, buf, 1);
    }

  return EXECUTION_SUCCESS;
}

int
tput_builtin (WORD_LIST *list)
{
  const char *term = getenv ("TERM");
  const char *var = NULL;
  const char *verb;
  int i;

  if (!list) { builtin_usage (); return EX_USAGE; }
  if (!strcmp (list->word->word, "--help") || !strcmp (list->word->word, "-h"))
    {
      char *const *dp;
      for (dp = tput_doc; *dp; dp++)
        puts (*dp);
      return (EX_USAGE);
    }
  verb = list->word->word;
  list = list->next;

  if (!strcmp (verb, "entry-list"))
    {
      DIR *d;
      for (i = 0; terms[i]; i++) puts (terms[i]);
      d = opendir (side_dir_primary ());
      if (!d && strcmp (side_dir_primary (), BTP_COMPAT_DIR))
        d = opendir (BTP_COMPAT_DIR);
      if (d)
        {
          struct dirent *de;
          while ((de = readdir (d)) != NULL)
            {
              if (de->d_name[0] == '.')
                continue;
              if (safe_term_name (de->d_name))
                puts (de->d_name);
            }
          closedir (d);
        }
      return EXECUTION_SUCCESS;
    }
  if (!strcmp (verb, "cap-list"))
    {
      while (list)
        {
          const char *w = list->word->word;
          if (!strcmp (w, "-T") && list->next) { list = list->next; term = list->word->word; }
          else if (!strcmp (w, "-V") && list->next) { list = list->next; var = list->word->word; }
          else { builtin_error ("unknown cap-list arg: %s", w); return EX_USAGE; }
          list = list->next;
        }
      if (term && *term)
        {
          sideterm st;
          if (load_side_term (&st, term))
            {
              if (var)
                {
                  char joined[1024] = "";
                  for (i = 0; i < st.ncap; i++)
                    {
                      if (i) strncat (joined, " ", sizeof joined - strlen (joined) - 1);
                      strncat (joined, st.caps[i].key, sizeof joined - strlen (joined) - 1);
                    }
                  builtin_bind_variable ((char *) var, joined, 0);
                }
              else
                for (i = 0; i < st.ncap; i++) puts (st.caps[i].key);
              return EXECUTION_SUCCESS;
            }
        }
      if (var)
        {
          char joined[512] = "";
          for (i = 0; caps[i]; i++)
            {
              if (i) strncat (joined, " ", sizeof joined - strlen (joined) - 1);
              strncat (joined, caps[i], sizeof joined - strlen (joined) - 1);
            }
          builtin_bind_variable ((char *) var, joined, 0);
        }
      else
        for (i = 0; caps[i]; i++) puts (caps[i]);
      return EXECUTION_SUCCESS;
    }
  if (!strcmp (verb, "info"))
    {
      while (list)
        {
          const char *w = list->word->word;
          if (!strcmp (w, "-T") && list->next) { list = list->next; term = list->word->word; }
          else { builtin_error ("unknown info arg: %s", w); return EX_USAGE; }
          list = list->next;
        }
      if (!term || !*term) term = "xterm-256color";
      if (!known_term (term))
        {
          sideterm st;
          if (load_side_term (&st, term))
            {
              printf ("name=%s\n", st.name[0] ? st.name : term);
              for (i = 0; i < st.ncap; i++)
                if (!strcmp (st.caps[i].key, "cols") ||
                    !strcmp (st.caps[i].key, "lines") ||
                    !strcmp (st.caps[i].key, "colors"))
                  printf ("%s=%s\n", st.caps[i].key, st.caps[i].val);
              return EXECUTION_SUCCESS;
            }
          fprintf (stderr, "tput: unknown terminal: %s\n", term);
          return 3;
        }
      printf ("name=%s\ncols=80\nlines=24\ncolors=%s\n", term,
              strcmp (term, "dumb") ? "256" : "0");
      return EXECUTION_SUCCESS;
    }
  if (!strcmp (verb, "query"))
    {
      const char *cap;
      if (!list) { builtin_error ("query needs CAP"); return EX_USAGE; }
      cap = list->word->word;
      list = list->next;
      while (list && list->word->word[0] == '-')
        {
          const char *w = list->word->word;
          if (!strcmp (w, "-T") && list->next) { list = list->next; term = list->word->word; }
          else if (!strcmp (w, "-V") && list->next) { list = list->next; var = list->word->word; }
          else break;
          list = list->next;
        }
      if (!known_cap (cap) && !side_known_cap (term, cap))
        {
          fprintf (stderr, "tput: unknown capability: %s\n", cap);
          return 2;
        }
      return emit_cap (cap, list, var, term);
    }

  if (!known_cap (verb) && !side_known_cap (term, verb))
    {
      fprintf (stderr, "tput: unknown capability: %s\n", verb);
      return 2;
    }
  return emit_cap (verb, list, NULL, term);
}

char *tput_doc[] = {
  "Query a curated terminfo-compatible ANSI capability table.",
  "",
  "    tput query CAP [-T TERM] [-V VAR] [ARGS...]",
  "    tput CAP [ARGS...]",
  "    tput cap-list [-T TERM] [-V VAR]",
  "    tput entry-list",
  "    tput info [-T TERM]",
  "",
  "Supported terminal entries: xterm-256color, xterm, screen-256color,",
  "tmux-256color, linux, vt100, dumb.",
  "Sidecar entries: BASHTPUT_TERMINFO_DIR/TERM or /etc/bash-os/terminfo.d/TERM,",
  "with key=value lines and escapes like \\E, \\n, and %i%p1%d parameters.",
  (char *)NULL
};

struct builtin tput_struct = {
  "tput",
  tput_builtin,
  BUILTIN_ENABLED,
  tput_doc,
  "tput query CAP [-T TERM] [-V VAR]",
  0
};
