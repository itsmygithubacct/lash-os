/* SPDX-License-Identifier: MIT */
/* cut.c — cut(1) as a bash builtin, with the GNU coreutils surface.
 *
 * Written for bash-os from the documented interface of coreutils cut(1) and
 * the behaviour of coreutils 9.7 on the cases a script meets, taken by
 * running the tool: -b, -c and -f with a LIST of ranges, -d, -s, -z, -n,
 * --complement, --output-delimiter, the long option names and their
 * unambiguous prefixes, options after the file operands unless
 * POSIXLY_CORRECT is set, and its error messages. -c selects bytes, as it
 * does in GNU cut. tests/cut-parity.sh holds it to byte-identical output
 * with the GNU tool. It is not derived from GNU bash's own cut loadable
 * (GPL), which it replaces; -a ARRAY here reimplements that loadable's
 * documented extension, loading the output lines into an indexed array
 * instead of printing them, so a script written for it keeps working.
 *
 * The input is read in 64 KB blocks with read(2); line ends and field
 * delimiters are found with memchr; the output goes out through one 64 KB
 * buffer. A line longer than a block grows the input buffer. The range list
 * is sorted and merged once, so whether a field is selected is a comparison
 * against the next range, and a line is left as soon as no later field can
 * be selected: `-f1` costs two memchr calls per line.
 *
 *   cut -b LIST | -c LIST | -f LIST [-d DELIM] [-s] [-z] [-n] [--complement]
 *       [--output-delimiter=STRING] [-a ARRAY] [FILE...]
 *
 * Copyright (c) 2026 bash_linux contributors
 * MIT License — full text in the repository's LICENSE file. The combined
 * binary is a derivative work of bash and is governed by GPL-3+ (bash's
 * licence); MIT for this source file is GPL-3+-compatible.
 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include "loadables.h"

#define CUT_BLOCK 65536

/* A selected range, 1-based and inclusive. hi == UINTMAX_MAX means "to the
   end of the line", which is why UINTMAX_MAX itself is refused as a position
   (GNU cut refuses it too, for the same reason). */
struct cut_range { uintmax_t lo, hi; };

struct cut_state {
  int mode;                     /* 'b': bytes (also -c); 'f': fields */
  unsigned char delim;          /* -d: the field delimiter byte */
  unsigned char eol;            /* '\n', or NUL with -z */
  int suppress;                 /* -s: drop the lines without a delimiter */
  int whole;                    /* the delimiter is the line delimiter: the whole
                                   input is one record (GNU: cut -d $'\n' -f2) */
  const unsigned char *odelim;  /* what separates selected items on output */
  size_t odlen;
  int odelim_set;               /* --output-delimiter given: -b joins ranges with it */
  struct cut_range *rp;         /* sorted, non-overlapping */
  size_t nrp, rcap;
  /* output: a block buffer to stdout, or one line at a time into ARRAY */
  unsigned char *ob;
  size_t olen, ocap;
  SHELL_VAR *array;
  arrayind_t index;
};

/* ---- the range list ---------------------------------------------------- */

static void
cut_add_range (struct cut_state *st, uintmax_t lo, uintmax_t hi)
{
  if (st->nrp == st->rcap)
    {
      st->rcap = st->rcap ? st->rcap * 2 : 8;
      st->rp = xrealloc (st->rp, st->rcap * sizeof *st->rp);
    }
  st->rp[st->nrp].lo = lo;
  st->rp[st->nrp].hi = hi;
  st->nrp++;
}

/* One decimal number at *sp. 1: parsed, *sp advanced; 0: no digits there;
   -1: reported as too large (UINTMAX_MAX or more). */
static int
cut_parse_num (struct cut_state *st, const char **sp, uintmax_t *out)
{
  const char *s = *sp, *start = s;
  uintmax_t v = 0;

  while (*s >= '0' && *s <= '9')
    {
      unsigned d = (unsigned) (*s - '0');
      if (v > (UINTMAX_MAX - d) / 10 || (v = v * 10 + d) == UINTMAX_MAX)
        {
          int len = (int) strspn (start, "0123456789");
          builtin_error (st->mode == 'f' ? "field number '%.*s' is too large"
                                         : "byte/character offset '%.*s' is too large", len, start);
          return -1;
        }
      s++;
    }
  if (s == start)
    return 0;
  *sp = s;
  *out = v;
  return 1;
}

/* LIST: items separated by commas or blanks, each N, N-, N-M or -M. An
   empty item, a 0, a second dash, a decreasing range and a bare dash are
   each their own error, with GNU's wording. Prints the error, returns -1. */
static int
cut_parse_list (struct cut_state *st, const char *s)
{
  int fields = st->mode == 'f';
  const char *what = fields ? "fields" : "byte/character positions";

  for (;;)
    {
      uintmax_t lo = 0, hi = 0;
      int has_lo, has_hi = 0, dash = 0;

      has_lo = cut_parse_num (st, &s, &lo);
      if (has_lo < 0)
        return -1;
      if (*s == '-')
        {
          dash = 1;
          s++;
          has_hi = cut_parse_num (st, &s, &hi);
          if (has_hi < 0)
            return -1;
        }
      if (*s == '-')
        {
          builtin_error (fields ? "invalid field range" : "invalid byte or character range");
          return -1;
        }
      if (*s != '\0' && *s != ',' && *s != ' ' && *s != '\t')
        {
          builtin_error (fields ? "invalid field value '%s'" : "invalid byte/character position '%s'", s);
          return -1;
        }
      if (!dash)
        {
          if (!has_lo || lo == 0)
            {
              builtin_error ("%s are numbered from 1", what);
              return -1;
            }
          cut_add_range (st, lo, lo);
        }
      else
        {
          if (!has_lo && !has_hi)
            {
              builtin_error ("invalid range with no endpoint: -");
              return -1;
            }
          if (has_lo && lo == 0)
            {
              builtin_error ("%s are numbered from 1", what);
              return -1;
            }
          if (!has_lo)
            lo = 1;
          if (!has_hi)
            hi = UINTMAX_MAX;
          else if (hi < lo)
            {
              builtin_error ("invalid decreasing range");
              return -1;
            }
          cut_add_range (st, lo, hi);
        }
      if (*s == '\0')
        break;
      s++;
    }
  return 0;
}

static int
cut_range_cmp (const void *a, const void *b)
{
  const struct cut_range *x = a, *y = b;
  return x->lo < y->lo ? -1 : x->lo > y->lo;
}

/* Sort; merge the ranges that overlap (ranges that merely touch stay apart:
   GNU prints the output delimiter between `1-2` and `3`); then complement
   if asked, which is the gaps plus what follows the last range unless that
   one is open. */
static void
cut_finish_ranges (struct cut_state *st, int complement)
{
  size_t i, m = 0;

  qsort (st->rp, st->nrp, sizeof *st->rp, cut_range_cmp);
  for (i = 0; i < st->nrp; i++)
    {
      if (m && st->rp[i].lo <= st->rp[m - 1].hi)
        {
          if (st->rp[i].hi > st->rp[m - 1].hi)
            st->rp[m - 1].hi = st->rp[i].hi;
        }
      else
        st->rp[m++] = st->rp[i];
    }
  st->nrp = m;

  if (complement)
    {
      struct cut_range *c = xmalloc ((m + 1) * sizeof *c);
      size_t k = 0;
      uintmax_t next = 1;
      int open = 0;

      for (i = 0; i < m; i++)
        {
          if (st->rp[i].lo > next)
            {
              c[k].lo = next;
              c[k].hi = st->rp[i].lo - 1;
              k++;
            }
          if (st->rp[i].hi == UINTMAX_MAX)
            {
              open = 1;
              break;
            }
          next = st->rp[i].hi + 1;
        }
      if (!open)
        {
          c[k].lo = next;
          c[k].hi = UINTMAX_MAX;
          k++;
        }
      free (st->rp);
      st->rp = c;
      st->nrp = k;
    }
}

/* ---- output ------------------------------------------------------------ */

static void
cut_flush (struct cut_state *st)
{
  if (st->olen)
    fwrite (st->ob, 1, st->olen, stdout);   /* a failure is caught by sh_chkwrite */
  st->olen = 0;
}

static void
cut_emit (struct cut_state *st, const unsigned char *p, size_t n)
{
  if (st->array)
    {
      /* an element is one line: grow, keeping room for the NUL */
      if (st->olen + n + 1 > st->ocap)
        {
          size_t cap = st->ocap;
          while (cap < st->olen + n + 1)
            cap *= 2;
          st->ob = xrealloc (st->ob, cap);
          st->ocap = cap;
        }
    }
  else if (n > st->ocap - st->olen)
    {
      cut_flush (st);
      if (n >= st->ocap)
        {
          fwrite (p, 1, n, stdout);
          return;
        }
    }
  memcpy (st->ob + st->olen, p, n);
  st->olen += n;
}

static void
cut_end_line (struct cut_state *st)
{
  if (st->array)
    {
      st->ob[st->olen] = '\0';
      bind_array_element (st->array, st->index++, (char *) st->ob, 0);
      st->olen = 0;
    }
  else
    cut_emit (st, &st->eol, 1);
}

/* ---- one line ---------------------------------------------------------- */

/* DELIMITED: the record held the delimiter even if this text does not (a
   whole-input record whose terminator was the delimiter). */
static void
cut_line (struct cut_state *st, const unsigned char *p, size_t len, int delimited, int terminate)
{
  int first = 1;

  if (st->mode == 'f')
    {
      const unsigned char *end = p + len, *start = p, *q;
      uintmax_t idx = 1;
      size_t r = 0;

      q = memchr (p, st->delim, len);
      if (q == NULL && !delimited)
        {
          /* no delimiter: the whole line, or with -s nothing at all */
          if (!st->suppress)
            {
              cut_emit (st, p, len);
              cut_end_line (st);
            }
          return;
        }
      for (;;)
        {
          while (r < st->nrp && idx > st->rp[r].hi)
            r++;
          if (r == st->nrp)
            break;                      /* no later field is selected */
          if (idx >= st->rp[r].lo)
            {
              if (!first)
                cut_emit (st, st->odelim, st->odlen);
              /* an open range joined by the input delimiter is the rest of
                 the line as it stands: one copy, no more scanning */
              if (st->rp[r].hi == UINTMAX_MAX && !st->odelim_set)
                {
                  cut_emit (st, start, (size_t) (end - start));
                  break;
                }
              cut_emit (st, start, (size_t) ((q ? q : end) - start));
              first = 0;
            }
          if (q == NULL)
            break;
          start = q + 1;
          idx++;
          q = memchr (start, st->delim, (size_t) (end - start));
        }
    }
  else
    {
      size_t i;
      for (i = 0; i < st->nrp; i++)
        {
          uintmax_t lo = st->rp[i].lo, hi = st->rp[i].hi;
          if (lo > len)
            break;
          if (hi > len)
            hi = len;
          if (!first && st->odelim_set)
            cut_emit (st, st->odelim, st->odlen);
          cut_emit (st, p + (lo - 1), (size_t) (hi - lo + 1));
          first = 0;
        }
    }
  if (terminate || (st->array && st->olen))
    cut_end_line (st);
}

/* ---- one file ---------------------------------------------------------- */

static int
cut_fd (struct cut_state *st, int fd, const char *name)
{
  size_t cap = CUT_BLOCK, len = 0;
  unsigned char *buf = xmalloc (cap);
  int rc = EXECUTION_SUCCESS;

  for (;;)
    {
      ssize_t n;
      unsigned char *p, *end, *q;

      if (len == cap)                   /* a line longer than the block */
        {
          cap *= 2;
          buf = xrealloc (buf, cap);
        }
      n = read (fd, buf + len, cap - len);
      if (n < 0)
        {
          if (errno == EINTR)
            {
              QUIT;
              continue;
            }
          builtin_error ("%s: %s", name, strerror (errno));
          rc = EXECUTION_FAILURE;
          break;
        }
      QUIT;
      if (n == 0)
        {
          if (st->whole && len)
            {
              /* one record: a final delimiter byte is its terminator. Whether
                 a record that held only that byte counts as delimited for -s
                 depends, in GNU, on which of its two reading paths runs: it
                 does when field 1 is selected, and not otherwise. */
              int term = buf[len - 1] == st->delim;
              int delimited = term && !(st->suppress && !(st->nrp && st->rp[0].lo == 1));
              cut_line (st, buf, len - term, delimited, 1);
            }
          else if (len)
            {
              /* GNU's buffered-first-field path omits the final NUL when
                 the only field delimiter is the last input byte. */
              int first_selected = st->nrp && st->rp[0].lo == 1;
              int terminate = !(st->mode == 'f' && st->eol == 0
                && st->suppress == first_selected
                && buf[len - 1] == st->delim
                && memchr (buf, st->delim, len - 1) == NULL);
              cut_line (st, buf, len, 0, terminate);
            }
          break;
        }
      len += (size_t) n;
      if (st->whole)
        continue;
      p = buf;
      end = buf + len;
      while ((q = memchr (p, st->eol, (size_t) (end - p))) != NULL)
        {
          cut_line (st, p, (size_t) (q - p), 0, 1);
          p = q + 1;
        }
      len = (size_t) (end - p);
      if (len && p != buf)
        memmove (buf, p, len);
    }
  free (buf);
  return rc;
}

/* ---- options ----------------------------------------------------------- */

static const struct cut_longopt { const char *name; int arg; int id; } cut_longopts[] = {
  { "bytes", 1, 'b' }, { "characters", 1, 'c' }, { "complement", 0, 'C' },
  { "delimiter", 1, 'd' }, { "fields", 1, 'f' }, { "help", 0, 'h' },
  { "only-delimited", 0, 's' }, { "output-delimiter", 1, 'O' },
  { "version", 0, 'V' }, { "zero-terminated", 0, 'z' }, { NULL, 0, 0 }
};

struct cut_opts {
  int delim_set, complement, odelim_set;
  const char *list, *odelim, *array_name;
};

/* Apply one option. 0: applied; 1: applied and the command is complete
   (--help, --version); -1: an error, already reported. */
static int
cut_option (struct cut_state *st, struct cut_opts *o, int id, const char *val)
{
  switch (id)
    {
    case 'b': case 'c': case 'f':
      if (st->mode)
        {
          builtin_error ("only one list may be specified");
          return -1;
        }
      st->mode = id == 'f' ? 'f' : 'b';
      o->list = val;                    /* parsed after the option checks, as GNU does */
      return 0;
    case 'd':
      if (val[0] && val[1])
        {
          builtin_error ("the delimiter must be a single character");
          return -1;
        }
      st->delim = (unsigned char) val[0];
      o->delim_set = 1;
      return 0;
    case 'a':
      o->array_name = val;
      return 0;
    case 'O':
      o->odelim = val;
      o->odelim_set = 1;
      return 0;
    case 'C':
      o->complement = 1;
      return 0;
    case 's':
      st->suppress = 1;
      return 0;
    case 'z':
      st->eol = '\0';
      return 0;
    case 'n':
      return 0;
    case 'h':
      builtin_help ();
      return 1;
    case 'V':
      printf ("cut (bash-os loadable)\n");
      return 1;
    }
  return -1;
}

int
cut_builtin (WORD_LIST *list)
{
  struct cut_state st;
  struct cut_opts o;
  WORD_LIST *l;
  char **files = NULL;
  size_t nfiles = 0, fcap = 0, i;
  int end_opts = 0, posix = getenv ("POSIXLY_CORRECT") != NULL;
  int rc = EXECUTION_SUCCESS, r;

  memset (&st, 0, sizeof st);
  memset (&o, 0, sizeof o);
  st.delim = '\t';
  st.eol = '\n';

  for (l = list; l; l = l->next)
    {
      char *w = l->word->word, *p;

      if (end_opts || w[0] != '-' || w[1] == '\0')
        {
          if (nfiles == fcap)
            {
              fcap = fcap ? fcap * 2 : 8;
              files = xrealloc (files, fcap * sizeof *files);
            }
          files[nfiles++] = w;
          if (posix)                    /* as GNU getopt: the first operand ends the options */
            end_opts = 1;
          continue;
        }
      if (w[1] == '-')
        {
          const struct cut_longopt *lo, *match = NULL;
          const char *name = w + 2, *eq = strchr (name, '='), *val = NULL;
          size_t nlen = eq ? (size_t) (eq - name) : strlen (name);
          int ambiguous = 0;

          if (w[2] == '\0')
            {
              end_opts = 1;
              continue;
            }
          for (lo = cut_longopts; lo->name; lo++)
            {
              if (strncmp (lo->name, name, nlen) != 0)
                continue;
              if (lo->name[nlen] == '\0')
                {
                  match = lo;           /* exact */
                  ambiguous = 0;
                  break;
                }
              if (match)
                ambiguous = 1;
              else
                match = lo;
            }
          if (match == NULL)
            {
              builtin_error ("unrecognized option '%s'", w);
              goto usage;
            }
          if (ambiguous)
            {
              char poss[256];
              size_t used = 0;
              for (lo = cut_longopts; lo->name; lo++)
                if (strncmp (lo->name, name, nlen) == 0 && used + strlen (lo->name) + 6 < sizeof poss)
                  used += (size_t) snprintf (poss + used, sizeof poss - used, " '--%s'", lo->name);
              builtin_error ("option '%s' is ambiguous; possibilities:%s", w, poss);
              goto usage;
            }
          if (match->arg)
            {
              if (eq)
                val = eq + 1;
              else if (l->next)
                {
                  l = l->next;
                  val = l->word->word;
                }
              else
                {
                  builtin_error ("option '--%s' requires an argument", match->name);
                  goto usage;
                }
            }
          else if (eq)
            {
              builtin_error ("option '--%s' doesn't allow an argument", match->name);
              goto usage;
            }
          r = cut_option (&st, &o, match->id, val);
          if (r < 0)
            goto usage;
          if (r > 0)
            goto done_ok;
          continue;
        }
      for (p = w + 1; *p; p++)
        {
          const char *val = NULL;
          switch (*p)
            {
            case 'b': case 'c': case 'f': case 'd': case 'a':
              if (p[1])
                val = p + 1;
              else if (l->next)
                {
                  l = l->next;
                  val = l->word->word;
                }
              else
                {
                  builtin_error ("option requires an argument -- '%c'", *p);
                  goto usage;
                }
              r = cut_option (&st, &o, *p, val);
              if (r < 0)
                goto usage;
              if (r > 0)
                goto done_ok;
              p = NULL;                 /* the rest of the word was the argument */
              break;
            case 's': case 'n': case 'z':
              cut_option (&st, &o, *p, NULL);
              break;
            default:
              builtin_error ("invalid option -- '%c'", *p);
              builtin_usage ();
              rc = EXECUTION_FAILURE;
              goto done;
            }
          if (p == NULL)
            break;
        }
    }

  if (st.mode == 0)
    {
      builtin_error ("you must specify a list of bytes, characters, or fields");
      goto usage;
    }
  if (o.delim_set && st.mode != 'f')
    {
      builtin_error ("an input delimiter may be specified only when operating on fields");
      goto usage;
    }
  if (st.suppress && st.mode != 'f')
    {
      builtin_error ("suppressing non-delimited lines makes sense\n\tonly when operating on fields");
      goto usage;
    }

  if (cut_parse_list (&st, o.list) < 0)
    goto usage;
  cut_finish_ranges (&st, o.complement);
  if (o.odelim_set)
    {
      /* GNU reads --output-delimiter='' as "a NUL byte": the string's own
         terminator is that byte */
      st.odelim = (const unsigned char *) o.odelim;
      st.odlen = o.odelim[0] ? strlen (o.odelim) : 1;
      st.odelim_set = 1;
    }
  else if (st.mode == 'f')
    {
      st.odelim = &st.delim;            /* fields come out joined by the input delimiter */
      st.odlen = 1;
    }
  st.whole = st.mode == 'f' && st.delim == st.eol;

  if (o.array_name)
    {
#if defined (ARRAY_VARS)
      if (valid_identifier (o.array_name) == 0)
        {
          sh_invalidid ((char *) o.array_name);
          rc = EXECUTION_FAILURE;
          goto done;
        }
      st.array = builtin_find_indexed_array ((char *) o.array_name, 1);
      if (st.array == NULL)
        {
          rc = EXECUTION_FAILURE;
          goto done;
        }
#else
      builtin_error ("arrays not available");
      rc = EXECUTION_FAILURE;
      goto done;
#endif
    }

  st.ocap = CUT_BLOCK;
  st.ob = xmalloc (st.ocap);

  if (nfiles == 0)
    rc = cut_fd (&st, 0, "-");
  for (i = 0; i < nfiles; i++)
    {
      const char *name = files[i];
      int fd, fr;

      if (name[0] == '-' && name[1] == '\0')
        fd = 0;
      else
        {
          fd = open (name, O_RDONLY);
          if (fd < 0)
            {
              builtin_error ("%s: %s", name, strerror (errno));
              rc = EXECUTION_FAILURE;
              continue;
            }
        }
      fr = cut_fd (&st, fd, name);
      if (!(name[0] == '-' && name[1] == '\0'))
        close (fd);
      if (fr != EXECUTION_SUCCESS)
        rc = fr;
    }
  cut_flush (&st);
  goto done;

usage:
  builtin_usage ();
  rc = EXECUTION_FAILURE;
  goto done;
done_ok:
  rc = EXECUTION_SUCCESS;
done:
  free (files);
  free (st.rp);
  free (st.ob);
  return sh_chkwrite (rc);
}

char *cut_doc[] = {
  "Print selected parts of lines from each FILE to standard output.",
  "",
  "Select bytes (-b), characters (-c) or fields (-f) of each line of each",
  "FILE, or of the standard input when no FILE is given or FILE is -, and",
  "write them to the standard output. Exactly one of -b, -c or -f is",
  "required. -c selects bytes, as GNU cut does.",
  "",
  "Options:",
  "  -b, --bytes=LIST        select only these bytes",
  "  -c, --characters=LIST   select only these characters",
  "  -d, --delimiter=DELIM   use DELIM instead of TAB for the field delimiter",
  "  -f, --fields=LIST       select only these fields; also print any line",
  "                          that contains no delimiter character, unless",
  "                          the -s option is specified",
  "  -n                      (ignored)",
  "      --complement        complement the set of selected bytes, characters",
  "                          or fields",
  "  -s, --only-delimited    do not print lines not containing delimiters",
  "      --output-delimiter=STRING  use STRING as the output delimiter;",
  "                          the default is to use the input delimiter",
  "  -z, --zero-terminated   line delimiter is NUL, not newline",
  "  -a ARRAY                assign the output lines to the indexed array",
  "                          ARRAY, from index 0, instead of printing them",
  "",
  "Each LIST is made up of one range, or many ranges separated by commas.",
  "Selected input is written in the same order that it is read, and is",
  "written exactly once. Each range is one of:",
  "  N     N'th byte, character or field, counted from 1",
  "  N-    from N'th byte, character or field, to end of line",
  "  N-M   from N'th to M'th (included) byte, character or field",
  "  -M    from first to M'th (included) byte, character or field",
  "",
  "Exit Status:",
  "Returns 0 unless an option is invalid or a FILE cannot be read.",
  (char *)NULL
};

struct builtin cut_struct = {
  "cut",
  cut_builtin,
  BUILTIN_ENABLED,
  cut_doc,
  "cut -b LIST | -c LIST | -f LIST [-d DELIM] [-s] [-z] [--complement] [--output-delimiter=STRING] [-a ARRAY] [FILE...]",
  0
};
