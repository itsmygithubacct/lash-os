/* SPDX-License-Identifier: MIT */
/* column.c — bundled column(1) / col(1) / colrm(1) bash loadable.
 *
 * Phase MISSING_LOADABLES T2 of bash-os (ML-T2-11).
 *
 * Three small text utilities, one .c, three exported builtins so each
 * registered name (column, col, colrm) dispatches to its
 * own argv handler via the builtin lookup table. Sibling .c files
 * (col.c, colrm.c) are empty stubs — they exist only so the
 * patch-bash-loadables.sh `cp examples/loadables/${name}.c` step has
 * a file at the expected path; the actual struct/_builtin/_doc
 * symbols are exported from this translation unit.
 *
 *   column [-t] [-s SEPSTR] [-o OUTSTR] [FILE...]
 *      Aligned table mode. SEPSTR (default " \t") names the set of
 *      bytes that separate input fields. Without -s, runs of those
 *      bytes collapse into one separator; with -s, each char in
 *      SEPSTR splits, so consecutive separators produce empty
 *      fields (matching `column -s : -t /etc/passwd`). OUTSTR
 *      (default "  ") joins output columns. The last column is not
 *      right-padded.
 *      Option parsing follows getopt shape for the implemented
 *      options, so `-ts :`, `-s:`, and `-o::` are accepted.
 *      Non-table mode supports `-S N` / `--use-spaces=N` as the
 *      util-linux no-tabs layout knob.
 *
 *   col [-b] [FILE...]
 *      Preserve CTL-H (backspace) overstrike sequences by default. With
 *      -b the backspace and the preceding byte are both removed
 *      (man-page "no backspaces" mode). ESC-7 (DECRC / reverse linefeed) and
 *      RI bytes are dropped on sight — they cannot be honored without
 *      a line buffer model col(1) does not advertise as required.
 *
 *   colrm [START [END]]
 *      Remove byte-columns START..END (1-based, inclusive) from each
 *      stdin line. With just START, remove START..end-of-line. With
 *      no operands, passthrough. Out-of-range columns produce a no-op
 *      on lines shorter than START. TAB-expansion (util-linux's
 *      colrm calls it out for the "<TAB> is 1 column" rule) is NOT
 *      done — columns are treated as bytes, which matches the most
 *      common ASCII use and avoids the heavier `wcwidth` dependency.
 *
 * Source counterparts (read for spec shape, not vendored):
 *   research/refs/util-linux/text-utils/column.c
 *   research/refs/util-linux/text-utils/col.c
 *   research/refs/util-linux/text-utils/colrm.c
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c / bashfold.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include "loadables.h"

#ifndef BCOL_MAX_FILES
#  define BCOL_MAX_FILES 256
#endif

/* ===================================================================
 * Shared helpers — stream slurp and getline-style read.
 * =================================================================== */

/* Own stdin's stdio state for this invocation. Bash's persistent stdin FILE
   keeps EOF and read-ahead across redirections. Repeated '-' operands share
   this stream. Never fclose stdin. */
static FILE *
bcol_open_stdin (void)
{
  int fd = dup (STDIN_FILENO);
  FILE *in = fd < 0 ? NULL : fdopen (fd, "r");
  if (!in)
    {
      int error = errno;
      if (fd >= 0)
        close (fd);
      builtin_error ("stdin: %s", strerror (error));
    }
  return in;
}

static FILE *
bcol_open (const char *path, FILE **in_stdin)
{
  if (path == NULL || (path[0] == '-' && path[1] == '\0'))
    {
      if (*in_stdin == NULL)
        *in_stdin = bcol_open_stdin ();
      return *in_stdin;
    }
  FILE *fp = fopen (path, "r");
  if (!fp)
    builtin_error ("%s: %s", path, strerror (errno));
  return fp;
}

/* Read one line including its newline (if any) into *out (malloc'd or
 * realloc'd; caller frees). Returns the byte length (0 = EOF with no
 * data, -1 = ferror). The trailing '\n' is included in the count when
 * present; callers strip it themselves. */
static ssize_t
bcol_getline (FILE *fp, char **out, size_t *cap)
{
  if (*out == NULL || *cap == 0)
    {
      *cap = 256;
      *out = malloc (*cap);
      if (!*out)
        return -1;
    }
  size_t len = 0;
  int c;
  while ((c = fgetc (fp)) != EOF)
    {
      if (len + 1 >= *cap)
        {
          size_t ncap = *cap * 2;
          char *nb = realloc (*out, ncap);
          if (!nb)
            return -1;
          *out = nb;
          *cap = ncap;
        }
      (*out)[len++] = (char) c;
      if (c == '\n')
        break;
    }
  if (ferror (fp))
    return -1;
  return (ssize_t) len;
}

/* ===================================================================
 * column verb.
 * =================================================================== */

typedef struct
{
  char **fields;    /* malloc'd field strings */
  int n;            /* count */
  int cap;          /* capacity */
} bcol_row;

static void
bcol_row_free (bcol_row *r)
{
  for (int i = 0; i < r->n; i++)
    free (r->fields[i]);
  free (r->fields);
  r->fields = NULL;
  r->n = 0;
  r->cap = 0;
}

static int
bcol_row_push (bcol_row *r, const char *s, size_t len)
{
  if (r->n >= r->cap)
    {
      int ncap = r->cap ? r->cap * 2 : 8;
      char **nf = realloc (r->fields, (size_t) ncap * sizeof (*nf));
      if (!nf)
        return -1;
      r->fields = nf;
      r->cap = ncap;
    }
  char *copy = malloc (len + 1);
  if (!copy)
    return -1;
  memcpy (copy, s, len);
  copy[len] = '\0';
  r->fields[r->n++] = copy;
  return 0;
}

/* Split LINE into fields using SEPS. If sflag is 0 (no -s given) runs
 * of any byte in SEPS collapse into one separator and leading runs are
 * skipped. If sflag is 1 each separator byte makes one cut, so
 * consecutive separators yield empty fields. */
static int
bcol_split (const char *line, size_t len, const char *seps, int sflag,
            bcol_row *out)
{
  size_t i = 0;
  if (!sflag)
    {
      while (i < len && strchr (seps, line[i]))
        i++;
      while (i < len)
        {
          size_t j = i;
          while (j < len && !strchr (seps, line[j]))
            j++;
          if (bcol_row_push (out, line + i, j - i) != 0)
            return -1;
          while (j < len && strchr (seps, line[j]))
            j++;
          i = j;
        }
      return 0;
    }
  /* sflag: split on every separator byte. */
  size_t start = 0;
  for (i = 0; i < len; i++)
    {
      if (strchr (seps, line[i]))
        {
          if (bcol_row_push (out, line + start, i - start) != 0)
            return -1;
          start = i + 1;
        }
    }
  if (bcol_row_push (out, line + start, len - start) != 0)
    return -1;
  return 0;
}

int
column_builtin (WORD_LIST *list)
{
  const char *seps = " \t";
  const char *outsep = "  ";
  int sflag = 0;
  int tflag = 0;
  int xflag = 0;
  long output_width = 80;
  long use_spaces = -1;
  const char *files[BCOL_MAX_FILES];
  int n_files = 0;

  for (WORD_LIST *p = list; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "--") == 0)
        {
          for (p = p->next; p; p = p->next)
            if (n_files < BCOL_MAX_FILES)
              files[n_files++] = p->word->word;
          break;
        }
      if (strcmp (w, "--help") == 0)
        { builtin_usage (); return EXECUTION_SUCCESS; }
      if (strcmp (w, "--version") == 0 || strcmp (w, "-V") == 0)
        { puts ("column 1.0 (bash-loadable)"); return EXECUTION_SUCCESS; }
      if (strcmp (w, "--table") == 0)
        { tflag = 1; continue; }
      if (strcmp (w, "--fillrows") == 0)
        { xflag = 1; continue; }
      if (strcmp (w, "--output-width") == 0)
        {
          char *endp = NULL;
          if (!p->next)
            {
              builtin_error ("column: %s requires an argument", w);
              builtin_usage ();
              return EX_USAGE;
            }
          output_width = strtol (p->next->word->word, &endp, 10);
          if (!endp || *endp || output_width < 1)
            {
              builtin_error ("column: bad output width: %s", p->next->word->word);
              builtin_usage ();
              return EX_USAGE;
            }
          p = p->next;
          continue;
        }
      if (strncmp (w, "--output-width=", 15) == 0)
        {
          char *endp = NULL;
          output_width = strtol (w + 15, &endp, 10);
          if (!endp || *endp || output_width < 1)
            {
              builtin_error ("column: bad output width: %s", w + 15);
              builtin_usage ();
              return EX_USAGE;
            }
          continue;
        }
      if (strcmp (w, "--use-spaces") == 0)
        {
          char *endp = NULL;
          if (!p->next)
            {
              builtin_error ("column: %s requires an argument", w);
              builtin_usage ();
              return EX_USAGE;
            }
          use_spaces = strtol (p->next->word->word, &endp, 10);
          if (!endp || *endp || use_spaces < 1)
            {
              builtin_error ("column: bad use-spaces value: %s", p->next->word->word);
              builtin_usage ();
              return EX_USAGE;
            }
          p = p->next;
          continue;
        }
      if (strncmp (w, "--use-spaces=", 13) == 0)
        {
          char *endp = NULL;
          use_spaces = strtol (w + 13, &endp, 10);
          if (!endp || *endp || use_spaces < 1)
            {
              builtin_error ("column: bad use-spaces value: %s", w + 13);
              builtin_usage ();
              return EX_USAGE;
            }
          continue;
        }
      if (strcmp (w, "--separator") == 0
          || strcmp (w, "--input-separator") == 0)
        {
          if (!p->next)
            {
              builtin_error ("column: %s requires an argument", w);
              builtin_usage ();
              return EX_USAGE;
            }
          seps = p->next->word->word;
          sflag = 1;
          p = p->next;
          continue;
        }
      if (strncmp (w, "--separator=", 12) == 0)
        { seps = w + 12; sflag = 1; continue; }
      if (strncmp (w, "--input-separator=", 18) == 0)
        { seps = w + 18; sflag = 1; continue; }
      if (strcmp (w, "--output-separator") == 0)
        {
          if (!p->next)
            {
              builtin_error ("column: %s requires an argument", w);
              builtin_usage ();
              return EX_USAGE;
            }
          outsep = p->next->word->word;
          p = p->next;
          continue;
        }
      if (strncmp (w, "--output-separator=", 19) == 0)
        { outsep = w + 19; continue; }
      if (w[0] == '-' && w[1] != '\0' && strcmp (w, "-") != 0)
        {
          for (const char *q = w + 1; *q; q++)
            {
              if (*q == 't')
                { tflag = 1; continue; }
              if (*q == 'x')
                { xflag = 1; continue; }
              if (*q == 'c')
                {
                  char *endp = NULL;
                  const char *arg = q[1] ? q + 1 : NULL;
                  if (!arg)
                    {
                      if (!p->next)
                        {
                          builtin_error ("column: -%c requires an argument", *q);
                          builtin_usage ();
                          return EX_USAGE;
                        }
                      arg = p->next->word->word;
                      p = p->next;
                    }
                  output_width = strtol (arg, &endp, 10);
                  if (!endp || *endp || output_width < 1)
                    {
                      builtin_error ("column: bad output width: %s", arg);
                      builtin_usage ();
                      return EX_USAGE;
                    }
                  break;
                }
              if (*q == 'S')
                {
                  char *endp = NULL;
                  const char *arg = q[1] ? q + 1 : NULL;
                  if (!arg)
                    {
                      if (!p->next)
                        {
                          builtin_error ("column: -%c requires an argument", *q);
                          builtin_usage ();
                          return EX_USAGE;
                        }
                      arg = p->next->word->word;
                      p = p->next;
                    }
                  use_spaces = strtol (arg, &endp, 10);
                  if (!endp || *endp || use_spaces < 1)
                    {
                      builtin_error ("column: bad use-spaces value: %s", arg);
                      builtin_usage ();
                      return EX_USAGE;
                    }
                  break;
                }
              if (*q == 's' || *q == 'o')
                {
                  const char *arg = q[1] ? q + 1 : NULL;
                  if (!arg)
                    {
                      if (!p->next)
                        {
                          builtin_error ("column: -%c requires an argument", *q);
                          builtin_usage ();
                          return EX_USAGE;
                        }
                      arg = p->next->word->word;
                      p = p->next;
                    }
                  if (*q == 's')
                    { seps = arg; sflag = 1; }
                  else
                    outsep = arg;
                  break;
                }
              builtin_error ("column: unknown flag: -%c", *q);
              builtin_usage ();
              return EX_USAGE;
            }
          continue;
        }
      if (n_files < BCOL_MAX_FILES)
        files[n_files++] = w;
    }

  if (!tflag)
    {
      char **items = NULL;
      int n_items = 0, cap_items = 0;
      size_t maxw = 0;
      int rc = EXECUTION_SUCCESS;
      int n_streams = n_files ? n_files : 1;
      FILE *in_stdin = NULL;

      for (int fi = 0; fi < n_streams; fi++)
        {
          FILE *fp = bcol_open (n_files ? files[fi] : NULL, &in_stdin);
          if (!fp)
            { rc = EXECUTION_FAILURE; continue; }
          char *line = NULL;
          size_t cap = 0;
          ssize_t got;
          while ((got = bcol_getline (fp, &line, &cap)) > 0)
            {
              if (line[got - 1] == '\n')
                got--;
              if (n_items >= cap_items)
                {
                  int nc = cap_items ? cap_items * 2 : 16;
                  char **ni = realloc (items, (size_t) nc * sizeof (*ni));
                  if (!ni) { rc = EXECUTION_FAILURE; free (line); goto columnar_cleanup; }
                  items = ni;
                  cap_items = nc;
                }
              char *copy = malloc ((size_t) got + 1);
              if (!copy) { rc = EXECUTION_FAILURE; free (line); goto columnar_cleanup; }
              memcpy (copy, line, (size_t) got);
              copy[got] = '\0';
              items[n_items++] = copy;
              if ((size_t) got > maxw)
                maxw = (size_t) got;
            }
          if (got < 0)
            { builtin_error ("read: %s", strerror (errno)); rc = EXECUTION_FAILURE; }
          free (line);
          if (fp != in_stdin) fclose (fp);
        }

      if (n_items > 0)
        {
          size_t colstep;
          if (use_spaces > 0)
            colstep = maxw + (size_t) use_spaces;
          else
            colstep = maxw ? ((maxw + 8) & ~(size_t) 7) : 8;
          int n_cols = (int) ((size_t) output_width / colstep);
          if (n_cols < 1) n_cols = 1;
          if (n_cols > n_items) n_cols = n_items;
          int n_rows = (n_items + n_cols - 1) / n_cols;

          for (int r = 0; r < n_rows; r++)
            {
              int printed = 0;
              for (int c = 0; c < n_cols; c++)
                {
                  int idx = xflag ? (r * n_cols + c) : (c * n_rows + r);
                  if (idx >= n_items)
                    continue;
                  if (printed && use_spaces <= 0)
                    putchar ('\t');
                  fputs (items[idx], stdout);
                  if (use_spaces > 0)
                    {
                      int more = 0;
                      for (int nc = c + 1; nc < n_cols; nc++)
                        {
                          int nidx = xflag ? (r * n_cols + nc) : (nc * n_rows + r);
                          if (nidx < n_items)
                            { more = 1; break; }
                        }
                      if (more)
                        {
                          size_t pad = colstep - strlen (items[idx]);
                          for (size_t sp = 0; sp < pad; sp++)
                            putchar (' ');
                        }
                    }
                  printed = 1;
                }
              putchar ('\n');
            }
        }

columnar_cleanup:
      if (in_stdin)
        fclose (in_stdin);
      for (int i = 0; i < n_items; i++)
        free (items[i]);
      free (items);
      return rc;
    }

  bcol_row *rows = NULL;
  int n_rows = 0, cap_rows = 0;
  size_t *colw = NULL;
  int n_cols = 0, cap_cols = 0;
  int rc = EXECUTION_SUCCESS;

  int n_streams = n_files ? n_files : 1;
  FILE *in_stdin = NULL;
  for (int fi = 0; fi < n_streams; fi++)
    {
      FILE *fp = bcol_open (n_files ? files[fi] : NULL, &in_stdin);
      if (!fp)
        { rc = EXECUTION_FAILURE; continue; }
      char *line = NULL;
      size_t cap = 0;
      ssize_t got;
      while ((got = bcol_getline (fp, &line, &cap)) > 0)
        {
          if (line[got - 1] == '\n')
            got--;
          if (n_rows >= cap_rows)
            {
              int nc = cap_rows ? cap_rows * 2 : 16;
              bcol_row *nr = realloc (rows, (size_t) nc * sizeof (*nr));
              if (!nr) { rc = EXECUTION_FAILURE; goto cleanup; }
              rows = nr;
              cap_rows = nc;
            }
          rows[n_rows].fields = NULL;
          rows[n_rows].n = 0;
          rows[n_rows].cap = 0;
          if (bcol_split (line, (size_t) got, seps, sflag, &rows[n_rows]) != 0)
            { rc = EXECUTION_FAILURE; goto cleanup; }
          if (rows[n_rows].n > n_cols)
            {
              int newn = rows[n_rows].n;
              if (newn > cap_cols)
                {
                  int nc = cap_cols ? cap_cols * 2 : 8;
                  while (nc < newn) nc *= 2;
                  size_t *nw = realloc (colw, (size_t) nc * sizeof (*nw));
                  if (!nw) { rc = EXECUTION_FAILURE; goto cleanup; }
                  for (int k = cap_cols; k < nc; k++) nw[k] = 0;
                  colw = nw;
                  cap_cols = nc;
                }
              n_cols = newn;
            }
          for (int k = 0; k < rows[n_rows].n; k++)
            {
              size_t w = strlen (rows[n_rows].fields[k]);
              if (w > colw[k])
                colw[k] = w;
            }
          n_rows++;
        }
      if (got < 0)
        { builtin_error ("read: %s", strerror (errno)); rc = EXECUTION_FAILURE; }
      free (line);
      if (fp != in_stdin) fclose (fp);
    }

  for (int r = 0; r < n_rows; r++)
    {
      for (int k = 0; k < rows[r].n; k++)
        {
          fputs (rows[r].fields[k], stdout);
          if (k + 1 < rows[r].n)
            {
              size_t pad = colw[k] - strlen (rows[r].fields[k]);
              for (size_t p = 0; p < pad; p++) putchar (' ');
              fputs (outsep, stdout);
            }
        }
      putchar ('\n');
    }

cleanup:
  if (in_stdin)
    fclose (in_stdin);
  for (int r = 0; r < n_rows; r++)
    bcol_row_free (&rows[r]);
  free (rows);
  free (colw);
  return rc;
}

/* ===================================================================
 * col verb.
 * =================================================================== */

int
col_builtin (WORD_LIST *list)
{
  int bflag = 0;
  const char *files[BCOL_MAX_FILES];
  int n_files = 0;

  for (WORD_LIST *p = list; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "--") == 0)
        {
          for (p = p->next; p; p = p->next)
            if (n_files < BCOL_MAX_FILES)
              files[n_files++] = p->word->word;
          break;
        }
      if (strcmp (w, "--help") == 0 || strcmp (w, "-H") == 0)
        { builtin_usage (); return EXECUTION_SUCCESS; }
      if (strcmp (w, "--version") == 0 || strcmp (w, "-V") == 0)
        { puts ("col 1.0 (bash-loadable)"); return EXECUTION_SUCCESS; }
      if (strcmp (w, "-b") == 0) { bflag = 1; continue; }
      if (w[0] == '-' && w[1] != '\0' && strcmp (w, "-") != 0)
        {
          builtin_error ("col: unknown flag: %s", w);
          builtin_usage ();
          return EX_USAGE;
        }
      if (n_files < BCOL_MAX_FILES)
        files[n_files++] = w;
    }

  int rc = EXECUTION_SUCCESS;
  int n_streams = n_files ? n_files : 1;
  FILE *in_stdin = NULL;
  /* util-linux col terminates its output: an input whose last line has no
     newline still gets one. Track the last byte written across every stream so
     the newline is added once, after the final operand, and not at all for
     empty input -- where util-linux writes nothing. */
  int last = -1;
  for (int fi = 0; fi < n_streams; fi++)
    {
      FILE *fp = bcol_open (n_files ? files[fi] : NULL, &in_stdin);
      if (!fp) { rc = EXECUTION_FAILURE; continue; }
      /* Hold the most recent input byte so -b can drop the byte a
         backspace overstrikes. Without -b, preserve the overstrike bytes. */
      int pending = -1;
      int in_esc = 0;
      int c;
      while ((c = fgetc (fp)) != EOF)
        {
          if (in_esc) { in_esc = 0; continue; }
          if (c == 0x1b) { in_esc = 1; continue; }
          if (c == '\b')
            {
              if (bflag)
                {
                  if (pending != -1) pending = -1;
                }
              else
                {
                  if (pending != -1)
                    {
                      putchar (pending);
                      last = pending;
                      pending = -1;
                    }
                  putchar ('\b');
                  last = '\b';
                }
              continue;
            }
          if (pending != -1) { putchar (pending); last = pending; }
          pending = c;
        }
      if (pending != -1) { putchar (pending); last = pending; pending = -1; }
      if (ferror (fp))
        { builtin_error ("read: %s", strerror (errno)); rc = EXECUTION_FAILURE; }
      if (fp != in_stdin) fclose (fp);
    }
  if (last != -1 && last != '\n')
    putchar ('\n');
  if (in_stdin)
    fclose (in_stdin);
  return rc;
}

/* ===================================================================
 * colrm verb.
 * =================================================================== */

int
colrm_builtin (WORD_LIST *list)
{
  long start = 0, end = 0;
  int n_pos = 0;
  for (WORD_LIST *p = list; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "--help") == 0 || strcmp (w, "-h") == 0)
        { builtin_usage (); return EXECUTION_SUCCESS; }
      if (strcmp (w, "--version") == 0 || strcmp (w, "-V") == 0)
        { puts ("colrm 1.0 (bash-loadable)"); return EXECUTION_SUCCESS; }
      if (w[0] == '-' && w[1] != '\0' && strcmp (w, "-") != 0)
        {
          builtin_error ("colrm: unknown flag: %s", w);
          builtin_usage ();
          return EX_USAGE;
        }
      char *e = NULL;
      long v = strtol (w, &e, 10);
      if (!e || *e != '\0' || v < 1)
        {
          builtin_error ("colrm: bad column: %s", w);
          builtin_usage ();
          return EX_USAGE;
        }
      if (n_pos == 0) start = v;
      else if (n_pos == 1) end = v;
      else
        {
          builtin_error ("colrm: too many operands");
          builtin_usage ();
          return EX_USAGE;
        }
      n_pos++;
    }
  if (n_pos == 1) end = 0;          /* 0 == "to end-of-line" */
  if (n_pos == 2 && end < start)
    {
      builtin_error ("colrm: END (%ld) < START (%ld)", end, start);
      builtin_usage ();
      return EX_USAGE;
    }

  char *line = NULL;
  size_t cap = 0;
  ssize_t got;
  int rc = EXECUTION_SUCCESS;
  FILE *in = bcol_open_stdin ();
  if (!in)
    return EXECUTION_FAILURE;
  while ((got = bcol_getline (in, &line, &cap)) > 0)
    {
      int has_nl = (line[got - 1] == '\n');
      size_t dlen = has_nl ? (size_t) got - 1 : (size_t) got;
      if (n_pos == 0)
        {
          fwrite (line, 1, (size_t) got, stdout);
          continue;
        }
      if ((long) dlen < start)
        {
          fwrite (line, 1, (size_t) got, stdout);
          continue;
        }
      fwrite (line, 1, (size_t) (start - 1), stdout);
      if (end > 0 && (long) dlen > end)
        fwrite (line + end, 1, dlen - (size_t) end, stdout);
      if (has_nl)
        putchar ('\n');
    }
  if (got < 0)
    { builtin_error ("read: %s", strerror (errno)); rc = EXECUTION_FAILURE; }
  free (line);
  fclose (in);
  return rc;
}

/* ===================================================================
 * Bash builtin registration — three names, three structs, all from
 * this translation unit. The sibling stub files col.c and
 * colrm.c contain no code; they exist so patch-bash-loadables.sh's
 * `cp examples/loadables/${name}.c` step has a file at the expected
 * path. The struct + _builtin + _doc symbols below are picked up via
 * the extern declarations inject-loadables-to-builtins-c.sh appends
 * to builtins/builtext.h.
 * =================================================================== */

char *column_doc[] = {
  "Aligned-column formatter (util-linux column subset).",
  "",
  "    column [-x] [-c WIDTH] [FILE...]",
  "    column -t [-s SEPSTR] [-o OUTSTR] [FILE...]",
  "    column --help | --version",
  "",
  "  -t          table mode",
  "  -x          fill rows before columns in non-table mode",
  "  -c WIDTH    output width for non-table mode (default 80)",
  "  -S NUM      use NUM spaces between non-table columns, no tabs",
  "  -s SEPSTR   each byte in SEPSTR splits input fields (preserves",
  "              empty fields between consecutive separators)",
  "  -o OUTSTR   column join string (default '  ')",
  "              getopt-style -ts:, -s:, and -o:: forms are accepted",
  "  --help      show usage",
  "  --version   show version",
  "",
  "Non-table mode formats each input line as one item.",
  "In table mode without -s, runs of whitespace collapse into one separator.",
  (char *) NULL
};

struct builtin column_struct = {
  "column",
  column_builtin,
  BUILTIN_ENABLED,
  column_doc,
  "column [-x] [-c WIDTH] [-t [-s SEPSTR] [-o OUTSTR]] [FILE...]",
  0
};

char *col_doc[] = {
  "Filter CTL-H overstrike sequences (util-linux col).",
  "",
  "    col [-b] [FILE...]",
  "    col --help | --version",
  "",
  "  -b   drop backspace and the byte it overstrikes (no overprint)",
  "  -H, --help     show usage",
  "  -V, --version  show version",
  "",
  "Without -b, backspace overstrike bytes are preserved. ESC and RI bytes are silently dropped.",
  (char *) NULL
};

struct builtin col_struct = {
  "col",
  col_builtin,
  BUILTIN_ENABLED,
  col_doc,
  "col [-b] [FILE...]",
  0
};

char *colrm_doc[] = {
  "Remove byte-columns from each stdin line (util-linux colrm).",
  "",
  "    colrm [START [END]]",
  "    colrm --help | --version",
  "",
  "  START      1-based first column to remove",
  "  END        1-based last column to remove (omit = to end-of-line)",
  "  -h, --help     show usage",
  "  -V, --version  show version",
  "",
  "Bytes (not display cells) are used for column counts.",
  (char *) NULL
};

struct builtin colrm_struct = {
  "colrm",
  colrm_builtin,
  BUILTIN_ENABLED,
  colrm_doc,
  "colrm [START [END]]",
  0
};
