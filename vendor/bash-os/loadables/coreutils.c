/* SPDX-License-Identifier: MIT */
/* coreutils.c — 12 small POSIX coreutils as a single bash loadable.
 *
 * Phase MISSING_LOADABLES T3 of bash-os. Bundles twelve short
 * coreutils that each lack a dedicated bash builtin:
 *
 *   coreutils tac    [FILE...]                  reverse lines
 *   coreutils shuf   [-i LO-HI|-e|-n COUNT|--random-source=F] [FILE]
 *   coreutils factor N [N...]                   prime factorize
 *   coreutils yes    [STRING...]                infinite repeat
 *   coreutils fmt    [-w WIDTH] [FILE...]       collapse paragraphs
 *   coreutils tsort  [FILE]                     topological sort
 *   coreutils nproc                             sched_getaffinity count; --all is configured
 *   coreutils numfmt [--to=iec|iec-i|si] [--from=iec|iec-i|si] N
 *   coreutils shred  [-n N] [-u] [-z] FILE...   overwrite + unlink
 *   coreutils groups [USER]                     list user groups
 *   coreutils install [-m MODE] [-d|-D] SRC... DST
 *   coreutils mknod  PATH {b|c|p} [MAJ MIN]     create device/fifo
 *
 * Twelve verbs, one .c file, single struct builtin dispatched via
 * the leading word. Each verb keeps its own static helpers under a
 * `bcu_<verb>_` prefix; the public entry points are `bcu_<verb>_cmd`
 * (taking a WORD_LIST). The bottom of the file holds the dispatch
 * table + the bash builtin glue.
 *
 * POSIX wrappers in rootfs/bash-os/<verb>.sh exec the verb directly so
 * external fork-exec callers (Node child_process, scripts that use
 * /usr/bin/<verb>) get a real PATH entry. The wrappers all `exec
 * coreutils <verb> "$@"` so the loadable runs in-process.
 *
 * Source counterparts:
 *   research/refs/coreutils/src/{tac,shuf,factor,yes,fmt,tsort,
 *     nproc,numfmt,shred,groups,install,mknod}.c (GNU canonical)
 *   research/refs/sbase/{tac,factor,yes,tsort,nproc,shred}.c (minimal)
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <sched.h>

#include "loadables.h"
#include "error.h"
#include <limits.h>

static void *bcu_calloc (size_t n, size_t size)
{
  if (size && n > SIZE_MAX / size) { fatal_error ("coreutils: allocation too large"); abort (); }
  size_t total = n * size;
  void *p = xmalloc (total ? total : 1);
  memset (p, 0, total);
  return p;
}
static char *bcu_strdup (const char *s)
{
  size_t n = strlen (s) + 1;
  char *p = xmalloc (n);
  memcpy (p, s, n);
  return p;
}
/* Temporary argument lists borrow words from Bash, owning only their nodes.
   Cleanup also runs when option parsing returns early. */
static void bcu_free_nodes (WORD_LIST **head)
{
  while (*head) { WORD_LIST *next = (*head)->next; free (*head); *head = next; }
}

#ifndef BUFSZ
#  define BUFSZ 8192
#endif

/* ===================================================================
 * Shared helpers — file I/O, parsing.
 * =================================================================== */

static FILE *
bcu_open_input (const char *path)
{
  if (path == NULL || (path[0] == '-' && path[1] == '\0'))
    return stdin;
  FILE *fp = fopen (path, "r");
  if (!fp)
    builtin_error ("%s: %s", path, strerror (errno));
  return fp;
}

/* Slurp a stream into a malloc'd buffer; returns -1 on error. *out is
 * freshly malloc'd with one extra byte for the caller's convenience
 * (callers may NUL-terminate themselves). */
static ssize_t
bcu_slurp (FILE *fp, char **out)
{
  size_t cap = 4096, len = 0;
  char *buf = xmalloc (cap);
  if (!buf) { *out = NULL; return -1; }
  for (;;)
    {
      if (len + 1 >= cap)
        {
          size_t ncap = cap * 2;
          char *nbuf = xrealloc (buf, ncap);
          if (!nbuf) { free (buf); *out = NULL; return -1; }
          buf = nbuf; cap = ncap;
        }
      size_t n = fread (buf + len, 1, cap - len - 1, fp);
      len += n;
      if (n == 0) break;
    }
  if (ferror (fp))
    {
      free (buf);
      *out = NULL;
      return -1;
    }
  buf[len] = '\0';
  *out = buf;
  return (ssize_t) len;
}

/* strtoll wrapper that returns 1 on success, 0 on failure. */
static int
bcu_parse_ll (const char *s, long long *out)
{
  if (!s || !*s) return 0;
  errno = 0;
  char *end = NULL;
  long long v = strtoll (s, &end, 10);
  if (errno || !end || *end != '\0') return 0;
  *out = v;
  return 1;
}

static void
bcu_usage (const char *verb)
{
  if (strcmp (verb, "tac") == 0)
    builtin_error ("usage: coreutils tac [FILE...]");
  else if (strcmp (verb, "shuf") == 0)
    builtin_error ("usage: coreutils shuf [-i LO-HI|-e|-n COUNT|--random-source=F] [FILE]");
  else if (strcmp (verb, "factor") == 0)
    builtin_error ("usage: coreutils factor N [N...]");
  else if (strcmp (verb, "yes") == 0)
    builtin_error ("usage: coreutils yes [STRING...]");
  else if (strcmp (verb, "fmt") == 0)
    builtin_error ("usage: coreutils fmt [-w WIDTH] [FILE...]");
  else if (strcmp (verb, "tsort") == 0)
    builtin_error ("usage: coreutils tsort [FILE]");
  else if (strcmp (verb, "nproc") == 0)
    builtin_error ("usage: coreutils nproc [--all] [--ignore=N]");
  else if (strcmp (verb, "numfmt") == 0)
    builtin_error ("usage: coreutils numfmt [--to=iec|iec-i|si] [--from=iec|iec-i|si] N");
  else if (strcmp (verb, "shred") == 0)
    builtin_error ("usage: coreutils shred [-n N] [-z] [-u] [-s SIZE] FILE...");
  else if (strcmp (verb, "groups") == 0)
    builtin_error ("usage: coreutils groups [USER...]");
  else if (strcmp (verb, "install") == 0)
    builtin_error ("usage: coreutils install [-m MODE] [-o OWNER] [-g GROUP] [-d|-D] SRC... DST");
  else if (strcmp (verb, "mknod") == 0)
    builtin_error ("usage: coreutils mknod [-m MODE] PATH {b|c|p} [MAJ MIN]");
  else
    builtin_usage ();
}

/* ===================================================================
 * tac — reverse lines.
 * =================================================================== */

static int
bcu_tac_stream (FILE *fp, const char *sep)
{
  char *buf = NULL;
  ssize_t len = bcu_slurp (fp, &buf);
  if (len < 0) return EXECUTION_FAILURE;
  if (len == 0) { free (buf); return EXECUTION_SUCCESS; }

  size_t seplen = strlen (sep);

  /* Split into records the way GNU tac does: the separator is attached
   * AFTER the text it follows, so a record runs from one record-start up
   * to (and including) the next separator. Collect record start offsets,
   * then emit the records in reverse. A trailing record that is NOT
   * separator-terminated is emitted first, as-is (no separator is added —
   * `printf 'a\nb\nc' | tac` => "cb\na\n", not "c\nb\na\n"). */
  size_t *starts = NULL, n = 0, cap = 0;
  #define BCU_TAC_PUSH(o) do { \
      if (n == cap) { cap = cap ? cap * 2 : 64; \
                      starts = xrealloc (starts, cap * sizeof *starts); \
                      if (!starts) { free (buf); builtin_error ("tac: oom"); return EXECUTION_FAILURE; } } \
      starts[n++] = (o); } while (0)
  BCU_TAC_PUSH (0);
  if (seplen > 0)
    {
      ssize_t i = 0;
      while (i + (ssize_t) seplen <= len)
        {
          if (memcmp (buf + i, sep, seplen) == 0)
            {
              size_t next = (size_t) i + seplen;
              if ((ssize_t) next < len) BCU_TAC_PUSH (next);
              i += (ssize_t) seplen;
            }
          else
            i++;
        }
    }
  #undef BCU_TAC_PUSH
  for (ssize_t k = (ssize_t) n - 1; k >= 0; k--)
    {
      size_t s = starts[k];
      size_t e = (k + 1 < (ssize_t) n) ? starts[k + 1] : (size_t) len;
      fwrite (buf + s, 1, e - s, stdout);
    }
  free (starts);
  free (buf);
  return EXECUTION_SUCCESS;
}

static int
bcu_tac_cmd (WORD_LIST *list)
{
  const char *sep = "\n";
  /* Parse -s SEP / -sSEP / --separator=SEP (GNU tac). -r/-b out of scope. */
  while (list && list->word->word[0] == '-' && list->word->word[1])
    {
      const char *w = list->word->word;
      if (!strcmp (w, "--")) { list = list->next; break; }
      if (!strcmp (w, "-s") || !strcmp (w, "--separator"))
        {
          if (!list->next) { builtin_error ("tac: option requires an argument -- 's'"); return EX_USAGE; }
          list = list->next; sep = list->word->word; list = list->next; continue;
        }
      if (!strncmp (w, "-s", 2))            { sep = w + 2; list = list->next; continue; }
      if (!strncmp (w, "--separator=", 12)) { sep = w + 12; list = list->next; continue; }
      break;   /* unknown dash-word: treat as a filename operand (e.g. "-") */
    }
  if (!sep[0]) sep = "\n";   /* empty separator: fall back to newline, as GNU */

  if (!list)
    return bcu_tac_stream (stdin, sep);

  int rc = EXECUTION_SUCCESS;
  for (WORD_LIST *w = list; w; w = w->next)
    {
      FILE *fp = bcu_open_input (w->word->word);
      if (!fp) { rc = EXECUTION_FAILURE; continue; }
      if (bcu_tac_stream (fp, sep) != EXECUTION_SUCCESS)
        rc = EXECUTION_FAILURE;
      if (fp != stdin) fclose (fp);
    }
  return rc;
}

/* ===================================================================
 * shuf — random permutation.
 *
 * Supports:
 *   -i LO-HI         shuffle integers LO..HI
 *   -e ITEM...       shuffle the explicit arguments
 *   -n COUNT         output at most COUNT items
 *   --random-source=FILE
 *                    use FILE as seed source (read 8 bytes;
 *                    deterministic for reproducible test pinning).
 * Plain `shuf` (or `shuf FILE`) reads lines from stdin/FILE.
 * =================================================================== */

/* xorshift64 — small deterministic PRNG seeded from /dev/urandom or
 * the user-supplied --random-source. NOT cryptographic; matches GNU
 * shuf's intent of "random for human-scale enumeration." */
static uint64_t bcu_shuf_state = 0;

static void
bcu_shuf_seed (const char *source)
{
  uint64_t s = 0;
  if (source)
    {
      FILE *fp = fopen (source, "rb");
      if (fp)
        {
          unsigned char b[8] = {0};
          fread (b, 1, 8, fp);
          fclose (fp);
          for (int i = 0; i < 8; i++)
            s = (s << 8) | b[i];
        }
    }
  if (s == 0)
    {
      FILE *fp = fopen ("/dev/urandom", "rb");
      if (fp)
        {
          unsigned char b[8] = {0};
          fread (b, 1, 8, fp);
          fclose (fp);
          for (int i = 0; i < 8; i++)
            s = (s << 8) | b[i];
        }
    }
  if (s == 0)
    s = ((uint64_t) time (NULL) << 16) ^ (uint64_t) getpid ();
  bcu_shuf_state = s ? s : 0x9E3779B97F4A7C15ULL;
}

static uint64_t
bcu_shuf_rand (void)
{
  uint64_t x = bcu_shuf_state;
  x ^= x << 13; x ^= x >> 7; x ^= x << 17;
  bcu_shuf_state = x;
  return x;
}

/* Fisher-Yates in place. */
static void
bcu_shuf_permute (char **items, size_t n)
{
  for (size_t i = n; i > 1; i--)
    {
      size_t j = (size_t) (bcu_shuf_rand () % i);
      char *t = items[i - 1];
      items[i - 1] = items[j];
      items[j] = t;
    }
}

static int
bcu_shuf_cmd (WORD_LIST *list)
{
  const char *source = NULL;
  long long lo = 0, hi = -1;
  int have_range = 0, have_e = 0;
  long long limit = -1;
  WORD_LIST *evals_head __attribute__((cleanup(bcu_free_nodes))) = NULL;
  WORD_LIST *evals_tail = NULL;
  const char *filename = NULL;

  for (WORD_LIST *w = list; w; w = w->next)
    {
      const char *a = w->word->word;
      if (have_e)
        {
          /* After -e, everything is a literal item. */
          WORD_LIST *nw = bcu_calloc (1, sizeof (*nw));
          if (!nw) { builtin_error ("oom"); return EXECUTION_FAILURE; }
          nw->word = w->word;
          if (!evals_head) evals_head = nw; else evals_tail->next = nw;
          evals_tail = nw;
          continue;
        }
      if (strcmp (a, "-e") == 0) { have_e = 1; continue; }
      if (strcmp (a, "-i") == 0 && w->next)
        {
          w = w->next;
          const char *r = w->word->word;
          char *dash = strchr (r, '-');
          if (!dash) { builtin_error ("shuf: bad -i range: %s", r); bcu_usage ("shuf"); return EX_USAGE; }
          *dash = '\0';
          int valid = bcu_parse_ll (r, &lo) && bcu_parse_ll (dash + 1, &hi)
                      && lo >= 0 && hi >= lo;
          *dash = '-';
          if (!valid || (uintmax_t) hi - (uintmax_t) lo >= SIZE_MAX / sizeof (char *))
            { builtin_error ("shuf: bad -i range"); bcu_usage ("shuf"); return EX_USAGE; }
          have_range = 1;
          continue;
        }
      if (strcmp (a, "-n") == 0 && w->next)
        {
          w = w->next;
          if (!bcu_parse_ll (w->word->word, &limit) || limit < 0)
            { builtin_error ("shuf: bad -n"); bcu_usage ("shuf"); return EX_USAGE; }
          continue;
        }
      if (strncmp (a, "--random-source=", 16) == 0)
        { source = a + 16; continue; }
      if (a[0] == '-' && a[1] != '\0' && strcmp (a, "-") != 0)
        { builtin_error ("shuf: unknown flag: %s", a); bcu_usage ("shuf"); return EX_USAGE; }
      filename = a;
    }

  bcu_shuf_seed (source);

  size_t n = 0, cap = 0;
  char **items = NULL;

  if (have_range)
    {
      size_t need = (size_t) ((uintmax_t) hi - (uintmax_t) lo + 1);
      items = xmalloc (need * sizeof (*items));
      if (!items) { builtin_error ("oom"); return EXECUTION_FAILURE; }
      for (size_t i = 0; i < need; i++)
        {
          char buf[32];
          snprintf (buf, sizeof buf, "%lld", lo + (long long) i);
          items[n++] = bcu_strdup (buf);
        }
    }
  else if (have_e)
    {
      for (WORD_LIST *w = evals_head; w; w = w->next)
        {
          if (n == cap)
            { cap = cap ? cap * 2 : 16; items = xrealloc (items, cap * sizeof (*items)); }
          items[n++] = bcu_strdup (w->word->word);
        }
    }
  else
    {
      FILE *fp = filename ? bcu_open_input (filename) : stdin;
      if (!fp) return EXECUTION_FAILURE;
      char *line = NULL; size_t llen = 0; ssize_t r;
      while ((r = getline (&line, &llen, fp)) != -1)
        {
          if (r > 0 && line[r - 1] == '\n') line[r - 1] = '\0';
          if (n == cap)
            { cap = cap ? cap * 2 : 64; items = xrealloc (items, cap * sizeof (*items)); }
          items[n++] = bcu_strdup (line);
        }
      free (line);
      if (fp != stdin) fclose (fp);
    }

  /* Permute, then optionally truncate. */
  bcu_shuf_permute (items, n);
  size_t out_n = n;
  if (limit >= 0 && (size_t) limit < n) out_n = (size_t) limit;

  for (size_t i = 0; i < out_n; i++)
    {
      fputs (items[i], stdout);
      fputc ('\n', stdout);
    }

  for (size_t i = 0; i < n; i++) free (items[i]);
  free (items);
  /* Free the -e word list spine (we did not own w->word). */


  return EXECUTION_SUCCESS;
}

/* ===================================================================
 * factor — prime factorize one or more decimal numbers.
 *
 * Trial division up to sqrt(N); good enough for the POSIX-shell use
 * case. 64-bit unsigned input range.
 * =================================================================== */

static void
bcu_factor_print (uint64_t n)
{
  printf ("%" PRIu64 ":", n);
  if (n <= 1)
    { putchar ('\n'); return; }
  while ((n & 1ULL) == 0)
    { printf (" 2"); n >>= 1; }
  for (uint64_t d = 3; d * d <= n; d += 2)
    while (n % d == 0)
      { printf (" %" PRIu64, d); n /= d; }
  if (n > 1)
    printf (" %" PRIu64, n);
  putchar ('\n');
}

static int
bcu_factor_cmd (WORD_LIST *list)
{
  if (list)
    {
      int rc = EXECUTION_SUCCESS;
      for (WORD_LIST *w = list; w; w = w->next)
        {
          errno = 0;
          char *end = NULL;
          unsigned long long n = strtoull (w->word->word, &end, 10);
          if (errno || !end || *end != '\0')
            {
              builtin_error ("factor: not a number: %s", w->word->word);
              rc = EXECUTION_FAILURE;
              continue;
            }
          bcu_factor_print ((uint64_t) n);
        }
      return rc;
    }

  /* No args: read whitespace-separated numbers from stdin. */
  char *line = NULL; size_t llen = 0; ssize_t r;
  int rc = EXECUTION_SUCCESS;
  while ((r = getline (&line, &llen, stdin)) != -1)
    {
      char *p = line;
      while (*p)
        {
          while (*p && isspace ((unsigned char) *p)) p++;
          if (!*p) break;
          char *end = NULL;
          errno = 0;
          unsigned long long n = strtoull (p, &end, 10);
          if (errno || end == p)
            { rc = EXECUTION_FAILURE; while (*p && !isspace ((unsigned char) *p)) p++; continue; }
          bcu_factor_print ((uint64_t) n);
          p = end;
        }
    }
  free (line);
  return rc;
}

/* ===================================================================
 * yes — repeat STRING (default "y") forever, one per line.
 * =================================================================== */

static int
bcu_yes_cmd (WORD_LIST *list)
{
  /* Assemble the line once; loop tight on fwrite. SIGPIPE from
   * `yes | head -3` terminates us cleanly. */
  char *line = NULL;
  size_t llen = 0;
  if (!list)
    {
      line = bcu_strdup ("y\n");
      llen = 2;
    }
  else
    {
      size_t total = 0;
      for (WORD_LIST *w = list; w; w = w->next)
        total += strlen (w->word->word) + 1;
      line = xmalloc (total + 1);
      if (!line) { builtin_error ("oom"); return EXECUTION_FAILURE; }
      char *p = line;
      for (WORD_LIST *w = list; w; w = w->next)
        {
          size_t n = strlen (w->word->word);
          memcpy (p, w->word->word, n); p += n;
          *p++ = w->next ? ' ' : '\n';
        }
      *p = '\0';
      llen = (size_t) (p - line);
    }
  while (fwrite (line, 1, llen, stdout) == llen)
    ;
  free (line);
  return EXECUTION_FAILURE;
}

/* ===================================================================
 * fmt — paragraph formatter.
 *
 * Subset of GNU fmt: collapse adjacent non-blank lines into
 * paragraphs and wrap at WIDTH (default 75). Blank lines separate
 * paragraphs. Leading whitespace on the first line of a paragraph is
 * preserved as the prefix for that paragraph's wrapped output.
 *
 * Line breaking is GNU fmt's cost-minimizing optimal fit, ported
 * verbatim from research/refs/coreutils/src/fmt.c (fmt_paragraph,
 * line_cost, base_cost, put_paragraph and the cost constants). The
 * greedy filler was replaced because GNU breaks paragraphs at the
 * least-total-cost set of lines, not the first line that fits.
 * =================================================================== */

/* Cost model constants and word descriptor — copied verbatim from GNU
 * fmt.c so the dynamic program below reproduces its breaks exactly.
 * Costs/bonuses are "equivalent departure from optimal length * 10". */

typedef long int BCU_COST;
#define BCU_MAXCOST  ((BCU_COST) ((~(unsigned long) 0) >> 1))   /* LONG_MAX */

#define BCU_LEEWAY        7         /* prefer lines LEEWAY% short of max. */
#define BCU_SQR(n)        ((BCU_COST) (n) * (BCU_COST) (n))
#define BCU_EQUIV(n)      BCU_SQR (n)
#define BCU_SHORT_COST(n) BCU_EQUIV ((n) * 10)        /* line n short/long. */
#define BCU_RAGGED_COST(n) (BCU_SHORT_COST (n) / 2)   /* adjacent-line diff. */
#define BCU_LINE_COST     BCU_EQUIV (70)              /* basic per-line cost. */
#define BCU_WIDOW_COST(n) (BCU_EQUIV (200) / ((n) + 2))
#define BCU_ORPHAN_COST(n) (BCU_EQUIV (150) / ((n) + 2))
#define BCU_SENTENCE_BONUS BCU_EQUIV (50)
#define BCU_NOBREAK_COST  BCU_EQUIV (600)
#define BCU_PAREN_BONUS   BCU_EQUIV (40)
#define BCU_PUNCT_BONUS   BCU_EQUIV (40)
#define BCU_LINE_CREDIT   BCU_EQUIV (3)

typedef struct bcu_word {
  const char *text;        /* the text of the word. */
  int length;              /* length of this word. */
  int space;               /* size of the following space (1 or 2). */
  unsigned int paren:1;    /* starts with open paren. */
  unsigned int period:1;   /* ends in [.?!])* */
  unsigned int punct:1;    /* ends in punctuation. */
  unsigned int final:1;    /* end of sentence. */
  /* Filled in during optimization. */
  int line_length;         /* length of the best line starting here. */
  BCU_COST best_cost;      /* cost of best paragraph starting here. */
  struct bcu_word *next_break;  /* break which achieves best_cost. */
} BCU_WORD;

/* Per-paragraph optimization state (GNU uses file-scope globals; we keep
 * them in one struct so the loadable stays reentrant-friendly). */
typedef struct {
  BCU_WORD *word;          /* word[0..n] (n is the sentinel). */
  BCU_WORD *word_limit;    /* &word[n], the sentinel slot. */
  int max_width;
  int goal_width;
  int first_indent;        /* indent of the first line (prefix length). */
  int other_indent;        /* indent of subsequent lines. */
} BCU_FMTCTX;

/* GNU isopen/isclose/isperiod ctype helpers. */
#define BCU_ISOPEN(c)   (strchr ("(['`\"", (c)) != NULL)
#define BCU_ISCLOSE(c)  (strchr (")]'\"",  (c)) != NULL)
#define BCU_ISPERIOD(c) (strchr (".?!",    (c)) != NULL)

/* GNU check_punctuation: set paren/punct/period flags for word W. */
static void
bcu_fmt_check_punctuation (BCU_WORD *w)
{
  const char *start = w->text;
  const char *finish = start + (w->length - 1);
  unsigned char fin = (unsigned char) *finish;

  w->paren  = BCU_ISOPEN ((unsigned char) *start);
  w->punct  = !! ispunct (fin);
  while (start < finish && BCU_ISCLOSE ((unsigned char) *finish))
    finish--;
  w->period = BCU_ISPERIOD ((unsigned char) *finish);
}

/* GNU base_cost: constant component of the cost of breaking before THIS. */
static BCU_COST
bcu_fmt_base_cost (BCU_FMTCTX *ctx, BCU_WORD *this)
{
  BCU_COST cost = BCU_LINE_COST;

  if (this > ctx->word)
    {
      if ((this - 1)->period)
        {
          if ((this - 1)->final)
            cost -= BCU_SENTENCE_BONUS;
          else
            cost += BCU_NOBREAK_COST;
        }
      else if ((this - 1)->punct)
        cost -= BCU_PUNCT_BONUS;
      else if (this > ctx->word + 1 && (this - 2)->final)
        cost += BCU_WIDOW_COST ((this - 1)->length);
    }

  if (this->paren)
    cost -= BCU_PAREN_BONUS;
  else if (this->final)
    cost += BCU_ORPHAN_COST (this->length);

  return cost;
}

/* GNU line_cost: the LEN-dependent component of breaking before NEXT. */
static BCU_COST
bcu_fmt_line_cost (BCU_FMTCTX *ctx, BCU_WORD *next, int len)
{
  int n;
  BCU_COST cost;

  if (next == ctx->word_limit)
    return 0;
  n = ctx->goal_width - len;
  cost = BCU_SHORT_COST (n);
  if (next->next_break != ctx->word_limit)
    {
      n = len - next->line_length;
      cost += BCU_RAGGED_COST (n);
    }
  return cost;
}

/* GNU fmt_paragraph: optimal formatting for the whole paragraph via the
 * suffix dynamic program. There is no long-paragraph split here (the
 * loadable buffers the whole paragraph), so last_line_length is 0. */
static void
bcu_fmt_paragraph (BCU_FMTCTX *ctx)
{
  BCU_WORD *w;
  int len;
  BCU_COST wcost, best;
  int saved_length;

  ctx->word_limit->best_cost = 0;
  saved_length = ctx->word_limit->length;
  ctx->word_limit->length = ctx->max_width;   /* sentinel. */

  for (BCU_WORD *start = ctx->word_limit - 1; start >= ctx->word; start--)
    {
      best = BCU_MAXCOST;
      len = (start == ctx->word) ? ctx->first_indent : ctx->other_indent;

      /* At least one word, however long, in the line. */
      w = start;
      len += w->length;
      do
        {
          w++;

          /* Consider breaking before w. */
          wcost = bcu_fmt_line_cost (ctx, w, len) + w->best_cost;
          if (wcost < best)
            {
              best = wcost;
              start->next_break = w;
              start->line_length = len;
            }

          /* Avoid computing len from the (possibly huge) sentinel. */
          if (w == ctx->word_limit)
            break;

          len += (w - 1)->space + w->length;  /* w > start >= word. */
        }
      while (len <= ctx->max_width);
      start->best_cost = best + bcu_fmt_base_cost (ctx, start);
    }

  ctx->word_limit->length = saved_length;
}

/* Emit one paragraph's words with GNU-optimal line breaks. Re-emits the
 * paragraph prefix at the start of each output line. */
static void
bcu_fmt_emit_para (char **words, size_t n, const char *prefix, int width)
{
  if (!n) return;
  size_t prefixlen = prefix ? strlen (prefix) : 0;

  /* Build the WORD array: n words plus a sentinel slot (GNU style). */
  BCU_WORD *word = bcu_calloc (n + 1, sizeof *word);
  if (!word)
    {
      /* Out of memory: degrade to one-word-per-line so we still emit. */
      for (size_t i = 0; i < n; i++)
        {
          if (prefix) fputs (prefix, stdout);
          fputs (words[i], stdout);
          putchar ('\n');
        }
      return;
    }

  for (size_t i = 0; i < n; i++)
    {
      word[i].text = words[i];
      word[i].length = (int) strlen (words[i]);
      bcu_fmt_check_punctuation (&word[i]);   /* sets paren/punct/period. */
      word[i].final = 0;
      word[i].space = 1;
    }

  /* GNU sets a word's 'final' flag only when its period is followed by
   * end-of-line or >1 space in the SOURCE. The stream feeding us has
   * already collapsed inter-word and inter-line whitespace to a single
   * space, so that lookahead is gone; the one word we can still prove is
   * sentence-final is the paragraph's last (GNU's get_paragraph forces
   * (word_limit-1)->period = final = true). We mark only that word, which
   * keeps single-spaced reflowed input byte-identical to GNU and avoids
   * inventing the 2-space gaps GNU never emits for such input. */
  word[n - 1].period = word[n - 1].final = 1;

  BCU_FMTCTX ctx;
  ctx.word = word;
  ctx.word_limit = &word[n];
  ctx.max_width = width;
  /* goal_width = width * (2*(100-LEEWAY)+1) / 200  (GNU derivation). */
  ctx.goal_width = width * (2 * (100 - BCU_LEEWAY) + 1) / 200;
  if (ctx.goal_width > width) ctx.goal_width = width;
  ctx.first_indent = (int) prefixlen;
  ctx.other_indent = (int) prefixlen;

  bcu_fmt_paragraph (&ctx);

  /* put_paragraph + put_line (GNU): the outer loop iterates the line-start
   * words via the next_break chain; each line emits its words up to (but
   * not including) the next break, separated by w->space. A distinct inner
   * cursor is used so the chain pointer is never clobbered. */
  for (BCU_WORD *line = word; line != ctx.word_limit; line = line->next_break)
    {
      if (prefix) fputs (prefix, stdout);
      BCU_WORD *endline = line->next_break - 1;
      BCU_WORD *w = line;
      for (; w != endline; w++)
        {
          fwrite (w->text, 1, (size_t) w->length, stdout);
          for (int s = 0; s < w->space; s++) putchar (' ');
        }
      fwrite (w->text, 1, (size_t) w->length, stdout);
      putchar ('\n');
    }

  free (word);
}

static int
bcu_fmt_stream (FILE *fp, int width)
{
  char *line = NULL; size_t llen = 0; ssize_t r;
  char **words = NULL; size_t n = 0, cap = 0;
  char *prefix = NULL;

  while ((r = getline (&line, &llen, fp)) != -1)
    {
      if (r > 0 && line[r - 1] == '\n') { line[r - 1] = '\0'; r--; }
      int blank = 1;
      for (ssize_t i = 0; i < r; i++)
        if (!isspace ((unsigned char) line[i])) { blank = 0; break; }
      if (blank)
        {
          bcu_fmt_emit_para (words, n, prefix, width);
          if (n) putchar ('\n');
          for (size_t i = 0; i < n; i++) free (words[i]);
          n = 0;
          free (prefix); prefix = NULL;
          continue;
        }
      char *p = line;
      if (!prefix)
        {
          size_t ws = 0;
          while (p[ws] && (p[ws] == ' ' || p[ws] == '\t')) ws++;
          if (ws)
            {
              prefix = xmalloc (ws + 1);
              memcpy (prefix, p, ws);
              prefix[ws] = '\0';
            }
        }
      /* Skip leading whitespace; we'll re-emit prefix per line. */
      while (*p == ' ' || *p == '\t') p++;
      while (*p)
        {
          while (*p && isspace ((unsigned char) *p)) p++;
          if (!*p) break;
          char *start = p;
          while (*p && !isspace ((unsigned char) *p)) p++;
          size_t wlen = (size_t) (p - start);
          if (n == cap) { cap = cap ? cap * 2 : 64; words = xrealloc (words, cap * sizeof (*words)); }
          char *w = xmalloc (wlen + 1);
          memcpy (w, start, wlen);
          w[wlen] = '\0';
          words[n++] = w;
        }
    }
  bcu_fmt_emit_para (words, n, prefix, width);
  for (size_t i = 0; i < n; i++) free (words[i]);
  free (words); free (prefix); free (line);
  return EXECUTION_SUCCESS;
}

static int
bcu_fmt_cmd (WORD_LIST *list)
{
  int width = 75;
  WORD_LIST *files __attribute__((cleanup(bcu_free_nodes))) = NULL;
  WORD_LIST *files_tail = NULL;
  for (WORD_LIST *w = list; w; w = w->next)
    {
      const char *a = w->word->word;
      if (strcmp (a, "-w") == 0 && w->next)
        {
          w = w->next;
          long long v;
          if (!bcu_parse_ll (w->word->word, &v) || v <= 0)
            { builtin_error ("fmt: bad -w"); bcu_usage ("fmt"); return EX_USAGE; }
          width = (int) v;
          continue;
        }
      if (a[0] == '-' && isdigit ((unsigned char) a[1]))
        {
          long long v;
          if (bcu_parse_ll (a + 1, &v) && v > 0) { width = (int) v; continue; }
        }
      WORD_LIST *nw = bcu_calloc (1, sizeof (*nw));
      nw->word = w->word;
      if (!files) files = nw; else files_tail->next = nw;
      files_tail = nw;
    }

  int rc = EXECUTION_SUCCESS;
  if (!files)
    rc = bcu_fmt_stream (stdin, width);
  else
    for (WORD_LIST *w = files; w; w = w->next)
      {
        FILE *fp = bcu_open_input (w->word->word);
        if (!fp) { rc = EXECUTION_FAILURE; continue; }
        if (bcu_fmt_stream (fp, width) != EXECUTION_SUCCESS) rc = EXECUTION_FAILURE;
        if (fp != stdin) fclose (fp);
      }

  return rc;
}

/* ===================================================================
 * tsort — topological sort over whitespace-separated pairs (A B per
 *         edge). Output is one node per line in topological order.
 *         Cycles get a diagnostic but partial output still emerges.
 * =================================================================== */

typedef struct bcu_tnode {
  char *name;
  size_t *succ;       /* indices into nodes[] */
  size_t  nsucc, csucc;
  int     indeg;
  int     emitted;
} bcu_tnode_t;

static size_t
bcu_tsort_find (bcu_tnode_t *nodes, size_t n, const char *name)
{
  for (size_t i = 0; i < n; i++)
    if (strcmp (nodes[i].name, name) == 0) return i;
  return (size_t) -1;
}

static int
bcu_tsort_cmd (WORD_LIST *list)
{
  const char *filename = list ? list->word->word : NULL;
  FILE *fp = filename ? bcu_open_input (filename) : stdin;
  if (!fp) return EXECUTION_FAILURE;

  bcu_tnode_t *nodes = NULL;
  size_t n = 0, cap = 0;
  char *buf = NULL;
  ssize_t blen = bcu_slurp (fp, &buf);
  if (fp != stdin) fclose (fp);
  if (blen < 0) return EXECUTION_FAILURE;

  /* Tokenize whitespace-separated words, pairing each consecutive
   * (a, b) as an edge a -> b. Singletons are passed through as
   * standalone nodes. */
  char *toks[2] = {NULL, NULL};
  int pair_pos = 0;
  char *p = buf;
  while (*p)
    {
      while (*p && isspace ((unsigned char) *p)) p++;
      if (!*p) break;
      char *start = p;
      while (*p && !isspace ((unsigned char) *p)) p++;
      char saved = *p; *p = '\0';
      char *tok = bcu_strdup (start);
      *p = saved;

      /* Ensure node exists. */
      size_t idx = bcu_tsort_find (nodes, n, tok);
      if (idx == (size_t) -1)
        {
          if (n == cap) { cap = cap ? cap * 2 : 32; nodes = xrealloc (nodes, cap * sizeof (*nodes)); }
          nodes[n].name = tok;
          nodes[n].succ = NULL; nodes[n].nsucc = nodes[n].csucc = 0;
          nodes[n].indeg = 0; nodes[n].emitted = 0;
          idx = n++;
        }
      else
        free (tok);

      toks[pair_pos++] = nodes[idx].name;
      if (pair_pos == 2)
        {
          /* Edge toks[0] -> toks[1]; skip self-loops (they trip cycle
           * detection but POSIX tsort tolerates them when both items
           * appear together — same behavior here). */
          size_t a = bcu_tsort_find (nodes, n, toks[0]);
          size_t b = bcu_tsort_find (nodes, n, toks[1]);
          if (a != b)
            {
              if (nodes[a].nsucc == nodes[a].csucc)
                {
                  nodes[a].csucc = nodes[a].csucc ? nodes[a].csucc * 2 : 4;
                  nodes[a].succ = xrealloc (nodes[a].succ, nodes[a].csucc * sizeof (*nodes[a].succ));
                }
              nodes[a].succ[nodes[a].nsucc++] = b;
              nodes[b].indeg++;
            }
          pair_pos = 0;
        }
    }
  free (buf);

  /* Kahn: emit zero-indegree nodes, decrement successors, repeat. */
  int rc = EXECUTION_SUCCESS;
  size_t emitted = 0;
  for (;;)
    {
      ssize_t pick = -1;
      for (size_t i = 0; i < n; i++)
        if (!nodes[i].emitted && nodes[i].indeg == 0) { pick = (ssize_t) i; break; }
      if (pick < 0) break;
      printf ("%s\n", nodes[pick].name);
      nodes[pick].emitted = 1;
      emitted++;
      for (size_t k = 0; k < nodes[pick].nsucc; k++)
        nodes[nodes[pick].succ[k]].indeg--;
    }
  if (emitted < n)
    {
      builtin_error ("tsort: cycle detected (%zu nodes unsorted)", n - emitted);
      for (size_t i = 0; i < n; i++)
        if (!nodes[i].emitted) printf ("%s\n", nodes[i].name);
      rc = EXECUTION_FAILURE;
    }

  for (size_t i = 0; i < n; i++)
    { free (nodes[i].name); free (nodes[i].succ); }
  free (nodes);
  return rc;
}

/* ===================================================================
 * nproc — processors available to this process; --all is every configured one
 * =================================================================== */

/* Processors this process may actually run on. GNU nproc's default counts the
   affinity mask, not the online CPUs, so under `taskset -c 3` it prints 1 while
   _SC_NPROCESSORS_ONLN still says 12. Returns 0 when the mask is unavailable so
   the caller can fall back.

   Scope: GNU also lets OMP_NUM_THREADS and OMP_THREAD_LIMIT override the
   default. That is deliberately not implemented here -- this is not an OpenMP
   runtime host -- and is recorded as a scope difference, not parity. */
static long
bcu_nproc_available (void)
{
  cpu_set_t set;
  if (sched_getaffinity (0, sizeof set, &set) != 0)
    return 0;
  return CPU_COUNT (&set);
}

static int
bcu_nproc_cmd (WORD_LIST *list)
{
  /* GNU nproc accepts --all and --ignore=N; --all reports every configured
   * processor, the default reports the ones this process may run on, and
   * --ignore=N subtracts from the count (floored at 1). */
  long ignore = 0;
  int use_all = 0;
  for (WORD_LIST *w = list; w; w = w->next)
    {
      const char *a = w->word->word;
      if (strcmp (a, "--all") == 0) { use_all = 1; continue; }
      if (strncmp (a, "--ignore=", 9) == 0)
        {
          ignore = strtol (a + 9, NULL, 10);
          if (ignore < 0) ignore = 0;
          continue;
        }
      builtin_error ("nproc: unknown flag: %s", a);
      bcu_usage ("nproc");
      return EX_USAGE;
    }
  long n = 0;
  if (!use_all)
    n = bcu_nproc_available ();
  if (n < 1)
    n = sysconf (use_all ? _SC_NPROCESSORS_CONF : _SC_NPROCESSORS_ONLN);
  if (n < 1) n = 1;
  n -= ignore;
  if (n < 1) n = 1;
  printf ("%ld\n", n);
  return EXECUTION_SUCCESS;
}

/* ===================================================================
 * numfmt — human-readable number conversion.
 *
 * Supports --to=iec|iec-i|si and --from=iec|iec-i|si.
 * =================================================================== */

typedef enum { BCU_SCALE_NONE, BCU_SCALE_IEC, BCU_SCALE_IEC_I, BCU_SCALE_SI } bcu_scale_t;

static bcu_scale_t
bcu_numfmt_scale (const char *s)
{
  if (!s) return BCU_SCALE_NONE;
  if (strcmp (s, "iec")   == 0) return BCU_SCALE_IEC;
  if (strcmp (s, "iec-i") == 0) return BCU_SCALE_IEC_I;
  if (strcmp (s, "si")    == 0) return BCU_SCALE_SI;
  return BCU_SCALE_NONE;
}

static double
bcu_numfmt_parse_human (const char *s, bcu_scale_t scale)
{
  char *end = NULL;
  double v = strtod (s, &end);
  if (!end || end == s) return 0.0;
  /* Skip optional space + suffix. */
  while (*end == ' ') end++;
  if (!*end) return v;
  double mult = 1.0;
  double base = (scale == BCU_SCALE_SI) ? 1000.0 : 1024.0;
  switch (toupper ((unsigned char) *end))
    {
    case 'K': mult = base; break;
    case 'M': mult = base * base; break;
    case 'G': mult = base * base * base; break;
    case 'T': mult = base * base * base * base; break;
    case 'P': mult = base * base * base * base * base; break;
    default: break;
    }
  return v * mult;
}

/* Rounding helpers ported from GNU numfmt's simple_round() family
 * (research/refs/coreutils/src/numfmt.c). numfmt's DEFAULT round mode is
 * round_from_zero (round away from zero), NOT truncation, so e.g.
 * `numfmt --to=si 1234567` => "1.3M" (1.234567 rounds UP to 1.3). */
static double
bcu_round_ceiling (double val)
{
  long long intval = (long long) val;
  if ((double) intval < val)
    intval++;
  return (double) intval;
}

static double
bcu_round_floor (double val)
{
  return -bcu_round_ceiling (-val);
}

/* round away from zero (the GNU numfmt default). */
static double
bcu_round_from_zero (double val)
{
  return val < 0 ? bcu_round_floor (val) : bcu_round_ceiling (val);
}

static void
bcu_numfmt_format (double v, bcu_scale_t scale, char *out, size_t outsz)
{
  /* SI kilo is lowercase 'k'; everything else uppercase (GNU numfmt). */
  const char *units    = (scale == BCU_SCALE_SI) ? "BkMGTPE" : "BKMGTPE";
  double base = (scale == BCU_SCALE_SI) ? 1000.0 : 1024.0;

  /* Normalize val to scale (GNU expld): scale down while |val| >= base. */
  int power = 0;
  double a = v < 0 ? -v : v;
  while (a >= base && units[power + 1])
    { a /= base; power++; }

  /* Perform rounding the way GNU double_to_human() does: for scaled
   * values below 10 we keep one decimal digit, so multiply by 10 before
   * rounding (away from zero) and divide back. Integers (power 0) and
   * values >= 10 round to whole units. */
  int power_adjust = (power > 0 && a < 10.0) ? 1 : 0;
  double scaled = a;
  for (int i = 0; i < power_adjust; i++) scaled *= 10.0;
  scaled = bcu_round_from_zero (scaled);
  for (int i = 0; i < power_adjust; i++) scaled /= 10.0;
  a = scaled;

  /* Special case after rounding: "9.9" can round to 10 at one decimal,
   * and "999" can round up to a full unit — scale down again (GNU). */
  if (a >= base && units[power + 1])
    { a /= base; power++; }

  /* show one decimal only when scaled, non-zero and < 10 (GNU rule). */
  int show_decimal = (a != 0.0) && (a < 10.0) && (power > 0);
  const char *suffix_i = (scale == BCU_SCALE_IEC_I && power > 0) ? "i" : "";

  if (power == 0)
    snprintf (out, outsz, "%.0f", v);
  else
    snprintf (out, outsz, "%s%.*f%c%s", v < 0 ? "-" : "",
              show_decimal ? 1 : 0, a, units[power], suffix_i);
}

static int
bcu_numfmt_cmd (WORD_LIST *list)
{
  bcu_scale_t from = BCU_SCALE_NONE;
  bcu_scale_t to   = BCU_SCALE_NONE;
  WORD_LIST *values __attribute__((cleanup(bcu_free_nodes))) = NULL;
  WORD_LIST *values_tail = NULL;

  for (WORD_LIST *w = list; w; w = w->next)
    {
      const char *a = w->word->word;
      if (strncmp (a, "--from=", 7) == 0) { from = bcu_numfmt_scale (a + 7); continue; }
      if (strncmp (a, "--to=",   5) == 0) { to   = bcu_numfmt_scale (a + 5); continue; }
      WORD_LIST *nw = bcu_calloc (1, sizeof (*nw));
      nw->word = w->word;
      if (!values) values = nw; else values_tail->next = nw;
      values_tail = nw;
    }

  int rc = EXECUTION_SUCCESS;
  if (!values)
    {
      char *line = NULL; size_t llen = 0; ssize_t r;
      while ((r = getline (&line, &llen, stdin)) != -1)
        {
          if (r > 0 && line[r - 1] == '\n') line[r - 1] = '\0';
          double v = bcu_numfmt_parse_human (line, from);
          char outbuf[64];
          if (to != BCU_SCALE_NONE) bcu_numfmt_format (v, to, outbuf, sizeof outbuf);
          else snprintf (outbuf, sizeof outbuf, "%.0f", v);
          puts (outbuf);
        }
      free (line);
    }
  else
    for (WORD_LIST *w = values; w; w = w->next)
      {
        double v = bcu_numfmt_parse_human (w->word->word, from);
        char outbuf[64];
        if (to != BCU_SCALE_NONE) bcu_numfmt_format (v, to, outbuf, sizeof outbuf);
        else snprintf (outbuf, sizeof outbuf, "%.0f", v);
        puts (outbuf);
      }


  return rc;
}

/* ===================================================================
 * shred — overwrite a file N times with random bytes, optionally
 *         unlink. Defaults: 3 passes, no zero-pass, no unlink.
 *
 * Flags:
 *   -n N    pass count (default 3)
 *   -z      add a final zero-fill pass
 *   -u      unlink after writing
 *   -s SZ   treat file as SZ bytes long (rare; default = current size)
 * =================================================================== */

static int
bcu_shred_one (const char *path, int passes, int zero_pass, int unlink_after, long long fixed_size)
{
  int fd = open (path, O_WRONLY);
  if (fd < 0) { builtin_error ("shred: %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
  off_t sz;
  if (fixed_size >= 0) sz = (off_t) fixed_size;
  else
    {
      struct stat st;
      if (fstat (fd, &st) < 0) { close (fd); builtin_error ("shred: fstat: %s", strerror (errno)); return EXECUTION_FAILURE; }
      sz = st.st_size;
    }
  unsigned char *buf = xmalloc (BUFSZ);
  if (!buf) { close (fd); return EXECUTION_FAILURE; }

  FILE *rnd = fopen ("/dev/urandom", "rb");
  for (int pass = 0; pass < passes + (zero_pass ? 1 : 0); pass++)
    {
      if (lseek (fd, 0, SEEK_SET) < 0) break;
      int is_zero_pass = (pass == passes); /* zero pass is appended */
      off_t remaining = sz;
      while (remaining > 0)
        {
          size_t chunk = (remaining < BUFSZ) ? (size_t) remaining : (size_t) BUFSZ;
          if (is_zero_pass)
            memset (buf, 0, chunk);
          else if (rnd)
            { if (fread (buf, 1, chunk, rnd) != chunk) memset (buf, 0xa5, chunk); }
          else
            memset (buf, 0xa5, chunk);
          ssize_t wn = write (fd, buf, chunk);
          if (wn < 0) { remaining = -1; break; }
          remaining -= wn;
        }
      fsync (fd);
    }
  if (rnd) fclose (rnd);
  free (buf);
  close (fd);
  if (unlink_after && unlink (path) < 0)
    { builtin_error ("shred: unlink %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
  return EXECUTION_SUCCESS;
}

static int
bcu_shred_cmd (WORD_LIST *list)
{
  int passes = 3, zero_pass = 0, unlink_after = 0;
  long long fixed_size = -1;
  WORD_LIST *files __attribute__((cleanup(bcu_free_nodes))) = NULL;
  WORD_LIST *files_tail = NULL;
  for (WORD_LIST *w = list; w; w = w->next)
    {
      const char *a = w->word->word;
      if (strcmp (a, "-n") == 0 && w->next)
        { w = w->next; long long v; if (!bcu_parse_ll (w->word->word, &v) || v < 0 || v >= INT_MAX) { builtin_error ("shred: bad -n"); bcu_usage ("shred"); return EX_USAGE; } passes = (int) v; continue; }
      if (strcmp (a, "-z") == 0) { zero_pass = 1; continue; }
      if (strcmp (a, "-u") == 0) { unlink_after = 1; continue; }
      if (strcmp (a, "-s") == 0 && w->next)
        { w = w->next; if (!bcu_parse_ll (w->word->word, &fixed_size) || fixed_size < 0) { builtin_error ("shred: bad -s"); bcu_usage ("shred"); return EX_USAGE; } continue; }
      if (a[0] == '-' && a[1] != '\0') { builtin_error ("shred: unknown flag: %s", a); bcu_usage ("shred"); return EX_USAGE; }
      WORD_LIST *nw = bcu_calloc (1, sizeof (*nw));
      nw->word = w->word;
      if (!files) files = nw; else files_tail->next = nw;
      files_tail = nw;
    }

  if (!files) { builtin_error ("shred: missing FILE"); bcu_usage ("shred"); return EX_USAGE; }

  int rc = EXECUTION_SUCCESS;
  for (WORD_LIST *w = files; w; w = w->next)
    if (bcu_shred_one (w->word->word, passes, zero_pass, unlink_after, fixed_size) != EXECUTION_SUCCESS)
      rc = EXECUTION_FAILURE;

  return rc;
}

/* ===================================================================
 * groups — print groups a user belongs to.
 * =================================================================== */

static int
bcu_groups_print (const char *user)
{
  struct passwd *pw = getpwnam (user);
  if (!pw) { builtin_error ("groups: no such user: %s", user); return EXECUTION_FAILURE; }
  int ngroups = 0;
  /* First call: ask glibc how many slots we need. */
  getgrouplist (pw->pw_name, pw->pw_gid, NULL, &ngroups);
  if (ngroups <= 0) ngroups = 16;
  gid_t *gids = xmalloc ((size_t) ngroups * sizeof (gid_t));
  if (!gids) { builtin_error ("groups: oom"); return EXECUTION_FAILURE; }
  if (getgrouplist (pw->pw_name, pw->pw_gid, gids, &ngroups) < 0)
    { free (gids); builtin_error ("groups: getgrouplist failed"); return EXECUTION_FAILURE; }
  for (int i = 0; i < ngroups; i++)
    {
      struct group *gr = getgrgid (gids[i]);
      if (i) putchar (' ');
      if (gr) fputs (gr->gr_name, stdout);
      else    printf ("%u", (unsigned) gids[i]);
    }
  putchar ('\n');
  free (gids);
  return EXECUTION_SUCCESS;
}

static int
bcu_groups_cmd (WORD_LIST *list)
{
  if (!list)
    {
      /* No operand: print the CURRENT PROCESS's groups via getgroups(),
         exactly like GNU `groups`. (Deriving them from getpwuid()+
         getgrouplist() recomputes from /etc/group and yields a different
         order — and aliases libc's static passwd buffer.) */
      int ng = getgroups (0, NULL);
      if (ng < 0) ng = 0;
      gid_t *gids = xmalloc ((size_t) (ng ? ng : 1) * sizeof (gid_t));
      if (!gids) { builtin_error ("groups: oom"); return EXECUTION_FAILURE; }
      ng = getgroups (ng, gids);
      if (ng < 0) { free (gids); builtin_error ("groups: getgroups failed"); return EXECUTION_FAILURE; }
      /* GNU prints the effective gid's group FIRST, then the remaining
         supplementary groups (in getgroups() order) skipping the egid. */
      gid_t egid = getegid ();
      struct group *eg = getgrgid (egid);
      if (eg) fputs (eg->gr_name, stdout);
      else    printf ("%u", (unsigned) egid);
      for (int i = 0; i < ng; i++)
        {
          if (gids[i] == egid) continue;
          putchar (' ');
          struct group *gr = getgrgid (gids[i]);
          if (gr) fputs (gr->gr_name, stdout);
          else    printf ("%u", (unsigned) gids[i]);
        }
      putchar ('\n');
      free (gids);
      return EXECUTION_SUCCESS;
    }
  int rc = EXECUTION_SUCCESS;
  for (WORD_LIST *w = list; w; w = w->next)
    {
      printf ("%s : ", w->word->word);
      if (bcu_groups_print (w->word->word) != EXECUTION_SUCCESS)
        rc = EXECUTION_FAILURE;
    }
  return rc;
}

/* ===================================================================
 * install — like `cp` with explicit -m mode and -d/-D for directories.
 *
 * Subset:
 *   install -m MODE SRC... DST          copy files, set MODE on each
 *   install -d [-m MODE] DIR...         mkdir -p style
 *   install -D [-m MODE] SRC DST        make parent dirs of DST first
 *
 * Owner/group flags (-o/-g) parse but only attempt the chown when
 * geteuid() == 0; non-root silently keeps the running uid/gid (this
 * matches GNU install behavior on non-root invocations).
 * =================================================================== */

static int
bcu_install_copyfile (const char *src, const char *dst, mode_t mode, uid_t uid, gid_t gid)
{
  int rfd = open (src, O_RDONLY);
  if (rfd < 0) { builtin_error ("install: %s: %s", src, strerror (errno)); return EXECUTION_FAILURE; }
  int wfd = open (dst, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (wfd < 0) { close (rfd); builtin_error ("install: %s: %s", dst, strerror (errno)); return EXECUTION_FAILURE; }
  char buf[BUFSZ];
  ssize_t n;
  while ((n = read (rfd, buf, sizeof buf)) > 0)
    {
      ssize_t off = 0;
      while (off < n)
        {
          ssize_t w = write (wfd, buf + off, (size_t) (n - off));
          if (w < 0) { close (rfd); close (wfd); builtin_error ("install: write: %s", strerror (errno)); return EXECUTION_FAILURE; }
          off += w;
        }
    }
  close (rfd);
  if (fchmod (wfd, mode) < 0)
    { close (wfd); builtin_error ("install: chmod %s: %s", dst, strerror (errno)); return EXECUTION_FAILURE; }
  if (geteuid () == 0 && (uid != (uid_t) -1 || gid != (gid_t) -1))
    {
      if (fchown (wfd, uid, gid) < 0)
        { close (wfd); builtin_error ("install: chown %s: %s", dst, strerror (errno)); return EXECUTION_FAILURE; }
    }
  close (wfd);
  return EXECUTION_SUCCESS;
}

static int
bcu_install_mkdir_p (const char *path, mode_t mode)
{
  char *tmp = bcu_strdup (path);
  if (!tmp) return EXECUTION_FAILURE;
  for (char *p = tmp + 1; *p; p++)
    if (*p == '/')
      {
        *p = '\0';
        if (mkdir (tmp, 0755) < 0 && errno != EEXIST)
          { builtin_error ("install: mkdir %s: %s", tmp, strerror (errno)); free (tmp); return EXECUTION_FAILURE; }
        *p = '/';
      }
  if (mkdir (tmp, mode) < 0 && errno != EEXIST)
    { builtin_error ("install: mkdir %s: %s", tmp, strerror (errno)); free (tmp); return EXECUTION_FAILURE; }
  /* Make sure the final component honors mode even if it already existed. */
  if (chmod (tmp, mode) < 0)
    { builtin_error ("install: chmod %s: %s", tmp, strerror (errno)); free (tmp); return EXECUTION_FAILURE; }
  free (tmp);
  return EXECUTION_SUCCESS;
}

static int
bcu_install_cmd (WORD_LIST *list)
{
  mode_t mode = 0755;
  int dir_only = 0, parents = 0;
  uid_t uid = (uid_t) -1;
  gid_t gid = (gid_t) -1;
  WORD_LIST *pos __attribute__((cleanup(bcu_free_nodes))) = NULL;
  WORD_LIST *pos_tail = NULL;

  for (WORD_LIST *w = list; w; w = w->next)
    {
      const char *a = w->word->word;
      if (strcmp (a, "-m") == 0 && w->next)
        {
          w = w->next;
          char *end = NULL;
          unsigned long m = strtoul (w->word->word, &end, 8);
          if (end == w->word->word || *end != '\0' || m > 07777)
            { builtin_error ("install: bad -m"); bcu_usage ("install"); return EX_USAGE; }
          mode = (mode_t) m;
          continue;
        }
      if (strcmp (a, "-d") == 0) { dir_only = 1; continue; }
      if (strcmp (a, "-D") == 0) { parents = 1; continue; }
      if (strcmp (a, "-o") == 0 && w->next)
        { w = w->next; struct passwd *pw = getpwnam (w->word->word); if (pw) uid = pw->pw_uid; continue; }
      if (strcmp (a, "-g") == 0 && w->next)
        { w = w->next; struct group *gr = getgrnam (w->word->word); if (gr) gid = gr->gr_gid; continue; }
      if (a[0] == '-' && a[1] != '\0') { builtin_error ("install: unknown flag: %s", a); bcu_usage ("install"); return EX_USAGE; }
      WORD_LIST *nw = bcu_calloc (1, sizeof (*nw));
      nw->word = w->word;
      if (!pos) pos = nw; else pos_tail->next = nw;
      pos_tail = nw;
    }

  int rc = EXECUTION_SUCCESS;
  if (dir_only)
    {
      if (!pos) { builtin_error ("install: -d requires DIR..."); bcu_usage ("install"); return EX_USAGE; }
      for (WORD_LIST *w = pos; w; w = w->next)
        if (bcu_install_mkdir_p (w->word->word, mode) != EXECUTION_SUCCESS)
          rc = EXECUTION_FAILURE;
      goto cleanup;
    }

  if (!pos || !pos->next) { builtin_error ("install: need SRC and DST"); bcu_usage ("install"); rc = EX_USAGE; goto cleanup; }

  /* Find tail = DST. Walk to last node. */
  WORD_LIST *dst_node = pos;
  while (dst_node->next) dst_node = dst_node->next;
  const char *dst = dst_node->word->word;
  /* If DST is an existing directory, copy each SRC into it. */
  struct stat dst_st;
  int dst_isdir = (stat (dst, &dst_st) == 0 && S_ISDIR (dst_st.st_mode));

  if (parents)
    {
      /* Create parent directory of DST. */
      char *tmp = bcu_strdup (dst);
      char *slash = strrchr (tmp, '/');
      if (slash && slash != tmp)
        { *slash = '\0'; bcu_install_mkdir_p (tmp, 0755); }
      free (tmp);
    }

  for (WORD_LIST *w = pos; w && w != dst_node; w = w->next)
    {
      const char *src = w->word->word;
      char target[4096];
      if (dst_isdir)
        {
          const char *base = strrchr (src, '/');
          base = base ? base + 1 : src;
          snprintf (target, sizeof target, "%s/%s", dst, base);
        }
      else
        snprintf (target, sizeof target, "%s", dst);
      if (bcu_install_copyfile (src, target, mode, uid, gid) != EXECUTION_SUCCESS)
        rc = EXECUTION_FAILURE;
    }

cleanup:

  return rc;
}

/* ===================================================================
 * mknod — create device or fifo.
 *
 *   mknod PATH p              named pipe (any uid; matches mkfifo)
 *   mknod PATH b MAJ MIN      block device (root only)
 *   mknod PATH c MAJ MIN      character device (root only)
 * =================================================================== */

static int
bcu_mknod_cmd (WORD_LIST *list)
{
  mode_t mode = 0644;
  WORD_LIST *pos __attribute__((cleanup(bcu_free_nodes))) = NULL;
  WORD_LIST *pos_tail = NULL;
  for (WORD_LIST *w = list; w; w = w->next)
    {
      const char *a = w->word->word;
      if (strcmp (a, "-m") == 0 && w->next)
        {
          w = w->next;
          char *end = NULL;
          unsigned long m = strtoul (w->word->word, &end, 8);
          if (end == w->word->word || *end != '\0' || m > 07777) { builtin_error ("mknod: bad -m"); bcu_usage ("mknod"); return EX_USAGE; }
          mode = (mode_t) m;
          continue;
        }
      if (a[0] == '-' && a[1] != '\0') { builtin_error ("mknod: unknown flag: %s", a); bcu_usage ("mknod"); return EX_USAGE; }
      WORD_LIST *nw = bcu_calloc (1, sizeof (*nw));
      nw->word = w->word;
      if (!pos) pos = nw; else pos_tail->next = nw;
      pos_tail = nw;
    }

  int npos = 0;
  for (WORD_LIST *w = pos; w; w = w->next) npos++;
  if (npos < 2) { builtin_error ("mknod: need PATH TYPE [MAJ MIN]"); bcu_usage ("mknod");  return EX_USAGE; }

  const char *path = pos->word->word;
  const char *type = pos->next->word->word;
  int rc = EXECUTION_SUCCESS;

  if (strcmp (type, "p") == 0)
    {
      if (mkfifo (path, mode) < 0)
        { builtin_error ("mknod: %s: %s", path, strerror (errno)); rc = EXECUTION_FAILURE; }
    }
  else if (strcmp (type, "b") == 0 || strcmp (type, "c") == 0)
    {
      if (npos < 4) { builtin_error ("mknod: %s requires MAJ MIN", type); bcu_usage ("mknod"); rc = EX_USAGE; goto mknod_out; }
      long long maj, min_;
      if (!bcu_parse_ll (pos->next->next->word->word, &maj)
          || !bcu_parse_ll (pos->next->next->next->word->word, &min_))
        { builtin_error ("mknod: bad MAJ/MIN"); bcu_usage ("mknod"); rc = EX_USAGE; goto mknod_out; }
      mode_t kind = (type[0] == 'b') ? S_IFBLK : S_IFCHR;
      if (mknod (path, mode | kind, makedev ((unsigned) maj, (unsigned) min_)) < 0)
        { builtin_error ("mknod: %s: %s", path, strerror (errno)); rc = EXECUTION_FAILURE; }
    }
  else
    { builtin_error ("mknod: unknown type: %s", type); bcu_usage ("mknod"); rc = EX_USAGE; }

mknod_out:

  return rc;
}

/* ===================================================================
 * Bash builtin dispatch.
 * =================================================================== */

int
coreutils_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *verb = list->word->word;
  WORD_LIST *args = list->next;
  if (strcmp (verb, "tac")     == 0) return bcu_tac_cmd     (args);
  if (strcmp (verb, "shuf")    == 0) return bcu_shuf_cmd    (args);
  if (strcmp (verb, "factor")  == 0) return bcu_factor_cmd  (args);
  if (strcmp (verb, "yes")     == 0) return bcu_yes_cmd     (args);
  if (strcmp (verb, "fmt")     == 0) return bcu_fmt_cmd     (args);
  if (strcmp (verb, "tsort")   == 0) return bcu_tsort_cmd   (args);
  if (strcmp (verb, "nproc")   == 0) return bcu_nproc_cmd   (args);
  if (strcmp (verb, "numfmt")  == 0) return bcu_numfmt_cmd  (args);
  if (strcmp (verb, "shred")   == 0) return bcu_shred_cmd   (args);
  if (strcmp (verb, "groups")  == 0) return bcu_groups_cmd  (args);
  if (strcmp (verb, "install") == 0) return bcu_install_cmd (args);
  if (strcmp (verb, "mknod")   == 0) return bcu_mknod_cmd   (args);
  builtin_error ("coreutils: unknown verb: %s", verb);
  builtin_error ("usage: coreutils {tac|shuf|factor|yes|fmt|tsort|nproc|numfmt|shred|groups|install|mknod} ARGS");
  return EX_USAGE;
}

char *coreutils_doc[] = {
  "Bundle of 12 small POSIX coreutils as a single bash loadable.",
  "",
  "    coreutils tac    [FILE...]",
  "    coreutils shuf   [-i LO-HI|-e|-n COUNT|--random-source=F] [FILE]",
  "    coreutils factor N [N...]",
  "    coreutils yes    [STRING...]",
  "    coreutils fmt    [-w WIDTH] [FILE...]",
  "    coreutils tsort  [FILE]",
  "    coreutils nproc  [--all] [--ignore=N]",
  "    coreutils numfmt [--to=iec|iec-i|si] [--from=iec|iec-i|si] N",
  "    coreutils shred  [-n N] [-z] [-u] [-s SIZE] FILE...",
  "    coreutils groups [USER...]",
  "    coreutils install [-m MODE] [-o OWNER] [-g GROUP] [-d|-D] SRC... DST",
  "    coreutils mknod  [-m MODE] PATH {b|c|p} [MAJ MIN]",
  "",
  "POSIX cmd-name wrappers in /bash-os/<verb>.sh exec the verb directly.",
  (char *)NULL
};

struct builtin coreutils_struct = {
  "coreutils",
  coreutils_builtin,
  BUILTIN_ENABLED,
  coreutils_doc,
  "coreutils VERB [ARGS...]",
  0
};
