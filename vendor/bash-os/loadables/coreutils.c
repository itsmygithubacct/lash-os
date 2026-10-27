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
#if defined (__linux__)
#  include <sys/syscall.h>
#endif

#include "loadables.h"
#include "error.h"
#include "bl-output.h"
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
    builtin_error ("usage: coreutils shred [-n N] [-z] [-u] [-x] [-s SIZE] FILE...");
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

/* Coalesce small records while retaining stdio ordering with other Bash
   builtins. A large record goes directly to stdout without another copy. */
typedef struct {
  char bytes[65536];
  size_t used;
  int failed;
} BCU_OUTPUT;

static void
bcu_output_flush (BCU_OUTPUT *out)
{
  if (!out->failed && out->used &&
      fwrite (out->bytes, 1, out->used, stdout) != out->used)
    out->failed = 1;
  out->used = 0;
}

static void
bcu_output_append (BCU_OUTPUT *out, const char *bytes, size_t len)
{
  if (out->failed || !len) return;
  if (len > sizeof out->bytes - out->used) bcu_output_flush (out);
  if (out->failed) return;
  if (len >= sizeof out->bytes)
    {
      if (fwrite (bytes, 1, len, stdout) != len) out->failed = 1;
    }
  else
    {
      memcpy (out->bytes + out->used, bytes, len);
      out->used += len;
    }
}

/* Read the descriptor rather than Bash's persistent stdin FILE: its EOF
   indicator and read-ahead buffer can survive shell redirections. */
static ssize_t
bcu_tac_slurp (int fd, char **out)
{
  size_t cap = 65536, len = 0;
  char *buf = xmalloc (cap);
  for (;;)
    {
      if (len == cap)
        {
          if (cap > (size_t) SSIZE_MAX / 2)
            { free (buf); errno = EOVERFLOW; return -1; }
          cap *= 2;
          buf = xrealloc (buf, cap);
        }
      ssize_t n = read (fd, buf + len, cap - len);
      if (n < 0 && errno == EINTR) continue;
      if (n < 0) { int e = errno; free (buf); errno = e; return -1; }
      if (!n) break;
      len += (size_t) n;
    }
  *out = buf;
  return (ssize_t) len;
}

static int
bcu_tac_stream (FILE *fp, const char *sep, bl_output *out)
{
  char *buf = NULL;
  ssize_t len = bcu_tac_slurp (fileno (fp), &buf);
  if (len < 0)
    { builtin_error ("tac: read: %s", strerror (errno)); return EXECUTION_FAILURE; }
  /* GNU selects NUL for an empty separator. Search from the right so
     overlapping literal separators consume the rightmost match first.
     Emit each record immediately, avoiding a per-record offset array. */
  size_t seplen = strlen (sep);
  if (!seplen) seplen = 1;
  size_t search_end = (size_t) len, record_end = (size_t) len;
  while (search_end >= seplen && !out->error)
    {
      size_t limit = search_end - seplen + 1;
      const char *found = NULL;
      while (limit)
        {
          found = memrchr (buf, (unsigned char) sep[0], limit);
          if (!found || seplen == 1 || memcmp (found, sep, seplen) == 0) break;
          limit = (size_t) (found - buf);
          found = NULL;
        }
      if (!found) break;
      size_t start = (size_t) (found - buf), boundary = start + seplen;
      bl_output_write (out, buf + boundary, record_end - boundary);
      record_end = boundary;
      search_end = start;
    }
  if (record_end) bl_output_write (out, buf, record_end);
  free (buf);
  return out->error ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
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
      builtin_error ("tac: unknown option: %s", w);
      return EX_USAGE;
    }
  bl_output out;
  bl_output_init (&out, stdout);
  int rc = EXECUTION_SUCCESS;
  if (!list)
    rc = bcu_tac_stream (stdin, sep, &out);
  for (WORD_LIST *w = list; w && !out.error; w = w->next)
    {
      FILE *fp = bcu_open_input (w->word->word);
      if (!fp) { rc = EXECUTION_FAILURE; continue; }
      if (bcu_tac_stream (fp, sep, &out) != EXECUTION_SUCCESS)
        rc = EXECUTION_FAILURE;
      if (fp != stdin) fclose (fp);
    }
  bl_output_flush (&out);
  if (out.error)
    { builtin_error ("tac: write: %s", strerror (out.error)); rc = EXECUTION_FAILURE; }
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

static int
bcu_shuf_seed (const char *source)
{
  uint64_t s = 0;
  if (source)
    {
      FILE *fp = fopen (source, "rb");
      if (!fp)
        { builtin_error ("shuf: %s: %s", source, strerror (errno)); return 0; }
      unsigned char b[8] = {0};
      size_t count = fread (b, 1, sizeof b, fp);
      int failed = ferror (fp);
      fclose (fp);
      if (failed)
        { builtin_error ("shuf: %s: read error", source); return 0; }
      for (size_t i = 0; i < count; i++) s = (s << 8) | b[i];
      bcu_shuf_state = s ? s : 0x9E3779B97F4A7C15ULL;
      return 1;
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
  return 1;
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

  if (!bcu_shuf_seed (source)) return EXECUTION_FAILURE;

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
  int length;              /* length of this word. */
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
bcu_fmt_check_punctuation (BCU_WORD *w, const char *start)
{
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

          len += 1 + w->length;  /* Parsing collapses every gap to one space. */
        }
      while (len <= ctx->max_width);
      start->best_cost = best + bcu_fmt_base_cost (ctx, start);
    }

  ctx->word_limit->length = saved_length;
}

/* Emit one paragraph's words with GNU-optimal line breaks. Re-emits the
 * paragraph prefix at the start of each output line. */
static void
bcu_fmt_emit_para (char *text, BCU_WORD *word, size_t n,
                   const char *prefix, int width, BCU_OUTPUT *out)
{
  if (!n) return;
  size_t prefixlen = prefix ? strlen (prefix) : 0;

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

  /* Word text and its single-space gaps are contiguous. The optimizer's
     line length already gives the span to emit, excluding the prefix. */
  char *line_text = text;
  for (BCU_WORD *line = word; line != ctx.word_limit; line = line->next_break)
    {
      if (prefix) bcu_output_append (out, prefix, prefixlen);
      size_t len = (size_t) line->line_length - prefixlen;
      line_text[len] = '\n';
      bcu_output_append (out, line_text, len + 1);
      line_text += len + 1;
    }
}

static int
bcu_fmt_stream (FILE *fp, int width)
{
  char *line = NULL; size_t llen = 0; ssize_t r;
  BCU_WORD *word = NULL; size_t n = 0, cap = 0;
  char *text = NULL; size_t textlen = 0, textcap = 0;
  char *prefix = NULL;
  BCU_OUTPUT out;
  out.used = 0; out.failed = 0;

  while ((r = getline (&line, &llen, fp)) != -1)
    {
      if (r > 0 && line[r - 1] == '\n') { line[r - 1] = '\0'; r--; }
      int blank = 1;
      for (ssize_t i = 0; i < r; i++)
        if (!isspace ((unsigned char) line[i])) { blank = 0; break; }
      if (blank)
        {
          bcu_fmt_emit_para (text, word, n, prefix, width, &out);
          if (n) bcu_output_append (&out, "\n", 1);
          n = 0; textlen = 0;
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
          if (n == cap) {
            if (cap > (SIZE_MAX / sizeof *word - 1) / 2) {
              fatal_error ("coreutils fmt: allocation too large"); abort ();
            }
            cap = cap ? cap * 2 : 64;
            word = xrealloc (word, (cap + 1) * sizeof *word);
          }
          if (wlen == SIZE_MAX || textlen > SIZE_MAX - wlen - 1) {
            fatal_error ("coreutils fmt: allocation too large"); abort ();
          }
          size_t need = textlen + wlen + 1;
          if (need > textcap) {
            size_t grow = textcap ? textcap : 4096;
            while (grow < need) {
              if (grow > SIZE_MAX / 2) { grow = need; break; }
              grow *= 2;
            }
            text = xrealloc (text, grow);
            textcap = grow;
          }
          word[n].length = (int) wlen;
          word[n].final = 0;
          bcu_fmt_check_punctuation (&word[n], start);
          n++;
          /* The final slot remains available for the optimizer's sentinel. */
          word[n].length = 0;
          memcpy (text + textlen, start, wlen);
          text[textlen + wlen] = ' ';
          textlen = need;
        }
    }
  bcu_fmt_emit_para (text, word, n, prefix, width, &out);
  bcu_output_flush (&out);
  free (word); free (text); free (prefix); free (line);
  return (out.failed || ferror (fp)) ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
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

/* Count the current affinity mask; zero requests a sysconf fallback. */
static unsigned long
bcu_nproc_available (void)
{
  cpu_set_t set;
  if (sched_getaffinity (0, sizeof set, &set) != 0) return 0;
  return CPU_COUNT (&set);
}

/* OpenMP permits surrounding whitespace and lists of nesting levels.
   Only the first level affects nproc. Invalid/zero values are ignored;
   strtoul saturation matches GNU for values larger than ULONG_MAX. */
static unsigned long
bcu_nproc_omp (const char *value)
{
  if (!value) return 0;
  while (isspace ((unsigned char) *value)) value++;
  if (*value < '0' || *value > '9') return 0;
  char *end;
  unsigned long n = strtoul (value, &end, 10);
  while (isspace ((unsigned char) *end)) end++;
  return !*end || *end == ',' ? n : 0;
}

static int
bcu_nproc_cmd (WORD_LIST *list)
{
  unsigned long ignore = 0;
  int use_all = 0;
  for (WORD_LIST *w = list; w; w = w->next)
    {
      const char *a = w->word->word, *value = NULL;
      if (!strcmp (a, "--all")) { use_all = 1; continue; }
      if (!strcmp (a, "--") && !w->next) break;
      if (!strncmp (a, "--ignore=", 9)) value = a + 9;
      else if (!strcmp (a, "--ignore") && w->next)
        { w = w->next; value = w->word->word; }
      if (value)
        {
          while (isspace ((unsigned char) *value)) value++;
          char *end;
          errno = 0;
          ignore = strtoul (value, &end, 10);
          if (*value && *value != '-' && end != value && !*end)
            continue;
          builtin_error ("nproc: invalid number: %s", value);
          return EXECUTION_FAILURE;
        }
      builtin_error ("nproc: unknown flag: %s", a);
      bcu_usage ("nproc");
      return EX_USAGE;
    }
  unsigned long n = 0, limit = ULONG_MAX;
  if (!use_all)
    {
      n = bcu_nproc_omp (getenv ("OMP_NUM_THREADS"));
      unsigned long v = bcu_nproc_omp (getenv ("OMP_THREAD_LIMIT"));
      if (v) limit = v;
      if (!n) n = bcu_nproc_available ();
    }
  if (!n)
    {
      long configured = sysconf (use_all ? _SC_NPROCESSORS_CONF : _SC_NPROCESSORS_ONLN);
      n = configured > 0 ? (unsigned long) configured : 1;
    }
  if (n > limit) n = limit;
  n = ignore < n ? n - ignore : 1;
  printf ("%lu\n", n);
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
 *   -x      exact size (also the default; no block-size rounding)
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

  int error = 0;
  FILE *rnd = passes ? fopen ("/dev/urandom", "rb") : NULL;
  if (passes && !rnd) error = errno;
  for (int pass = 0; !error && pass < passes + (zero_pass ? 1 : 0); pass++)
    {
      if (lseek (fd, 0, SEEK_SET) < 0) { error = errno; break; }
      int is_zero_pass = (pass == passes);
      off_t remaining = sz;
      while (remaining > 0 && !error)
        {
          size_t chunk = remaining < BUFSZ ? (size_t) remaining : (size_t) BUFSZ;
          if (is_zero_pass) memset (buf, 0, chunk);
          else if (fread (buf, 1, chunk, rnd) != chunk)
            { error = errno ? errno : EIO; break; }
          size_t written = 0;
          while (written < chunk)
            {
              ssize_t n = write (fd, buf + written, chunk - written);
              if (n < 0 && errno == EINTR) continue;
              if (n <= 0) { error = n < 0 ? errno : EIO; break; }
              written += (size_t) n;
            }
          remaining -= (off_t) written;
        }
      if (!error && fsync (fd) < 0) error = errno;
    }
  if (rnd) fclose (rnd);
  free (buf);
  if (close (fd) < 0 && !error) error = errno;
  /* Never unlink a file after an unsuccessful overwrite. */
  if (error)
    { builtin_error ("shred: %s: %s", path, strerror (error)); return EXECUTION_FAILURE; }
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
      /* This implementation always writes the exact requested/current size. */
      if (strcmp (a, "-x") == 0 || strcmp (a, "--exact") == 0) continue;
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
 * Owner/group flags (-o/-g) accept names or numeric IDs. Validate them
 * before modifying destinations, and report any ownership-change failure.
 * =================================================================== */

/* Whether two paths name one directory entry: the same last component in
   the same parent directory, however either path is spelled. An answer that
   cannot be established counts as the same entry, so the caller refuses
   instead of removing the source's only name. */
static int
bcu_install_same_entry (const char *a, const char *b)
{
  const char *paths[2] = { a, b };
  char parents[2][PATH_MAX];
  struct stat dirs[2];
  const char *sa = strrchr (a, '/'), *sb = strrchr (b, '/');
  if (strcmp (sa ? sa + 1 : a, sb ? sb + 1 : b))
    return 0;
  for (int i = 0; i < 2; i++)
    {
      const char *slash = strrchr (paths[i], '/');
      size_t len = slash ? (size_t) (slash - paths[i]) : 0;
      if (len >= PATH_MAX)
        return 1;
      if (!slash)
        strcpy (parents[i], ".");
      else if (len == 0)
        strcpy (parents[i], "/");
      else
        {
          memcpy (parents[i], paths[i], len);
          parents[i][len] = '\0';
        }
      if (stat (parents[i], &dirs[i]) < 0)
        return 1;
    }
  return dirs[0].st_dev == dirs[1].st_dev && dirs[0].st_ino == dirs[1].st_ino;
}

/* Handle a destination that already names the source's inode as GNU install
   does. The same directory entry, or a source that reaches the destination
   through a symbolic link, is refused. Another hard link or a symbolic link
   to the source is removed, so a fresh file takes its name and the source
   keeps its data. Returns -1 after reporting a refusal or failure. */
static int
bcu_install_same_file (const char *src, const char *dst, const struct stat *src_st)
{
  struct stat st;
  if (stat (dst, &st) < 0 || st.st_dev != src_st->st_dev || st.st_ino != src_st->st_ino)
    return 0;
  int replace;
  if (lstat (dst, &st) == 0 && S_ISLNK (st.st_mode))
    replace = 1;
  else
    replace = !(lstat (src, &st) == 0 && S_ISLNK (st.st_mode)) &&
              !bcu_install_same_entry (src, dst);
  if (!replace)
    {
      builtin_error ("install: '%s' and '%s' are the same file", src, dst);
      return -1;
    }
  if (unlink (dst) < 0)
    {
      builtin_error ("install: cannot remove %s: %s", dst, strerror (errno));
      return -1;
    }
  return 0;
}

static int
bcu_install_copyfile (const char *src, const char *dst, mode_t mode, uid_t uid, gid_t gid)
{
  int rfd = open (src, O_RDONLY);
  if (rfd < 0) { builtin_error ("install: %s: %s", src, strerror (errno)); return EXECUTION_FAILURE; }
  struct stat src_st, dst_st;
  if (fstat (rfd, &src_st) < 0)
    { int e = errno; close (rfd); builtin_error ("install: stat %s: %s", src, strerror (e)); return EXECUTION_FAILURE; }
  if (S_ISDIR (src_st.st_mode))
    { close (rfd); builtin_error ("install: %s is a directory", src); return EXECUTION_FAILURE; }
  if (bcu_install_same_file (src, dst, &src_st) < 0)
    { close (rfd); return EXECUTION_FAILURE; }
  /* GNU install replaces the directory entry. Other hard links keep their
     contents, and a destination symlink is replaced rather than followed.
     Open the source and reject same-file operands before removing anything. */
  if (unlink (dst) < 0 && errno != ENOENT)
    { int e = errno; close (rfd); builtin_error ("install: cannot remove %s: %s", dst, strerror (e)); return EXECUTION_FAILURE; }
  int wfd = open (dst, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (wfd < 0)
    { int e = errno; close (rfd); builtin_error ("install: %s: %s", dst, strerror (e)); return EXECUTION_FAILURE; }
  if (fstat (wfd, &dst_st) < 0)
    { int e = errno; close (rfd); close (wfd); builtin_error ("install: stat %s: %s", dst, strerror (e)); return EXECUTION_FAILURE; }
  if (dst_st.st_dev == src_st.st_dev && dst_st.st_ino == src_st.st_ino)
    {
      close (rfd); close (wfd);
      builtin_error ("install: '%s' and '%s' are the same file", src, dst);
      return EXECUTION_FAILURE;
    }
  int write_error = 0, read_error = 0;
#if defined (__linux__) && defined (SYS_copy_file_range)
  /* Unsupported filesystems (or a short kernel copy) continue through
     read/write at the descriptors' current offsets. */
  if (S_ISREG (src_st.st_mode) && S_ISREG (dst_st.st_mode))
    while (syscall (SYS_copy_file_range, rfd, NULL, wfd, NULL,
                    (size_t) 1024 * 1024 * 1024, 0) > 0)
      ;
  /* Always finish with read, including after a zero return: some virtual
     regular files report zero size yet still yield data when read. */
#endif
  /* Amortize read/write calls for streams and portable fallback copies.
     Short reads still emit at once. */
  char buf[128 * 1024];
  ssize_t n;
  while (1)
    {
      n = read (rfd, buf, sizeof buf);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) { if (n < 0) read_error = errno; break; }
      ssize_t off = 0;
      while (off < n)
        {
          ssize_t w = write (wfd, buf + off, (size_t) (n - off));
          if (w < 0 && errno == EINTR) continue;
          if (w <= 0) { write_error = w < 0 ? errno : EIO; goto copy_done; }
          off += w;
        }
    }
copy_done:
  close (rfd);
  if (read_error)
    {
      close (wfd);
      builtin_error ("install: read %s: %s", src, strerror (read_error));
      return EXECUTION_FAILURE;
    }
  if (write_error)
    {
      close (wfd);
      builtin_error ("install: write: %s", strerror (write_error));
      return EXECUTION_FAILURE;
    }
  if (uid != (uid_t) -1 || gid != (gid_t) -1)
    {
      if (fchown (wfd, uid, gid) < 0)
        { close (wfd); builtin_error ("install: chown %s: %s", dst, strerror (errno)); return EXECUTION_FAILURE; }
    }
  /* Ownership changes may clear set-ID bits. Apply the requested mode last. */
  if (fchmod (wfd, mode) < 0)
    { close (wfd); builtin_error ("install: chmod %s: %s", dst, strerror (errno)); return EXECUTION_FAILURE; }
  close (wfd);
  return EXECUTION_SUCCESS;
}

static int
bcu_install_mkdir_unmasked (const char *path, mode_t mode)
{
  /* mkdir itself preserves inherited setgid/default directory metadata.
     Creating with the final permissions avoids a chmod that clears setgid. */
  mode_t mask = umask (0);
  int rc = mkdir (path, mode);
  int error = errno;
  umask (mask);
  errno = error;
  return rc;
}

static int
bcu_install_mkdir_p (const char *path, mode_t mode, uid_t uid, gid_t gid,
                     int adjust_existing)
{
  char *tmp = bcu_strdup (path);
  if (!tmp) return EXECUTION_FAILURE;
  for (char *p = tmp + 1; *p; p++)
    if (*p == '/')
      {
        *p = '\0';
        if (bcu_install_mkdir_unmasked (tmp, 0755) < 0 && errno != EEXIST)
          { builtin_error ("install: mkdir %s: %s", tmp, strerror (errno)); free (tmp); return EXECUTION_FAILURE; }
        *p = '/';
      }
  int made = adjust_existing ? mkdir (tmp, mode) : bcu_install_mkdir_unmasked (tmp, mode);
  if (made < 0)
    {
      if (errno != EEXIST)
        { builtin_error ("install: mkdir %s: %s", tmp, strerror (errno)); free (tmp); return EXECUTION_FAILURE; }
      struct stat st;
      if (stat (tmp, &st) < 0 || !S_ISDIR (st.st_mode))
        { builtin_error ("install: %s is not a directory", tmp); free (tmp); return EXECUTION_FAILURE; }
    }
  /* -D only creates missing parents; -d explicitly sets their mode. */
  if (!adjust_existing) { free (tmp); return EXECUTION_SUCCESS; }
  if ((uid != (uid_t) -1 || gid != (gid_t) -1) && chown (tmp, uid, gid) < 0)
    { builtin_error ("install: chown %s: %s", tmp, strerror (errno)); free (tmp); return EXECUTION_FAILURE; }
  /* Make sure the final component honors mode even if it already existed. */
  if (chmod (tmp, mode) < 0)
    { builtin_error ("install: chmod %s: %s", tmp, strerror (errno)); free (tmp); return EXECUTION_FAILURE; }
  free (tmp);
  return EXECUTION_SUCCESS;
}

static int
bcu_install_id (const char *name, int group, uintmax_t *id)
{
#if defined (BASHOS_STATIC) && defined (__GLIBC__)
  /* Static glibc cannot safely load arbitrary host NSS modules. Restrict
     named install identities to the local account files in this build. */
  FILE *accounts = fopen (group ? "/etc/group" : "/etc/passwd", "r");
  if (accounts)
    {
      int found = 0;
      if (group)
        {
          struct group *gr;
          while ((gr = fgetgrent (accounts)) != NULL)
            if (!strcmp (gr->gr_name, name)) { *id = gr->gr_gid; found = 1; break; }
        }
      else
        {
          struct passwd *pw;
          while ((pw = fgetpwent (accounts)) != NULL)
            if (!strcmp (pw->pw_name, name)) { *id = pw->pw_uid; found = 1; break; }
        }
      fclose (accounts);
      if (found) return 0;
    }
#else
  if (group)
    {
      struct group *gr = getgrnam (name);
      if (gr) { *id = gr->gr_gid; return 0; }
    }
  else
    {
      struct passwd *pw = getpwnam (name);
      if (pw) { *id = pw->pw_uid; return 0; }
    }
#endif
  const char *number = name;
  while (isspace ((unsigned char) *number)) number++;
  char *end;
  errno = 0;
  uintmax_t value = strtoumax (number, &end, 10);
  if (*number == '-' || end == number || *end || errno == ERANGE ||
      (group ? (uintmax_t) (gid_t) value : (uintmax_t) (uid_t) value) != value)
    {
      builtin_error ("install: invalid %s '%s'", group ? "group" : "user", name);
      return -1;
    }
  *id = value;
  return 0;
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
      if ((strcmp (a, "-o") == 0 || strcmp (a, "-g") == 0) && w->next)
        {
          int group = a[1] == 'g';
          uintmax_t id;
          w = w->next;
          if (bcu_install_id (w->word->word, group, &id) < 0) return EXECUTION_FAILURE;
          if (group) gid = (gid_t) id;
          else uid = (uid_t) id;
          continue;
        }
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
        if (bcu_install_mkdir_p (w->word->word, mode, uid, gid, 1) != EXECUTION_SUCCESS)
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
        {
          *slash = '\0';
          if (bcu_install_mkdir_p (tmp, 0755, (uid_t) -1, (gid_t) -1, 0) != EXECUTION_SUCCESS)
            { free (tmp); return EXECUTION_FAILURE; }
        }
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
  mode_t mode = 0666;
  int explicit_mode = 0;
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
          explicit_mode = 1;
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
      /* An explicit FIFO mode is independent of the caller's umask. Apply
         it at creation, without chmod on a pathname that may already exist. */
      mode_t saved_mask = explicit_mode ? umask (0) : 0;
      int result = mkfifo (path, mode);
      int saved_errno = errno;
      if (explicit_mode) umask (saved_mask);
      errno = saved_errno;
      if (result < 0)
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

static int
bcu_dispatch (WORD_LIST *list)
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

int
coreutils_builtin (WORD_LIST *list)
{
  int rc = bcu_dispatch (list);
  if (fflush (stdout) == EOF || ferror (stdout))
    {
      builtin_error ("write: %s", strerror (errno ? errno : EIO));
      clearerr (stdout);
      rc = EXECUTION_FAILURE;
    }
  return rc;
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
  "    coreutils shred  [-n N] [-z] [-u] [-x] [-s SIZE] FILE...",
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
