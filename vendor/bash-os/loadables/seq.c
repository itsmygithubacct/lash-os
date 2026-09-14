/* SPDX-License-Identifier: MIT */
/* seq.c — seq(1) as a bash builtin, with the GNU coreutils surface.
 *
 * Written for bash-os from the documented interface and the observable
 * behaviour of coreutils seq(1); tests/seq-parity.sh holds it to the same
 * bytes and the same exit status as coreutils 9.7. It is not derived from
 * GNU bash's own seq loadable (GPL) nor from coreutils' source.
 *
 *   seq [-w] [-s STRING] [-f FORMAT] [FIRST [INCREMENT]] LAST
 *
 * The point of carrying it here is speed: `for i in $(seq N)` is everywhere
 * in scripts, and the loadable this replaces formatted every line through
 * printf, which made it 25 times slower than the GNU binary. Integers never
 * meet printf here: the number is a decimal string added to in place (a
 * 64-bit counter instead when a sign or -w is involved), appended into a
 * 64 KB block, one write per block. Counting on the digits is also what
 * keeps `seq 99999999999999999999 100000000000000000001` exact, as
 * coreutils is, past what a long double holds. Floats follow coreutils'
 * rules: the printed precision is the most decimals FIRST or INCREMENT has
 * (an exponent moves the point), -w pads to the widest operand, and the
 * value one step past LAST is printed as well when it prints as LAST and
 * the line before it did not.
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
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include "loadables.h"

#define SEQ_BLOCK 65536         /* output is written in blocks of this size */
#define SEQ_PREC_MAX (1 << 20)  /* decimals asked for by an exponent, capped */
#define SEQ_INT_MAX (1LL << 62) /* the 64-bit counter stays exact below this */

/* An operand: its value, and what its spelling says about the output.
   prec is the decimals to print (INT_MAX: a hex float, printed with %Lg);
   width is the characters it occupies as printed, for -w. */
struct seq_num { long double v; int prec; int width; };

/* ---- output: one buffer, one write per block --------------------------- */
struct seq_out { char *buf; size_t len, cap; };
static char seq_block[SEQ_BLOCK];

static int
seq_flush (struct seq_out *o)
{
  size_t n = o->len;
  o->len = 0;
  if (n && fwrite (o->buf, 1, n, stdout) != n) return -1;
  return (interrupt_state || terminating_signal) ? -1 : 0;
}

static int
seq_put (struct seq_out *o, const char *s, size_t n)
{
  if (n > o->cap - o->len)
    {
      if (seq_flush (o) < 0) return -1;
      if (n > o->cap) return fwrite (s, 1, n, stdout) == n ? 0 : -1;
    }
  memcpy (o->buf + o->len, s, n);
  o->len += n;
  return 0;
}

/* ---- operands ---------------------------------------------------------- */

/* strtold in the C locale whatever LC_NUMERIC says, as coreutils parses:
   "0.5" is a half everywhere and "0,5" is an error everywhere. */
static long double
seq_strtold (const char *s, char **end)
{
  static locale_t c_locale;
  locale_t old; long double v;
  if (c_locale == (locale_t) 0) c_locale = newlocale (LC_ALL_MASK, "C", (locale_t) 0);
  if (c_locale == (locale_t) 0) return strtold (s, end);
  old = uselocale (c_locale);
  v = strtold (s, end);
  uselocale (old);
  return v;
}

static int
seq_scan (const char *arg, struct seq_num *n)
{
  const char *s, *dot, *e; char *end; size_t len, frac = 0; long ex;

  errno = 0;
  n->v = seq_strtold (arg, &end);
  if (end == arg || *end || (errno == ERANGE && !isfinite (n->v)))
    { builtin_error ("invalid floating point argument: '%s'", arg); return -1; }
  if (isnan (n->v))
    { builtin_error ("invalid 'not-a-number' argument: '%s'", arg); return -1; }

  for (s = arg; isspace ((unsigned char) *s) || *s == '+'; s++) ;  /* neither is printed */
  n->width = 0;
  n->prec = INT_MAX;
  dot = strchr (s, '.');
  if (dot == 0 && strchr (s, 'p') == 0) n->prec = 0;   /* an integer, or 1e3 */
  if (strpbrk (s, "xX") || !isfinite (n->v)) return 0;  /* hex and inf: no width; a hex float prints with %Lg */

  len = strlen (s);
  n->width = len > INT_MAX ? INT_MAX : (int) len;
  if (dot)
    {
      frac = strcspn (dot + 1, "eE");
      if (frac <= INT_MAX) n->prec = (int) frac;
      if (frac == 0) n->width--;                                             /* "2." prints as "2" */
      else if (dot == s || !isdigit ((unsigned char) dot[-1])) n->width++;   /* ".5" as "0.5", "-.5" as "-0.5" */
    }
  e = strchr (s, 'e');
  if (e == 0) e = strchr (s, 'E');
  if (e)
    {
      /* The exponent moves the point: 1e-3 has three decimals, 1.5e1 none;
         "e…" itself is not printed, the digits it shifts in are. */
      ex = strtol (e + 1, (char **) 0, 10);
      if (ex < -LONG_MAX) ex = -LONG_MAX;
      if (ex < 0)
        n->prec = -ex > SEQ_PREC_MAX - n->prec ? SEQ_PREC_MAX : n->prec + (int) -ex;
      else
        n->prec -= n->prec < ex ? n->prec : (int) ex;
      n->width -= (int) (len - (size_t) (e - s));
      if (ex < 0)
        {
          if (dot == 0 || e == dot + 1) n->width++;   /* a "0." appears in front */
          ex = -ex;
        }
      else
        {
          if (dot && n->prec == 0 && frac) n->width--;  /* the point disappears */
          ex -= (long) frac < ex ? (long) frac : ex;
        }
      n->width = ex > INT_MAX - n->width ? INT_MAX : n->width + (int) ex;
    }
  return 0;
}

static int
seq_is_digits (const char *s)
{
  if (*s == 0) return 0;
  for (; *s; s++) if (!isdigit ((unsigned char) *s)) return 0;
  return 1;
}

static int
seq_is_int (const char *s)   /* [+-]digits: what the 64-bit counter takes */
{
  return seq_is_digits (s + (*s == '-' || *s == '+'));
}

/* ---- -f FORMAT --------------------------------------------------------- */

/* FORMAT must hold one %e %f %g %a conversion (a flag, width, precision and
   an L allowed) among literal text and %% pairs. Returns a copy with the L
   in place for a long double; *PRE and *SUF get the characters of output
   before and after the number. */
static char *
seq_format (const char *fmt, size_t *pre, size_t *suf)
{
  const char *p = fmt, *conv; char *out; size_t at; int has_l;

  *pre = *suf = 0;
  for (;;)
    {
      if (*p == '%' && p[1] == '%') { p += 2; (*pre)++; }
      else if (*p == '%') break;
      else if (*p == 0) { builtin_error ("format '%s' has no %% directive", fmt); return 0; }
      else { p++; (*pre)++; }
    }
  p++;
  p += strspn (p, "-+ #0'");
  p += strspn (p, "0123456789");
  if (*p == '.') { p++; p += strspn (p, "0123456789"); }
  conv = p;
  has_l = (*p == 'L');
  p += has_l;
  if (*p == 0) { builtin_error ("format '%s' ends in %%", fmt); return 0; }
  if (strchr ("efgaEFGA", *p) == 0)
    { builtin_error ("format '%s' has unknown %%%c directive", fmt, *p); return 0; }
  for (p++; *p; )
    {
      if (*p == '%' && p[1] == '%') { p += 2; (*suf)++; }
      else if (*p == '%') { builtin_error ("format '%s' has too many %% directives", fmt); return 0; }
      else { p++; (*suf)++; }
    }
  at = (size_t) (conv - fmt);
  out = xmalloc (strlen (fmt) + 2);
  memcpy (out, fmt, at);
  out[at] = 'L';
  strcpy (out + at + 1, conv + has_l);
  return out;
}

/* The default format: %.Nf with the most decimals any operand has, %0W.Nf
   under -w with W the widest operand once brought to N decimals, and %Lg
   when a hex float is involved. */
static const char *
seq_default_format (const struct seq_num *first, const struct seq_num *step,
                    const struct seq_num *last, int equal_width, char *buf, size_t bufsz)
{
  int prec = first->prec > step->prec ? first->prec : step->prec;
  long fw, lw, w;

  if (prec == INT_MAX || last->prec == INT_MAX) return "%Lg";
  if (!equal_width) { snprintf (buf, bufsz, "%%.%dLf", prec); return buf; }
  fw = (long) first->width + (prec - first->prec);
  lw = (long) last->width + (prec - last->prec);
  if (last->prec && prec == 0) lw--;    /* its point is not printed */
  if (last->prec == 0 && prec) lw++;    /* a point is added to it */
  if (first->prec == 0 && prec) fw++;
  w = fw > lw ? fw : lw;
  if (w < 0) w = 0;
  if (w > INT_MAX) w = INT_MAX;
  snprintf (buf, bufsz, "%%0%ld.%dLf", w, prec);
  return buf;
}

/* ---- the three ways to count ------------------------------------------- */

/* Count on decimal strings: A up to B (null: unbounded) in steps of ST,
   every one a run of digits. Exact at any size, and never formats. This is
   what `seq N` and `for i in $(seq A B)` run. */
static int
seq_count_digits (struct seq_out *o, const char *a, const char *b, const char *st, char sep)
{
  char *num; size_t cap, start, end, len, blen = 0, slen, i, k, carry;
  int rc = -1, one;

  while (*a == '0' && a[1]) a++;
  while (*st == '0' && st[1]) st++;
  if (b) { while (*b == '0' && b[1]) b++; blen = strlen (b); }
  slen = strlen (st);
  one = (slen == 1 && *st == '1');
  len = strlen (a);
  if (b && (len > blen || (len == blen && strcmp (a, b) > 0))) return 0;   /* nothing, not even a newline */

  cap = len > blen ? len : blen;
  if (cap < slen) cap = slen;
  cap += 32;
  num = xmalloc (cap);
  start = cap - len; end = cap;
  memcpy (num + start, a, len);
  if (seq_put (o, num + start, len) < 0) goto out;
  for (;;)
    {
      /* num += st, right to left with a carry, growing to the left */
      if (start < slen + 1)
        {
          num = xrealloc (num, cap * 2);
          memmove (num + cap, num, cap);
          start += cap; end += cap; cap *= 2;
        }
      if (one)                  /* step 1: bump the last digit, carry only past a 9 */
        {
          for (i = end; i > start; )
            {
              if (num[--i] != '9') { num[i]++; break; }
              num[i] = '0';
            }
          if (i == start && num[i] == '0') num[--start] = '1';
        }
      else
        {
          while (end - start < slen) num[--start] = '0';
          for (i = 1, carry = 0; i <= slen; i++)
            {
              k = (size_t) (num[end - i] - '0') + (size_t) (st[slen - i] - '0') + carry;
              num[end - i] = (char) ('0' + k % 10);
              carry = k / 10;
            }
          for (; carry && i <= end - start; i++)
            {
              k = (size_t) (num[end - i] - '0') + carry;
              num[end - i] = (char) ('0' + k % 10);
              carry = k / 10;
            }
          if (carry) num[--start] = '1';
        }
      len = end - start;
      if (b && (len > blen || (len == blen && memcmp (num + start, b, blen) > 0))) break;
      if (o->cap - o->len < len + 1)
        {
          if (seq_flush (o) < 0) goto out;
          if (len + 1 > o->cap)
            {
              if (seq_put (o, &sep, 1) < 0 || seq_put (o, num + start, len) < 0) goto out;
              continue;
            }
        }
      o->buf[o->len++] = sep;
      memcpy (o->buf + o->len, num + start, len);
      o->len += len;
    }
  rc = seq_put (o, "\n", 1);
out:
  free (num);
  return rc;
}

static size_t
seq_itoa (char *buf, long long x, int width)   /* sign, zeros to WIDTH, digits */
{
  char tmp[24]; size_t n = 0, k = 0; int pad;
  unsigned long long u = x < 0 ? 0ULL - (unsigned long long) x : (unsigned long long) x;

  do { tmp[n++] = (char) ('0' + u % 10); u /= 10; } while (u);
  if (x < 0) buf[k++] = '-';
  for (pad = width - (int) (n + k); pad > 0; pad--) buf[k++] = '0';
  while (n) buf[k++] = tmp[--n];
  return k;
}

/* Integer operands with a sign, a step other than 1, or -w: a 64-bit
   counter, exact and identical to the float path below it. */
static int
seq_count_int (struct seq_out *o, long long first, long long step, long long last,
               int last_inf, int width, const char *sep, size_t seplen)
{
  char small[64], *tmp = small; long long x = first;
  int rc = -1;

  if (!last_inf && (step > 0 ? first > last : first < last)) return 0;
  /* -w preserves the operand's leading zeros, even when the value itself
     fits the integer counter. The spelling can be much wider than 64. */
  if (width >= (int) sizeof small) tmp = xmalloc ((size_t) width + 24);
  for (;;)
    {
      if (seq_put (o, tmp, seq_itoa (tmp, x, width)) < 0) goto out;
      if (__builtin_add_overflow (x, step, &x)) break;
      if (!last_inf && (step > 0 ? x > last : x < last)) break;
      if (seq_put (o, sep, seplen) < 0) goto out;
    }
  rc = seq_put (o, "\n", 1);
out:
  if (tmp != small) free (tmp);
  return rc;
}

struct seq_str { char *s; size_t len, cap; };

static int
seq_fmt (struct seq_str *g, const char *fmt, long double x)
{
  int n = snprintf (g->s, g->cap, fmt, x);
  if (n >= 0 && (size_t) n >= g->cap)
    {
      g->cap = (size_t) n + 1;
      g->s = xrealloc (g->s, g->cap);
      n = snprintf (g->s, g->cap, fmt, x);
    }
  if (n < 0) return -1;
  g->len = (size_t) n;
  return 0;
}

/* Everything else: each value is FIRST + i * STEP in long double, printed
   with FMT. The value one step past LAST is printed too when it prints as
   LAST — 0.3 after `seq 0 0.1 0.2`, which arithmetic put a hair above 0.3 —
   unless that would repeat the line before it. */
static int
seq_count_float (struct seq_out *o, const char *fmt, size_t pre, size_t suf,
                 long double first, long double step, long double last,
                 const char *sep, size_t seplen)
{
  struct seq_str a = { 0, 0, 64 }, b = { 0, 0, 64 };
  long double x = first, i;
  int rc = -1;

  if (step < 0 ? first < last : last < first) return 0;
  a.s = xmalloc (a.cap);
  b.s = xmalloc (b.cap);
  for (i = 1; ; i++)
    {
      long double x0 = x, v; char *end;
      if (seq_fmt (&a, fmt, x0) < 0 || seq_put (o, a.s, a.len) < 0) goto out;
      x = first + i * step;
      if (step < 0 ? x < last : last < x)
        {
          if (seq_fmt (&b, fmt, x) < 0) goto out;
          if (b.len >= pre + suf)
            {
              char save = b.s[b.len - suf];
              b.s[b.len - suf] = 0;
              v = strtold (b.s + pre, &end);
              if (end == b.s + b.len - suf && end != b.s + pre && v == last
                  && !(a.len == b.len && memcmp (a.s + pre, b.s + pre, b.len - pre - suf) == 0))
                {
                  b.s[b.len - suf] = save;
                  if (seq_put (o, sep, seplen) < 0 || seq_put (o, b.s, b.len) < 0) goto out;
                }
            }
          break;
        }
      if (seq_put (o, sep, seplen) < 0) goto out;
    }
  rc = seq_put (o, "\n", 1);
out:
  free (a.s);
  free (b.s);
  return rc;
}

/* ---- the builtin ------------------------------------------------------- */

int
seq_builtin (WORD_LIST *list)
{
  WORD_LIST *l; char *w, *p;
  const char *sep = "\n", *fmt = 0, *args[3];
  int wflag = 0, nargs = 0, rc, k;
  struct seq_num first = { 1.0L, 0, 1 }, step = { 1.0L, 0, 1 }, last;
  struct seq_out o = { seq_block, 0, SEQ_BLOCK };
  char *lfmt = 0, fmtbuf[64]; size_t pre = 0, suf = 0, seplen;

  /* Options come first, as getopt's POSIX mode: the first operand ends
     them, and an operand may be a negative number. */
  for (l = list; l; l = l->next)
    {
      w = l->word->word;
      if (w[0] != '-' || w[1] == 0) break;
      if (isdigit ((unsigned char) w[1]) || w[1] == '.') break;
      if (strcmp (w, "--") == 0) { l = l->next; break; }
      if (w[1] == '-')
        {
          const char *name = w + 2, *eq = strchr (name, '='); size_t n = eq ? (size_t) (eq - name) : strlen (name);
          const char *val = 0;
          if (n && strncmp ("equal-width", name, n) == 0)
            {
              if (eq) { builtin_error ("option '--equal-width' doesn't allow an argument"); builtin_usage (); return EXECUTION_FAILURE; }
              wflag = 1; continue;
            }
          if (n && strncmp ("help", name, n) == 0) { builtin_help (); return EXECUTION_SUCCESS; }
          if (n && (strncmp ("format", name, n) == 0 || strncmp ("separator", name, n) == 0))
            {
              if (eq) val = eq + 1;
              else if (l->next) { l = l->next; val = l->word->word; }
              else { builtin_error ("option '%s' requires an argument", w); builtin_usage (); return EXECUTION_FAILURE; }
              if (name[0] == 'f') fmt = val; else sep = val;
              continue;
            }
          builtin_error ("unrecognized option '%s'", w); builtin_usage (); return EXECUTION_FAILURE;
        }
      for (p = w + 1; *p; p++)
        {
          if (*p == 'w') { wflag = 1; continue; }
          if (*p == 'f' || *p == 's')
            {
              const char *val;
              if (p[1]) val = p + 1;
              else if (l->next) { l = l->next; val = l->word->word; }
              else { builtin_error ("option requires an argument -- '%c'", *p); builtin_usage (); return EXECUTION_FAILURE; }
              if (*p == 'f') fmt = val; else sep = val;
              break;
            }
          builtin_error ("invalid option -- '%c'", *p); builtin_usage (); return EXECUTION_FAILURE;
        }
    }
  for (; l; l = l->next)
    {
      if (nargs == 3) { builtin_error ("extra operand '%s'", l->word->word); builtin_usage (); return EXECUTION_FAILURE; }
      args[nargs++] = l->word->word;
    }
  if (nargs == 0) { builtin_error ("missing operand"); builtin_usage (); return EXECUTION_FAILURE; }
  if (fmt && wflag)
    {
      builtin_error ("format string may not be specified when printing equal width strings");
      builtin_usage (); return EXECUTION_FAILURE;
    }
  if (fmt && (lfmt = seq_format (fmt, &pre, &suf)) == 0) return EXECUTION_FAILURE;

  /* [FIRST [INCREMENT]] LAST, scanned in that order so the first bad one is
     the one reported. */
  k = 0;
  if (nargs > 1 && seq_scan (args[k++], &first) < 0) goto usage;
  if (nargs > 2)
    {
      if (seq_scan (args[k++], &step) < 0) goto usage;
      if (step.v == 0) { builtin_error ("invalid Zero increment value: '%s'", args[1]); goto usage; }
    }
  if (seq_scan (args[k], &last) < 0) goto usage;
  seplen = strlen (sep);

  if (lfmt == 0)
    {
      const char *b = args[nargs - 1];
      int last_inf = isinf (last.v) && last.v > 0;
      /* the 64-bit counter: every operand [+-]digits and small enough that
         first + i * step is exact in a long double too (so the float path
         would print the same), LAST alternatively infinite */
      int ints = (nargs == 1 || (seq_is_int (args[0]) && fabsl (first.v) <= SEQ_INT_MAX))
                 && (nargs < 3 || (seq_is_int (args[1]) && fabsl (step.v) <= SEQ_INT_MAX))
                 && (last_inf || (seq_is_int (b) && fabsl (last.v) <= SEQ_INT_MAX));
      for (k = 0; k < nargs; k++)   /* "-0" prints as -0: that is the float path's */
        if (args[k][0] == '-' && seq_is_int (args[k]) && strspn (args[k] + 1, "0") == strlen (args[k] + 1)) ints = 0;

      /* The decimal-string counter, in the two cases coreutils uses its own,
         so the output agrees beyond the 64 bits a long double keeps exactly:
         the operands spelled as plain digits, counted on those very digits;
         or, failing that, no decimals anywhere and nothing negative, counted
         on what the values print as. `seq 99999999999999999999 1e20` shows
         the difference — the first form is exact, the second rounds first. */
      if (!wflag && seplen == 1 && (nargs == 1 || seq_is_digits (args[0]))
          && (nargs < 3 || seq_is_digits (args[1])) && seq_is_digits (b))
        rc = seq_count_digits (&o, nargs == 1 ? "1" : args[0], b, nargs == 3 ? args[1] : "1", sep[0]);
      else if (!wflag && seplen == 1 && first.prec == 0 && step.prec == 0 && last.prec == 0
               && isfinite (first.v) && isfinite (step.v) && step.v > 0
               && !signbit (first.v) && !signbit (last.v))
        {
          struct seq_str sa = { 0, 0, 64 }, sb = { 0, 0, 64 }, ss = { 0, 0, 64 };
          sa.s = xmalloc (sa.cap); sb.s = xmalloc (sb.cap); ss.s = xmalloc (ss.cap);
          if (seq_fmt (&sa, "%.0Lf", first.v) < 0 || seq_fmt (&ss, "%.0Lf", step.v) < 0
              || (!last_inf && seq_fmt (&sb, "%.0Lf", last.v) < 0))
            rc = -1;
          else
            rc = seq_count_digits (&o, sa.s, last_inf ? 0 : sb.s, ss.s, sep[0]);
          free (sa.s); free (sb.s); free (ss.s);
        }
      else if (ints)
        {
          int width = 0;
          if (wflag) width = first.width > last.width ? first.width : last.width;
          rc = seq_count_int (&o, (long long) first.v, (long long) step.v,
                              last_inf ? 0 : (long long) last.v, last_inf, width, sep, seplen);
        }
      else
        rc = seq_count_float (&o, seq_default_format (&first, &step, &last, wflag, fmtbuf, sizeof fmtbuf),
                              0, 0, first.v, step.v, last.v, sep, seplen);
    }
  else
    rc = seq_count_float (&o, lfmt, pre, suf, first.v, step.v, last.v, sep, seplen);

  if (rc == 0) rc = seq_flush (&o);
  free (lfmt);
  return sh_chkwrite (rc < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS);

usage:
  free (lfmt);
  builtin_usage ();
  return EXECUTION_FAILURE;
}

char *seq_doc[] = {
  "Print a sequence of numbers.",
  "",
  "Print the numbers from FIRST to LAST in steps of INCREMENT, one per line.",
  "FIRST and INCREMENT default to 1. A negative INCREMENT counts down. When",
  "LAST is on the wrong side of FIRST nothing is printed.",
  "",
  "  -f FORMAT, --format=FORMAT  print each number with a printf FORMAT",
  "                              holding one %e, %f, %g or %a conversion",
  "  -s STRING, --separator=STRING",
  "                              put STRING between numbers (default: newline)",
  "  -w, --equal-width           pad with leading zeros to one width",
  "",
  "Operands are floating point. The decimals they carry set the output",
  "precision: `seq 1 .5 2` prints 1.0 1.5 2.0. Output and exit status match",
  "GNU coreutils seq.",
  "",
  "Exit status: 0, or 1 on a bad number, a zero INCREMENT, a bad FORMAT or",
  "a write error.",
  (char *)NULL
};

struct builtin seq_struct = {
  "seq", seq_builtin, BUILTIN_ENABLED, seq_doc,
  "seq [-w] [-s STRING] [-f FORMAT] [FIRST [INCREMENT]] LAST", 0
};
