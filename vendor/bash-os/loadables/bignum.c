/* SPDX-License-Identifier: MIT */
/* bignum.c — arbitrary-precision integer arithmetic. Loadable for bash.
 *
 * bash's `(( ))` is signed 64-bit. Number theory, cryptography
 * research, financial calculations beyond ~10^18 stall. bignum
 * adds add/sub/mul/divmod/mod/modexp/cmp/bits with a self-contained
 * implementation. Stage 19 TLS uses its own mbedTLS bignum path.
 *
 * NOT constant-time. This is for general arithmetic — for crypto
 * (Ed25519, ECDSA, etc.) use crypto's primitives, which run on
 * audited constant-time C.
 *
 * Subcommands (all take + emit decimal strings; -x for hex):
 *   bignum add A B               A + B
 *   bignum sub A B               A - B
 *   bignum mul A B               A * B
 *   bignum divmod A B            quotient on stdout, remainder
 *                                    bound to BIGNUM_REM (or printed
 *                                    on a second line)
 *   bignum mod A B               A mod B
 *   bignum modexp BASE EXP MOD   BASE^EXP mod MOD
 *   bignum cmp A B               -1/0/1; exit code matches
 *   bignum bits A                bit length (0 for zero)
 *   bignum shl A N               A << N
 *   bignum shr A N               A >> N (truncating)
 *
 * Common flags:
 *   -x   hex input AND output (no leading 0x; lowercase). Default
 *        is decimal both ways.
 *
 * Companion docs:
 *     /docs/bash/bignum.txt
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
#include <ctype.h>
#include <limits.h>

#include "loadables.h"

/* ---- Bignum representation ----------------------------------------- *
 * Big integer stored as variable-length little-endian uint32_t array.
 * Sign is separate. Length is the number of significant limbs (no
 * leading zeros), or 0 if value is zero.
 *
 * Limb is 32 bits; we use 64-bit accumulators in arithmetic loops to
 * absorb carries cleanly.
 */
typedef struct {
  uint32_t *limbs;
  size_t    n;
  size_t    cap;
  int       neg;
} bn_t;

static long bbn_fail_reserve_at = 0;
static long bbn_reserve_count = 0;

static void
bbn_reset_reserve_fail_hook (void)
{
  const char *e = getenv ("BASHBIGNUM_FAIL_RESERVE_AT");
  char *end = NULL;
  bbn_fail_reserve_at = 0;
  bbn_reserve_count = 0;
  if (!e || !*e) return;
  errno = 0;
  long n = strtol (e, &end, 10);
  if (errno == 0 && end && *end == '\0' && n > 0)
    bbn_fail_reserve_at = n;
}

static void
bn_init (bn_t *b)
{
  memset (b, 0, sizeof *b);
}

static void
bn_free (bn_t *b)
{
  free (b->limbs);
  bn_init (b);
}

static int
bn_reserve (bn_t *b, size_t n)
{
  if (n <= b->cap) return 0;
  bbn_reserve_count++;
  if (bbn_fail_reserve_at > 0 && bbn_reserve_count == bbn_fail_reserve_at)
    return -1;
  size_t nc = b->cap ? b->cap : 4;
  while (nc < n) nc *= 2;
  uint32_t *p = realloc (b->limbs, nc * sizeof *p);
  if (!p) return -1;
  b->limbs = p;
  b->cap = nc;
  return 0;
}

static void
bn_normalize (bn_t *b)
{
  while (b->n > 0 && b->limbs[b->n - 1] == 0) b->n--;
  if (b->n == 0) b->neg = 0;
}

static int
bn_set_zero (bn_t *b)
{
  b->n = 0;
  b->neg = 0;
  return 0;
}

static int
bn_is_zero (const bn_t *b)
{
  return b->n == 0;
}

/* Compare absolute values: returns -1, 0, 1. */
static int
bn_cmp_abs (const bn_t *a, const bn_t *b)
{
  if (a->n != b->n) return a->n < b->n ? -1 : 1;
  for (ssize_t i = (ssize_t) a->n - 1; i >= 0; i--)
    if (a->limbs[i] != b->limbs[i])
      return a->limbs[i] < b->limbs[i] ? -1 : 1;
  return 0;
}

/* Sign-aware compare: returns -1, 0, 1. */
static int
bn_cmp (const bn_t *a, const bn_t *b)
{
  if (a->neg != b->neg)
    return bn_is_zero (a) && bn_is_zero (b) ? 0 : (a->neg ? -1 : 1);
  int c = bn_cmp_abs (a, b);
  return a->neg ? -c : c;
}

/* ---- Decimal I/O ---------------------------------------------------- */

/* Parse a decimal string into b. Returns 0 on success. */
static int
bn_from_dec (bn_t *b, const char *s)
{
  bn_set_zero (b);
  if (!s || !*s) return -1;
  if (*s == '-') { b->neg = 1; s++; }
  else if (*s == '+') s++;
  if (!*s) return -1;
  for (; *s; s++)
    {
      if (*s < '0' || *s > '9') return -1;
      /* b = b * 10 + (digit) */
      uint64_t carry = (uint32_t) (*s - '0');
      for (size_t i = 0; i < b->n; i++)
        {
          uint64_t v = (uint64_t) b->limbs[i] * 10 + carry;
          b->limbs[i] = (uint32_t) v;
          carry = v >> 32;
        }
      if (carry)
        {
          if (bn_reserve (b, b->n + 1) < 0) return -1;
          b->limbs[b->n++] = (uint32_t) carry;
        }
    }
  bn_normalize (b);
  return 0;
}

/* Hex parse: lowercase or uppercase, optional 0x/0X prefix. NOTE: unlike
   bn_from_dec, a leading '+' is intentionally rejected here — the asymmetry
   is pinned by e05-bignum-grammar-errors.sh ("reject hex leading plus"
   vs "decimal grammar: leading plus accepted"). Do not add '+' handling. */
static int
bn_from_hex (bn_t *b, const char *s)
{
  bn_set_zero (b);
  if (!s || !*s) return -1;
  if (*s == '-') { b->neg = 1; s++; }
  if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
  if (!*s) return -1;
  size_t hlen = strlen (s);
  size_t nlimbs = (hlen + 7) / 8;
  if (bn_reserve (b, nlimbs) < 0) return -1;
  /* Big-endian hex; limbs are little-endian uint32. */
  size_t li = 0;
  while (hlen > 0 && li < nlimbs)
    {
      size_t take = hlen >= 8 ? 8 : hlen;
      const char *start = s + hlen - take;
      uint32_t v = 0;
      for (size_t k = 0; k < take; k++)
        {
          char c = start[k];
          int d;
          if (c >= '0' && c <= '9') d = c - '0';
          else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
          else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
          else return -1;
          v = (v << 4) | (uint32_t) d;
        }
      b->limbs[li++] = v;
      hlen -= take;
    }
  b->n = li;
  bn_normalize (b);
  return 0;
}

/* Print b as decimal to stdout. Allocates and frees a digit buffer. */
static void
bn_print_dec (const bn_t *b)
{
  if (bn_is_zero (b)) { putchar ('0'); putchar ('\n'); return; }
  /* Repeatedly divmod by 10^9 (fits in uint32_t with room for carry). */
  /* Copy limbs (we'll consume them). */
  uint32_t *t = malloc (b->n * sizeof *t);
  memcpy (t, b->limbs, b->n * sizeof *t);
  size_t tn = b->n;

  /* Each div-by-1e9 yields up to 9 decimal digits per chunk. */
  char *digits = malloc (b->n * 10 + 16);
  size_t dpos = 0;

  while (tn > 0)
    {
      uint64_t rem = 0;
      for (ssize_t i = (ssize_t) tn - 1; i >= 0; i--)
        {
          uint64_t cur = (rem << 32) | t[i];
          t[i] = (uint32_t) (cur / 1000000000U);
          rem = cur % 1000000000U;
        }
      while (tn > 0 && t[tn - 1] == 0) tn--;
      /* Emit 9 digits LE; pad if more limbs remain. */
      char chunk[16];
      int cl = snprintf (chunk, sizeof chunk, "%09llu", (unsigned long long) rem);
      if (tn == 0)
        {
          /* Most-significant chunk: trim leading zeros. */
          int firstnz = 0;
          while (firstnz < cl - 1 && chunk[firstnz] == '0') firstnz++;
          for (int i = cl - 1; i >= firstnz; i--) digits[dpos++] = chunk[i];
        }
      else
        for (int i = cl - 1; i >= 0; i--) digits[dpos++] = chunk[i];
    }

  if (b->neg) putchar ('-');
  for (ssize_t i = (ssize_t) dpos - 1; i >= 0; i--) putchar (digits[i]);
  putchar ('\n');
  free (t);
  free (digits);
}

static void
bn_print_hex (const bn_t *b)
{
  if (bn_is_zero (b)) { putchar ('0'); putchar ('\n'); return; }
  if (b->neg) putchar ('-');
  int started = 0;
  for (ssize_t i = (ssize_t) b->n - 1; i >= 0; i--)
    {
      if (!started) printf ("%x", b->limbs[i]), started = 1;
      else          printf ("%08x", b->limbs[i]);
    }
  putchar ('\n');
}

/* ---- Arithmetic ----------------------------------------------------- */

/* dst = |a| + |b| */
static int
bn_add_abs (bn_t *dst, const bn_t *a, const bn_t *b)
{
  size_t n = (a->n > b->n ? a->n : b->n) + 1;
  if (bn_reserve (dst, n) < 0) return -1;
  uint64_t carry = 0;
  for (size_t i = 0; i < n; i++)
    {
      uint64_t av = (i < a->n) ? a->limbs[i] : 0;
      uint64_t bv = (i < b->n) ? b->limbs[i] : 0;
      uint64_t s = av + bv + carry;
      dst->limbs[i] = (uint32_t) s;
      carry = s >> 32;
    }
  dst->n = n;
  bn_normalize (dst);
  return 0;
}

/* dst = |a| - |b|, requires |a| >= |b|. */
static int
bn_sub_abs (bn_t *dst, const bn_t *a, const bn_t *b)
{
  if (bn_reserve (dst, a->n) < 0) return -1;
  int64_t borrow = 0;
  for (size_t i = 0; i < a->n; i++)
    {
      int64_t bv = (i < b->n) ? (int64_t) b->limbs[i] : 0;
      int64_t s = (int64_t) a->limbs[i] - bv - borrow;
      if (s < 0) { s += (1LL << 32); borrow = 1; }
      else borrow = 0;
      dst->limbs[i] = (uint32_t) s;
    }
  dst->n = a->n;
  bn_normalize (dst);
  return 0;
}

/* dst = a + b (signed). dst must not alias a or b. */
static int
bn_add (bn_t *dst, const bn_t *a, const bn_t *b)
{
  if (a->neg == b->neg)
    {
      if (bn_add_abs (dst, a, b) < 0) return -1;
      dst->neg = a->neg;
    }
  else
    {
      int c = bn_cmp_abs (a, b);
      if (c >= 0)
        {
          if (bn_sub_abs (dst, a, b) < 0) return -1;
          dst->neg = a->neg;
        }
      else
        {
          if (bn_sub_abs (dst, b, a) < 0) return -1;
          dst->neg = b->neg;
        }
    }
  bn_normalize (dst);
  return 0;
}

static int
bn_sub (bn_t *dst, const bn_t *a, const bn_t *b)
{
  bn_t nb = *b;
  nb.neg = !b->neg;
  return bn_add (dst, a, &nb);
}

/* dst = a * b (schoolbook O(n²)). dst must not alias a or b. */
static int
bn_mul (bn_t *dst, const bn_t *a, const bn_t *b)
{
  size_t n = a->n + b->n + 1;
  if (bn_reserve (dst, n) < 0) return -1;
  memset (dst->limbs, 0, n * sizeof *dst->limbs);
  for (size_t i = 0; i < a->n; i++)
    {
      uint64_t carry = 0;
      uint64_t av = a->limbs[i];
      for (size_t j = 0; j < b->n; j++)
        {
          uint64_t cur = (uint64_t) dst->limbs[i + j] + av * b->limbs[j] + carry;
          dst->limbs[i + j] = (uint32_t) cur;
          carry = cur >> 32;
        }
      dst->limbs[i + b->n] += (uint32_t) carry;
    }
  dst->n = n;
  dst->neg = a->neg ^ b->neg;
  bn_normalize (dst);
  return 0;
}

/* Shift |a| left by k bits, in-place — caller must reserve enough. */
/* Returns 0 on success, -1 on allocation failure (caller must propagate). */
static int
bn_shl_abs_inplace (bn_t *a, unsigned k)
{
  if (k == 0 || bn_is_zero (a)) return 0;
  unsigned word = k / 32, bit = k % 32;
  if (word > 0)
    {
      if (bn_reserve (a, a->n + word) < 0) return -1;
      memmove (a->limbs + word, a->limbs, a->n * sizeof *a->limbs);
      memset (a->limbs, 0, word * sizeof *a->limbs);
      a->n += word;
    }
  if (bit > 0)
    {
      if (bn_reserve (a, a->n + 1) < 0) return -1;
      uint32_t carry = 0;
      for (size_t i = 0; i < a->n; i++)
        {
          uint64_t cur = ((uint64_t) a->limbs[i] << bit) | carry;
          a->limbs[i] = (uint32_t) cur;
          carry = (uint32_t) (cur >> 32);
        }
      if (carry) a->limbs[a->n++] = carry;
    }
  bn_normalize (a);
  return 0;
}

static void
bn_shr_abs_inplace (bn_t *a, unsigned k)
{
  if (k == 0 || bn_is_zero (a)) return;
  unsigned word = k / 32, bit = k % 32;
  if (word > 0)
    {
      if (word >= a->n) { bn_set_zero (a); return; }
      memmove (a->limbs, a->limbs + word, (a->n - word) * sizeof *a->limbs);
      a->n -= word;
    }
  if (bit > 0)
    {
      uint32_t carry = 0;
      for (ssize_t i = (ssize_t) a->n - 1; i >= 0; i--)
        {
          uint64_t cur = ((uint64_t) a->limbs[i] | ((uint64_t) carry << 32)) >> bit;
          carry = a->limbs[i] & ((1U << bit) - 1);
          a->limbs[i] = (uint32_t) cur;
        }
    }
  bn_normalize (a);
}

/* bn_bits: position of highest set bit + 1 (0 for zero). */
static unsigned
bn_bits (const bn_t *a)
{
  if (bn_is_zero (a)) return 0;
  uint32_t top = a->limbs[a->n - 1];
  unsigned b = 0;
  while (top) { b++; top >>= 1; }
  return (unsigned) ((a->n - 1) * 32 + b);
}

/* Divide |a| by |b|, set q = quotient, r = remainder. Standard
   shift-and-subtract algorithm. b must be non-zero. */
static int
bn_divmod (bn_t *q, bn_t *r, const bn_t *a, const bn_t *b)
{
  if (bn_is_zero (b)) return -1;
  bn_set_zero (q);
  bn_set_zero (r);
  /* r = 0; for i = bits(a)-1 .. 0: r = (r<<1) | bit_i(a); if r >= b: r -= b, q |= 1<<i */
  unsigned ab = bn_bits (a);
  if (ab == 0)
    return 0;  /* both zero */
  if (bn_reserve (q, (ab + 31) / 32) < 0) return -1;
  memset (q->limbs, 0, q->cap * sizeof *q->limbs);
  q->n = (ab + 31) / 32;

  if (bn_reserve (r, b->n + 1) < 0) return -1;
  for (ssize_t i = (ssize_t) ab - 1; i >= 0; i--)
    {
      if (bn_shl_abs_inplace (r, 1) < 0) return -1;
      uint32_t bit_i = (a->limbs[i / 32] >> (i % 32)) & 1;
      if (bit_i)
        {
          if (r->n == 0) { if (bn_reserve (r, 1) < 0) return -1; r->limbs[0] = 0; r->n = 1; }
          r->limbs[0] |= 1;
        }
      if (bn_cmp_abs (r, b) >= 0)
        {
          bn_t tmp; bn_init (&tmp);
          if (bn_sub_abs (&tmp, r, b) < 0)
            { bn_free (&tmp); return -1; }
          bn_free (r); *r = tmp;
          q->limbs[i / 32] |= (1U << (i % 32));
        }
    }
  bn_normalize (q);
  bn_normalize (r);
  q->neg = a->neg ^ b->neg;
  r->neg = a->neg;  /* convention: matches dividend */
  bn_normalize (q); bn_normalize (r);
  return 0;
}

/* dst = a^e mod m, by square-and-multiply. */
static int
bn_modexp (bn_t *dst, const bn_t *a, const bn_t *e, const bn_t *m)
{
  if (bn_is_zero (m)) return -1;
  if (e->neg) return -1;   /* modular inverse not implemented */
  bn_t result, base, tmp, dummy_q, dummy_r;
  bn_init (&result); bn_init (&base); bn_init (&tmp);
  bn_init (&dummy_q); bn_init (&dummy_r);
  /* result = 1 */
  if (bn_reserve (&result, 1) < 0)
    { bn_free (&result); bn_free (&base); bn_free (&tmp);
      bn_free (&dummy_q); bn_free (&dummy_r); return -1; }
  result.limbs[0] = 1; result.n = 1;
  /* base = a mod m */
  bn_t a_copy = *a;
  if (bn_divmod (&dummy_q, &base, &a_copy, m) < 0)
    { bn_free (&result); bn_free (&base); bn_free (&tmp);
      bn_free (&dummy_q); bn_free (&dummy_r); return -1; }

  unsigned eb = bn_bits (e);
  for (unsigned i = 0; i < eb; i++)
    {
      uint32_t bit = (e->limbs[i / 32] >> (i % 32)) & 1;
      if (bit)
        {
          /* result = (result * base) mod m */
          if (bn_mul (&tmp, &result, &base) < 0)
            { bn_free (&result); bn_free (&base); bn_free (&tmp);
              bn_free (&dummy_q); bn_free (&dummy_r); return -1; }
          bn_t old = result; bn_init (&result);
          if (bn_divmod (&dummy_q, &result, &tmp, m) < 0)
            { bn_free (&old); bn_free (&result); bn_free (&base); bn_free (&tmp);
              bn_free (&dummy_q); bn_free (&dummy_r); return -1; }
          bn_free (&old);
        }
      /* base = (base * base) mod m */
      if (bn_mul (&tmp, &base, &base) < 0)
        { bn_free (&result); bn_free (&base); bn_free (&tmp);
          bn_free (&dummy_q); bn_free (&dummy_r); return -1; }
      bn_t oldb = base; bn_init (&base);
      if (bn_divmod (&dummy_q, &base, &tmp, m) < 0)
        { bn_free (&oldb); bn_free (&result); bn_free (&base); bn_free (&tmp);
          bn_free (&dummy_q); bn_free (&dummy_r); return -1; }
      bn_free (&oldb);
    }
  /* When exponent is 0, result stayed at initial 1 — reduce modulo m. */
  if (eb == 0) {
    bn_t leftover; bn_init (&leftover);
    if (bn_divmod (&dummy_q, &leftover, &result, m) < 0)
      { bn_free (&leftover); bn_free (&result); bn_free (&base); bn_free (&tmp);
        bn_free (&dummy_q); bn_free (&dummy_r); return -1; }
    bn_free (&result);
    result = leftover;
  }
  bn_free (&base);
  bn_free (&tmp);
  bn_free (&dummy_q);
  bn_free (&dummy_r);
  *dst = result;
  return 0;
}

/* ---- Bash glue ----------------------------------------------------- */

static int
bbn_parse (bn_t *b, const char *s, int hex_io)
{
  return hex_io ? bn_from_hex (b, s) : bn_from_dec (b, s);
}

static int
bbn_parse_shift_count (const char *s, unsigned *out)
{
  if (!s || !*s) return -1;
  for (const char *p = s; *p; p++)
    if (*p < '0' || *p > '9')
      return -1;

  errno = 0;
  char *end = NULL;
  unsigned long v = strtoul (s, &end, 10);
  if (errno == ERANGE || !end || *end || v > UINT_MAX)
    return -1;

  *out = (unsigned) v;
  return 0;
}

static void
bbn_print (const bn_t *b, int hex_io)
{
  if (hex_io) bn_print_hex (b);
  else        bn_print_dec (b);
}

static int
bbn_has_x (WORD_LIST *args)
{
  for (WORD_LIST *p = args; p; p = p->next)
    if (strcmp (p->word->word, "-x") == 0) return 1;
  return 0;
}

/* Strip -x flag, return positional args. */
static const char *
bbn_pos (WORD_LIST *args, int n_want, const char **out)
{
  int n = 0;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-x") == 0) continue;
      if (n >= n_want) return "extra arg";
      out[n++] = w;
    }
  if (n < n_want) return "missing arg";
  return NULL;
}

#define BBN_BINARY(name, op_fn) \
static int name (WORD_LIST *args) { \
  int hex_io = bbn_has_x (args); \
  const char *p[2]; \
  const char *err = bbn_pos (args, 2, p); \
  if (err) { builtin_error ("%s: %s (need A B)", #op_fn, err); return EX_USAGE; } \
  bn_t A, B, R; bn_init (&A); bn_init (&B); bn_init (&R); \
  if (bbn_parse (&A, p[0], hex_io) < 0 || bbn_parse (&B, p[1], hex_io) < 0) { \
    builtin_error ("bad number"); bn_free (&A); bn_free (&B); return EXECUTION_FAILURE; } \
  if (op_fn (&R, &A, &B) < 0) { \
    builtin_error ("op failed"); bn_free (&A); bn_free (&B); bn_free (&R); return EXECUTION_FAILURE; } \
  bbn_print (&R, hex_io); \
  bn_free (&A); bn_free (&B); bn_free (&R); \
  return EXECUTION_SUCCESS; \
}

BBN_BINARY (bbn_add, bn_add)
BBN_BINARY (bbn_sub, bn_sub)
BBN_BINARY (bbn_mul, bn_mul)

static int
bbn_divmod_cmd (WORD_LIST *args)
{
  int hex_io = bbn_has_x (args);
  const char *p[2];
  const char *err = bbn_pos (args, 2, p);
  if (err) { builtin_error ("divmod: %s (need A B)", err); return EX_USAGE; }
  bn_t A, B, Q, R;
  bn_init (&A); bn_init (&B); bn_init (&Q); bn_init (&R);
  if (bbn_parse (&A, p[0], hex_io) < 0 || bbn_parse (&B, p[1], hex_io) < 0)
    { builtin_error ("bad number"); goto fail; }
  if (bn_divmod (&Q, &R, &A, &B) < 0)
    { builtin_error (bn_is_zero (&B) ? "divmod by zero" : "divmod: op failed"); goto fail; }
  /* Emit quotient first, remainder on second line. */
  bbn_print (&Q, hex_io);
  bbn_print (&R, hex_io);
  bn_free (&A); bn_free (&B); bn_free (&Q); bn_free (&R);
  return EXECUTION_SUCCESS;
fail:
  bn_free (&A); bn_free (&B); bn_free (&Q); bn_free (&R);
  return EXECUTION_FAILURE;
}

static int
bbn_mod_cmd (WORD_LIST *args)
{
  int hex_io = bbn_has_x (args);
  const char *p[2];
  const char *err = bbn_pos (args, 2, p);
  if (err) { builtin_error ("mod: %s (need A B)", err); return EX_USAGE; }
  bn_t A, B, Q, R;
  bn_init (&A); bn_init (&B); bn_init (&Q); bn_init (&R);
  if (bbn_parse (&A, p[0], hex_io) < 0 || bbn_parse (&B, p[1], hex_io) < 0)
    { builtin_error ("bad number"); goto fail; }
  if (bn_divmod (&Q, &R, &A, &B) < 0)
    { builtin_error (bn_is_zero (&B) ? "mod by zero" : "mod: op failed"); goto fail; }
  bbn_print (&R, hex_io);
  bn_free (&A); bn_free (&B); bn_free (&Q); bn_free (&R);
  return EXECUTION_SUCCESS;
fail:
  bn_free (&A); bn_free (&B); bn_free (&Q); bn_free (&R);
  return EXECUTION_FAILURE;
}

static int
bbn_modexp_cmd (WORD_LIST *args)
{
  int hex_io = bbn_has_x (args);
  const char *p[3];
  const char *err = bbn_pos (args, 3, p);
  if (err) { builtin_error ("modexp: %s (need BASE EXP MOD)", err); return EX_USAGE; }
  bn_t A, E, M, R;
  bn_init (&A); bn_init (&E); bn_init (&M); bn_init (&R);
  if (bbn_parse (&A, p[0], hex_io) < 0 ||
      bbn_parse (&E, p[1], hex_io) < 0 ||
      bbn_parse (&M, p[2], hex_io) < 0)
    { builtin_error ("bad number"); goto fail; }
  if (E.neg) { builtin_error ("modexp: negative exponent not supported"); goto fail; }
  /* E.neg is already rejected above, so the only failure bn_modexp can
     report here is a zero modulus — name it like mod/divmod do. */
  if (bn_modexp (&R, &A, &E, &M) < 0)
    { builtin_error (bn_is_zero (&M) ? "modexp: mod by zero" : "modexp: op failed"); goto fail; }
  bbn_print (&R, hex_io);
  bn_free (&A); bn_free (&E); bn_free (&M); bn_free (&R);
  return EXECUTION_SUCCESS;
fail:
  bn_free (&A); bn_free (&E); bn_free (&M); bn_free (&R);
  return EXECUTION_FAILURE;
}

static int
bbn_cmp_cmd (WORD_LIST *args)
{
  int hex_io = bbn_has_x (args);
  const char *p[2];
  const char *err = bbn_pos (args, 2, p);
  if (err) { builtin_error ("cmp: %s (need A B)", err); return EX_USAGE; }
  bn_t A, B;
  bn_init (&A); bn_init (&B);
  if (bbn_parse (&A, p[0], hex_io) < 0 || bbn_parse (&B, p[1], hex_io) < 0)
    { builtin_error ("bad number"); bn_free (&A); bn_free (&B); return EX_USAGE; }
  int c = bn_cmp (&A, &B);
  printf ("%d\n", c);
  bn_free (&A); bn_free (&B);
  /* Exit code: 0 if equal, 1 if a<b, 2 if a>b — let callers branch
     directly on $? for ordering tests. */
  return c == 0 ? EXECUTION_SUCCESS : (c < 0 ? 1 : 2);
}

static int
bbn_bits_cmd (WORD_LIST *args)
{
  int hex_io = bbn_has_x (args);
  const char *p[1];
  const char *err = bbn_pos (args, 1, p);
  if (err) { builtin_error ("bits: %s (need A)", err); return EX_USAGE; }
  bn_t A; bn_init (&A);
  if (bbn_parse (&A, p[0], hex_io) < 0)
    { builtin_error ("bad number"); bn_free (&A); return EX_USAGE; }
  printf ("%u\n", bn_bits (&A));
  bn_free (&A);
  return EXECUTION_SUCCESS;
}

static int
bbn_shift_cmd (WORD_LIST *args, int left)
{
  int hex_io = bbn_has_x (args);
  const char *p[2];
  const char *err = bbn_pos (args, 2, p);
  if (err) { builtin_error ("sh: %s (need A N)", err); return EX_USAGE; }
  bn_t A; bn_init (&A);
  if (bbn_parse (&A, p[0], hex_io) < 0)
    { builtin_error ("bad number"); bn_free (&A); return EX_USAGE; }
  unsigned n;
  if (bbn_parse_shift_count (p[1], &n) < 0)
    { builtin_error ("bad shift count"); bn_free (&A); return EX_USAGE; }
  if (left)
    {
      if (bn_shl_abs_inplace (&A, n) < 0)
        { builtin_error ("out of memory"); bn_free (&A); return EXECUTION_FAILURE; }
    }
  else
    bn_shr_abs_inplace (&A, n);
  bbn_print (&A, hex_io);
  bn_free (&A);
  return EXECUTION_SUCCESS;
}

int
bignum_builtin (WORD_LIST *list)
{
  bbn_reset_reserve_fail_hook ();
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;
  if (strcmp (cmd, "add")    == 0) return bbn_add (args);
  if (strcmp (cmd, "sub")    == 0) return bbn_sub (args);
  if (strcmp (cmd, "mul")    == 0) return bbn_mul (args);
  if (strcmp (cmd, "divmod") == 0) return bbn_divmod_cmd (args);
  if (strcmp (cmd, "mod")    == 0) return bbn_mod_cmd (args);
  if (strcmp (cmd, "modexp") == 0) return bbn_modexp_cmd (args);
  if (strcmp (cmd, "cmp")    == 0) return bbn_cmp_cmd (args);
  if (strcmp (cmd, "bits")   == 0) return bbn_bits_cmd (args);
  if (strcmp (cmd, "shl")    == 0) return bbn_shift_cmd (args, 1);
  if (strcmp (cmd, "shr")    == 0) return bbn_shift_cmd (args, 0);
  builtin_error ("unknown subcommand: %s", cmd);
  return EX_USAGE;
}

char *bignum_doc[] = {
  "Arbitrary-precision integer arithmetic.",
  "",
  "    bignum add A B               A + B",
  "    bignum sub A B               A - B",
  "    bignum mul A B               A * B",
  "    bignum divmod A B            quotient, then remainder (one per line)",
  "    bignum mod A B               A mod B",
  "    bignum modexp BASE EXP MOD   BASE^EXP mod MOD",
  "    bignum cmp A B               -1/0/1; exit code 1/0/2",
  "    bignum bits A                bit-length of A (0 for zero)",
  "    bignum shl A N               A << N (left shift)",
  "    bignum shr A N               A >> N (right shift)",
  "",
  "Common flag:",
  "    -x   hex I/O instead of decimal (no leading 0x; lowercase out).",
  "Division truncates toward zero; remainders keep the dividend sign.",
  "",
  "NOT constant-time. For crypto, use crypto's primitives.",
  (char *)NULL
};

struct builtin bignum_struct = {
  "bignum",
  bignum_builtin,
  BUILTIN_ENABLED,
  bignum_doc,
  "bignum add|sub|mul|divmod|mod|modexp|cmp|bits|shl|shr [-x] ARGS...",
  0
};
