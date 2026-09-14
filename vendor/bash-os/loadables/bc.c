/* SPDX-License-Identifier: MIT */
/* bc.c — arbitrary-precision bc(1) as a bash builtin.
 *
 * GNU bc compatibility: expression evaluation with arbitrary-precision
 * decimal arithmetic. Reads expressions from args or stdin (one per line).
 * Supports the core POSIX bc surface: + - * / % ^, parentheses, sqrt(),
 * length(), scale(), and the standard variables scale/ibase/obase/last.
 *
 * Design: numbers are stored as decimal digit strings with a scale
 * (fractional digits). Operations use grade-school algorithms.
 *
 * v2 (GNU parity): bare assignments are silent, ';' separates statements,
 * simple variables persist within an invocation, and the standard math
 * library (s/c/a/l/e/j) is computed in arbitrary precision by porting GNU
 * bc's libmath.b Taylor/Maclaurin series onto this bignum core.  With the
 * `-l`/`--mathlib` flag the default scale becomes 20, matching GNU bc.
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
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
#include <limits.h>
#include <ctype.h>
#include <math.h>

#include "loadables.h"

/* ------------------------------------------------------------------ *
 * Number representation                                               *
 *                                                                     *
 * A bc_num is a signed decimal with arbitrary-length digit string.    *
 * digits[0..len-1] are ASCII '0'..'9'.  The decimal point sits after  *
 * (len - scale) integer digits.  E.g. "12345" with scale=2 → 123.45.  *
 *                                                                     *
 * bc_num's are always normalized: no leading or trailing zeros except  *
 * a single '0' for zero (len=1, scale=0, sign=0).                     *
 * ------------------------------------------------------------------ */

typedef struct {
    int  sign;        /* 0 = non-negative, 1 = negative */
    char *digits;     /* malloc'd, NUL-terminated, '0'..'9' */
    int  len;         /* strlen(digits) */
    int  scale;       /* fractional digits (0..len) */
} bc_num;

static bc_num _bc_zero;
static bc_num _bc_one;

/* Forward declarations */
static double bc_to_double (const bc_num *n);
static bc_num bc_parse_number (const char **s, int ibase);
static void bc_fix_scale (bc_num *n, int scale);

/* ---- allocation / free ---- */

static bc_num
bc_alloc (int cap)
{
    bc_num n;
    n.sign = 0;
    n.digits = malloc (cap + 1);
    if (!n.digits) { n.len = 0; n.scale = 0; return n; }
    memset (n.digits, '0', cap);
    n.digits[cap] = '\0';
    n.len = 0;
    n.scale = 0;
    return n;
}

static void
bc_free (bc_num *n)
{
    if (n->digits) { free (n->digits); n->digits = NULL; }
    n->len = 0;
    n->scale = 0;
}

static bc_num
bc_dup (const bc_num *src)
{
    bc_num n;
    n.sign = src->sign;
    n.len = src->len;
    n.scale = src->scale;
    n.digits = strdup (src->digits ? src->digits : "0");
    if (!n.digits) { n.len = 0; n.scale = 0; n.sign = 0; }
    return n;
}

static bc_num
bc_from_int (long long v)
{
    bc_num n;
    if (v < 0) { n.sign = 1; v = -v; } else n.sign = 0;
    char buf[64];
    int l = snprintf (buf, sizeof buf, "%lld", v);
    n.digits = strdup (buf);
    n.len = l;
    n.scale = 0;
    if (!n.digits) { n.len = 0; return n; }
    return n;
}

/* Read an integer from the digit string (no sign handling). */
static long long
bc_to_ll (const bc_num *n)
{
    long long v = 0;
    for (int i = 0; i < n->len && i < 18; i++) {
        v = v * 10 + (n->digits[i] - '0');
    }
    return v;
}

/* ---- normalisation ---- */

/* Remove leading zeros from the integer part. */
static void
bc_strip_leading (bc_num *n)
{
    int z = 0;
    int intpart = n->len - n->scale;
    while (z < intpart - 1 && n->digits[z] == '0') z++;
    if (z > 0) {
        memmove (n->digits, n->digits + z, n->len - z);
        n->len -= z;
        n->digits[n->len] = '\0';
    }
}

/* Remove trailing zeros from the fractional part. */
static void
bc_strip_trailing (bc_num *n)
{
    while (n->scale > 0 && n->digits[n->len - 1] == '0') {
        n->len--;
        n->scale--;
        n->digits[n->len] = '\0';
    }
}

static void
bc_normalize (bc_num *n)
{
    if (n->len == 0) {
        free (n->digits);
        n->digits = strdup ("0");
        n->len = 1;
        n->scale = 0;
        n->sign = 0;
        return;
    }
    bc_strip_leading (n);
    bc_strip_trailing (n);
    /* check for zero */
    if (n->len == 1 && n->digits[0] == '0') {
        n->sign = 0;
        n->scale = 0;
    }
    if (n->len == 0) {
        free (n->digits);
        n->digits = strdup ("0");
        n->len = 1;
        n->scale = 0;
        n->sign = 0;
    }
}

/* Truncate (toward zero) to at most 'scale' fractional digits.  Handles the
   case where 'scale' is smaller than the number of significant fractional
   digits available: dropping all of them yields zero.  Without this, a tiny
   product/quotient could keep a scale larger than its length, leaving a
   malformed number that bc_is_zero never recognises (series loops hang). */
static void
bc_truncate_to_scale (bc_num *n, int scale)
{
    if (scale < 0) scale = 0;
    if (n->scale <= scale) return;
    int drop = n->scale - scale;
    if (drop >= n->len) {
        /* every stored digit is below the new precision → value is 0 */
        free (n->digits);
        n->digits = strdup ("0");
        n->len = 1;
        n->scale = 0;
        n->sign = 0;
        return;
    }
    n->len -= drop;
    n->scale = scale;
    n->digits[n->len] = '\0';
}

static int
bc_is_zero (const bc_num *n)
{
    for (int i = 0; i < n->len; i++) if (n->digits[i] != '0') return 0;
    return 1;
}

/* ---- comparison ---- */

/* Compare absolute values.  Returns -1 (a<b), 0 (a==b), 1 (a>b). */
static int
bc_abs_cmp (const bc_num *a, const bc_num *b)
{
    /* Zero is stored as "0" (one integer digit), which would otherwise be
       counted as having more integer digits than a pure fraction like .5.
       Handle it explicitly so |.5| > |0| compares correctly. */
    int az = bc_is_zero (a);
    int bz = bc_is_zero (b);
    if (az || bz) {
        if (az && bz) return 0;
        return az ? -1 : 1;
    }

    int a_int = a->len - a->scale;
    int b_int = b->len - b->scale;
    if (a_int != b_int) return a_int > b_int ? 1 : -1;

    /* same number of integer digits — compare digit by digit */
    int max_len = a->len > b->len ? a->len : b->len;
    for (int i = 0; i < max_len; i++) {
        char da = (i < a->len) ? a->digits[i] : '0';
        char db = (i < b->len) ? b->digits[i] : '0';
        if (da != db) return da > db ? 1 : -1;
    }
    return 0;
}

static int
bc_cmp (const bc_num *a, const bc_num *b)
{
    if (a->sign != b->sign) return a->sign ? -1 : 1;
    int r = bc_abs_cmp (a, b);
    return a->sign ? -r : r;
}

/* ---- addition (unsigned) ---- */

static bc_num
bc_add_unsigned (const bc_num *a, const bc_num *b, int scale)
{
    /* work from the rightmost digit */
    int max_scale = a->scale > b->scale ? a->scale : b->scale;
    if (scale > max_scale) max_scale = scale;
    int a_int = a->len - a->scale;
    int b_int = b->len - b->scale;
    int max_int = a_int > b_int ? a_int : b_int;
    int total = max_int + max_scale;
    int cap = total + 2;  /* +1 for possible carry, +1 for NUL */

    bc_num r = bc_alloc (cap);
    r.len = total;
    r.scale = max_scale;

    int carry = 0;
    for (int i = total - 1; i >= 0; i--) {
        int pos_from_right = total - 1 - i;
        int da = 0, db = 0;
        /* Use simpler indexing: position from right of each number */
        int a_idx = a->len - 1 - pos_from_right + (max_scale - a->scale);
        int b_idx = b->len - 1 - pos_from_right + (max_scale - b->scale);
        if (a_idx >= 0 && a_idx < a->len) da = a->digits[a_idx] - '0';
        if (b_idx >= 0 && b_idx < b->len) db = b->digits[b_idx] - '0';
        int sum = da + db + carry;
        r.digits[i] = '0' + (sum % 10);
        carry = sum / 10;
    }

    /* if carry remains, shift right */
    if (carry) {
        memmove (r.digits + 1, r.digits, total);
        r.digits[0] = '1';
        r.len = total + 1;
        r.digits[r.len] = '\0';
        /* scale unchanged */
    } else {
        r.digits[total] = '\0';
    }
    bc_normalize (&r);
    return r;
}

/* ---- subtraction (unsigned, a >= b) ---- */

static bc_num
bc_sub_unsigned (const bc_num *a, const bc_num *b, int scale)
{
    int max_scale = a->scale > b->scale ? a->scale : b->scale;
    if (scale > max_scale) max_scale = scale;
    int a_int = a->len - a->scale;
    int max_int = a_int;  /* a >= b so a's integer part is largest */
    int total = max_int + max_scale;

    bc_num r = bc_alloc (total + 1);
    r.len = total;
    r.scale = max_scale;

    int borrow = 0;
    for (int i = total - 1; i >= 0; i--) {
        int pos_from_right = total - 1 - i;
        int a_idx = a->len - 1 - pos_from_right + (max_scale - a->scale);
        int b_idx = b->len - 1 - pos_from_right + (max_scale - b->scale);
        int da = (a_idx >= 0 && a_idx < a->len) ? a->digits[a_idx] - '0' : 0;
        int db = (b_idx >= 0 && b_idx < b->len) ? b->digits[b_idx] - '0' : 0;
        int diff = da - db - borrow;
        if (diff < 0) { diff += 10; borrow = 1; }
        else borrow = 0;
        r.digits[i] = '0' + diff;
    }
    r.digits[total] = '\0';
    bc_normalize (&r);
    return r;
}

static bc_num
bc_add (const bc_num *a, const bc_num *b, int scale)
{
    bc_num r;
    if (a->sign == b->sign) {
        r = bc_add_unsigned (a, b, scale);
        r.sign = a->sign;
    } else {
        int cmp = bc_abs_cmp (a, b);
        if (cmp >= 0) {
            r = bc_sub_unsigned (a, b, scale);
            r.sign = a->sign;
        } else {
            r = bc_sub_unsigned (b, a, scale);
            r.sign = b->sign;
        }
    }
    return r;
}

static bc_num
bc_sub (const bc_num *a, const bc_num *b, int scale)
{
    bc_num r;
    if (a->sign != b->sign) {
        r = bc_add_unsigned (a, b, scale);
        r.sign = a->sign;
    } else {
        int cmp = bc_abs_cmp (a, b);
        if (cmp >= 0) {
            r = bc_sub_unsigned (a, b, scale);
            r.sign = a->sign;
        } else {
            r = bc_sub_unsigned (b, a, scale);
            r.sign = !a->sign;
        }
    }
    return r;
}

/* ---- multiplication ---- */

static bc_num
bc_mul (const bc_num *a, const bc_num *b, int scale)
{
    if (bc_is_zero (a) || bc_is_zero (b)) {
        /* a zero product is the bare "0" (scale 0), like GNU bc */
        return bc_dup (&_bc_zero);
    }

    int result_scale = a->scale + b->scale;
    int total = a->len + b->len;

    /* temp array for digit-at-a-time multiplication */
    int *prod = calloc (total, sizeof (int));
    if (!prod) { bc_num r = bc_dup (&_bc_zero); return r; }

    for (int i = a->len - 1; i >= 0; i--) {
        int carry = 0;
        int da = a->digits[i] - '0';
        for (int j = b->len - 1; j >= 0; j--) {
            int db = b->digits[j] - '0';
            int p = da * db + prod[i + j + 1] + carry;
            prod[i + j + 1] = p % 10;
            carry = p / 10;
        }
        prod[i] += carry;
    }

    /* convert to digit string.  Strip integer-position leading zeros, but
       never strip so many that fewer than result_scale digits remain — the
       representation requires len >= scale (the decimal point must land
       within the digit string), otherwise a small product becomes malformed
       (scale > len) and bc_is_zero can never recognise it. */
    int start = 0;
    int min_keep = result_scale + 1;   /* >=1 integer digit + the fraction */
    if (min_keep > total) min_keep = total;
    while (start < total - min_keep && prod[start] == 0) start++;
    int rlen = total - start;

    bc_num r = bc_alloc (rlen + 1);
    for (int i = 0; i < rlen; i++)
        r.digits[i] = '0' + prod[start + i];
    r.digits[rlen] = '\0';
    r.len = rlen;
    r.scale = result_scale;
    r.sign = (a->sign != b->sign) ? 1 : 0;

    free (prod);

    /* enforce target scale */
    while (r.scale < scale) {
        /* pad with trailing zero and append '0' */
        r.digits = realloc (r.digits, r.len + 2);
        r.digits[r.len] = '0';
        r.len++;
        r.scale++;
        r.digits[r.len] = '\0';
    }
    if (r.scale > scale && scale >= 0)
        bc_truncate_to_scale (&r, scale);

    bc_normalize (&r);
    return r;
}

/* ---- division ---- */

/* Long division: a / b, producing 'scale' fractional digits in quotient. */
static bc_num
bc_div_internal (const bc_num *a, const bc_num *b, int scale)
{
    if (bc_is_zero (b)) {
        /* return zero on division by zero (caller should warn) */
        return bc_dup (&_bc_zero);
    }
    if (bc_is_zero (a)) {
        /* GNU prints a zero result as bare "0"; keep scale 0 so the single
           "0" digit stays consistent with len (no negative integer part). */
        bc_num r = bc_dup (&_bc_zero);
        r.scale = 0;
        return r;
    }
    if (scale < 0) scale = 0;

    /* Build an extended dividend: a's digits + (scale + b->scale) zeros.
       Adding b->scale extra zeros compensates for the divisor's fractional
       digits so the integer long division yields a correctly-scaled result. */
    int extra = scale + b->scale;
    int ext_len = a->len + extra;
    char *dividend = malloc (ext_len + 1);
    if (!dividend) return bc_dup (&_bc_zero);
    memcpy (dividend, a->digits, a->len);
    memset (dividend + a->len, '0', extra);
    dividend[ext_len] = '\0';

    /* b's digits as a string for comparison */
    /* We'll work with a running remainder */
    char *rem = malloc (ext_len + 2);
    if (!rem) { free (dividend); return bc_dup (&_bc_zero); }
    rem[0] = '\0';

    bc_num result = bc_alloc (ext_len + 1);
    int rpos = 0;

    /* Long division: process dividend digit by digit */
    int rem_len = 0;
    for (int i = 0; i < ext_len; i++) {
        /* bring down next digit */
        rem[rem_len] = dividend[i];
        rem_len++;
        rem[rem_len] = '\0';

        /* strip leading zeros in remainder */
        int rz = 0;
        while (rz < rem_len - 1 && rem[rz] == '0') rz++;
        if (rz > 0) { memmove (rem, rem + rz, rem_len - rz); rem_len -= rz; rem[rem_len] = '\0'; }

        /* how many times does divisor go into remainder? */
        int q = 0;
        while (1) {
            /* Compare rem (length rem_len) with b->digits (length b->len) */
            if (rem_len < b->len) break;
            if (rem_len == b->len) {
                int gt = 0, lt = 0;
                for (int k = 0; k < rem_len; k++) {
                    if (rem[k] > b->digits[k]) { gt = 1; break; }
                    if (rem[k] < b->digits[k]) { lt = 1; break; }
                }
                if (!gt && !lt) {
                    /* exact match: one more subtraction, then done */
                    q++;
                    rem[0] = '0'; rem[1] = '\0'; rem_len = 1;
                    break;
                }
                if (lt) break;
            }
            /* subtract b from rem */
            int borrow = 0;
            for (int k = b->len - 1; k >= 0; k--) {
                int rk = rem_len - (b->len - k);
                int dr = (rk >= 0) ? rem[rk] - '0' : 0;
                int db = b->digits[k] - '0';
                int diff = dr - db - borrow;
                if (diff < 0) { diff += 10; borrow = 1; }
                else borrow = 0;
                if (rk >= 0) rem[rk] = '0' + diff;
            }
            /* handle borrow on the most significant digit */
            if (borrow) {
                for (int k = rem_len - b->len - 1; k >= 0; k--) {
                    if (rem[k] > '0') { rem[k]--; break; }
                    rem[k] = '9';
                }
            }
            /* re-strip leading zeros */
            rz = 0;
            while (rz < rem_len - 1 && rem[rz] == '0') rz++;
            if (rz > 0) { memmove (rem, rem + rz, rem_len - rz); rem_len -= rz; rem[rem_len] = '\0'; }
            q++;
        }
        if (rpos < ext_len) {
            result.digits[rpos++] = '0' + q;
        }
    }
    result.digits[rpos] = '\0';
    result.len = rpos;
    /* decimal point: original dividend_scale + scale fractional digits produced,
       then subtract a->scale because the decimal point in the result is offset */
    result.scale = a->scale + scale;

    /* truncate to requested scale */
    if (result.scale > scale)
        bc_truncate_to_scale (&result, scale);

    free (dividend);
    free (rem);
    bc_normalize (&result);
    return result;
}

static bc_num
bc_div (const bc_num *a, const bc_num *b, int scale)
{
    bc_num r = bc_div_internal (a, b, scale);
    r.sign = (a->sign != b->sign) ? 1 : 0;
    if (bc_is_zero (&r)) r.sign = 0;
    bc_fix_scale (&r, scale);
    return r;
}

static bc_num
bc_mod (const bc_num *a, const bc_num *b)
{
    if (bc_is_zero (b)) return bc_dup (&_bc_zero);
    bc_num q = bc_div_internal (a, b, 0);  /* integer quotient */
    q.sign = 0;
    bc_num prod = bc_mul (&q, b, 0);
    prod.sign = b->sign;
    bc_num r = bc_sub (a, &prod, 0);
    bc_free (&q);
    bc_free (&prod);
    if (r.sign) {
        /* ensure positive remainder */
        bc_num b_abs = bc_dup (b);
        b_abs.sign = 0;
        bc_num tmp = bc_add (&r, &b_abs, 0);
        bc_free (&r);
        r = tmp;
        bc_free (&b_abs);
    }
    return r;
}

/* ---- exponentiation (integer exponent) ---- */

static bc_num
bc_pow (const bc_num *base, const bc_num *exp, int scale)
{
    if (bc_is_zero (exp)) return bc_dup (&_bc_one);
    if (bc_is_zero (base)) return bc_dup (&_bc_zero);
    if (exp->sign) return bc_dup (&_bc_zero);  /* negative exponent → 0 */

    long long e = bc_to_ll (exp);
    if (e <= 0) return bc_dup (&_bc_one);
    if (e == 1) { bc_num r = bc_dup (base); return r; }

    bc_num result = bc_dup (&_bc_one);
    bc_num b = bc_dup (base);
    int pow_scale = scale > base->scale * (int)e ? scale : base->scale * (int)e;

    while (e > 0) {
        if (e & 1) {
            bc_num tmp = bc_mul (&result, &b, pow_scale);
            bc_free (&result);
            result = tmp;
        }
        e >>= 1;
        if (e > 0) {
            bc_num tmp = bc_mul (&b, &b, pow_scale);
            bc_free (&b);
            b = tmp;
        }
    }
    bc_free (&b);
    bc_normalize (&result);
    return result;
}

/* ---- sqrt (Newton's method) ---- */

static bc_num
bc_sqrt (const bc_num *n, int scale)
{
    if (n->sign) return bc_dup (&_bc_zero);  /* domain error */
    if (bc_is_zero (n)) return bc_dup (&_bc_zero);  /* sqrt(0) prints as "0" */

    /* initial guess: use double sqrt for seed */
    double d = sqrt (bc_to_double (n));
    char buf[64];
    snprintf (buf, sizeof buf, "%.15f", d);
    bc_num x = bc_dup (&_bc_zero);
    free (x.digits);
    x.digits = strdup (buf);
    x.len = strlen (buf);
    /* find decimal point */
    char *dot = strchr (buf, '.');
    x.scale = dot ? (x.len - (dot - buf) - 1) : 0;
    if (dot) {
        memmove (x.digits + (dot - buf), x.digits + (dot - buf) + 1,
                 x.scale + 1);
        x.len--;
    }
    x.sign = 0;
    bc_normalize (&x);

    /* Newton iteration: x = (x + n/x) / 2 */
    bc_num two = bc_from_int (2);
    int iter_scale = scale + 5;
    for (int i = 0; i < 20; i++) {
        bc_num q = bc_div (n, &x, iter_scale);
        bc_num s = bc_add (&x, &q, iter_scale);
        bc_num new_x = bc_div (&s, &two, iter_scale);
        bc_free (&q);
        bc_free (&s);

        /* check convergence */
        bc_num diff = bc_sub (&new_x, &x, iter_scale);
        if (diff.sign) diff.sign = 0;
        int converged = (diff.len == 1 && diff.digits[0] == '0');
        bc_free (&diff);
        bc_free (&x);
        x = new_x;
        if (converged) break;
    }
    bc_free (&two);

    /* truncate to requested scale */
    if (x.scale > scale)
        bc_truncate_to_scale (&x, scale);
    bc_normalize (&x);
    /* GNU sqrt carries the global scale (3.0000000000, not 3). */
    bc_fix_scale (&x, scale);
    return x;
}

/* Convert bc_num to double (best-effort, for transcendental functions). */
static double
bc_to_double (const bc_num *n)
{
    double v = 0.0;
    for (int i = 0; i < n->len; i++)
        v = v * 10.0 + (n->digits[i] - '0');
    for (int i = 0; i < n->scale; i++)
        v /= 10.0;
    if (n->sign) v = -v;
    return v;
}

/* Ensure a result has at least 'scale' fractional digits (pad with zeros). */
static void
bc_pad_scale (bc_num *n, int scale)
{
    if (n->scale >= scale) return;
    int extra = scale - n->scale;
    int new_len = n->len + extra;
    n->digits = realloc (n->digits, new_len + 1);
    if (!n->digits) return;
    memset (n->digits + n->len, '0', extra);
    n->len = new_len;
    n->scale = scale;
    n->digits[new_len] = '\0';
}

/* Fix a freshly-computed result to carry exactly 'scale' fractional digits,
   the way GNU bc div/sqrt/library results do.  bc_normalize strips trailing
   zeros for clean arithmetic; this restores them so e.g. 1/2 at scale 10
   prints ".5000000000" and 6/2 prints "3.0000000000".  A zero value is left
   as the bare "0" (GNU prints a zero value as "0" regardless of scale). */
static void
bc_fix_scale (bc_num *n, int scale)
{
    if (scale <= 0) return;
    if (bc_is_zero (n)) return;
    bc_pad_scale (n, scale);
}

/* ------------------------------------------------------------------ *
 * Standard math library (s/c/a/l/e/j), ported from GNU bc libmath.b.  *
 *                                                                     *
 * Each routine mirrors the corresponding bc definition operation for  *
 * operation, using the same Taylor/Maclaurin series, guard-digit      *
 * scale formulas, and final `return (v/1)` truncation, so the digit   *
 * strings match GNU bc byte-for-byte at a given scale.  Numbers are   *
 * always base 10 here (bc_parse_number already decoded the input      *
 * base), so libmath's ibase!=A re-entrancy guard is unnecessary.      *
 * ------------------------------------------------------------------ */

/* Parse a decimal literal constant into a bc_num. */
static bc_num
bc_const (const char *lit)
{
    const char *s = lit;
    return bc_parse_number (&s, 10);
}

/* v / 1 at the given scale: truncate v to 'scale' fractional digits,
   carrying that scale on a non-zero value (GNU's `return (v/1)`). */
static bc_num
bc_trunc (const bc_num *v, int scale)
{
    bc_num one = bc_from_int (1);
    bc_num r = bc_div (v, &one, scale);
    bc_free (&one);
    return r;
}

/* Arctangent.  libmath.b define a(x). */
static bc_num
bc_func_a (const bc_num *xin, int scale)
{
    int m = 1;
    bc_num x = bc_dup (xin);
    if (x.sign) { m = -1; x.sign = 0; }

    bc_num one = bc_from_int (1);

    /* Fast path: a(1) and a(.2) have hard-coded constants in GNU bc. */
    if (bc_cmp (&x, &one) == 0) {
        const char *k;
        if (scale <= 25)
            k = ".7853981633974483096156608";
        else if (scale <= 40)
            k = ".7853981633974483096156608458198757210492";
        else if (scale <= 60)
            k = ".785398163397448309615660845819875721049292349843776455243736";
        else
            k = NULL;
        if (k) {
            bc_num c = bc_const (k);
            bc_num r = bc_trunc (&c, scale);
            if (m < 0) r.sign = !r.sign;
            if (bc_is_zero (&r)) r.sign = 0;
            bc_free (&c); bc_free (&x); bc_free (&one);
            return r;
        }
    }

    bc_num pt2 = bc_const (".2");
    if (bc_cmp (&x, &pt2) == 0 && scale <= 60) {
        const char *k;
        if (scale <= 25)
            k = ".1973955598498807583700497";
        else if (scale <= 40)
            k = ".1973955598498807583700497651947902934475";
        else
            k = ".197395559849880758370049765194790293447585103787852101517688";
        bc_num c = bc_const (k);
        bc_num r = bc_trunc (&c, scale);
        if (m < 0) r.sign = !r.sign;
        if (bc_is_zero (&r)) r.sign = 0;
        bc_free (&c); bc_free (&x); bc_free (&one); bc_free (&pt2);
        return r;
    }

    int z = scale;

    /* atan of a known number when x > .2. */
    bc_num a = bc_dup (&_bc_zero);
    long long f = 0;
    if (bc_cmp (&x, &pt2) > 0) {
        bc_num av = bc_func_a (&pt2, z + 5);
        bc_free (&a);
        a = av;
    }

    /* Precondition x to <= .2.  atan(x) = atan(.2)+atan((x-.2)/(1+x*.2)). */
    int wscale = z + 3;
    while (bc_cmp (&x, &pt2) > 0) {
        f += 1;
        bc_num num = bc_sub (&x, &pt2, wscale);
        bc_num xp2 = bc_mul (&x, &pt2, wscale);
        bc_num den = bc_add (&one, &xp2, wscale);
        bc_num nx = bc_div (&num, &den, wscale);
        bc_free (&num); bc_free (&xp2); bc_free (&den);
        bc_free (&x);
        x = nx;
    }

    /* Series: atan(x) = x - x^3/3 + x^5/5 - ...  v=n=x; s=-x*x. */
    bc_num v = bc_dup (&x);
    bc_num n = bc_dup (&x);
    bc_num s = bc_mul (&x, &x, wscale);
    s.sign = !s.sign;
    if (bc_is_zero (&s)) s.sign = 0;

    for (long long i = 3; ; i += 2) {
        bc_num nn = bc_mul (&n, &s, wscale);
        bc_free (&n); n = nn;
        bc_num iden = bc_from_int (i);
        bc_num e = bc_div (&n, &iden, wscale);
        bc_free (&iden);
        if (bc_is_zero (&e)) { bc_free (&e); break; }
        bc_num nv = bc_add (&v, &e, wscale);
        bc_free (&v); v = nv;
        bc_free (&e);
    }

    /* return ((f*a+v)/m) */
    bc_num fa;
    if (f) {
        bc_num fn = bc_from_int (f);
        fa = bc_mul (&fn, &a, wscale);
        bc_free (&fn);
    } else {
        fa = bc_dup (&_bc_zero);
    }
    bc_num sum = bc_add (&fa, &v, wscale);
    bc_num r = bc_trunc (&sum, z);
    if (m < 0) r.sign = !r.sign;
    if (bc_is_zero (&r)) r.sign = 0;

    bc_free (&fa); bc_free (&sum); bc_free (&v); bc_free (&n);
    bc_free (&s); bc_free (&a); bc_free (&x); bc_free (&one); bc_free (&pt2);
    return r;
}

/* e^x.  libmath.b define e(x). */
static bc_num
bc_func_e (const bc_num *xin, int scale)
{
    int m = 0;
    bc_num x = bc_dup (xin);
    if (x.sign) { m = 1; x.sign = 0; }

    int z = scale;
    /* n = 6 + z + .44*x  (integer working scale). */
    double xd = bc_to_double (&x);
    int n = (int) (6 + z + 0.44 * xd);
    if (n < z + 6) n = z + 6;

    bc_num one = bc_from_int (1);
    bc_num two = bc_from_int (2);

    /* while (x > 1) { f++; x/=2; }  — halve until x <= 1. */
    long long f = 0;
    int hscale = x.scale + 1;
    while (bc_cmp (&x, &one) > 0) {
        f += 1;
        hscale += 1;
        bc_num nx = bc_div (&x, &two, hscale);
        bc_free (&x);
        x = nx;
    }

    /* v = 1 + x; a = x; d = 1; series at scale n. */
    bc_num v = bc_add (&one, &x, n);
    bc_num a = bc_dup (&x);
    bc_num d = bc_from_int (1);

    for (long long i = 2; ; i++) {
        bc_num na = bc_mul (&a, &x, n);
        bc_free (&a); a = na;
        bc_num id = bc_from_int (i);
        bc_num nd = bc_mul (&d, &id, n);
        bc_free (&d); d = nd; bc_free (&id);
        bc_num e = bc_div (&a, &d, n);
        if (bc_is_zero (&e)) { bc_free (&e); break; }
        bc_num nv = bc_add (&v, &e, n);
        bc_free (&v); v = nv;
        bc_free (&e);
    }

    /* while (f--) v = v*v; */
    while (f-- > 0) {
        bc_num nv = bc_mul (&v, &v, n);
        bc_free (&v); v = nv;
    }

    bc_num r;
    if (m) {
        bc_num inv = bc_div (&one, &v, z);
        r = inv;
    } else {
        r = bc_trunc (&v, z);
    }
    bc_free (&v); bc_free (&a); bc_free (&d);
    bc_free (&one); bc_free (&two); bc_free (&x);
    return r;
}

/* Natural log.  libmath.b define l(x). */
static bc_num
bc_func_l (const bc_num *xin, int scale)
{
    int z = scale;
    bc_num x = bc_dup (xin);

    bc_num one = bc_from_int (1);
    bc_num two = bc_from_int (2);
    bc_num half = bc_const (".5");

    /* Special case: x <= 0 → (1 - 10^scale)/1. */
    if (x.sign || bc_is_zero (&x)) {
        bc_num ten = bc_from_int (10);
        bc_num sc = bc_from_int (z);
        bc_num p = bc_pow (&ten, &sc, 0);
        bc_num r = bc_sub (&one, &p, 0);
        bc_free (&ten); bc_free (&sc); bc_free (&p);
        bc_free (&x); bc_free (&one); bc_free (&two); bc_free (&half);
        return r;
    }

    int wscale = 6 + z;
    long long f = 2;
    /* while (x >= 2) { f*=2; x=sqrt(x); } */
    while (bc_cmp (&x, &two) >= 0) {
        f *= 2;
        bc_num sx = bc_sqrt (&x, wscale);
        bc_free (&x); x = sx;
    }
    /* while (x <= .5) { f*=2; x=sqrt(x); } */
    while (bc_cmp (&x, &half) <= 0) {
        f *= 2;
        bc_num sx = bc_sqrt (&x, wscale);
        bc_free (&x); x = sx;
    }

    /* v = n = (x-1)/(x+1); m = n*n. */
    bc_num xm1 = bc_sub (&x, &one, wscale);
    bc_num xp1 = bc_add (&x, &one, wscale);
    bc_num n = bc_div (&xm1, &xp1, wscale);
    bc_free (&xm1); bc_free (&xp1);
    bc_num v = bc_dup (&n);
    bc_num mm = bc_mul (&n, &n, wscale);

    for (long long i = 3; ; i += 2) {
        bc_num nn = bc_mul (&n, &mm, wscale);
        bc_free (&n); n = nn;
        bc_num id = bc_from_int (i);
        bc_num e = bc_div (&n, &id, wscale);
        bc_free (&id);
        if (bc_is_zero (&e)) { bc_free (&e); break; }
        bc_num nv = bc_add (&v, &e, wscale);
        bc_free (&v); v = nv;
        bc_free (&e);
    }

    /* v = f*v; return (v/1). */
    bc_num fn = bc_from_int (f);
    bc_num fv = bc_mul (&fn, &v, wscale);
    bc_free (&fn);
    bc_num r = bc_trunc (&fv, z);

    bc_free (&fv); bc_free (&v); bc_free (&n); bc_free (&mm);
    bc_free (&x); bc_free (&one); bc_free (&two); bc_free (&half);
    return r;
}

/* Sine.  libmath.b define s(x).  Needs a() for argument reduction. */
static bc_num
bc_func_s (const bc_num *xin, int scale)
{
    int z = scale;
    bc_num x = bc_dup (xin);

    bc_num one = bc_from_int (1);
    bc_num four = bc_from_int (4);

    /* scale = 1.1*z + 2; v = a(1)  (pi/4 to that scale). */
    int pscale = (int) (1.1 * z) + 2;
    bc_num v0 = bc_func_a (&one, pscale);   /* pi/4 */

    int m = 0;
    if (x.sign) { m = 1; x.sign = 0; }

    /* scale = 0; n = (x/v + 2)/4; x = x - 4*n*v; if (n%2) x = -x. */
    bc_num xv = bc_div (&x, &v0, 0);
    bc_num two = bc_from_int (2);
    bc_num xv2 = bc_add (&xv, &two, 0);
    bc_num n = bc_div (&xv2, &four, 0);     /* integer */
    bc_free (&xv); bc_free (&xv2);

    bc_num fourn = bc_mul (&four, &n, pscale);
    bc_num fournv = bc_mul (&fourn, &v0, pscale);
    bc_num nx = bc_sub (&x, &fournv, pscale);
    bc_free (&fourn); bc_free (&fournv);
    bc_free (&x); x = nx;

    /* if (n%2) x = -x */
    bc_num nmod = bc_mod (&n, &two);
    if (!bc_is_zero (&nmod)) { x.sign = !x.sign; if (bc_is_zero (&x)) x.sign = 0; }
    bc_free (&nmod);

    /* scale = z+2; v = e = x; s = -x*x; */
    int wscale = z + 2;
    bc_num v = bc_dup (&x);
    bc_num e = bc_dup (&x);
    bc_num s = bc_mul (&x, &x, wscale);
    s.sign = !s.sign;
    if (bc_is_zero (&s)) s.sign = 0;

    for (long long i = 3; ; i += 2) {
        /* e *= s/(i*(i-1)) */
        bc_num idn = bc_from_int (i * (i - 1));
        bc_num q = bc_div (&s, &idn, wscale);
        bc_free (&idn);
        bc_num ne = bc_mul (&e, &q, wscale);
        bc_free (&q);
        bc_free (&e); e = ne;
        if (bc_is_zero (&e)) break;
        bc_num nv = bc_add (&v, &e, wscale);
        bc_free (&v); v = nv;
    }

    bc_num r = bc_trunc (&v, z);
    if (m) { r.sign = !r.sign; if (bc_is_zero (&r)) r.sign = 0; }

    bc_free (&v); bc_free (&e); bc_free (&s); bc_free (&n); bc_free (&v0);
    bc_free (&x); bc_free (&one); bc_free (&two); bc_free (&four);
    return r;
}

/* Cosine: cos(x) = sin(x + pi/2).  libmath.b define c(x). */
static bc_num
bc_func_c (const bc_num *xin, int scale)
{
    int z = scale;
    int wscale = (int) (scale * 1.2);
    if (wscale < scale) wscale = scale;

    bc_num one = bc_from_int (1);
    bc_num two = bc_from_int (2);
    /* a(1)*2 = pi/2 at the working scale. */
    bc_num a1 = bc_func_a (&one, wscale);
    bc_num pi2 = bc_mul (&a1, &two, wscale);
    bc_num arg = bc_add (xin, &pi2, wscale);
    bc_num sv = bc_func_s (&arg, wscale);
    bc_num r = bc_trunc (&sv, z);

    bc_free (&a1); bc_free (&pi2); bc_free (&arg); bc_free (&sv);
    bc_free (&one); bc_free (&two);
    return r;
}

/* Bessel function of integer order n.  libmath.b define j(n,x). */
static bc_num
bc_func_j (const bc_num *nin, const bc_num *xin, int scale)
{
    int z = scale;
    bc_num x = bc_dup (xin);

    /* n = n/1 (integer); handle negative n. */
    bc_num one = bc_from_int (1);
    bc_num nint = bc_div (nin, &one, 0);
    int m = 0;
    long long nn = bc_to_ll (&nint);
    if (nint.sign) {
        nn = -nn;   /* magnitude */
        if (nn % 2 == 1) m = 1;
    }

    /* f = n!  ; f = x^n / 2^n / f at scale 1.5*z. */
    bc_num ffact = bc_from_int (1);
    for (long long i = 2; i <= nn; i++) {
        bc_num ii = bc_from_int (i);
        bc_num nf = bc_mul (&ffact, &ii, 0);
        bc_free (&ffact); ffact = nf; bc_free (&ii);
    }
    int w1 = (int) (1.5 * z);
    bc_num two = bc_from_int (2);
    bc_num nexp = bc_from_int (nn);
    bc_num xn = bc_pow (&x, &nexp, w1);
    bc_num twon = bc_pow (&two, &nexp, w1);
    bc_num t1 = bc_div (&xn, &twon, w1);
    bc_num f = bc_div (&t1, &ffact, w1);
    bc_free (&xn); bc_free (&twon); bc_free (&t1); bc_free (&nexp);

    /* v = e = 1; s = -x*x/4; scale = 1.5*z + length(f) - scale(f). */
    bc_num v = bc_from_int (1);
    bc_num e = bc_from_int (1);
    bc_num xx = bc_mul (&x, &x, w1);
    bc_num four = bc_from_int (4);
    bc_num s = bc_div (&xx, &four, w1);
    s.sign = !s.sign;
    if (bc_is_zero (&s)) s.sign = 0;
    bc_free (&xx);

    int wscale = (int) (1.5 * z) + (f.len - f.scale) - f.scale;
    if (wscale < z) wscale = z;

    for (long long i = 1; ; i++) {
        /* e = e * s / i / (n+i) */
        bc_num es = bc_mul (&e, &s, wscale);
        bc_num ii = bc_from_int (i);
        bc_num e1 = bc_div (&es, &ii, wscale);
        bc_num ni = bc_from_int (nn + i);
        bc_num e2 = bc_div (&e1, &ni, wscale);
        bc_free (&es); bc_free (&ii); bc_free (&e1); bc_free (&ni);
        bc_free (&e); e = e2;
        if (bc_is_zero (&e)) break;
        bc_num nv = bc_add (&v, &e, wscale);
        bc_free (&v); v = nv;
    }

    bc_num fv = bc_mul (&f, &v, wscale);
    bc_num r = bc_trunc (&fv, z);
    if (m) { r.sign = !r.sign; if (bc_is_zero (&r)) r.sign = 0; }

    bc_free (&fv); bc_free (&v); bc_free (&e); bc_free (&s); bc_free (&f);
    bc_free (&ffact); bc_free (&nint); bc_free (&x);
    bc_free (&one); bc_free (&two); bc_free (&four);
    return r;
}

/* ---- print ---- */

static void
bc_print (const bc_num *n, int obase, int newline)
{
    (void) obase;
    if (bc_is_zero (n)) {
        putchar ('0');
        if (newline) putchar ('\n');
        return;
    }
    if (n->sign) putchar ('-');
    int intpart = n->len - n->scale;
    if (!(intpart == 1 && n->digits[0] == '0' && n->scale > 0))
        for (int i = 0; i < intpart; i++) putchar (n->digits[i]);
    if (n->scale > 0) {
        putchar ('.');
        for (int i = intpart; i < n->len; i++)
            putchar (i < 0 ? '0' : n->digits[i]);
    }
    if (newline) putchar ('\n');
}

/* ---- parsing ---- */

static int
bc_parse_digit (int c, int ibase)
{
    if (c >= '0' && c <= '9') {
        int v = c - '0';
        return v < ibase ? v : -1;
    }
    if (c >= 'A' && c <= 'F') {
        int v = c - 'A' + 10;
        return v < ibase ? v : -1;
    }
    if (c >= 'a' && c <= 'f') {
        int v = c - 'a' + 10;
        return v < ibase ? v : -1;
    }
    return -1;
}

static bc_num
bc_parse_number (const char **s, int ibase)
{
    /* skip whitespace */
    while (**s == ' ' || **s == '\t') (*s)++;

    int sign = 0;
    if (**s == '-') { sign = 1; (*s)++; }
    else if (**s == '+') { (*s)++; }

    /* collect integer digits */
    char intbuf[4096];
    int ilen = 0;
    while (ilen < (int)sizeof(intbuf) - 1 && bc_parse_digit (**s, ibase) >= 0) {
        intbuf[ilen++] = **s;
        (*s)++;
    }
    /* A leading '.' with no integer digits (e.g. ".5") is valid.  Synthesize
       a single "0" integer digit so every number keeps at least one integer
       digit (intpart >= 1); this keeps the representation consistent with the
       output of division/multiplication and lets bc_abs_cmp align fractions
       like .2 and 0.0689 correctly. */
    if (ilen == 0) {
        if (**s == '.' && bc_parse_digit ((*s)[1], ibase) >= 0) {
            intbuf[ilen++] = '0';
        } else {
            /* no digits found */
            bc_num z = bc_dup (&_bc_zero);
            return z;
        }
    }
    intbuf[ilen] = '\0';

    int scale = 0;
    char fracbuf[256];
    int flen = 0;
    if (**s == '.') {
        (*s)++;
        while (flen < (int)sizeof(fracbuf) - 1 && bc_parse_digit (**s, ibase) >= 0) {
            fracbuf[flen++] = **s;
            (*s)++;
        }
        fracbuf[flen] = '\0';
        scale = flen;
    }

    /* Convert from ibase to decimal if not decimal. For bases 2-16,
       convert the integer and fractional parts. */
    bc_num result;
    if (ibase == 10) {
        int totlen = ilen + flen;
        result = bc_alloc (totlen + 1);
        memcpy (result.digits, intbuf, ilen);
        if (flen > 0) memcpy (result.digits + ilen, fracbuf, flen);
        result.len = totlen;
        result.scale = scale;
        result.digits[totlen] = '\0';
        result.sign = sign;
        bc_normalize (&result);
        bc_pad_scale (&result, scale); /* literal scale includes trailing zeros */
        return result;
    }

    /* Convert from base ibase to decimal */
    bc_num base = bc_from_int (ibase);
    bc_num p = bc_dup (&_bc_one);
    result = bc_dup (&_bc_zero);

    /* Integer part: sum of digit * ibase^(position from right) */
    for (int i = ilen - 1; i >= 0; i--) {
        int d = bc_parse_digit (intbuf[i], ibase);
        bc_num dv = bc_from_int (d);
        bc_num term = bc_mul (&dv, &p, 0);
        bc_num sum = bc_add (&result, &term, 0);
        bc_free (&result); bc_free (&term); bc_free (&dv);
        result = sum;
        if (i > 0) {
            bc_num np = bc_mul (&p, &base, 0);
            bc_free (&p);
            p = np;
        }
    }

    /* Fractional part: sum of digit * ibase^(-position) */
    if (flen > 0) {
        bc_num frac = bc_dup (&_bc_zero);
        bc_num inv = bc_dup (&_bc_one);
        for (int i = 0; i < flen; i++) {
            bc_num di = bc_div (&inv, &base, flen + 2);
            bc_free (&inv);
            inv = di;
            int d = bc_parse_digit (fracbuf[i], ibase);
            bc_num dv = bc_from_int (d);
            bc_num term = bc_mul (&dv, &inv, flen + 2);
            bc_num sum = bc_add (&frac, &term, flen + 2);
            bc_free (&frac); bc_free (&term); bc_free (&dv);
            frac = sum;
        }
        bc_num sum = bc_add (&result, &frac, flen);
        bc_free (&result); bc_free (&frac); bc_free (&inv);
        result = sum;
    }

    bc_free (&base); bc_free (&p);
    result.sign = sign;
    bc_normalize (&result);
    return result;
}

/* ---- standard input ---------------------------------------------- *
 *
 * bc reads its statements from the standard input.  As a builtin it runs
 * inside a shell that keeps every command in one process, so the C
 * library's `stdin` stream — its buffer and its end-of-file indicator —
 * outlives the invocation that touched it.  C makes the end-of-file
 * indicator sticky, so a second `bc < file` in the same shell saw an
 * immediate end of input and printed nothing, and bytes another builtin
 * had read ahead into that shared buffer would have been taken as bc
 * input.
 *
 * Each invocation therefore reads descriptor 0 through a private buffer
 * that lives exactly as long as the call.  That is what a separate bc
 * process sees: the bytes still in the open file description, read in
 * blocks, with nothing carried over from an earlier command.
 * ------------------------------------------------------------------ */

#ifndef STDIN_FILENO
#  define STDIN_FILENO 0
#endif

typedef struct {
    int    fd;
    int    eof;         /* input is exhausted */
    int    error;       /* errno of a failed read, or 0 */
    size_t pos;
    size_t len;
    char   buf[4096];
} bc_input;

static void
bc_input_init (bc_input *in, int fd)
{
    in->fd = fd;
    in->eof = 0;
    in->error = 0;
    in->pos = 0;
    in->len = 0;
}

/* Read one line into *LINE (grown as needed), without its newline, and
   return its length.  Returns -1 at end of input, on a read error, or when
   memory runs out.  A final line with no newline is returned like any
   other; the next call then reports the end of input. */
static ssize_t
bc_input_line (bc_input *in, char **line, size_t *cap)
{
    size_t used = 0;

    for (;;) {
        if (in->pos == in->len) {
            ssize_t got;
            if (in->eof) break;
            do
                got = read (in->fd, in->buf, sizeof in->buf);
            while (got < 0 && errno == EINTR);
            if (got < 0) { in->eof = 1; in->error = errno; break; }
            if (got == 0) { in->eof = 1; break; }
            in->pos = 0;
            in->len = (size_t) got;
        }

        const char *start = in->buf + in->pos;
        size_t avail = in->len - in->pos;
        const char *nl = memchr (start, '\n', avail);
        size_t take = nl ? (size_t) (nl - start) : avail;

        if (used > (size_t) SSIZE_MAX - take) {
            in->eof = 1; in->error = EOVERFLOW; return -1;
        }
        if (used + take + 1 > *cap) {
            size_t want = used + take + 1, grown = *cap ? *cap : 128;
            while (grown < want) {
                if (grown > SIZE_MAX / 2) { grown = want; break; }
                grown *= 2;
            }
            char *bigger = realloc (*line, grown);
            if (!bigger) { in->eof = 1; in->error = ENOMEM; return -1; }
            *line = bigger;
            *cap = grown;
        }
        memcpy (*line + used, start, take);
        used += take;
        in->pos += take + (nl ? 1 : 0);
        if (nl) { (*line)[used] = '\0'; return (ssize_t) used; }
    }

    if (used == 0) return -1;
    (*line)[used] = '\0';
    return (ssize_t) used;
}

/* ---- expression evaluator (recursive descent) ---- */

/* Simple variable storage (persists across the lines of one invocation). */
typedef struct {
    char  *name;
    bc_num val;
} bc_var;

typedef struct {
    const char *s;
    int         err;
    int         scale;
    int         ibase;
    int         obase;
    int         mathlib;       /* 1 when -l/--mathlib is in effect */
    bc_num      last;
    bc_var     *vars;          /* dynamic array of named variables */
    int         nvars;
    int         capvars;
    bc_input   *in;            /* this invocation's standard input */
} bc_parser;

/* Forward declarations */
static bc_num bc_parse_expr (bc_parser *p);
static bc_num bc_parse_assign (bc_parser *p, int *was_assign);
static int bc_line_done (bc_parser *p);
static bc_num bc_call_func (bc_parser *p, const char *name, const bc_num *arg);
static bc_num bc_call_func2 (bc_parser *p, const bc_num *n, const bc_num *x);

/* ---- variable storage ---- */

/* Find the slot index for NAME, or -1. */
static int
bc_var_find (bc_parser *p, const char *name)
{
    for (int i = 0; i < p->nvars; i++)
        if (!strcmp (p->vars[i].name, name)) return i;
    return -1;
}

/* Read NAME (defaults to 0 when unset). */
static bc_num
bc_var_get (bc_parser *p, const char *name)
{
    int i = bc_var_find (p, name);
    if (i < 0) return bc_dup (&_bc_zero);
    return bc_dup (&p->vars[i].val);
}

/* Store VAL into NAME (takes a copy). */
static void
bc_var_set (bc_parser *p, const char *name, const bc_num *val)
{
    int i = bc_var_find (p, name);
    if (i >= 0) {
        bc_free (&p->vars[i].val);
        p->vars[i].val = bc_dup (val);
        return;
    }
    if (p->nvars >= p->capvars) {
        int ncap = p->capvars ? p->capvars * 2 : 8;
        bc_var *nv = realloc (p->vars, ncap * sizeof (bc_var));
        if (!nv) return;
        p->vars = nv;
        p->capvars = ncap;
    }
    p->vars[p->nvars].name = strdup (name);
    p->vars[p->nvars].val = bc_dup (val);
    if (p->vars[p->nvars].name) p->nvars++;
}

static void
bc_vars_free (bc_parser *p)
{
    for (int i = 0; i < p->nvars; i++) {
        free (p->vars[i].name);
        bc_free (&p->vars[i].val);
    }
    free (p->vars);
    p->vars = NULL;
    p->nvars = 0;
    p->capvars = 0;
}

/* ---- function dispatch ---- */

/* Single-argument builtin functions. */
static bc_num
bc_call_func (bc_parser *p, const char *name, const bc_num *arg)
{
    if (!strcmp (name, "sqrt"))
        return bc_sqrt (arg, p->scale);
    if (!strcmp (name, "length")) {
        /* total number of significant decimal digits */
        int nd = arg->len;
        if (nd == 0) nd = 1;
        return bc_from_int (nd);
    }
    if (!strcmp (name, "scale"))
        return bc_from_int (arg->scale);
    /* Standard math library (libmath.b port). */
    if (!strcmp (name, "s")) return bc_func_s (arg, p->scale);
    if (!strcmp (name, "c")) return bc_func_c (arg, p->scale);
    if (!strcmp (name, "a")) return bc_func_a (arg, p->scale);
    if (!strcmp (name, "l")) return bc_func_l (arg, p->scale);
    if (!strcmp (name, "e")) return bc_func_e (arg, p->scale);
    /* unknown function → 0 */
    return bc_dup (&_bc_zero);
}

/* Two-argument builtin functions (j only). */
static bc_num
bc_call_func2 (bc_parser *p, const bc_num *n, const bc_num *x)
{
    return bc_func_j (n, x, p->scale);
}

/* Skip whitespace and peek. */
static int
bc_peek (bc_parser *p)
{
    while (*p->s == ' ' || *p->s == '\t') p->s++;
    return (unsigned char) *p->s;
}

static int
bc_try_char (bc_parser *p, int c)
{
    if (bc_peek (p) == c) { p->s++; return 1; }
    return 0;
}

/* Atom: NUMBER | NAME | '(' expr ')' | NAME '(' expr ')' | '-' atom */
static bc_num
bc_parse_atom (bc_parser *p)
{
    int c = bc_peek (p);

    /* unary minus */
    if (c == '-') {
        p->s++;
        bc_num v = bc_parse_atom (p);
        v.sign = !v.sign;
        if (bc_is_zero (&v)) v.sign = 0;
        return v;
    }

    /* unary plus */
    if (c == '+') {
        p->s++;
        return bc_parse_atom (p);
    }

    /* parenthesized expression */
    if (c == '(') {
        p->s++;
        bc_num v = bc_parse_expr (p);
        if (bc_peek (p) == ')') p->s++;
        else p->err = 1;
        return v;
    }

    /* number — only treat hex letters as digits when the base makes them valid */
    if ((c >= '0' && c <= '9') ||
        (p->ibase > 10 && c >= 'A' && c <= ('A' + p->ibase - 11)) ||
        (p->ibase > 10 && c >= 'a' && c <= ('a' + p->ibase - 11))) {
        return bc_parse_number (&p->s, p->ibase);
    }
    if (c == '.') {
        /* leading decimal point → 0.xxx */
        return bc_parse_number (&p->s, p->ibase);
    }

    /* name or function */
    if (isalpha (c) || c == '_') {
        char name[64];
        int nl = 0;
        while (nl < 63 && (isalnum ((unsigned char)*p->s) || *p->s == '_')) {
            name[nl++] = *p->s++;
        }
        name[nl] = '\0';

        /* function call? */
        if (bc_peek (p) == '(') {
            p->s++;
            if (!strcmp (name, "read")) {
                char *line = NULL;
                size_t cap = 0;
                ssize_t n;

                if (bc_peek (p) == ')') p->s++;
                else { p->err = 1; return bc_dup (&_bc_zero); }

                n = bc_input_line (p->in, &line, &cap);
                if (n < 0) {
                    free (line);
                    return bc_dup (&_bc_zero);
                }

                bc_parser rp = *p;
                rp.s = line;
                rp.err = 0;
                int was_assign = 0;
                bc_num r = bc_parse_assign (&rp, &was_assign);
                if (rp.err || !bc_line_done (&rp)) {
                    p->err = 1;
                    bc_free (&r);
                    free (line);
                    return bc_dup (&_bc_zero);
                }
                p->scale = rp.scale;
                p->ibase = rp.ibase;
                p->obase = rp.obase;
                /* propagate any variable-table growth from the read line */
                p->vars = rp.vars;
                p->nvars = rp.nvars;
                p->capvars = rp.capvars;
                bc_free (&p->last);
                p->last = bc_dup (&r);
                free (line);
                return r;
            }

            /* Two-argument library function: j(n, x). */
            if (!strcmp (name, "j")) {
                bc_num n1 = bc_parse_expr (p);
                if (!bc_try_char (p, ',')) {
                    p->err = 1; bc_free (&n1); return bc_dup (&_bc_zero);
                }
                bc_num x1 = bc_parse_expr (p);
                if (bc_peek (p) == ')') p->s++;
                else { p->err = 1; bc_free (&n1); bc_free (&x1); return bc_dup (&_bc_zero); }
                bc_num r = bc_call_func2 (p, &n1, &x1);
                bc_free (&n1); bc_free (&x1);
                return r;
            }

            bc_num arg = bc_parse_expr (p);
            if (bc_peek (p) == ')') p->s++;
            else { p->err = 1; bc_free (&arg); return bc_dup (&_bc_zero); }

            bc_num r = bc_call_func (p, name, &arg);
            bc_free (&arg);
            return r;
        }

        /* variable */
        if (!strcmp (name, "scale")) {
            return bc_from_int (p->scale);
        } else if (!strcmp (name, "ibase")) {
            return bc_from_int (p->ibase);
        } else if (!strcmp (name, "obase")) {
            return bc_from_int (p->obase);
        } else if (!strcmp (name, "last")) {
            return bc_dup (&p->last);
        } else {
            /* user variable (0 when unset) */
            return bc_var_get (p, name);
        }
    }

    /* nothing matched */
    p->err = 1;
    return bc_dup (&_bc_zero);
}

/* Power: atom ('^' power)?  (right-associative) */
static bc_num
bc_parse_power (bc_parser *p)
{
    bc_num left = bc_parse_atom (p);
    if (p->err) return left;

    if (bc_peek (p) == '^') {
        p->s++;
        bc_num right = bc_parse_power (p);
        if (p->err) { bc_free (&right); return left; }
        bc_num r = bc_pow (&left, &right, p->scale);
        bc_free (&left);
        bc_free (&right);
        return r;
    }
    return left;
}

/* Factor: power (('*'|'/'|'%') power)* */
static bc_num
bc_parse_factor (bc_parser *p)
{
    bc_num left = bc_parse_power (p);
    if (p->err) return left;

    while (1) {
        int c = bc_peek (p);
        if (c != '*' && c != '/' && c != '%') break;
        p->s++;
        bc_num right = bc_parse_power (p);
        if (p->err) { bc_free (&right); return left; }

        bc_num r;
        if (c == '*') {
            r = bc_mul (&left, &right, p->scale);
        } else if (c == '/') {
            if (bc_is_zero (&right)) {
                builtin_error ("divide by zero");
                p->err = 1;
                bc_free (&right);
                return left;
            }
            r = bc_div (&left, &right, p->scale);
        } else { /* % */
            if (bc_is_zero (&right)) {
                builtin_error ("modulo by zero");
                p->err = 1;
                bc_free (&right);
                return left;
            }
            r = bc_mod (&left, &right);
        }
        bc_free (&left);
        bc_free (&right);
        left = r;
    }
    return left;
}

/* Additive level: factor (('+'|'-') factor)* */
static bc_num
bc_parse_add (bc_parser *p)
{
    bc_num left = bc_parse_factor (p);
    if (p->err) return left;

    while (1) {
        int c = bc_peek (p);
        if (c != '+' && c != '-') break;
        p->s++;
        bc_num right = bc_parse_factor (p);
        if (p->err) { bc_free (&right); return left; }

        bc_num r;
        if (c == '+')
            r = bc_add (&left, &right, p->scale);
        else
            r = bc_sub (&left, &right, p->scale);
        bc_free (&left);
        bc_free (&right);
        left = r;
    }
    return left;
}

/* Assignment is an expression in bc: NAME '=' assign | add.
   When the top-level expression is exactly an assignment, *was_assign is set
   so the statement runner stays silent (GNU bc prints nothing for `x=3`).
   A parenthesized assignment goes through bc_parse_expr, which discards the
   flag, so `(x=3)` is still printed — matching GNU. */
static bc_num
bc_parse_assign (bc_parser *p, int *was_assign)
{
    /* peek at next token to see if it's NAME = */
    int c = bc_peek (p);
    if (!isalpha (c) && c != '_') return bc_parse_add (p);

    char name[64];
    int nl = 0;
    const char *s2 = p->s;
    while (nl < 63 && (isalnum ((unsigned char)*s2) || *s2 == '_')) {
        name[nl++] = *s2++;
    }
    name[nl] = '\0';
    if (nl == 0) return bc_parse_add (p);

    /* check for a single '=' after the name (not '==' comparison) */
    const char *s3 = s2;
    while (*s3 == ' ' || *s3 == '\t') s3++;
    if (*s3 != '=' || s3[1] == '=') return bc_parse_add (p);

    /* assignment (right-associative: RHS may itself be an assignment) */
    p->s = s3 + 1;
    int rhs_assign = 0;
    bc_num val = bc_parse_assign (p, &rhs_assign);
    if (p->err) return val;
    if (was_assign) *was_assign = 1;

    if (!strcmp (name, "scale")) {
        /* bc_to_ll ignores the sign; a negative scale clamps to 0 (GNU). */
        p->scale = val.sign ? 0 : (int) bc_to_ll (&val);
        if (p->scale < 0) p->scale = 0;
        /* assignment returns the value */
        bc_num r = bc_dup (&val);
        return r;
    } else if (!strcmp (name, "ibase")) {
        int v = (int) bc_to_ll (&val);
        if (v >= 2 && v <= 16) p->ibase = v;
        bc_num r = bc_dup (&val);
        return r;
    } else if (!strcmp (name, "obase")) {
        int v = (int) bc_to_ll (&val);
        if (v >= 2 && v <= 16) p->obase = v;
        bc_num r = bc_dup (&val);
        return r;
    }

    /* user variable: store and return the assigned value */
    bc_var_set (p, name, &val);
    (void) rhs_assign;
    return val;
}

/* Full expression (assignment is the lowest-precedence operator in bc).
   Used inside parentheses and function arguments, where the assignment flag
   does not bubble up to statement-level output suppression. */
static bc_num
bc_parse_expr (bc_parser *p)
{
    int dummy = 0;
    return bc_parse_assign (p, &dummy);
}

static void
bc_skip_line_ws (bc_parser *p)
{
    while (*p->s == ' ' || *p->s == '\t') p->s++;
}

static int
bc_parse_quoted_string (bc_parser *p)
{
    if (*p->s != '"') return 0;
    p->s++;
    while (*p->s && *p->s != '"') {
        if (*p->s == '\\') {
            p->s++;
            switch (*p->s) {
            case 'n': putchar ('\n'); break;
            case 't': putchar ('\t'); break;
            case 'r': putchar ('\r'); break;
            case '\\': putchar ('\\'); break;
            case '"': putchar ('"'); break;
            case '\0':
                p->err = 1;
                return 0;
            default:
                putchar (*p->s);
                break;
            }
            if (*p->s) p->s++;
        } else {
            putchar (*p->s++);
        }
    }
    if (*p->s == '"') {
        p->s++;
        return 1;
    }
    p->err = 1;
    return 0;
}

static int
bc_at_keyword (bc_parser *p, const char *kw)
{
    size_t len = strlen (kw);
    bc_skip_line_ws (p);
    if (strncmp (p->s, kw, len) != 0) return 0;
    if (isalnum ((unsigned char)p->s[len]) || p->s[len] == '_') return 0;
    p->s += len;
    return 1;
}

static int
bc_line_done (bc_parser *p)
{
    bc_skip_line_ws (p);
    return *p->s == '\0';
}

/* `print` list: comma-separated expressions/strings, no trailing newline.
   Consumes up to the next ';' or end of line. */
static int
bc_run_print_statement (bc_parser *p, bc_num *result_out)
{
    bc_free (result_out);
    *result_out = bc_dup (&p->last);

    while (1) {
        bc_skip_line_ws (p);
        if (*p->s == '\0' || *p->s == ';') return 1;

        if (*p->s == '"') {
            if (!bc_parse_quoted_string (p)) return 0;
        } else {
            bc_num v = bc_parse_expr (p);
            if (p->err) {
                bc_free (&v);
                return 0;
            }
            bc_print (&v, p->obase, 0);
            bc_free (result_out);
            *result_out = bc_dup (&v);
            bc_free (&v);
        }

        bc_skip_line_ws (p);
        if (*p->s == ',') {
            p->s++;
            continue;
        }
        return 1;
    }
}

/* Run one statement, stopping at the next ';' or end of line.
   A bare assignment statement produces no output (GNU bc behaviour). */
static int
bc_run_one_statement (bc_parser *p, int newline, bc_num *result_out)
{
    if (bc_at_keyword (p, "define")) {
        builtin_error ("define/functions are not implemented");
        p->err = 1;
        return 0;
    }
    if (bc_at_keyword (p, "print"))
        return bc_run_print_statement (p, result_out);

    int was_assign = 0;
    bc_num result = bc_parse_assign (p, &was_assign);
    if (p->err) {
        bc_free (&result);
        p->err = 1;
        return 0;
    }
    /* the statement must end here (';' or end of line handled by caller) */
    bc_skip_line_ws (p);
    if (*p->s != '\0' && *p->s != ';') {
        bc_free (&result);
        p->err = 1;
        return 0;
    }

    /* GNU bc prints the value of a non-assignment statement; a bare
       assignment is silent. */
    if (!was_assign)
        bc_print (&result, p->obase, newline);
    bc_free (result_out);
    *result_out = result;
    return 1;
}

/* Run a full input line: one or more ';'-separated statements. */
static int
bc_run_statement (bc_parser *p, int newline, bc_num *result_out)
{
    while (1) {
        bc_skip_line_ws (p);
        if (*p->s == '\0') return 1;     /* trailing ';' / empty statement */
        if (*p->s == ';') { p->s++; continue; }

        if (!bc_run_one_statement (p, newline, result_out))
            return 0;

        bc_skip_line_ws (p);
        if (*p->s == ';') { p->s++; continue; }
        if (*p->s == '\0') return 1;
        /* unexpected trailing token */
        p->err = 1;
        return 0;
    }
}

static void
bc_init_statics (void)
{
    if (_bc_zero.digits) return;
    _bc_zero.digits = strdup ("0");
    _bc_zero.len = 1;
    _bc_zero.scale = 0;
    _bc_zero.sign = 0;

    _bc_one.digits = strdup ("1");
    _bc_one.len = 1;
    _bc_one.scale = 0;
    _bc_one.sign = 0;
}

/* ---- builtin interface ---- */

int
bc_builtin (WORD_LIST *list)
{
    bc_init_statics ();

    /* Every invocation starts from the documented defaults and reads its
       own standard input, so no arithmetic or input state survives a
       previous call in the same shell. */
    bc_input input;
    bc_input_init (&input, STDIN_FILENO);

    bc_parser p;
    p.scale = 0;
    p.ibase = 10;
    p.obase = 10;
    p.mathlib = 0;
    p.last = bc_dup (&_bc_zero);
    p.vars = NULL;
    p.nvars = 0;
    p.capvars = 0;
    p.in = &input;

    /* Option scan: -l/--mathlib enables the math library and sets the
       default scale to 20 (as GNU bc does).  Other GNU bc flags that take
       no expression (-q, -s, -w, -i, --) are accepted and ignored so common
       invocations like `bc -l` work; the remaining words are the
       expression. */
    while (list) {
        const char *w = list->word->word;
        if (!strcmp (w, "-l") || !strcmp (w, "--mathlib")) {
            p.mathlib = 1;
            list = list->next;
        } else if (!strcmp (w, "-q") || !strcmp (w, "--quiet") ||
                   !strcmp (w, "-s") || !strcmp (w, "--standard") ||
                   !strcmp (w, "-w") || !strcmp (w, "--warn") ||
                   !strcmp (w, "-i") || !strcmp (w, "--interactive")) {
            list = list->next;
        } else if (!strcmp (w, "--")) {
            list = list->next;
            break;
        } else {
            break;
        }
    }

    if (p.mathlib)
        p.scale = 20;

    int rc = EXECUTION_SUCCESS;

    /* Collect expression from args or stdin */
    if (list) {
        /* Expression from args — concatenate all words */
        size_t total = 0;
        for (WORD_LIST *w = list; w; w = w->next)
            total += strlen (w->word->word) + 1;
        char *expr = malloc (total + 1);
        if (!expr) { bc_free (&p.last); bc_vars_free (&p); return EXECUTION_FAILURE; }
        expr[0] = '\0';
        for (WORD_LIST *w = list; w; w = w->next) {
            strcat (expr, w->word->word);
            if (w->next) strcat (expr, " ");
        }

        p.s = expr;
        p.err = 0;
        bc_num result = bc_dup (&_bc_zero);
        if (!bc_run_statement (&p, 1, &result)) {
            builtin_error ("syntax error in expression: %s", expr);
            bc_free (&result);
            free (expr);
            bc_free (&p.last);
            bc_vars_free (&p);
            return EXECUTION_FAILURE;
        }
        free (expr);

        bc_free (&p.last);
        p.last = bc_dup (&result);
        bc_free (&result);
        /* bc persists state across invocations... but bash builtins are
           re-entered fresh each time.  Variables persist across the lines of
           this one call (see the stdin loop below). */
    } else {
        /* Read expressions from stdin, one per line.  scale/ibase/obase and
           user variables persist across lines within this invocation. */
        char *line = NULL;
        size_t cap = 0;
        while (1) {
            ssize_t n = bc_input_line (&input, &line, &cap);
            if (n < 0) break;
            if (n == 0) continue;      /* a blank line evaluates to nothing */

            p.s = line;
            p.err = 0;
            bc_num result = bc_dup (&_bc_zero);
            if (!bc_run_statement (&p, 1, &result)) {
                builtin_error ("syntax error: %s", line);
                bc_free (&result);
                rc = EXECUTION_FAILURE;
                continue;
            }
            bc_free (&p.last);
            p.last = bc_dup (&result);
            bc_free (&result);
        }
        free (line);
        bc_free (&p.last);
    }

    if (input.error) {
        builtin_error ("standard input: %s", strerror (input.error));
        rc = EXECUTION_FAILURE;
    }

    bc_vars_free (&p);
    return rc;
}

char *bc_doc[] = {
    "Arbitrary-precision calculator (bc-compatible).",
    "",
    "    bc [-l] [EXPRESSION]",
    "        Evaluate EXPRESSION and print the result.",
    "        With no expression, read statements from stdin.",
    "        Several statements may share a line, separated by ';'.",
    "        A bare assignment (e.g. scale=10 or x=3) prints nothing.",
    "        -l / --mathlib enables the math library and sets scale=20.",
    "",
    "Supported operators (in precedence order):",
    "    + -          addition, subtraction",
    "    * / %        multiplication, division, remainder",
    "    ^            exponentiation (integer exponents)",
    "    ( )          grouping",
    "    =            assignment (also inside expressions, e.g. (x=3))",
    "",
    "Supported functions:",
    "    read()       read one stdin line and evaluate it as an expression",
    "    sqrt(x)      square root (arbitrary precision, Newton's method)",
    "    s(x)         sine (arbitrary precision, libmath series)",
    "    c(x)         cosine (arbitrary precision, libmath series)",
    "    l(x)         natural log (arbitrary precision, libmath series)",
    "    e(x)         exponential e^x (arbitrary precision, libmath series)",
    "    a(x)         arctangent (arbitrary precision, libmath series)",
    "    j(n,x)       Bessel function of integer order n",
    "    length(x)    number of significant digits",
    "    scale(x)     number of fractional digits",
    "",
    "Special variables:",
    "    scale        fractional digits in results (default 0, or 20 with -l)",
    "    ibase        input base 2..16 (default 10)",
    "    obase        output base (not yet implemented, results in decimal)",
    "    last         result of the previous expression",
    "    NAME         user variables persist across the statements of one run",
    "",
    "GNU extensions:",
    "    print EXPR   print an expression or quoted string without newline",
    "    define       deferred; user-defined functions are not implemented",
    "",
    "Examples:",
    "    bc '1 + 2 * 3'                → 7",
    "    printf 'scale=4\\n22/7\\n' | bc → 3.1428",
    "    echo 'scale=10; 22/7; x=3; x^2' | bc → 3.1428571428 then 9",
    "    printf '4*a(1)\\n' | bc -l    → 3.14159265358979323844",
    "    echo '3^100' | bc             → 515377520732011331036461129765621272702107522001",
    (char *)NULL
};

struct builtin bc_struct = {
    "bc",
    bc_builtin,
    BUILTIN_ENABLED,
    bc_doc,
    "bc [EXPRESSION...]",
    0
};
