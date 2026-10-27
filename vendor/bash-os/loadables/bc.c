/* SPDX-License-Identifier: MIT */
/* bc.c — arbitrary-precision bc(1) as a bash builtin.
 *
 * GNU bc language: arbitrary-precision arithmetic, functions and local
 * state, arrays, control flow, comments, strings and input/output bases.
 * Reads programs from expressions, named files and standard input.
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
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include "loadables.h"

#define BC_NOINLINE __attribute__ ((noinline))

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
static bc_num bc_str2num (const char *s, size_t n, int ibase);
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
    if (v < 10) {                 /* booleans, digits, small counters */
        n.digits = malloc (2);
        n.len = n.digits ? 1 : 0;
        n.scale = 0;
        if (n.digits) { n.digits[0] = (char) ('0' + v); n.digits[1] = '\0'; }
        return n;
    }
    char buf[64];
    int l = snprintf (buf, sizeof buf, "%lld", v);
    n.digits = strdup (buf);
    n.len = l;
    n.scale = 0;
    if (!n.digits) { n.len = 0; return n; }
    return n;
}

/* Read the integer part, truncating fractional digits (no sign handling). */
static long long
bc_to_ll (const bc_num *n)
{
    long long v = 0;
    for (int i = 0; i < n->len - n->scale && i < 18; i++) {
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
            r.sign = cmp > 0 && a->sign;
        } else {
            r = bc_sub_unsigned (b, a, scale);
            r.sign = b->sign;
        }
    }
    bc_fix_scale (&r, a->scale > b->scale ? a->scale : b->scale);
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
            r.sign = cmp > 0 && a->sign;
        } else {
            r = bc_sub_unsigned (b, a, scale);
            r.sign = !a->sign;
        }
    }
    bc_fix_scale (&r, a->scale > b->scale ? a->scale : b->scale);
    return r;
}

/* ---- multiplication ---- */

#define BC_LIMB 1000000000u

/* The N digits at D (most significant first) as base-10^9 limbs, least
   significant first.  *COUNT receives the number of limbs. */
static uint32_t *
bc_to_limbs (const char *d, int n, int *count)
{
    int k = (n + 8) / 9;
    uint32_t *l = malloc (sizeof (uint32_t) * (size_t) (k ? k : 1));
    if (!l) return NULL;
    for (int i = 0; i < k; i++) {
        int end = n - 9 * i, start = end - 9 < 0 ? 0 : end - 9;
        uint32_t v = 0;
        for (int j = start; j < end; j++) v = v * 10 + (uint32_t) (d[j] - '0');
        l[i] = v;
    }
    *count = k;
    return l;
}

/* PROD[0..TOTAL-1] = the decimal digits of A * B (as integers), most
   significant first, exactly as the digit-at-a-time loop produces them. */
static int
bc_mul_limbs (const bc_num *a, const bc_num *b, int *prod, int total)
{
    int ka, kb;
    uint32_t *la = bc_to_limbs (a->digits, a->len, &ka);
    uint32_t *lb = bc_to_limbs (b->digits, b->len, &kb);
    uint32_t *r = calloc ((size_t) (ka + kb), sizeof (uint32_t));
    if (!la || !lb || !r) { free (la); free (lb); free (r); return 0; }
    for (int i = 0; i < ka; i++) {
        uint64_t carry = 0, x = la[i];
        if (!x) continue;
        for (int j = 0; j < kb; j++) {
            uint64_t cur = r[i + j] + x * lb[j] + carry;
            r[i + j] = (uint32_t) (cur % BC_LIMB);
            carry = cur / BC_LIMB;
        }
        r[i + kb] = (uint32_t) carry;
    }
    for (int i = 0; i < ka + kb; i++) {
        uint32_t v = r[i];
        for (int t = 0; t < 9; t++) {
            int pos = total - 1 - (9 * i + t);
            if (pos < 0) break;
            prod[pos] = (int) (v % 10);
            v /= 10;
        }
    }
    free (la); free (lb); free (r);
    return 1;
}

static bc_num
bc_mul (const bc_num *a, const bc_num *b, int scale)
{
    int result_scale = a->scale + b->scale;
    int kept_scale = a->scale > b->scale ? a->scale : b->scale;
    if (scale > kept_scale) kept_scale = scale;
    if (kept_scale > result_scale) kept_scale = result_scale;

    if (bc_is_zero (a) || bc_is_zero (b)) {
        /* a zero product has the scale any other product would */
        bc_num z = bc_dup (&_bc_zero);
        bc_fix_scale (&z, kept_scale);
        return z;
    }
    int total = a->len + b->len;

    /* temp array for digit-at-a-time multiplication */
    int *prod = calloc (total, sizeof (int));
    if (!prod) { bc_num r = bc_dup (&_bc_zero); return r; }

    if (total > 40) {
        /* Long operands: multiply nine digits at a time in base 10^9, then
           spread the product back into decimal digits. */
        if (!bc_mul_limbs (a, b, prod, total)) { free (prod); return bc_dup (&_bc_zero); }
    } else {
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

    /* GNU bc keeps at least the precision of either operand, even when the
       global scale is smaller, but never more than their combined scale. */
    if (r.scale > kept_scale)
        bc_truncate_to_scale (&r, kept_scale);

    bc_normalize (&r);
    bc_fix_scale (&r, kept_scale);
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

    /* Fractional divisors have leading zero digits (for example .25 is
       stored as 025).  Long division needs the divisor's integer digits
       without those zeros, otherwise one quotient digit can exceed 9. */
    const char *divisor = b->digits;
    int divisor_len = b->len;
    while (divisor_len > 1 && *divisor == '0') {
        divisor++;
        divisor_len--;
    }

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
            /* Compare rem with the divisor's significant digits. */
            if (rem_len < divisor_len) break;
            if (rem_len == divisor_len) {
                int gt = 0, lt = 0;
                for (int k = 0; k < rem_len; k++) {
                    if (rem[k] > divisor[k]) { gt = 1; break; }
                    if (rem[k] < divisor[k]) { lt = 1; break; }
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
            for (int k = divisor_len - 1; k >= 0; k--) {
                int rk = rem_len - (divisor_len - k);
                int dr = (rk >= 0) ? rem[rk] - '0' : 0;
                int db = divisor[k] - '0';
                int diff = dr - db - borrow;
                if (diff < 0) { diff += 10; borrow = 1; }
                else borrow = 0;
                if (rk >= 0) rem[rk] = '0' + diff;
            }
            /* handle borrow on the most significant digit */
            if (borrow) {
                for (int k = rem_len - divisor_len - 1; k >= 0; k--) {
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
bc_mod (const bc_num *a, const bc_num *b, int scale)
{
    if (bc_is_zero (b)) return bc_dup (&_bc_zero);
    /* a % b = a - trunc(a / b, scale) * b.  The quotient is truncated
       toward zero and carries the sign of a / b. */
    bc_num q = bc_div_internal (a, b, scale);
    q.sign = a->sign != b->sign && !bc_is_zero (&q);
    /* Modulo retains the full precision of quotient times divisor before
       subtraction, even though ordinary multiplication uses global scale. */
    bc_num prod = bc_mul (&q, b, q.scale + b->scale);
    bc_num r = bc_sub (a, &prod, scale);
    bc_free (&q);
    bc_free (&prod);
    int result_scale = a->scale;
    if (scale + b->scale > result_scale) result_scale = scale + b->scale;
    bc_fix_scale (&r, result_scale);
    return r;
}

/* ---- exponentiation (integer exponent) ---- */

static bc_num
bc_pow (const bc_num *base, const bc_num *exp, int scale)
{
    if (bc_is_zero (exp)) return bc_dup (&_bc_one);
    int negative = exp->sign;

    long long e = bc_to_ll (exp);
    if (e <= 0) return bc_dup (&_bc_one);
    if (bc_is_zero (base) && !negative) {
        /* GNU's raise: rscale = min(scale(base)*e, max(scale, scale(base))) */
        long long full = (long long) base->scale * e;
        int kept = base->scale > scale ? base->scale : scale;
        if (full < kept) kept = (int) full;
        bc_num z = bc_dup (&_bc_zero);
        bc_fix_scale (&z, kept);
        return z;
    }
    if (e == 1 && !negative) { bc_num r = bc_dup (base); return r; }

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
    if (negative) {
        bc_num one = bc_dup (&_bc_one);
        bc_num reciprocal = bc_div (&one, &result, scale);
        bc_free (&one);
        bc_free (&result);
        return reciprocal;
    }
    int kept_scale = base->scale;
    if (scale > kept_scale) kept_scale = scale;
    int full_scale = base->scale * (int) bc_to_ll (exp);
    if (kept_scale > full_scale) kept_scale = full_scale;
    /* GNU truncates the power by shortening its scale and keeps the sign,
       so a negative power too small for the scale is a "-0", which prints
       as -0 and compares below zero.  Reproduce that. */
    int sign = result.sign;
    if (result.scale > kept_scale)
        bc_truncate_to_scale (&result, kept_scale);
    bc_normalize (&result);
    bc_fix_scale (&result, kept_scale);
    result.sign = sign;
    return result;
}

/* ---- sqrt (Newton's method) ---- */

static bc_num
bc_sqrt (const bc_num *n, int scale)
{
    if (n->sign) return bc_dup (&_bc_zero);  /* domain error */
    if (bc_is_zero (n)) return bc_dup (&_bc_zero);  /* sqrt(0) prints as "0" */
    if (bc_cmp (n, &_bc_one) == 0) return bc_dup (&_bc_one);
    /* GNU sqrt retains whichever precision is larger: input or scale. */
    if (n->scale > scale) scale = n->scale;

    /* Start above the root using only decimal magnitude. Converting through
       double and %.15f rounded small positive seeds to zero (and could
       overflow for large operands). ceil(digits / 2) gives a power of ten
       above sqrt(n), including when the first significant digit is fractional. */
    int first = 0;
    while (first < n->len && n->digits[first] == '0') first++;
    int magnitude = n->len - n->scale - first;
    int exponent = magnitude > 0 ? (magnitude + 1) / 2 : magnitude / 2;
    int length = (exponent < 0 ? -exponent : exponent) + 1;
    bc_num x = bc_alloc (length);
    if (!x.digits) {
        builtin_error ("out of memory");
        return bc_dup (&_bc_zero);
    }
    x.len = length;
    x.scale = exponent < 0 ? -exponent : 0;
    x.digits[exponent < 0 ? length - 1 : 0] = '1';

    /* Newton iteration: x = (x + n/x) / 2 */
    bc_num two = bc_from_int (2);
    int iter_scale = scale + 5;
    while (1) {
        bc_num q = bc_div (n, &x, iter_scale);
        bc_num s = bc_add (&x, &q, iter_scale);
        bc_num new_x = bc_div (&s, &two, iter_scale);
        bc_free (&q);
        bc_free (&s);

        /* Fixed-precision Newton steps decrease from the upper bound to
           the floor of the root. Stop before a possible rounding cycle. */
        if (bc_cmp (&new_x, &x) >= 0) {
            bc_free (&new_x);
            break;
        }
        bc_free (&x);
        x = new_x;
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
   prints ".5000000000" and 6/2 prints "3.0000000000".  A zero keeps its
   scale too: GNU prints it as "0", but 0/5+1 at scale 3 is 1.000. */
static void
bc_fix_scale (bc_num *n, int scale)
{
    if (scale <= 0) return;
    bc_pad_scale (n, scale);
}

/* ------------------------------------------------------------------ *
 * Standard math library (s/c/a/l/e/j), ported from GNU bc libmath.b.  *
 *                                                                     *
 * Each routine mirrors the corresponding bc definition operation for  *
 * operation, using the same Taylor/Maclaurin series, guard-digit      *
 * scale formulas, and final `return (v/1)` truncation, so the digit   *
 * strings match GNU bc byte-for-byte at a given scale.  Numbers are   *
 * always base 10 here (bc_str2num already decoded the input         *
 * base), so libmath's ibase!=A re-entrancy guard is unnecessary.      *
 * ------------------------------------------------------------------ */

/* Parse a decimal literal constant into a bc_num. */
static bc_num
bc_const (const char *lit)
{
    return bc_str2num (lit, strlen (lit), 10);
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
        bc_num d = bc_sub (&one, &p, 0);
        bc_num r = bc_trunc (&d, z);         /* return ((1 - 10^scale)/1) */
        bc_free (&d);
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
    bc_num nmod = bc_mod (&n, &two, 0);
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

/* length(): significant digits.  A value below one counts its fraction
   digits (length(.001) is 3), zero counts its scale, or 1. */
static int
bc_length (const bc_num *v)
{
    if (bc_is_zero (v)) return v->scale > 0 ? v->scale : 1;
    int first = 0;
    while (first < v->len - v->scale - 1 && v->digits[first] == '0') first++;
    int intpart = v->len - v->scale - first;
    if (intpart == 1 && v->digits[first] == '0') return v->scale;
    return v->len - first;
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
    long long nn = bc_to_ll (&nint);    /* the magnitude of n */
    if (nint.sign && nn % 2 == 1) m = 1;

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

    int wscale = (int) (1.5 * z) + bc_length (&f) - f.scale;
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

/* Read more bytes when the buffer is empty.  Returns 0 at end of input or
   after a read error (recorded in IN), 1 when a byte is available. */
static int
bc_input_fill (bc_input *in)
{
    ssize_t got;

    if (in->pos < in->len) return 1;
    if (in->eof) return 0;
    do
        got = read (in->fd, in->buf, sizeof in->buf);
    while (got < 0 && errno == EINTR && !interrupt_state && !terminating_signal);
    if (got < 0) { in->eof = 1; in->error = errno; return 0; }
    if (got == 0) { in->eof = 1; return 0; }
    in->pos = 0;
    in->len = (size_t) got;
    return 1;
}

/* ---- numbers from program text ----------------------------------- */

/* Value of an input digit: 0-9, then A-Z for 10..35. */
static int
bc_digit_value (int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'Z') return c - 'A' + 10;
    return -1;
}

/* Convert the text of a constant at input base IBASE, as GNU bc does.  A
   constant of one digit keeps that digit's value whatever the base (A is
   10 even when ibase is 2); in a longer constant a digit that is not below
   the base counts as ibase-1.  A fraction is the fraction digits read as an
   integer, divided by ibase^digits at a scale of that many digits. */
static bc_num
bc_str2num (const char *s, size_t n, int ibase)
{
    const char *dot = memchr (s, '.', n);
    size_t ilen = dot ? (size_t) (dot - s) : n;
    size_t flen = dot ? n - ilen - 1 : 0;
    int decimal = ibase == 10;

    if (n == 1 && !dot)
        return bc_from_int (bc_digit_value ((unsigned char) s[0]));
    for (size_t i = 0; i < n && decimal; i++)
        if (s[i] != '.' && (s[i] < '0' || s[i] > '9')) decimal = 0;

    if (decimal) {
        size_t lead = ilen == 0;
        size_t total = lead + ilen + flen;
        if (total > INT_MAX - 2) return bc_dup (&_bc_zero);
        bc_num r = bc_alloc ((int) total + 1);
        if (!r.digits) return bc_dup (&_bc_zero);
        if (lead) r.digits[0] = '0';
        memcpy (r.digits + lead, s, ilen);
        memcpy (r.digits + lead + ilen, s + ilen + 1, flen);
        r.digits[total] = '\0';
        r.len = (int) total;
        r.scale = (int) flen;
        bc_normalize (&r);
        bc_pad_scale (&r, (int) flen);   /* a literal keeps its trailing zeros */
        return r;
    }

    bc_num base = bc_from_int (ibase);
    bc_num result = bc_dup (&_bc_zero);
    for (size_t i = 0; i < ilen; i++) {
        int d = bc_digit_value ((unsigned char) s[i]);
        if (d >= ibase) d = ibase - 1;
        bc_num dv = bc_from_int (d);
        bc_num t = bc_mul (&result, &base, 0);
        bc_free (&result);
        result = bc_add (&t, &dv, 0);
        bc_free (&t); bc_free (&dv);
    }
    if (flen > 0) {
        bc_num num = bc_dup (&_bc_zero), mult = bc_dup (&_bc_one);
        for (size_t i = 0; i < flen; i++) {
            int d = bc_digit_value ((unsigned char) dot[1 + i]);
            if (d >= ibase) d = ibase - 1;
            bc_num dv = bc_from_int (d);
            bc_num t = bc_mul (&num, &base, 0);
            bc_free (&num);
            num = bc_add (&t, &dv, 0);
            bc_free (&t); bc_free (&dv);
            t = bc_mul (&mult, &base, 0);
            bc_free (&mult);
            mult = t;
        }
        bc_num frac = bc_div (&num, &mult, (int) flen);
        bc_num sum = bc_add (&result, &frac, 0);
        bc_free (&result); bc_free (&frac); bc_free (&num); bc_free (&mult);
        result = sum;
    }
    bc_free (&base);
    return result;
}

/* ---- output ------------------------------------------------------ *
 *
 * Output goes through a private buffer and reaches stdout in blocks, not a
 * putchar per digit.  The column is tracked the way GNU bc tracks it: when
 * a line reaches BC_LINE_LENGTH-1 characters a backslash-newline is
 * inserted, for numbers and strings alike, and the column runs on from one
 * printed item to the next until a newline is written.
 * ------------------------------------------------------------------ */

typedef struct {
    size_t len;
    int    col;
    int    line_size;      /* 0 disables wrapping */
    char   buf[8192];
} bc_out;

static void
bc_out_flush (bc_out *o)
{
    if (o->len)
        fwrite (o->buf, 1, o->len, stdout);   /* failures are seen by ferror */
    o->len = 0;
}

static inline void
bc_out_raw (bc_out *o, int c)
{
    if (o->len == sizeof o->buf) bc_out_flush (o);
    o->buf[o->len++] = (char) c;
}

static void
bc_out_char (bc_out *o, int c)
{
    if (c == '\n') {
        o->col = 0;
        bc_out_raw (o, '\n');
        return;
    }
    o->col++;
    if (o->line_size && o->col == o->line_size - 1) {
        bc_out_raw (o, '\\');
        bc_out_raw (o, '\n');
        o->col = 1;
    }
    bc_out_raw (o, c);
}

/* N characters without a newline among them. */
static void
bc_out_str (bc_out *o, const char *s, size_t n)
{
    if (o->line_size == 0 || o->col + n < (size_t) o->line_size - 1) {
        while (n) {
            size_t room = sizeof o->buf - o->len;
            if (room == 0) { bc_out_flush (o); continue; }
            size_t take = n < room ? n : room;
            memcpy (o->buf + o->len, s, take);
            o->len += take;
            o->col += (int) take;
            s += take;
            n -= take;
        }
        return;
    }
    while (n--) bc_out_char (o, (unsigned char) *s++);
}

/* One digit of a base above 16: a space, then the value zero-padded to the
   width of obase-1 (GNU's bc_out_long). */
static void
bc_out_long (bc_out *o, long val, int width, int space)
{
    char buf[32];
    int n = snprintf (buf, sizeof buf, "%ld", val);
    if (space) bc_out_char (o, ' ');
    for (int i = n; i < width; i++) bc_out_char (o, '0');
    bc_out_str (o, buf, (size_t) n);
}

/* Print N in base OBASE, following GNU bc's bc_out_num: zero is "0", a
   value below one has no integer digit, and a fraction gets as many digits
   as it takes for obase^k to exceed 10^scale. */
static void
bc_out_num (bc_out *o, const bc_num *n, long obase)
{
    static const char ref[] = "0123456789ABCDEF";

    if (n->sign) bc_out_char (o, '-');      /* before the zero test, as GNU does */
    if (bc_is_zero (n)) { bc_out_char (o, '0'); return; }

    int intpart = n->len - n->scale;
    const char *d = n->digits;

    if (obase == 10) {
        if (intpart > 0 && !(intpart == 1 && d[0] == '0'))
            bc_out_str (o, d, (size_t) intpart);
        if (n->scale > 0) {
            bc_out_char (o, '.');
            for (int i = intpart; i < 0; i++) bc_out_char (o, '0');
            int from = intpart > 0 ? intpart : 0;
            bc_out_str (o, d + from, (size_t) (n->len - from));
        }
        return;
    }

    int width = snprintf (NULL, 0, "%ld", obase - 1);

    /* Integer part: repeated division of base-10^9 limbs by the largest
       power of the base that fits 32 bits; each remainder gives that many
       output digits. */
    if (intpart > 0) {
        int first = 0;
        while (first < intpart && d[first] == '0') first++;
        int ilen = intpart - first;
        if (ilen > 0) {
            int nl = (ilen + 8) / 9;
            uint32_t *limb = malloc (sizeof (uint32_t) * (size_t) nl);   /* most significant first */
            uint64_t chunk = (uint64_t) obase;
            int per = 1;
            while (chunk * (uint64_t) obase <= UINT32_MAX) { chunk *= (uint64_t) obase; per++; }
            /* base 2 needs log2(10) < 4 digits per decimal digit */
            long *stack = malloc (sizeof (long) * ((size_t) ilen * 4 + (size_t) per + 1));
            if (!limb || !stack) { free (limb); free (stack); return; }
            int lead = ilen - 9 * (nl - 1), pos = first;
            for (int i = 0; i < nl; i++) {
                int take = i == 0 ? lead : 9;
                uint32_t v = 0;
                for (int t = 0; t < take; t++) v = v * 10 + (uint32_t) (d[pos++] - '0');
                limb[i] = v;
            }
            int top = 0, lo = 0;
            while (lo < nl) {
                uint64_t rem = 0;
                for (int i = lo; i < nl; i++) {
                    uint64_t cur = rem * BC_LIMB + limb[i];
                    limb[i] = (uint32_t) (cur / chunk);
                    rem = cur % chunk;
                }
                while (lo < nl && limb[lo] == 0) lo++;
                for (int t = 0; t < per; t++) {
                    stack[top++] = (long) (rem % (uint64_t) obase);
                    rem /= (uint64_t) obase;
                    if (lo == nl && rem == 0) break;   /* no padding above the top digit */
                }
            }
            while (top > 1 && stack[top - 1] == 0) top--;
            while (top > 0) {
                long digit = stack[--top];
                if (obase <= 16) bc_out_char (o, ref[digit]);
                else bc_out_long (o, digit, width, 1);
            }
            free (limb);
            free (stack);
        }
    }

    if (n->scale > 0) {
        int scale = n->scale;
        unsigned char *f = calloc ((size_t) scale, 1);
        unsigned char *t = calloc ((size_t) scale + 24, 1);   /* obase^k, little-endian */
        if (!f || !t) { free (f); free (t); return; }
        for (int i = 0; i < scale; i++) {
            int src = intpart + i;
            f[i] = src >= 0 ? (unsigned char) (d[src] - '0') : 0;
        }
        int tlen = 1, pre_space = 0;
        t[0] = 1;
        bc_out_char (o, '.');
        while (tlen <= scale) {
            long long carry = 0;
            for (int i = scale - 1; i >= 0; i--) {
                long long cur = (long long) f[i] * obase + carry;
                f[i] = (unsigned char) (cur % 10);
                carry = cur / 10;
            }
            if (obase <= 16) bc_out_char (o, ref[carry]);
            else { bc_out_long (o, (long) carry, width, pre_space); pre_space = 1; }
            carry = 0;
            for (int i = 0; i < tlen; i++) {
                long long cur = (long long) t[i] * obase + carry;
                t[i] = (unsigned char) (cur % 10);
                carry = cur / 10;
            }
            while (carry && tlen < scale + 24) {
                t[tlen++] = (unsigned char) (carry % 10);
                carry /= 10;
            }
        }
        free (f);
        free (t);
    }
}

/* ---- program representation ---------------------------------------- *
 *
 * Each top-level item (the statements up to a newline, or one function
 * definition) is parsed into a tree and then run, the way GNU bc compiles an
 * item and executes it.  Names are resolved to numbers at parse time, in
 * three separate namespaces: simple variables, arrays and functions.
 * Variables are dynamically scoped: a call saves the outer values of its
 * parameters and autos on a stack and restores them when it returns, on
 * every path including a runtime error.
 * ------------------------------------------------------------------ */

enum {
    /* expressions */
    E_NUM = 1, E_VAR, E_ELEM, E_SPECIAL, E_NEG, E_NOT, E_BIN, E_AND, E_OR,
    E_ASSIGN, E_INCDEC, E_CALL, E_ARRARG, E_LENGTH, E_SQRT, E_SCALEF, E_READ,
    /* statements */
    S_EXPR, S_STR, S_PRINT, S_BLOCK, S_IF, S_WHILE, S_FOR, S_BREAK,
    S_CONTINUE, S_RETURN, S_HALT, S_EMPTY
};

enum { SP_SCALE, SP_IBASE, SP_OBASE, SP_LAST };

/* The constants 0..35, shared and never freed: an E_NUM node whose
   cache_base is BC_ANY_BASE points here. */
static bc_num
bc_digit_const (int v)
{
    static char text[36][3];
    if (v < 0 || v > 35) v = 0;        /* the lexer passes only 0-9, A-Z */
    bc_num n = { 0, text[v], v < 10 ? 1 : 2, 0 };
    if (!text[v][0]) snprintf (text[v], sizeof text[v], "%d", v);
    return n;
}

/* binary operators (E_BIN op) */
enum { OP_ADD = 1, OP_SUB, OP_MUL, OP_DIV, OP_MOD, OP_POW,
       OP_EQ, OP_NE, OP_LT, OP_LE, OP_GT, OP_GE };

/* E_INCDEC op bits */
#define ID_DEC   1
#define ID_POST  2

typedef struct bc_node bc_node;
struct bc_node {
    short    kind;
    short    op;
    int      id;
    int      line;
    int      paren;          /* written in parentheses */
    bc_node *a, *b, *c, *d;
    bc_node *next;           /* next statement / argument / print item */
    signed char pure;        /* no assignment, call or read inside (-1: not known yet) */
    char    *text;
    size_t   tlen;
    bc_num   cache;          /* E_NUM value converted at cache_base */
    int      cache_base;
};

/* Nodes come from blocks owned by an arena: one per top-level item, and
   one per function definition.  A short item takes one small block rather
   than one allocation per node. */
typedef struct bc_block {
    struct bc_block *next;
    int              used, cap;
    bc_node          nodes[];
} bc_block;

typedef struct { bc_block *blocks; } bc_arena;

#define BC_FIRST_BLOCK 8
#define BC_ANY_BASE (-2)   /* E_NUM cache_base of a one-digit constant */

/* One emptied first block, reused by the next item so that a program of
   short lines does not allocate one per line.  Freed by bc_builtin. */
static bc_block *bc_spare_block;

static void
bc_arena_free (bc_arena *a)
{
    bc_block *b = a->blocks;
    while (b) {
        bc_block *next = b->next;
        for (int i = 0; i < b->used; i++) {
            free (b->nodes[i].text);
            if (b->nodes[i].cache.digits && b->nodes[i].cache_base != BC_ANY_BASE)
                bc_free (&b->nodes[i].cache);
        }
        if (!next && b->cap == BC_FIRST_BLOCK && !bc_spare_block) {
            b->used = 0;
            bc_spare_block = b;     /* the next item's first block */
        } else {
            free (b);
        }
        b = next;
    }
    a->blocks = NULL;
}

#define BC_PAGE      256
#define BC_INDEX_MAX 16777215L
#define BC_MAX_NAMES 32767

typedef struct {
    int      refs;
    size_t   npages;
    bc_num **pages;
} bc_array;

typedef struct { int id; int kind; } bc_param;  /* 0 scalar, 1 array, 2 array by reference */

typedef struct {
    int       defined;
    int       native;       /* mathlib routine (1..6) when not user-defined */
    int       is_void;
    int       nparams, nautos;
    bc_param *params, *autos;
    bc_node  *body;
    bc_arena  arena;
} bc_func;

typedef struct {
    char **names;
    int    count, cap;
    int   *slots;           /* open-addressed hash of name indexes, -1 empty */
    int    nslots;
} bc_names;

typedef struct { int kind; int id; bc_num num; bc_array *arr; } bc_saved;

typedef struct bc_src bc_src;

typedef struct {
    int        scale, ibase;
    int        call_base; /* constants use the function's entry ibase; 0 at top level */
    long       obase;
    int        mathlib;
    bc_num     last;
    bc_names   vnames, anames, fnames;
    bc_num    *vars;     int varcap;
    bc_array **arrays;   int arrcap;
    bc_func   *funcs;    int funccap;
    bc_saved  *saved;    int nsaved, capsaved;
    bc_num     retval;
    int        err;      /* a runtime error ends the current item */
    int        failed;   /* a syntax or runtime error was reported */
    int        fatal;    /* I/O or implementation resource failure */
    int        stop;     /* halt, quit, interrupt or output failure */
    bc_out     out;
    bc_input  *stdin_in;
    bc_src    *src;      /* the source being read, for diagnostics */
    const char *func;    /* the function running, for diagnostics */
    int        line;     /* line of the statement running */
    char      *stack_base;
    size_t     stack_limit;
} bc_interp;

/* ---- diagnostics ---- */

struct bc_src {
    bc_input   *in;      /* descriptor-backed source, or NULL */
    const char *str;     /* string-backed source */
    size_t      slen, spos;
    const char *name;
    int         line;
};

static void
bc_flush_for_message (bc_interp *ip)
{
    bc_out_flush (&ip->out);
    fflush (stdout);
}

static BC_NOINLINE void
bc_syntax_msg (bc_interp *ip, int line, const char *msg)
{
    bc_flush_for_message (ip);
    builtin_error ("%s %d: %s", ip->src ? ip->src->name : "(standard_in)", line, msg);
    ip->failed = 1;
}

static BC_NOINLINE void
bc_rt_error (bc_interp *ip, const char *fmt, const char *arg)
{
    char msg[256];
    if (ip->err) return;           /* only the first error of an item */
    snprintf (msg, sizeof msg, fmt, arg ? arg : "");
    bc_flush_for_message (ip);
    builtin_error ("%s %d: runtime error (func=%s): %s",
                   ip->src ? ip->src->name : "(standard_in)", ip->line,
                   ip->func ? ip->func : "(main)", msg);
    ip->err = 1;
    ip->failed = 1;
}

static void
bc_rt_failure (bc_interp *ip, const char *fmt, const char *arg)
{
    ip->fatal = 1;
    bc_rt_error (ip, fmt, arg);
}

static BC_NOINLINE void
bc_rt_warn (bc_interp *ip, const char *msg)
{
    bc_flush_for_message (ip);
    builtin_warning ("%s %d: runtime warning (func=%s): %s",
                     ip->src ? ip->src->name : "(standard_in)", ip->line,
                     ip->func ? ip->func : "(main)", msg);
}

/* Has the C stack used up its budget?  Recursion in a bc program becomes
   recursion here, and the shell must not be the one to overflow. */
static int
bc_stack_exhausted (bc_interp *ip)
{
    char *here = __builtin_frame_address (0);
    size_t used = ip->stack_base > here ? (size_t) (ip->stack_base - here)
                                        : (size_t) (here - ip->stack_base);
    return used > ip->stack_limit;
}

/* ---- names ---- */

static unsigned
bc_hash (const char *s)
{
    unsigned h = 2166136261u;
    while (*s) h = (h ^ (unsigned char) *s++) * 16777619u;
    return h;
}

static int
bc_names_find (bc_names *t, const char *name)
{
    if (!t->nslots) return -1;
    unsigned i = bc_hash (name) & (unsigned) (t->nslots - 1);
    while (t->slots[i] >= 0) {
        if (!strcmp (t->names[t->slots[i]], name)) return t->slots[i];
        i = (i + 1) & (unsigned) (t->nslots - 1);
    }
    return -1;
}

/* Index of NAME, adding it when new.  -1 when the table is full or memory
   runs out. */
static int
bc_names_intern (bc_names *t, const char *name)
{
    int found = bc_names_find (t, name);
    if (found >= 0) return found;
    if (t->count >= BC_MAX_NAMES) return -1;
    if ((t->count + 1) * 2 > t->nslots) {
        int nslots = t->nslots ? t->nslots * 2 : 64;
        int *slots = malloc (sizeof (int) * (size_t) nslots);
        if (!slots) return -1;
        for (int i = 0; i < nslots; i++) slots[i] = -1;
        for (int k = 0; k < t->count; k++) {
            unsigned i = bc_hash (t->names[k]) & (unsigned) (nslots - 1);
            while (slots[i] >= 0) i = (i + 1) & (unsigned) (nslots - 1);
            slots[i] = k;
        }
        free (t->slots);
        t->slots = slots;
        t->nslots = nslots;
    }
    if (t->count == t->cap) {
        int cap = t->cap ? t->cap * 2 : 32;
        char **names = realloc (t->names, sizeof (char *) * (size_t) cap);
        if (!names) return -1;
        t->names = names;
        t->cap = cap;
    }
    char *copy = strdup (name);
    if (!copy) return -1;
    t->names[t->count] = copy;
    unsigned i = bc_hash (name) & (unsigned) (t->nslots - 1);
    while (t->slots[i] >= 0) i = (i + 1) & (unsigned) (t->nslots - 1);
    t->slots[i] = t->count;
    return t->count++;
}

static void
bc_names_free (bc_names *t)
{
    for (int i = 0; i < t->count; i++) free (t->names[i]);
    free (t->names);
    free (t->slots);
    memset (t, 0, sizeof *t);
}

/* Grow a storage vector of ELEM-sized slots, zero-filled, to hold index ID. */
static int
bc_grow (void **vec, int *cap, int id, size_t elem)
{
    if (id < *cap) return 1;
    int ncap = *cap ? *cap : 16;
    while (ncap <= id) ncap *= 2;
    char *bigger = realloc (*vec, elem * (size_t) ncap);
    if (!bigger) return 0;
    memset (bigger + elem * (size_t) *cap, 0, elem * (size_t) (ncap - *cap));
    *vec = bigger;
    *cap = ncap;
    return 1;
}

static int
bc_var_id (bc_interp *ip, const char *name)
{
    int id = bc_names_intern (&ip->vnames, name);
    if (id >= 0 && !bc_grow ((void **) &ip->vars, &ip->varcap, id, sizeof (bc_num))) id = -1;
    return id;
}

static int
bc_array_id (bc_interp *ip, const char *name)
{
    int id = bc_names_intern (&ip->anames, name);
    if (id >= 0 && !bc_grow ((void **) &ip->arrays, &ip->arrcap, id, sizeof (bc_array *))) id = -1;
    return id;
}

static int
bc_func_id (bc_interp *ip, const char *name)
{
    int id = bc_names_intern (&ip->fnames, name);
    if (id >= 0 && !bc_grow ((void **) &ip->funcs, &ip->funccap, id, sizeof (bc_func))) id = -1;
    return id;
}

/* ---- arrays ---- */

static bc_array *
bc_array_new (void)
{
    bc_array *a = calloc (1, sizeof *a);
    if (a) a->refs = 1;
    return a;
}

static void
bc_array_release (bc_array *a)
{
    if (!a || --a->refs > 0) return;
    for (size_t p = 0; p < a->npages; p++) {
        if (!a->pages[p]) continue;
        for (int i = 0; i < BC_PAGE; i++)
            if (a->pages[p][i].digits) bc_free (&a->pages[p][i]);
        free (a->pages[p]);
    }
    free (a->pages);
    free (a);
}

static bc_array *
bc_array_copy (const bc_array *src)
{
    bc_array *a = bc_array_new ();
    if (!a || !src) return a;
    a->pages = calloc (src->npages ? src->npages : 1, sizeof (bc_num *));
    if (!a->pages) { free (a); return NULL; }
    a->npages = src->npages;
    for (size_t p = 0; p < src->npages; p++) {
        if (!src->pages[p]) continue;
        a->pages[p] = calloc (BC_PAGE, sizeof (bc_num));
        if (!a->pages[p]) { bc_array_release (a); return NULL; }
        for (int i = 0; i < BC_PAGE; i++)
            if (src->pages[p][i].digits)
                a->pages[p][i] = bc_dup (&src->pages[p][i]);
    }
    return a;
}

/* The slot for element IDX, created when CREATE is set; NULL otherwise
   when absent (an absent element is zero). */
static bc_num *
bc_array_slot (bc_array *a, long idx, int create)
{
    size_t page = (size_t) idx / BC_PAGE;
    if (page >= a->npages) {
        if (!create) return NULL;
        size_t np = a->npages ? a->npages : 4;
        while (np <= page) np *= 2;
        bc_num **pages = realloc (a->pages, np * sizeof (bc_num *));
        if (!pages) return NULL;
        memset (pages + a->npages, 0, (np - a->npages) * sizeof (bc_num *));
        a->pages = pages;
        a->npages = np;
    }
    if (!a->pages[page]) {
        if (!create) return NULL;
        a->pages[page] = calloc (BC_PAGE, sizeof (bc_num));
        if (!a->pages[page]) return NULL;
    }
    return &a->pages[page][idx % BC_PAGE];
}

/* The current array bound to ID, created on first use. */
static bc_array *
bc_array_get (bc_interp *ip, int id)
{
    if (!ip->arrays[id]) ip->arrays[id] = bc_array_new ();
    return ip->arrays[id];
}

/* ---- lexer ------------------------------------------------------- */

enum {
    T_EOF = 256, T_NL, T_NUM, T_STR, T_NAME, T_ILLEGAL,
    T_EQ, T_NE, T_LE, T_GE, T_AND, T_OR, T_INC, T_DEC, T_ASSIGN,
    /* keywords */
    T_AUTO, T_BREAK, T_CONTINUE, T_DEFINE, T_ELSE, T_FOR, T_HALT, T_IBASE,
    T_IF, T_LAST, T_LENGTH, T_LIMITS, T_OBASE, T_PRINT, T_QUIT, T_READ,
    T_RETURN, T_SCALE, T_SQRT, T_WARRANTY, T_WHILE
};

static const struct { const char *word; int tok; } bc_keywords[] = {
    { "auto", T_AUTO }, { "break", T_BREAK }, { "continue", T_CONTINUE },
    { "define", T_DEFINE }, { "else", T_ELSE }, { "for", T_FOR },
    { "halt", T_HALT }, { "ibase", T_IBASE }, { "if", T_IF },
    { "last", T_LAST }, { "length", T_LENGTH }, { "limits", T_LIMITS },
    { "obase", T_OBASE }, { "print", T_PRINT }, { "quit", T_QUIT },
    { "read", T_READ }, { "return", T_RETURN }, { "scale", T_SCALE },
    { "sqrt", T_SQRT }, { "warranty", T_WARRANTY }, { "while", T_WHILE },
};

typedef struct {
    int    type;
    int    op;            /* T_ASSIGN: the operator ('=' or + - * / % ^) */
    int    line;
    char  *text;          /* T_NUM, T_STR, T_NAME: sbuf, or owned */
    size_t len;
    char   sbuf[32];      /* short names and numbers, without an allocation */
} bc_tok;

static void
bc_tok_free (bc_tok *t)
{
    if (t->text != t->sbuf) free (t->text);
    t->text = NULL;
}


static inline int
bc_src_peek (bc_src *s)
{
    if (s->in) {
        if (s->in->pos < s->in->len) return (unsigned char) s->in->buf[s->in->pos];
        if (!bc_input_fill (s->in)) return EOF;
        return (unsigned char) s->in->buf[s->in->pos];
    }
    return s->spos < s->slen ? (unsigned char) s->str[s->spos] : EOF;
}

static inline int
bc_src_get (bc_src *s)
{
    int c = bc_src_peek (s);
    if (c == EOF) return EOF;
    if (s->in) s->in->pos++;
    else s->spos++;
    if (c == '\n') s->line++;
    return c;
}

/* A growable byte buffer for token text. */
typedef struct { char *p; size_t len, cap; } bc_buf;

static int
bc_buf_put (bc_buf *b, int c)
{
    if (b->len + 2 > b->cap) {
        size_t cap = b->cap ? b->cap * 2 : 32;
        char *p = realloc (b->p, cap);
        if (!p) return 0;
        b->p = p;
        b->cap = cap;
    }
    b->p[b->len++] = (char) c;
    b->p[b->len] = '\0';
    return 1;
}

/* Token text: kept in the token's own buffer while it fits, and moved to
   the heap only for long names and numbers. */
typedef struct { bc_tok *t; bc_buf heap; size_t len; int oom; } bc_tbuf;

static void
bc_tb_put (bc_tbuf *b, int c)
{
    if (!b->heap.p && b->len + 1 < sizeof b->t->sbuf) {
        b->t->sbuf[b->len++] = (char) c;
        b->t->sbuf[b->len] = '\0';
        return;
    }
    if (!b->heap.p)
        for (size_t i = 0; i < b->len; i++)
            if (!bc_buf_put (&b->heap, b->t->sbuf[i])) b->oom = 1;
    if (!bc_buf_put (&b->heap, c)) b->oom = 1;
    b->len++;
}

/* Install the text; 0 when memory ran out. */
static int
bc_tb_finish (bc_tbuf *b)
{
    if (b->oom) { free (b->heap.p); b->t->text = NULL; return 0; }
    b->t->text = b->heap.p ? b->heap.p : b->t->sbuf;
    b->t->len = b->len;
    return 1;
}

static int
bc_is_digit_char (int c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z');
}

/* Skip a backslash-newline continuation when one is next. */
static int
bc_skip_continuation (bc_src *s)
{
    if (bc_src_peek (s) != '\\') return 0;
    if (s->in) {
        bc_input *in = s->in;
        if (in->pos + 1 < in->len) {
            if (in->buf[in->pos + 1] != '\n') return 0;
        } else {
            /* the newline may be in the next block: keep the backslash
               in the buffer while reading on */
            if (in->pos > 0) {
                memmove (in->buf, in->buf + in->pos, in->len - in->pos);
                in->len -= in->pos;
                in->pos = 0;
            }
            if (in->eof) return 0;
            ssize_t got;
            do
                got = read (in->fd, in->buf + in->len, sizeof in->buf - in->len);
            while (got < 0 && errno == EINTR && !interrupt_state && !terminating_signal);
            if (got < 0) { in->eof = 1; in->error = errno; return 0; }
            if (got == 0) { in->eof = 1; return 0; }
            in->len += (size_t) got;
            if (in->buf[in->pos + 1] != '\n') return 0;
        }
    } else if (s->spos + 1 >= s->slen || s->str[s->spos + 1] != '\n') {
        return 0;
    }
    bc_src_get (s);
    bc_src_get (s);
    return 1;
}

typedef struct {
    bc_interp *ip;
    bc_src    *src;
    int        have;           /* tok holds an unconsumed token */
    bc_tok     tok;
    int        err;            /* a syntax error was reported in this item */
    int        quit;
    int        in_func, func_void, loops;
    int        stray_arrays;   /* NAME[] outside an argument list */
    int        void_calls;     /* calls of functions now defined void */
    bc_arena  *arena;
} bc_parser;

/* A lexical error is reported here; the T_ILLEGAL token that follows it
   then produces the syntax error, as in GNU bc. */
static void
bc_lex_error (bc_parser *p, int line, const char *msg)
{
    if (!p->err) bc_syntax_msg (p->ip, line, msg);
}

static void
bc_lex (bc_parser *p, bc_tok *t)
{
    bc_src *s = p->src;
    int c;

    t->text = NULL;
    t->len = 0;
    t->op = 0;
    for (;;) {
        c = bc_src_peek (s);
        if (c == ' ' || c == '\t') { bc_src_get (s); continue; }
        if (c == '\\' && bc_skip_continuation (s)) continue;
        if (c == '#') {
            while ((c = bc_src_peek (s)) != EOF && c != '\n') bc_src_get (s);
            continue;
        }
        if (c == '/' ) {
            /* a comment, or the division operator */
            int comment = 0;
            if (s->in) {
                bc_input *in = s->in;
                if (in->pos + 1 >= in->len && !in->eof) {
                    memmove (in->buf, in->buf + in->pos, in->len - in->pos);
                    in->len -= in->pos;
                    in->pos = 0;
                    ssize_t got;
                    do
                        got = read (in->fd, in->buf + in->len, sizeof in->buf - in->len);
                    while (got < 0 && errno == EINTR && !interrupt_state && !terminating_signal);
                    if (got < 0) { in->eof = 1; in->error = errno; }
                    else if (got == 0) in->eof = 1;
                    else in->len += (size_t) got;
                }
                comment = in->pos + 1 < in->len && in->buf[in->pos + 1] == '*';
            } else {
                comment = s->spos + 1 < s->slen && s->str[s->spos + 1] == '*';
            }
            if (!comment) break;
            int start = s->line;
            bc_src_get (s);
            bc_src_get (s);
            int prev = 0;
            for (;;) {
                c = bc_src_get (s);
                if (c == EOF) {
                    bc_lex_error (p, start, "EOF encountered in a comment");
                    t->type = T_ILLEGAL;
                    t->line = s->line;
                    return;
                }
                if (prev == '*' && c == '/') break;
                prev = c;
            }
            continue;
        }
        break;
    }

    t->line = s->line;
    c = bc_src_get (s);
    switch (c) {
    case EOF:  t->type = T_EOF; return;
    case '\n': t->type = T_NL; return;
    case '(': case ')': case '[': case ']': case '{': case '}':
    case ',': case ';':
        t->type = c; return;
    case '+': case '-': case '*': case '/': case '%': case '^': {
        int n = bc_src_peek (s);
        if ((c == '+' || c == '-') && n == c) { bc_src_get (s); t->type = c == '+' ? T_INC : T_DEC; return; }
        if (n == '=') { bc_src_get (s); t->type = T_ASSIGN; t->op = c; return; }
        t->type = c;
        return;
    }
    case '=':
        if (bc_src_peek (s) == '=') { bc_src_get (s); t->type = T_EQ; return; }
        t->type = T_ASSIGN; t->op = '=';
        return;
    case '!':
        if (bc_src_peek (s) == '=') { bc_src_get (s); t->type = T_NE; return; }
        t->type = '!';
        return;
    case '<':
        if (bc_src_peek (s) == '=') { bc_src_get (s); t->type = T_LE; return; }
        t->type = '<';
        return;
    case '>':
        if (bc_src_peek (s) == '=') { bc_src_get (s); t->type = T_GE; return; }
        t->type = '>';
        return;
    case '&':
        if (bc_src_peek (s) == '&') { bc_src_get (s); t->type = T_AND; return; }
        break;
    case '|':
        if (bc_src_peek (s) == '|') { bc_src_get (s); t->type = T_OR; return; }
        break;
    case '"': {
        bc_buf b = { NULL, 0, 0 };
        int start = t->line;
        for (;;) {
            c = bc_src_get (s);
            if (c == EOF) {
                free (b.p);
                bc_lex_error (p, start, "EOF encountered in a string");
                t->type = T_ILLEGAL;
                return;
            }
            if (c == '"') break;
            if (!bc_buf_put (&b, c)) { free (b.p); p->ip->fatal = 1; bc_lex_error (p, start, "out of memory"); t->type = T_ILLEGAL; return; }
        }
        if (!b.p) bc_buf_put (&b, 0), b.len = 0;
        t->type = T_STR;
        t->text = b.p;
        t->len = b.len;
        return;
    }
    default:
        break;
    }

    if (bc_is_digit_char (c) || c == '.') {
        if (c == '.') {
            int n = bc_src_peek (s);
            if (!bc_is_digit_char (n) && !(n == '\\')) { t->type = T_LAST; return; }
        }
        bc_tbuf b = { t, { NULL, 0, 0 }, 0, 0 };
        int seen_dot = c == '.';
        bc_tb_put (&b, c);
        for (;;) {
            int n = bc_src_peek (s);
            if (n == '\\' && bc_skip_continuation (s)) continue;
            if (bc_is_digit_char (n)) { bc_tb_put (&b, bc_src_get (s)); continue; }
            if (n == '.' && !seen_dot) { seen_dot = 1; bc_tb_put (&b, bc_src_get (s)); continue; }
            break;
        }
        if (!bc_tb_finish (&b)) { p->ip->fatal = 1; bc_lex_error (p, t->line, "out of memory"); t->type = T_ILLEGAL; return; }
        if (b.len == 1 && t->text[0] == '.') { bc_tok_free (t); t->type = T_LAST; return; }
        t->type = T_NUM;
        return;
    }

    if (c >= 'a' && c <= 'z') {
        bc_tbuf b = { t, { NULL, 0, 0 }, 0, 0 };
        bc_tb_put (&b, c);
        for (;;) {
            int n = bc_src_peek (s);
            if ((n >= 'a' && n <= 'z') || (n >= '0' && n <= '9') || n == '_')
                bc_tb_put (&b, bc_src_get (s));
            else
                break;
        }
        if (!bc_tb_finish (&b)) { p->ip->fatal = 1; bc_lex_error (p, t->line, "out of memory"); t->type = T_ILLEGAL; return; }
        if (b.len <= 8)
            for (size_t k = 0; k < sizeof bc_keywords / sizeof bc_keywords[0]; k++)
                if (bc_keywords[k].word[0] == t->text[0] && !strcmp (t->text, bc_keywords[k].word)) {
                    bc_tok_free (t);
                    t->type = bc_keywords[k].tok;
                    return;
                }
        t->type = T_NAME;
        return;
    }

    {
        char msg[64];
        if (c < 32 || c == 127) snprintf (msg, sizeof msg, "illegal character: ^%c", c == 127 ? '?' : c + 64);
        else snprintf (msg, sizeof msg, "illegal character: %c", c);
        bc_lex_error (p, t->line, msg);
        t->type = T_ILLEGAL;
    }
}

/* ---- parser ------------------------------------------------------ */

static bc_tok *
bc_peek_tok (bc_parser *p)
{
    if (!p->have) {
        bc_lex (p, &p->tok);
        p->have = 1;
    }
    return &p->tok;
}

static int
bc_peek_type (bc_parser *p)
{
    return bc_peek_tok (p)->type;
}

static void
bc_consume (bc_parser *p)
{
    bc_peek_tok (p);
    bc_tok_free (&p->tok);
    p->have = 0;
}

/* Take the current token's text, leaving the token consumed. */
static char *
bc_take_text (bc_parser *p, size_t *len)
{
    bc_peek_tok (p);
    char *text = p->tok.text;
    if (len) *len = p->tok.len;
    if (text == p->tok.sbuf) text = strdup (text);
    p->tok.text = NULL;
    p->have = 0;
    return text;
}

static void
bc_syntax_error (bc_parser *p)
{
    if (!p->err) bc_syntax_msg (p->ip, p->src->line, "syntax error");
    p->err = 1;
}

static void
bc_semantic_error (bc_parser *p, const char *msg)
{
    if (!p->err) bc_syntax_msg (p->ip, p->src->line, msg);
    p->err = 1;
}

static void
bc_parse_failure (bc_parser *p, const char *msg)
{
    p->ip->fatal = 1;
    bc_semantic_error (p, msg);
}

static int
bc_expect (bc_parser *p, int type)
{
    if (p->err) return 0;
    if (bc_peek_type (p) != type) { bc_syntax_error (p); return 0; }
    bc_consume (p);
    return 1;
}

static bc_node *
bc_mk (bc_parser *p, int kind)
{
    bc_block *b = p->arena->blocks;
    if (!b && bc_spare_block) {
        p->arena->blocks = b = bc_spare_block;
        bc_spare_block = NULL;
    }
    if (!b || b->used == b->cap) {
        int cap = b ? (b->cap < 256 ? b->cap * 4 : 256) : BC_FIRST_BLOCK;
        bc_block *nb = malloc (sizeof *nb + sizeof (bc_node) * (size_t) cap);
        if (!nb) { bc_parse_failure (p, "out of memory"); return NULL; }
        nb->next = b;
        nb->used = 0;
        nb->cap = cap;
        p->arena->blocks = b = nb;
    }
    bc_node *n = &b->nodes[b->used++];
    memset (n, 0, sizeof *n);
    n->kind = (short) kind;
    n->line = p->src->line;
    n->cache_base = -1;
    n->pure = -1;
    return n;
}

static bc_node *bc_parse_expr (bc_parser *p);
static bc_node *bc_parse_binary (bc_parser *p, int minprec);
static bc_node *bc_parse_stmt (bc_parser *p);

enum { PREC_OR = 1, PREC_AND, PREC_NOT, PREC_REL, PREC_ASSIGN, PREC_ADD,
       PREC_MUL, PREC_POW, PREC_UNARY };

static int
bc_binop (int type, int *op, int *right)
{
    *right = 0;
    switch (type) {
    case T_OR:  *op = 0; return PREC_OR;
    case T_AND: *op = 0; return PREC_AND;
    case T_EQ:  *op = OP_EQ; return PREC_REL;
    case T_NE:  *op = OP_NE; return PREC_REL;
    case '<':   *op = OP_LT; return PREC_REL;
    case T_LE:  *op = OP_LE; return PREC_REL;
    case '>':   *op = OP_GT; return PREC_REL;
    case T_GE:  *op = OP_GE; return PREC_REL;
    case '+':   *op = OP_ADD; return PREC_ADD;
    case '-':   *op = OP_SUB; return PREC_ADD;
    case '*':   *op = OP_MUL; return PREC_MUL;
    case '/':   *op = OP_DIV; return PREC_MUL;
    case '%':   *op = OP_MOD; return PREC_MUL;
    case '^':   *op = OP_POW; *right = 1; return PREC_POW;
    default:    return 0;
    }
}

static int
bc_is_named (const bc_node *n)
{
    return n && !n->paren && (n->kind == E_VAR || n->kind == E_ELEM || n->kind == E_SPECIAL);
}

/* NAME, NAME[expr], NAME(args), NAME[] (an array argument). */
static bc_node *
bc_parse_name (bc_parser *p)
{
    char local[sizeof p->tok.sbuf], *name;
    bc_node *n = NULL;

    if (p->tok.text == p->tok.sbuf) {
        memcpy (local, p->tok.sbuf, p->tok.len + 1);
        bc_consume (p);
        name = NULL;
    } else {
        name = bc_take_text (p, NULL);
    }
    const char *nm = name ? name : local;
    int type = bc_peek_type (p);

    if (p->err) { free (name); return NULL; }
    if (type == '(') {
        bc_consume (p);
        n = bc_mk (p, E_CALL);
        if (!n) { free (name); return NULL; }
        n->id = bc_func_id (p->ip, nm);
        if (n->id >= 0 && p->ip->funcs[n->id].defined && p->ip->funcs[n->id].is_void)
            p->void_calls++;
        bc_node **tail = &n->a;
        if (bc_peek_type (p) != ')') {
            for (;;) {
                int before = p->stray_arrays;
                bc_node *arg = bc_parse_expr (p);
                if (!arg) break;
                if (p->stray_arrays != before) {
                    if (arg->kind != E_ARRARG || p->stray_arrays != before + 1) {
                        bc_syntax_error (p);
                        break;
                    }
                    p->stray_arrays = before;
                }
                *tail = arg;
                tail = &arg->next;
                n->op++;
                if (bc_peek_type (p) != ',') break;
                bc_consume (p);
            }
        }
        bc_expect (p, ')');
    } else if (type == '[') {
        bc_consume (p);
        if (bc_peek_type (p) == ']') {
            bc_consume (p);
            n = bc_mk (p, E_ARRARG);
            if (n) n->id = bc_array_id (p->ip, nm);
            p->stray_arrays++;
        } else {
            n = bc_mk (p, E_ELEM);
            if (n) {
                n->id = bc_array_id (p->ip, nm);
                n->a = bc_parse_expr (p);
            }
            bc_expect (p, ']');
        }
    } else {
        n = bc_mk (p, E_VAR);
        if (n) n->id = bc_var_id (p->ip, nm);
    }
    if (n && n->id < 0) bc_parse_failure (p, "too many names");
    free (name);
    return p->err ? NULL : n;
}

static bc_node *
bc_parse_builtin1 (bc_parser *p, int kind)
{
    bc_consume (p);
    if (!bc_expect (p, '(')) return NULL;
    bc_node *n = bc_mk (p, kind);
    if (!n) return NULL;
    n->a = bc_parse_expr (p);
    if (!n->a) return NULL;
    if (!bc_expect (p, ')')) return NULL;
    return n;
}

static bc_node *
bc_parse_primary (bc_parser *p)
{
    bc_node *n;
    int type = bc_peek_type (p);

    if (p->err) return NULL;
    if (bc_stack_exhausted (p->ip)) {
        bc_parse_failure (p, "expression nested too deeply");
        return NULL;
    }
    switch (type) {
    case T_NUM:
        n = bc_mk (p, E_NUM);
        if (!n) return NULL;
        if (p->tok.len == 1) {
            /* One digit has the same value in every base: point at a shared
               constant now, with no conversion or allocation per item. */
            n->cache = bc_digit_const (bc_digit_value ((unsigned char) p->tok.text[0]));
            n->cache_base = BC_ANY_BASE;
            bc_consume (p);
            return n;
        }
        n->text = bc_take_text (p, &n->tlen);
        return n;
    case '(':
        bc_consume (p);
        n = bc_parse_expr (p);
        if (!n || !bc_expect (p, ')')) return NULL;
        n->paren = 1;
        return n;
    case T_NAME:
        return bc_parse_name (p);
    case T_SCALE:
        bc_consume (p);
        if (bc_peek_type (p) == '(') {
            bc_consume (p);
            n = bc_mk (p, E_SCALEF);
            if (!n) return NULL;
            n->a = bc_parse_expr (p);
            if (!n->a || !bc_expect (p, ')')) return NULL;
            return n;
        }
        n = bc_mk (p, E_SPECIAL);
        if (n) n->op = SP_SCALE;
        return n;
    case T_IBASE: case T_OBASE: case T_LAST:
        bc_consume (p);
        n = bc_mk (p, E_SPECIAL);
        if (n) n->op = type == T_IBASE ? SP_IBASE : type == T_OBASE ? SP_OBASE : SP_LAST;
        return n;
    case T_LENGTH:
        return bc_parse_builtin1 (p, E_LENGTH);
    case T_SQRT:
        return bc_parse_builtin1 (p, E_SQRT);
    case T_READ:
        bc_consume (p);
        if (!bc_expect (p, '(') || !bc_expect (p, ')')) return NULL;
        return bc_mk (p, E_READ);
    default:
        bc_syntax_error (p);
        return NULL;
    }
}

/* Prefix operators, postfix ++/--, and assignment.  An assignment binds to
   the named expression just before it, and its right side extends over
   + - * / % ^, but not over relational or logical operators: GNU bc's
   grammar gives `a = 3 < 5` the meaning (a = 3) < 5. */
static bc_node *
bc_parse_unary (bc_parser *p)
{
    int type = bc_peek_type (p);
    bc_node *n;

    if (p->err) return NULL;
    if (bc_stack_exhausted (p->ip)) {
        bc_parse_failure (p, "expression nested too deeply");
        return NULL;
    }
    if (type == '-') {
        bc_consume (p);
        n = bc_mk (p, E_NEG);
        if (!n) return NULL;
        n->a = bc_parse_unary (p);
        return n->a ? n : NULL;
    }
    if (type == '!') {
        bc_consume (p);
        n = bc_mk (p, E_NOT);
        if (!n) return NULL;
        n->a = bc_parse_binary (p, PREC_REL);
        return n->a ? n : NULL;
    }
    if (type == T_INC || type == T_DEC) {
        bc_consume (p);
        bc_node *target = bc_parse_primary (p);
        if (!target) return NULL;
        if (!bc_is_named (target)) { bc_syntax_error (p); return NULL; }
        n = bc_mk (p, E_INCDEC);
        if (!n) return NULL;
        n->op = type == T_DEC ? ID_DEC : 0;
        n->a = target;
        return n;
    }

    n = bc_parse_primary (p);
    if (!n) return NULL;
    if (!bc_is_named (n)) return n;
    type = bc_peek_type (p);
    if (type == T_INC || type == T_DEC) {
        bc_consume (p);
        bc_node *inc = bc_mk (p, E_INCDEC);
        if (!inc) return NULL;
        inc->op = ID_POST | (type == T_DEC ? ID_DEC : 0);
        inc->a = n;
        return inc;
    }
    if (type == T_ASSIGN) {
        int op = p->tok.op;
        bc_consume (p);
        bc_node *as = bc_mk (p, E_ASSIGN);
        if (!as) return NULL;
        as->op = (short) op;
        as->a = n;
        as->b = bc_parse_binary (p, PREC_ADD);
        return as->b ? as : NULL;
    }
    return n;
}

static bc_node *
bc_parse_binary (bc_parser *p, int minprec)
{
    bc_node *left = bc_parse_unary (p);

    while (left && !p->err) {
        int op, right;
        int prec = bc_binop (bc_peek_type (p), &op, &right);
        if (!prec || prec < minprec) break;
        int type = p->tok.type;
        bc_consume (p);
        bc_node *rhs = bc_parse_binary (p, right ? prec : prec + 1);
        if (!rhs) return NULL;
        bc_node *n = bc_mk (p, type == T_OR ? E_OR : type == T_AND ? E_AND : E_BIN);
        if (!n) return NULL;
        n->op = (short) op;
        n->a = left;
        n->b = rhs;
        left = n;
    }
    return p->err ? NULL : left;
}

static bc_node *
bc_parse_expr (bc_parser *p)
{
    return bc_parse_binary (p, PREC_OR);
}

/* An expression where a statement needs one: NAME[] may not appear, and
   neither may a call of a function already defined void, except as the
   whole of an expression statement (ALLOW_VOID).  GNU bc rejects the
   misuse when it parses the line, so nothing on that line runs. */
static bc_node *
bc_parse_value_void (bc_parser *p, int allow_void)
{
    int before = p->stray_arrays, voids = p->void_calls;
    bc_node *n = bc_parse_expr (p);
    if (n && p->stray_arrays != before) { bc_syntax_error (p); return NULL; }
    if (n && allow_void && n->kind == E_CALL && !n->paren && p->void_calls == voids + 1)
        p->void_calls = voids;
    if (n && p->void_calls != voids) {
        bc_semantic_error (p, "void function used in an expression");
        return NULL;
    }
    return n;
}

static bc_node *
bc_parse_value (bc_parser *p)
{
    return bc_parse_value_void (p, 0);
}

static void
bc_skip_one_newline (bc_parser *p)
{
    if (bc_peek_type (p) == T_NL) bc_consume (p);
}

static int
bc_stmt_end (int type)
{
    return type == ';' || type == T_NL || type == '}' || type == T_EOF || type == T_ELSE;
}

static void
bc_print_limits (bc_interp *ip)
{
    static const char text[] =
        "BC_BASE_MAX     = 2147483647\n"
        "BC_DIM_MAX      = 16777215\n"
        "BC_SCALE_MAX    = 2147483647\n"
        "BC_STRING_MAX   = 2147483647\n"
        "MAX Exponent    = 9223372036854775807\n"
        "Number of vars  = 32767\n";
    for (const char *c = text; *c; c++) bc_out_char (&ip->out, (unsigned char) *c);
}

static void
bc_print_warranty (bc_interp *ip)
{
    static const char text[] =
        "bc, a bash-os builtin, is distributed under the MIT license\n"
        "WITHOUT ANY WARRANTY; see the LICENSE file of bash-os.\n";
    for (const char *c = text; *c; c++) bc_out_char (&ip->out, (unsigned char) *c);
}

/* Statements inside { }: separated by ';' or newlines. */
static bc_node *
bc_parse_block (bc_parser *p)
{
    bc_node *block = bc_mk (p, S_BLOCK);
    if (!block) return NULL;
    bc_node **tail = &block->a;
    for (;;) {
        int type = bc_peek_type (p);
        if (p->err || p->quit) return NULL;
        if (type == ';' || type == T_NL) { bc_consume (p); continue; }
        if (type == '}') { bc_consume (p); return block; }
        if (type == T_EOF) { bc_syntax_error (p); return NULL; }
        bc_node *s = bc_parse_stmt (p);
        if (!s) return NULL;
        *tail = s;
        tail = &s->next;
        type = bc_peek_type (p);
        if (type != ';' && type != T_NL && type != '}') { bc_syntax_error (p); return NULL; }
    }
}

static bc_node *
bc_parse_stmt (bc_parser *p)
{
    int type = bc_peek_type (p);
    bc_node *n;

    if (p->err) return NULL;
    if (bc_stack_exhausted (p->ip)) {
        bc_parse_failure (p, "statements nested too deeply");
        return NULL;
    }
    switch (type) {
    case '{':
        bc_consume (p);
        return bc_parse_block (p);
    case T_IF:
        bc_consume (p);
        n = bc_mk (p, S_IF);
        if (!n || !bc_expect (p, '(')) return NULL;
        if (!(n->a = bc_parse_value (p)) || !bc_expect (p, ')')) return NULL;
        bc_skip_one_newline (p);
        if (!(n->b = bc_parse_stmt (p))) return NULL;
        if (bc_peek_type (p) == T_ELSE) {
            bc_consume (p);
            bc_skip_one_newline (p);
            if (!(n->c = bc_parse_stmt (p))) return NULL;
        }
        return n;
    case T_WHILE:
        bc_consume (p);
        n = bc_mk (p, S_WHILE);
        if (!n || !bc_expect (p, '(')) return NULL;
        if (!(n->a = bc_parse_value (p)) || !bc_expect (p, ')')) return NULL;
        bc_skip_one_newline (p);
        p->loops++;
        n->b = bc_parse_stmt (p);
        p->loops--;
        return n->b ? n : NULL;
    case T_FOR:
        bc_consume (p);
        n = bc_mk (p, S_FOR);
        if (!n || !bc_expect (p, '(')) return NULL;
        if (bc_peek_type (p) != ';' && !(n->a = bc_parse_value (p))) return NULL;
        if (!bc_expect (p, ';')) return NULL;
        if (bc_peek_type (p) != ';' && !(n->b = bc_parse_value (p))) return NULL;
        if (!bc_expect (p, ';')) return NULL;
        if (bc_peek_type (p) != ')' && !(n->c = bc_parse_value (p))) return NULL;
        if (!bc_expect (p, ')')) return NULL;
        bc_skip_one_newline (p);
        p->loops++;
        n->d = bc_parse_stmt (p);
        p->loops--;
        return n->d ? n : NULL;
    case T_BREAK: case T_CONTINUE:
        bc_consume (p);
        if (!p->loops) {
            bc_semantic_error (p, type == T_BREAK ? "break outside a for/while"
                                                  : "continue outside a for/while");
            return NULL;
        }
        return bc_mk (p, type == T_BREAK ? S_BREAK : S_CONTINUE);
    case T_QUIT:
        bc_consume (p);
        p->quit = 1;
        return NULL;
    case T_HALT:
        bc_consume (p);
        return bc_mk (p, S_HALT);
    case T_RETURN:
        bc_consume (p);
        if (!p->in_func) { bc_semantic_error (p, "return outside of a function"); return NULL; }
        n = bc_mk (p, S_RETURN);
        if (!n) return NULL;
        if (!bc_stmt_end (bc_peek_type (p))) {
            if (p->func_void) { bc_semantic_error (p, "return expression in a void function"); return NULL; }
            if (!(n->a = bc_parse_value (p))) return NULL;
        }
        return n;
    case T_LIMITS:
        bc_consume (p);
        bc_print_limits (p->ip);
        return bc_mk (p, S_EMPTY);
    case T_WARRANTY:
        bc_consume (p);
        bc_print_warranty (p->ip);
        return bc_mk (p, S_EMPTY);
    case T_STR:
        n = bc_mk (p, S_STR);
        if (n) n->text = bc_take_text (p, &n->tlen);
        return n;
    case T_PRINT: {
        bc_consume (p);
        n = bc_mk (p, S_PRINT);
        if (!n) return NULL;
        bc_node **tail = &n->a;
        for (;;) {
            bc_node *item;
            if (bc_peek_type (p) == T_STR) {
                item = bc_mk (p, S_STR);
                if (!item) return NULL;
                item->text = bc_take_text (p, &item->tlen);
            } else if (!(item = bc_parse_value (p))) {
                return NULL;
            }
            *tail = item;
            tail = &item->next;
            if (bc_peek_type (p) != ',') break;
            bc_consume (p);
        }
        return n;
    }
    default:
        n = bc_mk (p, S_EXPR);
        if (!n) return NULL;
        n->a = bc_parse_value_void (p, 1);
        return n->a ? n : NULL;
    }
}

static int
bc_add_param (bc_parser *p, bc_param **list, int *count, int id, int kind)
{
    bc_param *bigger = realloc (*list, sizeof (bc_param) * (size_t) (*count + 1));
    if (!bigger) { bc_parse_failure (p, "out of memory"); return 0; }
    *list = bigger;
    bigger[*count].id = id;
    bigger[*count].kind = kind;
    ++*count;
    return 1;
}

/* define [void] NAME ( params ) [newline] { [auto list] statements } */
static void
bc_parse_define (bc_parser *p)
{
    bc_interp *ip = p->ip;
    bc_func f;
    bc_arena arena = { NULL };
    bc_arena *outer = p->arena;
    char *name = NULL;

    memset (&f, 0, sizeof f);
    bc_consume (p);
    if (bc_peek_type (p) != T_NAME) { bc_syntax_error (p); return; }
    name = bc_take_text (p, NULL);
    if (!strcmp (name, "void") && bc_peek_type (p) == T_NAME) {
        free (name);
        name = bc_take_text (p, NULL);
        f.is_void = 1;
    }
    if (!bc_expect (p, '(')) goto fail;

    p->arena = &arena;
    if (bc_peek_type (p) != ')') {
        for (;;) {
            int ref = 0, kind = 0;
            if (bc_peek_type (p) == '*') { bc_consume (p); ref = 1; }
            if (bc_peek_type (p) != T_NAME) { bc_syntax_error (p); goto fail; }
            char *pname = bc_take_text (p, NULL);
            if (bc_peek_type (p) == '[') {
                bc_consume (p);
                if (!bc_expect (p, ']')) { free (pname); goto fail; }
                kind = ref ? 2 : 1;
            } else if (ref) {
                free (pname);
                bc_syntax_error (p);
                goto fail;
            }
            int id = kind ? bc_array_id (ip, pname) : bc_var_id (ip, pname);
            free (pname);
            if (id < 0) { bc_parse_failure (p, "too many names"); goto fail; }
            for (int i = 0; i < f.nparams; i++)
                if (f.params[i].id == id && (f.params[i].kind != 0) == (kind != 0)) {
                    bc_semantic_error (p, "duplicate parameter names");
                    goto fail;
                }
            if (!bc_add_param (p, &f.params, &f.nparams, id, kind)) goto fail;
            if (bc_peek_type (p) != ',') break;
            bc_consume (p);
        }
    }
    if (!bc_expect (p, ')')) goto fail;
    bc_skip_one_newline (p);
    if (!bc_expect (p, '{')) goto fail;
    while (bc_peek_type (p) == T_NL) bc_consume (p);
    if (bc_peek_type (p) == T_AUTO) {
        bc_consume (p);
        for (;;) {
            if (bc_peek_type (p) != T_NAME) { bc_syntax_error (p); goto fail; }
            char *aname = bc_take_text (p, NULL);
            int kind = 0;
            if (bc_peek_type (p) == '[') {
                bc_consume (p);
                if (!bc_expect (p, ']')) { free (aname); goto fail; }
                kind = 1;
            }
            int id = kind ? bc_array_id (ip, aname) : bc_var_id (ip, aname);
            free (aname);
            if (id < 0) { bc_parse_failure (p, "too many names"); goto fail; }
            for (int i = 0; i < f.nparams; i++)
                if (f.params[i].id == id && (f.params[i].kind != 0) == (kind != 0)) {
                    bc_semantic_error (p, "variable in both parameter and auto lists");
                    goto fail;
                }
            for (int i = 0; i < f.nautos; i++)
                if (f.autos[i].id == id && (f.autos[i].kind != 0) == (kind != 0)) {
                    bc_semantic_error (p, "duplicate auto variable names");
                    goto fail;
                }
            if (!bc_add_param (p, &f.autos, &f.nautos, id, kind)) goto fail;
            if (bc_peek_type (p) != ',') break;
            bc_consume (p);
        }
        int type = bc_peek_type (p);
        if (type != ';' && type != T_NL) { bc_syntax_error (p); goto fail; }
        bc_consume (p);
    }

    p->in_func = 1;
    p->func_void = f.is_void;
    p->loops = 0;
    f.body = bc_parse_block (p);
    p->in_func = 0;
    p->func_void = 0;
    if (!f.body || p->err || p->quit) goto fail;

    int id = bc_func_id (ip, name);
    if (id < 0) { bc_parse_failure (p, "too many names"); goto fail; }
    bc_func *old = &ip->funcs[id];
    int native = old->native;
    bc_arena_free (&old->arena);
    free (old->params);
    free (old->autos);
    f.defined = 1;
    f.native = native;
    f.arena = arena;
    *old = f;
    p->arena = outer;
    free (name);
    return;

fail:
    p->in_func = 0;
    p->func_void = 0;
    p->arena = outer;
    bc_arena_free (&arena);
    free (f.params);
    free (f.autos);
    free (name);
    if (!p->err && !p->quit) bc_syntax_error (p);
}

/* ---- evaluation -------------------------------------------------- */

enum { ST_OK, ST_BREAK, ST_CONTINUE, ST_RETURN, ST_HALT, ST_ERROR };

static bc_num bc_eval (bc_interp *ip, bc_node *n);
static int bc_exec (bc_interp *ip, bc_node *s);
static int bc_run_item (bc_interp *ip, bc_node *list);

static bc_num
bc_zero (void)
{
    return bc_dup (&_bc_zero);
}

/* Integer part of V as a long, saturating; *BIG is set when it does not
   fit (or exceeds LIMIT). */
static long
bc_to_long (const bc_num *v, long limit, int *big)
{
    int intpart = v->len - v->scale;
    long r = 0;
    *big = 0;
    for (int i = 0; i < intpart; i++) {
        int digit = v->digits[i] - '0';
        if (r > (limit - digit) / 10) { *big = 1; return limit; }
        r = r * 10 + digit;
    }
    return r;
}

static int
bc_check_interrupt (bc_interp *ip)
{
    if (interrupt_state || terminating_signal) {
        ip->stop = 1;
        return 1;
    }
    return 0;
}

static BC_NOINLINE bc_num
bc_special_get (bc_interp *ip, int which)
{
    switch (which) {
    case SP_SCALE: return bc_from_int (ip->scale);
    case SP_IBASE: return bc_from_int (ip->ibase);
    case SP_OBASE: return bc_from_int (ip->obase);
    default:       return bc_dup (&ip->last);
    }
}

static BC_NOINLINE void
bc_special_set (bc_interp *ip, int which, const bc_num *v)
{
    int big;
    long x;

    if (which == SP_LAST) {
        bc_free (&ip->last);
        ip->last = bc_dup (v);
        return;
    }
    x = bc_to_long (v, LONG_MAX, &big);
    if (v->sign && !bc_is_zero (v)) x = -x;
    switch (which) {
    case SP_SCALE:
        if (v->sign && x < 0) { bc_rt_warn (ip, "negative scale, set to 0"); x = 0; }
        else if (big || x > INT_MAX) { bc_rt_warn (ip, "scale too large, set to 2147483647"); x = INT_MAX; }
        ip->scale = (int) x;
        break;
    case SP_IBASE:
        if (x < 2) { bc_rt_warn (ip, "ibase too small, set to 2"); x = 2; }
        else if (big || x > 36) { bc_rt_warn (ip, "ibase too large, set to 36"); x = 36; }
        ip->ibase = (int) x;
        break;
    case SP_OBASE:
        if (x < 2) { bc_rt_warn (ip, "obase too small, set to 2"); x = 2; }
        else if (big || x > INT_MAX) { bc_rt_warn (ip, "obase too large, set to 2147483647"); x = INT_MAX; }
        ip->obase = x;
        break;
    }
}

/* Array subscript of an E_ELEM node, or -1 after reporting an error. */
static BC_NOINLINE long
bc_subscript (bc_interp *ip, bc_node *n)
{
    bc_num v = bc_eval (ip, n->a);
    int big;
    long idx;
    if (ip->err) { bc_free (&v); return -1; }
    idx = bc_to_long (&v, BC_INDEX_MAX + 1, &big);
    /* GNU converts with bc_num2long, whose 0 is also its overflow answer,
       so a nonzero subscript that truncates to 0 (a[.9], a[-.5]) is
       out of bounds too. */
    if ((v.sign && !bc_is_zero (&v)) || big || idx > BC_INDEX_MAX
        || (idx == 0 && !bc_is_zero (&v))) {
        bc_rt_error (ip, "array %s subscript out of bounds", ip->anames.names[n->id]);
        idx = -1;
    }
    bc_free (&v);
    return idx;
}

/* Read a named expression; IDX is the evaluated subscript for elements. */
static bc_num
bc_named_get (bc_interp *ip, bc_node *n, long idx)
{
    if (n->kind == E_VAR) {
        bc_num *v = &ip->vars[n->id];
        return v->digits ? bc_dup (v) : bc_zero ();
    }
    if (n->kind == E_SPECIAL) return bc_special_get (ip, n->op);
    bc_array *a = ip->arrays[n->id];
    bc_num *slot = a ? bc_array_slot (a, idx, 0) : NULL;
    return slot && slot->digits ? bc_dup (slot) : bc_zero ();
}

/* Store V, taking ownership of it. */
static void
bc_named_put (bc_interp *ip, bc_node *n, long idx, bc_num *v)
{
    bc_num *slot;
    if (n->kind == E_SPECIAL) { bc_special_set (ip, n->op, v); bc_free (v); return; }
    if (n->kind == E_VAR) {
        slot = &ip->vars[n->id];
    } else {
        bc_array *a = bc_array_get (ip, n->id);
        slot = a ? bc_array_slot (a, idx, 1) : NULL;
        if (!slot) { bc_free (v); bc_rt_failure (ip, "out of memory", NULL); return; }
    }
    if (slot->digits) bc_free (slot);
    *slot = *v;
}

static int
bc_compare_op (int op, int c)
{
    return op == OP_EQ ? c == 0 : op == OP_NE ? c != 0 : op == OP_LT ? c < 0
         : op == OP_LE ? c <= 0 : op == OP_GT ? c > 0 : c >= 0;
}

/* A binary arithmetic operation, with bc's runtime errors. */
static BC_NOINLINE bc_num
bc_arith (bc_interp *ip, int op, const bc_num *l, const bc_num *r)
{
    switch (op) {
    case OP_ADD: return bc_add (l, r, ip->scale);
    case OP_SUB: return bc_sub (l, r, ip->scale);
    case OP_MUL: return bc_mul (l, r, ip->scale);
    case OP_DIV:
        if (bc_is_zero (r)) { bc_rt_error (ip, "divide by zero", NULL); return bc_zero (); }
        return bc_div (l, r, ip->scale);
    case OP_MOD:
        if (bc_is_zero (r)) { bc_rt_error (ip, "modulo by zero", NULL); return bc_zero (); }
        return bc_mod (l, r, ip->scale);
    case OP_POW: {
        int big;
        if (r->scale > 0) bc_rt_warn (ip, "non-zero scale in exponent");
        bc_to_long (r, LONG_MAX, &big);
        if (big) { bc_rt_error (ip, "exponent too large in raise", NULL); return bc_zero (); }
        if (bc_is_zero (l) && r->sign && !bc_is_zero (r)) {
            bc_rt_error (ip, "divide by zero", NULL);
            return bc_zero ();
        }
        return bc_pow (l, r, ip->scale);
    }
    default:
        return bc_dup (bc_compare_op (op, bc_cmp (l, r)) ? &_bc_one : &_bc_zero);
    }
}

static int bc_is_void_call (bc_interp *ip, bc_node *n);
static bc_num bc_call (bc_interp *ip, bc_node *n, int allow_void);
static bc_num bc_read (bc_interp *ip);

/* Can evaluating N change a variable, call a function or read input?  The
   answer is cached in the node. */
static int
bc_pure (bc_interp *ip, bc_node *n)
{
    if (!n) return 1;
    if (n->pure < 0) {
        /* This walk can be deeper than the parser for a left-associated
           expression. Conservatively disable borrowing at the stack bound. */
        if (bc_stack_exhausted (ip)) return 0;
        switch (n->kind) {
        case E_ASSIGN: case E_INCDEC: case E_CALL: case E_READ: case E_ARRARG:
            n->pure = 0;
            break;
        default:
            n->pure = bc_pure (ip, n->a) && bc_pure (ip, n->b);
        }
    }
    return n->pure;
}

/* GNU fixes constant conversion to the input base at function entry,
   although assignments to ibase immediately affect subsequent calls. */
static const bc_num *
bc_constant (bc_interp *ip, bc_node *n)
{
    int base = ip->call_base ? ip->call_base : ip->ibase;
    if (n->cache_base != base && n->cache_base != BC_ANY_BASE) {
        if (n->cache.digits) bc_free (&n->cache);
        n->cache = bc_str2num (n->text, n->tlen, base);
        n->cache_base = base;
    }
    return &n->cache;
}

/* The value of N without a copy when it is already stored: a variable or a
   converted constant is returned in place, anything else is evaluated into
   *TMP (TMP->digits is NULL when nothing was allocated).  A borrowed value
   stays valid only until something assigns or parses. */
static const bc_num *
bc_eval_ref (bc_interp *ip, bc_node *n, bc_num *tmp)
{
    tmp->digits = NULL;
    if (!ip->err && !ip->stop) {
        if (n->kind == E_VAR)
            return ip->vars[n->id].digits ? &ip->vars[n->id] : &_bc_zero;
        if (n->kind == E_NUM)
            return bc_constant (ip, n);
    }
    *tmp = bc_eval (ip, n);
    return tmp;
}

static void
bc_release (bc_num *tmp)
{
    if (tmp->digits) bc_free (tmp);
}

/* The two operands of a binary operator, left first.  The left one may be
   borrowed only when evaluating the right one cannot change it. */
static void
bc_operands (bc_interp *ip, bc_node *n, const bc_num **l, bc_num *lt,
             const bc_num **r, bc_num *rt)
{
    if (bc_pure (ip, n->b)) {
        *l = bc_eval_ref (ip, n->a, lt);
    } else {
        *lt = bc_eval (ip, n->a);
        *l = lt;
    }
    *r = bc_eval_ref (ip, n->b, rt);
}

/* Is N true (nonzero)?  Conditions of if, while and for use this, so a
   comparison costs no allocation for its 0 or 1. */
static int
bc_truth (bc_interp *ip, bc_node *n)
{
    if (n->kind == E_BIN && n->op >= OP_EQ) {
        const bc_num *l, *r;
        bc_num lt, rt;
        bc_operands (ip, n, &l, &lt, &r, &rt);
        int t = ip->err ? 0 : bc_compare_op (n->op, bc_cmp (l, r));
        bc_release (&lt);
        bc_release (&rt);
        return t;
    }
    bc_num tmp;
    const bc_num *v = bc_eval_ref (ip, n, &tmp);
    int t = !ip->err && !bc_is_zero (v);
    bc_release (&tmp);
    return t;
}

/* An assignment or ++/--.  The value is returned only when WANT is set;
   a statement or a for-loop step that discards it saves the copy. */
static BC_NOINLINE bc_num
bc_update (bc_interp *ip, bc_node *n, int want)
{
    static const char ops[] = "+-*/%^";
    static const int codes[] = { OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD, OP_POW };
    bc_node *t = n->a;
    long idx = 0;
    bc_num l, r, v, none = { 0, NULL, 0, 0 };

    if (ip->err || ip->stop) return want ? bc_zero () : none;
    if (t->kind == E_ELEM && (idx = bc_subscript (ip, t)) < 0) return want ? bc_zero () : none;

    if (n->kind == E_INCDEC) {
        const bc_num *old;
        int borrowed = t->kind == E_VAR;
        l.digits = NULL;
        if (borrowed) old = ip->vars[t->id].digits ? &ip->vars[t->id] : &_bc_zero;
        else { l = bc_named_get (ip, t, idx); old = &l; }
        v = n->op & ID_DEC ? bc_sub (old, &_bc_one, 0) : bc_add (old, &_bc_one, 0);
        r = none;
        if (want) r = (n->op & ID_POST) ? (borrowed ? bc_dup (old) : l) : bc_dup (&v);
        if (!want || !(n->op & ID_POST) || borrowed) bc_release (&l);
        bc_named_put (ip, t, idx, &v);
        return r;
    }

    if (bc_is_void_call (ip, n->b)) {
        bc_rt_error (ip, "assignment of a void expression", NULL);
        return want ? bc_zero () : none;
    }
    if (n->op == '=') {
        r = bc_eval (ip, n->b);
    } else {
        /* x op= e loads x before evaluating e, as GNU's code does:
           x = 5; x += x -= 3 leaves 7.  When e cannot change anything, x
           is read in place. */
        const bc_num *lp, *rp;
        bc_num rt;
        l.digits = NULL;
        if (t->kind == E_VAR && bc_pure (ip, n->b))
            lp = ip->vars[t->id].digits ? &ip->vars[t->id] : &_bc_zero;
        else { l = bc_named_get (ip, t, idx); lp = &l; }
        rp = bc_eval_ref (ip, n->b, &rt);
        r = ip->err ? bc_zero () : bc_arith (ip, codes[strchr (ops, n->op) - ops], lp, rp);
        bc_release (&l);
        bc_release (&rt);
    }
    if (ip->err) { bc_free (&r); return want ? bc_zero () : none; }
    v = want ? bc_dup (&r) : none;
    bc_named_put (ip, t, idx, &r);
    return v;
}

static bc_num
bc_eval (bc_interp *ip, bc_node *n)
{
    bc_num l, r, v;

    if (ip->err || ip->stop) return bc_zero ();
    if (bc_stack_exhausted (ip)) {
        bc_rt_failure (ip, "expression nested too deeply", NULL);
        return bc_zero ();
    }
    switch (n->kind) {
    case E_NUM:
        return bc_dup (bc_constant (ip, n));
    case E_VAR:
        v = ip->vars[n->id];
        return v.digits ? bc_dup (&v) : bc_zero ();
    case E_SPECIAL:
        return bc_special_get (ip, n->op);
    case E_ELEM: {
        long idx = bc_subscript (ip, n);
        if (idx < 0) return bc_zero ();
        return bc_named_get (ip, n, idx);
    }
    case E_NEG:                     /* 0 - v: never a negative zero */
        v = bc_eval (ip, n->a);
        v.sign = !bc_is_zero (&v) && !v.sign;
        return v;
    case E_NOT:
        v = bc_eval (ip, n->a);
        r = bc_from_int (bc_is_zero (&v));
        bc_free (&v);
        return r;
    case E_AND:
        /* GNU's code for && leaves a zero operand itself as the value
           (with its scale and sign); otherwise the value is 1. */
        v = bc_eval (ip, n->a);
        if (ip->err || bc_is_zero (&v)) return v;
        bc_free (&v);
        v = bc_eval (ip, n->b);
        if (ip->err || bc_is_zero (&v)) return v;
        bc_free (&v);
        return bc_from_int (1);
    case E_OR: {
        v = bc_eval (ip, n->a);
        int truth = !bc_is_zero (&v);
        bc_free (&v);
        if (ip->err || truth) return bc_from_int (truth);
        v = bc_eval (ip, n->b);
        truth = !bc_is_zero (&v);
        bc_free (&v);
        return bc_from_int (truth);
    }
    case E_BIN: {
        const bc_num *lp, *rp;
        bc_operands (ip, n, &lp, &l, &rp, &r);
        v = ip->err ? bc_zero () : bc_arith (ip, n->op, lp, rp);
        bc_release (&l);
        bc_release (&r);
        return v;
    }
    case E_ASSIGN:
    case E_INCDEC:
        return bc_update (ip, n, 1);
    case E_CALL:
        return bc_call (ip, n, 0);
    case E_ARRARG:
        bc_rt_error (ip, "array used as a value", NULL);
        return bc_zero ();
    case E_LENGTH:
        v = bc_eval (ip, n->a);
        r = bc_from_int (bc_length (&v));
        bc_free (&v);
        return r;
    case E_SCALEF:
        v = bc_eval (ip, n->a);
        r = bc_from_int (v.scale);
        bc_free (&v);
        return r;
    case E_SQRT:
        v = bc_eval (ip, n->a);
        if (ip->err) { bc_free (&v); return bc_zero (); }
        if (v.sign) {               /* including GNU's -0 */
            bc_free (&v);
            bc_rt_error (ip, "square root of a negative number", NULL);
            return bc_zero ();
        }
        r = bc_sqrt (&v, ip->scale);
        bc_free (&v);
        return r;
    case E_READ:
        return bc_read (ip);
    }
    return bc_zero ();
}

static int
bc_is_void_call (bc_interp *ip, bc_node *n)
{
    if (!n || n->kind != E_CALL) return 0;
    bc_func *f = &ip->funcs[n->id];
    return f->defined && f->is_void;
}

/* Mathlib routines, available under -l until a program redefines them. */
static const char *const bc_lib_names[] = { "s", "c", "a", "l", "e", "j" };

static bc_num
bc_call_native (bc_interp *ip, int which, bc_num *args)
{
    switch (which) {
    case 1: return bc_func_s (&args[0], ip->scale);
    case 2: return bc_func_c (&args[0], ip->scale);
    case 3: return bc_func_a (&args[0], ip->scale);
    case 4: return bc_func_l (&args[0], ip->scale);
    case 5: return bc_func_e (&args[0], ip->scale);
    default: return bc_func_j (&args[0], &args[1], ip->scale);
    }
}

static int
bc_save (bc_interp *ip, int kind, int id)
{
    if (ip->nsaved == ip->capsaved) {
        int cap = ip->capsaved ? ip->capsaved * 2 : 32;
        bc_saved *s = realloc (ip->saved, sizeof (bc_saved) * (size_t) cap);
        if (!s) return 0;
        ip->saved = s;
        ip->capsaved = cap;
    }
    bc_saved *e = &ip->saved[ip->nsaved++];
    e->kind = kind;
    e->id = id;
    if (kind == 0) {
        e->num = ip->vars[id];
        memset (&ip->vars[id], 0, sizeof (bc_num));
        e->arr = NULL;
    } else {
        e->arr = ip->arrays[id];
        ip->arrays[id] = NULL;
        memset (&e->num, 0, sizeof e->num);
    }
    return 1;
}

static BC_NOINLINE void
bc_restore_to (bc_interp *ip, int mark)
{
    while (ip->nsaved > mark) {
        bc_saved *e = &ip->saved[--ip->nsaved];
        if (e->kind == 0) {
            if (ip->vars[e->id].digits) bc_free (&ip->vars[e->id]);
            ip->vars[e->id] = e->num;
        } else {
            bc_array_release (ip->arrays[e->id]);
            ip->arrays[e->id] = e->arr;
        }
    }
}

/* A call of a library routine (-l). */
static BC_NOINLINE bc_num
bc_call_lib (bc_interp *ip, bc_func *f, bc_node *n)
{
    bc_num args[2];
    /* read() in an argument may intern function names and move ip->funcs. */
    int native = f->native;
    int want = native == 6 ? 2 : 1, got = 0;
    if (n->op != want) { bc_rt_error (ip, "parameter number mismatch", NULL); return bc_zero (); }
    for (bc_node *a = n->a; a; a = a->next) {
        if (a->kind == E_ARRARG) {
            while (got > 0) bc_free (&args[--got]);
            bc_rt_error (ip, "parameter type mismatch", NULL);
            return bc_zero ();
        }
        args[got++] = bc_eval (ip, a);
    }
    bc_num r = ip->err ? bc_zero () : bc_call_native (ip, native, args);
    while (got > 0) bc_free (&args[--got]);
    return r;
}

/* Evaluate the arguments of call N in the caller's scope, then save the
   caller's values of the parameters and autos and bind the new ones.
   Returns the save-stack mark to restore to, or -1 after an error (with
   nothing left bound).  Kept out of bc_call so that the frame recursion
   passes through stays small. */
static BC_NOINLINE int
bc_bind (bc_interp *ip, bc_func *f, bc_node *n)
{
    /* read() parses expressions while binding arguments. Its name interning
       may reallocate the function vector; the definition's owned arrays and
       body remain stable, so keep the metadata outside that vector. */
    bc_func definition = *f;
    f = &definition;
    bc_num small_vals[8];
    bc_array *small_arrs[8];
    int np = f->nparams;
    bc_num *vals = small_vals;
    bc_array **arrs = small_arrs;

    if (np > 8) {
        vals = malloc (sizeof (bc_num) * (size_t) np);
        arrs = malloc (sizeof (bc_array *) * (size_t) np);
        if (!vals || !arrs) {
            free (vals); free (arrs);
            bc_rt_failure (ip, "out of memory", NULL);
            return -1;
        }
    }
    memset (vals, 0, sizeof (bc_num) * (size_t) np);
    memset (arrs, 0, sizeof (bc_array *) * (size_t) np);

    int i = 0;
    for (bc_node *a = n->a; a && !ip->err; a = a->next, i++) {
        bc_param *par = &f->params[i];
        if ((a->kind == E_ARRARG) != (par->kind != 0)) {
            bc_rt_error (ip, "parameter type mismatch, parameter %s",
                         par->kind ? ip->anames.names[par->id] : ip->vnames.names[par->id]);
            break;
        }
        if (par->kind == 0) {
            vals[i] = bc_eval (ip, a);
        } else {
            bc_array *src = bc_array_get (ip, a->id);
            if (par->kind == 2) { arrs[i] = src; if (src) src->refs++; }
            else arrs[i] = bc_array_copy (src);
            if (!arrs[i]) bc_rt_failure (ip, "out of memory", NULL);
        }
    }

    int mark = ip->nsaved;
    if (!ip->err) {
        for (i = 0; i < np; i++) {
            bc_param *par = &f->params[i];
            if (!bc_save (ip, par->kind != 0, par->id)) { bc_rt_failure (ip, "out of memory", NULL); break; }
            if (par->kind == 0) { ip->vars[par->id] = vals[i]; memset (&vals[i], 0, sizeof vals[i]); }
            else { ip->arrays[par->id] = arrs[i]; arrs[i] = NULL; }
        }
        for (i = 0; i < f->nautos && !ip->err; i++)
            if (!bc_save (ip, f->autos[i].kind, f->autos[i].id)) bc_rt_failure (ip, "out of memory", NULL);
    }
    for (i = 0; i < np; i++) {
        if (vals[i].digits) bc_free (&vals[i]);
        bc_array_release (arrs[i]);
    }
    if (vals != small_vals) { free (vals); free (arrs); }
    if (ip->err) { bc_restore_to (ip, mark); return -1; }
    return mark;
}

static bc_num
bc_call (bc_interp *ip, bc_node *n, int allow_void)
{
    bc_func *f = &ip->funcs[n->id];

    if (ip->err || ip->stop) return bc_zero ();
    if (!f->defined && !f->native) {
        bc_rt_error (ip, "function %s not defined", ip->fnames.names[n->id]);
        return bc_zero ();
    }
    if (f->defined && f->is_void && !allow_void) {
        bc_rt_error (ip, "void function %s used in an expression", ip->fnames.names[n->id]);
        return bc_zero ();
    }
    if (!f->defined) return bc_call_lib (ip, f, n);
    if (n->op != f->nparams) { bc_rt_error (ip, "parameter number mismatch", NULL); return bc_zero (); }
    if (bc_stack_exhausted (ip)) { bc_rt_failure (ip, "function calls nested too deeply", NULL); return bc_zero (); }
    if (bc_check_interrupt (ip)) return bc_zero ();

    int mark = bc_bind (ip, f, n);
    if (mark < 0) return bc_zero ();
    f = &ip->funcs[n->id];

    bc_num result = { 0, NULL, 0, 0 };
    const char *caller = ip->func;
    int line = ip->line;
    int caller_base = ip->call_base;
    ip->call_base = ip->ibase;
    ip->func = ip->fnames.names[n->id];
    if (bc_exec (ip, f->body) == ST_RETURN) {
        result = ip->retval;
        memset (&ip->retval, 0, sizeof ip->retval);
    }
    ip->func = caller;
    ip->line = line;
    ip->call_base = caller_base;
    bc_restore_to (ip, mark);
    if (!result.digits) result = bc_zero ();
    if (ip->err || ip->stop) { bc_free (&result); return bc_zero (); }
    return result;
}

/* read(): one line of standard input, evaluated as an expression. */
static BC_NOINLINE bc_num
bc_read (bc_interp *ip)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t n = bc_input_line (ip->stdin_in, &line, &cap);
    if (ip->stdin_in->error) {
        bc_rt_failure (ip, "read(): %s", strerror (ip->stdin_in->error));
        free (line);
        return bc_zero ();
    }
    if (n < 0) { free (line); return bc_zero (); }

    bc_src src = { NULL, line, (size_t) n, 0, "(read)", 1 };
    bc_arena arena = { NULL };
    bc_parser rp;
    memset (&rp, 0, sizeof rp);
    rp.ip = ip;
    rp.src = &src;
    rp.arena = &arena;

    bc_src *outer = ip->src;
    int outer_line = ip->line;
    ip->src = &src;
    bc_node *e = bc_parse_value (&rp);
    if (e && bc_peek_type (&rp) != T_EOF) bc_syntax_error (&rp);
    if (rp.have) bc_tok_free (&rp.tok);
    ip->src = outer;
    ip->line = outer_line;

    bc_num v;
    if (!e || rp.err) {
        ip->err = 1;              /* the syntax error has been reported */
        v = bc_zero ();
    } else {
        int caller_base = ip->call_base;
        ip->call_base = 0;        /* input is converted in the current ibase */
        v = bc_eval (ip, e);
        ip->call_base = caller_base;
    }
    bc_arena_free (&arena);
    free (line);
    return v;
}

static void
bc_print_string (bc_interp *ip, const char *s, size_t n, int escapes)
{
    for (size_t i = 0; i < n; i++) {
        int c = (unsigned char) s[i];
        if (escapes && c == '\\') {
            if (++i >= n) break;
            switch (s[i]) {
            case 'a': c = '\a'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'n': c = '\n'; break;
            case 'q': c = '"'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case '\\': c = '\\'; break;
            default: continue;   /* GNU bc drops an unknown escape */
            }
        }
        bc_out_char (&ip->out, c);
    }
}

static void
bc_set_last (bc_interp *ip, const bc_num *v)
{
    bc_free (&ip->last);
    ip->last = bc_dup (v);
}

static int
bc_check_output (bc_interp *ip)
{
    if (ip->out.len > sizeof ip->out.buf / 2) {
        bc_out_flush (&ip->out);
        if (ferror (stdout)) { ip->stop = 1; return 0; }
    }
    return 1;
}

/* Evaluate N for its effect only. */
static void
bc_discard (bc_interp *ip, bc_node *n)
{
    bc_num v = (n->kind == E_ASSIGN || n->kind == E_INCDEC) ? bc_update (ip, n, 0) : bc_eval (ip, n);
    bc_release (&v);
}

/* Expression, string and print statements, kept out of bc_exec so that the
   frame recursion passes through stays small. */
static BC_NOINLINE int
bc_exec_output (bc_interp *ip, bc_node *s)
{
    bc_num v;

    switch (s->kind) {
    case S_EXPR: {
        bc_node *e = s->a;
        if (e->kind == E_ASSIGN && !e->paren) {      /* silent: no value needed */
            bc_update (ip, e, 0);
            if (ip->err) return ST_ERROR;
            return ip->stop ? ST_HALT : ST_OK;
        }
        int is_void = bc_is_void_call (ip, e);
        v = e->kind == E_CALL ? bc_call (ip, e, 1) : bc_eval (ip, e);
        if (ip->err) { bc_free (&v); return ST_ERROR; }
        if (ip->stop) { bc_free (&v); return ST_HALT; }
        if ((e->kind != E_ASSIGN || e->paren) && !is_void) {
            bc_out_num (&ip->out, &v, ip->obase);
            bc_out_char (&ip->out, '\n');
            bc_set_last (ip, &v);
        }
        bc_free (&v);
        return bc_check_output (ip) ? ST_OK : ST_HALT;
    }
    case S_STR:
        bc_print_string (ip, s->text, s->tlen, 0);
        return bc_check_output (ip) ? ST_OK : ST_HALT;
    case S_PRINT:
        for (bc_node *item = s->a; item; item = item->next) {
            if (item->kind == S_STR) {
                bc_print_string (ip, item->text, item->tlen, 1);
                continue;
            }
            v = bc_eval (ip, item);
            if (ip->err) { bc_free (&v); return ST_ERROR; }
            if (ip->stop) { bc_free (&v); return ST_HALT; }
            bc_out_num (&ip->out, &v, ip->obase);
            bc_set_last (ip, &v);
            bc_free (&v);
        }
        return bc_check_output (ip) ? ST_OK : ST_HALT;
    }
    return ST_OK;
}

static int
bc_exec (bc_interp *ip, bc_node *s)
{
    int st;

    if (ip->err) return ST_ERROR;
    if (ip->stop) return ST_HALT;
    ip->line = s->line;
    if (bc_stack_exhausted (ip)) {
        bc_rt_failure (ip, "statements nested too deeply", NULL);
        return ST_ERROR;
    }
    switch (s->kind) {
    case S_EMPTY:
        return ST_OK;
    case S_EXPR: case S_STR: case S_PRINT:
        return bc_exec_output (ip, s);
    case S_BLOCK:
        for (bc_node *c = s->a; c; c = c->next)
            if ((st = bc_exec (ip, c)) != ST_OK) return st;
        return ST_OK;
    case S_IF:
        st = bc_truth (ip, s->a);
        if (ip->err) return ST_ERROR;
        if (st) return bc_exec (ip, s->b);
        return s->c ? bc_exec (ip, s->c) : ST_OK;
    case S_WHILE:
    case S_FOR:
        if (s->kind == S_FOR && s->a) bc_discard (ip, s->a);
        for (;;) {
            bc_node *cond = s->kind == S_FOR ? s->b : s->a;
            if (bc_check_interrupt (ip)) return ST_HALT;
            if (ip->err) return ST_ERROR;
            if (cond) {
                ip->line = s->line;
                int truth = bc_truth (ip, cond);
                if (ip->err) return ST_ERROR;
                if (!truth) break;
            }
            st = bc_exec (ip, s->kind == S_FOR ? s->d : s->b);
            if (st == ST_BREAK) break;
            if (st != ST_OK && st != ST_CONTINUE) return st;
            if (s->kind == S_FOR && s->c) bc_discard (ip, s->c);
        }
        return ip->err ? ST_ERROR : ST_OK;
    case S_BREAK:
        return ST_BREAK;
    case S_CONTINUE:
        return ST_CONTINUE;
    case S_RETURN:
        if (ip->retval.digits) bc_free (&ip->retval);
        if (s->a) {
            if (bc_is_void_call (ip, s->a)) { bc_rt_error (ip, "return of a void expression", NULL); return ST_ERROR; }
            ip->retval = bc_eval (ip, s->a);
            if (ip->err) { bc_free (&ip->retval); return ST_ERROR; }
        } else {
            ip->retval = bc_zero ();
        }
        return ST_RETURN;
    case S_HALT:
        ip->stop = 1;
        return ST_HALT;
    }
    return ST_OK;
}

static int
bc_run_item (bc_interp *ip, bc_node *list)
{
    for (bc_node *s = list; s; s = s->next) {
        int st = bc_exec (ip, s);
        if (st != ST_OK) return st;
    }
    return ST_OK;
}

/* ---- driver ------------------------------------------------------ */

/* Parse and run every item of one source.  Returns 0 normally, 1 when bc
   should stop (quit, halt, interrupt, output failure). */
static int
bc_run_source (bc_interp *ip, bc_src *src)
{
    bc_parser p;
    memset (&p, 0, sizeof p);
    p.ip = ip;
    p.src = src;
    ip->src = src;

    while (!ip->stop) {
        bc_arena arena = { NULL };
        bc_node *list = NULL, **tail = &list;
        int type;

        p.arena = &arena;
        p.err = 0;
        p.stray_arrays = 0;
        p.void_calls = 0;
        p.loops = 0;
        p.in_func = 0;

        type = bc_peek_type (&p);
        if (type == T_EOF && !p.err) { bc_arena_free (&arena); break; }
        if (type == T_DEFINE) {
            bc_parse_define (&p);
        } else {
            /* statements separated by ';' up to a newline or the end */
            for (;;) {
                type = bc_peek_type (&p);
                if (p.err || p.quit) break;
                if (type == ';') { bc_consume (&p); continue; }
                if (type == T_NL) { bc_consume (&p); break; }
                if (type == T_EOF) break;
                bc_node *s = bc_parse_stmt (&p);
                if (!s) break;
                *tail = s;
                tail = &s->next;
                type = bc_peek_type (&p);
                if (type != ';' && type != T_NL && type != T_EOF) { bc_syntax_error (&p); break; }
            }
        }

        if (p.quit) {
            bc_arena_free (&arena);
            ip->stop = 1;
            break;
        }
        if (p.err) {
            /* recover at the next newline, as GNU bc does */
            for (;;) {
                type = bc_peek_type (&p);
                if (type == T_EOF) break;
                bc_consume (&p);
                if (type == T_NL) break;
            }
            bc_arena_free (&arena);
            continue;
        }
        if (bc_check_interrupt (ip)) { bc_arena_free (&arena); break; }

        ip->err = 0;
        ip->func = NULL;
        bc_run_item (ip, list);
        ip->err = 0;
        bc_arena_free (&arena);
        if (bc_check_interrupt (ip)) break;
    }
    if (p.have) bc_tok_free (&p.tok);
    if (src->in && src->in->error) {
        bc_flush_for_message (ip);
        builtin_error ("%s: %s", src->name, strerror (src->in->error));
        ip->failed = 1;
        ip->fatal = 1;
        ip->stop = 1;
    }
    ip->src = NULL;
    return ip->stop;
}

/* BC_LINE_LENGTH as a separate bc would see it: exported shell variables
   only.  Unset means 70, 0 disables wrapping, and other values below 3
   also mean 70 (GNU bc 1.07). */
static int
bc_line_length (void)
{
    SHELL_VAR *v = find_variable ("BC_LINE_LENGTH");
    const char *s;
    if (!v || !exported_p (v) || invisible_p (v) || !(s = get_variable_value (v)))
        return 70;
    long n = strtol (s, NULL, 10);
    if (n > INT_MAX) n = INT_MAX;
    if (n < 3 && n != 0) n = 70;
    return (int) n;
}

static void
bc_interp_free (bc_interp *ip)
{
    bc_restore_to (ip, 0);
    for (int i = 0; i < ip->vnames.count; i++)
        if (ip->vars[i].digits) bc_free (&ip->vars[i]);
    for (int i = 0; i < ip->anames.count; i++) bc_array_release (ip->arrays[i]);
    for (int i = 0; i < ip->fnames.count; i++) {
        bc_arena_free (&ip->funcs[i].arena);
        free (ip->funcs[i].params);
        free (ip->funcs[i].autos);
    }
    free (ip->vars);
    free (ip->arrays);
    free (ip->funcs);
    free (ip->saved);
    if (ip->retval.digits) bc_free (&ip->retval);
    bc_free (&ip->last);
    bc_names_free (&ip->vnames);
    bc_names_free (&ip->anames);
    bc_names_free (&ip->fnames);
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

/* 'e' expression, 'f' explicit file (- is stdin), 'b' bare filename. */
typedef struct { int kind; const char *text; } bc_operand;

static void
bc_usage (FILE *fp)
{
    fprintf (fp, "usage: bc [-hilqsvw] [--strict-errors] [-e EXPR] [-f FILE] [FILE...]\n");
}

int
bc_builtin (WORD_LIST *list)
{
    bc_init_statics ();

    /* Every invocation starts from the documented defaults and reads its
       own standard input, so no arithmetic or input state survives a
       previous call in the same shell. */
    bc_input input;
    bc_input_init (&input, STDIN_FILENO);

    bc_interp *ip = calloc (1, sizeof *ip);
    if (!ip) { builtin_error ("out of memory"); return EXECUTION_FAILURE; }
    ip->scale = 0;
    ip->ibase = 10;
    ip->obase = 10;
    ip->last = bc_zero ();
    ip->stdin_in = &input;
    ip->out.line_size = bc_line_length ();

    struct rlimit rl;
    size_t budget = 8u << 20;
    if (getrlimit (RLIMIT_STACK, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur < budget)
        budget = (size_t) rl.rlim_cur;
    ip->stack_base = __builtin_frame_address (0);
    ip->stack_limit = budget > (1u << 20) ? budget - (768u << 10) : budget / 2;

    bc_operand *ops = calloc (1, sizeof (bc_operand) * (size_t) (list_length ((GENERIC_LIST *) list) + 1));
    int nops = 0, had_e = 0, had_files = 0, read_stdin_after = 0, rc = EXECUTION_SUCCESS;
    int strict_errors = 0;
    WORD_LIST *rest = NULL;
    if (!ops) { free (ip); builtin_error ("out of memory"); return EXECUTION_FAILURE; }

    /* Options, GNU style, plus -e/-f for unambiguous expressions and files.
       Short options may be grouped (-lq). */
    while (list) {
        const char *w = list->word->word;
        if (w[0] != '-' || w[1] == '\0') break;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (w[1] == '-') {
            const char *opt = w + 2;
            const char *eq = strchr (opt, '=');
            size_t olen = eq ? (size_t) (eq - opt) : strlen (opt);
            if (!strcmp (opt, "strict-errors")) strict_errors = 1;
            else if (!strncmp (opt, "mathlib", olen) && olen && !eq) ip->mathlib = 1;
            else if (olen && !eq && (!strncmp (opt, "quiet", olen) || !strncmp (opt, "standard", olen)
                     || !strncmp (opt, "warn", olen) || !strncmp (opt, "interactive", olen)))
                ;
            else if (olen && !eq && !strncmp (opt, "help", olen)) { bc_usage (stdout); free (ops); bc_interp_free (ip); free (ip); return sh_chkwrite (EXECUTION_SUCCESS); }
            else if (olen && !eq && !strncmp (opt, "version", olen)) { puts ("bc (bash-os builtin)"); free (ops); bc_interp_free (ip); free (ip); return sh_chkwrite (EXECUTION_SUCCESS); }
            else if (olen && (!strncmp (opt, "expression", olen) || !strncmp (opt, "file", olen))) {
                int kind = opt[0] == 'e' ? 'e' : 'f';
                const char *arg = eq ? eq + 1 : NULL;
                if (!arg) {
                    list = list->next;
                    if (!list) { builtin_error ("%s: option requires an argument", w); goto usage; }
                    arg = list->word->word;
                }
                ops[nops].kind = kind;
                ops[nops++].text = arg;
                strict_errors = 1;
                if (kind == 'e') had_e = 1;
                else if (!strcmp (arg, "-")) read_stdin_after = -1;
            } else {
                builtin_error ("%s: invalid option", w);
                goto usage;
            }
            list = list->next;
            continue;
        }
        for (const char *c = w + 1; *c; c++) {
            switch (*c) {
            case 'l': ip->mathlib = 1; break;
            case 'q': case 's': case 'w': case 'i': break;
            case 'h': bc_usage (stdout); free (ops); bc_interp_free (ip); free (ip); return sh_chkwrite (EXECUTION_SUCCESS);
            case 'v': puts ("bc (bash-os builtin)"); free (ops); bc_interp_free (ip); free (ip); return sh_chkwrite (EXECUTION_SUCCESS);
            case 'e': case 'f': {
                const char *arg = c[1] ? c + 1 : NULL;
                if (!arg) {
                    list = list->next;
                    if (!list) { builtin_error ("-%c: option requires an argument", *c); goto usage; }
                    arg = list->word->word;
                }
                ops[nops].kind = *c;
                ops[nops++].text = arg;
                strict_errors = 1;
                if (*c == 'e') had_e = 1;
                else if (!strcmp (arg, "-")) read_stdin_after = -1;
                goto next_word;   /* the rest of the word was the argument */
            }
            default:
                builtin_error ("-%c: invalid option", *c);
                goto usage;
            }
        }
    next_word:
        list = list->next;
    }
    rest = list;

    if (ip->mathlib) {
        ip->scale = 20;
        for (int k = 0; k < 6; k++) {
            int id = bc_func_id (ip, bc_lib_names[k]);
            if (id >= 0) ip->funcs[id].native = k + 1;
        }
    }

    /* A bare operand is always a file, even when it does not exist.
       Expressions use the explicit -e interface. */
    for (WORD_LIST *w = rest; w; w = w->next) {
        ops[nops].kind = 'b';
        ops[nops++].text = w->word->word;
    }
    for (int k = 0; k < nops; k++) if (ops[k].kind != 'e') had_files = 1;

    if (nops == 0)
        read_stdin_after = 1;
    else if (read_stdin_after == 0)
        read_stdin_after = had_files && !had_e;

    for (int k = 0; k < nops && !ip->stop; k++) {
        if (ops[k].kind == 'e') {
            bc_src src = { NULL, ops[k].text, strlen (ops[k].text), 0,
                           "(expression)", 1 };
            bc_run_source (ip, &src);
        } else if (ops[k].kind == 'f' && !strcmp (ops[k].text, "-")) {
            bc_src src = { &input, NULL, 0, 0, "(standard_in)", 1 };
            bc_run_source (ip, &src);
        } else {
            int fd = open (ops[k].text, O_RDONLY);
            if (fd < 0) {
                bc_flush_for_message (ip);
                fprintf (stderr, "File %s is unavailable.\n", ops[k].text);
                ip->failed = 1;
                ip->fatal = 1;
                ip->stop = 1;
                break;
            }
            bc_input fin;
            bc_input_init (&fin, fd);
            bc_src src = { &fin, NULL, 0, 0, ops[k].text, 1 };
            bc_run_source (ip, &src);
            close (fd);
        }
    }
    if (read_stdin_after > 0 && !ip->stop) {
        bc_src src = { &input, NULL, 0, 0, "(standard_in)", 1 };
        bc_run_source (ip, &src);
    }

    bc_out_flush (&ip->out);
    if (ip->fatal || (strict_errors && ip->failed)) rc = EXECUTION_FAILURE;
    {
        int interrupted = interrupt_state || terminating_signal;
        bc_interp_free (ip);
        free (bc_spare_block);
        bc_spare_block = NULL;
        free (ip);
        free (ops);
        rc = sh_chkwrite (rc);
        if (interrupted) QUIT;
        return rc;
    }

usage:
    bc_usage (stderr);
    bc_interp_free (ip);
    free (bc_spare_block);
    bc_spare_block = NULL;
    free (ip);
    free (ops);
    return EX_USAGE;
}

char *bc_doc[] = {
    "Arbitrary-precision calculator language (GNU bc compatible).",
    "",
    "    bc [-hilqsvw] [--strict-errors] [-e EXPR] [-f FILE] [FILE...]",
    "",
    "    Runs bc programs: named files in order and then standard input, or",
    "    the -e expressions and -f files in order (standard input is not",
    "    read after -e unless -f - is given).  Bare operands always name",
    "    files; use -e for a program supplied as an argument.",
    "",
    "    The language is GNU bc's: arbitrary-precision numbers; variables,",
    "    arrays (a[i]) and functions in separate namespaces; define with",
    "    parameters, array parameters (a[], *a[] by reference), auto locals,",
    "    void functions and recursion; if/else, while, for, break, continue,",
    "    return, halt and quit; print and quoted strings; /* */ and #",
    "    comments; scale, ibase (2-36), obase (2 and up) and last; length(),",
    "    scale(), sqrt() and read(); ++, --, op=, relational, ! && ||.",
    "",
    "    -l / --mathlib  set scale=20 and define s c a l e j (sine, cosine,",
    "                    arctangent, natural log, exponential, Bessel)",
    "    -e EXPR         run EXPR;  -f FILE  run FILE (- is standard input)",
    "    -q -s -w -i     accepted for compatibility; -h help; -v version",
    "",
    "    BC_LINE_LENGTH (exported) sets the output line length; 0 disables",
    "    line splitting.  Recovered syntax and runtime errors leave status",
    "    0, as in GNU bc.  --strict-errors, -e and -f select status 1 after",
    "    those errors.  Input, output and resource failures return 1.",
    (char *)NULL
};

struct builtin bc_struct = {
    "bc",
    bc_builtin,
    BUILTIN_ENABLED,
    bc_doc,
    "bc [-hilqsvw] [--strict-errors] [-e EXPR] [-f FILE] [FILE...]",
    0
};
