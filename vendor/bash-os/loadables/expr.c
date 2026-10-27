/* SPDX-License-Identifier: MIT */
/* expr.c — POSIX expr(1) as a bash builtin.
 *
 * Closes the POSIX gap noted in POSIX-CONFORMANCE-RESEARCH §4.1.
 * bash's `(( ))` covers integer arithmetic but POSIX scripts that
 * shell out to `expr` won't work — this provides the canonical surface.
 *
 * Supported:
 *   ARITHMETIC:  + - * / % ; precedence + parens
 *   COMPARE:     = != < <= > >=                 (yields 1 / 0)
 *   STRING:      length STR, substr STR POS LEN, index STR CHARS, match STR RE
 *   REGEX:       STR : RE   (POSIX BRE; outputs match length or ^()$ group)
 *   LOGIC:       | & — POSIX `expr` short-circuit (returns first non-zero
 *                / non-empty operand, else last; & returns first if both
 *                truthy, else 0)
 *
 * v1 cuts: only the canonical POSIX surface; no GNU extensions. Output
 * always single-line. Exit 0 if value is non-zero/non-empty, 1 if zero/
 * empty, 2 on syntax error, 3 on internal error.
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
#include <ctype.h>
#include <limits.h>
#include <regex.h>
#include <wchar.h>
#include <wctype.h>

#include "loadables.h"

/* Token / value type. POSIX expr operates on a stack of strings;
   numeric ops parse the operands as integers on demand. */
typedef struct {
    char *s;         /* string form (always present, malloc'd) */
    int   is_num;    /* 1 if the string parses cleanly as long long */
    long long n;     /* cached numeric form */
} bex_val;

static bex_val
bex_make (const char *s)
{
    bex_val v = { 0 };
    v.s = strdup (s ? s : "");
    if (!v.s) return v;
    char *end;
    errno = 0;
    long long n = strtoll (v.s, &end, 10);
    if (*v.s && *end == '\0' && errno == 0) { v.is_num = 1; v.n = n; }
    return v;
}

static bex_val
bex_from_ll (long long n)
{
    bex_val v = { 0 };
    v.is_num = 1; v.n = n;
    char buf[32];
    snprintf (buf, sizeof buf, "%lld", n);
    v.s = strdup (buf);
    return v;
}

static void
bex_free (bex_val *v) { free (v->s); v->s = NULL; }

static int
bex_truthy (const bex_val *v)
{
    if (v->is_num) return v->n != 0;
    return v->s && v->s[0] != '\0';
}

static int
bex_require_num (const bex_val *v, long long *out)
{
    if (!v->is_num) {
        builtin_error ("non-integer argument");  /* matches GNU expr */
        return -1;
    }
    *out = v->n;
    return 0;
}

#if defined (__GLIBC__)
/* glibc regexec enters set_regs only when the caller asks for more than
   one register. The gate in the gnulib copy of posix/regexec.c shipped with
   coreutils 9.7 (lib/regexec.c) is lines 839-842:

     if (!preg->no_sub && nmatch > 1)
       err = set_regs (preg, &mctx, nmatch, pmatch,
                       dfa->has_plural_match && dfa->nbackref > 0);

   set_regs asserts nmatch > 1 at line 1376 of that copy, so nmatch 0 and 1
   never walk the loop. glibc 2.41 posix/regexec.c has the same gate at
   re_search_internal line 849 and the walk at set_regs line 1415. A
   back-reference sets nbackref, which turns the fail stack on, and the
   walk returns.

   \+ and \{n,\} with n >= 1 and no upper bound compile as one mandatory copy
   plus an open star (regcomp.c parse_dup_op, about lines 2564-2595). The
   star of a nullable group is an epsilon cycle that does not advance the
   index. With no fail stack that cycle does not terminate. Star, question
   mark, and bounded intervals are not built that way.
*/
#define EL_STEP_BUDGET 2000000
#define EL_NODE_MAX 512

enum {
    EL_EMPTY = 1,
    EL_LIT,
    EL_DOT,
    EL_CLASS,
    EL_ANCHOR,
    EL_CAT,
    EL_ALT,
    EL_REP,
    EL_WORD,
    EL_NWORD,
    EL_SPACE,
    EL_NSPACE
};

enum {
    EL_CARET = 1,
    EL_DOLLAR,
    EL_BOS, /* \` */
    EL_EOS, /* \' */
    EL_WFIRST, /* \< */
    EL_WLAST,  /* \> */
    EL_WB,     /* \b */
    EL_NWB     /* \B */
};

/* POSIX classes inside a bracket. A wide character is classified with
   isw*, not with the byte set: [[:alpha:]] matches U+00E9 even though
   neither UTF-8 byte is an alphabetic byte. */
enum {
    EL_WC_ALNUM = 1 << 0,
    EL_WC_ALPHA = 1 << 1,
    EL_WC_DIGIT = 1 << 2,
    EL_WC_SPACE = 1 << 3,
    EL_WC_LOWER = 1 << 4,
    EL_WC_UPPER = 1 << 5,
    EL_WC_XDIGIT = 1 << 6,
    EL_WC_BLANK = 1 << 7,
    EL_WC_PUNCT = 1 << 8,
    EL_WC_CNTRL = 1 << 9,
    EL_WC_GRAPH = 1 << 10,
    EL_WC_PRINT = 1 << 11
};

typedef struct {
    int kind;
    int anch;
    unsigned char lit;
    int min, max; /* max < 0 means unbounded */
    int a, b;
    int neg;
    unsigned wclass;
    unsigned char bits[32];
    int nullable;
    int can_consume;
    int has_hang;
    int hang_cons;
    int backref;
    int dangerous;
} el_node;

typedef struct {
    int pos;
    unsigned char bad;
} el_end;

typedef struct {
    el_end *p;
    int *ix; /* 1-based index of pos, or NULL while the list is short */
    int n, cap;
} el_ends;

typedef struct {
    int *pos;
    unsigned char *bad;
    int n, cap;
} el_front;

typedef struct {
    const unsigned char *s;
    int n;
    int mb;
    int bad_refused;
    int steps;
    int uncertain;
    el_node *pool;
    int np;
    int *mark; /* generation last written for this offset */
    int *slot; /* index in the frontier being built; valid when mark matches */
    int gen;
} el_mx;

typedef struct {
    const char *s;
    int i, n;
    int caret_ok;
    int dup_ok;
    int err;
    int backref;
    int depth;
    el_node *pool;
    int np;
} el_ps;

static int
el_new (el_ps *ps, int kind)
{
    if (ps->np >= EL_NODE_MAX) {
        ps->err = 1;
        return -1;
    }
    int id = ps->np++;
    el_node *nd = &ps->pool[id];
    memset (nd, 0, sizeof *nd);
    nd->kind = kind;
    nd->a = nd->b = -1;
    nd->max = -1;
    return id;
}

static void
el_ends_add (el_mx *m, el_ends *e, int pos, int bad)
{
    int i;
    /* A failed realloc stores n == -1 and leaves p unchanged. The next
       call must not write p[-1]. Callers treat n < 0 as uncertain. */
    if (e->n < 0)
        return;
    /* The first thirty-two inserts stay a linear scan. That keeps the
       16-slot growth (128 bytes) on the same realloc the failure test
       intercepts. Past that, an index makes a long subject cheap. */
    if (e->n >= 32 && !e->ix && m->n >= 0 && pos >= 0 && pos <= m->n) {
        int *ix = calloc ((size_t) m->n + 1, sizeof (int));
        if (!ix) {
            e->n = -1;
            m->uncertain = 1;
            return;
        }
        for (i = 0; i < e->n; i++) {
            int p = e->p[i].pos;
            if (p >= 0 && p <= m->n)
                ix[p] = i + 1;
        }
        e->ix = ix;
    }
    if (e->ix && pos >= 0 && pos <= m->n && e->ix[pos]) {
        if (!bad)
            e->p[e->ix[pos] - 1].bad = 0;
        return;
    }
    if (!e->ix) {
        for (i = 0; i < e->n; i++) {
            if (e->p[i].pos == pos) {
                if (!bad)
                    e->p[i].bad = 0;
                return;
            }
        }
    }
    if (e->n >= e->cap) {
        int ncap = e->cap ? e->cap * 2 : 8;
        el_end *np = realloc (e->p, (size_t) ncap * sizeof (el_end));
        if (!np) {
            e->n = -1;
            m->uncertain = 1;
            return;
        }
        e->p = np;
        e->cap = ncap;
    }
    e->p[e->n].pos = pos;
    e->p[e->n].bad = (unsigned char) (bad ? 1 : 0);
    e->n++;
    if (e->ix && pos >= 0 && pos <= m->n)
        e->ix[pos] = e->n;
}

static void
el_ends_free (el_ends *e)
{
    free (e->p);
    free (e->ix);
    e->p = NULL;
    e->ix = NULL;
    e->n = e->cap = 0;
}

static int
el_word_byte (unsigned char c)
{
    return (isalnum (c) || c == '_') ? 1 : 0;
}

static int
el_prev_word (el_mx *m, int pos)
{
    wchar_t wc;
    mbstate_t st;
    size_t r;
    int i;
    if (pos <= 0)
        return 0;
    if (!m->mb)
        return el_word_byte (m->s[pos - 1]);
    i = pos - 1;
    while (i > 0 && (m->s[i] & 0xc0) == 0x80)
        i--;
    memset (&st, 0, sizeof st);
    r = mbrtowc (&wc, (const char *) m->s + i, (size_t) (pos - i), &st);
    if (r == (size_t) -1 || r == (size_t) -2 || r == 0)
        return el_word_byte (m->s[pos - 1]);
    return (iswalnum (wc) || wc == L'_') ? 1 : 0;
}

static int
el_next_word (el_mx *m, int pos)
{
    wchar_t wc;
    mbstate_t st;
    size_t r;
    if (pos >= m->n)
        return 0;
    if (!m->mb)
        return el_word_byte (m->s[pos]);
    memset (&st, 0, sizeof st);
    r = mbrtowc (&wc, (const char *) m->s + pos, (size_t) (m->n - pos), &st);
    if (r == (size_t) -1 || r == (size_t) -2 || r == 0)
        return el_word_byte (m->s[pos]);
    return (iswalnum (wc) || wc == L'_') ? 1 : 0;
}

static int
el_wclass_on (unsigned mask, wchar_t wc)
{
    if ((mask & EL_WC_ALNUM) && iswalnum (wc)) return 1;
    if ((mask & EL_WC_ALPHA) && iswalpha (wc)) return 1;
    if ((mask & EL_WC_DIGIT) && iswdigit (wc)) return 1;
    if ((mask & EL_WC_SPACE) && iswspace (wc)) return 1;
    if ((mask & EL_WC_LOWER) && iswlower (wc)) return 1;
    if ((mask & EL_WC_UPPER) && iswupper (wc)) return 1;
    if ((mask & EL_WC_XDIGIT) && iswxdigit (wc)) return 1;
    if ((mask & EL_WC_BLANK) && iswblank (wc)) return 1;
    if ((mask & EL_WC_PUNCT) && iswpunct (wc)) return 1;
    if ((mask & EL_WC_CNTRL) && iswcntrl (wc)) return 1;
    if ((mask & EL_WC_GRAPH) && iswgraph (wc)) return 1;
    if ((mask & EL_WC_PRINT) && iswprint (wc)) return 1;
    return 0;
}

static int
el_char_end (el_mx *m, int pos)
{
    wchar_t wc;
    mbstate_t st;
    size_t r;
    if (pos >= m->n)
        return -1;
    if (!m->mb)
        return pos + 1;
    memset (&st, 0, sizeof st);
    r = mbrtowc (&wc, (const char *) m->s + pos, (size_t) (m->n - pos), &st);
    if (r == (size_t) -1 || r == (size_t) -2 || r == 0)
        return pos + 1;
    return pos + (int) r;
}

static int
el_hang_bad (el_mx *m, int anch, int pos)
{
    switch (anch) {
    case EL_CARET:
        /* regexec's initial context is newline even when newline_anchor is 0,
           and a real newline still lets ^ finish. Anywhere else is the loop. */
        if (pos == 0)
            return 0;
        if (pos > 0 && m->s[pos - 1] == '\n')
            return 0;
        return 1;
    case EL_BOS:
        return pos != 0;
    case EL_WFIRST:
        /* \< loops only when the previous character is a word character. */
        return el_prev_word (m, pos);
    case EL_WLAST:
        /* \> loops only when the previous character is not a word character.
           BOS counts as not-a-word. A false \> after a word character returns. */
        return !el_prev_word (m, pos);
    default:
        return 0;
    }
}

static void el_match (el_mx *m, int id, int pos, el_ends *out);

static int
el_front_grow (el_front *f)
{
    int ncap = f->cap ? f->cap * 2 : 8;
    int *np = realloc (f->pos, (size_t) ncap * sizeof (int));
    unsigned char *nb;
    if (!np)
        return -1;
    f->pos = np;
    nb = realloc (f->bad, (size_t) ncap);
    if (!nb)
        return -1;
    f->bad = nb;
    f->cap = ncap;
    return 0;
}

static void
el_front_free (el_front *f)
{
    free (f->pos);
    free (f->bad);
    f->pos = NULL;
    f->bad = NULL;
    f->n = f->cap = 0;
}

static int
el_front_push (el_front *f, int pos, int bad)
{
    if (f->n >= f->cap && el_front_grow (f) < 0)
        return -1;
    f->pos[f->n] = pos;
    f->bad[f->n] = (unsigned char) (bad ? 1 : 0);
    f->n++;
    return 0;
}

static int
el_front_same (const el_front *a, const el_front *b)
{
    int i;
    if (a->n != b->n)
        return 0;
    for (i = 0; i < a->n; i++) {
        if (a->pos[i] != b->pos[i] || a->bad[i] != b->bad[i])
            return 0;
    }
    return 1;
}

static int
el_gen_fresh (el_mx *m)
{
    /* Signed overflow is undefined. Wrap by clearing the stamps. */
    if (m->gen >= INT_MAX) {
        memset (m->mark, 0, (size_t) (m->n + 1) * sizeof (int));
        m->gen = 1;
    } else {
        m->gen++;
    }
    return m->gen;
}

static void el_rep_run (el_mx *m, el_node *nd, el_front *seed, el_ends *out);

static void
el_match_rep (el_mx *m, el_node *nd, int pos, el_ends *out)
{
    el_front seed;
    memset (&seed, 0, sizeof seed);
    if (pos < 0 || pos > m->n || m->uncertain)
        return;
    if (el_front_push (&seed, pos, 0) < 0) {
        m->uncertain = 1;
        el_front_free (&seed);
        return;
    }
    el_rep_run (m, nd, &seed, out);
    el_front_free (&seed);
}

static void
el_rep_run (el_mx *m, el_node *nd, el_front *seed, el_ends *out)
{
    el_front cur, nxt;
    int k, guard, si;
    int min = nd->min;
    int max = nd->max;

    if (m->uncertain)
        return;
    if (!m->mark || !m->slot) {
        m->uncertain = 1;
        return;
    }
    memset (&cur, 0, sizeof cur);
    memset (&nxt, 0, sizeof nxt);
    for (si = 0; si < seed->n; si++) {
        if (seed->pos[si] < 0 || seed->pos[si] > m->n)
            continue;
        if (el_front_push (&cur, seed->pos[si], seed->bad[si]) < 0) {
            m->uncertain = 1;
            goto rep_done;
        }
    }
    guard = m->n + (min > 0 ? min : 0) + 3;
    for (k = 0; k <= guard; k++) {
        int fi, grew = 0;
        int mygen;
        if (k >= min) {
            for (fi = 0; fi < cur.n; fi++)
                el_ends_add (m, out, cur.pos[fi], cur.bad[fi]);
            if (m->uncertain)
                goto rep_done;
        }
        if (max >= 0 && k >= max)
            break;
        if (cur.n == 0)
            break;
        nxt.n = 0;
        mygen = el_gen_fresh (m);
        for (fi = 0; fi < cur.n; fi++) {
            el_ends body;
            int bi;
            int src_bad = cur.bad[fi] ? 1 : 0;
            int ri;
            memset (&body, 0, sizeof body);
            el_match (m, nd->a, cur.pos[fi], &body);
            if (body.n < 0 || m->uncertain) {
                el_ends_free (&body);
                m->uncertain = 1;
                goto rep_done;
            }
            /* A nested repeat reuses mark[]. The frontier list is the
               record of this round; restamp it under a fresh generation. */
            if (m->gen != mygen) {
                mygen = el_gen_fresh (m);
                for (ri = 0; ri < nxt.n; ri++) {
                    int np = nxt.pos[ri];
                    if (np >= 0 && np <= m->n) {
                        m->mark[np] = mygen;
                        m->slot[np] = ri;
                    }
                }
            }
            for (bi = 0; bi < body.n; bi++) {
                int np = body.p[bi].pos;
                int tainted = src_bad || body.p[bi].bad;
                if (np < 0 || np > m->n)
                    continue;
                if (m->mark[np] != mygen) {
                    if (nxt.n >= nxt.cap && el_front_grow (&nxt) < 0) {
                        el_ends_free (&body);
                        m->uncertain = 1;
                        goto rep_done;
                    }
                    m->mark[np] = mygen;
                    m->slot[np] = nxt.n;
                    nxt.pos[nxt.n] = np;
                    nxt.bad[nxt.n] = (unsigned char) (tainted ? 1 : 0);
                    nxt.n++;
                    grew = 1;
                } else if (!tainted && nxt.bad[m->slot[np]]) {
                    /* A clean path upgrades a bad one and counts as growth.
                       A second bad path does not. */
                    nxt.bad[m->slot[np]] = 0;
                    grew = 1;
                }
            }
            el_ends_free (&body);
            if (++m->steps > EL_STEP_BUDGET) {
                m->uncertain = 1;
                goto rep_done;
            }
        }
        if (!grew) {
            /* No new offset. Empty copies can still meet a minimum, and
               they cannot make the match longer. */
            if (k < min && (max < 0 || max >= min)) {
                cur.n = 0;
                k = min - 1;
                continue;
            }
            break;
        }
        if (el_front_same (&cur, &nxt)) {
            if (k >= min)
                break;
            if (max < 0 || max >= min) {
                k = min - 1;
                continue;
            }
            break;
        }
        {
            el_front tmp = cur;
            cur = nxt;
            nxt = tmp;
        }
    }
rep_done:
    el_front_free (&cur);
    el_front_free (&nxt);
}

static void
el_match (el_mx *m, int id, int pos, el_ends *out)
{
    el_node *nd;
    if (id < 0 || m->uncertain)
        return;
    if (++m->steps > EL_STEP_BUDGET) {
        m->uncertain = 1;
        return;
    }
    nd = &m->pool[id];
    switch (nd->kind) {
    case EL_EMPTY:
        el_ends_add (m, out, pos, 0);
        break;
    case EL_LIT:
        if (pos < m->n && m->s[pos] == nd->lit)
            el_ends_add (m, out, pos + 1, 0);
        break;
    case EL_DOT:
        if (pos < m->n && m->s[pos] != '\0') {
            int e = el_char_end (m, pos);
            if (e > pos)
                el_ends_add (m, out, e, 0);
        }
        break;
    case EL_CLASS:
        if (pos < m->n) {
            int end = el_char_end (m, pos);
            int on;
            if (end <= pos)
                break;
            if (m->mb && end > pos + 1) {
                /* Classify the whole character. The byte set does not
                   contain U+00E9 for [[:alpha:]], so a one-byte step
                   never sees the consuming path and then asks glibc
                   for two registers. */
                wchar_t wc;
                mbstate_t st;
                size_t r;
                memset (&st, 0, sizeof st);
                r = mbrtowc (&wc, (const char *) m->s + pos,
                             (size_t) (m->n - pos), &st);
                on = 0;
                if (r != (size_t) -1 && r != (size_t) -2 && r > 1)
                    on = el_wclass_on (nd->wclass, wc);
                if (nd->neg)
                    on = !on;
                if (on)
                    el_ends_add (m, out, end, 0);
            } else {
                unsigned char c = m->s[pos];
                on = (nd->bits[c >> 3] >> (c & 7)) & 1;
                if (nd->neg)
                    on = !on;
                if (on)
                    el_ends_add (m, out, pos + 1, 0);
            }
        }
        break;
    case EL_WORD:
    case EL_NWORD:
    case EL_SPACE:
    case EL_NSPACE: {
        int e = el_char_end (m, pos);
        int ok = 0;
        if (e > pos) {
            int w = el_next_word (m, pos);
            wchar_t wc;
            mbstate_t st;
            int sp = 0;
            if (!m->mb)
                sp = isspace (m->s[pos]) ? 1 : 0;
            else {
                size_t wr;
                memset (&st, 0, sizeof st);
                wr = mbrtowc (&wc, (const char *) m->s + pos,
                              (size_t) (m->n - pos), &st);
                if (wr == (size_t) -1 || wr == (size_t) -2)
                    sp = isspace (m->s[pos]) ? 1 : 0;
                else
                    sp = iswspace (wc) ? 1 : 0;
            }
            if (nd->kind == EL_WORD)
                ok = w;
            else if (nd->kind == EL_NWORD)
                ok = !w;
            else if (nd->kind == EL_SPACE)
                ok = sp;
            else
                ok = !sp;
            if (ok)
                el_ends_add (m, out, e, 0);
        }
        break;
    }
    case EL_ANCHOR: {
        int ok = 0, bad = 0;
        switch (nd->anch) {
        case EL_CARET:
        case EL_BOS:
        case EL_WFIRST:
        case EL_WLAST:
            ok = 1;
            bad = el_hang_bad (m, nd->anch, pos);
            break;
        case EL_DOLLAR:
        case EL_EOS:
            ok = (pos == m->n);
            break;
        case EL_WB:
            ok = el_prev_word (m, pos) != el_next_word (m, pos);
            break;
        case EL_NWB:
            ok = el_prev_word (m, pos) == el_next_word (m, pos);
            break;
        default:
            break;
        }
        if (ok)
            el_ends_add (m, out, pos, bad);
        break;
    }
    case EL_CAT: {
        el_ends left;
        int li;
        int batched = 0;
        memset (&left, 0, sizeof left);
        el_match (m, nd->a, pos, &left);
        if (left.n < 0) {
            m->uncertain = 1;
            el_ends_free (&left);
            break;
        }
        /* One repeat over every clean left end is the same set as repeating
           from each end, and it stays linear when .* feeds the group. */
        if (nd->b >= 0 && m->pool[nd->b].kind == EL_REP && left.n > 1
            && m->mark && m->slot) {
            el_front seed;
            int bi, mygen;
            memset (&seed, 0, sizeof seed);
            mygen = el_gen_fresh (m);
            for (bi = 0; bi < left.n && !m->uncertain; bi++) {
                int p;
                if (left.p[bi].bad)
                    continue;
                p = left.p[bi].pos;
                if (p < 0 || p > m->n || m->mark[p] == mygen)
                    continue;
                if (el_front_push (&seed, p, 0) < 0) {
                    m->uncertain = 1;
                    break;
                }
                m->mark[p] = mygen;
                m->slot[p] = seed.n - 1;
            }
            if (!m->uncertain && seed.n)
                el_rep_run (m, &m->pool[nd->b], &seed, out);
            el_front_free (&seed);
            batched = 1;
            if (m->uncertain) {
                el_ends_free (&left);
                break;
            }
        }
        for (li = 0; li < left.n; li++) {
            el_ends right;
            int ri;
            if (batched && !left.p[li].bad)
                continue;
            memset (&right, 0, sizeof right);
            el_match (m, nd->b, left.p[li].pos, &right);
            for (ri = 0; ri < right.n; ri++) {
                if (left.p[li].bad && right.p[ri].pos > left.p[li].pos) {
                    /* A hang-anchor was accepted and the same alternative
                       then consumed. That is the transition set_regs loops on. */
                    m->bad_refused = 1;
                    continue;
                }
                el_ends_add (m, out, right.p[ri].pos,
                             left.p[li].bad || right.p[ri].bad);
            }
            el_ends_free (&right);
        }
        el_ends_free (&left);
        break;
    }
    case EL_ALT: {
        el_match (m, nd->a, pos, out);
        el_match (m, nd->b, pos, out);
        break;
    }
    case EL_REP:
        el_match_rep (m, nd, pos, out);
        break;
    default:
        break;
    }
}

static void
el_props (el_node *pool, int id)
{
    el_node *nd;
    if (id < 0)
        return;
    nd = &pool[id];
    if (nd->a >= 0)
        el_props (pool, nd->a);
    if (nd->b >= 0)
        el_props (pool, nd->b);
    switch (nd->kind) {
    case EL_EMPTY:
    case EL_ANCHOR:
        nd->nullable = 1;
        nd->can_consume = 0;
        if (nd->kind == EL_ANCHOR
            && (nd->anch == EL_CARET || nd->anch == EL_BOS
                || nd->anch == EL_WFIRST || nd->anch == EL_WLAST))
            nd->has_hang = 1;
        break;
    case EL_LIT:
    case EL_DOT:
    case EL_CLASS:
    case EL_WORD:
    case EL_NWORD:
    case EL_SPACE:
    case EL_NSPACE:
        nd->can_consume = 1;
        break;
    case EL_CAT: {
        el_node *a = &pool[nd->a], *b = &pool[nd->b];
        nd->nullable = a->nullable && b->nullable;
        nd->can_consume = a->can_consume || b->can_consume;
        nd->has_hang = a->has_hang || b->has_hang;
        nd->hang_cons = a->hang_cons || b->hang_cons
            || (a->has_hang && (b->can_consume || b->hang_cons));
        nd->backref = a->backref || b->backref;
        nd->dangerous = a->dangerous || b->dangerous;
        break;
    }
    case EL_ALT: {
        el_node *a = &pool[nd->a], *b = &pool[nd->b];
        nd->nullable = a->nullable || b->nullable;
        nd->can_consume = a->can_consume || b->can_consume;
        nd->has_hang = a->has_hang || b->has_hang;
        nd->hang_cons = a->hang_cons || b->hang_cons;
        nd->backref = a->backref || b->backref;
        nd->dangerous = a->dangerous || b->dangerous;
        break;
    }
    case EL_REP: {
        el_node *a = &pool[nd->a];
        nd->nullable = (nd->min == 0) || a->nullable;
        nd->can_consume = a->can_consume && !(nd->max == 0);
        nd->has_hang = a->has_hang;
        nd->hang_cons = a->hang_cons;
        nd->backref = a->backref;
        nd->dangerous = a->dangerous;
        /* Mandatory copies followed by an open star: the set_regs cycle. */
        if (nd->min >= 1 && nd->max < 0 && a->nullable && a->hang_cons)
            nd->dangerous = 1;
        break;
    }
    default:
        if (nd->a >= 0) {
            nd->nullable = pool[nd->a].nullable;
            nd->can_consume = pool[nd->a].can_consume;
            nd->has_hang = pool[nd->a].has_hang;
            nd->hang_cons = pool[nd->a].hang_cons;
            nd->backref = pool[nd->a].backref;
            nd->dangerous = pool[nd->a].dangerous;
        }
        break;
    }
}

static int el_parse_alt_top (el_ps *ps);

static int
el_peek (el_ps *ps)
{
    if (ps->i >= ps->n)
        return -1;
    return (unsigned char) ps->s[ps->i];
}

static int
el_starts_dup (el_ps *ps)
{
    int c = el_peek (ps);
    if (c == '*')
        return 1;
    if (c == '\\' && ps->i + 1 < ps->n) {
        char n = ps->s[ps->i + 1];
        if (n == '+' || n == '?' || n == '{')
            return 1;
    }
    return 0;
}

static int
el_dup_kind (el_ps *ps)
{
    int c = el_peek (ps);
    if (c == '*')
        return '*';
    if (c == '\\' && ps->i + 1 < ps->n)
        return (unsigned char) ps->s[ps->i + 1];
    return 0;
}

static int
el_parse_class (el_ps *ps)
{
    int id = el_new (ps, EL_CLASS);
    int neg = 0;
    int first = 1;
    el_node *nd;
    if (id < 0)
        return -1;
    nd = &ps->pool[id];
    if (el_peek (ps) == '^') {
        neg = 1;
        ps->i++;
        first = 1;
    }
    nd->neg = neg;
    while (ps->i < ps->n) {
        unsigned char c;
        if (ps->s[ps->i] == ']' && !first)
            break;
        first = 0;
        if (ps->s[ps->i] == '[' && ps->i + 1 < ps->n && ps->s[ps->i + 1] == ':') {
            /* POSIX class. Enough for the characters expr patterns use. */
            const char *names[] = {
                "alnum", "alpha", "digit", "space", "lower", "upper",
                "xdigit", "blank", "punct", "cntrl", "graph", "print", NULL
            };
            int ni, close = -1, k;
            ps->i += 2;
            for (k = ps->i; k + 1 < ps->n; k++) {
                if (ps->s[k] == ':' && ps->s[k + 1] == ']') {
                    close = k;
                    break;
                }
            }
            if (close < 0) {
                ps->err = 1;
                return -1;
            }
            for (ni = 0; names[ni]; ni++) {
                int len = (int) strlen (names[ni]);
                if (close - ps->i == len && memcmp (ps->s + ps->i, names[ni], (size_t) len) == 0)
                    break;
            }
            if (!names[ni]) {
                ps->err = 1;
                return -1;
            }
            nd->wclass |= 1u << ni;
            for (k = 0; k < 256; k++) {
                int on = 0;
                if (!strcmp (names[ni], "alnum")) on = isalnum (k);
                else if (!strcmp (names[ni], "alpha")) on = isalpha (k);
                else if (!strcmp (names[ni], "digit")) on = isdigit (k);
                else if (!strcmp (names[ni], "space")) on = isspace (k);
                else if (!strcmp (names[ni], "lower")) on = islower (k);
                else if (!strcmp (names[ni], "upper")) on = isupper (k);
                else if (!strcmp (names[ni], "xdigit")) on = isxdigit (k);
                else if (!strcmp (names[ni], "blank")) on = (k == ' ' || k == '\t');
                else if (!strcmp (names[ni], "punct")) on = ispunct (k);
                else if (!strcmp (names[ni], "cntrl")) on = iscntrl (k);
                else if (!strcmp (names[ni], "graph")) on = isgraph (k);
                else if (!strcmp (names[ni], "print")) on = isprint (k);
                if (on)
                    nd->bits[k >> 3] |= (unsigned char) (1u << (k & 7));
            }
            ps->i = close + 2;
            continue;
        }
        c = (unsigned char) ps->s[ps->i++];
        if (ps->i + 1 < ps->n && ps->s[ps->i] == '-' && ps->s[ps->i + 1] != ']') {
            unsigned char d;
            int x;
            ps->i++;
            d = (unsigned char) ps->s[ps->i++];
            if (c > d) {
                ps->err = 1;
                return -1;
            }
            for (x = c; x <= d; x++)
                nd->bits[x >> 3] |= (unsigned char) (1u << (x & 7));
        } else {
            nd->bits[c >> 3] |= (unsigned char) (1u << (c & 7));
        }
    }
    if (el_peek (ps) != ']') {
        ps->err = 1;
        return -1;
    }
    ps->i++;
    return id;
}

static int
el_parse_atom (el_ps *ps)
{
    int c = el_peek (ps);
    if (c < 0) {
        ps->err = 1;
        return -1;
    }
    if (c == '^') {
        ps->i++;
        if (ps->caret_ok) {
            int id = el_new (ps, EL_ANCHOR);
            if (id >= 0)
                ps->pool[id].anch = EL_CARET;
            return id;
        }
        {
            int id = el_new (ps, EL_LIT);
            if (id >= 0)
                ps->pool[id].lit = '^';
            return id;
        }
    }
    if (c == '$') {
        int anchor = 0;
        ps->i++;
        if (ps->i >= ps->n)
            anchor = 1;
        else if (ps->s[ps->i] == '\\' && ps->i + 1 < ps->n
                 && (ps->s[ps->i + 1] == ')' || ps->s[ps->i + 1] == '|'))
            anchor = 1;
        {
            int id = el_new (ps, anchor ? EL_ANCHOR : EL_LIT);
            if (id >= 0) {
                if (anchor)
                    ps->pool[id].anch = EL_DOLLAR;
                else
                    ps->pool[id].lit = '$';
            }
            return id;
        }
    }
    if (c == '.') {
        ps->i++;
        return el_new (ps, EL_DOT);
    }
    if (c == '[') {
        ps->i++;
        return el_parse_class (ps);
    }
    if (c == '\\') {
        int n;
        if (ps->i + 1 >= ps->n) {
            ps->err = 1;
            return -1;
        }
        n = (unsigned char) ps->s[ps->i + 1];
        ps->i += 2;
        if (n == '(') {
            int id, body;
            /* Node storage already stops a nest that fits in EL_NODE_MAX.
               A deeper nest overflows the C stack before that. 256 is above
               every nest the node table can hold, so a pattern that parses
               today still parses. A deeper one fails closed to the same
               crude check as any other parse error. */
            if (ps->depth >= 256) {
                ps->err = 1;
                return -1;
            }
            ps->depth++;
            ps->caret_ok = 1;
            body = el_parse_alt_top (ps);
            ps->depth--;
            if (ps->err)
                return -1;
            if (!(ps->i + 1 < ps->n && ps->s[ps->i] == '\\' && ps->s[ps->i + 1] == ')')) {
                ps->err = 1;
                return -1;
            }
            ps->i += 2;
            /* Wrap the body so a group whose body is an anchor can still
               take a quantifier. glibc quantifies the group, not the anchor. */
            {
                int empty = el_new (ps, EL_EMPTY);
                if (body < 0)
                    body = el_new (ps, EL_EMPTY);
                id = el_new (ps, EL_CAT);
                if (id < 0 || empty < 0 || body < 0)
                    return -1;
                ps->pool[id].a = body;
                ps->pool[id].b = empty;
                return id;
            }
        }
        if (n >= '1' && n <= '9') {
            int id = el_new (ps, EL_EMPTY);
            ps->backref = 1;
            if (id >= 0)
                ps->pool[id].backref = 1;
            return id;
        }
        {
            int anch = 0, kind = 0;
            if (n == '`') anch = EL_BOS;
            else if (n == '\'') anch = EL_EOS;
            else if (n == '<') anch = EL_WFIRST;
            else if (n == '>') anch = EL_WLAST;
            else if (n == 'b') anch = EL_WB;
            else if (n == 'B') anch = EL_NWB;
            else if (n == 'w') kind = EL_WORD;
            else if (n == 'W') kind = EL_NWORD;
            else if (n == 's') kind = EL_SPACE;
            else if (n == 'S') kind = EL_NSPACE;
            if (anch) {
                int id = el_new (ps, EL_ANCHOR);
                if (id >= 0)
                    ps->pool[id].anch = anch;
                return id;
            }
            if (kind)
                return el_new (ps, kind);
            {
                int id = el_new (ps, EL_LIT);
                if (id >= 0)
                    ps->pool[id].lit = (unsigned char) n;
                return id;
            }
        }
    }
    {
        int id = el_new (ps, EL_LIT);
        ps->i++;
        if (id >= 0)
            ps->pool[id].lit = (unsigned char) c;
        return id;
    }
}

static int
el_parse_bounds (el_ps *ps, int *min, int *max)
{
    char buf[32];
    int bi = 0;
    int n1 = 0, n2 = 0, any1 = 0, any2 = 0;
    /* ps is at the character after \{ */
    while (ps->i < ps->n && isdigit ((unsigned char) ps->s[ps->i]) && bi < 30) {
        buf[bi++] = ps->s[ps->i++];
        any1 = 1;
    }
    buf[bi] = 0;
    if (any1)
        n1 = atoi (buf);
    if (ps->i < ps->n && ps->s[ps->i] == ',') {
        ps->i++;
        bi = 0;
        while (ps->i < ps->n && isdigit ((unsigned char) ps->s[ps->i]) && bi < 30) {
            buf[bi++] = ps->s[ps->i++];
            any2 = 1;
        }
        buf[bi] = 0;
        if (any2)
            n2 = atoi (buf);
        else
            n2 = -1;
    } else if (any1) {
        n2 = n1;
    } else {
        ps->err = 1;
        return -1;
    }
    if (!(ps->i + 1 < ps->n && ps->s[ps->i] == '\\' && ps->s[ps->i + 1] == '}')) {
        ps->err = 1;
        return -1;
    }
    ps->i += 2;
    if (n2 >= 0 && n1 > n2) {
        ps->err = 1;
        return -1;
    }
    *min = n1;
    *max = n2;
    return 0;
}

static int
el_apply_dup (el_ps *ps, int atom)
{
    int kind, min = 0, max = -1, id;
    if (!el_starts_dup (ps))
        return atom;
    kind = el_dup_kind (ps);
    if (kind == '*') {
        ps->i++;
        min = 0;
        max = -1;
    } else if (kind == '+') {
        ps->i += 2;
        min = 1;
        max = -1;
    } else if (kind == '?') {
        ps->i += 2;
        min = 0;
        max = 1;
    } else if (kind == '{') {
        ps->i += 2;
        if (el_parse_bounds (ps, &min, &max) < 0)
            return -1;
    } else {
        return atom;
    }
    /* A second * or \{ is a BRE error. \+ and \? may nest; reject a second
       open-ended dup only when glibc would (star or interval). */
    if (el_starts_dup (ps)) {
        int k2 = el_dup_kind (ps);
        if (k2 == '*' || k2 == '{') {
            ps->err = 1;
            return -1;
        }
    }
    if (min == 0 && max == 0)
        return el_new (ps, EL_EMPTY);
    id = el_new (ps, EL_REP);
    if (id < 0)
        return -1;
    ps->pool[id].a = atom;
    ps->pool[id].min = min;
    ps->pool[id].max = max;
    return id;
}

static int
el_parse_branch2 (el_ps *ps)
{
    int acc = -1;
    ps->caret_ok = 1;
    ps->dup_ok = 0;
    if (el_peek (ps) < 0)
        return el_new (ps, EL_EMPTY);
    if (el_peek (ps) == '\\' && ps->i + 1 < ps->n
        && (ps->s[ps->i + 1] == '|' || ps->s[ps->i + 1] == ')'))
        return el_new (ps, EL_EMPTY);
    while (ps->i < ps->n) {
        int piece;
        if (ps->s[ps->i] == '\\' && ps->i + 1 < ps->n
            && (ps->s[ps->i + 1] == '|' || ps->s[ps->i + 1] == ')'))
            break;
        if (!ps->dup_ok && el_starts_dup (ps)) {
            int k = el_dup_kind (ps);
            int id;
            if (k == '{') {
                ps->err = 1;
                return -1;
            }
            id = el_new (ps, EL_LIT);
            if (k == '*') {
                ps->i++;
                if (id >= 0)
                    ps->pool[id].lit = '*';
            } else {
                ps->i += 2;
                if (id >= 0)
                    ps->pool[id].lit = (unsigned char) k;
            }
            ps->caret_ok = 0;
            ps->dup_ok = 1;
            piece = el_apply_dup (ps, id);
        } else {
            piece = el_parse_atom (ps);
            if (piece < 0 || ps->err)
                return -1;
            ps->caret_ok = 0;
            if (ps->pool[piece].kind == EL_ANCHOR) {
                ps->dup_ok = 0;
            } else {
                ps->dup_ok = 1;
                piece = el_apply_dup (ps, piece);
            }
        }
        if (piece < 0 || ps->err)
            return -1;
        if (acc < 0)
            acc = piece;
        else {
            int id = el_new (ps, EL_CAT);
            if (id < 0)
                return -1;
            ps->pool[id].a = acc;
            ps->pool[id].b = piece;
            acc = id;
        }
    }
    if (acc < 0)
        return el_new (ps, EL_EMPTY);
    return acc;
}

/* The first branch parser is unused. Keep parse_alt calling branch2. */
static int
el_parse_alt_top (el_ps *ps)
{
    int left;
    /* Replace branch with branch2 by re-calling through a local wrap.
       parse_alt already calls el_parse_branch. Point that name's logic here
       by inlining: we do not use el_parse_alt. */
    left = el_parse_branch2 (ps);
    if (left < 0 || ps->err)
        return -1;
    while (ps->i + 1 < ps->n && ps->s[ps->i] == '\\' && ps->s[ps->i + 1] == '|') {
        int right, id;
        ps->i += 2;
        right = el_parse_branch2 (ps);
        if (right < 0 || ps->err)
            return -1;
        id = el_new (ps, EL_ALT);
        if (id < 0)
            return -1;
        ps->pool[id].a = left;
        ps->pool[id].b = right;
        left = id;
    }
    return left;
}

static int
el_parse (el_node *pool, const char *pat, int *backref, int *err)
{
    el_ps ps;
    int root;
    memset (&ps, 0, sizeof ps);
    ps.s = pat;
    ps.n = (int) strlen (pat);
    ps.pool = pool;
    ps.caret_ok = 1;
    root = el_parse_alt_top (&ps);
    if (ps.i != ps.n)
        ps.err = 1;
    *backref = ps.backref;
    *err = ps.err || root < 0;
    if (*err)
        return -1;
    el_props (pool, root);
    if (ps.backref)
        pool[root].backref = 1;
    return root;
}

static int
el_crude_dangerous (const char *pat)
{
    /* Used only when the structured parse fails. Refuse rather than hand a
       plus-of-group that contains a hang anchor to regexec with two registers. */
    const char *p;
    int group = 0, hang = 0, plus = 0;
    for (p = pat; *p; p++) {
        if (*p == '\\' && p[1]) {
            char n = p[1];
            if (n == '(')
                group = 1;
            else if (n == '+' )
                plus = 1;
            else if (n == '{') {
                const char *q = p + 2;
                int n1 = 0, any = 0;
                while (isdigit ((unsigned char) *q)) {
                    any = 1;
                    n1 = n1 * 10 + (*q - '0');
                    q++;
                }
                if (any && *q == ',' && q[1] == '\\' && q[2] == '}' && n1 >= 1)
                    plus = 1;
            } else if (n == '`' || n == '<' || n == '>')
                hang = 1;
            p++;
            continue;
        }
        if (*p == '^')
            hang = 1;
    }
    return group && hang && plus;
}

struct el_pred {
    int refuse;
    int dangerous;
    int bad_refused;
    int parse_err;
    int uncertain;
    int backref;
    int so, eo, safe_end;
};

static void
el_predict (const char *pat, const char *subj, struct el_pred *pr)
{
    el_node pool[EL_NODE_MAX];
    int root, err = 0, backref = 0;
    regex_t re;
    regmatch_t rm;
    el_mx mx;
    el_ends ends;
    int i, best;

    memset (pr, 0, sizeof *pr);
    pr->so = pr->eo = pr->safe_end = -1;
    memset (pool, 0, sizeof pool);
    root = el_parse (pool, pat, &backref, &err);
    pr->backref = backref;
    pr->parse_err = err;
    if (err || root < 0) {
        pr->refuse = el_crude_dangerous (pat);
        pr->dangerous = pr->refuse;
        return;
    }
    pr->dangerous = pool[root].dangerous;
    pr->backref = pool[root].backref || backref;
    if (pr->backref || !pr->dangerous)
        return;
    if (regcomp (&re, pat, 0) != 0)
        return;
    if (regexec (&re, subj, 1, &rm, 0) != 0) {
        regfree (&re);
        return;
    }
    pr->so = (int) rm.rm_so;
    pr->eo = (int) rm.rm_eo;
    regfree (&re);
    {
        size_t slen = strlen (subj);
        /* Offsets in this checker are ints. A dangerous pattern on a
           multi-gigabyte subject is refused rather than truncated. */
        if (slen > (size_t) (INT_MAX / 4)) {
            pr->uncertain = 1;
            pr->refuse = 1;
            return;
        }
        memset (&mx, 0, sizeof mx);
        mx.s = (const unsigned char *) subj;
        mx.n = (int) slen;
    }
    mx.mb = MB_CUR_MAX > 1;
    mx.pool = pool;
    mx.mark = calloc ((size_t) mx.n + 1, sizeof (int));
    mx.slot = calloc ((size_t) mx.n + 1, sizeof (int));
    if (!mx.mark || !mx.slot) {
        free (mx.mark);
        free (mx.slot);
        pr->uncertain = 1;
        pr->refuse = 1;
        return;
    }
    memset (&ends, 0, sizeof ends);
    el_match (&mx, root, pr->so, &ends);
    best = -1;
    for (i = 0; i < ends.n; i++) {
        if (ends.p[i].pos > best)
            best = ends.p[i].pos;
    }
    el_ends_free (&ends);
    free (mx.mark);
    free (mx.slot);
    mx.mark = NULL;
    mx.slot = NULL;
    pr->safe_end = best;
    pr->bad_refused = mx.bad_refused;
    pr->uncertain = mx.uncertain;
    if (mx.uncertain)
        pr->refuse = 1;
    else if (pr->eo > best && mx.bad_refused)
        pr->refuse = 1;
}
#endif /* __GLIBC__ */

static bex_val
bex_regex_result (regex_t *r, const char *s, const char *pat, int *err)
{
    regmatch_t m[2];
    int nmatch;
    int rc;
#if defined (__GLIBC__)
    if (r->re_nsub > 0) {
        regmatch_t one;
        int rc1;
        struct el_pred pred;
        /* GNU expr matches at offset 0 only. nmatch <= 1 does not enter
           set_regs, so a hit that starts later is a non-match and must
           not be searched again with two registers. */
        rc1 = regexec (r, s ? s : "", 1, &one, 0);
        if (rc1 != 0 || one.rm_so != 0)
            return bex_make ("");
        el_predict (pat, s ? s : "", &pred);
        if (pred.refuse) {
            builtin_error ("regex does not finish: repeated group with an anchor");
            if (err)
                *err = 2;
            return bex_make ("");
        }
    }
#else
    (void) pat;
    (void) err;
#endif
    nmatch = r->re_nsub > 0 ? 2 : 1;
    rc = regexec (r, s, nmatch, m, 0);

    if (r->re_nsub > 0) {
        if (rc != 0 || m[0].rm_so != 0 || m[1].rm_so < 0)
            return bex_make ("");

        long long len = m[1].rm_eo - m[1].rm_so;
        char *cap = malloc ((size_t) len + 1);
        if (!cap)
            return bex_make ("");
        memcpy (cap, s + m[1].rm_so, (size_t) len);
        cap[len] = '\0';
        bex_val v = bex_make (cap);
        free (cap);
        return v;
    }

    if (rc != 0 || m[0].rm_so != 0)
        return bex_from_ll (0);
    return bex_from_ll (m[0].rm_eo);
}

/* --- Recursive-descent parser. Token stream is the WORD_LIST. ----- */
typedef struct {
    WORD_LIST  *cur;
    int         err;
    const char *last;   /* most recently consumed token, for GNU-shaped errors */
} bex_parser;

static const char *
bex_peek (bex_parser *p)
{
    return p->cur ? p->cur->word->word : NULL;
}

static const char *
bex_take (bex_parser *p)
{
    const char *w = bex_peek (p);
    if (p->cur) { p->last = w; p->cur = p->cur->next; }
    return w;
}

/* After consuming an infix operator OP, verify a right operand follows.
   Returns 1 (and flags a GNU-shaped syntax error) when none does, so the
   binary parsers can bail instead of descending into a second, confusing
   "non-integer argument" / "missing operand" diagnostic. */
static int
bex_need_operand (bex_parser *p, const char *op)
{
    if (!p->cur) {
        builtin_error ("syntax error: missing argument after '%s'", op);
        p->err = 2;
        return 1;
    }
    return 0;
}

/* GNU expr threads a `bool evaluate` flag through every level: `|` and `&`
   short-circuit by evaluating the other operand only when needed, and a
   short-circuited (evaluate==0) branch still PARSES its tokens but performs
   no value computation, so its arithmetic/regex/division errors do not fire
   (e.g. `expr -5 \| 1 / 0` yields -5, not a division-by-zero error). Syntax
   errors (missing operand, unbalanced parens) fire regardless. */
static bex_val bex_parse_or (bex_parser *p, int evaluate);

/* primary: NUMBER | STRING | ( EXPR ) | length STR | substr S P L | index S C | match S RE */
static bex_val
bex_parse_primary (bex_parser *p, int evaluate)
{
    const char *w = bex_take (p);
    if (!w) {
        builtin_error ("syntax error: missing operand");
        p->err = 2;
        return bex_make ("");
    }
    if (!strcmp (w, "(")) {
        bex_val v = bex_parse_or (p, evaluate);
        const char *r = bex_take (p);
        if (!r) {
            builtin_error ("syntax error: expecting ')' after '%s'", p->last);
            p->err = 2;
        } else if (strcmp (r, ")") != 0) {
            builtin_error ("syntax error: expecting ')' instead of '%s'", r);
            p->err = 2;
        }
        return v;
    }
    if (!strcmp (w, "length")) {
        const char *s = bex_take (p);
        if (!s) { builtin_error ("syntax error: missing argument after '%s'", p->last); p->err = 2; return bex_make (""); }
        return bex_from_ll ((long long) strlen (s));
    }
    if (!strcmp (w, "substr")) {
        const char *s = bex_take (p);
        if (!s) { builtin_error ("syntax error: missing argument after '%s'", p->last); p->err = 2; return bex_make (""); }
        const char *ps = bex_take (p);
        if (!ps) { builtin_error ("syntax error: missing argument after '%s'", p->last); p->err = 2; return bex_make (""); }
        const char *ls = bex_take (p);
        if (!ls) { builtin_error ("syntax error: missing argument after '%s'", p->last); p->err = 2; return bex_make (""); }
        long long pos = atoll (ps), len = atoll (ls);
        long long slen = (long long) strlen (s);
        if (pos < 1 || pos > slen || len < 1) return bex_make ("");
        long long avail = slen - (pos - 1);
        if (len > avail) len = avail;
        char *out = malloc ((size_t) len + 1);
        if (!out) { builtin_error ("out of memory"); p->err = 2; return bex_make (""); }
        memcpy (out, s + (pos - 1), (size_t) len);
        out[len] = '\0';
        bex_val v = bex_make (out);
        free (out);
        return v;
    }
    if (!strcmp (w, "index")) {
        const char *s = bex_take (p);
        if (!s) { builtin_error ("syntax error: missing argument after '%s'", p->last); p->err = 2; return bex_make (""); }
        const char *c = bex_take (p);
        if (!c) { builtin_error ("syntax error: missing argument after '%s'", p->last); p->err = 2; return bex_make (""); }
        for (long long i = 0; s[i]; i++)
            if (strchr (c, s[i])) return bex_from_ll (i + 1);
        return bex_from_ll (0);
    }
    if (!strcmp (w, "match")) {
        const char *s = bex_take (p);
        if (!s) { builtin_error ("syntax error: missing argument after '%s'", p->last); p->err = 2; return bex_make (""); }
        const char *re = bex_take (p);
        if (!re) { builtin_error ("syntax error: missing argument after '%s'", p->last); p->err = 2; return bex_make (""); }
        if (!evaluate) return bex_make ("");  /* short-circuited: tokens consumed, value unused */
        regex_t r;
        if (regcomp (&r, re, 0) != 0) { builtin_error ("bad regex: %s", re); p->err = 2; return bex_make (""); }
        bex_val v = bex_regex_result (&r, s, re, &p->err);
        regfree (&r);
        return v;
    }
    return bex_make (w);
}

/* `:` regex match: STR : RE — POSIX shape. Same semantics as `match`. */
static bex_val
bex_parse_re (bex_parser *p, int evaluate)
{
    bex_val l = bex_parse_primary (p, evaluate);
    while (p->cur && !strcmp (p->cur->word->word, ":")) {
        bex_take (p);
        if (bex_need_operand (p, ":")) { return l; }
        bex_val r = bex_parse_primary (p, evaluate);
        if (!evaluate) { bex_free (&r); continue; }  /* short-circuited: keep l, skip match */
        regex_t rg;
        if (regcomp (&rg, r.s, 0) != 0) { builtin_error ("bad regex: %s", r.s); p->err = 2; bex_free (&l); bex_free (&r); return bex_make (""); }
        bex_val out = bex_regex_result (&rg, l.s, r.s, &p->err);
        regfree (&rg);
        bex_free (&l); bex_free (&r);
        l = out;
    }
    return l;
}

static bex_val
bex_parse_mul (bex_parser *p, int evaluate)
{
    bex_val l = bex_parse_re (p, evaluate);
    while (p->cur) {
        const char *op = p->cur->word->word;
        if (strcmp (op, "*") && strcmp (op, "/") && strcmp (op, "%")) break;
        bex_take (p);
        if (bex_need_operand (p, op)) { return l; }
        bex_val r = bex_parse_re (p, evaluate);
        if (!evaluate) { bex_free (&r); continue; }  /* short-circuited: no arith/div0 */
        long long a, b;
        if (bex_require_num (&l, &a) < 0 || bex_require_num (&r, &b) < 0) { p->err = 2; bex_free (&l); bex_free (&r); return bex_make (""); }
        long long n;
        if      (!strcmp (op, "*")) n = a * b;
        else if (!strcmp (op, "/")) { if (!b) { builtin_error ("division by zero"); p->err = 2; bex_free (&l); bex_free (&r); return bex_make (""); } n = a / b; }
        else                         { if (!b) { builtin_error ("division by zero"); p->err = 2; bex_free (&l); bex_free (&r); return bex_make (""); } n = a % b; }
        bex_free (&l); bex_free (&r);
        l = bex_from_ll (n);
    }
    return l;
}

static bex_val
bex_parse_add (bex_parser *p, int evaluate)
{
    bex_val l = bex_parse_mul (p, evaluate);
    while (p->cur) {
        const char *op = p->cur->word->word;
        if (strcmp (op, "+") && strcmp (op, "-")) break;
        bex_take (p);
        if (bex_need_operand (p, op)) { return l; }
        bex_val r = bex_parse_mul (p, evaluate);
        if (!evaluate) { bex_free (&r); continue; }  /* short-circuited: no arith */
        long long a, b;
        if (bex_require_num (&l, &a) < 0 || bex_require_num (&r, &b) < 0) { p->err = 2; bex_free (&l); bex_free (&r); return bex_make (""); }
        long long n = !strcmp (op, "+") ? a + b : a - b;
        bex_free (&l); bex_free (&r);
        l = bex_from_ll (n);
    }
    return l;
}

static bex_val
bex_parse_cmp (bex_parser *p, int evaluate)
{
    bex_val l = bex_parse_add (p, evaluate);
    while (p->cur) {
        const char *op = p->cur->word->word;
        if (strcmp (op, "=") && strcmp (op, "!=") && strcmp (op, "<") &&
            strcmp (op, "<=") && strcmp (op, ">") && strcmp (op, ">=")) break;
        bex_take (p);
        if (bex_need_operand (p, op)) { return l; }
        bex_val r = bex_parse_add (p, evaluate);
        if (!evaluate) { bex_free (&r); continue; }  /* short-circuited: skip compare */
        int t;
        if (l.is_num && r.is_num) {
            long long a = l.n, b = r.n;
            if (!strcmp (op, "="))  t = (a == b);
            else if (!strcmp (op, "!=")) t = (a != b);
            else if (!strcmp (op, "<"))  t = (a <  b);
            else if (!strcmp (op, "<=")) t = (a <= b);
            else if (!strcmp (op, ">"))  t = (a >  b);
            else                          t = (a >= b);
        } else {
            int c = strcmp (l.s, r.s);
            if (!strcmp (op, "="))  t = (c == 0);
            else if (!strcmp (op, "!=")) t = (c != 0);
            else if (!strcmp (op, "<"))  t = (c <  0);
            else if (!strcmp (op, "<=")) t = (c <= 0);
            else if (!strcmp (op, ">"))  t = (c >  0);
            else                          t = (c >= 0);
        }
        bex_free (&l); bex_free (&r);
        l = bex_from_ll (t);
    }
    return l;
}

static bex_val
bex_parse_and (bex_parser *p, int evaluate)
{
    bex_val l = bex_parse_cmp (p, evaluate);
    while (p->cur && !strcmp (p->cur->word->word, "&")) {
        bex_take (p);
        if (bex_need_operand (p, "&")) { return l; }
        /* GNU eval1: evaluate the right operand only if the left is truthy
           (a null/zero left short-circuits to 0). */
        bex_val r = bex_parse_cmp (p, evaluate && bex_truthy (&l));
        if (bex_truthy (&l) && bex_truthy (&r)) {
            bex_free (&r);
            /* keep l */
        } else {
            bex_free (&l); bex_free (&r);
            l = bex_from_ll (0);
        }
    }
    return l;
}

static bex_val
bex_parse_or (bex_parser *p, int evaluate)
{
    bex_val l = bex_parse_and (p, evaluate);
    while (p->cur && !strcmp (p->cur->word->word, "|")) {
        bex_take (p);
        if (bex_need_operand (p, "|")) { return l; }
        /* GNU eval (top): evaluate the right operand only if the left is
           null/zero; a truthy left short-circuits and returns the left. */
        bex_val r = bex_parse_and (p, evaluate && !bex_truthy (&l));
        if (bex_truthy (&l))
            bex_free (&r);
        else {
            bex_free (&l);
            l = r;
            /* GNU: when the chosen (right) operand is itself null/zero, the
               result normalizes to "0" rather than the empty string. */
            if (!bex_truthy (&l)) { bex_free (&l); l = bex_from_ll (0); }
        }
    }
    return l;
}

int
expr_builtin (WORD_LIST *list)
{
	if (!list) {
	    builtin_error ("missing operand");
	    builtin_usage ();
	    return 2;
	}
    bex_parser p = { list, 0, "" };
    bex_val v = bex_parse_or (&p, 1);
    if (p.err) { bex_free (&v); return p.err; }
    if (p.cur) {
        builtin_error ("syntax error: unexpected argument '%s'", p.cur->word->word);
        bex_free (&v);
        return 2;
    }
    puts (v.s);
    int rc = bex_truthy (&v) ? 0 : 1;
    bex_free (&v);
    return rc;
}

char *expr_doc[] = {
    "Evaluate POSIX expr(1) expressions.",
    "",
    "    expr ARG...",
    "",
    "Operators (POSIX precedence, lowest first):",
    "    | &                  — first-truthy / both-truthy logic",
    "    = != < <= > >=       — comparison (numeric if both args parse)",
    "    + -                  — addition / subtraction",
    "    * / %                — multiplication / division / modulo",
    "    :                    — STR : RE BRE match (paren-1 capture or len)",
    "    ( ... )              — grouping",
    "",
    "String functions:",
    "    length STR           — byte count",
    "    substr STR POS LEN   — POS is 1-based",
    "    index STR CHARS      — first byte of STR matching any of CHARS",
    "    match STR RE         — same as STR : RE",
    "",
    "On glibc, a pattern that would make regexec loop is an error (exit 2).",
    "That is a + or {n,} (n at least 1) on a group that can match empty,",
    "when the group contains ^, \\`, \\< or \\> followed by a consuming atom",
    "(a POSIX class consumes a whole multibyte character) and this subject",
    "would take that path. A match that does not begin at the first byte is",
    "a non-match, the same as GNU expr. A back-reference is unchanged.",
    "bash [[ =~ ]] uses the same matcher and can still hang; this command",
    "does not change it.",
    "",
    "Exit: 0 if result is non-zero/non-empty, 1 if zero/empty,",
    "      2 on syntax error.",
    (char *)NULL
};

struct builtin expr_struct = {
    "expr",
    expr_builtin,
    BUILTIN_ENABLED,
    expr_doc,
    "expr ARG...",
    0
};
