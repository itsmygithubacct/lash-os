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
#include <regex.h>

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

static bex_val
bex_regex_result (regex_t *r, const char *s)
{
    regmatch_t m[2];
    int nmatch = r->re_nsub > 0 ? 2 : 1;
    int rc = regexec (r, s, nmatch, m, 0);

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
        bex_val v = bex_regex_result (&r, s);
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
        bex_val out = bex_regex_result (&rg, l.s);
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
