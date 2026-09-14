/* grep.c — grep(1) as a bash builtin, held to GNU grep's output.
 *
 * The input is read in 96 KB blocks and searched a block at a time, not a
 * line at a time:
 *   - a pattern with no regex operator (or -F) is a fixed-string search over
 *     the block with memmem, and only the lines holding an occurrence are
 *     looked at;
 *   - a regular expression is prefiltered by a literal that every match must
 *     contain, found the same way, and regexec runs only on the lines that
 *     carry it;
 *   - a regular expression with no such literal runs regexec line by line.
 * Line numbers are counted only when -n asks for them, byte offsets come
 * from the block's file offset, and -B context is read back out of the
 * block, which keeps the lines before the current one.
 *
 * Dialects: the default is BRE as in GNU grep (\( \) \| \+ \? \{ \} are
 * operators, ( ) | + ? { } are literal), -E is ERE, -F fixed strings, -P
 * PCRE2 when built with BASHGREP_PCRE2=1. The rules GNU grep applies on top
 * of the regex engine are reproduced from grep 3.11: -w retries a shorter
 * match at the same place and then the next start; -x is a match spanning
 * the line; -m keeps printing trailing context; a NUL makes a file binary
 * (NULs then separate lines, output goes quiet, "binary file matches" goes
 * to stderr), and a printed line that is not valid in the locale's
 * encoding does the same; stdin is left positioned just after the last
 * match for -m, or at its end when grep stopped early. tests/grep-parity.sh
 * holds the output to GNU's.
 *
 * Flags: -E -F -G -P -i -y -v -c -l -L -n -b -o -q -s -H -h -w -x -r -R -a
 * -I -Z -z -m N -e PAT -f FILE -A N -B N -C N -NUM --include --exclude
 * --exclude-dir --binary-files --color (accepted, no color is emitted).
 *
 * SPDX-License-Identifier: MIT
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
#include <ctype.h>
#include <wchar.h>
#include <wctype.h>
#include <regex.h>
#include <fnmatch.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef BASHGREP_PCRE2
#define BASHGREP_PCRE2 0   /* set 1 to enable `grep -P`; needs libpcre2. Off: POSIX regex only. */
#endif
#if BASHGREP_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#else
/* No PCRE2 in this build. Stub the opaque types and the few functions used
   outside the (guarded) helper block; -P then fails cleanly at run time. */
typedef void pcre2_code;
typedef void pcre2_match_data;
typedef void pcre2_match_context;
#ifndef PCRE2_NOTBOL
#define PCRE2_NOTBOL 0u
#endif
#define pcre2_match_data_create_from_pattern(a,b) ((pcre2_match_data *)0)
#define pcre2_code_free(a)        ((void)0)
#define pcre2_match_data_free(a)  ((void)0)
#endif

#include "loadables.h"

/* glibc's REG_STARTEND lets regexec see a whole line while matching a part
   of it, so \< and \b know the character before the part and a NUL inside
   the line (-a) is data. Without it (musl) the part is NUL-terminated in
   place, and whether it follows the record delimiter decides REG_NOTBOL;
   the one thing that path cannot do is match across a NUL under -a (noted
   in docs/PROVENANCE.md). */
#ifdef REG_STARTEND
#  define BG_STARTEND 1
#else
#  define BG_STARTEND 0
#endif

#define BG_BLOCK (96 * 1024)
#define BG_NONE    ((size_t) -2)     /* needle cache: no occurrence ahead */
#define BG_UNKNOWN ((size_t) -1)     /* needle cache: not searched yet */
#define BG_NOHIT   ((size_t) -1)     /* bg_memfind: not found */

typedef struct { char *s; size_t n; size_t k; } bg_str;   /* k: index of its rarest byte */

enum bg_mode { BG_FIXED, BG_REGEX, BG_PCRE };

typedef struct {
    int iflag, vflag, cflag, lflag, Lflag, nflag, bflag, oflag, rflag, Rflag;
    int Hflag, hflag, Fflag, Gflag, Eflag, Pflag, qflag, sflag, wflag, xflag;
    int Zflag, zdflag, aflag, Iflag;
    int mflag, mflag_set;           /* -m N */
    int A, B, ctx;                  /* context lines; ctx: any of -A/-B/-C given */
    char **incl_globs;  int n_incl;
    char **excl_globs;  int n_excl;
    char **excl_dir_globs; int n_excl_dir;
    int delim;                      /* record delimiter: '\n', or NUL with -z */
    int mb;                         /* multibyte locale */
    int used;                       /* something was printed: "--" may be needed (across files, as GNU) */
    /* the patterns as given, one arm per -e/-f line or positional pattern */
    bg_str *arms; int n_arms, cap_arms;
    /* the matcher */
    enum bg_mode mode;
    bg_str *needles; int n_needles; /* BG_FIXED: sorted longest first */
    bg_str *xneedles;               /* the same wrapped in the delimiter (-x, ^lit, lit$) */
    int wrap_l, wrap_r;             /* the wrapped needles carry a delimiter on that side */
    int implicit_dot;               /* -r with no operand: the working directory */
    int fold;                       /* the fixed search folds case bytewise */
    unsigned char lower[256], alt[256];   /* fold table; the other byte folding to the same */
    bg_str must;                    /* BG_REGEX: a literal every match contains (n == 0: none) */
    int nl_safe;                    /* BG_REGEX: no match can hold the delimiter: search whole blocks */
    regex_t *re; int n_re;          /* BG_REGEX: one, or one per arm when that is needed */
    regex_t *re_ns;                 /* the same with REG_NOSUB: a faster yes or no (NULL: none) */
    char *combined;                 /* the combined pattern text, freed at the end */
    pcre2_code *pcre; pcre2_match_data *pcre_md;
    size_t *kw_blk, *kw_line;       /* needle caches: the block scan, the line scan */
    char *ob; size_t on;            /* the output buffer: bash line-buffers stdout, a write per line */
} bg_opts;

#define BG_OUTBUF (64 * 1024)

#define BG_PCRE_DEFAULT_MATCH_LIMIT 1000000u
#define BG_PCRE_DEFAULT_DEPTH_LIMIT 10000u

static int
bg_parse_count (const char *s, int *out)
{
    char *end = NULL;
    long n;
    errno = 0;
    n = strtol (s, &end, 10);
    if (errno || end == s || *end || n < 0 || n > 1000000)
        return -1;
    *out = (int) n;
    return 0;
}

/* ---------------------------------------------------------------- PCRE2 --- */

#if BASHGREP_PCRE2
static pcre2_match_context *
bg_pcre_match_ctx (void)
{
    static pcre2_match_context *ctx = NULL;
    if (!ctx)
    {
        ctx = pcre2_match_context_create (NULL);
        if (!ctx)
            return NULL;
    }
    uint32_t mlim = BG_PCRE_DEFAULT_MATCH_LIMIT;
    uint32_t dlim = BG_PCRE_DEFAULT_DEPTH_LIMIT;
    const char *e;
    if ((e = getenv ("BASHPCRE_MATCH_LIMIT")) && *e)
    {
        unsigned long v = strtoul (e, NULL, 10);
        if (v) mlim = (uint32_t) v;
    }
    if ((e = getenv ("BASHPCRE_DEPTH_LIMIT")) && *e)
    {
        unsigned long v = strtoul (e, NULL, 10);
        if (v) dlim = (uint32_t) v;
    }
    pcre2_set_match_limit (ctx, mlim);
    pcre2_set_depth_limit (ctx, dlim);
    return ctx;
}

static pcre2_code *
bg_pcre_compile (const char *pattern, int iflag)
{
    uint32_t flags = PCRE2_UTF | PCRE2_UCP;
    if (iflag)
        flags |= PCRE2_CASELESS;

    int errcode;
    PCRE2_SIZE erroffset;
    pcre2_code *code = pcre2_compile ((PCRE2_SPTR) pattern,
                                      PCRE2_ZERO_TERMINATED,
                                      flags, &errcode, &erroffset, NULL);
    if (!code)
    {
        char buf[256];
        pcre2_get_error_message (errcode, (PCRE2_UCHAR *) buf, sizeof buf);
        builtin_error ("bad PCRE regex at offset %zu: %s",
                       (size_t) erroffset, buf);
    }
    return code;
}

static int
bg_pcre_exec (const bg_opts *o, const char *line, size_t llen,
              size_t start, uint32_t match_opts, regmatch_t *m)
{
    int rc = pcre2_match (o->pcre, (PCRE2_SPTR) line, llen, start,
                          match_opts, o->pcre_md, bg_pcre_match_ctx ());
    if (rc == PCRE2_ERROR_NOMATCH)
        return 0;
    if (rc < 0)
    {
        char buf[128];
        pcre2_get_error_message (rc, (PCRE2_UCHAR *) buf, sizeof buf);
        builtin_error ("PCRE match error: %s", buf);
        return -1;
    }
    PCRE2_SIZE *ovec = pcre2_get_ovector_pointer (o->pcre_md);
    m->rm_so = (regoff_t) ovec[0];
    m->rm_eo = (regoff_t) ovec[1];
    return 1;
}
#else /* !BASHGREP_PCRE2 : POSIX-only build */
static pcre2_code *
bg_pcre_compile (const char *pattern, int iflag)
{
    (void) pattern; (void) iflag;
    builtin_error ("grep: -P (Perl regex) not supported in this build");
    return (pcre2_code *) 0;
}
static int
bg_pcre_exec (const bg_opts *o, const char *line, size_t llen,
              size_t start, uint32_t match_opts, regmatch_t *m)
{
    (void) o; (void) line; (void) llen; (void) start; (void) match_opts; (void) m;
    return -1;
}
#endif /* BASHGREP_PCRE2 */

/* ------------------------------------------------------- byte helpers --- */

static long
bg_memcount (const char *p, size_t n, int c)
{
    long k = 0;
    const char *e = p + n;
    while (p < e && (p = memchr (p, c, (size_t) (e - p))))
    {
        k++;
        p++;
    }
    return k;
}

/* How common a byte is in text, roughly (space and e t a o i n most): the
   search scans for the needle's rarest byte, so that a needle with a digit
   or punctuation in it makes memchr do nearly all the work. */
static unsigned char
bg_freq (unsigned char c)
{
    static const char *order = " etaoinshrdlcumwfgypbvkjxqz";
    if (c >= 'A' && c <= 'Z') c = (unsigned char) (c - 'A' + 'a');
    const char *q = (c < 0x80) ? strchr (order, c) : NULL;
    if (q && c) return (unsigned char) (100 - (q - order) * 3);
    if (c >= '0' && c <= '9') return 30;
    if (c >= 0x80) return 25;
    if (c == '\n' || c == '\t') return 40;
    return 10;
}

static void
bg_set_rare (bg_str *nd)
{
    nd->k = 0;
    for (size_t i = 1; i < nd->n; i++)
        if (bg_freq ((unsigned char) nd->s[i]) < bg_freq ((unsigned char) nd->s[nd->k])) nd->k = i;
}

/* NEEDLE[NLEN] equals HAY[..NLEN], folding case when the search folds. */
static int
bg_eq (const bg_opts *o, const char *hay, const char *needle, size_t nlen)
{
    if (!o->fold)
        return memcmp (hay, needle, nlen) == 0;
    for (size_t k = 0; k < nlen; k++)
        if (o->lower[(unsigned char) hay[k]] != o->lower[(unsigned char) needle[k]])
            return 0;
    return 1;
}

/* The leftmost occurrence of ND in HAY[HLEN] starting at or after FROM, or
   BG_NOHIT. memchr finds the candidates by the needle's rarest byte (both
   cases of it when folding, the second looked for only up to the first),
   and the rest is compared; there is no set-up per call, so a search that
   restarts at every matching line costs nothing extra. */
static size_t
bg_memfind (const bg_opts *o, const char *hay, size_t hlen, size_t from, const bg_str *nd)
{
    size_t nlen = nd->n, k = nd->k;
    if (from > hlen) return BG_NOHIT;
    if (nlen == 0) return from;
    if (nlen > hlen - from) return BG_NOHIT;
    unsigned char c0 = (unsigned char) nd->s[k], c1 = c0;
    if (o->fold) { c0 = o->lower[c0]; c1 = o->alt[c0]; }
    const char *p = hay + from + k, *end = hay + hlen - nlen + 1 + k;
    while (p < end)
    {
        const char *q = memchr (p, c0, (size_t) (end - p));
        if (!q) q = end;
        if (c1 != c0)
        {
            const char *r = memchr (p, c1, (size_t) (q - p));
            if (r) q = r;
        }
        if (q == end) return BG_NOHIT;
        if (bg_eq (o, q - k, nd->s, nlen)) return (size_t) (q - k - hay);
        p = q + 1;
    }
    return BG_NOHIT;
}

/* A set of needles searched over one haystack: NEXT caches where each
   needle occurs next, so a needle is searched once per occurrence rather
   than once per call (with many needles and one frequent, a fresh search
   per call would be quadratic). */
typedef struct { const char *hay; size_t hlen; size_t *next; } bg_kw;

/* The leftmost, then longest, occurrence of any of the N needles in
   HAY[HLEN] at or after FROM: 1 with the position and length, or 0. Needles are sorted
   longest first, so the first at a position is the longest. */
static int
bg_kw_find (const bg_opts *o, bg_kw *kw, const bg_str *needles, int n,
            const char *hay, size_t hlen, size_t from, size_t *at, size_t *len)
{
    if (kw->hay != hay || kw->hlen != hlen)
    {
        kw->hay = hay; kw->hlen = hlen;
        for (int i = 0; i < n; i++) kw->next[i] = BG_UNKNOWN;
    }
    size_t best = BG_NOHIT, blen = 0;
    for (int i = 0; i < n; i++)
    {
        size_t p = kw->next[i];
        if (p == BG_UNKNOWN || (p != BG_NONE && p < from))
        {
            p = bg_memfind (o, hay, hlen, from, &needles[i]);
            kw->next[i] = (p == BG_NOHIT) ? BG_NONE : p;
        }
        if (p == BG_NONE) continue;
        if (best == BG_NOHIT || p < best) { best = p; blen = needles[i].n; }
    }
    if (best == BG_NOHIT) return 0;
    *at = best; *len = blen;
    return 1;
}

/* ------------------------------------------------- locale: -w and UTF-8 --- */

/* Is the character starting at LINE[POS] a word constituent (alnum or _)?
   In a multibyte locale a multibyte character is decoded, as GNU does;
   an invalid sequence is not a word constituent. */
static int
bg_wordchar_at (const bg_opts *o, const char *line, size_t llen, size_t pos)
{
    if (pos >= llen) return 0;
    unsigned char c = (unsigned char) line[pos];
    if (!o->mb || c < 0x80) return isalnum (c) || c == '_';
    wchar_t wc; mbstate_t st; memset (&st, 0, sizeof st);
    size_t k = mbrtowc (&wc, line + pos, llen - pos, &st);
    if (k == (size_t) -1 || k == (size_t) -2 || k == 0) return 0;
    return iswalnum ((wint_t) wc) || wc == L'_';
}

/* Is the character ending at LINE[POS] (the one before POS) a word
   constituent? */
static int
bg_wordchar_before (const bg_opts *o, const char *line, size_t pos)
{
    if (pos == 0) return 0;
    unsigned char c = (unsigned char) line[pos - 1];
    if (!o->mb || c < 0x80) return isalnum (c) || c == '_';
    for (size_t k = 1; k <= (size_t) MB_CUR_MAX && k <= pos; k++)
    {
        wchar_t wc; mbstate_t st; memset (&st, 0, sizeof st);
        if (mbrtowc (&wc, line + pos - k, k, &st) == k)
            return iswalnum ((wint_t) wc) || wc == L'_';
    }
    return 0;
}

/* Does P[N] hold a byte sequence that is not a character of the locale?
   (Only asked in a multibyte locale; GNU then treats the file as binary.) */
static int
bg_encoding_error (const bg_opts *o, const char *p, size_t n)
{
    if (!o->mb) return 0;
    mbstate_t st; memset (&st, 0, sizeof st);
    size_t i = 0;
    while (i < n)
    {
        if ((unsigned char) p[i] < 0x80)
        {
            uint64_t w;
            while (i + 8 <= n && (memcpy (&w, p + i, 8), !(w & 0x8080808080808080ull))) i += 8;
            if (i < n && (unsigned char) p[i] < 0x80) { i++; continue; }
            if (i >= n) break;
        }
        size_t k = mbrtowc (NULL, p + i, n - i, &st);
        if (k == (size_t) -1 || k == (size_t) -2) return 1;
        i += k ? k : 1;
    }
    return 0;
}

/* ------------------------------------------------------ pattern analysis --- */

/* One arm of the pattern set is classified in its dialect: a pure literal
   (no operator: the unescaped bytes become a needle), or a regex with the
   longest run of literal bytes every match must contain (the prefilter).
   The analysis is conservative: anything not understood ends the run
   without adding to it, which can only shorten the must, never make it
   wrong. */
typedef struct {
    int ere;
    char *run; size_t rn;       /* the current literal run */
    char *best; size_t bn;      /* the longest run so far */
    int ops;                    /* an operator was seen: not a pure literal */
    int backref;                /* \1..\9 present */
    int prev_lit;               /* the previous atom is run's last byte */
} bg_ana;

static void bg_ana_end (bg_ana *a)
{
    if (a->rn > a->bn) { memcpy (a->best, a->run, a->rn); a->bn = a->rn; }
    a->rn = 0; a->prev_lit = 0;
}
static void bg_ana_lit (bg_ana *a, char c) { a->run[a->rn++] = c; a->prev_lit = 1; }
static void bg_ana_op (bg_ana *a) { a->ops = 1; bg_ana_end (a); }
/* A quantifier on the previous atom; an optional one takes it out of the run. */
static void bg_ana_quant (bg_ana *a, int optional)
{
    a->ops = 1;
    if (optional && a->prev_lit && a->rn > 0) a->rn--;
    bg_ana_end (a);
}

/* Skip the bracket expression opening at P[I]; the index after it. */
static size_t
bg_skip_bracket (const char *p, size_t n, size_t i)
{
    size_t j = i + 1;
    if (j < n && p[j] == '^') j++;
    if (j < n && p[j] == ']') j++;
    while (j < n && p[j] != ']')
    {
        if (p[j] == '[' && j + 1 < n
            && (p[j + 1] == ':' || p[j + 1] == '.' || p[j + 1] == '='))
        {
            char dl = p[j + 1];
            j += 2;
            while (j + 1 < n && !(p[j] == dl && p[j + 1] == ']')) j++;
            j = (j + 1 < n) ? j + 2 : n;
        }
        else j++;
    }
    return j < n ? j + 1 : n;
}

/* The index of the token closing the group opened at P[I] ("(" in ERE,
   "\(" in BRE), or N when unbalanced. */
static size_t
bg_group_close (const char *p, size_t n, size_t i, int ere)
{
    int depth = 0;
    for (size_t j = i; j < n; )
    {
        if (p[j] == '\\' && j + 1 < n)
        {
            if (!ere && p[j + 1] == '(') depth++;
            else if (!ere && p[j + 1] == ')' && --depth == 0) return j;
            j += 2; continue;
        }
        if (p[j] == '[') { j = bg_skip_bracket (p, n, j); continue; }
        if (ere && p[j] == '(') depth++;
        else if (ere && p[j] == ')' && --depth == 0) return j;
        j++;
    }
    return n;
}

/* Is there an alternation at the top level of P[I..E)? */
static int
bg_has_alt (const char *p, size_t e, size_t i, int ere)
{
    int depth = 0;
    for (size_t j = i; j < e; )
    {
        if (p[j] == '\\' && j + 1 < e)
        {
            if (!ere)
            {
                if (p[j + 1] == '(') depth++;
                else if (p[j + 1] == ')') depth--;
                else if (p[j + 1] == '|' && depth == 0) return 1;
            }
            j += 2; continue;
        }
        if (p[j] == '[') { j = bg_skip_bracket (p, e, j); continue; }
        if (ere)
        {
            if (p[j] == '(') depth++;
            else if (p[j] == ')') depth--;
            else if (p[j] == '|' && depth == 0) return 1;
        }
        j++;
    }
    return 0;
}

/* Parse an interval body at P[I] (after "{" or "\{"): the index after the
   closing brace, or 0 when it is not one. *OPTIONAL: the minimum is 0. */
static size_t
bg_interval (const char *p, size_t n, size_t i, int ere, int *optional)
{
    size_t j = i; long lo = -1;
    if (j < n && p[j] >= '0' && p[j] <= '9')
    {
        lo = 0;
        while (j < n && p[j] >= '0' && p[j] <= '9') lo = lo * 10 + (p[j++] - '0');
    }
    if (j < n && p[j] == ',')
    {
        j++;
        if (lo < 0) lo = 0;
        while (j < n && p[j] >= '0' && p[j] <= '9') j++;
    }
    if (lo < 0) return 0;
    if (ere)
    {
        if (j < n && p[j] == '}') { *optional = lo == 0; return j + 1; }
        return 0;
    }
    if (j + 1 < n && p[j] == '\\' && p[j + 1] == '}') { *optional = lo == 0; return j + 2; }
    return 0;
}

static void bg_ana_seq (bg_ana *a, const char *p, size_t e, size_t i);

/* A group with content P[CS..CE) whose closing token ends at AFTER: the
   index to continue from. A quantified group is not required as a whole
   and is skipped; one with an alternation inside contributes nothing. */
static size_t
bg_ana_group (bg_ana *a, const char *p, size_t e, size_t cs, size_t ce, size_t after)
{
    int ere = a->ere;
    bg_ana_op (a);
    if (ce >= e) return e;
    size_t q = after;
    if (q < e)
    {
        int opt = 0; size_t j;
        if (ere && (p[q] == '*' || p[q] == '+' || p[q] == '?')) return q + 1;
        if (ere && p[q] == '{') { j = bg_interval (p, e, q + 1, 1, &opt); return j ? j : q + 1; }
        if (!ere && p[q] == '*') return q + 1;
        if (!ere && q + 1 < e && p[q] == '\\' && (p[q + 1] == '+' || p[q + 1] == '?')) return q + 2;
        if (!ere && q + 1 < e && p[q] == '\\' && p[q + 1] == '{')
        { j = bg_interval (p, e, q + 2, 0, &opt); return j ? j : q + 2; }
    }
    if (!bg_has_alt (p, ce, cs, ere)) bg_ana_seq (a, p, ce, cs);
    bg_ana_end (a);
    return after;
}

/* Analyze the sequence P[I..E), which has no top-level alternation. */
static void
bg_ana_seq (bg_ana *a, const char *p, size_t e, size_t i)
{
    int ere = a->ere;
    size_t start = i;
    while (i < e)
    {
        char c = p[i];
        if (c == '\\')
        {
            if (i + 1 >= e) { bg_ana_op (a); i++; continue; }   /* trailing \: regcomp will say */
            char d = p[i + 1];
            if (!ere && d == '(')
            {
                size_t j = bg_group_close (p, e, i, 0);
                i = bg_ana_group (a, p, e, i + 2, j, j < e ? j + 2 : e);
                continue;
            }
            if (!ere && (d == ')' || d == '|')) { bg_ana_op (a); i += 2; continue; }
            if (!ere && d == '{')
            {
                int opt = 0; size_t j = bg_interval (p, e, i + 2, 0, &opt);
                bg_ana_quant (a, j ? opt : 1); i = j ? j : i + 2; continue;
            }
            if (!ere && (d == '+' || d == '?')) { bg_ana_quant (a, d == '?'); i += 2; continue; }
            if (d >= '1' && d <= '9') { a->backref = 1; bg_ana_op (a); i += 2; continue; }
            if (strchr ("<>bBwWsS`'", d)) { bg_ana_op (a); i += 2; continue; }
            bg_ana_lit (a, d); i += 2;          /* an escaped operator, or a stray \: the byte itself */
            continue;
        }
        if (c == '[') { size_t j = bg_skip_bracket (p, e, i); bg_ana_op (a); i = j; continue; }
        if (c == '.') { bg_ana_op (a); i++; continue; }
        if (ere)
        {
            if (c == '(') { size_t j = bg_group_close (p, e, i, 1); i = bg_ana_group (a, p, e, i + 1, j, j < e ? j + 1 : e); continue; }
            if (c == ')' || c == '|' || c == '^' || c == '$') { bg_ana_op (a); i++; continue; }
            if (c == '*' || c == '?') { bg_ana_quant (a, 1); i++; continue; }
            if (c == '+') { bg_ana_quant (a, 0); i++; continue; }
            if (c == '{')
            {
                int opt = 0; size_t j = bg_interval (p, e, i + 1, 1, &opt);
                bg_ana_quant (a, j ? opt : 1); i = j ? j : i + 1; continue;
            }
            bg_ana_lit (a, c); i++;
            continue;
        }
        /* BRE: * is literal at the start of an expression (or after its ^),
           ^ is an anchor only at the start, $ only at the end */
        if (c == '*')
        {
            if (i == start || (i == start + 1 && p[start] == '^')) bg_ana_lit (a, c);
            else bg_ana_quant (a, 1);
            i++; continue;
        }
        if (c == '^') { if (i == start) bg_ana_op (a); else bg_ana_lit (a, c); i++; continue; }
        if (c == '$') { if (i + 1 == e) bg_ana_op (a); else bg_ana_lit (a, c); i++; continue; }
        bg_ana_lit (a, c); i++;
    }
}

/* Classify ARM: returns 1 for a pure literal with its bytes in *LIT, else
   0 with the must in *MUST (n == 0 when none is known). Both point into
   freshly allocated memory owned by the caller. A literal may be anchored:
   *BOL for a leading ^, *EOL for a trailing $. */
static int
bg_analyze (const bg_str *arm, int ere, bg_str *lit, bg_str *must, int *backref, int *bol, int *eol)
{
    bg_ana a = {0};
    a.ere = ere;
    a.run = malloc (arm->n + 1); a.best = malloc (arm->n + 1);
    lit->s = must->s = NULL; lit->n = must->n = 0; *backref = 0; *bol = *eol = 0;
    if (!a.run || !a.best) { free (a.run); free (a.best); return 0; }
    size_t i = 0, e = arm->n;
    if (bg_has_alt (arm->s, arm->n, 0, ere)) a.ops = 1;
    else
    {
        /* the anchors at the ends are taken off first: what is left may be
           a literal the fixed search can find wrapped in the delimiter */
        if (e > 0 && arm->s[0] == '^') { *bol = 1; i = 1; }
        if (e > i && arm->s[e - 1] == '$')
        {
            size_t bs = 0;
            while (e - 1 - bs > i && arm->s[e - 2 - bs] == '\\') bs++;
            if (bs % 2 == 0) { *eol = 1; e--; }
        }
        bg_ana_seq (&a, arm->s, e, i);
        if (a.ops) *bol = *eol = 0;
    }
    *backref = a.backref;
    if (!a.ops)
    {
        lit->s = a.run; lit->n = a.rn;
        free (a.best);
        return 1;
    }
    bg_ana_end (&a);
    must->s = a.best; must->n = a.bn;
    bg_set_rare (must);
    free (a.run);
    return 0;
}

/* GNU grep lets an ERE start with a repetition operator, with a warning,
   and reads it as repeating nothing: take it out. */
static void
bg_ere_strip_leading (bg_str *arm)
{
    size_t i = 0, e = arm->n; int at_start = 1;
    while (i < e)
    {
        char c = arm->s[i];
        if (at_start && (c == '*' || c == '+' || c == '?'))
        {
            fprintf (stderr, "grep: warning: %c at start of expression\n", c);
            memmove (arm->s + i, arm->s + i + 1, e - i);
            e--; arm->n = e;
            continue;
        }
        if (at_start && c == '{')
        {
            int opt; size_t j = bg_interval (arm->s, e, i + 1, 1, &opt);
            if (j)
            {
                fprintf (stderr, "grep: warning: {...} at start of expression\n");
                memmove (arm->s + i, arm->s + j, e - j + 1);
                e -= j - i; arm->n = e;
                continue;
            }
        }
        if (c == '\\' && i + 1 < e) { i += 2; at_start = 0; continue; }
        if (c == '[') { i = bg_skip_bracket (arm->s, e, i); at_start = 0; continue; }
        at_start = (c == '(' || c == '|' || (at_start && c == '^'));
        i++;
    }
}

/* Split ARM at its top-level alternations into PIECES (at most N): the
   count. "foo|bar" (-E) or "foo\|bar" are two literal needles, as in GNU. */
static int
bg_split_alt (const bg_str *arm, int ere, bg_str *pieces, int n)
{
    const char *p = arm->s; size_t e = arm->n, i = 0, s = 0;
    int k = 0, depth = 0;
    while (i <= e)
    {
        int cut = (i == e);
        if (!cut)
        {
            if (p[i] == '\\' && i + 1 < e)
            {
                if (!ere && p[i + 1] == '(') depth++;
                else if (!ere && p[i + 1] == ')') depth--;
                else if (!ere && p[i + 1] == '|' && depth == 0) cut = 2;
                if (!cut) { i += 2; continue; }
            }
            else if (p[i] == '[') { i = bg_skip_bracket (p, e, i); continue; }
            else if (ere && p[i] == '(') depth++;
            else if (ere && p[i] == ')') depth--;
            else if (ere && p[i] == '|' && depth == 0) cut = 1;
            if (!cut) { i++; continue; }
        }
        if (k == n) return -1;
        pieces[k].s = (char *) p + s; pieces[k].n = i - s; k++;
        i += cut == 2 ? 2 : 1;
        s = i;
    }
    return k;
}

/* Could a match of ARM hold the record delimiter? If not, a block can be
   searched with one regexec: under REG_NEWLINE . and [^...] exclude the
   newline, so what is left is a literal newline, \s, \W, and a bracket
   expression with a class, a collating element, or a range that may reach
   the newline. With -z (NUL records) [^...] matches NUL, so: yes. */
static int
bg_can_match_delim (const bg_str *arm, int delim)
{
    const char *p = arm->s; size_t n = arm->n;
    if (delim == '\0') return 1;
    for (size_t i = 0; i < n; )
    {
        char c = p[i];
        if (c == '\n') return 1;
        if (c == '\\')
        {
            if (i + 1 >= n) return 1;
            char d = p[i + 1];
            if (d == 's' || d == 'W' || d == '\n') return 1;
            i += 2; continue;
        }
        if (c == '[')
        {
            size_t j = i + 1, end = bg_skip_bracket (p, n, i);
            if (j < n && p[j] == '^') { i = end; continue; }
            for (size_t k = j; k + 1 < end; k++)
            {
                unsigned char b = (unsigned char) p[k];
                if (b == '\n') return 1;
                if (b == '[' && (p[k + 1] == ':' || p[k + 1] == '.' || p[k + 1] == '=')) return 1;
                if (b == '-' && k > j && k + 2 < end)
                {
                    unsigned char lo = (unsigned char) p[k - 1], hi = (unsigned char) p[k + 1];
                    if (lo < 0x20 || hi < 0x20 || lo == '[' || hi == '[') return 1;
                }
            }
            i = end; continue;
        }
        i++;
    }
    return 0;
}

/* A fixed string as a BRE: for the fixed-string arms that must run through
   the regex engine (a case-folded search the byte table cannot do). */
static char *
bg_fixed_to_bre (const bg_str *s)
{
    char *out = malloc (s->n * 2 + 1);
    if (!out) return NULL;
    size_t k = 0;
    for (size_t i = 0; i < s->n; i++)
    {
        if (strchr ("\\.[*^$", s->s[i])) out[k++] = '\\';
        out[k++] = s->s[i];
    }
    out[k] = '\0';
    return out;
}

/* Escape every literal { and } in PATTERN (keeping \X escapes): the retry
   when regcomp rejects a stray brace that GNU and BSD grep treat as
   literal, e.g. the "^{" a script uses to count JSON records. */
static char *
bg_escape_braces (const char *pattern)
{
    size_t plen = strlen (pattern);
    char *out = malloc (plen * 2 + 1);
    if (!out) return NULL;
    size_t op = 0;
    for (size_t i = 0; i < plen; i++)
    {
        if (pattern[i] == '\\' && i + 1 < plen)
        {
            out[op++] = pattern[i];
            out[op++] = pattern[i + 1];
            i++;
            continue;
        }
        if (pattern[i] == '{' || pattern[i] == '}')
            out[op++] = '\\';
        out[op++] = pattern[i];
    }
    out[op] = '\0';
    return out;
}

/* ------------------------------------------------ matching within a line --- */

/* regexec over LINE[START..END) with the rest of the line as context. DELIM
   tells the fallback path whether START is a line start (the block search
   starts at one; -o and -w resume mid-line), so ^ can match there. */
static int
bg_re_exec (const regex_t *re, char *line, size_t llen, size_t start, size_t end,
            int eflags, regmatch_t *m, int delim)
{
    int rc;
#if BG_STARTEND
    (void) llen; (void) delim;
    m->rm_so = (regoff_t) start; m->rm_eo = (regoff_t) end;
    rc = regexec (re, line, 1, m, eflags | REG_STARTEND);
#else
    (void) llen;
    char saved = line[end];
    line[end] = '\0';
    if (start > 0 && line[start - 1] != delim) eflags |= REG_NOTBOL;
    rc = regexec (re, line + start, 1, m, eflags);
    line[end] = saved;
    if (rc == 0) { m->rm_so += (regoff_t) start; m->rm_eo += (regoff_t) start; }
#endif
    return rc == 0;
}

/* The leftmost, then longest, match over the compiled regexes. */
static int
bg_re_search (const bg_opts *o, char *line, size_t llen, size_t start, size_t end,
              int eflags, regmatch_t *m)
{
    if (o->n_re == 1)
        return bg_re_exec (&o->re[0], line, llen, start, end, eflags, m, o->delim);
    int found = 0;
    regmatch_t best = {0};
    for (int i = 0; i < o->n_re; i++)
    {
        regmatch_t t;
        if (!bg_re_exec (&o->re[i], line, llen, start, end, eflags, &t, o->delim)) continue;
        if (!found || t.rm_so < best.rm_so || (t.rm_so == best.rm_so && t.rm_eo > best.rm_eo)) best = t;
        found = 1;
    }
    if (found) *m = best;
    return found;
}

/* The fixed-string search within LINE[LLEN] from START, with -x and -w:
   1 with *M, or 0. -w as GNU: a hit whose left side is a word boundary but
   whose right side is not is retried with the shorter needles at the same
   place, then the search moves on by one byte. */
static int
bg_fixed_line (const bg_opts *o, const char *line, size_t llen, size_t start, regmatch_t *m)
{
    bg_kw kw = { NULL, 0, o->kw_line };
    size_t from = start;
    for (;;)
    {
        size_t at, len;
        if (!bg_kw_find (o, &kw, o->needles, o->n_needles, line, llen, from, &at, &len)) return 0;
        if (o->wrap_l && at != 0) return 0;
        if (o->wrap_r && at + len != llen) { if (at >= llen) return 0; from = at + 1; continue; }
        if (!o->wflag) { m->rm_so = (regoff_t) at; m->rm_eo = (regoff_t) (at + len); return 1; }
        if (!bg_wordchar_before (o, line, at))
        {
            if (!bg_wordchar_at (o, line, llen, at + len))
            { m->rm_so = (regoff_t) at; m->rm_eo = (regoff_t) (at + len); return 1; }
            for (int i = 0; i < o->n_needles; i++)
            {
                size_t k = o->needles[i].n;
                if (k >= len || k > llen - at || !bg_eq (o, line + at, o->needles[i].s, k)) continue;
                if (!bg_wordchar_at (o, line, llen, at + k))
                { m->rm_so = (regoff_t) at; m->rm_eo = (regoff_t) (at + k); return 1; }
            }
        }
        if (at >= llen) return 0;
        from = at + 1;
    }
}

/* A match in LINE[LLEN] starting at or after START under the mode and -x/-w:
   1 with *M, 0 for none, -1 on an error. */
static int
bg_match_line (const bg_opts *o, char *line, size_t llen, size_t start, regmatch_t *m)
{
    if (o->mode == BG_FIXED)
        return bg_fixed_line (o, line, llen, start, m);
    if (o->mode == BG_PCRE)
    {
        int prc = bg_pcre_exec (o, line, llen, start, start ? PCRE2_NOTBOL : 0, m);
        if (prc <= 0) return prc;
        if (o->xflag && (m->rm_so != 0 || (size_t) m->rm_eo != llen)) return 0;
        return 1;
    }
    if (!bg_re_search (o, line, llen, start, llen, 0, m)) return 0;
    if (o->xflag) return m->rm_so == 0 && (size_t) m->rm_eo == llen;
    if (!o->wflag) return 1;
    /* -w, as GNU grep: a match that is not word-bounded is retried shorter,
       anchored at the same place (with $ not matching the cut), then the
       search resumes one byte further on. */
    for (;;)
    {
        size_t s = (size_t) m->rm_so, e = (size_t) m->rm_eo;
        int left_ok = !bg_wordchar_before (o, line, s);
        if (left_ok && !bg_wordchar_at (o, line, llen, e)) return 1;
        if (left_ok && e > s)
        {
            regmatch_t t;
            if (bg_re_search (o, line, llen, s, e - 1, REG_NOTEOL, &t)
                && (size_t) t.rm_so == s && t.rm_eo > t.rm_so)
            { *m = t; continue; }
        }
        if (s >= llen) return 0;
        /* a match starting inside a run of word characters has one on its
           left and cannot pass: resume after the run (GNU resumes one
           byte on, and finds the same) */
        size_t n = s + 1;
        while (n < llen && bg_wordchar_before (o, line, n)) n++;
        if (o->mb) while (n < llen && ((unsigned char) line[n] & 0xC0) == 0x80) n++;
        if (!bg_re_search (o, line, llen, n, llen, 0, m)) return 0;
    }
}

/* ------------------------------------------------------- the block reader --- */

typedef struct {
    int fd;
    char *base;                 /* base[0] is a delimiter: the sentinel before line 0 */
    char *buf;                  /* base + 1 */
    size_t cap, len;
    off_t off;                  /* file offset of buf[0] */
    int eof;
} bg_in;

typedef struct {
    bg_opts *o;
    const char *name;           /* for prefixes and messages */
    int prefix;                 /* print the file name before lines */
    bg_in in;
    size_t pos, lim;            /* the window [pos, lim) of complete lines */
    bg_kw kw;                   /* the block needle cache */
    size_t nl_idx; long nl_count; int need_nl;   /* lazy line numbers */
    off_t last_out;             /* file offset after the last printed line */
    int pending;                /* -A lines still to print */
    off_t after_last;           /* file offset after the last selected line */
    long count, count_at_null;
    long outleft;               /* selected lines still allowed (-m); -1 unlimited */
    int quiet, done_on_match, done, binary, enc_err, printmode, err;
} bg_state;

static int
bg_in_grow (bg_in *in)
{
    size_t ncap = in->cap * 2;
    char *nb = realloc (in->base, ncap + 2);
    if (!nb) return -1;
    in->base = nb; in->buf = nb + 1; in->cap = ncap;
    return 0;
}

/* Refill the window: keep the lines -B may still print, move the unconsumed
   part to the front, read until a complete line is present. 1: a window
   [pos, lim) is ready; 0: end of input; -1: read error; -2: skip the file
   (binary, -I). */
static int
bg_fill (bg_state *st)
{
    bg_opts *o = st->o; bg_in *in = &st->in; int d = o->delim;
    size_t keep = st->pos;
    if (o->B > 0 && !st->quiet)
    {
        size_t bp = 0;
        if (st->last_out > in->off) bp = (size_t) (st->last_out - in->off);
        if (bp > keep) bp = keep;
        for (int i = 0; i < o->B && keep > bp; i++)
        {
            char *q = keep - 1 > bp ? memrchr (in->buf + bp, d, keep - 1 - bp) : NULL;
            keep = q ? (size_t) (q - in->buf) + 1 : bp;
        }
    }
    if (st->need_nl)
    {
        if (st->nl_idx < keep)
        {
            st->nl_count += bg_memcount (in->buf + st->nl_idx, keep - st->nl_idx, d);
            st->nl_idx = keep;
        }
        st->nl_idx -= keep;
    }
    if (keep > 0)
    {
        memmove (in->buf, in->buf + keep, in->len - keep);
        in->len -= keep; in->off += (off_t) keep; st->pos -= keep;
    }
    st->kw.hay = NULL;
    for (;;)
    {
        if (in->eof)
        {
            if (in->len > st->pos)          /* a last line without its delimiter */
            {
                in->buf[in->len++] = (char) d;
                st->lim = in->len;
                return 1;
            }
            st->lim = st->pos;
            return 0;
        }
        if (in->cap - in->len < in->cap / 4 + 2 && bg_in_grow (in) < 0)
        {
            errno = ENOMEM;
            return -1;
        }
        ssize_t n = read (in->fd, in->buf + in->len, in->cap - in->len - 1);
        if (n < 0)
        {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) { in->eof = 1; continue; }
        char *nd = in->buf + in->len;
        /* A NUL makes the file binary from here on, as GNU: NULs then
           separate lines, output goes quiet unless -c, and the file is
           skipped with -I. */
        if (d == '\n' && !o->aflag)
        {
            if (!st->binary && memchr (nd, '\0', (size_t) n))
            {
                st->binary = 1;
                if (o->Iflag) return -2;
                if (!o->cflag) { st->quiet = 1; st->done_on_match = 1; st->pending = 0; }
                st->count_at_null = st->count;
            }
            if (st->binary)
                for (char *z = nd; (z = memchr (z, '\0', (size_t) (nd + n - z))); ) *z++ = '\n';
        }
        in->len += (size_t) n;
        char *last = memrchr (nd, d, (size_t) n);
        if (last) { st->lim = (size_t) (last - in->buf) + 1; return 1; }
    }
}

/* The next line at or after FROM in the window that matches the pattern:
   1 with its bounds [*LS, *LE) (LE is its delimiter) and the match *M,
   0 for none, -1 on an error. */
static int
bg_find (bg_state *st, size_t from, size_t *ls, size_t *le, regmatch_t *m)
{
    bg_opts *o = st->o; char *buf = st->in.buf; size_t lim = st->lim; int d = o->delim;
    if (from >= lim) return 0;
    if (o->mode == BG_FIXED && (o->wrap_l || o->wrap_r) && !o->wflag)
    {
        /* every line follows a delimiter (buf[-1] is one), so a literal that
           must start or end its line is searched wrapped in the delimiter,
           from the one before FROM; the hit is the literal's position */
        size_t at, len, nlen;
        if (!bg_kw_find (o, &st->kw, o->xneedles, o->n_needles, buf - o->wrap_l, lim + o->wrap_l, from, &at, &len)) return 0;
        nlen = len - o->wrap_l - o->wrap_r;
        size_t s, eidx;
        if (o->wrap_l) s = at;
        else { char *b = at > from ? memrchr (buf + from, d, at - from) : NULL; s = b ? (size_t) (b - buf) + 1 : from; }
        if (o->wrap_r) eidx = at + nlen;
        else eidx = (size_t) ((char *) memchr (buf + at + nlen, d, lim - at - nlen) - buf);
        *ls = s; *le = eidx;
        m->rm_so = (regoff_t) (at - s); m->rm_eo = (regoff_t) (at - s + nlen);
        return 1;
    }
    for (;;)
    {
        size_t s, eidx, at, len;
        if (o->mode == BG_FIXED)
        {
            if (!bg_kw_find (o, &st->kw, o->needles, o->n_needles, buf, lim, from, &at, &len)) return 0;
        }
        else if (o->must.n)
        {
            at = bg_memfind (o, buf, lim, from, &o->must);
            if (at == BG_NOHIT) return 0;
            len = 0;
        }
        else if (o->nl_safe)
        {
            /* one regexec over the rest of the block: the leftmost match is
               in the first line that matches, and is that line's own
               leftmost-longest match, since no match spans a delimiter */
            regmatch_t bm;
            if (!bg_re_search (o, buf, lim, from, lim, 0, &bm)) return 0;
            at = (size_t) bm.rm_so; len = (size_t) (bm.rm_eo - bm.rm_so);
            if (at >= lim) return 0;                /* an empty match after the last line */
            char *b = at > from ? memrchr (buf + from, d, at - from) : NULL;
            s = b ? (size_t) (b - buf) + 1 : from;
            eidx = (size_t) ((char *) memchr (buf + at, d, lim - at) - buf);
            if (!o->wflag && !o->xflag)
            {
                *ls = s; *le = eidx;
                m->rm_so = (regoff_t) (at - s); m->rm_eo = (regoff_t) (at - s + len);
                return 1;
            }
            int r = bg_match_line (o, buf + s, eidx - s, 0, m);
            if (r < 0) return -1;
            if (r) { *ls = s; *le = eidx; return 1; }
            from = eidx + 1;
            if (from >= lim) return 0;
            continue;
        }
        else
            at = from, len = 0;
        {
            char *b = at > from ? memrchr (buf + from, d, at - from) : NULL;
            s = b ? (size_t) (b - buf) + 1 : from;
            char *e = memchr (buf + at, d, lim - at);
            eidx = (size_t) (e - buf);
        }
        if (o->mode == BG_FIXED && !o->wflag)
        {
            *ls = s; *le = eidx;
            m->rm_so = (regoff_t) (at - s); m->rm_eo = (regoff_t) (at - s + len);
            return 1;
        }
        int r;
        if (o->mode == BG_FIXED)
            r = bg_fixed_line (o, buf + s, eidx - s, at - s, m);
        else if (o->re_ns && !o->oflag && !o->wflag && !o->xflag)
        {
            r = bg_re_exec (o->re_ns, buf + s, eidx - s, 0, eidx - s, 0, m, d);   /* yes or no is all that is needed */
            m->rm_so = m->rm_eo = 0;
        }
        else
            r = bg_match_line (o, buf + s, eidx - s, 0, m);
        if (r < 0) return -1;
        if (r) { *ls = s; *le = eidx; return 1; }
        from = eidx + 1;
        if (from >= lim) return 0;
    }
}

/* ---------------------------------------------------------------- output --- */

static long
bg_lineno (bg_state *st, size_t idx)
{
    st->nl_count += bg_memcount (st->in.buf + st->nl_idx, idx - st->nl_idx, st->o->delim);
    st->nl_idx = idx;
    return st->nl_count + 1;
}

/* Output goes through a buffer of our own: bash line-buffers stdout, which
   would be a write(2) per printed line. */
static void
bg_out_flush (bg_opts *o)
{
    if (o->on) { fwrite (o->ob, 1, o->on, stdout); o->on = 0; }
}

static void
bg_out (bg_opts *o, const char *p, size_t n)
{
    if (n > BG_OUTBUF - o->on)
    {
        bg_out_flush (o);
        if (n > BG_OUTBUF) { fwrite (p, 1, n, stdout); return; }
    }
    memcpy (o->ob + o->on, p, n);
    o->on += n;
}

static void
bg_outc (bg_opts *o, int c)
{
    if (o->on == BG_OUTBUF) bg_out_flush (o);
    o->ob[o->on++] = (char) c;
}

static void
bg_out_num (bg_opts *o, long long v)
{
    char d[24]; int k = sizeof d;
    do { d[--k] = (char) ('0' + v % 10); v /= 10; } while (v);
    bg_out (o, d + k, sizeof d - (size_t) k);
}

static void
bg_prefix (bg_state *st, size_t ls, off_t boff, int sep)
{
    bg_opts *o = st->o;
    if (st->prefix) { bg_out (o, st->name, strlen (st->name)); bg_outc (o, o->Zflag ? '\0' : sep); }
    if (o->nflag) { bg_out_num (o, bg_lineno (st, ls)); bg_outc (o, sep); }
    if (o->bflag) { bg_out_num (o, (long long) boff); bg_outc (o, sep); }
}

/* Output switches off: a printed line was not valid in the locale (GNU
   then reports the file as binary and stops at this match). */
static void
bg_go_quiet (bg_state *st)
{
    st->enc_err = 1; st->quiet = 1; st->done_on_match = 1; st->pending = 0;
}

/* Print the line [LS, LE) with SEP (':' selected, '-' context). MATCHING
   says whether it matches the pattern: with -o only its matches print. */
static void
bg_emit (bg_state *st, size_t ls, size_t le, int sep, int matching)
{
    bg_opts *o = st->o;
    char *line = st->in.buf + ls; size_t llen = le - ls;
    off_t base = st->in.off + (off_t) ls;
    if (st->quiet) return;
    if (o->oflag)
    {
        if (matching)
        {
            size_t pos = 0; regmatch_t m;
            while (pos < llen)
            {
                int r = bg_match_line (o, line, llen, pos, &m);
                if (r < 0) { st->err = 1; break; }
                if (!r) break;
                if (m.rm_eo == m.rm_so) { pos = (size_t) m.rm_so + 1; continue; }
                if (!o->aflag && bg_encoding_error (o, line + m.rm_so, (size_t) (m.rm_eo - m.rm_so)))
                { bg_go_quiet (st); return; }
                bg_prefix (st, ls, base + m.rm_so, sep);
                bg_out (o, line + m.rm_so, (size_t) (m.rm_eo - m.rm_so));
                bg_outc (o, o->delim);
                pos = (size_t) m.rm_eo;
            }
        }
    }
    else
    {
        if (!o->aflag && bg_encoding_error (o, line, llen)) { bg_go_quiet (st); return; }
        bg_prefix (st, ls, base, sep);
        bg_out (o, line, llen);
        bg_outc (o, o->delim);
    }
    st->last_out = base + (off_t) llen + 1;
}

/* A selected line: count it, print it with its leading context, arm the
   trailing context. */
static void
bg_select (bg_state *st, size_t ls, size_t le)
{
    bg_opts *o = st->o;
    st->count++;
    if (st->outleft > 0) st->outleft--;
    if (!st->quiet)
    {
        char *buf = st->in.buf; int d = o->delim;
        size_t p = ls, bp = 0;
        if (st->last_out > st->in.off) bp = (size_t) (st->last_out - st->in.off);
        for (int i = 0; i < o->B && p > bp; i++)
        {
            char *q = p - 1 > bp ? memrchr (buf + bp, d, p - 1 - bp) : NULL;
            p = q ? (size_t) (q - buf) + 1 : bp;
        }
        if (o->ctx && o->used && st->in.off + (off_t) p != st->last_out)
            bg_out (o, "--\n", 3);
        while (p < ls && !st->quiet)
        {
            char *e = memchr (buf + p, d, ls - p);
            size_t pe = (size_t) (e - buf);
            bg_emit (st, p, pe, '-', o->vflag);
            p = pe + 1;
        }
        if (!st->quiet) bg_emit (st, ls, le, ':', !o->vflag);
        o->used = 1;
    }
    st->after_last = st->in.off + (off_t) le + 1;
    st->pending = st->quiet ? 0 : o->A;
    if (st->done_on_match && st->count > st->count_at_null) st->done = 1;
}

/* The lines [pos, END) do not match the pattern: under -v each one is
   selected; otherwise they only feed the trailing context. */
static void
bg_range_nomatch (bg_state *st, size_t end)
{
    bg_opts *o = st->o; char *buf = st->in.buf; int d = o->delim;
    if (o->vflag)
    {
        if (st->quiet && !st->done_on_match && st->outleft < 0)
        {
            st->count += bg_memcount (buf + st->pos, end - st->pos, d);   /* -v -c */
            st->pos = end;
            return;
        }
        while (st->pos < end && !st->done && st->outleft != 0)
        {
            char *e = memchr (buf + st->pos, d, end - st->pos);
            size_t le = (size_t) (e - buf);
            bg_select (st, st->pos, le);
            st->pos = le + 1;
        }
        return;
    }
    while (st->pending > 0 && st->pos < end)
    {
        char *e = memchr (buf + st->pos, d, end - st->pos);
        size_t le = (size_t) (e - buf);
        bg_emit (st, st->pos, le, '-', 0);
        st->pending--;
        st->pos = le + 1;
    }
    st->pos = end;
}

/* ------------------------------------------------------------- one file --- */

static void
bg_file_error (const bg_opts *o, const char *name, int err)
{
    if (!o->sflag) builtin_error ("%s: %s", name, strerror (err));
}

/* grep one file (PATH, or stdin when NULL or "-"). Returns the number of
   selected lines, or -1 on an error. */
static long
bg_grep_file (bg_opts *o, const char *path, int n_files, int from_recursion)
{
    bg_state st;
    memset (&st, 0, sizeof st);
    st.o = o;
    int is_stdin = path == NULL || (path[0] == '-' && path[1] == '\0');
    st.name = is_stdin ? "(standard input)" : path;
    st.prefix = o->Hflag || (!o->hflag && (n_files > 1 || from_recursion));
    int fd = is_stdin ? 0 : open (path, O_RDONLY);
    if (fd < 0) { bg_file_error (o, path, errno); return -1; }
    struct stat sb;
    if (fstat (fd, &sb) == 0 && S_ISDIR (sb.st_mode))
    {
        bg_file_error (o, path, EISDIR);
        if (!is_stdin) close (fd);
        return -1;
    }
    st.in.fd = fd; st.in.cap = BG_BLOCK;
    st.in.base = malloc (st.in.cap + 2);
    if (!st.in.base) { if (!is_stdin) close (fd); builtin_error ("out of memory"); return -1; }
    st.in.buf = st.in.base + 1;
    st.in.base[0] = (char) o->delim;
    st.kw.next = o->kw_blk;
    st.need_nl = o->nflag;
    st.last_out = -1;
    st.outleft = o->mflag_set ? o->mflag : -1;
    st.done_on_match = o->lflag || o->Lflag || o->qflag;
    st.quiet = o->cflag || st.done_on_match;
    st.printmode = !st.quiet;

    for (;;)
    {
        if (ferror (stdout)) break;
        if (st.pos >= st.lim)
        {
            if (st.done || (st.outleft == 0 && st.pending == 0)) break;
            int r = bg_fill (&st);
            if (r < 0)
            {
                if (r == -1) { bg_file_error (o, st.name, errno); st.err = 1; }
                break;
            }
            if (r == 0) break;
        }
        if (st.outleft == 0)
        {
            /* -m reached: only the trailing context is left to print */
            while (st.pending > 0 && st.pos < st.lim)
            {
                char *e = memchr (st.in.buf + st.pos, o->delim, st.lim - st.pos);
                size_t le = (size_t) (e - st.in.buf);
                bg_emit (&st, st.pos, le, '-', o->vflag);
                st.pending--;
                st.pos = le + 1;
            }
            if (st.pending == 0) { st.done = 1; break; }
            continue;
        }
        size_t ls = 0, le = 0; regmatch_t m;
        int r = bg_find (&st, st.pos, &ls, &le, &m);
        if (r < 0) { st.err = 1; break; }
        bg_range_nomatch (&st, r ? ls : st.lim);
        if (st.done || st.err) break;
        if (!r || st.outleft == 0) continue;
        if (o->vflag)
        {
            if (st.pending > 0) { bg_emit (&st, ls, le, '-', 1); st.pending--; }
        }
        else
            bg_select (&st, ls, le);
        st.pos = le + 1;
        if (st.done || st.err) break;
    }

    if (is_stdin)
    {
        /* as GNU: stdin is left just after the last match for -m, and at its
           end when grep stopped early, so the caller reads on from there */
        if (st.outleft == 0) lseek (0, st.after_last, SEEK_SET);
        else if (!st.in.eof) lseek (0, 0, SEEK_END);
    }
    else
        close (fd);
    free (st.in.base);

    if (o->cflag && !st.err)
    {
        if (st.prefix) { bg_out (o, st.name, strlen (st.name)); bg_outc (o, o->Zflag ? '\0' : ':'); }
        bg_out_num (o, st.count); bg_outc (o, '\n');
    }
    else if (!st.err && ((o->lflag && st.count > 0) || (o->Lflag && st.count == 0)))
    {
        bg_out (o, st.name, strlen (st.name));
        bg_outc (o, o->Zflag ? '\0' : '\n');
    }
    bg_out_flush (o);
    if (st.printmode && (st.enc_err || (st.binary && st.count_at_null < st.count)))
    {
        fflush (stdout);
        fprintf (stderr, "grep: %s: binary file matches\n", st.name);
    }
    if (st.err) return -1;
    return st.count;
}

/* ------------------------------------------------------------- recursion --- */

static int
bg_glob_any (char **globs, int n, const char *name)
{
    for (int i = 0; i < n; i++)
        if (fnmatch (globs[i], name, 0) == 0) return 1;
    return 0;
}

/* Walk PATH for -r/-R. Symlinks are followed on the command line and with
   -R; -r skips those met inside a directory, as GNU. */
static long
bg_grep_recursive (bg_opts *o, const char *path, int from_recursion)
{
    struct stat st;
    int rc = (from_recursion && !o->Rflag) ? lstat (path, &st) : stat (path, &st);
    if (rc != 0)
    {
        bg_file_error (o, path, errno);
        return -1;
    }
    if (S_ISREG (st.st_mode))
    {
        const char *bn = strrchr (path, '/');
        bn = bn ? bn + 1 : path;
        if (o->n_incl > 0 && !bg_glob_any (o->incl_globs, o->n_incl, bn)) return 0;
        if (o->n_excl > 0 && bg_glob_any (o->excl_globs, o->n_excl, bn)) return 0;
        return bg_grep_file (o, path, 1, from_recursion);
    }
    if (!S_ISDIR (st.st_mode)) return 0;
    if (o->n_excl_dir > 0)
    {
        const char *bn = strrchr (path, '/');
        bn = bn ? bn + 1 : path;
        if (bg_glob_any (o->excl_dir_globs, o->n_excl_dir, bn)) return 0;
    }
    DIR *d = opendir (path);
    if (!d)
    {
        bg_file_error (o, path, errno);
        return -1;
    }
    long total = 0; int err = 0;
    struct dirent *de;
    while ((de = readdir (d)) != NULL)
    {
        if (!strcmp (de->d_name, ".") || !strcmp (de->d_name, "..")) continue;
        size_t pl = strlen (path), nl = strlen (de->d_name);
        int slash = (pl > 0 && path[pl - 1] != '/') ? 1 : 0;
        int bare = !from_recursion && o->implicit_dot;      /* grep -r PAT: names relative to ., no ./ */
        char *child = malloc (pl + slash + nl + 1);
        if (!child) continue;
        if (bare) memcpy (child, de->d_name, nl + 1);
        else
        {
            memcpy (child, path, pl);
            if (slash) child[pl] = '/';
            memcpy (child + pl + slash, de->d_name, nl + 1);
        }
        long r = bg_grep_recursive (o, child, 1);
        free (child);
        if (r < 0) err = 1; else total += r;
        if (o->qflag && total > 0) break;
    }
    closedir (d);
    if (err && !(o->qflag && total > 0)) return -1;
    return total;
}

/* ------------------------------------------------------------- set-up --- */

static int
bg_add_arm (bg_opts *o, const char *s, size_t n)
{
    if (o->n_arms == o->cap_arms)
    {
        int nc = o->cap_arms ? o->cap_arms * 2 : 8;
        bg_str *na = realloc (o->arms, (size_t) nc * sizeof *na);
        if (!na) return -1;
        o->arms = na; o->cap_arms = nc;
    }
    char *c = malloc (n + 1);
    if (!c) return -1;
    memcpy (c, s, n); c[n] = '\0';
    o->arms[o->n_arms].s = c; o->arms[o->n_arms].n = n; o->n_arms++;
    return 0;
}

/* Add PATTERN, one arm per line: a newline separates patterns, as in GNU. */
static int
bg_add_patterns (bg_opts *o, const char *s, size_t n)
{
    size_t i = 0;
    for (;;)
    {
        const char *nl = memchr (s + i, '\n', n - i);
        size_t e = nl ? (size_t) (nl - s) : n;
        if (bg_add_arm (o, s + i, e - i) < 0) return -1;
        if (!nl) return 0;
        i = e + 1;                  /* what follows a newline is another pattern, even nothing */
    }
}

static int
bg_add_pattern_file (bg_opts *o, const char *path)
{
    FILE *pf = (path[0] == '-' && path[1] == '\0') ? stdin : fopen (path, "r");
    if (!pf) return -1;
    char *line = NULL; size_t cap = 0; ssize_t rd;
    int rc = 0;
    while ((rd = getline (&line, &cap, pf)) != -1)
    {
        if (rd > 0 && line[rd - 1] == '\n') rd--;
        if (bg_add_arm (o, line, (size_t) rd) < 0) { rc = -1; break; }
    }
    free (line);
    if (pf != stdin) fclose (pf);
    return rc;
}

/* Can the fixed search fold case for these bytes with the byte table? In
   a unibyte locale always; in a multibyte one only ASCII without i, k and
   s, the letters that non-ASCII characters (İ ı ſ K) fold to. */
static int
bg_fold_safe (const bg_opts *o, const char *s, size_t n)
{
    if (!o->iflag) return 1;
    if (!o->mb) return 1;
    for (size_t i = 0; i < n; i++)
    {
        unsigned char c = (unsigned char) s[i];
        if (c >= 0x80 || strchr ("iIkKsS", c)) return 0;
    }
    return 1;
}

/* The longest span of MUST the folded search can use (the whole of it when
   not folding). */
static void
bg_fold_span (const bg_opts *o, bg_str *must)
{
    if (!o->iflag || !o->mb) return;
    size_t bs = 0, bn = 0, i = 0;
    while (i < must->n)
    {
        size_t j = i;
        while (j < must->n && bg_fold_safe (o, must->s + j, 1)) j++;
        if (j - i > bn) { bs = i; bn = j - i; }
        i = j + 1;
    }
    memmove (must->s, must->s + bs, bn);
    must->n = bn;
}

static int
bg_cmp_len_desc (const void *a, const void *b)
{
    size_t x = ((const bg_str *) a)->n, y = ((const bg_str *) b)->n;
    return x > y ? -1 : x < y ? 1 : 0;
}

static int
bg_compile_one (bg_opts *o, regex_t *re, const char *pat, int flags)
{
    int rrc = regcomp (re, pat, flags);
    if (rrc && (flags & REG_EXTENDED)
        && (rrc == REG_BADBR || rrc == REG_BADRPT
#ifdef REG_EBRACE
            || rrc == REG_EBRACE
#endif
            ))
    {
        /* a stray brace GNU treats as literal: retry with braces escaped */
        char *retry = bg_escape_braces (pat);
        if (retry)
        {
            regex_t re2;
            if (regcomp (&re2, retry, flags) == 0) { *re = re2; rrc = 0; }
            free (retry);
        }
    }
    if (rrc != 0)
    {
        char ebuf[256];
        regerror (rrc, re, ebuf, sizeof ebuf);
        builtin_error ("%s", ebuf);
        return -1;
    }
    return 0;
}

/* Compile PAT (with the brace retry) quietly: an auxiliary regex the
   search can do without. */
static regex_t *
bg_compile_aux (const char *pat, int flags)
{
    regex_t *re = calloc (1, sizeof *re);
    if (!re) return NULL;
    int rrc = regcomp (re, pat, flags);
    if (rrc && (flags & REG_EXTENDED))
    {
        char *retry = bg_escape_braces (pat);
        if (retry) { rrc = regcomp (re, retry, flags); free (retry); }
    }
    if (rrc) { free (re); return NULL; }
    return re;
}

/* Build the matcher from the arms: 0, or -1 with the error reported. */
static int
bg_setup (bg_opts *o)
{
    int ere = o->Eflag;
    o->mb = MB_CUR_MAX > 1;
    o->ob = malloc (BG_OUTBUF);
    if (!o->ob) return -1;
    for (int c = 0; c < 256; c++) o->lower[c] = (unsigned char) tolower (c);
    for (int c = 0; c < 256; c++) o->alt[c] = (unsigned char) c;
    for (int c = 0; c < 256; c++)
        if (o->lower[c] != c) { o->alt[o->lower[c]] = (unsigned char) c; o->alt[c] = o->lower[c]; }

    if (o->Pflag)
    {
        size_t total = 3;
        for (int i = 0; i < o->n_arms; i++) total += o->arms[i].n + 6;
        char *s = malloc (total);
        if (!s) return -1;
        size_t k = 0;
        if (o->xflag) { s[k++] = '^'; s[k++] = '('; }
        for (int i = 0; i < o->n_arms; i++)
        {
            if (i) s[k++] = '|';
            memcpy (s + k, "(?:", 3); k += 3;
            memcpy (s + k, o->arms[i].s, o->arms[i].n); k += o->arms[i].n;
            s[k++] = ')';
        }
        if (o->xflag) { s[k++] = ')'; s[k++] = '$'; }
        s[k] = '\0';
        o->combined = s;
        o->mode = BG_PCRE;
        o->pcre = bg_pcre_compile (s, o->iflag);
        if (!o->pcre) return -1;
        o->pcre_md = pcre2_match_data_create_from_pattern (o->pcre, NULL);
        if (!o->pcre_md) { builtin_error ("pcre2 match_data allocation failed"); return -1; }
        return 0;
    }

    /* Every arm a literal (as given with -F, or with no operator, or an
       alternation of literals): the fixed-string search. */
    bg_str *needles = malloc ((size_t) (o->n_arms + 1) * 8 * sizeof *needles);
    int n_needles = 0, cap_needles = (o->n_arms + 1) * 8, all_literal = 1, bol = 0, eol = 0;
    if (!needles) return -1;
    if (ere) for (int i = 0; i < o->n_arms; i++) bg_ere_strip_leading (&o->arms[i]);
    for (int i = 0; i < o->n_arms && all_literal; i++)
    {
        bg_str pieces[64]; int np;
        if (o->Fflag) { pieces[0] = o->arms[i]; np = 1; }
        else
        {
            np = bg_split_alt (&o->arms[i], ere, pieces, 64);
            if (np < 0) { all_literal = 0; break; }
        }
        for (int j = 0; j < np; j++)
        {
            bg_str lit, must; int br, b, e;
            if (o->Fflag) { lit.s = malloc (pieces[j].n + 1); if (!lit.s) { all_literal = 0; break; } memcpy (lit.s, pieces[j].s, pieces[j].n); lit.n = pieces[j].n; }
            else if (!bg_analyze (&pieces[j], ere, &lit, &must, &br, &b, &e)) { free (must.s); all_literal = 0; break; }
            else if ((b || e) && (np > 1 || o->n_arms > 1)) { free (lit.s); all_literal = 0; break; }   /* an anchored literal: only alone */
            else { bol = b; eol = e; }
            if (n_needles == cap_needles)
            {
                cap_needles *= 2;
                bg_str *nn = realloc (needles, (size_t) cap_needles * sizeof *nn);
                if (!nn) { free (lit.s); all_literal = 0; break; }
                needles = nn;
            }
            needles[n_needles++] = lit;
        }
    }
    if (all_literal)
        for (int i = 0; i < n_needles; i++)
            if (!bg_fold_safe (o, needles[i].s, needles[i].n)) { all_literal = 0; break; }
    if (all_literal)
    {
        o->mode = BG_FIXED;
        o->fold = o->iflag;
        qsort (needles, (size_t) n_needles, sizeof *needles, bg_cmp_len_desc);
        for (int i = 0; i < n_needles; i++) bg_set_rare (&needles[i]);
        o->needles = needles; o->n_needles = n_needles;
        o->wrap_l = o->xflag || bol; o->wrap_r = o->xflag || eol;
        if (o->wrap_l || o->wrap_r)
        {
            o->xneedles = malloc ((size_t) n_needles * sizeof *o->xneedles);
            if (!o->xneedles) return -1;
            for (int i = 0; i < n_needles; i++)
            {
                char *w = malloc (needles[i].n + 2);
                if (!w) return -1;
                size_t k = 0;
                if (o->wrap_l) w[k++] = (char) o->delim;
                memcpy (w + k, needles[i].s, needles[i].n); k += needles[i].n;
                if (o->wrap_r) w[k++] = (char) o->delim;
                o->xneedles[i].s = w; o->xneedles[i].n = k;
                bg_set_rare (&o->xneedles[i]);
            }
        }
        o->kw_blk = malloc ((size_t) n_needles * sizeof *o->kw_blk);
        o->kw_line = malloc ((size_t) n_needles * sizeof *o->kw_line);
        if (!o->kw_blk || !o->kw_line) return -1;
        return 0;
    }
    for (int i = 0; i < n_needles; i++) free (needles[i].s);
    free (needles);

    /* The regex engine. -F arms are escaped into BREs. */
    o->mode = BG_REGEX;
    int flags = (ere ? REG_EXTENDED : 0) | (o->iflag ? REG_ICASE : 0) | (o->zdflag ? 0 : REG_NEWLINE);
    bg_str *texts = malloc ((size_t) o->n_arms * sizeof *texts);
    if (!texts) return -1;
    int any_backref = 0, any_caret = 0;
    o->nl_safe = 1;
    for (int i = 0; i < o->n_arms; i++)
    {
        if (bg_can_match_delim (&o->arms[i], o->delim)) o->nl_safe = 0;
        if (o->Fflag)
        {
            texts[i].s = bg_fixed_to_bre (&o->arms[i]);
            if (!texts[i].s) { for (int j = 0; j < i; j++) free (texts[j].s); free (texts); return -1; }
            texts[i].n = strlen (texts[i].s);
        }
        else
        {
            texts[i].s = o->arms[i].s; texts[i].n = o->arms[i].n;
            if (!ere && texts[i].n > 0 && texts[i].s[0] == '^') any_caret = 1;
            bg_str lit, must; int br, b, e;
            if (bg_analyze (&o->arms[i], ere, &lit, &must, &br, &b, &e))
            {
                if (o->n_arms == 1) { o->must = lit; bg_set_rare (&o->must); } else free (lit.s);
            }
            else
            {
                if (o->n_arms == 1) o->must = must; else free (must.s);
            }
            if (br) any_backref = 1;
        }
    }
    if (o->n_arms == 1 && o->Fflag)
    {
        /* a fixed string through the regex engine: itself is its must */
        o->must.s = malloc (o->arms[0].n + 1);
        if (o->must.s) { memcpy (o->must.s, o->arms[0].s, o->arms[0].n); o->must.n = o->arms[0].n; }
    }
    if (o->must.n && o->iflag) bg_fold_span (o, &o->must);
    if (o->must.n) { o->fold = o->iflag; bg_set_rare (&o->must); }
    else { free (o->must.s); o->must.s = NULL; }

    int rc = 0;
    if (o->n_arms == 1 || (!any_backref && !(any_caret && !ere)))
    {
        /* one regex: the arm itself, or the arms as \(a\)\|\(b\); a BRE
           arm starting with ^ is kept apart, since not every engine
           anchors ^ after \( */
        char *s;
        if (o->n_arms == 1) s = strdup (texts[0].s);
        else
        {
            size_t total = 1;
            for (int i = 0; i < o->n_arms; i++) total += texts[i].n + 6;
            s = malloc (total);
            if (s)
            {
                size_t k = 0;
                for (int i = 0; i < o->n_arms; i++)
                {
                    if (i) { if (!ere) s[k++] = '\\'; s[k++] = '|'; }
                    if (!ere) s[k++] = '\\';
                    s[k++] = '(';
                    memcpy (s + k, texts[i].s, texts[i].n); k += texts[i].n;
                    if (!ere) s[k++] = '\\';
                    s[k++] = ')';
                }
                s[k] = '\0';
            }
        }
        if (!s) rc = -1;
        else
        {
            o->combined = s;
            o->re = calloc (1, sizeof *o->re);
            if (!o->re || bg_compile_one (o, &o->re[0], s, flags) < 0) rc = -1;
            else o->n_re = 1;
        }
        if (rc == 0) o->re_ns = bg_compile_aux (s, flags | REG_NOSUB);
    }
    else
    {
        o->re = calloc ((size_t) o->n_arms, sizeof *o->re);
        if (!o->re) rc = -1;
        for (int i = 0; i < o->n_arms && rc == 0; i++)
        {
            if (bg_compile_one (o, &o->re[i], texts[i].s, flags) < 0) rc = -1;
            else o->n_re++;
        }
    }
    if (o->Fflag) for (int i = 0; i < o->n_arms; i++) free (texts[i].s);
    free (texts);
    return rc;
}

static void
bg_free (bg_opts *o)
{
    for (int i = 0; i < o->n_arms; i++) free (o->arms[i].s);
    free (o->arms);
    for (int i = 0; i < o->n_needles; i++) { free (o->needles[i].s); if (o->xneedles) free (o->xneedles[i].s); }
    free (o->needles); free (o->xneedles);
    free (o->must.s);
    for (int i = 0; i < o->n_re; i++) regfree (&o->re[i]);
    free (o->re);
    if (o->re_ns) { regfree (o->re_ns); free (o->re_ns); }
    free (o->combined);
    if (o->pcre_md) pcre2_match_data_free (o->pcre_md);
    if (o->pcre) pcre2_code_free (o->pcre);
    free (o->kw_blk); free (o->kw_line);
    free (o->ob);
    for (int i = 0; i < o->n_incl; i++) free (o->incl_globs[i]);
    for (int i = 0; i < o->n_excl; i++) free (o->excl_globs[i]);
    for (int i = 0; i < o->n_excl_dir; i++) free (o->excl_dir_globs[i]);
    free (o->incl_globs); free (o->excl_globs); free (o->excl_dir_globs);
}

/* ------------------------------------------------------------- options --- */

static void
bg_print_help (void)
{
    puts ("grep [OPTION]... PATTERNS [FILE]...");
    puts ("  -E, --extended-regexp       PATTERNS are extended regular expressions");
    puts ("  -F, --fixed-strings         PATTERNS are strings");
    puts ("  -G, --basic-regexp          PATTERNS are basic regular expressions (default)");
    puts ("  -P, --perl-regexp           PATTERNS are Perl regular expressions (if built in)");
    puts ("  -e, --regexp=PATTERNS       use PATTERNS for matching (a newline separates them)");
    puts ("  -f, --file=FILE             take PATTERNS from FILE (- is stdin)");
    puts ("  -i, -y, --ignore-case       ignore case distinctions");
    puts ("  -w, --word-regexp           match only whole words");
    puts ("  -x, --line-regexp           match only whole lines");
    puts ("  -z, --null-data             a data line ends in NUL, not newline");
    puts ("  -s, --no-messages           suppress error messages");
    puts ("  -v, --invert-match          select non-matching lines");
    puts ("  -m, --max-count=NUM         stop after NUM selected lines");
    puts ("  -b, --byte-offset           print the byte offset with output lines");
    puts ("  -n, --line-number           print line number with output lines");
    puts ("  -H, --with-filename         print file name with output lines");
    puts ("  -h, --no-filename           suppress the file name prefix on output");
    puts ("  -o, --only-matching         show only nonempty parts of lines that match");
    puts ("  -q, --quiet, --silent       suppress all normal output");
    puts ("      --binary-files=TYPE     TYPE is 'binary', 'text', or 'without-match'");
    puts ("  -a, --text                  equivalent to --binary-files=text");
    puts ("  -I                          equivalent to --binary-files=without-match");
    puts ("  -r, --recursive             like --directories=recurse");
    puts ("  -R, --dereference-recursive likewise, but follow all symlinks");
    puts ("      --include=GLOB          search only files that match GLOB");
    puts ("      --exclude=GLOB          skip files that match GLOB");
    puts ("      --exclude-dir=GLOB      skip directories that match GLOB");
    puts ("  -L, --files-without-match   print only names of FILEs with no selected lines");
    puts ("  -l, --files-with-matches    print only names of FILEs with selected lines");
    puts ("  -c, --count                 print only a count of selected lines per FILE");
    puts ("  -Z, --null                  print 0 byte after FILE name");
    puts ("  -B, --before-context=NUM    print NUM lines of leading context");
    puts ("  -A, --after-context=NUM     print NUM lines of trailing context");
    puts ("  -C, --context=NUM, -NUM     print NUM lines of output context");
    puts ("      --color[=WHEN]          accepted; no color is emitted");
    puts ("Exit status is 0 if any line is selected, 1 otherwise; 2 on an error.");
}

static void
bg_print_version (void)
{
    puts ("grep (bash-os) 3.11-compatible");
}

static void
bg_usage (void)
{
    fputs ("Usage: grep [OPTION]... PATTERNS [FILE]...\nTry 'grep --help' for more information.\n", stderr);
}

static int
bg_add_glob (char ***list, int *count, const char *glob)
{
    char **nl = realloc (*list, (size_t) (*count + 1) * sizeof **list);
    if (!nl) return -1;
    *list = nl;
    (*list)[*count] = strdup (glob);
    if (!(*list)[*count]) return -1;
    (*count)++;
    return 0;
}

#define BG_FAIL(code) do { rc = (code); goto out; } while (0)

int
grep_builtin (WORD_LIST *list)
{
    bg_opts o;
    memset (&o, 0, sizeof o);
    int rc = EXECUTION_SUCCESS;
    int have_e = 0;                 /* -e or -f given: the first operand is a file */
    int n_files = 0, paths_cap = 8;
    const char **paths = malloc ((size_t) paths_cap * sizeof *paths);
    if (!paths) { builtin_error ("out of memory"); return EXECUTION_FAILURE; }

    int end_options = 0;
    WORD_LIST *p = list;
    while (p)
    {
        const char *w = p->word->word;
        if (!end_options && !strcmp (w, "--")) { end_options = 1; p = p->next; continue; }
        if (!end_options && w[0] == '-' && w[1] == '-')
        {
            const char *val;
            if (!strcmp (w, "--help")) { bg_print_help (); BG_FAIL (EXECUTION_SUCCESS); }
            if (!strcmp (w, "--version")) { bg_print_version (); BG_FAIL (EXECUTION_SUCCESS); }
            if (!strcmp (w, "--extended-regexp")) { o.Eflag = 1; o.Fflag = 0; o.Gflag = 0; o.Pflag = 0; }
            else if (!strcmp (w, "--basic-regexp")) { o.Eflag = 0; o.Fflag = 0; o.Gflag = 1; o.Pflag = 0; }
            else if (!strcmp (w, "--fixed-strings")) { o.Eflag = 0; o.Fflag = 1; o.Gflag = 0; o.Pflag = 0; }
            else if (!strcmp (w, "--perl-regexp")) { o.Eflag = 0; o.Pflag = 1; o.Fflag = 0; o.Gflag = 0; }
            else if (!strcmp (w, "--ignore-case")) o.iflag = 1;
            else if (!strcmp (w, "--no-ignore-case")) o.iflag = 0;
            else if (!strcmp (w, "--invert-match")) o.vflag = 1;
            else if (!strcmp (w, "--count")) o.cflag = 1;
            else if (!strcmp (w, "--files-with-matches")) o.lflag = 1;
            else if (!strcmp (w, "--files-without-match")) o.Lflag = 1;
            else if (!strcmp (w, "--line-number")) o.nflag = 1;
            else if (!strcmp (w, "--byte-offset")) o.bflag = 1;
            else if (!strcmp (w, "--null-data")) o.zdflag = 1;
            else if ((!strncmp (w, "--color", 7) && (w[7] == '\0' || w[7] == '='))
                     || (!strncmp (w, "--colour", 8) && (w[8] == '\0' || w[8] == '='))) { /* no color */ }
            else if (!strcmp (w, "--only-matching")) o.oflag = 1;
            else if (!strcmp (w, "--recursive")) o.rflag = 1;
            else if (!strcmp (w, "--dereference-recursive")) { o.rflag = 1; o.Rflag = 1; }
            else if (!strcmp (w, "--quiet") || !strcmp (w, "--silent")) o.qflag = 1;
            else if (!strcmp (w, "--no-messages")) o.sflag = 1;
            else if (!strcmp (w, "--with-filename")) o.Hflag = 1;
            else if (!strcmp (w, "--no-filename")) o.hflag = 1;
            else if (!strcmp (w, "--word-regexp")) o.wflag = 1;
            else if (!strcmp (w, "--line-regexp")) o.xflag = 1;
            else if (!strcmp (w, "--text")) o.aflag = 1;
            else if (!strcmp (w, "--null")) o.Zflag = 1;
            else if (!strncmp (w, "--binary-files=", 15))
            {
                val = w + 15;
                if (!strcmp (val, "text")) { o.aflag = 1; o.Iflag = 0; }
                else if (!strcmp (val, "without-match")) { o.Iflag = 1; o.aflag = 0; }
                else if (!strcmp (val, "binary")) { o.aflag = 0; o.Iflag = 0; }
                else { builtin_error ("unknown binary-files type"); BG_FAIL (EX_USAGE); }
            }
            else if (!strncmp (w, "--max-count", 11) && (w[11] == '=' || w[11] == '\0'))
            {
                if (w[11] == '=') val = w + 12;
                else { if (!p->next) { builtin_error ("option '--max-count' requires an argument"); BG_FAIL (EX_USAGE); } p = p->next; val = p->word->word; }
                int n;
                if (bg_parse_count (val, &n) < 0) { builtin_error ("invalid max count"); BG_FAIL (EX_USAGE); }
                o.mflag = n; o.mflag_set = 1;
            }
            else if (!strncmp (w, "--regexp=", 9))
            {
                if (bg_add_patterns (&o, w + 9, strlen (w + 9)) < 0) BG_FAIL (EXECUTION_FAILURE);
                have_e = 1;
            }
            else if (!strncmp (w, "--file=", 7))
            {
                if (bg_add_pattern_file (&o, w + 7) < 0) { bg_file_error (&o, w + 7, errno); BG_FAIL (2); }
                have_e = 1;
            }
            else if (!strncmp (w, "--after-context=", 16) || !strncmp (w, "--before-context=", 17) || !strncmp (w, "--context=", 10))
            {
                val = strchr (w, '=') + 1;
                int n;
                if (bg_parse_count (val, &n) < 0) { builtin_error ("%s: invalid context length argument", val); BG_FAIL (EX_USAGE); }
                if (w[2] != 'b') o.A = n;
                if (w[2] != 'a') o.B = n;
                o.ctx = 1;
            }
            else if (!strncmp (w, "--include=", 10)) { if (bg_add_glob (&o.incl_globs, &o.n_incl, w + 10) < 0) BG_FAIL (EXECUTION_FAILURE); }
            else if (!strncmp (w, "--exclude=", 10)) { if (bg_add_glob (&o.excl_globs, &o.n_excl, w + 10) < 0) BG_FAIL (EXECUTION_FAILURE); }
            else if (!strncmp (w, "--exclude-dir=", 14)) { if (bg_add_glob (&o.excl_dir_globs, &o.n_excl_dir, w + 14) < 0) BG_FAIL (EXECUTION_FAILURE); }
            else
            {
                builtin_error ("unrecognized option '%s'", w);
                bg_usage ();
                BG_FAIL (EX_USAGE);
            }
            p = p->next;
            continue;
        }
        /* Options may appear anywhere (GNU). The first non-option word is
           the pattern unless -e/-f supplied one; the rest are files. */
        if (!end_options && w[0] == '-' && w[1] != '\0')
        {
            for (const char *c = w + 1; *c; c++)
            {
                switch (*c)
                {
                    case 'E': o.Eflag = 1; o.Fflag = 0; o.Gflag = 0; o.Pflag = 0; break;
                    case 'G': o.Eflag = 0; o.Fflag = 0; o.Gflag = 1; o.Pflag = 0; break;
                    case 'F': o.Eflag = 0; o.Fflag = 1; o.Gflag = 0; o.Pflag = 0; break;
                    case 'P': o.Eflag = 0; o.Pflag = 1; o.Fflag = 0; o.Gflag = 0; break;
                    case 'i': case 'y': o.iflag = 1; break;
                    case 'v': o.vflag = 1; break;
                    case 'c': o.cflag = 1; break;
                    case 'l': o.lflag = 1; break;
                    case 'L': o.Lflag = 1; break;
                    case 'n': o.nflag = 1; break;
                    case 'b': o.bflag = 1; break;
                    case 'z': o.zdflag = 1; break;
                    case 'o': o.oflag = 1; break;
                    case 'r': o.rflag = 1; break;
                    case 'R': o.rflag = 1; o.Rflag = 1; break;
                    case 'H': o.Hflag = 1; break;
                    case 'h': o.hflag = 1; break;
                    case 'q': o.qflag = 1; break;
                    case 's': o.sflag = 1; break;
                    case 'w': o.wflag = 1; break;
                    case 'x': o.xflag = 1; break;
                    case 'Z': o.Zflag = 1; break;
                    case 'a': o.aflag = 1; break;
                    case 'I': o.Iflag = 1; break;
                    case 'm': case 'e': case 'f': case 'A': case 'B': case 'C':
                    {
                        char which = *c;
                        const char *val;
                        if (c[1] != '\0') val = c + 1;
                        else
                        {
                            if (!p->next) { builtin_error ("option requires an argument -- '%c'", which); BG_FAIL (EX_USAGE); }
                            p = p->next;
                            val = p->word->word;
                        }
                        if (which == 'e')
                        {
                            if (bg_add_patterns (&o, val, strlen (val)) < 0) BG_FAIL (EXECUTION_FAILURE);
                            have_e = 1;
                        }
                        else if (which == 'f')
                        {
                            if (bg_add_pattern_file (&o, val) < 0) { bg_file_error (&o, val, errno); BG_FAIL (2); }
                            have_e = 1;
                        }
                        else
                        {
                            int n;
                            if (bg_parse_count (val, &n) < 0)
                            {
                                if (which == 'm') builtin_error ("invalid max count");
                                else builtin_error ("%s: invalid context length argument", val);
                                BG_FAIL (EX_USAGE);
                            }
                            if (which == 'm') { o.mflag = n; o.mflag_set = 1; }
                            else
                            {
                                if (which != 'B') o.A = n;
                                if (which != 'A') o.B = n;
                                o.ctx = 1;
                            }
                        }
                        goto next_word;
                    }
                    default:
                        if (*c >= '0' && *c <= '9')
                        {
                            /* -NUM: -C NUM */
                            int n = 0;
                            while (*c >= '0' && *c <= '9' && n < 1000000) n = n * 10 + (*c++ - '0');
                            c--;
                            o.A = o.B = n; o.ctx = 1;
                            break;
                        }
                        builtin_error ("invalid option -- '%c'", *c);
                        bg_usage ();
                        BG_FAIL (EX_USAGE);
                }
            }
        }
        else if (!have_e)
        {
            if (bg_add_patterns (&o, w, strlen (w)) < 0) BG_FAIL (EXECUTION_FAILURE);
            have_e = 2;
        }
        else
        {
            if (n_files == paths_cap)
            {
                paths_cap *= 2;
                const char **bigger = realloc (paths, (size_t) paths_cap * sizeof *paths);
                if (!bigger) BG_FAIL (EXECUTION_FAILURE);
                paths = bigger;
            }
            paths[n_files++] = w;
        }
    next_word:
        p = p->next;
    }

    if (!have_e)
    {
        bg_usage ();
        BG_FAIL (EX_USAGE);
    }
    if (o.xflag) o.wflag = 0;               /* -x takes precedence, as GNU */
    o.delim = o.zdflag ? '\0' : '\n';
    if (o.Pflag && o.zdflag) { builtin_error ("-P with -z is not supported"); BG_FAIL (EX_USAGE); }
    if (o.Pflag && o.wflag) { builtin_error ("-P with -w is not supported"); BG_FAIL (EX_USAGE); }

    /* No pattern at all (-f /dev/null): nothing matches, which -v turns
       into everything; and -x/-w are moot. As GNU. */
    if (o.n_arms == 0)
    {
        o.vflag = !o.vflag; o.xflag = o.wflag = 0;
        if (bg_add_arm (&o, "", 0) < 0) BG_FAIL (EXECUTION_FAILURE);
    }
    /* Nothing can be selected: -m 0, or -v of the one empty pattern that
       matches every line. GNU exits 1 without reading, and prints nothing. */
    if ((o.mflag_set && o.mflag == 0)
        || (o.n_arms == 1 && o.arms[0].n == 0 && o.vflag && !o.xflag && !o.wflag))
    {
        if (!o.Lflag) BG_FAIL (1);
    }
    /* -q overrides -l/-L, which override -c; no context under any of them. */
    if (o.qflag) o.lflag = o.Lflag = 0;
    if (o.qflag || o.lflag || o.Lflag) { o.cflag = 0; o.A = o.B = 0; }

    if (bg_setup (&o) < 0) BG_FAIL (2);

    long total = 0;
    int err = 0;
    if (n_files == 0)
    {
        if (o.rflag) { paths[n_files++] = "."; o.implicit_dot = 1; }
        else
        {
            long c = bg_grep_file (&o, NULL, 1, 0);
            if (c < 0) err = 1; else total += c;
        }
    }
    for (int i = 0; i < n_files; i++)
    {
        if (o.qflag && total > 0) break;
        long c = o.rflag ? bg_grep_recursive (&o, paths[i], 0)
                         : bg_grep_file (&o, paths[i], n_files, 0);
        if (c < 0) err = 1; else total += c;
    }
    fflush (stdout);
    /* 0 if any line was selected, 1 if none, 2 on an error; with -q a
       match wins over an earlier error, as GNU. */
    if (o.qflag && total > 0) rc = 0;
    else if (err) rc = 2;
    else rc = total > 0 ? 0 : 1;
out:
    if (fflush (stdout) == EOF || ferror (stdout))
    {
        int e = errno;
        builtin_error ("write error: %s", strerror (e ? e : EIO));
        clearerr (stdout);
        rc = 2;
    }
    bg_free (&o);
    free (paths);
    return rc;
}

char *grep_doc[] = {
    "Search FILEs (or standard input) for lines matching PATTERNS.",
    "",
    "    grep [OPTION]... PATTERNS [FILE]...",
    "",
    "PATTERNS are basic regular expressions as in GNU grep (\\( \\) \\| \\+",
    "\\? \\{ \\} are operators); -E makes them extended, -F fixed strings.",
    "A newline in PATTERNS separates patterns, as do repeated -e and the",
    "lines of -f FILE. Output, exit status and the treatment of binary",
    "files, context, -m and -w follow GNU grep 3.11.",
    "",
    "Options:",
    "    -E -F -G -P      extended, fixed, basic (default), Perl (if built)",
    "    -e PAT -f FILE   patterns; -f - reads them from standard input",
    "    -i -y -v -w -x   ignore case, invert, whole words, whole lines",
    "    -c -l -L -q -s   count, files with/without matches, quiet, no messages",
    "    -n -b -H -h -o   line numbers, byte offsets, file names, only matches",
    "    -m N             stop after N selected lines",
    "    -A N -B N -C N   context lines (also -NUM)",
    "    -r -R            recurse (-R follows symlinks); --include --exclude --exclude-dir",
    "    -a -I -z -Z      binary as text, skip binary, NUL-terminated lines, NUL after names",
    "",
    "Exit: 0 if a line is selected, 1 if none, 2 on an error.",
    (char *)NULL
};

struct builtin grep_struct = {
    "grep",
    grep_builtin,
    BUILTIN_ENABLED,
    grep_doc,
    "grep [-EFGPiyvwxclLqsnbHhoaIzZrR] [-m N] [-e PAT]... [-f FILE]... [-A N] [-B N] [-C N] [PATTERNS] [FILE...]",
    0
};
