/* SPDX-License-Identifier: MIT */
/* join.c — POSIX join(1) as a bash builtin.
 *
 *   join [-i] [-1 N] [-2 N] [-t SEP] [-a {1,2}] [-v {1,2}] [-e EMPTY] [-o FORMAT] FILE1 FILE2
 *
 * Joins lines from two pre-sorted files on a common field. Both files
 * must already be sorted on the join key (LC_COLLATE=C); we don't sort
 * internally — matching POSIX. `-` for FILE1 or FILE2 reads stdin.
 *
 * Flags:
 *   -i           ignore case when comparing join fields
 *   -1 N         join field for FILE1 (1-based; default 1)
 *   -2 N         join field for FILE2 (1-based; default 1)
 *   -t SEP       single-char field separator (default: any whitespace run)
 *   -a 1 / -a 2  also print unmatched lines from FILE1 / FILE2
 *   -v 1 / -v 2  only print unmatched lines from FILE1 / FILE2
 *   -e STR       replace missing or empty output fields with STR
 *   -o FORMAT    output format: comma-separated list of FILENUM.FIELDNUM
 *                or `0` (the join key). Default: key + remaining FILE1
 *                fields + remaining FILE2 fields.
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
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "loadables.h"

typedef struct {
    int   field1;       /* 1-based; 0 = an index beyond INT_MAX (missing) */
    int   field2;
    int   sep;          /* 0 = whitespace; else byte */
    int   show_unmatched_1;
    int   show_unmatched_2;
    int   only_unmatched;
    int   ignore_case;
    int   header;       /* --header: pass first line through as headers */
    int   order;        /* input-order check: BJ_ORDER_OFF, _DEFAULT or _ON */
    int   auto_fmt;     /* -o auto: infer field count from first records */
    const char *empty;
    /* Output format: array of (filenum, fieldnum). filenum 0 = key. */
    int   (*ofmt)[2];
    size_t ofmt_cap;
    int auto_n1, auto_n2;
    int   n_ofmt;
    FILE *out;
} bj_opts;

extern char *join_doc[];

static void
bj_print_help (void)
{
    for (char **p = join_doc; *p; p++)
        puts (*p);
}

/* Fields are byte slices: NUL and CR are ordinary input bytes. */
typedef struct {
    const char *data;
    size_t len;
} bj_value;

typedef struct {
    char *line;
    size_t cap;
    bj_value *fields;
    size_t fields_cap;
    int nf;
} bj_record;

static void
bj_free_rec (bj_record *r)
{
    free (r->line);
    free (r->fields);
    memset (r, 0, sizeof (*r));
}

typedef struct {
    bj_record *v;
    size_t n, cap;
} bj_group;

static void
bj_free_group (bj_group *g)
{
    for (size_t i = 0; i < g->cap; i++) bj_free_rec (&g->v[i]);
    free (g->v);
}

static int
bj_add_field (bj_record *r, size_t start, size_t end)
{
    if (r->nf == INT_MAX) return -1;
    if ((size_t) r->nf == r->fields_cap) {
        size_t cap = r->fields_cap ? r->fields_cap * 2 : 8;
        if (cap > SIZE_MAX / sizeof (*r->fields)) return -1;
        bj_value *v = realloc (r->fields, cap * sizeof (*v));
        if (!v) return -1;
        r->fields = v;
        r->fields_cap = cap;
    }
    r->fields[r->nf++] = (bj_value) { r->line + start, end - start };
    return 0;
}

/* Tokenize the getline buffer once, without copying or changing its bytes. */
static int
bj_split (bj_record *r, size_t len, int sep)
{
    if (len && r->line[len - 1] == '\n') len--;
    r->nf = 0;
    size_t pos = 0;
    if (sep == 0) {
        while (pos < len) {
            while (pos < len && (r->line[pos] == ' ' || r->line[pos] == '\t')) pos++;
            if (pos == len) break;
            size_t start = pos;
            while (pos < len && r->line[pos] != ' ' && r->line[pos] != '\t') pos++;
            if (bj_add_field (r, start, pos) < 0) return -1;
        }
    } else {
        size_t start = 0;
        for (; pos < len; pos++) {
            if ((unsigned char) r->line[pos] != sep) continue;
            if (bj_add_field (r, start, pos) < 0) return -1;
            start = pos + 1;
        }
        if (bj_add_field (r, start, len) < 0) return -1;
    }
    return r->nf;
}

/* Move ownership into the group. The old slot becomes the next read buffer;
   neither the row bytes nor their tokens need to be copied or parsed again. */
static int
bj_group_add (bj_group *g, bj_record *src)
{
    if (g->n == g->cap) {
        size_t cap = g->cap ? g->cap * 2 : 4;
        if (cap > SIZE_MAX / sizeof (*g->v)) return -1;
        bj_record *v = realloc (g->v, cap * sizeof (*v));
        if (!v) return -1;
        memset (v + g->cap, 0, (cap - g->cap) * sizeof (*v));
        g->v = v;
        g->cap = cap;
    }
    bj_record spare = g->v[g->n];
    g->v[g->n++] = *src;
    *src = spare;
    return 0;
}

static bj_value
bj_field (const bj_record *r, int n)
{
    if (!r || n < 1 || n > r->nf) return (bj_value) { "", 0 };
    return r->fields[n - 1];
}

static void
bj_emit_value (const bj_opts *o, bj_value v)
{
    if (v.len) fwrite (v.data, 1, v.len, o->out);
    else if (o->empty) fputs (o->empty, o->out);
}

static void
bj_emit_outsep (int sep, FILE *out)
{
    fputc (sep == 0 ? ' ' : (char) sep, out);
}

/* Default join layout: KEY <sep> rest-of-FILE1 <sep> rest-of-FILE2. */
static void
bj_emit_default (const bj_opts *o, const bj_record *r1, const bj_record *r2)
{
    const bj_record *key_rec = r1 ? r1 : r2;
    int key_field = r1 ? o->field1 : o->field2;
    bj_emit_value (o, bj_field (key_rec, key_field));
    if (r1 || o->auto_fmt) {
        for (int i = 1; i <= (o->auto_fmt ? o->auto_n1 : r1->nf); i++) {
            if (i == o->field1) continue;
            bj_emit_outsep (o->sep, o->out);
            bj_emit_value (o, bj_field (r1, i));
        }
    }
    if (r2 || o->auto_fmt) {
        for (int i = 1; i <= (o->auto_fmt ? o->auto_n2 : r2->nf); i++) {
            if (i == o->field2) continue;
            bj_emit_outsep (o->sep, o->out);
            bj_emit_value (o, bj_field (r2, i));
        }
    }
    fputc ('\n', o->out);
}

static void
bj_emit_format (const bj_opts *o, const bj_record *r1, const bj_record *r2)
{
    for (int i = 0; i < o->n_ofmt; i++) {
        if (i) bj_emit_outsep (o->sep, o->out);
        int filenum = o->ofmt[i][0];
        int fnum    = o->ofmt[i][1];
        bj_value v;
        if (filenum == 0) v = bj_field (r1 ? r1 : r2, r1 ? o->field1 : o->field2);
        else if (filenum == 1) v = r1 ? bj_field (r1, fnum) : (bj_value) { "", 0 };
        else                    v = r2 ? bj_field (r2, fnum) : (bj_value) { "", 0 };
        bj_emit_value (o, v);
    }
    fputc ('\n', o->out);
}

static void
bj_emit (const bj_opts *o, const bj_record *r1, const bj_record *r2)
{
    if (o->n_ofmt > 0) bj_emit_format (o, r1, r2);
    else               bj_emit_default (o, r1, r2);
}

/* Capture a stdout write failure before a later read overwrites errno. */
static int
bj_out_err (const bj_opts *o, int *err)
{
    if (*err)
        return 1;
    if (ferror (o->out)) {
        *err = errno ? errno : EIO;
        return 1;
    }
    return 0;
}

static int
bj_parse_ofmt (bj_opts *o, const char *s)
{
    if (!*s) return -1;
    while (*s) {
        int file = 0, field = 0;
        if (*s == '0') s++;
        else {
            if ((s[0] != '1' && s[0] != '2') || s[1] != '.') return -1;
            file = *s - '0';
            s += 2;
            if (!isdigit ((unsigned char) *s)) return -1;
            char *end;
            errno = 0;
            uintmax_t n = strtoumax (s, &end, 10);
            if (n == 0) return -1;
            /* A field beyond the representable record count is missing.
               GNU accepts arbitrarily large positive indexes as well. */
            field = n > INT_MAX ? 0 : (int) n;
            s = end;
        }
        if (*s && *s != ',' && *s != ' ' && *s != '\t') return -1;
        if (o->n_ofmt == INT_MAX) return -1;
        if ((size_t) o->n_ofmt == o->ofmt_cap) {
            size_t cap = o->ofmt_cap ? o->ofmt_cap * 2 : 8;
            if (cap > SIZE_MAX / sizeof (*o->ofmt)) return -1;
            void *v = realloc (o->ofmt, cap * sizeof (*o->ofmt));
            if (!v) return -1;
            o->ofmt = v;
            o->ofmt_cap = cap;
        }
        o->ofmt[o->n_ofmt][0] = file;
        o->ofmt[o->n_ofmt++][1] = field;
        if (*s) s++;
    }
    return 0;
}

static int
bj_keycmp (bj_value a, bj_value b, const bj_opts *o)
{
    size_t len = a.len < b.len ? a.len : b.len;
    int cmp = 0;
    if (o->ignore_case) {
        for (size_t i = 0; i < len; i++) {
            cmp = tolower ((unsigned char) a.data[i]) - tolower ((unsigned char) b.data[i]);
            if (cmp) break;
        }
    } else if (len) cmp = memcmp (a.data, b.data, len);
    return cmp ? cmp : (a.len > b.len) - (a.len < b.len);
}

/* Input-order checking, as GNU join does it. By default a disorder is
   reported, once per file, only after an unpairable line has been seen
   while both inputs remained, and the command fails at the end;
   --check-order makes the first disorder fatal. */
enum { BJ_ORDER_OFF, BJ_ORDER_DEFAULT, BJ_ORDER_ON };

typedef struct {
    const char *name[2];
    long long   lineno[2];
    bj_value    prev[2];        /* key of the record being replaced */
    size_t      prevcap[2];
    int         warned[2];
    int         seen_unpairable;
} bj_order;

/* Read input WHICH into R. Previous keys belong to ORD so moving a record
   into a group cannot invalidate order checking. TRACK excludes headers and
   initial reads. Return -1 for read/allocation errors or fatal disorder. */
static int
bj_advance (const bj_opts *o, bj_order *ord, int which, FILE *f,
            ssize_t *n, bj_record *r, int track)
{
    int field = which ? o->field2 : o->field1;
    *n = getline (&r->line, &r->cap, f);
    if (*n == -1) {
        if (ferror (f)) {
            builtin_error ("%s: read error: %s", ord->name[which], strerror (errno ? errno : EIO));
            return -1;
        }
        return 0;
    }
    ord->lineno[which]++;
    if (bj_split (r, (size_t) *n, o->sep) < 0) {
        builtin_error ("out of memory");
        return -1;
    }
    bj_value key = bj_field (r, field);
    if (track && o->order != BJ_ORDER_OFF && !ord->warned[which]
        && (o->order == BJ_ORDER_ON || ord->seen_unpairable)
        && bj_keycmp (ord->prev[which], key, o) > 0) {
        size_t len = (size_t) *n;
        if (len && r->line[len - 1] == '\n') len--;
        builtin_error ("%s:%lld: is not sorted: %.*s", ord->name[which],
                       ord->lineno[which], (int) (len > INT_MAX ? INT_MAX : len), r->line);
        if (o->order == BJ_ORDER_ON) return -1;
        ord->warned[which] = 1;
    }
    if (o->order != BJ_ORDER_OFF && !ord->warned[which]) {
        if (ord->prevcap[which] < key.len) {
            char *v = realloc ((void *) ord->prev[which].data, key.len);
            if (!v) { builtin_error ("out of memory"); return -1; }
            ord->prev[which].data = v;
            ord->prevcap[which] = key.len;
        }
        if (key.len) memcpy ((void *) ord->prev[which].data, key.data, key.len);
        ord->prev[which].len = key.len;
    }
    return 0;
}

/* Resolve a short option's argument, supporting both the attached form
   (-t:, -a1, -o1.1) and the separate form (-t : / -a 1). ATTACHED is the
   suffix of the current option word (w+2) or NULL when the word is bare.
   When separate, advances *lp to the next word (the argument). Returns the
   argument string, or NULL if one is required but missing. */
static const char *
bj_optarg (WORD_LIST **lp, const char *attached)
{
    if (attached) return attached;
    if (!(*lp)->next) return NULL;
    *lp = (*lp)->next;
    return (*lp)->word->word;
}

static FILE *
bj_open_input (const char *name)
{
    if (strcmp (name, "-")) return fopen (name, "r");
    /* A failed output can leave unread bytes in stdio. Own that buffer so
       a later stdin redirection cannot expose an earlier invocation's data. */
    /* Reserve the standard descriptors even when stdout/stderr is closed. */
    int fd = fcntl (STDIN_FILENO, F_DUPFD_CLOEXEC, 3);
    if (fd < 0) return NULL;
    FILE *input = fdopen (fd, "r");
    if (!input) {
        int saved_errno = errno;
        close (fd);
        errno = saved_errno;
    }
    return input;
}

static int
bj_join (WORD_LIST *list, bj_opts *o)
{
    clearerr (stdin);
    clearerr (stdout);

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        /* Long options. */
        if (!strcmp (w, "--help")) {
            bj_print_help ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version")) {
            puts ("join 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--ignore-case")) {
            o->ignore_case = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--header")) {
            o->header = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--nocheck-order")) {
            o->order = BJ_ORDER_OFF;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--check-order")) {
            o->order = BJ_ORDER_ON;
            list = list->next;
            continue;
        }
        /* Short options. w[1] is the flag; w+2 is any attached argument
           (e.g. -t:, -a1, -o1.1, -j2). Arg-taking flags accept both the
           attached and the separate (-t :) form via bj_optarg(). */
        char flag = w[1];
        const char *attached = w[2] ? w + 2 : NULL;
        const char *arg;
        switch (flag) {
            case 'i':
                if (attached) { builtin_error ("unknown flag: %s", w); builtin_usage (); return EX_USAGE; }
                o->ignore_case = 1;
                list = list->next;
                continue;
            case '1': case '2': case 'j': {
                arg = bj_optarg (&list, attached);
                if (!arg) { builtin_error ("-%c needs N", flag); builtin_usage (); return EX_USAGE; }
                char *end;
                errno = 0;
                const char *digits = arg;
                while (isspace ((unsigned char) *digits)) digits++;
                uintmax_t fld = strtoumax (arg, &end, 10);
                if (*digits == '-' || end == arg || *end || fld == 0) { builtin_error ("invalid field number: %s", arg); builtin_usage (); return EX_USAGE; }
                int field = fld > INT_MAX ? 0 : (int) fld;
                if (flag == '1' || flag == 'j') o->field1 = field;
                if (flag == '2' || flag == 'j') o->field2 = field;
                list = list->next;
                continue;
            }
            case 't': {
                arg = bj_optarg (&list, attached);
                if (!arg || arg[0] == '\0' || arg[1] != '\0') {
                    builtin_error ("-t: SEP must be a single byte");
                    builtin_usage ();
                    return EX_USAGE;
                }
                o->sep = (unsigned char) arg[0];
                list = list->next;
                continue;
            }
            case 'a': case 'v': {
                arg = bj_optarg (&list, attached);
                if (!arg || (strcmp (arg, "1") && strcmp (arg, "2"))) {
                    builtin_error ("-%c: must be 1 or 2", flag);
                    builtin_usage ();
                    return EX_USAGE;
                }
                if (arg[0] == '1') o->show_unmatched_1 = 1;
                else               o->show_unmatched_2 = 1;
                if (flag == 'v') o->only_unmatched = 1;
                list = list->next;
                continue;
            }
            case 'e': {
                arg = bj_optarg (&list, attached);
                if (!arg) { builtin_error ("-e needs STR"); builtin_usage (); return EX_USAGE; }
                o->empty = arg;
                list = list->next;
                continue;
            }
            case 'o': {
                arg = bj_optarg (&list, attached);
                if (!arg) { builtin_error ("-o needs FORMAT"); builtin_usage (); return EX_USAGE; }
                if (!strcmp (arg, "auto")) {
                    o->auto_fmt = 1;
                    list = list->next;
                    continue;
                }
                if (bj_parse_ofmt (o, arg) < 0) {
                    builtin_error ("-o: bad format: %s", arg);
                    builtin_usage ();
                    return EX_USAGE;
                }
                list = list->next;
                continue;
            }
            default:
                builtin_error ("unknown flag: %s", w);
                builtin_usage ();
                return EX_USAGE;
        }
    }

    if (!list || !list->next || list->next->next) {
        builtin_usage ();
        return EX_USAGE;
    }
    const char *p1 = list->word->word;
    const char *p2 = list->next->word->word;
    if (!strcmp (p1, "-") && !strcmp (p2, "-")) {
        builtin_error ("both files cannot be standard input");
        return EXECUTION_FAILURE;
    }
    FILE *fa = bj_open_input (p1);
    if (!fa) { builtin_error ("%s: %s", p1, strerror (errno)); return EXECUTION_FAILURE; }
    FILE *fb = bj_open_input (p2);
    if (!fb) {
        fclose (fa);
        builtin_error ("%s: %s", p2, strerror (errno));
        return EXECUTION_FAILURE;
    }

    /* A private output stream avoids Bash's line buffering for regular
       input files. Keep immediate writes for pipe/FIFO input: a producer
       may remain open after an output failure and must not make us wait. */
    struct stat sa, sb;
    if (!isatty (STDOUT_FILENO)
        && fstat (fileno (fa), &sa) == 0 && S_ISREG (sa.st_mode)
        && fstat (fileno (fb), &sb) == 0 && S_ISREG (sb.st_mode)
        && fflush (stdout) == 0) {
        int fd = dup (STDOUT_FILENO);
        FILE *buffered = fd < 0 ? NULL : fdopen (fd, "w");
        if (buffered) o->out = buffered;
        else if (fd >= 0) close (fd);
    }

    bj_record ra = { 0 }, rb = { 0 };
    /* Reuse record storage across groups; moves retain each getline buffer. */
    bj_group ga = { 0 }, gb = { 0 };
    bj_value key = { NULL, 0 };
    size_t keycap = 0;
    int out_err = 0;
    int rc = EXECUTION_SUCCESS;
    bj_order ord = { .name = { p1, p2 } };
    ssize_t na = 0, nb = 0;
    if (bj_advance (o, &ord, 0, fa, &na, &ra, 0) < 0 ||
        bj_advance (o, &ord, 1, fb, &nb, &rb, 0) < 0) {
        rc = EXECUTION_FAILURE; goto done;
    }

    /* -o auto: infer a fixed output layout from the field counts of the
       first records — key, then every non-key field of FILE1, then every
       non-key field of FILE2. The count is fixed for the whole run; later
       lines with more fields are truncated, fewer are padded (with -e). */
    if (o->auto_fmt) {
        o->auto_n1 = na != -1 ? ra.nf : 0;
        o->auto_n2 = nb != -1 ? rb.nf : 0;
    }

    /* --header: pass the first line of each file through as a header line,
       joined as a (forced) matched pair regardless of key comparison, then
       continue normal processing from the second line. The header is not
       order-checked. */
    if (o->header && (na != -1 || nb != -1)) {
        bj_emit (o, na != -1 ? &ra : NULL, nb != -1 ? &rb : NULL);
        if (!bj_out_err (o, &out_err)) {
            if ((na != -1 && bj_advance (o, &ord, 0, fa, &na, &ra, 0) < 0) ||
                (nb != -1 && bj_advance (o, &ord, 1, fb, &nb, &rb, 0) < 0)) {
                rc = EXECUTION_FAILURE; goto done;
            }
        }
    }

    /* Do not read another record after stdout has failed: with the producer
       still open that read blocks, while GNU join has already exited. */
    while (!out_err && (na != -1 || nb != -1)) {
        bj_value ka = bj_field (na != -1 ? &ra : NULL, o->field1);
        bj_value kb = bj_field (nb != -1 ? &rb : NULL, o->field2);
        int cmp;
        if (na == -1)      cmp =  1;
        else if (nb == -1) cmp = -1;
        else               cmp = bj_keycmp (ka, kb, o);
        if (cmp == 0) {
            size_t keylen = ka.len;
            int oom = 0;
            if (keycap < keylen) {
                char *next = realloc ((void *) key.data, keylen);
                if (!next) oom = 1;
                else { key.data = next; keycap = keylen; }
            }
            if (!oom) {
                if (keylen) memcpy ((void *) key.data, ka.data, keylen);
                key.len = keylen;
            }
            ga.n = gb.n = 0;

            while (!oom && na != -1 && bj_keycmp (bj_field (&ra, o->field1), key, o) == 0) {
                if (bj_group_add (&ga, &ra) < 0) { oom = 1; break; }
                if (bj_advance (o, &ord, 0, fa, &na, &ra, 1) < 0) {
                    rc = EXECUTION_FAILURE; goto done;
                }
            }
            while (!oom && nb != -1 && bj_keycmp (bj_field (&rb, o->field2), key, o) == 0) {
                if (bj_group_add (&gb, &rb) < 0) { oom = 1; break; }
                if (bj_advance (o, &ord, 1, fb, &nb, &rb, 1) < 0) {
                    rc = EXECUTION_FAILURE; goto done;
                }
            }

            if (oom) {
                builtin_error ("out of memory");
                rc = EXECUTION_FAILURE;
                goto done;
            }

            if (!o->only_unmatched)
                for (size_t i = 0; i < ga.n && !bj_out_err (o, &out_err); i++)
                    for (size_t j = 0; j < gb.n && !bj_out_err (o, &out_err); j++) {
                        bj_emit (o, &ga.v[i], &gb.v[j]);
                        bj_out_err (o, &out_err);
                    }
        } else if (cmp < 0) {
            if (o->show_unmatched_1 && na != -1) {
                bj_emit (o, &ra, NULL);
                if (bj_out_err (o, &out_err))
                    break;
            }
            /* As in GNU join, only an unpairable line met while both inputs
               remain enables the default order check, and only after the
               read that follows it. */
            int both = nb != -1;
            if (bj_advance (o, &ord, 0, fa, &na, &ra, 1) < 0) {
                rc = EXECUTION_FAILURE; goto done;
            }
            if (both) ord.seen_unpairable = 1;
        } else {
            if (o->show_unmatched_2 && nb != -1) {
                bj_emit (o, NULL, &rb);
                if (bj_out_err (o, &out_err))
                    break;
            }
            int both = na != -1;
            if (bj_advance (o, &ord, 1, fb, &nb, &rb, 1) < 0) {
                rc = EXECUTION_FAILURE; goto done;
            }
            if (both) ord.seen_unpairable = 1;
        }
    }

    /* A reported disorder fails the command once all output is written. */
    if (rc == EXECUTION_SUCCESS && (ord.warned[0] || ord.warned[1])) {
        builtin_error ("input is not in sorted order");
        rc = EXECUTION_FAILURE;
    }

done:
    free ((void *) ord.prev[0].data); free ((void *) ord.prev[1].data);
    free ((void *) key.data);
    bj_free_group (&ga); bj_free_group (&gb);
    bj_free_rec (&ra); bj_free_rec (&rb);
    fclose (fa);
    fclose (fb);
    if (!out_err && (fflush (o->out) == EOF || ferror (o->out)))
        out_err = errno ? errno : EIO;
    if (o->out != stdout && fclose (o->out) != 0 && !out_err)
        out_err = errno ? errno : EIO;
    if (out_err) {
        builtin_error ("write error: %s", strerror (out_err));
        return EXECUTION_FAILURE;
    }
    return rc;
}

int
join_builtin (WORD_LIST *list)
{
    bj_opts o = { .field1 = 1, .field2 = 1, .order = BJ_ORDER_DEFAULT, .out = stdout };
    int rc = bj_join (list, &o);
    free (o.ofmt);
    return rc;
}

char *join_doc[] = {
    "Relational join on two sorted files (POSIX join).",
    "",
    "    join [-i] [-1 N] [-2 N] [-t SEP] [-a 1|2] [-v 1|2] [-e EMPTY]",
    "             [-o FORMAT] [--help|--version] FILE1 FILE2",
    "",
    "    -i, --ignore-case  ignore case when comparing join fields",
    "    -1 N        join field for FILE1 (1-based, default 1)",
    "    -2 N        join field for FILE2 (1-based, default 1)",
    "    -j N        equivalent to -1 N -2 N",
    "    -t SEP      single-byte field separator (default: whitespace)",
    "    -a 1|2      also print unmatched lines from FILE1 / FILE2",
    "    -v 1|2      only print unmatched lines from FILE1 / FILE2",
    "    -e EMPTY    fill missing or empty output fields with EMPTY",
    "    -o FORMAT   comma-separated FILENUM.FIELDNUM list (or 0 = key);",
    "                -o auto infers a fixed layout from the first records",
    "    --header    treat the first line of each file as field headers",
    "    --check-order    fail at the first line that is out of order",
    "    --nocheck-order  do not check that input is correctly sorted",
    "    --help      display this help and exit",
    "    --version   display version information and exit",
    "",
    "Both files must be pre-sorted on the join key (LC_COLLATE=C). By default",
    "a file found out of order once an unpairable line has been seen is",
    "reported, and join then exits with status 1.",
    "Use `-` for FILE1 or FILE2 to read stdin.",
    (char *)NULL
};

struct builtin join_struct = {
    "join",
    join_builtin,
    BUILTIN_ENABLED,
    join_doc,
    "join [-i] [-1 N] [-2 N] [-j N] [-t SEP] [-a 1|2] [-v 1|2] [-e EMPTY] [-o FORMAT] [--help|--version] FILE1 FILE2",
    0
};
