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
 *   -e STR       replace empty fields in -o output with STR
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
#include <strings.h>
#include <errno.h>
#include <ctype.h>

#include "loadables.h"

#define BJ_MAX_FIELDS 64
#define BJ_MAX_OFMT   64

typedef struct {
    int   field1;       /* 1-based */
    int   field2;
    int   sep;          /* 0 = whitespace; else byte */
    int   show_unmatched_1;
    int   show_unmatched_2;
    int   only_unmatched;
    int   ignore_case;
    int   header;       /* --header: pass first line through as headers */
    int   nocheck;      /* --nocheck-order: suppress input-order check */
    int   auto_fmt;     /* -o auto: infer field count from first records */
    const char *empty;
    /* Output format: array of (filenum, fieldnum). filenum 0 = key. */
    int   ofmt[BJ_MAX_OFMT][2];
    int   n_ofmt;
} bj_opts;

extern char *join_doc[];

static void
bj_print_help (void)
{
    for (char **p = join_doc; *p; p++)
        puts (*p);
}

typedef struct {
    char *line;
    size_t cap;
    char *fields[BJ_MAX_FIELDS];
    int   nf;
    /* Owned storage for the split — `fields` point into a copy. */
    char *split_buf;
    size_t split_len;
} bj_record;

static void
bj_free_rec (bj_record *r)
{
    free (r->line);
    free (r->split_buf);
    r->line = NULL;
    r->split_buf = NULL;
    r->cap = r->split_len = 0;
}

typedef struct {
    bj_record *v;
    size_t n;
    size_t cap;
} bj_group;

static void
bj_free_group (bj_group *g)
{
    for (size_t i = 0; i < g->n; i++)
        bj_free_rec (&g->v[i]);
    free (g->v);
    g->v = NULL;
    g->n = g->cap = 0;
}

/* Split LINE into FIELDS using SEP (0 = whitespace runs). Mutates a
   newly-malloc'd copy. Returns the number of fields. */
static int
bj_split (bj_record *r, const char *line, size_t llen, int sep)
{
    /* Strip trailing newline. */
    while (llen > 0 && (line[llen - 1] == '\n' || line[llen - 1] == '\r')) llen--;
    char *raw = malloc (llen + 1);
    char *buf = malloc (llen + 1);
    if (!raw || !buf) {
        free (raw);
        free (buf);
        return 0;
    }
    memcpy (raw, line, llen);
    raw[llen] = '\0';
    memcpy (buf, line, llen);
    buf[llen] = '\0';
    free (r->line);
    free (r->split_buf);
    r->line = raw;
    r->cap = llen + 1;
    r->split_buf = buf;
    r->split_len = llen;
    r->nf = 0;
    if (sep == 0) {
        /* Whitespace runs. POSIX: leading whitespace doesn't form an
           empty field; collapsed runs separate fields. */
        char *p = buf;
        while (*p && r->nf < BJ_MAX_FIELDS) {
            while (*p == ' ' || *p == '\t') p++;
            if (!*p) break;
            r->fields[r->nf++] = p;
            while (*p && *p != ' ' && *p != '\t') p++;
            if (*p) *p++ = '\0';
        }
    } else {
        /* Single-char split: empty fields preserved. */
        char *p = buf;
        r->fields[r->nf++] = p;
        while (*p && r->nf < BJ_MAX_FIELDS) {
            if (*p == sep) {
                *p = '\0';
                r->fields[r->nf++] = p + 1;
            }
            p++;
        }
    }
    return r->nf;
}

static int
bj_group_add (bj_group *g, const bj_record *src, int sep)
{
    if (g->n == g->cap) {
        size_t ncap = g->cap ? g->cap * 2 : 4;
        bj_record *nv = realloc (g->v, ncap * sizeof (*nv));
        if (!nv) return -1;
        memset (nv + g->cap, 0, (ncap - g->cap) * sizeof (*nv));
        g->v = nv;
        g->cap = ncap;
    }
    bj_record *dst = &g->v[g->n];
    memset (dst, 0, sizeof (*dst));
    bj_split (dst, src->line ? src->line : "", src->split_len, sep);
    g->n++;
    return 0;
}

static const char *
bj_field (const bj_record *r, int n1based)
{
    if (!r) return "";
    if (n1based < 1 || n1based > r->nf) return "";
    return r->fields[n1based - 1];
}

static void
bj_emit_outsep (int sep)
{
    if (sep == 0) putchar (' ');
    else          putchar ((char) sep);
}

/* Default join layout: KEY <sep> rest-of-FILE1 <sep> rest-of-FILE2. */
static void
bj_emit_default (const bj_opts *o, const bj_record *r1, const bj_record *r2)
{
    const bj_record *key_rec = r1 ? r1 : r2;
    int key_field = r1 ? o->field1 : o->field2;
    const char *key = bj_field (key_rec, key_field);
    fputs (key && *key ? key : (o->empty ? o->empty : ""), stdout);
    if (r1) {
        for (int i = 1; i <= r1->nf; i++) {
            if (i == o->field1) continue;
            bj_emit_outsep (o->sep);
            const char *v = bj_field (r1, i);
            fputs (v && *v ? v : (o->empty ? o->empty : ""), stdout);
        }
    }
    if (r2) {
        for (int i = 1; i <= r2->nf; i++) {
            if (i == o->field2) continue;
            bj_emit_outsep (o->sep);
            const char *v = bj_field (r2, i);
            fputs (v && *v ? v : (o->empty ? o->empty : ""), stdout);
        }
    }
    putchar ('\n');
}

static void
bj_emit_format (const bj_opts *o, const bj_record *r1, const bj_record *r2)
{
    for (int i = 0; i < o->n_ofmt; i++) {
        if (i) bj_emit_outsep (o->sep);
        int filenum = o->ofmt[i][0];
        int fnum    = o->ofmt[i][1];
        const char *v;
        if (filenum == 0) v = bj_field (r1 ? r1 : r2, filenum == 0 ? (r1 ? o->field1 : o->field2) : 0);
        else if (filenum == 1) v = r1 ? bj_field (r1, fnum) : "";
        else                    v = r2 ? bj_field (r2, fnum) : "";
        fputs (v && *v ? v : (o->empty ? o->empty : ""), stdout);
    }
    putchar ('\n');
}

static void
bj_emit (const bj_opts *o, const bj_record *r1, const bj_record *r2)
{
    if (o->n_ofmt > 0) bj_emit_format (o, r1, r2);
    else               bj_emit_default (o, r1, r2);
}

/* Capture a stdout write failure before a later read overwrites errno. */
static int
bj_out_err (int *err)
{
    if (*err)
        return 1;
    if (ferror (stdout)) {
        *err = errno ? errno : EIO;
        return 1;
    }
    return 0;
}

static int
bj_parse_ofmt (bj_opts *o, const char *s)
{
    /* Comma-separated FILENUM.FIELDNUM pairs (or `0`). */
    while (*s && o->n_ofmt < BJ_MAX_OFMT) {
        while (*s == ',' || *s == ' ') s++;
        if (!*s) break;
        if (s[0] == '0' && (s[1] == ',' || s[1] == ' ' || s[1] == '\0')) {
            o->ofmt[o->n_ofmt][0] = 0;
            o->ofmt[o->n_ofmt][1] = 0;
            o->n_ofmt++;
            s++;
            continue;
        }
        if (s[0] != '1' && s[0] != '2') return -1;
        if (s[1] != '.') return -1;
        char *end;
        long n = strtol (s + 2, &end, 10);
        if (end == s + 2 || n < 1) return -1;
        o->ofmt[o->n_ofmt][0] = s[0] - '0';
        o->ofmt[o->n_ofmt][1] = (int) n;
        o->n_ofmt++;
        s = end;
    }
    return 0;
}

static int
bj_keycmp (const char *a, const char *b, const bj_opts *o)
{
    return o->ignore_case ? strcasecmp (a, b) : strcmp (a, b);
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

int
join_builtin (WORD_LIST *list)
{
    bj_opts o = { .field1 = 1, .field2 = 1 };

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
            o.ignore_case = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--header")) {
            o.header = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--nocheck-order")) {
            o.nocheck = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--check-order")) {
            o.nocheck = 0;
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
                o.ignore_case = 1;
                list = list->next;
                continue;
            case '1': case '2': case 'j': {
                arg = bj_optarg (&list, attached);
                if (!arg) { builtin_error ("-%c needs N", flag); builtin_usage (); return EX_USAGE; }
                char *end;
                long fld = strtol (arg, &end, 10);
                if (*end || fld < 1) { builtin_error ("invalid field number: %s", arg); builtin_usage (); return EX_USAGE; }
                if (flag == '1' || flag == 'j') o.field1 = (int) fld;
                if (flag == '2' || flag == 'j') o.field2 = (int) fld;
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
                o.sep = (unsigned char) arg[0];
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
                if (arg[0] == '1') o.show_unmatched_1 = 1;
                else               o.show_unmatched_2 = 1;
                if (flag == 'v') o.only_unmatched = 1;
                list = list->next;
                continue;
            }
            case 'e': {
                arg = bj_optarg (&list, attached);
                if (!arg) { builtin_error ("-e needs STR"); builtin_usage (); return EX_USAGE; }
                o.empty = arg;
                list = list->next;
                continue;
            }
            case 'o': {
                arg = bj_optarg (&list, attached);
                if (!arg) { builtin_error ("-o needs FORMAT"); builtin_usage (); return EX_USAGE; }
                if (!strcmp (arg, "auto")) {
                    o.auto_fmt = 1;
                    list = list->next;
                    continue;
                }
                if (bj_parse_ofmt (&o, arg) < 0) {
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
    FILE *fa = !strcmp (p1, "-") ? stdin : fopen (p1, "r");
    if (!fa) { builtin_error ("%s: %s", p1, strerror (errno)); return EXECUTION_FAILURE; }
    FILE *fb = !strcmp (p2, "-") ? stdin : fopen (p2, "r");
    if (!fb) {
        if (fa != stdin) fclose (fa);
        builtin_error ("%s: %s", p2, strerror (errno));
        return EXECUTION_FAILURE;
    }

    bj_record ra = { 0 }, rb = { 0 };
    char *la = NULL, *lb = NULL;
    size_t ca = 0, cb = 0;
    int out_err = 0;
    int rc = EXECUTION_SUCCESS;
    ssize_t na = getline (&la, &ca, fa);
    ssize_t nb = getline (&lb, &cb, fb);
    if (na > 0) bj_split (&ra, la, (size_t) na, o.sep);
    if (nb > 0) bj_split (&rb, lb, (size_t) nb, o.sep);

    /* -o auto: infer a fixed output layout from the field counts of the
       first records — key, then every non-key field of FILE1, then every
       non-key field of FILE2. The count is fixed for the whole run; later
       lines with more fields are truncated, fewer are padded (with -e). */
    if (o.auto_fmt) {
        int n1 = (na != -1) ? ra.nf : 0;
        int n2 = (nb != -1) ? rb.nf : 0;
        o.n_ofmt = 0;
        o.ofmt[o.n_ofmt][0] = 0; o.ofmt[o.n_ofmt][1] = 0; o.n_ofmt++;
        for (int i = 1; i <= n1 && o.n_ofmt < BJ_MAX_OFMT; i++) {
            if (i == o.field1) continue;
            o.ofmt[o.n_ofmt][0] = 1; o.ofmt[o.n_ofmt][1] = i; o.n_ofmt++;
        }
        for (int i = 1; i <= n2 && o.n_ofmt < BJ_MAX_OFMT; i++) {
            if (i == o.field2) continue;
            o.ofmt[o.n_ofmt][0] = 2; o.ofmt[o.n_ofmt][1] = i; o.n_ofmt++;
        }
    }

    /* --header: pass the first line of each file through as a header line,
       joined as a (forced) matched pair regardless of key comparison, then
       continue normal processing from the second line. The header is not
       order-checked. */
    if (o.header && (na != -1 || nb != -1)) {
        bj_emit (&o, na != -1 ? &ra : NULL, nb != -1 ? &rb : NULL);
        if (!bj_out_err (&out_err)) {
            if (na != -1) {
                na = getline (&la, &ca, fa);
                if (na > 0) bj_split (&ra, la, (size_t) na, o.sep);
            }
            if (nb != -1) {
                nb = getline (&lb, &cb, fb);
                if (nb > 0) bj_split (&rb, lb, (size_t) nb, o.sep);
            }
        }
    }

    /* Do not read another record after stdout has failed: with the producer
       still open that read blocks, while GNU join has already exited. */
    while (!out_err && (na != -1 || nb != -1)) {
        const char *ka = na != -1 ? bj_field (&ra, o.field1) : NULL;
        const char *kb = nb != -1 ? bj_field (&rb, o.field2) : NULL;
        int cmp;
        if (na == -1)      cmp =  1;
        else if (nb == -1) cmp = -1;
        else               cmp = bj_keycmp (ka, kb, &o);
        if (cmp == 0) {
            char *key = strdup (ka);
            bj_group ga = { 0 }, gb = { 0 };
            int oom = key == NULL;

            while (!oom && na != -1 && bj_keycmp (bj_field (&ra, o.field1), key, &o) == 0) {
                if (bj_group_add (&ga, &ra, o.sep) < 0) { oom = 1; break; }
                na = getline (&la, &ca, fa);
                if (na > 0) bj_split (&ra, la, (size_t) na, o.sep);
            }
            while (!oom && nb != -1 && bj_keycmp (bj_field (&rb, o.field2), key, &o) == 0) {
                if (bj_group_add (&gb, &rb, o.sep) < 0) { oom = 1; break; }
                nb = getline (&lb, &cb, fb);
                if (nb > 0) bj_split (&rb, lb, (size_t) nb, o.sep);
            }

            if (oom) {
                free (key);
                bj_free_group (&ga);
                bj_free_group (&gb);
                builtin_error ("out of memory");
                rc = EXECUTION_FAILURE;
                goto done;
            }

            if (!o.only_unmatched)
                for (size_t i = 0; i < ga.n && !bj_out_err (&out_err); i++)
                    for (size_t j = 0; j < gb.n && !bj_out_err (&out_err); j++) {
                        bj_emit (&o, &ga.v[i], &gb.v[j]);
                        bj_out_err (&out_err);
                    }
            free (key);
            bj_free_group (&ga);
            bj_free_group (&gb);
        } else if (cmp < 0) {
            if (o.show_unmatched_1 && na != -1) {
                bj_emit (&o, &ra, NULL);
                if (bj_out_err (&out_err))
                    break;
            }
            na = getline (&la, &ca, fa);
            if (na > 0) bj_split (&ra, la, (size_t) na, o.sep);
        } else {
            if (o.show_unmatched_2 && nb != -1) {
                bj_emit (&o, NULL, &rb);
                if (bj_out_err (&out_err))
                    break;
            }
            nb = getline (&lb, &cb, fb);
            if (nb > 0) bj_split (&rb, lb, (size_t) nb, o.sep);
        }
    }

done:
    bj_free_rec (&ra); bj_free_rec (&rb);
    free (la); free (lb);
    if (fa != stdin) fclose (fa);
    if (fb != stdin) fclose (fb);
    if (!out_err && (fflush (stdout) == EOF || ferror (stdout)))
        out_err = errno ? errno : EIO;
    if (out_err) {
        builtin_error ("write error: %s", strerror (out_err));
        return EXECUTION_FAILURE;
    }
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
    "    -e EMPTY    fill empty fields in -o output with EMPTY",
    "    -o FORMAT   comma-separated FILENUM.FIELDNUM list (or 0 = key);",
    "                -o auto infers a fixed layout from the first records",
    "    --header    treat the first line of each file as field headers",
    "    --nocheck-order  do not check that input is correctly sorted",
    "    --help      display this help and exit",
    "    --version   display version information and exit",
    "",
    "Both files must be pre-sorted on the join key (LC_COLLATE=C).",
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
