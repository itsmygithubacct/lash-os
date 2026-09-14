/* bashcomm.c — POSIX comm(1) as a bash builtin.
 *
 * Closes the POSIX gap noted in POSIX-CONFORMANCE-RESEARCH.md §4.1.
 * Compares two sorted files line-by-line and emits three columns:
 *   col 1 — lines unique to FILE1
 *   col 2 — lines unique to FILE2
 *   col 3 — lines common to both
 *
 *   bashcomm [-1] [-2] [-3] [--check-order] [--nocheck-order]
 *            [-z|--zero-terminated] [--total] [--output-delimiter=STR] FILE1 FILE2
 *
 * -1 / -2 / -3 suppress the corresponding column. Both files must
 * already be byte-sorted (LC_COLLATE=C); we don't sort internally —
 * matching POSIX. `-` for FILE1 or FILE2 means stdin.
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

#include "loadables.h"

struct bc_line {
    char *buf;
    size_t cap;
    ssize_t len;
};

extern char *comm_doc[];

static void
bc_print_help (void)
{
    for (char **p = comm_doc; *p; p++)
        puts (*p);
}

static ssize_t
bc_read_record (struct bc_line *line, FILE *f, int delim)
{
    line->len = getdelim (&line->buf, &line->cap, delim, f);
    return line->len;
}

/* Output is buffered so 15k short fwrite calls are not 15k libc trips.
   /dev/full still fails: a flush writes through to stdout. */
struct bc_obuf {
    char buf[65536];
    size_t n;
    int *err;
};

static void
bc_ob_flush (struct bc_obuf *o)
{
    if (*o->err || o->n == 0)
        return;
    if (fwrite (o->buf, 1, o->n, stdout) != o->n || ferror (stdout))
        *o->err = errno ? errno : EIO;
    o->n = 0;
}

static void
bc_ob_put (struct bc_obuf *o, const char *p, size_t n)
{
    if (*o->err)
        return;
    while (n) {
        if (o->n == sizeof o->buf)
            bc_ob_flush (o);
        if (*o->err)
            return;
        size_t room = sizeof o->buf - o->n;
        size_t k = n < room ? n : room;
        memcpy (o->buf + o->n, p, k);
        o->n += k;
        p += k;
        n -= k;
    }
}

static void
bc_write_sep (struct bc_obuf *o, const char *sep)
{
    if (sep[0] == '\0')
        bc_ob_put (o, "\0", 1);
    else
        bc_ob_put (o, sep, strlen (sep));
}

/* Write a line record, guaranteeing a trailing line delimiter. getdelim()
   does not synthesize one for a final line that lacks it, but GNU comm
   normalizes every output record to end with the delimiter (its
   readlinebuffer appends one at read time). Without this, a file whose last
   line has no newline makes the next column's content run onto the same
   line. */
static void
bc_write_record (struct bc_obuf *o, const char *buf, size_t len, int delim)
{
    bc_ob_put (o, buf, len);
    if (len == 0 || (unsigned char) buf[len - 1] != (unsigned char) delim) {
        char d = (char) delim;
        bc_ob_put (o, &d, 1);
    }
}

static void
bc_prefix (struct bc_obuf *o, int column, int suppress[3], const char *sep)
{
    for (int i = 0; i < column - 1; i++)
        if (!suppress[i])
            bc_write_sep (o, sep);
}

enum bc_order_mode {
    BC_ORDER_DEFAULT,
    BC_ORDER_CHECK,
    BC_ORDER_NOCHECK
};

static int
bc_linecmp (const struct bc_line *a, const struct bc_line *b, int delim)
{
    size_t alen = a->len < 0 ? 0 : (size_t)a->len;
    size_t blen = b->len < 0 ? 0 : (size_t)b->len;
    if (alen && (unsigned char)a->buf[alen - 1] == (unsigned char)delim) alen--;
    if (blen && (unsigned char)b->buf[blen - 1] == (unsigned char)delim) blen--;

    size_t n = alen < blen ? alen : blen;
    int cmp = memcmp (a->buf, b->buf, n);
    if (cmp) return cmp;
    return (alen > blen) - (alen < blen);
}

static int
bc_check_order (const struct bc_line *prev, const struct bc_line *cur,
                int file_no, int delim,
                enum bc_order_mode mode, int seen_unpairable,
                int issued[2], int *disorder)
{
    if (prev->len < 0 || mode == BC_ORDER_NOCHECK)
        return EXECUTION_SUCCESS;
    if (bc_linecmp (prev, cur, delim) <= 0)
        return EXECUTION_SUCCESS;
    if (mode == BC_ORDER_DEFAULT && !seen_unpairable)
        return EXECUTION_SUCCESS;
    if (!issued[file_no - 1]) {
        builtin_error ("file %d is not in sorted order", file_no);
        issued[file_no - 1] = 1;
    }
    *disorder = 1;
    return mode == BC_ORDER_CHECK ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static void
bc_swap_line (struct bc_line *a, struct bc_line *b)
{
    struct bc_line tmp = *a;
    *a = *b;
    *b = tmp;
}

static int
bc_advance (FILE *f, struct bc_line *line, struct bc_line *prev, int file_no,
            int delim, enum bc_order_mode mode, int seen_unpairable,
            int issued[2], int *disorder)
{
    /* Keep the previous record by swapping reusable getdelim buffers.
       Copying every line allocated ~15k blocks on the published fixture. */
    bc_swap_line (prev, line);

    ssize_t n = bc_read_record (line, f, delim);
    if (n == -1)
        return EXECUTION_SUCCESS;
    return bc_check_order (prev, line, file_no, delim, mode, seen_unpairable,
                           issued, disorder);
}

static int
bc_run (FILE *fa, FILE *fb, int suppress[3], int total_option,
        const char *sep, int delim, enum bc_order_mode order_mode)
{
    struct bc_line la = {0}, lb = {0}, prev_a = {0}, prev_b = {0};
    prev_a.len = prev_b.len = -1;
    ssize_t na = bc_read_record (&la, fa, delim);
    ssize_t nb = bc_read_record (&lb, fb, delim);
    unsigned long total[3] = {0, 0, 0};
    int issued[2] = {0, 0};
    int disorder = 0;
    int seen_unpairable = 0;
    int out_err = 0;
    struct bc_obuf ob = { .n = 0, .err = &out_err };
    /* POSIX column prefixes: col 1 = no tab, col 2 = 1 tab, col 3 = 2 tabs. */
    while (!out_err && (na != -1 || nb != -1)) {
        int cmp;
        if (na == -1)      cmp =  1;
        else if (nb == -1) cmp = -1;
        else               cmp = bc_linecmp (&la, &lb, delim);
        if (cmp < 0) {
            seen_unpairable = 1;
            total[0]++;
            if (!suppress[0])
                bc_write_record (&ob, la.buf, (size_t)la.len, delim);
            if (out_err)
                break;
            if (bc_advance (fa, &la, &prev_a, 1, delim, order_mode,
                            seen_unpairable, issued, &disorder) != EXECUTION_SUCCESS)
                goto fail;
            na = la.len;
        } else if (cmp > 0) {
            seen_unpairable = 1;
            total[1]++;
            if (!suppress[1]) {
                bc_prefix (&ob, 2, suppress, sep);
                bc_write_record (&ob, lb.buf, (size_t)lb.len, delim);
            }
            if (out_err)
                break;
            if (bc_advance (fb, &lb, &prev_b, 2, delim, order_mode,
                            seen_unpairable, issued, &disorder) != EXECUTION_SUCCESS)
                goto fail;
            nb = lb.len;
        } else {
            total[2]++;
            if (!suppress[2]) {
                bc_prefix (&ob, 3, suppress, sep);
                bc_write_record (&ob, la.buf, (size_t)la.len, delim);
            }
            if (out_err)
                break;
            if (bc_advance (fa, &la, &prev_a, 1, delim, order_mode,
                            seen_unpairable, issued, &disorder) != EXECUTION_SUCCESS)
                goto fail;
            na = la.len;
            if (bc_advance (fb, &lb, &prev_b, 2, delim, order_mode,
                            seen_unpairable, issued, &disorder) != EXECUTION_SUCCESS)
                goto fail;
            nb = lb.len;
        }
    }
    if (!out_err && total_option) {
        char tmp[32];
        int n;
        n = snprintf (tmp, sizeof tmp, "%lu", total[0]);
        if (n > 0) bc_ob_put (&ob, tmp, (size_t) n);
        bc_write_sep (&ob, sep);
        n = snprintf (tmp, sizeof tmp, "%lu", total[1]);
        if (n > 0) bc_ob_put (&ob, tmp, (size_t) n);
        bc_write_sep (&ob, sep);
        n = snprintf (tmp, sizeof tmp, "%lu", total[2]);
        if (n > 0) bc_ob_put (&ob, tmp, (size_t) n);
        bc_write_sep (&ob, sep);
        bc_ob_put (&ob, "total", 5);
        { char d = (char) delim; bc_ob_put (&ob, &d, 1); }
    }
    bc_ob_flush (&ob);
    if (!out_err && (fflush (stdout) == EOF || ferror (stdout)))
        out_err = errno ? errno : EIO;
    /* GNU comm: after a default-mode (warning) disorder, emit a final
       "input is not in sorted order" diagnostic before failing. In
       --check-order mode the run already short-circuited via `goto fail`,
       so this only fires for the warn-then-continue default path. */
    if (out_err)
        builtin_error ("write error: %s", strerror (out_err));
    else if (disorder)
        builtin_error ("input is not in sorted order");
    free (la.buf); free (lb.buf); free (prev_a.buf); free (prev_b.buf);
    return (out_err || disorder) ? EXECUTION_FAILURE : EXECUTION_SUCCESS;

fail:
    bc_ob_flush (&ob);
    free (la.buf); free (lb.buf); free (prev_a.buf); free (prev_b.buf);
    return EXECUTION_FAILURE;
}

int
comm_builtin (WORD_LIST *list)
{
    int suppress[3] = {0, 0, 0};
    int total_option = 0;
    const char *sep = "\t";
    int sep_set = 0;       /* tracks an explicit --output-delimiter */
    int delim = '\n';
    enum bc_order_mode order_mode = BC_ORDER_DEFAULT;
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--help")) { bc_print_help (); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "--version")) {
            puts ("bashcomm 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--check-order")) { order_mode = BC_ORDER_CHECK; list = list->next; continue; }
        if (!strcmp (w, "--nocheck-order")) { order_mode = BC_ORDER_NOCHECK; list = list->next; continue; }
        if (!strcmp (w, "--zero-terminated")) { delim = '\0'; list = list->next; continue; }
        if (!strcmp (w, "--total")) { total_option = 1; list = list->next; continue; }
        if (!strncmp (w, "--output-delimiter=", 19)) {
            const char *newsep = w + 19;
            /* GNU comm: a repeated --output-delimiter with a *different*
               value is fatal; the same value again is idempotent. */
            if (sep_set && strcmp (sep, newsep)) {
                builtin_error ("multiple output delimiters specified");
                return EXECUTION_FAILURE;
            }
            sep = newsep;
            sep_set = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--output-delimiter")) {
            if (!list->next) {
                builtin_error ("--output-delimiter needs an argument");
                builtin_usage ();
                return EX_USAGE;
            }
            const char *newsep = list->next->word->word;
            if (sep_set && strcmp (sep, newsep)) {
                builtin_error ("multiple output delimiters specified");
                return EXECUTION_FAILURE;
            }
            sep = newsep;
            sep_set = 1;
            list = list->next->next;
            continue;
        }
        if (!strcmp (w, "--")) { list = list->next; break; }
        /* Reject long-option-style --foo as unknown flag. */
        if (w[1] == '-' && w[2] != '\0') {
            builtin_error ("unknown flag: %s", w);
            builtin_usage ();
            return EX_USAGE;
        }
        for (const char *c = w + 1; *c; c++) {
            switch (*c) {
                case '1': suppress[0] = 1; break;
                case '2': suppress[1] = 1; break;
                case '3': suppress[2] = 1; break;
                case 'z': delim = '\0'; break;
                default:
                    builtin_error ("unknown flag: -%c", *c);
                    builtin_usage ();
                    return EX_USAGE;
            }
        }
        list = list->next;
    }
    /* Operand-count diagnostics mirror GNU comm's wording. */
    if (!list) {
        builtin_error ("missing operand");
        builtin_usage ();
        return EX_USAGE;
    }
    if (!list->next) {
        builtin_error ("missing operand after '%s'", list->word->word);
        builtin_usage ();
        return EX_USAGE;
    }
    if (list->next->next) {
        builtin_error ("extra operand '%s'", list->next->next->word->word);
        builtin_usage ();
        return EX_USAGE;
    }
    const char *p1 = list->word->word;
    const char *p2 = list->next->word->word;
    if (!strcmp (p1, "-") && !strcmp (p2, "-")) {
        builtin_error ("standard input is listed more than once");
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
    if (fa != stdin)
        setvbuf (fa, NULL, _IOFBF, 65536);
    if (fb != stdin)
        setvbuf (fb, NULL, _IOFBF, 65536);
    int rc = bc_run (fa, fb, suppress, total_option, sep, delim, order_mode);
    if (fa != stdin) fclose (fa);
    if (fb != stdin) fclose (fb);
    return rc;
}

char *comm_doc[] = {
    "Compare two sorted files line by line.",
    "",
    "    bashcomm [-1] [-2] [-3] [--check-order] [--nocheck-order]",
    "             [-z|--zero-terminated] [--total] [--output-delimiter=STR]",
    "             [--help|--version] FILE1 FILE2",
    "",
    "Output is three tab-separated columns:",
    "    col 1: lines unique to FILE1",
    "    col 2: lines unique to FILE2",
    "    col 3: lines common to both",
    "",
    "    -1   suppress column 1",
    "    -2   suppress column 2",
    "    -3   suppress column 3",
    "    --check-order    fail if either input is not sorted",
    "    --nocheck-order  do not diagnose unsorted input",
    "    -z, --zero-terminated  line delimiter is NUL, not newline",
    "    --total  output a final count summary line",
    "    --output-delimiter=STR  separate columns with STR instead of TAB",
    "    --help     display this help and exit",
    "    --version  display version information and exit",
    "",
    "Both files MUST be sorted byte-wise (LC_COLLATE=C). Use `-` for",
    "either file to read stdin. POSIX-shape: no -i extension.",
    (char *)NULL
};

struct builtin bashcomm_struct = {
    "bashcomm",
    comm_builtin,
    BUILTIN_ENABLED,
    comm_doc,
    "bashcomm [-1] [-2] [-3] [--check-order] [--nocheck-order] [-z|--zero-terminated] [--total] [--output-delimiter=STR] [--help|--version] FILE1 FILE2",
    0
};
