/* bashdiff.c — POSIX diff(1) as a bash builtin (Myers O(ND)).
 *
 * Phase T of bash-os POSIX gap-fillers.
 *
 *   bashdiff [-u] [-q] [-i] [--help|--version] FILE1 FILE2
 *
 *   -u   unified diff (with @@ hunks + 3 lines context)
 *   -q   quiet: only report whether files differ (no content)
 *   -i   ignore case
 *
 * Default output is POSIX ed-style: 1c2 / 1a1 / 2d3 with `< old`,
 * `---`, `> new` markers.
 *
 * Exit codes: 0 (same), 1 (differ), 2 (error). Per POSIX.
 *
 * Algorithm: Myers' O(ND) line-level diff. V-trace memoization
 * for backtrack. Live frontier O(N+M), saved active diagonals O(D^2).
 * Worst-case time and trace memory remain quadratic for unrelated inputs.
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
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdarg.h>

#include "loadables.h"
#include "bl-output.h"

typedef struct { int uflag, qflag, iflag; } bd_opts;
typedef struct { const unsigned char *data; size_t len; } bd_line;

static int
bd_is_stdin (const char *path)
{
    return path && strcmp (path, "-") == 0;
}

/* Read PATH into a buffer. "-" uses the caller's stdin descriptor, which
   this loader never opens or closes. */
static int
bd_load (const char *path, unsigned char **data, size_t *len)
{
    int fd, owned = 0;
    if (bd_is_stdin (path)) {
        fd = STDIN_FILENO;
    } else {
        fd = open (path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            builtin_error ("%s: %s", path, strerror (errno));
            return -1;
        }
        owned = 1;
    }
    size_t cap = 4096, n = 0;
    unsigned char *buf = malloc (cap);
    if (!buf) {
        builtin_error ("%s: out of memory", path);
        if (owned) close (fd);
        return -1;
    }
    for (;;) {
        if (n == cap) {
            if (cap > (size_t) -1 / 2) {
                builtin_error ("%s: out of memory", path);
                free (buf);
                if (owned) close (fd);
                return -1;
            }
            size_t ncap = cap * 2;
            unsigned char *grown = realloc (buf, ncap);
            if (!grown) {
                builtin_error ("%s: out of memory", path);
                free (buf);
                if (owned) close (fd);
                return -1;
            }
            buf = grown;
            cap = ncap;
        }
        ssize_t r = read (fd, buf + n, cap - n);
        if (r < 0) {
            if (errno == EINTR) continue;
            builtin_error ("%s: %s", path, strerror (errno));
            free (buf);
            if (owned) close (fd);
            return -1;
        }
        if (r == 0) break;
        n += (size_t) r;
    }
    if (owned) close (fd);
    *data = buf;
    *len = n;
    return 0;
}

/* Match the usual binary probe; later NULs remain part of text records. */
static int
bd_probe_binary (const unsigned char *data, size_t len)
{
    return memchr (data, '\0', len < 4096 ? len : 4096) != NULL;
}

static int
bd_files_equal (const unsigned char *a, size_t la, const unsigned char *b, size_t lb)
{
    if (la != lb) return 0;
    if (la == 0) return 1;
    return memcmp (a, b, la) == 0;
}

/* Split a loaded buffer into line views without trailing newlines. The loaded
   bytes remain owned by the caller until all views have been consumed.
   Returns NULL on error. *n_out gets line count. */
static bd_line *
bd_slurp (const unsigned char *data, size_t len, const char *path,
          int *n_out, int *no_newline)
{
    size_t cap = 256;
    bd_line *lines = malloc (cap * sizeof (*lines));
    if (!lines) {
        builtin_error ("%s: out of memory", path);
        *n_out = 0; *no_newline = 0;
        return NULL;
    }
    int n = 0;
    int last_had_nl = 0;
    size_t i = 0;
    while (i < len) {
        if (n == INT_MAX) {
            builtin_error ("%s: too many lines", path);
            goto fail;
        }
        size_t start = i;
        const unsigned char *end = memchr (data + i, '\n', len - i);
        i = end ? (size_t) (end - data) : len;
        int had_nl = (i < len && data[i] == '\n');
        size_t llen = i - start;
        if ((size_t) n >= cap) {
            if (cap > SIZE_MAX / 2 / sizeof (*lines)) {
                builtin_error ("%s: too many lines", path);
                goto fail;
            }
            bd_line *grown = realloc (lines, cap * 2 * sizeof (*lines));
            if (!grown) {
                builtin_error ("%s: out of memory", path);
                free (lines);
                *n_out = 0; *no_newline = 0;
                return NULL;
            }
            lines = grown; cap *= 2;
        }
        lines[n++] = (bd_line) { data + start, llen };
        last_had_nl = had_nl;
        if (had_nl) i++;
    }
    *n_out = n;
    *no_newline = (n > 0 && !last_had_nl);
    return lines;
fail:
    free (lines);
    *n_out = 0; *no_newline = 0;
    return NULL;
}

static int
bd_lineq (const bd_line *a, const bd_line *b, int icase)
{
    if (a->len != b->len) return 0;
    if (!icase) return memcmp (a->data, b->data, a->len) == 0;
    for (size_t i = 0; i < a->len; i++)
        if (tolower (a->data[i]) != tolower (b->data[i])) return 0;
    return 1;
}

static void
bd_text (bl_output *out, const char *text)
{
    bl_output_write (out, text, strlen (text));
}

/* Only fixed internal formats and numeric addresses use this small buffer.
   Unbounded filenames and line contents go through length-bearing writes. */
static void
bd_format (bl_output *out, const char *format, ...)
{
    char buffer[128];
    va_list args;
    va_start (args, format);
    int n = vsnprintf (buffer, sizeof buffer, format, args);
    va_end (args);
    if (n < 0 || (size_t) n >= sizeof buffer) {
        if (!out->error) out->error = EOVERFLOW;
        return;
    }
    bl_output_write (out, buffer, (size_t) n);
}

static void
bd_print_line (bl_output *out, const char *prefix, const bd_line *line)
{
    bd_text (out, prefix);
    bl_output_write (out, line->data, line->len);
    bl_output_byte (out, '\n');
}

typedef enum { BDOP_EQ, BDOP_DEL, BDOP_INS } bd_optype;
typedef struct { bd_optype op; int la; int lb; } bd_op;

/* Myers O(ND) — build edit-script ops. Returns op array (heap), sets *n_ops.
   Only d+1 diagonals of parity d are reachable at depth d. Save those rather
   than 2*(n+m)+1 cells per row. This reduces sparse-edit storage and copying;
   it does not remove quadratic worst-case time or trace memory. */
static int
bd_trace_x (const int *row, int d, int k)
{
    return row[(k + d) / 2];
}
static bd_op *
bd_myers (bd_line *A, int n, bd_line *B, int m, int icase,
          int no_newline_a, int no_newline_b, int *n_ops_out)
{
    *n_ops_out = -1;
    /* Both the diagonal index arithmetic and allocation products must fit. */
    if (n > (INT_MAX - 1) / 2 - m) {
        builtin_error ("too many lines to compare");
        return NULL;
    }
    int max = n + m;
    if (max == 0) { *n_ops_out = 0; return NULL; }
    int v_size = 2 * max + 1;
    if ((size_t) v_size > SIZE_MAX / sizeof (int) ||
        (size_t) (max + 1) > SIZE_MAX / sizeof (int *) ||
        (size_t) max > SIZE_MAX / sizeof (bd_op)) {
        builtin_error ("too many lines to compare");
        return NULL;
    }
    /* With an empty operand the only script is known; no search or saved
       frontier is needed, regardless of the amount of output. */
    if (n == 0 || m == 0) {
        bd_op *only = malloc ((size_t) max * sizeof (*only));
        if (!only) {
            builtin_error ("out of memory comparing files");
            return NULL;
        }
        for (int i = 0; i < max; i++)
            only[i] = n ? (bd_op) { BDOP_DEL, i, -1 } :
                          (bd_op) { BDOP_INS, -1, i };
        *n_ops_out = max;
        return only;
    }
    int *v = calloc ((size_t) v_size, sizeof (int));
    int **trace = calloc ((size_t) (max + 1), sizeof (int *));
    int d_done = -1;
    int rows = 0;
    bd_op *ops = NULL;
    if (!v || !trace) goto nomem;

    for (int d = 0; d <= max; d++) {
        trace[d] = malloc ((size_t) (d + 1) * sizeof (int));
        if (!trace[d]) goto nomem;
        rows++;
        for (int k = -d; k <= d; k += 2) {
            int x;
            if (k == -d || (k != d && v[k - 1 + max] < v[k + 1 + max]))
                x = v[k + 1 + max];          /* insertion */
            else
                x = v[k - 1 + max] + 1;      /* deletion */
            int y = x - k;
            while (x < n && y < m && bd_lineq (&A[x], &B[y], icase) &&
                   (x == n - 1 && no_newline_a) == (y == m - 1 && no_newline_b)) {
                x++; y++;
            }
            v[k + max] = x;
            if (x >= n && y >= m) { d_done = d; break; }
        }
        for (int k = -d; k <= d; k += 2)
            trace[d][(k + d) / 2] = v[k + max];
        if (d_done >= 0) break;
    }
    free (v);
    v = NULL;

    /* Backtrack: produce ops in reverse, then reverse. */
    /* Every operation consumes at least one input line. */
    ops = malloc ((size_t) max * sizeof (bd_op));
    if (!ops) goto nomem;
    int n_ops = 0;
    int x = n, y = m;
    for (int d = d_done; d > 0; d--) {
        int *vd = trace[d - 1];
        int k = x - y;
        int prev_k;
        if (k == -d || (k != d && bd_trace_x (vd, d - 1, k - 1) <
                                             bd_trace_x (vd, d - 1, k + 1)))
            prev_k = k + 1;
        else
            prev_k = k - 1;
        int prev_x = bd_trace_x (vd, d - 1, prev_k);
        int prev_y = prev_x - prev_k;
        /* Snake before the move (matches). */
        while (x > prev_x && y > prev_y) {
            ops[n_ops++] = (bd_op){ BDOP_EQ, x - 1, y - 1 };
            x--; y--;
        }
        if (x == prev_x) {
            ops[n_ops++] = (bd_op){ BDOP_INS, -1, y - 1 };
            y--;
        } else {
            ops[n_ops++] = (bd_op){ BDOP_DEL, x - 1, -1 };
            x--;
        }
    }
    while (x > 0 && y > 0) {
        ops[n_ops++] = (bd_op){ BDOP_EQ, x - 1, y - 1 };
        x--; y--;
    }
    /* Trim leftover (shouldn't happen but be safe). */
    while (x > 0) { ops[n_ops++] = (bd_op){ BDOP_DEL, x - 1, -1 }; x--; }
    while (y > 0) { ops[n_ops++] = (bd_op){ BDOP_INS, -1, y - 1 }; y--; }

    /* Reverse ops to forward order. */
    for (int i = 0, j = n_ops - 1; i < j; i++, j--) {
        bd_op t = ops[i]; ops[i] = ops[j]; ops[j] = t;
    }

    /* Free trace. */
    for (int d = 0; d <= d_done; d++) free (trace[d]);
    free (trace);

    *n_ops_out = n_ops;
    return ops;
nomem:
    builtin_error ("out of memory comparing files");
    free (v);
    for (int d = 0; d < rows; d++) free (trace[d]);
    free (trace);
    free (ops);
    return NULL;
}

/* Emit POSIX ed-style diff. Group consecutive ins/del into change-blocks. */
static void
bd_emit_ed (bl_output *out, bd_line *A, int n, bd_line *B, int m, bd_op *ops, int n_ops,
            int no_newline_a, int no_newline_b)
{
    (void) n; (void) m;
    int i = 0;
    while (i < n_ops) {
        if (ops[i].op == BDOP_EQ) { i++; continue; }
        /* Start of a change block. Find run of DEL/INS. */
        int j = i;
        int del0 = -1, del1 = -1, ins0 = -1, ins1 = -1;
        while (j < n_ops && ops[j].op != BDOP_EQ) {
            if (ops[j].op == BDOP_DEL) {
                if (del0 < 0) del0 = ops[j].la;
                del1 = ops[j].la;
            } else { /* INS */
                if (ins0 < 0) ins0 = ops[j].lb;
                ins1 = ops[j].lb;
            }
            j++;
        }
        /* Format header: 1-indexed inclusive ranges. */
        char header[64];
        int nd = (del0 < 0) ? 0 : (del1 - del0 + 1);
        int ni = (ins0 < 0) ? 0 : (ins1 - ins0 + 1);
        if (nd > 0 && ni > 0) {
            /* change */
            if (nd == 1)
                snprintf (header, sizeof header, "%dc", del0 + 1);
            else
                snprintf (header, sizeof header, "%d,%dc", del0 + 1, del1 + 1);
            char tail[32];
            if (ni == 1)
                snprintf (tail, sizeof tail, "%d", ins0 + 1);
            else
                snprintf (tail, sizeof tail, "%d,%d", ins0 + 1, ins1 + 1);
            bd_format (out, "%s%s\n", header, tail);
            for (int k = del0; k <= del1; k++) bd_print_line (out, "< ", &A[k]);
            if (no_newline_a && del1 == n - 1) bd_format (out, "\\ No newline at end of file\n");
            bd_format (out, "---\n");
            for (int k = ins0; k <= ins1; k++) bd_print_line (out, "> ", &B[k]);
            if (no_newline_b && ins1 == m - 1) bd_format (out, "\\ No newline at end of file\n");
        } else if (nd > 0) {
            /* delete from A; ed addressing wants index AFTER which to delete */
            int after = i > 0 ? ops[i - 1].lb + 1 : 0;
            if (nd == 1)
                bd_format (out, "%dd%d\n", del0 + 1, after);
            else
                bd_format (out, "%d,%dd%d\n", del0 + 1, del1 + 1, after);
            for (int k = del0; k <= del1; k++) bd_print_line (out, "< ", &A[k]);
            if (no_newline_a && del1 == n - 1) bd_format (out, "\\ No newline at end of file\n");
        } else { /* INS only */
            int after = i > 0 ? ops[i - 1].la + 1 : 0;
            if (ni == 1)
                bd_format (out, "%da%d\n", after, ins0 + 1);
            else
                bd_format (out, "%da%d,%d\n", after, ins0 + 1, ins1 + 1);
            for (int k = ins0; k <= ins1; k++) bd_print_line (out, "> ", &B[k]);
            if (no_newline_b && ins1 == m - 1) bd_format (out, "\\ No newline at end of file\n");
        }
        i = j;
    }
}

/* Emit unified diff (-u). 3 lines context per hunk; fuse hunks within
   6 lines of each other. */
#define BD_CTX 3
static void
bd_emit_unified (bl_output *out, bd_line *A, int n, bd_line *B, int m, bd_op *ops, int n_ops,
                 const char *fname1, const char *fname2,
                 int no_newline_a, int no_newline_b)
{
    (void) m;
    if (n_ops == 0) return;
    /* Print file headers. */
    bd_text (out, "--- "); bd_text (out, fname1); bd_text (out, "\n");
    bd_text (out, "+++ "); bd_text (out, fname2); bd_text (out, "\n");

    /* Walk ops, group into hunks bounded by ≥ 2*BD_CTX equals. */
    int i = 0;
    while (i < n_ops) {
        /* Skip leading equals; remember last BD_CTX of them. */
        while (i < n_ops && ops[i].op == BDOP_EQ) i++;
        if (i >= n_ops) break;
        /* Backtrack BD_CTX equals for context. */
        int hunk_start = i;
        int back = 0;
        while (hunk_start > 0 && back < BD_CTX && ops[hunk_start - 1].op == BDOP_EQ) {
            hunk_start--; back++;
        }
        /* Forward: extend hunk through changes + at most 2*BD_CTX equals
           (which we then trim to BD_CTX). */
        int j = i;
        while (j < n_ops) {
            if (ops[j].op != BDOP_EQ) { j++; continue; }
            /* Count run of equals from j. */
            int e0 = j;
            while (j < n_ops && ops[j].op == BDOP_EQ) j++;
            int run = j - e0;
            if (j >= n_ops) {
                /* Trailing equals — keep up to BD_CTX. */
                if (run > BD_CTX) j = e0 + BD_CTX;
                break;
            }
            if (run > 2 * BD_CTX) {
                /* Big gap — split hunk here. Trim trailing context to BD_CTX. */
                j = e0 + BD_CTX;
                break;
            }
            /* Otherwise fuse: keep going. */
        }
        int hunk_end = j;
        /* Compute line ranges over [hunk_start, hunk_end). */
        int a_start = -1, a_count = 0;
        int b_start = -1, b_count = 0;
        for (int k = hunk_start; k < hunk_end; k++) {
            if (ops[k].op == BDOP_EQ || ops[k].op == BDOP_DEL) {
                if (a_start < 0) a_start = ops[k].la;
                a_count++;
            }
            if (ops[k].op == BDOP_EQ || ops[k].op == BDOP_INS) {
                if (b_start < 0) b_start = ops[k].lb;
                b_count++;
            }
        }
        if (a_start < 0) a_start = 0;
        if (b_start < 0) b_start = 0;
        bd_format (out, "@@ -%d", a_count ? a_start + 1 : a_start);
        if (a_count != 1) bd_format (out, ",%d", a_count);
        bd_format (out, " +%d", b_count ? b_start + 1 : b_start);
        if (b_count != 1) bd_format (out, ",%d", b_count);
        bd_format (out, " @@\n");
        for (int k = hunk_start; k < hunk_end; k++) {
            switch (ops[k].op) {
            case BDOP_EQ:
                bd_print_line (out, " ", &A[ops[k].la]);
                if (no_newline_a && ops[k].la == n - 1)
                    bd_format (out, "\\ No newline at end of file\n");
                break;
            case BDOP_DEL:
                bd_print_line (out, "-", &A[ops[k].la]);
                if (no_newline_a && ops[k].la == n - 1)
                    bd_format (out, "\\ No newline at end of file\n");
                break;
            case BDOP_INS:
                bd_print_line (out, "+", &B[ops[k].lb]);
                if (no_newline_b && ops[k].lb == m - 1)
                    bd_format (out, "\\ No newline at end of file\n");
                break;
            }
        }
        (void) n;
        i = hunk_end;
    }
}

static int
bd_finish_output (int status)
{
    if (fflush (stdout) == EOF || ferror (stdout)) {
        builtin_error ("write error: %s", strerror (errno ? errno : EIO));
        clearerr (stdout);
        return 2;
    }
    return status;
}

int
diff_builtin (WORD_LIST *list)
{
    bd_opts o = {0};
    const char *paths[2] = { NULL, NULL };
    int npos = 0;
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "--help") == 0) { builtin_usage (); return EXECUTION_SUCCESS; }
        if (strcmp (w, "--version") == 0 || strcmp (w, "-v") == 0) {
            puts ("bashdiff 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--") == 0) {
            for (p = p->next; p; p = p->next) {
                if (npos < 2) paths[npos++] = p->word->word;
                else {
                    builtin_error ("extra operand: %s", p->word->word);
                    builtin_usage ();
                    return EX_USAGE;
                }
            }
            break;
        }
        if (w[0] == '-' && w[1] && strcmp (w, "-") != 0) {
            for (int i = 1; w[i]; i++) {
                switch (w[i]) {
                case 'u': o.uflag = 1; break;
                case 'q': o.qflag = 1; break;
                case 'i': o.iflag = 1; break;
                default:
                    builtin_error ("unknown flag: -%c", w[i]);
                    builtin_usage ();
                    return EX_USAGE;
                }
            }
        } else {
            if (npos < 2) paths[npos++] = w;
            else {
                builtin_error ("extra operand: %s", w);
                builtin_usage ();
                return EX_USAGE;
            }
        }
    }
    if (npos != 2) {
        builtin_usage ();
        return EX_USAGE;
    }

    /* GNU diff treats these as the same input without reading it. In
       particular, do not consume a pipe or wait for EOF before returning. */
    if (bd_is_stdin (paths[0]) && bd_is_stdin (paths[1]))
        return EXECUTION_SUCCESS;

    /* Load distinct operands once each; a single "-" borrows stdin. */
    unsigned char *da = NULL, *db = NULL;
    size_t la = 0, lb = 0;
    if (bd_load (paths[0], &da, &la) < 0)
        return 2;
    if (bd_load (paths[1], &db, &lb) < 0) {
        free (da);
        return 2;
    }

    /* Equal bytes imply equal lines for every supported comparison mode.
       Avoid indexing lines and building an edit trace when
       the complete inputs already establish that there is no difference. */
    if (bd_files_equal (da, la, db, lb)) {
        free (da);
        free (db);
        return EXECUTION_SUCCESS;
    }

    /* Byte inequality fully answers a case-sensitive quiet comparison. */
    if (o.qflag && !o.iflag) {
        printf ("Files %s and %s differ\n", paths[0], paths[1]);
        free (da);
        free (db);
        return bd_finish_output (1);
    }

    /* Binary detection: NUL in the first input block. Binary inputs are compared
       bytewise: identical files exit 0 silently; differing files report the
       standard binary-differ diagnostic and exit 1. */
    int bin_a = bd_probe_binary (da, la);
    int bin_b = bd_probe_binary (db, lb);
    if (bin_a == 1 || bin_b == 1) {
        int same = bd_files_equal (da, la, db, lb);
        int rc;
        if (same)
            rc = 0;
        else {
            if (o.qflag)
                printf ("Files %s and %s differ\n", paths[0], paths[1]);
            else
                printf ("Binary files %s and %s differ\n", paths[0], paths[1]);
            rc = 1;
        }
        free (da);
        free (db);
        return bd_finish_output (rc);
    }

    int n, m, no_newline_a = 0, no_newline_b = 0;
    bd_line *A = bd_slurp (da, la, paths[0], &n, &no_newline_a);
    if (!A) {
        free (da);
        free (db);
        return 2;
    }
    bd_line *B = bd_slurp (db, lb, paths[1], &m, &no_newline_b);
    if (!B) {
        free (A);
        free (da);
        free (db);
        return 2;
    }
    int n_ops;
    bd_op *ops = NULL;
    int rc = 2;
    if (o.qflag) {
        int equal = n == m && no_newline_a == no_newline_b;
        for (int i = 0; equal && i < n; i++)
            equal = bd_lineq (&A[i], &B[i], o.iflag);
        if (!equal) printf ("Files %s and %s differ\n", paths[0], paths[1]);
        rc = bd_finish_output (equal ? 0 : 1);
        goto cleanup;
    }
    ops = bd_myers (A, n, B, m, o.iflag, no_newline_a, no_newline_b, &n_ops);
    if (n_ops < 0) goto cleanup;

    /* Detect "differ at all" by scanning for non-EQ. */
    int differ = 0;
    for (int i = 0; i < n_ops; i++) {
        if (ops[i].op != BDOP_EQ) { differ = 1; break; }
    }
    if (no_newline_a != no_newline_b)
        differ = 1;

    rc = differ ? 1 : 0;
    if (differ && !o.qflag) {
        bl_output out;
        bl_output_init (&out, stdout);
        if (o.uflag) bd_emit_unified (&out, A, n, B, m, ops, n_ops, paths[0], paths[1],
                                     no_newline_a, no_newline_b);
        else         bd_emit_ed (&out, A, n, B, m, ops, n_ops, no_newline_a, no_newline_b);
        bl_output_flush (&out);
        if (out.error) {
            builtin_error ("write error: %s", strerror (out.error));
            clearerr (stdout);
            rc = 2;
        }
    } else if (differ && o.qflag) {
        printf ("Files %s and %s differ\n", paths[0], paths[1]);
    }

    rc = bd_finish_output (rc);
cleanup:
    free (ops);
    free (A);
    free (B);
    free (da);
    free (db);
    return rc;
}

char *diff_doc[] = {
    "Compare two files line by line (Myers O(ND)).",
    "",
    "    bashdiff [-u] [-q] [-i] [--help|--version] FILE1 FILE2",
    "",
    "    -u   unified diff (3 lines context per hunk)",
    "    -q   only report whether files differ",
    "    -i   ignore case",
    "    -v, --version  show version",
    "    --help         show this help",
    "",
    "Exit 0 (same), 1 (differ), 2 (error). Default output is POSIX",
    "ed-script style: 1c2 / 1a1 / 2d3 with < and > markers.",
    (char *)NULL
};

struct builtin bashdiff_struct = {
    "bashdiff",
    diff_builtin,
    BUILTIN_ENABLED,
    diff_doc,
    "bashdiff [-uqi] [--help|--version] FILE1 FILE2",
    0
};
