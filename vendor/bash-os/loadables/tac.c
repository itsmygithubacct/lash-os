/* SPDX-License-Identifier: MIT */
/* tac.c — GNU-style tac(1): concatenate and print files in reverse.
 *
 *   tac [OPTION]... [FILE]...
 *
 * Write each FILE to standard output, last record first. Records default to
 * lines (separator '\n'). With no FILE, or when FILE is '-', read stdin.
 *
 * Options:
 *   -b, --before          attach the separator BEFORE each record, not after
 *   -r, --regex           treat the separator string as an extended regex
 *   -s, --separator=SEP   use SEP as the record separator (default newline)
 *   -h, --help / -V, --version
 *
 * Each input is buffered separately. Literal separators are located from
 * right to left, and output is batched without changing Bash's stdio state.
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
#include <regex.h>
#include <stdint.h>

#include "loadables.h"
#include "bl-output.h"

/* Grow-on-demand byte buffer. */
typedef struct { char *p; size_t len, cap; } tac_buf;

static int
tac_buf_append (tac_buf *b, const char *s, size_t n)
{
    if (n > SIZE_MAX - b->len - 1) { errno = EOVERFLOW; return -1; }
    size_t needed = b->len + n + 1;
    if (needed > b->cap) {
        size_t nc = b->cap ? b->cap : 4096;
        while (needed > nc) {
            if (nc > SIZE_MAX / 2) { nc = needed; break; }
            nc *= 2;
        }
        char *np = realloc (b->p, nc);
        if (!np) return -1;
        b->p = np; b->cap = nc;
    }
    memcpy (b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
    return 0;
}

static int
tac_slurp (int fd, tac_buf *b)
{
    char rd[65536];
    /* The shell owns stdin's FILE state, which can retain an EOF flag or
       buffered bytes after fd 0 is redirected. Consume the descriptor to
       match a freshly executed tac without changing Bash's stdio state. */
    for (;;) {
        ssize_t n = read (fd, rd, sizeof rd);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) return 0;
        if (tac_buf_append (b, rd, (size_t) n) < 0) return -1;
    }
}

/* Emit the buffer's records in reverse. `before` attaches the separator at
   the start of each record instead of the end. Separator matches are given
   as [start,end) offsets in `seps` (n_seps entries). */
static void
tac_emit (const tac_buf *b, const size_t *sep_so, const size_t *sep_eo, size_t n_seps,
          int before, bl_output *out)
{
    if (before) {
        /* Separator begins each record: record i spans [sep_eo[i-1]..sep_so[i])
           preceded by its leading separator, except the first chunk (text
           before the first separator) which has none. Walk boundaries in
           reverse, emitting [sep_so[i] .. next_record_start). */
        size_t end = b->len;             /* end of the current (rightmost) record */
        for (size_t k = n_seps; k > 0 && !out->error; k--) {
            size_t i = k - 1;
            /* record = separator + following text, i.e. [sep_so[i] .. end) */
            bl_output_write (out, b->p + sep_so[i], end - sep_so[i]);
            end = sep_so[i];
        }
        /* leading chunk before the first separator (no separator attached) */
        if (end > 0) bl_output_write (out, b->p, end);
    } else {
        /* Separator ends each record: record k spans [start .. sep_eo[k])
           including the separator. A final partial record after the last
           separator (no separator) is emitted first (it is last in input). */
        size_t tail_start = n_seps ? sep_eo[n_seps - 1] : 0;
        if (tail_start < b->len)
            bl_output_write (out, b->p + tail_start, b->len - tail_start);
        for (size_t k = n_seps; k > 0 && !out->error; k--) {
            size_t i = k - 1;
            size_t start = i ? sep_eo[i - 1] : 0;
            bl_output_write (out, b->p + start, sep_eo[i] - start);
        }
    }
}

static int
tac_literal (const tac_buf *b, const char *sep, int before, bl_output *out)
{
    size_t slen = strlen (sep);
    if (slen == 0) slen = 1;             /* An empty argument selects NUL. */
    size_t search_end = b->len, record_end = b->len;
    while (search_end >= slen && !out->error) {
        /* Search only positions at which the complete separator fits.
           memrchr also supplies the common single-byte separator fast path. */
        size_t limit = search_end - slen + 1;
        const char *match = NULL;
        while (limit) {
            match = memrchr (b->p, (unsigned char) sep[0], limit);
            if (!match || slen == 1 || memcmp (match, sep, slen) == 0) break;
            limit = (size_t) (match - b->p);
            match = NULL;
        }
        if (!match) break;
        size_t start = (size_t) (match - b->p);
        size_t boundary = before ? start : start + slen;
        bl_output_write (out, b->p + boundary, record_end - boundary);
        record_end = boundary;
        /* Matches may overlap in the input; GNU tac consumes the rightmost
           one first. Exclude its entire span from the next search. */
        search_end = start;
    }
    if (record_end) bl_output_write (out, b->p, record_end);
    return out->error ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
tac_run (tac_buf *b, const char *sep, int before, int regex, bl_output *out)
{
    if (!regex) return tac_literal (b, sep, before, out);

    size_t cap = 16, n = 0;
    size_t *so = malloc (cap * sizeof *so), *eo = malloc (cap * sizeof *eo);
    if (!so || !eo) { free (so); free (eo); return EXECUTION_FAILURE; }

    int rc = EXECUTION_SUCCESS;
    {
        regex_t re;
        if (regcomp (&re, sep, REG_EXTENDED) != 0) {
            builtin_error ("invalid regex separator: %s", sep);
            free (so); free (eo); return EX_USAGE;
        }
        regmatch_t m;
        size_t off = 0;
        while (off <= b->len &&
               regexec (&re, b->p + off, 1, &m, off ? REG_NOTBOL : 0) == 0) {
            if (m.rm_eo == m.rm_so) { off++; continue; }  /* skip empty match */
            if (n == cap) {
                if (cap > SIZE_MAX / 2 / sizeof *so) {
                    builtin_error ("out of memory");
                    free (so); free (eo); regfree (&re);
                    return EXECUTION_FAILURE;
                }
                size_t nc = cap * 2, *ns = realloc (so, nc*sizeof*so), *ne = NULL;
                if (ns) ne = realloc (eo, nc*sizeof*eo);
                if (!ns || !ne) {
                    builtin_error ("out of memory");
                    free (ns ? ns : so); free (ne ? ne : eo); regfree (&re);
                    return EXECUTION_FAILURE;
                }
                so = ns; eo = ne; cap = nc;
            }
            so[n] = off + (size_t) m.rm_so;
            eo[n] = off + (size_t) m.rm_eo;
            n++;
            off += (size_t) m.rm_eo;
        }
        regfree (&re);
    }
    tac_emit (b, so, eo, n, before, out);
    if (out->error) rc = EXECUTION_FAILURE;
    free (so); free (eo);
    return rc;
}

static void
tac_help (void)
{
    puts ("Concatenate and print files in reverse (last record first).");
    puts ("");
    puts ("    tac [OPTION]... [FILE]...");
    puts ("");
    puts ("    -b, --before          attach the separator before each record");
    puts ("    -r, --regex           the separator is an extended regex");
    puts ("    -s, --separator=SEP   record separator (default newline)");
    puts ("    -h, --help / -V, --version");
}

int
tac_builtin (WORD_LIST *list)
{
    const char *sep = "\n";
    int before = 0, regex = 0;
    /* Collect file operands after parsing options. */
    char **files = NULL; int n_files = 0, cap_files = 0;
    int end_opts = 0;

    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (!end_opts && !strcmp (w, "--")) { end_opts = 1; continue; }
        if (!end_opts && !strcmp (w, "-h")) { tac_help (); free (files); return EXECUTION_SUCCESS; }
        if (!end_opts && !strcmp (w, "--help")) { tac_help (); free (files); return EXECUTION_SUCCESS; }
        if (!end_opts && (!strcmp (w, "-V") || !strcmp (w, "--version"))) {
            puts ("tac 1.0 (bash-loadable, coreutils-compatible)"); free (files); return EXECUTION_SUCCESS;
        }
        if (!end_opts && (!strcmp (w, "-b") || !strcmp (w, "--before"))) { before = 1; continue; }
        if (!end_opts && (!strcmp (w, "-r") || !strcmp (w, "--regex"))) { regex = 1; continue; }
        if (!end_opts && (!strcmp (w, "-s") || !strcmp (w, "--separator"))) {
            if (!p->next) { builtin_error ("option requires an argument -- s"); free (files); return EX_USAGE; }
            p = p->next; sep = p->word->word; continue;
        }
        if (!end_opts && !strncmp (w, "--separator=", 12)) { sep = w + 12; continue; }
        if (!end_opts && !strncmp (w, "-s", 2) && w[2]) { sep = w + 2; continue; }
        if (!end_opts && w[0] == '-' && w[1] != '\0' && strcmp (w, "-")) {
            builtin_error ("invalid option: %s", w);
            builtin_usage (); free (files); return EX_USAGE;
        }
        /* operand */
        if (n_files == cap_files) {
            int nc = cap_files ? cap_files * 2 : 8;
            char **nf = realloc (files, (size_t) nc * sizeof *files);
            if (!nf) { builtin_error ("out of memory"); free (files); return EXECUTION_FAILURE; }
            files = nf; cap_files = nc;
        }
        files[n_files++] = (char *) w;
    }

    /* GNU tac reverses each FILE independently and emits the reversed files
       in operand order — it does NOT reverse the whole concatenation. So
       slurp + reverse + emit one source at a time. */
    int rc = EXECUTION_SUCCESS;
    bl_output out;
    bl_output_init (&out, stdout);
    if (n_files == 0 && !out.error) {
        tac_buf b = {0};
        if (tac_slurp (STDIN_FILENO, &b) < 0) { builtin_error ("read error"); rc = EXECUTION_FAILURE; }
        else if (b.len > 0) rc = tac_run (&b, sep, before, regex, &out);
        free (b.p);
    } else {
        for (int i = 0; i < n_files && !out.error; i++) {
            FILE *f = !strcmp (files[i], "-") ? stdin : fopen (files[i], "r");
            if (!f) { builtin_error ("%s: %s", files[i], strerror (errno)); rc = EXECUTION_FAILURE; continue; }
            tac_buf b = {0};
            if (tac_slurp (fileno (f), &b) < 0) { builtin_error ("%s: read error", files[i]); rc = EXECUTION_FAILURE; }
            else if (b.len > 0) { int r = tac_run (&b, sep, before, regex, &out); if (r != EXECUTION_SUCCESS) rc = r; }
            free (b.p);
            if (f != stdin) fclose (f);
        }
    }
    bl_output_flush (&out);
    if (out.error) {
        builtin_error ("write error: %s", strerror (out.error));
        rc = EXECUTION_FAILURE;
    }
    free (files);
    return rc;
}

char *tac_doc[] = {
    "Concatenate and print files in reverse (last record first).",
    "",
    "    tac [OPTION]... [FILE]...",
    "",
    "Records default to lines. With no FILE (or '-'), read standard input.",
    "",
    "Options:",
    "    -b, --before          attach the separator before each record",
    "    -r, --regex           the separator is an extended regex",
    "    -s, --separator=SEP   record separator (default newline)",
    "    -h, --help            show this help",
    "    -V, --version         show version",
    (char *)NULL
};

struct builtin tac_struct = {
    "tac",
    tac_builtin,
    BUILTIN_ENABLED,
    tac_doc,
    "tac [OPTION]... [FILE]...",
    0
};
