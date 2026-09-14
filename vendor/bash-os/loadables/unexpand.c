/* SPDX-License-Identifier: MIT */
/* unexpand.c — POSIX unexpand(1) as a bash builtin.
 *
 * Closes the POSIX gap noted in POSIX-CONFORMANCE-RESEARCH.md §4.1.
 * Replaces runs of spaces with tabs. By default only LEADING runs are
 * converted (POSIX behavior); -a converts all runs of >= 2 spaces.
 *
 *   unexpand [-a|--all] [-t TABLIST|--tabs=TABLIST] [FILE...]
 *
 *   -a, --all           convert all whitespace runs, not just leading
 *   --first-only        convert only leading whitespace runs
 *   -t, --tabs TABLIST  tab stops; same syntax as bashexpand. Default: 8.
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
#include <ctype.h>

#include "loadables.h"

#define BU_MAX_STOPS 64

typedef struct {
    int stops[BU_MAX_STOPS];
    int n_stops;
    int every;
    int all;
} bu_opts;

static int
bu_parse_tablist (const char *s, bu_opts *o)
{
    char *end;
    long n = strtol (s, &end, 10);
    if (*end == '\0') {
        if (n <= 0) { builtin_error ("invalid tab size: %s", s); return -1; }
        o->every = (int) n;
        o->n_stops = 0;
        return 0;
    }
    o->every = 0;
    o->n_stops = 0;
    int prev = 0;
    while (*s) {
        while (*s == ',' || *s == ' ' || *s == '\t') s++;
        if (!*s) break;
        char *e;
        long v = strtol (s, &e, 10);
        if (e == s || v <= prev) {
            builtin_error ("bad tab list (must be strictly increasing): %s", s);
            return -1;
        }
        if (o->n_stops >= BU_MAX_STOPS) {
            builtin_error ("too many tab stops (max %d)", BU_MAX_STOPS);
            return -1;
        }
        o->stops[o->n_stops++] = (int) v;
        prev = (int) v;
        s = e;
    }
    return o->n_stops > 0 ? 0 : (builtin_error ("empty tab list"), -1);
}

/* Next tab-stop column strictly greater than COL. With a single tab size
   (`every`) stops repeat forever. With an explicit list there is no stop past
   the last entry: *LAST_TAB is set and col+1 is returned, mirroring GNU
   unexpand's get_next_tab_column() — there conversion stops for the rest of
   the line. (No running tab_index is needed: scanning for the first stop
   strictly greater than COL is stateless and gives the same answer GNU's
   incremental index does, including after a backspace lowers the column.) */
static int
bu_next_stop (int col, const bu_opts *o, int *last_tab)
{
    *last_tab = 0;
    if (o->every > 0)
        return col + (o->every - col % o->every);
    for (int i = 0; i < o->n_stops; i++)
        if (o->stops[i] > col)
            return o->stops[i];
    *last_tab = 1;
    return col + 1;
}

/* Convert one input stream, faithfully porting GNU unexpand's per-line state
   machine (coreutils unexpand.c fold_file). Blank runs are accumulated in
   `pending`; a run is replaced by a tab only when a blank lands exactly on a
   tab stop with a preceding blank, and a lone blank sitting on a stop is kept
   as a space (`one_blank_before`). `o->all` is GNU's convert_entire_line:
   when false, conversion stops after the first non-blank on each line. */
static int
bu_process (FILE *f, const bu_opts *o)
{
    char  *pending = NULL;       /* buffer of pending blank bytes */
    size_t pending_cap = 0;
    size_t pending_n = 0;
    int convert = 1;
    int column = 0;
    int one_blank_before = 0;
    int prev_blank = 1;          /* a line is treated as preceded by a blank */
    int out_failed = 0;
    int c;

    clearerr (f);
    for (;;) {
        int suppress = 0;        /* set when the current char is consumed (g.len=0) */
        c = fgetc (f);

        /* EOF is processed too: like GNU, it triggers the final pending flush
           (with the pending>1 conversion) before the loop ends. */
        if (convert) {
            int blank = (c != EOF && (c == ' ' || c == '\t'));
            if (blank) {
                int last_tab = 0;
                int next_tab = bu_next_stop (column, o, &last_tab);
                if (last_tab)
                    convert = 0;
                if (convert) {
                    if (c == '\t') {
                        column = next_tab;
                        if (pending_n) pending[0] = '\t';
                    } else { /* space (width 1) */
                        column += 1;
                        if (!(prev_blank && column == next_tab)) {
                            if (column == next_tab) one_blank_before = 1;
                            if (pending_n + 1 > pending_cap) {
                                size_t nc = pending_cap ? pending_cap * 2 : 64;
                                char *nb = realloc (pending, nc);
                                if (!nb) { free (pending); builtin_error ("realloc"); return EXECUTION_FAILURE; }
                                pending = nb;
                                pending_cap = nc;
                            }
                            pending[pending_n++] = ' ';
                            prev_blank = 1;
                            continue;            /* hold the blank; emit nothing yet */
                        }
                        /* Replace the pending blanks by a tab (or two). */
                        fputc ('\t', stdout);
                        if (pending_cap == 0) {
                            pending = malloc (pending_cap = 64);
                            if (!pending) { builtin_error ("malloc"); return EXECUTION_FAILURE; }
                        }
                        pending[0] = '\t';
                        suppress = 1;
                    }
                    /* Discard pending, unless a single blank sat on a stop. */
                    pending_n = one_blank_before ? 1 : 0;
                }
            } else if (c == '\b') {
                if (column > 0) column--;
            } else if (c != '\n' && c != EOF) {
                column += 1;
            }

            if (pending_n) {
                if (pending_n > 1 && one_blank_before) pending[0] = '\t';
                fwrite (pending, 1, pending_n, stdout);
                pending_n = 0;
                one_blank_before = 0;
            }
            prev_blank = blank;
            convert = convert && (o->all || blank);
        }

        if (c == EOF)
            break;

        if (c == '\n') {
            fputc ('\n', stdout);
            convert = 1; column = 0;
            one_blank_before = 0; prev_blank = 1; pending_n = 0;
        } else if (!suppress) {
            fputc (c, stdout);
        }
        if (ferror (stdout)) {
            out_failed = 1;
            break;
        }
    }

    free (pending);
    if (out_failed || ferror (stdout) || fflush (stdout) == EOF) {
        builtin_error ("write error: %s", strerror (errno ? errno : EIO));
        return EXECUTION_FAILURE;
    }
    return ferror (f) ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static void
bu_help (void)
{
    puts ("unexpand [OPTION] [FILE...]");
    puts ("Convert spaces to tabs. Reads stdin if no FILE or FILE is -.");
    puts ("");
    puts ("  -a, --all          convert all blanks, not just initial blanks");
    puts ("      --first-only   convert only leading blanks");
    puts ("  -t, --tabs=LIST    tab stops (single N or comma-separated)");
    puts ("  -h, --help         show this help");
    puts ("  -V, --version      show version");
}

int
unexpand_builtin (WORD_LIST *list)
{
    bu_opts o = { .every = 8 };
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "-h") || !strcmp (w, "--help")) {
            bu_help ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-V") || !strcmp (w, "--version")) {
            puts ("unexpand 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-a") || !strcmp (w, "--all")) { o.all = 1; list = list->next; continue; }
        if (!strcmp (w, "--first-only")) { o.all = 0; list = list->next; continue; }
        if (!strcmp (w, "-t") || !strcmp (w, "--tabs")) {
            if (!list->next) {
                builtin_error ("%s needs TABLIST", w);
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            if (bu_parse_tablist (list->word->word, &o) < 0) {
                builtin_usage ();
                return EX_USAGE;
            }
            /* POSIX: -t implies -a. */
            o.all = 1;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-t", 2) && w[2]) {
            if (bu_parse_tablist (w + 2, &o) < 0) {
                builtin_usage ();
                return EX_USAGE;
            }
            o.all = 1;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--tabs=", 7)) {
            if (bu_parse_tablist (w + 7, &o) < 0) {
                builtin_usage ();
                return EX_USAGE;
            }
            o.all = 1;
            list = list->next;
            continue;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    int rc = EXECUTION_SUCCESS;
    if (!list) {
        rc = bu_process (stdin, &o);
    } else {
        for (WORD_LIST *p = list; p; p = p->next) {
            FILE *f = !strcmp (p->word->word, "-") ? stdin : fopen (p->word->word, "r");
            if (!f) {
                builtin_error ("%s: %s", p->word->word, strerror (errno));
                rc = EXECUTION_FAILURE;
                continue;
            }
            int prc = bu_process (f, &o);
            if (f != stdin) fclose (f);
            if (prc != EXECUTION_SUCCESS) {
                rc = prc;
                break;
            }
        }
    }
    return rc;
}

char *unexpand_doc[] = {
    "Convert spaces to tabs (POSIX unexpand).",
    "",
    "    unexpand [OPTION] [FILE...]",
    "",
    "    -a, --all          convert all space runs of length >= 2, not just",
    "                       leading runs",
    "        --first-only   convert only leading runs",
    "    -t, --tabs=LIST    tab stops (single N or comma-separated). Default: 8.",
    "                       Specifying tabs implies --all per POSIX.",
    "    -h, --help         show help",
    "    -V, --version      show version",
    "",
    "Reads stdin when no FILE given or FILE is -. Output goes to stdout.",
    (char *)NULL
};

struct builtin unexpand_struct = {
    "unexpand",
    unexpand_builtin,
    BUILTIN_ENABLED,
    unexpand_doc,
    "unexpand [OPTION] [FILE...]",
    0
};
