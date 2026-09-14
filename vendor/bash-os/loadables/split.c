/* SPDX-License-Identifier: MIT */
/* split.c — POSIX split(1) as a bash builtin.
 *
 *   split [-l N | -b SIZE] [-a SUFLEN] [INPUT [PREFIX]]
 *
 * Splits INPUT (or stdin) into pieces named PREFIX{aa,ab,ac,...}.
 * Default: -l 1000 lines per piece, -a 2 (suffix length), PREFIX=x.
 *
 * SIZE accepts POSIX suffixes: c (1), k (1024), m (1024^2), g (1024^3).
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
#include <fcntl.h>
#include <ctype.h>

#include "loadables.h"

static long long
bs_parsesize (const char *s)
{
    char *end;
    long long n = strtoll (s, &end, 10);
    if (end == s || n <= 0) return -1;
    switch (*end) {
        case '\0':              return n;
        case 'c':               return n;
        case 'k': case 'K':     return n * 1024;
        case 'm': case 'M':     return n * 1024 * 1024;
        case 'g': case 'G':     return n * 1024LL * 1024LL * 1024LL;
        default:                return -1;
    }
}

/* Compose PREFIX + suffix-of-length-suflen from `index`. Suffix is all
   lowercase (a..z), big-endian. Returns -1 if index exceeds capacity. */
static int
bs_make_name (char *out, size_t cap, const char *prefix, int suflen, long index)
{
    size_t plen = strlen (prefix);
    if (plen + (size_t) suflen + 1 > cap) return -1;
    memcpy (out, prefix, plen);
    long max = 1;
    for (int i = 0; i < suflen; i++) max *= 26;
    if (index >= max) return -1;
    for (int i = suflen - 1; i >= 0; i--) {
        out[plen + i] = 'a' + (char) (index % 26);
        index /= 26;
    }
    out[plen + suflen] = '\0';
    return 0;
}

/* stdin's FILE belongs to the persistent shell. A private stream so a later
   redirection is not stuck at EOF from this invocation. */
static FILE *
bs_open_stdin (void)
{
    int fd = dup (STDIN_FILENO);
    FILE *in = fd < 0 ? NULL : fdopen (fd, "r");
    if (!in) {
        int error = errno;
        if (fd >= 0) close (fd);
        builtin_error ("stdin: %s", strerror (error));
    }
    return in;
}

int
split_builtin (WORD_LIST *list)
{
    long line_chunk = 1000;     /* -l N default */
    long long byte_chunk = 0;   /* -b SIZE; 0 = use lines */
    int suflen = 2;             /* -a */
    const char *prefix = "x";
    const char *input = NULL;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "-l") || !strncmp (w, "-l", 2)) {
            const char *v = w[2] ? w + 2 : (list = list->next, list ? list->word->word : NULL);
            if (!v) { builtin_error ("-l needs N"); builtin_usage (); return EX_USAGE; }
            line_chunk = atol (v);
            byte_chunk = 0;
            if (line_chunk <= 0) { builtin_error ("-l N must be > 0"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-b") || !strncmp (w, "-b", 2)) {
            const char *v = w[2] ? w + 2 : (list = list->next, list ? list->word->word : NULL);
            if (!v) { builtin_error ("-b needs SIZE"); builtin_usage (); return EX_USAGE; }
            byte_chunk = bs_parsesize (v);
            if (byte_chunk <= 0) { builtin_error ("-b: bad SIZE: %s", v); builtin_usage (); return EX_USAGE; }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-a") || !strncmp (w, "-a", 2)) {
            const char *v = w[2] ? w + 2 : (list = list->next, list ? list->word->word : NULL);
            if (!v) { builtin_error ("-a needs SUFLEN"); builtin_usage (); return EX_USAGE; }
            suflen = atoi (v);
            if (suflen < 1 || suflen > 6) { builtin_error ("-a: SUFLEN must be in 1..6"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            continue;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }
    if (list) { input = list->word->word; list = list->next; }
    if (list) { prefix = list->word->word; list = list->next; }
    if (list) { builtin_error ("split: extra argument: %s", list->word->word); builtin_usage (); return EX_USAGE; }

    int from_stdin = !input || !strcmp (input, "-");
    FILE *fin = from_stdin ? bs_open_stdin () : fopen (input, "r");
    if (!fin) {
        if (!from_stdin) builtin_error ("%s: %s", input, strerror (errno));
        return EXECUTION_FAILURE;
    }

    char namebuf[256];
    long idx = 0;
    int rc = EXECUTION_SUCCESS;

    if (byte_chunk > 0) {
        /* Byte-based splitting. */
        unsigned char buf[8192];
        long long left_in_chunk = 0;
        FILE *fout = NULL;
        for (;;) {
            /* Read BEFORE opening the next output file. GNU split never
               creates an empty trailing piece: a file is opened only once we
               have a byte to put in it, so an empty input (or an input whose
               size is an exact multiple of the chunk) produces no spurious
               zero-length file. */
            long long cap_chunk = (left_in_chunk > 0) ? left_in_chunk : byte_chunk;
            size_t want = ((long long) sizeof buf > cap_chunk) ? (size_t) cap_chunk : sizeof buf;
            size_t r = fread (buf, 1, want, fin);
            if (r == 0) break;
            if (fout == NULL) {
                if (bs_make_name (namebuf, sizeof namebuf, prefix, suflen, idx) < 0) {
                    builtin_error ("split: suffix exhausted (try larger -a)");
                    rc = EXECUTION_FAILURE;
                    break;
                }
                fout = fopen (namebuf, "wb");
                if (!fout) {
                    builtin_error ("create %s: %s", namebuf, strerror (errno));
                    rc = EXECUTION_FAILURE;
                    break;
                }
                left_in_chunk = byte_chunk;
            }
            if (fwrite (buf, 1, r, fout) != r) {
                builtin_error ("write %s: %s", namebuf, strerror (errno));
                rc = EXECUTION_FAILURE;
                break;
            }
            left_in_chunk -= (long long) r;
            if (left_in_chunk == 0) {
                fclose (fout);
                fout = NULL;
                idx++;
            }
        }
        if (fout) { fclose (fout); }
    } else {
        /* Line-based splitting. */
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        long lines_in_chunk = 0;
        FILE *fout = NULL;
        while ((n = getline (&line, &cap, fin)) != -1) {
            if (lines_in_chunk == 0) {
                if (bs_make_name (namebuf, sizeof namebuf, prefix, suflen, idx) < 0) {
                    builtin_error ("split: suffix exhausted (try larger -a)");
                    rc = EXECUTION_FAILURE;
                    break;
                }
                fout = fopen (namebuf, "w");
                if (!fout) {
                    builtin_error ("create %s: %s", namebuf, strerror (errno));
                    rc = EXECUTION_FAILURE;
                    break;
                }
            }
            fwrite (line, 1, (size_t) n, fout);
            lines_in_chunk++;
            if (lines_in_chunk >= line_chunk) {
                fclose (fout); fout = NULL;
                lines_in_chunk = 0;
                idx++;
            }
        }
        if (fout) fclose (fout);
        free (line);
    }

    fclose (fin);
    return rc;
}

char *split_doc[] = {
    "Split a file into pieces (POSIX split).",
    "",
    "    split [-l N | -b SIZE] [-a SUFLEN] [INPUT [PREFIX]]",
    "",
    "    -l N        N lines per piece (default 1000)",
    "    -b SIZE     SIZE bytes per piece. SIZE accepts c/k/m/g suffixes",
    "    -a SUFLEN   suffix length (default 2 → aa..zz, max 26^2 = 676)",
    "",
    "INPUT defaults to stdin (or `-`). Output files are named",
    "PREFIXaa, PREFIXab, ... where PREFIX defaults to `x`.",
    (char *)NULL
};

struct builtin split_struct = {
    "split",
    split_builtin,
    BUILTIN_ENABLED,
    split_doc,
    "split [-l N | -b SIZE] [-a SUFLEN] [INPUT [PREFIX]]",
    0
};
