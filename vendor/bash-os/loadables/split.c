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
#include <limits.h>
#include <sys/stat.h>

#include "loadables.h"

static long long
bs_parsenumber (const char *s, int suffix)
{
    char *end;
    errno = 0;
    long long n = strtoll (s, &end, 10);
    if (errno == ERANGE || end == s || n <= 0) return -1;
    if (*end == '\0') return n;
    if (!suffix || end[1]) return -1;
    long long factor;
    switch (*end) {
        case 'c':               factor = 1; break;
        case 'k': case 'K':     factor = 1024; break;
        case 'm': case 'M':     factor = 1024LL * 1024; break;
        case 'g': case 'G':     factor = 1024LL * 1024 * 1024; break;
        default:                return -1;
    }
    return n > LLONG_MAX / factor ? -1 : n * factor;
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

/* Open without truncation until we know this is not the input, including
   a hard link or a symlink to it. fdopen("w") does not truncate the fd. */
static FILE *
bs_open_output (const char *name, const struct stat *input)
{
    int fd = open (name, O_WRONLY | O_CREAT, 0666);
    if (fd < 0) {
        builtin_error ("create %s: %s", name, strerror (errno));
        return NULL;
    }
    struct stat output;
    if (fstat (fd, &output) < 0) {
        builtin_error ("stat %s: %s", name, strerror (errno));
        close (fd);
        return NULL;
    }
    if (output.st_dev == input->st_dev && output.st_ino == input->st_ino) {
        builtin_error ("%s would overwrite the input", name);
        close (fd);
        return NULL;
    }
    if (S_ISREG (output.st_mode) && ftruncate (fd, 0) < 0) {
        builtin_error ("truncate %s: %s", name, strerror (errno));
        close (fd);
        return NULL;
    }
    FILE *out = fdopen (fd, "w");
    if (!out) {
        builtin_error ("open %s: %s", name, strerror (errno));
        close (fd);
    }
    return out;
}

static int
bs_close_output (FILE *out, const char *name)
{
    if (fclose (out) == EOF) {
        builtin_error ("write %s: %s", name, strerror (errno ? errno : EIO));
        return -1;
    }
    return 0;
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
            if (!v) { builtin_error ("-l needs N"); builtin_usage (); return EXECUTION_FAILURE; }
            long long value = bs_parsenumber (v, 0);
            if (value <= 0 || value > LONG_MAX) {
                builtin_error ("-l: invalid line count: %s", v);
                builtin_usage ();
                return EXECUTION_FAILURE;
            }
            line_chunk = (long) value;
            byte_chunk = 0;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-b") || !strncmp (w, "-b", 2)) {
            const char *v = w[2] ? w + 2 : (list = list->next, list ? list->word->word : NULL);
            if (!v) { builtin_error ("-b needs SIZE"); builtin_usage (); return EXECUTION_FAILURE; }
            byte_chunk = bs_parsenumber (v, 1);
            if (byte_chunk <= 0) { builtin_error ("-b: bad SIZE: %s", v); builtin_usage (); return EXECUTION_FAILURE; }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-a") || !strncmp (w, "-a", 2)) {
            const char *v = w[2] ? w + 2 : (list = list->next, list ? list->word->word : NULL);
            if (!v) { builtin_error ("-a needs SUFLEN"); builtin_usage (); return EXECUTION_FAILURE; }
            long long value = bs_parsenumber (v, 0);
            if (value < 1 || value > 6) { builtin_error ("-a: SUFLEN must be in 1..6"); builtin_usage (); return EXECUTION_FAILURE; }
            suflen = (int) value;
            list = list->next;
            continue;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EXECUTION_FAILURE;
    }
    if (list) { input = list->word->word; list = list->next; }
    if (list) { prefix = list->word->word; list = list->next; }
    if (list) { builtin_error ("split: extra argument: %s", list->word->word); builtin_usage (); return EXECUTION_FAILURE; }

    int from_stdin = !input || !strcmp (input, "-");
    FILE *fin = from_stdin ? bs_open_stdin () : fopen (input, "r");
    if (!fin) {
        if (!from_stdin) builtin_error ("%s: %s", input, strerror (errno));
        return EXECUTION_FAILURE;
    }

    struct stat input_stat;
    if (fstat (fileno (fin), &input_stat) < 0) {
        builtin_error ("stat input: %s", strerror (errno));
        fclose (fin);
        return EXECUTION_FAILURE;
    }
    size_t namecap = strlen (prefix) + (size_t) suflen + 1;
    char *namebuf = malloc (namecap);
    if (!namebuf) {
        builtin_error ("out of memory");
        fclose (fin);
        return EXECUTION_FAILURE;
    }
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
                if (bs_make_name (namebuf, namecap, prefix, suflen, idx) < 0) {
                    builtin_error ("split: suffix exhausted (try larger -a)");
                    rc = EXECUTION_FAILURE;
                    break;
                }
                fout = bs_open_output (namebuf, &input_stat);
                if (!fout) {
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
                int failed = bs_close_output (fout, namebuf);
                fout = NULL;
                if (failed) { rc = EXECUTION_FAILURE; break; }
                idx++;
            }
        }
        if (fout && bs_close_output (fout, namebuf) < 0) rc = EXECUTION_FAILURE;
    } else {
        /* Line-based splitting. */
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        long lines_in_chunk = 0;
        FILE *fout = NULL;
        while ((n = getline (&line, &cap, fin)) != -1) {
            if (lines_in_chunk == 0) {
                if (bs_make_name (namebuf, namecap, prefix, suflen, idx) < 0) {
                    builtin_error ("split: suffix exhausted (try larger -a)");
                    rc = EXECUTION_FAILURE;
                    break;
                }
                fout = bs_open_output (namebuf, &input_stat);
                if (!fout) {
                    rc = EXECUTION_FAILURE;
                    break;
                }
            }
            if (fwrite (line, 1, (size_t) n, fout) != (size_t) n) {
                builtin_error ("write %s: %s", namebuf, strerror (errno ? errno : EIO));
                rc = EXECUTION_FAILURE;
                break;
            }
            lines_in_chunk++;
            if (lines_in_chunk >= line_chunk) {
                int failed = bs_close_output (fout, namebuf);
                fout = NULL;
                if (failed) { rc = EXECUTION_FAILURE; break; }
                lines_in_chunk = 0;
                idx++;
            }
        }
        if (fout && bs_close_output (fout, namebuf) < 0) rc = EXECUTION_FAILURE;
        free (line);
    }

    if (ferror (fin)) {
        builtin_error ("read %s: %s", input ? input : "stdin", strerror (errno ? errno : EIO));
        rc = EXECUTION_FAILURE;
    }
    if (fclose (fin) == EOF) {
        builtin_error ("close input: %s", strerror (errno));
        rc = EXECUTION_FAILURE;
    }
    free (namebuf);
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
