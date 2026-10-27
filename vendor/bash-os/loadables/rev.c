/* bashrev.c — POSIX rev(1).
 *
 *   bashrev [OPTION] [FILE...]
 *
 * Reverse bytes within each line. Reads stdin if no FILE.
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
#include <sys/stat.h>

#include "loadables.h"

static int
br_process (FILE *f)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int out_failed = 0;
    unsigned char output[65536];
    size_t used = 0;
    struct stat st;
    int batch = !isatty (fileno (stdout)) &&
                fstat (fileno (f), &st) == 0 && S_ISREG (st.st_mode);
    clearerr (f);
    while ((n = getline (&line, &cap, f)) != -1) {
        size_t l = (size_t) n;
        int trail_nl = (l > 0 && line[l - 1] == '\n');
        if (trail_nl) l--;
        /* Reverse the existing line storage, then emit all of its bytes in
           one call. The newline and embedded NUL bytes retain their places
           in the record format without per-byte stdio locking. */
        for (size_t i = 0; i < l / 2; i++) {
            char c = line[i];
            line[i] = line[l - i - 1];
            line[l - i - 1] = c;
        }
        /* Bash keeps stdout line buffered. Coalesce regular-file records
           without changing that persistent setting; live inputs keep their
           original per-line delivery and output-failure detection. */
        size_t len = (size_t) n;
        if (batch && len <= sizeof output) {
            if (len > sizeof output - used) {
                if (fwrite (output, 1, used, stdout) != used) {
                    out_failed = 1;
                    break;
                }
                used = 0;
            }
            memcpy (output + used, line, len);
            used += len;
        } else {
            if (used && fwrite (output, 1, used, stdout) != used) {
                out_failed = 1;
                break;
            }
            used = 0;
            if (fwrite (line, 1, len, stdout) != len) out_failed = 1;
        }
        if (out_failed || ferror (stdout)) {
            out_failed = 1;
            break;
        }
    }
    free (line);
    if (!out_failed && used && fwrite (output, 1, used, stdout) != used)
        out_failed = 1;
    if (out_failed || ferror (stdout) || fflush (stdout) == EOF) {
        builtin_error ("write error: %s", strerror (errno ? errno : EIO));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static void
br_help (void)
{
    puts ("bashrev [OPTION] [FILE...]");
    puts ("Reverse bytes within each line. Reads stdin if no FILE or FILE is -.");
    puts ("");
    puts ("  -h, --help     show this help");
    puts ("  -V, --version  show version");
}

int
rev_builtin (WORD_LIST *list)
{
    if (!list) return br_process (stdin);
    int options_done = 0, operands = 0;
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (!options_done && !strcmp (w, "--")) {
            options_done = 1;
            continue;
        }
        if (options_done) {
            operands++;
            continue;
        }
        if (!strcmp (w, "-h") || !strcmp (w, "--help")) {
            br_help ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-V") || !strcmp (w, "--version")) {
            puts ("bashrev 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (w[0] == '-' && w[1] != '\0' && strcmp (w, "-")) {
            builtin_error ("invalid option: %s", w);
            builtin_usage ();
            return EXECUTION_FAILURE;
        }
        operands++;
    }
    if (!operands) return br_process (stdin);
    int rc = EXECUTION_SUCCESS;
    options_done = 0;
    for (WORD_LIST *p = list; p; p = p->next) {
        if (!options_done && !strcmp (p->word->word, "--")) {
            options_done = 1;
            continue;
        }
        FILE *f = !strcmp (p->word->word, "-") ? stdin : fopen (p->word->word, "r");
        if (!f) {
            builtin_error ("%s: %s", p->word->word, strerror (errno));
            rc = EXECUTION_FAILURE;
            continue;
        }
        int prc = br_process (f);
        if (f != stdin) fclose (f);
        if (prc != EXECUTION_SUCCESS) {
            rc = prc;
            break;
        }
    }
    return rc;
}

char *rev_doc[] = {
    "Reverse bytes within each line (POSIX rev).",
    "",
    "    bashrev [OPTION] [FILE...]",
    "",
    "Reads stdin when no FILE given (or `-` in the list).",
    "",
    "Options:",
    "    -h, --help     show this help",
    "    -V, --version  show version",
    (char *)NULL
};

struct builtin bashrev_struct = {
    "bashrev",
    rev_builtin,
    BUILTIN_ENABLED,
    rev_doc,
    "bashrev [OPTION] [FILE...]",
    0
};
