/* bashcmp.c — POSIX cmp(1) as a bash builtin.
 *
 * Phase S of bash-os POSIX gap-fillers.
 *
 *   bashcmp [-l|-s] FILE1 FILE2 [SKIP1 [SKIP2]]
 *
 *   -l      list every diff: "<offset> <oct1> <oct2>" (1-indexed bytes,
 *           octal byte values without leading zero per POSIX).
 *   -s      silent: no output, only exit code.
 *
 *   SKIP1   skip first SKIP1 bytes of FILE1.
 *   SKIP2   skip first SKIP2 bytes of FILE2.
 *
 * Exit codes: 0 (same), 1 (differ), 2 (error). Matches POSIX exactly.
 *
 * Either FILE may be "-" to read stdin (but only one — POSIX).
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
#include <fcntl.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <sys/stat.h>

#include "loadables.h"

static int
bcm_parse_skip (const char *s, uint64_t *out)
{
    char *end = NULL;
    unsigned long long v;

    if (!s || !*s || s[0] == '-')
        return -1;
    errno = 0;
    v = strtoull (s, &end, 0);
    if (errno == ERANGE || !end || end == s || *end ||
        (off_t) v < 0 || (uintmax_t) (off_t) v != (uintmax_t) v)
        return -1;
    *out = (uint64_t) v;
    return 0;
}

static int
bcm_open (const char *path, int *out_fd)
{
    if (strcmp (path, "-") == 0) { *out_fd = STDIN_FILENO; return 0; }
    int fd = open (path, O_RDONLY);
    if (fd < 0) {
        builtin_error ("%s: %s", path, strerror (errno));
        return -1;
    }
    *out_fd = fd;
    return 0;
}

static int
bcm_skip (int fd, uint64_t n, const char *name)
{
    /* A borrowed stdin can already be partway through a regular file. */
    off_t offset = (off_t) n;
    if (offset >= 0 && (uint64_t) offset == n &&
        lseek (fd, offset, SEEK_CUR) >= 0) return 0;
    char buf[4096];
    while (n > 0) {
        size_t want = (n > sizeof buf) ? sizeof buf : (size_t) n;
        ssize_t r = read (fd, buf, want);
        if (r < 0 && errno == EINTR) continue;
        if (r == 0) return 0;
        if (r < 0) {
            builtin_error ("skip in %s: %s", name, strerror (errno));
            return -1;
        }
        n -= (uint64_t) r;
    }
    return 0;
}

int
cmp_builtin (WORD_LIST *list)
{
    int lflag = 0, sflag = 0;
    const char *paths[2] = { NULL, NULL };
    int npath = 0;
    uint64_t skip[2] = { 0, 0 };
    int nskip = 0;

    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "--help") == 0) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--version") == 0) {
            puts ("bashcmp 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--") == 0) {
            for (p = p->next; p; p = p->next) {
                if (npath < 2) paths[npath++] = p->word->word;
                else if (nskip < 2) {
                    if (bcm_parse_skip (p->word->word, &skip[nskip]) < 0) {
                        builtin_error ("invalid skip count: %s", p->word->word);
                        builtin_usage ();
                        return EX_USAGE;
                    }
                    nskip++;
                } else {
                    builtin_error ("too many arguments");
                    builtin_usage ();
                    return EX_USAGE;
                }
            }
            break;
        }
        if (npath >= 2) {
            if (nskip < 2) {
                if (bcm_parse_skip (w, &skip[nskip]) < 0) {
                    builtin_error ("invalid skip count: %s", w);
                    builtin_usage ();
                    return EX_USAGE;
                }
                nskip++;
            } else {
                builtin_error ("too many arguments");
                builtin_usage ();
                return EX_USAGE;
            }
            continue;
        }
        if (w[0] == '-' && w[1] && strcmp (w, "-") != 0) {
            for (int i = 1; w[i]; i++) {
                switch (w[i]) {
                case 'l': lflag = 1; break;
                case 's': sflag = 1; break;
                default:
                    builtin_error ("unknown flag: -%c", w[i]);
                    builtin_usage ();
                    return EX_USAGE;
                }
            }
        } else {
            if (npath < 2) paths[npath++] = w;
            else if (nskip < 2) {
                if (bcm_parse_skip (w, &skip[nskip]) < 0) {
                    builtin_error ("invalid skip count: %s", w);
                    builtin_usage ();
                    return EX_USAGE;
                }
                nskip++;
            }
            else { builtin_error ("too many arguments"); builtin_usage (); return EX_USAGE; }
        }
    }
    if (npath != 2) {
        builtin_error ("missing file operand");
        builtin_usage ();
        return EX_USAGE;
    }
    if (lflag && sflag) {
        builtin_error ("-l and -s are mutually exclusive");
        builtin_usage ();
        return EX_USAGE;
    }
    if (strcmp (paths[0], "-") == 0 && strcmp (paths[1], "-") == 0) {
        builtin_error ("only one stdin operand is supported");
        builtin_usage ();
        return EX_USAGE;
    }

    int fd[2];
    int owned[2] = { strcmp (paths[0], "-") != 0, strcmp (paths[1], "-") != 0 };
    /* Check before opening operands: an owned file may reuse descriptor 0. */
    if ((!owned[0] || !owned[1]) && fcntl (STDIN_FILENO, F_GETFD) < 0) {
        builtin_error ("standard input: %s", strerror (errno));
        return 2;
    }
    if (bcm_open (paths[0], &fd[0]) < 0) return 2;
    if (bcm_open (paths[1], &fd[1]) < 0) {
        if (owned[0]) close (fd[0]);
        return 2;
    }

    unsigned char buf[2][8192];
    size_t used[2] = { 0, 0 }, available[2] = { 0, 0 };
    uint64_t off = 1, line = 1;
    int rc = 0;
    int offset_width = 1;
    int eof[2] = { 0, 0 };
    if ((skip[0] && bcm_skip (fd[0], skip[0], paths[0]) < 0) ||
        (skip[1] && bcm_skip (fd[1], skip[1], paths[1]) < 0)) {
        rc = 2;
        goto done;
    }
    if (lflag) {
        uint64_t remaining = UINT64_MAX;
        for (int j = 0; j < 2; j++) {
            struct stat st;
            off_t position;
            if (fstat (fd[j], &st) == 0 && S_ISREG (st.st_mode)
                && (position = lseek (fd[j], 0, SEEK_CUR)) >= 0) {
                uint64_t count = position < st.st_size
                    ? (uint64_t) (st.st_size - position) : 0;
                if (count < remaining) remaining = count;
            }
        }
        /* Unknown-length streams use the signed file-offset range, as GNU
           cmp does. Known regular inputs narrow that bound. */
        if (remaining == UINT64_MAX)
            remaining = ((uint64_t) 1 << (sizeof (off_t) * CHAR_BIT - 1)) - 1;
        while (remaining >= 10) {
            offset_width++;
            remaining /= 10;
        }
    }
    for (;;) {
        /* Short reads are normal for pipes. Retain each unmatched suffix
           until the other input supplies bytes, and only read(2) == 0 is EOF. */
        for (int j = 0; j < 2; j++) {
            if (used[j] == available[j] && !eof[j]) {
                ssize_t n;
                do { n = read (fd[j], buf[j], sizeof buf[j]); }
                while (n < 0 && errno == EINTR);
                if (n < 0) {
                    builtin_error ("read %s: %s", paths[j], strerror (errno));
                    rc = 2;
                    goto done;
                }
                used[j] = 0;
                available[j] = (size_t) n;
                eof[j] = n == 0;
            }
        }
        if (eof[0] || eof[1]) {
            if (eof[0] != eof[1]) {
                if (!sflag)
                    fprintf (stderr,
                             "cmp: EOF on %s after byte %" PRIu64 ", in line %" PRIu64 "\n",
                             eof[0] ? paths[0] : paths[1], off - 1, line);
                rc = 1;
            }
            break;
        }
        size_t n0 = available[0] - used[0], n1 = available[1] - used[1];
        size_t lim = n0 < n1 ? n0 : n1;
        for (size_t i = 0; i < lim; i++) {
            unsigned char a = buf[0][used[0] + i], b = buf[1][used[1] + i];
            if (a != b) {
                if (lflag) {
                    printf ("%*" PRIu64 " %3o %3o\n",
                            offset_width, off + (uint64_t) i,
                            (unsigned) a, (unsigned) b);
                } else {
                    if (!sflag)
                        printf ("%s %s differ: char %" PRIu64 ", line %" PRIu64 "\n",
                                paths[0], paths[1], off + (uint64_t) i, line);
                    rc = 1;
                    goto done;
                }
                rc = 1;
            }
            if (a == '\n') line++;
        }
        off += (uint64_t) lim;
        used[0] += lim;
        used[1] += lim;
        if (ferror (stdout)) break;
    }
done:
    if (owned[0]) close (fd[0]);
    if (owned[1]) close (fd[1]);
    if (fflush (stdout) == EOF || ferror (stdout)) {
        builtin_error ("write error: %s", strerror (errno ? errno : EIO));
        clearerr (stdout);
        rc = 2;
    }
    return rc;
}

char *cmp_doc[] = {
    "Byte-compare two files.",
    "",
    "    bashcmp [-l|-s] FILE1 FILE2 [SKIP1 [SKIP2]]",
    "        Default: print 'FILE1 FILE2 differ: char N, line M' on first",
    "        diff. Exit 0 (same), 1 (differ), 2 (error).",
    "    -l   list every diff as 'offset oct1 oct2'",
    "    -s   silent: only exit code",
    "    SKIP — skip leading bytes (default 0).",
    "",
    "Either file may be '-' to read stdin (but only one).",
    (char *)NULL
};

struct builtin bashcmp_struct = {
    "bashcmp",
    cmp_builtin,
    BUILTIN_ENABLED,
    cmp_doc,
    "bashcmp [-ls] FILE1 FILE2 [SKIP1 [SKIP2]]",
    0
};
