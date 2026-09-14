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
    if (errno == ERANGE || !end || end == s || *end)
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
    /* Try lseek; on pipe/stdin, fall back to read+discard. */
    if (lseek (fd, (off_t) n, SEEK_SET) >= 0) return 0;
    char buf[4096];
    while (n > 0) {
        size_t want = (n > sizeof buf) ? sizeof buf : (size_t) n;
        ssize_t r = read (fd, buf, want);
        if (r <= 0) {
            builtin_error ("skip in %s: %s", name,
                           r < 0 ? strerror (errno) : "premature EOF");
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
    if (bcm_open (paths[0], &fd[0]) < 0) return 2;
    if (bcm_open (paths[1], &fd[1]) < 0) { close (fd[0]); return 2; }

    if (skip[0] && bcm_skip (fd[0], skip[0], paths[0]) < 0) {
        if (fd[0] != STDIN_FILENO) close (fd[0]);
        if (fd[1] != STDIN_FILENO) close (fd[1]);
        return 2;
    }
    if (skip[1] && bcm_skip (fd[1], skip[1], paths[1]) < 0) {
        if (fd[0] != STDIN_FILENO) close (fd[0]);
        if (fd[1] != STDIN_FILENO) close (fd[1]);
        return 2;
    }

    unsigned char buf[2][8192];
    uint64_t off = 1, line = 1;
    int rc = 0;
    int eof[2] = { 0, 0 };
    for (;;) {
        ssize_t n0 = eof[0] ? 0 : read (fd[0], buf[0], sizeof buf[0]);
        ssize_t n1 = eof[1] ? 0 : read (fd[1], buf[1], sizeof buf[1]);
        if (n0 < 0) { builtin_error ("read %s: %s", paths[0], strerror (errno)); rc = 2; break; }
        if (n1 < 0) { builtin_error ("read %s: %s", paths[1], strerror (errno)); rc = 2; break; }
        if (n0 == 0) eof[0] = 1;
        if (n1 == 0) eof[1] = 1;

        ssize_t lim = (n0 < n1 ? n0 : n1);
        for (ssize_t i = 0; i < lim; i++) {
            if (buf[0][i] != buf[1][i]) {
                if (lflag) {
                    printf ("%" PRIu64 " %o %o\n",
                            off + (uint64_t) i,
                            (unsigned) buf[0][i],
                            (unsigned) buf[1][i]);
                } else if (!sflag) {
                    printf ("%s %s differ: char %" PRIu64 ", line %" PRIu64 "\n",
                            paths[0], paths[1],
                            off + (uint64_t) i, line);
                    if (fd[0] != STDIN_FILENO) close (fd[0]);
                    if (fd[1] != STDIN_FILENO) close (fd[1]);
                    return 1;
                }
                rc = 1;
            }
            if (buf[0][i] == '\n') line++;
        }
        off += (uint64_t) lim;

        /* Same-read length mismatch: the matched prefix is equal but this
           chunk returned fewer bytes for one file, i.e. the shorter file hit
           EOF first (final/short read on a regular file). Without this, two
           files that each fit in a single read but differ in length set both
           eof flags together below and the diagnostic was skipped. */
        if (rc != 2 && n0 != n1) {
            if (!sflag) {
                fprintf (stderr,
                         "cmp: EOF on %s after byte %" PRIu64 ", in line %" PRIu64 "\n",
                         (n0 < n1) ? paths[0] : paths[1], off - 1, line);
            }
            rc = (rc == 2) ? 2 : 1;
            break;
        }

        /* Length mismatch: shorter file reaches EOF first. */
        if (eof[0] != eof[1] || (eof[0] && eof[1])) {
            if (eof[0] != eof[1]) {
                if (!sflag) {
                    /* GNU cmp keeps the "cmp:" program prefix here (the
                       differ line above is unprefixed, matching GNU) and
                       appends the line number. */
                    fprintf (stderr,
                             "cmp: EOF on %s after byte %" PRIu64 ", in line %" PRIu64 "\n",
                             eof[0] ? paths[0] : paths[1],
                             off - 1, line);
                }
                rc = (rc == 2) ? 2 : 1;
            }
            break;
        }
        /* Buffers can also be unequal length within a chunk if one
           read returned fewer bytes — handle by detecting eof above. */
        if (n0 < (ssize_t) sizeof buf[0]) eof[0] = 1;
        if (n1 < (ssize_t) sizeof buf[1]) eof[1] = 1;
    }
    if (fd[0] != STDIN_FILENO) close (fd[0]);
    if (fd[1] != STDIN_FILENO) close (fd[1]);
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
