/* bashreadlink.c — POSIX readlink + GNU realpath modes.
 *
 * Phase S of bash-os POSIX gap-fillers.
 *
 *   bashreadlink [-n] PATH
 *       Default: readlink(2). Print symlink target. PATH must itself
 *       be a symlink, or rc=1.
 *   bashreadlink -f [-n] PATH
 *       Canonicalize: resolve all components except optionally the
 *       last (so reading a -f path of a soon-to-be-created file
 *       works). Last component may not exist.
 *   bashreadlink -e [-n] PATH
 *       Like -f but every component (including last) must exist.
 *   bashreadlink -m [-n] PATH
 *       Canonicalize without existence requirements (purely lexical
 *       resolution + existing-prefix follow).
 *
 *   -n      do not emit trailing newline
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
#include <limits.h>
#include <sys/stat.h>

#include "loadables.h"

enum { MODE_PLAIN, MODE_F, MODE_E, MODE_M };

/* Emit S, then the line delimiter DELIM (newline, or NUL under -z) unless
   EMIT_DELIM is 0 (the -n / --no-newline case suppresses it entirely). */
static int
brl_emit (const char *s, int emit_delim, char delim)
{
    size_t n = strlen (s);
    if (n && write (STDOUT_FILENO, s, n) < 0) {
        builtin_error ("write: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (emit_delim && write (STDOUT_FILENO, &delim, 1) < 0) {
        builtin_error ("write: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
brl_append_component (char *out, size_t outsz, const char *comp)
{
    if (comp[0] == '\0' || strcmp (comp, ".") == 0)
        return 0;
    if (strcmp (comp, "..") == 0) {
        size_t len = strlen (out);
        if (len == 0) {
            if (outsz < 2) { errno = ENAMETOOLONG; return -1; }
            strcpy (out, "/");
            return 0;
        }
        while (len > 1 && out[len - 1] == '/')
            out[--len] = '\0';
        char *slash = strrchr (out, '/');
        if (slash == NULL || slash == out)
            strcpy (out, "/");
        else
            *slash = '\0';
        return 0;
    }

    size_t len = strlen (out);
    size_t clen = strlen (comp);
    int need_slash = (len == 0 || out[len - 1] != '/');
    if (len + (size_t) need_slash + clen >= outsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (need_slash)
        strcat (out, "/");
    strcat (out, comp);
    return 0;
}

static int
brl_make_child (char *out, size_t outsz, const char *base, const char *comp)
{
    size_t blen = strlen (base);
    size_t clen = strlen (comp);
    int need_slash = (blen == 0 || base[blen - 1] != '/');
    if (blen + (size_t) need_slash + clen >= outsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    strcpy (out, base);
    if (need_slash)
        strcat (out, "/");
    strcat (out, comp);
    return 0;
}

static char *
brl_join_rest (const char *target, const char *remaining)
{
    while (*remaining == '/')
        remaining++;
    size_t tlen = strlen (target);
    size_t rlen = strlen (remaining);
    size_t need = tlen + (rlen ? 1 + rlen : 0) + 1;
    char *joined = malloc (need);
    if (!joined)
        return NULL;
    strcpy (joined, target);
    if (rlen) {
        strcat (joined, "/");
        strcat (joined, remaining);
    }
    return joined;
}

static char *
brl_strdup_without_trailing_slashes (const char *path)
{
    size_t len = strlen (path);
    while (len > 1 && path[len - 1] == '/')
        len--;
    char *copy = malloc (len + 1);
    if (!copy)
        return NULL;
    memcpy (copy, path, len);
    copy[len] = '\0';
    return copy;
}

static int
brl_resolve_canonical (const char *path, char *out, size_t outsz,
                       int require_existing_prefix)
{
    char *rest = brl_strdup_without_trailing_slashes (path);
    if (!rest) {
        errno = ENOMEM;
        return -1;
    }

    if (rest[0] == '/') {
        if (outsz < 2) {
            free (rest);
            errno = ENAMETOOLONG;
            return -1;
        }
        strcpy (out, "/");
    } else if (realpath (".", out) == NULL) {
        free (rest);
        return -1;
    }

    char *cursor = rest;
    int symlinks = 0;
    while (1) {
        while (*cursor == '/')
            cursor++;
        if (*cursor == '\0')
            break;

        const char *start = cursor;
        while (*cursor && *cursor != '/')
            cursor++;
        size_t clen = (size_t) (cursor - start);
        if (clen >= PATH_MAX) {
            free (rest);
            errno = ENAMETOOLONG;
            return -1;
        }
        char comp[PATH_MAX];
        memcpy (comp, start, clen);
        comp[clen] = '\0';

        if (comp[0] == '\0' || strcmp (comp, ".") == 0)
            continue;
        if (strcmp (comp, "..") == 0) {
            if (brl_append_component (out, outsz, comp) < 0) {
                free (rest);
                return -1;
            }
            continue;
        }

        char candidate[PATH_MAX];
        if (brl_make_child (candidate, sizeof candidate, out, comp) < 0) {
            free (rest);
            return -1;
        }

        struct stat st;
        int is_last;
        const char *remaining = cursor;
        while (*remaining == '/')
            remaining++;
        is_last = (*remaining == '\0');

        if (lstat (candidate, &st) == 0 && S_ISLNK (st.st_mode)) {
            char target[PATH_MAX];
            ssize_t n = readlink (candidate, target, sizeof target - 1);
            if (n < 0) {
                free (rest);
                return -1;
            }
            target[n] = '\0';
            if (++symlinks > 40) {
                free (rest);
                errno = ELOOP;
                return -1;
            }
            char *joined = brl_join_rest (target, cursor);
            if (!joined) {
                free (rest);
                errno = ENOMEM;
                return -1;
            }
            if (target[0] == '/')
                strcpy (out, "/");
            free (rest);
            rest = joined;
            cursor = rest;
            continue;
        }

        if (require_existing_prefix) {
            if (lstat (candidate, &st) < 0) {
                if (!is_last) {
                    free (rest);
                    return -1;
                }
            } else if (!is_last && !S_ISDIR (st.st_mode)) {
                free (rest);
                errno = ENOTDIR;
                return -1;
            }
        }

        if (brl_append_component (out, outsz, comp) < 0) {
            free (rest);
            return -1;
        }
    }

    free (rest);
    return 0;
}

static int
brl_resolve_f (const char *path, char *out, size_t outsz)
{
    if (realpath (path, out) != NULL) return 0;
    return brl_resolve_canonical (path, out, outsz, 1);
}

/* MODE_M: canonicalize lexically without existence requirements while still
   resolving symlinks whose pathnames can be observed with lstat/readlink. */
static int
brl_resolve_m (const char *path, char *out, size_t outsz)
{
    if (realpath (path, out) != NULL) return 0;
    return brl_resolve_canonical (path, out, outsz, 0);
}

/* Resolve one PATH per MODE into OUT. Returns 0 on success, -1 on failure
   (errno set by the underlying readlink/realpath/lstat). */
static int
brl_resolve_one (int mode, const char *path, char *out, size_t outsz)
{
    if (mode == MODE_PLAIN) {
        ssize_t n = readlink (path, out, outsz - 1);
        if (n < 0) return -1;
        out[n] = '\0';
        return 0;
    }
    if (mode == MODE_F)
        /* GNU `readlink -f`: canonicalize, last component may not exist. */
        return brl_resolve_f (path, out, outsz);
    if (mode == MODE_E) {
        struct stat st;
        if (realpath (path, out) == NULL) return -1;
        if (lstat (out, &st) < 0) return -1;
        return 0;
    }
    return brl_resolve_m (path, out, outsz); /* MODE_M */
}

int
readlink_builtin (WORD_LIST *list)
{
    int mode = MODE_PLAIN;
    int newline = 1;
    int quiet = 0;
    int verbose = 0;
    int zero = 0;
    int only_files = 0; /* set after "--" */

    /* GNU readlink accepts FILE... (multiple operands). Collect them; an
       upper bound is the number of WORD_LIST entries. */
    int nwords = 0;
    for (WORD_LIST *p = list; p; p = p->next) nwords++;
    const char **operands = (const char **) malloc ((size_t) (nwords + 1)
                                                     * sizeof *operands);
    if (!operands) { builtin_error ("malloc: %s", strerror (errno)); return EXECUTION_FAILURE; }
    int nop = 0;

    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (!only_files && strcmp (w, "--") == 0) { only_files = 1; continue; }
        if (only_files) { operands[nop++] = w; continue; }
        if (strcmp (w, "--help") == 0) { builtin_usage (); free (operands); return EXECUTION_SUCCESS; }
        if (strcmp (w, "--version") == 0 || strcmp (w, "-V") == 0) {
            puts ("bashreadlink 1.0 (bash-loadable)"); free (operands); return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--canonicalize") == 0) { mode = MODE_F; continue; }
        if (strcmp (w, "--canonicalize-existing") == 0) { mode = MODE_E; continue; }
        if (strcmp (w, "--canonicalize-missing") == 0) { mode = MODE_M; continue; }
        if (strcmp (w, "--no-newline") == 0) { newline = 0; continue; }
        if (strcmp (w, "--zero") == 0) { zero = 1; continue; }
        if (strcmp (w, "--quiet") == 0 || strcmp (w, "--silent") == 0) { quiet = 1; verbose = 0; continue; }
        if (strcmp (w, "--verbose") == 0) { quiet = 0; verbose = 1; continue; }
        if (w[0] == '-' && w[1]) {
            for (int i = 1; w[i]; i++) {
                switch (w[i]) {
                case 'f': mode = MODE_F; break;
                case 'e': mode = MODE_E; break;
                case 'm': mode = MODE_M; break;
                case 'n': newline = 0; break;
                case 'z': zero = 1; break;
                case 's':
                case 'q': quiet = 1; verbose = 0; break;
                case 'v': quiet = 0; verbose = 1; break;
                default:
                    builtin_error ("unknown flag: -%c", w[i]);
                    builtin_usage (); free (operands);
                    return EX_USAGE;
                }
            }
        } else {
            operands[nop++] = w;
        }
    }

    if (nop == 0) {
        builtin_error ("missing operand");
        builtin_usage (); free (operands);
        return EX_USAGE;
    }

    char delim = zero ? '\0' : '\n';
    int rc = EXECUTION_SUCCESS;
    char out[PATH_MAX];
    for (int i = 0; i < nop; i++) {
        if (brl_resolve_one (mode, operands[i], out, sizeof out) < 0) {
            if (verbose && !quiet)
                builtin_error ("%s: %s", operands[i], strerror (errno));
            rc = EXECUTION_FAILURE;
            continue;
        }
        if (brl_emit (out, newline, delim) != EXECUTION_SUCCESS) {
            free (operands);
            return EXECUTION_FAILURE;
        }
    }
    free (operands);
    return rc;
}

char *readlink_doc[] = {
    "Read a symbolic link or canonicalize a path.",
    "",
    "    bashreadlink [-n] PATH",
    "        Print symlink target (rc=1 if PATH is not a symlink).",
    "    bashreadlink -f [-n] PATH",
    "        Canonicalize; last component may not exist.",
    "    bashreadlink -e [-n] PATH",
    "        Canonicalize; every component must exist.",
    "    bashreadlink -m [-n] PATH",
    "        Canonicalize lexically; no existence requirements.",
    "    Multiple PATH operands are processed in turn (rc=1 if any fails).",
    "    -n, --no-newline",
    "        Omit the trailing delimiter.",
    "    -z, --zero",
    "        Terminate each output line with NUL instead of newline.",
    "    -f, --canonicalize",
    "    -e, --canonicalize-existing",
    "    -m, --canonicalize-missing",
    "        GNU/coreutils canonicalization aliases.",
    "    -q, --quiet, -s, --silent",
    "        Suppress diagnostics.",
    "    -v, --verbose",
    "        Diagnose readlink/canonicalization failures.",
    "    --help | --version",
    "        Show usage or version.",
    (char *)NULL
};

struct builtin bashreadlink_struct = {
    "bashreadlink",
    readlink_builtin,
    BUILTIN_ENABLED,
    readlink_doc,
    "bashreadlink [-fem] [-nz] PATH...",
    0
};
