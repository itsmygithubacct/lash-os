/* bashtruncate.c — POSIX truncate(1).
 *
 *   bashtruncate [-c] [-o] -s SIZE FILE [FILE...]
 *   bashtruncate [-c] [-o] -r REF [-s SIZE] FILE [FILE...]
 *
 *   -s SIZE     set size. A leading modifier selects relative behavior:
 *                 +N  extend by N        -N  shrink by N
 *                 <N  shrink to at most N (only if larger)
 *                 >N  grow to at least N  (only if smaller)
 *                 /N  round down to a multiple of N
 *                 %N  round up to a multiple of N
 *               SIZE accepts GNU multiplier suffixes: K/KiB=1024, kB/KB=1000,
 *               M/MiB, MB, G/GiB, GB, T, P (lowercase k/m/g/t also accepted,
 *               BSD-style). `c` (bytes) is kept as a bash-os extension.
 *   -c          do not create FILE if it does not exist (--no-create)
 *   -o          treat SIZE as a count of IO blocks, not bytes (--io-blocks)
 *   -r REF      take the base size from REF (--reference); with -s the
 *               modifier is applied relative to REF's size
 *
 * Mirrors GNU coreutils truncate (do_ftruncate). POSIX 2024 Tier 1.
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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>

#include "loadables.h"

extern char *truncate_doc[];

typedef enum { RM_ABS = 0, RM_REL, RM_MIN, RM_MAX, RM_RDN, RM_RUP } bt_relmode;

/* GNU truncate SIZE suffix multipliers. A bare letter is a power of 1024; a
   letter followed by "B" is a power of 1000; "iB" is the explicit binary form.
   GNU truncate accepts lowercase k/m/g/t (BSD compat) but NOT dd's b=512/c=1;
   we keep `c`=1 (bytes) as a documented bash-os extension. Returns the
   multiplier, or 0 if the suffix is unrecognized. */
static long long
bt_suffix_mult (const char *suf)
{
    static const struct { const char *s; long long m; } tab[] = {
        { "",    1LL },
        { "c",   1LL },                                        /* bash-os ext */
        { "kB",  1000LL },          { "KB",  1000LL },
        { "k",   1024LL },          { "K",   1024LL },          { "KiB", 1024LL },
        { "MB",  1000000LL },
        { "m",   1048576LL },       { "M",   1048576LL },       { "MiB", 1048576LL },
        { "GB",  1000000000LL },
        { "g",   1073741824LL },    { "G",   1073741824LL },    { "GiB", 1073741824LL },
        { "TB",  1000000000000LL },
        { "t",   1099511627776LL }, { "T",   1099511627776LL }, { "TiB", 1099511627776LL },
        { "PB",  1000000000000000LL },
        { "P",   1125899906842624LL }, { "PiB", 1125899906842624LL },
        { NULL, 0 }
    };
    for (int i = 0; tab[i].s; i++)
        if (!strcmp (suf, tab[i].s))
            return tab[i].m;
    return 0;
}

/* Parse a SIZE operand: an optional leading relational modifier followed by a
   signed/unsigned integer with an optional suffix. On success sets *mode and
   *mag (the magnitude; signed for +/-). Returns 0, or -1 on a bad number. */
static int
bt_parse_size (const char *s, bt_relmode *mode, long long *mag)
{
    *mode = RM_ABS;
    while (isspace ((unsigned char) *s)) s++;
    switch (*s) {
        case '<': *mode = RM_MAX; s++; break;   /* at most  */
        case '>': *mode = RM_MIN; s++; break;   /* at least */
        case '/': *mode = RM_RDN; s++; break;   /* round down to multiple */
        case '%': *mode = RM_RUP; s++; break;   /* round up to multiple */
        case '+': case '-': *mode = RM_REL; break;   /* sign kept for strtoll */
        default: break;
    }

    char *end = NULL;
    errno = 0;
    long long n = strtoll (s, &end, 10);
    if (end == s || errno)
        return -1;

    long long mult = bt_suffix_mult (end);
    if (mult == 0)
        return -1;
    if (mult > 1) {
        long long an = n < 0 ? -n : n;
        if (an > 9223372036854775807LL / mult)   /* overflow guard */
            return -1;
        n *= mult;
    }
    *mag = n;
    return 0;
}

int
truncate_builtin (WORD_LIST *list)
{
    bt_relmode mode = RM_ABS;
    long long  mag = 0;
    int        got_size = 0;
    const char *ref = NULL;
    int        no_create = 0;
    int        block_mode = 0;

    /* Accept GNU long options alongside the short forms; bash's internal_getopt
       is short-only, so dispatch the long names manually. */
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        const char *sval = NULL;          /* -s / --size argument */
        const char *rval = NULL;          /* -r / --reference argument */

        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) {
            for (char **d = truncate_doc; *d; d++) puts (*d);
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version")) {
            puts ("bashtruncate 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-c") || !strcmp (w, "--no-create")) {
            no_create = 1; list = list->next; continue;
        }
        if (!strcmp (w, "-o") || !strcmp (w, "--io-blocks")) {
            block_mode = 1; list = list->next; continue;
        }
        if (!strcmp (w, "-s")) {
            if (!list->next) { builtin_error ("-s needs SIZE"); builtin_usage (); return EX_USAGE; }
            list = list->next; sval = list->word->word;
        } else if (!strncmp (w, "--size=", 7)) {
            sval = w + 7;
        } else if (!strcmp (w, "--size")) {
            if (!list->next) { builtin_error ("--size needs SIZE"); builtin_usage (); return EX_USAGE; }
            list = list->next; sval = list->word->word;
        } else if (!strcmp (w, "-r")) {
            if (!list->next) { builtin_error ("-r needs REF"); builtin_usage (); return EX_USAGE; }
            list = list->next; rval = list->word->word;
        } else if (!strncmp (w, "--reference=", 12)) {
            rval = w + 12;
        } else if (!strcmp (w, "--reference")) {
            if (!list->next) { builtin_error ("--reference needs REF"); builtin_usage (); return EX_USAGE; }
            list = list->next; rval = list->word->word;
        } else {
            builtin_error ("unknown flag: %s", w);
            builtin_usage ();
            return EX_USAGE;
        }

        if (sval) {
            if (bt_parse_size (sval, &mode, &mag) < 0) {
                builtin_error ("invalid number: %s", sval);
                builtin_usage ();
                return EX_USAGE;
            }
            if ((mode == RM_RDN || mode == RM_RUP) && mag == 0) {
                builtin_error ("division by zero");
                return EX_USAGE;
            }
            got_size = 1;
        }
        if (rval)
            ref = rval;
        list = list->next;
    }

    if (!ref && !got_size) {
        builtin_error ("you must specify either --size or --reference");
        builtin_usage ();
        return EX_USAGE;
    }
    /* GNU: a reference file combined with -s requires a relative modifier. */
    if (ref && got_size && mode == RM_ABS) {
        builtin_error ("you must specify a relative '--size' with '--reference'");
        builtin_usage ();
        return EX_USAGE;
    }
    if (!list) {
        builtin_error ("missing file operand");
        builtin_usage ();
        return EX_USAGE;
    }

    /* Resolve the reference base size (used as fsize for relative modes, and
       as the absolute target when only -r is given). */
    long long ref_size = -1;
    if (ref) {
        struct stat rst;
        if (stat (ref, &rst) < 0) {
            builtin_error ("cannot stat %s: %s", ref, strerror (errno));
            return EXECUTION_FAILURE;
        }
        ref_size = (long long) rst.st_size;
        if (!got_size) {           /* -r alone: absolute to the reference size */
            mode = RM_ABS;
            mag = ref_size;
        }
    }

    int rc = EXECUTION_SUCCESS;
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *path = p->word->word;
        int fd = open (path, O_WRONLY | (no_create ? 0 : O_CREAT) | O_CLOEXEC, 0666);
        if (fd < 0) {
            if (errno == ENOENT && no_create) continue;
            builtin_error ("cannot open %s for writing: %s", path, strerror (errno));
            rc = EXECUTION_FAILURE;
            continue;
        }

        struct stat st;
        int have_st = 0;
        long long blocks = 1;
        if (block_mode || mode != RM_ABS) {
            if (fstat (fd, &st) < 0) {
                builtin_error ("cannot fstat %s: %s", path, strerror (errno));
                close (fd); rc = EXECUTION_FAILURE; continue;
            }
            have_st = 1;
            if (block_mode && st.st_blksize > 0)
                blocks = (long long) st.st_blksize;
        }

        long long ssize;
        if (block_mode) {
            /* st_blksize is positive; mag * blocks must not wrap. */
            if (blocks > 1 && mag > 0 && mag > LLONG_MAX / blocks) {
                builtin_error ("overflow extending size of file %s", path);
                close (fd); rc = EXECUTION_FAILURE; continue;
            }
            if (blocks > 1 && mag < 0 && mag < LLONG_MIN / blocks) {
                builtin_error ("overflow extending size of file %s", path);
                close (fd); rc = EXECUTION_FAILURE; continue;
            }
            ssize = mag * blocks;
        } else
            ssize = mag;
        /* Base size for relative modes: the reference, else the file itself. */
        long long fsize = (ref_size >= 0) ? ref_size : (have_st ? (long long) st.st_size : 0);
        long long nsize = 0;
        int overflow = 0;
        switch (mode) {
            case RM_REL:
                if (ssize > 0 && fsize > LLONG_MAX - ssize)
                    overflow = 1;
                else if (ssize < 0 && fsize < LLONG_MIN - ssize)
                    overflow = 1;
                else
                    nsize = fsize + ssize;
                break;
            case RM_MIN: nsize = fsize > ssize ? fsize : ssize; break;   /* >= */
            case RM_MAX: nsize = fsize < ssize ? fsize : ssize; break;   /* <= */
            case RM_RDN: nsize = ssize ? fsize - fsize % ssize : fsize; break;
            case RM_RUP: {
                long long r = ssize ? fsize % ssize : 0;
                long long add = r ? ssize - r : 0;
                if (add > 0 && fsize > LLONG_MAX - add)
                    overflow = 1;
                else
                    nsize = fsize + add;
                break;
            }
            case RM_ABS:
            default:     nsize = ssize; break;
        }
        /* GNU: overflow on extend is an error and leaves the file alone.
           A relative shrink past zero is not overflow; it becomes empty. */
        if (!overflow && nsize < 0)
            nsize = 0;
        if (overflow || (long long) (off_t) nsize != nsize) {
            builtin_error ("overflow extending size of file %s", path);
            close (fd); rc = EXECUTION_FAILURE; continue;
        }

        if (ftruncate (fd, (off_t) nsize) < 0) {
            builtin_error ("cannot truncate %s: %s", path, strerror (errno));
            rc = EXECUTION_FAILURE;
        }
        close (fd);
    }
    return rc;
}

char *truncate_doc[] = {
    "Shrink or extend files to a given size (POSIX truncate).",
    "",
    "    bashtruncate [-c] [-o] -s SIZE FILE [FILE...]",
    "    bashtruncate [-c] [-o] -r REF [-s SIZE] FILE [FILE...]",
    "",
    "    -s, --size SIZE   target size. A leading modifier selects relative mode:",
    "                        +N extend   -N shrink   <N at most   >N at least",
    "                        /N round down to multiple   %N round up to multiple",
    "                      SIZE suffixes: K/KiB=1024, kB/KB=1000, M/MB, G/GB,",
    "                      T, P (lowercase k/m/g/t accepted; c = bytes)",
    "    -c, --no-create   do not create FILE if it is missing",
    "    -o, --io-blocks   treat SIZE as a number of IO blocks instead of bytes",
    "    -r, --reference REF   base the size on REF (with -s, relative to REF)",
    "    --help | --version",
    "",
    "Files smaller than the target gain holes (sparse).",
    (char *)NULL
};

struct builtin bashtruncate_struct = {
    "bashtruncate",
    truncate_builtin,
    BUILTIN_ENABLED,
    truncate_doc,
    "bashtruncate [-co] [-r REF] -s SIZE FILE... | -r REF FILE...",
    0
};
