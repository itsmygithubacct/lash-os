/* SPDX-License-Identifier: MIT */
/* fstrim.c — discard unused filesystem blocks via FITRIM.
 *
 * A pragmatic util-linux fstrim(8) subset:
 *   fstrim [-n|--dry-run] [-v] [--quiet-unsupported] MOUNTPOINT
 *   fstrim -a|-A [-n|--dry-run] [-t TYPES]
 *   fstrim -I FILE [-n|--dry-run]
 *
 * The real FITRIM ioctl is gated by root. Dry-run, help, version and
 * argument validation are non-destructive.
 *
 * --- LICENSE --- MIT, same boilerplate as the other bash-os loadables.
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
#include <stdint.h>
#include <limits.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/fs.h>

#include "loadables.h"

#ifndef FITRIM
#  define FITRIM _IOWR('X', 121, struct fstrim_range)
#endif

#ifndef O_CLOEXEC
#  define O_CLOEXEC 0
#endif

#define BF_LINE_MAX 8192

typedef struct {
    int all;
    int fstab;
    int from_list;
    int dry_run;
    int verbose;
    int quiet_unsupported;
    uint64_t start;
    uint64_t len;
    uint64_t minlen;
    const char *types;
} bf_opts;

typedef struct {
    char **v;
    int n;
    int cap;
} bf_targets;

static void
bf_usage (FILE *out)
{
    fputs ("\nUsage:\n", out);
    fputs (" fstrim [options] <-A|-a|mount point>\n\n", out);
    fputs ("Discard unused blocks on a mounted filesystem.\n\n", out);
    fputs ("Options:\n", out);
    fputs (" -a, --all                trim mounted filesystems\n", out);
    fputs (" -A, --fstab              trim filesystems from /etc/fstab\n", out);
    fputs (" -I, --listed-in <list>   trim filesystems listed in specified files\n", out);
    fputs (" -o, --offset <num>       the offset in bytes to start discarding from\n", out);
    fputs (" -l, --length <num>       the number of bytes to discard\n", out);
    fputs (" -m, --minimum <num>      the minimum extent length to discard\n", out);
    fputs (" -t, --types <list>       limit the set of filesystem types\n", out);
    fputs (" -v, --verbose            print number of discarded bytes\n", out);
    fputs ("     --quiet-unsupported  suppress error messages if trim unsupported\n", out);
    fputs (" -n, --dry-run            does everything, but trim\n\n", out);
    fputs (" -h, --help          display this help\n", out);
    fputs (" -V, --version       display version\n", out);
}

static int
bf_targets_add (bf_targets *t, const char *s)
{
    if (t->n == t->cap) {
        int ncap = t->cap ? t->cap * 2 : 16;
        char **nv = realloc (t->v, (size_t) ncap * sizeof *nv);
        if (!nv)
            return -1;
        t->v = nv;
        t->cap = ncap;
    }
    t->v[t->n] = strdup (s);
    if (!t->v[t->n])
        return -1;
    t->n++;
    return 0;
}

static void
bf_targets_free (bf_targets *t)
{
    for (int i = 0; i < t->n; i++)
        free (t->v[i]);
    free (t->v);
    t->v = NULL;
    t->n = t->cap = 0;
}

static void
bf_unescape (char *s)
{
    char *r = s, *w = s;
    while (*r) {
        if (r[0] == '\\' && r[1] >= '0' && r[1] <= '7'
            && r[2] >= '0' && r[2] <= '7'
            && r[3] >= '0' && r[3] <= '7') {
            *w++ = (char) (((r[1] - '0') << 6) | ((r[2] - '0') << 3) | (r[3] - '0'));
            r += 4;
        } else {
            *w++ = *r++;
        }
    }
    *w = '\0';
}

static int
bf_type_selected (const bf_opts *o, const char *type)
{
    if (!o->types || !*o->types)
        return 1;
    char buf[512];
    size_t n = strlen (o->types);
    if (n >= sizeof buf)
        n = sizeof buf - 1;
    memcpy (buf, o->types, n);
    buf[n] = '\0';

    char *save = NULL;
    for (char *tok = strtok_r (buf, ",", &save); tok; tok = strtok_r (NULL, ",", &save)) {
        while (*tok && isspace ((unsigned char) *tok)) tok++;
        size_t l = strlen (tok);
        while (l && isspace ((unsigned char) tok[l - 1])) tok[--l] = '\0';
        if (strcmp (tok, type) == 0)
            return 1;
    }
    return 0;
}

static int
bf_collect_mounts (const bf_opts *o, bf_targets *targets)
{
    FILE *f = fopen ("/proc/self/mounts", "r");
    if (!f) {
        fprintf (stderr, "fstrim: open /proc/self/mounts: %s\n", strerror (errno));
        return EXECUTION_FAILURE;
    }

    char line[BF_LINE_MAX];
    while (fgets (line, sizeof line, f)) {
        char *save = NULL;
        char *src = strtok_r (line, " \t\n", &save);
        char *mp = strtok_r (NULL, " \t\n", &save);
        char *type = strtok_r (NULL, " \t\n", &save);
        (void) src;
        if (!mp || !type)
            continue;
        bf_unescape (mp);
        bf_unescape (type);
        if (!bf_type_selected (o, type))
            continue;
        if (bf_targets_add (targets, mp) < 0) {
            fclose (f);
            fprintf (stderr, "fstrim: allocation failure\n");
            return EXECUTION_FAILURE;
        }
    }
    fclose (f);
    return EXECUTION_SUCCESS;
}

static int
bf_collect_fstab (const char *path, bf_targets *targets)
{
    FILE *f = fopen (path, "r");
    if (!f) {
        fprintf (stderr, "fstrim: cannot open %s: %s\n", path, strerror (errno));
        return EXECUTION_FAILURE;
    }

    char line[BF_LINE_MAX];
    while (fgets (line, sizeof line, f)) {
        char *p = line;
        while (*p && isspace ((unsigned char) *p)) p++;
        if (*p == '\0' || *p == '#')
            continue;
        char *save = NULL;
        char *first = strtok_r (p, " \t\n", &save);
        char *second = strtok_r (NULL, " \t\n", &save);
        const char *mp = second ? second : first;
        if (mp && strcmp (mp, "none") != 0) {
            if (bf_targets_add (targets, mp) < 0) {
                fclose (f);
                fprintf (stderr, "fstrim: allocation failure\n");
                return EXECUTION_FAILURE;
            }
        }
    }
    fclose (f);
    return EXECUTION_SUCCESS;
}

static int
bf_parse_size (const char *s, uint64_t *out)
{
    if (!s || !*s)
        return -1;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull (s, &end, 10);
    if (errno || end == s)
        return -1;

    uint64_t mult = 1;
    if (*end) {
        if (!strcasecmp (end, "b"))
            mult = 1;
        else if (!strcasecmp (end, "k") || !strcasecmp (end, "kb") || !strcasecmp (end, "kib"))
            mult = 1024ULL;
        else if (!strcasecmp (end, "m") || !strcasecmp (end, "mb") || !strcasecmp (end, "mib"))
            mult = 1024ULL * 1024ULL;
        else if (!strcasecmp (end, "g") || !strcasecmp (end, "gb") || !strcasecmp (end, "gib"))
            mult = 1024ULL * 1024ULL * 1024ULL;
        else if (!strcasecmp (end, "t") || !strcasecmp (end, "tb") || !strcasecmp (end, "tib"))
            mult = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
        else
            return -1;
    }
    if (v > ULLONG_MAX / mult)
        return -1;
    *out = (uint64_t) (v * mult);
    return 0;
}

static int
bf_trim_one (const bf_opts *o, const char *mp)
{
    struct stat st;
    if (stat (mp, &st) < 0) {
        if (o->all || o->fstab || o->from_list) {
            if (errno == ENOENT || (o->dry_run && (errno == EACCES || errno == EPERM)))
                return EXECUTION_SUCCESS;
        }
        fprintf (stderr, "fstrim: stat of %s failed: %s\n", mp, strerror (errno));
        return EXECUTION_FAILURE;
    }

    if (o->dry_run) {
        printf ("%s: 0 B (dry run) trimmed\n", mp);
        return EXECUTION_SUCCESS;
    }

    if (geteuid () != 0) {
        fprintf (stderr, "fstrim: cannot open %s: Permission denied\n", mp);
        return EXECUTION_FAILURE;
    }

    int fd = open (mp, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf (stderr, "fstrim: cannot open %s: %s\n", mp, strerror (errno));
        return EXECUTION_FAILURE;
    }

    struct fstrim_range r;
    memset (&r, 0, sizeof r);
    r.start = o->start;
    r.len = o->len ? o->len : ULLONG_MAX;
    r.minlen = o->minlen;

    if (ioctl (fd, FITRIM, &r) < 0) {
        int e = errno;
        close (fd);
        if ((e == EOPNOTSUPP || e == ENOTTY) && o->quiet_unsupported)
            return EXECUTION_SUCCESS;
        if (e == EOPNOTSUPP || e == ENOTTY)
            fprintf (stderr, "fstrim: %s: the discard operation is not supported\n", mp);
        else
            fprintf (stderr, "fstrim: %s: FITRIM ioctl failed: %s\n", mp, strerror (e));
        return EXECUTION_FAILURE;
    }
    close (fd);

    if (o->verbose)
        printf ("%s: %llu B trimmed\n", mp, (unsigned long long) r.len);
    return EXECUTION_SUCCESS;
}

int
fstrim_builtin (WORD_LIST *list)
{
    bf_opts o;
    memset (&o, 0, sizeof o);
    bf_targets targets = {0};
    bf_targets listed_files = {0};
    int saw_target = 0;

    while (list && list->word && list->word->word
           && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "-h") || !strcmp (w, "--help")) {
            bf_usage (stdout);
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-V") || !strcmp (w, "--version")) {
            puts ("fstrim from bash-os util-linux parity");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-n") || !strcmp (w, "--dry-run")) {
            o.dry_run = 1; list = list->next; continue;
        }
        if (!strcmp (w, "-a") || !strcmp (w, "--all")) {
            o.all = 1; list = list->next; continue;
        }
        if (!strcmp (w, "-A") || !strcmp (w, "--fstab")) {
            o.fstab = 1; list = list->next; continue;
        }
        if (!strcmp (w, "-v") || !strcmp (w, "--verbose")) {
            o.verbose = 1; list = list->next; continue;
        }
        if (!strcmp (w, "--quiet-unsupported")) {
            o.quiet_unsupported = 1; list = list->next; continue;
        }
        if (!strcmp (w, "-o") || !strcmp (w, "--offset")
            || !strcmp (w, "-l") || !strcmp (w, "--length")
            || !strcmp (w, "-m") || !strcmp (w, "--minimum")
            || !strcmp (w, "-t") || !strcmp (w, "--types")
            || !strcmp (w, "-I") || !strcmp (w, "--listed-in")) {
            if (!list->next || !list->next->word || !list->next->word->word) {
                fprintf (stderr, "fstrim: option %s requires an argument\n", w);
                bf_usage (stderr);
                bf_targets_free (&targets);
                bf_targets_free (&listed_files);
                return EX_USAGE;
            }
            const char *arg = list->next->word->word;
            if (!strcmp (w, "-o") || !strcmp (w, "--offset")) {
                if (bf_parse_size (arg, &o.start) < 0) {
                    fprintf (stderr, "fstrim: invalid offset: %s\n", arg);
                    bf_targets_free (&targets);
                    bf_targets_free (&listed_files);
                    return EX_USAGE;
                }
            } else if (!strcmp (w, "-l") || !strcmp (w, "--length")) {
                if (bf_parse_size (arg, &o.len) < 0) {
                    fprintf (stderr, "fstrim: invalid length: %s\n", arg);
                    bf_targets_free (&targets);
                    bf_targets_free (&listed_files);
                    return EX_USAGE;
                }
            } else if (!strcmp (w, "-m") || !strcmp (w, "--minimum")) {
                if (bf_parse_size (arg, &o.minlen) < 0) {
                    fprintf (stderr, "fstrim: invalid minimum: %s\n", arg);
                    bf_targets_free (&targets);
                    bf_targets_free (&listed_files);
                    return EX_USAGE;
                }
            } else if (!strcmp (w, "-t") || !strcmp (w, "--types")) {
                o.types = arg;
            } else if (bf_targets_add (&listed_files, arg) < 0) {
                fprintf (stderr, "fstrim: allocation failure\n");
                bf_targets_free (&targets);
                bf_targets_free (&listed_files);
                return EXECUTION_FAILURE;
            }
            list = list->next->next;
            continue;
        }
        fprintf (stderr, "fstrim: unrecognized option '%s'\n", w);
        fputs ("Try 'fstrim --help' for more information.\n", stderr);
        bf_targets_free (&targets);
        bf_targets_free (&listed_files);
        return EX_USAGE;
    }

    for (; list; list = list->next) {
        if (list->word && list->word->word) {
            if (bf_targets_add (&targets, list->word->word) < 0) {
                fprintf (stderr, "fstrim: allocation failure\n");
                bf_targets_free (&targets);
                bf_targets_free (&listed_files);
                return EXECUTION_FAILURE;
            }
            saw_target = 1;
        }
    }

    if (o.all || o.fstab) {
        if (bf_collect_mounts (&o, &targets) != EXECUTION_SUCCESS) {
            bf_targets_free (&targets);
            bf_targets_free (&listed_files);
            return EXECUTION_FAILURE;
        }
    }
    for (int i = 0; i < listed_files.n; i++) {
        if (bf_collect_fstab (listed_files.v[i], &targets) != EXECUTION_SUCCESS) {
            bf_targets_free (&targets);
            bf_targets_free (&listed_files);
            return EXECUTION_FAILURE;
        }
    }
    if (listed_files.n > 0)
        o.from_list = 1;

    if (!saw_target && !o.all && !o.fstab && listed_files.n == 0) {
        fputs ("fstrim: no mountpoint specified\n", stderr);
        bf_targets_free (&targets);
        bf_targets_free (&listed_files);
        return EX_USAGE;
    }

    int rc = EXECUTION_SUCCESS;
    for (int i = 0; i < targets.n; i++) {
        if (bf_trim_one (&o, targets.v[i]) != EXECUTION_SUCCESS)
            rc = EXECUTION_FAILURE;
    }
    bf_targets_free (&targets);
    bf_targets_free (&listed_files);
    return rc;
}

char *fstrim_doc[] = {
    "Discard unused blocks on a mounted filesystem.",
    "",
    "    fstrim [options] <-A|-a|mount point>",
    "    fstrim -n MOUNTPOINT",
    "",
    "Uses FITRIM for real trims; dry-run/help/version are non-destructive.",
    (char *) NULL
};

struct builtin fstrim_struct = {
    "fstrim",
    fstrim_builtin,
    BUILTIN_ENABLED,
    fstrim_doc,
    "fstrim [options] <-A|-a|mount point>",
    0
};
