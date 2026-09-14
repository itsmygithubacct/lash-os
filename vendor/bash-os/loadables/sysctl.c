/* SPDX-License-Identifier: MIT */
/* sysctl.c — sysctl(8) over /proc/sys file I/O.
 *
 *   sysctl KEY [KEY ...]              # read
 *   sysctl -w KEY=VALUE [...]         # write (procps also accepts
 *                                         # KEY=VALUE without -w)
 *   sysctl -a                         # dump all readable keys
 *   sysctl -p [FILE ...]              # load sysctl.conf-shaped files
 *   sysctl --system                   # load standard locations in
 *                                         # the procps-ng order
 *   sysctl -n                         # value only (suppress name = )
 *   sysctl -e                         # ignore unknown keys
 *   sysctl -q                         # quiet (no print on write)
 *
 * Source counterparts (read for shape, not ported):
 *   research/refs/procps-ng/src/sysctl.c
 *   research/refs/busybox/procps/sysctl.c
 *   research/refs/toybox/toys/posix/sysctl.c
 *
 * sysctl(2) the syscall was deprecated and removed in Linux 5.5; the
 * surviving interface is plain /proc/sys file I/O.  Key separator
 * is `.` on the user surface and `/` on the filesystem; the dots-to-
 * slashes mapping honours busybox-style nested-component lookups so
 * keys like `net.ipv4.conf.eth0.100.mc_forwarding` resolve correctly
 * when the on-disk path has `eth0.100/` as a single component.
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
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <regex.h>

#include "loadables.h"

#define BSC_PROC_SYS  "/proc/sys"
#define BSC_PATH_MAX  4096
#define BSC_VAL_MAX   65536

/* Flag bits — packed into a single int for easy threading. */
#define BSC_F_SHOW_KEYS      (1 << 0)
#define BSC_F_SHOW_KEY_ERROR (1 << 1)
#define BSC_F_QUIET          (1 << 2)
#define BSC_F_WRITE          (1 << 3)
#define BSC_F_PRELOAD        (1 << 4)
#define BSC_F_SYSTEM         (1 << 5)
#define BSC_F_DUMP_ALL       (1 << 6)
#define BSC_F_NAMES_ONLY     (1 << 7)

/* -r/--pattern: when set, only keys whose dotted name matches this
 * POSIX extended regex are read/written (procps-ng semantics). Reset at
 * each builtin invocation; valid only for the duration of one call. */
static const char *bsc_pattern = NULL;

/* Mirror procps-ng pattern_match(): REG_EXTENDED|REG_NOSUB over the dotted
 * key name. A pattern that fails to compile matches nothing. */
static int
bsc_pattern_match (const char *key)
{
    if (!bsc_pattern)
        return 1;
    regex_t re;
    if (regcomp (&re, bsc_pattern, REG_EXTENDED | REG_NOSUB) != 0)
        return 0;
    int rc = regexec (&re, key, 0, NULL, 0);
    regfree (&re);
    return rc == 0;
}

/* --- key/path mapping ----------------------------------------------- */

/* Mutate KEY in-place, swapping '.' <-> '/'.  Bounded by the first
 * '=' character (so KEY=VALUE forms are safe to call on too).
 *
 * busybox's variant tries the longest-prefix-with-dot first and falls
 * back to single-component splits when the path exists.  procps-ng's
 * variant is similar.  We implement the same end-anchored greedy walk:
 * each '.' from the right is provisionally promoted to '/' and the
 * resulting path is probed with access(F_OK); on hit, the '/' sticks
 * and we restart from the next position to the right.
 *
 * Caller MUST have prepended "/proc/sys/" to NAME before calling.
 */
static void
bsc_dots_to_slashes (char *name)
{
    char *cptr, *last_good, *end, *slash, end_ch;

    /* Bound at first '='. */
    end = strchrnul (name, '=');

    /* If the name contains both dots and slashes with the first dot
     * coming before the first slash, the user wrote raw mixed syntax
     * (e.g. `net.ipv4.conf.eth0/100.mc_forwarding`).  procps-ng treats
     * that as "swap dots and slashes everywhere".
     */
    slash = strchrnul (name, '/');
    if (slash < end && strchrnul (name, '.') < slash) {
        while (end != name) {
            end--;
            if (*end == '.') *end = '/';
            else if (*end == '/') *end = '.';
        }
        return;
    }

    /* Otherwise: greedy '.' -> '/' replacement, anchored from the right,
     * keeping replacements that resolve via access(F_OK). */
    end_ch = *end;
    *end = '.';     /* trick the loop into trying the full string */
    last_good = name - 1;

 again:
    cptr = end;
    while (cptr > last_good) {
        if (*cptr == '.') {
            *cptr = '\0';
            if (access (name, F_OK) == 0) {
                *cptr = '/';
                last_good = cptr;
                goto again;
            }
            *cptr = '.';
        }
        cptr--;
    }
    *end = end_ch;
}

/* Convert a filesystem path under /proc/sys back to dotted key form.
 *
 * Input:  "/proc/sys/kernel/ostype"
 * Output: "kernel.ostype"
 *
 * Writes into OUT (capacity OUTSZ).  Returns 0 on success, -1 on
 * overflow.
 */
static int
bsc_path_to_key (const char *path, char *out, size_t outsz)
{
    const char *p = path;
    size_t pfxlen = strlen (BSC_PROC_SYS "/");

    if (strncmp (p, BSC_PROC_SYS "/", pfxlen) != 0) {
        if (strlen (p) + 1 > outsz) return -1;
        strcpy (out, p);
        return 0;
    }
    p += pfxlen;
    size_t plen = strlen (p);
    if (plen + 1 > outsz) return -1;
    size_t i;
    for (i = 0; i < plen; i++)
        out[i] = (p[i] == '/') ? '.' : p[i];
    out[plen] = '\0';
    return 0;
}

/* --- per-key read / write ------------------------------------------- */

static int
bsc_is_known_readonly_key (const char *key)
{
    static const char *const readonly_keys[] = {
        "kernel.ostype",
        "kernel.osrelease",
        "kernel.version",
        NULL
    };
    int i;

    for (i = 0; readonly_keys[i]; i++)
        if (strcmp (key, readonly_keys[i]) == 0)
            return 1;
    return 0;
}

static int
bsc_read_key (const char *display_name, const char *fspath, int flags)
{
    /* -r/--pattern: skip keys whose dotted name doesn't match. */
    if (!bsc_pattern_match (display_name))
        return EXECUTION_SUCCESS;

    /* -N/--names: print only the key name (procps-ng). The value is not
     * read; the key must still exist (F_OK), so typos are reported. */
    if (flags & BSC_F_NAMES_ONLY) {
        if (access (fspath, F_OK) != 0) {
            if (flags & BSC_F_SHOW_KEY_ERROR)
                builtin_error ("'%s' is an unknown key", display_name);
            return EXECUTION_FAILURE;
        }
        printf ("%s\n", display_name);
        return EXECUTION_SUCCESS;
    }

    int fd = open (fspath, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            if (flags & BSC_F_SHOW_KEY_ERROR)
                builtin_error ("'%s' is an unknown key", display_name);
            return EXECUTION_FAILURE;
        }
        if (errno == EACCES) {
            /* write-only sysctls — silent under read, like procps. */
            return EXECUTION_FAILURE;
        }
        builtin_error ("read '%s': %s", display_name, strerror (errno));
        return EXECUTION_FAILURE;
    }

    char buf[BSC_VAL_MAX];
    ssize_t n = read (fd, buf, sizeof buf - 1);
    close (fd);
    if (n < 0) {
        builtin_error ("read '%s': %s", display_name, strerror (errno));
        return EXECUTION_FAILURE;
    }
    buf[n] = '\0';

    /* Multi-line settings (dev.cdrom.info, sunrpc.transports) emit one
     * "KEY = LINE\n" per line when keys are shown, matching busybox. */
    char *line = buf, *nl;
    int emitted = 0;
    while (line < buf + n) {
        nl = strchr (line, '\n');
        size_t llen = nl ? (size_t)(nl - line) : (size_t)(buf + n - line);
        if (flags & BSC_F_SHOW_KEYS)
            printf ("%s = %.*s\n", display_name, (int)llen, line);
        else
            printf ("%.*s\n", (int)llen, line);
        emitted = 1;
        if (!nl) break;
        line = nl + 1;
    }
    /* Trailing empty value still deserves a line with the key. */
    if (!emitted && (flags & BSC_F_SHOW_KEYS))
        printf ("%s = \n", display_name);
    return EXECUTION_SUCCESS;
}

static int
bsc_write_key (const char *display_name, const char *fspath,
               const char *value, int flags)
{
    /* -r/--pattern also gates writes (procps-ng filters set keys too). */
    if (!bsc_pattern_match (display_name))
        return EXECUTION_SUCCESS;

    int fd = open (fspath, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        if (bsc_is_known_readonly_key (display_name))
            builtin_error ("'%s' is a known read-only key", display_name);
        else if (errno == ENOENT && (flags & BSC_F_SHOW_KEY_ERROR))
            builtin_error ("'%s' is an unknown key", display_name);
        else if (errno != ENOENT)
            builtin_error ("write '%s': %s", display_name, strerror (errno));
        return EXECUTION_FAILURE;
    }
    size_t vlen = strlen (value);
    ssize_t w = write (fd, value, vlen);
    int saved = errno;
    close (fd);
    if (w < 0 || (size_t)w != vlen) {
        if (bsc_is_known_readonly_key (display_name))
            builtin_error ("'%s' is a known read-only key", display_name);
        else
            builtin_error ("write '%s': %s", display_name,
                           w < 0 ? strerror (saved) : "short write");
        return EXECUTION_FAILURE;
    }
    if (!(flags & BSC_F_QUIET)) {
        if (flags & BSC_F_NAMES_ONLY)
            printf ("%s\n", display_name);
        else if (flags & BSC_F_SHOW_KEYS)
            printf ("%s = %s\n", display_name, value);
        else
            printf ("%s\n", value);
    }
    return EXECUTION_SUCCESS;
}

/* --- recursive dump (-a) -------------------------------------------- */

static int
bsc_dump_dir (const char *path, int flags)
{
    DIR *d = opendir (path);
    if (!d) {
        if (errno == EACCES) return EXECUTION_SUCCESS; /* skip silently */
        builtin_error ("opendir '%s': %s", path, strerror (errno));
        return EXECUTION_FAILURE;
    }

    int rc = EXECUTION_SUCCESS;
    struct dirent *e;
    while ((e = readdir (d)) != NULL) {
        if (e->d_name[0] == '.' &&
            (e->d_name[1] == '\0' ||
             (e->d_name[1] == '.' && e->d_name[2] == '\0')))
            continue;

        char childpath[BSC_PATH_MAX];
        int n = snprintf (childpath, sizeof childpath, "%s/%s",
                          path, e->d_name);
        if (n < 0 || (size_t)n >= sizeof childpath) continue;

        struct stat st;
        if (lstat (childpath, &st) < 0) continue;

        if (S_ISDIR (st.st_mode)) {
            if (bsc_dump_dir (childpath, flags) != EXECUTION_SUCCESS)
                rc = EXECUTION_FAILURE;
        } else if (S_ISREG (st.st_mode)) {
            char keybuf[BSC_PATH_MAX];
            if (bsc_path_to_key (childpath, keybuf, sizeof keybuf) < 0)
                continue;
            /* Suppress per-key ENOENT/EACCES warnings during dump-all
             * — many entries are write-only. */
            int sub_flags = flags & ~BSC_F_SHOW_KEY_ERROR;
            (void) bsc_read_key (keybuf, childpath, sub_flags);
        }
    }
    closedir (d);
    return rc;
}

/* --- argv-side single-token apply ----------------------------------- */

static int
bsc_apply_token (char *raw, int flags)
{
    /* RAW = "KEY" or "KEY=VALUE" or "KEY = VALUE" (preload form).  We
     * normalise to: display_name = the dotted KEY portion; value =
     * pointer into RAW past '=' (write mode); fspath = "/proc/sys/.../KEY".
     *
     * RAW is mutated in place (NUL inserted at '='). */
    char *eq = strchr (raw, '=');
    int writing = (flags & BSC_F_WRITE) ? 1 : 0;
    char *value = NULL;

    if (eq) {
        writing = 1;
        *eq = '\0';
        value = eq + 1;
        /* Trim any trailing whitespace from key (preload-file slack). */
        char *k_end = eq - 1;
        while (k_end >= raw &&
               (*k_end == ' ' || *k_end == '\t')) {
            *k_end-- = '\0';
        }
        /* Trim leading whitespace from value. */
        while (*value == ' ' || *value == '\t') value++;
    } else if (writing) {
        builtin_error ("'%s' must be of the form name=value", raw);
        return EXECUTION_FAILURE;
    }

    if (raw[0] == '\0') {
        builtin_error ("empty key");
        return EXECUTION_FAILURE;
    }

    /* display_name = the dotted key as supplied (without value). */
    char display_name[BSC_PATH_MAX];
    if (strlen (raw) + 1 > sizeof display_name) {
        builtin_error ("key too long");
        return EXECUTION_FAILURE;
    }
    strcpy (display_name, raw);

    /* Build /proc/sys/<key-with-slashes>. */
    char fspath[BSC_PATH_MAX];
    int n = snprintf (fspath, sizeof fspath, "%s/%s", BSC_PROC_SYS, raw);
    if (n < 0 || (size_t)n >= sizeof fspath) {
        builtin_error ("key path too long: %s", raw);
        return EXECUTION_FAILURE;
    }
    bsc_dots_to_slashes (fspath);

    if (writing)
        return bsc_write_key (display_name, fspath, value, flags);
    else
        return bsc_read_key (display_name, fspath, flags);
}

/* --- preload file (-p / --system) ----------------------------------- */

static int
bsc_load_file (const char *path, int flags)
{
    FILE *fp = fopen (path, "re");
    if (!fp) {
        if (errno == ENOENT) return EXECUTION_SUCCESS; /* skip silently */
        builtin_error ("preload '%s': %s", path, strerror (errno));
        return EXECUTION_FAILURE;
    }
    char line[BSC_VAL_MAX];
    int rc = EXECUTION_SUCCESS;
    int load_flags = flags | BSC_F_WRITE;
    while (fgets (line, sizeof line, fp)) {
        /* Strip trailing newline. */
        size_t L = strlen (line);
        while (L > 0 && (line[L-1] == '\n' || line[L-1] == '\r'))
            line[--L] = '\0';
        /* Skip blank + comment (#, ;). */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '#' || *p == ';') continue;
        /* Hand to the per-token apply. */
        if (bsc_apply_token (p, load_flags) != EXECUTION_SUCCESS)
            rc = EXECUTION_FAILURE;
    }
    fclose (fp);
    return rc;
}

/* procps-ng --system load order (highest-precedence-wins is the OPPOSITE
 * of load order; later loads overwrite earlier ones, so the lowest-
 * precedence file is loaded FIRST):
 *
 *   /etc/sysctl.d/NAME.conf
 *   /run/sysctl.d/NAME.conf
 *   /usr/local/lib/sysctl.d/NAME.conf
 *   /usr/lib/sysctl.d/NAME.conf
 *   /lib/sysctl.d/NAME.conf
 *   /etc/sysctl.conf
 *
 * Files in the .d dirs are sorted lexically.
 */
static int
bsc_cmp_str (const void *a, const void *b)
{
    return strcmp (*(const char *const *)a, *(const char *const *)b);
}

static int
bsc_load_dir_sorted (const char *dir, int flags)
{
    DIR *d = opendir (dir);
    if (!d) return EXECUTION_SUCCESS;        /* missing = nothing to do */

    /* Collect *.conf names, then qsort. */
    char **names = NULL;
    size_t cap = 0, n = 0;
    struct dirent *e;
    while ((e = readdir (d)) != NULL) {
        size_t L = strlen (e->d_name);
        if (L < 6) continue;
        if (strcmp (e->d_name + L - 5, ".conf") != 0) continue;
        if (n == cap) {
            cap = cap ? cap * 2 : 16;
            char **nn = realloc (names, cap * sizeof *nn);
            if (!nn) { closedir (d); free (names); return EXECUTION_FAILURE; }
            names = nn;
        }
        names[n] = strdup (e->d_name);
        if (!names[n]) { closedir (d); for (size_t i=0;i<n;i++) free(names[i]); free(names); return EXECUTION_FAILURE; }
        n++;
    }
    closedir (d);

    if (n > 1)
        qsort (names, n, sizeof names[0], bsc_cmp_str);

    int rc = EXECUTION_SUCCESS;
    for (size_t i = 0; i < n; i++) {
        char path[BSC_PATH_MAX];
        int pn = snprintf (path, sizeof path, "%s/%s", dir, names[i]);
        if (pn > 0 && (size_t)pn < sizeof path) {
            if (bsc_load_file (path, flags) != EXECUTION_SUCCESS)
                rc = EXECUTION_FAILURE;
        }
        free (names[i]);
    }
    free (names);
    return rc;
}

static int
bsc_load_system (int flags)
{
    int rc = EXECUTION_SUCCESS;
    static const char *dirs[] = {
        "/etc/sysctl.d",
        "/run/sysctl.d",
        "/usr/local/lib/sysctl.d",
        "/usr/lib/sysctl.d",
        "/lib/sysctl.d",
        NULL
    };
    for (int i = 0; dirs[i]; i++)
        if (bsc_load_dir_sorted (dirs[i], flags) != EXECUTION_SUCCESS)
            rc = EXECUTION_FAILURE;
    if (bsc_load_file ("/etc/sysctl.conf", flags) != EXECUTION_SUCCESS)
        rc = EXECUTION_FAILURE;
    return rc;
}

/* --- builtin entry point -------------------------------------------- */

int
sysctl_builtin (WORD_LIST *list)
{
    /* Defaults match procps-ng: show keys + warn on unknown. */
    int flags = BSC_F_SHOW_KEYS | BSC_F_SHOW_KEY_ERROR;
    bsc_pattern = NULL;   /* reset -r/--pattern from any prior invocation */

    /* Phase 1: collect leading flags. */
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }

        if (!strcmp (w, "-h") || !strcmp (w, "--help")) {
            printf ("Usage: sysctl [-eNnq] [-r PATTERN] {-a | -p [FILE]... | "
                    "--system | [-w] KEY[=VAL]...}\n");
            printf ("  -a  dump all readable keys under /proc/sys\n");
            printf ("  -w  write mode (KEY=VAL is implicit -w too)\n");
            printf ("  -p  load conf file(s); default /etc/sysctl.conf\n");
            printf ("  --system  load standard sysctl.d locations in order\n");
            printf ("  -n, --values  print values without 'KEY = ' prefix\n");
            printf ("  -N, --names   print key names only (no values)\n");
            printf ("  -r, --pattern EXPR  only keys whose name matches EXPR (regex)\n");
            printf ("  -e  ignore 'unknown key' errors\n");
            printf ("  -q  quiet (do not echo on write)\n");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--system")) { flags |= BSC_F_SYSTEM; list = list->next; continue; }
        if (!strcmp (w, "-a") || !strcmp (w, "-A")) {
            flags |= BSC_F_DUMP_ALL; list = list->next; continue;
        }
        if (!strcmp (w, "-w")) { flags |= BSC_F_WRITE; list = list->next; continue; }
        if (!strcmp (w, "-p")) { flags |= BSC_F_PRELOAD; list = list->next; continue; }
        if (!strcmp (w, "-n") || !strcmp (w, "--values")) { flags &= ~BSC_F_SHOW_KEYS; list = list->next; continue; }
        if (!strcmp (w, "-N") || !strcmp (w, "--names")) { flags |= BSC_F_NAMES_ONLY; list = list->next; continue; }
        if (!strcmp (w, "-e")) { flags &= ~BSC_F_SHOW_KEY_ERROR; list = list->next; continue; }
        if (!strcmp (w, "-q")) { flags |= BSC_F_QUIET; list = list->next; continue; }
        if (!strcmp (w, "-r") || !strcmp (w, "--pattern")) {
            if (!list->next) { builtin_error ("-r needs a pattern"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            bsc_pattern = list->word->word;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--pattern=", 10)) { bsc_pattern = w + 10; list = list->next; continue; }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    /* Phase 2: dispatch. */
    if (flags & BSC_F_SYSTEM)
        return bsc_load_system (flags);

    if (flags & BSC_F_PRELOAD) {
        if (!list) {
            return bsc_load_file ("/etc/sysctl.conf", flags);
        }
        int rc = EXECUTION_SUCCESS;
        while (list) {
            if (bsc_load_file (list->word->word, flags) != EXECUTION_SUCCESS)
                rc = EXECUTION_FAILURE;
            list = list->next;
        }
        return rc;
    }

    if (flags & BSC_F_DUMP_ALL) {
        return bsc_dump_dir (BSC_PROC_SYS, flags);
    }

    if (!list) {
        builtin_error ("missing key (try -a or -p)");
        return EX_USAGE;
    }

    /* Per-token apply (read or write). */
    int rc = EXECUTION_SUCCESS;
    while (list) {
        /* Apply needs a writable copy: bsc_apply_token mutates buf. */
        const char *src = list->word->word;
        size_t L = strlen (src);
        if (L + 1 > BSC_PATH_MAX) {
            builtin_error ("token too long: %.40s...", src);
            rc = EXECUTION_FAILURE;
            list = list->next;
            continue;
        }
        char buf[BSC_PATH_MAX];
        memcpy (buf, src, L + 1);
        if (bsc_apply_token (buf, flags) != EXECUTION_SUCCESS)
            rc = EXECUTION_FAILURE;
        list = list->next;
    }
    return rc;
}

char *sysctl_doc[] = {
    "Read and write kernel parameters via /proc/sys.",
    "",
    "    sysctl KEY [KEY ...]            # read",
    "    sysctl [-w] KEY=VALUE [...]     # write",
    "    sysctl -a                       # dump all readable keys",
    "    sysctl -p [FILE ...]            # load sysctl.conf-shape file",
    "    sysctl --system                 # load standard locations",
    "",
    "Flags: -n/--values value-only, -N/--names names-only,",
    "       -r/--pattern EXPR filter keys by regex, -e ignore unknown,",
    "       -q quiet on write.",
    "",
    "KEY syntax: dotted (kernel.ostype) — internally mapped onto",
    "/proc/sys/kernel/ostype.  sysctl(2) the syscall was removed in",
    "Linux 5.5; this builtin uses plain file I/O.",
    (char *)NULL
};

struct builtin sysctl_struct = {
    "sysctl",
    sysctl_builtin,
    BUILTIN_ENABLED,
    sysctl_doc,
    "sysctl [-eNnq] [-r PATTERN] {-a | -p [FILE]... | --system | [-w] KEY[=VAL]...}",
    0
};
