/* bashtouch.c — POSIX touch(1) as a bash builtin.
 *
 * Phase A.5+ trailing item from POSIX-CONFORMANCE-RESEARCH §8.1: closes
 * the last high-impact POSIX gap (`touch` was the only Tier-1 item left
 * after Phase S landed cp/mv/cksum/cmp/link/readlink/timeout). Pure
 * `utimensat(2)` + create-if-missing semantics; same shape as
 * vendor/sbase/touch.c trimmed for bash-loadable conventions.
 *
 *   bashtouch [-acm] [--help|--version] [-d DATE | -r REF_FILE | -t TIME] FILE...
 *
 *     -a       set atime only
 *     -m       set mtime only
 *     -c       don't create if missing
 *     -r REF   copy atime+mtime from REF
 *     -t TIME  use TIME ([[CC]YY]MMDDhhmm[.SS])
 *     -d DATE  use DATE (ISO 8601: YYYY-MM-DDThh:mm:ss[Z])
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c / bashtail.c / bashlink.c.
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
#include <time.h>
#include <sys/stat.h>

#include "loadables.h"

/* Parse a -t/-d argument into a time_t. Supports the same length-keyed
   sbase format set: 8/10/11/12/13/15 (-t) and 19/20 (-d ISO). Returns 0
   on success, -1 on parse failure. */
static int
bt_parsetime (const char *str, time_t *out)
{
    struct tm cur_tm, t;
    time_t now;
    const char *fmt;
    int zulu = 0;
    size_t len = strlen (str);
    char buf[64];

    if (len >= sizeof buf) return -1;
    memcpy (buf, str, len + 1);

    memset (&t, 0, sizeof t);
    t.tm_isdst = -1;
    if (time (&now) == (time_t) -1) return -1;
    if (!localtime_r (&now, &cur_tm)) return -1;

    switch (len) {
        case 8:  t.tm_year = cur_tm.tm_year; fmt = "%m%d%H%M"; break;
        case 10: fmt = "%y%m%d%H%M"; break;
        case 11: t.tm_year = cur_tm.tm_year; fmt = "%m%d%H%M.%S"; break;
        case 12: fmt = "%Y%m%d%H%M"; break;
        case 13: fmt = "%y%m%d%H%M.%S"; break;
        case 15: fmt = "%Y%m%d%H%M.%S"; break;
        case 19: fmt = "%Y-%m-%dT%H:%M:%S"; break;
        case 20:
            if (buf[19] != 'Z') return -1;
            buf[19] = 0;
            zulu = 1;
            fmt = "%Y-%m-%dT%H:%M:%S";
            break;
        default: return -1;
    }
    char *end = strptime (buf, fmt, &t);
    if (!end || *end) return -1;
    struct tm parsed = t;
    *out = zulu ? timegm (&t) : mktime (&t);
    if (*out == (time_t) -1) return -1;

    struct tm roundtrip;
    if (zulu) {
        if (!gmtime_r (out, &roundtrip)) return -1;
    } else {
        if (!localtime_r (out, &roundtrip)) return -1;
    }
    if (roundtrip.tm_year != parsed.tm_year
        || roundtrip.tm_mon != parsed.tm_mon
        || roundtrip.tm_mday != parsed.tm_mday
        || roundtrip.tm_hour != parsed.tm_hour
        || roundtrip.tm_min != parsed.tm_min
        || roundtrip.tm_sec != parsed.tm_sec)
        return -1;
    return 0;
}

/* Map a --time=WORD value to atime/mtime selection (GNU touch): access /
   atime / use → atime; modify / mtime → mtime. Returns 0 on success and
   sets *a or *m; -1 on an unrecognized word. */
static int
bt_time_word (const char *w, int *a, int *m)
{
    if (!strcmp (w, "access") || !strcmp (w, "atime") || !strcmp (w, "use"))
        { *a = 1; return 0; }
    if (!strcmp (w, "modify") || !strcmp (w, "mtime"))
        { *m = 1; return 0; }
    return -1;
}

/* Apply `times` to `path`. Creates the file when missing and !cflag. When
   hflag is set (-h/--no-dereference) operate on a symlink itself rather than
   its target. Returns 0 on success, -1 on a fatal error (already reported). */
static int
bt_touch (const char *path, struct timespec times[2], int cflag, int hflag)
{
    if (utimensat (AT_FDCWD, path, times,
                   hflag ? AT_SYMLINK_NOFOLLOW : 0) == 0)
        return 0;
    if (errno != ENOENT) {
        builtin_error ("'%s': %s", path, strerror (errno));
        return -1;
    }
    if (cflag)
        return 0;
    int fd = open (path, O_WRONLY | O_CREAT | O_NOCTTY, 0666);
    if (fd < 0) {
        builtin_error ("create '%s': %s", path, strerror (errno));
        return -1;
    }
    int rc = futimens (fd, times);
    int saved = errno;
    close (fd);
    if (rc < 0) {
        errno = saved;
        builtin_error ("'%s': %s", path, strerror (errno));
        return -1;
    }
    return 0;
}

int
touch_builtin (WORD_LIST *list)
{
    int aflag = 0, mflag = 0, cflag = 0, hflag = 0;
    const char *ref = NULL;
    time_t fixed = 0;
    int have_fixed = 0;

    /* Hand-roll arg parsing to support both `-r REF` and `-rREF`,
       same idiom as bashtail.c. */
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version")) {
            puts ("bashtouch 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }

        /* GNU long-option aliases. */
        if (!strcmp (w, "--no-create")) { cflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--no-dereference")) { hflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--reference")) {
            if (!list->next) {
                builtin_error ("--reference needs FILE");
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            ref = list->word->word;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--reference=", 12)) {
            ref = w + 12;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--date") || !strncmp (w, "--date=", 7)) {
            const char *arg;
            if (w[6] == '=') {
                arg = w + 7;
            } else {
                if (!list->next) {
                    builtin_error ("--date needs argument");
                    builtin_usage ();
                    return EX_USAGE;
                }
                list = list->next;
                arg = list->word->word;
            }
            if (bt_parsetime (arg, &fixed) < 0) {
                builtin_error ("invalid time/date: %s", arg);
                builtin_usage ();
                return EX_USAGE;
            }
            have_fixed = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--time") || !strncmp (w, "--time=", 7)) {
            const char *arg;
            if (w[6] == '=') {
                arg = w + 7;
            } else {
                if (!list->next) {
                    builtin_error ("--time needs WORD");
                    builtin_usage ();
                    return EX_USAGE;
                }
                list = list->next;
                arg = list->word->word;
            }
            if (bt_time_word (arg, &aflag, &mflag) < 0) {
                builtin_error ("invalid argument '%s' for --time", arg);
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }

        /* -r REF / -rREF */
        if (!strcmp (w, "-r")) {
            if (!list->next) {
                builtin_error ("-r needs REF");
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            ref = list->word->word;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-r", 2) && w[2]) {
            ref = w + 2;
            list = list->next;
            continue;
        }

        /* -t TIME / -tTIME, -d DATE / -dDATE */
        if (!strcmp (w, "-t") || !strcmp (w, "-d")) {
            if (!list->next) {
                builtin_error ("%s needs argument", w);
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            if (bt_parsetime (list->word->word, &fixed) < 0) {
                builtin_error ("invalid time/date: %s", list->word->word);
                builtin_usage ();
                return EX_USAGE;
            }
            have_fixed = 1;
            list = list->next;
            continue;
        }
        if ((!strncmp (w, "-t", 2) || !strncmp (w, "-d", 2)) && w[2]) {
            if (bt_parsetime (w + 2, &fixed) < 0) {
                builtin_error ("invalid time/date: %s", w + 2);
                builtin_usage ();
                return EX_USAGE;
            }
            have_fixed = 1;
            list = list->next;
            continue;
        }

        if (!strncmp (w, "--", 2)) {
            builtin_error ("unknown flag: %s", w);
            builtin_usage ();
            return EX_USAGE;
        }

        /* Bundled short flags: -acm / -am / -c etc. */
        for (const char *p = w + 1; *p; p++) {
            switch (*p) {
                case 'a': aflag = 1; break;
                case 'm': mflag = 1; break;
                case 'c': cflag = 1; break;
                case 'h': hflag = 1; break;   /* --no-dereference */
                case 'f': break;              /* GNU compat: ignored */
                default:
                    builtin_error ("unknown flag: -%c", *p);
                    builtin_usage ();
                    return EX_USAGE;
            }
        }
        list = list->next;
    }

    if (!list) {
        builtin_error ("missing file operand");
        builtin_usage ();
        return EX_USAGE;
    }

    /* Default: both atime and mtime. */
    if (!aflag && !mflag) aflag = mflag = 1;

    /* Resolve the reference times. Precedence: -r > -t/-d > now. */
    struct timespec times[2] = {
        { .tv_sec = 0, .tv_nsec = UTIME_NOW },
        { .tv_sec = 0, .tv_nsec = UTIME_NOW },
    };
    if (ref) {
        struct stat st;
        if (stat (ref, &st) < 0) {
            builtin_error ("stat '%s': %s", ref, strerror (errno));
            return EXECUTION_FAILURE;
        }
        times[0] = st.st_atim;
        times[1] = st.st_mtim;
    } else if (have_fixed) {
        times[0].tv_sec = fixed; times[0].tv_nsec = 0;
        times[1].tv_sec = fixed; times[1].tv_nsec = 0;
    }
    if (!aflag) times[0].tv_nsec = UTIME_OMIT;
    if (!mflag) times[1].tv_nsec = UTIME_OMIT;

    int rc = EXECUTION_SUCCESS;
    for (WORD_LIST *p = list; p; p = p->next) {
        if (bt_touch (p->word->word, times, cflag, hflag) < 0)
            rc = EXECUTION_FAILURE;
    }
    return rc;
}

char *touch_doc[] = {
    "POSIX touch — change file timestamps.",
    "",
    "    bashtouch [-acm] [--help|--version] [-d DATE | -r REF | -t TIME] FILE...",
    "",
    "    -a        set access time only",
    "    -m        set modification time only",
    "    -c, --no-create      do not create FILE if it does not exist",
    "    -h, --no-dereference affect a symlink itself, not its target",
    "    -f        (ignored, for compatibility)",
    "    -r, --reference=REF  use REF's timestamps",
    "    -t TIME   use TIME ([[CC]YY]MMDDhhmm[.SS])",
    "    -d, --date=DATE      use DATE (ISO 8601: YYYY-MM-DDThh:mm:ss[Z])",
    "    --time=WORD          WORD=access|atime|use → -a; modify|mtime → -m",
    "    --help    show this help",
    "    --version show version",
    "",
    "Default behavior creates missing files and sets both timestamps to",
    "the current time. Default flag set is `-am` (both atime + mtime).",
    (char *)NULL
};

struct builtin bashtouch_struct = {
    "bashtouch",
    touch_builtin,
    BUILTIN_ENABLED,
    touch_doc,
    "bashtouch [-acm] [--help|--version] [-d DATE | -r REF | -t TIME] FILE...",
    0
};
