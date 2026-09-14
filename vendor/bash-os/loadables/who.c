/* SPDX-License-Identifier: MIT */
/* who.c — POSIX who(1) as a bash builtin.
 *
 *   who [-abdHqru] [--help|--version] [FILE]
 *
 * Reads /var/run/utmp (or FILE) and prints currently-logged-in users
 * in `who(1)` format. Mirrors `utmp dump`'s reader but with the
 * canonical `who` flag set. Closes the POSIX gap noted in
 * POSIX-CONFORMANCE-RESEARCH §4.1 (the row was "✗ — utmp dump
 * covers it functionally" — now answered with a real shim).
 *
 * Flags:
 *   -a   all login record types (USER + BOOT + RUN_LVL + DEAD + LOGIN + INIT)
 *   -b   show the boot-time record (BOOT_TIME)
 *   -d   show dead processes (DEAD_PROCESS)
 *   -H   print column headers
 *   -q   short form: usernames + count
 *   -r   show current run-level (RUN_LVL — shutdown/runlevel records)
 *   -u   include idle time + pid
 *
 * Filter semantics: -b, -d, -r, -a each set a bit in the record-type
 * mask and disable the implicit USER_PROCESS default. Multiple type
 * flags compose (e.g. `-bd` shows BOOT_TIME + DEAD_PROCESS). With no
 * type flag the default is USER_PROCESS only, matching prior behavior.
 * Corrupt ut_type values (out of the 0..9 enum range, e.g. from a
 * truncated/garbage fixture) never match any filter and are dropped
 * silently — see tests/bash-os/314-i04-who-record-types.sh.
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
#include <time.h>
#include <utmp.h>

#include "loadables.h"

#define BW_DEFAULT_PATH "/var/run/utmp"

int
who_builtin (WORD_LIST *list)
{
    int headers = 0, quiet = 0, with_idle = 0;
    unsigned int type_mask = 0;
    int explicit_filter = 0;
    const char *path = BW_DEFAULT_PATH;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version")) {
            puts ("who 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        for (const char *c = w + 1; *c; c++) {
            switch (*c) {
                case 'a':
                    type_mask |= (1u << USER_PROCESS) | (1u << BOOT_TIME)
                              |  (1u << RUN_LVL)      | (1u << DEAD_PROCESS)
                              |  (1u << LOGIN_PROCESS) | (1u << INIT_PROCESS);
                    explicit_filter = 1;
                    break;
                case 'b': type_mask |= (1u << BOOT_TIME);    explicit_filter = 1; break;
                case 'd': type_mask |= (1u << DEAD_PROCESS); explicit_filter = 1; break;
                case 'r': type_mask |= (1u << RUN_LVL);      explicit_filter = 1; break;
                case 'H': headers = 1; break;
                case 'q': quiet = 1; break;
                case 'u': with_idle = 1; break;
                default:
                    builtin_error ("unknown flag: -%c", *c);
                    builtin_usage ();
                    return EX_USAGE;
            }
        }
        list = list->next;
    }
    if (!explicit_filter) type_mask = (1u << USER_PROCESS);
    if (list) path = list->word->word;

    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        builtin_error ("%s: %s", path, strerror (errno));
        return EXECUTION_FAILURE;
    }

    if (headers && !quiet) {
        if (with_idle) printf ("%-8s %-12s %-19s %-16s %s\n", "USER", "LINE", "WHEN", "HOST", "PID");
        else           printf ("%-8s %-12s %-19s %s\n",       "USER", "LINE", "WHEN", "HOST");
    }

    struct utmp u;
    ssize_t n;
    int n_users = 0;
    /* Quiet mode: collect usernames into a single line. */
    while ((n = read (fd, &u, sizeof u)) == sizeof u) {
        /* Bounds-check ut_type before the shift: corrupt/garbage records
           often carry out-of-range values (e.g. 0xFFFF reinterpreted as
           short -1). The 0..31 window covers all legitimate utmp record
           types (0..9 on glibc/musl) with headroom against future enum
           additions, and keeps the shift well-defined. */
        if (u.ut_type < 0 || u.ut_type >= 32) continue;
        if (!(type_mask & (1u << u.ut_type))) continue;
        if (quiet) {
            printf ("%s%.*s", n_users ? " " : "", UT_NAMESIZE, u.ut_user);
            n_users++;
            continue;
        }
        char tbuf[32];
        time_t t = (time_t) u.ut_tv.tv_sec;
        struct tm tm;
        localtime_r (&t, &tm);
        strftime (tbuf, sizeof tbuf, "%Y-%m-%d %H:%M:%S", &tm);
        if (with_idle) {
            printf ("%-8.*s %-12.*s %s %-16.*s %d\n",
                    UT_NAMESIZE,  u.ut_user,
                    UT_LINESIZE,  u.ut_line,
                    tbuf,
                    UT_HOSTSIZE,  u.ut_host,
                    u.ut_pid);
        } else {
            printf ("%-8.*s %-12.*s %s %.*s\n",
                    UT_NAMESIZE,  u.ut_user,
                    UT_LINESIZE,  u.ut_line,
                    tbuf,
                    UT_HOSTSIZE,  u.ut_host);
        }
        n_users++;
    }
    close (fd);
    if (quiet) printf ("\n# users=%d\n", n_users);
    return EXECUTION_SUCCESS;
}

char *who_doc[] = {
    "List currently-logged-in users (POSIX who).",
    "",
    "    who [-abdHqru] [--help|--version] [FILE]",
    "",
    "    -a   all login record types (USER/BOOT/RUN_LVL/DEAD/LOGIN/INIT)",
    "    -b   show BOOT_TIME records",
    "    -d   show DEAD_PROCESS records",
    "    -H   print column headers",
    "    -q   short form: space-separated usernames + count",
    "    -r   show RUN_LVL records (shutdown / runlevel changes)",
    "    -u   include pid (idle-time approximation)",
    "    --help     show this help",
    "    --version  show version",
    "",
    "FILE defaults to /var/run/utmp. Identical reader to `utmp dump`",
    "but with the canonical `who` flag set. With no -a/-b/-d/-r flag the",
    "default is USER_PROCESS only. Multiple type flags compose (e.g. -bd",
    "shows BOOT_TIME and DEAD_PROCESS records).",
    (char *)NULL
};

struct builtin who_struct = {
    "who",
    who_builtin,
    BUILTIN_ENABLED,
    who_doc,
    "who [-abdHqru] [--help|--version] [FILE]",
    0
};
