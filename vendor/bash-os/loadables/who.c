/* SPDX-License-Identifier: MIT */
/* who.c — POSIX/GNU-style who as a bash builtin.
 * Independently implemented from private utmp fixtures and CLI observations.
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
#include <sys/stat.h>
#include "loadables.h"

#define BW_DEFAULT_PATH "/var/run/utmp"
#define BW_TYPE(t) (1u << (t))

/* Fixed-width utmp strings need not contain a terminating NUL. */
static void
bw_field (char *out, const char *in, size_t len)
{
    memcpy (out, in, len);
    out[len] = 0;
}

static int
bw_option (const char *word)
{
    static const struct { const char *name; int flag; } aliases[] = {
        {"--all", 'a'}, {"--boot", 'b'}, {"--dead", 'd'},
        {"--heading", 'H'}, {"--login", 'l'}, {"--process", 'p'},
        {"--count", 'q'}, {"--runlevel", 'r'}, {"--short", 's'},
        {"--time", 't'}, {"--mesg", 'T'}, {"--message", 'T'},
        {"--writable", 'T'}, {"--users", 'u'}, {NULL, 0}
    };
    for (int i = 0; aliases[i].name; i++)
        if (!strcmp (word, aliases[i].name)) return aliases[i].flag;
    return 0;
}

int
who_builtin (WORD_LIST *list)
{
    int headers = 0, quiet = 0, users = 0, all = 0, short_form = 0;
    int mesg = 0, my_line = 0, idle, pid, exits;
    unsigned int mask = 0;
    const char *path = BW_DEFAULT_PATH;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word, *flags = w + 1;
        char single[2] = {0, 0};
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { builtin_usage (); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "--version")) {
            puts ("who 1.0 (bash-loadable)"); return EXECUTION_SUCCESS;
        }
        if (w[1] == '-') {
            single[0] = bw_option (w);
            if (!single[0]) {
                builtin_error ("unrecognized option: %s", w);
                return EXECUTION_FAILURE;
            }
            flags = single;
        }
        for (const char *c = flags; *c; c++) {
            switch (*c) {
            case 'a':
                all = 1;
                mask |= BW_TYPE (USER_PROCESS) | BW_TYPE (BOOT_TIME)
                      | BW_TYPE (RUN_LVL) | BW_TYPE (DEAD_PROCESS)
                      | BW_TYPE (LOGIN_PROCESS) | BW_TYPE (INIT_PROCESS)
                      | BW_TYPE (NEW_TIME);
                break;
            case 'b': mask |= BW_TYPE (BOOT_TIME); break;
            case 'd': mask |= BW_TYPE (DEAD_PROCESS); break;
            case 'l': mask |= BW_TYPE (LOGIN_PROCESS); break;
            case 'p': mask |= BW_TYPE (INIT_PROCESS); break;
            case 'r': mask |= BW_TYPE (RUN_LVL); break;
            case 't': mask |= BW_TYPE (NEW_TIME); break;
            case 'u': users = 1; mask |= BW_TYPE (USER_PROCESS); break;
            case 'H': headers = 1; break;
            case 'q': quiet = 1; break;
            case 's': short_form = 1; break;
            case 'T': mesg = 1; break;
            case 'm': my_line = 1; break;
            default:
                builtin_error ("invalid option: -%c", *c);
                return EXECUTION_FAILURE;
            }
        }
        list = list->next;
    }
    if (list) {
        path = list->word->word;
        if (list->next) {
            builtin_error ("extra operand: %s", list->next->word->word);
            return EXECUTION_FAILURE;
        }
    }
    pid = mask != 0;
    idle = users || (mask & (BW_TYPE (DEAD_PROCESS) | BW_TYPE (LOGIN_PROCESS)
                           | BW_TYPE (RUN_LVL))) || all;
    exits = (mask & BW_TYPE (DEAD_PROCESS)) != 0;
    if (short_form && !all) idle = pid = 0;
    if (all) mesg = 1;
    if (!mask || quiet) mask = BW_TYPE (USER_PROCESS);

    if (headers && !quiet) {
        printf ("%-8s %s%-12s %-12s", "NAME", mesg ? "  " : "", "LINE", "TIME");
        if (idle) printf (" %-6s", "IDLE");
        if (pid) printf (" %10s", "PID");
        printf (" COMMENT%s\n", exits ? "  EXIT" : "");
    }

    /* GNU who treats unavailable explicit inputs and incomplete tails as empty.
       Use a private fd rather than changing libc's process-wide utmp state. */
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    const char *tty = my_line ? ttyname (STDIN_FILENO) : NULL;
    if (tty && !strncmp (tty, "/dev/", 5)) tty += 5;
    struct utmp u;
    int count = 0;
    while (fd >= 0 && read (fd, &u, sizeof u) == sizeof u) {
        if (u.ut_type < 0 || u.ut_type >= 32 || !(mask & BW_TYPE (u.ut_type))) continue;
        int is_user = u.ut_type == USER_PROCESS;
        if (is_user && !u.ut_user[0]) continue;
        char name[sizeof u.ut_user + 1], line[sizeof u.ut_line + 1];
        char host[sizeof u.ut_host + 1], id[sizeof u.ut_id + 1];
        bw_field (name, u.ut_user, sizeof u.ut_user);
        bw_field (line, u.ut_line, sizeof u.ut_line);
        bw_field (host, u.ut_host, sizeof u.ut_host);
        bw_field (id, u.ut_id, sizeof u.ut_id);
        if (my_line && (!tty || strcmp (tty, line))) continue;
        if (quiet) {
            printf ("%s%s", count++ ? " " : "", name);
            continue;
        }
        char tbuf[64] = "?", idlebuf[32] = "  ?";
        time_t t = (time_t) u.ut_tv.tv_sec;
        struct tm tm;
        if (localtime_r (&t, &tm)) strftime (tbuf, sizeof tbuf, "%b %e %H:%M", &tm);
        struct stat st;
        char terminal[sizeof u.ut_line + 6];
        snprintf (terminal, sizeof terminal, "/dev/%s", line);
        int have_stat = is_user && (idle || mesg) && stat (terminal, &st) == 0;
        char status = have_stat ? ((st.st_mode & S_IWGRP) ? '+' : '-') : '?';
        if (have_stat && idle) {
            time_t now = time (NULL);
            double age = difftime (now, st.st_atime);
            if (age < 60) strcpy (idlebuf, "  .");
            else if (age >= 86400) strcpy (idlebuf, " old");
            else snprintf (idlebuf, sizeof idlebuf, "%02d:%02d", (int)age / 3600, ((int)age / 60) % 60);
        }
        const char *display_name = is_user ? name : u.ut_type == LOGIN_PROCESS ? "LOGIN" : "";
        char runlevel[16];
        const char *display_line = line;
        if (u.ut_type == BOOT_TIME) display_line = "system boot";
        if (u.ut_type == NEW_TIME) display_line = "clock change";
        if (u.ut_type == RUN_LVL) {
            snprintf (runlevel, sizeof runlevel, "run-level %c", u.ut_pid & 255);
            display_line = runlevel;
        }
        printf ("%-8s ", display_name);
        if (mesg) printf ("%c ", is_user ? status : ' ');
        printf ("%-12s %s", display_line, tbuf);
        if (is_user) {
            if (idle) printf (" %-6s", idlebuf);
            if (pid) printf (" %10d", (int) u.ut_pid);
            if (host[0]) printf (" (%s)", host);
        } else if (u.ut_type == INIT_PROCESS || u.ut_type == LOGIN_PROCESS || u.ut_type == DEAD_PROCESS) {
            if (idle) printf (" %-6s", "");
            if (pid) printf (" %10d", (int) u.ut_pid);
            printf (" id=%s", id);
            if (u.ut_type == DEAD_PROCESS && exits)
                printf ("%*s term=%d exit=%d", (int)(5 - strlen (id)), "", u.ut_exit.e_termination, u.ut_exit.e_exit);
        } else if (u.ut_type == RUN_LVL) {
            int previous = (u.ut_pid >> 8) & 255;
            if (previous >= 32 && previous < 127) {
                if (idle) printf (" %-6s", "");
                if (pid) printf (" %10s", "");
                printf (" last=%c", previous);
            }
        }
        putchar ('\n');
    }
    if (fd >= 0) close (fd);
    if (quiet) printf ("\n# users=%d\n", count);
    return ferror (stdout) ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

char *who_doc[] = {
    "List users and selected records from a utmp file.",
    "",
    "    who [-abdHlmpqrstTu] [--help|--version] [FILE]",
    "",
    "    -a all; -b boot; -d dead; -l login; -p init; -r run-level; -t clock change",
    "    -H headings; -q usernames and count; -s short format; -T terminal status",
    "    -u users with idle time and pid; -m current terminal only",
    "    Long aliases: --all, --boot, --dead, --heading, --login, --process,",
    "    --count, --runlevel, --short, --time, --mesg, --message, --writable, --users.",
    "    FILE defaults to /var/run/utmp. Selection flags compose; -q selects users.",
    (char *)NULL
};

struct builtin who_struct = {
    "who", who_builtin, BUILTIN_ENABLED, who_doc,
    "who [-abdHlmpqrstTu] [--help|--version] [FILE]", 0
};
