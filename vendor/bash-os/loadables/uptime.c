/* SPDX-License-Identifier: MIT */
/* uptime.c — uptime(1) via /proc/uptime.
 *
 *   uptime [-p] [-s] [-h|--help|-V|--version]
 *
 *   -p   pretty: "up X hours, Y minutes"
 *   -s   since: print boot time as YYYY-MM-DD HH:MM:SS
 *   -h   help
 *   -V   version
 *
 * Default output mirrors uptime(1):
 *   HH:MM:SS up DAYS days, HH:MM,  N users,  load average: A, B, C
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

static const char *
bu_proc_path (const char *name, char *buf, size_t bufsz)
{
    const char *root = getenv ("BASHOS_PROC_ROOT");

    if (root && *root) {
        snprintf (buf, bufsz, "%s/%s", root, name);
        return buf;
    }
    snprintf (buf, bufsz, "/proc/%s", name);
    return buf;
}

static int
bu_read_uptime (double *up_secs, double *idle)
{
    char path[512];
    int fd = open (bu_proc_path ("uptime", path, sizeof path), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buf[256];
    ssize_t n = read (fd, buf, sizeof buf - 1);
    close (fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    return sscanf (buf, "%lf %lf", up_secs, idle) == 2 ? 0 : -1;
}

/* Exact boot time (epoch seconds) from /proc/stat's "btime" line — the same
   integer GNU `uptime -s` uses. Avoids the +/-1s rounding of now-uptime, which
   truncates the fractional /proc/uptime value and is read non-atomically.
   Scans line-by-line so the long "intr" line never truncates the search. */
static int
bu_read_btime (time_t *out)
{
    char path[512];
    FILE *fp = fopen (bu_proc_path ("stat", path, sizeof path), "re");
    if (!fp) return -1;
    char *line = NULL;
    size_t cap = 0;
    int rc = -1;
    while (getline (&line, &cap, fp) != -1) {
        if (strncmp (line, "btime ", 6) == 0) {
            long long v;
            if (sscanf (line + 6, "%lld", &v) == 1) { *out = (time_t) v; rc = 0; }
            break;
        }
    }
    free (line);
    fclose (fp);
    return rc;
}

static int
bu_read_loadavg (double l[3])
{
    char path[512];
    int fd = open (bu_proc_path ("loadavg", path, sizeof path), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buf[256];
    ssize_t n = read (fd, buf, sizeof buf - 1);
    close (fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    return sscanf (buf, "%lf %lf %lf", &l[0], &l[1], &l[2]) == 3 ? 0 : -1;
}

static int
bu_count_users (void)
{
    int fd = open ("/var/run/utmp", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    int n = 0;
    struct utmp u;
    while (read (fd, &u, sizeof u) == sizeof u)
        if (u.ut_type == USER_PROCESS) n++;
    close (fd);
    return n;
}

int
uptime_builtin (WORD_LIST *list)
{
    int pretty = 0, since = 0;
    while (list && list->word->word[0] == '-') {
        const char *w = list->word->word;
        if (!strcmp (w, "-h") || !strcmp (w, "--help")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        else if (!strcmp (w, "-V") || !strcmp (w, "--version")) {
            puts ("uptime 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        else if (!strcmp (w, "-p")) pretty = 1;
        else if (!strcmp (w, "-s")) since = 1;
        else { builtin_error ("unknown flag: %s", w); builtin_usage (); return EX_USAGE; }
        list = list->next;
    }
    if (list != NULL) {
        builtin_error ("unexpected operand: %s", list->word->word);
        builtin_usage ();
        return EX_USAGE;
    }
    double up_secs, idle;
    if (bu_read_uptime (&up_secs, &idle) < 0) {
        builtin_error ("read /proc/uptime: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    long u = (long) up_secs;
    long days = u / 86400;
    long hh = (u % 86400) / 3600;
    long mm = (u % 3600) / 60;

    if (since) {
        /* Prefer the exact /proc/stat btime (GNU uptime -s); fall back to
           now - uptime if /proc/stat lacks it. */
        time_t boot;
        if (bu_read_btime (&boot) < 0)
            boot = time (NULL) - (time_t) up_secs;
        struct tm tm;
        localtime_r (&boot, &tm);
        char buf[32];
        strftime (buf, sizeof buf, "%Y-%m-%d %H:%M:%S", &tm);
        puts (buf);
        return EXECUTION_SUCCESS;
    }
    if (pretty) {
        if (days > 0)
            printf ("up %ld day%s, %ld hour%s, %ld minute%s\n",
                    days, days == 1 ? "" : "s",
                    hh, hh == 1 ? "" : "s",
                    mm, mm == 1 ? "" : "s");
        else if (hh > 0)
            printf ("up %ld hour%s, %ld minute%s\n",
                    hh, hh == 1 ? "" : "s",
                    mm, mm == 1 ? "" : "s");
        else
            printf ("up %ld minute%s\n", mm, mm == 1 ? "" : "s");
        return EXECUTION_SUCCESS;
    }

    /* Default uptime(1) format. */
    time_t now = time (NULL);
    struct tm tm;
    localtime_r (&now, &tm);
    char timebuf[16];
    strftime (timebuf, sizeof timebuf, "%H:%M:%S", &tm);

    int users = bu_count_users ();
    double load[3] = { 0, 0, 0 };
    bu_read_loadavg (load);

    if (days > 0)
        printf (" %s up %ld day%s, %2ld:%02ld,  %d user%s,  load average: %.2f, %.2f, %.2f\n",
                timebuf, days, days == 1 ? "" : "s", hh, mm,
                users, users == 1 ? "" : "s",
                load[0], load[1], load[2]);
    else
        printf (" %s up %2ld:%02ld,  %d user%s,  load average: %.2f, %.2f, %.2f\n",
                timebuf, hh, mm,
                users, users == 1 ? "" : "s",
                load[0], load[1], load[2]);
    return EXECUTION_SUCCESS;
}

char *uptime_doc[] = {
    "Show system uptime + load (reads /proc/uptime + /proc/loadavg).",
    "",
    "    uptime [-p] [-s] [-h|--help|-V|--version]",
    "",
    "    -p   pretty: \"up X hours, Y minutes\"",
    "    -s   since: print boot timestamp (YYYY-MM-DD HH:MM:SS)",
    "    -h   show this help",
    "    -V   show version",
    "",
    "Default mirrors classic uptime(1) format with current time, days/HH:MM",
    "uptime, user count (from /var/run/utmp), and 1/5/15-min load avgs.",
    (char *)NULL
};

struct builtin uptime_struct = {
    "uptime",
    uptime_builtin,
    BUILTIN_ENABLED,
    uptime_doc,
    "uptime [-p] [-s] [-h|--help|-V|--version]",
    0
};
