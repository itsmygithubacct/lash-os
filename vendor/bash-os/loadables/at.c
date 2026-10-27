/* SPDX-License-Identifier: MIT */
/* at.c - small at(1)-shaped scheduler loadable for bash-os.
 *
 *   at TIME      read a script from stdin and schedule it
 *   at -l        list queued jobs
 *   at -r JOBID  remove a queued job
 *   at -c JOBID  print a queued job's script
 *
 * Jobs live under ${BASHCRON_SPOOL_DIR:-/var/spool/cron}/atjobs.
 * TIME accepts now, noon, midnight, teatime, @EPOCH, EPOCH,
 * +N[s|m|h|d], or HH:MM.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "loadables.h"

static const char *
bat_spool_root (void)
{
    const char *s = getenv ("BASHCRON_SPOOL_DIR");
    return (s && *s) ? s : "/var/spool/cron";
}

static int
bat_mkdir_p (const char *path)
{
    char tmp[PATH_MAX];
    size_t len = strlen (path);
    if (len == 0 || len >= sizeof tmp)
        return -1;
    memcpy (tmp, path, len + 1);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir (tmp, 0700) < 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir (tmp, 0700) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int
bat_at_dir (char *buf, size_t buflen)
{
    if (snprintf (buf, buflen, "%s/atjobs", bat_spool_root ()) >= (int) buflen)
        return -1;
    return bat_mkdir_p (buf);
}

static int
bat_read_stdin (char **out, size_t *outlen)
{
    size_t cap = 4096, len = 0;
    char *buf = malloc (cap);
    if (!buf)
        return -1;
    for (;;) {
        if (len + 2048 + 1 > cap) {
            if (cap > SIZE_MAX / 2) { free (buf); errno = EOVERFLOW; return -1; }
            cap *= 2;
            char *nb = realloc (buf, cap);
            if (!nb) {
                free (buf);
                return -1;
            }
            buf = nb;
        }
        ssize_t n = read (STDIN_FILENO, buf + len, 2048);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { free (buf); return -1; }
        if (n == 0) break;
        len += (size_t) n;
    }
    buf[len] = '\0';
    *out = buf;
    *outlen = len;
    return 0;
}

static int
bat_parse_time (const char *s, time_t *out)
{
    time_t now = time (NULL);
    if (!s || !*s)
        return -1;
    if (!strcmp (s, "now")) {
        *out = now;
        return 0;
    }
    if (!strcmp (s, "noon") || !strcmp (s, "midnight") || !strcmp (s, "teatime")) {
        struct tm tm;
        localtime_r (&now, &tm);
        if (!strcmp (s, "noon")) {
            tm.tm_hour = 12;
            tm.tm_min = 0;
        } else if (!strcmp (s, "teatime")) {
            tm.tm_hour = 16;
            tm.tm_min = 0;
        } else {
            tm.tm_hour = 0;
            tm.tm_min = 0;
        }
        tm.tm_sec = 0;
        time_t t = mktime (&tm);
        if (t < now)
            t += 86400;
        *out = t;
        return 0;
    }
    if (s[0] == '@')
        s++;
    if (isdigit ((unsigned char)s[0])) {
        char *end = NULL;
        errno = 0;
        long long v = strtoll (s, &end, 10);
        if (end && *end == '\0') {
            if (errno == ERANGE || v < 0 || (long long) (time_t) v != v) return -1;
            *out = (time_t) v;
            return 0;
        }
    }
    if (s[0] == '+') {
        char *end = NULL;
        if (!isdigit ((unsigned char) s[1])) return -1;
        errno = 0;
        long long n = strtoll (s + 1, &end, 10);
        if (errno == ERANGE || end == s + 1 || n < 0)
            return -1;
        long mult = 1;
        if (*end == 'm') mult = 60;
        else if (*end == 'h') mult = 3600;
        else if (*end == 'd') mult = 86400;
        else if (*end == 's' || *end == '\0') mult = 1;
        else return -1;
        if (end[0] && end[1])
            return -1;
        if (now < 0 || (unsigned long long) n >
            ((unsigned long long) LLONG_MAX - (unsigned long long) now) / (unsigned long) mult)
            return -1;
        long long value = (long long) now + n * mult;
        if ((long long) (time_t) value != value) return -1;
        *out = (time_t) value;
        return 0;
    }
    char *hend, *mend;
    errno = 0;
    long hh = strtol (s, &hend, 10);
    if (errno || !isdigit ((unsigned char) *s) || *hend != ':' || hh < 0 || hh > 23 ||
        !isdigit ((unsigned char) hend[1])) return -1;
    long mm = strtol (hend + 1, &mend, 10);
    if (!errno && !*mend && mm >= 0 && mm <= 59) {
        struct tm tm;
        localtime_r (&now, &tm);
        tm.tm_hour = hh;
        tm.tm_min = mm;
        tm.tm_sec = 0;
        time_t t = mktime (&tm);
        if (t < now)
            t += 86400;
        *out = t;
        return 0;
    }
    return -1;
}

static int
bat_job_path (const char *jobid, char *buf, size_t buflen)
{
    if (!jobid || !*jobid || strchr (jobid, '/') || strstr (jobid, ".."))
        return -1;
    char dir[PATH_MAX];
    if (bat_at_dir (dir, sizeof dir) < 0)
        return -1;
    return snprintf (buf, buflen, "%s/%s.job", dir, jobid) < (int) buflen ? 0 : -1;
}

static int
bat_output_status (int bad)
{
    if (fflush (stdout) == EOF || ferror (stdout)) bad = 1;
    if (bad) clearerr (stdout);
    return bad ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

static int
bat_schedule (time_t run_at, const char *script, size_t script_len)
{
    char dir[PATH_MAX], path[PATH_MAX], tmp[PATH_MAX];
    if (bat_at_dir (dir, sizeof dir) < 0) {
        builtin_error ("mkdir atjobs: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    int length = snprintf (tmp, sizeof tmp, "%s/.%lld.%ld.XXXXXX", dir,
                           (long long) run_at, (long) getpid ());
    if (length < 0 || (size_t) length + 3 >= sizeof path) {
        builtin_error ("job path too long");
        return EXECUTION_FAILURE;
    }
    /* Cron scans only *.job. Keep an incomplete script hidden until close,
       and use a unique name for multiple jobs from the same Bash process. */
    int fd = mkstemp (tmp);
    if (fd < 0) { builtin_error ("create job: %s", strerror (errno)); return EXECUTION_FAILURE; }
    const char *jobid = strrchr (tmp, '/') + 2;  /* drop the leading dot */
    FILE *f = NULL;
    if (snprintf (path, sizeof path, "%s/%s.job", dir, jobid) < (int) sizeof path &&
        fcntl (fd, F_SETFD, FD_CLOEXEC) >= 0) f = fdopen (fd, "w");
    if (!f) {
        close (fd);
        unlink (tmp);
        builtin_error ("create job: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    int bad = fprintf (f, "# run_at=%lld\n", (long long) run_at) < 0;
    if (script_len && fwrite (script, 1, script_len, f) != script_len) bad = 1;
    if (script_len == 0 || script[script_len - 1] != '\n')
        if (fputc ('\n', f) == EOF) bad = 1;
    if (ferror (f)) bad = 1;
    if (fclose (f) != 0) bad = 1;
    if (bad) {
        unlink (tmp);
        builtin_error ("write job: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    /* link publishes atomically without replacing an existing job. */
    if (link (tmp, path) < 0) {
        int saved = errno;
        unlink (tmp);
        builtin_error ("publish job: %s", strerror (saved));
        return EXECUTION_FAILURE;
    }
    if (unlink (tmp) < 0) builtin_warning ("remove job temp: %s", strerror (errno));
    int output_error = printf ("job %s scheduled for %lld\n", jobid, (long long) run_at) < 0;
    return bat_output_status (output_error);
}

static int
bat_list (void)
{
    char dir[PATH_MAX];
    if (bat_at_dir (dir, sizeof dir) < 0)
        return EXECUTION_FAILURE;

    DIR *d = opendir (dir);
    if (!d) {
        builtin_error ("open atjobs: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }

    struct dirent *de;
    while ((de = readdir (d)) != NULL) {
        const char *name = de->d_name;
        size_t len = strlen (name);
        if (len <= 4 || strcmp (name + len - 4, ".job") != 0)
            continue;
        printf ("%.*s\n", (int) (len - 4), name);
    }
    int bad = closedir (d) < 0;
    return bat_output_status (bad);
}

static int
bat_cat (const char *jobid)
{
    char path[PATH_MAX];
    if (bat_job_path (jobid, path, sizeof path) < 0) {
        builtin_error ("bad job id");
        return EX_USAGE;
    }
    FILE *f = fopen (path, "r");
    if (!f) {
        builtin_error ("open job: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    char line[4096];
    if (fgets (line, sizeof line, f) == NULL) {
        fclose (f);
        return EXECUTION_FAILURE;
    }
    size_t n;
    int bad = 0;
    while ((n = fread (line, 1, sizeof line, f)) > 0)
        if (fwrite (line, 1, n, stdout) != n) { bad = 1; break; }
    if (ferror (f)) bad = 1;
    if (fclose (f) != 0) bad = 1;
    return bat_output_status (bad);
}

int
at_builtin (WORD_LIST *list)
{
    if (!list) {
        builtin_error ("usage: at TIME | at -l | at -r JOBID | at -c JOBID");
        return EX_USAGE;
    }
    const char *arg = list->word->word;
    if (!strcmp (arg, "-l")) {
        if (list->next) {
            builtin_error ("-l takes no arguments (got '%s')", list->next->word->word);
            return EX_USAGE;
        }
        return bat_list ();
    }
    if (!strcmp (arg, "-r") || !strcmp (arg, "-c")) {
        if (!list->next) {
            builtin_error ("%s requires a JOBID", arg);
            return EX_USAGE;
        }
        if (list->next->next) {
            builtin_error ("%s takes one JOBID (got extra '%s')",
                           arg, list->next->next->word->word);
            return EX_USAGE;
        }
        if (!strcmp (arg, "-c"))
            return bat_cat (list->next->word->word);
        char path[PATH_MAX];
        if (bat_job_path (list->next->word->word, path, sizeof path) < 0) {
            builtin_error ("bad job id: %s", list->next->word->word);
            return EX_USAGE;
        }
        if (unlink (path) < 0) {
            builtin_error ("remove job: %s", strerror (errno));
            return EXECUTION_FAILURE;
        }
        return EXECUTION_SUCCESS;
    }
    if (list->next) {
        builtin_error ("unexpected extra argument");
        return EX_USAGE;
    }
    time_t run_at;
    if (bat_parse_time (arg, &run_at) < 0) {
        builtin_error ("unsupported time: %s", arg);
        return EX_USAGE;
    }
    char *script = NULL;
    size_t len = 0;
    if (bat_read_stdin (&script, &len) < 0) {
        builtin_error ("read stdin: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    int rc = bat_schedule (run_at, script, len);
    free (script);
    return rc;
}

char *at_doc[] = {
    "Schedule one-shot jobs (small POSIX at subset).",
    "",
    "    at TIME      read commands from stdin and queue them",
    "    at -l        list queued job ids",
    "    at -r JOBID  remove a queued job",
    "    at -c JOBID  print a queued job script",
    "",
    "TIME accepts now, noon, midnight, teatime, @EPOCH, EPOCH,",
    "+N[s|m|h|d], or HH:MM.",
    (char *)NULL
};

struct builtin at_struct = {
    "at",
    at_builtin,
    BUILTIN_ENABLED,
    at_doc,
    "at TIME | at -l | at -r JOBID | at -c JOBID",
    0
};
