/* SPDX-License-Identifier: MIT */
/* batch.c - small batch(1)-shaped wrapper for bash-os.
 *
 * batch reads a script from stdin and queues it for immediate execution
 * by cron. bash-os does not yet track system load, so "low load" is
 * interpreted as now.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "loadables.h"

static const char *
bb_spool_root (void)
{
    const char *s = getenv ("BASHCRON_SPOOL_DIR");
    return (s && *s) ? s : "/var/spool/cron";
}

static int
bb_mkdir_p (const char *path)
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
bb_read_stdin (char **out, size_t *outlen)
{
    clearerr (stdin);
    size_t cap = 4096, len = 0;
    char *buf = malloc (cap);
    if (!buf)
        return -1;
    for (;;) {
        if (len + 2048 + 1 > cap) {
            cap *= 2;
            char *nb = realloc (buf, cap);
            if (!nb) {
                free (buf);
                return -1;
            }
            buf = nb;
        }
        size_t n = fread (buf + len, 1, 2048, stdin);
        len += n;
        if (n < 2048) {
            if (ferror (stdin)) {
                free (buf);
                return -1;
            }
            break;
        }
    }
    buf[len] = '\0';
    *out = buf;
    *outlen = len;
    return 0;
}

int
batch_builtin (WORD_LIST *list)
{
    if (list) {
        builtin_error ("batch takes no arguments");
        return EX_USAGE;
    }

    char *script = NULL;
    size_t len = 0;
    if (bb_read_stdin (&script, &len) < 0) {
        builtin_error ("read stdin: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }

    char dir[PATH_MAX], path[PATH_MAX], jobid[128];
    if (snprintf (dir, sizeof dir, "%s/atjobs", bb_spool_root ()) >= (int) sizeof dir ||
        bb_mkdir_p (dir) < 0) {
        free (script);
        builtin_error ("mkdir atjobs: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }

    /* jobid = <sec>.<pid>.<seq>. The per-process atomic counter
       guarantees that two `batch` invocations from the same bash
       session (same pid) within the same wall-clock second still get
       distinct jobids — and the lexicographic sort order matches
       submission order, which is exactly the FIFO contract cron's
       atjobs scanner relies on. seq wraps every 10^6 calls; for an
       at-job poll cadence of seconds that's effectively unbounded. */
    static unsigned long bb_submit_seq;
    time_t run_at = time (NULL);
    snprintf (jobid, sizeof jobid, "%lld.%ld.%06lu",
              (long long) run_at, (long) getpid (), bb_submit_seq++ % 1000000UL);
    if (snprintf (path, sizeof path, "%s/%s.job", dir, jobid) >= (int) sizeof path) {
        free (script);
        builtin_error ("job path too long");
        return EXECUTION_FAILURE;
    }

    FILE *f = fopen (path, "wx");
    if (!f) {
        free (script);
        builtin_error ("create job: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    chmod (path, 0600);
    fprintf (f, "# run_at=%lld\n", (long long) run_at);
    if (len && fwrite (script, 1, len, f) != len) {
        fclose (f);
        unlink (path);
        free (script);
        builtin_error ("write job: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (len == 0 || script[len - 1] != '\n')
        fputc ('\n', f);
    free (script);
    if (fclose (f) != 0) {
        unlink (path);
        builtin_error ("close job: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    printf ("job %s scheduled for %lld\n", jobid, (long long) run_at);
    return EXECUTION_SUCCESS;
}

char *batch_doc[] = {
    "Schedule a job for low-load execution (currently immediate).",
    "",
    "    batch < script",
    "",
    "Jobs are written to ${BASHCRON_SPOOL_DIR:-/var/spool/cron}/atjobs.",
    "Jobid format is <seconds-since-epoch>.<pid>.<seq>; cron's atjobs",
    "scanner processes ready jobs in lexicographic-by-jobid order, which",
    "is equivalent to submission order (FIFO) for two jobs queued for the",
    "same fire time.",
    (char *)NULL
};

struct builtin batch_struct = {
    "batch",
    batch_builtin,
    BUILTIN_ENABLED,
    batch_doc,
    "batch",
    0
};
