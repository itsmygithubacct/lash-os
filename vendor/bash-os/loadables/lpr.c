/* SPDX-License-Identifier: MIT */
/* lpr.c — minimal line-printer-remote (lpr(1) subset) with
 *             SIGTERM-driven spool cleanup. v1.
 *
 *   lpr submit FILE
 *
 *     Spools FILE into $BASHLPR_SPOOL/<random>.lpr (default
 *     /var/spool/lpd), then enters a sleep that simulates a long-
 *     running print. On SIGTERM the spool file is unlinked and a
 *     diagnostic is emitted to stderr before exit (rc=143). On normal
 *     completion (sleep expires) the spool file is also unlinked
 *     (a real printer-driver path would mark the job done here).
 *
 *   lpr --help
 *     Print one-line usage.
 *
 *   Knobs:
 *     BASHLPR_SPOOL          spool dir (default /var/spool/lpd)
 *     BASHLPR_PRINT_SEC      simulated print duration (default 30 s;
 *                            capped at 3600 s)
 *
 * v1 scope: just enough surface to pin the regression contract that
 * SIGTERM mid-print cleans up the spool. Out of scope: actual
 * remote-printer wire protocol (RFC 1179 LPD), job-id queue, cancel
 * by job id, status verb, multi-file batches.
 *
 * Source counterparts: cups lpr(1) for surface inspiration; BSD lpr.c
 * for SIGTERM-cleanup conventions (signal-safe write + _exit).
 *
 * --- LICENSE --- MIT, same boilerplate as fsck.c / fw.c.
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
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include "loadables.h"

/* Async-signal-safe state. The SIGTERM handler unlinks these paths
 * and emits a diagnostic. Allocated as static byte buffers (not
 * strdup'd) so the handler doesn't need malloc-state assumptions.
 * blpr_pid_path is the sidecar file containing the lpr PID —
 * `lpr cancel BASENAME` reads it to discover which process to
 * SIGTERM. Both paths are unlinked on cancel and on normal
 * completion. */
static char blpr_spool_path[768];
static char blpr_pid_path[800];

static void
blpr_sigterm_handler (int signo)
{
    (void) signo;
    if (blpr_spool_path[0]) {
        (void) unlink (blpr_spool_path);
        if (blpr_pid_path[0]) (void) unlink (blpr_pid_path);
        /* Signal-safe diagnostic via write(2). Construct the message
         * piece-wise to avoid sprintf (not on the AS-Safe list under
         * POSIX, even though glibc/musl tolerate it in practice). */
        static const char p1[] = "lpr: cancelled — cleaned spool ";
        static const char p2[] = "\n";
        (void) write (STDERR_FILENO, p1, sizeof p1 - 1);
        (void) write (STDERR_FILENO, blpr_spool_path,
                      strlen (blpr_spool_path));
        (void) write (STDERR_FILENO, p2, sizeof p2 - 1);
    }
    _exit (143);   /* 128 + SIGTERM, matching shell convention */
}

/* Fill `out` with 16 lowercase hex chars from /dev/urandom; fall back
 * to a time+pid mix on /dev/urandom open failure. */
static void
blpr_random_hex (char *out, size_t outlen)
{
    static const char hex[] = "0123456789abcdef";
    unsigned char rb[8];
    int filled = 0;
    int ufd = open ("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (ufd >= 0) {
        ssize_t n = read (ufd, rb, sizeof rb);
        close (ufd);
        if (n == (ssize_t) sizeof rb) filled = 1;
    }
    if (!filled) {
        uint64_t mix = (uint64_t) time (NULL) ^ ((uint64_t) getpid () << 20);
        for (size_t i = 0; i < 8; i++) {
            rb[i] = (unsigned char) ((mix >> (i * 8)) & 0xff);
        }
    }
    size_t need = 16;
    if (need > outlen - 1) need = outlen - 1;
    size_t i = 0;
    for (; i < 8 && (i * 2 + 1) < need; i++) {
        out[i * 2]     = hex[(rb[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hex[ rb[i]       & 0x0f];
    }
    out[i * 2] = '\0';
}

static int
blpr_cmd_submit (WORD_LIST *args)
{
    if (!args) {
        builtin_error ("submit: needs FILE");
        return EX_USAGE;
    }
    const char *src = args->word->word;
    int sfd = open (src, O_RDONLY | O_CLOEXEC);
    if (sfd < 0) {
        builtin_error ("submit: cannot open %s: %s", src, strerror (errno));
        return EXECUTION_FAILURE;
    }

    const char *spool_root = getenv ("BASHLPR_SPOOL");
    if (!spool_root || !*spool_root) spool_root = "/var/spool/lpd";
    /* Best-effort spool dir creation. Operators usually pre-create it
     * via init / package post-install; we mkdir for convenience under
     * test fixtures where /tmp/whatever is the spool root. */
    (void) mkdir (spool_root, 0755);

    char rand_hex[20];
    blpr_random_hex (rand_hex, sizeof rand_hex);
    if (snprintf (blpr_spool_path, sizeof blpr_spool_path,
                  "%s/%s.lpr", spool_root, rand_hex)
        >= (int) sizeof blpr_spool_path) {
        builtin_error ("submit: spool path too long");
        close (sfd);
        return EXECUTION_FAILURE;
    }

    int dfd = open (blpr_spool_path,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (dfd < 0) {
        builtin_error ("submit: cannot create spool %s: %s",
                       blpr_spool_path, strerror (errno));
        close (sfd);
        blpr_spool_path[0] = '\0';
        return EXECUTION_FAILURE;
    }

    /* Copy contents src → spool with EINTR-tolerant read/write loop. */
    char buf[8192];
    ssize_t n;
    while ((n = read (sfd, buf, sizeof buf)) != 0) {
        if (n < 0) {
            if (errno == EINTR) continue;
            builtin_error ("submit: read %s: %s", src, strerror (errno));
            close (sfd); close (dfd);
            (void) unlink (blpr_spool_path);
            blpr_spool_path[0] = '\0';
            return EXECUTION_FAILURE;
        }
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write (dfd, buf + off, (size_t) (n - off));
            if (w < 0) {
                if (errno == EINTR) continue;
                builtin_error ("submit: write %s: %s",
                               blpr_spool_path, strerror (errno));
                close (sfd); close (dfd);
                (void) unlink (blpr_spool_path);
                blpr_spool_path[0] = '\0';
                return EXECUTION_FAILURE;
            }
            off += w;
        }
    }
    close (sfd);
    close (dfd);

    /* Write a sidecar .pid file alongside the spool entry. The PID
     * lets `lpr cancel BASENAME` discover which process to
     * SIGTERM. We write it BEFORE installing the SIGTERM handler so
     * the handler can blindly unlink it without race against partial
     * writes. Sidecar failures are non-fatal: if we can't write the
     * .pid, cancel-by-basename won't work for this job but the print
     * itself proceeds; the operator can still kill the lpr PID
     * directly. */
    if (snprintf (blpr_pid_path, sizeof blpr_pid_path,
                  "%s.pid", blpr_spool_path)
        < (int) sizeof blpr_pid_path) {
        int pfd = open (blpr_pid_path,
                        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (pfd >= 0) {
            char pidbuf[32];
            int plen = snprintf (pidbuf, sizeof pidbuf,
                                 "%ld\n", (long) getpid ());
            if (plen > 0) (void) write (pfd, pidbuf, (size_t) plen);
            close (pfd);
        } else {
            blpr_pid_path[0] = '\0';
        }
    } else {
        blpr_pid_path[0] = '\0';
    }

    /* Install SIGTERM handler that unlinks the spool path + emits the
     * cancel diagnostic. Done AFTER the spool file exists so the
     * handler's unlink always has something to clean. Use sigaction
     * (not signal) for portable + restartable semantics — no SA_RESTART
     * so the sleep returns EINTR on signal. */
    struct sigaction sa;
    memset (&sa, 0, sizeof sa);
    sa.sa_handler = blpr_sigterm_handler;
    sigemptyset (&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction (SIGTERM, &sa, NULL);

    printf ("lpr: spooled %s\n", blpr_spool_path);
    fflush (stdout);

    /* Sleep simulates the print. Capped at 1 h so a buggy test fixture
     * doesn't pin a stuck process for hours. Default 30 s gives a test
     * suite ample slack to send SIGTERM. */
    unsigned dur = 30;
    const char *envd = getenv ("BASHLPR_PRINT_SEC");
    if (envd && *envd) {
        char *end;
        long v = strtol (envd, &end, 10);
        if (end && *end == '\0' && v >= 0 && v <= 3600) dur = (unsigned) v;
    }
    (void) sleep (dur);

    /* Normal completion: clean up spool + sidecar, leave SIGTERM
     * handler torn down for the next invocation. Return SUCCESS (the
     * "print" was delivered). */
    (void) unlink (blpr_spool_path);
    if (blpr_pid_path[0]) (void) unlink (blpr_pid_path);
    blpr_spool_path[0] = '\0';
    blpr_pid_path[0] = '\0';
    sa.sa_handler = SIG_DFL;
    sigaction (SIGTERM, &sa, NULL);
    return EXECUTION_SUCCESS;
}

/* List entries currently in the spool dir, one per line. Observational
 * verb — doesn't open or touch any spool entry. Missing dir = silent
 * empty list (rc 0), so an operator who just installed bash-os and
 * hasn't done their first submit yet gets a clean "no jobs queued"
 * rather than a "no such directory" diagnostic. */
static int
blpr_cmd_list (WORD_LIST *args)
{
    (void) args;
    const char *spool_root = getenv ("BASHLPR_SPOOL");
    if (!spool_root || !*spool_root) spool_root = "/var/spool/lpd";
    DIR *d = opendir (spool_root);
    if (!d) return EXECUTION_SUCCESS;   /* empty list */
    struct dirent *de;
    while ((de = readdir (d)) != NULL) {
        if (de->d_name[0] == '.' &&
            (de->d_name[1] == '\0' ||
             (de->d_name[1] == '.' && de->d_name[2] == '\0')))
            continue;
        /* Only show .lpr entries — the spool dir might be co-located
         * with operator-side notes; the .lpr suffix is the canonical
         * shape submit emits. */
        size_t nl = strlen (de->d_name);
        if (nl < 4 || strcmp (de->d_name + nl - 4, ".lpr") != 0) continue;
        printf ("%s/%s\n", spool_root, de->d_name);
    }
    closedir (d);
    return EXECUTION_SUCCESS;
}

/* Cancel a spooled job by basename. Resolves the basename against
 * $BASHLPR_SPOOL, opens the matching `.pid` sidecar, reads the PID,
 * sends SIGTERM. The receiving lpr's handler unlinks both the
 * spool entry and the sidecar; we DON'T unlink them here so the
 * cancel diagnostic stays single-sourced (the original submitter
 * owns "cancelled — cleaned spool"). cancel itself just emits a
 * confirmation pointing at the affected path so the operator knows
 * which job was hit when several are queued. */
static int
blpr_cmd_cancel (WORD_LIST *args)
{
    if (!args) {
        builtin_error ("cancel: needs BASENAME (the <hex>.lpr basename from `lpr list`)");
        return EX_USAGE;
    }
    const char *basename = args->word->word;
    /* Reject path-separator chars to keep the basename argument scoped
     * to one entry in the spool dir; otherwise `lpr cancel /etc/X`
     * could look outside the spool tree. */
    if (strchr (basename, '/')) {
        builtin_error ("cancel: BASENAME must not contain '/'");
        return EX_USAGE;
    }
    const char *spool_root = getenv ("BASHLPR_SPOOL");
    if (!spool_root || !*spool_root) spool_root = "/var/spool/lpd";

    char pid_path[800];
    if (snprintf (pid_path, sizeof pid_path,
                  "%s/%s.pid", spool_root, basename)
        >= (int) sizeof pid_path) {
        builtin_error ("cancel: pid sidecar path too long");
        return EXECUTION_FAILURE;
    }
    int pfd = open (pid_path, O_RDONLY | O_CLOEXEC);
    if (pfd < 0) {
        builtin_error ("cancel: no job for basename %s (no %s)",
                       basename, pid_path);
        return EXECUTION_FAILURE;
    }
    char pidbuf[32];
    ssize_t r = read (pfd, pidbuf, sizeof pidbuf - 1);
    close (pfd);
    if (r <= 0) {
        builtin_error ("cancel: empty/unreadable pid sidecar %s", pid_path);
        return EXECUTION_FAILURE;
    }
    pidbuf[r] = '\0';
    char *end = NULL;
    long pid = strtol (pidbuf, &end, 10);
    if (end == pidbuf || pid <= 0) {
        builtin_error ("cancel: malformed pid in %s: '%s'",
                       pid_path, pidbuf);
        return EXECUTION_FAILURE;
    }
    if (kill ((pid_t) pid, SIGTERM) < 0) {
        builtin_error ("cancel: kill %ld: %s", pid, strerror (errno));
        return EXECUTION_FAILURE;
    }
    printf ("lpr: sent SIGTERM to pid %ld for %s/%s\n",
            pid, spool_root, basename);
    return EXECUTION_SUCCESS;
}

int
lpr_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    if (!strcmp (cmd, "--help") || !strcmp (cmd, "-h")) {
        builtin_usage ();
        return EXECUTION_SUCCESS;
    }
    if (!strcmp (cmd, "submit")) return blpr_cmd_submit (args);
    if (!strcmp (cmd, "list"))   return blpr_cmd_list (args);
    if (!strcmp (cmd, "cancel")) return blpr_cmd_cancel (args);
    builtin_error ("unknown subcommand: %s (try 'submit', 'list', 'cancel', or '--help')", cmd);
    return EX_USAGE;
}

char *lpr_doc[] = {
    "Submit a file to the print spool, with SIGTERM-cleanup.",
    "",
    "    lpr submit FILE      copy FILE → $BASHLPR_SPOOL/<rand>.lpr,",
    "                             write a sibling <rand>.lpr.pid with the",
    "                             submitter's PID, then sleep simulating",
    "                             a long print. SIGTERM unlinks both",
    "                             files + diagnoses.",
    "    lpr list             one line per *.lpr entry in the spool",
    "                             dir; missing dir = empty list, rc 0.",
    "    lpr cancel BASENAME  read $BASHLPR_SPOOL/BASENAME.pid, send",
    "                             SIGTERM to that PID. The receiving",
    "                             submitter unlinks the spool entry and",
    "                             sidecar; cancel prints a one-line",
    "                             confirmation.",
    "    lpr --help           this text",
    "",
    "Knobs:",
    "    BASHLPR_SPOOL       spool dir (default /var/spool/lpd)",
    "    BASHLPR_PRINT_SEC   simulated print duration (default 30s;",
    "                        max 3600s)",
    "",
    "v1 scope: only `submit` is implemented. The regression contract",
    "pinned is `cancel cleans spool` — out of scope: RFC 1179 LPD",
    "wire, job id queue, `lpr cancel JOBID`, `lpr status`,",
    "multi-file batches.",
    (char *) NULL
};

struct builtin lpr_struct = {
    "lpr",
    lpr_builtin,
    BUILTIN_ENABLED,
    lpr_doc,
    "lpr {submit FILE | list | cancel BASENAME}",
    0
};
