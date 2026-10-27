/* SPDX-License-Identifier: MIT */
/* lpr.c — print-spool front end that delivers each job to an explicitly
 *         configured backend executable. v2.
 *
 *   lpr submit FILE|-
 *
 *     Copies FILE (or standard input) into a private spool entry
 *     $BASHLPR_SPOOL/<id>.lpr, then runs the configured backend as an
 *     owned child with a literal argv (no shell, no PATH search):
 *
 *         $BASHLPR_BACKEND <id> <size> <title>
 *
 *     with the spool entry open read-only on its standard input. The job
 *     is ACCEPTED only when the backend exits 0 *and* its stdin offset
 *     reached the job size (it consumed every byte). Anything else is
 *     FAILED. A `lpr cancel` request or a terminating signal to the
 *     submitting shell CANCELS the job: the backend child is sent SIGTERM
 *     (SIGKILL after a 2 s grace) through its pidfd, reaped, and the
 *     spool entry removed. Every outcome removes the spool entry.
 *
 *     With no backend configured the job is refused before anything is
 *     spooled — nothing ever claims delivery without a backend saying so.
 *
 *   lpr list [-l]
 *     One line per *.lpr spool entry; -l prints "<id> <state> <bytes>"
 *     where state is "active" (a live submitter owns it) or "stale".
 *
 *   lpr cancel ID
 *     ID is the 16-hex job id, with or without ".lpr". A live job is asked
 *     to cancel through its control FIFO ($BASHLPR_SPOOL/<id>.ctl) and the
 *     command waits for the submitter to finish. cancel never signals any
 *     process itself: only the submitter signals, and only its own child.
 *     A job with no live submitter is stale; its leftovers are removed.
 *     PID files (the v1 <id>.lpr.pid sidecars) are never trusted.
 *
 *   Knobs:
 *     BASHLPR_SPOOL     spool dir (default /var/spool/lpd). Created 0700;
 *                       must be a real directory owned by the caller and
 *                       not group/other writable.
 *     BASHLPR_BACKEND   absolute path of the backend executable (required).
 *     BASHLPR_TIMEOUT   seconds before a running backend is failed and
 *                       terminated (default 0 = no limit, max 86400).
 *
 * Out of scope: the RFC 1179 LPD wire protocol, printer discovery, queue
 * ordering across submitters, multi-file batches. A backend that speaks
 * a network protocol is an executable like any other.
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
#include <poll.h>
#include <time.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <dirent.h>

#include "loadables.h"
#include "command-run.h"
#include "child-wait.h"

extern char **export_env;
extern void maybe_make_export_env (void);

#define BLPR_ID_LEN      16
#define BLPR_GRACE_MS    2000
#define BLPR_CANCEL_MS   10000
#define BLPR_EXIT_CANCEL 3

static const int blpr_term_sigs[] = { SIGTERM, SIGINT, SIGHUP };
#define BLPR_NTERM ((int) (sizeof blpr_term_sigs / sizeof blpr_term_sigs[0]))

static volatile sig_atomic_t blpr_caught;

static void
blpr_on_signal (int signo)
{
    if (!blpr_caught) blpr_caught = signo;
}

static const char *
blpr_spool_root (void)
{
    const char *root = get_string_value ("BASHLPR_SPOOL");
    return (root && *root) ? root : "/var/spool/lpd";
}

/* Open the spool directory without following a final symlink and insist
 * it is private: owned by us and not writable by anyone else. Another
 * writer could plant FIFOs, symlinks or forged job files. */
static int
blpr_open_spool (const char *root, int create)
{
    if (create && mkdir (root, 0700) < 0 && errno != EEXIST) {
        builtin_error ("cannot create spool %s: %s", root, strerror (errno));
        return -1;
    }
    int dfd = open (root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0) {
        builtin_error ("cannot open spool %s: %s", root, strerror (errno));
        return -1;
    }
    struct stat st;
    if (fstat (dfd, &st) < 0 || st.st_uid != geteuid ()
        || (st.st_mode & (S_IWGRP | S_IWOTH))) {
        builtin_error ("spool %s is not private (must be owned by uid %ld "
                       "and not group/other writable)", root, (long) geteuid ());
        close (dfd);
        return -1;
    }
    return dfd;
}

static int
blpr_random_id (char *out)
{
    static const char hex[] = "0123456789abcdef";
    unsigned char rb[BLPR_ID_LEN / 2];
    int ufd = open ("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (ufd < 0) return -1;
    ssize_t n = read (ufd, rb, sizeof rb);
    close (ufd);
    if (n != (ssize_t) sizeof rb) return -1;
    for (size_t i = 0; i < sizeof rb; i++) {
        out[i * 2]     = hex[rb[i] >> 4];
        out[i * 2 + 1] = hex[rb[i] & 0x0f];
    }
    out[BLPR_ID_LEN] = '\0';
    return 0;
}

static int
blpr_valid_id (const char *s, char *id)
{
    size_t n = strlen (s);
    if (n == BLPR_ID_LEN + 4 && !strcmp (s + BLPR_ID_LEN, ".lpr"))
        n = BLPR_ID_LEN;
    if (n != BLPR_ID_LEN) return 0;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return 0;
    memcpy (id, s, n);
    id[n] = '\0';
    return 1;
}

/* Report a failed write to stdout as the command's failure. */
static int
blpr_flush (const char *verb)
{
    if (fflush (stdout) == EOF || ferror (stdout)) {
        clearerr (stdout);
        builtin_error ("%s: write error on stdout", verb);
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static long
blpr_ms_since (const struct timespec *start)
{
    struct timespec now;
    clock_gettime (CLOCK_MONOTONIC, &now);
    return (long) (now.tv_sec - start->tv_sec) * 1000
         + (now.tv_nsec - start->tv_nsec) / 1000000;
}

/* Signals that cancel a job while submit runs. They stay blocked except
 * inside ppoll, so a signal can never slip between a check and a wait. */
typedef struct {
    bos_child_wait chld;
    sigset_t handled, wait_mask;
    struct sigaction old[BLPR_NTERM];
    int installed[BLPR_NTERM];
} blpr_signals;

static int
blpr_signals_begin (blpr_signals *s)
{
    blpr_caught = 0;
    sigemptyset (&s->handled);
    for (int i = 0; i < BLPR_NTERM; i++) {
        s->installed[i] = 0;
        if (sigaction (blpr_term_sigs[i], NULL, &s->old[i]) == 0
            && s->old[i].sa_handler != SIG_IGN)
            sigaddset (&s->handled, blpr_term_sigs[i]);
    }
    if (bos_child_wait_begin (&s->chld) < 0) return -1;
    sigprocmask (SIG_BLOCK, &s->handled, NULL);
    struct sigaction sa;
    memset (&sa, 0, sizeof sa);
    sa.sa_handler = blpr_on_signal;
    sigfillset (&sa.sa_mask);
    for (int i = 0; i < BLPR_NTERM; i++)
        if (sigismember (&s->handled, blpr_term_sigs[i])
            && sigaction (blpr_term_sigs[i], &sa, NULL) == 0)
            s->installed[i] = 1;
    sigprocmask (SIG_SETMASK, NULL, &s->wait_mask);
    for (int i = 0; i < BLPR_NTERM; i++)
        if (s->installed[i]) sigdelset (&s->wait_mask, blpr_term_sigs[i]);
    return 0;
}

/* A signal either ran our handler inside ppoll or is still pending. */
static int
blpr_interrupted (const blpr_signals *s)
{
    if (blpr_caught) return blpr_caught;
    sigset_t pending;
    if (sigpending (&pending) == 0)
        for (int i = 0; i < BLPR_NTERM; i++)
            if (s->installed[i] && sigismember (&pending, blpr_term_sigs[i]))
                return blpr_term_sigs[i];
    return 0;
}

/* Put the shell's handlers back before unblocking: a still-pending
 * signal then reaches them, and one our handler consumed is raised
 * again so the shell reacts exactly as it would have without lpr. */
static void
blpr_signals_end (blpr_signals *s)
{
    for (int i = 0; i < BLPR_NTERM; i++)
        if (s->installed[i]) sigaction (blpr_term_sigs[i], &s->old[i], NULL);
    bos_child_wait_end (&s->chld);
    if (blpr_caught) {
        int sig = blpr_caught;
        blpr_caught = 0;
        raise (sig);
    }
}

/* Drain the control FIFO; returns 1 if a cancel request arrived. */
static int
blpr_ctl_cancelled (int ctl)
{
    char buf[64];
    int hit = 0;
    ssize_t n;
    while ((n = read (ctl, buf, sizeof buf)) > 0)
        if (memchr (buf, 'c', (size_t) n)) hit = 1;
    return hit;
}

typedef struct {
    int dfd, ctl_r, ctl_w;
    char id[BLPR_ID_LEN + 1];
    char lpr_name[BLPR_ID_LEN + 8];
    char ctl_name[BLPR_ID_LEN + 8];
} blpr_job;

static void
blpr_job_cleanup (blpr_job *j)
{
    if (j->lpr_name[0]) (void) unlinkat (j->dfd, j->lpr_name, 0);
    if (j->ctl_name[0]) (void) unlinkat (j->dfd, j->ctl_name, 0);
    if (j->ctl_r >= 0) close (j->ctl_r);
    if (j->ctl_w >= 0) close (j->ctl_w);
    if (j->dfd >= 0) close (j->dfd);
    j->lpr_name[0] = j->ctl_name[0] = '\0';
    j->ctl_r = j->ctl_w = j->dfd = -1;
}

/* Create the control FIFO first and hold it open for reading for the
 * job's whole life: a .lpr entry without a reader on its .ctl is stale. */
static int
blpr_job_create (blpr_job *j, int *lpr_fd)
{
    for (int attempt = 0; attempt < 8; attempt++) {
        if (blpr_random_id (j->id) < 0) {
            builtin_error ("submit: /dev/urandom: %s", strerror (errno));
            return -1;
        }
        snprintf (j->ctl_name, sizeof j->ctl_name, "%s.ctl", j->id);
        if (mkfifoat (j->dfd, j->ctl_name, 0600) == 0) break;
        j->ctl_name[0] = '\0';
        if (errno != EEXIST) {
            builtin_error ("submit: cannot create control FIFO: %s", strerror (errno));
            return -1;
        }
    }
    if (!j->ctl_name[0]) {
        builtin_error ("submit: no free job id");
        return -1;
    }
    struct stat st;
    j->ctl_r = openat (j->dfd, j->ctl_name,
                       O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (j->ctl_r >= 0)
        j->ctl_w = openat (j->dfd, j->ctl_name,
                           O_WRONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (j->ctl_r < 0 || j->ctl_w < 0 || fstat (j->ctl_r, &st) < 0
        || !S_ISFIFO (st.st_mode)) {
        builtin_error ("submit: cannot open control FIFO: %s", strerror (errno));
        return -1;
    }
    snprintf (j->lpr_name, sizeof j->lpr_name, "%s.lpr", j->id);
    *lpr_fd = openat (j->dfd, j->lpr_name,
                      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (*lpr_fd < 0) {
        int e = errno;
        j->lpr_name[0] = '\0';   /* not ours to remove */
        builtin_error ("submit: cannot create spool entry: %s", strerror (e));
        return -1;
    }
    return 0;
}

enum { BLPR_OK, BLPR_FAIL, BLPR_CANCEL, BLPR_SIGNAL };

/* Copy the input into the spool entry. A pipe or FIFO is waited on with
 * ppoll so a cancel request or signal interrupts a stalled writer. */
static int
blpr_spool_copy (int sfd, int dfd, const char *src, blpr_job *j,
                 const blpr_signals *s, off_t *size)
{
    static char buf[65536];
    struct stat st;
    int waitable = fstat (sfd, &st) == 0 && !S_ISREG (st.st_mode);
    *size = 0;
    for (;;) {
        if (blpr_interrupted (s)) return BLPR_SIGNAL;
        if (waitable) {
            struct pollfd p[2] = { { sfd, POLLIN, 0 }, { j->ctl_r, POLLIN, 0 } };
            if (ppoll (p, 2, NULL, &s->wait_mask) < 0) {
                if (errno == EINTR) continue;
                builtin_error ("submit: poll: %s", strerror (errno));
                return BLPR_FAIL;
            }
            if ((p[1].revents & POLLIN) && blpr_ctl_cancelled (j->ctl_r))
                return BLPR_CANCEL;
            if (!p[0].revents) continue;
        }
        ssize_t n = read (sfd, buf, sizeof buf);
        if (n == 0) return BLPR_OK;
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            builtin_error ("submit: read %s: %s", src, strerror (errno));
            return BLPR_FAIL;
        }
        for (ssize_t off = 0; off < n; ) {
            ssize_t w = write (dfd, buf + off, (size_t) (n - off));
            if (w < 0) {
                if (errno == EINTR) continue;
                builtin_error ("submit: write spool %s: %s",
                               j->lpr_name, strerror (errno));
                return BLPR_FAIL;
            }
            off += w;
        }
        *size += n;
    }
}

/* Mark every inherited descriptor above 2 close-on-exec so the backend
 * sees only its job on stdin plus the caller's stdout and stderr. */
static void
blpr_cloexec_from_3 (void)
{
#if defined (SYS_close_range)
    if (syscall (SYS_close_range, 3U, ~0U, 4U /* CLOSE_RANGE_CLOEXEC */) == 0)
        return;
#endif
    long max = sysconf (_SC_OPEN_MAX);
    if (max < 0 || max > 65536) max = 65536;
    for (int fd = 3; fd < max; fd++) {
        int fl = fcntl (fd, F_GETFD);
        if (fl >= 0) fcntl (fd, F_SETFD, fl | FD_CLOEXEC);
    }
}

static void
blpr_signal_child (pid_t child, int pidfd, int sig)
{
    /* The child is unreaped (SIGCHLD is ours until we wait), so its pid
     * cannot have been recycled; the pidfd states the same identity. */
#if defined (SYS_pidfd_send_signal)
    if (pidfd >= 0 && syscall (SYS_pidfd_send_signal, pidfd, sig, NULL, 0) == 0)
        return;
#endif
    (void) pidfd;
    (void) kill (child, sig);
}

static int
blpr_wait_child (pid_t child, int pidfd, int *status, long ms,
                 const sigset_t *mask)
{
    struct timespec start;
    clock_gettime (CLOCK_MONOTONIC, &start);
    for (;;) {
        pid_t r = waitpid (child, status, WNOHANG);
        if (r == child) return 1;
        if (r < 0 && errno != EINTR) return -1;
        long left = ms < 0 ? 50 : ms - blpr_ms_since (&start);
        if (ms >= 0 && left <= 0) return 0;
        if (pidfd < 0 && left > 50) left = 50;
        struct timespec ts = { left / 1000, (left % 1000) * 1000000L };
        struct pollfd p = { pidfd, POLLIN, 0 };
        (void) ppoll (&p, pidfd >= 0 ? 1 : 0, &ts, mask);
    }
}

static int
blpr_cmd_submit (WORD_LIST *args)
{
    if (!args || args->next) {
        builtin_error ("submit: usage: lpr submit FILE|-");
        return EX_USAGE;
    }
    const char *src = args->word->word;

    const char *v = get_string_value ("BASHLPR_BACKEND");
    char backend[4096];
    if (!v || !*v) {
        builtin_error ("submit: no backend configured (set BASHLPR_BACKEND to "
                       "an executable); nothing was spooled or delivered");
        return EXECUTION_FAILURE;
    }
    if (v[0] != '/' || strlen (v) >= sizeof backend) {
        builtin_error ("submit: BASHLPR_BACKEND must be an absolute path: %s", v);
        return EXECUTION_FAILURE;
    }
    strcpy (backend, v);
    struct stat bst;
    errno = 0;
    if (stat (backend, &bst) < 0 || !S_ISREG (bst.st_mode)
        || access (backend, X_OK) < 0) {
        builtin_error ("submit: backend %s is not an executable file: %s",
                       backend, errno ? strerror (errno) : "not a regular file");
        return EXECUTION_FAILURE;
    }
    long timeout_s = 0;
    v = get_string_value ("BASHLPR_TIMEOUT");
    if (v && *v) {
        char *end;
        errno = 0;
        timeout_s = strtol (v, &end, 10);
        if (errno || *end || timeout_s < 0 || timeout_s > 86400) {
            builtin_error ("submit: BASHLPR_TIMEOUT must be 0..86400 seconds: %s", v);
            return EX_USAGE;
        }
    }
    char root[4096];
    if (strlen (blpr_spool_root ()) >= sizeof root) {
        builtin_error ("submit: spool path too long");
        return EXECUTION_FAILURE;
    }
    strcpy (root, blpr_spool_root ());

    const char *title = strrchr (src, '/');
    title = !strcmp (src, "-") ? "stdin" : title ? title + 1 : src;
    int sfd = !strcmp (src, "-") ? fcntl (0, F_DUPFD_CLOEXEC, 3)
                                 : open (src, O_RDONLY | O_CLOEXEC);
    if (sfd < 0) {
        builtin_error ("submit: cannot open %s: %s", src, strerror (errno));
        return EXECUTION_FAILURE;
    }

    blpr_signals sigs;
    if (blpr_signals_begin (&sigs) < 0) {
        builtin_error ("submit: signal setup: %s", strerror (errno));
        close (sfd);
        return EXECUTION_FAILURE;
    }
    blpr_job job = { .dfd = -1, .ctl_r = -1, .ctl_w = -1 };
    int lfd = -1, jfd = -1, pidfd = -1, outcome = BLPR_FAIL;
    off_t size = 0;
    char reason[256] = "";
    pid_t child = -1;

    job.dfd = blpr_open_spool (root, 1);
    if (job.dfd < 0 || blpr_job_create (&job, &lfd) < 0)
        goto done;
    outcome = blpr_spool_copy (sfd, lfd, src, &job, &sigs, &size);
    close (sfd);
    sfd = -1;
    if (close (lfd) < 0 && outcome == BLPR_OK) {
        builtin_error ("submit: close spool: %s", strerror (errno));
        outcome = BLPR_FAIL;
    }
    lfd = -1;
    if (outcome != BLPR_OK) goto done;

    printf ("lpr: spooled %s/%s\n", root, job.lpr_name);
    if (blpr_flush ("submit; job withdrawn")) {
        outcome = BLPR_FAIL;
        goto done;
    }

    /* The backend reads the spool entry through its own descriptor; the
     * offset of that shared open file description shows how far it got. */
    jfd = openat (job.dfd, job.lpr_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    int ep[2];
    if (jfd < 0 || pipe2 (ep, O_CLOEXEC) < 0) {
        builtin_error ("submit: %s", strerror (errno));
        outcome = BLPR_FAIL;
        goto done;
    }
    char size_arg[32];
    snprintf (size_arg, sizeof size_arg, "%lld", (long long) size);
    char *argv[] = { backend, job.id, size_arg, (char *) title, NULL };
    maybe_make_export_env ();
    fflush (stderr);
    child = fork ();
    if (child == 0) {
        bos_prepare_child ();
        struct sigaction dfl;
        memset (&dfl, 0, sizeof dfl);
        dfl.sa_handler = SIG_DFL;
        for (int i = 0; i < BLPR_NTERM; i++)
            if (sigs.installed[i]) sigaction (blpr_term_sigs[i], &dfl, NULL);
        sigaction (SIGPIPE, &dfl, NULL);
        sigaction (SIGCHLD, &dfl, NULL);
        sigset_t none;
        sigemptyset (&none);
        sigprocmask (SIG_SETMASK, &none, NULL);
        int e;
        /* dup2 onto itself would keep close-on-exec when stdin was closed. */
        if (jfd == 0 ? fcntl (0, F_SETFD, 0) < 0 : dup2 (jfd, 0) < 0)
            goto child_fail;
        blpr_cloexec_from_3 ();
        execve (backend, argv, export_env);
    child_fail:
        e = errno;
        (void) !write (ep[1], &e, sizeof e);
        _exit (127);
    }
    int fork_errno = errno;
    close (ep[1]);
    if (child < 0) {
        close (ep[0]);
        builtin_error ("submit: fork: %s", strerror (fork_errno));
        outcome = BLPR_FAIL;
        goto done;
    }
#if defined (SYS_pidfd_open)
    pidfd = (int) syscall (SYS_pidfd_open, child, 0);
#endif
    int exec_errno = 0;
    ssize_t er;
    while ((er = read (ep[0], &exec_errno, sizeof exec_errno)) < 0 && errno == EINTR)
        ;
    close (ep[0]);
    int status = 0;
    if (er == (ssize_t) sizeof exec_errno) {
        blpr_wait_child (child, pidfd, &status, -1, &sigs.wait_mask);
        snprintf (reason, sizeof reason, "cannot execute backend %s: %s",
                  backend, strerror (exec_errno));
        outcome = BLPR_FAIL;
        goto done;
    }

    struct timespec start;
    clock_gettime (CLOCK_MONOTONIC, &start);
    int stop = BLPR_OK, timed_out = 0;
    for (;;) {
        pid_t r = waitpid (child, &status, WNOHANG);
        if (r == child) break;
        if (r < 0 && errno != EINTR) {
            snprintf (reason, sizeof reason, "waitpid: %s", strerror (errno));
            break;
        }
        if (blpr_interrupted (&sigs)) stop = BLPR_SIGNAL;
        long left = -1;
        if (timeout_s > 0) {
            left = timeout_s * 1000 - blpr_ms_since (&start);
            if (left <= 0) { stop = BLPR_FAIL; timed_out = 1; }
        }
        if (stop != BLPR_OK) {
            blpr_signal_child (child, pidfd, SIGTERM);
            if (blpr_wait_child (child, pidfd, &status, BLPR_GRACE_MS,
                                 &sigs.wait_mask) == 0) {
                blpr_signal_child (child, pidfd, SIGKILL);
                blpr_wait_child (child, pidfd, &status, -1, &sigs.wait_mask);
            }
            break;
        }
        if (pidfd < 0 && (left < 0 || left > 50)) left = 50;
        struct timespec ts = { left / 1000, (left % 1000) * 1000000L };
        struct pollfd p[2] = { { job.ctl_r, POLLIN, 0 }, { pidfd, POLLIN, 0 } };
        if (ppoll (p, pidfd >= 0 ? 2 : 1, left < 0 ? NULL : &ts,
                   &sigs.wait_mask) > 0
            && (p[0].revents & POLLIN) && blpr_ctl_cancelled (job.ctl_r)) {
            /* A backend that already exited is final: cancel came late. */
            if (waitpid (child, &status, WNOHANG) == child) break;
            stop = BLPR_CANCEL;
            blpr_signal_child (child, pidfd, SIGTERM);
            if (blpr_wait_child (child, pidfd, &status, BLPR_GRACE_MS,
                                 &sigs.wait_mask) == 0) {
                blpr_signal_child (child, pidfd, SIGKILL);
                blpr_wait_child (child, pidfd, &status, -1, &sigs.wait_mask);
            }
            break;
        }
    }
    off_t consumed = lseek (jfd, 0, SEEK_CUR);
    if (reason[0])
        outcome = BLPR_FAIL;
    else if (WIFEXITED (status) && WEXITSTATUS (status) == 0 && consumed >= size)
        outcome = BLPR_OK;
    else if (stop == BLPR_CANCEL || stop == BLPR_SIGNAL)
        outcome = stop;
    else {
        outcome = BLPR_FAIL;
        if (timed_out)
            snprintf (reason, sizeof reason,
                      "backend timed out after %ld s", timeout_s);
        else if (WIFSIGNALED (status))
            snprintf (reason, sizeof reason,
                      "backend killed by signal %d", WTERMSIG (status));
        else if (WEXITSTATUS (status))
            snprintf (reason, sizeof reason,
                      "backend exited with status %d", WEXITSTATUS (status));
        else
            snprintf (reason, sizeof reason,
                      "backend exited 0 after consuming %lld of %lld bytes",
                      (long long) (consumed < 0 ? 0 : consumed), (long long) size);
    }

done:
    if (sfd >= 0) close (sfd);
    if (lfd >= 0) close (lfd);
    if (jfd >= 0) close (jfd);
    if (pidfd >= 0) close (pidfd);
    int sig = blpr_interrupted (&sigs);
    if (outcome == BLPR_SIGNAL && !sig) sig = SIGTERM;
    char spooled[4096 + BLPR_ID_LEN + 8];
    snprintf (spooled, sizeof spooled, "%s/%s", root, job.lpr_name);
    int had_entry = job.lpr_name[0] != '\0';
    blpr_job_cleanup (&job);
    int rc = EXECUTION_FAILURE;
    if (outcome == BLPR_OK) {
        printf ("lpr: accepted %s (%lld bytes)\n", job.id, (long long) size);
        rc = blpr_flush ("submit");
    } else if (outcome == BLPR_CANCEL) {
        fprintf (stderr, "lpr: cancelled %s — cleaned spool %s\n", job.id, spooled);
        rc = BLPR_EXIT_CANCEL;
    } else if (outcome == BLPR_SIGNAL) {
        fprintf (stderr, "lpr: interrupted by signal %d — cleaned spool %s\n",
                 sig, had_entry ? spooled : root);
        rc = 128 + sig;
    } else if (reason[0]) {
        fprintf (stderr, "lpr: failed %s: %s\n", job.id, reason);
    }
    blpr_signals_end (&sigs);
    return rc;
}

/* List entries currently in the spool dir, one per line. A missing dir
 * is a silent empty list (rc 0). A symlink or a directory other people
 * can write is refused, same as submit. A readdir error is not the end
 * of the directory: the directory is closed and the command fails, so a
 * read error cannot hide the jobs that were not visited. With -l, each
 * job's state is probed through its control FIFO without writing to it. */
static int
blpr_cmd_list (WORD_LIST *args)
{
    int longfmt = 0;
    if (args && !strcmp (args->word->word, "-l") && !args->next)
        longfmt = 1;
    else if (args) {
        builtin_error ("list: usage: lpr list [-l]");
        return EX_USAGE;
    }
    const char *spool_root = blpr_spool_root ();
    int dfd = open (spool_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0) {
        if (errno == ENOENT) return EXECUTION_SUCCESS;
        builtin_error ("cannot open spool %s: %s", spool_root, strerror (errno));
        return EXECUTION_FAILURE;
    }
    struct stat rst;
    if (fstat (dfd, &rst) < 0 || rst.st_uid != geteuid ()
        || (rst.st_mode & (S_IWGRP | S_IWOTH))) {
        builtin_error ("spool %s is not private (must be owned by uid %ld "
                       "and not group/other writable)", spool_root, (long) geteuid ());
        close (dfd);
        return EXECUTION_FAILURE;
    }
    DIR *d = fdopendir (dfd);
    if (!d) {
        builtin_error ("cannot open spool %s: %s", spool_root, strerror (errno));
        close (dfd);
        return EXECUTION_FAILURE;
    }
    struct dirent *de;
    for (;;) {
        errno = 0;
        de = readdir (d);
        if (!de) {
            if (errno != 0) {
                int saved = errno;
                builtin_error ("cannot read spool %s: %s", spool_root,
                               strerror (saved));
                closedir (d);
                return EXECUTION_FAILURE;
            }
            break;
        }
        size_t nl = strlen (de->d_name);
        if (nl < 4 || strcmp (de->d_name + nl - 4, ".lpr") != 0) continue;
        if (!longfmt) {
            printf ("%s/%s\n", spool_root, de->d_name);
            continue;
        }
        char id[BLPR_ID_LEN + 1], ctl[BLPR_ID_LEN + 8];
        if (!blpr_valid_id (de->d_name, id)) continue;
        struct stat st;
        if (fstatat (dirfd (d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
            continue;
        snprintf (ctl, sizeof ctl, "%s.ctl", id);
        int fd = openat (dirfd (d), ctl,
                         O_WRONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        struct stat cst;
        int live = fd >= 0 && fstat (fd, &cst) == 0 && S_ISFIFO (cst.st_mode);
        if (fd >= 0) close (fd);
        printf ("%s %s %lld\n", id, live ? "active" : "stale",
                (long long) st.st_size);
    }
    closedir (d);
    return blpr_flush ("list");
}

/* write(2) on a FIFO with no reader raises SIGPIPE and only then reports
 * EPIPE. The default disposition would kill the shell before the caller
 * could treat that as "already finished". Ignore SIGPIPE for this write
 * alone and put the caller's disposition back, so a trap or an explicit
 * ignore is unchanged. */
static ssize_t
blpr_write_caller_sigpipe (int fd, const void *buf, size_t n)
{
    struct sigaction saved, ignore;
    memset (&ignore, 0, sizeof ignore);
    ignore.sa_handler = SIG_IGN;
    sigemptyset (&ignore.sa_mask);
    if (sigaction (SIGPIPE, &ignore, &saved) < 0)
        return -1;
    ssize_t w;
    do
        w = write (fd, buf, n);
    while (w < 0 && errno == EINTR);
    int saved_errno = errno;
    sigaction (SIGPIPE, &saved, NULL);
    errno = saved_errno;
    return w;
}

/* Ask the live submitter of ID to cancel, or remove a stale job. The
 * request is a byte on the job's control FIFO; opening it for writing
 * without blocking fails with ENXIO unless a submitter holds the read end,
 * which makes liveness a property of the kernel object rather than of any
 * PID written in a file. */
static int
blpr_cmd_cancel (WORD_LIST *args)
{
    char id[BLPR_ID_LEN + 1];
    if (!args || args->next) {
        builtin_error ("cancel: needs ID (the <id>.lpr basename from `lpr list`)");
        return EX_USAGE;
    }
    if (strchr (args->word->word, '/')) {
        builtin_error ("cancel: ID must not contain '/'");
        return EX_USAGE;
    }
    if (!blpr_valid_id (args->word->word, id)) {
        builtin_error ("cancel: invalid job id %s (want 16 hex digits)",
                       args->word->word);
        return EX_USAGE;
    }
    const char *root = blpr_spool_root ();
    int dfd = blpr_open_spool (root, 0);
    if (dfd < 0) return EXECUTION_FAILURE;
    char lpr[BLPR_ID_LEN + 8], ctl[BLPR_ID_LEN + 8], pid[BLPR_ID_LEN + 12];
    snprintf (lpr, sizeof lpr, "%s.lpr", id);
    snprintf (ctl, sizeof ctl, "%s.ctl", id);
    snprintf (pid, sizeof pid, "%s.lpr.pid", id);

    int fd = openat (dfd, ctl, O_WRONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (fd >= 0 && (fstat (fd, &st) < 0 || !S_ISFIFO (st.st_mode))) {
        close (fd);
        fd = -1;
        errno = ENXIO;
    }
    if (fd < 0) {
        int e = errno;
        int had = fstatat (dfd, lpr, &st, AT_SYMLINK_NOFOLLOW) == 0
               || fstatat (dfd, ctl, &st, AT_SYMLINK_NOFOLLOW) == 0
               || fstatat (dfd, pid, &st, AT_SYMLINK_NOFOLLOW) == 0;
        if (!had || (e != ENXIO && e != ENOENT)) {
            if (had)
                builtin_error ("cancel: %s: %s", ctl, strerror (e));
            else
                builtin_error ("cancel: no job %s in %s", id, root);
            close (dfd);
            return EXECUTION_FAILURE;
        }
        (void) unlinkat (dfd, lpr, 0);
        (void) unlinkat (dfd, ctl, 0);
        (void) unlinkat (dfd, pid, 0);
        close (dfd);
        printf ("lpr: removed stale job %s (no live submitter; nothing signalled)\n", id);
        return blpr_flush ("cancel");
    }
    close (dfd);
    if (blpr_write_caller_sigpipe (fd, "c", 1) != 1) {
        int e = errno;
        close (fd);
        if (e == EPIPE) {
            printf ("lpr: job %s already finished\n", id);
            return blpr_flush ("cancel");
        }
        builtin_error ("cancel: write %s: %s", ctl, strerror (e));
        return EXECUTION_FAILURE;
    }
    /* The submitter closes its read end only after reaping the backend
     * and removing the spool entry; POLLERR on our end reports that. */
    struct timespec start;
    clock_gettime (CLOCK_MONOTONIC, &start);
    int done = 0;
    for (;;) {
        long left = BLPR_CANCEL_MS - blpr_ms_since (&start);
        if (left <= 0) break;
        struct pollfd p = { fd, 0, 0 };
        int r = poll (&p, 1, (int) left);
        if (r < 0 && errno == EINTR) {
            if (interrupt_state || terminating_signal) break;
            continue;
        }
        if (r > 0 && (p.revents & (POLLERR | POLLHUP))) { done = 1; break; }
        if (r < 0) break;
    }
    close (fd);
    if (!done) {
        builtin_error ("cancel: job %s did not finish within %d s",
                       id, BLPR_CANCEL_MS / 1000);
        return EXECUTION_FAILURE;
    }
    printf ("lpr: cancel request for %s handled; job ended\n", id);
    return blpr_flush ("cancel");
}

int
lpr_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    clearerr (stdout);
    if (!strcmp (cmd, "--help") || !strcmp (cmd, "-h")) {
        builtin_help ();
        return EXECUTION_SUCCESS;
    }
    if (!strcmp (cmd, "submit")) return blpr_cmd_submit (args);
    if (!strcmp (cmd, "list"))   return blpr_cmd_list (args);
    if (!strcmp (cmd, "cancel")) return blpr_cmd_cancel (args);
    builtin_error ("unknown subcommand: %s (try 'submit', 'list', 'cancel', or '--help')", cmd);
    return EX_USAGE;
}

char *lpr_doc[] = {
    "Spool a file and deliver it to a configured backend executable.",
    "",
    "    lpr submit FILE|-    copy FILE (or stdin) to the private spool",
    "                         $BASHLPR_SPOOL/<id>.lpr, then run",
    "                         $BASHLPR_BACKEND <id> <bytes> <title> with the",
    "                         job on stdin. Accepted (rc 0) only if the",
    "                         backend exits 0 having read every byte;",
    "                         failed (rc 1) otherwise; cancelled (rc 3) on",
    "                         `lpr cancel`; 128+N if signal N interrupted",
    "                         the shell. The spool entry is always removed.",
    "    lpr list [-l]        one line per *.lpr spool entry; -l prints",
    "                         <id> <active|stale> <bytes>.",
    "    lpr cancel ID        ask the live submitter of ID to cancel and",
    "                         wait for it; remove a stale job's files.",
    "                         Never signals by a recorded PID.",
    "    lpr --help           this text",
    "",
    "Knobs:",
    "    BASHLPR_SPOOL       spool dir (default /var/spool/lpd); must be",
    "                        owned by you and not group/other writable",
    "    BASHLPR_BACKEND     absolute path of the backend (required; with",
    "                        none set, submit refuses and delivers nothing)",
    "    BASHLPR_TIMEOUT     backend time limit in seconds (0 = none)",
    (char *) NULL
};

struct builtin lpr_struct = {
    "lpr",
    lpr_builtin,
    BUILTIN_ENABLED,
    lpr_doc,
    "lpr {submit FILE|- | list [-l] | cancel ID}",
    0
};
