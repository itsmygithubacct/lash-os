/* SPDX-License-Identifier: MIT */
/* timeout.c — POSIX timeout(1) as a bash builtin.
 *
 * Phase S of bash-os POSIX gap-fillers.
 *
 *   timeout [--help|--version] [-s SIG] [-k DUR] DURATION CMD [ARG...]
 *
 *   -s SIG    initial signal to send (name or number; default TERM).
 *   -k DUR    if CMD doesn't exit within DUR after the initial signal,
 *             escalate to SIGKILL.
 *
 *   DURATION  a number with optional suffix s/m/h/d (default seconds).
 *             Floating-point allowed.
 *
 * Exit codes:
 *   0..N     CMD's exit status if it exited normally before timeout.
 *   124      CMD timed out (we sent the signal).
 *   125      timeout itself (us) failed.
 *   126      CMD was found but not executable.
 *   127      CMD not found.
 *   128+N    CMD killed by signal N (after timeout, this becomes 124).
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <poll.h>
#include <time.h>
#include <fcntl.h>

#include "loadables.h"
#include "command-run.h"

/* Parse "30", "30s", "1.5m", "2h" → seconds (double). */
static int
bto_parse_duration (const char *s, double *out)
{
    char *end;
    double v = strtod (s, &end);
    if (end == s || v < 0) return -1;
    if (*end == '\0') { *out = v; return 0; }
    if (end[1] != '\0') return -1;
    switch (*end) {
    case 's': *out = v; return 0;
    case 'm': *out = v * 60.0; return 0;
    case 'h': *out = v * 3600.0; return 0;
    case 'd': *out = v * 86400.0; return 0;
    default: return -1;
    }
}

/* Symbolic signal name → number. Caller passes "TERM", "INT", "9", etc. */
static int
bto_parse_signal (const char *s)
{
    if (!s || !*s) return -1;
    /* Numeric form: "9" or "SIG9". */
    const char *p = s;
    if (strncasecmp (p, "SIG", 3) == 0) p += 3;
    if (*p >= '0' && *p <= '9') {
        char *end;
        long n = strtol (p, &end, 10);
        if (*end != '\0') return -1;
        return (int) n;
    }
    if (strncasecmp (p, "RTMIN", 5) == 0) {
        long off = 0;
        const char *tail = p + 5;
        if (*tail == '+') {
            char *end;
            errno = 0;
            off = strtol (tail + 1, &end, 10);
            if (errno || end == tail + 1 || *end != '\0' || off < 0)
                return -1;
        } else if (*tail != '\0') {
            return -1;
        }
        long v = (long) SIGRTMIN + off;
        return (v >= SIGRTMIN && v <= SIGRTMAX) ? (int) v : -1;
    }
    if (strncasecmp (p, "RTMAX", 5) == 0) {
        long off = 0;
        const char *tail = p + 5;
        if (*tail == '-') {
            char *end;
            errno = 0;
            off = strtol (tail + 1, &end, 10);
            if (errno || end == tail + 1 || *end != '\0' || off < 0)
                return -1;
        } else if (*tail != '\0') {
            return -1;
        }
        long v = (long) SIGRTMAX - off;
        return (v >= SIGRTMIN && v <= SIGRTMAX) ? (int) v : -1;
    }
    /* Common names. */
    static const struct { const char *name; int sig; } map[] = {
        {"HUP",SIGHUP}, {"INT",SIGINT}, {"QUIT",SIGQUIT}, {"ILL",SIGILL},
        {"ABRT",SIGABRT}, {"FPE",SIGFPE}, {"KILL",SIGKILL}, {"USR1",SIGUSR1},
        {"SEGV",SIGSEGV}, {"USR2",SIGUSR2}, {"PIPE",SIGPIPE}, {"ALRM",SIGALRM},
        {"TERM",SIGTERM}, {"STOP",SIGSTOP}, {"TSTP",SIGTSTP}, {"CONT",SIGCONT},
        {"CHLD",SIGCHLD}, {"WINCH",SIGWINCH}, {"PWR", SIGPWR}, {NULL,0}
    };
    for (int i = 0; map[i].name; i++) {
        if (strcasecmp (p, map[i].name) == 0) return map[i].sig;
    }
    return -1;
}

extern char *timeout_doc[];

/* Reverse signal-number → short name lookup (no SIG prefix). NULL
   if outside the common set; caller falls back to numeric. */
static const char *
bto_signal_name (int s)
{
    static char rtbuf[16];

    switch (s) {
    case SIGHUP:  return "HUP";
    case SIGINT:  return "INT";
    case SIGQUIT: return "QUIT";
    case SIGILL:  return "ILL";
    case SIGABRT: return "ABRT";
    case SIGFPE:  return "FPE";
    case SIGKILL: return "KILL";
    case SIGUSR1: return "USR1";
    case SIGSEGV: return "SEGV";
    case SIGUSR2: return "USR2";
    case SIGPIPE: return "PIPE";
    case SIGALRM: return "ALRM";
    case SIGTERM: return "TERM";
    case SIGSTOP: return "STOP";
    case SIGTSTP: return "TSTP";
    case SIGCONT: return "CONT";
    case SIGCHLD: return "CHLD";
    case SIGWINCH:return "WINCH";
#ifdef SIGPWR
    case SIGPWR:  return "PWR";
#endif
    default:
        if (s >= SIGRTMIN && s <= SIGRTMAX) {
            if (s == SIGRTMIN)
                return "RTMIN";
            if (s == SIGRTMAX)
                return "RTMAX";
            snprintf (rtbuf, sizeof rtbuf, "RTMIN+%d", s - SIGRTMIN);
            return rtbuf;
        }
        return NULL;
    }
}

/* GNU timeout(1)-compatible verbose diagnostic, written to stderr.
   Format mirrors coreutils: "timeout: sending signal NAME to
   command 'CMD'". Falls back to a numeric signal when the name
   is unknown (RT signals etc). */
static void
bto_verbose_signal (int sig, const char *cmd)
{
    const char *nm = bto_signal_name (sig);
    if (nm)
        fprintf (stderr, "timeout: sending signal %s to command '%s'\n",
                 nm, cmd ? cmd : "<unknown>");
    else
        fprintf (stderr, "timeout: sending signal %d to command '%s'\n",
                 sig, cmd ? cmd : "<unknown>");
    fflush (stderr);
}

/* Send sig to child (or its process group if setpgid succeeded).
   Tries process-group kill first (to catch subprocesses); falls
   back to single-PID when no process group exists (ESRCH). */
static void
bto_kill_pg (pid_t child, int sig)
{
    if (kill (-child, sig) < 0 && errno == ESRCH)
        kill (child, sig);
}

/* Close the child's pidfd (if any) and restore the caller's mask.
   SIGCHLD stays pending: we never dequeue it, so Bash still reaps
   any background job that exited while we ran. */
static void
bto_restore (const sigset_t *prev, int pidfd)
{
    int saved = errno;
    if (pidfd >= 0)
        close (pidfd);
    sigprocmask (SIG_SETMASK, prev, NULL);
    errno = saved;
}

/* Sleep until the child exits or remain elapses. pidfd+ppoll wakes
   on our child without consuming SIGCHLD. Without a pidfd, sleep the
   remaining time; waitpid (WNOHANG) at the top of the loop reaps. */
static void
bto_wait_remain (int pidfd, const struct timespec *remain)
{
    if (pidfd >= 0) {
        struct pollfd pfd;
        pfd.fd = pidfd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (ppoll (&pfd, 1, remain, NULL) < 0 && errno != EINTR)
            return;
        return;
    }
    {
        int rc = clock_nanosleep (CLOCK_MONOTONIC, 0, remain, NULL);
        (void) rc;
    }
}

int
timeout_builtin (WORD_LIST *list)
{
    int sig = SIGTERM;
    double kill_after = -1;
    double duration = -1;
    WORD_LIST *cmd_list = NULL;

    int preserve_status = 0;
    int foreground = 0;
    int verbose = 0;

    WORD_LIST *p = list;
    while (p) {
        const char *w = p->word->word;
        if (strcmp (w, "--") == 0) { p = p->next; break; }
        if (strcmp (w, "--help") == 0 || strcmp (w, "-h") == 0) {
            char **d;
            for (d = timeout_doc; *d; d++) puts (*d);
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--version") == 0) {
            puts ("timeout 1.0 (bash-loadable, coreutils-compatible)");
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--preserve-status") == 0) {
            preserve_status = 1;
            p = p->next;
            continue;
        }
        if (strcmp (w, "--foreground") == 0) {
            foreground = 1;
            p = p->next;
            continue;
        }
        if (strcmp (w, "--verbose") == 0 || strcmp (w, "-v") == 0) {
            verbose = 1;
            p = p->next;
            continue;
        }
	    if (strcmp (w, "-s") == 0) {
	        if (!p->next) {
	            builtin_error ("-s needs SIG");
	            builtin_usage ();
	            return 125;
	        }
	        sig = bto_parse_signal (p->next->word->word);
	        if (sig < 0) { fprintf (stderr, "timeout: '%s': invalid signal\n", p->next->word->word); return 125; }
	        p = p->next->next;
	        continue;
	    }
        if (strncmp (w, "--signal=", 9) == 0) {
            sig = bto_parse_signal (w + 9);
            if (sig < 0) { fprintf (stderr, "timeout: '%s': invalid signal\n", w + 9); return 125; }
            p = p->next; continue;
        }
        if (strcmp (w, "--signal") == 0) {
            if (!p->next) {
                builtin_error ("--signal needs SIG");
                builtin_usage ();
                return 125;
            }
            sig = bto_parse_signal (p->next->word->word);
            if (sig < 0) { fprintf (stderr, "timeout: '%s': invalid signal\n", p->next->word->word); return 125; }
            p = p->next->next;
            continue;
        }
	    if (strcmp (w, "-k") == 0) {
	        if (!p->next) {
	            builtin_error ("-k needs DUR");
	            builtin_usage ();
	            return 125;
	        }
	        if (bto_parse_duration (p->next->word->word, &kill_after) < 0) {
	            builtin_error ("invalid kill-after duration: %s", p->next->word->word);
	            return 125;
	        }
	        p = p->next->next; continue;
        }
        if (strncmp (w, "--kill-after=", 13) == 0) {
            if (bto_parse_duration (w + 13, &kill_after) < 0) {
                builtin_error ("invalid kill-after duration: %s", w + 13);
                return 125;
            }
            p = p->next; continue;
	    }
        if (strcmp (w, "--kill-after") == 0) {
            if (!p->next) {
                builtin_error ("--kill-after needs DUR");
                builtin_usage ();
                return 125;
            }
            if (bto_parse_duration (p->next->word->word, &kill_after) < 0) {
                builtin_error ("invalid kill-after duration: %s", p->next->word->word);
                return 125;
            }
            p = p->next->next; continue;
        }
	    /* First non-flag is DURATION. */
	    if (w[0] == '-' && w[1] != '\0') {
	        builtin_error ("unknown flag: %s", w);
	        builtin_usage ();
	        return 125;
	    }
	    if (bto_parse_duration (w, &duration) < 0) {
	        fprintf (stderr, "timeout: invalid time interval '%s'\n", w);
	        return 125;
        }
        cmd_list = p->next;
        break;
    }
    /* --foreground: skip setpgid(0,0) in the child so the child stays in
       the controlling-terminal pgrp and SIGINT/SIGQUIT from the tty reach
       it (GNU timeout semantics). Default mode still calls setpgid for
       process-group kill coverage. */
    /* Handle "--" terminator: remaining words after "--" are duration + cmd. */
    if (duration < 0 && p && bto_parse_duration (p->word->word, &duration) >= 0) {
        cmd_list = p->next;
    }
    if (duration < 0 || !cmd_list) {
        builtin_usage ();
        return 125;
    }

    /* Build argv. */
    int argc = 0;
    for (WORD_LIST *q = cmd_list; q; q = q->next) argc++;
    char **argv = (char **) malloc ((argc + 1) * sizeof (char *));
    if (!argv) { builtin_error ("malloc: %s", strerror (errno)); return 125; }
    int i = 0;
    for (WORD_LIST *q = cmd_list; q; q = q->next) argv[i++] = q->word->word;
    argv[argc] = NULL;

    /* Preserve the command name for any verbose diagnostics — argv
       is freed before the wait loop, but cmd_list points into the
       bash-managed WORD_LIST so the underlying string outlives us. */
    const char *cmd_name = cmd_list->word->word;

    /* Block SIGCHLD so bash's SIGCHLD handler doesn't reap our forked
       child out from under us. Bash's main loop calls waitpid(-1, ...)
       on SIGCHLD; without blocking, our subsequent waitpid(child, ...)
       returns ECHILD because bash already collected the status. */
    sigset_t chld_set, prev_set;
    sigemptyset (&chld_set);
    sigaddset (&chld_set, SIGCHLD);
    sigprocmask (SIG_BLOCK, &chld_set, &prev_set);

    pid_t child = fork ();
    if (child < 0) {
        free (argv);
        sigprocmask (SIG_SETMASK, &prev_set, NULL);
        builtin_error ("fork: %s", strerror (errno));
        return 125;
    }
    if (child == 0) {
        bos_prepare_child ();
        /* Restore signal mask in child so it sees signals normally. */
        sigprocmask (SIG_SETMASK, &prev_set, NULL);
        if (!foreground)
            setpgid (0, 0);  /* own process group — subprocess coverage on kill */
        /* Optional pgid probe for tests: write the post-setpgid pgid to
           the path named by BASHTIMEOUT_PGID_PROBE. Lets the test observe
           --foreground (caller pgid retained) vs default (new pgrp). */
        const char *pgid_probe = getenv ("BASHTIMEOUT_PGID_PROBE");
        if (pgid_probe && *pgid_probe) {
            int pfd = open (pgid_probe, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (pfd >= 0) {
                char pline[64];
                int pn = snprintf (pline, sizeof pline, "%ld\n",
                                   (long) getpgid (0));
                if (pn > 0) {
                    ssize_t wn = write (pfd, pline, (size_t) pn);
                    (void) wn;  /* best-effort */
                }
                close (pfd);
            }
        }
        bos_run_builtin (argv[0], argv, NULL);
        execvp (argv[0], argv);
        /* exec failed */
        if (errno == ENOENT) _exit (127);
        _exit (126);
    }
    if (!foreground)
        setpgid (child, child);  /* close parent/child process-group setup race */
    free (argv);

    /* Parent: SIGCHLD stays blocked so Bash cannot steal this child, but
       we must not dequeue it (sigtimedwait would). pidfd+ppoll wakes when
       this child exits; leftover SIGCHLD still reaches Bash after restore.
       SIGALRM is Bash's (TMOUT / read -t). No 50ms poll. */
    int pidfd = -1;
#ifdef SYS_pidfd_open
    pidfd = (int) syscall (SYS_pidfd_open, child, 0);
#endif
    struct timespec start, now;
    clock_gettime (CLOCK_MONOTONIC, &start);

    int status;
    int timed_out = 0;
    int killed_hard = 0;
    double elapsed_at_signal = 0;
    for (;;) {
        pid_t r = waitpid (child, &status, WNOHANG);
        if (r == child) break;
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) {
            builtin_error ("waitpid: %s", strerror (errno));
            bto_restore (&prev_set, pidfd);
            return 125;
        }
        clock_gettime (CLOCK_MONOTONIC, &now);
        double elapsed = (double)(now.tv_sec - start.tv_sec)
                       + (double)(now.tv_nsec - start.tv_nsec) / 1e9;
        /* DURATION of 0 disables the timeout (run CMD to completion), matching
           timeout(1): "A duration of 0 disables the associated timeout." */
        double deadline = -1;
        if (!timed_out && duration > 0)
            deadline = duration;
        else if (timed_out && !killed_hard && kill_after > 0)
            deadline = elapsed_at_signal + kill_after;
        if (deadline >= 0 && elapsed >= deadline) {
            if (!timed_out) {
                if (verbose) bto_verbose_signal (sig, cmd_name);
                bto_kill_pg (child, sig);
                timed_out = 1;
                elapsed_at_signal = elapsed;
            } else {
                if (verbose) bto_verbose_signal (SIGKILL, cmd_name);
                bto_kill_pg (child, SIGKILL);
                killed_hard = 1;
            }
            continue;
        }
        if (killed_hard || deadline < 0) {
            r = waitpid (child, &status, 0);
            if (r == child) break;
            if (r < 0 && errno == EINTR) continue;
            if (r < 0) {
                builtin_error ("waitpid: %s", strerror (errno));
                bto_restore (&prev_set, pidfd);
                return 125;
            }
            continue;
        }
        double remain = deadline - elapsed;
        struct timespec wait_ts;
        wait_ts.tv_sec = (time_t) remain;
        wait_ts.tv_nsec = (long) ((remain - (double) wait_ts.tv_sec) * 1e9);
        if (wait_ts.tv_nsec < 0) wait_ts.tv_nsec = 0;
        if (wait_ts.tv_nsec >= 1000000000L) {
            wait_ts.tv_sec += 1;
            wait_ts.tv_nsec -= 1000000000L;
        }
        bto_wait_remain (pidfd, &wait_ts);
    }

    bto_restore (&prev_set, pidfd);

    if (timed_out) {
        if (preserve_status) {
            if (WIFEXITED (status)) return WEXITSTATUS (status);
            if (WIFSIGNALED (status)) return 128 + WTERMSIG (status);
        }
        return 124;
    }
    if (WIFEXITED (status)) return WEXITSTATUS (status);
    if (WIFSIGNALED (status)) return 128 + WTERMSIG (status);
    return 125;
}

char *timeout_doc[] = {
    "Run a command with a time limit.",
    "",
    "    timeout [--help|--version] [--preserve-status] [--foreground] [-v|--verbose]",
    "                [-s SIG] [-k DUR] DURATION CMD [ARG...]",
    "",
    "    --help              show this help",
    "    --version           show version",
    "    -s SIG              initial signal (name, RTMIN[+N], RTMAX[-N], or number; default TERM)",
    "    -k DUR              send SIGKILL if still alive DUR after the initial signal",
    "    --preserve-status   return CMD's actual exit status even on timeout",
    "    -v, --verbose       diagnose to stderr any signal sent upon timeout",
    "                        (format: \"timeout: sending signal NAME to command 'CMD'\")",
    "    DURATION            <number>[s|m|h|d]  (default seconds; 0 disables the timeout)",
    "",
    "Exit 124 on timeout, 125 on internal error, 126 if CMD found but",
    "not executable, 127 if not found, 128+N if killed by signal N,",
    "otherwise CMD's own exit status.  With --preserve-status, returns",
    "CMD's exit status (128+N) instead of 124 when timeout occurs.",
    (char *)NULL
};

struct builtin timeout_struct = {
    "timeout",
    timeout_builtin,
    BUILTIN_ENABLED,
    timeout_doc,
    "timeout [--help|--version] [--preserve-status] [--foreground] [-v|--verbose] [-s SIG] [-k DUR] DURATION CMD [ARG...]",
    0
};
