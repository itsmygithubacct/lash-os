/* SPDX-License-Identifier: MIT */
/* flock.c — flock(2) advisory file locking as a bash builtin.
 *
 *   flock [-sxun] [-w SECONDS] FD                     # lock an open fd
 *   flock [-sxun] [-w SECONDS] FILE command [args...] # lock FILE, run command
 *   flock [-sxun] [-w SECONDS] FILE -c "shell command"
 *
 * The fd form is the reason this is a builtin rather than a forked tool:
 * because it runs IN the calling shell, `flock -x 9` locks the descriptor
 * the shell opened with `exec 9>lockfile`, and the lock persists after the
 * builtin returns (it lives on the open file description, not the process).
 * That makes the canonical idiom
 *
 *     exec 9>/var/lock/mine
 *     flock -n 9 || { echo "busy"; exit 1; }
 *     ... critical section ...
 *
 * work with no fork and no external binary.
 *
 * Options (util-linux flock(1) compatible subset):
 *   -s, --shared        take a shared lock
 *   -x, -e, --exclusive take an exclusive lock (default)
 *   -u, --unlock        drop a held lock
 *   -n, --nb, --nonblock fail (do not wait) if the lock is held
 *   -w, --wait SECONDS  wait at most SECONDS (fractional ok) for the lock
 *   -E, --conflict-exit-code N  exit code when -n/-w fails to lock (default 1)
 *   -o, --close         close the fd before running command (file form)
 *   -c, --command CMD   run CMD via /bin/sh -c (file form)
 *   -F, --no-fork       exec command directly without forking (file form)
 *
 * --- LICENSE --- MIT, same boilerplate as the other bash-os loadables.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <time.h>
#include <limits.h>
#include <math.h>

#include "loadables.h"
#include "child-wait.h"

extern char *flock_doc[];

/* util-linux uses sysexits values, distinct from Bash's EX_USAGE (2). */
enum { FLOCK_USAGE = 64, FLOCK_DATAERR = 65, FLOCK_NOINPUT = 66,
       FLOCK_OSERR = 71 };

static int
flock_contended_errno (int e)
{
    return e == EWOULDBLOCK || e == EAGAIN;
}

static double
flock_monotonic_seconds (void)
{
    struct timespec ts;
    if (clock_gettime (CLOCK_MONOTONIC, &ts) != 0)
        return 0.0;
    return (double) ts.tv_sec + ((double) ts.tv_nsec / 1000000000.0);
}

static void
flock_sleep_until_retry (double deadline)
{
    double now = flock_monotonic_seconds ();
    double remaining = deadline - now;
    if (remaining <= 0.0)
        return;

    if (remaining > 0.01)
        remaining = 0.01;

    struct timespec req;
    req.tv_sec = (time_t) remaining;
    req.tv_nsec = (long) ((remaining - (double) req.tv_sec) * 1000000000.0);
    if (req.tv_sec == 0 && req.tv_nsec <= 0)
        req.tv_nsec = 1;

    while (nanosleep (&req, &req) < 0 && errno == EINTR) {
        if (flock_monotonic_seconds () >= deadline)
            break;
    }
}

/* Take `operation` on `fd`. timeout < 0 means block forever; timeout == 0
   is handled by the caller via LOCK_NB. Returns 0 on success, 1 if the lock
   is contended (would block / timed out), -1 on a real error (errno set). */
static int
flock_apply (int fd, int operation, double timeout)
{
    if (timeout < 0) {
        if (flock (fd, operation) == 0)
            return 0;
        return flock_contended_errno (errno) ? 1 : -1;
    }

    /* Timed wait: avoid SIGALRM in the Bash process. Poll with LOCK_NB until
       the monotonic deadline so -w cannot wedge in a restarted blocking
       flock(2) inside a loadable builtin. */
    double deadline = flock_monotonic_seconds () + timeout;
    for (;;) {
        if (flock (fd, operation | LOCK_NB) == 0)
            return 0;

        int saved_errno = errno;
        if (!flock_contended_errno (saved_errno)) {
            errno = saved_errno;
            return -1;
        }

        if (timeout <= 0.0 || flock_monotonic_seconds () >= deadline) {
            errno = saved_errno;
            return 1;
        }

        flock_sleep_until_retry (deadline);
    }
}

static int
flock_all_digits (const char *s)
{
    if (!s || !*s)
        return 0;
    for (const char *p = s; *p; p++)
        if (!isdigit ((unsigned char) *p))
            return 0;
    return 1;
}

static int
flock_parse_exit (const char *s, int *out)
{
    char *end;
    errno = 0;
    long value = strtol (s, &end, 10);
    if (errno || end == s || *end || value < 0 || value > 255) {
        builtin_error ("invalid conflict exit code: %s", s);
        return -1;
    }
    *out = (int) value;
    return 0;
}

int
flock_builtin (WORD_LIST *list)
{
    int locktype = LOCK_EX;          /* default exclusive */
    int nonblock = 0;
    int do_unlock = 0;
    int close_before_exec = 0;
    int no_fork = 0;
    int conflict_exit = 1;
    int timeout_given = 0;
    double timeout = -1.0;           /* <0 = block forever */
    char *shell_cmd = NULL;

    /* ---- option parsing (bundled short flags + long forms) ---- */
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        char *w = list->word->word;

        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) {
            for (char **lp = flock_doc; *lp; lp++) puts (*lp);
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version")) {
            puts ("flock 1.0 (bash-loadable, util-linux compatible subset)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--shared"))    { locktype = LOCK_SH; list = list->next; continue; }
        if (!strcmp (w, "--exclusive")) { locktype = LOCK_EX; list = list->next; continue; }
        if (!strcmp (w, "--unlock"))    { do_unlock = 1;      list = list->next; continue; }
        if (!strcmp (w, "--nonblock") || !strcmp (w, "--nb")) { nonblock = 1; list = list->next; continue; }
        if (!strcmp (w, "--close"))     { close_before_exec = 1; list = list->next; continue; }
        if (!strcmp (w, "--no-fork"))   { no_fork = 1;        list = list->next; continue; }
        if (!strcmp (w, "--wait") || !strcmp (w, "--timeout")) {
            if (!list->next) { builtin_error ("option '%s' requires an argument", w); return FLOCK_USAGE; }
            list = list->next;
            char *end = NULL; errno = 0;
            timeout = strtod (list->word->word, &end);
            if (errno || end == list->word->word || *end || !isfinite (timeout)) {
                builtin_error ("invalid timeout value: %s", list->word->word);
                return FLOCK_USAGE;
            }
            timeout_given = 1;
            list = list->next; continue;
        }
        if (!strcmp (w, "--command")) {
            if (!list->next) { builtin_error ("option '--command' requires an argument"); return FLOCK_USAGE; }
            list = list->next; shell_cmd = list->word->word; list = list->next; continue;
        }
        if (!strcmp (w, "--conflict-exit-code")) {
            if (!list->next) { builtin_error ("option '--conflict-exit-code' requires an argument"); return FLOCK_USAGE; }
            list = list->next;
            if (flock_parse_exit (list->word->word, &conflict_exit) < 0) return FLOCK_USAGE;
            list = list->next; continue;
        }
        if (w[1] == '-') { builtin_error ("unknown option: %s", w); builtin_usage (); return FLOCK_USAGE; }

        /* Bundled single-char flags: -s -x -e -u -n -o -F, plus -w/-E/-c which
           take an argument (the rest of this token or the next token). */
        int consumed_arg = 0;
        for (const char *c = w + 1; *c && !consumed_arg; c++) {
            switch (*c) {
                case 's': locktype = LOCK_SH; break;
                case 'x': case 'e': locktype = LOCK_EX; break;
                case 'u': do_unlock = 1; break;
                case 'n': nonblock = 1; break;
                case 'o': close_before_exec = 1; break;
                case 'F': no_fork = 1; break;
                case 'w': case 'E': case 'c': {
                    /* The argument is the rest of this token (e.g. -w5) or the
                       next token (-w 5). Both `val` (into w) and the next
                       token persist for the lifetime of the call, so it is safe
                       to keep a pointer for -c. */
                    char optc = *c;
                    const char *val = c + 1;
                    if (!*val) {
                        if (!list->next) { builtin_error ("option '-%c' requires an argument", optc); return FLOCK_USAGE; }
                        list = list->next;
                        val = list->word->word;
                    }
                    if (optc == 'w') {
                        char *end = NULL; errno = 0;
                        timeout = strtod (val, &end);
                        if (errno || end == val || *end || !isfinite (timeout)) {
                            builtin_error ("invalid timeout value: %s", val);
                            return FLOCK_USAGE;
                        }
                        timeout_given = 1;
                    } else if (optc == 'E') {
                        if (flock_parse_exit (val, &conflict_exit) < 0) return FLOCK_USAGE;
                    } else { /* 'c' */
                        shell_cmd = (char *) val;
                    }
                    consumed_arg = 1;
                    break;
                }
                default:
                    builtin_error ("unknown option: -%c", *c);
                    builtin_usage ();
                    return FLOCK_USAGE;
            }
        }
        list = list->next;
    }

    if (!list) {
        builtin_error ("requires a file name or descriptor");
        builtin_usage ();
        return FLOCK_USAGE;
    }
    if (no_fork && close_before_exec) {
        builtin_error ("--no-fork and --close are incompatible");
        return FLOCK_USAGE;
    }

    char *operand = list->word->word;
    list = list->next;                /* remaining list = command argv (file form) */

    /* util-linux flock permutes options past the file, so the canonical
       `flock FILE -c "cmd"` puts -c after the operand. Honour that here. */
    if (list && (!strcmp (list->word->word, "-c") || !strcmp (list->word->word, "--command"))) {
        if (!list->next || list->next->next) {
            builtin_error ("-c requires exactly one command argument");
            return FLOCK_USAGE;
        }
        shell_cmd = list->next->word->word;
        list = NULL;                  /* -c supplies the command; no argv */
    }

    if (shell_cmd && list) {
        builtin_error ("-c requires exactly one command argument");
        return FLOCK_USAGE;
    }

    int operation = (do_unlock ? LOCK_UN : locktype) | (nonblock ? LOCK_NB : 0);

    /* A single operand is a descriptor; with a command it is a pathname,
       including when the pathname consists only of digits. */
    int is_fd = !list && !shell_cmd;
    if (is_fd && !flock_all_digits (operand)) {
        builtin_error ("invalid file descriptor: %s", operand);
        return FLOCK_USAGE;
    }
    int fd, opened = 0;

    if (is_fd) {
        errno = 0;
        long number = strtol (operand, NULL, 10);
        if (errno || number > INT_MAX) {
            builtin_error ("invalid file descriptor: %s", operand);
            return FLOCK_USAGE;
        }
        fd = (int) number;
    } else {
        fd = open (operand, O_RDWR | O_CREAT, 0666);
        if (fd < 0 && (errno == EACCES || errno == EROFS))
            fd = open (operand, O_RDONLY);
        if (fd < 0) {
            builtin_error ("%s: %s", operand, strerror (errno));
            return FLOCK_NOINPUT;
        }
        opened = 1;
    }

    /* Match util-linux's timer-setup failure for a finite negative wait.
       Do this after pathname opening and before descriptor locking, without
       installing a process-wide timer or signal handler in the shell. */
    if (timeout_given && timeout < 0.0) {
        builtin_error ("cannot set up timer: %s", strerror (EINVAL));
        if (opened) close (fd);
        return FLOCK_OSERR;
    }
    if (is_fd && fcntl (fd, F_GETFD) == -1) {
        builtin_error ("%s: bad file descriptor", operand);
        return FLOCK_DATAERR;
    }

    /* Apply the lock (or unlock). */
    int lrc = flock_apply (fd, operation, nonblock ? -1 : timeout);
    /* nonblock takes its own fast path via LOCK_NB; timeout only matters for a
       blocking wait, hence the conditional above. */
    if (lrc == 1) {
        if (opened) close (fd);
        return conflict_exit;          /* contended / timed out */
    }
    if (lrc < 0) {
        builtin_error ("flock: %s", strerror (errno));
        if (opened) close (fd);
        return EXECUTION_FAILURE;
    }

    /* Unlock, or fd-form lock: done. The descriptor (and thus the lock, for
       the lock case) stays exactly as the caller left it. */
    if (do_unlock || is_fd) {
        if (do_unlock && opened) close (fd);
        return EXECUTION_SUCCESS;
    }

    /* File form: run the command while holding the lock, then release. */
    int status = EXECUTION_SUCCESS;
    maybe_make_export_env ();
    fflush (stdout);
    fflush (stderr);

    if (no_fork) {
        /* Replace this shell — flock(1)'s -F/-n no-fork behaviour. */
        char **argv = NULL;
        if (shell_cmd) {
            execl ("/bin/sh", "sh", "-c", shell_cmd, (char *) NULL);
        } else {
            int argc = 0; for (WORD_LIST *p = list; p; p = p->next) argc++;
            argv = calloc ((size_t) argc + 1, sizeof *argv);
            if (!argv) {
                builtin_error ("calloc: %s", strerror (errno));
                close (fd);
                return EXECUTION_FAILURE;
            }
            int i = 0; for (WORD_LIST *p = list; p; p = p->next) argv[i++] = p->word->word;
            argv[argc] = NULL;
            execvp (argv[0], argv);
        }
        int saved = errno;
        free (argv);
        close (fd);
        builtin_error ("exec: %s", strerror (saved));
        return saved == ENOENT ? 127 : 126;
    }

    bos_child_wait child_wait;
    if (bos_child_wait_begin (&child_wait) < 0) {
        builtin_error ("SIGCHLD setup: %s", strerror (errno));
        if (opened) close (fd);
        return EXECUTION_FAILURE;
    }

    pid_t pid = fork ();
    if (pid < 0) {
        builtin_error ("fork: %s", strerror (errno));
        bos_child_wait_end (&child_wait);
        if (opened) close (fd);
        return EXECUTION_FAILURE;
    }
    if (pid == 0) {
        bos_child_wait_child (&child_wait);
        if (close_before_exec) close (fd);
        if (shell_cmd) {
            execl ("/bin/sh", "sh", "-c", shell_cmd, (char *) NULL);
        } else {
            int argc = 0; for (WORD_LIST *p = list; p; p = p->next) argc++;
            char **argv = calloc ((size_t) argc + 1, sizeof *argv);
            if (argv) {
                int i = 0; for (WORD_LIST *p = list; p; p = p->next) argv[i++] = p->word->word;
                argv[argc] = NULL;
                execvp (argv[0], argv);
            }
        }
        int saved = errno;
        fprintf (stderr, "flock: failed to execute command: %s\n", strerror (saved));
        _exit (saved == ENOENT ? 127 : 126);
    }

    int wstatus = 0;
    pid_t w;
    while ((w = waitpid (pid, &wstatus, 0)) < 0 && errno == EINTR) ;
    bos_child_wait_end (&child_wait);
    if (w < 0) {
        builtin_error ("waitpid: %s", strerror (errno));
        if (opened) close (fd);
        return EXECUTION_FAILURE;
    }
    if (WIFEXITED (wstatus))        status = WEXITSTATUS (wstatus);
    else if (WIFSIGNALED (wstatus)) status = 128 + WTERMSIG (wstatus);

    if (opened) close (fd);            /* releases the lock */
    return status;
}

char *flock_doc[] = {
    "Manage advisory file locks via flock(2).",
    "",
    "    flock [-sxun] [-w SECONDS] FD",
    "    flock [-sxun] [-w SECONDS] FILE command [args...]",
    "    flock [-sxun] [-w SECONDS] FILE -c \"shell command\"",
    "",
    "    -s, --shared        shared lock",
    "    -x, -e, --exclusive exclusive lock (default)",
    "    -u, --unlock        release a lock",
    "    -n, --nb, --nonblock fail instead of waiting if the lock is held",
    "    -w, --wait SECONDS  wait at most SECONDS for the lock (fractional ok)",
    "    -E N, --conflict-exit-code N  exit code on -n/-w failure (default 1)",
    "    -o, --close         close the descriptor before running the command",
    "    -F, --no-fork       exec the command without forking",
    "    -c, --command CMD   pass a single command to /bin/sh -c",
    "",
    "The FD form runs in the current shell, so `flock -x 9` locks a descriptor",
    "opened with `exec 9>file` and the lock persists after flock returns.",
    "On a non-blocking or timed-out conflict, flock exits with the conflict",
    "exit code (default 1) and prints nothing.",
    (char *) NULL
};

struct builtin flock_struct = {
    "flock",
    flock_builtin,
    BUILTIN_ENABLED,
    flock_doc,
    "flock [-sxun] [-w SECONDS] [-E N] FD | FILE [command [args] | -c CMD]",
    0
};
