/* bashnohup.c — POSIX nohup(1) as a bash builtin.
 *
 * Closes the POSIX gap noted in POSIX-CONFORMANCE-RESEARCH.md §4.1.
 * Runs CMD with SIGHUP ignored and (when stdout/stderr is a tty)
 * redirected to ./nohup.out (or $HOME/nohup.out as POSIX fallback).
 * stdin gets redirected from /dev/null when it's a tty.
 *
 *   bashnohup CMD [ARGS...]
 *
 * POSIX exit codes:
 *   126 — CMD found but not executable
 *   127 — CMD not found
 *   128+sig — CMD killed by signal
 *   0..125 — CMD's exit status
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
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "loadables.h"
#include "command-run.h"

extern char *nohup_doc[];

#define BN_USAGE_FAILURE 125

/* Redirect tty fds and emit the coreutils-shaped diagnostic.

   Behaviour matches GNU coreutils nohup 9.x exactly (verified empirically
   against /usr/bin/nohup across all eight tty(stdin,stdout,stderr) combos):

     - stdin  is a tty -> reopen from /dev/null  ("ignoring input")
     - stdout is a tty -> append to ./nohup.out (or $HOME/nohup.out per POSIX)
     - stderr is a tty -> dup2 onto stdout (whatever stdout now is)

   A single diagnostic line is printed to the *original* stderr (before the
   stderr dup2) built from two optional clauses joined by " and ":

       in-clause  = "ignoring input"                    (iff stdin tty)
       out-clause = "appending output to '<path>'"      (iff stdout tty)
                  | "redirecting stderr to stdout"       (iff !stdout tty &&
                                                              stderr tty)
                  | (none)

   <path> is the actual file opened (nohup.out or the HOME fallback),
   single-quoted as coreutils' quoteaf() renders an unspecial name. */
static int
bn_redirect_tty (void)
{
    const int in_tty  = isatty (STDIN_FILENO);
    const int out_tty = isatty (STDOUT_FILENO);
    const int err_tty = isatty (STDERR_FILENO);

    /* stdin: /dev/null if tty. */
    if (in_tty) {
        int devnull = open ("/dev/null", O_RDONLY | O_CLOEXEC);
        if (devnull < 0) {
            builtin_error ("open /dev/null: %s", strerror (errno));
            return -1;
        }
        if (dup2 (devnull, STDIN_FILENO) < 0) {
            close (devnull);
            builtin_error ("dup2 stdin: %s", strerror (errno));
            return -1;
        }
        close (devnull);
    }

    /* stdout: nohup.out (cwd, then HOME) if tty. Remember the path used so
       the diagnostic names the real file (matches GNU's HOME fallback). */
    int out_fd = -1;
    char *home_path = NULL;          /* freed before return */
    const char *path_used = NULL;
    if (out_tty) {
        path_used = "nohup.out";
        out_fd = open (path_used, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (out_fd < 0) {
            const char *home = getenv ("HOME");
            if (home && *home) {
                size_t hl = strlen (home);
                home_path = malloc (hl + sizeof "/nohup.out");
                if (home_path) {
                    memcpy (home_path, home, hl);
                    memcpy (home_path + hl, "/nohup.out", sizeof "/nohup.out");
                    out_fd = open (home_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
                    if (out_fd >= 0)
                        path_used = home_path;
                }
            }
        }
        if (out_fd < 0) {
            builtin_error ("cannot open nohup.out: %s", strerror (errno));
            free (home_path);
            return -1;
        }
        if (dup2 (out_fd, STDOUT_FILENO) < 0) {
            close (out_fd);
            free (home_path);
            builtin_error ("dup2 stdout: %s", strerror (errno));
            return -1;
        }
    }

    /* Emit the single combined diagnostic to the original stderr, before the
       stderr->stdout dup2 so it lands on the user's terminal (as GNU does). */
    if (in_tty || out_tty || err_tty) {
        const char *in_clause = in_tty ? "ignoring input" : NULL;
        if (out_tty)
            fprintf (stderr, "nohup: %s%sappending output to '%s'\n",
                     in_clause ? in_clause : "", in_clause ? " and " : "",
                     path_used);
        else if (err_tty)
            fprintf (stderr, "nohup: %s%sredirecting stderr to stdout\n",
                     in_clause ? in_clause : "", in_clause ? " and " : "");
        else if (in_clause)
            fprintf (stderr, "nohup: %s\n", in_clause);
    }

    /* stderr: coreutils dups a tty stderr onto stdout (whatever it now is). */
    if (err_tty) {
        if (dup2 (STDOUT_FILENO, STDERR_FILENO) < 0) {
            if (out_fd >= 0) close (out_fd);
            free (home_path);
            builtin_error ("dup2 stderr->stdout: %s", strerror (errno));
            return -1;
        }
    }
    if (out_fd >= 0) close (out_fd);
    free (home_path);
    return 0;
}

static void
bn_exec_shell_fallback (char **argv, int argc)
{
    char **sh_argv = calloc ((size_t) argc + 2, sizeof *sh_argv);
    if (!sh_argv)
        return;

    sh_argv[0] = "sh";
    sh_argv[1] = argv[0];
    for (int i = 1; i < argc; i++)
        sh_argv[i + 1] = argv[i];
    sh_argv[argc + 1] = NULL;

    execv ("/bin/sh", sh_argv);
    execvp ("sh", sh_argv);
    free (sh_argv);
}

int
nohup_builtin (WORD_LIST *list)
{
	if (!list) {
	    builtin_usage ();
	    return BN_USAGE_FAILURE;
	}

    /* coreutils-shape info flags before the command. The only flags
       coreutils nohup itself recognizes are --help and --version; any
       other leading argument is treated as the command name. A literal
       `--` terminates option parsing so e.g. `bashnohup -- --help`
       still execs a program named `--help`. */
    {
        const char *w = list->word->word;
        if (!strcmp (w, "--help") || !strcmp (w, "-h")) {
            for (char **lp = nohup_doc; *lp; lp++) puts (*lp);
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version") || !strcmp (w, "-V")) {
            puts ("bashnohup 1.0 (bash-loadable, coreutils-compatible)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--")) {
            list = list->next;
            if (!list) {
                builtin_usage ();
                return BN_USAGE_FAILURE;
            }
        } else if (w[0] == '-' && w[1] != '\0') {
            builtin_error ("invalid option: %s", w);
            builtin_usage ();
            return BN_USAGE_FAILURE;
        }
    }

    /* Build argv. */
    int argc = 0;
    for (WORD_LIST *p = list; p; p = p->next) argc++;
    char **argv = calloc ((size_t) argc + 1, sizeof *argv);
    if (!argv) {
        builtin_error ("calloc: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    int i = 0;
    for (WORD_LIST *p = list; p; p = p->next) argv[i++] = p->word->word;
    argv[argc] = NULL;

    /* Fork so the loadable can return cleanly to the calling shell.
       Child execs CMD; parent waits and propagates exit code.
       Reset SIGCHLD to default first: bash installs an async SIGCHLD
       handler for job control, and when a non-interactive bash
       (e.g. the bl-test runner) executes us, that handler can reap
       the child before our waitpid sees it. waitpid then returns
       -1/ECHILD and bashnohup mis-reports the rc as EXECUTION_FAILURE
       instead of forwarding the child's actual exit status. */
    struct sigaction chld_dfl;
    memset (&chld_dfl, 0, sizeof chld_dfl);
    chld_dfl.sa_handler = SIG_DFL;
    sigemptyset (&chld_dfl.sa_mask);
    struct sigaction chld_save;
    sigaction (SIGCHLD, &chld_dfl, &chld_save);
    sigset_t chld_set, old_set;
    sigemptyset (&chld_set);
    sigaddset (&chld_set, SIGCHLD);
    if (sigprocmask (SIG_BLOCK, &chld_set, &old_set) < 0) {
        sigaction (SIGCHLD, &chld_save, NULL);
        free (argv);
        return EXECUTION_FAILURE;
    }

    maybe_make_export_env ();
    fflush (stdout);
    fflush (stderr);
    pid_t pid = fork ();
    if (pid < 0) {
        builtin_error ("fork: %s", strerror (errno));
        sigprocmask (SIG_SETMASK, &old_set, NULL);
        sigaction (SIGCHLD, &chld_save, NULL);
        free (argv);
        return EXECUTION_FAILURE;
    }
    if (pid == 0) {
        bos_prepare_child ();
        sigprocmask (SIG_SETMASK, &old_set, NULL);
        /* Only the command child owns nohup's fd and signal changes. */
        struct sigaction sa;
        memset (&sa, 0, sizeof sa);
        sa.sa_handler = SIG_IGN;
        sigemptyset (&sa.sa_mask);
        if (sigaction (SIGHUP, &sa, NULL) < 0) {
            builtin_error ("sigaction(SIGHUP): %s", strerror (errno));
            _exit (EXECUTION_FAILURE);
        }
        if (bn_redirect_tty () < 0)
            _exit (BN_USAGE_FAILURE);
        bos_run_builtin (argv[0], argv, NULL);
        execvp (argv[0], argv);
        int err = errno;
        if (err == ENOEXEC) {
            bn_exec_shell_fallback (argv, argc);
            err = errno;
        }
        fprintf (stderr, "nohup: failed to run command '%s': %s\n",
                 argv[0], strerror (err));
        _exit (err == ENOENT ? 127 : 126);
    }
    free (argv);
    int status = 0;
    int wrc;
    while ((wrc = waitpid (pid, &status, 0)) < 0 && errno == EINTR)
        ;
    sigprocmask (SIG_SETMASK, &old_set, NULL);
    sigaction (SIGCHLD, &chld_save, NULL);
    if (wrc < 0) {
        builtin_error ("waitpid: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (WIFEXITED (status))   return WEXITSTATUS (status);
    if (WIFSIGNALED (status)) return 128 + WTERMSIG (status);
    return EXECUTION_FAILURE;
}

char *nohup_doc[] = {
    "Run CMD with SIGHUP ignored and tty fds redirected.",
    "CMD may be an enabled shell builtin or an external executable.",
    "",
    "    bashnohup CMD [ARGS...]",
    "",
    "If stdin is a terminal, it is reopened from /dev/null. If stdout",
    "or stderr is a terminal, it is appended to ./nohup.out (or",
    "$HOME/nohup.out as POSIX fallback). SIGHUP is set to SIG_IGN so",
    "the child survives controlling-terminal disconnect.",
    "",
    "Exit codes: CMD's status normally; 126 if CMD found but not",
    "executable; 127 if not found; 128+sig if killed by signal.",
    (char *)NULL
};

struct builtin bashnohup_struct = {
    "bashnohup",
    nohup_builtin,
    BUILTIN_ENABLED,
    nohup_doc,
    "bashnohup CMD [ARGS...]",
    0
};
