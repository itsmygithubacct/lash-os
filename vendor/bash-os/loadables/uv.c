/* SPDX-License-Identifier: MIT */
/* uv: run the uv Python package manager that `pkg install uv` puts beside
 * this loadable.
 *
 * The package installs loadable/uv.so under /usr/lib/bash-os/loadables and
 * upstream's static uv executable at /usr/lib/bash-os/libexec/uv/uv. The
 * builtin finds the program relative to its own shared object, so it works
 * with an empty PATH and under pkg --root, and runs it as the shell runs an
 * external command: with the exported variables, default job-control
 * signals, and uv's exit status (128+N when uv dies of signal N). uv cannot
 * run inside the shell process: its entry point assumes a fresh process
 * that has started no threads.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <config.h>

#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "loadables.h"
#include "command-run.h"

#define UV_PROGRAM "/usr/lib/bash-os/libexec/uv/uv"

/* Resolved when uv.so is loaded; empty when the builtin is compiled in. */
static char uv_path[PATH_MAX];

/* Called by enable -f while the path given to dlopen is still valid
   relative to the current directory. */
int
uv_builtin_load (char *name)
{
    (void) name;
    Dl_info info;
    if (!dladdr ((void *) uv_builtin_load, &info) || !info.dli_fname)
        return 1;
    const char *slash = strrchr (info.dli_fname, '/');
    const char *base = slash ? slash + 1 : info.dli_fname;
    if (strcmp (base, "uv.so") != 0)
        return 1;
    char dir[PATH_MAX], resolved[PATH_MAX];
    if (slash) {
        if ((size_t) (slash - info.dli_fname) >= sizeof dir)
            return 1;
        snprintf (dir, sizeof dir, "%.*s", (int) (slash - info.dli_fname),
                  info.dli_fname);
    } else {
        snprintf (dir, sizeof dir, ".");
    }
    if (!realpath (dir, resolved) ||
        snprintf (uv_path, sizeof uv_path, "%s/../libexec/uv/uv", resolved) >=
            (int) sizeof uv_path)
        uv_path[0] = 0;
    return 1;
}

/* What bash does for an external command: SIGINT and SIGQUIT back to their
   defaults unless the script trapped or ignored them. */
static void
uv_reset_job_signals (void)
{
    static const int sigs[] = { SIGINT, SIGQUIT };
    for (size_t i = 0; i < sizeof sigs / sizeof *sigs; i++) {
        if (signal_is_trapped (sigs[i]) || signal_is_hard_ignored (sigs[i]))
            continue;
        struct sigaction sa;
        memset (&sa, 0, sizeof sa);
        sa.sa_handler = SIG_DFL;
        sigemptyset (&sa.sa_mask);
        sigaction (sigs[i], &sa, NULL);
    }
}

int
uv_builtin (WORD_LIST *list)
{
    const char *program = uv_path[0] ? uv_path : UV_PROGRAM;
    if (access (program, X_OK) < 0) {
        builtin_error ("%s: %s (install it with: pkg install uv)", program,
                       strerror (errno));
        return EX_NOTFOUND;
    }

    int argc = 1;
    for (WORD_LIST *p = list; p; p = p->next)
        argc++;
    char **argv = calloc ((size_t) argc + 1, sizeof *argv);
    if (!argv) {
        builtin_error ("%s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    argv[0] = "uv";
    int i = 1;
    for (WORD_LIST *p = list; p; p = p->next)
        argv[i++] = p->word->word;

    /* bash's asynchronous SIGCHLD handler must not reap the child first. */
    struct sigaction chld_dfl, chld_save;
    memset (&chld_dfl, 0, sizeof chld_dfl);
    chld_dfl.sa_handler = SIG_DFL;
    sigemptyset (&chld_dfl.sa_mask);
    sigaction (SIGCHLD, &chld_dfl, &chld_save);
    sigset_t chld_set, old_set;
    sigemptyset (&chld_set);
    sigaddset (&chld_set, SIGCHLD);
    sigprocmask (SIG_BLOCK, &chld_set, &old_set);

    maybe_make_export_env ();
    fflush (stdout);
    fflush (stderr);
    pid_t pid = fork ();
    if (pid == 0) {
        bos_prepare_child ();
        sigprocmask (SIG_SETMASK, &old_set, NULL);
        uv_reset_job_signals ();
        execve (program, argv, export_env);
        int err = errno;
        fprintf (stderr, "uv: %s: %s\n", program, strerror (err));
        _exit (err == ENOENT ? EX_NOTFOUND : EX_NOEXEC);
    }
    int err = errno;
    free (argv);
    int status = 0, rc = -1;
    if (pid > 0)
        while ((rc = waitpid (pid, &status, 0)) < 0 && errno == EINTR)
            ;
    else
        errno = err;
    sigprocmask (SIG_SETMASK, &old_set, NULL);
    sigaction (SIGCHLD, &chld_save, NULL);
    if (rc < 0) {
        builtin_error ("%s: %s", pid < 0 ? "fork" : "waitpid", strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (WIFEXITED (status))
        return WEXITSTATUS (status);
    if (WIFSIGNALED (status))
        return 128 + WTERMSIG (status);
    return EXECUTION_FAILURE;
}

char *uv_doc[] = {
    "Run the uv Python package manager installed by pkg.",
    "",
    "Runs uv with ARGS and the shell's exported variables: the program at",
    "../libexec/uv/uv beside a loaded uv.so, or /usr/lib/bash-os/libexec/uv/uv",
    "when the builtin is compiled in. Install both with `pkg install uv`.",
    "",
    "Exit Status:",
    "uv's status, 128+N if uv is killed by signal N, or 127 if uv is not",
    "installed.",
    (char *) NULL
};

struct builtin uv_struct = {
    "uv",
    uv_builtin,
    BUILTIN_ENABLED,
    uv_doc,
    "uv [UV-ARGS ...]",
    0
};
