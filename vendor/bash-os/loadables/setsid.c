/* SPDX-License-Identifier: MIT */
/* setsid.c — run a program in a new session, as a bash builtin.
 *
 *   setsid [-w] [-f] [-c] program [args...]
 *
 *   -w, --wait      wait for the program, then return its exit status
 *   -f, --fork      always fork (default: fork only if already a group leader)
 *   -c, --ctty      set the controlling terminal to the current stdin
 *
 * setsid(2) fails if the caller is a process-group leader, so we fork a child
 * that is guaranteed not to be one, call setsid() there, and exec the program.
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
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <termios.h>

#include "loadables.h"

extern char *setsid_doc[];

int
setsid_builtin (WORD_LIST *list)
{
    int do_wait = 0, set_ctty = 0;
    /* -f (always fork) is implied: we always fork so setsid() can't fail on a
       group-leader caller. The flag is accepted for compatibility. */

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { for (char **lp = setsid_doc; *lp; lp++) puts (*lp); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "--version")) { puts ("setsid 1.0 (bash-loadable)"); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "-w") || !strcmp (w, "--wait")) { do_wait = 1; list = list->next; continue; }
        if (!strcmp (w, "-f") || !strcmp (w, "--fork")) { list = list->next; continue; }
        if (!strcmp (w, "-c") || !strcmp (w, "--ctty")) { set_ctty = 1; list = list->next; continue; }
        builtin_error ("unknown option: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    if (!list) {
        builtin_error ("no program specified");
        builtin_usage ();
        return EX_USAGE;
    }

    int argc = 0;
    for (WORD_LIST *p = list; p; p = p->next) argc++;
    char **argv = calloc ((size_t) argc + 1, sizeof *argv);
    if (!argv) { builtin_error ("calloc: %s", strerror (errno)); return EXECUTION_FAILURE; }
    int i = 0;
    for (WORD_LIST *p = list; p; p = p->next) argv[i++] = p->word->word;
    argv[argc] = NULL;

    struct sigaction chld_dfl, chld_save;
    memset (&chld_dfl, 0, sizeof chld_dfl);
    chld_dfl.sa_handler = SIG_DFL;
    sigemptyset (&chld_dfl.sa_mask);
    sigaction (SIGCHLD, &chld_dfl, &chld_save);

    pid_t pid = fork ();
    if (pid < 0) {
        builtin_error ("fork: %s", strerror (errno));
        sigaction (SIGCHLD, &chld_save, NULL);
        free (argv);
        return EXECUTION_FAILURE;
    }
    if (pid == 0) {
        if (setsid () < 0) {
            fprintf (stderr, "setsid: %s\n", strerror (errno));
            _exit (126);
        }
        if (set_ctty) {
            if (ioctl (STDIN_FILENO, TIOCSCTTY, 0) < 0) {
                fprintf (stderr, "setsid: TIOCSCTTY: %s\n", strerror (errno));
                /* non-fatal */
            }
        }
        execvp (argv[0], argv);
        fprintf (stderr, "setsid: %s: %s\n", argv[0], strerror (errno));
        _exit (errno == ENOENT ? 127 : 126);
    }

    free (argv);
    int status = EXECUTION_SUCCESS;
    if (do_wait) {
        int wst = 0; pid_t w;
        while ((w = waitpid (pid, &wst, 0)) < 0 && errno == EINTR) ;
        if (w < 0) { builtin_error ("waitpid: %s", strerror (errno)); status = EXECUTION_FAILURE; }
        else if (WIFEXITED (wst))   status = WEXITSTATUS (wst);
        else if (WIFSIGNALED (wst)) status = 128 + WTERMSIG (wst);
    }
    sigaction (SIGCHLD, &chld_save, NULL);
    return status;
}

char *setsid_doc[] = {
    "Run a program in a new session.",
    "",
    "    setsid [-w] [-f] [-c] program [args...]",
    "",
    "    -w, --wait   wait for the program and return its exit status",
    "    -f, --fork   always fork (the default here; setsid(2) needs a non-leader)",
    "    -c, --ctty   set the controlling terminal to the current stdin",
    "",
    "Without -w, setsid returns immediately and the program runs detached.",
    (char *) NULL
};

struct builtin setsid_struct = {
    "setsid",
    setsid_builtin,
    BUILTIN_ENABLED,
    setsid_doc,
    "setsid [-w] [-f] [-c] program [args...]",
    0
};
