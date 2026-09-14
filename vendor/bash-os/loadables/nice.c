/* bashnice.c — POSIX nice(1) as a bash builtin.
 *
 *   bashnice [--help|--version] [-n N] CMD [ARGS...]
 *
 * Adjusts the niceness of the about-to-fork child by N (default +10),
 * then execs CMD. Negative N requires CAP_SYS_NICE / uid 0. Closes a
 * POSIX-2024 medium-impact gap (see POSIX-CONFORMANCE-RESEARCH §4.1).
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
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include "loadables.h"
#include "command-run.h"

extern char *nice_doc[];

/* nice(1)'s own errors exit with EXIT_CANCELED (125), distinct from the
   126/127 used for the command. */
#define BNICE_CANCELED 125

/* Parse an adjustment value (decimal, optional sign). Rejects junk rather
   than coercing it to 0 like atoi, matching GNU's xstrtol validation. */
static int
bnice_parse_adj (const char *s, int *out)
{
    if (!s || !*s)
        return -1;
    char *end = NULL;
    errno = 0;
    long v = strtol (s, &end, 10);
    if (errno != 0 || end == s || *end != '\0')
        return -1;
    *out = (int) v;
    return 0;
}

int
nice_builtin (WORD_LIST *list)
{
    int incr = 10;
    int adjustment_given = 0;
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
	    if (!strcmp (w, "--help")) {
	        for (char **lp = nice_doc; *lp; lp++)
	            puts (*lp);
	        return EXECUTION_SUCCESS;
	    }
	    if (!strcmp (w, "--version")) {
	        puts ("bashnice 1.0 (bash-loadable, coreutils-compatible)");
	        return EXECUTION_SUCCESS;
	    }
	    if (!strcmp (w, "--")) { list = list->next; break; }
	    if (!strcmp (w, "-n") || !strcmp (w, "--adjustment")) {
	        if (!list->next) { builtin_error ("option '%s' requires an argument", w); builtin_usage (); return BNICE_CANCELED; }
	        list = list->next;
	        if (bnice_parse_adj (list->word->word, &incr) < 0)
	            { builtin_error ("invalid adjustment '%s'", list->word->word); return BNICE_CANCELED; }
	        adjustment_given = 1;
            list = list->next;
            continue;
        }
	    if (!strncmp (w, "--adjustment=", 13)) {
	        if (bnice_parse_adj (w + 13, &incr) < 0)
	            { builtin_error ("invalid adjustment '%s'", w + 13); return BNICE_CANCELED; }
	        adjustment_given = 1;
	        list = list->next;
	        continue;
	    }
	    if (!strncmp (w, "-n", 2) && w[2]) {
	        if (bnice_parse_adj (w + 2, &incr) < 0)
	            { builtin_error ("invalid adjustment '%s'", w + 2); return BNICE_CANCELED; }
	        adjustment_given = 1;
	        list = list->next;
	        continue;
	    }
	    if (w[1] == '-') {
	        builtin_error ("unknown flag: %s", w);
	        builtin_usage ();
	        return BNICE_CANCELED;
	    }
	    /* POSIX/obsolete shorthand: -N (e.g. nice -10 CMD). */
	    if (w[1] >= '0' && w[1] <= '9') {
	        if (bnice_parse_adj (w + 1, &incr) < 0)
	            { builtin_error ("invalid adjustment '%s'", w + 1); return BNICE_CANCELED; }
	        adjustment_given = 1;
	        list = list->next;
            continue;
	    }
	    builtin_error ("unknown flag: %s", w);
	    builtin_usage ();
	    return BNICE_CANCELED;
	}
    if (!list) {
        /* GNU: an adjustment without a command is an error. */
        if (adjustment_given) {
            builtin_error ("a command must be given with an adjustment");
            builtin_usage ();
            return BNICE_CANCELED;
        }
        /* POSIX: with no CMD, print current niceness. */
        errno = 0;
        int cur = getpriority (PRIO_PROCESS, 0);
        if (cur == -1 && errno != 0) {
            builtin_error ("getpriority: %s", strerror (errno));
            return EXECUTION_FAILURE;
        }
        printf ("%d\n", cur);
        return EXECUTION_SUCCESS;
    }
    /* Build argv. */
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

    sigset_t chld_set, prev_mask;
    sigemptyset (&chld_set);
    sigaddset (&chld_set, SIGCHLD);
    sigprocmask (SIG_BLOCK, &chld_set, &prev_mask);

    /* Fork so we don't poison the calling shell's niceness. */
    maybe_make_export_env ();
    fflush (stdout);
    fflush (stderr);
    pid_t pid = fork ();
    if (pid < 0) {
        int e = errno;
        sigprocmask (SIG_SETMASK, &prev_mask, NULL);
        sigaction (SIGCHLD, &chld_save, NULL);
        builtin_error ("fork: %s", strerror (e));
        free (argv);
        return EXECUTION_FAILURE;
    }
    if (pid == 0) {
        bos_prepare_child ();
        sigprocmask (SIG_SETMASK, &prev_mask, NULL);
        errno = 0;
        if (setpriority (PRIO_PROCESS, 0, getpriority (PRIO_PROCESS, 0) + incr) < 0) {
            fprintf (stderr, "nice: setpriority(%d): %s\n", incr, strerror (errno));
            /* POSIX says: continue anyway with the original priority. */
        }
        bos_run_builtin (argv[0], argv, NULL);
        execvp (argv[0], argv);
        int err = errno;
        fprintf (stderr, "nice: %s: %s\n", argv[0], strerror (err));
        _exit (err == ENOENT ? 127 : 126);
    }
    free (argv);
    int status = 0;
    pid_t w;
    while ((w = waitpid (pid, &status, 0)) < 0 && errno == EINTR) ;
    if (w < 0) {
        int e = errno;
        sigprocmask (SIG_SETMASK, &prev_mask, NULL);
        sigaction (SIGCHLD, &chld_save, NULL);
        builtin_error ("waitpid: %s", strerror (e));
        return EXECUTION_FAILURE;
    }
    sigprocmask (SIG_SETMASK, &prev_mask, NULL);
    sigaction (SIGCHLD, &chld_save, NULL);
    if (WIFEXITED (status))   return WEXITSTATUS (status);
    if (WIFSIGNALED (status)) return 128 + WTERMSIG (status);
    return EXECUTION_FAILURE;
}

char *nice_doc[] = {
    "Run CMD with adjusted scheduling niceness (POSIX nice).",
    "CMD may be an enabled shell builtin or an external executable.",
    "",
    "    bashnice [--help|--version] [-n N | --adjustment=N | -N] CMD [ARGS...]",
    "    bashnice                 (print current niceness)",
    "",
    "    -n, --adjustment=N  add N to the niceness (default +10)",
    "    --help      show this help",
    "    --version   show version",
    "",
    "An adjustment with no CMD is an error; a non-numeric N is rejected",
    "(both exit 125). Default increment is +10 (lower priority). Negative N requires",
    "CAP_SYS_NICE or uid 0. Setpriority failures are non-fatal: CMD",
    "still execs at the original priority with a stderr warning.",
    (char *)NULL
};

struct builtin bashnice_struct = {
    "bashnice",
    nice_builtin,
    BUILTIN_ENABLED,
    nice_doc,
    "bashnice [--help|--version] [-n N | --adjustment=N | -N] [CMD [ARGS...]]",
    0
};
