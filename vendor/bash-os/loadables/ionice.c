/* SPDX-License-Identifier: MIT */
/* ionice.c — get/set I/O scheduling class & priority, as a bash builtin.
 *
 *   ionice [-c CLASS] [-n LEVEL] -p PID...     # set (or, with no -c/-n, get)
 *   ionice [-c CLASS] [-n LEVEL] command [args] # set for a new process
 *   ionice -p PID                               # print PID's class/priority
 *
 *   -c CLASS  none|0, realtime|rt|1, best-effort|be|2, idle|3
 *   -n LEVEL  priority within the class, 0 (highest) .. 7 (lowest)
 *   -p PID    act on an existing process (repeatable)
 *   -t        ignore failures when setting
 *
 * Uses the ioprio_get/ioprio_set syscalls directly (no libc wrappers).
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
#include <sys/syscall.h>
#include <sys/wait.h>

#include "loadables.h"

extern char *ionice_doc[];

#define IOPRIO_CLASS_SHIFT 13
#define IOPRIO_PRIO_MASK   ((1u << IOPRIO_CLASS_SHIFT) - 1)
#define IOPRIO_PRIO_CLASS(v) ((v) >> IOPRIO_CLASS_SHIFT)
#define IOPRIO_PRIO_DATA(v)  ((v) & IOPRIO_PRIO_MASK)
#define IOPRIO_PRIO_VALUE(c, d) (((c) << IOPRIO_CLASS_SHIFT) | (d))

enum { IOPRIO_CLASS_NONE = 0, IOPRIO_CLASS_RT = 1, IOPRIO_CLASS_BE = 2, IOPRIO_CLASS_IDLE = 3 };
enum { IOPRIO_WHO_PROCESS = 1 };

static const char *class_names[] = { "none", "realtime", "best-effort", "idle" };

static int
ioprio_get_p (int pid)
{
    return (int) syscall (SYS_ioprio_get, IOPRIO_WHO_PROCESS, pid);
}
static int
ioprio_set_p (int pid, int class, int data)
{
    return (int) syscall (SYS_ioprio_set, IOPRIO_WHO_PROCESS, pid,
                          IOPRIO_PRIO_VALUE (class, data));
}

static int
parse_class (const char *s, int *out)
{
    if (!strcmp (s, "none")  || !strcmp (s, "0")) { *out = IOPRIO_CLASS_NONE; return 0; }
    if (!strcmp (s, "realtime") || !strcmp (s, "rt") || !strcmp (s, "1")) { *out = IOPRIO_CLASS_RT; return 0; }
    if (!strcmp (s, "best-effort") || !strcmp (s, "be") || !strcmp (s, "2")) { *out = IOPRIO_CLASS_BE; return 0; }
    if (!strcmp (s, "idle") || !strcmp (s, "3")) { *out = IOPRIO_CLASS_IDLE; return 0; }
    return -1;
}

static void
print_ioprio (int pid)
{
    int v = ioprio_get_p (pid);
    if (v < 0) { printf ("unknown\n"); return; }
    int cls = IOPRIO_PRIO_CLASS (v);
    int data = IOPRIO_PRIO_DATA (v);
    if (cls < 0 || cls > 3) cls = 0;
    /* util-linux prints the bare class name only for idle; every other class,
       none included, carries its priority ("none: prio 0"). */
    if (cls == IOPRIO_CLASS_IDLE)
        printf ("%s\n", class_names[cls]);
    else
        printf ("%s: prio %d\n", class_names[cls], data);
}

int
ionice_builtin (WORD_LIST *list)
{
    int klass = -1, level = -1, ignore_fail = 0;
    int pids[256]; int npid = 0;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { for (char **lp = ionice_doc; *lp; lp++) puts (*lp); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "--version")) { puts ("ionice 1.0 (bash-loadable)"); return EXECUTION_SUCCESS; }

        const char *val = NULL;
        char opt = 0;
        if (w[1] == 'c' || w[1] == 'n' || w[1] == 'p') {
            opt = w[1];
            if (w[2]) val = w + 2;
            else { if (!list->next) { builtin_error ("option '-%c' requires an argument", opt); return EX_USAGE; }
                   list = list->next; val = list->word->word; }
        } else if (!strcmp (w, "--class"))     { opt = 'c'; if (!list->next){builtin_error("--class requires an argument");return EX_USAGE;} list=list->next; val=list->word->word; }
        else if (!strcmp (w, "--classdata"))   { opt = 'n'; if (!list->next){builtin_error("--classdata requires an argument");return EX_USAGE;} list=list->next; val=list->word->word; }
        else if (!strcmp (w, "--pid"))         { opt = 'p'; if (!list->next){builtin_error("--pid requires an argument");return EX_USAGE;} list=list->next; val=list->word->word; }
        else if (!strcmp (w, "-t") || !strcmp (w, "--ignore")) { ignore_fail = 1; list = list->next; continue; }
        else { builtin_error ("unknown option: %s", w); builtin_usage (); return EX_USAGE; }

        if (opt == 'c') {
            if (parse_class (val, &klass) < 0) { builtin_error ("invalid class: %s", val); return EX_USAGE; }
        } else if (opt == 'n') {
            char *end = NULL; long l = strtol (val, &end, 10);
            if (*end || l < 0 || l > 7) { builtin_error ("invalid priority (0-7): %s", val); return EX_USAGE; }
            level = (int) l;
        } else if (opt == 'p') {
            char *end = NULL; long l = strtol (val, &end, 10);
            if (*end || l < 0) { builtin_error ("invalid pid: %s", val); return EX_USAGE; }
            if (npid < (int)(sizeof pids / sizeof pids[0])) pids[npid++] = (int) l;
        }
        list = list->next;
    }

    int set_mode = (klass >= 0 || level >= 0);
    /* When setting, default the class to best-effort and the level to 4. */
    int eff_class = (klass >= 0) ? klass : IOPRIO_CLASS_BE;
    int eff_level = (level >= 0) ? level : 4;

    if (npid > 0) {
        int rc = EXECUTION_SUCCESS;
        for (int i = 0; i < npid; i++) {
            if (set_mode) {
                if (ioprio_set_p (pids[i], eff_class, eff_level) < 0 && !ignore_fail) {
                    builtin_error ("ioprio_set (pid %d): %s", pids[i], strerror (errno));
                    rc = EXECUTION_FAILURE;
                }
            } else {
                print_ioprio (pids[i]);
            }
        }
        return rc;
    }

    if (!list) {
        /* No pid, no command: print our own class/priority. */
        print_ioprio (0);
        return EXECUTION_SUCCESS;
    }

    /* Command form: set our intended class, then fork+exec it. */
    int argc = 0; for (WORD_LIST *p = list; p; p = p->next) argc++;
    char **argv = calloc ((size_t) argc + 1, sizeof *argv);
    if (!argv) { builtin_error ("calloc: %s", strerror (errno)); return EXECUTION_FAILURE; }
    int i = 0; for (WORD_LIST *p = list; p; p = p->next) argv[i++] = p->word->word;
    argv[argc] = NULL;

    struct sigaction chld_dfl, chld_save;
    memset (&chld_dfl, 0, sizeof chld_dfl);
    chld_dfl.sa_handler = SIG_DFL; sigemptyset (&chld_dfl.sa_mask);
    sigaction (SIGCHLD, &chld_dfl, &chld_save);

    pid_t pid = fork ();
    if (pid < 0) { builtin_error ("fork: %s", strerror (errno)); sigaction (SIGCHLD, &chld_save, NULL); free (argv); return EXECUTION_FAILURE; }
    if (pid == 0) {
        if (ioprio_set_p (0, eff_class, eff_level) < 0 && !ignore_fail)
            fprintf (stderr, "ionice: ioprio_set: %s\n", strerror (errno));
        execvp (argv[0], argv);
        fprintf (stderr, "ionice: %s: %s\n", argv[0], strerror (errno));
        _exit (errno == ENOENT ? 127 : 126);
    }
    free (argv);
    int wst = 0, status = EXECUTION_SUCCESS; pid_t w;
    while ((w = waitpid (pid, &wst, 0)) < 0 && errno == EINTR) ;
    sigaction (SIGCHLD, &chld_save, NULL);
    if (w < 0) { builtin_error ("waitpid: %s", strerror (errno)); return EXECUTION_FAILURE; }
    if (WIFEXITED (wst)) status = WEXITSTATUS (wst);
    else if (WIFSIGNALED (wst)) status = 128 + WTERMSIG (wst);
    return status;
}

char *ionice_doc[] = {
    "Get or set the I/O scheduling class and priority of a process.",
    "",
    "    ionice [-c CLASS] [-n LEVEL] -p PID...      set (or get) for PIDs",
    "    ionice [-c CLASS] [-n LEVEL] command [args] set for a new process",
    "    ionice -p PID                               print PID's class/priority",
    "",
    "    -c CLASS  none|0, realtime|rt|1, best-effort|be|2, idle|3",
    "    -n LEVEL  0 (highest) .. 7 (lowest); default 4",
    "    -p PID    operate on an existing process (repeatable)",
    "    -t        ignore set failures",
    (char *) NULL
};

struct builtin ionice_struct = {
    "ionice",
    ionice_builtin,
    BUILTIN_ENABLED,
    ionice_doc,
    "ionice [-c CLASS] [-n LEVEL] [-t] {-p PID... | command [args]}",
    0
};
