/* bashenv.c — POSIX env(1) as a bash builtin.
 *
 *   bashenv [--help|--version] [-i] [-v] [-C DIR] [-a ARG] [-u NAME]...
 *           [NAME=VALUE]... [CMD [ARGS...]]
 *
 * If no CMD: print the (possibly modified) environment, one per line.
 * If CMD: execvp it with the modified environment.
 *
 * Flags:
 *   -, -i        start with an empty environment (POSIX -i / clean-env)
 *   -u NAME      remove NAME from the environment
 *   -C DIR       change directory before executing command
 *   -a ARG       pass ARG as command argv[0]
 *   -v, --debug  print verbose processing diagnostics
 *   NAME=VALUE   set/replace NAME (any number; processed in order)
 *
 * Closes a POSIX gap (POSIX-CONFORMANCE-RESEARCH §4.1: bash's
 * VAR=val cmd syntax covers most cases but lacks env -i and the bare
 * `env` print form).
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
#include <strings.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

#include "loadables.h"
#include "command-run.h"
#include "trap.h"   /* signal_is_trapped / signal_is_hard_ignored */

/* GNU env (coreutils) exits 125 (EXIT_CANCELED) for EVERY usage/option error
   — invalid signal name, missing option argument, bad -S escape, unterminated
   -S quote, unknown option, etc. (verified against coreutils 9.7). bash's
   builtin EX_USAGE is 258, which a builtin call truncates to exit code 2, so
   using it here diverges from GNU env. Use 125 for all bashenv usage errors to
   match GNU env's exit taxonomy. (Genuine runtime failures — exec/fork/calloc
   — keep EXECUTION_FAILURE; only the argument-validation paths use this.) */
#ifndef BASHENV_USAGE_ERR
#  define BASHENV_USAGE_ERR 125
#endif

extern char **environ;
extern char *env_doc[];

typedef enum {
    BASHENV_SIG_DEFAULT,
    BASHENV_SIG_IGNORE,
    BASHENV_SIG_BLOCK
} bashenv_sig_action_t;

struct bashenv_sig_action {
    int signo;
    bashenv_sig_action_t action;
};

struct bashenv_sig_name {
    const char *name;
    int signo;
};

static const struct bashenv_sig_name bashenv_sig_names[] = {
#ifdef SIGHUP
    { "HUP", SIGHUP },
#endif
#ifdef SIGINT
    { "INT", SIGINT },
#endif
#ifdef SIGQUIT
    { "QUIT", SIGQUIT },
#endif
#ifdef SIGILL
    { "ILL", SIGILL },
#endif
#ifdef SIGABRT
    { "ABRT", SIGABRT },
#endif
#ifdef SIGFPE
    { "FPE", SIGFPE },
#endif
#ifdef SIGKILL
    { "KILL", SIGKILL },
#endif
#ifdef SIGSEGV
    { "SEGV", SIGSEGV },
#endif
#ifdef SIGPIPE
    { "PIPE", SIGPIPE },
#endif
#ifdef SIGALRM
    { "ALRM", SIGALRM },
#endif
#ifdef SIGTERM
    { "TERM", SIGTERM },
#endif
#ifdef SIGUSR1
    { "USR1", SIGUSR1 },
#endif
#ifdef SIGUSR2
    { "USR2", SIGUSR2 },
#endif
#ifdef SIGCHLD
    { "CHLD", SIGCHLD },
#endif
#ifdef SIGCONT
    { "CONT", SIGCONT },
#endif
#ifdef SIGSTOP
    { "STOP", SIGSTOP },
#endif
#ifdef SIGTSTP
    { "TSTP", SIGTSTP },
#endif
#ifdef SIGTTIN
    { "TTIN", SIGTTIN },
#endif
#ifdef SIGTTOU
    { "TTOU", SIGTTOU },
#endif
};

static int
bashenv_parse_signal (const char *s)
{
    if (!s || !*s)
        return -1;

    char *end = NULL;
    errno = 0;
    long n = strtol (s, &end, 10);
    if (end && *end == '\0' && errno == 0 && n > 0 && n < 128)
        return (int) n;

    if (!strncasecmp (s, "SIG", 3))
        s += 3;
    for (size_t i = 0; i < sizeof bashenv_sig_names / sizeof bashenv_sig_names[0]; i++)
        if (!strcasecmp (s, bashenv_sig_names[i].name))
            return bashenv_sig_names[i].signo;
    return -1;
}

static int
bashenv_record_signal_action (struct bashenv_sig_action *actions, int *n_actions,
                              bashenv_sig_action_t action, const char *operand)
{
    /* GNU env (coreutils 9.x) accepts comma-separated signal lists in
       --default-signal=, --ignore-signal=, --block-signal=. Empty
       entries (including the all-empty list `--ignore-signal=`) are a
       documented no-op. We stop at the first invalid token, matching
       coreutils' behavior. */
    if (!operand)
        operand = "";

    const char *p = operand;
    for (;;) {
        const char *comma = strchr (p, ',');
        size_t len = comma ? (size_t) (comma - p) : strlen (p);
        if (len > 0) {
            char buf[64];
            if (len >= sizeof buf) {
                builtin_error ("'%.*s': invalid signal", (int) len, p);
                return BASHENV_USAGE_ERR;
            }
            memcpy (buf, p, len);
            buf[len] = '\0';
            int signo = bashenv_parse_signal (buf);
            if (signo < 0) {
                builtin_error ("'%s': invalid signal", buf);
                return BASHENV_USAGE_ERR;
            }
            if (*n_actions >= 32) {
                builtin_error ("too many signal options");
                return BASHENV_USAGE_ERR;
            }
            actions[*n_actions].signo = signo;
            actions[*n_actions].action = action;
            (*n_actions)++;
        }
        if (!comma)
            break;
        p = comma + 1;
    }
    return EXECUTION_SUCCESS;
}

/* Reset the shell's job-control signal dispositions to SIG_DFL in the child,
   mirroring what bash does when it forks an *external* command (see
   execute_cmd.c: it only keeps SIG_IGN for SIGINT when the signal is trapped
   or hard-ignored). bashenv is a builtin, so its fork()ed child inherits the
   shell's own SIGINT/SIGQUIT-ignore (bash ignores SIGQUIT, and SIGINT in some
   contexts, for its own operation) — which a forked /usr/bin/env child does
   NOT carry. Without this, `bashenv cmd` would exec `cmd` with SIGQUIT/SIGINT
   ignored where GNU env execs it with the default disposition.
   We reset a signal to SIG_DFL only when it is neither user-trapped nor
   hard-ignored, so an explicit `trap '' INT/QUIT` in the caller still
   propagates to the child exactly as it does through GNU env. Runs BEFORE the
   user's --*-signal actions so those still win (last-wins). */
static void
bashenv_reset_inherited_job_signals (void)
{
    static const int job_sigs[] = { SIGINT, SIGQUIT };
    for (size_t i = 0; i < sizeof job_sigs / sizeof job_sigs[0]; i++) {
        int s = job_sigs[i];
        if (signal_is_trapped (s) || signal_is_hard_ignored (s))
            continue;
        struct sigaction sa;
        memset (&sa, 0, sizeof sa);
        sa.sa_handler = SIG_DFL;
        sigemptyset (&sa.sa_mask);
        sigaction (s, &sa, NULL);
    }
}

static void
bashenv_apply_child_signal_actions (const struct bashenv_sig_action *actions, int n_actions)
{
    /* GNU env (coreutils 9.x) applies these flags in command-line order with
       "last wins" per signal. The disposition/mask interaction, verified
       against coreutils 9.7:
         --block-signal=SIG   : block SIG in the mask (handler untouched).
         --default-signal=SIG : set handler to SIG_DFL *and* UNBLOCK SIG.
         --ignore-signal=SIG  : set handler to SIG_IGN; does NOT unblock.
       So `--block-signal=SIG --default-signal=SIG` ends unblocked (default
       wins both), but `--block-signal=SIG --ignore-signal=SIG` ends IGNORED
       yet still BLOCKED (the block persists — only --default-signal clears
       the mask). Mirror exactly: only DEFAULT touches the mask. */
    for (int i = 0; i < n_actions; i++) {
        sigset_t set;
        sigemptyset (&set);
        sigaddset (&set, actions[i].signo);
        if (actions[i].action == BASHENV_SIG_BLOCK) {
            sigprocmask (SIG_BLOCK, &set, NULL);
        } else {
            struct sigaction sa;
            memset (&sa, 0, sizeof sa);
            sa.sa_handler = actions[i].action == BASHENV_SIG_IGNORE ? SIG_IGN : SIG_DFL;
            sigemptyset (&sa.sa_mask);
            sigaction (actions[i].signo, &sa, NULL);
            if (actions[i].action == BASHENV_SIG_DEFAULT)
                sigprocmask (SIG_UNBLOCK, &set, NULL);
        }
    }
}

static int
bashenv_has_option_space (const char *s)
{
    for (; *s; s++)
        if (*s == ' ' || *s == '\t' || *s == '\n' ||
            *s == '\v' || *s == '\f' || *s == '\r')
            return 1;
    return 0;
}

static void
bashenv_free_split (char **argv, int argc)
{
    if (!argv)
        return;
    for (int i = 0; i < argc; i++)
        free (argv[i]);
    free (argv);
}

static int
bashenv_push_split_arg (char ***argv, int *argc, int *cap, const char *buf, size_t len)
{
    if (*argc >= *cap) {
        int ncap = *cap ? *cap * 2 : 4;
        char **nargv = realloc (*argv, (size_t) ncap * sizeof **argv);
        if (!nargv)
            return -1;
        *argv = nargv;
        *cap = ncap;
    }
    char *arg = malloc (len + 1);
    if (!arg)
        return -1;
    memcpy (arg, buf, len);
    arg[len] = '\0';
    (*argv)[(*argc)++] = arg;
    return 0;
}

static int
bashenv_split_string (const char *s, char ***argv_out, int *argc_out)
{
    char **argv = NULL;
    int argc = 0;
    int cap = 0;
    size_t blen = 0;
    size_t bcap = 64;
    char *buf = malloc (bcap);
    int in_arg = 0;
    int sq = 0;
    int dq = 0;

    if (!buf)
        return -1;

    for (const char *p = s; ; p++) {
        unsigned char c = (unsigned char) *p;
        int eos = (c == '\0');
        int space = (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v');

        if ((eos || (space && !sq && !dq))) {
            if (in_arg) {
                if (bashenv_push_split_arg (&argv, &argc, &cap, buf, blen) < 0)
                    goto nomem;
                blen = 0;
                in_arg = 0;
            }
            if (eos)
                break;
            continue;
        }

        if (c == '\'' && !dq) {
            sq = !sq;
            in_arg = 1;
            continue;
        }
        if (c == '"' && !sq) {
            dq = !dq;
            in_arg = 1;
            continue;
        }
        if (c == '#' && !sq && !dq && !in_arg)
            break;

        if (c == '$' && !sq) {
            const char *name = p + 1;
            if (*name != '{') {
                builtin_error ("only ${VARNAME} expansion is supported in -S string");
                free (buf);
                bashenv_free_split (argv, argc);
                return -2;
            }
            name++;
            if (!((*name >= 'A' && *name <= 'Z') ||
                  (*name >= 'a' && *name <= 'z') ||
                  *name == '_')) {
                builtin_error ("invalid ${VARNAME} expansion in -S string");
                free (buf);
                bashenv_free_split (argv, argc);
                return -2;
            }
            const char *end = name + 1;
            while ((*end >= 'A' && *end <= 'Z') ||
                   (*end >= 'a' && *end <= 'z') ||
                   (*end >= '0' && *end <= '9') ||
                   *end == '_')
                end++;
            if (*end != '}') {
                builtin_error ("invalid ${VARNAME} expansion in -S string");
                free (buf);
                bashenv_free_split (argv, argc);
                return -2;
            }
            size_t nlen = (size_t) (end - name);
            char *vname = malloc (nlen + 1);
            if (!vname)
                goto nomem;
            memcpy (vname, name, nlen);
            vname[nlen] = '\0';
            const char *val = getenv (vname);
            free (vname);
            if (val) {
                size_t vlen = strlen (val);
                if (blen + vlen >= bcap) {
                    while (blen + vlen >= bcap)
                        bcap *= 2;
                    char *nbuf = realloc (buf, bcap);
                    if (!nbuf)
                        goto nomem;
                    buf = nbuf;
                }
                memcpy (buf + blen, val, vlen);
                blen += vlen;
                in_arg = 1;
            }
            p = end;
            continue;
        }

        if (c == '\\' && !sq) {
            c = (unsigned char) *++p;
            if (c == '\0') {
                builtin_error ("invalid backslash at end of -S string");
                free (buf);
                bashenv_free_split (argv, argc);
                return -2;
            }
            switch (c) {
            case '"':
            case '#':
            case '$':
            case '\'':
            case '\\':
                break;
            case 'c':
                if (dq) {
                    builtin_error ("\\c must not appear in double-quoted -S string");
                    free (buf);
                    bashenv_free_split (argv, argc);
                    return -2;
                }
                p += strlen (p) - 1;
                continue;
            case '_':
                if (!dq) {
                    if (in_arg) {
                        if (bashenv_push_split_arg (&argv, &argc, &cap, buf, blen) < 0)
                            goto nomem;
                        blen = 0;
                        in_arg = 0;
                    }
                    continue;
                }
                c = ' ';
                break;
            case 'n': c = '\n'; break;
            case 't': c = '\t'; break;
            case 'r': c = '\r'; break;
            case 'f': c = '\f'; break;
            case 'v': c = '\v'; break;
            default:
                builtin_error ("invalid sequence '\\%c' in -S", c);
                free (buf);
                bashenv_free_split (argv, argc);
                return -2;
            }
        }

        if (blen + 1 >= bcap) {
            bcap *= 2;
            char *nbuf = realloc (buf, bcap);
            if (!nbuf)
                goto nomem;
            buf = nbuf;
        }
        buf[blen++] = (char) c;
        in_arg = 1;
    }

    if (sq || dq) {
        builtin_error ("no terminating quote in -S string");
        free (buf);
        bashenv_free_split (argv, argc);
        return -2;
    }

    free (buf);
    *argv_out = argv;
    *argc_out = argc;
    return 0;

nomem:
    free (buf);
    bashenv_free_split (argv, argc);
    return -1;
}

static void
bashenv_exec_shell_fallback (const char *program, char **argv, int argc, char **envp)
{
    char **sh_argv = calloc ((size_t) argc + 2, sizeof *sh_argv);
    if (!sh_argv)
        return;

    sh_argv[0] = "sh";
    sh_argv[1] = (char *) program;
    for (int i = 1; i < argc; i++)
        sh_argv[i + 1] = argv[i];
    sh_argv[argc + 1] = NULL;

    execve ("/bin/sh", sh_argv, envp);
    free (sh_argv);
}

int
env_builtin (WORD_LIST *list)
{
    int clean = 0;
    int null_delim = 0;
    int debug = 0;
    /* Up to 32 -u removals + 64 NAME=VALUE entries — generous defaults
       sized for typical POSIX scripting. */
    const char *unsetv[32];
    int n_unset = 0;
    const char *setv[128];
    int n_set = 0;
    const char *newdir = NULL;
    const char *argv0_override = NULL;
    char **split_argv = NULL;
    int split_argc = 0;
    int options_done = 0;
    int operands_started = 0;
    struct bashenv_sig_action sig_actions[32];
    int n_sig_actions = 0;

    while (list) {
        const char *w = list->word->word;
        if (!options_done && !operands_started && !strcmp (w, "--help")) {
            for (char **lp = env_doc; *lp; lp++)
                puts (*lp);
            return EXECUTION_SUCCESS;
        }
        if (!options_done && !operands_started && !strcmp (w, "--version")) {
            puts ("bashenv 1.0 (bash-loadable, coreutils-compatible)");
            return EXECUTION_SUCCESS;
        }
        if (!options_done && !operands_started && !strcmp (w, "--")) {
            options_done = 1;
            list = list->next;
            continue;
        }
        if (!options_done && !operands_started && (!strcmp (w, "-") || !strcmp (w, "-i") || !strcmp (w, "--ignore-environment"))) {
            clean = 1;
            list = list->next;
            continue;
        }
        if (!options_done && !operands_started && (!strcmp (w, "-v") || !strcmp (w, "--debug"))) {
            debug = 1;
            list = list->next;
            continue;
        }
        if (!options_done && !operands_started && !strncmp (w, "--default-signal=", 17)) {
            int r = bashenv_record_signal_action (sig_actions, &n_sig_actions, BASHENV_SIG_DEFAULT, w + 17);
            if (r != EXECUTION_SUCCESS) return r;
            list = list->next;
            continue;
        }
        if (!options_done && !operands_started && !strncmp (w, "--ignore-signal=", 16)) {
            int r = bashenv_record_signal_action (sig_actions, &n_sig_actions, BASHENV_SIG_IGNORE, w + 16);
            if (r != EXECUTION_SUCCESS) return r;
            list = list->next;
            continue;
        }
        if (!options_done && !operands_started && !strncmp (w, "--block-signal=", 15)) {
            int r = bashenv_record_signal_action (sig_actions, &n_sig_actions, BASHENV_SIG_BLOCK, w + 15);
            if (r != EXECUTION_SUCCESS) return r;
            list = list->next;
            continue;
        }
        if (!options_done && !operands_started && (!strcmp (w, "-u") || !strcmp (w, "--unset"))) {
            if (!list->next) { builtin_error ("-u needs NAME"); return BASHENV_USAGE_ERR; }
            list = list->next;
            if (n_unset >= (int) (sizeof unsetv / sizeof unsetv[0])) {
                builtin_error ("too many -u entries");
                return BASHENV_USAGE_ERR;
            }
            unsetv[n_unset++] = list->word->word;
            list = list->next;
            continue;
        }
        if (!options_done && !operands_started && !strncmp (w, "--unset=", 8)) {
            if (n_unset >= (int) (sizeof unsetv / sizeof unsetv[0])) {
                builtin_error ("too many -u entries");
                return BASHENV_USAGE_ERR;
            }
            unsetv[n_unset++] = w + 8;
            list = list->next;
            continue;
        }
        if (!options_done && !operands_started && (!strcmp (w, "-C") || !strcmp (w, "--chdir"))) {
            if (!list->next) { builtin_error ("-C needs DIR"); return BASHENV_USAGE_ERR; }
            list = list->next;
            newdir = list->word->word;
            list = list->next;
            continue;
        }
        if (!options_done && !operands_started && !strncmp (w, "--chdir=", 8)) {
            newdir = w + 8;
            list = list->next;
            continue;
        }
        if (!options_done && !operands_started && (!strcmp (w, "-a") || !strcmp (w, "--argv0"))) {
            if (!list->next) { builtin_error ("-a needs ARG"); return BASHENV_USAGE_ERR; }
            list = list->next;
            argv0_override = list->word->word;
            list = list->next;
            continue;
        }
        if (!options_done && !operands_started && !strncmp (w, "--argv0=", 8)) {
            argv0_override = w + 8;
            list = list->next;
            continue;
        }
        if (!options_done && !operands_started && (!strcmp (w, "-S") || !strcmp (w, "--split-string"))) {
            if (!list->next) { builtin_error ("-S needs STRING"); return BASHENV_USAGE_ERR; }
            list = list->next;
            int sr = bashenv_split_string (list->word->word, &split_argv, &split_argc);
            if (sr < 0) {
                if (sr == -1)
                    builtin_error ("malloc: %s", strerror (errno));
                return sr == -2 ? BASHENV_USAGE_ERR : EXECUTION_FAILURE;
            }
            list = list->next;
            break;
        }
        /* Attached form `-S<string>` — how a `#!/usr/bin/env -S ...` shebang
           delivers the option (the kernel passes "-S ..." as one argv token;
           the split routine skips the leading blank). */
        if (!options_done && !operands_started && !strncmp (w, "-S", 2) && w[2]) {
            int sr = bashenv_split_string (w + 2, &split_argv, &split_argc);
            if (sr < 0) {
                if (sr == -1)
                    builtin_error ("malloc: %s", strerror (errno));
                return sr == -2 ? BASHENV_USAGE_ERR : EXECUTION_FAILURE;
            }
            list = list->next;
            break;
        }
        if (!options_done && !operands_started && !strncmp (w, "--split-string=", 15)) {
            int sr = bashenv_split_string (w + 15, &split_argv, &split_argc);
            if (sr < 0) {
                if (sr == -1)
                    builtin_error ("malloc: %s", strerror (errno));
                return sr == -2 ? BASHENV_USAGE_ERR : EXECUTION_FAILURE;
            }
            list = list->next;
            break;
        }
        if (!options_done && !operands_started && (!strcmp (w, "-0") || !strcmp (w, "--null"))) {
            null_delim = 1;
            list = list->next;
            continue;
        }
        if (!options_done && !operands_started && w[0] == '-' && w[1] != '\0' && w[1] != '=') {
            if (bashenv_has_option_space (w)) {
                builtin_error ("invalid option -- '%c'", ' ');
                builtin_error ("use -[v]S to pass options in shebang lines");
                return BASHENV_USAGE_ERR;
            }
            /* Unknown flag — could be CMD starting with -; POSIX uses
               first non-flag, non-NAME=VAL token as CMD, so leave it
               alone. */
            break;
        }
        /* NAME=VALUE? */
        const char *eq = strchr (w, '=');
        if (eq && eq != w) {
            if (n_set >= (int) (sizeof setv / sizeof setv[0])) {
                builtin_error ("too many NAME=VALUE entries");
                return BASHENV_USAGE_ERR;
            }
            setv[n_set++] = w;
            operands_started = 1;
            list = list->next;
            continue;
        }
        /* Otherwise: this is CMD. */
        break;
    }

    int split_cmd_start = 0;
    options_done = 0;
    operands_started = 0;
    if (split_argc > 0) {
        while (split_cmd_start < split_argc) {
            const char *w = split_argv[split_cmd_start];
            if (!options_done && !operands_started && !strcmp (w, "--")) {
                options_done = 1;
                split_cmd_start++;
                continue;
            }
            if (!options_done && !operands_started && (!strcmp (w, "-") || !strcmp (w, "-i") || !strcmp (w, "--ignore-environment"))) {
                clean = 1;
                split_cmd_start++;
                continue;
            }
            if (!options_done && !operands_started && (!strcmp (w, "-v") || !strcmp (w, "--debug"))) {
                debug = 1;
                split_cmd_start++;
                continue;
            }
            if (!options_done && !operands_started && !strncmp (w, "--default-signal=", 17)) {
                int r = bashenv_record_signal_action (sig_actions, &n_sig_actions, BASHENV_SIG_DEFAULT, w + 17);
                if (r != EXECUTION_SUCCESS) {
                    bashenv_free_split (split_argv, split_argc);
                    return r;
                }
                split_cmd_start++;
                continue;
            }
            if (!options_done && !operands_started && !strncmp (w, "--ignore-signal=", 16)) {
                int r = bashenv_record_signal_action (sig_actions, &n_sig_actions, BASHENV_SIG_IGNORE, w + 16);
                if (r != EXECUTION_SUCCESS) {
                    bashenv_free_split (split_argv, split_argc);
                    return r;
                }
                split_cmd_start++;
                continue;
            }
            if (!options_done && !operands_started && !strncmp (w, "--block-signal=", 15)) {
                int r = bashenv_record_signal_action (sig_actions, &n_sig_actions, BASHENV_SIG_BLOCK, w + 15);
                if (r != EXECUTION_SUCCESS) {
                    bashenv_free_split (split_argv, split_argc);
                    return r;
                }
                split_cmd_start++;
                continue;
            }
            if (!options_done && !operands_started && (!strcmp (w, "-u") || !strcmp (w, "--unset"))) {
                if (split_cmd_start + 1 >= split_argc) {
                    builtin_error ("-u needs NAME");
                    bashenv_free_split (split_argv, split_argc);
                    return BASHENV_USAGE_ERR;
                }
                if (n_unset >= (int) (sizeof unsetv / sizeof unsetv[0])) {
                    builtin_error ("too many -u entries");
                    bashenv_free_split (split_argv, split_argc);
                    return BASHENV_USAGE_ERR;
                }
                unsetv[n_unset++] = split_argv[++split_cmd_start];
                split_cmd_start++;
                continue;
            }
            if (!options_done && !operands_started && !strncmp (w, "--unset=", 8)) {
                if (n_unset >= (int) (sizeof unsetv / sizeof unsetv[0])) {
                    builtin_error ("too many -u entries");
                    bashenv_free_split (split_argv, split_argc);
                    return BASHENV_USAGE_ERR;
                }
                unsetv[n_unset++] = w + 8;
                split_cmd_start++;
                continue;
            }
            if (!options_done && !operands_started && (!strcmp (w, "-C") || !strcmp (w, "--chdir"))) {
                if (split_cmd_start + 1 >= split_argc) {
                    builtin_error ("-C needs DIR");
                    bashenv_free_split (split_argv, split_argc);
                    return BASHENV_USAGE_ERR;
                }
                newdir = split_argv[++split_cmd_start];
                split_cmd_start++;
                continue;
            }
            if (!options_done && !operands_started && !strncmp (w, "--chdir=", 8)) {
                newdir = w + 8;
                split_cmd_start++;
                continue;
            }
            if (!options_done && !operands_started && (!strcmp (w, "-a") || !strcmp (w, "--argv0"))) {
                if (split_cmd_start + 1 >= split_argc) {
                    builtin_error ("-a needs ARG");
                    bashenv_free_split (split_argv, split_argc);
                    return BASHENV_USAGE_ERR;
                }
                argv0_override = split_argv[++split_cmd_start];
                split_cmd_start++;
                continue;
            }
            if (!options_done && !operands_started && !strncmp (w, "--argv0=", 8)) {
                argv0_override = w + 8;
                split_cmd_start++;
                continue;
            }
            if (!options_done && !operands_started && (!strcmp (w, "-0") || !strcmp (w, "--null"))) {
                null_delim = 1;
                split_cmd_start++;
                continue;
            }
            const char *eq = strchr (w, '=');
            if (eq && eq != w) {
                if (n_set >= (int) (sizeof setv / sizeof setv[0])) {
                    builtin_error ("too many NAME=VALUE entries");
                    bashenv_free_split (split_argv, split_argc);
                    return BASHENV_USAGE_ERR;
                }
                setv[n_set++] = w;
                operands_started = 1;
                split_cmd_start++;
                continue;
            }
            break;
        }
    }

    /* Sync bash's export table into the C `environ` array before reading it.
       bash keeps exported shell variables in its own internal table and only
       materializes them into `environ` lazily (at execve time, via
       maybe_make_export_env). Without this call a variable exported in the
       current shell (`export FOO=bar; bashenv`) is invisible to our environ
       walk, even though a forked /usr/bin/env would see it — the same fix
       printenv.c uses. Harmless when there is nothing new to export. */
    maybe_make_export_env ();

    /* Build the new envp. */
    int oldn = 0;
    if (!clean && environ) {
        while (environ[oldn]) oldn++;
    }
    char **envp = calloc ((size_t) (oldn + n_set + 1), sizeof *envp);
    if (!envp) { builtin_error ("calloc: %s", strerror (errno)); return EXECUTION_FAILURE; }
    int en = 0;
    if (clean && debug)
        fprintf (stderr, "cleaning environ\n");
    if (!clean) {
        if (debug) {
            for (int j = 0; j < n_unset; j++)
                fprintf (stderr, "unset:    %s\n", unsetv[j]);
        }
        for (int i = 0; i < oldn; i++) {
            const char *e = environ[i];
            const char *eq = strchr (e, '=');
            if (!eq) continue;
            size_t nlen = (size_t) (eq - e);
            int skip = 0;
            for (int j = 0; j < n_unset; j++) {
                if (strlen (unsetv[j]) == nlen && !memcmp (unsetv[j], e, nlen)) {
                    skip = 1; break;
                }
            }
            if (skip) continue;
            for (int j = 0; j < n_set; j++) {
                const char *seq = strchr (setv[j], '=');
                if (seq && (size_t) (seq - setv[j]) == nlen && !memcmp (setv[j], e, nlen)) {
                    skip = 1; break;
                }
            }
            if (skip) continue;
            envp[en++] = (char *) e;
        }
    }
    for (int j = 0; j < n_set; j++) {
        if (debug)
            fprintf (stderr, "setenv:   %s\n", setv[j]);
        envp[en++] = (char *) setv[j];
    }
    envp[en] = NULL;

    if (!list && split_argc == split_cmd_start) {
        if (newdir) {
            free (envp);
            bashenv_free_split (split_argv, split_argc);
            builtin_error ("must specify command with --chdir (-C)");
            return BASHENV_USAGE_ERR;
        }
        if (argv0_override) {
            free (envp);
            bashenv_free_split (split_argv, split_argc);
            builtin_error ("must specify command with --argv0 (-a)");
            return BASHENV_USAGE_ERR;
        }
        /* No CMD: print env, one per line (or NUL-delimited with -0). */
        for (int i = 0; i < en; i++) {
            if (null_delim) {
                size_t len = strlen (envp[i]);
                fwrite (envp[i], 1, len, stdout);
                fputc (0, stdout);
            } else {
                puts (envp[i]);
            }
        }
        free (envp);
        bashenv_free_split (split_argv, split_argc);
        return EXECUTION_SUCCESS;
    }

    /* Build argv for execvp. */
    int argc = 0;
    for (WORD_LIST *p = list; p; p = p->next) argc++;
    argc += split_argc - split_cmd_start;
    char **argv = calloc ((size_t) argc + 1, sizeof *argv);
    if (!argv) {
        builtin_error ("calloc: %s", strerror (errno));
        free (envp);
        bashenv_free_split (split_argv, split_argc);
        return EXECUTION_FAILURE;
    }
    int i = 0;
    for (int s = split_cmd_start; s < split_argc; s++)
        argv[i++] = split_argv[s];
    for (WORD_LIST *p = list; p; p = p->next) argv[i++] = p->word->word;
    argv[argc] = NULL;

    if (argc == 0) {
        free (envp);
        free (argv);
        bashenv_free_split (split_argv, split_argc);
        if (newdir)
            builtin_error ("must specify command with --chdir (-C)");
        else if (argv0_override)
            builtin_error ("must specify command with --argv0 (-a)");
        else
            builtin_error ("-S produced no command");
        return BASHENV_USAGE_ERR;
    }
    if (null_delim) {
        free (envp);
        free (argv);
        bashenv_free_split (split_argv, split_argc);
        builtin_error ("cannot specify --null (-0) with command");
        return BASHENV_USAGE_ERR;
    }

    const char *program = argv[0];
    if (argv0_override)
        argv[0] = (char *) argv0_override;

    struct sigaction chld_dfl, chld_save;
    memset (&chld_dfl, 0, sizeof chld_dfl);
    chld_dfl.sa_handler = SIG_DFL;
    sigemptyset (&chld_dfl.sa_mask);
    sigaction (SIGCHLD, &chld_dfl, &chld_save);

    sigset_t chld_set, prev_mask;
    sigemptyset (&chld_set);
    sigaddset (&chld_set, SIGCHLD);
    sigprocmask (SIG_BLOCK, &chld_set, &prev_mask);

    /* Fork+exec so we don't replace the calling shell. */
    fflush (stdout);
    fflush (stderr);
    pid_t pid = fork ();
    if (pid < 0) {
        int e = errno;
        sigprocmask (SIG_SETMASK, &prev_mask, NULL);
        sigaction (SIGCHLD, &chld_save, NULL);
        builtin_error ("fork: %s", strerror (e));
        free (envp);
        free (argv);
        bashenv_free_split (split_argv, split_argc);
        return EXECUTION_FAILURE;
    }
    if (pid == 0) {
        bos_prepare_child ();
        sigprocmask (SIG_SETMASK, &prev_mask, NULL);
        bashenv_reset_inherited_job_signals ();
        bashenv_apply_child_signal_actions (sig_actions, n_sig_actions);
        if (newdir) {
            if (debug)
                fprintf (stderr, "chdir:    %s\n", newdir);
            if (chdir (newdir) < 0) {
                fprintf (stderr, "env: cannot change directory to %s: %s\n", newdir, strerror (errno));
                _exit (125);
            }
        }
        if (debug) {
            if (argv0_override)
                fprintf (stderr, "argv0:     %s\n", argv0_override);
            fprintf (stderr, "executing: %s\n", program);
            /* GNU env --debug wraps each arg in U+2018/U+2019 quotation marks
               (e.g. `   arg[0]= ‘prog’`); the surrounding lines (cleaning
               environ / setenv: / executing:) are unquoted. Match the quoting
               byte-for-byte (\xe2\x80\x98 ... \xe2\x80\x99). */
            for (int k = 0; k < argc; k++)
                fprintf (stderr, "   arg[%d]= \xe2\x80\x98%s\xe2\x80\x99\n",
                         k, argv[k]);
        }
        bos_run_builtin (program, argv, envp);
        execvpe (program, argv, envp);
        int err = errno;
        if (err == ENOEXEC) {
            bashenv_exec_shell_fallback (program, argv, argc, envp);
            err = errno;
        }
        fprintf (stderr, "env: %s: %s\n", program, strerror (err));
        _exit (err == ENOENT ? 127 : 126);
    }
    free (envp); free (argv);
    bashenv_free_split (split_argv, split_argc);
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

char *env_doc[] = {
    "Print or modify the environment, optionally exec a command.",
    "",
    "    bashenv [--help|--version] [-i] [-C DIR] [-a ARG] [-S STRING] [-u NAME]... [NAME=VALUE]... [CMD [ARGS...]]",
    "",
    "    --help    show this help",
    "    --version show version",
    "    -, -i, --ignore-environment  start with an empty environment",
    "    -C, --chdir DIR  change directory before executing command",
    "    -a, --argv0 ARG  pass ARG as command argv[0]",
    "    -u, --unset NAME  remove NAME from the environment (repeatable)",
    "    -v, --debug  print verbose processing diagnostics",
    "    -0, --null  end each output line with NUL (script-friendly)",
    "    -S, --split-string STRING  split STRING into options/command argv",
    "    --default-signal=SIG  reset SIG to its default disposition for CMD",
    "    --ignore-signal=SIG  ignore SIG for CMD",
    "    --block-signal=SIG  block SIG for CMD",
    "    NAME=VAL  set/replace NAME (any number, processed in order)",
    "",
    "Without CMD, prints the resulting environment one entry per line.",
    "With CMD, run an enabled builtin or external command in a child process.",
    "",
    "Bash's `VAR=val cmd` syntax handles the common case; bashenv adds",
    "-i (clean exec) and the print-env form.",
    (char *)NULL
};

struct builtin bashenv_struct = {
    "bashenv",
    env_builtin,
    BUILTIN_ENABLED,
    env_doc,
    "bashenv [--help|--version] [-i] [-v] [-0] [-C DIR] [-a ARG] [-S STRING] [--default-signal=SIG] [--ignore-signal=SIG] [--block-signal=SIG] [-u NAME]... [NAME=VALUE]... [CMD [ARGS...]]",
    0
};
