/* bashxargs.c — POSIX xargs(1) as a bash builtin.
 *
 * Phase A.4 of bash-os shell-ergonomics. Reads arguments from stdin
 * and runs CMD with them in batches.
 *
 *   bashxargs [-0] [-r] [-t] [-p] [-n MAX] [-L MAX] [-P MAX]
 *             [-s SIZE] [-I REPL] CMD [ARG...]
 *
 *   -0       NUL-separated input (pairs with `bashfind ... -print0`)
 *   -r       no-run-if-empty
 *   -t       echo command before each invocation
 *   -p       prompt before each invocation (implies -t)
 *   -n MAX   max-args-per-invocation (default: as many as fit)
 *   -L MAX   max input lines/items per invocation
 *   -P MAX   run up to MAX invocations in parallel
 *   -s SIZE  max command-line bytes per invocation, counting the
 *            template words (CMD + its initial args), each input arg,
 *            and one terminating-NUL byte per word (POSIX/GNU xargs).
 *            Overrides the internal min(ARG_MAX/2, 65536) heuristic.
 *   -I REPL  substitute REPL with each input arg, run CMD once per
 *            input (implies -n 1)
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
#include <ctype.h>
#include <limits.h>

#include "loadables.h"
#include "command-run.h"

/* GNU/BSD xargs exit status folding. POSIX leaves "some other error" to the
   implementation; we mirror GNU so `lc_tap_compare` against /usr/bin/xargs
   has a chance of agreement and so callers can distinguish kinds of failure.

       0       all invocations succeeded
       123     any invocation exited 1..125
       124     a child exited with status 255 (fatal: stop reading input)
       125     a child was terminated by a signal (fatal)
       126     the command was found but could not be executed
       127     the command was not found
       1       bashxargs itself hit a fatal error (parse, I/O, fork) */
#define BX_OK         0
#define BX_ANY_FAIL   123
#define BX_FATAL_255  124
#define BX_SIGNALED   125
#define BX_NOEXEC     126
#define BX_NOTFOUND   127
#define BX_BAD        1

/* Promote `cur` to `add` if `add` is "worse." The ordering reflects
   POSIX-ish severity (not numeric): notfound/noexec/signaled/fatal_255
   are sticky, then any_fail, then ok. */
static int
bx_fold (int cur, int add)
{
    if (cur == 0) return add;
    if (add == 0) return cur;
    /* Higher severity always wins; both nonzero collapse on max. */
    if (add == BX_NOTFOUND || cur == BX_NOTFOUND) return BX_NOTFOUND;
    if (add == BX_NOEXEC   || cur == BX_NOEXEC)   return BX_NOEXEC;
    if (add == BX_SIGNALED || cur == BX_SIGNALED) return BX_SIGNALED;
    if (add == BX_FATAL_255 || cur == BX_FATAL_255) return BX_FATAL_255;
    return BX_ANY_FAIL;
}

static int
bx_is_fatal (int rc)
{
    return rc == BX_FATAL_255 || rc == BX_SIGNALED
        || rc == BX_NOEXEC    || rc == BX_NOTFOUND;
}

static int
bx_parse_positive_int (const char *s, int *out)
{
    char *end = NULL;
    long n;

    errno = 0;
    n = strtol (s, &end, 10);
    if (errno || end == s || *end || n <= 0 || n > INT_MAX)
        return -1;
    *out = (int) n;
    return 0;
}

static int
bx_parse_positive_long (const char *s, long *out)
{
    char *end = NULL;
    long n;

    errno = 0;
    n = strtol (s, &end, 10);
    if (errno || end == s || *end || n <= 0)
        return -1;
    *out = n;
    return 0;
}

static int
bx_prompt_yes (char **argv, int n)
{
    FILE *tty = fopen ("/dev/tty", "r");
    FILE *in = tty ? tty : stdin;
    for (int i = 0; i < n; i++) fprintf (stderr, "%s%s", i ? " " : "", argv[i]);
    fputs (" ?...", stderr);
    fflush (stderr);

    char ans[16];
    int yes = 0;
    if (fgets (ans, sizeof ans, in))
        yes = (ans[0] == 'y' || ans[0] == 'Y');
    if (tty) fclose (tty);
    return yes;
}

/* Read one input arg.  In normal POSIX xargs mode, unquoted blanks split
   arguments and quotes/backslashes group or escape bytes.  In line_mode
   (-I), consume one full line/item as the replacement argument. */
static char *
bx_read_arg (FILE *in, int nul_sep, int line_mode, int *errp)
{
    int term = nul_sep ? '\0' : '\n';
    size_t cap = 64, len = 0;
    char *buf = malloc (cap);
    if (!buf) return NULL;
    int c;

    if (!line_mode && !nul_sep) {
        while ((c = fgetc (in)) != EOF && isspace ((unsigned char)c))
            ;
        if (c == EOF) { free (buf); return NULL; }
    } else {
        c = fgetc (in);
        if (c == EOF) { free (buf); return NULL; }
    }

    int quote = 0;
    for (;;) {
        if (c == EOF) break;
        if (nul_sep) {
            if (c == '\0') break;
        } else if (line_mode) {
            if (c == term) break;
        } else {
            if (!quote && isspace ((unsigned char)c)) break;
            if (c == '\'' || c == '"') {
                if (!quote) { quote = c; c = fgetc (in); continue; }
                if (quote == c) { quote = 0; c = fgetc (in); continue; }
            } else if (c == '\\') {
                c = fgetc (in);
                if (c == EOF) {
                    if (errp) *errp = 1;
                    builtin_error ("unterminated escape in input");
                    free (buf);
                    return NULL;
                }
            }
        }
        if (len + 1 >= cap) {
            cap *= 2;
            char *nb = realloc (buf, cap);
            if (!nb) { free (buf); return NULL; }
            buf = nb;
        }
        buf[len++] = (char) c;
        c = fgetc (in);
    }

    if (quote && !line_mode && !nul_sep) {
        if (errp) *errp = 1;
        builtin_error ("unmatched %c quote in input", quote);
        free (buf);
        return NULL;
    }

    if (c == EOF && len == 0) { free (buf); return NULL; }
    buf[len] = '\0';
    /* For -I line mode, also accept blank lines as separators (skip empties). */
    if (line_mode && !nul_sep && len == 0) return bx_read_arg (in, nul_sep, line_mode, errp);
    return buf;
}

/* Run argv[0..n-1]. Returns one of BX_OK / BX_ANY_FAIL / BX_FATAL_255 /
   BX_SIGNALED / BX_NOEXEC / BX_NOTFOUND / BX_BAD. The child encodes its
   own failure to exec: exit 126 = found-but-cannot-exec, exit 127 =
   not-found. Anything else maps directly to its WEXITSTATUS.

   Bash installs its own SIGCHLD handler (waitchld) which calls
   WAITPID(-1, ...) and reaps ANY unwaited child — including ones a
   loadable fork()s directly. If we don't block SIGCHLD around our
   fork+waitpid pair, bash's reaper can race us, snatch the status, and
   our own waitpid returns -1/ECHILD with `status` left uninitialised;
   reading WEXITSTATUS(garbage) then folds to BX_ANY_FAIL (=123) and the
   true exit code (126 / 127 / 255 / signal) is lost. Block SIGCHLD
   across the fork+wait pair to keep the status ours, then restore the
   original mask so any pending SIGCHLD bash queued runs after we
   return. The child unblocks immediately so its own SIGCHLD delivery
   (if any) is unaffected. */
static int
bx_run (char **argv, int n, int tflag)
{
    if (tflag) {
        for (int i = 0; i < n; i++) fprintf (stderr, "%s%s", i ? " " : "", argv[i]);
        fputc ('\n', stderr);
    }
    sigset_t block_chld, prev_mask;
    sigemptyset (&block_chld);
    sigaddset (&block_chld, SIGCHLD);
    sigprocmask (SIG_BLOCK, &block_chld, &prev_mask);

    maybe_make_export_env ();
    fflush (stdout);
    fflush (stderr);
    pid_t pid = fork ();
    if (pid == 0) {
        bos_prepare_child ();
        /* Restore the inherited mask in the child so its own children
           (if it spawns any) trigger the normal SIGCHLD path. */
        sigprocmask (SIG_SETMASK, &prev_mask, NULL);
        bos_run_builtin (argv[0], argv, NULL);
        execvp (argv[0], argv);
        /* execvp failed. Distinguish "not found" from "cannot execute" so
           the parent can fold accurately. POSIX: ENOENT/ENOTDIR → 127,
           anything else (EACCES, ENOEXEC, E2BIG, ETXTBSY…) → 126. */
        int code = (errno == ENOENT || errno == ENOTDIR) ? 127 : 126;
        /* Single diagnostic on the child's stderr; the parent already
           describes the exit code to the caller. */
        fprintf (stderr, "bashxargs: %s: %s\n", argv[0], strerror (errno));
        _exit (code);
    } else if (pid > 0) {
        int status = 0;
        int wr;
        while ((wr = waitpid (pid, &status, 0)) < 0 && errno == EINTR) { }
        /* Restore the previous mask so bash's own SIGCHLD handler runs
           for any other children it spawned before/after our fork. */
        sigprocmask (SIG_SETMASK, &prev_mask, NULL);
        if (wr < 0) {
            /* Either ECHILD (someone else reaped — defensive: shouldn't
               happen with SIGCHLD blocked) or a real error. Report it
               and fold to BX_BAD so the caller surfaces a fault rather
               than reading garbage out of `status`. */
            builtin_error ("waitpid(%ld): %s", (long) pid, strerror (errno));
            return BX_BAD;
        }
        if (WIFSIGNALED (status)) {
            int sig = WTERMSIG (status);
            fprintf (stderr, "bashxargs: %s: terminated by signal %d\n",
                     argv[0], sig);
            return BX_SIGNALED;
        }
        if (WIFEXITED (status)) {
            int s = WEXITSTATUS (status);
            if (s == 0)   return BX_OK;
            if (s == 127) return BX_NOTFOUND;
            if (s == 126) return BX_NOEXEC;
            if (s == 255) return BX_FATAL_255;
            return BX_ANY_FAIL;
        }
        return BX_ANY_FAIL;
    }
    sigprocmask (SIG_SETMASK, &prev_mask, NULL);
    builtin_error ("fork: %s", strerror (errno));
    return BX_BAD;
}

static pid_t
bx_spawn (char **argv, int n, int tflag)
{
    if (tflag) {
        for (int i = 0; i < n; i++) fprintf (stderr, "%s%s", i ? " " : "", argv[i]);
        fputc ('\n', stderr);
    }

    maybe_make_export_env ();
    fflush (stdout);
    fflush (stderr);
    pid_t pid = fork ();
    if (pid == 0) {
        bos_prepare_child ();
        sigset_t empty;
        sigemptyset (&empty);
        sigprocmask (SIG_SETMASK, &empty, NULL);
        bos_run_builtin (argv[0], argv, NULL);
        execvp (argv[0], argv);
        int code = (errno == ENOENT || errno == ENOTDIR) ? 127 : 126;
        fprintf (stderr, "bashxargs: %s: %s\n", argv[0], strerror (errno));
        _exit (code);
    }
    if (pid < 0)
        builtin_error ("fork: %s", strerror (errno));
    (void)n;
    return pid;
}

static int
bx_status_to_rc (const char *cmd, int status)
{
    if (WIFSIGNALED (status)) {
        int sig = WTERMSIG (status);
        fprintf (stderr, "bashxargs: %s: terminated by signal %d\n", cmd, sig);
        return BX_SIGNALED;
    }
    if (WIFEXITED (status)) {
        int s = WEXITSTATUS (status);
        if (s == 0)   return BX_OK;
        if (s == 127) return BX_NOTFOUND;
        if (s == 126) return BX_NOEXEC;
        if (s == 255) return BX_FATAL_255;
        return BX_ANY_FAIL;
    }
    return BX_ANY_FAIL;
}

static int
bx_wait_one (pid_t *pids, char **cmds, int *n_pids, int *fatal)
{
    while (*n_pids > 0) {
        int status = 0;
        pid_t pid = waitpid (-1, &status, 0);
        if (pid < 0) {
            if (errno == EINTR) continue;
            builtin_error ("waitpid: %s", strerror (errno));
            return BX_BAD;
        }
        for (int i = 0; i < *n_pids; i++) {
            if (pids[i] != pid) continue;
            int rc = bx_status_to_rc (cmds[i], status);
            free (cmds[i]);
            pids[i] = pids[*n_pids - 1];
            cmds[i] = cmds[*n_pids - 1];
            (*n_pids)--;
            if (bx_is_fatal (rc)) *fatal = 1;
            return rc;
        }
    }
    return BX_OK;
}

int
xargs_builtin (WORD_LIST *list)
{
    int nul_sep = 0, rflag = 0, tflag = 0, pflag = 0;
    int max_n = 0, max_l = 0, max_p = 1;
    /* Reading stdin in the shell process leaves the EOF flag set for the next
       invocation, which would then build no command lines and exit 0. */
    clearerr (stdin);
    long s_flag = 0;          /* -s SIZE: 0 = unset (use default cap). */
    char *Iflag = NULL;

    /* Parse flags. */
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version")) {
            puts ("bashxargs 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-0")) { nul_sep = 1; list = list->next; continue; }
        if (!strcmp (w, "-r")) { rflag = 1; list = list->next; continue; }
        if (!strcmp (w, "-t")) { tflag = 1; list = list->next; continue; }
        if (!strcmp (w, "-p")) { pflag = 1; tflag = 1; list = list->next; continue; }
        if (w[1] == 'n' && w[2]) {
            if (bx_parse_positive_int (w + 2, &max_n) != 0) {
                builtin_error ("-n needs a positive count");
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-n")) {
            if (!list->next) { builtin_error ("-n needs MAX"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            if (bx_parse_positive_int (list->word->word, &max_n) != 0) {
                builtin_error ("-n needs a positive count");
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (w[1] == 'L' && w[2]) {
            if (bx_parse_positive_int (w + 2, &max_l) != 0) {
                builtin_error ("-L needs a positive count");
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-L")) {
            if (!list->next) { builtin_error ("-L needs MAX"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            if (bx_parse_positive_int (list->word->word, &max_l) != 0) {
                builtin_error ("-L needs a positive count");
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (w[1] == 'P' && w[2]) {
            if (bx_parse_positive_int (w + 2, &max_p) != 0) {
                builtin_error ("-P needs a positive count");
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-P")) {
            if (!list->next) { builtin_error ("-P needs MAX"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            if (bx_parse_positive_int (list->word->word, &max_p) != 0) {
                builtin_error ("-P needs a positive count");
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (w[1] == 's' && w[2]) {
            if (bx_parse_positive_long (w + 2, &s_flag) != 0) {
                builtin_error ("-s needs a positive byte count");
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-s")) {
            if (!list->next) { builtin_error ("-s needs SIZE"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            if (bx_parse_positive_long (list->word->word, &s_flag) != 0) {
                builtin_error ("-s needs a positive byte count");
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (w[1] == 'I' && w[2]) {
            Iflag = (char *) (w + 2);
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-I")) {
            if (!list->next) { builtin_error ("-I needs REPL"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            Iflag = list->word->word;
            list = list->next;
            continue;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    /* Build template argv. Default if no CMD: /bin/echo. */
    int tmpl_n = 0;
    for (WORD_LIST *p = list; p; p = p->next) tmpl_n++;
    char **tmpl;
    int default_echo = 0;
    if (tmpl_n == 0) {
        tmpl = malloc (2 * sizeof *tmpl);
        if (!tmpl) return EXECUTION_FAILURE;
        tmpl[0] = (char *) "/bin/echo";
        tmpl[1] = NULL;
        tmpl_n = 1;
        default_echo = 1;
    } else {
        tmpl = malloc ((size_t) (tmpl_n + 1) * sizeof *tmpl);
        if (!tmpl) return EXECUTION_FAILURE;
        int i = 0;
        for (WORD_LIST *p = list; p; p = p->next) tmpl[i++] = p->word->word;
        tmpl[tmpl_n] = NULL;
    }

    int rc = BX_OK;
    int got_any = 0;
    int pool_n = 0, pool_fatal = 0;
    pid_t *pool_pids = NULL;
    char **pool_cmds = NULL;
    sigset_t block_chld, prev_mask;
    int parallel = max_p > 1;
    if (parallel) {
        pool_pids = calloc ((size_t) max_p, sizeof *pool_pids);
        pool_cmds = calloc ((size_t) max_p, sizeof *pool_cmds);
        if (!pool_pids || !pool_cmds) {
            free (pool_pids); free (pool_cmds); free (tmpl);
            return BX_BAD;
        }
        sigemptyset (&block_chld);
        sigaddset (&block_chld, SIGCHLD);
        sigprocmask (SIG_BLOCK, &block_chld, &prev_mask);
    }

    if (Iflag) {
        /* -I REPL: run CMD once per input, with REPL replaced by the input. */
        char *arg;
        int read_error = 0;
        while ((arg = bx_read_arg (stdin, nul_sep, 1, &read_error)) != NULL) {
            got_any = 1;
            char **argv = malloc ((size_t) (tmpl_n + 1) * sizeof *argv);
            if (!argv) { free (arg); break; }
            size_t Ilen = strlen (Iflag);
            size_t alen = strlen (arg);
            for (int i = 0; i < tmpl_n; i++) {
                /* Replace EVERY occurrence of REPL in tmpl[i] with arg.
                   GNU xargs parity: `-I X echo a-X-b-X` with input "foo"
                   yields "echo a-foo-b-foo", not "echo a-foo-b-X". The
                   scan advances past each substitution so a REPL byte
                   that appears inside the input itself does NOT trigger
                   re-substitution (also GNU parity).  Empty REPL → no
                   substitution (avoids an infinite strstr loop and keeps
                   the diagnostic clean; GNU xargs rejects it as "command
                   too long"). */
                if (Ilen == 0) {
                    argv[i] = strdup (tmpl[i]);
                    continue;
                }
                const char *src = tmpl[i];
                size_t nocc = 0;
                const char *scan = src;
                const char *hit;
                while ((hit = strstr (scan, Iflag)) != NULL) {
                    nocc++;
                    scan = hit + Ilen;
                }
                if (nocc == 0) {
                    argv[i] = strdup (tmpl[i]);
                    continue;
                }
                size_t outlen = strlen (src) + nocc * alen - nocc * Ilen;
                char *out = malloc (outlen + 1);
                if (!out) {
                    /* Allocation failure: fall back to template-as-is
                       so the run continues; the missing substitution
                       will surface as a child error. */
                    argv[i] = strdup (tmpl[i]);
                    continue;
                }
                const char *p = src;
                char *o = out;
                while ((hit = strstr (p, Iflag)) != NULL) {
                    size_t lhs = (size_t) (hit - p);
                    memcpy (o, p, lhs); o += lhs;
                    memcpy (o, arg, alen); o += alen;
                    p = hit + Ilen;
                }
                memcpy (o, p, strlen (p) + 1);
                argv[i] = out;
            }
            argv[tmpl_n] = NULL;
            int r = BX_OK;
            if (!pflag || bx_prompt_yes (argv, tmpl_n)) {
                if (parallel) {
                    while (pool_n >= max_p) {
                        r = bx_wait_one (pool_pids, pool_cmds, &pool_n, &pool_fatal);
                        rc = bx_fold (rc, r);
                        if (pool_fatal) break;
                    }
                    if (!pool_fatal) {
                        pid_t pid = bx_spawn (argv, tmpl_n, tflag);
                        if (pid < 0) { r = BX_BAD; rc = bx_fold (rc, r); }
                        else { pool_pids[pool_n] = pid; pool_cmds[pool_n++] = strdup (argv[0]); }
                    }
                } else {
                    r = bx_run (argv, tmpl_n, tflag);
                    rc = bx_fold (rc, r);
                }
            }
            for (int i = 0; i < tmpl_n; i++) free (argv[i]);
            free (argv);
            free (arg);
            /* GNU xargs aborts after a fatal child (signaled, 255, or
               exec failure). Drop the rest of stdin and stop. */
            if (bx_is_fatal (r) || pool_fatal) break;
        }
        if (read_error) rc = bx_fold (rc, BX_BAD);
    } else {
        /* Batch mode: collect args up to max_n (or per-batch byte limit).
           Default cap is min(ARG_MAX/2, 65536); -s SIZE overrides it.
           The accumulator (`batch_bytes`) tracks input-arg bytes only,
           so when -s is given we subtract the template overhead
           (sum of strlen(tmpl[i])+1) once up front. If the template
           already meets or exceeds SIZE, no input can fit — diagnose
           and exit EX_USAGE, matching GNU "argument list too long". */
        long arg_max = sysconf (_SC_ARG_MAX);
        if (arg_max <= 0) arg_max = 131072;
        size_t cap_bytes;
        if (s_flag > 0) {
            size_t tmpl_bytes = 0;
            for (int i = 0; i < tmpl_n; i++) tmpl_bytes += strlen (tmpl[i]) + 1;
            if ((size_t) s_flag <= tmpl_bytes) {
                builtin_error ("-s %ld: argument list too long (template alone needs %zu bytes)",
                               s_flag, tmpl_bytes);
                free (tmpl);
                return EX_USAGE;
            }
            cap_bytes = (size_t) s_flag - tmpl_bytes;
        } else {
            cap_bytes = (size_t) arg_max / 2;
            if (cap_bytes > 65536) cap_bytes = 65536;
        }

        size_t batch_cap = 64, batch_n = 0;
        size_t batch_bytes = 0;
        char **batch = malloc (batch_cap * sizeof *batch);
        if (!batch) { free (tmpl); return BX_BAD; }
        char *arg;
        int read_error = 0;
        int aborted_fatal = 0;
        while ((arg = bx_read_arg (stdin, nul_sep, max_l > 0, &read_error)) != NULL) {
            got_any = 1;
            size_t alen = strlen (arg) + 1;
            int flush = 0;
            if (max_n > 0 && (int) batch_n >= max_n) flush = 1;
            if (max_l > 0 && (int) batch_n >= max_l) flush = 1;
            if (batch_n > 0 && batch_bytes + alen > cap_bytes) flush = 1;
            if (flush) {
                /* Build argv = template + batch. */
                int total = tmpl_n + (int) batch_n;
                char **argv = malloc ((size_t) (total + 1) * sizeof *argv);
                int j = 0;
                for (int i = 0; i < tmpl_n; i++) argv[j++] = tmpl[i];
                for (size_t i = 0; i < batch_n; i++) argv[j++] = batch[i];
                argv[total] = NULL;
                int r = BX_OK;
                if (!pflag || bx_prompt_yes (argv, total)) {
                    if (parallel) {
                        while (pool_n >= max_p) {
                            r = bx_wait_one (pool_pids, pool_cmds, &pool_n, &pool_fatal);
                            rc = bx_fold (rc, r);
                            if (pool_fatal) break;
                        }
                        if (!pool_fatal) {
                            pid_t pid = bx_spawn (argv, total, tflag);
                            if (pid < 0) { r = BX_BAD; rc = bx_fold (rc, r); }
                            else { pool_pids[pool_n] = pid; pool_cmds[pool_n++] = strdup (argv[0]); }
                        }
                    } else {
                        r = bx_run (argv, total, tflag);
                        rc = bx_fold (rc, r);
                    }
                }
                free (argv);
                for (size_t i = 0; i < batch_n; i++) free (batch[i]);
                batch_n = 0; batch_bytes = 0;
                if (bx_is_fatal (r) || pool_fatal) { free (arg); aborted_fatal = 1; break; }
            }
            if (batch_n >= batch_cap) {
                batch_cap *= 2;
                char **nb = realloc (batch, batch_cap * sizeof *nb);
                if (!nb) { free (arg); break; }
                batch = nb;
            }
            batch[batch_n++] = arg;
            batch_bytes += alen;
        }
        if (read_error) rc = bx_fold (rc, BX_BAD);
        /* Final flush — only if we didn't abort on a fatal child. */
        if (!aborted_fatal && batch_n > 0) {
            int total = tmpl_n + (int) batch_n;
            char **argv = malloc ((size_t) (total + 1) * sizeof *argv);
            int j = 0;
            for (int i = 0; i < tmpl_n; i++) argv[j++] = tmpl[i];
            for (size_t i = 0; i < batch_n; i++) argv[j++] = batch[i];
            argv[total] = NULL;
            int r = BX_OK;
            if (!pflag || bx_prompt_yes (argv, total)) {
                if (parallel) {
                    while (pool_n >= max_p) {
                        r = bx_wait_one (pool_pids, pool_cmds, &pool_n, &pool_fatal);
                        rc = bx_fold (rc, r);
                        if (pool_fatal) break;
                    }
                    if (!pool_fatal) {
                        pid_t pid = bx_spawn (argv, total, tflag);
                        if (pid < 0) { r = BX_BAD; rc = bx_fold (rc, r); }
                        else { pool_pids[pool_n] = pid; pool_cmds[pool_n++] = strdup (argv[0]); }
                    }
                } else {
                    r = bx_run (argv, total, tflag);
                    rc = bx_fold (rc, r);
                }
            }
            free (argv);
            for (size_t i = 0; i < batch_n; i++) free (batch[i]);
        } else if (aborted_fatal) {
            for (size_t i = 0; i < batch_n; i++) free (batch[i]);
        }
        free (batch);
    }

    /* If no input AND -r set, do nothing and exit success.
       If no input AND -r not set, run CMD once with no args (POSIX). */
    if (!got_any && !rflag && !Iflag) {
        char **argv = malloc ((size_t) (tmpl_n + 1) * sizeof *argv);
        for (int i = 0; i < tmpl_n; i++) argv[i] = tmpl[i];
        argv[tmpl_n] = NULL;
        int r = BX_OK;
        if (!pflag || bx_prompt_yes (argv, tmpl_n)) {
            r = bx_run (argv, tmpl_n, tflag);
            rc = bx_fold (rc, r);
        }
        free (argv);
    }

    while (parallel && pool_n > 0) {
        int r = bx_wait_one (pool_pids, pool_cmds, &pool_n, &pool_fatal);
        rc = bx_fold (rc, r);
    }
    if (parallel) {
        sigprocmask (SIG_SETMASK, &prev_mask, NULL);
        free (pool_pids);
        free (pool_cmds);
    }

    if (default_echo) free (tmpl); else free (tmpl);
    return rc;
}

char *xargs_doc[] = {
    "Run an enabled builtin or external command for each argument batch.",
    "Build and run command lines from stdin.",
    "",
    "    bashxargs [-0rtp] [-n MAX] [-L MAX] [-P MAX] [-s SIZE]",
    "              [-I REPL] [CMD [ARG...]]",
    "    bashxargs --help | --version",
    "",
    "    -0        NUL-separated input (pair with `find -print0`)",
    "    -r        no-run-if-empty",
    "    -t        echo command before run",
    "    -p        prompt before run (yes/no)",
    "    -n MAX    max args per invocation",
    "    -L MAX    max input lines/items per invocation",
    "    -P MAX    run up to MAX invocations in parallel",
    "    -s SIZE   max command-line bytes per invocation (POSIX/GNU)",
    "    -I REPL   substitute REPL with input arg; run once per input",
    (char *)NULL
};

struct builtin bashxargs_struct = {
    "bashxargs",
    xargs_builtin,
    BUILTIN_ENABLED,
    xargs_doc,
    "bashxargs [-0rtp] [-n MAX] [-L MAX] [-P MAX] [-s SIZE] [-I REPL] [CMD [ARG...]]",
    0
};
