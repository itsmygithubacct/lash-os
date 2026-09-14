/* scrub.c — history-scrubbing loadable (Stage 36.B-lite).
 *
 * Closes research/bash_linux/SECURITY-REVIEW.md §3.4 (MEDIUM): bash
 * captures every command line into ~/.bash_history. Accidental paste
 * of `mysql -p hunter2` or `FOO=secret some-cmd` then persists on the
 * rootfs.
 *
 * Layered defenses (pre-existing): /etc/profile sets HISTCONTROL=
 * ignorespace:erasedups + HISTIGNORE for common secret forms (Stage
 * 36.A). This loadable adds a POST-HOC scrub mechanism: an operator-
 * configurable pattern store + verbs that drop matching lines from a
 * history file, atomically.
 *
 * Live mode removes matching entries from readline's in-memory history
 * list and wires that pruning into PROMPT_COMMAND. Bash's statically linked
 * add_history() call sites cannot be interposed from a loadable, so the
 * command is visible only until the next prompt-command pass.
 *
 * Verbs:
 *   scrub enable             flip the loadable's enabled flag
 *   scrub disable            flip back
 *   scrub status             print enabled / pattern-count
 *   scrub add-pattern REGEX  compile + append POSIX ERE to denylist
 *   scrub list-patterns      print stored patterns (one per line)
 *   scrub clear-patterns     drop every pattern (incl. baked-ins)
 *   scrub scrub-line LINE    rc 0 if line OK, 1 if denylist match
 *   scrub scrub-current [FILE]
 *                               read FILE, drop matched lines, atomic
 *                               rewrite. Default FILE: $HISTFILE or
 *                               ~/.bash_history.
 *   scrub scrub-argv [LABEL]
 *                               overwrite this process's argv memory
 *                               range as exposed by /proc/self/stat.
 *
 * Built-in denylist seeded at first-use. Tuned conservatively (no
 * false-positives on benign forms; HISTIGNORE catches the rest).
 *
 * SPDX-License-Identifier: MIT
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
#include <regex.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <readline/history.h>

#include "loadables.h"

#define BSC_MAX_PATTERNS 64

struct bsc_pattern {
    int      in_use;
    char    *src;       /* original pattern string (owned) */
    regex_t  re;
};

static struct bsc_pattern bsc_patterns[BSC_MAX_PATTERNS];
static int bsc_initialized = 0;
static int bsc_explicitly_cleared = 0; /* clear-patterns was called; prevents auto-reload */
static int bsc_enabled = 1;
static int bsc_live_enabled = 0;
static long bsc_live_dropped = 0;
static char *bsc_saved_prompt_command = NULL;
extern char *get_string_value (const char *);

static const char *bsc_default_patterns[] = {
    "--password=",
    "--token=",
    "--secret=",
    "--api-key=",
    "PASSWORD=",
    "PASSWD=",
    "SECRET=",
    "TOKEN=",
    "API_KEY=",
    "[A-Z_]+PASSWORD=",
    "[A-Z_]+PASSWD=",
    "[A-Z_]+SECRET=",
    "[A-Z_]+TOKEN=",
    "[A-Z_]+API_KEY=",
    NULL
};

/* Compile + push REGEX onto the denylist. Returns 0 on success, -1 on
 * full table or compile error (errmsg printed). */
static int
bsc_add (const char *src)
{
    if (!src || !*src) {
        builtin_error ("add-pattern: empty regex");
        return -1;
    }
    int slot = -1;
    for (int i = 0; i < BSC_MAX_PATTERNS; i++) {
        if (!bsc_patterns[i].in_use) { slot = i; break; }
    }
    if (slot < 0) {
        builtin_error ("add-pattern: pattern table full (%d)",
                       BSC_MAX_PATTERNS);
        return -1;
    }
    regex_t re;
    int rc = regcomp (&re, src, REG_EXTENDED | REG_NOSUB);
    if (rc != 0) {
        char buf[256];
        regerror (rc, &re, buf, sizeof buf);
        regfree (&re);
        builtin_error ("add-pattern: regcomp failed for '%s': %s", src, buf);
        return -1;
    }
    char *dup = strdup (src);
    if (!dup) {
        regfree (&re);
        builtin_error ("add-pattern: strdup failed");
        return -1;
    }
    bsc_patterns[slot].in_use = 1;
    bsc_patterns[slot].src    = dup;
    bsc_patterns[slot].re     = re;
    return 0;
}

static void
bsc_init_defaults (void)
{
    if (bsc_initialized || bsc_explicitly_cleared) return;
    bsc_initialized = 1;
    for (const char **p = bsc_default_patterns; *p; p++) {
        (void) bsc_add (*p);   /* best-effort */
    }
}

/* Returns 1 if LINE matches any denylist pattern, 0 otherwise. */
static int
bsc_match (const char *line)
{
    if (!line) return 0;
    bsc_init_defaults ();
    for (int i = 0; i < BSC_MAX_PATTERNS; i++) {
        if (!bsc_patterns[i].in_use) continue;
        if (regexec (&bsc_patterns[i].re, line, 0, NULL, 0) == 0) return 1;
    }
    return 0;
}

/* ---- verb handlers ------------------------------------------------- */

static int
bsc_enable_cmd (WORD_LIST *args)
{
    (void) args;
    bsc_explicitly_cleared = 0;  /* allow re-seeding defaults after clear-patterns */
    bsc_init_defaults ();
    bsc_enabled = 1;
    return EXECUTION_SUCCESS;
}

static int
bsc_disable_cmd (WORD_LIST *args)
{
    (void) args;
    bsc_enabled = 0;
    return EXECUTION_SUCCESS;
}

static int
bsc_status_cmd (WORD_LIST *args)
{
    (void) args;
    bsc_init_defaults ();
    int n = 0;
    for (int i = 0; i < BSC_MAX_PATTERNS; i++)
        if (bsc_patterns[i].in_use) n++;
    printf ("enabled=%d patterns=%d live=%s dropped=%ld\n",
            bsc_enabled, n, bsc_live_enabled ? "yes" : "no",
            bsc_live_dropped);
    return EXECUTION_SUCCESS;
}

static int
bsc_add_pattern_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("add-pattern: REGEX required"); return EX_USAGE; }
    bsc_init_defaults ();
    return bsc_add (args->word->word) == 0
        ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
bsc_list_patterns_cmd (WORD_LIST *args)
{
    (void) args;
    bsc_init_defaults ();
    for (int i = 0; i < BSC_MAX_PATTERNS; i++) {
        if (!bsc_patterns[i].in_use) continue;
        printf ("%s\n", bsc_patterns[i].src);
    }
    return EXECUTION_SUCCESS;
}

static int
bsc_clear_patterns_cmd (WORD_LIST *args)
{
    (void) args;
    for (int i = 0; i < BSC_MAX_PATTERNS; i++) {
        if (!bsc_patterns[i].in_use) continue;
        regfree (&bsc_patterns[i].re);
        free (bsc_patterns[i].src);
        bsc_patterns[i].in_use = 0;
        bsc_patterns[i].src    = NULL;
    }
    /* Set flag so bsc_init_defaults does NOT auto-reload. Only enable clears it. */
    bsc_explicitly_cleared = 1;
    return EXECUTION_SUCCESS;
}

/* `scrub scrub-line LINE` — rc 0 if LINE is safe, 1 if it matches
   any denylist pattern. When disabled, all lines pass through (rc 0). */
static int
bsc_scrub_line_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("scrub-line: LINE required"); return EX_USAGE; }
    if (!bsc_enabled) return EXECUTION_SUCCESS;
    return bsc_match (args->word->word) ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

/* `scrub scrub-current [FILE]` — read FILE, drop denylist matches,
   atomically rewrite. Returns counts via `scrub scrub-current FILE
   -V VAR` (sets VAR="kept dropped"). */
static int
bsc_scrub_current_cmd (WORD_LIST *args)
{
    const char *path = NULL;
    const char *var  = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if      (!strcmp (w, "-V") && p->next) { p = p->next; var = p->word->word; }
        else if (!path)                        { path = w; }
        else { builtin_error ("scrub-current: unexpected arg: %s", w); return EX_USAGE; }
    }
    if (!bsc_enabled) {
        if (var) builtin_bind_variable ((char *) var, "pass", 0);
        return EXECUTION_SUCCESS;
    }
    if (!path) {
        path = getenv ("HISTFILE");
        if (!path || !*path) {
            const char *home = getenv ("HOME");
            static char fallback[1024];
            if (!home || !*home) {
                builtin_error ("scrub-current: HISTFILE / HOME both unset; pass FILE");
                return EX_USAGE;
            }
            snprintf (fallback, sizeof fallback, "%s/.bash_history", home);
            path = fallback;
        }
    }
    bsc_init_defaults ();

    FILE *in = fopen (path, "r");
    if (!in) {
        if (errno == ENOENT) return EXECUTION_SUCCESS; /* nothing to do */
        builtin_error ("scrub-current: open %s: %s", path, strerror (errno));
        return EXECUTION_FAILURE;
    }

    /* Atomic rewrite via FILE.scrub.tmp + rename. Same dir so the
       rename is atomic on POSIX. */
    char tmp[1100];
    snprintf (tmp, sizeof tmp, "%s.scrub.tmp", path);
    int tmpfd = open (tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (tmpfd < 0) {
        builtin_error ("scrub-current: open %s: %s", tmp, strerror (errno));
        fclose (in);
        return EXECUTION_FAILURE;
    }
    FILE *out = fdopen (tmpfd, "w");
    if (!out) {
        builtin_error ("scrub-current: fdopen failed");
        close (tmpfd); unlink (tmp); fclose (in);
        return EXECUTION_FAILURE;
    }

    /* Preserve the original file's mode, not just our 0600 default. */
    struct stat st;
    if (fstat (fileno (in), &st) == 0)
        fchmod (tmpfd, st.st_mode & 07777);

    char *line = NULL;
    size_t lcap = 0;
    ssize_t n;
    long kept = 0, dropped = 0;
    while ((n = getline (&line, &lcap, in)) >= 0) {
        /* Strip trailing newline for match (re-add on emit). */
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = 0;
        if (bsc_match (line)) {
            dropped++;
        } else {
            fputs (line, out);
            fputc ('\n', out);
            kept++;
        }
    }
    free (line);
    fclose (in);
    if (fclose (out) != 0) {
        builtin_error ("scrub-current: close %s: %s", tmp, strerror (errno));
        unlink (tmp);
        return EXECUTION_FAILURE;
    }
    if (rename (tmp, path) != 0) {
        builtin_error ("scrub-current: rename: %s", strerror (errno));
        unlink (tmp);
        return EXECUTION_FAILURE;
    }

    if (var) {
        char buf[64];
        snprintf (buf, sizeof buf, "%ld %ld", kept, dropped);
        builtin_bind_variable ((char *) var, buf, 0);
    } else {
        printf ("%ld %ld\n", kept, dropped);
    }
    return EXECUTION_SUCCESS;
}

static int
bsc_proc_arg_bounds (unsigned long long *startp, unsigned long long *endp)
{
    FILE *fp = fopen ("/proc/self/stat", "r");
    if (!fp) {
        builtin_error ("scrub-argv: open /proc/self/stat: %s", strerror (errno));
        return -1;
    }

    char buf[4096];
    if (!fgets (buf, sizeof buf, fp)) {
        builtin_error ("scrub-argv: read /proc/self/stat: %s", strerror (errno));
        fclose (fp);
        return -1;
    }
    fclose (fp);

    char *rp = strrchr (buf, ')');
    if (!rp || rp[1] != ' ') {
        builtin_error ("scrub-argv: malformed /proc/self/stat");
        return -1;
    }

    unsigned long long arg_start = 0, arg_end = 0;
    int field = 3;              /* first token after comm is state. */
    char *save = NULL;
    for (char *tok = strtok_r (rp + 2, " \n", &save);
         tok;
         tok = strtok_r (NULL, " \n", &save), field++) {
        if (field == 48)
            arg_start = strtoull (tok, NULL, 10);
        else if (field == 49) {
            arg_end = strtoull (tok, NULL, 10);
            break;
        }
    }

    if (arg_start == 0 || arg_end <= arg_start) {
        builtin_error ("scrub-argv: unavailable argv bounds");
        return -1;
    }

    *startp = arg_start;
    *endp = arg_end;
    return 0;
}

/* `scrub scrub-argv [LABEL]` overwrites this shell's Linux argv
   memory range. This is intentionally current-process only: it avoids
   ptrace-like cross-process mutation while removing /proc/$pid/cmdline
   exposure for secrets passed to an already-running shell. */
static int
bsc_scrub_argv_cmd (WORD_LIST *args)
{
    const char *label = "[scrub]";
    if (args) {
        label = args->word->word;
        if (args->next) {
            builtin_error ("scrub-argv: unexpected arg: %s",
                           args->next->word->word);
            return EX_USAGE;
        }
    }
    if (!label) label = "";

    unsigned long long arg_start = 0, arg_end = 0;
    if (bsc_proc_arg_bounds (&arg_start, &arg_end) < 0)
        return EXECUTION_FAILURE;

    unsigned long long span = arg_end - arg_start;
    int fd = open ("/proc/self/mem", O_RDWR);
    if (fd < 0) {
        builtin_error ("scrub-argv: open /proc/self/mem: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }

    size_t llen = strlen (label);
    if (llen >= span) llen = (size_t) span - 1;
    if (llen > 0) {
        if (pwrite (fd, label, llen, (off_t) arg_start) != (ssize_t) llen) {
            builtin_error ("scrub-argv: write label: %s", strerror (errno));
            close (fd);
            return EXECUTION_FAILURE;
        }
    }

    char zeros[256];
    memset (zeros, 0, sizeof zeros);
    unsigned long long off = arg_start + llen;
    unsigned long long left = span - llen;
    while (left > 0) {
        size_t chunk = left > sizeof zeros ? sizeof zeros : (size_t) left;
        if (pwrite (fd, zeros, chunk, (off_t) off) != (ssize_t) chunk) {
            builtin_error ("scrub-argv: zero argv: %s", strerror (errno));
            close (fd);
            return EXECUTION_FAILURE;
        }
        off += chunk;
        left -= chunk;
    }
    close (fd);
    return EXECUTION_SUCCESS;
}

static long
bsc_prune_history (void)
{
    long dropped = 0;
    bsc_init_defaults ();
    for (int i = history_length - 1; i >= 0; i--) {
        HIST_ENTRY **list = history_list ();
        if (!list || !list[i] || !list[i]->line) continue;
        if (bsc_enabled && bsc_match (list[i]->line)) {
            HIST_ENTRY *removed = remove_history (i);
            if (removed)
                free_history_entry (removed);
            dropped++;
        }
    }
    bsc_live_dropped += dropped;
    return dropped;
}

static int
bsc_live_cmd (WORD_LIST *args)
{
    if (!args) {
        builtin_error ("live: enable|disable|prune");
        return EX_USAGE;
    }
    const char *sub = args->word->word;
    if (!strcmp (sub, "prune")) {
        long n = bsc_prune_history ();
        printf ("%ld\n", n);
        return EXECUTION_SUCCESS;
    }
    if (!strcmp (sub, "enable")) {
        if (!bsc_live_enabled) {
            const char *pc = get_string_value ? get_string_value ("PROMPT_COMMAND") : NULL;
            free (bsc_saved_prompt_command);
            bsc_saved_prompt_command = strdup (pc ? pc : "");
            if (pc && strstr (pc, "scrub live prune"))
                builtin_bind_variable ("PROMPT_COMMAND", (char *) pc, 0);
            else if (pc && *pc) {
                size_t n = strlen (pc) + 32;
                char *joined = malloc (n);
                if (!joined)
                    { builtin_error ("live enable: malloc"); return EXECUTION_FAILURE; }
                snprintf (joined, n, "scrub live prune >/dev/null; %s", pc);
                builtin_bind_variable ("PROMPT_COMMAND", joined, 0);
                free (joined);
            } else {
                builtin_bind_variable ("PROMPT_COMMAND", "scrub live prune >/dev/null", 0);
            }
            bsc_live_enabled = 1;
        }
        bsc_prune_history ();
        return EXECUTION_SUCCESS;
    }
    if (!strcmp (sub, "disable")) {
        if (bsc_live_enabled) {
            builtin_bind_variable ("PROMPT_COMMAND",
                                   bsc_saved_prompt_command ? bsc_saved_prompt_command : "", 0);
            bsc_live_enabled = 0;
        }
        return EXECUTION_SUCCESS;
    }
    builtin_error ("live: unknown subcommand: %s", sub);
    return EX_USAGE;
}

/* ---- bash builtin entry ------------------------------------------- */

extern char *scrub_doc[];

int
scrub_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    if (strcmp (cmd, "--help") == 0 || strcmp (cmd, "-h") == 0) {
        char **d;
        for (d = scrub_doc; *d; d++) puts (*d);
        return EXECUTION_SUCCESS;
    }
    WORD_LIST *args = list->next;
    if (!strcmp (cmd, "enable"))          return bsc_enable_cmd          (args);
    if (!strcmp (cmd, "disable"))         return bsc_disable_cmd         (args);
    if (!strcmp (cmd, "status"))          return bsc_status_cmd          (args);
    if (!strcmp (cmd, "add-pattern"))     return bsc_add_pattern_cmd     (args);
    if (!strcmp (cmd, "list-patterns"))   return bsc_list_patterns_cmd   (args);
    if (!strcmp (cmd, "clear-patterns"))  return bsc_clear_patterns_cmd  (args);
    if (!strcmp (cmd, "scrub-line"))      return bsc_scrub_line_cmd      (args);
    if (!strcmp (cmd, "scrub-current"))   return bsc_scrub_current_cmd   (args);
    if (!strcmp (cmd, "scrub-argv"))      return bsc_scrub_argv_cmd      (args);
    if (!strcmp (cmd, "live"))            return bsc_live_cmd            (args);
    builtin_error ("unknown verb: %s "
                   "(try enable/disable/status/add-pattern/list-patterns/"
                   "clear-patterns/scrub-line/scrub-current/scrub-argv/live)", cmd);
    return EX_USAGE;
}

char *scrub_doc[] = {
    "bash history scrub helper (Stage 36.B-lite).",
    "",
    "    scrub enable             flip the enabled flag",
    "    scrub disable            flip back",
    "    scrub status             print enabled / pattern-count",
    "    scrub add-pattern REGEX  push a POSIX ERE onto the denylist",
    "    scrub list-patterns      print every pattern, one per line",
    "    scrub clear-patterns     drop every pattern (incl. baked-ins)",
    "    scrub scrub-line LINE    rc 0 if line OK, 1 if denylist hit",
    "    scrub scrub-current [FILE] [-V VAR]",
    "                                read FILE (or $HISTFILE / ~/.bash_history)",
    "                                drop matched lines, atomic rewrite.",
    "                                Without -V: prints \"kept dropped\".",
    "    scrub scrub-argv [LABEL]",
    "                                Linux-only: overwrite this process's",
    "                                /proc/self/cmdline argv memory range.",
    "    scrub live enable|disable|prune",
    "                                prune matching entries from live history",
    "                                and wire prune into PROMPT_COMMAND.",
    "",
    "Built-in denylist (seeded at first use): --password=, --token=,",
    "--secret=, --api-key=, [A-Z_]+(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY)=.",
    "Use `scrub live enable` for prompt-time in-memory pruning.",
    (char *) NULL
};

struct builtin scrub_struct = {
    "scrub",
    scrub_builtin,
    BUILTIN_ENABLED,
    scrub_doc,
    "scrub <verb> [args...]",
    0
};
