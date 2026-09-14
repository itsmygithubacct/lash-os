/* SPDX-License-Identifier: MIT */
/* escdelay.c — configurable ESC grace knob (ncurses-input phase 1).
 *
 *   escdelay set [--screen NAME] MS
 *   escdelay get [--screen NAME]
 *   escdelay --help | --version
 *
 * Knob for the ESC-vs-CSI grace period that the input-decoding pipeline
 * uses to disambiguate a bare ESC keypress from the start of a CSI
 * sequence. ncurses' default is 1000 ms (the source of universally-
 * complained laggy-ESC in vim/nano on curses); bash-os already uses
 * 50 ms in scripts/loadables/_bl_key.c, and this loadable lets
 * operators read or override that value.
 *
 * Precedence (highest wins):
 *   1. $BASHESCDELAY_SCREEN_<NAME> env (per-screen GET only)
 *   2. builtin per-screen state (per-screen GET only)
 *   3. $BASHESCDELAY env
 *   4. builtin global state
 *   5. default 50 ms
 *
 * Bounds: 0..5000 ms inclusive (ncurses uses [0, INT_MAX] but a 5 s
 * cap is more than enough for any human-typed ESC pulse and prevents
 * pathological values from wedging downstream readers).
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
#include <ctype.h>

#include "loadables.h"

#define BSD_DEFAULT_MS    50
#define BSD_MIN_MS        0
#define BSD_MAX_MS        5000
#define BSD_MAX_SCREENS   16
#define BSD_MAX_NAME_LEN  63

static int bsd_global_ms = -1;   /* -1 sentinel: unset (use default) */
static struct bsd_screen_state {
    char name[BSD_MAX_NAME_LEN + 1];
    int  ms;
} bsd_screens[BSD_MAX_SCREENS];
static int bsd_n_screens = 0;

/* Parse `s` as a decimal integer in [BSD_MIN_MS..BSD_MAX_MS].
   Returns 0 on success (writes *out), -1 on bad parse / out of range. */
static int
bsd_parse_ms (const char *s, int *out)
{
    if (s == NULL || *s == '\0') return -1;
    char *end = NULL;
    errno = 0;
    long v = strtol (s, &end, 10);
    if (errno != 0 || end == NULL || *end != '\0' || end == s) return -1;
    if (v < BSD_MIN_MS || v > BSD_MAX_MS) return -1;
    *out = (int) v;
    return 0;
}

/* Validate a screen name: alnum + '_' + '.', length 1..BSD_MAX_NAME_LEN.
   Matches what's safe to embed in an env-var suffix. */
static int
bsd_valid_screen_name (const char *name)
{
    if (name == NULL || *name == '\0') return 0;
    size_t n = strlen (name);
    if (n > BSD_MAX_NAME_LEN) return 0;
    for (const char *p = name; *p; p++) {
        unsigned char c = (unsigned char) *p;
        if (!(isalnum (c) || c == '_' || c == '.')) return 0;
    }
    return 1;
}

/* Look up `name` in the per-screen state table. Returns ms or -1 if
   not found. */
static int
bsd_screen_lookup (const char *name)
{
    for (int i = 0; i < bsd_n_screens; i++) {
        if (strcmp (bsd_screens[i].name, name) == 0)
            return bsd_screens[i].ms;
    }
    return -1;
}

/* Set per-screen state. Returns 0 on success, -1 if table full
   AND name not already present. Updates existing entry in place. */
static int
bsd_screen_set (const char *name, int ms)
{
    for (int i = 0; i < bsd_n_screens; i++) {
        if (strcmp (bsd_screens[i].name, name) == 0) {
            bsd_screens[i].ms = ms;
            return 0;
        }
    }
    if (bsd_n_screens >= BSD_MAX_SCREENS) return -1;
    strncpy (bsd_screens[bsd_n_screens].name, name, BSD_MAX_NAME_LEN);
    bsd_screens[bsd_n_screens].name[BSD_MAX_NAME_LEN] = '\0';
    bsd_screens[bsd_n_screens].ms = ms;
    bsd_n_screens++;
    return 0;
}

/* Probe an env var by name; on success write *out and return 0. Bad
   parse or out-of-range silently returns -1 (the env override is
   advisory — invalid values fall through to lower precedence levels
   rather than erroring out a `get` query). */
static int
bsd_env_lookup (const char *envname, int *out)
{
    const char *v = getenv (envname);
    if (v == NULL) return -1;
    return bsd_parse_ms (v, out);
}

/* Resolve the effective ms value per the precedence table. `screen`
   may be NULL for the global query. */
static int
bsd_resolve (const char *screen)
{
    int ms;
    if (screen != NULL) {
        char envname[16 + BSD_MAX_NAME_LEN + 1];
        snprintf (envname, sizeof envname, "BASHESCDELAY_SCREEN_%s", screen);
        if (bsd_env_lookup (envname, &ms) == 0) return ms;
        int sm = bsd_screen_lookup (screen);
        if (sm >= 0) return sm;
        /* Fall through to global precedence. */
    }
    if (bsd_env_lookup ("BASHESCDELAY", &ms) == 0) return ms;
    if (bsd_global_ms >= 0) return bsd_global_ms;
    return BSD_DEFAULT_MS;
}

/* Parse `set` argv: optional `--screen NAME`, required MS. */
static int
bsd_cmd_set (WORD_LIST *args)
{
    const char *screen = NULL;
    const char *ms_str = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "--screen") == 0) {
            if (!p->next) {
                builtin_error ("set: --screen needs NAME");
                return EX_USAGE;
            }
            p = p->next;
            screen = p->word->word;
            if (!bsd_valid_screen_name (screen)) {
                builtin_error ("set: invalid --screen NAME '%s' (alnum/_/. only, <= %d chars)",
                               screen, BSD_MAX_NAME_LEN);
                return EX_USAGE;
            }
        } else if (ms_str == NULL) {
            ms_str = w;
        } else {
            builtin_error ("set: unexpected argument '%s'", w);
            return EX_USAGE;
        }
    }
    if (ms_str == NULL) {
        builtin_error ("set: MS required (set [--screen NAME] MS)");
        return EX_USAGE;
    }
    int ms;
    if (bsd_parse_ms (ms_str, &ms) < 0) {
        builtin_error ("set: MS must be integer in [%d..%d] (got '%s')",
                       BSD_MIN_MS, BSD_MAX_MS, ms_str);
        return EX_USAGE;
    }
    if (screen != NULL) {
        if (bsd_screen_set (screen, ms) < 0) {
            builtin_error ("set: per-screen table full (%d entries)",
                           BSD_MAX_SCREENS);
            return EXECUTION_FAILURE;
        }
    } else {
        bsd_global_ms = ms;
    }
    return EXECUTION_SUCCESS;
}

/* Parse `get` argv: optional `--screen NAME`, no positional. */
static int
bsd_cmd_get (WORD_LIST *args)
{
    const char *screen = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "--screen") == 0) {
            if (!p->next) {
                builtin_error ("get: --screen needs NAME");
                return EX_USAGE;
            }
            p = p->next;
            screen = p->word->word;
            if (!bsd_valid_screen_name (screen)) {
                builtin_error ("get: invalid --screen NAME '%s' (alnum/_/. only, <= %d chars)",
                               screen, BSD_MAX_NAME_LEN);
                return EX_USAGE;
            }
        } else {
            builtin_error ("get: unexpected argument '%s'", w);
            return EX_USAGE;
        }
    }
    printf ("%d\n", bsd_resolve (screen));
    return EXECUTION_SUCCESS;
}

int
escdelay_builtin (WORD_LIST *list)
{
    if (list == NULL) {
        builtin_usage ();
        return EX_USAGE;
    }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    if (strcmp (cmd, "--help") == 0) { builtin_usage (); return EXECUTION_SUCCESS; }
    if (strcmp (cmd, "--version") == 0) {
        puts ("escdelay 1.0 (bash-loadable)");
        return EXECUTION_SUCCESS;
    }
    if (strcmp (cmd, "set") == 0) return bsd_cmd_set (args);
    if (strcmp (cmd, "get") == 0) return bsd_cmd_get (args);
    builtin_error ("unknown verb: %s (try set/get)", cmd);
    return EX_USAGE;
}

char *escdelay_doc[] = {
    "Configurable ESC grace knob for the bash-os input pipeline.",
    "",
    "    escdelay set [--screen NAME] MS",
    "    escdelay get [--screen NAME]",
    "    escdelay --help | --version",
    "",
    "Default: 50 ms (preserves bash-os's improvement over ncurses' 1000 ms).",
    "Bounds:  0..5000 ms inclusive; out-of-range returns EX_USAGE.",
    "",
    "Precedence (highest wins):",
    "    1. $BASHESCDELAY_SCREEN_<NAME> env (per-screen GET only)",
    "    2. builtin per-screen state",
    "    3. $BASHESCDELAY env",
    "    4. builtin global state",
    "    5. default 50",
    (char *)NULL
};

struct builtin escdelay_struct = {
    "escdelay",
    escdelay_builtin,
    BUILTIN_ENABLED,
    escdelay_doc,
    "escdelay set [--screen NAME] MS | get [--screen NAME] | --help | --version",
    0
};
