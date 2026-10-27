/* SPDX-License-Identifier: MIT */
/* renice.c — absolute-priority renice(1) as a bash builtin.
 *
 *   renice [-n] PRIORITY [-g|-p|-u] ID...
 *
 * Sets niceness on already-running processes (-p PID), process groups
 * (-g PGID), or all processes owned by user (-u USER). Default target
 * type is -p. Like traditional util-linux renice, -n is absolute too.
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
#include <limits.h>
#include <ctype.h>
#include <pwd.h>
#include <sys/resource.h>

#include "loadables.h"

static int
brenice_priority (const char *s, int *out)
{
    char *end;
    errno = 0;
    long value = strtol (s, &end, 10);
    if (errno || end == s || *end || isspace ((unsigned char) *s) ||
        value < INT_MIN || value > INT_MAX) {
        builtin_error ("invalid priority: %s", s);
        return -1;
    }
    *out = (int) value;
    return 0;
}

int
renice_builtin (WORD_LIST *list)
{
    int which = PRIO_PROCESS;
    int prio = 0;
    int rc = EXECUTION_SUCCESS;
    int target_count = 0;

    /* Selectors may precede the priority for compatibility. Consume the
       priority exactly once, before any mutation. A misplaced -n must not
       change it halfway through a target list (or expose its value as a PID). */
    while (list) {
        const char *w = list->word->word;
        if (!strcmp (w, "-p")) which = PRIO_PROCESS;
        else if (!strcmp (w, "-g")) which = PRIO_PGRP;
        else if (!strcmp (w, "-u")) which = PRIO_USER;
        else break;
        list = list->next;
    }
    if (list && !strcmp (list->word->word, "-n")) list = list->next;
    if (!list) {
        builtin_usage ();
        return EXECUTION_FAILURE;
    }
    if (brenice_priority (list->word->word, &prio) < 0) return EXECUTION_FAILURE;
    list = list->next;
    for (WORD_LIST *p = list; p; p = p->next) {
        if (!strcmp (p->word->word, "-n")) {
            builtin_error ("-n must precede the priority");
            return EXECUTION_FAILURE;
        }
    }

    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-p")) { which = PRIO_PROCESS; continue; }
        if (!strcmp (w, "-g")) { which = PRIO_PGRP;    continue; }
        if (!strcmp (w, "-u")) { which = PRIO_USER;    continue; }
        target_count++;
        /* This is a target ID — interpret per the current `which`. */
        id_t id;
        if (which == PRIO_USER) {
            /* Numeric uid? Else look up by name. */
            char *end;
            errno = 0;
            unsigned long n = strtoul (w, &end, 10);
            if (!*w || *w == '-' || isspace ((unsigned char) *w) ||
                (end != w && !*end && (errno || n >= (id_t) -1))) {
                builtin_error ("invalid user ID: %s", w);
                rc = EXECUTION_FAILURE;
                continue;
            }
            if (end != w && *end == '\0') {
                id = (id_t) n;
            } else {
                struct passwd *pw = getpwnam (w);
                if (!pw) {
                    builtin_error ("unknown user: %s", w);
                    rc = EXECUTION_FAILURE;
                    continue;
                }
                id = pw->pw_uid;
            }
        } else {
            char *end;
            errno = 0;
            long n = strtol (w, &end, 10);
            if (errno || end == w || *end || isspace ((unsigned char) *w) ||
                n < 0 || n > INT_MAX) {
                builtin_error ("invalid process ID: %s", w);
                rc = EXECUTION_FAILURE;
                continue;
            }
            id = (id_t) n;
        }
        if (setpriority (which, id, prio) < 0) {
            builtin_error ("setpriority(%d, %lu, %d): %s",
                           which, (unsigned long) id, prio, strerror (errno));
            rc = EXECUTION_FAILURE;
        }
    }

    if (target_count == 0) {
        builtin_error ("usage: renice [-n] PRIORITY [-g|-p|-u] ID...");
        return EXECUTION_FAILURE;
    }
    return rc;
}

char *renice_doc[] = {
    "Set absolute niceness of running processes.",
    "",
    "    renice [-n] PRIORITY [-p|-g|-u] ID...",
    "",
    "    -p   IDs are PIDs (default)",
    "    -g   IDs are process group IDs",
    "    -u   IDs are usernames or UIDs (every process owned)",
    "",
    "Set the niceness to PRIORITY (an absolute value, NOT an increment",
    "— that's nice's job). -n is also absolute, regardless of POSIXLY_CORRECT.",
    "PRIORITY must fit a signed int; Linux clamps it to -20 through 19.",
    "Lowering niceness requires privilege or an adequate RLIMIT_NICE.",
    "Target 0 selects the caller, its group, or its real UID, respectively.",
    "Selectors apply to subsequent IDs. Invalid targets do not stop later IDs.",
    "Success is silent; failure may leave earlier targets changed.",
    (char *)NULL
};

struct builtin renice_struct = {
    "renice",
    renice_builtin,
    BUILTIN_ENABLED,
    renice_doc,
    "renice [-n] PRIORITY [-p|-g|-u] ID...",
    0
};
