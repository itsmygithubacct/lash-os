/* bashkillall.c — killall(1) entry; thin shim over bashpgrep.c's bp_dispatch.
 *
 * Shares the /proc walker, the flag parser, and the signal-name table
 * with bashpgrep + bashpkill. The differentiator is the match semantic:
 * killall uses exact /proc/PID/comm strcmp (psmisc semantics) rather
 * than substring, so `killall sleep` terminates every sleep but does
 * not accidentally signal `gpg-agent-sleeper` or `sleepd`. Counterpart
 * binaries: psmisc killall (canonical), busybox killall, toybox killall —
 * all three exact-match by default.
 *
 * The exact-match path lives in bp_walk; bp_dispatch knows about
 * BP_MODE_KILLALL via BP_DELIVERS_SIGNAL so `-SIGNAL`, `-u USER` and
 * the standard `-h`/`--help` and `-V`/`--version` short-circuits behave
 * identically to bashpkill. The one user-visible divergence is that killall
 * requires NAME (no `-u USER` without NAME), matching psmisc which
 * errors out the same way.
 *
 * Supports the psmisc positional shape `killall NAME [NAME ...]`; each
 * NAME is matched independently and a process is signalled when any exact
 * name matches.
 *
 * Accepts psmisc's `-e`/`--exact` (force exact) as compatibility no-ops because
 * exact matching is already the default. v1 deliberately omits `-r`
 * (regex match — superset of substring),
 * `-w`/`-y` (wait/young, would require iterated /proc walks against a
 * deadline).
 *
 * --- LICENSE --- MIT, same boilerplate as bashpgrep.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <string.h>

#include "loadables.h"

#define BP_MODE_KILLALL 2

extern int bp_dispatch (WORD_LIST *list, int mode);

static WORD_LIST *
bashkillall_strip_exact_long (WORD_LIST *list)
{
    WORD_LIST *head = list;
    WORD_LIST *prev = NULL;

    for (WORD_LIST *cur = list; cur && cur->word && cur->word->word; ) {
        const char *w = cur->word->word;

        if (strcmp (w, "--") == 0)
            break;
        if (w[0] != '-' || w[1] == '\0')
            break;

        if (strcmp (w, "--exact") == 0) {
            if (prev)
                prev->next = cur->next;
            else
                head = cur->next;
            cur = cur->next;
            continue;
        }

        prev = cur;
        cur = cur->next;
    }

    return head;
}

int
killall_builtin (WORD_LIST *list)
{
    return bp_dispatch (bashkillall_strip_exact_long (list), BP_MODE_KILLALL);
}

char *killall_doc[] = {
    "Signal every process with comm exactly equal to any NAME.",
    "",
    "    bashkillall [-SIGNAL] [-e|--exact] [-f] [-u USER] NAME [NAME ...]",
    "    bashkillall -h | --help | -V | --version",
    "",
    "    -SIGNAL    signal name (TERM, KILL, HUP, USR1, ...) or number;",
    "               with or without leading SIG. Default: TERM",
    "    -e, --exact",
    "               accepted psmisc compatibility no-op; exact matching",
    "               is already the default",
    "    -f         match against /proc/PID/cmdline (full command line)",
    "               instead of /proc/PID/comm",
    "    -u USER    only signal processes whose real uid is USER",
    "               (numeric or /etc/passwd name)",
    "",
    "Each NAME is matched exactly against /proc/PID/comm (kernel-truncated",
    "to 15 chars). Self is never signalled. Use bashpkill for substring.",
    "Returns 0 if any process was signalled, 1 if none, 2 on usage error.",
    (char *)NULL
};

struct builtin bashkillall_struct = {
    "bashkillall",
    killall_builtin,
    BUILTIN_ENABLED,
    killall_doc,
    "bashkillall [-SIGNAL] [-e|--exact] [-f] [-u USER] NAME [NAME ...] [-h|--help|-V|--version]",
    0
};
