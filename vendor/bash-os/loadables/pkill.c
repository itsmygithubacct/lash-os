/* bashpkill.c — pkill(1) entry; thin shim over bashpgrep.c's bp_dispatch.
 *
 * The pgrep/pkill pair shares a /proc-walker, a flag parser, and a
 * signal-name table in bashpgrep.c. Counterpart binaries (procps-ng,
 * busybox) ship a single binary that argv[0]-dispatches; here we
 * register both names in config/bash-loadables-bash-os.list and each
 * registered name needs its own .c (scripts/inject-loadables-to-builtins-c.sh
 * references NAME_builtin + NAME_doc per list entry). Keeping the
 * shared logic in bashpgrep.c avoids duplication; this file is the
 * minimum stub for the pkill name.
 *
 * --- LICENSE --- MIT, same boilerplate as bashpgrep.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include "loadables.h"

#define BP_MODE_KILL 1

extern int bp_dispatch (WORD_LIST *list, int mode);

int
pkill_builtin (WORD_LIST *list)
{
    return bp_dispatch (list, BP_MODE_KILL);
}

char *pkill_doc[] = {
    "Signal running processes by name or cmdline.",
    "",
    "    bashpkill [-SIGNAL] [-cfx] [-n|-o] [SELECTORS] [PATTERN]",
    "    bashpkill [-SIGNAL] [-cf] -u USER",
    "    bashpkill -h | --help | -V | --version",
    "",
    "    -SIGNAL    signal name (TERM, KILL, HUP, USR1, …) or number;",
    "               with or without leading SIG. Default: TERM",
    "    -f         match against /proc/PID/cmdline (full command line)",
    "    -c, --count  print only the count of processes signalled",
    "    -x, --exact  require the regex to match the whole comm/cmdline",
    "    -u USER    only signal processes whose effective uid is USER",
    "    -U USER    filter real uid; -G GROUP filter real gid",
    "    -P PID     filter parent; -g PGRP process group; -s SID session",
    "               selectors accept comma-separated alternatives",
    "    -n, --newest / -o, --oldest select one by start time (ties by PID)",
    "",
    "PATTERN is a POSIX extended regular expression. Self is never signalled.",
    "A pattern or identity/parent/group/session selector is required.",
    "Count includes successful signal requests; vanished processes are skipped.",
    "Returns 0 if any request succeeded, 1 if none, 2 on usage error, 3 on fatal.",
    (char *)NULL
};

struct builtin bashpkill_struct = {
    "bashpkill",
    pkill_builtin,
    BUILTIN_ENABLED,
    pkill_doc,
    "bashpkill [-SIGNAL] [-cfx] [-n|-o] [SELECTORS] [PATTERN] [-h|--help|-V|--version]",
    0
};
