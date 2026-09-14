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
    "    bashpkill [-SIGNAL] [-cfx] [-u USER] PATTERN",
    "    bashpkill [-SIGNAL] [-cf] -u USER",
    "    bashpkill -h | --help | -V | --version",
    "",
    "    -SIGNAL    signal name (TERM, KILL, HUP, USR1, …) or number;",
    "               with or without leading SIG. Default: TERM",
    "    -f         match against /proc/PID/cmdline (full command line)",
    "    -c, --count  print only the count of processes signalled",
    "    -x, --exact  match the whole comm/cmdline, not a substring",
    "    -u USER    only signal processes whose real uid is USER",
    "",
    "PATTERN is a substring (not a regex) unless -x is given. Self is never signalled.",
    "Returns 0 if any process was signalled, 1 if none matched.",
    (char *)NULL
};

struct builtin bashpkill_struct = {
    "bashpkill",
    pkill_builtin,
    BUILTIN_ENABLED,
    pkill_doc,
    "bashpkill [-SIGNAL] [-cfx] [-u USER] PATTERN [-h|--help|-V|--version]",
    0
};
