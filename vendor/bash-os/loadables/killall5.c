/* bashkillall5.c — SysV killall5 entry; thin shim over bashpgrep.c.
 *
 * killall5 is not psmisc killall(1): it broadcasts a signal to every
 * non-kernel-thread process outside the caller's session, honoring -o
 * omitpid lists. The shared backend in bashpgrep.c owns the /proc walk,
 * BASHOS_PROC_ROOT fixture guard, session skip, and signal delivery.
 *
 * --- LICENSE --- MIT, same boilerplate as bashpgrep.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include "loadables.h"

#define BP_MODE_KILLALL5 3

extern int bp_dispatch (WORD_LIST *list, int mode);

int
killall5_builtin (WORD_LIST *list)
{
    return bp_dispatch (list, BP_MODE_KILLALL5);
}

char *killall5_doc[] = {
    "Signal all processes outside the caller's session.",
    "",
    "    bashkillall5 -signalnumber [-o omitpid[,omitpid...]]...",
    "    bashkillall5 --dry-run|-n [-o omitpid[,omitpid...]]...",
    "    bashkillall5 -h | --help | -V | --version",
    "",
    "    -signalnumber   signal number or name to deliver, for example -15",
    "    -o PIDS         omit one or more comma-separated process IDs",
    "    -n, --dry-run   list target PIDs without signalling them",
    "",
    "Kernel threads and the caller's whole session are excluded. Under",
    "BASHOS_PROC_ROOT, dry-run enumeration is allowed but signal delivery",
    "is refused because the fixture procfs is read-only.",
    "Returns 0 if any process was selected, 2 if none, 1 if /proc is unreadable.",
    (char *)NULL
};

struct builtin bashkillall5_struct = {
    "bashkillall5",
    killall5_builtin,
    BUILTIN_ENABLED,
    killall5_doc,
    "bashkillall5 -signalnumber [-o omitpid[,omitpid...]]... [-n|--dry-run] [-h|--help|-V|--version]",
    0
};
