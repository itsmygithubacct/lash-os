/* bashlink.c — POSIX link(1) as a bash builtin.
 *
 * Phase S of bash-os POSIX gap-fillers. Strict POSIX hardlink — no
 * GNU-style -f / -s / -v / -L flags. Just `link TARGET LINK_NAME`.
 *
 *   bashlink TARGET LINK_NAME
 *       link(2) syscall. Errors mirror GNU's `link:` prefix on
 *       stderr with strerror(errno) text.
 *
 * Symbolic link creation and unlink/rm operations live elsewhere
 * (bash builtin `ln` for symlinks, bash builtin `rm` / `unlink` for
 * deletion). bashlink is the POSIX `link` utility specifically —
 * it only does hardlink.
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

#include "loadables.h"

int
link_builtin (WORD_LIST *list)
{
    if (list && strcmp (list->word->word, "--help") == 0) {
        builtin_usage ();
        return EXECUTION_SUCCESS;
    }
    if (list && strcmp (list->word->word, "--version") == 0) {
        puts ("bashlink 1.0 (bash-loadable)");
        return EXECUTION_SUCCESS;
    }
    if (list && strcmp (list->word->word, "--") == 0)
        list = list->next;
    if (!list || !list->next || list->next->next) {
        builtin_error ("usage: bashlink TARGET LINK_NAME");
        return EX_USAGE;
    }
    const char *target = list->word->word;
    const char *linkname = list->next->word->word;
    if (link (target, linkname) < 0) {
        builtin_error ("cannot create link '%s' to '%s': %s",
                       linkname, target, strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

char *link_doc[] = {
    "POSIX link — create a hard link.",
    "",
    "    bashlink TARGET LINK_NAME",
    "    bashlink --help | --version",
    "        Make LINK_NAME a hard link to TARGET. Both must reside",
    "        on the same filesystem; cannot link directories.",
    "",
    "Errors mirror GNU's diagnostic style. Returns 0 on success,",
    "non-zero on failure.",
    (char *)NULL
};

struct builtin bashlink_struct = {
    "bashlink",
    link_builtin,
    BUILTIN_ENABLED,
    link_doc,
    "bashlink TARGET LINK_NAME",
    0
};
