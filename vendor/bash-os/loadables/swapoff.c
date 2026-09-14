/* SPDX-License-Identifier: MIT */
/* swapoff.c — disable a swap area, as a bash builtin.
 *
 *   swapoff device...   # disable specific swap areas (needs root)
 *   swapoff -a          # disable all swaps listed in /proc/swaps
 *
 * --- LICENSE --- MIT, same boilerplate as the other bash-os loadables.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/swap.h>

#include "loadables.h"

static int
swapoff_all (void)
{
    FILE *fp = fopen ("/proc/swaps", "r");
    if (!fp) { builtin_error ("/proc/swaps: %s", strerror (errno)); return EXECUTION_FAILURE; }
    char buf[1024];
    int first = 1, rc = EXECUTION_SUCCESS;
    while (fgets (buf, sizeof buf, fp)) {
        if (first) { first = 0; continue; }   /* header row */
        char path[1024];
        if (sscanf (buf, "%1023s", path) == 1) {
            if (swapoff (path) < 0) { builtin_error ("%s: %s", path, strerror (errno)); rc = EXECUTION_FAILURE; }
        }
    }
    fclose (fp);
    return rc;
}

int
swapoff_builtin (WORD_LIST *list)
{
    int all = 0;
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { extern char *swapoff_doc[]; for (char **lp = swapoff_doc; *lp; lp++) puts (*lp); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "-a") || !strcmp (w, "--all")) { all = 1; list = list->next; continue; }
        builtin_error ("unknown option: %s", w); builtin_usage (); return EX_USAGE;
    }

    if (all) return swapoff_all ();
    if (!list) { builtin_error ("no device specified (or use -a)"); builtin_usage (); return EX_USAGE; }

    int rc = EXECUTION_SUCCESS;
    for (WORD_LIST *p = list; p; p = p->next)
        if (swapoff (p->word->word) < 0) { builtin_error ("%s: %s", p->word->word, strerror (errno)); rc = EXECUTION_FAILURE; }
    return rc;
}

char *swapoff_doc[] = {
    "Disable a swap area.",
    "",
    "    swapoff device...   disable the named swap areas",
    "    swapoff -a          disable every active swap area",
    "",
    "Requires root.",
    (char *) NULL
};

struct builtin swapoff_struct = {
    "swapoff",
    swapoff_builtin,
    BUILTIN_ENABLED,
    swapoff_doc,
    "swapoff [-a] [device...]",
    0
};
