/* SPDX-License-Identifier: MIT */
/* swapon.c — enable a swap area (and list active ones), as a bash builtin.
 *
 *   swapon                       # list active swap areas (/proc/swaps)
 *   swapon -s | --show           # same
 *   swapon [-p PRIO] [-d] device # enable a swap area (needs root)
 *
 *   -p PRIO   set the swap priority (0..32767)
 *   -d        discard freed pages where supported
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

#ifndef SWAP_FLAG_PREFER
#  define SWAP_FLAG_PREFER     0x8000
#endif
#ifndef SWAP_FLAG_PRIO_SHIFT
#  define SWAP_FLAG_PRIO_SHIFT 0
#endif
#ifndef SWAP_FLAG_DISCARD
#  define SWAP_FLAG_DISCARD    0x10000
#endif

static int
show_swaps (void)
{
    FILE *fp = fopen ("/proc/swaps", "r");
    if (!fp) { builtin_error ("/proc/swaps: %s", strerror (errno)); return EXECUTION_FAILURE; }
    char buf[1024];
    while (fgets (buf, sizeof buf, fp)) fputs (buf, stdout);
    fclose (fp);
    return EXECUTION_SUCCESS;
}

int
swapon_builtin (WORD_LIST *list)
{
    int prio = -1, discard = 0, show = 0;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { extern char *swapon_doc[]; for (char **lp = swapon_doc; *lp; lp++) puts (*lp); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "-s") || !strcmp (w, "--show") || !strcmp (w, "--summary")) { show = 1; list = list->next; continue; }
        if (!strcmp (w, "-d") || !strcmp (w, "--discard")) { discard = 1; list = list->next; continue; }
        if (!strcmp (w, "-p") || !strcmp (w, "--priority")) {
            if (!list->next) { builtin_error ("-p requires an argument"); return EX_USAGE; }
            list = list->next;
            char *end = NULL; long v = strtol (list->word->word, &end, 10);
            if (*end || v < 0 || v > 32767) { builtin_error ("invalid priority: %s", list->word->word); return EX_USAGE; }
            prio = (int) v; list = list->next; continue;
        }
        builtin_error ("unknown option: %s", w); builtin_usage (); return EX_USAGE;
    }

    if (show || !list)
        return show_swaps ();

    int flags = 0;
    if (prio >= 0)  flags |= SWAP_FLAG_PREFER | ((prio << SWAP_FLAG_PRIO_SHIFT) & 0x7fff);
    if (discard)    flags |= SWAP_FLAG_DISCARD;

    int rc = EXECUTION_SUCCESS;
    for (WORD_LIST *p = list; p; p = p->next) {
        if (swapon (p->word->word, flags) < 0) {
            builtin_error ("%s: %s", p->word->word, strerror (errno));
            rc = EXECUTION_FAILURE;
        }
    }
    return rc;
}

char *swapon_doc[] = {
    "Enable a swap area, or list the active ones.",
    "",
    "    swapon                  list active swap areas (/proc/swaps)",
    "    swapon -s               same as above",
    "    swapon [-p PRIO] [-d] device",
    "",
    "    -p PRIO  swap priority (0..32767)     -d  discard freed pages",
    "",
    "Enabling a swap area requires root.",
    (char *) NULL
};

struct builtin swapon_struct = {
    "swapon",
    swapon_builtin,
    BUILTIN_ENABLED,
    swapon_doc,
    "swapon [-s] [-p PRIO] [-d] [device...]",
    0
};
