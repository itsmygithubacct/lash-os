/* SPDX-License-Identifier: MIT */
/* apropos.c — apropos(1) over the whatis index.
 *
 * Sibling of man.c. Reads $MANPATH/whatis and prints every line
 * whose name or description contains the pattern. SKIPs cleanly when
 * the corpus's index is not present (returns nonzero with a short
 * diagnostic) so the /bash-os/apropos.sh wrapper can degrade.
 *
 *   apropos PATTERN [PATTERN ...]
 *   apropos -w PATTERN      anchored word match
 *
 * --- LICENSE --- MIT, same boilerplate as man.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "loadables.h"

extern FILE *bm_open_whatis (void);
extern int   bm_whatis_match (const char *line, const char *needle, int exact);
extern char *apropos_doc[];

int
apropos_builtin (WORD_LIST *list)
{
    int word_match = 0;

    while (list && list->word && list->word->word[0] == '-' && list->word->word[1])
    {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "-w") || !strcmp (w, "--word"))
        {
            word_match = 1; list = list->next; continue;
        }
        if (!strcmp (w, "-h") || !strcmp (w, "--help"))
        {
            for (char **lp = apropos_doc; *lp; lp++)
                puts (*lp);
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-V") || !strcmp (w, "--version"))
        {
            puts ("apropos 0.1 (bash-os whatis search)");
            return EXECUTION_SUCCESS;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    if (!list || !list->word) { builtin_usage (); return EX_USAGE; }

    FILE *f = bm_open_whatis ();
    if (!f)
    {
        builtin_error ("no whatis index found under $MANPATH (corpus may be absent)");
        return EXECUTION_FAILURE;
    }

    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int hits = 0;
    while ((n = getline (&line, &cap, f)) != -1)
    {
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        int matched = 1;
        for (WORD_LIST *p = list; p; p = p->next)
        {
            if (!bm_whatis_match (line, p->word->word, word_match))
            {
                matched = 0; break;
            }
        }
        if (matched)
        {
            puts (line);
            hits++;
        }
    }
    free (line);
    fclose (f);
    return hits > 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

char *apropos_doc[] = {
    "Search the whatis index for manpages matching PATTERN.",
    "",
    "    apropos [-w] PATTERN [PATTERN ...]",
    "",
    "    -w   anchored word match (head of name); default is substring.",
    "",
    "Reads the whatis cache from $MANPATH (default /usr/share/man).",
    "Multiple PATTERNs AND together. Returns nonzero when nothing matches",
    "or when the corpus's whatis index is missing.",
    (char *)NULL
};

struct builtin apropos_struct = {
    "apropos",
    apropos_builtin,
    BUILTIN_ENABLED,
    apropos_doc,
    "apropos [-w] PATTERN [PATTERN ...]",
    0
};
