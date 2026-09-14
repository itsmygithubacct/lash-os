/* SPDX-License-Identifier: MIT */
/* whatis.c — whatis(1) over the whatis index.
 *
 * Sibling of man.c / apropos.c. Looks up exact-name matches
 * in $MANPATH/whatis. Exits 1 if the corpus's index is absent or
 * the name has no entry.
 *
 *   whatis NAME [NAME ...]
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

int
whatis_builtin (WORD_LIST *list)
{
    while (list && list->word && list->word->word[0] == '-' && list->word->word[1])
    {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "-h") || !strcmp (w, "--help"))
        {
            puts ("whatis NAME [NAME ...]");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-V") || !strcmp (w, "--version"))
        {
            puts ("whatis 0.1 (bash-os whatis lookup)");
            return EXECUTION_SUCCESS;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    if (!list || !list->word) { builtin_usage (); return EX_USAGE; }

    /* Buffer the index once and rewind per name so multiple lookups
       in a single invocation do not pay N reads. */
    FILE *f = bm_open_whatis ();
    if (!f)
    {
        builtin_error ("no whatis index found under $MANPATH (corpus may be absent)");
        return EXECUTION_FAILURE;
    }

    int any_hit = 0;
    for (WORD_LIST *p = list; p; p = p->next)
    {
        rewind (f);
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        int hit = 0;
        while ((n = getline (&line, &cap, f)) != -1)
        {
            if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
            if (bm_whatis_match (line, p->word->word, 1))
            {
                puts (line);
                hit = 1;
            }
        }
        free (line);
        if (hit) any_hit = 1;
        else
            fprintf (stderr, "%s: nothing appropriate\n", p->word->word);
    }
    fclose (f);
    return any_hit ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

char *whatis_doc[] = {
    "Display one-line manpage descriptions for NAME(s).",
    "",
    "    whatis NAME [NAME ...]",
    "",
    "Reads the whatis cache from $MANPATH (default /usr/share/man).",
    "Returns nonzero when no NAME has an entry or when the corpus's",
    "whatis index is missing.",
    (char *)NULL
};

struct builtin whatis_struct = {
    "whatis",
    whatis_builtin,
    BUILTIN_ENABLED,
    whatis_doc,
    "whatis NAME [NAME ...]",
    0
};
