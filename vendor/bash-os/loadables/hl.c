/* SPDX-License-Identifier: MIT */
/* hl.c - tree-sitter syntax highlighting wrapper.
 *
 * Stage 7 handoff required tree-sitter as multiple loadables:
 * ts owns parser/query primitives, while hl is the operator-facing
 * highlighter wrapper. The actual highlight engine lives in ts.c so
 * nano and hl share one SGR/capture implementation.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "loadables.h"

extern int bashts_highlight_fd (const char *lang_name, int span_mode, int fd);

static int
bhl_highlight_cmd (WORD_LIST *args)
{
    const char *lang = NULL;
    const char *path = NULL;
    int span_mode = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-L") && p->next) {
            p = p->next;
            lang = p->word->word;
        } else if (!strcmp (w, "-S")) {
            span_mode = 1;
        } else if (w[0] == '-' && w[1] != '\0') {
            builtin_error ("highlight: unknown option: %s", w);
            return EX_USAGE;
        } else if (!path) {
            path = w;
        } else {
            builtin_error ("highlight: too many file arguments");
            return EX_USAGE;
        }
    }

    if (!lang) {
        builtin_error ("highlight: -L LANG required");
        return EX_USAGE;
    }

    int fd = STDIN_FILENO;
    if (path) {
        fd = open (path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            builtin_error ("open %s: %s", path, strerror (errno));
            return EXECUTION_FAILURE;
        }
    }

    int rc = bashts_highlight_fd (lang, span_mode, fd);
    if (path)
        close (fd);
    return rc;
}

int
hl_builtin (WORD_LIST *list)
{
    if (list && list->word && list->word->word) {
        const char *w = list->word->word;
        if (!strcmp (w, "--help")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version")) {
            puts ("hl 1.0 (bash-os tree-sitter highlighter)");
            return EXECUTION_SUCCESS;
        }
    }
    return bhl_highlight_cmd (list);
}

char *hl_doc[] = {
    "tree-sitter syntax highlighting wrapper.",
    "",
    "    hl -L LANG [-S] [FILE]",
    "",
    "Reads FILE or stdin, runs the curated tree-sitter highlight query",
    "for LANG, and emits source with inline SGR escapes. With -S, emits",
    "span records: START-END SGR CAPTURE.",
    "Languages are the compiled-in ts languages.",
    (char *) NULL
};

struct builtin hl_struct = {
    "hl",
    hl_builtin,
    BUILTIN_ENABLED,
    hl_doc,
    "hl -L LANG [-S] [FILE]",
    0
};
