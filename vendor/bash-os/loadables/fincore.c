/* SPDX-License-Identifier: MIT */
/* fincore.c — count pages of a file resident in the page cache, as a bash
 * builtin (util-linux fincore).
 *
 *   fincore [-n|--noheadings] FILE...
 *
 * For each FILE, maps it and calls mincore(2) to report how many pages are
 * currently cached in RAM. Columns: RES PAGES SIZE FILE  (resident bytes,
 * resident pages, total size, name).
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
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "loadables.h"

static int
fincore_one (const char *path, long pagesize)
{
    int fd = open (path, O_RDONLY);
    if (fd < 0) { builtin_error ("%s: %s", path, strerror (errno)); return -1; }

    struct stat st;
    if (fstat (fd, &st) < 0) { builtin_error ("%s: %s", path, strerror (errno)); close (fd); return -1; }

    unsigned long long size = (unsigned long long) st.st_size;
    unsigned long long pages = 0, res_pages = 0;

    if (size > 0 && S_ISREG (st.st_mode)) {
        pages = (size + (unsigned long long) pagesize - 1) / (unsigned long long) pagesize;
        void *addr = mmap (NULL, (size_t) size, PROT_READ, MAP_SHARED, fd, 0);
        if (addr == MAP_FAILED) {
            builtin_error ("%s: mmap: %s", path, strerror (errno)); close (fd); return -1;
        }
        unsigned char *vec = malloc ((size_t) pages);
        if (!vec) { builtin_error ("malloc: %s", strerror (errno)); munmap (addr, size); close (fd); return -1; }
        if (mincore (addr, (size_t) size, vec) < 0) {
            builtin_error ("%s: mincore: %s", path, strerror (errno));
            free (vec); munmap (addr, size); close (fd); return -1;
        }
        for (unsigned long long i = 0; i < pages; i++)
            if (vec[i] & 1) res_pages++;
        free (vec);
        munmap (addr, size);
    }
    close (fd);

    printf ("%11llu %5llu %11llu %s\n",
            res_pages * (unsigned long long) pagesize, res_pages, size, path);
    return 0;
}

int
fincore_builtin (WORD_LIST *list)
{
    int headings = 1;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { extern char *fincore_doc[]; for (char **lp = fincore_doc; *lp; lp++) puts (*lp); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "-n") || !strcmp (w, "--noheadings")) { headings = 0; list = list->next; continue; }
        if (!strcmp (w, "-b") || !strcmp (w, "--bytes")) { list = list->next; continue; }  /* accepted */
        builtin_error ("unknown option: %s", w); builtin_usage (); return EX_USAGE;
    }
    if (!list) { builtin_error ("no file specified"); builtin_usage (); return EX_USAGE; }

    long pagesize = sysconf (_SC_PAGESIZE);
    if (headings) printf ("%11s %5s %11s %s\n", "RES", "PAGES", "SIZE", "FILE");

    int rc = EXECUTION_SUCCESS;
    for (WORD_LIST *p = list; p; p = p->next)
        if (fincore_one (p->word->word, pagesize) < 0) rc = EXECUTION_FAILURE;
    return rc;
}

char *fincore_doc[] = {
    "Count pages of a file resident in core (the page cache).",
    "",
    "    fincore [-n|--noheadings] FILE...",
    "",
    "Maps each FILE and uses mincore(2). Columns: RES PAGES SIZE FILE.",
    (char *) NULL
};

struct builtin fincore_struct = {
    "fincore",
    fincore_builtin,
    BUILTIN_ENABLED,
    fincore_doc,
    "fincore [-n] FILE...",
    0
};
