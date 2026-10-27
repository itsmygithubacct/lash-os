/* SPDX-License-Identifier: MIT */
/* fincore.c — count pages of a file resident in the page cache, as a bash
 * builtin (util-linux fincore).
 *
 *   fincore [-b|--bytes] [-n|--noheadings] FILE...
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

struct fincore_row {
    const char *path;
    char res[64], pages[32], size[64];
};

/* util-linux's default units use powers of 1024 and one fractional digit,
   omitting a zero fraction. This is independent of the residency measurement. */
static void
fincore_size (char *out, size_t len, unsigned long long size, int bytes)
{
    if (bytes) { snprintf (out, len, "%llu", size); return; }
    static const char units[] = "BKMGTPE";
    long double value = size;
    int unit = 0;
    while (value >= 1024 && unit < 6) { value /= 1024; unit++; }
    if (!unit) snprintf (out, len, "%lluB", size);
    else {
        char number[48];
        snprintf (number, sizeof number, "%.1Lf", value);
        size_t n = strlen (number);
        if (n >= 2 && number[n - 2] == '.' && number[n - 1] == '0') number[n - 2] = 0;
        snprintf (out, len, "%s%c", number, units[unit]);
    }
}

static int
fincore_one (const char *path, long pagesize, int bytes, struct fincore_row *row)
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

    row->path = path;
    fincore_size (row->res, sizeof row->res, res_pages * (unsigned long long) pagesize, bytes);
    snprintf (row->pages, sizeof row->pages, "%llu", res_pages);
    fincore_size (row->size, sizeof row->size, size, bytes);
    return 0;
}

int
fincore_builtin (WORD_LIST *list)
{
    int headings = 1, bytes = 0;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { extern char *fincore_doc[]; for (char **lp = fincore_doc; *lp; lp++) puts (*lp); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "--noheadings")) headings = 0;
        else if (!strcmp (w, "--bytes")) bytes = 1;
        else if (w[1] != '-') {
            for (const char *c = w + 1; *c; c++) {
                if (*c == 'n') headings = 0;
                else if (*c == 'b') bytes = 1;
                else { builtin_error ("unknown option: -%c", *c); return EXECUTION_FAILURE; }
            }
        } else { builtin_error ("unknown option: %s", w); return EXECUTION_FAILURE; }
        list = list->next;
    }
    if (!list) { builtin_error ("no file specified"); builtin_usage (); return EXECUTION_FAILURE; }

    long pagesize = sysconf (_SC_PAGESIZE);
    if (pagesize <= 0) { builtin_error ("cannot determine page size"); return EXECUTION_FAILURE; }
    size_t capacity = 0, count = 0;
    for (WORD_LIST *p = list; p; p = p->next) capacity++;
    struct fincore_row *rows = calloc (capacity, sizeof *rows);
    if (!rows) { builtin_error ("out of memory"); return EXECUTION_FAILURE; }
    int rc = EXECUTION_SUCCESS;
    size_t res_width = 0, pages_width = headings ? 5 : 0, size_width = 0;
    for (WORD_LIST *p = list; p; p = p->next) {
        if (fincore_one (p->word->word, pagesize, bytes, &rows[count]) < 0) {
            rc = EXECUTION_FAILURE;
            continue;
        }
        size_t n = strlen (rows[count].res);
        if (n > res_width) res_width = n;
        n = strlen (rows[count].pages);
        if (n > pages_width) pages_width = n;
        n = strlen (rows[count].size);
        if (n > size_width) size_width = n;
        count++;
    }
    /* Numeric size columns have a five-character width hint. A heading
       wider than every value takes precedence over that hint. */
    if (headings && res_width < 3) res_width = 3;
    else if (res_width < 5) res_width = 5;
    if (headings && size_width < 4) size_width = 4;
    else if (size_width < 5) size_width = 5;
    if (count && headings)
        printf ("%*s %*s %*s FILE\n", (int)res_width, "RES", (int)pages_width, "PAGES", (int)size_width, "SIZE");
    for (size_t i = 0; i < count; i++)
        printf ("%*s %*s %*s %s\n", (int)res_width, rows[i].res,
                (int)pages_width, rows[i].pages, (int)size_width, rows[i].size, rows[i].path);
    free (rows);
    return ferror (stdout) ? EXECUTION_FAILURE : rc;
}

char *fincore_doc[] = {
    "Count pages of a file resident in core (the page cache).",
    "",
    "    fincore [-b|--bytes] [-n|--noheadings] FILE...",
    "",
    "Maps each FILE and uses mincore(2). Columns: RES PAGES SIZE FILE.",
    "Sizes use human-readable units by default; -b/--bytes prints bytes.",
    "Use -n/--noheadings to omit column headings.",
    (char *) NULL
};

struct builtin fincore_struct = {
    "fincore",
    fincore_builtin,
    BUILTIN_ENABLED,
    fincore_doc,
    "fincore [-b|--bytes] [-n|--noheadings] FILE...",
    0
};
