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
#include <limits.h>
#include <sys/swap.h>

#include "loadables.h"

/* /proc/swaps uses five whitespace-separated fields, with seq_escape()'s
 * octal encoding for whitespace and backslashes in the filename. Never send
 * a truncated line, undecoded filename, or arbitrary first token to swapoff. */
static int
swapoff_fields (char *line, char **fields)
{
    int n = 0;
    char *save, *word = strtok_r (line, " \t\n", &save);
    while (word) {
        if (n == 5) return -1;
        fields[n++] = word;
        word = strtok_r (NULL, " \t\n", &save);
    }
    return n;
}

static int
swapoff_number (const char *s, unsigned long long *value)
{
    if (!*s) return 0;
    for (const char *p = s; *p; p++) if (*p < '0' || *p > '9') return 0;
    errno = 0;
    *value = strtoull (s, NULL, 10);
    return errno == 0;
}

static int
swapoff_row (char **fields)
{
    unsigned long long size, used, priority;
    const char *p = fields[4];
    int negative = *p == '-';
    if (negative) p++;
    if ((strcmp (fields[1], "file") && strcmp (fields[1], "partition")) ||
        !swapoff_number (fields[2], &size) ||
        !swapoff_number (fields[3], &used) || used > size ||
        !swapoff_number (p, &priority) ||
        priority > (unsigned long long) INT_MAX + negative)
        return 0;

    char *src = fields[0], *dst = src;
    if (*src != '/') return 0;
    while (*src) {
        if (*src != '\\') { *dst++ = *src++; continue; }
        /* Only escapes emitted by the kernel for this table are accepted.
         * Decode once: a literal "\\040" is represented as "\\134040". */
        if (!strncmp (src, "\\040", 4)) *dst++ = ' ';
        else if (!strncmp (src, "\\011", 4)) *dst++ = '\t';
        else if (!strncmp (src, "\\012", 4)) *dst++ = '\n';
        else if (!strncmp (src, "\\134", 4)) *dst++ = '\\';
        else return 0;
        src += 4;
    }
    *dst = 0;
    return 1;
}

static int
swapoff_all (void)
{
    FILE *fp = fopen ("/proc/swaps", "r");
    if (!fp) { builtin_error ("/proc/swaps: %s", strerror (errno)); return EXECUTION_FAILURE; }
    char *line = NULL, **paths = NULL;
    size_t capacity = 0, count = 0, allocated = 0, row = 0;
    ssize_t length;
    int rc = EXECUTION_SUCCESS, readable = 1;
    /* Finish and close the snapshot before making mutation requests. */
    while ((length = getline (&line, &capacity, fp)) >= 0) {
        char *fields[5];
        row++;
        int n = memchr (line, 0, (size_t) length) ? -1 : swapoff_fields (line, fields);
        if (row == 1) {
            if (n == 5 && !strcmp (fields[0], "Filename") &&
                !strcmp (fields[1], "Type") && !strcmp (fields[2], "Size") &&
                !strcmp (fields[3], "Used") && !strcmp (fields[4], "Priority"))
                continue;
            builtin_error ("/proc/swaps: invalid header");
            readable = 0; break;
        }
        if (n == 0) continue;
        if (n != 5 || !swapoff_row (fields)) {
            builtin_error ("/proc/swaps: malformed row %zu", row);
            rc = EXECUTION_FAILURE; continue;
        }
        size_t i;
        for (i = 0; i < count; i++) if (!strcmp (paths[i], fields[0])) break;
        if (i < count) continue;
        if (count == allocated) {
            size_t next = allocated ? allocated * 2 : 16;
            if (next < allocated || next > (size_t) -1 / sizeof *paths) {
                builtin_error ("/proc/swaps: too many entries");
                readable = 0; break;
            }
            char **grown = realloc (paths, next * sizeof *paths);
            if (!grown) { builtin_error ("out of memory"); readable = 0; break; }
            paths = grown; allocated = next;
        }
        paths[count] = strdup (fields[0]);
        if (!paths[count]) { builtin_error ("out of memory"); readable = 0; break; }
        count++;
    }
    if (!row || ferror (fp) || (readable && !feof (fp))) {
        builtin_error ("/proc/swaps: %s", row ? "read error" : "missing header");
        readable = 0;
    }
    if (fclose (fp) != 0) { builtin_error ("/proc/swaps: %s", strerror (errno)); readable = 0; }
    free (line);
    if (!readable) rc = EXECUTION_FAILURE;
    for (size_t i = 0; i < count; i++) {
        if (readable && swapoff (paths[i]) < 0) {
            builtin_error ("%s: %s", paths[i], strerror (errno)); rc = EXECUTION_FAILURE;
        }
        free (paths[i]);
    }
    free (paths);
    return rc;
}

int
swapoff_builtin (WORD_LIST *list)
{
    int all = 0;
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) {
            extern char *swapoff_doc[];
            for (char **lp = swapoff_doc; *lp; lp++) puts (*lp);
            return fflush (stdout) == 0 && !ferror (stdout) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
        }
        if (!strcmp (w, "-a") || !strcmp (w, "--all")) { all = 1; list = list->next; continue; }
        builtin_error ("unknown option: %s", w); builtin_usage (); return EX_USAGE;
    }

    if (all) {
        if (list) { builtin_error ("-a does not accept device operands"); return EX_USAGE; }
        return swapoff_all ();
    }
    if (!list) { builtin_error ("no device specified (or use -a)"); builtin_usage (); return EX_USAGE; }

    int rc = EXECUTION_SUCCESS;
    for (WORD_LIST *p = list; p; p = p->next) {
        if (!*p->word->word) { builtin_error ("empty device name"); rc = EXECUTION_FAILURE; continue; }
        if (swapoff (p->word->word) < 0) { builtin_error ("%s: %s", p->word->word, strerror (errno)); rc = EXECUTION_FAILURE; }
    }
    return rc;
}

char *swapoff_doc[] = {
    "Disable a swap area.",
    "",
    "    swapoff device...   disable the named swap areas",
    "    swapoff -a          disable every active swap area",
    "",
    "-a/--all reads /proc/swaps, decodes pathnames and skips duplicates.",
    "Malformed rows are reported and skipped; valid entries are still attempted.",
    "Named operands are literal paths; use -- before a name beginning with '-'.",
    "Returns 0 on success, 1 on any request/input failure, 2 for usage errors.",
    "-a cannot be combined with device operands.",
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
