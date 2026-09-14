/* SPDX-License-Identifier: MIT */
/* hostid.c — POSIX hostid(1).
 *
 *   hostid               # print 32-bit host ID in hex (8 chars)
 *
 * Wraps gethostid(3), matching hostid(1): on Linux that is /etc/hostid,
 * or an address-derived value when that file is unset. Tests may set
 * BASHHOSTID_MACHINE_ID_PATH to a file of eight hex digits.
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include "loadables.h"

static int
bhid_read_machine_id (const char *path, unsigned long *out)
{
    FILE *fp;
    char buf[128];
    size_t n, i, ndigits;
    unsigned long id;

    if (path == 0 || *path == '\0')
        return 0;

    fp = fopen (path, "r");
    if (fp == 0)
        return 0;

    n = fread (buf, 1, sizeof (buf), fp);
    fclose (fp);
    if (n == 0)
        return 0;

    id = 0;
    ndigits = 0;
    for (i = 0; i < n && ndigits < 8; i++) {
        unsigned char ch = (unsigned char)buf[i];
        unsigned int v;

        if (ch == '\n' || ch == '\r')
            break;
        if (isspace (ch))
            continue;
        if (ch >= '0' && ch <= '9')
            v = (unsigned int)(ch - '0');
        else if (ch >= 'a' && ch <= 'f')
            v = (unsigned int)(ch - 'a' + 10);
        else if (ch >= 'A' && ch <= 'F')
            v = (unsigned int)(ch - 'A' + 10);
        else
            return 0;

        id = (id << 4) | v;
        ndigits++;
    }

    if (ndigits != 8)
        return 0;
    *out = id & 0xffffffffUL;
    return 1;
}

int
hostid_builtin (WORD_LIST *list)
{
    if (list && list->next == 0) {
        const char *w = list->word->word;
        if (strcmp (w, "--help") == 0 || strcmp (w, "-h") == 0) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--version") == 0 || strcmp (w, "-V") == 0) {
            puts ("hostid 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
    }

    if (list) {
        builtin_error ("hostid takes no arguments");
        builtin_usage ();
        return EX_USAGE;
    }
    const char *machine_id_path = getenv ("BASHHOSTID_MACHINE_ID_PATH");
    unsigned long id;

    if (bhid_read_machine_id (machine_id_path, &id)) {
        printf ("%08lx\n", id);
        return EXECUTION_SUCCESS;
    }

    id = (unsigned long)gethostid ();
    printf ("%08lx\n", id & 0xffffffffUL);
    return EXECUTION_SUCCESS;
}

char *hostid_doc[] = {
    "Print the 32-bit host ID (POSIX hostid).",
    "",
    "    hostid [--help|--version]",
    "",
    "Prints gethostid(3) as 8 lowercase hex chars, like hostid(1).",
    "BASHHOSTID_MACHINE_ID_PATH may name a test fixture of eight hex digits.",
    (char *)NULL
};

struct builtin hostid_struct = {
    "hostid",
    hostid_builtin,
    BUILTIN_ENABLED,
    hostid_doc,
    "hostid [--help|--version]",
    0
};
