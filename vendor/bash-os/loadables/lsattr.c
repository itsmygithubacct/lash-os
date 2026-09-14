/* SPDX-License-Identifier: MIT */
/* lsattr.c — list ext2/3/4 file attributes, as a bash builtin.
 *
 *   lsattr [-d] [-a] [-R] [file...]
 *
 *   -d   list a directory itself, not its contents
 *   -a   include entries whose name starts with '.'
 *   -R   recurse into directories
 *
 * Prints "FLAGS path" per file, where FLAGS is the lsattr letter string
 * (dashes for unset attributes). Reads FS_IOC_GETFLAGS.
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
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "loadables.h"

#ifndef FS_IOC_GETFLAGS
#  define FS_IOC_GETFLAGS _IOR('f', 1, long)
#endif

/* lsattr's fixed display order (e2fsprogs short form). */
static const struct { unsigned int bit; char ch; } lsattr_flagtab[] = {
    { 0x00000001u, 's' }, { 0x00000002u, 'u' }, { 0x00000008u, 'S' },
    { 0x00010000u, 'D' }, { 0x00000010u, 'i' }, { 0x00000020u, 'a' },
    { 0x00000040u, 'd' }, { 0x00000080u, 'A' }, { 0x00000004u, 'c' },
    { 0x00004000u, 'j' }, { 0x00008000u, 't' }, { 0x00020000u, 'T' },
    { 0x00080000u, 'e' }, { 0x00800000u, 'C' },
};
#define LSATTR_NFLAGS (sizeof lsattr_flagtab / sizeof lsattr_flagtab[0])

static int
format_flags (const char *path, char *out, size_t outsz)
{
    int fd = open (path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) return -1;
    unsigned int flags = 0;
    int rc = ioctl (fd, FS_IOC_GETFLAGS, &flags);
    close (fd);
    if (rc < 0) return -1;

    size_t n = 0;
    for (size_t i = 0; i < LSATTR_NFLAGS && n + 1 < outsz; i++)
        out[n++] = (flags & lsattr_flagtab[i].bit) ? lsattr_flagtab[i].ch : '-';
    out[n] = '\0';
    return 0;
}

static int
print_one (const char *path)
{
    char flags[32];
    if (format_flags (path, flags, sizeof flags) < 0) {
        builtin_error ("%s: %s", path, strerror (errno));
        return -1;
    }
    printf ("%s %s\n", flags, path);
    return 0;
}

static int list_path (const char *path, int dironly, int show_all, int recurse);

static int
list_dir_contents (const char *path, int show_all, int recurse)
{
    DIR *d = opendir (path);
    if (!d) { builtin_error ("%s: %s", path, strerror (errno)); return -1; }
    int rc = 0;
    struct dirent *de;
    while ((de = readdir (d))) {
        if (!strcmp (de->d_name, ".") || !strcmp (de->d_name, "..")) continue;
        if (!show_all && de->d_name[0] == '.') continue;
        char child[4096];
        snprintf (child, sizeof child, "%s/%s", path, de->d_name);
        if (print_one (child) < 0) rc = -1;
        if (recurse) {
            struct stat st;
            if (lstat (child, &st) == 0 && S_ISDIR (st.st_mode) && !S_ISLNK (st.st_mode))
                if (list_dir_contents (child, show_all, recurse) < 0) rc = -1;
        }
    }
    closedir (d);
    return rc;
}

static int
list_path (const char *path, int dironly, int show_all, int recurse)
{
    struct stat st;
    if (lstat (path, &st) < 0) { builtin_error ("%s: %s", path, strerror (errno)); return -1; }
    if (S_ISDIR (st.st_mode) && !dironly)
        return list_dir_contents (path, show_all, recurse);
    return print_one (path);
}

int
lsattr_builtin (WORD_LIST *list)
{
    int dironly = 0, show_all = 0, recurse = 0;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) {
            extern char *lsattr_doc[];
            for (char **lp = lsattr_doc; *lp; lp++) puts (*lp);
            return EXECUTION_SUCCESS;
        }
        int ok = 1;
        for (const char *c = w + 1; *c; c++) {
            switch (*c) {
                case 'd': dironly = 1; break;
                case 'a': show_all = 1; break;
                case 'R': recurse = 1; break;
                default: ok = 0; break;
            }
            if (!ok) break;
        }
        if (!ok) { builtin_error ("unknown option: %s", w); builtin_usage (); return EX_USAGE; }
        list = list->next;
    }

    int rc = EXECUTION_SUCCESS;
    if (!list) {
        if (list_path (".", dironly, show_all, recurse) < 0) rc = EXECUTION_FAILURE;
    } else {
        for (WORD_LIST *p = list; p; p = p->next)
            if (list_path (p->word->word, dironly, show_all, recurse) < 0)
                rc = EXECUTION_FAILURE;
    }
    return rc;
}

char *lsattr_doc[] = {
    "List file attributes on a Linux filesystem.",
    "",
    "    lsattr [-d] [-a] [-R] [file...]",
    "",
    "    -d  list a directory itself, not its contents",
    "    -a  include dot entries        -R  recurse into directories",
    "",
    "Prints the lsattr flag string (dashes for unset) and the path.",
    (char *) NULL
};

struct builtin lsattr_struct = {
    "lsattr",
    lsattr_builtin,
    BUILTIN_ENABLED,
    lsattr_doc,
    "lsattr [-d] [-a] [-R] [file...]",
    0
};
