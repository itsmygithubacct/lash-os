/* SPDX-License-Identifier: MIT */
/* chattr.c — change ext2/3/4 file attributes, as a bash builtin.
 *
 *   chattr [-R] [+-=]MODE file...
 *
 *   +flags   add the listed attributes
 *   -flags   remove the listed attributes
 *   =flags   set exactly the listed attributes
 *   -R       recurse into directories
 *
 * Flags: a(append) i(immutable) A(no-atime) d(no-dump) s(secure-delete)
 *        u(undeletable) S(sync) D(dirsync) c(compress) j(data-journal)
 *        t(no-tail-merge) T(top-of-dir) e(extents) C(no-COW)
 *
 * Uses the FS_IOC_GETFLAGS / FS_IOC_SETFLAGS ioctls. Note that i/a require
 * CAP_LINUX_IMMUTABLE, and many filesystems (tmpfs) don't support these at
 * all (the ioctl returns ENOTTY / EOPNOTSUPP).
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

/* Self-contained ioctl + flag definitions: musl's headers may not pull all of
   these in, and the numeric ABI is stable. */
#ifndef FS_IOC_GETFLAGS
#  define FS_IOC_GETFLAGS _IOR('f', 1, long)
#endif
#ifndef FS_IOC_SETFLAGS
#  define FS_IOC_SETFLAGS _IOW('f', 2, long)
#endif

static const struct { unsigned int bit; char ch; } chattr_flagtab[] = {
    { 0x00000001u, 's' }, /* SECRM   */
    { 0x00000002u, 'u' }, /* UNRM    */
    { 0x00000004u, 'c' }, /* COMPR   */
    { 0x00000008u, 'S' }, /* SYNC    */
    { 0x00000010u, 'i' }, /* IMMUTABLE */
    { 0x00000020u, 'a' }, /* APPEND  */
    { 0x00000040u, 'd' }, /* NODUMP  */
    { 0x00000080u, 'A' }, /* NOATIME */
    { 0x00004000u, 'j' }, /* JOURNAL_DATA */
    { 0x00008000u, 't' }, /* NOTAIL  */
    { 0x00010000u, 'D' }, /* DIRSYNC */
    { 0x00020000u, 'T' }, /* TOPDIR  */
    { 0x00080000u, 'e' }, /* EXTENT  */
    { 0x00800000u, 'C' }, /* NOCOW   */
};
#define CHATTR_NFLAGS (sizeof chattr_flagtab / sizeof chattr_flagtab[0])

static int
char_to_bit (char c, unsigned int *bit)
{
    for (size_t i = 0; i < CHATTR_NFLAGS; i++)
        if (chattr_flagtab[i].ch == c) { *bit = chattr_flagtab[i].bit; return 0; }
    return -1;
}

static int
apply_to_path (const char *path, char op, unsigned int mask, int recurse);

static int
apply_one (const char *path, char op, unsigned int mask)
{
    int fd = open (path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) { builtin_error ("%s: %s", path, strerror (errno)); return -1; }

    unsigned int flags = 0;
    if (ioctl (fd, FS_IOC_GETFLAGS, &flags) < 0) {
        builtin_error ("%s: reading flags: %s", path, strerror (errno));
        close (fd);
        return -1;
    }
    unsigned int newflags = flags;
    if      (op == '+') newflags |= mask;
    else if (op == '-') newflags &= ~mask;
    else /* '=' */      newflags = mask;

    if (newflags != flags) {
        if (ioctl (fd, FS_IOC_SETFLAGS, &newflags) < 0) {
            builtin_error ("%s: setting flags: %s", path, strerror (errno));
            close (fd);
            return -1;
        }
    }
    close (fd);
    return 0;
}

static int
apply_to_path (const char *path, char op, unsigned int mask, int recurse)
{
    int rc = apply_one (path, op, mask);

    if (recurse) {
        struct stat st;
        if (lstat (path, &st) == 0 && S_ISDIR (st.st_mode)) {
            DIR *d = opendir (path);
            if (d) {
                struct dirent *de;
                while ((de = readdir (d))) {
                    if (!strcmp (de->d_name, ".") || !strcmp (de->d_name, ".."))
                        continue;
                    char child[4096];
                    snprintf (child, sizeof child, "%s/%s", path, de->d_name);
                    if (apply_to_path (child, op, mask, recurse) < 0) rc = -1;
                }
                closedir (d);
            }
        }
    }
    return rc;
}

int
chattr_builtin (WORD_LIST *list)
{
    int recurse = 0;
    char op = 0;
    unsigned int mask = 0;

    while (list) {
        const char *w = list->word->word;
        if (!strcmp (w, "--help")) {
            extern char *chattr_doc[];
            for (char **lp = chattr_doc; *lp; lp++) puts (*lp);
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-R") || !strcmp (w, "--recursive")) { recurse = 1; list = list->next; continue; }
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (w[0] == '+' || w[0] == '-' || w[0] == '=') {
            /* A flag-spec token. (A bare "-" with no following letters is not
               valid here; "-R" was handled above.) */
            if (w[0] == '-' && w[1] == '\0') break;
            op = w[0];
            for (const char *c = w + 1; *c; c++) {
                unsigned int bit;
                if (char_to_bit (*c, &bit) < 0) {
                    builtin_error ("unknown attribute: %c", *c);
                    return EX_USAGE;
                }
                mask |= bit;
            }
            list = list->next;
            continue;
        }
        break;  /* first non-option, non-flagspec token → start of file list */
    }

    if (op == 0) {
        builtin_error ("missing +-= attribute specification");
        builtin_usage ();
        return EX_USAGE;
    }
    if (!list) {
        builtin_error ("no files specified");
        builtin_usage ();
        return EX_USAGE;
    }

    int rc = EXECUTION_SUCCESS;
    for (WORD_LIST *p = list; p; p = p->next)
        if (apply_to_path (p->word->word, op, mask, recurse) < 0)
            rc = EXECUTION_FAILURE;
    return rc;
}

char *chattr_doc[] = {
    "Change file attributes on a Linux filesystem.",
    "",
    "    chattr [-R] [+-=]MODE file...",
    "",
    "    +flags  add attributes      -flags  remove attributes",
    "    =flags  set exactly         -R      recurse into directories",
    "",
    "Flags: a append, i immutable, A no-atime, d no-dump, s secure-delete,",
    "       u undeletable, S sync, D dirsync, c compress, j data-journal,",
    "       t no-tail, T top-of-dir, e extents, C no-COW.",
    "i and a require CAP_LINUX_IMMUTABLE; some filesystems support no flags.",
    (char *) NULL
};

struct builtin chattr_struct = {
    "chattr",
    chattr_builtin,
    BUILTIN_ENABLED,
    chattr_doc,
    "chattr [-R] [+-=]MODE file...",
    0
};
