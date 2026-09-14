/* SPDX-License-Identifier: MIT */
/* fsfreeze.c — suspend or resume access to a filesystem, as a bash builtin
 * (util-linux fsfreeze).
 *
 *   fsfreeze -f | --freeze    MOUNTPOINT
 *   fsfreeze -u | --unfreeze  MOUNTPOINT
 *
 * Issues the FIFREEZE / FITHAW ioctls on the mountpoint's directory fd.
 * Requires CAP_SYS_ADMIN (root) and a filesystem that supports freezing.
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
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "loadables.h"

#ifndef FIFREEZE
#  define FIFREEZE _IOWR('X', 119, int)   /* freeze the filesystem */
#endif
#ifndef FITHAW
#  define FITHAW   _IOWR('X', 120, int)   /* thaw  the filesystem */
#endif

int
fsfreeze_builtin (WORD_LIST *list)
{
    int op = 0;   /* 'f' freeze, 'u' thaw */
    const char *mp = NULL;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { extern char *fsfreeze_doc[]; for (char **lp = fsfreeze_doc; *lp; lp++) puts (*lp); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "-f") || !strcmp (w, "--freeze"))   { op = 'f'; list = list->next; continue; }
        if (!strcmp (w, "-u") || !strcmp (w, "--unfreeze")) { op = 'u'; list = list->next; continue; }
        builtin_error ("unknown option: %s", w); builtin_usage (); return EX_USAGE;
    }
    if (list) { mp = list->word->word; list = list->next; }

    if (op == 0)  { builtin_error ("exactly one of --freeze or --unfreeze is required"); builtin_usage (); return EX_USAGE; }
    if (!mp)      { builtin_error ("a mountpoint is required"); builtin_usage (); return EX_USAGE; }

    struct stat st;
    if (stat (mp, &st) < 0) { builtin_error ("%s: %s", mp, strerror (errno)); return EXECUTION_FAILURE; }
    if (!S_ISDIR (st.st_mode)) { builtin_error ("%s: not a directory", mp); return EXECUTION_FAILURE; }

    int fd = open (mp, O_RDONLY);
    if (fd < 0) { builtin_error ("%s: %s", mp, strerror (errno)); return EXECUTION_FAILURE; }

    int rc = ioctl (fd, (op == 'f') ? FIFREEZE : FITHAW, 0);
    int e = errno;
    close (fd);
    if (rc < 0) {
        builtin_error ("%s: %s: %s", mp, (op == 'f') ? "freeze" : "unfreeze", strerror (e));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

char *fsfreeze_doc[] = {
    "Suspend or resume access to a filesystem.",
    "",
    "    fsfreeze -f | --freeze    MOUNTPOINT",
    "    fsfreeze -u | --unfreeze  MOUNTPOINT",
    "",
    "Uses the FIFREEZE / FITHAW ioctls; requires root and a freezable fs.",
    (char *) NULL
};

struct builtin fsfreeze_struct = {
    "fsfreeze",
    fsfreeze_builtin,
    BUILTIN_ENABLED,
    fsfreeze_doc,
    "fsfreeze {-f|-u} MOUNTPOINT",
    0
};
