/* SPDX-License-Identifier: MIT */
/* blockdev.c — call block-device ioctls, as a bash builtin.
 *
 *   blockdev [actions...] device [device...]
 *
 *   --getsz        size in 512-byte sectors
 *   --getsize64    size in bytes
 *   --getsize      size in 512-byte sectors (32-bit, deprecated)
 *   --getss        logical sector size (bytes)
 *   --getbsz       block size (bytes)
 *   --getro        1 if read-only, else 0
 *   --setro        set read-only
 *   --setrw        set read-write
 *   --flushbufs    flush buffers
 *   --rereadpt     re-read the partition table
 *
 * Actions are applied in order to each device argument.
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
#include <stdint.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include "loadables.h"

extern char *blockdev_doc[];

enum { A_GETSZ, A_GETSIZE64, A_GETSIZE, A_GETSS, A_GETBSZ, A_GETRO, A_SETRO, A_SETRW, A_FLUSH, A_REREAD };

static int
run_action (int fd, int act, const char *dev)
{
    switch (act) {
        case A_GETSZ: {
            uint64_t bytes = 0;
            if (ioctl (fd, BLKGETSIZE64, &bytes) < 0) goto err;
            printf ("%llu\n", (unsigned long long) (bytes / 512));
            return 0;
        }
        case A_GETSIZE64: {
            uint64_t bytes = 0;
            if (ioctl (fd, BLKGETSIZE64, &bytes) < 0) goto err;
            printf ("%llu\n", (unsigned long long) bytes);
            return 0;
        }
        case A_GETSIZE: {
            unsigned long s = 0;
            if (ioctl (fd, BLKGETSIZE, &s) < 0) goto err;
            printf ("%lu\n", s);
            return 0;
        }
        case A_GETSS: {
            int v = 0;
            if (ioctl (fd, BLKSSZGET, &v) < 0) goto err;
            printf ("%d\n", v);
            return 0;
        }
        case A_GETBSZ: {
            int v = 0;
            if (ioctl (fd, BLKBSZGET, &v) < 0) goto err;
            printf ("%d\n", v);
            return 0;
        }
        case A_GETRO: {
            int v = 0;
            if (ioctl (fd, BLKROGET, &v) < 0) goto err;
            printf ("%d\n", v ? 1 : 0);
            return 0;
        }
        case A_SETRO: { int v = 1; if (ioctl (fd, BLKROSET, &v) < 0) goto err; return 0; }
        case A_SETRW: { int v = 0; if (ioctl (fd, BLKROSET, &v) < 0) goto err; return 0; }
        case A_FLUSH:  if (ioctl (fd, BLKFLSBUF, 0) < 0) goto err; return 0;
        case A_REREAD: if (ioctl (fd, BLKRRPART, 0) < 0) goto err; return 0;
    }
    return 0;
err:
    builtin_error ("%s: ioctl: %s", dev, strerror (errno));
    return -1;
}

static int
action_number (const char *word)
{
    static const char *const options[] = {
        "--getsz", "--getsize64", "--getsize", "--getss", "--getbsz",
        "--getro", "--setro", "--setrw", "--flushbufs", "--rereadpt"
    };
    for (int i = 0; i < (int)(sizeof options / sizeof options[0]); i++)
        if (!strcmp (word, options[i])) return i;
    return -1;
}

static int
finish_output (int rc)
{
    if (fflush (stdout) == EOF || ferror (stdout)) {
        builtin_error ("write error: %s", strerror (errno));
        clearerr (stdout);
        return EXECUTION_FAILURE;
    }
    return rc;
}

int
blockdev_builtin (WORD_LIST *list)
{
    WORD_LIST *first_action = list;
    size_t nact = 0;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        else if (!strcmp (w, "--help")) { for (char **lp = blockdev_doc; *lp; lp++) puts (*lp); return finish_output (EXECUTION_SUCCESS); }
        else if (!strcmp (w, "--version")) { puts ("blockdev 1.0 (bash-loadable)"); return finish_output (EXECUTION_SUCCESS); }
        else if (action_number (w) < 0) {
            builtin_error ("unknown option: %s", w);
            builtin_usage ();
            return EX_USAGE;
        }
        nact++;
        list = list->next;
    }

    if (nact == 0) { builtin_error ("no action specified"); builtin_usage (); return EX_USAGE; }
    if (!list)     { builtin_error ("no device specified"); builtin_usage (); return EX_USAGE; }

    int rc = EXECUTION_SUCCESS;
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *dev = p->word->word;
        int fd = open (dev, O_RDONLY | O_CLOEXEC);
        if (fd < 0 && errno == EACCES) fd = open (dev, O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            builtin_error ("%s: %s", dev, strerror (errno));
            rc = EXECUTION_FAILURE;
            continue;
        }
        WORD_LIST *action = first_action;
        for (size_t i = 0; i < nact; i++, action = action->next)
            if (run_action (fd, action_number (action->word->word), dev) < 0)
                rc = EXECUTION_FAILURE;
        if (close (fd) < 0) {
            builtin_error ("%s: close: %s", dev, strerror (errno));
            rc = EXECUTION_FAILURE;
        }
    }
    return finish_output (rc);
}

char *blockdev_doc[] = {
    "Call block-device ioctls from the command line.",
    "",
    "    blockdev [actions...] device [device...]",
    "",
    "    --getsz       size in 512-byte sectors      --getsize64  size in bytes",
    "    --getsize     size in 512-byte sectors (legacy ioctl)",
    "    --getss       logical sector size            --getbsz     block size",
    "    --getro       read-only flag (1/0)            --setro/--setrw  set ro/rw",
    "    --flushbufs   flush buffers                   --rereadpt   re-read partitions",
    "",
    "Actions are applied in order to each device.",
    (char *) NULL
};

struct builtin blockdev_struct = {
    "blockdev",
    blockdev_builtin,
    BUILTIN_ENABLED,
    blockdev_doc,
    "blockdev [--getsz|--getsize64|--getsize|--getss|--getbsz|--getro|--setro|--setrw|--flushbufs|--rereadpt] device...",
    0
};
