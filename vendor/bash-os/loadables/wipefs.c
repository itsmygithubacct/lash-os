/* SPDX-License-Identifier: MIT */
/* wipefs.c — detect and (optionally) wipe filesystem/swap signatures.
 *
 *   wipefs device              # list detected signatures
 *   wipefs -a device           # erase all detected signatures
 *   wipefs -n device           # dry-run: show what -a would erase
 *
 * A pragmatic subset of util-linux wipefs(8): recognises the common magic
 * numbers (swap, ext2/3/4, xfs, btrfs, ntfs, vfat, iso9660). Works on a
 * regular file or a block device.
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

#include "loadables.h"

struct sig { const char *type; off_t offset; const char *magic; size_t len; };

/* Fixed-offset signatures. The swap signature (page-size dependent) is
   checked separately below. */
static const struct sig sigs[] = {
    { "xfs",     0,        "XFSB",            4  },
    { "ntfs",    3,        "NTFS    ",        8  },
    { "ext",     0x438,    "\x53\xef",        2  },  /* s_magic 0xEF53 LE */
    { "vfat",    0x52,     "FAT32   ",        8  },
    { "vfat",    0x36,     "FAT16   ",        8  },
    { "vfat",    0x36,     "FAT12   ",        8  },
    { "btrfs",   0x10040,  "_BHRfS_M",        8  },
    { "iso9660", 0x8001,   "CD001",           5  },
};
#define NSIGS (sizeof sigs / sizeof sigs[0])

static int
match_at (int fd, off_t off, const char *magic, size_t len)
{
    char buf[32];
    if (len > sizeof buf) return 0;
    if (pread (fd, buf, len, off) != (ssize_t) len) return 0;
    return memcmp (buf, magic, len) == 0;
}

int
wipefs_builtin (WORD_LIST *list)
{
    int do_wipe = 0, dry_run = 0;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { extern char *wipefs_doc[]; for (char **lp = wipefs_doc; *lp; lp++) puts (*lp); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "-a") || !strcmp (w, "--all"))    { do_wipe = 1; list = list->next; continue; }
        if (!strcmp (w, "-n") || !strcmp (w, "--no-act")) { dry_run = 1; list = list->next; continue; }
        builtin_error ("unknown option: %s", w); builtin_usage (); return EX_USAGE;
    }

    if (!list) { builtin_error ("no device specified"); builtin_usage (); return EX_USAGE; }

    /* swap signature lives in the last 10 bytes of the first page. */
    long ps = sysconf (_SC_PAGESIZE);
    off_t swap_off = (off_t) ps - 10;

    int rc = EXECUTION_SUCCESS;
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *dev = p->word->word;
        int flags = (do_wipe && !dry_run) ? O_RDWR : O_RDONLY;
        int fd = open (dev, flags);
        if (fd < 0) { builtin_error ("%s: %s", dev, strerror (errno)); rc = EXECUTION_FAILURE; continue; }

        int found = 0;

        /* swap (two historic magics). */
        for (int v = 0; v < 2; v++) {
            const char *m = v ? "SWAP-SPACE" : "SWAPSPACE2";
            if (match_at (fd, swap_off, m, 10)) {
                found++;
                printf ("0x%llx\tswap\t%s\n", (unsigned long long) swap_off, dev);
                if (do_wipe && !dry_run) {
                    char z[10] = {0};
                    if (pwrite (fd, z, 10, swap_off) != 10) { builtin_error ("%s: write: %s", dev, strerror (errno)); rc = EXECUTION_FAILURE; }
                }
            }
        }

        for (size_t i = 0; i < NSIGS; i++) {
            if (match_at (fd, sigs[i].offset, sigs[i].magic, sigs[i].len)) {
                found++;
                printf ("0x%llx\t%s\t%s\n", (unsigned long long) sigs[i].offset, sigs[i].type, dev);
                if (do_wipe && !dry_run) {
                    char z[16] = {0};
                    if (pwrite (fd, z, sigs[i].len, sigs[i].offset) != (ssize_t) sigs[i].len) { builtin_error ("%s: write: %s", dev, strerror (errno)); rc = EXECUTION_FAILURE; }
                }
            }
        }

        if (do_wipe && !dry_run) fsync (fd);
        close (fd);
        if (!found && !do_wipe) {
            /* match util-linux: silent when nothing is found, still success */
        }
    }
    return rc;
}

char *wipefs_doc[] = {
    "Detect or wipe filesystem / swap signatures.",
    "",
    "    wipefs device       list detected signatures (offset, type)",
    "    wipefs -a device    erase all detected signatures",
    "    wipefs -n device    dry-run: show what -a would erase",
    "",
    "Recognises swap, ext, xfs, btrfs, ntfs, vfat and iso9660 magics.",
    (char *) NULL
};

struct builtin wipefs_struct = {
    "wipefs",
    wipefs_builtin,
    BUILTIN_ENABLED,
    wipefs_doc,
    "wipefs [-a] [-n] device...",
    0
};
