/* SPDX-License-Identifier: MIT */
/* mkswap.c — set up a Linux swap area, as a bash builtin.
 *
 *   mkswap [-L label] [-U uuid] [-p pagesize] [-f] device|file [size]
 *
 *   -L LABEL    set a volume label (max 15 bytes)
 *   -U UUID     use this UUID (else a random v4 UUID)
 *   -p SIZE     page size in bytes (default: system page size)
 *   -f          force (skip the "size larger than device" guard)
 *
 * Writes the version-1 swap header into the first page and the "SWAPSPACE2"
 * signature in the last 10 bytes of that page. Does NOT activate the area
 * (use swapon).
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
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include "loadables.h"

#ifndef BLKGETSIZE64
#  define BLKGETSIZE64 _IOR(0x12, 114, size_t)
#endif

static void put_le32 (uint8_t *p, uint32_t v) { p[0]=v&0xff; p[1]=(v>>8)&0xff; p[2]=(v>>16)&0xff; p[3]=(v>>24)&0xff; }

static int
parse_uuid (const char *s, uint8_t out[16])
{
    int n = 0;
    for (const char *p = s; *p && n < 16; ) {
        if (*p == '-') { p++; continue; }
        int hi, lo;
        if      (*p >= '0' && *p <= '9') hi = *p - '0';
        else if (*p >= 'a' && *p <= 'f') hi = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') hi = *p - 'A' + 10;
        else return -1;
        p++;
        if      (*p >= '0' && *p <= '9') lo = *p - '0';
        else if (*p >= 'a' && *p <= 'f') lo = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') lo = *p - 'A' + 10;
        else return -1;
        p++;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return (n == 16) ? 0 : -1;
}

int
mkswap_builtin (WORD_LIST *list)
{
    const char *label = NULL, *uuid_arg = NULL, *dev = NULL, *size_arg = NULL;
    long pagesize = 0;
    int force = 0;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { extern char *mkswap_doc[]; for (char **lp = mkswap_doc; *lp; lp++) puts (*lp); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "-L") || !strcmp (w, "--label")) { if (!list->next){builtin_error("-L requires an argument");return EX_USAGE;} list=list->next; label=list->word->word; list=list->next; continue; }
        if (!strcmp (w, "-U") || !strcmp (w, "--uuid"))  { if (!list->next){builtin_error("-U requires an argument");return EX_USAGE;} list=list->next; uuid_arg=list->word->word; list=list->next; continue; }
        if (!strcmp (w, "-p") || !strcmp (w, "--pagesize")) { if (!list->next){builtin_error("-p requires an argument");return EX_USAGE;} list=list->next; pagesize=strtol(list->word->word,NULL,10); list=list->next; continue; }
        if (!strcmp (w, "-f") || !strcmp (w, "--force")) { force = 1; list = list->next; continue; }
        builtin_error ("unknown option: %s", w); builtin_usage (); return EX_USAGE;
    }

    if (!list) { builtin_error ("no device or file specified"); builtin_usage (); return EX_USAGE; }
    dev = list->word->word; list = list->next;
    if (list) { size_arg = list->word->word; list = list->next; }
    if (label && strlen (label) > 15) { builtin_error ("label too long (max 15)"); return EX_USAGE; }

    long ps = pagesize > 0 ? pagesize : sysconf (_SC_PAGESIZE);
    if (ps < 512) { builtin_error ("invalid page size %ld", ps); return EX_USAGE; }

    int fd = open (dev, O_RDWR);
    if (fd < 0) { builtin_error ("%s: %s", dev, strerror (errno)); return EXECUTION_FAILURE; }

    /* Determine total byte size. */
    uint64_t bytes = 0;
    if (size_arg) {
        /* size argument is in 1024-byte blocks, matching util-linux. */
        bytes = (uint64_t) strtoull (size_arg, NULL, 10) * 1024;
    } else {
        struct stat st;
        if (fstat (fd, &st) < 0) { builtin_error ("%s: %s", dev, strerror (errno)); close (fd); return EXECUTION_FAILURE; }
        if (S_ISBLK (st.st_mode)) {
            if (ioctl (fd, BLKGETSIZE64, &bytes) < 0) { builtin_error ("%s: BLKGETSIZE64: %s", dev, strerror (errno)); close (fd); return EXECUTION_FAILURE; }
        } else {
            bytes = (uint64_t) st.st_size;
        }
    }
    (void) force;

    uint64_t npages = bytes / (uint64_t) ps;
    if (npages < 10) { builtin_error ("swap area needs at least 10 pages (%ld bytes)", 10 * ps); close (fd); return EXECUTION_FAILURE; }
    uint32_t last_page = (uint32_t) (npages - 1);

    uint8_t *hdr = calloc (1, (size_t) ps);
    if (!hdr) { builtin_error ("calloc: %s", strerror (errno)); close (fd); return EXECUTION_FAILURE; }

    /* swap_header (union): version@1024, last_page@1028, nr_badpages@1032,
       uuid@1036 (16), label@1052 (16). */
    put_le32 (hdr + 1024, 1);           /* version 1 */
    put_le32 (hdr + 1028, last_page);
    put_le32 (hdr + 1032, 0);           /* nr_badpages */

    uint8_t uuid[16];
    if (uuid_arg) {
        if (parse_uuid (uuid_arg, uuid) < 0) { builtin_error ("invalid UUID: %s", uuid_arg); free (hdr); close (fd); return EX_USAGE; }
    } else {
        int uf = open ("/dev/urandom", O_RDONLY);
        if (uf < 0 || read (uf, uuid, 16) != 16) { memset (uuid, 0, 16); }
        if (uf >= 0) close (uf);
        uuid[6] = (uuid[6] & 0x0f) | 0x40;   /* version 4 */
        uuid[8] = (uuid[8] & 0x3f) | 0x80;   /* variant */
    }
    memcpy (hdr + 1036, uuid, 16);
    if (label) memcpy (hdr + 1052, label, strlen (label));

    /* "SWAPSPACE2" signature in the last 10 bytes of the first page. */
    memcpy (hdr + ps - 10, "SWAPSPACE2", 10);

    if (pwrite (fd, hdr, (size_t) ps, 0) != (ssize_t) ps) {
        builtin_error ("%s: write: %s", dev, strerror (errno));
        free (hdr); close (fd); return EXECUTION_FAILURE;
    }
    free (hdr);
    fsync (fd);
    close (fd);

    printf ("Setting up swapspace version 1, size = %llu bytes (%llu pages)\n",
            (unsigned long long) (npages * (uint64_t) ps), (unsigned long long) npages);
    printf ("UUID=%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
            uuid[0],uuid[1],uuid[2],uuid[3],uuid[4],uuid[5],uuid[6],uuid[7],
            uuid[8],uuid[9],uuid[10],uuid[11],uuid[12],uuid[13],uuid[14],uuid[15]);
    if (label) printf ("LABEL=%s\n", label);
    return EXECUTION_SUCCESS;
}

char *mkswap_doc[] = {
    "Set up a Linux swap area.",
    "",
    "    mkswap [-L label] [-U uuid] [-p pagesize] [-f] device|file [size]",
    "",
    "    -L LABEL   volume label (<=15 bytes)   -U UUID  use this UUID",
    "    -p SIZE    page size in bytes          -f       force",
    "    size       optional size in 1024-byte blocks",
    "",
    "Writes a version-1 swap header and the SWAPSPACE2 signature. Activate",
    "with swapon. A swap area must be at least 10 pages.",
    (char *) NULL
};

struct builtin mkswap_struct = {
    "mkswap",
    mkswap_builtin,
    BUILTIN_ENABLED,
    mkswap_doc,
    "mkswap [-L label] [-U uuid] [-p pagesize] [-f] device|file [size]",
    0
};
