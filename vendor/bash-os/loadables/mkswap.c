/* SPDX-License-Identifier: MIT */
/* mkswap.c — set up a Linux swap area, as a bash builtin.
 *
 *   mkswap [-L label] [-U uuid] [-p pagesize] [-f] device|file [size]
 *
 *   -L LABEL    set a volume label (truncate to 15 bytes, with a warning)
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
#include <limits.h>
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
    if (strlen(s) != 36) return -1;
    int n = 0;
    for (const char *p = s; *p; ) {
        size_t offset = (size_t)(p - s);
        if (offset == 8 || offset == 13 || offset == 18 || offset == 23) {
            if (*p++ != '-') return -1;
            continue;
        }
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

static int
parse_number (const char *s, uint64_t *out)
{
    if (!*s) return -1;
    for (const char *p = s; *p; p++) if (*p < '0' || *p > '9') return -1;
    char *end;
    errno = 0;
    unsigned long long value = strtoull(s, &end, 10);
    if (errno || *end || value > UINT64_MAX) return -1;
    *out = (uint64_t)value;
    return 0;
}

/* IEC units, rounded to one fractional digit, omitting a zero fraction. */
static void
human_size (uint64_t bytes, char *out, size_t size)
{
    static const char *units[] = { "B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB" };
    uint64_t unit = 1;
    unsigned index = 0;
    while (index < 6 && bytes / unit >= 1024) { unit *= 1024; index++; }
    uint64_t whole = bytes / unit;
    uint64_t tenth = ((bytes % unit) * 10 + unit / 2) / unit;
    if (tenth == 10) { whole++; tenth = 0; }
    if (tenth) snprintf(out, size, "%llu.%llu %s", (unsigned long long)whole,
                        (unsigned long long)tenth, units[index]);
    else snprintf(out, size, "%llu %s", (unsigned long long)whole, units[index]);
}

int
mkswap_builtin (WORD_LIST *list)
{
    const char *label = NULL, *uuid_arg = NULL, *dev = NULL, *size_arg = NULL;
    uint64_t pagesize = 0;
    int force = 0;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { extern char *mkswap_doc[]; for (char **lp = mkswap_doc; *lp; lp++) puts (*lp); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "-L") || !strcmp (w, "--label")) { if (!list->next){builtin_error("-L requires an argument");return EXECUTION_FAILURE;} list=list->next; label=list->word->word; list=list->next; continue; }
        if (!strcmp (w, "-U") || !strcmp (w, "--uuid"))  { if (!list->next){builtin_error("-U requires an argument");return EXECUTION_FAILURE;} list=list->next; uuid_arg=list->word->word; list=list->next; continue; }
        if (!strcmp (w, "-p") || !strcmp (w, "--pagesize")) { if (!list->next){builtin_error("-p requires an argument");return EXECUTION_FAILURE;} list=list->next; if(parse_number(list->word->word, &pagesize) || !pagesize){builtin_error("invalid page size: %s",list->word->word);return EXECUTION_FAILURE;} list=list->next; continue; }
        if (!strcmp (w, "-f") || !strcmp (w, "--force")) { force = 1; list = list->next; continue; }
        builtin_error ("unknown option: %s", w); builtin_usage (); return EXECUTION_FAILURE;
    }

    if (!list) { builtin_error ("no device or file specified"); builtin_usage (); return EXECUTION_FAILURE; }
    dev = list->word->word; list = list->next;
    if (list) { size_arg = list->word->word; list = list->next; }
    if (list) { builtin_error("too many arguments"); return EXECUTION_FAILURE; }
    long system_page = pagesize ? 0 : sysconf(_SC_PAGESIZE);
    uint64_t ps = pagesize ? pagesize : system_page > 0 ? (uint64_t)system_page : 0;
    /* Keep the fixed header and trailing signature separate, and bound allocation.
       2048..65536 are accepted powers of two; only ordinary 4096-byte pages
       are currently qualified against util-linux. */
    if (ps < 2048 || ps > 65536 || (ps & (ps - 1)) || ps < 1068 + 10) {
        builtin_error("unsupported page size: %llu", (unsigned long long)ps);
        return EXECUTION_FAILURE;
    }
    uint64_t requested = 0;
    if (size_arg && (parse_number(size_arg, &requested) || requested > UINT64_MAX / 1024)) {
        builtin_error("invalid size: %s", size_arg); return EXECUTION_FAILURE;
    }
    uint8_t uuid[16];
    if (uuid_arg && parse_uuid(uuid_arg, uuid) < 0) {
        builtin_error("invalid UUID: %s", uuid_arg); return EXECUTION_FAILURE;
    }
    char stored_label[16] = {0};
    size_t label_size = label ? strlen(label) : 0;
    if (label_size > 15) label_size = 15;
    if (label) memcpy(stored_label, label, label_size);

    int fd = open (dev, O_RDWR);
    if (fd < 0) { builtin_error ("%s: %s", dev, strerror (errno)); return EXECUTION_FAILURE; }

    /* Determine total byte size. */
    uint64_t available = 0;
    {
        struct stat st;
        if (fstat (fd, &st) < 0) { builtin_error ("%s: %s", dev, strerror (errno)); close (fd); return EXECUTION_FAILURE; }
        if (S_ISBLK (st.st_mode)) {
            if (ioctl (fd, BLKGETSIZE64, &available) < 0) { builtin_error ("%s: BLKGETSIZE64: %s", dev, strerror (errno)); close (fd); return EXECUTION_FAILURE; }
        } else if (S_ISREG(st.st_mode) && st.st_size >= 0) {
            available = (uint64_t) st.st_size;
        } else {
            builtin_error("%s: not a regular file or block device", dev); close(fd); return EXECUTION_FAILURE;
        }
    }
    uint64_t bytes = size_arg ? requested * 1024 : available;
    if (!force && bytes > available) {
        builtin_error("requested size exceeds available file or device size"); close(fd); return EXECUTION_FAILURE;
    }

    uint64_t npages = bytes / (uint64_t) ps;
    if (npages < 10 || npages - 1 > UINT32_MAX) { builtin_error ("swap area must contain 10..4294967296 pages"); close (fd); return EXECUTION_FAILURE; }
    uint32_t last_page = (uint32_t) (npages - 1);

    uint8_t *hdr = calloc (1, (size_t) ps);
    if (!hdr) { builtin_error ("calloc: %s", strerror (errno)); close (fd); return EXECUTION_FAILURE; }

    /* swap_header (union): version@1024, last_page@1028, nr_badpages@1032,
       uuid@1036 (16), label@1052 (16). */
    put_le32 (hdr + 1024, 1);           /* version 1 */
    put_le32 (hdr + 1028, last_page);
    put_le32 (hdr + 1032, 0);           /* nr_badpages */

    if (!uuid_arg) {
        int uf = open ("/dev/urandom", O_RDONLY);
        if (uf < 0 || read (uf, uuid, 16) != 16) { memset (uuid, 0, 16); }
        if (uf >= 0) close (uf);
        uuid[6] = (uuid[6] & 0x0f) | 0x40;   /* version 4 */
        uuid[8] = (uuid[8] & 0x3f) | 0x80;   /* variant */
    }
    memcpy (hdr + 1036, uuid, 16);
    memcpy (hdr + 1052, stored_label, sizeof stored_label);

    /* "SWAPSPACE2" signature in the last 10 bytes of the first page. */
    memcpy (hdr + ps - 10, "SWAPSPACE2", 10);

    if (pwrite (fd, hdr, (size_t) ps, 0) != (ssize_t) ps) {
        builtin_error ("%s: write: %s", dev, strerror (errno));
        free (hdr); close (fd); return EXECUTION_FAILURE;
    }
    free (hdr);
    int failed = fsync(fd) < 0;
    if (close(fd) < 0) failed = 1;
    if (failed) { builtin_error("%s: flush or close failed", dev); return EXECUTION_FAILURE; }

    if (label && strlen(label) > 15) builtin_warning("Label was truncated.");
    uint64_t usable = (npages - 1) * ps;
    char human[64]; human_size(usable, human, sizeof human);
    printf ("Setting up swapspace version 1, size = %s (%llu bytes)\n", human,
            (unsigned long long)usable);
    if (*stored_label) printf("LABEL=%s, ", stored_label);
    else printf("no label, ");
    printf ("UUID=%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
            uuid[0],uuid[1],uuid[2],uuid[3],uuid[4],uuid[5],uuid[6],uuid[7],
            uuid[8],uuid[9],uuid[10],uuid[11],uuid[12],uuid[13],uuid[14],uuid[15]);
    return fflush(stdout) || ferror(stdout) ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
}

char *mkswap_doc[] = {
    "Set up a Linux swap area.",
    "",
    "    mkswap [-L label] [-U uuid] [-p pagesize] [-f] device|file [size]",
    "",
    "    -L LABEL   volume label (truncated to 15 bytes, with warning)",
    "    -U UUID    use this UUID (complete canonical hexadecimal form)",
    "    -p SIZE    page size in bytes          -f       force",
    "    size       optional size in 1024-byte blocks",
    "    pagesize   a power of two from 2048 to 65536 bytes",
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
