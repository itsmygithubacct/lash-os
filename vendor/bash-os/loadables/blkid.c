/* bashblkid.c — superblock + partition-table probe (blkid(8) subset).
 *
 *   bashblkid [-o FMT] [-s TAG] [DEV...]
 *   bashblkid -L LABEL                  # find device by label
 *   bashblkid -U UUID                   # find device by UUID
 *
 * Reads the first 128 KiB of each DEV (a regular file or a block
 * device), matches the byte ranges against a curated table of
 * filesystem and partition-table signatures, and prints
 *
 *     DEV: LABEL="x" UUID="y" TYPE="ext4" PTTYPE="gpt"
 *
 * Coverage:
 *   filesystems    ext2 / ext3 / ext4 / xfs / btrfs / f2fs / vfat /
 *                  ntfs / exfat / swap
 *   partition tbl  MBR (with ≥1 sane entry) / GPT (EFI PART)
 *
 * With no DEV the builtin walks /sys/class/block and probes each
 * /dev/NAME that has a corresponding block-special node or fixture file.
 *
 * Output formats (-o FMT):
 *   default   tag=val tag=val …            (mirror blkid(8) default)
 *   value     newline-separated values     (combine with -s TAG)
 *   export    TAG_NAME=VALUE per line      (shell-eval ready)
 *
 * -s TAG     restrict default/value output to the given TAG.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "loadables.h"

#define BBLK_PROBE_LEN (128 * 1024)
#define BBLK_LABEL_MAX 128
#define BBLK_UUID_MAX  40
#define BBLK_TYPE_MAX  16
#define BBLK_PT_MAX    8
#define BBLK_PATH_MAX  1024
#define BBLK_PARTLABEL_MAX 128

typedef struct {
    char label[BBLK_LABEL_MAX];
    char uuid[BBLK_UUID_MAX];
    char type[BBLK_TYPE_MAX];
    char pttype[BBLK_PT_MAX];
    char partlabel[BBLK_PARTLABEL_MAX];
    char partuuid[BBLK_UUID_MAX];
    char sec_type[BBLK_TYPE_MAX];
} bblk_info;

/* ---------------- helpers ----------------------------------------- */

static uint16_t
bblk_le16 (const unsigned char *p)
{
    return (uint16_t) p[0] | ((uint16_t) p[1] << 8);
}

static uint32_t
bblk_le32 (const unsigned char *p)
{
    return (uint32_t) p[0]
         | ((uint32_t) p[1] << 8)
         | ((uint32_t) p[2] << 16)
         | ((uint32_t) p[3] << 24);
}

static uint64_t
bblk_le64 (const unsigned char *p)
{
    return (uint64_t) bblk_le32 (p)
         | ((uint64_t) bblk_le32 (p + 4) << 32);
}

static const char *
bblk_sys_block_dir (void)
{
    const char *e = getenv ("BASHBLKID_SYS_BLOCK_DIR");
    return (e && *e) ? e : "/sys/class/block";
}

static const char *
bblk_dev_root (void)
{
    const char *e = getenv ("BASHBLKID_DEV_ROOT");
    return (e && *e) ? e : "/dev";
}

/* Trim trailing whitespace + NULs from a fixed-width string copy. */
static void
bblk_trim (char *s)
{
    size_t n = strlen (s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\0'))
        s[--n] = '\0';
}

/* Copy a fixed-length byte run into a NUL-terminated buffer, stopping
   at the first NUL byte and trimming trailing whitespace. */
static void
bblk_copy_fixed (char *dst, size_t dstlen, const unsigned char *src, size_t n)
{
    size_t i = 0;
    if (n + 1 > dstlen) n = dstlen - 1;
    for (i = 0; i < n; i++) {
        if (src[i] == 0) break;
        dst[i] = (char) src[i];
    }
    dst[i] = '\0';
    bblk_trim (dst);
}

/* Format a 16-byte big-endian UUID as canonical 36-char string. */
static void
bblk_uuid_be (char *out, const unsigned char *u)
{
    snprintf (out, BBLK_UUID_MAX,
              "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
              u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
              u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
}

/* Format a 16-byte GUID (GPT-style: first three fields little-endian). */
static void
bblk_uuid_gpt (char *out, const unsigned char *u)
{
    snprintf (out, BBLK_UUID_MAX,
              "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
              u[3], u[2], u[1], u[0], u[5], u[4], u[7], u[6],
              u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
}

static int
bblk_guid_zero (const unsigned char *u)
{
    for (int i = 0; i < 16; i++)
        if (u[i] != 0)
            return 0;
    return 1;
}

static void
bblk_copy_utf16le_ascii (char *dst, size_t dstlen,
                         const unsigned char *src, size_t nbytes)
{
    size_t di = 0;
    if (dstlen == 0) return;
    for (size_t i = 0; i + 1 < nbytes && di + 1 < dstlen; i += 2) {
        unsigned char lo = src[i];
        unsigned char hi = src[i + 1];
        if (lo == 0 && hi == 0) break;
        if (hi != 0 || lo < 0x20 || lo > 0x7e) {
            dst[di++] = '?';
            continue;
        }
        dst[di++] = (char) lo;
    }
    dst[di] = '\0';
    bblk_trim (dst);
}

/* Short FAT-style serial like "AB12-CD34" from 4 little-endian bytes. */
static void
bblk_serial4 (char *out, const unsigned char *u)
{
    snprintf (out, BBLK_UUID_MAX, "%02X%02X-%02X%02X",
              u[3], u[2], u[1], u[0]);
}

/* Short NTFS/exFAT serial — 8 hex chars (4 LE bytes). */
static void
bblk_serial8 (char *out, const unsigned char *u)
{
    snprintf (out, BBLK_UUID_MAX, "%02X%02X%02X%02X%02X%02X%02X%02X",
              u[7], u[6], u[5], u[4], u[3], u[2], u[1], u[0]);
}

/* ---------------- filesystem detectors ---------------------------- */

/* ext2/3/4 superblock starts at byte 1024. Distinguishing features:
   feature_compat (1024+0x5c), feature_incompat (1024+0x60),
   feature_ro_compat (1024+0x64). HAS_JOURNAL = 0x4 in compat selects
   ext3/4; EXTENTS = 0x40 in incompat selects ext4. */
static int
bblk_match_ext (const unsigned char *p, size_t n, bblk_info *out)
{
    if (n < 1024 + 0x100) return 0;
    const unsigned char *sb = p + 1024;
    /* s_magic at sb+0x38 */
    if (bblk_le16 (sb + 0x38) != 0xef53) return 0;

    uint32_t compat   = bblk_le32 (sb + 0x5c);
    uint32_t incompat = bblk_le32 (sb + 0x60);

    const char *t = "ext2";
    if (compat & 0x4) {
        t = (incompat & 0x40) ? "ext4" : "ext3";
    }
    strncpy (out->type, t, BBLK_TYPE_MAX - 1);
    out->type[BBLK_TYPE_MAX - 1] = '\0';
    if (strcmp (t, "ext3") == 0 || strcmp (t, "ext4") == 0) {
        strncpy (out->sec_type, "ext2", BBLK_TYPE_MAX - 1);
        out->sec_type[BBLK_TYPE_MAX - 1] = '\0';
    }

    /* uuid at sb+0x68 (16 bytes), label at sb+0x78 (16 bytes). */
    bblk_uuid_be (out->uuid, sb + 0x68);
    bblk_copy_fixed (out->label, BBLK_LABEL_MAX, sb + 0x78, 16);
    return 1;
}

/* xfs: "XFSB" at offset 0; uuid at offset 32 (16 B); label at offset
   108 (12 B). */
static int
bblk_match_xfs (const unsigned char *p, size_t n, bblk_info *out)
{
    if (n < 128) return 0;
    if (memcmp (p, "XFSB", 4) != 0) return 0;
    strncpy (out->type, "xfs", BBLK_TYPE_MAX - 1);
    out->type[BBLK_TYPE_MAX - 1] = '\0';
    bblk_uuid_be (out->uuid, p + 32);
    bblk_copy_fixed (out->label, BBLK_LABEL_MAX, p + 108, 12);
    return 1;
}

/* btrfs superblock begins at byte 65536. Magic "_BHRfS_M" lives at
   offset 64 inside the SB (i.e. file offset 65536+64). fsid at +32,
   label at +299 (256 bytes). */
static int
bblk_match_btrfs (const unsigned char *p, size_t n, bblk_info *out)
{
    if (n < 65536 + 0x300) return 0;
    const unsigned char *sb = p + 65536;
    if (memcmp (sb + 64, "_BHRfS_M", 8) != 0) return 0;
    strncpy (out->type, "btrfs", BBLK_TYPE_MAX - 1);
    out->type[BBLK_TYPE_MAX - 1] = '\0';
    bblk_uuid_be (out->uuid, sb + 32);
    bblk_copy_fixed (out->label, BBLK_LABEL_MAX, sb + 299, 256);
    return 1;
}

/* f2fs: little-endian magic 0xF2F52010 at file offset 1024 (+0).
   uuid at sb+108 (16 B). volume_name at sb+124 is UTF-16LE (512 chars);
   we transcribe the ASCII subset and stop at the first non-ASCII or
   NUL pair. */
static int
bblk_match_f2fs (const unsigned char *p, size_t n, bblk_info *out)
{
    if (n < 1024 + 512) return 0;
    const unsigned char *sb = p + 1024;
    if (bblk_le32 (sb) != 0xF2F52010u) return 0;
    strncpy (out->type, "f2fs", BBLK_TYPE_MAX - 1);
    out->type[BBLK_TYPE_MAX - 1] = '\0';
    bblk_uuid_be (out->uuid, sb + 108);
    /* UTF-16LE volume_name — extract ASCII run. */
    size_t li = 0;
    for (int i = 0; i < 64 && li + 1 < BBLK_LABEL_MAX; i++) {
        unsigned char lo = sb[124 + i * 2];
        unsigned char hi = sb[124 + i * 2 + 1];
        if (lo == 0 && hi == 0) break;
        if (hi != 0 || lo < 0x20 || lo > 0x7e) break;
        out->label[li++] = (char) lo;
    }
    out->label[li] = '\0';
    bblk_trim (out->label);
    return 1;
}

/* NTFS: "NTFS    " at offset 3. Magic 0x55 0xAA at offset 510.
   8-byte volume serial at offset 72. Labels live in the MFT (skip). */
static int
bblk_match_ntfs (const unsigned char *p, size_t n, bblk_info *out)
{
    if (n < 512) return 0;
    if (memcmp (p + 3, "NTFS    ", 8) != 0) return 0;
    if (p[510] != 0x55 || p[511] != 0xAA) return 0;
    strncpy (out->type, "ntfs", BBLK_TYPE_MAX - 1);
    out->type[BBLK_TYPE_MAX - 1] = '\0';
    bblk_serial8 (out->uuid, p + 72);
    return 1;
}

/* exFAT: "EXFAT   " at offset 3. Magic 0x55 0xAA at offset 510.
   Volume serial at offset 100 (4 bytes). */
static int
bblk_match_exfat (const unsigned char *p, size_t n, bblk_info *out)
{
    if (n < 512) return 0;
    if (memcmp (p + 3, "EXFAT   ", 8) != 0) return 0;
    if (p[510] != 0x55 || p[511] != 0xAA) return 0;
    strncpy (out->type, "exfat", BBLK_TYPE_MAX - 1);
    out->type[BBLK_TYPE_MAX - 1] = '\0';
    bblk_serial4 (out->uuid, p + 100);
    return 1;
}

/* VFAT (FAT12/16/32):
     boot signature 0x55 0xAA at offset 510
     for FAT12/16: BS_BootSig = 0x29 at offset 38, label at 43 (11 B),
                   serial at 39 (4 B), FS type at 54 (8 B "FAT16   ")
     for FAT32:    BS_BootSig = 0x29 at offset 66, label at 71 (11 B),
                   serial at 67 (4 B), FS type at 82 (8 B "FAT32   ") */
static int
bblk_match_vfat (const unsigned char *p, size_t n, bblk_info *out)
{
    if (n < 512) return 0;
    if (p[510] != 0x55 || p[511] != 0xAA) return 0;

    int is_fat32 = 0;
    if (p[66] == 0x29 && (memcmp (p + 82, "FAT32   ", 8) == 0
                          || memcmp (p + 82, "FAT     ", 8) == 0))
        is_fat32 = 1;

    /* Plausible BPB sector size + reserved sector count keeps this from
       false-matching MBRs that only have 0x55 0xAA without a BPB. */
    uint16_t bytes_per_sector = bblk_le16 (p + 11);
    uint16_t reserved = bblk_le16 (p + 14);
    if (!(bytes_per_sector == 512 || bytes_per_sector == 1024
          || bytes_per_sector == 2048 || bytes_per_sector == 4096))
        return 0;
    if (reserved == 0) return 0;

    if (is_fat32) {
        strncpy (out->type, "vfat", BBLK_TYPE_MAX - 1);
        out->type[BBLK_TYPE_MAX - 1] = '\0';
        bblk_serial4 (out->uuid, p + 67);
        bblk_copy_fixed (out->label, BBLK_LABEL_MAX, p + 71, 11);
        if (strcmp (out->label, "NO NAME") == 0)
            out->label[0] = '\0';
        return 1;
    }
    if (p[38] == 0x29) {
        strncpy (out->type, "vfat", BBLK_TYPE_MAX - 1);
        out->type[BBLK_TYPE_MAX - 1] = '\0';
        bblk_serial4 (out->uuid, p + 39);
        bblk_copy_fixed (out->label, BBLK_LABEL_MAX, p + 43, 11);
        if (strcmp (out->label, "NO NAME") == 0)
            out->label[0] = '\0';
        return 1;
    }
    return 0;
}

/* swap: "SWAPSPACE2" (v2) or "SWAP-SPACE" (v1) at file offset
   (PAGE_SIZE - 10). PAGE_SIZE for the swap header is whatever was in
   effect at swapon(2) time; commonly 4096 but can be 1024, 2048, 8192,
   16384, 32768, 65536. v1 has no UUID/label fields; v2 stores uuid at
   1036 and label at 1052 (regardless of page size — the swap header
   union lives in the first page). */
static int
bblk_match_swap (const unsigned char *p, size_t n, bblk_info *out)
{
    static const size_t page_sizes[] = {
        1024, 2048, 4096, 8192, 16384, 32768, 65536
    };
    int v2 = 0;
    int found = 0;
    for (size_t i = 0; i < sizeof page_sizes / sizeof page_sizes[0]; i++) {
        size_t off = page_sizes[i];
        if (off < 10 || off > n) continue;
        const unsigned char *q = p + off - 10;
        if (memcmp (q, "SWAPSPACE2", 10) == 0) { found = 1; v2 = 1; break; }
        if (memcmp (q, "SWAP-SPACE", 10) == 0) { found = 1; v2 = 0; break; }
    }
    if (!found) return 0;
    strncpy (out->type, "swap", BBLK_TYPE_MAX - 1);
    out->type[BBLK_TYPE_MAX - 1] = '\0';
    if (v2 && n >= 1052 + 16) {
        bblk_uuid_be (out->uuid, p + 1036);
        bblk_copy_fixed (out->label, BBLK_LABEL_MAX, p + 1052, 16);
    }
    return 1;
}

/* ---------------- partition-table detectors ---------------------- */

/* GPT primary header at LBA 1 (byte offset 512). Signature "EFI PART"
   at +0. Disk GUID at +56 (mixed-endian). */
static int
bblk_match_gpt (const unsigned char *p, size_t n, bblk_info *out)
{
    if (n < 512 + 92) return 0;
    if (memcmp (p + 512, "EFI PART", 8) != 0) return 0;
    strncpy (out->pttype, "gpt", BBLK_PT_MAX - 1);
    out->pttype[BBLK_PT_MAX - 1] = '\0';
    /* If FS UUID slot is empty, surface the disk GUID under PTUUID via
       the formatted output layer. We still emit a regular pttype line
       even if no fs is present. */
    if (out->uuid[0] == '\0')
        bblk_uuid_gpt (out->uuid, p + 512 + 56);
    return 1;
}

static int
bblk_match_gpt_partition (const unsigned char *p, size_t n, int partno,
                          bblk_info *out)
{
    if (partno <= 0) return 0;
    if (n < 512 + 92) return 0;
    if (memcmp (p + 512, "EFI PART", 8) != 0) return 0;
    uint64_t ents_lba = bblk_le64 (p + 512 + 72);
    uint32_t nents = bblk_le32 (p + 512 + 80);
    uint32_t entsz = bblk_le32 (p + 512 + 84);
    if (ents_lba == 0 || nents == 0 || entsz < 56 || entsz > 4096)
        return 0;
    if ((uint32_t) partno > nents)
        return 0;
    uint64_t off64 = ents_lba * 512ULL + (uint64_t) (partno - 1) * entsz;
    if (off64 + entsz > n)
        return 0;
    const unsigned char *e = p + off64;
    if (bblk_guid_zero (e) || bblk_guid_zero (e + 16))
        return 0;
    bblk_uuid_gpt (out->partuuid, e + 16);
    if (entsz > 56)
        bblk_copy_utf16le_ascii (out->partlabel, sizeof out->partlabel,
                                 e + 56, entsz - 56);
    return 1;
}

/* MBR fallback: 0x55 0xAA at offset 510 with at least one entry whose
   sys-id is not 0 and whose start_lba/size_lba look sane. Type 0xEE
   means a protective MBR (so GPT will already have set pttype). */
static int
bblk_match_mbr (const unsigned char *p, size_t n, bblk_info *out)
{
    if (n < 512) return 0;
    if (p[510] != 0x55 || p[511] != 0xAA) return 0;
    int saw = 0;
    int protective = 0;
    for (int i = 0; i < 4; i++) {
        const unsigned char *e = p + 446 + 16 * i;
        unsigned char sys = e[4];
        if (sys == 0) continue;
        uint32_t lba_start = bblk_le32 (e + 8);
        uint32_t lba_size  = bblk_le32 (e + 12);
        if (lba_size == 0) continue;
        if (lba_start == 0xffffffffu) continue;
        saw = 1;
        if (sys == 0xEE) protective = 1;
    }
    if (!saw) return 0;
    /* Protective MBR collapses into the GPT pttype set by bblk_match_gpt. */
    if (protective) return 0;
    if (out->pttype[0] == '\0') {
        strncpy (out->pttype, "dos", BBLK_PT_MAX - 1);
        out->pttype[BBLK_PT_MAX - 1] = '\0';
    }
    return 1;
}

/* ---------------- top-level probe + I/O --------------------------- */

/* Returns 1 if a filesystem signature was matched. Partition tables
   are recorded separately in info->pttype. */
static int
bblk_probe_buf (const unsigned char *buf, size_t n, bblk_info *info)
{
    /* Most specific first — btrfs uses a non-trivial offset so it's
       safe to probe early; ext/xfs/f2fs share the first 2 KiB but use
       disjoint magic constants. */
    int hit = 0;
    if (bblk_match_btrfs (buf, n, info)) hit = 1;
    else if (bblk_match_ext   (buf, n, info)) hit = 1;
    else if (bblk_match_xfs   (buf, n, info)) hit = 1;
    else if (bblk_match_f2fs  (buf, n, info)) hit = 1;
    else if (bblk_match_ntfs  (buf, n, info)) hit = 1;
    else if (bblk_match_exfat (buf, n, info)) hit = 1;
    else if (bblk_match_vfat  (buf, n, info)) hit = 1;
    else if (bblk_match_swap  (buf, n, info)) hit = 1;
    /* Partition tables run regardless of FS detection — a disk may
       host both an MBR and (rarely) a filesystem at offset 0; the
       former wins for PTTYPE, the latter for TYPE. */
    bblk_match_gpt (buf, n, info);
    bblk_match_mbr (buf, n, info);
    return hit;
}

/* Read up to BBLK_PROBE_LEN bytes from path. Returns # bytes read, or
   -1 on error (with errno). Block devices may return 0 (empty / no
   media); the caller treats 0 as "no signature". */
static ssize_t
bblk_read_probe (const char *path, unsigned char *buf)
{
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t total = 0;
    while (total < (ssize_t) BBLK_PROBE_LEN) {
        ssize_t r = read (fd, buf + total, BBLK_PROBE_LEN - (size_t) total);
        if (r < 0) {
            if (errno == EINTR) continue;
            int e = errno;
            close (fd);
            errno = e;
            return -1;
        }
        if (r == 0) break;
        total += r;
    }
    close (fd);
    return total;
}

static void
bblk_probe_gpt_partition_path (const char *parent_path, int partno, bblk_info *info)
{
    static unsigned char buf[BBLK_PROBE_LEN];
    if (!parent_path || !*parent_path || partno <= 0)
        return;
    ssize_t n = bblk_read_probe (parent_path, buf);
    if (n <= 0)
        return;
    bblk_match_gpt_partition (buf, (size_t) n, partno, info);
}

/* ---------------- output -------------------------------------------- */

/* Sanitize a value for export-format VAR=value: keep printable bytes,
   strip quotes and backslashes that would unbalance the assignment. */
static void
bblk_print_safe (const char *s)
{
    for (const char *c = s; *c; c++) {
        if (*c == '"' || *c == '\\') continue;
        if (*c < 0x20 || (unsigned char) *c > 0x7e) continue;
        fputc (*c, stdout);
    }
}

/* Emit one TAG="VALUE" pair (default + value formats). */
static void
bblk_emit_kv (const char *tag, const char *val, const char *only_tag,
              const char *fmt, int *count)
{
    if (val[0] == '\0') return;
    if (only_tag && strcmp (only_tag, tag) != 0) return;

    if (strcmp (fmt, "value") == 0) {
        if (*count > 0) putchar ('\n');
        bblk_print_safe (val);
        (*count)++;
        return;
    }
    if (strcmp (fmt, "export") == 0) {
        printf ("ID_FS_%s=", tag);
        bblk_print_safe (val);
        putchar ('\n');
        (*count)++;
        return;
    }
    /* default — every kv is preceded by one space (including the first
       so it lands one column after the "DEV:" header). */
    putchar (' ');
    printf ("%s=\"", tag);
    bblk_print_safe (val);
    putchar ('"');
    (*count)++;
}

static void
bblk_emit (const char *dev, const bblk_info *info, const char *only_tag,
           const char *fmt)
{
    int count = 0;
    if (strcmp (fmt, "value") != 0 && strcmp (fmt, "export") != 0) {
        printf ("%s:", dev);
        /* Insert one space after "DEV:" so the first kv lines up. */
        count = 0;  /* triggers a leading space on the first emit_kv */
        bblk_emit_kv ("LABEL",  info->label,  only_tag, fmt, &count);
        bblk_emit_kv ("UUID",   info->uuid,   only_tag, fmt, &count);
        bblk_emit_kv ("TYPE",   info->type,   only_tag, fmt, &count);
        bblk_emit_kv ("SEC_TYPE", info->sec_type, only_tag, fmt, &count);
        bblk_emit_kv ("PTTYPE", info->pttype, only_tag, fmt, &count);
        bblk_emit_kv ("PARTLABEL", info->partlabel, only_tag, fmt, &count);
        bblk_emit_kv ("PARTUUID", info->partuuid, only_tag, fmt, &count);
        putchar ('\n');
        return;
    }
    bblk_emit_kv ("LABEL",  info->label,  only_tag, fmt, &count);
    bblk_emit_kv ("UUID",   info->uuid,   only_tag, fmt, &count);
    bblk_emit_kv ("TYPE",   info->type,   only_tag, fmt, &count);
    bblk_emit_kv ("SEC_TYPE", info->sec_type, only_tag, fmt, &count);
    bblk_emit_kv ("PTTYPE", info->pttype, only_tag, fmt, &count);
    bblk_emit_kv ("PARTLABEL", info->partlabel, only_tag, fmt, &count);
    bblk_emit_kv ("PARTUUID", info->partuuid, only_tag, fmt, &count);
    if (count > 0) putchar ('\n');
}

/* ---------------- /sys/class/block enumeration -------------------- */

/* Walk /sys/class/block and call probe_one for each entry that maps to
   a /dev/<name> block-special node. Returns # devices visited. */
static int
bblk_read_sys_int (const char *base, const char *leaf, int *out)
{
    char path[BBLK_PATH_MAX];
    char buf[64];
    int n = snprintf (path, sizeof path, "%s/%s", base, leaf);
    if (n < 0 || (size_t) n >= sizeof path) return -1;
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t r = read (fd, buf, sizeof buf - 1);
    close (fd);
    if (r <= 0) return -1;
    buf[r] = '\0';
    char *end = NULL;
    long v = strtol (buf, &end, 10);
    if (end == buf || v < 0 || v > 65535) return -1;
    *out = (int) v;
    return 0;
}

static int
bblk_read_sys_parent (const char *base, char *out, size_t outsz)
{
    char path[BBLK_PATH_MAX];
    int n = snprintf (path, sizeof path, "%s/parent", base);
    if (n < 0 || (size_t) n >= sizeof path) return -1;
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t r = read (fd, out, outsz - 1);
    close (fd);
    if (r <= 0) return -1;
    out[r] = '\0';
    while (r > 0 && (out[r - 1] == '\n' || out[r - 1] == ' '
                  || out[r - 1] == '\t' || out[r - 1] == '\r'))
        out[--r] = '\0';
    return out[0] ? 0 : -1;
}

/* Walk /sys/class/block and call probe_one for each entry that maps to
   a /dev/<name> node. Fixture files under BASHBLKID_DEV_ROOT are accepted
   in addition to real block-special nodes so host tests can run unprivileged. */
static int
bblk_each_sys_block (int (*probe_one) (const char *dev, const char *parent_dev,
                                      int partno, void *ctx),
                     void *ctx)
{
    const char *sys_block = bblk_sys_block_dir ();
    const char *dev_root = bblk_dev_root ();
    DIR *d = opendir (sys_block);
    if (!d) return 0;
    int visited = 0;
    struct dirent *de;
    while ((de = readdir (d))) {
        if (de->d_name[0] == '.') continue;
        char path[BBLK_PATH_MAX];
        char sysent[BBLK_PATH_MAX];
        int pn = snprintf (path, sizeof path, "%s/%s", dev_root, de->d_name);
        int sn = snprintf (sysent, sizeof sysent, "%s/%s", sys_block, de->d_name);
        if (pn < 0 || (size_t) pn >= sizeof path || sn < 0 || (size_t) sn >= sizeof sysent)
            continue;
        struct stat st;
        if (lstat (path, &st) < 0) continue;
        if (!S_ISBLK (st.st_mode) && !S_ISREG (st.st_mode)) continue;
        int partno = 0;
        char parent[BBLK_PATH_MAX] = "";
        if (bblk_read_sys_int (sysent, "partition", &partno) == 0) {
            char parent_name[128];
            if (bblk_read_sys_parent (sysent, parent_name, sizeof parent_name) == 0)
                snprintf (parent, sizeof parent, "%s/%s", dev_root, parent_name);
        }
        visited++;
        if (probe_one (path, parent[0] ? parent : NULL, partno, ctx) < 0) {
            closedir (d);
            return -1;
        }
    }
    closedir (d);
    return visited;
}

/* ---------------- builtin --------------------------------------- */

typedef struct {
    const char *fmt;        /* "default" / "value" / "export" */
    const char *tag;        /* -s TAG */
    const char *find_label; /* -L LABEL */
    const char *find_uuid;  /* -U UUID */
    int any_match;          /* set by find_match_one when a hit lands */
} bblk_opts;

static int
bblk_probe_one_ex (const char *path, const char *parent_path, int partno,
                   bblk_opts *opt)
{
    static unsigned char buf[BBLK_PROBE_LEN];
    bblk_info info;
    memset (&info, 0, sizeof info);
    ssize_t n = bblk_read_probe (path, buf);
    if (n < 0) {
        builtin_error ("%s: %s", path, strerror (errno));
        return -1;
    }
    if (n == 0) {
        /* No media / empty file: gracefully omit. */
        return 0;
    }
    if (!bblk_probe_buf (buf, (size_t) n, &info) && info.pttype[0] == '\0') {
        /* No FS, no PT. A partition may still have GPT entry tags from
           its parent disk; populate those before deciding to omit. */
    }
    if (parent_path && partno > 0)
        bblk_probe_gpt_partition_path (parent_path, partno, &info);
    if (info.label[0] == '\0' && info.uuid[0] == '\0' && info.type[0] == '\0'
        && info.pttype[0] == '\0' && info.partlabel[0] == '\0'
        && info.partuuid[0] == '\0' && info.sec_type[0] == '\0')
        return 0;
    if (opt->find_label) {
        if (strcmp (info.label, opt->find_label) != 0) return 0;
        puts (path);
        opt->any_match = 1;
        return 0;
    }
    if (opt->find_uuid) {
        if (strcmp (info.uuid, opt->find_uuid) != 0) return 0;
        puts (path);
        opt->any_match = 1;
        return 0;
    }
    bblk_emit (path, &info, opt->tag, opt->fmt);
    opt->any_match = 1;
    return 0;
}

static int
bblk_probe_one (const char *path, bblk_opts *opt)
{
    return bblk_probe_one_ex (path, NULL, 0, opt);
}

static int
bblk_probe_one_ctx (const char *path, const char *parent_path, int partno, void *ctx)
{
    return bblk_probe_one_ex (path, parent_path, partno, (bblk_opts *) ctx);
}

int
blkid_builtin (WORD_LIST *list)
{
    bblk_opts opt = { "default", NULL, NULL, NULL, 0 };
    int n_pos = 0;
    const char *pos[256];

    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "--help") == 0) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--") == 0) {
            for (p = p->next; p; p = p->next) {
                if (n_pos < 256) pos[n_pos++] = p->word->word;
            }
            break;
        }
        if (strcmp (w, "-o") == 0) {
            if (!p->next) {
                builtin_error ("-o requires an argument");
                return EX_USAGE;
            }
            p = p->next;
            opt.fmt = p->word->word;
            if (strcmp (opt.fmt, "default") != 0
                && strcmp (opt.fmt, "value") != 0
                && strcmp (opt.fmt, "export") != 0) {
                builtin_error ("unknown -o format: %s (want default/value/export)",
                               opt.fmt);
                return EX_USAGE;
            }
            continue;
        }
        if (strcmp (w, "-s") == 0) {
            if (!p->next) { builtin_error ("-s requires TAG"); return EX_USAGE; }
            p = p->next;
            opt.tag = p->word->word;
            continue;
        }
        if (strcmp (w, "-L") == 0) {
            if (!p->next) { builtin_error ("-L requires LABEL"); return EX_USAGE; }
            p = p->next;
            opt.find_label = p->word->word;
            continue;
        }
        if (strcmp (w, "-U") == 0) {
            if (!p->next) { builtin_error ("-U requires UUID"); return EX_USAGE; }
            p = p->next;
            opt.find_uuid = p->word->word;
            continue;
        }
        if (w[0] == '-' && w[1] != '\0') {
            builtin_error ("unknown flag: %s", w);
            builtin_usage ();
            return EX_USAGE;
        }
        if (n_pos < 256) pos[n_pos++] = w;
    }

    if (opt.find_label && opt.find_uuid) {
        builtin_error ("-L and -U are mutually exclusive");
        return EX_USAGE;
    }

    if (n_pos > 0) {
        int rc = EXECUTION_SUCCESS;
        for (int i = 0; i < n_pos; i++) {
            if (bblk_probe_one (pos[i], &opt) < 0)
                rc = EXECUTION_FAILURE;
        }
        if ((opt.find_label || opt.find_uuid) && !opt.any_match)
            return 2;
        return rc;
    }

    int v = bblk_each_sys_block (bblk_probe_one_ctx, &opt);
    if (v < 0) return EXECUTION_FAILURE;
    if ((opt.find_label || opt.find_uuid) && !opt.any_match)
        return 2;
    return EXECUTION_SUCCESS;
}

char *blkid_doc[] = {
    "Probe filesystem and partition-table signatures (blkid).",
    "",
    "    bashblkid [-o FMT] [-s TAG] [DEV...]",
    "    bashblkid -L LABEL",
    "    bashblkid -U UUID",
    "",
    "Reads the first 128 KiB of each DEV and matches against ext2/3/4,",
    "xfs, btrfs, f2fs, vfat, ntfs, exfat, swap, MBR, and GPT signatures.",
    "Prints LABEL/UUID/TYPE/PTTYPE/PARTLABEL/PARTUUID/SEC_TYPE for matched devices.",
    "",
    "Output formats (-o FMT):",
    "    default   tag=val tag=val …",
    "    value     newline-separated values",
    "    export    ID_FS_TAG=value per line",
    "",
    "With no DEV the builtin walks /sys/class/block. Tests may override",
    "enumeration with BASHBLKID_SYS_BLOCK_DIR and BASHBLKID_DEV_ROOT.",
    "-L LABEL and -U UUID",
    "print the matching DEV path; exit 2 if nothing matched.",
    (char *)NULL
};

struct builtin bashblkid_struct = {
    "bashblkid",
    blkid_builtin,
    BUILTIN_ENABLED,
    blkid_doc,
    "bashblkid [-o FMT] [-s TAG] [-L LABEL | -U UUID] [DEV...]",
    0
};
