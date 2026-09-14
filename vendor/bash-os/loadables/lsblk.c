/* bashlsblk.c — list block devices walking /sys/class/block.
 *
 *   bashlsblk [-l] [-d] [-f] [-n] [-P|-r] [-o LIST] [DEV ...]
 *
 *   default      tree form — disks first, partitions indented under them
 *   -l           list form — flat, disks and partitions printed alike
 *   -d           nodeps    — disks only, partitions suppressed
 *   -f           --fs      — emit FSTYPE column by probing matching
 *                            /dev/<NAME> nodes for known superblocks
 *   DEV          restrict output to the named device(s). DEV may be a
 *                bare basename (`vda`), a /dev path (`/dev/vda`), or a
 *                /sys path; the trailing component is what matches.
 *
 * v1 scope (ML-T1-05, paired with bashblkid):
 *   - Enumerates /sys/class/block (the canonical "every kobject with a
 *     block major:minor" view).
 *   - Reads NAME, MAJ:MIN (sys/dev), SIZE (sys/size, 512-byte sectors),
 *     RO (sys/ro), TYPE (disk / part / loop / ram / dm / md inferred
 *     from name + the `partition` file's presence), and a bounded
 *     Debian-shaped column set via -o.
 *   - Builds parent->children edges by inspecting each entry's
 *     `/sys/class/block/<name>` symlink target: a partition's resolved
 *     path ends in `…/block/<DISK>/<NAME>`, so the parent disk name is
 *     the second-to-last path component.
 *   - Tree form indents partitions under their parent disk.
 *
 * v1 does NOT do:
 *   - lvm / dm-crypt / md / loop topology beyond the simple parent map.
 *   - JSON / full util-linux column vocabulary / topology sorting.
 *   - Full blkid tag output. -f surfaces filesystem type only.
 *
 * Exit codes (subset of lsblk(8) convention):
 *   0    success
 *   1    operational error (open/read failure under /sys)
 *   2    usage error
 *   32   no matching devices when DEV operand given
 *
 * Source counterparts:
 *   research/refs/busybox/util-linux/lsblk.c   (382 LoC — minimal
 *      reference; same /sys-walk-then-print structure we use here)
 *   research/refs/util-linux/lsblk-cmd/lsblk.c (2909 LoC — canonical
 *      reference, used for column-set ordering)
 *
 * --- LICENSE --- MIT, same boilerplate as bashfsck.c / bashblkid.c.
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
#include <sys/statvfs.h>
#include <sys/types.h>

#include "loadables.h"

#define BLB_MAX_DEVS    256
#define BLB_NAME_MAX    64
#define BLB_PARENT_MAX  64
#define BLB_MAJMIN_MAX  16
#define BLB_TYPE_MAX    8
#define BLB_FSTYPE_MAX  16
#define BLB_FSVER_MAX   16
#define BLB_LABEL_MAX   128
#define BLB_UUID_MAX    40
#define BLB_MOUNT_MAX   256
#define BLB_PARTLABEL_MAX 128
#define BLB_PATH_MAX    1024
#define BLB_PROBE_LEN   (128 * 1024)
#define BLB_COL_MAX     32

typedef struct {
    char     name[BLB_NAME_MAX];
    char     parent[BLB_PARENT_MAX];     /* "" for top-level disks */
    char     majmin[BLB_MAJMIN_MAX];     /* "MAJ:MIN" or "?" */
    char     type[BLB_TYPE_MAX];         /* disk / part / loop / ram / dm / md */
    char     fstype[BLB_FSTYPE_MAX];     /* ext4 / vfat / ... or "" */
    char     fsver[BLB_FSVER_MAX];
    char     label[BLB_LABEL_MAX];
    char     uuid[BLB_UUID_MAX];
    char     mountpoint[BLB_MOUNT_MAX];
    char     partlabel[BLB_PARTLABEL_MAX];
    char     partuuid[BLB_UUID_MAX];
    uint64_t fsavail;
    int      fsuse_pct;
    uint64_t size_bytes;                 /* size-in-sectors × 512 */
    int      ro;                         /* 1 if /sys/.../ro reads "1" */
    int      removable;                  /* 1 if /sys/.../removable reads "1" */
    int      hidden;                     /* 1 if /sys/.../hidden reads "1" — skipped */
} blb_dev;

typedef enum {
    BLB_COL_NAME,
    BLB_COL_MAJMIN,
    BLB_COL_RM,
    BLB_COL_SIZE,
    BLB_COL_RO,
    BLB_COL_TYPE,
    BLB_COL_FSTYPE,
    BLB_COL_FSVER,
    BLB_COL_LABEL,
    BLB_COL_UUID,
    BLB_COL_PARTLABEL,
    BLB_COL_PARTUUID,
    BLB_COL_MOUNTPOINT,
    BLB_COL_FSAVAIL,
    BLB_COL_FSUSE_PCT
} blb_col_id;

typedef struct {
    const char *name;
    blb_col_id id;
} blb_col_def;

static const blb_col_def blb_cols[] = {
    { "NAME",       BLB_COL_NAME },
    { "MAJ:MIN",    BLB_COL_MAJMIN },
    { "RM",         BLB_COL_RM },
    { "SIZE",       BLB_COL_SIZE },
    { "RO",         BLB_COL_RO },
    { "TYPE",       BLB_COL_TYPE },
    { "FSTYPE",     BLB_COL_FSTYPE },
    { "FSVER",      BLB_COL_FSVER },
    { "LABEL",      BLB_COL_LABEL },
    { "UUID",       BLB_COL_UUID },
    { "PARTLABEL",  BLB_COL_PARTLABEL },
    { "PARTUUID",   BLB_COL_PARTUUID },
    { "MOUNTPOINT", BLB_COL_MOUNTPOINT },
    { "MOUNTPOINTS", BLB_COL_MOUNTPOINT },
    { "FSAVAIL",    BLB_COL_FSAVAIL },
    { "FSUSE%",     BLB_COL_FSUSE_PCT },
    { NULL, 0 }
};

static const char *
blb_sys_block_dir (void)
{
    const char *e = getenv ("BASHLSBLK_SYS_BLOCK_DIR");
    return (e && *e) ? e : "/sys/class/block";
}

static const char *
blb_dev_root (void)
{
    const char *e = getenv ("BASHLSBLK_DEV_ROOT");
    return (e && *e) ? e : "/dev";
}

static const char *
blb_proc_mounts (void)
{
    const char *e = getenv ("BASHLSBLK_PROC_MOUNTS");
    return (e && *e) ? e : "/proc/mounts";
}

static int
blb_join2 (char *out, size_t outsz, const char *a, const char *b)
{
    int n = snprintf (out, outsz, "%s/%s", a, b);
    return (n < 0 || (size_t) n >= outsz) ? -1 : 0;
}

/* ---------- read helpers ---------- */

static int
blb_read_str (const char *base, const char *leaf, char *out, size_t outsz)
{
    char path[BLB_PATH_MAX];
    int n = snprintf (path, sizeof path, "%s/%s", base, leaf);
    if (n < 0 || (size_t) n >= sizeof path) return -1;
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t r = read (fd, out, outsz - 1);
    close (fd);
    if (r < 0) return -1;
    out[r] = '\0';
    /* trim trailing newline + whitespace */
    while (r > 0 && (out[r - 1] == '\n' || out[r - 1] == ' '
                  || out[r - 1] == '\t' || out[r - 1] == '\r')) {
        out[--r] = '\0';
    }
    return 0;
}

static int
blb_read_int (const char *base, const char *leaf, long long *out)
{
    char buf[64];
    if (blb_read_str (base, leaf, buf, sizeof buf) < 0) return -1;
    char *end = NULL;
    errno = 0;
    long long v = strtoll (buf, &end, 10);
    if (errno != 0 || end == buf) return -1;
    *out = v;
    return 0;
}

static int
blb_exists (const char *base, const char *leaf)
{
    char path[BLB_PATH_MAX];
    int n = snprintf (path, sizeof path, "%s/%s", base, leaf);
    if (n < 0 || (size_t) n >= sizeof path) return 0;
    struct stat st;
    return (stat (path, &st) == 0);
}

/* ---------- classification ---------- */

/* Resolve /sys/class/block/<name> and pick the parent disk if any.
 * Returns 1 if a parent was extracted into out_parent, 0 otherwise.
 *
 * Disk readlink target shape:    …/devices/.../block/<DISK>
 * Partition readlink target:     …/devices/.../block/<DISK>/<PART>
 *
 * So the parent name is the second-to-last segment IF and only IF that
 * segment is "block". For a disk the second-to-last segment is the bus
 * directory (e.g. "virtio2"), which is NOT "block". This is robust to
 * the various sysfs topologies (virtio-blk / nvme / scsi / loop / ram).
 */
static int
blb_resolve_parent (const char *name, char *out_parent, size_t outsz)
{
    char link_path[BLB_PATH_MAX];
    char parent_path[BLB_PATH_MAX];
    if (snprintf (link_path, sizeof link_path, "%s/%s",
                  blb_sys_block_dir (), name) >= (int) sizeof link_path)
        return 0;

    if (snprintf (parent_path, sizeof parent_path, "%s/parent",
                  link_path) < (int) sizeof parent_path
        && blb_read_str (link_path, "parent", out_parent, outsz) == 0
        && out_parent[0] != '\0')
        return 1;

    char target[BLB_PATH_MAX];
    ssize_t n = readlink (link_path, target, sizeof target - 1);
    if (n < 0) return 0;
    target[n] = '\0';

    /* Walk backwards to find the last and second-to-last components. */
    char *last_slash = strrchr (target, '/');
    if (!last_slash || last_slash == target) return 0;
    *last_slash = '\0';
    char *prev_slash = strrchr (target, '/');
    if (!prev_slash) return 0;
    char *parent_seg = prev_slash + 1;

    if (strcmp (parent_seg, "block") == 0) {
        /* Top-level disk — its target ends in `…/block/<NAME>`. */
        return 0;
    }
    char parent_base[BLB_PATH_MAX];
    if (snprintf (parent_base, sizeof parent_base, "%s/%s",
                  blb_sys_block_dir (), parent_seg) >= (int) sizeof parent_base)
        return 0;
    struct stat st;
    if (stat (parent_base, &st) < 0)
        return 0;
    /* Partition: parent_seg IS the parent disk. */
    size_t plen = strlen (parent_seg);
    if (plen >= outsz) return 0;
    memcpy (out_parent, parent_seg, plen + 1);
    return 1;
}

/* Infer device class from name + the `partition` file's presence. */
static void
blb_classify (blb_dev *d)
{
    char base[BLB_PATH_MAX];
    snprintf (base, sizeof base, "%s/%s", blb_sys_block_dir (), d->name);

    if (d->parent[0] != '\0' || blb_exists (base, "partition")) {
        strncpy (d->type, "part", sizeof d->type - 1);
        return;
    }
    /* Top-level: classify by name prefix. The order matters — "loop1"
     * matches "loop", "ram0" matches "ram", etc. */
    if (strncmp (d->name, "loop", 4) == 0) {
        strncpy (d->type, "loop", sizeof d->type - 1);
    } else if (strncmp (d->name, "ram", 3) == 0) {
        strncpy (d->type, "ram", sizeof d->type - 1);
    } else if (strncmp (d->name, "dm-", 3) == 0) {
        strncpy (d->type, "dm", sizeof d->type - 1);
    } else if (strncmp (d->name, "md", 2) == 0
            && isdigit ((unsigned char) d->name[2])) {
        strncpy (d->type, "md", sizeof d->type - 1);
    } else {
        strncpy (d->type, "disk", sizeof d->type - 1);
    }
}

static uint16_t
blb_le16 (const unsigned char *p)
{
    return (uint16_t) p[0] | ((uint16_t) p[1] << 8);
}

static uint32_t
blb_le32 (const unsigned char *p)
{
    return (uint32_t) p[0]
         | ((uint32_t) p[1] << 8)
         | ((uint32_t) p[2] << 16)
         | ((uint32_t) p[3] << 24);
}

static uint64_t
blb_le64 (const unsigned char *p)
{
    return (uint64_t) blb_le32 (p)
         | ((uint64_t) blb_le32 (p + 4) << 32);
}

static void
blb_trim (char *s)
{
    size_t n = strlen (s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\0'))
        s[--n] = '\0';
}

static void
blb_copy_fixed (char *dst, size_t dstlen, const unsigned char *src, size_t n)
{
    size_t i = 0;
    if (dstlen == 0) return;
    if (n + 1 > dstlen) n = dstlen - 1;
    for (i = 0; i < n; i++) {
        if (src[i] == 0) break;
        dst[i] = (char) src[i];
    }
    dst[i] = '\0';
    blb_trim (dst);
}

static void
blb_uuid_be (char *out, const unsigned char *u)
{
    snprintf (out, BLB_UUID_MAX,
              "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
              u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
              u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
}

static void
blb_uuid_gpt (char *out, const unsigned char *u)
{
    snprintf (out, BLB_UUID_MAX,
              "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
              u[3], u[2], u[1], u[0], u[5], u[4], u[7], u[6],
              u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
}

static void
blb_serial4 (char *out, const unsigned char *u)
{
    snprintf (out, BLB_UUID_MAX, "%02X%02X-%02X%02X",
              u[3], u[2], u[1], u[0]);
}

static void
blb_serial8 (char *out, const unsigned char *u)
{
    snprintf (out, BLB_UUID_MAX, "%02X%02X%02X%02X%02X%02X%02X%02X",
              u[7], u[6], u[5], u[4], u[3], u[2], u[1], u[0]);
}

static int
blb_guid_zero (const unsigned char *u)
{
    for (int i = 0; i < 16; i++)
        if (u[i] != 0)
            return 0;
    return 1;
}

static void
blb_copy_utf16le_ascii (char *dst, size_t dstlen,
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
    blb_trim (dst);
}

static ssize_t
blb_read_probe (const char *path, unsigned char *buf)
{
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t total = 0;
    while (total < (ssize_t) BLB_PROBE_LEN) {
        ssize_t r = read (fd, buf + total, BLB_PROBE_LEN - (size_t) total);
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
blb_probe_super (const char *name, blb_dev *d)
{
    static unsigned char buf[BLB_PROBE_LEN];
    char path[BLB_PATH_MAX];

    if (blb_join2 (path, sizeof path, blb_dev_root (), name) < 0)
        return;
    ssize_t n = blb_read_probe (path, buf);
    if (n <= 0)
        return;

    if ((size_t) n >= 1024 + 0x100 && blb_le16 (buf + 1024 + 0x38) == 0xef53) {
        const unsigned char *sb = buf + 1024;
        uint32_t compat = blb_le32 (sb + 0x5c);
        uint32_t incompat = blb_le32 (sb + 0x60);
        const char *t = "ext2";
        if (compat & 0x4)
            t = (incompat & 0x40) ? "ext4" : "ext3";
        snprintf (d->fstype, sizeof d->fstype, "%s", t);
        snprintf (d->fsver, sizeof d->fsver, "1.0");
        blb_uuid_be (d->uuid, sb + 0x68);
        blb_copy_fixed (d->label, sizeof d->label, sb + 0x78, 16);
        return;
    }
    if ((size_t) n >= 128 && memcmp (buf, "XFSB", 4) == 0) {
        snprintf (d->fstype, sizeof d->fstype, "xfs");
        blb_uuid_be (d->uuid, buf + 32);
        blb_copy_fixed (d->label, sizeof d->label, buf + 108, 12);
        return;
    }
    if ((size_t) n >= 65536 + 72 && memcmp (buf + 65536 + 64, "_BHRfS_M", 8) == 0) {
        snprintf (d->fstype, sizeof d->fstype, "btrfs");
        blb_uuid_be (d->uuid, buf + 65536 + 32);
        if ((size_t) n >= 65536 + 0x300)
            blb_copy_fixed (d->label, sizeof d->label, buf + 65536 + 299, 256);
        return;
    }
    if ((size_t) n >= 1024 + 512 && blb_le32 (buf + 1024) == 0xF2F52010u) {
        const unsigned char *sb = buf + 1024;
        snprintf (d->fstype, sizeof d->fstype, "f2fs");
        blb_uuid_be (d->uuid, sb + 108);
        size_t li = 0;
        for (int i = 0; i < 64 && li + 1 < sizeof d->label; i++) {
            unsigned char lo = sb[124 + i * 2];
            unsigned char hi = sb[124 + i * 2 + 1];
            if (lo == 0 && hi == 0) break;
            if (hi != 0 || lo < 0x20 || lo > 0x7e) break;
            d->label[li++] = (char) lo;
        }
        d->label[li] = '\0';
        blb_trim (d->label);
        return;
    }
    if ((size_t) n >= 512 && memcmp (buf + 3, "NTFS    ", 8) == 0
        && buf[510] == 0x55 && buf[511] == 0xaa) {
        snprintf (d->fstype, sizeof d->fstype, "ntfs");
        blb_serial8 (d->uuid, buf + 72);
        return;
    }
    if ((size_t) n >= 512 && memcmp (buf + 3, "EXFAT   ", 8) == 0
        && buf[510] == 0x55 && buf[511] == 0xaa) {
        snprintf (d->fstype, sizeof d->fstype, "exfat");
        blb_serial4 (d->uuid, buf + 100);
        return;
    }
    if ((size_t) n >= 512 && buf[510] == 0x55 && buf[511] == 0xaa) {
        uint16_t bytes_per_sector = blb_le16 (buf + 11);
        uint16_t reserved = blb_le16 (buf + 14);
        if ((bytes_per_sector == 512 || bytes_per_sector == 1024
             || bytes_per_sector == 2048 || bytes_per_sector == 4096)
            && reserved != 0
            && ((buf[66] == 0x29 && (memcmp (buf + 82, "FAT32   ", 8) == 0
                                     || memcmp (buf + 82, "FAT     ", 8) == 0))
                || buf[38] == 0x29)) {
            snprintf (d->fstype, sizeof d->fstype, "vfat");
            if (buf[66] == 0x29) {
                blb_serial4 (d->uuid, buf + 67);
                blb_copy_fixed (d->label, sizeof d->label, buf + 71, 11);
                snprintf (d->fsver, sizeof d->fsver, "FAT32");
            } else {
                blb_serial4 (d->uuid, buf + 39);
                blb_copy_fixed (d->label, sizeof d->label, buf + 43, 11);
                snprintf (d->fsver, sizeof d->fsver, "FAT16");
            }
            if (strcmp (d->label, "NO NAME") == 0)
                d->label[0] = '\0';
            return;
        }
    }
    static const size_t page_sizes[] = { 1024, 2048, 4096, 8192, 16384, 32768, 65536 };
    for (size_t i = 0; i < sizeof page_sizes / sizeof page_sizes[0]; i++) {
        size_t off = page_sizes[i];
        if (off < 10 || off > (size_t) n) continue;
        if (memcmp (buf + off - 10, "SWAPSPACE2", 10) == 0
            || memcmp (buf + off - 10, "SWAP-SPACE", 10) == 0) {
            snprintf (d->fstype, sizeof d->fstype, "swap");
            if ((size_t) n >= 1052 + 16) {
                blb_uuid_be (d->uuid, buf + 1036);
                blb_copy_fixed (d->label, sizeof d->label, buf + 1052, 16);
            }
            return;
        }
    }
}

static int
blb_read_partition_no (const char *name)
{
    char base[BLB_PATH_MAX];
    long long v = 0;
    if (snprintf (base, sizeof base, "%s/%s", blb_sys_block_dir (), name) >= (int) sizeof base)
        return 0;
    if (blb_read_int (base, "partition", &v) < 0 || v <= 0 || v > 65535)
        return 0;
    return (int) v;
}

static void
blb_probe_part_gpt (blb_dev *d)
{
    if (!d->parent[0])
        return;
    int partno = blb_read_partition_no (d->name);
    if (partno <= 0)
        return;
    char parent_path[BLB_PATH_MAX];
    if (blb_join2 (parent_path, sizeof parent_path, blb_dev_root (), d->parent) < 0)
        return;
    static unsigned char buf[BLB_PROBE_LEN];
    ssize_t n = blb_read_probe (parent_path, buf);
    if (n <= 0 || (size_t) n < 512 + 92)
        return;
    if (memcmp (buf + 512, "EFI PART", 8) != 0)
        return;
    uint64_t ents_lba = blb_le64 (buf + 512 + 72);
    uint32_t nents = blb_le32 (buf + 512 + 80);
    uint32_t entsz = blb_le32 (buf + 512 + 84);
    if (ents_lba == 0 || nents == 0 || entsz < 56 || entsz > 4096)
        return;
    if ((uint32_t) partno > nents)
        return;
    uint64_t off64 = ents_lba * 512ULL + (uint64_t) (partno - 1) * entsz;
    if (off64 + entsz > (uint64_t) n)
        return;
    const unsigned char *e = buf + off64;
    if (blb_guid_zero (e) || blb_guid_zero (e + 16))
        return;
    blb_uuid_gpt (d->partuuid, e + 16);
    if (entsz > 56)
        blb_copy_utf16le_ascii (d->partlabel, sizeof d->partlabel, e + 56, entsz - 56);
}

static void
blb_unescape_mount (const char *in, char *out, size_t outsz)
{
    size_t oi = 0;
    for (size_t i = 0; in[i] && oi + 1 < outsz; i++) {
        if (in[i] == '\\'
            && in[i + 1] >= '0' && in[i + 1] <= '7'
            && in[i + 2] >= '0' && in[i + 2] <= '7'
            && in[i + 3] >= '0' && in[i + 3] <= '7') {
            int v = (in[i + 1] - '0') * 64 + (in[i + 2] - '0') * 8 + (in[i + 3] - '0');
            out[oi++] = (char) v;
            i += 3;
        } else {
            out[oi++] = in[i];
        }
    }
    out[oi] = '\0';
}

static int
blb_mount_dev_matches (const char *field, const char *name)
{
    char devpath[BLB_PATH_MAX];
    if (blb_join2 (devpath, sizeof devpath, blb_dev_root (), name) == 0
        && strcmp (field, devpath) == 0)
        return 1;
    if (strncmp (field, "/dev/", 5) == 0 && strcmp (field + 5, name) == 0)
        return 1;
    if (strcmp (field, name) == 0)
        return 1;
    return 0;
}

static void
blb_load_mountpoint (blb_dev *d)
{
    const char *paths[2];
    paths[0] = blb_proc_mounts ();
    paths[1] = "/proc/self/mounts";
    for (int pi = 0; pi < 2; pi++) {
        if (!paths[pi] || !*paths[pi]) continue;
        if (pi == 1 && strcmp (paths[0], paths[1]) == 0) continue;
        FILE *f = fopen (paths[pi], "r");
        if (!f) continue;
        char line[2048];
        while (fgets (line, sizeof line, f)) {
            char src[512], mnt[512];
            if (sscanf (line, "%511s %511s", src, mnt) != 2)
                continue;
            char usrc[512], umnt[512];
            blb_unescape_mount (src, usrc, sizeof usrc);
            if (!blb_mount_dev_matches (usrc, d->name))
                continue;
            blb_unescape_mount (mnt, umnt, sizeof umnt);
            snprintf (d->mountpoint, sizeof d->mountpoint, "%s", umnt);
            fclose (f);
            return;
        }
        fclose (f);
    }
}

static void
blb_load_fs_usage (blb_dev *d)
{
    d->fsuse_pct = -1;
    if (!d->mountpoint[0])
        return;
    struct statvfs vfs;
    if (statvfs (d->mountpoint, &vfs) < 0)
        return;
    uint64_t bsize = vfs.f_frsize ? (uint64_t) vfs.f_frsize : (uint64_t) vfs.f_bsize;
    uint64_t total = (uint64_t) vfs.f_blocks * bsize;
    uint64_t avail = (uint64_t) vfs.f_bavail * bsize;
    uint64_t used = (total > avail) ? total - avail : 0;
    d->fsavail = avail;
    if (total > 0)
        d->fsuse_pct = (int) ((used * 100ULL + total - 1ULL) / total);
}

/* ---------- enumerate ---------- */

static int
blb_load_one (const char *name, blb_dev *d)
{
    memset (d, 0, sizeof *d);
    size_t nlen = strlen (name);
    if (nlen >= sizeof d->name) return -1;
    memcpy (d->name, name, nlen + 1);

    blb_resolve_parent (d->name, d->parent, sizeof d->parent);

    char base[BLB_PATH_MAX];
    snprintf (base, sizeof base, "%s/%s", blb_sys_block_dir (), name);

    /* size: sectors × 512. Missing/unreadable -> 0. */
    long long sec = 0;
    if (blb_read_int (base, "size", &sec) == 0 && sec > 0) {
        d->size_bytes = (uint64_t) sec * 512ULL;
    }

    /* MAJ:MIN from /sys/class/block/<name>/dev. */
    if (blb_read_str (base, "dev", d->majmin, sizeof d->majmin) < 0) {
        strncpy (d->majmin, "?", sizeof d->majmin - 1);
    }

    /* ro / removable / hidden — each optional. */
    long long v = 0;
    if (blb_read_int (base, "ro", &v) == 0) d->ro = (v != 0);
    if (blb_read_int (base, "removable", &v) == 0) d->removable = (v != 0);
    if (blb_read_int (base, "hidden", &v) == 0) d->hidden = (v != 0);

    blb_classify (d);
    d->fsuse_pct = -1;
    blb_probe_super (d->name, d);
    blb_probe_part_gpt (d);
    blb_load_mountpoint (d);
    blb_load_fs_usage (d);
    return 0;
}

static int
blb_cmp_dev (const void *a, const void *b)
{
    const blb_dev *da = (const blb_dev *) a;
    const blb_dev *db = (const blb_dev *) b;
    /* Disks first (parent==""), then partitions; within each bucket sort
     * by name. For partitions we group by parent so the tree printer
     * sees them adjacent to (or at least after) their disk. */
    int a_part = (da->parent[0] != '\0');
    int b_part = (db->parent[0] != '\0');
    if (a_part != b_part) return a_part - b_part;
    if (a_part) {
        int p = strcmp (da->parent, db->parent);
        if (p != 0) return p;
    }
    return strcmp (da->name, db->name);
}

static int
blb_load_all (blb_dev *devs, int max, int *out_n)
{
    const char *sys_block = blb_sys_block_dir ();
    DIR *d = opendir (sys_block);
    if (!d) {
        builtin_error ("opendir %s: %s", sys_block, strerror (errno));
        return -1;
    }
    int n = 0;
    struct dirent *de;
    while ((de = readdir (d))) {
        if (de->d_name[0] == '.') continue;
        if (n >= max) break;
        if (blb_load_one (de->d_name, &devs[n]) < 0) continue;
        if (devs[n].hidden) continue;     /* skip device-mapper hidden kobjects */
        n++;
    }
    closedir (d);
    qsort (devs, n, sizeof *devs, blb_cmp_dev);
    *out_n = n;
    return 0;
}

/* ---------- size formatter (human-readable, 1024-base) ---------- */

static void
blb_format_size (uint64_t b, char *out, size_t outsz)
{
    static const char units[] = { 'B', 'K', 'M', 'G', 'T', 'P', 'E' };
    if (b == 0) {
        snprintf (out, outsz, "0B");
        return;
    }
    double v = (double) b;
    int u = 0;
    while (v >= 1024.0 && u < (int) (sizeof units / sizeof units[0]) - 1) {
        v /= 1024.0;
        u++;
    }
    if (u == 0) {
        snprintf (out, outsz, "%llu%c", (unsigned long long) b, units[0]);
    } else if (v >= 100.0) {
        snprintf (out, outsz, "%.0f%c", v, units[u]);
    } else if (v >= 10.0) {
        snprintf (out, outsz, "%.1f%c", v, units[u]);
    } else {
        snprintf (out, outsz, "%.2f%c", v, units[u]);
    }
}

/* ---------- printing ---------- */

typedef struct {
    int list;        /* -l */
    int nodeps;      /* -d */
    int fs;          /* -f */
    int show_header; /* default 1 */
    int pairs;       /* -P */
    int raw;         /* -r */
    int custom_cols; /* -o/--output */
    blb_col_id cols[BLB_COL_MAX];
    int ncols;
} blb_opts;

static const char *
blb_col_name (blb_col_id id)
{
    for (int i = 0; blb_cols[i].name; i++)
        if (blb_cols[i].id == id && strcmp (blb_cols[i].name, "MOUNTPOINTS") != 0)
            return blb_cols[i].name;
    return "?";
}

static int
blb_col_lookup (const char *name, blb_col_id *out)
{
    for (int i = 0; blb_cols[i].name; i++) {
        if (strcmp (blb_cols[i].name, name) == 0) {
            *out = blb_cols[i].id;
            return 0;
        }
    }
    return -1;
}

static void
blb_supported_columns_stderr (void)
{
    fputs ("supported columns: ", stderr);
    for (int i = 0; blb_cols[i].name; i++) {
        if (i) fputc (',', stderr);
        fputs (blb_cols[i].name, stderr);
    }
    fputc ('\n', stderr);
}

static void
blb_add_col (blb_opts *opt, blb_col_id id)
{
    if (opt->ncols >= BLB_COL_MAX)
        return;
    opt->cols[opt->ncols++] = id;
}

static void
blb_add_default_cols (blb_opts *opt)
{
    blb_add_col (opt, BLB_COL_NAME);
    blb_add_col (opt, BLB_COL_MAJMIN);
    blb_add_col (opt, BLB_COL_RM);
    blb_add_col (opt, BLB_COL_SIZE);
    blb_add_col (opt, BLB_COL_RO);
    blb_add_col (opt, BLB_COL_TYPE);
    if (opt->fs)
        blb_add_col (opt, BLB_COL_FSTYPE);
}

static int
blb_parse_cols (blb_opts *opt, const char *spec)
{
    if (!spec || !*spec) {
        builtin_error ("-o/--output requires a column list");
        return -1;
    }
    int append = (spec[0] == '+');
    if (append)
        spec++;
    else
        opt->ncols = 0;
    if (append && opt->ncols == 0)
        blb_add_default_cols (opt);

    char tmp[512];
    if (strlen (spec) >= sizeof tmp) {
        builtin_error ("-o/--output column list too long");
        return -1;
    }
    strcpy (tmp, spec);
    for (char *p = tmp; *p; p++)
        *p = (char) toupper ((unsigned char) *p);

    char *save = NULL;
    for (char *tok = strtok_r (tmp, ",", &save); tok; tok = strtok_r (NULL, ",", &save)) {
        while (*tok == ' ' || *tok == '\t') tok++;
        char *end = tok + strlen (tok);
        while (end > tok && (end[-1] == ' ' || end[-1] == '\t')) *--end = '\0';
        if (!*tok) continue;
        blb_col_id id;
        if (blb_col_lookup (tok, &id) < 0) {
            builtin_error ("unknown column: %s", tok);
            blb_supported_columns_stderr ();
            return -1;
        }
        blb_add_col (opt, id);
    }
    if (opt->ncols == 0) {
        builtin_error ("-o/--output produced no columns");
        return -1;
    }
    opt->custom_cols = 1;
    return 0;
}

static void
blb_print_help (void)
{
    puts ("List block devices (lsblk).");
    puts ("");
    puts ("    bashlsblk [-l] [-d] [-f] [-n] [-P|-r] [-o LIST] [DEV ...]");
    puts ("    bashlsblk -h | --help");
    puts ("");
    puts ("Walks /sys/class/block. Default output is a tree: disks first, then");
    puts ("each disk's partitions indented with ASCII branch characters.");
    puts ("");
    puts ("    -l    list form (flat)");
    puts ("    -d    --nodeps; print disks only, suppress partitions");
    puts ("    -f    --fs; emit FSTYPE column from matching /dev nodes");
    puts ("    -n    --noheadings; suppress the column header row");
    puts ("    -P    --pairs; emit fixed key=\"value\" rows");
    puts ("    -r    --raw; emit fixed space-separated rows");
    puts ("    -o    --output LIST; select columns, or +COL to append to defaults");
    puts ("    DEV   restrict to named device(s); basename, /dev path, or /sys path");
    puts ("");
    puts ("Columns: NAME MAJ:MIN RM SIZE RO TYPE FSTYPE FSVER LABEL UUID");
    puts ("         PARTLABEL PARTUUID MOUNTPOINT MOUNTPOINTS FSAVAIL FSUSE%.");
    puts ("Exit codes: 0 success, 1 sysfs error, 2 usage, 32 no matching device.");
}

static const char *
blb_col_value (const blb_dev *d, const char *namecol, blb_col_id id,
               char *buf, size_t bufsz)
{
    switch (id) {
    case BLB_COL_NAME:
        return namecol;
    case BLB_COL_MAJMIN:
        return d->majmin;
    case BLB_COL_RM:
        snprintf (buf, bufsz, "%d", d->removable);
        return buf;
    case BLB_COL_SIZE:
        blb_format_size (d->size_bytes, buf, bufsz);
        return buf;
    case BLB_COL_RO:
        snprintf (buf, bufsz, "%d", d->ro);
        return buf;
    case BLB_COL_TYPE:
        return d->type;
    case BLB_COL_FSTYPE:
        return d->fstype;
    case BLB_COL_FSVER:
        return d->fsver;
    case BLB_COL_LABEL:
        return d->label;
    case BLB_COL_UUID:
        return d->uuid;
    case BLB_COL_PARTLABEL:
        return d->partlabel;
    case BLB_COL_PARTUUID:
        return d->partuuid;
    case BLB_COL_MOUNTPOINT:
        return d->mountpoint;
    case BLB_COL_FSAVAIL:
        if (d->fsavail == 0) return "";
        blb_format_size (d->fsavail, buf, bufsz);
        return buf;
    case BLB_COL_FSUSE_PCT:
        if (d->fsuse_pct < 0) return "";
        snprintf (buf, bufsz, "%d%%", d->fsuse_pct);
        return buf;
    }
    return "";
}

/* Emit one device row. `prefix` is the tree branch prefix ("", "├─",
 * "└─") — for the list form prefix is always "". */
static void
blb_print_one (const blb_dev *d, const char *prefix, const blb_opts *opt)
{
    char sizebuf[16];
    blb_format_size (d->size_bytes, sizebuf, sizeof sizebuf);

    /* The NAME column carries the tree prefix; left-align in 16 cols. */
    char namecol[80];
    snprintf (namecol, sizeof namecol, "%s%s", prefix, d->name);

    if (opt->custom_cols) {
        for (int i = 0; i < opt->ncols; i++) {
            char vbuf[64];
            const char *v = blb_col_value (d, opt->pairs || opt->raw ? d->name : namecol,
                                           opt->cols[i], vbuf, sizeof vbuf);
            if (opt->pairs) {
                if (i) putchar (' ');
                printf ("%s=\"%s\"", blb_col_name (opt->cols[i]), v);
            } else {
                if (i) putchar (' ');
                fputs (v, stdout);
            }
        }
        putchar ('\n');
        return;
    }

    if (opt->pairs) {
        printf ("NAME=\"%s\" MAJ:MIN=\"%s\" RM=\"%d\" SIZE=\"%s\" RO=\"%d\" TYPE=\"%s\"",
                d->name, d->majmin, d->removable, sizebuf, d->ro, d->type);
        if (opt->fs)
            printf (" FSTYPE=\"%s\"", d->fstype);
        putchar ('\n');
        return;
    }

    if (opt->raw) {
        printf ("%s %s %d %s %d %s",
                d->name, d->majmin, d->removable, sizebuf, d->ro, d->type);
        if (opt->fs)
            printf (" %s", d->fstype);
        putchar ('\n');
        return;
    }

    if (opt->fs) {
        printf ("%-16s %-7s %d %6s %d %-5s %s\n",
                namecol, d->majmin, d->removable, sizebuf,
                d->ro, d->type, d->fstype);
    } else {
        printf ("%-16s %-7s %d %6s %d %s\n",
                namecol, d->majmin, d->removable, sizebuf,
                d->ro, d->type);
    }
}

static void
blb_print_header (const blb_opts *opt)
{
    if (opt->pairs || opt->raw) return;
    if (!opt->show_header) return;
    if (opt->custom_cols) {
        for (int i = 0; i < opt->ncols; i++) {
            if (i) putchar (' ');
            fputs (blb_col_name (opt->cols[i]), stdout);
        }
        putchar ('\n');
        return;
    }
    if (opt->fs) {
        printf ("%-16s %-7s %s %6s %s %-5s %s\n",
                "NAME", "MAJ:MIN", "RM", "SIZE", "RO", "TYPE", "FSTYPE");
    } else {
        printf ("%-16s %-7s %s %6s %s %s\n",
                "NAME", "MAJ:MIN", "RM", "SIZE", "RO", "TYPE");
    }
}

/* Tree form: walk disks in order, then for each disk print every part
 * whose parent==disk.name with ASCII branch chars. */
static void
blb_emit_tree (const blb_dev *devs, int n, const blb_opts *opt)
{
    for (int i = 0; i < n; i++) {
        if (devs[i].parent[0] != '\0') continue;     /* not a top-level */
        blb_print_one (&devs[i], "", opt);
        if (opt->nodeps) continue;

        /* Find this disk's children. */
        int child_idxs[BLB_MAX_DEVS];
        int nchildren = 0;
        for (int j = 0; j < n; j++) {
            if (devs[j].parent[0] == '\0') continue;
            if (strcmp (devs[j].parent, devs[i].name) != 0) continue;
            if (nchildren < BLB_MAX_DEVS)
                child_idxs[nchildren++] = j;
        }
        for (int k = 0; k < nchildren; k++) {
            int j = child_idxs[k];
            const char *pref = (k == nchildren - 1) ? "`-" : "|-";
            blb_print_one (&devs[j], pref, opt);
        }
    }
}

/* List form: flat. -d omits partitions; otherwise everything. */
static void
blb_emit_list (const blb_dev *devs, int n, const blb_opts *opt)
{
    for (int i = 0; i < n; i++) {
        if (opt->nodeps && devs[i].parent[0] != '\0') continue;
        blb_print_one (&devs[i], "", opt);
    }
}

/* ---------- filter: restrict to named devices ---------- */

/* Returns 1 if `cand` is mentioned (by basename) in argv `wants[0..n-1]`. */
static int
blb_matches_wanted (const char *cand, char **wants, int nwants)
{
    for (int i = 0; i < nwants; i++) {
        const char *w = wants[i];
        const char *base = strrchr (w, '/');
        base = base ? base + 1 : w;
        if (strcmp (base, cand) == 0) return 1;
    }
    return 0;
}

/* Filter `devs` in-place: keep only entries whose name is in `wants`,
 * plus all their children (so a `bashlsblk vda` call still shows the
 * partition table tree under vda). Returns new count. */
static int
blb_filter (blb_dev *devs, int n, char **wants, int nwants)
{
    int kept[BLB_MAX_DEVS];
    int nkept = 0;
    /* Pass 1: select top-level matches by name. */
    for (int i = 0; i < n; i++) {
        if (blb_matches_wanted (devs[i].name, wants, nwants)) {
            kept[nkept++] = i;
        }
    }
    /* Pass 2: include partitions whose parent is in `kept`. */
    int extra = 0;
    for (int i = 0; i < n; i++) {
        if (devs[i].parent[0] == '\0') continue;
        for (int k = 0; k < nkept; k++) {
            if (strcmp (devs[i].parent, devs[kept[k]].name) == 0) {
                /* Avoid double-add if the user also named the partition. */
                int dup = 0;
                for (int x = 0; x < nkept + extra; x++) {
                    if (kept[x] == i) { dup = 1; break; }
                }
                if (!dup && nkept + extra < BLB_MAX_DEVS) {
                    kept[nkept + extra] = i;
                    extra++;
                }
                break;
            }
        }
    }
    int total = nkept + extra;
    /* Compact: write kept entries to a temp, then back. Allocate on the
     * stack — BLB_MAX_DEVS ceiling caps the size. */
    blb_dev tmp[BLB_MAX_DEVS];
    for (int i = 0; i < total; i++) tmp[i] = devs[kept[i]];
    for (int i = 0; i < total; i++) devs[i] = tmp[i];
    qsort (devs, total, sizeof *devs, blb_cmp_dev);
    return total;
}

/* ---------- builtin ---------- */

int
lsblk_builtin (WORD_LIST *list)
{
    blb_opts opt = { 0, 0, 0, 1, 0, 0, 0, { 0 }, 0 };
    char *wants[BLB_MAX_DEVS];
    int nwants = 0;
    int n_pos_max = (int) (sizeof wants / sizeof wants[0]);

    /* Argument parse: -l / -d / -f / -h / --help / --, then positionals. */
    while (list) {
        const char *w = list->word->word;
        if (strcmp (w, "--") == 0) {
            for (list = list->next; list; list = list->next) {
                if (nwants < n_pos_max) wants[nwants++] = list->word->word;
            }
            break;
        }
        if (strcmp (w, "--help") == 0 || strcmp (w, "-h") == 0) {
            blb_print_help ();
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "-l") == 0 || strcmp (w, "--list") == 0) {
            opt.list = 1;
        } else if (strcmp (w, "-d") == 0 || strcmp (w, "--nodeps") == 0) {
            opt.nodeps = 1;
        } else if (strcmp (w, "-f") == 0 || strcmp (w, "--fs") == 0) {
            opt.fs = 1;
        } else if (strcmp (w, "-n") == 0 || strcmp (w, "--noheadings") == 0) {
            opt.show_header = 0;
        } else if (strcmp (w, "-P") == 0 || strcmp (w, "--pairs") == 0) {
            opt.pairs = 1;
            opt.raw = 0;
            opt.list = 1;
        } else if (strcmp (w, "-r") == 0 || strcmp (w, "--raw") == 0) {
            opt.raw = 1;
            opt.pairs = 0;
            opt.list = 1;
        } else if (strcmp (w, "-o") == 0 || strcmp (w, "--output") == 0) {
            if (!list->next) {
                builtin_error ("%s requires a column list", w);
                blb_supported_columns_stderr ();
                return EX_USAGE;
            }
            list = list->next;
            if (blb_parse_cols (&opt, list->word->word) < 0)
                return EX_USAGE;
        } else if (strncmp (w, "--output=", 9) == 0) {
            if (blb_parse_cols (&opt, w + 9) < 0)
                return EX_USAGE;
        } else if (strncmp (w, "-o", 2) == 0 && w[2] != '\0') {
            if (blb_parse_cols (&opt, w + 2) < 0)
                return EX_USAGE;
        } else if (w[0] == '-' && w[1] != '\0') {
            builtin_error ("unknown flag: %s", w);
            builtin_usage ();
            return EX_USAGE;
        } else {
            if (nwants < n_pos_max) wants[nwants++] = (char *) w;
        }
        list = list->next;
    }

    blb_dev devs[BLB_MAX_DEVS];
    int n = 0;
    if (blb_load_all (devs, BLB_MAX_DEVS, &n) < 0) {
        return EXECUTION_FAILURE;
    }

    if (nwants > 0) {
        n = blb_filter (devs, n, wants, nwants);
        if (n == 0) {
            /* lsblk(8) exits 32 when *no* requested device exists. */
            for (int i = 0; i < nwants; i++) {
                builtin_error ("not a block device: %s", wants[i]);
            }
            return 32;
        }
    }

    blb_print_header (&opt);
    if (opt.list) {
        blb_emit_list (devs, n, &opt);
    } else {
        blb_emit_tree (devs, n, &opt);
    }
    return EXECUTION_SUCCESS;
}

char *lsblk_doc[] = {
    "List block devices (lsblk).",
    "",
    "    bashlsblk [-l] [-d] [-f] [-n] [-P|-r] [-o LIST] [DEV ...]",
    "    bashlsblk -h | --help",
    "",
    "Walks /sys/class/block. Default output is a tree: disks first, then",
    "each disk's partitions indented with ASCII branch characters.",
    "",
    "    -l    list form (flat)",
    "    -d    --nodeps; print disks only, suppress partitions",
    "    -f    --fs; emit FSTYPE column from matching /dev nodes",
    "    -n    --noheadings; suppress the column header row",
    "    -P    --pairs; emit fixed key=\"value\" rows",
    "    -r    --raw; emit fixed space-separated rows",
    "    -o    --output LIST; select supported columns; +COL appends",
    "    DEV   restrict to named device(s). DEV may be a basename",
    "          (`vda`), a /dev path (`/dev/vda`), or a /sys path; the",
    "          trailing component is what matches. Partitions of a",
    "          matched disk are also shown.",
    "",
    "Columns: NAME MAJ:MIN RM SIZE RO TYPE FSTYPE FSVER LABEL UUID",
    "PARTLABEL PARTUUID MOUNTPOINT/MOUNTPOINTS FSAVAIL FSUSE%. Sizes are",
    "human-readable powers-of-1024.",
    "",
    "Exit codes:",
    "    0    success",
    "    1    operational error (sysfs unavailable)",
    "    2    usage error",
    "    32   no matching device when DEV operand given",
    (char *)NULL
};

struct builtin bashlsblk_struct = {
    "bashlsblk",
    lsblk_builtin,
    BUILTIN_ENABLED,
    lsblk_doc,
    "bashlsblk [-l] [-d] [-f] [-n] [-P|-r] [-o LIST] [DEV ...]",
    0
};
