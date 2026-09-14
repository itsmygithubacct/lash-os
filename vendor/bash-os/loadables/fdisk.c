/* SPDX-License-Identifier: MIT */
/* fdisk.c — MBR + GPT partition-table editor (subset). Loadable for bash.
 *
 * MISSING_LOADABLES T2 (ML-T2-01) shell. v1 surface is intentionally
 * narrow: list existing tables, create a fresh primary-only MBR layout
 * non-interactively, create a fresh MBR extended/logical layout
 * non-interactively, create a fresh GPT layout non-interactively, delete
 * existing primary/logical MBR and GPT slots from image-backed fixtures, and
 * mutate GPT entry attributes in place.
 * Interactive prompt UI (the classic `fdisk` n/d/p/w menu) is deferred.
 * A small stdin script subset is implemented in /bash-os/sfdisk.sh by
 * translating label/sector and named-field rows to the inline SPEC form below.
 * MBR extended/logical partitions are listed by walking the EBR chain, logical
 * partition deletion can clear an existing EBR data entry, and fresh extended
 * chains can be created from explicit sector specs.
 *
 * Subcommands / flags:
 *     fdisk -l DEV ...               list partition tables on each DEV
 *     fdisk --create-mbr DEV SPEC... overwrite DEV with a fresh MBR
 *     fdisk --create-mbr-extended DEV EXT_SPEC LOGICAL_SPEC...
 *                                          overwrite DEV with a fresh MBR +
 *                                          one extended partition and EBR chain
 *     fdisk --create-gpt DEV SPEC... overwrite DEV with a fresh GPT
 *     fdisk --delete DEV N           clear partition slot N in-place
 *     fdisk --delete-compact DEV N   delete MBR logical N and relink EBRs
 *     fdisk --set-attrs DEV N ATTRS  mutate GPT partition attribute bits
 *     fdisk --partx-kernel OP DEV [MIN MAX]
 *                                          apply BLKPG add/delete/update for
 *                                          the partx(8) wrapper
 *
 * SPEC for --create-mbr (1..4 primary partitions, in order):
 *     [START[,SIZE[,TYPE[,BOOT]]]]
 *       START : starting LBA (default = next free, first slot starts at 2048)
 *       SIZE  : size in sectors (default = remaining space; only legal on
 *               the last specified slot; "+" means same as default)
 *       TYPE  : MBR partition type byte in hex (default = 83 = Linux)
 *       BOOT  : "boot" / "*" sets the active flag; anything else clears.
 *     SPEC strings are comma-delimited; trailing commas may be omitted.
 *
 * SPEC for --create-mbr-extended:
 *     EXT_SPEC      = START,SIZE[,TYPE]        (TYPE default = 05)
 *     LOGICAL_SPEC  = START,SIZE[,TYPE[,BOOT]] (TYPE default = 83)
 *       All starts/sizes are explicit absolute sectors. Logical partitions must
 *       be sorted, non-overlapping, fully inside the extended container, and
 *       leave one sector before each logical data range for its EBR.
 *
 * SPEC for --create-gpt (1..128 partitions):
 *     [START[,SIZE[,TYPE-GUID[,NAME[,ATTRS]]]]]
 *       START : starting LBA (default = next free; first slot starts at 2048)
 *       SIZE  : size in sectors (default = remaining usable space; only legal
 *               on the last specified slot)
 *       TYPE-GUID : 36-char GUID, "linux" (=0FC63DAF-...-4F2C6), or
 *                   "swap" (=0657FD6D-...-4F4F); default = linux
 *                   filesystem GUID.
 *       NAME  : up to 36 UTF-16LE chars, encoded from US-ASCII verbatim.
 *       ATTRS : GPT attribute bits as a number, or names separated by '+',
 *               '|' or spaces: RequiredPartition, NoBlockIOProtocol,
 *               LegacyBIOSBootable, GUID:N for bits 48..63.
 *
 * Block-size discovery uses BLKSSZGET (logical-sector size) and
 * BLKGETSIZE64 (size in bytes). After a write we BLKRRPART so the kernel
 * re-reads the table. On non-block-device targets (a regular file backing
 * a loop image) those ioctls degrade to fstat(2) + skip rather than fail.
 *
 * Source counterparts walked:
 *   research/refs/util-linux/disk-utils/{fdisk,sfdisk}.c + libfdisk/
 *   research/refs/busybox/util-linux/{fdisk.c,fdisk_gpt.c}
 *   research/refs/toybox/toys/{other,pending}/fdisk.c
 *
 * Differences from util-linux fdisk:
 *   - No interactive prompt UI in v1.
 *   - Logical/extended creation is limited to a fresh single-extended-container
 *     EBR chain from explicit sector specs; logical deletion clears existing
 *     EBR data entries without compacting the chain unless --delete-compact is
 *     used for an MBR logical partition.
 *   - Full sfdisk script parity is still deferred; the wrapper accepts
 *     label/unit headers plus START,SIZE,TYPE[,BOOT_OR_NAME] rows and
 *     named fresh-table rows such as start=, size=, type=, bootable,
 *     and name=. GPT type aliases include linux and swap.
 *   - GPT supports flat-name only (no Unicode normalization).
 *   - GPT attributes are supported for fresh-table creation and in-place
 *     mutation of existing GPT entries.
 *   - Mutation support is currently limited to deleting a numbered slot,
 *     compact-deleting MBR logical partition metadata, and setting GPT entry
 *     attributes. Compact deletion relinks EBR metadata; it does not move
 *     partition payload sectors or create extended chains.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c. See that file's header
 * for the full grant.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/blkpg.h>
#include <linux/fs.h>

#include "loadables.h"

/* ---- Magic / constants ----------------------------------------------- */

#define BFD_SECTOR             512u    /* logical-sector fallback */
#define BFD_MBR_PARTS          4
#define BFD_GPT_PARTS          128
#define BFD_GPT_ENTRY_SZ       128
#define BFD_GPT_PRIMARY_LBA    1
#define BFD_GPT_HDR_SIZE       92u
#define BFD_GPT_REVISION       0x00010000u
/* "EFI PART" little-endian -> 0x5452415020494645 */
#define BFD_GPT_SIG            0x5452415020494645ULL
#define BFD_MBR_BOOT_SIG       0xAA55u
#define BFD_FIRST_USABLE_LBA   2048u   /* 1 MiB alignment */

/* Linux-filesystem partition GUID, in mixed-endian on-disk byte order:
 *   0FC63DAF-8483-4772-8E79-3D69D8477DE4
 * (first three sub-fields are little-endian; last two are big-endian.) */
static const uint8_t BFD_GPT_LINUX_GUID[16] = {
    0xAF,0x3D,0xC6,0x0F, 0x83,0x84, 0x72,0x47,
    0x8E,0x79, 0x3D,0x69,0xD8,0x47,0x7D,0xE4
};

/* Linux swap partition GUID:
 *   0657FD6D-A4AB-43C4-84E5-0933C84B4F4F */
static const uint8_t BFD_GPT_SWAP_GUID[16] = {
    0x6D,0xFD,0x57,0x06, 0xAB,0xA4, 0xC4,0x43,
    0x84,0xE5, 0x09,0x33,0xC8,0x4B,0x4F,0x4F
};

/* --no-act / -n: when set, mutating verbs validate and report what they
 * would do but skip the actual disk write (sfdisk --no-act semantics).
 * File-scope because the table-model serialize path is the single choke
 * point; reset to 0 at the top of every fdisk_builtin invocation
 * (loadable builtins persist state across calls within one bash). */
static int bfd_no_act = 0;

/* --repair: allow serializing a GPT table that was recovered from its
 * backup header (gpt_recovered). Set only by the --repair verb; reset per
 * invocation. Without it, a recovered table refuses to serialize. */
static int bfd_repair = 0;

/* Per-verb "what happened" confirmation to stderr. Suppressed under
 * --no-act, where bfd_table_serialize has already emitted the single
 * authoritative "would write ... (not written)" dry-run notice — a
 * trailing "wrote/set/deleted ..." would contradict it. */
static void
bfd_report (const char *fmt, ...)
{
    if (bfd_no_act) return;
    va_list ap;
    va_start (ap, fmt);
    vfprintf (stderr, fmt, ap);
    va_end (ap);
}

/* ---- CRC32 (IEEE 802.3, reflected) ----------------------------------- */

static uint32_t bfd_crc_tbl[256];
static int bfd_crc_init = 0;

static void
bfd_crc_init_table (void)
{
    if (bfd_crc_init) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        bfd_crc_tbl[i] = c;
    }
    bfd_crc_init = 1;
}

static uint32_t
bfd_crc32 (const void *buf, size_t len)
{
    bfd_crc_init_table ();
    const uint8_t *p = (const uint8_t *) buf;
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        c = bfd_crc_tbl[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

/* ---- Endianness helpers (little-endian on-disk) ---------------------- */

static void bfd_put_le16 (void *p, uint16_t v)
{ uint8_t *b = p; b[0] = v & 0xFF; b[1] = (v >> 8) & 0xFF; }

static void bfd_put_le32 (void *p, uint32_t v)
{ uint8_t *b = p; b[0] = v; b[1] = v >> 8; b[2] = v >> 16; b[3] = v >> 24; }

static void bfd_put_le64 (void *p, uint64_t v)
{ uint8_t *b = p;
  for (int i = 0; i < 8; i++) b[i] = (v >> (i * 8)) & 0xFF; }

static uint16_t bfd_get_le16 (const void *p)
{ const uint8_t *b = p; return (uint16_t) b[0] | ((uint16_t) b[1] << 8); }

static uint32_t bfd_get_le32 (const void *p)
{ const uint8_t *b = p;
  return (uint32_t) b[0]      | ((uint32_t) b[1] << 8)
       | ((uint32_t) b[2] << 16) | ((uint32_t) b[3] << 24); }

static uint64_t bfd_get_le64 (const void *p)
{ const uint8_t *b = p; uint64_t v = 0;
  for (int i = 0; i < 8; i++) v |= ((uint64_t) b[i]) << (i * 8);
  return v; }

static void bfd_format_gpt_attrs (uint64_t attrs, char *out, size_t outsz);

/* ---- Geometry helpers ------------------------------------------------- */

struct bfd_geom {
    uint32_t sector_size;     /* logical sector size in bytes */
    uint64_t size_bytes;      /* total device/file size */
    uint64_t total_sectors;   /* size_bytes / sector_size */
    int      is_block;        /* 1 if S_ISBLK, 0 if S_ISREG */
};

static void bfd_reread_partitions_if_needed (int fd, const struct bfd_geom *g);

static int
bfd_probe_geom (int fd, struct bfd_geom *g)
{
    struct stat st;
    if (fstat (fd, &st) < 0) {
        builtin_error ("fstat: %s", strerror (errno));
        return -1;
    }
    g->sector_size  = BFD_SECTOR;
    g->size_bytes   = 0;
    g->total_sectors = 0;
    g->is_block     = 0;

    if (S_ISBLK (st.st_mode)) {
        g->is_block = 1;
        int ss = 0;
        if (ioctl (fd, BLKSSZGET, &ss) == 0 && ss > 0) g->sector_size = (uint32_t) ss;
        unsigned long long sz = 0;
        if (ioctl (fd, BLKGETSIZE64, &sz) == 0) g->size_bytes = (uint64_t) sz;
    } else if (S_ISREG (st.st_mode)) {
        g->size_bytes = (uint64_t) st.st_size;
    } else {
        builtin_error ("unsupported target type (not block dev / regular file)");
        return -1;
    }
    if (g->size_bytes == 0) {
        builtin_error ("target size is zero");
        return -1;
    }
    g->total_sectors = g->size_bytes / g->sector_size;
    if (g->total_sectors < 64) {
        builtin_error ("target too small (%llu sectors)",
                       (unsigned long long) g->total_sectors);
        return -1;
    }
    return 0;
}

static int
bfd_pread_full (int fd, void *buf, size_t len, uint64_t off)
{
    uint8_t *p = (uint8_t *) buf;
    size_t n = 0;
    while (n < len) {
        ssize_t r = pread (fd, p + n, len - n, (off_t) (off + n));
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) { errno = EIO; return -1; }
        n += (size_t) r;
    }
    return 0;
}

static int
bfd_pwrite_full (int fd, const void *buf, size_t len, uint64_t off)
{
    const uint8_t *p = (const uint8_t *) buf;
    size_t n = 0;
    while (n < len) {
        ssize_t w = pwrite (fd, p + n, len - n, (off_t) (off + n));
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) { errno = EIO; return -1; }
        n += (size_t) w;
    }
    return 0;
}

/* ---- Listing ---------------------------------------------------------- */

static void
bfd_print_guid (const uint8_t *g, char *out)
{
    /* Mixed-endian: first three sub-fields swap on print. */
    snprintf (out, 37,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        g[3], g[2], g[1], g[0],
        g[5], g[4],
        g[7], g[6],
        g[8], g[9],
        g[10], g[11], g[12], g[13], g[14], g[15]);
}

static int
bfd_mbr_type_is_extended (uint8_t type)
{
    return type == 0x05 || type == 0x0f || type == 0x85;
}

static void
bfd_print_mbr_row (const char *name, unsigned int partno,
                   uint8_t boot, uint8_t type,
                   uint64_t start, uint64_t sectors)
{
    /* Device paths are arbitrary-length; size the label to fit so a long
     * path overflows the column rather than being silently truncated
     * (matches util-linux fdisk -l, which never clips the device name). */
    size_t need = strlen (name) + 16;
    char *dev_label = (char *) malloc (need);
    if (!dev_label) return;
    snprintf (dev_label, need, "%s%u", name, partno);
    printf ("%-12s %-5s %-12llu %-12llu %-12llu %02x\n",
            dev_label,
            (boot == 0x80) ? "*" : "",
            (unsigned long long) start,
            (unsigned long long) (start + sectors - 1),
            (unsigned long long) sectors,
            type);
    free (dev_label);
}

static int
bfd_list_mbr_logicals (const char *name, int fd, const struct bfd_geom *g,
                       uint64_t ext_base, uint64_t ext_sectors, int *any)
{
    uint64_t ebr_lba = ext_base;
    uint64_t ext_end;
    uint64_t seen[128];
    unsigned int logical_no = 5;
    size_t nseen = 0;

    if (ext_sectors == 0 || ext_base >= g->total_sectors
        || ext_base + ext_sectors < ext_base)
        return 0;
    ext_end = ext_base + ext_sectors;
    if (ext_end > g->total_sectors)
        ext_end = g->total_sectors;

    while (ebr_lba > 0 && ebr_lba < ext_end && logical_no < 1024) {
        for (size_t i = 0; i < nseen; i++) {
            if (seen[i] == ebr_lba) {
                builtin_error ("EBR loop detected at LBA %llu",
                               (unsigned long long) ebr_lba);
                return -1;
            }
        }
        if (nseen < sizeof seen / sizeof seen[0])
            seen[nseen++] = ebr_lba;
        else {
            builtin_error ("too many EBR links");
            return -1;
        }

        uint8_t ebr[512];
        if (bfd_pread_full (fd, ebr, sizeof ebr,
                            ebr_lba * g->sector_size) < 0) {
            builtin_error ("read EBR at LBA %llu: %s",
                           (unsigned long long) ebr_lba, strerror (errno));
            return -1;
        }
        if (ebr[510] != 0x55 || ebr[511] != 0xAA)
            break;

        const uint8_t *logical = ebr + 446;
        uint8_t l_boot = logical[0];
        uint8_t l_type = logical[4];
        uint32_t l_rel_start = bfd_get_le32 (logical + 8);
        uint32_t l_sectors = bfd_get_le32 (logical + 12);
        if (l_type != 0 && l_sectors != 0) {
            uint64_t abs_start = ebr_lba + l_rel_start;
            if (abs_start < ext_base || abs_start >= ext_end
                || abs_start + l_sectors < abs_start
                || abs_start + l_sectors > ext_end) {
                builtin_error ("logical partition %u extends outside extended partition",
                               logical_no);
                return -1;
            }
            *any = 1;
            bfd_print_mbr_row (name, logical_no, l_boot, l_type,
                               abs_start, l_sectors);
        }
        logical_no++;

        const uint8_t *next = ebr + 446 + 16;
        uint8_t n_type = next[4];
        uint32_t n_rel_start = bfd_get_le32 (next + 8);
        uint32_t n_sectors = bfd_get_le32 (next + 12);
        if (!bfd_mbr_type_is_extended (n_type) || n_rel_start == 0 || n_sectors == 0)
            break;
        uint64_t next_lba = ext_base + n_rel_start;
        if (next_lba < ext_base || next_lba >= ext_end
            || next_lba + n_sectors < next_lba
            || next_lba + n_sectors > ext_end) {
            builtin_error ("next EBR link extends outside extended partition");
            return -1;
        }
        ebr_lba = next_lba;
    }
    return 0;
}

static int
bfd_list_mbr (const char *name, int fd, const uint8_t *mbr,
              const struct bfd_geom *g)
{
    printf ("Disk %s: %llu sectors, %llu bytes, sector size %u\n",
            name,
            (unsigned long long) g->total_sectors,
            (unsigned long long) g->size_bytes,
            (unsigned int) g->sector_size);
    printf ("Disklabel: dos\n");
    printf ("%-12s %-5s %-12s %-12s %-12s %-5s\n",
            "Device", "Boot", "Start", "End", "Sectors", "Type");
    int any = 0;
    uint64_t ext_bases[BFD_MBR_PARTS];
    uint64_t ext_sizes[BFD_MBR_PARTS];
    int next_ext = 0;
    for (int i = 0; i < BFD_MBR_PARTS; i++) {
        const uint8_t *p = mbr + 446 + i * 16;
        uint8_t boot = p[0];
        uint8_t type = p[4];
        uint32_t start = bfd_get_le32 (p + 8);
        uint32_t sectors = bfd_get_le32 (p + 12);
        if (type == 0 && start == 0 && sectors == 0) continue;
        any = 1;
        bfd_print_mbr_row (name, (unsigned int) i + 1, boot, type,
                           start, sectors);
        if (bfd_mbr_type_is_extended (type) && sectors != 0
            && next_ext < BFD_MBR_PARTS) {
            ext_bases[next_ext] = start;
            ext_sizes[next_ext] = sectors;
            next_ext++;
        }
    }
    for (int i = 0; i < next_ext; i++)
        if (bfd_list_mbr_logicals (name, fd, g, ext_bases[i], ext_sizes[i], &any) < 0)
            return -1;
    if (!any) printf ("(no MBR partitions)\n");
    return 0;
}

static int
bfd_list_gpt (const char *name, int fd,
              const uint8_t *hdr, const struct bfd_geom *g)
{
    uint32_t hdr_size       = bfd_get_le32 (hdr + 12);
    uint32_t n_parts        = bfd_get_le32 (hdr + 80);
    uint32_t part_entry_len = bfd_get_le32 (hdr + 84);
    uint64_t first_part_lba = bfd_get_le64 (hdr + 72);
    uint64_t first_usable   = bfd_get_le64 (hdr + 40);
    uint64_t last_usable    = bfd_get_le64 (hdr + 48);
    uint32_t pa_crc         = bfd_get_le32 (hdr + 88);
    uint32_t stored_crc     = bfd_get_le32 (hdr + 16);

    /* Verify header CRC: zero the field, hash hdr_size bytes. */
    uint8_t tmp[512];
    if (hdr_size > sizeof tmp) hdr_size = sizeof tmp;
    memcpy (tmp, hdr, hdr_size);
    memset (tmp + 16, 0, 4);
    uint32_t calc_crc = bfd_crc32 (tmp, hdr_size);

    printf ("Disk %s: %llu sectors, %llu bytes, sector size %u\n",
            name,
            (unsigned long long) g->total_sectors,
            (unsigned long long) g->size_bytes,
            (unsigned int) g->sector_size);
    printf ("Disklabel: gpt\n");
    printf ("First usable: %llu  Last usable: %llu  Entries: %u  EntrySize: %u\n",
            (unsigned long long) first_usable,
            (unsigned long long) last_usable,
            n_parts, part_entry_len);
    printf ("Header CRC: %s (stored=%08x calc=%08x)\n",
            (stored_crc == calc_crc) ? "ok" : "BAD",
            stored_crc, calc_crc);

    if (part_entry_len < BFD_GPT_ENTRY_SZ || part_entry_len > BFD_GPT_ENTRY_SZ * 4
        || (part_entry_len % 8) != 0
        || n_parts == 0 || n_parts > 4096) {
        printf ("(entry table parameters out of range; skipping list)\n");
        return 0;
    }

    size_t pa_len = (size_t) n_parts * (size_t) part_entry_len;
    uint8_t *pa = (uint8_t *) calloc (1, pa_len);
    if (!pa) {
        builtin_error ("malloc: %s", strerror (errno));
        return -1;
    }
    if (bfd_pread_full (fd, pa, pa_len,
                        first_part_lba * g->sector_size) < 0) {
        builtin_error ("read partition array: %s", strerror (errno));
        free (pa);
        return -1;
    }
    uint32_t calc_pa = bfd_crc32 (pa, pa_len);
    printf ("Array CRC: %s (stored=%08x calc=%08x)\n",
            (calc_pa == pa_crc) ? "ok" : "BAD",
            pa_crc, calc_pa);

    printf ("%-12s %-12s %-12s %-12s %-36s %-20s %s\n",
            "Device", "Start", "End", "Sectors", "Type", "Attrs", "Name");
    int any = 0;
    for (uint32_t i = 0; i < n_parts; i++) {
        const uint8_t *e = pa + i * part_entry_len;
        int empty = 1;
        for (int k = 0; k < 16; k++) if (e[k]) { empty = 0; break; }
        if (empty) continue;
        any = 1;
        uint64_t s = bfd_get_le64 (e + 32);
        uint64_t en = bfd_get_le64 (e + 40);
        uint64_t attrs = bfd_get_le64 (e + 48);
        char guid[40];
        bfd_print_guid (e, guid);
        char attrbuf[160];
        bfd_format_gpt_attrs (attrs, attrbuf, sizeof attrbuf);
        char nm[64]; size_t nl = 0;
        for (int k = 0; k < 36 && nl + 1 < sizeof nm; k++) {
            uint16_t w = bfd_get_le16 (e + 56 + k * 2);
            if (w == 0) break;
            nm[nl++] = (w < 0x80) ? (char) w : '?';
        }
        nm[nl] = '\0';
        /* Size the device label to the path length (see bfd_print_mbr_row):
         * never truncate the device name in the listing. */
        size_t need = strlen (name) + 16;
        char *dev_label = (char *) malloc (need);
        if (!dev_label) { free (pa); return -1; }
        snprintf (dev_label, need, "%s%u", name, i + 1);
        printf ("%-12s %-12llu %-12llu %-12llu %-36s %-20s %s\n",
                dev_label,
                (unsigned long long) s,
                (unsigned long long) en,
                (unsigned long long) (en >= s ? en - s + 1 : 0),
                guid, attrbuf, nm);
        free (dev_label);
    }
    if (!any) printf ("(no GPT partitions)\n");
    free (pa);
    return 0;
}

static int
bfd_list_one (const char *path)
{
    int fd = open (path, O_RDONLY);
    if (fd < 0) {
        builtin_error ("%s: %s", path, strerror (errno));
        return -1;
    }
    struct bfd_geom g;
    if (bfd_probe_geom (fd, &g) < 0) { close (fd); return -1; }

    uint8_t sec0[512];
    if (bfd_pread_full (fd, sec0, sizeof sec0, 0) < 0) {
        builtin_error ("read MBR: %s", strerror (errno));
        close (fd); return -1;
    }
    int has_mbr_sig = (sec0[510] == 0x55 && sec0[511] == 0xAA);

    /* Probe GPT: protective MBR has type 0xEE in partition slot 1. */
    int has_protective = has_mbr_sig && (sec0[446 + 4] == 0xEE);
    int rc = 0;
    if (has_protective) {
        uint8_t hdr[512];
        if (bfd_pread_full (fd, hdr, sizeof hdr,
                            (uint64_t) BFD_GPT_PRIMARY_LBA * g.sector_size) < 0) {
            builtin_error ("read GPT header: %s", strerror (errno));
            close (fd); return -1;
        }
        if (bfd_get_le64 (hdr) == BFD_GPT_SIG) {
            rc = bfd_list_gpt (path, fd, hdr, &g);
        } else {
            printf ("(protective MBR detected but no valid GPT header at LBA 1)\n");
            rc = -1;
        }
    } else if (has_mbr_sig) {
        rc = bfd_list_mbr (path, fd, sec0, &g);
    } else {
        printf ("Disk %s: no partition table (no MBR signature)\n", path);
    }
    close (fd);
    return rc;
}

/* =====================================================================
 * v2 canonical table model (Phase 1.A spine)
 *
 * struct bfd_table is the in-memory representation that every mutating
 * verb will eventually load -> mutate -> serialize through. Phase 1.A
 * adds this spine *additively*: existing v1 verbs still operate via
 * direct per-verb sector I/O. The hidden --debug-roundtrip verb
 * exercises the load + serialize path so the round-trip-byte-identical
 * contract can be regression-tested before any v1 verb is migrated.
 *
 * Design reference:
 *   research/bash-os/BASHFDISK-FULL-PARITY-DESIGN.md
 *
 * Phase 1.A acceptance: for every v1-produced disk image (MBR-only,
 * MBR with extended/logical chain, GPT), bfd_table_load followed by
 * bfd_table_serialize MUST produce a byte-identical disk image.
 * ===================================================================== */

enum bfd_label { BFD_LABEL_NONE, BFD_LABEL_MBR, BFD_LABEL_GPT };

struct bfd_part {
    /* common */
    int      used;
    uint64_t start_lba;
    uint64_t sectors;

    /* MBR-only */
    uint8_t  mbr_type;
    int      boot;
    int      is_extended;
    int      is_logical;
    uint64_t ebr_lba;
    uint8_t  mbr_chs_first[3];
    uint8_t  mbr_chs_last[3];

    /* GPT-only */
    uint8_t  type_guid[16];
    uint8_t  part_guid[16];
    uint64_t attrs;
    uint16_t name[36];
};

struct bfd_table {
    enum bfd_label label;
    struct bfd_geom geom;

    /* MBR-shape view */
    struct bfd_part  primary[BFD_MBR_PARTS];
    struct bfd_part *logicals;
    size_t           nlogicals;
    size_t           nlogicals_cap;
    int              ext_index;        /* -1 or index into primary[] */
    uint8_t          raw_mbr[512];     /* round-trip preservation */
    /* EBR sectors present on disk at load time. On rewrite, any of these
     * not reused by the new chain is zeroed so no stale 0x55AA EBR
     * signatures linger (matches util-linux compact/reorder cleanup). */
    uint64_t         loaded_ebr_lba[128];
    size_t           n_loaded_ebr;

    /* GPT-shape view */
    struct bfd_part  gpt[BFD_GPT_PARTS];
    uint8_t          disk_guid[16];
    uint32_t         gpt_revision;
    uint32_t         gpt_n_parts;      /* what header said (default 128) */
    uint32_t         gpt_entry_size;   /* what header said (default 128) */
    uint64_t         gpt_first_usable;
    uint64_t         gpt_last_usable;
    uint64_t         gpt_primary_array_lba;
    uint64_t         gpt_backup_array_lba;
    uint64_t         gpt_backup_header_lba;
    uint8_t          gpt_pmbr[512];    /* preserved protective MBR */
    /* Set when the primary GPT header was corrupt and the table was
     * recovered from the backup header at load time (Q6). A recovered
     * table refuses to serialize unless --repair is in effect, so a
     * mutating verb can't silently paper over underlying corruption. */
    int              gpt_recovered;

    int              dirty;
};

/* --- table lifecycle --- */

static void
bfd_table_init (struct bfd_table *tbl)
{
    memset (tbl, 0, sizeof *tbl);
    tbl->label = BFD_LABEL_NONE;
    tbl->ext_index = -1;
    tbl->gpt_revision = BFD_GPT_REVISION;
    tbl->gpt_n_parts = BFD_GPT_PARTS;
    tbl->gpt_entry_size = BFD_GPT_ENTRY_SZ;
}

static void
bfd_table_release (struct bfd_table *tbl)
{
    if (!tbl) return;
    free (tbl->logicals);
    tbl->logicals = NULL;
    tbl->nlogicals = 0;
    tbl->nlogicals_cap = 0;
}

static int
bfd_table_grow_logicals (struct bfd_table *tbl)
{
    size_t want = tbl->nlogicals_cap ? tbl->nlogicals_cap * 2 : 16;
    if (want > 127) want = 127;
    if (want == tbl->nlogicals_cap) return -1;
    struct bfd_part *nl = (struct bfd_part *)
        realloc (tbl->logicals, want * sizeof *nl);
    if (!nl) return -1;
    memset (nl + tbl->nlogicals_cap, 0,
            (want - tbl->nlogicals_cap) * sizeof *nl);
    tbl->logicals = nl;
    tbl->nlogicals_cap = want;
    return 0;
}

/* --- table load: MBR --- */

static int
bfd_table_load_ebr_chain (int fd, struct bfd_table *tbl,
                          uint64_t ext_base, uint64_t ext_sectors)
{
    uint64_t ext_end;
    uint64_t ebr_lba = ext_base;
    uint64_t seen[128];
    size_t nseen = 0;

    if (ext_sectors == 0 || ext_base >= tbl->geom.total_sectors
        || ext_base + ext_sectors < ext_base)
        return 0;
    ext_end = ext_base + ext_sectors;
    if (ext_end > tbl->geom.total_sectors)
        ext_end = tbl->geom.total_sectors;

    while (ebr_lba > 0 && ebr_lba < ext_end) {
        for (size_t i = 0; i < nseen; i++) {
            if (seen[i] == ebr_lba) {
                builtin_error ("EBR loop detected at LBA %llu",
                               (unsigned long long) ebr_lba);
                return -1;
            }
        }
        if (nseen >= sizeof seen / sizeof seen[0]) {
            builtin_error ("too many EBR links");
            return -1;
        }
        seen[nseen++] = ebr_lba;

        uint8_t ebr[512];
        if (bfd_pread_full (fd, ebr, sizeof ebr,
                            ebr_lba * tbl->geom.sector_size) < 0) {
            builtin_error ("read EBR at LBA %llu: %s",
                           (unsigned long long) ebr_lba, strerror (errno));
            return -1;
        }
        if (ebr[510] != 0x55 || ebr[511] != 0xAA)
            break;

        /* Record this EBR sector so a later rewrite can zero it if the
         * new chain no longer uses it. */
        if (tbl->n_loaded_ebr
            < sizeof tbl->loaded_ebr_lba / sizeof tbl->loaded_ebr_lba[0])
            tbl->loaded_ebr_lba[tbl->n_loaded_ebr++] = ebr_lba;

        const uint8_t *lo = ebr + 446;
        uint8_t l_boot = lo[0];
        uint8_t l_type = lo[4];
        uint32_t l_rel_start = bfd_get_le32 (lo + 8);
        uint32_t l_sectors = bfd_get_le32 (lo + 12);
        /* Append one node per chain EBR. A node with a populated data slot
         * is a live logical (used=1); an empty data slot is a TOMBSTONE
         * (used=0) — an emptied-but-still-numbered slot left by a prior
         * non-compact --delete. Loading tombstones preserves the chain's
         * by-position numbering so the spine delete verbs match the v1
         * in-place semantics. */
        {
            int has_data = (l_type != 0 && l_sectors != 0);
            uint64_t abs_start = ebr_lba + l_rel_start;
            if (has_data
                && (abs_start < ext_base || abs_start >= ext_end
                    || abs_start + l_sectors < abs_start
                    || abs_start + l_sectors > ext_end)) {
                builtin_error ("logical partition extends outside extended");
                return -1;
            }
            if (tbl->nlogicals == tbl->nlogicals_cap
                && bfd_table_grow_logicals (tbl) < 0) {
                builtin_error ("too many logicals or out of memory");
                return -1;
            }
            struct bfd_part *p = &tbl->logicals[tbl->nlogicals++];
            memset (p, 0, sizeof *p);
            p->is_logical = 1;
            p->ebr_lba = ebr_lba;
            if (has_data) {
                p->used = 1;
                p->start_lba = abs_start;
                p->sectors = l_sectors;
                p->mbr_type = l_type;
                p->boot = (l_boot == 0x80) ? 1 : 0;
                memcpy (p->mbr_chs_first, lo + 1, 3);
                memcpy (p->mbr_chs_last, lo + 5, 3);
            }
            /* else: tombstone — used stays 0, start/sectors/type 0. */
        }

        const uint8_t *nx = ebr + 446 + 16;
        uint8_t n_type = nx[4];
        uint32_t n_rel_start = bfd_get_le32 (nx + 8);
        uint32_t n_sectors = bfd_get_le32 (nx + 12);
        if (!bfd_mbr_type_is_extended (n_type) || n_rel_start == 0
            || n_sectors == 0)
            break;
        uint64_t next_lba = ext_base + n_rel_start;
        if (next_lba < ext_base || next_lba >= ext_end
            || next_lba + n_sectors < next_lba
            || next_lba + n_sectors > ext_end) {
            builtin_error ("next EBR link extends outside extended");
            return -1;
        }
        ebr_lba = next_lba;
    }
    return 0;
}

static int
bfd_table_load_mbr (int fd, struct bfd_table *tbl)
{
    /* raw_mbr already populated in bfd_table_load */
    const uint8_t *mbr = tbl->raw_mbr;
    int next_ext = -1;
    for (int i = 0; i < BFD_MBR_PARTS; i++) {
        const uint8_t *p = mbr + 446 + i * 16;
        uint8_t boot = p[0];
        uint8_t type = p[4];
        uint32_t start = bfd_get_le32 (p + 8);
        uint32_t sectors = bfd_get_le32 (p + 12);
        struct bfd_part *out = &tbl->primary[i];
        memset (out, 0, sizeof *out);
        if (type == 0 && start == 0 && sectors == 0) {
            out->used = 0;
            continue;
        }
        out->used = 1;
        out->mbr_type = type;
        out->boot = (boot == 0x80) ? 1 : 0;
        out->start_lba = start;
        out->sectors = sectors;
        memcpy (out->mbr_chs_first, p + 1, 3);
        memcpy (out->mbr_chs_last, p + 5, 3);
        if (bfd_mbr_type_is_extended (type)) {
            out->is_extended = 1;
            if (next_ext < 0) {
                next_ext = i;
                tbl->ext_index = i;
                if (bfd_table_load_ebr_chain (fd, tbl, start, sectors) < 0)
                    return -1;
            }
        }
    }
    return 0;
}

/* --- table load: GPT --- */

/* Parse one GPT header (primary or backup) + its partition array into
 * tbl. Validates the GPT signature, header CRC, and array CRC. Returns 0
 * on success, -1 if anything is bad — WITHOUT emitting a diagnostic, so
 * the caller can silently fall back to the other header (Q6 recovery). */
static int
bfd_gpt_load_from_header (int fd, struct bfd_table *tbl, const uint8_t *hdr)
{
    uint32_t hdr_size       = bfd_get_le32 (hdr + 12);
    uint32_t stored_crc     = bfd_get_le32 (hdr + 16);
    uint64_t backup_lba     = bfd_get_le64 (hdr + 32);
    uint64_t first_usable   = bfd_get_le64 (hdr + 40);
    uint64_t last_usable    = bfd_get_le64 (hdr + 48);
    uint64_t first_part_lba = bfd_get_le64 (hdr + 72);
    uint32_t n_parts        = bfd_get_le32 (hdr + 80);
    uint32_t part_entry_len = bfd_get_le32 (hdr + 84);
    uint32_t pa_crc         = bfd_get_le32 (hdr + 88);

    if (bfd_get_le64 (hdr) != BFD_GPT_SIG) return -1;
    if (hdr_size < BFD_GPT_HDR_SIZE || hdr_size > 512) return -1;
    uint8_t tmp[512];
    memcpy (tmp, hdr, hdr_size);
    memset (tmp + 16, 0, 4);
    if (bfd_crc32 (tmp, hdr_size) != stored_crc) return -1;
    if (part_entry_len < BFD_GPT_ENTRY_SZ || part_entry_len > BFD_GPT_ENTRY_SZ * 4
        || (part_entry_len % 8) != 0
        || n_parts == 0 || n_parts > 4096) return -1;

    uint64_t pa_bytes = (uint64_t) n_parts * part_entry_len;
    uint64_t pa_sectors = (pa_bytes + tbl->geom.sector_size - 1)
                          / tbl->geom.sector_size;
    size_t pa_len = (size_t) n_parts * (size_t) part_entry_len;
    uint8_t *pa = (uint8_t *) calloc (1, pa_len);
    if (!pa) { builtin_error ("malloc: %s", strerror (errno)); return -1; }
    if (bfd_pread_full (fd, pa, pa_len,
                        first_part_lba * tbl->geom.sector_size) < 0
        || bfd_crc32 (pa, pa_len) != pa_crc) {
        free (pa);
        return -1;
    }

    tbl->label = BFD_LABEL_GPT;
    tbl->gpt_revision = bfd_get_le32 (hdr + 8);
    tbl->gpt_n_parts = n_parts;
    tbl->gpt_entry_size = part_entry_len;
    tbl->gpt_first_usable = first_usable;
    tbl->gpt_last_usable = last_usable;
    tbl->gpt_primary_array_lba = first_part_lba;
    tbl->gpt_backup_header_lba = backup_lba;
    tbl->gpt_backup_array_lba = (backup_lba >= pa_sectors)
                              ? backup_lba - pa_sectors : 0;
    memcpy (tbl->disk_guid, hdr + 56, 16);

    uint32_t cap_parts = n_parts > BFD_GPT_PARTS ? BFD_GPT_PARTS : n_parts;
    for (uint32_t i = 0; i < cap_parts; i++) {
        const uint8_t *e = pa + (size_t) i * (size_t) part_entry_len;
        int empty = 1;
        for (int k = 0; k < 16; k++) if (e[k]) { empty = 0; break; }
        struct bfd_part *out = &tbl->gpt[i];
        memset (out, 0, sizeof *out);
        if (empty) { out->used = 0; continue; }
        out->used = 1;
        memcpy (out->type_guid, e, 16);
        memcpy (out->part_guid, e + 16, 16);
        uint64_t s = bfd_get_le64 (e + 32);
        uint64_t en = bfd_get_le64 (e + 40);
        out->start_lba = s;
        out->sectors = (en >= s) ? (en - s + 1) : 0;
        out->attrs = bfd_get_le64 (e + 48);
        for (int k = 0; k < 36; k++)
            out->name[k] = bfd_get_le16 (e + 56 + k * 2);
    }
    free (pa);
    return 0;
}

static int
bfd_table_load_gpt (int fd, struct bfd_table *tbl, const uint8_t *hdr)
{
    if (bfd_gpt_load_from_header (fd, tbl, hdr) == 0)
        return 0;

    /* Primary header or array is bad — recover from the backup GPT header
     * at the device tail (LBA total_sectors - 1), per Q6. */
    uint8_t bhdr[512];
    if (tbl->geom.total_sectors < 2
        || bfd_pread_full (fd, bhdr, sizeof bhdr,
                           (tbl->geom.total_sectors - 1)
                           * tbl->geom.sector_size) < 0
        || bfd_gpt_load_from_header (fd, tbl, bhdr) != 0) {
        builtin_error ("GPT primary header is corrupt and the backup header "
                       "could not be used either");
        return -1;
    }

    /* Recovered. The backup header describes the BACKUP locations; reset to
     * the canonical primary layout so a later serialize writes a standard
     * primary array at LBA 2 and a fresh backup at the tail. The entry
     * data, disk GUID, usable range, and entry geometry are already
     * correct (identical in both headers). */
    uint64_t pa_bytes = (uint64_t) tbl->gpt_n_parts * tbl->gpt_entry_size;
    uint64_t pa_sectors = (pa_bytes + tbl->geom.sector_size - 1)
                          / tbl->geom.sector_size;
    tbl->gpt_primary_array_lba = BFD_GPT_PRIMARY_LBA + 1;   /* = 2 */
    tbl->gpt_backup_header_lba = tbl->geom.total_sectors - 1;
    tbl->gpt_backup_array_lba  = tbl->gpt_backup_header_lba - pa_sectors;
    tbl->gpt_recovered = 1;
    builtin_warning ("primary GPT header corrupt; recovered from backup "
                     "(rerun with --repair to rewrite both headers)");
    return 0;
}

/* --- table load: entry point --- */

static int
bfd_table_load (const char *path, struct bfd_table *tbl)
{
    bfd_table_init (tbl);
    int fd = open (path, O_RDONLY);
    if (fd < 0) {
        builtin_error ("%s: %s", path, strerror (errno));
        return -1;
    }
    if (bfd_probe_geom (fd, &tbl->geom) < 0) { close (fd); return -1; }

    if (bfd_pread_full (fd, tbl->raw_mbr, sizeof tbl->raw_mbr, 0) < 0) {
        builtin_error ("read MBR: %s", strerror (errno));
        close (fd); return -1;
    }
    int has_mbr_sig = (tbl->raw_mbr[510] == 0x55 && tbl->raw_mbr[511] == 0xAA);
    int has_protective = has_mbr_sig && (tbl->raw_mbr[446 + 4] == 0xEE);

    int rc = 0;
    if (has_protective) {
        uint8_t hdr[512];
        if (bfd_pread_full (fd, hdr, sizeof hdr,
                            (uint64_t) BFD_GPT_PRIMARY_LBA
                            * tbl->geom.sector_size) < 0) {
            builtin_error ("read GPT header: %s", strerror (errno));
            close (fd); return -1;
        }
        /* Don't hard-fail on a bad primary signature/CRC here — a
         * protective MBR is present, so this is a GPT disk; let
         * bfd_table_load_gpt try the primary header and, failing that,
         * recover from the backup header at the tail (Q6). */
        /* preserve protective MBR verbatim for round-trip */
        memcpy (tbl->gpt_pmbr, tbl->raw_mbr, 512);
        rc = bfd_table_load_gpt (fd, tbl, hdr);
    } else if (has_mbr_sig) {
        tbl->label = BFD_LABEL_MBR;
        rc = bfd_table_load_mbr (fd, tbl);
    } else {
        tbl->label = BFD_LABEL_NONE;
    }
    close (fd);
    if (rc < 0) {
        bfd_table_release (tbl);
        return -1;
    }
    return 0;
}

/* --- table validate --- */

static int
bfd_table_validate (const struct bfd_table *tbl)
{
    if (tbl->label == BFD_LABEL_NONE) {
        builtin_error ("table validate: empty/unknown label");
        return -1;
    }
    if (tbl->label == BFD_LABEL_MBR) {
        int n_ext = 0;
        for (int i = 0; i < BFD_MBR_PARTS; i++) {
            const struct bfd_part *p = &tbl->primary[i];
            if (!p->used) continue;
            if (p->sectors == 0) {
                builtin_error ("MBR primary %d: zero sectors", i + 1);
                return -1;
            }
            if (p->start_lba + p->sectors < p->start_lba
                || p->start_lba + p->sectors > tbl->geom.total_sectors) {
                builtin_error ("MBR primary %d: extends past end", i + 1);
                return -1;
            }
            if (p->is_extended) n_ext++;
        }
        if (n_ext > 1) {
            builtin_error ("MBR has >1 extended container");
            return -1;
        }
        /* primary overlap */
        for (int i = 0; i < BFD_MBR_PARTS; i++) {
            if (!tbl->primary[i].used) continue;
            uint64_t ai = tbl->primary[i].start_lba;
            uint64_t bi = ai + tbl->primary[i].sectors;
            for (int j = i + 1; j < BFD_MBR_PARTS; j++) {
                if (!tbl->primary[j].used) continue;
                uint64_t aj = tbl->primary[j].start_lba;
                uint64_t bj = aj + tbl->primary[j].sectors;
                if (ai < bj && aj < bi) {
                    builtin_error ("MBR primary %d/%d overlap", i + 1, j + 1);
                    return -1;
                }
            }
        }
        /* logicals inside extended, sorted, non-overlap, EBR sector reserved */
        if (tbl->nlogicals > 0) {
            if (tbl->ext_index < 0) {
                builtin_error ("logicals present but no extended container");
                return -1;
            }
            uint64_t ext_base = tbl->primary[tbl->ext_index].start_lba;
            uint64_t ext_end = ext_base
                             + tbl->primary[tbl->ext_index].sectors;
            uint64_t prev_end = ext_base;  /* allow logical 1 EBR at ext_base */
            for (size_t k = 0; k < tbl->nlogicals; k++) {
                const struct bfd_part *l = &tbl->logicals[k];
                if (!l->used) continue;
                if (l->start_lba <= ext_base || l->start_lba >= ext_end
                    || l->start_lba + l->sectors > ext_end
                    || l->start_lba + l->sectors < l->start_lba) {
                    builtin_error ("logical %zu outside extended container",
                                   k + 1);
                    return -1;
                }
                if (l->start_lba < prev_end + 1) {
                    builtin_error ("logical %zu overlaps prior or lacks EBR",
                                   k + 1);
                    return -1;
                }
                prev_end = l->start_lba + l->sectors;
            }
        }
    } else if (tbl->label == BFD_LABEL_GPT) {
        for (uint32_t i = 0; i < BFD_GPT_PARTS; i++) {
            const struct bfd_part *p = &tbl->gpt[i];
            if (!p->used) continue;
            if (p->start_lba < tbl->gpt_first_usable
                || p->start_lba + p->sectors - 1 > tbl->gpt_last_usable) {
                builtin_error ("GPT %u: outside usable LBA range", i + 1);
                return -1;
            }
            for (uint32_t j = i + 1; j < BFD_GPT_PARTS; j++) {
                if (!tbl->gpt[j].used) continue;
                uint64_t ai = p->start_lba;
                uint64_t bi = ai + p->sectors;
                uint64_t aj = tbl->gpt[j].start_lba;
                uint64_t bj = aj + tbl->gpt[j].sectors;
                if (ai < bj && aj < bi) {
                    builtin_error ("GPT %u/%u overlap", i + 1, j + 1);
                    return -1;
                }
            }
        }
    }
    return 0;
}

/* --- table serialize: helpers --- */

static void
bfd_put_mbr_entry_raw (uint8_t *p, uint8_t boot, const uint8_t chs_first[3],
                       uint8_t type, const uint8_t chs_last[3],
                       uint32_t start, uint32_t sectors)
{
    p[0] = boot;
    memcpy (p + 1, chs_first, 3);
    p[4] = type;
    memcpy (p + 5, chs_last, 3);
    bfd_put_le32 (p + 8, start);
    bfd_put_le32 (p + 12, sectors);
}

static int
bfd_table_serialize_mbr (int fd, struct bfd_table *tbl)
{
    /* Build new LBA-0 from preserved raw_mbr (bootloader + disk-sig
     * bytes 0..445 stay; entries + signature rewritten). */
    uint8_t sec0[512];
    memcpy (sec0, tbl->raw_mbr, sizeof sec0);
    memset (sec0 + 446, 0, 64);
    for (int i = 0; i < BFD_MBR_PARTS; i++) {
        const struct bfd_part *p = &tbl->primary[i];
        if (!p->used) continue;
        if (p->start_lba > UINT32_MAX || p->sectors > UINT32_MAX) {
            builtin_error ("MBR primary %d: LBA too large for MBR",
                           i + 1);
            return -1;
        }
        bfd_put_mbr_entry_raw (sec0 + 446 + i * 16,
                               p->boot ? 0x80 : 0x00,
                               p->mbr_chs_first,
                               p->mbr_type,
                               p->mbr_chs_last,
                               (uint32_t) p->start_lba,
                               (uint32_t) p->sectors);
    }
    bfd_put_le16 (sec0 + 510, BFD_MBR_BOOT_SIG);

    /* Serialize the EBR chain first (if there is an extended container).
     * EBR write-order: innermost first (highest LBA), then walk down to
     * ext_base. LBA 0 is written last so a partial write leaves the OS
     * with the prior valid table. The set of EBR LBAs we write is tracked
     * in active[]; any EBR sector present at load time but not reused is
     * zeroed afterwards so no stale 0x55AA signatures linger. */
    if (tbl->ext_index >= 0) {
        uint64_t ext_base = tbl->primary[tbl->ext_index].start_lba;
        uint64_t ext_end = ext_base + tbl->primary[tbl->ext_index].sectors;
        uint64_t active[128];
        size_t   n_active = 0;

        if (tbl->nlogicals == 0) {
            /* Empty extended container: write one clean EBR at ext_base
             * (empty entries + boot signature) so the chain head is valid
             * and no phantom logical is readable. */
            uint8_t ebr[512];
            memset (ebr, 0, sizeof ebr);
            bfd_put_le16 (ebr + 510, BFD_MBR_BOOT_SIG);
            if (bfd_pwrite_full (fd, ebr, sizeof ebr,
                                 ext_base * tbl->geom.sector_size) < 0) {
                builtin_error ("write empty EBR at LBA %llu: %s",
                               (unsigned long long) ext_base,
                               strerror (errno));
                return -1;
            }
            active[n_active++] = ext_base;
        } else {
            /* compute each logical's EBR LBA: logical 1 sits at ext_base;
             * logicals 2..N each have their EBR one sector before data */
            uint64_t *ebr_lbas = (uint64_t *) calloc (tbl->nlogicals,
                                                      sizeof (uint64_t));
            if (!ebr_lbas) {
                builtin_error ("malloc: %s", strerror (errno));
                return -1;
            }
            for (size_t i = 0; i < tbl->nlogicals; i++) {
                /* logical 1's EBR sits at ext_base; a live logical's EBR is
                 * one sector before its data; a tombstone (used==0) has no
                 * data, so keep its EBR at the LBA it loaded from. */
                if (i == 0)
                    ebr_lbas[i] = ext_base;
                else if (tbl->logicals[i].used)
                    ebr_lbas[i] = tbl->logicals[i].start_lba - 1;
                else
                    ebr_lbas[i] = tbl->logicals[i].ebr_lba;
                if (ebr_lbas[i] < ext_base || ebr_lbas[i] >= ext_end
                    || (tbl->logicals[i].used
                        && ebr_lbas[i] >= tbl->logicals[i].start_lba)) {
                    builtin_error ("logical %zu: no room for EBR sector",
                                   i + 1);
                    free (ebr_lbas);
                    return -1;
                }
            }

            /* write EBRs in reverse order (innermost first) */
            for (ssize_t i = (ssize_t) tbl->nlogicals - 1; i >= 0; i--) {
                uint8_t ebr[512];
                memset (ebr, 0, sizeof ebr);
                const struct bfd_part *l = &tbl->logicals[i];
                if (l->used) {
                    uint32_t rel_start =
                        (uint32_t) (l->start_lba - ebr_lbas[i]);
                    bfd_put_mbr_entry_raw (ebr + 446,
                                           l->boot ? 0x80 : 0x00,
                                           l->mbr_chs_first,
                                           l->mbr_type,
                                           l->mbr_chs_last,
                                           rel_start,
                                           (uint32_t) l->sectors);
                }
                /* tombstone: data slot stays zero (emptied-but-numbered) */
                if ((size_t) i + 1 < tbl->nlogicals) {
                    uint32_t next_rel = (uint32_t) (ebr_lbas[i + 1] - ext_base);
                    uint32_t next_size =
                        (uint32_t) (ext_end - ebr_lbas[i + 1]);
                    bfd_put_mbr_entry_raw (ebr + 446 + 16, 0x00,
                                           l->mbr_chs_first,
                                           tbl->primary[tbl->ext_index].mbr_type,
                                           l->mbr_chs_last,
                                           next_rel, next_size);
                }
                bfd_put_le16 (ebr + 510, BFD_MBR_BOOT_SIG);
                if (bfd_pwrite_full (fd, ebr, sizeof ebr,
                                     ebr_lbas[i] * tbl->geom.sector_size) < 0) {
                    builtin_error ("write EBR %zu at LBA %llu: %s",
                                   (size_t) i + 1,
                                   (unsigned long long) ebr_lbas[i],
                                   strerror (errno));
                    free (ebr_lbas);
                    return -1;
                }
            }
            for (size_t i = 0; i < tbl->nlogicals && n_active < 128; i++)
                active[n_active++] = ebr_lbas[i];
            free (ebr_lbas);
        }

        /* Zero any EBR sector present at load but not in the new chain
         * (orphan cleanup). Only touch sectors inside this extended
         * container — EBRs never sit on partition data. */
        for (size_t i = 0; i < tbl->n_loaded_ebr; i++) {
            uint64_t lba = tbl->loaded_ebr_lba[i];
            if (lba < ext_base || lba >= ext_end) continue;
            int reused = 0;
            for (size_t j = 0; j < n_active; j++)
                if (active[j] == lba) { reused = 1; break; }
            if (reused) continue;
            uint8_t zero[512];
            memset (zero, 0, sizeof zero);
            if (bfd_pwrite_full (fd, zero, sizeof zero,
                                 lba * tbl->geom.sector_size) < 0) {
                builtin_error ("zero orphan EBR at LBA %llu: %s",
                               (unsigned long long) lba, strerror (errno));
                return -1;
            }
        }

        if (fsync (fd) < 0) {
            builtin_error ("fsync after EBR chain: %s", strerror (errno));
            return -1;
        }
    }

    if (bfd_pwrite_full (fd, sec0, sizeof sec0, 0) < 0) {
        builtin_error ("write MBR LBA 0: %s", strerror (errno));
        return -1;
    }
    if (fsync (fd) < 0) {
        builtin_error ("fsync after LBA 0: %s", strerror (errno));
        return -1;
    }
    return 0;
}

static int
bfd_table_serialize_gpt (int fd, struct bfd_table *tbl)
{
    uint64_t pa_bytes = (uint64_t) tbl->gpt_n_parts * tbl->gpt_entry_size;
    size_t pa_len = (size_t) pa_bytes;

    uint8_t *pa = (uint8_t *) calloc (1, pa_len);
    if (!pa) {
        builtin_error ("malloc: %s", strerror (errno));
        return -1;
    }
    uint32_t cap_parts = tbl->gpt_n_parts > BFD_GPT_PARTS
                       ? BFD_GPT_PARTS : tbl->gpt_n_parts;
    for (uint32_t i = 0; i < cap_parts; i++) {
        const struct bfd_part *p = &tbl->gpt[i];
        uint8_t *e = pa + (size_t) i * tbl->gpt_entry_size;
        if (!p->used) continue;
        memcpy (e, p->type_guid, 16);
        memcpy (e + 16, p->part_guid, 16);
        bfd_put_le64 (e + 32, p->start_lba);
        bfd_put_le64 (e + 40, p->start_lba + p->sectors - 1);
        bfd_put_le64 (e + 48, p->attrs);
        for (int k = 0; k < 36; k++)
            bfd_put_le16 (e + 56 + k * 2, p->name[k]);
    }
    uint32_t pa_crc = bfd_crc32 (pa, pa_len);

    /* Build primary header. */
    uint8_t hdr[512];
    memset (hdr, 0, sizeof hdr);
    bfd_put_le64 (hdr + 0, BFD_GPT_SIG);
    bfd_put_le32 (hdr + 8, tbl->gpt_revision);
    bfd_put_le32 (hdr + 12, BFD_GPT_HDR_SIZE);
    bfd_put_le32 (hdr + 20, 0);                          /* reserved */
    bfd_put_le64 (hdr + 24, BFD_GPT_PRIMARY_LBA);
    bfd_put_le64 (hdr + 32, tbl->gpt_backup_header_lba);
    bfd_put_le64 (hdr + 40, tbl->gpt_first_usable);
    bfd_put_le64 (hdr + 48, tbl->gpt_last_usable);
    memcpy        (hdr + 56, tbl->disk_guid, 16);
    bfd_put_le64 (hdr + 72, tbl->gpt_primary_array_lba);
    bfd_put_le32 (hdr + 80, tbl->gpt_n_parts);
    bfd_put_le32 (hdr + 84, tbl->gpt_entry_size);
    bfd_put_le32 (hdr + 88, pa_crc);
    uint32_t hdr_crc = bfd_crc32 (hdr, BFD_GPT_HDR_SIZE);
    bfd_put_le32 (hdr + 16, hdr_crc);

    /* Build backup header. */
    uint8_t bhdr[512];
    memcpy (bhdr, hdr, sizeof bhdr);
    bfd_put_le32 (bhdr + 16, 0);
    bfd_put_le64 (bhdr + 24, tbl->gpt_backup_header_lba);
    bfd_put_le64 (bhdr + 32, BFD_GPT_PRIMARY_LBA);
    bfd_put_le64 (bhdr + 72, tbl->gpt_backup_array_lba);
    uint32_t bhdr_crc = bfd_crc32 (bhdr, BFD_GPT_HDR_SIZE);
    bfd_put_le32 (bhdr + 16, bhdr_crc);

    /* Write order: backup-array -> backup-hdr -> primary-array ->
     * primary-hdr -> protective-MBR. Each half ends with fsync. */
    if (bfd_pwrite_full (fd, pa, pa_len,
                         tbl->gpt_backup_array_lba
                         * tbl->geom.sector_size) < 0) {
        builtin_error ("write backup array: %s", strerror (errno));
        free (pa); return -1;
    }
    if (bfd_pwrite_full (fd, bhdr, sizeof bhdr,
                         tbl->gpt_backup_header_lba
                         * tbl->geom.sector_size) < 0) {
        builtin_error ("write backup GPT header: %s", strerror (errno));
        free (pa); return -1;
    }
    if (fsync (fd) < 0) {
        builtin_error ("fsync after backup: %s", strerror (errno));
        free (pa); return -1;
    }
    if (bfd_pwrite_full (fd, pa, pa_len,
                         tbl->gpt_primary_array_lba
                         * tbl->geom.sector_size) < 0) {
        builtin_error ("write primary array: %s", strerror (errno));
        free (pa); return -1;
    }
    if (bfd_pwrite_full (fd, hdr, sizeof hdr,
                         (uint64_t) BFD_GPT_PRIMARY_LBA
                         * tbl->geom.sector_size) < 0) {
        builtin_error ("write primary GPT header: %s", strerror (errno));
        free (pa); return -1;
    }
    /* protective MBR — preserved verbatim from load if available, else
     * build fresh (covers the case where the table was constructed in
     * memory rather than loaded). */
    uint8_t pmbr[512];
    int has_pmbr = 0;
    for (size_t i = 0; i < sizeof tbl->gpt_pmbr; i++)
        if (tbl->gpt_pmbr[i]) { has_pmbr = 1; break; }
    if (has_pmbr) {
        memcpy (pmbr, tbl->gpt_pmbr, 512);
    } else {
        memset (pmbr, 0, sizeof pmbr);
        uint8_t *pe = pmbr + 446;
        pe[0] = 0;
        pe[1] = 0; pe[2] = 0x02; pe[3] = 0;
        pe[4] = 0xEE;
        pe[5] = 0xFF; pe[6] = 0xFF; pe[7] = 0xFF;
        bfd_put_le32 (pe + 8, 1);
        uint64_t pmbr_size = (tbl->geom.total_sectors > UINT32_MAX)
                           ? UINT32_MAX : (tbl->geom.total_sectors - 1);
        bfd_put_le32 (pe + 12, (uint32_t) pmbr_size);
        bfd_put_le16 (pmbr + 510, BFD_MBR_BOOT_SIG);
    }
    if (bfd_pwrite_full (fd, pmbr, sizeof pmbr, 0) < 0) {
        builtin_error ("write protective MBR: %s", strerror (errno));
        free (pa); return -1;
    }
    if (fsync (fd) < 0) {
        builtin_error ("fsync after primary: %s", strerror (errno));
        free (pa); return -1;
    }
    free (pa);
    return 0;
}

static int
bfd_table_serialize (const char *path, struct bfd_table *tbl)
{
    if (bfd_table_validate (tbl) < 0) return -1;
    /* Q6: a GPT table recovered from its backup header reflects a corrupt
     * primary. Refuse to write it (which would paper over the underlying
     * storage corruption) unless the operator opted in with --repair. */
    if (tbl->label == BFD_LABEL_GPT && tbl->gpt_recovered && !bfd_repair) {
        builtin_error ("%s: GPT primary was recovered from backup; rerun "
                       "with --repair to rewrite both headers", path);
        return -1;
    }
    if (bfd_no_act) {
        fprintf (stderr, "fdisk: --no-act: would write %s table to %s "
                 "(not written)\n",
                 tbl->label == BFD_LABEL_MBR ? "MBR" : "GPT", path);
        return 0;
    }
    int fd = open (path, O_RDWR);
    if (fd < 0) {
        builtin_error ("%s: %s", path, strerror (errno));
        return -1;
    }
    int rc;
    if (tbl->label == BFD_LABEL_MBR)
        rc = bfd_table_serialize_mbr (fd, tbl);
    else if (tbl->label == BFD_LABEL_GPT)
        rc = bfd_table_serialize_gpt (fd, tbl);
    else {
        builtin_error ("serialize: empty/unknown label");
        rc = -1;
    }
    if (rc == 0 && tbl->geom.is_block)
        bfd_reread_partitions_if_needed (fd, &tbl->geom);
    close (fd);
    return rc;
}

/* --- hidden --debug-roundtrip verb (Phase 1.A regression tool) ---
 * Loads DEV into a table, then serializes back. Used by the round-
 * trip test to prove byte-identity. Not advertised in --help. */
static int
bfd_debug_roundtrip (const char *path)
{
    struct bfd_table tbl;
    if (bfd_table_load (path, &tbl) < 0) return -1;
    if (tbl.label == BFD_LABEL_NONE) {
        builtin_error ("--debug-roundtrip: no partition table on %s", path);
        bfd_table_release (&tbl);
        return -1;
    }
    int rc = bfd_table_serialize (path, &tbl);
    bfd_table_release (&tbl);
    return rc;
}

/* ---- SPEC parsing ----------------------------------------------------- */

struct bfd_mbr_spec {
    int      have_start;
    int      have_size;
    uint32_t start;
    uint32_t size;
    uint8_t  type;
    int      boot;
};

struct bfd_gpt_spec {
    int      have_start;
    int      have_size;
    uint64_t start;
    uint64_t size;
    uint8_t  type_guid[16];
    uint64_t attrs;
    uint16_t name[36];
};

/* strtoull with full-string check; returns 0 ok, -1 bad. */
static int
bfd_parse_u64 (const char *s, uint64_t *out)
{
    if (!s || !*s) return -1;
    if (!strcmp (s, "+")) return 1; /* sentinel: "default" */
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull (s, &end, 0);
    if (errno || !end || *end || end == s) return -1;
    *out = (uint64_t) v;
    return 0;
}

/* Split SPEC into up to max_fields fields by ','. The first comma may be missing
   (single-token shortcut: "START" alone). Empty fields keep "" so callers
   can detect them. fields[i] points into a private mutable copy stashed
   in *bufp (caller frees). */
static int
bfd_split_spec (const char *spec, char **bufp, char **fields, int max_fields)
{
    char *buf = strdup (spec ? spec : "");
    if (!buf) return -1;
    *bufp = buf;
    int n = 0;
    char *p = buf, *q;
    while (n < max_fields) {
        fields[n++] = p;
        q = strchr (p, ',');
        if (!q) break;
        *q = '\0';
        p = q + 1;
    }
    while (n < max_fields) fields[n++] = (char *) "";
    return 0;
}

static int
bfd_parse_mbr_type (const char *s, uint8_t *out)
{
    if (!s || !*s) { *out = 0x83; return 0; }
    if (!strcmp (s, "linux"))  { *out = 0x83; return 0; }
    if (!strcmp (s, "swap"))   { *out = 0x82; return 0; }
    if (!strcmp (s, "fat32"))  { *out = 0x0c; return 0; }
    if (!strcmp (s, "ntfs"))   { *out = 0x07; return 0; }
    /* hex byte */
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    char *end = NULL;
    unsigned long v = strtoul (s, &end, 16);
    if (!end || *end || end == s || v > 0xff) return -1;
    *out = (uint8_t) v;
    return 0;
}

static int
bfd_parse_mbr_spec_default (const char *spec, struct bfd_mbr_spec *out,
                            uint8_t default_type)
{
    char *buf = NULL, *f[4];
    memset (out, 0, sizeof *out);
    out->type = default_type;
    if (bfd_split_spec (spec, &buf, f, 4) < 0) return -1;

    if (f[0][0]) {
        uint64_t v;
        int rc = bfd_parse_u64 (f[0], &v);
        if (rc < 0 || v > UINT32_MAX) { free (buf); return -1; }
        if (rc == 0) { out->have_start = 1; out->start = (uint32_t) v; }
    }
    if (f[1][0]) {
        uint64_t v;
        int rc = bfd_parse_u64 (f[1], &v);
        if (rc < 0 || v > UINT32_MAX) { free (buf); return -1; }
        if (rc == 0) { out->have_size = 1; out->size = (uint32_t) v; }
    }
    if (bfd_parse_mbr_type (f[2], &out->type) < 0) { free (buf); return -1; }
    if (f[3][0]) {
        if (!strcmp (f[3], "boot") || !strcmp (f[3], "*"))
            out->boot = 1;
        else if (strcmp (f[3], "noboot") && strcmp (f[3], "-")) {
            free (buf); return -1;
        }
    }
    free (buf);
    return 0;
}

static int
bfd_parse_mbr_spec (const char *spec, struct bfd_mbr_spec *out)
{
    return bfd_parse_mbr_spec_default (spec, out, 0x83);
}

static int
bfd_hexnyb (int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int
bfd_parse_guid (const char *s, uint8_t out[16])
{
    /* AABBCCDD-EEFF-GGHH-IIJJ-KKLLMMNNOOPP form. We follow the on-disk
       mixed-endian layout: first three sub-fields are LE byte-reversed,
       last two are stored verbatim. */
    if (!s) return -1;
    /* Strip braces if present. */
    if (s[0] == '{') s++;
    char buf[40];
    size_t i = 0;
    while (*s && i + 1 < sizeof buf) {
        if (*s == '}') break;
        buf[i++] = *s++;
    }
    buf[i] = '\0';
    if (i != 36) return -1;
    if (buf[8] != '-' || buf[13] != '-' || buf[18] != '-' || buf[23] != '-')
        return -1;
    /* Group sizes (in bytes), with the mixed-endian flag. */
    const int groups[][3] = { {0, 4, 1}, {9, 2, 1}, {14, 2, 1},
                              {19, 2, 0}, {24, 6, 0} };
    int w = 0;
    for (int gi = 0; gi < 5; gi++) {
        int off = groups[gi][0], bytes = groups[gi][1], reverse = groups[gi][2];
        uint8_t tmp[8];
        for (int k = 0; k < bytes; k++) {
            int hi = bfd_hexnyb (buf[off + 2 * k]);
            int lo = bfd_hexnyb (buf[off + 2 * k + 1]);
            if (hi < 0 || lo < 0) return -1;
            tmp[k] = (uint8_t) ((hi << 4) | lo);
        }
        if (reverse)
            for (int k = bytes - 1; k >= 0; k--) out[w++] = tmp[k];
        else
            for (int k = 0; k < bytes; k++) out[w++] = tmp[k];
    }
    return 0;
}

static int
bfd_parse_gpt_type (const char *s, uint8_t out[16])
{
    if (!s || !*s || !strcmp (s, "linux")) {
        memcpy (out, BFD_GPT_LINUX_GUID, 16);
        return 0;
    }
    if (!strcmp (s, "swap")) {
        memcpy (out, BFD_GPT_SWAP_GUID, 16);
        return 0;
    }
    return bfd_parse_guid (s, out);
}

static int
bfd_parse_gpt_attr_token (const char *s, uint64_t *attrs)
{
    if (!s || !*s) return 0;
    if (!strcasecmp (s, "RequiredPartition")) {
        *attrs |= 1ULL << 0;
        return 0;
    }
    if (!strcasecmp (s, "NoBlockIOProtocol")) {
        *attrs |= 1ULL << 1;
        return 0;
    }
    if (!strcasecmp (s, "LegacyBIOSBootable")) {
        *attrs |= 1ULL << 2;
        return 0;
    }
    if (!strncasecmp (s, "GUID:", 5)) {
        uint64_t bit;
        if (bfd_parse_u64 (s + 5, &bit) != 0 || bit < 48 || bit > 63)
            return -1;
        *attrs |= 1ULL << bit;
        return 0;
    }

    uint64_t v;
    if (bfd_parse_u64 (s, &v) == 0) {
        *attrs |= v;
        return 0;
    }
    return -1;
}

static int
bfd_parse_gpt_attrs (const char *s, uint64_t *out)
{
    uint64_t attrs = 0;
    if (!s || !*s) {
        *out = 0;
        return 0;
    }

    char *buf = strdup (s);
    if (!buf) return -1;
    for (char *p = buf; *p; p++) {
        if (*p == '|' || *p == '+') *p = ' ';
    }

    char *save = NULL;
    for (char *tok = strtok_r (buf, " \t\r\n", &save);
         tok;
         tok = strtok_r (NULL, " \t\r\n", &save)) {
        if (bfd_parse_gpt_attr_token (tok, &attrs) < 0) {
            free (buf);
            return -1;
        }
    }
    free (buf);
    *out = attrs;
    return 0;
}

static void
bfd_format_gpt_attrs (uint64_t attrs, char *out, size_t outsz)
{
    if (attrs == 0) {
        snprintf (out, outsz, "-");
        return;
    }

    size_t used = 0;
    used += (size_t) snprintf (out + used, (used < outsz) ? outsz - used : 0,
                               "0x%016llx",
                               (unsigned long long) attrs);
#define BFD_APPEND_ATTR(name) \
    do { \
        if (used < outsz) \
            used += (size_t) snprintf (out + used, outsz - used, "|%s", name); \
    } while (0)
    if (attrs & (1ULL << 0)) BFD_APPEND_ATTR ("RequiredPartition");
    if (attrs & (1ULL << 1)) BFD_APPEND_ATTR ("NoBlockIOProtocol");
    if (attrs & (1ULL << 2)) BFD_APPEND_ATTR ("LegacyBIOSBootable");
    for (int bit = 48; bit <= 63; bit++) {
        if (attrs & (1ULL << bit)) {
            char label[16];
            snprintf (label, sizeof label, "GUID:%d", bit);
            BFD_APPEND_ATTR (label);
        }
    }
#undef BFD_APPEND_ATTR
}

static int
bfd_parse_gpt_spec (const char *spec, struct bfd_gpt_spec *out)
{
    char *buf = NULL, *f[5];
    memset (out, 0, sizeof *out);
    memcpy (out->type_guid, BFD_GPT_LINUX_GUID, 16);
    if (bfd_split_spec (spec, &buf, f, 5) < 0) return -1;

    if (f[0][0]) {
        uint64_t v;
        int rc = bfd_parse_u64 (f[0], &v);
        if (rc < 0) { free (buf); return -1; }
        if (rc == 0) { out->have_start = 1; out->start = v; }
    }
    if (f[1][0]) {
        uint64_t v;
        int rc = bfd_parse_u64 (f[1], &v);
        if (rc < 0) { free (buf); return -1; }
        if (rc == 0) { out->have_size = 1; out->size = v; }
    }
    if (bfd_parse_gpt_type (f[2], out->type_guid) < 0) { free (buf); return -1; }
    if (f[3][0]) {
        for (int k = 0; k < 36 && f[3][k]; k++)
            out->name[k] = (uint16_t) (unsigned char) f[3][k];
    }
    if (bfd_parse_gpt_attrs (f[4], &out->attrs) < 0) { free (buf); return -1; }
    free (buf);
    return 0;
}

/* ---- MBR creator ------------------------------------------------------ */

/* The v1 helper bfd_put_mbr_entry (CHS-zero shorthand) was retired in
 * Phase 1.B once create-mbr / create-mbr-extended both routed through
 * bfd_table_serialize, whose bfd_put_mbr_entry_raw preserves loaded
 * CHS bytes (and writes zero for fresh slots — same end state). */

static int
bfd_create_mbr (const char *path, char **specs, int nspecs)
{
    if (nspecs < 1 || nspecs > BFD_MBR_PARTS) {
        builtin_error ("--create-mbr requires 1..%d partition specs",
                       BFD_MBR_PARTS);
        return -1;
    }
    struct bfd_mbr_spec parts[BFD_MBR_PARTS];
    memset (parts, 0, sizeof parts);
    for (int i = 0; i < nspecs; i++) {
        if (bfd_parse_mbr_spec (specs[i], &parts[i]) < 0) {
            builtin_error ("bad MBR spec %d: %s", i + 1, specs[i]);
            return -1;
        }
    }

    int fd = open (path, O_RDWR);
    if (fd < 0) {
        builtin_error ("%s: %s", path, strerror (errno));
        return -1;
    }
    struct bfd_geom g;
    if (bfd_probe_geom (fd, &g) < 0) { close (fd); return -1; }

    /* MBR fields are 32-bit; reject targets larger than ~2 TiB sectors. */
    if (g.total_sectors > UINT32_MAX) {
        builtin_error ("target too large for MBR (>2^32 sectors); use --create-gpt");
        close (fd); return -1;
    }

    /* Resolve START / SIZE defaults left-to-right. */
    uint32_t cursor = BFD_FIRST_USABLE_LBA;
    for (int i = 0; i < nspecs; i++) {
        if (parts[i].have_start) {
            if (parts[i].start < cursor) {
                builtin_error ("MBR spec %d: start %u overlaps prior partition",
                               i + 1, parts[i].start);
                close (fd); return -1;
            }
            cursor = parts[i].start;
        } else {
            parts[i].start = cursor;
        }
        if (!parts[i].have_size) {
            /* Default = remaining; only legal on the last spec. */
            if (i != nspecs - 1) {
                builtin_error ("MBR spec %d: size required (not last)", i + 1);
                close (fd); return -1;
            }
            uint64_t rem = g.total_sectors - parts[i].start;
            if (rem == 0 || rem > UINT32_MAX) {
                builtin_error ("MBR spec %d: no room", i + 1);
                close (fd); return -1;
            }
            parts[i].size = (uint32_t) rem;
        }
        if ((uint64_t) parts[i].start + parts[i].size > g.total_sectors) {
            builtin_error ("MBR spec %d: extends past end of device", i + 1);
            close (fd); return -1;
        }
        cursor = parts[i].start + parts[i].size;
    }

    /* Phase 1.B: route through the canonical table spine instead of a
     * direct LBA-0 write. Build a BFD_LABEL_MBR table from the resolved
     * specs and serialize it. CHS first/last stay zero (bfd_table_init)
     * — same end state as v1's CHS-zero direct write; raw_mbr is zero
     * so LBA-0 bytes 0..445 are zero — byte-identical to the old direct
     * path. bfd_table_serialize owns the fd + post-write partition
     * re-read, so close the probe fd first. */
    close (fd);

    struct bfd_table tbl;
    bfd_table_init (&tbl);
    tbl.label = BFD_LABEL_MBR;
    tbl.geom  = g;
    for (int i = 0; i < nspecs; i++) {
        struct bfd_part *p = &tbl.primary[i];
        p->used      = 1;
        p->start_lba = parts[i].start;
        p->sectors   = parts[i].size;
        p->mbr_type  = parts[i].type;
        p->boot      = parts[i].boot ? 1 : 0;
    }
    int rc = bfd_table_serialize (path, &tbl);
    bfd_table_release (&tbl);
    if (rc < 0)
        return -1;
    bfd_report ("fdisk: wrote MBR with %d partition(s) to %s\n",
             nspecs, path);
    return 0;
}

static int
bfd_create_mbr_extended (const char *path, const char *ext_spec,
                         char **logical_specs, int nlogicals)
{
    if (nlogicals < 1 || nlogicals > 127) {
        builtin_error ("--create-mbr-extended requires 1..127 logical specs");
        return -1;
    }

    struct bfd_mbr_spec ext;
    struct bfd_mbr_spec logicals[127];
    memset (logicals, 0, sizeof logicals);

    if (bfd_parse_mbr_spec_default (ext_spec, &ext, 0x05) < 0) {
        builtin_error ("bad extended MBR spec: %s", ext_spec);
        return -1;
    }
    if (!ext.have_start || !ext.have_size || ext.size == 0) {
        builtin_error ("--create-mbr-extended: EXT_SPEC requires START and SIZE");
        return -1;
    }
    if (!bfd_mbr_type_is_extended (ext.type)) {
        builtin_error ("--create-mbr-extended: EXT_SPEC type must be extended (05/0f/85)");
        return -1;
    }
    if (ext.boot) {
        builtin_error ("--create-mbr-extended: extended container cannot be bootable");
        return -1;
    }

    for (int i = 0; i < nlogicals; i++) {
        if (bfd_parse_mbr_spec (logical_specs[i], &logicals[i]) < 0) {
            builtin_error ("bad logical MBR spec %d: %s", i + 1, logical_specs[i]);
            return -1;
        }
        if (!logicals[i].have_start || !logicals[i].have_size
            || logicals[i].size == 0) {
            builtin_error ("logical MBR spec %d requires START and SIZE", i + 1);
            return -1;
        }
        if (bfd_mbr_type_is_extended (logicals[i].type)) {
            builtin_error ("logical MBR spec %d cannot use an extended type", i + 1);
            return -1;
        }
    }

    int fd = open (path, O_RDWR);
    if (fd < 0) {
        builtin_error ("%s: %s", path, strerror (errno));
        return -1;
    }
    struct bfd_geom g;
    if (bfd_probe_geom (fd, &g) < 0) { close (fd); return -1; }

    if (g.total_sectors > UINT32_MAX) {
        builtin_error ("target too large for MBR (>2^32 sectors); use --create-gpt");
        close (fd); return -1;
    }
    if ((uint64_t) ext.start + ext.size > g.total_sectors) {
        builtin_error ("extended partition extends past end of device");
        close (fd); return -1;
    }

    uint64_t ext_base = ext.start;
    uint64_t ext_end = (uint64_t) ext.start + ext.size;
    uint32_t ebr_lbas[127];
    memset (ebr_lbas, 0, sizeof ebr_lbas);

    for (int i = 0; i < nlogicals; i++) {
        uint64_t start = logicals[i].start;
        uint64_t end = start + logicals[i].size;
        if (end < start || start <= ext_base || end > ext_end) {
            builtin_error ("logical MBR spec %d extends outside extended partition",
                           i + 1);
            close (fd); return -1;
        }
        if (i > 0) {
            uint64_t prev_end = (uint64_t) logicals[i - 1].start
                              + logicals[i - 1].size;
            if (start <= prev_end) {
                builtin_error ("logical MBR spec %d overlaps prior logical partition",
                               i + 1);
                close (fd); return -1;
            }
        }

        uint64_t ebr_lba = (i == 0) ? ext_base : start - 1;
        if (ebr_lba < ext_base || ebr_lba >= ext_end || ebr_lba >= start) {
            builtin_error ("logical MBR spec %d has no room for an EBR sector",
                           i + 1);
            close (fd); return -1;
        }
        if (start - ebr_lba > UINT32_MAX || end - ebr_lba > UINT32_MAX) {
            builtin_error ("logical MBR spec %d is too far from its EBR", i + 1);
            close (fd); return -1;
        }
        if (ebr_lba > UINT32_MAX) {
            builtin_error ("logical MBR spec %d EBR LBA is too large", i + 1);
            close (fd); return -1;
        }
        ebr_lbas[i] = (uint32_t) ebr_lba;
    }

    /* Phase 1.B: route through the canonical table spine instead of
     * direct LBA-0 + per-EBR writes. Build a BFD_LABEL_MBR table with
     * the extended container in primary slot 0 and the logicals (each
     * carrying its already-validated ebr_lba) in the chain. Pre-spine
     * validation above remains because it produces v1-shaped error
     * messages (logical-overlap-prior, EBR-room-32-bit) before
     * bfd_table_validate's coarser refusals fire. */
    close (fd);

    struct bfd_table tbl;
    bfd_table_init (&tbl);
    tbl.label = BFD_LABEL_MBR;
    tbl.geom  = g;
    /* Extended container in primary[0]. */
    tbl.primary[0].used        = 1;
    tbl.primary[0].is_extended = 1;
    tbl.primary[0].mbr_type    = ext.type;
    tbl.primary[0].start_lba   = ext.start;
    tbl.primary[0].sectors     = ext.size;
    tbl.primary[0].boot        = 0;
    tbl.ext_index              = 0;
    (void) ext_end;
    /* Logicals in argv order; each carries its computed EBR LBA. */
    for (int i = 0; i < nlogicals; i++) {
        if (tbl.nlogicals == tbl.nlogicals_cap
            && bfd_table_grow_logicals (&tbl) < 0) {
            builtin_error ("logicals out of memory");
            bfd_table_release (&tbl);
            return -1;
        }
        struct bfd_part *p = &tbl.logicals[tbl.nlogicals++];
        memset (p, 0, sizeof *p);
        p->used       = 1;
        p->is_logical = 1;
        p->start_lba  = logicals[i].start;
        p->sectors    = logicals[i].size;
        p->mbr_type   = logicals[i].type;
        p->boot       = logicals[i].boot ? 1 : 0;
        p->ebr_lba    = ebr_lbas[i];
    }
    int rc = bfd_table_serialize (path, &tbl);
    bfd_table_release (&tbl);
    if (rc < 0)
        return -1;
    bfd_report ("fdisk: wrote fresh MBR extended/logical table to %s\n",
             path);
    return 0;
}

/* ---- GPT creator ------------------------------------------------------ */

/* Derive a stable 16-byte GUID from a (path, index, urandom-or-time) seed.
   Sets the version (v4) and variant nibbles per RFC 4122. We do not require
   crypto-strength randomness; we DO require uniqueness within the table. */
static void
bfd_make_guid (uint8_t out[16], uint64_t seed_a, uint64_t seed_b)
{
    /* xorshift64 mix — same approach as a libuuid uuid_generate_random
       fallback would take when /dev/urandom is missing. */
    uint64_t s = seed_a ^ 0x9E3779B97F4A7C15ULL;
    s ^= s >> 30; s *= 0xBF58476D1CE4E5B9ULL;
    s ^= s >> 27; s *= 0x94D049BB133111EBULL;
    s ^= s >> 31;
    uint64_t t = seed_b ^ 0xC2B2AE3D27D4EB4FULL;
    t ^= t >> 33; t *= 0xBF58476D1CE4E5B9ULL;
    t ^= t >> 29; t *= 0x94D049BB133111EBULL;
    t ^= t >> 32;
    for (int i = 0; i < 8; i++) out[i]     = (uint8_t) (s >> (i * 8));
    for (int i = 0; i < 8; i++) out[8 + i] = (uint8_t) (t >> (i * 8));
    /* Set version=4 / variant=RFC4122. The on-disk byte order makes
       byte 7 = time_hi_and_version high byte and byte 8 = clock_seq_hi. */
    out[7] = (uint8_t) ((out[7] & 0x0F) | 0x40);
    out[8] = (uint8_t) ((out[8] & 0x3F) | 0x80);
}

static int
bfd_create_gpt (const char *path, char **specs, int nspecs)
{
    if (nspecs < 1 || nspecs > BFD_GPT_PARTS) {
        builtin_error ("--create-gpt requires 1..%d partition specs",
                       BFD_GPT_PARTS);
        return -1;
    }
    struct bfd_gpt_spec *parts =
        (struct bfd_gpt_spec *) calloc ((size_t) nspecs, sizeof *parts);
    if (!parts) {
        builtin_error ("malloc: %s", strerror (errno));
        return -1;
    }
    for (int i = 0; i < nspecs; i++) {
        if (bfd_parse_gpt_spec (specs[i], &parts[i]) < 0) {
            builtin_error ("bad GPT spec %d: %s", i + 1, specs[i]);
            free (parts); return -1;
        }
    }

    int fd = open (path, O_RDWR);
    if (fd < 0) {
        builtin_error ("%s: %s", path, strerror (errno));
        free (parts); return -1;
    }
    struct bfd_geom g;
    if (bfd_probe_geom (fd, &g) < 0) { close (fd); free (parts); return -1; }

    /* Layout (all values in logical sectors):
         LBA 0           : protective MBR
         LBA 1           : primary GPT header
         LBA 2 .. 33     : primary partition array (128 entries × 128 B = 16 KiB
                            = 32 sectors at 512 B/s)
         LBA total-33 .. total-2 : backup partition array
         LBA total-1     : backup GPT header
       First usable = 34, last usable = total - 34. */
    uint64_t pa_sectors =
        ((uint64_t) BFD_GPT_PARTS * BFD_GPT_ENTRY_SZ + g.sector_size - 1) / g.sector_size;
    if (g.total_sectors < 2 + 2 * pa_sectors + 2) {
        builtin_error ("target too small for GPT");
        close (fd); free (parts); return -1;
    }
    uint64_t first_usable = 2 + pa_sectors;
    if (first_usable < BFD_FIRST_USABLE_LBA) first_usable = BFD_FIRST_USABLE_LBA;
    uint64_t last_usable  = g.total_sectors - pa_sectors - 2;

    /* Resolve START / SIZE defaults left-to-right. */
    uint64_t cursor = first_usable;
    for (int i = 0; i < nspecs; i++) {
        if (parts[i].have_start) {
            if (parts[i].start < cursor || parts[i].start < first_usable) {
                builtin_error ("GPT spec %d: start %llu < cursor %llu",
                               i + 1,
                               (unsigned long long) parts[i].start,
                               (unsigned long long) cursor);
                close (fd); free (parts); return -1;
            }
            cursor = parts[i].start;
        } else {
            parts[i].start = cursor;
        }
        if (!parts[i].have_size) {
            if (i != nspecs - 1) {
                builtin_error ("GPT spec %d: size required (not last)", i + 1);
                close (fd); free (parts); return -1;
            }
            if (cursor > last_usable) {
                builtin_error ("GPT spec %d: no room", i + 1);
                close (fd); free (parts); return -1;
            }
            parts[i].size = last_usable - cursor + 1;
        }
        if (parts[i].start + parts[i].size - 1 > last_usable) {
            builtin_error ("GPT spec %d: extends past last usable LBA", i + 1);
            close (fd); free (parts); return -1;
        }
        cursor = parts[i].start + parts[i].size;
    }

    /* Phase 1.B: build a fresh BFD_LABEL_GPT table and route through
     * the canonical spine. The on-disk bytes match v1's direct-write
     * exactly because:
     *   - disk_guid and per-partition part_guid use the same
     *     bfd_make_guid seed pairs (size_bytes/total_sectors^0x5A...,
     *     start^i / size^0xA5...).
     *   - n_parts=128, entry_size=128, primary_array_lba=2, plus
     *     first_usable/last_usable/backup_*_lba match v1's layout.
     *   - the spine's "no-loaded-pmbr" path builds the protective MBR
     *     with identical CHS bytes (00/00/02/00 first, FF/FF/FF last)
     *     and identical pmbr_size formula. */
    close (fd);

    struct bfd_table tbl;
    bfd_table_init (&tbl);
    tbl.label = BFD_LABEL_GPT;
    tbl.geom  = g;
    /* bfd_table_init already sets gpt_revision/n_parts/entry_size to
     * the v1 constants; keep that. */
    tbl.gpt_first_usable      = first_usable;
    tbl.gpt_last_usable       = last_usable;
    tbl.gpt_primary_array_lba = 2;
    tbl.gpt_backup_array_lba  = g.total_sectors - 1 - pa_sectors;
    tbl.gpt_backup_header_lba = g.total_sectors - 1;
    bfd_make_guid (tbl.disk_guid,
                   (uint64_t) g.size_bytes,
                   (uint64_t) g.total_sectors ^ 0x5A5A5A5A5A5A5A5AULL);
    for (int i = 0; i < nspecs; i++) {
        struct bfd_part *e = &tbl.gpt[i];
        e->used      = 1;
        memcpy (e->type_guid, parts[i].type_guid, 16);
        bfd_make_guid (e->part_guid,
                       (uint64_t) parts[i].start ^ (uint64_t) i,
                       (uint64_t) parts[i].size ^ 0xA5A5A5A5A5A5A5A5ULL);
        e->start_lba = parts[i].start;
        e->sectors   = parts[i].size;
        e->attrs     = parts[i].attrs;
        memcpy (e->name, parts[i].name, sizeof e->name);
    }
    free (parts);
    int rc = bfd_table_serialize (path, &tbl);
    bfd_table_release (&tbl);
    if (rc < 0)
        return -1;
    bfd_report ("fdisk: wrote GPT with %d partition(s) to %s\n",
             nspecs, path);
    return 0;
}

/* ---- --apply composite verb ------------------------------------------ */

/* Resolve a START token:
 *   "" or "+"  -> auto (sets *is_auto = 1; caller fills from the cursor)
 *   "<n>"      -> absolute LBA (decimal, 0x.. hex, etc. via strtoull base 0)
 * Returns 0 ok, -1 on a malformed token. */
static int
bfd_apply_start_tok (const char *tok, uint64_t *out_lba, int *is_auto)
{
    *is_auto = 0;
    if (!tok || !tok[0] || !strcmp (tok, "+")) { *is_auto = 1; return 0; }
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull (tok, &end, 0);
    if (errno || end == tok || *end) return -1;
    *out_lba = (uint64_t) v;
    return 0;
}

/* Resolve a SIZE token into a sector count:
 *   "" or "+"           -> "remaining" (sets *remaining = 1)
 *   "<n>" / "+<n>"      -> n sectors (leading '+' optional)
 *   "<n>{K,M,G,T,P}"    -> n * 1024^x bytes / sector_size sectors (optional
 *                          leading '+'); the byte size must be a whole
 *                          number of sectors.
 * Returns 0 ok, -1 on a malformed token. */
static int
bfd_apply_size_tok (const char *tok, uint32_t secsize,
                    uint64_t *out_sectors, int *remaining)
{
    *remaining = 0;
    if (!tok || !tok[0] || !strcmp (tok, "+")) { *remaining = 1; return 0; }
    const char *s = tok;
    if (s[0] == '+') s++;
    if (!*s) return -1;

    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull (s, &end, 0);
    if (errno || end == s) return -1;

    uint64_t mult = 0;
    switch (*end) {
        case 'K': case 'k': mult = 1024ULL; break;
        case 'M': case 'm': mult = 1024ULL * 1024; break;
        case 'G': case 'g': mult = 1024ULL * 1024 * 1024; break;
        case 'T': case 't': mult = 1024ULL * 1024 * 1024 * 1024; break;
        case 'P': case 'p': mult = 1024ULL * 1024 * 1024 * 1024 * 1024; break;
        case '\0': mult = 0; break;
        default: return -1;
    }
    if (mult) {
        if (end[1] != '\0') return -1;      /* exactly one unit char */
        if (secsize == 0) return -1;
        uint64_t bytes = (uint64_t) v * mult;
        if (bytes % secsize != 0) return -1; /* whole number of sectors */
        *out_sectors = bytes / secsize;
    } else {
        *out_sectors = (uint64_t) v;
    }
    return 0;
}

/* Find the next unused primary slot (0..3), or -1 if none free. */
static int
bfd_apply_free_primary (const struct bfd_table *tbl)
{
    for (int i = 0; i < BFD_MBR_PARTS; i++)
        if (!tbl->primary[i].used) return i;
    return -1;
}

/* Find the next unused GPT slot (0..n_parts-1), or -1 if none free. */
static int
bfd_apply_free_gpt (const struct bfd_table *tbl)
{
    uint32_t cap = tbl->gpt_n_parts < BFD_GPT_PARTS
                 ? tbl->gpt_n_parts : BFD_GPT_PARTS;
    for (uint32_t i = 0; i < cap; i++)
        if (!tbl->gpt[i].used) return (int) i;
    return -1;
}

/* --apply DEV LABEL SPEC ... — compose a whole partition table from a
 * prefixed spec list and serialize it in one transaction. LABEL is
 * 'mbr' (alias 'dos') or 'gpt'. SPEC grammar:
 *   p:[N:]START,SIZE[,TYPE[,BOOT]]       MBR primary  (N = 1..4)
 *   e:[N:]START,SIZE[,TYPE]              MBR extended container (unique)
 *   l:START,SIZE[,TYPE[,BOOT]]           MBR logical  (must follow an e:)
 *   g:[N:]START,SIZE[,TYPE-GUID[,NAME[,ATTRS]]]  GPT entry (N = 1..128)
 * START: absolute LBA or '+' (next free). SIZE: absolute sectors,
 * '+<n>{K,M,G,T,P}' human size, or '+' (remaining). N: pins an exact
 * slot; otherwise the next free slot is auto-filled. This is the only
 * verb that can place primaries + an extended container + logicals in a
 * single MBR write. Validation (overlap, range, EBR-chain coherence,
 * GPT bounds) is the spine's bfd_table_validate, run by serialize. */
static int
bfd_apply (const char *path, const char *label_s, char **specs, int nspecs,
           int append)
{
    int want_mbr = !strcmp (label_s, "mbr") || !strcmp (label_s, "dos");
    int want_gpt = !strcmp (label_s, "gpt");
    if (!want_mbr && !want_gpt) {
        builtin_error ("--apply: LABEL must be 'mbr' or 'gpt' (got %s)",
                       label_s);
        return -1;
    }
    if (nspecs < 1 || nspecs > BFD_GPT_PARTS) {
        builtin_error ("--apply requires 1..%d SPEC(s)", BFD_GPT_PARTS);
        return -1;
    }

    /* Load the device first — this always gives geometry, and the
     * existing table when --append is in effect. */
    struct bfd_table tbl;
    if (bfd_table_load (path, &tbl) < 0)
        return -1;
    struct bfd_geom g = tbl.geom;
    enum bfd_label label;

    if (append && tbl.label != BFD_LABEL_NONE) {
        /* Append to the existing table: keep its partitions, GPT layout,
         * and MBR bootloader bytes; add the new specs to free slots. */
        label = tbl.label;
        if ((label == BFD_LABEL_MBR && !want_mbr)
            || (label == BFD_LABEL_GPT && !want_gpt)) {
            builtin_error ("--apply --append: existing %s table does not "
                           "match requested label %s",
                           label == BFD_LABEL_MBR ? "mbr" : "gpt", label_s);
            bfd_table_release (&tbl);
            return -1;
        }
    } else {
        /* Fresh table (also --append onto a blank device): discard any
         * existing content but keep the probed geometry. */
        bfd_table_release (&tbl);
        bfd_table_init (&tbl);
        tbl.geom  = g;
        label     = want_mbr ? BFD_LABEL_MBR : BFD_LABEL_GPT;
        tbl.label = label;
        if (label == BFD_LABEL_GPT) {
            uint64_t pa_sectors =
                ((uint64_t) BFD_GPT_PARTS * BFD_GPT_ENTRY_SZ
                 + g.sector_size - 1) / g.sector_size;
            if (g.total_sectors < 2 + 2 * pa_sectors + 2) {
                builtin_error ("--apply: target too small for GPT");
                bfd_table_release (&tbl);
                return -1;
            }
            uint64_t first = 2 + pa_sectors;
            if (first < BFD_FIRST_USABLE_LBA) first = BFD_FIRST_USABLE_LBA;
            tbl.gpt_first_usable      = first;
            tbl.gpt_last_usable       = g.total_sectors - pa_sectors - 2;
            tbl.gpt_primary_array_lba = 2;
            tbl.gpt_backup_array_lba  = g.total_sectors - 1 - pa_sectors;
            tbl.gpt_backup_header_lba = g.total_sectors - 1;
            bfd_make_guid (tbl.disk_guid, (uint64_t) g.size_bytes,
                           (uint64_t) g.total_sectors ^ 0x5A5A5A5A5A5A5A5AULL);
        }
    }

    if (label == BFD_LABEL_MBR && g.total_sectors > UINT32_MAX) {
        builtin_error ("--apply: target too large for MBR (>2^32 sectors); "
                       "use gpt");
        bfd_table_release (&tbl);
        return -1;
    }

    /* Initialise the placement cursors from whatever is already present
     * (all loops are empty for a fresh table). */
    uint64_t gpt_first = 0, gpt_last = 0;
    uint64_t cursor, ext_base = 0, ext_end = 0, log_cursor = 0;
    int      have_ext = 0;
    if (label == BFD_LABEL_GPT) {
        gpt_first = tbl.gpt_first_usable;
        gpt_last  = tbl.gpt_last_usable;
        cursor = gpt_first;
        for (uint32_t k = 0; k < BFD_GPT_PARTS; k++)
            if (tbl.gpt[k].used) {
                uint64_t end = tbl.gpt[k].start_lba + tbl.gpt[k].sectors;
                if (end > cursor) cursor = end;
            }
    } else {
        cursor = BFD_FIRST_USABLE_LBA;
        for (int k = 0; k < BFD_MBR_PARTS; k++)
            if (tbl.primary[k].used) {
                uint64_t end = tbl.primary[k].start_lba
                             + tbl.primary[k].sectors;
                if (end > cursor) cursor = end;
            }
        if (tbl.ext_index >= 0) {
            have_ext   = 1;
            ext_base   = tbl.primary[tbl.ext_index].start_lba;
            ext_end    = ext_base + tbl.primary[tbl.ext_index].sectors;
            log_cursor = ext_base;
            for (size_t k = 0; k < tbl.nlogicals; k++) {
                uint64_t end = tbl.logicals[k].start_lba
                             + tbl.logicals[k].sectors;
                if (end > log_cursor) log_cursor = end;
            }
        }
    }
    int rc = -1;

    for (int i = 0; i < nspecs; i++) {
        const char *tok = specs[i];
        if (strlen (tok) < 2 || tok[1] != ':') {
            builtin_error ("--apply: spec %d missing p:/e:/l:/g: prefix: %s",
                           i + 1, tok);
            goto done;
        }
        char        kind = tok[0];
        const char *rest = tok + 2;

        if (label == BFD_LABEL_MBR
            && !(kind == 'p' || kind == 'e' || kind == 'l')) {
            builtin_error ("--apply: spec %d: '%c:' invalid for mbr "
                           "(use p:/e:/l:)", i + 1, kind);
            goto done;
        }
        if (label == BFD_LABEL_GPT && kind != 'g') {
            builtin_error ("--apply: spec %d: '%c:' invalid for gpt (use g:)",
                           i + 1, kind);
            goto done;
        }

        /* Optional pinned slot "N:" before the comma fields. */
        int           have_slot = 0;
        unsigned long slot = 0;
        const char   *fields = rest;
        const char   *comma = strchr (rest, ',');
        const char   *colon = NULL;
        for (const char *q = rest; *q && (!comma || q < comma); q++)
            if (*q == ':') { colon = q; break; }
        if (colon) {
            char *e2 = NULL;
            errno = 0;
            slot = strtoul (rest, &e2, 10);
            if (errno || e2 != colon || e2 == rest || slot == 0) {
                builtin_error ("--apply: spec %d: bad slot prefix: %s",
                               i + 1, tok);
                goto done;
            }
            have_slot = 1;
            fields = colon + 1;
        }

        char *buf = NULL, *f[5];
        if (bfd_split_spec (fields, &buf, f, 5) < 0) {
            builtin_error ("--apply: out of memory");
            goto done;
        }

        uint64_t start = 0, size = 0;
        int      sauto = 0, srem = 0;
        if (bfd_apply_start_tok (f[0], &start, &sauto) < 0) {
            builtin_error ("--apply: spec %d: bad START: %s", i + 1, f[0]);
            free (buf);
            goto done;
        }
        if (bfd_apply_size_tok (f[1], g.sector_size, &size, &srem) < 0) {
            builtin_error ("--apply: spec %d: bad SIZE: %s", i + 1, f[1]);
            free (buf);
            goto done;
        }

        if (kind == 'g') {
            if (sauto) start = cursor;
            else if (start < gpt_first) {
                builtin_error ("--apply: spec %d: start %llu below first "
                               "usable LBA %llu", i + 1,
                               (unsigned long long) start,
                               (unsigned long long) gpt_first);
                free (buf);
                goto done;
            }
            if (srem) {
                if (start > gpt_last) {
                    builtin_error ("--apply: spec %d: no room", i + 1);
                    free (buf);
                    goto done;
                }
                size = gpt_last - start + 1;
            }
            uint8_t type_guid[16];
            if (bfd_parse_gpt_type (f[2], type_guid) < 0) {
                builtin_error ("--apply: spec %d: bad GPT type: %s",
                               i + 1, f[2]);
                free (buf);
                goto done;
            }
            uint64_t attrs = 0;
            if (bfd_parse_gpt_attrs (f[4], &attrs) < 0) {
                builtin_error ("--apply: spec %d: bad attrs: %s", i + 1, f[4]);
                free (buf);
                goto done;
            }
            int idx;
            if (have_slot) {
                if (slot > tbl.gpt_n_parts || slot > BFD_GPT_PARTS) {
                    builtin_error ("--apply: spec %d: GPT slot %lu out of "
                                   "range", i + 1, slot);
                    free (buf);
                    goto done;
                }
                idx = (int) slot - 1;
                if (tbl.gpt[idx].used) {
                    builtin_error ("--apply: spec %d: GPT slot %lu already "
                                   "assigned", i + 1, slot);
                    free (buf);
                    goto done;
                }
            } else if ((idx = bfd_apply_free_gpt (&tbl)) < 0) {
                builtin_error ("--apply: spec %d: no free GPT slot", i + 1);
                free (buf);
                goto done;
            }
            struct bfd_part *e = &tbl.gpt[idx];
            e->used = 1;
            memcpy (e->type_guid, type_guid, 16);
            bfd_make_guid (e->part_guid,
                           start ^ (uint64_t) idx,
                           size ^ 0xA5A5A5A5A5A5A5A5ULL);
            e->start_lba = start;
            e->sectors   = size;
            e->attrs     = attrs;
            for (int k = 0; k < 36 && f[3][k]; k++)
                e->name[k] = (uint16_t) (unsigned char) f[3][k];
            cursor = start + size;

        } else if (kind == 'p' || kind == 'e') {
            uint8_t type;
            if (bfd_parse_mbr_type (f[2], &type) < 0) {
                builtin_error ("--apply: spec %d: bad MBR type: %s",
                               i + 1, f[2]);
                free (buf);
                goto done;
            }
            if (kind == 'e') {
                if (!f[2][0]) type = 0x05;       /* default extended type */
                if (!bfd_mbr_type_is_extended (type)) {
                    builtin_error ("--apply: spec %d: e: type must be "
                                   "extended (05/0f/85)", i + 1);
                    free (buf);
                    goto done;
                }
                if (have_ext) {
                    builtin_error ("--apply: spec %d: more than one extended "
                                   "container", i + 1);
                    free (buf);
                    goto done;
                }
            } else if (bfd_mbr_type_is_extended (type)) {
                builtin_error ("--apply: spec %d: p: cannot use an extended "
                               "type (use e:)", i + 1);
                free (buf);
                goto done;
            }
            int boot = 0;
            if (f[3][0]) {
                if (!strcmp (f[3], "boot") || !strcmp (f[3], "*")) boot = 1;
                else if (strcmp (f[3], "noboot") && strcmp (f[3], "-")) {
                    builtin_error ("--apply: spec %d: bad BOOT: %s",
                                   i + 1, f[3]);
                    free (buf);
                    goto done;
                }
            }
            if (kind == 'e' && boot) {
                builtin_error ("--apply: spec %d: extended container cannot "
                               "be bootable", i + 1);
                free (buf);
                goto done;
            }
            if (sauto) start = cursor;
            if (srem) {
                if (start >= g.total_sectors) {
                    builtin_error ("--apply: spec %d: no room", i + 1);
                    free (buf);
                    goto done;
                }
                size = g.total_sectors - start;
            }
            int idx;
            if (have_slot) {
                if (slot > BFD_MBR_PARTS) {
                    builtin_error ("--apply: spec %d: MBR slot %lu out of "
                                   "range (1..4)", i + 1, slot);
                    free (buf);
                    goto done;
                }
                idx = (int) slot - 1;
                if (tbl.primary[idx].used) {
                    builtin_error ("--apply: spec %d: MBR slot %lu already "
                                   "assigned", i + 1, slot);
                    free (buf);
                    goto done;
                }
            } else if ((idx = bfd_apply_free_primary (&tbl)) < 0) {
                builtin_error ("--apply: spec %d: no free MBR primary slot",
                               i + 1);
                free (buf);
                goto done;
            }
            struct bfd_part *p = &tbl.primary[idx];
            p->used      = 1;
            p->start_lba = start;
            p->sectors   = size;
            p->mbr_type  = type;
            p->boot      = boot;
            if (kind == 'e') {
                p->is_extended = 1;
                tbl.ext_index  = idx;
                have_ext   = 1;
                ext_base   = start;
                ext_end    = start + size;
                log_cursor = ext_base;        /* first EBR sits at ext_base */
                if (cursor < ext_end) cursor = ext_end;
            } else {
                cursor = start + size;
            }

        } else { /* kind == 'l' */
            if (!have_ext) {
                builtin_error ("--apply: spec %d: l: requires a preceding e: "
                               "extended container", i + 1);
                free (buf);
                goto done;
            }
            uint8_t type;
            if (bfd_parse_mbr_type (f[2], &type) < 0) {
                builtin_error ("--apply: spec %d: bad MBR type: %s",
                               i + 1, f[2]);
                free (buf);
                goto done;
            }
            if (bfd_mbr_type_is_extended (type)) {
                builtin_error ("--apply: spec %d: logical cannot use an "
                               "extended type", i + 1);
                free (buf);
                goto done;
            }
            int boot = 0;
            if (f[3][0]) {
                if (!strcmp (f[3], "boot") || !strcmp (f[3], "*")) boot = 1;
                else if (strcmp (f[3], "noboot") && strcmp (f[3], "-")) {
                    builtin_error ("--apply: spec %d: bad BOOT: %s",
                                   i + 1, f[3]);
                    free (buf);
                    goto done;
                }
            }
            /* Data start: auto packs one sector past the running logical
             * cursor (leaving log_cursor for this logical's EBR sector);
             * absolute uses the given LBA. */
            if (sauto) start = log_cursor + 1;
            if (srem) {
                if (start >= ext_end) {
                    builtin_error ("--apply: spec %d: no room in extended "
                                   "container", i + 1);
                    free (buf);
                    goto done;
                }
                size = ext_end - start;
            }
            if (tbl.nlogicals == tbl.nlogicals_cap
                && bfd_table_grow_logicals (&tbl) < 0) {
                builtin_error ("--apply: out of memory");
                free (buf);
                goto done;
            }
            struct bfd_part *p = &tbl.logicals[tbl.nlogicals++];
            memset (p, 0, sizeof *p);
            p->used       = 1;
            p->is_logical = 1;
            p->start_lba  = start;
            p->sectors    = size;
            p->mbr_type   = type;
            p->boot       = boot;
            p->ebr_lba    = (tbl.nlogicals == 1) ? ext_base : start - 1;
            log_cursor    = start + size;
        }

        free (buf);
    }

    rc = bfd_table_serialize (path, &tbl);

done:
    bfd_table_release (&tbl);
    if (rc < 0)
        return -1;
    bfd_report ("fdisk: applied %d spec(s) to %s as %s\n",
                nspecs, path, label == BFD_LABEL_MBR ? "mbr" : "gpt");
    return 0;
}

/* ---- logical-chain rewrites (Phase 3) -------------------------------- */

/* Sort a table's logicals[] in place by ascending start_lba. The EBR
 * chain order the serializer writes follows this array, and
 * bfd_table_validate requires ascending starts, so every chain rewrite
 * sorts before serializing. */
static void
bfd_sort_logicals (struct bfd_table *tbl)
{
    for (size_t i = 1; i < tbl->nlogicals; i++) {
        struct bfd_part key = tbl->logicals[i];
        size_t j = i;
        while (j > 0 && tbl->logicals[j - 1].start_lba > key.start_lba) {
            tbl->logicals[j] = tbl->logicals[j - 1];
            j--;
        }
        tbl->logicals[j] = key;
    }
}

/* --insert-logical DEV SPEC — splice a new logical partition into an
 * existing MBR extended chain. SPEC = START,SIZE[,TYPE[,BOOT]] with
 * absolute START and SIZE (sectors). The logical is inserted in
 * start-sorted order; the serializer relinks the EBR chain and the
 * partition numbering follows the new sorted order. Data sectors are
 * not moved. */
static int
bfd_insert_logical (const char *path, const char *spec)
{
    struct bfd_mbr_spec s;
    if (bfd_parse_mbr_spec (spec, &s) < 0) {
        builtin_error ("--insert-logical: bad SPEC: %s", spec);
        return -1;
    }
    if (!s.have_start || !s.have_size || s.size == 0) {
        builtin_error ("--insert-logical: SPEC requires absolute START and "
                       "SIZE (got %s)", spec);
        return -1;
    }
    if (bfd_mbr_type_is_extended (s.type)) {
        builtin_error ("--insert-logical: logical cannot use an extended "
                       "type");
        return -1;
    }

    struct bfd_table tbl;
    if (bfd_table_load (path, &tbl) < 0)
        return -1;
    if (tbl.label != BFD_LABEL_MBR || tbl.ext_index < 0) {
        builtin_error ("--insert-logical: no MBR extended container on %s",
                       path);
        bfd_table_release (&tbl);
        return -1;
    }
    uint64_t ext_base = tbl.primary[tbl.ext_index].start_lba;
    uint64_t ext_end  = ext_base + tbl.primary[tbl.ext_index].sectors;
    if (s.start <= ext_base || (uint64_t) s.start + s.size > ext_end) {
        builtin_error ("--insert-logical: %u,%u does not fit inside the "
                       "extended container [%llu,%llu)", s.start, s.size,
                       (unsigned long long) ext_base,
                       (unsigned long long) ext_end);
        bfd_table_release (&tbl);
        return -1;
    }
    /* Overlap against existing logicals (data + the EBR sector each one
     * needs at start-1). */
    uint64_t nstart = s.start, nend = (uint64_t) s.start + s.size;
    for (size_t k = 0; k < tbl.nlogicals; k++) {
        uint64_t es = tbl.logicals[k].start_lba;
        uint64_t ee = es + tbl.logicals[k].sectors;
        if (nstart < ee && es < nend) {
            builtin_error ("--insert-logical: overlaps existing logical "
                           "at %llu", (unsigned long long) es);
            bfd_table_release (&tbl);
            return -1;
        }
    }
    if (tbl.nlogicals >= 127) {
        builtin_error ("--insert-logical: extended chain is full (127)");
        bfd_table_release (&tbl);
        return -1;
    }
    if (tbl.nlogicals == tbl.nlogicals_cap
        && bfd_table_grow_logicals (&tbl) < 0) {
        builtin_error ("--insert-logical: out of memory");
        bfd_table_release (&tbl);
        return -1;
    }
    struct bfd_part *p = &tbl.logicals[tbl.nlogicals++];
    memset (p, 0, sizeof *p);
    p->used       = 1;
    p->is_logical = 1;
    p->start_lba  = s.start;
    p->sectors    = s.size;
    p->mbr_type   = s.type;
    p->boot       = s.boot ? 1 : 0;
    bfd_sort_logicals (&tbl);

    int rc = bfd_table_serialize (path, &tbl);
    bfd_table_release (&tbl);
    if (rc < 0)
        return -1;
    bfd_report ("fdisk: inserted logical %u,%u into %s\n",
                s.start, s.size, path);
    return 0;
}

/* --reorder DEV — sort the MBR logical chain by ascending data start and
 * rewrite the EBR links so partition numbering follows data order.
 * Orphaned EBR sectors from the old order are zeroed by the serializer.
 * Data sectors are not moved. Matches util-linux 'sfdisk -r'. */
static int
bfd_reorder (const char *path)
{
    struct bfd_table tbl;
    if (bfd_table_load (path, &tbl) < 0)
        return -1;
    if (tbl.label != BFD_LABEL_MBR || tbl.ext_index < 0) {
        builtin_error ("--reorder: no MBR extended container on %s", path);
        bfd_table_release (&tbl);
        return -1;
    }
    if (tbl.nlogicals < 2) {
        /* Nothing to reorder, but re-serialize so a clean chain is still
         * written (and any orphan EBRs are swept). */
        bfd_sort_logicals (&tbl);
        int rc0 = bfd_table_serialize (path, &tbl);
        bfd_table_release (&tbl);
        if (rc0 < 0) return -1;
        bfd_report ("fdisk: %s logical chain already ordered\n", path);
        return 0;
    }
    bfd_sort_logicals (&tbl);
    int rc = bfd_table_serialize (path, &tbl);
    bfd_table_release (&tbl);
    if (rc < 0)
        return -1;
    bfd_report ("fdisk: reordered logical chain on %s\n", path);
    return 0;
}

/* ---- In-place mutation helpers --------------------------------------- */

static void
bfd_reread_partitions_if_needed (int fd, const struct bfd_geom *g)
{
    if (!g->is_block)
        return;
    if (ioctl (fd, BLKRRPART) < 0 && errno != EINVAL && errno != ENOTTY)
        fprintf (stderr, "fdisk: BLKRRPART warning: %s\n",
                 strerror (errno));
}

static int
bfd_partx_parse_bound (const char *s, unsigned long *out, const char *name)
{
    char *end = NULL;

    if (s == NULL || *s == '\0') {
        *out = 0;
        return 0;
    }
    errno = 0;
    unsigned long v = strtoul (s, &end, 10);
    if (errno || end == s || *end != '\0' || v > INT_MAX) {
        builtin_error ("--partx-kernel: invalid %s partition number: %s", name, s);
        return -1;
    }
    *out = v;
    return 0;
}

static int
bfd_partx_nr_selected (unsigned int nr, unsigned long min, unsigned long max)
{
    if (min && nr < min)
        return 0;
    if (max && nr > max)
        return 0;
    return 1;
}

static int
bfd_partx_one_ioctl (int fd, int op, unsigned int nr,
                     const struct bfd_part *part,
                     const struct bfd_geom *g)
{
    struct blkpg_partition p;
    struct blkpg_ioctl_arg arg;
    uint64_t start_bytes = 0, length_bytes = 0;

    memset (&p, 0, sizeof p);
    memset (&arg, 0, sizeof arg);
    if (part != NULL) {
        if (part->start_lba > (uint64_t)LLONG_MAX / g->sector_size
            || part->sectors > (uint64_t)LLONG_MAX / g->sector_size) {
            builtin_error ("--partx-kernel: partition %u geometry overflows BLKPG", nr);
            return -1;
        }
        start_bytes = part->start_lba * g->sector_size;
        length_bytes = part->sectors * g->sector_size;
    }
    p.start = (long long)start_bytes;
    p.length = (long long)length_bytes;
    p.pno = (int)nr;
    arg.op = op;
    arg.datalen = (int)sizeof p;
    arg.data = &p;

    if (ioctl (fd, BLKPG, &arg) < 0) {
        builtin_error ("--partx-kernel: BLKPG partition %u: %s", nr, strerror (errno));
        return -1;
    }
    return 0;
}

static int
bfd_partx_visit (int fd, int op, unsigned int nr, const struct bfd_part *part,
                 const struct bfd_geom *g, unsigned long min, unsigned long max,
                 unsigned int *count)
{
    if (!bfd_partx_nr_selected (nr, min, max))
        return 0;
    if (part != NULL && (!part->used || part->sectors == 0))
        return 0;
    if (bfd_no_act) {
        bfd_report ("fdisk: --no-act: would BLKPG partition %u\n", nr);
        (*count)++;
        return 0;
    }
    if (op == BLKPG_RESIZE_PARTITION && part == NULL) {
        builtin_error ("--partx-kernel: update needs partition geometry");
        return -1;
    }
    if (bfd_partx_one_ioctl (fd, op, nr, part, g) < 0)
        return -1;
    (*count)++;
    return 0;
}

static int
bfd_partx_kernel (const char *op_s, const char *path,
                  const char *min_s, const char *max_s)
{
    int op;
    int fd = -1;
    int rc = -1;
    unsigned long min = 0, max = 0;
    unsigned int count = 0;
    struct bfd_table tbl;

    if (!strcmp (op_s, "add"))
        op = BLKPG_ADD_PARTITION;
    else if (!strcmp (op_s, "delete"))
        op = BLKPG_DEL_PARTITION;
    else if (!strcmp (op_s, "update"))
        op = BLKPG_RESIZE_PARTITION;
    else {
        builtin_error ("--partx-kernel: OP must be add, delete, or update");
        return -1;
    }
    if (bfd_partx_parse_bound (min_s, &min, "minimum") < 0
        || bfd_partx_parse_bound (max_s, &max, "maximum") < 0)
        return -1;
    if (min && max && min > max) {
        builtin_error ("--partx-kernel: MIN is greater than MAX");
        return -1;
    }
    if (geteuid () != 0) {
        builtin_error ("--partx-kernel: BLKPG mutation requires uid 0");
        return -1;
    }

    if (bfd_table_load (path, &tbl) < 0)
        return -1;
    if (!tbl.geom.is_block) {
        builtin_error ("--partx-kernel: %s is not a block device", path);
        goto out_table;
    }
    fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        builtin_error ("--partx-kernel: open %s: %s", path, strerror (errno));
        goto out_table;
    }

    if (op == BLKPG_DEL_PARTITION) {
        unsigned int max_nr = 0;
        if (tbl.label == BFD_LABEL_GPT)
            max_nr = tbl.gpt_n_parts < BFD_GPT_PARTS ? tbl.gpt_n_parts : BFD_GPT_PARTS;
        else if (tbl.label == BFD_LABEL_MBR)
            max_nr = (unsigned int)(4 + tbl.nlogicals);
        if (max_nr == 0)
            max_nr = max ? (unsigned int)max : 256;
        if (!max)
            max = max_nr;
        for (unsigned int nr = min ? (unsigned int)min : 1; nr <= max; nr++) {
            if (bfd_partx_visit (fd, op, nr, NULL, &tbl.geom, min, max, &count) < 0)
                goto out;
        }
    } else if (tbl.label == BFD_LABEL_MBR) {
        for (unsigned int i = 0; i < BFD_MBR_PARTS; i++) {
            const struct bfd_part *p = &tbl.primary[i];
            if (bfd_partx_visit (fd, op, i + 1, p, &tbl.geom, min, max, &count) < 0)
                goto out;
        }
        for (size_t i = 0; i < tbl.nlogicals; i++) {
            const struct bfd_part *p = &tbl.logicals[i];
            if (bfd_partx_visit (fd, op, (unsigned int)i + 5, p, &tbl.geom, min, max, &count) < 0)
                goto out;
        }
    } else if (tbl.label == BFD_LABEL_GPT) {
        unsigned int cap = tbl.gpt_n_parts < BFD_GPT_PARTS ? tbl.gpt_n_parts : BFD_GPT_PARTS;
        for (unsigned int i = 0; i < cap; i++) {
            const struct bfd_part *p = &tbl.gpt[i];
            if (bfd_partx_visit (fd, op, i + 1, p, &tbl.geom, min, max, &count) < 0)
                goto out;
        }
    } else {
        builtin_error ("--partx-kernel: no MBR/GPT partition table on %s", path);
        goto out;
    }

    bfd_report ("fdisk: BLKPG %s applied to %u partition(s) on %s\n",
                op_s, count, path);
    rc = 0;

out:
    if (fd >= 0)
        close (fd);
out_table:
    bfd_table_release (&tbl);
    return rc;
}



static int
bfd_delete_partition (const char *path, const char *partno_s)
{
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul (partno_s, &end, 10);
    if (errno || end == partno_s || *end != '\0' || v == 0 || v > UINT32_MAX) {
        builtin_error ("--delete: invalid partition number: %s", partno_s);
        return -1;
    }

    /* All --delete paths route through the table-model spine: MBR-primary
     * and GPT deletes clear a single entry; MBR-logical delete (partno >=
     * 5) marks the chain node a tombstone (gap-preserving — later logicals
     * keep their numbers, unlike --delete-compact which renumbers).
     * serialize rewrites the label/chain accordingly. */
    struct bfd_table tbl;
    if (bfd_table_load (path, &tbl) < 0)
        return -1;
    if (tbl.label == BFD_LABEL_NONE) {
        builtin_error ("--delete: no MBR/GPT partition table signature");
        bfd_table_release (&tbl);
        return -1;
    }

    if (tbl.label == BFD_LABEL_GPT) {
        if (v > BFD_GPT_PARTS || v > tbl.gpt_n_parts) {
            builtin_error ("--delete: GPT partition number must be 1..%u",
                           (unsigned int) (tbl.gpt_n_parts < BFD_GPT_PARTS
                                           ? tbl.gpt_n_parts : BFD_GPT_PARTS));
            bfd_table_release (&tbl);
            return -1;
        }
        if (!tbl.gpt[v - 1].used) {
            builtin_error ("--delete: GPT partition %lu is empty", v);
            bfd_table_release (&tbl);
            return -1;
        }
        memset (&tbl.gpt[v - 1], 0, sizeof tbl.gpt[v - 1]);
        int rc = bfd_table_serialize (path, &tbl);
        bfd_table_release (&tbl);
        if (rc < 0)
            return -1;
        bfd_report ("fdisk: deleted GPT partition %lu from %s\n",
                 v, path);
        return 0;
    }

    /* MBR */
    if (v <= BFD_MBR_PARTS) {
        if (!tbl.primary[v - 1].used) {
            builtin_error ("--delete: MBR partition %lu is empty", v);
            bfd_table_release (&tbl);
            return -1;
        }
        /* If clearing the extended container, drop the in-memory chain
         * so serialize won't try to rewrite EBRs whose ext_index slot
         * is now empty. v1's bfd_delete_mbr_slot leaves orphaned EBR
         * sectors untouched on disk; we just don't reference them
         * (= byte-identical for the LBA-0 write, and orphaned EBR
         * sectors are reachable only via a chain whose root is gone). */
        if (tbl.primary[v - 1].is_extended) {
            tbl.ext_index = -1;
            tbl.nlogicals = 0;
        }
        memset (&tbl.primary[v - 1], 0, sizeof tbl.primary[v - 1]);
        int rc = bfd_table_serialize (path, &tbl);
        bfd_table_release (&tbl);
        if (rc < 0)
            return -1;
        bfd_report ("fdisk: deleted MBR partition %lu from %s\n",
                 v, path);
        return 0;
    }

    /* MBR logical (N>=5): mark the chain node at position N a TOMBSTONE
     * (data slot cleared, EBR + chain link preserved) so later logicals
     * keep their numbers — the gap-preserving contract of v1 --delete —
     * then write via the spine. Tombstones round-trip through
     * bfd_table_load / bfd_table_serialize, so chain position (incl.
     * already-emptied slots) maps directly to logicals[]. */
    size_t lidx = (size_t) (v - 5);
    if (lidx >= tbl.nlogicals) {
        builtin_error ("--delete: MBR logical partition %lu not found", v);
        bfd_table_release (&tbl);
        return -1;
    }
    if (!tbl.logicals[lidx].used) {
        builtin_error ("--delete: MBR logical partition %lu is empty", v);
        bfd_table_release (&tbl);
        return -1;
    }
    tbl.logicals[lidx].used = 0;   /* tombstone (keeps ebr_lba + position) */
    int rc = bfd_table_serialize (path, &tbl);
    bfd_table_release (&tbl);
    if (rc < 0)
        return -1;
    bfd_report ("fdisk: deleted MBR logical partition %lu from %s\n",
                v, path);
    return 0;
}

static int
bfd_delete_partition_compact (const char *path, const char *partno_s)
{
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul (partno_s, &end, 10);
    if (errno || end == partno_s || *end != '\0' || v == 0 || v > UINT32_MAX) {
        builtin_error ("--delete-compact: invalid partition number: %s", partno_s);
        return -1;
    }
    if (v < 5) {
        builtin_error ("--delete-compact: only MBR logical partitions (N >= 5) are supported");
        return -1;
    }

    struct bfd_table tbl;
    if (bfd_table_load (path, &tbl) < 0)
        return -1;
    if (tbl.label == BFD_LABEL_GPT) {
        builtin_error ("--delete-compact: GPT partitions are not supported");
        bfd_table_release (&tbl);
        return -1;
    }
    if (tbl.label != BFD_LABEL_MBR || tbl.ext_index < 0) {
        builtin_error ("--delete-compact: no MBR extended container on %s",
                       path);
        bfd_table_release (&tbl);
        return -1;
    }
    /* Chain position N (incl. tombstones, since load preserves them) maps
     * to logicals[N-5]. A live logical there is removed and the remaining
     * nodes renumber (compact); the dropped node's old EBR is swept by the
     * serializer's orphan-zeroing pass. */
    size_t idx = (size_t) (v - 5);
    if (idx >= tbl.nlogicals || !tbl.logicals[idx].used) {
        builtin_error ("--delete-compact: MBR logical partition %lu is empty",
                       v);
        bfd_table_release (&tbl);
        return -1;
    }
    for (size_t k = idx; k + 1 < tbl.nlogicals; k++)
        tbl.logicals[k] = tbl.logicals[k + 1];
    tbl.nlogicals--;

    int rc = bfd_table_serialize (path, &tbl);
    bfd_table_release (&tbl);
    if (rc < 0)
        return -1;
    bfd_report ("fdisk: compact-deleted MBR logical partition %lu "
                "from %s\n", v, path);
    return 0;
}

static int
bfd_set_gpt_attrs (const char *path, const char *partno_s, const char *attrs_s)
{
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul (partno_s, &end, 10);
    if (errno || end == partno_s || *end != '\0' || v == 0 || v > UINT32_MAX) {
        builtin_error ("--set-attrs: invalid partition number: %s", partno_s);
        return -1;
    }

    uint64_t attrs;
    if (bfd_parse_gpt_attrs (attrs_s, &attrs) < 0) {
        builtin_error ("--set-attrs: invalid GPT attrs: %s", attrs_s);
        return -1;
    }

    /* Phase 1.B: route through the canonical table spine. Load the
     * GPT, mutate gpt[N-1].attrs in memory, then serialize. The
     * serialize path rewrites primary+backup pa+hdr (and re-emits the
     * loaded protective MBR), matching v1's bfd_set_gpt_attrs_slot
     * byte-for-byte because:
     *   - disk_guid / per-part type+part GUIDs / start_lba / sectors
     *     / name / non-changed attrs are all loaded verbatim;
     *   - the GPT header is rebuilt with the same constants
     *     (signature, revision, hdr_size, primary_array_lba,
     *     n_parts, entry_size, first_usable, last_usable,
     *     backup_lba) all loaded from the on-disk header;
     *   - serialize's pa_crc / hdr_crc are freshly computed —
     *     and so are v1's. */

    struct bfd_table tbl;
    if (bfd_table_load (path, &tbl) < 0)
        return -1;
    if (tbl.label != BFD_LABEL_GPT) {
        builtin_error ("--set-attrs: no GPT partition table signature");
        bfd_table_release (&tbl);
        return -1;
    }
    if (v > BFD_GPT_PARTS || v > tbl.gpt_n_parts) {
        builtin_error ("--set-attrs: GPT partition number must be 1..%u",
                       (unsigned int) (tbl.gpt_n_parts < BFD_GPT_PARTS
                                       ? tbl.gpt_n_parts : BFD_GPT_PARTS));
        bfd_table_release (&tbl);
        return -1;
    }
    if (!tbl.gpt[v - 1].used) {
        builtin_error ("--set-attrs: GPT partition %lu is empty", v);
        bfd_table_release (&tbl);
        return -1;
    }
    tbl.gpt[v - 1].attrs = attrs;
    int rc = bfd_table_serialize (path, &tbl);
    bfd_table_release (&tbl);
    if (rc < 0)
        return -1;

    char attrbuf[160];
    bfd_format_gpt_attrs (attrs, attrbuf, sizeof attrbuf);
    bfd_report ("fdisk: set GPT partition %lu attrs to %s on %s\n",
             v, attrbuf, path);
    return 0;
}

/* ====================================================================
 * Phase 2 mutation verbs — each loads the table, mutates a single
 * field, validates, and serializes. Byte-identity with v1 is moot
 * here (these are new verbs), but the serialize path produces a
 * disk image v1's --debug-roundtrip will accept verbatim.
 * ==================================================================== */

/* --activate DEV N {on|off|boot|noboot|1|0} — MBR boot flag toggle.
 * Matches util-linux `sfdisk -A` semantics: setting on clears the
 * boot flag on every other primary (only one active per MBR). */
static int
bfd_activate (const char *path, const char *partno_s, const char *onoff_s)
{
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul (partno_s, &end, 10);
    if (errno || end == partno_s || *end != '\0' || v == 0
        || v > BFD_MBR_PARTS) {
        builtin_error ("--activate: invalid partition number: %s (1..%d)",
                       partno_s, BFD_MBR_PARTS);
        return -1;
    }
    int on;
    if (!strcmp (onoff_s, "on") || !strcmp (onoff_s, "boot")
        || !strcmp (onoff_s, "1") || !strcmp (onoff_s, "*"))
        on = 1;
    else if (!strcmp (onoff_s, "off") || !strcmp (onoff_s, "noboot")
             || !strcmp (onoff_s, "0") || !strcmp (onoff_s, "-"))
        on = 0;
    else {
        builtin_error ("--activate: expected on/off (got %s)", onoff_s);
        return -1;
    }

    struct bfd_table tbl;
    if (bfd_table_load (path, &tbl) < 0)
        return -1;
    if (tbl.label != BFD_LABEL_MBR) {
        builtin_error ("--activate: only MBR labels support the boot flag");
        bfd_table_release (&tbl);
        return -1;
    }
    if (!tbl.primary[v - 1].used) {
        builtin_error ("--activate: MBR partition %lu is empty", v);
        bfd_table_release (&tbl);
        return -1;
    }
    if (on) {
        for (int i = 0; i < BFD_MBR_PARTS; i++)
            tbl.primary[i].boot = 0;
    }
    tbl.primary[v - 1].boot = on;
    int rc = bfd_table_serialize (path, &tbl);
    bfd_table_release (&tbl);
    if (rc < 0)
        return -1;
    bfd_report ("fdisk: %s MBR partition %lu boot flag on %s\n",
             on ? "set" : "cleared", v, path);
    return 0;
}

/* --part-type DEV N TYPE — mutate the partition type byte (MBR) or
 * the type GUID (GPT). MBR primary->extended (or vice versa) toggling
 * is rejected because it would orphan the EBR chain or fabricate one;
 * use --delete + --create-mbr-extended for that transition. Logical
 * partitions (MBR N>=5) cannot adopt an extended type. */
static int
bfd_part_type (const char *path, const char *partno_s, const char *type_s)
{
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul (partno_s, &end, 10);
    if (errno || end == partno_s || *end != '\0' || v == 0
        || v > UINT32_MAX) {
        builtin_error ("--part-type: invalid partition number: %s", partno_s);
        return -1;
    }

    struct bfd_table tbl;
    if (bfd_table_load (path, &tbl) < 0)
        return -1;

    if (tbl.label == BFD_LABEL_MBR) {
        uint8_t new_type;
        if (bfd_parse_mbr_type (type_s, &new_type) < 0) {
            builtin_error ("--part-type: invalid MBR type: %s", type_s);
            bfd_table_release (&tbl);
            return -1;
        }
        if (v <= BFD_MBR_PARTS) {
            if (!tbl.primary[v - 1].used) {
                builtin_error ("--part-type: MBR partition %lu is empty", v);
                bfd_table_release (&tbl);
                return -1;
            }
            int was_ext = tbl.primary[v - 1].is_extended;
            int now_ext = bfd_mbr_type_is_extended (new_type);
            if (was_ext != now_ext) {
                builtin_error ("--part-type: cannot toggle MBR primary "
                               "between extended and data via this verb "
                               "(use --delete + --create-mbr-extended)");
                bfd_table_release (&tbl);
                return -1;
            }
            tbl.primary[v - 1].mbr_type = new_type;
        } else {
            size_t idx = (size_t) (v - 5);
            if (idx >= tbl.nlogicals || !tbl.logicals[idx].used) {
                builtin_error ("--part-type: MBR logical %lu not found", v);
                bfd_table_release (&tbl);
                return -1;
            }
            if (bfd_mbr_type_is_extended (new_type)) {
                builtin_error ("--part-type: logical partition cannot be "
                               "an extended container type");
                bfd_table_release (&tbl);
                return -1;
            }
            tbl.logicals[idx].mbr_type = new_type;
        }
    } else if (tbl.label == BFD_LABEL_GPT) {
        if (v > BFD_GPT_PARTS || v > tbl.gpt_n_parts) {
            builtin_error ("--part-type: GPT partition number must be 1..%u",
                           (unsigned int) (tbl.gpt_n_parts < BFD_GPT_PARTS
                                           ? tbl.gpt_n_parts : BFD_GPT_PARTS));
            bfd_table_release (&tbl);
            return -1;
        }
        if (!tbl.gpt[v - 1].used) {
            builtin_error ("--part-type: GPT partition %lu is empty", v);
            bfd_table_release (&tbl);
            return -1;
        }
        uint8_t guid[16];
        if (bfd_parse_gpt_type (type_s, guid) < 0) {
            builtin_error ("--part-type: invalid GPT type: %s", type_s);
            bfd_table_release (&tbl);
            return -1;
        }
        memcpy (tbl.gpt[v - 1].type_guid, guid, 16);
    } else {
        builtin_error ("--part-type: no MBR/GPT partition table signature");
        bfd_table_release (&tbl);
        return -1;
    }

    int rc = bfd_table_serialize (path, &tbl);
    bfd_table_release (&tbl);
    if (rc < 0)
        return -1;
    bfd_report ("fdisk: set partition %lu type to %s on %s\n",
             v, type_s, path);
    return 0;
}

/* --part-label DEV N NAME — mutate the GPT partition name (UTF-16LE,
 * up to 36 chars). Matches bfd_parse_gpt_spec's encoding: each input
 * byte is cast to uint16_t (US-ASCII passes through; Latin-1 bytes
 * map verbatim). MBR labels are rejected (no name field in MBR
 * entries). Pass an empty string to clear the name. */
static int
bfd_part_label (const char *path, const char *partno_s, const char *name_s)
{
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul (partno_s, &end, 10);
    if (errno || end == partno_s || *end != '\0' || v == 0
        || v > UINT32_MAX) {
        builtin_error ("--part-label: invalid partition number: %s", partno_s);
        return -1;
    }
    size_t nlen = strlen (name_s);
    if (nlen > 36) {
        builtin_error ("--part-label: name too long (max 36 chars): '%s'",
                       name_s);
        return -1;
    }

    struct bfd_table tbl;
    if (bfd_table_load (path, &tbl) < 0)
        return -1;
    if (tbl.label != BFD_LABEL_GPT) {
        builtin_error ("--part-label: only GPT supports partition labels");
        bfd_table_release (&tbl);
        return -1;
    }
    if (v > BFD_GPT_PARTS || v > tbl.gpt_n_parts) {
        builtin_error ("--part-label: GPT partition number must be 1..%u",
                       (unsigned int) (tbl.gpt_n_parts < BFD_GPT_PARTS
                                       ? tbl.gpt_n_parts : BFD_GPT_PARTS));
        bfd_table_release (&tbl);
        return -1;
    }
    if (!tbl.gpt[v - 1].used) {
        builtin_error ("--part-label: GPT partition %lu is empty", v);
        bfd_table_release (&tbl);
        return -1;
    }
    uint16_t *out = tbl.gpt[v - 1].name;
    memset (out, 0, 36 * sizeof (uint16_t));
    for (size_t i = 0; i < nlen; i++)
        out[i] = (uint16_t) (unsigned char) name_s[i];

    int rc = bfd_table_serialize (path, &tbl);
    bfd_table_release (&tbl);
    if (rc < 0)
        return -1;
    bfd_report ("fdisk: set GPT partition %lu label to '%s' on %s\n",
             v, name_s, path);
    return 0;
}

/* --part-uuid DEV N UUID — mutate the GPT partition's unique GUID
 * (gpt[N-1].part_guid). GPT-only; MBR has no per-partition GUID field.
 * UUID is a 36-char canonical GUID string (optionally brace-wrapped),
 * parsed with the same mixed-endian on-disk layout as --create-gpt's
 * TYPE-GUID and --disk-id. */
static int
bfd_part_uuid (const char *path, const char *partno_s, const char *uuid_s)
{
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul (partno_s, &end, 10);
    if (errno || end == partno_s || *end != '\0' || v == 0
        || v > UINT32_MAX) {
        builtin_error ("--part-uuid: invalid partition number: %s", partno_s);
        return -1;
    }

    uint8_t guid[16];
    if (bfd_parse_guid (uuid_s, guid) < 0) {
        builtin_error ("--part-uuid: invalid partition GUID: %s", uuid_s);
        return -1;
    }

    struct bfd_table tbl;
    if (bfd_table_load (path, &tbl) < 0)
        return -1;
    if (tbl.label != BFD_LABEL_GPT) {
        builtin_error ("--part-uuid: only GPT supports per-partition GUIDs");
        bfd_table_release (&tbl);
        return -1;
    }
    if (v > BFD_GPT_PARTS || v > tbl.gpt_n_parts) {
        builtin_error ("--part-uuid: GPT partition number must be 1..%u",
                       (unsigned int) (tbl.gpt_n_parts < BFD_GPT_PARTS
                                       ? tbl.gpt_n_parts : BFD_GPT_PARTS));
        bfd_table_release (&tbl);
        return -1;
    }
    if (!tbl.gpt[v - 1].used) {
        builtin_error ("--part-uuid: GPT partition %lu is empty", v);
        bfd_table_release (&tbl);
        return -1;
    }
    memcpy (tbl.gpt[v - 1].part_guid, guid, 16);

    int rc = bfd_table_serialize (path, &tbl);
    bfd_table_release (&tbl);
    if (rc < 0)
        return -1;
    bfd_report ("fdisk: set GPT partition %lu UUID to %s on %s\n",
             v, uuid_s, path);
    return 0;
}

/* --set-part DEV N SPEC — rewrite ONLY partition N's geometry/type from
 * SPEC, leaving every other slot (and its GPT part-GUID) untouched. Backs
 * sfdisk's `-N N`. SPEC = START,SIZE[,TYPE[,BOOT|NAME]]; an EMPTY field
 * keeps the current value (so you can change just the size, just the
 * type, etc.). START is an absolute LBA; SIZE is absolute sectors or
 * +<n>{K,M,G,T,P}. MBR uses TYPE=hex/alias + BOOT; GPT uses TYPE-GUID +
 * NAME. */
static int
bfd_set_part (const char *path, const char *partno_s, const char *spec)
{
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul (partno_s, &end, 10);
    if (errno || end == partno_s || *end != '\0' || v == 0 || v > UINT32_MAX) {
        builtin_error ("--set-part: invalid partition number: %s", partno_s);
        return -1;
    }

    struct bfd_table tbl;
    if (bfd_table_load (path, &tbl) < 0)
        return -1;

    char *buf = NULL, *f[4];
    if (bfd_split_spec (spec, &buf, f, 4) < 0) {
        builtin_error ("--set-part: out of memory");
        bfd_table_release (&tbl);
        return -1;
    }

    int is_gpt = (tbl.label == BFD_LABEL_GPT);
    struct bfd_part *p = NULL;
    if (is_gpt) {
        if (v > BFD_GPT_PARTS || v > tbl.gpt_n_parts || !tbl.gpt[v - 1].used) {
            builtin_error ("--set-part: GPT partition %lu is empty or out of "
                           "range", v);
            goto bad;
        }
        p = &tbl.gpt[v - 1];
    } else if (tbl.label == BFD_LABEL_MBR) {
        if (v <= BFD_MBR_PARTS) {
            if (!tbl.primary[v - 1].used) {
                builtin_error ("--set-part: MBR partition %lu is empty", v);
                goto bad;
            }
            p = &tbl.primary[v - 1];
        } else {
            size_t idx = (size_t) (v - 5);
            if (idx >= tbl.nlogicals || !tbl.logicals[idx].used) {
                builtin_error ("--set-part: MBR logical %lu not found", v);
                goto bad;
            }
            p = &tbl.logicals[idx];
        }
    } else {
        builtin_error ("--set-part: no MBR/GPT partition table on %s", path);
        goto bad;
    }

    if (f[0][0]) {                    /* START — absolute LBA */
        char *e2 = NULL;
        errno = 0;
        unsigned long long s = strtoull (f[0], &e2, 0);
        if (errno || e2 == f[0] || *e2) {
            builtin_error ("--set-part: bad START: %s", f[0]);
            goto bad;
        }
        p->start_lba = (uint64_t) s;
    }
    if (f[1][0]) {                    /* SIZE — sectors or +<n>{K,M,G,T,P} */
        uint64_t sz;
        int rem;
        if (bfd_apply_size_tok (f[1], tbl.geom.sector_size, &sz, &rem) < 0
            || rem || sz == 0) {
            builtin_error ("--set-part: bad SIZE: %s", f[1]);
            goto bad;
        }
        p->sectors = sz;
    }
    if (f[2][0]) {                    /* TYPE */
        if (is_gpt) {
            uint8_t g[16];
            if (bfd_parse_gpt_type (f[2], g) < 0) {
                builtin_error ("--set-part: bad GPT type: %s", f[2]);
                goto bad;
            }
            memcpy (p->type_guid, g, 16);
        } else {
            uint8_t t;
            if (bfd_parse_mbr_type (f[2], &t) < 0
                || bfd_mbr_type_is_extended (t)) {
                builtin_error ("--set-part: bad or extended MBR type: %s",
                               f[2]);
                goto bad;
            }
            p->mbr_type = t;
        }
    }
    if (f[3][0]) {                    /* GPT NAME, or MBR BOOT flag */
        if (is_gpt) {
            memset (p->name, 0, sizeof p->name);
            for (int k = 0; k < 36 && f[3][k]; k++)
                p->name[k] = (uint16_t) (unsigned char) f[3][k];
        } else if (!strcmp (f[3], "boot") || !strcmp (f[3], "*")) {
            p->boot = 1;
        } else if (!strcmp (f[3], "noboot") || !strcmp (f[3], "-")) {
            p->boot = 0;
        } else {
            builtin_error ("--set-part: bad BOOT flag: %s", f[3]);
            goto bad;
        }
    }
    free (buf);

    int rc = bfd_table_serialize (path, &tbl);
    bfd_table_release (&tbl);
    if (rc < 0)
        return -1;
    bfd_report ("fdisk: updated partition %lu on %s\n", v, path);
    return 0;

bad:
    free (buf);
    bfd_table_release (&tbl);
    return -1;
}

/* --repair DEV — rewrite both GPT headers + arrays fresh from the
 * in-memory table (Q6). Purpose: recover a disk whose primary GPT header
 * is corrupt but whose backup is intact — bfd_table_load recovers from
 * the backup, and serialize (with bfd_repair set) writes a clean primary
 * + backup pair. Idempotent on an already-valid GPT. */
static int
bfd_repair_gpt (const char *path)
{
    bfd_repair = 1;
    struct bfd_table tbl;
    if (bfd_table_load (path, &tbl) < 0)
        return -1;
    if (tbl.label != BFD_LABEL_GPT) {
        builtin_error ("--repair: %s has no GPT table to repair", path);
        bfd_table_release (&tbl);
        return -1;
    }
    int was_recovered = tbl.gpt_recovered;
    int rc = bfd_table_serialize (path, &tbl);
    bfd_table_release (&tbl);
    if (rc < 0)
        return -1;
    if (was_recovered)
        bfd_report ("fdisk: repaired GPT on %s (rewrote primary from "
                    "backup)\n", path);
    else
        bfd_report ("fdisk: rewrote GPT headers on %s (primary was "
                    "already valid)\n", path);
    return 0;
}

/* --verify DEV — load the partition table, run bfd_table_validate,
 * report. Read-only; never writes. Exit success on clean validate,
 * failure with a diagnostic on any issue. */
static int
bfd_verify (const char *path)
{
    struct bfd_table tbl;
    if (bfd_table_load (path, &tbl) < 0)
        return -1;
    if (tbl.label == BFD_LABEL_NONE) {
        builtin_error ("--verify: no MBR/GPT partition table signature");
        bfd_table_release (&tbl);
        return -1;
    }
    int rc = bfd_table_validate (&tbl);
    if (rc == 0) {
        printf ("%s: %s table validates cleanly\n", path,
                tbl.label == BFD_LABEL_MBR ? "MBR" : "GPT");
    }
    bfd_table_release (&tbl);
    return rc;
}

/* --list-free DEV — emit free-LBA ranges between used partitions.
 * For MBR, walks primary slots (logicals are inside the extended
 * container, already covered); for GPT, walks gpt[] across
 * [first_usable, last_usable]. */
struct bfd_range {
    uint64_t start;
    uint64_t sectors;
};

static int
bfd_table_free_ranges (const struct bfd_table *tbl,
                       struct bfd_range *out, size_t cap, size_t *out_n)
{
    *out_n = 0;
    if (tbl->label == BFD_LABEL_NONE)
        return 0;

    /* Collect used. Worst case: 4 MBR + 128 GPT = 132; round up. */
    struct bfd_range used[BFD_MBR_PARTS + BFD_GPT_PARTS + 2];
    size_t nused = 0;
    uint64_t first, last;

    if (tbl->label == BFD_LABEL_MBR) {
        first = BFD_FIRST_USABLE_LBA;
        last = tbl->geom.total_sectors - 1;
        for (int i = 0; i < BFD_MBR_PARTS; i++) {
            if (tbl->primary[i].used) {
                used[nused].start = tbl->primary[i].start_lba;
                used[nused].sectors = tbl->primary[i].sectors;
                nused++;
            }
        }
    } else {
        first = tbl->gpt_first_usable;
        last = tbl->gpt_last_usable;
        for (uint32_t i = 0; i < BFD_GPT_PARTS; i++) {
            if (tbl->gpt[i].used) {
                used[nused].start = tbl->gpt[i].start_lba;
                used[nused].sectors = tbl->gpt[i].sectors;
                nused++;
            }
        }
    }

    /* Insertion sort by start. */
    for (size_t i = 1; i < nused; i++) {
        struct bfd_range key = used[i];
        size_t j = i;
        while (j > 0 && used[j - 1].start > key.start) {
            used[j] = used[j - 1];
            j--;
        }
        used[j] = key;
    }

    uint64_t cursor = first;
    size_t nfree = 0;
    for (size_t i = 0; i < nused; i++) {
        if (used[i].start > cursor && nfree < cap) {
            out[nfree].start = cursor;
            out[nfree].sectors = used[i].start - cursor;
            nfree++;
        }
        uint64_t end = used[i].start + used[i].sectors;
        if (end > cursor)
            cursor = end;
    }
    if (cursor <= last && nfree < cap) {
        out[nfree].start = cursor;
        out[nfree].sectors = last - cursor + 1;
        nfree++;
    }
    *out_n = nfree;
    return 0;
}

static int
bfd_list_free (const char *path)
{
    struct bfd_table tbl;
    if (bfd_table_load (path, &tbl) < 0)
        return -1;
    if (tbl.label == BFD_LABEL_NONE) {
        /* Whole disk is free. */
        printf ("Disk %s: no partition table — entire disk is free\n", path);
        printf ("%-12s %-12s %-12s\n", "Device", "Start", "Sectors");
        printf ("%-12s %-12llu %-12llu\n",
                "(free)", 0ULL,
                (unsigned long long) tbl.geom.total_sectors);
        bfd_table_release (&tbl);
        return 0;
    }

    struct bfd_range ranges[BFD_MBR_PARTS + BFD_GPT_PARTS + 2];
    size_t n = 0;
    if (bfd_table_free_ranges (&tbl, ranges,
                               sizeof ranges / sizeof ranges[0], &n) < 0) {
        bfd_table_release (&tbl);
        return -1;
    }

    printf ("Disk %s: %s table free ranges\n", path,
            tbl.label == BFD_LABEL_MBR ? "MBR" : "GPT");
    printf ("%-12s %-12s %-12s\n", "Device", "Start", "Sectors");
    for (size_t i = 0; i < n; i++) {
        printf ("%-12s %-12llu %-12llu\n",
                "(free)",
                (unsigned long long) ranges[i].start,
                (unsigned long long) ranges[i].sectors);
    }
    if (n == 0)
        printf ("(no free ranges)\n");
    bfd_table_release (&tbl);
    return 0;
}

/* --disk-id DEV [STR] — print (no STR) or set (STR) the on-disk
 * identifier. MBR: 4-byte signature at offset 0x1B8, displayed as
 * 0xNNNNNNNN; set by 8-char hex (optional 0x prefix). GPT: 16-byte
 * disk GUID, displayed as a 36-char canonical form; set by a 36-char
 * GUID string. */
static int
bfd_disk_id (const char *path, const char *new_id)
{
    struct bfd_table tbl;
    if (bfd_table_load (path, &tbl) < 0)
        return -1;
    if (tbl.label == BFD_LABEL_NONE) {
        builtin_error ("--disk-id: no MBR/GPT partition table signature");
        bfd_table_release (&tbl);
        return -1;
    }

    if (!new_id) {
        if (tbl.label == BFD_LABEL_MBR) {
            uint32_t sig = bfd_get_le32 (tbl.raw_mbr + 0x1B8);
            printf ("0x%08x\n", sig);
        } else {
            char guid[40];
            bfd_print_guid (tbl.disk_guid, guid);
            printf ("%s\n", guid);
        }
        bfd_table_release (&tbl);
        return 0;
    }

    if (tbl.label == BFD_LABEL_MBR) {
        const char *s = new_id;
        if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
            s += 2;
        char *end = NULL;
        errno = 0;
        unsigned long sig = strtoul (s, &end, 16);
        if (errno || end == s || *end != '\0' || sig > 0xFFFFFFFFul) {
            builtin_error ("--disk-id: invalid MBR signature: %s "
                           "(expected up to 8 hex chars)", new_id);
            bfd_table_release (&tbl);
            return -1;
        }
        bfd_put_le32 (tbl.raw_mbr + 0x1B8, (uint32_t) sig);
    } else {
        uint8_t guid[16];
        if (bfd_parse_guid (new_id, guid) < 0) {
            builtin_error ("--disk-id: invalid GPT disk GUID: %s", new_id);
            bfd_table_release (&tbl);
            return -1;
        }
        memcpy (tbl.disk_guid, guid, 16);
    }

    int rc = bfd_table_serialize (path, &tbl);
    bfd_table_release (&tbl);
    if (rc < 0)
        return -1;
    bfd_report ("fdisk: set disk-id to %s on %s\n", new_id, path);
    return 0;
}

/* --list-types — informational dump of the partition-type aliases this
 * builtin understands. No DEV argument, no disk I/O. MBR types are the
 * one-byte hex codes accepted by --part-type / --create-mbr; GPT types
 * are the canonical type GUIDs accepted by --part-type / --create-gpt.
 * Any hex byte (MBR) or 36-char GUID (GPT) also works directly. */
static int
bfd_list_types (void)
{
    static const struct { const char *name; uint8_t code; } mbr_types[] = {
        { "linux", 0x83 }, { "swap", 0x82 }, { "fat32", 0x0c },
        { "ntfs", 0x07 },
    };
    static const struct { const char *name; const uint8_t *guid; }
    gpt_types[] = {
        { "linux", BFD_GPT_LINUX_GUID }, { "swap", BFD_GPT_SWAP_GUID },
    };
    char guid[40];

    printf ("MBR partition types (alias -> hex code):\n");
    for (size_t i = 0; i < sizeof mbr_types / sizeof mbr_types[0]; i++)
        printf ("  %-8s %02x\n", mbr_types[i].name, mbr_types[i].code);
    printf ("  (any other 1-byte hex code, e.g. 05/0f/85 extended, also "
            "accepted)\n");

    printf ("\nGPT partition types (alias -> type GUID):\n");
    for (size_t i = 0; i < sizeof gpt_types / sizeof gpt_types[0]; i++) {
        bfd_print_guid (gpt_types[i].guid, guid);
        printf ("  %-8s %s\n", gpt_types[i].name, guid);
    }
    printf ("  (any other 36-char type GUID also accepted)\n");
    return 0;
}

/* ---- interactive UI (Phase 4) ---------------------------------------- */

/* Print PROMPT (if any), read one line from stdin into BUF, strip the
 * trailing newline. Returns BUF, or NULL on EOF (Ctrl-D). The loop and
 * every handler read via this single point so input works under a PTY
 * and under piped/heredoc redirection alike (plain fgets, no readline). */
static char *
bfd_prompt (const char *prompt, char *buf, size_t sz)
{
    if (prompt) { fputs (prompt, stdout); fflush (stdout); }
    if (!fgets (buf, (int) sz, stdin)) return NULL;
    size_t n = strlen (buf);
    while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = '\0';
    return buf;
}

/* Lowest 2048-aligned LBA at/after the end of the highest-ending used
 * primary (never below the 2048 first-usable LBA). Interactive default
 * for a new primary's first sector; the user may override. */
static uint64_t
bfd_mbr_next_free (const struct bfd_table *tbl)
{
    uint64_t cur = BFD_FIRST_USABLE_LBA;
    for (int i = 0; i < BFD_MBR_PARTS; i++)
        if (tbl->primary[i].used) {
            uint64_t end = tbl->primary[i].start_lba + tbl->primary[i].sectors;
            if (end > cur) cur = end;
        }
    return cur;
}

static uint64_t
bfd_gpt_next_free (const struct bfd_table *tbl)
{
    uint64_t cur = tbl->gpt_first_usable;
    for (uint32_t i = 0; i < BFD_GPT_PARTS; i++)
        if (tbl->gpt[i].used) {
            uint64_t end = tbl->gpt[i].start_lba + tbl->gpt[i].sectors;
            if (end > cur) cur = end;
        }
    return cur;
}

/* Parse a "last sector" answer relative to START:
 *   ""              -> default_end (size = default_end - start + 1)
 *   "+<n>[KMGTP]"   -> that many sectors / bytes (via bfd_apply_size_tok)
 *   "<n>"           -> absolute END LBA (size = end - start + 1)
 * Returns 0 ok, -1 on a malformed answer or zero/negative span. */
static int
bfd_parse_last (const char *tok, uint32_t secsize, uint64_t start,
                uint64_t default_end, uint64_t *out_size)
{
    if (!tok || !tok[0]) {
        if (default_end < start) return -1;
        *out_size = default_end - start + 1;
        return 0;
    }
    if (tok[0] == '+') {
        uint64_t sz; int rem;
        if (bfd_apply_size_tok (tok, secsize, &sz, &rem) < 0) return -1;
        if (rem) { *out_size = default_end - start + 1; return 0; }
        if (sz == 0) return -1;
        *out_size = sz;
        return 0;
    }
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull (tok, &end, 0);
    if (errno || end == tok || *end || v < start) return -1;
    *out_size = (uint64_t) v - start + 1;
    return 0;
}

static void
bfd_print_help (void)
{
    printf ("Commands:\n"
            "  m  print this menu\n"
            "  p  print the partition table\n"
            "  n  add a new partition\n"
            "  d  delete a partition\n"
            "  t  change a partition type\n"
            "  L  list known partition types\n"
            "  a  toggle the bootable flag (MBR primary)\n"
            "  v  verify the partition table\n"
            "  w  write the table to disk and exit\n"
            "  q  quit without saving changes\n");
}

static void
bfd_print_table_mem (const struct bfd_table *tbl, const char *dev)
{
    printf ("Disk %s: %llu sectors, %llu bytes, sector size %u\n",
            dev, (unsigned long long) tbl->geom.total_sectors,
            (unsigned long long) tbl->geom.size_bytes, tbl->geom.sector_size);
    if (tbl->label == BFD_LABEL_MBR) {
        printf ("Disklabel: dos\n");
        printf ("%-4s %-5s %-12s %-12s %-12s %s\n",
                "#", "Boot", "Start", "End", "Sectors", "Type");
        for (int i = 0; i < BFD_MBR_PARTS; i++) {
            const struct bfd_part *p = &tbl->primary[i];
            if (!p->used) continue;
            printf ("%-4d %-5s %-12llu %-12llu %-12llu %02x\n", i + 1,
                    p->boot ? "*" : "",
                    (unsigned long long) p->start_lba,
                    (unsigned long long) (p->start_lba + p->sectors - 1),
                    (unsigned long long) p->sectors, p->mbr_type);
        }
        for (size_t k = 0; k < tbl->nlogicals; k++) {
            const struct bfd_part *p = &tbl->logicals[k];
            printf ("%-4zu %-5s %-12llu %-12llu %-12llu %02x\n", k + 5, "",
                    (unsigned long long) p->start_lba,
                    (unsigned long long) (p->start_lba + p->sectors - 1),
                    (unsigned long long) p->sectors, p->mbr_type);
        }
    } else if (tbl->label == BFD_LABEL_GPT) {
        printf ("Disklabel: gpt\n");
        printf ("%-4s %-12s %-12s %-12s %-36s %s\n",
                "#", "Start", "End", "Sectors", "Type", "Name");
        for (uint32_t i = 0; i < BFD_GPT_PARTS; i++) {
            const struct bfd_part *p = &tbl->gpt[i];
            if (!p->used) continue;
            char guid[40], nm[64]; size_t nl = 0;
            bfd_print_guid (p->type_guid, guid);
            for (int k = 0; k < 36 && nl + 1 < sizeof nm; k++) {
                uint16_t w = p->name[k];
                if (!w) break;
                nm[nl++] = (w < 0x80) ? (char) w : '?';
            }
            nm[nl] = '\0';
            printf ("%-4u %-12llu %-12llu %-12llu %-36s %s\n", i + 1,
                    (unsigned long long) p->start_lba,
                    (unsigned long long) (p->start_lba + p->sectors - 1),
                    (unsigned long long) p->sectors, guid, nm);
        }
    } else {
        printf ("(no partition table)\n");
    }
}

/* 'n' — add a new partition. Prompt sequence (one input line each):
 *   MBR primary/extended : type(p/e[/l]), number, first, last
 *   MBR logical          : type(p/l) [only if a free primary also exists],
 *                          first, last   (number is auto, next in chain)
 *   GPT                  : number, first, last  (type defaults to Linux;
 *                          change it later with 't') */
static void
bfd_interactive_new (struct bfd_table *tbl)
{
    char buf[128];

    if (tbl->label == BFD_LABEL_GPT) {
        int idx = bfd_apply_free_gpt (tbl);
        if (idx < 0) { printf ("No free GPT slots.\n"); return; }
        uint32_t cap = tbl->gpt_n_parts < BFD_GPT_PARTS
                     ? tbl->gpt_n_parts : BFD_GPT_PARTS;
        snprintf (buf, sizeof buf,
                  "Partition number (1-%u, default %d): ", cap, idx + 1);
        char nb[128];
        if (!bfd_prompt (buf, nb, sizeof nb)) return;
        if (nb[0]) {
            char *e = NULL; errno = 0;
            unsigned long v = strtoul (nb, &e, 10);
            if (errno || *e || v < 1 || v > cap || tbl->gpt[v - 1].used) {
                printf ("Invalid or used partition number.\n");
                return;
            }
            idx = (int) v - 1;
        }
        uint64_t cur = bfd_gpt_next_free (tbl);
        if (cur < tbl->gpt_first_usable) cur = tbl->gpt_first_usable;
        char fb[128];
        snprintf (buf, sizeof buf, "First sector (default %llu): ",
                  (unsigned long long) cur);
        if (!bfd_prompt (buf, fb, sizeof fb)) return;
        uint64_t start = cur;
        if (fb[0]) {
            char *e = NULL; errno = 0;
            unsigned long long v = strtoull (fb, &e, 0);
            if (errno || *e || v < tbl->gpt_first_usable
                || v > tbl->gpt_last_usable) {
                printf ("Invalid first sector.\n"); return;
            }
            start = (uint64_t) v;
        }
        char lb[128];
        snprintf (buf, sizeof buf,
                  "Last sector, +sectors or +size{K,M,G,T,P} (default %llu): ",
                  (unsigned long long) tbl->gpt_last_usable);
        if (!bfd_prompt (buf, lb, sizeof lb)) return;
        uint64_t size = 0;
        if (bfd_parse_last (lb, tbl->geom.sector_size, start,
                            tbl->gpt_last_usable, &size) < 0
            || start + size - 1 > tbl->gpt_last_usable) {
            printf ("Invalid last sector / size.\n"); return;
        }
        struct bfd_part *e = &tbl->gpt[idx];
        memset (e, 0, sizeof *e);
        e->used = 1;
        memcpy (e->type_guid, BFD_GPT_LINUX_GUID, 16);
        bfd_make_guid (e->part_guid, start ^ (uint64_t) idx,
                       size ^ 0xA5A5A5A5A5A5A5A5ULL);
        e->start_lba = start;
        e->sectors = size;
        printf ("Created GPT partition %d (%llu..%llu).\n", idx + 1,
                (unsigned long long) start,
                (unsigned long long) (start + size - 1));
        return;
    }

    /* MBR (treat a blank/NONE label as a fresh DOS label). */
    int free_pri = bfd_apply_free_primary (tbl);
    int has_ext  = tbl->ext_index >= 0;
    char kind;
    if (free_pri < 0 && !has_ext) {
        printf ("No free primary slots and no extended container.\n");
        return;
    }
    if (free_pri < 0 && has_ext) {
        kind = 'l';
    } else {
        if (!bfd_prompt (has_ext
                ? "Partition type - p primary, l logical (default p): "
                : "Partition type - p primary, e extended (default p): ",
                buf, sizeof buf))
            return;
        char c = buf[0] ? buf[0] : 'p';
        if (c == 'p' || c == 'P') kind = 'p';
        else if (c == 'e' || c == 'E') {
            if (has_ext) { printf ("An extended partition already exists.\n"); return; }
            kind = 'e';
        } else if (c == 'l' || c == 'L') {
            if (!has_ext) { printf ("No extended container for a logical.\n"); return; }
            kind = 'l';
        } else { printf ("Invalid partition type.\n"); return; }
    }

    if (kind == 'p' || kind == 'e') {
        int idx = bfd_apply_free_primary (tbl);
        if (idx < 0) { printf ("No free primary slots.\n"); return; }
        char nb[128];
        snprintf (buf, sizeof buf, "Partition number (1-4, default %d): ",
                  idx + 1);
        if (!bfd_prompt (buf, nb, sizeof nb)) return;
        if (nb[0]) {
            char *e = NULL; errno = 0;
            unsigned long v = strtoul (nb, &e, 10);
            if (errno || *e || v < 1 || v > BFD_MBR_PARTS
                || tbl->primary[v - 1].used) {
                printf ("Invalid or used partition number.\n"); return;
            }
            idx = (int) v - 1;
        }
        uint64_t cur = bfd_mbr_next_free (tbl);
        char fb[128];
        snprintf (buf, sizeof buf, "First sector (default %llu): ",
                  (unsigned long long) cur);
        if (!bfd_prompt (buf, fb, sizeof fb)) return;
        uint64_t start = cur;
        if (fb[0]) {
            char *e = NULL; errno = 0;
            unsigned long long v = strtoull (fb, &e, 0);
            if (errno || *e || v < BFD_FIRST_USABLE_LBA
                || v >= tbl->geom.total_sectors) {
                printf ("Invalid first sector.\n"); return;
            }
            start = (uint64_t) v;
        }
        char lb[128];
        uint64_t default_end = tbl->geom.total_sectors - 1;
        snprintf (buf, sizeof buf,
                  "Last sector, +sectors or +size{K,M,G,T,P} (default %llu): ",
                  (unsigned long long) default_end);
        if (!bfd_prompt (buf, lb, sizeof lb)) return;
        uint64_t size = 0;
        if (bfd_parse_last (lb, tbl->geom.sector_size, start,
                            default_end, &size) < 0
            || start + size > tbl->geom.total_sectors
            || start + size > (uint64_t) UINT32_MAX + 1) {
            printf ("Invalid last sector / size.\n"); return;
        }
        struct bfd_part *p = &tbl->primary[idx];
        memset (p, 0, sizeof *p);
        p->used = 1;
        p->start_lba = start;
        p->sectors = size;
        if (kind == 'e') {
            p->mbr_type = 0x05;
            p->is_extended = 1;
            tbl->ext_index = idx;
            printf ("Created extended container %d (%llu..%llu).\n", idx + 1,
                    (unsigned long long) start,
                    (unsigned long long) (start + size - 1));
        } else {
            p->mbr_type = 0x83;
            printf ("Created primary partition %d (%llu..%llu).\n", idx + 1,
                    (unsigned long long) start,
                    (unsigned long long) (start + size - 1));
        }
        return;
    }

    /* kind == 'l' : logical, auto-numbered, appended in start order. */
    uint64_t ext_base = tbl->primary[tbl->ext_index].start_lba;
    uint64_t ext_end  = ext_base + tbl->primary[tbl->ext_index].sectors;
    uint64_t cur = ext_base;
    for (size_t k = 0; k < tbl->nlogicals; k++) {
        uint64_t end = tbl->logicals[k].start_lba + tbl->logicals[k].sectors;
        if (end > cur) cur = end;
    }
    uint64_t dflt = cur + 1;   /* leave one sector for the EBR */
    char fb[128];
    snprintf (buf, sizeof buf, "First sector (default %llu): ",
              (unsigned long long) dflt);
    if (!bfd_prompt (buf, fb, sizeof fb)) return;
    uint64_t start = dflt;
    if (fb[0]) {
        char *e = NULL; errno = 0;
        unsigned long long v = strtoull (fb, &e, 0);
        if (errno || *e || v <= ext_base || v >= ext_end) {
            printf ("Invalid first sector.\n"); return;
        }
        start = (uint64_t) v;
    }
    char lb[128];
    snprintf (buf, sizeof buf,
              "Last sector, +sectors or +size{K,M,G,T,P} (default %llu): ",
              (unsigned long long) (ext_end - 1));
    if (!bfd_prompt (buf, lb, sizeof lb)) return;
    uint64_t size = 0;
    if (bfd_parse_last (lb, tbl->geom.sector_size, start, ext_end - 1, &size) < 0
        || start + size > ext_end) {
        printf ("Invalid last sector / size.\n"); return;
    }
    if (tbl->nlogicals >= 127
        || (tbl->nlogicals == tbl->nlogicals_cap
            && bfd_table_grow_logicals (tbl) < 0)) {
        printf ("Cannot add another logical partition.\n"); return;
    }
    struct bfd_part *p = &tbl->logicals[tbl->nlogicals++];
    memset (p, 0, sizeof *p);
    p->used = 1;
    p->is_logical = 1;
    p->start_lba = start;
    p->sectors = size;
    p->mbr_type = 0x83;
    bfd_sort_logicals (tbl);
    printf ("Created logical partition (%llu..%llu).\n",
            (unsigned long long) start,
            (unsigned long long) (start + size - 1));
}

static void
bfd_interactive_delete (struct bfd_table *tbl)
{
    char buf[64];
    if (!bfd_prompt ("Partition number to delete: ", buf, sizeof buf)) return;
    char *e = NULL; errno = 0;
    unsigned long v = strtoul (buf, &e, 10);
    if (errno || !buf[0] || *e || v == 0) { printf ("Invalid number.\n"); return; }

    if (tbl->label == BFD_LABEL_GPT) {
        if (v > BFD_GPT_PARTS || !tbl->gpt[v - 1].used) {
            printf ("GPT partition %lu is empty.\n", v); return;
        }
        memset (&tbl->gpt[v - 1], 0, sizeof tbl->gpt[v - 1]);
        printf ("Deleted GPT partition %lu.\n", v);
        return;
    }
    /* MBR */
    if (v <= BFD_MBR_PARTS) {
        if (!tbl->primary[v - 1].used) { printf ("Partition %lu is empty.\n", v); return; }
        if (tbl->primary[v - 1].is_extended) {
            tbl->ext_index = -1;
            tbl->nlogicals = 0;   /* dropping the container drops the chain */
        }
        memset (&tbl->primary[v - 1], 0, sizeof tbl->primary[v - 1]);
        printf ("Deleted partition %lu.\n", v);
        return;
    }
    size_t idx = (size_t) (v - 5);
    if (idx >= tbl->nlogicals) { printf ("Logical partition %lu not found.\n", v); return; }
    for (size_t k = idx; k + 1 < tbl->nlogicals; k++)
        tbl->logicals[k] = tbl->logicals[k + 1];
    tbl->nlogicals--;
    printf ("Deleted logical partition %lu (later logicals renumber).\n", v);
}

static void
bfd_interactive_set_type (struct bfd_table *tbl)
{
    char nb[64], tb[64];
    if (!bfd_prompt ("Partition number: ", nb, sizeof nb)) return;
    char *e = NULL; errno = 0;
    unsigned long v = strtoul (nb, &e, 10);
    if (errno || !nb[0] || *e || v == 0) { printf ("Invalid number.\n"); return; }
    if (!bfd_prompt ("New type: ", tb, sizeof tb)) return;

    if (tbl->label == BFD_LABEL_GPT) {
        if (v > BFD_GPT_PARTS || !tbl->gpt[v - 1].used) {
            printf ("GPT partition %lu is empty.\n", v); return;
        }
        uint8_t guid[16];
        if (bfd_parse_gpt_type (tb, guid) < 0) { printf ("Invalid GPT type.\n"); return; }
        memcpy (tbl->gpt[v - 1].type_guid, guid, 16);
        printf ("Changed type of GPT partition %lu.\n", v);
        return;
    }
    uint8_t type;
    if (bfd_parse_mbr_type (tb, &type) < 0) { printf ("Invalid MBR type.\n"); return; }
    if (bfd_mbr_type_is_extended (type)) {
        printf ("Cannot change a partition into an extended container here.\n");
        return;
    }
    if (v <= BFD_MBR_PARTS) {
        if (!tbl->primary[v - 1].used) { printf ("Partition %lu is empty.\n", v); return; }
        if (tbl->primary[v - 1].is_extended) {
            printf ("Cannot retype the extended container.\n"); return;
        }
        tbl->primary[v - 1].mbr_type = type;
    } else {
        size_t idx = (size_t) (v - 5);
        if (idx >= tbl->nlogicals) { printf ("Logical %lu not found.\n", v); return; }
        tbl->logicals[idx].mbr_type = type;
    }
    printf ("Changed type of partition %lu to %02x.\n", v, type);
}

static void
bfd_interactive_toggle_boot (struct bfd_table *tbl)
{
    char buf[64];
    if (tbl->label != BFD_LABEL_MBR) {
        printf ("The bootable flag applies to MBR primary partitions only.\n");
        return;
    }
    if (!bfd_prompt ("Partition number: ", buf, sizeof buf)) return;
    char *e = NULL; errno = 0;
    unsigned long v = strtoul (buf, &e, 10);
    if (errno || !buf[0] || *e || v == 0 || v > BFD_MBR_PARTS) {
        printf ("Bootable applies to primary partitions 1-4.\n"); return;
    }
    if (!tbl->primary[v - 1].used) { printf ("Partition %lu is empty.\n", v); return; }
    tbl->primary[v - 1].boot = !tbl->primary[v - 1].boot;
    printf ("Bootable flag on partition %lu is now %s.\n", v,
            tbl->primary[v - 1].boot ? "set" : "clear");
}

static void
bfd_interactive_verify (struct bfd_table *tbl)
{
    if (bfd_table_validate (tbl) == 0)
        printf ("Table validates cleanly.\n");
    /* bfd_table_validate prints its own diagnostic on failure. */
}

/* fdisk DEV  (or  -i DEV) — interactive editor. Reads single-letter
 * commands from stdin; changes stay in memory until 'w'. */
static int
bfd_interactive (const char *path)
{
    struct bfd_table tbl;
    if (bfd_table_load (path, &tbl) < 0) return EXECUTION_FAILURE;
    if (tbl.label == BFD_LABEL_NONE) {
        tbl.label = BFD_LABEL_MBR;   /* fresh DOS label, like fdisk(8) */
        printf ("Device %s has no partition table; starting a new DOS "
                "(MBR) disklabel.\n", path);
    }
    printf ("Welcome to fdisk interactive mode.\n"
            "Changes stay in memory until you write them with 'w'.\n");
    char line[256];
    int rc = EXECUTION_SUCCESS;
    for (;;) {
        if (!bfd_prompt ("\nCommand (m for help): ", line, sizeof line)) {
            printf ("\nEOF - quitting without saving.\n");
            break;
        }
        char c = 0;
        for (char *p = line; *p; p++)
            if (!isspace ((unsigned char) *p)) { c = *p; break; }
        if (c == 0) continue;
        if (c == 'm') bfd_print_help ();
        else if (c == 'p') bfd_print_table_mem (&tbl, path);
        else if (c == 'n') bfd_interactive_new (&tbl);
        else if (c == 'd') bfd_interactive_delete (&tbl);
        else if (c == 't') bfd_interactive_set_type (&tbl);
        else if (c == 'L' || c == 'l') bfd_list_types ();
        else if (c == 'a') bfd_interactive_toggle_boot (&tbl);
        else if (c == 'v') bfd_interactive_verify (&tbl);
        else if (c == 'q') {
            printf ("Quitting without saving changes.\n");
            break;
        } else if (c == 'w') {
            if (bfd_table_validate (&tbl) != 0) {
                printf ("Table is invalid; not writing. Fix it or 'q' to quit.\n");
                continue;
            }
            if (bfd_table_serialize (path, &tbl) != 0) {
                printf ("Write failed; table not saved.\n");
                continue;
            }
            printf ("The partition table has been written to %s.\n", path);
            bfd_table_release (&tbl);
            return EXECUTION_SUCCESS;
        } else {
            printf ("%c: unknown command (m for help)\n", c);
        }
    }
    bfd_table_release (&tbl);
    return rc;
}

/* ---- builtin entry ---------------------------------------------------- */

int
fdisk_builtin (WORD_LIST *list)
{
    if (!list) {
        builtin_usage ();
        return EX_USAGE;
    }

    /* --no-act / -n is a leading global flag; reset per invocation since
     * loadable-builtin file-scope state persists across calls. */
    bfd_no_act = 0;
    bfd_repair = 0;

    /* Collect argv-shape. */
    int argc = 0;
    for (WORD_LIST *l = list; l; l = l->next) argc++;
    if (argc < 1) { builtin_usage (); return EX_USAGE; }

    /* Consume leading global flags in any order: --no-act/-n (dry run)
     * and --append/-a (--apply onto an existing table). */
    int append = 0;
    const char *mode = list->word->word;
    for (;;) {
        if (!strcmp (mode, "--no-act") || !strcmp (mode, "-n"))
            bfd_no_act = 1;
        else if (!strcmp (mode, "--append") || !strcmp (mode, "-a"))
            append = 1;
        else
            break;
        list = list->next;
        if (!list) {
            builtin_error ("--no-act/--append require a following mode "
                           "(e.g. --apply, --create-mbr, ...)");
            return EX_USAGE;
        }
        mode = list->word->word;
    }
    if (!strcmp (mode, "-h") || !strcmp (mode, "--help")) {
        builtin_usage ();
        return EXECUTION_SUCCESS;
    }
    if (!strcmp (mode, "-i") || !strcmp (mode, "--interactive")) {
        WORD_LIST *l = list->next;
        if (!l || l->next) {
            builtin_error ("-i requires exactly one DEV");
            return EX_USAGE;
        }
        return bfd_interactive (l->word->word);
    }
    /* A bare first argument (no leading '-') is a device for the
     * interactive editor — matches fdisk(8)'s `fdisk DEV`. */
    if (mode[0] != '-') {
        if (list->next) {
            builtin_error ("interactive mode takes a single DEV "
                           "(got extra arguments)");
            return EX_USAGE;
        }
        return bfd_interactive (mode);
    }
    if (!strcmp (mode, "-l") || !strcmp (mode, "--list")) {
        WORD_LIST *l = list->next;
        if (!l) {
            builtin_error ("-l requires at least one device");
            return EX_USAGE;
        }
        int rc = 0;
        for (; l; l = l->next) {
            if (bfd_list_one (l->word->word) < 0) rc = 1;
            if (l->next) printf ("\n");
        }
        return rc ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    }
    if (!strcmp (mode, "--partx-kernel")) {
        WORD_LIST *l = list->next;
        if (!l || !l->next || (l->next->next && l->next->next->next
                               && l->next->next->next->next)) {
            builtin_error ("--partx-kernel requires OP DEV [MIN MAX]");
            return EX_USAGE;
        }
        const char *op = l->word->word;
        const char *dev = l->next->word->word;
        const char *min = l->next->next ? l->next->next->word->word : NULL;
        const char *max = (l->next->next && l->next->next->next)
                        ? l->next->next->next->word->word : NULL;
        return (bfd_partx_kernel (op, dev, min, max) == 0)
            ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
    if (!strcmp (mode, "--delete")) {
        WORD_LIST *l = list->next;
        if (!l || !l->next || l->next->next) {
            builtin_error ("--delete requires DEV and partition number");
            return EX_USAGE;
        }
        return (bfd_delete_partition (l->word->word, l->next->word->word) == 0)
            ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
    if (!strcmp (mode, "--insert-logical")) {
        WORD_LIST *l = list->next;
        if (!l || !l->next || l->next->next) {
            builtin_error ("--insert-logical requires DEV and SPEC "
                           "(START,SIZE[,TYPE[,BOOT]])");
            return EX_USAGE;
        }
        return (bfd_insert_logical (l->word->word, l->next->word->word) == 0)
            ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
    if (!strcmp (mode, "--reorder") || !strcmp (mode, "-r")) {
        WORD_LIST *l = list->next;
        if (!l || l->next) {
            builtin_error ("--reorder requires exactly one DEV");
            return EX_USAGE;
        }
        return (bfd_reorder (l->word->word) == 0)
            ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
    if (!strcmp (mode, "--delete-compact")) {
        WORD_LIST *l = list->next;
        if (!l || !l->next || l->next->next) {
            builtin_error ("--delete-compact requires DEV and partition number");
            return EX_USAGE;
        }
        return (bfd_delete_partition_compact (l->word->word,
                                              l->next->word->word) == 0)
            ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
    if (!strcmp (mode, "--set-attrs")) {
        WORD_LIST *l = list->next;
        if (!l || !l->next || !l->next->next || l->next->next->next) {
            builtin_error ("--set-attrs requires DEV, partition number, and ATTRS");
            return EX_USAGE;
        }
        return (bfd_set_gpt_attrs (l->word->word, l->next->word->word,
                                   l->next->next->word->word) == 0)
            ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
    if (!strcmp (mode, "--activate") || !strcmp (mode, "-A")) {
        WORD_LIST *l = list->next;
        if (!l || !l->next || !l->next->next || l->next->next->next) {
            builtin_error ("--activate requires DEV, partition number, and on/off");
            return EX_USAGE;
        }
        return (bfd_activate (l->word->word, l->next->word->word,
                              l->next->next->word->word) == 0)
            ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
    if (!strcmp (mode, "--part-type")) {
        WORD_LIST *l = list->next;
        if (!l || !l->next || !l->next->next || l->next->next->next) {
            builtin_error ("--part-type requires DEV, partition number, and TYPE");
            return EX_USAGE;
        }
        return (bfd_part_type (l->word->word, l->next->word->word,
                               l->next->next->word->word) == 0)
            ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
    if (!strcmp (mode, "--set-part")) {
        WORD_LIST *l = list->next;
        if (!l || !l->next || !l->next->next || l->next->next->next) {
            builtin_error ("--set-part requires DEV, partition number, and "
                           "SPEC (START,SIZE[,TYPE[,BOOT|NAME]])");
            return EX_USAGE;
        }
        return (bfd_set_part (l->word->word, l->next->word->word,
                              l->next->next->word->word) == 0)
            ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
    if (!strcmp (mode, "--part-label")) {
        WORD_LIST *l = list->next;
        if (!l || !l->next || !l->next->next || l->next->next->next) {
            builtin_error ("--part-label requires DEV, partition number, and NAME");
            return EX_USAGE;
        }
        return (bfd_part_label (l->word->word, l->next->word->word,
                                l->next->next->word->word) == 0)
            ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
    if (!strcmp (mode, "--part-uuid")) {
        WORD_LIST *l = list->next;
        if (!l || !l->next || !l->next->next || l->next->next->next) {
            builtin_error ("--part-uuid requires DEV, partition number, and UUID");
            return EX_USAGE;
        }
        return (bfd_part_uuid (l->word->word, l->next->word->word,
                               l->next->next->word->word) == 0)
            ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
    if (!strcmp (mode, "--list-types") || !strcmp (mode, "-T")) {
        if (list->next) {
            builtin_error ("--list-types takes no arguments");
            return EX_USAGE;
        }
        return (bfd_list_types () == 0)
            ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
    if (!strcmp (mode, "--repair")) {
        WORD_LIST *l = list->next;
        if (!l || l->next) {
            builtin_error ("--repair requires exactly one DEV");
            return EX_USAGE;
        }
        return (bfd_repair_gpt (l->word->word) == 0)
            ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
    if (!strcmp (mode, "--verify") || !strcmp (mode, "-V")) {
        WORD_LIST *l = list->next;
        if (!l || l->next) {
            builtin_error ("--verify requires exactly one DEV");
            return EX_USAGE;
        }
        return (bfd_verify (l->word->word) == 0)
            ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
    if (!strcmp (mode, "--list-free") || !strcmp (mode, "-F")) {
        WORD_LIST *l = list->next;
        if (!l || l->next) {
            builtin_error ("--list-free requires exactly one DEV");
            return EX_USAGE;
        }
        return (bfd_list_free (l->word->word) == 0)
            ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
    if (!strcmp (mode, "--disk-id")) {
        WORD_LIST *l = list->next;
        if (!l || (l->next && l->next->next)) {
            builtin_error ("--disk-id requires DEV [STR]");
            return EX_USAGE;
        }
        const char *new_id = l->next ? l->next->word->word : NULL;
        return (bfd_disk_id (l->word->word, new_id) == 0)
            ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
    if (!strcmp (mode, "--apply")) {
        WORD_LIST *l = list->next;
        if (!l || !l->next || !l->next->next) {
            builtin_error ("--apply requires DEV, LABEL (mbr|gpt), and at "
                           "least one SPEC");
            return EX_USAGE;
        }
        const char *dev = l->word->word;
        const char *label = l->next->word->word;
        l = l->next->next;
        int nspecs = 0;
        for (WORD_LIST *q = l; q; q = q->next) nspecs++;
        if (nspecs > BFD_GPT_PARTS) {
            builtin_error ("--apply: too many SPECs (%d)", nspecs);
            return EX_USAGE;
        }
        char **specs = (char **) calloc ((size_t) nspecs, sizeof *specs);
        if (!specs) {
            builtin_error ("malloc: %s", strerror (errno));
            return EXECUTION_FAILURE;
        }
        int i = 0;
        for (WORD_LIST *q = l; q; q = q->next) specs[i++] = q->word->word;
        int rc = bfd_apply (dev, label, specs, nspecs, append);
        free (specs);
        return (rc == 0) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
    if (!strcmp (mode, "--create-mbr") || !strcmp (mode, "--create-gpt")
        || !strcmp (mode, "--create-mbr-extended")) {
        WORD_LIST *l = list->next;
        if (!l) {
            builtin_error ("%s requires DEV and at least one SPEC", mode);
            return EX_USAGE;
        }
        const char *dev = l->word->word;
        l = l->next;
        if (!l) {
            builtin_error ("%s: missing SPEC(s)", mode);
            return EX_USAGE;
        }
        /* Materialize spec argv. */
        char **specs = NULL;
        int nspecs = 0;
        for (WORD_LIST *q = l; q; q = q->next) nspecs++;
        if (nspecs > BFD_GPT_PARTS) {
            builtin_error ("%s: too many SPECs (%d)", mode, nspecs);
            return EX_USAGE;
        }
        specs = (char **) calloc ((size_t) nspecs, sizeof *specs);
        if (!specs) {
            builtin_error ("malloc: %s", strerror (errno));
            return EXECUTION_FAILURE;
        }
        int i = 0;
        for (WORD_LIST *q = l; q; q = q->next) specs[i++] = q->word->word;

        int rc;
        if (!strcmp (mode, "--create-mbr"))
            rc = bfd_create_mbr (dev, specs, nspecs);
        else if (!strcmp (mode, "--create-mbr-extended")) {
            if (nspecs < 2) {
                builtin_error ("%s requires EXT_SPEC and at least one LOGICAL_SPEC",
                               mode);
                free (specs);
                return EX_USAGE;
            }
            rc = bfd_create_mbr_extended (dev, specs[0], specs + 1, nspecs - 1);
        }
        else
            rc = bfd_create_gpt (dev, specs, nspecs);
        free (specs);
        return (rc == 0) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }

    if (!strcmp (mode, "--debug-roundtrip")) {
        /* Hidden Phase 1.A regression tool: load the table from DEV
         * and serialize it back. The on-disk image must be byte-
         * identical pre- and post-roundtrip. Not advertised in -h
         * or doc[]; consumed by the round-trip test. */
        WORD_LIST *l = list->next;
        if (!l || l->next) {
            builtin_error ("--debug-roundtrip requires exactly one DEV");
            return EX_USAGE;
        }
        return (bfd_debug_roundtrip (l->word->word) == 0)
            ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }

    builtin_error ("unknown mode: %s (try -l / --create-mbr / --create-mbr-extended / --create-gpt / --apply / --delete / --delete-compact / --insert-logical / --reorder / --set-attrs / --activate / --part-type / --set-part / --part-label / --part-uuid / --repair / --verify / --list-free / --list-types / --disk-id; prefix --no-act for a dry run)", mode);
    return EX_USAGE;
}

static char *fdisk_doc[] = {
    "MBR + GPT partition-table editor (subset).",
    "",
    "    fdisk DEV                 (interactive editor; also -i DEV)",
    "    fdisk -l DEV ...",
    "    fdisk --create-mbr DEV SPEC [SPEC ...]",
    "    fdisk --create-mbr-extended DEV EXT_SPEC LOGICAL_SPEC [LOGICAL_SPEC ...]",
    "    fdisk --create-gpt DEV SPEC [SPEC ...]",
    "    fdisk [--append] --apply DEV {mbr|gpt} SPEC [SPEC ...]",
    "    fdisk --delete DEV N",
    "    fdisk --delete-compact DEV N",
    "    fdisk --insert-logical DEV START,SIZE[,TYPE[,BOOT]]",
    "    fdisk --reorder DEV",
    "    fdisk --set-attrs DEV N ATTRS",
    "    fdisk --activate DEV N {on|off}",
    "    fdisk --part-type DEV N TYPE",
    "    fdisk --set-part DEV N START,SIZE[,TYPE[,BOOT|NAME]]",
    "    fdisk --part-label DEV N NAME",
    "    fdisk --part-uuid DEV N UUID",
    "    fdisk --repair DEV",
    "    fdisk --verify DEV",
    "    fdisk --list-free DEV",
    "    fdisk --list-types",
    "    fdisk --disk-id DEV [STR]",
    "    fdisk --no-act MODE ...   (dry run: validate, skip the write)",
    "",
    "  DEV   (or -i DEV / --interactive DEV)",
    "      Interactive editor. Reads single-letter commands from stdin",
    "      (m help, p print, n new, d delete, t type, a bootable, v verify,",
    "      w write+exit, q quit). Changes stay in memory until 'w'. A blank",
    "      device starts a fresh DOS (MBR) disklabel. Works under a PTY or",
    "      from piped/heredoc input.",
    "",
    "  -l / --list",
    "      Print partition table(s) on each DEV (block device or regular file).",
    "",
    "  --create-mbr DEV SPEC...",
    "      Overwrite DEV with a fresh MBR holding 1..4 primary partitions.",
    "      SPEC = [START[,SIZE[,TYPE[,BOOT]]]]. Empty fields default:",
    "        START -> next free (first slot = 2048),",
    "        SIZE  -> remaining space (last spec only),",
    "        TYPE  -> 83 (Linux) — accepts hex byte or 'linux/swap/fat32/ntfs',",
    "        BOOT  -> 'boot' or '*' to set the active flag.",
    "",
    "  --create-mbr-extended DEV EXT_SPEC LOGICAL_SPEC...",
    "      Overwrite DEV with a fresh DOS MBR containing one extended",
    "      partition and an EBR chain. EXT_SPEC = START,SIZE[,TYPE] with TYPE",
    "      default 05. LOGICAL_SPEC = START,SIZE[,TYPE[,BOOT]] with TYPE",
    "      default 83. Starts and sizes are absolute sectors and must be sorted,",
    "      non-overlapping, inside the extended range, and leave one EBR sector",
    "      before each logical data range.",
    "",
    "  --create-gpt DEV SPEC...",
    "      Overwrite DEV with a fresh GPT (128 entries × 128 B; protective MBR;",
    "      primary + backup headers; CRC32-validated on disk).",
    "      SPEC = [START[,SIZE[,TYPE-GUID[,NAME[,ATTRS]]]]]. TYPE-GUID defaults",
    "      to Linux; ATTRS accepts a number or RequiredPartition,",
    "      NoBlockIOProtocol, LegacyBIOSBootable, and GUID:N.",
    "",
    "  --apply DEV {mbr|gpt} SPEC...",
    "      Compose a whole partition table from a prefixed spec list and",
    "      write it in one transaction. The only verb that can place MBR",
    "      primaries + an extended container + logicals together. SPEC:",
    "        p:[N:]START,SIZE[,TYPE[,BOOT]]   MBR primary (N = 1..4)",
    "        e:[N:]START,SIZE[,TYPE]          MBR extended container (unique)",
    "        l:START,SIZE[,TYPE[,BOOT]]       MBR logical (must follow an e:)",
    "        g:[N:]START,SIZE[,TYPE-GUID[,NAME[,ATTRS]]]  GPT entry (N=1..128)",
    "      START is an absolute LBA or '+' (next free). SIZE is absolute",
    "      sectors, a '+<n>{K,M,G,T,P}' human size, or '+' (remaining). The",
    "      optional 'N:' pins an exact slot; otherwise the next free slot",
    "      is auto-filled. p:/e:/l: require LABEL mbr; g: requires gpt.",
    "      Prefix --append (or -a) to add the SPECs to the existing table",
    "      instead of writing a fresh one (free slots / extend the chain;",
    "      LABEL must match the on-disk table). A blank device is treated",
    "      as a fresh table.",
    "",
    "  --delete DEV N",
    "      Clear partition slot N in-place. MBR primary slots, MBR logical",
    "      EBR data entries, and GPT entries are supported; GPT primary and",
    "      backup array/header CRCs are updated.",
    "",
    "  --delete-compact DEV N",
    "      Delete MBR logical partition N (N >= 5) and relink EBR metadata so",
    "      later logical partitions compact by chain order. Payload sectors are",
    "      not moved; GPT and primary MBR slots are rejected.",
    "",
    "  --insert-logical DEV START,SIZE[,TYPE[,BOOT]]",
    "      Splice a new logical partition into an existing MBR extended",
    "      chain. START and SIZE are absolute sectors; the logical is",
    "      inserted in start-sorted order and the EBR chain is relinked,",
    "      so later logicals renumber. Data sectors are not moved.",
    "",
    "  --reorder DEV   (alias -r)",
    "      Sort the MBR logical chain by ascending data start and rewrite",
    "      the EBR links so partition numbering follows data order. Stale",
    "      EBR sectors from the old order are zeroed. Data is not moved.",
    "",
    "  --set-attrs DEV N ATTRS",
    "      Set GPT partition N attribute bits in-place. ATTRS accepts the",
    "      same number/name syntax as --create-gpt. GPT primary and backup",
    "      array/header CRCs are updated.",
    "",
    "  --activate DEV N {on|off}",
    "      Set or clear the MBR boot flag on primary slot N (1..4). Setting",
    "      on clears the boot flag on every other primary (matches",
    "      util-linux 'sfdisk -A' semantics: only one active per MBR).",
    "      Accepts on/boot/*/1 and off/noboot/-/0 spellings. GPT labels",
    "      are rejected; logical (N>=5) is rejected.",
    "",
    "  --part-type DEV N TYPE",
    "      Mutate partition N's type. MBR accepts hex byte or",
    "      linux/swap/fat32/ntfs aliases; GPT accepts a 36-char GUID or",
    "      linux/swap aliases. Toggling between extended and data MBR",
    "      types is rejected (use --delete + --create-mbr-extended).",
    "      Logical MBR slots (N>=5) cannot adopt an extended type.",
    "",
    "  --set-part DEV N START,SIZE[,TYPE[,BOOT|NAME]]",
    "      Rewrite ONLY partition N's geometry/type, leaving every other",
    "      slot (and its GPT part-GUID) untouched — the engine behind",
    "      sfdisk's -N. An empty SPEC field keeps the current value, so",
    "      you can change just the size or just the type. START is an",
    "      absolute LBA; SIZE is sectors or +<n>{K,M,G,T,P}. MBR uses a",
    "      hex/alias TYPE + BOOT; GPT uses a TYPE-GUID + NAME.",
    "",
    "  --part-label DEV N NAME",
    "      Mutate the GPT partition label (UTF-16LE, up to 36 chars).",
    "      Each NAME byte is cast to uint16_t — US-ASCII passes through,",
    "      Latin-1 high bytes map verbatim. Empty NAME clears the label.",
    "      MBR labels are rejected (no name field in MBR entries).",
    "",
    "  --part-uuid DEV N UUID",
    "      Mutate the GPT partition's unique GUID. UUID is a 36-char",
    "      canonical GUID string (optional braces), parsed with the same",
    "      mixed-endian on-disk layout as --create-gpt's TYPE-GUID. MBR is",
    "      rejected (no per-partition GUID field).",
    "",
    "  --repair DEV",
    "      Rewrite both GPT headers + entry arrays fresh. Recovers a disk",
    "      whose primary GPT header is corrupt but whose backup header (at",
    "      the device tail) is intact: the table is read from the backup",
    "      and a clean primary + backup pair is written. Other mutating",
    "      verbs refuse a backup-recovered table until --repair runs.",
    "",
    "  --verify DEV",
    "      Read-only validation: load the partition table and run the",
    "      table-model validator (alignment, overlap, in-range,",
    "      EBR-chain coherence, GPT bounds). Exits success if clean.",
    "",
    "  --list-free DEV",
    "      Read-only enumeration of free LBA ranges between used",
    "      partitions. For MBR, walks primary slots across",
    "      [first-usable, end-of-disk]. For GPT, walks gpt[] across",
    "      [first_usable, last_usable]. Logical-inside-extended ranges",
    "      are covered by the extended container slot.",
    "",
    "  --list-types",
    "      Print the partition-type aliases this builtin understands (MBR",
    "      hex codes and GPT type GUIDs). Informational; no DEV, no I/O.",
    "",
    "  --no-act / -n MODE ...",
    "      Dry run: run the selected mutating MODE through validation and",
    "      report what it would write, but skip the actual disk write.",
    "      Prefix any create/mutation/delete verb (e.g. --no-act",
    "      --create-gpt DEV ...); the in-place EBR-chain rewrites",
    "      (--delete-compact and --delete of an MBR logical) honor it too.",
    "",
    "  --disk-id DEV [STR]",
    "      Print (no STR) or set (STR) the disk identifier. MBR: 4-byte",
    "      signature at offset 0x1B8 — prints as 0xNNNNNNNN; sets from",
    "      up to 8 hex chars (with or without 0x prefix). GPT: 16-byte",
    "      disk GUID — prints in canonical 36-char form; sets from a",
    "      36-char GUID string.",
    "",
    "Differences from util-linux fdisk: no interactive prompt UI; extended",
    "creation is fresh-table explicit-sector only; compact logical deletion",
    "relinks EBR metadata but does not move payload sectors; only a bounded",
    "sfdisk-style multiline script subset.",
    (char *) NULL
};

struct builtin fdisk_struct = {
    "fdisk",
    fdisk_builtin,
    BUILTIN_ENABLED,
    fdisk_doc,
    "fdisk DEV (interactive; or -i DEV) | [--no-act] -l DEV ... | --create-mbr DEV SPEC ... | --create-mbr-extended DEV EXT_SPEC LOGICAL_SPEC ... | --create-gpt DEV SPEC ... | --apply DEV {mbr|gpt} SPEC ... | --delete DEV N | --delete-compact DEV N | --insert-logical DEV START,SIZE[,TYPE[,BOOT]] | --reorder DEV | --set-attrs DEV N ATTRS | --activate DEV N {on|off} | --part-type DEV N TYPE | --set-part DEV N START,SIZE[,TYPE[,BOOT|NAME]] | --part-label DEV N NAME | --part-uuid DEV N UUID | --repair DEV | --verify DEV | --list-free DEV | --list-types | --disk-id DEV [STR]",
    0
};
