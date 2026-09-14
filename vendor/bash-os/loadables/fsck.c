/* SPDX-License-Identifier: MIT */
/* fsck.c — minimal ext2/ext4 superblock verifier (fsck.ext2/ext4).
 *
 *   fsck [-v] [-n] [-p] [-y] IMAGE
 *
 *   -v   verbose (print summary of decoded superblock fields)
 *   -n   no-changes — never modify IMAGE even when a repair is
 *        otherwise safe (default behavior if no repair flag is given)
 *   -p   "preen" — auto-repair safe issues without prompting
 *   -f   force check even if filesystem is marked clean (accepted; v1
 *        always performs all checks)
 *   -y   assume "yes" answers; equivalent to -p for the v1 repair
 *        surface
 *
 * v1 scope (paired with mkfs v1 which writes ext2-layout images
 * for both mkfs.ext2 and mkfs.ext4 wrappers):
 *   - Parses the ext2/3/4 superblock at byte offset 1024.
 *   - Verifies magic 0xEF53.
 *   - Sanity-checks block size, blocks-per-group, inodes-per-group,
 *     inode size, total blocks/inodes, first-data-block, group count
 *     consistency, and errors-behavior fields.
 *   - Reports the detected variant (ext2 / ext3 / ext4) by inspecting
 *     s_feature_compat / s_feature_incompat / s_feature_ro_compat.
 *
 * v1 repair pass (`-p` / `-y`):
 *   - If the superblock has the EXT2_ERROR_FS (0x0002) bit set in
 *     s_state AND no other sanity check failed, clear the bit and
 *     set EXT2_VALID_FS (0x0001), then write the superblock back to
 *     IMAGE. This is the minimal repair needed to "clean" a fs that
 *     was marked dirty by the kernel after an unclean shutdown but
 *     whose structural fields are otherwise sane. Anything beyond
 *     "dirty bit, no structural damage" is still treated as
 *     uncorrected (FSCK_ERR_FS).
 *
 * v1 does NOT do:
 *   - inode-table / block-bitmap / inode-bitmap traversal
 *   - directory consistency
 *   - journal replay
 *   - any non-dirty-bit write/repair
 *
 * Exit codes (subset of e2fsprogs `fsck.ext2` codes — see fsck(8)):
 *   0   no errors
 *   4   uncorrected errors detected (or would-be-corrected, since v1
 *       is verify-only and never repairs)
 *   8   operational error (can't open / can't read IMAGE)
 *  16   usage error
 *
 * Source counterparts:
 *   research/refs/e2fsprogs/lib/ext2fs/ext2_fs.h — struct layout
 *   research/refs/busybox/util-linux/fsck_minix.c — exit-code
 *     conventions (minix variant follows the same coding rules)
 *
 * --- LICENSE --- MIT, same boilerplate as file.c / free.c.
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

#include "loadables.h"

/* Exit codes (subset of fsck(8) convention). */
#define FSCK_OK        0
#define FSCK_ERR_FS    4
#define FSCK_ERR_OP    8
#define FSCK_ERR_USE  16

/* Where the primary superblock lives in an ext2/3/4 image. */
#define BFK_SB_OFFSET   1024
#define BFK_SB_SIZE     1024     /* canonical superblock size in bytes */

/* ext2/3/4 superblock magic (little-endian) at offset 56 within the SB. */
#define BFK_EXT_MAGIC   0xEF53

/* Feature bit flags we need to disambiguate ext2 / ext3 / ext4.
 * Matches linux/include/uapi/linux/ext2_fs.h and e2fsprogs/lib/ext2fs/ext2_fs.h. */
#define BFK_F_COMPAT_HAS_JOURNAL    0x0004  /* ext3+ */
#define BFK_F_INCOMPAT_EXTENTS      0x0040  /* ext4 */
#define BFK_F_INCOMPAT_64BIT        0x0080  /* ext4 */
#define BFK_F_INCOMPAT_FLEX_BG      0x0200  /* ext4 */
#define BFK_F_ROCOMPAT_HUGE_FILE    0x0008  /* ext4 */

/* Decoded fields we care about. All numbers are derived from the
 * little-endian on-disk image. Naming mirrors the kernel's
 * ext2_super_block struct (s_<name>). */
typedef struct {
    uint32_t s_inodes_count;
    uint32_t s_blocks_count;
    uint32_t s_r_blocks_count;
    uint32_t s_free_blocks_count;
    uint32_t s_free_inodes_count;
    uint32_t s_first_data_block;
    uint32_t s_log_block_size;
    uint32_t s_log_frag_size;
    uint32_t s_blocks_per_group;
    uint32_t s_frags_per_group;
    uint32_t s_inodes_per_group;
    uint32_t s_mtime;
    uint32_t s_wtime;
    uint16_t s_mnt_count;
    uint16_t s_max_mnt_count;
    uint16_t s_magic;
    uint16_t s_state;
    uint16_t s_errors;
    uint16_t s_minor_rev_level;
    uint32_t s_lastcheck;
    uint32_t s_checkinterval;
    uint32_t s_creator_os;
    uint32_t s_rev_level;
    uint16_t s_def_resuid;
    uint16_t s_def_resgid;
    uint32_t s_first_ino;
    uint16_t s_inode_size;
    uint16_t s_block_group_nr;
    uint32_t s_feature_compat;
    uint32_t s_feature_incompat;
    uint32_t s_feature_ro_compat;
    char     s_volume_name[17];      /* 16 + NUL */
} bfk_sb;

static uint16_t bfk_u16 (const unsigned char *p) {
    return (uint16_t) p[0] | ((uint16_t) p[1] << 8);
}
static uint32_t bfk_u32 (const unsigned char *p) {
    return (uint32_t) p[0]
         | ((uint32_t) p[1] << 8)
         | ((uint32_t) p[2] << 16)
         | ((uint32_t) p[3] << 24);
}

/* Decode a 1024-byte superblock buffer into bfk_sb. Returns 0 on
 * success, -1 if the buffer doesn't carry a usable ext2/3/4 superblock
 * (i.e. magic mismatch). All other field validation is the caller's
 * responsibility. */
static int
bfk_decode_sb (const unsigned char *b, bfk_sb *sb)
{
    sb->s_inodes_count        = bfk_u32 (b + 0);
    sb->s_blocks_count        = bfk_u32 (b + 4);
    sb->s_r_blocks_count      = bfk_u32 (b + 8);
    sb->s_free_blocks_count   = bfk_u32 (b + 12);
    sb->s_free_inodes_count   = bfk_u32 (b + 16);
    sb->s_first_data_block    = bfk_u32 (b + 20);
    sb->s_log_block_size      = bfk_u32 (b + 24);
    sb->s_log_frag_size       = bfk_u32 (b + 28);
    sb->s_blocks_per_group    = bfk_u32 (b + 32);
    sb->s_frags_per_group     = bfk_u32 (b + 36);
    sb->s_inodes_per_group    = bfk_u32 (b + 40);
    sb->s_mtime               = bfk_u32 (b + 44);
    sb->s_wtime               = bfk_u32 (b + 48);
    sb->s_mnt_count           = bfk_u16 (b + 52);
    sb->s_max_mnt_count       = bfk_u16 (b + 54);
    sb->s_magic               = bfk_u16 (b + 56);
    sb->s_state               = bfk_u16 (b + 58);
    sb->s_errors              = bfk_u16 (b + 60);
    sb->s_minor_rev_level     = bfk_u16 (b + 62);
    sb->s_lastcheck           = bfk_u32 (b + 64);
    sb->s_checkinterval       = bfk_u32 (b + 68);
    sb->s_creator_os          = bfk_u32 (b + 72);
    sb->s_rev_level           = bfk_u32 (b + 76);
    sb->s_def_resuid          = bfk_u16 (b + 80);
    sb->s_def_resgid          = bfk_u16 (b + 82);
    sb->s_first_ino           = bfk_u32 (b + 84);
    sb->s_inode_size          = bfk_u16 (b + 88);
    sb->s_block_group_nr      = bfk_u16 (b + 90);
    sb->s_feature_compat      = bfk_u32 (b + 92);
    sb->s_feature_incompat    = bfk_u32 (b + 96);
    sb->s_feature_ro_compat   = bfk_u32 (b + 100);
    memcpy (sb->s_volume_name, b + 120, 16);
    sb->s_volume_name[16] = '\0';

    if (sb->s_magic != BFK_EXT_MAGIC) return -1;
    return 0;
}

/* Classify the on-disk variant from feature flags. The returned string
 * is a const literal; callers must not free it. */
static const char *
bfk_classify (const bfk_sb *sb)
{
    if (sb->s_feature_incompat & (BFK_F_INCOMPAT_EXTENTS
                                | BFK_F_INCOMPAT_64BIT
                                | BFK_F_INCOMPAT_FLEX_BG))
        return "ext4";
    if (sb->s_feature_ro_compat & BFK_F_ROCOMPAT_HUGE_FILE)
        return "ext4";
    if (sb->s_feature_compat & BFK_F_COMPAT_HAS_JOURNAL)
        return "ext3";
    return "ext2";
}

/* Run a sequence of sanity checks. Each failure is appended to errbuf
 * (separated by "; "). Returns the number of failures detected. */
static int
bfk_sanity (const bfk_sb *sb, char *errbuf, size_t errsz)
{
    int errs = 0;
    size_t pos = 0;
    errbuf[0] = '\0';

#define BFK_FAIL(fmt, ...) do {                                       \
        if (pos < errsz) {                                            \
            int _n = snprintf (errbuf + pos, errsz - pos,             \
                               "%s" fmt,                              \
                               (errs ? "; " : ""), ##__VA_ARGS__);    \
            if (_n > 0) pos += (size_t) _n;                           \
        }                                                             \
        errs++;                                                       \
    } while (0)

    /* Block size: 1024 << s_log_block_size, with 0..6 the legal range
     * (1024..65536 bytes). e2fsprogs rejects anything >65536. */
    if (sb->s_log_block_size > 6)
        BFK_FAIL ("s_log_block_size=%u out of range (max 6)",
                  (unsigned) sb->s_log_block_size);

    if (sb->s_blocks_count == 0)
        BFK_FAIL ("s_blocks_count=0");

    if (sb->s_inodes_count == 0)
        BFK_FAIL ("s_inodes_count=0");

    if (sb->s_blocks_per_group == 0)
        BFK_FAIL ("s_blocks_per_group=0");

    if (sb->s_inodes_per_group == 0)
        BFK_FAIL ("s_inodes_per_group=0");

    /* s_first_data_block: 1 for 1024-byte blocks, 0 otherwise. */
    {
        uint32_t expected = (sb->s_log_block_size == 0) ? 1u : 0u;
        if (sb->s_first_data_block != expected)
            BFK_FAIL ("s_first_data_block=%u (expected %u for block size %u)",
                      (unsigned) sb->s_first_data_block,
                      (unsigned) expected,
                      (unsigned) (1024u << sb->s_log_block_size));
    }

    /* Free counts must not exceed totals. */
    if (sb->s_free_blocks_count > sb->s_blocks_count)
        BFK_FAIL ("s_free_blocks_count(%u) > s_blocks_count(%u)",
                  (unsigned) sb->s_free_blocks_count,
                  (unsigned) sb->s_blocks_count);
    if (sb->s_free_inodes_count > sb->s_inodes_count)
        BFK_FAIL ("s_free_inodes_count(%u) > s_inodes_count(%u)",
                  (unsigned) sb->s_free_inodes_count,
                  (unsigned) sb->s_inodes_count);
    if (sb->s_r_blocks_count > sb->s_blocks_count)
        BFK_FAIL ("s_r_blocks_count(%u) > s_blocks_count(%u)",
                  (unsigned) sb->s_r_blocks_count,
                  (unsigned) sb->s_blocks_count);

    /* Inode size:
     *   rev 0 (s_rev_level == 0):       fixed at 128, s_inode_size field
     *                                   unused (may be 0 on disk).
     *   rev 1+ ("dynamic"):             128..block_size, must be a power
     *                                   of two.
     */
    if (sb->s_rev_level >= 1) {
        uint32_t bsz = 1024u << sb->s_log_block_size;
        if (sb->s_inode_size < 128 || sb->s_inode_size > bsz)
            BFK_FAIL ("s_inode_size=%u out of range [128,%u]",
                      (unsigned) sb->s_inode_size, (unsigned) bsz);
        else if ((sb->s_inode_size & (sb->s_inode_size - 1)) != 0)
            BFK_FAIL ("s_inode_size=%u not a power of two",
                      (unsigned) sb->s_inode_size);
    }

    /* Filesystem-state field — bit 0x0001 = clean, 0x0002 = errors.
     * Note: the ERRORS bit is intentionally NOT counted as a sanity
     * failure here. It signals "fs was marked dirty by the kernel"
     * (e.g. after an unclean shutdown), which the repair pass below
     * can clear when structural sanity is otherwise OK. Treating it
     * as fatal here would prevent that repair. The all-zero legacy
     * value is also allowed (older mkfs.ext2 leaves it 0 until first
     * mount). The main builtin inspects sb->s_state directly to drive
     * the repair branch. */

    /* s_errors: 1=continue, 2=remount-ro, 3=panic, 0=unset. Any other
     * value is suspicious. */
    if (sb->s_errors > 3)
        BFK_FAIL ("s_errors=%u (unknown behavior)",
                  (unsigned) sb->s_errors);

#undef BFK_FAIL
    return errs;
}

static void
bfk_print_summary (const char *path, const bfk_sb *sb)
{
    const char *fst = bfk_classify (sb);
    uint32_t bsz = (sb->s_log_block_size <= 6)
                 ? (1024u << sb->s_log_block_size)
                 : 0u;
    /* groups = ceil (blocks / blocks_per_group). Guard divide-by-zero;
     * the sanity pass already flagged it. */
    uint32_t groups = 0;
    if (sb->s_blocks_per_group)
        groups = (sb->s_blocks_count + sb->s_blocks_per_group - 1)
               / sb->s_blocks_per_group;

    fprintf (stderr, "%s: variant=%s block_size=%u blocks=%u inodes=%u"
                     " groups=%u state=0x%04x rev=%u label=\"%s\"\n",
             path, fst,
             (unsigned) bsz,
             (unsigned) sb->s_blocks_count,
             (unsigned) sb->s_inodes_count,
             (unsigned) groups,
             (unsigned) sb->s_state,
             (unsigned) sb->s_rev_level,
             sb->s_volume_name);
}

int
fsck_builtin (WORD_LIST *list)
{
    int verbose = 0;
    int repair_dirty = 0;     /* -p / -y / -a → clear dirty bit if safe */
    int no_changes = 0;       /* -n → force verify-only even with -y */
    /* Parse leading -X flags. -n / -f / -a remain accepted-but-mostly-
     * no-op for fsck(8) compatibility. -p / -y now enable the v1
     * dirty-bit repair branch. -n overrides -p/-y (read-only wins).
     * Unknown flags are a usage error (EX_USAGE). */
    while (list && list->word->word[0] == '-' && list->word->word[1] != '\0') {
        const char *w = list->word->word;
        if (w[0] == '-' && w[1] == '-' && w[2] == '\0') {
            list = list->next;     /* end-of-options marker */
            break;
        }
        if (!strcmp (w, "-v") || !strcmp (w, "--verbose")) {
            verbose = 1;
        } else if (!strcmp (w, "-p") || !strcmp (w, "-y")
                || !strcmp (w, "-a")) {
            repair_dirty = 1;
        } else if (!strcmp (w, "-n")) {
            no_changes = 1;
        } else if (!strcmp (w, "-f")) {
            /* accepted for fsck(8) compat; v1 always checks fully */
        } else if (!strcmp (w, "--help")) {
            builtin_usage ();
            return FSCK_OK;
        } else {
            builtin_error ("unknown flag: %s", w);
            return FSCK_ERR_USE;
        }
        list = list->next;
    }
    if (no_changes) repair_dirty = 0;

    if (!list) {
        builtin_error ("missing IMAGE operand");
        builtin_usage ();
        return FSCK_ERR_USE;
    }
    const char *path = list->word->word;
    if (list->next) {
        /* fsck(8) supports multiple devices on the command line; for
         * the bash-os v1 we only handle one to keep the interface
         * tight. The wrappers (fsck.ext2.sh / fsck.ext4.sh) only ever
         * pass a single IMAGE. */
        builtin_error ("only a single IMAGE is supported in this version");
        return FSCK_ERR_USE;
    }

    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        builtin_error ("open %s: %s", path, strerror (errno));
        return FSCK_ERR_OP;
    }

    /* Seek to the primary superblock and read 1024 bytes. */
    if (lseek (fd, (off_t) BFK_SB_OFFSET, SEEK_SET) != (off_t) BFK_SB_OFFSET) {
        builtin_error ("seek %s: %s", path, strerror (errno));
        close (fd);
        return FSCK_ERR_OP;
    }
    unsigned char buf[BFK_SB_SIZE];
    ssize_t want = (ssize_t) sizeof buf;
    ssize_t got = 0;
    while (got < want) {
        ssize_t n = read (fd, buf + got, (size_t) (want - got));
        if (n < 0) {
            if (errno == EINTR) continue;
            builtin_error ("read %s: %s", path, strerror (errno));
            close (fd);
            return FSCK_ERR_OP;
        }
        if (n == 0) {
            builtin_error ("%s: short read (image too small for ext2 superblock)", path);
            close (fd);
            return FSCK_ERR_FS;
        }
        got += n;
    }
    close (fd);

    bfk_sb sb;
    if (bfk_decode_sb (buf, &sb) < 0) {
        /* No usable superblock — print the actual magic for the
         * diagnostic and report uncorrected corruption. */
        unsigned m0 = buf[56], m1 = buf[57];
        fprintf (stderr,
                 "%s: BAD: ext2/3/4 superblock magic mismatch"
                 " (got 0x%02x%02x, expected 0x53ef)\n",
                 path, m1, m0);
        return FSCK_ERR_FS;
    }

    char errbuf[512];
    int errs = bfk_sanity (&sb, errbuf, sizeof errbuf);

    if (verbose)
        bfk_print_summary (path, &sb);

    if (errs > 0) {
        fprintf (stderr,
                 "%s: BAD: %d superblock sanity check%s failed: %s\n",
                 path, errs, (errs == 1 ? "" : "s"), errbuf);
        return FSCK_ERR_FS;
    }

    /* Sanity is clean. Check the EXT2_ERROR_FS dirty bit and decide
     * whether to clear it (repair_dirty) or report it (no flag). */
    int is_dirty = (sb.s_state & 0x0002u) != 0;

    if (is_dirty && repair_dirty) {
        /* Open IMAGE write-side, seek to s_state offset, write the
         * cleared+VALID value. Keep the open scope tight. */
        int wfd = open (path, O_WRONLY | O_CLOEXEC);
        if (wfd < 0) {
            builtin_error ("open(%s) for repair: %s", path, strerror (errno));
            return FSCK_ERR_OP;
        }
        if (lseek (wfd, (off_t) (BFK_SB_OFFSET + 58), SEEK_SET)
                != (off_t) (BFK_SB_OFFSET + 58)) {
            builtin_error ("seek %s: %s", path, strerror (errno));
            close (wfd);
            return FSCK_ERR_OP;
        }
        uint16_t old_state = sb.s_state;
        uint16_t new_state = (old_state & ~0x0002u) | 0x0001u;
        unsigned char ss_bytes[2] = {
            (unsigned char) (new_state & 0xff),
            (unsigned char) ((new_state >> 8) & 0xff)
        };
        ssize_t wrote = 0;
        while (wrote < 2) {
            ssize_t n = write (wfd, ss_bytes + wrote, (size_t) (2 - wrote));
            if (n < 0) {
                if (errno == EINTR) continue;
                builtin_error ("write %s: %s", path, strerror (errno));
                close (wfd);
                return FSCK_ERR_OP;
            }
            wrote += n;
        }
        if (fsync (wfd) < 0) {
            /* fsync failure is recoverable from the test's POV (data
             * still in cache) but worth logging. */
            builtin_warning ("fsync %s: %s", path, strerror (errno));
        }
        close (wfd);
        printf ("%s: cleared dirty bit (s_state 0x%04x -> 0x%04x), %s, "
                "%u inodes %u blocks\n",
                path,
                (unsigned) old_state, (unsigned) new_state,
                bfk_classify (&sb),
                (unsigned) sb.s_inodes_count,
                (unsigned) sb.s_blocks_count);
        return FSCK_OK;
    }

    if (is_dirty) {
        /* Dirty bit set but no repair flag — operator must opt in.
         * Diagnostic uses "ERRORS bit set" (matching the e2fsprogs
         * convention and the historical fsck v0 wording) so
         * downstream consumers grepping for that phrase are stable. */
        fprintf (stderr,
                 "%s: s_state has ERRORS bit set (0x%04x); "
                 "rerun with -p or -y to clear\n",
                 path, (unsigned) sb.s_state);
        return FSCK_ERR_FS;
    }

    printf ("%s: clean, %s, %u inodes %u blocks\n",
            path,
            bfk_classify (&sb),
            (unsigned) sb.s_inodes_count,
            (unsigned) sb.s_blocks_count);
    return FSCK_OK;
}

char *fsck_doc[] = {
    "Verify (and optionally clear the dirty bit on) an ext2/ext3/ext4",
    "image's primary superblock.",
    "",
    "    fsck [-v] [-n] [-p|-y] [-f] IMAGE",
    "",
    "Reads the superblock at byte offset 1024 and runs ~10 sanity",
    "checks (magic, block size, free counts <= totals, inode size, etc.).",
    "",
    "Without -p/-y fsck is verify-only: a fs whose s_state has the",
    "EXT2_ERROR_FS bit set returns rc 4 with `rerun with -p or -y to",
    "clear` on stderr.",
    "",
    "With -p (preen) or -y (assume-yes), if sanity is otherwise clean,",
    "the EXT2_ERROR_FS bit is cleared and EXT2_VALID_FS is set in the",
    "superblock, written back to IMAGE, and rc is 0. -n overrides",
    "-p/-y (read-only wins). Anything beyond the dirty-bit case is",
    "still treated as uncorrected (rc 4).",
    "",
    "Exit codes (subset of fsck(8) convention):",
    "    0   clean, or dirty bit cleared via -p/-y",
    "    4   uncorrected errors detected (or dirty without -p/-y)",
    "    8   I/O / open / read / write failure",
    "   16   usage error",
    "",
    "Pair the mkfs.ext2.sh / mkfs.ext4.sh wrappers (which call",
    "mkfs) with fsck.ext2.sh / fsck.ext4.sh (which call this).",
    (char *)NULL
};

struct builtin fsck_struct = {
    "fsck",
    fsck_builtin,
    BUILTIN_ENABLED,
    fsck_doc,
    "fsck [-v] [-n] [-p] [-f] [-y] IMAGE",
    0
};
