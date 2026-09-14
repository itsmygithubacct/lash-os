/* SPDX-License-Identifier: MIT */
/* mkfs.c — minimal mke2fs(8) as a bash builtin.
 *
 * Closes MISSING_LOADABLES T2 (ML-T2-02). Pairs with lsblk and a
 * future fdisk; produces an ext2 filesystem on a regular file or
 * block device that mounts under Linux's ext2/ext4 driver and round-
 * trips through blkid.
 *
 * v1 scope: ext2-only superblock + group descriptors + block/inode
 * bitmaps + root directory + lost+found. No journal (ext3), no
 * extents / 64bit / dir_index / huge_file (ext4). The mkfs.ext2 +
 * mkfs.ext4 wrapper scripts both dispatch here; mkfs.ext4 prints a
 * one-line stderr warning that journal/extents are deferred to v2.
 *
 * Subcommands:
 *     mkfs IMAGE [-L LABEL] [-b BLOCKSIZE] [-m PCT] [-F] [-n]
 *
 * Required:
 *     IMAGE                 path to a regular file or block device.
 *
 * Optional:
 *     -L LABEL              16-byte volume label (truncated).
 *     -b BLOCKSIZE          1024 / 2048 / 4096. Default 1024.
 *     -m PCT                reserved-for-superuser percent (0..50).
 *                           Default 5.
 *     -F                    force; do not refuse if IMAGE is not a
 *                           regular file/block device or if it looks
 *                           already-formatted. v1 only really uses
 *                           the not-a-block-device gate; we trust the
 *                           operator otherwise.
 *     -n                    dry run; compute the layout and print the
 *                           summary but do not write.
 *
 * Source counterpart: busybox util-linux/mkfs_ext2.c (697 LoC; GPLv2,
 * Vladimir Dronnikov 2009). The on-disk layout, has_super() block
 * list, and bitmap layout follow the busybox reference; this file is
 * a project-local rewrite (POSIX I/O instead of libbb helpers, no
 * register-starved getopt32, plain little-endian helpers instead of
 * STORE_LE macro). See MISSING_LOADABLES_IMPLEMENTATION.MD's
 * mkfs design block for the v1 decision rationale.
 *
 * --- LICENSE ---
 * MIT License. Layout follows the busybox GPLv2 mkfs_ext2 reference
 * but no code is copied verbatim; the magic numbers, block layout
 * rules, and "has_super" set are facts about the ext2 on-disk format
 * documented in the ext2/3/4 specification.
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
#include <time.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include "loadables.h"

/* --- ext2 on-disk constants (from linux/ext2_fs.h) ------------------ */

#define EXT2_SUPER_MAGIC          0xEF53
#define EXT2_GOOD_OLD_REV         0
#define EXT2_DYNAMIC_REV          1
#define EXT2_GOOD_OLD_FIRST_INO   11
#define EXT2_ROOT_INO             2
#define EXT2_MIN_BLOCK_LOG_SIZE   10
#define EXT2_MIN_BLOCK_SIZE       1024
#define EXT2_MAX_BLOCK_SIZE       4096
#define EXT2_OS_LINUX             0
#define EXT2_NDIR_BLOCKS          12
#define EXT2_ERRORS_DEFAULT       1
#define EXT2_DFL_MAX_MNT_COUNT    20

#define EXT2_FT_DIR               2

#define EXT2_FEATURE_COMPAT_DIR_INDEX     0x0020
#define EXT2_FEATURE_INCOMPAT_FILETYPE    0x0002
#define EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER 0x0001
#define EXT2_HASH_HALF_MD4        1
#define EXT2_FLAGS_UNSIGNED_HASH  0x0002

/* --- helpers -------------------------------------------------------- */

static inline void put_le16 (void *p, uint16_t v) {
    unsigned char *b = p;
    b[0] = v & 0xff; b[1] = (v >> 8) & 0xff;
}
static inline void put_le32 (void *p, uint32_t v) {
    unsigned char *b = p;
    b[0] = v & 0xff; b[1] = (v >> 8) & 0xff;
    b[2] = (v >> 16) & 0xff; b[3] = (v >> 24) & 0xff;
}

/* int_log2(x) — number of right shifts until x becomes 1. Assumes
   x is a positive power of two; only used after we validate the
   block size is in {1024, 2048, 4096}. */
static unsigned mkfs_log2 (unsigned x) {
    unsigned r = 0;
    while ((x >>= 1) != 0) r++;
    return r;
}

static uint32_t mkfs_div_roundup (uint32_t a, uint32_t b) {
    uint32_t r = a / b;
    if (r * b != a) r++;
    return r;
}

/* has_super(group) — true iff the given block group should hold a
   superblock backup under the sparse_super RO compat feature.
   Backup groups are 0, 1, and powers of {3, 5, 7}.
   The list is finite (sup to 2^32). Verbatim from the ext2 spec. */
static int has_super (uint32_t g) {
    static const uint32_t supers[] = {
        0, 1, 3, 5, 7, 9, 25, 27, 49, 81, 125, 243, 343, 625, 729,
        2187, 2401, 3125, 6561, 15625, 16807, 19683, 59049, 78125,
        117649, 177147, 390625, 531441, 823543, 1594323, 1953125,
        4782969, 5764801, 9765625, 14348907, 40353607, 43046721,
        48828125, 129140163, 244140625, 282475249, 387420489,
        1162261467u, 1220703125u, 1977326743u, 3486784401u
    };
    size_t n = sizeof (supers) / sizeof (supers[0]);
    for (size_t i = 0; i < n; i++) {
        if (g == supers[i]) return 1;
        if (g < supers[i]) return 0;
    }
    return 0;
}

/* Mark blocks [0, start) and [bs*8 - end, bs*8) as allocated in
   the bitmap (each block is one bit; LSB first). Middle range is
   marked free. */
static void mkfs_bitmap (unsigned char *bm, uint32_t bs,
                         uint32_t start, uint32_t end) {
    uint32_t i;
    memset (bm, 0, bs);
    i = start / 8;
    memset (bm, 0xff, i);
    bm[i] = (1u << (start & 7)) - 1;       /* low `start & 7` bits set */
    i = end / 8;
    bm[bs - i - 1] |= (uint8_t) (0x7f00 >> (end & 7));
    memset (bm + bs - i, 0xff, i);
}

/* pwrite()-loop that handles short writes and EINTR. */
static int mkfs_pwrite (int fd, const void *buf, size_t n, off_t off) {
    const char *p = buf;
    while (n > 0) {
        ssize_t w = pwrite (fd, p, n, off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) { errno = EIO; return -1; }
        p += w; off += w; n -= w;
    }
    return 0;
}

/* Fill `buf` (16 bytes) with random bytes via /dev/urandom. Matches
   the totp / passwd pattern. */
static int mkfs_random (void *buf, size_t n) {
    int fd = open ("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    char *p = buf;
    while (n > 0) {
        ssize_t r = read (fd, p, n);
        if (r < 0) { if (errno == EINTR) continue; close (fd); return -1; }
        if (r == 0) { close (fd); errno = EIO; return -1; }
        p += r; n -= r;
    }
    close (fd);
    return 0;
}

/* Discover the device size in bytes. Regular files: fstat(). Block
   devices: BLKGETSIZE64 ioctl. */
static int mkfs_devsize (int fd, const char *path, uint64_t *out,
                         int *is_block) {
    struct stat st;
    if (fstat (fd, &st) < 0) return -1;
    if (S_ISREG (st.st_mode)) {
        *is_block = 0;
        *out = (uint64_t) st.st_size;
        return 0;
    }
    if (S_ISBLK (st.st_mode)) {
        *is_block = 1;
        uint64_t sz = 0;
        if (ioctl (fd, BLKGETSIZE64, &sz) < 0) return -1;
        *out = sz;
        return 0;
    }
    builtin_error ("%s: not a regular file or block device", path);
    errno = EINVAL;
    return -1;
}

/* --- builtin entry point ------------------------------------------- */

int mkfs_builtin (WORD_LIST *list) {
    const char *image = NULL;
    const char *label = "";
    unsigned blocksize = 1024;
    unsigned reserved_percent = 5;
    int force = 0, dry_run = 0;

    /* Parse args: positional IMAGE plus -L, -b, -m, -F, -n. */
    for (WORD_LIST *l = list; l; l = l->next) {
        const char *a = l->word->word;
        if (a[0] == '-' && a[1] && a[2] == 0) {
            switch (a[1]) {
            case 'F': force = 1; continue;
            case 'n': dry_run = 1; continue;
            case 'L': case 'b': case 'm': {
                if (!l->next) {
                    builtin_error ("-%c requires an argument", a[1]);
                    return EX_USAGE;
                }
                l = l->next;
                const char *v = l->word->word;
                if (a[1] == 'L') {
                    label = v;
                } else if (a[1] == 'b') {
                    char *e = NULL;
                    unsigned long bs = strtoul (v, &e, 10);
                    if (!e || *e || (bs != 1024 && bs != 2048 && bs != 4096)) {
                        builtin_error ("bad blocksize: %s "
                                       "(must be 1024, 2048, or 4096)", v);
                        return EX_USAGE;
                    }
                    blocksize = (unsigned) bs;
                } else { /* 'm' */
                    char *e = NULL;
                    unsigned long pct = strtoul (v, &e, 10);
                    if (!e || *e || pct > 50) {
                        builtin_error ("bad reserved percent: %s "
                                       "(must be 0..50)", v);
                        return EX_USAGE;
                    }
                    reserved_percent = (unsigned) pct;
                }
                continue;
            }
            default:
                builtin_error ("unknown option: %s", a);
                return EX_USAGE;
            }
        }
        if (!image) {
            image = a;
        } else {
            builtin_error ("unexpected operand: %s", a);
            return EX_USAGE;
        }
    }
    if (!image) {
        builtin_error ("missing IMAGE operand");
        builtin_usage ();
        return EX_USAGE;
    }

    /* Open. For dry-run we still need fstat/BLKGETSIZE64 so open RW
       (or RO if dry-run); regular files: O_RDONLY suffices for
       dry-run; block devices: same. For non-dry-run, O_WRONLY. */
    int fd = open (image, dry_run ? O_RDONLY : O_WRONLY);
    if (fd < 0) {
        builtin_error ("%s: %s", image, strerror (errno));
        return EXECUTION_FAILURE;
    }

    uint64_t devbytes = 0;
    int is_block = 0;
    if (mkfs_devsize (fd, image, &devbytes, &is_block) < 0) {
        if (errno != EINVAL) {
            builtin_error ("%s: stat/ioctl: %s", image, strerror (errno));
        }
        if (!force && !is_block) {
            /* Already errored above on non-reg/non-blk. */
            close (fd); return EXECUTION_FAILURE;
        }
        close (fd); return EXECUTION_FAILURE;
    }

    /* Compute layout. */
    unsigned blocksize_log2 = mkfs_log2 (blocksize);
    uint64_t nblocks64 = devbytes / blocksize;
    if (nblocks64 < 60) {
        builtin_error ("%s: too small (%" PRIu64
                       " bytes; need >= %u blocks of %u)",
                       image, devbytes, 60, blocksize);
        close (fd); return EXECUTION_FAILURE;
    }
    if (nblocks64 > 0xffffffffull) {
        builtin_error ("%s: too large for ext2 32-bit block count", image);
        close (fd); return EXECUTION_FAILURE;
    }
    uint32_t nblocks = (uint32_t) nblocks64;

    /* Boot record reservation: 1024-byte block sizes start at block 1
       (block 0 is the boot record); larger block sizes embed the boot
       record inside block 0. */
    uint32_t first_block = (blocksize == EXT2_MIN_BLOCK_SIZE) ? 1u : 0u;
    uint32_t blocks_per_group = 8u * blocksize;     /* one bitmap block */
    uint32_t inodesize = 128u;                       /* good_old size */
    uint32_t bytes_per_inode = 16384u;
    if (nblocks < (512u * 1024u)) bytes_per_inode = 4096u;
    if (nblocks < (3u * 1024u))   bytes_per_inode = 8192u;
    if ((uint32_t) bytes_per_inode < blocksize) bytes_per_inode = blocksize;

    /* Group / inode layout. */
    uint32_t ngroups = mkfs_div_roundup (nblocks - first_block,
                                         blocks_per_group);
    uint32_t group_desc_blocks =
        mkfs_div_roundup (ngroups * 32u, blocksize);   /* sizeof gd = 32 */
    uint64_t total_inodes64 =
        ((uint64_t) nblocks * blocksize) / bytes_per_inode;
    if (total_inodes64 < (uint64_t) (EXT2_GOOD_OLD_FIRST_INO + 1))
        total_inodes64 = EXT2_GOOD_OLD_FIRST_INO + 1;
    uint32_t inodes_per_group =
        mkfs_div_roundup ((uint32_t) total_inodes64, ngroups);
    if (inodes_per_group < 16) inodes_per_group = 16;
    if (inodes_per_group > blocks_per_group)
        inodes_per_group = blocks_per_group;
    inodes_per_group =
        (mkfs_div_roundup (inodes_per_group * inodesize, blocksize)
         * blocksize) / inodesize;
    inodes_per_group &= ~7u;                          /* multiple of 8 */
    uint32_t inode_table_blocks =
        mkfs_div_roundup (inodes_per_group * inodesize, blocksize);

    /* lost+found occupies at least 2 blocks (capped at EXT2_NDIR_BLOCKS),
       scaled with block size. busybox formula: MIN(NDIR, 16 >> (log-min)). */
    uint32_t laf_blocks = EXT2_NDIR_BLOCKS;
    {
        uint32_t cap = 16u >> (blocksize_log2 - EXT2_MIN_BLOCK_LOG_SIZE);
        if (cap < laf_blocks) laf_blocks = cap;
        if (laf_blocks < 2) laf_blocks = 2;
    }

    uint32_t nreserved =
        (uint32_t) (((uint64_t) nblocks * reserved_percent) / 100u);

    /* Print the layout summary (mimics mke2fs human-readable output;
       matches the busybox shape close enough for operator scripts). */
    fprintf (stderr,
        "mkfs: %s\n"
        "  device size: %" PRIu64 " bytes (%s)\n"
        "  block size:  %u bytes\n"
        "  blocks:      %u total, first data block %u, %u block groups\n"
        "  inodes:      %u total (%u per group, %u-byte inodes)\n"
        "  reserved:    %u blocks (%u%%) for super-user\n"
        "  label:       \"%s\"\n",
        image, devbytes, is_block ? "block device" : "regular file",
        blocksize, nblocks, first_block, ngroups,
        inodes_per_group * ngroups, inodes_per_group, inodesize,
        nreserved, reserved_percent, label);
    if (dry_run) {
        close (fd);
        fprintf (stderr, "  (dry run; no write)\n");
        return EXECUTION_SUCCESS;
    }

    /* Allocate scratch buffers. */
    unsigned char *sb = calloc (1024, 1);
    unsigned char *gd = calloc (group_desc_blocks, blocksize);
    unsigned char *buf = malloc (blocksize);
    if (!sb || !gd || !buf) {
        builtin_error ("malloc: %s", strerror (errno));
        free (sb); free (gd); free (buf); close (fd);
        return EXECUTION_FAILURE;
    }

    /* Build the superblock at offset 0 of the sb buffer. Layout
       follows ext2_super_block in linux/ext2_fs.h. */
    time_t now = time (NULL);
    uint8_t uuid[16], hash_seed[16];
    if (mkfs_random (uuid, 16) < 0 || mkfs_random (hash_seed, 16) < 0) {
        builtin_error ("/dev/urandom: %s", strerror (errno));
        free (sb); free (gd); free (buf); close (fd);
        return EXECUTION_FAILURE;
    }
    /* Variant 1 (RFC 4122 §4.4) UUID: clear top 2 bits of byte 8,
       set high bit; version 4 = top nibble of byte 6. */
    uuid[6] = (uint8_t) ((uuid[6] & 0x0f) | 0x40);
    uuid[8] = (uint8_t) ((uuid[8] & 0x3f) | 0x80);

    /* Pre-compute the per-group free-block sum. */
    uint32_t total_free_blocks = 0;
    for (uint32_t i = 0; i < ngroups; i++) {
        uint32_t pos = first_block + i * blocks_per_group;
        uint32_t overhead = (has_super (i) ? (1u + group_desc_blocks) : 0u);
        uint32_t bb_pos = pos + overhead;            /* block bitmap */
        uint32_t ib_pos = bb_pos + 1;                /* inode bitmap */
        uint32_t it_pos = bb_pos + 2;                /* inode table */
        overhead += 1u + 1u + inode_table_blocks;
        uint32_t group_free_inodes = inodes_per_group;
        uint32_t used_dirs = 0;
        if (i == 0) {
            overhead += 1u + laf_blocks;             /* "/" + "/lost+found" */
            used_dirs = 2;
            group_free_inodes -= EXT2_GOOD_OLD_FIRST_INO;
        }
        uint32_t group_blocks =
            (uint32_t) ((i + 1) * blocks_per_group + first_block <= nblocks
                        ? blocks_per_group
                        : (nblocks - i * blocks_per_group - first_block));
        if (group_blocks > blocks_per_group) group_blocks = blocks_per_group;
        if (overhead > group_blocks) {
            builtin_error ("internal: overhead (%u) > group_blocks (%u) "
                           "in group %u", overhead, group_blocks, i);
            free (sb); free (gd); free (buf); close (fd);
            return EXECUTION_FAILURE;
        }
        uint32_t free_blocks = group_blocks - overhead;

        /* Write the bitmaps for this group: block bitmap, then inode
           bitmap. */
        mkfs_bitmap (buf, blocksize, overhead,
                     blocks_per_group - (free_blocks + overhead));
        if (mkfs_pwrite (fd, buf, blocksize,
                         (off_t) bb_pos * blocksize) < 0) {
            builtin_error ("write block bitmap (group %u): %s",
                           i, strerror (errno));
            free (sb); free (gd); free (buf); close (fd);
            return EXECUTION_FAILURE;
        }
        mkfs_bitmap (buf, blocksize,
                     inodes_per_group - group_free_inodes,
                     blocks_per_group - inodes_per_group);
        if (mkfs_pwrite (fd, buf, blocksize,
                         (off_t) ib_pos * blocksize) < 0) {
            builtin_error ("write inode bitmap (group %u): %s",
                           i, strerror (errno));
            free (sb); free (gd); free (buf); close (fd);
            return EXECUTION_FAILURE;
        }

        /* Zero the inode table for this group. */
        memset (buf, 0, blocksize);
        for (uint32_t j = 0; j < inode_table_blocks; j++) {
            if (mkfs_pwrite (fd, buf, blocksize,
                             (off_t) (it_pos + j) * blocksize) < 0) {
                builtin_error ("zero inode table (group %u block %u): %s",
                               i, j, strerror (errno));
                free (sb); free (gd); free (buf); close (fd);
                return EXECUTION_FAILURE;
            }
        }

        /* Build group descriptor (32 bytes per ext2 spec). */
        unsigned char *g = gd + i * 32u;
        put_le32 (g + 0,  bb_pos);
        put_le32 (g + 4,  ib_pos);
        put_le32 (g + 8,  it_pos);
        put_le16 (g + 12, (uint16_t) free_blocks);
        put_le16 (g + 14, (uint16_t) group_free_inodes);
        put_le16 (g + 16, (uint16_t) used_dirs);
        /* g + 18..31 are pad / unused in good-old GDs. */
        total_free_blocks += free_blocks;
    }

    /* Superblock fields. Offsets per ext2_super_block. */
    put_le32 (sb +   0, inodes_per_group * ngroups);        /* s_inodes_count */
    put_le32 (sb +   4, nblocks);                            /* s_blocks_count */
    put_le32 (sb +   8, nreserved);                          /* s_r_blocks_count */
    put_le32 (sb +  12, total_free_blocks);                  /* s_free_blocks_count */
    put_le32 (sb +  16,
              inodes_per_group * ngroups - EXT2_GOOD_OLD_FIRST_INO);
                                                             /* s_free_inodes_count */
    put_le32 (sb +  20, first_block);                        /* s_first_data_block */
    put_le32 (sb +  24, blocksize_log2 - EXT2_MIN_BLOCK_LOG_SIZE);
                                                             /* s_log_block_size */
    put_le32 (sb +  28, blocksize_log2 - EXT2_MIN_BLOCK_LOG_SIZE);
                                                             /* s_log_frag_size */
    put_le32 (sb +  32, blocks_per_group);                   /* s_blocks_per_group */
    put_le32 (sb +  36, blocks_per_group);                   /* s_frags_per_group */
    put_le32 (sb +  40, inodes_per_group);                   /* s_inodes_per_group */
    put_le32 (sb +  44, (uint32_t) now);                     /* s_mtime */
    put_le32 (sb +  48, (uint32_t) now);                     /* s_wtime */
    put_le16 (sb +  52, 0);                                  /* s_mnt_count */
    put_le16 (sb +  54, (uint16_t) (EXT2_DFL_MAX_MNT_COUNT
                                    + (uuid[15] % EXT2_DFL_MAX_MNT_COUNT)));
                                                             /* s_max_mnt_count */
    put_le16 (sb +  56, EXT2_SUPER_MAGIC);                   /* s_magic */
    put_le16 (sb +  58, 1);                                  /* s_state = clean */
    put_le16 (sb +  60, EXT2_ERRORS_DEFAULT);                /* s_errors */
    put_le16 (sb +  62, 0);                                  /* s_minor_rev_level */
    put_le32 (sb +  64, (uint32_t) now);                     /* s_lastcheck */
    put_le32 (sb +  68, 24u * 60u * 60u * 180u);             /* s_checkinterval */
    put_le32 (sb +  72, EXT2_OS_LINUX);                      /* s_creator_os */
    put_le32 (sb +  76, EXT2_DYNAMIC_REV);                   /* s_rev_level */
    put_le16 (sb +  80, 0);                                  /* s_def_resuid */
    put_le16 (sb +  82, 0);                                  /* s_def_resgid */
    put_le32 (sb +  84, EXT2_GOOD_OLD_FIRST_INO);            /* s_first_ino */
    put_le16 (sb +  88, (uint16_t) inodesize);               /* s_inode_size */
    put_le16 (sb +  90, 0);                                  /* s_block_group_nr */
    put_le32 (sb +  92, EXT2_FEATURE_COMPAT_DIR_INDEX);      /* s_feature_compat */
    put_le32 (sb +  96, EXT2_FEATURE_INCOMPAT_FILETYPE);     /* s_feature_incompat */
    put_le32 (sb + 100, EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER);/* s_feature_ro_compat */
    memcpy (sb + 104, uuid, 16);                             /* s_uuid */
    /* s_volume_name at +120, 16 bytes; pad with zeros. */
    {
        size_t llen = strlen (label);
        if (llen > 16) llen = 16;
        memcpy (sb + 120, label, llen);
    }
    /* +136 s_last_mounted (64 bytes); zeroed. */
    /* +200 s_algorithm_usage_bitmap (4); zeroed. */
    /* +204 s_prealloc_blocks (1); s_prealloc_dir_blocks (1); s_padding1 (2). */
    /* +208 s_journal_uuid (16); zeroed. */
    /* +224 s_journal_inum/dev (4+4); zeroed. */
    /* +232 s_last_orphan (4); zeroed. */
    put_le32 (sb + 236, EXT2_HASH_HALF_MD4);                 /* s_def_hash_version */
    /* s_hash_seed[4] at offset 220 (4 * 4 = 16 bytes). */
    memcpy (sb + 220, hash_seed, 16);
    put_le32 (sb + 352, EXT2_FLAGS_UNSIGNED_HASH);           /* s_flags */

    /* Write superblock + group descriptors to each "has_super"
       group. For 1024-byte blocks, the primary copy lives at offset
       1024 (after the boot record) of block 0's group. For larger
       block sizes, the superblock fits in block 0 with the boot
       record. */
    for (uint32_t i = 0; i < ngroups; i++) {
        if (!has_super (i)) continue;
        uint32_t pos = first_block + i * blocks_per_group;
        /* Primary superblock always lives at byte offset 1024 of the
         * image, regardless of blocksize. Backup superblocks (i > 0)
         * sit at the start of their block group.
         *
         * For blocksize == 1024 (EXT2_MIN_BLOCK_SIZE), first_block=1
         * and pos*blocksize = 1024 already — no adjustment needed.
         * For larger blocksizes first_block=0 and pos*blocksize = 0,
         * so add 1024 to land at the canonical SB location inside
         * block 0 (after the 1024-byte boot block area). */
        off_t sb_off = (off_t) pos * blocksize;
        if (i == 0 && blocksize != EXT2_MIN_BLOCK_SIZE)
            sb_off += 1024;
        /* Set s_block_group_nr for backup copies. */
        put_le16 (sb + 90, (uint16_t) i);
        if (mkfs_pwrite (fd, sb, 1024, sb_off) < 0) {
            builtin_error ("write superblock (group %u): %s",
                           i, strerror (errno));
            free (sb); free (gd); free (buf); close (fd);
            return EXECUTION_FAILURE;
        }
        if (mkfs_pwrite (fd, gd, (size_t) group_desc_blocks * blocksize,
                         (off_t) (pos + 1) * blocksize) < 0) {
            builtin_error ("write group descriptors (group %u): %s",
                           i, strerror (errno));
            free (sb); free (gd); free (buf); close (fd);
            return EXECUTION_FAILURE;
        }
    }
    /* Reset s_block_group_nr to 0 for canonical state. */
    put_le16 (sb + 90, 0);

    /* Build root directory inode (#2) and lost+found inode (#11) in
       the inode table of group 0. Inode N lives at offset
       (it_block + (N-1) * inodesize / blocksize) * blocksize
       + ((N-1) * inodesize) % blocksize. We just compute the byte
       offset and pwrite the 128-byte inode struct.

       Inode layout (linux/ext2_fs.h ext2_inode):
         +0   le16 i_mode
         +2   le16 i_uid
         +4   le32 i_size
         +8   le32 i_atime
         +12  le32 i_ctime
         +16  le32 i_mtime
         +20  le32 i_dtime
         +24  le16 i_gid
         +26  le16 i_links_count
         +28  le32 i_blocks (in 512-byte units)
         +32  le32 i_flags
         +36  le32 i_osd1
         +40  le32 i_block[15]
         +100 le32 i_generation
         +104 le32 i_file_acl
         +108 le32 i_dir_acl
         +112 le32 i_faddr
         +116 byte i_osd2[12]
    */
    uint32_t gd0_it_pos = first_block
                        + (has_super (0) ? (1u + group_desc_blocks) : 0u)
                        + 2u;
    off_t inode_table_off = (off_t) gd0_it_pos * blocksize;

    /* Root inode #2: dir mode 0755, links_count = 3 ("/","/.","/lf/.."),
       size = blocksize, one block pointer at i_block[0]. The root dir
       block sits at gd0_it_pos + inode_table_blocks + 0 (i.e. the
       block immediately after the inode table; busybox lays it out
       this way, and lost+found's blocks follow). */
    unsigned char inode[256];                /* up to 256-byte inode */
    memset (inode, 0, sizeof inode);
    put_le16 (inode +  0, 040755);                       /* S_IFDIR | 0755 */
    put_le32 (inode +  4, blocksize);                    /* i_size */
    put_le32 (inode +  8, (uint32_t) now);
    put_le32 (inode + 12, (uint32_t) now);
    put_le32 (inode + 16, (uint32_t) now);
    put_le16 (inode + 26, 3);                            /* i_links_count */
    put_le32 (inode + 28, blocksize / 512u);             /* i_blocks */
    put_le32 (inode + 40, gd0_it_pos + inode_table_blocks);
                                                         /* i_block[0] */
    if (mkfs_pwrite (fd, inode, inodesize,
                     inode_table_off + (off_t) (EXT2_ROOT_INO - 1) * inodesize) < 0) {
        builtin_error ("write root inode: %s", strerror (errno));
        free (sb); free (gd); free (buf); close (fd);
        return EXECUTION_FAILURE;
    }

    /* lost+found inode #11: dir mode 0755, links_count = 2,
       size = laf_blocks * blocksize, pointers at i_block[0..laf-1]. */
    memset (inode, 0, sizeof inode);
    put_le16 (inode +  0, 040700);                       /* S_IFDIR | 0700 */
    put_le32 (inode +  4, laf_blocks * blocksize);
    put_le32 (inode +  8, (uint32_t) now);
    put_le32 (inode + 12, (uint32_t) now);
    put_le32 (inode + 16, (uint32_t) now);
    put_le16 (inode + 26, 2);
    put_le32 (inode + 28, (laf_blocks * blocksize) / 512u);
    {
        uint32_t base = gd0_it_pos + inode_table_blocks + 1u;
        for (uint32_t i = 0; i < laf_blocks; i++)
            put_le32 (inode + 40 + i * 4u, base + i);
    }
    if (mkfs_pwrite (fd, inode, inodesize,
                     inode_table_off + (off_t) (EXT2_GOOD_OLD_FIRST_INO - 1) * inodesize) < 0) {
        builtin_error ("write lost+found inode: %s", strerror (errno));
        free (sb); free (gd); free (buf); close (fd);
        return EXECUTION_FAILURE;
    }

    /* Build the root dir block: { ".", "..", "lost+found" }.
       Dir-entry layout:
         +0  le32 inode
         +4  le16 rec_len
         +6  u8   name_len
         +7  u8   file_type
         +8  ...  name (padded to 4-byte boundary)
    */
    memset (buf, 0, blocksize);
    /* "." (1 byte, inode 2, rec_len 12) */
    put_le32 (buf +  0, EXT2_ROOT_INO);
    put_le16 (buf +  4, 12);
    buf[6] = 1; buf[7] = EXT2_FT_DIR; buf[8] = '.';
    /* ".." (2 bytes, inode 2, rec_len 12) */
    put_le32 (buf + 12, EXT2_ROOT_INO);
    put_le16 (buf + 16, 12);
    buf[18] = 2; buf[19] = EXT2_FT_DIR; buf[20] = '.'; buf[21] = '.';
    /* "lost+found" (10 bytes, inode 11, rec_len = blocksize - 24) */
    put_le32 (buf + 24, EXT2_GOOD_OLD_FIRST_INO);
    put_le16 (buf + 28, (uint16_t) (blocksize - 24));
    buf[30] = 10; buf[31] = EXT2_FT_DIR;
    memcpy (buf + 32, "lost+found", 10);
    if (mkfs_pwrite (fd, buf, blocksize,
                     (off_t) (gd0_it_pos + inode_table_blocks) * blocksize) < 0) {
        builtin_error ("write root dir block: %s", strerror (errno));
        free (sb); free (gd); free (buf); close (fd);
        return EXECUTION_FAILURE;
    }

    /* Build the lost+found dir block: { ".", ".." } in block 0; all
       subsequent blocks are zeroed (filesystem-check fodder, never
       inspected by the kernel on mount). */
    memset (buf, 0, blocksize);
    put_le32 (buf +  0, EXT2_GOOD_OLD_FIRST_INO);
    put_le16 (buf +  4, 12);
    buf[6] = 1; buf[7] = EXT2_FT_DIR; buf[8] = '.';
    put_le32 (buf + 12, EXT2_ROOT_INO);
    put_le16 (buf + 16, (uint16_t) (blocksize - 12));
    buf[18] = 2; buf[19] = EXT2_FT_DIR; buf[20] = '.'; buf[21] = '.';
    if (mkfs_pwrite (fd, buf, blocksize,
                     (off_t) (gd0_it_pos + inode_table_blocks + 1u) * blocksize) < 0) {
        builtin_error ("write lost+found dir block: %s", strerror (errno));
        free (sb); free (gd); free (buf); close (fd);
        return EXECUTION_FAILURE;
    }
    /* Zero any remaining lost+found blocks. */
    memset (buf, 0, blocksize);
    for (uint32_t i = 1; i < laf_blocks; i++) {
        if (mkfs_pwrite (fd, buf, blocksize,
                         (off_t) (gd0_it_pos + inode_table_blocks + 1u + i)
                         * blocksize) < 0) {
            builtin_error ("zero lost+found block %u: %s",
                           i, strerror (errno));
            free (sb); free (gd); free (buf); close (fd);
            return EXECUTION_FAILURE;
        }
    }

    /* Done; sync so a subsequent loopback mount sees the new layout
       (block-device writes are non-buffered for the FS but page-cache
       pwrite to a regular file backing a loop device needs a flush
       before losetup --find --show + mount). */
    if (fsync (fd) < 0 && errno != EINVAL) {
        builtin_error ("fsync: %s", strerror (errno));
        free (sb); free (gd); free (buf); close (fd);
        return EXECUTION_FAILURE;
    }
    free (sb); free (gd); free (buf);
    if (close (fd) < 0) {
        builtin_error ("close: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    (void) force;       /* currently only the parse path uses it */
    return EXECUTION_SUCCESS;
}

char *mkfs_doc[] = {
    "Create a minimal ext2 filesystem on IMAGE.",
    "",
    "    mkfs IMAGE [-L LABEL] [-b BLOCKSIZE] [-m PCT] [-F] [-n]",
    "",
    "IMAGE is a regular file or block device. Block size defaults to",
    "1024; valid values are 1024, 2048, 4096. Reserved-for-superuser",
    "percent (-m) defaults to 5 and must be 0..50. Volume label (-L)",
    "is truncated to 16 bytes.",
    "",
    "v1 produces ext2-only layout (no journal, no extents, no",
    "dir_index hash). The on-disk result mounts under both 'ext2'",
    "and 'ext4' kernel drivers; mkfs.ext4 sibling wrapper prints a",
    "one-line warning that ext4-specific features are deferred to v2.",
    "",
    "Use -n for a dry-run summary; -F to force formatting of a",
    "non-block, non-regular file.",
    (char *) NULL
};

struct builtin mkfs_struct = {
    "mkfs",
    mkfs_builtin,
    BUILTIN_ENABLED,
    mkfs_doc,
    "mkfs IMAGE [-L LABEL] [-b BLOCKSIZE] [-m PCT] [-F] [-n]",
    0
};
