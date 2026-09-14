/* bashdf.c — POSIX df(1) as a bash builtin.
 *
 * Phase T of bash-os POSIX gap-fillers.
 *
 *   bashdf [-ahHiklmPT] [-t TYPE] [-x TYPE] [FILE...]
 *
 *   -a   show all filesystems, including pseudo filesystems
 *   -h   human-readable sizes (1.0K, 2.5G, etc.)
 *   -H   SI human-readable sizes, powers of 1000 (1.0k, 2.5G, etc.)
 *   -i   list inode usage instead of block usage
 *   -k   1024-byte blocks (POSIX default; we follow this even without -k)
 *   -m   1024K-byte (1M) blocks
 *   -l   limit listing to local filesystems
 *   -P   POSIX output format: 6 columns, no breaks
 *   -t   limit listing to filesystems of type TYPE
 *   -T   print filesystem type column
 *   -x   exclude filesystems of type TYPE
 *
 * No FILE: enumerate /proc/mounts and report each mounted filesystem.
 * With FILE: report the FS containing each path.
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
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <sys/statvfs.h>
#include <sys/stat.h>

#include "loadables.h"

typedef struct {
    int aflag, hflag, Hflag, iflag, kflag, lflag, mflag, Pflag, Tflag;
    int totalflag, output_count, block_explicit;
    const char *type_filter;
    const char *exclude_type;
    uint64_t block_size;
    char block_suffix;
    char block_label[32];
    int output_fields[16];
} bdf_opts;

typedef struct {
    const char **v;
    int n;
    int cap;
} bdf_words;

enum {
    BDF_OUT_SOURCE,
    BDF_OUT_FSTYPE,
    BDF_OUT_SIZE,
    BDF_OUT_USED,
    BDF_OUT_AVAIL,
    BDF_OUT_PCENT,
    BDF_OUT_FILE,
    BDF_OUT_TARGET,
    BDF_OUT_ITOTAL,
    BDF_OUT_IUSED,
    BDF_OUT_IAVAIL,
    BDF_OUT_IPCENT
};

typedef struct {
    const char *fs;
    const char *type;
    const char *path;
    uint64_t total, used, avail;
    uint64_t inodes, iused, ifree;
    int use_pct, iuse_pct;
} bdf_row;

extern char *df_doc[];

static void
bdf_print_help (void)
{
    for (char **lp = df_doc; *lp; lp++)
        puts (*lp);
}

static int
bdf_words_add (bdf_words *w, const char *s)
{
    if (w->n == w->cap) {
        int ncap = w->cap ? w->cap * 2 : 32;
        const char **nv = realloc (w->v, (size_t) ncap * sizeof *nv);
        if (!nv) return -1;
        w->v = nv;
        w->cap = ncap;
    }
    w->v[w->n++] = s;
    return 0;
}

/* Decode any backslash-octal escapes in /proc/mounts entries. */
static void
bdf_unescape (char *s)
{
    char *r = s, *w = s;
    while (*r) {
        if (*r == '\\' && r[1] >= '0' && r[1] <= '7'
            && r[2] >= '0' && r[2] <= '7' && r[3] >= '0' && r[3] <= '7') {
            *w++ = (char) (((r[1] - '0') << 6) | ((r[2] - '0') << 3) | (r[3] - '0'));
            r += 4;
        } else {
            *w++ = *r++;
        }
    }
    *w = '\0';
}

static int
bdf_is_remote_type (const char *type)
{
    return strcmp (type, "9p") == 0
        || strcmp (type, "nfs") == 0
        || strcmp (type, "nfs4") == 0
        || strcmp (type, "cifs") == 0
        || strcmp (type, "smbfs") == 0
        || strcmp (type, "sshfs") == 0
        || strcmp (type, "fuse.sshfs") == 0
        || strcmp (type, "fuse.virtiofs") == 0
        || strcmp (type, "virtiofs") == 0;
}

static int
bdf_type_selected (const bdf_opts *o, const char *type)
{
    return o->type_filter == NULL || strcmp (o->type_filter, type) == 0;
}

static int
bdf_type_excluded (const bdf_opts *o, const char *type)
{
    return o->exclude_type != NULL && strcmp (o->exclude_type, type) == 0;
}

static void
bdf_human (uint64_t bytes, int si, char *out, size_t outsz)
{
    const char *unit = si ? " kMGTPE" : " KMGTPE";
    const double base = si ? 1000.0 : 1024.0;
    double v = (double) bytes;
    int u = 0;
    while (v >= base && u < 6) { v /= base; u++; }
    if (u == 0) { snprintf (out, outsz, "%" PRIu64, bytes); return; }
    /* GNU df -h/-H rounds UP (ceiling) at the display precision, so the
       shown figure is never smaller than the true size: one decimal below
       10, integer at/above 10. */
    if (v < 10.0) {
        double r = ceil (v * 10.0) / 10.0;
        if (r < 10.0) { snprintf (out, outsz, "%.1f%c", r, unit[u]); return; }
        v = r;                                  /* carried into the >=10 range */
    }
    v = ceil (v);
    if (v >= base && u < 6)                      /* carried into the next unit */
        snprintf (out, outsz, "1.0%c", unit[u + 1]);
    else
        snprintf (out, outsz, "%.0f%c", v, unit[u]);
}

static uint64_t
bdf_div_ceil (uint64_t n, uint64_t d)
{
    if (d == 0)
        return 0;
    return n / d + (n % d != 0);
}

static const char *
bdf_block_label (const bdf_opts *o)
{
    if (o->block_label[0])
        return o->block_label;
    if (o->mflag)
        return "1M-blocks";
    if (o->Pflag)
        return "1024-blocks";
    return "1K-blocks";
}

static uint64_t
bdf_block_size (const bdf_opts *o)
{
    if (o->block_explicit && o->block_size)
        return o->block_size;
    if (o->mflag)
        return 1024ULL * 1024ULL;
    return 1024;
}

static void
bdf_block_value (uint64_t bytes, const bdf_opts *o, char *out, size_t outsz)
{
    uint64_t v = bdf_div_ceil (bytes, bdf_block_size (o));
    if (o->block_suffix)
        snprintf (out, outsz, "%" PRIu64 "%c", v, o->block_suffix);
    else
        snprintf (out, outsz, "%" PRIu64, v);
}

static int
bdf_parse_block_size (const char *arg, bdf_opts *o)
{
    char *end = NULL;
    uint64_t n = 1, mult = 1;
    char suffix = '\0';

    if (arg == NULL || *arg == '\0')
        return -1;
    errno = 0;
    if (arg[0] >= '0' && arg[0] <= '9') {
        unsigned long long parsed = strtoull (arg, &end, 10);
        if (errno || parsed == 0)
            return -1;
        n = (uint64_t) parsed;
    } else {
        end = (char *) arg;
    }
    if (*end) {
        char c = *end++;
        if (*end == 'B' && end[1] == '\0')
            end++;
        if (*end != '\0')
            return -1;
        switch (c) {
        case 'K': case 'k': mult = 1024ULL; suffix = 'K'; break;
        case 'M': case 'm': mult = 1024ULL * 1024ULL; suffix = 'M'; break;
        case 'G': case 'g': mult = 1024ULL * 1024ULL * 1024ULL; suffix = 'G'; break;
        case 'T': case 't': mult = 1024ULL * 1024ULL * 1024ULL * 1024ULL; suffix = 'T'; break;
        case 'P': case 'p': mult = 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL; suffix = 'P'; break;
        case 'E': case 'e': mult = 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL; suffix = 'E'; break;
        case 'B': mult = 1; suffix = '\0'; break;
        default: return -1;
        }
    }
    if (n > UINT64_MAX / mult)
        return -1;
    o->block_size = n * mult;
    o->block_explicit = 1;
    o->mflag = 0;
    o->block_suffix = suffix;
    if (suffix)
        snprintf (o->block_label, sizeof o->block_label, "%" PRIu64 "%c-blocks", n, suffix);
    else
        snprintf (o->block_label, sizeof o->block_label, "%" PRIu64 "B-blocks", n);
    return 0;
}

static int
bdf_field_id (const char *name)
{
    if (strcmp (name, "source") == 0) return BDF_OUT_SOURCE;
    if (strcmp (name, "fstype") == 0) return BDF_OUT_FSTYPE;
    if (strcmp (name, "size") == 0) return BDF_OUT_SIZE;
    if (strcmp (name, "used") == 0) return BDF_OUT_USED;
    if (strcmp (name, "avail") == 0) return BDF_OUT_AVAIL;
    if (strcmp (name, "pcent") == 0) return BDF_OUT_PCENT;
    if (strcmp (name, "file") == 0) return BDF_OUT_FILE;
    if (strcmp (name, "target") == 0) return BDF_OUT_TARGET;
    if (strcmp (name, "itotal") == 0) return BDF_OUT_ITOTAL;
    if (strcmp (name, "iused") == 0) return BDF_OUT_IUSED;
    if (strcmp (name, "iavail") == 0) return BDF_OUT_IAVAIL;
    if (strcmp (name, "ipcent") == 0) return BDF_OUT_IPCENT;
    return -1;
}

static int
bdf_output_add (bdf_opts *o, int id)
{
    if (o->output_count >= (int) (sizeof o->output_fields / sizeof o->output_fields[0]))
        return -1;
    o->output_fields[o->output_count++] = id;
    return 0;
}

static int
bdf_parse_output (const char *spec, bdf_opts *o)
{
    char *copy, *tok, *save;

    o->output_count = 0;
    if (spec == NULL || *spec == '\0') {
        int defaults[] = { BDF_OUT_SOURCE, BDF_OUT_SIZE, BDF_OUT_USED,
                           BDF_OUT_AVAIL, BDF_OUT_PCENT, BDF_OUT_TARGET };
        for (size_t i = 0; i < sizeof defaults / sizeof defaults[0]; i++)
            if (bdf_output_add (o, defaults[i]) < 0)
                return -1;
        return 0;
    }

    copy = strdup (spec);
    if (copy == NULL)
        return -1;
    for (tok = strtok_r (copy, ",", &save); tok; tok = strtok_r (NULL, ",", &save)) {
        int id = bdf_field_id (tok);
        if (id < 0 || bdf_output_add (o, id) < 0) {
            free (copy);
            return -1;
        }
    }
    free (copy);
    return o->output_count > 0 ? 0 : -1;
}

static int
bdf_find_mount_info (const char *path, char *fs, size_t fssz,
                     char *type, size_t typesz, char *mnt, size_t mntsz)
{
    struct stat pst;
    if (stat (path, &pst) < 0)
        return -1;

    FILE *mp = fopen ("/proc/mounts", "r");
    if (!mp) mp = fopen ("/proc/self/mounts", "r");
    if (!mp)
        return -1;

    int found = 0;
    size_t best_len = 0;
    char line[4096];
    while (fgets (line, sizeof line, mp)) {
        char dev[512], cur_mnt[512], cur_type[64];
        struct stat mst;
        if (sscanf (line, "%511s %511s %63s", dev, cur_mnt, cur_type) != 3)
            continue;
        bdf_unescape (dev);
        bdf_unescape (cur_mnt);
        bdf_unescape (cur_type);
        if (stat (cur_mnt, &mst) < 0 || mst.st_dev != pst.st_dev)
            continue;

        size_t len = strlen (cur_mnt);
        if (!found || len > best_len) {
            snprintf (fs, fssz, "%s", dev);
            snprintf (type, typesz, "%s", cur_type);
            snprintf (mnt, mntsz, "%s", cur_mnt);
            best_len = len;
            found = 1;
        }
    }
    fclose (mp);
    return found ? 0 : -1;
}

static int
bdf_fill_row (const char *path, const char *fs, const char *type, bdf_row *row)
{
    struct statvfs vfs;
    uint64_t bsize;

    if (statvfs (path, &vfs) < 0) {
        builtin_error ("%s: %s", path, strerror (errno));
        return -1;
    }

    bsize = vfs.f_frsize ? vfs.f_frsize : vfs.f_bsize;
    memset (row, 0, sizeof *row);
    row->fs = fs;
    row->type = type;
    row->path = path;
    row->total = (uint64_t) vfs.f_blocks * bsize;
    row->avail = (uint64_t) vfs.f_bavail * bsize;
    row->used = row->total - (uint64_t) vfs.f_bfree * bsize;
    if (row->used + row->avail > 0)
        row->use_pct = (int) ((row->used * 100 + row->used + row->avail - 1) / (row->used + row->avail));
    row->inodes = (uint64_t) vfs.f_files;
    row->ifree = (uint64_t) vfs.f_favail;
    row->iused = row->inodes >= (uint64_t) vfs.f_ffree ? row->inodes - (uint64_t) vfs.f_ffree : 0;
    if (row->iused + row->ifree > 0)
        row->iuse_pct = (int) ((row->iused * 100 + row->iused + row->ifree - 1) / (row->iused + row->ifree));
    return 0;
}

static void
bdf_format_space (uint64_t bytes, const bdf_opts *o, char *out, size_t outsz)
{
    if (o->hflag || o->Hflag)
        bdf_human (bytes, o->Hflag, out, outsz);
    else
        bdf_block_value (bytes, o, out, outsz);
}

static const char *
bdf_output_header (int field, const bdf_opts *o)
{
    switch (field) {
    case BDF_OUT_SOURCE: return "Filesystem";
    case BDF_OUT_FSTYPE: return "Type";
    case BDF_OUT_SIZE: return (o->hflag || o->Hflag) ? "Size" : bdf_block_label (o);
    case BDF_OUT_USED: return "Used";
    case BDF_OUT_AVAIL: return "Avail";
    case BDF_OUT_PCENT: return "Use%";
    case BDF_OUT_FILE: return "File";
    case BDF_OUT_TARGET: return "Mounted on";
    case BDF_OUT_ITOTAL: return "Inodes";
    case BDF_OUT_IUSED: return "IUsed";
    case BDF_OUT_IAVAIL: return "IAvail";
    case BDF_OUT_IPCENT: return "IUse%";
    default: return "?";
    }
}

static void
bdf_output_value (const bdf_row *row, const bdf_opts *o, int field, char *out, size_t outsz)
{
    switch (field) {
    case BDF_OUT_SOURCE: snprintf (out, outsz, "%s", row->fs); break;
    case BDF_OUT_FSTYPE: snprintf (out, outsz, "%s", row->type); break;
    case BDF_OUT_SIZE: bdf_format_space (row->total, o, out, outsz); break;
    case BDF_OUT_USED: bdf_format_space (row->used, o, out, outsz); break;
    case BDF_OUT_AVAIL: bdf_format_space (row->avail, o, out, outsz); break;
    case BDF_OUT_PCENT: snprintf (out, outsz, "%d%%", row->use_pct); break;
    case BDF_OUT_FILE: snprintf (out, outsz, "%s", row->path); break;
    case BDF_OUT_TARGET: snprintf (out, outsz, "%s", row->path); break;
    case BDF_OUT_ITOTAL: snprintf (out, outsz, "%" PRIu64, row->inodes); break;
    case BDF_OUT_IUSED: snprintf (out, outsz, "%" PRIu64, row->iused); break;
    case BDF_OUT_IAVAIL: snprintf (out, outsz, "%" PRIu64, row->ifree); break;
    case BDF_OUT_IPCENT: snprintf (out, outsz, "%d%%", row->iuse_pct); break;
    default: snprintf (out, outsz, "?"); break;
    }
}

static void
bdf_print_output_header (const bdf_opts *o)
{
    for (int i = 0; i < o->output_count; i++)
        printf ("%s%s", i ? " " : "", bdf_output_header (o->output_fields[i], o));
    putchar ('\n');
}

static void
bdf_print_output_row (const bdf_row *row, const bdf_opts *o)
{
    char val[64];
    for (int i = 0; i < o->output_count; i++) {
        bdf_output_value (row, o, o->output_fields[i], val, sizeof val);
        printf ("%s%s", i ? " " : "", val);
    }
    putchar ('\n');
}

static void
bdf_print_default_header (const bdf_opts *o)
{
    if (o->iflag) {
        if (o->Tflag)
            printf ("%-20s %-10s %12s %12s %12s %5s %s\n",
                    "Filesystem", "Type", "Inodes", "IUsed", "IFree", "IUse%", "Mounted on");
        else
            printf ("%-20s %12s %12s %12s %5s %s\n",
                    "Filesystem", "Inodes", "IUsed", "IFree", "IUse%", "Mounted on");
    } else if (o->hflag || o->Hflag) {
        if (o->Tflag)
            printf ("%-20s %-10s %8s %8s %8s %4s %s\n",
                    "Filesystem", "Type", "Size", "Used", "Avail", "Use%", "Mounted on");
        else
            printf ("%-20s %8s %8s %8s %4s %s\n",
                    "Filesystem", "Size", "Used", "Avail", "Use%", "Mounted on");
    } else {
        if (o->Tflag)
            printf ("%-20s %-10s %12s %12s %12s %4s %s\n",
                    "Filesystem", "Type", bdf_block_label (o), "Used", "Available",
                    o->Pflag ? "Capacity" : "Use%", "Mounted on");
        else
            printf ("%-20s %12s %12s %12s %4s %s\n",
                    "Filesystem", bdf_block_label (o), "Used", "Available",
                    o->Pflag ? "Capacity" : "Use%", "Mounted on");
    }
}

static void
bdf_print_default_row (const bdf_row *row, const bdf_opts *o)
{
    char tot[32], use[32], av[32];

    if (o->iflag) {
        if (o->hflag || o->Hflag) {
            bdf_human (row->inodes, o->Hflag, tot, sizeof tot);
            bdf_human (row->iused, o->Hflag, use, sizeof use);
            bdf_human (row->ifree, o->Hflag, av, sizeof av);
            if (o->Tflag)
                printf ("%-20s %-10s %12s %12s %12s %4d%% %s\n",
                        row->fs, row->type, tot, use, av, row->iuse_pct, row->path);
            else
                printf ("%-20s %12s %12s %12s %4d%% %s\n",
                        row->fs, tot, use, av, row->iuse_pct, row->path);
        } else if (o->Tflag) {
            printf ("%-20s %-10s %12" PRIu64 " %12" PRIu64 " %12" PRIu64 " %4d%% %s\n",
                    row->fs, row->type, row->inodes, row->iused, row->ifree, row->iuse_pct, row->path);
        } else {
            printf ("%-20s %12" PRIu64 " %12" PRIu64 " %12" PRIu64 " %4d%% %s\n",
                    row->fs, row->inodes, row->iused, row->ifree, row->iuse_pct, row->path);
        }
    } else if (o->hflag || o->Hflag) {
        bdf_human (row->total, o->Hflag, tot, sizeof tot);
        bdf_human (row->used, o->Hflag, use, sizeof use);
        bdf_human (row->avail, o->Hflag, av, sizeof av);
        if (o->Tflag)
            printf ("%-20s %-10s %8s %8s %8s %3d%% %s\n",
                    row->fs, row->type, tot, use, av, row->use_pct, row->path);
        else
            printf ("%-20s %8s %8s %8s %3d%% %s\n", row->fs, tot, use, av, row->use_pct, row->path);
    } else {
        bdf_block_value (row->total, o, tot, sizeof tot);
        bdf_block_value (row->used, o, use, sizeof use);
        bdf_block_value (row->avail, o, av, sizeof av);
        if (o->Tflag)
            printf ("%-20s %-10s %12s %12s %12s %3d%% %s\n",
                    row->fs, row->type, tot, use, av, row->use_pct, row->path);
        else
            printf ("%-20s %12s %12s %12s %3d%% %s\n",
                    row->fs, tot, use, av, row->use_pct, row->path);
    }
}

static void
bdf_total_add (bdf_row *total, const bdf_row *row)
{
    total->fs = "total";
    total->type = "-";
    total->path = "-";
    total->total += row->total;
    total->used += row->used;
    total->avail += row->avail;
    total->inodes += row->inodes;
    total->iused += row->iused;
    total->ifree += row->ifree;
    if (total->used + total->avail > 0)
        total->use_pct = (int) ((total->used * 100 + total->used + total->avail - 1) /
                                (total->used + total->avail));
    if (total->iused + total->ifree > 0)
        total->iuse_pct = (int) ((total->iused * 100 + total->iused + total->ifree - 1) /
                                 (total->iused + total->ifree));
}

static int
bdf_one (const char *path, const char *fs, const char *type,
         const bdf_opts *o, int *header_emitted, bdf_row *total)
{
    bdf_row row;

    if (bdf_fill_row (path, fs, type, &row) < 0)
        return -1;
    if (!*header_emitted) {
        if (o->output_count)
            bdf_print_output_header (o);
        else
            bdf_print_default_header (o);
        *header_emitted = 1;
    }
    if (o->output_count)
        bdf_print_output_row (&row, o);
    else
        bdf_print_default_row (&row, o);
    if (total)
        bdf_total_add (total, &row);
    return 0;
}

static void
bdf_print_total (const bdf_opts *o, const bdf_row *total)
{
    if (o->output_count)
        bdf_print_output_row (total, o);
    else
        bdf_print_default_row (total, o);
}

int
df_builtin (WORD_LIST *list)
{
    bdf_opts o = {0};
    bdf_words positional = {0};
    o.block_size = 1024;
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "--help") == 0) {
            bdf_print_help ();
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--version") == 0) {
            puts ("bashdf 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--human-readable") == 0) {
            o.hflag = 1;
            o.Hflag = 0;
            continue;
        }
        if (strcmp (w, "--si") == 0) {
            o.Hflag = 1;
            o.hflag = 0;
            continue;
        }
        if (strcmp (w, "--print-type") == 0) {
            o.Tflag = 1;
            continue;
        }
        if (strcmp (w, "--all") == 0) {
            o.aflag = 1;
            continue;
        }
        if (strcmp (w, "--local") == 0) {
            o.lflag = 1;
            continue;
        }
        if (strcmp (w, "--total") == 0) {
            o.totalflag = 1;
            continue;
        }
        if (strcmp (w, "--output") == 0) {
            if (bdf_parse_output (NULL, &o) < 0) {
                builtin_error ("--output: invalid field list");
                return EX_USAGE;
            }
            continue;
        }
        if (strncmp (w, "--output=", 9) == 0) {
            if (bdf_parse_output (w + 9, &o) < 0) {
                builtin_error ("--output: invalid field list");
                return EX_USAGE;
            }
            continue;
        }
        if (strncmp (w, "--block-size=", 13) == 0) {
            if (bdf_parse_block_size (w + 13, &o) < 0) {
                builtin_error ("--block-size: invalid size");
                return EX_USAGE;
            }
            continue;
        }
        if (strcmp (w, "--block-size") == 0) {
            if (p->next == NULL || bdf_parse_block_size (p->next->word->word, &o) < 0) {
                builtin_error ("--block-size: invalid size");
                return EX_USAGE;
            }
            p = p->next;
            continue;
        }
        if (strncmp (w, "--type=", 7) == 0) {
            if (w[7] == '\0') {
                builtin_error ("--type: missing filesystem type");
                builtin_usage ();
                return EX_USAGE;
            }
            o.type_filter = w + 7;
            continue;
        }
        if (strcmp (w, "--type") == 0) {
            if (p->next == NULL) {
                builtin_error ("--type: missing filesystem type");
                builtin_usage ();
                return EX_USAGE;
            }
            p = p->next;
            o.type_filter = p->word->word;
            if (o.type_filter[0] == '\0') {
                builtin_error ("--type: missing filesystem type");
                builtin_usage ();
                return EX_USAGE;
            }
            continue;
        }
        if (strncmp (w, "--exclude-type=", 15) == 0) {
            if (w[15] == '\0') {
                builtin_error ("--exclude-type: missing filesystem type");
                builtin_usage ();
                return EX_USAGE;
            }
            o.exclude_type = w + 15;
            continue;
        }
        if (strcmp (w, "--exclude-type") == 0) {
            if (p->next == NULL) {
                builtin_error ("--exclude-type: missing filesystem type");
                builtin_usage ();
                return EX_USAGE;
            }
            p = p->next;
            o.exclude_type = p->word->word;
            if (o.exclude_type[0] == '\0') {
                builtin_error ("--exclude-type: missing filesystem type");
                builtin_usage ();
                return EX_USAGE;
            }
            continue;
        }
        if (strcmp (w, "--") == 0) {
            for (p = p->next; p; p = p->next) {
                if (bdf_words_add (&positional, p->word->word) < 0) {
                    free (positional.v);
                    return EXECUTION_FAILURE;
                }
            }
            break;
        }
        if (w[0] == '-' && w[1] && strcmp (w, "-") != 0) {
            for (int i = 1; w[i]; i++) {
                switch (w[i]) {
                case 'a': o.aflag = 1; break;
                case 'h': o.hflag = 1; o.Hflag = 0; break;
                case 'H': o.Hflag = 1; o.hflag = 0; break;
                case 'i': o.iflag = 1; break;
                case 'k':
                    o.kflag = 1;
                    o.mflag = 0;
                    o.block_explicit = 0;
                    o.block_suffix = '\0';
                    o.block_label[0] = '\0';
                    break;
                case 'm':
                    o.mflag = 1;
                    o.block_explicit = 0;
                    o.block_suffix = '\0';
                    o.block_label[0] = '\0';
                    break;
                case 'B':
                    if (w[i + 1]) {
                        if (bdf_parse_block_size (w + i + 1, &o) < 0) {
                            builtin_error ("-B: invalid size");
                            return EX_USAGE;
                        }
                        i = (int) strlen (w) - 1;
                    } else {
                        if (p->next == NULL || bdf_parse_block_size (p->next->word->word, &o) < 0) {
                            builtin_error ("-B: invalid size");
                            return EX_USAGE;
                        }
                        p = p->next;
                    }
                    break;
                case 'l': o.lflag = 1; break;
                case 'P': o.Pflag = 1; break;
                case 't':
                    if (w[i + 1]) {
                        o.type_filter = w + i + 1;
                        i = (int) strlen (w) - 1;
                    } else {
                        if (p->next == NULL) {
                            builtin_error ("-t: missing filesystem type");
                            builtin_usage ();
                            return EX_USAGE;
                        }
                        p = p->next;
                        o.type_filter = p->word->word;
                        if (o.type_filter[0] == '\0') {
                            builtin_error ("-t: missing filesystem type");
                            builtin_usage ();
                            return EX_USAGE;
                        }
                    }
                    break;
                case 'T': o.Tflag = 1; break;
                case 'x':
                    if (w[i + 1]) {
                        o.exclude_type = w + i + 1;
                        i = (int) strlen (w) - 1;
                    } else {
                        if (p->next == NULL) {
                            builtin_error ("-x: missing filesystem type");
                            builtin_usage ();
                            return EX_USAGE;
                        }
                        p = p->next;
                        o.exclude_type = p->word->word;
                        if (o.exclude_type[0] == '\0') {
                            builtin_error ("-x: missing filesystem type");
                            builtin_usage ();
                            return EX_USAGE;
                        }
                    }
                    break;
                default:
                    builtin_error ("unknown flag: -%c", w[i]);
                    builtin_usage ();
                    return EX_USAGE;
                }
            }
        } else {
            if (bdf_words_add (&positional, w) < 0) {
                free (positional.v);
                return EXECUTION_FAILURE;
            }
        }
    }

    int header_emitted = 0;
    int rc = EXECUTION_SUCCESS;
    bdf_row total = {0};
    bdf_row *totalp = o.totalflag ? &total : NULL;

    if (positional.n > 0) {
        /* Per-path mode. */
        for (int i = 0; i < positional.n; i++) {
            char fs[512], type[64], mnt[512];
            const char *display_fs = positional.v[i];
            const char *display_type = "";
            const char *display_path = positional.v[i];
            if (bdf_find_mount_info (positional.v[i], fs, sizeof fs, type, sizeof type, mnt, sizeof mnt) == 0) {
                display_fs = fs;
                display_type = type;
                display_path = mnt;
            }
            if (!bdf_type_selected (&o, display_type))
                continue;
            if (bdf_type_excluded (&o, display_type))
                continue;
            if (bdf_one (display_path, display_fs, display_type, &o, &header_emitted, totalp) < 0)
                rc = EXECUTION_FAILURE;
        }
        if (o.totalflag && header_emitted)
            bdf_print_total (&o, &total);
        free (positional.v);
        return rc;
    }
    free (positional.v);

    /* Enumerate /proc/mounts. */
    FILE *mp = fopen ("/proc/mounts", "r");
    if (!mp) mp = fopen ("/proc/self/mounts", "r");
    if (!mp) {
        builtin_error ("/proc/mounts: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    char line[4096];
    while (fgets (line, sizeof line, mp)) {
        char dev[512], mnt[512], type[64];
        if (sscanf (line, "%511s %511s %63s", dev, mnt, type) != 3) continue;
        bdf_unescape (dev);
        bdf_unescape (mnt);
        bdf_unescape (type);
        if (o.lflag && bdf_is_remote_type (type))
            continue;
        if (!bdf_type_selected (&o, type))
            continue;
        if (bdf_type_excluded (&o, type))
            continue;
        /* Skip pseudo filesystems with no meaningful disk usage unless -a asks for all entries. */
        if (!o.aflag
            && (strcmp (type, "proc") == 0 || strcmp (type, "sysfs") == 0
            || strcmp (type, "cgroup") == 0 || strcmp (type, "cgroup2") == 0
            || strcmp (type, "devpts") == 0 || strcmp (type, "rpc_pipefs") == 0
            || strcmp (type, "binfmt_misc") == 0 || strcmp (type, "mqueue") == 0
            || strcmp (type, "pstore") == 0 || strcmp (type, "configfs") == 0
            || strcmp (type, "debugfs") == 0 || strcmp (type, "fusectl") == 0
            || strcmp (type, "securityfs") == 0 || strcmp (type, "tracefs") == 0
            || strcmp (type, "bpf") == 0 || strcmp (type, "autofs") == 0))
            continue;
        if (bdf_one (mnt, dev, type, &o, &header_emitted, totalp) < 0)
            rc = EXECUTION_FAILURE;
    }
    fclose (mp);
    if (o.totalflag && header_emitted)
        bdf_print_total (&o, &total);
    return rc;
}

char *df_doc[] = {
    "Report filesystem disk space usage.",
    "",
    "    bashdf [-ahHiklmPT] [-B SIZE] [-t TYPE] [-x TYPE] [FILE...]",
    "",
    "    -a   show all filesystems",
    "    -h   human-readable sizes (powers of 1024)",
    "    -H   SI human-readable sizes (powers of 1000)",
    "    -B SIZE  scale block output by SIZE (for example 1, K, M, G)",
    "    -i   list inode usage",
    "    -k   1024-byte blocks (POSIX default)",
    "    -m   1M-byte blocks",
    "    -l   limit listing to local filesystems",
    "    -P   POSIX output format",
    "    -t TYPE  limit listing to filesystem type",
    "    -T   print filesystem type",
    "    -x TYPE  exclude filesystem type",
    "    --help     show usage and exit",
    "    --version  show version and exit",
    "    --all         show all filesystems",
    "    --human-readable  human-readable sizes (powers of 1024)",
    "    --si            SI human-readable sizes (powers of 1000)",
    "    --block-size=SIZE  scale block output by SIZE",
    "    --output[=LIST] select output columns (source,size,used,avail,pcent,target,...)",
    "    --total       show a grand-total row",
    "    --local       limit listing to local filesystems",
    "    --type=TYPE   limit listing to filesystem type",
    "    --exclude-type=TYPE  exclude filesystem type",
    "    --print-type  print filesystem type",
    "",
    "No FILE: enumerate /proc/mounts. Pseudo-filesystems",
    "(proc/sysfs/cgroup/etc.) are filtered out.",
    (char *)NULL
};

struct builtin bashdf_struct = {
    "bashdf",
    df_builtin,
    BUILTIN_ENABLED,
    df_doc,
    "bashdf [-ahHiklmPT] [-B SIZE] [-t TYPE] [-x TYPE] [FILE...]",
    0
};
