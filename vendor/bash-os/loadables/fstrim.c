/* SPDX-License-Identifier: MIT */
/* fstrim.c — discard unused filesystem blocks via FITRIM.
 *
 * util-linux fstrim(8):
 *   fstrim [-n] [-v] [--quiet-unsupported] [-o N] [-l N] [-m N] MOUNTPOINT
 *   fstrim -a|-A|-I LIST [-n] [-v] [-t TYPES] [--quiet-unsupported]
 *
 * -a reads the mount table (/proc/self/mountinfo), -A reads /etc/fstab and
 * -I reads the first non-empty file of a colon-separated list; each file may
 * be fstab or mountinfo shaped. As in util-linux, an entry is trimmed only if
 * its target is really a mountpoint now (its st_dev differs from its
 * parent's), is writable, is not a pseudo, network, swap, autofs or read-only
 * filesystem and its source device does not report zero discard granularity.
 * Duplicated targets keep the last entry and duplicated sources the first;
 * the surviving entries are trimmed in reverse table order.
 *
 * The FITRIM ioctl itself is refused by the kernel without CAP_SYS_ADMIN.
 * --dry-run does everything apart from the ioctl. The table paths and the
 * sysfs root are macros so the tests can compile this file against fixtures.
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
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <linux/fs.h>

#include "loadables.h"

#ifndef FITRIM
#  define FITRIM _IOWR('X', 121, struct fstrim_range)
#endif

#ifndef O_CLOEXEC
#  define O_CLOEXEC 0
#endif

#ifndef FSTRIM_MOUNTINFO_PATH
#  define FSTRIM_MOUNTINFO_PATH "/proc/self/mountinfo"
#endif
#ifndef FSTRIM_FSTAB_PATH
#  define FSTRIM_FSTAB_PATH "/etc/fstab"
#endif
#ifndef FSTRIM_CMDLINE_PATH
#  define FSTRIM_CMDLINE_PATH "/proc/cmdline"
#endif
#ifndef FSTRIM_SYSFS_ROOT
#  define FSTRIM_SYSFS_ROOT "/sys"
#endif
#ifndef FSTRIM_DEVDISK_ROOT
#  define FSTRIM_DEVDISK_ROOT "/dev/disk"
#endif

#define BF_AUTOFS_MAGIC 0x0187

/* util-linux exit codes for the table modes */
#define BF_EX_USAGE  1
#define BF_EX_FAIL   32
#define BF_EX_SOMEOK 64
#define BF_EX_EMPTY  255

typedef struct {
    int fstab;
    int dry_run;
    int verbose;
    int quiet_unsupported;
    struct fstrim_range range;
    const char *types;
} bf_opts;

typedef struct {
    char *src;
    char *tgt;
    char *type;
    char *opts;
    int gone;
} bf_fs;

typedef struct {
    bf_fs *v;
    size_t n;
    size_t cap;
} bf_table;

static void
bf_usage (FILE *out)
{
    fputs ("\nUsage:\n", out);
    fputs (" fstrim [options] <-A|-a|mount point>\n\n", out);
    fputs ("Discard unused blocks on a mounted filesystem.\n\n", out);
    fputs ("Options:\n", out);
    fputs (" -a, --all                trim mounted filesystems\n", out);
    fputs (" -A, --fstab              trim filesystems from /etc/fstab\n", out);
    fputs (" -I, --listed-in <list>   trim filesystems listed in specified files\n", out);
    fputs (" -o, --offset <num>       the offset in bytes to start discarding from\n", out);
    fputs (" -l, --length <num>       the number of bytes to discard\n", out);
    fputs (" -m, --minimum <num>      the minimum extent length to discard\n", out);
    fputs (" -t, --types <list>       limit the set of filesystem types\n", out);
    fputs (" -v, --verbose            print number of discarded bytes\n", out);
    fputs ("     --quiet-unsupported  suppress error messages if trim unsupported\n", out);
    fputs (" -n, --dry-run            does everything, but trim\n\n", out);
    fputs (" -h, --help          display this help\n", out);
    fputs (" -V, --version       display version\n", out);
    fputs ("\nArguments:\n", out);
    fputs (" Values for <num> may be followed by a suffix: KiB, MiB,\n", out);
    fputs (" GiB, TiB, PiB, EiB, ZiB, or YiB (where the \"iB\" is optional).\n", out);
    fputs ("\nFor more details see fstrim(8).\n", out);
}

static int
bf_try_help (void)
{
    fputs ("Try 'fstrim --help' for more information.\n", stderr);
    return BF_EX_USAGE;
}

static int
bf_finish (int rc)
{
    if (fflush (stdout) == EOF || ferror (stdout)) {
        fprintf (stderr, "fstrim: write error: %s\n", strerror (errno));
        clearerr (stdout);
        return EXECUTION_FAILURE;
    }
    return rc;
}

/* --- sizes ------------------------------------------------------------ */

static int
bf_scale (uintmax_t *x, unsigned base, int pwr)
{
    while (pwr--) {
        if (*x > UINTMAX_MAX / base)
            return -ERANGE;
        *x *= base;
    }
    return 0;
}

/* util-linux parse_size(): base-0 integer, optional .fraction, optional
 * K/M/G/T/P/E/Z/Y suffix followed by nothing (1024), "iB" (1024) or "B"
 * (1000). The result must fit in 64 bits. */
static int
bf_parse_size (const char *str, uint64_t *out)
{
    static const char suf[] = "KMGTPEZY", suf2[] = "kmgtpezy";
    const char *p = str;
    char *end = NULL;
    uintmax_t x, frac = 0;
    unsigned base = 1024;
    int pwr = 0, frac_zeros = 0;

    if (!str || !*str)
        return -EINVAL;
    while (isspace ((unsigned char) *p))
        p++;
    if (*p == '-')
        return -EINVAL;

    errno = 0;
    x = strtoumax (str, &end, 0);
    if (end == str || (errno != 0 && (x == UINTMAX_MAX || x == 0)))
        return errno ? -errno : -EINVAL;
    if (!end || !*end)
        goto done;
    p = end;

check_suffix:
    if (*p && p[1] == 'i' && (p[2] == 'B' || p[2] == 'b') && !p[3])
        base = 1024;
    else if (*p && (p[1] == 'B' || p[1] == 'b') && !p[2])
        base = 1000;
    else if (*p && p[1]) {
        if (frac == 0 && *p == '.') {
            const char *f = p + 1;
            for (; *f == '0'; f++)
                frac_zeros++;
            p = f;
            if (isdigit ((unsigned char) *f)) {
                errno = 0;
                frac = strtoumax (f, &end, 0);
                if (end == f || (errno != 0 && (frac == UINTMAX_MAX || frac == 0)))
                    return errno ? -errno : -EINVAL;
                p = end;
            }
            if (!*p)
                return -EINVAL;     /* a fraction needs a size suffix */
            goto check_suffix;
        }
        return -EINVAL;
    }

    {
        const char *sp = strchr (suf, *p);
        if (sp)
            pwr = (int) (sp - suf) + 1;
        else if ((sp = strchr (suf2, *p)))
            pwr = (int) (sp - suf2) + 1;
        else
            return -EINVAL;
    }
    if (bf_scale (&x, base, pwr) < 0)
        return -ERANGE;

    if (frac && pwr) {
        uintmax_t frac_div = 10, frac_poz = 1, frac_base = 1;

        bf_scale (&frac_base, base, pwr);
        while (frac_div < frac) {
            if (frac_div <= UINTMAX_MAX / 10)
                frac_div *= 10;
            else
                frac /= 10;
        }
        for (int i = 0; i < frac_zeros; i++) {
            if (frac_div <= UINTMAX_MAX / 10)
                frac_div *= 10;
            else
                frac /= 10;
        }
        do {
            unsigned seg = (unsigned) (frac % 10);
            uintmax_t seg_div = frac_div / frac_poz;

            frac /= 10;
            frac_poz *= 10;
            if (seg && seg_div / seg)
                x += frac_base / (seg_div / seg);
        } while (frac);
    }

done:
    if (x > UINT64_MAX)
        return -ERANGE;
    *out = (uint64_t) x;
    return 0;
}

/* util-linux size_to_human_string (SIZE_SUFFIX_3LETTER | SIZE_SUFFIX_SPACE) */
static void
bf_human (uint64_t bytes, char *buf, size_t sz)
{
    static const char letters[] = "BKMGTPE";
    int exp = 0, shft;
    uint64_t dec, frac;
    char suffix[8];

    for (shft = 10; shft <= 60; shft += 10)
        if (bytes < (1ULL << shft))
            break;
    exp = shft - 10;
    char c = letters[exp ? exp / 10 : 0];
    dec = exp ? bytes / (1ULL << exp) : bytes;
    frac = exp ? bytes % (1ULL << exp) : 0;
    if (c != 'B')
        snprintf (suffix, sizeof suffix, " %ciB", c);
    else
        snprintf (suffix, sizeof suffix, " B");

    if (frac) {
        if (frac >= UINT64_MAX / 1000)
            frac = ((frac / 1024) * 1000) / (1ULL << (exp - 10));
        else
            frac = (frac * 1000) / (1ULL << exp);
        frac = (frac + 50) / 100;
        if (frac == 10) {
            dec++;
            frac = 0;
        }
    }
    if (frac)
        snprintf (buf, sz, "%d.%d%s", (int) dec, (int) frac, suffix);
    else
        snprintf (buf, sz, "%d%s", (int) dec, suffix);
}

/* --- paths and types --------------------------------------------------- */

static const char *
bf_segment (const char *p, size_t *len)
{
    while (*p == '/')
        p++;
    const char *e = p;
    while (*e && *e != '/')
        e++;
    *len = (size_t) (e - p);
    return p;
}

/* libmount streq_paths(): equal after collapsing repeated and trailing '/' */
static int
bf_streq_paths (const char *a, const char *b)
{
    if (!a || !b)
        return 0;
    for (;;) {
        size_t al, bl;
        const char *as = bf_segment (a, &al), *bs = bf_segment (b, &bl);
        if (al != bl)
            return 0;
        if (al == 0)
            return 1;
        if (strncmp (as, bs, al))
            return 0;
        a = as + al;
        b = bs + bl;
    }
}

/* Key under which bf_streq_paths() is plain equality: the segments joined
 * by single slashes. */
static char *
bf_path_key (const char *p)
{
    char *k = malloc (strlen (p) + 1), *w = k;
    size_t l;

    if (!k)
        return NULL;
    for (;;) {
        const char *seg = bf_segment (p, &l);
        if (!l)
            break;
        if (w != k)
            *w++ = '/';
        memcpy (w, seg, l);
        w += l;
        p = seg + l;
    }
    *w = '\0';
    return k;
}

/* Open-addressing set of path keys, sized for the table being scanned. */
typedef struct {
    char **slot;
    size_t mask;
} bf_set;

static int
bf_set_init (bf_set *s, size_t n)
{
    size_t cap = 16;
    while (cap < n * 2)
        cap *= 2;
    s->slot = calloc (cap, sizeof *s->slot);
    s->mask = cap - 1;
    return s->slot ? 0 : -1;
}

static void
bf_set_free (bf_set *s)
{
    if (!s->slot)
        return;
    for (size_t i = 0; i <= s->mask; i++)
        free (s->slot[i]);
    free (s->slot);
    s->slot = NULL;
}

/* 1 if PATH's key was already present, 0 if added, -1 on allocation failure */
static int
bf_set_seen (bf_set *s, const char *path)
{
    char *k = bf_path_key (path);
    uint64_t h = 1469598103934665603ULL;
    size_t i;

    if (!k)
        return -1;
    for (const unsigned char *c = (const unsigned char *) k; *c; c++)
        h = (h ^ *c) * 1099511628211ULL;
    for (i = (size_t) h & s->mask; s->slot[i]; i = (i + 1) & s->mask)
        if (!strcmp (s->slot[i], k)) {
            free (k);
            return 1;
        }
    s->slot[i] = k;
    return 0;
}

/* libmount mnt_get_mountpoint(): climb while st_dev stays the same. Returns
 * the nearest mountpoint at or above PATH, or NULL if a stat fails. */
static char *
bf_mountpoint_of (const char *path)
{
    struct stat st;
    dev_t base;
    char *mnt = strdup (path);

    if (!mnt)
        return NULL;
    if (mnt[0] == '/' && mnt[1] == '\0')
        return mnt;
    if (stat (mnt, &st) != 0)
        goto err;
    base = st.st_dev;
    do {
        char *slash = strrchr (mnt, '/');
        if (!slash)
            break;
        *slash = '\0';
        if (stat (*mnt ? mnt : "/", &st) != 0)
            goto err;
        if (st.st_dev != base) {
            *slash = '/';
            return mnt;
        }
        base = st.st_dev;
    } while (mnt[0] && mnt[1] != '\0');
    memcpy (mnt, "/", 2);
    return mnt;
err:
    free (mnt);
    return NULL;
}

static int
bf_is_mountpoint (const char *tgt)
{
    char *mp = bf_mountpoint_of (tgt);
    int r = mp && bf_streq_paths (mp, tgt);
    free (mp);
    return r;
}

static int
bf_in_list (const char *type, const char *const *list)
{
    for (; *list; list++)
        if (!strcmp (type, *list))
            return 1;
    return 0;
}

static const char *const bf_pseudofs[] = {
    "anon_inodefs", "apparmorfs", "autofs", "bdev", "binder", "binfmt_misc",
    "bpf", "cgroup", "cgroup2", "configfs", "cpuset", "debugfs", "devfs",
    "devpts", "devtmpfs", "dlmfs", "dmabuf", "drm", "efivarfs", "fuse",
    "fuse.archivemount", "fuse.avfsd", "fuse.dumpfs", "fuse.encfs",
    "fuse.gvfs-fuse-daemon", "fuse.gvfsd-fuse", "fuse.lxcfs", "fuse.portal",
    "fuse.rofiles-fuse", "fuse.vmware-vmblock", "fuse.xwmfs", "fusectl",
    "hugetlbfs", "ipathfs", "mqueue", "nfsd", "none", "nsfs", "overlay",
    "pipefs", "proc", "pstore", "ramfs", "resctrl", "rootfs", "rpc_pipefs",
    "securityfs", "selinuxfs", "smackfs", "sockfs", "spufs", "sysfs", "tmpfs",
    "tracefs", "vboxsf", "virtiofs", NULL
};

static const char *const bf_netfs[] = {
    "9p", "afs", "cifs", "fuse.curlftpfs", "fuse.sshfs", "glusterfs",
    "ncpfs", "nfs", "nfs4", "smb3", "smbfs", NULL
};

/* libmount match_fstype(): comma list, a leading "no" negates the whole
 * list and "noTYPE" items exclude one type; comparison ignores case. */
static int
bf_match_fstype (const char *type, const char *pattern)
{
    int no = 0;
    size_t len;
    const char *p;

    if (!pattern)
        return 1;
    if (!type)
        type = "";
    if (!strncmp (pattern, "no", 2)) {
        no = 1;
        pattern += 2;
    }
    len = strlen (type);
    for (p = pattern;;) {
        if (!strncmp (p, "no", 2) && !strncasecmp (p + 2, type, len)
            && (p[len + 2] == '\0' || p[len + 2] == ','))
            return 0;
        if (!strncasecmp (p, type, len) && (p[len] == '\0' || p[len] == ','))
            return !no;
        p = strchr (p, ',');
        if (!p)
            break;
        p++;
    }
    return no;
}

/* option NAME present in the comma list, with or without a value */
static int
bf_has_option (const char *opts, const char *name)
{
    size_t n = strlen (name);
    const char *p = opts;

    while (p && *p) {
        const char *e = strchr (p, ',');
        size_t l = e ? (size_t) (e - p) : strlen (p);
        if (l >= n && !strncmp (p, name, n) && (l == n || p[n] == '='))
            return 1;
        p = e ? e + 1 : NULL;
    }
    return 0;
}

static int
bf_read_u64 (const char *path, uint64_t *v)
{
    FILE *f = fopen (path, "re");
    unsigned long long x;
    int ok;

    if (!f)
        return -1;
    ok = fscanf (f, "%llu", &x) == 1;
    fclose (f);
    if (!ok)
        return -1;
    *v = x;
    return 0;
}

/* util-linux has_discard(): 0 only when sysfs says the device cannot
 * discard (granularity 0, unreadable queue attribute or read-only);
 * an unknown device counts as capable. */
static int
bf_has_discard (const char *src)
{
    const char *root = FSTRIM_SYSFS_ROOT;
    struct stat st;
    unsigned maj = 0, min = 0;
    char path[PATH_MAX];
    uint64_t dg = 0, ro = 0;

    if (stat (src, &st) == 0 && S_ISBLK (st.st_mode)) {
        maj = major (st.st_rdev);
        min = minor (st.st_rdev);
    } else {
        const char *name = strncmp (src, "/dev/", 5) ? src : src + 5;
        char tmp[NAME_MAX + 1];
        FILE *f;
        size_t i;

        if (!*name || strlen (name) > NAME_MAX)
            return 1;
        for (i = 0; name[i]; i++)
            tmp[i] = name[i] == '/' ? '!' : name[i];
        tmp[i] = '\0';
        snprintf (path, sizeof path, "%s/class/block/%s/dev", root, tmp);
        f = fopen (path, "re");
        if (!f)
            return 1;
        i = fscanf (f, "%u:%u", &maj, &min);
        fclose (f);
        if (i != 2)
            return 1;
    }

    snprintf (path, sizeof path, "%s/dev/block/%u:%u", root, maj, min);
    if (stat (path, &st) != 0)
        return 1;
    snprintf (path, sizeof path, "%s/dev/block/%u:%u/partition", root, maj, min);
    if (stat (path, &st) == 0)
        snprintf (path, sizeof path, "%s/dev/block/%u:%u/../queue/discard_granularity",
                  root, maj, min);
    else
        snprintf (path, sizeof path, "%s/dev/block/%u:%u/queue/discard_granularity",
                  root, maj, min);
    if (bf_read_u64 (path, &dg) != 0)
        return 0;
    snprintf (path, sizeof path, "%s/dev/block/%u:%u/ro", root, maj, min);
    if (bf_read_u64 (path, &ro) != 0)
        ro = 0;
    return dg > 0 && ro == 0;
}

/* --- tables ------------------------------------------------------------ */

static void
bf_table_free (bf_table *t)
{
    for (size_t i = 0; i < t->n; i++) {
        free (t->v[i].src);
        free (t->v[i].tgt);
        free (t->v[i].type);
        free (t->v[i].opts);
    }
    free (t->v);
    t->v = NULL;
    t->n = t->cap = 0;
}

static char *
bf_dup_unmangled (const char *s, size_t n)
{
    char *d = malloc (n + 1), *w = d;
    const char *r = s, *e = s + n;

    if (!d)
        return NULL;
    while (r < e) {
        if (r[0] == '\\' && e - r >= 4
            && r[1] >= '0' && r[1] <= '3' && r[2] >= '0' && r[2] <= '7'
            && r[3] >= '0' && r[3] <= '7') {
            *w++ = (char) (((r[1] - '0') << 6) | ((r[2] - '0') << 3) | (r[3] - '0'));
            r += 4;
        } else
            *w++ = *r++;
    }
    *w = '\0';
    return d;
}

/* next blank-separated word; returns NULL at end of line */
static const char *
bf_word (const char **sp, size_t *len)
{
    const char *s = *sp, *e;

    while (*s == ' ' || *s == '\t')
        s++;
    if (!*s || *s == '\n')
        return NULL;
    for (e = s; *e && *e != ' ' && *e != '\t' && *e != '\n'; e++)
        ;
    *len = (size_t) (e - s);
    *sp = e;
    return s;
}

static int
bf_table_add (bf_table *t, char *src, char *tgt, char *type, char *opts)
{
    if (!src || !tgt || !type || !opts)
        goto fail;
    if (t->n == t->cap) {
        size_t ncap = t->cap ? t->cap * 2 : 32;
        bf_fs *nv = realloc (t->v, ncap * sizeof *nv);
        if (!nv)
            goto fail;
        t->v = nv;
        t->cap = ncap;
    }
    t->v[t->n].src = src;
    t->v[t->n].tgt = tgt;
    t->v[t->n].type = type;
    t->v[t->n].opts = opts;
    t->v[t->n].gone = 0;
    t->n++;
    return 0;
fail:
    free (src);
    free (tgt);
    free (type);
    free (opts);
    return -1;
}

/* fstab: SOURCE TARGET TYPE [OPTIONS [FREQ [PASS]]]; fewer than three
 * fields is a parse error and the line is skipped, as libmount does. */
static int
bf_parse_fstab_line (bf_table *t, const char *s)
{
    const char *w[4];
    size_t l[4] = {0};
    int n;

    for (n = 0; n < 4; n++)
        if (!(w[n] = bf_word (&s, &l[n])))
            break;
    if (n < 3)
        return 0;
    return bf_table_add (t, bf_dup_unmangled (w[0], l[0]), bf_dup_unmangled (w[1], l[1]),
                         bf_dup_unmangled (w[2], l[2]),
                         n > 3 ? bf_dup_unmangled (w[3], l[3]) : strdup (""));
}

/* mountinfo: ID PARENT MAJ:MIN ROOT TARGET VFS-OPTS [OPTIONAL...] - TYPE
 * SOURCE FS-OPTS. Options are matched against both option lists. */
static int
bf_parse_mountinfo_line (bf_table *t, const char *s)
{
    const char *sep;
    size_t l, tl, sl, vl, fl = 0;
    const char *tgt, *vfs, *type, *src, *fso = NULL;
    char *opts;
    int i;

    for (i = 0; i < 4; i++)
        if (!bf_word (&s, &l))
            return 0;
    if (!(tgt = bf_word (&s, &tl)) || !(vfs = bf_word (&s, &vl)))
        return 0;
    sep = strstr (s, " - ");
    if (!sep)
        return 0;
    s = sep + 3;
    if (!(type = bf_word (&s, &l)))
        return 0;
    if (!(src = bf_word (&s, &sl)))
        return 0;
    {
        size_t typel = l;
        if (!(fso = bf_word (&s, &fl)))
            return 0;
        opts = malloc (vl + fl + 2);
        if (!opts)
            return -1;
        memcpy (opts, vfs, vl);
        opts[vl] = ',';
        memcpy (opts + vl + 1, fso, fl);
        opts[vl + 1 + fl] = '\0';
        return bf_table_add (t, bf_dup_unmangled (src, sl), bf_dup_unmangled (tgt, tl),
                             bf_dup_unmangled (type, typel), opts);
    }
}

/* Parse FILE (format guessed from the first entry line). Returns 0, or -1
 * with errno set when the file cannot be read. */
static int
bf_table_parse (bf_table *t, const char *file)
{
    FILE *f = fopen (file, "re");
    char *line = NULL;
    size_t cap = 0;
    int mountinfo = -1, rc = 0;

    if (!f)
        return -1;
    while (getline (&line, &cap, f) > 0) {
        const char *s = line;
        unsigned a, b;

        while (*s == ' ' || *s == '\t')
            s++;
        if (*s == '#' || *s == '\n' || *s == '\0')
            continue;
        if (mountinfo < 0)
            mountinfo = sscanf (s, "%u %u", &a, &b) == 2;
        if ((mountinfo ? bf_parse_mountinfo_line (t, s)
                       : bf_parse_fstab_line (t, s)) < 0) {
            rc = -1;
            errno = ENOMEM;
            break;
        }
    }
    if (rc == 0 && ferror (f)) {
        rc = -1;
        if (!errno)
            errno = EIO;
    }
    free (line);
    fclose (f);
    return rc;
}

static int
bf_is_tag (const char *s, const char **val)
{
    static const char *const tags[] = { "LABEL", "UUID", "PARTLABEL", "PARTUUID", "ID", NULL };
    for (int i = 0; tags[i]; i++) {
        size_t n = strlen (tags[i]);
        if (!strncmp (s, tags[i], n) && s[n] == '=') {
            if (val)
                *val = s + n + 1;
            return 1;
        }
    }
    return 0;
}

/* LABEL=, UUID=, PARTLABEL=, PARTUUID= and ID= through the udev symlinks */
static char *
bf_resolve_tag (const char *spec)
{
    static const char *const tags[] = { "LABEL", "UUID", "PARTLABEL", "PARTUUID", "ID", NULL };
    static const char *const dirs[] = { "by-label", "by-uuid", "by-partlabel", "by-partuuid", "by-id", NULL };
    char path[PATH_MAX], val[NAME_MAX + 1];
    const char *v;
    size_t n;

    for (int i = 0; tags[i]; i++) {
        size_t tl = strlen (tags[i]);
        if (strncmp (spec, tags[i], tl) || spec[tl] != '=')
            continue;
        v = spec + tl + 1;
        n = strlen (v);
        if (n >= 2 && (v[0] == '"' || v[0] == '\'') && v[n - 1] == v[0]) {
            v++;
            n -= 2;
        }
        if (!n || n > NAME_MAX || memchr (v, '/', n))
            return NULL;
        memcpy (val, v, n);
        val[n] = '\0';
        snprintf (path, sizeof path, "%s/%s/%s", FSTRIM_DEVDISK_ROOT, dirs[i], val);
        return realpath (path, NULL);
    }
    return NULL;
}

/* libmount mnt_guess_system_root(): root= from the kernel command line,
 * otherwise the device holding "/". */
static char *
bf_guess_root (void)
{
    FILE *f = fopen (FSTRIM_CMDLINE_PATH, "re");
    char *line = NULL, *spec = NULL;
    size_t cap = 0;
    unsigned maj = 0, min = 0;
    int have = 0;

    if (f) {
        if (getline (&line, &cap, f) > 0) {
            for (char *tok = strtok (line, " \t\n"); tok; tok = strtok (NULL, " \t\n"))
                if (!strncmp (tok, "root=", 5)) {
                    free (spec);
                    spec = strdup (tok + 5);
                }
        }
        free (line);
        fclose (f);
    }
    if (spec && *spec) {
        char *r = NULL;
        if (spec[0] == '/')
            return spec;
        if (bf_is_tag (spec, NULL))
            r = bf_resolve_tag (spec);
        else if (sscanf (spec, "%u:%u", &maj, &min) == 2)
            have = 1;
        free (spec);
        if (r || !have)
            return r;
    } else
        free (spec);

    if (!have) {
        struct stat st;
        if (stat ("/", &st) != 0)
            return NULL;
        maj = major (st.st_dev);
        min = minor (st.st_dev);
    }

    char path[PATH_MAX], buf[PATH_MAX];
    snprintf (path, sizeof path, "%s/dev/block/%u:%u/uevent", FSTRIM_SYSFS_ROOT, maj, min);
    f = fopen (path, "re");
    if (!f)
        return NULL;
    char *res = NULL;
    while (fgets (buf, sizeof buf, f))
        if (!strncmp (buf, "DEVNAME=", 8)) {
            buf[strcspn (buf, "\n")] = '\0';
            size_t n = strlen (buf + 8) + 6;
            if ((res = malloc (n)))
                snprintf (res, n, "/dev/%s", buf + 8);
            break;
        }
    fclose (f);
    return res;
}

/* util-linux is_unwanted_fs() plus the access() test of the trim loop */
static int
bf_unwanted (const bf_opts *o, const bf_fs *fs)
{
    struct statfs vfs;

    if (bf_in_list (fs->type, bf_pseudofs) || bf_in_list (fs->type, bf_netfs))
        return 1;
    if (!strcmp (fs->type, "swap"))
        return 1;
    if (bf_has_option (fs->opts, "ro") || bf_has_option (fs->opts, "X-fstrim.notrim"))
        return 1;
    if (o->types && !bf_match_fstype (fs->type, o->types))
        return 1;
    if (statfs (fs->tgt, &vfs) != 0 || vfs.f_type == BF_AUTOFS_MAGIC)
        return 1;
    if (access (fs->tgt, W_OK) != 0 && (errno == EROFS || errno == EACCES))
        return 1;
    return 0;
}

static int
bf_is_directory (const char *path, int quiet)
{
    struct stat st;

    if (stat (path, &st) != 0) {
        if (!quiet)
            fprintf (stderr, "fstrim: stat of %s failed: %s\n", path, strerror (errno));
        return 0;
    }
    if (!S_ISDIR (st.st_mode)) {
        if (!quiet)
            fprintf (stderr, "fstrim: %s: not a directory\n", path);
        return 0;
    }
    return 1;
}

/* 0 trimmed, 1 unsupported, <0 -errno failure */
static int
bf_trim_fs (const bf_opts *o, const char *path, const char *devname)
{
    struct fstrim_range range;
    char *rpath = realpath (path, NULL);
    int fd, rc;

    if (!rpath) {
        rc = -errno;
        fprintf (stderr, "fstrim: cannot get realpath: %s: %s\n", path, strerror (-rc));
        return rc;
    }
    fd = open (rpath, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        rc = -errno;
        fprintf (stderr, "fstrim: cannot open %s: %s\n", path, strerror (-rc));
        free (rpath);
        return rc;
    }
    free (rpath);

    if (o->dry_run) {
        if (devname)
            printf ("%s: 0 B (dry run) trimmed on %s\n", path, devname);
        else
            printf ("%s: 0 B (dry run) trimmed\n", path);
        close (fd);
        return 0;
    }

    range = o->range;
    errno = 0;
    if (ioctl (fd, FITRIM, &range) != 0) {
        int e = errno;
        close (fd);
        if (e == EBADF || e == ENOTTY || e == EOPNOTSUPP)
            return 1;
        fprintf (stderr, "fstrim: %s: FITRIM ioctl failed: %s\n", path, strerror (e));
        return -e;
    }
    close (fd);

    if (o->verbose) {
        char h[32];
        bf_human ((uint64_t) range.len, h, sizeof h);
        if (devname)
            printf ("%s: %s (%llu bytes) trimmed on %s\n", path, h,
                    (unsigned long long) range.len, devname);
        else
            printf ("%s: %s (%llu bytes) trimmed\n", path, h,
                    (unsigned long long) range.len);
    }
    return 0;
}

static int
bf_all_from_file (const bf_opts *o, const char *file)
{
    bf_table t = {0};
    bf_set seen = {0};
    size_t i;
    int cnt = 0, cnt_err = 0;

    if (bf_table_parse (&t, file) != 0) {
        fprintf (stderr, "fstrim: failed to parse %s: %s\n", file, strerror (errno));
        bf_table_free (&t);
        return BF_EX_FAIL;
    }
    if (t.n == 0) {
        bf_table_free (&t);
        return -1;
    }

    /* de-duplicate by mountpoint: the later entry wins */
    if (bf_set_init (&seen, t.n + 1) < 0)
        goto nomem;
    for (i = t.n; i-- > 0;) {
        int r = bf_set_seen (&seen, t.v[i].tgt);
        if (r < 0)
            goto nomem;
        t.v[i].gone = r;
    }
    bf_set_free (&seen);

    if (o->fstab) {
        int have_root = 0;
        for (i = 0; i < t.n; i++)
            if (!t.v[i].gone && *t.v[i].tgt && bf_streq_paths (t.v[i].tgt, "/"))
                have_root = 1;
        if (!have_root) {
            char *root = bf_guess_root ();
            if (root && bf_table_add (&t, root, strdup ("/"), strdup (""), strdup ("")) < 0)
                goto nomem;
        }
    }

    /* drop everything that cannot or must not be trimmed */
    for (i = t.n; i-- > 0;) {
        bf_fs *fs = &t.v[i];
        if (fs->gone)
            continue;
        if (!*fs->tgt || bf_unwanted (o, fs)) {
            fs->gone = 1;
            continue;
        }
        if (bf_is_tag (fs->src, NULL)) {
            char *r = o->fstab ? bf_resolve_tag (fs->src) : NULL;
            if (!r) {
                fs->gone = 1;
                continue;
            }
            free (fs->src);
            fs->src = r;
        }
        if (fs->src[0] != '/' || !bf_is_mountpoint (fs->tgt)
            || !bf_is_directory (fs->tgt, 1) || !bf_has_discard (fs->src))
            fs->gone = 1;
    }

    /* de-duplicate by source device: the first entry wins */
    if (bf_set_init (&seen, t.n + 1) < 0)
        goto nomem;
    for (i = 0; i < t.n; i++) {
        int r;
        if (t.v[i].gone)
            continue;
        if ((r = bf_set_seen (&seen, t.v[i].src)) < 0)
            goto nomem;
        t.v[i].gone = r;
    }
    bf_set_free (&seen);

    for (i = t.n; i-- > 0;) {
        bf_fs *fs = &t.v[i];
        int rc;
        if (fs->gone)
            continue;
        cnt++;
        rc = bf_trim_fs (o, fs->tgt, fs->src);
        if (rc < 0)
            cnt_err++;
        else if (rc == 1 && !o->quiet_unsupported)
            fprintf (stderr, "fstrim: %s: the discard operation is not supported\n", fs->tgt);
    }
    bf_table_free (&t);

    if (cnt && cnt == cnt_err)
        return BF_EX_FAIL;
    if (cnt && cnt_err)
        return BF_EX_SOMEOK;
    return EXECUTION_SUCCESS;

nomem:
    fprintf (stderr, "fstrim: allocation failure\n");
    bf_set_free (&seen);
    bf_table_free (&t);
    return BF_EX_FAIL;
}

/* first regular, non-empty file of a colon-separated list */
static int
bf_all (const bf_opts *o, const char *tabs)
{
    char *list = strdup (tabs), *save = NULL;
    int rc = BF_EX_FAIL;

    if (!list) {
        fprintf (stderr, "fstrim: allocation failure\n");
        return BF_EX_FAIL;
    }
    for (char *file = strtok_r (list, ":", &save); file; file = strtok_r (NULL, ":", &save)) {
        struct stat st;
        if (stat (file, &st) != 0 || !S_ISREG (st.st_mode))
            continue;
        rc = bf_all_from_file (o, file);
        if (rc >= 0)
            break;
    }
    free (list);
    return rc < 0 ? BF_EX_EMPTY : rc;
}

/* --- options ----------------------------------------------------------- */

static const struct {
    const char *name;
    int has_arg;
    int val;
} bf_longopts[] = {
    { "all", 0, 'a' },
    { "fstab", 0, 'A' },
    { "help", 0, 'h' },
    { "listed-in", 1, 'I' },
    { "version", 0, 'V' },
    { "offset", 1, 'o' },
    { "length", 1, 'l' },
    { "minimum", 1, 'm' },
    { "types", 1, 't' },
    { "verbose", 0, 'v' },
    { "quiet-unsupported", 0, 'q' },
    { "dry-run", 0, 'n' },
};
#define BF_NLONG ((int) (sizeof bf_longopts / sizeof bf_longopts[0]))

static int
bf_option (bf_opts *o, int c, const char *arg, int *excl, const char **tabs)
{
    uint64_t v = 0;
    int r;

    if (c == 'a' || c == 'A' || c == 'I') {
        if (*excl && *excl != c) {
            fputs ("fstrim: mutually exclusive arguments: --fstab --listed-in --all\n", stderr);
            return BF_EX_USAGE;
        }
        *excl = c;
    }
    switch (c) {
    case 'A':
        o->fstab = 1;
        *tabs = FSTRIM_FSTAB_PATH;
        break;
    case 'a':
        *tabs = FSTRIM_MOUNTINFO_PATH;
        break;
    case 'I':
        *tabs = arg;
        break;
    case 'n':
        o->dry_run = 1;
        break;
    case 'v':
        o->verbose = 1;
        break;
    case 'q':
        o->quiet_unsupported = 1;
        break;
    case 't':
        o->types = arg;
        break;
    case 'o': case 'l': case 'm':
        r = bf_parse_size (arg, &v);
        if (r < 0) {
            fprintf (stderr, "fstrim: %s: '%s': %s\n",
                     c == 'o' ? "failed to parse offset"
                     : c == 'l' ? "failed to parse length"
                     : "failed to parse minimum extent length",
                     arg, strerror (-r));
            return BF_EX_USAGE;
        }
        if (c == 'o')
            o->range.start = v;
        else if (c == 'l')
            o->range.len = v;
        else
            o->range.minlen = v;
        break;
    case 'h':
        bf_usage (stdout);
        return -2;
    case 'V':
        puts ("fstrim from bash-os util-linux parity");
        return -2;
    }
    return 0;
}

int
fstrim_builtin (WORD_LIST *list)
{
    bf_opts o;
    const char *tabs = NULL;
    const char *operands[2];
    int noperands = 0, excl = 0, rc, ddash = 0;

    memset (&o, 0, sizeof o);
    o.range.len = ULLONG_MAX;

    /* GNU getopt_long with argument permutation */
    for (; list; list = list->next) {
        const char *w = list->word ? list->word->word : NULL;
        if (!w)
            continue;
        if (ddash || w[0] != '-' || w[1] == '\0') {
            if (noperands < 2)
                operands[noperands] = w;
            noperands++;
            continue;
        }
        if (!strcmp (w, "--")) {
            ddash = 1;
            continue;
        }
        if (w[1] == '-') {
            const char *name = w + 2, *eq = strchr (name, '=');
            size_t nl = eq ? (size_t) (eq - name) : strlen (name);
            int hit = -1, nhits = 0;
            for (int i = 0; i < BF_NLONG; i++) {
                if (strncmp (bf_longopts[i].name, name, nl))
                    continue;
                if (strlen (bf_longopts[i].name) == nl) {
                    hit = i;
                    nhits = 1;
                    break;
                }
                if (hit < 0)
                    hit = i;
                nhits++;
            }
            if (nhits == 0) {
                fprintf (stderr, "fstrim: unrecognized option '%s'\n", w);
                return bf_try_help ();
            }
            if (nhits > 1) {
                fprintf (stderr, "fstrim: option '%.*s' is ambiguous; possibilities:",
                         (int) nl + 2, w);
                for (int i = 0; i < BF_NLONG; i++)
                    if (!strncmp (bf_longopts[i].name, name, nl))
                        fprintf (stderr, " '--%s'", bf_longopts[i].name);
                fputc ('\n', stderr);
                return bf_try_help ();
            }
            const char *arg = NULL;
            if (bf_longopts[hit].has_arg) {
                if (eq)
                    arg = eq + 1;
                else if (list->next && list->next->word && list->next->word->word) {
                    list = list->next;
                    arg = list->word->word;
                } else {
                    fprintf (stderr, "fstrim: option '--%s' requires an argument\n",
                             bf_longopts[hit].name);
                    return bf_try_help ();
                }
            } else if (eq) {
                fprintf (stderr, "fstrim: option '--%s' doesn't allow an argument\n",
                         bf_longopts[hit].name);
                return bf_try_help ();
            }
            rc = bf_option (&o, bf_longopts[hit].val, arg, &excl, &tabs);
            if (rc == -2)
                return bf_finish (EXECUTION_SUCCESS);
            if (rc)
                return rc;
            continue;
        }
        for (const char *p = w + 1; *p; p++) {
            const char *arg = NULL;
            if (!strchr ("AahI:l:m:no:t:Vv", *p) || *p == ':') {
                fprintf (stderr, "fstrim: invalid option -- '%c'\n", *p);
                return bf_try_help ();
            }
            if (strchr ("Ilmot", *p)) {
                if (p[1])
                    arg = p + 1;
                else if (list->next && list->next->word && list->next->word->word) {
                    list = list->next;
                    arg = list->word->word;
                } else {
                    fprintf (stderr, "fstrim: option requires an argument -- '%c'\n", *p);
                    return bf_try_help ();
                }
            }
            rc = bf_option (&o, *p, arg, &excl, &tabs);
            if (rc == -2)
                return bf_finish (EXECUTION_SUCCESS);
            if (rc)
                return rc;
            if (arg)
                break;
        }
    }

    if (tabs) {
        if (noperands) {
            fputs ("fstrim: unexpected number of arguments\n", stderr);
            return bf_try_help ();
        }
        return bf_finish (bf_all (&o, tabs));
    }
    if (noperands == 0) {
        fputs ("fstrim: no mountpoint specified\n", stderr);
        return BF_EX_USAGE;
    }
    if (noperands > 1) {
        fputs ("fstrim: unexpected number of arguments\n", stderr);
        return bf_try_help ();
    }
    if (!bf_is_directory (operands[0], 0))
        return EXECUTION_FAILURE;
    rc = bf_trim_fs (&o, operands[0], NULL);
    if (rc == 1 && o.quiet_unsupported)
        rc = 0;
    if (rc == 1)
        fprintf (stderr, "fstrim: %s: the discard operation is not supported\n", operands[0]);
    return bf_finish (rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE);
}

char *fstrim_doc[] = {
    "Discard unused blocks on a mounted filesystem.",
    "",
    "    fstrim [options] <-A|-a|mount point>",
    "",
    "-a trims mounted filesystems, -A those in /etc/fstab and -I LIST those",
    "in the first non-empty file of a colon-separated fstab/mountinfo list;",
    "entries that are not mounted, writable, discard-capable local",
    "filesystems are skipped. -n does everything apart from FITRIM.",
    (char *) NULL
};

struct builtin fstrim_struct = {
    "fstrim",
    fstrim_builtin,
    BUILTIN_ENABLED,
    fstrim_doc,
    "fstrim [options] <-A|-a|mount point>",
    0
};
