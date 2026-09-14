/* bashmount.c — mount(2)/umount2(2) loadable + /proc/self/mountinfo
 *                lister (ML-T1-01). v1: tmpfs / bind / recursive-bind /
 *                remount-ro/rw; UUID/LABEL/fstab resolution deferred.
 *
 * Verbs / flags:
 *   bashmount [-t TYPE] [-o OPTS] SRC DST     mount(SRC, DST, TYPE, …)
 *   bashmount -B SRC DST                      bind mount  (MS_BIND)
 *   bashmount -R SRC DST                      recursive bind (MS_BIND|MS_REC)
 *   bashmount --remount [-o OPTS] DST         remount in place
 *   bashmount -l                              list /proc/self/mountinfo
 *   bashmount -u [-l|-f] DST                  umount2(DST, flags)
 *   bashmount --findmnt-table [PATH]          tabular mountinfo rows
 *   bashmount -h | --help                     usage
 *
 * Skipped in v1 (documented but not implemented):
 *   - /etc/fstab parsing
 *   - UUID=… / LABEL=… SRC resolution (needs bashblkid; the wrapper layer
 *     can do this prior to invoking us)
 *   - mount move (MS_MOVE), shared/private/slave propagation flags beyond
 *     what plain MS_BIND|MS_REC needs
 *
 * The OPTS string is comma-separated. Known names map to MS_* bits:
 *
 *     ro nosuid nodev noexec noatime nodiratime relatime strictatime
 *     sync dirsync mand bind remount shared private slave unbindable rec
 *
 * Unknown tokens become part of the fs-specific data string passed to
 * mount(2)'s 5th arg (so e.g. `-o size=64m` for tmpfs works). `rw` is
 * accepted as a no-op (the absence of `ro`).
 *
 * Output of -l mirrors mount(8) so it's grep-friendly:
 *
 *     SRC on DST type TYPE (OPTS)
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as other project-local loadables.
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
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#include "loadables.h"

#ifndef MS_LAZYTIME
#  define MS_LAZYTIME (1<<25)
#endif

#define BM_OPTS_MAX  4096
#define BM_LINE_MAX  8192

/* ---------------- options-string parser --------------------------------- */

typedef struct {
    unsigned long flags;       /* MS_* OR-mask                              */
    unsigned long clear;       /* MS_* bits explicitly turned off (rw)      */
    char data[BM_OPTS_MAX];    /* fs-specific opts collected for mount(2)   */
    size_t data_len;
} bm_opts;

typedef struct {
    const char *name;
    unsigned long bit;
    int clears;                /* if 1, this flag clears `bit` instead      */
} bm_flag_row;

static const bm_flag_row bm_flag_table[] = {
    { "ro",          MS_RDONLY,      0 },
    { "rw",          MS_RDONLY,      1 },
    { "nosuid",      MS_NOSUID,      0 },
    { "suid",        MS_NOSUID,      1 },
    { "nodev",       MS_NODEV,       0 },
    { "dev",         MS_NODEV,       1 },
    { "noexec",      MS_NOEXEC,      0 },
    { "exec",        MS_NOEXEC,      1 },
    { "noatime",     MS_NOATIME,     0 },
    { "atime",       MS_NOATIME,     1 },
    { "nodiratime",  MS_NODIRATIME,  0 },
    { "diratime",    MS_NODIRATIME,  1 },
    { "relatime",    MS_RELATIME,    0 },
    { "norelatime",  MS_RELATIME,    1 },
    { "strictatime", MS_STRICTATIME, 0 },
    { "lazytime",    MS_LAZYTIME,    0 },
    { "sync",        MS_SYNCHRONOUS, 0 },
    { "async",       MS_SYNCHRONOUS, 1 },
    { "dirsync",     MS_DIRSYNC,     0 },
    { "mand",        MS_MANDLOCK,    0 },
    { "bind",        MS_BIND,        0 },
    { "remount",     MS_REMOUNT,     0 },
    { "shared",      MS_SHARED,      0 },
    { "private",     MS_PRIVATE,     0 },
    { "slave",       MS_SLAVE,       0 },
    { "unbindable",  MS_UNBINDABLE,  0 },
    { "rec",         MS_REC,         0 },
    { NULL, 0, 0 }
};

static int
bm_parse_opt_token (bm_opts *o, const char *tok)
{
    if (!*tok) return 0;
    for (const bm_flag_row *r = bm_flag_table; r->name; r++) {
        if (strcmp (tok, r->name) == 0) {
            if (r->clears) o->clear |= r->bit;
            else           o->flags |= r->bit;
            return 0;
        }
    }
    /* Unknown — append to fs-specific data, comma-separated. */
    size_t add = strlen (tok);
    size_t need = o->data_len + (o->data_len ? 1 : 0) + add + 1;
    if (need > sizeof (o->data)) {
        builtin_error ("opts data too long");
        return -1;
    }
    if (o->data_len) o->data[o->data_len++] = ',';
    memcpy (o->data + o->data_len, tok, add);
    o->data_len += add;
    o->data[o->data_len] = '\0';
    return 0;
}

static int
bm_parse_opts (bm_opts *o, const char *opts)
{
    if (!opts || !*opts) return 0;
    char buf[BM_OPTS_MAX];
    size_t L = strlen (opts);
    if (L >= sizeof (buf)) {
        builtin_error ("-o argument too long (%zu bytes)", L);
        return -1;
    }
    memcpy (buf, opts, L + 1);
    char *save = NULL;
    for (char *tok = strtok_r (buf, ",", &save); tok;
         tok = strtok_r (NULL, ",", &save)) {
        /* Trim leading/trailing whitespace. */
        while (*tok && isspace ((unsigned char) *tok)) tok++;
        size_t tl = strlen (tok);
        while (tl > 0 && isspace ((unsigned char) tok[tl-1])) tok[--tl] = '\0';
        if (bm_parse_opt_token (o, tok) < 0) return -1;
    }
    return 0;
}

/* ---------------- /proc/self/mountinfo --------------------------------- */

/* Each line of mountinfo looks like:
 *
 *   36 35 98:0 /mnt1 /mnt/parent rw,noatime master:1 - ext4 /dev/root rw
 *
 * Fields (1-based):
 *   1 mount-id  2 parent-id  3 dev  4 root  5 mount-point  6 mount-opts
 *   7+         optional fields (master:N, propagate_from:N, unbindable)
 *   then `-` then  fs-type  source  super-opts
 *
 * For -l we extract:
 *   src     = field after `-`            (8th)
 *   dst     = field 5 (mount-point)
 *   type    = field after `-`            (7th)
 *   opts    = field 6 + super-opts joined with `,`
 *
 * Output (mount(8) style):
 *
 *   SRC on DST type TYPE (OPTS)
 */

/* mountinfo encodes special chars as \NNN octal. Decode in place. */
static void
bm_unescape (char *s)
{
    char *r = s, *w = s;
    while (*r) {
        if (r[0] == '\\' && isdigit ((unsigned char) r[1])
            && isdigit ((unsigned char) r[2])
            && isdigit ((unsigned char) r[3])) {
            int v = (r[1]-'0')*64 + (r[2]-'0')*8 + (r[3]-'0');
            *w++ = (char) v;
            r += 4;
        } else {
            *w++ = *r++;
        }
    }
    *w = '\0';
}

static int
bm_list_mounts (void)
{
    FILE *f = fopen ("/proc/self/mountinfo", "r");
    if (!f) {
        builtin_error ("open /proc/self/mountinfo: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    char line[BM_LINE_MAX];
    while (fgets (line, sizeof (line), f)) {
        size_t L = strlen (line);
        if (L && line[L-1] == '\n') line[L-1] = '\0';

        /* Tokenize first 6 mandatory fields. */
        char *tok[6] = {0};
        int n = 0;
        char *save = NULL;
        char *t = strtok_r (line, " \t", &save);
        while (t && n < 6) {
            tok[n++] = t;
            if (n < 6)
                t = strtok_r (NULL, " \t", &save);
        }
        if (n < 6) continue;
        char *dst  = tok[4];
        char *opts = tok[5];

        /* Find the `-` separator. After tokenizing 6 fields we've eaten
         * the line up to tok[5]; the rest lives at save. */
        if (!save) continue;
        char *rest = save;

        /* Skip optional fields up to and through the `-` token. */
        char *type = NULL, *src = NULL, *sopts = NULL;
        char *psave = NULL;
        int saw_dash = 0;
        for (char *t = strtok_r (rest, " \t", &psave); t;
             t = strtok_r (NULL, " \t", &psave)) {
            if (!saw_dash) {
                if (strcmp (t, "-") == 0) saw_dash = 1;
                continue;
            }
            if (!type) type = t;
            else if (!src) src = t;
            else if (!sopts) sopts = t;
            else break;
        }
        if (!type || !src) continue;

        bm_unescape (dst);
        bm_unescape (src);

        if (sopts && *sopts && strcmp (sopts, opts) != 0)
            printf ("%s on %s type %s (%s,%s)\n", src, dst, type, opts, sopts);
        else
            printf ("%s on %s type %s (%s)\n", src, dst, type, opts);
    }
    fclose (f);
    return EXECUTION_SUCCESS;
}

static int
bm_findmnt_table (const char *path)
{
    FILE *f;
    char line[BM_LINE_MAX];

    if (path == NULL || *path == '\0')
        path = "/proc/self/mountinfo";
    f = fopen (path, "r");
    if (!f) {
        builtin_error ("open %s: %s", path, strerror (errno));
        return EXECUTION_FAILURE;
    }

    while (fgets (line, sizeof line, f)) {
        char *tok[6] = {0};
        char *save = NULL;
        char *t;
        char *rest;
        char *type = NULL, *src = NULL;
        char *psave = NULL;
        int n = 0;
        int saw_dash = 0;
        size_t L = strlen (line);

        if (L && line[L - 1] == '\n')
            line[L - 1] = '\0';
        t = strtok_r (line, " \t", &save);
        while (t && n < 6) {
            tok[n++] = t;
            if (n < 6)
                t = strtok_r (NULL, " \t", &save);
        }
        if (n < 6 || save == NULL)
            continue;

        rest = save;
        for (t = strtok_r (rest, " \t", &psave); t;
             t = strtok_r (NULL, " \t", &psave)) {
            if (!saw_dash) {
                if (strcmp (t, "-") == 0)
                    saw_dash = 1;
                continue;
            }
            if (type == NULL)
                type = t;
            else if (src == NULL) {
                src = t;
                break;
            }
        }
        if (type == NULL || src == NULL)
            continue;

        bm_unescape (tok[3]);
        bm_unescape (tok[4]);
        bm_unescape (src);
        printf ("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
                tok[0], tok[1], tok[2], tok[3], tok[4], tok[5], type, src);
    }

    fclose (f);
    return EXECUTION_SUCCESS;
}

/* ---------------- mount/umount wrappers --------------------------------- */

/* Probe the filesystems the kernel knows, the way mount(8) does when given no
 * -t: try each non-nodev line of /proc/filesystems until one mounts. Returns 1
 * if a type mounted, 0 if none did. */
static int
bm_probe_types (const char *src, const char *dst,
                unsigned long flags, const char *data)
{
    FILE *f = fopen ("/proc/filesystems", "r");
    if (!f)
        return 0;
    char line[128];
    int mounted = 0;
    while (!mounted && fgets (line, sizeof line, f)) {
        /* "\t<name>" is device-backed; "nodev\t<name>" is not — skip those. */
        if (line[0] != '\t')
            continue;
        char *fs = line + 1;
        fs[strcspn (fs, " \t\n")] = '\0';
        if (*fs && mount (src, dst, fs, flags, data) == 0)
            mounted = 1;
    }
    fclose (f);
    return mounted;
}

static int
bm_do_mount (const char *src, const char *dst, const char *type,
             unsigned long flags, const char *data)
{
    if (mount (src, dst, type, flags, data) == 0)
        return EXECUTION_SUCCESS;
    /* No -t and the kernel rejected the NULL type: a plain
     * `bashmount /dev/mmcblk0p2 /data` should work, not silently fail. Only
     * probe for that exact case; a real mount error (ENOENT, EBUSY, wrong
     * type given) is reported as-is. Bind/move/remount carry no type. */
    int saved = errno;
    if (type == NULL && saved == EINVAL
        && !(flags & (MS_BIND | MS_REMOUNT
#ifdef MS_MOVE
                      | MS_MOVE
#endif
                     ))
        && bm_probe_types (src, dst, flags, data))
        return EXECUTION_SUCCESS;
    errno = saved;
    builtin_error ("mount(%s, %s, %s, 0x%lx, %s): %s",
                   src ? src : "(null)",
                   dst ? dst : "(null)",
                   type ? type : "(null)",
                   flags, data ? data : "(null)",
                   strerror (errno));
    return EXECUTION_FAILURE;
}

static int
bm_do_umount (const char *dst, int u_flags)
{
    if (umount2 (dst, u_flags) == 0)
        return EXECUTION_SUCCESS;
    builtin_error ("umount2(%s, 0x%x): %s", dst, u_flags, strerror (errno));
    return EXECUTION_FAILURE;
}

/* ---------------- mountpoint helper -------------------------------------- */

static int
bm_mountpoint_find (const char *canon, char *dev_out, size_t dev_outsz)
{
    FILE *f = fopen ("/proc/self/mountinfo", "r");
    char line[BM_LINE_MAX];

    if (!f) {
        fprintf (stderr, "mountpoint: /proc/self/mountinfo unreadable\n");
        return -1;
    }

    while (fgets (line, sizeof line, f)) {
        char *tok[5] = {0};
        char *save = NULL;
        char *t;
        int n = 0;

        for (t = strtok_r (line, " \t\r\n", &save);
             t && n < 5;
             t = strtok_r (NULL, " \t\r\n", &save))
            tok[n++] = t;

        if (n < 5)
            continue;
        bm_unescape (tok[4]);
        if (strcmp (tok[4], canon) == 0) {
            snprintf (dev_out, dev_outsz, "%s", tok[2]);
            fclose (f);
            return 1;
        }
    }

    fclose (f);
    return 0;
}

static int
bm_mountpoint (const char *path, int quiet, int print_dir_dev, int print_block_dev)
{
    struct stat st;
    char *canon;
    char dev[64] = "";
    int found;

    if (print_block_dev) {
        if (stat (path, &st) < 0) {
            if (!quiet)
                fprintf (stderr, "mountpoint: %s: cannot stat\n", path);
            return EXECUTION_FAILURE;
        }
        if (!S_ISBLK (st.st_mode)) {
            if (!quiet)
                fprintf (stderr, "mountpoint: %s: not a block device\n", path);
            return EXECUTION_FAILURE;
        }
        printf ("%u:%u\n", major (st.st_rdev), minor (st.st_rdev));
        return EXECUTION_SUCCESS;
    }

    canon = realpath (path, NULL);
    if (canon == NULL) {
        if (!quiet)
            fprintf (stderr, "mountpoint: %s: No such file or directory\n", path);
        return EXECUTION_FAILURE;
    }

    found = bm_mountpoint_find (canon, dev, sizeof dev);
    if (found < 0) {
        free (canon);
        return EX_USAGE;
    }

    if (print_dir_dev) {
        if (found) {
            printf ("%s\n", dev);
            free (canon);
            return EXECUTION_SUCCESS;
        }
        if (!quiet)
            fprintf (stderr, "mountpoint: %s: not a mountpoint\n", canon);
        free (canon);
        return EXECUTION_FAILURE;
    }

    if (found) {
        if (!quiet)
            printf ("%s is a mountpoint\n", canon);
        free (canon);
        return EXECUTION_SUCCESS;
    }

    if (!quiet)
        printf ("%s is not a mountpoint\n", canon);
    free (canon);
    return EXECUTION_FAILURE;
}

/* ---------------- argv parser & dispatch -------------------------------- */

static int
bm_print_usage (FILE *out)
{
    fputs (
      "usage: bashmount [-t TYPE] [-o OPTS] SRC DST\n"
      "       bashmount -B SRC DST            (bind)\n"
      "       bashmount -R SRC DST            (recursive bind)\n"
      "       bashmount --remount [-o OPTS] DST\n"
      "       bashmount -l                    (list /proc/self/mountinfo)\n"
      "       bashmount -u [-l|-f] DST        (umount2)\n"
      "       bashmount --mountpoint [-q|-d|-x] PATH\n"
      "       bashmount --findmnt-table [PATH]\n"
      "       bashmount -h | --help\n",
      out);
    return EXECUTION_SUCCESS;
}

int
bashmount_builtin (WORD_LIST *list)
{
    int do_help = 0;
    int do_list = 0;
    int do_bind = 0;
    int do_rbind = 0;
    int do_remount = 0;
    int do_umount = 0;
    int do_mountpoint = 0;
    int do_findmnt_table = 0;
    int mp_quiet = 0;
    int mp_dir_dev = 0;
    int mp_block_dev = 0;
    int u_flags = 0;
    const char *type = NULL;
    const char *opts = NULL;
    const char *pos[4] = { NULL, NULL, NULL, NULL };
    int n_pos = 0;

    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;

        if (strcmp (w, "--") == 0) {
            for (p = p->next; p; p = p->next)
                if (n_pos < 4) pos[n_pos++] = p->word->word;
            break;
        }
        if (strcmp (w, "-h") == 0 || strcmp (w, "--help") == 0) {
            do_help = 1; continue;
        }
        if (strcmp (w, "-l") == 0) {
            /* Context-sensitive: bare -l ⇒ list mode; -l after -u ⇒ MNT_DETACH. */
            if (do_umount) u_flags |= MNT_DETACH;
            else do_list = 1;
            continue;
        }
        if (strcmp (w, "-f") == 0) {
            if (do_umount) u_flags |= MNT_FORCE;
            else { builtin_error ("-f is only valid after -u"); return EX_USAGE; }
            continue;
        }
        if (strcmp (w, "-u") == 0 || strcmp (w, "--umount") == 0) {
            do_umount = 1; continue;
        }
        if (strcmp (w, "--mountpoint") == 0) {
            do_mountpoint = 1; continue;
        }
        if (strcmp (w, "--findmnt-table") == 0) {
            do_findmnt_table = 1; continue;
        }
        if (strcmp (w, "-q") == 0 || strcmp (w, "--quiet") == 0) {
            mp_quiet = 1; continue;
        }
        if (strcmp (w, "-d") == 0 || strcmp (w, "--devno") == 0) {
            mp_dir_dev = 1; continue;
        }
        if (strcmp (w, "-x") == 0 || strcmp (w, "--xdevno") == 0) {
            mp_block_dev = 1; continue;
        }
        if (strcmp (w, "-B") == 0 || strcmp (w, "--bind") == 0) {
            do_bind = 1; continue;
        }
        if (strcmp (w, "-R") == 0 || strcmp (w, "--rbind") == 0) {
            do_rbind = 1; continue;
        }
        if (strcmp (w, "--remount") == 0) { do_remount = 1; continue; }
        if (strcmp (w, "-t") == 0) {
            if (!p->next) { builtin_error ("-t requires TYPE"); return EX_USAGE; }
            p = p->next; type = p->word->word; continue;
        }
        if (strcmp (w, "-o") == 0) {
            if (!p->next) { builtin_error ("-o requires OPTS"); return EX_USAGE; }
            p = p->next; opts = p->word->word; continue;
        }
        if (w[0] == '-' && w[1] != '\0') {
            builtin_error ("unknown flag: %s", w);
            bm_print_usage (stderr);
            return EX_USAGE;
        }
        if (n_pos < 4) pos[n_pos++] = w;
        else { builtin_error ("too many positional args"); return EX_USAGE; }
    }

    if (do_help) { bm_print_usage (stdout); return EXECUTION_SUCCESS; }

    int modes = do_list + do_bind + do_rbind + do_remount + do_umount + do_mountpoint + do_findmnt_table;
    if (modes > 1) {
        builtin_error ("conflicting verbs (pick one of -l / -B / -R / --remount / -u / --mountpoint / --findmnt-table)");
        return EX_USAGE;
    }

    if (!do_mountpoint && (mp_quiet || mp_dir_dev || mp_block_dev)) {
        builtin_error ("-q/-d/-x are only valid with --mountpoint");
        return EX_USAGE;
    }

    if (do_list) {
        if (n_pos != 0) {
            builtin_error ("-l takes no positional args");
            return EX_USAGE;
        }
        return bm_list_mounts ();
    }

    if (do_findmnt_table) {
        if (n_pos > 1) {
            builtin_error ("--findmnt-table [PATH] (got %d positional args)", n_pos);
            return EX_USAGE;
        }
        return bm_findmnt_table (n_pos == 1 ? pos[0] : NULL);
    }

    if (do_umount) {
        if (n_pos != 1) {
            builtin_error ("-u DST (got %d positional args)", n_pos);
            return EX_USAGE;
        }
        return bm_do_umount (pos[0], u_flags);
    }

    if (do_mountpoint) {
        if (n_pos != 1) {
            builtin_error ("--mountpoint [-q|-d|-x] PATH (got %d positional args)", n_pos);
            return EX_USAGE;
        }
        if (mp_dir_dev && mp_block_dev) {
            builtin_error ("--mountpoint: pick only one of -d / -x");
            return EX_USAGE;
        }
        return bm_mountpoint (pos[0], mp_quiet, mp_dir_dev, mp_block_dev);
    }

    /* From here every verb needs an opts struct. */
    bm_opts o = {0};
    if (bm_parse_opts (&o, opts) < 0) return EX_USAGE;
    o.flags &= ~o.clear;
    const char *data = o.data_len ? o.data : NULL;

    if (do_bind || do_rbind) {
        if (n_pos != 2) {
            builtin_error ("%s SRC DST (got %d positional args)",
                           do_bind ? "-B" : "-R", n_pos);
            return EX_USAGE;
        }
        unsigned long fl = MS_BIND;
        if (do_rbind) fl |= MS_REC;
        fl |= o.flags;
        int rc = bm_do_mount (pos[0], pos[1], NULL, fl, data);
        if (rc != EXECUTION_SUCCESS) return rc;
        /* If ro was requested with a bind, the kernel ignores MS_RDONLY
         * on the initial bind — do a follow-up remount. */
        if ((o.flags & MS_RDONLY) != 0) {
            unsigned long fl2 = MS_BIND | MS_REMOUNT | MS_RDONLY;
            if (do_rbind) fl2 |= MS_REC;
            rc = bm_do_mount (pos[0], pos[1], NULL, fl2, data);
        }
        return rc;
    }

    if (do_remount) {
        if (n_pos != 1) {
            builtin_error ("--remount DST (got %d positional args)", n_pos);
            return EX_USAGE;
        }
        unsigned long fl = MS_REMOUNT | o.flags;
        return bm_do_mount (NULL, pos[0], NULL, fl, data);
    }

    /* Plain mount: SRC DST. TYPE optional (kernel rejects if needed). */
    if (n_pos != 2) {
        builtin_error ("usage: bashmount [-t TYPE] [-o OPTS] SRC DST");
        return EX_USAGE;
    }
    return bm_do_mount (pos[0], pos[1], type, o.flags, data);
}

char *bashmount_doc[] = {
    "Mount/umount filesystems and list /proc/self/mountinfo.",
    "",
    "    bashmount [-t TYPE] [-o OPTS] SRC DST",
    "    bashmount -B SRC DST              # bind mount",
    "    bashmount -R SRC DST              # recursive bind mount",
    "    bashmount --remount [-o OPTS] DST",
    "    bashmount -l                       # list mounts",
    "    bashmount -u [-l|-f] DST           # umount (-l detach, -f force)",
    "    bashmount --mountpoint [-q|-d|-x] PATH",
    "    bashmount --findmnt-table [PATH]",
    "    bashmount -h | --help",
    "",
    "OPTS is a comma-separated subset of:",
    "    ro / rw / nosuid / nodev / noexec / noatime / nodiratime /",
    "    relatime / strictatime / sync / dirsync / mand / bind / remount /",
    "    shared / private / slave / unbindable / rec",
    "Unknown tokens are passed as fs-specific data (e.g. tmpfs size=64m).",
    (char *)NULL
};

struct builtin bashmount_struct = {
    "bashmount",
    bashmount_builtin,
    BUILTIN_ENABLED,
    bashmount_doc,
    "bashmount [-t TYPE] [-o OPTS] [-B|-R|--remount|-u|-l|--mountpoint|--findmnt-table] SRC DST",
    0
};
