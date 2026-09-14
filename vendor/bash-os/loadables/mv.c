/* bashmv.c — POSIX mv(1) as a bash builtin.
 *
 * Phase S of bash-os POSIX gap-fillers.
 *
 *   bashmv [-fin] SOURCE... DEST
 *
 *   -f   force: silently overwrite (no prompt)
 *   -i   interactive: prompt before overwrite
 *   -n   no-clobber: never overwrite
 *
 * Strategy: try rename(2) first. On EXDEV (cross-device move), fall
 * back to recursive copy + unlink. The copy core duplicates the file/
 * symlink/dir copy from bashcp.c — three similar lines beats
 * cross-loadable abstraction in bash's static-link pipeline.
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
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "loadables.h"

typedef struct { int fflag, iflag, nflag, Tflag; const char *target_dir; } bmv_opts;

typedef struct {
    const char **v;
    int n;
    int cap;
} bmv_words;

static int
bmv_words_add (bmv_words *words, const char *word)
{
    if (words->n == words->cap) {
        int new_cap = words->cap ? words->cap * 2 : 16;
        const char **nv = realloc (words->v, (size_t) new_cap * sizeof (*words->v));
        if (!nv) {
            builtin_error ("realloc: %s", strerror (errno));
            return -1;
        }
        words->v = nv;
        words->cap = new_cap;
    }
    words->v[words->n++] = word;
    return 0;
}

static int bmv_xdev_move (const char *src, const char *dst);

static int
bmv_copy_data (int sfd, int dfd)
{
    char buf[64 * 1024];
    ssize_t n;
    while ((n = read (sfd, buf, sizeof buf)) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write (dfd, buf + off, (size_t) (n - off));
            if (w < 0) { if (errno == EINTR) continue; return -1; }
            off += w;
        }
    }
    return n < 0 ? -1 : 0;
}

static int
bmv_copy_regular (const char *src, const char *dst, const struct stat *sst)
{
    int sfd = open (src, O_RDONLY);
    if (sfd < 0) { builtin_error ("open %s: %s", src, strerror (errno)); return -1; }
    if (unlink (dst) < 0 && errno != ENOENT) {
        close (sfd);
        builtin_error ("unlink %s: %s", dst, strerror (errno));
        return -1;
    }
    int dfd = open (dst, O_WRONLY | O_CREAT | O_TRUNC, sst->st_mode & 0777);
    if (dfd < 0) {
        close (sfd);
        builtin_error ("open %s for write: %s", dst, strerror (errno));
        return -1;
    }
    int rc = bmv_copy_data (sfd, dfd);
    close (sfd);
    close (dfd);
    if (rc < 0) {
        builtin_error ("copy %s -> %s failed", src, dst);
        return -1;
    }
    /* Preserve mode + owner + times across xdev move. */
    chmod (dst, sst->st_mode & 07777);
    if (chown (dst, sst->st_uid, sst->st_gid) < 0 && errno != EPERM) {
        builtin_error ("chown %s: %s", dst, strerror (errno));
    }
    struct timespec ts[2] = {
        { .tv_sec = sst->st_atim.tv_sec, .tv_nsec = sst->st_atim.tv_nsec },
        { .tv_sec = sst->st_mtim.tv_sec, .tv_nsec = sst->st_mtim.tv_nsec }
    };
    utimensat (AT_FDCWD, dst, ts, AT_SYMLINK_NOFOLLOW);
    return 0;
}

static int
bmv_copy_symlink (const char *src, const char *dst)
{
    char target[4096];
    ssize_t n = readlink (src, target, sizeof target - 1);
    if (n < 0) { builtin_error ("readlink %s: %s", src, strerror (errno)); return -1; }
    target[n] = '\0';
    unlink (dst);
    if (symlink (target, dst) < 0) {
        builtin_error ("symlink %s: %s", dst, strerror (errno));
        return -1;
    }
    return 0;
}

static int
bmv_copy_dir (const char *src, const char *dst, const struct stat *sst)
{
    if (mkdir (dst, sst->st_mode & 0777) < 0 && errno != EEXIST) {
        builtin_error ("mkdir %s: %s", dst, strerror (errno));
        return -1;
    }
    DIR *d = opendir (src);
    if (!d) { builtin_error ("opendir %s: %s", src, strerror (errno)); return -1; }
    int rc = 0;
    struct dirent *de;
    while ((de = readdir (d)) != NULL) {
        if (!strcmp (de->d_name, ".") || !strcmp (de->d_name, "..")) continue;
        char sc[4096], dc[4096];
        snprintf (sc, sizeof sc, "%s/%s", src, de->d_name);
        snprintf (dc, sizeof dc, "%s/%s", dst, de->d_name);
        if (bmv_xdev_move (sc, dc) < 0) rc = -1;
    }
    closedir (d);
    chmod (dst, sst->st_mode & 07777);
    if (chown (dst, sst->st_uid, sst->st_gid) < 0 && errno != EPERM) {
        builtin_error ("chown %s: %s", dst, strerror (errno));
    }
    struct timespec ts[2] = {
        { .tv_sec = sst->st_atim.tv_sec, .tv_nsec = sst->st_atim.tv_nsec },
        { .tv_sec = sst->st_mtim.tv_sec, .tv_nsec = sst->st_mtim.tv_nsec }
    };
    utimensat (AT_FDCWD, dst, ts, AT_SYMLINK_NOFOLLOW);
    return rc;
}

/* Recursive cross-device move: copy entry, then unlink source. */
static int
bmv_xdev_move (const char *src, const char *dst)
{
    struct stat sst;
    if (lstat (src, &sst) < 0) {
        builtin_error ("stat %s: %s", src, strerror (errno));
        return -1;
    }
    int rc;
    if (S_ISLNK (sst.st_mode))      rc = bmv_copy_symlink (src, dst);
    else if (S_ISDIR (sst.st_mode)) rc = bmv_copy_dir (src, dst, &sst);
    else if (S_ISREG (sst.st_mode)) rc = bmv_copy_regular (src, dst, &sst);
    else {
        builtin_error ("%s: unsupported file type", src);
        return -1;
    }
    if (rc < 0) return -1;
    /* Remove source. */
    if (S_ISDIR (sst.st_mode)) {
        if (rmdir (src) < 0) {
            builtin_error ("rmdir %s: %s", src, strerror (errno));
            return -1;
        }
    } else {
        if (unlink (src) < 0) {
            builtin_error ("unlink %s: %s", src, strerror (errno));
            return -1;
        }
    }
    return 0;
}

static int
bmv_one (const char *src, const char *dst, const bmv_opts *o)
{
    /* Existence check on dst with -i / -n / -f. */
    struct stat dst_st;
    int dst_exists = (lstat (dst, &dst_st) == 0);
    if (dst_exists) {
        if (o->nflag) return 0;  /* skip silently */
        if (o->iflag && !o->fflag) {
            fprintf (stderr, "bashmv: overwrite '%s'? ", dst);
            fflush (stderr);
            int c = getchar ();
            if (c != 'y' && c != 'Y') return 0;
            while (c != EOF && c != '\n') c = getchar ();
        }
    }
    {
        struct stat src_st;
        if (lstat (src, &src_st) == 0 && dst_exists
            && src_st.st_dev == dst_st.st_dev && src_st.st_ino == dst_st.st_ino) {
            builtin_error ("'%s' and '%s' are the same file", src, dst);
            return -1;
        }
    }
    /* rename(2) handles same-fs atomically. */
    if (rename (src, dst) == 0) return 0;
    if (errno != EXDEV) {
        builtin_error ("rename %s -> %s: %s", src, dst, strerror (errno));
        return -1;
    }
    /* Cross-device — copy + unlink. */
    return bmv_xdev_move (src, dst);
}

int
mv_builtin (WORD_LIST *list)
{
    bmv_opts o = {0};
    bmv_words positional = {0};
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "--help") == 0) {
            /* Emit the full doc table — builtin_usage() only prints the
             * terse one-line short_usage (`bashmv: usage: bashmv`)
             * which doesn't satisfy the D01 / GNU-style parity contract
             * (the SOURCE/DEST synopsis must appear). */
            extern char *mv_doc[];
            for (int _i = 0; mv_doc[_i]; _i++)
                puts (mv_doc[_i]);
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--version") == 0) {
            puts ("bashmv 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (strncmp (w, "--target-directory=", 19) == 0) { o.target_dir = w + 19; continue; }
        if (strcmp (w, "--target-directory") == 0) {
            p = p->next;
            if (!p) { builtin_error ("option '--target-directory' requires an argument"); free (positional.v); return EX_USAGE; }
            o.target_dir = p->word->word;
            continue;
        }
        if (strcmp (w, "--no-target-directory") == 0) { o.Tflag = 1; continue; }
        if (strcmp (w, "--") == 0) {
            for (p = p->next; p; p = p->next) {
                if (bmv_words_add (&positional, p->word->word) < 0) {
                    free (positional.v);
                    return EXECUTION_FAILURE;
                }
            }
            break;
        }
        if (w[0] == '-' && w[1] && strcmp (w, "-") != 0) {
            for (int i = 1; w[i]; i++) {
                if (w[i] == 't') {  /* -t DIR: arg is the rest of the word, else the next word */
                    if (w[i + 1]) {
                        o.target_dir = &w[i + 1];
                    } else {
                        if (!p->next) { builtin_error ("option requires an argument -- 't'"); free (positional.v); return EX_USAGE; }
                        p = p->next;
                        o.target_dir = p->word->word;
                    }
                    break;  /* remainder of this word (if any) consumed as DIR */
                }
                switch (w[i]) {
                case 'f': o.fflag = 1; o.iflag = 0; o.nflag = 0; break;
                case 'i': o.iflag = 1; o.fflag = 0; o.nflag = 0; break;
                case 'n': o.nflag = 1; o.fflag = 0; o.iflag = 0; break;
                case 'T': o.Tflag = 1; break;
                default:
                    builtin_error ("unknown flag: -%c", w[i]);
                    free (positional.v);
                    return EX_USAGE;
                }
            }
        } else {
            if (bmv_words_add (&positional, w) < 0) {
                free (positional.v);
                return EXECUTION_FAILURE;
            }
        }
    }
    if (o.target_dir && o.Tflag) {
        builtin_error ("cannot combine --target-directory (-t) and --no-target-directory (-T)");
        free (positional.v);
        return EX_USAGE;
    }

    const char *dest;
    int nsrc;
    struct stat dst_st;
    int dst_is_dir;

    if (o.target_dir) {
        /* -t DIR: every operand is a SOURCE; DEST is DIR (must be a dir). */
        if (positional.n < 1) {
            builtin_error ("missing file operand");
            free (positional.v);
            return EX_USAGE;
        }
        dest = o.target_dir;
        nsrc = positional.n;
        if (!(stat (dest, &dst_st) == 0 && S_ISDIR (dst_st.st_mode))) {
            builtin_error ("target '%s' is not a directory", dest);
            free (positional.v);
            return EXECUTION_FAILURE;
        }
        dst_is_dir = 1;
    } else {
        if (positional.n < 2) {
            builtin_error ("usage: bashmv [-fin] [-t DIR | -T] SOURCE... DEST");
            free (positional.v);
            return EX_USAGE;
        }
        dest = positional.v[positional.n - 1];
        nsrc = positional.n - 1;
        if (o.Tflag) {
            /* -T: treat DEST as a normal file, never a directory to move into.
               Requires exactly one SOURCE. */
            if (nsrc != 1) {
                builtin_error ("extra operand '%s'", positional.v[1]);
                free (positional.v);
                return EX_USAGE;
            }
            dst_is_dir = 0;
        } else {
            dst_is_dir = (stat (dest, &dst_st) == 0 && S_ISDIR (dst_st.st_mode));
            if (nsrc > 1 && !dst_is_dir) {
                builtin_error ("target '%s' is not a directory", dest);
                free (positional.v);
                return EXECUTION_FAILURE;
            }
        }
    }

    int rc = EXECUTION_SUCCESS;
    for (int i = 0; i < nsrc; i++) {
        const char *src = positional.v[i];
        char dst_buf[4096];
        const char *dst;
        if (dst_is_dir) {
            const char *base = strrchr (src, '/');
            base = base ? base + 1 : src;
            snprintf (dst_buf, sizeof dst_buf, "%s/%s", dest, base);
            dst = dst_buf;
        } else {
            dst = dest;
        }
        if (bmv_one (src, dst, &o) < 0) rc = EXECUTION_FAILURE;
    }
    free (positional.v);
    return rc;
}

char *mv_doc[] = {
    "Move (rename) files.",
    "",
    "    bashmv [-fin] [-T] SOURCE DEST",
    "    bashmv [-fin] SOURCE... DIRECTORY",
    "    bashmv [-fin] -t DIRECTORY SOURCE...",
    "",
    "    -f   force: silently overwrite",
    "    -i   interactive: prompt before overwrite",
    "    -n   no-clobber: never overwrite",
    "    -t, --target-directory=DIR   move all SOURCEs into DIR",
    "    -T, --no-target-directory    treat DEST as a normal file, not a dir",
    "",
    "Tries rename(2) first; on EXDEV (cross-device), falls back to",
    "recursive copy + unlink.",
    (char *)NULL
};

struct builtin bashmv_struct = {
    "bashmv",
    mv_builtin,
    BUILTIN_ENABLED,
    mv_doc,
    "bashmv [-fin] [-t DIR | -T] SOURCE... DEST",
    0
};
