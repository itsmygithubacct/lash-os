/* bashcp.c — POSIX cp(1) as a bash builtin.
 *
 * Phase S of bash-os POSIX gap-fillers.
 *
 *   bashcp [-afipRrv] [-HLP] SOURCE... DEST
 *
 *   -a      archive: same as -dpR (preserve symlinks-as-symlinks, preserve
 *           metadata, recursive). Matches GNU coreutils cp -a semantics.
 *   -f      force: replace existing dest after the source is opened
 *   -i      interactive: prompt before overwrite (refused unless tty)
 *   -p      preserve mode/owner/group/timestamps
 *   -R, -r  recursive
 *   -v      verbose: print each completed copy
 *   -H      follow symlinks given on the command line; preserve nested
 *   -L      always follow symlinks
 *   -P      don't follow symlinks
 *           (default: don't follow; clone symlinks as symlinks)
 *
 * Multiple SOURCE → DEST must be a directory. Single SOURCE → DEST
 * is either a target file or, if it's a directory, the file is
 * copied into it as basename(SOURCE).
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
#include <sys/time.h>
#include <utime.h>

#include "loadables.h"

typedef struct {
    int fflag, iflag, pflag, rflag, vflag;
    int Hflag, Lflag;
} bcp_opts;

typedef struct {
    const char **v;
    int n;
    int cap;
} bcp_words;

static int
bcp_words_add (bcp_words *words, const char *word)
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

/* Forward decls. */
static int bcp_one (const char *src, const char *dst,
                    const bcp_opts *o, int top_level_source);

/* Fast path: read+write loop. No sendfile dependency — keep portable. */
static int
bcp_copy_data (int sfd, int dfd, const char *src, const char *dst)
{
    char buf[64 * 1024];
    ssize_t n;
    while ((n = read (sfd, buf, sizeof buf)) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write (dfd, buf + off, (size_t) (n - off));
            if (w < 0) {
                if (errno == EINTR) continue;
                builtin_error ("write %s: %s", dst, strerror (errno));
                return -1;
            }
            off += w;
        }
    }
    if (n < 0) {
        builtin_error ("read %s: %s", src, strerror (errno));
        return -1;
    }
    return 0;
}

static int
bcp_apply_metadata (const char *dst, const struct stat *st)
{
    /* Permissions first; then owner (silent on EPERM); then times. */
    if (chmod (dst, st->st_mode & 07777) < 0) {
        builtin_error ("chmod %s: %s", dst, strerror (errno));
        /* Non-fatal — keep going. */
    }
    if (chown (dst, st->st_uid, st->st_gid) < 0) {
        if (errno != EPERM) {
            builtin_error ("chown %s: %s", dst, strerror (errno));
        }
    }
    struct timespec ts[2];
    ts[0].tv_sec  = st->st_atim.tv_sec;
    ts[0].tv_nsec = st->st_atim.tv_nsec;
    ts[1].tv_sec  = st->st_mtim.tv_sec;
    ts[1].tv_nsec = st->st_mtim.tv_nsec;
    if (utimensat (AT_FDCWD, dst, ts, AT_SYMLINK_NOFOLLOW) < 0) {
        /* fallback for old kernels */
        struct timeval tv[2];
        tv[0].tv_sec = ts[0].tv_sec; tv[0].tv_usec = ts[0].tv_nsec / 1000;
        tv[1].tv_sec = ts[1].tv_sec; tv[1].tv_usec = ts[1].tv_nsec / 1000;
        utimes (dst, tv);
    }
    return 0;
}

/* Copy a regular file. dst is a full path — no path-joining here. */
static int
bcp_copy_regular (const char *src, const char *dst,
                  const struct stat *sst, const bcp_opts *o)
{
    /* Detect dst exists; honor -f / -i. */
    struct stat dst_st;
    int dst_exists = (lstat (dst, &dst_st) == 0);
    if (dst_exists) {
        /* Refuse identical-inode (cp file file). */
        if (dst_st.st_dev == sst->st_dev && dst_st.st_ino == sst->st_ino) {
            builtin_error ("'%s' and '%s' are the same file", src, dst);
            return -1;
        }
        if (o->iflag) {
            fprintf (stderr, "bashcp: overwrite '%s'? ", dst);
            fflush (stderr);
            int c = getchar ();
            if (c != 'y' && c != 'Y') return 0;
            while (c != EOF && c != '\n') c = getchar ();
        }
        if (!o->fflag && S_ISLNK (dst_st.st_mode)) {
            struct stat target_st;
            if (stat (dst, &target_st) < 0) {
                builtin_error ("%s: existing destination is a dangling symlink (use -f to replace it)", dst);
                return -1;
            }
            if (S_ISDIR (target_st.st_mode)) {
                builtin_error ("%s: existing destination symlink target is a directory", dst);
                return -1;
            }
        } else if (!o->fflag && S_ISDIR (dst_st.st_mode)) {
            builtin_error ("%s: existing destination is a directory", dst);
            return -1;
        }
    }
    /* Open the source before replacing dest. -f must not unlink an
       existing destination when the source cannot be read. */
    int sfd = open (src, O_RDONLY);
    if (sfd < 0) {
        builtin_error ("open %s: %s", src, strerror (errno));
        return -1;
    }
    if (dst_exists && o->fflag) {
        if (unlink (dst) < 0 && errno != ENOENT) {
            builtin_error ("unlink %s: %s", dst, strerror (errno));
            close (sfd);
            return -1;
        }
    }
    /* Open without truncating: dst may be a symlink back to src, and the
       lstat check above compares the link's inode rather than its target. */
    int dfd = open (dst, O_WRONLY | O_CREAT, sst->st_mode & 0777);
    if (dfd < 0) {
        builtin_error ("open %s for write: %s", dst, strerror (errno));
        close (sfd);
        return -1;
    }
    struct stat opened_src, opened_dst;
    if (fstat (sfd, &opened_src) < 0 || fstat (dfd, &opened_dst) < 0) {
        builtin_error ("stat open file: %s", strerror (errno));
        close (sfd);
        close (dfd);
        return -1;
    }
    if (opened_src.st_dev == opened_dst.st_dev &&
        opened_src.st_ino == opened_dst.st_ino) {
        builtin_error ("'%s' and '%s' are the same file", src, dst);
        close (sfd);
        close (dfd);
        return -1;
    }
    /* Truncate a regular file; a device, fifo or socket is simply written into. */
    int dst_regular = S_ISREG (opened_dst.st_mode);
    if (dst_regular && ftruncate (dfd, 0) < 0) {
        builtin_error ("truncate %s: %s", dst, strerror (errno));
        close (sfd);
        close (dfd);
        return -1;
    }
    int rc = bcp_copy_data (sfd, dfd, src, dst);
    close (sfd);
    close (dfd);
    if (rc < 0) return -1;
    if (o->pflag && dst_regular) bcp_apply_metadata (dst, sst);
    if (o->vflag)
        printf ("'%s' -> '%s'\n", src, dst);  /* GNU cp -v writes to stdout */
    return 0;
}

static int
bcp_copy_symlink (const char *src, const char *dst, const struct stat *sst,
                  const bcp_opts *o)
{
    char target[4096];
    ssize_t n = readlink (src, target, sizeof target - 1);
    if (n < 0) {
        builtin_error ("readlink %s: %s", src, strerror (errno));
        return -1;
    }
    target[n] = '\0';
    /* Replace existing dst on -f. Use symlink-to-temp + rename so the
       replacement is atomic (no window where dst doesn't exist). */
    struct stat ds;
    int dst_exists = (lstat (dst, &ds) == 0);
    if (dst_exists && !o->fflag) {
        builtin_error ("'%s' exists", dst);
        return -1;
    }
    if (dst_exists) {
        char tmp_path[4096 + 16];
        int wlen = snprintf (tmp_path, sizeof tmp_path,
                             "%s.bcptmp.%d", dst, (int) getpid ());
        if (wlen < 0 || (size_t) wlen >= sizeof tmp_path) {
            builtin_error ("symlink %s: dst path too long for atomic replace", dst);
            return -1;
        }
        (void) unlink (tmp_path);
        if (symlink (target, tmp_path) < 0) {
            builtin_error ("symlink %s -> %s: %s", tmp_path, target, strerror (errno));
            return -1;
        }
        if (rename (tmp_path, dst) < 0) {
            builtin_error ("rename %s -> %s: %s", tmp_path, dst, strerror (errno));
            unlink (tmp_path);
            return -1;
        }
    } else if (symlink (target, dst) < 0) {
        builtin_error ("symlink %s -> %s: %s", dst, target, strerror (errno));
        return -1;
    }
    if (o->pflag) {
        /* lchown for symlink owner. */
        if (lchown (dst, sst->st_uid, sst->st_gid) < 0 && errno != EPERM)
            builtin_error ("lchown %s: %s", dst, strerror (errno));
    }
    if (o->vflag)
        printf ("'%s' -> '%s'\n", src, dst);  /* GNU cp -v writes to stdout */
    return 0;
}

static int
bcp_copy_dir (const char *src, const char *dst, const struct stat *sst,
              const bcp_opts *o)
{
    if (!o->rflag) {
        builtin_error ("-r not specified; omitting directory '%s'", src);
        return -1;
    }
    /* mkdir if not present. */
    struct stat ds;
    if (lstat (dst, &ds) < 0) {
        if (mkdir (dst, sst->st_mode & 0777) < 0) {
            builtin_error ("mkdir %s: %s", dst, strerror (errno));
            return -1;
        }
        if (o->vflag)
            printf ("'%s' -> '%s'\n", src, dst);  /* GNU cp -v writes to stdout */
    } else if (!S_ISDIR (ds.st_mode)) {
        builtin_error ("'%s' exists and is not a directory", dst);
        return -1;
    }
    DIR *dir = opendir (src);
    if (!dir) {
        builtin_error ("opendir %s: %s", src, strerror (errno));
        return -1;
    }
    int rc = 0;
    struct dirent *de;
    while ((de = readdir (dir)) != NULL) {
        if (strcmp (de->d_name, ".") == 0 || strcmp (de->d_name, "..") == 0)
            continue;
        char src_child[4096], dst_child[4096];
        snprintf (src_child, sizeof src_child, "%s/%s", src, de->d_name);
        snprintf (dst_child, sizeof dst_child, "%s/%s", dst, de->d_name);
        if (bcp_one (src_child, dst_child, o, 0) < 0) rc = -1;
    }
    closedir (dir);
    if (o->pflag) bcp_apply_metadata (dst, sst);
    return rc;
}

/* Top-level dispatcher per source. dst must be a complete target path
   (file or directory entry name); caller resolves dir-into. */
static int
bcp_one (const char *src, const char *dst, const bcp_opts *o, int top_level_source)
{
    struct stat sst;
    int follow = o->Lflag || (top_level_source && o->Hflag);
    int rc;
    if (follow) rc = stat (src, &sst);
    else        rc = lstat (src, &sst);
    if (rc < 0) {
        builtin_error ("stat %s: %s", src, strerror (errno));
        return -1;
    }
    if (S_ISLNK (sst.st_mode))    return bcp_copy_symlink (src, dst, &sst, o);
    if (S_ISDIR (sst.st_mode))    return bcp_copy_dir     (src, dst, &sst, o);
    if (S_ISREG (sst.st_mode))    return bcp_copy_regular (src, dst, &sst, o);
    /* Other (fifo, sock, dev) — refuse for now. */
    builtin_error ("%s: unsupported file type", src);
    return -1;
}

int
cp_builtin (WORD_LIST *list)
{
    bcp_opts o = {0};
    /* Parse flags + collect SOURCE list + DEST. */
    bcp_words positional = {0};
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "--help") == 0) {
            builtin_usage ();
            free (positional.v);
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--version") == 0) {
            puts ("bashcp 1.0 (bash-loadable)");
            free (positional.v);
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--") == 0) {
            for (p = p->next; p; p = p->next) {
                if (bcp_words_add (&positional, p->word->word) < 0) {
                    free (positional.v);
                    return EXECUTION_FAILURE;
                }
            }
            break;
        }
        if (w[0] == '-' && w[1] && strcmp (w, "-") != 0) {
            for (int i = 1; w[i]; i++) {
                switch (w[i]) {
                case 'a':
                    /* Archive: -dpR. -d means "no-dereference + preserve
                       link" — bashcp's default symlink mode is already
                       no-dereference (clones symlinks as symlinks) so
                        we clear Hflag/Lflag to guarantee that even if a
                       prior char in the same word set them; pflag covers
                       the metadata side (lchown for symlinks is already
                       handled in bcp_copy_symlink). Recursion via rflag. */
                    o.pflag = 1;
                    o.rflag = 1;
                    o.Hflag = 0;
                    o.Lflag = 0;
                    break;
                case 'f': o.fflag = 1; o.iflag = 0; break;
                case 'i': o.iflag = 1; o.fflag = 0; break;
                case 'p': o.pflag = 1; break;
                case 'R': case 'r': o.rflag = 1; break;
                case 'H': o.Hflag = 1; o.Lflag = 0; break;
                case 'L': o.Lflag = 1; break;
                case 'P': o.Hflag = 0; o.Lflag = 0; break;
                case 'v': o.vflag = 1; break;
                default:
                    builtin_error ("unknown flag: -%c", w[i]);
                    builtin_usage ();
                    free (positional.v);
                    return EX_USAGE;
                }
            }
        } else {
            if (bcp_words_add (&positional, w) < 0) {
                free (positional.v);
                return EXECUTION_FAILURE;
            }
        }
    }
    if (positional.n < 2) {
        builtin_error ("missing file operand");
        builtin_usage ();
        free (positional.v);
        return EX_USAGE;
    }
    const char *dest = positional.v[positional.n - 1];
    int nsrc = positional.n - 1;

    /* Is DEST a directory? */
    struct stat dst_st;
    int dst_is_dir = (stat (dest, &dst_st) == 0 && S_ISDIR (dst_st.st_mode));

    if (nsrc > 1 && !dst_is_dir) {
        builtin_error ("target '%s' is not a directory", dest);
        free (positional.v);
        return EXECUTION_FAILURE;
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
        if (bcp_one (src, dst, &o, 1) < 0) rc = EXECUTION_FAILURE;
    }
    free (positional.v);
    return rc;
}

char *cp_doc[] = {
    "Copy files and directories.",
    "",
    "    bashcp [-afipRrv] [-HLP] SOURCE... DEST",
    "",
    "    -a   archive: same as -dpR (clone symlinks as symlinks,",
    "         preserve metadata, recursive)",
    "    -f   force: replace existing dest after the source is opened",
    "    -i   interactive: prompt before overwrite",
    "    -p   preserve mode/owner/group/timestamps",
    "    -R, -r   recursive",
    "    -v   verbose: print each completed copy",
    "    -H   follow symlinks named on the command line",
    "    -L   always follow symlinks",
    "    -P   don't follow symlinks",
    "         (default: clone symlinks as symlinks)",
    (char *)NULL
};

struct builtin bashcp_struct = {
    "bashcp",
    cp_builtin,
    BUILTIN_ENABLED,
    cp_doc,
    "bashcp [-afipRrv] [-HLP] SOURCE... DEST",
    0
};
