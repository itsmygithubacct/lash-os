/* bashcp.c — POSIX cp(1) as a bash builtin.
 *
 * Phase S of bash-os POSIX gap-fillers.
 *
 *   bashcp [-afinpRrv] [-HLP] SOURCE... DEST
 *
 *   -a      archive: same as -dpR (preserve symlinks-as-symlinks, preserve
 *           metadata, recursive). Matches GNU coreutils cp -a semantics.
 *   -f      force: remove dest only if opening it for write fails
 *   -i      interactive: prompt before overwrite (refused unless tty)
 *   -p      preserve mode/owner/group/timestamps
 *   -R, -r  recursive
 *   -v      verbose: print each completed copy
 *   -H      follow symlinks given on the command line; preserve nested
 *   -L      always follow symlinks
 *   -P      don't follow symlinks
 *           (default: follow unless recursive)
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

typedef struct bcp_link {
    dev_t source_dev, destination_dev;
    ino_t source_ino, destination_ino;
    char *path;
    int follow;
    struct bcp_link *next;
} bcp_link;

typedef struct bcp_dir {
    dev_t source_dev, destination_dev;
    ino_t source_ino, destination_ino;
    struct bcp_dir *parent;
} bcp_dir;

typedef struct {
    int fflag, iflag, nflag, pflag, rflag, vflag;
    int Hflag, Lflag, Pflag, aflag;
    bcp_link *links;
    bcp_dir *directories;
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
                    bcp_opts *o, int top_level_source);

static bcp_link *
bcp_find_link (const bcp_opts *o, const struct stat *src)
{
    for (bcp_link *entry = o->links; entry; entry = entry->next) {
        struct stat st;
        if (entry->source_dev == src->st_dev && entry->source_ino == src->st_ino &&
            (entry->follow ? stat (entry->path, &st) : lstat (entry->path, &st)) == 0 &&
            st.st_dev == entry->destination_dev && st.st_ino == entry->destination_ino)
            return entry;
    }
    return NULL;
}

static int
bcp_remember_link (bcp_opts *o, const struct stat *src, const char *dst)
{
    struct stat st;
    int follow = S_ISREG (src->st_mode);
    if ((follow ? stat (dst, &st) : lstat (dst, &st)) < 0) {
        builtin_error ("stat %s: %s", dst, strerror (errno));
        return -1;
    }
    bcp_link *entry = malloc (sizeof *entry);
    if (!entry) { builtin_error ("out of memory"); return -1; }
    entry->path = strdup (dst);
    if (!entry->path) { free (entry); builtin_error ("out of memory"); return -1; }
    entry->source_dev = src->st_dev;
    entry->source_ino = src->st_ino;
    entry->destination_dev = st.st_dev;
    entry->destination_ino = st.st_ino;
    entry->follow = follow;
    entry->next = o->links;
    o->links = entry;
    return 0;
}

static int
bcp_copy_link (const char *src, const char *dst, const struct stat *sst,
               const bcp_link *entry, const bcp_opts *o)
{
    struct stat st;
    if (lstat (dst, &st) == 0) {
        if (o->nflag) return 1;
        if (st.st_dev == sst->st_dev && st.st_ino == sst->st_ino) {
            builtin_error ("'%s' and '%s' are the same file", src, dst);
            return -1;
        }
        if (st.st_dev == entry->destination_dev && st.st_ino == entry->destination_ino)
            return 0;
        if (o->iflag) {
            fprintf (stderr, "bashcp: overwrite '%s'? ", dst);
            fflush (stderr);
            int c = getchar (), answer = c;
            while (c != EOF && c != '\n') c = getchar ();
            if (answer != 'y' && answer != 'Y') return -1;
        }
        if (unlink (dst) < 0) {
            builtin_error ("unlink %s: %s", dst, strerror (errno));
            return -1;
        }
    } else if (errno != ENOENT) {
        builtin_error ("stat %s: %s", dst, strerror (errno));
        return -1;
    }
    if (linkat (AT_FDCWD, entry->path, AT_FDCWD, dst,
                entry->follow ? AT_SYMLINK_FOLLOW : 0) < 0) {
        if (o->nflag && errno == EEXIST) return 1;
        builtin_error ("link %s -> %s: %s", entry->path, dst, strerror (errno));
        return -1;
    }
    if (o->vflag) printf ("'%s' -> '%s'\n", src, dst);
    return 0;
}

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
    int rc = 0;
    /* chown can clear set-ID bits, so apply the final mode afterwards. */
    if (chown (dst, st->st_uid, st->st_gid) < 0) {
        if (errno != EPERM) {
            builtin_error ("chown %s: %s", dst, strerror (errno));
            rc = -1;
        }
    }
    if (chmod (dst, st->st_mode & 07777) < 0) {
        builtin_error ("chmod %s: %s", dst, strerror (errno));
        rc = -1;
    }
    struct timespec ts[2];
    ts[0].tv_sec  = st->st_atim.tv_sec;
    ts[0].tv_nsec = st->st_atim.tv_nsec;
    ts[1].tv_sec  = st->st_mtim.tv_sec;
    ts[1].tv_nsec = st->st_mtim.tv_nsec;
    /* Regular-file copies follow destination symlinks, just like chown and
       chmod above. Symlink copies use their own metadata path. */
    if (utimensat (AT_FDCWD, dst, ts, 0) < 0) {
        if (errno == ENOSYS) {
            /* Fall back only when the kernel lacks utimensat, not on I/O
               errors from a supported operation. */
            struct timeval tv[2];
            tv[0].tv_sec = ts[0].tv_sec; tv[0].tv_usec = ts[0].tv_nsec / 1000;
            tv[1].tv_sec = ts[1].tv_sec; tv[1].tv_usec = ts[1].tv_nsec / 1000;
            if (utimes (dst, tv) == 0) return rc;
        }
        builtin_error ("preserve times %s: %s", dst, strerror (errno));
        rc = -1;
    }
    return rc;
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
        if (o->nflag) return 1;
        /* Refuse identical-inode (cp file file). */
        if (dst_st.st_dev == sst->st_dev && dst_st.st_ino == sst->st_ino) {
            builtin_error ("'%s' and '%s' are the same file", src, dst);
            return -1;
        }
        if (o->iflag) {
            fprintf (stderr, "bashcp: overwrite '%s'? ", dst);
            fflush (stderr);
            int c = getchar (), answer = c;
            while (c != EOF && c != '\n') c = getchar ();
            if (answer != 'y' && answer != 'Y') return -1;
        }
        if (S_ISLNK (dst_st.st_mode)) {
            struct stat target_st;
            if (stat (dst, &target_st) < 0) {
                builtin_error ("stat destination %s: %s", dst, strerror (errno));
                return -1;
            }
            if (target_st.st_dev == sst->st_dev && target_st.st_ino == sst->st_ino) {
                builtin_error ("'%s' and '%s' are the same file", src, dst);
                return -1;
            }
            if (S_ISDIR (target_st.st_mode)) {
                builtin_error ("%s: existing destination symlink target is a directory", dst);
                return -1;
            }
        } else if (S_ISDIR (dst_st.st_mode)) {
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
    if (dst_exists &&
        o->aflag && S_ISREG (dst_st.st_mode) && dst_st.st_nlink > 1) {
        if (unlink (dst) < 0 && errno != ENOENT) {
            builtin_error ("unlink %s: %s", dst, strerror (errno));
            close (sfd);
            return -1;
        }
    }
    /* Open without truncating: dst may be a symlink back to src, and the
       lstat check above compares the link's inode rather than its target. */
    int dfd = open (dst, O_WRONLY | O_CREAT | (o->nflag ? O_EXCL : 0), sst->st_mode & 0777);
    /* -f is a retry after a failed write-open, not unconditional removal.
       Keep openable symlinks, hardlinks and destination modes intact. The
       source is already open and same-file checks precede any unlink. */
    if (dfd < 0 && o->fflag && !o->nflag && dst_exists) {
        if (unlink (dst) < 0) {
            builtin_error ("unlink %s: %s", dst, strerror (errno));
            close (sfd);
            return -1;
        }
        dfd = open (dst, O_WRONLY | O_CREAT | O_EXCL, sst->st_mode & 0777);
    }
    if (dfd < 0) {
        if (o->nflag && errno == EEXIST) { close (sfd); return 1; }
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
    if (close (sfd) < 0) {
        builtin_error ("close %s: %s", src, strerror (errno));
        rc = -1;
    }
    if (close (dfd) < 0) {
        builtin_error ("close %s: %s", dst, strerror (errno));
        rc = -1;
    }
    if (rc < 0) return -1;
    if (o->pflag && dst_regular && bcp_apply_metadata (dst, sst) < 0) return -1;
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
    /* Replace existing entries. Use symlink-to-temp + rename so the
       replacement is atomic (no window where dst doesn't exist). */
    struct stat ds;
    int dst_exists = (lstat (dst, &ds) == 0);
    if (dst_exists && o->nflag) return 1;
    if (dst_exists && ds.st_dev == sst->st_dev && ds.st_ino == sst->st_ino) {
        builtin_error ("'%s' and '%s' are the same file", src, dst);
        return -1;
    }
    if (dst_exists && o->iflag) {
        fprintf (stderr, "bashcp: overwrite '%s'? ", dst);
        fflush (stderr);
        int c = getchar (), answer = c;
        while (c != EOF && c != '\n') c = getchar ();
        if (answer != 'y' && answer != 'Y') return -1;
    }
    if (dst_exists) {
        char tmp_path[4096 + 32];
        int wlen = snprintf (tmp_path, sizeof tmp_path,
                             "%s.bcptmp.XXXXXX", dst);
        if (wlen < 0 || (size_t) wlen + sizeof "/link" > sizeof tmp_path) {
            builtin_error ("symlink %s: dst path too long for atomic replace", dst);
            return -1;
        }
        /* Reserve a private directory atomically. A predictable temporary
           name must never unlink an unrelated entry beside the destination. */
        if (!mkdtemp (tmp_path)) {
            builtin_error ("temporary directory for %s: %s", dst, strerror (errno));
            return -1;
        }
        size_t dirlen = strlen (tmp_path);
        memcpy (tmp_path + dirlen, "/link", sizeof "/link");
        int failed = 0;
        if (symlink (target, tmp_path) < 0) {
            builtin_error ("symlink %s -> %s: %s", tmp_path, target, strerror (errno));
            failed = 1;
        } else if (rename (tmp_path, dst) < 0) {
            builtin_error ("rename %s -> %s: %s", tmp_path, dst, strerror (errno));
            unlink (tmp_path);
            failed = 1;
        }
        tmp_path[dirlen] = '\0';
        if (rmdir (tmp_path) < 0) {
            builtin_error ("rmdir %s: %s", tmp_path, strerror (errno));
            failed = 1;
        }
        if (failed) return -1;
    } else if (symlink (target, dst) < 0) {
        if (o->nflag && errno == EEXIST) return 1;
        builtin_error ("symlink %s -> %s: %s", dst, target, strerror (errno));
        return -1;
    }
    if (o->pflag) {
        /* lchown for symlink owner. */
        if (lchown (dst, sst->st_uid, sst->st_gid) < 0 && errno != EPERM) {
            builtin_error ("lchown %s: %s", dst, strerror (errno));
            return -1;
        }
        struct timespec ts[2] = { sst->st_atim, sst->st_mtim };
        if (utimensat (AT_FDCWD, dst, ts, AT_SYMLINK_NOFOLLOW) < 0) {
            builtin_error ("utimensat %s: %s", dst, strerror (errno));
            return -1;
        }
    }
    if (o->vflag)
        printf ("'%s' -> '%s'\n", src, dst);  /* GNU cp -v writes to stdout */
    return 0;
}

static int
bcp_copy_dir (const char *src, const char *dst, const struct stat *sst,
              bcp_opts *o)
{
    if (!o->rflag) {
        builtin_error ("-r not specified; omitting directory '%s'", src);
        return -1;
    }
    for (const bcp_dir *parent = o->directories; parent; parent = parent->parent) {
        if (sst->st_dev == parent->source_dev && sst->st_ino == parent->source_ino) {
            builtin_error ("%s: cyclic directory traversal", src);
            return -1;
        }
        if (sst->st_dev == parent->destination_dev && sst->st_ino == parent->destination_ino) {
            builtin_error ("cannot copy a directory into itself: %s", src);
            return -1;
        }
    }
    /* mkdir if not present. */
    struct stat ds;
    int created = 0;
    mode_t final_mode = 0;
    int rc = 0;
    if (lstat (dst, &ds) < 0) {
        if (errno != ENOENT) {
            builtin_error ("stat %s: %s", dst, strerror (errno));
            return -1;
        }
        mode_t mask = umask (0);
        umask (mask);
        final_mode = (sst->st_mode & 0777) & ~mask;
        if (mkdir (dst, final_mode | S_IRWXU) < 0) {
            builtin_error ("mkdir %s: %s", dst, strerror (errno));
            return -1;
        }
        created = 1;
        /* Populate read-only trees before applying their final mode. chmod
           also restores owner access when the caller's umask removed it. */
        if (chmod (dst, final_mode | S_IRWXU) < 0) {
            builtin_error ("chmod %s: %s", dst, strerror (errno));
            rc = -1;
            goto restore_mode;
        }
        if (o->vflag)
            printf ("'%s' -> '%s'\n", src, dst);  /* GNU cp -v writes to stdout */
    } else if (!S_ISDIR (ds.st_mode)) {
        builtin_error ("'%s' exists and is not a directory", dst);
        return -1;
    } else if (ds.st_dev == sst->st_dev && ds.st_ino == sst->st_ino) {
        builtin_error ("'%s' and '%s' are the same file", src, dst);
        return -1;
    }
    if (created && lstat (dst, &ds) < 0) {
        builtin_error ("stat %s: %s", dst, strerror (errno));
        rc = -1;
        goto restore_mode;
    }
    DIR *dir = opendir (src);
    if (!dir) {
        builtin_error ("opendir %s: %s", src, strerror (errno));
        rc = -1;
        goto restore_mode;
    }
    bcp_dir current = { sst->st_dev, ds.st_dev, sst->st_ino, ds.st_ino,
                        o->directories };
    o->directories = &current;
    struct dirent *de;
    for (;;) {
        errno = 0;
        de = readdir (dir);
        if (!de) {
            if (errno) {
                builtin_error ("readdir %s: %s", src, strerror (errno));
                rc = -1;
            }
            break;
        }
        if (strcmp (de->d_name, ".") == 0 || strcmp (de->d_name, "..") == 0)
            continue;
        size_t sn = strlen (src) + strlen (de->d_name) + 2;
        size_t dn = strlen (dst) + strlen (de->d_name) + 2;
        if (sn > 4096 || dn > 4096) {
            builtin_error ("path too long while copying %s", de->d_name);
            rc = -1;
            continue;
        }
        /* Keep long paths off each recursive stack frame. */
        char *src_child = malloc (sn), *dst_child = malloc (dn);
        if (!src_child || !dst_child) {
            builtin_error ("out of memory");
            free (src_child);
            free (dst_child);
            rc = -1;
            break;
        }
        snprintf (src_child, sn, "%s/%s", src, de->d_name);
        snprintf (dst_child, dn, "%s/%s", dst, de->d_name);
        if (bcp_one (src_child, dst_child, o, 0) < 0) rc = -1;
        free (src_child);
        free (dst_child);
    }
    o->directories = current.parent;
    if (closedir (dir) < 0) {
        builtin_error ("closedir %s: %s", src, strerror (errno));
        rc = -1;
    }
restore_mode:
    if (created && chmod (dst, final_mode) < 0) {
        builtin_error ("chmod %s: %s", dst, strerror (errno));
        rc = -1;
    }
    if (o->pflag && bcp_apply_metadata (dst, sst) < 0) rc = -1;
    return rc;
}

/* Top-level dispatcher per source. dst must be a complete target path
   (file or directory entry name); caller resolves dir-into. */
static int
bcp_one (const char *src, const char *dst, bcp_opts *o, int top_level_source)
{
    struct stat sst;
    int follow = o->Lflag || (top_level_source && o->Hflag)
                 || (!o->rflag && !o->Pflag);
    int rc;
    if (follow) rc = stat (src, &sst);
    else        rc = lstat (src, &sst);
    if (rc < 0) {
        builtin_error ("stat %s: %s", src, strerror (errno));
        return -1;
    }
    if (S_ISDIR (sst.st_mode))    return bcp_copy_dir     (src, dst, &sst, o);
    if (S_ISREG (sst.st_mode) || S_ISLNK (sst.st_mode)) {
        /* -n skips existing entries before same-file checks or link tracking.
           GNU still diagnoses a dangling destination when copying regular
           data through it. Directories continue to merge. */
        struct stat dst_st;
        if (o->nflag && lstat (dst, &dst_st) == 0) {
            struct stat target;
            if (S_ISREG (sst.st_mode) && S_ISLNK (dst_st.st_mode) && stat (dst, &target) < 0) {
                builtin_error ("not writing through dangling symlink '%s'", dst);
                return -1;
            }
            return 0;
        }
        /* A later operand must not overwrite a result from this invocation:
           it may already be the backing file for preserved hard links. */
        for (bcp_link **slot = &o->links; *slot;) {
            bcp_link *written = *slot;
            if (!strcmp (written->path, dst) &&
                (written->source_dev != sst.st_dev || written->source_ino != sst.st_ino)) {
                if (top_level_source) {
                    builtin_error ("will not overwrite just-copied '%s' with '%s'", dst, src);
                    return -1;
                }
                /* Directory operands may merge. This path will no longer
                   represent the cached source after its contents change. */
                *slot = written->next;
                free (written->path);
                free (written);
            } else {
                slot = &written->next;
            }
        }
        /* Scope link tracking to this invocation, including multiple source
           operands. Dereferencing may expose aliases whose link count is 1. */
        int preserve_link = o->aflag && (sst.st_nlink > 1 || o->Hflag || o->Lflag);
        bcp_link *entry = preserve_link ? bcp_find_link (o, &sst) : NULL;
        if (entry) rc = bcp_copy_link (src, dst, &sst, entry, o);
        else rc = S_ISLNK (sst.st_mode) ? bcp_copy_symlink (src, dst, &sst, o)
                                  : bcp_copy_regular (src, dst, &sst, o);
        if (rc == 0 && (preserve_link || top_level_source))
            rc = bcp_remember_link (o, &sst, dst);
        return rc;
    }
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
        if (!strcmp (w, "--no-clobber")) { o.nflag = 1; o.iflag = 0; continue; }
        if (!strcmp (w, "--interactive")) { o.iflag = 1; o.nflag = 0; continue; }
        if (!strcmp (w, "--force")) { o.fflag = 1; continue; }
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
                    /* Archive: -dpR. Reset earlier dereference flags;
                       later -H/-L/-P may select a different symlink mode. */
                    o.pflag = 1;
                    o.aflag = 1;
                    o.rflag = 1;
                    o.Hflag = 0;
                    o.Lflag = 0;
                    o.Pflag = 1;
                    break;
                case 'f': o.fflag = 1; break;
                case 'i': o.iflag = 1; o.nflag = 0; break;
                case 'n': o.nflag = 1; o.iflag = 0; break;
                case 'p': o.pflag = 1; break;
                case 'R': case 'r': o.rflag = 1; break;
                case 'H': o.Hflag = 1; o.Lflag = 0; o.Pflag = 0; break;
                case 'L': o.Lflag = 1; o.Hflag = 0; o.Pflag = 0; break;
                case 'P': o.Hflag = 0; o.Lflag = 0; o.Pflag = 1; break;
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
            /* A trailing slash affects source symlink resolution, but is
               not an empty basename. Keep src intact for stat/open. */
            size_t end = strlen (src);
            while (end > 1 && src[end - 1] == '/') end--;
            size_t start = end;
            while (start > 0 && src[start - 1] != '/') start--;
            int len = snprintf (dst_buf, sizeof dst_buf, "%s/%.*s", dest,
                                (int) (end - start), src + start);
            if (len < 0 || (size_t) len >= sizeof dst_buf) {
                builtin_error ("destination path too long: %s", dest);
                rc = EXECUTION_FAILURE;
                continue;
            }
            dst = dst_buf;
        } else {
            dst = dest;
        }
        if (bcp_one (src, dst, &o, 1) < 0) rc = EXECUTION_FAILURE;
    }
    free (positional.v);
    while (o.links) {
        bcp_link *next = o.links->next;
        free (o.links->path);
        free (o.links);
        o.links = next;
    }
    return rc;
}

char *cp_doc[] = {
    "Copy files and directories.",
    "",
    "    bashcp [-afinpRrv] [-HLP] SOURCE... DEST",
    "",
    "    -a   archive: same as -dpR (clone symlinks as symlinks,",
    "         preserve hard links and metadata, recursive)",
    "    -f   force: remove dest only if opening it for write fails",
    "    -i   interactive: prompt before overwrite",
    "    -n, --no-clobber   skip existing destinations; last -i/-n wins",
    "    -p   preserve mode/owner/group/timestamps",
    "    -R, -r   recursive",
    "    -v   verbose: print each completed copy",
    "    -H   follow symlinks named on the command line",
    "    -L   always follow symlinks",
    "    -P   don't follow symlinks",
    "         (default: follow unless recursive)",
    (char *)NULL
};

struct builtin bashcp_struct = {
    "bashcp",
    cp_builtin,
    BUILTIN_ENABLED,
    cp_doc,
    "bashcp [-afinpRrv] [-HLP] SOURCE... DEST",
    0
};
