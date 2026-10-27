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

typedef struct bmv_link {
    dev_t source_dev, destination_dev;
    ino_t source_ino, destination_ino;
    char *path;
    struct bmv_link *next;
} bmv_link;

typedef struct {
    int fflag, iflag, nflag, Tflag;
    const char *target_dir;
    bmv_link *links, *written;
} bmv_opts;

typedef struct bmv_source {
    dev_t dev;
    ino_t ino;
    mode_t type;
    char *path;
    struct bmv_source *next;
} bmv_source;

typedef struct {
    bmv_source *head, *tail;
} bmv_removals;

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

static int bmv_xdev_copy (const char *src, const char *dst, bmv_opts *o,
                          bmv_removals *removals);

static char *
bmv_join_path (const char *dir, const char *name, size_t name_length)
{
    size_t dir_length = strlen (dir);
    /* These operations use full pathnames. Reject an unsupported length
       before it can name a different entry through silent truncation. */
    if (dir_length > 4094 || name_length > 4094 - dir_length) {
        builtin_error ("path too long while moving into %s", dir);
        return NULL;
    }
    char *path = malloc (dir_length + name_length + 2);
    if (!path) { builtin_error ("out of memory"); return NULL; }
    memcpy (path, dir, dir_length);
    path[dir_length] = '/';
    memcpy (path + dir_length + 1, name, name_length);
    path[dir_length + name_length + 1] = '\0';
    return path;
}

static bmv_link *
bmv_find_link (const bmv_opts *o, const struct stat *src)
{
    for (bmv_link *entry = o->links; entry; entry = entry->next) {
        struct stat dst;
        if (entry->source_dev == src->st_dev && entry->source_ino == src->st_ino &&
            lstat (entry->path, &dst) == 0 &&
            dst.st_dev == entry->destination_dev && dst.st_ino == entry->destination_ino)
            return entry;
    }
    return NULL;
}

static int
bmv_remember_link (bmv_link **head, const struct stat *src, const char *dst)
{
    struct stat st;
    if (lstat (dst, &st) < 0) {
        builtin_error ("stat %s: %s", dst, strerror (errno));
        return -1;
    }
    bmv_link *entry = malloc (sizeof *entry);
    if (!entry) { builtin_error ("out of memory"); return -1; }
    entry->path = strdup (dst);
    if (!entry->path) { free (entry); builtin_error ("out of memory"); return -1; }
    entry->source_dev = src->st_dev;
    entry->source_ino = src->st_ino;
    entry->destination_dev = st.st_dev;
    entry->destination_ino = st.st_ino;
    entry->next = *head;
    *head = entry;
    return 0;
}

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
    if (rc < 0) {
        builtin_error ("copy %s -> %s: %s", src, dst, strerror (errno));
    }
    if (close (sfd) < 0) {
        builtin_error ("close %s: %s", src, strerror (errno));
        rc = -1;
    }
    if (close (dfd) < 0) {
        builtin_error ("close %s: %s", dst, strerror (errno));
        rc = -1;
    }
    if (rc < 0) return -1;
    /* Preserve mode + owner + times across xdev move. */
    if (chown (dst, sst->st_uid, sst->st_gid) < 0 && errno != EPERM) {
        builtin_error ("chown %s: %s", dst, strerror (errno));
        rc = -1;
    }
    /* chown clears set-ID bits; restore the final mode afterwards. */
    if (chmod (dst, sst->st_mode & 07777) < 0) {
        builtin_error ("chmod %s: %s", dst, strerror (errno));
        return -1;
    }
    struct timespec ts[2] = {
        { .tv_sec = sst->st_atim.tv_sec, .tv_nsec = sst->st_atim.tv_nsec },
        { .tv_sec = sst->st_mtim.tv_sec, .tv_nsec = sst->st_mtim.tv_nsec }
    };
    if (utimensat (AT_FDCWD, dst, ts, AT_SYMLINK_NOFOLLOW) < 0) {
        builtin_error ("utimensat %s: %s", dst, strerror (errno));
        rc = -1;
    }
    return rc;
}

static int
bmv_copy_symlink (const char *src, const char *dst, const struct stat *sst)
{
    char target[4096];
    ssize_t n = readlink (src, target, sizeof target - 1);
    if (n < 0) { builtin_error ("readlink %s: %s", src, strerror (errno)); return -1; }
    target[n] = '\0';
    if (unlink (dst) < 0 && errno != ENOENT) {
        builtin_error ("unlink %s: %s", dst, strerror (errno));
        return -1;
    }
    if (symlink (target, dst) < 0) {
        builtin_error ("symlink %s: %s", dst, strerror (errno));
        return -1;
    }
    if (lchown (dst, sst->st_uid, sst->st_gid) < 0 && errno != EPERM) {
        builtin_error ("lchown %s: %s", dst, strerror (errno));
        return -1;
    }
    struct timespec ts[2] = { sst->st_atim, sst->st_mtim };
    if (utimensat (AT_FDCWD, dst, ts, AT_SYMLINK_NOFOLLOW) < 0) {
        builtin_error ("utimensat %s: %s", dst, strerror (errno));
        return -1;
    }
    return 0;
}

static int
bmv_copy_dir (const char *src, const char *dst, const struct stat *sst, bmv_opts *o,
              bmv_removals *removals)
{
    if (mkdir (dst, sst->st_mode & 0777) < 0) {
        /* Match rename's directory replacement rules: only an empty
           directory may be replaced. Never merge and delete source entries
           into an existing tree after rename reports EXDEV. */
        if (errno != EEXIST || rmdir (dst) < 0 ||
            mkdir (dst, sst->st_mode & 0777) < 0) {
            builtin_error ("cannot replace directory %s: %s", dst, strerror (errno));
            return -1;
        }
    }
    /* The caller's umask may have removed all owner access. Populate the
       new directory before restoring the source's final permissions. */
    if (chmod (dst, (sst->st_mode & 0777) | S_IRWXU) < 0) {
        builtin_error ("chmod %s: %s", dst, strerror (errno));
        return -1;
    }
    DIR *d = opendir (src);
    int rc = 0;
    if (!d) {
        builtin_error ("opendir %s: %s", src, strerror (errno));
        rc = -1;
        goto restore_metadata;
    }
    struct dirent *de;
    for (;;) {
        errno = 0;
        de = readdir (d);
        if (!de) {
            if (errno) {
                builtin_error ("readdir %s: %s", src, strerror (errno));
                rc = -1;
            }
            break;
        }
        if (!strcmp (de->d_name, ".") || !strcmp (de->d_name, "..")) continue;
        size_t length = strlen (de->d_name);
        char *sc = bmv_join_path (src, de->d_name, length);
        char *dc = sc ? bmv_join_path (dst, de->d_name, length) : NULL;
        if (!sc || !dc || bmv_xdev_copy (sc, dc, o, removals) < 0) rc = -1;
        free (sc);
        free (dc);
        if (rc < 0) break;
    }
    if (closedir (d) < 0) {
        builtin_error ("closedir %s: %s", src, strerror (errno));
        rc = -1;
    }
restore_metadata:
    if (chown (dst, sst->st_uid, sst->st_gid) < 0 && errno != EPERM) {
        builtin_error ("chown %s: %s", dst, strerror (errno));
        rc = -1;
    }
    if (chmod (dst, sst->st_mode & 07777) < 0) {
        builtin_error ("chmod %s: %s", dst, strerror (errno));
        rc = -1;
    }
    struct timespec ts[2] = {
        { .tv_sec = sst->st_atim.tv_sec, .tv_nsec = sst->st_atim.tv_nsec },
        { .tv_sec = sst->st_mtim.tv_sec, .tv_nsec = sst->st_mtim.tv_nsec }
    };
    if (utimensat (AT_FDCWD, dst, ts, AT_SYMLINK_NOFOLLOW) < 0) {
        builtin_error ("utimensat %s: %s", dst, strerror (errno));
        rc = -1;
    }
    return rc;
}

/* Record copied sources in postorder. No source is removed until the entire
   operand, including directory metadata, has been copied successfully. */
static int
bmv_xdev_copy (const char *src, const char *dst, bmv_opts *o,
               bmv_removals *removals)
{
    struct stat sst;
    if (lstat (src, &sst) < 0) {
        builtin_error ("stat %s: %s", src, strerror (errno));
        return -1;
    }
    int rc;
    /* Earlier source names have already been unlinked, so even nlink == 1
       can be the last member of a group remembered by this invocation. */
    bmv_link *entry = S_ISDIR (sst.st_mode) ? NULL : bmv_find_link (o, &sst);
    if (entry) {
        struct stat ds;
        if (lstat (dst, &ds) == 0 &&
            ds.st_dev == entry->destination_dev && ds.st_ino == entry->destination_ino)
            rc = 0;
        else {
            if (unlink (dst) < 0 && errno != ENOENT) {
                builtin_error ("unlink %s: %s", dst, strerror (errno));
                return -1;
            }
            rc = linkat (AT_FDCWD, entry->path, AT_FDCWD, dst, 0);
            if (rc < 0) builtin_error ("link %s -> %s: %s", entry->path, dst, strerror (errno));
        }
    }
    else if (S_ISLNK (sst.st_mode)) rc = bmv_copy_symlink (src, dst, &sst);
    else if (S_ISDIR (sst.st_mode)) rc = bmv_copy_dir (src, dst, &sst, o, removals);
    else if (S_ISREG (sst.st_mode)) rc = bmv_copy_regular (src, dst, &sst);
    else {
        builtin_error ("%s: unsupported file type", src);
        return -1;
    }
    if (rc < 0) return -1;
    if (!entry && !S_ISDIR (sst.st_mode) && sst.st_nlink > 1 &&
        bmv_remember_link (&o->links, &sst, dst) < 0) return -1;
    bmv_source *source = malloc (sizeof *source);
    if (!source) { builtin_error ("out of memory"); return -1; }
    source->path = strdup (src);
    if (!source->path) { free (source); builtin_error ("out of memory"); return -1; }
    source->dev = sst.st_dev;
    source->ino = sst.st_ino;
    source->type = sst.st_mode & S_IFMT;
    source->next = NULL;
    if (removals->tail) removals->tail->next = source;
    else removals->head = source;
    removals->tail = source;
    return 0;
}

static int
bmv_xdev_move (const char *src, const char *dst, bmv_opts *o)
{
    bmv_removals removals = {0};
    bmv_link *old_links = o->links;
    int rc = bmv_xdev_copy (src, dst, o, &removals);
    if (rc < 0) {
        /* A failed copy must not supply hard-link destinations for a later
           operand, whose source may still need its data or metadata copied. */
        while (o->links != old_links) {
            bmv_link *entry = o->links;
            o->links = entry->next;
            free (entry->path);
            free (entry);
        }
    } else {
        /* Remove only the recorded entries. A fresh recursive traversal could
           delete newly created files that were never copied. Check identity
           as well, so a replaced source is not removed in place of the copy. */
        for (bmv_source *source = removals.head; source; source = source->next) {
            struct stat st;
            if (lstat (source->path, &st) < 0) {
                builtin_error ("stat %s: %s", source->path, strerror (errno));
                rc = -1;
                break;
            }
            if (st.st_dev != source->dev || st.st_ino != source->ino ||
                (st.st_mode & S_IFMT) != source->type) {
                builtin_error ("source changed while moving %s", source->path);
                rc = -1;
                break;
            }
            if ((S_ISDIR (st.st_mode) ? rmdir (source->path) : unlink (source->path)) < 0) {
                builtin_error ("remove %s: %s", source->path, strerror (errno));
                rc = -1;
                break;
            }
        }
    }
    while (removals.head) {
        bmv_source *source = removals.head;
        removals.head = source->next;
        free (source->path);
        free (source);
    }
    return rc;
}

static int
bmv_one (const char *src, const char *dst, bmv_opts *o)
{
    /* A skip still requires a valid source. Diagnose missing operands before
       no-clobber or an interactive refusal can hide the source error. */
    struct stat src_st;
    if (lstat (src, &src_st) < 0) {
        builtin_error ("stat %s: %s", src, strerror (errno));
        return -1;
    }
    /* Existence check on dst with -i / -n / -f. */
    struct stat dst_st;
    int dst_exists = (lstat (dst, &dst_st) == 0);
    if (dst_exists) {
        if (o->nflag) return 1;  /* skipped, not a new destination */
        if (o->iflag && !o->fflag) {
            fprintf (stderr, "bashmv: overwrite '%s'? ", dst);
            fflush (stderr);
            int c = getchar (), answer = c;
            while (c != EOF && c != '\n') c = getchar ();
            /* A declined interactive move is a failure, including EOF.
               The operand loop still continues with later sources. */
            if (answer != 'y' && answer != 'Y') return -1;
        }
        for (bmv_link *entry = o->written; entry; entry = entry->next) {
            /* GNU mv permits replacing a just-moved empty directory. */
            if (!S_ISDIR (dst_st.st_mode) && !strcmp (entry->path, dst) &&
                dst_st.st_dev == entry->destination_dev &&
                dst_st.st_ino == entry->destination_ino) {
                builtin_error ("will not overwrite just-moved '%s' with '%s'", dst, src);
                return -1;
            }
        }
    }
    if (dst_exists && src_st.st_dev == dst_st.st_dev && src_st.st_ino == dst_st.st_ino) {
        builtin_error ("'%s' and '%s' are the same file", src, dst);
        return -1;
    }
    /* rename(2) handles same-fs atomically. */
    if (rename (src, dst) == 0) return 0;
    if (errno != EXDEV) {
        builtin_error ("rename %s -> %s: %s", src, dst, strerror (errno));
        return -1;
    }
    /* Cross-device — copy + unlink. */
    return bmv_xdev_move (src, dst, o);
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
        char *dst_buf = NULL;
        const char *dst;
        if (dst_is_dir) {
            const char *end = src + strlen (src);
            while (end > src && end[-1] == '/') end--;
            const char *base = end;
            while (base > src && base[-1] != '/') base--;
            dst_buf = bmv_join_path (dest, base, (size_t) (end - base));
            if (!dst_buf) {
                rc = EXECUTION_FAILURE;
                continue;
            }
            dst = dst_buf;
        } else {
            dst = dest;
        }
        int moved = bmv_one (src, dst, &o);
        if (moved < 0) rc = EXECUTION_FAILURE;
        else if (moved == 0) {
            struct stat st;
            if (lstat (dst, &st) < 0) {
                builtin_error ("stat %s: %s", dst, strerror (errno));
                rc = EXECUTION_FAILURE;
                free (dst_buf);
                break;
            }
            if (bmv_remember_link (&o.written, &st, dst) < 0) {
                /* Stop rather than continue without collision protection. */
                rc = EXECUTION_FAILURE;
                free (dst_buf);
                break;
            }
        }
        free (dst_buf);
    }
    free (positional.v);
    while (o.links) {
        bmv_link *next = o.links->next;
        free (o.links->path);
        free (o.links);
        o.links = next;
    }
    while (o.written) {
        bmv_link *next = o.written->next;
        free (o.written->path);
        free (o.written);
        o.written = next;
    }
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
