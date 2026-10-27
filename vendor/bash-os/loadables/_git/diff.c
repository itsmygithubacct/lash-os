/* SPDX-License-Identifier: MIT */
/* _git/diff.c — what changed between two trees, or a tree and the index or
 * working tree. See diff.h.
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
#include <sys/stat.h>

#include "loadables.h"

#include "diff.h"
#include "index.h"
#include "odb.h"
#include "repo.h"
#include "tree.h"
#include "worktree.h"

struct bgit_diff_build {
    bgit_diff_entry *entries;
    size_t n, cap;
};

static int
bgit_diff_push (struct bgit_diff_build *build, const char *path, char status,
                uint32_t old_mode, const char *old_sha,
                uint32_t new_mode, const char *new_sha)
{
    if (build->n == build->cap) {
        size_t next = build->cap ? build->cap * 2 : 32;
        bgit_diff_entry *grown = realloc (build->entries, next * sizeof *grown);
        if (!grown) return -1;
        build->entries = grown;
        build->cap = next;
    }
    bgit_diff_entry *entry = &build->entries[build->n];
    memset (entry, 0, sizeof *entry);
    entry->path = strdup (path);
    if (!entry->path) return -1;
    entry->status = status;
    entry->old_mode = old_mode;
    entry->new_mode = new_mode;
    if (old_sha) snprintf (entry->old_sha, sizeof entry->old_sha, "%s", old_sha);
    if (new_sha) snprintf (entry->new_sha, sizeof entry->new_sha, "%s", new_sha);
    build->n++;
    return 0;
}

static int
bgit_diff_cmp (const void *a, const void *b)
{
    return strcmp (((const bgit_diff_entry *) a)->path,
                   ((const bgit_diff_entry *) b)->path);
}

/* Compare two sorted path lists. */
int
bgit_diff_entries (const bgit_index_entry *old, size_t n_old,
                 const bgit_index_entry *new_entries, size_t n_new,
                 bgit_diff_entry **out, size_t *n_out)
{
    struct bgit_diff_build build;
    memset (&build, 0, sizeof build);
    size_t i = 0, j = 0;
    while (i < n_old || j < n_new) {
        int order;
        if (i >= n_old) order = 1;
        else if (j >= n_new) order = -1;
        else order = strcmp (old[i].path, new_entries[j].path);
        char old_hex[41], new_hex[41];
        if (order < 0) {
            bgit_sha_to_hex (old[i].sha, old_hex);
            if (bgit_diff_push (&build, old[i].path, 'D', old[i].mode, old_hex,
                                0, NULL) < 0)
                goto oom;
            i++;
        } else if (order > 0) {
            bgit_sha_to_hex (new_entries[j].sha, new_hex);
            if (bgit_diff_push (&build, new_entries[j].path, 'A', 0, NULL,
                                new_entries[j].mode, new_hex) < 0)
                goto oom;
            j++;
        } else {
            if (memcmp (old[i].sha, new_entries[j].sha, 20) != 0 ||
                old[i].mode != new_entries[j].mode) {
                bgit_sha_to_hex (old[i].sha, old_hex);
                bgit_sha_to_hex (new_entries[j].sha, new_hex);
                if (bgit_diff_push (&build, old[i].path, 'M', old[i].mode,
                                    old_hex, new_entries[j].mode, new_hex) < 0)
                    goto oom;
            }
            i++; j++;
        }
    }
    if (build.n > 1)
        qsort (build.entries, build.n, sizeof *build.entries, bgit_diff_cmp);
    *out = build.entries;
    *n_out = build.n;
    return 0;
oom:
    bgit_diff_free (build.entries, build.n);
    return -1;
}

int
bgit_diff_trees (bgit_odb *odb, const char *old_tree, const char *new_tree,
                 bgit_diff_entry **out, size_t *n_out)
{
    bgit_index_entry *old = NULL, *new_entries = NULL;
    size_t n_old = 0, n_new = 0;
    if (old_tree && bgit_read_tree (odb, old_tree, &old, &n_old) < 0) return -1;
    if (new_tree && bgit_read_tree (odb, new_tree, &new_entries, &n_new) < 0) {
        bgit_index_free_entries (old, n_old);
        return -1;
    }
    int rc = bgit_diff_entries (old, n_old, new_entries, n_new, out, n_out);
    bgit_index_free_entries (old, n_old);
    bgit_index_free_entries (new_entries, n_new);
    return rc;
}

int
bgit_diff_tree_index (bgit_odb *odb, const char *tree,
                      const bgit_index_entry *index, size_t n_index,
                      bgit_diff_entry **out, size_t *n_out)
{
    bgit_index_entry *old = NULL;
    size_t n_old = 0;
    if (tree && bgit_read_tree (odb, tree, &old, &n_old) < 0) return -1;
    int rc = bgit_diff_entries (old, n_old, index, n_index, out, n_out);
    bgit_index_free_entries (old, n_old);
    return rc;
}

int
bgit_diff_index_worktree (const bgit_repo *repo, bgit_odb *odb,
                          const bgit_index_entry *index, size_t n_index,
                          bgit_diff_entry **out, size_t *n_out)
{
    struct bgit_diff_build build;
    memset (&build, 0, sizeof build);
    for (size_t i = 0; i < n_index; i++) {
        char full[4096];
        if (snprintf (full, sizeof full, "%s/%s", repo->work_tree,
                      index[i].path) >= (int) sizeof full)
            continue;
        char old_hex[41];
        bgit_sha_to_hex (index[i].sha, old_hex);
        struct stat st;
        if (lstat (full, &st) < 0) {
            if (bgit_diff_push (&build, index[i].path, 'D', index[i].mode,
                                old_hex, 0, NULL) < 0)
                goto oom;
            continue;
        }
        if (bgit_worktree_matches (odb, full, &index[i], &st)) continue;
        /* A submodule differs by what it has checked out, and is named by
           that rather than by anything read out of the directory. */
        if (index[i].mode == 0160000) {
            char head[41] = "";
            if (bgit_submodule_head (full, head) == 0 &&
                bgit_diff_push (&build, index[i].path, 'M', 0160000, old_hex,
                                0160000, head) < 0)
                goto oom;
            continue;
        }
        /* The file differs: name it by the id its content has now. */
        unsigned char *content = NULL;
        size_t len = 0;
        char new_hex[41] = "";
        uint32_t mode = bgit_worktree_mode (&st);
        if (S_ISLNK (st.st_mode)) {
            char target[4096];
            ssize_t got = readlink (full, target, sizeof target);
            if (got >= 0) {
                content = malloc ((size_t) got);
                if (content) { memcpy (content, target, (size_t) got); len = (size_t) got; }
            }
        } else if (bgit_slurp_file (full, &content, &len) < 0) {
            content = NULL;
        }
        if (content) {
            bgit_write_object (NULL, "blob", content, len, 0, new_hex);
            free (content);
        }
        if (bgit_diff_push (&build, index[i].path, 'M', index[i].mode, old_hex,
                            mode, new_hex[0] ? new_hex : NULL) < 0)
            goto oom;
    }
    if (build.n > 1)
        qsort (build.entries, build.n, sizeof *build.entries, bgit_diff_cmp);
    *out = build.entries;
    *n_out = build.n;
    return 0;
oom:
    bgit_diff_free (build.entries, build.n);
    return -1;
}

void
bgit_diff_free (bgit_diff_entry *entries, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        free (entries[i].path);
        free (entries[i].from);
    }
    free (entries);
}

int
bgit_worktree_entries (const bgit_repo *repo, bgit_odb *odb,
                       const char *objects_dir,
                       const bgit_index_entry *index, size_t n_index,
                       bgit_index_entry **out, size_t *n_out)
{
    bgit_index_entry *entries = calloc (n_index ? n_index : 1, sizeof *entries);
    if (!entries) return -1;
    size_t n = 0;
    for (size_t i = 0; i < n_index; i++) {
        char full[4096];
        if (snprintf (full, sizeof full, "%s/%s", repo->work_tree,
                      index[i].path) >= (int) sizeof full)
            continue;
        struct stat st;
        if (lstat (full, &st) < 0) continue;      /* deleted: not in the tree */
        bgit_index_entry *entry = &entries[n];
        memset (entry, 0, sizeof *entry);
        entry->path = strdup (index[i].path);
        if (!entry->path) { bgit_index_free_entries (entries, n); return -1; }
        entry->mode = bgit_worktree_mode (&st);
        memcpy (entry->sha, index[i].sha, 20);
        /* A submodule's own HEAD stands for its content: there is nothing
           there to read, and reading it would be reading a directory. */
        if (index[i].mode == 0160000) {
            char head[41];
            entry->mode = 0160000;
            if (bgit_submodule_head (full, head) == 0)
                bgit_hex_to_sha (head, entry->sha);
            n++;
            continue;
        }
        if (!bgit_worktree_matches (odb, full, &index[i], &st)) {
            unsigned char *content = NULL;
            size_t len = 0;
            char hex[41] = "";
            if (S_ISLNK (st.st_mode)) {
                char target[4096];
                ssize_t got = readlink (full, target, sizeof target);
                if (got >= 0) {
                    content = malloc ((size_t) got);
                    if (content) { memcpy (content, target, (size_t) got); len = (size_t) got; }
                }
            } else {
                bgit_slurp_file (full, &content, &len);
            }
            if (content) {
                if (bgit_write_object (objects_dir, "blob", content, len,
                                       objects_dir != NULL, hex) == 0)
                    bgit_hex_to_sha (hex, entry->sha);
                free (content);
            }
        }
        n++;
    }
    *out = entries;
    *n_out = n;
    return 0;
}
