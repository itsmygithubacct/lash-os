/* SPDX-License-Identifier: MIT */
/* _git/worktree.h — the working tree: walking it, and comparing it.
 *
 * git's status is two comparisons: HEAD against the index (what is staged),
 * and the index against the files on disk (what is not). A file the index
 * does not know about is untracked, unless an ignore rule covers it.
 *
 * The index records each file's stat data, so an unchanged file is usually
 * recognised without reading it. Only a file whose stat data has moved is
 * hashed to see whether its content really changed.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_WORKTREE_H
#define BASH_OS_GIT_WORKTREE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

#include "config.h"
#include "ignore.h"
#include "index.h"
#include "odb.h"
#include "repo.h"

/* Each file the walk reports, relative to the worktree root. FN returning
   non-zero stops the walk. Directories are reported before their contents,
   and returning 1 from FN for a directory skips it. */
typedef int (*bgit_walk_fn) (void *ctx, const char *path, int is_dir,
                             const struct stat *st);
int bgit_worktree_walk (const bgit_repo *repo, bgit_walk_fn fn, void *ctx);

/* One path's standing in the three places git compares. */
typedef struct {
    char *path;
    int staged;        /* HEAD -> index: 'A', 'M', 'D', or 0 */
    int unstaged;      /* index -> working tree: 'M', 'D', or 0 */
    int untracked;
    int ignored;
    int unmerged;      /* which stages the index holds: bit 1, 2 or 3 */
    char *renamed_from; /* where a staged rename came from, or NULL */
    int score;          /* how alike the two were, on git's 60000 scale */
    uint32_t head_mode, index_mode, worktree_mode, their_mode;
    char head_sha[41];
    char index_sha[41];
    char their_sha[41];   /* stage 3, when the path is unmerged */
} bgit_status_entry;

/* Compare HEAD, the index and the working tree. HEAD_TREE may be NULL for
   an unborn branch. With UNTRACKED_ALL every untracked file is listed;
   otherwise a directory holding only untracked files is listed once, with a
   trailing '/', as git does. WANT_IGNORED adds ignored paths.
   Entries come back sorted by path. */
int bgit_status (const bgit_repo *repo, bgit_odb *odb, const bgit_config *cfg,
                 const bgit_index_entry *index, size_t n_index,
                 const char *head_tree, int untracked_all, int want_ignored,
                 int find_renames, bgit_status_entry **out, size_t *n_out);

void bgit_status_free (bgit_status_entry *entries, size_t n);

/* Every path in the working tree the index does not hold, in path order.
   With DIRECTORY a directory holding none of the index's paths is named
   once, with a trailing '/', instead of what is under it. EXCLUDE applies
   the ignore rules: without it nothing is ignored, and with it an ignored
   path is left out — or is the only kind listed, when ONLY_IGNORED.
   The caller frees the result with bgit_others_free. */
int bgit_worktree_others (const bgit_repo *repo, const bgit_config *cfg,
                          const bgit_index_entry *index, size_t n_index,
                          int directory, int exclude, int only_ignored,
                          char ***out, size_t *n_out);

void bgit_others_free (char **paths, size_t n);

/* The mode git records for a file: 100755 when it is executable, 120000 for
   a symbolic link, 100644 otherwise. */
uint32_t bgit_worktree_mode (const struct stat *st);

/* 1 when the file at PATH still matches ENTRY, by stat data where that is
   conclusive and by content otherwise. */
/* What the submodule at FULL_PATH has checked out. Returns 0 with the id,
   or -1 when there is no repository there — one that was never cloned. */
int bgit_submodule_head (const char *full_path, char out[41]);

/* Whether the submodule at FULL_PATH has changes of its own: tracked ones
   in *CHANGED, untracked ones in *UNTRACKED. Returns 0, or -1 when there
   is no repository there to ask. */
int bgit_submodule_dirt (const char *full_path, int *changed, int *untracked);

int bgit_worktree_matches (bgit_odb *odb, const char *full_path,
                           const bgit_index_entry *entry, const struct stat *st);

#endif /* BASH_OS_GIT_WORKTREE_H */
