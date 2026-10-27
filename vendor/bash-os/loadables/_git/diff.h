/* SPDX-License-Identifier: MIT */
/* _git/diff.h — what changed between two trees, or a tree and the index or
 * working tree.
 *
 * This is the name-level comparison: which paths were added, deleted or
 * modified, and with what modes and ids. The line-level diff that turns one
 * of these into a patch is separate.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_DIFF_H
#define BASH_OS_GIT_DIFF_H

#include <stddef.h>
#include <stdint.h>

#include "index.h"
#include "odb.h"
#include "repo.h"

typedef struct {
    char *path;
    char status;         /* 'A', 'D', 'M' or 'R' */
    uint32_t old_mode, new_mode;
    char old_sha[41];
    char new_sha[41];
    char *from;          /* where a rename came from; NULL otherwise */
    int score;           /* how alike the two were, on git's 60000 scale */
} bgit_diff_entry;

/* Compare two trees. Either id may be NULL, meaning an empty tree, so the
   first commit compares against nothing. Entries come back sorted by path. */
int bgit_diff_trees (bgit_odb *odb, const char *old_tree, const char *new_tree,
                     bgit_diff_entry **out, size_t *n_out);

/* Compare a tree with the index: what `git diff --cached` reports. */
int bgit_diff_tree_index (bgit_odb *odb, const char *tree,
                          const bgit_index_entry *index, size_t n_index,
                          bgit_diff_entry **out, size_t *n_out);

/* Compare the index with the files on disk: what `git diff` reports. A file
   whose stat data still matches the index is unchanged and is not read. */
int bgit_diff_index_worktree (const bgit_repo *repo, bgit_odb *odb,
                              const bgit_index_entry *index, size_t n_index,
                              bgit_diff_entry **out, size_t *n_out);

/* Compare two sorted entry lists directly, for callers that have built
   their own — a tree read into entries, say, against the working tree. */
int bgit_diff_entries (const bgit_index_entry *old, size_t n_old,
                       const bgit_index_entry *new_entries, size_t n_new,
                       bgit_diff_entry **out, size_t *n_out);

/* The working tree as entries: the index's paths, with the ids and modes
   the files have now, and anything deleted left out. With OBJECTS_DIR the
   blobs are written there, which a caller building a tree from them needs;
   NULL only hashes, which is all a comparison needs. */
int bgit_worktree_entries (const bgit_repo *repo, bgit_odb *odb,
                           const char *objects_dir,
                           const bgit_index_entry *index, size_t n_index,
                           bgit_index_entry **out, size_t *n_out);

void bgit_diff_free (bgit_diff_entry *entries, size_t n);

#endif /* BASH_OS_GIT_DIFF_H */
