/* SPDX-License-Identifier: MIT */
/* _git/checkout.h — putting a tree into the working tree and the index.
 *
 * Moving to another commit rewrites files, and git refuses when that would
 * throw away work: a modified file, or an untracked file that the new tree
 * would overwrite. The check happens before anything is written, so a
 * refusal leaves the tree as it was.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_CHECKOUT_H
#define BASH_OS_GIT_CHECKOUT_H

#include <stddef.h>
#include <stdint.h>

#include "index.h"
#include "odb.h"
#include "repo.h"

/* Open FULL_PATH's parent by directory fd, refusing symlink ancestors.
   With CREATE, make missing directories. The caller closes the returned
   fd; *NAME borrows the final component from FULL_PATH. */
int bgit_worktree_parent (const char *full_path, int create, const char **name);

/* Unlink a worktree file without following any parent symlink. */
int bgit_worktree_unlink (const char *full_path);

/* Write one object into the working tree, with the mode a tree records. */
int bgit_checkout_file (bgit_odb *odb, const char *full_path, const char *sha,
                        uint32_t mode);

/* Make the working tree and the index match TREE (NULL for an empty tree).
   *index is replaced with the new entries. Without FORCE, a change that
   would be lost stops everything and names the path in *lost (malloc'd). */
int bgit_checkout_tree (const bgit_repo *repo, bgit_odb *odb, const char *tree,
                        bgit_index_entry **index, size_t *n, int force,
                        char **lost);

/* Restore single paths from a tree or from the index, as `git restore` and
   `git checkout -- <path>` do. PATHS are worktree-relative. Returns -2,
   having said so, when a pathspec named nothing: git leaves with 1 there,
   not with the 128 a real failure gets. */
int bgit_checkout_paths (const bgit_repo *repo, bgit_odb *odb,
                         const char *tree, bgit_index_entry **index, size_t *n,
                         const char *const *paths, size_t n_paths,
                         int to_index, int to_worktree);

/* `git reset <paths>` and `git restore --staged <paths>`: the index goes
   back to what TREE holds, and a path TREE does not have is dropped from
   the index instead. With MUST_MATCH a pathspec that names nothing in
   either place is an error, as it is for restore but not for reset. */
int bgit_reset_paths (const bgit_repo *repo, bgit_odb *odb, const char *tree,
                      bgit_index_entry **index, size_t *n,
                      const char *const *paths, size_t n_paths,
                      int to_worktree, int must_match);

#endif /* BASH_OS_GIT_CHECKOUT_H */
