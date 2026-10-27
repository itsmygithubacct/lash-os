/* SPDX-License-Identifier: MIT */
/* _git/tree.h — trees: building them from the index, and reading them back.
 *
 * A tree object lists its entries as "<mode> <name>\0<20-byte id>", sorted
 * by name — with the subtlety that a directory sorts as though its name
 * ended in '/', so "a.b" and "a/b" land where git puts them.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_TREE_H
#define BASH_OS_GIT_TREE_H

#include <stddef.h>

#include "index.h"
#include "odb.h"

/* Write the tree the index describes, and every subtree under it, into
   OBJECTS_DIR. ENTRIES must be sorted by path, as the index keeps them.
   Returns 0 and the root tree's id. Conflict stages are refused, as git
   refuses to write a tree from an unmerged index. */
int bgit_write_tree (bgit_odb *odb, const char *objects_dir,
                     const bgit_index_entry *entries, size_t n, char out[41]);

/* Read a tree recursively into index entries: stage 0, no stat data, sorted
   by path. Caller frees with bgit_index_free_entries. */
int bgit_read_tree (bgit_odb *odb, const char *tree_sha,
                    bgit_index_entry **entries, size_t *n);

/* Walk a tree. FN sees the mode as stored, the type its mode implies, the
   id, and the path with any prefix. With RECURSIVE, subtrees are entered;
   SHOW_TREES also reports the subtree entries themselves. FN returning
   non-zero stops the walk, and that value is returned. */
typedef int (*bgit_tree_fn) (void *ctx, const char *mode, const char *type,
                             const char *sha, const char *path);
int bgit_tree_walk (bgit_odb *odb, const char *tree_sha, const char *prefix,
                    int recursive, int show_trees, bgit_tree_fn fn, void *ctx);

#endif /* BASH_OS_GIT_TREE_H */
