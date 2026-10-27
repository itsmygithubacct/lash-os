/* SPDX-License-Identifier: MIT */
/* _git/repo.h — finding a repository and its object directories.
 *
 * Covers what git itself accepts: a .git directory, a .git *file* holding
 * "gitdir: PATH" (linked worktrees and submodules), a bare repository, the
 * commondir indirection a linked worktree uses for refs and objects, and the
 * GIT_DIR, GIT_WORK_TREE, GIT_OBJECT_DIRECTORY and
 * GIT_ALTERNATE_OBJECT_DIRECTORIES environment variables.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_REPO_H
#define BASH_OS_GIT_REPO_H

#include <stddef.h>

typedef struct {
    char *git_dir;       /* this worktree's git directory */
    char *common_dir;    /* where refs and objects live; == git_dir normally */
    char *work_tree;     /* NULL for a bare repository */
    int bare;
} bgit_repo;

/* Find the repository containing START (a directory; "." for the current one),
   honouring GIT_DIR and GIT_WORK_TREE, walking parents as git does, and
   following a .git file to its target. Returns 0, or -1 without a message, so
   the caller can word "not a git repository" its own way. */
int bgit_repo_discover (const char *start, bgit_repo *out);

/* One variable's value, copied away. bash hands a loadable a single
   buffer for a variable set for this command alone and frees it when the
   next one is asked for, so two values cannot be held at once. Returns
   OUT, or NULL when the variable is unset or empty. */
const char *bgit_env (const char *name, char *out, size_t outsz);

/* Open a known git directory (or a directory containing .git). */
int bgit_repo_open (const char *git_dir, bgit_repo *out);

/* Free what discover or open allocated. */
void bgit_repo_release (bgit_repo *repo);

/* The object directories to search, in order: this repository's own (or
   GIT_OBJECT_DIRECTORY), then every alternate from
   GIT_ALTERNATE_OBJECT_DIRECTORIES and objects/info/alternates. Returns a
   malloc'd array of malloc'd paths; the caller frees both with
   bgit_repo_free_object_dirs. */
int bgit_repo_object_dirs (const bgit_repo *repo, char ***dirs, size_t *n);
void bgit_repo_free_object_dirs (char **dirs, size_t n);

#endif /* BASH_OS_GIT_REPO_H */
