/* SPDX-License-Identifier: MIT */
/* _git/revision.h — revision syntax: what a user may write instead of an id.
 *
 * Supported here, as gitrevisions(7) describes them:
 *   <id>            a full object id or a unique abbreviation
 *   <ref>           HEAD, a branch or tag name, or a full ref path
 *   <rev>^          the first parent; ^<n> the nth; ^0 the commit itself
 *   <rev>~          the first parent; ~<n> n first-parent steps back
 *   <rev>^{}        a tag peeled to what it points at
 *   <rev>^{<type>}  peeled to that type: commit, tree, blob or tag
 *   <rev>@{<n>}     the nth previous value of that ref, from its reflog
 *   <rev>:<path>    what that path held in that revision; <rev>: its tree
 *
 * Suffixes chain, left to right, as git applies them.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_REVISION_H
#define BASH_OS_GIT_REVISION_H

#include <stddef.h>

#include "odb.h"
#include "repo.h"

/* The parents a commit may have before we stop counting. */
#define BGIT_MAX_PARENTS 16

/* Resolve SPEC to an object id. With SYMREF, the ref name the base resolved
   through is returned there (malloc'd; NULL when the base was an id).
   Returns 0, or -1 without a message, so each command can word its own. */
int bgit_rev_parse (const bgit_repo *repo, bgit_odb *odb, const char *spec,
                    char out[41], char **symref);

/* A commit's parent ids, in order. Returns how many, or -1. */
int bgit_commit_parents (bgit_odb *odb, const char *sha,
                         char parents[][41], int max);

/* A commit's tree id. Returns 0, or -1. */
int bgit_commit_tree (bgit_odb *odb, const char *sha, char out[41]);

/* Follow tags until the object is of type WANT. With WANT as BGIT_UNKNOWN,
   peel exactly one tag, which is what ^{} means. Returns 0, or -1. */
int bgit_peel_to_type (bgit_odb *odb, const char *sha, enum bgit_type want,
                       char out[41]);

#endif /* BASH_OS_GIT_REVISION_H */
