/* SPDX-License-Identifier: MIT */
/* _git/refs.h — refs, packed-refs, symbolic refs and the reflog.
 *
 * A ref is a file under the git directory holding an object id, or a line in
 * packed-refs. A symbolic ref holds "ref: <other>"; HEAD is normally one.
 * Some refs belong to a single worktree (HEAD, ORIG_HEAD, MERGE_HEAD and the
 * rest of the in-progress state); the others are shared through commondir.
 *
 * Every change is made under a lock file and appends a reflog entry, so a
 * repository bash-os writes is one git can read, and the other way round.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_REFS_H
#define BASH_OS_GIT_REFS_H

#include <stddef.h>

#include "repo.h"

typedef struct {
    char *name;
    char sha[41];
} bgit_ref;

/* 1 if NAME is a ref name git would accept (check-ref-format's rules). */
int bgit_ref_name_ok (const char *name);

/* The file holding REFNAME for this repository, per-worktree names in the
   worktree's own git directory and the rest in commondir. Returns 0. */
int bgit_ref_path (const bgit_repo *repo, const char *refname,
                   char *out, size_t outsz);

/* Read one ref, loose or packed. Returns 0 with FULL set, 1 if there is no
   such ref, or -1 on an unreadable or malformed one. Does not follow
   symbolic refs. Silent. */
int bgit_ref_read (const bgit_repo *repo, const char *refname, char full[41]);

/* Read a symbolic ref's target, e.g. HEAD -> "refs/heads/main". Returns 0
   with *target malloc'd, 1 if NAME is not symbolic, -1 on error. Silent. */
int bgit_symref_read (const bgit_repo *repo, const char *name, char **target);

/* Resolve a ref name, HEAD, or a full object id, following symbolic refs up
   to a sane depth. With SYMREF, the last ref name reached is returned there
   (malloc'd, NULL when NAME resolved directly to an id). Returns 0, 1 when
   nothing is there (an unborn branch, say), or -1. Silent. */
int bgit_ref_resolve (const bgit_repo *repo, const char *name, char full[41],
                      char **symref);

/* Point NAME at TARGET, under a lock, with a reflog entry. */
int bgit_symref_write (const bgit_repo *repo, const char *name,
                       const char *target, const char *message);

/* Set REFNAME under a lock and write no log entry, which is what a clone
   does for the tracking refs it lays down. Same OLD_SHA rule as below. */
int bgit_ref_set (const bgit_repo *repo, const char *refname,
                  const char *new_sha, const char *old_sha);

/* Create or change REFNAME under a lock, then append to its reflog.
   OLD_SHA, when given, must match what the ref holds: 40 digits for "must
   be this", or "" for "must not exist". NULL skips the check. */
int bgit_ref_update (const bgit_repo *repo, const char *refname,
                     const char *new_sha, const char *old_sha,
                     const char *message);

/* Delete REFNAME, loose and packed, with the same OLD_SHA rule. */
int bgit_ref_delete (const bgit_repo *repo, const char *refname,
                     const char *old_sha, const char *message);

/* Every ref whose name starts with PREFIX ("" for all), loose and packed,
   sorted by name, a loose ref hiding the packed one. */
int bgit_refs_list (const bgit_repo *repo, const char *prefix,
                    bgit_ref **out, size_t *n);
void bgit_refs_free (bgit_ref *refs, size_t n);

/* Append "<old> <new> <ident> <time> <tz>\t<message>" to REFNAME's reflog,
   creating it for a branch or HEAD as git does. */
int bgit_reflog_append (const bgit_repo *repo, const char *refname,
                        const char *old_sha, const char *new_sha,
                        const char *message);

/* A ref's reflog, oldest first. Caller frees each line and the array. */
int bgit_reflog_lines (const bgit_repo *repo, const char *refname,
                       char ***lines, size_t *n);

/* Remove entry INDEX, counting back from the newest, and join the entries
   either side so the chain of ids still reads straight — which is what
   `git stash drop` does to the stash's reflog. With the last entry gone the
   ref itself goes too. Returns 0, or -1. */
int bgit_reflog_drop (const bgit_repo *repo, const char *refname, size_t index);

/* "Name <email> 1750000100 +0000" from GIT_COMMITTER_NAME, _EMAIL and
   _DATE, falling back to a plain identity and the current time. */
int bgit_committer_ident (char *out, size_t outsz);

/* The identity reflog entries record. The git builtin sets it once per
   command, from the configuration; without it the environment is used. */
void bgit_refs_set_ident (const char *ident);

#endif /* BASH_OS_GIT_REFS_H */
