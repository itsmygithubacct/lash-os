/* SPDX-License-Identifier: MIT */
/* _git/ignore.h — .gitignore matching.
 *
 * The rules gitignore(5) describes: patterns from .gitignore in each
 * directory from the repository root down, then $GIT_DIR/info/exclude, then
 * core.excludesFile; a later pattern wins; a leading '!' negates; a trailing
 * '/' matches only directories; a '/' anywhere but the end anchors the
 * pattern to the file holding it; '*' and '?' stop at '/' unless the pattern
 * uses '**'; and a directory that is ignored ignores everything under it.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_IGNORE_H
#define BASH_OS_GIT_IGNORE_H

#include <stddef.h>

#include "config.h"
#include "repo.h"

typedef struct {
    char *pattern;     /* for matching: without '!', a leading or trailing '/' */
    char *text;        /* the line as written, which check-ignore -v reports */
    char *source;      /* the file it came from, for check-ignore -v */
    long line;         /* its line number there */
    char *base;        /* the directory the pattern is relative to, "" at the root */
    int negated;
    int directory_only;
    int anchored;
} bgit_ignore_rule;

typedef struct {
    bgit_ignore_rule *rules;
    size_t n, cap;
} bgit_ignore;

/* Match one gitignore-style pattern against a path. Attributes use the same
   wildcards, though their rule precedence and directory behavior differ. */
int bgit_wild (const char *pattern, const char *path);

/* Load the exclude files that apply to REPO: info/exclude, core.excludesFile,
   and the .gitignore at the top of the worktree. Directories deeper down are
   loaded as they are reached, by bgit_ignore_add_dir. */
int bgit_ignore_load (bgit_ignore *ignore, const bgit_repo *repo,
                      const bgit_config *cfg);

/* Add the .gitignore in one directory of the worktree, named relative to the
   worktree root ("" for the root itself). */
int bgit_ignore_add_dir (bgit_ignore *ignore, const bgit_repo *repo,
                         const char *relative);

void bgit_ignore_release (bgit_ignore *ignore);

/* Does PATH (relative to the worktree, no leading "./") match? IS_DIR says
   whether it is a directory. Returns 1 for ignored, 0 for not, and with
   MATCHED the rule that decided, which may be a negation. */
int bgit_ignore_match (const bgit_ignore *ignore, const char *path, int is_dir,
                       const bgit_ignore_rule **matched);

#endif /* BASH_OS_GIT_IGNORE_H */
