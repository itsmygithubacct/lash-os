/* SPDX-License-Identifier: MIT */
/* _git/patch.h — turning a list of changed paths into what git prints.
 *
 * The name-level diff in diff.h says which paths changed; this writes them
 * out: a unified patch, a diffstat, --numstat, --shortstat, or the summary
 * of created and deleted files that `git commit` ends with.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_PATCH_H
#define BASH_OS_GIT_PATCH_H

#include <stdio.h>

#include "diff.h"
#include "odb.h"
#include "repo.h"

enum {
    BGIT_DIFF_ALGORITHM_DEFAULT,
    BGIT_DIFF_ALGORITHM_MINIMAL,
    BGIT_DIFF_ALGORITHM_PATIENCE,
    BGIT_DIFF_ALGORITHM_HISTOGRAM
};

typedef struct {
    int context;          /* lines of context; git's default is 3 */
    int inter_context;    /* extra unchanged lines that may join two hunks */
    int abbrev;           /* how much of an id the index line shows */
    int new_from_worktree;/* the new side is a file on disk, not a blob */
    const char *prefix_old, *prefix_new;   /* "a/" and "b/" */
    const char *line_prefix;               /* what log -p indents with */
    int word_diff;        /* 0 by lines, 1 [-word-]{+by word+}, 2 porcelain */
    int ignore_ws;        /* which whitespace to overlook: see xdiff.h */
    int function_context; /* -W: a hunk covers the definition it sits in */
    int ignore_blank_lines;/* a run of blank lines on its own says nothing */
    int algorithm;       /* one of BGIT_DIFF_ALGORITHM_* */
} bgit_patch_options;

void bgit_patch_options_init (bgit_patch_options *options);

/* Load one side of a change: SIDE is 0 for the old, 1 for the new. Returns
   0 with *data owned by the caller, or -1. A side that does not exist (an
   added or deleted path) comes back empty. */
int bgit_patch_content (bgit_odb *odb, const bgit_repo *repo,
                        const bgit_diff_entry *entry, int side,
                        const bgit_patch_options *options,
                        char **data, size_t *len);

/* Write a unified patch for every entry. */
int bgit_patch_write (FILE *out, bgit_odb *odb, const bgit_repo *repo,
                      const bgit_diff_entry *entries, size_t n,
                      const bgit_patch_options *options);

/* How many lines each path gained and lost, for the stat forms. */
typedef struct {
    const bgit_diff_entry *entry;
    size_t added, removed;
    int binary;
} bgit_diffstat_entry;

/* *N_OUT can come back smaller than N: a modified path whose diff turns out
   to say nothing — which whitespace overlooked can do — is left out of the
   stat altogether, as git leaves it out. */
int bgit_diffstat (bgit_odb *odb, const bgit_repo *repo,
                   const bgit_diff_entry *entries, size_t n,
                   const bgit_patch_options *options,
                   bgit_diffstat_entry **out, size_t *n_out);

/* The forms git prints from those counts.

   How wide a stat is drawn and how many of its lines are shown: 0 in a
   field means the width git works out for itself. */
typedef struct {
    int width;         /* the whole line */
    int name_width;    /* the column the paths sit in */
    int graph_width;   /* the column of + and - marks */
    int count;         /* how many files to show, the rest as " ..." */
} bgit_diffstat_layout;

void bgit_diffstat_write (FILE *out, const bgit_diffstat_entry *stats,
                          size_t n, const char *line_prefix,
                          const bgit_diffstat_layout *layout);
void bgit_numstat_write (FILE *out, const bgit_diffstat_entry *stats, size_t n);
void bgit_shortstat_write (FILE *out, const bgit_diffstat_entry *stats,
                           size_t n, const char *line_prefix);
/* " 2 files changed, 3 insertions(+), 1 deletion(-)" */
void bgit_stat_summary (FILE *out, size_t files, size_t added, size_t removed);
/* " create mode 100644 a.txt", as `git commit` and --summary print it. */
void bgit_diff_summary (FILE *out, const bgit_diff_entry *entries, size_t n,
                        const char *line_prefix);

/* --check: what whitespace a change brings in and anything that looks like a
   conflict marker left behind, in git's words. Returns 1 when something was
   found, 0 when nothing was, or -1. */
int bgit_patch_check (FILE *out, bgit_odb *odb, const bgit_repo *repo,
                      const bgit_diff_entry *entries, size_t n,
                      const bgit_patch_options *options);

/* A file in the working tree, with a symlink read as git reads one: its
   content is the path it points at. Caller frees *data. */
int bgit_read_worktree_file (const bgit_repo *repo, const char *path,
                            char **data, size_t *len);

/* core.quotePath, which decides whether a byte outside ASCII is written as
   an escape. Set from the configuration; git's default is on. */
extern int bgit_quote_path_fully;

/* What comes off the front of every path a patch or a stat names, which is
   what --relative asks for. NULL, or a directory with a slash at the end. */
extern const char *bgit_relative_to;

/* The same, forcing the quotes where the name holds a space: what the short
   status does, so that its columns can be told apart. */
const char *bgit_quote_path_sp (const char *path, char *buf, size_t size);

/* Two pieces written as one name — "a/" and the path, say. Where either
   wants quoting, the whole is quoted once, as git quotes it. */
const char *bgit_quote_two (const char *first, const char *second, char *buf,
                            size_t size);

/* A path as git shows it, quoted when it holds anything unusual. Returns a
   pointer to BUF or to PATH itself. */
const char *bgit_quote_path (const char *path, char *buf, size_t size);

#endif /* BASH_OS_GIT_PATCH_H */
