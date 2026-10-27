/* SPDX-License-Identifier: MIT */
/* _git/xdiff.h — the line diff behind a patch.
 *
 * Myers' algorithm over lines, in the linear-space divide and conquer form,
 * with everything git does around it: the problem is cut down first, so the
 * search never sees a line that cannot be part of a match; the search gives
 * up on an exact answer where one would cost too much, as git's does; and
 * afterwards a run of changed lines is slid as far down as it can go while
 * still describing the same edit, with the indent heuristic picking the
 * position that reads best, which is what git has done by default since
 * 2.14. Hunks carry three lines of context unless asked otherwise, and two
 * changes closer than twice the context become one hunk.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_XDIFF_H
#define BASH_OS_GIT_XDIFF_H

#include <stddef.h>

/* One side of a comparison, split into lines. A file not ending in a
   newline is remembered, so the patch can say so. */
typedef struct {
    const char *text;
    size_t len;
    const char **lines;     /* each line, without its newline */
    size_t *lengths;
    unsigned long *hashes;
    size_t n;
    int missing_newline;
    int binary;
} bgit_xdiff_file;

/* A hunk, as the header describes it: the context is already included. */
typedef struct {
    size_t old_start, old_count;   /* zero-based line numbers */
    size_t new_start, new_count;
} bgit_xdiff_hunk;

typedef struct {
    char *old_changed;             /* one byte per line: was it removed? */
    char *new_changed;             /* one byte per line: was it added? */
    bgit_xdiff_hunk *hunks;
    size_t n_hunks;
    size_t added, removed;
} bgit_xdiff_result;

/* Split TEXT into lines. Caller frees with bgit_xdiff_release. */
int bgit_xdiff_load (bgit_xdiff_file *file, const char *text, size_t len);
void bgit_xdiff_release (bgit_xdiff_file *file);

/* One run of changed lines, as a replacement: COUNT lines of the old file
   from START become COUNT lines of the new file from its own START. */
typedef struct {
    size_t old_start, old_count;
    size_t new_start, new_count;
} bgit_xdiff_change;

/* The runs a result describes, in order. Caller frees *out. */
int bgit_xdiff_changes (const bgit_xdiff_result *result, size_t n_old,
                        size_t n_new, bgit_xdiff_change **out, size_t *n_out);

/* Compare two files with CONTEXT lines of context. Caller frees the result
   with bgit_xdiff_result_release. */
int bgit_xdiff (const bgit_xdiff_file *old, const bgit_xdiff_file *new_file,
                int context, bgit_xdiff_result *out);

/* Let indentation choose where a run of changes that could sit in more than
   one place ends up. git asks for this in a diff of lines, and not in a diff
   of words, where there is no indentation to speak of, nor in a blame or a
   merge. */
#define BGIT_XDIFF_INDENT_HEURISTIC 1

/* Set aside a long tail the two sides already share before comparing them.
   git does this whenever it wants a diff it will show without context: none
   of the tail could appear anyway, and the search is the smaller for it.
   It is also why the same diff can come out differently with -U0. */
#define BGIT_XDIFF_TRIM_TAIL 2

/* Whitespace a comparison may overlook, in git's order of precedence: each
   of these matches everything the one below it matches, and only the first
   one given has any say. */
#define BGIT_XDIFF_IGNORE_WS 4          /* -w: all of it, anywhere */
#define BGIT_XDIFF_IGNORE_WS_CHANGE 8   /* -b: how much of it there is */
#define BGIT_XDIFF_IGNORE_WS_AT_EOL 16  /* whatever trails a line */
#define BGIT_XDIFF_IGNORE_CR_AT_EOL 32  /* a carriage return before the end */
#define BGIT_XDIFF_WS_MASK (BGIT_XDIFF_IGNORE_WS | BGIT_XDIFF_IGNORE_WS_CHANGE \
                            | BGIT_XDIFF_IGNORE_WS_AT_EOL \
                            | BGIT_XDIFF_IGNORE_CR_AT_EOL)

/* Reach each hunk out to the definition it sits in, both ways: git's -W. */
#define BGIT_XDIFF_FUNCTION_CONTEXT 64

/* Say nothing about a run of changes that is nothing but blank lines, when
   it stands far enough from a change that is not: git's
   --ignore-blank-lines. */
#define BGIT_XDIFF_IGNORE_BLANK_LINES 128

/* Search every Myers box exactly, without its cost-cutting heuristics. */
#define BGIT_XDIFF_MINIMAL 256
#define BGIT_XDIFF_PATIENCE 512
#define BGIT_XDIFF_HISTOGRAM 1024

/* The same comparison, saying which of those to do. */
int bgit_xdiff_opts (const bgit_xdiff_file *old, const bgit_xdiff_file *new_file,
                     int context, int flags, bgit_xdiff_result *out);

/* And the same again with INTER_CONTEXT: how many further lines two
   changes may have between them and still be shown as one hunk, over the
   context they each print. git's --inter-hunk-context. */
int bgit_xdiff_full (const bgit_xdiff_file *old, const bgit_xdiff_file *new_file,
                     int context, int inter_context, int flags,
                     bgit_xdiff_result *out);
void bgit_xdiff_result_release (bgit_xdiff_result *result);

/* The text a hunk header shows after the @@ pair: the nearest line at or
   above START that looks like the start of a definition, searched no further
   up than LIMIT (the previous hunk's, or -1). Returns the line's index, or
   -1 when nothing matched; *TEXT and *LEN describe the trimmed text. */
long bgit_xdiff_function (const bgit_xdiff_file *file, long start, long limit,
                          const char **text, size_t *len);

#endif /* BASH_OS_GIT_XDIFF_H */
