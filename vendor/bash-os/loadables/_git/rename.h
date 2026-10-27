/* SPDX-License-Identifier: MIT */
/* _git/rename.h — noticing that a file was renamed.
 *
 * A deletion and an addition in the same change are one rename when the
 * content is the same, or close enough. git measures "close enough" by
 * cutting both files into chunks — each ending at a newline, or after 64
 * bytes — and counting how many of the source's bytes survive in chunks the
 * destination also has. The score is those bytes against the larger file,
 * out of 60000, and half of that is the threshold; the percentage git
 * prints as "similarity index" is the same number out of a hundred.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_RENAME_H
#define BASH_OS_GIT_RENAME_H

#include <stddef.h>

#include "diff.h"
#include "odb.h"

/* git's score scale, and the half of it that counts as a rename. */
#define BGIT_RENAME_MAX_SCORE 60000
#define BGIT_RENAME_THRESHOLD 30000

/* How alike two blobs are, on git's scale. Either may be absent. */
int bgit_similarity (bgit_odb *odb, const char *old_sha, const char *new_sha);

/* Pair the deletions and additions in ENTRIES that are really renames: the
   pair becomes one entry with status 'R', its score, and the path it came
   from. Entries stay sorted by their new path, as git sorts them. */
int bgit_detect_renames (bgit_odb *odb, bgit_diff_entry **entries, size_t *n);

/* The same, for a comparison that ends at the working tree: what is there
   has been hashed but not written down, so REPO says where to read it. */
int bgit_detect_renames_in (bgit_odb *odb, const bgit_repo *repo,
                            bgit_diff_entry **entries, size_t *n);

#endif /* BASH_OS_GIT_RENAME_H */
