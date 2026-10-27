/* SPDX-License-Identifier: MIT */
/* _git/rename.c — noticing that a file was renamed. See rename.h.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "loadables.h"

#include <sys/stat.h>

#include "diff.h"
#include "odb.h"
#include "rename.h"
#include "repo.h"

/* One run of bytes as git cuts them: up to a newline, or 64 bytes. */
struct bgit_chunk {
    unsigned long hash;      /* of the chunk's bytes */
    unsigned int length;     /* how many bytes it holds */
};

struct bgit_chunks {
    struct bgit_chunk *items;
    size_t n, cap;
    unsigned long size;
};

static int
bgit_chunk_cmp (const void *a, const void *b)
{
    const struct bgit_chunk *left = a, *right = b;
    if (left->hash < right->hash) return -1;
    if (left->hash > right->hash) return 1;
    return 0;
}

/* Cut a blob into chunks and count the bytes of each. */
static int
bgit_chunk_file (const unsigned char *data, size_t len, struct bgit_chunks *out)
{
    memset (out, 0, sizeof *out);
    out->size = (unsigned long) len;
    size_t start = 0;
    for (size_t i = 0; i < len; i++) {
        size_t run = i - start + 1;
        if (data[i] != '\n' && run < 64 && i + 1 < len) continue;
        unsigned long hash = 1469598103934665603UL;
        for (size_t k = start; k <= i; k++) {
            hash ^= data[k];
            hash *= 1099511628211UL;
        }
        if (out->n == out->cap) {
            size_t next = out->cap ? out->cap * 2 : 64;
            struct bgit_chunk *grown = realloc (out->items, next * sizeof *grown);
            if (!grown) { free (out->items); return -1; }
            out->items = grown;
            out->cap = next;
        }
        out->items[out->n].hash = hash;
        out->items[out->n].length = (unsigned int) run;
        out->n++;
        start = i + 1;
    }
    if (out->n > 1) qsort (out->items, out->n, sizeof *out->items, bgit_chunk_cmp);
    return 0;
}

/* How many of the source's bytes survive in chunks the destination has. */
static unsigned long
bgit_copied (const struct bgit_chunks *src, const struct bgit_chunks *dst)
{
    unsigned long copied = 0;
    size_t i = 0, j = 0;
    while (i < src->n && j < dst->n) {
        if (src->items[i].hash < dst->items[j].hash) { i++; continue; }
        if (src->items[i].hash > dst->items[j].hash) { j++; continue; }
        /* The same chunk on both sides: count it once, as often as the
           thinner side holds it. */
        unsigned long source_bytes = 0, dest_bytes = 0;
        unsigned long hash = src->items[i].hash;
        while (i < src->n && src->items[i].hash == hash)
            source_bytes += src->items[i++].length;
        while (j < dst->n && dst->items[j].hash == hash)
            dest_bytes += dst->items[j++].length;
        copied += source_bytes < dest_bytes ? source_bytes : dest_bytes;
    }
    return copied;
}

static int
bgit_read_blob (bgit_odb *odb, const char *sha, unsigned char **data, size_t *len)
{
    *data = NULL;
    *len = 0;
    if (!sha || !*sha) {
        *data = calloc (1, 1);
        return *data ? 0 : -1;
    }
    enum bgit_type type;
    return bgit_odb_read (odb, sha, &type, data, len);
}

/* The same, for a comparison that ends at the working tree: what is there
   has been hashed but not written down, so it is read from the file when
   the object store has not got it. */
static int
bgit_read_side (bgit_odb *odb, const bgit_repo *repo, const char *sha,
                const char *path, unsigned char **data, size_t *len)
{
    if (bgit_read_blob (odb, sha, data, len) == 0) return 0;
    if (!repo || !repo->work_tree || !path) return -1;
    char full[4096];
    if (snprintf (full, sizeof full, "%s/%s", repo->work_tree, path) >=
        (int) sizeof full)
        return -1;
    struct stat st;
    if (lstat (full, &st) < 0) return -1;
    if (S_ISLNK (st.st_mode)) {
        char target[4096];
        ssize_t got = readlink (full, target, sizeof target);
        if (got < 0) return -1;
        *data = malloc ((size_t) got ? (size_t) got : 1);
        if (!*data) return -1;
        memcpy (*data, target, (size_t) got);
        *len = (size_t) got;
        return 0;
    }
    return bgit_slurp_file (full, data, len);
}

static int
bgit_score_sides (bgit_odb *odb, const bgit_repo *repo,
                  const char *old_sha, const char *old_path,
                  const char *new_sha, const char *new_path)
{
    if (old_sha && new_sha && *old_sha && *new_sha && !strcmp (old_sha, new_sha))
        return BGIT_RENAME_MAX_SCORE;
    unsigned char *old_data = NULL, *new_data = NULL;
    size_t old_len = 0, new_len = 0;
    if (bgit_read_side (odb, repo, old_sha, old_path, &old_data, &old_len) < 0)
        return 0;
    if (bgit_read_side (odb, repo, new_sha, new_path, &new_data, &new_len) < 0) {
        free (old_data);
        return 0;
    }
    unsigned long max_size = old_len > new_len ? old_len : new_len;
    unsigned long min_size = old_len < new_len ? old_len : new_len;
    int score = 0;
    if (max_size) {
        /* Too different in size to be worth measuring: git gives up when
           the difference alone puts the score under the threshold. */
        unsigned long delta = max_size - min_size;
        if (max_size * (unsigned long) (BGIT_RENAME_MAX_SCORE -
                                        BGIT_RENAME_THRESHOLD) >=
            delta * BGIT_RENAME_MAX_SCORE) {
            struct bgit_chunks src, dst;
            if (bgit_chunk_file (old_data, old_len, &src) == 0) {
                if (bgit_chunk_file (new_data, new_len, &dst) == 0) {
                    unsigned long copied = bgit_copied (&src, &dst);
                    score = (int) (copied * BGIT_RENAME_MAX_SCORE / max_size);
                    free (dst.items);
                }
                free (src.items);
            }
        }
    }
    free (old_data);
    free (new_data);
    return score;
}

int
bgit_similarity (bgit_odb *odb, const char *old_sha, const char *new_sha)
{
    return bgit_score_sides (odb, NULL, old_sha, NULL, new_sha, NULL);
}

/* One possible pairing, while the best ones are being chosen. */
struct bgit_pair {
    size_t deleted, added;
    int score;
};

static int
bgit_pair_cmp (const void *a, const void *b)
{
    const struct bgit_pair *left = a, *right = b;
    if (left->score != right->score) return right->score - left->score;
    if (left->deleted != right->deleted)
        return left->deleted < right->deleted ? -1 : 1;
    return left->added < right->added ? -1 : 1;
}

int
bgit_detect_renames_in (bgit_odb *odb, const bgit_repo *repo,
                        bgit_diff_entry **entries, size_t *n)
{
    size_t count = *n;
    bgit_diff_entry *list = *entries;
    char *paired = calloc (count ? count : 1, 1);
    if (!paired) return -1;

    /* Content that is the same on both sides pairs first, as git pairs it,
       and the search for near matches never reconsiders those. */
    for (size_t added = 0; added < count; added++) {
        if (list[added].status != 'A' || paired[added]) continue;
        for (size_t gone = 0; gone < count; gone++) {
            if (list[gone].status != 'D' || paired[gone]) continue;
            if (strcmp (list[gone].old_sha, list[added].new_sha)) continue;
            paired[gone] = paired[added] = 1;
            list[added].status = 'R';
            list[added].score = BGIT_RENAME_MAX_SCORE;
            list[added].old_mode = list[gone].old_mode;
            memcpy (list[added].old_sha, list[gone].old_sha, 41);
            free (list[added].from);
            list[added].from = strdup (list[gone].path);
            if (!list[added].from) { free (paired); return -1; }
            break;
        }
    }

    /* Then the near matches, best first, each path used once. */
    struct bgit_pair *pairs = NULL;
    size_t n_pairs = 0, cap = 0;
    for (size_t gone = 0; gone < count; gone++) {
        if (list[gone].status != 'D' || paired[gone]) continue;
        for (size_t added = 0; added < count; added++) {
            if (list[added].status != 'A' || paired[added]) continue;
            int score = bgit_score_sides (odb, repo, list[gone].old_sha,
                                          list[gone].from ? list[gone].from
                                                          : list[gone].path,
                                          list[added].new_sha,
                                          list[added].path);
            if (score < BGIT_RENAME_THRESHOLD) continue;
            if (n_pairs == cap) {
                size_t next = cap ? cap * 2 : 32;
                struct bgit_pair *grown = realloc (pairs, next * sizeof *grown);
                if (!grown) { free (pairs); free (paired); return -1; }
                pairs = grown;
                cap = next;
            }
            pairs[n_pairs].deleted = gone;
            pairs[n_pairs].added = added;
            pairs[n_pairs].score = score;
            n_pairs++;
        }
    }
    if (n_pairs > 1) qsort (pairs, n_pairs, sizeof *pairs, bgit_pair_cmp);
    for (size_t i = 0; i < n_pairs; i++) {
        size_t gone = pairs[i].deleted, added = pairs[i].added;
        if (paired[gone] || paired[added]) continue;
        paired[gone] = paired[added] = 1;
        list[added].status = 'R';
        list[added].score = pairs[i].score;
        list[added].old_mode = list[gone].old_mode;
        memcpy (list[added].old_sha, list[gone].old_sha, 41);
        free (list[added].from);
        list[added].from = strdup (list[gone].path);
        if (!list[added].from) { free (pairs); free (paired); return -1; }
    }
    free (pairs);

    /* The deletions that were paired away are no longer changes of their
       own. */
    size_t kept = 0;
    for (size_t i = 0; i < count; i++) {
        if (paired[i] && list[i].status == 'D') {
            free (list[i].path);
            free (list[i].from);
            continue;
        }
        list[kept++] = list[i];
    }
    *n = kept;
    free (paired);
    return 0;
}

int
bgit_detect_renames (bgit_odb *odb, bgit_diff_entry **entries, size_t *n)
{
    return bgit_detect_renames_in (odb, NULL, entries, n);
}
