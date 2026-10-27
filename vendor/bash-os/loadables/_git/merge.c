/* SPDX-License-Identifier: MIT */
/* _git/merge.c — where two histories last agreed. See merge.h.
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

#include "index.h"
#include "merge.h"
#include "odb.h"
#include "tree.h"
#include "revision.h"
#include "xdiff.h"

#define BGIT_PARENT1 1u
#define BGIT_PARENT2 2u
#define BGIT_STALE   4u
#define BGIT_RESULT  8u

/* What is known about one commit during a walk. */
struct bgit_mark {
    char sha[41];
    unsigned flags;
    long long date;
    int used;
};

/* An open-addressed table of marks, so a big history costs one lookup a
   commit rather than a scan. */
struct bgit_marks {
    struct bgit_mark *slots;
    size_t size, count;
};

static size_t
bgit_mark_hash (const char *sha)
{
    size_t hash = 1469598103934665603ULL % 1000000007ULL;
    for (int i = 0; i < 40 && sha[i]; i++)
        hash = hash * 131 + (unsigned char) sha[i];
    return hash;
}

static int bgit_marks_grow (struct bgit_marks *marks);

static struct bgit_mark *
bgit_marks_at (struct bgit_marks *marks, const char *sha)
{
    if (marks->count * 2 >= marks->size && bgit_marks_grow (marks) < 0)
        return NULL;
    size_t mask = marks->size - 1;
    size_t at = bgit_mark_hash (sha) & mask;
    while (marks->slots[at].used) {
        if (!memcmp (marks->slots[at].sha, sha, 40)) return &marks->slots[at];
        at = (at + 1) & mask;
    }
    marks->slots[at].used = 1;
    memcpy (marks->slots[at].sha, sha, 40);
    marks->slots[at].sha[40] = '\0';
    marks->slots[at].flags = 0;
    marks->slots[at].date = 0;
    marks->count++;
    return &marks->slots[at];
}

static int
bgit_marks_grow (struct bgit_marks *marks)
{
    size_t next = marks->size ? marks->size * 2 : 256;
    struct bgit_mark *slots = calloc (next, sizeof *slots);
    if (!slots) return -1;
    struct bgit_mark *old = marks->slots;
    size_t old_size = marks->size;
    marks->slots = slots;
    marks->size = next;
    marks->count = 0;
    for (size_t i = 0; i < old_size; i++) {
        if (!old[i].used) continue;
        struct bgit_mark *mark = bgit_marks_at (marks, old[i].sha);
        if (!mark) { free (old); return -1; }
        mark->flags = old[i].flags;
        mark->date = old[i].date;
    }
    free (old);
    return 0;
}

static void
bgit_marks_release (struct bgit_marks *marks)
{
    free (marks->slots);
    memset (marks, 0, sizeof *marks);
}

/* The committer date a commit records, which is what orders the walk. */
static long long
bgit_commit_date (bgit_odb *odb, const char *sha)
{
    enum bgit_type type;
    unsigned char *data = NULL;
    size_t len = 0;
    if (bgit_odb_read (odb, sha, &type, &data, &len) < 0) return 0;
    long long date = 0;
    const char *p = (const char *) data, *end = p + len;
    while (p < end) {
        const char *nl = memchr (p, '\n', (size_t) (end - p));
        size_t line = nl ? (size_t) (nl - p) : (size_t) (end - p);
        if (!line) break;
        if (line > 10 && !memcmp (p, "committer ", 10)) {
            const char *close = memchr (p, '>', line);
            if (close) date = strtoll (close + 1, NULL, 10);
            break;
        }
        if (!nl) break;
        p = nl + 1;
    }
    free (data);
    return date;
}

/* Commits waiting to be walked: newest first, and among commits of the same
   date the one that arrived first, which is the order git's queue keeps. */
struct bgit_queue {
    struct { char sha[41]; long long date; unsigned long counter; } *items;
    size_t n, cap;
    unsigned long counter;
};

static int
bgit_queue_put (struct bgit_queue *queue, const char *sha, long long date)
{
    if (queue->n == queue->cap) {
        size_t next = queue->cap ? queue->cap * 2 : 64;
        void *grown = realloc (queue->items, next * sizeof *queue->items);
        if (!grown) return -1;
        queue->items = grown;
        queue->cap = next;
    }
    memcpy (queue->items[queue->n].sha, sha, 40);
    queue->items[queue->n].sha[40] = '\0';
    queue->items[queue->n].date = date;
    queue->items[queue->n].counter = queue->counter++;
    queue->n++;
    return 0;
}

static int
bgit_queue_get (struct bgit_queue *queue, char out[41])
{
    if (!queue->n) return -1;
    size_t best = 0;
    for (size_t i = 1; i < queue->n; i++) {
        if (queue->items[i].date > queue->items[best].date ||
            (queue->items[i].date == queue->items[best].date &&
             queue->items[i].counter < queue->items[best].counter))
            best = i;
    }
    memcpy (out, queue->items[best].sha, 41);
    memmove (queue->items + best, queue->items + best + 1,
             (queue->n - best - 1) * sizeof *queue->items);
    queue->n--;
    return 0;
}

/* Is anything left that is not already known to be stale? */
static int
bgit_queue_has_fresh (struct bgit_queue *queue, struct bgit_marks *marks)
{
    for (size_t i = 0; i < queue->n; i++) {
        struct bgit_mark *mark = bgit_marks_at (marks, queue->items[i].sha);
        if (mark && !(mark->flags & BGIT_STALE)) return 1;
    }
    return 0;
}

/* A list of ids, kept in the order they were added. */
struct bgit_ids {
    char (*ids)[41];
    size_t n, cap;
};

static int
bgit_ids_add (struct bgit_ids *list, const char *sha)
{
    if (list->n == list->cap) {
        size_t next = list->cap ? list->cap * 2 : 8;
        void *grown = realloc (list->ids, next * sizeof *list->ids);
        if (!grown) return -1;
        list->ids = grown;
        list->cap = next;
    }
    memcpy (list->ids[list->n], sha, 40);
    list->ids[list->n][40] = '\0';
    list->n++;
    return 0;
}

/* Paint down to the common ancestors, as git does: the commits carrying
   both marks, oldest ancestors dropped as stale. */
static int
bgit_paint_down (bgit_odb *odb, const char *one, const char *const *twos,
                 int n_twos, struct bgit_ids *result)
{
    struct bgit_marks marks;
    struct bgit_queue queue;
    memset (&marks, 0, sizeof marks);
    memset (&queue, 0, sizeof queue);
    int rc = -1;

    struct bgit_mark *mark = bgit_marks_at (&marks, one);
    if (!mark) goto done;
    mark->flags |= BGIT_PARENT1;
    if (bgit_queue_put (&queue, one, bgit_commit_date (odb, one)) < 0) goto done;
    for (int i = 0; i < n_twos; i++) {
        mark = bgit_marks_at (&marks, twos[i]);
        if (!mark) goto done;
        mark->flags |= BGIT_PARENT2;
        if (bgit_queue_put (&queue, twos[i], bgit_commit_date (odb, twos[i])) < 0)
            goto done;
    }

    while (bgit_queue_has_fresh (&queue, &marks)) {
        char current[41];
        if (bgit_queue_get (&queue, current) < 0) break;
        mark = bgit_marks_at (&marks, current);
        if (!mark) goto done;
        unsigned flags = mark->flags & (BGIT_PARENT1 | BGIT_PARENT2 | BGIT_STALE);
        if (flags == (BGIT_PARENT1 | BGIT_PARENT2)) {
            if (!(mark->flags & BGIT_RESULT)) {
                mark->flags |= BGIT_RESULT;
                if (bgit_ids_add (result, current) < 0) goto done;
            }
            flags |= BGIT_STALE;     /* its ancestors cannot be better */
        }
        char parents[BGIT_MAX_PARENTS][41];
        int count = bgit_commit_parents (odb, current, parents, BGIT_MAX_PARENTS);
        for (int i = 0; i < count; i++) {
            struct bgit_mark *parent = bgit_marks_at (&marks, parents[i]);
            if (!parent) goto done;
            if ((parent->flags & flags) == flags) continue;
            parent->flags |= flags;
            if (bgit_queue_put (&queue, parents[i],
                                bgit_commit_date (odb, parents[i])) < 0)
                goto done;
        }
    }
    rc = 0;
done:
    bgit_marks_release (&marks);
    free (queue.items);
    return rc;
}

int
bgit_is_ancestor (bgit_odb *odb, const char *ancestor, const char *commit)
{
    if (!memcmp (ancestor, commit, 40)) return 1;
    struct bgit_ids bases;
    memset (&bases, 0, sizeof bases);
    const char *twos[1] = { commit };
    if (bgit_paint_down (odb, ancestor, twos, 1, &bases) < 0) {
        free (bases.ids);
        return -1;
    }
    int found = 0;
    for (size_t i = 0; i < bases.n && !found; i++)
        if (!memcmp (bases.ids[i], ancestor, 40)) found = 1;
    free (bases.ids);
    return found;
}

/* Drop any candidate another candidate already reaches. */
static int
bgit_remove_redundant (bgit_odb *odb, struct bgit_ids *list)
{
    if (list->n < 2) return 0;
    char *drop = calloc (list->n, 1);
    if (!drop) return -1;
    for (size_t i = 0; i < list->n; i++) {
        for (size_t j = 0; j < list->n; j++) {
            if (i == j || drop[i] || drop[j]) continue;
            int reaches = bgit_is_ancestor (odb, list->ids[i], list->ids[j]);
            if (reaches < 0) { free (drop); return -1; }
            if (reaches) { drop[i] = 1; break; }
        }
    }
    size_t kept = 0;
    for (size_t i = 0; i < list->n; i++)
        if (!drop[i]) memcpy (list->ids[kept++], list->ids[i], 41);
    list->n = kept;
    free (drop);
    return 0;
}

int
bgit_merge_bases_many (bgit_odb *odb, const char *one, const char *const *twos,
                       int n_twos, char (**out)[41], size_t *n_out)
{
    *out = NULL;
    *n_out = 0;
    /* A commit named on both sides is its own base. */
    for (int i = 0; i < n_twos; i++)
        if (!memcmp (one, twos[i], 40)) {
            struct bgit_ids single;
            memset (&single, 0, sizeof single);
            if (bgit_ids_add (&single, one) < 0) return -1;
            *out = single.ids;
            *n_out = single.n;
            return 0;
        }

    struct bgit_ids result;
    memset (&result, 0, sizeof result);
    if (bgit_paint_down (odb, one, twos, n_twos, &result) < 0 ||
        bgit_remove_redundant (odb, &result) < 0) {
        free (result.ids);
        return -1;
    }
    *out = result.ids;
    *n_out = result.n;
    return 0;
}

int
bgit_merge_bases_octopus (bgit_odb *odb, const char *const *commits, int n,
                          char (**out)[41], size_t *n_out)
{
    *out = NULL;
    *n_out = 0;
    if (n < 1) return 0;
    struct bgit_ids carried;
    memset (&carried, 0, sizeof carried);
    if (bgit_ids_add (&carried, commits[0]) < 0) return -1;

    for (int i = 1; i < n; i++) {
        struct bgit_ids next;
        memset (&next, 0, sizeof next);
        for (size_t j = 0; j < carried.n; j++) {
            char (*bases)[41] = NULL;
            size_t n_bases = 0;
            const char *twos[1] = { carried.ids[j] };
            if (bgit_merge_bases_many (odb, commits[i], twos, 1, &bases,
                                       &n_bases) < 0) {
                free (next.ids);
                free (carried.ids);
                return -1;
            }
            for (size_t k = 0; k < n_bases; k++)
                if (bgit_ids_add (&next, bases[k]) < 0) {
                    free (bases);
                    free (next.ids);
                    free (carried.ids);
                    return -1;
                }
            free (bases);
        }
        free (carried.ids);
        carried = next;
    }
    if (bgit_remove_redundant (odb, &carried) < 0) {
        free (carried.ids);
        return -1;
    }
    *out = carried.ids;
    *n_out = carried.n;
    return 0;
}

int
bgit_independent (bgit_odb *odb, const char *const *commits, int n,
                  char (**out)[41], size_t *n_out)
{
    struct bgit_ids list;
    memset (&list, 0, sizeof list);
    for (int i = 0; i < n; i++)
        if (bgit_ids_add (&list, commits[i]) < 0) {
            free (list.ids);
            return -1;
        }
    if (bgit_remove_redundant (odb, &list) < 0) {
        free (list.ids);
        return -1;
    }
    *out = list.ids;
    *n_out = list.n;
    return 0;
}


/* ---- merging one file's three versions --------------------------------- */

/* Text being built a line at a time. */
struct bgit_text {
    char *data;
    size_t len, cap;
};

static int
bgit_text_add (struct bgit_text *text, const char *bytes, size_t len)
{
    if (text->len + len + 1 > text->cap) {
        size_t next = text->cap ? text->cap : 256;
        while (next < text->len + len + 1) next *= 2;
        char *grown = realloc (text->data, next);
        if (!grown) return -1;
        text->data = grown;
        text->cap = next;
    }
    memcpy (text->data + text->len, bytes, len);
    text->len += len;
    text->data[text->len] = '\0';
    return 0;
}

/* Copy lines [FROM, TO) of FILE, each with the newline it had. */
static int
bgit_text_lines (struct bgit_text *text, const bgit_xdiff_file *file,
                 size_t from, size_t to)
{
    for (size_t i = from; i < to && i < file->n; i++) {
        if (bgit_text_add (text, file->lines[i], file->lengths[i]) < 0) return -1;
        /* A file that ended without a newline keeps its last line ragged. */
        if (i + 1 == file->n && file->missing_newline) continue;
        if (bgit_text_add (text, "\n", 1) < 0) return -1;
    }
    return 0;
}

/* Where a base line sits in one side, counting only the changes that end
   before it — a change that starts exactly there belongs to what follows,
   which matters when both sides add lines at the same place. */
static size_t
bgit_map_before (const bgit_xdiff_change *changes, size_t n, size_t base_line)
{
    long offset = 0;
    for (size_t i = 0; i < n; i++) {
        if (changes[i].old_start >= base_line) break;
        if (changes[i].old_start + changes[i].old_count <= base_line)
            offset += (long) changes[i].new_count - (long) changes[i].old_count;
    }
    return (size_t) ((long) base_line + offset);
}

/* How many lines longer a stretch of the base is on one side, over the
   changes that fall inside it. */
static long
bgit_delta_over (const bgit_xdiff_change *changes, size_t from, size_t to)
{
    long delta = 0;
    for (size_t i = from; i <= to; i++)
        delta += (long) changes[i].new_count - (long) changes[i].old_count;
    return delta;
}

/* Do two runs of lines say the same thing? */
static int
bgit_lines_equal (const bgit_xdiff_file *a, size_t a0, size_t a1,
                  const bgit_xdiff_file *b, size_t b0, size_t b1)
{
    if (a1 - a0 != b1 - b0) return 0;
    for (size_t i = 0; i < a1 - a0; i++) {
        if (a->lengths[a0 + i] != b->lengths[b0 + i] ||
            memcmp (a->lines[a0 + i], b->lines[b0 + i], a->lengths[a0 + i]))
            return 0;
    }
    return 1;
}

/* One stretch of the result: lines taken from one side, from both when
   they agree, or written out between conflict markers. */
struct bgit_region {
    size_t base_start, base_end;
    size_t our_start, our_end;
    size_t their_start, their_end;
    enum { BGIT_TAKE_OURS, BGIT_TAKE_THEIRS, BGIT_TAKE_EITHER, BGIT_CONFLICT } kind;
};

/* A view of part of one side, so two stretches can be compared without
   copying their lines. */
static bgit_xdiff_file
bgit_view (const bgit_xdiff_file *file, size_t from, size_t to)
{
    bgit_xdiff_file view;
    memset (&view, 0, sizeof view);
    view.lines = file->lines + from;
    view.lengths = file->lengths + from;
    view.hashes = file->hashes + from;
    view.n = to - from;
    view.missing_newline = to == file->n ? file->missing_newline : 0;
    return view;
}

/* Two conflicts with three or fewer settled lines between them read better
   as one: moving those lines inside costs no more lines than the markers
   that separating them would need. git does the same. */
static void
bgit_simplify_conflicts (struct bgit_region *regions, size_t *n)
{
    size_t kept = 0;
    for (size_t i = 0; i < *n; i++) {
        if (kept && regions[kept - 1].kind == BGIT_CONFLICT &&
            regions[i].kind == BGIT_CONFLICT &&
            regions[i].base_start - regions[kept - 1].base_end <= 3) {
            regions[kept - 1].base_end = regions[i].base_end;
            regions[kept - 1].our_end = regions[i].our_end;
            regions[kept - 1].their_end = regions[i].their_end;
            continue;
        }
        regions[kept++] = regions[i];
    }
    *n = kept;
}

/* Write one conflict, refined the way git refines it: the two sides are
   compared with each other, so whatever they turned out to agree on is
   settled outside the markers, and only what is left is in dispute. Two
   disputes with three or fewer agreed lines between them stay as one. */
static int
bgit_write_conflict (struct bgit_text *text, const bgit_xdiff_file *our_file,
                     const bgit_xdiff_file *their_file,
                     const struct bgit_region *region,
                     const char *our_label, const char *their_label,
                     int *conflicts)
{
    size_t our_start = region->our_start, our_end = region->our_end;
    size_t their_start = region->their_start, their_end = region->their_end;
    bgit_xdiff_file ours = bgit_view (our_file, our_start, our_end);
    bgit_xdiff_file theirs = bgit_view (their_file, their_start, their_end);
    bgit_xdiff_change *changes = NULL;
    size_t n_changes = 0;

    /* With one side empty there is nothing to compare, and git leaves such
       a conflict whole. */
    if (ours.n && theirs.n) {
        bgit_xdiff_result refined;
        memset (&refined, 0, sizeof refined);
        if (bgit_xdiff_opts (&ours, &theirs, 0,
                         BGIT_XDIFF_INDENT_HEURISTIC, &refined) == 0) {
            if (bgit_xdiff_changes (&refined, ours.n, theirs.n, &changes,
                                    &n_changes) < 0)
                n_changes = 0;
            bgit_xdiff_result_release (&refined);
        }
    }

    if (!n_changes) {
        free (changes);
        *conflicts += 1;
        if (bgit_text_add (text, "<<<<<<< ", 8) < 0 ||
            bgit_text_add (text, our_label, strlen (our_label)) < 0 ||
            bgit_text_add (text, "\n", 1) < 0 ||
            bgit_text_lines (text, our_file, our_start, our_end) < 0 ||
            bgit_text_add (text, "=======\n", 8) < 0 ||
            bgit_text_lines (text, their_file, their_start, their_end) < 0 ||
            bgit_text_add (text, ">>>>>>> ", 8) < 0 ||
            bgit_text_add (text, their_label, strlen (their_label)) < 0 ||
            bgit_text_add (text, "\n", 1) < 0)
            return -1;
        return 0;
    }

    /* Three or fewer agreed lines between two disputes: keep them as one. */
    size_t kept = 0;
    for (size_t i = 0; i < n_changes; i++) {
        if (kept && changes[i].old_start -
            (changes[kept - 1].old_start + changes[kept - 1].old_count) <= 3) {
            changes[kept - 1].old_count = changes[i].old_start +
                changes[i].old_count - changes[kept - 1].old_start;
            changes[kept - 1].new_count = changes[i].new_start +
                changes[i].new_count - changes[kept - 1].new_start;
            continue;
        }
        changes[kept++] = changes[i];
    }
    n_changes = kept;

    size_t at = 0;
    for (size_t i = 0; i < n_changes; i++) {
        if (bgit_text_lines (text, &ours, at, changes[i].old_start) < 0) goto fail;
        *conflicts += 1;
        if (bgit_text_add (text, "<<<<<<< ", 8) < 0 ||
            bgit_text_add (text, our_label, strlen (our_label)) < 0 ||
            bgit_text_add (text, "\n", 1) < 0 ||
            bgit_text_lines (text, &ours, changes[i].old_start,
                             changes[i].old_start + changes[i].old_count) < 0 ||
            bgit_text_add (text, "=======\n", 8) < 0 ||
            bgit_text_lines (text, &theirs, changes[i].new_start,
                             changes[i].new_start + changes[i].new_count) < 0 ||
            bgit_text_add (text, ">>>>>>> ", 8) < 0 ||
            bgit_text_add (text, their_label, strlen (their_label)) < 0 ||
            bgit_text_add (text, "\n", 1) < 0)
            goto fail;
        at = changes[i].old_start + changes[i].old_count;
    }
    if (bgit_text_lines (text, &ours, at, ours.n) < 0) goto fail;
    free (changes);
    return 0;
fail:
    free (changes);
    return -1;
}

int
bgit_merge_content (const char *base, size_t base_len,
                    const char *ours, size_t ours_len,
                    const char *theirs, size_t theirs_len,
                    const char *our_label, const char *their_label,
                    bgit_merge_result *result)
{
    memset (result, 0, sizeof *result);
    bgit_xdiff_file base_file, our_file, their_file;
    bgit_xdiff_result ours_diff, theirs_diff;
    bgit_xdiff_change *ours_changes = NULL, *theirs_changes = NULL;
    struct bgit_region *regions = NULL;
    size_t n_ours = 0, n_theirs = 0, n_regions = 0;
    struct bgit_text text;
    memset (&text, 0, sizeof text);
    int rc = -1;

    if (bgit_xdiff_load (&base_file, base, base_len) < 0) return -1;
    if (bgit_xdiff_load (&our_file, ours, ours_len) < 0) {
        bgit_xdiff_release (&base_file);
        return -1;
    }
    if (bgit_xdiff_load (&their_file, theirs, theirs_len) < 0) {
        bgit_xdiff_release (&base_file);
        bgit_xdiff_release (&our_file);
        return -1;
    }
    memset (&ours_diff, 0, sizeof ours_diff);
    memset (&theirs_diff, 0, sizeof theirs_diff);
    if (bgit_xdiff_opts (&base_file, &our_file, 0,
                         BGIT_XDIFF_INDENT_HEURISTIC, &ours_diff) < 0 ||
        bgit_xdiff_opts (&base_file, &their_file, 0,
                         BGIT_XDIFF_INDENT_HEURISTIC, &theirs_diff) < 0 ||
        bgit_xdiff_changes (&ours_diff, base_file.n, our_file.n,
                            &ours_changes, &n_ours) < 0 ||
        bgit_xdiff_changes (&theirs_diff, base_file.n, their_file.n,
                            &theirs_changes, &n_theirs) < 0)
        goto done;

    regions = calloc (n_ours + n_theirs + 1, sizeof *regions);
    if (!regions) goto done;

    size_t a = 0, b = 0;    /* the next change from each side */
    while (a < n_ours || b < n_theirs) {
        struct bgit_region *region = &regions[n_regions];
        /* A change only one side made, clear of the other, is simply taken. */
        if (b == n_theirs ||
            (a < n_ours &&
             ours_changes[a].old_start + ours_changes[a].old_count <
             theirs_changes[b].old_start)) {
            region->kind = BGIT_TAKE_OURS;
            region->base_start = ours_changes[a].old_start;
            region->base_end = ours_changes[a].old_start + ours_changes[a].old_count;
            region->our_start = ours_changes[a].new_start;
            region->our_end = ours_changes[a].new_start + ours_changes[a].new_count;
            n_regions++;
            a++;
            continue;
        }
        if (a == n_ours ||
            theirs_changes[b].old_start + theirs_changes[b].old_count <
            ours_changes[a].old_start) {
            region->kind = BGIT_TAKE_THEIRS;
            region->base_start = theirs_changes[b].old_start;
            region->base_end = theirs_changes[b].old_start + theirs_changes[b].old_count;
            region->their_start = theirs_changes[b].new_start;
            region->their_end = theirs_changes[b].new_start + theirs_changes[b].new_count;
            n_regions++;
            b++;
            continue;
        }

        /* Both sides touched this stretch of the base. Take in every change
           that reaches into it from either side. */
        size_t first_a = a, first_b = b;
        for (;;) {
            size_t end_a = ours_changes[a].old_start + ours_changes[a].old_count;
            size_t end_b = theirs_changes[b].old_start + theirs_changes[b].old_count;
            if (a + 1 < n_ours && ours_changes[a + 1].old_start <= end_b) { a++; continue; }
            if (b + 1 < n_theirs && theirs_changes[b + 1].old_start <= end_a) { b++; continue; }
            break;
        }
        size_t start = ours_changes[first_a].old_start < theirs_changes[first_b].old_start
                       ? ours_changes[first_a].old_start
                       : theirs_changes[first_b].old_start;
        size_t end_a = ours_changes[a].old_start + ours_changes[a].old_count;
        size_t end_b = theirs_changes[b].old_start + theirs_changes[b].old_count;
        size_t end = end_a > end_b ? end_a : end_b;

        region->base_start = start;
        region->base_end = end;
        region->our_start = bgit_map_before (ours_changes, n_ours, start);
        region->their_start = bgit_map_before (theirs_changes, n_theirs, start);
        region->our_end = (size_t) ((long) (region->our_start + (end - start)) +
                                    bgit_delta_over (ours_changes, first_a, a));
        region->their_end = (size_t) ((long) (region->their_start + (end - start)) +
                                      bgit_delta_over (theirs_changes, first_b, b));
        region->kind = bgit_lines_equal (&our_file, region->our_start, region->our_end,
                                         &their_file, region->their_start,
                                         region->their_end)
                       ? BGIT_TAKE_EITHER : BGIT_CONFLICT;
        n_regions++;
        a++;
        b++;
    }

    bgit_simplify_conflicts (regions, &n_regions);

    size_t at = 0;          /* how far through the base has been written */
    for (size_t i = 0; i < n_regions; i++) {
        const struct bgit_region *region = &regions[i];
        if (bgit_text_lines (&text, &base_file, at, region->base_start) < 0)
            goto done;
        switch (region->kind) {
        case BGIT_TAKE_OURS:
            if (bgit_text_lines (&text, &our_file, region->our_start,
                                 region->our_end) < 0) goto done;
            break;
        case BGIT_TAKE_THEIRS:
            if (bgit_text_lines (&text, &their_file, region->their_start,
                                 region->their_end) < 0) goto done;
            break;
        case BGIT_TAKE_EITHER:
            if (bgit_text_lines (&text, &our_file, region->our_start,
                                 region->our_end) < 0) goto done;
            break;
        case BGIT_CONFLICT:
            if (bgit_write_conflict (&text, &our_file, &their_file, region,
                                     our_label, their_label,
                                     &result->conflicts) < 0)
                goto done;
            break;
        }
        at = region->base_end;
    }
    if (bgit_text_lines (&text, &base_file, at, base_file.n) < 0) goto done;
    rc = 0;

done:
    if (rc == 0) {
        result->text = text.data ? text.data : calloc (1, 1);
        result->len = text.len;
        if (!result->text) rc = -1;
    } else free (text.data);
    free (regions);
    free (ours_changes);
    free (theirs_changes);
    bgit_xdiff_result_release (&ours_diff);
    bgit_xdiff_result_release (&theirs_diff);
    bgit_xdiff_release (&base_file);
    bgit_xdiff_release (&our_file);
    bgit_xdiff_release (&their_file);
    return rc;
}

/* ---- merging two trees -------------------------------------------------- */

void
bgit_merge_paths_free (bgit_merge_path *paths, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        free (paths[i].path);
        free (paths[i].text);
    }
    free (paths);
}

/* The entry for PATH in a tree that was read into index entries. */
static const bgit_index_entry *
bgit_entry_for_path (const bgit_index_entry *entries, size_t n, const char *path)
{
    for (size_t i = 0; i < n; i++)
        if (!strcmp (entries[i].path, path)) return &entries[i];
    return NULL;
}

/* Is the path the same in two trees — the same content and the same mode? */
static int
bgit_same_entry (const bgit_index_entry *a, const bgit_index_entry *b)
{
    if (!a || !b) return a == b;
    return a->mode == b->mode && !memcmp (a->sha, b->sha, 20);
}

static void
bgit_fill_side (const bgit_index_entry *entry, uint32_t *mode, char sha[41])
{
    if (!entry) { *mode = 0; sha[0] = '\0'; return; }
    *mode = entry->mode;
    bgit_sha_to_hex (entry->sha, sha);
}

/* Read one blob, or nothing at all for a side that has no such path. */
static int
bgit_blob_text (bgit_odb *odb, const bgit_index_entry *entry, char **text,
                size_t *len)
{
    *text = NULL;
    *len = 0;
    if (!entry) {
        *text = calloc (1, 1);
        return *text ? 0 : -1;
    }
    char sha[41];
    bgit_sha_to_hex (entry->sha, sha);
    enum bgit_type type;
    unsigned char *data = NULL;
    size_t size = 0;
    if (bgit_odb_read (odb, sha, &type, &data, &size) < 0) return -1;
    *text = (char *) data;
    *len = size;
    return 0;
}

int
bgit_merge_trees (bgit_odb *odb, const char *objects_dir, const char *base_tree,
                  const char *our_tree, const char *their_tree,
                  const char *our_label, const char *their_label,
                  bgit_merge_path **out, size_t *n_out)
{
    bgit_index_entry *base = NULL, *ours = NULL, *theirs = NULL;
    size_t n_base = 0, n_ours = 0, n_theirs = 0;
    bgit_merge_path *paths = NULL;
    size_t n_paths = 0;
    int rc = -1;

    if ((base_tree && bgit_read_tree (odb, base_tree, &base, &n_base) < 0) ||
        (our_tree && bgit_read_tree (odb, our_tree, &ours, &n_ours) < 0) ||
        (their_tree && bgit_read_tree (odb, their_tree, &theirs, &n_theirs) < 0))
        goto done;

    paths = calloc (n_base + n_ours + n_theirs + 1, sizeof *paths);
    if (!paths) goto done;

    /* Every path any of the three trees knows, in order, each seen once. */
    size_t i = 0, j = 0, k = 0;
    while (i < n_ours || j < n_theirs || k < n_base) {
        const char *candidate = NULL;
        if (i < n_ours) candidate = ours[i].path;
        if (j < n_theirs && (!candidate || strcmp (theirs[j].path, candidate) < 0))
            candidate = theirs[j].path;
        if (k < n_base && (!candidate || strcmp (base[k].path, candidate) < 0))
            candidate = base[k].path;

        const bgit_index_entry *our_entry = bgit_entry_for_path (ours, n_ours, candidate);
        const bgit_index_entry *their_entry = bgit_entry_for_path (theirs, n_theirs, candidate);
        const bgit_index_entry *base_entry = bgit_entry_for_path (base, n_base, candidate);
        if (i < n_ours && !strcmp (ours[i].path, candidate)) i++;
        if (j < n_theirs && !strcmp (theirs[j].path, candidate)) j++;
        if (k < n_base && !strcmp (base[k].path, candidate)) k++;

        bgit_merge_path *result = &paths[n_paths];
        result->path = strdup (candidate);
        if (!result->path) goto done;
        result->kind = BGIT_MERGE_CLEAN;
        bgit_fill_side (base_entry, &result->base_mode, result->base_sha);
        bgit_fill_side (our_entry, &result->our_mode, result->our_sha);
        bgit_fill_side (their_entry, &result->their_mode, result->their_sha);
        n_paths++;

        if (bgit_same_entry (our_entry, their_entry)) {
            /* Both sides agree, whether they changed it or not. */
            bgit_fill_side (our_entry, &result->mode, result->sha);
            continue;
        }
        if (bgit_same_entry (base_entry, our_entry)) {
            /* Only they touched it. */
            bgit_fill_side (their_entry, &result->mode, result->sha);
            continue;
        }
        if (bgit_same_entry (base_entry, their_entry)) {
            /* Only we touched it. */
            bgit_fill_side (our_entry, &result->mode, result->sha);
            continue;
        }
        if (!our_entry || !their_entry) {
            /* One side deleted what the other changed. The side that still
               has it keeps it in the working tree, as git leaves it. */
            result->kind = BGIT_MERGE_MODIFY_DELETE;
            result->deleted_in_ours = our_entry == NULL;
            const bgit_index_entry *kept = our_entry ? our_entry : their_entry;
            bgit_fill_side (kept, &result->mode, result->sha);
            continue;
        }

        /* Both sides have it and they differ: merge the lines. */
        char *base_text = NULL, *our_text = NULL, *their_text = NULL;
        size_t base_len = 0, our_len = 0, their_len = 0;
        if (bgit_blob_text (odb, base_entry, &base_text, &base_len) < 0 ||
            bgit_blob_text (odb, our_entry, &our_text, &our_len) < 0 ||
            bgit_blob_text (odb, their_entry, &their_text, &their_len) < 0) {
            free (base_text); free (our_text); free (their_text);
            goto done;
        }
        bgit_merge_result merged;
        int merge_rc = bgit_merge_content (base_text, base_len, our_text, our_len,
                                           their_text, their_len, our_label,
                                           their_label, &merged);
        free (base_text);
        free (our_text);
        free (their_text);
        if (merge_rc < 0) goto done;

        /* A mode both sides changed differently is a conflict of its own;
           otherwise whichever side changed it wins. */
        uint32_t mode = our_entry->mode;
        if (base_entry && our_entry->mode == base_entry->mode)
            mode = their_entry->mode;

        if (merged.conflicts) {
            result->kind = base_entry ? BGIT_MERGE_CONTENT : BGIT_MERGE_ADD_ADD;
            result->text = merged.text;
            result->len = merged.len;
            result->mode = mode;
            continue;
        }
        char sha[41];
        if (bgit_write_object (objects_dir, "blob",
                               (const unsigned char *) merged.text, merged.len,
                               1, sha) < 0) {
            free (merged.text);
            goto done;
        }
        free (merged.text);
        result->kind = BGIT_MERGE_AUTO;
        result->mode = mode;
        memcpy (result->sha, sha, 41);
    }
    rc = 0;

done:
    bgit_index_free_entries (base, n_base);
    bgit_index_free_entries (ours, n_ours);
    bgit_index_free_entries (theirs, n_theirs);
    if (rc < 0) {
        bgit_merge_paths_free (paths, n_paths);
        return -1;
    }
    *out = paths;
    *n_out = n_paths;
    return 0;
}
