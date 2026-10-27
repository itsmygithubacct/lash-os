/* SPDX-License-Identifier: MIT */
/* _git/transport.c — moving objects between two repositories. See
 * transport.h.
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

#include "odb.h"
#include "revision.h"
#include "transport.h"
#include "tree.h"

/* Ids waiting to be copied, and those already seen. */
struct bgit_copy_queue {
    char (*ids)[41];
    size_t n, cap;
};

static int
bgit_queue_push (struct bgit_copy_queue *queue, const char *sha)
{
    if (queue->n == queue->cap) {
        size_t next = queue->cap ? queue->cap * 2 : 256;
        void *grown = realloc (queue->ids, next * sizeof *queue->ids);
        if (!grown) return -1;
        queue->ids = grown;
        queue->cap = next;
    }
    memcpy (queue->ids[queue->n], sha, 40);
    queue->ids[queue->n][40] = '\0';
    queue->n++;
    return 0;
}

/* A set of ids, so nothing is walked twice. */
struct bgit_seen {
    char (*ids)[41];
    size_t n, cap;
};

static int
bgit_seen_add (struct bgit_seen *seen, const char *sha)
{
    /* Kept sorted, so membership is a binary search. */
    size_t low = 0, high = seen->n;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        int cmp = memcmp (seen->ids[mid], sha, 40);
        if (cmp < 0) low = mid + 1;
        else if (cmp > 0) high = mid;
        else return 1;                 /* already there */
    }
    if (seen->n == seen->cap) {
        size_t next = seen->cap ? seen->cap * 2 : 256;
        void *grown = realloc (seen->ids, next * sizeof *seen->ids);
        if (!grown) return -1;
        seen->ids = grown;
        seen->cap = next;
    }
    memmove (seen->ids[low + 1], seen->ids[low],
             (seen->n - low) * sizeof *seen->ids);
    memcpy (seen->ids[low], sha, 40);
    seen->ids[low][40] = '\0';
    seen->n++;
    return 0;
}

/* Everything one object points at goes on the queue with it. */
static int
bgit_queue_children (bgit_odb *from, const char *sha, enum bgit_type type,
                     const unsigned char *data, size_t len,
                     struct bgit_copy_queue *queue)
{
    (void) from;
    if (type == BGIT_COMMIT || type == BGIT_TAG) {
        const char *p = (const char *) data, *end = p + len;
        while (p < end) {
            const char *nl = memchr (p, '\n', (size_t) (end - p));
            size_t line = nl ? (size_t) (nl - p) : (size_t) (end - p);
            if (!line) break;                    /* the header ends */
            if ((line > 5 && !memcmp (p, "tree ", 5)) ||
                (line > 7 && !memcmp (p, "parent ", 7)) ||
                (line > 7 && !memcmp (p, "object ", 7))) {
                const char *id = memchr (p, ' ', line) + 1;
                if (p + line - id >= 40 && bgit_queue_push (queue, id) < 0)
                    return -1;
            }
            if (!nl) break;
            p = nl + 1;
        }
        return 0;
    }
    if (type != BGIT_TREE) return 0;
    /* A tree entry is "<mode> <name>\0<20 raw bytes>". */
    const unsigned char *p = data, *end = data + len;
    while (p < end) {
        const unsigned char *nul = memchr (p, '\0', (size_t) (end - p));
        if (!nul || end - nul < 21) break;
        char hex[41];
        bgit_sha_to_hex (nul + 1, hex);
        if (bgit_queue_push (queue, hex) < 0) return -1;
        p = nul + 21;
    }
    return 0;
}

/* Walk everything ROOTS reaches, into the set SEEN. Objects already in
   it stop the walk there, which is how a fetch leaves out what the
   asking end already has. Returns 0, or -1. */
static int
bgit_walk_into (bgit_odb *odb, const char *const *roots, size_t n_roots,
                struct bgit_seen *seen, char (**ids)[41], size_t *n_ids,
                size_t *cap_ids)
{
    struct bgit_copy_queue queue;
    memset (&queue, 0, sizeof queue);
    int rc = -1;

    for (size_t i = 0; i < n_roots; i++)
        if (roots[i] && *roots[i] && bgit_queue_push (&queue, roots[i]) < 0)
            goto done;

    while (queue.n) {
        char sha[41];
        memcpy (sha, queue.ids[--queue.n], 41);
        int already = bgit_seen_add (seen, sha);
        if (already < 0) goto done;
        if (already) continue;

        enum bgit_type type;
        unsigned char *data = NULL;
        size_t len = 0;
        /* An object that is not here stops the walk: a shallow history,
           or something already pruned. */
        if (bgit_odb_read (odb, sha, &type, &data, &len) < 0) continue;
        if (ids) {
            if (*n_ids == *cap_ids) {
                size_t next = *cap_ids ? *cap_ids * 2 : 256;
                void *grown = realloc (*ids, next * sizeof **ids);
                if (!grown) { free (data); goto done; }
                *ids = grown;
                *cap_ids = next;
            }
            memcpy ((*ids)[*n_ids], sha, 41);
            (*n_ids)++;
        }
        if (bgit_queue_children (odb, sha, type, data, len, &queue) < 0) {
            free (data);
            goto done;
        }
        free (data);
    }
    rc = 0;

done:
    free (queue.ids);
    return rc;
}

int
bgit_reachable_objects (bgit_odb *odb, const char *const *roots, size_t n_roots,
                        const char *const *stop, size_t n_stop,
                        char (**ids)[41], size_t *n_ids)
{
    struct bgit_seen seen;
    memset (&seen, 0, sizeof seen);
    char (*found)[41] = NULL;
    size_t n = 0, cap = 0;
    int rc = -1;

    /* What the far end already has goes into the set first, so the walk
       for what it wants stops wherever the two histories meet. */
    if (bgit_walk_into (odb, stop, n_stop, &seen, NULL, NULL, NULL) < 0)
        goto done;
    if (bgit_walk_into (odb, roots, n_roots, &seen, &found, &n, &cap) < 0)
        goto done;
    rc = 0;

done:
    free (seen.ids);
    if (rc < 0) {
        free (found);
        found = NULL;
        n = 0;
    }
    *ids = found;
    *n_ids = n;
    return rc;
}

int
bgit_copy_objects (bgit_odb *from, bgit_odb *into, const char *objects_dir,
                   const char *const *roots, size_t n_roots, size_t *copied)
{
    struct bgit_copy_queue queue;
    struct bgit_seen seen;
    memset (&queue, 0, sizeof queue);
    memset (&seen, 0, sizeof seen);
    size_t count = 0;
    int rc = -1;

    for (size_t i = 0; i < n_roots; i++)
        if (roots[i] && *roots[i] && bgit_queue_push (&queue, roots[i]) < 0)
            goto done;

    while (queue.n) {
        char sha[41];
        memcpy (sha, queue.ids[--queue.n], 41);
        int already = bgit_seen_add (&seen, sha);
        if (already < 0) goto done;
        if (already) continue;

        enum bgit_type type;
        unsigned char *data = NULL;
        size_t len = 0;
        if (bgit_odb_read (from, sha, &type, &data, &len) < 0) {
            /* An object the far end does not have stops the walk there:
               a shallow history, or something already pruned. */
            continue;
        }
        /* An object already at this end brings everything under it with
           it, so the walk stops there: that is what makes a second fetch
           cheap. */
        if (bgit_odb_has (into, sha)) {
            free (data);
            continue;
        }
        char written[41];
        if (bgit_write_object (objects_dir, bgit_type_name (type), data, len,
                               1, written) < 0) {
            free (data);
            goto done;
        }
        count++;
        if (bgit_queue_children (from, sha, type, data, len, &queue) < 0) {
            free (data);
            goto done;
        }
        free (data);
    }
    rc = 0;

done:
    free (queue.ids);
    free (seen.ids);
    if (copied) *copied = count;
    return rc;
}
