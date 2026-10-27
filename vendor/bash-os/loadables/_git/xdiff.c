/* SPDX-License-Identifier: MIT */
/* _git/xdiff.c — the line diff behind a patch. See xdiff.h.
 *
 * Four stages, in git's order. First the problem is cut down: the lines the
 * two files share at top and bottom are set aside, and so is every line
 * between that no line of the other file matches, or that too many of them
 * match to mean anything. Then Myers' algorithm decides which of the rest
 * changed, in the linear-space form so a long file costs memory in the
 * number of lines rather than its square, and with git's two heuristics for
 * giving up on an exact answer when one costs too much. Then each run of
 * changed lines is slid as far down as the file allows — sliding is possible
 * whenever the line above a run matches its last line — and the indent
 * heuristic scores every position it could have taken, preferring the one
 * whose edges sit at the shallower indentation, which is how a diff comes to
 * start at the line that opens a block rather than the one that closes the
 * block before it.
 * Finally the runs are gathered into hunks: each takes its context, and two
 * runs closer than twice the context become one.
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
#include <ctype.h>
#include <limits.h>
#include <stdint.h>

#include "xdiff.h"

int
bgit_xdiff_load (bgit_xdiff_file *file, const char *text, size_t len)
{
    memset (file, 0, sizeof *file);
    file->text = text;
    file->len = len;
    size_t scan = len > 8000 ? 8000 : len;
    for (size_t i = 0; i < scan; i++)
        if (!text[i]) { file->binary = 1; return 0; }

    size_t n = 0;
    for (size_t i = 0; i < len; i++)
        if (text[i] == '\n') n++;
    if (len && text[len - 1] != '\n') { n++; file->missing_newline = 1; }

    file->lines = calloc (n + 1, sizeof *file->lines);
    file->lengths = calloc (n + 1, sizeof *file->lengths);
    file->hashes = calloc (n + 1, sizeof *file->hashes);
    if (!file->lines || !file->lengths || !file->hashes) {
        bgit_xdiff_release (file);
        return -1;
    }
    size_t start = 0, index = 0;
    for (size_t i = 0; i <= len && index < n; i++) {
        if (i < len && text[i] != '\n') continue;
        file->lines[index] = text + start;
        file->lengths[index] = i - start;
        unsigned long hash = 5381;
        for (size_t k = start; k < i; k++)
            hash = hash * 33 + (unsigned char) text[k];
        file->hashes[index] = hash;
        index++;
        start = i + 1;
        if (i == len) break;
    }
    file->n = index;
    return 0;
}

void
bgit_xdiff_release (bgit_xdiff_file *file)
{
    free (file->lines);
    free (file->lengths);
    free (file->hashes);
    file->lines = NULL;
    file->lengths = NULL;
    file->hashes = NULL;
    file->n = 0;
}

void
bgit_xdiff_result_release (bgit_xdiff_result *result)
{
    if (result->old_changed) free (result->old_changed - 1);
    if (result->new_changed) free (result->new_changed - 1);
    free (result->hunks);
    memset (result, 0, sizeof *result);
}

/* ------------------------------------------- overlooking whitespace */

/* The form of a line that a comparison overlooking whitespace compares
   instead of the line: under -w nothing of the whitespace at all, under -b
   each run of it inside the line down to one space and none of what trails
   the line, and under the two narrower rules only what trails — a whole run
   of whitespace, or one carriage return on a line that had a newline of its
   own to end. Writes to OUT, which needs room for LEN bytes, and returns
   how much it wrote. */
static size_t
bgit_line_canonical (const char *line, size_t len, int complete, int flags,
                     char *out)
{
    size_t n = 0;
    if (flags & BGIT_XDIFF_IGNORE_WS) {
        for (size_t i = 0; i < len; i++)
            if (!isspace ((unsigned char) line[i])) out[n++] = line[i];
        return n;
    }
    if (flags & BGIT_XDIFF_IGNORE_WS_CHANGE) {
        for (size_t i = 0; i < len; ) {
            if (!isspace ((unsigned char) line[i])) {
                out[n++] = line[i++];
                continue;
            }
            size_t run = i;
            while (run < len && isspace ((unsigned char) line[run])) run++;
            if (run < len) out[n++] = ' ';
            i = run;
        }
        return n;
    }
    n = len;
    if (flags & BGIT_XDIFF_IGNORE_WS_AT_EOL) {
        while (n && isspace ((unsigned char) line[n - 1])) n--;
    } else if (complete && n && line[n - 1] == '\r') {
        n--;
    }
    memcpy (out, line, n);
    return n;
}

/* A file of canonical lines, one for each of FILE's, to compare in its
   place. *TEXT is the buffer the caller frees once the file is released. */
static int
bgit_canonical_file (const bgit_xdiff_file *file, int flags,
                     bgit_xdiff_file *out, char **text)
{
    char *buffer = malloc (file->len + file->n + 2);
    if (!buffer) return -1;
    size_t at = 0;
    for (size_t i = 0; i < file->n; i++) {
        int complete = !(i + 1 == file->n && file->missing_newline);
        at += bgit_line_canonical (file->lines[i], file->lengths[i], complete,
                                   flags, buffer + at);
        buffer[at++] = '\n';
    }
    if (bgit_xdiff_load (out, buffer, at) < 0 || out->binary ||
        out->n != file->n) {
        bgit_xdiff_release (out);
        free (buffer);
        return -1;
    }
    *text = buffer;
    return 0;
}

/* --------------------------------------------- reducing the problem */

#define BGIT_MAX_EQLIMIT 1024
#define BGIT_KPDIS_RUN 4
#define BGIT_SIMSCAN_WINDOW 100

/* git's integer square root: a power of two at or above the root. Two of
   its heuristics are scaled by this, so the approximation is part of the
   answer rather than a detail of it. */
static long
bgit_bogosqrt (long n)
{
    long i;
    for (i = 1; n > 0; n >>= 2) i <<= 1;
    return i;
}

/* Is line I of A the same line as line J of B? */
static int
bgit_line_same (const bgit_xdiff_file *a, long i,
                const bgit_xdiff_file *b, long j)
{
    return a->hashes[i] == b->hashes[j] && a->lengths[i] == b->lengths[j] &&
           !memcmp (a->lines[i], b->lines[j], a->lengths[i]);
}

/* A line of one of the two files, so both files' lines can be sorted
   together and the equal ones counted. */
typedef struct {
    const bgit_xdiff_file *file;
    size_t index;
    size_t position;
    int side;
} bgit_line_ref;

static int
bgit_line_ref_cmp (const void *pa, const void *pb)
{
    const bgit_line_ref *a = pa, *b = pb;
    unsigned long ha = a->file->hashes[a->index];
    unsigned long hb = b->file->hashes[b->index];
    if (ha != hb) return ha < hb ? -1 : 1;
    size_t la = a->file->lengths[a->index], lb = b->file->lengths[b->index];
    size_t shorter = la < lb ? la : lb;
    int order = shorter ? memcmp (a->file->lines[a->index],
                                  b->file->lines[b->index], shorter) : 0;
    if (order) return order;
    return (la > lb) - (la < lb);
}

static int
bgit_line_ref_sort_cmp (const void *pa, const void *pb)
{
    const bgit_line_ref *a = pa, *b = pb;
    int order = bgit_line_ref_cmp (pa, pb);
    if (order) return order;
    if (a->side != b->side) return a->side - b->side;
    return (a->position > b->position) - (a->position < b->position);
}

/* How many lines of the other file each line is equal to, over the first NA
   lines of A and NB of B: *OUT_A gets one count per line of A, counted in B,
   and *OUT_B the other way about. Caller frees both. */
static int
bgit_match_counts (const bgit_xdiff_file *a, size_t na,
                   const bgit_xdiff_file *b, size_t nb,
                   const size_t *index_a, const size_t *index_b,
                   long **out_a, long **out_b)
{
    size_t total = na + nb;
    bgit_line_ref *refs = malloc ((total + 1) * sizeof *refs);
    long *ca = calloc (na + 1, sizeof *ca);
    long *cb = calloc (nb + 1, sizeof *cb);
    if (!refs || !ca || !cb) {
        free (refs);
        free (ca);
        free (cb);
        return -1;
    }

    size_t k = 0;
    for (size_t i = 0; i < na; i++) {
        refs[k].file = a;
        refs[k].index = index_a ? index_a[i] : i;
        refs[k].position = i;
        refs[k].side = 0;
        k++;
    }
    for (size_t j = 0; j < nb; j++) {
        refs[k].file = b;
        refs[k].index = index_b ? index_b[j] : j;
        refs[k].position = j;
        refs[k].side = 1;
        k++;
    }
    qsort (refs, total, sizeof *refs, bgit_line_ref_sort_cmp);

    for (size_t start = 0; start < total; ) {
        size_t end = start + 1;
        while (end < total && !bgit_line_ref_cmp (&refs[start], &refs[end]))
            end++;
        long in_a = 0, in_b = 0;
        for (size_t t = start; t < end; t++) {
            if (refs[t].side) in_b++;
            else in_a++;
        }
        for (size_t t = start; t < end; t++) {
            if (refs[t].side) cb[refs[t].position] = in_a;
            else ca[refs[t].position] = in_b;
        }
        start = end;
    }
    free (refs);
    *out_a = ca;
    *out_b = cb;
    return 0;
}

/* How many of a file's lines start before BYTES. */
static size_t
bgit_lines_within (const bgit_xdiff_file *file, size_t bytes)
{
    size_t n = 0;
    while (n < file->n && (size_t) (file->lines[n] - file->text) < bytes) n++;
    return n;
}

/* DIS says of each line whether it matches nothing in the other file (0), a
   few lines (1), or so many that a match would mean little (2). A line of
   the third kind is worth searching for only if it has company: when the
   lines around it match nothing either, matching this one somewhere is more
   likely to line up noise than anything real, and git leaves it out. */
static int
bgit_clean_mmatch (const char *dis, long i, long s, long e)
{
    long r, rdis0, rpdis0, rdis1, rpdis1;

    /* Look no further than a hundred lines either way: without the limit a
       long run of unmatched lines in a big file costs far too much. */
    if (i - s > BGIT_SIMSCAN_WINDOW) s = i - BGIT_SIMSCAN_WINDOW;
    if (e - i > BGIT_SIMSCAN_WINDOW) e = i + BGIT_SIMSCAN_WINDOW;

    for (r = 1, rdis0 = 0, rpdis0 = 1; (i - r) >= s; r++) {
        if (!dis[i - r]) rdis0++;
        else if (dis[i - r] == 2) rpdis0++;
        else break;
    }
    /* Nothing unmatched above: the line is in good company, so keep it. */
    if (rdis0 == 0) return 0;
    for (r = 1, rdis1 = 0, rpdis1 = 1; (i + r) <= e; r++) {
        if (!dis[i + r]) rdis1++;
        else if (dis[i + r] == 2) rpdis1++;
        else break;
    }
    if (rdis1 == 0) return 0;
    rdis1 += rdis0;
    rpdis1 += rpdis0;

    return rpdis1 * BGIT_KPDIS_RUN < (rpdis1 + rdis1);
}

/* ---------------------------------------------------------------- Myers */

#define BGIT_SNAKE_CNT 20
#define BGIT_HEUR_MIN_COST 256
#define BGIT_MAX_COST_MIN 256
#define BGIT_K_HEUR 4

typedef struct {
    const bgit_xdiff_file *a, *b;
    const size_t *ia, *ib;      /* the lines still in the search, by index */
    char *ca, *cb;              /* changed flags, with a zero either side */
    long *vf, *vb;              /* the furthest-reaching paths, both ways */
    long mxcost;                /* the cost at which the search gives up */
    int algorithm;
    const char *dis_a, *dis_b;  /* Myers' pre-search classifications */
    long dstart, dend_a, dend_b;
} bgit_xd;

/* Where a box was split, and whether each half must be searched exactly. */
typedef struct {
    long i1, i2;
    int min_lo, min_hi;
} bgit_xd_split;

static int
bgit_xd_eq (const bgit_xd *x, long i, long j)
{
    return bgit_line_same (x->a, (long) x->ia[i], x->b, (long) x->ib[j]);
}

/* Where an edit path crosses the middle of the box: the search from the
   front and the search from the back are each carried one step further
   until they meet. Left alone that is exact but can cost the square of the
   file's length, so unless NEED_MIN forbids it two of git's heuristics cut
   it short — the first takes a path that has run a long way clear of the
   middle diagonal once a long enough run of matching lines has been seen,
   the second gives up at a ceiling on cost and takes whichever path has
   reached furthest. Either way the half the heuristic guessed at is
   searched exactly next time round. Returns the cost paid. */
static long
bgit_xd_find_split (bgit_xd *x, long off1, long lim1, long off2, long lim2,
                    int need_min, bgit_xd_split *spl)
{
    long dmin = off1 - lim2, dmax = lim1 - off2;
    long fmid = off1 - off2, bmid = lim1 - lim2;
    long odd = (fmid - bmid) & 1;
    long fmin = fmid, fmax = fmid, bmin = bmid, bmax = bmid;
    long *vf = x->vf, *vb = x->vb;
    long ec, d, i1, i2, prev1, best, dd, v, k;

    vf[fmid] = off1;
    vb[bmid] = lim1;

    for (ec = 1;; ec++) {
        int got_snake = 0;

        /* Widen the band of diagonals by one. Where that would leave the
           box, narrow it at the other end instead, which keeps the width
           even. The diagonal just outside the band is given a value that
           always loses, so the loop below needs no bounds test. */
        if (fmin > dmin) vf[--fmin - 1] = -1;
        else ++fmin;
        if (fmax < dmax) vf[++fmax + 1] = -1;
        else --fmax;

        for (d = fmax; d >= fmin; d -= 2) {
            i1 = vf[d - 1] >= vf[d + 1] ? vf[d - 1] + 1 : vf[d + 1];
            prev1 = i1;
            i2 = i1 - d;
            while (i1 < lim1 && i2 < lim2 && bgit_xd_eq (x, i1, i2)) {
                i1++;
                i2++;
            }
            if (i1 - prev1 > BGIT_SNAKE_CNT) got_snake = 1;
            vf[d] = i1;
            if (odd && bmin <= d && d <= bmax && vb[d] <= i1) {
                spl->i1 = i1;
                spl->i2 = i2;
                spl->min_lo = spl->min_hi = 1;
                return ec;
            }
        }

        if (bmin > dmin) vb[--bmin - 1] = LONG_MAX;
        else ++bmin;
        if (bmax < dmax) vb[++bmax + 1] = LONG_MAX;
        else --bmax;

        for (d = bmax; d >= bmin; d -= 2) {
            i1 = vb[d - 1] < vb[d + 1] ? vb[d - 1] : vb[d + 1] - 1;
            prev1 = i1;
            i2 = i1 - d;
            while (i1 > off1 && i2 > off2 && bgit_xd_eq (x, i1 - 1, i2 - 1)) {
                i1--;
                i2--;
            }
            if (prev1 - i1 > BGIT_SNAKE_CNT) got_snake = 1;
            vb[d] = i1;
            if (!odd && fmin <= d && d <= fmax && i1 <= vf[d]) {
                spl->i1 = i1;
                spl->i2 = i2;
                spl->min_lo = spl->min_hi = 1;
                return ec;
            }
        }

        if (need_min) continue;

        /* The first heuristic. How far a diagonal has got from the corner
           it started at, less a penalty for sitting far from the middle
           diagonal, measures how promising it is; a diagonal that has done
           better than the cost so far times a constant, and whose last
           twenty lines all match, is taken as the answer. */
        if (got_snake && ec > BGIT_HEUR_MIN_COST) {
            for (best = 0, d = fmax; d >= fmin; d -= 2) {
                dd = d > fmid ? d - fmid : fmid - d;
                i1 = vf[d];
                i2 = i1 - d;
                v = (i1 - off1) + (i2 - off2) - dd;
                if (v > BGIT_K_HEUR * ec && v > best &&
                    off1 + BGIT_SNAKE_CNT <= i1 && i1 < lim1 &&
                    off2 + BGIT_SNAKE_CNT <= i2 && i2 < lim2) {
                    for (k = 1; bgit_xd_eq (x, i1 - k, i2 - k); k++)
                        if (k == BGIT_SNAKE_CNT) {
                            best = v;
                            spl->i1 = i1;
                            spl->i2 = i2;
                            break;
                        }
                }
            }
            if (best > 0) {
                spl->min_lo = 1;
                spl->min_hi = 0;
                return ec;
            }

            for (best = 0, d = bmax; d >= bmin; d -= 2) {
                dd = d > bmid ? d - bmid : bmid - d;
                i1 = vb[d];
                i2 = i1 - d;
                v = (lim1 - i1) + (lim2 - i2) - dd;
                if (v > BGIT_K_HEUR * ec && v > best &&
                    off1 < i1 && i1 <= lim1 - BGIT_SNAKE_CNT &&
                    off2 < i2 && i2 <= lim2 - BGIT_SNAKE_CNT) {
                    for (k = 0; bgit_xd_eq (x, i1 + k, i2 + k); k++)
                        if (k == BGIT_SNAKE_CNT - 1) {
                            best = v;
                            spl->i1 = i1;
                            spl->i2 = i2;
                            break;
                        }
                }
            }
            if (best > 0) {
                spl->min_lo = 0;
                spl->min_hi = 1;
                return ec;
            }
        }

        /* Enough is enough: take the furthest-reaching path there is, from
           whichever end of the box has got further. */
        if (ec >= x->mxcost) {
            long fbest = -1, fbest1 = -1;
            long bbest = LONG_MAX, bbest1 = LONG_MAX;

            for (d = fmax; d >= fmin; d -= 2) {
                i1 = vf[d] < lim1 ? vf[d] : lim1;
                i2 = i1 - d;
                if (lim2 < i2) { i1 = lim2 + d; i2 = lim2; }
                if (fbest < i1 + i2) {
                    fbest = i1 + i2;
                    fbest1 = i1;
                }
            }
            for (d = bmax; d >= bmin; d -= 2) {
                i1 = vb[d] > off1 ? vb[d] : off1;
                i2 = i1 - d;
                if (i2 < off2) { i1 = off2 + d; i2 = off2; }
                if (i1 + i2 < bbest) {
                    bbest = i1 + i2;
                    bbest1 = i1;
                }
            }

            if ((lim1 + lim2) - bbest < fbest - (off1 + off2)) {
                spl->i1 = fbest1;
                spl->i2 = fbest - fbest1;
                spl->min_lo = 1;
                spl->min_hi = 0;
            } else {
                spl->i1 = bbest1;
                spl->i2 = bbest - bbest1;
                spl->min_lo = 0;
                spl->min_hi = 1;
            }
            return ec;
        }
    }
}

typedef struct { long a, b; } bgit_xd_anchor;

static int
bgit_xd_anchor_cmp (const void *pa, const void *pb)
{
    const bgit_xd_anchor *a = pa, *b = pb;
    return (a->a > b->a) - (a->a < b->a);
}

static int bgit_xd_compare (bgit_xd *, long, long, long, long, int);

static int
bgit_xd_myers_fallback (bgit_xd *x, long a0, long a1, long b0, long b1,
                        int need_min)
{
    size_t cap_a = (size_t) (a1 - a0), cap_b = (size_t) (b1 - b0);
    size_t *src_a = malloc ((cap_a ? cap_a : 1) * sizeof *src_a);
    size_t *src_b = malloc ((cap_b ? cap_b : 1) * sizeof *src_b);
    size_t *ia = malloc ((cap_a ? cap_a : 1) * sizeof *ia);
    size_t *ib = malloc ((cap_b ? cap_b : 1) * sizeof *ib);
    long *matches_a = NULL, *matches_b = NULL;
    char *dis_a = calloc (cap_a ? cap_a : 1, 1);
    char *dis_b = calloc (cap_b ? cap_b : 1, 1);
    if (!src_a || !src_b || !ia || !ib || !dis_a || !dis_b) {
        free (src_a); free (src_b); free (ia); free (ib);
        free (dis_a); free (dis_b);
        return -1;
    }
    for (size_t i = 0; i < cap_a; i++) src_a[i] = x->ia[a0 + (long) i];
    for (size_t j = 0; j < cap_b; j++) src_b[j] = x->ib[b0 + (long) j];
    if (bgit_match_counts (x->a, cap_a, x->b, cap_b, src_a, src_b,
                           &matches_a, &matches_b) < 0) {
        free (src_a); free (src_b); free (ia); free (ib);
        free (dis_a); free (dis_b);
        return -1;
    }
    long limit = bgit_bogosqrt ((long) cap_a);
    if (limit > BGIT_MAX_EQLIMIT) limit = BGIT_MAX_EQLIMIT;
    for (size_t i = 0; i < cap_a; i++)
        dis_a[i] = matches_a[i] == 0 ? 0 : matches_a[i] >= limit ? 2 : 1;
    limit = bgit_bogosqrt ((long) cap_b);
    if (limit > BGIT_MAX_EQLIMIT) limit = BGIT_MAX_EQLIMIT;
    for (size_t j = 0; j < cap_b; j++)
        dis_b[j] = matches_b[j] == 0 ? 0 : matches_b[j] >= limit ? 2 : 1;
    free (matches_a); free (matches_b);

    size_t na = 0, nb = 0;
    /* Git falls back by preparing a fresh classic diff over this subregion,
       so popular-line classification and its cutoff are local to the region. */
    for (size_t i = 0; i < cap_a; i++) {
        if (dis_a[i] == 1 ||
            (dis_a[i] == 2 && !bgit_clean_mmatch (dis_a, (long) i, 0,
                                                   (long) cap_a - 1)))
            ia[na++] = src_a[i];
        else x->ca[src_a[i]] = 1;
    }
    for (size_t j = 0; j < cap_b; j++) {
        if (dis_b[j] == 1 ||
            (dis_b[j] == 2 && !bgit_clean_mmatch (dis_b, (long) j, 0,
                                                   (long) cap_b - 1)))
            ib[nb++] = src_b[j];
        else x->cb[src_b[j]] = 1;
    }
    free (src_a); free (src_b); free (dis_a); free (dis_b);
    long ndiags = (long) (na + nb) + 3;
    long *vf = calloc ((size_t) ndiags, sizeof *vf);
    long *vb = calloc ((size_t) ndiags, sizeof *vb);
    if (!vf || !vb) {
        free (ia); free (ib); free (vf); free (vb);
        return -1;
    }
    bgit_xd fallback = *x;
    fallback.ia = ia;
    fallback.ib = ib;
    fallback.algorithm = 0;
    fallback.vf = vf + nb + 1;
    fallback.vb = vb + nb + 1;
    fallback.mxcost = bgit_bogosqrt (ndiags);
    if (fallback.mxcost < BGIT_MAX_COST_MIN)
        fallback.mxcost = BGIT_MAX_COST_MIN;
    int status = bgit_xd_compare (&fallback, 0, (long) na,
                                  0, (long) nb, need_min);
    free (ia); free (ib); free (vf); free (vb);
    return status;
}

/* Find the longest chain of lines unique on each side. Recomputing this in
   each gap is what lets lines repeated in the outer range become anchors
   after the range narrows. */
static int
bgit_xd_patience (bgit_xd *x, long a0, long a1, long b0, long b1)
{
    size_t na = (size_t) (a1 - a0), nb = (size_t) (b1 - b0);
    if (na > SIZE_MAX - nb || na + nb > SIZE_MAX / sizeof (bgit_line_ref))
        return -1;
    size_t total = na + nb;
    bgit_line_ref *refs = malloc ((total ? total : 1) * sizeof *refs);
    bgit_xd_anchor *anchors = malloc ((na ? na : 1) * sizeof *anchors);
    size_t *tails = malloc ((na ? na : 1) * sizeof *tails);
    size_t *previous = malloc ((na ? na : 1) * sizeof *previous);
    if (!refs || !anchors || !tails || !previous) {
        free (refs); free (anchors); free (tails); free (previous);
        return -1;
    }
    size_t at = 0;
    for (long i = a0; i < a1; i++) {
        refs[at++] = (bgit_line_ref) {x->a, x->ia[i], (size_t) i, 0};
    }
    for (long j = b0; j < b1; j++) {
        refs[at++] = (bgit_line_ref) {x->b, x->ib[j], (size_t) j, 1};
    }
    qsort (refs, total, sizeof *refs, bgit_line_ref_sort_cmp);

    size_t n_anchors = 0;
    for (size_t start = 0; start < total; ) {
        size_t end = start + 1;
        while (end < total && !bgit_line_ref_cmp (&refs[start], &refs[end]))
            end++;
        size_t apos = SIZE_MAX, bpos = SIZE_MAX, acount = 0, bcount = 0;
        for (size_t k = start; k < end; k++) {
            if (refs[k].side) { bpos = refs[k].position; bcount++; }
            else { apos = refs[k].position; acount++; }
        }
        if (acount == 1 && bcount == 1)
            anchors[n_anchors++] = (bgit_xd_anchor) {(long) apos, (long) bpos};
        start = end;
    }
    free (refs);
    if (!n_anchors) {
        free (anchors); free (tails); free (previous);
        return -2;              /* no unique common line: use Myers */
    }
    qsort (anchors, n_anchors, sizeof *anchors, bgit_xd_anchor_cmp);

    /* Longest strictly increasing sequence of positions in the new file. */
    size_t length = 0;
    for (size_t i = 0; i < n_anchors; i++) {
        size_t lo = 0, hi = length;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (anchors[tails[mid]].b < anchors[i].b) lo = mid + 1;
            else hi = mid;
        }
        previous[i] = lo ? tails[lo - 1] : SIZE_MAX;
        tails[lo] = i;
        if (lo == length) length++;
    }
    bgit_xd_anchor *sequence = malloc (length * sizeof *sequence);
    if (!sequence) {
        free (anchors); free (tails); free (previous);
        return -1;
    }
    size_t pick = tails[length - 1];
    for (size_t i = length; i; i--) {
        sequence[i - 1] = anchors[pick];
        pick = previous[pick];
    }
    free (anchors); free (tails); free (previous);

    long old_at = a0, new_at = b0;
    int status = 0;
    for (size_t i = 0; i < length; i++) {
        bgit_xd_anchor anchor = sequence[i];
        long next_a = anchor.a, next_b = anchor.b;
        while (next_a > old_at && next_b > new_at &&
               bgit_xd_eq (x, next_a - 1, next_b - 1)) {
            next_a--; next_b--;
        }
        while (old_at < next_a && new_at < next_b &&
               bgit_xd_eq (x, old_at, new_at)) {
            old_at++; new_at++;
        }
        status = bgit_xd_compare (x, old_at, next_a, new_at, next_b, 0);
        if (status < 0) break;
        old_at = anchor.a + 1;
        new_at = anchor.b + 1;
    }
    if (!status) {
        while (old_at < a1 && new_at < b1 &&
               bgit_xd_eq (x, old_at, new_at)) {
            old_at++; new_at++;
        }
        status = bgit_xd_compare (x, old_at, a1, new_at, b1, 0);
    }
    free (sequence);
    return status;
}

/* Histogram chooses a longest common run whose lines are relatively rare.
   It falls back to Myers when no bounded-frequency common run is available. */
static int
bgit_xd_histogram (bgit_xd *x, long a0, long a1, long b0, long b1,
                   int need_min)
{
    size_t na = (size_t) (a1 - a0), nb = (size_t) (b1 - b0);
    if (na > SIZE_MAX - nb || na + nb > SIZE_MAX / sizeof (bgit_line_ref))
        return -1;
    size_t total = na + nb;
    bgit_line_ref *refs = malloc ((total ? total : 1) * sizeof *refs);
    size_t *a_counts = calloc (na ? na : 1, sizeof *a_counts);
    if (!refs || !a_counts) { free (refs); free (a_counts); return -1; }
    size_t at = 0;
    for (long i = a0; i < a1; i++)
        refs[at++] = (bgit_line_ref) {x->a, x->ia[i], (size_t) i, 0};
    for (long j = b0; j < b1; j++)
        refs[at++] = (bgit_line_ref) {x->b, x->ib[j], (size_t) j, 1};
    qsort (refs, total, sizeof *refs, bgit_line_ref_sort_cmp);

    long best_a = -1, best_b = -1, best_len = 0;
    size_t best_frequency = 65;
    int has_common = 0;
    for (size_t start = 0; start < total; ) {
        size_t end = start + 1, count = 0;
        while (end < total && !bgit_line_ref_cmp (&refs[start], &refs[end]))
            end++;
        for (size_t k = start; k < end; k++)
            if (!refs[k].side) count++;
        for (size_t k = start; k < end; k++)
            if (!refs[k].side)
                a_counts[refs[k].position - (size_t) a0] = count;
        start = end;
    }
    long b_ptr = b0;
    while (b_ptr < b1) {
        bgit_line_ref key = {x->b, x->ib[b_ptr], (size_t) b_ptr, 1};
        size_t lo = 0, hi = total;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (bgit_line_ref_cmp (&refs[mid], &key) < 0) lo = mid + 1;
            else hi = mid;
        }
        size_t start = lo, end = start;
        while (end < total && !bgit_line_ref_cmp (&refs[end], &key)) end++;
        size_t acount = 0, bcount = 0;
        for (size_t k = start; k < end; k++)
            if (refs[k].side) bcount++; else acount++;
        long b_next = b_ptr + 1;
        if (acount && bcount) {
            has_common = 1;
            if (acount <= best_frequency) {
                long a_next = a0;
                for (size_t ai = start; ai < end; ai++) if (!refs[ai].side) {
                    long a = (long) refs[ai].position;
                    if (a < a_next) continue;
                    size_t frequency = acount;
                    long left = 0, right = 1;
                    while (a - left - 1 >= a0 && b_ptr - left - 1 >= b0 &&
                           bgit_xd_eq (x, a - left - 1, b_ptr - left - 1)) {
                        left++;
                        if (frequency > 1 &&
                            a_counts[a - left - (size_t) a0] < frequency)
                            frequency = a_counts[a - left - (size_t) a0];
                    }
                    while (a + right < a1 && b_ptr + right < b1 &&
                           bgit_xd_eq (x, a + right, b_ptr + right)) {
                        if (frequency > 1 &&
                            a_counts[a + right - (size_t) a0] < frequency)
                            frequency = a_counts[a + right - (size_t) a0];
                        right++;
                    }
                    long run = left + right;
                    if (b_ptr + right > b_next) b_next = b_ptr + right;
                    if (a + right > a_next) a_next = a + right;
                    if (run > best_len || frequency < best_frequency) {
                        best_a = a - left;
                        best_b = b_ptr - left;
                        best_len = run;
                        best_frequency = frequency;
                    }
                }
            }
        }
        b_ptr = b_next;
    }
    free (refs);
    free (a_counts);
    if (best_a < 0) {
        if (!has_common) {
            for (long i = a0; i < a1; i++) x->ca[x->ia[i]] = 1;
            for (long j = b0; j < b1; j++) x->cb[x->ib[j]] = 1;
            return 0;
        }
        return bgit_xd_myers_fallback (x, a0, a1, b0, b1, need_min);
    }
    int status = bgit_xd_compare (x, a0, best_a, b0, best_b, need_min);
    if (!status)
        status = bgit_xd_compare (x, best_a + best_len, a1,
                                  best_b + best_len, b1, need_min);
    return status;
}

/* Divide and conquer with the selected algorithm. Myers remains the fallback
   inside patience and histogram regions that have no useful anchors. */
static int
bgit_xd_compare (bgit_xd *x, long a0, long a1, long b0, long b1, int need_min)
{
    if (a0 == a1) {
        for (long j = b0; j < b1; j++) x->cb[x->ib[j]] = 1;
        return 0;
    }
    if (b0 == b1) {
        for (long i = a0; i < a1; i++) x->ca[x->ia[i]] = 1;
        return 0;
    }

    if (x->algorithm == BGIT_XDIFF_PATIENCE) {
        int status = bgit_xd_patience (x, a0, a1, b0, b1);
        if (status != -2) return status;
        return bgit_xd_myers_fallback (x, a0, a1, b0, b1, need_min);
    }
    if (x->algorithm == BGIT_XDIFF_HISTOGRAM)
        return bgit_xd_histogram (x, a0, a1, b0, b1, need_min);

    while (a0 < a1 && b0 < b1 && bgit_xd_eq (x, a0, b0)) { a0++; b0++; }
    while (a0 < a1 && b0 < b1 && bgit_xd_eq (x, a1 - 1, b1 - 1)) { a1--; b1--; }
    if (a0 == a1) {
        for (long j = b0; j < b1; j++) x->cb[x->ib[j]] = 1;
        return 0;
    }
    if (b0 == b1) {
        for (long i = a0; i < a1; i++) x->ca[x->ia[i]] = 1;
        return 0;
    }

    bgit_xd_split spl = {0, 0, 0, 0};
    bgit_xd_find_split (x, a0, a1, b0, b1, need_min, &spl);
    if ((spl.i1 == a0 && spl.i2 == b0) || (spl.i1 == a1 && spl.i2 == b1)) {
        /* No progress: rather than recur for ever, take the whole box as
           changed. The search does not do this, but a split that moved
           nothing would cost the stack everything. */
        for (long i = a0; i < a1; i++) x->ca[x->ia[i]] = 1;
        for (long j = b0; j < b1; j++) x->cb[x->ib[j]] = 1;
        return 0;
    }
    int status = bgit_xd_compare (x, a0, spl.i1, b0, spl.i2, spl.min_lo);
    if (status < 0) return status;
    return bgit_xd_compare (x, spl.i1, a1, spl.i2, b1, spl.min_hi);
}

/* ---------------------------------------------------- git's compaction */

#define BGIT_MAX_INDENT 200
#define BGIT_MAX_BLANKS 20
#define BGIT_INDENT_MAX_SLIDING 100
#define BGIT_INDENT_WEIGHT 60
#define BGIT_START_OF_FILE_PENALTY 1
#define BGIT_END_OF_FILE_PENALTY 21
#define BGIT_TOTAL_BLANK_WEIGHT (-30)
#define BGIT_POST_BLANK_WEIGHT 6
#define BGIT_RELATIVE_INDENT_PENALTY (-4)
#define BGIT_RELATIVE_INDENT_WITH_BLANK_PENALTY 10
#define BGIT_RELATIVE_OUTDENT_PENALTY 24
#define BGIT_RELATIVE_OUTDENT_WITH_BLANK_PENALTY 17
#define BGIT_RELATIVE_DEDENT_PENALTY 23
#define BGIT_RELATIVE_DEDENT_WITH_BLANK_PENALTY 17

/* How far a line is indented, counting a tab to the next multiple of eight.
   A line that is nothing but whitespace has no indentation at all: -1. */
static int
bgit_indent_of (const char *line, size_t len)
{
    int indent = 0;
    for (size_t i = 0; i < len; i++) {
        char c = line[i];
        if (!isspace ((unsigned char) c)) return indent;
        if (c == ' ') indent += 1;
        else if (c == '\t') indent += 8 - indent % 8;
        if (indent >= BGIT_MAX_INDENT) return BGIT_MAX_INDENT;
    }
    return -1;
}

typedef struct {
    int end_of_file;
    int indent;
    int pre_blank, pre_indent;
    int post_blank, post_indent;
} bgit_split_measure;

typedef struct {
    int effective_indent;
    int penalty;
} bgit_split_score;

static void
bgit_measure_split (const bgit_xdiff_file *file, long n, long split,
                    bgit_split_measure *m)
{
    memset (m, 0, sizeof *m);
    if (split >= n) {
        m->end_of_file = 1;
        m->indent = -1;
    } else {
        m->indent = bgit_indent_of (file->lines[split], file->lengths[split]);
    }

    m->pre_indent = -1;
    for (long i = split - 1; i >= 0; i--) {
        m->pre_indent = bgit_indent_of (file->lines[i], file->lengths[i]);
        if (m->pre_indent != -1) break;
        m->pre_blank += 1;
        if (m->pre_blank == BGIT_MAX_BLANKS) { m->pre_indent = 0; break; }
    }

    m->post_indent = -1;
    for (long i = split + 1; i < n; i++) {
        m->post_indent = bgit_indent_of (file->lines[i], file->lengths[i]);
        if (m->post_indent != -1) break;
        m->post_blank += 1;
        if (m->post_blank == BGIT_MAX_BLANKS) { m->post_indent = 0; break; }
    }
}

static void
bgit_score_add_split (const bgit_split_measure *m, bgit_split_score *s)
{
    if (m->pre_indent == -1 && m->pre_blank == 0)
        s->penalty += BGIT_START_OF_FILE_PENALTY;
    if (m->end_of_file)
        s->penalty += BGIT_END_OF_FILE_PENALTY;

    int post_blank = (m->indent == -1) ? 1 + m->post_blank : 0;
    int total_blank = m->pre_blank + post_blank;
    s->penalty += BGIT_TOTAL_BLANK_WEIGHT * total_blank;
    s->penalty += BGIT_POST_BLANK_WEIGHT * post_blank;

    int indent = (m->indent != -1) ? m->indent : m->post_indent;
    int any_blanks = total_blank != 0;
    s->effective_indent += indent;

    if (indent == -1 || m->pre_indent == -1 || indent == m->pre_indent) {
        /* Nothing more to say about this split. */
    } else if (indent > m->pre_indent) {
        s->penalty += any_blanks ? BGIT_RELATIVE_INDENT_WITH_BLANK_PENALTY
                                 : BGIT_RELATIVE_INDENT_PENALTY;
    } else if (m->post_indent != -1 && m->post_indent > m->indent) {
        /* Less indented than the line above but more than the line below:
           this looks like the start of a block, not the end of one. */
        s->penalty += any_blanks ? BGIT_RELATIVE_OUTDENT_WITH_BLANK_PENALTY
                                 : BGIT_RELATIVE_OUTDENT_PENALTY;
    } else {
        s->penalty += any_blanks ? BGIT_RELATIVE_DEDENT_WITH_BLANK_PENALTY
                                 : BGIT_RELATIVE_DEDENT_PENALTY;
    }
}

static int
bgit_score_cmp (const bgit_split_score *a, const bgit_split_score *b)
{
    int indents = (a->effective_indent > b->effective_indent) -
                  (a->effective_indent < b->effective_indent);
    return BGIT_INDENT_WEIGHT * indents + (a->penalty - b->penalty);
}

/* A run of changed lines, as compaction moves it about. */
typedef struct { long start, end; } bgit_group;

static void
bgit_group_init (const char *changed, bgit_group *g)
{
    g->start = g->end = 0;
    while (changed[g->end]) g->end++;
}

static int
bgit_group_next (const char *changed, long n, bgit_group *g)
{
    if (g->end == n) return -1;
    g->start = g->end + 1;
    for (g->end = g->start; changed[g->end]; g->end++)
        ;
    return 0;
}

static int
bgit_group_previous (const char *changed, bgit_group *g)
{
    if (g->start == 0) return -1;
    g->end = g->start - 1;
    for (g->start = g->end; changed[g->start - 1]; g->start--)
        ;
    return 0;
}

static int
bgit_lines_match (const bgit_xdiff_file *file, long i, long j)
{
    return file->hashes[i] == file->hashes[j] &&
           file->lengths[i] == file->lengths[j] &&
           !memcmp (file->lines[i], file->lines[j], file->lengths[i]);
}

static int
bgit_group_slide_up (const bgit_xdiff_file *file, char *changed, bgit_group *g)
{
    if (g->start > 0 && bgit_lines_match (file, g->start - 1, g->end - 1)) {
        changed[--g->start] = 1;
        changed[--g->end] = 0;
        while (changed[g->start - 1]) g->start--;
        return 0;
    }
    return -1;
}

static int
bgit_group_slide_down (const bgit_xdiff_file *file, long n, char *changed,
                       bgit_group *g)
{
    if (g->end < n && bgit_lines_match (file, g->start, g->end)) {
        changed[g->start++] = 0;
        changed[g->end++] = 1;
        while (changed[g->end]) g->end++;
        return 0;
    }
    return -1;
}

/* Move each run of changes in FILE to where it reads best, keeping the runs
   in the other file in step so the two descriptions stay paired. A run
   moves where FILE says two lines are the same; how far it should move is
   read off TEXT, which is the same file as it really is where FILE is a
   file of lines with their whitespace taken out. Only when
   INDENT_HEURISTIC does indentation get a say; git leaves it out of a diff
   of words, where indentation means nothing. */
static int
bgit_compact (const bgit_xdiff_file *file, const bgit_xdiff_file *text, long n,
              char *changed, long other_n, char *other_changed,
              int indent_heuristic)
{
    bgit_group g, go;
    bgit_group_init (changed, &g);
    bgit_group_init (other_changed, &go);

    for (;;) {
        if (g.end == g.start) goto next;

        long size, earliest_end, matching_other;
        do {
            size = g.end - g.start;
            matching_other = -1;
            while (!bgit_group_slide_up (file, changed, &g))
                if (bgit_group_previous (other_changed, &go)) break;
            /* This is as high as the run will go. From here down, every
               position at which a run of the other file stands beside it is
               one it could be lined up with, and the last such position is
               the one git settles on. */
            earliest_end = g.end;
            if (go.end > go.start) matching_other = g.end;
            for (;;) {
                if (bgit_group_slide_down (file, n, changed, &g)) break;
                if (bgit_group_next (other_changed, other_n, &go)) break;
                if (go.end > go.start) matching_other = g.end;
            }
        } while (size != g.end - g.start);

        if (g.end == earliest_end) {
            /* The run cannot move, so there is nothing to choose. */
        } else if (matching_other != -1) {
            /* Line the run up with the last run in the other file it can
               sit beside: a replacement reads better than a delete and an
               add that have drifted apart. */
            while (go.end == go.start) {
                if (bgit_group_slide_up (file, changed, &g)) break;
                if (bgit_group_previous (other_changed, &go)) break;
            }
        } else if (indent_heuristic) {
            /* The run sits as far down as it will go, so every position it
               could take is at or above this one — but no further up than
               its own length, and never more than a hundred lines. */
            long shift = earliest_end;
            if (g.end - size - 1 > shift) shift = g.end - size - 1;
            if (g.end - BGIT_INDENT_MAX_SLIDING > shift)
                shift = g.end - BGIT_INDENT_MAX_SLIDING;
            long best_shift = -1;
            bgit_split_score best = {0, 0};
            for (; shift <= g.end; shift++) {
                bgit_split_measure m;
                bgit_split_score score = {0, 0};
                bgit_measure_split (text, n, shift, &m);
                bgit_score_add_split (&m, &score);
                bgit_measure_split (text, n, shift - size, &m);
                bgit_score_add_split (&m, &score);
                if (best_shift == -1 || bgit_score_cmp (&score, &best) <= 0) {
                    best = score;
                    best_shift = shift;
                }
            }
            while (g.end > best_shift) {
                if (bgit_group_slide_up (file, changed, &g)) break;
                if (bgit_group_previous (other_changed, &go)) break;
            }
        }

    next:
        if (bgit_group_next (changed, n, &g)) break;
        if (bgit_group_next (other_changed, other_n, &go)) break;
    }
    return 0;
}

/* Does this line look like the start of a definition? git asks only what
   its first character is, which is what makes a hunk header name the
   function it sits in. */
static int
bgit_is_func_rec (const bgit_xdiff_file *file, long i)
{
    if (i < 0 || i >= (long) file->n || !file->lengths[i]) return 0;
    unsigned char first = (unsigned char) file->lines[i][0];
    return isalpha (first) || first == '_' || first == '$';
}

/* Is this line blank? git counts a line as blank when there is nothing on
   it at all — or, where whitespace is already being overlooked, when there
   is nothing on it but whitespace. */
static int
bgit_blank_line (const bgit_xdiff_file *file, size_t i, int flags)
{
    if (i >= file->n) return 1;
    if (!(flags & BGIT_XDIFF_WS_MASK)) return file->lengths[i] == 0;
    for (size_t k = 0; k < file->lengths[i]; k++)
        if (!isspace ((unsigned char) file->lines[i][k])) return 0;
    return 1;
}

/* A line with nothing on it but whitespace. */
static int
bgit_is_empty_rec (const bgit_xdiff_file *file, long i)
{
    if (i < 0 || i >= (long) file->n) return 1;
    for (size_t k = 0; k < file->lengths[i]; k++)
        if (!isspace ((unsigned char) file->lines[i][k])) return 0;
    return 1;
}

/* The nearest line at or beyond START, looking towards LIMIT, that opens a
   definition. -1 when there is none that way. */
static long
bgit_func_line (const bgit_xdiff_file *file, long start, long limit)
{
    long step = start > limit ? -1 : 1;
    for (long l = start; l != limit && l >= 0 && l < (long) file->n; l += step)
        if (bgit_is_func_rec (file, l)) return l;
    return -1;
}

/* ------------------------------------------------------------- the hunks */

int
bgit_xdiff (const bgit_xdiff_file *old, const bgit_xdiff_file *new_file,
            int context, bgit_xdiff_result *out)
{
    return bgit_xdiff_opts (old, new_file, context,
                            BGIT_XDIFF_INDENT_HEURISTIC |
                            (context ? 0 : BGIT_XDIFF_TRIM_TAIL), out);
}

/* How much of a shared tail git sets aside at a time. */
#define BGIT_TRIM_BLOCK 1024

int
bgit_xdiff_opts (const bgit_xdiff_file *old, const bgit_xdiff_file *new_file,
                 int context, int flags, bgit_xdiff_result *out)
{
    return bgit_xdiff_full (old, new_file, context, 0, flags, out);
}

int
bgit_xdiff_full (const bgit_xdiff_file *old, const bgit_xdiff_file *new_file,
                 int context, int inter_context, int flags,
                 bgit_xdiff_result *out)
{
    int indent_heuristic = (flags & BGIT_XDIFF_INDENT_HEURISTIC) != 0;
    memset (out, 0, sizeof *out);
    if (context < 0) context = 0;

    /* One spare byte at each end, so a scan may look just past either. */
    char *ca = calloc (old->n + 2, 1);
    char *cb = calloc (new_file->n + 2, 1);
    if (!ca || !cb) {
        free (ca);
        free (cb);
        return -1;
    }
    out->old_changed = ca + 1;
    out->new_changed = cb + 1;

    /* Reduce the problem before searching it, as git does. First trim the
       lines the two files already share at top and bottom. Then leave out
       of the search every line between that matches nothing in the other
       file — it can be part of no match, so it is changed and that is that
       — and every line matching so many that a match would mean little,
       when the lines around it match nothing either. Leaving these out is
       most of what makes two equally short answers come out the same way
       round as git's. */
    size_t n_old = old->n, n_new = new_file->n;
    if (flags & BGIT_XDIFF_TRIM_TAIL) {
        size_t trimmed = 0, recovered = 0;
        size_t smaller = old->len < new_file->len ? old->len : new_file->len;
        const char *tail_old = old->text + old->len;
        const char *tail_new = new_file->text + new_file->len;
        while (BGIT_TRIM_BLOCK + trimmed <= smaller &&
               !memcmp (tail_old - BGIT_TRIM_BLOCK, tail_new - BGIT_TRIM_BLOCK,
                        BGIT_TRIM_BLOCK)) {
            trimmed += BGIT_TRIM_BLOCK;
            tail_old -= BGIT_TRIM_BLOCK;
            tail_new -= BGIT_TRIM_BLOCK;
        }
        /* Give back enough of the tail to start on a line. */
        while (recovered < trimmed)
            if (tail_old[recovered++] == '\n') break;
        size_t cut = trimmed - recovered;
        if (cut) {
            n_old = bgit_lines_within (old, old->len - cut);
            n_new = bgit_lines_within (new_file, new_file->len - cut);
        }
    }

    /* Where whitespace is to be overlooked, what gets compared is a file of
       lines with theirs taken out; the files themselves are still what the
       patch shows, and still what indentation is read from. */
    const bgit_xdiff_file *key_old = old, *key_new = new_file;
    bgit_xdiff_file canon_old, canon_new;
    char *canon_old_text = NULL, *canon_new_text = NULL;
    memset (&canon_old, 0, sizeof canon_old);
    memset (&canon_new, 0, sizeof canon_new);
    if ((flags & BGIT_XDIFF_WS_MASK) &&
        bgit_canonical_file (old, flags, &canon_old, &canon_old_text) == 0 &&
        bgit_canonical_file (new_file, flags, &canon_new, &canon_new_text) == 0) {
        key_old = &canon_old;
        key_new = &canon_new;
    }

    int algorithm = flags & (BGIT_XDIFF_MINIMAL | BGIT_XDIFF_PATIENCE |
                             BGIT_XDIFF_HISTOGRAM);
    int alternate = (algorithm & (BGIT_XDIFF_PATIENCE |
                                  BGIT_XDIFF_HISTOGRAM)) != 0;
    long dstart = 0, tail = 0;
    if (!alternate) {
        long shared = (long) (n_old < n_new ? n_old : n_new);
        while (dstart < shared &&
               bgit_line_same (key_old, dstart, key_new, dstart))
            dstart++;
        while (tail < shared - dstart &&
               bgit_line_same (key_old, (long) n_old - 1 - tail,
                               key_new, (long) n_new - 1 - tail))
            tail++;
    }
    long dend_old = (long) n_old - tail - 1;
    long dend_new = (long) n_new - tail - 1;

    char *dis_old = calloc (n_old + 1, 1);
    char *dis_new = calloc (n_new + 1, 1);
    size_t *ia = malloc ((n_old + 1) * sizeof *ia);
    size_t *ib = malloc ((n_new + 1) * sizeof *ib);
    if (!dis_old || !dis_new || !ia || !ib) {
        free (dis_old); free (dis_new); free (ia); free (ib);
        bgit_xdiff_release (&canon_old);
        bgit_xdiff_release (&canon_new);
        free (canon_old_text);
        free (canon_new_text);
        bgit_xdiff_result_release (out);
        return -1;
    }

    long *count_in_new = NULL, *count_in_old = NULL;
    if (bgit_match_counts (key_old, n_old, key_new, n_new, NULL, NULL,
                           &count_in_new, &count_in_old) < 0) {
        free (dis_old); free (dis_new); free (ia); free (ib);
        bgit_xdiff_release (&canon_old);
        bgit_xdiff_release (&canon_new);
        free (canon_old_text); free (canon_new_text);
        bgit_xdiff_result_release (out);
        return -1;
    }
    long limit = bgit_bogosqrt ((long) n_old);
    if (limit > BGIT_MAX_EQLIMIT) limit = BGIT_MAX_EQLIMIT;
    for (long i = dstart; i <= dend_old; i++) {
        long matches = count_in_new[i];
        dis_old[i] = matches == 0 ? 0 : matches >= limit ? 2 : 1;
    }
    limit = bgit_bogosqrt ((long) n_new);
    if (limit > BGIT_MAX_EQLIMIT) limit = BGIT_MAX_EQLIMIT;
    for (long j = dstart; j <= dend_new; j++) {
        long matches = count_in_old[j];
        dis_new[j] = matches == 0 ? 0 : matches >= limit ? 2 : 1;
    }
    free (count_in_new);
    free (count_in_old);

    size_t na = 0, nb = 0;
    if (alternate) {
        for (long i = dstart; i <= dend_old; i++) ia[na++] = (size_t) i;
        for (long j = dstart; j <= dend_new; j++) ib[nb++] = (size_t) j;
    } else {
        for (long i = dstart; i <= dend_old; i++) {
            if (dis_old[i] == 1 ||
                (dis_old[i] == 2 &&
                 !bgit_clean_mmatch (dis_old, i, dstart, dend_old)))
                ia[na++] = (size_t) i;
            else out->old_changed[i] = 1;
        }
        for (long j = dstart; j <= dend_new; j++) {
            if (dis_new[j] == 1 ||
                (dis_new[j] == 2 &&
                 !bgit_clean_mmatch (dis_new, j, dstart, dend_new)))
                ib[nb++] = (size_t) j;
            else out->new_changed[j] = 1;
        }
    }
    /* One diagonal either side of every one the box can hold, and the
       middle of the array is the diagonal through the origin. */
    long ndiags = (long) (na + nb) + 3;
    long *vf = calloc ((size_t) ndiags, sizeof *vf);
    long *vb = calloc ((size_t) ndiags, sizeof *vb);
    if (!vf || !vb) {
        free (vf); free (vb); free (ia); free (ib);
        free (dis_old); free (dis_new);
        bgit_xdiff_release (&canon_old);
        bgit_xdiff_release (&canon_new);
        free (canon_old_text);
        free (canon_new_text);
        bgit_xdiff_result_release (out);
        return -1;
    }
    long mxcost = bgit_bogosqrt (ndiags);
    if (mxcost < BGIT_MAX_COST_MIN) mxcost = BGIT_MAX_COST_MIN;

    bgit_xd x = {key_old, key_new, ia, ib, out->old_changed, out->new_changed,
                 vf + nb + 1, vb + nb + 1, mxcost, algorithm,
                 dis_old, dis_new, dstart, dend_old, dend_new};
    int compared = bgit_xd_compare (&x, 0, (long) na, 0, (long) nb,
                                    (flags & BGIT_XDIFF_MINIMAL) != 0);
    if (compared < 0) {
        free (vf); free (vb); free (ia); free (ib);
        free (dis_old); free (dis_new);
        bgit_xdiff_release (&canon_old);
        bgit_xdiff_release (&canon_new);
        free (canon_old_text); free (canon_new_text);
        bgit_xdiff_result_release (out);
        return -1;
    }

    if (bgit_compact (key_old, old, (long) n_old, out->old_changed,
                      (long) n_new, out->new_changed,
                      indent_heuristic) < 0 ||
        bgit_compact (key_new, new_file, (long) n_new, out->new_changed,
                      (long) n_old, out->old_changed,
                      indent_heuristic) < 0) {
        free (vf); free (vb); free (ia); free (ib);
        free (dis_old); free (dis_new);
        bgit_xdiff_release (&canon_old);
        bgit_xdiff_release (&canon_new);
        free (canon_old_text); free (canon_new_text);
        bgit_xdiff_result_release (out);
        return -1;
    }
    free (vf); free (vb); free (ia); free (ib);
    free (dis_old); free (dis_new);
    bgit_xdiff_release (&canon_old);
    bgit_xdiff_release (&canon_new);
    free (canon_old_text);
    free (canon_new_text);

    for (size_t i = 0; i < old->n; i++) out->removed += !!out->old_changed[i];
    for (size_t j = 0; j < new_file->n; j++) out->added += !!out->new_changed[j];
    if (!out->added && !out->removed) return 0;

    /* Gather the runs of change, then give each hunk its context: two runs
       no further apart than twice that become one hunk, and where the whole
       definition is asked for a hunk reaches back to the line that opens the
       one it sits in and forward to the line that opens the next. */
    int whole_function = (flags & BGIT_XDIFF_FUNCTION_CONTEXT) != 0;
    int skip_blank = (flags & BGIT_XDIFF_IGNORE_BLANK_LINES) != 0;
    size_t capacity = 8;
    bgit_xdiff_hunk *hunks = calloc (capacity, sizeof *hunks);
    if (!hunks) { bgit_xdiff_result_release (out); return -1; }
    size_t n_hunks = 0;
    bgit_xdiff_change *runs = NULL;
    size_t n_runs = 0;
    if (bgit_xdiff_changes (out, old->n, new_file->n, &runs, &n_runs) < 0) {
        free (hunks);
        bgit_xdiff_result_release (out);
        return -1;
    }

    /* Which runs are nothing but blank lines, when that is to be overlooked.
       One of them is still shown where it sits among changes that are not:
       what is skipped is a run standing on its own. */
    char *skippable = NULL;
    if (skip_blank && n_runs) {
        skippable = calloc (n_runs, 1);
        if (!skippable) {
            free (runs);
            free (hunks);
            bgit_xdiff_result_release (out);
            return -1;
        }
        for (size_t k = 0; k < n_runs; k++) {
            int blank = 1;
            for (size_t i = 0; blank && i < runs[k].old_count; i++)
                blank = bgit_blank_line (old, runs[k].old_start + i, flags);
            for (size_t j = 0; blank && j < runs[k].new_count; j++)
                blank = bgit_blank_line (new_file, runs[k].new_start + j, flags);
            skippable[k] = (char) blank;
        }
    }
    long max_ignorable = context;
    /* How far apart two runs may be and still be shown as one hunk: the
       context each would print, and what --inter-hunk-context adds. */
    long max_common = 2 * context + (inter_context > 0 ? inter_context : 0);
    size_t kept_added = 0, kept_removed = 0;

    for (size_t r = 0; r < n_runs; ) {
        /* A blank run far enough in front of the next change is passed over
           altogether, along with anything blank before it. */
        for (size_t k = r; skippable && k < n_runs && skippable[k]; k++) {
            size_t next = k + 1;
            if (next >= n_runs ||
                (long) runs[next].old_start -
                (long) (runs[k].old_start + runs[k].old_count) >= max_ignorable)
                r = next;
        }
        if (r >= n_runs) break;

        size_t last = r;
        long ignored = 0;
        for (size_t prev = r, k = r + 1; k < n_runs; prev = k, k++) {
            long distance = (long) runs[k].old_start -
                            (long) (runs[prev].old_start + runs[prev].old_count);
            if (distance > max_common) break;
            int blank = skippable && skippable[k];
            if (distance < max_ignorable && (!blank || last == prev)) {
                last = k;
                ignored = 0;
            } else if (distance < max_ignorable && blank) {
                ignored += (long) runs[k].new_count;
            } else if (last != prev &&
                       (long) runs[k].old_start + ignored -
                       (long) (runs[last].old_start + runs[last].old_count) >
                       max_common) {
                break;
            } else if (!blank) {
                last = k;
                ignored = 0;
            } else {
                ignored += (long) runs[k].new_count;
            }
        }

        long s1 = (long) runs[r].old_start - context;
        long s2 = (long) runs[r].new_start - context;
        if (s1 < 0) s1 = 0;
        if (s2 < 0) s2 = 0;
        if (whole_function) {
            long i1 = (long) runs[r].old_start;
            int appended = 0;
            /* A run past the end of the old file has nothing above it to
               reach back to, and a whole definition added needs nothing. */
            if (i1 >= (long) old->n) {
                for (long i2 = (long) runs[r].new_start;
                     i2 < (long) new_file->n; i2++)
                    if (bgit_is_func_rec (new_file, i2)) { appended = 1; break; }
                if (!appended) i1 = (long) old->n - 1;
            }
            if (!appended) {
                long fs1 = bgit_func_line (old, i1, -1);
                while (fs1 > 0 && !bgit_is_empty_rec (old, fs1 - 1) &&
                       !bgit_is_func_rec (old, fs1 - 1))
                    fs1--;
                if (fs1 < 0) fs1 = 0;
                if (fs1 < s1) {
                    s2 -= s1 - fs1;
                    if (s2 < 0) s2 = 0;
                    s1 = fs1;
                }
            }
        }

        long e1, e2;
        for (;;) {
            long end1 = (long) (runs[last].old_start + runs[last].old_count);
            long end2 = (long) (runs[last].new_start + runs[last].new_count);
            long lctx = context;
            if (lctx > (long) old->n - end1) lctx = (long) old->n - end1;
            if (lctx > (long) new_file->n - end2) lctx = (long) new_file->n - end2;
            e1 = end1 + lctx;
            e2 = end2 + lctx;
            if (!whole_function) break;
            long fe1 = bgit_func_line (old, end1, (long) old->n);
            while (fe1 > 0 && bgit_is_empty_rec (old, fe1 - 1)) fe1--;
            if (fe1 < 0) fe1 = (long) old->n;
            if (fe1 > e1) {
                e2 += fe1 - e1;
                if (e2 > (long) new_file->n) e2 = (long) new_file->n;
                e1 = fe1;
            }
            /* Does the next run fall inside what this hunk now covers? Then
               it belongs to it, and the end has to be found again. */
            if (last + 1 >= n_runs) break;
            long next = (long) runs[last + 1].old_start;
            if (next > (long) old->n - 1) next = (long) old->n - 1;
            if (next - context <= e1 || bgit_func_line (old, next, e1) < 0) {
                last++;
                continue;
            }
            break;
        }

        if (n_hunks == capacity) {
            capacity *= 2;
            bgit_xdiff_hunk *grown = realloc (hunks, capacity * sizeof *grown);
            if (!grown) {
                free (runs);
                free (hunks);
                bgit_xdiff_result_release (out);
                return -1;
            }
            hunks = grown;
        }
        hunks[n_hunks].old_start = (size_t) s1;
        hunks[n_hunks].old_count = (size_t) (e1 - s1);
        hunks[n_hunks].new_start = (size_t) s2;
        hunks[n_hunks].new_count = (size_t) (e2 - s2);
        n_hunks++;
        for (size_t k = r; k <= last; k++) {
            kept_removed += runs[k].old_count;
            kept_added += runs[k].new_count;
        }
        r = last + 1;
    }
    /* What was passed over was not changed as far as anyone is told, and
       the counts a stat is made of say so. */
    if (skippable) {
        out->added = kept_added;
        out->removed = kept_removed;
    }
    free (skippable);
    free (runs);
    out->hunks = hunks;
    out->n_hunks = n_hunks;
    return 0;
}

int
bgit_xdiff_changes (const bgit_xdiff_result *result, size_t n_old, size_t n_new,
                    bgit_xdiff_change **out, size_t *n_out)
{
    size_t capacity = 8, n = 0;
    bgit_xdiff_change *changes = calloc (capacity, sizeof *changes);
    if (!changes) return -1;
    size_t i = 0, j = 0;
    while (i < n_old || j < n_new) {
        int changed = (i < n_old && result->old_changed[i]) ||
                      (j < n_new && result->new_changed[j]);
        if (!changed) { i++; j++; continue; }
        size_t i0 = i, j0 = j;
        while (i < n_old && result->old_changed[i]) i++;
        while (j < n_new && result->new_changed[j]) j++;
        if (n == capacity) {
            capacity *= 2;
            bgit_xdiff_change *grown = realloc (changes, capacity * sizeof *grown);
            if (!grown) { free (changes); return -1; }
            changes = grown;
        }
        changes[n].old_start = i0;
        changes[n].old_count = i - i0;
        changes[n].new_start = j0;
        changes[n].new_count = j - j0;
        n++;
    }
    *out = changes;
    *n_out = n;
    return 0;
}

long
bgit_xdiff_function (const bgit_xdiff_file *file, long start, long limit,
                     const char **text, size_t *len)
{
    for (long i = start; i > limit && i >= 0 && i < (long) file->n; i--) {
        const char *line = file->lines[i];
        size_t length = file->lengths[i];
        if (!length) continue;
        unsigned char first = (unsigned char) line[0];
        if (!isalpha (first) && first != '_' && first != '$') continue;
        if (length > 80) length = 80;
        while (length > 0 && isspace ((unsigned char) line[length - 1])) length--;
        *text = line;
        *len = length;
        return i;
    }
    return -1;
}
