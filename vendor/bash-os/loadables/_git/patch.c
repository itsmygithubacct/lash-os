/* SPDX-License-Identifier: MIT */
/* _git/patch.c — turning a list of changed paths into what git prints.
 * See patch.h.
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
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "loadables.h"

#include "patch.h"
#include "xdiff.h"

void
bgit_patch_options_init (bgit_patch_options *options)
{
    memset (options, 0, sizeof *options);
    options->context = 3;
    options->abbrev = 7;
    options->prefix_old = "a/";
    options->prefix_new = "b/";
    options->line_prefix = "";
}


/* ---- word diff ---------------------------------------------------------- */

/* One side of a hunk, as words: the text it holds and where each word sits
   in it. What lies between words is whitespace, which is written out with
   the side it came from rather than compared. */
typedef struct {
    char *text;
    size_t len, cap;
    struct { size_t begin, end; } *words;
    size_t n_words, cap_words;
} bgit_word_side;

static void
bgit_word_side_release (bgit_word_side *side)
{
    free (side->text);
    free (side->words);
    memset (side, 0, sizeof *side);
}

static int
bgit_word_side_add (bgit_word_side *side, const char *line, size_t len)
{
    if (side->len + len + 1 > side->cap) {
        size_t next = side->cap ? side->cap : 256;
        while (next < side->len + len + 1) next *= 2;
        char *grown = realloc (side->text, next);
        if (!grown) return -1;
        side->text = grown;
        side->cap = next;
    }
    memcpy (side->text + side->len, line, len);
    side->len += len;
    side->text[side->len] = '\0';
    return 0;
}

/* Where the words are: every run of anything that is not whitespace. */
static int
bgit_word_side_split (bgit_word_side *side)
{
    for (size_t at = 0; at < side->len;) {
        while (at < side->len && isspace ((unsigned char) side->text[at])) at++;
        if (at >= side->len) break;
        size_t begin = at;
        while (at < side->len && !isspace ((unsigned char) side->text[at])) at++;
        if (side->n_words == side->cap_words) {
            size_t next = side->cap_words ? side->cap_words * 2 : 64;
            void *grown = realloc (side->words, next * sizeof *side->words);
            if (!grown) return -1;
            side->words = grown;
            side->cap_words = next;
        }
        side->words[side->n_words].begin = begin;
        side->words[side->n_words].end = at;
        side->n_words++;
    }
    return 0;
}

/* The words, one to a line, which is what the line differ can compare. */
static char *
bgit_word_side_lines (const bgit_word_side *side, size_t *out_len)
{
    size_t len = 0;
    for (size_t i = 0; i < side->n_words; i++)
        len += side->words[i].end - side->words[i].begin + 1;
    char *text = malloc (len + 1);
    if (!text) return NULL;
    size_t at = 0;
    for (size_t i = 0; i < side->n_words; i++) {
        size_t n = side->words[i].end - side->words[i].begin;
        memcpy (text + at, side->text + side->words[i].begin, n);
        at += n;
        text[at++] = '\n';
    }
    text[at] = '\0';
    *out_len = at;
    return text;
}

/* A run of text, marked as git marks it: as it stands, taken away, or put
   in. Each line of it is written on its own, since a run can cross one. */
static void
bgit_word_write (FILE *out, const char *lp, int porcelain, char kind,
                 const char *text, size_t len, int *at_line_start)
{
    static const char *const open[] = { "", "[-", "{+" };
    static const char *const close[] = { "", "-]", "+}" };
    int which = kind == '-' ? 1 : kind == '+' ? 2 : 0;
    size_t at = 0;
    while (at < len) {
        const char *nl = memchr (text + at, '\n', len - at);
        size_t piece = nl ? (size_t) (nl - (text + at)) : len - at;
        if (porcelain) {
            if (piece) {
                fprintf (out, "%s%c", lp, kind);
                fwrite (text + at, 1, piece, out);
                fputc ('\n', out);
            }
            if (nl) fprintf (out, "%s~\n", lp);
            *at_line_start = 1;
        } else {
            if (piece) {
                /* Each line carries whatever a log indents with, written
                   once when the line starts. */
                if (*at_line_start) { fputs (lp, out); *at_line_start = 0; }
                fputs (open[which], out);
                fwrite (text + at, 1, piece, out);
                fputs (close[which], out);
            }
            if (nl) {
                if (*at_line_start) fputs (lp, out);
                fputc ('\n', out);
                *at_line_start = 1;
            }
        }
        if (!nl) break;
        at += piece + 1;
    }
}

/* core.quotePath: with it set, which is git's default, a byte outside ASCII
   is written as its octal escape rather than passed through. */
int bgit_quote_path_fully = 1;

/* git quotes a name when a byte of it would not read back as itself: a
   control character, a quote, a backslash — and, unless core.quotePath says
   otherwise, anything outside ASCII. A space only forces it where the caller
   asks, which is what the short status does so that its columns can be told
   apart. */
static int
bgit_quote_needed (const char *path, int spaces)
{
    for (const char *p = path; *p; p++) {
        unsigned char c = (unsigned char) *p;
        if (c < 0x20 || c == 0x7f || c == '"' || c == '\\') return 1;
        if (c >= 0x80 && bgit_quote_path_fully) return 1;
        if (c == ' ' && spaces) return 1;
    }
    return 0;
}

/* The bytes of a name inside the quotes. Returns how much was written. */
static size_t
bgit_quote_body (const char *path, char *buf, size_t at, size_t size)
{
    for (const char *p = path; *p && at + 5 < size; p++) {
        unsigned char c = (unsigned char) *p;
        const char *escape = NULL;
        switch (c) {
        case '"': escape = "\\\""; break;
        case '\\': escape = "\\\\"; break;
        case '\a': escape = "\\a"; break;
        case '\b': escape = "\\b"; break;
        case '\f': escape = "\\f"; break;
        case '\n': escape = "\\n"; break;
        case '\r': escape = "\\r"; break;
        case '\t': escape = "\\t"; break;
        case '\v': escape = "\\v"; break;
        default: break;
        }
        if (escape) {
            at += (size_t) snprintf (buf + at, size - at, "%s", escape);
        } else if (c < 0x20 || c == 0x7f ||
                   (c >= 0x80 && bgit_quote_path_fully)) {
            at += (size_t) snprintf (buf + at, size - at, "\\%03o", c);
        } else {
            buf[at++] = (char) c;
        }
    }
    return at;
}

const char *
bgit_quote_path (const char *path, char *buf, size_t size)
{
    if (!bgit_quote_needed (path, 0)) return path;
    size_t at = 0;
    if (at + 1 < size) buf[at++] = '"';
    at = bgit_quote_body (path, buf, at, size);
    if (at + 2 < size) buf[at++] = '"';
    buf[at] = '\0';
    return buf;
}

const char *
bgit_quote_path_sp (const char *path, char *buf, size_t size)
{
    if (!bgit_quote_needed (path, 1)) return path;
    size_t at = 0;
    if (at + 1 < size) buf[at++] = '"';
    at = bgit_quote_body (path, buf, at, size);
    if (at + 2 < size) buf[at++] = '"';
    buf[at] = '\0';
    return buf;
}

const char *
bgit_quote_two (const char *first, const char *second, char *buf, size_t size)
{
    if (!bgit_quote_needed (first, 0) && !bgit_quote_needed (second, 0)) {
        snprintf (buf, size, "%s%s", first, second);
        return buf;
    }
    size_t at = 0;
    if (at + 1 < size) buf[at++] = '"';
    at = bgit_quote_body (first, buf, at, size);
    at = bgit_quote_body (second, buf, at, size);
    if (at + 2 < size) buf[at++] = '"';
    buf[at] = '\0';
    return buf;
}

/* Read a file in the working tree, following git's view of a symlink: its
   content is the path it points at. */
int
bgit_read_worktree_file (const bgit_repo *repo, const char *path,
                         char **data, size_t *len)
{
    char full[4096];
    if (!repo || !repo->work_tree ||
        snprintf (full, sizeof full, "%s/%s", repo->work_tree, path) >=
        (int) sizeof full)
        return -1;
    struct stat st;
    if (lstat (full, &st) < 0) return -1;
    if (S_ISLNK (st.st_mode)) {
        size_t size = (size_t) st.st_size + 1;
        char *target = malloc (size + 1);
        if (!target) return -1;
        ssize_t got = readlink (full, target, size);
        if (got < 0) { free (target); return -1; }
        target[got] = '\0';
        *data = target;
        *len = (size_t) got;
        return 0;
    }
    int fd = open (full, O_RDONLY);
    if (fd < 0) return -1;
    size_t size = (size_t) st.st_size, at = 0;
    char *buf = malloc (size + 1);
    if (!buf) { close (fd); return -1; }
    while (at < size) {
        ssize_t got = read (fd, buf + at, size - at);
        if (got < 0) {
            if (errno == EINTR) continue;
            free (buf);
            close (fd);
            return -1;
        }
        if (!got) break;
        at += (size_t) got;
    }
    close (fd);
    buf[at] = '\0';
    *data = buf;
    *len = at;
    return 0;
}

int
bgit_patch_content (bgit_odb *odb, const bgit_repo *repo,
                    const bgit_diff_entry *entry, int side,
                    const bgit_patch_options *options,
                    char **data, size_t *len)
{
    *data = NULL;
    *len = 0;
    const char *sha = side ? entry->new_sha : entry->old_sha;
    if (side ? entry->status == 'D'
             : (entry->status == 'A' || !*entry->old_sha)) {
        *data = malloc (1);
        if (!*data) return -1;
        (*data)[0] = '\0';
        return 0;
    }
    /* A submodule has no blob. What git shows for one is the line that
       names the commit it points at. */
    if ((side ? entry->new_mode : entry->old_mode) == 0160000) {
        char line[80];
        int wrote = snprintf (line, sizeof line, "Subproject commit %s\n", sha);
        if (wrote < 0 || wrote >= (int) sizeof line) return -1;
        *data = malloc ((size_t) wrote + 1);
        if (!*data) return -1;
        memcpy (*data, line, (size_t) wrote + 1);
        *len = (size_t) wrote;
        return 0;
    }
    if (side && options->new_from_worktree)
        return bgit_read_worktree_file (repo, entry->path, data, len);

    enum bgit_type type;
    unsigned char *content = NULL;
    size_t size = 0;
    if (bgit_odb_read (odb, sha, &type, &content, &size) < 0) return -1;
    *data = (char *) content;
    *len = size;
    return 0;
}

const char *bgit_relative_to;

/* A path as a patch names it: with --relative, what is under the place it is
   relative to is named from there. */
static const char *
bgit_shown_path (const char *path)
{
    size_t off = bgit_relative_to ? strlen (bgit_relative_to) : 0;
    if (off && !strncmp (path, bgit_relative_to, off)) return path + off;
    return path;
}

/* The header lines every changed path starts with. */
static void
bgit_patch_header (FILE *out, const bgit_diff_entry *entry,
                   const bgit_patch_options *options, int identical)
{
    char quoted[8192];
    const char *name = bgit_quote_path (bgit_shown_path (entry->path),
                                        quoted, sizeof quoted);
    const char *lp = options->line_prefix;
    char from_quoted[8192];
    const char *from = entry->from
        ? bgit_quote_path (bgit_shown_path (entry->from), from_quoted,
                           sizeof from_quoted) : name;
    /* The prefix and the name are one name on this line: where either wants
       quoting, git quotes the pair of them together. */
    char old_side[8320], new_side[8320];
    fprintf (out, "%sdiff --git %s %s\n", lp,
             bgit_quote_two (options->prefix_old,
                             bgit_shown_path (entry->from ? entry->from
                                                          : entry->path),
                             old_side, sizeof old_side),
             bgit_quote_two (options->prefix_new,
                             bgit_shown_path (entry->path), new_side,
                             sizeof new_side));

    if (entry->status == 'R') {
        /* The percentage is the score out of git's sixty thousand. */
        fprintf (out, "%ssimilarity index %d%%\n", lp,
                 entry->score * 100 / 60000);
        fprintf (out, "%srename from %s\n", lp, from);
        fprintf (out, "%srename to %s\n", lp, name);
    }
    if (entry->status == 'A')
        fprintf (out, "%snew file mode %06o\n", lp, entry->new_mode);
    else if (entry->status == 'D')
        fprintf (out, "%sdeleted file mode %06o\n", lp, entry->old_mode);
    else if (entry->old_mode != entry->new_mode) {
        fprintf (out, "%sold mode %06o\n", lp, entry->old_mode);
        fprintf (out, "%snew mode %06o\n", lp, entry->new_mode);
    }
    if (identical) return;   /* nothing moved but the name or the mode */

    int abbrev = options->abbrev;
    char zeros[41];
    memset (zeros, '0', sizeof zeros);
    zeros[abbrev] = '\0';
    const char *old_id = entry->status == 'A' ? zeros : entry->old_sha;
    const char *new_id = entry->status == 'D' ? zeros : entry->new_sha;
    fprintf (out, "%sindex %.*s..%.*s", lp, abbrev, old_id, abbrev, new_id);
    if ((entry->status == 'M' || entry->status == 'R') &&
        entry->old_mode == entry->new_mode)
        fprintf (out, " %06o", entry->new_mode);
    fputc ('\n', out);
}

/* Put out a header that was waiting for something to go under it. */
static void
bgit_patch_held (FILE *out, char **held, size_t len)
{
    if (!*held) return;
    fwrite (*held, 1, len, out);
    free (*held);
    *held = NULL;
}

static void
bgit_patch_range (FILE *out, size_t start, size_t count)
{
    if (count == 1) fprintf (out, "%zu", start + 1);
    else fprintf (out, "%zu,%zu", count ? start + 1 : start, count);
}

static void
bgit_patch_line (FILE *out, const char *lp, char sign,
                 const bgit_xdiff_file *file, size_t index)
{
    fprintf (out, "%s%c", lp, sign);
    fwrite (file->lines[index], 1, file->lengths[index], out);
    fputc ('\n', out);
    if (file->missing_newline && index + 1 == file->n)
        fprintf (out, "%s\\ No newline at end of file\n", lp);
}

/* A symlink, a file and a submodule are different kinds of thing, so a path
   that changed from one to another is shown as a deletion and an addition. */
static int
bgit_mode_kind (uint32_t mode)
{
    return mode == 0120000 ? 1 : mode == 0160000 ? 2 : 0;
}

/* One run of removed and added lines, compared word by word. Each word only
   one side has is bracketed, and what lies between a side's words comes out
   with that side; where nothing was added, the removal is all there is to
   say. */
static void
bgit_word_run (FILE *out, const char *lp, int porcelain,
               const bgit_xdiff_file *old_file, size_t old_from, size_t old_to,
               const bgit_xdiff_file *new_file, size_t new_from, size_t new_to,
               int *at_line_start)
{
    bgit_word_side minus, plus;
    memset (&minus, 0, sizeof minus);
    memset (&plus, 0, sizeof plus);
    int ok = 1;
    for (size_t k = old_from; ok && k < old_to; k++)
        if (bgit_word_side_add (&minus, old_file->lines[k],
                                old_file->lengths[k]) < 0 ||
            bgit_word_side_add (&minus, "\n", 1) < 0)
            ok = 0;
    for (size_t k = new_from; ok && k < new_to; k++)
        if (bgit_word_side_add (&plus, new_file->lines[k],
                                new_file->lengths[k]) < 0 ||
            bgit_word_side_add (&plus, "\n", 1) < 0)
            ok = 0;
    if (ok && (bgit_word_side_split (&minus) < 0 ||
               bgit_word_side_split (&plus) < 0))
        ok = 0;

    if (ok && !plus.len) {
        if (minus.len)
            bgit_word_write (out, lp, porcelain, '-', minus.text, minus.len,
                             at_line_start);
        bgit_word_side_release (&minus);
        bgit_word_side_release (&plus);
        return;
    }

    size_t minus_len = 0, plus_len = 0;
    char *minus_lines = ok ? bgit_word_side_lines (&minus, &minus_len) : NULL;
    char *plus_lines = ok ? bgit_word_side_lines (&plus, &plus_len) : NULL;
    bgit_xdiff_file old_words, new_words;
    bgit_xdiff_result words;
    memset (&old_words, 0, sizeof old_words);
    memset (&new_words, 0, sizeof new_words);
    memset (&words, 0, sizeof words);
    bgit_xdiff_change *runs = NULL;
    size_t n_runs = 0;
    if (ok && minus_lines && plus_lines &&
        bgit_xdiff_load (&old_words, minus_lines, minus_len) == 0 &&
        bgit_xdiff_load (&new_words, plus_lines, plus_len) == 0 &&
        bgit_xdiff_opts (&old_words, &new_words, 0,
                         BGIT_XDIFF_TRIM_TAIL, &words) == 0)
        bgit_xdiff_changes (&words, old_words.n, new_words.n, &runs, &n_runs);

    size_t current = 0;
    for (size_t r = 0; r < n_runs; r++) {
        size_t start;
        if (runs[r].new_count)
            start = plus.words[runs[r].new_start].begin;
        else if (runs[r].new_start)
            start = plus.words[runs[r].new_start - 1].end;
        else start = 0;
        if (start > current)
            bgit_word_write (out, lp, porcelain, ' ', plus.text + current,
                             start - current, at_line_start);
        if (runs[r].old_count) {
            size_t from = minus.words[runs[r].old_start].begin;
            size_t to = minus.words[runs[r].old_start +
                                    runs[r].old_count - 1].end;
            bgit_word_write (out, lp, porcelain, '-', minus.text + from,
                             to - from, at_line_start);
        }
        if (runs[r].new_count) {
            size_t from = plus.words[runs[r].new_start].begin;
            size_t to = plus.words[runs[r].new_start +
                                   runs[r].new_count - 1].end;
            bgit_word_write (out, lp, porcelain, '+', plus.text + from,
                             to - from, at_line_start);
            current = to;
        } else current = start;
    }
    if (plus.len > current)
        bgit_word_write (out, lp, porcelain, ' ', plus.text + current,
                         plus.len - current, at_line_start);

    free (runs);
    bgit_xdiff_result_release (&words);
    bgit_xdiff_release (&old_words);
    bgit_xdiff_release (&new_words);
    free (minus_lines);
    free (plus_lines);
    bgit_word_side_release (&minus);
    bgit_word_side_release (&plus);
}

static int
bgit_patch_single (FILE *out, bgit_odb *odb, const bgit_repo *repo,
                   const bgit_diff_entry *entry,
                   const bgit_patch_options *options)
{
    char *old_data = NULL, *new_data = NULL;
    size_t old_len = 0, new_len = 0;
    if (bgit_patch_content (odb, repo, entry, 0, options, &old_data, &old_len) < 0)
        return -1;
    if (bgit_patch_content (odb, repo, entry, 1, options, &new_data, &new_len) < 0) {
        free (old_data);
        return -1;
    }

    int identical = (entry->status == 'M' || entry->status == 'R') &&
                    !strcmp (entry->old_sha, entry->new_sha);
    /* A path that was added, deleted, renamed or given a new mode has
       something to say whatever its diff comes to, so its header goes out
       now. Any other header waits until there is a line to put under it:
       overlook enough whitespace and there may be none, and then git says
       nothing about the path at all. */
    int must_show = entry->status != 'M' || entry->old_mode != entry->new_mode;
    char *held = NULL;
    size_t held_len = 0;
    FILE *holder = must_show ? NULL : open_memstream (&held, &held_len);
    bgit_patch_header (holder ? holder : out, entry, options, identical);
    if (holder) fclose (holder);
    if (identical) {
        free (held);
        free (old_data);
        free (new_data);
        return 0;
    }

    bgit_xdiff_file old_file, new_file;
    if (bgit_xdiff_load (&old_file, old_data, old_len) < 0 ||
        bgit_xdiff_load (&new_file, new_data, new_len) < 0) {
        bgit_xdiff_release (&old_file);
        free (held);
        free (old_data);
        free (new_data);
        return -1;
    }
    const char *lp = options->line_prefix;
    if (old_file.binary || new_file.binary) {
        char quoted[8192];
        const char *name = bgit_quote_path (entry->path, quoted, sizeof quoted);
        bgit_patch_held (out, &held, held_len);
        fprintf (out, "%sBinary files %s%s and %s%s differ\n", lp,
                 entry->status == 'A' ? "" : options->prefix_old,
                 entry->status == 'A' ? "/dev/null" : name,
                 entry->status == 'D' ? "" : options->prefix_new,
                 entry->status == 'D' ? "/dev/null" : name);
        bgit_xdiff_release (&old_file);
        bgit_xdiff_release (&new_file);
        free (old_data);
        free (new_data);
        return 0;
    }

    bgit_xdiff_result result;
    /* The tail is only set aside where none of it could be shown, and asking
       for the whole definition can show any of it. */
    int diff_flags = BGIT_XDIFF_INDENT_HEURISTIC | options->ignore_ws |
                     (options->algorithm == BGIT_DIFF_ALGORITHM_MINIMAL
                      ? BGIT_XDIFF_MINIMAL :
                      options->algorithm == BGIT_DIFF_ALGORITHM_PATIENCE
                      ? BGIT_XDIFF_PATIENCE :
                      options->algorithm == BGIT_DIFF_ALGORITHM_HISTOGRAM
                      ? BGIT_XDIFF_HISTOGRAM : 0) |
                     (options->ignore_blank_lines
                      ? BGIT_XDIFF_IGNORE_BLANK_LINES : 0) |
                     (options->function_context
                      ? BGIT_XDIFF_FUNCTION_CONTEXT
                      : options->context ? 0 : BGIT_XDIFF_TRIM_TAIL);
    if (bgit_xdiff_full (&old_file, &new_file, options->context,
                         options->inter_context, diff_flags, &result) < 0) {
        bgit_xdiff_release (&old_file);
        bgit_xdiff_release (&new_file);
        free (held);
        free (old_data);
        free (new_data);
        return -1;
    }

    if (result.n_hunks) {
        bgit_patch_held (out, &held, held_len);
        /* The prefix and the name are quoted together, and a name with a
           space in it ends in a tab so that the two can be told apart —
           both of which git does here. */
        char old_side[8320], new_side[8320];
        /* A rename's old side is named where it used to live. */
        const char *from = bgit_quote_two (options->prefix_old,
                                           bgit_shown_path (entry->from
                                                            ? entry->from
                                                            : entry->path),
                                           old_side, sizeof old_side);
        const char *name = bgit_quote_two (options->prefix_new,
                                           bgit_shown_path (entry->path),
                                           new_side, sizeof new_side);
        if (entry->status == 'A')
            fprintf (out, "%s--- /dev/null\n", lp);
        else
            fprintf (out, "%s--- %s%s\n", lp, from,
                     strchr (from, ' ') ? "\t" : "");
        if (entry->status == 'D')
            fprintf (out, "%s+++ /dev/null\n", lp);
        else
            fprintf (out, "%s+++ %s%s\n", lp, name,
                     strchr (name, ' ') ? "\t" : "");
    }

    for (size_t h = 0; h < result.n_hunks; h++) {
        const bgit_xdiff_hunk *hunk = &result.hunks[h];
        fprintf (out, "%s@@ -", lp);
        bgit_patch_range (out, hunk->old_start, hunk->old_count);
        fprintf (out, " +");
        bgit_patch_range (out, hunk->new_start, hunk->new_count);
        fprintf (out, " @@");
        const char *text = NULL;
        size_t length = 0;
        /* Each hunk looks as far up as it needs to, and two hunks inside the
           same definition both name it, as git's headers do. */
        long line = bgit_xdiff_function (&old_file, (long) hunk->old_start - 1,
                                         -1, &text, &length);
        if (line >= 0 && length) {
            fputc (' ', out);
            fwrite (text, 1, length, out);
        }
        fputc ('\n', out);

        size_t i = hunk->old_start, j = hunk->new_start;
        size_t end_old = i + hunk->old_count, end_new = j + hunk->new_count;
        if (options->word_diff) {
            /* git takes the words a run of changed lines at a time: a line
               of context is put out as it stands, and the removed and added
               lines between two of them make one comparison of their own,
               so nothing can drift across a line that did not change. */
            int porcelain = options->word_diff == 2;
            int at_line_start = 1;
            while (i < end_old || j < end_new) {
                int changed = (i < end_old && result.old_changed[i]) ||
                              (j < end_new && result.new_changed[j]);
                if (!changed) {
                    /* A line nothing happened to stands as it is, as the new
                       side has it — which is the side git shows, and only
                       tells the two apart where whitespace is overlooked. In
                       the porcelain it keeps the leading space even when
                       there is nothing after it, unlike a word that comes
                       out empty. */
                    if (porcelain) {
                        fprintf (out, "%s ", lp);
                        fwrite (new_file.lines[j], 1, new_file.lengths[j], out);
                        fprintf (out, "\n%s~\n", lp);
                        at_line_start = 1;
                    } else {
                        bgit_word_write (out, lp, porcelain, ' ',
                                         new_file.lines[j], new_file.lengths[j],
                                         &at_line_start);
                        bgit_word_write (out, lp, porcelain, ' ', "\n", 1,
                                         &at_line_start);
                    }
                    i++;
                    j++;
                    continue;
                }
                size_t from_old = i, from_new = j;
                while (i < end_old && result.old_changed[i]) i++;
                while (j < end_new && result.new_changed[j]) j++;
                bgit_word_run (out, lp, porcelain, &old_file, from_old, i,
                               &new_file, from_new, j, &at_line_start);
            }
            /* A hunk ends on a line of its own, even where the last thing
               written did not end one. */
            if (!at_line_start) fputc ('\n', out);
            continue;
        }
        while (i < end_old || j < end_new) {
            int changed = (i < end_old && result.old_changed[i]) ||
                          (j < end_new && result.new_changed[j]);
            if (!changed) {
                /* The new side's copy of a line nothing happened to: with
                   whitespace overlooked the two can differ, and git shows
                   this one. */
                bgit_patch_line (out, lp, ' ', &new_file, j);
                i++;
                j++;
                continue;
            }
            while (i < end_old && result.old_changed[i])
                bgit_patch_line (out, lp, '-', &old_file, i++);
            while (j < end_new && result.new_changed[j])
                bgit_patch_line (out, lp, '+', &new_file, j++);
        }
    }

    bgit_xdiff_result_release (&result);
    bgit_xdiff_release (&old_file);
    bgit_xdiff_release (&new_file);
    free (held);
    free (old_data);
    free (new_data);
    return 0;
}

static int
bgit_patch_one (FILE *out, bgit_odb *odb, const bgit_repo *repo,
                const bgit_diff_entry *entry, const bgit_patch_options *options)
{
    if (entry->status == 'M' &&
        bgit_mode_kind (entry->old_mode) != bgit_mode_kind (entry->new_mode)) {
        bgit_diff_entry removed = *entry, added = *entry;
        removed.status = 'D';
        added.status = 'A';
        return bgit_patch_single (out, odb, repo, &removed, options) < 0 ||
               bgit_patch_single (out, odb, repo, &added, options) < 0 ? -1 : 0;
    }
    return bgit_patch_single (out, odb, repo, entry, options);
}

int
bgit_patch_write (FILE *out, bgit_odb *odb, const bgit_repo *repo,
                  const bgit_diff_entry *entries, size_t n,
                  const bgit_patch_options *options)
{
    for (size_t i = 0; i < n; i++)
        if (bgit_patch_one (out, odb, repo, &entries[i], options) < 0)
            return -1;
    return 0;
}

int
bgit_diffstat (bgit_odb *odb, const bgit_repo *repo,
               const bgit_diff_entry *entries, size_t n,
               const bgit_patch_options *options, bgit_diffstat_entry **out,
               size_t *n_out)
{
    bgit_diffstat_entry *stats = calloc (n ? n : 1, sizeof *stats);
    if (!stats) return -1;
    size_t kept = 0;
    for (size_t i = 0; i < n; i++) {
        bgit_diffstat_entry *stat = &stats[kept++];
        memset (stat, 0, sizeof *stat);
        stat->entry = &entries[i];
        if (entries[i].status == 'M' &&
            !strcmp (entries[i].old_sha, entries[i].new_sha))
            continue;                       /* a mode change counts as nothing */
        char *old_data = NULL, *new_data = NULL;
        size_t old_len = 0, new_len = 0;
        if (bgit_patch_content (odb, repo, &entries[i], 0, options,
                                &old_data, &old_len) < 0 ||
            bgit_patch_content (odb, repo, &entries[i], 1, options,
                                &new_data, &new_len) < 0) {
            free (old_data);
            free (stats);
            return -1;
        }
        bgit_xdiff_file old_file, new_file;
        bgit_xdiff_load (&old_file, old_data, old_len);
        bgit_xdiff_load (&new_file, new_data, new_len);
        if (old_file.binary || new_file.binary) {
            stat->binary = 1;
            stat->removed = old_len;
            stat->added = new_len;
        } else {
            bgit_xdiff_result result;
            int diff_flags = BGIT_XDIFF_INDENT_HEURISTIC | options->ignore_ws |
                             (options->algorithm == BGIT_DIFF_ALGORITHM_MINIMAL
                              ? BGIT_XDIFF_MINIMAL :
                              options->algorithm == BGIT_DIFF_ALGORITHM_PATIENCE
                              ? BGIT_XDIFF_PATIENCE :
                              options->algorithm == BGIT_DIFF_ALGORITHM_HISTOGRAM
                              ? BGIT_XDIFF_HISTOGRAM : 0) |
                             (options->ignore_blank_lines
                              ? BGIT_XDIFF_IGNORE_BLANK_LINES : 0) |
                             (options->function_context
                              ? BGIT_XDIFF_FUNCTION_CONTEXT
                              : options->context ? 0 : BGIT_XDIFF_TRIM_TAIL);
            if (bgit_xdiff_full (&old_file, &new_file, options->context,
                                 options->inter_context, diff_flags,
                                 &result) == 0) {
                stat->added = result.added;
                stat->removed = result.removed;
                bgit_xdiff_result_release (&result);
            }
            /* A path git calls modified whose diff says nothing after all —
               which is what overlooking whitespace can leave — is not in
               the stat at all. An added, deleted or renamed path is, and so
               is a mode change, empty though its diff may be. */
            if (entries[i].status == 'M' && !stat->added && !stat->removed &&
                entries[i].old_mode == entries[i].new_mode)
                kept--;
        }
        bgit_xdiff_release (&old_file);
        bgit_xdiff_release (&new_file);
        free (old_data);
        free (new_data);
    }
    *out = stats;
    *n_out = kept;
    return 0;
}

/* --check: what whitespace a change brings in, and anything that looks like
   a conflict marker left behind. git looks only at the lines a patch adds,
   with the rules that are on unless told otherwise — whitespace at the end
   of a line, a space before a tab in the indent, and a new blank line at the
   end of the file. Returns 1 when something was found, 0 when nothing was,
   or -1. */

/* The default rules, as bits, so that several can be named at once. */
#define BGIT_WS_BLANK_AT_EOL 1
#define BGIT_WS_SPACE_BEFORE_TAB 2

/* Nothing on this line but whitespace. */
static int
bgit_ws_blank (const char *line, size_t len)
{
    for (size_t i = 0; i < len; i++)
        if (!isspace ((unsigned char) line[i])) return 0;
    return 1;
}

/* Which of the whitespace rules this line breaks. */
static unsigned
bgit_ws_check (const char *line, size_t len)
{
    unsigned found = 0;
    size_t end = len;
    while (end && isspace ((unsigned char) line[end - 1])) {
        end--;
        found |= BGIT_WS_BLANK_AT_EOL;
    }
    /* A tab in the indent with a space anywhere before it. */
    int had_space = 0;
    for (size_t i = 0; i < end; i++) {
        if (line[i] == ' ') { had_space = 1; continue; }
        if (line[i] != '\t') break;
        if (had_space) found |= BGIT_WS_SPACE_BEFORE_TAB;
    }
    return found;
}

/* Does this line look like one side of a conflict git left behind? Seven of
   the same character from <>=| with whitespace, or nothing, after them. */
static int
bgit_conflict_marker (const char *line, size_t len)
{
    const size_t marker = 7;
    if (len < marker) return 0;
    char first = line[0];
    if (first != '<' && first != '>' && first != '=' && first != '|') return 0;
    for (size_t i = 1; i < marker; i++)
        if (line[i] != first) return 0;
    return len == marker || isspace ((unsigned char) line[marker]);
}

/* How many blank lines a file ends with. */
static size_t
bgit_trailing_blanks (const bgit_xdiff_file *file)
{
    size_t blanks = 0;
    while (blanks < file->n &&
           bgit_ws_blank (file->lines[file->n - 1 - blanks],
                          file->lengths[file->n - 1 - blanks]))
        blanks++;
    return blanks;
}

int
bgit_patch_check (FILE *out, bgit_odb *odb, const bgit_repo *repo,
                 const bgit_diff_entry *entries, size_t n,
                 const bgit_patch_options *options)
{
    int found = 0;
    for (size_t i = 0; i < n; i++) {
        char *old_data = NULL, *new_data = NULL;
        size_t old_len = 0, new_len = 0;
        if (bgit_patch_content (odb, repo, &entries[i], 0, options,
                                &old_data, &old_len) < 0 ||
            bgit_patch_content (odb, repo, &entries[i], 1, options,
                                &new_data, &new_len) < 0) {
            free (old_data);
            return -1;
        }
        bgit_xdiff_file old_file, new_file;
        bgit_xdiff_load (&old_file, old_data, old_len);
        bgit_xdiff_load (&new_file, new_data, new_len);
        char quoted[8192];
        const char *name = bgit_quote_path (entries[i].path, quoted,
                                            sizeof quoted);
        if (old_file.binary || new_file.binary) goto next;

        bgit_xdiff_result result;
        /* git asks for one line of context here, and the line numbers it
           reports are the new file's own. */
        if (bgit_xdiff_opts (&old_file, &new_file, 1,
                             BGIT_XDIFF_INDENT_HEURISTIC, &result) < 0) {
            bgit_xdiff_release (&old_file);
            bgit_xdiff_release (&new_file);
            free (old_data);
            free (new_data);
            return -1;
        }
        for (size_t h = 0; h < result.n_hunks; h++) {
            const bgit_xdiff_hunk *hunk = &result.hunks[h];
            for (size_t j = hunk->new_start;
                 j < hunk->new_start + hunk->new_count; j++) {
                if (!result.new_changed[j]) continue;
                const char *line = new_file.lines[j];
                size_t len = new_file.lengths[j];
                if (bgit_conflict_marker (line, len)) {
                    fprintf (out, "%s%s:%zu: leftover conflict marker\n",
                             options->line_prefix, name, j + 1);
                    found = 1;
                }
                unsigned bad = bgit_ws_check (line, len);
                if (!bad) continue;
                fprintf (out, "%s%s:%zu: %s%s%s.\n", options->line_prefix, name,
                         j + 1,
                         bad & BGIT_WS_BLANK_AT_EOL ? "trailing whitespace" : "",
                         (bad & BGIT_WS_BLANK_AT_EOL) &&
                         (bad & BGIT_WS_SPACE_BEFORE_TAB) ? ", " : "",
                         bad & BGIT_WS_SPACE_BEFORE_TAB
                         ? "space before tab in indent" : "");
                fprintf (out, "%s+", options->line_prefix);
                fwrite (line, 1, len, out);
                fputc ('\n', out);
                found = 1;
            }
        }
        bgit_xdiff_result_release (&result);

        /* A blank line at the end of the file is reported once, where the
           run of them begins, and only when the change made more of them. */
        size_t before = bgit_trailing_blanks (&old_file);
        size_t after = bgit_trailing_blanks (&new_file);
        if (after > before) {
            fprintf (out, "%s%s:%zu: new blank line at EOF.\n",
                     options->line_prefix, name, new_file.n - after + 1);
            found = 1;
        }

    next:
        bgit_xdiff_release (&old_file);
        bgit_xdiff_release (&new_file);
        free (old_data);
        free (new_data);
    }
    return found;
}

/* ------------------------------------------------------------ the forms */

static int
bgit_decimal_width (size_t value)
{
    int width = 1;
    while (value >= 10) { value /= 10; width++; }
    return width;
}

/* git scales the graph as if it were one column narrower, then adds one, so
   that any change at all shows at least one mark. */
static int
bgit_scale_linear (size_t count, int width, size_t max_change)
{
    if (!count) return 0;
    return 1 + (int) (count * (size_t) (width - 1) / max_change);
}

static void
bgit_show_graph (FILE *out, char mark, int count)
{
    while (count-- > 0) fputc (mark, out);
}

void
bgit_stat_summary (FILE *out, size_t files, size_t added, size_t removed)
{
    if (!files) {
        fprintf (out, " 0 files changed\n");
        return;
    }
    fprintf (out, " %zu file%s changed", files, files == 1 ? "" : "s");
    if (added || !removed)
        fprintf (out, ", %zu insertion%s(+)", added, added == 1 ? "" : "s");
    if (removed || !added)
        fprintf (out, ", %zu deletion%s(-)", removed, removed == 1 ? "" : "s");
    fputc ('\n', out);
}

/* What the stat calls a path: a rename shows where it came from too. */
static const char *
bgit_stat_name (const bgit_diff_entry *entry, char *quoted, size_t quoted_size,
                char *both, size_t both_size)
{
    const char *name = bgit_quote_path (bgit_shown_path (entry->path), quoted,
                                        quoted_size);
    if (!entry->from) return name;
    char from_quoted[8192];
    const char *from = bgit_quote_path (bgit_shown_path (entry->from),
                                        from_quoted, sizeof from_quoted);
    snprintf (both, both_size, "%s => %s", from, name);
    return both;
}

void
bgit_diffstat_write (FILE *out, const bgit_diffstat_entry *stats, size_t n,
                     const char *line_prefix,
                     const bgit_diffstat_layout *layout)
{
    if (!n) return;
    char quoted[8192];
    /* Only the lines that will be shown decide how wide the columns are,
       while the summary underneath counts every file. */
    size_t shown = n;
    if (layout && layout->count > 0 && (size_t) layout->count < n)
        shown = (size_t) layout->count;
    size_t max_change = 0, max_len = 0, added = 0, removed = 0;
    for (size_t i = 0; i < n; i++) {
        if (i < shown) {
            char both[8192];
            const char *name = bgit_stat_name (stats[i].entry, quoted,
                                               sizeof quoted, both,
                                               sizeof both);
            size_t len = strlen (name);
            if (len > max_len) max_len = len;
            if (!stats[i].binary) {
                size_t change = stats[i].added + stats[i].removed;
                if (change > max_change) max_change = change;
            }
        }
        if (stats[i].binary) continue;
        added += stats[i].added;
        removed += stats[i].removed;
    }

    int width = layout && layout->width > 0 ? layout->width : 80;
    int number_width = bgit_decimal_width (max_change);
    int name_width = layout && layout->name_width > 0 &&
                     (size_t) layout->name_width < max_len
                     ? layout->name_width : (int) max_len;
    int graph_width = (int) max_change;
    if (width < 16 + 6 + number_width) width = 16 + 6 + number_width;
    if (name_width + number_width + 6 + graph_width > width) {
        if (graph_width > width * 3 / 8 - number_width - 6) {
            graph_width = width * 3 / 8 - number_width - 6;
            if (graph_width < 6) graph_width = 6;
        }
        /* A graph width of its own is a ceiling: it leaves room for the
           names before they are fitted, and holds after they have been. */
        if (layout && layout->graph_width > 0 &&
            layout->graph_width < graph_width)
            graph_width = layout->graph_width;
        if (name_width > width - number_width - 6 - graph_width)
            name_width = width - number_width - 6 - graph_width;
        else
            graph_width = width - number_width - 6 - name_width;
    }
    if (layout && layout->graph_width > 0 && layout->graph_width < graph_width)
        graph_width = layout->graph_width;

    for (size_t i = 0; i < shown; i++) {
        char both[8192];
        const char *name = bgit_stat_name (stats[i].entry, quoted, sizeof quoted,
                                           both, sizeof both);
        size_t len = strlen (name);
        char shortened[8192];
        if ((int) len > name_width && name_width > 3) {
            /* Too long to show whole: git keeps the end of the path, and
               then as much of it as starts at a directory of its own. */
            const char *tail = name + len - (size_t) name_width + 3;
            const char *slash = strchr (tail, '/');
            snprintf (shortened, sizeof shortened, "...%s",
                      slash ? slash : tail);
            name = shortened;
        }
        fprintf (out, "%s %-*s |", line_prefix, name_width, name);
        if (stats[i].binary) {
            fprintf (out, " %*s %zu -> %zu bytes\n", number_width, "Bin",
                     stats[i].removed, stats[i].added);
            continue;
        }
        size_t change = stats[i].added + stats[i].removed;
        fprintf (out, " %*zu%s", number_width, change, change ? " " : "");
        int add = (int) stats[i].added, del = (int) stats[i].removed;
        if ((size_t) graph_width <= max_change && max_change) {
            int total = bgit_scale_linear (change, graph_width, max_change);
            if (total < 2 && add && del) total = 2;
            if (stats[i].added < stats[i].removed) {
                add = bgit_scale_linear (stats[i].added, graph_width, max_change);
                del = total - add;
            } else {
                del = bgit_scale_linear (stats[i].removed, graph_width, max_change);
                add = total - del;
            }
        }
        bgit_show_graph (out, '+', add);
        bgit_show_graph (out, '-', del);
        fputc ('\n', out);
    }
    /* What was left out is one line of its own, as git marks it. */
    if (shown < n) fprintf (out, "%s ...\n", line_prefix);
    fprintf (out, "%s", line_prefix);
    bgit_stat_summary (out, n, added, removed);
}

void
bgit_numstat_write (FILE *out, const bgit_diffstat_entry *stats, size_t n)
{
    char quoted[8192];
    for (size_t i = 0; i < n; i++) {
        const char *name = bgit_quote_path (bgit_shown_path (stats[i].entry->path),
                                            quoted,
                                            sizeof quoted);
        if (stats[i].binary) fprintf (out, "-\t-\t%s\n", name);
        else fprintf (out, "%zu\t%zu\t%s\n", stats[i].added, stats[i].removed,
                      name);
    }
}

void
bgit_shortstat_write (FILE *out, const bgit_diffstat_entry *stats, size_t n,
                      const char *line_prefix)
{
    if (!n) return;
    size_t added = 0, removed = 0;
    for (size_t i = 0; i < n; i++) {
        if (stats[i].binary) continue;
        added += stats[i].added;
        removed += stats[i].removed;
    }
    fprintf (out, "%s", line_prefix);
    bgit_stat_summary (out, n, added, removed);
}

void
bgit_diff_summary (FILE *out, const bgit_diff_entry *entries, size_t n,
                   const char *line_prefix)
{
    char quoted[8192];
    for (size_t i = 0; i < n; i++) {
        const char *name = bgit_quote_path (entries[i].path, quoted,
                                            sizeof quoted);
        if (entries[i].status == 'R')
            fprintf (out, "%s rename %s => %s (%d%%)\n", line_prefix,
                     entries[i].from, name, entries[i].score * 100 / 60000);
        else if (entries[i].status == 'A')
            fprintf (out, "%s create mode %06o %s\n", line_prefix,
                     entries[i].new_mode, name);
        else if (entries[i].status == 'D')
            fprintf (out, "%s delete mode %06o %s\n", line_prefix,
                     entries[i].old_mode, name);
        else if (entries[i].old_mode != entries[i].new_mode)
            fprintf (out, "%s mode change %06o => %06o %s\n", line_prefix,
                     entries[i].old_mode, entries[i].new_mode, name);
    }
}
