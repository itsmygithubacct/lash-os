/* SPDX-License-Identifier: MIT */
/* pr.c — POSIX pr(1) paginator/formatter.
 *
 *   pr [--help|--version] [-t] [-m] [-h HEADER] [-l LINES] [-w WIDTH]
 *          [-n] [-N] [-a] [-o OFFSET] [-s[SEP]] [FILE...]
 *
 *   -t          terse: no header / footer / form-feed paging
 *   -m          merge: read all FILEs in parallel, side-by-side columns
 *   -h HEADER   override the page header (default: filename)
 *   -l LINES    lines per page (default 66; header + body + footer = 66)
 *   -w WIDTH    page width for column layout (default 72)
 *   -n          number lines (1-based, 5-digit-wide column + tab)
 *   -N          (a bare digit) lay a single file out in N balanced columns
 *   -a          (--across) fill -N columns left-to-right, not top-to-bottom
 *   -o OFFSET   indent every output line by OFFSET spaces (left margin)
 *   -s[SEP]     separate columns with SEP (default TAB); no padding/truncate
 *
 * Input and output state are per invocation. Bash runs every builtin inside
 * one long-lived process, so anything left in the C library's `stdin` and
 * `stdout` objects outlives the call: reading through `stdin` made the second
 * `pr -t < file` in a shell see the first call's end-of-file and print
 * nothing. Records are read straight from the descriptor into a buffer owned
 * by this invocation, and written through a `bl_output` buffer whose write
 * failures become a non-zero exit status. docs/pr.md records the supported
 * option subset and the differences from GNU pr that remain.
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
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
#include <limits.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "loadables.h"
#include "bl-output.h"

typedef struct {
    int    terse;
    int    merge;
    int    across;         /* -a: fill columns left-to-right (row-major) */
    const char *header;
    int    page_lines;     /* total lines per page including header/footer */
    int    body_lines;     /* derived: page_lines - 10 */
    int    width;
    int    number;
    int    num_width;      /* -n DIGITS: width of the line-number field (default 5) */
    char   num_sep;        /* -n SEP: char after the number (default TAB) */
    int    dbl;            /* -d: double-space (blank line after each body line) */
    int    formfeed;       /* -f / -F: form-feed page separation, no blank padding */
    int    columns;        /* -N: number of output columns (default 1) */
    int    offset;         /* -o N: left-margin indent (default 0) */
    int    sep_set;        /* -s seen */
    char   sep;            /* -s[c] column separator (default '\t' when set) */
} pr_opts;

/* One output record: the bytes and their length, so an embedded NUL stays part
   of the record instead of ending it. An absent column is { NULL, 0 }. */
typedef struct {
    char       *text;
    size_t      len;
} pr_cell;

/* Per-invocation input over a descriptor. `stdin` is deliberately unused: its
   end-of-file indicator and its read-ahead buffer belong to the shell process
   and would carry into the next invocation of this builtin. */
#define PR_INPUT_BUFFER 65536

typedef struct {
    int         fd;
    int         owned;     /* close fd when finished — never the shell's own 0 */
    int         at_eof;
    int         failed;    /* errno of a failed read(2), 0 while healthy */
    const char *title;     /* header title; NULL for standard input */
    time_t      stamp;     /* header timestamp */
    size_t      start, end;
    char       *buf;
} pr_input;

/* Open NAME, or standard input for NULL and "-". GNU pr dates a page from the
   file's last modification and a standard-input page from the current time,
   and leaves the title of a standard-input page blank. Returns -1 with errno
   set; a directory is rejected here so the failure names the operand rather
   than surfacing later as a read error. */
static int
pr_input_open (pr_input *in, const char *name)
{
    memset (in, 0, sizeof *in);
    in->stamp = time (NULL);
    if (name && strcmp (name, "-") != 0) {
        struct stat st;
        in->fd = open (name, O_RDONLY);
        if (in->fd < 0)
            return -1;
        in->owned = 1;
        in->title = name;
        if (fstat (in->fd, &st) == 0) {
            if (S_ISDIR (st.st_mode)) {
                close (in->fd);
                in->fd = -1;
                errno = EISDIR;
                return -1;
            }
            in->stamp = st.st_mtime;
        }
    }
    in->buf = malloc (PR_INPUT_BUFFER);
    if (!in->buf) {
        if (in->owned) close (in->fd);
        in->fd = -1;
        errno = ENOMEM;
        return -1;
    }
    return 0;
}

static void
pr_input_close (pr_input *in)
{
    if (in->owned && in->fd >= 0)
        close (in->fd);
    in->owned = 0;
    in->fd = -1;
    free (in->buf);
    in->buf = NULL;
}

/* getline(3) over the invocation's own buffer. Stores a NUL-terminated record
   including its trailing newline and returns its length, or -1 once the input
   is exhausted or a read failed (in->failed then holds the errno). */
static ssize_t
pr_input_line (pr_input *in, char **line, size_t *cap)
{
    size_t len = 0;

    for (;;) {
        if (in->start == in->end) {
            ssize_t n;
            if (in->at_eof)
                break;
            n = read (in->fd, in->buf, PR_INPUT_BUFFER);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                in->failed = errno;
                in->at_eof = 1;
                break;
            }
            if (n == 0) {
                in->at_eof = 1;
                break;
            }
            in->start = 0;
            in->end = (size_t) n;
        }
        const char *from = in->buf + in->start;
        size_t avail = in->end - in->start;
        const char *nl = memchr (from, '\n', avail);
        size_t take = nl ? (size_t) (nl - from) + 1 : avail;
        if (len > (size_t) SSIZE_MAX - take) {
            in->failed = EOVERFLOW;
            in->at_eof = 1;
            return -1;
        }
        if (len + take + 1 > *cap) {
            size_t want = *cap ? *cap : 256;
            char *grown;
            while (want < len + take + 1) {
                if (want > SIZE_MAX / 2) { want = len + take + 1; break; }
                want *= 2;
            }
            grown = realloc (*line, want);
            if (!grown) {
                in->failed = ENOMEM;
                in->at_eof = 1;
                break;
            }
            *line = grown;
            *cap = want;
        }
        memcpy (*line + len, from, take);
        len += take;
        in->start += take;
        if (nl)
            break;
    }
    if (len == 0)
        return -1;
    (*line)[len] = '\0';
    return (ssize_t) len;
}

/* Emit COUNT spaces. -o and the page geometry can ask for more than a single
   write, so the blanks come from one small constant run. */
static void
pr_spaces (bl_output *out, int count)
{
    static const char blanks[] = "                                                                ";
    while (count > 0 && !out->error) {
        int n = count < (int) (sizeof blanks - 1) ? count : (int) (sizeof blanks - 1);
        bl_output_write (out, blanks, (size_t) n);
        count -= n;
    }
}

/* Emit the -o left-margin indent (spaces) at the start of a row. */
static void
pr_offset (bl_output *out, const pr_opts *o)
{
    pr_spaces (out, o->offset);
}

static int
pr_parse_int_arg (const char *opt, const char *arg, int *out)
{
    char *end = NULL;
    long v;

    errno = 0;
    v = strtol (arg, &end, 10);
    if (end == arg || *end != '\0' || errno == ERANGE || v > INT_MAX || v < 0) {
        builtin_error ("%s: invalid number: %s", opt, arg);
        builtin_usage ();
        return EX_USAGE;
    }

    *out = (int) v;
    return EXECUTION_SUCCESS;
}

/* Header: blank, blank, DATE FILENAME PAGE, blank, blank (5 lines).
   GNU pr uses ISO-like date/minute text and centers the title between
   date and page marker within the page width. STAMP is the file's
   modification time, or the current time for standard input. */
static void
pr_header (bl_output *out, const pr_opts *o, const char *fname, time_t stamp,
           int page_no)
{
    if (o->terse) return;
    char tbuf[64];
    char pagebuf[32];
    struct tm tm;
    const char *title = o->header ? o->header : (fname ? fname : "");
    int title_len;
    int sep_left;
    int sep_right;
    int available;

    tbuf[0] = '\0';
    if (localtime_r (&stamp, &tm))
        strftime (tbuf, sizeof tbuf, "%Y-%m-%d %H:%M", &tm);
    snprintf (pagebuf, sizeof pagebuf, "Page %d", page_no);

    title_len = (int) strlen (title);
    available = o->width - (int) strlen (tbuf) - title_len - (int) strlen (pagebuf);
    sep_left = available / 2;
    sep_right = available - sep_left;
    if (sep_left < 1)
        sep_left = 1;
    if (sep_right < 1)
        sep_right = 1;

    /* The -o margin shifts the header right by OFFSET columns, exactly like
       the body rows, while the date/title/page centering stays computed
       against the unshifted page width (matches GNU pr's chars_per_margin).
       GNU also emits the margin on the first of the two leading blank lines
       (an artifact of its pad_across_to()+print_white_space() before the
       newlines); the leading run of spaces reproduces that. Every run
       collapses to nothing when OFFSET is 0, so the no-offset header is
       byte-unchanged. */
    pr_spaces (out, o->offset);
    bl_output_write (out, "\n\n", 2);
    pr_spaces (out, o->offset);
    bl_output_write (out, tbuf, strlen (tbuf));
    pr_spaces (out, sep_left);
    bl_output_write (out, title, (size_t) title_len);
    pr_spaces (out, sep_right);
    bl_output_write (out, pagebuf, strlen (pagebuf));
    bl_output_write (out, "\n\n\n", 3);
}

static void
pr_footer (bl_output *out, const pr_opts *o, int body_printed)
{
    if (o->terse) return;
    /* -f/-F: a single form-feed replaces the blank footer padding; the next
       page's header leading blanks follow it (so it renders as \f\n...). The
       final page's footer is just the bare \f with no trailing newline. */
    if (o->formfeed) {
        bl_output_byte (out, '\f');
        return;
    }
    /* Pad the body region out to body_lines (for a short final page), then the
       fixed 5-line footer. Equivalent to page_lines-5-body_printed when
       body_lines == page_lines-10, but stays correct when body_lines was
       adjusted (e.g. -d rounds it down to even). */
    int blanks = (o->body_lines - body_printed) + 5;
    if (blanks < 0)
        blanks = 0;
    while (blanks-- > 0 && !out->error)
        bl_output_byte (out, '\n');
}

/* Drop the record's terminating newline, if any. A carriage return is part of
   the record: GNU pr passes it through. */
static size_t
pr_chomp (char *s, size_t len)
{
    if (len > 0 && s[len - 1] == '\n')
        s[--len] = '\0';
    return len;
}

/* GNU pr's column line-number geometry (default -n): a CHARS_PER_NUMBER-wide
   right-justified number followed by (NUMBER_WIDTH - CHARS_PER_NUMBER) spaces.
   NUMBER_WIDTH rounds the number field up to the next 8-col tab stop, matching
   GNU's `number_width = chars_per_number + TAB_WIDTH(8, chars_per_number)`.
   With -n the digit count is configurable (`o->num_width`, default 5) and the
   trailing pad is a TAB stop only when the separator is the default TAB; a
   custom -n separator (e.g. -nc3) uses exactly one separator char with no
   tab-stop rounding. */
#define PR_DEFAULT_CHARS_PER_NUMBER 5
/* chars_per_number for this run */
#define PR_CHARS_PER_NUMBER (o->num_width)
/* full number field incl. separator: TAB-rounded for the default TAB sep,
   else digits + 1 separator char. */
#define PR_NUMBER_WIDTH \
    ((o->num_sep == '\t') \
       ? (o->num_width + (8 - o->num_width % 8)) \
       : (o->num_width + 1))

/* Tab-compressing output tracker, mirroring GNU pr's tabify_output path
   (print_char buffers spaces; print_white_space flushes them as TABs to each
   8-col stop plus residual spaces). Tracks absolute output column so the
   TAB/space split matches GNU byte-for-byte. Trailing buffered spaces that are
   never followed by a glyph are dropped — that is GNU's trailing-space strip. */
typedef struct { bl_output *out; int pos; int pending; } pr_tw;

static void
pr_tw_flush (pr_tw *w)            /* == GNU print_white_space () */
{
    int goal = w->pos + w->pending;
    int h = w->pos;
    while (goal - h > 1) {
        int next_tab = h + 8 - (h % 8);          /* POS_AFTER_TAB(8, h) */
        if (next_tab > goal) break;
        bl_output_byte (w->out, '\t');
        h = next_tab;
    }
    while (++h <= goal) bl_output_byte (w->out, ' ');
    w->pos = goal;
    w->pending = 0;
}

static void
pr_tw_putc (pr_tw *w, char c)     /* == GNU print_char () under tabify_output */
{
    if (c == ' ') { w->pending++; return; }
    if (w->pending) pr_tw_flush (w);
    bl_output_byte (w->out, (unsigned char) c);
    w->pos++;                     /* glyphs assumed width 1 */
}

/* Buffer enough spaces to reach absolute column `target`, then flush — GNU
   pads to each column's start_position as a discrete (flushed) step before
   the number begins, which is why the pad and the number's leading spaces
   tab-compress independently. */
static void
pr_tw_pad_to (pr_tw *w, int target)
{
    int cur = w->pos + w->pending;
    if (target > cur)
        w->pending += target - cur;
    pr_tw_flush (w);
}

/* Emit one row of `ncol` column records (a NULL text = empty column). When a
   -s separator is set, columns are joined by that single byte with no padding
   or truncation (GNU semantics); otherwise each column is padded/truncated
   to width/ncol and tab-aligned to its column origin. The -o offset indent
   precedes everything.

   Numbering has two GNU-distinct shapes:
     - `colnums != NULL` → COLUMN mode (-N/-a with -n): each cell prints its
       OWN "%5ld\t" number field at its column origin (colnums[i]; 0 = none).
       Column origins stay at offset + i*col_w — the number sits inside the
       cell, it does not shift the grid.
     - else `lineno > 0` → MERGE / single-column: one "%5ld\t" field is
       printed once, before all columns, and reserves a 4-col extra margin
       that pushes the later column origins out. */
/* Print the line-number field of a single-column page: the number
   right-justified in num_width columns (GNU keeps the low-order digits when
   the count overflows the field), then the separator character. A
   single-column page is not tabified, so the field is emitted verbatim. */
static void
pr_print_number (bl_output *out, const pr_opts *o, long lineno)
{
    char nb[3 * sizeof (long) + 2];
    int nl = snprintf (nb, sizeof nb, "%*ld", o->num_width, lineno);
    const char *s = (nl > o->num_width) ? nb + (nl - o->num_width) : nb;

    bl_output_write (out, s, strlen (s));
    bl_output_byte (out, (unsigned char) o->num_sep);
}

/* GNU pr's column accounting for the text of one cell in a multi-column row
   (its char_to_clump()/print_char() pair). A printable byte occupies one
   column, a TAB advances to the next eight-column stop measured from the
   start of the cell and is re-emitted as spaces for the output tabifier to
   compress, a backspace moves back one column, and any other byte occupies
   none. LIMIT is the cell's text field in columns, or -1 for no limit: the
   first clump that would overrun it ends the cell, which is where GNU
   truncates a column. CLUMP is 0 for the one layout GNU leaves alone — a -s
   separator that is the default TAB — where every byte counts as one column
   and an input TAB passes through untouched. */
static void
pr_write_cell (pr_tw *w, const pr_cell *cell, int limit, int clump)
{
    int pos = 0;                          /* column within this cell */

    for (size_t i = 0; i < cell->len; i++) {
        unsigned char c = (unsigned char) cell->text[i];
        int width;

        if (!clump)
            width = 1;
        else if (c == '\t')
            width = 8 - pos % 8;
        else if (c == '\b')
            width = -1;
        else if (isprint (c))
            width = 1;
        else
            width = 0;
        if (limit >= 0 && pos + width > limit)
            break;
        if (c == '\t' && clump) {
            w->pending += width;          /* spaces the tabifier may re-compress */
        } else if (c == ' ') {
            w->pending++;
        } else {
            if (w->pending) pr_tw_flush (w);
            bl_output_byte (w->out, c);
            w->pos += width;
            if (w->pos < 0) w->pos = 0;
        }
        pos += width;
        if (pos < 0) pos = 0;
    }
}

/* Emit a line-number field through the tabifier: the number right-justified
   in num_width columns (GNU keeps the low-order digits when the count
   overflows the field), then its separator — for the default TAB that is the
   run of spaces that pads the field out to the next eight-column stop, which
   the tabifier then re-compresses; for a custom separator it is that one
   character. */
static void
pr_tw_number (pr_tw *w, const pr_opts *o, long lineno)
{
    char nb[3 * sizeof (long) + 2];
    int nl = snprintf (nb, sizeof nb, "%*ld", o->num_width, lineno);
    const char *s = (nl > o->num_width) ? nb + (nl - o->num_width) : nb;

    for (; *s; s++) pr_tw_putc (w, *s);
    if (o->num_sep == '\t')
        w->pending += PR_NUMBER_WIDTH - o->num_width;
    else
        pr_tw_putc (w, o->num_sep);
}

static void
pr_emit_row (bl_output *out, const pr_cell *cols, int ncol, const pr_opts *o,
             long lineno, const long *colnums)
{
    /* One column is a byte-for-byte pass-through in GNU pr: no column
       accounting, no TAB compression of the margin, no truncation. */
    if (ncol <= 1) {
        pr_offset (out, o);
        if (lineno > 0)
            pr_print_number (out, o, lineno);
        else if (colnums && colnums[0] > 0)
            pr_print_number (out, o, colnums[0]);
        if (ncol > 0 && cols[0].len)
            bl_output_write (out, cols[0].text, cols[0].len);
        bl_output_byte (out, '\n');
        return;
    }

    /* Trailing columns that hold no record at all produce no padding and no
       separator (GNU strips trailing whitespace on a short final page). A
       record that exists but is empty still counts. Merge mode is different:
       every FILE is a live column, so GNU advances to each column origin even
       after a file has been exhausted — do NOT strip there. */
    int last = ncol;
    if (!o->merge)
        while (last > 0 && !cols[last - 1].text
               && !(colnums && colnums[last - 1] > 0))
            last--;

    /* GNU expands an input TAB into the columns it spans and re-compresses
       the result, except with a -s separator that is itself the default TAB:
       there the records pass through byte for byte. */
    int clump = !(o->sep_set && o->sep == '\t');

    /* Numbering has two GNU-distinct shapes:
         - `colnums != NULL` -> COLUMN mode (-N/-a with -n): each cell prints
           its OWN number field at its column origin (colnums[i]; 0 = none).
           The number sits inside the cell and does not shift the grid; the
           text field is what is left of the column after it.
         - else `lineno > 0` -> MERGE: one number field is printed before all
           columns and reserves NUMBER_WIDTH columns of left margin that push
           every column origin out. */
    int num_field = (!colnums && lineno > 0) ? PR_NUMBER_WIDTH : 0;
    /* Column stride (origin-to-origin). GNU reserves a one-column separator
       between columns: chars_per_column = (width - number - (ncol-1))/ncol and
       the stride is chars_per_column + 1. */
    int col_w = (o->width - num_field - (ncol - 1)) / ncol + 1;
    /* GNU floors chars_per_column (= stride - 1) at 1, i.e. the stride at 2. */
    if (col_w < 2) col_w = 2;
    int cell_w = col_w - 1;
    if (colnums) {
        cell_w -= PR_NUMBER_WIDTH;
        if (cell_w < 1) cell_w = 1;
    }

    pr_tw w = { .out = out, .pos = 0, .pending = 0 };
    pr_tw_pad_to (&w, o->offset);
    if (!colnums && lineno > 0)
        pr_tw_number (&w, o, lineno);

    for (int i = 0; i < last; i++) {
        if (o->sep_set) {
            /* -s joins the columns with the separator instead of padding to
               the next origin, and never truncates. */
            if (i) pr_tw_putc (&w, o->sep);
        } else {
            /* A discrete flush at the column origin: GNU pads to each column's
               start position as its own step, so the pad and anything the cell
               buffers afterwards tab-compress independently. */
            pr_tw_pad_to (&w, o->offset + num_field + i * col_w);
        }
        if (colnums && colnums[i] > 0)
            pr_tw_number (&w, o, colnums[i]);
        pr_write_cell (&w, &cols[i], o->sep_set ? -1 : cell_w, clump);
    }
    bl_output_byte (out, '\n');     /* trailing buffered spaces dropped (GNU strip) */
}

/* Single-file, single-column mode: paginate the input one line per row. */
static int
pr_single (bl_output *out, pr_input *in, const pr_opts *o)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int line_in_page = 0;
    int page_no = 1;
    long lineno = 1;

    /* In -d mode each input line occupies two body slots (the line + a trailing
       blank), and GNU will not start a line whose blank won't also fit — so the
       break threshold is body_lines minus the per-line slot count. */
    while ((n = pr_input_line (in, &line, &cap)) != -1) {
        if (line_in_page >= o->body_lines) {
            pr_footer (out, o, line_in_page);
            page_no++;
            line_in_page = 0;
        }
        if (line_in_page == 0)
            pr_header (out, o, in->title, in->stamp, page_no);
        pr_cell cell;
        cell.text = line;
        cell.len = pr_chomp (line, (size_t) n);
        pr_emit_row (out, &cell, 1, o, o->number ? lineno++ : 0, NULL);
        line_in_page++;
        if (o->dbl) {           /* -d: blank line after each body line, counts as a body line */
            bl_output_byte (out, '\n');
            line_in_page++;
        }
    }
    if (line_in_page > 0) pr_footer (out, o, line_in_page);
    free (line);
    return in->failed ? -1 : 0;
}

/* Single-file, multi-column mode (-N): balanced columns. The file is read
   fully, then laid out. Default (column-major / "down"): column 1 gets the
   first ceil(L/N) lines, column 2 the next batch, etc. With -a ("across"):
   row-major — lines fill left-to-right across each row before the next.
   With -n the number is per-cell (each cell shows its input line number),
   matching GNU column-mode placement. */
static int
pr_columns (bl_output *out, pr_input *in, const pr_opts *o)
{
    pr_cell *lines = NULL;
    long nlines = 0, lcap = 0;
    char *raw = NULL;
    size_t rawcap = 0;
    ssize_t nread;

    while ((nread = pr_input_line (in, &raw, &rawcap)) != -1) {
        if (nlines == lcap) {
            long newcap = lcap ? lcap * 2 : 64;
            pr_cell *grown = realloc (lines, (size_t) newcap * sizeof *lines);
            if (!grown) { in->failed = ENOMEM; break; }
            lines = grown; lcap = newcap;
        }
        size_t len = pr_chomp (raw, (size_t) nread);
        char *copy = malloc (len + 1);
        if (!copy) { in->failed = ENOMEM; break; }
        memcpy (copy, raw, len);
        copy[len] = '\0';
        lines[nlines].text = copy;
        lines[nlines].len = len;
        nlines++;
    }
    free (raw);

    int ncol = o->columns;
    /* GNU pr lays each page out on its own: a page holds body_lines*ncol
       records, and the balancing below applies within that page, so column 2
       of page 1 starts at record body_lines+1 however long the input is. */
    /* -d gives each record a trailing blank, so a page holds half as many
       rows; body_lines was already rounded down to an even number. */
    long rows_per_page = o->dbl ? o->body_lines / 2 : o->body_lines;
    if (rows_per_page < 1) rows_per_page = 1;
    long per_page = rows_per_page * ncol;
    int page_no = 1;
    pr_cell *cols = calloc ((size_t) ncol, sizeof *cols);
    long *colnums = o->number ? calloc ((size_t) ncol, sizeof *colnums) : NULL;

    if (!cols || (o->number && !colnums)) {
        in->failed = ENOMEM;
    } else for (long first = 0; first < nlines; first += per_page) {
        long count = nlines - first < per_page ? nlines - first : per_page;
        /* GNU balances "down" columns when the page's record count is not a
           multiple of ncol: the first `rem` columns get base+1 records, the
           rest get base (e.g. 7 in 3 cols => heights 3,2,2, not 3,3,1).
           Column c then begins at start(c) = c*base + min(c, rem). "across"
           is unaffected (row-major). */
        long base = count / ncol;
        int  rem  = (int) (count % ncol);
        long rows = (count + ncol - 1) / ncol;

        pr_header (out, o, in->title, in->stamp, page_no);
        for (long row = 0; row < rows; row++) {
            for (int c = 0; c < ncol; c++) {
                long idx;
                if (o->across) {
                    /* row-major: records fill left-to-right across each row. */
                    idx = first + row * ncol + c;
                } else {
                    /* column-major, balanced: column c holds base(+1 if c<rem)
                       records from start(c); rows past its height are empty. */
                    long height = base + (c < rem ? 1 : 0);
                    long start  = first + (long) c * base + (c < rem ? c : rem);
                    idx = (row < height) ? start + row : nlines;
                }
                if (idx < first + count) {
                    cols[c] = lines[idx];
                } else {
                    cols[c].text = NULL;
                    cols[c].len = 0;
                }
                if (colnums)
                    colnums[c] = (idx < first + count) ? idx + 1 : 0;
            }
            pr_emit_row (out, cols, ncol, o, 0, colnums);
            if (o->dbl)
                bl_output_byte (out, '\n');
        }
        pr_footer (out, o, (int) (o->dbl ? rows * 2 : rows));
        page_no++;
    }

    for (long j = 0; j < nlines; j++) free (lines[j].text);
    free (lines); free (cols); free (colnums);
    return in->failed ? -1 : 0;
}

/* Merge mode: read all inputs line-by-line in parallel, side by side. End of
   input on one leaves its column blank until the others finish. With -n the
   line number is emitted once per row, before all columns (GNU placement).
   GNU dates a merged page from the current time and leaves its title blank,
   because the page belongs to no single file. */
static int
pr_merge (bl_output *out, pr_input *ins, int n, const pr_opts *o)
{
    char **lines = calloc ((size_t) n, sizeof *lines);
    size_t *caps = calloc ((size_t) n, sizeof *caps);
    pr_cell *cols = calloc ((size_t) n, sizeof *cols);
    int line_in_page = 0;
    int page_no = 1;
    long lineno = 1;
    time_t now = time (NULL);
    int failed = 0;

    if (!lines || !caps || !cols) {
        free (lines); free (caps); free (cols);
        return -1;
    }
    for (;;) {
        int any = 0;
        for (int i = 0; i < n; i++) {
            ssize_t got = pr_input_line (&ins[i], &lines[i], &caps[i]);
            if (got != -1) {
                any = 1;
                cols[i].text = lines[i];
                cols[i].len = pr_chomp (lines[i], (size_t) got);
            } else {
                cols[i].text = NULL;
                cols[i].len = 0;
            }
        }
        if (!any) break;
        if (line_in_page >= o->body_lines) {
            pr_footer (out, o, line_in_page);
            page_no++;
            line_in_page = 0;
        }
        if (line_in_page == 0)
            pr_header (out, o, NULL, now, page_no);
        pr_emit_row (out, cols, n, o, o->number ? lineno++ : 0, NULL);
        line_in_page++;
    }
    if (line_in_page > 0) pr_footer (out, o, line_in_page);
    for (int i = 0; i < n; i++) {
        free (lines[i]);
        if (ins[i].failed) failed = 1;
    }
    free (lines); free (caps); free (cols);
    return failed ? -1 : 0;
}

/* -l/--length: GNU pr rejects a zero page length, and prints a page of ten
   lines or fewer without the five-line header and five-line footer that
   would not fit. */
static int
pr_set_length (pr_opts *o, const char *opt, const char *arg)
{
    int parsed;
    if (pr_parse_int_arg (opt, arg, &parsed) != EXECUTION_SUCCESS)
        return EX_USAGE;
    if (parsed < 1) {
        builtin_error ("%s: invalid number of lines: %s", opt, arg);
        builtin_usage ();
        return EX_USAGE;
    }
    o->page_lines = parsed;
    if (parsed <= 10)
        o->terse = 1;
    return EXECUTION_SUCCESS;
}

/* -w/--width: the supported range starts at 8 columns; see docs/pr.md. */
static int
pr_set_width (pr_opts *o, const char *opt, const char *arg)
{
    int parsed;
    if (pr_parse_int_arg (opt, arg, &parsed) != EXECUTION_SUCCESS)
        return EX_USAGE;
    if (parsed < 8) {
        builtin_error ("%s: invalid width: %s", opt, arg);
        builtin_usage ();
        return EX_USAGE;
    }
    o->width = parsed;
    return EXECUTION_SUCCESS;
}

/* Report a failed read and turn it into a non-zero exit status. Buffered
   output is flushed first so the diagnostic keeps its place relative to the
   records already produced. */
static void
pr_report (bl_output *out, const char *name, int number)
{
    bl_output_flush (out);
    builtin_error ("%s: %s", name ? name : "standard input", strerror (number));
}

int
pr_builtin (WORD_LIST *list)
{
    pr_opts o = { .page_lines = 66, .width = 72, .columns = 1,
                  .num_width = PR_DEFAULT_CHARS_PER_NUMBER, .num_sep = '\t' };
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version")) {
            puts ("pr 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-t")) { o.terse = 1; list = list->next; continue; }
        if (!strcmp (w, "-m")) { o.merge = 1; list = list->next; continue; }
        if (!strcmp (w, "-d") || !strcmp (w, "--double-space")) { o.dbl = 1; list = list->next; continue; }
        if (!strcmp (w, "-f") || !strcmp (w, "-F")
            || !strcmp (w, "--form-feed") || !strcmp (w, "--form-feed=")) {
            o.formfeed = 1; list = list->next; continue;
        }
        /* -n[SEP[DIGITS]]: number lines. Attached arg is GNU's only form (a
           separated token is taken as a filename). SEP = a single leading
           non-digit char (default TAB); DIGITS = the field width (default 5).
           e.g. -n => 5/TAB, -n3 => 3/TAB, -nc3 => 3/sep 'c', -n: => 5/sep ':'. */
        if (w[1] == 'n') {
            o.number = 1;
            const char *p = w + 2;
            if (*p && !(*p >= '0' && *p <= '9')) {
                o.num_sep = *p;                 /* leading non-digit = separator */
                p++;
            }
            if (*p) {                           /* remaining = digit width */
                char *end;
                long d = strtol (p, &end, 10);
                if (*end != '\0' || d < 1) {
                    builtin_error ("-n: invalid number format: %s", w);
                    builtin_usage ();
                    return EX_USAGE;
                }
                o.num_width = (int) d;
            }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-a") || !strcmp (w, "--across")) { o.across = 1; list = list->next; continue; }
        /* -N (a bare digit count) selects N output columns. */
        if (w[1] >= '1' && w[1] <= '9' && w[2] == '\0') {
            o.columns = w[1] - '0';
            list = list->next;
            continue;
        }
        /* -o OFFSET (attached -oN or separate -o N): left-margin indent. */
        if (w[1] == 'o') {
            int parsed;
            const char *arg;
            if (w[2] != '\0') {
                arg = w + 2;
            } else {
                if (!list->next) { builtin_error ("-o needs OFFSET"); builtin_usage (); return EX_USAGE; }
                list = list->next;
                arg = list->word->word;
            }
            if (pr_parse_int_arg ("-o", arg, &parsed) != EXECUTION_SUCCESS)
                return EX_USAGE;
            o.offset = parsed;
            list = list->next;
            continue;
        }
        /* -s[c]: column separator (default TAB). Disables width padding. */
        if (w[1] == 's' && (w[2] == '\0' || w[3] == '\0')) {
            o.sep_set = 1;
            o.sep = (w[2] != '\0') ? w[2] : '\t';
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--header")) {
            if (!list->next) { builtin_error ("--header needs HEADER"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            o.header = list->word->word;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--header=", 9)) {
            o.header = w + 9;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-h")) {
            if (!list->next) { builtin_error ("-h needs HEADER"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            o.header = list->word->word;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--length") || !strcmp (w, "-l")) {
            if (!list->next) { builtin_error ("%s needs LINES", w); builtin_usage (); return EX_USAGE; }
            list = list->next;
            if (pr_set_length (&o, w, list->word->word) != EXECUTION_SUCCESS)
                return EX_USAGE;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--length=", 9)) {
            if (pr_set_length (&o, "--length", w + 9) != EXECUTION_SUCCESS)
                return EX_USAGE;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--width") || !strcmp (w, "-w")) {
            if (!list->next) { builtin_error ("%s needs WIDTH", w); builtin_usage (); return EX_USAGE; }
            list = list->next;
            if (pr_set_width (&o, w, list->word->word) != EXECUTION_SUCCESS)
                return EX_USAGE;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--width=", 8)) {
            if (pr_set_width (&o, "--width", w + 8) != EXECUTION_SUCCESS)
                return EX_USAGE;
            list = list->next;
            continue;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }
    o.body_lines = o.terse ? o.page_lines : (o.page_lines - 10);
    if (o.body_lines < 1) o.body_lines = 56;
    /* -d emits each body line as a 2-line unit (line + blank); GNU rounds the
       body region down to an even number of lines so a unit never straddles a
       page boundary. */
    if (o.dbl && (o.body_lines & 1)) o.body_lines--;

    int rc = EXECUTION_SUCCESS;
    int n_files = 0;
    for (WORD_LIST *p = list; p; p = p->next) n_files++;

    /* Output goes through this invocation's own buffer rather than the shell's
       stdout object, so a failed write is seen here and reported. */
    bl_output output;
    bl_output_init (&output, stdout);

    if (n_files == 0) {
        pr_input in;
        if (pr_input_open (&in, NULL) < 0) {
            pr_report (&output, NULL, errno);
            rc = EXECUTION_FAILURE;
        } else {
            int bad = (o.columns > 1 && !o.merge) ? pr_columns (&output, &in, &o)
                                                  : pr_single (&output, &in, &o);
            if (bad < 0) {
                pr_report (&output, NULL, in.failed);
                rc = EXECUTION_FAILURE;
            }
            pr_input_close (&in);
        }
    } else if (o.merge && n_files > 1) {
        pr_input *ins = calloc ((size_t) n_files, sizeof *ins);
        if (!ins) {
            pr_report (&output, "pr", ENOMEM);
            rc = EXECUTION_FAILURE;
        } else {
            int opened = 0;
            for (WORD_LIST *p = list; p; p = p->next) {
                if (pr_input_open (&ins[opened], p->word->word) < 0) {
                    pr_report (&output, p->word->word, errno);
                    rc = EXECUTION_FAILURE;
                    continue;
                }
                opened++;
            }
            if (opened > 0 && pr_merge (&output, ins, opened, &o) < 0) {
                for (int j = 0; j < opened; j++)
                    if (ins[j].failed)
                        pr_report (&output, ins[j].title, ins[j].failed);
                rc = EXECUTION_FAILURE;
            }
            for (int j = 0; j < opened; j++) pr_input_close (&ins[j]);
            free (ins);
        }
    } else {
        /* Single-file mode: paginate each FILE separately. */
        for (WORD_LIST *p = list; p; p = p->next) {
            pr_input in;
            if (pr_input_open (&in, p->word->word) < 0) {
                pr_report (&output, p->word->word, errno);
                rc = EXECUTION_FAILURE;
                continue;
            }
            /* -m always uses a blank header title and the current time (GNU
               pr), even with a single FILE, where this would otherwise fall
               through to the filename-titled single-file path. */
            if (o.merge) { in.title = NULL; in.stamp = time (NULL); }
            int bad = (o.columns > 1 && !o.merge) ? pr_columns (&output, &in, &o)
                                                  : pr_single (&output, &in, &o);
            if (bad < 0) {
                pr_report (&output, in.title, in.failed);
                rc = EXECUTION_FAILURE;
            }
            pr_input_close (&in);
        }
    }

    bl_output_flush (&output);
    if (output.error) {
        builtin_error ("write error: %s", strerror (output.error));
        rc = EXECUTION_FAILURE;
    }
    return rc;
}

char *pr_doc[] = {
    "Format text for printing (POSIX pr).",
    "",
    "    pr [--help|--version] [-t] [-m] [-h HEADER] [-l LINES] [-w WIDTH] [-n] [-N] [-a] [-o OFFSET] [-s[SEP]] [FILE...]",
    "",
    "    -t          terse: no header / footer paging",
    "    -m          merge mode: side-by-side columns of all FILEs",
    "    -d          double-space the output (blank line after each body line)",
    "    -f, -F      use a form-feed to separate pages (no blank padding)",
    "    -h HEADER   override page header (default: filename)",
    "    -l LINES    lines per page (default 66 — 5 hdr + 56 body + 5 ftr)",
    "    -w WIDTH    column-layout width (default 72, minimum 8)",
    "    -n[SEP[N]]  number body lines (N digits, default 5; SEP after, def tab)",
    "    -N          a bare digit: lay one file out in N balanced columns",
    "    -a          (--across) fill -N columns left-to-right, not top-down",
    "    -o OFFSET   indent every line by OFFSET spaces (left margin)",
    "    -s[SEP]     separate columns with SEP (default tab), no padding",
    "    --help      show this help",
    "    --version   show version",
    "",
    "Without flags: paginates with 5-line top header (date + filename +",
    "page #), 56 lines of body, 5-line footer. Reads standard input if no",
    "FILE. A page is dated from the file's last modification, and from the",
    "current time when the input is standard input or several merged files.",
    (char *)NULL
};

struct builtin pr_struct = {
    "pr",
    pr_builtin,
    BUILTIN_ENABLED,
    pr_doc,
    "pr [--help|--version] [-tmnadfF] [-N] [-o OFFSET] [-s[SEP]] [-h HEADER] [-l LINES] [-w WIDTH] [FILE...]",
    0
};
