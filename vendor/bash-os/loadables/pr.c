/* SPDX-License-Identifier: MIT */
/* pr.c — POSIX pr(1) paginator/formatter.
 *
 *   pr [--help|--version] [-t] [-m] [-h HEADER] [-l LINES] [-w WIDTH]
 *          [-n] [-COLUMN] [-N NUMBER] [-a] [-o OFFSET] [-s[SEP]] [FILE...]
 *
 *   -t          terse: no header / footer / page padding
 *   -m          merge: read all FILEs in parallel, side-by-side columns
 *   -h HEADER   override the page header (default: filename)
 *   -l LINES    lines per page (default 66; header + body + footer = 66)
 *   -w WIDTH    page width for column layout (default 72)
 *   -n          number lines (1-based, 5-digit-wide column + tab)
 *   -COLUMN     lay a single file out in COLUMN balanced columns
 *   -N NUMBER   first line number on the first page printed
 *   -a          (--across) fill -N columns left-to-right, not top-to-bottom
 *   -o OFFSET   indent every output line by OFFSET spaces (left margin)
 *   -s[STRING]  separate columns (default TAB); -w retains truncation
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
    int    columns;        /* -COLUMN: number of output columns (default 1) */
    int    offset;         /* -o N: left-margin indent (default 0) */
    const char *separator;
    int sep_len, width_set, page_width, columns_set, join, no_warn;
    int expand, tabify, in_tab_width, out_tab_width, show_control, show_octal;
    unsigned char in_tab, out_tab;
    int omit_pagination;
    const char *date_format;
    int first_page, last_page, first_number, number_set;

} pr_opts;

/* One output record: the bytes and their length, so an embedded NUL stays part
   of the record instead of ending it. An absent column is { NULL, 0 }. */
typedef struct {
    char       *text;
    size_t      len;
    int         renumber, backspace;
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
    int         form_break, skip_nl, buffer_ff, buffer_bs, record_bs;
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

/* Read a NUL-terminated record, preserving a trailing newline. A form feed
   ends the record without becoming part of it: form_break marks the page end,
   and a following newline is consumed. A standalone form feed returns zero;
   -1 means exhaustion or a read failure (in->failed holds errno). record_bs
   records whether byte-wise backspace accounting is needed for this record. */
static ssize_t
pr_input_line (pr_input *in, char **line, size_t *cap)
{
    size_t len = 0;
    in->form_break = in->record_bs = 0;

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
            /* Scan once per read buffer; ordinary records then need only
               the newline search, with no per-record control-byte scans. */
            in->buffer_ff = memchr (in->buf, '\f', (size_t) n) != NULL;
            in->buffer_bs = memchr (in->buf, '\b', (size_t) n) != NULL;
        }
        const char *from = in->buf + in->start;
        size_t avail = in->end - in->start;
        if (in->skip_nl) {
            in->skip_nl = 0;
            if (*from == '\n') { in->start++; continue; }
        }
        const char *nl = memchr (from, '\n', avail);
        const char *ff = in->buffer_ff ? memchr (from, '\f', nl ? (size_t) (nl - from) : avail) : NULL;
        if (ff && (!nl || ff < nl)) nl = ff;
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
        if (in->buffer_bs && memchr (from, '\b', take)) in->record_bs = 1;
        memcpy (*line + len, from, take);
        len += take;
        in->start += take;
        if (nl) {
            if (*nl == '\f') {
                len--; in->form_break = in->skip_nl = 1;
            }
            break;
        }
    }
    if (len == 0 && !in->form_break)
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
        return EXECUTION_FAILURE;
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
    char *tbuf;
    size_t date_cap = 128;
    char pagebuf[32];
    struct tm tm;
    const char *title = o->header ? o->header : (fname ? fname : "");
    int title_len;
    int sep_left;
    int sep_right;
    int available;

    tbuf = malloc (date_cap);
    if (!tbuf) { out->error = ENOMEM; return; }
    tbuf[0] = '\0';
    if (*o->date_format && localtime_r (&stamp, &tm)) {
        while (!strftime (tbuf, date_cap, o->date_format, &tm)) {
            char *larger;
            /* A locale's empty date expansion must not grow forever. */
            if (date_cap >= 1024 * 1024) { tbuf[0] = '\0'; break; }
            date_cap *= 2;
            larger = realloc (tbuf, date_cap);
            if (!larger) { free (tbuf); out->error = ENOMEM; return; }
            tbuf = larger;
        }
    }
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
    int margin = o->offset;
    if (o->tabify)
        while (margin > 1 && margin >= o->out_tab_width) {
            bl_output_byte (out, o->out_tab);
            margin -= o->out_tab_width;
        }
    pr_spaces (out, margin);
    bl_output_write (out, "\n\n", 2);
    pr_spaces (out, o->offset);
    bl_output_write (out, tbuf, strlen (tbuf));
    pr_spaces (out, sep_left);
    bl_output_write (out, title, (size_t) title_len);
    pr_spaces (out, sep_right);
    bl_output_write (out, pagebuf, strlen (pagebuf));
    bl_output_write (out, "\n\n\n", 3);
    free (tbuf);
}

static void
pr_footer (bl_output *out, const pr_opts *o, int body_printed)
{
    if (o->terse) return;
    /* -f/-F: a single form-feed replaces the blank footer padding; the next
       page's header leading blanks follow it (so it renders as \f\n...). The
       final page's footer is just the bare \f with no trailing newline. */
    if (o->formfeed) {
        /* A header-only input page still prints one empty body row. */
        if (!body_printed) {
            bl_output_byte (out, '\n');
            if (o->dbl) bl_output_byte (out, '\n');
        }
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
   configured tab stop plus residual spaces). Tracks absolute output column so the
   TAB/space split matches GNU byte-for-byte. Trailing buffered spaces that are
   never followed by a glyph are dropped — that is GNU's trailing-space strip. */
typedef struct { bl_output *out; int pos; int pending; const pr_opts *opts; } pr_tw;

static void
pr_tw_flush (pr_tw *w)            /* == GNU print_white_space () */
{
    int goal = w->pos + w->pending;
    int h = w->pos;
    while (w->opts->tabify && goal - h > 1) {
        int stop = w->opts->out_tab_width;
        int remainder = stop == 8 && h >= 0 ? h & 7 : h % stop;
        int next_tab = h + stop - remainder;          /* POS_AFTER_TAB(8, h) */
        if (next_tab > goal) break;
        bl_output_byte (w->out, w->opts->out_tab);
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
    if (w->pending > 0) pr_tw_flush (w);
    bl_output_byte (w->out, (unsigned char) c);
    if (isprint ((unsigned char) c)) w->pos++;
    else if (c == '\b') w->pos--;
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
     - `colnums != NULL` → COLUMN mode (-COLUMN/-a with -n): each cell prints its
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
    int nl = snprintf (nb, sizeof nb, "%ld", lineno);
    const char *digits = nl > o->num_width ? nb + nl - o->num_width : nb;
    pr_spaces (out, o->num_width - nl);
    bl_output_write (out, digits, strlen (digits));
    bl_output_byte (out, (unsigned char) o->num_sep);
}

/* Render a record as display clumps. The first input byte is measured
   before advancing past the number field. Raw TABs advance the logical input
   position while occupying zero columns in the output tabifier. LIMIT is the
   whole column width, including its number field, or -1 for joined records. */
static int
pr_write_cell (pr_tw *w, const pr_cell *cell, int limit, int clump,
               int number_advance)
{
    const pr_opts *o = w->opts;
    int pos = 0;
    for (size_t i = 0; i < cell->len; i++) {
        unsigned char c = (unsigned char) cell->text[i];
        char repr[5];
        int count = 1, width = 0;
        int printable = isprint (c);
        repr[0] = c;
        if (c == o->in_tab || c == '\t') {
            int stop = c == o->in_tab ? o->in_tab_width : 8;
            width = stop - (stop == 8 ? pos & 7 : pos % stop);
            if (clump || o->expand) count = 0;
        } else if (!printable && (o->show_octal || o->show_control)) {
            if (o->show_octal || c >= 128) {
                snprintf (repr, sizeof repr, "\\%03o", c);
                count = width = 4;
            } else {
                repr[0] = '^'; repr[1] = c ^ 64;
                count = width = 2;
            }
        } else if (c == '\b') {
            if (pos == 0) count = 0;
            else width = -1;
        } else if (printable) width = 1;
        if (limit >= 0 && pos + width > limit) break;
        pos += width;
        if (i == 0) pos += number_advance;
        if (count == 0 && width > 0) w->pending += width;
        else if (count == 1) {
            if (c == ' ') w->pending++;
            else {
                if (w->pending > 0) pr_tw_flush (w);
                bl_output_byte (w->out, c);
                w->pos += printable ? 1 : (c == '\b' ? -1 : 0);
            }
        } else for (int j = 0; j < count; j++) pr_tw_putc (w, repr[j]);
    }
    return pos;
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
    int nl = snprintf (nb, sizeof nb, "%ld", lineno);
    const char *s = nl > o->num_width ? nb + nl - o->num_width : nb;
    if (o->num_width > nl) w->pending += o->num_width - nl;
    for (; *s; s++) pr_tw_putc (w, *s);
    if (o->num_sep == '\t')
        w->pending += PR_NUMBER_WIDTH - o->num_width;
    else
        pr_tw_putc (w, o->num_sep);
}

/* Separators have literal-byte geometry, even for a TAB. Flush spaces at
   the end of each separator independently from the following number. */
static void
pr_separator (pr_tw *w)
{
    const pr_opts *o = w->opts;
    for (int j = 0; j < o->sep_len; j++) {
        unsigned char c = o->separator[j];
        if (c == ' ') w->pending++;
        else {
            if (w->pending > 0) pr_tw_flush (w);
            bl_output_byte (w->out, c); w->pos++;
        }
    }
    if (w->pending > 0) pr_tw_flush (w);
}

static void
pr_emit_row (bl_output *out, const pr_cell *cols, int ncol, const pr_opts *o,
             long lineno, const long *colnums, int last)
{
    /* Keep ordinary one-column delivery out of the column geometry and
       tabifier. Only backspaces require per-byte input-position accounting. */
    if (ncol == 1 && !o->tabify && !o->expand && !o->show_control
        && !o->show_octal && (!o->page_width || o->join)
        && !cols[0].backspace) {
        pr_spaces (out, o->offset);
        if (o->number) pr_print_number (out, o, colnums ? colnums[0] : lineno);
        bl_output_write (out, cols[0].text, cols[0].len);
        bl_output_byte (out, '\n');
        return;
    }
    int num_field = (o->merge && o->number) ? PR_NUMBER_WIDTH : 0;
    int cell_w = (o->width - num_field - (ncol - 1) * o->sep_len) / ncol;
    int stride = cell_w + o->sep_len;
    int truncate = !o->join && (ncol > 1 || o->page_width);
    int clump = o->expand || (ncol > 1 && !(o->sep_len == 1 && o->separator[0] == '\t'));
    pr_tw w = { .out = out, .pos = 0, .pending = 0, .opts = o };
    pr_tw_pad_to (&w, o->offset);
    if (o->number && !colnums) {
        if (ncol == 1) {
            if (!o->tabify && !o->expand && !o->show_control && !o->show_octal && !truncate)
                pr_print_number (out, o, lineno);
            else {
                pr_tw_number (&w, o, lineno);
                if (o->num_sep == '\t') {
                    w.pending = 0;
                    bl_output_byte (out, '\t');
                    w.pos += o->out_tab_width - w.pos % o->out_tab_width;
                }
            }
        } else {
            pr_tw_number (&w, o, lineno);
            if (!cols[0].text && o->join) w.pending = 0;
        }
    }
    if (!o->merge) while (last > 0 && !cols[last - 1].text) last--;
    for (int i = 0; i < last; i++) {
        if (i) {
            if (!o->join) {
                int target = o->offset + num_field + i * stride - o->sep_len;
                w.pending = target - w.pos;
            }
            pr_separator (&w);
        }
        if (colnums && cols[i].text) {
            if (ncol == 1) pr_print_number (out, o, colnums[i]);
            else pr_tw_number (&w, o, colnums[i]);
        }
        int input_end = pr_write_cell (&w, &cols[i], truncate ? cell_w : -1, clump,
                                      truncate && o->number && !o->merge ? PR_NUMBER_WIDTH : 0);
        /* Down-column pages replay stored records. Their final input
           position becomes the origin for the next separator/number,
           even when raw TABs had zero physical output width. */
        if (colnums && !o->across && !w.pending)
            w.pos = (o->join ? (i ? 0 : o->offset) : o->offset + i * stride) + input_end;
        if (o->merge && cols[i].renumber && o->number) {
            if (w.pending > 0) pr_tw_flush (&w);
            pr_tw_number (&w, o, lineno + 1);
        }
    }
    /* Single-column output without -i retains trailing spaces. */
    if (!o->tabify) pr_tw_flush (&w);
    bl_output_byte (out, '\n');
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
    long lineno = o->first_number;

    /* In -d mode each input line occupies two body slots (the line + a trailing
       blank), and GNU will not start a line whose blank won't also fit — so the
       break threshold is body_lines minus the per-line slot count. */
    while (!out->error && page_no <= o->last_page && !(page_no == o->last_page && line_in_page >= o->body_lines)
           && (n = pr_input_line (in, &line, &cap)) != -1) {
        if (!n && in->form_break && line_in_page >= o->body_lines) {
            n = pr_input_line (in, &line, &cap);
            if (n < 0) break;
        }
        if (line_in_page >= o->body_lines) {
            if (page_no >= o->first_page && page_no <= o->last_page) pr_footer (out, o, line_in_page);
            page_no++;
            line_in_page = 0;
        }
        if (line_in_page == 0 && page_no >= o->first_page && page_no <= o->last_page)
            pr_header (out, o, in->title, in->stamp, page_no);
        if (!n && in->form_break) {
            if (page_no >= o->first_page && page_no <= o->last_page) {
                if (o->terse && !o->omit_pagination) bl_output_byte (out, '\f');
                else pr_footer (out, o, line_in_page);
            }
            line_in_page = 0;
            if (page_no == o->last_page) break;
            page_no++; continue;
        }
        pr_cell cell = {0};
        cell.text = line;
        cell.len = pr_chomp (line, (size_t) n);
        cell.backspace = in->record_bs;
        if (page_no >= o->first_page && page_no <= o->last_page) {
            pr_emit_row (out, &cell, 1, o, o->number ? lineno : 0, NULL, 1);
        }
        if (page_no >= o->first_page || !o->number_set) lineno++;
        line_in_page++;
        if (o->dbl) {           /* -d: blank line after each body line, counts as a body line */
            if (page_no >= o->first_page && page_no <= o->last_page
                && !(o->terse && (in->form_break || in->at_eof)))
                bl_output_byte (out, '\n');
            line_in_page++;
        }
        if (in->form_break) {
            if (page_no >= o->first_page && page_no <= o->last_page) {
                if (o->terse && !o->omit_pagination) bl_output_byte (out, '\f');
                else pr_footer (out, o, line_in_page);
            }
            line_in_page = 0;
            if (page_no == o->last_page) break;
            page_no++;
        }
    }
    if (line_in_page > 0 && page_no >= o->first_page && page_no <= o->last_page) pr_footer (out, o, line_in_page);
    free (line);
    return in->failed ? -1 : 0;
}

/* A natural page end suppresses one leading form feed on the next read
   of each column. Across columns share a reader, but not this flag. */
static ssize_t
pr_column_line (pr_input *in, char **line, size_t *cap, int *full)
{
    ssize_t got = pr_input_line (in, line, cap);
    if (*full && got == 0 && in->form_break)
        got = pr_input_line (in, line, cap);
    *full = 0;
    return got;
}

/* GNU skips pages in input-row order even for a down-column layout.
   Boundary flags remain per column, so replaying a balanced output page is
   not equivalent when a later skipped page begins with form feeds. */
static int
pr_skip_column_page (pr_input *in, const pr_opts *o, int *full,
                     size_t rows, char **raw, size_t *cap, long *number)
{
    for (size_t row = 0; row < rows; row++) {
        for (int c = 0; c < o->columns; c++) {
            ssize_t got = pr_column_line (in, raw, cap, &full[c]);
            if (got < 0) return 1;
            if (got > 0 && !o->number_set) (*number)++;
            if (in->form_break) {
                if (row + 1 == rows)
                    memset (full, 0, (size_t) o->columns * sizeof *full);
                return 0;
            }
            if (in->at_eof) return 1;
            if (row + 1 == rows) full[c] = 1;
        }
    }
    return 0;
}

/* Down columns need at most one page to balance; across columns need only
   one row. Neither path reads the next page before delivering this one. */
static int
pr_columns (bl_output *out, pr_input *in, const pr_opts *o)
{
    int ncol = o->columns;
    size_t rows_per_page = o->dbl ? o->body_lines / 2 : o->body_lines;
    if (!rows_per_page) rows_per_page = 1;
    if (rows_per_page > SIZE_MAX / (size_t) ncol) {
        in->failed = EOVERFLOW; return -1;
    }
    size_t per_page = rows_per_page * ncol;
    pr_cell *lines = NULL, *cols = calloc ((size_t) ncol, sizeof *cols);
    size_t capacity = 0;
    int *full = calloc ((size_t) ncol, sizeof *full);
    long *colnums = o->number ? calloc ((size_t) ncol, sizeof *colnums) : NULL;
    char *raw = NULL;
    size_t rawcap = 0;
    int page_no = 1, ended = 0;
    long number_base = o->first_number;
    if (!cols || !full || (o->number && !colnums)) in->failed = ENOMEM;

    while (!in->failed && !out->error && !ended && page_no <= o->last_page) {
        size_t count = 0, rows = 0;
        int form_break = 0;
        int selected = page_no >= o->first_page;
        if (!selected) {
            ended = pr_skip_column_page (in, o, full, rows_per_page,
                                         &raw, &rawcap, &number_base);
            page_no++;
            continue;
        }
        do {
            int c = o->across ? count % ncol : count / rows_per_page;
            ssize_t got = pr_column_line (in, &raw, &rawcap, &full[c]);
            if (got < 0) { ended = 1; break; }
            form_break = in->form_break;
            if (in->at_eof) ended = 1;
            if (got > 0) {
                size_t slot = o->across ? count % ncol : count;
                if (slot == capacity) {
                    size_t limit = o->across ? (size_t) ncol : per_page;
                    size_t next = capacity ? capacity * 2 : 64;
                    if (next < capacity || next > limit) next = limit;
                    if (next > SIZE_MAX / sizeof *lines) { in->failed = EOVERFLOW; break; }
                    pr_cell *grown = realloc (lines, next * sizeof *lines);
                    if (!grown) { in->failed = ENOMEM; break; }
                    lines = grown; capacity = next;
                }
                size_t len = pr_chomp (raw, (size_t) got);
                char *copy = malloc (len + 1);
                if (!copy) { in->failed = ENOMEM; break; }
                memcpy (copy, raw, len + 1);
                lines[slot] = (pr_cell) { .text = copy, .len = len,
                                        .backspace = in->record_bs };
                count++;
            }
            if (o->across && (count % ncol == 0 || form_break)) {
                size_t cells = count - rows * ncol;
                if (cells) {
                    if (selected) {
                        if (!rows) pr_header (out, o, in->title, in->stamp, page_no);
                        memset (cols, 0, (size_t) ncol * sizeof *cols);
                        for (size_t j = 0; j < cells; j++) {
                            cols[j] = lines[j];
                            if (colnums) colnums[j] = number_base + (long) (rows * ncol + j);
                        }
                        pr_emit_row (out, cols, ncol, o, 0, colnums, ncol);
                        if (o->dbl && !(o->terse && (form_break || ended))) bl_output_byte (out, '\n');
                    }
                    for (size_t j = 0; j < cells; j++) free (lines[j].text);
                    rows++;
                }
            }
        } while (!form_break && !ended && count < per_page && !out->error);

        if (o->across) {
            /* EOF can finish a partial row. */
            size_t cells = count > rows * ncol ? count - rows * ncol : 0;
            if (cells) {
                if (selected) {
                    if (!rows) pr_header (out, o, in->title, in->stamp, page_no);
                    memset (cols, 0, (size_t) ncol * sizeof *cols);
                    for (size_t j = 0; j < cells; j++) {
                        cols[j] = lines[j];
                        if (colnums) colnums[j] = number_base + (long) (rows * ncol + j);
                    }
                    pr_emit_row (out, cols, ncol, o, 0, colnums, ncol);
                    if (o->dbl && !o->terse) bl_output_byte (out, '\n');
                }
                for (size_t j = 0; j < cells; j++) free (lines[j].text);
                rows++;
            }
        } else {
            size_t base = count / ncol, rem = count % ncol;
            rows = base + (rem != 0);
            if (selected && (count || form_break)) {
                pr_header (out, o, in->title, in->stamp, page_no);
                for (size_t row = 0; row < rows && !out->error; row++) {
                    memset (cols, 0, (size_t) ncol * sizeof *cols);
                    for (int c = 0; c < ncol; c++) {
                        size_t start = c * base + ((size_t) c < rem ? (size_t) c : rem);
                        if (row < base + ((size_t) c < rem)) {
                            cols[c] = lines[start + row];
                            if (colnums) colnums[c] = number_base + (long) (start + row);
                        }
                    }
                    pr_emit_row (out, cols, ncol, o, 0, colnums, ncol);
                    if (o->dbl && !(o->terse && row + 1 == rows && (ended || form_break)))
                        bl_output_byte (out, '\n');
                }
            }
            for (size_t j = 0; j < count; j++) free (lines[j].text);
        }
        if (selected && (count || form_break)) {
            if (o->across && !count) pr_header (out, o, in->title, in->stamp, page_no);
            pr_footer (out, o, (int) (o->dbl ? rows * 2 : rows));
            if (form_break && o->terse && !o->omit_pagination) bl_output_byte (out, '\f');
            bl_output_flush (out);
        }
        if (count == per_page && !form_break)
            for (int c = 0; c < ncol; c++) full[c] = 1;
        if (selected || !o->number_set) number_base += (long) count;
        if (page_no == o->last_page) break;
        page_no++;
    }
    free (raw); free (lines); free (cols); free (full); free (colnums);
    return in->failed ? -1 : 0;
}

/* Merge reader ownership is separate from column page state: repeated '-'
   operands share bytes and EOF, while each column holds/releases independently. */
static int
pr_merge (bl_output *out, pr_input *ins, int n, const pr_opts *o)
{
    char **lines = calloc ((size_t) n, sizeof *lines);
    size_t *caps = calloc ((size_t) n, sizeof *caps);
    pr_cell *cols = calloc ((size_t) n, sizeof *cols);
    int *state = calloc ((size_t) n, sizeof *state); /* 0 open, 1 held, 2 closed */
    int *full = calloc ((size_t) n, sizeof *full);
    int page_no = 1, failed = 0;
    long lineno = o->first_number;
    time_t now = time (NULL);
    int rows_per_page = o->dbl ? o->body_lines / 2 : o->body_lines;
    if (!rows_per_page) rows_per_page = 1;
    if (!lines || !caps || !cols || !state || !full) {
        free (lines); free (caps); free (cols); free (state); free (full);
        ins[0].failed = ENOMEM; return -1;
    }
    while (!out->error && page_no <= o->last_page) {
        int ready = 0, rows = 0, form_break = 0, page_started = 0;
        int selected = page_no >= o->first_page;
        for (int i = 0; i < n; i++) if (state[i] != 2) { state[i] = 0; ready++; }
        if (!ready) break;
        while (ready && rows < rows_per_page && !out->error) {
            int any = 0, last = n;
            memset (cols, 0, (size_t) n * sizeof *cols);
            for (int i = 0; i < n; i++) {
                if (state[i]) continue;
                pr_input *reader = &ins[i];
                if (!reader->owned)
                    for (int j = 0; j < i; j++)
                        if (!ins[j].owned) { reader = &ins[j]; break; }
                ssize_t got = pr_column_line (reader, &lines[i], &caps[i], &full[i]);
                if (reader->failed) ins[i].failed = reader->failed;
                if (!selected && !o->number_set && i == 0
                    && !(got == 0 && reader->form_break)) lineno++;
                if (reader->form_break) { state[i] = 1; form_break = 1; }
                else if (got < 0 || reader->at_eof) state[i] = 2;
                if (got > 0) {
                    any = 1;
                    cols[i] = (pr_cell) { .text = lines[i],
                        .backspace = reader->record_bs,
                        .len = pr_chomp (lines[i], (size_t) got) };
                }
                if (state[i]) ready--;
                /* GNU aligns a just-closed first column before discovering
                   whether the remaining open columns contain another record. */
                if (i == 0 && got > 0 && reader->at_eof && ready)
                    cols[0].renumber = 1;
                if (!ready) { last = got > 0 ? i + 1 : i; break; }
            }
            if (selected && !page_started && (any || form_break)) {
                pr_header (out, o, NULL, now, page_no); page_started = 1;
            }
            if (!any) break;
            if (selected) {
                pr_emit_row (out, cols, n, o, o->number ? lineno : 0, NULL, last);
                if (o->dbl && (ready || !o->terse)) bl_output_byte (out, '\n');
            }
            if (selected) {
                lineno++;
                if (cols[0].renumber) lineno++;
            }
            rows++;
        }
        if (selected && page_started) {
            pr_footer (out, o, o->dbl ? rows * 2 : rows);
            if (form_break && o->terse && !o->omit_pagination) bl_output_byte (out, '\f');
            bl_output_flush (out);
        }
        if (rows == rows_per_page)
            for (int i = 0; i < n; i++) if (!state[i]) full[i] = 1;
        if (page_no == o->last_page) break;
        page_no++;
    }
    for (int i = 0; i < n; i++) { free (lines[i]); if (ins[i].failed) failed = 1; }
    free (lines); free (caps); free (cols); free (state); free (full);
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
        return EXECUTION_FAILURE;
    if (parsed < 1) {
        builtin_error ("%s: invalid number of lines: %s", opt, arg);
        builtin_usage ();
        return EXECUTION_FAILURE;
    }
    o->page_lines = parsed;
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

/* CLI parsing is kept separate from descriptor ownership and rendering. */
static int
pr_optional_format (const char *arg, unsigned char *sep, int *width)
{
    if (!arg) return 0;
    if (!*arg) return EXECUTION_FAILURE;
    if (!isdigit ((unsigned char) *arg)) *sep = *arg++;
    if (*arg) {
        if (pr_parse_int_arg ("format", arg, width) || *width < 1) return EXECUTION_FAILURE;
    }
    return 0;
}

static int
pr_options (WORD_LIST *list, pr_opts *o, const char ***files, int *count)
{
    size_t total = 0;
    for (WORD_LIST *p = list; p; p = p->next) total++;
    *files = calloc (total + 1, sizeof **files);
    if (!*files) { builtin_error ("out of memory"); return 1; }
    const char *old_sep = NULL, *new_sep = NULL;
    int old_s = 0, new_s = 0, end_options = 0;
    struct option_name { const char *name; char key; int argument; };
    static const struct option_name names[] = {
        {"across", 'a', 0}, {"show-control-chars", 'c', 0},
        {"double-space", 'd', 0}, {"date-format", 'D', 1},
        {"expand-tabs", 'e', 2}, {"form-feed", 'f', 0},
        {"header", 'h', 1}, {"output-tabs", 'i', 2},
        {"join-lines", 'J', 0}, {"length", 'l', 1}, {"merge", 'm', 0},
        {"number-lines", 'n', 2}, {"first-line-number", 'N', 1},
        {"indent", 'o', 1}, {"no-file-warnings", 'r', 0},
        {"separator", 's', 2}, {"sep-string", 'S', 2},
        {"omit-header", 't', 0}, {"omit-pagination", 'T', 0},
        {"show-nonprinting", 'v', 0}, {"width", 'w', 1},
        {"page-width", 'W', 1}, {"columns", '#', 1}, {"pages", '+', 1},
        {NULL, 0, 0}
    };
    for (; list; list = list->next) {
        const char *word = list->word->word;
        if (!end_options && !strcmp (word, "--")) { end_options = 1; continue; }
        if (!end_options && (!strcmp (word, "--help") || !strcmp (word, "--version"))) {
            if (word[2] == 'h') builtin_usage ();
            else puts ("pr 1.1 (bash-loadable)");
            return -1;
        }
        if (end_options || (!word[0] || (word[0] != '-' && word[0] != '+')) || !word[1]
            || (word[0] == '+' && !isdigit ((unsigned char) word[1]))) {
            (*files)[(*count)++] = word; continue;
        }
        int long_option = word[0] == '-' && word[1] == '-';
        const char *cursor = word + (long_option ? 2 : 1);
        do {
            char key;
            const char *arg = NULL;
            int kind = 0;
            if (word[0] == '+') { key = '+'; arg = cursor; cursor += strlen (cursor); }
            else if (long_option) {
                const char *equals = strchr (cursor, '=');
                size_t len = equals ? (size_t) (equals - cursor) : strlen (cursor);
                int found = -1;
                for (int k = 0; names[k].name; k++)
                    if (strlen (names[k].name) == len && !strncmp (cursor, names[k].name, len)) { found = k; break; }
                if (found < 0) goto invalid;
                key = names[found].key; kind = names[found].argument;
                if (equals) { if (!kind) goto invalid; arg = equals + 1; }
                cursor += strlen (cursor);
            } else if (isdigit ((unsigned char) *cursor)) {
                key = '#'; arg = cursor; cursor += strlen (cursor);
            } else {
                key = *cursor++;
                if (strchr ("DhlNowW", key)) kind = 1;
                else if (strchr ("einsS", key)) kind = 2;
                if (kind && *cursor) { arg = cursor; cursor += strlen (cursor); }
            }
            if (kind == 1 && !arg) {
                if (!list->next) goto invalid;
                list = list->next; arg = list->word->word;
            }
            int value = 0;
            switch (key) {
            case 'a': o->across = 1; break;
            case 'b': break; /* balancing is the default */
            case 'c': o->show_control = 1; break;
            case 'd': o->dbl = 1; break;
            case 'D': o->date_format = arg; break;
            case 'e': o->expand = 1;
                if (pr_optional_format (arg, &o->in_tab, &o->in_tab_width)) goto invalid;
                break;
            case 'f': case 'F': o->formfeed = 1; break;
            case 'h': o->header = arg; break;
            case 'i': o->tabify = 1;
                if (pr_optional_format (arg, &o->out_tab, &o->out_tab_width)) goto invalid;
                break;
            case 'J': o->join = 1; break;
            case 'l': if (pr_set_length (o, word, arg)) goto invalid; break;
            case 'm': o->merge = 1; break;
            case 'n': {
                unsigned char sep = o->num_sep;
                o->number = 1;
                if (pr_optional_format (arg, &sep, &o->num_width)) goto invalid;
                if (o->num_width > INT_MAX - 8) goto invalid;
                o->num_sep = sep; break;
            }
            case 'N': {
                char *end; errno = 0;
                long n = strtol (arg, &end, 10);
                if (!*arg || *end || errno || n < INT_MIN || n > INT_MAX) goto invalid;
                o->first_number = n; o->number_set = 1; break;
            }
            case 'o': if (pr_parse_int_arg (word, arg, &o->offset)) goto invalid; break;
            case 'r': o->no_warn = 1; break;
            case 's': old_s = 1; old_sep = arg; break;
            case 'S': new_s = 1; new_sep = arg ? arg : ""; break;
            case 't': o->terse = 1; o->omit_pagination = 0; break;
            case 'T': o->terse = o->omit_pagination = 1; break;
            case 'v': o->show_octal = 1; break;
            case 'w': case 'W':
                if (pr_parse_int_arg (word, arg, &value) || value < 1) goto invalid;
                if (key == 'W' || !o->page_width) o->width = value;
                if (key == 'W') o->page_width = 1;
                else o->width_set = 1;
                break;
            case '#':
                if (pr_parse_int_arg (word, arg, &value) || value < 1) goto invalid;
                o->columns = value; o->columns_set = 1; break;
            case '+': {
                char *end; errno = 0;
                long first = strtol (arg, &end, 10), last = INT_MAX;
                if (end == arg || first < 1 || first > INT_MAX || errno) goto invalid;
                if (*end == ':') {
                    const char *tail = end + 1;
                    last = strtol (tail, &end, 10);
                    if (end == tail || last < first || last > INT_MAX || errno) goto invalid;
                }
                if (*end) goto invalid;
                o->first_page = first; o->last_page = last; break;
            }
            default: goto invalid;
            }
        } while (*cursor && !long_option);
        continue;
invalid:
        builtin_error ("invalid option or argument: %s", word);
        builtin_usage ();
        return EXECUTION_FAILURE;
    }
    if (o->merge && (o->columns_set || o->across)) {
        builtin_error ("cannot combine merge with columns or across"); return 1;
    }
    if (o->page_lines <= 10) {
        o->terse = 1;
        /* GNU's implicit short-page mode re-enables input form feeds,
           including when -T was explicitly requested. */
        o->omit_pagination = 0;
    }
    /* Capital options control separation independently of width. */
    if (old_s && !new_s) {
        if (!o->width_set && !o->page_width) o->join = 1;
        o->separator = old_sep ? old_sep : (o->join ? "\t" : "");
    } else o->separator = new_s ? new_sep : (o->join ? "\t" : " ");
    if (!o->join && !strcmp (o->separator, "\t")) o->separator = " ";
    o->sep_len = strlen (o->separator);
    return 0;
}


int
pr_builtin (WORD_LIST *list)
{
    pr_opts o = { .page_lines = 66, .width = 72, .columns = 1,
                  .num_width = PR_DEFAULT_CHARS_PER_NUMBER, .num_sep = '\t',
                  .in_tab = '\t', .out_tab = '\t', .in_tab_width = 8, .out_tab_width = 8,
                  .date_format = "%Y-%m-%d %H:%M", .first_page = 1, .last_page = INT_MAX,
                  .first_number = 1 };
    const char **files = NULL;
    int n_files = 0;
    int parsed = pr_options (list, &o, &files, &n_files);
    if (parsed) { free (files); return parsed == -1 ? 0 : parsed; }
    /* With no operands GNU disables parallel input after translating old
       width options; an explicit -w therefore still truncates this stream. */
    if (o.merge && o.width_set) o.page_width = 1;
    if (o.merge && !n_files) o.merge = 0;
    o.body_lines = o.terse ? o.page_lines : o.page_lines - 10;
    if (o.dbl) o.body_lines = o.body_lines > 1 ? o.body_lines - (o.body_lines & 1) : 2;
    int ncol = o.merge && n_files ? n_files : o.columns;
    int number_width = o.num_sep == '\t' ? o.num_width + 8 - o.num_width % 8 : o.num_width + 1;
    if ((int64_t) o.width - (o.merge && o.number ? number_width : 0)
        - (int64_t) (ncol - 1) * o.sep_len < ncol) {
        builtin_error ("page width too narrow"); free (files); return 1;
    }
    o.tabify |= ncol > 1;
    int rc = EXECUTION_SUCCESS;

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
            for (int f = 0; f < n_files; f++) {
                if (pr_input_open (&ins[opened], files[f]) < 0) {
                    if (!o.no_warn) pr_report (&output, files[f], errno);
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
        /* Paginate operands separately, retaining standard-input read-ahead
           within this invocation when a selected page range ends early. */
        pr_input standard_input;
        int standard_open = 0;
        for (int f = 0; f < n_files && !output.error; f++) {
            pr_input file_input, *in;
            int is_standard = !strcmp (files[f], "-");
            in = is_standard ? &standard_input : &file_input;
            if (!is_standard || !standard_open) {
                if (pr_input_open (in, files[f]) < 0) {
                    if (!o.no_warn) pr_report (&output, files[f], errno);
                    rc = EXECUTION_FAILURE;
                    continue;
                }
                if (is_standard) standard_open = 1;
            } else in->stamp = time (NULL);
            if (o.merge) { in->title = NULL; in->stamp = time (NULL); }
            int bad = (o.columns > 1 && !o.merge) ? pr_columns (&output, in, &o)
                                                  : pr_single (&output, in, &o);
            if (bad < 0) {
                pr_report (&output, in->title, in->failed);
                rc = EXECUTION_FAILURE;
            }
            if (!is_standard) pr_input_close (in);
        }
        if (standard_open) pr_input_close (&standard_input);
    }

    bl_output_flush (&output);
    if (output.error) {
        builtin_error ("write error: %s", strerror (output.error));
        rc = EXECUTION_FAILURE;
    }
    free (files);
    return rc;
}

char *pr_doc[] = {
    "Format text for printing (POSIX pr).",
    "",
    "    pr [--help|--version] [-t] [-m] [-h HEADER] [-l LINES] [-w WIDTH] [-n] [-COLUMN] [-N NUMBER] [-a] [-o OFFSET] [-s[SEP]] [FILE...]",
    "",
    "    -t          terse: no header / footer paging",
    "    -m          merge mode: side-by-side columns of all FILEs",
    "    -d          double-space the output (blank line after each body line)",
    "    -f, -F      use a form-feed to separate pages (no blank padding)",
    "    -h HEADER   override page header (default: filename)",
    "    -l LINES    lines per page (default 66 — 5 hdr + 56 body + 5 ftr)",
    "    -w WIDTH    column-layout width (default 72, positive)",
    "    -n[SEP[N]]  number body lines (N digits, default 5; SEP after, def tab)",
    "    -COLUMN     lay one file out in COLUMN balanced columns",
    "    -N NUMBER   first line number on the first page printed",
    "    -a          (--across) fill -N columns left-to-right, not top-down",
    "    -o OFFSET   indent every line by OFFSET spaces (left margin)",
    "    -s[STRING]  separate columns (default tab); -w retains truncation",
    "    -S[STRING]  set separator independently of column alignment",
    "    -J          join full lines; -W WIDTH truncates even one column",
    "    -e[C[N]]    expand input tabs; -i[C[N]] tabify output (default 8)",
    "    -c, -v      show control bytes using caret / octal notation",
    "    -D FORMAT   strftime format for the header date",
    "    -r          suppress failed-open diagnostics",
    "    -T          omit headers, trailers and input form-feed bytes",
    "    +FIRST:LAST or --pages=FIRST:LAST: print selected pages",
    "    Options may follow operands; long GNU option names are accepted.",
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
    "pr [OPTION...] [+FIRST[:LAST]] [-COLUMN] [FILE...]",
    0
};
