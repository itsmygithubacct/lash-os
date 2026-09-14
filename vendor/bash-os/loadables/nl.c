/* nl.c — POSIX nl(1) as a bash builtin.
 *
 *   bashnl [-ba|-bt|-bn|-bpBRE] [-h STYLE] [-f STYLE] [-d CC] [-i N] [-l N]
 *          [-s SEP] [-v N] [-w W] [-n ln|rn|rz] [-p] [FILE...]
 *
 * Numbers lines from FILE(s) (or stdin), with the header/body/footer
 * logical-page sections of nl(1).
 *
 * Body/header/footer style:
 *   a      number all lines
 *   t      number only non-empty lines (body default; header/footer default n)
 *   n      no numbering (silent passthrough)
 *   pBRE   number only lines matching BRE
 *
 * Other flags:
 *   -i N        increment between numbered lines (default 1)
 *   -l N        group N empty lines as one numbered blank line (default 1)
 *   -s SEP      separator between number and text (default \t)
 *   -w W        line-number column width (default 6)
 *   -n FORMAT   number format: ln (left), rn (right, default), rz (zero-pad)
 *   -v N        initial line number (default 1)
 *   -d CC       section delimiter string (default \:); one character is
 *               completed with ':', an empty string disables sections
 *   -p          do NOT reset numbering at logical page breaks
 *
 * Long aliases mirror nl(1), and unambiguous abbreviations of them are
 * accepted, as are options written after an operand:
 *   --body-numbering, --header-numbering, --footer-numbering,
 *   --section-delimiter, --line-increment, --join-blank-lines,
 *   --number-separator, --number-width, --number-format,
 *   --starting-line-number, --no-renumber
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
#include <errno.h>
#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <fcntl.h>
#include <regex.h>

#include "loadables.h"
#include "bl-output.h"

typedef enum { BNL_ALL = 0, BNL_NONEMPTY, BNL_NONE, BNL_REGEX } bnl_body;
typedef enum { BNL_RN = 0, BNL_LN, BNL_RZ } bnl_fmt;
typedef enum { BNL_BODY = 0, BNL_HEADER, BNL_FOOTER } bnl_section;

typedef struct {
    bnl_body body;
    regex_t  body_re;
    int      body_re_compiled;
    bnl_body header;
    regex_t  header_re;
    int      header_re_compiled;
    bnl_body footer;
    regex_t  footer_re;
    int      footer_re_compiled;
    intmax_t incr;
    intmax_t start;
    intmax_t blank_join;
    int      width;
    bnl_fmt  fmt;
    const char *sep;
    size_t   sep_len;
    const char *delim;          /* one delimiter unit; empty disables sections */
    size_t   delim_len;
    char     delim_pad[3];      /* storage for a completed one-character -d */
    int      no_reset;
} bnl_opts;

/* nl(1) keeps the line number, the run of blank lines and the current
   section in process-wide storage that a fresh process resets. A builtin
   stays in the shell's process, so this call-local state is what makes one
   invocation independent of the last while still carrying across the FILE
   operands of a single invocation, exactly as nl(1)'s own statics do. */
typedef struct {
    intmax_t    counter;
    intmax_t    blanks;
    bnl_section section;
    int         overflow;       /* the last increment overflowed */
} bnl_state;

enum { BNL_OK = 0, BNL_FILE_ERROR, BNL_FATAL };

extern char *nl_doc[];

static const char bnl_spaces[64] =
    "                                                                ";
static const char bnl_zeros[64] =
    "0000000000000000000000000000000000000000000000000000000000000000";

static void
bnl_print_help (void)
{
    for (char **p = nl_doc; *p; p++)
        puts (*p);
}

static void
bnl_emit_fill (bl_output *out, size_t n, const char *fill)
{
    while (n && !out->error) {
        size_t chunk = n < sizeof bnl_spaces ? n : sizeof bnl_spaces;
        bl_output_write (out, fill, chunk);
        n -= chunk;
    }
}

/* Mirror nl(1)'s printf formats (FORMAT_LEFT / FORMAT_RIGHT_LZ /
   FORMAT_RIGHT_NOLZ) without printf, so an arbitrary -w width costs no
   allocation and a negative line number pads as "-0005", not "0000-5". */
static void
bnl_emit_number (bl_output *out, intmax_t n, const bnl_opts *o)
{
    char digits[32];
    int len = snprintf (digits, sizeof digits, "%jd", n);
    size_t width = (size_t) o->width;
    size_t pad = (size_t) len < width ? width - (size_t) len : 0;

    switch (o->fmt) {
        case BNL_LN:
            bl_output_write (out, digits, (size_t) len);
            bnl_emit_fill (out, pad, bnl_spaces);
            break;
        case BNL_RZ: {
            size_t sign = digits[0] == '-' ? 1 : 0;
            bl_output_write (out, digits, sign);
            bnl_emit_fill (out, pad, bnl_zeros);
            bl_output_write (out, digits + sign, (size_t) len - sign);
            break;
        }
        case BNL_RN:
        default:
            bnl_emit_fill (out, pad, bnl_spaces);
            bl_output_write (out, digits, (size_t) len);
            break;
    }
    bl_output_write (out, o->sep, o->sep_len);
}

/* Match nl(1): an unnumbered line reserves the number and separator width. */
static void
bnl_emit_blank_field (bl_output *out, const bnl_opts *o)
{
    bnl_emit_fill (out, (size_t) o->width + o->sep_len, bnl_spaces);
}

/* nl(1) reports "line number overflow" only when a later line actually needs
   a number, so the last line of a file may carry the extreme value and still
   exit successfully. Defer the diagnosis the same way. */
static int
bnl_number_line (bl_output *out, bnl_state *st, const bnl_opts *o)
{
    if (st->overflow) {
        builtin_error ("line number overflow");
        return -1;
    }
    bnl_emit_number (out, st->counter, o);
    if (o->incr > 0 ? st->counter > INTMAX_MAX - o->incr
                    : o->incr < 0 && st->counter < INTMAX_MIN - o->incr)
        st->overflow = 1;
    else
        st->counter += o->incr;
    return 0;
}

static int
bnl_parse_intmax (const char *v, intmax_t *out)
{
    char *end = NULL;
    intmax_t n;
    if (!v || !*v)
        return -1;
    errno = 0;
    n = strtoimax (v, &end, 10);
    if (errno || !end || end == v || *end)
        return -1;
    *out = n;
    return 0;
}

static int
bnl_set_style (const char *v, const char *what, bnl_body *out,
               regex_t *re, int *re_compiled)
{
    /* nl(1) (build_type_arg) switches on the FIRST character of the style
       only: for a/t/n any trailing characters are ignored ("-bary" == "-ba"),
       and 'p' takes the remainder as the BRE, which may be empty. */
    switch (v ? v[0] : '\0') {
        case 'a': *out = BNL_ALL;      return 0;
        case 't': *out = BNL_NONEMPTY; return 0;
        case 'n': *out = BNL_NONE;     return 0;
        case 'p': {
            regex_t next;
            if (regcomp (&next, v + 1, REG_NOSUB) != 0) {
                builtin_error ("invalid regular expression");
                return -1;
            }
            if (*re_compiled)
                regfree (re);
            *re = next;
            *re_compiled = 1;
            *out = BNL_REGEX;
            return 0;
        }
        default:
            builtin_error ("invalid %s numbering style: '%s'", what, v ? v : "");
            return -1;
    }
}

static int
bnl_apply (bnl_opts *o, int opt, const char *val)
{
    intmax_t n;

    switch (opt) {
        case 'b':
            return bnl_set_style (val, "body", &o->body, &o->body_re, &o->body_re_compiled);
        case 'h':
            return bnl_set_style (val, "header", &o->header, &o->header_re, &o->header_re_compiled);
        case 'f':
            return bnl_set_style (val, "footer", &o->footer, &o->footer_re, &o->footer_re_compiled);
        case 'd': {
            size_t len = strlen (val);
            /* nl(1) completes a one-character delimiter with ':' and treats
               an empty one as "no sections at all". */
            if (len == 0) {
                o->delim = "";
                o->delim_len = 0;
            } else if (len == 1) {
                o->delim_pad[0] = val[0];
                o->delim_pad[1] = ':';
                o->delim_pad[2] = '\0';
                o->delim = o->delim_pad;
                o->delim_len = 2;
            } else {
                o->delim = val;
                o->delim_len = len;
            }
            return 0;
        }
        case 'i':
            if (bnl_parse_intmax (val, &o->incr) < 0) {
                builtin_error ("invalid line number increment: '%s'", val);
                return -1;
            }
            return 0;
        case 'v':
            if (bnl_parse_intmax (val, &o->start) < 0) {
                builtin_error ("invalid starting line number: '%s'", val);
                return -1;
            }
            return 0;
        case 'l':
            if (bnl_parse_intmax (val, &n) < 0 || n < 0) {
                builtin_error ("invalid line number of blank lines: '%s'", val);
                return -1;
            }
            o->blank_join = n;
            return 0;
        case 's':
            o->sep = val;
            o->sep_len = strlen (val);
            return 0;
        case 'w':
            if (bnl_parse_intmax (val, &n) < 0 || n < 1 || n > INT_MAX) {
                builtin_error ("invalid line number field width: '%s'", val);
                return -1;
            }
            o->width = (int) n;
            return 0;
        case 'n':
            if (!strcmp (val, "ln"))      o->fmt = BNL_LN;
            else if (!strcmp (val, "rn")) o->fmt = BNL_RN;
            else if (!strcmp (val, "rz")) o->fmt = BNL_RZ;
            else {
                builtin_error ("invalid line numbering format: '%s'", val);
                return -1;
            }
            return 0;
        default:
            builtin_error ("invalid option -- '%c'", opt);
            return -1;
    }
}

/* How many times the delimiter unit fills the line, ignoring one trailing
   newline: 3 opens a header, 2 a body, 1 a footer, 0 is ordinary text.
   nl(1) compares the raw bytes, so a carriage return before the newline
   keeps the line ordinary. */
static int
bnl_section_delim (const char *line, size_t n, const bnl_opts *o)
{
    size_t len = n, reps, i;
    if (len > 0 && line[len - 1] == '\n')
        len--;
    if (o->delim_len == 0 || len == 0 || len % o->delim_len)
        return 0;
    reps = len / o->delim_len;
    if (reps > 3)
        return 0;
    for (i = 0; i < reps; i++)
        if (memcmp (line + i * o->delim_len, o->delim, o->delim_len) != 0)
            return 0;
    return (int) reps;
}

static int
bnl_matches (const char *line, size_t n, bnl_section section, const bnl_opts *o)
{
    const regex_t *re = section == BNL_HEADER
                            ? (o->header_re_compiled ? &o->header_re : NULL)
                        : section == BNL_FOOTER
                            ? (o->footer_re_compiled ? &o->footer_re : NULL)
                            : (o->body_re_compiled ? &o->body_re : NULL);
    size_t len = n;
    if (!re)
        return 0;
    /* nl(1) searches the line content WITHOUT the trailing newline (over
       line_buf.length - 1), so the BRE "." never matches an empty line, and
       it passes an explicit length, so a NUL inside the line does not end
       the subject. */
    if (len > 0 && line[len - 1] == '\n')
        len--;
#ifdef REG_STARTEND
    {
        regmatch_t range;
        range.rm_so = 0;
        range.rm_eo = (regoff_t) len;
        return regexec (re, line, 0, &range, REG_STARTEND) == 0;
    }
#else
    {
        char *text = (char *) line;
        char saved = text[len];
        int hit;
        text[len] = '\0';
        hit = regexec (re, text, 0, NULL, 0) == 0;
        text[len] = saved;
        return hit;
    }
#endif
}

/* Input comes from the descriptor, never from the process-wide stdin stream.
   Bash's `stdin` FILE is shared by every builtin in the shell, so whatever an
   earlier one read ahead of what it printed is still sitting in that buffer,
   and a later redirection replaces the descriptor without touching it. Reading
   the descriptor is what an external nl(1) does and the only way to see the
   bytes this redirection actually carries. A short read is processed as it
   arrives, so a pipe or a terminal still streams. */
#define BNL_INPUT_SIZE 65536

typedef struct {
    int    fd;
    int    error;               /* errno of a failed read */
    int    eof;
    size_t pos, len;
    unsigned char *data;
} bnl_input;

static void
bnl_input_open (bnl_input *in, int fd)
{
    in->fd = fd;
    in->error = 0;
    in->eof = 0;
    in->pos = in->len = 0;
}

/* One line into *line, with its trailing newline and any NUL bytes, growing
   the buffer as needed. Returns its length; 0 means end of input, and a read
   failure leaves in->error set with any partial line discarded, as a failed
   getline did. */
static size_t
bnl_read_line (bnl_input *in, char **line, size_t *cap)
{
    size_t used = 0;

    for (;;) {
        unsigned char *start, *stop;
        size_t take;

        if (in->pos == in->len) {
            ssize_t n;
            if (in->eof || in->error)
                break;
            n = read (in->fd, in->data, BNL_INPUT_SIZE);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                in->error = errno;
                break;
            }
            if (n == 0) {
                in->eof = 1;
                break;
            }
            in->pos = 0;
            in->len = (size_t) n;
        }
        start = in->data + in->pos;
        stop = memchr (start, '\n', in->len - in->pos);
        take = stop ? (size_t) (stop - start) + 1 : in->len - in->pos;
        if (take > SIZE_MAX - used - 1) {
            in->error = EOVERFLOW;
            break;
        }
        if (used + take + 1 > *cap) {
            size_t want = *cap ? *cap : 128;
            char *grown;
            while (want < used + take + 1) {
                if (want > (size_t) -1 / 2) { want = used + take + 1; break; }
                want *= 2;
            }
            grown = realloc (*line, want);
            if (!grown) {
                in->error = ENOMEM;
                break;
            }
            *line = grown;
            *cap = want;
        }
        memcpy (*line + used, start, take);
        used += take;
        in->pos += take;
        if (stop)
            break;
    }
    /* getline terminated its buffer, and callers that take the line as a C
       string — the regexec fallback, and any library that measures it — rely
       on that. The growth above always reserves the extra byte. */
    if (*line && used < *cap)
        (*line)[used] = '\0';
    return used;
}

static int
bnl_process (bnl_input *in, const char *name, char **line, size_t *cap,
             bl_output *out, bnl_opts *o, bnl_state *st)
{
    int status = BNL_OK;

    while (!out->error) {
        size_t len = bnl_read_line (in, line, cap);
        int delim, numbered = 0;
        bnl_body style;

        if (in->error || len == 0)
            break;
        delim = bnl_section_delim (*line, len, o);
        if (delim) {
            st->section = delim == 3 ? BNL_HEADER : delim == 2 ? BNL_BODY : BNL_FOOTER;
            if (!o->no_reset) {
                st->counter = o->start;
                st->overflow = 0;
            }
            bl_output_byte (out, '\n');
            continue;
        }

        style = st->section == BNL_HEADER ? o->header
              : st->section == BNL_FOOTER ? o->footer : o->body;
        switch (style) {
            case BNL_ALL:
                /* Only this branch touches the blank run, so a run survives
                   a section delimiter and a file boundary, as in nl(1). */
                if (o->blank_join > 1) {
                    if (len != 1 || (*line)[0] != '\n' || ++st->blanks == o->blank_join) {
                        numbered = 1;
                        st->blanks = 0;
                    }
                } else
                    numbered = 1;
                break;
            case BNL_NONEMPTY:
                numbered = !(len == 1 && (*line)[0] == '\n');
                break;
            case BNL_REGEX:
                numbered = bnl_matches (*line, len, st->section, o);
                break;
            case BNL_NONE:
                numbered = 0;
                break;
        }

        if (numbered) {
            if (bnl_number_line (out, st, o) < 0) {
                status = BNL_FATAL;
                break;
            }
        } else
            bnl_emit_blank_field (out, o);
        bl_output_write (out, *line, len);
        /* nl(1)'s readlinebuffer appends the delimiter at end of file, so a
           final line lacking a newline still gets one on output. */
        if ((*line)[len - 1] != '\n')
            bl_output_byte (out, '\n');
    }
    if (status == BNL_OK && in->error) {
        builtin_error ("%s: %s", name, strerror (in->error));
        status = BNL_FILE_ERROR;
    }
    return status;
}

static int
bnl_open_fd (const char *name)
{
    return !strcmp (name, "-") ? STDIN_FILENO : open (name, O_RDONLY);
}

static void
bnl_release (bnl_opts *o, const char **files)
{
    free (files);
    if (o->body_re_compiled) regfree (&o->body_re);
    if (o->header_re_compiled) regfree (&o->header_re);
    if (o->footer_re_compiled) regfree (&o->footer_re);
}

static const struct { const char *name; int opt; int arg; } bnl_long[] = {
    { "body-numbering",       'b', 1 },
    { "section-delimiter",    'd', 1 },
    { "footer-numbering",     'f', 1 },
    { "header-numbering",     'h', 1 },
    { "line-increment",       'i', 1 },
    { "join-blank-lines",     'l', 1 },
    { "number-format",        'n', 1 },
    { "no-renumber",          'p', 0 },
    { "number-separator",     's', 1 },
    { "starting-line-number", 'v', 1 },
    { "number-width",         'w', 1 },
    { "help",                 'H', 0 },
    { "version",              'V', 0 },
    { NULL,                   0,   0 }
};

int
nl_builtin (WORD_LIST *list)
{
    bnl_opts o;
    bnl_state st;
    bl_output out;
    bnl_input in;
    char *line = NULL;
    size_t cap = 0;
    const char **files = NULL;
    size_t nwords = 0, nfiles = 0, k;
    int end_of_options = 0, rc = EXECUTION_SUCCESS;
    WORD_LIST *l;

    memset (&o, 0, sizeof o);
    o.body = BNL_NONEMPTY;
    o.header = BNL_NONE;
    o.footer = BNL_NONE;
    o.incr = 1;
    o.start = 1;
    o.blank_join = 1;
    o.width = 6;
    o.fmt = BNL_RN;
    o.sep = "\t";
    o.sep_len = 1;
    o.delim = "\\:";
    o.delim_len = 2;

    for (l = list; l; l = l->next)
        nwords++;
    if (nwords) {
        files = malloc (nwords * sizeof *files);
        if (!files) {
            builtin_error ("%s", strerror (ENOMEM));
            return EXECUTION_FAILURE;
        }
    }

    /* nl(1) parses with getopt_long, which permutes: an option may follow an
       operand, long names may be abbreviated when unambiguous, and "--" ends
       the options. */
    for (l = list; l; l = l->next) {
        const char *w = l->word->word;

        if (end_of_options || w[0] != '-' || w[1] == '\0') {
            files[nfiles++] = w;
            continue;
        }
        if (w[1] == '-') {
            const char *name = w + 2, *eq, *val;
            size_t len;
            int match = -1, matches = 0, i;

            if (*name == '\0') { end_of_options = 1; continue; }
            eq = strchr (name, '=');
            len = eq ? (size_t) (eq - name) : strlen (name);
            for (i = 0; len && bnl_long[i].name; i++) {
                if (strncmp (bnl_long[i].name, name, len) != 0)
                    continue;
                if (strlen (bnl_long[i].name) == len) { match = i; matches = 1; break; }
                match = i;
                matches++;
            }
            if (matches == 0) {
                builtin_error ("unrecognized option '%s'", w);
                goto usage;
            }
            if (matches > 1) {
                builtin_error ("option '%s' is ambiguous", w);
                goto usage;
            }
            if (bnl_long[match].opt == 'H' || bnl_long[match].opt == 'V') {
                if (bnl_long[match].opt == 'H')
                    bnl_print_help ();
                else
                    puts ("bashnl 1.0 (bash-loadable)");
                bnl_release (&o, files);
                return EXECUTION_SUCCESS;
            }
            if (!bnl_long[match].arg) {
                if (eq) {
                    builtin_error ("option '--%s' doesn't allow an argument", bnl_long[match].name);
                    goto usage;
                }
                o.no_reset = 1;         /* the only argument-free option */
                continue;
            }
            if (eq)
                val = eq + 1;
            else if (l->next) { l = l->next; val = l->word->word; }
            else {
                builtin_error ("option '--%s' requires an argument", bnl_long[match].name);
                goto usage;
            }
            if (bnl_apply (&o, bnl_long[match].opt, val) < 0)
                goto usage;
            continue;
        }
        for (const char *p = w + 1; *p; p++) {
            const char *val;
            if (*p == 'p') { o.no_reset = 1; continue; }
            if (!strchr ("bdfhilnsvw", *p)) {
                builtin_error ("invalid option -- '%c'", *p);
                goto usage;
            }
            if (p[1])
                val = p + 1;
            else if (l->next) { l = l->next; val = l->word->word; }
            else {
                builtin_error ("option requires an argument -- '%c'", *p);
                goto usage;
            }
            if (bnl_apply (&o, *p, val) < 0)
                goto usage;
            break;                      /* the rest of the word was the value */
        }
    }

    st.counter = o.start;
    st.blanks = 0;
    st.section = BNL_BODY;
    st.overflow = 0;

    /* One read buffer and one line buffer for the whole invocation, freed
       with it; nothing survives the call. */
    in.data = malloc (BNL_INPUT_SIZE);
    if (!in.data) {
        builtin_error ("%s", strerror (ENOMEM));
        bnl_release (&o, files);
        return EXECUTION_FAILURE;
    }

    bl_output_init (&out, stdout);
    if (nfiles == 0) {
        bnl_input_open (&in, STDIN_FILENO);
        if (bnl_process (&in, "-", &line, &cap, &out, &o, &st) != BNL_OK)
            rc = EXECUTION_FAILURE;
    } else {
        for (k = 0; k < nfiles; k++) {
            int status, fd = bnl_open_fd (files[k]);
            if (fd < 0) {
                builtin_error ("%s: %s", files[k], strerror (errno));
                rc = EXECUTION_FAILURE;
                continue;
            }
            bnl_input_open (&in, fd);
            status = bnl_process (&in, files[k], &line, &cap, &out, &o, &st);
            /* A named file can receive fd 0 when the shell's stdin is
               closed. Ownership follows the operand, not the fd number. */
            if (strcmp (files[k], "-") != 0)
                close (fd);
            if (status != BNL_OK)
                rc = EXECUTION_FAILURE;
            if (status == BNL_FATAL || out.error)
                break;
        }
    }
    free (in.data);
    free (line);
    bl_output_flush (&out);
    if (out.error) {
        builtin_error ("write error: %s", strerror (out.error));
        rc = EXECUTION_FAILURE;
    }
    bnl_release (&o, files);
    return rc;

usage:
    builtin_usage ();
    bnl_release (&o, files);
    return EXECUTION_FAILURE;
}

char *nl_doc[] = {
    "Number lines (POSIX nl).",
    "",
    "    bashnl [-ba|-bt|-bn|-bpBRE] [-h STYLE] [-f STYLE]",
    "           [-d CC] [-i N] [-l N] [-s SEP] [-v N] [-w W]",
    "           [-n ln|rn|rz] [-p] [--help|--version] [FILE...]",
    "",
    "    -b STYLE  body numbering: a (all), t (non-empty, default),",
    "              n (none), or pBRE (lines matching BRE)",
    "    -h STYLE  header numbering style, as -b (default n)",
    "    -f STYLE  footer numbering style, as -b (default n)",
    "    -d CC     section delimiter string (default \\:); one character is",
    "              completed with ':', an empty string disables sections",
    "    -i N      increment between numbered lines (default 1)",
    "    -l N      group N empty lines as one numbered blank line (default 1)",
    "    -s SEP    separator after the number (default tab)",
    "    -v N      starting line number (default 1)",
    "    -w W      column width (default 6)",
    "    -n FMT    ln (left), rn (right, default), rz (zero-pad)",
    "    -p        do not reset numbering at logical page delimiters",
    "    --help    display this help and exit",
    "    --version display version information and exit",
    "    Long aliases, abbreviated when unambiguous: --body-numbering,",
    "                  --header-numbering, --footer-numbering,",
    "                  --section-delimiter, --line-increment, --join-blank-lines,",
    "                  --number-separator, --number-width, --number-format,",
    "                  --starting-line-number, --no-renumber",
    "",
    "A logical page delimiter line (\\:\\:\\: header, \\:\\: body, \\: footer)",
    "switches section and restarts numbering unless -p is given. The line",
    "number, the blank-line run and the section carry across FILE operands",
    "of one invocation and start afresh on the next.",
    "",
    "Reads stdin when no FILE given (or use `-` in the list).",
    (char *)NULL
};

struct builtin bashnl_struct = {
    "bashnl",
    nl_builtin,
    BUILTIN_ENABLED,
    nl_doc,
    "bashnl [-ba|-bt|-bn|-bpBRE] [-h STYLE] [-f STYLE] [-d CC] [-i N] [-l N] [-s SEP] [-v N] [-w W] [-n FORMAT] [-p] [--help|--version] [FILE...]",
    0
};

/* The unprefixed registration matches the compiled-in command name, so the
   same source also loads with `enable -f`. */
struct builtin nl_struct = {
    "nl",
    nl_builtin,
    BUILTIN_ENABLED,
    nl_doc,
    "bashnl [-ba|-bt|-bn|-bpBRE] [-h STYLE] [-f STYLE] [-d CC] [-i N] [-l N] [-s SEP] [-v N] [-w W] [-n FORMAT] [-p] [--help|--version] [FILE...]",
    0
};
