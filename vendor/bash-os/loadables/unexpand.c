/* SPDX-License-Identifier: MIT */
/* unexpand.c — POSIX unexpand(1) as a bash builtin.
 *
 * Closes the POSIX gap noted in POSIX-CONFORMANCE-RESEARCH.md §4.1.
 * Replaces runs of spaces with tabs. By default only LEADING runs are
 * converted (POSIX behavior); -a also converts blanks after non-blanks.
 *
 *   unexpand [-a|--all] [-t TABLIST|--tabs=TABLIST] [FILE...]
 *
 *   -a, --all           convert all whitespace runs, not just leading
 *   --first-only        convert only leading whitespace runs
 *   -t, --tabs TABLIST  tab stops; same syntax as bashexpand. Default: 8.
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
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "loadables.h"
#include "unwind_prot.h"
#include "bl-output.h"

#define BU_MAX_STOPS 64

typedef struct {
    int stops[BU_MAX_STOPS];
    int n_stops;
    int every;
    int extend_size, increment_size;
    int all, first_only;
} bu_opts;

/* Keep explicit stops until option parsing finishes: repeated -t options
   append to the list. A single stop means a repeating tab width. */
static int
bu_parse_tablist (const char *s, bu_opts *o)
{
    while (*s) {
        while (*s == ',' || *s == ' ' || *s == '\t') s++;
        if (!*s) break;
        int extension = 0;
        if (*s == '/' || *s == '+') extension = *s++;
        char *end;
        errno = 0;
        long n = strtol (s, &end, 10);
        if (!isdigit ((unsigned char) *s) || errno == ERANGE || n > INT_MAX ||
            n < 0 || (n == 0 && !extension) || end == s ||
            (*end && *end != ',' && *end != ' ' && *end != '\t')) {
            builtin_error ("invalid tab size: %s", s);
            return -1;
        }
        if (o->extend_size || o->increment_size) {
            builtin_error ("tab extension must be last");
            return -1;
        }
        if (extension) {
            if (extension == '/') o->extend_size = (int) n;
            else o->increment_size = (int) n;
            s = end;
            while (*s == ',' || *s == ' ' || *s == '\t') s++;
            if (*s) {
                builtin_error ("tab extension must be last");
                return -1;
            }
            break;
        }
        if ((o->n_stops && n <= o->stops[o->n_stops - 1]) ||
            o->n_stops == BU_MAX_STOPS) {
            builtin_error ("tab stops must increase (maximum %d stops)", BU_MAX_STOPS);
            return -1;
        }
        o->stops[o->n_stops++] = (int) n;
        s = end;
    }
    return 0;
}

/* First stop strictly past COL, also after a backspace. /N aligns to the
   origin; +N aligns to the last explicit stop. Finite lists stop conversion. */
static uintmax_t
bu_next_stop (uintmax_t col, const bu_opts *o, int *last_tab)
{
    *last_tab = 0;
    if (o->every > 0) {
        uintmax_t offset = (o->every & (o->every - 1)) == 0
                            ? col & (o->every - 1) : col % o->every;
        return col + (o->every - offset);
    }
    for (int i = 0; i < o->n_stops; i++)
        if ((uintmax_t) o->stops[i] > col)
            return o->stops[i];
    if (o->extend_size)
        return col + o->extend_size - col % o->extend_size;
    if (o->increment_size) {
        int base = o->n_stops ? o->stops[o->n_stops - 1] : 0;
        return col + o->increment_size - (col - base) % o->increment_size;
    }
    *last_tab = 1;
    return col + 1;
}

typedef struct {
    WORD_LIST *files;
    FILE *stream;
    int implicit_stdin, status, regular;
    const char *name;
} bu_input;

static void
bu_close_input (void *arg)
{
    bu_input *input = arg;
    if (input->stream) fclose (input->stream);
    input->stream = NULL;
}

/* Treat the operands as one stream, carrying pending blanks and column state
   across empty, missing and unterminated files. Give stdin a private stdio
   wrapper: a failed write can leave read-ahead bytes, which must not remain
   attached to the shell's FILE when fd 0 is redirected on the next call. */
static int
bu_open_next (bu_input *input)
{
    bu_close_input (input);
    while (input->files || input->implicit_stdin) {
        const char *name = input->files ? input->files->word->word : "-";
        if (input->files) input->files = input->files->next;
        input->implicit_stdin = 0;
        if (!strcmp (name, "-")) {
            /* Keep standard descriptors closed if the caller closed them,
               and prevent this private input from leaking through exec. */
            int fd = fcntl (STDIN_FILENO, F_DUPFD_CLOEXEC, 3);
            if (fd >= 0) {
                input->stream = fdopen (fd, "r");
                if (!input->stream) {
                    int error = errno;
                    close (fd);
                    errno = error;
                }
            }
        } else input->stream = fopen (name, "r");
        input->name = name;
        if (!input->stream) {
            builtin_error ("%s: %s", name, strerror (errno));
            input->status = EXECUTION_FAILURE;
            continue;
        }
        clearerr (input->stream);
        struct stat st;
        input->regular = fstat (fileno (input->stream), &st) == 0 && S_ISREG (st.st_mode);
        return 1;
    }
    return 0;
}

static void
bu_output_byte (bl_output *out, unsigned char c)
{
    if (!out) {
        putc_unlocked (c, stdout);
        return;
    }
    if (out->error) return;
    out->data[out->used++] = c;
    if (out->used == sizeof out->data)
        bl_output_flush (out);
}

/* Convert one input stream, faithfully porting GNU unexpand's per-line state
   machine (coreutils unexpand.c fold_file). Blank runs are accumulated in
   `pending`; a run is replaced by a tab only when a blank lands exactly on a
   tab stop with a preceding blank, and a lone blank sitting on a stop is kept
   as a space (`one_blank_before`). `o->all` is GNU's convert_entire_line:
   when false, conversion stops after the first non-blank on each line. */
static void
bu_free_pending (void *arg)
{
    /* The pointer can change when the pending buffer grows. */
    free (*(char **) arg);
}

static int
bu_process (WORD_LIST *files, const bu_opts *o)
{
    char  *pending = NULL;       /* buffer of pending blank bytes */
    size_t pending_cap = 0;
    size_t pending_n = 0;
    int convert = 1;
    uintmax_t column = 0;
    int one_blank_before = 0;
    int prev_blank = 1;          /* a line is treated as preceded by a blank */
    int out_failed = 0;
    uintmax_t next_tab = 0;
    int last_tab = 0;
    int c;
    unsigned char input[65536];
    size_t pos = 0, have = 0;
    bl_output output, *out = NULL;
    bu_input in = { .files = files, .implicit_stdin = files == NULL };
    int regular = 0;
    int terminal = isatty (STDOUT_FILENO);

    begin_unwind_frame ("unexpand pending");
    add_unwind_protect (bu_free_pending, &pending);
    add_unwind_protect (bu_close_input, &in);
    bu_open_next (&in);
    if (in.stream && in.regular && !terminal) {
        bl_output_init (&output, stdout);
        out = &output;
    }
    for (;;) {
        int suppress = 0;        /* set when the current char is consumed (g.len=0) */
        if (out && out->error) { out_failed = 1; break; }
        /* Full blocks are safe for regular files. Pipes/terminals keep byte
           reads, so output errors and terminal lines don't wait for EOF. */
        if (pos == have) {
            for (;;) {
                if (!in.stream) { c = EOF; break; }
                regular = out && in.regular;
                if (regular) {
                    have = fread (input, 1, sizeof input, in.stream);
                    pos = 0;
                    QUIT;
                    if (have) break;
                } else {
                    c = getc_unlocked (in.stream);
                    QUIT;
                    if (c != EOF) break;
                }
                if (ferror (in.stream)) {
                    builtin_error ("%s: read error: %s", in.name, strerror (errno ? errno : EIO));
                    in.status = EXECUTION_FAILURE;
                }
                /* Flush emitted bytes before opening another operand. Keep
                   pending blanks intact, but preserve stdio's early failure
                   detection for pipes and line delivery to terminals. */
                if (out) {
                    bl_output_flush (out);
                    if (out->error) out_failed = 1;
                } else if (fflush (stdout) == EOF) out_failed = 1;
                if (out_failed) break;
                if (!bu_open_next (&in)) { c = EOF; break; }
                if (in.regular && !terminal) {
                    if (!out) bl_output_init (&output, stdout);
                    out = &output;
                } else out = NULL;
            }
        }
        if (out_failed) break;
        if (regular && pos < have) {
            if (!pending_n) {
                /* Ordinary runs need no blank/backspace/newline transition.
                   After leading-only conversion stops, everything up to the
                   next newline can be copied unchanged. */
                static const unsigned char special[256] = {
                    [' '] = 1, ['\t'] = 1, ['\b'] = 1, ['\n'] = 1
                };
                size_t end = pos;
                if (!convert) {
                    unsigned char *nl = memchr (input + pos, '\n', have - pos);
                    end = nl ? (size_t) (nl - input) : have;
                } else {
                    while (end < have && !special[input[end]]) end++;
                }
                if (end > pos) {
                    bl_output_write (out, input + pos, end - pos);
                    if (convert) {
                        column += end - pos;
                        prev_blank = 0;
                        convert = o->all;
                    }
                    pos = end;
                    continue;
                }
            }
            c = input[pos++];
        }

        /* EOF is processed too: like GNU, it triggers the final pending flush
           (with the pending>1 conversion) before the loop ends. */
        if (convert) {
            int blank = (c != EOF && (c == ' ' || c == '\t'));
            if (blank) {
                if (column >= next_tab) {
                    if (o->every > 0 && column == next_tab) {
                        next_tab = column + o->every;
                        last_tab = 0;
                    } else {
                        next_tab = bu_next_stop (column, o, &last_tab);
                    }
                }
                if (last_tab)
                    convert = 0;
                if (convert) {
                    if (c == '\t') {
                        column = next_tab;
                        if (pending_n) pending[0] = '\t';
                    } else { /* space (width 1) */
                        column += 1;
                        if (!(prev_blank && column == next_tab)) {
                            if (column == next_tab) one_blank_before = 1;
                            /* Inside a stop interval, consecutive spaces
                               only extend pending: batch them without crossing
                               the next stop or a regular-file input block. */
                            size_t count = 1;
                            if (regular && column < next_tab) {
                                size_t limit = have - pos;
                                uintmax_t padding = next_tab - column - 1;
                                if (padding < limit) limit = (size_t) padding;
                                while (count <= limit && input[pos + count - 1] == ' ')
                                    count++;
                            }
                            if (count > SIZE_MAX - pending_n) {
                                run_unwind_frame ("unexpand pending");
                                builtin_error ("too many pending blanks");
                                return EXECUTION_FAILURE;
                            }
                            size_t needed = pending_n + count;
                            if (needed > pending_cap) {
                                size_t nc = pending_cap ? pending_cap : 64;
                                while (nc < needed)
                                    nc = nc > SIZE_MAX / 2 ? needed : nc * 2;
                                char *nb = realloc (pending, nc);
                                if (!nb) { run_unwind_frame ("unexpand pending"); builtin_error ("realloc"); return EXECUTION_FAILURE; }
                                pending = nb;
                                pending_cap = nc;
                            }
                            if (count == 1) pending[pending_n] = ' ';
                            else memset (pending + pending_n, ' ', count);
                            pending_n = needed;
                            pos += count - 1;
                            column += count - 1;
                            prev_blank = 1;
                            continue;            /* hold the blank; emit nothing yet */
                        }
                        /* Replace the pending blanks by a tab (or two). */
                        bu_output_byte (out, '\t');
                        if (pending_cap == 0) {
                            pending = malloc (pending_cap = 64);
                            if (!pending) { run_unwind_frame ("unexpand pending"); builtin_error ("malloc"); return EXECUTION_FAILURE; }
                        }
                        pending[0] = '\t';
                        suppress = 1;
                    }
                    /* Discard pending, unless a single blank sat on a stop. */
                    pending_n = one_blank_before ? 1 : 0;
                }
            } else if (c == '\b') {
                if (column > 0) column--;
                next_tab = 0;
            } else if (c != '\n' && c != EOF) {
                column += 1;
            }

            if (pending_n) {
                if (pending_n > 1 && one_blank_before) pending[0] = '\t';
                if (out) bl_output_write (out, pending, pending_n);
                else fwrite (pending, 1, pending_n, stdout);
                pending_n = 0;
                one_blank_before = 0;
            }
            prev_blank = blank;
            convert = convert && (o->all || blank);
        }

        if (c == EOF)
            break;

        if (c == '\n') {
            bu_output_byte (out, '\n');
            convert = 1; column = 0;
            one_blank_before = 0; prev_blank = 1; pending_n = 0;
            next_tab = 0; last_tab = 0;
        } else if (!suppress) {
            bu_output_byte (out, (unsigned char) c);
        }
        if ((out && out->error) || ferror_unlocked (stdout)) {
            out_failed = 1;
            break;
        }
    }

    run_unwind_frame ("unexpand pending");
    if (out) bl_output_flush (out);
    if (out_failed || (out && out->error) || ferror (stdout) || fflush (stdout) == EOF) {
        int error = out && out->error ? out->error : errno;
        builtin_error ("write error: %s", strerror (error ? error : EIO));
        return EXECUTION_FAILURE;
    }
    return in.status;
}

static void
bu_help (void)
{
    puts ("unexpand [OPTION] [FILE...]");
    puts ("Convert spaces to tabs. Reads stdin if no FILE or FILE is -.");
    puts ("");
    puts ("  -a, --all          convert all blanks, not just initial blanks");
    puts ("      --first-only   convert only leading blanks (overrides -a)");
    puts ("  -t, --tabs=LIST    tab stops (N, list, trailing /N or +N)");
    puts ("  -h, --help         show this help");
    puts ("  -V, --version      show version");
}

int
unexpand_builtin (WORD_LIST *list)
{
    bu_opts o = { .every = 8 };
    unsigned int legacy_size = 0;
    int legacy_seen = 0;
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "-h") || !strcmp (w, "--help")) {
            bu_help ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-V") || !strcmp (w, "--version")) {
            puts ("unexpand 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-a") || !strcmp (w, "--all")) { o.all = 1; list = list->next; continue; }
        if (!strcmp (w, "--first-only")) { o.first_only = 1; list = list->next; continue; }
        if (!strcmp (w, "-t") || !strcmp (w, "--tabs")) {
            if (!list->next) {
                builtin_error ("%s needs TABLIST", w);
                builtin_usage ();
                return EXECUTION_FAILURE;
            }
            list = list->next;
            if (bu_parse_tablist (list->word->word, &o) < 0) {
                builtin_usage ();
                return EXECUTION_FAILURE;
            }
            /* POSIX: -t implies -a. */
            o.all = 1;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--tabs=", 7)) {
            if (bu_parse_tablist (w + 7, &o) < 0) {
                builtin_usage ();
                return EXECUTION_FAILURE;
            }
            o.all = 1;
            list = list->next;
            continue;
        }
        if (w[1] != '-') {
            const char *arg = w + 1;
            while (*arg) {
                if (*arg == 'a') { o.all = 1; arg++; continue; }
                /* GNU's obsolete -DIGITS syntax accumulates digits across
                   options; a comma ends a stop, while the last number is
                   appended after all modern -t options have been parsed. */
                if (isdigit ((unsigned char) *arg)) {
                    unsigned int digit = *arg++ - '0';
                    if (legacy_size > (INT_MAX - digit) / 10) {
                        builtin_error ("tab size too large");
                        return EXECUTION_FAILURE;
                    }
                    legacy_size = legacy_size * 10 + digit;
                    legacy_seen = 1;
                    continue;
                }
                if (*arg == ',') {
                    if (legacy_seen) {
                        char number[32];
                        snprintf (number, sizeof number, "%u", legacy_size);
                        if (bu_parse_tablist (number, &o) < 0) return EXECUTION_FAILURE;
                        legacy_size = 0;
                        legacy_seen = 0;
                    }
                    arg++;
                    continue;
                }
                if (*arg == 't') {
                    arg++;
                    if (!*arg && list->next) { list = list->next; arg = list->word->word; }
                    else if (!*arg) { builtin_error ("-t needs TABLIST"); return EXECUTION_FAILURE; }
                    o.all = 1;
                    if (bu_parse_tablist (arg, &o) < 0) return EXECUTION_FAILURE;
                    break;
                }
                builtin_error ("unknown flag: -%c", *arg);
                return EXECUTION_FAILURE;
            }
            list = list->next;
            continue;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EXECUTION_FAILURE;
    }
    if (legacy_seen) {
        char number[32];
        snprintf (number, sizeof number, "%u", legacy_size);
        if (bu_parse_tablist (number, &o) < 0) return EXECUTION_FAILURE;
    }
    if (!o.n_stops) {
        o.every = o.extend_size ? o.extend_size : o.increment_size ? o.increment_size : 8;
        o.extend_size = o.increment_size = 0;
    } else if (o.n_stops == 1 && !o.extend_size && !o.increment_size) {
        o.every = o.stops[0];
        o.n_stops = 0;
    } else o.every = 0;
    if (o.first_only) o.all = 0;
    return bu_process (list, &o);
}

char *unexpand_doc[] = {
    "Convert spaces to tabs (POSIX unexpand).",
    "",
    "    unexpand [OPTION] [FILE...]",
    "",
    "    -a, --all          convert all blanks, not just leading blanks",
    "        --first-only   convert only leading blanks (overrides -a)",
    "    -t, --tabs=LIST    tab stops (N, list, trailing /N or +N). Default: 8.",
    "                       Specifying tabs implies --all per POSIX.",
    "    -h, --help         show help",
    "    -V, --version      show version",
    "",
    "Reads stdin when no FILE given or FILE is -. Output goes to stdout.",
    (char *)NULL
};

struct builtin unexpand_struct = {
    "unexpand",
    unexpand_builtin,
    BUILTIN_ENABLED,
    unexpand_doc,
    "unexpand [OPTION] [FILE...]",
    0
};
