/* bashpaste.c — POSIX paste(1) as a bash builtin.
 *
 * Phase A.3 of bash-os shell-ergonomics. Replaces rootfs/bash/paste.sh.
 *
 *   bashpaste [-d DELIM] FILE [FILE...]   # parallel-merge columns
 *   bashpaste -s [-d DELIM] FILE [FILE...] # serial: each file → one line
 *
 * DELIM cycles: `-d ',|'` uses ',' between cols 0/1, '|' between 1/2,
 * back to ',' between 2/3, etc. Default delimiter is tab. POSIX
 * backslash escapes in DELIM (`\n`, `\t`, `\\`).
 *
 * Line content is emitted through a length-tracked block buffer so embedded
 * NUL bytes (binary line content) round-trip unchanged. The trailing
 * newline from getline is stripped by length, not by writing '\0'.
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
#include <limits.h>
#include <sys/stat.h>

#include "loadables.h"
#include "bl-output.h"

typedef struct {
    char *bytes;
    size_t *lens;
    size_t count;
} bp_delims;

typedef struct {
    char *data;
    size_t pos, len;
} bp_block;

/* A record wholly inside a regular-file block can be consumed in place.
   Only records crossing block boundaries need a separate line allocation.
   Pipes and shared stdin keep getdelim's existing incremental behavior. */
static ssize_t
bp_read_record (FILE *f, bp_block *block, char **line, size_t *cap,
                unsigned char delim, char **record)
{
    if (!block->data) {
        ssize_t n = getdelim (line, cap, delim, f);
        *record = *line;
        return n;
    }
    size_t copied = 0;
    for (;;) {
        if (block->pos == block->len) {
            if (feof (f) || ferror (f)) {
                *record = *line;
                return copied ? (ssize_t) copied : -1;
            }
            block->len = fread (block->data, 1, 65536, f);
            block->pos = 0;
            if (!block->len) {
                *record = *line;
                return copied ? (ssize_t) copied : -1;
            }
        }
        char *start = block->data + block->pos;
        char *end = memchr (start, delim, block->len - block->pos);
        size_t n = end ? (size_t) (end - start) + 1 : block->len - block->pos;
        if (!copied && end) {
            *record = start;
            block->pos += n;
            return (ssize_t) n;
        }
        if (n > (size_t) SSIZE_MAX - copied) {
            errno = EOVERFLOW;
            return -1;
        }
        size_t need = copied + n;
        if (need > *cap) {
            size_t nc = *cap > (size_t) SSIZE_MAX / 2 ? (size_t) SSIZE_MAX : *cap * 2;
            if (nc < need) nc = need;
            char *next = realloc (*line, nc);
            if (!next) return -1;
            *line = next;
            *cap = nc;
        }
        memcpy (*line + copied, start, n);
        copied += n;
        block->pos += n;
        if (end) {
            *record = *line;
            return (ssize_t) copied;
        }
    }
}

/* Expand POSIX/GNU backslash escapes in delim string.  The \0 escape is an
   empty delimiter, so lengths are tracked separately from the byte buffer.
   Returns 0 on success, -1 on allocation failure, and 1 if the delimiter
   ends with an unescaped backslash (a hard error in GNU paste; the caller
   reports it).  out->{bytes,lens,count} are always populated so the caller
   can free them regardless of return code. */
static int
bp_expand_delim (const char *s, bp_delims *out)
{
    size_t cap = strlen (s) + 1;
    char *bytes = malloc (cap ? cap : 1);
    size_t *lens = calloc (cap ? cap : 1, sizeof *lens);
    if (!bytes || !lens) { free (bytes); free (lens); return -1; }

    size_t op = 0;
    size_t idx = 0;
    int backslash_at_end = 0;
    while (*s) {
        if (*s == '\\') {
            /* GNU paste rejects a trailing unescaped backslash rather than
               treating it as a literal delimiter byte. Flag it and stop. */
            if (s[1] == '\0') { backslash_at_end = 1; break; }
            switch (s[1]) {
                case 'b':  bytes[op++] = '\b'; lens[idx++] = 1; s += 2; break;
                case 'f':  bytes[op++] = '\f'; lens[idx++] = 1; s += 2; break;
                case 'n':  bytes[op++] = '\n'; lens[idx++] = 1; s += 2; break;
                case 't':  bytes[op++] = '\t'; lens[idx++] = 1; s += 2; break;
                case 'r':  bytes[op++] = '\r'; lens[idx++] = 1; s += 2; break;
                case 'v':  bytes[op++] = '\v'; lens[idx++] = 1; s += 2; break;
                case '\\': bytes[op++] = '\\'; lens[idx++] = 1; s += 2; break;
                case '0':  lens[idx++] = 0; s += 2; break;
                default:   bytes[op++] = s[1]; lens[idx++] = 1; s += 2; break;
            }
        } else {
            bytes[op++] = *s++;
            lens[idx++] = 1;
        }
    }
    if (idx == 0)
        lens[idx++] = 0;
    out->bytes = bytes;
    out->lens = lens;
    out->count = idx;
    return backslash_at_end ? 1 : 0;
}

static void
bp_free_delims (bp_delims *d)
{
    free (d->bytes);
    free (d->lens);
}

static void
bp_write_delim (bl_output *out, const bp_delims *d, size_t *pos, size_t *off)
{
    size_t len = d->lens[*pos];
    if (len)
        bl_output_write (out, d->bytes + *off, len);
    *off += len;
    if (++*pos == d->count) {
        *pos = 0;
        *off = 0;
    }
}

static FILE *
bp_open_input (const char *name, int *is_stdin)
{
    if (!strcmp (name, "-")) {
        *is_stdin = 1;
        clearerr (stdin);
        return stdin;
    }
    *is_stdin = 0;
    return fopen (name, "r");
}

static int
bp_close_input (FILE *f, int is_stdin)
{
    if (!f) return 0;
    if (is_stdin) {
        clearerr (f);
        return 0;
    }
    return fclose (f);
}

int
paste_builtin (WORD_LIST *list)
{
    int sflag = 0;
    unsigned char line_delim = '\n';
    const char *delim_arg = "\t";
    /* Parse flags. */
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version")) {
            puts ("bashpaste 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--serial")) { sflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--zero-terminated")) { line_delim = '\0'; list = list->next; continue; }
        if (!strcmp (w, "--delimiters")) {
            if (!list->next) {
                builtin_error ("--delimiters needs DELIM");
                builtin_usage ();
                return EXECUTION_FAILURE;
            }
            list = list->next;
            delim_arg = list->word->word;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--delimiters=", 13)) { delim_arg = w + 13; list = list->next; continue; }
        if (w[0] == '-' && w[1] && w[1] != '-') {
            const char *arg = NULL;
            for (size_t pos = 1; w[pos]; pos++) {
                if (w[pos] == 's') {
                    sflag = 1;
                } else if (w[pos] == 'z') {
                    line_delim = '\0';
                } else if (w[pos] == 'd') {
                    if (w[pos + 1])
                        arg = w + pos + 1;
                    else {
                        if (!list->next) {
                            builtin_error ("-d needs DELIM");
                            builtin_usage ();
                            return EXECUTION_FAILURE;
                        }
                        list = list->next;
                        arg = list->word->word;
                    }
                    delim_arg = arg;
                    break;
                } else {
                    builtin_error ("unknown flag: %s", w);
                    builtin_usage ();
                    return EXECUTION_FAILURE;
                }
            }
            list = list->next;
            continue;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EXECUTION_FAILURE;
    }

    bp_delims delims = {0};
    int de = bp_expand_delim (delim_arg, &delims);
    if (de < 0) return EXECUTION_FAILURE;
    if (de > 0) {
        /* Match GNU paste's diagnostic and failure status. */
        builtin_error ("delimiter list ends with an unescaped backslash: %s", delim_arg);
        bp_free_delims (&delims);
        return EXECUTION_FAILURE;
    }

    /* No files = stdin. */
    int n_files = 0;
    for (WORD_LIST *p = list; p; p = p->next) n_files++;

    int rc = EXECUTION_SUCCESS;
    bl_output output;
    bl_output_init (&output, stdout);
    /* Keep embedded NULs and batch records instead of flushing each line. */
    if (sflag) {
        /* Serial: one file per output line, joined by cycling delim. */
        if (n_files == 0) {
            FILE *f = stdin;
            char *line = NULL; size_t cap = 0; ssize_t rd;
            int first = 1;
            size_t dpos = 0, doff = 0;
            while (!output.error && (rd = getdelim (&line, &cap, line_delim, f)) != -1) {
                size_t len = (size_t) rd;
                if (len > 0 && (unsigned char) line[len - 1] == line_delim) len--;
                if (!first) bp_write_delim (&output, &delims, &dpos, &doff);
                bl_output_write (&output, line, len);
                first = 0;
            }
            if (ferror (f)) { builtin_error ("read error: %s", strerror (errno)); rc = EXECUTION_FAILURE; }
            bl_output_byte (&output, line_delim);
            free (line);
        } else {
            for (WORD_LIST *p = list; p; p = p->next) {
                int is_stdin = 0;
                FILE *f = bp_open_input (p->word->word, &is_stdin);
                if (!f) {
                    builtin_error ("%s: %s", p->word->word, strerror (errno));
                    rc = EXECUTION_FAILURE;
                    continue;
                }
                char *line = NULL; size_t cap = 0; ssize_t rd;
                int first = 1;
                size_t dpos = 0, doff = 0;
                while (!output.error && (rd = getdelim (&line, &cap, line_delim, f)) != -1) {
                    size_t len = (size_t) rd;
                    if (len > 0 && (unsigned char) line[len - 1] == line_delim) len--;
                    if (!first) bp_write_delim (&output, &delims, &dpos, &doff);
                    bl_output_write (&output, line, len);
                    first = 0;
                }
                if (ferror (f)) { builtin_error ("read error: %s", strerror (errno)); rc = EXECUTION_FAILURE; }
                bl_output_byte (&output, line_delim);
                free (line);
                bp_close_input (f, is_stdin);
            }
        }
    } else {
        /* Parallel: one line from each file, joined. */
        if (n_files == 0)
            n_files = 1;
        FILE **files = calloc ((size_t) n_files, sizeof *files);
        int *is_stdin = calloc ((size_t) n_files, sizeof *is_stdin);
        if (!files || !is_stdin) { free (files); free (is_stdin); bp_free_delims (&delims); return EXECUTION_FAILURE; }
        char **lines = NULL;
        char **records = NULL;
        size_t *caps = NULL;
        size_t *lens = NULL;
        bp_block *blocks = calloc ((size_t) n_files, sizeof *blocks);
        if (!blocks) { free (files); free (is_stdin); bp_free_delims (&delims); return EXECUTION_FAILURE; }
        int i = 0;
        for (WORD_LIST *p = list; i < n_files; i++) {
            const char *name = p ? p->word->word : "-";
            files[i] = bp_open_input (name, &is_stdin[i]);
            if (!files[i]) {
                builtin_error ("%s: %s", name, strerror (errno));
                rc = EXECUTION_FAILURE;
            } else if (!is_stdin[i]) {
                struct stat st;
                if (fstat (fileno (files[i]), &st) == 0 && S_ISREG (st.st_mode)) {
                    blocks[i].data = malloc (65536);
                    if (!blocks[i].data) rc = EXECUTION_FAILURE;
                }
            }
            if (p) p = p->next;
        }
        if (rc != EXECUTION_SUCCESS)
            goto parallel_done;
        lines = calloc ((size_t) n_files, sizeof *lines);
        records = calloc ((size_t) n_files, sizeof *records);
        caps = calloc ((size_t) n_files, sizeof *caps);
        lens = calloc ((size_t) n_files, sizeof *lens);
        if (!lines || !records || !caps || !lens) {
            rc = EXECUTION_FAILURE;
            goto parallel_done;
        }
        while (!output.error) {
            int any = 0;
            for (i = 0; i < n_files; i++) {
                if (!files[i]) { lens[i] = 0; continue; }
                errno = 0;
                ssize_t rd = bp_read_record (files[i], &blocks[i], &lines[i], &caps[i],
                                            line_delim, &records[i]);
                if (rd == -1) {
                    if (ferror (files[i]) || errno) {
                        builtin_error ("read error: %s", strerror (errno)); rc = EXECUTION_FAILURE;
                    }
                    bp_close_input (files[i], is_stdin[i]); files[i] = NULL;
                    lens[i] = 0;
                } else {
                    size_t len = (size_t) rd;
                    if (len > 0 && (unsigned char) records[i][len - 1] == line_delim) len--;
                    lens[i] = len;
                    any = 1;
                }
            }
            if (!any) break;
            size_t dpos = 0, doff = 0;
            for (i = 0; i < n_files; i++) {
                if (i > 0) bp_write_delim (&output, &delims, &dpos, &doff);
                if (records[i] && lens[i]) bl_output_write (&output, records[i], lens[i]);
            }
            bl_output_byte (&output, line_delim);
        }
parallel_done:
        for (i = 0; i < n_files; i++) {
            if (lines) free (lines[i]);
            free (blocks[i].data);
            if (files[i]) bp_close_input (files[i], is_stdin[i]);
        }
        free (blocks); free (records); free (lines); free (caps); free (lens); free (files); free (is_stdin);
    }
    bl_output_flush (&output);
    if (output.error) { builtin_error ("write error: %s", strerror (output.error)); rc = EXECUTION_FAILURE; }
    bp_free_delims (&delims);
    return rc;
}

char *paste_doc[] = {
    "Merge lines from FILEs side-by-side (parallel) or end-to-end (serial).",
    "",
    "    bashpaste [-z] [-d DELIM] FILE [FILE...]    # parallel: cols joined by DELIM",
    "    bashpaste -s [-z] [-d DELIM] FILE [FILE...] # serial: one file → one line",
    "    bashpaste --help | --version",
    "",
    "Default DELIM is tab. DELIM may cycle: -d ',|' uses ',' then '|' between",
    "successive columns. Backslash escapes \\0 \\b \\f \\n \\r \\t \\v \\\\ recognized.",
    "-z, --zero-terminated uses NUL instead of newline as the record delimiter.",
    (char *)NULL
};

struct builtin bashpaste_struct = {
    "bashpaste",
    paste_builtin,
    BUILTIN_ENABLED,
    paste_doc,
    "bashpaste [-s] [-z] [-d DELIM] [FILE...]",
    0
};

/* The unprefixed registration matches the compiled-in command name. */
struct builtin paste_struct = {
    "paste",
    paste_builtin,
    BUILTIN_ENABLED,
    paste_doc,
    "paste [-s] [-z] [-d DELIM] [FILE...]",
    0
};
