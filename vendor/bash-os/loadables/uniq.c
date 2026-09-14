/* bashuniq.c — POSIX uniq(1) as a bash builtin.
 *
 * Phase A.3 of bash-os shell-ergonomics. Compares ADJACENT lines (input
 * must be sorted for global uniqueness). v1 flags:
 *   -c, --count        prefix each line with its count
 *   -d, --repeated     only print duplicate lines
 *   -u, --unique       only print non-duplicate (singleton) lines
 *   -i, --ignore-case  case-insensitive compare
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

#include "loadables.h"
#include "bl-output.h"

/* Keep embedded NULs and batch records without changing the shell's stdio. */
static void
bu_emit_line (bl_output *out, long count, const char *line, size_t len, int cflag)
{
    if (cflag) {
        char prefix[48];
        int n = snprintf (prefix, sizeof prefix, "%7ld ", count);
        bl_output_write (out, prefix, (size_t) n);
    }
    bl_output_write (out, line, len);
}

static int
bu_append_record (char **buf, size_t *len, size_t *cap, const char *line, size_t line_len)
{
    char *grown;
    size_t need;

    if (line_len > (size_t) -1 - *len)
        return -1;
    need = *len + line_len;
    if (need > *cap) {
        size_t ncap = *cap ? *cap : 128;
        while (ncap < need) {
            if (ncap > (size_t) -1 / 2) {
                ncap = need;
                break;
            }
            ncap *= 2;
        }
        grown = realloc (*buf, ncap);
        if (!grown)
            return -1;
        *buf = grown;
        *cap = ncap;
    }
    memcpy (*buf + *len, line, line_len);
    *len = need;
    return 0;
}

typedef struct {
    size_t skip_fields;
    size_t skip_chars;
    size_t check_chars;
    char delimiter;
} bu_opts;

typedef enum {
    BU_GROUP_NONE = 0,
    BU_GROUP_PREPEND,
    BU_GROUP_APPEND,
    BU_GROUP_SEPARATE,
    BU_GROUP_BOTH
} bu_group_mode;

typedef enum {
    BU_ALL_NONE = 0,
    BU_ALL_SEPARATE,
    BU_ALL_PREPEND
} bu_all_mode;

static int
bu_parse_group_mode (const char *s, bu_group_mode *mode)
{
    if (!s || !*s || !strcmp (s, "separate")) {
        *mode = BU_GROUP_SEPARATE;
        return 0;
    }
    if (!strcmp (s, "prepend")) {
        *mode = BU_GROUP_PREPEND;
        return 0;
    }
    if (!strcmp (s, "append")) {
        *mode = BU_GROUP_APPEND;
        return 0;
    }
    if (!strcmp (s, "both")) {
        *mode = BU_GROUP_BOTH;
        return 0;
    }
    return -1;
}

static ssize_t
bu_get_record (char **line, size_t *cap, FILE *f, char delimiter)
{
    ssize_t rd = getdelim (line, cap, delimiter, f);
    char *grown;

    if (rd < 0)
        return rd;
    if (rd > 0 && (*line)[rd - 1] == delimiter)
        return rd;

    if (*cap <= (size_t) rd + 1) {
        grown = realloc (*line, (size_t) rd + 2);
        if (!grown)
            return -1;
        *line = grown;
        *cap = (size_t) rd + 2;
    }
    (*line)[rd++] = delimiter;
    (*line)[rd] = '\0';
    return rd;
}

static int
bu_parse_size (const char *s, size_t *out)
{
    char *end = NULL;
    unsigned long v;

    if (!s || !*s || s[0] == '-' || s[0] == '+')
        return -1;
    errno = 0;
    v = strtoul (s, &end, 10);
    if (errno || *end)
        return -1;
    *out = (size_t) v;
    if ((unsigned long) *out != v)
        *out = (size_t) -1;
    return 0;
}

/* Parse a numeric option argument, emitting GNU uniq's exact diagnostic body
   on failure ("<arg>: invalid number of fields to skip", etc.). GNU_MSG is the
   trailing phrase. Returns 0 on success, EX_USAGE on failure. */
static int
bu_size_arg (const char *arg, const char *gnu_msg, size_t *out)
{
    if (bu_parse_size (arg, out) < 0) {
        builtin_error ("%s: %s", arg, gnu_msg);
        return EX_USAGE;
    }
    return 0;
}

#define BU_MSG_FIELDS  "invalid number of fields to skip"
#define BU_MSG_SKIP    "invalid number of bytes to skip"
#define BU_MSG_CHECK   "invalid number of bytes to compare"

/* Obsolete POSIX skip syntax: a "+N" operand means "skip N chars" (like
   -s N), accepted by GNU uniq for backward compatibility. True iff S is
   '+' followed by one or more decimal digits. */
static int
bu_is_plus_number (const char *s)
{
    if (s[0] != '+' || !s[1])
        return 0;
    for (const char *p = s + 1; *p; p++)
        if (*p < '0' || *p > '9')
            return 0;
    return 1;
}

static size_t
bu_compare_start (const char *line, size_t len, const bu_opts *o)
{
    size_t lim = len;
    size_t pos = 0;

    if (lim > 0 && line[lim - 1] == o->delimiter)
        lim--;
    for (size_t f = 0; f < o->skip_fields && pos < lim; f++) {
        while (pos < lim && (line[pos] == ' ' || line[pos] == '\t' || line[pos] == '\n'))
            pos++;
        while (pos < lim && line[pos] != ' ' && line[pos] != '\t' && line[pos] != '\n')
            pos++;
    }
    for (size_t c = 0; c < o->skip_chars && pos < lim; c++)
        pos++;
    return pos;
}

/* NUL-safe comparison: memcmp over the exact byte length (NUL bytes
   compare as themselves). strcmp/strcasecmp would stop at the first NUL
   and so could collapse two distinct lines that share a NUL-prefixed
   common head. */
static int
bu_eq (const char *a, size_t alen, const char *b, size_t blen, const bu_opts *o, int icase)
{
    size_t aoff = bu_compare_start (a, alen, o);
    size_t boff = bu_compare_start (b, blen, o);
    alen -= aoff;
    blen -= boff;
    if (alen > 0 && a[aoff + alen - 1] == o->delimiter)
        alen--;
    if (blen > 0 && b[boff + blen - 1] == o->delimiter)
        blen--;
    if (alen > o->check_chars)
        alen = o->check_chars;
    if (blen > o->check_chars)
        blen = o->check_chars;
    if (alen != blen) return 0;
    if (!icase) return memcmp (a + aoff, b + boff, alen) == 0;
    for (size_t i = 0; i < alen; i++) {
        if (tolower ((unsigned char) a[aoff + i]) != tolower ((unsigned char) b[boff + i])) return 0;
    }
    return 1;
}

int
uniq_builtin (WORD_LIST *list)
{
    int cflag = 0, dflag = 0, uflag = 0, iflag = 0, all_repeated = 0;
    int sfo_new = 0;   /* skip_fields last set by -f/--skip-fields (new form) */
    bu_group_mode grouping = BU_GROUP_NONE;
    bu_all_mode all_mode = BU_ALL_NONE;
    bu_opts o = {0, 0, (size_t) -1, '\n'};
    while (list && ((list->word->word[0] == '-' && list->word->word[1])
                    || bu_is_plus_number (list->word->word))) {
        const char *w = list->word->word;
        /* Obsolete POSIX "+N" → skip N chars, like -s N (GNU uniq compat). */
        if (bu_is_plus_number (w)) {
            if (bu_size_arg (w + 1, BU_MSG_SKIP, &o.skip_chars) != 0)
                return EX_USAGE;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version")) {
            puts ("bashuniq 1.0 (bash-os)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--count")) {
            cflag = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--repeated")) {
            dflag = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--all-repeated") || !strcmp (w, "--all-repeated=none")) {
            all_repeated = 1;
            all_mode = BU_ALL_NONE;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--all-repeated=", 15)) {
            const char *method = w + 15;
            if (!strcmp (method, "separate")) {
                all_repeated = 1;
                all_mode = BU_ALL_SEPARATE;
                list = list->next;
                continue;
            }
            if (!strcmp (method, "prepend")) {
                all_repeated = 1;
                all_mode = BU_ALL_PREPEND;
                list = list->next;
                continue;
            }
            builtin_error ("invalid argument '%s' for '--all-repeated'", method);
            builtin_usage ();
            return EX_USAGE;
        }
        if (!strcmp (w, "--group")) {
            grouping = BU_GROUP_SEPARATE;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--group=", 8)) {
            if (bu_parse_group_mode (w + 8, &grouping) < 0) {
                builtin_error ("invalid argument '%s' for '--group'", w + 8);
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--unique")) {
            uflag = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--ignore-case")) {
            iflag = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--zero-terminated")) {
            o.delimiter = '\0';
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--skip-fields")) {
            if (!list->next) { builtin_error ("option '%s' requires an argument", w); return EX_USAGE; }
            if (bu_size_arg (list->next->word->word, BU_MSG_FIELDS, &o.skip_fields) != 0) return EX_USAGE;
            sfo_new = 1;
            list = list->next->next;
            continue;
        }
        if (!strncmp (w, "--skip-fields=", 14)) {
            if (bu_size_arg (w + 14, BU_MSG_FIELDS, &o.skip_fields) != 0) return EX_USAGE;
            sfo_new = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--skip-chars")) {
            if (!list->next) { builtin_error ("option '%s' requires an argument", w); return EX_USAGE; }
            if (bu_size_arg (list->next->word->word, BU_MSG_SKIP, &o.skip_chars) != 0) return EX_USAGE;
            list = list->next->next;
            continue;
        }
        if (!strncmp (w, "--skip-chars=", 13)) {
            if (bu_size_arg (w + 13, BU_MSG_SKIP, &o.skip_chars) != 0) return EX_USAGE;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--check-chars")) {
            if (!list->next) { builtin_error ("option '%s' requires an argument", w); return EX_USAGE; }
            if (bu_size_arg (list->next->word->word, BU_MSG_CHECK, &o.check_chars) != 0) return EX_USAGE;
            list = list->next->next;
            continue;
        }
        if (!strncmp (w, "--check-chars=", 14)) {
            if (bu_size_arg (w + 14, BU_MSG_CHECK, &o.check_chars) != 0) return EX_USAGE;
            list = list->next;
            continue;
        }
        if (w[1] == '-') {
            builtin_error ("unknown option: %s", w);
            builtin_usage ();
            return EX_USAGE;
        }
        for (const char *p = w + 1; *p; p++) {
            /* Obsolete POSIX "-N" → skip N fields (like -f N). Digits
               accumulate (so -12 == skip 12); a digit after a new-form -f
               resets the count first, matching GNU uniq. */
            if (*p >= '0' && *p <= '9') {
                if (sfo_new) { o.skip_fields = 0; sfo_new = 0; }
                o.skip_fields = o.skip_fields * 10 + (size_t) (*p - '0');
                continue;
            }
            switch (*p) {
                case 'c': cflag = 1; break;
                case 'd': dflag = 1; break;
                case 'D': all_repeated = 1; all_mode = BU_ALL_NONE; break;
                case 'u': uflag = 1; break;
                case 'i': iflag = 1; break;
                case 'z': o.delimiter = '\0'; break;
                case 'f':
                    if (p[1]) {
                        if (bu_size_arg (p + 1, BU_MSG_FIELDS, &o.skip_fields) != 0) return EX_USAGE;
                        p += strlen (p) - 1;
                    } else {
                        if (!list->next) { builtin_error ("option requires an argument -- 'f'"); return EX_USAGE; }
                        if (bu_size_arg (list->next->word->word, BU_MSG_FIELDS, &o.skip_fields) != 0) return EX_USAGE;
                        list = list->next;
                    }
                    sfo_new = 1;
                    break;
                case 's':
                    if (p[1]) {
                        if (bu_size_arg (p + 1, BU_MSG_SKIP, &o.skip_chars) != 0) return EX_USAGE;
                        p += strlen (p) - 1;
                    } else {
                        if (!list->next) { builtin_error ("option requires an argument -- 's'"); return EX_USAGE; }
                        if (bu_size_arg (list->next->word->word, BU_MSG_SKIP, &o.skip_chars) != 0) return EX_USAGE;
                        list = list->next;
                    }
                    break;
                case 'w':
                    if (p[1]) {
                        if (bu_size_arg (p + 1, BU_MSG_CHECK, &o.check_chars) != 0) return EX_USAGE;
                        p += strlen (p) - 1;
                    } else {
                        if (!list->next) { builtin_error ("option requires an argument -- 'w'"); return EX_USAGE; }
                        if (bu_size_arg (list->next->word->word, BU_MSG_CHECK, &o.check_chars) != 0) return EX_USAGE;
                        list = list->next;
                    }
                    break;
                default: builtin_error ("unknown flag: -%c", *p); builtin_usage (); return EX_USAGE;
            }
        }
        list = list->next;
    }
    if (cflag && all_repeated) {
        builtin_error ("printing all duplicated lines and repeat counts is meaningless");
        builtin_usage ();
        return EX_USAGE;
    }
    if (grouping != BU_GROUP_NONE && (cflag || dflag || all_repeated || uflag)) {
        builtin_error ("--group is mutually exclusive with -c/-d/-D/-u");
        builtin_usage ();
        return EX_USAGE;
    }
    FILE *f = stdin;
    FILE *fopened = NULL;
    FILE *out = stdout;
    FILE *outopened = NULL;
    if (list) {
        const char *input = list->word->word;
        list = list->next;
        if (strcmp (input, "-") != 0) {
            fopened = fopen (input, "r");
            if (!fopened) {
                builtin_error ("%s: %s", input, strerror (errno));
                return EXECUTION_FAILURE;
            }
            f = fopened;
        }
        if (list) {
            const char *output = list->word->word;
            list = list->next;
            if (list) {
                builtin_error ("extra operand '%s'", list->word->word);
                builtin_usage ();
                if (fopened) fclose (fopened);
                return EX_USAGE;
            }
            if (strcmp (output, "-") != 0) {
                outopened = fopen (output, "w");
                if (!outopened) {
                    builtin_error ("%s: %s", output, strerror (errno));
                    if (fopened) fclose (fopened);
                    return EXECUTION_FAILURE;
                }
                out = outopened;
            }
        }
    }
    char *prev = NULL, *cur = NULL;
    char *group = NULL;
    size_t prev_cap = 0, cur_cap = 0;
    size_t group_len = 0, group_cap = 0;
    size_t prev_len = 0, cur_len = 0;
    long count = 0;
    int first_group = 1;
    int first_repeated_group = 1;
    ssize_t rd;

    if (f == stdin)
        clearerr (f);
    if (out == stdout)
        clearerr (out);

    bl_output output;
    bl_output_init (&output, out);
    while (!output.error && (rd = bu_get_record (&cur, &cur_cap, f, o.delimiter)) != -1) {
        cur_len = (size_t) rd;
        if (prev && bu_eq (prev, prev_len, cur, cur_len, &o, iflag)) {
            if (all_repeated) {
                if (count == 1 && bu_append_record (&group, &group_len, &group_cap, prev, prev_len) < 0)
                    goto memory_error;
                if (bu_append_record (&group, &group_len, &group_cap, cur, cur_len) < 0)
                    goto memory_error;
            } else if (grouping != BU_GROUP_NONE) {
                if (bu_append_record (&group, &group_len, &group_cap, cur, cur_len) < 0)
                    goto memory_error;
            }
            count++;
            continue;
        }
        /* emit prev if any */
        if (prev) {
            if (all_repeated) {
                if (count > 1) {
                    if (all_mode == BU_ALL_PREPEND
                        || (all_mode == BU_ALL_SEPARATE && !first_repeated_group))
                        bl_output_byte (&output, (unsigned char) o.delimiter);
                    bl_output_write (&output, group, group_len);
                    first_repeated_group = 0;
                }
                group_len = 0;
            } else if (grouping != BU_GROUP_NONE) {
                if (grouping == BU_GROUP_PREPEND || (grouping == BU_GROUP_BOTH && first_group) ||
                    (!first_group && grouping == BU_GROUP_SEPARATE))
                    bl_output_byte (&output, (unsigned char) o.delimiter);
                bl_output_write (&output, group, group_len);
                if (grouping == BU_GROUP_APPEND || grouping == BU_GROUP_BOTH)
                    bl_output_byte (&output, (unsigned char) o.delimiter);
                group_len = 0;
                first_group = 0;
            } else {
                int emit = 1;
                if (dflag && count == 1) emit = 0;     /* -d only dups */
                if (uflag && count > 1) emit = 0;      /* -u only singletons */
                if (emit) {
                    bu_emit_line (&output, count, prev, prev_len, cflag);
                }
            }
        }
        /* swap: prev := cur, cur := scratch (capacities + lengths too) */
        char *tmp = prev; prev = cur; cur = tmp;
        size_t tcap = prev_cap; prev_cap = cur_cap; cur_cap = tcap;
        prev_len = cur_len;
        count = 1;
        if (grouping != BU_GROUP_NONE && bu_append_record (&group, &group_len, &group_cap, prev, prev_len) < 0)
            goto memory_error;
    }
    /* Final emit. */
    if (prev) {
        if (all_repeated) {
            if (count > 1) {
                if (all_mode == BU_ALL_PREPEND
                    || (all_mode == BU_ALL_SEPARATE && !first_repeated_group))
                    bl_output_byte (&output, (unsigned char) o.delimiter);
                bl_output_write (&output, group, group_len);
            }
        } else if (grouping != BU_GROUP_NONE) {
            if (grouping == BU_GROUP_PREPEND || (grouping == BU_GROUP_BOTH && first_group) ||
                (!first_group && grouping == BU_GROUP_SEPARATE))
                bl_output_byte (&output, (unsigned char) o.delimiter);
            bl_output_write (&output, group, group_len);
            if (grouping == BU_GROUP_APPEND || grouping == BU_GROUP_BOTH)
                bl_output_byte (&output, (unsigned char) o.delimiter);
        } else {
            int emit = 1;
            if (dflag && count == 1) emit = 0;
            if (uflag && count > 1) emit = 0;
            if (emit) {
                bu_emit_line (&output, count, prev, prev_len, cflag);
            }
        }
    }
    int rc = EXECUTION_SUCCESS;
    if (ferror (f)) { builtin_error ("read error: %s", strerror (errno)); rc = EXECUTION_FAILURE; }
    bl_output_flush (&output);
    if (output.error) { builtin_error ("write error: %s", strerror (output.error)); rc = EXECUTION_FAILURE; }
    free (prev); free (cur); free (group);
    if (outopened && fclose (outopened) != 0) {
        builtin_error ("%s", strerror (errno));
        if (fopened) fclose (fopened);
        return EXECUTION_FAILURE;
    }
    if (fopened) fclose (fopened);
    return rc;

memory_error:
    bl_output_flush (&output);
    builtin_error ("%s", strerror (ENOMEM));
    free (prev); free (cur); free (group);
    if (outopened) fclose (outopened);
    if (fopened) fclose (fopened);
    return EXECUTION_FAILURE;
}

char *uniq_doc[] = {
    "Filter adjacent matching lines (input must be sorted for global uniqueness).",
    "",
    "    bashuniq [-cdDuiz] [-f N] [-s N] [-w N] [INPUT [OUTPUT]]",
    "",
    "    -c, --count        prefix lines with run count",
    "    -d, --repeated     only emit lines that have duplicates",
    "    -D, --all-repeated[=METHOD]  emit all lines from duplicate groups",
    "        METHOD is none, separate, or prepend",
    "        --group[=METHOD]  show all groups; METHOD is separate, prepend, append, or both",
    "    -u, --unique       only emit lines that are unique",
    "    -i, --ignore-case  case-insensitive compare",
    "    -z, --zero-terminated  use NUL as the line delimiter",
    "    -f, --skip-fields=N  avoid comparing the first N fields",
    "    -s, --skip-chars=N   avoid comparing the first N chars after fields",
    "    -w, --check-chars=N  compare no more than N chars after skips",
    "    -N (obsolete)      skip N fields, like -f N",
    "    +N (obsolete)      skip N chars, like -s N",
    (char *)NULL
};

struct builtin bashuniq_struct = {
    "bashuniq",
    uniq_builtin,
    BUILTIN_ENABLED,
    uniq_doc,
    "bashuniq [-cdDuiz] [-f N] [-s N] [-w N] [INPUT [OUTPUT]]",
    0
};

/* The unprefixed registration matches the compiled-in command name. */
struct builtin uniq_struct = {
    "uniq",
    uniq_builtin,
    BUILTIN_ENABLED,
    uniq_doc,
    "bashuniq [-cdDuiz] [-f N] [-s N] [-w N] [INPUT [OUTPUT]]",
    0
};
