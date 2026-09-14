/* bashtr.c — POSIX tr(1) as a bash builtin.
 *
 * Phase A.3 of bash-os shell-ergonomics. Replaces rootfs/bash/tr.sh
 * (which was a pure-bash shim limited to ASCII without escape handling).
 *
 * Modes:
 *   bashtr SET1 SET2          translate chars in SET1 → corresponding in SET2
 *   bashtr -d SET             delete chars in SET
 *   bashtr -s SET             squeeze runs of SET-chars to one
 *   bashtr -ds SET1 SET2      delete in SET1, then squeeze in SET2
 *   bashtr -c/-C …            complement: act on chars NOT in SET
 *
 * Char-set syntax:
 *   - Literal bytes
 *   - Ranges  `a-z` (printable-ASCII order)
 *   - POSIX backslash escapes `\n` `\t` `\r` `\\` `\NNN` (octal)
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

#include "loadables.h"

static int
btr_parse_escaped_char (const char **sp, unsigned char *out)
{
    const char *s = *sp;

    if (*s == '\\' && s[1]) {
        switch (s[1]) {
            case 'n': *out = '\n'; *sp = s + 2; return 1;
            case 't': *out = '\t'; *sp = s + 2; return 1;
            case 'r': *out = '\r'; *sp = s + 2; return 1;
            case '\\': *out = '\\'; *sp = s + 2; return 1;
            case 'a': *out = '\a'; *sp = s + 2; return 1;
            case 'b': *out = '\b'; *sp = s + 2; return 1;
            case 'f': *out = '\f'; *sp = s + 2; return 1;
            case 'v': *out = '\v'; *sp = s + 2; return 1;
            default:
                if (s[1] >= '0' && s[1] <= '7') {
                    int n = 0, k = 0;
                    s++;
                    while (k < 3 && *s >= '0' && *s <= '7') {
                        n = n * 8 + (*s - '0');
                        s++; k++;
                    }
                    *out = (unsigned char) n;
                    *sp = s;
                    return 1;
                }
                *out = (unsigned char) s[1];
                *sp = s + 2;
                return 1;
        }
    }

    if (*s == '\0')
        return 0;
    *out = (unsigned char) *s;
    *sp = s + 1;
    return 1;
}

/* Parse GNU/POSIX repeat syntax [C*] or [C*N].  A count of -1 means
   "repeat until SET1 is exhausted"; callers cap that at their buffer size. */
static int
btr_parse_repeat (const char *s, unsigned char *c_out, int *count_out,
                  const char **next_out)
{
    const char *p;
    int count;

    if (s[0] != '[' || s[1] == ':' || s[1] == '\0')
        return 0;

    p = s + 1;
    if (btr_parse_escaped_char (&p, c_out) == 0 || *p != '*')
        return 0;
    p++;

    /* Read the repeat-count digits. GNU tr (tr.c) interprets the count as
       OCTAL when it begins with '0', decimal otherwise; an absent count
       ([c*]) or an explicit zero ([c*0]) both mean "repeat indefinitely",
       i.e. pad to the length of SET1 (signalled here as -1). */
    {
        const char *digits = p;
        while (*p >= '0' && *p <= '9')
            p++;
        if (*p != ']')
            return 0;
        if (p == digits)
            count = -1;                       /* [c*] — indefinite */
        else {
            long v = strtol (digits, NULL, (*digits == '0') ? 8 : 10);
            if (v <= 0)        count = -1;     /* [c*0] — indefinite */
            else if (v > 256)  count = 256;    /* cap to caller buffer */
            else               count = (int) v;
        }
    }

    *count_out = count;
    *next_out = p + 1;
    return 1;
}

static int
btr_set_has_repeat (const char *s)
{
    unsigned char c;
    int count;
    const char *next;

    while (*s) {
        if (btr_parse_repeat (s, &c, &count, &next))
            return 1;
        s++;
    }
    return 0;
}

/* Expand SET into a 256-byte slot array. Each slot[i] = 1 iff byte i is
   in the set. Resolves backslash escapes and `a-z` ranges. */
static int
btr_expand_set (const char *s, unsigned char in_set[256])
{
    memset (in_set, 0, 256);
    while (*s) {
        unsigned char c;
        int repeat_count;
        const char *repeat_next;
        if (btr_parse_repeat (s, &c, &repeat_count, &repeat_next)) {
            in_set[c] = 1;
            s = repeat_next;
            continue;
        }
        /* Character class [:class:]. */
        if (*s == '[' && s[1] == ':') {
            const char *end = strstr (s + 2, ":]");
            if (end) {
                size_t nlen = (size_t) (end - (s + 2));
                if (nlen > 0 && nlen <= 10) {
                    char cls[12]; memcpy (cls, s + 2, nlen); cls[nlen] = '\0';
                    if      (strcmp (cls, "alpha")  == 0) {
                        memset (in_set + 'A', 1, 26); memset (in_set + 'a', 1, 26);
                    } else if (strcmp (cls, "upper")  == 0) {
                        memset (in_set + 'A', 1, 26);
                    } else if (strcmp (cls, "lower")  == 0) {
                        memset (in_set + 'a', 1, 26);
                    } else if (strcmp (cls, "digit")  == 0) {
                        memset (in_set + '0', 1, 10);
                    } else if (strcmp (cls, "xdigit") == 0) {
                        memset (in_set + '0', 1, 10);
                        memset (in_set + 'A', 1, 6); memset (in_set + 'a', 1, 6);
                    } else if (strcmp (cls, "alnum")  == 0) {
                        memset (in_set + '0', 1, 10);
                        memset (in_set + 'A', 1, 26); memset (in_set + 'a', 1, 26);
                    } else if (strcmp (cls, "space")  == 0) {
                        unsigned char sp[] = {' ','\t','\n','\v','\f','\r'};
                        for (size_t i = 0; i < sizeof sp; i++) in_set[sp[i]] = 1;
                    } else if (strcmp (cls, "blank")  == 0) {
                        in_set[' '] = 1; in_set['\t'] = 1;
                    } else if (strcmp (cls, "punct")  == 0) {
                        for (int i = '!'; i <= '/';  i++) in_set[i] = 1;
                        for (int i = ':'; i <= '@';  i++) in_set[i] = 1;
                        for (int i = '['; i <= '`';  i++) in_set[i] = 1;
                        for (int i = '{'; i <= '~';  i++) in_set[i] = 1;
                    } else if (strcmp (cls, "graph")  == 0) {
                        for (int i = '!'; i <= '~';  i++) in_set[i] = 1;
                    } else if (strcmp (cls, "print")  == 0) {
                        for (int i = ' '; i <= '~';  i++) in_set[i] = 1;
                    } else if (strcmp (cls, "cntrl")  == 0) {
                        memset (in_set, 1, 0x20); in_set[0x7F] = 1;
                    } /* else unknown → silently ignore per GNU tr compat */
                    s = end + 2;
                    continue;
                }
            }
            /* Not a valid [:class:] — fall through to general parse below. */
        }
        /* Equivalence class [=c=]. In the C/POSIX locale a character is
           equivalent only to itself, so [=c=] contributes just c (GNU tr
           parity). */
        if (*s == '[' && s[1] == '=') {
            const char *end = strstr (s + 2, "=]");
            if (end && end > s + 2) {
                const char *q = s + 2;
                unsigned char ec;
                while (q < end && btr_parse_escaped_char (&q, &ec))
                    in_set[ec] = 1;
                s = end + 2;
                continue;
            }
            /* Not a valid [=...=] — fall through to general parse below. */
        }
        /* General element: one (possibly escaped) byte, optionally the low
           end of a range X-Y. Both endpoints go through
           btr_parse_escaped_char so backslash/octal escapes resolve and
           advance correctly on either side of the '-' (GNU tr parity). */
        if (btr_parse_escaped_char (&s, &c) == 0)
            break;
        if (*s == '-' && s[1] && s[1] != ']') {
            const char *p = s + 1;
            unsigned char hi;
            if (btr_parse_escaped_char (&p, &hi)) {
                s = p;
                if (c <= hi) { for (int i = c; i <= hi; i++) in_set[i] = 1; }
                else         { in_set[c] = 1; in_set[hi] = 1; }
                continue;
            }
        }
        in_set[c] = 1;
    }
    return 0;
}

/* Build an ordered list of bytes in SET (in expansion order — needed for
   translation pairing where SET2's i-th char is the replacement for
   SET1's i-th char). */
static int
btr_expand_list (const char *s, unsigned char *out, int *n_out, int max)
{
    int n = 0;
    while (*s && n < max) {
        unsigned char c;
        int repeat_count;
        const char *repeat_next;
        if (btr_parse_repeat (s, &c, &repeat_count, &repeat_next)) {
            int limit = (repeat_count < 0) ? max : repeat_count;
            for (int i = 0; i < limit && n < max; i++)
                out[n++] = c;
            s = repeat_next;
            continue;
        }
        /* Character class [:class:]. */
        if (*s == '[' && s[1] == ':') {
            const char *end = strstr (s + 2, ":]");
            if (end) {
                size_t nlen = (size_t) (end - (s + 2));
                if (nlen > 0 && nlen <= 10) {
                    char cls[12]; memcpy (cls, s + 2, nlen); cls[nlen] = '\0';
                    if      (strcmp (cls, "alpha")  == 0) {
                        for (int i = 'A'; i <= 'Z' && n < max; i++) out[n++] = (unsigned char) i;
                        for (int i = 'a'; i <= 'z' && n < max; i++) out[n++] = (unsigned char) i;
                    } else if (strcmp (cls, "upper")  == 0) {
                        for (int i = 'A'; i <= 'Z' && n < max; i++) out[n++] = (unsigned char) i;
                    } else if (strcmp (cls, "lower")  == 0) {
                        for (int i = 'a'; i <= 'z' && n < max; i++) out[n++] = (unsigned char) i;
                    } else if (strcmp (cls, "digit")  == 0) {
                        for (int i = '0'; i <= '9' && n < max; i++) out[n++] = (unsigned char) i;
                    } else if (strcmp (cls, "xdigit") == 0) {
                        for (int i = '0'; i <= '9' && n < max; i++) out[n++] = (unsigned char) i;
                        for (int i = 'A'; i <= 'F' && n < max; i++) out[n++] = (unsigned char) i;
                        for (int i = 'a'; i <= 'f' && n < max; i++) out[n++] = (unsigned char) i;
                    } else if (strcmp (cls, "alnum")  == 0) {
                        for (int i = '0'; i <= '9' && n < max; i++) out[n++] = (unsigned char) i;
                        for (int i = 'A'; i <= 'Z' && n < max; i++) out[n++] = (unsigned char) i;
                        for (int i = 'a'; i <= 'z' && n < max; i++) out[n++] = (unsigned char) i;
                    } else if (strcmp (cls, "space")  == 0) {
                        static const unsigned char sp[] = {' ','\t','\n','\v','\f','\r'};
                        for (size_t i = 0; i < sizeof sp && n < max; i++) out[n++] = sp[i];
                    } else if (strcmp (cls, "blank")  == 0) {
                        out[n++] = ' '; if (n < max) out[n++] = '\t';
                    } else if (strcmp (cls, "punct")  == 0) {
                        for (int i = '!'; i <= '/'  && n < max; i++) out[n++] = (unsigned char) i;
                        for (int i = ':'; i <= '@'  && n < max; i++) out[n++] = (unsigned char) i;
                        for (int i = '['; i <= '`'  && n < max; i++) out[n++] = (unsigned char) i;
                        for (int i = '{'; i <= '~'  && n < max; i++) out[n++] = (unsigned char) i;
                    } else if (strcmp (cls, "graph")  == 0) {
                        for (int i = '!'; i <= '~'  && n < max; i++) out[n++] = (unsigned char) i;
                    } else if (strcmp (cls, "print")  == 0) {
                        for (int i = ' '; i <= '~'  && n < max; i++) out[n++] = (unsigned char) i;
                    } else if (strcmp (cls, "cntrl")  == 0) {
                        for (int i = 0; i <= 0x1F && n < max; i++) out[n++] = (unsigned char) i;
                        if (n < max) out[n++] = 0x7F;
                    } /* else unknown → silently ignore per GNU tr compat */
                    s = end + 2;
                    continue;
                }
            }
            /* Not a valid [:class:] — fall through to general parse below. */
        }
        /* Equivalence class [=c=] — C/POSIX locale: contributes just c. */
        if (*s == '[' && s[1] == '=') {
            const char *end = strstr (s + 2, "=]");
            if (end && end > s + 2) {
                const char *q = s + 2;
                unsigned char ec;
                while (q < end && n < max && btr_parse_escaped_char (&q, &ec))
                    out[n++] = ec;
                s = end + 2;
                continue;
            }
            /* Not a valid [=...=] — fall through to general parse below. */
        }
        /* General element: one (possibly escaped) byte, optionally the low
           end of a range X-Y. Both endpoints go through
           btr_parse_escaped_char (GNU tr parity for octal/backslash on
           either side of the '-'). */
        if (btr_parse_escaped_char (&s, &c) == 0)
            break;
        if (*s == '-' && s[1] && s[1] != ']') {
            const char *p = s + 1;
            unsigned char hi;
            if (btr_parse_escaped_char (&p, &hi)) {
                s = p;
                if (c <= hi) {
                    for (int i = c; i <= hi && n < max; i++) out[n++] = (unsigned char) i;
                } else {
                    out[n++] = c;
                    if (n < max) out[n++] = hi;
                }
                continue;
            }
        }
        out[n++] = c;
    }
    *n_out = n;
    return 0;
}

int
tr_builtin (WORD_LIST *list)
{
    int dflag = 0, sflag = 0, cflag = 0, tflag = 0;
    /* Parse flags. */
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--truncate-set1")) { tflag = 1; list = list->next; continue; }
        for (const char *p = w + 1; *p; p++) {
            switch (*p) {
                case 'd': dflag = 1; break;
                case 's': sflag = 1; break;
                case 't': tflag = 1; break;
                case 'c': case 'C': cflag = 1; break;
                default:
                    builtin_error ("unknown flag: -%c", *p);
                    builtin_usage ();
                    return EX_USAGE;
            }
        }
        list = list->next;
    }
    if (!list) { builtin_error ("usage: bashtr [-Ccdst] SET1 [SET2]"); return EX_USAGE; }
    const char *set1 = list->word->word;
    const char *set2 = (list->next) ? list->next->word->word : "";
    if (list->next && list->next->next) {
        builtin_error ("extra operand: %s", list->next->next->word->word);
        builtin_usage ();
        return EX_USAGE;
    }
    /* POSIX: translate mode (no -d/-s) requires SET2. */
    if (!dflag && !sflag && !set2[0]) {
        builtin_error ("translate mode requires SET2; use -d/-s for single-set ops");
        return EX_USAGE;
    }
    /* GNU parity: deleting without squeezing takes only one string. */
    if (dflag && !sflag && set2[0]) {
        builtin_error ("extra operand '%s' (only one string may be given "
                       "when deleting without squeezing repeats)", set2);
        return EX_USAGE;
    }
    if (btr_set_has_repeat (set1)) {
        builtin_error ("tr: the [c*] repeat construct may not appear in string1");
        return EXECUTION_FAILURE;
    }

    /* Build set membership for SET1 (with -c complement applied). */
    unsigned char in1[256], in2_set[256];
    btr_expand_set (set1, in1);
    if (cflag) for (int i = 0; i < 256; i++) in1[i] = !in1[i];

    /* Translation pair lists (ordered). */
    unsigned char xlat[256];
    int translate_mode = (!dflag && set2[0]);
    if (translate_mode) {
        unsigned char l1[256], l2[256];
        int n1 = 0, n2 = 0;
        btr_expand_list (set1, l1, &n1, 256);
        if (cflag) {
            /* Complement: build l1 from bytes NOT in original SET1. */
            unsigned char orig[256];
            btr_expand_set (set1, orig);
            n1 = 0;
            for (int i = 0; i < 256; i++) if (!orig[i]) l1[n1++] = (unsigned char) i;
        }
        btr_expand_list (set2, l2, &n2, 256);
        if (n2 == 0) { builtin_error ("tr: SET2 empty for translate mode"); return EX_USAGE; }
        /* Build xlat: identity, then map l1[i] -> l2[i] (last char of l2
           pads if SET2 shorter — POSIX).  With -t (--truncate-set1) SET1 is
           truncated to the length of SET2, so only the first n2 chars of
           SET1 are translated and the remainder pass through unchanged. */
        int nmap = tflag ? ((n1 < n2) ? n1 : n2) : n1;
        for (int i = 0; i < 256; i++) xlat[i] = (unsigned char) i;
        for (int i = 0; i < nmap; i++) {
            unsigned char repl = (i < n2) ? l2[i] : l2[n2 - 1];
            xlat[l1[i]] = repl;
        }
    }

    /* Squeeze set: SET2 if -ds, else SET1 (potentially complemented). */
    btr_expand_set (sflag && set2[0] ? set2 : set1, in2_set);
    if (cflag && !translate_mode) for (int i = 0; i < 256; i++) in2_set[i] = !in2_set[i];

    /* Stream stdin → stdout. */
    unsigned char inbuf[4096], outbuf[4096];
    ssize_t n;
    int last_emit = -1;   /* for squeeze */
    while ((n = read (STDIN_FILENO, inbuf, sizeof inbuf)) > 0) {
        size_t op = 0;
        for (ssize_t i = 0; i < n; i++) {
            unsigned char c = inbuf[i];
            /* Delete. */
            if (dflag && in1[c]) continue;
            /* Translate. */
            if (translate_mode) c = xlat[c];
            /* Squeeze. */
            if (sflag && in2_set[c] && (int) c == last_emit) continue;
            outbuf[op++] = c;
            last_emit = c;
            if (op == sizeof outbuf) {
                if (write (STDOUT_FILENO, outbuf, op) < 0) {
                    builtin_error ("write: %s", strerror (errno));
                    return EXECUTION_FAILURE;
                }
                op = 0;
            }
        }
        if (op > 0) {
            if (write (STDOUT_FILENO, outbuf, op) < 0) {
                builtin_error ("write: %s", strerror (errno));
                return EXECUTION_FAILURE;
            }
        }
    }
    if (n < 0) { builtin_error ("read: %s", strerror (errno)); return EXECUTION_FAILURE; }
    return EXECUTION_SUCCESS;
}

char *tr_doc[] = {
    "Translate, squeeze, or delete characters from stdin → stdout.",
    "",
    "    bashtr SET1 SET2          translate chars in SET1 → SET2",
    "    bashtr -d SET             delete chars in SET",
    "    bashtr -s SET             squeeze runs of SET-chars to one",
    "    bashtr -ds SET1 SET2      delete in SET1 then squeeze in SET2",
    "    bashtr -c/-C ...          complement: act on chars NOT in SET",
    "    bashtr -t SET1 SET2       truncate SET1 to length of SET2 first",
    "",
    "Char-set syntax: literal bytes, ranges `a-z`, escape sequences",
    "`\\n \\t \\r \\\\ \\NNN` (octal), POSIX classes `[:alpha:]` etc.,",
    "equivalence classes `[=c=]`, and `[c*]`/`[c*N]` repeats in SET2",
    "(N is octal if it begins with 0).",
    "",
    "Examples:",
    "    echo Hello | bashtr A-Z a-z      # 'hello'",
    "    echo a,,,b | bashtr -s ,         # 'a,b'",
    "    echo a:b:c | bashtr ':' '\\n'      # one per line",
    (char *)NULL
};

struct builtin bashtr_struct = {
    "bashtr",
    tr_builtin,
    BUILTIN_ENABLED,
    tr_doc,
    "bashtr [-Ccdst] SET1 [SET2]",
    0
};
