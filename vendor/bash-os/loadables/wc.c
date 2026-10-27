/* bashwc.c — POSIX wc(1) as a bash builtin.
 *
 * Phase A.3 of bash-os shell-ergonomics. -l (lines), -w (words),
 * -c (bytes), -m (chars). Multi-file with per-file rows and a
 * `total` row. No flags = -lwc (default GNU/POSIX behavior).
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <locale.h>
#include <wchar.h>
#include <wctype.h>
#include <sys/stat.h>

#include "loadables.h"

typedef struct {
    long long lines;
    long long words;
    long long bytes;
    long long chars;
    long long max_line;
} bwc_counts;

/* Count bytes, lines and words from an open FILE * without decoding
 * characters: the path for every invocation that asks for none of -m/-L.
 * Blocks in, newlines by memchr, words by a byte state machine. Whitespace
 * is ASCII's plus the UTF-8 encodings of the Unicode spaces GNU wc treats as
 * separators in a UTF-8 locale (U+00A0, U+1680, U+2000-U+200A, U+2028,
 * U+2029, U+202F, U+205F, U+3000 — each checked against GNU wc 9.7; U+0085,
 * U+180E, U+200B and U+FEFF are word characters there), matched by bytes; any other byte
 * >= 0x80 is a word character, so a multibyte character never splits a
 * word and an invalid byte counts as GNU counts it. Up to two bytes are
 * carried across block boundaries so a sequence is never cut. Measured on
 * the appliance (1 GHz RISC-V, 2026-09-06): the decoding loop below took
 * 261 ms for a 423 KB file, five times busybox's wc; this takes the file at
 * the speed of the read. */
/* GNU wc separates words on the non-breaking spaces U+00A0, U+2007, U+202F
   and U+2060 as well as on iswspace, unless POSIXLY_CORRECT is set. */
static int
bwc_nbsp_ok (void)
{
    return getenv ("POSIXLY_CORRECT") == NULL;
}
static int
bwc_is_nbspace (wchar_t wc)
{
    return wc == 0x00A0 || wc == 0x2007 || wc == 0x202F || wc == 0x2060;
}
/* The UTF-8 encodings of the Unicode spaces, matched by bytes. NBSP is the
   non-breaking set above (gated on nbsp); the rest are iswspace. */
static size_t
bwc_uspace (const unsigned char *p, size_t avail, int nbsp)
{
    if (avail >= 2 && p[0] == 0xC2 && p[1] == 0xA0) return nbsp ? 2 : 0;                 /* U+00A0 */
    if (avail >= 3) {
        if (p[0] == 0xE1 && p[1] == 0x9A && p[2] == 0x80) return 3;                      /* U+1680 */
        if (p[0] == 0xE2 && p[1] == 0x80) {
            if (p[2] == 0x87 || p[2] == 0xAF) return nbsp ? 3 : 0;                      /* U+2007 U+202F */
            if ((p[2] >= 0x80 && p[2] <= 0x8A) || p[2] == 0xA8 || p[2] == 0xA9) return 3; /* U+2000-200A U+2028 U+2029 */
        }
        if (p[0] == 0xE2 && p[1] == 0x81 && p[2] == 0x9F) return 3;                      /* U+205F */
        if (p[0] == 0xE2 && p[1] == 0x81 && p[2] == 0xA0) return nbsp ? 3 : 0;           /* U+2060 */
        if (p[0] == 0xE3 && p[1] == 0x80 && p[2] == 0x80) return 3;                      /* U+3000 */
    }
    return 0;
}
static int
bwc_count_fast (FILE *f, bwc_counts *c)
{
    static unsigned char buf[65536 + 4];
    long long L = 0, W = 0, B = 0;
    int in_word = 0;
    int mb = MB_CUR_MAX > 1;          /* the Unicode spaces separate words only in a multibyte locale */
    int nbsp = bwc_nbsp_ok ();        /* in a unibyte locale GNU treats the byte 0xA0 as one */
    size_t off = 0, n;
    for (;;) {
        n = fread (buf + off, 1, sizeof buf - 4 - off, f);
        int eof = (n == 0);
        size_t have = off + n;
        B += (long long) n;
        /* keep the last two bytes for the next block unless this is the end:
         * a multibyte space sequence may straddle the boundary */
        size_t lim = eof ? have : (have > 2 ? have - 2 : 0);
        const unsigned char *p = buf, *end = buf + lim, *q;
        for (q = p; (q = memchr (q, '\n', (size_t)(end - q))) != NULL; q++) L++;
        while (p < end) {
            unsigned char b = *p;
            size_t adv = 1, sp = 0;
            if (b == ' ' || b == '\n' || b == '\t' || b == '\r' || b == '\v' || b == '\f') sp = 1;
            else if (!mb) { if (nbsp && b == 0xA0) sp = 1; }
            else if (b >= 0xC2) { size_t u = bwc_uspace (p, (size_t)(buf + have - p), nbsp); if (u) { sp = 1; adv = u; } }
            if (sp) in_word = 0;
            else if (!in_word) { in_word = 1; W++; }
            p += adv;
        }
        if (eof) break;
        /* a space sequence that began before the carry region was consumed
           whole: carry only what was not scanned, or its tail bytes would be
           rescanned as the start of a word */
        if ((size_t)(p - buf) > lim) lim = (size_t)(p - buf);
        off = have - lim;
        memmove (buf, buf + lim, off);
    }
    c->lines = L; c->words = W; c->bytes = B; c->chars = B; c->max_line = 0;
    return 0;
}

/* Count an ASCII run without alignment/aliasing assumptions or reading past
   the block. In a multibyte locale these bytes each encode one character.
   memcpy of a machine word is inlined by optimizing compilers. */
static const unsigned char *
bwc_ascii_end (const unsigned char *p, const unsigned char *end)
{
    const size_t high_bits = (size_t) -1 / 255 * 128;
    while ((size_t) (end - p) >= sizeof (size_t)) {
        size_t word;
        memcpy (&word, p, sizeof word);
        if (word & high_bits) break;
        p += sizeof word;
    }
    while (p < end && *p < 0x80) p++;
    return p;
}

/* Decode directly from each input block. Only an incomplete final sequence
   is moved to the next block; invalid bytes remain word characters, but do
   not contribute to the character count or display width. Keep classification
   out of the character-only path and use ASCII directly in the combined path. */
static int
bwc_count_stream (FILE *f, bwc_counts *c, int lflag, int wflag, int Lflag)
{
    long long L = 0, W = 0, B = 0, M = 0, cur = 0, maxl = 0;
    int in_word = 0, nbsp = bwc_nbsp_ok (), mb = MB_CUR_MAX > 1;
    unsigned char buf[65536 + MB_LEN_MAX];
    size_t off = 0, n;
#define BWC_WORDCHAR() do { if (!in_word) { in_word = 1; W++; } } while (0)
    for (;;) {
        n = fread (buf + off, 1, 65536, f);
        int eof = (n == 0);
        B += (long long) n;
        const unsigned char *p = buf, *end = buf + off + n;
        while (p < end) {
            wchar_t wc;
            if (mb && !wflag && !Lflag) {
                const unsigned char *next = bwc_ascii_end (p, end);
                M += (long long) (next - p);
                if (lflag) {
                    const unsigned char *q = p;
                    while ((q = memchr (q, '\n', (size_t) (next - q))) != NULL) { L++; q++; }
                }
                p = next;
                if (p == end) break;
            }
            if (!mb || *p < 0x80) {
                wc = *p++;
            } else {
                mbstate_t st;
                memset (&st, 0, sizeof st);
                size_t r = mbrtowc (&wc, (const char *) p, (size_t) (end - p), &st);
                if (r == (size_t) -2 && !eof && (size_t) (end - p) < MB_LEN_MAX)
                    break;
                if (r == (size_t) -2 || r == (size_t) -1) {
                    if (wflag) BWC_WORDCHAR ();
                    p++;
                    continue;
                }
                p += r ? r : 1;
            }
            M++;
            if (wc == L'\n') L++;
            if (Lflag) {
                if (wc == L'\n' || wc == L'\r' || wc == L'\f') {
                    if (cur > maxl) maxl = cur;
                    cur = 0;
                } else if (wc == L'\t') cur += 8 - (cur % 8);
                else if (wc < 0x80) { if (wc >= 0x20 && wc < 0x7f) cur++; }
                else if (!mb) { if (isprint ((unsigned char) wc)) cur++; }
                else if (iswprint (wc)) { int w = wcwidth (wc); if (w > 0) cur += w; }
            }
            if (wflag) {
                int space = (!mb || wc < 0x80)
                    ? isspace ((unsigned char) wc) : iswspace (wc);
                if (space || (nbsp && bwc_is_nbspace (wc))) in_word = 0;
                else BWC_WORDCHAR ();
            }
        }
        if (eof) break;
        off = (size_t) (end - p);
        memmove (buf, p, off);
    }
#undef BWC_WORDCHAR
    if (cur > maxl) maxl = cur;
    c->lines = L; c->words = W; c->bytes = B; c->chars = M; c->max_line = maxl;
    return 0;
}

/* Number of decimal digits needed to represent a non-negative value
 * (GNU's compute_number_width uses the running-divide form; replicate it). */
static int
bwc_digits (unsigned long long v)
{
    int width = 1;
    for (; v >= 10; v /= 10)
        width++;
    return width;
}

/* Byte counts and single-byte character counts do not require word or
   display-width classification. Count only the requested fields, keeping
   the existing decoding path for multibyte characters and display widths.
   Reading the stream (rather than using a cached file size) also preserves
   its current position and works for pipes and changing pseudo-files. */
static int
bwc_count_selected (FILE *f, bwc_counts *c, int lflag, int wflag,
                    int cflag, int mflag, int Lflag)
{
    if ((lflag || cflag || mflag) && !wflag && !Lflag &&
        (!mflag || MB_CUR_MAX == 1)) {
        unsigned char buf[65536];
        size_t n;
        while ((n = fread (buf, 1, sizeof buf, f)) != 0) {
            c->bytes += (long long) n;
            c->chars += (long long) n;
            if (lflag) {
                const unsigned char *p = buf, *end = buf + n;
                while ((p = memchr (p, '\n', (size_t) (end - p))) != NULL) {
                    c->lines++;
                    p++;
                }
            }
        }
        return 0;
    }
    if (Lflag && !wflag && MB_CUR_MAX == 1) {
        unsigned char buf[65536];
        long long width = 0;
        size_t n;
        while ((n = fread (buf, 1, sizeof buf, f)) != 0) {
            c->bytes += (long long) n;
            c->chars += (long long) n;
            const unsigned char *p = buf, *end = buf + n;
            while (p < end) {
                /* Printable ASCII runs need only their byte length. Keep
                   the locale classification for other single-byte values. */
                const unsigned char *start = p;
                while (p < end && *p >= 0x20 && *p < 0x7f) p++;
                width += (long long) (p - start);
                if (p == end) break;
                unsigned char b = *p++;
                if (b == '\n' || b == '\r' || b == '\f') {
                    if (width > c->max_line) c->max_line = width;
                    width = 0;
                    if (b == '\n') c->lines++;
                } else if (b == '\t') width += 8 - width % 8;
                else if (isprint (b)) width++;
            }
        }
        if (width > c->max_line) c->max_line = width;
        return 0;
    }
    return (mflag || Lflag) ? bwc_count_stream (f, c, lflag, wflag, Lflag) : bwc_count_fast (f, c);
}

/* Print one row of counts according to enabled flags, right-aligning each
 * count column to field width `w` (GNU wc's number_width). Columns are
 * separated by a single space; the first column is also padded to `w`. */
static void
bwc_print (bwc_counts *c, int lflag, int wflag, int cflag, int mflag, int Lflag, int w, const char *name)
{
    int any = lflag || wflag || cflag || mflag || Lflag;
    if (!any) lflag = wflag = cflag = 1;   /* default */
    int first = 1;
    if (lflag) { printf ("%s%*lld", first ? "" : " ", w, c->lines); first = 0; }
    if (wflag) { printf ("%s%*lld", first ? "" : " ", w, c->words); first = 0; }
    if (mflag) { printf ("%s%*lld", first ? "" : " ", w, c->chars); first = 0; }   /* GNU order: lines words chars bytes maxline */
    if (cflag) { printf ("%s%*lld", first ? "" : " ", w, c->bytes); first = 0; }
    if (Lflag) { printf ("%s%*lld", first ? "" : " ", w, c->max_line); first = 0; }
    if (name) printf (" %s", name);
    putchar ('\n');
}

/* Read the entire contents of FILE (or stdin if FILE is "-") into a
 * NUL-allowing buffer, returning the byte count via *lenp. Returns the
 * malloc'd buffer (caller frees) or NULL on error. */
static char *
bwc_slurp (const char *file, size_t *lenp)
{
    FILE *f = (strcmp (file, "-") == 0) ? stdin : fopen (file, "r");
    char *buf = NULL;
    size_t len = 0, cap = 0;
    int ch;

    if (!f) {
        builtin_error ("cannot open '%s' for reading: %s", file, strerror (errno));
        return NULL;
    }
    while ((ch = fgetc (f)) != EOF) {
        if (len >= cap) {
            size_t ncap = cap ? cap * 2 : 256;
            char *nb = realloc (buf, ncap + 1);
            if (!nb) {
                free (buf);
                if (f != stdin) fclose (f);
                return NULL;
            }
            buf = nb;
            cap = ncap;
        }
        buf[len++] = (char) ch;
    }
    if (ferror (f)) {
        builtin_error ("%s: read error: %s", file, strerror (errno ? errno : EIO));
        free (buf);
        if (f != stdin) fclose (f);
        return NULL;
    }
    if (f != stdin) fclose (f);
    if (!buf) buf = malloc (1);
    if (!buf) return NULL;
    buf[len] = '\0';
    *lenp = len;
    return buf;
}

/* Compute GNU wc's number_width for the given file list and column count.
 * Mirrors get_input_fstatus + compute_number_width:
 *   - nfiles==0 (e.g. --files0-from=-), or (nfiles==1 && ncols==1): width 1.
 *   - else sum st_size of regular inputs; width = digits(sum); any
 *     non-regular input forces a minimum width of 7. */
static int
bwc_number_width (char **files, int nfiles, int ncols)
{
    if (nfiles == 0 || (nfiles == 1 && ncols == 1))
        return 1;

    struct stat st;
    int first_failed;
    if (strcmp (files[0], "-") == 0)
        first_failed = fstat (STDIN_FILENO, &st);
    else
        first_failed = stat (files[0], &st);
    if (first_failed > 0)
        return 1;

    int minimum_width = 1;
    unsigned long long regular_total = 0;
    for (int i = 0; i < nfiles; i++) {
        struct stat s;
        int failed = (strcmp (files[i], "-") == 0)
            ? fstat (STDIN_FILENO, &s)
            : stat (files[i], &s);
        if (failed)
            continue;
        if (!S_ISREG (s.st_mode))
            minimum_width = 7;
        else if (s.st_size > 0)
            regular_total += (unsigned long long) s.st_size;
    }
    int width = bwc_digits (regular_total);
    if (width < minimum_width)
        width = minimum_width;
    return width;
}

int
wc_builtin (WORD_LIST *list)
{
    /* The shell owns these streams across invocations and redirections. */
    clearerr (stdin);
    clearerr (stdout);
    int lflag = 0, wflag = 0, cflag = 0, mflag = 0, Lflag = 0;
    const char *files_from = NULL;
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version")) {
            puts ("bashwc 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--lines")) { lflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--words")) { wflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--bytes")) { cflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--chars")) { mflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--max-line-length")) { Lflag = 1; list = list->next; continue; }
        if (!strcmp (w, "--files0-from")) {
            if (!list->next) { builtin_error ("%s needs FILE", w); return EXECUTION_FAILURE; }
            list = list->next;
            files_from = list->word->word;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--files0-from=", 14)) {
            files_from = w + 14;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--", 2)) {
            builtin_error ("unknown flag: %s", w);
            builtin_usage ();
            return EXECUTION_FAILURE;
        }
        for (const char *p = w + 1; *p; p++) {
            switch (*p) {
                case 'l': lflag = 1; break;
                case 'w': wflag = 1; break;
                case 'c': cflag = 1; break;
                case 'm': mflag = 1; break;
                case 'L': Lflag = 1; break;
                default: builtin_error ("unknown flag: -%c", *p); builtin_usage (); return EXECUTION_FAILURE;
            }
        }
        list = list->next;
    }

    int ncols = lflag + wflag + cflag + mflag + Lflag;
    if (ncols == 0) {
        lflag = wflag = cflag = 1;
        ncols = 3;   /* default -lwc */
    }

    bwc_counts total = {0};
    int rc = EXECUTION_SUCCESS;

    /* --files0-from: read NUL-separated filenames; counts each like an
     * operand. With files_from == "-" the list comes from stdin, and (per
     * GNU) the number_width drops to 1 (the nfiles==0 fstatus path). */
    if (files_from) {
        if (list) {
            builtin_error ("file operands cannot be combined with --files0-from");
            return EXECUTION_FAILURE;
        }
        size_t blen = 0;
        char *blob = bwc_slurp (files_from, &blen);
        if (!blob)
            return EXECUTION_FAILURE;

        /* Split on NUL into a name array. */
        char **names = NULL;
        int nnames = 0, ncap = 0;
        int tokpos = 0;       /* 1-based NUL-delimited token position */
        size_t i = 0;
        while (i < blen) {
            size_t start = i;
            while (i < blen && blob[i] != '\0') i++;
            if (i == start && i < blen) {
                /* Empty (zero-length) file name. */
                tokpos++;
                builtin_error ("%s:%d: invalid zero-length file name", files_from, tokpos);
                rc = EXECUTION_FAILURE;
                i++;
                continue;
            }
            if (i >= blen && start == i)
                break;
            tokpos++;
            if (nnames >= ncap) {
                ncap = ncap ? ncap * 2 : 16;
                char **nn = realloc (names, (size_t) ncap * sizeof *nn);
                if (!nn) { free (names); free (blob); return EXECUTION_FAILURE; }
                names = nn;
            }
            blob[i] = '\0';
            names[nnames++] = blob + start;
            i++;
        }

        /* GNU wc width rule for --files0-from (coreutils 9.x):
         *   - list from a regular file (a real --files0-from=FILE, OR
         *     --files0-from=- with stdin redirected from a regular file):
         *     all names are read up front, so nfiles is known and the width
         *     is computed from the operand files' sizes (the normal path).
         *   - list from a non-regular stream (pipe/tty via --files0-from=-):
         *     names are streamed one at a time, nfiles==0, so width is 1. */
        int width;
        if (strcmp (files_from, "-") == 0) {
            struct stat lst;
            if (fstat (STDIN_FILENO, &lst) == 0 && S_ISREG (lst.st_mode))
                width = bwc_number_width (names, nnames, ncols);
            else
                width = 1;
        } else {
            width = bwc_number_width (names, nnames, ncols);
        }

        for (int k = 0; k < nnames; k++) {
            int from_stdin = strcmp (names[k], "-") == 0;
            FILE *f = from_stdin ? stdin : fopen (names[k], "r");
            if (!f) {
                builtin_error ("%s: %s", names[k], strerror (errno));
                rc = EXECUTION_FAILURE;
                continue;
            }
            if (!from_stdin) {
                struct stat dst;
                if (fstat (fileno (f), &dst) == 0 && S_ISDIR (dst.st_mode)) {
                    /* GNU wc: diagnose + exit 1, but still emit a 0/0/0
                       count line (reading the dir fd yields 0 bytes). */
                    builtin_error ("%s: Is a directory", names[k]);
                    rc = EXECUTION_FAILURE;
                }
            }
            bwc_counts c = {0};
            bwc_count_selected (f, &c, lflag, wflag, cflag, mflag, Lflag);
            if (ferror (f)) {
                builtin_error ("read error: %s", strerror (errno ? errno : EIO));
                rc = EXECUTION_FAILURE;
            }
            if (!from_stdin)
                fclose (f);
            bwc_print (&c, lflag, wflag, cflag, mflag, Lflag, width, names[k]);
            total.lines += c.lines;
            total.words += c.words;
            total.bytes += c.bytes;
            total.chars += c.chars;
            if (c.max_line > total.max_line)
                total.max_line = c.max_line;
        }
        if (nnames > 1)
            bwc_print (&total, lflag, wflag, cflag, mflag, Lflag, width, "total");
        free (names);
        free (blob);
        if (fflush (stdout) == EOF || ferror (stdout)) {
            builtin_error ("write error: %s", strerror (errno ? errno : EIO));
            return EXECUTION_FAILURE;
        }
        return rc;
    }

    if (!list) {
        int width = bwc_number_width ((char *[]){ (char *) "-" }, 1, ncols);
        bwc_counts c = {0};
        bwc_count_selected (stdin, &c, lflag, wflag, cflag, mflag, Lflag);
        if (ferror (stdin)) {
            builtin_error ("read error: %s", strerror (errno ? errno : EIO));
            rc = EXECUTION_FAILURE;
        }
        bwc_print (&c, lflag, wflag, cflag, mflag, Lflag, width, NULL);
    } else {
        int n_files = 0;
        for (WORD_LIST *p = list; p; p = p->next) n_files++;
        char **files = malloc ((size_t) n_files * sizeof *files);
        if (!files)
            return EXECUTION_FAILURE;
        {
            int k = 0;
            for (WORD_LIST *p = list; p; p = p->next)
                files[k++] = p->word->word;
        }
        int width = bwc_number_width (files, n_files, ncols);
        free (files);

        for (WORD_LIST *p = list; p; p = p->next) {
            int from_stdin = strcmp (p->word->word, "-") == 0;
            FILE *f = from_stdin ? stdin : fopen (p->word->word, "r");
            if (!f) {
                builtin_error ("%s: %s", p->word->word, strerror (errno));
                rc = EXECUTION_FAILURE;
                continue;
            }
            if (!from_stdin) {
                struct stat dst;
                if (fstat (fileno (f), &dst) == 0 && S_ISDIR (dst.st_mode)) {
                    /* GNU wc: diagnose + exit 1, but still emit a 0/0/0
                       count line (reading the dir fd yields 0 bytes). */
                    builtin_error ("%s: Is a directory", p->word->word);
                    rc = EXECUTION_FAILURE;
                }
            }
            bwc_counts c = {0};
            bwc_count_selected (f, &c, lflag, wflag, cflag, mflag, Lflag);
            if (ferror (f)) {
                builtin_error ("read error: %s", strerror (errno ? errno : EIO));
                rc = EXECUTION_FAILURE;
            }
            if (!from_stdin)
                fclose (f);
            bwc_print (&c, lflag, wflag, cflag, mflag, Lflag, width, p->word->word);
            total.lines += c.lines;
            total.words += c.words;
            total.bytes += c.bytes;
            total.chars += c.chars;
            if (c.max_line > total.max_line)
                total.max_line = c.max_line;
        }
        if (n_files > 1)
            bwc_print (&total, lflag, wflag, cflag, mflag, Lflag, width, "total");
    }
    if (fflush (stdout) == EOF || ferror (stdout)) {
        builtin_error ("write error: %s", strerror (errno ? errno : EIO));
        return EXECUTION_FAILURE;
    }
    return rc;
}

char *wc_doc[] = {
    "Count lines / words / bytes / chars in FILEs (or stdin).",
    "",
    "    bashwc [-lwcmL] [--lines|--words|--bytes|--chars|--max-line-length] [FILE...]",
    "    bashwc --help | --version",
    "",
    "Flags:",
    "    -l   count lines",
    "    -w   count words (whitespace-separated runs)",
    "    -c   count bytes",
    "    -m   count characters",
    "    -L   count maximum display line length",
    "    --lines, --words, --bytes, --chars, --max-line-length",
    "    --files0-from=F  read NUL-separated file names from F (- for stdin)",
    "    --help      show usage",
    "    --version   show version",
    "    (no flags) → -lwc (default)",
    "",
    "Multi-file output emits one row per file plus a `total` row.",
    (char *)NULL
};

struct builtin bashwc_struct = {
    "bashwc",
    wc_builtin,
    BUILTIN_ENABLED,
    wc_doc,
    "bashwc [-lwcmL] [--lines|--words|--bytes|--chars|--max-line-length] [FILE...]",
    0
};
