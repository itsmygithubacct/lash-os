/* bashod.c — POSIX od(1) as a bash builtin.
 *
 *   bashod [-A {x,o,d,n}] [-j BYTES] [-N BYTES] [-t TYPE] [-w[WIDTH]] [-v]
 *          [-c] [-x] [-o] [-d] [-b] [-s [N]] [FILE...]
 *
 *   -A x|o|d|n      address radix (hex / octal / decimal / none); default o
 *   -c              char (printable + \-escapes for whitespace, octal otherwise)
 *   -b              1-byte octal (legacy, == -t o1)
 *   -x              16-bit hex
 *   -o              16-bit octal (default if no -[cxodb])
 *   -d              16-bit decimal
 *   -t TYPE         a, c, [doux]{1,2,4}
 *   -w[WIDTH]       bytes per output line (default 16)
 *   -v              do not collapse runs of identical lines into "*"
 *   -s [N]          strings: print runs of >= N (default 3) printable chars
 *
 * Reads stdin when no FILE given. Multiple display modes can be combined
 * (e.g. `-c -x` prints chars and hex on stacked lines per address). Each
 * type's column is padded to its own element width and aligned GNU-style.
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
#include <limits.h>
#include <sys/types.h>

#include "loadables.h"

#define OD_DEFAULT_WIDTH 16   /* default bytes per output line */
#define OD_MAX_SPECS     16   /* max stacked -t / legacy selectors */

/* A single display format. kind: 'c' char-escape, 'a' named-char,
   'i' integer (then base in 'x'/'o'/'d'/'u' and bytes in {1,2,4,8}),
   'f' IEEE float (bytes in {4,8}). */
typedef struct {
    char kind;
    char base;     /* for kind 'i': 'x' 'o' 'd' (signed) 'u' (unsigned) */
    int  bytes;    /* element width in bytes (1,2,4,8) */
    int  field;    /* natural field width incl. leading separator space */
} od_spec;

typedef struct {
    char addr_radix;       /* 'x' 'o' 'd' 'n' */
    od_spec specs[OD_MAX_SPECS];
    int  nspecs;
    int  width;            /* bytes per output line */
    int  no_dedup;         /* -v: disable '*' run collapsing */
    int  strings_min;      /* 0 = -s mode off; otherwise minimum run length */
    int  gnu_strings_min;  /* 0 = -S mode off; >0 = GNU NUL-terminated mode */
    long long skip_bytes;  /* -j: bytes to skip before dumping */
    long long max_bytes;   /* -1 = unlimited; >=0 = stop after N bytes (-N) */
} od_opts;

/* Named ASCII control chars for -t a (bytes 0x00..0x1f, 0x20=sp, 0x7f=del). */
static const char *od_ascii_names[] = {
    "nul","soh","stx","etx","eot","enq","ack","bel",
    " bs"," ht"," nl"," vt"," ff"," cr"," so"," si",
    "dle","dc1","dc2","dc3","dc4","nak","syn","etb",
    "can"," em","sub","esc"," fs"," gs"," rs"," us"
};

static int
od_spec_field (char kind, char base, int bytes)
{
    if (kind == 'c' || kind == 'a')
        return 4;            /* "   A" / " nul" */
    if (kind == 'f')         /* GNU: f4 => 16 cols, f8 => 25 cols (incl sep) */
        return (bytes == 4) ? 16 : 25;
    switch (base) {
        case 'x': return (bytes == 1) ? 3 : (bytes == 2) ? 5 : (bytes == 4) ? 9 : 17;
        case 'o': return (bytes == 1) ? 4 : (bytes == 2) ? 7 : (bytes == 4) ? 12 : 23;
        case 'd': return (bytes == 1) ? 5 : (bytes == 2) ? 7 : (bytes == 4) ? 12 : 21;
        case 'u':
        default:  return (bytes == 1) ? 4 : (bytes == 2) ? 6 : (bytes == 4) ? 11 : 21;
    }
}

static void
od_add_spec (od_opts *o, char kind, char base, int bytes)
{
    if (o->nspecs >= OD_MAX_SPECS)
        return;
    od_spec *s = &o->specs[o->nspecs++];
    s->kind  = kind;
    s->base  = base;
    s->bytes = bytes;
    s->field = od_spec_field (kind, base, bytes);
}

static void
od_print_addr (long long off, char rad)
{
    switch (rad) {
        case 'x': printf ("%06llx", off); break;
        case 'd': printf ("%07lld", off); break;
        case 'n': return;
        case 'o':
        default:  printf ("%07llo", off); break;
    }
}

/* Render a single byte under the char-escape format ('-c'). */
static void
od_emit_c (unsigned char c)
{
    const char *e = NULL;
    switch (c) {
        case '\0': e = "\\0"; break;
        case '\a': e = "\\a"; break;
        case '\b': e = "\\b"; break;
        case '\t': e = "\\t"; break;
        case '\n': e = "\\n"; break;
        case '\v': e = "\\v"; break;
        case '\f': e = "\\f"; break;
        case '\r': e = "\\r"; break;
        case ' ' : e = "  "; break;
    }
    if (e)                printf ("  %s", e);
    else if (isprint (c)) printf ("   %c", c);
    else                  printf (" %03o", c);
}

/* Render a single byte under the named-char format ('-t a'). */
static void
od_emit_a (unsigned char c)
{
    c &= 0x7f;               /* GNU -t a strips the high bit */
    if (c < 0x20)            printf (" %s", od_ascii_names[c]);
    else if (c == 0x20)      printf ("  sp");
    else if (c == 0x7f)      printf (" del");
    else                     printf ("   %c", c);
}

/* Read a little-endian element of `bytes` width starting at buf[i]; bytes
   past `n` are treated as zero (GNU pads short trailing groups with NUL). */
static unsigned long long
od_read_le (const unsigned char *buf, size_t i, size_t n, int bytes)
{
    unsigned long long v = 0;
    for (int k = 0; k < bytes; k++) {
        unsigned long long b = (i + (size_t) k < n) ? buf[i + (size_t) k] : 0ull;
        v |= b << (8 * k);
    }
    return v;
}

static void
od_emit_int (unsigned long long v, char base, int bytes)
{
    switch (base) {
        case 'x':
            if (bytes == 1)      printf (" %02x", (unsigned) (v & 0xffULL));
            else if (bytes == 2) printf (" %04x", (unsigned) (v & 0xffffULL));
            else if (bytes == 4) printf (" %08llx", v & 0xffffffffULL);
            else                 printf (" %016llx", v);
            break;
        case 'o':
            if (bytes == 1)      printf (" %03o", (unsigned) (v & 0xffULL));
            else if (bytes == 2) printf (" %06o", (unsigned) (v & 0xffffULL));
            else if (bytes == 4) printf (" %011llo", v & 0xffffffffULL);
            else                 printf (" %022llo", v);
            break;
        case 'd': {
            long long sv;
            if (bytes == 1)      sv = (long long) (signed char) (v & 0xffULL);
            else if (bytes == 2) sv = (long long) (short) (v & 0xffffULL);
            else if (bytes == 4) sv = (long long) (int) (unsigned int) (v & 0xffffffffULL);
            else                 sv = (long long) v;
            if (bytes == 1)      printf (" %4lld", sv);
            else if (bytes == 2) printf (" %6lld", sv);
            else if (bytes == 4) printf (" %11lld", sv);
            else                 printf (" %20lld", sv);
            break;
        }
        case 'u':
        default:
            if (bytes == 1)      printf (" %3llu", v & 0xffULL);
            else if (bytes == 2) printf (" %5llu", v & 0xffffULL);
            else if (bytes == 4) printf (" %10llu", v & 0xffffffffULL);
            else                 printf (" %20llu", v);
            break;
    }
}

/* Render a float (bytes==4) or double (bytes==8) element. GNU emits the
   shortest decimal that round-trips (minimal %.*g precision), right-justified
   in a fixed column: 15 chars for f4, 24 chars for f8 (the leading separator
   space brings totals to 16 / 25). */
static void
od_emit_float (unsigned long long bits, int bytes)
{
    char buf[384];           /* %g of a double is at most ~310 chars */
    int width = (bytes == 4) ? 15 : 24;
    int maxprec = (bytes == 4) ? 9 : 17;
    double val;

    if (bytes == 4) {
        union { unsigned int u; float f; } cv;
        cv.u = (unsigned int) (bits & 0xffffffffULL);
        val = (double) cv.f;
    } else {
        union { unsigned long long u; double d; } cv;
        cv.u = bits;
        val = cv.d;
    }

    /* Shortest round-tripping representation. */
    int prec;
    for (prec = 1; prec < maxprec; prec++) {
        snprintf (buf, sizeof buf, "%.*g", prec, val);
        if (bytes == 4) {
            if ((float) strtod (buf, NULL) == (float) val) break;
        } else {
            if (strtod (buf, NULL) == val) break;
        }
    }
    printf (" %*.*g", width, prec, val);
}

/* Print one spec's line for `n` bytes of `buf`, padding each `groupbytes`-byte
   group on the left so columns align across stacked types (GNU layout). */
static void
od_emit_spec_line (const od_spec *s, const unsigned char *buf, size_t n,
                   int width, int groupbytes, int gwidth)
{
    /* Each group of `groupbytes` bytes is a column of total width `gwidth`,
       shared by this spec's `elems_per_group` elements. GNU divides the
       column evenly; any remainder is added to the FIRST element's field. */
    int elems_per_group = groupbytes / s->bytes;
    int base_field = gwidth / elems_per_group;
    int extra = gwidth - base_field * elems_per_group;   /* goes on first elem */
    for (int g = 0; g < width; g += groupbytes) {
        if ((size_t) g >= n) break;                  /* no data left */
        int e = 0;
        for (size_t i = (size_t) g;
             i < (size_t) (g + groupbytes) && i < n;
             i += (size_t) s->bytes, e++) {
            int target = base_field + (e == 0 ? extra : 0);
            int pad = target - s->field;             /* left-pad to align */
            for (int p = 0; p < pad; p++) putchar (' ');
            if (s->kind == 'c')      od_emit_c (buf[i]);
            else if (s->kind == 'a') od_emit_a (buf[i]);
            else if (s->kind == 'f') od_emit_float (od_read_le (buf, i, n, s->bytes), s->bytes);
            else od_emit_int (od_read_le (buf, i, n, s->bytes), s->base, s->bytes);
        }
    }
    putchar ('\n');
}

static int
od_dump (FILE *f, od_opts *o, int *seen_block, unsigned char *prev,
         size_t *prev_n, int *dedup_active)
{
    /* Largest element width and the aligned group width across all specs. */
    int groupbytes = 1;
    for (int k = 0; k < o->nspecs; k++)
        if (o->specs[k].bytes > groupbytes) groupbytes = o->specs[k].bytes;
    int gwidth = 0;
    for (int k = 0; k < o->nspecs; k++) {
        int gw = (groupbytes / o->specs[k].bytes) * o->specs[k].field;
        if (gw > gwidth) gwidth = gw;
    }

    /* GNU requires the line width to be a multiple of the largest element
       size; round down (min one group) so columns stay aligned. */
    int width = o->width - (o->width % groupbytes);
    if (width < groupbytes) width = groupbytes;
    unsigned char *buf = (unsigned char *) malloc ((size_t) width);
    if (!buf) { builtin_error ("out of memory"); return EXECUTION_FAILURE; }

    long long off = o->skip_bytes;
    long long emitted = 0;
    size_t n;
    while (1) {
        size_t want = (size_t) width;
        if (o->max_bytes >= 0) {
            long long remaining = o->max_bytes - emitted;
            if (remaining <= 0) break;
            if ((long long) want > remaining) want = (size_t) remaining;
        }
        n = fread (buf, 1, want, f);
        if (n == 0) break;

        /* '*' dedup: only full-width lines that match the previous full-width
           line collapse; partial trailing lines never dedup. */
        if (!o->no_dedup && *seen_block && *prev_n == (size_t) width
            && n == (size_t) width && memcmp (buf, prev, n) == 0) {
            if (!*dedup_active) { printf ("*\n"); *dedup_active = 1; }
            off += (long long) n;
            emitted += (long long) n;
            continue;
        }
        *dedup_active = 0;

        for (int k = 0; k < o->nspecs; k++) {
            if (k == 0) od_print_addr (off, o->addr_radix);
            else if (o->addr_radix != 'n') {
                int aw = (o->addr_radix == 'x') ? 6 : 7;
                for (int p = 0; p < aw; p++) putchar (' ');
            }
            od_emit_spec_line (&o->specs[k], buf, n, width, groupbytes, gwidth);
        }

        memcpy (prev, buf, n);
        *prev_n = n;
        *seen_block = 1;
        off += (long long) n;
        emitted += (long long) n;
    }

    free (buf);
    /* Trailing address. */
    if (o->addr_radix != 'n') {
        od_print_addr (off, o->addr_radix);
        putchar ('\n');
    }
    return EXECUTION_SUCCESS;
}

static int
od_strings (FILE *f, int min)
{
    /* Print each contiguous run of printable bytes (including space)
       of length >= min, NUL-terminated. */
    unsigned char buf[8192];
    size_t n;
    int run = 0;
    char run_buf[4096];
    long long off = 0, run_start = 0;
    while ((n = fread (buf, 1, sizeof buf, f)) > 0) {
        for (size_t i = 0; i < n; i++) {
            unsigned char c = buf[i];
            int p = (c >= 0x20 && c < 0x7f) || c == '\t';
            if (p) {
                if (run == 0) run_start = off + (long long) i;
                if (run < (int) sizeof run_buf - 1) run_buf[run++] = (char) c;
            } else {
                if (run >= min) {
                    run_buf[run] = '\0';
                    printf ("%07llo %s\n", run_start, run_buf);
                }
                run = 0;
            }
        }
        off += (long long) n;
    }
    if (run >= min) {
        run_buf[run] = '\0';
        printf ("%07llo %s\n", run_start, run_buf);
    }
    return EXECUTION_SUCCESS;
}

/* GNU `od -S N` / `--strings[=N]`: print each NUL-terminated run of >= N
   ASCII-graphic bytes (0x20..0x7e only; tab/newline/high-bit break the run
   and a run NOT terminated by NUL is discarded). The offset of the run's
   first byte is printed in the address radix (suppressed when 'n'). */
static int
od_strings_gnu (FILE *f, int min, char rad)
{
    unsigned char buf[8192];
    size_t n;
    int run = 0;
    static char run_buf[1 << 20];    /* GNU has no fixed cap; this is generous */
    long long off = 0, run_start = 0;

    while ((n = fread (buf, 1, sizeof buf, f)) > 0) {
        for (size_t i = 0; i < n; i++) {
            unsigned char c = buf[i];
            if (c >= 0x20 && c <= 0x7e) {           /* ASCII graphic + space */
                if (run == 0) run_start = off + (long long) i;
                if (run < (int) sizeof run_buf - 1) run_buf[run++] = (char) c;
            } else {
                if (c == '\0' && run >= min) {       /* only NUL closes a string */
                    run_buf[run] = '\0';
                    if (rad == 'n') printf ("%s\n", run_buf);
                    else {
                        od_print_addr (run_start, rad);
                        printf (" %s\n", run_buf);
                    }
                }
                run = 0;                             /* any non-graphic resets */
            }
        }
        off += (long long) n;
    }
    /* A run ending at EOF (no NUL terminator) is intentionally discarded. */
    return EXECUTION_SUCCESS;
}

static int
od_skip_input (FILE *f, long long n)
{
    unsigned char discard[4096];

    if (n <= 0)
        return 0;

    if (fseeko (f, (off_t)n, SEEK_SET) == 0)
        return 0;

    if (ferror (f))
        clearerr (f);

    while (n > 0) {
        size_t want = sizeof discard;
        size_t got;

        if ((long long)want > n)
            want = (size_t)n;
        got = fread (discard, 1, want, f);
        if (got == 0)
            return -1;
        n -= (long long)got;
    }
    return 0;
}

/* Map a named-size letter (C/S/I/L) to a byte width for int types.
   Returns 0 if the char is not a size letter. */
static int
od_size_letter (char c)
{
    switch (c) {
        case 'C': return 1;   /* char  */
        case 'S': return 2;   /* short */
        case 'I': return 4;   /* int   */
        case 'L': return 8;   /* long  */
        default:  return 0;
    }
}

/* Parse a -t TYPE token. Accepts: c, a, {d,o,u,x} with optional width
   1/2/4/8 or named-size letter C/S/I/L (default 4), and f with width
   4/8 or named-size F(4)/D(8) (default 8). Multiple specs may be packed
   into one token (e.g. "x1z"). Returns 0 on success. */
static int
od_parse_type (const char *type, od_opts *o)
{
    if (!strcmp (type, "c")) { od_add_spec (o, 'c', 0, 1); return 0; }
    if (!strcmp (type, "a")) { od_add_spec (o, 'a', 0, 1); return 0; }

    const char *p = type;
    while (*p) {
        char base = *p++;
        int bytes;
        if (base == 'f') {
            /* float: width 4/8 or named-size F(4)/D(8), default 8 (double). */
            if (*p == '4')      { bytes = 4; p++; }
            else if (*p == '8') { bytes = 8; p++; }
            else if (*p == 'F') { bytes = 4; p++; }
            else if (*p == 'D') { bytes = 8; p++; }
            else                  bytes = 8;   /* GNU default for f */
            od_add_spec (o, 'f', 0, bytes);
            continue;
        }
        if (base != 'x' && base != 'o' && base != 'd' && base != 'u') {
            builtin_error ("-t: unsupported TYPE '%s'", type);
            return -1;
        }
        int sl;
        if (*p == '1')               { bytes = 1; p++; }
        else if (*p == '2')          { bytes = 2; p++; }
        else if (*p == '4')          { bytes = 4; p++; }
        else if (*p == '8')          { bytes = 8; p++; }
        else if ((sl = od_size_letter (*p))) { bytes = sl; p++; }
        else                           bytes = 4;   /* GNU default width for int types */
        od_add_spec (o, 'i', base, bytes);
    }
    return 0;
}

extern char *od_doc[];

static int
od_parse_nonnegative_ll (const char *s, const char *what, long long *out)
{
    char *end = NULL;
    long long n;

    if (s == NULL || *s == '\0') {
        builtin_error ("%s needs N", what);
        builtin_usage ();
        return -1;
    }
    errno = 0;
    n = strtoll (s, &end, 0);
    if (errno || end == s || *end || n < 0) {
        builtin_error ("%s: N must be a non-negative integer (got '%s')", what, s);
        builtin_usage ();
        return -1;
    }
    *out = n;
    return 0;
}

/* Own stdin's stdio state for this invocation. Bash's persistent stdin FILE
   keeps EOF across redirections. Repeated '-' operands share this stream.
   Never fclose stdin. */
static FILE *
od_open_stdin (void)
{
    int fd = dup (STDIN_FILENO);
    FILE *in = fd < 0 ? NULL : fdopen (fd, "rb");
    if (!in) {
        int error = errno;
        if (fd >= 0) close (fd);
        builtin_error ("stdin: %s", strerror (error));
    }
    return in;
}

int
od_builtin (WORD_LIST *list)
{
    od_opts o = { .addr_radix = 'o', .nspecs = 0, .width = OD_DEFAULT_WIDTH,
                  .no_dedup = 0, .strings_min = 0, .gnu_strings_min = 0,
                  .skip_bytes = 0, .max_bytes = -1 };
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help") || !strcmp (w, "-h")) {
            for (char **dp = od_doc; *dp; dp++) puts (*dp);
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-v") || !strcmp (w, "--output-duplicates")) {
            o.no_dedup = 1;
            list = list->next;
            continue;
        }
        /* -w[WIDTH] / --width[=WIDTH]: bytes per output line (default 16). */
        if (!strcmp (w, "-w") || (!strncmp (w, "-w", 2) && w[2] != '\0')
            || !strncmp (w, "--width", 7)) {
            const char *nv = NULL;
            if (!strncmp (w, "--width", 7)) {
                nv = (w[7] == '=') ? w + 8 : NULL;   /* bare --width => default 32 */
                if (nv == NULL) { o.width = 32; list = list->next; continue; }
            } else if (w[2] != '\0') {
                nv = w + 2;
            } else {
                /* bare -w => 32 (GNU default when no width given). */
                o.width = 32;
                list = list->next;
                continue;
            }
            long long n;
            if (od_parse_nonnegative_ll (nv, "-w", &n) < 0) return EX_USAGE;
            o.width = (n < 1) ? OD_DEFAULT_WIDTH : (int) n;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-A") || (!strncmp (w, "-A", 2) && w[2] != '\0')) {
            const char *rv = NULL;
            if (w[2] != '\0') {
                rv = w + 2;
            } else {
                if (!list->next) { builtin_error ("-A needs RADIX"); builtin_usage (); return EX_USAGE; }
                list = list->next;
                rv = list->word->word;
            }
            char r = rv[0];
            if (rv[1] != '\0') {
                builtin_error ("-A: radix must be a single x/o/d/n");
                builtin_usage ();
                return EX_USAGE;
            }
            if (r != 'x' && r != 'o' && r != 'd' && r != 'n') {
                builtin_error ("-A: radix must be x/o/d/n");
                builtin_usage ();
                return EX_USAGE;
            }
            o.addr_radix = r;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-t") || (!strncmp (w, "-t", 2) && w[2] != '\0')) {
            const char *type = NULL;
            if (w[2] != '\0') {
                type = w + 2;
            } else {
                if (!list->next) { builtin_error ("-t needs TYPE"); builtin_usage (); return EX_USAGE; }
                list = list->next;
                type = list->word->word;
            }
            if (od_parse_type (type, &o) < 0) { builtin_usage (); return EX_USAGE; }
            list = list->next;
            continue;
        }
        /* -j N  — skip N bytes before dumping. GNU od also accepts -jN. */
        if (!strcmp (w, "-j") || (!strncmp (w, "-j", 2) && w[2] != '\0')) {
            const char *nv = NULL;
            if (w[2] != '\0') {
                nv = w + 2;
            } else {
                if (!list->next) { builtin_error ("-j needs BYTES"); builtin_usage (); return EX_USAGE; }
                list = list->next;
                nv = list->word->word;
            }
            long long n;
            if (od_parse_nonnegative_ll (nv, "-j", &n) < 0) return EX_USAGE;
            o.skip_bytes = n;
            list = list->next;
            continue;
        }
        /* -S N / -SN / --strings[=N]: GNU NUL-terminated string extraction.
           GNU requires an argument for -S; --strings defaults to 3. */
        if (!strcmp (w, "-S") || (!strncmp (w, "-S", 2) && w[2] != '\0')
            || !strncmp (w, "--strings", 9)) {
            const char *nv = NULL;
            if (!strncmp (w, "--strings", 9)) {
                nv = (w[9] == '=') ? w + 10 : NULL;
                if (nv == NULL) { o.gnu_strings_min = 3; list = list->next; continue; }
            } else if (w[2] != '\0') {
                nv = w + 2;
            } else {
                if (!list->next) {
                    builtin_error ("option requires an argument -- 'S'");
                    builtin_usage ();
                    return EX_USAGE;
                }
                list = list->next;
                nv = list->word->word;
            }
            long long n;
            if (od_parse_nonnegative_ll (nv, "-S", &n) < 0) return EX_USAGE;
            o.gnu_strings_min = (n < 1) ? 3 : (int) n;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-s")) {
            o.strings_min = 3;
            list = list->next;
            /* Optional N argument (numeric only). */
            if (list && list->word->word[0] >= '0' && list->word->word[0] <= '9') {
                o.strings_min = atoi (list->word->word);
                if (o.strings_min < 1) o.strings_min = 3;
                list = list->next;
            }
            continue;
        }
        /* -N N  — process at most N bytes from input(s) before stopping.
           Accept either `-N 4` (space-separated) or `-N4` (joined).
           POSIX-compat: GNU od / BSD od both accept this form. */
        if (!strcmp (w, "-N") || (!strncmp (w, "-N", 2) && w[2] != '\0')) {
            const char *nv = NULL;
            if (w[2] != '\0') {
                nv = w + 2;
            } else {
                if (!list->next) { builtin_error ("-N needs BYTE_COUNT"); builtin_usage (); return EX_USAGE; }
                list = list->next;
                nv = list->word->word;
            }
            long long n;
            if (od_parse_nonnegative_ll (nv, "-N", &n) < 0) return EX_USAGE;
            o.max_bytes = n;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-s", 2) && w[2] >= '0' && w[2] <= '9') {
            o.strings_min = atoi (w + 2);
            if (o.strings_min < 1) o.strings_min = 3;
            list = list->next;
            continue;
        }
        for (const char *c = w + 1; *c; c++) {
            switch (*c) {
                case 'c': od_add_spec (&o, 'c', 0, 1);   break;
                case 'a': od_add_spec (&o, 'a', 0, 1);   break;
                case 'b': od_add_spec (&o, 'i', 'o', 1); break; /* legacy: o1 */
                case 'x': od_add_spec (&o, 'i', 'x', 2); break;
                case 'o': od_add_spec (&o, 'i', 'o', 2); break;
                case 'd': od_add_spec (&o, 'i', 'u', 2); break; /* legacy -d is UNSIGNED 2-byte */
                default:
                    builtin_error ("unknown flag: -%c", *c);
                    builtin_usage ();
                    return EX_USAGE;
            }
        }
        list = list->next;
    }
    /* If no display flag set and not in either strings mode, default to -t o2. */
    if (!o.strings_min && !o.gnu_strings_min && o.nspecs == 0)
        od_add_spec (&o, 'i', 'o', 2);

    int rc = EXECUTION_SUCCESS;
    FILE *input = NULL;
    if (!list) {
        input = od_open_stdin ();
        if (!input)
            return EXECUTION_FAILURE;
        if (od_skip_input (input, o.skip_bytes) < 0) {
            builtin_error ("stdin: cannot skip %lld bytes", o.skip_bytes);
            rc = EXECUTION_FAILURE;
        } else if (o.gnu_strings_min) rc = od_strings_gnu (input, o.gnu_strings_min, o.addr_radix);
        else if (o.strings_min) rc = od_strings (input, o.strings_min);
        else {
            int seen = 0, dactive = 0; size_t pn = 0;
            unsigned char *prev = (unsigned char *) malloc ((size_t) o.width);
            if (!prev) {
                builtin_error ("out of memory");
                fclose (input);
                return EXECUTION_FAILURE;
            }
            rc = od_dump (input, &o, &seen, prev, &pn, &dactive);
            free (prev);
        }
        fclose (input);
    } else {
        for (WORD_LIST *p = list; p; p = p->next) {
            FILE *f;
            if (!strcmp (p->word->word, "-")) {
                if (!input) input = od_open_stdin ();
                f = input;
            } else
                f = fopen (p->word->word, "rb");
            if (!f) {
                builtin_error ("%s: %s", p->word->word, strerror (errno));
                rc = EXECUTION_FAILURE;
                continue;
            }
            if (od_skip_input (f, o.skip_bytes) < 0) {
                builtin_error ("%s: cannot skip %lld bytes", p->word->word, o.skip_bytes);
                rc = EXECUTION_FAILURE;
            } else if (o.gnu_strings_min) od_strings_gnu (f, o.gnu_strings_min, o.addr_radix);
            else if (o.strings_min) od_strings (f, o.strings_min);
            else {
                int seen = 0, dactive = 0; size_t pn = 0;
                unsigned char *prev = (unsigned char *) malloc ((size_t) o.width);
                if (prev) {
                    od_dump (f, &o, &seen, prev, &pn, &dactive);
                    free (prev);
                } else {
                    builtin_error ("out of memory");
                    rc = EXECUTION_FAILURE;
                }
            }
            if (f != input) fclose (f);
        }
        if (input) fclose (input);
    }
    return rc;
}

char *od_doc[] = {
    "Octal / hex / decimal / char dump (POSIX od).",
    "",
    "    bashod [-A x|o|d|n] [-j BYTES] [-N BYTES] [-t TYPE] [-w[WIDTH]] [-v]",
    "           [-c] [-x] [-o] [-d] [-b] [-s [N]] [FILE...]",
    "",
    "    -A RADIX   address radix: x (hex), o (octal, default), d (decimal),",
    "               n (suppress address field)",
    "    -c         show bytes as chars (escapes for control + space)",
    "    -b         1-byte octal (legacy, == -t o1)",
    "    -j BYTES   skip BYTES input bytes before dumping",
    "    -x         16-bit hex words (LE)",
    "    -t TYPE    a, c, [doux] with width 1/2/4/8 or size C/S/I/L (e.g. x4,",
    "               dL), or f with width 4/8 or size F/D (IEEE float/double)",
    "    -w[WIDTH]  bytes per output line (default 16; bare -w => 32)",
    "    -v         do not collapse runs of identical lines into a single '*'",
    "    -N BYTES   stop after BYTES bytes of input (POSIX -N)",
    "    -o         16-bit octal words (default)",
    "    -d         16-bit decimal words",
    "    -s [N]     print printable-byte runs of length >= N (default 3)",
    "    -S N       print NUL-terminated graphic runs >= N (GNU --strings)",
    "",
    "Reads stdin when no FILE given (or `-` in the list). Combinable",
    "modes (`-cx`, `-t o2 -t x2`) print each on stacked lines under the",
    "same address, with per-type columns aligned GNU-style.",
    (char *)NULL
};

struct builtin bashod_struct = {
    "bashod",
    od_builtin,
    BUILTIN_ENABLED,
    od_doc,
    "bashod [-A x|o|d|n] [-j BYTES] [-t TYPE] [-N BYTES] [-w[WIDTH]] [-v] [-c] [-x] [-o] [-d] [-b] [-s [N]] [-S N] [FILE...]",
    0
};
