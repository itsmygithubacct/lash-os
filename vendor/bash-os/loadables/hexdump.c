/* SPDX-License-Identifier: MIT */
/* hexdump.c — hexdump(1) compatible builtin focused on -C canonical.
 *
 * Cmd surfaces (Round 1778961001 / Doc 56, ML-T2-09):
 *
 *   hexdump [-C] [-e FORMAT] [-n LIMIT] [-s OFFSET] [FILE...]
 *
 *   -C              canonical (hex + ASCII): one 16-byte row with
 *                   8-byte split, trailing `|ASCII|` gutter. Final
 *                   offset line uses 8 hex digits.
 *   -n LIMIT        stop after LIMIT bytes (decimal; 0x.. hex; 0... octal)
 *   -s OFFSET       skip OFFSET bytes before formatting (same numeric form)
 *
 *   No flags: default = util-linux's bare `hexdump` format — sixteen
 *   bytes per row formatted as eight 16-bit little-endian hex words,
 *   addresses in 7-hex-digit, no ASCII gutter.
 *
 * `-e FORMAT` supports the common hexdump format-unit subset:
 * quoted printf-style strings, optional ITER/BYTES prefixes, integer
 * conversions over little-endian byte groups, `%%`, `%_p`, `%_c`,
 * and `%_a`/`%_A` address pseudo-conversions.  It intentionally does
 * not attempt the full util-linux color/file format language.
 *
 * Reads stdin when no FILE given (or `-` as FILE name). Multiple FILEs
 * concatenate logically — `-s` and `-n` apply across the combined stream
 * (matching util-linux semantics).
 *
 * Counterparts:
 *   research/refs/util-linux/text-utils/hexdump.c — canonical
 *   research/refs/busybox/util-linux/hexdump.c    — tiny variant
 *
 * Output goal: byte-for-byte parity with util-linux hexdump -C on
 * fixture-sized inputs (smoke fixture lives in
 * tests/bash-os/335-hexdump.sh).
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

#include "loadables.h"

#define HD_LINE 16   /* 16 bytes per output line — fixed for both formats */

typedef struct {
    int canonical;          /* -C flag */
    char *format;           /* -e FORMAT; NULL = built-in default/-C modes */
    long long limit;        /* -1 = unlimited; >=0 = stop after N bytes */
    long long skip;         /* 0 = none; >0 = skip N bytes before formatting */
    int verbose;            /* -v: print every row; 0 = fold runs with '*' */
    int shortcut;           /* set by -b/-c/-d/-o/-x; triggers util-linux's
                               special final-offset line at EOF. Bare -e
                               does not, even if it includes %_ax. */
} hd_opts;

typedef struct {
    int iter;
    int bytes;
    int consumes;
    char *fmt;
} hd_fmt_unit;

typedef struct {
    hd_fmt_unit *v;
    size_t n, cap;
} hd_fmt_prog;

typedef struct {
    unsigned char *data;
    size_t len, cap;
} hd_buf;

/* Parse a numeric argument the way hexdump does: decimal default,
   `0x.../0X...` for hex, `0...` for octal. Rejects empty/non-numeric.
   `*out` is set on success; -1 returned on parse failure. */
static int
hd_parse_count (const char *s, long long *out, const char *what)
{
    if (!s || !*s) { builtin_error ("%s: numeric value required", what); return -1; }
    errno = 0;
    char *end = NULL;
    long long v = strtoll (s, &end, 0);
    if (errno != 0 || !end || *end != '\0' || end == s) {
        builtin_error ("%s: must be a number (got '%s')", what, s);
        return -1;
    }
    if (v < 0) {
        builtin_error ("%s: must be non-negative (got %lld)", what, v);
        return -1;
    }
    *out = v;
    return 0;
}

/* Write a canonical row (-C format):
   00000000  48 65 6c 6c 6f 20 57 6f  72 6c 64 0a              |Hello World.|
   The 8/8 byte split is at byte 8 with a single extra space. Trailing
   short rows are padded with `   ` (three spaces per missing byte) so
   the gutter aligns. */
static void
hd_print_canonical_row (long long off, const unsigned char *buf, size_t n)
{
    printf ("%08llx ", off);
    for (size_t i = 0; i < HD_LINE; i++) {
        if (i == 8) putchar (' ');           /* extra split-gap */
        if (i < n) printf (" %02x", buf[i]);
        else       printf ("   ");
    }
    printf ("  |");
    for (size_t i = 0; i < n; i++) {
        unsigned char c = buf[i];
        putchar (isprint (c) ? c : '.');
    }
    printf ("|\n");
}

/* Default (no flag) format: 16 bytes per row as 8 little-endian 16-bit
   words, addresses 7 hex digits, no ASCII gutter. Short rows print only
   the complete-word part for the bytes that exist (util-linux behavior:
   trailing odd byte at end of file is rendered as a single 2-digit byte
   word, e.g. " 00xx" with no padding to the right). */
static void
hd_print_default_row (long long off, const unsigned char *buf, size_t n)
{
    printf ("%07llx", off);
    size_t words = 0;
    for (size_t i = 0; i < n; i += 2) {
        if (i + 1 < n) {
            unsigned w = (unsigned) buf[i] | ((unsigned) buf[i + 1] << 8);
            printf (" %04x", w);
        } else {
            /* trailing single byte at EOF — emit as low byte only.
               util-linux renders this as " %04x" treating the absent
               high byte as 0. */
            unsigned w = (unsigned) buf[i];
            printf (" %04x", w);
        }
        words++;
    }
    /* Pad partial rows out to the full 8-word width with trailing spaces
       (util-linux uses 5 chars per word position: space + 4 hex digits). */
    for (size_t i = words; i < 8; i++)
        printf ("     ");
    putchar ('\n');
}

static void
hd_buf_free (hd_buf *b)
{
    free (b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

static int
hd_buf_append (hd_buf *b, const unsigned char *p, size_t n)
{
    if (n == 0) return 0;
    if (b->len > SIZE_MAX - n) return -1;
    size_t need = b->len + n;
    if (need > b->cap) {
        size_t nc = b->cap ? b->cap : 4096;
        while (nc < need) {
            if (nc > SIZE_MAX / 2) { nc = need; break; }
            nc *= 2;
        }
        unsigned char *nv = realloc (b->data, nc);
        if (!nv) return -1;
        b->data = nv;
        b->cap = nc;
    }
    memcpy (b->data + b->len, p, n);
    b->len += n;
    return 0;
}

static void
hd_fmt_free (hd_fmt_prog *p)
{
    for (size_t i = 0; i < p->n; i++)
        free (p->v[i].fmt);
    free (p->v);
    p->v = NULL;
    p->n = p->cap = 0;
}

static int
hd_fmt_push (hd_fmt_prog *p, hd_fmt_unit *u)
{
    if (p->n == p->cap) {
        size_t nc = p->cap ? p->cap * 2 : 8;
        hd_fmt_unit *nv = realloc (p->v, nc * sizeof (*nv));
        if (!nv) return -1;
        p->v = nv;
        p->cap = nc;
    }
    p->v[p->n++] = *u;
    return 0;
}

static int
hd_is_conv (int c)
{
    return c == 'd' || c == 'i' || c == 'u' || c == 'o' ||
           c == 'x' || c == 'X' || c == 'c';
}

static int
hd_fmt_consumes (const char *s)
{
    for (const char *p = s; *p; p++) {
        if (*p != '%') continue;
        p++;
        if (*p == '%') continue;
        while (*p && strchr ("#0-+ '0123456789.*hljztL", *p))
            p++;
        if (*p == '_' && (p[1] == 'a' || p[1] == 'A')) {
            if (p[2]) p += 2;
            continue;
        }
        if (*p == '_' && (p[1] == 'p' || p[1] == 'c'))
            return 1;
        if (hd_is_conv ((unsigned char)*p))
            return 1;
    }
    return 0;
}

static int
hd_fmt_default_bytes (const char *s)
{
    for (const char *p = s; *p; p++) {
        if (*p != '%') continue;
        p++;
        if (*p == '%') continue;
        while (*p && strchr ("#0-+ '0123456789.*", *p))
            p++;
        if (*p == '_' && (p[1] == 'p' || p[1] == 'c'))
            return 1;
        int long_seen = 0, short_seen = 0, char_seen = 0;
        while (*p && strchr ("hljztL", *p)) {
            if (*p == 'l' || *p == 'j' || *p == 'z' || *p == 't' || *p == 'L')
                long_seen++;
            if (*p == 'h') {
                if (p[1] == 'h') { char_seen = 1; p++; }
                else short_seen = 1;
            }
            p++;
        }
        if (*p == 'c') return 1;
        if (hd_is_conv ((unsigned char)*p)) {
            if (char_seen) return 1;
            if (short_seen) return 2;
            if (long_seen) return 8;
            return 2;
        }
    }
    return 1;
}

static char *
hd_parse_quoted (const char **sp)
{
    const char *s = *sp;
    if (*s != '"') return NULL;
    s++;
    size_t cap = strlen (s) + 1, n = 0;
    char *out = malloc (cap);
    if (!out) return NULL;
    while (*s && *s != '"') {
        unsigned char c = (unsigned char)*s++;
        if (c == '\\' && *s) {
            c = (unsigned char)*s++;
            switch (c) {
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'v': c = '\v'; break;
            case '\\': c = '\\'; break;
            case '"': c = '"'; break;
            case '0':
                c = 0;
                for (int oi = 0; oi < 2 && *s >= '0' && *s <= '7'; oi++)
                    c = (unsigned char)((c * 8) + (*s++ - '0'));
                break;
            default: break;
            }
        }
        out[n++] = (char)c;
    }
    if (*s != '"') {
        free (out);
        return NULL;
    }
    out[n] = '\0';
    *sp = s + 1;
    return out;
}

static int
hd_parse_format (const char *fmt, hd_fmt_prog *prog)
{
    const char *p = fmt;
    while (*p) {
        while (isspace ((unsigned char)*p)) p++;
        if (!*p) break;
        int iter = 1, bytes = 0;
        if (isdigit ((unsigned char)*p)) {
            char *end = NULL;
            long n = strtol (p, &end, 10);
            if (n <= 0 || n > INT_MAX) {
                builtin_error ("-e FORMAT: bad iteration count");
                return -1;
            }
            p = end;
            if (*p == '/') {
                iter = (int)n;
                p++;
                if (!isdigit ((unsigned char)*p)) {
                    builtin_error ("-e FORMAT: byte count required after /");
                    return -1;
                }
                long b = strtol (p, &end, 10);
                if (b <= 0 || b > 8) {
                    builtin_error ("-e FORMAT: byte count must be 1..8");
                    return -1;
                }
                bytes = (int)b;
                p = end;
            } else {
                builtin_error ("-e FORMAT: counts must use ITER/BYTES");
                return -1;
            }
            while (isspace ((unsigned char)*p)) p++;
        }
        char *q = hd_parse_quoted (&p);
        if (!q) {
            builtin_error ("-e FORMAT: expected quoted format unit");
            return -1;
        }
        hd_fmt_unit u;
        u.iter = iter;
        u.fmt = q;
        u.consumes = hd_fmt_consumes (q);
        u.bytes = bytes ? bytes : (u.consumes ? hd_fmt_default_bytes (q) : 0);
        if (u.consumes && u.bytes <= 0) u.bytes = 1;
        if (hd_fmt_push (prog, &u) < 0) {
            free (q);
            builtin_error ("-e FORMAT: out of memory");
            return -1;
        }
    }
    if (prog->n == 0) {
        builtin_error ("-e FORMAT: empty format");
        return -1;
    }
    return 0;
}

static unsigned long long
hd_get_le (const unsigned char *p, size_t avail, int bytes)
{
    unsigned long long v = 0;
    for (int i = 0; i < bytes && (size_t)i < avail; i++)
        v |= ((unsigned long long)p[i]) << (8 * i);
    return v;
}

static void
hd_print_addr (const char **pp, long long addr)
{
    const char *p = *pp;
    int zero = 0, width = 0, prec = -1;
    if (*p == '0') { zero = 1; p++; }
    while (isdigit ((unsigned char)*p)) {
        width = width * 10 + (*p - '0');
        p++;
    }
    /* Optional .PRECISION — used by util-linux's `%07.7_ax`/`%08.8_Ax`
       to pin the minimum hex-digit count. Without consuming it here,
       the parser drops out at the '.' and the rest ('.7_ax') ends up
       in the output literally. */
    if (*p == '.') {
        p++;
        prec = 0;
        while (isdigit ((unsigned char)*p)) { prec = prec * 10 + (*p - '0'); p++; }
    }
    if (*p == '_') p++;
    if (*p == 'a' || *p == 'A') p++;
    char base = *p ? *p++ : 'x';
    char spec[32];
    char conv = (base == 'o') ? 'o' : (base == 'd' ? 'u' : 'x');
    if (prec >= 0)
        snprintf (spec, sizeof spec, "%%%s%d.%dll%c", zero ? "0" : "", width, prec, conv);
    else
        snprintf (spec, sizeof spec, "%%%s%dll%c", zero ? "0" : "", width, conv);
    printf (spec, (unsigned long long)addr);
    *pp = p;
}

static void
hd_print_c_escape (unsigned char c)
{
    switch (c) {
    case '\0': fputs ("\\0", stdout); break;
    case '\a': fputs ("\\a", stdout); break;
    case '\b': fputs ("\\b", stdout); break;
    case '\t': fputs ("\\t", stdout); break;
    case '\n': fputs ("\\n", stdout); break;
    case '\v': fputs ("\\v", stdout); break;
    case '\f': fputs ("\\f", stdout); break;
    case '\r': fputs ("\\r", stdout); break;
    default:
        if (isprint (c)) putchar (c);
        else printf ("\\%03o", c);
        break;
    }
}

static void
hd_render_fmt (const char *fmt, const unsigned char *p, size_t avail,
               int bytes, long long addr, int final_pad, int strip_trailing_sp)
{
    unsigned long long v = hd_get_le (p, avail, bytes);
    /* util-linux drops ONE trailing space from the format string on
       the last iteration of an iterated consuming unit (iter > 1).
       e.g. `8/2 " %05u "` emits "...XXXXX " seven times, then
       "...XXXXX" (no trailing space) on the 8th. Standalone no-iter
       spaces and separate " " units are preserved. */
    const char *end = fmt + strlen (fmt);
    if (strip_trailing_sp && end > fmt && end[-1] == ' ') end--;
    for (const char *s = fmt; *s && s < end; ) {
        if (*s != '%') { putchar ((unsigned char)*s++); continue; }
        s++;
        if (*s == '%') { putchar ('%'); s++; continue; }
        if (*s == '_' && s[1] == 'p') {
            if (bytes > 0 && avail == 0) {
                putchar (' ');
                s += 2;
                continue;
            }
            unsigned char c = avail ? p[0] : 0;
            putchar (isprint (c) ? c : '.');
            s += 2;
            continue;
        }
        if (*s == '_' && s[1] == 'c') {
            if (bytes > 0 && avail == 0) {
                fputs ("  ", stdout);
                s += 2;
                continue;
            }
            hd_print_c_escape (avail ? p[0] : 0);
            s += 2;
            continue;
        }
        const char *start = s;
        while (*s && strchr ("#0-+ '0123456789.*", *s))
            s++;
        if (*s == '_' && (s[1] == 'a' || s[1] == 'A')) {
            s = start;
            hd_print_addr (&s, addr);
            continue;
        }
        /* Width-prefixed `%N_c` / `%N_p` — needed by util-linux's
           -c format (`%3_c`). Render the char/escape to a small
           buffer, then right-align to the width. */
        if (*s == '_' && (s[1] == 'c' || s[1] == 'p')) {
            int width = 0;
            for (const char *q = start; q < s && isdigit ((unsigned char) *q); q++)
                width = width * 10 + (*q - '0');
            char buf[8];
            int len;
            if (s[1] == 'p') {
                unsigned char c = avail ? p[0] : 0;
                if (bytes > 0 && avail == 0) { buf[0] = ' '; buf[1] = '\0'; len = 1; }
                else { buf[0] = isprint (c) ? c : '.'; buf[1] = '\0'; len = 1; }
            } else {
                unsigned char c = avail ? p[0] : 0;
                if (bytes > 0 && avail == 0) { buf[0] = '\0'; len = 0; }
                else switch (c) {
                case '\0': len = snprintf (buf, sizeof buf, "\\0");  break;
                case '\a': len = snprintf (buf, sizeof buf, "\\a");  break;
                case '\b': len = snprintf (buf, sizeof buf, "\\b");  break;
                case '\t': len = snprintf (buf, sizeof buf, "\\t");  break;
                case '\n': len = snprintf (buf, sizeof buf, "\\n");  break;
                case '\v': len = snprintf (buf, sizeof buf, "\\v");  break;
                case '\f': len = snprintf (buf, sizeof buf, "\\f");  break;
                case '\r': len = snprintf (buf, sizeof buf, "\\r");  break;
                default:
                    if (isprint (c)) { buf[0] = c; buf[1] = '\0'; len = 1; }
                    else             len = snprintf (buf, sizeof buf, "%03o", c);
                    break;
                }
            }
            if (width > len)
                for (int k = 0; k < width - len; k++) putchar (' ');
            fputs (buf, stdout);
            s += 2;
            continue;
        }
        const char *mod_start = s;
        while (*s && strchr ("hljztL", *s))
            s++;
        if (!hd_is_conv ((unsigned char)*s)) {
            putchar ('%');
            s = start;
            continue;
        }
        char conv = *s++;
        size_t prefix_len = (size_t)(mod_start - start);
        size_t flen = prefix_len + 5;
        char spec[64];
        if (flen > sizeof spec) flen = sizeof spec;
        spec[0] = '%';
        memcpy (spec + 1, start, prefix_len);
        if (conv == 'c')
        {
            spec[prefix_len + 1] = 'c';
            spec[prefix_len + 2] = '\0';
            if (bytes > 0 && avail == 0) {
                char tmp[128];
                int nn = snprintf (tmp, sizeof tmp, spec, 0);
                for (int i = 0; i < nn; i++) putchar (' ');
                if (final_pad && *s == ' ') s++;
            } else {
                printf (spec, (int)(v & 0xff));
            }
        }
        else {
            spec[prefix_len + 1] = 'l';
            spec[prefix_len + 2] = 'l';
            spec[prefix_len + 3] = conv;
            spec[prefix_len + 4] = '\0';
            if (bytes > 0 && avail == 0) {
                char tmp[128];
                int nn = snprintf (tmp, sizeof tmp, spec, v);
                for (int i = 0; i < nn; i++) putchar (' ');
                if (final_pad && *s == ' ') s++;
            } else {
                printf (spec, v);
            }
        }
    }
}

static void
hd_emit_custom (hd_fmt_prog *prog, const unsigned char *data, size_t len,
                long long base)
{
    size_t pos = 0;
    while (pos < len) {
        size_t before = pos;
        for (size_t ui = 0; ui < prog->n; ui++) {
            hd_fmt_unit *u = &prog->v[ui];
            if (!u->consumes) {
                hd_render_fmt (u->fmt, data + pos, pos < len ? len - pos : 0,
                               0, base + (long long)pos, 0, 0);
                continue;
            }
            for (int i = 0; i < u->iter; i++) {
                size_t avail = len - pos;
                int last_iter = (i == u->iter - 1);
                hd_render_fmt (u->fmt, data + pos, avail, u->bytes,
                               base + (long long)pos,
                               avail == 0 && last_iter,
                               /* strip 1 trailing space on last iter
                                  of an iter>1 unit (util-linux rule) */
                               (u->iter > 1 && last_iter));
                if (avail > 0)
                    pos += (avail < (size_t)u->bytes) ? avail : (size_t)u->bytes;
            }
        }
        if (pos == before)
            break;
    }
}

/* Drain stdin until @skip bytes have been read or EOF. Returns the
   number of bytes actually skipped (may be < skip on short input). */
static long long
hd_skip_bytes (FILE *f, long long skip)
{
    long long n = 0;
    unsigned char buf[4096];
    while (n < skip) {
        size_t chunk = (skip - n) > (long long) sizeof buf ? sizeof buf : (size_t) (skip - n);
        size_t got = fread (buf, 1, chunk, f);
        if (!got) break;
        n += (long long) got;
    }
    return n;
}

/* Stream a single FILE through the row-emitter. State is carried via
   *off, *rowbuf, *rowfill so multiple input files form one logical
   stream (matching util-linux's behavior under multiple FILE args).
   Returns 0 on clean read; -1 on ferror. */
static int
hd_emit_stream (FILE *f, hd_opts *o, long long *off,
                long long *remaining, unsigned char *rowbuf, size_t *rowfill,
                unsigned char *prev, int *have_prev, int *squeezing)
{
    int c;
    while ((c = fgetc (f)) != EOF) {
        if (*remaining == 0) return 0;
        rowbuf[(*rowfill)++] = (unsigned char) c;
        if (*remaining > 0) (*remaining)--;
        if (*rowfill == HD_LINE) {
            /* util-linux folds a run of identical full rows into a single
               '*' line (suppressed by -v). The offset still advances so the
               next distinct row prints at its true address. */
            if (!o->verbose && *have_prev && memcmp (rowbuf, prev, HD_LINE) == 0) {
                if (!*squeezing) { fputs ("*\n", stdout); *squeezing = 1; }
            } else {
                if (o->canonical) hd_print_canonical_row (*off, rowbuf, HD_LINE);
                else              hd_print_default_row   (*off, rowbuf, HD_LINE);
                *squeezing = 0;
            }
            memcpy (prev, rowbuf, HD_LINE);
            *have_prev = 1;
            *off += HD_LINE;
            *rowfill = 0;
            if (*remaining == 0) return 0;
        }
    }
    if (ferror (f)) return -1;
    return 0;
}

static int
hd_collect_stream (FILE *f, long long *remaining, hd_buf *out)
{
    unsigned char buf[4096];
    while (*remaining != 0) {
        size_t want = sizeof buf;
        if (*remaining > 0 && *remaining < (long long)want)
            want = (size_t)*remaining;
        size_t got = fread (buf, 1, want, f);
        if (!got) break;
        if (hd_buf_append (out, buf, got) < 0)
            return -2;
        if (*remaining > 0)
            *remaining -= (long long)got;
    }
    if (ferror (f)) return -1;
    return 0;
}

extern char *hexdump_doc[];

/* Own stdin's stdio state for this invocation. Bash's persistent stdin FILE
   keeps EOF across redirections. Repeated '-' operands share this stream.
   Never fclose stdin. */
static FILE *
hd_open_stdin (void)
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

static FILE *
hd_open (const char *path, FILE **input)
{
    if (path == NULL || (path[0] == '-' && path[1] == '\0')) {
        if (*input == NULL)
            *input = hd_open_stdin ();
        return *input;
    }
    FILE *f = fopen (path, "rb");
    if (!f)
        builtin_error ("%s: %s", path, strerror (errno));
    return f;
}

int
hexdump_builtin (WORD_LIST *list)
{
    hd_opts o = { .canonical = 0, .format = NULL, .limit = -1, .skip = 0, .verbose = 0 };

    /* Manual argv scan — we deliberately avoid getopt so behavior
       matches util-linux's hexdump tolerance of clustered shorts and
       `-Cn LIMIT` style. Stop on the first non-flag word or `--`. */
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "-h") || !strcmp (w, "--help")) {
            for (char **dp = hexdump_doc; *dp; dp++) puts (*dp);
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-C")) { o.canonical = 1; list = list->next; continue; }
        if (!strcmp (w, "-n") || (!strncmp (w, "-n", 2) && w[2] != '\0')) {
            const char *nv;
            if (w[2] != '\0') {
                nv = w + 2;
            } else {
                if (!list->next) { builtin_error ("-n needs LIMIT"); return EX_USAGE; }
                list = list->next;
                nv = list->word->word;
            }
            if (hd_parse_count (nv, &o.limit, "-n LIMIT") < 0) return EX_USAGE;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-s") || (!strncmp (w, "-s", 2) && w[2] != '\0')) {
            const char *sv;
            if (w[2] != '\0') {
                sv = w + 2;
            } else {
                if (!list->next) { builtin_error ("-s needs OFFSET"); return EX_USAGE; }
                list = list->next;
                sv = list->word->word;
            }
            if (hd_parse_count (sv, &o.skip, "-s OFFSET") < 0) return EX_USAGE;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-e") || (!strncmp (w, "-e", 2) && w[2] != '\0')) {
            if (w[2] != '\0') {
                o.format = (char *)w + 2;
            } else {
                if (!list->next) { builtin_error ("-e needs FORMAT"); return EX_USAGE; }
                list = list->next;
                o.format = list->word->word;
            }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-v")) {
            o.verbose = 1;   /* disable the '*' folding of duplicate rows */
            list = list->next;
            continue;
        }
        /* util-linux one-letter format shortcuts. Each sets o.format to
           the canonical string (the same strings util-linux uses); the
           trailing offset line at end-of-builtin already matches the
           %07.7_Ax format these expect. */
        if (!strcmp (w, "-b")) { o.format = "\"%07.7_ax \" 16/1 \"%03o \" \"\\n\"";   o.shortcut = 1; list = list->next; continue; }
        if (!strcmp (w, "-c")) { o.format = "\"%07.7_ax \" 16/1 \"%3_c \" \"\\n\"";   o.shortcut = 1; list = list->next; continue; }
        if (!strcmp (w, "-d")) { o.format = "\"%07.7_ax \" 8/2 \"  %05u \" \"\\n\"";  o.shortcut = 1; list = list->next; continue; }
        if (!strcmp (w, "-o")) { o.format = "\"%07.7_ax \" 8/2 \" %06o \" \"\\n\"";   o.shortcut = 1; list = list->next; continue; }
        if (!strcmp (w, "-x")) { o.format = "\"%07.7_ax \" 8/2 \"   %04x \" \"\\n\"";  o.shortcut = 1; list = list->next; continue; }
        builtin_error ("unknown flag: %s (try -C, -n, -s, --help)", w);
        builtin_usage ();
        return EX_USAGE;
    }

    if (o.format) {
        hd_fmt_prog prog = {0};
        if (hd_parse_format (o.format, &prog) < 0) {
            hd_fmt_free (&prog);
            return EX_USAGE;
        }

        long long remaining = o.limit;
        long long skip_remaining = o.skip;
        long long base = 0;
        hd_buf data = {0};
        int rc = EXECUTION_SUCCESS;
        FILE *input = NULL;

        if (!list) {
            FILE *f = hd_open (NULL, &input);
            if (!f)
                rc = EXECUTION_FAILURE;
            else {
                if (skip_remaining > 0) {
                    long long skipped = hd_skip_bytes (f, skip_remaining);
                    base += skipped;
                    skip_remaining -= skipped;
                }
                int cr = hd_collect_stream (f, &remaining, &data);
                if (cr == -2) { builtin_error ("out of memory"); rc = EXECUTION_FAILURE; }
                else if (cr < 0) { builtin_error ("stdin: read error: %s", strerror (errno)); rc = EXECUTION_FAILURE; }
            }
        } else {
            for (WORD_LIST *p = list; p; p = p->next) {
                if (remaining == 0) break;
                FILE *f = hd_open (p->word->word, &input);
                if (!f) {
                    rc = EXECUTION_FAILURE;
                    continue;
                }
                if (skip_remaining > 0) {
                    long long skipped = hd_skip_bytes (f, skip_remaining);
                    base += skipped;
                    skip_remaining -= skipped;
                }
                if (remaining != 0) {
                    int cr = hd_collect_stream (f, &remaining, &data);
                    if (cr == -2) { builtin_error ("out of memory"); rc = EXECUTION_FAILURE; }
                    else if (cr < 0) {
                        builtin_error ("%s: read error: %s", p->word->word, strerror (errno));
                        rc = EXECUTION_FAILURE;
                    }
                }
                if (f != input) fclose (f);
            }
        }
        if (input) fclose (input);

        if (rc == EXECUTION_SUCCESS) {
            hd_emit_custom (&prog, data.data, data.len, base);
            /* util-linux emits the final 7-hex-digit offset line at
               end-of-input only for its built-in shortcut formats
               (-b/-c/-d/-o/-x). A user-supplied `-e` program never
               gets it — even if the program literally contains %_ax. */
            if (o.shortcut)
                printf ("%07llx\n", (unsigned long long)(base + (long long)data.len));
        }
        hd_buf_free (&data);
        hd_fmt_free (&prog);
        return rc;
    }

    long long off = 0;
    long long remaining = o.limit;
    unsigned char rowbuf[HD_LINE];
    size_t rowfill = 0;
    unsigned char prev[HD_LINE];   /* last full row, for '*' run-folding */
    int have_prev = 0, squeezing = 0;
    int rc = EXECUTION_SUCCESS;

    /* `-s OFFSET` applies to the concatenation; skip from the first
       file's start and let any residual be applied to subsequent files.
       Matches util-linux for the common case of a single FILE; for
       multiple FILEs the kernel-side conventions differ but our
       semantic ("skip is byte-count into the logical stream") is the
       documented intent. */
    long long skip_remaining = o.skip;
    FILE *input = NULL;

    if (!list) {
        FILE *f = hd_open (NULL, &input);
        if (!f)
            rc = EXECUTION_FAILURE;
        else {
            if (skip_remaining > 0) {
                long long skipped = hd_skip_bytes (f, skip_remaining);
                off += skipped;
                skip_remaining -= skipped;
            }
            if (remaining != 0)
                (void) hd_emit_stream (f, &o, &off, &remaining, rowbuf, &rowfill,
                                       prev, &have_prev, &squeezing);
        }
    } else {
        for (WORD_LIST *p = list; p; p = p->next) {
            if (remaining == 0) break;
            FILE *f = hd_open (p->word->word, &input);
            if (!f) {
                rc = EXECUTION_FAILURE;
                continue;
            }
            if (skip_remaining > 0) {
                long long skipped = hd_skip_bytes (f, skip_remaining);
                off += skipped;
                skip_remaining -= skipped;
            }
            if (remaining != 0) {
                if (hd_emit_stream (f, &o, &off, &remaining, rowbuf, &rowfill,
                                    prev, &have_prev, &squeezing) < 0) {
                    builtin_error ("%s: read error: %s", p->word->word, strerror (errno));
                    rc = EXECUTION_FAILURE;
                }
            }
            if (f != input) fclose (f);
        }
    }
    if (input) fclose (input);

    /* Flush the partial trailing row (if any) and the final offset line. */
    if (rowfill > 0) {
        if (o.canonical) hd_print_canonical_row (off, rowbuf, rowfill);
        else             hd_print_default_row   (off, rowbuf, rowfill);
        off += (long long) rowfill;
        rowfill = 0;
    }
    /* Final EOF offset:
         -C       → 8 hex digits ("%08llx")
         default  → 7 hex digits ("%07llx") */
    if (o.canonical) printf ("%08llx\n", off);
    else             printf ("%07llx\n", off);

    return rc;
}

char *hexdump_doc[] = {
    "Byte-oriented hex dump (hexdump-compatible, focused on -C canonical).",
    "",
    "    hexdump [-C] [-e FORMAT] [-n LIMIT] [-s OFFSET] [FILE...]",
    "",
    "    -C         canonical 16-byte rows with 8/8 split + |ASCII| gutter",
    "               (matches util-linux `hexdump -C` byte-for-byte)",
    "    -e FORMAT  custom hexdump format unit subset (quoted printf strings,",
    "               optional ITER/BYTES prefixes, %_p/%_c, and %_a/%_A)",
    "    -n LIMIT   stop after LIMIT bytes (decimal; 0x.. hex; 0... octal)",
    "    -s OFFSET  skip OFFSET bytes before formatting",
    "",
    "Default format (no -C) emits eight 16-bit little-endian hex words per row,",
    "addresses in 7 hex digits, no ASCII gutter — matches util-linux's bare",
    "`hexdump FILE` output.",
    "",
    "Reads stdin when no FILE is given (or `-` in the FILE list). `-s` and `-n`",
    "apply to the concatenated logical stream when multiple FILEs are given.",
    "",
    "`-e FORMAT` covers common byte/word integer and printable-char formats;",
    "full util-linux color/file format parsing remains out of scope.",
    (char *)NULL
};

struct builtin hexdump_struct = {
    "hexdump",
    hexdump_builtin,
    BUILTIN_ENABLED,
    hexdump_doc,
    "hexdump [-C] [-e FORMAT] [-n LIMIT] [-s OFFSET] [FILE...]",
    0
};
