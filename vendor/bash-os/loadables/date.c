/* bashdate.c — POSIX date(1) as a bash builtin.
 *
 *   bashdate [-u] [-d STRING|--date=STRING] [-I[FMT]|--iso-8601[=FMT]]
 *            [--rfc-3339=FMT] [+FORMAT]
 *
 *   -u           use UTC (gmtime instead of localtime)
 *   -d STRING    parse STRING (ISO 8601 + a few common shapes) instead
 *   --date=STRING
 *                of the current time
 *   -I[FMT], --iso-8601[=FMT]
 *                GNU ISO-8601 output forms: date, hours, minutes, seconds.
 *   --rfc-3339=FMT
 *                GNU RFC 3339 output forms: date, seconds.
 *   +FORMAT      strftime(3) format plus GNU %N and %:z/%::z/%:::z forms.
 *                Default: %a %b %e %T %Z %Y
 *
 * Closes the POSIX-2024 medium-impact gap (POSIX-CONFORMANCE-RESEARCH
 * §4.1: bashclock has time underpinnings but no date(1) shape).
 *
 * The -d parser is deliberately narrow — accepts:
 *   YYYY-MM-DDTHH[:MM[:SS]][+HH:MM|-HHMM]
 *   YYYY-MM-DDTHH:MM[:SS]Z
 *                              (ISO 8601 with optional zone)
 *   YYYY-MM-DD HH[:MM[:SS]]   (separator space variant)
 *   [DAY[,]] D Mon YYYY HH:MM:SS UTC|GMT|+HHMM|-HH:MM
 *                              (bounded RFC/email timestamp subset)
 *   YYYY-MM-DD                (date-only; time = 00:00:00)
 *   @SECONDS                  (epoch seconds — useful for scripts)
 *   now                       (alias for current time)
 * Anything else returns EX_USAGE. For richer parsing use system+ date.
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
#include <time.h>

#include "loadables.h"

static int
bd_parse_tz_offset (const char *s, long *offset)
{
    int sign, hh, mm;

    if (s[0] != '+' && s[0] != '-')
        return -1;
    sign = s[0] == '+' ? 1 : -1;

    if (s[1] < '0' || s[1] > '9' || s[2] < '0' || s[2] > '9')
        return -1;

    hh = (s[1] - '0') * 10 + (s[2] - '0');
    if (s[3] == ':') {
        if (s[4] < '0' || s[4] > '9' || s[5] < '0' || s[5] > '9' || s[6] != '\0')
            return -1;
        mm = (s[4] - '0') * 10 + (s[5] - '0');
    } else {
        if (s[3] < '0' || s[3] > '9' || s[4] < '0' || s[4] > '9' || s[5] != '\0')
            return -1;
        mm = (s[3] - '0') * 10 + (s[4] - '0');
    }

    if (hh > 23 || mm > 59)
        return -1;
    *offset = sign * (long) (hh * 3600 + mm * 60);
    return 0;
}

static int
bd_ci3_eq (const char *s, const char *lit)
{
    for (int i = 0; i < 3; i++) {
        char a = s[i];
        char b = lit[i];
        if (a >= 'A' && a <= 'Z')
            a = (char) (a + 32);
        if (b >= 'A' && b <= 'Z')
            b = (char) (b + 32);
        if (a != b)
            return 0;
    }
    return 1;
}

static const char *
bd_skip_space (const char *p)
{
    while (*p == ' ' || *p == '\t')
        p++;
    return p;
}

static int
bd_parse_uint_width (const char **pp, int min_digits, int max_digits, int *out)
{
    const char *p = *pp;
    int n = 0;
    int v = 0;
    while (n < max_digits && *p >= '0' && *p <= '9') {
        v = v * 10 + (*p - '0');
        p++;
        n++;
    }
    if (n < min_digits)
        return -1;
    *pp = p;
    *out = v;
    return 0;
}

static int
bd_month_index (const char *p)
{
    static const char *months[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    for (int i = 0; i < 12; i++)
        if (bd_ci3_eq (p, months[i]))
            return i;
    return -1;
}

static int
bd_weekday_index (const char *p)
{
    static const char *days[] = {
        "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
    };
    for (int i = 0; i < 7; i++)
        if (bd_ci3_eq (p, days[i]))
            return i;
    return -1;
}

static int
bd_valid_tm_utc (struct tm *t)
{
    struct tm check;
    int year = t->tm_year;
    int mon = t->tm_mon;
    int mday = t->tm_mday;
    int hour = t->tm_hour;
    int min = t->tm_min;
    int sec = t->tm_sec;
    time_t tt = timegm (t);
    if (tt == (time_t) -1)
        return -1;
    if (!gmtime_r (&tt, &check))
        return -1;
    if (check.tm_year != year || check.tm_mon != mon ||
        check.tm_mday != mday || check.tm_hour != hour ||
        check.tm_min != min || check.tm_sec != sec)
        return -1;
    return 0;
}

static int
bd_parse_rfc_lenient (const char *s, time_t *out)
{
    const char *p = s;
    struct tm t;
    int day, month, year, hour, minute, second;
    long offset = 0;

    if (bd_weekday_index (p) >= 0) {
        p += 3;
        if (*p == ',')
            p++;
        if (*p != ' ' && *p != '\t')
            return -1;
        p = bd_skip_space (p);
    }

    if (bd_parse_uint_width (&p, 1, 2, &day) < 0)
        return -1;
    if (*p != ' ' && *p != '\t')
        return -1;
    p = bd_skip_space (p);

    month = bd_month_index (p);
    if (month < 0)
        return -1;
    p += 3;
    if (*p != ' ' && *p != '\t')
        return -1;
    p = bd_skip_space (p);

    if (bd_parse_uint_width (&p, 4, 4, &year) < 0)
        return -1;
    if (*p != ' ' && *p != '\t')
        return -1;
    p = bd_skip_space (p);

    if (bd_parse_uint_width (&p, 2, 2, &hour) < 0 || *p++ != ':' ||
        bd_parse_uint_width (&p, 2, 2, &minute) < 0 || *p++ != ':' ||
        bd_parse_uint_width (&p, 2, 2, &second) < 0)
        return -1;
    if (*p != ' ' && *p != '\t')
        return -1;
    p = bd_skip_space (p);

    if (!strcmp (p, "UTC") || !strcmp (p, "utc") ||
        !strcmp (p, "GMT") || !strcmp (p, "gmt")) {
        offset = 0;
    } else if (bd_parse_tz_offset (p, &offset) == 0) {
        ;
    } else {
        return -1;
    }

    memset (&t, 0, sizeof t);
    t.tm_year = year - 1900;
    t.tm_mon = month;
    t.tm_mday = day;
    t.tm_hour = hour;
    t.tm_min = minute;
    t.tm_sec = second;
    t.tm_isdst = -1;
    if (bd_valid_tm_utc (&t) < 0)
        return -1;
    *out = timegm (&t) - (time_t) offset;
    return *out == (time_t) -1 ? -1 : 0;
}

static int
bd_parse_d (const char *s, time_t *out, int utc)
{
    if (!strcmp (s, "now")) { *out = time (NULL); return 0; }
    if (s[0] == '@') {
        char *end;
        long long ll = strtoll (s + 1, &end, 10);
        if (end == s + 1) return -1;
        /* Accept a fractional tail "@SEC.frac" — GNU truncates toward the
           integer second for whole-second output. Require the tail to be a
           '.' followed by zero or more decimal digits and nothing else. */
        if (*end == '.') {
            const char *q = end + 1;
            while (*q >= '0' && *q <= '9') q++;
            if (*q != '\0') return -1;
        } else if (*end != '\0') {
            return -1;
        }
        *out = (time_t) ll;
        return 0;
    }
    if (bd_parse_rfc_lenient (s, out) == 0)
        return 0;
    struct tm t;
    memset (&t, 0, sizeof t);
    t.tm_isdst = -1;
    const char *fmts[] = {
        "%a, %d %b %Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%MZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H",
        "%Y-%m-%d %H",
        "%Y%m%d",
        "%Y-%m-%d",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d %H:%M",
        "%Y/%m/%d",
        NULL
    };
    const int fmt_zulu[] = { 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const int fmt_terminal_ok[] = { 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1 };
    for (int i = 0; fmts[i]; i++) {
        char *e = strptime (s, fmts[i], &t);
        if (e && fmt_terminal_ok[i] && (*e == '\0' || (*e == 'Z' && e[1] == '\0')
            || strcmp (e, " UTC") == 0)) {
            int zulu = (*e == 'Z') || strcmp (e, " UTC") == 0 || fmt_zulu[i];
            *out = (zulu || utc) ? timegm (&t) : mktime (&t);
            return *out == (time_t) -1 ? -1 : 0;
        }
        if (e && i < 9) {
            while (*e == ' ' || *e == '\t') e++;
        }
        if (e && i < 9 && (*e == '+' || *e == '-')) {
            long offset;
            if (bd_parse_tz_offset (e, &offset) == 0) {
                *out = timegm (&t) - (time_t) offset;
                return *out == (time_t) -1 ? -1 : 0;
            }
        }
        memset (&t, 0, sizeof t);
        t.tm_isdst = -1;
    }
    return -1;
}

static long
bd_tm_offset (const struct tm *tm, time_t t, int utc)
{
    struct tm copy;

    if (utc)
        return 0;
    copy = *tm;
    return (long) (timegm (&copy) - t);
}

static void
bd_format_offset (long offset, int colons, char *out, size_t outsz)
{
    char sign = '+';
    long hh, mm, ss;

    if (offset < 0) {
        sign = '-';
        offset = -offset;
    }
    hh = offset / 3600;
    mm = (offset / 60) % 60;
    ss = offset % 60;

    if (colons == 1)
        snprintf (out, outsz, "%c%02ld:%02ld", sign, hh, mm);
    else if (colons == 2)
        snprintf (out, outsz, "%c%02ld:%02ld:%02ld", sign, hh, mm, ss);
    else if (ss != 0)
        snprintf (out, outsz, "%c%02ld:%02ld:%02ld", sign, hh, mm, ss);
    else if (mm != 0)
        snprintf (out, outsz, "%c%02ld:%02ld", sign, hh, mm);
    else
        snprintf (out, outsz, "%c%02ld", sign, hh);
}

/* Append `n` bytes of `src` to a growable buffer (*out, *cap, *j). Returns
   0 on success, -1 on OOM (caller frees *out). Always leaves room for a
   trailing NUL. */
static int
bd_buf_append (char **out, size_t *cap, size_t *j, const char *src, size_t n)
{
    if (*j + n + 1 > *cap) {
        size_t ncap = *cap * 2 + n + 16;
        char *nb = realloc (*out, ncap);
        if (!nb)
            return -1;
        *out = nb;
        *cap = ncap;
    }
    memcpy (*out + *j, src, n);
    *j += n;
    return 0;
}

/* Append `src` with any '%' doubled to '%%' so a later strftime pass treats
   it as literal text. Rendered date text never contains '%' but we stay
   defensive. */
static int
bd_buf_append_literal (char **out, size_t *cap, size_t *j, const char *src)
{
    for (const char *p = src; *p; p++) {
        char c = *p;
        if (bd_buf_append (out, cap, j, &c, 1) < 0)
            return -1;
        if (c == '%' && bd_buf_append (out, cap, j, &c, 1) < 0)
            return -1;
    }
    return 0;
}

/* Render a single bare "%<spec>" (spec is one strftime conversion char) for
   the given tm into `dst`. */
static void
bd_strftime_one (char spec, const struct tm *tm, char *dst, size_t dstsz)
{
    char one_fmt[3] = { '%', spec, '\0' };
    if (strftime (dst, dstsz, one_fmt, tm) == 0)
        dst[0] = '\0';
}

static char *
bd_expand_gnu_tz_formats (const char *fmt, const struct tm *tm, time_t t, int utc)
{
    size_t len = strlen (fmt);
    size_t cap = len * 3 + 32;
    char *out = malloc (cap);
    size_t i, j = 0;
    long offset = bd_tm_offset (tm, t, utc);

    if (!out)
        return NULL;

    for (i = 0; i < len; i++) {
        if (fmt[i] != '%') {
            if (bd_buf_append (&out, &cap, &j, &fmt[i], 1) < 0) {
                free (out);
                return NULL;
            }
            continue;
        }

        /* fmt[i] == '%'. Handle the GNU %:z / %::z / %:::z timezone forms
           first (colons sit between '%' and 'z', not a flag/width run). */
        if (i + 2 < len && fmt[i + 1] == ':' &&
            (fmt[i + 2] == 'z' ||
             (i + 3 < len && fmt[i + 2] == ':' && fmt[i + 3] == 'z') ||
             (i + 4 < len && fmt[i + 2] == ':' && fmt[i + 3] == ':' && fmt[i + 4] == 'z'))) {
            char zbuf[16];
            int colons = 1;
            if (fmt[i + 2] == ':' && fmt[i + 3] == ':')
                colons = 3;
            else if (fmt[i + 2] == ':')
                colons = 2;
            bd_format_offset (offset, colons, zbuf, sizeof zbuf);
            if (bd_buf_append (&out, &cap, &j, zbuf, strlen (zbuf)) < 0) {
                free (out);
                return NULL;
            }
            i += (size_t) colons + 1;
            continue;
        }

        /* General GNU shape: %[flags][width]<spec>. Scan the optional flag
           run ('-' '_' '0' '^' '#') and the optional decimal width. We
           remember the first case-fold flag seen and whether a '0' flag was
           present, then dispatch on the final spec char. */
        size_t k = i + 1;
        int casefold = 0;       /* 0 none, '^' upper, '#' swapcase */
        int zero_flag = 0;
        int minus_flag = 0;     /* '-' => suppress padding */
        while (k < len &&
               (fmt[k] == '-' || fmt[k] == '_' || fmt[k] == '0' ||
                fmt[k] == '^' || fmt[k] == '#')) {
            if (fmt[k] == '^' || fmt[k] == '#') {
                if (!casefold) casefold = fmt[k];
            } else if (fmt[k] == '0') {
                zero_flag = 1;
            } else if (fmt[k] == '-') {
                minus_flag = 1;
            }
            k++;
        }
        size_t width_start = k;
        while (k < len && fmt[k] >= '0' && fmt[k] <= '9')
            k++;
        size_t width = (width_start < k)
            ? (size_t) strtoul (fmt + width_start, NULL, 10) : 0;
        char spec = (k < len) ? fmt[k] : '\0';
        int have_flags = (k > i + 1);   /* anything between '%' and spec */

        /* (a) Sub-second precision: %N (9 digits) or %[1-9]N. Integer epoch
           => all zeros. Bare %N already worked; keep that path too. */
        if (spec == 'N') {
            /* width digits present and > 0 => that many; otherwise bare %N
               which GNU treats as 9-digit nanoseconds. */
            size_t digits = (width_start < k && width > 0) ? width : 9;
            if (digits > 9) digits = 9;
            char nbuf[10];
            memset (nbuf, '0', digits);
            nbuf[digits] = '\0';
            if (bd_buf_append (&out, &cap, &j, nbuf, digits) < 0) {
                free (out);
                return NULL;
            }
            i = k;
            continue;
        }

        /* (a2) Epoch seconds %s: GNU date emits the actual time_t, NOT
           strftime's %s — glibc/musl derive %s from the broken-down tm via
           mktime(), which is wrong for a UTC-filled tm under -u (it adds the
           local UTC offset). Emit t directly; honor -/0/width like %k/%l. */
        if (spec == 's') {
            char sbuf[32];
            int w = (width_start < k && width > 0) ? (int) width : 0;
            if (minus_flag || w == 0)
                snprintf (sbuf, sizeof sbuf, "%lld", (long long) t);
            else if (zero_flag)
                snprintf (sbuf, sizeof sbuf, "%0*lld", w, (long long) t);
            else
                snprintf (sbuf, sizeof sbuf, "%*lld", w, (long long) t);
            if (bd_buf_append_literal (&out, &cap, &j, sbuf) < 0) {
                free (out);
                return NULL;
            }
            i = k;
            continue;
        }

        /* (a3) %Z under -u: GNU date prints "UTC" (it operates in the UTC
           zone). gmtime() yields tm_zone "GMT" on glibc (musl gives "UTC"),
           so emit "UTC" explicitly to match GNU independently of the host
           libc. Without -u, strftime's local zone name is correct. */
        if (spec == 'Z' && utc && !have_flags) {
            if (bd_buf_append_literal (&out, &cap, &j, "UTC") < 0) {
                free (out);
                return NULL;
            }
            i = k;
            continue;
        }

        /* (b) Case-fold flags %^X / %#X on textual specs: musl strftime
           ignores '^'/'#', so render the bare spec then transform here. */
        if (casefold && spec) {
            char tbuf[256];
            bd_strftime_one (spec, tm, tbuf, sizeof tbuf);
            for (char *p = tbuf; *p; p++) {
                unsigned char c = (unsigned char) *p;
                if (casefold == '^') {
                    if (c >= 'a' && c <= 'z') *p = (char) (c - 32);
                } else { /* '#' swapcase */
                    if (c >= 'a' && c <= 'z') *p = (char) (c - 32);
                    else if (c >= 'A' && c <= 'Z') *p = (char) (c + 32);
                }
            }
            if (bd_buf_append_literal (&out, &cap, &j, tbuf) < 0) {
                free (out);
                return NULL;
            }
            i = k;
            continue;
        }

        /* (b2) Lowercase meridian %P: musl strftime does not implement it
           (returns empty). Render %p (uppercase AM/PM, which musl supports)
           and lowercase the result. */
        if (spec == 'P' && !casefold) {
            char pbuf[16];
            bd_strftime_one ('p', tm, pbuf, sizeof pbuf);
            for (char *p = pbuf; *p; p++)
                if (*p >= 'A' && *p <= 'Z') *p = (char) (*p + 32);
            if (bd_buf_append_literal (&out, &cap, &j, pbuf) < 0) {
                free (out);
                return NULL;
            }
            i = k;
            continue;
        }

        /* (c) Hour specs %k (24h) and %l (12h): musl strftime does NOT
           implement them at all (it returns an empty string), so compute
           the value from tm here. GNU defaults to field width 2, space
           padded; the '0' flag zero-pads, the '-' flag suppresses padding,
           and an explicit width overrides the default 2. */
        if (spec == 'k' || spec == 'l') {
            int h = tm->tm_hour;
            if (spec == 'l') { h %= 12; if (h == 0) h = 12; }
            int w = (width_start < k && width > 0) ? (int) width : 2;
            char hbuf[32];
            if (minus_flag)
                snprintf (hbuf, sizeof hbuf, "%d", h);
            else if (zero_flag)
                snprintf (hbuf, sizeof hbuf, "%0*d", w, h);
            else
                snprintf (hbuf, sizeof hbuf, "%*d", w, h);
            if (bd_buf_append_literal (&out, &cap, &j, hbuf) < 0) {
                free (out);
                return NULL;
            }
            i = k;
            continue;
        }

        /* Fallback: copy the whole "%[flags][width]spec" verbatim so the
           later strftime pass handles already-working specs (%-d, %_d, %0d,
           %0e, plain %B, etc.) exactly as before. */
        (void) have_flags;
        {
            size_t runlen = (spec ? (k - i + 1) : (k - i));
            if (bd_buf_append (&out, &cap, &j, fmt + i, runlen) < 0) {
                free (out);
                return NULL;
            }
            i += runlen - 1;
        }
    }
    out[j] = '\0';
    return out;
}

static const char *
bd_iso8601_format (const char *level)
{
    if (level == NULL || *level == '\0' || !strcmp (level, "date"))
        return "%Y-%m-%d";
    if (!strcmp (level, "hours"))
        return "%Y-%m-%dT%H%:z";
    if (!strcmp (level, "minutes"))
        return "%Y-%m-%dT%H:%M%:z";
    if (!strcmp (level, "seconds"))
        return "%Y-%m-%dT%H:%M:%S%:z";
    return NULL;
}

static const char *
bd_rfc3339_format (const char *level)
{
    if (!strcmp (level, "date"))
        return "%Y-%m-%d";
    if (!strcmp (level, "seconds"))
        return "%Y-%m-%d %H:%M:%S%:z";
    return NULL;
}

int
date_builtin (WORD_LIST *list)
{
    int utc = 0;
    const char *date_str = NULL;
    const char *fmt = NULL;
    const char *iso_fmt = NULL;

    while (list) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version")) {
            puts ("bashdate 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-u") || !strcmp (w, "--utc")) {
            utc = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-R") || !strcmp (w, "--rfc-email")) {
            /* RFC 5322 date, C-locale equivalent of
               "+%a, %d %b %Y %H:%M:%S %z". */
            fmt = "%a, %d %b %Y %H:%M:%S %z";
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-I") || !strcmp (w, "--iso-8601")) {
            iso_fmt = bd_iso8601_format ("date");
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-I", 2) && w[2]) {
            iso_fmt = bd_iso8601_format (w + 2);
            if (!iso_fmt) {
                builtin_error ("invalid ISO-8601 timespec: %s", w + 2);
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--iso-8601=", 11)) {
            iso_fmt = bd_iso8601_format (w + 11);
            if (!iso_fmt) {
                builtin_error ("invalid ISO-8601 timespec: %s", w + 11);
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--rfc-3339")) {
            builtin_error ("--rfc-3339 needs TIMESPEC");
            builtin_usage ();
            return EX_USAGE;
        }
        if (!strncmp (w, "--rfc-3339=", 11)) {
            iso_fmt = bd_rfc3339_format (w + 11);
            if (!iso_fmt) {
                builtin_error ("invalid RFC 3339 timespec: %s", w + 11);
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-d") || !strcmp (w, "--date")) {
            if (!list->next) {
                builtin_error ("%s needs STRING", w);
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            date_str = list->word->word;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--date=", 7)) {
            if (w[7] == '\0') {
                builtin_error ("--date needs STRING");
                builtin_usage ();
                return EX_USAGE;
            }
            date_str = w + 7;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-d", 2) && w[2]) {
            date_str = w + 2;
            list = list->next;
            continue;
        }
        if (w[0] == '+') {
            fmt = w + 1;
            list = list->next;
            continue;
        }
        builtin_error ("unknown arg: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    time_t t;
    if (date_str) {
        if (bd_parse_d (date_str, &t, utc) < 0) {
            builtin_error ("date: cannot parse '%s' (try ISO 8601 or @SECONDS)", date_str);
            return EX_USAGE;
        }
    } else {
        t = time (NULL);
    }

    struct tm tm;
    if (utc) gmtime_r (&t, &tm);
    else     localtime_r (&t, &tm);

    char buf[256];
    const char *use_fmt = fmt ? fmt : (iso_fmt ? iso_fmt : "%a %b %e %T %Z %Y");
    char *expanded_fmt = bd_expand_gnu_tz_formats (use_fmt, &tm, t, utc);
    if (!expanded_fmt) {
        builtin_error ("out of memory");
        return EXECUTION_FAILURE;
    }
    if (strftime (buf, sizeof buf, expanded_fmt, &tm) == 0) {
        /* Empty result is allowed (e.g. `+`); but if buf overflowed,
           strftime returned 0 with undefined contents — we conservatively
           print empty in that case. */
        buf[0] = '\0';
    }
    free (expanded_fmt);
    puts (buf);
    return EXECUTION_SUCCESS;
}

char *date_doc[] = {
    "Print the date or convert a timestamp (POSIX date).",
    "",
    "    bashdate [-u] [-d STRING|--date=STRING] [-I[FMT]|--iso-8601[=FMT]] [--rfc-3339=FMT] [+FORMAT]",
    "    bashdate --help | --version",
    "",
    "    -u           UTC instead of local time",
    "    -R, --rfc-email",
    "                 RFC 5322 date (%a, %d %b %Y %H:%M:%S %z in C locale)",
    "    -d STRING, --date=STRING",
    "                 parse STRING; accepted shapes:",
    "                   YYYY-MM-DDTHH[:MM[:SS]][+HH:MM|-HHMM]",
    "                   YYYY-MM-DDTHH:MM[:SS]Z",
    "                   YYYY-MM-DD HH[:MM[:SS]]",
    "                   [DAY[,]] D Mon YYYY HH:MM:SS UTC|GMT|+HHMM|-HH:MM",
    "                   YYYY-MM-DD",
    "                   @SECONDS                 (epoch)",
    "                   now",
    "    -I[FMT], --iso-8601[=FMT]",
    "                 print GNU ISO-8601 form; FMT is date, hours, minutes, seconds",
    "    --rfc-3339=FMT",
    "                 print GNU RFC 3339 form; FMT is date, seconds",
    "    +FORMAT      strftime(3) format plus GNU %N / %[1-9]N, %:z/%::z/%:::z,",
    "                 case-fold %^X/%#X, and zero-padded %0k/%0l forms",
    "                 Default: %a %b %e %T %Z %Y",
    "",
    "For richer date arithmetic / `last week` shorthand use system+ date.",
    (char *)NULL
};

struct builtin bashdate_struct = {
    "bashdate",
    date_builtin,
    BUILTIN_ENABLED,
    date_doc,
    "bashdate [-u] [-d STRING|--date=STRING] [-I[FMT]|--iso-8601[=FMT]] [--rfc-3339=FMT] [+FORMAT]",
    0
};
