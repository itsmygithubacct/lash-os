/* SPDX-License-Identifier: MIT */
/* cal.c — cal(1) calendar display. Loadable for bash.
 *
 * util-linux's misc-utils/cal.c and BusyBox's util-linux/cal.c both
 * implement the same "print one month, one year, or one Julian-day
 * variant" surface; cal ships the same minimal contract as a bash
 * builtin so bash-os doesn't need a separate cal binary on PATH.
 *
 * Verbs:
 *     cal                       # current month (Gregorian, Sunday-first)
 *     cal YYYY | -y YYYY        # full year (12 months, 3 columns)
 *     cal MM YYYY               # specific month
 *     cal -j ...                # Julian day-of-year mode
 *     cal -m ...                # Monday-first week
 *     cal -w MM YYYY            # ncal-style month with week numbers
 *     cal -3 | -A N | -B N ...  # month spans
 *     cal -h | --help           # usage
 *
 * Output shape (default mode):
 *     22-char-wide month grid; 2-char day cells with single space
 *     separators; centered "<MonthName> <YYYY>" title; Sunday-first
 *     header "Su Mo Tu We Th Fr Sa". `-m` rotates to "Mo Tu ... Su".
 *
 * Output shape (-j Julian):
 *     29-char-wide month grid; 3-char day-of-year cells with single
 *     space separators; 2-letter padded " Su  Mo ..." header. Day-of-year
 *     accounts for leap-February.
 *
 * Year mode:
 *     Non-Julian year output follows util-linux's horizontal
 *     three-column layout. Julian year output uses util-linux's
 *     two-column layout.
 *
 * Calendar model:
 *     Gregorian calendar with util-linux-compatible British 1752
 *     reformation handling: September 3..13, 1752 are omitted. Dates
 *     before the cutover use Julian day-of-week arithmetic. Acceptable
 *     year range: 1..9999.
 *
 * Source counterparts:
 *     research/refs/util-linux/misc-utils/cal.c   (canonical)
 *     research/refs/busybox/util-linux/cal.c
 *
 * Companion wrapper:
 *     /bash-os/cal.sh    (POSIX command-name shim — forwards to builtin
 *                         if loaded, falls back to pure-bash impl).
 *
 * --- LICENSE ---
 * MIT License
 *
 * Copyright (c) 2026 bash_linux contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "loadables.h"

static const int bc_days_in_month[] = {
    0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

static const char *bc_month_names[] = {
    "", "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
};

static int bc_days_this_month (int m, int y);

static int
bc_is_leap (int y)
{
    return (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0));
}

/* Zeller's congruence, Gregorian. Returns 0=Sun..6=Sat for the 1st
   of m/y. Treats Jan/Feb as months 13/14 of (y-1). */
static int
bc_dow_of_first (int m, int y)
{
    int q = 1;
    if (m < 3) { m += 12; y -= 1; }
    int K = y % 100;
    int J = y / 100;
    int h = (q + (13 * (m + 1)) / 5 + K + K / 4 + J / 4 - 2 * J) % 7;
    if (h < 0) h += 7;
    /* Zeller's 0=Saturday → shift so 0=Sunday. */
    return (h + 6) % 7;
}

static int
bc_julian_dow (int d, int m, int y)
{
    int a = (14 - m) / 12;
    int yy = y + 4800 - a;
    int mm = m + 12 * a - 3;
    long jdn = d + (153 * mm + 2) / 5 + 365L * yy + yy / 4 - 32083;

    return (int) ((jdn + 1) % 7);
}

static long
bc_gregorian_jdn (int d, int m, int y)
{
    int a = (14 - m) / 12;
    int yy = y + 4800 - a;
    int mm = m + 12 * a - 3;

    return d + (153 * mm + 2) / 5 + 365L * yy + yy / 4 - yy / 100
           + yy / 400 - 32045;
}

static int
bc_gregorian_dow (int d, int m, int y)
{
    return (int) ((bc_gregorian_jdn (d, m, y) + 1) % 7);
}

static int
bc_reform_month (int m, int y)
{
    return y == 1752 && m == 9;
}

static int
bc_before_reform (int m, int y)
{
    return y < 1752 || (y == 1752 && m < 9);
}

static int
bc_display_dow_of_first (int m, int y)
{
    if (bc_before_reform (m, y) || bc_reform_month (m, y))
        return bc_julian_dow (1, m, y);
    return bc_dow_of_first (m, y);
}

static int
bc_display_dow (int d, int m, int y)
{
    if (bc_before_reform (m, y) || (bc_reform_month (m, y) && d < 14))
        return bc_julian_dow (d, m, y);
    return bc_gregorian_dow (d, m, y);
}

/* 1-based day-of-year for (1, m, y). */
static int
bc_doy_of_first (int m, int y)
{
    int doy = 1;
    for (int i = 1; i < m; i++) {
        doy += bc_days_in_month[i];
        if (i == 2 && bc_is_leap (y)) doy += 1;
    }
    return doy;
}

static int
bc_gregorian_doy (int d, int m, int y)
{
    return bc_doy_of_first (m, y) + d - 1;
}

static int
bc_week_sunday (int d, int m, int y)
{
    int yday = bc_gregorian_doy (d, m, y) - 1;
    int dow = bc_gregorian_dow (d, m, y);
    int week = (yday + 7 - dow) / 7;

    if (week == 0) {
        return bc_week_sunday (31, 12, y - 1) + 1;
    }
    return week;
}

static long
bc_iso_week1_monday (int y)
{
    long jan4 = bc_gregorian_jdn (4, 1, y);
    int dow = bc_gregorian_dow (4, 1, y);       /* 0=Sun..6=Sat */
    int monday_dow = (dow + 6) % 7;             /* 0=Mon..6=Sun */

    return jan4 - monday_dow;
}

static int
bc_iso_weeks_in_year (int y)
{
    return (int) ((bc_iso_week1_monday (y + 1) - bc_iso_week1_monday (y)) / 7);
}

static int
bc_week_monday_iso (int d, int m, int y)
{
    long day = bc_gregorian_jdn (d, m, y);
    long week1 = bc_iso_week1_monday (y);

    if (day < week1)
        return bc_iso_weeks_in_year (y - 1);
    if (day >= bc_iso_week1_monday (y + 1))
        return 1;
    return (int) ((day - week1) / 7) + 1;
}

static int
bc_display_doy (int d, int m, int y)
{
    int doy = bc_doy_of_first (m, y) + d - 1;

    if (y == 1752 && (m > 9 || (m == 9 && d >= 14)))
        doy -= 11;
    return doy;
}

static void
bc_print_ncal_week_month (int m, int y, int monday)
{
    int slots[7][6];
    int weeks[6];
    int used[6];
    int ncols = 0;
    char title[64];

    memset (slots, 0, sizeof slots);
    memset (weeks, 0, sizeof weeks);
    memset (used, 0, sizeof used);

    int days = bc_days_this_month (m, y);
    int col = 0;
    int first_display = 1;
    if (bc_reform_month (m, y))
        first_display = 1;
    for (int d = 1; d <= days; d++) {
        int display_day = d;
        if (bc_reform_month (m, y) && d == 3)
            d = display_day = 14;

        int dow = bc_display_dow (display_day, m, y);
        int row = monday ? (dow + 6) % 7 : dow;
        if (display_day != first_display &&
            (dow == 1 || (bc_reform_month (m, y) && display_day == 14)))
            col++;
        int display_col = (!monday && dow == 0 && display_day != first_display) ? col + 1 : col;
        if (display_col >= 6)
            display_col = 5;
        slots[row][display_col] = display_day;
        used[col < 6 ? col : 5] = 1;
    }

    for (int i = 0; i < 6; i++)
        if (used[i])
            ncols = i + 1;
    if (ncols == 0)
        ncols = 1;

    for (int col = 0; col < ncols; col++) {
        int first_day = 0;
        for (int row = 0; row < 7; row++)
            if (slots[row][col] && (first_day == 0 || slots[row][col] < first_day))
                first_day = slots[row][col];
        weeks[col] = monday ? bc_week_monday_iso (first_day, m, y)
                            : bc_week_sunday (first_day, m, y);
    }

    snprintf (title, sizeof title, "%s %d", bc_month_names[m], y);
    printf ("    %-18s\n", title);

    static const char *sun_names[7] = {"Su", "Mo", "Tu", "We", "Th", "Fr", "Sa"};
    static const char *mon_names[7] = {"Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"};
    for (int row = 0; row < 7; row++) {
        fputs (monday ? mon_names[row] : sun_names[row], stdout);
        for (int col = 0; col < ncols; col++) {
            if (slots[row][col])
                printf ("%3d", slots[row][col]);
            else
                fputs ("   ", stdout);
        }
        for (int col = ncols; col < 5; col++)
            fputs ("   ", stdout);
        fputs ("   \n", stdout);
    }
    fputs ("  ", stdout);
    for (int col = 0; col < ncols; col++)
        printf ("%3d", weeks[col]);
    for (int col = ncols; col < 5; col++)
        fputs ("   ", stdout);
    fputs ("   \n", stdout);
}

static int
bc_days_this_month (int m, int y)
{
    int n = bc_days_in_month[m];
    if (m == 2 && bc_is_leap (y)) n = 29;
    return n;
}

static int
bc_parse_num (const char *s, long min, long max, const char *what, int *out)
{
    char *end = NULL;
    long v;

    v = strtol (s, &end, 10);
    if (end == s || *end != '\0' || v < min || v > max) {
        builtin_error ("bad %s: %s", what, s);
        return -1;
    }
    *out = (int) v;
    return 0;
}

static void
bc_pad (int n)
{
    for (int i = 0; i < n; i++) putchar (' ');
}

static void
bc_print_title (const char *t, int title_width, int line_width)
{
    int tl = (int) strlen (t);
    int pad = (title_width - tl) / 2;
    if (pad < 0) pad = 0;
    bc_pad (pad);
    fputs (t, stdout);
    bc_pad (line_width - pad - tl);
    putchar ('\n');
}

static void
bc_blank_line (char *line, int width)
{
    memset (line, ' ', (size_t) width);
    line[width] = '\0';
}

static void
bc_put_centered (char *line, int line_width, int title_width, const char *text)
{
    int tl = (int) strlen (text);
    int pad = (title_width - tl) / 2;
    if (pad < 0) pad = 0;
    if (pad + tl > line_width) tl = line_width - pad;
    memcpy (line + pad, text, (size_t) tl);
}

static void
bc_month_lines (int m, int y, int julian, int monday, int include_year,
                char lines[8][32])
{
    char title[64];
    int field = julian ? 4 : 3;
    int title_width = field * 7 - 1;
    int width = title_width + 2;

    if (include_year)
        snprintf (title, sizeof title, "%s %d", bc_month_names[m], y);
    else
        snprintf (title, sizeof title, "%s", bc_month_names[m]);

    for (int i = 0; i < 8; i++)
        bc_blank_line (lines[i], width);

    bc_put_centered (lines[0], width, title_width, title);

    if (julian)
        memcpy (lines[1], monday ? " Mo  Tu  We  Th  Fr  Sa  Su  "
                                : " Su  Mo  Tu  We  Th  Fr  Sa  ",
                (size_t) width);
    else
        memcpy (lines[1], monday ? "Mo Tu We Th Fr Sa Su  "
                                : "Su Mo Tu We Th Fr Sa  ",
                (size_t) width);

    int dow = bc_display_dow_of_first (m, y);
    if (monday) dow = (dow + 6) % 7;

    int days = bc_days_this_month (m, y);
    int row = 2;
    int col = field * dow;
    int wcol = dow;

    for (int d = 1; d <= days && row < 8; d++) {
        char cell[8];
        int display_day = d;
        int display_value;

        if (bc_reform_month (m, y) && d == 3)
            d = display_day = 14;

        display_value = julian ? bc_display_doy (display_day, m, y)
                               : display_day;
        int n = snprintf (cell, sizeof cell, julian ? "%3d" : "%2d",
                          display_value);
        if (n > 0 && col + n <= width)
            memcpy (lines[row] + col, cell, (size_t) n);
        wcol++;
        if (wcol == 7) {
            row++;
            col = 0;
            wcol = 0;
        } else {
            col += field;
        }
    }
}

static void
bc_print_month (int m, int y, int julian, int monday)
{
    char lines[8][32];
    bc_month_lines (m, y, julian, monday, 1, lines);
    for (int i = 0; i < 8; i++)
        puts (lines[i]);
}

static void
bc_month_from_index (int idx, int *m, int *y)
{
    *y = idx / 12;
    *m = idx % 12 + 1;
}

static int
bc_month_index (int m, int y)
{
    return y * 12 + (m - 1);
}

static int
bc_check_span_range (int start_idx, int count)
{
    int end_idx = start_idx + count - 1;
    int m, y;

    bc_month_from_index (start_idx, &m, &y);
    if (y < 1 || y > 9999)
        return -1;
    bc_month_from_index (end_idx, &m, &y);
    if (y < 1 || y > 9999)
        return -1;
    return 0;
}

static void
bc_print_month_span (int start_m, int start_y, int count, int julian, int monday)
{
    int cols = julian ? 2 : 3;
    int start_idx = bc_month_index (start_m, start_y);
    int month_width = julian ? 29 : 22;
    int title_width = cols * (month_width - 2);
    char lines[3][8][32];

    /* Title style, matching cal(1)/ncal: a span is shown in "year" form
       — a centered YEAR header over year-less month sub-titles, one
       header per run of same-year months — only when it begins on a
       row boundary AND its first row is complete. A row holds `cols`
       months (3 normally, 2 in Julian mode), so the boundary is
       (start_m-1) % cols == 0 (Jan/Apr/Jul/Oct for cols=3; odd months
       for cols=2) and "complete first row" is count >= cols. Such a row
       never crosses a year, so every row of the span is single-year;
       any other span gives each month its own "Month YYYY" title.

       The old heuristic (year header for any full row of three same-year
       months) mis-titled forward spans like `-A 2 5 2026` (May/Jun/Jul),
       which cal(1) renders with per-month titles, split multi-row spans
       inconsistently, and wrongly forced Julian spans to per-month. */
    int year_mode = ((start_m - 1) % cols == 0) && (count >= cols);
    int prev_year = 0;          /* year of the last header emitted */
    int first = 1;

    for (int offset = 0; offset < count; offset += cols) {
        int group = count - offset < cols ? count - offset : cols;
        int months[3], years[3];

        for (int col = 0; col < group; col++)
            bc_month_from_index (start_idx + offset + col, &months[col], &years[col]);

        if (!first)
            putchar ('\n');     /* blank line between row groups */

        if (year_mode && years[0] != prev_year) {
            char yt[16];
            snprintf (yt, sizeof yt, "%d", years[0]);
            bc_pad ((title_width - (int) strlen (yt)) / 2);
            fputs (yt, stdout);
            putchar ('\n');
            prev_year = years[0];
        }

        for (int col = 0; col < group; col++)
            bc_month_lines (months[col], years[col], julian, monday,
                            year_mode ? 0 : 1, lines[col]);

        for (int row = 0; row < 8; row++) {
            for (int col = 0; col < group; col++)
                fputs (lines[col][row], stdout);
            putchar ('\n');
        }
        first = 0;
    }
}

static void
bc_print_year (int y, int julian, int monday)
{
    int cols = julian ? 2 : 3;
    int month_width = julian ? 29 : 22;
    int title_width = cols * (month_width - 2);
    char lines[3][8][32];
    char yt[16];

    snprintf (yt, sizeof yt, "%d", y);
    bc_pad ((title_width - (int) strlen (yt)) / 2);
    fputs (yt, stdout);
    putchar ('\n');

    for (int first = 1; first <= 12; first += cols) {
        for (int col = 0; col < cols; col++)
            bc_month_lines (first + col, y, julian, monday, 0, lines[col]);

        for (int row = 0; row < 8; row++) {
            for (int col = 0; col < cols; col++)
                fputs (lines[col][row], stdout);
            putchar ('\n');
        }
        if (first + cols <= 12)
            putchar ('\n');
    }
}

int
cal_builtin (WORD_LIST *list)
{
    int julian = 0;
    int monday = 0;
    int explicit_year = 0;
    int year = 0;
    int before = 0;
    int after = 0;
    int span_requested = 0;
    int three_requested = 0;
    int week_numbers = 0;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--version")) {
            puts ("cal 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-j") || !strcmp (w, "--julian")) {
            julian = 1; list = list->next; continue;
        }
        if (!strcmp (w, "-m") || !strcmp (w, "--monday")) {
            monday = 1; list = list->next; continue;
        }
        if (!strcmp (w, "-M") || !strcmp (w, "--monday")) {
            monday = 1; list = list->next; continue;
        }
        if (!strcmp (w, "-S") || !strcmp (w, "-s") || !strcmp (w, "--sunday")) {
            monday = 0; list = list->next; continue;
        }
        if (!strcmp (w, "-w") || !strcmp (w, "--week")) {
            week_numbers = 1; list = list->next; continue;
        }
        if (!strcmp (w, "-3") || !strcmp (w, "--three")) {
            before = 1; after = 1; span_requested = 1;
            three_requested = 1;
            list = list->next; continue;
        }
        if (!strcmp (w, "-1") || !strcmp (w, "--one")) {
            /* Single month (the default); resets any prior -3/-A/-B span,
               matching util-linux/bsd cal's last-one-wins flag handling. */
            before = 0; after = 0; span_requested = 0; three_requested = 0;
            list = list->next; continue;
        }
        if (!strcmp (w, "-A") || !strcmp (w, "--after")) {
            if (!list->next) {
                builtin_error ("%s requires a month count", w);
                builtin_usage ();
                return EX_USAGE;
            }
            if (bc_parse_num (list->next->word->word, 0, 120000, "month count", &after) < 0)
                return EX_USAGE;
            span_requested = 1;
            list = list->next->next;
            continue;
        }
        if (!strcmp (w, "-B") || !strcmp (w, "--before")) {
            if (!list->next) {
                builtin_error ("%s requires a month count", w);
                builtin_usage ();
                return EX_USAGE;
            }
            if (bc_parse_num (list->next->word->word, 0, 120000, "month count", &before) < 0)
                return EX_USAGE;
            span_requested = 1;
            list = list->next->next;
            continue;
        }
        if (!strcmp (w, "-y") || !strcmp (w, "--year")) {
            if (!list->next) {
                builtin_error ("%s requires a year", w);
                builtin_usage ();
                return EX_USAGE;
            }
            if (bc_parse_num (list->next->word->word, 1, 9999, "year", &year) < 0)
                return EX_USAGE;
            explicit_year = 1;
            list = list->next->next;
            continue;
        }
        if (!strcmp (w, "-h") || !strcmp (w, "--help")) {
            puts ("cal: display a calendar (cal(1) subset)");
            puts ("Usage: cal [-jm] [-1|-3] [-A N] [-B N] [[MM] YYYY]");
            puts ("       cal [-jm] -y YEAR");
            puts ("  -j   Julian day-of-year mode (3-digit cells)");
            puts ("  -m   Monday-first week");
            puts ("  -S   Sunday-first week (default)");
            puts ("  -w   ncal-style week numbers for MM YYYY");
            puts ("  -1   display single month (default)");
            puts ("  -3   display previous, current, and next month");
            puts ("  -A N display N months after the target month");
            puts ("  -B N display N months before the target month");
            puts ("  -y   display a full year");
            puts ("  --version   show version");
            return EXECUTION_SUCCESS;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    int npos = 0;
    WORD_LIST *p;
    for (p = list; p; p = p->next) npos++;

    if (explicit_year) {
        if (npos != 0) {
            builtin_error ("too many arguments");
            return EX_USAGE;
        }
        bc_print_year (year, julian, monday);
        return EXECUTION_SUCCESS;
    }

    if (npos == 0) {
        time_t now = time (NULL);
        struct tm *lt = localtime (&now);
        if (!lt) {
            builtin_error ("localtime: failed");
            return EXECUTION_FAILURE;
        }
        int m = lt->tm_mon + 1;
        int y = lt->tm_year + 1900;
        if (span_requested) {
            if (week_numbers) {
                builtin_error ("-w is only supported for MM YYYY");
                return EX_USAGE;
            }
            int start_idx = bc_month_index (m, y) - before;
            int count = before + 1 + after;
            if (bc_check_span_range (start_idx, count) < 0) {
                builtin_error ("month span out of range");
                return EX_USAGE;
            }
            bc_month_from_index (start_idx, &m, &y);
            bc_print_month_span (m, y, count, julian, monday);
            return EXECUTION_SUCCESS;
        }
        bc_print_month (m, y, julian, monday);
        return EXECUTION_SUCCESS;
    }

    if (npos == 1) {
        if (bc_parse_num (list->word->word, 1, 9999, "year", &year) < 0)
            return EX_USAGE;
        if (span_requested) {
            int start_idx;
            int count;

            if (three_requested) {
                builtin_error ("-3 together with a given year but no given month is not supported");
                return EX_USAGE;
            }
            start_idx = bc_month_index (1, year) - before;
            count = before + 12 + after;
            if (bc_check_span_range (start_idx, count) < 0) {
                builtin_error ("month span out of range");
                return EX_USAGE;
            }
            {
                int start_m, start_y;
                bc_month_from_index (start_idx, &start_m, &start_y);
                bc_print_month_span (start_m, start_y, count, julian, monday);
            }
            return EXECUTION_SUCCESS;
        }
        if (week_numbers) {
            builtin_error ("-w is only supported for MM YYYY");
            return EX_USAGE;
        }
        bc_print_year (year, julian, monday);
        return EXECUTION_SUCCESS;
    }

    if (npos == 2) {
        int month;
        if (bc_parse_num (list->word->word, 1, 12, "month", &month) < 0)
            return EX_USAGE;
        if (bc_parse_num (list->next->word->word, 1, 9999, "year", &year) < 0)
            return EX_USAGE;
        if (span_requested) {
            if (week_numbers) {
                builtin_error ("-w is only supported for MM YYYY");
                return EX_USAGE;
            }
            int start_idx = bc_month_index (month, year) - before;
            int count = before + 1 + after;
            if (bc_check_span_range (start_idx, count) < 0) {
                builtin_error ("month span out of range");
                return EX_USAGE;
            }
            bc_month_from_index (start_idx, &month, &year);
            bc_print_month_span (month, year, count, julian, monday);
            return EXECUTION_SUCCESS;
        }
        if (week_numbers) {
            if (julian) {
                builtin_error ("-w is not supported together with -j");
                return EX_USAGE;
            }
            bc_print_ncal_week_month (month, year, monday);
            return EXECUTION_SUCCESS;
        }
        bc_print_month (month, year, julian, monday);
        return EXECUTION_SUCCESS;
    }

    builtin_error ("too many arguments");
    return EX_USAGE;
}

char *cal_doc[] = {
    "Display a calendar month or year (cal(1) subset).",
    "",
    "    cal                   # current month",
    "    cal YYYY | -y YYYY    # entire year (12 months)",
    "    cal MM YYYY           # specific month",
    "    cal -j ...            # Julian day-of-year mode (3-digit cells)",
    "    cal -m ...            # Monday-first week",
    "    cal -3 | -A N | -B N  # month spans",
    "    cal --help | --version",
    "",
    "Gregorian calendar with British 1752 reformation correction.",
    "Day-of-week derived from Gregorian/Julian arithmetic. Year range: 1..9999.",
    "",
    "Source counterparts:",
    "    research/refs/util-linux/misc-utils/cal.c",
    "    research/refs/busybox/util-linux/cal.c",
    (char *) NULL
};

struct builtin cal_struct = {
    "cal",
    cal_builtin,
    BUILTIN_ENABLED,
    cal_doc,
    "cal [-jm] [-3] [-A N] [-B N] [[MM] YYYY] | cal [-jm] -y YEAR",
    0
};
