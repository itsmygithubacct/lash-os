/* SPDX-License-Identifier: MIT */
/* signal.c — signal name ↔ number lookup.
 *
 *   signal -l                  list all known signals
 *   signal -n NAME             print number for NAME (HUP / SIGHUP)
 *   signal -s NUMBER           print name for NUMBER
 *   signal NAME-or-NUMBER      print the other form
 *
 * Useful for trap handlers and `kill -SIGNAL` lookups in scripts. The
 * table is the standard set: SIGHUP/INT/QUIT/.../USR1/USR2/CHLD/CONT/
 * STOP/TSTP/TTIN/TTOU/URG/XCPU/XFSZ/VTALRM/PROF/WINCH/IO/PWR/SYS plus
 * the canonical Linux RT-min/RT-max bracket.
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
#include <signal.h>
#include <errno.h>
#include <ctype.h>

#include "loadables.h"

typedef struct { const char *name; int num; } sig_entry;

#define BS(n) { #n, SIG##n }

static const sig_entry bs_table[] = {
    BS (HUP),  BS (INT),  BS (QUIT), BS (ILL),  BS (TRAP), BS (ABRT),
    BS (BUS),  BS (FPE),  BS (KILL), BS (USR1), BS (SEGV), BS (USR2),
    BS (PIPE), BS (ALRM), BS (TERM), BS (CHLD), BS (CONT), BS (STOP),
    BS (TSTP), BS (TTIN), BS (TTOU), BS (URG),  BS (XCPU), BS (XFSZ),
    BS (VTALRM), BS (PROF), BS (WINCH),
#ifdef SIGIO
    BS (IO),
#endif
#ifdef SIGPWR
    BS (PWR),
#endif
#ifdef SIGSYS
    BS (SYS),
#endif
};

#undef BS
#define BS_NTAB (sizeof bs_table / sizeof bs_table[0])

/* Strip optional "SIG" prefix and uppercase. Returns -1 on lookup miss. */
static int
bs_lookup_name (const char *raw)
{
    char up[32];
    size_t n = 0;
    /* Skip leading "SIG" (case-insensitive). */
    const char *s = raw;
    if ((s[0] == 'S' || s[0] == 's') &&
        (s[1] == 'I' || s[1] == 'i') &&
        (s[2] == 'G' || s[2] == 'g')) {
        s += 3;
    }
    while (s[n] && n < sizeof up - 1) {
        up[n] = (char) toupper ((unsigned char) s[n]);
        n++;
    }
    up[n] = '\0';
    for (size_t i = 0; i < BS_NTAB; i++)
        if (!strcmp (bs_table[i].name, up)) return bs_table[i].num;
    /* RT signal range: SIGRTMIN..SIGRTMAX */
    if (!strncmp (up, "RTMIN", 5)) {
        int off = up[5] == '+' ? atoi (up + 6) : 0;
        int v = SIGRTMIN + off;
        return (v >= SIGRTMIN && v <= SIGRTMAX) ? v : -1;
    }
    if (!strncmp (up, "RTMAX", 5)) {
        int off = up[5] == '-' ? atoi (up + 6) : 0;
        int v = SIGRTMAX - off;
        return (v >= SIGRTMIN && v <= SIGRTMAX) ? v : -1;
    }
    return -1;
}

static const char *
bs_lookup_num (int n)
{
    static char buf[16];
    for (size_t i = 0; i < BS_NTAB; i++)
        if (bs_table[i].num == n) return bs_table[i].name;
    if (n >= SIGRTMIN && n <= SIGRTMAX) {
        int off = n - SIGRTMIN;
        if (off == 0) return "RTMIN";
        if (n == SIGRTMAX) return "RTMAX";
        snprintf (buf, sizeof buf, "RTMIN+%d", off);
        return buf;
    }
    return NULL;
}

extern char *signal_doc[];

int
signal_builtin (WORD_LIST *list)
{
    if (!list) {
        builtin_error ("usage: signal -l | -n NAME | -s NUMBER | NAME-OR-NUMBER");
        return EX_USAGE;
    }
    const char *w = list->word->word;

    if (!strcmp (w, "-l")) {
        for (size_t i = 0; i < BS_NTAB; i++)
            printf ("%2d %s\n", bs_table[i].num, bs_table[i].name);
        printf ("%2d RTMIN\n%2d RTMAX\n", SIGRTMIN, SIGRTMAX);
        return EXECUTION_SUCCESS;
    }
    if (!strcmp (w, "-n")) {
        if (!list->next) { builtin_error ("-n needs NAME"); return EX_USAGE; }
        int n = bs_lookup_name (list->next->word->word);
        if (n < 0) { builtin_error ("unknown signal: %s", list->next->word->word); return EXECUTION_FAILURE; }
        printf ("%d\n", n);
        return EXECUTION_SUCCESS;
    }
    if (!strcmp (w, "-s")) {
        if (!list->next) { builtin_error ("-s needs NUMBER"); return EX_USAGE; }
        int num = atoi (list->next->word->word);
        const char *nm = bs_lookup_num (num);
        if (!nm) { builtin_error ("unknown signal number: %d", num); return EXECUTION_FAILURE; }
        printf ("%s\n", nm);
        return EXECUTION_SUCCESS;
    }
    /* --help / -h */
    if (!strcmp (w, "--help") || !strcmp (w, "-h")) {
        char **d;
        for (d = signal_doc; *d; d++) puts (*d);
        return EXECUTION_SUCCESS;
    }

    /* Bare argument: numeric → name, else name → number. */
    char *end;
    long n = strtol (w, &end, 10);
    if (*end == '\0') {
        const char *nm = bs_lookup_num ((int) n);
        if (!nm) { builtin_error ("unknown signal number: %ld", n); return EXECUTION_FAILURE; }
        printf ("%s\n", nm);
        return EXECUTION_SUCCESS;
    }
    int num = bs_lookup_name (w);
    if (num < 0) { builtin_error ("unknown signal: %s", w); return EXECUTION_FAILURE; }
    printf ("%d\n", num);
    return EXECUTION_SUCCESS;
}

char *signal_doc[] = {
    "Look up signal name ↔ number.",
    "",
    "    signal -l                list all known signals",
    "    signal -n NAME           print number for NAME (HUP or SIGHUP)",
    "    signal -s NUMBER         print name for NUMBER",
    "    signal NAME-OR-NUMBER    auto-detect direction",
    "",
    "RT signals: RTMIN, RTMIN+N, RTMAX, RTMAX-N. Useful for `kill",
    "-$(signal -n HUP) PID` and trap-handler setup.",
    (char *)NULL
};

struct builtin signal_struct = {
    "signal",
    signal_builtin,
    BUILTIN_ENABLED,
    signal_doc,
    "signal -l | -n NAME | -s NUMBER | NAME-OR-NUMBER",
    0
};
