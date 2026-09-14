/* SPDX-License-Identifier: MIT */
/* strings.c - printable strings extractor. */
#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include "loadables.h"

/* Own stdin's stdio state for this invocation. Bash's persistent stdin FILE
   keeps EOF across redirections. Never fclose stdin. */
static FILE *
strings_open_stdin (void)
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

/* Per-string output prefix, matching binutils print_filename_and_address():
   "FILENAME: " when -f/--print-file-name, then the byte offset of the string
   in the selected radix ("%7lo/%7ld/%7lx ") when -t/-o is given. */
static void
strings_prefix (const char *fname, int print_fname, int radix, long addr)
{
    if (print_fname)
        printf ("%s: ", fname);
    switch (radix) {
        case 8:  printf ("%7lo ", (unsigned long) addr); break;
        case 10: printf ("%7ld ", (long) addr);          break;
        case 16: printf ("%7lx ", (unsigned long) addr); break;
        default: break;   /* radix 0 → no address */
    }
}

/* Scan F for runs of "graphic" bytes of length >= MIN and print them.
   A byte is graphic if it is TAB or printable ASCII — matching binutils'
   default STRING_ISGRAPHIC ((c)=='\t' || ISPRINT(c)). With -w (INCL_WS) any
   isspace() byte also counts, so newlines/CR/FF/VT no longer break a run. */
static int strings_stream(FILE *f, int min, const char *fname,
                          int print_fname, int radix, int incl_ws) {
    char *buf = NULL; size_t cap = 0, len = 0; int c, rc = 0;
    long off = 0, start_off = 0;
    while ((c = fgetc(f)) != EOF) {
        int graphic = (c == '\t') || (c >= 32 && c <= 126)
                      || (incl_ws && isspace((unsigned char) c));
        if (graphic) {
            if (len == 0) start_off = off;
            if (len + 1 >= cap) {
                cap = cap ? cap * 2 : 64;
                char *nb = realloc(buf, cap);
                if (!nb) { free(buf); builtin_error("realloc"); return 1; }
                buf = nb;
            }
            buf[len++] = (char)c;
        } else {
            if ((int)len >= min) {
                strings_prefix(fname, print_fname, radix, start_off);
                fwrite(buf, 1, len, stdout); putchar('\n');
            }
            len = 0;
        }
        off++;
    }
    if ((int)len >= min) {
        strings_prefix(fname, print_fname, radix, start_off);
        fwrite(buf, 1, len, stdout); putchar('\n');
    }
    if (ferror(f)) rc = 1;
    free(buf);
    return rc;
}

static int parse_min_length(const char *s, int *out) {
    char *end = NULL;
    long v;

    if (s == NULL || *s == '\0')
        return -1;

    errno = 0;
    v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < 1 || v > INT_MAX)
        return -1;

    *out = (int)v;
    return 0;
}

/* Map a -t/--radix argument ("o"/"d"/"x") to a numeric radix; -1 if invalid. */
static int parse_radix(const char *s) {
    if (s && s[0] && s[1] == '\0') {
        if (s[0] == 'o') return 8;
        if (s[0] == 'd') return 10;
        if (s[0] == 'x') return 16;
    }
    return -1;
}

int strings_builtin(WORD_LIST *list) {
    int min = 4, rc = EXECUTION_SUCCESS;
    int print_fname = 0, radix = 0, incl_ws = 0;
    while (list && list->word->word[0] == '-') {
        char *w = list->word->word;
        if (!strcmp(w, "--")) { list = list->next; break; }
        if (!strcmp(w, "--help") || !strcmp(w, "-h")) {
            builtin_usage();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp(w, "--version") || !strcmp(w, "-v") || !strcmp(w, "-V")) {
            puts("strings 1.0 (bash-loadable, binutils-compatible)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp(w, "-a") || !strcmp(w, "--all")) { list = list->next; continue; }
        if (!strcmp(w, "-f") || !strcmp(w, "--print-file-name")) {
            print_fname = 1; list = list->next; continue;
        }
        if (!strcmp(w, "-w") || !strcmp(w, "--include-all-whitespace")) {
            incl_ws = 1; list = list->next; continue;
        }
        if (!strcmp(w, "-o")) { radix = 8; list = list->next; continue; }
        /* -t RADIX | --radix RADIX */
        if (!strcmp(w, "-t") || !strcmp(w, "--radix")) {
            if (!list->next) {
                builtin_error("%s requires o, d, or x", w);
                builtin_usage();
                return EX_USAGE;
            }
            radix = parse_radix(list->next->word->word);
            if (radix < 0) {
                builtin_error("invalid radix: %s", list->next->word->word);
                builtin_usage();
                return EX_USAGE;
            }
            list = list->next->next; continue;
        }
        if (!strncmp(w, "-t", 2) && w[2]) {            /* -tRADIX */
            radix = parse_radix(w + 2);
            if (radix < 0) {
                builtin_error("invalid radix: %s", w + 2);
                builtin_usage();
                return EX_USAGE;
            }
            list = list->next; continue;
        }
        if (!strncmp(w, "--radix=", 8)) {
            radix = parse_radix(w + 8);
            if (radix < 0) {
                builtin_error("invalid radix: %s", w + 8);
                builtin_usage();
                return EX_USAGE;
            }
            list = list->next; continue;
        }
        /* -n LEN | --bytes LEN */
        if (!strcmp(w, "-n") || !strcmp(w, "--bytes")) {
            if (!list->next) {
                builtin_error("-n requires a length");
                builtin_usage();
                return EX_USAGE;
            }
            if (parse_min_length(list->next->word->word, &min) < 0) {
                builtin_error("invalid minimum string length: %s", list->next->word->word);
                builtin_usage();
                return EX_USAGE;
            }
            list = list->next->next; continue;
        }
        if (!strncmp(w, "-n", 2) && w[2]) {            /* -nLEN */
            if (parse_min_length(w + 2, &min) < 0) {
                builtin_error("invalid minimum string length: %s", w + 2);
                builtin_usage();
                return EX_USAGE;
            }
            list = list->next; continue;
        }
        if (!strncmp(w, "--bytes=", 8)) {
            if (parse_min_length(w + 8, &min) < 0) {
                builtin_error("invalid minimum string length: %s", w + 8);
                builtin_usage();
                return EX_USAGE;
            }
            list = list->next; continue;
        }
        if (isdigit((unsigned char)w[1])) {            /* -LEN */
            if (parse_min_length(w + 1, &min) < 0) {
                builtin_error("invalid minimum string length: %s", w + 1);
                builtin_usage();
                return EX_USAGE;
            }
            list = list->next; continue;
        }
        builtin_error("unknown option: %s", w);
        builtin_usage();
        return EX_USAGE;
    }
    if (!list) {
        FILE *in = strings_open_stdin ();
        int src;
        if (!in)
            return EXECUTION_FAILURE;
        src = strings_stream(in, min, "{standard input}", print_fname,
                             radix, incl_ws);
        fclose (in);
        return src ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    }
    for (; list; list = list->next) {
        FILE *f = fopen(list->word->word, "rb");
        if (!f) { builtin_error("%s: %s", list->word->word, strerror(errno)); rc = EXECUTION_FAILURE; continue; }
        if (strings_stream(f, min, list->word->word, print_fname, radix, incl_ws)) rc = EXECUTION_FAILURE;
        fclose(f);
    }
    return rc;
}

char *strings_doc[] = {
    "Print printable character sequences from files or stdin.",
    "    strings [-afw] [-n LEN|-LEN|--bytes=LEN] [-t o|d|x|-o] [FILE...]",
    "",
    "    -a, --all      scan the whole file (accepted; strings always does)",
    "    -f, --print-file-name  print the file name before each string",
    "    -n LEN, --bytes=LEN, -LEN  require >= LEN printable chars (LEN >= 1)",
    "    -t {o,d,x}, --radix={o,d,x}  print the offset of each string",
    "    -o             like -t o (octal offsets)",
    "    -w, --include-all-whitespace  count newlines/CR/etc. as printable",
    "    -h, --help     show this help",
    "    -v, -V, --version  show version",
    "",
    "By default a string is a run of TAB or printable-ASCII bytes (matching",
    "GNU binutils strings); -w additionally keeps all whitespace.",
    (char *)NULL
};

struct builtin strings_struct = {
    "strings", strings_builtin, BUILTIN_ENABLED, strings_doc,
    "strings [-afw] [-n LEN|-LEN|--bytes=LEN] [-t o|d|x|-o] [FILE...]", 0
};
