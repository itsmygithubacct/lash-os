/* SPDX-License-Identifier: MIT */
/* Concatenate files with GNU's common display options. */
#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "loadables.h"

struct cat_state {
    int number, nonblank, squeeze, ends, tabs, visible;
    int line_start, blank;
    unsigned long long line;
};

static int cat_copy(int fd, struct cat_state *s)
{
    unsigned char buf[16384];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { builtin_error("read: %s", strerror(errno)); return 1; }
        if (!n) return 0;
        if (!(s->number || s->nonblank || s->squeeze || s->ends || s->tabs || s->visible)) {
            if (fwrite(buf, 1, (size_t)n, stdout) != (size_t)n) return 1;
            continue;
        }
        for (ssize_t i = 0; i < n; i++) {
            unsigned char c = buf[i];
            if (s->line_start) {
                if (c == '\n') {
                    if (s->squeeze && s->blank) continue;
                    s->blank = 1;
                } else s->blank = 0;
                if ((s->number || s->nonblank) && (!s->nonblank || c != '\n'))
                    printf("%6llu\t", ++s->line);
                s->line_start = 0;
            }
            if (c == '\n') {
                if (s->ends) putchar('$');
                putchar('\n'); s->line_start = 1;
            } else if (c == '\t') {
                if (s->tabs) fputs("^I", stdout); else putchar(c);
            } else if (s->visible) {
                if (c >= 128) { fputs("M-", stdout); c -= 128; }
                if (c < 32) { putchar('^'); putchar(c + 64); }
                else if (c == 127) fputs("^?", stdout);
                else putchar(c);
            } else putchar(c);
        }
        if (ferror(stdout)) return 1;
    }
}

int cat_builtin(WORD_LIST *list)
{
    struct cat_state s = { .line_start = 1 };
    size_t count = 0;
    for (WORD_LIST *p = list; p; p = p->next) count++;
    const char **files = calloc(count + 1, sizeof *files);
    if (!files) { builtin_error("out of memory"); return 1; }
    size_t used = 0;
    int end_options = 0, rc = 0;
    for (; list; list = list->next) {
        const char *w = list->word->word, *options = NULL;
        if (!end_options && !strcmp(w, "--")) { end_options = 1; continue; }
        if (!end_options && !strcmp(w, "--help")) {
            puts("Usage: cat [-AbEnstTuv] [FILE...]\nConcatenate FILEs, or standard input. Use -- before option-like filenames.");
            goto done;
        }
        if (!end_options && !strcmp(w, "--version")) { puts("cat (bash-os) 0.1.1"); goto done; }
        if (!end_options && !strcmp(w, "--number")) options = "n";
        else if (!end_options && !strcmp(w, "--number-nonblank")) options = "b";
        else if (!end_options && !strcmp(w, "--squeeze-blank")) options = "s";
        else if (!end_options && !strcmp(w, "--show-ends")) options = "E";
        else if (!end_options && !strcmp(w, "--show-tabs")) options = "T";
        else if (!end_options && !strcmp(w, "--show-nonprinting")) options = "v";
        else if (!end_options && !strcmp(w, "--show-all")) options = "A";
        else if (!end_options && w[0] == '-' && w[1]) options = w + 1;
        if (options) {
            for (; *options; options++) switch (*options) {
                case 'n': s.number = 1; break;
                case 'b': s.nonblank = 1; break;
                case 's': s.squeeze = 1; break;
                case 'E': s.ends = 1; break;
                case 'T': s.tabs = 1; break;
                case 'v': s.visible = 1; break;
                case 'A': s.visible = s.ends = s.tabs = 1; break;
                case 'e': s.visible = s.ends = 1; break;
                case 't': s.visible = s.tabs = 1; break;
                case 'u': break;
                default: builtin_error("invalid option: %s", w); rc = 1; goto done;
            }
        } else files[used++] = w;
    }
    if (!used) files[used++] = "-";
    for (size_t i = 0; i < used; i++) {
        int fd = !strcmp(files[i], "-") ? 0 : open(files[i], O_RDONLY | O_CLOEXEC);
        if (fd < 0) { builtin_error("%s: %s", files[i], strerror(errno)); rc = 1; continue; }
        struct stat src, dst;
        if (!fstat(fd, &src) && !fstat(1, &dst) && S_ISREG(dst.st_mode) &&
            src.st_dev == dst.st_dev && src.st_ino == dst.st_ino) {
            builtin_error("%s: input file is output file", files[i]);
            if (fd) close(fd);
            rc = 1; continue;
        }
        rc |= cat_copy(fd, &s);
        if (fd != 0 && close(fd) < 0) rc = 1;
        if (ferror(stdout)) break;
    }
done:
    free(files);
    if (fflush(stdout) || ferror(stdout)) {
        builtin_error("write: %s", strerror(errno)); clearerr(stdout); rc = 1;
    }
    return rc;
}

char *cat_doc[] = {
    "Concatenate FILEs (or stdin). -- ends option parsing; '-' reads stdin.",
    "-n number lines; -b number nonblank; -s squeeze blank lines; -E show ends;",
    "-T show tabs; -v show nonprinting bytes; -A equals -vET; -u is ignored.",
    NULL
};
struct builtin cat_struct = {
    "cat", cat_builtin, BUILTIN_ENABLED, cat_doc, "cat [-AbEnstTuv] [FILE...]", 0
};
