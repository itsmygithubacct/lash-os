/* SPDX-License-Identifier: MIT */
/* GNU-compatible base64 command; bashbase64 retains its unwrapped default. */
#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include "loadables.h"
#include "base64-codec.h"

/* Decode incrementally, including concatenated padded groups. Only LF is
   ignored without -i. Emit each completed byte even if a later byte is bad. */
static int base64_decode(int fd, int ignore)
{
    unsigned char input[16384], output[16384];
    size_t used = 0;
    unsigned bits = 0;
    int count = 0, need_pad = 0, invalid = 0;
    for (;;) {
        ssize_t n = read(fd, input, sizeof input);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { builtin_error("read: %s", strerror(errno)); return 1; }
        if (!n) break;
        for (ssize_t i = 0; i < n; i++) {
            unsigned char c = input[i];
            if (c == '\n') continue;
            int value = b64_lookup(c, 0);
            if (value < 0 && c != '=' && ignore) continue;
            if (need_pad) {
                if (c != '=') { invalid = 1; break; }
                need_pad = count = 0;
                continue;
            }
            if (c == '=') {
                if (count == 2) need_pad = 1;
                else if (count == 3) count = 0;
                else { invalid = 1; break; }
                continue;
            }
            if (value < 0) { invalid = 1; break; }
            bits = (bits << 6) | (unsigned)value;
            count++;
            if (count >= 2) output[used++] = (unsigned char)(bits >> (8 - 2 * count));
            if (count == 4) count = 0;
        }
        if (b64_write_all(1, (const char *)output, used) < 0) return 1;
        used = 0;
        if (invalid) break;
    }
    if (invalid || need_pad || count == 1) {
        builtin_error("invalid input");
        return 1;
    }
    return 0;
}

static int base64_width(const char *s, int *width)
{
    char *end;
    if (!*s || *s == '-') return -1;
    errno = 0;
    unsigned long n = strtoul(s, &end, 10);
    if (errno || *end || n > INT_MAX) return -1;
    *width = (int)n;
    return 0;
}

int base64_builtin(WORD_LIST *list)
{
    int decode = 0, ignore = 0, wrap = 76, end_options = 0;
    const char *file = NULL;
    for (; list; list = list->next) {
        const char *w = list->word->word, *width = NULL;
        if (!end_options && !strcmp(w, "--")) { end_options = 1; continue; }
        if (!end_options && !strcmp(w, "--help")) {
            puts("Usage: base64 [-di] [-w COLS] [FILE]\nEncode or decode FILE, or standard input. Default wrap: 76.\n-d, --decode  -i, --ignore-garbage  -w, --wrap=COLS (0 disables wrapping)");
            return fflush(stdout) ? 1 : 0;
        }
        if (!end_options && !strcmp(w, "--version")) {
            puts("base64 (bash-os) 0.1.1"); return fflush(stdout) ? 1 : 0;
        }
        if (!end_options && !strcmp(w, "--decode")) { decode = 1; continue; }
        if (!end_options && !strcmp(w, "--ignore-garbage")) { ignore = 1; continue; }
        if (!end_options && !strncmp(w, "--wrap=", 7)) width = w + 7;
        else if (!end_options && !strcmp(w, "--wrap")) {
            if (!(list = list->next)) goto bad_option;
            width = list->word->word;
        } else if (!end_options && w[0] == '-' && w[1]) {
            for (const char *p = w + 1; *p; p++) {
                if (*p == 'd') decode = 1;
                else if (*p == 'i') ignore = 1;
                else if (*p == 'w') {
                    if (p[1]) width = p + 1;
                    else {
                        if (!(list = list->next)) goto bad_option;
                        width = list->word->word;
                    }
                    break;
                } else goto bad_option;
            }
            if (!width) continue;
        } else {
            if (file) { builtin_error("extra operand: %s", w); return 1; }
            file = w;
            continue;
        }
        if (base64_width(width, &wrap) < 0) {
            builtin_error("invalid wrap size: %s", width); return 1;
        }
    }
    int fd = !file || !strcmp(file, "-") ? 0 : open(file, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { builtin_error("%s: %s", file, strerror(errno)); return 1; }
    int rc = decode ? base64_decode(fd, ignore) : b64_encode(fd, 1, 0, wrap);
    if (fd != 0 && close(fd) < 0) rc = 1;
    return rc;
bad_option:
    builtin_error("invalid option or missing argument; try base64 --help");
    return 1;
}

char *base64_doc[] = {
    "RFC 4648 base64 with GNU wrapping, decoding and ignore-garbage options.",
    "With no FILE or FILE '-', read standard input. Default line width is 76.",
    NULL
};
struct builtin base64_struct = {
    "base64", base64_builtin, BUILTIN_ENABLED, base64_doc,
    "base64 [-di] [-w COLS] [FILE]", 0
};
