/* SPDX-License-Identifier: MIT */
/* SHA-256 files and GNU/BSD checksum-file verification, using bundled mbedTLS. */
#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include "loadables.h"
#include "_mbedtls_sha256.h"

struct sum_options { int binary, zero, tag, check, quiet, status, strict, warn, ignore; };

static int sum_digest(const char *name, char hex[65], int quiet, int *missing)
{
    int fd = !strcmp(name, "-") ? 0 : open(name, O_RDONLY | O_CLOEXEC);
    *missing = fd < 0 && errno == ENOENT;
    if (fd < 0) {
        if (!quiet) builtin_error("%s: %s", name, strerror(errno));
        return 1;
    }
    unsigned char data[32768], hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    int rc = mbedtls_sha256_starts(&ctx, 0);
    while (!rc) {
        ssize_t n = read(fd, data, sizeof data);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { rc = -1; break; }
        if (!n) break;
        rc = mbedtls_sha256_update(&ctx, data, (size_t)n);
    }
    if (!rc) rc = mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);
    if (fd && close(fd) < 0) rc = -1;
    if (rc) {
        if (!quiet) builtin_error("%s: cannot read or hash input", name);
        return 1;
    }
    for (int i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "%02x", hash[i]);
    return 0;
}

static int sum_needs_escape(const char *s) { return strpbrk(s, "\\\n\r") != NULL; }
static void sum_name(const char *s, int escape)
{
    for (; *s; s++) {
        if (escape && *s == '\\') fputs("\\\\", stdout);
        else if (escape && *s == '\n') fputs("\\n", stdout);
        else if (escape && *s == '\r') fputs("\\r", stdout);
        else putchar((unsigned char)*s);
    }
}

static int sum_unescape(char *s)
{
    char *out = s;
    while (*s) {
        if (*s == '\\') {
            s++;
            if (*s == 'n') *out++ = '\n';
            else if (*s == 'r') *out++ = '\r';
            else if (*s == '\\') *out++ = '\\';
            else return -1;
            s++;
        } else *out++ = *s++;
    }
    *out = 0;
    return 0;
}

static int sum_verify(const char *file, const struct sum_options *o)
{
    FILE *f = !strcmp(file, "-") ? fdopen(dup(0), "r") : fopen(file, "r");
    if (!f) { if (!o->status) builtin_error("%s: %s", file, strerror(errno)); return 1; }
    char *line = NULL;
    size_t cap = 0, number = 0, valid = 0, checked = 0, bad = 0;
    int rc = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, f)) >= 0) {
        number++;
        if (n && line[n-1] == '\n') line[--n] = 0;
        if (n && line[n-1] == '\r') line[--n] = 0;
        if (!n || line[0] == '#') continue;
        if ((size_t)n != strlen(line)) goto malformed;
        char *p = line, *name = NULL, *digest = NULL;
        int escape = *p == '\\';
        if (escape) p++;
        if (!strncmp(p, "SHA256 (", 8)) {
            name = p + 8;
            char *end = strrchr(name, ')');
            if (!end || strncmp(end, ") = ", 4)) goto malformed;
            *end = 0; digest = end + 4;
            if (strlen(digest) != 64) goto malformed;
        } else {
            if (strlen(p) < 67 || p[64] != ' ' || (p[65] != ' ' && p[65] != '*')) goto malformed;
            digest = p; name = p + 66; p[64] = 0;
        }
        for (int i = 0; i < 64; i++) if (!isxdigit((unsigned char)digest[i])) goto malformed;
        if (!*name || (escape && sum_unescape(name))) goto malformed;
        valid++;
        char actual[65]; int missing = 0;
        int failed = sum_digest(name, actual, o->status || o->ignore, &missing);
        if (failed && missing && o->ignore) continue;
        checked++;
        int matches = !failed && !strcasecmp(actual, digest);
        if (!matches) rc = 1;
        if (!o->status && (!o->quiet || !matches)) {
            int escaped = sum_needs_escape(name);
            if (escaped) putchar('\\');
            sum_name(name, escaped);
            printf(": %s\n", matches ? "OK" : failed ? "FAILED open or read" : "FAILED");
        }
        continue;
malformed:
        bad++;
        if (o->warn && !o->status) builtin_error("%s: %zu: improperly formatted SHA256 checksum line", file, number);
    }
    if (ferror(f)) { if (!o->status) builtin_error("%s: read error", file); rc = 1; }
    free(line);
    if (fclose(f)) rc = 1;
    if (!valid) {
        if (!o->status) builtin_error("%s: no properly formatted checksum lines found", file);
        rc = 1;
    } else if (!checked) {
        if (!o->status) builtin_error("%s: no file was verified", file);
        rc = 1;
    }
    if (bad && !o->status && !o->warn) builtin_error("WARNING: %zu improperly formatted checksum line%s", bad, bad == 1 ? "" : "s");
    if (bad && o->strict) rc = 1;
    return rc;
}

int sha256sum_builtin(WORD_LIST *list)
{
    struct sum_options o = {0};
    size_t count = 0;
    for (WORD_LIST *p = list; p; p = p->next) count++;
    const char **files = calloc(count + 1, sizeof *files);
    if (!files) { builtin_error("out of memory"); return 1; }
    size_t used = 0;
    int end_options = 0, rc = 0;
    for (; list; list = list->next) {
        const char *w = list->word->word;
        if (!end_options && !strcmp(w, "--")) { end_options = 1; continue; }
        if (!end_options && !strcmp(w, "--help")) {
            puts("Usage: sha256sum [-bctwz] [--tag] [FILE...]\nCheck options: --quiet --status --strict --warn --ignore-missing\nWith no FILE, or FILE '-', read standard input."); goto done;
        }
        if (!end_options && !strcmp(w, "--version")) { puts("sha256sum (bash-os) 0.1.1"); goto done; }
        if (!end_options && w[0] == '-' && w[1]) {
            if (!strcmp(w, "--binary")) o.binary = 1;
            else if (!strcmp(w, "--text")) o.binary = 0;
            else if (!strcmp(w, "--check")) o.check = 1;
            else if (!strcmp(w, "--zero")) o.zero = 1;
            else if (!strcmp(w, "--tag")) o.tag = 1;
            else if (!strcmp(w, "--quiet")) o.quiet = 1;
            else if (!strcmp(w, "--status")) o.status = 1;
            else if (!strcmp(w, "--strict")) o.strict = 1;
            else if (!strcmp(w, "--warn")) o.warn = 1;
            else if (!strcmp(w, "--ignore-missing")) o.ignore = 1;
            else for (const char *p = w + 1; *p; p++) switch (*p) {
                case 'b': o.binary = 1; break;
                case 't': o.binary = 0; break;
                case 'c': o.check = 1; break;
                case 'w': o.warn = 1; break;
                case 'z': o.zero = 1; break;
                default: builtin_error("invalid option: %s", w); rc = 1; goto done;
            }
        } else files[used++] = w;
    }
    if ((o.check && (o.zero || o.tag)) || (!o.check && (o.quiet || o.status || o.strict || o.warn || o.ignore))) {
        builtin_error("incompatible checksum options"); rc = 1; goto done;
    }
    if (!used) files[used++] = "-";
    for (size_t i = 0; i < used; i++) {
        if (o.check) { rc |= sum_verify(files[i], &o); continue; }
        char hex[65]; int missing;
        if (sum_digest(files[i], hex, 0, &missing)) { rc = 1; continue; }
        int escape = !o.zero && sum_needs_escape(files[i]);
        if (escape) putchar('\\');
        if (o.tag) fputs("SHA256 (", stdout);
        else printf("%s %c", hex, o.binary ? '*' : ' ');
        sum_name(files[i], escape);
        if (o.tag) printf(") = %s", hex);
        putchar(o.zero ? 0 : '\n');
    }
done:
    free(files);
    if (fflush(stdout) || ferror(stdout)) { builtin_error("write error"); clearerr(stdout); rc = 1; }
    return rc;
}

char *sha256sum_doc[] = {
    "Print SHA-256 checksums or verify GNU/BSD checksum files with -c.",
    "-b/-t select the marker; --tag selects BSD output; -z ends records with NUL.",
    "Verification: --quiet, --status, --strict, --warn, --ignore-missing.", NULL
};
struct builtin sha256sum_struct = {
    "sha256sum", sha256sum_builtin, BUILTIN_ENABLED, sha256sum_doc,
    "sha256sum [-bctwz] [--tag] [FILE...]", 0
};
