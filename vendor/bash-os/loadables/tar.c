/* SPDX-License-Identifier: MIT */
/* GNU-style tar interface to bash-os's ustar/PAX archive engine. */
#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include "loadables.h"
#include "pax-stream.h"
#include "gzip-stream.h"

struct tar_arg { const char *text; int directory; };

int tar_builtin(WORD_LIST *list)
{
    size_t count = 0;
    for (WORD_LIST *p = list; p; p = p->next) count++;
    struct tar_arg *args = calloc(count + 1, sizeof *args);
    const char **members = calloc(count + 1, sizeof *members);
    if (!args || !members) { free(args); free(members); builtin_error("out of memory"); return 2; }
    size_t used = 0, member_count = 0;
    int mode = 0, zip = 0, verbose = 0, end_options = 0, first = 1, no_recurse = 0;
    int saved = -1, rc = 0;
    const char *archive = "-";
    FILE *stream = NULL, *temporary = NULL;
    struct bashos_pax_write_context writer = {0};
    struct bashos_pax_read_options read_options = { .tar_mode = 1 };
    for (; list; list = list->next) {
        const char *w = list->word->word, *opts = NULL, *value = NULL;
        char value_option = 0;
        int old_style = first && *w && w[0] != '-';
        first = 0;
        if (!end_options && !strcmp(w, "--")) { end_options = 1; continue; }
        if (!end_options && !strcmp(w, "--help")) {
            puts("Usage: tar -c|-t|-x [-zv] [-f ARCHIVE] [-C DIR] [FILE...]\nCreate, list, or extract ustar/PAX archives. '-' means stdin/stdout.\n-O extracts to stdout; --strip-components=N removes leading path components.\n-p preserves permissions; --no-recursion archives only directory entries."); goto done;
        }
        if (!end_options && !strcmp(w, "--version")) { puts("tar (bash-os) 0.1.1"); goto done; }
        if (!end_options && !strcmp(w, "--create")) opts = "c";
        else if (!end_options && !strcmp(w, "--extract")) opts = "x";
        else if (!end_options && !strcmp(w, "--get")) opts = "x";
        else if (!end_options && !strcmp(w, "--list")) opts = "t";
        else if (!end_options && (!strcmp(w, "--gzip") || !strcmp(w, "--gunzip"))) opts = "z";
        else if (!end_options && !strcmp(w, "--verbose")) opts = "v";
        else if (!end_options && !strcmp(w, "--to-stdout")) opts = "O";
        else if (!end_options && !strcmp(w, "--same-permissions")) opts = "p";
        else if (!end_options && !strcmp(w, "--no-recursion")) { no_recurse = 1; continue; }
        else if (!end_options && !strcmp(w, "--file")) opts = "f";
        else if (!end_options && !strcmp(w, "--directory")) opts = "C";
        else if (!end_options && !strncmp(w, "--file=", 7)) { value_option = 'f'; value = w + 7; }
        else if (!end_options && !strncmp(w, "--directory=", 12)) { value_option = 'C'; value = w + 12; }
        else if (!end_options && (!strcmp(w, "--strip-components") || !strncmp(w, "--strip-components=", 19))) {
            value = w + 18;
            if (*value == '=') value++;
            else { if (!(list = list->next)) goto invalid; value = list->word->word; }
            char *end; errno = 0;
            unsigned long n = strtoul(value, &end, 10);
            if (!*value || *value == '-' || *end || errno || n > UINT_MAX) goto invalid;
            read_options.strip = (unsigned)n; continue;
        }
        else if (!end_options && w[0] == '-' && w[1]) opts = w + 1;
        else if (!end_options && old_style) opts = w;
        if (opts) {
            for (; *opts; opts++) {
                if (*opts == 'c' || *opts == 't' || *opts == 'x') {
                    if (mode && mode != *opts) goto invalid;
                    mode = *opts;
                } else if (*opts == 'z') zip = 1;
                else if (*opts == 'v') verbose = 1;
                else if (*opts == 'O') read_options.to_stdout = 1;
                else if (*opts == 'p') read_options.preserve = 1;
                else if (*opts == 'f' || *opts == 'C') {
                    char option = *opts;
                    if (!old_style && opts[1]) { value = opts + 1; opts += strlen(opts) - 1; }
                    else { if (!(list = list->next)) goto invalid; value = list->word->word; }
                    if (option == 'f') archive = value;
                    else args[used++] = (struct tar_arg){value, 1};
                } else goto invalid;
            }
        } else if (value_option == 'f') archive = value;
        else if (value_option == 'C') args[used++] = (struct tar_arg){value, 1};
        else { args[used++] = (struct tar_arg){w, 0}; members[member_count++] = w; }
    }
    if (!mode || (mode == 'c' && !member_count)) goto invalid;
    if (mode == 'c' && (read_options.to_stdout || read_options.strip)) goto invalid;
    saved = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (saved < 0) { builtin_error("save working directory: %s", strerror(errno)); rc = 2; goto done; }
    /* Open the archive before -C affects member paths. */
    if (!strcmp(archive, "-")) {
        int fd = dup(mode == 'c' ? 1 : 0);
        stream = fd < 0 ? NULL : fdopen(fd, mode == 'c' ? "wb" : "rb");
        if (!stream && fd >= 0) close(fd);
    } else stream = fopen(archive, mode == 'c' ? "wb" : "rb");
    if (!stream) { builtin_error("%s: %s", archive, strerror(errno)); rc = 2; goto done; }
    FILE *payload = stream;
    if (zip) {
        temporary = tmpfile();
        if (!temporary) { builtin_error("temporary archive: %s", strerror(errno)); rc = 2; goto done; }
        payload = temporary;
        if (mode != 'c') {
            if (bgz_decode(fileno(stream), fileno(temporary), NULL) || fseek(temporary, 0, SEEK_SET)) { rc = 2; goto done; }
        }
    }
    if (mode == 'c') {
        writer.no_recurse = no_recurse;
        for (size_t i = 0; i < used; i++) {
            if (args[i].directory) {
                if (chdir(args[i].text)) { builtin_error("%s: %s", args[i].text, strerror(errno)); rc = 2; break; }
            } else {
                if (args[i].text[0] == '/') { builtin_error("use -C with relative archive members"); rc = 2; break; }
                if (verbose) fprintf(!strcmp(archive, "-") ? stderr : stdout, "%s\n", args[i].text);
                if (bashos_pax_write_member_context(payload, args[i].text, &writer)) rc = 2;
            }
        }
        unsigned char zero[1024] = {0};
        if (fwrite(zero, 1, sizeof zero, payload) != sizeof zero || fflush(payload)) rc = 2;
        if (!rc && zip) {
            if (fseek(payload, 0, SEEK_SET) || bgz_encode(fileno(payload), fileno(stream), 6, NULL, 0)) rc = 2;
        }
    } else {
        for (size_t i = 0; i < used; i++) if (args[i].directory && chdir(args[i].text)) {
            builtin_error("%s: %s", args[i].text, strerror(errno)); rc = 2; goto done;
        }
        read_options.extract = mode == 'x'; read_options.verbose = verbose;
        read_options.members = members; read_options.count = member_count;
        if (bashos_pax_read(payload, &read_options)) rc = 2;
    }
    goto done;
invalid:
    builtin_error("unsupported option, missing argument, or conflicting operation; try tar --help"); rc = 2;
done:
    bashos_pax_write_clear(&writer);
    if (temporary && fclose(temporary)) rc = 2;
    if (stream && fclose(stream)) rc = 2;
    if (saved >= 0) {
        if (fchdir(saved)) { builtin_error("restore working directory: %s", strerror(errno)); rc = 2; }
        close(saved);
    }
    free(args); free(members);
    if (fflush(stdout) || ferror(stdout)) { clearerr(stdout); rc = 2; }
    return rc;
}

char *tar_doc[] = {
    "Create (-c), list (-t), or extract (-x) ustar/PAX archives; -f selects the archive.",
    "Supports -C directory, -z gzip, -v, -O stdout, -p permissions, --strip-components.",
    "Uses the pax engine. Unsupported options fail instead of being ignored.",
    "Preserves regular-file hardlinks with nonconflicting member names; supports FIFOs.",
    "No append/update, sparse/device entries, absolute member names or automatic compression detection.", NULL
};
struct builtin tar_struct = {
    "tar", tar_builtin, BUILTIN_ENABLED, tar_doc, "tar -c|-t|-x [-zv] [-f ARCHIVE] [-C DIR] [FILE...]", 0
};
