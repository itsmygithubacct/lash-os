/* SPDX-License-Identifier: MIT */
/* gzip file and filter interface backed by zlib. */
#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "loadables.h"
#include "gzip-stream.h"

struct gzip_options { int decode, stdout_mode, keep, force, test, no_name, level, quiet; const char *suffix; };

static int gzip_same_input(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_size == b->st_size && a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec;
}

static int gzip_one(const char *file, const struct gzip_options *o)
{
    int from_stdin = !strcmp(file, "-");
    int filter = from_stdin || o->stdout_mode || o->test;
    struct stat entry;
    int followed_link = !filter && o->force && lstat(file, &entry) == 0 && S_ISLNK(entry.st_mode);
    /* GNU treats an unforced named-input symlink as an open error, even
       under -q. Filters and explicit -f may follow the input link. */
    int flags = O_RDONLY | O_CLOEXEC | O_NONBLOCK;
    if (!filter && !o->force) flags |= O_NOFOLLOW;
    int in = from_stdin ? 0 : open(file, flags);
    if (in < 0) { builtin_error("%s: %s", file, strerror(errno)); return 1; }
    struct stat st;
    if (fstat(in, &st)) { if (in) close(in); return 1; }
    if (!filter && (!S_ISREG(st.st_mode) || (!o->force && st.st_nlink > 1))) {
        if (!o->quiet) builtin_error("%s: not a regular file with a single link -- unchanged", file);
        close(in); return 2;
    }
    struct stat lst;
    if (!o->force && ((from_stdin && o->decode && isatty(0)) || (filter && !o->decode && !o->test && isatty(1)))) {
        builtin_error("refusing compressed data on a terminal; use -f to override");
        if (in) close(in); return 1;
    }
    char *dest = NULL, *temp = NULL;
    int out = o->test ? -1 : 1, rc = 0;
    if (!filter) {
        size_t len = strlen(file), slen = strlen(o->suffix);
        size_t cut = slen;
        int tgz = 0;
        if (o->decode) {
            if (len <= cut || strcmp(file + len - cut, o->suffix)) {
                if (!strcmp(o->suffix, ".gz") && len > 4 && !strcmp(file + len - 4, ".tgz")) { cut = 4; tgz = 1; }
                else { if (!o->quiet) builtin_error("%s: unknown suffix -- ignored", file); rc = 2; goto done; }
            }
            dest = malloc(len + 5);
            if (dest) { memcpy(dest, file, len - cut); strcpy(dest + len - cut, tgz ? ".tar" : ""); }
        } else {
            if (len >= slen && !strcmp(file + len - slen, o->suffix)) {
                if (!o->quiet) builtin_error("%s: already has suffix %s -- unchanged", file, o->suffix);
                rc = 2; goto done;
            }
            dest = malloc(len + slen + 1);
            if (dest) { strcpy(dest, file); strcat(dest, o->suffix); }
        }
        if (!dest) { rc = 1; goto done; }
        if (!o->force && lstat(dest, &lst) == 0) {
            if (!o->quiet) builtin_error("%s already exists -- unchanged", dest);
            rc = 2; goto done;
        }
        temp = malloc(strlen(dest) + 16);
        if (!temp) { rc = 1; goto done; }
        sprintf(temp, "%s.XXXXXX", dest);
        out = mkstemp(temp);
        if (out < 0) { builtin_error("%s: %s", dest, strerror(errno)); rc = 1; goto done; }
    }
    const char *base = strrchr(file, '/'); base = base ? base + 1 : file;
    unsigned long mtime = 0;
    rc = o->decode ? bgz_decode(in, out, &mtime) :
        bgz_encode(in, out, o->level, o->no_name || from_stdin ? NULL : base,
                   o->no_name || from_stdin ? 0 : (unsigned long)st.st_mtime);
    if (!filter) {
        struct timespec times[2] = { st.st_atim, st.st_mtim };
        if (o->decode && !o->no_name && mtime) { times[1].tv_sec = (time_t)mtime; times[1].tv_nsec = 0; }
        if (fchmod(out, st.st_mode & 0777) || futimens(out, times)) rc = 1;
        if (close(out)) rc = 1;
        out = -1;
        if (!rc) {
            /* Publish only complete streams. -f replaces the directory entry,
               never follows an existing destination symlink. */
            if (o->force ? rename(temp, dest) : link(temp, dest)) {
                builtin_error("%s: %s", dest, strerror(errno)); rc = 1;
            } else if (!o->keep) {
                struct stat current;
                int unchanged = lstat(file, &lst) == 0;
                if (followed_link)
                    unchanged = unchanged && gzip_same_input(&lst, &entry) &&
                        fstat(in, &current) == 0 && gzip_same_input(&current, &st);
                else
                    unchanged = unchanged && gzip_same_input(&lst, &st);
                if (!unchanged) {
                    builtin_error("%s changed while processing -- input retained", file); rc = 1;
                } else if (unlink(file)) { builtin_error("%s: %s", file, strerror(errno)); rc = 1; }
            }
        }
    }
done:
    if (!from_stdin && close(in)) rc = 1;
    if (temp) { unlink(temp); free(temp); }
    free(dest);
    return rc;
}

int gzip_builtin(WORD_LIST *list)
{
    struct gzip_options o = { .level = 6, .suffix = ".gz" };
    size_t count = 0;
    for (WORD_LIST *p = list; p; p = p->next) count++;
    const char **files = calloc(count + 1, sizeof *files);
    if (!files) { builtin_error("out of memory"); return 1; }
    size_t used = 0;
    int end_options = 0, rc = 0;
    for (; list; list = list->next) {
        const char *w = list->word->word, *opts = NULL;
        if (!end_options && !strcmp(w, "--")) { end_options = 1; continue; }
        if (!end_options && !strcmp(w, "--help")) {
            puts("Usage: gzip [-cdfkntq1-9] [-S SUFFIX] [FILE...]\nCompress files to .gz, or filter stdin. -d decompresses, -c writes stdout,\n-k keeps input, -f overwrites, -t checks integrity, -n omits name/time."); goto done;
        }
        if (!end_options && !strcmp(w, "--version")) { puts("gzip (bash-os) 0.1.1"); goto done; }
        if (!end_options && !strcmp(w, "--decompress")) opts = "d";
        else if (!end_options && !strcmp(w, "--uncompress")) opts = "d";
        else if (!end_options && (!strcmp(w, "--stdout") || !strcmp(w, "--to-stdout"))) opts = "c";
        else if (!end_options && !strcmp(w, "--keep")) opts = "k";
        else if (!end_options && !strcmp(w, "--force")) opts = "f";
        else if (!end_options && !strcmp(w, "--test")) opts = "t";
        else if (!end_options && !strcmp(w, "--no-name")) opts = "n";
        else if (!end_options && !strcmp(w, "--quiet")) opts = "q";
        else if (!end_options && !strcmp(w, "--fast")) opts = "1";
        else if (!end_options && !strcmp(w, "--best")) opts = "9";
        else if (!end_options && !strncmp(w, "--suffix=", 9)) { o.suffix = w + 9; continue; }
        else if (!end_options && !strcmp(w, "--suffix")) opts = "S";
        else if (!end_options && w[0] == '-' && w[1]) opts = w + 1;
        if (opts) {
            for (; *opts; opts++) switch (*opts) {
                case 'c': o.stdout_mode = 1; break;
                case 'd': o.decode = 1; break;
                case 'k': o.keep = 1; break;
                case 'f': o.force = 1; break;
                case 't': o.test = o.decode = 1; break;
                case 'n': o.no_name = 1; break;
                case 'q': o.quiet = 1; break;
                case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9': o.level = *opts - '0'; break;
                case 'S':
                    if (opts[1]) { o.suffix = opts + 1; opts += strlen(opts) - 1; }
                    else { if (!(list = list->next)) goto invalid; o.suffix = list->word->word; }
                    break;
                default: goto invalid;
            }
        } else files[used++] = w;
    }
    if (!*o.suffix || strchr(o.suffix, '/')) goto invalid;
    if (!used) files[used++] = "-";
    for (size_t i = 0; i < used; i++) {
        int result = gzip_one(files[i], &o);
        if (result == 1 || !rc) rc = result;
    }
    goto done;
invalid:
    builtin_error("unsupported option or invalid argument; try gzip --help"); rc = 1;
done:
    free(files);
    if (fflush(stdout) || ferror(stdout)) { clearerr(stdout); rc = 1; }
    return rc;
}

char *gzip_doc[] = {
    "Compress/decompress gzip files or stdin, including concatenated members.",
    "-c stdout, -d decompress, -k keep, -f force, -t test, -n no name/time,",
    "-1..-9 compression level, -S suffix, -q quiet. Checks CRC and truncation.",
    "Unsupported: recursive traversal, listing statistics, and -N name restoration.", NULL
};
struct builtin gzip_struct = {
    "gzip", gzip_builtin, BUILTIN_ENABLED, gzip_doc, "gzip [-cdfkntq1-9] [-S SUFFIX] [FILE...]", 0
};
