/* SPDX-License-Identifier: MIT */
/* tail.c — POSIX tail(1) as a bash builtin.
 *
 *   tail [-n N | -N] [-c BYTES] [-f|-F] [-q|-v] [FILE...]
 *
 * Flags: -n N (or POSIX shorthand -N), -c BYTES, -f follow,
 * -F follow by name and retry after rotation/disappearance.
 *
 * Follow mode (-f): after printing the initial tail, watches the file
 * for IN_MODIFY events via inotify(7). On each event, reads any newly-
 * appended bytes and writes them to stdout. Loops until SIGINT/SIGTERM.
 * Multi-file follow watches all files concurrently in one inotify
 * instance and prefixes each output chunk with `==> FILE <==` on
 * source switch.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
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
#include <limits.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/inotify.h>
#include <sys/stat.h>

#include "loadables.h"

/* Never read through Bash's long-lived stdin FILE: its EOF flag and
   buffer survive a builtin call, so the second `tail -n 1 < file` in
   one shell prints nothing. Duplicate fd 0 for this invocation. */
static FILE *
bt_open_stdin (void)
{
    int fd = dup (STDIN_FILENO);
    FILE *f = fd < 0 ? NULL : fdopen (fd, "r");
    if (!f) {
        int e = errno;
        if (fd >= 0) close (fd);
        builtin_error ("stdin: %s", strerror (e));
        return NULL;
    }
    if (lseek (fd, 0, SEEK_CUR) == (off_t) -1)
        setvbuf (f, NULL, _IONBF, 0);
    return f;
}

static int
bt_close_stdin (FILE *f)
{
    int rc = 0;
    if (!f) return 0;
    /* Return unread stdio bytes to the shared descriptor before fclose
       drops the duplicate. */
    if (lseek (fileno (f), 0, SEEK_CUR) != (off_t) -1 &&
        fseeko (f, 0, SEEK_CUR) != 0)
        rc = -1;
    if (fclose (f) != 0)
        rc = -1;
    return rc;
}

static int
bt_write (const void *p, size_t n)
{
    if (n == 0) return 0;
    if (fwrite (p, 1, n, stdout) != n || ferror (stdout)) {
        builtin_error ("write error: %s", strerror (errno ? errno : EIO));
        return -1;
    }
    return 0;
}

/* Print last N lines of a seekable file by reading it from the END: blocks
   backwards until N+1 delimiters (or the start) are found, then copy from
   there. Measured on the appliance (2026-09-06): the ring below read an
   89 KB log from the start for `tail -n 1` at 3.2 ms; `tail -c 100` on the
   same file, which seeks, took 0.55 ms. Returns 1 if it did the job, 0 if
   the stream is not seekable (a pipe, a tty) and the ring must run. */
static int
bt_tail_lines_seek (FILE *f, int n, char delim)
{
    /* the stream may not be at its start (`{ read x; tail -n 5; } < file`):
       GNU tail reads from the current offset, so never look before it */
    off_t begin = ftello (f);
    if (begin < 0) { clearerr (f); return 0; }
    if (fseeko (f, 0, SEEK_END) != 0) { clearerr (f); return 0; }
    off_t size = ftello (f);
    if (size < 0) { clearerr (f); return 0; }
    if (size <= begin) return 1;
    char buf[8192];
    off_t pos = size;
    long long seen = 0;               /* delimiters found, from the end */
    off_t start = begin;              /* where the output begins */
    int found = 0;
    /* a trailing delimiter ends the last line; it must not count as a line
       boundary before it */
    int trailing = 0;
    {
        if (fseeko (f, size - 1, SEEK_SET) != 0) { clearerr (f); return 0; }
        int c = fgetc (f);
        trailing = (c == (unsigned char) delim);
    }
    while (pos > begin && !found) {
        size_t want = (size_t) (pos - begin > (off_t) sizeof buf ? (off_t) sizeof buf : pos - begin);
        pos -= (off_t) want;
        if (fseeko (f, pos, SEEK_SET) != 0) { clearerr (f); return 0; }
        if (fread (buf, 1, want, f) != want) { clearerr (f); return 0; }
        for (size_t i = want; i > 0; i--) {
            if (buf[i - 1] == delim) {
                if (trailing && pos + (off_t) i == size) continue;   /* the trailing one */
                seen++;
                if (seen == n) { start = pos + (off_t) i; found = 1; break; }
            }
        }
    }
    if (fseeko (f, start, SEEK_SET) != 0) { clearerr (f); return 0; }
    size_t r;
    while ((r = fread (buf, 1, sizeof buf, f)) > 0)
        if (bt_write (buf, r) < 0) return -1;
    return 1;
}

/* Print last N lines of one file/stream. Implementation: ring buffer of
   size N, capturing recent lines. After EOF, emit the buffer in order.
   A seekable file takes the path above instead. */
static int
bt_tail_lines (FILE *f, int n, char delim)
{
    if (n <= 0) return 0;
    int sk = bt_tail_lines_seek (f, n, delim);
    if (sk < 0) return -1;
    if (sk > 0) return 0;
    char **ring = calloc ((size_t) n, sizeof *ring);
    int *rcap = calloc ((size_t) n, sizeof *rcap);
    if (!ring || !rcap) {
        free (ring); free (rcap);
        builtin_error ("memory exhausted");
        return -1;
    }
    int head = 0, count = 0, oom = 0;
    char *line = NULL; size_t cap = 0; ssize_t rd;
    errno = 0;
    while ((rd = getdelim (&line, &cap, delim, f)) != -1) {
        /* Grow the occupied slot in place. Freeing first, then failing
           malloc, left a dangling pointer for the emit/cleanup loops. */
        char *p = realloc (ring[head], (size_t) rd + 1);
        if (!p) { oom = 1; break; }
        memcpy (p, line, (size_t) rd);
        ring[head] = p;
        rcap[head] = (int) rd;
        head = (head + 1) % n;
        if (count < n) count++;
    }
    if (!oom && ferror (f) && errno == ENOMEM)
        oom = 1;
    free (line);
    int status = 0;
    if (oom) {
        builtin_error ("memory exhausted");
        status = -1;
    } else {
        int start = (count == n) ? head : 0;
        for (int i = 0; i < count; i++) {
            int idx = (start + i) % n;
            if (ring[idx] && bt_write (ring[idx], (size_t) rcap[idx]) < 0) {
                status = -1;
                break;
            }
        }
    }
    for (int i = 0; i < n; i++) free (ring[i]);
    free (ring); free (rcap);
    return status;
}

static int
bt_tail_lines_from (FILE *f, long long start, char delim)
{
    if (start < 1) start = 1;
    char *line = NULL;
    size_t cap = 0;
    ssize_t rd;
    long long nr = 1;
    while ((rd = getdelim (&line, &cap, delim, f)) != -1) {
        if (nr >= start && bt_write (line, (size_t) rd) < 0) {
            free (line);
            return -1;
        }
        nr++;
    }
    free (line);
    return 0;
}

/* Print last C bytes. Seek if regular file, else buffer-and-trim. */
static int
bt_tail_bytes (FILE *f, long long c)
{
    if (c <= 0) return 0;
    /* Try seek-end first, but never look behind the current offset. */
    off_t begin = ftello (f);
    if (begin >= 0 && fseeko (f, 0, SEEK_END) == 0) {
        off_t sz = ftello (f);
        if (sz >= 0) {
            off_t off = (sz - begin > c) ? sz - c : begin;
            if (fseeko (f, off, SEEK_SET) == 0) {
                char buf[8192];
                size_t r;
                while ((r = fread (buf, 1, sizeof buf, f)) > 0)
                    if (bt_write (buf, r) < 0) return -1;
                return 0;
            }
        }
        clearerr (f);
        if (fseeko (f, begin, SEEK_SET) != 0) clearerr (f);
    } else {
        clearerr (f);
    }
    /* Stream fallback: buffer up to last C bytes. Must read to EOF
       before any output, matching GNU. */
    char *buf = malloc ((size_t) c);
    if (!buf) {
        builtin_error ("memory exhausted");
        return -1;
    }
    size_t total = 0;
    int rd;
    while ((rd = fgetc (f)) != EOF) {
        if (total < (size_t) c) buf[total++] = (char) rd;
        else {
            memmove (buf, buf + 1, (size_t) c - 1);
            buf[c - 1] = (char) rd;
        }
    }
    int status = bt_write (buf, total);
    free (buf);
    return status;
}

static int
bt_tail_bytes_from (FILE *f, long long start)
{
    if (start < 1) start = 1;
    off_t off = (off_t) (start - 1);
    if (fseeko (f, off, SEEK_SET) != 0) {
        long long skipped = 0;
        while (skipped < start - 1) {
            if (fgetc (f) == EOF) return 0;
            skipped++;
        }
    }
    char buf[8192];
    size_t r;
    while ((r = fread (buf, 1, sizeof buf, f)) > 0)
        if (bt_write (buf, r) < 0) return -1;
    return 0;
}

/* GNU tail NUM multiplier suffixes (matching `tail --help`):
   b=512, kB=1000, K/KiB=1024, MB=1000^2, M/MiB=1024^2, GB=1000^3,
   G/GiB=1024^3. Returns the multiplier, or 0 if SUF is unrecognized. */
static long long
bt_suffix_mult (const char *suf)
{
    static const struct { const char *s; long long m; } tab[] = {
        { "b",   512LL },
        { "kB",  1000LL },            { "KB",  1000LL },
        { "k",   1024LL },            { "K",   1024LL },  { "KiB", 1024LL },
        { "MB",  1000000LL },         { "M",   1048576LL }, { "MiB", 1048576LL },
        { "GB",  1000000000LL },      { "G",   1073741824LL }, { "GiB", 1073741824LL },
        { NULL, 0 }
    };
    for (int i = 0; tab[i].s; i++)
        if (!strcmp (suf, tab[i].s))
            return tab[i].m;
    return 0;
}

static int
bt_parse_count (const char *s, const char *what, int allow_sign,
                int *from_start, long long *out)
{
    char *end = NULL;
    long long n;
    int local_from_start = 0;

    if (s == NULL || *s == '\0') {
        builtin_error ("%s needs N", what);
        builtin_usage ();
        return -1;
    }
    if (*s == '+') {
        local_from_start = 1;
        s++;
    } else if (allow_sign && *s == '-') {
        s++;
    }
    if (*s == '\0') {
        builtin_error ("%s needs a non-negative count", what);
        builtin_usage ();
        return -1;
    }
    errno = 0;
    n = strtoll (s, &end, 10);
    if (errno || end == s || n < 0) {
        builtin_error ("%s needs a non-negative count", what);
        builtin_usage ();
        return -1;
    }
    /* Optional GNU multiplier suffix (e.g. 1K, 512b, 4M). */
    if (*end) {
        long long mult = bt_suffix_mult (end);
        if (mult == 0 || (mult > 1 && n > INT_MAX / mult)) {
            builtin_error ("%s: invalid number: %s", what, s);
            builtin_usage ();
            return -1;
        }
        n *= mult;
    }
    if (n > INT_MAX) {
        builtin_error ("%s needs a non-negative count", what);
        builtin_usage ();
        return -1;
    }
    if (from_start)
        *from_start = local_from_start;
    *out = n;
    return 0;
}

/* Follow mode (-f). After the initial tail of each file is printed,
   watches each FILE via inotify for IN_MODIFY / IN_MOVE_SELF /
   IN_DELETE_SELF and emits appended bytes. POSIX-shape: line-buffered
   writes; multi-file separators on source switch. Loops until SIGINT
   (the parent shell's signal disposition propagates here). */
struct bt_follow_file {
    char *path;
    int wd;
    int fd;
    int read_from_start;
};

static void
bt_follow_close_one (struct bt_follow_file *f)
{
    if (f->fd >= 0) close (f->fd);
    f->fd = -1;
    f->wd = -1;
}

static int
bt_follow_open_one (int infd, struct bt_follow_file *f, int retry)
{
    int fd = open (f->path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    int wd = inotify_add_watch (infd, f->path,
                                IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF |
                                IN_ATTRIB);
    if (wd < 0) {
        close (fd);
        return -1;
    }

    f->fd = fd;
    f->wd = wd;
    if (retry && f->read_from_start)
        lseek (f->fd, 0, SEEK_SET);
    else
        lseek (f->fd, 0, SEEK_END);
    return 0;
}

static int
bt_follow_drain_one (struct bt_follow_file *f, int idx, int n_paths,
                     int *last_emitted, char *buf, size_t bufsz)
{
    if (f->fd < 0) return 0;
    if (n_paths > 1 && *last_emitted != idx) {
        if (printf ("\n==> %s <==\n", f->path) < 0 || ferror (stdout)) {
            builtin_error ("write error: %s", strerror (errno ? errno : EIO));
            return -1;
        }
        *last_emitted = idx;
    }
    ssize_t r;
    while ((r = read (f->fd, buf, bufsz)) > 0)
        if (bt_write (buf, (size_t) r) < 0) return -1;
    if (fflush (stdout) == EOF) {
        builtin_error ("write error: %s", strerror (errno ? errno : EIO));
        return -1;
    }
    return 0;
}

static int
bt_follow (char **paths, int n_paths, int retry)
{
    /* Open one inotify fd; one watch per path; track per-path the file
       descriptor + last read offset. */
    int infd = inotify_init1 (IN_CLOEXEC);
    if (infd < 0) {
        builtin_error ("inotify_init1: %s", strerror (errno));
        return -1;
    }
    struct bt_follow_file *files = calloc ((size_t) n_paths, sizeof *files);
    if (!files) { close (infd); return -1; }
    for (int i = 0; i < n_paths; i++) {
        files[i].path = paths[i];
        files[i].wd = -1;
        files[i].fd = -1;
        files[i].read_from_start = 0;
        if (bt_follow_open_one (infd, &files[i], retry) < 0) {
            if (!retry)
                builtin_error ("inotify_add_watch %s: %s", paths[i], strerror (errno));
            files[i].read_from_start = 1;
        }
    }

    int last_emitted = -1;
    int follow_rc = 0;
    char buf[8192];
    char evbuf[4096] __attribute__((aligned (8)));
    for (;;) {
        if (retry) {
            for (int i = 0; i < n_paths; i++) {
                if (files[i].fd < 0 &&
                    bt_follow_open_one (infd, &files[i], retry) == 0) {
                    if (bt_follow_drain_one (&files[i], i, n_paths, &last_emitted,
                                             buf, sizeof buf) < 0) {
                        follow_rc = -1;
                        break;
                    }
                }
            }
            if (follow_rc < 0) break;
        }

        struct pollfd pfd;
        pfd.fd = infd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int prc = poll (&pfd, 1, retry ? 250 : -1);
        if (prc < 0) {
            if (errno == EINTR) continue;
            builtin_error ("inotify poll: %s", strerror (errno));
            break;
        }
        if (prc == 0) continue;

        ssize_t nread = read (infd, evbuf, sizeof evbuf);
        if (nread < 0) {
            if (errno == EINTR) continue;
            builtin_error ("inotify read: %s", strerror (errno));
            break;
        }
        if (nread == 0) continue;
        for (char *p = evbuf; p < evbuf + nread; ) {
            struct inotify_event *e = (struct inotify_event *) p;
            int idx = -1;
            for (int i = 0; i < n_paths; i++) if (files[i].wd == e->wd) { idx = i; break; }
            p += sizeof (struct inotify_event) + e->len;
            if (idx < 0) continue;

            if (e->mask & (IN_MOVE_SELF | IN_DELETE_SELF | IN_IGNORED)) {
                /* -f follows the original file descriptor; -F follows the
                   pathname and retries after rotation or disappearance. */
                if (retry) {
                    bt_follow_close_one (&files[idx]);
                    files[idx].read_from_start = 1;
                }
                continue;
            }
            if (!(e->mask & IN_MODIFY)) continue;

            if (bt_follow_drain_one (&files[idx], idx, n_paths, &last_emitted,
                                     buf, sizeof buf) < 0) {
                follow_rc = -1;
                break;
            }
        }
        if (follow_rc < 0) break;
    }
    for (int i = 0; i < n_paths; i++) if (files[i].fd >= 0) close (files[i].fd);
    close (infd);
    free (files);
    return follow_rc;
}

static int
bt_process (FILE *f, long long n_bytes, int from_start, long long start_count,
            int n_lines, char delim)
{
    if (n_bytes >= 0) {
        if (from_start) return bt_tail_bytes_from (f, start_count);
        return bt_tail_bytes (f, n_bytes);
    }
    if (from_start) return bt_tail_lines_from (f, start_count, delim);
    return bt_tail_lines (f, n_lines, delim);
}

int
tail_builtin (WORD_LIST *list)
{
    int n_lines = 10;
    long long n_bytes = -1;
    int from_start = 0;
    long long start_count = 1;
    int follow = 0;
    int follow_retry = 0;
    int quiet = 0;
    int verbose = 0;
    char delim = '\n';     /* -z/--zero-terminated switches this to NUL */
    /* Parse flags. */
    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version") || !strcmp (w, "-V")) {
            puts ("bashtail 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-n")) {
            long long n;
            if (!list->next) { builtin_error ("-n needs N"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            if (bt_parse_count (list->word->word, "-n", 1, &from_start, &n) != 0) return EX_USAGE;
            if (from_start) start_count = n;
            else            n_lines = (int) n;
            n_bytes = -1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--lines")) {
            long long n;
            if (!list->next) { builtin_error ("--lines needs N"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            if (bt_parse_count (list->word->word, "--lines", 1, &from_start, &n) != 0) return EX_USAGE;
            if (from_start) start_count = n;
            else            n_lines = (int) n;
            n_bytes = -1;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--lines=", 8)) {
            long long n;
            const char *v = w + 8;
            if (bt_parse_count (v, "--lines", 1, &from_start, &n) != 0) return EX_USAGE;
            if (from_start) start_count = n;
            else            n_lines = (int) n;
            n_bytes = -1;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-n", 2) && (w[2] == '+' || w[2] == '-' || (w[2] >= '0' && w[2] <= '9'))) {
            long long n;
            if (bt_parse_count (w + 2, "-n", 1, &from_start, &n) != 0) return EX_USAGE;
            if (from_start) start_count = n;
            else            n_lines = (int) n;
            n_bytes = -1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-c")) {
            long long n;
            if (!list->next) { builtin_error ("-c needs N"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            if (bt_parse_count (list->word->word, "-c", 1, &from_start, &n) != 0) return EX_USAGE;
            if (from_start) { start_count = n; n_bytes = 0; }
            else            n_bytes = n;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--bytes")) {
            long long n;
            if (!list->next) { builtin_error ("--bytes needs N"); builtin_usage (); return EX_USAGE; }
            list = list->next;
            if (bt_parse_count (list->word->word, "--bytes", 1, &from_start, &n) != 0) return EX_USAGE;
            if (from_start) { start_count = n; n_bytes = 0; }
            else            n_bytes = n;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--bytes=", 8)) {
            long long n;
            const char *v = w + 8;
            if (bt_parse_count (v, "--bytes", 1, &from_start, &n) != 0) return EX_USAGE;
            if (from_start) { start_count = n; n_bytes = 0; }
            else            n_bytes = n;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-c", 2) && (w[2] == '+' || w[2] == '-' || (w[2] >= '0' && w[2] <= '9'))) {
            long long n;
            if (bt_parse_count (w + 2, "-c", 1, &from_start, &n) != 0) return EX_USAGE;
            if (from_start) { start_count = n; n_bytes = 0; }
            else            n_bytes = n;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-f") || !strcmp (w, "--follow") || !strcmp (w, "--follow=descriptor")) {
            follow = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-F") || !strcmp (w, "--follow=name") || !strcmp (w, "--retry")) {
            follow = 1;
            follow_retry = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-q") || !strcmp (w, "--quiet") || !strcmp (w, "--silent")) {
            quiet = 1;
            verbose = 0;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-v") || !strcmp (w, "--verbose")) {
            verbose = 1;
            quiet = 0;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-z") || !strcmp (w, "--zero-terminated")) {
            delim = '\0';
            list = list->next;
            continue;
        }
        /* POSIX shorthand: -N (digits only). */
        if (w[1] >= '0' && w[1] <= '9') {
            long long n;
            from_start = 0;
            n_bytes = -1;
            if (bt_parse_count (w + 1, "-n", 0, NULL, &n) != 0) return EX_USAGE;
            n_lines = (int) n;
            list = list->next;
            continue;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    int n_files = 0;
    for (WORD_LIST *p = list; p; p = p->next) n_files++;
    int rc = EXECUTION_SUCCESS;
    FILE *stdin_f = NULL;
    if (n_files == 0) {
        if (follow) {
            builtin_error ("-f requires at least one FILE (cannot follow stdin)");
            return EX_USAGE;
        }
        stdin_f = bt_open_stdin ();
        if (!stdin_f) return EXECUTION_FAILURE;
        if (bt_process (stdin_f, n_bytes, from_start, start_count,
                        n_lines, delim) < 0)
            rc = EXECUTION_FAILURE;
        if (fflush (stdout) == EOF) {
            builtin_error ("write error: %s", strerror (errno ? errno : EIO));
            rc = EXECUTION_FAILURE;
        }
    } else {
        /* Initial tails. */
        char **paths = follow ? calloc ((size_t) n_files, sizeof (char *)) : NULL;
        int p_idx = 0;
        int first = 1;
        int initial_zero = !from_start &&
            ((n_bytes >= 0 && n_bytes == 0) || (n_bytes < 0 && n_lines == 0));
        int show_headers = !initial_zero && !quiet && (verbose || n_files > 1);
        for (WORD_LIST *p = list; p; p = p->next) {
            /* GNU treats "-" as standard input (header "standard input"). */
            int is_stdin = (strcmp (p->word->word, "-") == 0);
            FILE *f;
            if (is_stdin) {
                if (!stdin_f) stdin_f = bt_open_stdin ();
                f = stdin_f;
            } else {
                f = fopen (p->word->word, "r");
            }
            if (!f) {
                /* Match GNU tail's open-failure diagnostic. */
                if (!is_stdin)
                    builtin_error ("cannot open '%s' for reading: %s",
                                   p->word->word, strerror (errno));
                rc = EXECUTION_FAILURE;
                if (paths && follow_retry)
                    paths[p_idx++] = p->word->word;
                continue;
            }
            if (show_headers) {
                if (!first) putchar ('\n');
                printf ("==> %s <==\n", is_stdin ? "standard input" : p->word->word);
            }
            first = 0;
            if (!initial_zero) {
                if (bt_process (f, n_bytes, from_start, start_count,
                                n_lines, delim) < 0)
                    rc = EXECUTION_FAILURE;
            }
            if (!is_stdin) fclose (f);
            /* Don't add "-" (stdin) to the inotify follow set — it can't be
               watched by pathname; GNU likewise won't follow a stdin pipe. */
            if (paths && !is_stdin) paths[p_idx++] = p->word->word;
        }
        if (fflush (stdout) == EOF) {
            builtin_error ("write error: %s", strerror (errno ? errno : EIO));
            rc = EXECUTION_FAILURE;
        }
        if (follow && p_idx > 0) {
            if (bt_follow (paths, p_idx, follow_retry) < 0)
                rc = EXECUTION_FAILURE;
        }
        free (paths);
    }
    if (stdin_f && bt_close_stdin (stdin_f) < 0)
        rc = EXECUTION_FAILURE;
    return rc;
}

char *tail_doc[] = {
    "Print the last N lines (default 10) of FILE(s) or stdin.",
    "",
    "    bashtail [-n N|-n +N|-N] [-c BYTES|-c +BYTES] [-f|-F]",
    "             [-q|-v] [FILE...]",
    "",
    "    -n N       last N lines (default 10)",
    "    -n +N      start at line N (1-based)",
    "    -N         POSIX shorthand for -n N",
    "    -c BYTES   last BYTES bytes",
    "    -c +BYTES  start at byte BYTES (1-based)",
    "    -f         follow: after the initial tail, watch each FILE via",
    "               inotify(7) and emit appended bytes until interrupted",
    "    -F         follow by name: retry missing files and reopen after",
    "               rotation, emitting data from the replacement file",
    "    -q         never print multi-file headers",
    "    -v         always print file headers",
    "    -z         line delimiter is NUL, not newline (--zero-terminated)",
    "    -c N also accepts a GNU multiplier suffix (b=512, K=1024, kB=1000,",
    "    M=1024^2, MB=1000^2, G, GB, ...). A FILE of `-` reads standard input.",
    "    --help | --version",
    "               show usage or version",
    "",
    "Multi-file: prints `==> FILE <==` headers by default; in -f mode,",
    "also on source switch.",
    (char *)NULL
};

struct builtin tail_struct = {
    "tail",
    tail_builtin,
    BUILTIN_ENABLED,
    tail_doc,
    "tail [-n N|-n +N|-N] [-c BYTES|-c +BYTES] [-f|-F] [-q|-v] [FILE...]",
    0
};
