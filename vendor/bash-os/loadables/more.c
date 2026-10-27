/* SPDX-License-Identifier: MIT */
/* more.c — POSIX more(1) as a bash builtin.
 *
 *   more [-d] [-n LINES] [FILE...]
 *
 * Page through input one terminal-screen at a time. After each screen
 * waits on /dev/tty for a single key:
 *   space / f      next screen
 *   enter / j      next line
 *   /pattern       search forward to the next matching line
 *   q              quit
 *   anything else  next screen (with help hint if -d is set)
 *
 * Flags:
 *   -d        emit help hint on prompt ("Press space to continue, q to quit")
 *   -n LINES  override screen-page size (default: TIOCGWINSZ rows or 24)
 *
 * Reads /dev/tty for keypresses so it works even when stdin is a pipe
 * (the typical `cmd | more` case). If /dev/tty isn't available
 * (non-interactive container), pages out the entire input without
 * pausing — matches GNU more's heuristic.
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "loadables.h"
#include "unwind_prot.h"

/* Shared CSI/SS3 key decoder. Wired in 2026-05-18 so arrow keys,
 * PgUp/PgDn and Home/End map onto the existing letter bindings.
 * See scripts/loadables/_bl_key/bl_key.h for the full enum. */
#include "_bl_key_bl_key.h"

extern char *more_doc[];

enum { BM_QUIT = 3 }; /* internal result; q quits the entire operand list */

/* Reject overflow before narrowing page sizes to int. */
static int
bm_parse_rows (const char *text, int *rows)
{
    unsigned long value = 0;
    if (!text || !*text) return 0;
    for (const unsigned char *p = (const unsigned char *) text; *p; p++) {
        if (*p < '0' || *p > '9' || value > (INT_MAX - (*p - '0')) / 10UL)
            return 0;
        value = value * 10 + (*p - '0');
    }
    *rows = value < 2 ? 23 : (int) value;
    return 1;
}

static int
bm_screen_rows (void)
{
    struct winsize ws;
    if (ioctl (STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0)
        return ws.ws_row > 1 ? ws.ws_row - 1 : 1;   /* save one row for the prompt */
    return 23;
}

static volatile sig_atomic_t bm_resize_seen = 0;

static void
bm_sigwinch (int sig)
{
    (void) sig;
    bm_resize_seen = 1;
}

static void
bm_install_sigwinch (struct sigaction *oldsa, int *installed)
{
    struct sigaction sa;

    *installed = 0;
    memset (&sa, 0, sizeof sa);
    sa.sa_handler = bm_sigwinch;
    sigemptyset (&sa.sa_mask);
    /* Resizing must not turn a blocking input read into a false EOF.
       The flag is consumed when the next record or key arrives. */
    sa.sa_flags = SA_RESTART;
    if (sigaction (SIGWINCH, &sa, oldsa) == 0)
        *installed = 1;
}

static void
bm_restore_sigwinch (const struct sigaction *oldsa, int installed)
{
    if (installed)
        sigaction (SIGWINCH, oldsa, NULL);
}

/* One invocation owns its terminal and temporary storage. Bash can unwind
   through QUIT while waiting for input, so cleanup must precede every wait. */
typedef struct {
    int tty, have_termios, have_winch;
    struct termios saved;
    struct sigaction old_winch;
    char *line;
    size_t cap;
} bm_session;

static void
bm_cleanup (void *arg)
{
    bm_session *s = arg;
    if (s->have_termios) tcsetattr (s->tty, TCSANOW, &s->saved);
    if (s->tty >= 0) close (s->tty);
    bm_restore_sigwinch (&s->old_winch, s->have_winch);
    free (s->line);
}

static void
bm_erase_prompt (void)
{
    fputs ("\r                                                  \r", stderr);
    fflush (stderr);
}

static int
bm_open_terminal (bm_session *s)
{
    if (!isatty (STDOUT_FILENO)) return 0;
    s->tty = open ("/dev/tty", O_RDONLY | O_NOCTTY | O_CLOEXEC);
    if (s->tty < 0) return 0;
    if (tcgetattr (s->tty, &s->saved) < 0) return 0;
    s->have_termios = 1;
    bl_key_reset ();
    bm_resize_seen = 0;
    bm_install_sigwinch (&s->old_winch, &s->have_winch);
    return 1;
}

static int
bm_cbreak (bm_session *s)
{
    struct termios raw = s->saved;
    raw.c_lflag &= ~(ICANON | ECHO);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    return tcsetattr (s->tty, TCSANOW, &raw);
}

/* Let Bash handle interrupts at safe points inside the decoder's retry
   loops; no SIGINT disposition or shell-global signal state is replaced. */
static void
bm_check_interrupt (void)
{
    int saved_errno = errno;
    QUIT;
    errno = saved_errno;
}

static int
bm_wait (int fd, short events)
{
    for (;;) {
        struct pollfd p = { .fd = fd, .events = events };
        QUIT;
        int ready = poll (&p, 1, -1);
        int poll_errno = errno;
        QUIT;
        errno = poll_errno;
        if (ready > 0) return 0;
        if (ready < 0 && poll_errno == EINTR) continue;
        return -1;
    }
}

static int
bm_get_key (bm_session *s, int hint)
{
    if (bm_cbreak (s) < 0) return -1;
    if (hint) fputs ("--More-- (space=page, enter=line, q=quit)", stderr);
    else fputs ("--More--", stderr);
    fflush (stderr);
    for (;;) {
        int c = bl_read_key_checked (s->tty, bm_check_interrupt);
        switch (c) {
        case BL_KEY_NONE: return -1;
        case BL_KEY_RET:
        case BL_KEY_DOWN: return '\n';
        case BL_KEY_PGDN:
        case BL_KEY_END: return ' ';
        case BL_KEY_UP:
        case BL_KEY_PGUP:
        case BL_KEY_HOME:
        case BL_KEY_LEFT:
        case BL_KEY_RIGHT:
        case BL_KEY_INS:
        case BL_KEY_DEL:
        case BL_KEY_ESC:
        case BL_KEY_PASTE_START:
        case BL_KEY_PASTE_END:
            continue;
        default: return c;
        }
    }
}

static int
bm_prompt_search (bm_session *s, char *buf, size_t bufsz)
{
    if (bm_cbreak (s) < 0) return -1;
    fputs ("/", stderr);
    fflush (stderr);
    size_t n = 0;
    for (;;) {
        unsigned char c;
        if (bm_wait (s->tty, POLLIN) < 0) {
            tcsetattr (s->tty, TCSANOW, &s->saved);
            return -1;
        }
        ssize_t r = read (s->tty, &c, 1);
        int read_errno = errno;
        QUIT;
        if (r < 0 && read_errno == EINTR) continue;
        if (r <= 0) {
            tcsetattr (s->tty, TCSANOW, &s->saved);
            return -1;
        }
        if (c == '\n' || c == '\r') break;
        if (c == 0x7f || c == 0x08) {
            if (n) {
                n--;
                fputs ("\b \b", stderr);
                fflush (stderr);
            }
            continue;
        }
        if (!isprint (c) || n + 1 >= bufsz) continue;
        buf[n++] = (char) c;
        fputc (c, stderr);
        fflush (stderr);
    }
    buf[n] = '\0';
    tcsetattr (s->tty, TCSANOW, &s->saved);
    bm_erase_prompt ();
    return n ? 0 : -1;
}

static ssize_t
bm_read_line (bm_session *s, FILE *f)
{
    for (;;) {
        QUIT;
        ssize_t n = getline (&s->line, &s->cap, f);
        int read_errno = errno;
        QUIT;
        if (n < 0 && ferror (f) && read_errno == EINTR) {
            clearerr (f);
            continue;
        }
        errno = read_errno;
        return n;
    }
}

static void
bm_show_key_help (void)
{
    fputs ("\r\nhelp: space/f next page, enter/j next line, /PATTERN search, q quit\r\n",
           stderr);
    fflush (stderr);
}

static int
bm_copy_stream (FILE *f)
{
    unsigned char buf[65536];
    /* These are private, newly opened streams: no stdio read-ahead exists.
       read returns available pipe bytes instead of waiting to fill fread's
       block. Flush each read so a held-open producer remains responsive. */
    if (fflush (stdout) == EOF || ferror (stdout)) goto write_error;
    for (;;) {
        QUIT;
        if (bm_wait (fileno (f), POLLIN) < 0) {
            builtin_error ("read error: %s", strerror (errno));
            return EXECUTION_FAILURE;
        }
        ssize_t n = read (fileno (f), buf, sizeof buf);
        int read_errno = errno;
        QUIT;
        if (n < 0) {
            if (read_errno == EINTR) continue;
            builtin_error ("read error: %s", strerror (read_errno));
            return EXECUTION_FAILURE;
        }
        if (n == 0) return EXECUTION_SUCCESS;
        size_t offset = 0;
        while (offset < (size_t) n) {
            if (bm_wait (STDOUT_FILENO, POLLOUT) < 0) goto write_error;
            ssize_t written = write (STDOUT_FILENO, buf + offset, (size_t) n - offset);
            int write_errno = errno;
            QUIT;
            if (written < 0 && write_errno == EINTR) continue;
            if (written <= 0) {
                errno = written < 0 ? write_errno : EIO;
                goto write_error;
            }
            offset += (size_t) written;
        }
    }
write_error:
    builtin_error ("write error: %s", strerror (errno));
    return EXECUTION_FAILURE;
}

static int
bm_pager (FILE *f, int rows, int hint)
{
    if (!isatty (STDOUT_FILENO)) return bm_copy_stream (f);

    bm_session s = { .tty = -1 };
    begin_unwind_frame ("more session");
    add_unwind_protect (bm_cleanup, &s);
    int interactive = bm_open_terminal (&s);
    int shown = 0, single_line = 0;
    int rc = EXECUTION_SUCCESS;
    ssize_t n;
    while ((n = bm_read_line (&s, f)) != -1) {
        if (bm_resize_seen && interactive) {
            rows = bm_screen_rows ();
            bm_resize_seen = 0;
        }
        if (fwrite (s.line, 1, (size_t) n, stdout) != (size_t) n || ferror (stdout))
            goto write_error;
        if (!interactive) continue; /* Complete lines stay visible on pipes. */
        shown++;
        if (!single_line && shown < rows) continue;
        for (;;) {
            /* A non-newline final record must be visible before the prompt. */
            if (fflush (stdout) == EOF) goto write_error;
            int k = bm_get_key (&s, hint);
            tcsetattr (s.tty, TCSANOW, &s.saved);
            bm_erase_prompt ();
            if (bm_resize_seen) {
                rows = bm_screen_rows ();
                bm_resize_seen = 0;
            }
            if (k == 'q' || k == 'Q') { rc = BM_QUIT; goto done; }
            if (k < 0) { interactive = 0; break; }
            if (k == 'h' || k == 'H' || k == '?') {
                bm_show_key_help ();
                continue; /* Help never consumes another input record. */
            }
            if (k == '/') {
                char pat[128];
                if (bm_prompt_search (&s, pat, sizeof pat) < 0) continue;
                int found = 0;
                while ((n = bm_read_line (&s, f)) != -1) {
                    /* Literal byte search includes text after embedded NULs. */
                    if (memmem (s.line, (size_t) n, pat, strlen (pat))) {
                        if (fwrite (s.line, 1, (size_t) n, stdout) != (size_t) n)
                            goto write_error;
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    fputs ("Pattern not found\r\n", stderr);
                    goto input_done;
                }
                single_line = 0;
                shown = 1;
                break;
            }
            single_line = k == '\n' || k == '\r' || k == 'j';
            shown = 0;
            break;
        }
    }
input_done:
    if (ferror (f)) {
        builtin_error ("read error: %s", strerror (errno));
        rc = EXECUTION_FAILURE;
    }
done:
    if (fflush (stdout) == EOF || ferror (stdout)) {
write_error:
        builtin_error ("write error: %s", strerror (errno));
        rc = EXECUTION_FAILURE;
    }
    run_unwind_frame ("more session");
    return rc;
}

static void
bm_close_input (void *arg)
{
    fclose ((FILE *) arg);
}

/* The shell's persistent stdin FILE may retain read-ahead after q. Give
   every invocation a private stream without changing stdin's buffering or
   error state. Closing the duplicate never closes the shell's descriptor. */
static FILE *
bm_open_input (const char *path)
{
    if (strcmp (path, "-")) return fopen (path, "r");
    int fd = fcntl (STDIN_FILENO, F_DUPFD_CLOEXEC, 3);
    if (fd < 0) return NULL;
    FILE *f = fdopen (fd, "r");
    if (!f) {
        int saved_errno = errno;
        close (fd);
        errno = saved_errno;
    }
    return f;
}

static int
bm_page_input (FILE *f, int rows, int hint)
{
    begin_unwind_frame ("more input");
    add_unwind_protect (bm_close_input, f);
    int result = bm_pager (f, rows, hint);
    run_unwind_frame ("more input");
    return result;
}

int
more_builtin (WORD_LIST *list)
{
    int hint = 0;
    int rows = bm_screen_rows ();

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help") || !strcmp (w, "-h")) {
            for (char **p = more_doc; p && *p; p++)
                puts (*p);
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version") || !strcmp (w, "-V")) {
            puts ("more 1.0 (bash-os POSIX more builtin)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-d")) { hint = 1; list = list->next; continue; }
        if (!strcmp (w, "-n")) {
            if (!list->next) { builtin_error ("-n needs LINES"); return EXECUTION_FAILURE; }
            list = list->next;
            if (!bm_parse_rows (list->word->word, &rows)) {
                builtin_error ("-n: invalid number: %s", list->word->word);
                return EXECUTION_FAILURE;
            }
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-n", 2) && w[2]) {
            if (!bm_parse_rows (w + 2, &rows)) {
                builtin_error ("-n: invalid number: %s", w + 2);
                return EXECUTION_FAILURE;
            }
            list = list->next;
            continue;
        }
        if (w[1] >= '1' && w[1] <= '9' && bm_parse_rows (w + 1, &rows)) {
            list = list->next;
            continue;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EXECUTION_FAILURE;
    }

    if (!list) {
        FILE *f = bm_open_input ("-");
        if (!f) {
            builtin_error ("stdin: %s", strerror (errno));
            return EXECUTION_FAILURE;
        }
        int result = bm_page_input (f, rows, hint);
        return result == BM_QUIT ? EXECUTION_SUCCESS : result;
    }
    int rc = EXECUTION_SUCCESS;
    int n_files = 0;
    for (WORD_LIST *p = list; p; p = p->next) n_files++;
    for (WORD_LIST *p = list; p; p = p->next) {
        FILE *f = bm_open_input (p->word->word);
        if (!f) {
            builtin_error ("%s: %s", p->word->word, strerror (errno));
            /* util-linux more reports unavailable named inputs but keeps
               processing the operand list with success status. */
            continue;
        }
        struct stat st;
        if (fstat (fileno (f), &st) == 0 && S_ISDIR (st.st_mode)) {
            printf ("\n*** %s: directory ***\n\n", p->word->word);
            fclose (f);
            continue;
        }
        /* Nonterminal output labels every named file, including a single
           operand. The documented '-' extension continues to read stdin. */
        if (n_files > 1 || (!isatty (STDOUT_FILENO) && strcmp (p->word->word, "-")))
            printf ("::::::::::::::\n%s\n::::::::::::::\n", p->word->word);
        int result = bm_page_input (f, rows, hint);
        if (result != EXECUTION_SUCCESS && result != BM_QUIT)
            rc = EXECUTION_FAILURE;
        if (result == BM_QUIT) break;
        /* Output already failed: later files could only repeat the error. */
        if (ferror (stdout)) break;
    }
    return rc;
}

char *more_doc[] = {
    "Page through input (POSIX more).",
    "",
    "    more [-d] [-n LINES] [FILE...]",
    "",
    "    -d         show help hint on the --More-- prompt",
    "    -n LINES   override screen-page size (default: TIOCGWINSZ row",
    "               count, fallback 24)",
    "    -h/--help  show this help",
    "    -V/--version show version",
    "",
    "Reads stdin when no FILE given (or `-` in the list). Named files",
    "receive `::::::::::::::\\nFILE\\n::::::::::::::` headers on nonterminal",
    "output; terminal mode shows headers for multiple operands.",
    "Unavailable named inputs are diagnosed and skipped with success status.",
    "Pause keys (read from /dev/tty):",
    "    space / f       next page",
    "    enter / j       next line",
    "    /PATTERN        search forward",
    "    h / ?           show key help",
    "    q / Q           quit",
    "When /dev/tty is not available (non-interactive), drains all input",
    "without pausing.",
    (char *)NULL
};

struct builtin more_struct = {
    "more",
    more_builtin,
    BUILTIN_ENABLED,
    more_doc,
    "more [-d] [-n LINES] [FILE...]",
    0
};
