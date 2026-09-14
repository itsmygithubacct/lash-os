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
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>

#include "loadables.h"

/* Shared CSI/SS3 key decoder. Wired in 2026-05-18 so arrow keys,
 * PgUp/PgDn and Home/End map onto the existing letter bindings.
 * See scripts/loadables/_bl_key/bl_key.h for the full enum. */
#include "_bl_key_bl_key.h"

extern char *more_doc[];

/* Return non-zero when every byte of s is an ASCII digit. */
static int
bm_str_is_num (const char *s)
{
    if (!s || !*s) return 0;
    while (*s) { if (!isdigit ((unsigned char)*s)) return 0; s++; }
    return 1;
}

static int
bm_screen_rows (void)
{
    struct winsize ws;
    if (ioctl (STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0)
        return ws.ws_row - 1;   /* save one row for the prompt */
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
    /* SA_RESTART so a SIGWINCH delivered mid-drain transparently restarts
       the interrupted getline()/read() instead of returning EINTR — without
       it the drain loop (getline == -1) mistook the interruption for EOF and
       aborted with only part of the input emitted. The resize flag is still
       set and consumed at the top of bm_pager's loop, so terminal-resize
       handling is unaffected. */
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

/* Read one keypress from /dev/tty in cbreak mode. Returns the byte,
   or -1 if /dev/tty isn't available (signals "no pause"). */
static int
bm_get_key (int hint)
{
    /* If stdout isn't a terminal, there's no human watching pages
     * roll by — pausing here would block forever waiting for a
     * keypress that never comes. This bites tests that capture
     * more output via $(...) inside a guest where /dev/tty IS
     * open-able (we'd otherwise read it and stall): host shells
     * without a controlling tty fail-open on the /dev/tty open,
     * but in-guest the open succeeds against the serial console
     * and the read blocks indefinitely. Treat non-tty stdout the
     * same as "no /dev/tty" — fall through to bm_pager's drain
     * arm. */
    if (!isatty (STDOUT_FILENO)) return -1;
    int tty = open ("/dev/tty", O_RDONLY | O_NOCTTY | O_CLOEXEC);
    if (tty < 0) return -1;
    struct termios old, raw;
    if (tcgetattr (tty, &old) < 0) { close (tty); return -1; }
    raw = old;
    raw.c_lflag &= ~(ICANON | ECHO);
    raw.c_cc[VMIN]  = 1;
    raw.c_cc[VTIME] = 0;
    tcsetattr (tty, TCSANOW, &raw);
    if (hint) fputs ("--More-- (space=page, enter=line, q=quit)", stderr);
    else      fputs ("--More--", stderr);
    fflush (stderr);
    /* bl_read_key absorbs CSI/SS3 follow-ups so arrow / PgUp / PgDn /
     * Home / End come back as BL_KEY_* constants instead of leaking
     * the bare leading ESC byte (and dropping the rest of the burst
     * to be re-read as garbage on the next prompt). Map specials to
     * the existing letter bindings:
     *   Down  -> '\n' (line)        PgDn -> ' ' (page)
     *   End   -> ' ' (page; forward-only pager can't jump to bottom)
     * Up / PgUp / Home / Left / Right / Ins / Del / bare ESC re-loop
     * so an unrenderable key in a forward-streaming pager does
     * nothing rather than accidentally advancing the screen. */
    int out = -1;
    for (;;) {
        int c = bl_read_key (tty);
        switch (c) {
        case BL_KEY_NONE: out = -1; break;
        case BL_KEY_DOWN: out = '\n'; break;
        case BL_KEY_PGDN: out = ' ';  break;
        case BL_KEY_END:  out = ' ';  break;
        case BL_KEY_UP:
        case BL_KEY_PGUP:
        case BL_KEY_HOME:
        case BL_KEY_LEFT:
        case BL_KEY_RIGHT:
        case BL_KEY_INS:
        case BL_KEY_DEL:
        case BL_KEY_ESC:
            continue;                  /* swallow + re-poll */
        default: out = c; break;       /* plain ASCII */
        }
        break;
    }
    tcsetattr (tty, TCSANOW, &old);
    close (tty);
    /* Erase the prompt with CR + spaces + CR. Best effort. */
    fputs ("\r                                                  \r", stderr);
    fflush (stderr);
    return out;
}

static int
bm_prompt_search (char *buf, size_t bufsz)
{
    if (!buf || bufsz == 0 || !isatty (STDOUT_FILENO))
        return -1;

    int tty = open ("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (tty < 0)
        return -1;

    struct termios old, raw;
    int have_termios = 0;
    if (tcgetattr (tty, &old) == 0) {
        raw = old;
        raw.c_lflag &= ~(ICANON | ECHO);
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;
        if (tcsetattr (tty, TCSANOW, &raw) == 0)
            have_termios = 1;
    }

    fputs ("/", stderr);
    fflush (stderr);

    size_t n = 0;
    int rc = -1;
    for (;;) {
        unsigned char c;
        ssize_t r = read (tty, &c, 1);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            goto cleanup;
        }
        if (r == 0 || c == '\n' || c == '\r')
            break;
        if (c == 0x7f || c == 0x08) {
            if (n) {
                n--;
                fputs ("\b \b", stderr);
                fflush (stderr);
            }
            continue;
        }
        if (!isprint (c) || n + 1 >= bufsz)
            continue;
        buf[n++] = (char) c;
        fputc (c, stderr);
        fflush (stderr);
    }
    buf[n] = '\0';
    rc = n ? 0 : -1;

cleanup:
    if (have_termios)
        tcsetattr (tty, TCSANOW, &old);
    fputs ("\r                                                  \r", stderr);
    fflush (stderr);
    close (tty);
    return rc;
}

static int
bm_search_forward (FILE *f, char **linep, size_t *capp, const char *pat, int *shown)
{
    ssize_t n;

    if (!pat || !*pat)
        return 0;
    while ((n = getline (linep, capp, f)) != -1) {
        if (strstr (*linep, pat)) {
            fwrite (*linep, 1, (size_t) n, stdout);
            if (shown)
                *shown = 1;
            return 1;
        }
    }
    fputs ("Pattern not found\r\n", stderr);
    fflush (stderr);
    return 0;
}

static void
bm_show_key_help (void)
{
    fputs ("\r\nhelp: space/f next page, enter/j next line, /PATTERN search, q quit\r\n",
           stderr);
    fflush (stderr);
}

static int
bm_pager (FILE *f, int rows, int hint)
{
    /* A builtin runs in the shell process, so the stdio stream outlives the
       call. Without this, the EOF flag left by a previous invocation makes
       every later `more < FILE' read nothing and still exit 0. */
    clearerr (f);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int shown = 0;
    int single_line_mode = 0;
    struct sigaction old_winch;
    int have_winch = 0;

    bm_resize_seen = 0;
    bm_install_sigwinch (&old_winch, &have_winch);

    while ((n = getline (&line, &cap, f)) != -1) {
        if (bm_resize_seen) {
            rows = bm_screen_rows ();
            bm_resize_seen = 0;
            if (shown > rows)
                shown = rows;
        }
        fwrite (line, 1, (size_t) n, stdout);
        shown++;
        if (single_line_mode) {
            int k = bm_get_key (hint);
            if (bm_resize_seen) {
                rows = bm_screen_rows ();
                bm_resize_seen = 0;
            }
            if (k < 0) { single_line_mode = 0; continue; }
            if (k == 'q' || k == 'Q') {
                bm_restore_sigwinch (&old_winch, have_winch);
                free (line);
                return EXECUTION_SUCCESS;
            }
            if (k == ' ' || k == 'f') { single_line_mode = 0; shown = 0; continue; }
            if (k == 'h' || k == 'H' || k == '?') {
                bm_show_key_help ();
                continue;
            }
            if (k == '/') {
                char pat[128];
                if (bm_prompt_search (pat, sizeof pat) == 0)
                    bm_search_forward (f, &line, &cap, pat, &shown);
                single_line_mode = 0;
                continue;
            }
            /* Stay in single-line mode for enter / j. */
            continue;
        }
        if (shown < rows) continue;
        int k = bm_get_key (hint);
        if (bm_resize_seen) {
            rows = bm_screen_rows ();
            bm_resize_seen = 0;
        }
        if (k < 0) {
            /* No tty — drain rest without pausing. */
            while ((n = getline (&line, &cap, f)) != -1)
                fwrite (line, 1, (size_t) n, stdout);
            break;
        }
        if (k == 'q' || k == 'Q') {
            bm_restore_sigwinch (&old_winch, have_winch);
            free (line);
            return EXECUTION_SUCCESS;
        }
        if (k == '\n' || k == '\r' || k == 'j') { single_line_mode = 1; shown = rows - 1; continue; }
        if (k == 'h' || k == 'H' || k == '?') {
            bm_show_key_help ();
            continue;
        }
        if (k == '/') {
            char pat[128];
            if (bm_prompt_search (pat, sizeof pat) == 0)
                bm_search_forward (f, &line, &cap, pat, &shown);
            continue;
        }
        /* space, f, anything else → next page */
        shown = 0;
    }
    bm_restore_sigwinch (&old_winch, have_winch);
    free (line);
    return EXECUTION_SUCCESS;
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
            if (!list->next) { builtin_error ("-n needs LINES"); return EX_USAGE; }
            list = list->next;
            if (!bm_str_is_num (list->word->word)) {
                builtin_error ("-n: invalid number: %s", list->word->word);
                return EX_USAGE;
            }
            rows = atoi (list->word->word);
            if (rows < 2) rows = 23;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-n", 2) && w[2]) {
            if (!bm_str_is_num (w + 2)) {
                builtin_error ("-n: invalid number: %s", w + 2);
                return EX_USAGE;
            }
            rows = atoi (w + 2);
            if (rows < 2) rows = 23;
            list = list->next;
            continue;
        }
        if (w[1] >= '1' && w[1] <= '9' && bm_str_is_num (w + 1)) {
            rows = atoi (w + 1);
            if (rows < 2) rows = 23;
            list = list->next;
            continue;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    if (!list) {
        return bm_pager (stdin, rows, hint);
    }
    int rc = EXECUTION_SUCCESS;
    int n_files = 0;
    for (WORD_LIST *p = list; p; p = p->next) n_files++;
    int idx = 0;
    for (WORD_LIST *p = list; p; p = p->next, idx++) {
        if (n_files > 1) printf ("::::::::::::::\n%s\n::::::::::::::\n", p->word->word);
        FILE *f = !strcmp (p->word->word, "-") ? stdin : fopen (p->word->word, "r");
        if (!f) {
            builtin_error ("%s: %s", p->word->word, strerror (errno));
            rc = EXECUTION_FAILURE;
            continue;
        }
        bm_pager (f, rows, hint);
        if (f != stdin) fclose (f);
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
    "Reads stdin when no FILE given (or `-` in the list). Multi-file",
    "mode prints `::::::::::::::\\nFILE\\n::::::::::::::` headers per",
    "file. Pause keys (read from /dev/tty):",
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
