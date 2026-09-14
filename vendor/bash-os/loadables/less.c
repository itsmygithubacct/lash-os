/* SPDX-License-Identifier: MIT */
/* less.c - less-shaped pager as a bash builtin.
 *
 * This is not a wholesale import of upstream less. It borrows the
 * behavioral contract from less(1) and keeps a small implementation that
 * fits bash-os' compiled-loadable model:
 *
 *   less [-F] [-N] [-S] [-n LINES] [FILE...]
 *
 * Non-interactive mode drains input unchanged, matching the existing
 * more convention. Interactive mode reads files/stdin into a line
 * vector, renders one screen at a time, and supports the less muscle
 * memory most scripts/users expect first: space/f/^F, b/^B, j/down,
 * k/up, g, G, /PATTERN, n, N, q.
 *
 * Upstream less source is kept for study under research/refs/less.
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <sys/ioctl.h>

#include "loadables.h"

/* Shared CSI/SS3 key decoder (arrows, PgUp/PgDn, Home/End, Delete).
 * The inline ESC-[ parser this file used to ship was replaced
 * 2026-05-18 by a single bl_read_key() call so less/more/vi/nano/top
 * share one decoder. See scripts/loadables/_bl_key/bl_key.h. */
#include "_bl_key_bl_key.h"

typedef struct {
    char **v;
    size_t *len;    /* byte length of each line (excludes our NUL terminator);
                       tracked so binary content with embedded NULs round-trips
                       byte-exact instead of being truncated by strlen(). */
    size_t n;
    size_t cap;
} bl_lines;

static void
bl_lines_free (bl_lines *ls)
{
    if (!ls) return;
    for (size_t i = 0; i < ls->n; i++)
        free (ls->v[i]);
    free (ls->v);
    free (ls->len);
    memset (ls, 0, sizeof *ls);
}

static int
bl_lines_push (bl_lines *ls, const char *s, size_t n)
{
    if (ls->n == ls->cap)
    {
        size_t nc = ls->cap ? ls->cap * 2 : 128;
        char **nv = realloc (ls->v, nc * sizeof *nv);
        if (!nv) return -1;
        ls->v = nv;
        size_t *nl = realloc (ls->len, nc * sizeof *nl);
        if (!nl) return -1;
        ls->len = nl;
        ls->cap = nc;
    }
    char *copy = malloc (n + 1);
    if (!copy) return -1;
    memcpy (copy, s, n);
    copy[n] = '\0';
    ls->v[ls->n] = copy;
    ls->len[ls->n] = n;
    ls->n++;
    return 0;
}

static int
bl_read_stream (FILE *f, bl_lines *ls)
{
    /* Clear the EOF flag a previous invocation left on a persistent stream:
       a builtin does not fork, so stdin's FILE is reused across calls. */
    clearerr (f);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline (&line, &cap, f)) != -1)
    {
        if (bl_lines_push (ls, line, (size_t) n) < 0)
        {
            free (line);
            return -1;
        }
    }
    free (line);
    return ferror (f) ? -1 : 0;
}

static int
bl_read_file_operand (const char *path, bl_lines *ls)
{
    FILE *f = !strcmp (path, "-") ? stdin : fopen (path, "r");
    if (!f)
    {
        builtin_error ("%s: %s", path, strerror (errno));
        return -1;
    }
    int rc = bl_read_stream (f, ls);
    if (f != stdin) fclose (f);
    if (rc < 0)
        builtin_error ("%s: %s", path, strerror (errno));
    return rc;
}

static int
bl_term_rows (void)
{
    struct winsize ws;
    if (ioctl (STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 2)
        return (int) ws.ws_row - 1;
    return 23;
}

static volatile sig_atomic_t bl_resize_seen = 0;

static void
bl_sigwinch (int sig)
{
    (void) sig;
    bl_resize_seen = 1;
}

static void
bl_install_sigwinch (struct sigaction *oldsa, int *installed)
{
    struct sigaction sa;

    *installed = 0;
    memset (&sa, 0, sizeof sa);
    sa.sa_handler = bl_sigwinch;
    sigemptyset (&sa.sa_mask);
    if (sigaction (SIGWINCH, &sa, oldsa) == 0)
        *installed = 1;
}

static void
bl_restore_sigwinch (const struct sigaction *oldsa, int installed)
{
    if (installed)
        sigaction (SIGWINCH, oldsa, NULL);
}

/* Return non-zero when every byte of s is an ASCII digit. Mirrors
   more's bm_str_is_num for G02 option-parity: `-n` rejects
   non-numeric and signed arguments instead of silently falling back
   to the default via atoi() returning 0. */
static int
bl_str_is_num (const char *s)
{
    if (!s || !*s) return 0;
    while (*s) { if (!isdigit ((unsigned char) *s)) return 0; s++; }
    return 1;
}

static void
bl_write (int fd, const char *s)
{
    size_t n = strlen (s);
    while (n)
    {
        ssize_t w = write (fd, s, n);
        if (w < 0)
        {
            if (errno == EINTR) continue;
            return;
        }
        s += w;
        n -= (size_t) w;
    }
}

static void
bl_render_line (const char *line, size_t linelen, int chop, int numbers, size_t lineno, int cols)
{
    int prefix = 0;
    if (numbers)
        prefix = printf ("%6zu  ", lineno + 1);
    int room = cols > prefix ? cols - prefix : cols;
    size_t len = linelen;
    if (len && line[len - 1] == '\n') len--;
    if (chop && room > 0 && len > (size_t) room)
        fwrite (line, 1, (size_t) room, stdout);
    else
        fwrite (line, 1, len, stdout);
    putchar ('\n');
}

static int
bl_find (const bl_lines *ls, const char *pat, size_t from, int reverse, size_t *hit)
{
    if (!pat || !*pat || ls->n == 0) return 0;
    if (reverse)
    {
        size_t i = from >= ls->n ? ls->n - 1 : from;
        for (;;)
        {
            if (strstr (ls->v[i], pat)) { *hit = i; return 1; }
            if (i == 0) break;
            i--;
        }
        return 0;
    }
    for (size_t i = from; i < ls->n; i++)
        if (strstr (ls->v[i], pat)) { *hit = i; return 1; }
    return 0;
}

static int
bl_prompt_line (int tty, const char *label, char *buf, size_t bufsz)
{
    if (bufsz == 0) return -1;
    bl_write (tty, label);
    size_t n = 0;
    for (;;)
    {
        unsigned char c;
        ssize_t r = read (tty, &c, 1);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0 || c == '\n' || c == '\r') break;
        if (c == 0x7f || c == 0x08)
        {
            if (n) { n--; bl_write (tty, "\b \b"); }
            continue;
        }
        if (!isprint (c) || n + 1 >= bufsz) continue;
        buf[n++] = (char) c;
        write (tty, &c, 1);
    }
    buf[n] = '\0';
    bl_write (tty, "\r\n");
    return 0;
}

static int
bl_interactive (const bl_lines *ls, int rows, int chop, int numbers, int quit_if_one)
{
    if (ls->n == 0) return EXECUTION_SUCCESS;
    if (!isatty (STDOUT_FILENO))
    {
        int cols = 80;
        const char *env_cols = getenv ("COLUMNS");
        if (env_cols && atoi (env_cols) > 0) cols = atoi (env_cols);
        for (size_t i = 0; i < ls->n; i++)
        {
            if (numbers || chop)
                bl_render_line (ls->v[i], ls->len[i], chop, numbers, i, cols);
            else
                /* Byte-counted write so embedded NULs (and the bytes after
                   them) survive — fputs/strlen would truncate at the first
                   NUL, dropping the rest of the line and matching more's
                   binary-safe drain. */
                fwrite (ls->v[i], 1, ls->len[i], stdout);
        }
        return EXECUTION_SUCCESS;
    }
    if (quit_if_one && ls->n <= (size_t) rows)
    {
        for (size_t i = 0; i < ls->n; i++)
            bl_render_line (ls->v[i], ls->len[i], chop, numbers, i, 80);
        return EXECUTION_SUCCESS;
    }

    int tty = open ("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (tty < 0)
    {
        for (size_t i = 0; i < ls->n; i++)
            fwrite (ls->v[i], 1, ls->len[i], stdout);
        return EXECUTION_SUCCESS;
    }

    struct termios old, raw;
    int have_termios = (tcgetattr (tty, &old) == 0);
    if (have_termios)
    {
        raw = old;
        raw.c_lflag &= ~(ICANON | ECHO);
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;
        tcsetattr (tty, TCSANOW, &raw);
    }

    size_t top = 0;
    char last_pat[128] = "";
    int last_reverse = 0;
    int cols = 80;
    struct winsize ws;
    struct sigaction old_winch;
    int have_winch = 0;
    if (ioctl (STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
        cols = (int) ws.ws_col;

    bl_resize_seen = 0;
    bl_install_sigwinch (&old_winch, &have_winch);

    for (;;)
    {
        if (bl_resize_seen)
        {
            int new_rows = bl_term_rows ();
            rows = new_rows > 0 ? new_rows : rows;
            if (ioctl (STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
                cols = (int) ws.ws_col;
            if (top >= ls->n)
                top = ls->n - 1;
            bl_resize_seen = 0;
        }
        bl_write (STDOUT_FILENO, "\033[H\033[J");
        for (int r = 0; r < rows && top + (size_t) r < ls->n; r++)
            bl_render_line (ls->v[top + (size_t) r], ls->len[top + (size_t) r],
                            chop, numbers, top + (size_t) r, cols);

        char prompt[96];
        int pct = (int) (((top + 1) * 100) / ls->n);
        snprintf (prompt, sizeof prompt,
                  "\033[7m less %zu/%zu %d%% (q quit, h help) \033[m",
                  top + 1, ls->n, pct);
        bl_write (STDERR_FILENO, prompt);

        /* One keystroke. bl_read_key() blocks on the first byte and
         * (when it sees ESC) assembles the CSI/SS3 follow-up burst
         * with its own grace-window timeouts. Plain ASCII keys come
         * back as their byte value; specials come back as BL_KEY_*
         * constants ≥ 0x100, which we fold into the legacy ASCII
         * dispatch below so the rest of the loop is unchanged. */
        int c = bl_read_key (tty);
        bl_write (STDERR_FILENO, "\r\033[K");
        if (bl_resize_seen)
            continue;  /* redraw with the fresh size at the top of the loop */
        if (c == BL_KEY_NONE) break;

        switch (c)
        {
        case BL_KEY_UP:    c = 'k'; break;
        case BL_KEY_DOWN:  c = 'j'; break;
        case BL_KEY_HOME:  c = 'g'; break;
        case BL_KEY_END:   c = 'G'; break;
        case BL_KEY_PGUP:  c = 'b'; break;
        case BL_KEY_PGDN:  c = ' '; break;
        case BL_KEY_LEFT:
        case BL_KEY_RIGHT:
        case BL_KEY_INS:
        case BL_KEY_DEL:
        case BL_KEY_ESC:
            continue;  /* ignore */
        default: break; /* plain ASCII byte — fall through */
        }

        if (c == 'q' || c == 'Q') break;
        if (c == ' ' || c == 'f' || c == 0x06)
        {
            top = top + (size_t) rows < ls->n ? top + (size_t) rows : ls->n - 1;
        }
        else if (c == 'b' || c == 0x02)
        {
            top = top > (size_t) rows ? top - (size_t) rows : 0;
        }
        else if (c == 'j' || c == '\n' || c == '\r')
        {
            if (top + 1 < ls->n) top++;
        }
        else if (c == 'k')
        {
            if (top > 0) top--;
        }
        else if (c == 'g' || c == '<')
        {
            top = 0;
        }
        else if (c == 'G' || c == '>')
        {
            top = ls->n > (size_t) rows ? ls->n - (size_t) rows : 0;
        }
        else if (c == '/' || c == '?')
        {
            if (have_termios) tcsetattr (tty, TCSANOW, &old);
            char pat[128];
            if (bl_prompt_line (tty, c == '/' ? "/" : "?", pat, sizeof pat) == 0 && pat[0])
            {
                strncpy (last_pat, pat, sizeof last_pat - 1);
                last_pat[sizeof last_pat - 1] = '\0';
                last_reverse = (c == '?');
                size_t hit = top;
                size_t start = last_reverse ? (top ? top - 1 : 0) : top + 1;
                if (bl_find (ls, last_pat, start, last_reverse, &hit))
                    top = hit;
            }
            if (have_termios) tcsetattr (tty, TCSANOW, &raw);
        }
        else if ((c == 'n' || c == 'N') && last_pat[0])
        {
            int rev = (c == 'N') ? !last_reverse : last_reverse;
            size_t hit = top;
            size_t start = rev ? (top ? top - 1 : 0) : top + 1;
            if (bl_find (ls, last_pat, start, rev, &hit))
                top = hit;
        }
        else if (c == 'h' || c == 'H')
        {
            bl_write (STDOUT_FILENO,
                      "\033[H\033[Jspace/f/PgDn next page  b/PgUp previous page\n"
                      "j/down/enter next line     k/up previous line\n"
                      "g/Home top                  G/End bottom\n"
                      "/ search forward            ? search backward   n/N repeat\n"
                      "q quit\n");
            (void) bl_read_key (tty);
        }
    }

    if (have_termios) tcsetattr (tty, TCSANOW, &old);
    bl_restore_sigwinch (&old_winch, have_winch);
    close (tty);
    return EXECUTION_SUCCESS;
}

int
less_builtin (WORD_LIST *list)
{
    int rows = bl_term_rows ();
    int chop = 0;
    int numbers = 0;
    int quit_if_one = 0;
    bl_lines ls = { 0 };
    int rc = EXECUTION_SUCCESS;

    while (list && list->word && list->word->word[0] == '-' && list->word->word[1])
    {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "-F")) { quit_if_one = 1; list = list->next; continue; }
        if (!strcmp (w, "-N")) { numbers = 1; list = list->next; continue; }
        if (!strcmp (w, "-S")) { chop = 1; list = list->next; continue; }
        if (!strcmp (w, "-n"))
        {
            if (!list->next) { builtin_error ("-n needs LINES"); return EX_USAGE; }
            list = list->next;
            if (!bl_str_is_num (list->word->word)) {
                builtin_error ("-n: invalid number: %s", list->word->word);
                return EX_USAGE;
            }
            rows = atoi (list->word->word);
            if (rows < 2) rows = bl_term_rows ();
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-n", 2) && w[2])
        {
            if (!bl_str_is_num (w + 2)) {
                builtin_error ("-n: invalid number: %s", w + 2);
                return EX_USAGE;
            }
            rows = atoi (w + 2);
            if (rows < 2) rows = bl_term_rows ();
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-h") || !strcmp (w, "--help"))
        {
            puts ("less [-F] [-N] [-S] [-n LINES] [FILE...]");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "-V") || !strcmp (w, "--version"))
        {
            puts ("less 0.1 (bash-os less-shaped pager)");
            return EXECUTION_SUCCESS;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    if (!list)
    {
        if (bl_read_stream (stdin, &ls) < 0)
            rc = EXECUTION_FAILURE;
    }
    else
    {
        int n_files = 0;
        for (WORD_LIST *p = list; p; p = p->next) n_files++;
        for (WORD_LIST *p = list; p; p = p->next)
        {
            if (n_files > 1)
            {
                char hdr[512];
                snprintf (hdr, sizeof hdr, "::::::::::::::\n%s\n::::::::::::::\n",
                          p->word->word);
                bl_lines_push (&ls, hdr, strlen (hdr));
            }
            if (bl_read_file_operand (p->word->word, &ls) < 0)
                rc = EXECUTION_FAILURE;
        }
    }

    if (rc == EXECUTION_SUCCESS)
        rc = bl_interactive (&ls, rows, chop, numbers, quit_if_one);
    bl_lines_free (&ls);
    return rc;
}

char *less_doc[] = {
    "Page through input with a small less-shaped interface.",
    "",
    "    less [-F] [-N] [-S] [-n LINES] [FILE...]",
    "",
    "    -F          quit if content fits on one screen",
    "    -N          show line numbers",
    "    -S          chop long lines to screen width",
    "    -n LINES    override screen-page size",
    "",
    "Interactive keys: space/f next page, b previous page, j/k line",
    "movement, g/G top/bottom, / and ? search, n/N repeat search, q quit.",
    "When /dev/tty is unavailable, drains input without pausing.",
    (char *)NULL
};

struct builtin less_struct = {
    "less",
    less_builtin,
    BUILTIN_ENABLED,
    less_doc,
    "less [-F] [-N] [-S] [-n LINES] [FILE...]",
    0
};
