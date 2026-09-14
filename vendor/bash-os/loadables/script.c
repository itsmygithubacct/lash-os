/* SPDX-License-Identifier: MIT */
/* script.c — script(1)-style session recorder + asciinema v2 cast.
 *
 * Plan B-1 (multiplexer-adjacent). Spawns a child shell on a pty;
 * proxies stdin↔master, master→stdout + log file. Optional timing
 * file (util-linux script -t format) and asciinema cast file.
 *
 * Verbs:
 *   script record [-c CMD] [-O OUT] [-T TIMING] [-A CAST]
 *       Spawn shell (or CMD), record session.
 *
 *       -c CMD       command to spawn (default: $SHELL or /bin/bash)
 *       -O OUT       typescript file (raw output bytes)
 *       -T TIMING    util-linux timing file ("<delay> <bytes>" lines)
 *       -A CAST      asciinema v2 cast file (JSON-lines)
 *
 *   script replay TIMING OUT [-d DIVISOR]
 *       Re-emit OUT to stdout pacing per TIMING.
 *
 * Uses pty's posix_openpt + grantpt for the master pty allocation.
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
#include <fcntl.h>
#include <termios.h>
#include <signal.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "loadables.h"
#include "command-run.h"

/* JSON-encode a chunk of bytes (printable + escape backslash, quote,
   control chars). Returns malloc'd; caller frees. */
static char *
bsc_json_encode (const unsigned char *data, size_t n)
{
    /* Worst case: 6 chars per byte (\u00XX). */
    char *out = malloc (n * 6 + 1);
    if (!out) return NULL;
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = data[i];
        if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = (char) c; }
        else if (c == '\n')  { out[o++] = '\\'; out[o++] = 'n'; }
        else if (c == '\r')  { out[o++] = '\\'; out[o++] = 'r'; }
        else if (c == '\t')  { out[o++] = '\\'; out[o++] = 't'; }
        else if (c < 0x20)   { o += (size_t) sprintf (out + o, "\\u%04x", c); }
        else                 { out[o++] = (char) c; }
    }
    out[o] = '\0';
    return out;
}

static double
bsc_now_secs (void)
{
    struct timespec ts;
    clock_gettime (CLOCK_MONOTONIC, &ts);
    return (double) ts.tv_sec + (double) ts.tv_nsec / 1e9;
}

static long long
bsc_parse_limit (const char *s)
{
    char *end = NULL;
    double v;
    if (!s || !*s) return -1;
    errno = 0;
    v = strtod (s, &end);
    if (errno || end == s || v < 0) return -1;
    if (*end) {
        if (end[1] != '\0') return -1;
        switch (*end) {
        case 'k': case 'K': v *= 1024.0; break;
        case 'm': case 'M': v *= 1024.0 * 1024.0; break;
        case 'g': case 'G': v *= 1024.0 * 1024.0 * 1024.0; break;
        default: return -1;
        }
    }
    if (v > 9223372036854775807.0) return -1;
    return (long long) v;
}

static int
bsc_echo_mode (const char *s, int *out)
{
    if (!s || !out) return -1;
    if (strcmp (s, "auto") == 0) { *out = -1; return 0; }
    if (strcmp (s, "never") == 0) { *out = 0; return 0; }
    if (strcmp (s, "always") == 0) { *out = 1; return 0; }
    return -1;
}

static int
bsc_apply_echo (int fd, int mode)
{
    struct termios tio;
    if (mode < 0) return 0;
    if (tcgetattr (fd, &tio) < 0) return -1;
    if (mode)
        tio.c_lflag |= ECHO;
    else
        tio.c_lflag &= (tcflag_t) ~ECHO;
    return tcsetattr (fd, TCSANOW, &tio);
}

static void
bsc_timing_event (FILE *ftim, int advanced, char tag, double delta, long bytes)
{
    if (!ftim) return;
    if (advanced)
        fprintf (ftim, "%c %.6f %ld\n", tag, delta, bytes);
    else if (tag == 'O')
        fprintf (ftim, "%.6f %ld\n", delta, bytes);
}

static void
bsc_timing_resize (FILE *ftim, int advanced, double delta,
                   unsigned int rows, unsigned int cols)
{
    if (!ftim) return;
    if (advanced)
        fprintf (ftim, "S %.6f SIGWINCH ROWS=%u COLS=%u\n", delta, rows, cols);
    else
        fprintf (ftim, "%.6f RESIZE %u %u\n", delta, rows, cols);
}

static void
bsc_timing_header (FILE *ftim, int advanced, const char *key, const char *value)
{
    if (!ftim || !advanced || !key || !value) return;
    fprintf (ftim, "H 0.000000 %s %s\n", key, value);
}

/* Save current termios; switch to raw. */
static struct termios bsc_saved_tio;
static int bsc_tio_saved = 0;

static int
bsc_set_raw (void)
{
    if (!isatty (STDIN_FILENO)) return 0;  /* nothing to save */
    if (tcgetattr (STDIN_FILENO, &bsc_saved_tio) < 0) return -1;
    bsc_tio_saved = 1;
    struct termios raw = bsc_saved_tio;
    raw.c_iflag &= (tcflag_t) ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
    raw.c_oflag &= (tcflag_t) ~OPOST;
    raw.c_lflag &= (tcflag_t) ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    raw.c_cflag &= (tcflag_t) ~(CSIZE | PARENB);
    raw.c_cflag |= CS8;
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    tcsetattr (STDIN_FILENO, TCSANOW, &raw);
    return 0;
}

static void
bsc_restore_tio (void)
{
    if (bsc_tio_saved) tcsetattr (STDIN_FILENO, TCSANOW, &bsc_saved_tio);
    bsc_tio_saved = 0;
}

/* Stage 46.A — SIGWINCH capture: a signal handler sets the flag,
 * the main record loop tests it on each tick, propagates the new
 * window size to the slave pty, and emits a RESIZE marker into
 * the typescript / asciinema-cast streams so scriptreplay can
 * reproduce the resize. The handler does the bare minimum that's
 * async-signal-safe; everything else lives in the loop. */
static volatile sig_atomic_t bsc_winch_pending = 0;
static void bsc_winch_handler (int sig) { (void) sig; bsc_winch_pending = 1; }

struct bsc_child_guard {
    struct sigaction old_chld;
    sigset_t oldmask;
};

static int
bsc_child_guard_begin (struct bsc_child_guard *g)
{
    struct sigaction dfl;
    sigset_t block;
    memset (&dfl, 0, sizeof dfl);
    dfl.sa_handler = SIG_DFL;
    sigemptyset (&dfl.sa_mask);
    if (sigaction (SIGCHLD, &dfl, &g->old_chld) < 0)
        return -1;
    sigemptyset (&block);
    sigaddset (&block, SIGCHLD);
    if (sigprocmask (SIG_BLOCK, &block, &g->oldmask) < 0) {
        sigaction (SIGCHLD, &g->old_chld, NULL);
        return -1;
    }
    return 0;
}

static void
bsc_child_guard_parent_end (struct bsc_child_guard *g)
{
    sigprocmask (SIG_SETMASK, &g->oldmask, NULL);
    sigaction (SIGCHLD, &g->old_chld, NULL);
}

static void
bsc_child_guard_child_end (struct bsc_child_guard *g)
{
    sigprocmask (SIG_SETMASK, &g->oldmask, NULL);
}

static int
bsc_record_cmd (WORD_LIST *args)
{
    const char *user_cmd = NULL;
    const char *out_path = NULL, *in_path = NULL, *tim_path = NULL, *cast_path = NULL;
    int timing_advanced = 0;
    int echo_mode = -1;
    long long output_limit = -1, output_seen = 0;
    int flush_mode = 0;          /* Stage 46.B: -f / fdatasync after every write. */
    int append_mode = 0;         /* W5.D: util-linux script(1) -a parity — append vs truncate. */
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-c") == 0 && p->next) { user_cmd = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-I") == 0 && p->next) { in_path = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-O") == 0 && p->next) { out_path = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-T") == 0 && p->next) { tim_path = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-A") == 0 && p->next) { cast_path = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-m") == 0 && p->next) {
            const char *fmt = p->next->word->word; p = p->next;
            if (strcmp (fmt, "advanced") == 0) timing_advanced = 1;
            else if (strcmp (fmt, "classic") == 0) timing_advanced = 0;
            else { builtin_error ("record: -m must be classic|advanced"); return EX_USAGE; }
        }
        else if (strcmp (w, "-l") == 0 && p->next) {
            output_limit = bsc_parse_limit (p->next->word->word); p = p->next;
            if (output_limit < 0) { builtin_error ("record: bad output limit"); return EX_USAGE; }
        }
        else if (strcmp (w, "-E") == 0 && p->next) {
            if (bsc_echo_mode (p->next->word->word, &echo_mode) < 0) {
                builtin_error ("record: -E must be auto|never|always");
                return EX_USAGE;
            }
            p = p->next;
        }
        else if (strcmp (w, "-f") == 0) { flush_mode = 1; }
        else if (strcmp (w, "-a") == 0 || strcmp (w, "--append") == 0) { append_mode = 1; }
        else if (w[0] == '-' && w[1] != '\0') {
            builtin_error ("record: unknown flag %s", w);
            builtin_usage ();
            return EX_USAGE;
        }
        else { builtin_error ("record: unexpected '%s'", w); builtin_usage (); return EX_USAGE; }
    }
    if (!out_path && !in_path && !tim_path && !cast_path) {
        builtin_error ("record: at least one of -O / -I / -T / -A required");
        return EX_USAGE;
    }
    if (!user_cmd) {
        user_cmd = getenv ("SHELL");
        if (!user_cmd) user_cmd = "/bin/bash";
    }

    /* Allocate pty. */
    int master = posix_openpt (O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (master < 0) { builtin_error ("posix_openpt: %s", strerror (errno)); return EXECUTION_FAILURE; }
    if (grantpt (master) < 0 || unlockpt (master) < 0) {
        builtin_error ("grantpt/unlockpt: %s", strerror (errno));
        close (master); return EXECUTION_FAILURE;
    }
    char slave_path[256];
    if (ptsname_r (master, slave_path, sizeof slave_path) != 0) {
        builtin_error ("ptsname: %s", strerror (errno));
        close (master); return EXECUTION_FAILURE;
    }

    struct winsize ws = {0};
    ioctl (STDIN_FILENO, TIOCGWINSZ, &ws);

    /* Open log files. W5.D: -a / --append uses "ab"/"a" so prior bytes
     * survive. For -A (asciinema v2 cast), the header line is only
     * emitted when the file is newly created or empty — appending to an
     * existing cast continues the event stream so scriptreplay / asciicast
     * players see one coherent recording instead of two stacked headers. */
    FILE *fout = NULL, *fin = NULL, *ftim = NULL, *fcast = NULL;
    if (out_path) {
        fout = fopen (out_path, append_mode ? "ab" : "wb");
        if (!fout) { builtin_error ("open %s: %s", out_path, strerror (errno)); close (master); return EXECUTION_FAILURE; }
    }
    if (in_path) {
        if (out_path && strcmp (in_path, out_path) == 0) {
            fin = fout;
        } else {
            fin = fopen (in_path, append_mode ? "ab" : "wb");
            if (!fin) { builtin_error ("open %s: %s", in_path, strerror (errno)); if (fout) fclose (fout); close (master); return EXECUTION_FAILURE; }
        }
    }
    if (tim_path) {
        ftim = fopen (tim_path, append_mode ? "a" : "w");
        if (!ftim) { builtin_error ("open %s: %s", tim_path, strerror (errno)); if (fin && fin != fout) fclose (fin); if (fout) fclose (fout); close (master); return EXECUTION_FAILURE; }
    }
    if (cast_path) {
        /* Header suppression check is done BEFORE fopen so a fresh
         * stat() reflects on-disk state (some libcs leave the position
         * indicator at 0 immediately after fopen("a"), making ftell()
         * unreliable for "is the file already populated?" detection). */
        int emit_header = 1;
        if (append_mode) {
            struct stat st;
            if (stat (cast_path, &st) == 0 && st.st_size > 0)
                emit_header = 0;
        }
        fcast = fopen (cast_path, append_mode ? "a" : "w");
        if (!fcast) { builtin_error ("open %s: %s", cast_path, strerror (errno)); if (fin && fin != fout) fclose (fin); if (fout) fclose (fout); if (ftim) fclose (ftim); close (master); return EXECUTION_FAILURE; }
        if (emit_header) {
            /* Asciinema v2 header line. */
            unsigned short cols = ws.ws_col ? ws.ws_col : 80;
            unsigned short rows = ws.ws_row ? ws.ws_row : 24;
            fprintf (fcast,
                     "{\"version\":2,\"width\":%u,\"height\":%u,\"timestamp\":%lld}\n",
                     cols, rows, (long long) time (NULL));
        }
    }
    if (ftim && timing_advanced) {
        char tmp[256];
        snprintf (tmp, sizeof tmp, "%lld", (long long) time (NULL));
        bsc_timing_header (ftim, 1, "START_TIME", tmp);
        bsc_timing_header (ftim, 1, "TERM", getenv ("TERM") ? getenv ("TERM") : "unknown");
        snprintf (tmp, sizeof tmp, "%u", ws.ws_col ? ws.ws_col : 80);
        bsc_timing_header (ftim, 1, "COLUMNS", tmp);
        snprintf (tmp, sizeof tmp, "%u", ws.ws_row ? ws.ws_row : 24);
        bsc_timing_header (ftim, 1, "LINES", tmp);
        bsc_timing_header (ftim, 1, "SHELL", user_cmd);
        if (out_path) bsc_timing_header (ftim, 1, "OUTPUT_LOG", out_path);
        if (in_path)  bsc_timing_header (ftim, 1, "INPUT_LOG", in_path);
        if (tim_path) bsc_timing_header (ftim, 1, "TIMING_LOG", tim_path);
    }

    /* Inherit window size to slave. */
    if (ws.ws_col || ws.ws_row) {
        ioctl (master, TIOCSWINSZ, &ws);
    }

    /* Fork child. */
    struct bsc_child_guard guard;
    if (bsc_child_guard_begin (&guard) < 0) {
        builtin_error ("SIGCHLD guard: %s", strerror (errno));
        if (fin && fin != fout) fclose (fin);
        if (fout) fclose (fout);
        if (ftim) fclose (ftim);
        if (fcast) fclose (fcast);
        close (master);
        return EXECUTION_FAILURE;
    }
    pid_t pid = fork ();
    if (pid < 0) {
        bsc_child_guard_parent_end (&guard);
        builtin_error ("fork: %s", strerror (errno));
        if (fin && fin != fout) fclose (fin);
        if (fout) fclose (fout);
        if (ftim) fclose (ftim);
        if (fcast) fclose (fcast);
        close (master);
        return EXECUTION_FAILURE;
    }
    if (pid == 0) {
        bsc_child_guard_child_end (&guard);
        /* Child: open slave, become session leader, dup to 0/1/2, exec. */
        close (master);
        setsid ();
        int slave = open (slave_path, O_RDWR);
        if (slave < 0) _exit (126);
        ioctl (slave, TIOCSCTTY, 0);
        bsc_apply_echo (slave, echo_mode);
        dup2 (slave, 0); dup2 (slave, 1); dup2 (slave, 2);
        if (slave > 2) close (slave);
        bos_prepare_child ();
        char *eval_argv[] = {"eval", (char *) user_cmd, NULL};
        bos_run_builtin ("eval", eval_argv, NULL);
        execl ("/bin/sh", "sh", "-c", user_cmd, (char *) NULL);
        _exit (127);
    }

    /* Parent: relay stdin↔master, master→files. */
    bsc_set_raw ();

    /* Stage 46.A: install SIGWINCH handler so terminal resizes are
     * recorded as RESIZE events. SA_RESTART left OFF so select() returns
     * EINTR after the signal — the loop tick re-runs and observes the
     * winch_pending flag. */
    bsc_winch_pending = 0;
    struct sigaction sa_winch = {0};
    sa_winch.sa_handler = bsc_winch_handler;
    sigemptyset (&sa_winch.sa_mask);
    sa_winch.sa_flags = 0;
    struct sigaction sa_winch_prev;
    sigaction (SIGWINCH, &sa_winch, &sa_winch_prev);

    double last_tick = bsc_now_secs ();
    double start_tick = last_tick;
    char buf[4096];
    int limit_hit = 0;

    int stdin_open = 1;
    for (;;) {
        /* Stage 46.A: drain a pending SIGWINCH before every select tick.
         * The handler is async-signal-safe (just a flag); the actual
         * ioctl + write happens here in normal context. */
        if (bsc_winch_pending) {
            bsc_winch_pending = 0;
            struct winsize ws2 = {0};
            if (ioctl (STDIN_FILENO, TIOCGWINSZ, &ws2) == 0 && ws2.ws_col && ws2.ws_row) {
                /* Propagate to slave so the child app re-renders. */
                ioctl (master, TIOCSWINSZ, &ws2);
                double now = bsc_now_secs ();
                if (ftim) {
                    bsc_timing_resize (ftim, timing_advanced, now - last_tick,
                                       ws2.ws_row, ws2.ws_col);
                    if (flush_mode) { fflush (ftim); fdatasync (fileno (ftim)); }
                }
                if (fcast) {
                    /* Asciinema v2 first-class resize event:
                     *   [TIME, "r", "COLSxROWS"] */
                    fprintf (fcast, "[%.6f, \"r\", \"%ux%u\"]\n",
                             now - start_tick, ws2.ws_col, ws2.ws_row);
                    if (flush_mode) { fflush (fcast); fdatasync (fileno (fcast)); }
                }
                last_tick = now;
            }
        }

        fd_set rfds;
        FD_ZERO (&rfds);
        if (stdin_open)
            FD_SET (STDIN_FILENO, &rfds);
        FD_SET (master, &rfds);
        int nfds = master > STDIN_FILENO ? master : STDIN_FILENO;
        int sel = select (nfds + 1, &rfds, NULL, NULL, NULL);
        if (sel < 0) { if (errno == EINTR) continue; break; }
        if (stdin_open && FD_ISSET (STDIN_FILENO, &rfds)) {
            ssize_t n = read (STDIN_FILENO, buf, sizeof buf);
            if (n <= 0) {
                stdin_open = 0;
                continue;
            }
            double now = bsc_now_secs ();
            if (fin) {
                fwrite (buf, 1, (size_t) n, fin);
                if (flush_mode) { fflush (fin); fdatasync (fileno (fin)); }
            }
            if (ftim && timing_advanced) {
                bsc_timing_event (ftim, timing_advanced, 'I', now - last_tick, n);
                if (flush_mode) { fflush (ftim); fdatasync (fileno (ftim)); }
            }
            if (fcast) {
                char *enc = bsc_json_encode ((unsigned char *) buf, (size_t) n);
                if (enc) {
                    fprintf (fcast, "[%.6f, \"i\", \"%s\"]\n", now - start_tick, enc);
                    free (enc);
                }
                if (flush_mode) { fflush (fcast); fdatasync (fileno (fcast)); }
            }
            if (ftim && timing_advanced)
                last_tick = now;
            ssize_t off = 0;
            while (off < n) {
                ssize_t w = write (master, buf + off, (size_t) (n - off));
                if (w < 0) { if (errno == EINTR) continue; break; }
                off += w;
            }
        }
        if (FD_ISSET (master, &rfds)) {
            ssize_t n = read (master, buf, sizeof buf);
            if (n <= 0) break;
            /* Mirror to stdout (so user sees output). */
            ssize_t off = 0;
            while (off < n) {
                ssize_t w = write (STDOUT_FILENO, buf + off, (size_t) (n - off));
                if (w < 0) { if (errno == EINTR) continue; break; }
                off += w;
            }
            /* Log to files. */
            if (fout) {
                fwrite (buf, 1, (size_t) n, fout);
                if (flush_mode) { fflush (fout); fdatasync (fileno (fout)); }
            }
            double now = bsc_now_secs ();
            if (ftim) {
                bsc_timing_event (ftim, timing_advanced, 'O', now - last_tick, n);
                if (flush_mode) { fflush (ftim); fdatasync (fileno (ftim)); }
            }
            if (fcast) {
                char *enc = bsc_json_encode ((unsigned char *) buf, (size_t) n);
                if (enc) {
                    fprintf (fcast, "[%.6f, \"o\", \"%s\"]\n", now - start_tick, enc);
                    free (enc);
                }
                if (flush_mode) { fflush (fcast); fdatasync (fileno (fcast)); }
            }
            last_tick = now;
            output_seen += n;
            if (output_limit >= 0 && output_seen > output_limit) {
                builtin_error ("record: max output size exceeded");
                limit_hit = 1;
                kill (pid, SIGTERM);
                break;
            }
        }
    }

    /* Stage 46.A: restore the previous SIGWINCH handler — script
     * runs as a builtin in the user's shell, so leaving our handler in
     * place would persist across record invocations. */
    sigaction (SIGWINCH, &sa_winch_prev, NULL);

    bsc_restore_tio ();
    if (ftim && timing_advanced) {
        double dur = bsc_now_secs () - start_tick;
        char tmp[128];
        snprintf (tmp, sizeof tmp, "%.6f", dur);
        bsc_timing_header (ftim, 1, "DURATION", tmp);
    }
    close (master);
    int status = 0;
    pid_t w;
    while ((w = waitpid (pid, &status, 0)) < 0) {
        if (errno == EINTR) continue;
        break;
    }
    bsc_child_guard_parent_end (&guard);
    if (ftim && timing_advanced) {
        char tmp[64];
        int code = (w == pid && WIFEXITED (status)) ? WEXITSTATUS (status) : 1;
        snprintf (tmp, sizeof tmp, "%d", code);
        bsc_timing_header (ftim, 1, "EXIT_CODE", tmp);
    }
    if (fin && fin != fout) fclose (fin);
    if (fout) fclose (fout);
    if (ftim) fclose (ftim);
    if (fcast) fclose (fcast);
    if (limit_hit)
        return EXECUTION_FAILURE;
    return w == pid && WIFEXITED (status) ? WEXITSTATUS (status) : 1;
}

static int
bsc_replay_cmd (WORD_LIST *args)
{
    const char *tim = NULL, *out = NULL, *in = NULL, *streams = "O";
    double divisor = 1.0;
    int out_fd = STDOUT_FILENO;
    int npos = 0;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (strcmp (w, "-d") == 0 && p->next) { divisor = atof (p->next->word->word); p = p->next; }
        else if (strcmp (w, "-I") == 0 && p->next) { in = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-x") == 0 && p->next) { streams = p->next->word->word; p = p->next; }
        else if (strcmp (w, "-F") == 0 && p->next) { out_fd = atoi (p->next->word->word); p = p->next; }
        else if (w[0] == '-' && w[1] != '\0') {
            builtin_error ("replay: unknown flag %s", w);
            builtin_usage ();
            return EX_USAGE;
        } else {
            if (npos == 0) tim = w;
            else if (npos == 1) out = w;
            else { builtin_error ("replay: too many args"); return EX_USAGE; }
            npos++;
        }
    }
    if (!tim || !out) { builtin_error ("replay: TIMING OUT required"); return EX_USAGE; }
    if (divisor <= 0) divisor = 1.0;

    FILE *ft = fopen (tim, "r");
    if (!ft) { builtin_error ("open %s: %s", tim, strerror (errno)); return EXECUTION_FAILURE; }
    FILE *fo = fopen (out, "rb");
    if (!fo) { builtin_error ("open %s: %s", out, strerror (errno)); fclose (ft); return EXECUTION_FAILURE; }
    FILE *fi = NULL;
    if (in) {
        fi = fopen (in, "rb");
        if (!fi) { builtin_error ("open %s: %s", in, strerror (errno)); fclose (fo); fclose (ft); return EXECUTION_FAILURE; }
    }

    char line[512];
    while (fgets (line, sizeof line, ft)) {
        double delay = 0.0;
        long bytes = 0;
        char tag = 'O';
        FILE *src = fo;
        int emit = 1;

        if (line[0] == 'H' || line[0] == 'S')
            continue;
        if ((line[0] == 'O' || line[0] == 'I') && line[1] == ' ') {
            tag = line[0];
            if (sscanf (line + 2, "%lf %ld", &delay, &bytes) != 2)
                continue;
            if (!strchr (streams, tag))
                emit = 0;
            if (tag == 'I') {
                if (!fi) continue;
                src = fi;
            }
        } else {
            if (sscanf (line, "%lf %ld", &delay, &bytes) != 2)
                continue;
            if (!strchr (streams, 'O'))
                emit = 0;
        }
        if (delay > 0) {
            struct timespec slp;
            slp.tv_sec  = (time_t) (delay / divisor);
            slp.tv_nsec = (long) (((delay / divisor) - (double) slp.tv_sec) * 1e9);
            nanosleep (&slp, NULL);
        }
        if (!emit) {
            if (fseek (src, bytes, SEEK_CUR) != 0) {
                char discard[8192];
                long left = bytes;
                while (left > 0) {
                    size_t want = left > (long) sizeof discard ? sizeof discard : (size_t) left;
                    size_t got = fread (discard, 1, want, src);
                    if (got == 0) break;
                    left -= (long) got;
                }
            }
            continue;
        }
        char buf[8192];
        long left = bytes;
        while (left > 0) {
            size_t want = left > (long) sizeof buf ? sizeof buf : (size_t) left;
            size_t got = fread (buf, 1, want, src);
            if (got == 0) break;
            if (write (out_fd, buf, got) != (ssize_t) got)
                break;
            left -= (long) got;
        }
    }
    if (fi) fclose (fi);
    fclose (ft);
    fclose (fo);
    return EXECUTION_SUCCESS;
}

static void
bsc_print_help (void)
{
    puts ("Session recorder (script(1)-style) + asciinema v2 cast emitter.");
    puts ("");
    puts ("    script [--help|-h|--version|-V]");
    puts ("    script record [-c CMD] [-O OUT] [-I IN] [-T TIMING] [-A CAST]");
    puts ("                      [-m classic|advanced] [-l LIMIT] [-E auto|never|always]");
    puts ("                      [-f] [-a|--append]");
    puts ("        Spawn CMD on a pty; record streams. At least one of -O/-I/-T/-A.");
    puts ("        -a / --append: append to OUT/IN/TIMING/CAST instead of truncating.");
    puts ("        Asciinema v2 header is suppressed when -a is appending to a non-empty CAST.");
    puts ("    script replay TIMING OUT [-I IN] [-x OI] [-F FD] [-d DIVISOR]");
    puts ("        Re-emit OUT pacing per TIMING. -d 2 = 2x speed, 0.5 = 0.5x.");
}

int
script_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    if (!strcmp (cmd, "--help") || !strcmp (cmd, "-h")) {
        bsc_print_help ();
        return EXECUTION_SUCCESS;
    }
    if (!strcmp (cmd, "--version") || !strcmp (cmd, "-V")) {
        puts ("script 1.0 (bash-loadable)");
        return EXECUTION_SUCCESS;
    }
    if (!strcmp (cmd, "record")) return bsc_record_cmd (args);
    if (!strcmp (cmd, "replay")) return bsc_replay_cmd (args);
    builtin_error ("unknown verb: %s", cmd);
    builtin_usage ();
    return EX_USAGE;
}

char *script_doc[] = {
    "Session recorder (script(1)-style) + asciinema v2 cast emitter.",
    "",
    "    script [--help|-h|--version|-V]",
    "    script record [-c CMD] [-O OUT] [-I IN] [-T TIMING] [-A CAST]",
    "                      [-m classic|advanced] [-l LIMIT] [-E auto|never|always]",
    "                      [-f] [-a|--append]",
    "        Spawn CMD on a pty; record streams. At least one of -O/-I/-T/-A.",
    "        -a / --append mirrors util-linux `script -a`: prior bytes preserved;",
    "        asciinema v2 header suppressed when CAST already non-empty.",
    "    script replay TIMING OUT [-I IN] [-x OI] [-F FD] [-d DIVISOR]",
    "        Re-emit OUT pacing per TIMING. -d 2 = 2× speed, 0.5 = 0.5×.",
    (char *)NULL
};

struct builtin script_struct = {
    "script",
    script_builtin,
    BUILTIN_ENABLED,
    script_doc,
    "script [--help|-h|--version|-V] record|replay ARGS",
    0
};
