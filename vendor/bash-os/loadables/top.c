/* SPDX-License-Identifier: MIT */
/* top.c — interactive top(1) over /proc + termraw-style termios.
 *
 *   top [--once|-b] [-n COUNT] [-d SEC] [-o COL] [-r N]
 *
 *   --once / -b   one snapshot, write to stdout, exit (smoke / batch).
 *   -n COUNT      run COUNT redraws, then exit (default: forever).
 *   -d SEC        refresh interval, integer seconds (default 2).
 *   -o COL        initial sort column: cpu, mem, pid, time (default cpu).
 *   -r N          row cap (max process rows, default = tty rows - 7).
 *
 * Interactive keys (TUI mode):
 *   q / ESC     exit
 *   space       redraw immediately
 *   Up / Down   scroll process list by one row
 *   PgUp / PgDn scroll process list by one page
 *   Home / End  jump to first / last process
 *   n           prompt for new refresh interval
 *   o           cycle sort column (cpu → mem → pid → time → cpu)
 *   k           prompt for PID + signal, send signal
 *   r           prompt for PID + nice delta, renice
 *
 * Data sources:
 *   /proc/[pid]/stat       — pid, comm, state, ppid, utime+stime, rss, vsize
 *   /proc/[pid]/status     — Uid (for username via getpwuid)
 *   /proc/[pid]/cmdline    — full args (NUL-separated)
 *   /proc/stat             — total CPU jiffies for %CPU delta
 *   /proc/meminfo          — MemTotal/MemAvailable/SwapTotal/SwapFree
 *   /proc/loadavg          — load averages (1/5/15)
 *
 * Source counterparts consulted (none ported verbatim):
 *   research/refs/procps-ng/src/top/top.c   (canonical, big)
 *   research/refs/busybox/procps/top.c      (minimal)
 *   research/refs/toybox/toys/posix/top.c   (middle)
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as ps.c. When statically linked
 * into bash, the combined binary is governed by bash's GPL-3+.
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
#include <ctype.h>
#include <dirent.h>
#include <pwd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <termios.h>
#include <poll.h>
#include <time.h>

/* Shared CSI/SS3 key decoder (vendored under scripts/loadables/_bl_key/,
 * flattened to builtins/_bl_key_bl_key.{c,h} by patch-bash-loadables.sh).
 * Bashtop uses it for arrow/PgUp/PgDn/Home/End scroll of the process
 * list — see btop_run_interactive's input dispatch. */
#include "_bl_key_bl_key.h"
#include "_bl_screen_screen.h"   /* ncurses-subset cell/diff TUI engine */

#include "loadables.h"

#define BTOP_BUF       4096
#define BTOP_MAX_PROCS 8192
#define BTOP_COMM_LEN  64
#define BTOP_ARGS_LEN  256

/* --- per-process snapshot ----------------------------------------------- */
typedef struct {
    int   pid;
    int   ppid;
    uid_t uid;
    char  state;
    char  comm[BTOP_COMM_LEN];
    char  args[BTOP_ARGS_LEN];
    long  utime;        /* jiffies */
    long  stime;        /* jiffies */
    long  rss_pages;    /* RSS in pages */
    long  vsize_bytes;
    long  nice;
    /* derived */
    long  cpu_total;    /* utime + stime, current snapshot */
    long  cpu_delta;    /* (utime+stime) - prev (utime+stime) */
    double pcpu;        /* % of total cpu time in interval */
} btop_proc;

/* --- system-wide snapshot ------------------------------------------------ */
typedef struct {
    long  cpu_jiffies_total;  /* sum of all fields in /proc/stat cpu line */
    long  mem_total_kb;
    long  mem_avail_kb;
    long  swap_total_kb;
    long  swap_free_kb;
    char  loadavg[64];
    int   nproc;              /* count populated in procs[] */
} btop_sys;

/* --- sort column enum --------------------------------------------------- */
typedef enum {
    BTOP_SORT_CPU = 0,
    BTOP_SORT_MEM,
    BTOP_SORT_PID,
    BTOP_SORT_TIME,
    BTOP_SORT__COUNT
} btop_sort;

static const char *btop_sort_name[BTOP_SORT__COUNT] = {
    "CPU", "MEM", "PID", "TIME"
};

/* --- prev-snapshot table (pid → prev cpu_total) ------------------------- */
typedef struct {
    int  pid;
    long cpu_total;
    long cpu_jiffies_total;  /* system total at that snapshot */
} btop_prev;

static btop_prev *btop_prev_tbl = NULL;
static int        btop_prev_n   = 0;
static long       btop_prev_total = 0;

/* Terminal lifecycle, raw mode, winsize, alt-screen and the diff-optimized
   frame emit are owned by the shared _bl_screen module (interactive mode). */

/* --- helpers ------------------------------------------------------------ */

static long
btop_page_size (void)
{
    long p = sysconf (_SC_PAGESIZE);
    return p > 0 ? p : 4096;
}

static const char *
btop_user (uid_t uid)
{
    static char buf[32];
    struct passwd *pw = getpwuid (uid);
    if (pw) return pw->pw_name;
    snprintf (buf, sizeof buf, "%u", (unsigned) uid);
    return buf;
}

/* Read /proc/[pid]/stat into p. Anchor on the LAST ')' to skip past comm
   (which may contain spaces or parentheses). */
static int
btop_read_stat (int pid, btop_proc *p)
{
    char path[64];
    snprintf (path, sizeof path, "/proc/%d/stat", pid);
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buf[BTOP_BUF];
    ssize_t n = read (fd, buf, sizeof buf - 1);
    close (fd);
    if (n <= 0) return -1;
    buf[n] = '\0';

    char *first = strchr (buf, '(');
    char *last  = strrchr (buf, ')');
    if (!first || !last || first >= last) return -1;
    size_t clen = (size_t)(last - first - 1);
    if (clen >= sizeof p->comm) clen = sizeof p->comm - 1;
    memcpy (p->comm, first + 1, clen);
    p->comm[clen] = '\0';

    /* Per proc(5): after `pid (comm) `:
       (3) state (4) ppid (5) pgrp (6) sid (7) tty_nr (8) tpgid (9) flags
       (10) minflt (11) cminflt (12) majflt (13) cmajflt
       (14) utime (15) stime (16) cutime (17) cstime
       (18) priority (19) nice ...
       (23) vsize (24) rss */
    char *rest = last + 2;
    long prio;
    int got = sscanf (rest,
        "%c %d %*d %*d %*d %*d %*u "             /* state ppid pgrp sid tty tpgid flags */
        "%*u %*u %*u %*u "                       /* minflt cminflt majflt cmajflt */
        "%ld %ld %*d %*d "                       /* utime stime cutime cstime */
        "%ld %ld "                               /* priority nice */
        "%*d %*d %*d "                           /* num_threads itrealvalue starttime placeholder */
        "%ld %ld",                               /* vsize rss */
        &p->state, &p->ppid,
        &p->utime, &p->stime,
        &prio, &p->nice,
        &p->vsize_bytes, &p->rss_pages);
    if (got < 4) return -1;

    p->pid = pid;
    p->cpu_total = p->utime + p->stime;

    /* uid via /proc/PID/status */
    snprintf (path, sizeof path, "/proc/%d/status", pid);
    fd = open (path, O_RDONLY | O_CLOEXEC);
    p->uid = 0;
    if (fd >= 0) {
        char sbuf[1024];
        ssize_t sn = read (fd, sbuf, sizeof sbuf - 1);
        close (fd);
        if (sn > 0) {
            sbuf[sn] = '\0';
            char *u = strstr (sbuf, "\nUid:");
            if (u) {
                long uid_val = 0;
                sscanf (u, "\nUid:\t%ld", &uid_val);
                p->uid = (uid_t) uid_val;
            }
        }
    }

    /* args via /proc/PID/cmdline */
    snprintf (path, sizeof path, "/proc/%d/cmdline", pid);
    fd = open (path, O_RDONLY | O_CLOEXEC);
    p->args[0] = '\0';
    if (fd >= 0) {
        ssize_t an = read (fd, p->args, sizeof p->args - 1);
        close (fd);
        if (an > 0) {
            for (ssize_t i = 0; i < an - 1; i++)
                if (p->args[i] == '\0') p->args[i] = ' ';
            p->args[an] = '\0';
        }
    }
    if (!p->args[0])
        snprintf (p->args, sizeof p->args, "[%s]", p->comm);

    return 0;
}

/* Read /proc/stat first 'cpu' line; sum fields = total jiffies across CPUs. */
static long
btop_read_cpu_total (void)
{
    int fd = open ("/proc/stat", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    char buf[BTOP_BUF];
    ssize_t n = read (fd, buf, sizeof buf - 1);
    close (fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    /* First line: "cpu  user nice system idle iowait irq softirq steal guest guest_nice" */
    if (strncmp (buf, "cpu ", 4) != 0 && strncmp (buf, "cpu\t", 4) != 0) return 0;
    char *p = buf + 3;
    long total = 0;
    char *end;
    while (*p && *p != '\n') {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\n' || *p == '\0') break;
        long v = strtol (p, &end, 10);
        if (end == p) break;
        total += v;
        p = end;
    }
    return total;
}

/* Read /proc/meminfo into sys. Robust: parse line-by-line. */
static void
btop_read_meminfo (btop_sys *sys)
{
    sys->mem_total_kb = sys->mem_avail_kb = 0;
    sys->swap_total_kb = sys->swap_free_kb = 0;
    int fd = open ("/proc/meminfo", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    char buf[BTOP_BUF];
    ssize_t n = read (fd, buf, sizeof buf - 1);
    close (fd);
    if (n <= 0) return;
    buf[n] = '\0';
    char *line = buf;
    while (*line) {
        char *nl = strchr (line, '\n');
        if (nl) *nl = '\0';
        long v;
        if      (sscanf (line, "MemTotal: %ld kB",     &v) == 1) sys->mem_total_kb  = v;
        else if (sscanf (line, "MemAvailable: %ld kB", &v) == 1) sys->mem_avail_kb  = v;
        else if (sscanf (line, "SwapTotal: %ld kB",    &v) == 1) sys->swap_total_kb = v;
        else if (sscanf (line, "SwapFree: %ld kB",     &v) == 1) sys->swap_free_kb  = v;
        if (!nl) break;
        line = nl + 1;
    }
}

static void
btop_read_loadavg (btop_sys *sys)
{
    sys->loadavg[0] = '\0';
    int fd = open ("/proc/loadavg", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    ssize_t n = read (fd, sys->loadavg, sizeof sys->loadavg - 1);
    close (fd);
    if (n <= 0) { sys->loadavg[0] = '\0'; return; }
    sys->loadavg[n] = '\0';
    /* keep just the three load numbers (chop after the 3rd whitespace-sep field). */
    int spaces = 0;
    for (char *q = sys->loadavg; *q; q++) {
        if (*q == ' ') { spaces++; if (spaces == 3) { *q = '\0'; break; } }
        if (*q == '\n') { *q = '\0'; break; }
    }
}

/* --- sample everything ------------------------------------------------- */
static int
btop_sample (btop_proc *procs, int cap, btop_sys *sys)
{
    sys->cpu_jiffies_total = btop_read_cpu_total ();
    btop_read_meminfo (sys);
    btop_read_loadavg (sys);

    DIR *d = opendir ("/proc");
    if (!d) return -1;
    int n = 0;
    struct dirent *de;
    while ((de = readdir (d)) && n < cap) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        int pid = atoi (de->d_name);
        if (pid <= 0) continue;
        btop_proc p; memset (&p, 0, sizeof p);
        if (btop_read_stat (pid, &p) == 0) {
            procs[n++] = p;
        }
    }
    closedir (d);
    sys->nproc = n;
    return n;
}

/* --- prev-snapshot lookup ---------------------------------------------- */
static long
btop_prev_lookup (int pid)
{
    for (int i = 0; i < btop_prev_n; i++)
        if (btop_prev_tbl[i].pid == pid) return btop_prev_tbl[i].cpu_total;
    return -1;
}

static void
btop_prev_store (btop_proc *procs, int n, long cpu_total)
{
    free (btop_prev_tbl);
    btop_prev_tbl = (btop_prev *) calloc ((size_t) n, sizeof (btop_prev));
    if (!btop_prev_tbl) { btop_prev_n = 0; btop_prev_total = 0; return; }
    btop_prev_n = n;
    btop_prev_total = cpu_total;
    for (int i = 0; i < n; i++) {
        btop_prev_tbl[i].pid = procs[i].pid;
        btop_prev_tbl[i].cpu_total = procs[i].cpu_total;
    }
}

/* --- compute pcpu, then sort ------------------------------------------- */
static void
btop_compute_pcpu (btop_proc *procs, int n, long cpu_total)
{
    long delta_total = cpu_total - btop_prev_total;
    if (delta_total <= 0) delta_total = 1;  /* avoid div-by-zero */
    for (int i = 0; i < n; i++) {
        long prev = btop_prev_lookup (procs[i].pid);
        if (prev < 0) { procs[i].cpu_delta = 0; procs[i].pcpu = 0.0; continue; }
        long d = procs[i].cpu_total - prev;
        if (d < 0) d = 0;
        procs[i].cpu_delta = d;
        procs[i].pcpu = (double) d * 100.0 / (double) delta_total;
    }
}

/* --- comparators -------------------------------------------------------- */
static int
btop_cmp_cpu (const void *a, const void *b)
{
    const btop_proc *p = a, *q = b;
    if (p->pcpu < q->pcpu) return 1;
    if (p->pcpu > q->pcpu) return -1;
    return q->pid - p->pid;
}
static int
btop_cmp_mem (const void *a, const void *b)
{
    const btop_proc *p = a, *q = b;
    if (p->rss_pages < q->rss_pages) return 1;
    if (p->rss_pages > q->rss_pages) return -1;
    return q->pid - p->pid;
}
static int
btop_cmp_pid (const void *a, const void *b)
{
    const btop_proc *p = a, *q = b;
    return p->pid - q->pid;
}
static int
btop_cmp_time (const void *a, const void *b)
{
    const btop_proc *p = a, *q = b;
    if (p->cpu_total < q->cpu_total) return 1;
    if (p->cpu_total > q->cpu_total) return -1;
    return q->pid - p->pid;
}

static void
btop_sort_procs (btop_proc *procs, int n, btop_sort sort)
{
    int (*cmp) (const void *, const void *);
    switch (sort) {
        case BTOP_SORT_MEM:  cmp = btop_cmp_mem;  break;
        case BTOP_SORT_PID:  cmp = btop_cmp_pid;  break;
        case BTOP_SORT_TIME: cmp = btop_cmp_time; break;
        case BTOP_SORT_CPU:
        default:             cmp = btop_cmp_cpu;  break;
    }
    qsort (procs, (size_t) n, sizeof procs[0], cmp);
}

/* --- formatting --------------------------------------------------------- */

static void
btop_print_header (FILE *fp, const btop_sys *sys, int delay_sec, btop_sort sort,
                   const char *extra)
{
    long mem_used = sys->mem_total_kb - sys->mem_avail_kb;
    long swap_used = sys->swap_total_kb - sys->swap_free_kb;
    fprintf (fp, "top - load %s  procs %d  sort %s  every %ds\n",
             sys->loadavg[0] ? sys->loadavg : "?", sys->nproc,
             btop_sort_name[sort], delay_sec);
    fprintf (fp, "Mem: %ld kB total, %ld kB used, %ld kB avail\n",
             sys->mem_total_kb, mem_used, sys->mem_avail_kb);
    fprintf (fp, "Swap: %ld kB total, %ld kB used, %ld kB free\n",
             sys->swap_total_kb, swap_used, sys->swap_free_kb);
    if (extra && extra[0])
        fprintf (fp, "%s\n", extra);
    fprintf (fp, "  PID USER     %%CPU    RSS S COMMAND\n");
}

static void
btop_print_row (FILE *fp, const btop_proc *p)
{
    long rss_kb = p->rss_pages * btop_page_size () / 1024;
    const char *cmd = p->args[0] ? p->args : p->comm;
    fprintf (fp, "%5d %-8.8s %5.1f %6ld %c %s\n",
             p->pid, btop_user (p->uid), p->pcpu, rss_kb, p->state, cmd);
}

/* --- cell-drawing variants for interactive mode (_bl_screen) ----------- */

/* Draw the header block into stdscr; returns the row after the header (where
   the process rows begin). Truecolor title/column bars exercise the new path. */
static int
btop_draw_header (bls_win *w, const btop_sys *sys, int delay_sec,
                  btop_sort sort, const char *extra)
{
    long mem_used = sys->mem_total_kb - sys->mem_avail_kb;
    long swap_used = sys->swap_total_kb - sys->swap_free_kb;
    int cols = bls_cols (); char bar[1024];
    int row = 0;

    bls_attrset (w, BLS_A_BOLD);
    bls_setfg (w, BLS_RGB (16, 16, 24)); bls_setbg (w, BLS_RGB (120, 200, 140));
    snprintf (bar, sizeof bar, " top  load %s  procs %d  sort %s  every %ds",
              sys->loadavg[0] ? sys->loadavg : "?", sys->nproc,
              btop_sort_name[sort], delay_sec);
    bls_mvaddstr (w, row, 0, bar); bls_clrtoeol (w); row++;

    bls_attrset (w, BLS_A_NORMAL); bls_setfg (w, BLS_DEFAULT); bls_setbg (w, BLS_DEFAULT);
    bls_move (w, row, 0);
    bls_printw (w, "Mem: %ld kB total, %ld kB used, %ld kB avail",
                sys->mem_total_kb, mem_used, sys->mem_avail_kb);
    bls_clrtoeol (w); row++;
    bls_move (w, row, 0);
    bls_printw (w, "Swap: %ld kB total, %ld kB used, %ld kB free",
                sys->swap_total_kb, swap_used, sys->swap_free_kb);
    bls_clrtoeol (w); row++;
    if (extra && extra[0]) {
        bls_attrset (w, BLS_A_BOLD); bls_setfg (w, BLS_RGB (255, 220, 120));
        bls_mvaddstr (w, row, 0, extra); bls_clrtoeol (w);
        bls_attrset (w, BLS_A_NORMAL); bls_setfg (w, BLS_DEFAULT); row++;
    }
    bls_attrset (w, BLS_A_REVERSE);
    snprintf (bar, sizeof bar, "%-*.*s", cols, cols, "  PID USER     %CPU    RSS S COMMAND");
    bls_mvaddstr (w, row, 0, bar);
    bls_attrset (w, BLS_A_NORMAL);
    row++;
    return row;
}

static void
btop_draw_row (bls_win *w, int row, const btop_proc *p)
{
    long rss_kb = p->rss_pages * btop_page_size () / 1024;
    const char *cmd = p->args[0] ? p->args : p->comm;
    bls_setfg (w, BLS_DEFAULT); bls_setbg (w, BLS_DEFAULT); bls_attrset (w, BLS_A_NORMAL);
    bls_move (w, row, 0);
    bls_printw (w, "%5d %-8.8s %5.1f %6ld %c %s",
                p->pid, btop_user (p->uid), p->pcpu, rss_kb, p->state, cmd);
    bls_clrtoeol (w);
}

/* termios/tty/winsize/cursor and the cooked-prompt path are now provided by
   the shared _bl_screen module (bls_init/bls_getnstr/...). */

/* --- once mode --------------------------------------------------------- */
static int
btop_run_once (btop_sort sort, int row_cap)
{
    btop_proc *procs = (btop_proc *) calloc (BTOP_MAX_PROCS, sizeof (btop_proc));
    if (!procs) { builtin_error ("out of memory"); return EXECUTION_FAILURE; }
    btop_sys sys; memset (&sys, 0, sizeof sys);

    /* Two snapshots ~200ms apart so %CPU has real numbers in --once. */
    int n = btop_sample (procs, BTOP_MAX_PROCS, &sys);
    if (n < 0) {
        free (procs);
        builtin_error ("opendir /proc: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    long cpu_total_1 = sys.cpu_jiffies_total;
    btop_prev_store (procs, n, cpu_total_1);

    struct timespec ts = { 0, 200000000L };  /* 200 ms */
    nanosleep (&ts, NULL);

    n = btop_sample (procs, BTOP_MAX_PROCS, &sys);
    if (n < 0) {
        free (procs);
        builtin_error ("opendir /proc: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    btop_compute_pcpu (procs, n, sys.cpu_jiffies_total);
    btop_sort_procs (procs, n, sort);

    btop_print_header (stdout, &sys, 0, sort, "(--once snapshot)");
    int limit = row_cap > 0 && row_cap < n ? row_cap : n;
    for (int i = 0; i < limit; i++)
        btop_print_row (stdout, &procs[i]);

    free (procs);
    return EXECUTION_SUCCESS;
}

/* --- interactive mode -------------------------------------------------- */
static int
btop_run_interactive (int delay_sec, btop_sort sort, int max_iters, int row_cap)
{
    btop_proc *procs = (btop_proc *) calloc (BTOP_MAX_PROCS, sizeof (btop_proc));
    if (!procs) { builtin_error ("out of memory"); return EXECUTION_FAILURE; }
    btop_sys sys; memset (&sys, 0, sizeof sys);

    if (bls_init () != 0) { free (procs); builtin_error ("not a terminal"); return EXECUTION_FAILURE; }
    bls_win *win = bls_stdscr ();
    bls_timeout (delay_sec * 1000);

    /* Prime previous snapshot so the first redraw has %CPU numbers. */
    int n = btop_sample (procs, BTOP_MAX_PROCS, &sys);
    if (n >= 0) btop_prev_store (procs, n, sys.cpu_jiffies_total);

    int iter = 0;
    int redraw = 1;
    int scroll = 0;          /* row offset into the sorted process list */
    int last_n = n;          /* last n seen by redraw (for clamping) */
    int last_window = 1;     /* last visible window size (for PgUp/PgDn) */
    char extra[160] = "";
    int rc = EXECUTION_SUCCESS;

    for (;;) {
        if (redraw) {
            n = btop_sample (procs, BTOP_MAX_PROCS, &sys);
            if (n < 0) {
                rc = EXECUTION_FAILURE;
                break;
            }
            btop_compute_pcpu (procs, n, sys.cpu_jiffies_total);
            btop_sort_procs (procs, n, sort);

            /* Clamp scroll offset against the post-sample list. */
            if (scroll < 0) scroll = 0;
            if (n > 0 && scroll > n - 1) scroll = n - 1;
            last_n = n;

            bls_erase (win);
            int hr = btop_draw_header (win, &sys, delay_sec, sort, extra);
            int limit = bls_lines () - hr;
            if (row_cap > 0 && row_cap < limit) limit = row_cap;
            if (limit < 1) limit = 1;
            last_window = limit;
            int avail = n - scroll;
            int rowmax = limit > avail ? avail : limit;
            if (rowmax < 0) rowmax = 0;
            for (int i = 0; i < rowmax; i++)
                btop_draw_row (win, hr + i, &procs[scroll + i]);
            bls_move (win, bls_lines () - 1, 0);
            bls_refresh (win);

            btop_prev_store (procs, n, sys.cpu_jiffies_total);
            extra[0] = '\0';
            redraw = 0;
            iter++;
            if (max_iters > 0 && iter >= max_iters) break;
        }

        /* bls_getch blocks up to the refresh interval (bls_timeout); a timeout
         * or a SIGWINCH-interrupted poll both surface as BLS_ERR → redraw.
         * bls_refresh re-queries the terminal size on resize internally. */
        int k = bls_getch ();
        if (k == BLS_ERR) { redraw = 1; continue; }
        if (k == BLS_KEY_NONE) {
            /* EOF on stdin (pipe-fed input drained). Treat as exit. */
            break;
        }
        if (k == 0x03) goto out;          /* Ctrl-C → quit */
        if (k == BL_KEY_ESC) goto out;     /* bare ESC → quit */

        /* Page size for PgUp/PgDn — visible-window minus 1 row of
         * overlap, never less than 1. */
        int page = last_window > 1 ? last_window - 1 : 1;

        switch (k) {
            case 'q': case 'Q':
                goto out;
            case ' ':
                redraw = 1;
                break;
            case BL_KEY_UP:
                if (scroll > 0) { scroll--; redraw = 1; }
                break;
            case BL_KEY_DOWN:
                if (scroll + 1 < last_n) { scroll++; redraw = 1; }
                break;
            case BL_KEY_PGUP:
                scroll -= page;
                if (scroll < 0) scroll = 0;
                redraw = 1;
                break;
            case BL_KEY_PGDN: {
                int max_scroll = last_n - 1;
                if (max_scroll < 0) max_scroll = 0;
                scroll += page;
                if (scroll > max_scroll) scroll = max_scroll;
                redraw = 1;
                break;
            }
            case BL_KEY_HOME:
                scroll = 0;
                redraw = 1;
                break;
            case BL_KEY_END: {
                int max_scroll = last_n - 1;
                if (max_scroll < 0) max_scroll = 0;
                scroll = max_scroll;
                redraw = 1;
                break;
            }
            case 'o': case 'O':
                sort = (btop_sort) ((sort + 1) % BTOP_SORT__COUNT);
                snprintf (extra, sizeof extra, "sort → %s", btop_sort_name[sort]);
                redraw = 1;
                break;
            case 'n': case 'N': {
                char buf[32];
                if (bls_getnstr (win, bls_lines () - 1, 0,"delay (s): ", buf, sizeof buf) > 0) {
                    int v = atoi (buf);
                    if (v > 0 && v < 3600) { delay_sec = v; bls_timeout (delay_sec * 1000); }
                    snprintf (extra, sizeof extra, "delay → %ds", delay_sec);
                }
                redraw = 1;
                break;
            }
            case 'k': case 'K': {
                char pidbuf[32], sigbuf[32];
                if (bls_getnstr (win, bls_lines () - 1, 0,"kill PID: ", pidbuf, sizeof pidbuf) <= 0) {
                    redraw = 1; break;
                }
                if (bls_getnstr (win, bls_lines () - 1, 0,"signal [TERM]: ", sigbuf, sizeof sigbuf) < 0) {
                    redraw = 1; break;
                }
                int pid = atoi (pidbuf);
                int sig = SIGTERM;
                if (sigbuf[0]) {
                    int v = atoi (sigbuf);
                    if (v > 0) sig = v;
                }
                if (pid > 0 && kill (pid, sig) == 0)
                    snprintf (extra, sizeof extra, "kill -%d %d ok", sig, pid);
                else
                    snprintf (extra, sizeof extra, "kill -%d %d: %s", sig, pid, strerror (errno));
                redraw = 1;
                break;
            }
            case 'r': case 'R': {
                char pidbuf[32], nicebuf[32];
                if (bls_getnstr (win, bls_lines () - 1, 0,"renice PID: ", pidbuf, sizeof pidbuf) <= 0) {
                    redraw = 1; break;
                }
                if (bls_getnstr (win, bls_lines () - 1, 0,"delta: ", nicebuf, sizeof nicebuf) <= 0) {
                    redraw = 1; break;
                }
                int pid = atoi (pidbuf);
                int delta = atoi (nicebuf);
                errno = 0;
                int cur = getpriority (PRIO_PROCESS, (id_t) pid);
                if (cur == -1 && errno != 0) {
                    snprintf (extra, sizeof extra, "renice %d: %s", pid, strerror (errno));
                } else if (setpriority (PRIO_PROCESS, (id_t) pid, cur + delta) == 0) {
                    snprintf (extra, sizeof extra, "renice %d → %d", pid, cur + delta);
                } else {
                    snprintf (extra, sizeof extra, "renice %d: %s", pid, strerror (errno));
                }
                redraw = 1;
                break;
            }
            default:
                /* ignore */
                break;
        }
    }

out:
    bls_end ();
    free (procs);
    return rc;
}

/* --- arg parsing -------------------------------------------------------- */

static int
btop_parse_sort (const char *s, btop_sort *out)
{
    if (!s || !*s) return -1;
    if (!strcasecmp (s, "cpu"))  { *out = BTOP_SORT_CPU;  return 0; }
    if (!strcasecmp (s, "mem"))  { *out = BTOP_SORT_MEM;  return 0; }
    if (!strcasecmp (s, "pid"))  { *out = BTOP_SORT_PID;  return 0; }
    if (!strcasecmp (s, "time")) { *out = BTOP_SORT_TIME; return 0; }
    return -1;
}

int
top_builtin (WORD_LIST *list)
{
    int       once = 0;
    int       iters = 0;
    int       delay = 2;
    btop_sort sort = BTOP_SORT_CPU;
    int       row_cap = 0;

    while (list) {
        const char *w = list->word->word;
        if (!w || !*w || w[0] != '-') break;

        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--once") || !strcmp (w, "-b") || !strcmp (w, "--batch")) {
            once = 1; list = list->next; continue;
        }
        if (!strcmp (w, "--help") || !strcmp (w, "-h")) {
            extern char *top_doc[];
            for (char **dp = top_doc; *dp; dp++) puts (*dp);
            return EX_USAGE;
        }
        if (!strcmp (w, "-n")) {
            list = list->next;
            if (!list) { builtin_error ("-n requires COUNT"); return EX_USAGE; }
            iters = atoi (list->word->word);
            if (iters < 0) iters = 0;
            list = list->next; continue;
        }
        if (!strcmp (w, "-d")) {
            list = list->next;
            if (!list) { builtin_error ("-d requires SEC"); return EX_USAGE; }
            delay = atoi (list->word->word);
            if (delay < 1) delay = 1;
            list = list->next; continue;
        }
        if (!strcmp (w, "-o")) {
            list = list->next;
            if (!list) { builtin_error ("-o requires COLUMN"); return EX_USAGE; }
            if (btop_parse_sort (list->word->word, &sort) < 0) {
                builtin_error ("unknown sort column: %s (cpu|mem|pid|time)",
                               list->word->word);
                return EX_USAGE;
            }
            list = list->next; continue;
        }
        if (!strcmp (w, "-r")) {
            list = list->next;
            if (!list) { builtin_error ("-r requires N"); return EX_USAGE; }
            row_cap = atoi (list->word->word);
            if (row_cap < 0) row_cap = 0;
            list = list->next; continue;
        }
        builtin_error ("unknown option: %s", w);
        return EX_USAGE;
    }

    if (once)
        return btop_run_once (sort, row_cap);
    return btop_run_interactive (delay, sort, iters, row_cap);
}

char *top_doc[] = {
    "Interactive process viewer over /proc (top(1) shape).",
    "",
    "    top [--once|-b] [-n COUNT] [-d SEC] [-o COL] [-r N]",
    "",
    "    --once / -b   one snapshot, write to stdout, exit (batch).",
    "    -n COUNT      run COUNT interactive redraws then exit.",
    "    -d SEC        refresh interval (integer seconds, default 2).",
    "    -o COL        initial sort: cpu | mem | pid | time (default cpu).",
    "    -r N          cap process rows shown (default = tty rows - 5).",
    "",
    "Interactive keys:",
    "    q / ESC       exit.",
    "    space         redraw immediately.",
    "    Up / Down     scroll the process list one row.",
    "    PgUp / PgDn   scroll the process list one page.",
    "    Home / End    jump to first / last process.",
    "    n             prompt for new refresh interval.",
    "    o             cycle sort column.",
    "    k             prompt for PID + signal, send signal.",
    "    r             prompt for PID + nice delta, renice.",
    "",
    "Header lines: load averages, process count, sort column, refresh;",
    "Mem total/used/avail (kB); Swap total/used/free (kB). Row columns:",
    "PID USER %CPU RSS S COMMAND. %CPU is computed across two snapshots",
    "(refresh interval in interactive mode, 200ms in --once).",
    (char *) NULL
};

struct builtin top_struct = {
    "top",
    top_builtin,
    BUILTIN_ENABLED,
    top_doc,
    "top [--once|-b] [-n COUNT] [-d SEC] [-o cpu|mem|pid|time] [-r N]",
    0
};
