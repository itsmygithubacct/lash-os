/* bashps.c — POSIX-shape ps(1) via /proc walking.
 *
 *   bashps [-e] [-f] [-o COL,COL,...] [PID...]
 *   bashps aux [PID...]
 *
 *   -e         all processes (default if no PID given)
 *   -f         "full" format: USER PID PPID S TIME CMD
 *              (subset of POSIX -f: no TTY, no STIME — bashps's TTY
 *              detection isn't implemented; use -o pid,stime for STIME)
 *   -o LIST    custom column list. Recognized columns:
 *              pid, ppid, pgrp, sid, uid, user, state, ttybytes,
 *              comm, args, time, stime, %cpu, rss, vsz
 *
 * Output is one line per matching PID. `aux` is a bounded procps/BSD-key
 * compatibility surface with a fixed USER/PID/%CPU/%MEM/VSZ/RSS/TTY/STAT/
 * START/TIME/COMMAND layout. POSIX-shape otherwise (single-line CMD,
 * no -ww wide mode); for richer output use system+ procps.
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
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
#include <sys/stat.h>
#include <time.h>

#include "loadables.h"

#define BPS_BUF 4096
#define BPS_MAX_COLS 32
#define BPS_PATH_MAX 1024

typedef enum {
    BPS_COL_PID,
    BPS_COL_PPID,
    BPS_COL_PGRP,
    BPS_COL_SID,
    BPS_COL_UID,
    BPS_COL_USER,
    BPS_COL_STATE,
    BPS_COL_STAT,
    BPS_COL_TTYBYTES,
    BPS_COL_COMM,
    BPS_COL_ARGS,
    BPS_COL_TIME,
    BPS_COL_STIME,
    BPS_COL_PCPU,
    BPS_COL_RSS,
    BPS_COL_VSZ
} bps_col;

typedef struct {
    bps_col col;
    const char *header;
    char header_override[32];   /* procps -o field=HEADER custom/empty header */
    int  has_override;          /* 1 when '=' was present */
} bps_colspec;

typedef struct {
    int pid, ppid, pgrp, sid;
    int   tpgid;             /* /proc/[pid]/stat field 8  (for STAT '+') */
    uid_t uid;
    char  state;
    char  comm[64];
    char  args[256];
    long  starttime_ticks;   /* /proc/[pid]/stat field 22 */
    long  utime, stime;
    long  nice;              /* field 19 (for STAT '<' / 'N') */
    long  num_threads;       /* field 20 (for STAT 'l') */
    long  vmlck_kb;          /* /proc/[pid]/status VmLck  (for STAT 'L') */
    long  rss_pages;
    long  vsize_bytes;
} bps_proc;

static const char *
bps_proc_root (void)
{
    const char *root = getenv ("BASHOS_PROC_ROOT");
    return (root && *root) ? root : "/proc";
}

static int
bps_proc_path (char *buf, size_t bufsz, const char *name)
{
    int n = snprintf (buf, bufsz, "%s/%s", bps_proc_root (), name);
    return (n < 0 || (size_t)n >= bufsz) ? -1 : 0;
}

static int
bps_proc_pid_path (char *buf, size_t bufsz, int pid, const char *name)
{
    char rel[64];
    int n = snprintf (rel, sizeof rel, "%d/%s", pid, name);
    if (n < 0 || (size_t)n >= sizeof rel)
        return -1;
    return bps_proc_path (buf, bufsz, rel);
}

/* Read all of /proc/PID/stat into buf and slot fields. Returns 0 on
   success. The `comm` field is in `()` parens and may contain spaces;
   we anchor on the LAST `)` to find the start of the rest of the line. */
static int
bps_read_stat (int pid, bps_proc *p)
{
    char path[BPS_PATH_MAX];
    if (bps_proc_pid_path (path, sizeof path, pid, "stat") < 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buf[BPS_BUF];
    ssize_t n = read (fd, buf, sizeof buf - 1);
    close (fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    /* Find last `)` to skip past comm. */
    char *last = strrchr (buf, ')');
    if (!last) return -1;
    /* Extract comm: between first '(' and last ')'. */
    char *first = strchr (buf, '(');
    if (!first || first > last) return -1;
    size_t clen = (size_t) (last - first - 1);
    if (clen >= sizeof p->comm) clen = sizeof p->comm - 1;
    memcpy (p->comm, first + 1, clen);
    p->comm[clen] = '\0';

    p->pid = pid;
    /* Skip past `) ` and parse the rest. Field 3 = state. */
    char *rest = last + 2;
    /* Layout per proc(5):
       (3) state, (4) ppid, (5) pgrp, (6) session, (7) tty_nr, (8) tpgid,
       (9) flags ... (14) utime, (15) stime, (18) priority, (19) nice,
       (20) num_threads, ... (22) starttime, (23) vsize, (24) rss.
       We capture tpgid/nice/num_threads for the procps STAT flag chars. */
    int got = sscanf (rest,
        "%c %d %d %d "                  /* state(3) ppid(4) pgrp(5) session(6) */
        "%*d %d %*u %*u %*u %*u %*u "   /* tty_nr(7) [tpgid(8)] flags..cmajflt (9-13) */
        "%ld %ld "                      /* utime(14) stime(15) */
        "%*d %*d %*d %ld %ld %*d "      /* cutime cstime priority [nice(19)] [num_threads(20)] itrealvalue */
        "%ld %ld %ld",                  /* starttime(22) vsize(23) rss(24) */
        &p->state, &p->ppid, &p->pgrp, &p->sid,
        &p->tpgid,
        &p->utime, &p->stime,
        &p->nice, &p->num_threads,
        &p->starttime_ticks, &p->vsize_bytes, &p->rss_pages);
    if (got < 4) return -1;

    /* uid: read /proc/PID/status. */
    if (bps_proc_pid_path (path, sizeof path, pid, "status") < 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        char sbuf[1024];
        ssize_t sn = read (fd, sbuf, sizeof sbuf - 1);
        close (fd);
        if (sn > 0) {
            sbuf[sn] = '\0';
            char *u = strstr (sbuf, "\nUid:");
            if (u) {
                u++;
            } else if (strncmp (sbuf, "Uid:", 4) == 0) {
                u = sbuf;
            }
            if (u) {
                long uid_val = 0;
                u += 4;
                while (*u == ' ' || *u == '\t') u++;
                sscanf (u, "%ld", &uid_val);
                p->uid = (uid_t) uid_val;
            }
            /* VmLck: locked pages -> STAT 'L' (rarely nonzero). Never the
               first status line (Name: is), so anchoring on '\n' is safe. */
            char *vl = strstr (sbuf, "\nVmLck:");
            if (vl) sscanf (vl + 7, "%ld", &p->vmlck_kb);
        }
    }

    /* args: /proc/PID/cmdline (NUL-separated argv). */
    if (bps_proc_pid_path (path, sizeof path, pid, "cmdline") < 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t an = read (fd, p->args, sizeof p->args - 1);
        close (fd);
        if (an > 0) {
            for (ssize_t i = 0; i < an - 1; i++) if (p->args[i] == '\0') p->args[i] = ' ';
            p->args[an] = '\0';
        } else {
            /* Kernel threads have empty cmdline — fall back to [comm]. */
            snprintf (p->args, sizeof p->args, "[%s]", p->comm);
        }
    } else {
        snprintf (p->args, sizeof p->args, "[%s]", p->comm);
    }
    return 0;
}

static const char *
bps_user (uid_t uid)
{
    static char buf[32];
    struct passwd *pw = getpwuid (uid);
    if (pw) return pw->pw_name;
    snprintf (buf, sizeof buf, "%u", (unsigned) uid);
    return buf;
}

static void
bps_print (const bps_proc *p, int full)
{
    long ticks_per_sec = sysconf (_SC_CLK_TCK);
    if (ticks_per_sec <= 0) ticks_per_sec = 100;
    long total_secs = (p->utime + p->stime) / ticks_per_sec;
    int hh = (int) (total_secs / 3600);
    int mm = (int) ((total_secs % 3600) / 60);
    int ss = (int) (total_secs % 60);
    if (full) {
        printf ("%-8s %5d %5d %c %02d:%02d:%02d %s\n",
                bps_user (p->uid), p->pid, p->ppid,
                p->state, hh, mm, ss,
                p->args[0] ? p->args : p->comm);
    } else {
        printf ("%5d %c %02d:%02d:%02d %s\n",
                p->pid, p->state, hh, mm, ss,
                p->args[0] ? p->args : p->comm);
    }
}

static int
bps_parse_pid_operand (const char *s, int *pidp)
{
    char *end = NULL;
    long n;

    if (s == NULL || *s == '\0') {
        builtin_error ("PID operand must be a decimal integer");
        builtin_usage ();
        return -1;
    }

    errno = 0;
    n = strtol (s, &end, 10);
    if (errno || end == s || *end != '\0' || n < 0 || n > INT_MAX) {
        builtin_error ("invalid PID operand: %s", s);
        builtin_usage ();
        return -1;
    }

    *pidp = (int) n;
    return 0;
}

static int
bps_add_pid_operand (const char *s, int *explicit_pids, int *n_pids, int max_pids)
{
    if (*n_pids >= max_pids) {
        builtin_error ("too many PIDs");
        builtin_usage ();
        return -1;
    }
    if (bps_parse_pid_operand (s, &explicit_pids[*n_pids]) < 0)
        return -1;
    (*n_pids)++;
    return 0;
}

static int
bps_add_pid_list (const char *s, int *explicit_pids, int *n_pids, int max_pids)
{
    const char *p = s;

    if (!s || !*s) {
        builtin_error ("PID operand must be a decimal integer");
        builtin_usage ();
        return -1;
    }
    while (*p) {
        const char *comma = strchr (p, ',');
        size_t len = comma ? (size_t) (comma - p) : strlen (p);
        char buf[64];

        if (len == 0 || len >= sizeof buf) {
            builtin_error ("invalid PID operand: %s", s);
            builtin_usage ();
            return -1;
        }
        memcpy (buf, p, len);
        buf[len] = '\0';
        if (bps_add_pid_operand (buf, explicit_pids, n_pids, max_pids) < 0)
            return -1;
        if (!comma)
            break;
        p = comma + 1;
    }
    return 0;
}

static int
bps_col_from_name (const char *name, bps_colspec *out)
{
    struct {
        const char *name;
        bps_col col;
        const char *header;
    } map[] = {
        { "pid",      BPS_COL_PID,      "PID" },
        { "ppid",     BPS_COL_PPID,     "PPID" },
        { "pgrp",     BPS_COL_PGRP,     "PGRP" },
        { "pgid",     BPS_COL_PGRP,     "PGID" },
        { "sid",      BPS_COL_SID,      "SID" },
        { "uid",      BPS_COL_UID,      "UID" },
        { "user",     BPS_COL_USER,     "USER" },
        { "state",    BPS_COL_STATE,    "S" },
        { "stat",     BPS_COL_STAT,     "STAT" },
        { "s",        BPS_COL_STATE,    "S" },
        { "ttybytes", BPS_COL_TTYBYTES, "TTYBYTES" },
        { "comm",     BPS_COL_COMM,     "COMMAND" },
        { "command",  BPS_COL_ARGS,     "COMMAND" },
        { "cmd",      BPS_COL_ARGS,     "COMMAND" },
        { "args",     BPS_COL_ARGS,     "COMMAND" },
        { "time",     BPS_COL_TIME,     "TIME" },
        { "stime",    BPS_COL_STIME,    "STIME" },
        { "%cpu",     BPS_COL_PCPU,     "%CPU" },
        { "pcpu",     BPS_COL_PCPU,     "%CPU" },
        { "rss",      BPS_COL_RSS,      "RSS" },
        { "vsz",      BPS_COL_VSZ,      "VSZ" },
    };

    for (size_t i = 0; i < sizeof map / sizeof map[0]; i++) {
        if (strcmp (name, map[i].name) == 0) {
            out->col = map[i].col;
            out->header = map[i].header;
            return 0;
        }
    }
    return -1;
}

static int
bps_add_o_list (const char *list, bps_colspec *cols, int *n_cols)
{
    char buf[256];
    size_t n = strlen (list);
    if (n == 0 || n >= sizeof buf) {
        builtin_error ("invalid -o list: %s", list);
        return -1;
    }
    memcpy (buf, list, n + 1);

    char *save = NULL;
    for (char *tok = strtok_r (buf, ",", &save); tok; tok = strtok_r (NULL, ",", &save)) {
        while (isspace ((unsigned char)*tok)) tok++;
        char *end = tok + strlen (tok);
        while (end > tok && isspace ((unsigned char)end[-1])) *--end = '\0';
        const char *ovr = NULL;
        char *eq = strchr (tok, '=');
        if (eq) {
            ovr = eq + 1;
            *eq = '\0';
            while (eq > tok && isspace ((unsigned char)eq[-1])) *--eq = '\0';
        }
        if (*tok == '\0') {
            builtin_error ("empty -o column");
            return -1;
        }
        if (*n_cols >= BPS_MAX_COLS) {
            builtin_error ("too many -o columns");
            return -1;
        }
        if (bps_col_from_name (tok, &cols[*n_cols]) < 0) {
            builtin_error ("unknown -o column: %s", tok);
            return -1;
        }
        cols[*n_cols].has_override = ovr ? 1 : 0;
        if (ovr)
            snprintf (cols[*n_cols].header_override,
                      sizeof cols[*n_cols].header_override, "%s", ovr);
        else
            cols[*n_cols].header_override[0] = '\0';
        (*n_cols)++;
    }
    return 0;
}

static void
bps_print_time_field (long ticks)
{
    long ticks_per_sec = sysconf (_SC_CLK_TCK);
    if (ticks_per_sec <= 0) ticks_per_sec = 100;
    long total_secs = ticks / ticks_per_sec;
    printf ("%02ld:%02ld:%02ld", total_secs / 3600,
            (total_secs % 3600) / 60, total_secs % 60);
}

static void
bps_print_custom_header (const bps_colspec *cols, int n_cols)
{
    int any = 0;
    for (int i = 0; i < n_cols; i++) {
        const char *h = cols[i].has_override ? cols[i].header_override : cols[i].header;
        if (h && *h) { any = 1; break; }
    }
    if (!any) return;
    for (int i = 0; i < n_cols; i++) {
        const char *h = cols[i].has_override ? cols[i].header_override : cols[i].header;
        if (i) putchar (' ');
        printf ("%s", h ? h : "");
    }
    putchar ('\n');
}

/* Format a /proc/PID/stat-style starttime (ticks since boot) into the
   ps(1) STIME shape: "HH:MM" if the process started today, otherwise
   "MMMDD" (3-letter abbreviated month + 2-digit day, matching procps).
   btime is read from /proc/stat once and cached. On failure (no btime
   line, no CLK_TCK, localtime failure) emits "?". */
static void
bps_fmt_stime (long ticks_since_boot, char *buf, size_t bufsz)
{
    static time_t btime = 0;
    static int    btime_done = 0;
    if (!btime_done) {
        char path[BPS_PATH_MAX];
        if (bps_proc_path (path, sizeof path, "stat") == 0) {
            FILE *f = fopen (path, "r");
            if (f) {
                char line[256];
                long v;
                while (fgets (line, sizeof line, f))
                    if (sscanf (line, "btime %ld", &v) == 1) { btime = (time_t) v; break; }
                fclose (f);
            }
        }
        btime_done = 1;
    }
    long hz = sysconf (_SC_CLK_TCK);
    if (hz <= 0) hz = 100;
    if (btime == 0) { snprintf (buf, bufsz, "?"); return; }
    time_t start = btime + ticks_since_boot / hz;
    time_t now   = time (NULL);
    struct tm tm_start, tm_now;
    if (!localtime_r (&start, &tm_start) || !localtime_r (&now, &tm_now))
        { snprintf (buf, bufsz, "?"); return; }
    if (tm_start.tm_year == tm_now.tm_year && tm_start.tm_yday == tm_now.tm_yday)
        strftime (buf, bufsz, "%H:%M", &tm_start);
    else
        strftime (buf, bufsz, "%b%d", &tm_start);
}

/* Build the procps STAT string: the run-state char followed by mode flags
   in procps' fixed order ( <|N , L , s , l , + ). Matches ps(1)'s pr_stat():
     <  nice < 0      N  nice > 0       L  VmLck > 0
     s  session leader (session == pid)  l  multithreaded (nlwp > 1)
     +  pgrp == tpgid (foreground process group). */
static void
bps_build_stat (const bps_proc *p, char *buf, size_t bufsz)
{
    size_t i = 0;
    if (i + 1 < bufsz) buf[i++] = p->state;
    if (p->nice < 0)      { if (i + 1 < bufsz) buf[i++] = '<'; }
    else if (p->nice > 0) { if (i + 1 < bufsz) buf[i++] = 'N'; }
    if (p->vmlck_kb > 0)        { if (i + 1 < bufsz) buf[i++] = 'L'; }
    if (p->sid == p->pid)       { if (i + 1 < bufsz) buf[i++] = 's'; }
    if (p->num_threads > 1)     { if (i + 1 < bufsz) buf[i++] = 'l'; }
    if (p->pgrp == p->tpgid)    { if (i + 1 < bufsz) buf[i++] = '+'; }
    buf[i] = '\0';
}

static void
bps_print_custom (const bps_proc *p, const bps_colspec *cols, int n_cols)
{
    long page_size = sysconf (_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;

    for (int i = 0; i < n_cols; i++) {
        if (i) putchar (' ');
        switch (cols[i].col) {
            case BPS_COL_PID:      printf ("%d", p->pid); break;
            case BPS_COL_PPID:     printf ("%d", p->ppid); break;
            case BPS_COL_PGRP:     printf ("%d", p->pgrp); break;
            case BPS_COL_SID:      printf ("%d", p->sid); break;
            case BPS_COL_UID:      printf ("%u", (unsigned) p->uid); break;
            case BPS_COL_USER:     printf ("%s", bps_user (p->uid)); break;
            case BPS_COL_STATE:    printf ("%c", p->state); break;
            case BPS_COL_STAT:     { char sb[16]; bps_build_stat (p, sb, sizeof sb); fputs (sb, stdout); } break;
            case BPS_COL_TTYBYTES: printf ("?"); break;
            case BPS_COL_COMM:     printf ("%s", p->comm); break;
            case BPS_COL_ARGS:     printf ("%s", p->args[0] ? p->args : p->comm); break;
            case BPS_COL_TIME:     bps_print_time_field (p->utime + p->stime); break;
            case BPS_COL_STIME:    { char sb[16]; bps_fmt_stime (p->starttime_ticks, sb, sizeof sb); fputs (sb, stdout); } break;
            case BPS_COL_PCPU:     printf ("0.0"); break;
            case BPS_COL_RSS:      printf ("%ld", p->rss_pages * page_size / 1024); break;
            case BPS_COL_VSZ:      printf ("%ld", p->vsize_bytes / 1024); break;
        }
    }
    putchar ('\n');
}

static long
bps_mem_total_kb (void)
{
    static int done = 0;
    static long mem_total = 0;

    if (done)
        return mem_total;

    char path[BPS_PATH_MAX];
    if (bps_proc_path (path, sizeof path, "meminfo") == 0) {
        FILE *f = fopen (path, "r");
        if (f) {
            char line[256];
            long v;
            while (fgets (line, sizeof line, f)) {
                if (sscanf (line, "MemTotal: %ld kB", &v) == 1) {
                    mem_total = v;
                    break;
                }
            }
            fclose (f);
        }
    }

    done = 1;
    return mem_total;
}

static void
bps_fmt_aux_time (long ticks, char *buf, size_t bufsz)
{
    long ticks_per_sec = sysconf (_SC_CLK_TCK);
    if (ticks_per_sec <= 0) ticks_per_sec = 100;
    long total_secs = ticks / ticks_per_sec;
    snprintf (buf, bufsz, "%ld:%02ld", total_secs / 60, total_secs % 60);
}

static void
bps_print_aux_header (void)
{
    puts ("USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND");
}

static void
bps_print_aux_row (const bps_proc *p)
{
    long page_size = sysconf (_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;

    long rss_kb = p->rss_pages * page_size / 1024;
    long vsz_kb = p->vsize_bytes / 1024;
    long mem_total = bps_mem_total_kb ();
    double pmem = 0.0;
    if (mem_total > 0 && rss_kb > 0)
        pmem = ((double) rss_kb * 100.0) / (double) mem_total;

    char stat[16];
    char start[16];
    char timebuf[32];
    bps_build_stat (p, stat, sizeof stat);
    bps_fmt_stime (p->starttime_ticks, start, sizeof start);
    bps_fmt_aux_time (p->utime + p->stime, timebuf, sizeof timebuf);

    printf ("%-10s %5d %4.1f %4.1f %6ld %5ld %-8s %-4s %5s %6s %s\n",
            bps_user (p->uid), p->pid, 0.0, pmem, vsz_kb, rss_kb,
            "?", stat, start, timebuf, p->args[0] ? p->args : p->comm);
}

static int
bps_is_aux_bsd_key (const char *s)
{
    int have_a = 0, have_u = 0, have_x = 0;

    if (!s || !*s)
        return 0;
    for (const char *p = s; *p; p++) {
        switch (*p) {
            case 'a': have_a = 1; break;
            case 'u': have_u = 1; break;
            case 'x': have_x = 1; break;
            default: return 0;
        }
    }
    return have_a && (have_u || have_x);
}

int
ps_builtin (WORD_LIST *list)
{
    int all = 0;
    int full = 0;
    int aux_mode = 0;
    bps_colspec cols[BPS_MAX_COLS];
    int n_cols = 0;
    int explicit_pids[256];
    int n_pids = 0;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version")) {
            puts ("bashps 1.0 (bash-loadable, procps-compatible)");
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--pid")) {
            list = list->next;
            if (!list) {
                builtin_error ("option --pid requires a PID list");
                builtin_usage ();
                return EX_USAGE;
            }
            if (bps_add_pid_list (list->word->word, explicit_pids, &n_pids,
                                  (int) (sizeof explicit_pids / sizeof explicit_pids[0])) < 0)
                return EX_USAGE;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "--pid=", 6)) {
            if (bps_add_pid_list (w + 6, explicit_pids, &n_pids,
                                  (int) (sizeof explicit_pids / sizeof explicit_pids[0])) < 0)
                return EX_USAGE;
            list = list->next;
            continue;
        }
        if (w[1] == '-') {
            builtin_error ("unknown flag: %s", w);
            builtin_usage ();
            return EX_USAGE;
        }
        if (!strcmp (w, "-o")) {
            list = list->next;
            if (!list) {
                builtin_error ("option -o requires a column list");
                builtin_usage ();
                return EX_USAGE;
            }
            if (bps_add_o_list (list->word->word, cols, &n_cols) < 0) {
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-p")) {
            list = list->next;
            if (!list) {
                builtin_error ("option -p requires a PID list");
                builtin_usage ();
                return EX_USAGE;
            }
            if (bps_add_pid_list (list->word->word, explicit_pids, &n_pids,
                                  (int) (sizeof explicit_pids / sizeof explicit_pids[0])) < 0)
                return EX_USAGE;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-p", 2) && w[2]) {
            if (bps_add_pid_list (w + 2, explicit_pids, &n_pids,
                                  (int) (sizeof explicit_pids / sizeof explicit_pids[0])) < 0)
                return EX_USAGE;
            list = list->next;
            continue;
        }
        if (!strncmp (w, "-o", 2) && w[2]) {
            if (bps_add_o_list (w + 2, cols, &n_cols) < 0) {
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        for (const char *c = w + 1; *c; c++) {
            switch (*c) {
                case 'e': case 'A': all = 1; break;
                case 'f':           full = 1; break;
                case 'o': case 'p': {
                    /* Argument-taking options inside a combined token, e.g.
                       procps `ps -eo comm` or `ps -ep PID`. The remainder of
                       the token after this letter is the argument; if empty
                       the next word is consumed. Either way the rest of the
                       token is now used up, so we break the per-letter loop. */
                    char opt = *c;
                    const char *arg = c + 1;
                    if (*arg == '\0') {
                        list = list->next;
                        if (!list) {
                            builtin_error (opt == 'o'
                                ? "option -o requires a column list"
                                : "option -p requires a PID list");
                            builtin_usage ();
                            return EX_USAGE;
                        }
                        arg = list->word->word;
                    }
                    if (opt == 'o') {
                        if (bps_add_o_list (arg, cols, &n_cols) < 0) {
                            builtin_usage ();
                            return EX_USAGE;
                        }
                    } else {
                        if (bps_add_pid_list (arg, explicit_pids, &n_pids,
                                              (int) (sizeof explicit_pids / sizeof explicit_pids[0])) < 0)
                            return EX_USAGE;
                    }
                    goto next_word;
                }
                case 'V':
                    if (c[1] != '\0') {
                        builtin_error ("unknown flag: -%c", c[1]);
                        builtin_usage ();
                        return EX_USAGE;
                    }
                    puts ("bashps 1.0 (bash-loadable, procps-compatible)");
                    return EXECUTION_SUCCESS;
                default:
                    builtin_error ("unknown flag: -%c", *c);
                    builtin_usage ();
                    return EX_USAGE;
            }
        }
    next_word:
        list = list->next;
    }
    if (list && bps_is_aux_bsd_key (list->word->word)) {
        aux_mode = 1;
        all = 1;
        list = list->next;
    }
    /* Explicit PID list. */
    while (list) {
        if (bps_add_pid_operand (list->word->word, explicit_pids, &n_pids,
                                 (int) (sizeof explicit_pids / sizeof explicit_pids[0])) < 0)
            return EX_USAGE;
        list = list->next;
    }
    if (n_pids == 0) all = 1;

    if (aux_mode) bps_print_aux_header ();
    else if (n_cols > 0) bps_print_custom_header (cols, n_cols);
    else if (full)  printf ("USER       PID  PPID S TIME     CMD\n");
    else            printf ("  PID S TIME     CMD\n");

    if (n_pids > 0) {
        for (int i = 0; i < n_pids; i++) {
            bps_proc p = { 0 };
            if (bps_read_stat (explicit_pids[i], &p) == 0) {
                if (aux_mode) bps_print_aux_row (&p);
                else if (n_cols > 0) bps_print_custom (&p, cols, n_cols);
                else bps_print (&p, full);
            }
            else builtin_error ("pid %d: %s", explicit_pids[i], strerror (errno));
        }
        return EXECUTION_SUCCESS;
    }

    DIR *d = opendir (bps_proc_root ());
    if (!d) { builtin_error ("opendir %s: %s", bps_proc_root (), strerror (errno)); return EXECUTION_FAILURE; }
    struct dirent *de;
    while ((de = readdir (d))) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        int pid = atoi (de->d_name);
        if (pid <= 0) continue;
        bps_proc p = { 0 };
        if (bps_read_stat (pid, &p) == 0) {
            if (aux_mode) bps_print_aux_row (&p);
            else if (n_cols > 0) bps_print_custom (&p, cols, n_cols);
            else bps_print (&p, full);
        }
        (void) all;
    }
    closedir (d);
    return EXECUTION_SUCCESS;
}

char *ps_doc[] = {
    "List processes via /proc (POSIX-shape ps).",
    "",
    "    bashps [-ef] [-o COL,COL,...] [-p PIDLIST] [PID...]",
    "    bashps aux [PID...]",
    "",
    "    -e        all processes (default if no PID given)",
    "    -f        full format: USER PID PPID STATE TIME CMD",
    "    aux       BSD/procps-style USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND",
    "    -p LIST   select comma-separated process IDs (also --pid=LIST)",
    "    -o LIST   custom columns: pid,ppid,pgrp,sid,uid,user,state,stat,comm,args,time,stime,rss,vsz",
    "    --help    print usage information and exit",
    "    -V, --version",
    "              print version information and exit",
    "",
    "Without -f, output is `PID STATE TIME CMD`. CMD comes from",
    "/proc/PID/cmdline (or [comm] for kernel threads).",
    "The aux %CPU column is a fixed 0.0 snapshot placeholder; TTY is `?`.",
    "POSIX-shape — for richer formats use system+ procps.",
    (char *)NULL
};

struct builtin bashps_struct = {
    "bashps",
    ps_builtin,
    BUILTIN_ENABLED,
    ps_doc,
    "bashps [-ef] [-o COL,COL,...] [-p PIDLIST] [PID...] | bashps aux [PID...]",
    0
};
