/* bashpgrep.c — pgrep(1) + pkill(1) via /proc walking.
 *
 * Bundled loadable: bashpgrep.c exports the pgrep entry point and the
 * shared backend bp_dispatch(); the sibling bashpkill.c shim exports
 * the pkill entry point and forwards into bp_dispatch() with the
 * signal-delivery flag set. Both names are registered in
 * config/bash-loadables-bash-os.list. This mirrors the
 * procps-ng/busybox shape where a single binary serves both names
 * (argv[0] dispatch) — here the dispatch is via the per-entry flag.
 *
 * Surfaces:
 *   bashpgrep [-f] [-u USER] PATTERN     — pgrep extended-regex match (default: comm)
 *   bashpgrep [-f] -u USER               — list all PIDs for USER
 *   bashpkill [-SIGNAL] [-f] [-u USER] PATTERN — pkill (default signal TERM)
 *   bashkillall [-SIGNAL] [-f] [-u USER] NAME [NAME ...]
 *                                            — exact-name killall
 *   bashkillall5 [-SIGNAL] [-o PID[,PID...]] [--dry-run|-n]
 *                                            — SysV broadcast killall5
 *
 * Match modes:
 *   default — match against /proc/PID/comm (basename of the command name,
 *             capped at 15 chars by kernel)
 *   -f      — match against /proc/PID/cmdline (full command line, nul-joined-as-space)
 *   -u/-U   — effective/real uid; -G real gid; -P parent; -g group; -s session
 *             (comma-separated alternatives, combined selectors are ANDed)
 *
 * Self-exclusion: the calling pgrep/pkill PID is never matched (mirrors
 * procps-ng default; busybox respects the same invariant).
 *
 * Exit codes:
 *   0 — pgrep printed at least one PID / pkill signalled at least one process
 *   1 — no match
 *   2 — usage error (EX_USAGE)
 *   3 — fatal (proc unreadable, etc.) — distinct from "no match"
 *
 * --- LICENSE --- MIT, same boilerplate as the other scripts/loadables/ TUs.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <ctype.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <regex.h>

#include "loadables.h"

/* Backend dispatch flag — bashpkill.c / bashkillall.c set this via bp_dispatch. */
#define BP_MODE_GREP    0
#define BP_MODE_KILL    1
/* BP_MODE_KILLALL: exact /proc/PID/comm strcmp (no substring), then signal.
   Mirrors psmisc killall(1): match on comm equality so `killall sleep`
   targets every sleep process without also signalling `gpg-agent-sleeper`.
   pkill (regex) and killall (exact) intentionally differ here. */
#define BP_MODE_KILLALL 2
/* BP_MODE_KILLALL5: SysV killall5 semantics. Pattern-less broadcast over
   every non-kernel-thread PID outside the caller's session, with optional
   -o omit PID list. */
#define BP_MODE_KILLALL5 3

#define BP_DELIVERS_SIGNAL(m) ((m) == BP_MODE_KILL || (m) == BP_MODE_KILLALL || (m) == BP_MODE_KILLALL5)
#define BP_PATH_MAX 1024
#define BP_OMIT_MAX 256

/* ---- /proc helpers ------------------------------------------------------ */

static const char *
bp_proc_root (void)
{
    const char *root = getenv ("BASHOS_PROC_ROOT");
    return (root && *root) ? root : "/proc";
}

static int
bp_using_proc_fixture (void)
{
    const char *root = getenv ("BASHOS_PROC_ROOT");
    return root && *root;
}

static int
bp_proc_path (char *buf, size_t bufsz, const char *name)
{
    int n = snprintf (buf, bufsz, "%s/%s", bp_proc_root (), name);
    return (n < 0 || (size_t)n >= bufsz) ? -1 : 0;
}

static int
bp_proc_pid_path (char *buf, size_t bufsz, int pid, const char *name)
{
    char rel[64];
    int n = snprintf (rel, sizeof rel, "%d/%s", pid, name);
    if (n < 0 || (size_t)n >= sizeof rel)
        return -1;
    return bp_proc_path (buf, bufsz, rel);
}

static int
bp_read_file (const char *path, char *out, size_t cap, int complete)
{
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n;
    do n = read (fd, out, cap - 1); while (n < 0 && errno == EINTR);
    if (n >= 0 && complete && (size_t)n == cap - 1) {
        char extra;
        ssize_t more;
        do more = read (fd, &extra, 1); while (more < 0 && errno == EINTR);
        if (more != 0) {
            close (fd);
            if (more > 0) errno = EOVERFLOW;
            return -1;  /* never claim an exact match on a truncated prefix */
        }
    }
    int saved_errno = errno;
    close (fd);
    errno = saved_errno;
    if (n < 0) return -1;
    out[n] = '\0';
    return (int)n;
}

static int
bp_read_comm (int pid, char *out, size_t cap)
{
    char path[BP_PATH_MAX];
    if (bp_proc_pid_path (path, sizeof path, pid, "comm") < 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int n = bp_read_file (path, out, cap, 1);
    if (n <= 0 || memchr (out, '\0', (size_t)n)) return -1;
    /* Strip trailing newline (always present). */
    if (out[n - 1] == '\n') out[n - 1] = '\0';
    return 0;
}

/* Reuse a growable buffer across entries: command lines can exceed 4 KiB.
   Keep every argument. Procps normalizes newlines; exact killall keeps them.
   Both modes replace NUL argument separators with spaces. */
static int
bp_read_cmdline (int pid, char **out, size_t *cap, int normalize_newlines)
{
    char path[BP_PATH_MAX];
    if (bp_proc_pid_path (path, sizeof path, pid, "cmdline") < 0)
        return -1;
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t n = 0;
    for (;;) {
        if (*cap - n < 2) {
            size_t next = *cap ? *cap * 2 : 4096;
            if (next <= *cap) { close (fd); errno = ENOMEM; return -1; }
            char *buf = realloc (*out, next);
            if (!buf) { close (fd); return -1; }
            *out = buf;
            *cap = next;
        }
        ssize_t got = read (fd, *out + n, *cap - n - 1);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) { close (fd); return -1; }
        if (got == 0) break;
        n += got;
    }
    close (fd);
    if (n && (*out)[n - 1] == '\0') n--;
    for (size_t i = 0; i < n; i++)
        if ((*out)[i] == '\0' || (normalize_newlines && (*out)[i] == '\n')) (*out)[i] = ' ';
    (*out)[n] = '\0';
    return 0;
}

/* A selector list is ORed internally; distinct lists are ANDed. */
enum { BP_EUID, BP_RUID, BP_RGID, BP_PARENT, BP_PGROUP, BP_SESSION, BP_SELECTORS };
struct bp_selector { unsigned long ids[BP_OMIT_MAX]; int count; };
struct bp_selection {
    struct bp_selector list[BP_SELECTORS];
    int age;                         /* 1 newest, -1 oldest, 0 all */
};

static int
bp_selector_kind (int c)
{
    switch (c) {
        case 'u': return BP_EUID;
        case 'U': return BP_RUID;
        case 'G': return BP_RGID;
        case 'P': return BP_PARENT;
        case 'g': return BP_PGROUP;
        case 's': return BP_SESSION;
        default: return -1;
    }
}

static int
bp_selector_parse (struct bp_selector *sel, int kind, const char *spec)
{
    const char *p = spec;
    if (!*p) return -1;
    while (*p) {
        const char *comma = strchr (p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen (p);
        char token[256], *end;
        unsigned long id;
        if (!len || len >= sizeof token || sel->count == BP_OMIT_MAX) return -1;
        memcpy (token, p, len);
        token[len] = '\0';
        int numeric = 1;
        for (size_t i = 0; i < len; i++)
            if (!isdigit ((unsigned char)token[i])) numeric = 0;
        if (numeric) {
            errno = 0;
            id = strtoul (token, &end, 10);
            if (errno || *end || id > (kind <= BP_RGID ? UINT_MAX : INT_MAX)) return -1;
        } else if (kind == BP_EUID || kind == BP_RUID) {
            struct passwd *pw = getpwnam (token);
            if (!pw) return -1;
            id = pw->pw_uid;
        } else if (kind == BP_RGID) {
            struct group *gr = getgrnam (token);
            if (!gr) return -1;
            id = gr->gr_gid;
        } else return -1;
        if (id == 0 && kind == BP_PGROUP) id = getpgrp ();
        if (id == 0 && kind == BP_SESSION) {
            pid_t sid = getsid (0);
            if (sid < 0) return -1;
            id = sid;
        }
        sel->ids[sel->count++] = id;
        if (!comma) return 0;
        p = comma + 1;
    }
    return 0;
}

static int
bp_selector_has (const struct bp_selector *sel, unsigned long id)
{
    if (!sel->count) return 1;
    for (int i = 0; i < sel->count; i++)
        if (sel->ids[i] == id) return 1;
    return 0;
}

static int
bp_read_ids (int pid, unsigned long *ruid, unsigned long *euid, unsigned long *rgid)
{
    char path[BP_PATH_MAX], buf[8192];
    if (bp_proc_pid_path (path, sizeof path, pid, "status") < 0 ||
        bp_read_file (path, buf, sizeof buf, 0) <= 0) return -1;
    int uid_ok = 0, gid_ok = 0;
    for (char *line = buf; line && *line;) {
        char *next = strchr (line, '\n');
        if (next) *next++ = '\0';
        /* Require the complete four-field records, not partial or signed IDs. */
        if (!strncmp (line, "Uid:", 4) || !strncmp (line, "Gid:", 4)) {
            unsigned long ids[4];
            char *q = line + 4, *end;
            for (int i = 0; i < 4; i++) {
                while (*q == ' ' || *q == '\t') q++;
                if (!isdigit ((unsigned char)*q)) return -1;
                errno = 0;
                ids[i] = strtoul (q, &end, 10);
                if (errno || ids[i] > UINT_MAX || (*end && *end != ' ' && *end != '\t')) return -1;
                q = end;
            }
            while (*q == ' ' || *q == '\t') q++;
            if (*q) return -1;
            if (line[0] == 'U') { *ruid = ids[0]; *euid = ids[1]; uid_ok = 1; }
            else { *rgid = ids[0]; gid_ok = 1; }
        }
        line = next;
    }
    return uid_ok && gid_ok ? 0 : -1;
}

/* stat comm may contain spaces and right parentheses: use the last ')'. */
static int
bp_read_selection_stat (int pid, unsigned long ids[3], unsigned long long *start)
{
    char path[BP_PATH_MAX], buf[4096];
    if (bp_proc_pid_path (path, sizeof path, pid, "stat") < 0 ||
        bp_read_file (path, buf, sizeof buf, 0) <= 0) return -1;
    char *p = strrchr (buf, ')');
    if (!p || p[1] != ' ' || !p[2] || p[3] != ' ') return -1;
    p += 4;
    for (int field = 4; field <= 22; field++) {
        char *end;
        while (*p == ' ') p++;
        if (!*p) return -1;
        errno = 0;
        if (field <= 6 || field == 22) {
            if (!isdigit ((unsigned char)*p)) return -1;
            unsigned long long v = strtoull (p, &end, 10);
            if (errno || (field <= 6 && v > INT_MAX)) return -1;
            if (field <= 6) ids[field - 4] = (unsigned long)v;
            else *start = v;
        } else {
            strtoll (p, &end, 10);
            if (errno || end == p) return -1;
        }
        if (*end && *end != ' ' && *end != '\n') return -1;
        p = end;
    }
    return 0;
}

static int
bp_read_session_from_stat (int pid, pid_t *out)
{
    char path[BP_PATH_MAX], buf[1024];
    if (bp_proc_pid_path (path, sizeof path, pid, "stat") < 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int n = bp_read_file (path, buf, sizeof buf, 0);
    if (n <= 0) return -1;

    char *rp = strrchr (buf, ')');
    if (!rp) return -1;
    char *p = rp + 1;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '\0') return -1;

    /* Field 3 is state. Fields 4, 5, 6 are ppid, pgrp, session. */
    while (*p && *p != ' ' && *p != '\t') p++;
    for (int field = 4; field <= 6; field++) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0') return -1;
        char *end = NULL;
        long v = strtol (p, &end, 10);
        if (end == p) return -1;
        if (field == 6) {
            *out = (pid_t)v;
            return 0;
        }
        p = end;
    }
    return -1;
}

static int
bp_read_session_id (int pid, pid_t *out)
{
    if (bp_using_proc_fixture ())
        return bp_read_session_from_stat (pid, out);

    pid_t sid = getsid ((pid_t)pid);
    if (sid < 0) return -1;
    *out = sid;
    return 0;
}

static int
bp_resolve_user (const char *spec, uid_t *out)
{
    /* All-digit form: numeric uid. */
    int alldigit = (spec[0] != '\0');
    for (const char *q = spec; *q && alldigit; q++)
        if (!isdigit ((unsigned char)*q)) alldigit = 0;
    if (alldigit) {
        char *end = NULL;
        errno = 0;
        unsigned long v = strtoul (spec, &end, 10);
        if (errno || end == spec || *end != '\0' || v > UINT_MAX) return -1;
        *out = (uid_t)v;
        return 0;
    }
    /* Name form: resolve via getpwnam. */
    struct passwd *pw = getpwnam (spec);
    if (!pw) return -1;
    *out = pw->pw_uid;
    return 0;
}

/* ---- Signal name → number ----------------------------------------------- */

static const struct { const char *name; int num; } bp_signals[] = {
    { "HUP",   SIGHUP   }, { "INT",  SIGINT  }, { "QUIT", SIGQUIT },
    { "ILL",   SIGILL   }, { "TRAP", SIGTRAP }, { "ABRT", SIGABRT },
    { "BUS",   SIGBUS   }, { "FPE",  SIGFPE  }, { "KILL", SIGKILL },
    { "USR1",  SIGUSR1  }, { "SEGV", SIGSEGV }, { "USR2", SIGUSR2 },
    { "PIPE",  SIGPIPE  }, { "ALRM", SIGALRM }, { "TERM", SIGTERM },
    { "CHLD",  SIGCHLD  }, { "CONT", SIGCONT }, { "STOP", SIGSTOP },
    { "TSTP",  SIGTSTP  }, { "TTIN", SIGTTIN }, { "TTOU", SIGTTOU },
    { "URG",   SIGURG   }, { "XCPU", SIGXCPU }, { "XFSZ", SIGXFSZ },
    { "VTALRM",SIGVTALRM}, { "PROF", SIGPROF }, { "WINCH",SIGWINCH},
    { "IO",    SIGIO    }, { "PWR",  SIGPWR  }, { "SYS",  SIGSYS  },
    { NULL, 0 }
};

static int
bp_parse_signal (const char *spec)
{
    /* Strip leading SIG if present. */
    if (strncasecmp (spec, "SIG", 3) == 0) spec += 3;
    /* Numeric form. */
    if (isdigit ((unsigned char)spec[0])) {
        char *end = NULL;
        errno = 0;
        unsigned long v = strtoul (spec, &end, 10);
        if (errno || end == spec || *end != '\0' || v >= NSIG) return -1;
        return (int)v;
    }
    for (int i = 0; bp_signals[i].name; i++)
        if (strcasecmp (spec, bp_signals[i].name) == 0)
            return bp_signals[i].num;
    return -1;
}

static int
bp_omit_contains (const int *omit_pids, int omit_count, int pid)
{
    for (int i = 0; i < omit_count; i++)
        if (omit_pids[i] == pid)
            return 1;
    return 0;
}

static int
bp_parse_omit_list (const char *spec, int *omit_pids, int *omit_count)
{
    const char *p = spec;
    if (!p || !*p) return -1;

    while (*p) {
        if (*omit_count >= BP_OMIT_MAX) return -1;
        char *end = NULL;
        unsigned long v = strtoul (p, &end, 10);
        if (end == p || v == 0 || v > 2147483647UL) return -1;
        omit_pids[*omit_count] = (int)v;
        (*omit_count)++;
        if (*end == '\0') return 0;
        if (*end != ',') return -1;
        p = end + 1;
        if (*p == '\0') return -1;
    }
    return 0;
}

/* ---- Core: walk /proc and act ------------------------------------------- */

static int
bp_match (const char *hay, WORD_LIST *patterns, int pattern_count, int mode,
          const regex_t *regex)
{
    if (mode == BP_MODE_KILLALL5)
        return 1;

    if (pattern_count == 0) {
        /* -u USER with no PATTERN: every uid-matching PID is a hit
           (cmdline-empty already filtered above when by_cmdline). */
        return 1;
    }

    if (mode == BP_MODE_KILLALL) {
        /* killall semantics: exact comm equality (psmisc killall(1)).
           When -f is in effect the comparand is the joined cmdline,
           which is uncommon for killall but kept consistent with the
           shared walker. */
        for (WORD_LIST *p = patterns; p && p->word && p->word->word; p = p->next)
            if (strcmp (hay, p->word->word) == 0)
                return 1;
        return 0;
    }

    return regexec (regex, hay, 0, NULL, 0) == 0;
}

static void
bp_print_pid (int pid, int lflag, int aflag, const char *delim, int *first,
              char **cmdline, size_t *cap)
{
    if (!*first) fputs (delim, stdout);
    printf ("%d", pid);
    if (lflag) {
        char name[64];
        if (bp_read_comm (pid, name, sizeof name) == 0) printf (" %s", name);
    } else if (aflag && bp_read_cmdline (pid, cmdline, cap, 1) == 0 && **cmdline)
        printf (" %s", *cmdline);
    *first = 0;
}

/* Count successful requests, not merely selected processes. A process exiting
   between selection and kill is an ordinary race; diagnose other failures. */
static int
bp_signal_pid (int pid, int sig)
{
    if (kill (pid, sig) == 0) return 1;
    if (errno != ESRCH)
        builtin_error ("kill (%d): %s", pid, strerror (errno));
    return 0;
}

static int
bp_walk (WORD_LIST *patterns, int pattern_count, int by_cmdline,
         int filter_uid_set, uid_t want_uid, int mode, int sig,
         int count_only, const regex_t *regex, const struct bp_selection *selection,
         int lflag, int aflag, int vflag, const char *odelim,
         int killall5_dry_run, pid_t killall5_sid,
         const int *omit_pids, int omit_count)
{
    int delivers = BP_DELIVERS_SIGNAL (mode) && !(mode == BP_MODE_KILLALL5 && killall5_dry_run);

    if (delivers && bp_using_proc_fixture ()) {
        builtin_error ("BASHOS_PROC_ROOT is read-only for signal operations");
        return 3;
    }

    DIR *d = opendir (bp_proc_root ());
    if (!d) {
        builtin_error ("opendir %s: %s", bp_proc_root (), strerror (errno));
        return mode == BP_MODE_KILLALL5 ? 1 : 3;
    }

    int matched = 0;
    int first_print = 1;
    struct dirent *de;
    pid_t self_pid = getpid ();

    char comm[64];
    char *cmdline = NULL;
    size_t cmdcap = 0;
    int best_pid = 0;
    unsigned long long best_start = 0;

    while ((de = readdir (d))) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        char *end = NULL;
        errno = 0;
        long lpid = strtol (de->d_name, &end, 10);
        if (errno == ERANGE || lpid <= 0 || lpid > INT_MAX ||
            de->d_name[0] == '0' || (end && *end != '\0')) continue;
        int pid = (int)lpid;
        if (pid == (int)self_pid) continue;  /* never match self */

        if (mode == BP_MODE_KILLALL5) {
            pid_t sid = -1;
            if (bp_omit_contains (omit_pids, omit_count, pid))
                continue;
            if (bp_read_session_id (pid, &sid) < 0)
                continue;
            if (sid == killall5_sid)
                continue;
            if (bp_read_cmdline (pid, &cmdline, &cmdcap, mode != BP_MODE_KILLALL) < 0)
                continue;
            if (cmdline[0] == '\0')
                continue;  /* kernel threads: empty cmdline */
        }

        if (filter_uid_set) {
            unsigned long ruid, euid, rgid;
            if (bp_read_ids (pid, &ruid, &euid, &rgid) < 0) continue;
            if (ruid != want_uid) continue;
        }

        int selected = 1;
        unsigned long long start = 0;
        if (selection) {
            const struct bp_selector *sel = selection->list;
            if (sel[BP_EUID].count || sel[BP_RUID].count || sel[BP_RGID].count) {
                unsigned long ruid, euid, rgid;
                if (bp_read_ids (pid, &ruid, &euid, &rgid) < 0) continue;
                selected = bp_selector_has (&sel[BP_EUID], euid) &&
                           bp_selector_has (&sel[BP_RUID], ruid) &&
                           bp_selector_has (&sel[BP_RGID], rgid);
            }
            if (sel[BP_PARENT].count || sel[BP_PGROUP].count || sel[BP_SESSION].count || selection->age) {
                unsigned long ids[3];
                if (bp_read_selection_stat (pid, ids, &start) < 0) continue;
                selected = selected && bp_selector_has (&sel[BP_PARENT], ids[0]) &&
                           bp_selector_has (&sel[BP_PGROUP], ids[1]) &&
                           bp_selector_has (&sel[BP_SESSION], ids[2]);
            }
        }

        const char *hay = NULL;
        if (mode == BP_MODE_KILLALL5) {
            hay = "";
        } else if (by_cmdline) {
            if (bp_read_cmdline (pid, &cmdline, &cmdcap, mode != BP_MODE_KILLALL) < 0) continue;
            if (cmdline[0] == '\0') continue;  /* kernel threads: empty cmdline */
            hay = cmdline;
        } else {
            if (bp_read_comm (pid, comm, sizeof comm) < 0) continue;
            hay = comm;
        }

        {
            int m = selected && bp_match (hay, patterns, pattern_count, mode, regex);
            if (vflag) m = !m;            /* -v: keep the NON-matching processes */
            if (!m) continue;
        }

        if (selection && selection->age) {
            if (!best_pid || (selection->age > 0 ?
                (start > best_start || (start == best_start && pid > best_pid)) :
                (start < best_start || (start == best_start && pid < best_pid)))) {
                best_pid = pid;
                best_start = start;
            }
            continue;
        }

        if (delivers) {
            matched += bp_signal_pid (pid, sig);
        } else {
            matched++;
            if (!count_only) {
                bp_print_pid (pid, lflag, aflag, odelim, &first_print, &cmdline, &cmdcap);
            }
        }
    }
    closedir (d);
    if (best_pid) {
        if (delivers)
            matched = bp_signal_pid (best_pid, sig);
        else {
            matched = 1;
            if (!count_only)
                bp_print_pid (best_pid, lflag, aflag, odelim, &first_print, &cmdline, &cmdcap);
        }
    }
    free (cmdline);
    /* -c/--count: print only the tally (procps-ng prints "0" + exit 1 on
       no match, for both pgrep and pkill). */
    if (count_only)
        printf ("%d\n", matched);
    else if (!delivers && matched > 0)
        putchar ('\n');
    if (fflush (stdout) == EOF || ferror (stdout)) {
        builtin_error ("write error: %s", strerror (errno));
        return 3;
    }
    if (mode == BP_MODE_KILLALL5)
        return matched > 0 ? EXECUTION_SUCCESS : 2;
    return matched > 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* ---- Shared dispatch (called from both bashpgrep and bashpkill) --------- */

int
bp_dispatch (WORD_LIST *list, int mode)
{
    clearerr (stdout);
    struct bp_selection selection = {0};
    int has_selection = 0;
    int by_cmdline = 0;
    int filter_uid_set = 0;
    uid_t want_uid = 0;
    int sig = SIGTERM;
    int count_only = 0;
    int exact = 0;
    int lflag = 0, aflag = 0, vflag = 0;   /* pgrep-only: -l/-a list, -v invert */
    const char *odelim = "\n";             /* -d DELIM */
    int killall5_dry_run = 0;
    int killall5_signal_set = 0;
    pid_t killall5_sid = -1;
    int omit_pids[BP_OMIT_MAX];
    int omit_count = 0;
    WORD_LIST *patterns = NULL;
    int pattern_count = 0;
    const char *self;
    switch (mode) {
        case BP_MODE_KILL:    self = "bashpkill";    break;
        case BP_MODE_KILLALL: self = "bashkillall";  break;
        case BP_MODE_KILLALL5:self = "bashkillall5"; break;
        default:              self = "bashpgrep";    break;
    }

    /* Standard help/version short-circuit (must precede missing-arg). */
    if (list && list->word && list->word->word) {
        const char *w = list->word->word;
        if (strcmp (w, "--help") == 0 || strcmp (w, "-h") == 0) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (strcmp (w, "--version") == 0 || strcmp (w, "-V") == 0) {
            printf ("%s 1.0 (bash-loadable)\n", self);
            return sh_chkwrite (EXECUTION_SUCCESS);
        }
    }

    while (list && list->word && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help") || !strcmp (w, "-h")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (w, "--version") || !strcmp (w, "-V")) {
            printf ("%s 1.0 (bash-loadable)\n", self);
            return sh_chkwrite (EXECUTION_SUCCESS);
        }
        /* Signal names such as -USR1, -URG, -PIPE and -PWR overlap
           attached -U/-P selectors. Preserve whole-signal precedence. */
        if (mode == BP_MODE_KILL) {
            int signal_number = bp_parse_signal (w + 1);
            if (signal_number >= 0) {
                sig = signal_number;
                list = list->next;
                continue;
            }
        }
        if (mode == BP_MODE_GREP || mode == BP_MODE_KILL) {
            int kind = -1;
            const char *value = NULL;
            static const char *longopts[BP_SELECTORS] = {
                "--euid", "--uid", "--group", "--parent", "--pgroup", "--session"
            };
            if (w[1] != '-' && bp_selector_kind (w[1]) >= 0) {
                kind = bp_selector_kind (w[1]);
                if (w[2]) value = w + 2;
            } else {
                for (int i = 0; i < BP_SELECTORS; i++) {
                    size_t len = strlen (longopts[i]);
                    if (!strncmp (w, longopts[i], len) && (w[len] == '\0' || w[len] == '=')) {
                        kind = i;
                        if (w[len] == '=') value = w + len + 1;
                        break;
                    }
                }
            }
            if (kind >= 0) {
                if (!value) {
                    list = list->next;
                    if (!list || !list->word) { builtin_error ("selector needs an argument"); return EX_USAGE; }
                    value = list->word->word;
                }
                if (bp_selector_parse (&selection.list[kind], kind, value) < 0) {
                    builtin_error ("invalid selector: %s", value);
                    return EX_USAGE;
                }
                has_selection = 1;
                list = list->next;
                continue;
            }
        }
        if ((mode == BP_MODE_GREP || mode == BP_MODE_KILL) && (!strcmp (w, "-n") || !strcmp (w, "--newest") ||
                                     !strcmp (w, "-o") || !strcmp (w, "--oldest"))) {
            int age = (!strcmp (w, "-n") || !strcmp (w, "--newest")) ? 1 : -1;
            if (selection.age && selection.age != age) { builtin_error ("-n and -o are mutually exclusive"); return EX_USAGE; }
            selection.age = age;
            list = list->next;
            continue;
        }
        if (mode != BP_MODE_KILLALL5 && (!strcmp (w, "-f") || !strcmp (w, "--full"))) { by_cmdline = 1; list = list->next; continue; }
        if (mode == BP_MODE_KILLALL5 && (!strcmp (w, "-n") || !strcmp (w, "--dry-run"))) {
            killall5_dry_run = 1;
            list = list->next;
            continue;
        }
        if (mode == BP_MODE_KILLALL5 && !strcmp (w, "-o")) {
            list = list->next;
            if (!list || !list->word || !list->word->word) {
                builtin_error ("-o: missing PID argument");
                builtin_usage ();
                return EX_USAGE;
            }
            if (bp_parse_omit_list (list->word->word, omit_pids, &omit_count) < 0) {
                builtin_error ("-o: invalid omit pid list: %s", list->word->word);
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (mode == BP_MODE_KILLALL5 && !strncmp (w, "-o", 2) && w[2]) {
            if (bp_parse_omit_list (w + 2, omit_pids, &omit_count) < 0) {
                builtin_error ("-o: invalid omit pid list: %s", w + 2);
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        if (mode != BP_MODE_KILLALL5 && (!strcmp (w, "-c") || !strcmp (w, "--count"))) {
            count_only = 1;
            list = list->next;
            continue;
        }
        if (mode != BP_MODE_KILLALL5 && (!strcmp (w, "-x") || !strcmp (w, "--exact"))) {
            exact = 1;
            list = list->next;
            continue;
        }
        /* pgrep-only output/selection flags (kept out of the signal modes so
           they cannot be mistaken for `-SIGNAL` selectors in pkill/killall). */
        if (mode == BP_MODE_GREP) {
            if (!strcmp (w, "-l") || !strcmp (w, "--list-name")) { lflag = 1; aflag = 0; list = list->next; continue; }
            if (!strcmp (w, "-a") || !strcmp (w, "--list-full")) { aflag = 1; lflag = 0; list = list->next; continue; }
            if (!strcmp (w, "-v") || !strcmp (w, "--inverse"))   { vflag = 1; list = list->next; continue; }
            if (!strcmp (w, "-d") || !strcmp (w, "--delimiter")) {
                list = list->next;
                if (!list || !list->word) { builtin_error ("-d needs a DELIM argument"); builtin_usage (); return EX_USAGE; }
                odelim = list->word->word; list = list->next; continue;
            }
            if (!strncmp (w, "-d", 2) && w[2]) { odelim = w + 2; list = list->next; continue; }  /* attached -d, */
            if (!strncmp (w, "--delimiter=", 12)) { odelim = w + 12; list = list->next; continue; }
        }
        if (mode == BP_MODE_KILLALL && !strcmp (w, "-e")) {
            /* psmisc killall -e asks for exact matching. That is already
               bashkillall's default, so accept it as a compatibility no-op. */
            list = list->next;
            continue;
        }
        if (mode != BP_MODE_KILLALL5 && !strcmp (w, "-u")) {
            list = list->next;
            if (!list || !list->word || !list->word->word) {
                builtin_error ("-u: missing USER argument");
                builtin_usage ();
                return EX_USAGE;
            }
            if (bp_resolve_user (list->word->word, &want_uid) < 0) {
                builtin_error ("-u: unknown user: %s", list->word->word);
                builtin_usage ();
                return EX_USAGE;
            }
            filter_uid_set = 1;
            list = list->next;
            continue;
        }
        /* Shared short-option clusters. Whole pkill signal names were handled
           above, before selector parsing, so -USR1/-PIPE retain precedence.
           Listing, inversion and delimiter options remain pgrep-only. */
        if ((mode == BP_MODE_GREP || mode == BP_MODE_KILL) && w[0] == '-' && w[1] && w[1] != '-') {
            const char *c;
            for (c = w + 1; *c; c++) {
                if (*c == 'f') { by_cmdline = 1; continue; }
                if (*c == 'c') { count_only = 1; continue; }
                if (*c == 'x') { exact = 1; continue; }
                if (mode == BP_MODE_GREP && *c == 'l') { lflag = 1; aflag = 0; continue; }
                if (mode == BP_MODE_GREP && *c == 'a') { aflag = 1; lflag = 0; continue; }
                if (mode == BP_MODE_GREP && *c == 'v') { vflag = 1; continue; }
                if (*c == 'n' || *c == 'o') {
                    int age = *c == 'n' ? 1 : -1;
                    if (selection.age && selection.age != age) { builtin_error ("-n and -o are mutually exclusive"); return EX_USAGE; }
                    selection.age = age;
                    continue;
                }
                if ((mode == BP_MODE_GREP && *c == 'd') || bp_selector_kind (*c) >= 0) {
                    /* Value flag: its argument is the rest of the cluster when
                       attached (-fdX), else the next argv element (-fu USER).
                       Either way it consumes the cluster remainder. */
                    const char *val = c + 1;
                    if (*val == '\0') {
                        list = list->next;
                        if (!list || !list->word || !list->word->word) {
                            builtin_error ("-%c needs an argument", *c);
                            builtin_usage ();
                            return EX_USAGE;
                        }
                        val = list->word->word;
                    }
                    if (*c == 'd') {
                        odelim = val;
                    } else {
                        int kind = bp_selector_kind (*c);
                        if (bp_selector_parse (&selection.list[kind], kind, val) < 0) {
                            builtin_error ("invalid selector: %s", val);
                            builtin_usage ();
                            return EX_USAGE;
                        }
                        has_selection = 1;
                    }
                    break;
                }
                builtin_error ("unknown flag: -%c", *c);
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            continue;
        }
        /* In any signal-delivering mode, an unrecognised -X / -SIG is
           interpreted as a signal selector (pkill and killall both
           accept `-SIGNAL`). */
        if (BP_DELIVERS_SIGNAL (mode)) {
            int s = bp_parse_signal (w + 1);
            if (s > 0 || (s == 0 && mode == BP_MODE_KILL)) {
                sig = s;
                if (mode == BP_MODE_KILLALL5) killall5_signal_set = 1;
                list = list->next;
                continue;
            }
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    if (list && list->word && list->word->word) {
        patterns = list;
        if (mode == BP_MODE_KILLALL) {
            WORD_LIST *p;
            for (p = list; p && p->word && p->word->word; p = p->next)
                pattern_count++;
            list = p;
        } else {
            pattern_count = 1;
            list = list->next;
        }
    }
    /* Extra positional args are an error for pgrep/pkill/killall5. killall accepts
       NAME [NAME ...] and matches any exact name. */
    if (list) {
        builtin_error ("extra positional arg: %s", list->word->word);
        builtin_usage ();
        return EX_USAGE;
    }
    /* killall always requires NAME (psmisc killall errors with
       "killall: no process found" if no NAME is supplied — we surface
       it as EX_USAGE because there is no useful default). pgrep/pkill
       still accept `-u USER` alone with no pattern. */
    if (mode == BP_MODE_KILLALL && pattern_count == 0) {
        builtin_error ("NAME required");
        builtin_usage ();
        return EX_USAGE;
    }
    if (mode == BP_MODE_KILLALL5) {
        if (pattern_count != 0) {
            builtin_error ("killall5 takes no pattern arguments");
            builtin_usage ();
            return EX_USAGE;
        }
        if (!killall5_dry_run && !killall5_signal_set) {
            builtin_error ("signal number required");
            builtin_usage ();
            return EX_USAGE;
        }
        killall5_sid = getsid (0);
        if (killall5_sid < 0) {
            builtin_error ("getsid: %s", strerror (errno));
            return 1;
        }
    }
    if (pattern_count == 0 && !filter_uid_set && !has_selection && mode != BP_MODE_KILLALL5) {
        builtin_usage ();
        return EX_USAGE;
    }
    if (selection.age && vflag) {
        builtin_error ("-n/-o and -v are mutually exclusive");
        return EX_USAGE;
    }

    regex_t regex;
    int compiled = 0;
    if ((mode == BP_MODE_GREP || mode == BP_MODE_KILL) && pattern_count) {
        const char *pattern = patterns->word->word;
        char *anchored = NULL;
        if (exact) {
            size_t len = strlen (pattern);
            anchored = malloc (len + 5);
            if (!anchored) { builtin_error ("out of memory"); return 3; }
            snprintf (anchored, len + 5, "^(%s)$", pattern);
            pattern = anchored;
        }
        int err = regcomp (&regex, pattern, REG_EXTENDED | REG_NOSUB);
        free (anchored);
        if (err) {
            char message[256];
            regerror (err, &regex, message, sizeof message);
            builtin_error ("invalid regular expression: %s", message);
            return 2;
        }
        compiled = 1;
    }
    int result = bp_walk (patterns, pattern_count, by_cmdline, filter_uid_set,
                          want_uid, mode, sig, count_only, compiled ? &regex : NULL,
                          (mode == BP_MODE_GREP || mode == BP_MODE_KILL) ? &selection : NULL,
                          lflag, aflag, vflag, odelim,
                          killall5_dry_run, killall5_sid, omit_pids, omit_count);
    if (compiled) regfree (&regex);
    return result;
}

/* ---- pgrep entry --------------------------------------------------------- */

int
pgrep_builtin (WORD_LIST *list)
{
    return bp_dispatch (list, BP_MODE_GREP);
}

char *pgrep_doc[] = {
    "Find PIDs of running processes by name or cmdline.",
    "",
    "    bashpgrep [-cflaxv] [-n|-o] [-u|-U USER] [-G GROUP] [-P PID] [-g PGRP] [-s SID] [PATTERN]",
    "    bashpgrep [-cf] -u USER",
    "    bashpgrep -h | --help | -V | --version",
    "",
    "    -f         match against the full command line (/proc/PID/cmdline)",
    "               instead of the comm field (kernel-truncated to 15 chars)",
    "    -c, --count  print only the count of matching processes",
    "    -x, --exact  require the regex to match the whole comm/cmdline",
    "    -u, --euid USER,...  filter effective uid (numeric or user name)",
    "    -U, --uid USER,...   filter real uid (numeric or user name)",
    "    -G, --group GROUP,... filter real gid (numeric or group name)",
    "    -P, --parent PID,... filter parent PID",
    "    -g, --pgroup PID,... filter process group (0 means own group)",
    "    -s, --session SID,... filter session (0 means own session)",
    "    -n, --newest / -o, --oldest select one by start time (ties by PID)",
    "    -l         list the process name after each PID",
    "    -a         list the full command line after each PID",
    "    -d DELIM   delimit output PIDs with DELIM (default newline)",
    "    -v         negate: print processes that do NOT match",
    "",
    "PATTERN is a POSIX extended regular expression. Self is never matched.",
    "Returns 0 if any PID matched, 1 if none, 2 on usage error, 3 on fatal.",
    (char *)NULL
};

struct builtin bashpgrep_struct = {
    "bashpgrep",
    pgrep_builtin,
    BUILTIN_ENABLED,
    pgrep_doc,
    "bashpgrep [-cflaxv] [-n|-o] [-u|-U USER] [-G GROUP] [-P PID] [-g PGRP] [-s SID] [PATTERN] [-h|--help|-V|--version]",
    0
};
