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
 *   bashpgrep [-f] [-u USER] PATTERN     — pgrep substring match (default: comm)
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
 *   -u USER — filter by /proc/PID/status `Uid:` real-uid field (user can be
 *             a numeric uid or a name resolved via /etc/passwd)
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

#include "loadables.h"

/* Backend dispatch flag — bashpkill.c / bashkillall.c set this via bp_dispatch. */
#define BP_MODE_GREP    0
#define BP_MODE_KILL    1
/* BP_MODE_KILLALL: exact /proc/PID/comm strcmp (no substring), then signal.
   Mirrors psmisc killall(1): match on comm equality so `killall sleep`
   targets every sleep process without also signalling `gpg-agent-sleeper`.
   pkill (substring) and killall (exact) intentionally differ here. */
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
bp_read_file (const char *path, char *out, size_t cap)
{
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read (fd, out, cap - 1);
    close (fd);
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
    int n = bp_read_file (path, out, cap);
    if (n <= 0) return -1;
    /* Strip trailing newline (always present). */
    if (out[n - 1] == '\n') out[n - 1] = '\0';
    return 0;
}

/* /proc/PID/cmdline is NUL-separated. Convert NULs (except the final one)
   to spaces in-place so substring search treats it as a single line. */
static int
bp_read_cmdline (int pid, char *out, size_t cap)
{
    char path[BP_PATH_MAX];
    if (bp_proc_pid_path (path, sizeof path, pid, "cmdline") < 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int n = bp_read_file (path, out, cap);
    if (n < 0) return -1;
    if (n == 0) { out[0] = '\0'; return 0; }
    /* Drop trailing NUL if cmdline ends with one (most kernels). */
    int end = (out[n - 1] == '\0') ? n - 1 : n;
    for (int i = 0; i < end; i++)
        if (out[i] == '\0') out[i] = ' ';
    out[end] = '\0';
    return 0;
}

static int
bp_read_real_uid (int pid, uid_t *out)
{
    char path[BP_PATH_MAX], buf[512];
    if (bp_proc_pid_path (path, sizeof path, pid, "status") < 0) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int n = bp_read_file (path, buf, sizeof buf);
    if (n <= 0) return -1;
    const char *p = strstr (buf, "\nUid:");
    if (!p) {
        if (strncmp (buf, "Uid:", 4) == 0) p = buf;
        else return -1;
    } else {
        p++; /* past '\n' */
    }
    p += 4; /* past "Uid:" */
    while (*p == ' ' || *p == '\t') p++;
    char *end = NULL;
    unsigned long v = strtoul (p, &end, 10);
    if (end == p) return -1;
    *out = (uid_t)v;
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
    int n = bp_read_file (path, buf, sizeof buf);
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
        unsigned long v = strtoul (spec, &end, 10);
        if (end == spec || *end != '\0') return -1;
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
    if (strncmp (spec, "SIG", 3) == 0) spec += 3;
    /* Numeric form. */
    if (isdigit ((unsigned char)spec[0])) {
        char *end = NULL;
        unsigned long v = strtoul (spec, &end, 10);
        if (end == spec || *end != '\0') return -1;
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
          int exact)
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

    /* pgrep/pkill default to substring; -x/--exact anchors to the whole
       comm (or full cmdline under -f), matching procps-ng. */
    if (exact)
        return strcmp (hay, patterns->word->word) == 0;
    return strstr (hay, patterns->word->word) != NULL;
}

static int
bp_walk (WORD_LIST *patterns, int pattern_count, int by_cmdline,
         int filter_uid_set, uid_t want_uid, int mode, int sig,
         int count_only, int exact,
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

    /* Match against /proc/PID/cmdline: cmdline can be large (kernel
       allows up to ARG_MAX). 4 KiB is the conventional pgrep buffer
       and avoids stack pressure; long cmdlines truncate, which mirrors
       procps-ng's 4 KiB default in src/pgrep.c. */
    char comm[64];
    char cmdline[4096];

    while ((de = readdir (d))) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        char *end = NULL;
        long lpid = strtol (de->d_name, &end, 10);
        if (lpid <= 0 || (end && *end != '\0')) continue;
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
            if (bp_read_cmdline (pid, cmdline, sizeof cmdline) < 0)
                continue;
            if (cmdline[0] == '\0')
                continue;  /* kernel threads: empty cmdline */
        }

        if (filter_uid_set) {
            uid_t u;
            if (bp_read_real_uid (pid, &u) < 0) continue;
            if (u != want_uid) continue;
        }

        const char *hay = NULL;
        if (mode == BP_MODE_KILLALL5) {
            hay = "";
        } else if (by_cmdline) {
            if (bp_read_cmdline (pid, cmdline, sizeof cmdline) < 0) continue;
            if (cmdline[0] == '\0') continue;  /* kernel threads: empty cmdline */
            hay = cmdline;
        } else {
            if (bp_read_comm (pid, comm, sizeof comm) < 0) continue;
            hay = comm;
        }

        {
            int m = bp_match (hay, patterns, pattern_count, mode, exact);
            if (vflag) m = !m;            /* -v: keep the NON-matching processes */
            if (!m) continue;
        }

        if (delivers) {
            if (kill (pid, sig) == 0) matched++;
            /* Else: ESRCH (race with exit) is silently skipped; EPERM
               counts as a process we tried to signal but couldn't.
               procps-ng's pkill prints a warning on EPERM; we mirror. */
            else if (errno == EPERM)
                builtin_error ("kill (%d): %s", pid, strerror (errno));
        } else {
            matched++;
            if (!count_only) {
                if (!first_print) fputs (odelim, stdout);   /* -d DELIM (default "\n") */
                printf ("%d", pid);
                if (lflag) {            /* -l: PID + comm name */
                    if (by_cmdline) {
                        char nm[64];
                        if (bp_read_comm (pid, nm, sizeof nm) == 0) printf (" %s", nm);
                    } else
                        printf (" %s", comm);
                } else if (aflag) {     /* -a: PID + full command line */
                    if (by_cmdline)
                        printf (" %s", cmdline);
                    else {
                        char cl[4096];
                        if (bp_read_cmdline (pid, cl, sizeof cl) == 0 && cl[0])
                            printf (" %s", cl);
                    }
                }
                first_print = 0;
            }
        }
    }
    closedir (d);
    /* -c/--count: print only the tally (procps-ng prints "0" + exit 1 on
       no match, for both pgrep and pkill). */
    if (count_only)
        printf ("%d\n", matched);
    else if (!delivers && matched > 0)
        putchar ('\n');
    if (mode == BP_MODE_KILLALL5)
        return matched > 0 ? EXECUTION_SUCCESS : 2;
    return matched > 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* ---- Shared dispatch (called from both bashpgrep and bashpkill) --------- */

int
bp_dispatch (WORD_LIST *list, int mode)
{
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
            return EXECUTION_SUCCESS;
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
            return EXECUTION_SUCCESS;
        }
        if (mode != BP_MODE_KILLALL5 && !strcmp (w, "-f")) { by_cmdline = 1; list = list->next; continue; }
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
        /* GREP-mode short-flag clustering (procps-ng compat): -af, -fa, -cf,
           -lf, -vf, -xf, and value flags as cluster members (-fu USER, -fdX).
           Reached only for single-dash, multi-char, non-"--" tokens that no
           whole-word arm above matched. Signal modes (pkill/killall) are
           deliberately NOT clustered so the `-SIGNAL` selector arm below keeps
           owning `-9`, `-TERM`, etc. (matches procps-ng, which does not cluster
           pkill's listing flags). */
        if (mode == BP_MODE_GREP && w[0] == '-' && w[1] && w[1] != '-') {
            const char *c;
            for (c = w + 1; *c; c++) {
                if (*c == 'f') { by_cmdline = 1; continue; }
                if (*c == 'c') { count_only = 1; continue; }
                if (*c == 'x') { exact = 1; continue; }
                if (*c == 'l') { lflag = 1; aflag = 0; continue; }
                if (*c == 'a') { aflag = 1; lflag = 0; continue; }
                if (*c == 'v') { vflag = 1; continue; }
                if (*c == 'd' || *c == 'u') {
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
                        if (bp_resolve_user (val, &want_uid) < 0) {
                            builtin_error ("-u: unknown user: %s", val);
                            builtin_usage ();
                            return EX_USAGE;
                        }
                        filter_uid_set = 1;
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
            if (s > 0) {
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
    if (pattern_count == 0 && !filter_uid_set) {
        if (mode == BP_MODE_KILLALL5)
            return bp_walk (patterns, pattern_count, by_cmdline, filter_uid_set,
                            want_uid, mode, sig, count_only, exact,
                            lflag, aflag, vflag, odelim,
                            killall5_dry_run, killall5_sid, omit_pids, omit_count);
        builtin_usage ();
        return EX_USAGE;
    }

    return bp_walk (patterns, pattern_count, by_cmdline, filter_uid_set,
                    want_uid, mode, sig, count_only, exact,
                    lflag, aflag, vflag, odelim,
                    killall5_dry_run, killall5_sid, omit_pids, omit_count);
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
    "    bashpgrep [-cfx] [-u USER] PATTERN",
    "    bashpgrep [-cf] -u USER",
    "    bashpgrep -h | --help | -V | --version",
    "",
    "    -f         match against the full command line (/proc/PID/cmdline)",
    "               instead of the comm field (kernel-truncated to 15 chars)",
    "    -c, --count  print only the count of matching processes",
    "    -x, --exact  match the whole comm/cmdline, not a substring",
    "    -u USER    only match processes whose real uid is USER",
    "               (numeric or /etc/passwd name)",
    "    -l         list the process name after each PID",
    "    -a         list the full command line after each PID",
    "    -d DELIM   delimit output PIDs with DELIM (default newline)",
    "    -v         negate: print processes that do NOT match",
    "",
    "PATTERN is a substring (not a regex) unless -x is given. Self is never matched.",
    "Returns 0 if any PID matched, 1 if none, 2 on usage error, 3 on fatal.",
    (char *)NULL
};

struct builtin bashpgrep_struct = {
    "bashpgrep",
    pgrep_builtin,
    BUILTIN_ENABLED,
    pgrep_doc,
    "bashpgrep [-cfx] [-u USER] PATTERN [-h|--help|-V|--version]",
    0
};
