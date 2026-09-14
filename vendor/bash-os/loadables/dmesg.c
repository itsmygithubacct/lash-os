/* SPDX-License-Identifier: MIT */
/* dmesg.c — dmesg(1) subset: read the kernel ring buffer via
 *               /dev/kmsg (record-level, RFC-shaped) instead of the
 *               legacy klogctl(SYSLOG_ACTION_READ_ALL) path.
 *
 * Modeled after Documentation/ABI/testing/dev-kmsg + util-linux
 * sys-utils/dmesg.c + toybox toys/lsb/dmesg.c. Mode flags follow the
 * dmesg(1) UX:
 *
 *   dmesg            print decoded ring buffer (default output)
 *   dmesg -k         kernel-facility messages only
 *   dmesg -T         human-readable timestamps via boot offset
 *   dmesg -r         raw "<priority>,seq,us;message" lines
 *   dmesg -t         suppress timestamp column
 *   dmesg -l LEVELS  comma list: emerg/alert/crit/err/warn/notice/info/debug
 *   dmesg -f FACILS  comma list: kern/user/mail/daemon/... facilities
 *   dmesg --since S  print records at/after S seconds since boot
 *   dmesg --until S  print records at/before S seconds since boot
 *   dmesg -w|--follow
 *                        keep waiting for new records after current drain
 *   dmesg -n LEVEL   set console log level (CAP_SYSLOG via klogctl 8)
 *   dmesg -c         clear ring buffer (CAP_SYSLOG via klogctl 5)
 *
 * /dev/kmsg record format (each read returns exactly one record,
 * Linux >= 3.5):
 *
 *   <priority>,<seqnum>,<timestamp_us>,<flag>[,subsys=val,...];<text>\n
 *   ...optional continuation lines beginning with ' ' (extra metadata)
 *
 * priority = facility * 8 + level. Kernel facility is 0; level is the
 * low three bits.
 *
 * Test hook: $BASHDMESG_DEV_KMSG_FILE overrides the device path so a
 * fixture file with mock records can be parsed without CAP_SYSLOG or
 * an actual kernel ring buffer. $BASHDMESG_BOOT_EPOCH overrides the
 * monotonic offset used by -T so the rendered wall-clock string is
 * deterministic across hosts.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c. When statically linked
 * into GNU bash the resulting binary is governed by GPL-3+; MIT is
 * GPL-3+-compatible so the binary's licence is unchanged.
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
#include <time.h>
#include <sys/syscall.h>
#include <poll.h>

/* Userspace declarations of klogctl(3). musl ships <sys/klog.h>; we
   prefer the syscall wrapper to keep the header surface portable. */
#ifndef SYSLOG_ACTION_CLEAR
#  define SYSLOG_ACTION_CLEAR 5
#endif
#ifndef SYSLOG_ACTION_CONSOLE_LEVEL
#  define SYSLOG_ACTION_CONSOLE_LEVEL 8
#endif

#include "loadables.h"

/* Linux ABI: priority byte = (facility << 3) | level. */
#define BD_LEVEL(p)    ((p) & 0x07)
#define BD_FACILITY(p) ((p) >> 3)

static const char * const bd_level_names[8] = {
    "emerg", "alert", "crit", "err",
    "warn",  "notice","info", "debug"
};

static const char * const bd_facility_names[16] = {
    "kern", "user", "mail", "daemon",
    "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp",
    "ntp", "security", "console", "solaris-cron"
};

/* Resolve a level token (numeric or name) to 0..7, or -1 on unknown. */
static int
bd_level_index (const char *tok)
{
    if (!tok || !*tok) return -1;
    if (isdigit ((unsigned char) tok[0]) && tok[1] == '\0')
        return tok[0] - '0';
    for (int i = 0; i < 8; i++)
        if (!strcmp (tok, bd_level_names[i]))
            return i;
    /* dmesg(1) also accepts the older "warning" spelling for "warn". */
    if (!strcmp (tok, "warning")) return 4;
    return -1;
}

/* Resolve a facility token (numeric or name) to 0..15, or -1 on unknown. */
static int
bd_facility_index (const char *tok)
{
    if (!tok || !*tok) return -1;
    if (isdigit ((unsigned char) tok[0])) {
        char *end = NULL;
        long v = strtol (tok, &end, 10);
        if (end && *end == '\0' && v >= 0 && v < 16)
            return (int) v;
        return -1;
    }
    for (int i = 0; i < 16; i++)
        if (!strcmp (tok, bd_facility_names[i]))
            return i;
    /* Common alias; util-linux accepts the canonical authpriv spelling. */
    if (!strcmp (tok, "auth-private")) return 10;
    return -1;
}

/* Parse comma-separated list of level names/numbers into a bitmask
   over 0..7. Returns -1 if any token is unknown. */
static int
bd_parse_level_mask (const char *spec)
{
    int mask = 0;
    char buf[64];
    if (strlen (spec) >= sizeof buf) return -1;
    strcpy (buf, spec);
    char *save = NULL;
    char *t = strtok_r (buf, ",", &save);
    while (t) {
        int idx = bd_level_index (t);
        if (idx < 0) return -1;
        mask |= 1 << idx;
        t = strtok_r (NULL, ",", &save);
    }
    return mask;
}

/* Parse comma-separated list of facility names/numbers into a bitmask
   over 0..15. Returns -1 if any token is unknown. */
static int
bd_parse_facility_mask (const char *spec)
{
    int mask = 0;
    char buf[128];
    if (strlen (spec) >= sizeof buf) return -1;
    strcpy (buf, spec);
    char *save = NULL;
    char *t = strtok_r (buf, ",", &save);
    while (t) {
        int idx = bd_facility_index (t);
        if (idx < 0) return -1;
        mask |= 1 << idx;
        t = strtok_r (NULL, ",", &save);
    }
    return mask;
}

static int
bd_parse_seconds_us (const char *spec, unsigned long long *out)
{
    char *end = NULL;
    double v;
    if (!spec || !*spec) return -1;
    errno = 0;
    v = strtod (spec, &end);
    if (errno || !end || *end != '\0' || v < 0)
        return -1;
    *out = (unsigned long long) (v * 1000000.0);
    return 0;
}

/* Boot wall-clock offset for -T: time(NULL) - CLOCK_BOOTTIME. The
   record's timestamp is microseconds since boot. Override via
   $BASHDMESG_BOOT_EPOCH so tests can render deterministic dates. */
static time_t
bd_boot_epoch (void)
{
    const char *env = getenv ("BASHDMESG_BOOT_EPOCH");
    if (env && *env) return (time_t) strtoll (env, NULL, 10);
    struct timespec mono;
    if (clock_gettime (CLOCK_BOOTTIME, &mono) == 0)
        return time (NULL) - (time_t) mono.tv_sec;
    /* Fall back to MONOTONIC if BOOTTIME is unavailable (very old
       kernel — unlikely on bash-os but keep the code robust). */
    if (clock_gettime (CLOCK_MONOTONIC, &mono) == 0)
        return time (NULL) - (time_t) mono.tv_sec;
    return 0;
}

static const char *
bd_kmsg_path (void)
{
    const char *e = getenv ("BASHDMESG_DEV_KMSG_FILE");
    return (e && *e) ? e : "/dev/kmsg";
}

/* Decode one /dev/kmsg record line into priority/seq/time_us + pointer
   to the message text. Returns 0 on success, -1 on malformed input. */
static int
bd_parse_record (const char *line, unsigned int *pri,
                 unsigned long long *seq, unsigned long long *us,
                 const char **text)
{
    const char *semi = strchr (line, ';');
    if (!semi) return -1;
    if (sscanf (line, "%u,%llu,%llu", pri, seq, us) != 3) return -1;
    *text = semi + 1;
    return 0;
}

/* Print one record honoring the mode flags. text already points past
   the ';' delimiter; the trailing newline (if any) is stripped. */
static void
bd_emit (unsigned int pri, unsigned long long us, const char *text,
         int raw, int no_ts, int human_ts, time_t boot_epoch)
{
    char tbuf[64];
    tbuf[0] = '\0';
    if (!no_ts) {
        if (human_ts) {
            time_t when = boot_epoch + (time_t) (us / 1000000ULL);
            struct tm tm;
            localtime_r (&when, &tm);
            strftime (tbuf, sizeof tbuf, "[%a %b %e %H:%M:%S %Y] ", &tm);
        } else {
            unsigned long long secs = us / 1000000ULL;
            unsigned long long frac = us % 1000000ULL;
            snprintf (tbuf, sizeof tbuf, "[%5llu.%06llu] ", secs, frac);
        }
    }

    /* Strip a trailing newline; the kernel always terminates a record
       with \n. */
    size_t tl = strlen (text);
    char *copy = malloc (tl + 1);
    if (!copy) return;
    memcpy (copy, text, tl + 1);
    if (tl && copy[tl - 1] == '\n') copy[tl - 1] = '\0';

    if (raw) {
        /* "<pri>tbuf<text>" — keeps callers that grep for <N> happy. */
        printf ("<%u>%s%s\n", pri, tbuf, copy);
    } else {
        printf ("%s%s\n", tbuf, copy);
    }
    free (copy);
}

/* Read /dev/kmsg records until EAGAIN (no more records) or EOF on a
   fixture file. Decoded records that pass the filters are emitted. */
static int
bd_process_record (const char *record, int kernel_only, int facility_mask,
                   int level_mask,
                   int raw, int no_ts, int human_ts, time_t boot_epoch,
                   int have_since, unsigned long long since_us,
                   int have_until, unsigned long long until_us)
{
    unsigned int pri;
    unsigned long long seq, us;
    const char *text;

    if (bd_parse_record (record, &pri, &seq, &us, &text) != 0) return 0;
    (void) seq;

    if (kernel_only && BD_FACILITY (pri) != 0) return 0;
    if (facility_mask && !((facility_mask >> BD_FACILITY (pri)) & 1)) return 0;
    if (level_mask && !((level_mask >> BD_LEVEL (pri)) & 1)) return 0;
    if (have_since && us < since_us) return 0;
    if (have_until && us > until_us) return 0;

    bd_emit (pri, us, text, raw, no_ts, human_ts, boot_epoch);
    return 1;
}

static int
bd_drain (int fd, int kernel_only, int facility_mask, int level_mask,
          int raw, int no_ts,
          int human_ts, time_t boot_epoch,
          int have_since, unsigned long long since_us,
          int have_until, unsigned long long until_us,
          unsigned long long *emitted)
{
    char buf[8193];   /* kernel CONSOLE_EXT_LOG_MAX + 1 */
    int fixture_file = getenv ("BASHDMESG_DEV_KMSG_FILE") != NULL;
    for (;;) {
        ssize_t n = read (fd, buf, sizeof buf - 1);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            /* EPIPE on /dev/kmsg means the record we tried to read
               was overrun while we were reading; just keep going. */
            if (errno == EPIPE) continue;
            if (errno == EINTR) continue;
            builtin_error ("read %s: %s", bd_kmsg_path (), strerror (errno));
            return EXECUTION_FAILURE;
        }
        if (n == 0) break;     /* EOF on a fixture */
        buf[n] = '\0';

        if (fixture_file) {
            char *save = NULL;
            char *line = strtok_r (buf, "\n", &save);
            while (line) {
                *emitted += bd_process_record (line, kernel_only,
                                               facility_mask, level_mask,
                                               raw, no_ts, human_ts,
                                               boot_epoch, have_since,
                                               since_us, have_until,
                                               until_us);
                line = strtok_r (NULL, "\n", &save);
            }
        } else {
            *emitted += bd_process_record (buf, kernel_only, facility_mask,
                                           level_mask, raw, no_ts, human_ts,
                                           boot_epoch, have_since, since_us,
                                           have_until, until_us);
        }
    }
    return EXECUTION_SUCCESS;
}

static unsigned long long
bd_follow_max_records (void)
{
    const char *e = getenv ("BASHDMESG_FOLLOW_MAX_RECORDS");
    char *end = NULL;
    unsigned long long v;

    if (!getenv ("BASHDMESG_DEV_KMSG_FILE") || !e || !*e)
        return 0;
    errno = 0;
    v = strtoull (e, &end, 10);
    if (errno || !end || *end != '\0')
        return 0;
    return v;
}

static int
bd_wait_for_more (int fd, int fixture_file)
{
    if (fixture_file) {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 100000000L;
        while (nanosleep (&ts, &ts) < 0) {
            if (errno == EINTR) continue;
            return EXECUTION_FAILURE;
        }
        return EXECUTION_SUCCESS;
    }

    for (;;) {
        struct pollfd pfd;
        int prc;

        pfd.fd = fd;
        pfd.events = POLLIN | POLLERR | POLLHUP;
        pfd.revents = 0;
        prc = poll (&pfd, 1, -1);
        if (prc > 0) return EXECUTION_SUCCESS;
        if (prc < 0 && errno == EINTR) continue;
        if (prc < 0) {
            builtin_error ("poll %s: %s", bd_kmsg_path (), strerror (errno));
            return EXECUTION_FAILURE;
        }
    }
}

int
dmesg_builtin (WORD_LIST *list)
{
    int kernel_only = 0;
    int facility_mask = 0;    /* 0 = no filter */
    int level_mask  = 0;       /* 0 = no filter */
    int raw         = 0;
    int no_ts       = 0;
    int human_ts    = 0;
    int do_clear    = 0;
    int set_console = -1;      /* -n LEVEL */
    int have_since = 0;
    int have_until = 0;
    int follow = 0;
    unsigned long long since_us = 0;
    unsigned long long until_us = 0;

    while (list && list->word->word[0] == '-') {
        const char *w = list->word->word;
        if (!strcmp (w, "-k")) kernel_only = 1;
        else if (!strcmp (w, "-T")) human_ts = 1;
        else if (!strcmp (w, "-r")) raw = 1;
        else if (!strcmp (w, "-t")) no_ts = 1;
        else if (!strcmp (w, "-w") || !strcmp (w, "--follow")) follow = 1;
        else if (!strcmp (w, "-c") || !strcmp (w, "-C")) do_clear = 1;
        else if (!strcmp (w, "--since")) {
            list = list->next;
            if (!list) { builtin_error ("--since: missing SECONDS"); builtin_usage (); return EX_USAGE; }
            if (bd_parse_seconds_us (list->word->word, &since_us) < 0) {
                builtin_error ("--since: invalid seconds '%s'", list->word->word);
                builtin_usage ();
                return EX_USAGE;
            }
            have_since = 1;
        }
        else if (!strncmp (w, "--since=", 8)) {
            if (bd_parse_seconds_us (w + 8, &since_us) < 0) {
                builtin_error ("--since: invalid seconds '%s'", w + 8);
                builtin_usage ();
                return EX_USAGE;
            }
            have_since = 1;
        }
        else if (!strcmp (w, "--until")) {
            list = list->next;
            if (!list) { builtin_error ("--until: missing SECONDS"); builtin_usage (); return EX_USAGE; }
            if (bd_parse_seconds_us (list->word->word, &until_us) < 0) {
                builtin_error ("--until: invalid seconds '%s'", list->word->word);
                builtin_usage ();
                return EX_USAGE;
            }
            have_until = 1;
        }
        else if (!strncmp (w, "--until=", 8)) {
            if (bd_parse_seconds_us (w + 8, &until_us) < 0) {
                builtin_error ("--until: invalid seconds '%s'", w + 8);
                builtin_usage ();
                return EX_USAGE;
            }
            have_until = 1;
        }
        else if (!strcmp (w, "-f")) {
            list = list->next;
            if (!list) { builtin_error ("-f: missing FACILITIES"); builtin_usage (); return EX_USAGE; }
            int mask = bd_parse_facility_mask (list->word->word);
            if (mask < 0) {
                builtin_error ("-f: unknown facility in '%s'", list->word->word);
                builtin_usage ();
                return EX_USAGE;
            }
            facility_mask = mask;
        }
        else if (!strcmp (w, "-l")) {
            list = list->next;
            if (!list) { builtin_error ("-l: missing LEVELS"); builtin_usage (); return EX_USAGE; }
            int mask = bd_parse_level_mask (list->word->word);
            if (mask < 0) {
                builtin_error ("-l: unknown level in '%s'", list->word->word);
                builtin_usage ();
                return EX_USAGE;
            }
            level_mask = mask;
        }
        else if (!strcmp (w, "-n")) {
            list = list->next;
            if (!list) { builtin_error ("-n: missing LEVEL"); builtin_usage (); return EX_USAGE; }
            int lvl = bd_level_index (list->word->word);
            if (lvl < 0) {
                builtin_error ("-n: unknown level '%s'", list->word->word);
                builtin_usage ();
                return EX_USAGE;
            }
            set_console = lvl;
        }
        else if (!strcmp (w, "--help") || !strcmp (w, "-h")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        else {
            builtin_error ("unknown flag: %s", w);
            builtin_usage ();
            return EX_USAGE;
        }
        list = list->next;
    }
    if (list) {
        builtin_error ("unexpected operand: %s", list->word->word);
        builtin_usage ();
        return EX_USAGE;
    }

    /* -n LEVEL: set console log level. SYSLOG_ACTION_CONSOLE_LEVEL
       expects level in arg3 (the "len" slot of klogctl). */
    if (set_console >= 0) {
        long rc = syscall (SYS_syslog, SYSLOG_ACTION_CONSOLE_LEVEL,
                           (char *) NULL, set_console);
        if (rc < 0) {
            builtin_error ("set console level: %s",
                           errno == EPERM ? "need CAP_SYSLOG" : strerror (errno));
            return EXECUTION_FAILURE;
        }
        return EXECUTION_SUCCESS;
    }

    /* Reader path: open /dev/kmsg (or fixture) non-blocking so we
       stop at the end of the current buffer rather than blocking
       forever waiting for new records. */
    const char *path = bd_kmsg_path ();
    int fd = open (path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        builtin_error ("open %s: %s", path, strerror (errno));
        return EXECUTION_FAILURE;
    }
    /* /dev/kmsg starts at the oldest available record by default after
       lseek(SEEK_DATA); regular fixture files honor lseek(0,SET). */
    (void) lseek (fd, 0, SEEK_SET);

    time_t boot_epoch = human_ts ? bd_boot_epoch () : 0;
    int fixture_file = getenv ("BASHDMESG_DEV_KMSG_FILE") != NULL;
    unsigned long long emitted = 0;
    unsigned long long follow_max = bd_follow_max_records ();
    int rc;

    for (;;) {
        rc = bd_drain (fd, kernel_only, facility_mask, level_mask, raw, no_ts,
                       human_ts, boot_epoch, have_since, since_us,
                       have_until, until_us, &emitted);
        if (rc != EXECUTION_SUCCESS) break;
        fflush (stdout);
        if (!follow) break;
        if (follow_max && emitted >= follow_max) break;
        rc = bd_wait_for_more (fd, fixture_file);
        if (rc != EXECUTION_SUCCESS) break;
    }
    close (fd);
    if (rc != EXECUTION_SUCCESS) return rc;

    /* -c after printing: SYSLOG_ACTION_CLEAR. Ignored for fixture
       paths so the test hook cannot accidentally drain the host's
       ring buffer when BASHDMESG_DEV_KMSG_FILE is set. */
    if (do_clear) {
        if (getenv ("BASHDMESG_DEV_KMSG_FILE")) return EXECUTION_SUCCESS;
        if (syscall (SYS_syslog, SYSLOG_ACTION_CLEAR,
                     (char *) NULL, 0) < 0) {
            builtin_error ("clear ring buffer: %s",
                           errno == EPERM ? "need CAP_SYSLOG" : strerror (errno));
            return EXECUTION_FAILURE;
        }
    }
    return EXECUTION_SUCCESS;
}

char *dmesg_doc[] = {
    "Read / control the kernel ring buffer via /dev/kmsg.",
    "",
    "    dmesg [-k] [-T] [-r] [-t] [--since S] [--until S]",
    "               [-f FACILITIES] [-l LEVELS] [-w|--follow] [-n LEVEL] [-c]",
    "",
    "    -k          kernel-facility messages only",
    "    -T          human-readable wall-clock timestamps",
    "    -r          raw output (keeps the leading <priority> column)",
    "    -t          suppress the timestamp column",
    "    -f FACILS   comma list: kern,user,mail,daemon,auth,syslog,...",
    "    -l LEVELS   comma list: emerg,alert,crit,err,warn,notice,info,debug",
    "    --since S   records at/after S seconds since boot",
    "    --until S   records at/before S seconds since boot",
    "    -w, --follow",
    "                wait for new records after the current drain",
    "    -n LEVEL    set console log level (needs CAP_SYSLOG)",
    "    -c          clear ring buffer after printing (needs CAP_SYSLOG)",
    "",
    "Reads /dev/kmsg non-blocking, stopping at the current end of the",
    "ring buffer unless --follow is set. Set $BASHDMESG_DEV_KMSG_FILE to point at a fixture",
    "file for testing without root; -c is suppressed in that mode so",
    "the host's real ring buffer is never touched.",
    (char *)NULL
};

struct builtin dmesg_struct = {
    "dmesg",
    dmesg_builtin,
    BUILTIN_ENABLED,
    dmesg_doc,
    "dmesg [-k] [-T] [-r] [-t] [--since S] [--until S] [-f FACILITIES] [-l LEVELS] [-w|--follow] [-n LEVEL] [-c]",
    0
};
